// Modbus TCP master: mounts a FUSE projection of `device-description.toml`
// at `mountpoint`, backed by a real device reachable at `address` (e.g.
// `127.0.0.1:502`). Staging a transaction and creating TRANSACTION_END
// sends the real write(s) to that device; `holding-registers/`/`report/`
// only update once the device actually confirms them (see CLAUDE.md's
// "TRANSACTION_END confirmation semantics").
//
// Usage:
//   cargo run -p client -- <mountpoint> <device-description.toml> <address:port> [unit-id]
//
// Scope of this first pass (see client/src/write_confirmation.rs and
// transaction_consumer.rs for more detail): TCP only, one persistent
// connection with no reconnect logic, U16 writes only (F32 rejected with a
// clear WriteStatus::Failed rather than guessing a wire format), and no
// continuous polling of `holding-registers/` from the device yet — only the
// transaction write-confirmation path is wired up so far.

use client::transaction_consumer::run_transaction_consumer;
use fuse_fs::filesystem::InfusedFilesystem;
use fuse_fs::{RegisterStore, WriteReport};
use protocol::device_description::DeviceDescription;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::net::TcpStream;

const DEFAULT_UNIT_ID: u8 = 1;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn usage() -> ! {
    eprintln!("Usage: client <mountpoint> <device-description.toml> <address:port> [unit-id]");
    std::process::exit(1);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(mountpoint) = args.next() else {
        usage();
    };
    let Some(device_description_path) = args.next() else {
        usage();
    };
    let Some(address) = args.next() else {
        usage();
    };
    let unit_id: u8 = match args.next() {
        Some(value) => value
            .parse()
            .unwrap_or_else(|error| panic!("invalid unit id {value:?}: {error}")),
        None => DEFAULT_UNIT_ID,
    };

    let toml_source = std::fs::read_to_string(&device_description_path)
        .unwrap_or_else(|error| panic!("failed to read {device_description_path}: {error}"));
    let registers = DeviceDescription::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {device_description_path}: {error}"))
        .registers;

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");
    let stream = runtime
        .block_on(TcpStream::connect(&address))
        .unwrap_or_else(|error| panic!("failed to connect to {address}: {error}"));

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    let report = Arc::new(Mutex::new(WriteReport::new()));
    let (transaction_sender, transaction_receiver) = mpsc::channel();

    let handle = runtime.handle().clone();
    let consumer_registers = registers.clone();
    let consumer_store = Arc::clone(&store);
    let consumer_report = Arc::clone(&report);
    std::thread::spawn(move || {
        run_transaction_consumer(
            &handle,
            stream,
            &consumer_registers,
            &consumer_store,
            &consumer_report,
            transaction_receiver,
            unit_id,
            WRITE_TIMEOUT,
        );
    });

    std::fs::create_dir_all(&mountpoint).ok();
    println!("Mounting infused_modbus at {mountpoint}, connected to {address} (unit {unit_id})");

    let filesystem = InfusedFilesystem::new(registers, store, transaction_sender, report);
    // spawn_mount (not the blocking mount()) so Ctrl+C/SIGTERM below can
    // unmount cleanly instead of just killing the process and leaving a
    // stale mountpoint behind.
    let session = fuser::spawn_mount(filesystem, &mountpoint, &fuser::Config::default())
        .unwrap_or_else(|error| panic!("mount failed: {error}"));

    runtime.block_on(async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => println!("Received Ctrl+C, unmounting..."),
            _ = sigterm.recv() => println!("Received SIGTERM, unmounting..."),
        }
    });

    session
        .umount_and_join()
        .unwrap_or_else(|error| panic!("failed to unmount cleanly: {error}"));
}
