// Modbus TCP master: mounts a FUSE projection of `device-description.toml`
// at `mountpoint`, backed by a real device reachable at `address` (e.g.
// `127.0.0.1:502`). Staging a transaction and creating TRANSACTION_END
// sends the real write(s) to that device; `holding-registers/`/`report/`
// only update once the device actually confirms them (see CLAUDE.md's
// "TRANSACTION_END confirmation semantics").
//
// Usage:
//   cargo run -p client -- <mountpoint> <device-description.toml> <address:port> [unit-id] [poll-interval-ms]
//
// Scope of this first pass (see client/src/write_confirmation.rs,
// transaction_consumer.rs, and polling.rs for more detail): TCP only, one
// persistent connection (shared between polling and writes) with no
// reconnect logic, and U16 registers only — F32 is rejected with a clear
// WriteStatus::Failed / logged and skipped rather than guessing a wire
// format, on both the write and the poll-read side.

use client::polling::run_polling_loop;
use client::transaction_consumer::run_transaction_consumer;
use fuse_fs::filesystem::InfusedFilesystem;
use fuse_fs::{RegisterStore, WriteReport};
use protocol::device_description::DeviceDescription;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

const DEFAULT_UNIT_ID: u8 = 1;
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(5);

fn usage() -> ! {
    eprintln!(
        "Usage: client <mountpoint> <device-description.toml> <address:port> [unit-id] [poll-interval-ms]"
    );
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
    let poll_interval: Duration = match args.next() {
        Some(value) => Duration::from_millis(
            value
                .parse()
                .unwrap_or_else(|error| panic!("invalid poll interval {value:?}: {error}")),
        ),
        None => Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
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
    // Shared, not owned outright: the polling loop (added separately) also
    // needs to talk to the device over this same connection, and a generic
    // Modbus device/gateway can't be assumed to accept more than one
    // concurrent connection.
    let stream = Arc::new(AsyncMutex::new(stream));

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    let report = Arc::new(Mutex::new(WriteReport::new()));
    let (transaction_sender, transaction_receiver) = mpsc::channel();

    let handle = runtime.handle().clone();
    let consumer_stream = Arc::clone(&stream);
    let consumer_registers = registers.clone();
    let consumer_store = Arc::clone(&store);
    let consumer_report = Arc::clone(&report);
    std::thread::spawn(move || {
        run_transaction_consumer(
            &handle,
            &consumer_stream,
            &consumer_registers,
            &consumer_store,
            &consumer_report,
            transaction_receiver,
            unit_id,
            WRITE_TIMEOUT,
        );
    });

    let polling_stream = Arc::clone(&stream);
    let polling_store = Arc::clone(&store);
    let polling_registers = registers.clone();
    runtime.spawn(async move {
        run_polling_loop(
            polling_stream,
            &polling_registers,
            polling_store,
            unit_id,
            poll_interval,
            POLL_TIMEOUT,
        )
        .await;
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
