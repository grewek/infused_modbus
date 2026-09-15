// Modbus TCP slave: mounts a FUSE projection of `device-description.toml`
// at `mountpoint` and listens on `bind-address` for real Modbus masters to
// query/write against. This process's own RegisterStore is the
// authoritative state being served — an external write applies directly
// (see server/src/handler.rs), and a locally staged transaction
// (transactions/ + TRANSACTION_END) applies directly too (see
// transaction_consumer.rs) — unlike the client, there's no separate real
// device to round-trip with, so there's no "wait for confirmation" step on
// either side.
//
// Usage:
//   cargo run -p server -- <mountpoint> <device-description.toml> <bind-address:port>
//
// Scope of this first pass (see handler.rs/connection.rs for detail): only
// U16 registers over Read Holding Registers / Write Single Register are
// served; F32 registers and Write Multiple Registers requests get a
// Modbus exception rather than a guessed wire format, matching the same
// boundary drawn on the client side.
//
// Also serves FC 43 / MEI 0x0E (Read Device Identification, Extended
// access only) so a client can fetch this server's device-description.toml
// over the wire instead of needing its own local copy — see
// device_identification.rs for the object layout.

use fuse_fs::filesystem::InfusedFilesystem;
use fuse_fs::{RegisterStore, WriteReport};
use protocol::device_description::DeviceDescription;
use server::connection::serve_connection;
use server::transaction_consumer::run_transaction_consumer;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::net::TcpListener;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn usage() -> ! {
    eprintln!("Usage: server <mountpoint> <device-description.toml> <bind-address:port>");
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
    let Some(bind_address) = args.next() else {
        usage();
    };

    let toml_source = std::fs::read_to_string(&device_description_path)
        .unwrap_or_else(|error| panic!("failed to read {device_description_path}: {error}"));
    let registers = DeviceDescription::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {device_description_path}: {error}"))
        .registers;

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    let report = Arc::new(Mutex::new(WriteReport::new()));
    let (transaction_sender, transaction_receiver) = mpsc::channel();

    let consumer_store = Arc::clone(&store);
    let consumer_report = Arc::clone(&report);
    std::thread::spawn(move || {
        run_transaction_consumer(&consumer_store, &consumer_report, transaction_receiver);
    });

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");
    let listener = runtime
        .block_on(TcpListener::bind(&bind_address))
        .unwrap_or_else(|error| panic!("failed to bind {bind_address}: {error}"));

    let accept_registers = Arc::new(registers.clone());
    let accept_store = Arc::clone(&store);
    let accept_toml_source = Arc::new(toml_source.clone());
    runtime.spawn(async move {
        loop {
            let (stream, _peer_address) = match listener.accept().await {
                Ok(accepted) => accepted,
                // A single failed accept (e.g. a transient resource limit)
                // shouldn't take the whole server down.
                Err(_) => continue,
            };
            let registers = Arc::clone(&accept_registers);
            let store = Arc::clone(&accept_store);
            let toml_source = Arc::clone(&accept_toml_source);
            tokio::spawn(async move {
                serve_connection(stream, registers, store, toml_source, REQUEST_TIMEOUT).await;
            });
        }
    });

    std::fs::create_dir_all(&mountpoint).ok();
    println!("Mounting infused_modbus server at {mountpoint}, listening on {bind_address}");

    let filesystem = InfusedFilesystem::new(registers, store, transaction_sender, report);
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
