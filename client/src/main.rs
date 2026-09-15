// Modbus master: mounts a FUSE projection of `device-description.toml` at
// `mountpoint`, backed by a real device reachable over TCP or RTU (see
// `<connection>` below). Staging a transaction and creating
// TRANSACTION_END sends the real write(s) to that device;
// `holding-registers/`/`report/` only update once the device actually
// confirms them (see CLAUDE.md's "TRANSACTION_END confirmation
// semantics").
//
// Usage:
//   cargo run -p client -- <mountpoint> <device-description.toml> <connection> [unit-id] [poll-interval-ms]
//
// <connection> is either:
//   tcp://<address:port>                e.g. tcp://127.0.0.1:502
//   rtu://<serial-path>:<baud-rate>      e.g. rtu:///dev/ttyUSB0:9600
//
// Scope of this first pass (see client/src/write_confirmation.rs,
// transaction_consumer.rs, and polling.rs for more detail): one persistent
// connection (shared between polling and writes) with no reconnect logic,
// and U16 registers only — F32 is rejected with a clear WriteStatus::Failed
// / logged and skipped rather than guessing a wire format, on both the
// write and the poll-read side. RTU's serial parameters beyond baud rate
// (data bits, parity, stop bits) aren't configurable yet — this uses
// tokio-serial's defaults (8 data bits, no parity, 1 stop bit).

use client::connection::Connection;
use client::polling::run_polling_loop;
use client::transaction_consumer::run_transaction_consumer;
use fuse_fs::filesystem::InfusedFilesystem;
use fuse_fs::{RegisterStore, WriteReport};
use protocol::device_description::DeviceDescription;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

const DEFAULT_UNIT_ID: u8 = 1;
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(5);

fn usage() -> ! {
    eprintln!(
        "Usage: client <mountpoint> <device-description.toml> <connection> [unit-id] [poll-interval-ms]\n\
         <connection> is tcp://<address:port> or rtu://<serial-path>:<baud-rate>"
    );
    std::process::exit(1);
}

fn open_connection(runtime: &tokio::runtime::Runtime, connection_string: &str) -> Connection {
    if let Some(address) = connection_string.strip_prefix("tcp://") {
        runtime
            .block_on(Connection::connect_tcp(address))
            .unwrap_or_else(|error| panic!("failed to connect to {address}: {error}"))
    } else if let Some(rest) = connection_string.strip_prefix("rtu://") {
        let Some((path, baud_rate)) = rest.rsplit_once(':') else {
            panic!("rtu:// connection must be rtu://<path>:<baud-rate>, got {connection_string:?}");
        };
        let baud_rate: u32 = baud_rate
            .parse()
            .unwrap_or_else(|error| panic!("invalid baud rate {baud_rate:?}: {error}"));
        Connection::open_rtu(runtime.handle(), path, baud_rate)
            .unwrap_or_else(|error| panic!("failed to open serial port {path:?}: {error}"))
    } else {
        panic!("connection must start with tcp:// or rtu://, got {connection_string:?}");
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(mountpoint) = args.next() else {
        usage();
    };
    let Some(device_description_path) = args.next() else {
        usage();
    };
    let Some(connection_string) = args.next() else {
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
    let connection = open_connection(&runtime, &connection_string);
    // Shared, not owned outright: the polling loop and the transaction
    // consumer both need to talk to the device over this same connection,
    // and a generic Modbus device/gateway can't be assumed to accept more
    // than one concurrent connection (true for TCP gateways, and doubly
    // true for RTU — one physical serial link, full stop).
    let connection = Arc::new(AsyncMutex::new(connection));

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    let report = Arc::new(Mutex::new(WriteReport::new()));
    let (transaction_sender, transaction_receiver) = mpsc::channel();

    let handle = runtime.handle().clone();
    let consumer_connection = Arc::clone(&connection);
    let consumer_registers = registers.clone();
    let consumer_store = Arc::clone(&store);
    let consumer_report = Arc::clone(&report);
    std::thread::spawn(move || {
        run_transaction_consumer(
            &handle,
            &consumer_connection,
            &consumer_registers,
            &consumer_store,
            &consumer_report,
            transaction_receiver,
            unit_id,
            WRITE_TIMEOUT,
        );
    });

    let polling_connection = Arc::clone(&connection);
    let polling_store = Arc::clone(&store);
    let polling_registers = registers.clone();
    runtime.spawn(async move {
        run_polling_loop(
            polling_connection,
            &polling_registers,
            polling_store,
            unit_id,
            poll_interval,
            POLL_TIMEOUT,
        )
        .await;
    });

    std::fs::create_dir_all(&mountpoint).ok();
    println!(
        "Mounting infused_modbus at {mountpoint}, connected via {connection_string} (unit {unit_id})"
    );

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
