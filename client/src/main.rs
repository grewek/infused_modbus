// Modbus master: mounts a FUSE projection of a device description at
// `mountpoint`, backed by a real device reachable over TCP or RTU (see
// `<connection>` below). Staging a transaction and creating
// TRANSACTION_END sends the real write(s) to that device;
// `holding-registers/`/`report/` only update once the device actually
// confirms them (see CLAUDE.md's "TRANSACTION_END confirmation
// semantics").
//
// The device description itself is preferably fetched from the server
// over the wire (FC 43 / MEI 0x0E — see client/src/device_identification.rs)
// so it doesn't need to be kept in sync with a local file by hand;
// `<device-description.toml>` is still a required argument as the fallback
// used if the server has none, doesn't support the request, or the fetch
// otherwise fails.
//
// Usage:
//   cargo run -p client -- <mountpoint> <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>]
//
// <connection> is one of:
//   tcp://<address:port>                e.g. tcp://127.0.0.1:502
//   rtu://<serial-path>:<baud-rate>      e.g. rtu:///dev/ttyUSB0:9600
//   tls+tcp://<address:port>            e.g. tls+tcp://127.0.0.1:502
//
// tls+tcp:// verifies the server's identity by comparing its certificate's
// public-key fingerprint against --expect-server-fingerprint (pinned out of
// band, e.g. read off the server's own startup log at commissioning) — see
// client::connection::PinnedFingerprintServerCertVerifier. Without that
// flag, the connection falls back to accepting any server certificate
// unconditionally (client::connection::InsecureAcceptAnyServerCert) —
// useful for local testing, not for a real deployment. Either way, the
// server does not yet verify *this* client's identity (mutual TLS is a
// later milestone, M/N) — see CLAUDE.md's TLS design. The client does
// already generate/persist its own identity under
// CLIENT_TLS_IDENTITY_DIRECTORY and prints its fingerprint, ahead of it
// actually being presented during the handshake, so that value is ready
// once it's needed.
//
// Every register DataType is read (polling.rs) and written
// (write_confirmation.rs/transaction_consumer.rs) over the wire now, honoring
// the device description's mem_layout for anything wider than one register.
// One persistent connection is shared between polling and writes, with no
// reconnect logic. RTU's serial parameters beyond baud rate (data bits,
// parity, stop bits) aren't configurable yet — this uses tokio-serial's
// defaults (8 data bits, no parity, 1 stop bit).

use client::connection::Connection;
use client::device_identification::fetch_device_description;
use client::polling::run_polling_loop;
use client::transaction_consumer::run_transaction_consumer;
use fuse_fs::filesystem::InfusedFilesystem;
use fuse_fs::{CoilStore, RegisterStore, WriteReport};
use protocol::connection_string::{ConnectionTarget, parse_connection_string};
use protocol::device_description::DeviceDescription;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

const DEFAULT_UNIT_ID: u8 = 1;
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const CLIENT_TLS_IDENTITY_DIRECTORY: &str = "client-tls-identity";
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(5);
const DEVICE_DESCRIPTION_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

fn usage() -> ! {
    eprintln!(
        "Usage: client <mountpoint> <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>]\n\
         <connection> is tcp://<address:port>, tls+tcp://<address:port>, or rtu://<serial-path>:<baud-rate>\n\
         --expect-server-fingerprint pins the server's TLS identity (tls+tcp:// only) — \
         without it, the server's identity is not verified at all (see CLAUDE.md's TLS design)."
    );
    std::process::exit(1);
}

/// Pulls `--expect-server-fingerprint <value>` out of `args` if present
/// (order-independent relative to the positional arguments), leaving the
/// rest of `args` untouched.
fn extract_expected_server_fingerprint(
    args: &mut Vec<String>,
) -> Option<protocol::tls::Fingerprint> {
    let flag_index = args
        .iter()
        .position(|arg| arg == "--expect-server-fingerprint")?;
    if flag_index + 1 >= args.len() {
        panic!("--expect-server-fingerprint requires a value");
    }
    args.remove(flag_index);
    let value = args.remove(flag_index);
    Some(value.parse().unwrap_or_else(|error: String| {
        panic!("invalid --expect-server-fingerprint value: {error}")
    }))
}

fn open_connection(
    runtime: &tokio::runtime::Runtime,
    connection_string: &str,
    expected_server_fingerprint: Option<protocol::tls::Fingerprint>,
) -> Connection {
    let target =
        parse_connection_string(connection_string).unwrap_or_else(|error| panic!("{error}"));
    match target {
        ConnectionTarget::Tcp { address } => runtime
            .block_on(Connection::connect_tcp(&address))
            .unwrap_or_else(|error| panic!("failed to connect to {address}: {error}")),
        ConnectionTarget::TlsTcp { address } => runtime
            .block_on(Connection::connect_tls(
                &address,
                expected_server_fingerprint,
            ))
            .unwrap_or_else(|error| panic!("failed to connect over TLS to {address}: {error}")),
        ConnectionTarget::Rtu { path, baud_rate } => {
            Connection::open_rtu(runtime.handle(), &path, baud_rate)
                .unwrap_or_else(|error| panic!("failed to open serial port {path:?}: {error}"))
        }
    }
}

fn main() {
    let mut raw_args: Vec<String> = std::env::args().skip(1).collect();
    let expected_server_fingerprint = extract_expected_server_fingerprint(&mut raw_args);
    let mut args = raw_args.into_iter();
    let Some(mountpoint) = args.next() else {
        usage();
    };
    let Some(device_description_path) = args.next() else {
        usage();
    };
    let Some(connection_string) = args.next() else {
        usage();
    };
    if connection_string.starts_with("tls+tcp://") {
        match &expected_server_fingerprint {
            Some(fingerprint) => println!("Pinning server TLS fingerprint {fingerprint}."),
            None => println!(
                "No --expect-server-fingerprint given — the server's identity will NOT be \
                 verified (insecure placeholder verifier)."
            ),
        }
        // Not yet presented during the handshake (mTLS is milestone M2) —
        // generating/persisting it now, and printing its fingerprint,
        // means a technician already has what they'll need to hand to the
        // server operator once client approval (milestone N) exists.
        let client_identity = protocol::tls::load_or_generate_identity(std::path::Path::new(
            CLIENT_TLS_IDENTITY_DIRECTORY,
        ))
        .unwrap_or_else(|error| panic!("failed to load/generate client TLS identity: {error}"));
        let client_fingerprint = protocol::tls::Fingerprint::of(&client_identity.public_key_der);
        println!("Client TLS fingerprint: {client_fingerprint}");
    }
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

    let local_toml_source = std::fs::read_to_string(&device_description_path)
        .unwrap_or_else(|error| panic!("failed to read {device_description_path}: {error}"));

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");
    let mut connection = open_connection(&runtime, &connection_string, expected_server_fingerprint);

    // Ask the server to "introduce itself" (FC 43) before doing anything
    // else with the connection — see client/src/device_identification.rs.
    // Any failure (server has none, doesn't support it, transport error)
    // falls back to `local_toml_source`, which is why that's always read
    // above regardless of whether it ends up used.
    let toml_source = runtime
        .block_on(fetch_device_description(
            &mut connection,
            unit_id,
            DEVICE_DESCRIPTION_FETCH_TIMEOUT,
        ))
        .unwrap_or_else(|| {
            println!("Using the local device description ({device_description_path}).");
            local_toml_source
        });
    let description = DeviceDescription::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse device description: {error}"));
    let registers = description.registers;
    let coils = description.coils;
    let mem_layout = description.mem_layout;

    // Shared, not owned outright: the polling loop and the transaction
    // consumer both need to talk to the device over this same connection,
    // and a generic Modbus device/gateway can't be assumed to accept more
    // than one concurrent connection (true for TCP gateways, and doubly
    // true for RTU — one physical serial link, full stop).
    let connection = Arc::new(AsyncMutex::new(connection));

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    let coil_store = Arc::new(Mutex::new(CoilStore::new()));
    let report = Arc::new(Mutex::new(WriteReport::new()));
    let (transaction_sender, transaction_receiver) = mpsc::channel();

    let handle = runtime.handle().clone();
    let consumer_connection = Arc::clone(&connection);
    let consumer_registers = registers.clone();
    let consumer_coils = coils.clone();
    let consumer_report = Arc::clone(&report);
    std::thread::spawn(move || {
        run_transaction_consumer(
            &handle,
            &consumer_connection,
            &consumer_registers,
            &consumer_coils,
            &consumer_report,
            mem_layout,
            transaction_receiver,
            unit_id,
            WRITE_TIMEOUT,
        );
    });

    let polling_connection = Arc::clone(&connection);
    let polling_store = Arc::clone(&store);
    let polling_registers = registers.clone();
    let polling_coils = coils.clone();
    let polling_coil_store = Arc::clone(&coil_store);
    runtime.spawn(async move {
        run_polling_loop(
            polling_connection,
            &polling_registers,
            polling_store,
            &polling_coils,
            polling_coil_store,
            mem_layout,
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

    let filesystem = InfusedFilesystem::new(
        registers,
        coils,
        store,
        coil_store,
        transaction_sender,
        report,
    );
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
