// Modbus slave: mounts a FUSE projection of `device-description.toml` at
// `mountpoint` and serves real Modbus masters over TCP or RTU (see
// `<connection>` below). This process's own RegisterStore is the
// authoritative state being served — an external write applies directly
// (see server/src/handler.rs), and a locally staged transaction
// (transactions/ + TRANSACTION_END) applies directly too (see
// transaction_consumer.rs) — unlike the client, there's no separate real
// device to round-trip with, so there's no "wait for confirmation" step on
// either side.
//
// Usage:
//   cargo run -p server -- <mountpoint> <device-description.toml> <connection>
//
// <connection> is one of:
//   tcp://<bind-address:port>          e.g. tcp://0.0.0.0:502
//   rtu://<serial-path>:<baud-rate>    e.g. rtu:///dev/ttyUSB0:9600
//   tls+tcp://<bind-address:port>      e.g. tls+tcp://0.0.0.0:502
//
// tls+tcp:// requires a client certificate and checks its fingerprint
// against an approved set (see server::tls::build_server_config /
// server::client_trust::ApprovedClients) — but that set is currently always
// empty and has no way to be populated yet (the admin approval channel is
// Milestone P), so **every** client is rejected until that exists. The
// server's own TLS identity is generated on first run and persisted under
// TLS_IDENTITY_DIRECTORY below (a fixed default, not yet CLI-configurable).
//
// Every register DataType can be read and written over the wire now (see
// handler.rs) — Write Single Register only ever carries one register
// wide value, so wider types go through Write Multiple Registers instead.
//
// Also serves FC 43 / MEI 0x0E (Read Device Identification, Extended
// access only) so a client can fetch this server's device-description.toml
// over the wire instead of needing its own local copy — see
// device_identification.rs for the object layout.

use fuse_fs::filesystem::InfusedFilesystem;
use fuse_fs::{CoilStore, RegisterStore, WriteReport};
use protocol::connection_string::{ConnectionTarget, parse_connection_string};
use protocol::device_description::{
    CoilDescription, DeviceDescription, MemLayout, RegisterDescription,
};
use server::connection::{serve_rtu_connection, serve_tcp_connection};
use server::transaction_consumer::run_transaction_consumer;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_serial::SerialPortBuilderExt;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_IDENTITY_DIRECTORY: &str = "server-tls-identity";

fn usage() -> ! {
    eprintln!(
        "Usage: server <mountpoint> <device-description.toml> <connection>\n\
         <connection> is tcp://<bind-address:port>, tls+tcp://<bind-address:port>, or rtu://<serial-path>:<baud-rate>"
    );
    std::process::exit(1);
}

#[allow(clippy::too_many_arguments)]
fn start_serving(
    runtime: &tokio::runtime::Runtime,
    connection_string: &str,
    registers: Arc<Vec<RegisterDescription>>,
    store: Arc<Mutex<RegisterStore>>,
    coils: Arc<Vec<CoilDescription>>,
    coil_store: Arc<Mutex<CoilStore>>,
    mem_layout: MemLayout,
    toml_source: Arc<String>,
) {
    let target =
        parse_connection_string(connection_string).unwrap_or_else(|error| panic!("{error}"));
    match target {
        ConnectionTarget::Tcp {
            address: bind_address,
        } => {
            let listener = runtime
                .block_on(TcpListener::bind(&bind_address))
                .unwrap_or_else(|error| panic!("failed to bind {bind_address}: {error}"));
            runtime.spawn(async move {
                loop {
                    let (stream, _peer_address) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        // A single failed accept (e.g. a transient resource
                        // limit) shouldn't take the whole server down.
                        Err(_) => continue,
                    };
                    let registers = Arc::clone(&registers);
                    let store = Arc::clone(&store);
                    let coils = Arc::clone(&coils);
                    let coil_store = Arc::clone(&coil_store);
                    let toml_source = Arc::clone(&toml_source);
                    tokio::spawn(async move {
                        serve_tcp_connection(
                            stream,
                            registers,
                            store,
                            coils,
                            coil_store,
                            mem_layout,
                            toml_source,
                            REQUEST_TIMEOUT,
                        )
                        .await;
                    });
                }
            });
        }
        ConnectionTarget::TlsTcp {
            address: bind_address,
        } => {
            let identity =
                protocol::tls::load_or_generate_identity(Path::new(TLS_IDENTITY_DIRECTORY))
                    .unwrap_or_else(|error| {
                        panic!("failed to load/generate TLS identity: {error}")
                    });
            // Printed so a technician commissioning this server can read it
            // off the console and hand it to whoever configures a client's
            // --expect-server-fingerprint — otherwise there is no way to
            // learn this value short of inspecting the persisted identity
            // files by hand.
            let fingerprint = protocol::tls::Fingerprint::of(&identity.public_key_der);
            println!("Server TLS fingerprint: {fingerprint}");
            // Empty and, for now, permanently so — there is no admin
            // channel yet to approve anything (that's Milestone P). Until
            // it exists, tls+tcp:// is fail-closed against every client,
            // not just unapproved ones: nothing can ever become approved.
            let approved_clients =
                Arc::new(Mutex::new(server::client_trust::ApprovedClients::new()));
            let server_config = server::tls::build_server_config(&identity, approved_clients)
                .unwrap_or_else(|error| panic!("failed to build TLS server config: {error}"));
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            let listener = runtime
                .block_on(TcpListener::bind(&bind_address))
                .unwrap_or_else(|error| panic!("failed to bind {bind_address}: {error}"));
            runtime.spawn(async move {
                loop {
                    let (tcp_stream, _peer_address) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(_) => continue,
                    };
                    let acceptor = acceptor.clone();
                    let registers = Arc::clone(&registers);
                    let store = Arc::clone(&store);
                    let coils = Arc::clone(&coils);
                    let coil_store = Arc::clone(&coil_store);
                    let toml_source = Arc::clone(&toml_source);
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(tcp_stream).await else {
                            // A failed handshake (e.g. a peer that isn't
                            // actually speaking TLS) shouldn't take the whole
                            // server down, same reasoning as a failed accept
                            // above.
                            return;
                        };
                        serve_tcp_connection(
                            stream,
                            registers,
                            store,
                            coils,
                            coil_store,
                            mem_layout,
                            toml_source,
                            REQUEST_TIMEOUT,
                        )
                        .await;
                    });
                }
            });
        }
        ConnectionTarget::Rtu { path, baud_rate } => {
            let frame_silence = protocol::rtu::frame_silence_for_baud_rate(baud_rate);
            // See client::connection::Connection::open_rtu: tokio-serial
            // registers the file descriptor with the reactor immediately at
            // open time, so opening it needs an active runtime context even
            // though this isn't an async call.
            let stream = {
                let _guard = runtime.handle().enter();
                tokio_serial::new(&path, baud_rate)
                    .open_native_async()
                    .unwrap_or_else(|error| panic!("failed to open serial port {path:?}: {error}"))
            };
            // Unlike TCP, there's only ever one of these — the physical
            // serial link itself — so just one spawned task, not an
            // accept-and-spawn-per-connection loop.
            runtime.spawn(async move {
                serve_rtu_connection(
                    stream,
                    registers,
                    store,
                    coils,
                    coil_store,
                    mem_layout,
                    toml_source,
                    frame_silence,
                    REQUEST_TIMEOUT,
                )
                .await;
            });
        }
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

    let toml_source = std::fs::read_to_string(&device_description_path)
        .unwrap_or_else(|error| panic!("failed to read {device_description_path}: {error}"));
    let description = DeviceDescription::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {device_description_path}: {error}"));
    let registers = description.registers;
    let coils = description.coils;
    let mem_layout = description.mem_layout;

    let store = Arc::new(Mutex::new(RegisterStore::new()));
    let coil_store = Arc::new(Mutex::new(CoilStore::new()));
    let report = Arc::new(Mutex::new(WriteReport::new()));
    let (transaction_sender, transaction_receiver) = mpsc::channel();

    let consumer_store = Arc::clone(&store);
    let consumer_coil_store = Arc::clone(&coil_store);
    let consumer_report = Arc::clone(&report);
    std::thread::spawn(move || {
        run_transaction_consumer(
            &consumer_store,
            &consumer_coil_store,
            &consumer_report,
            transaction_receiver,
        );
    });

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");
    start_serving(
        &runtime,
        &connection_string,
        Arc::new(registers.clone()),
        Arc::clone(&store),
        Arc::new(coils.clone()),
        Arc::clone(&coil_store),
        mem_layout,
        Arc::new(toml_source.clone()),
    );

    std::fs::create_dir_all(&mountpoint).ok();
    println!("Mounting infused_modbus server at {mountpoint}, serving via {connection_string}");

    let filesystem = InfusedFilesystem::new(
        registers,
        coils,
        store,
        coil_store,
        transaction_sender,
        report,
        Some(Arc::new(Mutex::new(
            fuse_fs::client_trust::ClientTrustState::new(),
        ))),
    );
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
