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
//   cargo run -p server -- admin approve|revoke <fingerprint>
//   cargo run -p server -- admin list
//
// <connection> is one of:
//   tcp://<bind-address:port>          e.g. tcp://0.0.0.0:502
//   rtu://<serial-path>:<baud-rate>    e.g. rtu:///dev/ttyUSB0:9600
//   tls+tcp://<bind-address:port>      e.g. tls+tcp://0.0.0.0:502
//
// tls+tcp:// requires a client certificate and checks its fingerprint
// against an approved set (see server::tls::build_server_config /
// server::client_trust::ApprovedClients). The set is seeded at startup from
// APPROVED_CLIENTS_PATH below (Milestone S1; empty if the file doesn't
// exist yet — see server::persistence) and is populated via the `admin`
// subcommand above, which talks to a Unix domain socket
// (ADMIN_SOCKET_PATH below, fixed and not yet CLI-configurable) that this
// process always serves in the background, regardless of which connection
// type it was started with — the same "always present regardless of
// transport" precedent as the FUSE `client-trust/` subtree itself. The
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
const ADMIN_SOCKET_PATH: &str = "server-admin.sock";
const APPROVED_CLIENTS_PATH: &str = "approved-clients.toml";

fn usage() -> ! {
    eprintln!(
        "Usage: server <mountpoint> <device-description.toml> <connection> [--fuse-permissions <fuse-permissions.toml>] [--max-clients <n>]\n\
         <connection> is tcp://<bind-address:port>, tls+tcp://<bind-address:port>, or rtu://<serial-path>:<baud-rate>\n\
         --fuse-permissions sets custom mode/uid/gid per top-level FUSE directory — \
         without it, every directory keeps its historical hardcoded behavior.\n\
         --max-clients bounds how many TLS client fingerprints can be approved at once \
         (tls+tcp:// only) — without it, there is no limit.\n\
         \n\
         Usage: server admin approve|revoke <fingerprint>\n\
         Usage: server admin list"
    );
    std::process::exit(1);
}

/// Pulls `--fuse-permissions <path>` out of `args` if present
/// (order-independent), leaving the rest of `args` untouched. Absent
/// entirely, every directory keeps its historical hardcoded behavior
/// (`FusePermissions::default()`). Extracted before the `admin` subcommand
/// check, so it's harmless (simply unused) if given alongside `admin`.
fn extract_fuse_permissions(args: &mut Vec<String>) -> fuse_fs::permissions::FusePermissions {
    let Some(flag_index) = args.iter().position(|arg| arg == "--fuse-permissions") else {
        return fuse_fs::permissions::FusePermissions::default();
    };
    if flag_index + 1 >= args.len() {
        panic!("--fuse-permissions requires a path");
    }
    args.remove(flag_index);
    let path = args.remove(flag_index);
    let toml_source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    fuse_fs::permissions::FusePermissions::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
}

/// Pulls `--max-clients <n>` out of `args` if present (order-independent,
/// same shape as `--fuse-permissions`), leaving the rest of `args`
/// untouched. Absent entirely, `None` means unlimited — matches every
/// pre-Q server's behavior exactly (see `ApprovedClients::new`).
fn extract_max_clients(args: &mut Vec<String>) -> Option<usize> {
    let flag_index = args.iter().position(|arg| arg == "--max-clients")?;
    if flag_index + 1 >= args.len() {
        panic!("--max-clients requires a value");
    }
    args.remove(flag_index);
    let value = args.remove(flag_index);
    Some(
        value
            .parse()
            .unwrap_or_else(|error| panic!("invalid --max-clients value {value:?}: {error}")),
    )
}

fn admin_usage() -> ! {
    eprintln!("Usage: server admin approve|revoke <fingerprint>\nUsage: server admin list");
    std::process::exit(1);
}

/// Handles the `server admin approve|revoke|list [<fingerprint>]`
/// subcommand (P4): translates it into one line of the admin protocol,
/// sends it over ADMIN_SOCKET_PATH via `server::admin::send_admin_command`,
/// and prints the response — a technician never has to speak the raw
/// protocol (`APPROVE <fp>` / `REVOKE <fp>` / `LIST`) by hand.
fn run_admin_subcommand(mut args: impl Iterator<Item = String>) {
    let Some(verb) = args.next() else {
        admin_usage();
    };
    let command = match verb.as_str() {
        "approve" | "revoke" => {
            let Some(fingerprint) = args.next() else {
                admin_usage();
            };
            format!("{} {fingerprint}", verb.to_uppercase())
        }
        "list" => "LIST".to_string(),
        _ => admin_usage(),
    };

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");
    let response = runtime
        .block_on(server::admin::send_admin_command(
            Path::new(ADMIN_SOCKET_PATH),
            &command,
        ))
        .unwrap_or_else(|error| {
            panic!("failed to talk to the admin socket at {ADMIN_SOCKET_PATH}: {error}")
        });
    println!("{response}");
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
    client_trust: Arc<Mutex<fuse_fs::client_trust::ClientTrustState>>,
    approved_clients: Arc<Mutex<server::client_trust::ApprovedClients>>,
    live_connections: Arc<Mutex<server::live_connections::LiveConnections>>,
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
            // Shared with the admin socket (see main()) so `server admin
            // approve|revoke` actually changes who this verifier accepts —
            // starts empty on every run (not persisted yet, Milestone S),
            // so tls+tcp:// is fail-closed against every client until at
            // least one has been approved via the admin subcommand.
            let server_config = server::tls::build_server_config(
                &identity,
                approved_clients,
                Arc::clone(&client_trust),
            )
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
                    let live_connections = Arc::clone(&live_connections);
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(tcp_stream).await else {
                            // A failed handshake (e.g. a peer that isn't
                            // actually speaking TLS) shouldn't take the whole
                            // server down, same reasoning as a failed accept
                            // above.
                            return;
                        };
                        // mTLS is mandatory (build_server_config), so a
                        // completed handshake always presented and verified
                        // a client certificate — `None` here would mean
                        // that invariant broke somehow; served but
                        // untracked (unrevocable) rather than dropped, same
                        // "don't take the connection down over this"
                        // reasoning as the failed-accept/-handshake cases
                        // above.
                        let fingerprint = {
                            let (_io, connection) = stream.get_ref();
                            server::tls::peer_fingerprint(connection)
                        };
                        let Some(fingerprint) = fingerprint else {
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
                            return;
                        };
                        let (handle, cancelled) =
                            live_connections.lock().unwrap().register(fingerprint);
                        tokio::select! {
                            _ = serve_tcp_connection(
                                stream,
                                registers,
                                store,
                                coils,
                                coil_store,
                                mem_layout,
                                toml_source,
                                REQUEST_TIMEOUT,
                            ) => {}
                            // Resolves once `server admin revoke` drops this
                            // connection's sender (Milestone R) — dropping
                            // `stream` here (as the select branch exits)
                            // closes the TCP connection, actually
                            // terminating it rather than just marking it
                            // revoked somewhere.
                            _ = cancelled => {}
                        }
                        live_connections.lock().unwrap().deregister(handle);
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
    let mut raw_args: Vec<String> = std::env::args().skip(1).collect();
    let fuse_permissions = extract_fuse_permissions(&mut raw_args);
    let max_clients = extract_max_clients(&mut raw_args);
    let mut args = raw_args.into_iter();
    let Some(first_argument) = args.next() else {
        usage();
    };
    if first_argument == "admin" {
        run_admin_subcommand(args);
        return;
    }
    let mountpoint = first_argument;
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

    // Shared between the TLS handshake path (which logs connection
    // attempts and, later, checks approvals) and the FUSE `client-trust/`
    // subtree (which displays that same state) — one `ClientTrustState`,
    // not two independently-populated copies. See O2's "known gap" note:
    // this is what closes it.
    let client_trust = Arc::new(Mutex::new(fuse_fs::client_trust::ClientTrustState::new()));
    // Shared between the TLS client-cert verifier (which enforces it) and
    // the admin socket below (which is the only thing that ever mutates
    // it) — same one-writer-per-piece-of-state precedent as `client_trust`
    // just above. `--max-clients` (Milestone Q) is stored here too.
    let mut approved_clients = match max_clients {
        Some(max_clients) => server::client_trust::ApprovedClients::with_max_clients(max_clients),
        None => server::client_trust::ApprovedClients::new(),
    };
    // Seeded from disk (Milestone S1) — `seed` bypasses the `--max-clients`
    // check deliberately, see its own doc comment: a fingerprint approved
    // before this restart must not silently vanish just because the limit
    // was lowered in the meantime. Read once, here, at startup only — see
    // server::persistence's module doc comment for why this file is never
    // hot-reloaded afterwards. Also seeds `client_trust`'s own mirror in
    // the same loop — otherwise `admin list`/`client-trust/approved/`
    // would show nothing approved right after a restart even though the
    // TLS verifier (which only consults `approved_clients`) would already
    // accept a previously-approved client; the same "two stores, one
    // writer" discipline O2/P2 established for the admin channel applies
    // here too.
    let approved_clients_path = Path::new(APPROVED_CLIENTS_PATH);
    for fingerprint in server::persistence::load(approved_clients_path)
        .unwrap_or_else(|error| panic!("failed to load {approved_clients_path:?}: {error}"))
    {
        approved_clients.seed(fingerprint);
        client_trust
            .lock()
            .unwrap()
            .insert_approved(fingerprint.to_string());
    }
    let approved_clients = Arc::new(Mutex::new(approved_clients));
    // Shared between the TLS accept loop (which registers/deregisters each
    // connection as it opens/closes) and the admin socket below (which
    // calls `revoke` on it) — see Milestone R: `REVOKE` must terminate an
    // already-open connection, not just block future handshakes.
    let live_connections = Arc::new(Mutex::new(server::live_connections::LiveConnections::new()));

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");

    // Always served, regardless of connection type — approving/revoking
    // clients is meaningful only under tls+tcp://, but `client-trust/`'s
    // FUSE presence is likewise unconditional (see fuse-fs O1), so the
    // admin channel that manages it follows the same precedent rather than
    // depending on which transport was chosen.
    runtime.spawn({
        let approved_clients = Arc::clone(&approved_clients);
        let client_trust = Arc::clone(&client_trust);
        let live_connections = Arc::clone(&live_connections);
        async move {
            if let Err(error) = server::admin::run_admin_socket(
                Path::new(ADMIN_SOCKET_PATH),
                approved_clients,
                client_trust,
                live_connections,
            )
            .await
            {
                eprintln!("admin socket at {ADMIN_SOCKET_PATH} failed: {error}");
            }
        }
    });

    start_serving(
        &runtime,
        &connection_string,
        Arc::new(registers.clone()),
        Arc::clone(&store),
        Arc::new(coils.clone()),
        Arc::clone(&coil_store),
        mem_layout,
        Arc::new(toml_source.clone()),
        Arc::clone(&client_trust),
        approved_clients,
        live_connections,
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
        Some(client_trust),
        fuse_permissions,
    );
    // default_permissions makes the kernel actually enforce what getattr
    // reports (see fuse_fs::permissions) instead of every request being
    // allowed regardless of mode/uid/gid.
    let mut mount_config = fuser::Config::default();
    mount_config.mount_options = vec![fuser::MountOption::DefaultPermissions];
    let session = fuser::spawn_mount(filesystem, &mountpoint, &mount_config)
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
