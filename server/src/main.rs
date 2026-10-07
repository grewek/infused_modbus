// Modbus slave: serves real Modbus masters over TCP or RTU (see
// `<connection>` below) and exposes its own data over MQTT/Sparkplug B (see
// CLAUDE.md's "MQTT (Sparkplug B) representation layer" section) — no
// filesystem of any kind. This process's own RegisterStore is the
// authoritative state being served — an external Modbus write applies
// directly (see server/src/handler.rs), and a local write via the data
// socket (see server_handle.rs/data_daemon.rs) applies directly too —
// unlike the client, there's no separate real device to round-trip with, so
// there's no "wait for confirmation" step on either side.
//
// Usage:
//   cargo run -p server -- <device-description.toml> <connection>
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

use protocol::connection_string::{ConnectionTarget, parse_connection_string};
use protocol::device_description::DeviceDescription;
use protocol::device_description_manifest::ManifestMachine;
use server::connection::{serve_rtu_connection, serve_tcp_connection};
use server::fc43_bulk_transfer::Fc43BulkTransfer;
use server::handler::ServerMachineState;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_serial::SerialPortBuilderExt;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
// Separate from REQUEST_TIMEOUT (Milestone U1): a peer that opens a TCP
// connection but never completes the TLS handshake (or drags it out
// deliberately) would otherwise tie up an accepted connection and its
// spawned task indefinitely — this bounds that specific window, distinct
// from the per-I/O-step timeout that only starts once a connection is
// already serving real Modbus PDUs.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// Milestone U2: bounds how many TLS connections (handshaking or already
// serving) may exist at once, so an attacker opening far more connections
// than any real deployment would ever need can't exhaust file
// descriptors/threads by holding them all open simultaneously. Deliberately
// a fixed constant, not yet CLI-configurable — see U1/U3's own constants
// for the same precedent. A distributed flood from many source addresses
// is explicitly out of scope for this application layer (CLAUDE.md).
const MAX_CONCURRENT_TLS_CONNECTIONS: usize = 100;
// Milestone U3: bounds how many connections a single approved fingerprint
// may hold open at once, independent of MAX_CONCURRENT_TLS_CONNECTIONS —
// so an already-approved but compromised or buggy client can't exhaust the
// whole connection pool by itself. A legitimate client normally holds
// exactly one persistent connection; this leaves headroom for e.g. brief
// reconnect overlap without allowing unbounded growth.
const MAX_CONNECTIONS_PER_FINGERPRINT: usize = 5;
const TLS_IDENTITY_DIRECTORY: &str = "server-tls-identity";
const ADMIN_SOCKET_PATH: &str = "server-admin.sock";
const APPROVED_CLIENTS_PATH: &str = "approved-clients.toml";
// Fixed, not yet CLI-configurable — same precedent as ADMIN_SOCKET_PATH
// above.
const DATA_SOCKET_PATH: &str = "server-data.sock";

fn usage() -> ! {
    eprintln!(
        "Usage: server <device-description.toml> <connection> [--max-clients <n>] [--server-options <server-options.toml>]\n\
         <connection> is tcp://<bind-address:port>, tls+tcp://<bind-address:port>, or rtu://<serial-path>:<baud-rate>\n\
         --max-clients bounds how many TLS client fingerprints can be approved at once \
         (tls+tcp:// only) — without it, there is no limit.\n\
         --server-options explicitly enables function codes this server will answer — \
         without it (or with an empty file), every function code is disabled and every \
         request gets ILLEGAL_FUNCTION.\n\
         \n\
         Usage: server admin approve|revoke <fingerprint>\n\
         Usage: server admin list"
    );
    std::process::exit(1);
}

/// Pulls `--max-clients <n>` out of `args` if present (order-independent),
/// leaving the rest of `args` untouched. Absent entirely, `None` means
/// unlimited (see `ApprovedClients::new`).
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

/// Pulls `--server-options <path>` out of `args` if present
/// (order-independent), leaving the rest of `args` untouched. Absent
/// entirely, behaves exactly like a present-but-empty file
/// (`ServerOptions::default()`) — every function code disabled, not a
/// startup error (CLAUDE.md's "server-options.toml" section).
fn extract_server_options(args: &mut Vec<String>) -> server::server_options::ServerOptions {
    let Some(flag_index) = args.iter().position(|arg| arg == "--server-options") else {
        return server::server_options::ServerOptions::default();
    };
    if flag_index + 1 >= args.len() {
        panic!("--server-options requires a path");
    }
    args.remove(flag_index);
    let path = args.remove(flag_index);
    let toml_source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    server::server_options::ServerOptions::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
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
    server_options: server::server_options::ServerOptions,
    machines: Arc<HashMap<u8, ServerMachineState>>,
    toml_source: Arc<String>,
    fc43_bulk_transfer: Arc<Fc43BulkTransfer>,
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
                    let machines = Arc::clone(&machines);
                    let toml_source = Arc::clone(&toml_source);
                    let fc43_bulk_transfer = Arc::clone(&fc43_bulk_transfer);
                    tokio::spawn(async move {
                        serve_tcp_connection(
                            stream,
                            server_options,
                            machines,
                            toml_source,
                            fc43_bulk_transfer,
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
            let server_config = server::tls::build_server_config(&identity, approved_clients)
                .unwrap_or_else(|error| panic!("failed to build TLS server config: {error}"));
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            let listener = runtime
                .block_on(TcpListener::bind(&bind_address))
                .unwrap_or_else(|error| panic!("failed to bind {bind_address}: {error}"));
            // Milestone U2: one permit per connection, held for its entire
            // lifetime (handshake + serving), not just the handshake — an
            // already-authenticated connection still consumes a file
            // descriptor/task for as long as it stays open.
            let connection_semaphore =
                Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TLS_CONNECTIONS));
            runtime.spawn(async move {
                loop {
                    let (tcp_stream, _peer_address) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(_) => continue,
                    };
                    let acceptor = acceptor.clone();
                    let machines = Arc::clone(&machines);
                    let toml_source = Arc::clone(&toml_source);
                    let fc43_bulk_transfer = Arc::clone(&fc43_bulk_transfer);
                    let live_connections = Arc::clone(&live_connections);
                    let connection_semaphore = Arc::clone(&connection_semaphore);
                    tokio::spawn(async move {
                        // At the global concurrent-connection cap: drop
                        // this connection outright (closing `tcp_stream` by
                        // letting it go out of scope) rather than queuing
                        // it — queuing would still let an attacker hold
                        // arbitrarily many pending sockets open while
                        // waiting for a permit, defeating the point of a
                        // hard cap. `_permit`'s scope is this whole async
                        // block, so it's held for the connection's entire
                        // lifetime, released automatically once this task
                        // ends (handshake failure/timeout, normal
                        // completion, or revocation).
                        let Ok(_permit) = connection_semaphore.try_acquire_owned() else {
                            return;
                        };
                        // Covers both a failed handshake (e.g. a peer that
                        // isn't actually speaking TLS) and one that never
                        // completed within TLS_HANDSHAKE_TIMEOUT (Milestone
                        // U1, e.g. a peer that opens the connection and then
                        // sends nothing) — neither should take the whole
                        // server down, same reasoning as a failed accept
                        // above.
                        let Some(stream) = server::tls::accept_with_timeout(
                            &acceptor,
                            tcp_stream,
                            TLS_HANDSHAKE_TIMEOUT,
                        )
                        .await
                        else {
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
                                server_options,
                                machines,
                                toml_source,
                                fc43_bulk_transfer,
                                REQUEST_TIMEOUT,
                            )
                            .await;
                            return;
                        };
                        // Already at MAX_CONNECTIONS_PER_FINGERPRINT for
                        // this fingerprint (Milestone U3) — drop this
                        // connection outright, same reasoning as the
                        // global cap (U2): an already-approved but
                        // compromised or buggy client shouldn't be able to
                        // exhaust the whole connection pool by itself.
                        let Some((handle, cancelled)) =
                            live_connections.lock().unwrap().register(fingerprint)
                        else {
                            return;
                        };
                        tokio::select! {
                            _ = serve_tcp_connection(
                                stream,
                                server_options,
                                machines,
                                toml_source,
                                fc43_bulk_transfer,
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
                    server_options,
                    machines,
                    toml_source,
                    fc43_bulk_transfer,
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
    let max_clients = extract_max_clients(&mut raw_args);
    let server_options = extract_server_options(&mut raw_args);
    let mut args = raw_args.into_iter();
    let Some(first_argument) = args.next() else {
        usage();
    };
    if first_argument == "admin" {
        run_admin_subcommand(args);
        return;
    }
    // "The server starts fine but answers nothing" is a real footgun for a
    // forgotten/empty --server-options file — every function code defaults
    // to disabled (CLAUDE.md's "server-options.toml" section), so a
    // technician who didn't mean that needs to notice immediately, not
    // after wondering why every real Modbus master gets ILLEGAL_FUNCTION.
    // Checked here rather than right after extraction, since the `admin`
    // subcommand above never actually serves anything and has no use for
    // this warning.
    if !server_options.any_enabled() {
        eprintln!(
            "WARNING: no function codes are enabled (see --server-options) — \
             this server will answer ILLEGAL_FUNCTION to every request."
        );
    }
    let device_description_path = first_argument;
    let Some(connection_string) = args.next() else {
        usage();
    };

    let toml_source = std::fs::read_to_string(&device_description_path)
        .unwrap_or_else(|error| panic!("failed to read {device_description_path}: {error}"));
    let description = DeviceDescription::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {device_description_path}: {error}"));

    // Built once, here, at startup — not per FC43 request (see
    // fc43_bulk_transfer's own doc comment on why that matters: DEFLATE
    // compression of the whole description is real CPU work whose result
    // never changes afterward). Only ever consulted by
    // handle_encapsulated_interface_transport once the real `toml_source`
    // doesn't fit FC43's own inline-chunk budget, and only once
    // `detect_machine_layout` is on — but it's unconditionally built
    // regardless of that toggle, since the common case (a small
    // description) makes this trivially cheap anyway.
    let fc43_bulk_transfer = Arc::new(Fc43BulkTransfer::build(
        &toml_source,
        description
            .machines
            .iter()
            .map(|machine| ManifestMachine {
                name: machine.name.clone(),
                unit_id: machine.unit_id,
            })
            .collect(),
    ));

    // One fresh set of stores per configured machine, name-keyed — shared
    // by the wire-facing Modbus handler (via `machines` below) and
    // `ServerHandle`'s own direct store access (further down). See
    // datafs::build_machine_stores.
    let machine_stores: HashMap<String, datafs::MachineStores> =
        datafs::build_machine_stores(&description.machines);

    // Unit-ID-keyed, separate from `machine_stores` above (which is
    // name-keyed) — this is what `handle_request`/`start_serving` use to
    // route an incoming request's `unit_id` to the right machine's static
    // descriptions and stores. Two different keys for two different
    // purposes: `machine_stores` by name (`ServerHandle`'s direct store
    // access), `machines` by unit_id (wire dispatch).
    let machines: Arc<HashMap<u8, ServerMachineState>> = Arc::new(
        description
            .machines
            .iter()
            .map(|machine| {
                let stores = &machine_stores[&machine.name];
                (
                    machine.unit_id,
                    ServerMachineState {
                        registers: Arc::new(machine.registers.clone()),
                        store: Arc::clone(&stores.registers),
                        coils: Arc::new(machine.coils.clone()),
                        coil_store: Arc::clone(&stores.coils),
                        discrete_inputs: Arc::new(machine.discrete_inputs.clone()),
                        discrete_input_store: Arc::clone(&stores.discrete_inputs),
                        input_registers: Arc::new(machine.input_registers.clone()),
                        input_register_store: Arc::clone(&stores.input_registers),
                        file_records: Arc::new(machine.file_records.clone()),
                        file_record_store: Arc::clone(&stores.file_records),
                        mem_layout: machine.mem_layout,
                        input_register_mem_layout: machine.input_register_mem_layout,
                        server_id: machine.server_id.clone(),
                    },
                )
            })
            .collect(),
    );

    // Shared between the TLS client-cert verifier (which enforces it) and
    // the admin socket below (which is the only thing that ever mutates
    // it). `--max-clients` is stored here too.
    let mut approved_clients = match max_clients {
        Some(max_clients) => server::client_trust::ApprovedClients::with_max_clients(max_clients),
        None => server::client_trust::ApprovedClients::new(),
    };
    // Seeded from disk (Milestone S1) — `seed` bypasses the `--max-clients`
    // check deliberately, see its own doc comment: a fingerprint approved
    // before this restart must not silently vanish just because the limit
    // was lowered in the meantime. Read once, here, at startup only — see
    // server::persistence's module doc comment for why this file is never
    // hot-reloaded afterwards.
    let approved_clients_path = Path::new(APPROVED_CLIENTS_PATH);
    for fingerprint in server::persistence::load(approved_clients_path)
        .unwrap_or_else(|error| panic!("failed to load {approved_clients_path:?}: {error}"))
    {
        approved_clients.seed(fingerprint);
    }
    let approved_clients = Arc::new(Mutex::new(approved_clients));
    // Shared between the TLS accept loop (which registers/deregisters each
    // connection as it opens/closes) and the admin socket below (which
    // calls `revoke` on it) — see Milestone R: `REVOKE` must terminate an
    // already-open connection, not just block future handshakes.
    // `with_max_connections_per_fingerprint` (Milestone U3) additionally
    // rejects a *new* registration once one fingerprint already holds this
    // many connections open, independent of U2's global cap.
    let live_connections = Arc::new(Mutex::new(
        server::live_connections::LiveConnections::with_max_connections_per_fingerprint(
            MAX_CONNECTIONS_PER_FINGERPRINT,
        ),
    ));

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");

    // Always served, regardless of connection type — approving/revoking
    // clients is meaningful only under tls+tcp://, but the admin channel
    // that manages them runs unconditionally rather than depending on which
    // transport was chosen.
    runtime.spawn({
        let approved_clients = Arc::clone(&approved_clients);
        let live_connections = Arc::clone(&live_connections);
        async move {
            if let Err(error) = server::admin::run_admin_socket(
                Path::new(ADMIN_SOCKET_PATH),
                approved_clients,
                live_connections,
                approved_clients_path.to_path_buf(),
            )
            .await
            {
                eprintln!("admin socket at {ADMIN_SOCKET_PATH} failed: {error}");
            }
        }
    });

    let toml_source = Arc::new(toml_source);

    start_serving(
        &runtime,
        &connection_string,
        server_options,
        Arc::clone(&machines),
        Arc::clone(&toml_source),
        Arc::clone(&fc43_bulk_transfer),
        approved_clients,
        live_connections,
    );

    let machine_names: Vec<&str> = description
        .machines
        .iter()
        .map(|machine| machine.name.as_str())
        .collect();
    println!(
        "Starting infused_modbus server, serving via {connection_string} — machines: {}",
        machine_names.join(", ")
    );

    // No filesystem tree at all, just ServerHandle behind a local Unix
    // socket — see server::server_handle/data_daemon. Reads the same
    // machine_stores the wire-facing Modbus handler in handler.rs already
    // always writes into, so an external Modbus master's write and a SET
    // over this socket are always looking at the same data.
    let server_handle = Arc::new(server::server_handle::ServerHandle::new(
        &description.machines,
        &machine_stores,
    ));
    runtime.spawn({
        let server_handle = Arc::clone(&server_handle);
        async move {
            if let Err(error) =
                server::data_daemon::run_data_socket(Path::new(DATA_SOCKET_PATH), server_handle)
                    .await
            {
                eprintln!("data socket at {DATA_SOCKET_PATH} failed: {error}");
            }
        }
    });
    println!("Data socket listening at {DATA_SOCKET_PATH}");

    wait_for_shutdown_signal(&runtime);
}

fn wait_for_shutdown_signal(runtime: &tokio::runtime::Runtime) {
    runtime.block_on(async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => println!("Received Ctrl+C, shutting down..."),
            _ = sigterm.recv() => println!("Received SIGTERM, shutting down..."),
        }
    });
}
