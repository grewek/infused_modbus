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
//   cargo run -p client -- <root> <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>] [--fuse-permissions <fuse-permissions.toml>] [--data-representation-layer fuse|files]
//
// --data-representation-layer picks how the machines' data is exposed:
// "files" (the default, see CLAUDE.md's "Planned: pluggable data-
// representation layer") writes real files under <root>, updated via
// atomic rename() and a background inotify watch on transactions/ — no
// FUSE driver involved at all. "fuse" mounts <root> as a synthetic FUSE
// filesystem, this project's original mechanism. Both present the exact
// same directory shape at <root>.
//
// --fuse-permissions sets custom mode/uid/gid for holding-registers/,
// transactions/, report/, and coils/ (see datafs::permissions) — under
// "fuse", enforced by the kernel via the `default_permissions` mount
// option; under "files", applied as real chmod/chown on the underlying
// directories (datafs::flatfile::apply_directory_permissions). Without
// it, every directory keeps its historical hardcoded behavior (mode
// 0o755, owned by whichever uid/gid made a given FUSE request, or the
// process's own real uid/gid under "files").
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
// One persistent connection is shared between polling and writes. If it
// breaks (server restart, network blip, unplugged serial adapter, ...),
// client::reconnect's dedicated background task notices (via polling, which
// runs continuously regardless of write activity) and redials with
// exponential backoff, retrying forever — see client/src/reconnect.rs's own
// doc comment. RTU's serial parameters beyond baud rate (data bits, parity,
// stop bits) aren't configurable yet — this uses tokio-serial's defaults (8
// data bits, no parity, 1 stop bit).

use client::broker::BrokerConfig;
use client::connection::Connection;
use client::device_identification::fetch_device_description;
use client::edge_node::connect_edge_node;
use client::polling::run_polling_loop;
use client::reconnect::{ReconnectSignal, run_reconnect_loop};
use client::sparkplug_alias::AliasAllocator;
use client::sparkplug_change_tracker::ChangeTracker;
use client::sparkplug_command::{run_dcmd_forwarder, run_rebirth_handler};
use client::sparkplug_translator::build_machine_metrics;
use client::transaction_consumer::{MachineTransactionConfig, run_transaction_consumer};
use datafs::filesystem::{InfusedFilesystem, WriteMode};
use protocol::connection_string::{ConnectionTarget, parse_connection_string};
use protocol::device_description::DeviceDescription;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

const DEFAULT_UNIT_ID: u8 = 1;
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const CLIENT_TLS_IDENTITY_DIRECTORY: &str = "client-tls-identity";
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(5);
const DEVICE_DESCRIPTION_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
// A technician deploying more than one `client` instance against the same
// broker/host application must override this — left as a plain, obviously-
// generic default rather than something that looks unique (e.g. a random
// suffix), so it's not mistaken for something already made unique for them.
const DEFAULT_MQTT_GROUP_ID: &str = "infused_modbus";
const DEFAULT_MQTT_EDGE_NODE_ID: &str = "client";
// How long to wait after starting the embedded broker before connecting to
// it as the Edge Node's own loopback client — `start_embedded_broker`
// returns as soon as the listener thread is spawned, not once it's actually
// accepting connections (see client::broker's own doc comment), so without
// this the very first connection attempt can race a broker that isn't
// listening yet. Mirrors the same wait every `client::edge_node`/
// `client::sparkplug_command` test already uses against a freshly started
// embedded broker.
const BROKER_STARTUP_GRACE_PERIOD: Duration = Duration::from_millis(300);
// Persists this Edge Node's next bdSeq across process restarts — see
// client::bd_seq_persistence's own module doc comment for why this is
// required for real Sparkplug B conformance, not just a nice-to-have.
const MQTT_BD_SEQ_PATH: &str = "client-mqtt-bdseq";

fn usage() -> ! {
    eprintln!(
        "Usage: client <root> <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>] [--fuse-permissions <fuse-permissions.toml>] [--data-representation-layer fuse|files|mqtt] [--mqtt-broker-config <path.toml>] [--mqtt-group-id <id>] [--mqtt-edge-node-id <id>] [--mqtt-external-broker <host:port>] [--mqtt-primary-host-id <id>]\n\
         <connection> is tcp://<address:port>, tls+tcp://<address:port>, or rtu://<serial-path>:<baud-rate>\n\
         --expect-server-fingerprint pins the server's TLS identity (tls+tcp:// only) — \
         without it, the server's identity is not verified at all (see CLAUDE.md's TLS design).\n\
         --fuse-permissions sets custom mode/uid/gid per top-level directory — \
         without it, every directory keeps its historical hardcoded behavior. Ignored under \
         --data-representation-layer mqtt, which has no directories to permission.\n\
         --data-representation-layer picks fuse (a synthetic FUSE mount), files \
         (real files, the default), or mqtt (a Sparkplug B Edge Node over an embedded MQTT \
         broker — see CLAUDE.md's \"Planned: MQTT (Sparkplug B) representation layer\"). \
         <root> is ignored under mqtt, which has nothing to mount/write to disk.\n\
         --mqtt-broker-config sets the embedded broker's tuning (listen address, connection \
         limits, ...) — without it, every setting keeps client::broker::BrokerConfig's own \
         defaults. mqtt layer only.\n\
         --mqtt-group-id/--mqtt-edge-node-id set this Edge Node's Sparkplug B identity \
         (defaults: {DEFAULT_MQTT_GROUP_ID:?}/{DEFAULT_MQTT_EDGE_NODE_ID:?} — override \
         --mqtt-edge-node-id for any deployment running more than one client instance against \
         the same broker/host application, since it must be unique per Edge Node). mqtt layer \
         only.\n\
         --mqtt-external-broker <host:port> connects the Edge Node to an already-running \
         broker instead of starting the embedded one (--mqtt-broker-config is then ignored) — \
         for targeting an external broker such as the Sparkplug TCK's own HiveMQ instance. \
         mqtt layer only.\n\
         --mqtt-primary-host-id <id> makes this Edge Node wait for the named Primary Host \
         Application to come online (via its retained spBv1.0/STATE/<id> message) before \
         publishing NBIRTH — without it, NBIRTH is published immediately, with no Primary Host \
         awareness at all (the common case). mqtt layer only."
    );
    std::process::exit(1);
}

/// Pulls `--data-representation-layer <fuse|files|mqtt>` out of `args` if
/// present (order-independent, same shape as `--fuse-permissions`), leaving
/// the rest of `args` untouched. Absent entirely, defaults to `Files` — a
/// deliberate breaking change to this project's original all-FUSE default,
/// same "explicit/simple over preserving existing behavior while nothing
/// is deployed" stance as every other breaking default in this project.
fn extract_representation_layer(args: &mut Vec<String>) -> RepresentationLayer {
    let Some(flag_index) = args
        .iter()
        .position(|arg| arg == "--data-representation-layer")
    else {
        return RepresentationLayer::Files;
    };
    if flag_index + 1 >= args.len() {
        panic!("--data-representation-layer requires a value (fuse, files, or mqtt)");
    }
    args.remove(flag_index);
    let value = args.remove(flag_index);
    match value.as_str() {
        "fuse" => RepresentationLayer::Fuse,
        "files" => RepresentationLayer::Files,
        "mqtt" => RepresentationLayer::Mqtt,
        other => panic!(
            "invalid --data-representation-layer value {other:?}: expected fuse, files, or mqtt"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepresentationLayer {
    Fuse,
    Files,
    Mqtt,
}

/// Pulls `--mqtt-broker-config <path.toml>` out of `args` if present (same
/// shape as `--fuse-permissions`), leaving the rest of `args` untouched.
/// Absent entirely, every broker setting keeps `BrokerConfig::default()`.
fn extract_mqtt_broker_config(args: &mut Vec<String>) -> BrokerConfig {
    let Some(flag_index) = args.iter().position(|arg| arg == "--mqtt-broker-config") else {
        return BrokerConfig::default();
    };
    if flag_index + 1 >= args.len() {
        panic!("--mqtt-broker-config requires a path");
    }
    args.remove(flag_index);
    let path = args.remove(flag_index);
    let toml_source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    BrokerConfig::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
}

/// Pulls `--mqtt-external-broker <host:port>` out of `args` if present,
/// leaving the rest of `args` untouched. Absent entirely, `None` means "use
/// the embedded broker" (the normal case). Exists for situations where the
/// Edge Node must connect to a broker this process doesn't own itself —
/// concretely, the Eclipse Sparkplug TCK's own HiveMQ instance, which the
/// conformance test drives directly rather than observing traffic through
/// our own embedded `rumqttd`. `--mqtt-broker-config` is silently ignored
/// when this is set, since there is no embedded broker left to configure.
fn extract_mqtt_external_broker(args: &mut Vec<String>) -> Option<(String, u16)> {
    let flag_index = args
        .iter()
        .position(|arg| arg == "--mqtt-external-broker")?;
    if flag_index + 1 >= args.len() {
        panic!("--mqtt-external-broker requires a value (host:port)");
    }
    args.remove(flag_index);
    let value = args.remove(flag_index);
    let (host, port) = value.rsplit_once(':').unwrap_or_else(|| {
        panic!("invalid --mqtt-external-broker value {value:?}: expected host:port")
    });
    let port: u16 = port
        .parse()
        .unwrap_or_else(|error| panic!("invalid --mqtt-external-broker port {port:?}: {error}"));
    Some((host.to_string(), port))
}

/// Pulls a single-value flag (e.g. `--mqtt-group-id <id>`) out of `args` if
/// present, leaving the rest of `args` untouched. Shared by
/// `--mqtt-group-id`/`--mqtt-edge-node-id` — both are a bare required string
/// with no parsing beyond "is it present at all".
fn extract_string_flag(args: &mut Vec<String>, flag: &str, default: &str) -> String {
    let Some(flag_index) = args.iter().position(|arg| arg == flag) else {
        return default.to_string();
    };
    if flag_index + 1 >= args.len() {
        panic!("{flag} requires a value");
    }
    args.remove(flag_index);
    args.remove(flag_index)
}

/// Pulls `--mqtt-primary-host-id <id>` out of `args` if present, leaving the
/// rest of `args` untouched. Absent entirely (the common case — most
/// deployments have no Primary Host Application at all), `None` means this
/// Edge Node publishes `NBIRTH` immediately with no Primary Host awareness,
/// exactly as before this flag existed.
fn extract_mqtt_primary_host_id(args: &mut Vec<String>) -> Option<String> {
    let flag_index = args
        .iter()
        .position(|arg| arg == "--mqtt-primary-host-id")?;
    if flag_index + 1 >= args.len() {
        panic!("--mqtt-primary-host-id requires a value");
    }
    args.remove(flag_index);
    Some(args.remove(flag_index))
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

/// Pulls `--fuse-permissions <path>` out of `args` if present
/// (order-independent, same shape as `--expect-server-fingerprint`),
/// leaving the rest of `args` untouched. Absent entirely, every directory
/// keeps its historical hardcoded behavior (`FusePermissions::default()`).
fn extract_fuse_permissions(args: &mut Vec<String>) -> datafs::permissions::FusePermissions {
    let Some(flag_index) = args.iter().position(|arg| arg == "--fuse-permissions") else {
        return datafs::permissions::FusePermissions::default();
    };
    if flag_index + 1 >= args.len() {
        panic!("--fuse-permissions requires a path");
    }
    args.remove(flag_index);
    let path = args.remove(flag_index);
    let toml_source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    datafs::permissions::FusePermissions::parse(&toml_source)
        .unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
}

fn open_connection(
    runtime: &tokio::runtime::Runtime,
    target: &ConnectionTarget,
    expected_server_fingerprint: Option<protocol::tls::Fingerprint>,
) -> Connection {
    if matches!(target, ConnectionTarget::TlsTcp { .. }) {
        // Not yet policed by the server (client approval is milestone N) —
        // presenting it now proves the two-sided mTLS handshake itself
        // works (M2) ahead of any real approval decision. Printed once
        // here at startup, ahead of it actually being presented, so the
        // value's ready before it's needed — `client::reconnect::redial`
        // loads the same persisted identity again on every reconnect
        // attempt but doesn't reprint it, to avoid repeating this on every
        // retry.
        let client_identity = protocol::tls::load_or_generate_identity(std::path::Path::new(
            CLIENT_TLS_IDENTITY_DIRECTORY,
        ))
        .unwrap_or_else(|error| panic!("failed to load/generate client TLS identity: {error}"));
        println!(
            "Client TLS fingerprint: {}",
            protocol::tls::Fingerprint::of(&client_identity.public_key_der)
        );
    }
    runtime
        .block_on(client::reconnect::redial(
            runtime.handle(),
            target,
            expected_server_fingerprint,
            std::path::Path::new(CLIENT_TLS_IDENTITY_DIRECTORY),
        ))
        .unwrap_or_else(|error| panic!("failed to connect via {target:?}: {error}"))
}

fn main() {
    let mut raw_args: Vec<String> = std::env::args().skip(1).collect();
    let expected_server_fingerprint = extract_expected_server_fingerprint(&mut raw_args);
    let fuse_permissions = extract_fuse_permissions(&mut raw_args);
    let representation_layer = extract_representation_layer(&mut raw_args);
    let mqtt_broker_config = extract_mqtt_broker_config(&mut raw_args);
    let mqtt_external_broker = extract_mqtt_external_broker(&mut raw_args);
    let mqtt_group_id =
        extract_string_flag(&mut raw_args, "--mqtt-group-id", DEFAULT_MQTT_GROUP_ID);
    let mqtt_edge_node_id = extract_string_flag(
        &mut raw_args,
        "--mqtt-edge-node-id",
        DEFAULT_MQTT_EDGE_NODE_ID,
    );
    let mqtt_primary_host_id = extract_mqtt_primary_host_id(&mut raw_args);
    let mut args = raw_args.into_iter();
    let Some(root) = args.next() else {
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

    let connection_target =
        parse_connection_string(&connection_string).unwrap_or_else(|error| panic!("{error}"));

    let runtime = tokio::runtime::Runtime::new().expect("failed to start the async runtime");
    let mut connection = open_connection(&runtime, &connection_target, expected_server_fingerprint);

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

    // Shared, not owned outright: the polling loop(s) and the transaction
    // consumer both need to talk to the device over this same connection,
    // and a generic Modbus device/gateway can't be assumed to accept more
    // than one concurrent connection (true for TCP gateways, and doubly
    // true for RTU — one physical serial link, full stop). One connection
    // is shared by every configured machine too — see CLAUDE.md's
    // multi-machine design: a single CLI-supplied connection string, each
    // machine dispatching via its own `unit_id` on that shared link.
    let connection = Arc::new(AsyncMutex::new(connection));

    // Heals `connection` in the background if it ever breaks — see
    // client/src/reconnect.rs's own doc comment. One signal/task per
    // process, shared by every machine's polling task (spawned below) and
    // the transaction consumer, exactly like `connection` itself is.
    let reconnect_signal = Arc::new(ReconnectSignal::new());
    runtime.spawn(run_reconnect_loop(
        Arc::clone(&connection),
        Arc::clone(&reconnect_signal),
        runtime.handle().clone(),
        connection_target,
        expected_server_fingerprint,
        PathBuf::from(CLIENT_TLS_IDENTITY_DIRECTORY),
    ));

    // One fresh set of stores per configured machine — see
    // datafs::build_machine_stores.
    let machine_stores = datafs::build_machine_stores(&description.machines);

    let (transaction_sender, transaction_receiver) = mpsc::channel();

    // One consumer thread services every machine's writes, reading a
    // single shared channel tagged with the originating machine's name
    // (see datafs's multi-machine `InfusedFilesystem` — the same
    // "TRANSACTION_END confirmation semantics" apply per machine).
    let machine_transaction_configs: HashMap<String, MachineTransactionConfig> = description
        .machines
        .iter()
        .map(|machine| {
            let stores = &machine_stores[&machine.name];
            (
                machine.name.clone(),
                MachineTransactionConfig {
                    registers: machine.registers.clone(),
                    coils: machine.coils.clone(),
                    file_records: machine.file_records.clone(),
                    report: Arc::clone(&stores.report),
                    mem_layout: machine.mem_layout,
                    unit_id: machine.unit_id,
                },
            )
        })
        .collect();

    let handle = runtime.handle().clone();
    let consumer_connection = Arc::clone(&connection);
    std::thread::spawn(move || {
        run_transaction_consumer(
            &handle,
            &consumer_connection,
            &machine_transaction_configs,
            transaction_receiver,
            WRITE_TIMEOUT,
        );
    });

    // One polling task per machine — `run_polling_loop` is already fully
    // parameterized per-machine (its own unit_id/descriptions/stores), so
    // multi-machine polling is just spawning it once per configured
    // machine, all sharing the one connection.
    for machine in &description.machines {
        let stores = &machine_stores[&machine.name];
        let polling_connection = Arc::clone(&connection);
        let polling_registers = machine.registers.clone();
        let polling_store = Arc::clone(&stores.registers);
        let polling_coils = machine.coils.clone();
        let polling_coil_store = Arc::clone(&stores.coils);
        let polling_discrete_inputs = machine.discrete_inputs.clone();
        let polling_discrete_input_store = Arc::clone(&stores.discrete_inputs);
        let polling_input_registers = machine.input_registers.clone();
        let polling_input_register_store = Arc::clone(&stores.input_registers);
        let polling_file_records = machine.file_records.clone();
        let polling_file_record_store = Arc::clone(&stores.file_records);
        let mem_layout = machine.mem_layout;
        let input_register_mem_layout = machine.input_register_mem_layout;
        let machine_unit_id = machine.unit_id;
        let polling_reconnect_signal = Arc::clone(&reconnect_signal);
        runtime.spawn(async move {
            run_polling_loop(
                polling_connection,
                &polling_registers,
                polling_store,
                &polling_coils,
                polling_coil_store,
                &polling_discrete_inputs,
                polling_discrete_input_store,
                &polling_input_registers,
                polling_input_register_store,
                &polling_file_records,
                polling_file_record_store,
                mem_layout,
                input_register_mem_layout,
                machine_unit_id,
                poll_interval,
                POLL_TIMEOUT,
                polling_reconnect_signal,
            )
            .await;
        });
    }

    let machine_names: Vec<&str> = description
        .machines
        .iter()
        .map(|machine| machine.name.as_str())
        .collect();
    println!(
        "Starting infused_modbus ({representation_layer:?}), connected via {connection_string} — machines: {}",
        machine_names.join(", ")
    );
    if representation_layer != RepresentationLayer::Mqtt {
        std::fs::create_dir_all(&root).ok();
        println!("Data root: {root}");
    }

    match representation_layer {
        RepresentationLayer::Fuse => {
            let mut machine_stores = machine_stores;
            let machines_for_fs: Vec<datafs::filesystem::MachineConfig> = description
                .machines
                .into_iter()
                .map(|machine| {
                    let stores = machine_stores
                        .remove(&machine.name)
                        .expect("machine_stores was built from the same machine list");
                    datafs::filesystem::MachineConfig {
                        name: machine.name,
                        registers: machine.registers,
                        coils: machine.coils,
                        discrete_inputs: machine.discrete_inputs,
                        input_registers: machine.input_registers,
                        file_records: machine.file_records,
                        store: stores.registers,
                        coil_store: stores.coils,
                        discrete_input_store: stores.discrete_inputs,
                        input_register_store: stores.input_registers,
                        file_record_store: stores.file_records,
                        report: stores.report,
                        permissions: fuse_permissions,
                        server_id: machine.server_id,
                    }
                })
                .collect();

            let filesystem = InfusedFilesystem::new(
                machines_for_fs,
                transaction_sender,
                WriteMode::Staged,
                // client-trust/ only exists on the server — see CLAUDE.md's
                // TLS design and datafs::client_trust::ClientTrustState.
                None,
            );
            // spawn_mount (not the blocking mount()) so Ctrl+C/SIGTERM below
            // can unmount cleanly instead of just killing the process and
            // leaving a stale mountpoint behind. default_permissions makes
            // the kernel actually enforce what getattr reports (see
            // datafs::permissions) instead of every request being allowed
            // regardless of mode/uid/gid.
            let mut mount_config = fuser::Config::default();
            mount_config.mount_options = vec![fuser::MountOption::DefaultPermissions];
            let session = fuser::spawn_mount(filesystem, &root, &mount_config)
                .unwrap_or_else(|error| panic!("mount failed: {error}"));

            wait_for_shutdown_signal(&runtime);

            session
                .umount_and_join()
                .unwrap_or_else(|error| panic!("failed to unmount cleanly: {error}"));
        }
        RepresentationLayer::Files => {
            let root_path = std::path::Path::new(&root);

            let readers = datafs::flatfile::build_machine_readers(
                root_path,
                &description.machines,
                &machine_stores,
            );
            for (name, reader) in &readers {
                reader.initialize().unwrap_or_else(|error| {
                    panic!("failed to initialize {name}'s data directory: {error}")
                });
                if let Err(error) = reader.apply_permissions(&fuse_permissions) {
                    eprintln!("warning: failed to apply permissions for {name}: {error}");
                }
            }
            for machine in &description.machines {
                datafs::flatfile::write_machine_server_id_file(root_path, machine).unwrap_or_else(
                    |error| panic!("failed to write {}'s server-id file: {error}", machine.name),
                );
            }

            // One FlatfileTransactionWatcher per machine, each blocking its
            // own dedicated thread on inotify — mirrors how the FUSE branch
            // above gets its write path for free from the mounted
            // filesystem's own write()/release() callbacks; here nothing
            // calls into this crate at all until a watcher thread notices a
            // real file event.
            for machine in &description.machines {
                let watcher = Arc::new(datafs::flatfile::build_machine_transaction_watcher(
                    root_path,
                    machine,
                    transaction_sender.clone(),
                ));
                watcher.initialize().unwrap_or_else(|error| {
                    panic!(
                        "failed to initialize {}'s transactions/ directory: {error}",
                        machine.name
                    )
                });
                if let Err(error) = watcher.apply_permissions(fuse_permissions.transactions) {
                    eprintln!(
                        "warning: failed to apply permissions for {}'s transactions/: {error}",
                        machine.name
                    );
                }
                std::thread::spawn(move || {
                    if let Err(error) = watcher.run_forever() {
                        eprintln!("transactions/ watcher stopped: {error}");
                    }
                });
            }

            // No push-based change notification yet (see datafs::flatfile's
            // own module doc comment) — a plain periodic re-render is the
            // deliberately simple mechanism for now, purely local so it's
            // never gated on a Modbus round trip.
            runtime.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(200));
                loop {
                    interval.tick().await;
                    for reader in readers.values() {
                        let _ = reader.render_once();
                    }
                }
            });

            wait_for_shutdown_signal(&runtime);

            // Mirrors the FUSE branch's unmount-on-shutdown: a real
            // directory doesn't disappear on its own the way a FUSE mount
            // does, so this has to remove it explicitly.
            std::fs::remove_dir_all(&root)
                .unwrap_or_else(|error| eprintln!("warning: failed to clean up {root}: {error}"));
        }
        RepresentationLayer::Mqtt => {
            // Either dial an already-running external broker (e.g. the
            // Sparkplug TCK's own HiveMQ instance — see
            // extract_mqtt_external_broker's doc comment) or start and
            // connect to our own embedded one, loopback-only, via
            // 127.0.0.1 regardless of what listen_address it was configured
            // to bind (e.g. "0.0.0.0:1883" for external/network consumers)
            // — only the port is shared between the two in that case.
            let (broker_host, broker_port): (String, u16) = match mqtt_external_broker {
                Some((host, port)) => (host, port),
                None => {
                    let broker_port: u16 = mqtt_broker_config
                        .listen_address
                        .rsplit(':')
                        .next()
                        .and_then(|port| port.parse().ok())
                        .unwrap_or_else(|| {
                            panic!(
                                "invalid --mqtt-broker-config listen_address {:?}: expected host:port",
                                mqtt_broker_config.listen_address
                            )
                        });
                    client::broker::start_embedded_broker(mqtt_broker_config);
                    std::thread::sleep(BROKER_STARTUP_GRACE_PERIOD);
                    ("127.0.0.1".to_string(), broker_port)
                }
            };

            let bd_seq =
                client::bd_seq_persistence::next_bd_seq(std::path::Path::new(MQTT_BD_SEQ_PATH));
            if let Some(host_id) = &mqtt_primary_host_id {
                println!(
                    "Waiting for Primary Host Application {host_id:?} to come online before publishing NBIRTH..."
                );
            }
            let edge_node = Arc::new(runtime.block_on(connect_edge_node(
                &broker_host,
                broker_port,
                &mqtt_group_id,
                &mqtt_edge_node_id,
                bd_seq,
                mqtt_primary_host_id.as_deref(),
            )));
            println!(
                "Sparkplug B Edge Node connected (group_id={mqtt_group_id:?}, edge_node_id={mqtt_edge_node_id:?}), broker at {broker_host}:{broker_port}"
            );

            let aliases = Arc::new(AliasAllocator::build(&description.machines));

            runtime
                .block_on(edge_node.subscribe_ncmd())
                .unwrap_or_else(|error| panic!("failed to subscribe to NCMD: {error}"));

            // Initial DBIRTH per machine. Each machine's ChangeTracker is
            // seeded with this same metric list right away, so the first
            // periodic tick below only republishes as DDATA whatever
            // actually changed since birth, not everything all over again.
            let mut change_trackers: HashMap<String, ChangeTracker> = HashMap::new();
            for machine in &description.machines {
                runtime
                    .block_on(edge_node.subscribe_dcmd(&machine.name))
                    .unwrap_or_else(|error| {
                        panic!("failed to subscribe to DCMD for {}: {error}", machine.name)
                    });

                let stores = &machine_stores[&machine.name];
                let metrics = build_machine_metrics(machine, stores, &aliases);
                let mut tracker = ChangeTracker::new();
                tracker.changed_metrics(&metrics);
                change_trackers.insert(machine.name.clone(), tracker);

                runtime
                    .block_on(edge_node.publish_dbirth(&machine.name, metrics))
                    .unwrap_or_else(|error| {
                        panic!("failed to publish DBIRTH for {}: {error}", machine.name)
                    });
            }

            // DCMD write path — forwards resolved writes into the exact
            // same transaction_sender/transaction_consumer every other
            // representation layer already uses.
            {
                let edge_node = Arc::clone(&edge_node);
                let machines = description.machines.clone();
                let aliases = Arc::clone(&aliases);
                let transaction_sender = transaction_sender.clone();
                runtime.spawn(async move {
                    run_dcmd_forwarder(&edge_node, &machines, &aliases, &transaction_sender).await;
                });
            }

            // Node Control/Rebirth handling.
            {
                let edge_node = Arc::clone(&edge_node);
                let machines = description.machines.clone();
                let stores_by_machine = machine_stores.clone();
                let aliases = Arc::clone(&aliases);
                runtime.spawn(async move {
                    run_rebirth_handler(&edge_node, &machines, &stores_by_machine, &aliases).await;
                });
            }

            // Periodic DDATA publishing per machine, tied to the same
            // poll_interval the Modbus polling loop above already uses —
            // there is no point checking for changes to publish faster than
            // the stores themselves can actually change.
            for machine in description.machines.clone() {
                let edge_node = Arc::clone(&edge_node);
                let stores = machine_stores[&machine.name].clone();
                let aliases = Arc::clone(&aliases);
                let mut tracker = change_trackers
                    .remove(&machine.name)
                    .expect("seeded above for every configured machine");
                runtime.spawn(async move {
                    let mut ticker = tokio::time::interval(poll_interval);
                    loop {
                        ticker.tick().await;
                        let metrics = build_machine_metrics(&machine, &stores, &aliases);
                        let changed = tracker.changed_metrics(&metrics);
                        if changed.is_empty() {
                            continue;
                        }
                        if let Err(error) = edge_node.publish_ddata(&machine.name, changed).await {
                            eprintln!("failed to publish DDATA for {}: {error}", machine.name);
                        }
                    }
                });
            }

            wait_for_shutdown_signal(&runtime);
        }
    }
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
