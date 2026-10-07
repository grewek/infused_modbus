// Modbus master: talks to a real device reachable over TCP or RTU (see
// `<connection>` below) and exposes its data as a Sparkplug B Edge Node
// over an external MQTT broker (see CLAUDE.md's "MQTT (Sparkplug B)
// representation layer" section) — no filesystem of any kind. A write
// arrives as a Sparkplug DCMD and is confirmed against the real device
// before anything is reported back as succeeded.
//
// The device description itself is preferably fetched from the server
// over the wire (FC 43 / MEI 0x0E — see client/src/device_identification.rs)
// so it doesn't need to be kept in sync with a local file by hand;
// `<device-description.toml>` is still a required argument as the fallback
// used if the server has none, doesn't support the request, or the fetch
// otherwise fails.
//
// Usage:
//   cargo run -p client -- <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>] [--mqtt-broker <host:port>] [--mqtt-group-id <id>] [--mqtt-edge-node-id <id>] [--mqtt-primary-host-id <id>]
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

use client::connection::Connection;
use client::device_identification::fetch_device_description;
use client::edge_node::connect_edge_node;
use client::reconnect::{ReconnectSignal, run_reconnect_loop};
use client::sparkplug_alias::AliasAllocator;
use client::sparkplug_command::{run_dcmd_forwarder, run_ncmd_handler};
use client::sparkplug_translator::build_machine_metrics_null_placeholders;
use client::subscription_state::SubscriptionState;
use client::transaction_consumer::{MachineTransactionConfig, run_transaction_consumer};
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
// Persists this Edge Node's next bdSeq across process restarts — see
// client::bd_seq_persistence's own module doc comment for why this is
// required for real Sparkplug B conformance, not just a nice-to-have.
const MQTT_BD_SEQ_PATH: &str = "client-mqtt-bdseq";

fn usage() -> ! {
    eprintln!(
        "Usage: client <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>] [--mqtt-broker <host:port>] [--mqtt-group-id <id>] [--mqtt-edge-node-id <id>] [--mqtt-primary-host-id <id>]\n\
         <connection> is tcp://<address:port>, tls+tcp://<address:port>, or rtu://<serial-path>:<baud-rate>\n\
         --expect-server-fingerprint pins the server's TLS identity (tls+tcp:// only) — \
         without it, the server's identity is not verified at all (see CLAUDE.md's TLS design).\n\
         --mqtt-broker <host:port> is the already-running MQTT broker this Edge Node connects \
         to (e.g. Mosquitto) — required, this project does not run a broker itself. See \
         examples/mqtt-broker for a disposable broker to test against.\n\
         --mqtt-group-id/--mqtt-edge-node-id set this Edge Node's Sparkplug B identity \
         (defaults: {DEFAULT_MQTT_GROUP_ID:?}/{DEFAULT_MQTT_EDGE_NODE_ID:?} — override \
         --mqtt-edge-node-id for any deployment running more than one client instance against \
         the same broker/host application, since it must be unique per Edge Node).\n\
         --mqtt-primary-host-id <id> makes this Edge Node wait for the named Primary Host \
         Application to come online (via its retained spBv1.0/STATE/<id> message) before \
         publishing NBIRTH — without it, NBIRTH is published immediately, with no Primary Host \
         awareness at all (the common case)."
    );
    std::process::exit(1);
}

/// Pulls `--mqtt-broker <host:port>` out of `args` if present, leaving the
/// rest of `args` untouched. Absent entirely, `None` — the caller rejects
/// that, since this project no longer runs a broker itself (see
/// CLAUDE.md's "MQTT (Sparkplug B) representation layer" for why the
/// embedded broker was removed).
fn extract_mqtt_broker(args: &mut Vec<String>) -> Option<(String, u16)> {
    let flag_index = args.iter().position(|arg| arg == "--mqtt-broker")?;
    if flag_index + 1 >= args.len() {
        panic!("--mqtt-broker requires a value (host:port)");
    }
    args.remove(flag_index);
    let value = args.remove(flag_index);
    let (host, port) = value
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("invalid --mqtt-broker value {value:?}: expected host:port"));
    let port: u16 = port
        .parse()
        .unwrap_or_else(|error| panic!("invalid --mqtt-broker port {port:?}: {error}"));
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
    let mqtt_broker = extract_mqtt_broker(&mut raw_args);
    let mqtt_group_id =
        extract_string_flag(&mut raw_args, "--mqtt-group-id", DEFAULT_MQTT_GROUP_ID);
    let mqtt_edge_node_id = extract_string_flag(
        &mut raw_args,
        "--mqtt-edge-node-id",
        DEFAULT_MQTT_EDGE_NODE_ID,
    );
    let mqtt_primary_host_id = extract_mqtt_primary_host_id(&mut raw_args);
    let mut args = raw_args.into_iter();
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
    // single shared channel tagged with the originating machine's name —
    // CLAUDE.md's "TRANSACTION_END confirmation semantics" apply per
    // machine the same way.
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

    // A machine's polling task only starts once a Host Application actually
    // subscribes to it (see CLAUDE.md's "Planned: dynamic per-machine
    // subscription via Sparkplug B") — spawned on demand by
    // `run_ncmd_handler`'s subscribe handling below, never eagerly here.

    let machine_names: Vec<&str> = description
        .machines
        .iter()
        .map(|machine| machine.name.as_str())
        .collect();
    println!(
        "Starting infused_modbus, connected via {connection_string} — machines: {}",
        machine_names.join(", ")
    );
    // The client's own effective `server_id` per machine (from the local
    // fallback TOML or an FC43 fetch) — had a dedicated read-only FUSE file
    // before the FUSE/files removal; printed here now since there's no
    // other way for a technician to see which of the two it ended up
    // being. Machines without one configured are silently skipped, same
    // "None means not configured" convention FC11 itself uses.
    for machine in &description.machines {
        if let Some(server_id) = &machine.server_id {
            println!("  {}: server_id = {server_id:?}", machine.name);
        }
    }

    // This project doesn't run a broker itself — see CLAUDE.md's "MQTT
    // (Sparkplug B) representation layer" for why the embedded broker was
    // removed. examples/mqtt-broker has a disposable one for local testing.
    let (broker_host, broker_port) =
        mqtt_broker.unwrap_or_else(|| panic!("--mqtt-broker <host:port> is required"));

    let bd_seq = client::bd_seq_persistence::next_bd_seq(std::path::Path::new(MQTT_BD_SEQ_PATH));
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

    // Initial DBIRTH per machine, every metric an `is_null: true`
    // placeholder — no real Modbus access has happened for any machine yet
    // (polling only starts once a Host Application subscribes). The spec
    // requires a DBIRTH to declare a Device's full metric shape up front, so
    // every machine is birthed immediately regardless of whether anything
    // ever subscribes to it (see CLAUDE.md's "Planned: dynamic per-machine
    // subscription via Sparkplug B"). Each machine's own ChangeTracker is
    // created fresh, seeded with this same placeholder baseline, once it's
    // actually subscribed (see run_ncmd_handler's handle_subscribe) — not
    // here, since nothing has a DDATA ticker running until then.
    for machine in &description.machines {
        runtime
            .block_on(edge_node.subscribe_dcmd(&machine.name))
            .unwrap_or_else(|error| {
                panic!("failed to subscribe to DCMD for {}: {error}", machine.name)
            });

        let metrics = build_machine_metrics_null_placeholders(machine, &aliases);

        runtime
            .block_on(edge_node.publish_dbirth(&machine.name, metrics))
            .unwrap_or_else(|error| {
                panic!("failed to publish DBIRTH for {}: {error}", machine.name)
            });
    }

    // DCMD write path — forwards resolved writes into
    // transaction_sender/transaction_consumer.
    {
        let edge_node = Arc::clone(&edge_node);
        let machines = description.machines.clone();
        let aliases = Arc::clone(&aliases);
        let transaction_sender = transaction_sender.clone();
        runtime.spawn(async move {
            run_dcmd_forwarder(&edge_node, &machines, &aliases, &transaction_sender).await;
        });
    }

    // Node Control/Rebirth + Subscribe handling — the sole consumer of
    // `ncmd_receiver` (only one task may ever drain it). Subscribe is what
    // actually starts a machine's real Modbus polling task and DDATA ticker.
    let subscription_state = Arc::new(SubscriptionState::new());
    {
        let edge_node = Arc::clone(&edge_node);
        let machines = description.machines.clone();
        let stores_by_machine = machine_stores.clone();
        let aliases = Arc::clone(&aliases);
        let connection = Arc::clone(&connection);
        let reconnect_signal = Arc::clone(&reconnect_signal);
        let subscription_state = Arc::clone(&subscription_state);
        let runtime_handle = runtime.handle().clone();
        runtime.spawn(async move {
            run_ncmd_handler(
                edge_node,
                &machines,
                &stores_by_machine,
                aliases,
                connection,
                poll_interval,
                POLL_TIMEOUT,
                reconnect_signal,
                subscription_state,
                runtime_handle,
            )
            .await;
        });
    }

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
