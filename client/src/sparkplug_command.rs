//! M7's write path: decodes incoming `DCMD` payloads (already routed to
//! `EdgeNodeConnection::dcmd_receiver` by `client::edge_node`, keyed by
//! `device_id`) into `StagedValue`s and forwards them into the exact same
//! `(machine_name, HashMap<String, StagedValue>)` channel `client::
//! transaction_consumer` already reads from — the same "new frontend, zero
//! changes to the Modbus-facing half" bet that held for `datafs::flatfile`
//! (see CLAUDE.md).

use crate::connection::Connection;
use crate::edge_node::EdgeNodeConnection;
use crate::polling::spawn_machine_polling_task;
use crate::reconnect::ReconnectSignal;
use crate::sparkplug_alias::AliasAllocator;
use crate::sparkplug_change_tracker::ChangeTracker;
use crate::sparkplug_translator::{
    build_machine_metrics, build_machine_metrics_null_placeholders, metric_value_to_staged_value,
};
use crate::subscription_state::{MachineTasks, SubscriptionState};
use datafs::{MachineStores, StagedValue};
use protocol::device_description::MachineDescription;
use sparkplug::metric_value::MetricValue;
use sparkplug::payload::{Payload, decode_payload};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

/// The well-known Sparkplug B metric name a host application sends (as an
/// `NCMD`, `Boolean(true)`) to request that an Edge Node republish its full
/// `NBIRTH`/`DBIRTH` set — e.g. after the host itself restarted and lost
/// whatever birth data it had cached. Always identified by this literal
/// name, never by alias, since it's a node-level control metric outside the
/// translated Modbus data model `client::sparkplug_alias::AliasAllocator`
/// assigns aliases for.
const REBIRTH_METRIC_NAME: &str = "Node Control/Rebirth";

/// Whether `payload` (an already-decoded `NCMD`) is a `Node Control/Rebirth`
/// request.
pub fn is_rebirth_request(payload: &Payload) -> bool {
    payload.metrics.iter().any(|metric| {
        metric.name == REBIRTH_METRIC_NAME && metric.value == MetricValue::Boolean(true)
    })
}

/// The well-known Sparkplug B metric names a host application sends (as an
/// `NCMD`) to request that an Edge Node start/stop producing real data for
/// one machine — see CLAUDE.md's "Planned: dynamic per-machine subscription
/// via Sparkplug B", "Subscribe/Unsubscribe metric convention" (C4.1). Same
/// fixed-name, never-aliased convention as `REBIRTH_METRIC_NAME` above —
/// node-level control metrics, outside `AliasAllocator`'s translated Modbus
/// alias space.
const SUBSCRIBE_METRIC_NAME: &str = "Node Control/Subscribe";
const UNSUBSCRIBE_METRIC_NAME: &str = "Node Control/Unsubscribe";

/// Every machine name requested via a `"Node Control/Subscribe"` metric in
/// `payload` — a payload may carry more than one (a Host Application
/// subscribing several machines in one `NCMD`), so this returns every match
/// rather than just the first. v1 is whole-machine-only (see CLAUDE.md): the
/// metric's value is a bare `String` naming the machine, not yet the
/// `{machine, points}` shape a future per-point granularity would need. A
/// matching metric whose value isn't a `String` is logged and skipped, not
/// treated as a reason to reject the rest of the payload — same "one bad
/// entry doesn't reject the rest" precedent `decode_dcmd_metrics` already
/// established for `DCMD`.
pub fn subscribe_requests(payload: &Payload) -> Vec<String> {
    requested_machine_names(payload, SUBSCRIBE_METRIC_NAME)
}

/// The `"Node Control/Unsubscribe"` counterpart to `subscribe_requests` —
/// same shape, same per-entry error handling.
pub fn unsubscribe_requests(payload: &Payload) -> Vec<String> {
    requested_machine_names(payload, UNSUBSCRIBE_METRIC_NAME)
}

fn requested_machine_names(payload: &Payload, metric_name: &str) -> Vec<String> {
    payload
        .metrics
        .iter()
        .filter(|metric| metric.name == metric_name)
        .filter_map(|metric| match &metric.value {
            MetricValue::String(machine_name) => Some(machine_name.clone()),
            other => {
                eprintln!(
                    "{metric_name}: expected a String value naming the machine, got {other:?}"
                );
                None
            }
        })
        .collect()
}

/// Decodes one already-parsed `DCMD` `Payload` addressed to `machine` into a
/// map of staged writes, resolving each metric's target name from its
/// `alias` (the spec-conventional shape a real host application sends, once
/// `DBIRTH` has established the alias mapping) or falling back to its raw
/// `name` field if no alias was sent. Every metric is resolved
/// independently — one unresolvable or invalid entry (unknown alias, wrong
/// machine, unknown metric name, wrong value shape) is logged and skipped
/// rather than rejecting the whole message, mirroring how `client::
/// transaction_consumer` already treats an unrecognized machine name as
/// "log and drop", not fatal.
pub fn decode_dcmd_metrics(
    machine: &MachineDescription,
    aliases: &AliasAllocator,
    payload: &Payload,
) -> HashMap<String, StagedValue> {
    let mut staged = HashMap::new();

    for metric in &payload.metrics {
        let metric_name = if let Some(alias) = metric.alias {
            match aliases.metric_for_alias(alias) {
                Some((owning_machine, metric_name)) if owning_machine == machine.name => {
                    metric_name.to_string()
                }
                Some((owning_machine, _)) => {
                    eprintln!(
                        "DCMD for {}: alias {alias} belongs to machine {owning_machine}, not {}",
                        machine.name, machine.name
                    );
                    continue;
                }
                None => {
                    eprintln!("DCMD for {}: unknown alias {alias}", machine.name);
                    continue;
                }
            }
        } else if !metric.name.is_empty() {
            metric.name.clone()
        } else {
            eprintln!(
                "DCMD for {}: metric identified by neither alias nor name",
                machine.name
            );
            continue;
        };

        match metric_value_to_staged_value(machine, &metric_name, &metric.value) {
            Ok(staged_value) => {
                staged.insert(metric_name, staged_value);
            }
            Err(reason) => eprintln!("DCMD for {}: {reason}", machine.name),
        }
    }

    staged
}

/// Drives `edge_node.dcmd_receiver` forever, decoding every incoming `DCMD`
/// and forwarding resolved writes into `transaction_sender`. `std::sync::
/// mpsc`, not `tokio::sync::mpsc` — matches the real, deliberate channel
/// type `client::transaction_consumer` already uses everywhere else (see
/// its own module doc comment referencing H2's blocking-receive design);
/// its `Sender::send` is non-blocking regardless (the channel is unbounded),
/// so calling it directly from this async loop never stalls the runtime.
/// Returns once `dcmd_receiver` closes (the Edge Node connection is gone) or
/// `transaction_sender`'s receiving end has been dropped (the transaction
/// consumer shut down) — both are treated as "nothing left to do", not
/// errors worth panicking over.
pub async fn run_dcmd_forwarder(
    edge_node: &EdgeNodeConnection,
    machines: &[MachineDescription],
    aliases: &AliasAllocator,
    transaction_sender: &std::sync::mpsc::Sender<(String, HashMap<String, StagedValue>)>,
) {
    loop {
        let received = edge_node.dcmd_receiver.lock().await.recv().await;
        let Some((device_id, payload_bytes)) = received else {
            return;
        };

        let payload = match decode_payload(&payload_bytes) {
            Ok(payload) => payload,
            Err(error) => {
                eprintln!("failed to decode DCMD payload for {device_id}: {error:?}");
                continue;
            }
        };

        let Some(machine) = machines.iter().find(|machine| machine.name == device_id) else {
            eprintln!("DCMD received for unknown machine {device_id}");
            continue;
        };

        let staged = decode_dcmd_metrics(machine, aliases, &payload);
        if staged.is_empty() {
            continue;
        }

        if transaction_sender.send((device_id, staged)).is_err() {
            return;
        }
    }
}

/// Spawns the periodic DDATA-publishing task for `machine` — reads `stores`
/// on every `poll_interval` tick, diffs the resulting metrics against
/// `tracker`, and publishes only what changed. Factored out of `client::
/// main`'s own (previously unconditional, now subscription-gated) DDATA
/// loop so `handle_subscribe` below can spawn the identical task once a
/// machine is actually subscribed. `tracker` should already be seeded with
/// the machine's current baseline (e.g. the same placeholder metrics its
/// `DBIRTH` carried — see `build_machine_metrics_null_placeholders`) so the
/// first real tick only reports genuine changes, not a full redundant dump.
/// Takes an explicit `runtime_handle` for the same reason `client::polling::
/// spawn_machine_polling_task` does — see that function's own doc comment.
pub fn spawn_machine_ddata_ticker(
    edge_node: Arc<EdgeNodeConnection>,
    machine: MachineDescription,
    stores: MachineStores,
    aliases: Arc<AliasAllocator>,
    poll_interval: Duration,
    mut tracker: ChangeTracker,
    runtime_handle: &tokio::runtime::Handle,
) -> tokio::task::JoinHandle<()> {
    runtime_handle.spawn(async move {
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
    })
}

/// Activates `machine_name` for the dynamic per-machine subscription model
/// (see CLAUDE.md's "Planned: dynamic per-machine subscription via
/// Sparkplug B"): if it matches a configured machine and isn't already
/// active, spawns its Modbus polling task and DDATA ticker and registers
/// both in `subscription_state`. A no-op if the machine is already active
/// (idempotent — see `SubscriptionState::activate`) or if `machine_name`
/// matches no configured machine (logged, not fatal — same "log and drop"
/// precedent as everywhere else in this project).
#[allow(clippy::too_many_arguments)]
async fn handle_subscribe(
    machine_name: &str,
    machines: &[MachineDescription],
    stores_by_machine: &HashMap<String, MachineStores>,
    aliases: &Arc<AliasAllocator>,
    connection: &Arc<AsyncMutex<Connection>>,
    poll_interval: Duration,
    poll_timeout: Duration,
    reconnect_signal: &Arc<ReconnectSignal>,
    subscription_state: &SubscriptionState,
    edge_node: &Arc<EdgeNodeConnection>,
    runtime_handle: &tokio::runtime::Handle,
) {
    if subscription_state.is_active(machine_name).await {
        return;
    }
    let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) else {
        eprintln!("Subscribe for unknown machine {machine_name:?}, ignoring it");
        return;
    };
    let Some(stores) = stores_by_machine.get(machine_name) else {
        eprintln!("no stores registered for machine {machine_name}, cannot subscribe");
        return;
    };

    let polling = spawn_machine_polling_task(
        machine,
        stores,
        Arc::clone(connection),
        poll_interval,
        poll_timeout,
        Arc::clone(reconnect_signal),
        runtime_handle,
    );

    let mut tracker = ChangeTracker::new();
    tracker.changed_metrics(&build_machine_metrics_null_placeholders(machine, aliases));

    let ddata_ticker = spawn_machine_ddata_ticker(
        Arc::clone(edge_node),
        machine.clone(),
        stores.clone(),
        Arc::clone(aliases),
        poll_interval,
        tracker,
        runtime_handle,
    );

    subscription_state
        .activate(
            machine_name.to_string(),
            MachineTasks {
                polling,
                ddata_ticker,
            },
        )
        .await;

    println!("Subscribed to machine {machine_name:?} — Modbus polling started.");
}

/// Drives `edge_node.ncmd_receiver` forever, handling every node-level
/// control metric this project understands. Named `run_ncmd_handler`, not
/// `run_rebirth_handler` — it outgrew handling only `Node Control/Rebirth`
/// once Subscribe needed the same single consumer loop (only one task may
/// ever drain `ncmd_receiver`, so every `NCMD` concern has to live in one
/// loop, not a separate task per concern). On a `Rebirth` request,
/// republishes `NBIRTH` (`EdgeNodeConnection::publish_nbirth` — same
/// `bdSeq`, `seq` reset to 0) followed by a fresh `DBIRTH` for every machine
/// in `machines`, built from `stores_by_machine`'s current live values
/// exactly like the original birth at connect time. On a Subscribe request
/// (see CLAUDE.md's "Subscribe/Unsubscribe metric convention"), activates
/// the named machine via `handle_subscribe`. Unsubscribe handling is not
/// yet wired here (Thread C6). Returns once `ncmd_receiver` closes.
#[allow(clippy::too_many_arguments)]
pub async fn run_ncmd_handler(
    edge_node: Arc<EdgeNodeConnection>,
    machines: &[MachineDescription],
    stores_by_machine: &HashMap<String, MachineStores>,
    aliases: Arc<AliasAllocator>,
    connection: Arc<AsyncMutex<Connection>>,
    poll_interval: Duration,
    poll_timeout: Duration,
    reconnect_signal: Arc<ReconnectSignal>,
    subscription_state: Arc<SubscriptionState>,
    runtime_handle: tokio::runtime::Handle,
) {
    loop {
        let received = edge_node.ncmd_receiver.lock().await.recv().await;
        let Some(payload_bytes) = received else {
            return;
        };

        let payload = match decode_payload(&payload_bytes) {
            Ok(payload) => payload,
            Err(error) => {
                eprintln!("failed to decode NCMD payload: {error:?}");
                continue;
            }
        };

        if is_rebirth_request(&payload) {
            if let Err(error) = edge_node.publish_nbirth().await {
                eprintln!("failed to republish NBIRTH for a rebirth request: {error}");
                continue;
            }

            for machine in machines {
                let Some(stores) = stores_by_machine.get(&machine.name) else {
                    eprintln!(
                        "no stores registered for machine {} during rebirth",
                        machine.name
                    );
                    continue;
                };
                let metrics = build_machine_metrics(machine, stores, &aliases);
                if let Err(error) = edge_node.publish_dbirth(&machine.name, metrics).await {
                    eprintln!(
                        "failed to republish DBIRTH for machine {} during rebirth: {error}",
                        machine.name
                    );
                }
            }
            continue;
        }

        for machine_name in subscribe_requests(&payload) {
            handle_subscribe(
                &machine_name,
                machines,
                stores_by_machine,
                &aliases,
                &connection,
                poll_interval,
                poll_timeout,
                &reconnect_signal,
                &subscription_state,
                &edge_node,
                &runtime_handle,
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafs::{CoilValue, RegisterValue};
    use protocol::device_description::{
        AccessRight, CoilDescription, MemLayout, RegisterDescription,
    };
    use sparkplug::data_type::DataType;
    use sparkplug::metric::Metric;
    use sparkplug::metric_value::MetricValue;

    fn test_machine(name: &str) -> MachineDescription {
        MachineDescription {
            name: name.to_string(),
            unit_id: 1,
            registers: vec![RegisterDescription {
                name: "Tank_Temperature".to_string(),
                address: 0,
                data_type: protocol::device_description::DataType::U16,
                access: AccessRight::ReadWrite,
            }],
            coils: vec![CoilDescription {
                name: "Motor_Running".to_string(),
                address: 0,
            }],
            discrete_inputs: Vec::new(),
            input_registers: Vec::new(),
            file_records: Vec::new(),
            mem_layout: MemLayout::Abcd,
            input_register_mem_layout: MemLayout::Abcd,
            server_id: None,
        }
    }

    #[test]
    fn resolves_a_metric_identified_by_alias() {
        let machine = test_machine("PumpA");
        let aliases = AliasAllocator::build(std::slice::from_ref(&machine));
        let alias = aliases.alias_for("PumpA", "Tank_Temperature").unwrap();

        let payload = Payload {
            timestamp: Some(0),
            seq: Some(1),
            metrics: vec![Metric {
                name: String::new(),
                alias: Some(alias),
                timestamp: None,
                data_type: DataType::UInt16,
                is_null: false,
                properties: None,
                value: MetricValue::Int(30),
            }],
        };

        let staged = decode_dcmd_metrics(&machine, &aliases, &payload);
        assert_eq!(
            staged.get("Tank_Temperature"),
            Some(&StagedValue::Register(RegisterValue::U16(30)))
        );
    }

    #[test]
    fn resolves_a_metric_identified_by_raw_name_when_no_alias_is_sent() {
        let machine = test_machine("PumpA");
        let aliases = AliasAllocator::build(std::slice::from_ref(&machine));

        let payload = Payload {
            timestamp: Some(0),
            seq: Some(1),
            metrics: vec![Metric {
                name: "Motor_Running".to_string(),
                alias: None,
                timestamp: None,
                data_type: DataType::Boolean,
                is_null: false,
                properties: None,
                value: MetricValue::Boolean(true),
            }],
        };

        let staged = decode_dcmd_metrics(&machine, &aliases, &payload);
        assert_eq!(
            staged.get("Motor_Running"),
            Some(&StagedValue::Coil(CoilValue(true)))
        );
    }

    #[test]
    fn skips_an_alias_belonging_to_a_different_machine() {
        let machine_a = test_machine("PumpA");
        let machine_b = test_machine("PumpB");
        let aliases = AliasAllocator::build(&[machine_a.clone(), machine_b.clone()]);
        let alias_for_b = aliases.alias_for("PumpB", "Tank_Temperature").unwrap();

        let payload = Payload {
            timestamp: Some(0),
            seq: Some(1),
            metrics: vec![Metric {
                name: String::new(),
                alias: Some(alias_for_b),
                timestamp: None,
                data_type: DataType::UInt16,
                is_null: false,
                properties: None,
                value: MetricValue::Int(30),
            }],
        };

        let staged = decode_dcmd_metrics(&machine_a, &aliases, &payload);
        assert!(staged.is_empty());
    }

    #[test]
    fn skips_an_unknown_alias() {
        let machine = test_machine("PumpA");
        let aliases = AliasAllocator::build(std::slice::from_ref(&machine));

        let payload = Payload {
            timestamp: Some(0),
            seq: Some(1),
            metrics: vec![Metric {
                name: String::new(),
                alias: Some(9999),
                timestamp: None,
                data_type: DataType::UInt16,
                is_null: false,
                properties: None,
                value: MetricValue::Int(30),
            }],
        };

        let staged = decode_dcmd_metrics(&machine, &aliases, &payload);
        assert!(staged.is_empty());
    }

    #[test]
    fn skips_a_metric_with_neither_alias_nor_name() {
        let machine = test_machine("PumpA");
        let aliases = AliasAllocator::build(std::slice::from_ref(&machine));

        let payload = Payload {
            timestamp: Some(0),
            seq: Some(1),
            metrics: vec![Metric {
                name: String::new(),
                alias: None,
                timestamp: None,
                data_type: DataType::UInt16,
                is_null: false,
                properties: None,
                value: MetricValue::Int(30),
            }],
        };

        let staged = decode_dcmd_metrics(&machine, &aliases, &payload);
        assert!(staged.is_empty());
    }

    #[test]
    fn skips_a_metric_that_resolves_but_has_the_wrong_value_shape() {
        let machine = test_machine("PumpA");
        let aliases = AliasAllocator::build(std::slice::from_ref(&machine));
        let alias = aliases.alias_for("PumpA", "Tank_Temperature").unwrap();

        let payload = Payload {
            timestamp: Some(0),
            seq: Some(1),
            metrics: vec![Metric {
                name: String::new(),
                alias: Some(alias),
                timestamp: None,
                data_type: DataType::UInt16,
                is_null: false,
                properties: None,
                value: MetricValue::Boolean(true),
            }],
        };

        let staged = decode_dcmd_metrics(&machine, &aliases, &payload);
        assert!(staged.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_dcmd_forwarder_end_to_end_over_a_real_embedded_broker() {
        use crate::broker::{BrokerConfig, start_embedded_broker};
        use crate::edge_node::connect_edge_node;
        use rumqttc::{AsyncClient, MqttOptions, QoS};
        use sparkplug::payload::encode_payload;
        use tokio::time::{Duration, timeout};

        timeout(Duration::from_secs(10), async {
            let port = 18836;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let machine = test_machine("PumpA");
            let aliases = AliasAllocator::build(std::slice::from_ref(&machine));
            let alias = aliases.alias_for("PumpA", "Tank_Temperature").unwrap();

            let edge_node =
                connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge", 0, None).await;
            edge_node.subscribe_dcmd("PumpA").await.unwrap();

            let (transaction_sender, transaction_receiver) = std::sync::mpsc::channel();
            let machines = vec![machine];
            tokio::spawn(async move {
                run_dcmd_forwarder(&edge_node, &machines, &aliases, &transaction_sender).await;
            });

            let mut host_options = MqttOptions::new("host-application-2", "127.0.0.1", port);
            host_options.set_keep_alive(Duration::from_secs(30));
            let (host_client, mut host_eventloop) = AsyncClient::new(host_options, 10);
            tokio::spawn(async move {
                loop {
                    if host_eventloop.poll().await.is_err() {
                        break;
                    }
                }
            });
            tokio::time::sleep(Duration::from_millis(200)).await;

            let dcmd_payload = Payload {
                timestamp: Some(0),
                seq: None,
                metrics: vec![Metric {
                    name: String::new(),
                    alias: Some(alias),
                    timestamp: None,
                    data_type: DataType::UInt16,
                    is_null: false,
                    properties: None,
                    value: MetricValue::Int(42),
                }],
            };
            let mut dcmd_bytes = Vec::new();
            encode_payload(&dcmd_payload, &mut dcmd_bytes);
            host_client
                .publish(
                    "spBv1.0/TestGroup/DCMD/TestEdge/PumpA",
                    QoS::AtLeastOnce,
                    false,
                    dcmd_bytes,
                )
                .await
                .unwrap();

            let (machine_name, staged) =
                tokio::task::spawn_blocking(move || transaction_receiver.recv())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(machine_name, "PumpA");
            assert_eq!(
                staged.get("Tank_Temperature"),
                Some(&StagedValue::Register(RegisterValue::U16(42)))
            );
        })
        .await
        .expect("test timed out");
    }

    #[test]
    fn is_rebirth_request_recognizes_the_well_known_metric() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![Metric {
                name: "Node Control/Rebirth".to_string(),
                alias: None,
                timestamp: None,
                data_type: DataType::Boolean,
                is_null: false,
                properties: None,
                value: MetricValue::Boolean(true),
            }],
        };
        assert!(is_rebirth_request(&payload));
    }

    #[test]
    fn is_rebirth_request_rejects_the_metric_with_a_false_value() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![Metric {
                name: "Node Control/Rebirth".to_string(),
                alias: None,
                timestamp: None,
                data_type: DataType::Boolean,
                is_null: false,
                properties: None,
                value: MetricValue::Boolean(false),
            }],
        };
        assert!(!is_rebirth_request(&payload));
    }

    #[test]
    fn is_rebirth_request_rejects_an_unrelated_ncmd() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![Metric {
                name: "Some_Other_Command".to_string(),
                alias: None,
                timestamp: None,
                data_type: DataType::Boolean,
                is_null: false,
                properties: None,
                value: MetricValue::Boolean(true),
            }],
        };
        assert!(!is_rebirth_request(&payload));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_ncmd_handler_republishes_nbirth_and_dbirth_on_rebirth() {
        use crate::broker::{BrokerConfig, start_embedded_broker};
        use crate::edge_node::connect_edge_node;
        use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
        use sparkplug::payload::encode_payload;
        use tokio::time::{Duration, timeout};

        timeout(Duration::from_secs(10), async {
            let port = 18839;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let machine = test_machine("PumpA");
            let aliases = Arc::new(AliasAllocator::build(std::slice::from_ref(&machine)));
            let mut stores_by_machine = HashMap::new();
            stores_by_machine.insert("PumpA".to_string(), datafs::MachineStores::new());

            // The rebirth path never touches `connection` at all — a real
            // TCP connection to a loopback listener that never has to
            // accept/respond to anything is enough to satisfy
            // `run_ncmd_handler`'s signature (it needs a real connection
            // object, but one is never used for this test's scenario).
            let dummy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dummy_address = dummy_listener.local_addr().unwrap().to_string();
            let connection = Arc::new(AsyncMutex::new(
                Connection::connect_tcp(&dummy_address).await.unwrap(),
            ));
            let reconnect_signal = Arc::new(ReconnectSignal::new());
            let subscription_state = Arc::new(SubscriptionState::new());

            // Subscribe *before* connecting the Edge Node, so the initial
            // NBIRTH connect_edge_node publishes is actually captured
            // (an MQTT publish isn't retained/replayed to a late subscriber).
            let mut external_options = MqttOptions::new("external-subscriber-5", "127.0.0.1", port);
            external_options.set_keep_alive(Duration::from_secs(30));
            let (external_client, mut external_eventloop) = AsyncClient::new(external_options, 10);
            external_client
                .subscribe("spBv1.0/TestGroup/#", QoS::AtLeastOnce)
                .await
                .unwrap();
            loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::SubAck(_)) => break,
                    _ => continue,
                }
            }

            let edge_node = Arc::new(
                connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge", 0, None).await,
            );
            edge_node.subscribe_ncmd().await.unwrap();

            // Drain the initial NBIRTH from connect_edge_node itself.
            loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(_)) => break,
                    _ => continue,
                }
            }

            let machines = vec![machine];
            let runtime_handle = tokio::runtime::Handle::current();
            tokio::spawn(async move {
                run_ncmd_handler(
                    edge_node,
                    &machines,
                    &stores_by_machine,
                    aliases,
                    connection,
                    Duration::from_millis(100),
                    Duration::from_secs(5),
                    reconnect_signal,
                    subscription_state,
                    runtime_handle,
                )
                .await;
            });

            let mut host_options = MqttOptions::new("host-application-4", "127.0.0.1", port);
            host_options.set_keep_alive(Duration::from_secs(30));
            let (host_client, mut host_eventloop) = AsyncClient::new(host_options, 10);
            tokio::spawn(async move {
                loop {
                    if host_eventloop.poll().await.is_err() {
                        break;
                    }
                }
            });
            tokio::time::sleep(Duration::from_millis(200)).await;

            let rebirth_payload = Payload {
                timestamp: Some(0),
                seq: None,
                metrics: vec![Metric {
                    name: "Node Control/Rebirth".to_string(),
                    alias: None,
                    timestamp: None,
                    data_type: DataType::Boolean,
                    is_null: false,
                    properties: None,
                    value: MetricValue::Boolean(true),
                }],
            };
            let mut rebirth_bytes = Vec::new();
            encode_payload(&rebirth_payload, &mut rebirth_bytes);
            host_client
                .publish(
                    "spBv1.0/TestGroup/NCMD/TestEdge",
                    QoS::AtLeastOnce,
                    false,
                    rebirth_bytes,
                )
                .await
                .unwrap();

            let republished_nbirth_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish))
                        if publish.topic.contains("NBIRTH") =>
                    {
                        break publish.payload;
                    }
                    Event::Incoming(Incoming::Publish(_)) => continue,
                    _ => continue,
                }
            };
            assert_eq!(
                decode_payload(&republished_nbirth_bytes).unwrap().seq,
                Some(0)
            );

            let dbirth_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish))
                        if publish.topic.contains("DBIRTH") =>
                    {
                        break publish.payload;
                    }
                    Event::Incoming(Incoming::Publish(_)) => continue,
                    _ => continue,
                }
            };
            let dbirth = decode_payload(&dbirth_bytes).unwrap();
            assert!(!dbirth.metrics.is_empty());
        })
        .await
        .expect("test timed out");
    }

    fn control_metric(name: &str, value: MetricValue) -> Metric {
        Metric {
            name: name.to_string(),
            alias: None,
            timestamp: None,
            data_type: DataType::String,
            is_null: false,
            properties: None,
            value,
        }
    }

    #[test]
    fn subscribe_requests_extracts_the_named_machine() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![control_metric(
                "Node Control/Subscribe",
                MetricValue::String("PumpA".to_string()),
            )],
        };
        assert_eq!(subscribe_requests(&payload), vec!["PumpA".to_string()]);
        assert!(unsubscribe_requests(&payload).is_empty());
    }

    #[test]
    fn subscribe_requests_extracts_every_match_in_one_payload() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![
                control_metric(
                    "Node Control/Subscribe",
                    MetricValue::String("PumpA".to_string()),
                ),
                control_metric(
                    "Node Control/Subscribe",
                    MetricValue::String("PumpB".to_string()),
                ),
            ],
        };
        assert_eq!(
            subscribe_requests(&payload),
            vec!["PumpA".to_string(), "PumpB".to_string()]
        );
    }

    #[test]
    fn unsubscribe_requests_extracts_the_named_machine() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![control_metric(
                "Node Control/Unsubscribe",
                MetricValue::String("PumpA".to_string()),
            )],
        };
        assert_eq!(unsubscribe_requests(&payload), vec!["PumpA".to_string()]);
        assert!(subscribe_requests(&payload).is_empty());
    }

    #[test]
    fn subscribe_and_unsubscribe_requests_in_the_same_payload_are_kept_separate() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![
                control_metric(
                    "Node Control/Subscribe",
                    MetricValue::String("PumpA".to_string()),
                ),
                control_metric(
                    "Node Control/Unsubscribe",
                    MetricValue::String("PumpB".to_string()),
                ),
            ],
        };
        assert_eq!(subscribe_requests(&payload), vec!["PumpA".to_string()]);
        assert_eq!(unsubscribe_requests(&payload), vec!["PumpB".to_string()]);
    }

    #[test]
    fn subscribe_requests_skips_a_non_string_value() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![control_metric(
                "Node Control/Subscribe",
                MetricValue::Boolean(true),
            )],
        };
        assert!(subscribe_requests(&payload).is_empty());
    }

    #[test]
    fn subscribe_requests_ignores_unrelated_metrics() {
        let payload = Payload {
            timestamp: Some(0),
            seq: None,
            metrics: vec![control_metric(
                "Node Control/Rebirth",
                MetricValue::Boolean(true),
            )],
        };
        assert!(subscribe_requests(&payload).is_empty());
        assert!(unsubscribe_requests(&payload).is_empty());
    }
}
