//! M7's write path: decodes incoming `DCMD` payloads (already routed to
//! `EdgeNodeConnection::dcmd_receiver` by `client::edge_node`, keyed by
//! `device_id`) into `StagedValue`s and forwards them into the exact same
//! `(machine_name, HashMap<String, StagedValue>)` channel `client::
//! transaction_consumer` already reads from — the same "new frontend, zero
//! changes to the Modbus-facing half" bet that held for `datafs::flatfile`
//! (see CLAUDE.md).

use crate::edge_node::EdgeNodeConnection;
use crate::sparkplug_alias::AliasAllocator;
use crate::sparkplug_translator::metric_value_to_staged_value;
use datafs::StagedValue;
use protocol::device_description::MachineDescription;
use sparkplug::payload::{Payload, decode_payload};
use std::collections::HashMap;
use tokio::sync::mpsc;

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
/// and forwarding resolved writes into `transaction_sender`. Returns once
/// `dcmd_receiver` closes (the Edge Node connection is gone) or
/// `transaction_sender`'s receiving end has been dropped (the transaction
/// consumer shut down) — both are treated as "nothing left to do", not
/// errors worth panicking over.
pub async fn run_dcmd_forwarder(
    edge_node: &EdgeNodeConnection,
    machines: &[MachineDescription],
    aliases: &AliasAllocator,
    transaction_sender: &mpsc::Sender<(String, HashMap<String, StagedValue>)>,
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

        if transaction_sender.send((device_id, staged)).await.is_err() {
            return;
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
                data_type: DataType::UInt16,
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
                data_type: DataType::Boolean,
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
                data_type: DataType::UInt16,
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
                data_type: DataType::UInt16,
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
                data_type: DataType::UInt16,
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
                data_type: DataType::UInt16,
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

            let edge_node = connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge").await;
            edge_node.subscribe_dcmd("PumpA").await.unwrap();

            let (transaction_sender, mut transaction_receiver) = mpsc::channel(4);
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
                    data_type: DataType::UInt16,
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

            let (machine_name, staged) = transaction_receiver.recv().await.unwrap();
            assert_eq!(machine_name, "PumpA");
            assert_eq!(
                staged.get("Tank_Temperature"),
                Some(&StagedValue::Register(RegisterValue::U16(42)))
            );
        })
        .await
        .expect("test timed out");
    }
}
