//! `client` acting as a Sparkplug B Edge Node — its own MQTT client, connected
//! by loopback to the broker it embeds itself (`client::broker`). This is
//! separate from any external consumer (Node-RED, a SCADA host application,
//! ...) connecting to the same broker over the network; those never go
//! through this module.
//!
//! One `connect_edge_node` call per `client` process, returning one
//! `EdgeNodeConnection` — there is exactly one Edge Node identity per
//! `client` instance by construction, nothing here loops or creates more
//! than one.
//!
//! **Not yet handled:** what happens to `bdSeq`/`NBIRTH` across an internal
//! `rumqttc` reconnect after a real, later connection drop (rumqttc retries
//! automatically, but spec-correct behavior would need a *fresh* `bdSeq` and
//! a republished `NBIRTH` for that new session, not silent reuse of the
//! first session's values) — flagged as a real gap, not silently assumed
//! away, revisit once the project looks at MQTT-side reconnection
//! deliberately (mirroring how `client::reconnect` already handles this for
//! the Modbus side).

use rumqttc::{AsyncClient, ClientError, Event, Incoming, LastWill, MqttOptions, QoS};
use sparkplug::metric::Metric;
use sparkplug::payload::encode_payload;
use sparkplug::seq_counter::{BdSeqCounter, SeqCounter};
use sparkplug::session::{
    build_dbirth_payload, build_ddata_payload, build_ddeath_payload, build_nbirth_payload,
    build_ndata_payload, build_ndeath_payload,
};
use sparkplug::topic::{MessageType, build_topic};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};

/// An Edge Node's live connection to its own embedded broker, plus the
/// session state later Sparkplug messages (`NDATA` in particular) need to
/// keep advancing correctly rather than restarting from scratch.
pub struct EdgeNodeConnection {
    pub client: AsyncClient,
    pub group_id: String,
    pub edge_node_id: String,
    pub seq_counter: Mutex<SeqCounter>,
    /// Fixed for the whole life of this connection session — kept around so
    /// a later `Rebirth` request (see `publish_nbirth`) republishes `NBIRTH`
    /// with the *same* `bdSeq` the connection's `NDEATH` Will was registered
    /// with, not a new one (a new `bdSeq` is only ever warranted by a new
    /// MQTT connection, which a `Rebirth` request is not).
    bd_seq: u64,
    /// Every `DCMD` publish this Edge Node has subscribed to (see
    /// `subscribe_dcmd`), as `(device_id, raw_payload_bytes)` — decoding and
    /// resolving these into a real write belongs to `client::
    /// sparkplug_command`, which has the Modbus knowledge this module
    /// deliberately doesn't.
    pub dcmd_receiver: Mutex<mpsc::UnboundedReceiver<(String, Vec<u8>)>>,
    /// Every `NCMD` publish addressed to this Edge Node itself (not any one
    /// device) — in practice, as of M8, only ever a `Node Control/Rebirth`
    /// request, but modeled as raw bytes here for the same reason
    /// `dcmd_receiver` is: decoding is Modbus/Sparkplug-metric-aware glue
    /// that belongs in `client::sparkplug_command`.
    pub ncmd_receiver: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
}

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_millis() as u64
}

/// Connects to the broker at `broker_host:broker_port` as the Sparkplug B
/// Edge Node identified by `group_id`/`edge_node_id` (also used as the MQTT
/// client id): registers a matching `NDEATH`+`bdSeq` as the MQTT Will
/// *before* connecting, waits for the connection to actually be
/// acknowledged, publishes the session's `NBIRTH` (same `bdSeq`, `seq = 0`),
/// then keeps driving the connection in the background for the rest of the
/// process's life. Panics if the initial connection or the `NBIRTH` publish
/// fails — connecting to our own just-started embedded broker is a startup
/// precondition, the same "first connection failing is fatal" stance already
/// used for the Modbus connection in `client::main`.
pub async fn connect_edge_node(
    broker_host: &str,
    broker_port: u16,
    group_id: &str,
    edge_node_id: &str,
) -> EdgeNodeConnection {
    let bd_seq = BdSeqCounter::new().next_bd_seq();

    let ndeath_topic = build_topic(group_id, MessageType::NDeath, edge_node_id, None)
        .expect("NDEATH is a node-scoped message type and never needs a device_id");
    let mut ndeath_bytes = Vec::new();
    encode_payload(&build_ndeath_payload(bd_seq), &mut ndeath_bytes);

    let mut options = MqttOptions::new(edge_node_id, broker_host, broker_port);
    options.set_keep_alive(Duration::from_secs(30));
    options.set_last_will(LastWill::new(
        ndeath_topic,
        ndeath_bytes,
        QoS::AtLeastOnce,
        false,
    ));
    let (client, mut eventloop) = AsyncClient::new(options, 10);

    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Incoming::ConnAck(_))) => break,
            Ok(_) => continue,
            Err(error) => panic!("failed to connect edge node to embedded broker: {error}"),
        }
    }

    // rumqttc only makes progress (keepalive pings, acks, automatic
    // reconnection) while something keeps polling the event loop. Piggybacks
    // on that same loop to also pick out DCMD/NCMD publishes and forward
    // them into their respective channels, rather than running a second,
    // competing consumer of the one `AsyncClient`/`EventLoop` pair.
    let dcmd_topic_prefix = format!("spBv1.0/{group_id}/DCMD/{edge_node_id}/");
    let ncmd_topic = build_topic(group_id, MessageType::NCmd, edge_node_id, None)
        .expect("NCMD is a node-scoped message type and never needs a device_id");
    let (dcmd_sender, dcmd_receiver) = mpsc::unbounded_channel();
    let (ncmd_sender, ncmd_receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Incoming::Publish(publish))) => {
                    if let Some(device_id) = publish.topic.strip_prefix(&dcmd_topic_prefix) {
                        let _ = dcmd_sender.send((device_id.to_string(), publish.payload.to_vec()));
                    } else if publish.topic == ncmd_topic {
                        let _ = ncmd_sender.send(publish.payload.to_vec());
                    }
                }
                Ok(_) => {}
                Err(error) => eprintln!("edge node MQTT event loop error: {error}"),
            }
        }
    });

    let connection = EdgeNodeConnection {
        client,
        group_id: group_id.to_string(),
        edge_node_id: edge_node_id.to_string(),
        seq_counter: Mutex::new(SeqCounter::new()),
        bd_seq,
        dcmd_receiver: Mutex::new(dcmd_receiver),
        ncmd_receiver: Mutex::new(ncmd_receiver),
    };
    connection
        .publish_nbirth()
        .await
        .expect("failed to publish NBIRTH after connecting");
    connection
}

impl EdgeNodeConnection {
    /// Subscribes to the `DCMD` topic for the Device identified by
    /// `device_id`, so incoming write commands for it start showing up on
    /// `dcmd_receiver`. Must be called once per machine this `client`
    /// instance manages — nothing here subscribes on a caller's behalf.
    pub async fn subscribe_dcmd(&self, device_id: &str) -> Result<(), ClientError> {
        let topic = build_topic(
            &self.group_id,
            MessageType::DCmd,
            &self.edge_node_id,
            Some(device_id),
        )
        .expect("DCMD is a device-scoped message type and always carries a device_id");
        self.client.subscribe(topic, QoS::AtLeastOnce).await
    }

    /// Subscribes to this Edge Node's own `NCMD` topic, so incoming
    /// node-level commands (as of M8, only ever `Node Control/Rebirth`)
    /// start showing up on `ncmd_receiver`. Must be called once per
    /// connection — never subscribed automatically by `connect_edge_node`
    /// itself, matching `subscribe_dcmd`'s own "caller opts in" precedent.
    pub async fn subscribe_ncmd(&self) -> Result<(), ClientError> {
        let topic = build_topic(&self.group_id, MessageType::NCmd, &self.edge_node_id, None)
            .expect("NCMD is a node-scoped message type and never needs a device_id");
        self.client.subscribe(topic, QoS::AtLeastOnce).await
    }

    /// (Re-)publishes `NBIRTH`, resetting `seq_counter` to 0 first (per
    /// spec, every `NBIRTH` always carries `seq = 0`) but reusing this
    /// connection's original `bd_seq` unchanged — see the field's own doc
    /// comment for why a `Rebirth` request must not get a fresh one. Called
    /// once by `connect_edge_node` itself right after connecting, and again
    /// by `client::sparkplug_command`'s rebirth handling whenever a `Node
    /// Control/Rebirth` request arrives.
    pub async fn publish_nbirth(&self) -> Result<(), ClientError> {
        let payload = {
            let mut seq_counter = self.seq_counter.lock().await;
            build_nbirth_payload(self.bd_seq, current_timestamp_millis(), &mut seq_counter)
        };
        let mut payload_bytes = Vec::new();
        encode_payload(&payload, &mut payload_bytes);
        let topic = build_topic(
            &self.group_id,
            MessageType::NBirth,
            &self.edge_node_id,
            None,
        )
        .expect("NBIRTH is a node-scoped message type and never needs a device_id");
        self.client
            .publish(topic, QoS::AtLeastOnce, false, payload_bytes)
            .await
    }

    /// Publishes a `DBIRTH` for the Device identified by `device_id`,
    /// carrying `metrics` (built by `client::sparkplug_translator::
    /// build_machine_metrics`, outside this module — kept Modbus-agnostic
    /// here just like `connect_edge_node` itself). Advances the Edge Node's
    /// one shared `seq_counter` rather than resetting it, since only
    /// `NBIRTH` ever resets `seq` to 0.
    pub async fn publish_dbirth(
        &self,
        device_id: &str,
        metrics: Vec<Metric>,
    ) -> Result<(), ClientError> {
        let payload = {
            let mut seq_counter = self.seq_counter.lock().await;
            build_dbirth_payload(metrics, current_timestamp_millis(), &mut seq_counter)
        };
        let mut payload_bytes = Vec::new();
        encode_payload(&payload, &mut payload_bytes);
        let topic = build_topic(
            &self.group_id,
            MessageType::DBirth,
            &self.edge_node_id,
            Some(device_id),
        )
        .expect("DBIRTH is a device-scoped message type and always carries a device_id");
        self.client
            .publish(topic, QoS::AtLeastOnce, false, payload_bytes)
            .await
    }

    /// Publishes a `DDEATH` for the Device identified by `device_id` — see
    /// `sparkplug::session::build_ddeath_payload` for why this is actively
    /// published here rather than delivered via the MQTT Will the way
    /// `NDEATH` is.
    pub async fn publish_ddeath(&self, device_id: &str) -> Result<(), ClientError> {
        let payload = {
            let mut seq_counter = self.seq_counter.lock().await;
            build_ddeath_payload(current_timestamp_millis(), &mut seq_counter)
        };
        let mut payload_bytes = Vec::new();
        encode_payload(&payload, &mut payload_bytes);
        let topic = build_topic(
            &self.group_id,
            MessageType::DDeath,
            &self.edge_node_id,
            Some(device_id),
        )
        .expect("DDEATH is a device-scoped message type and always carries a device_id");
        self.client
            .publish(topic, QoS::AtLeastOnce, false, payload_bytes)
            .await
    }

    /// Publishes a `DDATA` for the Device identified by `device_id`, carrying
    /// only the metrics `client::sparkplug_change_tracker::ChangeTracker`
    /// determined actually changed. A no-op (not even consuming a `seq`
    /// value) when `metrics` is empty — there is nothing worth publishing,
    /// and every poll tick with no changed values would otherwise burn a
    /// `seq` number for an empty message.
    pub async fn publish_ddata(
        &self,
        device_id: &str,
        metrics: Vec<Metric>,
    ) -> Result<(), ClientError> {
        if metrics.is_empty() {
            return Ok(());
        }
        let payload = {
            let mut seq_counter = self.seq_counter.lock().await;
            build_ddata_payload(metrics, current_timestamp_millis(), &mut seq_counter)
        };
        let mut payload_bytes = Vec::new();
        encode_payload(&payload, &mut payload_bytes);
        let topic = build_topic(
            &self.group_id,
            MessageType::DData,
            &self.edge_node_id,
            Some(device_id),
        )
        .expect("DDATA is a device-scoped message type and always carries a device_id");
        self.client
            .publish(topic, QoS::AtLeastOnce, false, payload_bytes)
            .await
    }

    /// Publishes an `NDATA` for the Edge Node itself — see
    /// `sparkplug::session::build_ndata_payload` for why this is expected to
    /// be rare in practice today. Same empty-metrics no-op as `publish_ddata`.
    pub async fn publish_ndata(&self, metrics: Vec<Metric>) -> Result<(), ClientError> {
        if metrics.is_empty() {
            return Ok(());
        }
        let payload = {
            let mut seq_counter = self.seq_counter.lock().await;
            build_ndata_payload(metrics, current_timestamp_millis(), &mut seq_counter)
        };
        let mut payload_bytes = Vec::new();
        encode_payload(&payload, &mut payload_bytes);
        let topic = build_topic(&self.group_id, MessageType::NData, &self.edge_node_id, None)
            .expect("NDATA is a node-scoped message type and never needs a device_id");
        self.client
            .publish(topic, QoS::AtLeastOnce, false, payload_bytes)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{BrokerConfig, start_embedded_broker};
    use sparkplug::metric_value::MetricValue;
    use sparkplug::payload::decode_payload;
    use tokio::time::timeout;

    #[tokio::test(flavor = "multi_thread")]
    async fn edge_node_publishes_nbirth_matching_its_will_ndeath_bd_seq() {
        timeout(Duration::from_secs(10), async {
            let port = 18832;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            // Stands in for a host application (e.g. a real SCADA system)
            // subscribing to the Edge Node's birth topic over the network.
            let mut external_options = MqttOptions::new("external-subscriber", "127.0.0.1", port);
            external_options.set_keep_alive(Duration::from_secs(30));
            let (external_client, mut external_eventloop) = AsyncClient::new(external_options, 10);
            external_client
                .subscribe("spBv1.0/TestGroup/NBIRTH/TestEdge", QoS::AtLeastOnce)
                .await
                .unwrap();
            loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::SubAck(_)) => break,
                    _ => continue,
                }
            }

            let edge_node = connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge").await;
            assert_eq!(edge_node.group_id, "TestGroup");
            assert_eq!(edge_node.edge_node_id, "TestEdge");

            let nbirth_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            let nbirth = decode_payload(&nbirth_bytes).unwrap();
            assert_eq!(nbirth.seq, Some(0));
            assert_eq!(nbirth.metrics.len(), 1);
            assert_eq!(nbirth.metrics[0].name, "bdSeq");
            assert_eq!(nbirth.metrics[0].value, MetricValue::Long(0));

            // the counter used to build NBIRTH is preserved, not discarded,
            // ready for the next message (NDATA, once M6 sends one) to
            // continue the sequence rather than restart it.
            let mut seq_counter = edge_node.seq_counter.lock().await;
            assert_eq!(seq_counter.next_seq(), 1);
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn edge_node_publishes_dbirth_and_ddeath_for_a_device_continuing_the_shared_seq() {
        timeout(Duration::from_secs(10), async {
            let port = 18833;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let mut external_options = MqttOptions::new("external-subscriber-2", "127.0.0.1", port);
            external_options.set_keep_alive(Duration::from_secs(30));
            let (external_client, mut external_eventloop) = AsyncClient::new(external_options, 10);
            external_client
                .subscribe("spBv1.0/TestGroup/+/TestEdge/PumpA", QoS::AtLeastOnce)
                .await
                .unwrap();
            loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::SubAck(_)) => break,
                    _ => continue,
                }
            }

            let edge_node = connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge").await;

            let metrics = vec![Metric {
                name: "Tank_Temperature".to_string(),
                alias: Some(0),
                data_type: sparkplug::data_type::DataType::UInt16,
                value: MetricValue::Int(21),
            }];
            edge_node
                .publish_dbirth("PumpA", metrics.clone())
                .await
                .unwrap();
            edge_node.publish_ddeath("PumpA").await.unwrap();

            let dbirth_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            let dbirth = decode_payload(&dbirth_bytes).unwrap();
            assert_eq!(dbirth.seq, Some(1));
            assert_eq!(dbirth.metrics, metrics);

            let ddeath_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            let ddeath = decode_payload(&ddeath_bytes).unwrap();
            assert_eq!(ddeath.seq, Some(2));
            assert!(ddeath.metrics.is_empty());
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn edge_node_publishes_ddata_and_ndata_but_skips_empty_metric_lists() {
        timeout(Duration::from_secs(10), async {
            let port = 18834;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let mut external_options = MqttOptions::new("external-subscriber-3", "127.0.0.1", port);
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

            let edge_node = connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge").await;

            // An empty diff must not publish anything or consume a seq value.
            edge_node.publish_ddata("PumpA", Vec::new()).await.unwrap();
            edge_node.publish_ndata(Vec::new()).await.unwrap();

            let metrics = vec![Metric {
                name: "Tank_Temperature".to_string(),
                alias: Some(0),
                data_type: sparkplug::data_type::DataType::UInt16,
                value: MetricValue::Int(23),
            }];
            edge_node
                .publish_ddata("PumpA", metrics.clone())
                .await
                .unwrap();

            // Drain the NBIRTH first (always published by connect_edge_node).
            let nbirth_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            assert_eq!(decode_payload(&nbirth_bytes).unwrap().seq, Some(0));

            let ddata_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            let ddata = decode_payload(&ddata_bytes).unwrap();
            // seq is 1, not higher, proving the two earlier empty-metric
            // calls consumed no seq value at all.
            assert_eq!(ddata.seq, Some(1));
            assert_eq!(ddata.metrics, metrics);
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn edge_node_forwards_dcmd_publishes_for_a_subscribed_device_only() {
        timeout(Duration::from_secs(10), async {
            let port = 18835;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let edge_node = connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge").await;
            edge_node.subscribe_dcmd("PumpA").await.unwrap();
            // No subscribe_dcmd("PumpB") — its DCMD publishes must never
            // show up on dcmd_receiver.

            // Stands in for a real host application (e.g. Node-RED, SCADA)
            // issuing a write command over the network.
            let mut host_options = MqttOptions::new("host-application", "127.0.0.1", port);
            host_options.set_keep_alive(Duration::from_secs(30));
            let (host_client, mut host_eventloop) = AsyncClient::new(host_options, 10);
            tokio::spawn(async move {
                loop {
                    if host_eventloop.poll().await.is_err() {
                        break;
                    }
                }
            });
            // Give the subscription time to actually land at the broker
            // before either publish, so neither is missed.
            tokio::time::sleep(Duration::from_millis(200)).await;

            host_client
                .publish(
                    "spBv1.0/TestGroup/DCMD/TestEdge/PumpB",
                    QoS::AtLeastOnce,
                    false,
                    vec![9, 9],
                )
                .await
                .unwrap();
            host_client
                .publish(
                    "spBv1.0/TestGroup/DCMD/TestEdge/PumpA",
                    QoS::AtLeastOnce,
                    false,
                    vec![1, 2, 3],
                )
                .await
                .unwrap();

            let (device_id, payload_bytes) = edge_node
                .dcmd_receiver
                .lock()
                .await
                .recv()
                .await
                .expect("dcmd_receiver closed unexpectedly");
            assert_eq!(device_id, "PumpA");
            assert_eq!(payload_bytes, vec![1, 2, 3]);
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn edge_node_forwards_ncmd_publishes_but_not_dcmd_ones() {
        timeout(Duration::from_secs(10), async {
            let port = 18837;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let edge_node = connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge").await;
            edge_node.subscribe_ncmd().await.unwrap();

            let mut host_options = MqttOptions::new("host-application-3", "127.0.0.1", port);
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

            // Never subscribed to any device's DCMD, so this must not
            // surface on ncmd_receiver either.
            host_client
                .publish(
                    "spBv1.0/TestGroup/DCMD/TestEdge/PumpA",
                    QoS::AtLeastOnce,
                    false,
                    vec![9, 9],
                )
                .await
                .unwrap();
            host_client
                .publish(
                    "spBv1.0/TestGroup/NCMD/TestEdge",
                    QoS::AtLeastOnce,
                    false,
                    vec![1, 2, 3],
                )
                .await
                .unwrap();

            let payload_bytes = edge_node
                .ncmd_receiver
                .lock()
                .await
                .recv()
                .await
                .expect("ncmd_receiver closed unexpectedly");
            assert_eq!(payload_bytes, vec![1, 2, 3]);
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_nbirth_resets_seq_but_reuses_the_same_bd_seq() {
        timeout(Duration::from_secs(10), async {
            let port = 18838;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let mut external_options = MqttOptions::new("external-subscriber-4", "127.0.0.1", port);
            external_options.set_keep_alive(Duration::from_secs(30));
            let (external_client, mut external_eventloop) = AsyncClient::new(external_options, 10);
            external_client
                .subscribe("spBv1.0/TestGroup/NBIRTH/TestEdge", QoS::AtLeastOnce)
                .await
                .unwrap();
            loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::SubAck(_)) => break,
                    _ => continue,
                }
            }

            let edge_node = connect_edge_node("127.0.0.1", port, "TestGroup", "TestEdge").await;
            // advance seq past 0 before the "rebirth"
            {
                let mut seq_counter = edge_node.seq_counter.lock().await;
                seq_counter.next_seq();
                seq_counter.next_seq();
            }

            edge_node.publish_nbirth().await.unwrap();

            let first_nbirth_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            let first_bd_seq = decode_payload(&first_nbirth_bytes).unwrap().metrics[0]
                .value
                .clone();

            let second_nbirth_bytes = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            let second_nbirth = decode_payload(&second_nbirth_bytes).unwrap();
            assert_eq!(second_nbirth.seq, Some(0));
            assert_eq!(second_nbirth.metrics[0].value, first_bd_seq);
        })
        .await
        .expect("test timed out");
    }
}
