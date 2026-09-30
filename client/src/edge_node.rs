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

use rumqttc::{AsyncClient, Event, Incoming, LastWill, MqttOptions, QoS};
use sparkplug::payload::encode_payload;
use sparkplug::seq_counter::{BdSeqCounter, SeqCounter};
use sparkplug::session::{build_nbirth_payload, build_ndeath_payload};
use sparkplug::topic::{MessageType, build_topic};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// An Edge Node's live connection to its own embedded broker, plus the
/// session state later Sparkplug messages (`NDATA` in particular) need to
/// keep advancing correctly rather than restarting from scratch.
pub struct EdgeNodeConnection {
    pub client: AsyncClient,
    pub group_id: String,
    pub edge_node_id: String,
    pub seq_counter: Mutex<SeqCounter>,
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
    // reconnection) while something keeps polling the event loop.
    tokio::spawn(async move {
        loop {
            if let Err(error) = eventloop.poll().await {
                eprintln!("edge node MQTT event loop error: {error}");
            }
        }
    });

    let mut seq_counter = SeqCounter::new();
    let nbirth_payload = build_nbirth_payload(bd_seq, current_timestamp_millis(), &mut seq_counter);
    let mut nbirth_bytes = Vec::new();
    encode_payload(&nbirth_payload, &mut nbirth_bytes);
    let nbirth_topic = build_topic(group_id, MessageType::NBirth, edge_node_id, None)
        .expect("NBIRTH is a node-scoped message type and never needs a device_id");
    client
        .publish(nbirth_topic, QoS::AtLeastOnce, false, nbirth_bytes)
        .await
        .expect("failed to publish NBIRTH after connecting");

    EdgeNodeConnection {
        client,
        group_id: group_id.to_string(),
        edge_node_id: edge_node_id.to_string(),
        seq_counter: Mutex::new(seq_counter),
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
}
