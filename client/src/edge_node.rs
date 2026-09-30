//! `client` acting as a Sparkplug B Edge Node — its own MQTT client, connected
//! by loopback to the broker it embeds itself (`client::broker`). This is
//! separate from any external consumer (Node-RED, a SCADA host application,
//! ...) connecting to the same broker over the network; those never go
//! through this module.

use rumqttc::{AsyncClient, Event, Incoming, MqttOptions};
use std::time::Duration;

/// An Edge Node's live connection to its own embedded broker.
pub struct EdgeNodeConnection {
    pub client: AsyncClient,
}

/// Connects to the broker at `broker_host:broker_port` as an MQTT client
/// identified by `client_id`, waits for the connection to actually be
/// acknowledged, then keeps driving the connection in the background for the
/// rest of the process's life. Panics if the initial connection attempt
/// fails — connecting to our own just-started embedded broker is a startup
/// precondition, the same "first connection failing is fatal" stance already
/// used for the Modbus connection in `client::main`.
pub async fn connect_edge_node(
    client_id: &str,
    broker_host: &str,
    broker_port: u16,
) -> EdgeNodeConnection {
    let mut options = MqttOptions::new(client_id, broker_host, broker_port);
    options.set_keep_alive(Duration::from_secs(30));
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

    EdgeNodeConnection { client }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{BrokerConfig, start_embedded_broker};
    use rumqttc::QoS;
    use tokio::time::timeout;

    #[tokio::test(flavor = "multi_thread")]
    async fn edge_node_publish_is_received_by_an_external_subscriber() {
        timeout(Duration::from_secs(10), async {
            let port = 18831;
            start_embedded_broker(BrokerConfig {
                listen_address: format!("127.0.0.1:{port}"),
                ..BrokerConfig::default()
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let edge_node = connect_edge_node("test-edge-node", "127.0.0.1", port).await;

            // Stands in for an external consumer (e.g. Node-RED) connecting
            // to the same broker over the network, never through this crate.
            let mut external_options = MqttOptions::new("external-subscriber", "127.0.0.1", port);
            external_options.set_keep_alive(Duration::from_secs(30));
            let (external_client, mut external_eventloop) = AsyncClient::new(external_options, 10);
            external_client
                .subscribe("test/topic", QoS::AtLeastOnce)
                .await
                .unwrap();
            loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::SubAck(_)) => break,
                    _ => continue,
                }
            }

            edge_node
                .client
                .publish("test/topic", QoS::AtLeastOnce, false, b"hello".to_vec())
                .await
                .unwrap();

            let received_payload = loop {
                match external_eventloop.poll().await.unwrap() {
                    Event::Incoming(Incoming::Publish(publish)) => break publish.payload,
                    _ => continue,
                }
            };
            assert_eq!(received_payload.as_ref(), b"hello");
        })
        .await
        .expect("test timed out");
    }
}
