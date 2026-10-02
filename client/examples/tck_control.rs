// Direct-MQTT control interface for the Eclipse Sparkplug TCK, bypassing its
// web console entirely. Reverse-engineered from the TCK's own source
// (PublishInterceptor.java + Constants.java): the console itself is just an
// MQTT publisher on SPARKPLUG_TCK/TEST_CONTROL ("NEW_TEST <PROFILE>
// <TestClassName> <parms...>" / "END_TEST"), and results/log lines are
// published on SPARKPLUG_TCK/RESULT and SPARKPLUG_TCK/LOG. Kept around (not
// deleted after use, unlike most manual-verification harnesses in this
// project) since the web console's own "start test" action never reliably
// worked — see CLAUDE.md's M10 section.
//
// Usage:
//   cargo run -p client --example tck_control -- <port> start <hostAppId> <groupId> <edgeNodeId> [deviceIds...]
//   cargo run -p client --example tck_control -- <port> stop
//   cargo run -p client --example tck_control -- <port> watch <seconds>

use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
use std::time::Duration;

const TEST_CONTROL_TOPIC: &str = "SPARKPLUG_TCK/TEST_CONTROL";
const RESULT_TOPIC: &str = "SPARKPLUG_TCK/RESULT";
const LOG_TOPIC: &str = "SPARKPLUG_TCK/LOG";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port: u16 = args[0].parse().unwrap();
    let mode = &args[1];

    let client_id = format!("tck_control_{mode}_{}", std::process::id());
    let mut options = MqttOptions::new(client_id, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(30));
    let (client, mut eventloop) = AsyncClient::new(options, 10);

    tokio::spawn(async move {
        loop {
            if eventloop.poll().await.is_err() {
                break;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    match mode.as_str() {
        "start" => {
            let host_app_id = &args[2];
            let group_id = &args[3];
            let edge_node_id = &args[4];
            let device_ids = &args[5..];
            let payload = format!(
                "NEW_TEST EDGE SessionEstablishmentTest {host_app_id} {group_id} {edge_node_id} {}",
                device_ids.join(" ")
            );
            println!("publishing to {TEST_CONTROL_TOPIC}: {payload:?}");
            client
                .publish(TEST_CONTROL_TOPIC, QoS::AtLeastOnce, false, payload)
                .await
                .unwrap();
        }
        "stop" => {
            println!("publishing to {TEST_CONTROL_TOPIC}: \"END_TEST\"");
            client
                .publish(TEST_CONTROL_TOPIC, QoS::AtLeastOnce, false, "END_TEST")
                .await
                .unwrap();
        }
        "watch" => {
            let seconds: u64 = args[2].parse().unwrap();
            client
                .subscribe(RESULT_TOPIC, QoS::AtLeastOnce)
                .await
                .unwrap();
            client.subscribe(LOG_TOPIC, QoS::AtLeastOnce).await.unwrap();
            let (client2, mut eventloop2) = {
                let mut options2 = MqttOptions::new(
                    format!("tck_control_watch2_{}", std::process::id()),
                    "127.0.0.1",
                    port,
                );
                options2.set_keep_alive(Duration::from_secs(30));
                AsyncClient::new(options2, 10)
            };
            client2
                .subscribe(RESULT_TOPIC, QoS::AtLeastOnce)
                .await
                .unwrap();
            client2
                .subscribe(LOG_TOPIC, QoS::AtLeastOnce)
                .await
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, eventloop2.poll()).await {
                    Ok(Ok(Event::Incoming(Incoming::Publish(publish)))) => {
                        let text = String::from_utf8_lossy(&publish.payload);
                        println!("{} -> {}", publish.topic, text);
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(error)) => {
                        println!("eventloop error: {error}");
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
        other => panic!("unknown mode {other}"),
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
}
