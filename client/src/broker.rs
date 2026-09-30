//! Embeds an MQTT broker (`rumqttd`) directly in the `client` process, per the
//! MQTT/Sparkplug B design in CLAUDE.md — a technician still runs one binary,
//! no separate broker service to stand up. `client` itself later connects to
//! this broker as its own loopback MQTT client (see M3's remaining steps) to
//! publish Sparkplug B data; external consumers (Node-RED, a SCADA host
//! application, ...) connect to the same listener over the network.
//!
//! `rumqttd::Config` is only ever built via its own `serde::Deserialize` impl
//! from TOML (the officially documented embedding path), never hand-
//! constructed in Rust — its exact field shape isn't public API this crate
//! should depend on directly. `BrokerConfig` below is what's actually
//! user-configurable; it gets interpolated into that TOML template. CLI flag
//! wiring so a technician can actually set these from the command line (vs. a
//! caller constructing a `BrokerConfig` value in code) is still M9's job, not
//! this module's — but every field a real deployment could plausibly need to
//! change already exists as a parameter here, not hardcoded, so nothing about
//! *this* module can leave a technician stuck once M9 wires it up.

use rumqttd::{Broker, Config};
use serde::Deserialize;
use std::fmt;

/// The subset of `rumqttd`'s configuration a technician needs to control.
/// Every field here is something a real deployment could plausibly be
/// blocked by if it were fixed: a `max_payload_size` too small for a large
/// NBIRTH, a `max_connections`/`max_inflight_count` too low for many
/// Node-RED/SCADA consumers, a `connection_timeout_ms` too short over a
/// flaky link, or a segment budget too large for memory-constrained
/// industrial hardware. Deliberately still not every `rumqttd` knob (TLS,
/// WebSocket, bridging, per-client ACLs, ...) — those have no concrete need
/// yet; add them when one shows up, not speculatively.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// e.g. `"0.0.0.0:1883"` to accept connections from any interface, or
    /// `"127.0.0.1:1883"` to restrict the broker to the local machine only.
    pub listen_address: String,
    /// Maximum number of simultaneously connected MQTT clients.
    pub max_connections: u64,
    /// Maximum size, in bytes, of a single MQTT publish payload.
    pub max_payload_size: u32,
    /// How long an idle connection is tolerated before being dropped.
    pub connection_timeout_ms: u32,
    /// Maximum number of unacknowledged QoS 1/2 messages per connection.
    pub max_inflight_count: u16,
    /// Size, in bytes, of one commit-log segment.
    pub max_segment_size: u64,
    /// How many commit-log segments are retained.
    pub max_segment_count: u32,
}

impl Default for BrokerConfig {
    /// Mirrors `rumqttd`'s own published demo configuration values.
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:1883".to_string(),
            max_connections: 10_010,
            max_payload_size: 20_480,
            connection_timeout_ms: 60_000,
            max_inflight_count: 100,
            max_segment_size: 104_857_600,
            max_segment_count: 10,
        }
    }
}

/// Mirrors `BrokerConfig`, but with every field optional — parsed from an
/// operator-supplied `--mqtt-broker-config <path.toml>` (M9), where an
/// absent field keeps `BrokerConfig::default()`'s value. Same
/// `deny_unknown_fields` discipline as `datafs::permissions::
/// FusePermissions`'s own `RawFusePermissions`, so a typo'd key is a hard
/// parse error rather than a silently-ignored setting.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBrokerConfig {
    listen_address: Option<String>,
    max_connections: Option<u64>,
    max_payload_size: Option<u32>,
    connection_timeout_ms: Option<u32>,
    max_inflight_count: Option<u16>,
    max_segment_size: Option<u64>,
    max_segment_count: Option<u32>,
}

#[derive(Debug)]
pub struct BrokerConfigError(toml::de::Error);

impl fmt::Display for BrokerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for BrokerConfigError {}

impl From<toml::de::Error> for BrokerConfigError {
    fn from(error: toml::de::Error) -> Self {
        BrokerConfigError(error)
    }
}

impl BrokerConfig {
    /// Parses a `BrokerConfig` from TOML, defaulting every field
    /// `toml_source` doesn't set. An empty source is equivalent to
    /// `BrokerConfig::default()` entirely.
    pub fn parse(toml_source: &str) -> Result<Self, BrokerConfigError> {
        let raw: RawBrokerConfig = toml::from_str(toml_source)?;
        let default = BrokerConfig::default();
        Ok(BrokerConfig {
            listen_address: raw.listen_address.unwrap_or(default.listen_address),
            max_connections: raw.max_connections.unwrap_or(default.max_connections),
            max_payload_size: raw.max_payload_size.unwrap_or(default.max_payload_size),
            connection_timeout_ms: raw
                .connection_timeout_ms
                .unwrap_or(default.connection_timeout_ms),
            max_inflight_count: raw.max_inflight_count.unwrap_or(default.max_inflight_count),
            max_segment_size: raw.max_segment_size.unwrap_or(default.max_segment_size),
            max_segment_count: raw.max_segment_count.unwrap_or(default.max_segment_count),
        })
    }
}

fn render_config_toml(broker_config: &BrokerConfig) -> String {
    format!(
        r#"
id = 0

[router]
id = 0
max_connections = {max_connections}
max_outgoing_packet_count = 200
max_segment_size = {max_segment_size}
max_segment_count = {max_segment_count}

[v4.1]
name = "v4-1"
listen = "{listen_address}"
next_connection_delay_ms = 1
    [v4.1.connections]
    connection_timeout_ms = {connection_timeout_ms}
    max_payload_size = {max_payload_size}
    max_inflight_count = {max_inflight_count}
    dynamic_filters = true
"#,
        listen_address = broker_config.listen_address,
        max_connections = broker_config.max_connections,
        max_segment_size = broker_config.max_segment_size,
        max_segment_count = broker_config.max_segment_count,
        connection_timeout_ms = broker_config.connection_timeout_ms,
        max_payload_size = broker_config.max_payload_size,
        max_inflight_count = broker_config.max_inflight_count,
    )
}

/// Starts the embedded broker on its own dedicated thread (`Broker::start` is a
/// blocking call, not async) and returns immediately — does not wait for the
/// listener to actually be accepting connections yet.
pub fn start_embedded_broker(broker_config: BrokerConfig) {
    let config_toml = render_config_toml(&broker_config);
    let config = config::Config::builder()
        .add_source(config::File::from_str(
            &config_toml,
            config::FileFormat::Toml,
        ))
        .build()
        .expect("rendered broker config is valid TOML");
    let rumqttd_config: Config = config
        .try_deserialize()
        .expect("rendered broker config matches rumqttd::Config's shape");

    std::thread::spawn(move || {
        let mut broker = Broker::new(rumqttd_config);
        if let Err(error) = broker.start() {
            eprintln!("embedded MQTT broker stopped: {error}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    fn embedded_broker_accepts_tcp_connections_on_its_configured_address() {
        start_embedded_broker(BrokerConfig {
            listen_address: "127.0.0.1:18830".to_string(),
            ..BrokerConfig::default()
        });
        std::thread::sleep(Duration::from_millis(300));
        let stream = TcpStream::connect("127.0.0.1:18830");
        assert!(
            stream.is_ok(),
            "expected embedded broker to accept a TCP connection on its configured address"
        );
    }

    #[test]
    fn render_config_toml_embeds_every_configurable_field() {
        let toml = render_config_toml(&BrokerConfig {
            listen_address: "127.0.0.1:9999".to_string(),
            max_connections: 42,
            max_payload_size: 12_345,
            connection_timeout_ms: 7_000,
            max_inflight_count: 9,
            max_segment_size: 1_000_000,
            max_segment_count: 3,
        });
        assert!(toml.contains(r#"listen = "127.0.0.1:9999""#));
        assert!(toml.contains("max_connections = 42"));
        assert!(toml.contains("max_payload_size = 12345"));
        assert!(toml.contains("connection_timeout_ms = 7000"));
        assert!(toml.contains("max_inflight_count = 9"));
        assert!(toml.contains("max_segment_size = 1000000"));
        assert!(toml.contains("max_segment_count = 3"));
    }

    #[test]
    fn default_config_matches_rumqttds_own_demo_values() {
        let default = BrokerConfig::default();
        assert_eq!(default.listen_address, "0.0.0.0:1883");
        assert_eq!(default.max_connections, 10_010);
        assert_eq!(default.max_payload_size, 20_480);
        assert_eq!(default.connection_timeout_ms, 60_000);
        assert_eq!(default.max_inflight_count, 100);
        assert_eq!(default.max_segment_size, 104_857_600);
        assert_eq!(default.max_segment_count, 10);
    }

    #[test]
    fn parse_of_empty_source_uses_defaults_for_every_field() {
        let parsed = BrokerConfig::parse("").unwrap();
        let default = BrokerConfig::default();
        assert_eq!(parsed.listen_address, default.listen_address);
        assert_eq!(parsed.max_connections, default.max_connections);
        assert_eq!(parsed.max_payload_size, default.max_payload_size);
        assert_eq!(parsed.connection_timeout_ms, default.connection_timeout_ms);
        assert_eq!(parsed.max_inflight_count, default.max_inflight_count);
        assert_eq!(parsed.max_segment_size, default.max_segment_size);
        assert_eq!(parsed.max_segment_count, default.max_segment_count);
    }

    #[test]
    fn parse_reads_a_fully_specified_config() {
        let parsed = BrokerConfig::parse(
            r#"
            listen_address = "127.0.0.1:9999"
            max_connections = 42
            max_payload_size = 12345
            connection_timeout_ms = 7000
            max_inflight_count = 9
            max_segment_size = 1000000
            max_segment_count = 3
            "#,
        )
        .unwrap();
        assert_eq!(parsed.listen_address, "127.0.0.1:9999");
        assert_eq!(parsed.max_connections, 42);
        assert_eq!(parsed.max_payload_size, 12_345);
        assert_eq!(parsed.connection_timeout_ms, 7_000);
        assert_eq!(parsed.max_inflight_count, 9);
        assert_eq!(parsed.max_segment_size, 1_000_000);
        assert_eq!(parsed.max_segment_count, 3);
    }

    #[test]
    fn parse_supports_a_partial_override() {
        let parsed = BrokerConfig::parse(r#"listen_address = "127.0.0.1:1884""#).unwrap();
        assert_eq!(parsed.listen_address, "127.0.0.1:1884");
        assert_eq!(
            parsed.max_connections,
            BrokerConfig::default().max_connections
        );
    }

    #[test]
    fn parse_rejects_an_unknown_field() {
        assert!(BrokerConfig::parse("not_a_real_field = 1").is_err());
    }

    #[test]
    fn parse_rejects_invalid_toml_syntax() {
        assert!(BrokerConfig::parse("not valid toml [[[").is_err());
    }
}
