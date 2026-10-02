pub mod batching;
pub mod bd_seq_persistence;
// Test-only: spins up a real in-process broker for the MQTT/Sparkplug test
// suite (edge_node.rs, sparkplug_command.rs). Not used in production — this
// project connects to an already-running external broker instead (see
// CLAUDE.md's "MQTT (Sparkplug B) representation layer"), so `rumqttd` lives
// in [dev-dependencies] and this module is unavailable outside `cargo test`.
#[cfg(test)]
pub(crate) mod broker;
pub mod connection;
pub mod device_identification;
pub mod edge_node;
pub mod polling;
pub mod primary_host_state;
pub mod reconnect;
pub mod sparkplug_alias;
pub mod sparkplug_change_tracker;
pub mod sparkplug_command;
pub mod sparkplug_translator;
pub mod transaction_consumer;
pub mod write_confirmation;
