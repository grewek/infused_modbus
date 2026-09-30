//! From-scratch Eclipse Sparkplug B implementation: protobuf wire format for the
//! fixed Sparkplug `Payload`/`Metric`/`PropertySet` message set, topic namespace,
//! and session (seq/bdSeq) semantics. Not a general-purpose protobuf library.

pub mod data_type;
pub mod metric_value;
pub mod topic;
pub mod wire;
