//! The scalar shape of `Metric.value` (Sparkplug B's protobuf `oneof`, fields
//! 10-16). `dataset_value`/`template_value`/`extension_value` (fields 17-19)
//! are deliberately not modeled — no concrete need for composite/array metric
//! values yet; every value this project produces from Modbus data is scalar.

#[derive(Debug, Clone, PartialEq)]
pub enum MetricValue {
    Int(u32),
    Long(u64),
    Float(f32),
    Double(f64),
    Boolean(bool),
    String(String),
    Bytes(Vec<u8>),
}
