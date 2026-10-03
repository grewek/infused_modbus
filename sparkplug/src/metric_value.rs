//! The shape of `Metric.value` (Sparkplug B's protobuf `oneof`, fields
//! 10-17). `template_value`/`extension_value` (fields 18-19) are deliberately
//! not modeled — no concrete need for templates or composite/array metric
//! values yet; every scalar value this project produces from Modbus data is
//! one of the first seven variants here. `DataSet` (field 17, see
//! `data_set::DataSet`) was added per CLAUDE.md's Thread B3 as a general
//! capability — not yet produced by any Modbus-derived metric, but a real
//! wire type this crate can now encode/decode.

use crate::data_set::DataSet;

#[derive(Debug, Clone, PartialEq)]
pub enum MetricValue {
    Int(u32),
    Long(u64),
    Float(f32),
    Double(f64),
    Boolean(bool),
    String(String),
    Bytes(Vec<u8>),
    DataSet(DataSet),
}
