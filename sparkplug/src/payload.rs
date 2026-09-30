//! Encode/decode for the top-level Sparkplug B `Payload` message: `timestamp`
//! (field 1), `metrics` (field 2, repeated), `seq` (field 3). `uuid`/`body`
//! (fields 4/5) aren't modeled — no concrete need for them yet (they exist
//! for special cases like file transfer, out of this project's current scope).

use crate::metric::{self, Metric};
use crate::wire::{self, Tag, WireType};

const FIELD_TIMESTAMP: u32 = 1;
const FIELD_METRICS: u32 = 2;
const FIELD_SEQ: u32 = 3;

#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    pub timestamp: Option<u64>,
    pub metrics: Vec<Metric>,
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Wire(wire::DecodeError),
    Metric(metric::DecodeError),
}

impl From<wire::DecodeError> for DecodeError {
    fn from(error: wire::DecodeError) -> Self {
        DecodeError::Wire(error)
    }
}

impl From<metric::DecodeError> for DecodeError {
    fn from(error: metric::DecodeError) -> Self {
        DecodeError::Metric(error)
    }
}

pub fn encode_payload(payload: &Payload, buffer: &mut Vec<u8>) {
    if let Some(timestamp) = payload.timestamp {
        wire::encode_tag(
            Tag {
                field_number: FIELD_TIMESTAMP,
                wire_type: WireType::Varint,
            },
            buffer,
        );
        wire::encode_varint(timestamp, buffer);
    }

    for metric in &payload.metrics {
        wire::encode_tag(
            Tag {
                field_number: FIELD_METRICS,
                wire_type: WireType::LengthDelimited,
            },
            buffer,
        );
        let mut metric_bytes = Vec::new();
        metric::encode_metric(metric, &mut metric_bytes);
        wire::encode_length_delimited(&metric_bytes, buffer);
    }

    if let Some(seq) = payload.seq {
        wire::encode_tag(
            Tag {
                field_number: FIELD_SEQ,
                wire_type: WireType::Varint,
            },
            buffer,
        );
        wire::encode_varint(seq, buffer);
    }
}

pub fn decode_payload(bytes: &[u8]) -> Result<Payload, DecodeError> {
    let mut timestamp = None;
    let mut metrics = Vec::new();
    let mut seq = None;

    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_len) = wire::decode_tag(&bytes[offset..])?;
        offset += tag_len;

        match tag.field_number {
            FIELD_TIMESTAMP => {
                let (value, consumed) = wire::decode_varint(&bytes[offset..])?;
                timestamp = Some(value);
                offset += consumed;
            }
            FIELD_METRICS => {
                let (metric_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                metrics.push(metric::decode_metric(metric_bytes)?);
                offset += consumed;
            }
            FIELD_SEQ => {
                let (value, consumed) = wire::decode_varint(&bytes[offset..])?;
                seq = Some(value);
                offset += consumed;
            }
            _ => {
                offset += wire::skip_field(tag.wire_type, &bytes[offset..])?;
            }
        }
    }

    Ok(Payload {
        timestamp,
        metrics,
        seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_type::DataType;
    use crate::metric_value::MetricValue;

    fn round_trip(payload: Payload) {
        let mut buffer = Vec::new();
        encode_payload(&payload, &mut buffer);
        assert_eq!(decode_payload(&buffer), Ok(payload));
    }

    #[test]
    fn round_trips_empty_payload() {
        round_trip(Payload {
            timestamp: None,
            metrics: Vec::new(),
            seq: None,
        });
    }

    #[test]
    fn round_trips_timestamp_and_seq_only() {
        round_trip(Payload {
            timestamp: Some(1_700_000_000_000),
            metrics: Vec::new(),
            seq: Some(0),
        });
    }

    #[test]
    fn round_trips_a_single_metric() {
        round_trip(Payload {
            timestamp: Some(1_700_000_000_000),
            metrics: vec![Metric {
                name: "bdSeq".to_string(),
                alias: None,
                data_type: DataType::UInt64,
                value: MetricValue::Long(3),
            }],
            seq: Some(0),
        });
    }

    #[test]
    fn round_trips_multiple_metrics_in_order() {
        round_trip(Payload {
            timestamp: Some(1),
            metrics: vec![
                Metric {
                    name: "Tank_Temperature".to_string(),
                    alias: None,
                    data_type: DataType::UInt16,
                    value: MetricValue::Int(21),
                },
                Metric {
                    name: "Motor_Running".to_string(),
                    alias: None,
                    data_type: DataType::Boolean,
                    value: MetricValue::Boolean(true),
                },
                Metric {
                    name: "Flow_Rate".to_string(),
                    alias: None,
                    data_type: DataType::Float,
                    value: MetricValue::Float(12.5),
                },
            ],
            seq: Some(5),
        });
    }

    #[test]
    fn decode_skips_unknown_top_level_field() {
        let mut buffer = Vec::new();
        // An unmodeled field: uuid (field 4), length-delimited wire type.
        wire::encode_tag(
            Tag {
                field_number: 4,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        wire::encode_length_delimited(b"some-uuid", &mut buffer);

        let payload = Payload {
            timestamp: Some(42),
            metrics: Vec::new(),
            seq: Some(1),
        };
        encode_payload(&payload, &mut buffer);

        assert_eq!(decode_payload(&buffer), Ok(payload));
    }

    #[test]
    fn decode_propagates_metric_decode_errors() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: FIELD_METRICS,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        // An empty embedded Metric message: missing every required field.
        wire::encode_length_delimited(&[], &mut buffer);

        assert_eq!(
            decode_payload(&buffer),
            Err(DecodeError::Metric(metric::DecodeError::MissingName))
        );
    }

    #[test]
    fn decode_propagates_wire_errors() {
        assert_eq!(
            decode_payload(&[0xFF]),
            Err(DecodeError::Wire(wire::DecodeError::TooShort))
        );
    }
}
