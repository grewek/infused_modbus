//! Encode/decode for Sparkplug B's `Metric` message — the missing link between
//! `wire`'s raw protobuf primitives and `data_type`/`metric_value`'s pure data
//! types. Deliberately minimal: `name` (field 1), `alias` (field 2), `datatype`
//! (field 4), and the scalar `value` oneof (fields 10-16, via `MetricValue`)
//! are modeled. `timestamp`/`is_historical`/`is_transient`/`is_null`/
//! `metadata`/`properties` aren't yet — no concrete need for them has shown
//! up; add them once one does, per this project's Extraction-Based
//! Programming convention. (`alias` itself was added in M5, once
//! `client::sparkplug_alias`'s per-Edge-Node alias assignment became a real
//! need — M4 had deliberately left it out for the same reason.)

use crate::data_type::DataType;
use crate::metric_value::MetricValue;
use crate::wire::{self, Tag, WireType};

const FIELD_NAME: u32 = 1;
const FIELD_ALIAS: u32 = 2;
const FIELD_DATATYPE: u32 = 4;
const FIELD_INT_VALUE: u32 = 10;
const FIELD_LONG_VALUE: u32 = 11;
const FIELD_FLOAT_VALUE: u32 = 12;
const FIELD_DOUBLE_VALUE: u32 = 13;
const FIELD_BOOLEAN_VALUE: u32 = 14;
const FIELD_STRING_VALUE: u32 = 15;
const FIELD_BYTES_VALUE: u32 = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    pub name: String,
    pub alias: Option<u64>,
    pub data_type: DataType,
    pub value: MetricValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Wire(wire::DecodeError),
    /// Neither `name` nor `alias` was present — per spec a metric always
    /// carries at least one of the two (a `BIRTH` message always has `name`;
    /// a `DATA`/`CMD` message from a real host application may carry only
    /// `alias`, per spec's own bandwidth-saving convention, once the alias
    /// was established by an earlier `BIRTH`). A metric with neither can't
    /// be identified at all.
    MissingIdentifier,
    MissingDataType,
    MissingValue,
    UnknownDataTypeCode(u32),
}

impl From<wire::DecodeError> for DecodeError {
    fn from(error: wire::DecodeError) -> Self {
        DecodeError::Wire(error)
    }
}

pub fn encode_metric(metric: &Metric, buffer: &mut Vec<u8>) {
    wire::encode_tag(
        Tag {
            field_number: FIELD_NAME,
            wire_type: WireType::LengthDelimited,
        },
        buffer,
    );
    wire::encode_length_delimited(metric.name.as_bytes(), buffer);

    if let Some(alias) = metric.alias {
        wire::encode_tag(
            Tag {
                field_number: FIELD_ALIAS,
                wire_type: WireType::Varint,
            },
            buffer,
        );
        wire::encode_varint(alias, buffer);
    }

    wire::encode_tag(
        Tag {
            field_number: FIELD_DATATYPE,
            wire_type: WireType::Varint,
        },
        buffer,
    );
    wire::encode_varint(u64::from(u32::from(metric.data_type)), buffer);

    match &metric.value {
        MetricValue::Int(value) => {
            wire::encode_tag(
                Tag {
                    field_number: FIELD_INT_VALUE,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(u64::from(*value), buffer);
        }
        MetricValue::Long(value) => {
            wire::encode_tag(
                Tag {
                    field_number: FIELD_LONG_VALUE,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(*value, buffer);
        }
        MetricValue::Float(value) => {
            wire::encode_tag(
                Tag {
                    field_number: FIELD_FLOAT_VALUE,
                    wire_type: WireType::Fixed32,
                },
                buffer,
            );
            wire::encode_fixed32(value.to_bits(), buffer);
        }
        MetricValue::Double(value) => {
            wire::encode_tag(
                Tag {
                    field_number: FIELD_DOUBLE_VALUE,
                    wire_type: WireType::Fixed64,
                },
                buffer,
            );
            wire::encode_fixed64(value.to_bits(), buffer);
        }
        MetricValue::Boolean(value) => {
            wire::encode_tag(
                Tag {
                    field_number: FIELD_BOOLEAN_VALUE,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(u64::from(*value), buffer);
        }
        MetricValue::String(value) => {
            wire::encode_tag(
                Tag {
                    field_number: FIELD_STRING_VALUE,
                    wire_type: WireType::LengthDelimited,
                },
                buffer,
            );
            wire::encode_length_delimited(value.as_bytes(), buffer);
        }
        MetricValue::Bytes(value) => {
            wire::encode_tag(
                Tag {
                    field_number: FIELD_BYTES_VALUE,
                    wire_type: WireType::LengthDelimited,
                },
                buffer,
            );
            wire::encode_length_delimited(value, buffer);
        }
    }
}

/// Decodes exactly one `Metric` message from `bytes` (the already-extracted
/// contents of a length-delimited `metrics` entry, not a whole `Payload`).
/// Unknown field numbers are skipped based on their wire type rather than
/// rejected — a real Sparkplug B message may carry fields this crate doesn't
/// model (`alias`, `timestamp`, ...), and skipping them is the only way to
/// still parse the fields this crate does care about.
pub fn decode_metric(bytes: &[u8]) -> Result<Metric, DecodeError> {
    let mut name: Option<String> = None;
    let mut alias: Option<u64> = None;
    let mut data_type: Option<DataType> = None;
    let mut value: Option<MetricValue> = None;

    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_len) = wire::decode_tag(&bytes[offset..])?;
        offset += tag_len;

        match tag.field_number {
            FIELD_NAME => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                name = Some(String::from_utf8_lossy(field_bytes).into_owned());
                offset += consumed;
            }
            FIELD_ALIAS => {
                let (value, consumed) = wire::decode_varint(&bytes[offset..])?;
                alias = Some(value);
                offset += consumed;
            }
            FIELD_DATATYPE => {
                let (code, consumed) = wire::decode_varint(&bytes[offset..])?;
                // `datatype` is a wire `uint32` field — truncate to 32 bits
                // like any protobuf uint32, don't reject an oversized varint.
                let code = code as u32;
                data_type = Some(
                    DataType::try_from(code).map_err(|_| DecodeError::UnknownDataTypeCode(code))?,
                );
                offset += consumed;
            }
            FIELD_INT_VALUE => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(MetricValue::Int(raw as u32));
                offset += consumed;
            }
            FIELD_LONG_VALUE => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(MetricValue::Long(raw));
                offset += consumed;
            }
            FIELD_FLOAT_VALUE => {
                let (raw, consumed) = wire::decode_fixed32(&bytes[offset..])?;
                value = Some(MetricValue::Float(f32::from_bits(raw)));
                offset += consumed;
            }
            FIELD_DOUBLE_VALUE => {
                let (raw, consumed) = wire::decode_fixed64(&bytes[offset..])?;
                value = Some(MetricValue::Double(f64::from_bits(raw)));
                offset += consumed;
            }
            FIELD_BOOLEAN_VALUE => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(MetricValue::Boolean(raw != 0));
                offset += consumed;
            }
            FIELD_STRING_VALUE => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                value = Some(MetricValue::String(
                    String::from_utf8_lossy(field_bytes).into_owned(),
                ));
                offset += consumed;
            }
            FIELD_BYTES_VALUE => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                value = Some(MetricValue::Bytes(field_bytes.to_vec()));
                offset += consumed;
            }
            _ => {
                offset += wire::skip_field(tag.wire_type, &bytes[offset..])?;
            }
        }
    }

    if name.is_none() && alias.is_none() {
        return Err(DecodeError::MissingIdentifier);
    }

    Ok(Metric {
        name: name.unwrap_or_default(),
        alias,
        data_type: data_type.ok_or(DecodeError::MissingDataType)?,
        value: value.ok_or(DecodeError::MissingValue)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(metric: Metric) {
        let mut buffer = Vec::new();
        encode_metric(&metric, &mut buffer);
        assert_eq!(decode_metric(&buffer), Ok(metric));
    }

    #[test]
    fn round_trips_int_value() {
        round_trip(Metric {
            name: "Status_Flags".to_string(),
            alias: None,
            data_type: DataType::UInt8,
            value: MetricValue::Int(42),
        });
    }

    #[test]
    fn round_trips_with_an_alias_present() {
        round_trip(Metric {
            name: "Tank_Temperature".to_string(),
            alias: Some(7),
            data_type: DataType::UInt16,
            value: MetricValue::Int(21),
        });
    }

    #[test]
    fn round_trips_long_value() {
        round_trip(Metric {
            name: "bdSeq".to_string(),
            alias: None,
            data_type: DataType::UInt64,
            value: MetricValue::Long(7),
        });
    }

    #[test]
    fn round_trips_float_value() {
        round_trip(Metric {
            name: "Frequency".to_string(),
            alias: None,
            data_type: DataType::Float,
            value: MetricValue::Float(50.05),
        });
    }

    #[test]
    fn round_trips_double_value() {
        round_trip(Metric {
            name: "Flow_Rate".to_string(),
            alias: None,
            data_type: DataType::Double,
            value: MetricValue::Double(12.345_678_9),
        });
    }

    #[test]
    fn round_trips_boolean_value() {
        round_trip(Metric {
            name: "Motor_Running".to_string(),
            alias: None,
            data_type: DataType::Boolean,
            value: MetricValue::Boolean(true),
        });
    }

    #[test]
    fn round_trips_string_value() {
        round_trip(Metric {
            name: "server-id".to_string(),
            alias: None,
            data_type: DataType::String,
            value: MetricValue::String("pump-a-plc".to_string()),
        });
    }

    #[test]
    fn round_trips_bytes_value() {
        round_trip(Metric {
            name: "file-record".to_string(),
            alias: None,
            data_type: DataType::Bytes,
            value: MetricValue::Bytes(vec![0x0D, 0xFE, 0x00, 0x20]),
        });
    }

    #[test]
    fn decode_rejects_metric_missing_both_name_and_alias() {
        // Manually built (rather than via encode_metric) so both the name
        // and alias fields are genuinely absent, not just empty/None.
        let mut without_identifier = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: FIELD_DATATYPE,
                wire_type: WireType::Varint,
            },
            &mut without_identifier,
        );
        wire::encode_varint(
            u64::from(u32::from(DataType::Boolean)),
            &mut without_identifier,
        );
        wire::encode_tag(
            Tag {
                field_number: FIELD_BOOLEAN_VALUE,
                wire_type: WireType::Varint,
            },
            &mut without_identifier,
        );
        wire::encode_varint(1, &mut without_identifier);
        assert_eq!(
            decode_metric(&without_identifier),
            Err(DecodeError::MissingIdentifier)
        );
    }

    #[test]
    fn decode_accepts_a_metric_identified_by_alias_alone() {
        // The real shape of an incoming DCMD/DDATA from a spec-conformant
        // host application, which stops re-sending `name` once a BIRTH has
        // established the alias — see CLAUDE.md's M7 notes.
        let mut alias_only = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: FIELD_ALIAS,
                wire_type: WireType::Varint,
            },
            &mut alias_only,
        );
        wire::encode_varint(7, &mut alias_only);
        wire::encode_tag(
            Tag {
                field_number: FIELD_DATATYPE,
                wire_type: WireType::Varint,
            },
            &mut alias_only,
        );
        wire::encode_varint(u64::from(u32::from(DataType::UInt16)), &mut alias_only);
        wire::encode_tag(
            Tag {
                field_number: FIELD_INT_VALUE,
                wire_type: WireType::Varint,
            },
            &mut alias_only,
        );
        wire::encode_varint(21, &mut alias_only);

        assert_eq!(
            decode_metric(&alias_only),
            Ok(Metric {
                name: String::new(),
                alias: Some(7),
                data_type: DataType::UInt16,
                value: MetricValue::Int(21),
            })
        );
    }

    #[test]
    fn decode_skips_unknown_field_and_still_parses_known_ones() {
        let mut buffer = Vec::new();
        // An unmodeled field: timestamp (field 3), varint wire type.
        wire::encode_tag(
            Tag {
                field_number: 3,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(999, &mut buffer);

        let metric = Metric {
            name: "Tank_Temperature".to_string(),
            alias: None,
            data_type: DataType::UInt16,
            value: MetricValue::Int(21),
        };
        encode_metric(&metric, &mut buffer);

        assert_eq!(decode_metric(&buffer), Ok(metric));
    }

    #[test]
    fn decode_rejects_unknown_data_type_code() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: FIELD_NAME,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        wire::encode_length_delimited(b"X", &mut buffer);
        wire::encode_tag(
            Tag {
                field_number: FIELD_DATATYPE,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(9999, &mut buffer);
        assert_eq!(
            decode_metric(&buffer),
            Err(DecodeError::UnknownDataTypeCode(9999))
        );
    }

    #[test]
    fn decode_propagates_wire_errors() {
        assert_eq!(
            decode_metric(&[0xFF]),
            Err(DecodeError::Wire(wire::DecodeError::TooShort))
        );
    }
}
