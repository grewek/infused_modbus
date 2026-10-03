//! Encode/decode for Sparkplug B's `PropertyValue` and `PropertySet` messages
//! — the spec's generic per-metric-metadata mechanism (`Metric.properties`,
//! field 9, not yet wired in — see `metric.rs`'s own doc comment). Named
//! `Property`/`PropertyValue` here, mirroring this crate's existing
//! `Metric`/`MetricValue` split: `Property` is the full wire message (the
//! spec calls it `PropertyValue`, renamed here to avoid colliding with the
//! oneof-only type), `PropertyValue` is its scalar `value` oneof.
//!
//! Deliberately minimal, same scope discipline as `MetricValue`: only the
//! scalar oneof variants (fields 3-9: Int/Long/Float/Double/Boolean/String/
//! Bytes) are modeled. `propertyset_value`/`propertysets_value` (fields
//! 10-11, nested `PropertySet`/`PropertySetList`) aren't — no concrete need
//! for nested property sets has shown up yet. `is_null` (field 2) also isn't
//! modeled — unlike `Metric.is_null`, nothing in this project needs a
//! property to exist without a value yet.
//!
//! **`PropertyDataType`'s codes are a genuinely different enumeration from
//! `Metric`'s own `DataType`** (e.g. `Int32` is code 1 here, code 3 there) —
//! the spec defines these as two separate enums that happen to share several
//! names. Don't conflate the two or reuse `data_type::DataType` here.

use crate::wire::{self, Tag, WireType};

const PROPERTY_FIELD_TYPE: u32 = 1;
const PROPERTY_FIELD_INT_VALUE: u32 = 3;
const PROPERTY_FIELD_LONG_VALUE: u32 = 4;
const PROPERTY_FIELD_FLOAT_VALUE: u32 = 5;
const PROPERTY_FIELD_DOUBLE_VALUE: u32 = 6;
const PROPERTY_FIELD_BOOLEAN_VALUE: u32 = 7;
const PROPERTY_FIELD_STRING_VALUE: u32 = 8;
const PROPERTY_FIELD_BYTES_VALUE: u32 = 9;

const PROPERTY_SET_FIELD_KEYS: u32 = 1;
const PROPERTY_SET_FIELD_VALUES: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyDataType {
    Unknown,
    Int32,
    Int64,
    UInt32,
    UInt64,
    Float,
    Double,
    Boolean,
    String,
    DateTime,
    Text,
    Uuid,
    DataSet,
    Bytes,
    File,
    PropertySet,
    PropertySetList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPropertyDataTypeCode {
    pub code: u32,
}

impl From<PropertyDataType> for u32 {
    fn from(data_type: PropertyDataType) -> Self {
        match data_type {
            PropertyDataType::Unknown => 0,
            PropertyDataType::Int32 => 1,
            PropertyDataType::Int64 => 2,
            PropertyDataType::UInt32 => 3,
            PropertyDataType::UInt64 => 4,
            PropertyDataType::Float => 5,
            PropertyDataType::Double => 6,
            PropertyDataType::Boolean => 7,
            PropertyDataType::String => 8,
            PropertyDataType::DateTime => 9,
            PropertyDataType::Text => 10,
            PropertyDataType::Uuid => 11,
            PropertyDataType::DataSet => 12,
            PropertyDataType::Bytes => 13,
            PropertyDataType::File => 14,
            PropertyDataType::PropertySet => 15,
            PropertyDataType::PropertySetList => 16,
        }
    }
}

impl TryFrom<u32> for PropertyDataType {
    type Error = UnknownPropertyDataTypeCode;

    fn try_from(code: u32) -> Result<Self, UnknownPropertyDataTypeCode> {
        match code {
            0 => Ok(PropertyDataType::Unknown),
            1 => Ok(PropertyDataType::Int32),
            2 => Ok(PropertyDataType::Int64),
            3 => Ok(PropertyDataType::UInt32),
            4 => Ok(PropertyDataType::UInt64),
            5 => Ok(PropertyDataType::Float),
            6 => Ok(PropertyDataType::Double),
            7 => Ok(PropertyDataType::Boolean),
            8 => Ok(PropertyDataType::String),
            9 => Ok(PropertyDataType::DateTime),
            10 => Ok(PropertyDataType::Text),
            11 => Ok(PropertyDataType::Uuid),
            12 => Ok(PropertyDataType::DataSet),
            13 => Ok(PropertyDataType::Bytes),
            14 => Ok(PropertyDataType::File),
            15 => Ok(PropertyDataType::PropertySet),
            16 => Ok(PropertyDataType::PropertySetList),
            _ => Err(UnknownPropertyDataTypeCode { code }),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    Int(u32),
    Long(u64),
    Float(f32),
    Double(f64),
    Boolean(bool),
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Property {
    pub data_type: PropertyDataType,
    pub value: PropertyValue,
}

/// One `PropertySet`: an ordered list of key/property pairs. Modeled as a
/// `Vec` rather than a `HashMap` — the wire format is two parallel repeated
/// fields (`keys`, `values`) matched up by position, and a `Vec` preserves
/// that order exactly rather than losing or reshuffling it.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertySet {
    pub entries: Vec<(String, Property)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Wire(wire::DecodeError),
    MissingDataType,
    MissingValue,
    UnknownDataTypeCode(u32),
    /// `PropertySet.keys`/`PropertySet.values` are two independently-repeated
    /// wire fields the spec requires to be the same length (position `i` in
    /// one corresponds to position `i` in the other) — a real peer sending
    /// mismatched counts has sent a message with no sound interpretation.
    MismatchedKeyValueCounts {
        keys: usize,
        values: usize,
    },
}

impl From<wire::DecodeError> for DecodeError {
    fn from(error: wire::DecodeError) -> Self {
        DecodeError::Wire(error)
    }
}

pub fn encode_property(property: &Property, buffer: &mut Vec<u8>) {
    wire::encode_tag(
        Tag {
            field_number: PROPERTY_FIELD_TYPE,
            wire_type: WireType::Varint,
        },
        buffer,
    );
    wire::encode_varint(u64::from(u32::from(property.data_type)), buffer);

    match &property.value {
        PropertyValue::Int(value) => {
            wire::encode_tag(
                Tag {
                    field_number: PROPERTY_FIELD_INT_VALUE,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(u64::from(*value), buffer);
        }
        PropertyValue::Long(value) => {
            wire::encode_tag(
                Tag {
                    field_number: PROPERTY_FIELD_LONG_VALUE,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(*value, buffer);
        }
        PropertyValue::Float(value) => {
            wire::encode_tag(
                Tag {
                    field_number: PROPERTY_FIELD_FLOAT_VALUE,
                    wire_type: WireType::Fixed32,
                },
                buffer,
            );
            wire::encode_fixed32(value.to_bits(), buffer);
        }
        PropertyValue::Double(value) => {
            wire::encode_tag(
                Tag {
                    field_number: PROPERTY_FIELD_DOUBLE_VALUE,
                    wire_type: WireType::Fixed64,
                },
                buffer,
            );
            wire::encode_fixed64(value.to_bits(), buffer);
        }
        PropertyValue::Boolean(value) => {
            wire::encode_tag(
                Tag {
                    field_number: PROPERTY_FIELD_BOOLEAN_VALUE,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(u64::from(*value), buffer);
        }
        PropertyValue::String(value) => {
            wire::encode_tag(
                Tag {
                    field_number: PROPERTY_FIELD_STRING_VALUE,
                    wire_type: WireType::LengthDelimited,
                },
                buffer,
            );
            wire::encode_length_delimited(value.as_bytes(), buffer);
        }
        PropertyValue::Bytes(value) => {
            wire::encode_tag(
                Tag {
                    field_number: PROPERTY_FIELD_BYTES_VALUE,
                    wire_type: WireType::LengthDelimited,
                },
                buffer,
            );
            wire::encode_length_delimited(value, buffer);
        }
    }
}

/// Decodes exactly one `Property` message from `bytes` (the already-extracted
/// contents of a length-delimited `values` entry, not a whole `PropertySet`).
/// Unknown field numbers are skipped based on their wire type, same as
/// `metric::decode_metric` — a real peer's `PropertyValue` may carry fields
/// this crate doesn't model (`is_null`, `propertyset_value`, ...).
pub fn decode_property(bytes: &[u8]) -> Result<Property, DecodeError> {
    let mut data_type: Option<PropertyDataType> = None;
    let mut value: Option<PropertyValue> = None;

    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_len) = wire::decode_tag(&bytes[offset..])?;
        offset += tag_len;

        match tag.field_number {
            PROPERTY_FIELD_TYPE => {
                let (code, consumed) = wire::decode_varint(&bytes[offset..])?;
                let code = code as u32;
                data_type = Some(
                    PropertyDataType::try_from(code)
                        .map_err(|_| DecodeError::UnknownDataTypeCode(code))?,
                );
                offset += consumed;
            }
            PROPERTY_FIELD_INT_VALUE => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(PropertyValue::Int(raw as u32));
                offset += consumed;
            }
            PROPERTY_FIELD_LONG_VALUE => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(PropertyValue::Long(raw));
                offset += consumed;
            }
            PROPERTY_FIELD_FLOAT_VALUE => {
                let (raw, consumed) = wire::decode_fixed32(&bytes[offset..])?;
                value = Some(PropertyValue::Float(f32::from_bits(raw)));
                offset += consumed;
            }
            PROPERTY_FIELD_DOUBLE_VALUE => {
                let (raw, consumed) = wire::decode_fixed64(&bytes[offset..])?;
                value = Some(PropertyValue::Double(f64::from_bits(raw)));
                offset += consumed;
            }
            PROPERTY_FIELD_BOOLEAN_VALUE => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(PropertyValue::Boolean(raw != 0));
                offset += consumed;
            }
            PROPERTY_FIELD_STRING_VALUE => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                value = Some(PropertyValue::String(
                    String::from_utf8_lossy(field_bytes).into_owned(),
                ));
                offset += consumed;
            }
            PROPERTY_FIELD_BYTES_VALUE => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                value = Some(PropertyValue::Bytes(field_bytes.to_vec()));
                offset += consumed;
            }
            _ => {
                offset += wire::skip_field(tag.wire_type, &bytes[offset..])?;
            }
        }
    }

    Ok(Property {
        data_type: data_type.ok_or(DecodeError::MissingDataType)?,
        value: value.ok_or(DecodeError::MissingValue)?,
    })
}

pub fn encode_property_set(property_set: &PropertySet, buffer: &mut Vec<u8>) {
    for (key, property) in &property_set.entries {
        wire::encode_tag(
            Tag {
                field_number: PROPERTY_SET_FIELD_KEYS,
                wire_type: WireType::LengthDelimited,
            },
            buffer,
        );
        wire::encode_length_delimited(key.as_bytes(), buffer);

        wire::encode_tag(
            Tag {
                field_number: PROPERTY_SET_FIELD_VALUES,
                wire_type: WireType::LengthDelimited,
            },
            buffer,
        );
        let mut property_bytes = Vec::new();
        encode_property(property, &mut property_bytes);
        wire::encode_length_delimited(&property_bytes, buffer);
    }
}

/// Decodes a `PropertySet` message, collecting `keys` and `values` separately
/// (in wire order) before pairing them up by position — protobuf's repeated
/// fields don't require two different field numbers to interleave on the
/// wire, only that each field's own occurrences preserve their relative
/// order, so `keys[i]`/`values[i]` can't simply be read off field-by-field
/// as the bytes are walked.
pub fn decode_property_set(bytes: &[u8]) -> Result<PropertySet, DecodeError> {
    let mut keys = Vec::new();
    let mut values = Vec::new();

    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_len) = wire::decode_tag(&bytes[offset..])?;
        offset += tag_len;

        match tag.field_number {
            PROPERTY_SET_FIELD_KEYS => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                keys.push(String::from_utf8_lossy(field_bytes).into_owned());
                offset += consumed;
            }
            PROPERTY_SET_FIELD_VALUES => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                values.push(decode_property(field_bytes)?);
                offset += consumed;
            }
            _ => {
                offset += wire::skip_field(tag.wire_type, &bytes[offset..])?;
            }
        }
    }

    if keys.len() != values.len() {
        return Err(DecodeError::MismatchedKeyValueCounts {
            keys: keys.len(),
            values: values.len(),
        });
    }

    Ok(PropertySet {
        entries: keys.into_iter().zip(values).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_property(property: Property) {
        let mut buffer = Vec::new();
        encode_property(&property, &mut buffer);
        assert_eq!(decode_property(&buffer), Ok(property));
    }

    fn round_trip_property_set(property_set: PropertySet) {
        let mut buffer = Vec::new();
        encode_property_set(&property_set, &mut buffer);
        assert_eq!(decode_property_set(&buffer), Ok(property_set));
    }

    #[test]
    fn property_data_type_round_trips_through_its_code() {
        let all = [
            PropertyDataType::Unknown,
            PropertyDataType::Int32,
            PropertyDataType::Int64,
            PropertyDataType::UInt32,
            PropertyDataType::UInt64,
            PropertyDataType::Float,
            PropertyDataType::Double,
            PropertyDataType::Boolean,
            PropertyDataType::String,
            PropertyDataType::DateTime,
            PropertyDataType::Text,
            PropertyDataType::Uuid,
            PropertyDataType::DataSet,
            PropertyDataType::Bytes,
            PropertyDataType::File,
            PropertyDataType::PropertySet,
            PropertyDataType::PropertySetList,
        ];
        for data_type in all {
            let code = u32::from(data_type);
            assert_eq!(PropertyDataType::try_from(code), Ok(data_type));
        }
    }

    #[test]
    fn property_data_type_codes_differ_from_metric_data_type_codes() {
        // The spec's own point of confusion this doc comment warns about:
        // Int32 is code 1 here, but code 3 in `data_type::DataType`.
        assert_eq!(u32::from(PropertyDataType::Int32), 1);
        assert_eq!(u32::from(crate::data_type::DataType::Int32), 3);
    }

    #[test]
    fn rejects_unknown_property_data_type_code() {
        assert_eq!(
            PropertyDataType::try_from(17),
            Err(UnknownPropertyDataTypeCode { code: 17 })
        );
    }

    #[test]
    fn round_trips_int_property() {
        round_trip_property(Property {
            data_type: PropertyDataType::Int32,
            value: PropertyValue::Int(42),
        });
    }

    #[test]
    fn round_trips_string_property() {
        round_trip_property(Property {
            data_type: PropertyDataType::String,
            value: PropertyValue::String("CEL".to_string()),
        });
    }

    #[test]
    fn round_trips_boolean_property() {
        round_trip_property(Property {
            data_type: PropertyDataType::Boolean,
            value: PropertyValue::Boolean(true),
        });
    }

    #[test]
    fn round_trips_bytes_property() {
        round_trip_property(Property {
            data_type: PropertyDataType::Bytes,
            value: PropertyValue::Bytes(vec![0x0D, 0xFE]),
        });
    }

    #[test]
    fn round_trips_float_and_double_properties() {
        round_trip_property(Property {
            data_type: PropertyDataType::Float,
            value: PropertyValue::Float(1.5),
        });
        round_trip_property(Property {
            data_type: PropertyDataType::Double,
            value: PropertyValue::Double(2.5),
        });
    }

    #[test]
    fn round_trips_long_property() {
        round_trip_property(Property {
            data_type: PropertyDataType::UInt64,
            value: PropertyValue::Long(7),
        });
    }

    #[test]
    fn decode_property_rejects_missing_data_type() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: PROPERTY_FIELD_BOOLEAN_VALUE,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(1, &mut buffer);
        assert_eq!(decode_property(&buffer), Err(DecodeError::MissingDataType));
    }

    #[test]
    fn decode_property_rejects_missing_value() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: PROPERTY_FIELD_TYPE,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(u64::from(u32::from(PropertyDataType::Boolean)), &mut buffer);
        assert_eq!(decode_property(&buffer), Err(DecodeError::MissingValue));
    }

    #[test]
    fn decode_property_rejects_unknown_data_type_code() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: PROPERTY_FIELD_TYPE,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(9999, &mut buffer);
        assert_eq!(
            decode_property(&buffer),
            Err(DecodeError::UnknownDataTypeCode(9999))
        );
    }

    #[test]
    fn decode_property_skips_unknown_field_and_still_parses_known_ones() {
        let mut buffer = Vec::new();
        // An unmodeled field: is_null (field 2), varint wire type.
        wire::encode_tag(
            Tag {
                field_number: 2,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(1, &mut buffer);

        let property = Property {
            data_type: PropertyDataType::Boolean,
            value: PropertyValue::Boolean(true),
        };
        encode_property(&property, &mut buffer);

        assert_eq!(decode_property(&buffer), Ok(property));
    }

    #[test]
    fn decode_property_propagates_wire_errors() {
        assert_eq!(
            decode_property(&[0xFF]),
            Err(DecodeError::Wire(wire::DecodeError::TooShort))
        );
    }

    #[test]
    fn round_trips_empty_property_set() {
        round_trip_property_set(PropertySet {
            entries: Vec::new(),
        });
    }

    #[test]
    fn round_trips_a_single_entry_property_set() {
        round_trip_property_set(PropertySet {
            entries: vec![(
                "unit".to_string(),
                Property {
                    data_type: PropertyDataType::String,
                    value: PropertyValue::String("CEL".to_string()),
                },
            )],
        });
    }

    #[test]
    fn round_trips_multiple_entries_preserving_order() {
        round_trip_property_set(PropertySet {
            entries: vec![
                (
                    "unit".to_string(),
                    Property {
                        data_type: PropertyDataType::String,
                        value: PropertyValue::String("CEL".to_string()),
                    },
                ),
                (
                    "precision".to_string(),
                    Property {
                        data_type: PropertyDataType::Int32,
                        value: PropertyValue::Int(2),
                    },
                ),
                (
                    "writable".to_string(),
                    Property {
                        data_type: PropertyDataType::Boolean,
                        value: PropertyValue::Boolean(true),
                    },
                ),
            ],
        });
    }

    #[test]
    fn decode_property_set_rejects_mismatched_key_and_value_counts() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: PROPERTY_SET_FIELD_KEYS,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        wire::encode_length_delimited(b"unit", &mut buffer);
        // No matching `values` entry at all.

        assert_eq!(
            decode_property_set(&buffer),
            Err(DecodeError::MismatchedKeyValueCounts { keys: 1, values: 0 })
        );
    }

    #[test]
    fn decode_property_set_propagates_property_decode_errors() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: PROPERTY_SET_FIELD_KEYS,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        wire::encode_length_delimited(b"unit", &mut buffer);
        wire::encode_tag(
            Tag {
                field_number: PROPERTY_SET_FIELD_VALUES,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        // An empty embedded Property message: missing every field.
        wire::encode_length_delimited(&[], &mut buffer);

        assert_eq!(
            decode_property_set(&buffer),
            Err(DecodeError::MissingDataType)
        );
    }

    #[test]
    fn decode_property_set_propagates_wire_errors() {
        assert_eq!(
            decode_property_set(&[0xFF]),
            Err(DecodeError::Wire(wire::DecodeError::TooShort))
        );
    }
}
