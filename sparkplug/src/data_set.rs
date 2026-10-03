//! Encode/decode for Sparkplug B's `DataSet` message (a table: named/typed
//! columns, then rows of scalar values) — a general capability per
//! CLAUDE.md's Thread B3, not yet wired into `Metric.value` (that's field 17
//! of the `value` oneof, modeled by `metric_value::MetricValue` — adding the
//! variant there is a separate step).
//!
//! `DataSet.types` (field 3, per-column data type) reuses `data_type::
//! DataType` directly — unlike `property::PropertyDataType`, the spec's
//! `DataSet` message shares the *same* `DataType` enum/numbering `Metric`
//! itself uses, there's no separate "DataSet data type" enum to get wrong
//! here.
//!
//! `num_of_columns` (field 1, redundant with `columns.len()`) is deliberately
//! not modeled, same "don't carry a length field that's always derivable"
//! convention this project already applies to `WriteMultipleRegistersRequest`
//! /`WriteFileRecordSubRequest` — `encode_data_set` doesn't emit it at all.
//! Revisit if a real conformance test (TCK or otherwise) ever shows a peer
//! that requires it.

use crate::data_type::DataType;
use crate::wire::{self, Tag, WireType};

const ROW_FIELD_ELEMENTS: u32 = 1;

const DATA_SET_FIELD_COLUMNS: u32 = 2;
const DATA_SET_FIELD_TYPES: u32 = 3;
const DATA_SET_FIELD_ROWS: u32 = 4;

const VALUE_FIELD_INT: u32 = 1;
const VALUE_FIELD_LONG: u32 = 2;
const VALUE_FIELD_FLOAT: u32 = 3;
const VALUE_FIELD_DOUBLE: u32 = 4;
const VALUE_FIELD_BOOLEAN: u32 = 5;
const VALUE_FIELD_STRING: u32 = 6;
const VALUE_FIELD_BYTES: u32 = 7;

/// The scalar shape of one `DataSetValue` — structurally identical to
/// `MetricValue`/`property::PropertyValue`, but modeled as its own type
/// rather than reused, same "each spec message gets its own value type even
/// when the shape overlaps" precedent `PropertyValue` already established
/// relative to `MetricValue`.
#[derive(Debug, Clone, PartialEq)]
pub enum DataSetValue {
    Int(u32),
    Long(u64),
    Float(f32),
    Double(f64),
    Boolean(bool),
    String(String),
    Bytes(Vec<u8>),
}

/// One row: exactly `DataSet.columns.len()` values, column `i`'s value
/// matching `DataSet.types[i]` — neither invariant is enforced by `Row`
/// itself, only by `decode_data_set` once it has the whole table to check.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub elements: Vec<DataSetValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DataSet {
    pub columns: Vec<String>,
    pub types: Vec<DataType>,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Wire(wire::DecodeError),
    MissingValue,
    UnknownDataTypeCode(u32),
    /// `columns` and `types` are two independently-repeated wire fields the
    /// spec requires to be the same length (column `i`'s declared type is
    /// `types[i]`) — mirrors `property::DecodeError::MismatchedKeyValueCounts`.
    MismatchedColumnsAndTypes {
        columns: usize,
        types: usize,
    },
    /// A row didn't carry exactly `columns.len()` values.
    RowLengthMismatch {
        row_index: usize,
        expected: usize,
        actual: usize,
    },
}

impl From<wire::DecodeError> for DecodeError {
    fn from(error: wire::DecodeError) -> Self {
        DecodeError::Wire(error)
    }
}

pub fn encode_data_set_value(value: &DataSetValue, buffer: &mut Vec<u8>) {
    match value {
        DataSetValue::Int(value) => {
            wire::encode_tag(
                Tag {
                    field_number: VALUE_FIELD_INT,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(u64::from(*value), buffer);
        }
        DataSetValue::Long(value) => {
            wire::encode_tag(
                Tag {
                    field_number: VALUE_FIELD_LONG,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(*value, buffer);
        }
        DataSetValue::Float(value) => {
            wire::encode_tag(
                Tag {
                    field_number: VALUE_FIELD_FLOAT,
                    wire_type: WireType::Fixed32,
                },
                buffer,
            );
            wire::encode_fixed32(value.to_bits(), buffer);
        }
        DataSetValue::Double(value) => {
            wire::encode_tag(
                Tag {
                    field_number: VALUE_FIELD_DOUBLE,
                    wire_type: WireType::Fixed64,
                },
                buffer,
            );
            wire::encode_fixed64(value.to_bits(), buffer);
        }
        DataSetValue::Boolean(value) => {
            wire::encode_tag(
                Tag {
                    field_number: VALUE_FIELD_BOOLEAN,
                    wire_type: WireType::Varint,
                },
                buffer,
            );
            wire::encode_varint(u64::from(*value), buffer);
        }
        DataSetValue::String(value) => {
            wire::encode_tag(
                Tag {
                    field_number: VALUE_FIELD_STRING,
                    wire_type: WireType::LengthDelimited,
                },
                buffer,
            );
            wire::encode_length_delimited(value.as_bytes(), buffer);
        }
        DataSetValue::Bytes(value) => {
            wire::encode_tag(
                Tag {
                    field_number: VALUE_FIELD_BYTES,
                    wire_type: WireType::LengthDelimited,
                },
                buffer,
            );
            wire::encode_length_delimited(value, buffer);
        }
    }
}

pub fn decode_data_set_value(bytes: &[u8]) -> Result<DataSetValue, DecodeError> {
    let mut value: Option<DataSetValue> = None;

    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_len) = wire::decode_tag(&bytes[offset..])?;
        offset += tag_len;

        match tag.field_number {
            VALUE_FIELD_INT => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(DataSetValue::Int(raw as u32));
                offset += consumed;
            }
            VALUE_FIELD_LONG => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(DataSetValue::Long(raw));
                offset += consumed;
            }
            VALUE_FIELD_FLOAT => {
                let (raw, consumed) = wire::decode_fixed32(&bytes[offset..])?;
                value = Some(DataSetValue::Float(f32::from_bits(raw)));
                offset += consumed;
            }
            VALUE_FIELD_DOUBLE => {
                let (raw, consumed) = wire::decode_fixed64(&bytes[offset..])?;
                value = Some(DataSetValue::Double(f64::from_bits(raw)));
                offset += consumed;
            }
            VALUE_FIELD_BOOLEAN => {
                let (raw, consumed) = wire::decode_varint(&bytes[offset..])?;
                value = Some(DataSetValue::Boolean(raw != 0));
                offset += consumed;
            }
            VALUE_FIELD_STRING => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                value = Some(DataSetValue::String(
                    String::from_utf8_lossy(field_bytes).into_owned(),
                ));
                offset += consumed;
            }
            VALUE_FIELD_BYTES => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                value = Some(DataSetValue::Bytes(field_bytes.to_vec()));
                offset += consumed;
            }
            _ => {
                offset += wire::skip_field(tag.wire_type, &bytes[offset..])?;
            }
        }
    }

    value.ok_or(DecodeError::MissingValue)
}

pub fn encode_row(row: &Row, buffer: &mut Vec<u8>) {
    for element in &row.elements {
        wire::encode_tag(
            Tag {
                field_number: ROW_FIELD_ELEMENTS,
                wire_type: WireType::LengthDelimited,
            },
            buffer,
        );
        let mut element_bytes = Vec::new();
        encode_data_set_value(element, &mut element_bytes);
        wire::encode_length_delimited(&element_bytes, buffer);
    }
}

pub fn decode_row(bytes: &[u8]) -> Result<Row, DecodeError> {
    let mut elements = Vec::new();

    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_len) = wire::decode_tag(&bytes[offset..])?;
        offset += tag_len;

        match tag.field_number {
            ROW_FIELD_ELEMENTS => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                elements.push(decode_data_set_value(field_bytes)?);
                offset += consumed;
            }
            _ => {
                offset += wire::skip_field(tag.wire_type, &bytes[offset..])?;
            }
        }
    }

    Ok(Row { elements })
}

pub fn encode_data_set(data_set: &DataSet, buffer: &mut Vec<u8>) {
    for column in &data_set.columns {
        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_COLUMNS,
                wire_type: WireType::LengthDelimited,
            },
            buffer,
        );
        wire::encode_length_delimited(column.as_bytes(), buffer);
    }

    for data_type in &data_set.types {
        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_TYPES,
                wire_type: WireType::Varint,
            },
            buffer,
        );
        wire::encode_varint(u64::from(u32::from(*data_type)), buffer);
    }

    for row in &data_set.rows {
        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_ROWS,
                wire_type: WireType::LengthDelimited,
            },
            buffer,
        );
        let mut row_bytes = Vec::new();
        encode_row(row, &mut row_bytes);
        wire::encode_length_delimited(&row_bytes, buffer);
    }
}

/// Decodes a `DataSet` message, collecting `columns`/`types`/`rows`
/// separately (in wire order) before validating them against each other —
/// same reasoning as `property::decode_property_set`: protobuf's repeated
/// fields don't require different field numbers to interleave on the wire,
/// only that each field's own occurrences preserve their relative order.
pub fn decode_data_set(bytes: &[u8]) -> Result<DataSet, DecodeError> {
    let mut columns = Vec::new();
    let mut types = Vec::new();
    let mut rows = Vec::new();

    let mut offset = 0;
    while offset < bytes.len() {
        let (tag, tag_len) = wire::decode_tag(&bytes[offset..])?;
        offset += tag_len;

        match tag.field_number {
            DATA_SET_FIELD_COLUMNS => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                columns.push(String::from_utf8_lossy(field_bytes).into_owned());
                offset += consumed;
            }
            DATA_SET_FIELD_TYPES => {
                let (code, consumed) = wire::decode_varint(&bytes[offset..])?;
                let code = code as u32;
                types.push(
                    DataType::try_from(code).map_err(|_| DecodeError::UnknownDataTypeCode(code))?,
                );
                offset += consumed;
            }
            DATA_SET_FIELD_ROWS => {
                let (field_bytes, consumed) = wire::decode_length_delimited(&bytes[offset..])?;
                rows.push(decode_row(field_bytes)?);
                offset += consumed;
            }
            _ => {
                offset += wire::skip_field(tag.wire_type, &bytes[offset..])?;
            }
        }
    }

    if columns.len() != types.len() {
        return Err(DecodeError::MismatchedColumnsAndTypes {
            columns: columns.len(),
            types: types.len(),
        });
    }

    for (row_index, row) in rows.iter().enumerate() {
        if row.elements.len() != columns.len() {
            return Err(DecodeError::RowLengthMismatch {
                row_index,
                expected: columns.len(),
                actual: row.elements.len(),
            });
        }
    }

    Ok(DataSet {
        columns,
        types,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data_set: DataSet) {
        let mut buffer = Vec::new();
        encode_data_set(&data_set, &mut buffer);
        assert_eq!(decode_data_set(&buffer), Ok(data_set));
    }

    #[test]
    fn round_trips_an_empty_data_set() {
        round_trip(DataSet {
            columns: Vec::new(),
            types: Vec::new(),
            rows: Vec::new(),
        });
    }

    #[test]
    fn round_trips_columns_with_no_rows() {
        round_trip(DataSet {
            columns: vec!["Name".to_string(), "UnitId".to_string()],
            types: vec![DataType::String, DataType::UInt8],
            rows: Vec::new(),
        });
    }

    #[test]
    fn round_trips_a_table_with_multiple_rows_preserving_order() {
        round_trip(DataSet {
            columns: vec!["Name".to_string(), "UnitId".to_string()],
            types: vec![DataType::String, DataType::UInt8],
            rows: vec![
                Row {
                    elements: vec![
                        DataSetValue::String("PumpA".to_string()),
                        DataSetValue::Int(1),
                    ],
                },
                Row {
                    elements: vec![
                        DataSetValue::String("PumpB".to_string()),
                        DataSetValue::Int(2),
                    ],
                },
            ],
        });
    }

    #[test]
    fn round_trips_every_scalar_value_kind() {
        round_trip(DataSet {
            columns: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
                "e".to_string(),
                "f".to_string(),
                "g".to_string(),
            ],
            types: vec![
                DataType::UInt32,
                DataType::UInt64,
                DataType::Float,
                DataType::Double,
                DataType::Boolean,
                DataType::String,
                DataType::Bytes,
            ],
            rows: vec![Row {
                elements: vec![
                    DataSetValue::Int(42),
                    DataSetValue::Long(7),
                    DataSetValue::Float(1.5),
                    DataSetValue::Double(2.5),
                    DataSetValue::Boolean(true),
                    DataSetValue::String("x".to_string()),
                    DataSetValue::Bytes(vec![0x0D, 0xFE]),
                ],
            }],
        });
    }

    #[test]
    fn decode_rejects_mismatched_columns_and_types_counts() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_COLUMNS,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        wire::encode_length_delimited(b"Name", &mut buffer);
        // No matching `types` entry at all.

        assert_eq!(
            decode_data_set(&buffer),
            Err(DecodeError::MismatchedColumnsAndTypes {
                columns: 1,
                types: 0
            })
        );
    }

    #[test]
    fn decode_rejects_a_row_with_the_wrong_number_of_elements() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_COLUMNS,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        wire::encode_length_delimited(b"Name", &mut buffer);
        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_TYPES,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(u64::from(u32::from(DataType::String)), &mut buffer);

        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_ROWS,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        // An empty row: zero elements, but one column was declared.
        wire::encode_length_delimited(&[], &mut buffer);

        assert_eq!(
            decode_data_set(&buffer),
            Err(DecodeError::RowLengthMismatch {
                row_index: 0,
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_rejects_unknown_data_type_code_in_types() {
        let mut buffer = Vec::new();
        wire::encode_tag(
            Tag {
                field_number: DATA_SET_FIELD_TYPES,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(9999, &mut buffer);
        assert_eq!(
            decode_data_set(&buffer),
            Err(DecodeError::UnknownDataTypeCode(9999))
        );
    }

    #[test]
    fn decode_data_set_value_rejects_missing_value() {
        assert_eq!(decode_data_set_value(&[]), Err(DecodeError::MissingValue));
    }

    #[test]
    fn decode_data_set_propagates_wire_errors() {
        assert_eq!(
            decode_data_set(&[0xFF]),
            Err(DecodeError::Wire(wire::DecodeError::TooShort))
        );
    }

    #[test]
    fn decode_row_skips_unknown_field_and_still_parses_known_elements() {
        let mut buffer = Vec::new();
        // An unmodeled field number for Row.
        wire::encode_tag(
            Tag {
                field_number: 50,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        wire::encode_varint(999, &mut buffer);

        let row = Row {
            elements: vec![DataSetValue::Boolean(true)],
        };
        encode_row(&row, &mut buffer);

        assert_eq!(decode_row(&buffer), Ok(row));
    }
}
