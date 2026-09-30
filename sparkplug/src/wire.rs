//! Protobuf wire-format primitives (varint, tag, length-delimited, fixed32/64) —
//! only what the fixed Sparkplug B message set needs, not general-purpose protobuf.

/// A varint is at most 10 bytes: 64 bits / 7 payload bits per byte, rounded up.
const MAX_VARINT_BYTES: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    VarintOverflow,
    UnsupportedWireType { wire_type: u64 },
    FieldNumberOverflow,
    InvalidFieldNumber,
    LengthOverflow,
}

/// The four protobuf wire types this crate supports. `StartGroup`/`EndGroup`
/// (bits 3/4) are deprecated and unused by Sparkplug B's own schema, so they're
/// not modeled at all — a message using them is rejected, not silently skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Varint,
    Fixed64,
    LengthDelimited,
    Fixed32,
}

impl From<WireType> for u64 {
    fn from(wire_type: WireType) -> Self {
        match wire_type {
            WireType::Varint => 0,
            WireType::Fixed64 => 1,
            WireType::LengthDelimited => 2,
            WireType::Fixed32 => 5,
        }
    }
}

impl TryFrom<u64> for WireType {
    type Error = DecodeError;

    fn try_from(bits: u64) -> Result<Self, DecodeError> {
        match bits {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::Fixed64),
            2 => Ok(WireType::LengthDelimited),
            5 => Ok(WireType::Fixed32),
            _ => Err(DecodeError::UnsupportedWireType { wire_type: bits }),
        }
    }
}

/// A decoded protobuf field tag: which field, and how its value is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub field_number: u32,
    pub wire_type: WireType,
}

/// Encodes a field tag as `(field_number << 3) | wire_type`, appending to `buffer`.
pub fn encode_tag(tag: Tag, buffer: &mut Vec<u8>) {
    let encoded = ((tag.field_number as u64) << 3) | u64::from(tag.wire_type);
    encode_varint(encoded, buffer);
}

/// Decodes a field tag from the start of `bytes`, returning it and how many
/// bytes it consumed. Rejects field number 0 (invalid per the protobuf spec)
/// and any wire type this crate doesn't support.
pub fn decode_tag(bytes: &[u8]) -> Result<(Tag, usize), DecodeError> {
    let (value, consumed) = decode_varint(bytes)?;
    let wire_type = WireType::try_from(value & 0x7)?;
    let field_number = u32::try_from(value >> 3).map_err(|_| DecodeError::FieldNumberOverflow)?;
    if field_number == 0 {
        return Err(DecodeError::InvalidFieldNumber);
    }
    Ok((
        Tag {
            field_number,
            wire_type,
        },
        consumed,
    ))
}

/// Encodes `value` as a length-delimited field: a varint byte count followed by
/// the raw bytes, appending to `buffer`. Used for strings, byte fields, and
/// embedded messages.
pub fn encode_length_delimited(value: &[u8], buffer: &mut Vec<u8>) {
    encode_varint(value.len() as u64, buffer);
    buffer.extend_from_slice(value);
}

/// Decodes a length-delimited field from the start of `bytes`, returning a
/// borrowed slice of exactly the declared length and how many bytes were
/// consumed in total (length prefix + value). Never allocates: an oversized
/// declared length is rejected before any bytes are copied anywhere.
pub fn decode_length_delimited(bytes: &[u8]) -> Result<(&[u8], usize), DecodeError> {
    let (length, length_consumed) = decode_varint(bytes)?;
    let length = usize::try_from(length).map_err(|_| DecodeError::LengthOverflow)?;
    let remaining = &bytes[length_consumed..];
    if remaining.len() < length {
        return Err(DecodeError::TooShort);
    }
    Ok((&remaining[..length], length_consumed + length))
}

/// Encodes `value` as 4 little-endian bytes, appending to `buffer`. Used for
/// the protobuf `fixed32`/`sfixed32`/`float` wire representation.
pub fn encode_fixed32(value: u32, buffer: &mut Vec<u8>) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// Decodes 4 little-endian bytes from the start of `bytes`, returning the
/// value and that it consumed exactly 4 bytes.
pub fn decode_fixed32(bytes: &[u8]) -> Result<(u32, usize), DecodeError> {
    let Some(field_bytes) = bytes.get(..4) else {
        return Err(DecodeError::TooShort);
    };
    let value = u32::from_le_bytes(field_bytes.try_into().unwrap());
    Ok((value, 4))
}

/// Encodes `value` as 8 little-endian bytes, appending to `buffer`. Used for
/// the protobuf `fixed64`/`sfixed64`/`double` wire representation.
pub fn encode_fixed64(value: u64, buffer: &mut Vec<u8>) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// Decodes 8 little-endian bytes from the start of `bytes`, returning the
/// value and that it consumed exactly 8 bytes.
pub fn decode_fixed64(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    let Some(field_bytes) = bytes.get(..8) else {
        return Err(DecodeError::TooShort);
    };
    let value = u64::from_le_bytes(field_bytes.try_into().unwrap());
    Ok((value, 8))
}

/// Consumes and discards one field's value of the given wire type from the
/// start of `bytes`, returning how many bytes it occupied. Used by message
/// decoders (`metric`, `payload`) to skip over fields they don't model,
/// rather than rejecting a message just because it carries a field this
/// crate hasn't implemented yet.
pub fn skip_field(wire_type: WireType, bytes: &[u8]) -> Result<usize, DecodeError> {
    match wire_type {
        WireType::Varint => decode_varint(bytes).map(|(_, consumed)| consumed),
        WireType::Fixed32 => decode_fixed32(bytes).map(|(_, consumed)| consumed),
        WireType::Fixed64 => decode_fixed64(bytes).map(|(_, consumed)| consumed),
        WireType::LengthDelimited => decode_length_delimited(bytes).map(|(_, consumed)| consumed),
    }
}

/// Encodes `value` as an unsigned LEB128 varint, appending to `buffer`.
pub fn encode_varint(mut value: u64, buffer: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buffer.push(byte);
            break;
        }
        buffer.push(byte | 0x80);
    }
}

/// Decodes an unsigned LEB128 varint from the start of `bytes`, returning the
/// value and how many bytes it consumed.
pub fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    let mut value: u64 = 0;
    for (index, &byte) in bytes.iter().take(MAX_VARINT_BYTES).enumerate() {
        let payload = (byte & 0x7F) as u64;
        if index == MAX_VARINT_BYTES - 1 && payload > 1 {
            return Err(DecodeError::VarintOverflow);
        }
        value |= payload << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    if bytes.len() >= MAX_VARINT_BYTES {
        return Err(DecodeError::VarintOverflow);
    }
    Err(DecodeError::TooShort)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: u64) {
        let mut buffer = Vec::new();
        encode_varint(value, &mut buffer);
        assert_eq!(decode_varint(&buffer), Ok((value, buffer.len())));
    }

    #[test]
    fn round_trips_zero() {
        round_trip(0);
    }

    #[test]
    fn round_trips_one_byte_boundary() {
        round_trip(127);
    }

    #[test]
    fn round_trips_two_byte_boundary() {
        round_trip(128);
    }

    #[test]
    fn round_trips_u32_max() {
        round_trip(u32::MAX as u64);
    }

    #[test]
    fn round_trips_u64_max() {
        round_trip(u64::MAX);
    }

    #[test]
    fn encodes_zero_as_single_zero_byte() {
        let mut buffer = Vec::new();
        encode_varint(0, &mut buffer);
        assert_eq!(buffer, vec![0x00]);
    }

    #[test]
    fn encodes_127_as_single_byte() {
        let mut buffer = Vec::new();
        encode_varint(127, &mut buffer);
        assert_eq!(buffer, vec![0x7F]);
    }

    #[test]
    fn encodes_128_as_two_bytes() {
        let mut buffer = Vec::new();
        encode_varint(128, &mut buffer);
        assert_eq!(buffer, vec![0x80, 0x01]);
    }

    #[test]
    fn decode_consumes_only_the_varint_not_trailing_bytes() {
        let mut buffer = vec![];
        encode_varint(1, &mut buffer);
        buffer.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(decode_varint(&buffer), Ok((1, 1)));
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert_eq!(decode_varint(&[]), Err(DecodeError::TooShort));
    }

    #[test]
    fn decode_rejects_truncated_input_missing_terminator() {
        // continuation bit set on every byte, buffer just ends
        assert_eq!(
            decode_varint(&[0x80, 0x80, 0x80]),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn decode_rejects_more_than_ten_bytes() {
        let bytes = [0x80u8; 11];
        assert_eq!(decode_varint(&bytes), Err(DecodeError::VarintOverflow));
    }

    #[test]
    fn decode_rejects_tenth_byte_overflowing_64_bits() {
        // 9 continuation bytes of 0xFF, 10th byte contributes 2 bits (> the 1 allowed)
        let mut bytes = vec![0xFFu8; 9];
        bytes.push(0x02);
        assert_eq!(decode_varint(&bytes), Err(DecodeError::VarintOverflow));
    }

    #[test]
    fn decode_accepts_maximal_ten_byte_varint() {
        // u64::MAX encodes to 9 bytes of 0xFF followed by 0x01
        let mut bytes = vec![0xFFu8; 9];
        bytes.push(0x01);
        assert_eq!(decode_varint(&bytes), Ok((u64::MAX, 10)));
    }

    fn tag_round_trip(tag: Tag) {
        let mut buffer = Vec::new();
        encode_tag(tag, &mut buffer);
        assert_eq!(decode_tag(&buffer), Ok((tag, buffer.len())));
    }

    #[test]
    fn tag_round_trips_field_one_varint() {
        tag_round_trip(Tag {
            field_number: 1,
            wire_type: WireType::Varint,
        });
    }

    #[test]
    fn tag_round_trips_field_two_fixed64() {
        tag_round_trip(Tag {
            field_number: 2,
            wire_type: WireType::Fixed64,
        });
    }

    #[test]
    fn tag_round_trips_length_delimited_at_one_byte_tag_boundary() {
        // field 15 << 3 | 2 = 122, still fits in a single tag byte (max 127)
        tag_round_trip(Tag {
            field_number: 15,
            wire_type: WireType::LengthDelimited,
        });
    }

    #[test]
    fn tag_round_trips_field_number_needing_two_tag_bytes() {
        // field 16 << 3 = 128, tips the tag itself over the one-byte varint boundary
        tag_round_trip(Tag {
            field_number: 16,
            wire_type: WireType::Fixed32,
        });
    }

    #[test]
    fn tag_round_trips_large_field_number() {
        tag_round_trip(Tag {
            field_number: 268_435_455, // 2^28 - 1
            wire_type: WireType::Varint,
        });
    }

    #[test]
    fn encode_tag_matches_known_bytes() {
        let mut buffer = Vec::new();
        encode_tag(
            Tag {
                field_number: 1,
                wire_type: WireType::Varint,
            },
            &mut buffer,
        );
        assert_eq!(buffer, vec![0x08]);

        let mut buffer = Vec::new();
        encode_tag(
            Tag {
                field_number: 2,
                wire_type: WireType::LengthDelimited,
            },
            &mut buffer,
        );
        assert_eq!(buffer, vec![0x12]);
    }

    #[test]
    fn decode_tag_rejects_start_group_wire_type() {
        // field 1, wire type 3 (deprecated StartGroup)
        assert_eq!(
            decode_tag(&[0x0B]),
            Err(DecodeError::UnsupportedWireType { wire_type: 3 })
        );
    }

    #[test]
    fn decode_tag_rejects_end_group_wire_type() {
        // field 1, wire type 4 (deprecated EndGroup)
        assert_eq!(
            decode_tag(&[0x0C]),
            Err(DecodeError::UnsupportedWireType { wire_type: 4 })
        );
    }

    #[test]
    fn decode_tag_rejects_unknown_wire_type() {
        // field 1, wire type 6 (never defined by protobuf)
        assert_eq!(
            decode_tag(&[0x0E]),
            Err(DecodeError::UnsupportedWireType { wire_type: 6 })
        );
    }

    #[test]
    fn decode_tag_rejects_field_number_zero() {
        // field 0, wire type 2 (length-delimited)
        assert_eq!(decode_tag(&[0x02]), Err(DecodeError::InvalidFieldNumber));
    }

    #[test]
    fn decode_tag_propagates_underlying_varint_error() {
        assert_eq!(decode_tag(&[]), Err(DecodeError::TooShort));
    }

    #[test]
    fn decode_tag_does_not_consume_trailing_bytes() {
        let mut buffer = Vec::new();
        encode_tag(
            Tag {
                field_number: 3,
                wire_type: WireType::Fixed32,
            },
            &mut buffer,
        );
        let consumed_len = buffer.len();
        buffer.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(
            decode_tag(&buffer),
            Ok((
                Tag {
                    field_number: 3,
                    wire_type: WireType::Fixed32
                },
                consumed_len
            ))
        );
    }

    fn length_delimited_round_trip(value: &[u8]) {
        let mut buffer = Vec::new();
        encode_length_delimited(value, &mut buffer);
        assert_eq!(decode_length_delimited(&buffer), Ok((value, buffer.len())));
    }

    #[test]
    fn length_delimited_round_trips_empty_value() {
        length_delimited_round_trip(&[]);
    }

    #[test]
    fn length_delimited_round_trips_short_value() {
        length_delimited_round_trip(b"hello");
    }

    #[test]
    fn length_delimited_round_trips_value_needing_two_byte_length_prefix() {
        length_delimited_round_trip(&[0xAB; 200]);
    }

    #[test]
    fn encode_length_delimited_matches_known_bytes() {
        let mut buffer = Vec::new();
        encode_length_delimited(b"hi", &mut buffer);
        assert_eq!(buffer, vec![0x02, b'h', b'i']);
    }

    #[test]
    fn decode_length_delimited_does_not_consume_trailing_bytes() {
        let mut buffer = Vec::new();
        encode_length_delimited(b"hi", &mut buffer);
        let consumed_len = buffer.len();
        buffer.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(
            decode_length_delimited(&buffer),
            Ok((b"hi".as_slice(), consumed_len))
        );
    }

    #[test]
    fn decode_length_delimited_rejects_declared_length_exceeding_available_bytes() {
        let mut buffer = Vec::new();
        encode_varint(10, &mut buffer); // claims 10 bytes follow
        buffer.extend_from_slice(b"abc"); // only 3 actually do
        assert_eq!(decode_length_delimited(&buffer), Err(DecodeError::TooShort));
    }

    #[test]
    fn decode_length_delimited_propagates_underlying_varint_error() {
        assert_eq!(decode_length_delimited(&[]), Err(DecodeError::TooShort));
    }

    #[test]
    fn decode_length_delimited_does_not_allocate_or_panic_on_huge_declared_length() {
        // length prefix claims u32::MAX bytes follow, buffer has almost none —
        // must be rejected via a length check, not by trying to slice/allocate it
        let mut buffer = Vec::new();
        encode_varint(u32::MAX as u64, &mut buffer);
        buffer.extend_from_slice(b"x");
        assert_eq!(decode_length_delimited(&buffer), Err(DecodeError::TooShort));
    }

    fn fixed32_round_trip(value: u32) {
        let mut buffer = Vec::new();
        encode_fixed32(value, &mut buffer);
        assert_eq!(decode_fixed32(&buffer), Ok((value, buffer.len())));
    }

    #[test]
    fn fixed32_round_trips_zero() {
        fixed32_round_trip(0);
    }

    #[test]
    fn fixed32_round_trips_max() {
        fixed32_round_trip(u32::MAX);
    }

    #[test]
    fn fixed32_round_trips_arbitrary_value() {
        fixed32_round_trip(0x01020304);
    }

    #[test]
    fn encode_fixed32_uses_little_endian_byte_order() {
        let mut buffer = Vec::new();
        encode_fixed32(0x01020304, &mut buffer);
        assert_eq!(buffer, vec![0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn fixed32_always_consumes_exactly_four_bytes() {
        let mut buffer = Vec::new();
        encode_fixed32(7, &mut buffer);
        buffer.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(decode_fixed32(&buffer), Ok((7, 4)));
    }

    #[test]
    fn decode_fixed32_rejects_too_short_input() {
        assert_eq!(
            decode_fixed32(&[0x01, 0x02, 0x03]),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn decode_fixed32_rejects_empty_input() {
        assert_eq!(decode_fixed32(&[]), Err(DecodeError::TooShort));
    }

    fn fixed64_round_trip(value: u64) {
        let mut buffer = Vec::new();
        encode_fixed64(value, &mut buffer);
        assert_eq!(decode_fixed64(&buffer), Ok((value, buffer.len())));
    }

    #[test]
    fn fixed64_round_trips_zero() {
        fixed64_round_trip(0);
    }

    #[test]
    fn fixed64_round_trips_max() {
        fixed64_round_trip(u64::MAX);
    }

    #[test]
    fn fixed64_round_trips_arbitrary_value() {
        fixed64_round_trip(0x0102030405060708);
    }

    #[test]
    fn encode_fixed64_uses_little_endian_byte_order() {
        let mut buffer = Vec::new();
        encode_fixed64(0x0102030405060708, &mut buffer);
        assert_eq!(buffer, vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn fixed64_always_consumes_exactly_eight_bytes() {
        let mut buffer = Vec::new();
        encode_fixed64(7, &mut buffer);
        buffer.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(decode_fixed64(&buffer), Ok((7, 8)));
    }

    #[test]
    fn decode_fixed64_rejects_too_short_input() {
        assert_eq!(
            decode_fixed64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn decode_fixed64_rejects_empty_input() {
        assert_eq!(decode_fixed64(&[]), Err(DecodeError::TooShort));
    }

    #[test]
    fn skip_field_consumes_a_varint() {
        let mut buffer = Vec::new();
        encode_varint(300, &mut buffer);
        buffer.extend_from_slice(&[0xAA]);
        assert_eq!(skip_field(WireType::Varint, &buffer), Ok(2));
    }

    #[test]
    fn skip_field_consumes_a_length_delimited_value() {
        let mut buffer = Vec::new();
        encode_length_delimited(b"hello", &mut buffer);
        buffer.extend_from_slice(&[0xAA]);
        assert_eq!(skip_field(WireType::LengthDelimited, &buffer), Ok(6));
    }

    #[test]
    fn skip_field_consumes_fixed32_and_fixed64() {
        let mut buffer32 = Vec::new();
        encode_fixed32(7, &mut buffer32);
        assert_eq!(skip_field(WireType::Fixed32, &buffer32), Ok(4));

        let mut buffer64 = Vec::new();
        encode_fixed64(7, &mut buffer64);
        assert_eq!(skip_field(WireType::Fixed64, &buffer64), Ok(8));
    }

    #[test]
    fn skip_field_propagates_decode_error() {
        assert_eq!(
            skip_field(WireType::Fixed32, &[0x01, 0x02]),
            Err(DecodeError::TooShort)
        );
    }
}
