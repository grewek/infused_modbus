// Converts a RegisterValue to/from the sequence of raw 16-bit words it
// occupies on the Modbus wire — the piece that was missing before either
// `client` (reading a real device) or `server` (answering a real Modbus
// master's read) could support anything beyond U16.
//
// A value's *natural* byte representation is always big-endian (byte A =
// most significant .. byte D/H = least significant, via each Rust numeric
// type's own `to_be_bytes()`/`from_be_bytes()`). `MemLayout` describes how
// a device rearranges those bytes across its registers before/after
// Modbus's own (fixed) big-endian-per-register wire framing — see
// `protocol::device_description::MemLayout`'s doc comment for the ABCD/
// BADC/CDAB/DCBA naming. That rearrangement decomposes into two
// independent, self-inverse operations (word order, and byte order within
// each word) that also commute with each other, which is why
// `apply_mem_layout` is its own inverse and gets used for both directions
// below instead of needing separate encode/decode transforms.
//
// U8/I8 are the one case with no MemLayout involvement: they occupy a
// whole register (see CLAUDE.md — deliberately not packed two-per-register)
// with the value in the register's low byte and the high byte zero
// (U8) or sign-extended (I8), same as if the 8-bit value were simply
// promoted to 16 bits before being treated as an ordinary single register.
//
// U24/I24 have no native Rust type, so they're handled identically to
// U32/I32 (4-byte big-endian representation, 2 registers, MemLayout
// applied) — the value is simply a u32/i32 restricted to the 24-bit range,
// with that range enforced where a value is constructed from user input
// (`InfusedFilesystem::parse_register_value`), not here on the wire path.

use crate::RegisterValue;
use protocol::device_description::{DataType, MemLayout};

/// Reverses word order and/or swaps each word's own two bytes, according to
/// `mem_layout`. Applying this twice returns the original `words` — both
/// operations are self-inverse and commute, so the same function serves as
/// its own inverse; used identically to go from a value's natural
/// big-endian words to wire order, and back.
fn apply_mem_layout(words: &mut [u16], mem_layout: MemLayout) {
    let (reverse_word_order, swap_bytes_within_word) = match mem_layout {
        MemLayout::Abcd => (false, false),
        MemLayout::Badc => (false, true),
        MemLayout::Cdab => (true, false),
        MemLayout::Dcba => (true, true),
    };
    if swap_bytes_within_word {
        for word in words.iter_mut() {
            *word = word.swap_bytes();
        }
    }
    if reverse_word_order {
        words.reverse();
    }
}

fn words_from_natural_bytes(bytes: &[u8], mem_layout: MemLayout) -> Vec<u16> {
    let mut words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();
    apply_mem_layout(&mut words, mem_layout);
    words
}

fn natural_bytes_from_words(words: &[u16], mem_layout: MemLayout) -> Vec<u8> {
    let mut words = words.to_vec();
    apply_mem_layout(&mut words, mem_layout);
    words.iter().flat_map(|word| word.to_be_bytes()).collect()
}

/// Encodes `value` into the sequence of wire register words it should be
/// written as, in wire order (i.e. ready to place at consecutive
/// addresses starting from the register's own address).
pub fn register_value_to_words(value: RegisterValue, mem_layout: MemLayout) -> Vec<u16> {
    match value {
        RegisterValue::U8(value) => vec![value as u16],
        RegisterValue::I8(value) => vec![value as i16 as u16],
        RegisterValue::U16(value) => vec![value],
        RegisterValue::I16(value) => vec![value as u16],
        RegisterValue::U24(value) | RegisterValue::U32(value) => {
            words_from_natural_bytes(&value.to_be_bytes(), mem_layout)
        }
        RegisterValue::I24(value) | RegisterValue::I32(value) => {
            words_from_natural_bytes(&value.to_be_bytes(), mem_layout)
        }
        RegisterValue::F32(value) => words_from_natural_bytes(&value.to_be_bytes(), mem_layout),
        RegisterValue::U64(value) => words_from_natural_bytes(&value.to_be_bytes(), mem_layout),
        RegisterValue::I64(value) => words_from_natural_bytes(&value.to_be_bytes(), mem_layout),
        RegisterValue::F64(value) => words_from_natural_bytes(&value.to_be_bytes(), mem_layout),
    }
}

/// Reconstructs a RegisterValue of type `data_type` from `words` — exactly
/// `data_type.register_count()` wire register words, in wire order.
/// Returns `None` if `words` is the wrong length for `data_type`.
pub fn register_value_from_words(
    data_type: DataType,
    words: &[u16],
    mem_layout: MemLayout,
) -> Option<RegisterValue> {
    if words.len() != data_type.register_count() as usize {
        return None;
    }
    Some(match data_type {
        DataType::U8 => RegisterValue::U8(words[0] as u8),
        DataType::I8 => RegisterValue::I8(words[0] as u8 as i8),
        DataType::U16 => RegisterValue::U16(words[0]),
        DataType::I16 => RegisterValue::I16(words[0] as i16),
        DataType::U24 => RegisterValue::U24(u32::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
        DataType::I24 => RegisterValue::I24(i32::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
        DataType::U32 => RegisterValue::U32(u32::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
        DataType::I32 => RegisterValue::I32(i32::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
        DataType::F32 => RegisterValue::F32(f32::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
        DataType::U64 => RegisterValue::U64(u64::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
        DataType::I64 => RegisterValue::I64(i64::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
        DataType::F64 => RegisterValue::F64(f64::from_be_bytes(
            natural_bytes_from_words(words, mem_layout)
                .try_into()
                .expect("register slice length already validated above"),
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u8_occupies_one_register_in_the_low_byte() {
        assert_eq!(
            register_value_to_words(RegisterValue::U8(0xAB), MemLayout::Abcd),
            vec![0x00AB]
        );
    }

    #[test]
    fn i8_occupies_one_register_sign_extended() {
        assert_eq!(
            register_value_to_words(RegisterValue::I8(-1), MemLayout::Abcd),
            vec![0xFFFF]
        );
        assert_eq!(
            register_value_to_words(RegisterValue::I8(1), MemLayout::Abcd),
            vec![0x0001]
        );
    }

    #[test]
    fn u16_occupies_one_register_unchanged_by_mem_layout() {
        for mem_layout in [
            MemLayout::Abcd,
            MemLayout::Badc,
            MemLayout::Cdab,
            MemLayout::Dcba,
        ] {
            assert_eq!(
                register_value_to_words(RegisterValue::U16(0xBEEF), mem_layout),
                vec![0xBEEF]
            );
        }
    }

    // A known 4-byte value (bytes A=0x12 B=0x34 C=0x56 D=0x78) run through
    // all four MemLayout conventions, checked against their own names:
    // ABCD/BADC/CDAB/DCBA describe exactly which byte ends up in which
    // wire position, in order.
    #[test]
    fn u32_encodes_to_the_four_named_byte_orders() {
        let value = RegisterValue::U32(0x1234_5678);
        assert_eq!(
            register_value_to_words(value, MemLayout::Abcd),
            vec![0x1234, 0x5678]
        );
        assert_eq!(
            register_value_to_words(value, MemLayout::Badc),
            vec![0x3412, 0x7856]
        );
        assert_eq!(
            register_value_to_words(value, MemLayout::Cdab),
            vec![0x5678, 0x1234]
        );
        assert_eq!(
            register_value_to_words(value, MemLayout::Dcba),
            vec![0x7856, 0x3412]
        );
    }

    #[test]
    fn u32_round_trips_through_every_mem_layout() {
        for mem_layout in [
            MemLayout::Abcd,
            MemLayout::Badc,
            MemLayout::Cdab,
            MemLayout::Dcba,
        ] {
            let value = RegisterValue::U32(0x1234_5678);
            let words = register_value_to_words(value, mem_layout);
            assert_eq!(
                register_value_from_words(DataType::U32, &words, mem_layout),
                Some(value)
            );
        }
    }

    #[test]
    fn i32_round_trips_including_negative_values() {
        for mem_layout in [
            MemLayout::Abcd,
            MemLayout::Badc,
            MemLayout::Cdab,
            MemLayout::Dcba,
        ] {
            let value = RegisterValue::I32(-123_456_789);
            let words = register_value_to_words(value, mem_layout);
            assert_eq!(
                register_value_from_words(DataType::I32, &words, mem_layout),
                Some(value)
            );
        }
    }

    #[test]
    fn f32_round_trips() {
        let value = RegisterValue::F32(3.5);
        let words = register_value_to_words(value, MemLayout::Cdab);
        assert_eq!(
            register_value_from_words(DataType::F32, &words, MemLayout::Cdab),
            Some(value)
        );
    }

    #[test]
    fn u64_round_trips_across_four_registers() {
        for mem_layout in [
            MemLayout::Abcd,
            MemLayout::Badc,
            MemLayout::Cdab,
            MemLayout::Dcba,
        ] {
            let value = RegisterValue::U64(0x1122_3344_5566_7788);
            let words = register_value_to_words(value, mem_layout);
            assert_eq!(words.len(), 4);
            assert_eq!(
                register_value_from_words(DataType::U64, &words, mem_layout),
                Some(value)
            );
        }
    }

    #[test]
    fn i64_round_trips_a_negative_value() {
        let value = RegisterValue::I64(-1);
        let words = register_value_to_words(value, MemLayout::Dcba);
        assert_eq!(words, vec![0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]);
        assert_eq!(
            register_value_from_words(DataType::I64, &words, MemLayout::Dcba),
            Some(value)
        );
    }

    #[test]
    fn f64_round_trips() {
        let value = RegisterValue::F64(3.5);
        let words = register_value_to_words(value, MemLayout::Badc);
        assert_eq!(
            register_value_from_words(DataType::F64, &words, MemLayout::Badc),
            Some(value)
        );
    }

    #[test]
    fn u24_and_i24_round_trip_like_u32_i32_with_a_zero_padding_byte() {
        let value = RegisterValue::U24(0x00FF_FFFF);
        let words = register_value_to_words(value, MemLayout::Abcd);
        assert_eq!(words, vec![0x00FF, 0xFFFF]);
        assert_eq!(
            register_value_from_words(DataType::U24, &words, MemLayout::Abcd),
            Some(value)
        );

        let value = RegisterValue::I24(-1);
        let words = register_value_to_words(value, MemLayout::Abcd);
        assert_eq!(words, vec![0xFFFF, 0xFFFF]);
        assert_eq!(
            register_value_from_words(DataType::I24, &words, MemLayout::Abcd),
            Some(value)
        );
    }

    #[test]
    fn register_value_from_words_rejects_the_wrong_word_count() {
        assert_eq!(
            register_value_from_words(DataType::U32, &[0x1234], MemLayout::Abcd),
            None
        );
        assert_eq!(
            register_value_from_words(DataType::U16, &[0x1234, 0x5678], MemLayout::Abcd),
            None
        );
    }
}
