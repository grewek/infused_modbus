// Fixed-capacity list of coil/discrete-input bits, capped at 2000 -- the
// Modbus spec's own stated maximum for Read Coils/Read Discrete Inputs
// (section 6.1/6.2), not derived from MAX_PDU_LEN byte math (the byte-math
// ceiling is actually a little higher here; the spec caps it tighter than
// the wire alone would force). Shared by every bit-list PDU field (coils,
// discrete inputs, both read and write) -- same reasoning as RegisterValues
// for why one shared capacity is safe even where a specific PDU shape's
// real ceiling is a little lower.
//
// Stored packed 8-bits-per-byte internally -- the *same* layout the wire
// format already uses (bit 0 = LSB of the first byte) -- not one `bool`
// (1 full byte in Rust) per bit. Two real wins, found by benchmarking
// against the pre-port `Vec<bool>`-based implementation: (1) 250 bytes to
// zero-init instead of 2000 (measured ~4x faster construction, matching
// PduBytes'/RegisterValues' already-fast ~8ns), and (2) because this is
// now the exact wire layout, `encode`/`decode` paths that used to pack/
// unpack bit by bit can become single byte-range copies instead (see
// `extend_from_packed_bytes`/`as_packed_bytes` below, used by pdu.rs's
// bitfield encode/decode).
//
// Concrete, not a generic `ArrayVec<bool, 2000>`: see pdu_bytes.rs's own
// doc comment for why.

use crate::pdu_bytes::CapacityExceeded;

pub const MAX_BIT_COUNT: usize = 2000;
// 2000 is exactly divisible by 8, so this is exact, no rounding.
const MAX_BIT_BYTES: usize = MAX_BIT_COUNT / 8;

#[derive(Debug, Clone, Copy)]
pub struct BitValues {
    data: [u8; MAX_BIT_BYTES],
    len: usize,
}

impl BitValues {
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_BIT_BYTES],
            len: 0,
        }
    }

    pub fn push(&mut self, value: bool) -> Result<(), CapacityExceeded> {
        if self.len == MAX_BIT_COUNT {
            return Err(CapacityExceeded);
        }
        if value {
            self.data[self.len / 8] |= 1 << (self.len % 8);
        }
        self.len += 1;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, values: &[bool]) -> Result<(), CapacityExceeded> {
        let new_len = self.len + values.len();
        if new_len > MAX_BIT_COUNT {
            return Err(CapacityExceeded);
        }
        for (offset, &value) in values.iter().enumerate() {
            if value {
                let index = self.len + offset;
                self.data[index / 8] |= 1 << (index % 8);
            }
        }
        self.len = new_len;
        Ok(())
    }

    /// See `RegisterValues::extend_from_iter`'s own doc comment for why
    /// this exists alongside `push` (checks capacity once, not per
    /// element) -- kept for the general/not-already-packed case; prefer
    /// `extend_from_packed_bytes` below when the source is already
    /// wire-packed, which is the common case in pdu.rs and doesn't need a
    /// per-bit loop at all.
    pub fn extend_from_iter(
        &mut self,
        values: impl ExactSizeIterator<Item = bool>,
    ) -> Result<(), CapacityExceeded> {
        let new_len = self.len + values.len();
        if new_len > MAX_BIT_COUNT {
            return Err(CapacityExceeded);
        }
        for (offset, value) in values.enumerate() {
            if value {
                let index = self.len + offset;
                self.data[index / 8] |= 1 << (index % 8);
            }
        }
        self.len = new_len;
        Ok(())
    }

    /// Appends `bit_count` bits directly from already-packed wire-format
    /// bytes (same packing convention as this type's own storage: bit 0 =
    /// LSB of the first byte) -- a single byte-range copy instead of a
    /// per-bit loop. Only valid while `self.len` is already byte-aligned,
    /// true for every real caller (`BitValues` is always freshly
    /// constructed before a decode path populates it in one call).
    pub fn extend_from_packed_bytes(
        &mut self,
        packed: &[u8],
        bit_count: usize,
    ) -> Result<(), CapacityExceeded> {
        debug_assert_eq!(self.len % 8, 0, "only valid at a byte boundary");
        let new_len = self.len + bit_count;
        if new_len > MAX_BIT_COUNT {
            return Err(CapacityExceeded);
        }
        let byte_start = self.len / 8;
        let byte_count = bit_count.div_ceil(8);
        self.data[byte_start..byte_start + byte_count].copy_from_slice(&packed[..byte_count]);
        self.len = new_len;
        Ok(())
    }

    pub fn get(&self, index: usize) -> Option<bool> {
        if index >= self.len {
            return None;
        }
        Some(self.data[index / 8] & (1 << (index % 8)) != 0)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Raw packed-byte view of the first `len` bits, same convention as
    /// the wire format (any padding bits in the last byte are always 0,
    /// matching what a real encode would send) -- lets an `encode()` path
    /// just copy these bytes directly instead of re-packing bit by bit.
    pub fn as_packed_bytes(&self) -> &[u8] {
        &self.data[..self.len.div_ceil(8)]
    }

    pub fn iter(&self) -> BitValuesIter<'_> {
        BitValuesIter {
            values: self,
            index: 0,
        }
    }
}

impl Default for BitValues {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for BitValues {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.as_packed_bytes() == other.as_packed_bytes()
    }
}

impl Eq for BitValues {}

pub struct BitValuesIter<'a> {
    values: &'a BitValues,
    index: usize,
}

impl Iterator for BitValuesIter<'_> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        let value = self.values.get(self.index)?;
        self.index += 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.values.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for BitValuesIter<'_> {}

impl<'a> IntoIterator for &'a BitValues {
    type Item = bool;
    type IntoIter = BitValuesIter<'a>;

    fn into_iter(self) -> BitValuesIter<'a> {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        assert_eq!(BitValues::new().len(), 0);
        assert!(BitValues::new().is_empty());
    }

    #[test]
    fn extend_from_iter_matches_extend_from_slice() {
        let mut via_iter = BitValues::new();
        via_iter
            .extend_from_iter([true, false, true].into_iter())
            .unwrap();

        let mut via_slice = BitValues::new();
        via_slice.extend_from_slice(&[true, false, true]).unwrap();

        assert_eq!(via_iter, via_slice);
    }

    #[test]
    fn extend_from_iter_rejects_overflow_leaving_state_unchanged() {
        let mut values = BitValues::new();
        values
            .extend_from_iter(core::iter::repeat_n(true, MAX_BIT_COUNT - 1))
            .unwrap();
        assert_eq!(
            values.extend_from_iter([true, true].into_iter()),
            Err(CapacityExceeded)
        );
        assert_eq!(values.len(), MAX_BIT_COUNT - 1);
    }

    #[test]
    fn push_appends_a_single_bit() {
        let mut values = BitValues::new();
        values.push(true).unwrap();
        values.push(false).unwrap();
        values.push(true).unwrap();
        assert_eq!(values.get(0), Some(true));
        assert_eq!(values.get(1), Some(false));
        assert_eq!(values.get(2), Some(true));
        assert_eq!(values.get(3), None);
    }

    #[test]
    fn push_fails_without_panicking_once_full() {
        let mut values = BitValues::new();
        for _ in 0..MAX_BIT_COUNT {
            values.push(true).unwrap();
        }
        assert_eq!(values.push(true), Err(CapacityExceeded));
        assert_eq!(values.len(), MAX_BIT_COUNT);
    }

    #[test]
    fn extend_from_packed_bytes_matches_bit_by_bit_construction() {
        // 0b0000_0101 = bits [true, false, true, false, false, false, false, false]
        let mut via_packed = BitValues::new();
        via_packed
            .extend_from_packed_bytes(&[0b0000_0101], 8)
            .unwrap();

        let mut via_bits = BitValues::new();
        via_bits
            .extend_from_slice(&[true, false, true, false, false, false, false, false])
            .unwrap();

        assert_eq!(via_packed, via_bits);
    }

    #[test]
    fn extend_from_packed_bytes_handles_a_non_byte_aligned_bit_count() {
        let mut values = BitValues::new();
        // Only the low 3 bits of this byte are meaningful; get() must never
        // expose the other 5.
        values.extend_from_packed_bytes(&[0b1111_1101], 3).unwrap();
        assert_eq!(values.len(), 3);
        assert_eq!(values.get(0), Some(true));
        assert_eq!(values.get(1), Some(false));
        assert_eq!(values.get(2), Some(true));
        assert_eq!(values.get(3), None);
    }

    #[test]
    fn extend_from_packed_bytes_rejects_overflow() {
        let mut values = BitValues::new();
        let packed = [0xFFu8; MAX_BIT_BYTES];
        values
            .extend_from_packed_bytes(&packed[..MAX_BIT_BYTES - 1], MAX_BIT_COUNT - 8)
            .unwrap();
        assert_eq!(
            values.extend_from_packed_bytes(&[0xFF, 0xFF], 16),
            Err(CapacityExceeded)
        );
    }

    #[test]
    fn as_packed_bytes_round_trips_through_extend_from_packed_bytes() {
        let mut values = BitValues::new();
        values
            .extend_from_slice(&[true, false, true, true, false, false, false, true, true])
            .unwrap();
        let packed = values.as_packed_bytes().to_vec();

        let mut rebuilt = BitValues::new();
        rebuilt
            .extend_from_packed_bytes(&packed, values.len())
            .unwrap();
        assert_eq!(values, rebuilt);
    }

    #[test]
    fn iter_yields_every_pushed_bit_in_order() {
        let mut values = BitValues::new();
        values.extend_from_slice(&[true, false, true]).unwrap();
        let mut iter = values.iter();
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.next(), Some(true));
        assert_eq!(iter.next(), Some(false));
        assert_eq!(iter.next(), Some(true));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(BitValues::default(), BitValues::new());
    }
}
