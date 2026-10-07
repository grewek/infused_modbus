// Fixed-capacity list of coil/discrete-input bits, capped at 2000 -- the
// Modbus spec's own stated maximum for Read Coils/Read Discrete Inputs
// (section 6.1/6.2), not derived from MAX_PDU_LEN byte math the way
// register_values.rs's 125 is (the byte-math ceiling is actually a little
// higher here; the spec caps it tighter than the wire alone would force).
// Shared by every bit-list PDU field (coils, discrete inputs, both read and
// write) -- same reasoning as RegisterValues for why one shared capacity is
// safe even where a specific PDU shape's real ceiling is a little lower.
//
// Concrete, not a generic `ArrayVec<bool, 2000>`: see pdu_bytes.rs's own
// doc comment for why.

use crate::pdu_bytes::CapacityExceeded;

pub const MAX_BIT_COUNT: usize = 2000;

#[derive(Debug, Clone, Copy)]
pub struct BitValues {
    data: [bool; MAX_BIT_COUNT],
    len: usize,
}

impl BitValues {
    pub const fn new() -> Self {
        Self {
            data: [false; MAX_BIT_COUNT],
            len: 0,
        }
    }

    pub fn push(&mut self, value: bool) -> Result<(), CapacityExceeded> {
        if self.len == MAX_BIT_COUNT {
            return Err(CapacityExceeded);
        }
        self.data[self.len] = value;
        self.len += 1;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, values: &[bool]) -> Result<(), CapacityExceeded> {
        let new_len = self.len + values.len();
        if new_len > MAX_BIT_COUNT {
            return Err(CapacityExceeded);
        }
        self.data[self.len..new_len].copy_from_slice(values);
        self.len = new_len;
        Ok(())
    }

    pub fn as_slice(&self) -> &[bool] {
        &self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for BitValues {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for BitValues {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for BitValues {}

impl core::ops::Deref for BitValues {
    type Target = [bool];

    fn deref(&self) -> &[bool] {
        self.as_slice()
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
    fn push_and_extend_from_slice_agree() {
        let mut via_push = BitValues::new();
        via_push.push(true).unwrap();
        via_push.push(false).unwrap();

        let mut via_extend = BitValues::new();
        via_extend.extend_from_slice(&[true, false]).unwrap();

        assert_eq!(via_push, via_extend);
        assert_eq!(via_push.as_slice(), &[true, false]);
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
    fn extend_from_slice_rejects_overflow_leaving_state_unchanged() {
        let mut values = BitValues::new();
        values
            .extend_from_slice(&[true; MAX_BIT_COUNT - 1])
            .unwrap();
        assert_eq!(
            values.extend_from_slice(&[true, true]),
            Err(CapacityExceeded)
        );
        assert_eq!(values.len(), MAX_BIT_COUNT - 1);
    }

    #[test]
    fn deref_gives_slice_methods_for_free() {
        let mut values = BitValues::new();
        values.extend_from_slice(&[true, false, true]).unwrap();
        assert!(values[0]);
        assert_eq!(values.iter().filter(|&&bit| bit).count(), 2);
    }
}
