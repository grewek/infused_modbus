// Fixed-capacity list of register values, capped at Modbus's own per-PDU
// register-count ceiling: function_code(1) + byte_count(1) + 2 bytes per
// register <= MAX_PDU_LEN (253) => at most 125 registers -- the spec's own
// stated maximum (sections 6.3/6.4), not a number this project invented.
// Shared by every register-list PDU field (holding registers, input
// registers, both halves of read/write multiple registers): this capacity
// is a safe upper bound for all of them even where a specific PDU shape's
// own header overhead makes its true wire-level ceiling a little lower
// (e.g. Write Multiple Registers' real max is 123, not 125) -- the tighter
// limit is still enforced separately during decode; this type's capacity
// only has to never be smaller than any real case.
//
// Concrete, not a generic `ArrayVec<u16, 125>`: see pdu_bytes.rs's own doc
// comment for why.

use crate::pdu_bytes::CapacityExceeded;

pub const MAX_REGISTER_COUNT: usize = 125;

#[derive(Debug, Clone, Copy)]
pub struct RegisterValues {
    data: [u16; MAX_REGISTER_COUNT],
    len: usize,
}

impl RegisterValues {
    pub const fn new() -> Self {
        Self {
            data: [0u16; MAX_REGISTER_COUNT],
            len: 0,
        }
    }

    pub fn push(&mut self, value: u16) -> Result<(), CapacityExceeded> {
        if self.len == MAX_REGISTER_COUNT {
            return Err(CapacityExceeded);
        }
        self.data[self.len] = value;
        self.len += 1;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, values: &[u16]) -> Result<(), CapacityExceeded> {
        let new_len = self.len + values.len();
        if new_len > MAX_REGISTER_COUNT {
            return Err(CapacityExceeded);
        }
        self.data[self.len..new_len].copy_from_slice(values);
        self.len = new_len;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RegisterValues {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for RegisterValues {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for RegisterValues {}

impl core::ops::Deref for RegisterValues {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        assert_eq!(RegisterValues::new().len(), 0);
        assert!(RegisterValues::new().is_empty());
    }

    #[test]
    fn push_and_extend_from_slice_agree() {
        let mut via_push = RegisterValues::new();
        via_push.push(1).unwrap();
        via_push.push(2).unwrap();

        let mut via_extend = RegisterValues::new();
        via_extend.extend_from_slice(&[1, 2]).unwrap();

        assert_eq!(via_push, via_extend);
        assert_eq!(via_push.as_slice(), &[1, 2]);
    }

    #[test]
    fn push_fails_without_panicking_once_full() {
        let mut values = RegisterValues::new();
        for _ in 0..MAX_REGISTER_COUNT {
            values.push(0).unwrap();
        }
        assert_eq!(values.push(0), Err(CapacityExceeded));
        assert_eq!(values.len(), MAX_REGISTER_COUNT);
    }

    #[test]
    fn extend_from_slice_rejects_overflow_leaving_state_unchanged() {
        let mut values = RegisterValues::new();
        values
            .extend_from_slice(&[0u16; MAX_REGISTER_COUNT - 1])
            .unwrap();
        assert_eq!(values.extend_from_slice(&[0, 0]), Err(CapacityExceeded));
        assert_eq!(values.len(), MAX_REGISTER_COUNT - 1);
    }

    #[test]
    fn deref_gives_slice_methods_for_free() {
        let mut values = RegisterValues::new();
        values.extend_from_slice(&[10, 20, 30]).unwrap();
        assert_eq!(values[1], 20);
        assert_eq!(values.iter().sum::<u16>(), 60);
    }
}
