// A fixed-capacity byte buffer sized to Modbus's own hard ceiling: every
// PDU (request or response, any function code) is capped at 253 bytes by
// the protocol itself -- a 256-byte RTU serial frame minus 1 function-code
// byte minus 2 CRC bytes, and TCP's own MBAP length field enforces the same
// bound. That's a protocol fact, not an implementation choice, so a fixed
// stack-allocated buffer is strictly more correct here than a
// heap-allocated `Vec<u8>` ever was, independent of the no_std motivation.
//
// Deliberately a concrete, non-generic type rather than a generic
// `ArrayVec<T, const N: usize>`: every byte-buffer use in this codebase
// needs exactly this one capacity, so a generic parameter would only add a
// monomorphization surface for nothing -- see this project's own binary-
// size findings on exactly that pattern (resolve_addresses, 2026-10-07).

/// The hard per-PDU byte ceiling every `PduBytes` is sized to. Matches
/// `server::handler::MAX_PDU_LEN` and `device_identification::MAX_PDU_LEN`
/// (not yet unified with those — this crate doesn't depend on `server` or
/// vice versa; left as a follow-up once `pdu.rs`/`adu.rs` actually move
/// here).
pub const MAX_PDU_LEN: usize = 253;

/// Returned by `push`/`extend_from_slice` when the write would exceed
/// `MAX_PDU_LEN` — never a panic. A well-formed Modbus peer can never
/// trigger this (every real PDU fits), so in practice this only fires
/// against a malformed or malicious one, matching this project's standing
/// "validate untrusted lengths/counts before allocating/reading" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityExceeded;

#[derive(Debug, Clone, Copy)]
pub struct PduBytes {
    data: [u8; MAX_PDU_LEN],
    len: usize,
}

impl PduBytes {
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_PDU_LEN],
            len: 0,
        }
    }

    pub fn push(&mut self, byte: u8) -> Result<(), CapacityExceeded> {
        if self.len == MAX_PDU_LEN {
            return Err(CapacityExceeded);
        }
        self.data[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), CapacityExceeded> {
        let new_len = self.len + bytes.len();
        if new_len > MAX_PDU_LEN {
            return Err(CapacityExceeded);
        }
        self.data[self.len..new_len].copy_from_slice(bytes);
        self.len = new_len;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// For in-place bit-packing (coil/discrete-input responses): push the
    /// needed number of zero bytes first via `push`/`extend_from_slice`,
    /// then flip individual bits through this.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for PduBytes {
    fn default() -> Self {
        Self::new()
    }
}

// Compares meaningful content only, not the unused tail of `data` -- never
// actually divergent in practice (every constructor path leaves the tail
// zeroed), but comparing `as_slice()` directly states the real intent
// (equal content, not equal byte-for-byte memory) rather than leaning on
// that invariant.
impl PartialEq for PduBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PduBytes {}

impl core::ops::Deref for PduBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let bytes = PduBytes::new();
        assert_eq!(bytes.len(), 0);
        assert!(bytes.is_empty());
        assert_eq!(bytes.as_slice(), &[] as &[u8]);
    }

    #[test]
    fn push_appends_a_single_byte() {
        let mut bytes = PduBytes::new();
        bytes.push(0x42).unwrap();
        bytes.push(0x43).unwrap();
        assert_eq!(bytes.as_slice(), &[0x42, 0x43]);
    }

    #[test]
    fn push_fails_without_panicking_once_full() {
        let mut bytes = PduBytes::new();
        for _ in 0..MAX_PDU_LEN {
            bytes.push(0).unwrap();
        }
        assert_eq!(bytes.push(0), Err(CapacityExceeded));
        assert_eq!(bytes.len(), MAX_PDU_LEN);
    }

    #[test]
    fn extend_from_slice_appends_every_byte() {
        let mut bytes = PduBytes::new();
        bytes.extend_from_slice(&[1, 2, 3]).unwrap();
        bytes.extend_from_slice(&[4, 5]).unwrap();
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn extend_from_slice_rejects_a_write_that_would_overflow_leaving_state_unchanged() {
        let mut bytes = PduBytes::new();
        bytes.extend_from_slice(&[0u8; MAX_PDU_LEN - 1]).unwrap();
        assert_eq!(bytes.extend_from_slice(&[0, 0]), Err(CapacityExceeded));
        // Rejected atomically -- the one byte that would have fit wasn't
        // partially written either.
        assert_eq!(bytes.len(), MAX_PDU_LEN - 1);
    }

    #[test]
    fn extend_from_slice_succeeds_at_exactly_the_capacity_boundary() {
        let mut bytes = PduBytes::new();
        bytes.extend_from_slice(&[7u8; MAX_PDU_LEN]).unwrap();
        assert_eq!(bytes.len(), MAX_PDU_LEN);
    }

    #[test]
    fn deref_gives_slice_methods_for_free() {
        let mut bytes = PduBytes::new();
        bytes.extend_from_slice(&[9, 8, 7]).unwrap();
        assert_eq!(bytes[1], 8);
        assert_eq!(bytes.iter().sum::<u8>(), 24);
    }

    #[test]
    fn equal_content_compares_equal_regardless_of_build_path() {
        let mut via_push = PduBytes::new();
        via_push.push(1).unwrap();
        via_push.push(2).unwrap();

        let mut via_extend = PduBytes::new();
        via_extend.extend_from_slice(&[1, 2]).unwrap();

        assert_eq!(via_push, via_extend);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(PduBytes::default(), PduBytes::new());
    }
}
