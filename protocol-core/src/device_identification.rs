// FC 0x2B/0x0E (Read Device Identification) object-list support type.

use crate::pdu_bytes::{CapacityExceeded, PduBytes};

/// The id/value pairs of a Read Device Identification response: every
/// object's raw `value` bytes, concatenated into one flat `PduBytes`
/// buffer, plus each object's own `id` and byte length so a caller can
/// slice the buffer back apart. Same flat-buffer-over-array-of-buffers
/// reasoning as `file_record::FileRecordResponseData` — a `[DeviceIdObject;
/// 84]` where each object embeds its own full `PduBytes` would reserve
/// `84 * MAX_PDU_LEN` bytes (~21KB) per instance; this flat form only ever
/// uses the PDU's real ~253-byte budget once.
///
/// Capacity 84 is a rough computed ceiling (every object at its
/// theoretical minimum size: 1 id byte + 1 length byte + 1 value byte =
/// 3 bytes; MAX_PDU_LEN / 3 ≈ 84), not a number grounded in how this
/// project's own FC43 responses actually look in practice (usually 1-3
/// objects per response) — a deliberately generous placeholder, revisit if
/// it ever turns out to matter.
pub const MAX_DEVICE_IDENTIFICATION_OBJECTS: usize = 84;

#[derive(Debug, Clone, Copy)]
pub struct DeviceIdentificationObjects {
    data: PduBytes,
    ids: [u8; MAX_DEVICE_IDENTIFICATION_OBJECTS],
    // The object model's own length byte caps a single value at 255 bytes
    // (see the pre-move `DeviceIdentificationObject` doc comment) — `u8` is
    // the right width here, not `u16` like file_record.rs's per-record
    // lengths (which can run up to MAX_PDU_LEN).
    lengths: [u8; MAX_DEVICE_IDENTIFICATION_OBJECTS],
    count: usize,
}

impl DeviceIdentificationObjects {
    pub const fn new() -> Self {
        Self {
            data: PduBytes::new(),
            ids: [0u8; MAX_DEVICE_IDENTIFICATION_OBJECTS],
            lengths: [0u8; MAX_DEVICE_IDENTIFICATION_OBJECTS],
            count: 0,
        }
    }

    pub fn push(&mut self, id: u8, value: &[u8]) -> Result<(), CapacityExceeded> {
        if self.count == MAX_DEVICE_IDENTIFICATION_OBJECTS || value.len() > u8::MAX as usize {
            return Err(CapacityExceeded);
        }
        self.data.extend_from_slice(value)?;
        self.ids[self.count] = id;
        self.lengths[self.count] = value.len() as u8;
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn object(&self, index: usize) -> Option<(u8, &[u8])> {
        if index >= self.count {
            return None;
        }
        let start: usize = self.lengths[..index]
            .iter()
            .map(|&length| length as usize)
            .sum();
        let end = start + self.lengths[index] as usize;
        Some((self.ids[index], &self.data[start..end]))
    }
}

impl Default for DeviceIdentificationObjects {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for DeviceIdentificationObjects {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count
            && (0..self.count).all(|index| self.object(index) == other.object(index))
    }
}

impl Eq for DeviceIdentificationObjects {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_read_back() {
        let mut objects = DeviceIdentificationObjects::new();
        objects.push(0x80, &[0x01]).unwrap();
        objects.push(0x81, b"infused_modbus").unwrap();

        assert_eq!(objects.count(), 2);
        assert_eq!(objects.object(0), Some((0x80, &[0x01][..])));
        assert_eq!(
            objects.object(1),
            Some((0x81, b"infused_modbus".as_slice()))
        );
        assert_eq!(objects.object(2), None);
    }

    #[test]
    fn push_fails_without_panicking_once_byte_capacity_exceeded() {
        let mut objects = DeviceIdentificationObjects::new();
        objects.push(0x81, &[0u8; 250]).unwrap();
        assert_eq!(objects.push(0x82, &[0u8; 10]), Err(CapacityExceeded));
        assert_eq!(objects.count(), 1);
    }

    #[test]
    fn push_fails_without_panicking_once_object_count_exceeded() {
        let mut objects = DeviceIdentificationObjects::new();
        for _ in 0..MAX_DEVICE_IDENTIFICATION_OBJECTS {
            objects.push(0, &[]).unwrap();
        }
        assert_eq!(objects.push(0, &[]), Err(CapacityExceeded));
    }

    #[test]
    fn equality_compares_objects_not_padding() {
        let mut a = DeviceIdentificationObjects::new();
        a.push(1, &[9]).unwrap();
        let mut b = DeviceIdentificationObjects::new();
        b.push(1, &[9]).unwrap();
        assert_eq!(a, b);
    }
}
