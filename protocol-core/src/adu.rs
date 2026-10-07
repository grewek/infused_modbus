// Moved from `protocol::adu` (pre-move) -- converted `pdu: Vec<u8>` fields
// to `PduBytes` (the PDU portion of an ADU can never exceed MAX_PDU_LEN,
// that's the whole invariant PduBytes already encodes) and `encode()`'s
// `Vec<u8>` return to a new small fixed-capacity buffer, `AduBytes`, sized
// for the slightly larger ADU-level output (MBAP header + PDU, or unit ID +
// PDU + CRC) -- not yet wired up as `protocol`'s own `adu` module (a later,
// separate step once this port is reviewed, same as `pdu.rs`).

use crate::error::{DecodeError, read_u16_be};
use crate::pdu_bytes::{CapacityExceeded, MAX_PDU_LEN, PduBytes};

/// TCP's MBAP header (7 bytes: transaction ID + protocol ID + length + unit
/// ID) plus the PDU itself -- the largest of the two ADU shapes this crate
/// needs, so `AduBytes` is sized to it (RTU's own shape, unit ID + PDU +
/// 2-byte CRC, is smaller at 256).
pub const MAX_ADU_LEN: usize = MBAP_HEADER_LEN + MAX_PDU_LEN;

#[derive(Debug, Clone, Copy)]
pub struct AduBytes {
    data: [u8; MAX_ADU_LEN],
    len: usize,
}

impl AduBytes {
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_ADU_LEN],
            len: 0,
        }
    }

    pub fn push(&mut self, byte: u8) -> Result<(), CapacityExceeded> {
        if self.len == MAX_ADU_LEN {
            return Err(CapacityExceeded);
        }
        self.data[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), CapacityExceeded> {
        let new_len = self.len + bytes.len();
        if new_len > MAX_ADU_LEN {
            return Err(CapacityExceeded);
        }
        self.data[self.len..new_len].copy_from_slice(bytes);
        self.len = new_len;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for AduBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for AduBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for AduBytes {}

impl core::ops::Deref for AduBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

const MBAP_PROTOCOL_ID: u16 = 0x0000;
const MBAP_TRANSACTION_ID_BYTE: usize = 0;
const MBAP_PROTOCOL_ID_BYTE: usize = 2;
pub(crate) const MBAP_LENGTH_BYTE: usize = 4;
const MBAP_UNIT_ID_BYTE: usize = 6;
pub(crate) const MBAP_HEADER_LEN: usize = 7;

// Real Modbus caps the PDU at 253 bytes (1 function code + 252 data bytes), so
// the length field (unit ID + PDU) can never legitimately exceed 254. Rejecting
// anything above that here — rather than trusting a peer-supplied length and
// reading/allocating however much it claims — closes a memory-exhaustion DoS:
// a malicious peer could otherwise send a 7-byte header claiming a huge length
// and force a large allocation before ever sending the rest of the frame.
pub(crate) const MBAP_MAX_LENGTH: u16 = 254;

/// A Modbus TCP ADU wraps a PDU with an MBAP header: transaction ID, protocol ID
/// (always 0 for Modbus), a length covering unit ID + PDU, and the unit ID. The
/// PDU itself is kept as opaque bytes here — the ADU layer doesn't need to know
/// which PDU type it's carrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAdu {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub pdu: PduBytes,
}

impl TcpAdu {
    pub fn encode(&self) -> AduBytes {
        let mut buffer = AduBytes::new();
        buffer
            .extend_from_slice(&self.transaction_id.to_be_bytes())
            .expect("fits MAX_ADU_LEN");
        buffer
            .extend_from_slice(&MBAP_PROTOCOL_ID.to_be_bytes())
            .expect("fits MAX_ADU_LEN");
        let length = (self.pdu.len() + 1) as u16;
        buffer
            .extend_from_slice(&length.to_be_bytes())
            .expect("fits MAX_ADU_LEN");
        buffer.push(self.unit_id).expect("fits MAX_ADU_LEN");
        buffer
            .extend_from_slice(&self.pdu)
            .expect("fits MAX_ADU_LEN");
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < MBAP_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        let protocol_id = read_u16_be(bytes, MBAP_PROTOCOL_ID_BYTE);
        if protocol_id != MBAP_PROTOCOL_ID {
            return Err(DecodeError::UnexpectedProtocolId {
                actual: protocol_id,
            });
        }
        let length = read_u16_be(bytes, MBAP_LENGTH_BYTE);
        if length == 0 || length > MBAP_MAX_LENGTH {
            return Err(DecodeError::InvalidAduLength { length });
        }
        let pdu_len = length as usize - 1;
        if bytes.len() < MBAP_HEADER_LEN + pdu_len {
            return Err(DecodeError::TooShort);
        }
        let transaction_id = read_u16_be(bytes, MBAP_TRANSACTION_ID_BYTE);
        let unit_id = bytes[MBAP_UNIT_ID_BYTE];
        let mut pdu = PduBytes::new();
        // pdu_len <= MBAP_MAX_LENGTH - 1 = 253 = MAX_PDU_LEN, so this can
        // never actually fail -- checked via the length guard above, not
        // re-derived here.
        pdu.extend_from_slice(&bytes[MBAP_HEADER_LEN..MBAP_HEADER_LEN + pdu_len])
            .expect("pdu_len <= MAX_PDU_LEN, checked above");
        Ok(Self {
            transaction_id,
            unit_id,
            pdu,
        })
    }
}

const RTU_UNIT_ID_BYTE: usize = 0;
const RTU_CRC_LEN: usize = 2;
const RTU_MIN_FRAME_LEN: usize = 1 + RTU_CRC_LEN;

/// A Modbus RTU ADU wraps a PDU with a one-byte unit ID and a trailing
/// CRC16 over (unit ID + PDU). Unlike every big-endian u16 field elsewhere in
/// this protocol, the CRC is transmitted low byte first on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtuAdu {
    pub unit_id: u8,
    pub pdu: PduBytes,
}

fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

impl RtuAdu {
    pub fn encode(&self) -> AduBytes {
        let mut buffer = AduBytes::new();
        buffer.push(self.unit_id).expect("fits MAX_ADU_LEN");
        buffer
            .extend_from_slice(&self.pdu)
            .expect("fits MAX_ADU_LEN");
        let crc = crc16_modbus(&buffer);
        buffer
            .extend_from_slice(&crc.to_le_bytes())
            .expect("fits MAX_ADU_LEN");
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < RTU_MIN_FRAME_LEN {
            return Err(DecodeError::TooShort);
        }
        let crc_start = bytes.len() - RTU_CRC_LEN;
        let unit_id_and_pdu = &bytes[..crc_start];
        let expected_crc = crc16_modbus(unit_id_and_pdu);
        let actual_crc = u16::from_le_bytes([bytes[crc_start], bytes[crc_start + 1]]);
        if actual_crc != expected_crc {
            return Err(DecodeError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }
        let unit_id = bytes[RTU_UNIT_ID_BYTE];
        let mut pdu = PduBytes::new();
        pdu.extend_from_slice(&bytes[1..crc_start])
            .map_err(|_| DecodeError::TooLargeForBuffer)?;
        Ok(Self { unit_id, pdu })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pdu_bytes(bytes: &[u8]) -> PduBytes {
        let mut result = PduBytes::new();
        result.extend_from_slice(bytes).unwrap();
        result
    }

    #[test]
    fn tcp_adu_round_trips() {
        let adu = TcpAdu {
            transaction_id: 0x0042,
            unit_id: 0x01,
            pdu: pdu_bytes(&[0x03, 0x00, 0x00, 0x00, 0x0A]),
        };
        let encoded = adu.encode();
        assert_eq!(TcpAdu::decode(&encoded).unwrap(), adu);
    }

    #[test]
    fn tcp_adu_decode_rejects_too_short() {
        assert_eq!(TcpAdu::decode(&[0x00, 0x01]), Err(DecodeError::TooShort));
    }

    #[test]
    fn tcp_adu_decode_rejects_wrong_protocol_id() {
        let bytes = [0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03];
        assert_eq!(
            TcpAdu::decode(&bytes),
            Err(DecodeError::UnexpectedProtocolId { actual: 1 })
        );
    }

    #[test]
    fn tcp_adu_decode_rejects_zero_length() {
        let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(
            TcpAdu::decode(&bytes),
            Err(DecodeError::InvalidAduLength { length: 0 })
        );
    }

    #[test]
    fn tcp_adu_decode_rejects_length_exceeding_maximum_without_reading_a_huge_body() {
        // A malicious header claiming the maximum possible length (0xFFFF),
        // with no body ever supplied to back it up -- decode must reject
        // based on the header alone, not try to read/allocate for it.
        let bytes = [0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01];
        assert_eq!(
            TcpAdu::decode(&bytes),
            Err(DecodeError::InvalidAduLength { length: 0xFFFF })
        );
    }

    #[test]
    fn rtu_adu_round_trips() {
        let adu = RtuAdu {
            unit_id: 0x01,
            pdu: pdu_bytes(&[0x03, 0x00, 0x00, 0x00, 0x0A]),
        };
        let encoded = adu.encode();
        assert_eq!(RtuAdu::decode(&encoded).unwrap(), adu);
    }

    #[test]
    fn rtu_adu_decode_rejects_a_bad_crc() {
        let encoded = RtuAdu {
            unit_id: 0x01,
            pdu: pdu_bytes(&[0x03, 0x00, 0x00, 0x00, 0x0A]),
        }
        .encode();
        let last = encoded.len() - 1;
        let mut corrupted = AduBytes::new();
        corrupted.extend_from_slice(&encoded[..last]).unwrap();
        corrupted.push(encoded[last] ^ 0xFF).unwrap();
        assert!(matches!(
            RtuAdu::decode(&corrupted),
            Err(DecodeError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn rtu_adu_decode_rejects_too_short() {
        assert_eq!(RtuAdu::decode(&[0x01, 0x02]), Err(DecodeError::TooShort));
    }
}
