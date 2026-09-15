use crate::{DecodeError, read_u16_be};

const MBAP_PROTOCOL_ID: u16 = 0x0000;
const MBAP_TRANSACTION_ID_BYTE: usize = 0;
const MBAP_PROTOCOL_ID_BYTE: usize = 2;
// Visible to `crate::tcp`, which has to know these to frame a stream of bytes
// into whole ADUs before it can hand a complete one to `TcpAdu::decode`.
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

// A Modbus TCP ADU wraps a PDU with an MBAP header: transaction ID, protocol ID
// (always 0 for Modbus), a length covering unit ID + PDU, and the unit ID. The
// PDU itself is kept as opaque bytes here — the ADU layer doesn't need to know
// which PDU type it's carrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAdu {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub pdu: Vec<u8>,
}

impl TcpAdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(MBAP_HEADER_LEN + self.pdu.len());
        buffer.extend_from_slice(&self.transaction_id.to_be_bytes());
        buffer.extend_from_slice(&MBAP_PROTOCOL_ID.to_be_bytes());
        let length = (self.pdu.len() + 1) as u16;
        buffer.extend_from_slice(&length.to_be_bytes());
        buffer.push(self.unit_id);
        buffer.extend_from_slice(&self.pdu);
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
        let pdu = bytes[MBAP_HEADER_LEN..MBAP_HEADER_LEN + pdu_len].to_vec();
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

// A Modbus RTU ADU wraps a PDU with a one-byte unit ID and a trailing
// CRC16 over (unit ID + PDU). Unlike every big-endian u16 field elsewhere in
// this protocol, the CRC is transmitted low byte first on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtuAdu {
    pub unit_id: u8,
    pub pdu: Vec<u8>,
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
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(1 + self.pdu.len() + RTU_CRC_LEN);
        buffer.push(self.unit_id);
        buffer.extend_from_slice(&self.pdu);
        let crc = crc16_modbus(&buffer);
        buffer.extend_from_slice(&crc.to_le_bytes());
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
        let pdu = unit_id_and_pdu[1..].to_vec();
        Ok(Self { unit_id, pdu })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_adu_round_trip() {
        let adu = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x01, 0x00, 0x02],
        };
        let encoded = adu.encode();
        let decoded = TcpAdu::decode(&encoded).unwrap();
        assert_eq!(adu, decoded);
    }

    #[test]
    fn tcp_adu_encode_produces_expected_bytes() {
        let adu = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x01, 0x00, 0x02],
        };
        assert_eq!(
            adu.encode(),
            vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x02
            ]
        );
    }

    #[test]
    fn tcp_adu_decode_rejects_too_short_header() {
        let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06];
        assert_eq!(TcpAdu::decode(&bytes), Err(DecodeError::TooShort));
    }

    #[test]
    fn tcp_adu_decode_rejects_buffer_shorter_than_declared_length() {
        let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00];
        assert_eq!(TcpAdu::decode(&bytes), Err(DecodeError::TooShort));
    }

    #[test]
    fn tcp_adu_decode_rejects_unexpected_protocol_id() {
        let bytes = [0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03];
        assert_eq!(
            TcpAdu::decode(&bytes),
            Err(DecodeError::UnexpectedProtocolId { actual: 0x0001 })
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
    fn tcp_adu_decode_rejects_length_exceeding_maximum() {
        let mut bytes = vec![0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01];
        bytes.extend(std::iter::repeat_n(0u8, 0xFFFF - 1));
        assert_eq!(
            TcpAdu::decode(&bytes),
            Err(DecodeError::InvalidAduLength { length: 0xFFFF })
        );
    }

    #[test]
    fn crc16_modbus_matches_known_vector() {
        // Widely cited Modbus RTU example: slave 1, Read Holding Registers,
        // starting address 0, quantity 10.
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];
        assert_eq!(crc16_modbus(&data), 0xCDC5);
    }

    #[test]
    fn rtu_adu_round_trip() {
        let adu = RtuAdu {
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };
        let encoded = adu.encode();
        let decoded = RtuAdu::decode(&encoded).unwrap();
        assert_eq!(adu, decoded);
    }

    #[test]
    fn rtu_adu_encode_produces_expected_bytes() {
        let adu = RtuAdu {
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };
        assert_eq!(
            adu.encode(),
            vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD]
        );
    }

    #[test]
    fn rtu_adu_decode_rejects_too_short_buffer() {
        let bytes = [0x01, 0xC5];
        assert_eq!(RtuAdu::decode(&bytes), Err(DecodeError::TooShort));
    }

    #[test]
    fn rtu_adu_decode_rejects_crc_mismatch() {
        let bytes = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00];
        assert_eq!(
            RtuAdu::decode(&bytes),
            Err(DecodeError::CrcMismatch {
                expected: 0xCDC5,
                actual: 0x0000
            })
        );
    }
}
