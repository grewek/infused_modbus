pub mod adu;
pub mod pdu;
pub mod tcp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    UnexpectedFunctionCode { expected: u8, actual: u8 },
    OddByteCount { byte_count: u8 },
    NotAnExceptionResponse { function_code: u8 },
    UnexpectedProtocolId { actual: u16 },
    InvalidAduLength { length: u16 },
    CrcMismatch { expected: u16, actual: u16 },
}

pub(crate) fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
