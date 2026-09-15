use crate::{DecodeError, read_u16_be};

pub const FUNCTION_CODE_READ_HOLDING_REGISTERS: u8 = 0x03;
pub const FUNCTION_CODE_WRITE_SINGLE_REGISTER: u8 = 0x06;
pub const FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS: u8 = 0x10;

const FUNCTION_CODE_BYTE: usize = 0;

// Byte 0 is always the function code, and every PDU in this family (Read Holding
// Registers request, Write Single Register request/response, Write Multiple
// Registers response) places an address field followed by a quantity-or-value
// field at these same fixed offsets, so one shared pair of offsets covers all of them.
const ADDRESS_FIELD_BYTE: usize = 1;
const QUANTITY_OR_VALUE_FIELD_BYTE: usize = 3;

// Length of any PDU that is just function code + two u16 fields (see above).
const TWO_FIELD_PDU_LEN: usize = 5;

const BYTE_COUNT_BYTE: usize = 1;
const REGISTER_VALUES_START: usize = 2;
const RESPONSE_HEADER_LEN: usize = 2;

const WRITE_MULTIPLE_REGISTERS_BYTE_COUNT_BYTE: usize = 5;
const WRITE_MULTIPLE_REGISTERS_VALUES_START: usize = 6;
const WRITE_MULTIPLE_REGISTERS_REQUEST_HEADER_LEN: usize = 6;

// Modbus marks a response as an exception by setting the top bit of the
// (otherwise normal) function code byte; the original function code is
// recovered by clearing that bit again.
const EXCEPTION_RESPONSE_FUNCTION_CODE_BIT: u8 = 0x80;
const EXCEPTION_CODE_BYTE: usize = 1;
const EXCEPTION_RESPONSE_LEN: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadHoldingRegistersRequest {
    pub starting_address: u16,
    pub quantity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadHoldingRegistersResponse {
    pub register_values: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSingleRegisterRequest {
    pub register_address: u16,
    pub register_value: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSingleRegisterResponse {
    pub register_address: u16,
    pub register_value: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteMultipleRegistersRequest {
    pub starting_address: u16,
    pub register_values: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteMultipleRegistersResponse {
    pub starting_address: u16,
    pub quantity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionResponse {
    pub function_code: u8,
    pub exception_code: u8,
}

impl ReadHoldingRegistersRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(5);
        buffer.push(FUNCTION_CODE_READ_HOLDING_REGISTERS);
        buffer.extend_from_slice(&self.starting_address.to_be_bytes());
        buffer.extend_from_slice(&self.quantity.to_be_bytes());
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < TWO_FIELD_PDU_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_HOLDING_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let starting_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
        let quantity = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

impl ReadHoldingRegistersResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(RESPONSE_HEADER_LEN + self.register_values.len() * 2);
        buffer.push(FUNCTION_CODE_READ_HOLDING_REGISTERS);
        buffer.push((self.register_values.len() * 2) as u8);
        for value in &self.register_values {
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < RESPONSE_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_HOLDING_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let byte_count = bytes[BYTE_COUNT_BYTE];
        if !byte_count.is_multiple_of(2) {
            return Err(DecodeError::OddByteCount { byte_count });
        }
        if bytes.len() < REGISTER_VALUES_START + byte_count as usize {
            return Err(DecodeError::TooShort);
        }
        let register_values = bytes
            [REGISTER_VALUES_START..(REGISTER_VALUES_START + byte_count as usize)]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(Self { register_values })
    }
}

fn encode_write_single_register(register_address: u16, register_value: u16) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(TWO_FIELD_PDU_LEN);
    buffer.push(FUNCTION_CODE_WRITE_SINGLE_REGISTER);
    buffer.extend_from_slice(&register_address.to_be_bytes());
    buffer.extend_from_slice(&register_value.to_be_bytes());
    buffer
}

fn decode_write_single_register(bytes: &[u8]) -> Result<(u16, u16), DecodeError> {
    if bytes.len() < TWO_FIELD_PDU_LEN {
        return Err(DecodeError::TooShort);
    }
    if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_WRITE_SINGLE_REGISTER {
        return Err(DecodeError::UnexpectedFunctionCode {
            expected: FUNCTION_CODE_WRITE_SINGLE_REGISTER,
            actual: bytes[FUNCTION_CODE_BYTE],
        });
    }
    let register_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
    let register_value = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
    Ok((register_address, register_value))
}

impl WriteSingleRegisterRequest {
    pub fn encode(&self) -> Vec<u8> {
        encode_write_single_register(self.register_address, self.register_value)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (register_address, register_value) = decode_write_single_register(bytes)?;
        Ok(Self {
            register_address,
            register_value,
        })
    }
}

impl WriteSingleRegisterResponse {
    pub fn encode(&self) -> Vec<u8> {
        encode_write_single_register(self.register_address, self.register_value)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (register_address, register_value) = decode_write_single_register(bytes)?;
        Ok(Self {
            register_address,
            register_value,
        })
    }
}

impl WriteMultipleRegistersRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(
            WRITE_MULTIPLE_REGISTERS_REQUEST_HEADER_LEN + self.register_values.len() * 2,
        );
        buffer.push(FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS);
        buffer.extend_from_slice(&self.starting_address.to_be_bytes());
        let quantity = self.register_values.len() as u16;
        buffer.extend_from_slice(&quantity.to_be_bytes());
        buffer.push((self.register_values.len() * 2) as u8);
        for value in &self.register_values {
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < WRITE_MULTIPLE_REGISTERS_REQUEST_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let starting_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
        let byte_count = bytes[WRITE_MULTIPLE_REGISTERS_BYTE_COUNT_BYTE];
        if !byte_count.is_multiple_of(2) {
            return Err(DecodeError::OddByteCount { byte_count });
        }
        if bytes.len() < WRITE_MULTIPLE_REGISTERS_VALUES_START + byte_count as usize {
            return Err(DecodeError::TooShort);
        }
        let register_values = bytes[WRITE_MULTIPLE_REGISTERS_VALUES_START
            ..(WRITE_MULTIPLE_REGISTERS_VALUES_START + byte_count as usize)]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(Self {
            starting_address,
            register_values,
        })
    }
}

impl WriteMultipleRegistersResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(TWO_FIELD_PDU_LEN);
        buffer.push(FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS);
        buffer.extend_from_slice(&self.starting_address.to_be_bytes());
        buffer.extend_from_slice(&self.quantity.to_be_bytes());
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < TWO_FIELD_PDU_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let starting_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
        let quantity = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

impl ExceptionResponse {
    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.function_code | EXCEPTION_RESPONSE_FUNCTION_CODE_BIT,
            self.exception_code,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < EXCEPTION_RESPONSE_LEN {
            return Err(DecodeError::TooShort);
        }
        let raw_function_code = bytes[FUNCTION_CODE_BYTE];
        if raw_function_code & EXCEPTION_RESPONSE_FUNCTION_CODE_BIT == 0 {
            return Err(DecodeError::NotAnExceptionResponse {
                function_code: raw_function_code,
            });
        }
        let function_code = raw_function_code & !EXCEPTION_RESPONSE_FUNCTION_CODE_BIT;
        let exception_code = bytes[EXCEPTION_CODE_BYTE];
        Ok(Self {
            function_code,
            exception_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let request = ReadHoldingRegistersRequest {
            starting_address: 0x0001,
            quantity: 10,
        };
        let encoded = request.encode();
        let decoded = ReadHoldingRegistersRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn request_encode_produces_expected_bytes() {
        let request = ReadHoldingRegistersRequest {
            starting_address: 0x0001,
            quantity: 0x0002,
        };
        assert_eq!(request.encode(), vec![0x03, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn request_decode_rejects_too_short_buffer() {
        let bytes = [0x03, 0x00, 0x01, 0x00];
        assert_eq!(
            ReadHoldingRegistersRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn request_decode_rejects_wrong_function_code() {
        let bytes = [0x04, 0x00, 0x01, 0x00, 0x02];
        assert_eq!(
            ReadHoldingRegistersRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x03,
                actual: 0x04
            })
        );
    }

    #[test]
    fn response_round_trip() {
        let response = ReadHoldingRegistersResponse {
            register_values: vec![0x0001, 0xBEEF, 0x0000],
        };
        let encoded = response.encode();
        let decoded = ReadHoldingRegistersResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn response_encode_produces_expected_bytes() {
        let response = ReadHoldingRegistersResponse {
            register_values: vec![0x0001, 0x0002],
        };
        assert_eq!(response.encode(), vec![0x03, 0x04, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn response_decode_rejects_too_short_header() {
        let bytes = [0x03];
        assert_eq!(
            ReadHoldingRegistersResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn response_decode_rejects_declared_byte_count_exceeding_buffer() {
        let bytes = [0x03, 0x04, 0x00, 0x01];
        assert_eq!(
            ReadHoldingRegistersResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn response_decode_rejects_wrong_function_code() {
        let bytes = [0x04, 0x00];
        assert_eq!(
            ReadHoldingRegistersResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x03,
                actual: 0x04
            })
        );
    }

    #[test]
    fn response_decode_rejects_odd_byte_count() {
        let bytes = [0x03, 0x03, 0x00, 0x01, 0x00];
        assert_eq!(
            ReadHoldingRegistersResponse::decode(&bytes),
            Err(DecodeError::OddByteCount { byte_count: 3 })
        );
    }

    #[test]
    fn write_single_register_request_round_trip() {
        let request = WriteSingleRegisterRequest {
            register_address: 0x0001,
            register_value: 0x00FF,
        };
        let encoded = request.encode();
        let decoded = WriteSingleRegisterRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn write_single_register_request_encode_produces_expected_bytes() {
        let request = WriteSingleRegisterRequest {
            register_address: 0x0001,
            register_value: 0x00FF,
        };
        assert_eq!(request.encode(), vec![0x06, 0x00, 0x01, 0x00, 0xFF]);
    }

    #[test]
    fn write_single_register_request_decode_rejects_too_short_buffer() {
        let bytes = [0x06, 0x00, 0x01, 0x00];
        assert_eq!(
            WriteSingleRegisterRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_single_register_request_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x00, 0x01, 0x00, 0xFF];
        assert_eq!(
            WriteSingleRegisterRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x06,
                actual: 0x03
            })
        );
    }

    #[test]
    fn write_single_register_response_round_trip() {
        let response = WriteSingleRegisterResponse {
            register_address: 0x0001,
            register_value: 0x00FF,
        };
        let encoded = response.encode();
        let decoded = WriteSingleRegisterResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn write_single_register_response_encode_produces_expected_bytes() {
        let response = WriteSingleRegisterResponse {
            register_address: 0x0001,
            register_value: 0x00FF,
        };
        assert_eq!(response.encode(), vec![0x06, 0x00, 0x01, 0x00, 0xFF]);
    }

    #[test]
    fn write_single_register_response_decode_rejects_too_short_buffer() {
        let bytes = [0x06, 0x00, 0x01, 0x00];
        assert_eq!(
            WriteSingleRegisterResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_single_register_response_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x00, 0x01, 0x00, 0xFF];
        assert_eq!(
            WriteSingleRegisterResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x06,
                actual: 0x03
            })
        );
    }

    #[test]
    fn write_multiple_registers_request_round_trip() {
        let request = WriteMultipleRegistersRequest {
            starting_address: 0x0001,
            register_values: vec![0x000A, 0x0102],
        };
        let encoded = request.encode();
        let decoded = WriteMultipleRegistersRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn write_multiple_registers_request_encode_produces_expected_bytes() {
        let request = WriteMultipleRegistersRequest {
            starting_address: 0x0001,
            register_values: vec![0x000A, 0x0102],
        };
        assert_eq!(
            request.encode(),
            vec![0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02]
        );
    }

    #[test]
    fn write_multiple_registers_request_decode_rejects_too_short_header() {
        let bytes = [0x10, 0x00, 0x01, 0x00, 0x02];
        assert_eq!(
            WriteMultipleRegistersRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_multiple_registers_request_decode_rejects_declared_byte_count_exceeding_buffer() {
        let bytes = [0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A];
        assert_eq!(
            WriteMultipleRegistersRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_multiple_registers_request_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02];
        assert_eq!(
            WriteMultipleRegistersRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x10,
                actual: 0x03
            })
        );
    }

    #[test]
    fn write_multiple_registers_request_decode_rejects_odd_byte_count() {
        let bytes = [0x10, 0x00, 0x01, 0x00, 0x01, 0x03, 0x00];
        assert_eq!(
            WriteMultipleRegistersRequest::decode(&bytes),
            Err(DecodeError::OddByteCount { byte_count: 3 })
        );
    }

    #[test]
    fn write_multiple_registers_response_round_trip() {
        let response = WriteMultipleRegistersResponse {
            starting_address: 0x0001,
            quantity: 2,
        };
        let encoded = response.encode();
        let decoded = WriteMultipleRegistersResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn write_multiple_registers_response_encode_produces_expected_bytes() {
        let response = WriteMultipleRegistersResponse {
            starting_address: 0x0001,
            quantity: 2,
        };
        assert_eq!(response.encode(), vec![0x10, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn write_multiple_registers_response_decode_rejects_too_short_buffer() {
        let bytes = [0x10, 0x00, 0x01, 0x00];
        assert_eq!(
            WriteMultipleRegistersResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_multiple_registers_response_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x00, 0x01, 0x00, 0x02];
        assert_eq!(
            WriteMultipleRegistersResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x10,
                actual: 0x03
            })
        );
    }

    #[test]
    fn exception_response_round_trip() {
        let response = ExceptionResponse {
            function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
            exception_code: 0x02,
        };
        let encoded = response.encode();
        let decoded = ExceptionResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn exception_response_encode_produces_expected_bytes() {
        let response = ExceptionResponse {
            function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
            exception_code: 0x02,
        };
        assert_eq!(response.encode(), vec![0x83, 0x02]);
    }

    #[test]
    fn exception_response_decode_rejects_too_short_buffer() {
        let bytes = [0x83];
        assert_eq!(
            ExceptionResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn exception_response_decode_rejects_missing_exception_bit() {
        let bytes = [0x03, 0x02];
        assert_eq!(
            ExceptionResponse::decode(&bytes),
            Err(DecodeError::NotAnExceptionResponse {
                function_code: 0x03
            })
        );
    }
}
