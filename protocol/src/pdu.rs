use crate::{DecodeError, read_u16_be};

pub const FUNCTION_CODE_READ_COILS: u8 = 0x01;
pub const FUNCTION_CODE_READ_DISCRETE_INPUTS: u8 = 0x02;
pub const FUNCTION_CODE_WRITE_SINGLE_COIL: u8 = 0x05;
pub const FUNCTION_CODE_WRITE_MULTIPLE_COILS: u8 = 0x0F;
pub const FUNCTION_CODE_READ_HOLDING_REGISTERS: u8 = 0x03;
pub const FUNCTION_CODE_READ_INPUT_REGISTERS: u8 = 0x04;
pub const FUNCTION_CODE_WRITE_SINGLE_REGISTER: u8 = 0x06;
pub const FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS: u8 = 0x10;
pub const FUNCTION_CODE_MASK_WRITE_REGISTER: u8 = 0x16;
pub const FUNCTION_CODE_REPORT_SERVER_ID: u8 = 0x11;
pub const FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT: u8 = 0x2B;

// Function code 0x2B is itself a container for different "MEI" (Modbus
// Encapsulated Interface) sub-protocols; Read Device Identification is the
// only one this crate implements (CANopen, MEI type 0x0D, is the other
// standard one and isn't needed here).
pub const MEI_TYPE_READ_DEVICE_IDENTIFICATION: u8 = 0x0E;

// The four "Read Device ID code" values a Read Device Identification
// request can specify. Basic/Regular/Extended are stream access (read as
// many objects starting at a given object ID as fit in one response,
// following More-Follows continuation for the rest); Individual reads
// exactly one named object.
pub const READ_DEVICE_ID_BASIC: u8 = 0x01;
pub const READ_DEVICE_ID_REGULAR: u8 = 0x02;
pub const READ_DEVICE_ID_EXTENDED: u8 = 0x03;
pub const READ_DEVICE_ID_INDIVIDUAL: u8 = 0x04;

// Standard Modbus exception codes (Modbus Application Protocol V1.1b3,
// section 7) — a slave/server puts one of these in an ExceptionResponse's
// exception_code field to say why it's rejecting an otherwise
// well-formed-looking request.
pub const EXCEPTION_ILLEGAL_FUNCTION: u8 = 0x01;
pub const EXCEPTION_ILLEGAL_DATA_ADDRESS: u8 = 0x02;
pub const EXCEPTION_ILLEGAL_DATA_VALUE: u8 = 0x03;

const FUNCTION_CODE_BYTE: usize = 0;

// Byte 0 is always the function code, and every PDU in this family (Read Holding
// Registers request, Write Single Register request/response, Write Multiple
// Registers response) places an address field followed by a quantity-or-value
// field at these same fixed offsets, so one shared pair of offsets covers all of them.
const ADDRESS_FIELD_BYTE: usize = 1;
const QUANTITY_OR_VALUE_FIELD_BYTE: usize = 3;

// Length of any PDU that is just function code + two u16 fields (see above).
const TWO_FIELD_PDU_LEN: usize = 5;

// Mask Write Register (FC 0x16) reuses ADDRESS_FIELD_BYTE (reference
// address) and QUANTITY_OR_VALUE_FIELD_BYTE (and_mask) above, but has a
// third u16 field (or_mask) beyond what either of the other two-field PDUs
// carry, hence its own offset/length pair.
const OR_MASK_FIELD_BYTE: usize = 5;
const MASK_WRITE_REGISTER_PDU_LEN: usize = 7;

// Report Server ID's response reuses the same function-code(1) +
// byte-count(1) + payload shape as BYTE_COUNT_BYTE/RESPONSE_DATA_START
// above, but under its own name: that pair is documented as specific to a
// register/coil-address response, and Report Server ID's payload isn't
// address-shaped data at all (a vendor-specific byte string + a trailing
// run-indicator byte), so reusing the same constants would conflate two
// structurally different PDUs that just happen to share byte offsets 1/2.
const REPORT_SERVER_ID_BYTE_COUNT_BYTE: usize = 1;
const REPORT_SERVER_ID_DATA_START: usize = 2;
const REPORT_SERVER_ID_RESPONSE_HEADER_LEN: usize = 2;
const RUN_INDICATOR_ON: u8 = 0xFF;
const RUN_INDICATOR_OFF: u8 = 0x00;

const BYTE_COUNT_BYTE: usize = 1;
// Byte 2 is where the payload starts in any response shaped as
// function code (1) + byte count (1) + payload — true for Read Holding
// Registers and Read Coils alike, so this offset is structural, not
// register-specific, despite the "register" name it started with.
const RESPONSE_DATA_START: usize = 2;
const RESPONSE_HEADER_LEN: usize = 2;

// The two wire values Write Single Coil's value field is allowed to carry
// (Modbus Application Protocol V1.1b3, section 6.5) — any other u16 value
// is a malformed request/response, not just an unusual one.
const COIL_VALUE_ON: u16 = 0xFF00;
const COIL_VALUE_OFF: u16 = 0x0000;

// Header shape (function code + address + quantity + byte count) shared by
// both "write multiple" request PDUs (Write Multiple Registers, Write
// Multiple Coils) — structural, not coincidental: both families put an
// explicit byte count right before the values so a decoder can validate the
// payload length before reading it, only the value encoding after this
// point differs (2 bytes/value for registers, packed bits for coils).
const WRITE_MULTIPLE_BYTE_COUNT_BYTE: usize = 5;
const WRITE_MULTIPLE_VALUES_START: usize = 6;
const WRITE_MULTIPLE_REQUEST_HEADER_LEN: usize = 6;

// Modbus marks a response as an exception by setting the top bit of the
// (otherwise normal) function code byte; the original function code is
// recovered by clearing that bit again.
const EXCEPTION_RESPONSE_FUNCTION_CODE_BIT: u8 = 0x80;
const EXCEPTION_CODE_BYTE: usize = 1;
const EXCEPTION_RESPONSE_LEN: usize = 2;

const MEI_TYPE_BYTE: usize = 1;
const READ_DEVICE_ID_CODE_BYTE: usize = 2;

const REQUEST_OBJECT_ID_BYTE: usize = 3;
const READ_DEVICE_IDENTIFICATION_REQUEST_LEN: usize = 4;

const CONFORMITY_LEVEL_BYTE: usize = 3;
const MORE_FOLLOWS_BYTE: usize = 4;
const NEXT_OBJECT_ID_BYTE: usize = 5;
const NUMBER_OF_OBJECTS_BYTE: usize = 6;
const RESPONSE_OBJECTS_START: usize = 7;
const READ_DEVICE_IDENTIFICATION_RESPONSE_HEADER_LEN: usize = 7;

const MORE_FOLLOWS_YES: u8 = 0xFF;
const MORE_FOLLOWS_NO: u8 = 0x00;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCoilsRequest {
    pub starting_address: u16,
    pub quantity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDiscreteInputsRequest {
    pub starting_address: u16,
    pub quantity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadHoldingRegistersRequest {
    pub starting_address: u16,
    pub quantity: u16,
}

/// Same request shape as [`ReadHoldingRegistersRequest`] — Read Input
/// Registers is the read-only counterpart of Read Holding Registers,
/// distinguished only by function code and by addressing a separate
/// input-register space on the device (same relationship as
/// [`ReadDiscreteInputsRequest`] is to [`ReadCoilsRequest`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadInputRegistersRequest {
    pub starting_address: u16,
    pub quantity: u16,
}

/// Coil status bits, one `bool` per requested coil. The wire format packs
/// these 8-to-a-byte (first coil = LSB of the first byte) and always sends
/// a whole number of bytes, so a response whose coil count isn't a multiple
/// of 8 carries trailing zero-padding bits in its last byte; `decode`
/// exposes all `byte_count * 8` bits as-is (matching how
/// `ReadHoldingRegistersResponse` doesn't know the original request's
/// `quantity` either) — the caller trims to however many coils it actually
/// asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCoilsResponse {
    pub coil_values: Vec<bool>,
}

/// Same packed-bit wire shape and the same "caller trims to the requested
/// quantity" caveat as [`ReadCoilsResponse`] — Read Discrete Inputs is the
/// read-only counterpart of Read Coils, distinguished only by function code
/// and by addressing a separate discrete-input space on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDiscreteInputsResponse {
    pub discrete_input_values: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadHoldingRegistersResponse {
    pub register_values: Vec<u16>,
}

/// Same wire encoding as [`ReadHoldingRegistersResponse`] — see
/// [`ReadInputRegistersRequest`] for why this is a separate type rather
/// than a shared one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadInputRegistersResponse {
    pub register_values: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSingleCoilRequest {
    pub coil_address: u16,
    pub coil_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSingleCoilResponse {
    pub coil_address: u16,
    pub coil_value: bool,
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

/// Mask Write Register (Modbus Application Protocol V1.1b3, section 6.8):
/// applies `result = (current_contents AND and_mask) OR (or_mask AND (NOT
/// and_mask))` to a single register in place, rather than replacing its
/// contents outright. Request and response share this exact shape — a
/// successful response just echoes back the request unchanged, same pattern
/// as [`WriteSingleRegisterRequest`]/[`WriteSingleRegisterResponse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskWriteRegisterRequest {
    pub reference_address: u16,
    pub and_mask: u16,
    pub or_mask: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskWriteRegisterResponse {
    pub reference_address: u16,
    pub and_mask: u16,
    pub or_mask: u16,
}

/// Report Server ID (Modbus Application Protocol V1.1b3, section 6.11) —
/// the request carries no fields at all, just the function code byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportServerIdRequest;

/// `server_id`'s content is entirely vendor-specific per the spec (no
/// normative format) — kept as raw bytes rather than a `String` here, since
/// `protocol` has no business assuming it's valid UTF-8; whatever produced
/// it (see `server::handler`) is responsible for that. `run_indicator_status`
/// is `true` for "running" (wire value `0xFF`), `false` for "not running"
/// (wire value `0x00`) — any other wire value is out of spec but decoded as
/// `true`/non-zero rather than rejected, since a stray non-`0x00` value is
/// still unambiguously "not off".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportServerIdResponse {
    pub server_id: Vec<u8>,
    pub run_indicator_status: bool,
}

/// Same packed-bit wire encoding as [`ReadCoilsResponse`]/`WriteSingleCoil`'s
/// value field, but as a request payload: `coil_values.len()` doubles as the
/// wire's `quantity` field (mirrors how [`WriteMultipleRegistersRequest`]
/// derives its own `quantity` from `register_values.len()` instead of
/// storing it separately, so the two can't disagree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteMultipleCoilsRequest {
    pub starting_address: u16,
    pub coil_values: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteMultipleCoilsResponse {
    pub starting_address: u16,
    pub quantity: u16,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDeviceIdentificationRequest {
    pub read_device_id_code: u8,
    /// Where to start a stream-access read (codes 1-3) — `0x00` for a
    /// fresh read, or the previous response's `next_object_id` to
    /// continue one that had `more_follows`. For individual access
    /// (code 4), this names the one object being requested.
    pub object_id: u8,
}

/// One `id`/`value` pair from a Read Device Identification response.
/// `value` is arbitrary bytes (conventionally ASCII text) up to 255 bytes
/// long — the object model's own length byte is what caps it, not
/// anything we impose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentificationObject {
    pub id: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDeviceIdentificationResponse {
    pub read_device_id_code: u8,
    pub conformity_level: u8,
    /// `true` if the full requested object range didn't fit in this one
    /// response — the requester should issue another request with
    /// `object_id` set to `next_object_id` to continue.
    pub more_follows: bool,
    pub next_object_id: u8,
    pub objects: Vec<DeviceIdentificationObject>,
}

impl ReadCoilsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(TWO_FIELD_PDU_LEN);
        buffer.push(FUNCTION_CODE_READ_COILS);
        buffer.extend_from_slice(&self.starting_address.to_be_bytes());
        buffer.extend_from_slice(&self.quantity.to_be_bytes());
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < TWO_FIELD_PDU_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_COILS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_COILS,
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

impl ReadDiscreteInputsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(TWO_FIELD_PDU_LEN);
        buffer.push(FUNCTION_CODE_READ_DISCRETE_INPUTS);
        buffer.extend_from_slice(&self.starting_address.to_be_bytes());
        buffer.extend_from_slice(&self.quantity.to_be_bytes());
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < TWO_FIELD_PDU_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_DISCRETE_INPUTS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_DISCRETE_INPUTS,
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

impl ReadInputRegistersRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(TWO_FIELD_PDU_LEN);
        buffer.push(FUNCTION_CODE_READ_INPUT_REGISTERS);
        buffer.extend_from_slice(&self.starting_address.to_be_bytes());
        buffer.extend_from_slice(&self.quantity.to_be_bytes());
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < TWO_FIELD_PDU_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_INPUT_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_INPUT_REGISTERS,
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

impl ReadCoilsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let byte_count = self.coil_values.len().div_ceil(8);
        let mut buffer = vec![0u8; RESPONSE_HEADER_LEN + byte_count];
        buffer[FUNCTION_CODE_BYTE] = FUNCTION_CODE_READ_COILS;
        buffer[BYTE_COUNT_BYTE] = byte_count as u8;
        for (index, &coil_value) in self.coil_values.iter().enumerate() {
            if coil_value {
                buffer[RESPONSE_DATA_START + index / 8] |= 1 << (index % 8);
            }
        }
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < RESPONSE_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_COILS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_COILS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let byte_count = bytes[BYTE_COUNT_BYTE] as usize;
        if bytes.len() < RESPONSE_DATA_START + byte_count {
            return Err(DecodeError::TooShort);
        }
        let coil_values = bytes[RESPONSE_DATA_START..(RESPONSE_DATA_START + byte_count)]
            .iter()
            .flat_map(|&byte| (0..8).map(move |bit| byte & (1 << bit) != 0))
            .collect();
        Ok(Self { coil_values })
    }
}

impl ReadDiscreteInputsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let byte_count = self.discrete_input_values.len().div_ceil(8);
        let mut buffer = vec![0u8; RESPONSE_HEADER_LEN + byte_count];
        buffer[FUNCTION_CODE_BYTE] = FUNCTION_CODE_READ_DISCRETE_INPUTS;
        buffer[BYTE_COUNT_BYTE] = byte_count as u8;
        for (index, &discrete_input_value) in self.discrete_input_values.iter().enumerate() {
            if discrete_input_value {
                buffer[RESPONSE_DATA_START + index / 8] |= 1 << (index % 8);
            }
        }
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < RESPONSE_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_DISCRETE_INPUTS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_DISCRETE_INPUTS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let byte_count = bytes[BYTE_COUNT_BYTE] as usize;
        if bytes.len() < RESPONSE_DATA_START + byte_count {
            return Err(DecodeError::TooShort);
        }
        let discrete_input_values = bytes[RESPONSE_DATA_START..(RESPONSE_DATA_START + byte_count)]
            .iter()
            .flat_map(|&byte| (0..8).map(move |bit| byte & (1 << bit) != 0))
            .collect();
        Ok(Self {
            discrete_input_values,
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
        if bytes.len() < RESPONSE_DATA_START + byte_count as usize {
            return Err(DecodeError::TooShort);
        }
        let register_values = bytes
            [RESPONSE_DATA_START..(RESPONSE_DATA_START + byte_count as usize)]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(Self { register_values })
    }
}

impl ReadInputRegistersResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(RESPONSE_HEADER_LEN + self.register_values.len() * 2);
        buffer.push(FUNCTION_CODE_READ_INPUT_REGISTERS);
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
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_INPUT_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_INPUT_REGISTERS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let byte_count = bytes[BYTE_COUNT_BYTE];
        if !byte_count.is_multiple_of(2) {
            return Err(DecodeError::OddByteCount { byte_count });
        }
        if bytes.len() < RESPONSE_DATA_START + byte_count as usize {
            return Err(DecodeError::TooShort);
        }
        let register_values = bytes
            [RESPONSE_DATA_START..(RESPONSE_DATA_START + byte_count as usize)]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(Self { register_values })
    }
}

fn encode_write_single_coil(coil_address: u16, coil_value: bool) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(TWO_FIELD_PDU_LEN);
    buffer.push(FUNCTION_CODE_WRITE_SINGLE_COIL);
    buffer.extend_from_slice(&coil_address.to_be_bytes());
    let wire_value = if coil_value {
        COIL_VALUE_ON
    } else {
        COIL_VALUE_OFF
    };
    buffer.extend_from_slice(&wire_value.to_be_bytes());
    buffer
}

fn decode_write_single_coil(bytes: &[u8]) -> Result<(u16, bool), DecodeError> {
    if bytes.len() < TWO_FIELD_PDU_LEN {
        return Err(DecodeError::TooShort);
    }
    if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_WRITE_SINGLE_COIL {
        return Err(DecodeError::UnexpectedFunctionCode {
            expected: FUNCTION_CODE_WRITE_SINGLE_COIL,
            actual: bytes[FUNCTION_CODE_BYTE],
        });
    }
    let coil_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
    let wire_value = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
    let coil_value = match wire_value {
        COIL_VALUE_ON => true,
        COIL_VALUE_OFF => false,
        actual => return Err(DecodeError::InvalidCoilValue { actual }),
    };
    Ok((coil_address, coil_value))
}

impl WriteSingleCoilRequest {
    pub fn encode(&self) -> Vec<u8> {
        encode_write_single_coil(self.coil_address, self.coil_value)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (coil_address, coil_value) = decode_write_single_coil(bytes)?;
        Ok(Self {
            coil_address,
            coil_value,
        })
    }
}

impl WriteSingleCoilResponse {
    pub fn encode(&self) -> Vec<u8> {
        encode_write_single_coil(self.coil_address, self.coil_value)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (coil_address, coil_value) = decode_write_single_coil(bytes)?;
        Ok(Self {
            coil_address,
            coil_value,
        })
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

fn encode_mask_write_register(reference_address: u16, and_mask: u16, or_mask: u16) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(MASK_WRITE_REGISTER_PDU_LEN);
    buffer.push(FUNCTION_CODE_MASK_WRITE_REGISTER);
    buffer.extend_from_slice(&reference_address.to_be_bytes());
    buffer.extend_from_slice(&and_mask.to_be_bytes());
    buffer.extend_from_slice(&or_mask.to_be_bytes());
    buffer
}

fn decode_mask_write_register(bytes: &[u8]) -> Result<(u16, u16, u16), DecodeError> {
    if bytes.len() < MASK_WRITE_REGISTER_PDU_LEN {
        return Err(DecodeError::TooShort);
    }
    if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_MASK_WRITE_REGISTER {
        return Err(DecodeError::UnexpectedFunctionCode {
            expected: FUNCTION_CODE_MASK_WRITE_REGISTER,
            actual: bytes[FUNCTION_CODE_BYTE],
        });
    }
    let reference_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
    let and_mask = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
    let or_mask = read_u16_be(bytes, OR_MASK_FIELD_BYTE);
    Ok((reference_address, and_mask, or_mask))
}

impl MaskWriteRegisterRequest {
    pub fn encode(&self) -> Vec<u8> {
        encode_mask_write_register(self.reference_address, self.and_mask, self.or_mask)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (reference_address, and_mask, or_mask) = decode_mask_write_register(bytes)?;
        Ok(Self {
            reference_address,
            and_mask,
            or_mask,
        })
    }
}

impl MaskWriteRegisterResponse {
    pub fn encode(&self) -> Vec<u8> {
        encode_mask_write_register(self.reference_address, self.and_mask, self.or_mask)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (reference_address, and_mask, or_mask) = decode_mask_write_register(bytes)?;
        Ok(Self {
            reference_address,
            and_mask,
            or_mask,
        })
    }
}

impl ReportServerIdRequest {
    pub fn encode(&self) -> Vec<u8> {
        vec![FUNCTION_CODE_REPORT_SERVER_ID]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let Some(&function_code) = bytes.first() else {
            return Err(DecodeError::TooShort);
        };
        if function_code != FUNCTION_CODE_REPORT_SERVER_ID {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_REPORT_SERVER_ID,
                actual: function_code,
            });
        }
        Ok(Self)
    }
}

impl ReportServerIdResponse {
    pub fn encode(&self) -> Vec<u8> {
        // +1 for the trailing run_indicator_status byte, which byte_count
        // covers alongside server_id (Modbus Application Protocol V1.1b3,
        // section 6.11's own worked example).
        let byte_count = self.server_id.len() + 1;
        let mut buffer = Vec::with_capacity(REPORT_SERVER_ID_RESPONSE_HEADER_LEN + byte_count);
        buffer.push(FUNCTION_CODE_REPORT_SERVER_ID);
        buffer.push(byte_count as u8);
        buffer.extend_from_slice(&self.server_id);
        buffer.push(if self.run_indicator_status {
            RUN_INDICATOR_ON
        } else {
            RUN_INDICATOR_OFF
        });
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < REPORT_SERVER_ID_RESPONSE_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_REPORT_SERVER_ID {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_REPORT_SERVER_ID,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let byte_count = bytes[REPORT_SERVER_ID_BYTE_COUNT_BYTE] as usize;
        // byte_count must cover at least the trailing run_indicator_status
        // byte — a claimed 0 has nowhere for it to live.
        if byte_count == 0 {
            return Err(DecodeError::TooShort);
        }
        if bytes.len() < REPORT_SERVER_ID_DATA_START + byte_count {
            return Err(DecodeError::TooShort);
        }
        let server_id_end = REPORT_SERVER_ID_DATA_START + byte_count - 1;
        let server_id = bytes[REPORT_SERVER_ID_DATA_START..server_id_end].to_vec();
        let run_indicator_status = bytes[server_id_end] != RUN_INDICATOR_OFF;
        Ok(Self {
            server_id,
            run_indicator_status,
        })
    }
}

impl WriteMultipleCoilsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let byte_count = self.coil_values.len().div_ceil(8);
        let mut buffer = vec![0u8; WRITE_MULTIPLE_REQUEST_HEADER_LEN + byte_count];
        buffer[FUNCTION_CODE_BYTE] = FUNCTION_CODE_WRITE_MULTIPLE_COILS;
        buffer[ADDRESS_FIELD_BYTE..ADDRESS_FIELD_BYTE + 2]
            .copy_from_slice(&self.starting_address.to_be_bytes());
        let quantity = self.coil_values.len() as u16;
        buffer[QUANTITY_OR_VALUE_FIELD_BYTE..QUANTITY_OR_VALUE_FIELD_BYTE + 2]
            .copy_from_slice(&quantity.to_be_bytes());
        buffer[WRITE_MULTIPLE_BYTE_COUNT_BYTE] = byte_count as u8;
        for (index, &coil_value) in self.coil_values.iter().enumerate() {
            if coil_value {
                buffer[WRITE_MULTIPLE_VALUES_START + index / 8] |= 1 << (index % 8);
            }
        }
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < WRITE_MULTIPLE_REQUEST_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_WRITE_MULTIPLE_COILS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_WRITE_MULTIPLE_COILS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let starting_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
        let quantity = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
        let byte_count = bytes[WRITE_MULTIPLE_BYTE_COUNT_BYTE];
        // Unlike registers (2 wire bytes per value, so byte_count alone
        // pins down the exact count), coils are packed 8-to-a-byte: any
        // quantity from (byte_count-1)*8+1 up to byte_count*8 encodes to
        // the same byte_count, with the rest of the last byte as
        // meaningless padding. The wire's own quantity field is the only
        // way to know how many of those bits are real, so it must agree
        // with byte_count exactly (per spec, byte_count = ceil(quantity /
        // 8)) rather than being ignored in favor of just trusting
        // byte_count and exposing padding bits as if they were real data.
        if byte_count as usize != (quantity as usize).div_ceil(8) {
            return Err(DecodeError::QuantityByteCountMismatch {
                quantity,
                byte_count,
            });
        }
        let byte_count = byte_count as usize;
        if bytes.len() < WRITE_MULTIPLE_VALUES_START + byte_count {
            return Err(DecodeError::TooShort);
        }
        let coil_values = bytes
            [WRITE_MULTIPLE_VALUES_START..(WRITE_MULTIPLE_VALUES_START + byte_count)]
            .iter()
            .flat_map(|&byte| (0..8).map(move |bit| byte & (1 << bit) != 0))
            .take(quantity as usize)
            .collect();
        Ok(Self {
            starting_address,
            coil_values,
        })
    }
}

impl WriteMultipleCoilsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(TWO_FIELD_PDU_LEN);
        buffer.push(FUNCTION_CODE_WRITE_MULTIPLE_COILS);
        buffer.extend_from_slice(&self.starting_address.to_be_bytes());
        buffer.extend_from_slice(&self.quantity.to_be_bytes());
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < TWO_FIELD_PDU_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_WRITE_MULTIPLE_COILS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_WRITE_MULTIPLE_COILS,
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

impl WriteMultipleRegistersRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer =
            Vec::with_capacity(WRITE_MULTIPLE_REQUEST_HEADER_LEN + self.register_values.len() * 2);
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
        if bytes.len() < WRITE_MULTIPLE_REQUEST_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let starting_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
        let byte_count = bytes[WRITE_MULTIPLE_BYTE_COUNT_BYTE];
        if !byte_count.is_multiple_of(2) {
            return Err(DecodeError::OddByteCount { byte_count });
        }
        if bytes.len() < WRITE_MULTIPLE_VALUES_START + byte_count as usize {
            return Err(DecodeError::TooShort);
        }
        let register_values = bytes
            [WRITE_MULTIPLE_VALUES_START..(WRITE_MULTIPLE_VALUES_START + byte_count as usize)]
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

impl ReadDeviceIdentificationRequest {
    pub fn encode(&self) -> Vec<u8> {
        vec![
            FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
            MEI_TYPE_READ_DEVICE_IDENTIFICATION,
            self.read_device_id_code,
            self.object_id,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < READ_DEVICE_IDENTIFICATION_REQUEST_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        if bytes[MEI_TYPE_BYTE] != MEI_TYPE_READ_DEVICE_IDENTIFICATION {
            return Err(DecodeError::UnexpectedMeiType {
                expected: MEI_TYPE_READ_DEVICE_IDENTIFICATION,
                actual: bytes[MEI_TYPE_BYTE],
            });
        }
        Ok(Self {
            read_device_id_code: bytes[READ_DEVICE_ID_CODE_BYTE],
            object_id: bytes[REQUEST_OBJECT_ID_BYTE],
        })
    }
}

impl ReadDeviceIdentificationResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(
            RESPONSE_OBJECTS_START
                + self
                    .objects
                    .iter()
                    .map(|object| 2 + object.value.len())
                    .sum::<usize>(),
        );
        buffer.push(FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT);
        buffer.push(MEI_TYPE_READ_DEVICE_IDENTIFICATION);
        buffer.push(self.read_device_id_code);
        buffer.push(self.conformity_level);
        buffer.push(if self.more_follows {
            MORE_FOLLOWS_YES
        } else {
            MORE_FOLLOWS_NO
        });
        buffer.push(self.next_object_id);
        buffer.push(self.objects.len() as u8);
        for object in &self.objects {
            buffer.push(object.id);
            buffer.push(object.value.len() as u8);
            buffer.extend_from_slice(&object.value);
        }
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < READ_DEVICE_IDENTIFICATION_RESPONSE_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        if bytes[MEI_TYPE_BYTE] != MEI_TYPE_READ_DEVICE_IDENTIFICATION {
            return Err(DecodeError::UnexpectedMeiType {
                expected: MEI_TYPE_READ_DEVICE_IDENTIFICATION,
                actual: bytes[MEI_TYPE_BYTE],
            });
        }

        let read_device_id_code = bytes[READ_DEVICE_ID_CODE_BYTE];
        let conformity_level = bytes[CONFORMITY_LEVEL_BYTE];
        let more_follows = bytes[MORE_FOLLOWS_BYTE] != MORE_FOLLOWS_NO;
        let next_object_id = bytes[NEXT_OBJECT_ID_BYTE];
        let number_of_objects = bytes[NUMBER_OF_OBJECTS_BYTE];

        // Each object's own length byte is untrusted peer input — checked
        // against the actual remaining buffer before every read, the same
        // "validate before allocating/reading" discipline used elsewhere
        // in this crate, not just a single upfront bounds check.
        let mut objects = Vec::with_capacity(number_of_objects as usize);
        let mut offset = RESPONSE_OBJECTS_START;
        for _ in 0..number_of_objects {
            if bytes.len() < offset + 2 {
                return Err(DecodeError::TooShort);
            }
            let id = bytes[offset];
            let length = bytes[offset + 1] as usize;
            let value_start = offset + 2;
            if bytes.len() < value_start + length {
                return Err(DecodeError::TooShort);
            }
            objects.push(DeviceIdentificationObject {
                id,
                value: bytes[value_start..value_start + length].to_vec(),
            });
            offset = value_start + length;
        }

        Ok(Self {
            read_device_id_code,
            conformity_level,
            more_follows,
            next_object_id,
            objects,
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
    fn read_coils_request_round_trip() {
        let request = ReadCoilsRequest {
            starting_address: 0x0001,
            quantity: 10,
        };
        let encoded = request.encode();
        let decoded = ReadCoilsRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn read_coils_request_encode_produces_expected_bytes() {
        let request = ReadCoilsRequest {
            starting_address: 0x0001,
            quantity: 0x0002,
        };
        assert_eq!(request.encode(), vec![0x01, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn read_coils_request_decode_rejects_too_short_buffer() {
        let bytes = [0x01, 0x00, 0x01, 0x00];
        assert_eq!(ReadCoilsRequest::decode(&bytes), Err(DecodeError::TooShort));
    }

    #[test]
    fn read_coils_request_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x00, 0x01, 0x00, 0x02];
        assert_eq!(
            ReadCoilsRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x01,
                actual: 0x03
            })
        );
    }

    #[test]
    fn read_coils_response_round_trip() {
        // 10 coils, not a multiple of 8, so the last byte carries padding
        // bits that must survive the round trip unchanged.
        let response = ReadCoilsResponse {
            coil_values: vec![
                true, false, true, true, false, false, false, true, true, false, false, false,
                false, false, false, false,
            ],
        };
        let encoded = response.encode();
        let decoded = ReadCoilsResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn read_coils_response_encode_produces_expected_bytes() {
        let response = ReadCoilsResponse {
            coil_values: vec![true, false, true, true, false, false, false, true],
        };
        assert_eq!(response.encode(), vec![0x01, 0x01, 0x8D]);
    }

    #[test]
    fn read_coils_response_decode_rejects_too_short_header() {
        let bytes = [0x01];
        assert_eq!(
            ReadCoilsResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_coils_response_decode_rejects_declared_byte_count_exceeding_buffer() {
        let bytes = [0x01, 0x02, 0x8D];
        assert_eq!(
            ReadCoilsResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_coils_response_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x01, 0x8D];
        assert_eq!(
            ReadCoilsResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x01,
                actual: 0x03
            })
        );
    }

    #[test]
    fn read_discrete_inputs_request_round_trip() {
        let request = ReadDiscreteInputsRequest {
            starting_address: 0x0001,
            quantity: 10,
        };
        let encoded = request.encode();
        let decoded = ReadDiscreteInputsRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn read_discrete_inputs_request_encode_produces_expected_bytes() {
        let request = ReadDiscreteInputsRequest {
            starting_address: 0x0001,
            quantity: 0x0002,
        };
        assert_eq!(request.encode(), vec![0x02, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn read_discrete_inputs_request_decode_rejects_too_short_buffer() {
        let bytes = [0x02, 0x00, 0x01, 0x00];
        assert_eq!(
            ReadDiscreteInputsRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_discrete_inputs_request_decode_rejects_wrong_function_code() {
        let bytes = [0x01, 0x00, 0x01, 0x00, 0x02];
        assert_eq!(
            ReadDiscreteInputsRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x02,
                actual: 0x01
            })
        );
    }

    #[test]
    fn read_discrete_inputs_response_round_trip() {
        let response = ReadDiscreteInputsResponse {
            discrete_input_values: vec![
                true, false, true, true, false, false, false, true, true, false, false, false,
                false, false, false, false,
            ],
        };
        let encoded = response.encode();
        let decoded = ReadDiscreteInputsResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn read_discrete_inputs_response_encode_produces_expected_bytes() {
        let response = ReadDiscreteInputsResponse {
            discrete_input_values: vec![true, false, true, true, false, false, false, true],
        };
        assert_eq!(response.encode(), vec![0x02, 0x01, 0x8D]);
    }

    #[test]
    fn read_discrete_inputs_response_decode_rejects_too_short_header() {
        let bytes = [0x02];
        assert_eq!(
            ReadDiscreteInputsResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_discrete_inputs_response_decode_rejects_declared_byte_count_exceeding_buffer() {
        let bytes = [0x02, 0x02, 0x8D];
        assert_eq!(
            ReadDiscreteInputsResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_discrete_inputs_response_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x01, 0x8D];
        assert_eq!(
            ReadDiscreteInputsResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x02,
                actual: 0x03
            })
        );
    }

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
    fn read_input_registers_request_round_trip() {
        let request = ReadInputRegistersRequest {
            starting_address: 0x0001,
            quantity: 10,
        };
        let encoded = request.encode();
        let decoded = ReadInputRegistersRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn read_input_registers_request_encode_produces_expected_bytes() {
        let request = ReadInputRegistersRequest {
            starting_address: 0x0001,
            quantity: 0x0002,
        };
        assert_eq!(request.encode(), vec![0x04, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn read_input_registers_request_decode_rejects_too_short_buffer() {
        let bytes = [0x04, 0x00, 0x01, 0x00];
        assert_eq!(
            ReadInputRegistersRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_input_registers_request_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x00, 0x01, 0x00, 0x02];
        assert_eq!(
            ReadInputRegistersRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x04,
                actual: 0x03
            })
        );
    }

    #[test]
    fn read_input_registers_response_round_trip() {
        let response = ReadInputRegistersResponse {
            register_values: vec![0x0001, 0xBEEF, 0x0000],
        };
        let encoded = response.encode();
        let decoded = ReadInputRegistersResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn read_input_registers_response_encode_produces_expected_bytes() {
        let response = ReadInputRegistersResponse {
            register_values: vec![0x0001, 0x0002],
        };
        assert_eq!(response.encode(), vec![0x04, 0x04, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn read_input_registers_response_decode_rejects_too_short_header() {
        let bytes = [0x04];
        assert_eq!(
            ReadInputRegistersResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_input_registers_response_decode_rejects_declared_byte_count_exceeding_buffer() {
        let bytes = [0x04, 0x04, 0x00, 0x01];
        assert_eq!(
            ReadInputRegistersResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_input_registers_response_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x00];
        assert_eq!(
            ReadInputRegistersResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x04,
                actual: 0x03
            })
        );
    }

    #[test]
    fn read_input_registers_response_decode_rejects_odd_byte_count() {
        let bytes = [0x04, 0x03, 0x00, 0x01, 0x00];
        assert_eq!(
            ReadInputRegistersResponse::decode(&bytes),
            Err(DecodeError::OddByteCount { byte_count: 3 })
        );
    }

    #[test]
    fn write_single_coil_request_round_trip() {
        let request = WriteSingleCoilRequest {
            coil_address: 0x0001,
            coil_value: true,
        };
        let encoded = request.encode();
        let decoded = WriteSingleCoilRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn write_single_coil_request_encode_produces_expected_bytes() {
        let request = WriteSingleCoilRequest {
            coil_address: 0x0001,
            coil_value: true,
        };
        assert_eq!(request.encode(), vec![0x05, 0x00, 0x01, 0xFF, 0x00]);

        let request_off = WriteSingleCoilRequest {
            coil_address: 0x0001,
            coil_value: false,
        };
        assert_eq!(request_off.encode(), vec![0x05, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn write_single_coil_request_decode_rejects_too_short_buffer() {
        let bytes = [0x05, 0x00, 0x01, 0xFF];
        assert_eq!(
            WriteSingleCoilRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_single_coil_request_decode_rejects_wrong_function_code() {
        let bytes = [0x06, 0x00, 0x01, 0xFF, 0x00];
        assert_eq!(
            WriteSingleCoilRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x05,
                actual: 0x06
            })
        );
    }

    #[test]
    fn write_single_coil_request_decode_rejects_invalid_coil_value() {
        let bytes = [0x05, 0x00, 0x01, 0x12, 0x34];
        assert_eq!(
            WriteSingleCoilRequest::decode(&bytes),
            Err(DecodeError::InvalidCoilValue { actual: 0x1234 })
        );
    }

    #[test]
    fn write_single_coil_response_round_trip() {
        let response = WriteSingleCoilResponse {
            coil_address: 0x0001,
            coil_value: true,
        };
        let encoded = response.encode();
        let decoded = WriteSingleCoilResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn write_single_coil_response_encode_produces_expected_bytes() {
        let response = WriteSingleCoilResponse {
            coil_address: 0x0001,
            coil_value: true,
        };
        assert_eq!(response.encode(), vec![0x05, 0x00, 0x01, 0xFF, 0x00]);
    }

    #[test]
    fn write_single_coil_response_decode_rejects_too_short_buffer() {
        let bytes = [0x05, 0x00, 0x01, 0xFF];
        assert_eq!(
            WriteSingleCoilResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_single_coil_response_decode_rejects_wrong_function_code() {
        let bytes = [0x06, 0x00, 0x01, 0xFF, 0x00];
        assert_eq!(
            WriteSingleCoilResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x05,
                actual: 0x06
            })
        );
    }

    #[test]
    fn write_single_coil_response_decode_rejects_invalid_coil_value() {
        let bytes = [0x05, 0x00, 0x01, 0x12, 0x34];
        assert_eq!(
            WriteSingleCoilResponse::decode(&bytes),
            Err(DecodeError::InvalidCoilValue { actual: 0x1234 })
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
    fn mask_write_register_request_round_trip() {
        let request = MaskWriteRegisterRequest {
            reference_address: 0x0004,
            and_mask: 0x00F2,
            or_mask: 0x0025,
        };
        let encoded = request.encode();
        let decoded = MaskWriteRegisterRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn mask_write_register_request_encode_produces_expected_bytes() {
        let request = MaskWriteRegisterRequest {
            reference_address: 0x0004,
            and_mask: 0x00F2,
            or_mask: 0x0025,
        };
        assert_eq!(
            request.encode(),
            vec![0x16, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25]
        );
    }

    #[test]
    fn mask_write_register_request_decode_rejects_too_short_buffer() {
        let bytes = [0x16, 0x00, 0x04, 0x00, 0xF2, 0x00];
        assert_eq!(
            MaskWriteRegisterRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn mask_write_register_request_decode_rejects_wrong_function_code() {
        let bytes = [0x06, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25];
        assert_eq!(
            MaskWriteRegisterRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x16,
                actual: 0x06
            })
        );
    }

    #[test]
    fn mask_write_register_response_round_trip() {
        let response = MaskWriteRegisterResponse {
            reference_address: 0x0004,
            and_mask: 0x00F2,
            or_mask: 0x0025,
        };
        let encoded = response.encode();
        let decoded = MaskWriteRegisterResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn mask_write_register_response_encode_produces_expected_bytes() {
        let response = MaskWriteRegisterResponse {
            reference_address: 0x0004,
            and_mask: 0x00F2,
            or_mask: 0x0025,
        };
        assert_eq!(
            response.encode(),
            vec![0x16, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25]
        );
    }

    #[test]
    fn mask_write_register_response_decode_rejects_too_short_buffer() {
        let bytes = [0x16, 0x00, 0x04, 0x00, 0xF2, 0x00];
        assert_eq!(
            MaskWriteRegisterResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn mask_write_register_response_decode_rejects_wrong_function_code() {
        let bytes = [0x06, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25];
        assert_eq!(
            MaskWriteRegisterResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x16,
                actual: 0x06
            })
        );
    }

    #[test]
    fn report_server_id_request_round_trip() {
        let request = ReportServerIdRequest;
        let encoded = request.encode();
        let decoded = ReportServerIdRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn report_server_id_request_encode_produces_expected_bytes() {
        assert_eq!(ReportServerIdRequest.encode(), vec![0x11]);
    }

    #[test]
    fn report_server_id_request_decode_rejects_empty_buffer() {
        assert_eq!(
            ReportServerIdRequest::decode(&[]),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn report_server_id_request_decode_rejects_wrong_function_code() {
        assert_eq!(
            ReportServerIdRequest::decode(&[0x06]),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x11,
                actual: 0x06
            })
        );
    }

    #[test]
    fn report_server_id_response_round_trip() {
        let response = ReportServerIdResponse {
            server_id: b"infused_modbus".to_vec(),
            run_indicator_status: true,
        };
        let encoded = response.encode();
        let decoded = ReportServerIdResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn report_server_id_response_encode_produces_expected_bytes() {
        let response = ReportServerIdResponse {
            server_id: vec![0x41, 0x42],
            run_indicator_status: true,
        };
        // function code, byte_count (2 id bytes + 1 run indicator = 3), id
        // bytes, run indicator (0xFF = ON).
        assert_eq!(response.encode(), vec![0x11, 0x03, 0x41, 0x42, 0xFF]);
    }

    #[test]
    fn report_server_id_response_encode_of_an_empty_server_id() {
        let response = ReportServerIdResponse {
            server_id: vec![],
            run_indicator_status: false,
        };
        assert_eq!(response.encode(), vec![0x11, 0x01, 0x00]);
    }

    #[test]
    fn report_server_id_response_decode_reads_the_run_indicator_status() {
        let bytes = [0x11, 0x03, 0x41, 0x42, 0x00];
        assert_eq!(
            ReportServerIdResponse::decode(&bytes).unwrap(),
            ReportServerIdResponse {
                server_id: vec![0x41, 0x42],
                run_indicator_status: false,
            }
        );
    }

    #[test]
    fn report_server_id_response_decode_rejects_too_short_buffer() {
        assert_eq!(
            ReportServerIdResponse::decode(&[0x11]),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn report_server_id_response_decode_rejects_a_byte_count_claiming_more_than_the_buffer_holds() {
        // byte_count says 10, but only 2 bytes actually follow — must be
        // rejected before slicing, not read out-of-bounds or truncated
        // silently.
        let bytes = [0x11, 0x0A, 0x41, 0x42];
        assert_eq!(
            ReportServerIdResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn report_server_id_response_decode_rejects_a_zero_byte_count() {
        let bytes = [0x11, 0x00];
        assert_eq!(
            ReportServerIdResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn report_server_id_response_decode_rejects_wrong_function_code() {
        let bytes = [0x06, 0x03, 0x41, 0x42, 0xFF];
        assert_eq!(
            ReportServerIdResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x11,
                actual: 0x06
            })
        );
    }

    #[test]
    fn write_multiple_coils_request_round_trip() {
        // 9 coils, not a multiple of 8 — decode must trim the last byte's
        // padding bits back off using the wire's own quantity field,
        // rather than exposing all 16 raw bits from byte_count.
        let request = WriteMultipleCoilsRequest {
            starting_address: 0x0013,
            coil_values: vec![true, false, true, true, false, false, false, true, true],
        };
        let encoded = request.encode();
        let decoded = WriteMultipleCoilsRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn write_multiple_coils_request_decode_rejects_quantity_byte_count_mismatch() {
        // quantity = 9 (needs byte_count 2) but byte_count claims 3 —
        // decode must not silently trust byte_count and expose an extra,
        // meaningless byte of "coil" data.
        let bytes = [0x0F, 0x00, 0x13, 0x00, 0x09, 0x03, 0x8D, 0x01, 0x00];
        assert_eq!(
            WriteMultipleCoilsRequest::decode(&bytes),
            Err(DecodeError::QuantityByteCountMismatch {
                quantity: 9,
                byte_count: 3
            })
        );
    }

    #[test]
    fn write_multiple_coils_request_encode_produces_expected_bytes() {
        let request = WriteMultipleCoilsRequest {
            starting_address: 0x0013,
            coil_values: vec![true, false, true, true, false, false, false, true, true],
        };
        assert_eq!(
            request.encode(),
            vec![0x0F, 0x00, 0x13, 0x00, 0x09, 0x02, 0x8D, 0x01]
        );
    }

    #[test]
    fn write_multiple_coils_request_decode_rejects_too_short_header() {
        let bytes = [0x0F, 0x00, 0x13, 0x00, 0x09];
        assert_eq!(
            WriteMultipleCoilsRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_multiple_coils_request_decode_rejects_declared_byte_count_exceeding_buffer() {
        let bytes = [0x0F, 0x00, 0x13, 0x00, 0x09, 0x02, 0x8D];
        assert_eq!(
            WriteMultipleCoilsRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_multiple_coils_request_decode_rejects_wrong_function_code() {
        let bytes = [0x10, 0x00, 0x13, 0x00, 0x09, 0x02, 0x8D, 0x01];
        assert_eq!(
            WriteMultipleCoilsRequest::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x0F,
                actual: 0x10
            })
        );
    }

    #[test]
    fn write_multiple_coils_response_round_trip() {
        let response = WriteMultipleCoilsResponse {
            starting_address: 0x0013,
            quantity: 9,
        };
        let encoded = response.encode();
        let decoded = WriteMultipleCoilsResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn write_multiple_coils_response_encode_produces_expected_bytes() {
        let response = WriteMultipleCoilsResponse {
            starting_address: 0x0013,
            quantity: 9,
        };
        assert_eq!(response.encode(), vec![0x0F, 0x00, 0x13, 0x00, 0x09]);
    }

    #[test]
    fn write_multiple_coils_response_decode_rejects_too_short_buffer() {
        let bytes = [0x0F, 0x00, 0x13, 0x00];
        assert_eq!(
            WriteMultipleCoilsResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn write_multiple_coils_response_decode_rejects_wrong_function_code() {
        let bytes = [0x10, 0x00, 0x13, 0x00, 0x09];
        assert_eq!(
            WriteMultipleCoilsResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x0F,
                actual: 0x10
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

    #[test]
    fn read_device_identification_request_round_trip() {
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id: 0x80,
        };
        let encoded = request.encode();
        let decoded = ReadDeviceIdentificationRequest::decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn read_device_identification_request_encode_produces_expected_bytes() {
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id: 0x80,
        };
        assert_eq!(request.encode(), vec![0x2B, 0x0E, 0x03, 0x80]);
    }

    #[test]
    fn read_device_identification_request_decode_rejects_wrong_mei_type() {
        let bytes = [0x2B, 0x0D, 0x03, 0x80];
        assert_eq!(
            ReadDeviceIdentificationRequest::decode(&bytes),
            Err(DecodeError::UnexpectedMeiType {
                expected: 0x0E,
                actual: 0x0D
            })
        );
    }

    #[test]
    fn read_device_identification_request_decode_rejects_too_short_buffer() {
        let bytes = [0x2B, 0x0E, 0x03];
        assert_eq!(
            ReadDeviceIdentificationRequest::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_device_identification_response_round_trip_with_objects() {
        let response = ReadDeviceIdentificationResponse {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            conformity_level: 0x83,
            more_follows: true,
            next_object_id: 0x82,
            objects: vec![
                DeviceIdentificationObject {
                    id: 0x80,
                    value: vec![0x01],
                },
                DeviceIdentificationObject {
                    id: 0x81,
                    value: b"name = \"Stop_Process\"".to_vec(),
                },
            ],
        };
        let encoded = response.encode();
        let decoded = ReadDeviceIdentificationResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn read_device_identification_response_round_trip_with_no_objects() {
        let response = ReadDeviceIdentificationResponse {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            conformity_level: 0x83,
            more_follows: false,
            next_object_id: 0x00,
            objects: vec![],
        };
        let encoded = response.encode();
        let decoded = ReadDeviceIdentificationResponse::decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn read_device_identification_response_decode_rejects_too_short_header() {
        let bytes = [0x2B, 0x0E, 0x03, 0x83, 0x00];
        assert_eq!(
            ReadDeviceIdentificationResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_device_identification_response_decode_rejects_declared_object_count_exceeding_buffer() {
        // Claims 2 objects but only includes bytes for a truncated first one.
        let bytes = [0x2B, 0x0E, 0x03, 0x83, 0x00, 0x00, 0x02, 0x80, 0x05, 0x01];
        assert_eq!(
            ReadDeviceIdentificationResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_device_identification_response_decode_rejects_declared_object_length_exceeding_buffer()
    {
        // Object 0x80 claims a length of 10 but only 1 byte of value follows.
        let bytes = [0x2B, 0x0E, 0x03, 0x83, 0x00, 0x00, 0x01, 0x80, 0x0A, 0x01];
        assert_eq!(
            ReadDeviceIdentificationResponse::decode(&bytes),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_device_identification_response_decode_rejects_wrong_function_code() {
        let bytes = [0x03, 0x0E, 0x03, 0x83, 0x00, 0x00, 0x00];
        assert_eq!(
            ReadDeviceIdentificationResponse::decode(&bytes),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: 0x2B,
                actual: 0x03
            })
        );
    }
}
