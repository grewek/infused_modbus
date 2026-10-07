// Moved from `protocol::pdu` (pre-move), converted from `Vec`-based
// payloads to this crate's fixed-capacity container types (see the
// `pdu_bytes`/`register_values`/`bit_values`/`file_record`/
// `device_identification` modules) -- not yet wired up as `protocol`'s own
// `pdu` module (a later, separate step once this port is reviewed).
//
// Every `encode()` below that doesn't need to be fallible builds its output
// with `.expect("fits MAX_PDU_LEN")` on each `push`/`extend_from_slice`:
// safe because the *input* is itself already one of this crate's capacity-
// bounded types (e.g. `RegisterValues`'s 125-entry cap keeps a register
// response's data well under `MAX_PDU_LEN` once the fixed header is added).
// Where a container's own capacity does *not* tightly match a specific
// wire shape's real ceiling once per-entry wire overhead is added back in
// (`ReportServerIdResponse`, `ReadDeviceIdentificationResponse`,
// `ReadFileRecordResponse`, `WriteFileRecordRequest`/`Response`), `encode`
// stays (or newly becomes) fallible and checks the real total size up
// front -- the same treatment the pre-move code already gave
// `WriteMultipleRegistersRequest`/`ReadWriteMultipleRegistersRequest` for
// the same underlying reason (a valid Rust value that doesn't fit the wire
// format is a real `EncodeError`, not a panic).

use crate::bit_values::BitValues;
use crate::device_identification::DeviceIdentificationObjects;
use crate::error::{DecodeError, EncodeError, read_u16_be};
use crate::file_record::{
    FileRecordResponseData, FileRecordSubRequest, FileRecordSubRequests, WriteFileRecordSubRequests,
};
use crate::pdu_bytes::{MAX_PDU_LEN, PduBytes};
use crate::register_values::RegisterValues;

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
pub const FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS: u8 = 0x17;
pub const FUNCTION_CODE_READ_FILE_RECORD: u8 = 0x14;
pub const FUNCTION_CODE_WRITE_FILE_RECORD: u8 = 0x15;
pub const FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT: u8 = 0x2B;

pub const MEI_TYPE_READ_DEVICE_IDENTIFICATION: u8 = 0x0E;

pub const READ_DEVICE_ID_BASIC: u8 = 0x01;
pub const READ_DEVICE_ID_REGULAR: u8 = 0x02;
pub const READ_DEVICE_ID_EXTENDED: u8 = 0x03;
pub const READ_DEVICE_ID_INDIVIDUAL: u8 = 0x04;

pub const EXCEPTION_ILLEGAL_FUNCTION: u8 = 0x01;
pub const EXCEPTION_ILLEGAL_DATA_ADDRESS: u8 = 0x02;
pub const EXCEPTION_ILLEGAL_DATA_VALUE: u8 = 0x03;
pub const EXCEPTION_SERVER_DEVICE_FAILURE: u8 = 0x04;

const FUNCTION_CODE_BYTE: usize = 0;
const ADDRESS_FIELD_BYTE: usize = 1;
const QUANTITY_OR_VALUE_FIELD_BYTE: usize = 3;
const TWO_FIELD_PDU_LEN: usize = 5;
const OR_MASK_FIELD_BYTE: usize = 5;
const MASK_WRITE_REGISTER_PDU_LEN: usize = 7;

const REPORT_SERVER_ID_BYTE_COUNT_BYTE: usize = 1;
const REPORT_SERVER_ID_DATA_START: usize = 2;
const REPORT_SERVER_ID_RESPONSE_HEADER_LEN: usize = 2;
const RUN_INDICATOR_ON: u8 = 0xFF;
const RUN_INDICATOR_OFF: u8 = 0x00;

const READ_WRITE_WRITE_STARTING_ADDRESS_BYTE: usize = 5;
const READ_WRITE_BYTE_COUNT_BYTE: usize = 9;
const READ_WRITE_VALUES_START: usize = 10;
const READ_WRITE_REQUEST_HEADER_LEN: usize = 10;

const BYTE_COUNT_BYTE: usize = 1;
const RESPONSE_DATA_START: usize = 2;
const RESPONSE_HEADER_LEN: usize = 2;

const COIL_VALUE_ON: u16 = 0xFF00;
const COIL_VALUE_OFF: u16 = 0x0000;

const FILE_RECORD_REFERENCE_TYPE: u8 = 6;
const FILE_RECORD_SUB_REQUEST_LEN: usize = 7;

const WRITE_MULTIPLE_BYTE_COUNT_BYTE: usize = 5;
const WRITE_MULTIPLE_VALUES_START: usize = 6;
const WRITE_MULTIPLE_REQUEST_HEADER_LEN: usize = 6;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadInputRegistersRequest {
    pub starting_address: u16,
    pub quantity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCoilsResponse {
    pub coil_values: BitValues,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDiscreteInputsResponse {
    pub discrete_input_values: BitValues,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadHoldingRegistersResponse {
    pub register_values: RegisterValues,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadInputRegistersResponse {
    pub register_values: RegisterValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleCoilRequest {
    pub coil_address: u16,
    pub coil_value: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleCoilResponse {
    pub coil_address: u16,
    pub coil_value: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleRegisterRequest {
    pub register_address: u16,
    pub register_value: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteSingleRegisterResponse {
    pub register_address: u16,
    pub register_value: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskWriteRegisterRequest {
    pub reference_address: u16,
    pub and_mask: u16,
    pub or_mask: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskWriteRegisterResponse {
    pub reference_address: u16,
    pub and_mask: u16,
    pub or_mask: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportServerIdRequest;

/// `server_id`'s content is entirely vendor-specific per the spec -- kept as
/// raw bytes (`PduBytes`) rather than a `String`, same reasoning as before
/// the move: `protocol-core` has no business assuming it's valid UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportServerIdResponse {
    pub server_id: PduBytes,
    pub run_indicator_status: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadWriteMultipleRegistersRequest {
    pub read_starting_address: u16,
    pub read_quantity: u16,
    pub write_starting_address: u16,
    pub write_values: RegisterValues,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadWriteMultipleRegistersResponse {
    pub register_values: RegisterValues,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteMultipleCoilsRequest {
    pub starting_address: u16,
    pub coil_values: BitValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleCoilsResponse {
    pub starting_address: u16,
    pub quantity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteMultipleRegistersRequest {
    pub starting_address: u16,
    pub register_values: RegisterValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMultipleRegistersResponse {
    pub starting_address: u16,
    pub quantity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFileRecordRequest {
    pub sub_requests: FileRecordSubRequests,
}

/// Deliberately untyped/uninterpreted, same as before the move: what a
/// record's bytes actually mean is entirely vendor-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFileRecordResponse {
    pub records: FileRecordResponseData,
}

/// Per spec, a Write File Record response is byte-identical in shape to its
/// request -- [`WriteFileRecordRequest`]/[`WriteFileRecordResponse`] are two
/// distinct types sharing one container type for `sub_requests`, same
/// `encode_write_file_record`/`decode_write_file_record` helpers as before
/// the move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFileRecordRequest {
    pub sub_requests: WriteFileRecordSubRequests,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFileRecordResponse {
    pub sub_requests: WriteFileRecordSubRequests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionResponse {
    pub function_code: u8,
    pub exception_code: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadDeviceIdentificationRequest {
    pub read_device_id_code: u8,
    pub object_id: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDeviceIdentificationResponse {
    pub read_device_id_code: u8,
    pub conformity_level: u8,
    pub more_follows: bool,
    pub next_object_id: u8,
    pub objects: DeviceIdentificationObjects,
}

struct AddressAndQuantity {
    starting_address: u16,
    quantity: u16,
}

fn encode_address_and_quantity(
    function_code: u8,
    starting_address: u16,
    quantity: u16,
) -> PduBytes {
    let mut buffer = PduBytes::new();
    buffer.push(function_code).expect("fits MAX_PDU_LEN");
    buffer
        .extend_from_slice(&starting_address.to_be_bytes())
        .expect("fits MAX_PDU_LEN");
    buffer
        .extend_from_slice(&quantity.to_be_bytes())
        .expect("fits MAX_PDU_LEN");
    debug_assert_eq!(buffer.len(), TWO_FIELD_PDU_LEN);
    buffer
}

fn decode_address_and_quantity(
    bytes: &[u8],
    function_code: u8,
) -> Result<AddressAndQuantity, DecodeError> {
    if bytes.len() < TWO_FIELD_PDU_LEN {
        return Err(DecodeError::TooShort);
    }
    if bytes[FUNCTION_CODE_BYTE] != function_code {
        return Err(DecodeError::UnexpectedFunctionCode {
            expected: function_code,
            actual: bytes[FUNCTION_CODE_BYTE],
        });
    }
    let starting_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
    let quantity = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
    Ok(AddressAndQuantity {
        starting_address,
        quantity,
    })
}

impl ReadCoilsRequest {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_READ_COILS,
            self.starting_address,
            self.quantity,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address,
            quantity,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_READ_COILS)?;
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

impl ReadDiscreteInputsRequest {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_READ_DISCRETE_INPUTS,
            self.starting_address,
            self.quantity,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address,
            quantity,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_READ_DISCRETE_INPUTS)?;
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

impl ReadHoldingRegistersRequest {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_READ_HOLDING_REGISTERS,
            self.starting_address,
            self.quantity,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address,
            quantity,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_READ_HOLDING_REGISTERS)?;
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

impl ReadInputRegistersRequest {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_READ_INPUT_REGISTERS,
            self.starting_address,
            self.quantity,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address,
            quantity,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_READ_INPUT_REGISTERS)?;
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

// pack_bit/unpack_bit (bit-by-bit helpers) are gone -- BitValues now stores
// bits packed exactly like the wire format internally, so both directions
// below are a single byte-range copy instead of a per-bit loop (measured:
// this plus BitValues' own packed storage closed the decode-side
// performance gap found when first benchmarking this port against the
// pre-move Vec<bool>-based implementation, see CLAUDE.md's "server-no-std
// initiative").

fn encode_bitfield_response(function_code: u8, values: &BitValues) -> PduBytes {
    let mut buffer = PduBytes::new();
    buffer.push(function_code).expect("fits MAX_PDU_LEN");
    buffer
        .push(values.as_packed_bytes().len() as u8)
        .expect("fits MAX_PDU_LEN");
    buffer
        .extend_from_slice(values.as_packed_bytes())
        .expect("fits MAX_PDU_LEN");
    buffer
}

/// `byte_count` is an untrusted wire `u8` (max 255 -> up to 2040 bits),
/// which can exceed `BitValues`' own 2000-bit real-spec capacity -- unlike
/// most decode paths in this file, this one is reachable by a genuinely
/// malformed (out-of-spec) peer, not just a theoretically-impossible edge
/// case, so it's propagated as a real `DecodeError`, never `.expect()`'d.
///
/// Out-parameter, same reasoning as `decode_register_array_response`'s own
/// doc comment: `BitValues` is also ~250 bytes inline, not a cheap `Vec`
/// handle, so returning it by value risked the same redundant-memcpy
/// pattern at the `Result`/struct-wrapping boundary.
fn decode_bitfield_response(
    bytes: &[u8],
    function_code: u8,
    values: &mut BitValues,
) -> Result<(), DecodeError> {
    if bytes.len() < RESPONSE_HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    if bytes[FUNCTION_CODE_BYTE] != function_code {
        return Err(DecodeError::UnexpectedFunctionCode {
            expected: function_code,
            actual: bytes[FUNCTION_CODE_BYTE],
        });
    }
    let byte_count = bytes[BYTE_COUNT_BYTE] as usize;
    if bytes.len() < RESPONSE_DATA_START + byte_count {
        return Err(DecodeError::TooShort);
    }
    let packed = &bytes[RESPONSE_DATA_START..(RESPONSE_DATA_START + byte_count)];
    values
        .extend_from_packed_bytes(packed, byte_count * 8)
        .map_err(|_| DecodeError::TooLargeForBuffer)?;
    Ok(())
}

impl ReadCoilsResponse {
    pub fn encode(&self) -> PduBytes {
        encode_bitfield_response(FUNCTION_CODE_READ_COILS, &self.coil_values)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut coil_values = BitValues::new();
        decode_bitfield_response(bytes, FUNCTION_CODE_READ_COILS, &mut coil_values)?;
        Ok(Self { coil_values })
    }
}

impl ReadDiscreteInputsResponse {
    pub fn encode(&self) -> PduBytes {
        encode_bitfield_response(
            FUNCTION_CODE_READ_DISCRETE_INPUTS,
            &self.discrete_input_values,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut discrete_input_values = BitValues::new();
        decode_bitfield_response(
            bytes,
            FUNCTION_CODE_READ_DISCRETE_INPUTS,
            &mut discrete_input_values,
        )?;
        Ok(Self {
            discrete_input_values,
        })
    }
}

fn encode_register_array_response(function_code: u8, register_values: &[u16]) -> PduBytes {
    let mut buffer = PduBytes::new();
    buffer.push(function_code).expect("fits MAX_PDU_LEN");
    buffer
        .push((register_values.len() * 2) as u8)
        .expect("fits MAX_PDU_LEN");
    for value in register_values {
        buffer
            .extend_from_slice(&value.to_be_bytes())
            .expect("fits MAX_PDU_LEN");
    }
    buffer
}

/// Same "untrusted `byte_count` can exceed the container's real-spec
/// capacity" situation as `decode_bitfield_response` above: a wire
/// `byte_count` of 254 decodes to 127 registers, over `RegisterValues`' own
/// 125-entry cap.
///
/// Out-parameter (`values: &mut RegisterValues`) rather than returning
/// `RegisterValues` by value: `RegisterValues` is ~250 bytes and lives
/// inline in its enclosing structs (no heap indirection like `Vec` had).
/// Measured at the assembly level (benchmark baseline, see CLAUDE.md's
/// "server-no-std initiative") that returning it by value -- even with
/// `#[inline(always)]` on every layer of the call chain -- still left one
/// `memcpy` of the full value at the `Result`/struct-wrapping boundary on
/// its way out, something `Vec`'s cheap 24-byte handle never suffered
/// from. Writing directly into a caller-owned `RegisterValues` removes
/// that copy structurally instead of hoping the optimizer elides it.
/// Callers (`ReadHoldingRegistersResponse` etc.) still expose the normal
/// `decode(bytes) -> Result<Self, DecodeError>` public shape -- this is
/// purely an internal-plumbing fix. A `decode_into(bytes, &mut Self)`
/// public fast path (letting a caller reuse one `Self` across many decode
/// calls, eliminating even the last copy) was designed but deliberately
/// deferred to the phase-2 integration work, where a real hot-path
/// consumer either does or doesn't materialize to justify it.
fn decode_register_array_response(
    bytes: &[u8],
    function_code: u8,
    values: &mut RegisterValues,
) -> Result<(), DecodeError> {
    if bytes.len() < RESPONSE_HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    if bytes[FUNCTION_CODE_BYTE] != function_code {
        return Err(DecodeError::UnexpectedFunctionCode {
            expected: function_code,
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
    values
        .extend_from_iter(
            bytes[RESPONSE_DATA_START..(RESPONSE_DATA_START + byte_count as usize)]
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])),
        )
        .map_err(|_| DecodeError::TooLargeForBuffer)?;
    Ok(())
}

impl ReadHoldingRegistersResponse {
    pub fn encode(&self) -> PduBytes {
        encode_register_array_response(FUNCTION_CODE_READ_HOLDING_REGISTERS, &self.register_values)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut register_values = RegisterValues::new();
        decode_register_array_response(
            bytes,
            FUNCTION_CODE_READ_HOLDING_REGISTERS,
            &mut register_values,
        )?;
        Ok(Self { register_values })
    }
}

impl ReadInputRegistersResponse {
    pub fn encode(&self) -> PduBytes {
        encode_register_array_response(FUNCTION_CODE_READ_INPUT_REGISTERS, &self.register_values)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut register_values = RegisterValues::new();
        decode_register_array_response(
            bytes,
            FUNCTION_CODE_READ_INPUT_REGISTERS,
            &mut register_values,
        )?;
        Ok(Self { register_values })
    }
}

fn encode_write_single_coil(coil_address: u16, coil_value: bool) -> PduBytes {
    let wire_value = if coil_value {
        COIL_VALUE_ON
    } else {
        COIL_VALUE_OFF
    };
    encode_address_and_quantity(FUNCTION_CODE_WRITE_SINGLE_COIL, coil_address, wire_value)
}

fn decode_write_single_coil(bytes: &[u8]) -> Result<(u16, bool), DecodeError> {
    let AddressAndQuantity {
        starting_address: coil_address,
        quantity: wire_value,
    } = decode_address_and_quantity(bytes, FUNCTION_CODE_WRITE_SINGLE_COIL)?;
    let coil_value = match wire_value {
        COIL_VALUE_ON => true,
        COIL_VALUE_OFF => false,
        actual => return Err(DecodeError::InvalidCoilValue { actual }),
    };
    Ok((coil_address, coil_value))
}

impl WriteSingleCoilRequest {
    pub fn encode(&self) -> PduBytes {
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
    pub fn encode(&self) -> PduBytes {
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

impl WriteSingleRegisterRequest {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_WRITE_SINGLE_REGISTER,
            self.register_address,
            self.register_value,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address: register_address,
            quantity: register_value,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_WRITE_SINGLE_REGISTER)?;
        Ok(Self {
            register_address,
            register_value,
        })
    }
}

impl WriteSingleRegisterResponse {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_WRITE_SINGLE_REGISTER,
            self.register_address,
            self.register_value,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address: register_address,
            quantity: register_value,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_WRITE_SINGLE_REGISTER)?;
        Ok(Self {
            register_address,
            register_value,
        })
    }
}

fn encode_mask_write_register(reference_address: u16, and_mask: u16, or_mask: u16) -> PduBytes {
    let mut buffer = PduBytes::new();
    buffer
        .push(FUNCTION_CODE_MASK_WRITE_REGISTER)
        .expect("fits MAX_PDU_LEN");
    buffer
        .extend_from_slice(&reference_address.to_be_bytes())
        .expect("fits MAX_PDU_LEN");
    buffer
        .extend_from_slice(&and_mask.to_be_bytes())
        .expect("fits MAX_PDU_LEN");
    buffer
        .extend_from_slice(&or_mask.to_be_bytes())
        .expect("fits MAX_PDU_LEN");
    debug_assert_eq!(buffer.len(), MASK_WRITE_REGISTER_PDU_LEN);
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
    pub fn encode(&self) -> PduBytes {
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
    pub fn encode(&self) -> PduBytes {
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
    pub fn encode(&self) -> PduBytes {
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_REPORT_SERVER_ID)
            .expect("fits MAX_PDU_LEN");
        buffer
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
    /// Fallible, unlike most `encode()`s here: `server_id` is a full
    /// `PduBytes` (253-byte capacity), but the response wraps it with 2
    /// header bytes + 1 trailing `run_indicator_status` byte, so a
    /// `server_id` anywhere near its own full capacity would overflow
    /// `MAX_PDU_LEN` once wrapped -- checked up front rather than silently
    /// truncating or panicking.
    pub fn encode(&self) -> Result<PduBytes, EncodeError> {
        // +1 for the trailing run_indicator_status byte, which byte_count
        // covers alongside server_id (Modbus Application Protocol V1.1b3,
        // section 6.11's own worked example).
        let byte_count = self.server_id.len() + 1;
        if REPORT_SERVER_ID_RESPONSE_HEADER_LEN + byte_count > MAX_PDU_LEN {
            return Err(EncodeError::TooLargeForBuffer);
        }
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_REPORT_SERVER_ID)
            .expect("checked above");
        buffer.push(byte_count as u8).expect("checked above");
        buffer
            .extend_from_slice(&self.server_id)
            .expect("checked above");
        buffer
            .push(if self.run_indicator_status {
                RUN_INDICATOR_ON
            } else {
                RUN_INDICATOR_OFF
            })
            .expect("checked above");
        Ok(buffer)
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
        let mut server_id = PduBytes::new();
        server_id
            .extend_from_slice(&bytes[REPORT_SERVER_ID_DATA_START..server_id_end])
            .map_err(|_| DecodeError::TooLargeForBuffer)?;
        let run_indicator_status = bytes[server_id_end] != RUN_INDICATOR_OFF;
        Ok(Self {
            server_id,
            run_indicator_status,
        })
    }
}

// The spec's own limit on how many registers Read/Write Multiple Registers
// (0x17) may *write* — lower than plain Write Multiple Registers' 123
// (WriteMultipleRegistersRequest's own MAX_WRITE_MULTIPLE_REGISTERS_COUNT),
// since this PDU's extra read-address/read-quantity/write-address fields eat
// into the same 253-byte PDU budget. Tighter than RegisterValues' own
// 125-entry capacity -- still enforced explicitly, same as before the move.
const MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT: usize = 121;

impl ReadWriteMultipleRegistersRequest {
    pub fn encode(&self) -> Result<PduBytes, EncodeError> {
        if self.write_values.len() > MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT {
            return Err(EncodeError::TooManyRegisters {
                count: self.write_values.len(),
                max: MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT,
            });
        }
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS)
            .expect("checked above");
        buffer
            .extend_from_slice(&self.read_starting_address.to_be_bytes())
            .expect("checked above");
        buffer
            .extend_from_slice(&self.read_quantity.to_be_bytes())
            .expect("checked above");
        buffer
            .extend_from_slice(&self.write_starting_address.to_be_bytes())
            .expect("checked above");
        let write_quantity = self.write_values.len() as u16;
        buffer
            .extend_from_slice(&write_quantity.to_be_bytes())
            .expect("checked above");
        buffer
            .push((self.write_values.len() * 2) as u8)
            .expect("checked above");
        for value in self.write_values.as_slice() {
            buffer
                .extend_from_slice(&value.to_be_bytes())
                .expect("checked above");
        }
        Ok(buffer)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < READ_WRITE_REQUEST_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let read_starting_address = read_u16_be(bytes, ADDRESS_FIELD_BYTE);
        let read_quantity = read_u16_be(bytes, QUANTITY_OR_VALUE_FIELD_BYTE);
        let write_starting_address = read_u16_be(bytes, READ_WRITE_WRITE_STARTING_ADDRESS_BYTE);
        let byte_count = bytes[READ_WRITE_BYTE_COUNT_BYTE];
        if !byte_count.is_multiple_of(2) {
            return Err(DecodeError::OddByteCount { byte_count });
        }
        if bytes.len() < READ_WRITE_VALUES_START + byte_count as usize {
            return Err(DecodeError::TooShort);
        }
        let mut write_values = RegisterValues::new();
        write_values
            .extend_from_iter(
                bytes[READ_WRITE_VALUES_START..(READ_WRITE_VALUES_START + byte_count as usize)]
                    .chunks_exact(2)
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])),
            )
            .map_err(|_| DecodeError::TooLargeForBuffer)?;
        Ok(Self {
            read_starting_address,
            read_quantity,
            write_starting_address,
            write_values,
        })
    }
}

impl ReadWriteMultipleRegistersResponse {
    pub fn encode(&self) -> PduBytes {
        encode_register_array_response(
            FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS,
            &self.register_values,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut register_values = RegisterValues::new();
        decode_register_array_response(
            bytes,
            FUNCTION_CODE_READ_WRITE_MULTIPLE_REGISTERS,
            &mut register_values,
        )?;
        Ok(Self { register_values })
    }
}

impl WriteMultipleCoilsRequest {
    pub fn encode(&self) -> PduBytes {
        let byte_count = self.coil_values.len().div_ceil(8);
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_WRITE_MULTIPLE_COILS)
            .expect("fits MAX_PDU_LEN");
        buffer
            .extend_from_slice(&self.starting_address.to_be_bytes())
            .expect("fits MAX_PDU_LEN");
        let quantity = self.coil_values.len() as u16;
        buffer
            .extend_from_slice(&quantity.to_be_bytes())
            .expect("fits MAX_PDU_LEN");
        buffer.push(byte_count as u8).expect("fits MAX_PDU_LEN");
        buffer
            .extend_from_slice(self.coil_values.as_packed_bytes())
            .expect("fits MAX_PDU_LEN");
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
        let packed =
            &bytes[WRITE_MULTIPLE_VALUES_START..(WRITE_MULTIPLE_VALUES_START + byte_count)];
        let mut coil_values = BitValues::new();
        coil_values
            .extend_from_packed_bytes(packed, quantity as usize)
            .map_err(|_| DecodeError::TooLargeForBuffer)?;
        Ok(Self {
            starting_address,
            coil_values,
        })
    }
}

impl WriteMultipleCoilsResponse {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_WRITE_MULTIPLE_COILS,
            self.starting_address,
            self.quantity,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address,
            quantity,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_WRITE_MULTIPLE_COILS)?;
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

// The spec's own limit on how many registers one Write Multiple Registers
// (0x10) request may carry — same value `client::transaction_consumer`'s
// write-batching already caps itself at, but enforced here too since that's
// an application-level choice, not something the wire format itself
// guarantees against a caller that bypasses it. Tighter than RegisterValues'
// own 125-entry capacity — still enforced explicitly, same as before the
// move.
const MAX_WRITE_MULTIPLE_REGISTERS_COUNT: usize = 123;

impl WriteMultipleRegistersRequest {
    pub fn encode(&self) -> Result<PduBytes, EncodeError> {
        if self.register_values.len() > MAX_WRITE_MULTIPLE_REGISTERS_COUNT {
            return Err(EncodeError::TooManyRegisters {
                count: self.register_values.len(),
                max: MAX_WRITE_MULTIPLE_REGISTERS_COUNT,
            });
        }
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS)
            .expect("checked above");
        buffer
            .extend_from_slice(&self.starting_address.to_be_bytes())
            .expect("checked above");
        let quantity = self.register_values.len() as u16;
        buffer
            .extend_from_slice(&quantity.to_be_bytes())
            .expect("checked above");
        buffer
            .push((self.register_values.len() * 2) as u8)
            .expect("checked above");
        for value in self.register_values.as_slice() {
            buffer
                .extend_from_slice(&value.to_be_bytes())
                .expect("checked above");
        }
        Ok(buffer)
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
        let mut register_values = RegisterValues::new();
        register_values
            .extend_from_iter(
                bytes[WRITE_MULTIPLE_VALUES_START
                    ..(WRITE_MULTIPLE_VALUES_START + byte_count as usize)]
                    .chunks_exact(2)
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])),
            )
            .map_err(|_| DecodeError::TooLargeForBuffer)?;
        Ok(Self {
            starting_address,
            register_values,
        })
    }
}

impl WriteMultipleRegistersResponse {
    pub fn encode(&self) -> PduBytes {
        encode_address_and_quantity(
            FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
            self.starting_address,
            self.quantity,
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let AddressAndQuantity {
            starting_address,
            quantity,
        } = decode_address_and_quantity(bytes, FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS)?;
        Ok(Self {
            starting_address,
            quantity,
        })
    }
}

impl ReadDeviceIdentificationRequest {
    pub fn encode(&self) -> PduBytes {
        let mut buffer = PduBytes::new();
        buffer
            .extend_from_slice(&[
                FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
                MEI_TYPE_READ_DEVICE_IDENTIFICATION,
                self.read_device_id_code,
                self.object_id,
            ])
            .expect("fits MAX_PDU_LEN");
        buffer
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
    /// Fallible, unlike before the move: `objects`' flat `PduBytes` buffer
    /// caps total *value* bytes at `MAX_PDU_LEN`, but each object adds 2
    /// more wire bytes (id + length) on top, and the response itself has a
    /// 7-byte header -- a large enough object count can overflow
    /// `MAX_PDU_LEN` even while every individual object is small. Checked
    /// up front rather than silently truncating or panicking (the pre-move
    /// `Vec`-based code never checked this at all -- a real, if unlikely,
    /// pre-existing gap this conversion forces into the open).
    pub fn encode(&self) -> Result<PduBytes, EncodeError> {
        let data_len: usize = (0..self.objects.count())
            .map(|index| 2 + self.objects.object(index).expect("index < count").1.len())
            .sum();
        if RESPONSE_OBJECTS_START + data_len > MAX_PDU_LEN {
            return Err(EncodeError::TooLargeForBuffer);
        }
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT)
            .expect("checked above");
        buffer
            .push(MEI_TYPE_READ_DEVICE_IDENTIFICATION)
            .expect("checked above");
        buffer
            .push(self.read_device_id_code)
            .expect("checked above");
        buffer.push(self.conformity_level).expect("checked above");
        buffer
            .push(if self.more_follows {
                MORE_FOLLOWS_YES
            } else {
                MORE_FOLLOWS_NO
            })
            .expect("checked above");
        buffer.push(self.next_object_id).expect("checked above");
        buffer
            .push(self.objects.count() as u8)
            .expect("checked above");
        for index in 0..self.objects.count() {
            let (id, value) = self.objects.object(index).expect("index < count");
            buffer.push(id).expect("checked above");
            buffer.push(value.len() as u8).expect("checked above");
            buffer.extend_from_slice(value).expect("checked above");
        }
        Ok(buffer)
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
        // "validate before allocating/reading" discipline used elsewhere.
        let mut objects = DeviceIdentificationObjects::new();
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
            objects
                .push(id, &bytes[value_start..value_start + length])
                .map_err(|_| DecodeError::TooLargeForBuffer)?;
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

impl ReadFileRecordRequest {
    pub fn encode(&self) -> PduBytes {
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_READ_FILE_RECORD)
            .expect("fits MAX_PDU_LEN");
        buffer
            .push((self.sub_requests.len() * FILE_RECORD_SUB_REQUEST_LEN) as u8)
            .expect("fits MAX_PDU_LEN");
        for sub_request in self.sub_requests.as_slice() {
            buffer
                .push(FILE_RECORD_REFERENCE_TYPE)
                .expect("fits MAX_PDU_LEN");
            buffer
                .extend_from_slice(&sub_request.file_number.to_be_bytes())
                .expect("fits MAX_PDU_LEN");
            buffer
                .extend_from_slice(&sub_request.record_number.to_be_bytes())
                .expect("fits MAX_PDU_LEN");
            buffer
                .extend_from_slice(&sub_request.record_length.to_be_bytes())
                .expect("fits MAX_PDU_LEN");
        }
        buffer
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < RESPONSE_DATA_START {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_FILE_RECORD {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_FILE_RECORD,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let byte_count = bytes[BYTE_COUNT_BYTE];
        if byte_count == 0 || !(byte_count as usize).is_multiple_of(FILE_RECORD_SUB_REQUEST_LEN) {
            return Err(DecodeError::InvalidFileRecordByteCount { byte_count });
        }
        if bytes.len() < RESPONSE_DATA_START + byte_count as usize {
            return Err(DecodeError::TooShort);
        }

        let sub_request_count = byte_count as usize / FILE_RECORD_SUB_REQUEST_LEN;
        let mut sub_requests = FileRecordSubRequests::new();
        let mut offset = RESPONSE_DATA_START;
        for _ in 0..sub_request_count {
            let reference_type = bytes[offset];
            if reference_type != FILE_RECORD_REFERENCE_TYPE {
                return Err(DecodeError::InvalidFileRecordReferenceType {
                    actual: reference_type,
                });
            }
            sub_requests
                .push(FileRecordSubRequest {
                    file_number: read_u16_be(bytes, offset + 1),
                    record_number: read_u16_be(bytes, offset + 3),
                    record_length: read_u16_be(bytes, offset + 5),
                })
                .map_err(|_| DecodeError::TooLargeForBuffer)?;
            offset += FILE_RECORD_SUB_REQUEST_LEN;
        }
        Ok(Self { sub_requests })
    }
}

impl ReadFileRecordResponse {
    /// Fallible, unlike before the move: `records`' flat `PduBytes` buffer
    /// caps total record-data bytes at `MAX_PDU_LEN`, but each record adds
    /// 2 more wire bytes (length + reference type) on top of its own data
    /// — same overflow shape as `ReadDeviceIdentificationResponse::encode`.
    pub fn encode(&self) -> Result<PduBytes, EncodeError> {
        let data_len: usize = (0..self.records.record_count())
            .map(|index| 2 + self.records.record(index).expect("index < count").len())
            .sum();
        if RESPONSE_DATA_START + data_len > MAX_PDU_LEN {
            return Err(EncodeError::TooLargeForBuffer);
        }
        let mut buffer = PduBytes::new();
        buffer
            .push(FUNCTION_CODE_READ_FILE_RECORD)
            .expect("checked above");
        buffer.push(data_len as u8).expect("checked above");
        for index in 0..self.records.record_count() {
            let record = self.records.record(index).expect("index < count");
            // File response length: reference type byte + this record's
            // own data bytes — does NOT include this length byte itself.
            buffer
                .push((1 + record.len()) as u8)
                .expect("checked above");
            buffer
                .push(FILE_RECORD_REFERENCE_TYPE)
                .expect("checked above");
            buffer.extend_from_slice(record).expect("checked above");
        }
        Ok(buffer)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < RESPONSE_DATA_START {
            return Err(DecodeError::TooShort);
        }
        if bytes[FUNCTION_CODE_BYTE] != FUNCTION_CODE_READ_FILE_RECORD {
            return Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_FILE_RECORD,
                actual: bytes[FUNCTION_CODE_BYTE],
            });
        }
        let byte_count = bytes[BYTE_COUNT_BYTE] as usize;
        if bytes.len() < RESPONSE_DATA_START + byte_count {
            return Err(DecodeError::TooShort);
        }

        // Each sub-response's own length byte is untrusted peer input —
        // checked against the actual remaining buffer before every read,
        // the same discipline ReadDeviceIdentificationResponse::decode
        // already applies to its own variable-length objects.
        let end = RESPONSE_DATA_START + byte_count;
        let mut records = FileRecordResponseData::new();
        let mut offset = RESPONSE_DATA_START;
        while offset < end {
            if bytes.len() < offset + 1 {
                return Err(DecodeError::TooShort);
            }
            let sub_response_length = bytes[offset];
            if sub_response_length == 0 {
                return Err(DecodeError::InvalidFileRecordSubResponseLength {
                    length: sub_response_length,
                });
            }
            let reference_type_offset = offset + 1;
            if bytes.len() < reference_type_offset + 1 {
                return Err(DecodeError::TooShort);
            }
            let reference_type = bytes[reference_type_offset];
            if reference_type != FILE_RECORD_REFERENCE_TYPE {
                return Err(DecodeError::InvalidFileRecordReferenceType {
                    actual: reference_type,
                });
            }
            let data_start = reference_type_offset + 1;
            let data_len = sub_response_length as usize - 1;
            if bytes.len() < data_start + data_len {
                return Err(DecodeError::TooShort);
            }
            records
                .push_record(&bytes[data_start..data_start + data_len])
                .map_err(|_| DecodeError::TooLargeForBuffer)?;
            offset = data_start + data_len;
        }
        Ok(Self { records })
    }
}

fn encode_write_file_record(
    function_code: u8,
    sub_requests: &WriteFileRecordSubRequests,
) -> Result<PduBytes, EncodeError> {
    for index in 0..sub_requests.count() {
        let (file_number, record_number, record_data) =
            sub_requests.sub_request(index).expect("index < count");
        if record_data.len() % 2 != 0 {
            return Err(EncodeError::OddFileRecordDataLength {
                file_number,
                record_number,
                length: record_data.len(),
            });
        }
    }
    let data_len: usize = (0..sub_requests.count())
        .map(|index| {
            FILE_RECORD_SUB_REQUEST_LEN
                + sub_requests
                    .sub_request(index)
                    .expect("index < count")
                    .2
                    .len()
        })
        .sum();
    if RESPONSE_DATA_START + data_len > MAX_PDU_LEN {
        return Err(EncodeError::TooLargeForBuffer);
    }
    let mut buffer = PduBytes::new();
    buffer.push(function_code).expect("checked above");
    buffer.push(data_len as u8).expect("checked above");
    for index in 0..sub_requests.count() {
        let (file_number, record_number, record_data) =
            sub_requests.sub_request(index).expect("index < count");
        buffer
            .push(FILE_RECORD_REFERENCE_TYPE)
            .expect("checked above");
        buffer
            .extend_from_slice(&file_number.to_be_bytes())
            .expect("checked above");
        buffer
            .extend_from_slice(&record_number.to_be_bytes())
            .expect("checked above");
        let record_length = (record_data.len() / 2) as u16;
        buffer
            .extend_from_slice(&record_length.to_be_bytes())
            .expect("checked above");
        buffer
            .extend_from_slice(record_data)
            .expect("checked above");
    }
    Ok(buffer)
}

fn decode_write_file_record(
    bytes: &[u8],
    expected_function_code: u8,
) -> Result<WriteFileRecordSubRequests, DecodeError> {
    if bytes.len() < RESPONSE_DATA_START {
        return Err(DecodeError::TooShort);
    }
    if bytes[FUNCTION_CODE_BYTE] != expected_function_code {
        return Err(DecodeError::UnexpectedFunctionCode {
            expected: expected_function_code,
            actual: bytes[FUNCTION_CODE_BYTE],
        });
    }
    let byte_count = bytes[BYTE_COUNT_BYTE] as usize;
    if bytes.len() < RESPONSE_DATA_START + byte_count {
        return Err(DecodeError::TooShort);
    }

    // Unlike Read File Record's fixed 7-byte sub-requests, each sub-request
    // here has its own variable length (7 + 2*record_length), so the total
    // sub-request count can't be derived from byte_count alone up front —
    // walked one at a time instead, each one's own embedded record_length
    // field is untrusted peer input checked against the actual remaining
    // buffer before every read, same discipline as ReadFileRecordResponse.
    let end = RESPONSE_DATA_START + byte_count;
    let mut sub_requests = WriteFileRecordSubRequests::new();
    let mut offset = RESPONSE_DATA_START;
    while offset < end {
        if bytes.len() < offset + FILE_RECORD_SUB_REQUEST_LEN {
            return Err(DecodeError::TooShort);
        }
        let reference_type = bytes[offset];
        if reference_type != FILE_RECORD_REFERENCE_TYPE {
            return Err(DecodeError::InvalidFileRecordReferenceType {
                actual: reference_type,
            });
        }
        let file_number = read_u16_be(bytes, offset + 1);
        let record_number = read_u16_be(bytes, offset + 3);
        let record_length = read_u16_be(bytes, offset + 5);
        let data_start = offset + FILE_RECORD_SUB_REQUEST_LEN;
        let data_len = record_length as usize * 2;
        if bytes.len() < data_start + data_len {
            return Err(DecodeError::TooShort);
        }
        sub_requests
            .push(
                file_number,
                record_number,
                &bytes[data_start..data_start + data_len],
            )
            .map_err(|_| DecodeError::TooLargeForBuffer)?;
        offset = data_start + data_len;
    }
    Ok(sub_requests)
}

impl WriteFileRecordRequest {
    pub fn encode(&self) -> Result<PduBytes, EncodeError> {
        encode_write_file_record(FUNCTION_CODE_WRITE_FILE_RECORD, &self.sub_requests)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            sub_requests: decode_write_file_record(bytes, FUNCTION_CODE_WRITE_FILE_RECORD)?,
        })
    }
}

impl WriteFileRecordResponse {
    pub fn encode(&self) -> Result<PduBytes, EncodeError> {
        encode_write_file_record(FUNCTION_CODE_WRITE_FILE_RECORD, &self.sub_requests)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            sub_requests: decode_write_file_record(bytes, FUNCTION_CODE_WRITE_FILE_RECORD)?,
        })
    }
}

impl ExceptionResponse {
    pub fn encode(&self) -> PduBytes {
        let mut buffer = PduBytes::new();
        buffer
            .extend_from_slice(&[
                self.function_code | EXCEPTION_RESPONSE_FUNCTION_CODE_BIT,
                self.exception_code,
            ])
            .expect("fits MAX_PDU_LEN");
        buffer
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

    fn register_values(values: &[u16]) -> RegisterValues {
        let mut result = RegisterValues::new();
        result.extend_from_slice(values).unwrap();
        result
    }

    fn bit_values(values: &[bool]) -> BitValues {
        let mut result = BitValues::new();
        result.extend_from_slice(values).unwrap();
        result
    }

    fn make_pdu_bytes(bytes: &[u8]) -> PduBytes {
        let mut result = PduBytes::new();
        result.extend_from_slice(bytes).unwrap();
        result
    }

    #[test]
    fn read_coils_request_round_trips() {
        let request = ReadCoilsRequest {
            starting_address: 40001,
            quantity: 10,
        };
        let encoded = request.encode();
        assert_eq!(ReadCoilsRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn read_coils_request_decode_rejects_wrong_function_code() {
        let other = ReadDiscreteInputsRequest {
            starting_address: 1,
            quantity: 1,
        }
        .encode();
        assert_eq!(
            ReadCoilsRequest::decode(&other),
            Err(DecodeError::UnexpectedFunctionCode {
                expected: FUNCTION_CODE_READ_COILS,
                actual: FUNCTION_CODE_READ_DISCRETE_INPUTS,
            })
        );
    }

    #[test]
    fn read_coils_request_decode_rejects_too_short() {
        assert_eq!(
            ReadCoilsRequest::decode(&[0x01]),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn read_discrete_inputs_request_round_trips() {
        let request = ReadDiscreteInputsRequest {
            starting_address: 1,
            quantity: 3,
        };
        assert_eq!(
            ReadDiscreteInputsRequest::decode(&request.encode()).unwrap(),
            request
        );
    }

    #[test]
    fn read_holding_registers_request_round_trips() {
        let request = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 2,
        };
        assert_eq!(
            ReadHoldingRegistersRequest::decode(&request.encode()).unwrap(),
            request
        );
    }

    #[test]
    fn read_input_registers_request_round_trips() {
        let request = ReadInputRegistersRequest {
            starting_address: 30001,
            quantity: 2,
        };
        assert_eq!(
            ReadInputRegistersRequest::decode(&request.encode()).unwrap(),
            request
        );
    }

    #[test]
    fn read_coils_response_round_trips() {
        // Exactly one byte's worth of bits -- decode always returns
        // byte_count * 8 bits (see decode_bitfield_response's own doc
        // comment), so a non-8-aligned quantity wouldn't round-trip to the
        // same length; that's pre-existing, documented behavior, not
        // something this test is meant to cover.
        let response = ReadCoilsResponse {
            coil_values: bit_values(&[true, false, true, true, false, false, false, true]),
        };
        assert_eq!(
            ReadCoilsResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn read_discrete_inputs_response_round_trips() {
        let response = ReadDiscreteInputsResponse {
            discrete_input_values: bit_values(&[
                true, false, true, false, true, false, true, false,
            ]),
        };
        assert_eq!(
            ReadDiscreteInputsResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn decode_bitfield_response_rejects_a_byte_count_that_would_overflow_bit_values() {
        // byte_count 255 -> 2040 bits, over BitValues' 2000-bit capacity.
        let mut bytes = [0u8; 257];
        bytes[0] = FUNCTION_CODE_READ_COILS;
        bytes[1] = 255;
        assert_eq!(
            ReadCoilsResponse::decode(&bytes),
            Err(DecodeError::TooLargeForBuffer)
        );
    }

    #[test]
    fn read_holding_registers_response_round_trips() {
        let response = ReadHoldingRegistersResponse {
            register_values: register_values(&[1, 2, 3, 65535]),
        };
        assert_eq!(
            ReadHoldingRegistersResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn read_input_registers_response_round_trips() {
        let response = ReadInputRegistersResponse {
            register_values: register_values(&[42]),
        };
        assert_eq!(
            ReadInputRegistersResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn decode_register_array_response_rejects_a_byte_count_that_would_overflow_register_values() {
        // byte_count 254 -> 127 registers, over RegisterValues' 125 capacity.
        let mut bytes = [0u8; 256];
        bytes[0] = FUNCTION_CODE_READ_HOLDING_REGISTERS;
        bytes[1] = 254;
        assert_eq!(
            ReadHoldingRegistersResponse::decode(&bytes),
            Err(DecodeError::TooLargeForBuffer)
        );
    }

    #[test]
    fn write_single_coil_round_trips() {
        let request = WriteSingleCoilRequest {
            coil_address: 1,
            coil_value: true,
        };
        assert_eq!(
            WriteSingleCoilRequest::decode(&request.encode()).unwrap(),
            request
        );
        let response = WriteSingleCoilResponse {
            coil_address: 1,
            coil_value: false,
        };
        assert_eq!(
            WriteSingleCoilResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn write_single_coil_decode_rejects_an_invalid_wire_value() {
        let bytes = encode_address_and_quantity(FUNCTION_CODE_WRITE_SINGLE_COIL, 1, 0x1234);
        assert_eq!(
            WriteSingleCoilRequest::decode(&bytes),
            Err(DecodeError::InvalidCoilValue { actual: 0x1234 })
        );
    }

    #[test]
    fn write_single_register_round_trips() {
        let request = WriteSingleRegisterRequest {
            register_address: 40001,
            register_value: 7,
        };
        assert_eq!(
            WriteSingleRegisterRequest::decode(&request.encode()).unwrap(),
            request
        );
        let response = WriteSingleRegisterResponse {
            register_address: 40001,
            register_value: 7,
        };
        assert_eq!(
            WriteSingleRegisterResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn mask_write_register_round_trips() {
        let request = MaskWriteRegisterRequest {
            reference_address: 1,
            and_mask: 0x00FF,
            or_mask: 0xFF00,
        };
        assert_eq!(
            MaskWriteRegisterRequest::decode(&request.encode()).unwrap(),
            request
        );
        let response = MaskWriteRegisterResponse {
            reference_address: 1,
            and_mask: 0x00FF,
            or_mask: 0xFF00,
        };
        assert_eq!(
            MaskWriteRegisterResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn report_server_id_request_round_trips() {
        assert_eq!(
            ReportServerIdRequest::decode(&ReportServerIdRequest.encode()).unwrap(),
            ReportServerIdRequest
        );
    }

    #[test]
    fn report_server_id_response_round_trips() {
        let response = ReportServerIdResponse {
            server_id: make_pdu_bytes(b"infused_modbus"),
            run_indicator_status: true,
        };
        let encoded = response.encode().unwrap();
        assert_eq!(ReportServerIdResponse::decode(&encoded).unwrap(), response);
    }

    #[test]
    fn report_server_id_response_encode_rejects_a_server_id_too_large_to_wrap() {
        let response = ReportServerIdResponse {
            server_id: make_pdu_bytes(&[0u8; MAX_PDU_LEN]),
            run_indicator_status: true,
        };
        assert_eq!(response.encode(), Err(EncodeError::TooLargeForBuffer));
    }

    #[test]
    fn read_write_multiple_registers_round_trips() {
        let request = ReadWriteMultipleRegistersRequest {
            read_starting_address: 1,
            read_quantity: 2,
            write_starting_address: 10,
            write_values: register_values(&[1, 2, 3]),
        };
        let encoded = request.encode().unwrap();
        assert_eq!(
            ReadWriteMultipleRegistersRequest::decode(&encoded).unwrap(),
            request
        );

        let response = ReadWriteMultipleRegistersResponse {
            register_values: register_values(&[9, 8]),
        };
        assert_eq!(
            ReadWriteMultipleRegistersResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn read_write_multiple_registers_request_encode_rejects_too_many_write_values() {
        let request = ReadWriteMultipleRegistersRequest {
            read_starting_address: 0,
            read_quantity: 0,
            write_starting_address: 0,
            write_values: register_values(
                &[0u16; MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT + 1],
            ),
        };
        assert_eq!(
            request.encode(),
            Err(EncodeError::TooManyRegisters {
                count: MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT + 1,
                max: MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT,
            })
        );
    }

    #[test]
    fn write_multiple_coils_round_trips() {
        let request = WriteMultipleCoilsRequest {
            starting_address: 1,
            coil_values: bit_values(&[true, false, true]),
        };
        assert_eq!(
            WriteMultipleCoilsRequest::decode(&request.encode()).unwrap(),
            request
        );

        let response = WriteMultipleCoilsResponse {
            starting_address: 1,
            quantity: 3,
        };
        assert_eq!(
            WriteMultipleCoilsResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn write_multiple_coils_decode_rejects_quantity_byte_count_mismatch() {
        let bytes = make_pdu_bytes(&[
            FUNCTION_CODE_WRITE_MULTIPLE_COILS,
            0,
            1, // starting_address = 1
            0,
            3, // quantity = 3 (correct byte_count would be 1, not 2)
            2, // byte_count = 2
            0xFF,
            0xFF,
        ]);
        assert_eq!(
            WriteMultipleCoilsRequest::decode(&bytes),
            Err(DecodeError::QuantityByteCountMismatch {
                quantity: 3,
                byte_count: 2,
            })
        );
    }

    #[test]
    fn write_multiple_registers_round_trips() {
        let request = WriteMultipleRegistersRequest {
            starting_address: 40001,
            register_values: register_values(&[1, 2, 3]),
        };
        let encoded = request.encode().unwrap();
        assert_eq!(
            WriteMultipleRegistersRequest::decode(&encoded).unwrap(),
            request
        );

        let response = WriteMultipleRegistersResponse {
            starting_address: 40001,
            quantity: 3,
        };
        assert_eq!(
            WriteMultipleRegistersResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn write_multiple_registers_request_encode_rejects_too_many_values() {
        let request = WriteMultipleRegistersRequest {
            starting_address: 0,
            register_values: register_values(&[0u16; MAX_WRITE_MULTIPLE_REGISTERS_COUNT + 1]),
        };
        assert_eq!(
            request.encode(),
            Err(EncodeError::TooManyRegisters {
                count: MAX_WRITE_MULTIPLE_REGISTERS_COUNT + 1,
                max: MAX_WRITE_MULTIPLE_REGISTERS_COUNT,
            })
        );
    }

    #[test]
    fn read_device_identification_request_round_trips() {
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id: 0x80,
        };
        assert_eq!(
            ReadDeviceIdentificationRequest::decode(&request.encode()).unwrap(),
            request
        );
    }

    #[test]
    fn read_device_identification_response_round_trips() {
        let mut objects = DeviceIdentificationObjects::new();
        objects.push(0x80, &[0x01]).unwrap();
        objects.push(0x81, b"infused_modbus").unwrap();
        let response = ReadDeviceIdentificationResponse {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            conformity_level: 0x83,
            more_follows: false,
            next_object_id: 0x00,
            objects,
        };
        let encoded = response.encode().unwrap();
        assert_eq!(
            ReadDeviceIdentificationResponse::decode(&encoded).unwrap(),
            response
        );
    }

    #[test]
    fn read_device_identification_response_encode_rejects_too_much_object_data() {
        let mut objects = DeviceIdentificationObjects::new();
        // 70 objects * 4 bytes each (2 overhead + 2-byte value) = 280 bytes,
        // comfortably overflows MAX_PDU_LEN (253) once the 7-byte response
        // header is added -- well under the 84-object/253-value-byte
        // container capacity either way, so this is purely exercising the
        // encode()-time total-size check, not the container's own limits.
        for _ in 0..70 {
            objects.push(0x81, &[0, 0]).unwrap();
        }
        let response = ReadDeviceIdentificationResponse {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            conformity_level: 0x83,
            more_follows: false,
            next_object_id: 0x00,
            objects,
        };
        assert_eq!(response.encode(), Err(EncodeError::TooLargeForBuffer));
    }

    #[test]
    fn read_file_record_round_trips() {
        let request = ReadFileRecordRequest {
            sub_requests: {
                let mut sub_requests = FileRecordSubRequests::new();
                sub_requests
                    .push(FileRecordSubRequest {
                        file_number: 20,
                        record_number: 5,
                        record_length: 9,
                    })
                    .unwrap();
                sub_requests
            },
        };
        assert_eq!(
            ReadFileRecordRequest::decode(&request.encode()).unwrap(),
            request
        );

        let response = ReadFileRecordResponse {
            records: {
                let mut records = FileRecordResponseData::new();
                records.push_record(&[1, 2, 3, 4]).unwrap();
                records
            },
        };
        let encoded = response.encode().unwrap();
        assert_eq!(ReadFileRecordResponse::decode(&encoded).unwrap(), response);
    }

    #[test]
    fn read_file_record_response_encode_rejects_too_much_record_data() {
        let mut records = FileRecordResponseData::new();
        for _ in 0..35 {
            records.push_record(&[0u8; 7]).unwrap();
        }
        let response = ReadFileRecordResponse { records };
        assert_eq!(response.encode(), Err(EncodeError::TooLargeForBuffer));
    }

    #[test]
    fn write_file_record_round_trips() {
        let mut sub_requests = WriteFileRecordSubRequests::new();
        sub_requests.push(20, 5, &[1, 2, 3, 4]).unwrap();
        let request = WriteFileRecordRequest { sub_requests };
        let encoded = request.encode().unwrap();
        assert_eq!(WriteFileRecordRequest::decode(&encoded).unwrap(), request);

        let mut sub_requests = WriteFileRecordSubRequests::new();
        sub_requests.push(20, 5, &[1, 2, 3, 4]).unwrap();
        let response = WriteFileRecordResponse { sub_requests };
        let encoded = response.encode().unwrap();
        assert_eq!(WriteFileRecordResponse::decode(&encoded).unwrap(), response);
    }

    #[test]
    fn write_file_record_encode_rejects_odd_record_data_length() {
        let mut sub_requests = WriteFileRecordSubRequests::new();
        sub_requests.push(1, 1, &[1, 2, 3]).unwrap();
        let request = WriteFileRecordRequest { sub_requests };
        assert_eq!(
            request.encode(),
            Err(EncodeError::OddFileRecordDataLength {
                file_number: 1,
                record_number: 1,
                length: 3,
            })
        );
    }

    #[test]
    fn exception_response_round_trips() {
        let response = ExceptionResponse {
            function_code: FUNCTION_CODE_READ_COILS,
            exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
        };
        let encoded = response.encode();
        assert_eq!(encoded.as_slice()[0], FUNCTION_CODE_READ_COILS | 0x80);
        assert_eq!(ExceptionResponse::decode(&encoded).unwrap(), response);
    }

    #[test]
    fn exception_response_decode_rejects_a_non_exception_response() {
        let bytes = ReadCoilsRequest {
            starting_address: 0,
            quantity: 1,
        }
        .encode();
        assert_eq!(
            ExceptionResponse::decode(&bytes),
            Err(DecodeError::NotAnExceptionResponse {
                function_code: FUNCTION_CODE_READ_COILS,
            })
        );
    }
}
