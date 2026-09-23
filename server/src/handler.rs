// Turning an incoming Modbus request PDU into a response PDU, backed by
// `RegisterStore`. Pure aside from locking the store — no network I/O here
// (see the module that actually accepts connections for that).
//
// Unlike the client, there's no real device to round-trip with: this
// process's own `RegisterStore` *is* the authoritative state a real Modbus
// client is asking about, so a successful write applies immediately, no
// separate confirmation step needed (contrast with CLAUDE.md's
// "TRANSACTION_END confirmation semantics", which is about the client
// talking to a real external device).
//
// Every DataType is served for both reads and writes now (see handle_read/
// handle_write_single/handle_write_multiple_registers) — mem_layout was the
// missing piece that made multi-register values a "we'd be guessing a wire
// format" problem; that's decided now, so there's no more scope boundary
// here beyond what each function code can physically carry (Write Single
// Register can only ever hold one wire word, hence
// DataType::register_count() == 1 types only — anything wider must go
// through Write Multiple Registers, matching the client's own dispatch
// choice in client::transaction_consumer). Coils get the same Read/Write
// treatment (Read Coils / Write Single Coil / Write Multiple Coils); a coil
// is always read/write (see
// protocol::device_description::CoilDescription's own doc comment), so
// unlike registers there's no access-right check on the write side.
//
// Both "write multiple" handlers validate every address in the request
// before applying anything — a bad address partway through the batch
// rejects the whole request with no partial write, rather than applying
// a prefix and leaving the store in a state that doesn't match either the
// old or the fully-requested new one.

use crate::device_identification::{build_objects, handle_read_device_identification};
use fuse_fs::register_encoding::{register_value_from_words, register_value_to_words};
use fuse_fs::{
    CoilStore, CoilValue, DiscreteInputStore, InputRegisterStore, RegisterStore, RegisterValue,
};
use protocol::device_description::{
    AccessRight, CoilDescription, DataType, DiscreteInputDescription, InputRegisterDescription,
    MemLayout, RegisterDescription,
};
use protocol::pdu::{
    EXCEPTION_ILLEGAL_DATA_ADDRESS, EXCEPTION_ILLEGAL_DATA_VALUE, EXCEPTION_ILLEGAL_FUNCTION,
    ExceptionResponse, FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
    FUNCTION_CODE_MASK_WRITE_REGISTER, FUNCTION_CODE_READ_COILS,
    FUNCTION_CODE_READ_DISCRETE_INPUTS, FUNCTION_CODE_READ_HOLDING_REGISTERS,
    FUNCTION_CODE_READ_INPUT_REGISTERS, FUNCTION_CODE_REPORT_SERVER_ID,
    FUNCTION_CODE_WRITE_MULTIPLE_COILS, FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
    FUNCTION_CODE_WRITE_SINGLE_COIL, FUNCTION_CODE_WRITE_SINGLE_REGISTER, MaskWriteRegisterRequest,
    MaskWriteRegisterResponse, ReadCoilsRequest, ReadCoilsResponse,
    ReadDeviceIdentificationRequest, ReadDiscreteInputsRequest, ReadDiscreteInputsResponse,
    ReadHoldingRegistersRequest, ReadHoldingRegistersResponse, ReadInputRegistersRequest,
    ReadInputRegistersResponse, ReportServerIdRequest, ReportServerIdResponse,
    WriteMultipleCoilsRequest, WriteMultipleCoilsResponse, WriteMultipleRegistersRequest,
    WriteMultipleRegistersResponse, WriteSingleCoilRequest, WriteSingleCoilResponse,
    WriteSingleRegisterRequest, WriteSingleRegisterResponse,
};
use std::sync::{Mutex, PoisonError};

#[allow(clippy::too_many_arguments)]
pub fn handle_request(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
    coils: &[CoilDescription],
    coil_store: &Mutex<CoilStore>,
    discrete_inputs: &[DiscreteInputDescription],
    discrete_input_store: &Mutex<DiscreteInputStore>,
    input_registers: &[InputRegisterDescription],
    input_register_store: &Mutex<InputRegisterStore>,
    mem_layout: MemLayout,
    input_register_mem_layout: MemLayout,
    toml_source: &str,
    server_id: Option<&str>,
) -> Vec<u8> {
    let Some(&function_code) = pdu.first() else {
        return ExceptionResponse {
            function_code: 0,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode();
    };

    match function_code {
        FUNCTION_CODE_READ_HOLDING_REGISTERS => handle_read(pdu, registers, store, mem_layout),
        FUNCTION_CODE_WRITE_SINGLE_REGISTER => {
            handle_write_single(pdu, registers, store, mem_layout)
        }
        FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS => {
            handle_write_multiple_registers(pdu, registers, store, mem_layout)
        }
        FUNCTION_CODE_MASK_WRITE_REGISTER => {
            handle_mask_write_register(pdu, registers, store, mem_layout)
        }
        FUNCTION_CODE_REPORT_SERVER_ID => handle_report_server_id(pdu, server_id),
        FUNCTION_CODE_READ_COILS => handle_read_coils(pdu, coils, coil_store),
        FUNCTION_CODE_WRITE_SINGLE_COIL => handle_write_single_coil(pdu, coils, coil_store),
        FUNCTION_CODE_WRITE_MULTIPLE_COILS => handle_write_multiple_coils(pdu, coils, coil_store),
        FUNCTION_CODE_READ_DISCRETE_INPUTS => {
            handle_read_discrete_inputs(pdu, discrete_inputs, discrete_input_store)
        }
        FUNCTION_CODE_READ_INPUT_REGISTERS => handle_read_input_registers(
            pdu,
            input_registers,
            input_register_store,
            input_register_mem_layout,
        ),
        FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT => {
            handle_encapsulated_interface_transport(pdu, toml_source)
        }
        _ => ExceptionResponse {
            function_code,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode(),
    }
}

// See device_identification.rs for the object layout and continuation
// handling; this just decodes the request PDU and hands off to it. MEI
// types other than Read Device Identification (0x0E) — only CANopen,
// 0x0D, exists in the spec — aren't implemented, hence the plain
// ILLEGAL_FUNCTION fallback in the decode-failure branch (decode() itself
// distinguishes "wrong MEI type" from other malformed-request cases, but
// there's no other MEI type to dispatch to yet, so it collapses to the
// same response here).
fn handle_encapsulated_interface_transport(pdu: &[u8], toml_source: &str) -> Vec<u8> {
    let Ok(request) = ReadDeviceIdentificationRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode();
    };
    let objects = build_objects(toml_source);
    handle_read_device_identification(&request, &objects)
}

// Zero (or 0.0) for every DataType — what an unset register reads back as,
// same meaning "no value staged/confirmed yet" as U16's old bare `0` did.
fn default_register_value(data_type: DataType) -> RegisterValue {
    match data_type {
        DataType::U8 => RegisterValue::U8(0),
        DataType::I8 => RegisterValue::I8(0),
        DataType::U16 => RegisterValue::U16(0),
        DataType::I16 => RegisterValue::I16(0),
        DataType::U24 => RegisterValue::U24(0),
        DataType::I24 => RegisterValue::I24(0),
        DataType::U32 => RegisterValue::U32(0),
        DataType::I32 => RegisterValue::I32(0),
        DataType::U64 => RegisterValue::U64(0),
        DataType::I64 => RegisterValue::I64(0),
        DataType::F32 => RegisterValue::F32(0.0),
        DataType::F64 => RegisterValue::F64(0.0),
    }
}

fn handle_read(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
    mem_layout: MemLayout,
) -> Vec<u8> {
    let Ok(request) = ReadHoldingRegistersRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    let store = store.lock().unwrap_or_else(PoisonError::into_inner);
    let mut register_values = Vec::with_capacity(request.quantity as usize);
    let mut address = request.starting_address;
    let end_address = request.starting_address.wrapping_add(request.quantity);
    // Walk register-by-register (not address-by-address): a register only
    // exists at its own starting address, so a request that lands mid-way
    // through a multi-register value, spans past one register into an
    // address gap, or doesn't end exactly on a register boundary has no
    // well-defined answer and is rejected rather than guessed at.
    while address != end_address {
        let Some(register) = registers
            .iter()
            .find(|register| register.address == address)
        else {
            return ExceptionResponse {
                function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
            .encode();
        };

        let value = match store.get(&register.name) {
            Some(value) if value.data_type() == register.data_type => value,
            _ => default_register_value(register.data_type),
        };
        let words = register_value_to_words(value, mem_layout);

        if register_values.len() + words.len() > request.quantity as usize {
            return ExceptionResponse {
                function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
            .encode();
        }
        register_values.extend(words);
        address = address.wrapping_add(register.data_type.register_count());
    }
    ReadHoldingRegistersResponse { register_values }.encode()
}

// Write Single Register (FC6) can only ever carry exactly one wire word —
// that's the function code's own shape, not a scope decision — so only
// DataType::register_count() == 1 types (U8/I8/U16/I16) can be served this
// way at all; anything wider must go through Write Multiple Registers
// (FC16, handle_write_multiple_registers below), same as the client only
// ever sends FC6 for a single one-register-wide value (see
// client::transaction_consumer).
fn handle_write_single(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
    mem_layout: MemLayout,
) -> Vec<u8> {
    let Ok(request) = WriteSingleRegisterRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_WRITE_SINGLE_REGISTER,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    let register = registers.iter().find(|register| {
        register.address == request.register_address
            && register.data_type.register_count() == 1
            && register.access == AccessRight::ReadWrite
    });
    match register {
        Some(register) => {
            // Always Some: register_count() == 1 was just checked above,
            // matching the one-word slice given here.
            let value = register_value_from_words(
                register.data_type,
                &[request.register_value],
                mem_layout,
            )
            .expect("a single word always decodes for a 1-register-wide DataType");
            store
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .set(register.name.clone(), value);
            WriteSingleRegisterResponse {
                register_address: request.register_address,
                register_value: request.register_value,
            }
            .encode()
        }
        // Covers three cases alike: no register at this address, a
        // register too wide for FC6, and a read-only register — all "you
        // can't write here [this way]".
        None => ExceptionResponse {
            function_code: FUNCTION_CODE_WRITE_SINGLE_REGISTER,
            exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
        }
        .encode(),
    }
}

// Mask Write Register (FC 0x16) modifies a single existing register's
// contents in place — `result = (current AND and_mask) OR (or_mask AND (NOT
// and_mask))` — rather than replacing them outright. Same 1-register-wide
// scope as Write Single Register (FC6, handle_write_single above), for the
// same reason: the function code has no way to address more than one wire
// word. The read of the current value and the write of the new one happen
// under one held lock, not two separate lock acquisitions, so a concurrent
// write to the same register can't land between them and get silently
// overwritten.
fn handle_mask_write_register(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
    mem_layout: MemLayout,
) -> Vec<u8> {
    let Ok(request) = MaskWriteRegisterRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_MASK_WRITE_REGISTER,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    let register = registers.iter().find(|register| {
        register.address == request.reference_address
            && register.data_type.register_count() == 1
            && register.access == AccessRight::ReadWrite
    });
    match register {
        Some(register) => {
            let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
            let current_value = match store.get(&register.name) {
                Some(value) if value.data_type() == register.data_type => value,
                _ => default_register_value(register.data_type),
            };
            // Always exactly one word: register_count() == 1 was just
            // checked above.
            let current_word = register_value_to_words(current_value, mem_layout)[0];
            let new_word =
                (current_word & request.and_mask) | (request.or_mask & !request.and_mask);
            let new_value = register_value_from_words(register.data_type, &[new_word], mem_layout)
                .expect("a single word always decodes for a 1-register-wide DataType");
            store.set(register.name.clone(), new_value);
            MaskWriteRegisterResponse {
                reference_address: request.reference_address,
                and_mask: request.and_mask,
                or_mask: request.or_mask,
            }
            .encode()
        }
        // Covers the same three cases as handle_write_single: no register
        // at this address, a register too wide for this FC, and a
        // read-only register.
        None => ExceptionResponse {
            function_code: FUNCTION_CODE_MASK_WRITE_REGISTER,
            exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
        }
        .encode(),
    }
}

// Report Server ID (FC 0x11) — `server_id` comes straight from the
// device-description TOML's optional `server-id` field (see CLAUDE.md's
// "FC 0x11 (Report Server ID)" section); this handler has no store/register
// involvement at all, unlike every other dispatch target in this file.
// Unconfigured (`None`) responds exactly like a function code this crate
// never implemented at all — the same ILLEGAL_FUNCTION exception, not a
// response with an empty server_id — since answering with nothing
// meaningful isn't really "supporting" the function code.
fn handle_report_server_id(pdu: &[u8], server_id: Option<&str>) -> Vec<u8> {
    let Ok(_request) = ReportServerIdRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_REPORT_SERVER_ID,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode();
    };
    match server_id {
        Some(server_id) => ReportServerIdResponse {
            server_id: server_id.as_bytes().to_vec(),
            run_indicator_status: true,
        }
        .encode(),
        None => ExceptionResponse {
            function_code: FUNCTION_CODE_REPORT_SERVER_ID,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode(),
    }
}

fn handle_write_multiple_registers(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
    mem_layout: MemLayout,
) -> Vec<u8> {
    let Ok(request) = WriteMultipleRegistersRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    // Walk register-by-register, same shape as handle_read: only a
    // register's own starting address is a valid boundary, so a value
    // wider than one register consumes that many words from the request
    // before moving on to the next register's address.
    let mut resolved: Vec<(&RegisterDescription, RegisterValue)> = Vec::new();
    let mut address = request.starting_address;
    let end_address = request
        .starting_address
        .wrapping_add(request.register_values.len() as u16);
    let mut offset = 0usize;
    while address != end_address {
        let Some(register) = registers.iter().find(|register| {
            register.address == address && register.access == AccessRight::ReadWrite
        }) else {
            return ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
            .encode();
        };

        let register_count = register.data_type.register_count() as usize;
        if offset + register_count > request.register_values.len() {
            return ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
            .encode();
        }
        let words = &request.register_values[offset..offset + register_count];
        // Always Some: `words` is exactly `register_count` long by
        // construction above.
        let value = register_value_from_words(register.data_type, words, mem_layout)
            .expect("word slice length always matches the register's own width");
        resolved.push((register, value));
        offset += register_count;
        address = address.wrapping_add(register.data_type.register_count());
    }

    let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
    for (register, value) in resolved {
        store.set(register.name.clone(), value);
    }
    WriteMultipleRegistersResponse {
        starting_address: request.starting_address,
        quantity: request.register_values.len() as u16,
    }
    .encode()
}

fn handle_read_coils(
    pdu: &[u8],
    coils: &[CoilDescription],
    coil_store: &Mutex<CoilStore>,
) -> Vec<u8> {
    let Ok(request) = ReadCoilsRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_READ_COILS,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    let coil_store = coil_store.lock().unwrap_or_else(PoisonError::into_inner);
    let mut coil_values = Vec::with_capacity(request.quantity as usize);
    for offset in 0..request.quantity {
        let address = request.starting_address.wrapping_add(offset);
        match coils.iter().find(|coil| coil.address == address) {
            Some(coil) => {
                let value = coil_store.get(&coil.name).is_some_and(|value| value.0);
                coil_values.push(value);
            }
            None => {
                return ExceptionResponse {
                    function_code: FUNCTION_CODE_READ_COILS,
                    exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
                }
                .encode();
            }
        }
    }
    ReadCoilsResponse { coil_values }.encode()
}

// Read-only counterpart of handle_read_coils — same packed-bit response
// shape, same "missing value defaults to false" behavior, just backed by
// DiscreteInputStore instead of CoilStore. No write-side handler exists
// for this, on purpose: no Modbus function code ever lets a master write a
// discrete input (see protocol::device_description::DiscreteInputDescription's
// own doc comment).
fn handle_read_discrete_inputs(
    pdu: &[u8],
    discrete_inputs: &[DiscreteInputDescription],
    discrete_input_store: &Mutex<DiscreteInputStore>,
) -> Vec<u8> {
    let Ok(request) = ReadDiscreteInputsRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_READ_DISCRETE_INPUTS,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    let discrete_input_store = discrete_input_store
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut discrete_input_values = Vec::with_capacity(request.quantity as usize);
    for offset in 0..request.quantity {
        let address = request.starting_address.wrapping_add(offset);
        match discrete_inputs
            .iter()
            .find(|discrete_input| discrete_input.address == address)
        {
            Some(discrete_input) => {
                let value = discrete_input_store
                    .get(&discrete_input.name)
                    .is_some_and(|value| value.0);
                discrete_input_values.push(value);
            }
            None => {
                return ExceptionResponse {
                    function_code: FUNCTION_CODE_READ_DISCRETE_INPUTS,
                    exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
                }
                .encode();
            }
        }
    }
    ReadDiscreteInputsResponse {
        discrete_input_values,
    }
    .encode()
}

// Read-only counterpart of handle_read — same register-by-register walk
// and multi-register assembly, just backed by InputRegisterStore and its
// own mem_layout instead of RegisterStore's. No write-side handler exists
// for this, on purpose, same reasoning as handle_read_discrete_inputs
// above.
fn handle_read_input_registers(
    pdu: &[u8],
    input_registers: &[InputRegisterDescription],
    input_register_store: &Mutex<InputRegisterStore>,
    input_register_mem_layout: MemLayout,
) -> Vec<u8> {
    let Ok(request) = ReadInputRegistersRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_READ_INPUT_REGISTERS,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    let store = input_register_store
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut register_values = Vec::with_capacity(request.quantity as usize);
    let mut address = request.starting_address;
    let end_address = request.starting_address.wrapping_add(request.quantity);
    while address != end_address {
        let Some(input_register) = input_registers
            .iter()
            .find(|input_register| input_register.address == address)
        else {
            return ExceptionResponse {
                function_code: FUNCTION_CODE_READ_INPUT_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
            .encode();
        };

        let value = match store.get(&input_register.name) {
            Some(value) if value.data_type() == input_register.data_type => value,
            _ => default_register_value(input_register.data_type),
        };
        let words = register_value_to_words(value, input_register_mem_layout);

        if register_values.len() + words.len() > request.quantity as usize {
            return ExceptionResponse {
                function_code: FUNCTION_CODE_READ_INPUT_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
            .encode();
        }
        register_values.extend(words);
        address = address.wrapping_add(input_register.data_type.register_count());
    }
    ReadInputRegistersResponse { register_values }.encode()
}

fn handle_write_single_coil(
    pdu: &[u8],
    coils: &[CoilDescription],
    coil_store: &Mutex<CoilStore>,
) -> Vec<u8> {
    let Ok(request) = WriteSingleCoilRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_WRITE_SINGLE_COIL,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    match coils
        .iter()
        .find(|coil| coil.address == request.coil_address)
    {
        Some(coil) => {
            coil_store
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .set(coil.name.clone(), CoilValue(request.coil_value));
            WriteSingleCoilResponse {
                coil_address: request.coil_address,
                coil_value: request.coil_value,
            }
            .encode()
        }
        None => ExceptionResponse {
            function_code: FUNCTION_CODE_WRITE_SINGLE_COIL,
            exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
        }
        .encode(),
    }
}

fn handle_write_multiple_coils(
    pdu: &[u8],
    coils: &[CoilDescription],
    coil_store: &Mutex<CoilStore>,
) -> Vec<u8> {
    let Ok(request) = WriteMultipleCoilsRequest::decode(pdu) else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_WRITE_MULTIPLE_COILS,
            exception_code: EXCEPTION_ILLEGAL_DATA_VALUE,
        }
        .encode();
    };

    let mut resolved = Vec::with_capacity(request.coil_values.len());
    for (offset, &value) in request.coil_values.iter().enumerate() {
        let address = request.starting_address.wrapping_add(offset as u16);
        match coils.iter().find(|coil| coil.address == address) {
            Some(coil) => resolved.push((coil, value)),
            None => {
                return ExceptionResponse {
                    function_code: FUNCTION_CODE_WRITE_MULTIPLE_COILS,
                    exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
                }
                .encode();
            }
        }
    }

    let mut coil_store = coil_store.lock().unwrap_or_else(PoisonError::into_inner);
    for (coil, value) in resolved {
        coil_store.set(coil.name.clone(), CoilValue(value));
    }
    WriteMultipleCoilsResponse {
        starting_address: request.starting_address,
        quantity: request.coil_values.len() as u16,
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registers() -> Vec<RegisterDescription> {
        vec![
            RegisterDescription {
                name: "Tank_Temperature".to_string(),
                address: 40001,
                data_type: DataType::U16,
                access: AccessRight::ReadOnly,
            },
            RegisterDescription {
                name: "Stop_Process".to_string(),
                address: 40002,
                data_type: DataType::U16,
                access: AccessRight::ReadWrite,
            },
            RegisterDescription {
                name: "Flow_Rate".to_string(),
                address: 40003,
                data_type: DataType::F32,
                access: AccessRight::ReadOnly,
            },
            RegisterDescription {
                name: "Valve_1".to_string(),
                address: 40010,
                data_type: DataType::U16,
                access: AccessRight::ReadWrite,
            },
            RegisterDescription {
                name: "Valve_2".to_string(),
                address: 40011,
                data_type: DataType::U16,
                access: AccessRight::ReadWrite,
            },
            RegisterDescription {
                name: "Precise_Value".to_string(),
                address: 40020,
                data_type: DataType::F64,
                access: AccessRight::ReadWrite,
            },
        ]
    }

    fn coils() -> Vec<CoilDescription> {
        vec![
            CoilDescription {
                name: "Motor_Running".to_string(),
                address: 1,
            },
            CoilDescription {
                name: "Alarm_Reset".to_string(),
                address: 2,
            },
        ]
    }

    fn discrete_inputs() -> Vec<DiscreteInputDescription> {
        vec![
            DiscreteInputDescription {
                name: "Door_Open_Sensor".to_string(),
                address: 1,
            },
            DiscreteInputDescription {
                name: "Emergency_Stop_Pressed".to_string(),
                address: 2,
            },
        ]
    }

    fn input_registers() -> Vec<InputRegisterDescription> {
        vec![
            InputRegisterDescription {
                name: "Pressure".to_string(),
                address: 30001,
                data_type: DataType::U16,
            },
            InputRegisterDescription {
                name: "Flow_Rate".to_string(),
                address: 30002,
                data_type: DataType::F32,
            },
        ]
    }

    #[test]
    fn read_returns_current_store_values() {
        let store = Mutex::new(RegisterStore::new());
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(72));
        let coil_store = Mutex::new(CoilStore::new());

        let request = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ReadHoldingRegistersResponse::decode(&response).unwrap(),
            ReadHoldingRegistersResponse {
                register_values: vec![72]
            }
        );
    }

    #[test]
    fn read_defaults_to_zero_for_a_register_with_no_value_yet() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ReadHoldingRegistersResponse::decode(&response).unwrap(),
            ReadHoldingRegistersResponse {
                register_values: vec![0]
            }
        );
    }

    #[test]
    fn read_of_unknown_address_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReadHoldingRegistersRequest {
            starting_address: 49999,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }

    #[test]
    fn read_with_a_quantity_smaller_than_the_register_s_width_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // Flow_Rate is F32 (2 registers wide) — asking for only 1 register
        // starting at its address can't be answered, since the value
        // doesn't fit in what was actually requested.
        let request = ReadHoldingRegistersRequest {
            starting_address: 40003,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }

    #[test]
    fn read_starting_mid_way_through_a_multi_register_value_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // 40004 is Flow_Rate's second word (F32 spans 40003-40004), not a
        // register's own starting address — nothing is described as
        // starting there.
        let request = ReadHoldingRegistersRequest {
            starting_address: 40004,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }

    #[test]
    fn read_returns_a_correctly_assembled_multi_register_value() {
        use fuse_fs::register_encoding::register_value_from_words;

        let store = Mutex::new(RegisterStore::new());
        store
            .lock()
            .unwrap()
            .set("Flow_Rate", RegisterValue::F32(3.5));
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReadHoldingRegistersRequest {
            starting_address: 40003,
            quantity: 2,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Cdab,
            MemLayout::Abcd,
            "",
            None,
        );

        let decoded = ReadHoldingRegistersResponse::decode(&response).unwrap();
        let value =
            register_value_from_words(DataType::F32, &decoded.register_values, MemLayout::Cdab)
                .unwrap();
        assert_eq!(value, RegisterValue::F32(3.5));
    }

    #[test]
    fn write_single_applies_to_the_store_and_echoes_the_request() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = WriteSingleRegisterRequest {
            register_address: 40002,
            register_value: 1,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            WriteSingleRegisterResponse::decode(&response).unwrap(),
            WriteSingleRegisterResponse {
                register_address: 40002,
                register_value: 1,
            }
        );
        assert_eq!(
            store.lock().unwrap().get("Stop_Process"),
            Some(RegisterValue::U16(1))
        );
    }

    #[test]
    fn write_single_to_a_read_only_register_returns_an_exception_and_does_not_apply() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = WriteSingleRegisterRequest {
            register_address: 40001,
            register_value: 99,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_SINGLE_REGISTER,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
        assert_eq!(store.lock().unwrap().get("Tank_Temperature"), None);
    }

    #[test]
    fn write_single_of_a_multi_register_type_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // Precise_Value is F64 (4 registers wide) and read/write — Write
        // Single Register (FC6) can only ever carry one wire word, so
        // this can never succeed no matter the access rights.
        let request = WriteSingleRegisterRequest {
            register_address: 40020,
            register_value: 0x3FF0,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_SINGLE_REGISTER,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
        assert_eq!(store.lock().unwrap().get("Precise_Value"), None);
    }

    #[test]
    fn mask_write_register_applies_mask_to_existing_value_and_echoes_the_request() {
        // Current=0x0012, And=0x00F2, Or=0x0025 -> Result=0x0017 is the
        // Modbus spec's own worked example (Application Protocol V1.1b3,
        // section 6.8) — reused here rather than an arbitrary value so the
        // expected result is independently verifiable against the spec.
        let store = Mutex::new(RegisterStore::new());
        store
            .lock()
            .unwrap()
            .set("Stop_Process", RegisterValue::U16(0x0012));
        let coil_store = Mutex::new(CoilStore::new());
        let request = MaskWriteRegisterRequest {
            reference_address: 40002,
            and_mask: 0x00F2,
            or_mask: 0x0025,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            MaskWriteRegisterResponse::decode(&response).unwrap(),
            MaskWriteRegisterResponse {
                reference_address: 40002,
                and_mask: 0x00F2,
                or_mask: 0x0025,
            }
        );
        assert_eq!(
            store.lock().unwrap().get("Stop_Process"),
            Some(RegisterValue::U16(0x0017))
        );
    }

    #[test]
    fn mask_write_register_to_a_read_only_register_returns_an_exception_and_does_not_apply() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = MaskWriteRegisterRequest {
            reference_address: 40001,
            and_mask: 0x0000,
            or_mask: 0xFFFF,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_MASK_WRITE_REGISTER,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
        assert_eq!(store.lock().unwrap().get("Tank_Temperature"), None);
    }

    #[test]
    fn mask_write_register_of_a_multi_register_type_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // Precise_Value is F64 (4 registers wide) and read/write — Mask
        // Write Register, like Write Single Register, can only ever carry
        // one wire word, so this can never succeed no matter the access
        // rights.
        let request = MaskWriteRegisterRequest {
            reference_address: 40020,
            and_mask: 0x0000,
            or_mask: 0xFFFF,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_MASK_WRITE_REGISTER,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
        assert_eq!(store.lock().unwrap().get("Precise_Value"), None);
    }

    #[test]
    fn report_server_id_responds_with_the_configured_id_when_present() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReportServerIdRequest.encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            Some("infused_modbus-demo-plc"),
        );

        assert_eq!(
            ReportServerIdResponse::decode(&response).unwrap(),
            ReportServerIdResponse {
                server_id: b"infused_modbus-demo-plc".to_vec(),
                run_indicator_status: true,
            }
        );
    }

    #[test]
    fn report_server_id_without_a_configured_id_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReportServerIdRequest.encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_REPORT_SERVER_ID,
                exception_code: EXCEPTION_ILLEGAL_FUNCTION,
            }
        );
    }

    #[test]
    fn write_multiple_registers_applies_all_and_echoes_the_request() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = WriteMultipleRegistersRequest {
            starting_address: 40010,
            register_values: vec![11, 22],
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            WriteMultipleRegistersResponse::decode(&response).unwrap(),
            WriteMultipleRegistersResponse {
                starting_address: 40010,
                quantity: 2,
            }
        );
        assert_eq!(
            store.lock().unwrap().get("Valve_1"),
            Some(RegisterValue::U16(11))
        );
        assert_eq!(
            store.lock().unwrap().get("Valve_2"),
            Some(RegisterValue::U16(22))
        );
    }

    #[test]
    fn write_multiple_registers_writes_a_correctly_assembled_multi_register_value() {
        use fuse_fs::register_encoding::register_value_to_words;

        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let words = register_value_to_words(RegisterValue::F64(3.5), MemLayout::Dcba);
        let request = WriteMultipleRegistersRequest {
            starting_address: 40020,
            register_values: words,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Dcba,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            WriteMultipleRegistersResponse::decode(&response).unwrap(),
            WriteMultipleRegistersResponse {
                starting_address: 40020,
                quantity: 4,
            }
        );
        assert_eq!(
            store.lock().unwrap().get("Precise_Value"),
            Some(RegisterValue::F64(3.5))
        );
    }

    #[test]
    fn write_multiple_registers_rejects_the_whole_batch_without_partial_apply_on_a_bad_address() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // First address (40001, Tank_Temperature) is read-only and should
        // reject the whole request; the second address (40002,
        // Stop_Process) is writable on its own, so this also proves a
        // valid address later in the batch doesn't get applied either.
        let request = WriteMultipleRegistersRequest {
            starting_address: 40001,
            register_values: vec![1, 2],
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_MULTIPLE_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
        // Stop_Process (40002, the second address in this batch) is
        // writable, but nothing should have been applied since the first
        // address (40001, Tank_Temperature) is read-only.
        assert_eq!(store.lock().unwrap().get("Stop_Process"), None);
    }

    #[test]
    fn unimplemented_function_code_returns_illegal_function() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // Report Server ID (0x11) — not implemented at all.
        let request = vec![0x11, 0x00, 0x00, 0x00, 0x01];
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: 0x11,
                exception_code: EXCEPTION_ILLEGAL_FUNCTION,
            }
        );
    }

    #[test]
    fn empty_pdu_returns_illegal_function_without_panicking() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let response = handle_request(
            &[],
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap().exception_code,
            EXCEPTION_ILLEGAL_FUNCTION
        );
    }

    #[test]
    fn dispatches_encapsulated_interface_transport_requests() {
        use protocol::pdu::{
            READ_DEVICE_ID_EXTENDED, ReadDeviceIdentificationRequest,
            ReadDeviceIdentificationResponse,
        };

        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id: 0x80,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "name = \"X\"",
            None,
        );

        let decoded = ReadDeviceIdentificationResponse::decode(&response).unwrap();
        assert_eq!(decoded.objects[0].id, 0x80);
        assert_eq!(decoded.objects[0].value, vec![0x01]);
    }

    #[test]
    fn read_coils_returns_current_store_values() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        coil_store
            .lock()
            .unwrap()
            .set("Motor_Running", CoilValue(true));

        let request = ReadCoilsRequest {
            starting_address: 1,
            quantity: 2,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ReadCoilsResponse::decode(&response).unwrap(),
            ReadCoilsResponse {
                coil_values: vec![true, false, false, false, false, false, false, false]
            }
        );
    }

    #[test]
    fn read_coils_defaults_to_false_for_a_coil_with_no_value_yet() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReadCoilsRequest {
            starting_address: 1,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ReadCoilsResponse::decode(&response).unwrap(),
            ReadCoilsResponse {
                coil_values: vec![false; 8]
            }
        );
    }

    #[test]
    fn read_coils_of_unknown_address_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReadCoilsRequest {
            starting_address: 99,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_COILS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }

    #[test]
    fn write_single_coil_applies_to_the_store_and_echoes_the_request() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = WriteSingleCoilRequest {
            coil_address: 1,
            coil_value: true,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            WriteSingleCoilResponse::decode(&response).unwrap(),
            WriteSingleCoilResponse {
                coil_address: 1,
                coil_value: true,
            }
        );
        assert_eq!(
            coil_store.lock().unwrap().get("Motor_Running"),
            Some(CoilValue(true))
        );
    }

    #[test]
    fn write_single_coil_of_unknown_address_returns_an_exception_and_does_not_apply() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = WriteSingleCoilRequest {
            coil_address: 99,
            coil_value: true,
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_SINGLE_COIL,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }

    #[test]
    fn write_multiple_coils_applies_all_and_echoes_the_request() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = WriteMultipleCoilsRequest {
            starting_address: 1,
            coil_values: vec![true, false],
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            WriteMultipleCoilsResponse::decode(&response).unwrap(),
            WriteMultipleCoilsResponse {
                starting_address: 1,
                quantity: 2,
            }
        );
        assert_eq!(
            coil_store.lock().unwrap().get("Motor_Running"),
            Some(CoilValue(true))
        );
        assert_eq!(
            coil_store.lock().unwrap().get("Alarm_Reset"),
            Some(CoilValue(false))
        );
    }

    #[test]
    fn write_multiple_coils_rejects_the_whole_batch_without_partial_apply_on_a_bad_address() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // Address 1 (Motor_Running) is valid, but address 2 doesn't exist
        // in this fixture beyond Alarm_Reset — use an out-of-range third
        // address instead so the batch starts valid and then rejects.
        let request = WriteMultipleCoilsRequest {
            starting_address: 1,
            coil_values: vec![true, true, true],
        }
        .encode();

        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &Vec::new(),
            &Mutex::new(DiscreteInputStore::new()),
            &Vec::new(),
            &Mutex::new(InputRegisterStore::new()),
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_MULTIPLE_COILS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
        assert_eq!(coil_store.lock().unwrap().get("Motor_Running"), None);
        assert_eq!(coil_store.lock().unwrap().get("Alarm_Reset"), None);
    }

    #[test]
    fn read_discrete_inputs_returns_current_store_values() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let discrete_input_store = Mutex::new(DiscreteInputStore::new());
        discrete_input_store
            .lock()
            .unwrap()
            .set("Door_Open_Sensor", CoilValue(true));
        let input_register_store = Mutex::new(InputRegisterStore::new());

        let request = ReadDiscreteInputsRequest {
            starting_address: 1,
            quantity: 2,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &discrete_inputs(),
            &discrete_input_store,
            &input_registers(),
            &input_register_store,
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ReadDiscreteInputsResponse::decode(&response).unwrap(),
            ReadDiscreteInputsResponse {
                discrete_input_values: vec![true, false, false, false, false, false, false, false]
            }
        );
    }

    #[test]
    fn read_discrete_inputs_defaults_to_false_for_an_input_with_no_value_yet() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let discrete_input_store = Mutex::new(DiscreteInputStore::new());
        let input_register_store = Mutex::new(InputRegisterStore::new());

        let request = ReadDiscreteInputsRequest {
            starting_address: 1,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &discrete_inputs(),
            &discrete_input_store,
            &input_registers(),
            &input_register_store,
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ReadDiscreteInputsResponse::decode(&response).unwrap(),
            ReadDiscreteInputsResponse {
                discrete_input_values: vec![false; 8]
            }
        );
    }

    #[test]
    fn read_discrete_inputs_of_unknown_address_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let discrete_input_store = Mutex::new(DiscreteInputStore::new());
        let input_register_store = Mutex::new(InputRegisterStore::new());

        let request = ReadDiscreteInputsRequest {
            starting_address: 99,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &discrete_inputs(),
            &discrete_input_store,
            &input_registers(),
            &input_register_store,
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_DISCRETE_INPUTS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }

    #[test]
    fn read_input_registers_returns_current_store_values() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let discrete_input_store = Mutex::new(DiscreteInputStore::new());
        let input_register_store = Mutex::new(InputRegisterStore::new());
        input_register_store
            .lock()
            .unwrap()
            .set("Pressure", RegisterValue::U16(1013));

        let request = ReadInputRegistersRequest {
            starting_address: 30001,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &discrete_inputs(),
            &discrete_input_store,
            &input_registers(),
            &input_register_store,
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ReadInputRegistersResponse::decode(&response).unwrap(),
            ReadInputRegistersResponse {
                register_values: vec![1013]
            }
        );
    }

    #[test]
    fn read_input_registers_defaults_to_zero_for_a_register_with_no_value_yet() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let discrete_input_store = Mutex::new(DiscreteInputStore::new());
        let input_register_store = Mutex::new(InputRegisterStore::new());

        let request = ReadInputRegistersRequest {
            starting_address: 30001,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &discrete_inputs(),
            &discrete_input_store,
            &input_registers(),
            &input_register_store,
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ReadInputRegistersResponse::decode(&response).unwrap(),
            ReadInputRegistersResponse {
                register_values: vec![0]
            }
        );
    }

    #[test]
    fn read_input_registers_returns_a_correctly_assembled_multi_register_value() {
        use fuse_fs::register_encoding::register_value_from_words;

        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let discrete_input_store = Mutex::new(DiscreteInputStore::new());
        let input_register_store = Mutex::new(InputRegisterStore::new());
        input_register_store
            .lock()
            .unwrap()
            .set("Flow_Rate", RegisterValue::F32(3.5));

        let request = ReadInputRegistersRequest {
            starting_address: 30002,
            quantity: 2,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &discrete_inputs(),
            &discrete_input_store,
            &input_registers(),
            &input_register_store,
            MemLayout::Abcd,
            MemLayout::Cdab,
            "",
            None,
        );

        let decoded = ReadInputRegistersResponse::decode(&response).unwrap();
        let value =
            register_value_from_words(DataType::F32, &decoded.register_values, MemLayout::Cdab)
                .unwrap();
        assert_eq!(value, RegisterValue::F32(3.5));
    }

    #[test]
    fn read_input_registers_of_unknown_address_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let discrete_input_store = Mutex::new(DiscreteInputStore::new());
        let input_register_store = Mutex::new(InputRegisterStore::new());

        let request = ReadInputRegistersRequest {
            starting_address: 39999,
            quantity: 1,
        }
        .encode();
        let response = handle_request(
            &request,
            &registers(),
            &store,
            &coils(),
            &coil_store,
            &discrete_inputs(),
            &discrete_input_store,
            &input_registers(),
            &input_register_store,
            MemLayout::Abcd,
            MemLayout::Abcd,
            "",
            None,
        );

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_INPUT_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }
}
