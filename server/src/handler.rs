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
// Scope of this first pass, matching the client's write_confirmation.rs:
// only U16 registers are supported for both reads and writes, and only
// Read Holding Registers / Write Single Register — Write Multiple
// Registers falls through to the same "illegal function" handling as any
// other unimplemented function code. Coils get the same Read/Write Single
// treatment (Read Coils / Write Single Coil); a coil is always read/write
// (see protocol::device_description::CoilDescription's own doc comment),
// so unlike registers there's no access-right check on the write side.

use crate::device_identification::{build_objects, handle_read_device_identification};
use fuse_fs::{CoilStore, CoilValue, RegisterStore, RegisterValue};
use protocol::device_description::{AccessRight, CoilDescription, DataType, RegisterDescription};
use protocol::pdu::{
    EXCEPTION_ILLEGAL_DATA_ADDRESS, EXCEPTION_ILLEGAL_DATA_VALUE, EXCEPTION_ILLEGAL_FUNCTION,
    ExceptionResponse, FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT, FUNCTION_CODE_READ_COILS,
    FUNCTION_CODE_READ_HOLDING_REGISTERS, FUNCTION_CODE_WRITE_SINGLE_COIL,
    FUNCTION_CODE_WRITE_SINGLE_REGISTER, ReadCoilsRequest, ReadCoilsResponse,
    ReadDeviceIdentificationRequest, ReadHoldingRegistersRequest, ReadHoldingRegistersResponse,
    WriteSingleCoilRequest, WriteSingleCoilResponse, WriteSingleRegisterRequest,
    WriteSingleRegisterResponse,
};
use std::sync::{Mutex, PoisonError};

#[allow(clippy::too_many_arguments)]
pub fn handle_request(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
    coils: &[CoilDescription],
    coil_store: &Mutex<CoilStore>,
    toml_source: &str,
) -> Vec<u8> {
    let Some(&function_code) = pdu.first() else {
        return ExceptionResponse {
            function_code: 0,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode();
    };

    match function_code {
        FUNCTION_CODE_READ_HOLDING_REGISTERS => handle_read(pdu, registers, store),
        FUNCTION_CODE_WRITE_SINGLE_REGISTER => handle_write_single(pdu, registers, store),
        FUNCTION_CODE_READ_COILS => handle_read_coils(pdu, coils, coil_store),
        FUNCTION_CODE_WRITE_SINGLE_COIL => handle_write_single_coil(pdu, coils, coil_store),
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

fn handle_read(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
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
    for offset in 0..request.quantity {
        let address = request.starting_address.wrapping_add(offset);
        // Only a register that exists at this exact address and is a
        // (currently the only supported) U16 register can be served; a gap
        // in the address range or an F32 register both report "illegal
        // data address" rather than guessing a value or a wire format.
        match registers
            .iter()
            .find(|register| register.address == address && register.data_type == DataType::U16)
        {
            Some(register) => {
                let value = match store.get(&register.name) {
                    Some(RegisterValue::U16(value)) => value,
                    _ => 0,
                };
                register_values.push(value);
            }
            None => {
                return ExceptionResponse {
                    function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                    exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
                }
                .encode();
            }
        }
    }
    ReadHoldingRegistersResponse { register_values }.encode()
}

fn handle_write_single(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
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
            && register.data_type == DataType::U16
            && register.access == AccessRight::ReadWrite
    });
    match register {
        Some(register) => {
            store.lock().unwrap_or_else(PoisonError::into_inner).set(
                register.name.clone(),
                RegisterValue::U16(request.register_value),
            );
            WriteSingleRegisterResponse {
                register_address: request.register_address,
                register_value: request.register_value,
            }
            .encode()
        }
        // Covers three cases alike for now: no register at this address,
        // an F32 register (unsupported wire format, same as the client
        // side), and a read-only register — all "you can't write here".
        None => ExceptionResponse {
            function_code: FUNCTION_CODE_WRITE_SINGLE_REGISTER,
            exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
        }
        .encode(),
    }
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
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");

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
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");
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
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }

    #[test]
    fn read_of_an_f32_register_returns_an_exception() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let request = ReadHoldingRegistersRequest {
            starting_address: 40003,
            quantity: 1,
        }
        .encode();
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_READ_HOLDING_REGISTERS,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
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

        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");

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

        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");

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
    fn unimplemented_function_code_returns_illegal_function() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        // Write Multiple Registers (0x10) — decodable, but not handled yet.
        let request = vec![0x10, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01];
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: 0x10,
                exception_code: EXCEPTION_ILLEGAL_FUNCTION,
            }
        );
    }

    #[test]
    fn empty_pdu_returns_illegal_function_without_panicking() {
        let store = Mutex::new(RegisterStore::new());
        let coil_store = Mutex::new(CoilStore::new());
        let response = handle_request(&[], &registers(), &store, &coils(), &coil_store, "");
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
            "name = \"X\"",
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
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");

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
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");
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
        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");
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

        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");

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

        let response = handle_request(&request, &registers(), &store, &coils(), &coil_store, "");

        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_WRITE_SINGLE_COIL,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }
}
