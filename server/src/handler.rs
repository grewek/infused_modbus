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
// other unimplemented function code.

use fuse_fs::{RegisterStore, RegisterValue};
use protocol::device_description::{AccessRight, DataType, RegisterDescription};
use protocol::pdu::{
    EXCEPTION_ILLEGAL_DATA_ADDRESS, EXCEPTION_ILLEGAL_DATA_VALUE, EXCEPTION_ILLEGAL_FUNCTION,
    ExceptionResponse, FUNCTION_CODE_READ_HOLDING_REGISTERS, FUNCTION_CODE_WRITE_SINGLE_REGISTER,
    ReadHoldingRegistersRequest, ReadHoldingRegistersResponse, WriteSingleRegisterRequest,
    WriteSingleRegisterResponse,
};
use std::sync::{Mutex, PoisonError};

pub fn handle_request(
    pdu: &[u8],
    registers: &[RegisterDescription],
    store: &Mutex<RegisterStore>,
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
        _ => ExceptionResponse {
            function_code,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode(),
    }
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

    #[test]
    fn read_returns_current_store_values() {
        let store = Mutex::new(RegisterStore::new());
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(72));

        let request = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 1,
        }
        .encode();
        let response = handle_request(&request, &registers(), &store);

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
        let request = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 1,
        }
        .encode();
        let response = handle_request(&request, &registers(), &store);
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
        let request = ReadHoldingRegistersRequest {
            starting_address: 49999,
            quantity: 1,
        }
        .encode();
        let response = handle_request(&request, &registers(), &store);
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
        let request = ReadHoldingRegistersRequest {
            starting_address: 40003,
            quantity: 1,
        }
        .encode();
        let response = handle_request(&request, &registers(), &store);
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
        let request = WriteSingleRegisterRequest {
            register_address: 40002,
            register_value: 1,
        }
        .encode();

        let response = handle_request(&request, &registers(), &store);

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
        let request = WriteSingleRegisterRequest {
            register_address: 40001,
            register_value: 99,
        }
        .encode();

        let response = handle_request(&request, &registers(), &store);

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
        // Write Multiple Registers (0x10) — decodable, but not handled yet.
        let request = vec![0x10, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01];
        let response = handle_request(&request, &registers(), &store);
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
        let response = handle_request(&[], &registers(), &store);
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap().exception_code,
            EXCEPTION_ILLEGAL_FUNCTION
        );
    }
}
