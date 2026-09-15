// Turning a staged (register, value) pair into a real Modbus write, and
// turning the device's response back into a WriteStatus.

use crate::connection::Connection;
use fuse_fs::{RegisterValue, WriteStatus};
use protocol::DecodeError;
use protocol::device_description::{DataType, RegisterDescription};
use protocol::pdu::{ExceptionResponse, WriteSingleRegisterRequest};
use std::time::Duration;

/// Encodes the Modbus request PDU for writing `value` to `register`.
///
/// F32 is deliberately not supported yet: it would need to span two 16-bit
/// registers, and which one carries the high/low word is a real,
/// device-dependent decision (see CLAUDE.md) that hasn't been made — better
/// to fail loudly than guess a wire format.
pub fn encode_write_request(
    register: &RegisterDescription,
    value: RegisterValue,
) -> Result<Vec<u8>, String> {
    match (register.data_type, value) {
        (DataType::U16, RegisterValue::U16(register_value)) => Ok(WriteSingleRegisterRequest {
            register_address: register.address,
            register_value,
        }
        .encode()),
        (DataType::F32, RegisterValue::F32(_)) => Err(format!(
            "register {}: F32 writes not yet supported (32-bit word order over two registers hasn't been decided)",
            register.name
        )),
        (data_type, value) => Err(format!(
            "register {}: expected a {data_type:?} value but got {value:?}",
            register.name
        )),
    }
}

/// Interprets a write response PDU: a Modbus exception response means the
/// device rejected the write; anything else is treated as success, since a
/// successful Write Single/Multiple Registers response simply echoes back
/// what was requested — there's no extra information to extract beyond
/// "not an exception".
pub fn interpret_write_response(response_pdu: &[u8]) -> WriteStatus {
    match ExceptionResponse::decode(response_pdu) {
        Ok(exception) => WriteStatus::Failed(format!(
            "device returned Modbus exception code {}",
            exception.exception_code
        )),
        Err(DecodeError::NotAnExceptionResponse { .. }) => WriteStatus::Ok,
        Err(error) => WriteStatus::Failed(format!("malformed write response: {error:?}")),
    }
}

/// Sends `value` as a write to `register` over `stream` and returns the
/// resulting `WriteStatus` — the real, over-the-wire "does the device
/// confirm this write" step referred to by CLAUDE.md's "TRANSACTION_END
/// confirmation semantics". Never panics on a transport failure (a timeout,
/// a dropped connection, ...): those are reported as `WriteStatus::Failed`
/// just like a Modbus-level rejection, since from the caller's perspective
/// both just mean "the write didn't happen".
pub async fn confirm_write(
    connection: &mut Connection,
    register: &RegisterDescription,
    value: RegisterValue,
    unit_id: u8,
    timeout: Duration,
) -> WriteStatus {
    let pdu = match encode_write_request(register, value) {
        Ok(pdu) => pdu,
        Err(reason) => return WriteStatus::Failed(reason),
    };
    match connection.request(unit_id, pdu, timeout).await {
        Ok(response_pdu) => interpret_write_response(&response_pdu),
        Err(error) => WriteStatus::Failed(format!("write failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::device_description::AccessRight;

    fn u16_register() -> RegisterDescription {
        RegisterDescription {
            name: "Stop_Process".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadWrite,
        }
    }

    fn f32_register() -> RegisterDescription {
        RegisterDescription {
            name: "Flow_Setpoint".to_string(),
            address: 40002,
            data_type: DataType::F32,
            access: AccessRight::ReadWrite,
        }
    }

    #[test]
    fn encode_write_request_builds_write_single_register_pdu_for_u16() {
        let pdu = encode_write_request(&u16_register(), RegisterValue::U16(1)).unwrap();
        assert_eq!(pdu, vec![0x06, 0x9C, 0x41, 0x00, 0x01]);
    }

    #[test]
    fn encode_write_request_rejects_f32() {
        let result = encode_write_request(&f32_register(), RegisterValue::F32(3.5));
        assert!(result.is_err());
    }

    #[test]
    fn encode_write_request_rejects_mismatched_value_type() {
        let result = encode_write_request(&u16_register(), RegisterValue::F32(3.5));
        assert!(result.is_err());
    }

    #[test]
    fn interpret_write_response_treats_non_exception_as_ok() {
        let response = WriteSingleRegisterRequest {
            register_address: 40001,
            register_value: 1,
        }
        .encode();
        assert_eq!(interpret_write_response(&response), WriteStatus::Ok);
    }

    #[test]
    fn interpret_write_response_treats_exception_as_failed() {
        let response = ExceptionResponse {
            function_code: 0x06,
            exception_code: 0x02,
        }
        .encode();
        assert_eq!(
            interpret_write_response(&response),
            WriteStatus::Failed("device returned Modbus exception code 2".to_string())
        );
    }

    #[test]
    fn interpret_write_response_treats_malformed_bytes_as_failed() {
        assert!(matches!(
            interpret_write_response(&[]),
            WriteStatus::Failed(_)
        ));
    }

    async fn connected_pair() -> (Connection, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let connection = Connection::connect_tcp(&address).await.unwrap();
        let (device, _peer) = listener.accept().await.unwrap();
        (connection, device)
    }

    #[tokio::test]
    async fn confirm_write_returns_ok_when_device_echoes_the_write() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            // The response PDU is the same length as the request PDU here
            // (a Write Single Register response just echoes the request),
            // so the request's own header — transaction ID, protocol ID,
            // length, unit ID — is already correct to reuse verbatim.
            let mut response = header;
            response.extend_from_slice(&pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let status = confirm_write(
            &mut connection,
            &u16_register(),
            RegisterValue::U16(1),
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(status, WriteStatus::Ok);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirm_write_returns_failed_when_device_returns_an_exception() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let exception = ExceptionResponse {
                function_code: 0x06,
                exception_code: 0x02,
            }
            .encode();
            // Unlike the echo case, the exception response (2 bytes) is a
            // different length than the request PDU (5 bytes), so the
            // length field (bytes 4..6 of the MBAP header) has to be
            // recomputed — everything else (transaction ID, protocol ID,
            // unit ID) is still correct to echo verbatim.
            let mut response = header;
            let length = (exception.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&exception);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let status = confirm_write(
            &mut connection,
            &u16_register(),
            RegisterValue::U16(1),
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirm_write_returns_failed_when_the_device_never_responds() {
        let (mut connection, _device) = connected_pair().await;

        let status = confirm_write(
            &mut connection,
            &u16_register(),
            RegisterValue::U16(1),
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
    }

    #[tokio::test]
    async fn confirm_write_returns_failed_without_sending_for_unsupported_types() {
        let (mut connection, _device) = connected_pair().await;

        let status = confirm_write(
            &mut connection,
            &f32_register(),
            RegisterValue::F32(3.5),
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
    }
}
