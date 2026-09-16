// Turning a staged (register, value) pair into a real Modbus write, and
// turning the device's response back into a WriteStatus.

use crate::connection::Connection;
use fuse_fs::register_encoding::register_value_to_words;
use fuse_fs::{CoilValue, RegisterValue, WriteStatus};
use protocol::DecodeError;
use protocol::device_description::{CoilDescription, MemLayout, RegisterDescription};
use protocol::pdu::{
    ExceptionResponse, WriteMultipleCoilsRequest, WriteMultipleRegistersRequest,
    WriteSingleCoilRequest, WriteSingleRegisterRequest,
};
use std::time::Duration;

/// Encodes the Modbus request PDU for writing `value` to `register` as a
/// Write Single Register (FC6) request.
///
/// Only registers whose `DataType::register_count()` is 1 (U8/I8/U16/I16)
/// can go through FC6 at all — that's the function code's own shape, not a
/// scope decision: it physically carries exactly one wire word. A wider
/// value needs Write Multiple Registers (FC16) instead — see
/// `client::transaction_consumer`, which is the one place that decides
/// which function code a given batch needs and never calls this for a
/// register wider than one slot.
pub fn encode_write_request(
    register: &RegisterDescription,
    value: RegisterValue,
    mem_layout: MemLayout,
) -> Result<Vec<u8>, String> {
    if register.data_type.register_count() != 1 {
        return Err(format!(
            "register {}: {:?} needs {} registers, Write Single Register can't carry it",
            register.name,
            register.data_type,
            register.data_type.register_count()
        ));
    }
    if value.data_type() != register.data_type {
        return Err(format!(
            "register {}: expected a {:?} value but got a {:?} one",
            register.name,
            register.data_type,
            value.data_type()
        ));
    }
    let words = register_value_to_words(value, mem_layout);
    Ok(WriteSingleRegisterRequest {
        register_address: register.address,
        register_value: words[0],
    }
    .encode())
}

/// Encodes the Modbus request PDU for writing `value` to `coil`. Unlike
/// `encode_write_request`, this can't fail: a coil is always exactly one
/// bit, so there's no F32-style word-order ambiguity to reject.
pub fn encode_coil_write_request(coil: &CoilDescription, value: CoilValue) -> Vec<u8> {
    WriteSingleCoilRequest {
        coil_address: coil.address,
        coil_value: value.0,
    }
    .encode()
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
    mem_layout: MemLayout,
    unit_id: u8,
    timeout: Duration,
) -> WriteStatus {
    let pdu = match encode_write_request(register, value, mem_layout) {
        Ok(pdu) => pdu,
        Err(reason) => return WriteStatus::Failed(reason),
    };
    match connection.request(unit_id, pdu, timeout).await {
        Ok(response_pdu) => interpret_write_response(&response_pdu),
        Err(error) => WriteStatus::Failed(format!("write failed: {error}")),
    }
}

/// Coil counterpart of `confirm_write` — same round trip and the same
/// `interpret_write_response` interpretation of the result, since a
/// successful Write Single Coil response also just echoes the request.
pub async fn confirm_coil_write(
    connection: &mut Connection,
    coil: &CoilDescription,
    value: CoilValue,
    unit_id: u8,
    timeout: Duration,
) -> WriteStatus {
    let pdu = encode_coil_write_request(coil, value);
    match connection.request(unit_id, pdu, timeout).await {
        Ok(response_pdu) => interpret_write_response(&response_pdu),
        Err(error) => WriteStatus::Failed(format!("write failed: {error}")),
    }
}

/// Sends a batch of contiguous register writes as one Write Multiple
/// Registers request — the round-trip counterpart of `confirm_write`, used
/// when more than one staged register can be grouped into a single
/// request. Modbus gives no finer-grained outcome than "the whole request
/// succeeded or failed", so a caller applying this status to several
/// staged names must apply the same status to all of them.
pub async fn confirm_write_multiple(
    connection: &mut Connection,
    starting_address: u16,
    values: &[u16],
    unit_id: u8,
    timeout: Duration,
) -> WriteStatus {
    let pdu = WriteMultipleRegistersRequest {
        starting_address,
        register_values: values.to_vec(),
    }
    .encode();
    match connection.request(unit_id, pdu, timeout).await {
        Ok(response_pdu) => interpret_write_response(&response_pdu),
        Err(error) => WriteStatus::Failed(format!("write failed: {error}")),
    }
}

/// Coil counterpart of `confirm_write_multiple`.
pub async fn confirm_coil_write_multiple(
    connection: &mut Connection,
    starting_address: u16,
    values: &[bool],
    unit_id: u8,
    timeout: Duration,
) -> WriteStatus {
    let pdu = WriteMultipleCoilsRequest {
        starting_address,
        coil_values: values.to_vec(),
    }
    .encode();
    match connection.request(unit_id, pdu, timeout).await {
        Ok(response_pdu) => interpret_write_response(&response_pdu),
        Err(error) => WriteStatus::Failed(format!("write failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::device_description::{AccessRight, DataType};

    fn u16_register() -> RegisterDescription {
        RegisterDescription {
            name: "Stop_Process".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadWrite,
        }
    }

    fn a_coil() -> CoilDescription {
        CoilDescription {
            name: "Motor_Running".to_string(),
            address: 1,
        }
    }

    #[test]
    fn encode_coil_write_request_builds_write_single_coil_pdu() {
        let pdu = encode_coil_write_request(&a_coil(), CoilValue(true));
        assert_eq!(pdu, vec![0x05, 0x00, 0x01, 0xFF, 0x00]);
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
        let pdu =
            encode_write_request(&u16_register(), RegisterValue::U16(1), MemLayout::Abcd).unwrap();
        assert_eq!(pdu, vec![0x06, 0x9C, 0x41, 0x00, 0x01]);
    }

    #[test]
    fn encode_write_request_builds_write_single_register_pdu_for_i16() {
        let register = RegisterDescription {
            name: "Signed_Setpoint".to_string(),
            address: 40003,
            data_type: DataType::I16,
            access: AccessRight::ReadWrite,
        };
        let pdu = encode_write_request(&register, RegisterValue::I16(-5), MemLayout::Abcd).unwrap();
        assert_eq!(pdu, vec![0x06, 0x9C, 0x43, 0xFF, 0xFB]);
    }

    #[test]
    fn encode_write_request_rejects_registers_wider_than_one_slot() {
        // F32 needs 2 registers — Write Single Register can only ever
        // carry one wire word, regardless of the value's own correctness.
        let result =
            encode_write_request(&f32_register(), RegisterValue::F32(3.5), MemLayout::Abcd);
        assert!(result.is_err());
    }

    #[test]
    fn encode_write_request_rejects_mismatched_value_type() {
        let result =
            encode_write_request(&u16_register(), RegisterValue::F32(3.5), MemLayout::Abcd);
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
            MemLayout::Abcd,
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
            MemLayout::Abcd,
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
            MemLayout::Abcd,
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
    }

    #[tokio::test]
    async fn confirm_write_returns_failed_without_sending_for_a_register_wider_than_one_slot() {
        let (mut connection, _device) = connected_pair().await;

        let status = confirm_write(
            &mut connection,
            &f32_register(),
            RegisterValue::F32(3.5),
            MemLayout::Abcd,
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
    }

    #[tokio::test]
    async fn confirm_coil_write_returns_ok_when_device_echoes_the_write() {
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
            let mut response = header;
            response.extend_from_slice(&pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let status = confirm_coil_write(
            &mut connection,
            &a_coil(),
            CoilValue(true),
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(status, WriteStatus::Ok);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirm_coil_write_returns_failed_when_device_returns_an_exception() {
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
                function_code: 0x05,
                exception_code: 0x02,
            }
            .encode();
            let mut response = header;
            let length = (exception.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&exception);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let status = confirm_coil_write(
            &mut connection,
            &a_coil(),
            CoilValue(true),
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirm_coil_write_returns_failed_when_the_device_never_responds() {
        let (mut connection, _device) = connected_pair().await;

        let status = confirm_coil_write(
            &mut connection,
            &a_coil(),
            CoilValue(true),
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
    }

    #[tokio::test]
    async fn confirm_write_multiple_returns_ok_when_device_echoes_the_write() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            // Write Multiple Registers request PDU for 2 values: function
            // code (1) + starting address (2) + quantity (2) + byte count
            // (1) + 2 values (4) = 10 bytes.
            let mut pdu = vec![0u8; 10];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            // A successful Write Multiple Registers response echoes just
            // starting address + quantity (5 bytes), not the values.
            let response_pdu = protocol::pdu::WriteMultipleRegistersResponse {
                starting_address: 40010,
                quantity: 2,
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let status = confirm_write_multiple(
            &mut connection,
            40010,
            &[11, 22],
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(status, WriteStatus::Ok);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirm_write_multiple_returns_failed_when_device_returns_an_exception() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 10];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let exception = ExceptionResponse {
                function_code: 0x10,
                exception_code: 0x02,
            }
            .encode();
            let mut response = header;
            let length = (exception.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&exception);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let status = confirm_write_multiple(
            &mut connection,
            40010,
            &[11, 22],
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirm_coil_write_multiple_returns_ok_when_device_echoes_the_write() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            // Write Multiple Coils request PDU for 2 values: function code
            // (1) + starting address (2) + quantity (2) + byte count (1) +
            // 1 packed byte = 7 bytes.
            let mut pdu = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let response_pdu = protocol::pdu::WriteMultipleCoilsResponse {
                starting_address: 1,
                quantity: 2,
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let status = confirm_coil_write_multiple(
            &mut connection,
            1,
            &[true, false],
            0x01,
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(status, WriteStatus::Ok);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirm_coil_write_multiple_returns_failed_when_the_device_never_responds() {
        let (mut connection, _device) = connected_pair().await;

        let status = confirm_coil_write_multiple(
            &mut connection,
            1,
            &[true, false],
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert!(matches!(status, WriteStatus::Failed(_)));
    }
}
