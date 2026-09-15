// Serves one Modbus TCP connection: reads requests and writes responses in
// a loop via protocol::tcp::serve_request + handler::handle_request, until
// the peer disconnects or a request fails (matches protocol::tcp's own
// per-step timeout hardening — a stalled peer can't hang this forever).
//
// Takes Arc'd shared state (rather than plain references, like
// handler::handle_request does) because each accepted connection is served
// as its own spawned tokio task, which needs 'static ownership.

use crate::handler::handle_request;
use fuse_fs::RegisterStore;
use protocol::device_description::RegisterDescription;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn serve_connection<S>(
    mut stream: S,
    registers: Arc<Vec<RegisterDescription>>,
    store: Arc<Mutex<RegisterStore>>,
    timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        // Clone the Arcs into the closure by value (not by reference) each
        // iteration: an async closure that instead *borrows* `registers`/
        // `store` from the surrounding scope runs into a higher-ranked
        // Send inference issue ("implementation of Send is not general
        // enough") once this whole function is spawned as its own task —
        // owned clones sidestep it entirely, and Arc::clone is cheap.
        let handler_registers = Arc::clone(&registers);
        let handler_store = Arc::clone(&store);
        let result = protocol::tcp::serve_request(
            &mut stream,
            async move |pdu: &[u8]| handle_request(pdu, &handler_registers, &handler_store),
            timeout,
        )
        .await;
        if result.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_fs::RegisterValue;
    use protocol::adu::TcpAdu;
    use protocol::device_description::{AccessRight, DataType};
    use protocol::pdu::{
        ReadHoldingRegistersRequest, ReadHoldingRegistersResponse, WriteSingleRegisterRequest,
        WriteSingleRegisterResponse,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn registers() -> Arc<Vec<RegisterDescription>> {
        Arc::new(vec![
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
        ])
    }

    #[tokio::test]
    async fn serves_a_read_request_from_the_current_store_value() {
        let (mut master, server_stream) = tokio::io::duplex(1024);
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(72));

        tokio::spawn(serve_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            Duration::from_secs(1),
        ));

        let request = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: ReadHoldingRegistersRequest {
                starting_address: 40001,
                quantity: 1,
            }
            .encode(),
        };
        master.write_all(&request.encode()).await.unwrap();

        let expected_response = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: ReadHoldingRegistersResponse {
                register_values: vec![72],
            }
            .encode(),
        };
        let expected_bytes = expected_response.encode();
        let mut received = vec![0u8; expected_bytes.len()];
        master.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected_bytes);
    }

    #[tokio::test]
    async fn serves_a_write_request_and_applies_it_to_the_store() {
        let (mut master, server_stream) = tokio::io::duplex(1024);
        let store = Arc::new(Mutex::new(RegisterStore::new()));

        tokio::spawn(serve_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            Duration::from_secs(1),
        ));

        let request = TcpAdu {
            transaction_id: 0x0002,
            unit_id: 0x01,
            pdu: WriteSingleRegisterRequest {
                register_address: 40002,
                register_value: 1,
            }
            .encode(),
        };
        master.write_all(&request.encode()).await.unwrap();

        let expected_response = TcpAdu {
            transaction_id: 0x0002,
            unit_id: 0x01,
            pdu: WriteSingleRegisterResponse {
                register_address: 40002,
                register_value: 1,
            }
            .encode(),
        };
        let expected_bytes = expected_response.encode();
        let mut received = vec![0u8; expected_bytes.len()];
        master.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected_bytes);

        assert_eq!(
            store.lock().unwrap().get("Stop_Process"),
            Some(RegisterValue::U16(1))
        );
    }

    #[tokio::test]
    async fn serves_multiple_requests_on_the_same_connection() {
        let (mut master, server_stream) = tokio::io::duplex(1024);
        let store = Arc::new(Mutex::new(RegisterStore::new()));

        tokio::spawn(serve_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            Duration::from_secs(1),
        ));

        for transaction_id in [0x0001u16, 0x0002u16] {
            let request = TcpAdu {
                transaction_id,
                unit_id: 0x01,
                pdu: ReadHoldingRegistersRequest {
                    starting_address: 40001,
                    quantity: 1,
                }
                .encode(),
            };
            master.write_all(&request.encode()).await.unwrap();

            let expected_response = TcpAdu {
                transaction_id,
                unit_id: 0x01,
                pdu: ReadHoldingRegistersResponse {
                    register_values: vec![0],
                }
                .encode(),
            };
            let expected_bytes = expected_response.encode();
            let mut received = vec![0u8; expected_bytes.len()];
            master.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_bytes);
        }
    }
}
