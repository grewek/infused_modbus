// Serves Modbus requests via handler::handle_request, over either
// transport. Takes Arc'd shared state (rather than plain references, like
// handler::handle_request does) because each connection/port is served as
// its own spawned tokio task, which needs 'static ownership.

use crate::handler::handle_request;
use fuse_fs::{CoilStore, RegisterStore};
use protocol::device_description::{CoilDescription, RegisterDescription};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Serves one Modbus TCP connection: reads requests and writes responses
/// in a loop via protocol::tcp::serve_request, until the peer disconnects
/// or a request fails (matches protocol::tcp's own per-step timeout
/// hardening — a stalled peer can't hang this forever). Ending the loop
/// here just means this one connection is done — the accept loop that
/// spawned this task keeps accepting new ones.
#[allow(clippy::too_many_arguments)]
pub async fn serve_tcp_connection<S>(
    mut stream: S,
    registers: Arc<Vec<RegisterDescription>>,
    store: Arc<Mutex<RegisterStore>>,
    coils: Arc<Vec<CoilDescription>>,
    coil_store: Arc<Mutex<CoilStore>>,
    toml_source: Arc<String>,
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
        let handler_coils = Arc::clone(&coils);
        let handler_coil_store = Arc::clone(&coil_store);
        let handler_toml_source = Arc::clone(&toml_source);
        let result = protocol::tcp::serve_request(
            &mut stream,
            async move |pdu: &[u8]| {
                handle_request(
                    pdu,
                    &handler_registers,
                    &handler_store,
                    &handler_coils,
                    &handler_coil_store,
                    &handler_toml_source,
                )
            },
            timeout,
        )
        .await;
        if result.is_err() {
            break;
        }
    }
}

/// Serves Modbus RTU requests on one serial port, forever. Unlike TCP,
/// there's no "accept a new connection" concept here — this one port *is*
/// the server's entire lifetime connection to the bus, so unlike
/// `serve_tcp_connection`, a failed request (a bad CRC, a timeout, a
/// malformed frame) is logged and the loop keeps going rather than
/// breaking out of it: there's nothing else to fall back to or reconnect
/// to, and one glitched frame shouldn't take the whole server offline
/// until it's manually restarted.
#[allow(clippy::too_many_arguments)]
pub async fn serve_rtu_connection<S>(
    mut stream: S,
    registers: Arc<Vec<RegisterDescription>>,
    store: Arc<Mutex<RegisterStore>>,
    coils: Arc<Vec<CoilDescription>>,
    coil_store: Arc<Mutex<CoilStore>>,
    toml_source: Arc<String>,
    frame_silence: Duration,
    timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let handler_registers = Arc::clone(&registers);
        let handler_store = Arc::clone(&store);
        let handler_coils = Arc::clone(&coils);
        let handler_coil_store = Arc::clone(&coil_store);
        let handler_toml_source = Arc::clone(&toml_source);
        let result = protocol::rtu::serve_request(
            &mut stream,
            async move |pdu: &[u8]| {
                handle_request(
                    pdu,
                    &handler_registers,
                    &handler_store,
                    &handler_coils,
                    &handler_coil_store,
                    &handler_toml_source,
                )
            },
            frame_silence,
            timeout,
        )
        .await;
        if let Err(error) = result {
            eprintln!("RTU request failed: {error}");
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

    fn coils() -> Arc<Vec<CoilDescription>> {
        Arc::new(Vec::new())
    }

    fn coil_store() -> Arc<Mutex<CoilStore>> {
        Arc::new(Mutex::new(CoilStore::new()))
    }

    #[tokio::test]
    async fn serves_a_read_request_from_the_current_store_value() {
        let (mut master, server_stream) = tokio::io::duplex(1024);
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(72));

        tokio::spawn(serve_tcp_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            coils(),
            coil_store(),
            Arc::new(String::new()),
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

        tokio::spawn(serve_tcp_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            coils(),
            coil_store(),
            Arc::new(String::new()),
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

        tokio::spawn(serve_tcp_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            coils(),
            coil_store(),
            Arc::new(String::new()),
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

    #[tokio::test]
    async fn serve_rtu_connection_serves_a_read_request() {
        use protocol::adu::RtuAdu;

        let (mut master, server_stream) = tokio::io::duplex(1024);
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(72));

        tokio::spawn(serve_rtu_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            coils(),
            coil_store(),
            Arc::new(String::new()),
            Duration::from_millis(20),
            Duration::from_secs(1),
        ));

        let request = RtuAdu {
            unit_id: 0x01,
            pdu: ReadHoldingRegistersRequest {
                starting_address: 40001,
                quantity: 1,
            }
            .encode(),
        };
        master.write_all(&request.encode()).await.unwrap();

        let expected_response = RtuAdu {
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
    async fn serve_rtu_connection_keeps_serving_after_a_bad_crc_frame() {
        use protocol::adu::RtuAdu;

        let (mut master, server_stream) = tokio::io::duplex(1024);
        let store = Arc::new(Mutex::new(RegisterStore::new()));

        tokio::spawn(serve_rtu_connection(
            server_stream,
            registers(),
            Arc::clone(&store),
            coils(),
            coil_store(),
            Arc::new(String::new()),
            Duration::from_millis(20),
            Duration::from_secs(1),
        ));

        // A well-formed-looking frame with a deliberately wrong CRC —
        // should be logged and skipped, not kill the loop.
        master
            .write_all(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
            .await
            .unwrap();
        // Give the bad frame time to be read and discarded before sending
        // a real one on the same "connection".
        tokio::time::sleep(Duration::from_millis(50)).await;

        let request = RtuAdu {
            unit_id: 0x01,
            pdu: ReadHoldingRegistersRequest {
                starting_address: 40001,
                quantity: 1,
            }
            .encode(),
        };
        master.write_all(&request.encode()).await.unwrap();

        let expected_response = RtuAdu {
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
