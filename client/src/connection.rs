// Unifies TCP and RTU behind one "send this PDU, get a response PDU" call
// so write_confirmation/transaction_consumer/polling don't need to care
// which transport they're actually talking over. An enum rather than a
// trait: the two transports use different ADU types (TcpAdu carries a
// transaction_id RtuAdu has no use for) and there are exactly two concrete
// cases, known up front — no need for open-ended dynamic dispatch.

use protocol::adu::{RtuAdu, TcpAdu};
use protocol::rtu::frame_silence_for_baud_rate;
use std::io;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

pub enum Connection {
    Tcp {
        stream: TcpStream,
        next_transaction_id: u16,
    },
    Rtu {
        stream: SerialStream,
        frame_silence: Duration,
    },
}

impl Connection {
    pub async fn connect_tcp(address: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(address).await?;
        Ok(Self::Tcp {
            stream,
            next_transaction_id: 0,
        })
    }

    /// `path` is the serial device (e.g. `/dev/ttyUSB0`); `frame_silence`
    /// (the gap that marks a frame boundary — see `protocol::rtu`) is
    /// derived from `baud_rate` per the Modbus spec, not configurable
    /// separately since it's not an independent physical parameter.
    ///
    /// Takes `handle` (rather than just assuming an ambient runtime like
    /// `TcpStream::connect` can) because tokio-serial registers the file
    /// descriptor with the reactor immediately at open time, not lazily on
    /// first use — so opening it needs an active runtime context even
    /// though this function itself isn't async.
    pub fn open_rtu(
        handle: &tokio::runtime::Handle,
        path: &str,
        baud_rate: u32,
    ) -> io::Result<Self> {
        let _guard = handle.enter();
        let stream = tokio_serial::new(path, baud_rate)
            .open_native_async()
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self::Rtu {
            stream,
            frame_silence: frame_silence_for_baud_rate(baud_rate),
        })
    }

    /// Sends `pdu` under `unit_id` and returns the response PDU bytes,
    /// dispatching to whichever transport this connection actually is.
    pub async fn request(
        &mut self,
        unit_id: u8,
        pdu: Vec<u8>,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        match self {
            Connection::Tcp {
                stream,
                next_transaction_id,
            } => {
                *next_transaction_id = next_transaction_id.wrapping_add(1);
                let request = TcpAdu {
                    transaction_id: *next_transaction_id,
                    unit_id,
                    pdu,
                };
                let response = protocol::tcp::send_request(stream, request, timeout).await?;
                Ok(response.pdu)
            }
            Connection::Rtu {
                stream,
                frame_silence,
            } => {
                let request = RtuAdu { unit_id, pdu };
                let response =
                    protocol::rtu::send_request(stream, request, *frame_silence, timeout).await?;
                Ok(response.pdu)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::pdu::{ReadHoldingRegistersRequest, ReadHoldingRegistersResponse};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_connection_sends_a_request_and_returns_the_response_pdu() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let server_task = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut header = vec![0u8; 7];
            stream.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            stream.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadHoldingRegistersResponse {
                register_values: vec![42],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            stream.write_all(&response).await.unwrap();
        });

        let mut connection = Connection::connect_tcp(&address).await.unwrap();
        let request_pdu = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 1,
        }
        .encode();
        let response_pdu = connection
            .request(0x01, request_pdu, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(
            ReadHoldingRegistersResponse::decode(&response_pdu).unwrap(),
            ReadHoldingRegistersResponse {
                register_values: vec![42]
            }
        );
        server_task.await.unwrap();
    }
}
