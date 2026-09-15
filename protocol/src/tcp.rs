use crate::adu::{MBAP_HEADER_LEN, MBAP_LENGTH_BYTE, MBAP_MAX_LENGTH, TcpAdu};
use crate::read_u16_be;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Generic over AsyncRead/AsyncWrite rather than named to `tokio::net::TcpStream`
// directly: a real caller still passes a TcpStream (which implements both
// traits), but this lets tests drive it over an in-memory `tokio::io::duplex`
// pair instead of needing a real socket.

// A TCP ADU is a stream of bytes, not a single message the way UDP or an
// in-memory buffer would be: a `read()` call can return any part of it. The
// fixed 7-byte MBAP header is read first so its length field can tell us
// exactly how many more bytes make up the rest of the frame.
async fn read_adu<S>(stream: &mut S) -> io::Result<TcpAdu>
where
    S: AsyncRead + Unpin,
{
    let mut header = vec![0u8; MBAP_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let length = read_u16_be(&header, MBAP_LENGTH_BYTE);
    // Reject an out-of-range length before allocating anything for the body:
    // a peer that lies about the length shouldn't be able to make us allocate
    // on its say-so alone. See MBAP_MAX_LENGTH's doc comment for why 254 is
    // the real ceiling.
    if length == 0 || length > MBAP_MAX_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid MBAP length field: {length}"),
        ));
    }
    let mut frame = header;
    let pdu_len = length as usize - 1;
    let body_start = frame.len();
    frame.resize(body_start + pdu_len, 0);
    stream.read_exact(&mut frame[body_start..]).await?;
    TcpAdu::decode(&frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))
}

/// Sends `request` over `stream` and returns the response with the matching
/// transaction ID.
pub async fn send_request<S>(stream: &mut S, request: TcpAdu) -> io::Result<TcpAdu>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&request.encode()).await?;
    let response = read_adu(stream).await?;
    if response.transaction_id != request.transaction_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "transaction id mismatch: sent {}, received {}",
                request.transaction_id, response.transaction_id
            ),
        ));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_request_returns_matching_response() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let request = TcpAdu {
            transaction_id: 0x0042,
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };
        let expected_request_bytes = request.encode();

        let response = TcpAdu {
            transaction_id: 0x0042,
            unit_id: 0x01,
            pdu: vec![0x03, 0x04, 0x00, 0x01, 0x00, 0x02],
        };
        let response_bytes = response.encode();

        let server_task = tokio::spawn(async move {
            let mut received = vec![0u8; expected_request_bytes.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_request_bytes);
            server.write_all(&response_bytes).await.unwrap();
        });

        let received_response = send_request(&mut client, request).await.unwrap();
        assert_eq!(received_response, response);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn send_request_rejects_mismatched_transaction_id() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let request = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };

        let response = TcpAdu {
            transaction_id: 0x0002,
            unit_id: 0x01,
            pdu: vec![0x03, 0x04, 0x00, 0x01, 0x00, 0x02],
        };
        let response_bytes = response.encode();

        let server_task = tokio::spawn(async move {
            let mut received = vec![0u8; MBAP_HEADER_LEN + 5];
            server.read_exact(&mut received).await.unwrap();
            server.write_all(&response_bytes).await.unwrap();
        });

        let result = send_request(&mut client, request).await;
        assert!(result.is_err());

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn send_request_rejects_oversized_length_without_reading_body() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let request = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };
        let expected_request_bytes = request.encode();

        // A malicious header claiming the maximum possible length (0xFFFF),
        // far beyond MBAP_MAX_LENGTH, with no body ever sent to back it up.
        // If read_adu allocated/read on the peer's say-so, this would hang
        // forever waiting for a body that's never coming.
        let malicious_header = [0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01];

        let server_task = tokio::spawn(async move {
            let mut received = vec![0u8; expected_request_bytes.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_request_bytes);
            server.write_all(&malicious_header).await.unwrap();
        });

        let result = send_request(&mut client, request).await;
        assert!(result.is_err());

        server_task.await.unwrap();
    }
}
