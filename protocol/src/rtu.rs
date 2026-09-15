// Modbus RTU transport. Unlike TCP's MBAP header, an RTU frame carries no
// length field at all — the spec marks frame boundaries by silence on the
// wire (a gap of at least 3.5 character times between frames). This module
// implements that: read bytes as they arrive, and treat a gap of
// `frame_silence` with no new byte as "the frame is done".
//
// Deliberately NOT implemented: the spec's stricter 1.5-character-time
// inter-byte gap rule (exceeding it mid-frame should be a framing error).
// Enforcing that tightly against a generic async runtime's scheduling would
// risk spuriously discarding valid frames over harmless jitter, for a rule
// most real-world implementations don't strictly enforce either. Skipping
// it means we're not fully spec-conformant, but the 3.5-character silence
// rule (which we do implement) is what actually delimits frames in
// practice.
//
// RTU is a secondary transport in this project — TCP is the one getting
// first-class attention (see CLAUDE.md). RTU exists so the protocol isn't
// TCP-only, not because it's expected to be most users' primary path today.
//
// `frame_silence` depends on the serial link's baud rate (the spec: 3.5
// character times, or a flat 1.75ms at ≥19200 baud) — since this module is
// generic over AsyncRead/AsyncWrite and has no idea what's actually
// backing the stream, the caller has to compute and supply it.

use crate::adu::RtuAdu;
use crate::with_timeout;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Largest possible RTU ADU: 1 (unit ID) + 253 (max PDU) + 2 (CRC). A peer
// that keeps sending bytes without ever pausing long enough to look like a
// real frame boundary is either broken or hostile — bail out rather than
// growing this buffer without bound.
const RTU_MAX_FRAME_LEN: usize = 256;

/// The spec's 3.5-character-time silence gap that marks a frame boundary,
/// for a link running at `baud_rate`. A Modbus character is 11 bits total
/// (start bit, 8 data bits, a parity-or-filler bit, and a stop bit), so 3.5
/// character times is `38.5 / baud_rate` seconds — except the spec fixes it
/// to a flat 1.75ms at 19200 baud and above, since the formula would
/// otherwise give a gap too short to detect reliably in software at high
/// baud rates.
pub fn frame_silence_for_baud_rate(baud_rate: u32) -> Duration {
    const HIGH_BAUD_RATE_THRESHOLD: u32 = 19200;
    const HIGH_BAUD_RATE_FRAME_SILENCE: Duration = Duration::from_micros(1750);

    if baud_rate >= HIGH_BAUD_RATE_THRESHOLD {
        HIGH_BAUD_RATE_FRAME_SILENCE
    } else {
        let char_time_nanos = 11_000_000_000u64 / baud_rate as u64;
        Duration::from_nanos(char_time_nanos * 7 / 2)
    }
}

/// Reads one RTU frame's raw bytes (unit ID + PDU + CRC, undecoded) by
/// waiting for silence: `timeout` bounds how long to wait for the *first*
/// byte (matching how a stalled peer is handled elsewhere in this crate),
/// then `frame_silence` bounds the gap allowed between any two bytes
/// within the same frame — once that elapses, whatever's been read so far
/// is the complete frame.
async fn read_rtu_frame<S>(
    stream: &mut S,
    frame_silence: Duration,
    timeout: Duration,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut frame = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let step_timeout = if frame.is_empty() {
            timeout
        } else {
            frame_silence
        };
        match tokio::time::timeout(step_timeout, stream.read(&mut byte)).await {
            Ok(Ok(0)) if frame.is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before any RTU frame data arrived",
                ));
            }
            Ok(Ok(0)) => break, // connection closed after a partial/complete frame
            Ok(Ok(_)) => {
                frame.push(byte[0]);
                if frame.len() > RTU_MAX_FRAME_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "RTU frame exceeded the maximum possible ADU length without a silence gap",
                    ));
                }
            }
            Ok(Err(error)) => return Err(error),
            Err(_elapsed) if frame.is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Modbus operation timed out",
                ));
            }
            Err(_elapsed) => break, // silence: the frame is complete
        }
    }
    Ok(frame)
}

/// Sends `request` over `stream` and returns the response. RTU has no
/// transaction ID to match (see `RtuAdu`) — on a mostly-half-duplex serial
/// link there's only ever one outstanding request, so whatever comes back
/// after sending is taken as the response to it.
pub async fn send_request<S>(
    stream: &mut S,
    request: RtuAdu,
    frame_silence: Duration,
    timeout: Duration,
) -> io::Result<RtuAdu>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    with_timeout(timeout, stream.write_all(&request.encode())).await?;
    let frame = read_rtu_frame(stream, frame_silence, timeout).await?;
    RtuAdu::decode(&frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))
}

/// Reads one request off `stream`, passes its PDU bytes to `handler`, and
/// writes the handler's response PDU back under the same unit ID —
/// mirrors `tcp::serve_request`'s shape and hardening (bounded read/write
/// steps; `handler` itself is not subject to a timeout, same reasoning as
/// the TCP version).
pub async fn serve_request<S, H>(
    stream: &mut S,
    mut handler: H,
    frame_silence: Duration,
    timeout: Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: AsyncFnMut(&[u8]) -> Vec<u8>,
{
    let frame = read_rtu_frame(stream, frame_silence, timeout).await?;
    let request = RtuAdu::decode(&frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))?;
    let response_pdu = handler(&request.pdu).await;
    let response = RtuAdu {
        unit_id: request.unit_id,
        pdu: response_pdu,
    };
    with_timeout(timeout, stream.write_all(&response.encode())).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_silence_is_a_flat_1_75ms_at_high_baud_rates() {
        assert_eq!(
            frame_silence_for_baud_rate(19200),
            Duration::from_micros(1750)
        );
        assert_eq!(
            frame_silence_for_baud_rate(115200),
            Duration::from_micros(1750)
        );
    }

    #[test]
    fn frame_silence_follows_the_3_5_character_time_formula_below_19200() {
        // At 9600 baud, one character (11 bits) takes 11/9600 s ≈ 1145.83µs;
        // 3.5 character times ≈ 4010.4µs.
        let silence = frame_silence_for_baud_rate(9600);
        assert!(
            silence >= Duration::from_micros(4000) && silence <= Duration::from_micros(4020),
            "expected ~4010µs, got {silence:?}"
        );
    }

    #[tokio::test]
    async fn send_request_returns_the_response_after_a_silence_gap() {
        let (mut client, mut device) = tokio::io::duplex(1024);

        let request = RtuAdu {
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };
        let expected_request_bytes = request.encode();

        let response = RtuAdu {
            unit_id: 0x01,
            pdu: vec![0x03, 0x04, 0x00, 0x01, 0x00, 0x02],
        };
        let response_bytes = response.encode();

        let device_task = tokio::spawn(async move {
            let mut received = vec![0u8; expected_request_bytes.len()];
            device.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_request_bytes);
            // Write byte-by-byte with a gap shorter than frame_silence
            // between each, to prove the reader tolerates a slow/dribbling
            // peer within one frame instead of only working when the
            // whole response arrives in a single chunk.
            for byte in &response_bytes {
                device.write_all(&[*byte]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });

        let received_response = send_request(
            &mut client,
            request,
            Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(received_response, response);

        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn send_request_times_out_when_nothing_ever_arrives() {
        let (mut client, _device) = tokio::io::duplex(1024);

        let request = RtuAdu {
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };

        let result = send_request(
            &mut client,
            request,
            Duration::from_millis(20),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn serve_request_dispatches_to_handler_and_writes_response() {
        let (mut server, mut client) = tokio::io::duplex(1024);

        let request = RtuAdu {
            unit_id: 0x07,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };
        let request_bytes = request.encode();

        let response_pdu = vec![0x03, 0x04, 0x00, 0x01, 0x00, 0x02];
        let expected_response = RtuAdu {
            unit_id: 0x07,
            pdu: response_pdu.clone(),
        };
        let expected_response_bytes = expected_response.encode();

        let client_task = tokio::spawn(async move {
            client.write_all(&request_bytes).await.unwrap();
            let mut received = vec![0u8; expected_response_bytes.len()];
            client.read_exact(&mut received).await.unwrap();
            received
        });

        serve_request(
            &mut server,
            async move |pdu: &[u8]| {
                assert_eq!(pdu, &[0x03, 0x00, 0x00, 0x00, 0x0A]);
                response_pdu.clone()
            },
            Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        let received_bytes = client_task.await.unwrap();
        assert_eq!(RtuAdu::decode(&received_bytes).unwrap(), expected_response);
    }

    #[tokio::test]
    async fn serve_request_times_out_when_request_never_arrives() {
        let (mut server, _client) = tokio::io::duplex(1024);

        let result = serve_request(
            &mut server,
            async move |_pdu: &[u8]| Vec::new(),
            Duration::from_millis(20),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn send_request_rejects_a_frame_with_a_bad_crc() {
        let (mut client, mut device) = tokio::io::duplex(1024);

        let request = RtuAdu {
            unit_id: 0x01,
            pdu: vec![0x03, 0x00, 0x00, 0x00, 0x0A],
        };
        let expected_request_bytes = request.encode();

        let device_task = tokio::spawn(async move {
            let mut received = vec![0u8; expected_request_bytes.len()];
            device.read_exact(&mut received).await.unwrap();
            // A well-formed-looking frame with a deliberately wrong CRC.
            device
                .write_all(&[0x01, 0x03, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00])
                .await
                .unwrap();
        });

        let result = send_request(
            &mut client,
            request,
            Duration::from_millis(20),
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());

        device_task.await.unwrap();
    }
}
