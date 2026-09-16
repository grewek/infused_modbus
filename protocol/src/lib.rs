pub mod adu;
pub mod device_description;
pub mod pdu;
pub mod rtu;
pub mod tcp;

use std::future::Future;
use std::io;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    UnexpectedFunctionCode { expected: u8, actual: u8 },
    OddByteCount { byte_count: u8 },
    NotAnExceptionResponse { function_code: u8 },
    InvalidCoilValue { actual: u16 },
    UnexpectedMeiType { expected: u8, actual: u8 },
    UnexpectedProtocolId { actual: u16 },
    InvalidAduLength { length: u16 },
    CrcMismatch { expected: u16, actual: u16 },
}

pub(crate) fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

// Wraps a single I/O step (one read or one write) so a peer that stalls
// mid-operation can't tie up a connection indefinitely. `timeout` bounds
// each I/O step individually, not the whole request/response exchange,
// matching how a plain socket read/write timeout behaves. Shared between
// `tcp` and `rtu` — both need the identical wrapping around their I/O.
pub(crate) async fn with_timeout<T>(
    timeout: Duration,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Modbus operation timed out",
        )),
    }
}
