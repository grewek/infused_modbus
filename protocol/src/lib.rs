pub mod adu;
pub mod connection_string;
pub mod device_description;
pub mod device_description_manifest;
pub mod pdu;
pub mod rtu;
pub mod tcp;
pub mod tls;

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
    QuantityByteCountMismatch { quantity: u16, byte_count: u8 },
    UnexpectedMeiType { expected: u8, actual: u8 },
    UnexpectedProtocolId { actual: u16 },
    InvalidAduLength { length: u16 },
    CrcMismatch { expected: u16, actual: u16 },
    InvalidFileRecordByteCount { byte_count: u8 },
    InvalidFileRecordReferenceType { actual: u8 },
    InvalidFileRecordSubResponseLength { length: u8 },
}

// Unlike `DecodeError`, used sparingly — every other `encode()` in this crate
// is infallible by construction (it's building wire bytes from an already-
// valid Rust value). `WriteMultipleRegistersRequest::encode` and
// `ReadWriteMultipleRegistersRequest::encode` are the exceptions: both carry
// a register-value vec whose length isn't bounded by the type system, so an
// over-long one has to be rejected explicitly rather than silently truncated
// by the `as u16`/`as u8` casts their wire format's own quantity/byte-count
// fields need. `WriteFileRecordRequest::encode`/`WriteFileRecordResponse::encode`
// are the same kind of exception: `record_data`'s byte length isn't bounded
// to be even by the type system either, and the wire's own `record_length`
// field (`record_data.len() / 2`) would otherwise silently truncate an odd
// length instead of failing loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    TooManyRegisters {
        count: usize,
        max: usize,
    },
    OddFileRecordDataLength {
        file_number: u16,
        record_number: u16,
        length: usize,
    },
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
