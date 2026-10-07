// Moved here verbatim from `protocol::lib.rs` (pre-move) -- both enums are
// already dependency-free (plain u8/u16/usize fields), no change needed to
// make them portable. `protocol` will re-export these once it's wired to
// depend on `protocol-core` (a later, separate step) rather than keeping a
// second, divergence-prone copy.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    UnexpectedFunctionCode {
        expected: u8,
        actual: u8,
    },
    OddByteCount {
        byte_count: u8,
    },
    NotAnExceptionResponse {
        function_code: u8,
    },
    InvalidCoilValue {
        actual: u16,
    },
    QuantityByteCountMismatch {
        quantity: u16,
        byte_count: u8,
    },
    UnexpectedMeiType {
        expected: u8,
        actual: u8,
    },
    UnexpectedProtocolId {
        actual: u16,
    },
    InvalidAduLength {
        length: u16,
    },
    CrcMismatch {
        expected: u16,
        actual: u16,
    },
    InvalidFileRecordByteCount {
        byte_count: u8,
    },
    InvalidFileRecordReferenceType {
        actual: u8,
    },
    InvalidFileRecordSubResponseLength {
        length: u8,
    },
    /// New in the `protocol-core` port: a decoded count/length that fits
    /// the wire's own fields (e.g. a `u8` byte_count) but would overflow
    /// one of this crate's fixed-capacity container types. Every container
    /// capacity was sized to the real Modbus per-PDU ceiling (see e.g.
    /// `register_values::MAX_REGISTER_COUNT`'s own doc comment), so a
    /// well-formed peer can never actually trigger this -- same status as
    /// every other variant here, a malformed/malicious-peer-only case.
    TooLargeForBuffer,
}

// Unlike `DecodeError`, used sparingly — every other `encode()` in this crate
// is infallible by construction (it's building wire bytes from an already-
// valid Rust value). `WriteMultipleRegistersRequest::encode` and
// `ReadWriteMultipleRegistersRequest::encode` are the exceptions: both carry
// a register-value list whose length isn't bounded tightly enough by the
// container type alone (their own wire-level ceiling, 123/121, is stricter
// than `RegisterValues`' shared 125 capacity), so an over-long one has to be
// rejected explicitly rather than silently truncated by the `as u16`/`as u8`
// casts their wire format's own quantity/byte-count fields need.
// `WriteFileRecordRequest::encode`/`WriteFileRecordResponse::encode` are the
// same kind of exception: `record_data`'s byte length isn't required to be
// even by the type system either, and the wire's own `record_length` field
// (`record_data.len() / 2`) would otherwise silently truncate an odd length
// instead of failing loudly.
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
    /// New in the `protocol-core` port: the real wire-encoded total (after
    /// adding back per-entry overhead a flat-buffer container's own
    /// capacity doesn't account for -- see e.g.
    /// `ReportServerIdResponse::encode`'s doc comment) would exceed
    /// `MAX_PDU_LEN`. A valid Rust value that doesn't fit the wire format,
    /// same status as `TooManyRegisters`/`OddFileRecordDataLength` above,
    /// not a panic.
    TooLargeForBuffer,
}

pub(crate) fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
