// FC 0x14/0x15 (Read/Write File Record) support types.

use crate::pdu_bytes::{CapacityExceeded, PduBytes};

/// One sub-request within a Read File Record request — see
/// `protocol::pdu::FileRecordSubRequest`'s own (pre-move) doc comment for
/// the full wire-format rationale; this is the same plain, dependency-free
/// shape (three `u16`s, no `reference_type` field since the wire's own
/// value is always the protocol constant `6`, not information a caller can
/// get wrong).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRecordSubRequest {
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
}

const ZERO_SUB_REQUEST: FileRecordSubRequest = FileRecordSubRequest {
    file_number: 0,
    record_number: 0,
    record_length: 0,
};

/// Capped at 35: each sub-request wire-encodes to 7 bytes (reference_type +
/// file_number + record_number + record_length), and a request PDU has
/// function_code(1) + up to MAX_PDU_LEN - 1 = 252 bytes left for
/// sub-requests -- 252 / 7 = 36, so 35 is the real floor (36 would overflow
/// by one byte once the function-code byte is accounted for exactly).
pub const MAX_FILE_RECORD_SUB_REQUESTS: usize = 35;

#[derive(Debug, Clone, Copy)]
pub struct FileRecordSubRequests {
    data: [FileRecordSubRequest; MAX_FILE_RECORD_SUB_REQUESTS],
    len: usize,
}

impl FileRecordSubRequests {
    pub const fn new() -> Self {
        Self {
            data: [ZERO_SUB_REQUEST; MAX_FILE_RECORD_SUB_REQUESTS],
            len: 0,
        }
    }

    pub fn push(&mut self, sub_request: FileRecordSubRequest) -> Result<(), CapacityExceeded> {
        if self.len == MAX_FILE_RECORD_SUB_REQUESTS {
            return Err(CapacityExceeded);
        }
        self.data[self.len] = sub_request;
        self.len += 1;
        Ok(())
    }

    pub fn as_slice(&self) -> &[FileRecordSubRequest] {
        &self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for FileRecordSubRequests {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for FileRecordSubRequests {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for FileRecordSubRequests {}

impl core::ops::Deref for FileRecordSubRequests {
    type Target = [FileRecordSubRequest];

    fn deref(&self) -> &[FileRecordSubRequest] {
        self.as_slice()
    }
}

/// A Read File Record *response*'s records: every record's raw bytes,
/// concatenated into one flat `PduBytes` buffer, plus each record's own
/// byte length so a caller can slice the buffer back apart. Deliberately
/// flat rather than `[PduBytes; N]`: a single record can in principle be
/// nearly PDU-sized, so an array of `N` full `PduBytes`-sized slots would
/// reserve `N * MAX_PDU_LEN` bytes per instance (~8.6KB for N=35)
/// regardless of how much data is actually present. The flat buffer only
/// ever uses the PDU's own real ~253-byte budget once, since every record
/// in one response always shares that same budget on the wire anyway.
pub const MAX_FILE_RECORDS: usize = MAX_FILE_RECORD_SUB_REQUESTS;

#[derive(Debug, Clone, Copy)]
pub struct FileRecordResponseData {
    data: PduBytes,
    record_lengths: [u16; MAX_FILE_RECORDS],
    record_count: usize,
}

impl FileRecordResponseData {
    pub const fn new() -> Self {
        Self {
            data: PduBytes::new(),
            record_lengths: [0u16; MAX_FILE_RECORDS],
            record_count: 0,
        }
    }

    pub fn push_record(&mut self, record: &[u8]) -> Result<(), CapacityExceeded> {
        if self.record_count == MAX_FILE_RECORDS {
            return Err(CapacityExceeded);
        }
        self.data.extend_from_slice(record)?;
        self.record_lengths[self.record_count] = record.len() as u16;
        self.record_count += 1;
        Ok(())
    }

    pub fn record_count(&self) -> usize {
        self.record_count
    }

    pub fn record(&self, index: usize) -> Option<&[u8]> {
        if index >= self.record_count {
            return None;
        }
        let start: usize = self.record_lengths[..index]
            .iter()
            .map(|&length| length as usize)
            .sum();
        let end = start + self.record_lengths[index] as usize;
        Some(&self.data[start..end])
    }
}

impl Default for FileRecordResponseData {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for FileRecordResponseData {
    fn eq(&self, other: &Self) -> bool {
        self.record_count == other.record_count
            && (0..self.record_count).all(|index| self.record(index) == other.record(index))
    }
}

impl Eq for FileRecordResponseData {}

/// A Write File Record request's (or its echoing response's) sub-requests:
/// each one's `record_data` bytes, concatenated into one flat `PduBytes`
/// buffer, plus each sub-request's `file_number`/`record_number` and byte
/// length so a caller can both identify each entry and slice the buffer
/// back apart. Same flat-buffer-over-array-of-buffers reasoning as
/// `FileRecordResponseData` above — an array of `N` full
/// `WriteFileRecordSubRequest`-with-embedded-`PduBytes` slots would reserve
/// roughly `N * MAX_PDU_LEN` bytes per instance regardless of how much data
/// is actually present. One shared type for both the request and the
/// response: per spec, a Write File Record response echoes its request's
/// sub-requests back exactly, same shape either way.
pub const MAX_WRITE_FILE_RECORD_SUB_REQUESTS: usize = MAX_FILE_RECORD_SUB_REQUESTS;

#[derive(Debug, Clone, Copy)]
pub struct WriteFileRecordSubRequests {
    data: PduBytes,
    file_numbers: [u16; MAX_WRITE_FILE_RECORD_SUB_REQUESTS],
    record_numbers: [u16; MAX_WRITE_FILE_RECORD_SUB_REQUESTS],
    record_data_lengths: [u16; MAX_WRITE_FILE_RECORD_SUB_REQUESTS],
    count: usize,
}

impl WriteFileRecordSubRequests {
    pub const fn new() -> Self {
        Self {
            data: PduBytes::new(),
            file_numbers: [0u16; MAX_WRITE_FILE_RECORD_SUB_REQUESTS],
            record_numbers: [0u16; MAX_WRITE_FILE_RECORD_SUB_REQUESTS],
            record_data_lengths: [0u16; MAX_WRITE_FILE_RECORD_SUB_REQUESTS],
            count: 0,
        }
    }

    pub fn push(
        &mut self,
        file_number: u16,
        record_number: u16,
        record_data: &[u8],
    ) -> Result<(), CapacityExceeded> {
        if self.count == MAX_WRITE_FILE_RECORD_SUB_REQUESTS {
            return Err(CapacityExceeded);
        }
        self.data.extend_from_slice(record_data)?;
        self.file_numbers[self.count] = file_number;
        self.record_numbers[self.count] = record_number;
        self.record_data_lengths[self.count] = record_data.len() as u16;
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns `(file_number, record_number, record_data)` for the
    /// sub-request at `index`.
    pub fn sub_request(&self, index: usize) -> Option<(u16, u16, &[u8])> {
        if index >= self.count {
            return None;
        }
        let start: usize = self.record_data_lengths[..index]
            .iter()
            .map(|&length| length as usize)
            .sum();
        let end = start + self.record_data_lengths[index] as usize;
        Some((
            self.file_numbers[index],
            self.record_numbers[index],
            &self.data[start..end],
        ))
    }
}

impl Default for WriteFileRecordSubRequests {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for WriteFileRecordSubRequests {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count
            && (0..self.count).all(|index| self.sub_request(index) == other.sub_request(index))
    }
}

impl Eq for WriteFileRecordSubRequests {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_requests_push_and_slice() {
        let mut sub_requests = FileRecordSubRequests::new();
        sub_requests
            .push(FileRecordSubRequest {
                file_number: 20,
                record_number: 5,
                record_length: 9,
            })
            .unwrap();
        assert_eq!(sub_requests.len(), 1);
        assert_eq!(sub_requests[0].file_number, 20);
    }

    #[test]
    fn sub_requests_push_fails_without_panicking_once_full() {
        let mut sub_requests = FileRecordSubRequests::new();
        for _ in 0..MAX_FILE_RECORD_SUB_REQUESTS {
            sub_requests.push(ZERO_SUB_REQUEST).unwrap();
        }
        assert_eq!(sub_requests.push(ZERO_SUB_REQUEST), Err(CapacityExceeded));
    }

    #[test]
    fn response_data_push_record_and_read_back() {
        let mut data = FileRecordResponseData::new();
        data.push_record(&[1, 2, 3]).unwrap();
        data.push_record(&[4, 5]).unwrap();

        assert_eq!(data.record_count(), 2);
        assert_eq!(data.record(0), Some(&[1, 2, 3][..]));
        assert_eq!(data.record(1), Some(&[4, 5][..]));
        assert_eq!(data.record(2), None);
    }

    #[test]
    fn response_data_push_record_fails_without_panicking_once_byte_capacity_exceeded() {
        let mut data = FileRecordResponseData::new();
        data.push_record(&[0u8; 250]).unwrap();
        assert_eq!(data.push_record(&[0u8; 10]), Err(CapacityExceeded));
        // Rejected atomically -- the first record is still intact.
        assert_eq!(data.record_count(), 1);
        assert_eq!(data.record(0), Some(&[0u8; 250][..]));
    }

    #[test]
    fn response_data_push_record_fails_without_panicking_once_record_count_exceeded() {
        let mut data = FileRecordResponseData::new();
        for _ in 0..MAX_FILE_RECORDS {
            data.push_record(&[1]).unwrap();
        }
        assert_eq!(data.push_record(&[1]), Err(CapacityExceeded));
    }

    #[test]
    fn response_data_equality_compares_records_not_padding() {
        let mut a = FileRecordResponseData::new();
        a.push_record(&[1, 2]).unwrap();
        let mut b = FileRecordResponseData::new();
        b.push_record(&[1, 2]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn write_sub_requests_push_and_read_back() {
        let mut sub_requests = WriteFileRecordSubRequests::new();
        sub_requests.push(20, 5, &[1, 2, 3, 4]).unwrap();
        sub_requests.push(21, 6, &[9, 9]).unwrap();

        assert_eq!(sub_requests.count(), 2);
        assert_eq!(
            sub_requests.sub_request(0),
            Some((20, 5, &[1, 2, 3, 4][..]))
        );
        assert_eq!(sub_requests.sub_request(1), Some((21, 6, &[9, 9][..])));
        assert_eq!(sub_requests.sub_request(2), None);
    }

    #[test]
    fn write_sub_requests_push_fails_without_panicking_once_byte_capacity_exceeded() {
        let mut sub_requests = WriteFileRecordSubRequests::new();
        sub_requests.push(1, 1, &[0u8; 250]).unwrap();
        assert_eq!(sub_requests.push(1, 2, &[0u8; 10]), Err(CapacityExceeded));
        assert_eq!(sub_requests.count(), 1);
    }

    #[test]
    fn write_sub_requests_push_fails_without_panicking_once_count_exceeded() {
        let mut sub_requests = WriteFileRecordSubRequests::new();
        for _ in 0..MAX_WRITE_FILE_RECORD_SUB_REQUESTS {
            sub_requests.push(1, 1, &[1]).unwrap();
        }
        assert_eq!(sub_requests.push(1, 1, &[1]), Err(CapacityExceeded));
    }

    #[test]
    fn write_sub_requests_equality_compares_entries_not_padding() {
        let mut a = WriteFileRecordSubRequests::new();
        a.push(1, 2, &[3, 4]).unwrap();
        let mut b = WriteFileRecordSubRequests::new();
        b.push(1, 2, &[3, 4]).unwrap();
        assert_eq!(a, b);
    }
}
