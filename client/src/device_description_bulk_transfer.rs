// Thread A8's client-side half of the FC43-manifest + FC20-bulk-transfer
// fallback (CLAUDE.md's "Planned: grow FC43's device-description transfer
// capacity past its current ~31KB ceiling") — the counterpart to
// `server::fc43_bulk_transfer`/`handler::handle_read_device_description_
// bulk_transfer`. `device_identification::fetch_device_description` calls
// into `fetch_compressed_device_description` once it notices its FC43
// response parses as a `DeviceDescriptionManifest` rather than a real
// device description.
//
// Every failure here (transport error, exception, malformed response,
// decompression failure) folds into the exact same fallback chain as
// every other FC43 failure mode: `None`, meaning "use the local TOML file
// instead" — no new failure philosophy needed, per CLAUDE.md's
// "Decompression failure" note.
//
// `decompress_toml_source` deliberately duplicates
// `server::device_description_compression::decompress_toml_source` rather
// than sharing it across a crate boundary — the two sides need opposite
// halves of the same codec (server only ever compresses, client only
// ever decompresses), and it's a handful of lines, not a case this
// project's extraction-based-programming convention calls a shared
// abstraction for yet. `MAX_DECOMPRESSED_LEN` is copied for the same
// "harden against a malicious/buggy peer" reason the server's own copy
// exists: an attacker-controlled `compressed_length`/stream shouldn't be
// able to make this client allocate unbounded memory.

use crate::connection::Connection;
use miniz_oxide::inflate::{DecompressError, decompress_to_vec_with_limit};
use protocol::device_description_manifest::{DeviceDescriptionManifest, bulk_transfer_chunk_range};
use protocol::pdu::{
    ExceptionResponse, FileRecordSubRequest, ReadFileRecordRequest, ReadFileRecordResponse,
};
use std::time::Duration;

const MAX_DECOMPRESSED_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug)]
enum DecompressTomlSourceError {
    Decompress(DecompressError),
    InvalidUtf8(std::string::FromUtf8Error),
}

impl std::fmt::Display for DecompressTomlSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompressTomlSourceError::Decompress(error) => {
                write!(formatter, "failed to decompress: {error:?}")
            }
            DecompressTomlSourceError::InvalidUtf8(error) => {
                write!(formatter, "decompressed bytes are not valid UTF-8: {error}")
            }
        }
    }
}

fn decompress_toml_source(compressed: &[u8]) -> Result<String, DecompressTomlSourceError> {
    let decompressed = decompress_to_vec_with_limit(compressed, MAX_DECOMPRESSED_LEN)
        .map_err(DecompressTomlSourceError::Decompress)?;
    String::from_utf8(decompressed).map_err(DecompressTomlSourceError::InvalidUtf8)
}

/// Fetches and decompresses the real device description via FC20, using
/// `manifest`'s `file_number`/`compressed_length` — `bulk_transfer_chunk_range`
/// (shared with the server, so the two sides can never disagree about
/// chunk boundaries) determines how many records to request and exactly
/// what `record_length` each one needs. Returns `None` on any failure,
/// same meaning as `device_identification::fetch_device_description`'s own
/// `None`: fall back to the caller's local description.
pub async fn fetch_compressed_device_description(
    connection: &mut Connection,
    unit_id: u8,
    manifest: &DeviceDescriptionManifest,
    timeout: Duration,
) -> Option<String> {
    println!(
        "Server's device description doesn't fit FC43 directly — fetching {} compressed \
         byte(s) over FC20 instead ({} machine(s))...",
        manifest.compressed_length,
        manifest.machines.len()
    );

    let compressed_length = manifest.compressed_length as usize;
    let mut compressed = Vec::with_capacity(compressed_length);
    let mut record_number: u16 = 0;

    while let Some(range) = bulk_transfer_chunk_range(compressed_length, record_number) {
        let record_length = (range.end - range.start).div_ceil(2) as u16;
        let request_pdu = ReadFileRecordRequest {
            sub_requests: vec![FileRecordSubRequest {
                file_number: manifest.file_number,
                record_number,
                record_length,
            }],
        }
        .encode();

        let response_pdu = match connection.request(unit_id, request_pdu, timeout).await {
            Ok(response_pdu) => response_pdu,
            Err(error) => {
                println!(
                    "FC20 bulk-transfer request failed ({error}) — using the local description \
                     instead."
                );
                return None;
            }
        };

        if let Ok(exception) = ExceptionResponse::decode(&response_pdu) {
            println!(
                "Server rejected the FC20 bulk-transfer request (Modbus exception code {}) — \
                 using the local description instead.",
                exception.exception_code
            );
            return None;
        }
        let Ok(response) = ReadFileRecordResponse::decode(&response_pdu) else {
            println!(
                "Server sent an unexpected response to the FC20 bulk-transfer request — using \
                 the local description instead."
            );
            return None;
        };
        let Some(record) = response.records.first() else {
            println!(
                "Server's FC20 bulk-transfer response carried no record — using the local \
                 description instead."
            );
            return None;
        };
        compressed.extend_from_slice(record);
        record_number += 1;
    }

    compressed.truncate(compressed_length);
    match decompress_toml_source(&compressed) {
        Ok(toml_source) => {
            println!(
                "Decompressed the server's device description ({} bytes).",
                toml_source.len()
            );
            Some(toml_source)
        }
        Err(error) => {
            println!(
                "Failed to decompress the server's device description ({error}) — using the \
                 local description instead."
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::compress_to_vec;
    use protocol::adu::TcpAdu;
    use protocol::device_description_manifest::{BULK_TRANSFER_CHUNK_BYTES, ManifestMachine};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn connected_pair() -> (Connection, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let connection = Connection::connect_tcp(&address).await.unwrap();
        let (device, _peer) = listener.accept().await.unwrap();
        (connection, device)
    }

    async fn read_request(device: &mut tokio::net::TcpStream) -> (u16, ReadFileRecordRequest) {
        let mut header = vec![0u8; 7];
        device.read_exact(&mut header).await.unwrap();
        // Unlike FC43's fixed-length request, FC20's PDU is variable-length
        // (function code + byte_count + byte_count more bytes) — read the
        // first two bytes to learn byte_count before reading the rest.
        let mut function_and_count = vec![0u8; 2];
        device.read_exact(&mut function_and_count).await.unwrap();
        let byte_count = function_and_count[1];
        let mut rest = vec![0u8; byte_count as usize];
        device.read_exact(&mut rest).await.unwrap();
        let transaction_id = u16::from_be_bytes([header[0], header[1]]);
        let mut pdu = function_and_count;
        pdu.extend_from_slice(&rest);
        (transaction_id, ReadFileRecordRequest::decode(&pdu).unwrap())
    }

    async fn write_response(device: &mut tokio::net::TcpStream, transaction_id: u16, pdu: Vec<u8>) {
        let response = TcpAdu {
            transaction_id,
            unit_id: 1,
            pdu,
        };
        device.write_all(&response.encode()).await.unwrap();
    }

    fn sample_manifest(compressed: &[u8]) -> DeviceDescriptionManifest {
        DeviceDescriptionManifest {
            file_number: 0xFFFF,
            compressed_length: compressed.len() as u32,
            machines: vec![ManifestMachine {
                name: "PumpA".to_string(),
                unit_id: 1,
            }],
        }
    }

    #[tokio::test]
    async fn fetches_and_decompresses_a_single_chunk_blob() {
        let (mut connection, mut device) = connected_pair().await;
        let toml_source = "name = \"Stop_Process\"\n";
        let compressed = compress_to_vec(toml_source.as_bytes(), 10);
        let manifest = sample_manifest(&compressed);

        let expected_record_length = compressed.len().div_ceil(2) as u16;
        let device_compressed = compressed.clone();
        let device_task = tokio::spawn(async move {
            let (transaction_id, request) = read_request(&mut device).await;
            assert_eq!(request.sub_requests[0].record_number, 0);
            assert_eq!(
                request.sub_requests[0].record_length,
                expected_record_length
            );

            let mut record = device_compressed;
            if !record.len().is_multiple_of(2) {
                record.push(0);
            }
            let response = ReadFileRecordResponse {
                records: vec![record],
            };
            write_response(&mut device, transaction_id, response.encode()).await;
        });

        let result = fetch_compressed_device_description(
            &mut connection,
            1,
            &manifest,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result, Some(toml_source.to_string()));
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn fetches_and_reassembles_a_blob_spanning_several_chunks() {
        let (mut connection, mut device) = connected_pair().await;
        // Pseudo-random, not trivially compressible -- same reasoning as
        // server::handler's own multi-chunk test: a highly repetitive
        // source would collapse to a single chunk under DEFLATE.
        let toml_source: String = {
            let mut state: u32 = 0xABCD_EF01;
            (0..BULK_TRANSFER_CHUNK_BYTES * 3)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    (b'!' + (state % 94) as u8) as char
                })
                .collect()
        };
        let compressed = compress_to_vec(toml_source.as_bytes(), 10);
        assert!(
            compressed.len() > BULK_TRANSFER_CHUNK_BYTES,
            "test setup needs more than one chunk"
        );
        let manifest = sample_manifest(&compressed);

        let device_compressed = compressed.clone();
        let device_task = tokio::spawn(async move {
            loop {
                let (transaction_id, request) = read_request(&mut device).await;
                let sub_request = request.sub_requests[0];
                let start = sub_request.record_number as usize * BULK_TRANSFER_CHUNK_BYTES;
                let end = (start + BULK_TRANSFER_CHUNK_BYTES).min(device_compressed.len());
                let mut record = device_compressed[start..end].to_vec();
                if !record.len().is_multiple_of(2) {
                    record.push(0);
                }
                let response = ReadFileRecordResponse {
                    records: vec![record],
                };
                write_response(&mut device, transaction_id, response.encode()).await;
                if end >= device_compressed.len() {
                    break;
                }
            }
        });

        let result = fetch_compressed_device_description(
            &mut connection,
            1,
            &manifest,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result, Some(toml_source));
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_when_the_server_rejects_the_request() {
        let (mut connection, mut device) = connected_pair().await;
        let compressed = compress_to_vec(b"name = \"X\"", 10);
        let manifest = sample_manifest(&compressed);

        let device_task = tokio::spawn(async move {
            let (transaction_id, _request) = read_request(&mut device).await;
            let exception = ExceptionResponse {
                function_code: 0x14,
                exception_code: protocol::pdu::EXCEPTION_ILLEGAL_DATA_ADDRESS,
            };
            write_response(&mut device, transaction_id, exception.encode()).await;
        });

        let result = fetch_compressed_device_description(
            &mut connection,
            1,
            &manifest,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result, None);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_when_decompression_fails() {
        let (mut connection, mut device) = connected_pair().await;
        // A manifest claiming one byte of garbage, not a real DEFLATE
        // stream -- decompression must fail cleanly, not panic.
        let manifest = sample_manifest(&[0xFF]);

        let device_task = tokio::spawn(async move {
            let (transaction_id, _request) = read_request(&mut device).await;
            let response = ReadFileRecordResponse {
                records: vec![vec![0xFF, 0x00]],
            };
            write_response(&mut device, transaction_id, response.encode()).await;
        });

        let result = fetch_compressed_device_description(
            &mut connection,
            1,
            &manifest,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result, None);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_when_the_server_never_responds() {
        let (mut connection, _device) = connected_pair().await;
        let compressed = compress_to_vec(b"name = \"X\"", 10);
        let manifest = sample_manifest(&compressed);

        let result = fetch_compressed_device_description(
            &mut connection,
            1,
            &manifest,
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(result, None);
    }
}
