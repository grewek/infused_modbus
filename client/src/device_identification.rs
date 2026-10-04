// Asks a server to "introduce itself" via FC 43 / MEI 0x0E (Read Device
// Identification, Extended access) instead of requiring a local copy of
// its device-description.toml — see server/src/device_identification.rs
// for the object layout this reads (0x80 = presence flag, 0x81+ = the
// TOML source, chunked).
//
// This can take several round trips (one per response that doesn't fit
// everything in one PDU — see the server side's MAX_TOML_CHUNK_LEN), so
// progress is printed as it goes: without this, a user watching the
// client start up would have no way to tell "still fetching" apart from
// "hung".

use crate::connection::Connection;
use crate::device_description_bulk_transfer::fetch_compressed_device_description;
use protocol::device_description_manifest::DeviceDescriptionManifest;
use protocol::pdu::{
    ExceptionResponse, READ_DEVICE_ID_EXTENDED, ReadDeviceIdentificationRequest,
    ReadDeviceIdentificationResponse,
};
use std::time::Duration;

const PRESENCE_OBJECT_ID: u8 = 0x80;
const FIRST_TOML_CHUNK_OBJECT_ID: u8 = 0x81;

/// Fetches the server's device description over FC43, or returns `None`
/// if it doesn't have one (presence flag false), doesn't support the
/// request at all (a Modbus exception, e.g. an older/simpler device), or
/// anything about the exchange goes wrong (transport error, malformed
/// response, non-UTF-8 content) — every failure mode is treated the same
/// way: fall back to the caller's local description, not a fatal error.
pub async fn fetch_device_description(
    connection: &mut Connection,
    unit_id: u8,
    timeout: Duration,
) -> Option<String> {
    println!("Asking server for a device description (FC43)...");

    let mut object_id = PRESENCE_OBJECT_ID;
    let mut chunks: Vec<Vec<u8>> = Vec::new();

    loop {
        let request_pdu = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id,
        }
        .encode();

        let response_pdu = match connection.request(unit_id, request_pdu, timeout).await {
            Ok(response_pdu) => response_pdu,
            Err(error) => {
                println!("FC43 request failed ({error}) — using the local description instead.");
                return None;
            }
        };

        if let Ok(exception) = ExceptionResponse::decode(&response_pdu) {
            println!(
                "Server doesn't support FC43 (Modbus exception code {}) — using the local description instead.",
                exception.exception_code
            );
            return None;
        }
        let Ok(response) = ReadDeviceIdentificationResponse::decode(&response_pdu) else {
            println!(
                "Server sent an unexpected response to the FC43 request — using the local description instead."
            );
            return None;
        };

        for object in response.objects {
            match object.id {
                PRESENCE_OBJECT_ID => {
                    if object.value.first() != Some(&1) {
                        println!(
                            "Server has no device description to offer — using the local description instead."
                        );
                        return None;
                    }
                    println!("Server has a device description — fetching it...");
                }
                id if id >= FIRST_TOML_CHUNK_OBJECT_ID => {
                    println!(
                        "Received chunk 0x{:02X} ({} bytes)...",
                        id,
                        object.value.len()
                    );
                    chunks.push(object.value);
                }
                _ => {}
            }
        }

        if !response.more_follows {
            break;
        }
        object_id = response.next_object_id;
    }

    let toml_bytes: Vec<u8> = chunks.into_iter().flatten().collect();
    let toml_source = match String::from_utf8(toml_bytes) {
        Ok(toml_source) => toml_source,
        Err(_) => {
            println!(
                "Server's device description was not valid UTF-8 — using the local description instead."
            );
            return None;
        }
    };

    // Thread A7/A8: a real device description's TOML never has top-level
    // `file_number`/`compressed_length` keys (only `[[machines]]`), so a
    // successful parse here unambiguously means the server fell back to
    // the manifest (Thread A6, once the real description didn't fit
    // FC43's own inline-chunk budget) — fetch and decompress the real
    // thing over FC20 instead of treating this manifest text as the
    // description itself.
    if let Ok(manifest) = DeviceDescriptionManifest::parse(&toml_source) {
        return fetch_compressed_device_description(connection, unit_id, &manifest, timeout).await;
    }

    println!(
        "Received the full device description from the server ({} bytes).",
        toml_source.len()
    );
    Some(toml_source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::adu::TcpAdu;
    use protocol::pdu::{DeviceIdentificationObject, EXCEPTION_ILLEGAL_FUNCTION};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn connected_pair() -> (Connection, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let connection = Connection::connect_tcp(&address).await.unwrap();
        let (device, _peer) = listener.accept().await.unwrap();
        (connection, device)
    }

    // Returns the transaction ID alongside the decoded request so the
    // fake device can echo it back — Connection increments it per
    // request, so a hardcoded response transaction ID only survives the
    // first of several round trips.
    async fn read_request(
        device: &mut tokio::net::TcpStream,
    ) -> (u16, ReadDeviceIdentificationRequest) {
        let mut header = vec![0u8; 7];
        device.read_exact(&mut header).await.unwrap();
        let mut pdu = vec![0u8; 4];
        device.read_exact(&mut pdu).await.unwrap();
        let transaction_id = u16::from_be_bytes([header[0], header[1]]);
        (
            transaction_id,
            ReadDeviceIdentificationRequest::decode(&pdu).unwrap(),
        )
    }

    async fn write_response(device: &mut tokio::net::TcpStream, transaction_id: u16, pdu: Vec<u8>) {
        let response = TcpAdu {
            transaction_id,
            unit_id: 1,
            pdu,
        };
        device.write_all(&response.encode()).await.unwrap();
    }

    #[tokio::test]
    async fn fetches_a_description_that_fits_in_one_response() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let (transaction_id, _request) = read_request(&mut device).await;
            let response = ReadDeviceIdentificationResponse {
                read_device_id_code: READ_DEVICE_ID_EXTENDED,
                conformity_level: 0x03,
                more_follows: false,
                next_object_id: 0,
                objects: vec![
                    DeviceIdentificationObject {
                        id: 0x80,
                        value: vec![0x01],
                    },
                    DeviceIdentificationObject {
                        id: 0x81,
                        value: b"name = \"X\"".to_vec(),
                    },
                ],
            };
            write_response(&mut device, transaction_id, response.encode()).await;
        });

        let result = fetch_device_description(&mut connection, 1, Duration::from_secs(1)).await;
        assert_eq!(result, Some("name = \"X\"".to_string()));
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn fetches_a_description_split_across_multiple_responses() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let (transaction_id, request) = read_request(&mut device).await;
            assert_eq!(request.object_id, 0x80);
            let first = ReadDeviceIdentificationResponse {
                read_device_id_code: READ_DEVICE_ID_EXTENDED,
                conformity_level: 0x03,
                more_follows: true,
                next_object_id: 0x81,
                objects: vec![DeviceIdentificationObject {
                    id: 0x80,
                    value: vec![0x01],
                }],
            };
            write_response(&mut device, transaction_id, first.encode()).await;

            let (transaction_id, request) = read_request(&mut device).await;
            assert_eq!(request.object_id, 0x81);
            let second = ReadDeviceIdentificationResponse {
                read_device_id_code: READ_DEVICE_ID_EXTENDED,
                conformity_level: 0x03,
                more_follows: true,
                next_object_id: 0x82,
                objects: vec![DeviceIdentificationObject {
                    id: 0x81,
                    value: b"part one, ".to_vec(),
                }],
            };
            write_response(&mut device, transaction_id, second.encode()).await;

            let (transaction_id, request) = read_request(&mut device).await;
            assert_eq!(request.object_id, 0x82);
            let third = ReadDeviceIdentificationResponse {
                read_device_id_code: READ_DEVICE_ID_EXTENDED,
                conformity_level: 0x03,
                more_follows: false,
                next_object_id: 0,
                objects: vec![DeviceIdentificationObject {
                    id: 0x82,
                    value: b"part two".to_vec(),
                }],
            };
            write_response(&mut device, transaction_id, third.encode()).await;
        });

        let result = fetch_device_description(&mut connection, 1, Duration::from_secs(1)).await;
        assert_eq!(result, Some("part one, part two".to_string()));
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_when_the_server_has_no_description() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let (transaction_id, _request) = read_request(&mut device).await;
            let response = ReadDeviceIdentificationResponse {
                read_device_id_code: READ_DEVICE_ID_EXTENDED,
                conformity_level: 0x03,
                more_follows: false,
                next_object_id: 0,
                objects: vec![DeviceIdentificationObject {
                    id: 0x80,
                    value: vec![0x00],
                }],
            };
            write_response(&mut device, transaction_id, response.encode()).await;
        });

        let result = fetch_device_description(&mut connection, 1, Duration::from_secs(1)).await;
        assert_eq!(result, None);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_when_the_server_does_not_support_fc43() {
        let (mut connection, mut device) = connected_pair().await;

        let device_task = tokio::spawn(async move {
            let (transaction_id, _request) = read_request(&mut device).await;

            let exception = ExceptionResponse {
                function_code: 0x2B,
                exception_code: EXCEPTION_ILLEGAL_FUNCTION,
            };
            write_response(&mut device, transaction_id, exception.encode()).await;
        });

        let result = fetch_device_description(&mut connection, 1, Duration::from_secs(1)).await;
        assert_eq!(result, None);
        device_task.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_when_the_server_never_responds() {
        let (mut connection, _device) = connected_pair().await;

        let result = fetch_device_description(&mut connection, 1, Duration::from_millis(50)).await;
        assert_eq!(result, None);
    }

    // End-to-end across both halves of Threads A6-A8: an FC43 response
    // whose chunks reassemble into a `DeviceDescriptionManifest` (not a
    // real device description) is recognized as such, and the real TOML is
    // then fetched over FC20 and decompressed — not returned as-is.
    #[tokio::test]
    async fn fc43_manifest_response_is_fetched_and_decompressed_via_fc20() {
        use miniz_oxide::deflate::compress_to_vec;
        use protocol::device_description_manifest::ManifestMachine;
        use protocol::pdu::{ReadFileRecordRequest, ReadFileRecordResponse};

        let (mut connection, mut device) = connected_pair().await;
        let real_toml_source = "name = \"Stop_Process\"\n";
        let compressed = compress_to_vec(real_toml_source.as_bytes(), 10);
        let manifest = DeviceDescriptionManifest {
            file_number: 0xFFFF,
            compressed_length: compressed.len() as u32,
            machines: vec![ManifestMachine {
                name: "PumpA".to_string(),
                unit_id: 1,
            }],
        };
        let manifest_toml = manifest.to_toml_string();
        assert!(
            manifest_toml.len() <= 244,
            "test assumes the manifest itself fits in a single FC43 chunk"
        );

        let device_task = tokio::spawn(async move {
            // First round trip: FC43 serves the manifest, exactly like a
            // real device description that fits in one response.
            let (transaction_id, _request) = read_request(&mut device).await;
            let response = ReadDeviceIdentificationResponse {
                read_device_id_code: READ_DEVICE_ID_EXTENDED,
                conformity_level: 0x03,
                more_follows: false,
                next_object_id: 0,
                objects: vec![
                    DeviceIdentificationObject {
                        id: 0x80,
                        value: vec![0x01],
                    },
                    DeviceIdentificationObject {
                        id: 0x81,
                        value: manifest_toml.into_bytes(),
                    },
                ],
            };
            write_response(&mut device, transaction_id, response.encode()).await;

            // Second round trip: FC20 serves the real, compressed TOML.
            let mut header = vec![0u8; 7];
            device.read_exact(&mut header).await.unwrap();
            let mut function_and_count = vec![0u8; 2];
            device.read_exact(&mut function_and_count).await.unwrap();
            let byte_count = function_and_count[1];
            let mut rest = vec![0u8; byte_count as usize];
            device.read_exact(&mut rest).await.unwrap();
            let transaction_id = u16::from_be_bytes([header[0], header[1]]);
            let mut pdu = function_and_count;
            pdu.extend_from_slice(&rest);
            let request = ReadFileRecordRequest::decode(&pdu).unwrap();
            assert_eq!(request.sub_requests[0].file_number, 0xFFFF);

            let response = ReadFileRecordResponse {
                records: vec![compressed],
            };
            write_response(&mut device, transaction_id, response.encode()).await;
        });

        let result = fetch_device_description(&mut connection, 1, Duration::from_secs(1)).await;
        assert_eq!(result, Some(real_toml_source.to_string()));
        device_task.await.unwrap();
    }
}
