// Lets a client discover this server's device description over the wire
// (FC 43 / MEI 0x0E, Read Device Identification) instead of needing its own
// local copy of the TOML file — see CLAUDE.md for the full design
// rationale (private objects 0x80+ chosen because Read Device
// Identification's continuation mechanism already solves "transfer a
// string too long for one response" for us, for free).
//
// Scope of this first pass: only Extended access (Read Device ID code
// 0x03) is supported, and only two kinds of object — everything else this
// FC could theoretically do (Basic/Regular/Individual access, the
// standard VendorName/ProductCode/etc. objects) is explicitly deferred to
// a later pass that supports FC 43 more completely.
//
// Object layout:
//   0x80 — presence flag, one byte: 0x01 (this server always has a
//          description, since device-description.toml is a required CLI
//          argument) — kept as an explicit flag rather than just "absence
//          of 0x81 means no description" so a future server mode that
//          might genuinely have none has a clean way to say so.
//   0x81, 0x82, ... — the raw TOML source, chunked (see build_objects for
//          why the chunk size is capped well below the object model's own
//          255-byte limit).

use protocol::pdu::{
    DeviceIdentificationObject, EXCEPTION_ILLEGAL_DATA_ADDRESS, EXCEPTION_ILLEGAL_FUNCTION,
    ExceptionResponse, FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT, READ_DEVICE_ID_EXTENDED,
    ReadDeviceIdentificationRequest, ReadDeviceIdentificationResponse,
};

const PRESENCE_OBJECT_ID: u8 = 0x80;
const FIRST_TOML_CHUNK_OBJECT_ID: u8 = 0x81;

// "Extended Identification, stream access only" — the only conformity
// level that's actually true of what's implemented here (Individual
// access, code 0x04, isn't supported yet).
const EXTENDED_STREAM_CONFORMITY_LEVEL: u8 = 0x03;

// Modbus's own PDU size cap (function code + 252 data bytes).
const MAX_PDU_LEN: usize = 253;

// Chosen so that a single chunk object (2-byte object header + value)
// always fits alongside the 7-byte Read Device Identification response
// header even when it's the only object in the response — 7 + 2 + 244 =
// 253 exactly. Without this margin, a near-max 255-byte chunk (as the
// object model's own length byte would otherwise allow) couldn't fit in
// any response at all, since 7 + 2 + 255 = 264 > 253.
const MAX_TOML_CHUNK_LEN: usize = 244;

/// `build_objects` couldn't fit `toml_source` into the private-object ID
/// space — see `build_objects`'s own doc comment for the exact budget.
/// Carries the chunk count actually needed and the number of slots really
/// available, so a caller can report something more useful than a bare
/// "too big" (`handler::handle_encapsulated_interface_transport` doesn't
/// use these today — it just turns this into
/// `EXCEPTION_SERVER_DEVICE_FAILURE` — but a future manifest fallback, see
/// CLAUDE.md's "Planned: grow FC43's device-description transfer capacity",
/// is the real consumer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLargeForFc43 {
    pub chunks_needed: usize,
    pub chunks_available: usize,
}

/// Builds the full, fixed list of objects this server can serve — object
/// 0x80 (the presence flag) plus the TOML source split into
/// `MAX_TOML_CHUNK_LEN`-byte chunks starting at 0x81. Computed fresh per
/// call rather than cached: `toml_source` is loaded once at server
/// startup and never changes, so this is trivially deterministic, and
/// FC 43 requests are rare (client startup, not the polling hot path).
///
/// Returns `Err(TooLargeForFc43)` — rather than panicking, as this used to
/// (fixed per CLAUDE.md's Thread A2: a description that grows past the
/// ceiling over time shouldn't crash the server outright at the next FC43
/// request) — if `toml_source` is long enough that its chunks would run
/// past object ID 0xFF. The private-object ID space (0x81..=0xFF, 127
/// slots) caps how much text this scheme can carry to roughly 31KB.
pub fn build_objects(
    toml_source: &str,
) -> Result<Vec<DeviceIdentificationObject>, TooLargeForFc43> {
    let mut objects = vec![DeviceIdentificationObject {
        id: PRESENCE_OBJECT_ID,
        value: vec![0x01],
    }];

    let chunks_available = 0xFF - FIRST_TOML_CHUNK_OBJECT_ID as usize + 1;
    for (index, chunk) in toml_source
        .as_bytes()
        .chunks(MAX_TOML_CHUNK_LEN)
        .enumerate()
    {
        let id = FIRST_TOML_CHUNK_OBJECT_ID as usize + index;
        if id > 0xFF {
            let chunks_needed = toml_source.len().div_ceil(MAX_TOML_CHUNK_LEN);
            return Err(TooLargeForFc43 {
                chunks_needed,
                chunks_available,
            });
        }
        objects.push(DeviceIdentificationObject {
            id: id as u8,
            value: chunk.to_vec(),
        });
    }

    Ok(objects)
}

/// Answers a Read Device Identification request against a fixed object
/// list, filling as many objects starting at the requested `object_id` as
/// fit in one response PDU and reporting `more_follows`/`next_object_id`
/// for the rest, per the FC's own continuation mechanism.
pub fn handle_read_device_identification(
    request: &ReadDeviceIdentificationRequest,
    all_objects: &[DeviceIdentificationObject],
) -> Vec<u8> {
    if request.read_device_id_code != READ_DEVICE_ID_EXTENDED {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
            exception_code: EXCEPTION_ILLEGAL_FUNCTION,
        }
        .encode();
    }

    let Some(start_index) = all_objects
        .iter()
        .position(|object| object.id == request.object_id)
    else {
        return ExceptionResponse {
            function_code: FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
            exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
        }
        .encode();
    };

    let mut objects = Vec::new();
    let mut next_index = start_index;
    while next_index < all_objects.len() {
        objects.push(all_objects[next_index].clone());
        let next_object_id = all_objects
            .get(next_index + 1)
            .map_or(0, |object| object.id);
        let candidate = ReadDeviceIdentificationResponse {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            conformity_level: EXTENDED_STREAM_CONFORMITY_LEVEL,
            more_follows: true,
            next_object_id,
            objects: objects.clone(),
        };
        if candidate.encode().len() > MAX_PDU_LEN {
            objects.pop();
            break;
        }
        next_index += 1;
    }

    let more_follows = next_index < all_objects.len();
    let next_object_id = if more_follows {
        all_objects[next_index].id
    } else {
        0
    };

    ReadDeviceIdentificationResponse {
        read_device_id_code: READ_DEVICE_ID_EXTENDED,
        conformity_level: EXTENDED_STREAM_CONFORMITY_LEVEL,
        more_follows,
        next_object_id,
        objects,
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::pdu::READ_DEVICE_ID_BASIC;

    #[test]
    fn build_objects_always_includes_the_presence_flag() {
        let objects = build_objects("").unwrap();
        assert_eq!(objects[0].id, 0x80);
        assert_eq!(objects[0].value, vec![0x01]);
    }

    #[test]
    fn build_objects_chunks_toml_source_starting_at_0x81() {
        let toml_source = "a".repeat(MAX_TOML_CHUNK_LEN + 10);
        let objects = build_objects(&toml_source).unwrap();
        assert_eq!(objects.len(), 3); // presence flag + 2 chunks
        assert_eq!(objects[1].id, 0x81);
        assert_eq!(objects[1].value.len(), MAX_TOML_CHUNK_LEN);
        assert_eq!(objects[2].id, 0x82);
        assert_eq!(objects[2].value.len(), 10);
    }

    #[test]
    fn build_objects_returns_an_error_instead_of_panicking_when_too_large() {
        // 127 chunk slots available (0x81..=0xFF) -- one byte over the
        // 128th chunk's worth of source overflows that budget.
        let toml_source = "x".repeat(MAX_TOML_CHUNK_LEN * 127 + 1);
        assert_eq!(
            build_objects(&toml_source),
            Err(TooLargeForFc43 {
                chunks_needed: 128,
                chunks_available: 127,
            })
        );
    }

    #[test]
    fn build_objects_succeeds_at_exactly_the_chunk_budget() {
        let toml_source = "x".repeat(MAX_TOML_CHUNK_LEN * 127);
        let objects = build_objects(&toml_source).unwrap();
        assert_eq!(objects.len(), 128); // presence flag + 127 chunks
        assert_eq!(objects.last().unwrap().id, 0xFF);
    }

    #[test]
    fn build_objects_reassembles_to_the_original_source() {
        let toml_source = "name = \"Stop_Process\"\naddress = 40002\n".repeat(20);
        let objects = build_objects(&toml_source).unwrap();
        let reassembled: Vec<u8> = objects[1..]
            .iter()
            .flat_map(|object| object.value.clone())
            .collect();
        assert_eq!(reassembled, toml_source.as_bytes());
    }

    #[test]
    fn handle_extended_read_starting_at_presence_flag_returns_it() {
        let objects = build_objects("hello").unwrap();
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id: 0x80,
        };
        let response = ReadDeviceIdentificationResponse::decode(
            &handle_read_device_identification(&request, &objects),
        )
        .unwrap();
        assert!(!response.more_follows);
        assert_eq!(response.objects.len(), 2);
        assert_eq!(response.objects[0].id, 0x80);
        assert_eq!(response.objects[1].value, b"hello");
    }

    #[test]
    fn handle_extended_read_paginates_when_objects_do_not_fit_in_one_response() {
        // Three max-size chunks: none of them can share a response with
        // another (see MAX_TOML_CHUNK_LEN's doc comment), so this should
        // take exactly four responses (presence flag + one per chunk).
        let toml_source = "x".repeat(MAX_TOML_CHUNK_LEN * 3);
        let objects = build_objects(&toml_source).unwrap();
        assert_eq!(objects.len(), 4);

        let mut request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id: 0x80,
        };
        let mut round_trips = 0;
        let mut collected = Vec::new();
        loop {
            round_trips += 1;
            assert!(round_trips <= 10, "did not terminate");
            let response = ReadDeviceIdentificationResponse::decode(
                &handle_read_device_identification(&request, &objects),
            )
            .unwrap();
            collected.extend(response.objects);
            if !response.more_follows {
                break;
            }
            request.object_id = response.next_object_id;
        }

        assert_eq!(round_trips, 4);
        assert_eq!(collected.len(), 4);
        assert_eq!(collected[0].id, 0x80);
        assert_eq!(collected[1].id, 0x81);
        assert_eq!(collected[2].id, 0x82);
        assert_eq!(collected[3].id, 0x83);
    }

    #[test]
    fn handle_rejects_unsupported_read_device_id_codes() {
        let objects = build_objects("hello").unwrap();
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_BASIC,
            object_id: 0x00,
        };
        let response = handle_read_device_identification(&request, &objects);
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
                exception_code: EXCEPTION_ILLEGAL_FUNCTION,
            }
        );
    }

    #[test]
    fn handle_rejects_unknown_starting_object_id() {
        let objects = build_objects("hello").unwrap();
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: READ_DEVICE_ID_EXTENDED,
            object_id: 0xAA,
        };
        let response = handle_read_device_identification(&request, &objects);
        assert_eq!(
            ExceptionResponse::decode(&response).unwrap(),
            ExceptionResponse {
                function_code: FUNCTION_CODE_ENCAPSULATED_INTERFACE_TRANSPORT,
                exception_code: EXCEPTION_ILLEGAL_DATA_ADDRESS,
            }
        );
    }
}
