// A small, machine-count-scaling stand-in for the full device-description
// TOML, served over FC43 once the real description is too large to fit its
// existing inline-chunk object budget (CLAUDE.md's "Planned: grow FC43's
// device-description transfer capacity past its current ~31KB ceiling").
// `DeviceDescriptionManifest` itself and its TOML (de)serialization were
// built standalone (Thread A5), then wired into the server's actual FC43
// dispatch (Thread A6: `server::handler::handle_encapsulated_interface_
// transport` falls back to serving this manifest once the real
// description doesn't fit). `BULK_TRANSFER_CHUNK_BYTES`/
// `bulk_transfer_chunk_range` below are Thread A7's shared chunking math,
// used by the server's dedicated FC20 dispatch for the reserved
// `file_number` — kept here, not server-only, so a client (Thread A8,
// not yet built) computes the exact same chunk boundaries independently,
// with no round trip needed to discover them.
//
// Deliberately excludes every per-point field (registers, coils, ...) —
// that's the whole point of a manifest: size scales with machine count,
// not point count. Carries only what a client needs to (a) know every
// machine this server describes before fetching anything heavier, and (b)
// perform the FC20 bulk fetch of the real, compressed TOML: which reserved
// `file_number` to read from, and the compressed blob's exact length (to
// compute how many FC20 records to request up front, since FC20 has no
// equivalent to FC43's own More-Follows continuation).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Range;

/// Each FC20 "record" of the reserved bulk-transfer file carries this many
/// bytes. Derived from Modbus's own 253-byte PDU cap, same `MAX_PDU_LEN`
/// every other PDU-size check in this project uses: a `ReadFileRecordResponse`
/// carrying one record costs 2 header bytes (function code + byte count)
/// plus 2 bytes of per-record overhead (the record's own length byte +
/// the fixed reference-type byte), leaving 249 bytes for data — rounded
/// down to 248, the nearest even number, since a record's byte length is
/// always `2 * record_length` (whole 16-bit words). Fixed and shared
/// between server and client — neither computes it independently, so a
/// client can work out exactly how many FC20 records to request from
/// `compressed_length` alone.
pub const BULK_TRANSFER_CHUNK_BYTES: usize = 248;

/// The half-open byte range of the compressed TOML blob that chunk
/// `record_number` covers, given the blob's total `compressed_length` —
/// `None` once `record_number` is past the end. Every chunk is exactly
/// `BULK_TRANSFER_CHUNK_BYTES` long except possibly the last, which is
/// whatever remains. Shared by the server (building a response — Thread
/// A7) and, eventually, the client (deciding how many chunks to request
/// and what `record_length` each one needs — Thread A8) so the two sides
/// can never disagree about where a chunk starts or ends.
pub fn bulk_transfer_chunk_range(
    compressed_length: usize,
    record_number: u16,
) -> Option<Range<usize>> {
    let start = record_number as usize * BULK_TRANSFER_CHUNK_BYTES;
    if start >= compressed_length {
        return None;
    }
    let end = (start + BULK_TRANSFER_CHUNK_BYTES).min(compressed_length);
    Some(start..end)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestMachine {
    pub name: String,
    pub unit_id: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDescriptionManifest {
    /// Always `device_description::RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER`
    /// in practice — carried explicitly, rather than left for the client to
    /// assume, so parsing this manifest alone is enough to know how to
    /// fetch the rest.
    pub file_number: u16,
    /// Byte length of the *compressed* TOML source (not the original) —
    /// what the client needs to compute how many FC20 records to request.
    pub compressed_length: u32,
    pub machines: Vec<ManifestMachine>,
}

#[derive(Debug)]
pub struct DeviceDescriptionManifestError(toml::de::Error);

impl fmt::Display for DeviceDescriptionManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for DeviceDescriptionManifestError {}

impl From<toml::de::Error> for DeviceDescriptionManifestError {
    fn from(error: toml::de::Error) -> Self {
        DeviceDescriptionManifestError(error)
    }
}

// `toml::to_string` on `DeviceDescriptionManifest` directly would render
// `machines` as `[[machines]]` array-of-tables (one per machine, several
// lines each) — correct TOML, but not the compact shape this format is
// specifically for (CLAUDE.md's measured 11,405-byte/47-chunk size for 255
// machines assumes the inline form). The `toml` crate's serializer picks
// array-of-tables vs. inline purely based on nesting structure, with no
// per-field way to ask for the other form — so each machine is serialized
// on its own (reusing the crate's own correct string-escaping/quoting) and
// the lines stitched into an inline table by hand.
fn machine_to_inline_toml(machine: &ManifestMachine) -> String {
    let table_source = toml::to_string(machine).expect("a name/unit_id pair always serializes");
    let fields: Vec<&str> = table_source.lines().collect();
    format!("{{ {} }}", fields.join(", "))
}

impl DeviceDescriptionManifest {
    pub fn to_toml_string(&self) -> String {
        let machines = self
            .machines
            .iter()
            .map(machine_to_inline_toml)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "file_number = {}\ncompressed_length = {}\nmachines = [{}]\n",
            self.file_number, self.compressed_length, machines
        )
    }

    pub fn parse(toml_source: &str) -> Result<Self, DeviceDescriptionManifestError> {
        Ok(toml::from_str(toml_source)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DeviceDescriptionManifest {
        DeviceDescriptionManifest {
            file_number: 0xFFFF,
            compressed_length: 11_405,
            machines: vec![
                ManifestMachine {
                    name: "PumpA".to_string(),
                    unit_id: 1,
                },
                ManifestMachine {
                    name: "PumpB".to_string(),
                    unit_id: 2,
                },
            ],
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let manifest = sample();
        let toml_source = manifest.to_toml_string();
        assert_eq!(
            DeviceDescriptionManifest::parse(&toml_source).unwrap(),
            manifest
        );
    }

    #[test]
    fn serializes_machines_as_a_compact_inline_table_array() {
        // Not `[[machines]]` array-of-tables — that would scale worse and
        // defeats the point of a size-conscious manifest format.
        let toml_source = sample().to_toml_string();
        assert!(!toml_source.contains("[[machines]]"));
        assert!(toml_source.contains("{ name = \"PumpA\", unit_id = 1 }"));
    }

    #[test]
    fn round_trips_with_no_machines() {
        let manifest = DeviceDescriptionManifest {
            file_number: 0xFFFF,
            compressed_length: 0,
            machines: vec![],
        };
        let toml_source = manifest.to_toml_string();
        assert_eq!(
            DeviceDescriptionManifest::parse(&toml_source).unwrap(),
            manifest
        );
    }

    #[test]
    fn parse_rejects_malformed_toml() {
        assert!(DeviceDescriptionManifest::parse("this is not valid toml [[[").is_err());
    }

    #[test]
    fn parse_rejects_a_missing_required_field() {
        let toml_source = "compressed_length = 0\nmachines = []\n";
        assert!(DeviceDescriptionManifest::parse(toml_source).is_err());
    }

    #[test]
    fn chunk_range_covers_a_full_chunk_in_the_middle() {
        let compressed_length = BULK_TRANSFER_CHUNK_BYTES * 3;
        assert_eq!(
            bulk_transfer_chunk_range(compressed_length, 1),
            Some(BULK_TRANSFER_CHUNK_BYTES..BULK_TRANSFER_CHUNK_BYTES * 2)
        );
    }

    #[test]
    fn chunk_range_shrinks_for_a_partial_final_chunk() {
        let compressed_length = BULK_TRANSFER_CHUNK_BYTES + 10;
        assert_eq!(
            bulk_transfer_chunk_range(compressed_length, 1),
            Some(BULK_TRANSFER_CHUNK_BYTES..BULK_TRANSFER_CHUNK_BYTES + 10)
        );
    }

    #[test]
    fn chunk_range_is_none_past_the_end() {
        let compressed_length = BULK_TRANSFER_CHUNK_BYTES;
        assert_eq!(bulk_transfer_chunk_range(compressed_length, 1), None);
    }

    #[test]
    fn chunk_range_is_none_for_an_empty_blob() {
        assert_eq!(bulk_transfer_chunk_range(0, 0), None);
    }

    #[test]
    fn chunk_range_covers_the_only_chunk_of_a_small_blob() {
        assert_eq!(bulk_transfer_chunk_range(10, 0), Some(0..10));
    }

    #[test]
    fn chunk_count_matches_a_naive_ceiling_division() {
        for compressed_length in [0usize, 1, 247, 248, 249, 1000, 65536] {
            let mut naive_count = 0u16;
            let mut covered = 0usize;
            while covered < compressed_length {
                let range = bulk_transfer_chunk_range(compressed_length, naive_count)
                    .expect("must cover every byte up to compressed_length");
                covered = range.end;
                naive_count += 1;
            }
            assert_eq!(
                bulk_transfer_chunk_range(compressed_length, naive_count),
                None,
                "one past the last real chunk must be out of range for length {compressed_length}"
            );
        }
    }
}
