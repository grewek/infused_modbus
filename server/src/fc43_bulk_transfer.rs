// Cached, process-lifetime state for FC43's manifest+FC20 bulk-transfer
// fallback (CLAUDE.md's "Planned: grow FC43's device-description transfer
// capacity past its current ~31KB ceiling", Thread A6) — built exactly
// once at server startup and threaded alongside `toml_source` everywhere
// `handler::handle_request` is reachable from. `device_description_
// compression::compress_toml_source` is real CPU work whose result never
// changes afterward (the TOML is loaded once and never mutated), unlike
// `device_identification::build_objects`, which is cheap enough to redo on
// every FC43 request — so it happens here, once, rather than per request.
//
// `handler::handle_encapsulated_interface_transport` falls back to serving
// `manifest_toml` — through FC43's own existing object mechanism, as if it
// were just a much smaller device description — only once the real
// `toml_source` doesn't fit the inline-chunk budget AND
// `server_options::ServerOptions::detect_machine_layout` is enabled.
//
// `compressed_toml` isn't consumed by anything yet — that's Thread A7's
// still-unbuilt dedicated FC20 dispatch for
// `RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER`. Computing it here already,
// rather than waiting for A7, means it's never computed twice: A6 needs
// its *length* for the manifest's `compressed_length` field regardless.

use crate::device_description_compression::compress_toml_source;
use protocol::device_description::RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER;
use protocol::device_description_manifest::{DeviceDescriptionManifest, ManifestMachine};

pub struct Fc43BulkTransfer {
    pub compressed_toml: Vec<u8>,
    pub manifest_toml: String,
}

impl Fc43BulkTransfer {
    pub fn build(toml_source: &str, machines: Vec<ManifestMachine>) -> Self {
        let compressed_toml = compress_toml_source(toml_source);
        let manifest = DeviceDescriptionManifest {
            file_number: RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER,
            compressed_length: compressed_toml.len() as u32,
            machines,
        };
        Fc43BulkTransfer {
            compressed_toml,
            manifest_toml: manifest.to_toml_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_description_compression::decompress_toml_source;

    #[test]
    fn compressed_toml_round_trips_to_the_original_source() {
        let toml_source = "name = \"Stop_Process\"\naddress = 40002\n";
        let bulk_transfer = Fc43BulkTransfer::build(toml_source, vec![]);
        assert_eq!(
            decompress_toml_source(&bulk_transfer.compressed_toml).unwrap(),
            toml_source
        );
    }

    #[test]
    fn manifest_toml_parses_back_with_matching_fields() {
        let toml_source = "name = \"Stop_Process\"\n";
        let machines = vec![
            ManifestMachine {
                name: "PumpA".to_string(),
                unit_id: 1,
            },
            ManifestMachine {
                name: "PumpB".to_string(),
                unit_id: 2,
            },
        ];
        let bulk_transfer = Fc43BulkTransfer::build(toml_source, machines.clone());

        let manifest = DeviceDescriptionManifest::parse(&bulk_transfer.manifest_toml).unwrap();
        assert_eq!(
            manifest.file_number,
            RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER
        );
        assert_eq!(
            manifest.compressed_length as usize,
            bulk_transfer.compressed_toml.len()
        );
        assert_eq!(manifest.machines, machines);
    }
}
