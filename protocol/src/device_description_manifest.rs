// A small, machine-count-scaling stand-in for the full device-description
// TOML, served over FC43 once the real description is too large to fit its
// existing inline-chunk object budget (CLAUDE.md's "Planned: grow FC43's
// device-description transfer capacity past its current ~31KB ceiling",
// Thread A5). Standalone here — not yet wired into
// `device_identification::build_objects` (Thread A6) or any client-side
// FC43 response handling (Thread A8); this module is just the data type
// and its TOML (de)serialization, the same "capability first, wire in
// later" sequencing Thread B used for `sparkplug::property`/`data_set`.
//
// Deliberately excludes every per-point field (registers, coils, ...) —
// that's the whole point of a manifest: size scales with machine count,
// not point count. Carries only what a client needs to (a) know every
// machine this server describes before fetching anything heavier, and (b)
// perform the FC20 bulk fetch of the real, compressed TOML: which reserved
// `file_number` to read from, and the compressed blob's exact length (to
// compute `ceil(length / 249)` FC20 records up front, since FC20 has no
// equivalent to FC43's own More-Follows continuation).

use serde::{Deserialize, Serialize};
use std::fmt;

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
}
