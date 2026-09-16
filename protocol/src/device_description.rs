use serde::Deserialize;
use std::fmt;

// Only the fields needed to identify and access a register are modeled so
// far. CLAUDE.md flags scaling/units as part of the eventual schema too, but
// nothing concretely needs them yet (per Extraction-Based Programming) — add
// them once a real consumer, like the in-memory register store, needs to
// apply a scale factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataType {
    U16,
    F32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessRight {
    ReadOnly,
    ReadWrite,
}

// The resolved, absolute Modbus address a register lives at. Not deserialized
// directly — the TOML source only ever specifies a `base_address` per section
// plus a per-entry `offset` (see `RawRegisterEntry`/`RawRegisterSection`
// below); `DeviceDescription::parse` resolves `address = base_address +
// offset` once, here, so every downstream consumer (client polling/writes,
// server handling) keeps working with a single plain wire address like
// before, unaware base_address/offset ever existed.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisterDescription {
    pub name: String,
    pub address: u16,
    pub data_type: DataType,
    pub access: AccessRight,
}

// Coils have no `data_type` (always 1 bit) and no `access` (assumed always
// read/write for now, since that's what the Modbus spec's own coil object
// is — see CLAUDE.md's FUSE layout section for the reasoning). Both are
// deliberately not modeled as fields yet; add `access` only once making it
// configurable is an actual, concrete need.
#[derive(Debug, Clone, PartialEq)]
pub struct CoilDescription {
    pub name: String,
    pub address: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceDescription {
    pub registers: Vec<RegisterDescription>,
    pub coils: Vec<CoilDescription>,
}

#[derive(Debug, Deserialize)]
struct RawRegisterEntry {
    name: String,
    offset: u16,
    data_type: DataType,
    access: AccessRight,
}

#[derive(Debug, Default, Deserialize)]
struct RawRegisterSection {
    base_address: u16,
    entries: Vec<RawRegisterEntry>,
}

#[derive(Debug, Deserialize)]
struct RawCoilEntry {
    name: String,
    offset: u16,
}

#[derive(Debug, Default, Deserialize)]
struct RawCoilSection {
    base_address: u16,
    entries: Vec<RawCoilEntry>,
}

// `registers`/`coils` are each optional at the top level (default: no
// entries) so a device that only has one of the two doesn't need to spell
// out an empty section for the other. Once a section *is* present, though,
// its own `base_address` stays a required field — see `DeviceDescription`'s
// existing `parse_rejects_missing_base_address` test.
#[derive(Debug, Default, Deserialize)]
struct RawDeviceDescription {
    #[serde(default)]
    registers: RawRegisterSection,
    #[serde(default)]
    coils: RawCoilSection,
}

#[derive(Debug)]
pub enum DeviceDescriptionError {
    Toml(toml::de::Error),
    AddressOverflow {
        name: String,
        base_address: u16,
        offset: u16,
    },
}

impl fmt::Display for DeviceDescriptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceDescriptionError::Toml(error) => write!(formatter, "{error}"),
            DeviceDescriptionError::AddressOverflow {
                name,
                base_address,
                offset,
            } => write!(
                formatter,
                "'{name}' address overflows u16: base_address {base_address} + offset {offset}"
            ),
        }
    }
}

impl std::error::Error for DeviceDescriptionError {}

impl From<toml::de::Error> for DeviceDescriptionError {
    fn from(error: toml::de::Error) -> Self {
        DeviceDescriptionError::Toml(error)
    }
}

// Resolves `base_address + offset` for every entry in a section, sharing the
// same overflow handling regardless of whether the caller is registers or
// coils.
fn resolve_addresses<Entry>(
    base_address: u16,
    entries: Vec<Entry>,
    offset_of: impl Fn(&Entry) -> u16,
    name_of: impl Fn(&Entry) -> String,
) -> Result<Vec<(Entry, u16)>, DeviceDescriptionError> {
    entries
        .into_iter()
        .map(|entry| {
            let offset = offset_of(&entry);
            let address = base_address.checked_add(offset).ok_or_else(|| {
                DeviceDescriptionError::AddressOverflow {
                    name: name_of(&entry),
                    base_address,
                    offset,
                }
            })?;
            Ok((entry, address))
        })
        .collect()
}

impl DeviceDescription {
    pub fn parse(toml_source: &str) -> Result<Self, DeviceDescriptionError> {
        let raw: RawDeviceDescription = toml::from_str(toml_source)?;

        let registers = resolve_addresses(
            raw.registers.base_address,
            raw.registers.entries,
            |entry: &RawRegisterEntry| entry.offset,
            |entry: &RawRegisterEntry| entry.name.clone(),
        )?
        .into_iter()
        .map(|(entry, address)| RegisterDescription {
            name: entry.name,
            address,
            data_type: entry.data_type,
            access: entry.access,
        })
        .collect();

        let coils = resolve_addresses(
            raw.coils.base_address,
            raw.coils.entries,
            |entry: &RawCoilEntry| entry.offset,
            |entry: &RawCoilEntry| entry.name.clone(),
        )?
        .into_iter()
        .map(|(entry, address)| CoilDescription {
            name: entry.name,
            address,
        })
        .collect();

        Ok(DeviceDescription { registers, coils })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_valid_device_description() {
        let toml_source = r#"
            [registers]
            base_address = 40000

            [[registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"

            [[registers.entries]]
            name = "Stop_Process"
            offset = 2
            data_type = "f32"
            access = "read_write"

            [coils]
            base_address = 0

            [[coils.entries]]
            name = "Motor_Running"
            offset = 1

            [[coils.entries]]
            name = "Alarm_Active"
            offset = 2
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert_eq!(
            description,
            DeviceDescription {
                registers: vec![
                    RegisterDescription {
                        name: "Tank_Temperature".to_string(),
                        address: 40001,
                        data_type: DataType::U16,
                        access: AccessRight::ReadOnly,
                    },
                    RegisterDescription {
                        name: "Stop_Process".to_string(),
                        address: 40002,
                        data_type: DataType::F32,
                        access: AccessRight::ReadWrite,
                    },
                ],
                coils: vec![
                    CoilDescription {
                        name: "Motor_Running".to_string(),
                        address: 1,
                    },
                    CoilDescription {
                        name: "Alarm_Active".to_string(),
                        address: 2,
                    },
                ],
            }
        );
    }

    #[test]
    fn parse_treats_an_absent_coils_section_as_no_coils() {
        let toml_source = r#"
            [registers]
            base_address = 40000

            [[registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert!(description.coils.is_empty());
    }

    #[test]
    fn parse_treats_an_absent_registers_section_as_no_registers() {
        let toml_source = r#"
            [coils]
            base_address = 0

            [[coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert!(description.registers.is_empty());
        assert_eq!(description.coils.len(), 1);
    }

    #[test]
    fn parse_rejects_missing_required_field() {
        let toml_source = r#"
            [registers]
            base_address = 40000

            [[registers.entries]]
            name = "Tank_Temperature"
            data_type = "u16"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_missing_base_address() {
        let toml_source = r#"
            [[registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_coil_missing_base_address() {
        let toml_source = r#"
            [[coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_coil_missing_offset() {
        let toml_source = r#"
            [coils]
            base_address = 0

            [[coils.entries]]
            name = "Motor_Running"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_unknown_data_type() {
        let toml_source = r#"
            [registers]
            base_address = 40000

            [[registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u32"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_unknown_access_right() {
        let toml_source = r#"
            [registers]
            base_address = 40000

            [[registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "write_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_malformed_toml() {
        let toml_source = "this is not valid toml [[[";

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_address_overflow() {
        let toml_source = r#"
            [registers]
            base_address = 65535

            [[registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
        "#;

        let error = DeviceDescription::parse(toml_source).unwrap_err();

        assert!(matches!(
            error,
            DeviceDescriptionError::AddressOverflow {
                base_address: 65535,
                offset: 1,
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_coil_address_overflow() {
        let toml_source = r#"
            [coils]
            base_address = 65535

            [[coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        let error = DeviceDescription::parse(toml_source).unwrap_err();

        assert!(matches!(
            error,
            DeviceDescriptionError::AddressOverflow {
                base_address: 65535,
                offset: 1,
                ..
            }
        ));
    }
}
