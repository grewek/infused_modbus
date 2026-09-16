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

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceDescription {
    pub registers: Vec<RegisterDescription>,
}

#[derive(Debug, Deserialize)]
struct RawRegisterEntry {
    name: String,
    offset: u16,
    data_type: DataType,
    access: AccessRight,
}

#[derive(Debug, Deserialize)]
struct RawRegisterSection {
    base_address: u16,
    entries: Vec<RawRegisterEntry>,
}

#[derive(Debug, Deserialize)]
struct RawDeviceDescription {
    registers: RawRegisterSection,
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
                "register '{name}' address overflows u16: base_address {base_address} + offset {offset}"
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

impl DeviceDescription {
    pub fn parse(toml_source: &str) -> Result<Self, DeviceDescriptionError> {
        let raw: RawDeviceDescription = toml::from_str(toml_source)?;
        let RawRegisterSection {
            base_address,
            entries,
        } = raw.registers;

        let registers = entries
            .into_iter()
            .map(|entry| {
                let address = base_address.checked_add(entry.offset).ok_or(
                    DeviceDescriptionError::AddressOverflow {
                        name: entry.name.clone(),
                        base_address,
                        offset: entry.offset,
                    },
                )?;

                Ok(RegisterDescription {
                    name: entry.name,
                    address,
                    data_type: entry.data_type,
                    access: entry.access,
                })
            })
            .collect::<Result<Vec<_>, DeviceDescriptionError>>()?;

        Ok(DeviceDescription { registers })
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
            }
        );
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
}
