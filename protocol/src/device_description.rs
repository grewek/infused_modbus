use serde::Deserialize;

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

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RegisterDescription {
    pub name: String,
    pub address: u16,
    pub data_type: DataType,
    pub access: AccessRight,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DeviceDescription {
    pub registers: Vec<RegisterDescription>,
}

impl DeviceDescription {
    pub fn parse(toml_source: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_valid_device_description() {
        let toml_source = r#"
            [[registers]]
            name = "Tank_Temperature"
            address = 40001
            data_type = "u16"
            access = "read_only"

            [[registers]]
            name = "Stop_Process"
            address = 40002
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
            [[registers]]
            name = "Tank_Temperature"
            data_type = "u16"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_unknown_data_type() {
        let toml_source = r#"
            [[registers]]
            name = "Tank_Temperature"
            address = 40001
            data_type = "u32"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_unknown_access_right() {
        let toml_source = r#"
            [[registers]]
            name = "Tank_Temperature"
            address = 40001
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
}
