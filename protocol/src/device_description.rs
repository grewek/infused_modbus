use crate::unit_of_measure::is_valid_unit_code;
use serde::Deserialize;
use std::fmt;

// CLAUDE.md flags per-value metadata (unit, device_class, display_name, ...)
// as part of the eventual schema — `unit` (see `RegisterDescription::unit`)
// is the first of these to actually land, per Extraction-Based Programming;
// the rest stay unmodeled until a real consumer needs them too (e.g. a scale
// factor applied by the in-memory register store).
//
// U24/I24 exist because some real devices use them (audio-style 24-bit
// values), even though Modbus has no native 24-bit register — they occupy
// two registers (32 bits) with the most-significant byte always zero/unused
// padding, same as if they were a 32-bit value with a restricted range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataType {
    U8,
    I8,
    U16,
    I16,
    U24,
    I24,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
}

impl DataType {
    /// How many consecutive 16-bit Modbus registers a value of this type
    /// spans on the wire.
    pub fn register_count(self) -> u16 {
        match self {
            DataType::U8 | DataType::I8 | DataType::U16 | DataType::I16 => 1,
            DataType::U24 | DataType::I24 | DataType::U32 | DataType::I32 | DataType::F32 => 2,
            DataType::U64 | DataType::I64 | DataType::F64 => 4,
        }
    }
}

// How a device lays a multi-register value's bytes out on the wire before
// Modbus's own (fixed, non-configurable) big-endian-per-register framing
// takes over. Real devices vary along two independent axes — which
// register holds the more significant half of the value ("word order"),
// and whether each register's own two bytes are in their natural order or
// swapped ("byte order") — and the four combinations of those two axes are
// conventionally named after which of a 32-bit value's four bytes (A =
// most significant .. D = least significant) ends up where on the wire:
// ABCD (big-endian, both axes "natural"), DCBA (little-endian, both
// swapped), and the two mixed conventions BADC/CDAB that real devices
// (e.g. some Schneider/Modicon PLCs, for CDAB) also use. Only meaningful
// for values spanning more than one register (U24 and up) — U8/I8/U16/I16
// fit in a single register, whose own byte order Modbus already fixes.
// `Default` exists only so `RawRegisterSection` (below) can derive its own
// `Default`, used solely when the whole `[registers]` section is absent —
// same as `base_address`'s meaningless-when-unused default of 0, `Abcd`
// here is never actually applied to a real register.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemLayout {
    #[default]
    Abcd,
    Badc,
    Cdab,
    Dcba,
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
    // Engineering unit, as a UN/ECE Recommendation 20 common code (e.g.
    // `"CEL"` for degree Celsius) — see `protocol::unit_of_measure`'s own
    // doc comment for why this standard was chosen over free text, and
    // CLAUDE.md's "UN/ECE `unit` field, decided". `None` means "not
    // configured" (the common case today — every TOML written before this
    // field existed keeps parsing unchanged). Scoped to registers/input
    // registers only for now — a physical unit has little meaning on a
    // single-bit coil/discrete-input, so neither gets this field.
    pub unit: Option<String>,
}

// Input registers (FC 4) are always read-only per the Modbus spec — no
// Modbus function code ever lets a master write one, so unlike
// `RegisterDescription` there is no `access` field to model.
#[derive(Debug, Clone, PartialEq)]
pub struct InputRegisterDescription {
    pub name: String,
    pub address: u16,
    pub data_type: DataType,
    // Same `unit` field and reasoning as `RegisterDescription::unit` above.
    pub unit: Option<String>,
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

// Discrete inputs (FC 2) are the read-only counterpart to coils: always 1
// bit, never writable by a Modbus master (same reasoning as
// `InputRegisterDescription` above) — so, like `CoilDescription`, no
// `data_type`/`access` fields.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscreteInputDescription {
    pub name: String,
    pub address: u16,
}

// A single named "file record" for FC 0x14/0x15 (Read/Write File Record) —
// see CLAUDE.md's "FC 0x14 (Read File Record)" section. Unlike every other
// entry in this file, `file_number`/`record_number` ARE the address — no
// base_address+offset resolution, since the wire's own two-axis addressing
// scheme has no natural "base" to offset from — and there is no `name`
// field: the `(file_number, record_number)` pair itself is the identifier,
// matching how a real device's own documentation already names these
// things (e.g. "File 20 = event log"). `record_length`
// is in 16-bit words (matches the wire field's own unit) and is fixed per
// entry: an incoming request that doesn't ask for exactly this many words
// is rejected, the same "must land on an exact boundary" discipline
// `handle_read` already applies to multi-register values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRecordDescription {
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
}

/// Reserved for the server's own compressed-device-description bulk
/// transfer over FC20 (see CLAUDE.md's "Planned: grow FC43's device-
/// description transfer capacity past its current ~31KB ceiling", Thread
/// A3) — a user's own `[[file-records]]` entry is not allowed to use this
/// `file_number` at all, enforced as a hard parse error (see
/// `DeviceDescriptionError::ReservedFileNumber`), the same "can't even
/// appear in the config" discipline `fuse-permissions.toml` already
/// applies to a `client-trust` key, not a "realistically nobody would pick
/// this number" assumption. Chosen at the very top of the `u16` range —
/// real devices documented for FC20/21 use low numbers (e.g. 20, 90, per
/// the research in CLAUDE.md's "FC 0x14" section) — mirroring how FC43
/// itself reserves the top of its own object-ID range (0x80-0xFF) for
/// private/vendor use rather than the bottom.
pub const RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER: u16 = 0xFFFF;

// One machine on a shared link (a multi-drop RTU bus, or a device reachable
// through a Unit-ID-aware TCP gateway) — see CLAUDE.md's "Planned:
// multi-machine device description & FUSE layout" section. Everything that
// used to be a flat, single-device `DeviceDescription` now lives here
// instead, one level down, per machine.
#[derive(Debug, Clone, PartialEq)]
pub struct MachineDescription {
    // Used directly as this machine's Sparkplug B `device_id` (see
    // `client::main`'s `edge_node.publish_dbirth(&machine.name, ...)`),
    // which becomes an MQTT topic path segment — must be unique across the
    // whole file and restricted to ASCII alphanumeric plus `_`/`-` (see
    // `validate_machine_name`), enforced as a parse error rather than a
    // runtime surprise, since two machines sharing a name would collide on
    // one Sparkplug device topic and other characters (`/`, `+`, `#`, ...)
    // could break topic handling.
    pub name: String,
    // Which Modbus Unit ID on the shared link this machine answers to. A
    // deliberate, flagged exception to this project's usual "TOML describes
    // data shape, CLI/config describes connection" separation — a Unit ID is
    // normally connection/wire-addressing information, but it's needed here
    // to tell multiple machines described in one file apart.
    pub unit_id: u8,
    pub registers: Vec<RegisterDescription>,
    pub coils: Vec<CoilDescription>,
    pub discrete_inputs: Vec<DiscreteInputDescription>,
    pub input_registers: Vec<InputRegisterDescription>,
    pub file_records: Vec<FileRecordDescription>,
    // Global for the whole machine, not per-register: real devices bake
    // their word/byte order into firmware once, not per data point — see
    // MemLayout's own doc comment. Meaningless when `registers` is empty.
    pub mem_layout: MemLayout,
    // Kept separate from `mem_layout` above rather than shared: nothing
    // establishes that a device's input registers share the same wire
    // convention as its holding registers, so each gets its own field.
    // Meaningless when `input_registers` is empty.
    pub input_register_mem_layout: MemLayout,
    // Optional, user-set-once identity string served by the server over
    // FC 0x11 (Report Server ID) (see CLAUDE.md's "FC 0x11 (Report Server
    // ID)" section) and printed at startup by the client (`client::main`),
    // so a technician can see whatever ended up in the client's own
    // effective description — `None` means "not configured", not "empty
    // string": the server answers FC11 with ILLEGAL_FUNCTION rather than
    // an empty identity, and the client prints nothing for that machine
    // rather than an empty value. Per-machine since FC11 answers per Unit
    // ID, and each machine on a shared link has its own identity.
    pub server_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceDescription {
    pub machines: Vec<MachineDescription>,
}

#[derive(Debug, Deserialize)]
struct RawRegisterEntry {
    name: String,
    offset: u16,
    data_type: DataType,
    access: AccessRight,
    #[serde(default)]
    unit: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawRegisterSection {
    base_address: u16,
    #[serde(rename = "mem-layout")]
    mem_layout: MemLayout,
    entries: Vec<RawRegisterEntry>,
}

#[derive(Debug, Deserialize)]
struct RawInputRegisterEntry {
    name: String,
    offset: u16,
    data_type: DataType,
    #[serde(default)]
    unit: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawInputRegisterSection {
    base_address: u16,
    #[serde(rename = "mem-layout")]
    mem_layout: MemLayout,
    entries: Vec<RawInputRegisterEntry>,
}

// Coils and discrete inputs are both bare "name + offset" (no `data_type`/
// `access`, see `CoilDescription`/`DiscreteInputDescription`'s own doc
// comments) — one shared raw-parsing shape for both TOML sections instead
// of two field-identical copies, cutting the number of distinct types
// `toml`'s generic deserializer has to be monomorphized for. Validation
// behavior is unaffected either way: neither this type nor the two it
// replaces ever had `#[serde(deny_unknown_fields)]` (unlike server_options.rs/
// client::broker's config types, which do) -- an unrecognized key in a
// `[[coils.entries]]`/`[[discrete-inputs.entries]]` table is silently
// ignored before and after this change, not a new or newly-fixed gap.
// The two *output* types stay fully distinct below (`resolve_addresses`
// maps each into its own `CoilDescription`/`DiscreteInputDescription`) --
// only this intermediate parsing stage is shared.
#[derive(Debug, Deserialize)]
struct RawBitEntry {
    name: String,
    offset: u16,
}

#[derive(Debug, Default, Deserialize)]
struct RawBitSection {
    base_address: u16,
    entries: Vec<RawBitEntry>,
}

// No wrapping section/`base_address` here, unlike every other entry kind —
// see `FileRecordDescription`'s own doc comment for why. A flat top-level
// `[[file-records]]` array of tables instead.
#[derive(Debug, Deserialize)]
struct RawFileRecordEntry {
    file_number: u16,
    record_number: u16,
    record_length: u16,
}

// `registers`/`coils`/`discrete-inputs`/`input-registers` are each optional
// per machine (default: no entries) so a machine that only has some of the
// four doesn't need to spell out empty sections for the rest. Once a
// section *is* present, though, its own `base_address` stays a required
// field — see `DeviceDescription`'s existing `parse_rejects_missing_base_address`
// test.
#[derive(Debug, Deserialize)]
struct RawMachine {
    name: String,
    unit_id: u8,
    #[serde(default)]
    registers: RawRegisterSection,
    #[serde(default)]
    coils: RawBitSection,
    #[serde(default, rename = "discrete-inputs")]
    discrete_inputs: RawBitSection,
    #[serde(default, rename = "input-registers")]
    input_registers: RawInputRegisterSection,
    #[serde(default, rename = "file-records")]
    file_records: Vec<RawFileRecordEntry>,
    #[serde(default, rename = "server-id")]
    server_id: Option<String>,
}

// The whole file is just an array of machines — `machines` itself is
// optional (default: empty) so an empty/whitespace-only TOML source parses
// to a `DeviceDescription` with no machines at all, rather than an error.
#[derive(Debug, Default, Deserialize)]
struct RawDeviceDescription {
    #[serde(default)]
    machines: Vec<RawMachine>,
}

#[derive(Debug)]
pub enum DeviceDescriptionError {
    Toml(toml::de::Error),
    AddressOverflow {
        machine: String,
        name: String,
        base_address: u16,
        offset: u16,
    },
    // A machine `name` that is empty or contains a character other than
    // ASCII alphanumeric, `_`, or `-` — enforced at parse time since it
    // becomes this machine's Sparkplug B `device_id`, an MQTT topic path
    // segment, and other characters (`/`, `+`, `#`, ...) could break topic
    // handling.
    InvalidMachineName {
        name: String,
    },
    // Two machines in the same file sharing a `name` — would collide on one
    // Sparkplug device topic, so rejected outright rather than picking a
    // winner.
    DuplicateMachineName {
        name: String,
    },
    // A `[[file-records]]` entry using `RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER`
    // — reserved for the server's own compressed-description bulk transfer,
    // see that constant's own doc comment.
    ReservedFileNumber {
        machine: String,
        file_number: u16,
    },
    // A register/input-register `unit` naming something other than a
    // currently-active UN/ECE Recommendation 20 common code — see
    // `crate::unit_of_measure`'s own doc comment for why this standard was
    // chosen, and why only currently-active codes (not deprecated/deleted
    // ones) validate successfully.
    InvalidUnitCode {
        machine: String,
        name: String,
        unit: String,
    },
}

impl fmt::Display for DeviceDescriptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceDescriptionError::Toml(error) => write!(formatter, "{error}"),
            DeviceDescriptionError::AddressOverflow {
                machine,
                name,
                base_address,
                offset,
            } => write!(
                formatter,
                "machine '{machine}': '{name}' address overflows u16: base_address {base_address} + offset {offset}"
            ),
            DeviceDescriptionError::InvalidMachineName { name } => write!(
                formatter,
                "invalid machine name '{name}': must be non-empty and contain only ASCII alphanumeric characters, '_', or '-'"
            ),
            DeviceDescriptionError::DuplicateMachineName { name } => {
                write!(formatter, "duplicate machine name '{name}'")
            }
            DeviceDescriptionError::ReservedFileNumber {
                machine,
                file_number,
            } => write!(
                formatter,
                "machine '{machine}': file_number {file_number} is reserved for the server's own compressed-description transfer and cannot be used in [[file-records]]"
            ),
            DeviceDescriptionError::InvalidUnitCode {
                machine,
                name,
                unit,
            } => write!(
                formatter,
                "machine '{machine}': '{name}' has unit '{unit}', which is not a currently-active UN/ECE Recommendation 20 common code"
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

fn validate_machine_name(name: &str) -> Result<(), DeviceDescriptionError> {
    let is_valid = !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        });

    if is_valid {
        Ok(())
    } else {
        Err(DeviceDescriptionError::InvalidMachineName {
            name: name.to_string(),
        })
    }
}

// Resolves `base_address + offset` for every entry in a section, sharing the
// same overflow handling regardless of whether the caller is registers or
// coils.
fn resolve_addresses<Entry>(
    machine_name: &str,
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
                    machine: machine_name.to_string(),
                    name: name_of(&entry),
                    base_address,
                    offset,
                }
            })?;
            Ok((entry, address))
        })
        .collect()
}

// Shared by both register-bearing entry types (`RegisterDescription`,
// `InputRegisterDescription`) — the only two with a `unit` field at all, see
// `RegisterDescription::unit`'s own doc comment for why coils/discrete-
// inputs don't get one. A `None` unit (the common case) always passes.
fn validate_unit_code(
    machine_name: &str,
    name: &str,
    unit: &Option<String>,
) -> Result<(), DeviceDescriptionError> {
    match unit {
        Some(code) if !is_valid_unit_code(code) => Err(DeviceDescriptionError::InvalidUnitCode {
            machine: machine_name.to_string(),
            name: name.to_string(),
            unit: code.clone(),
        }),
        _ => Ok(()),
    }
}

fn resolve_machine(raw: RawMachine) -> Result<MachineDescription, DeviceDescriptionError> {
    let machine_name = raw.name.as_str();
    let mem_layout = raw.registers.mem_layout;

    let registers = resolve_addresses(
        machine_name,
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
        unit: entry.unit,
    })
    .collect::<Vec<_>>();
    for register in &registers {
        validate_unit_code(machine_name, &register.name, &register.unit)?;
    }

    let coils = resolve_addresses(
        machine_name,
        raw.coils.base_address,
        raw.coils.entries,
        |entry: &RawBitEntry| entry.offset,
        |entry: &RawBitEntry| entry.name.clone(),
    )?
    .into_iter()
    .map(|(entry, address)| CoilDescription {
        name: entry.name,
        address,
    })
    .collect();

    let input_register_mem_layout = raw.input_registers.mem_layout;

    let input_registers = resolve_addresses(
        machine_name,
        raw.input_registers.base_address,
        raw.input_registers.entries,
        |entry: &RawInputRegisterEntry| entry.offset,
        |entry: &RawInputRegisterEntry| entry.name.clone(),
    )?
    .into_iter()
    .map(|(entry, address)| InputRegisterDescription {
        name: entry.name,
        address,
        data_type: entry.data_type,
        unit: entry.unit,
    })
    .collect::<Vec<_>>();
    for input_register in &input_registers {
        validate_unit_code(machine_name, &input_register.name, &input_register.unit)?;
    }

    let discrete_inputs = resolve_addresses(
        machine_name,
        raw.discrete_inputs.base_address,
        raw.discrete_inputs.entries,
        |entry: &RawBitEntry| entry.offset,
        |entry: &RawBitEntry| entry.name.clone(),
    )?
    .into_iter()
    .map(|(entry, address)| DiscreteInputDescription {
        name: entry.name,
        address,
    })
    .collect();

    for entry in &raw.file_records {
        if entry.file_number == RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER {
            return Err(DeviceDescriptionError::ReservedFileNumber {
                machine: machine_name.to_string(),
                file_number: entry.file_number,
            });
        }
    }

    let file_records = raw
        .file_records
        .into_iter()
        .map(|entry| FileRecordDescription {
            file_number: entry.file_number,
            record_number: entry.record_number,
            record_length: entry.record_length,
        })
        .collect();

    Ok(MachineDescription {
        name: raw.name,
        unit_id: raw.unit_id,
        registers,
        coils,
        discrete_inputs,
        input_registers,
        file_records,
        mem_layout,
        input_register_mem_layout,
        server_id: raw.server_id,
    })
}

impl DeviceDescription {
    pub fn parse(toml_source: &str) -> Result<Self, DeviceDescriptionError> {
        let raw: RawDeviceDescription = toml::from_str(toml_source)?;

        let mut seen_names = std::collections::HashSet::new();
        let mut machines = Vec::with_capacity(raw.machines.len());

        for raw_machine in raw.machines {
            validate_machine_name(&raw_machine.name)?;
            if !seen_names.insert(raw_machine.name.clone()) {
                return Err(DeviceDescriptionError::DuplicateMachineName {
                    name: raw_machine.name,
                });
            }

            machines.push(resolve_machine(raw_machine)?);
        }

        Ok(DeviceDescription { machines })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_example_device_description_parses_and_validates() {
        let toml_source = include_str!("../../examples/device-description.toml");
        DeviceDescription::parse(toml_source)
            .expect("examples/device-description.toml must always parse cleanly");
    }

    #[test]
    fn register_count_matches_each_type_s_wire_width() {
        for data_type in [DataType::U8, DataType::I8, DataType::U16, DataType::I16] {
            assert_eq!(data_type.register_count(), 1);
        }
        for data_type in [
            DataType::U24,
            DataType::I24,
            DataType::U32,
            DataType::I32,
            DataType::F32,
        ] {
            assert_eq!(data_type.register_count(), 2);
        }
        for data_type in [DataType::U64, DataType::I64, DataType::F64] {
            assert_eq!(data_type.register_count(), 4);
        }
    }

    #[test]
    fn parse_reads_valid_device_description() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"

            [[machines.registers.entries]]
            name = "Stop_Process"
            offset = 2
            data_type = "f32"
            access = "read_write"

            [machines.coils]
            base_address = 0

            [[machines.coils.entries]]
            name = "Motor_Running"
            offset = 1

            [[machines.coils.entries]]
            name = "Alarm_Active"
            offset = 2
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert_eq!(
            description,
            DeviceDescription {
                machines: vec![MachineDescription {
                    name: "PumpA".to_string(),
                    unit_id: 1,
                    registers: vec![
                        RegisterDescription {
                            name: "Tank_Temperature".to_string(),
                            address: 40001,
                            data_type: DataType::U16,
                            access: AccessRight::ReadOnly,
                            unit: None,
                        },
                        RegisterDescription {
                            name: "Stop_Process".to_string(),
                            address: 40002,
                            data_type: DataType::F32,
                            access: AccessRight::ReadWrite,
                            unit: None,
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
                    discrete_inputs: vec![],
                    input_registers: vec![],
                    file_records: vec![],
                    mem_layout: MemLayout::Abcd,
                    input_register_mem_layout: MemLayout::Abcd,
                    server_id: None,
                }],
            }
        );
    }

    #[test]
    fn parse_of_empty_source_has_no_machines() {
        let description = DeviceDescription::parse("").unwrap();
        assert_eq!(description.machines, vec![]);
    }

    #[test]
    fn parse_reads_several_independent_machines() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.coils]
            base_address = 0

            [[machines.coils.entries]]
            name = "Motor_Running"
            offset = 1

            [[machines]]
            name = "PumpB"
            unit_id = 2

            [machines.coils]
            base_address = 0

            [[machines.coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert_eq!(description.machines.len(), 2);
        assert_eq!(description.machines[0].name, "PumpA");
        assert_eq!(description.machines[0].unit_id, 1);
        assert_eq!(description.machines[1].name, "PumpB");
        assert_eq!(description.machines[1].unit_id, 2);
    }

    #[test]
    fn parse_rejects_duplicate_machine_names() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines]]
            name = "PumpA"
            unit_id = 2
        "#;

        let error = DeviceDescription::parse(toml_source).unwrap_err();

        assert!(matches!(
            error,
            DeviceDescriptionError::DuplicateMachineName { name } if name == "PumpA"
        ));
    }

    #[test]
    fn parse_rejects_empty_machine_name() {
        let toml_source = r#"
            [[machines]]
            name = ""
            unit_id = 1
        "#;

        let error = DeviceDescription::parse(toml_source).unwrap_err();

        assert!(matches!(
            error,
            DeviceDescriptionError::InvalidMachineName { name } if name.is_empty()
        ));
    }

    #[test]
    fn parse_rejects_machine_name_with_disallowed_characters() {
        for name in ["Pump A", "Pump.A", "Pump/A", "Pümp"] {
            let toml_source = format!(
                r#"
                    [[machines]]
                    name = "{name}"
                    unit_id = 1
                "#
            );

            let error = DeviceDescription::parse(&toml_source).unwrap_err();

            assert!(
                matches!(error, DeviceDescriptionError::InvalidMachineName { .. }),
                "expected {name:?} to be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn parse_accepts_machine_name_with_underscores_and_hyphens() {
        let toml_source = r#"
            [[machines]]
            name = "Pump_A-1"
            unit_id = 1
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert_eq!(description.machines[0].name, "Pump_A-1");
    }

    #[test]
    fn parse_rejects_machine_missing_unit_id() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_reads_file_record_entries() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines.file-records]]
            file_number = 20
            record_number = 5
            record_length = 9

            [[machines.file-records]]
            file_number = 20
            record_number = 6
            record_length = 9
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert_eq!(
            description.machines[0].file_records,
            vec![
                FileRecordDescription {
                    file_number: 20,
                    record_number: 5,
                    record_length: 9,
                },
                FileRecordDescription {
                    file_number: 20,
                    record_number: 6,
                    record_length: 9,
                },
            ]
        );
    }

    #[test]
    fn parse_rejects_a_file_record_using_the_reserved_file_number() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines.file-records]]
            file_number = 65535
            record_number = 1
            record_length = 1
        "#;

        let error = DeviceDescription::parse(toml_source).unwrap_err();
        match error {
            DeviceDescriptionError::ReservedFileNumber {
                machine,
                file_number,
            } => {
                assert_eq!(machine, "PumpA");
                assert_eq!(file_number, RESERVED_DEVICE_DESCRIPTION_FILE_NUMBER);
            }
            other => panic!("expected ReservedFileNumber, got {other:?}"),
        }
    }

    #[test]
    fn parse_accepts_a_register_with_a_valid_unit_code() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
            unit = "CEL"
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();
        assert_eq!(
            description.machines[0].registers[0].unit,
            Some("CEL".to_string())
        );
    }

    #[test]
    fn parse_accepts_a_register_without_a_unit() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();
        assert_eq!(description.machines[0].registers[0].unit, None);
    }

    #[test]
    fn parse_rejects_a_register_with_an_invalid_unit_code() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
            unit = "NOT_A_REAL_UNIT_CODE"
        "#;

        let error = DeviceDescription::parse(toml_source).unwrap_err();
        match error {
            DeviceDescriptionError::InvalidUnitCode {
                machine,
                name,
                unit,
            } => {
                assert_eq!(machine, "PumpA");
                assert_eq!(name, "Tank_Temperature");
                assert_eq!(unit, "NOT_A_REAL_UNIT_CODE");
            }
            other => panic!("expected InvalidUnitCode, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_an_input_register_with_an_invalid_unit_code() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.input-registers]
            base_address = 30000
            mem-layout = "abcd"

            [[machines.input-registers.entries]]
            name = "Flow_Rate"
            offset = 1
            data_type = "f32"
            unit = "NOT_A_REAL_UNIT_CODE"
        "#;

        let error = DeviceDescription::parse(toml_source).unwrap_err();
        match error {
            DeviceDescriptionError::InvalidUnitCode {
                machine,
                name,
                unit,
            } => {
                assert_eq!(machine, "PumpA");
                assert_eq!(name, "Flow_Rate");
                assert_eq!(unit, "NOT_A_REAL_UNIT_CODE");
            }
            other => panic!("expected InvalidUnitCode, got {other:?}"),
        }
    }

    #[test]
    fn parse_accepts_an_input_register_with_a_valid_unit_code() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.input-registers]
            base_address = 30000
            mem-layout = "abcd"

            [[machines.input-registers.entries]]
            name = "Flow_Rate"
            offset = 1
            data_type = "f32"
            unit = "MTQ"
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();
        assert_eq!(
            description.machines[0].input_registers[0].unit,
            Some("MTQ".to_string())
        );
    }

    #[test]
    fn parse_accepts_a_file_record_one_below_the_reserved_file_number() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines.file-records]]
            file_number = 65534
            record_number = 1
            record_length = 1
        "#;

        assert!(DeviceDescription::parse(toml_source).is_ok());
    }

    #[test]
    fn parse_of_machine_with_no_file_records_has_none() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();
        assert_eq!(description.machines[0].file_records, vec![]);
    }

    #[test]
    fn parse_reads_a_configured_server_id() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1
            server-id = "infused_modbus-demo-plc"
        "#;
        let description = DeviceDescription::parse(toml_source).unwrap();
        assert_eq!(
            description.machines[0].server_id,
            Some("infused_modbus-demo-plc".to_string())
        );
    }

    #[test]
    fn parse_treats_an_absent_server_id_as_none() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1
        "#;
        let description = DeviceDescription::parse(toml_source).unwrap();
        assert_eq!(description.machines[0].server_id, None);
    }

    #[test]
    fn parse_reads_discrete_inputs_and_input_registers() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.discrete-inputs]
            base_address = 10000

            [[machines.discrete-inputs.entries]]
            name = "Door_Open_Sensor"
            offset = 1

            [[machines.discrete-inputs.entries]]
            name = "Emergency_Stop_Pressed"
            offset = 2

            [machines.input-registers]
            base_address = 30000
            mem-layout = "cdab"

            [[machines.input-registers.entries]]
            name = "Flow_Rate"
            offset = 1
            data_type = "f32"
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();
        let machine = &description.machines[0];

        assert_eq!(
            machine.discrete_inputs,
            vec![
                DiscreteInputDescription {
                    name: "Door_Open_Sensor".to_string(),
                    address: 10001,
                },
                DiscreteInputDescription {
                    name: "Emergency_Stop_Pressed".to_string(),
                    address: 10002,
                },
            ]
        );
        assert_eq!(
            machine.input_registers,
            vec![InputRegisterDescription {
                name: "Flow_Rate".to_string(),
                address: 30001,
                data_type: DataType::F32,
                unit: None,
            }]
        );
        assert_eq!(machine.input_register_mem_layout, MemLayout::Cdab);
    }

    #[test]
    fn parse_treats_an_absent_discrete_inputs_section_as_no_discrete_inputs() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.coils]
            base_address = 0

            [[machines.coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert!(description.machines[0].discrete_inputs.is_empty());
    }

    #[test]
    fn parse_treats_an_absent_input_registers_section_as_no_input_registers() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.coils]
            base_address = 0

            [[machines.coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert!(description.machines[0].input_registers.is_empty());
    }

    #[test]
    fn parse_rejects_discrete_input_missing_base_address() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines.discrete-inputs.entries]]
            name = "Door_Open_Sensor"
            offset = 1
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_input_register_missing_base_address() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines.input-registers.entries]]
            name = "Flow_Rate"
            offset = 1
            data_type = "f32"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_input_register_missing_mem_layout() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.input-registers]
            base_address = 30000

            [[machines.input-registers.entries]]
            name = "Flow_Rate"
            offset = 1
            data_type = "f32"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_discrete_input_address_overflow() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.discrete-inputs]
            base_address = 65535

            [[machines.discrete-inputs.entries]]
            name = "Door_Open_Sensor"
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

    #[test]
    fn parse_rejects_input_register_address_overflow() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.input-registers]
            base_address = 65535
            mem-layout = "abcd"

            [[machines.input-registers.entries]]
            name = "Flow_Rate"
            offset = 1
            data_type = "f32"
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
    fn parse_reads_every_data_type() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 0
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "A"
            offset = 0
            data_type = "u8"
            access = "read_only"

            [[machines.registers.entries]]
            name = "B"
            offset = 1
            data_type = "i8"
            access = "read_only"

            [[machines.registers.entries]]
            name = "C"
            offset = 2
            data_type = "u16"
            access = "read_only"

            [[machines.registers.entries]]
            name = "D"
            offset = 3
            data_type = "i16"
            access = "read_only"

            [[machines.registers.entries]]
            name = "E"
            offset = 4
            data_type = "u24"
            access = "read_only"

            [[machines.registers.entries]]
            name = "F"
            offset = 5
            data_type = "i24"
            access = "read_only"

            [[machines.registers.entries]]
            name = "G"
            offset = 6
            data_type = "u32"
            access = "read_only"

            [[machines.registers.entries]]
            name = "H"
            offset = 7
            data_type = "i32"
            access = "read_only"

            [[machines.registers.entries]]
            name = "I"
            offset = 8
            data_type = "u64"
            access = "read_only"

            [[machines.registers.entries]]
            name = "J"
            offset = 9
            data_type = "i64"
            access = "read_only"

            [[machines.registers.entries]]
            name = "K"
            offset = 10
            data_type = "f32"
            access = "read_only"

            [[machines.registers.entries]]
            name = "L"
            offset = 11
            data_type = "f64"
            access = "read_only"
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        let data_types: Vec<DataType> = description.machines[0]
            .registers
            .iter()
            .map(|register| register.data_type)
            .collect();
        assert_eq!(
            data_types,
            vec![
                DataType::U8,
                DataType::I8,
                DataType::U16,
                DataType::I16,
                DataType::U24,
                DataType::I24,
                DataType::U32,
                DataType::I32,
                DataType::U64,
                DataType::I64,
                DataType::F32,
                DataType::F64,
            ]
        );
    }

    #[test]
    fn parse_reads_every_mem_layout() {
        for (tag, expected) in [
            ("abcd", MemLayout::Abcd),
            ("badc", MemLayout::Badc),
            ("cdab", MemLayout::Cdab),
            ("dcba", MemLayout::Dcba),
        ] {
            let toml_source = format!(
                r#"
                    [[machines]]
                    name = "PumpA"
                    unit_id = 1

                    [machines.registers]
                    base_address = 0
                    mem-layout = "{tag}"

                    [[machines.registers.entries]]
                    name = "A"
                    offset = 0
                    data_type = "u16"
                    access = "read_only"
                "#
            );

            let description = DeviceDescription::parse(&toml_source).unwrap();
            assert_eq!(description.machines[0].mem_layout, expected);
        }
    }

    #[test]
    fn parse_rejects_missing_mem_layout() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_unknown_mem_layout() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "wxyz"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_treats_an_absent_coils_section_as_no_coils() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u16"
            access = "read_only"
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert!(description.machines[0].coils.is_empty());
    }

    #[test]
    fn parse_treats_an_absent_registers_section_as_no_registers() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.coils]
            base_address = 0

            [[machines.coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        let description = DeviceDescription::parse(toml_source).unwrap();

        assert!(description.machines[0].registers.is_empty());
        assert_eq!(description.machines[0].coils.len(), 1);
    }

    #[test]
    fn parse_rejects_missing_required_field() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            data_type = "u16"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_missing_base_address() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines.registers.entries]]
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
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [[machines.coils.entries]]
            name = "Motor_Running"
            offset = 1
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_coil_missing_offset() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.coils]
            base_address = 0

            [[machines.coils.entries]]
            name = "Motor_Running"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_unknown_data_type() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
            name = "Tank_Temperature"
            offset = 1
            data_type = "u128"
            access = "read_only"
        "#;

        assert!(DeviceDescription::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_unknown_access_right() {
        let toml_source = r#"
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 40000
            mem-layout = "abcd"

            [[machines.registers.entries]]
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
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.registers]
            base_address = 65535
            mem-layout = "abcd"

            [[machines.registers.entries]]
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
            [[machines]]
            name = "PumpA"
            unit_id = 1

            [machines.coils]
            base_address = 65535

            [[machines.coils.entries]]
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
