//! `ServerHandle` — the "Option C" design from CLAUDE.md's MQTT/Sparkplug B
//! section: a plain safe-Rust library (no `unsafe`, no FFI) that wraps
//! `datafs::MachineStores` behind a validated, synchronous, name-based
//! `set`/`get` API. Motivation: every existing way to update the server's own
//! dataset (FUSE's `WriteMode::Direct` write path, `datafs::flatfile`'s
//! direct-write watcher) re-implements the same "resolve a name against the
//! `DeviceDescription`, check it's writable, parse the raw value, apply it"
//! logic, keyed off something specific to that presentation layer (an inode,
//! a file path). `ServerHandle` is that same logic keyed off nothing but a
//! plain machine/point name — meant to be reused by any future local
//! interface (the socket daemon this module's own sibling adds, and
//! eventually a `cdylib` FFI shim, per CLAUDE.md's explicitly-deferred plan)
//! without depending on `fuser`/inotify machinery at all.
//!
//! Writes go directly through the same `Arc<Mutex<_>>` stores every other
//! writer already locks — not through `transaction_sender`'s channel. The
//! channel's real job (see CLAUDE.md's "server direct-write model") is
//! sequencing concurrent FUSE `write()`/`release()` calls that can't block
//! on a lock held elsewhere without stalling the kernel; a plain synchronous
//! library call has no such constraint; and the `Mutex` each store already
//! wraps is exactly what continues to make a `ServerHandle` call and a
//! concurrent channel-drain from `transaction_consumer` mutually exclusive,
//! not a new correctness mechanism.
//!
//! **Typed API, added once a direct-embedding Rust consumer (not just a
//! text-protocol one like `data_daemon`) became a real target:** alongside
//! the original string-based `set`/`get`, every point kind also has a typed
//! `set_*`/`get_*` pair (`set_register`/`get_register`, `set_coil`/
//! `get_coil`, ...) operating on `datafs`'s own `RegisterValue`/`CoilValue`
//! directly — `set_register` rejects a value whose own `RegisterValue::
//! data_type()` doesn't match the register's declared type
//! (`ServerHandleError::TypeMismatch`), which a raw string can't express at
//! all. `registers`/`coils`/`discrete_inputs`/`input_registers`/
//! `file_records` expose each machine's declared shape (straight from its
//! `MachineDescription`) so a caller can enumerate what exists and which
//! type each point expects, without hardcoding names or re-parsing the TOML
//! itself. String `set`/`get` now just parse `raw_value` and delegate to
//! the typed methods — one place does string parsing, one place does
//! validation.
//!
//! **Discrete inputs/input registers are writable here**, even though no
//! Modbus function code ever lets a master write either over the wire, and
//! neither is writable on the client: on `server`, nothing else populates
//! them, so local, direct writes are how an operator/technician (or an
//! embedding program using this API) provides what a real sensor would
//! otherwise supply — consistent with CLAUDE.md's "server direct-write
//! model" already covering the same two types on the FUSE/`files` side.
//! (The original version of this API incorrectly rejected these two with
//! `ReadOnly`, inherited unreviewed from the string-only `set`'s own
//! pre-typed-API logic — fixed alongside adding the typed methods.)

use datafs::{
    CoilValue, MachineStores, RegisterValue, WriteStatus, default_register_value, parse_coil_value,
    parse_file_record_name, parse_file_record_value, parse_register_value,
};
use protocol::device_description::{
    AccessRight, CoilDescription, DataType, DiscreteInputDescription, FileRecordDescription,
    InputRegisterDescription, MachineDescription, RegisterDescription,
};
use std::collections::HashMap;
use std::fmt;
use std::sync::PoisonError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerHandleError {
    UnknownMachine(String),
    UnknownPoint(String),
    ReadOnly(String),
    InvalidValue(String),
    /// A typed `set_*` call (`set_register`/`set_input_register`) was given a
    /// `RegisterValue` whose own `data_type()` doesn't match what the point
    /// is actually declared as in the device description — e.g. a `U32`
    /// value for a register declared `u16`. Distinct from `InvalidValue`,
    /// which is about a *string* that doesn't parse at all; this is about an
    /// already-typed value of the wrong type, only reachable through the
    /// typed API.
    TypeMismatch {
        expected: DataType,
        got: DataType,
    },
}

impl fmt::Display for ServerHandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerHandleError::UnknownMachine(name) => write!(formatter, "unknown machine {name}"),
            ServerHandleError::UnknownPoint(name) => write!(formatter, "unknown point {name}"),
            ServerHandleError::ReadOnly(name) => write!(formatter, "{name} is read-only"),
            ServerHandleError::InvalidValue(value) => {
                write!(formatter, "invalid value {value:?} for this point's type")
            }
            ServerHandleError::TypeMismatch { expected, got } => {
                write!(formatter, "expected {expected:?}, got {got:?}")
            }
        }
    }
}

impl std::error::Error for ServerHandleError {}

fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

struct ServerHandleMachine {
    description: MachineDescription,
    stores: MachineStores,
}

/// One `ServerHandle` covers every machine a `server` process was started
/// with — mirrors how `HashMap<String, MachineStores>` is already the
/// established per-machine bundle shape in `server::main`.
pub struct ServerHandle {
    machines: HashMap<String, ServerHandleMachine>,
}

impl ServerHandle {
    pub fn new(machines: &[MachineDescription], stores: &HashMap<String, MachineStores>) -> Self {
        let machines = machines
            .iter()
            .map(|machine| {
                let handle_machine = ServerHandleMachine {
                    description: machine.clone(),
                    stores: stores
                        .get(&machine.name)
                        .expect("stores was built from the same machine list")
                        .clone(),
                };
                (machine.name.clone(), handle_machine)
            })
            .collect();
        ServerHandle { machines }
    }

    fn machine(&self, machine_name: &str) -> Result<&ServerHandleMachine, ServerHandleError> {
        self.machines
            .get(machine_name)
            .ok_or_else(|| ServerHandleError::UnknownMachine(machine_name.to_string()))
    }

    /// Every machine name this handle covers, in no particular order — lets
    /// a caller discover what's available without already knowing the
    /// device description out of band.
    pub fn machine_names(&self) -> impl Iterator<Item = &str> {
        self.machines.keys().map(String::as_str)
    }

    /// This machine's declared holding registers — name, address, data
    /// type, and access right for each, straight from the device
    /// description. Lets a caller enumerate what's settable/readable (and
    /// with which `RegisterValue` variant `set_register` expects) without
    /// hardcoding names or re-parsing the TOML themselves.
    pub fn registers(
        &self,
        machine_name: &str,
    ) -> Result<&[RegisterDescription], ServerHandleError> {
        Ok(&self.machine(machine_name)?.description.registers)
    }

    /// This machine's declared coils.
    pub fn coils(&self, machine_name: &str) -> Result<&[CoilDescription], ServerHandleError> {
        Ok(&self.machine(machine_name)?.description.coils)
    }

    /// This machine's declared discrete inputs.
    pub fn discrete_inputs(
        &self,
        machine_name: &str,
    ) -> Result<&[DiscreteInputDescription], ServerHandleError> {
        Ok(&self.machine(machine_name)?.description.discrete_inputs)
    }

    /// This machine's declared input registers.
    pub fn input_registers(
        &self,
        machine_name: &str,
    ) -> Result<&[InputRegisterDescription], ServerHandleError> {
        Ok(&self.machine(machine_name)?.description.input_registers)
    }

    /// This machine's declared file records.
    pub fn file_records(
        &self,
        machine_name: &str,
    ) -> Result<&[FileRecordDescription], ServerHandleError> {
        Ok(&self.machine(machine_name)?.description.file_records)
    }

    /// Sets `point_name` (a holding register) on `machine_name` to `value`,
    /// after validating it exists, is writable, and that `value`'s own
    /// `RegisterValue::data_type()` matches what this register is actually
    /// declared as in the device description — the type-safety this typed
    /// API exists for (the string-based `set` below can only reject an
    /// unparseable string, not a well-formed value of the wrong width).
    pub fn set_register(
        &self,
        machine_name: &str,
        point_name: &str,
        value: RegisterValue,
    ) -> Result<(), ServerHandleError> {
        let machine = self.machine(machine_name)?;
        let register = machine
            .description
            .registers
            .iter()
            .find(|register| register.name == point_name)
            .ok_or_else(|| ServerHandleError::UnknownPoint(point_name.to_string()))?;
        if register.access != AccessRight::ReadWrite {
            return Err(ServerHandleError::ReadOnly(point_name.to_string()));
        }
        if value.data_type() != register.data_type {
            return Err(ServerHandleError::TypeMismatch {
                expected: register.data_type,
                got: value.data_type(),
            });
        }
        machine
            .stores
            .registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(point_name.to_string(), value);
        machine
            .stores
            .report
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(point_name.to_string(), WriteStatus::Ok);
        Ok(())
    }

    /// Reads `point_name`'s (a holding register's) current value on
    /// `machine_name`, typed — an unset register reads back as its typed
    /// default (`datafs::default_register_value`), never an error.
    pub fn get_register(
        &self,
        machine_name: &str,
        point_name: &str,
    ) -> Result<RegisterValue, ServerHandleError> {
        let machine = self.machine(machine_name)?;
        let register = machine
            .description
            .registers
            .iter()
            .find(|register| register.name == point_name)
            .ok_or_else(|| ServerHandleError::UnknownPoint(point_name.to_string()))?;
        let value = machine
            .stores
            .registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(point_name)
            .unwrap_or_else(|| default_register_value(register.data_type));
        Ok(value)
    }

    /// Sets `point_name` (a coil) on `machine_name` to `value`. Coils have
    /// no `data_type`/`access` variance to validate (always 1 bit, always
    /// writable per the device description's own `CoilDescription` shape)
    /// — only existence needs checking.
    pub fn set_coil(
        &self,
        machine_name: &str,
        point_name: &str,
        value: CoilValue,
    ) -> Result<(), ServerHandleError> {
        let machine = self.machine(machine_name)?;
        if !machine
            .description
            .coils
            .iter()
            .any(|coil| coil.name == point_name)
        {
            return Err(ServerHandleError::UnknownPoint(point_name.to_string()));
        }
        machine
            .stores
            .coils
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(point_name.to_string(), value);
        machine
            .stores
            .report
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(point_name.to_string(), WriteStatus::Ok);
        Ok(())
    }

    /// Reads `point_name`'s (a coil's) current value on `machine_name` —
    /// an unset coil reads back as `CoilValue(false)`, never an error.
    pub fn get_coil(
        &self,
        machine_name: &str,
        point_name: &str,
    ) -> Result<CoilValue, ServerHandleError> {
        let machine = self.machine(machine_name)?;
        if !machine
            .description
            .coils
            .iter()
            .any(|coil| coil.name == point_name)
        {
            return Err(ServerHandleError::UnknownPoint(point_name.to_string()));
        }
        let value = machine
            .stores
            .coils
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(point_name)
            .unwrap_or(CoilValue(false));
        Ok(value)
    }

    /// Sets `point_name` (a discrete input) on `machine_name` to `value`.
    /// Discrete inputs are never writable over the wire (no Modbus function
    /// code lets a master write one) nor on the client — but on `server`
    /// they're directly writable locally, same as every other data type,
    /// per CLAUDE.md's "server direct-write model": nothing else populates
    /// them, so an operator/technician needs some way to set what a real
    /// sensor would otherwise provide. No `report/` coverage, matching the
    /// same established precedent `holding-registers`/`coils` writes don't
    /// share with discrete-inputs/input-registers.
    pub fn set_discrete_input(
        &self,
        machine_name: &str,
        point_name: &str,
        value: CoilValue,
    ) -> Result<(), ServerHandleError> {
        let machine = self.machine(machine_name)?;
        if !machine
            .description
            .discrete_inputs
            .iter()
            .any(|entry| entry.name == point_name)
        {
            return Err(ServerHandleError::UnknownPoint(point_name.to_string()));
        }
        machine
            .stores
            .discrete_inputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(point_name.to_string(), value);
        Ok(())
    }

    /// Reads `point_name`'s (a discrete input's) current value on
    /// `machine_name` — an unset one reads back as `CoilValue(false)`,
    /// never an error.
    pub fn get_discrete_input(
        &self,
        machine_name: &str,
        point_name: &str,
    ) -> Result<CoilValue, ServerHandleError> {
        let machine = self.machine(machine_name)?;
        if !machine
            .description
            .discrete_inputs
            .iter()
            .any(|entry| entry.name == point_name)
        {
            return Err(ServerHandleError::UnknownPoint(point_name.to_string()));
        }
        let value = machine
            .stores
            .discrete_inputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(point_name)
            .unwrap_or(CoilValue(false));
        Ok(value)
    }

    /// Sets `point_name` (an input register) on `machine_name` to `value`,
    /// validating `value.data_type()` against the point's declared type —
    /// same reasoning and `report/`-exclusion as `set_discrete_input`, just
    /// for the register-shaped (not coil-shaped) read-only-over-the-wire
    /// data type.
    pub fn set_input_register(
        &self,
        machine_name: &str,
        point_name: &str,
        value: RegisterValue,
    ) -> Result<(), ServerHandleError> {
        let machine = self.machine(machine_name)?;
        let input_register = machine
            .description
            .input_registers
            .iter()
            .find(|entry| entry.name == point_name)
            .ok_or_else(|| ServerHandleError::UnknownPoint(point_name.to_string()))?;
        if value.data_type() != input_register.data_type {
            return Err(ServerHandleError::TypeMismatch {
                expected: input_register.data_type,
                got: value.data_type(),
            });
        }
        machine
            .stores
            .input_registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(point_name.to_string(), value);
        Ok(())
    }

    /// Reads `point_name`'s (an input register's) current value on
    /// `machine_name`, typed — an unset one reads back as its typed
    /// default.
    pub fn get_input_register(
        &self,
        machine_name: &str,
        point_name: &str,
    ) -> Result<RegisterValue, ServerHandleError> {
        let machine = self.machine(machine_name)?;
        let input_register = machine
            .description
            .input_registers
            .iter()
            .find(|entry| entry.name == point_name)
            .ok_or_else(|| ServerHandleError::UnknownPoint(point_name.to_string()))?;
        let value = machine
            .stores
            .input_registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(point_name)
            .unwrap_or_else(|| default_register_value(input_register.data_type));
        Ok(value)
    }

    /// Sets the file record identified by `(file_number, record_number)` on
    /// `machine_name` to `value` — raw bytes, no field-level interpretation,
    /// matching this project's established "file records are vendor-specific
    /// opaque blobs" stance (see CLAUDE.md's FC 0x14/0x15 section). No
    /// length check against the declared `record_length` here either, same
    /// "a technician always sees exactly what they set" precedent the
    /// FUSE/flatfile direct-write path already uses — length is enforced at
    /// the wire-response boundary instead, not here.
    pub fn set_file_record(
        &self,
        machine_name: &str,
        file_number: u16,
        record_number: u16,
        value: Vec<u8>,
    ) -> Result<(), ServerHandleError> {
        let machine = self.machine(machine_name)?;
        if !machine
            .description
            .file_records
            .iter()
            .any(|entry| entry.file_number == file_number && entry.record_number == record_number)
        {
            return Err(ServerHandleError::UnknownPoint(format!(
                "{file_number}:{record_number}"
            )));
        }
        machine
            .stores
            .file_records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set(file_number, record_number, value);
        Ok(())
    }

    /// Reads the file record identified by `(file_number, record_number)` on
    /// `machine_name` — an unset one reads back as `2 * record_length` zero
    /// bytes, never an error.
    pub fn get_file_record(
        &self,
        machine_name: &str,
        file_number: u16,
        record_number: u16,
    ) -> Result<Vec<u8>, ServerHandleError> {
        let machine = self.machine(machine_name)?;
        let entry = machine
            .description
            .file_records
            .iter()
            .find(|entry| entry.file_number == file_number && entry.record_number == record_number)
            .ok_or_else(|| {
                ServerHandleError::UnknownPoint(format!("{file_number}:{record_number}"))
            })?;
        let value = machine
            .stores
            .file_records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(file_number, record_number)
            .cloned()
            .unwrap_or_else(|| vec![0u8; 2 * entry.record_length as usize]);
        Ok(value)
    }

    /// Sets `point_name` on `machine_name` to `raw_value` (the same text
    /// shapes `transactions/`/a direct FUSE write already accept — decimal
    /// or `0x`-hex for registers, `0`/`1` for coils, whitespace-tolerant hex
    /// for file records). Parses `raw_value` against whichever point kind
    /// `point_name` resolves to, then delegates to that kind's typed
    /// `set_*` method — this is the only place in `ServerHandle` that still
    /// does string parsing; every actual validation (writability, type)
    /// lives once, in the typed methods.
    pub fn set(
        &self,
        machine_name: &str,
        point_name: &str,
        raw_value: &str,
    ) -> Result<(), ServerHandleError> {
        let description = &self.machine(machine_name)?.description;

        if let Some(register) = description
            .registers
            .iter()
            .find(|register| register.name == point_name)
        {
            let value = parse_register_value(register.data_type, raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
            return self.set_register(machine_name, point_name, value);
        }

        if description.coils.iter().any(|coil| coil.name == point_name) {
            let value = parse_coil_value(raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
            return self.set_coil(machine_name, point_name, value);
        }

        if description
            .discrete_inputs
            .iter()
            .any(|entry| entry.name == point_name)
        {
            let value = parse_coil_value(raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
            return self.set_discrete_input(machine_name, point_name, value);
        }

        if let Some(input_register) = description
            .input_registers
            .iter()
            .find(|entry| entry.name == point_name)
        {
            let value = parse_register_value(input_register.data_type, raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
            return self.set_input_register(machine_name, point_name, value);
        }

        if let Some((file_number, record_number)) = parse_file_record_name(point_name)
            && description.file_records.iter().any(|entry| {
                entry.file_number == file_number && entry.record_number == record_number
            })
        {
            let value = parse_file_record_value(raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
            return self.set_file_record(machine_name, file_number, record_number, value);
        }

        Err(ServerHandleError::UnknownPoint(point_name.to_string()))
    }

    /// Reads `point_name`'s current value on `machine_name`, formatted the
    /// same way its FUSE/flatfile file content already is — an unset point
    /// reads back as its typed default, never an error. Delegates to
    /// whichever kind's typed `get_*` method `point_name` resolves to and
    /// formats the result, same "one place does string conversion" shape
    /// as `set` above.
    pub fn get(&self, machine_name: &str, point_name: &str) -> Result<String, ServerHandleError> {
        let description = &self.machine(machine_name)?.description;

        if description
            .registers
            .iter()
            .any(|register| register.name == point_name)
        {
            return self
                .get_register(machine_name, point_name)
                .map(|value| value.to_string());
        }

        if description.coils.iter().any(|coil| coil.name == point_name) {
            return self
                .get_coil(machine_name, point_name)
                .map(|value| value.to_string());
        }

        if description
            .discrete_inputs
            .iter()
            .any(|entry| entry.name == point_name)
        {
            return self
                .get_discrete_input(machine_name, point_name)
                .map(|value| value.to_string());
        }

        if description
            .input_registers
            .iter()
            .any(|entry| entry.name == point_name)
        {
            return self
                .get_input_register(machine_name, point_name)
                .map(|value| value.to_string());
        }

        if let Some((file_number, record_number)) = parse_file_record_name(point_name)
            && description.file_records.iter().any(|entry| {
                entry.file_number == file_number && entry.record_number == record_number
            })
        {
            return self
                .get_file_record(machine_name, file_number, record_number)
                .map(|value| format_hex(&value));
        }

        Err(ServerHandleError::UnknownPoint(point_name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafs::RegisterValue;
    use protocol::device_description::{
        CoilDescription, DataType, DiscreteInputDescription, FileRecordDescription,
        InputRegisterDescription, MemLayout, RegisterDescription,
    };

    fn test_machine(name: &str) -> MachineDescription {
        MachineDescription {
            name: name.to_string(),
            unit_id: 1,
            registers: vec![
                RegisterDescription {
                    name: "Tank_Temperature".to_string(),
                    address: 0,
                    data_type: DataType::U16,
                    access: AccessRight::ReadWrite,
                },
                RegisterDescription {
                    name: "Firmware_Version".to_string(),
                    address: 1,
                    data_type: DataType::U16,
                    access: AccessRight::ReadOnly,
                },
            ],
            coils: vec![CoilDescription {
                name: "Motor_Running".to_string(),
                address: 0,
            }],
            discrete_inputs: vec![DiscreteInputDescription {
                name: "Door_Open".to_string(),
                address: 0,
            }],
            input_registers: vec![InputRegisterDescription {
                name: "Flow_Rate".to_string(),
                address: 0,
                data_type: DataType::F32,
            }],
            file_records: vec![FileRecordDescription {
                file_number: 4,
                record_number: 1,
                record_length: 2,
            }],
            mem_layout: MemLayout::Abcd,
            input_register_mem_layout: MemLayout::Abcd,
            server_id: None,
        }
    }

    fn test_handle() -> ServerHandle {
        let machine = test_machine("PumpA");
        let mut stores = HashMap::new();
        stores.insert("PumpA".to_string(), MachineStores::new());
        ServerHandle::new(std::slice::from_ref(&machine), &stores)
    }

    #[test]
    fn machine_names_lists_every_covered_machine() {
        let machine_a = test_machine("PumpA");
        let machine_b = test_machine("PumpB");
        let mut stores = HashMap::new();
        stores.insert("PumpA".to_string(), MachineStores::new());
        stores.insert("PumpB".to_string(), MachineStores::new());
        let handle = ServerHandle::new(&[machine_a, machine_b], &stores);

        let mut names: Vec<&str> = handle.machine_names().collect();
        names.sort_unstable();
        assert_eq!(names, vec!["PumpA", "PumpB"]);
    }

    #[test]
    fn registers_lists_every_declared_register_with_its_shape() {
        let handle = test_handle();
        let registers = handle.registers("PumpA").unwrap();
        assert_eq!(registers.len(), 2);
        let tank_temperature = registers
            .iter()
            .find(|register| register.name == "Tank_Temperature")
            .unwrap();
        assert_eq!(tank_temperature.data_type, DataType::U16);
        assert_eq!(tank_temperature.access, AccessRight::ReadWrite);
    }

    #[test]
    fn coils_lists_every_declared_coil() {
        let handle = test_handle();
        let coils = handle.coils("PumpA").unwrap();
        assert_eq!(coils.len(), 1);
        assert_eq!(coils[0].name, "Motor_Running");
    }

    #[test]
    fn discrete_inputs_lists_every_declared_discrete_input() {
        let handle = test_handle();
        let discrete_inputs = handle.discrete_inputs("PumpA").unwrap();
        assert_eq!(discrete_inputs.len(), 1);
        assert_eq!(discrete_inputs[0].name, "Door_Open");
    }

    #[test]
    fn input_registers_lists_every_declared_input_register() {
        let handle = test_handle();
        let input_registers = handle.input_registers("PumpA").unwrap();
        assert_eq!(input_registers.len(), 1);
        assert_eq!(input_registers[0].name, "Flow_Rate");
        assert_eq!(input_registers[0].data_type, DataType::F32);
    }

    #[test]
    fn file_records_lists_every_declared_file_record() {
        let handle = test_handle();
        let file_records = handle.file_records("PumpA").unwrap();
        assert_eq!(file_records.len(), 1);
        assert_eq!(file_records[0].file_number, 4);
        assert_eq!(file_records[0].record_number, 1);
    }

    #[test]
    fn every_listing_method_rejects_an_unknown_machine() {
        let handle = test_handle();
        assert_eq!(
            handle.registers("Nonexistent"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.coils("Nonexistent"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.discrete_inputs("Nonexistent"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.input_registers("Nonexistent"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.file_records("Nonexistent"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_and_get_a_register_round_trips() {
        let handle = test_handle();
        handle.set("PumpA", "Tank_Temperature", "30").unwrap();
        assert_eq!(handle.get("PumpA", "Tank_Temperature").unwrap(), "30");
    }

    #[test]
    fn set_register_and_get_register_round_trip() {
        let handle = test_handle();
        handle
            .set_register("PumpA", "Tank_Temperature", RegisterValue::U16(30))
            .unwrap();
        assert_eq!(
            handle.get_register("PumpA", "Tank_Temperature").unwrap(),
            RegisterValue::U16(30)
        );
    }

    #[test]
    fn get_register_of_an_unset_register_returns_the_typed_default() {
        let handle = test_handle();
        assert_eq!(
            handle.get_register("PumpA", "Tank_Temperature").unwrap(),
            RegisterValue::U16(0)
        );
    }

    #[test]
    fn set_register_rejects_a_value_of_the_wrong_type() {
        let handle = test_handle();
        assert_eq!(
            handle.set_register("PumpA", "Tank_Temperature", RegisterValue::U32(30)),
            Err(ServerHandleError::TypeMismatch {
                expected: DataType::U16,
                got: DataType::U32,
            })
        );
    }

    #[test]
    fn set_register_rejects_a_read_only_register() {
        let handle = test_handle();
        assert_eq!(
            handle.set_register("PumpA", "Firmware_Version", RegisterValue::U16(1)),
            Err(ServerHandleError::ReadOnly("Firmware_Version".to_string()))
        );
    }

    #[test]
    fn set_register_and_get_register_reject_an_unknown_point_name() {
        let handle = test_handle();
        assert_eq!(
            handle.set_register("PumpA", "Nonexistent", RegisterValue::U16(1)),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_register("PumpA", "Nonexistent"),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_register_and_get_register_reject_an_unknown_machine() {
        let handle = test_handle();
        assert_eq!(
            handle.set_register("Nonexistent", "Tank_Temperature", RegisterValue::U16(1)),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_register("Nonexistent", "Tank_Temperature"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_and_get_a_coil_round_trips() {
        let handle = test_handle();
        handle.set("PumpA", "Motor_Running", "1").unwrap();
        assert_eq!(handle.get("PumpA", "Motor_Running").unwrap(), "1");
    }

    #[test]
    fn set_coil_and_get_coil_round_trip() {
        let handle = test_handle();
        handle
            .set_coil("PumpA", "Motor_Running", CoilValue(true))
            .unwrap();
        assert_eq!(
            handle.get_coil("PumpA", "Motor_Running").unwrap(),
            CoilValue(true)
        );
    }

    #[test]
    fn get_coil_of_an_unset_coil_returns_false() {
        let handle = test_handle();
        assert_eq!(
            handle.get_coil("PumpA", "Motor_Running").unwrap(),
            CoilValue(false)
        );
    }

    #[test]
    fn set_coil_and_get_coil_reject_an_unknown_point_name() {
        let handle = test_handle();
        assert_eq!(
            handle.set_coil("PumpA", "Nonexistent", CoilValue(true)),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_coil("PumpA", "Nonexistent"),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_coil_and_get_coil_reject_an_unknown_machine() {
        let handle = test_handle();
        assert_eq!(
            handle.set_coil("Nonexistent", "Motor_Running", CoilValue(true)),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_coil("Nonexistent", "Motor_Running"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_and_get_a_file_record_round_trips() {
        let handle = test_handle();
        handle.set("PumpA", "4:1", "0D FE 00 20").unwrap();
        assert_eq!(handle.get("PumpA", "4:1").unwrap(), "0D FE 00 20");
    }

    #[test]
    fn get_of_an_unset_register_returns_the_typed_default() {
        let handle = test_handle();
        assert_eq!(handle.get("PumpA", "Tank_Temperature").unwrap(), "0");
    }

    #[test]
    fn get_of_an_unset_file_record_returns_the_zeroed_default() {
        let handle = test_handle();
        assert_eq!(handle.get("PumpA", "4:1").unwrap(), "00 00 00 00");
    }

    #[test]
    fn set_rejects_a_read_only_register() {
        let handle = test_handle();
        assert_eq!(
            handle.set("PumpA", "Firmware_Version", "1"),
            Err(ServerHandleError::ReadOnly("Firmware_Version".to_string()))
        );
    }

    #[test]
    fn set_writes_a_discrete_input_locally_on_the_server() {
        // Discrete inputs are never writable over the wire (no Modbus
        // function code lets a master write one) nor on the client, but on
        // `server` they're directly writable locally — see
        // `set_discrete_input`'s own doc comment for why.
        let handle = test_handle();
        handle.set("PumpA", "Door_Open", "1").unwrap();
        assert_eq!(handle.get("PumpA", "Door_Open").unwrap(), "1");
    }

    #[test]
    fn set_writes_an_input_register_locally_on_the_server() {
        let handle = test_handle();
        handle.set("PumpA", "Flow_Rate", "1.5").unwrap();
        assert_eq!(handle.get("PumpA", "Flow_Rate").unwrap(), "1.5");
    }

    #[test]
    fn get_reads_a_discrete_input_and_input_register_fine() {
        let handle = test_handle();
        assert_eq!(handle.get("PumpA", "Door_Open").unwrap(), "0");
        assert_eq!(handle.get("PumpA", "Flow_Rate").unwrap(), "0");
    }

    #[test]
    fn set_discrete_input_and_get_discrete_input_round_trip() {
        let handle = test_handle();
        handle
            .set_discrete_input("PumpA", "Door_Open", CoilValue(true))
            .unwrap();
        assert_eq!(
            handle.get_discrete_input("PumpA", "Door_Open").unwrap(),
            CoilValue(true)
        );
    }

    #[test]
    fn get_discrete_input_of_an_unset_one_returns_false() {
        let handle = test_handle();
        assert_eq!(
            handle.get_discrete_input("PumpA", "Door_Open").unwrap(),
            CoilValue(false)
        );
    }

    #[test]
    fn set_discrete_input_and_get_discrete_input_reject_an_unknown_point_name() {
        let handle = test_handle();
        assert_eq!(
            handle.set_discrete_input("PumpA", "Nonexistent", CoilValue(true)),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_discrete_input("PumpA", "Nonexistent"),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_discrete_input_and_get_discrete_input_reject_an_unknown_machine() {
        let handle = test_handle();
        assert_eq!(
            handle.set_discrete_input("Nonexistent", "Door_Open", CoilValue(true)),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_discrete_input("Nonexistent", "Door_Open"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_input_register_and_get_input_register_round_trip() {
        let handle = test_handle();
        handle
            .set_input_register("PumpA", "Flow_Rate", RegisterValue::F32(12.5))
            .unwrap();
        assert_eq!(
            handle.get_input_register("PumpA", "Flow_Rate").unwrap(),
            RegisterValue::F32(12.5)
        );
    }

    #[test]
    fn get_input_register_of_an_unset_one_returns_the_typed_default() {
        let handle = test_handle();
        assert_eq!(
            handle.get_input_register("PumpA", "Flow_Rate").unwrap(),
            RegisterValue::F32(0.0)
        );
    }

    #[test]
    fn set_input_register_rejects_a_value_of_the_wrong_type() {
        let handle = test_handle();
        assert_eq!(
            handle.set_input_register("PumpA", "Flow_Rate", RegisterValue::U16(1)),
            Err(ServerHandleError::TypeMismatch {
                expected: DataType::F32,
                got: DataType::U16,
            })
        );
    }

    #[test]
    fn set_input_register_and_get_input_register_reject_an_unknown_point_name() {
        let handle = test_handle();
        assert_eq!(
            handle.set_input_register("PumpA", "Nonexistent", RegisterValue::U16(1)),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_input_register("PumpA", "Nonexistent"),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_input_register_and_get_input_register_reject_an_unknown_machine() {
        let handle = test_handle();
        assert_eq!(
            handle.set_input_register("Nonexistent", "Flow_Rate", RegisterValue::F32(1.0)),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_input_register("Nonexistent", "Flow_Rate"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_file_record_and_get_file_record_round_trip() {
        let handle = test_handle();
        handle
            .set_file_record("PumpA", 4, 1, vec![0x0D, 0xFE, 0x00, 0x20])
            .unwrap();
        assert_eq!(
            handle.get_file_record("PumpA", 4, 1).unwrap(),
            vec![0x0D, 0xFE, 0x00, 0x20]
        );
    }

    #[test]
    fn get_file_record_of_an_unset_one_returns_zeroed_default() {
        let handle = test_handle();
        assert_eq!(handle.get_file_record("PumpA", 4, 1).unwrap(), vec![0; 4]);
    }

    #[test]
    fn set_file_record_and_get_file_record_reject_an_unknown_point() {
        let handle = test_handle();
        assert_eq!(
            handle.set_file_record("PumpA", 99, 1, vec![0x01]),
            Err(ServerHandleError::UnknownPoint("99:1".to_string()))
        );
        assert_eq!(
            handle.get_file_record("PumpA", 99, 1),
            Err(ServerHandleError::UnknownPoint("99:1".to_string()))
        );
    }

    #[test]
    fn set_file_record_and_get_file_record_reject_an_unknown_machine() {
        let handle = test_handle();
        assert_eq!(
            handle.set_file_record("Nonexistent", 4, 1, vec![0x01]),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get_file_record("Nonexistent", 4, 1),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_rejects_an_unparseable_value() {
        let handle = test_handle();
        assert_eq!(
            handle.set("PumpA", "Tank_Temperature", "not-a-number"),
            Err(ServerHandleError::InvalidValue("not-a-number".to_string()))
        );
    }

    #[test]
    fn set_and_get_reject_an_unknown_point_name() {
        let handle = test_handle();
        assert_eq!(
            handle.set("PumpA", "Nonexistent", "1"),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get("PumpA", "Nonexistent"),
            Err(ServerHandleError::UnknownPoint("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_and_get_reject_an_unknown_machine() {
        let handle = test_handle();
        assert_eq!(
            handle.set("Nonexistent", "Tank_Temperature", "1"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
        assert_eq!(
            handle.get("Nonexistent", "Tank_Temperature"),
            Err(ServerHandleError::UnknownMachine("Nonexistent".to_string()))
        );
    }

    #[test]
    fn set_writes_through_to_the_same_stores_handle_was_built_from() {
        let machine = test_machine("PumpA");
        let mut stores = HashMap::new();
        let machine_stores = MachineStores::new();
        stores.insert("PumpA".to_string(), machine_stores.clone());
        let handle = ServerHandle::new(std::slice::from_ref(&machine), &stores);

        handle.set("PumpA", "Tank_Temperature", "42").unwrap();

        assert_eq!(
            machine_stores
                .registers
                .lock()
                .unwrap()
                .get("Tank_Temperature"),
            Some(RegisterValue::U16(42))
        );
    }
}
