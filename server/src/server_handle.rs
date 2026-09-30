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

use datafs::{
    CoilValue, MachineStores, WriteStatus, default_register_value, parse_coil_value,
    parse_file_record_name, parse_file_record_value, parse_register_value,
};
use protocol::device_description::{AccessRight, MachineDescription};
use std::collections::HashMap;
use std::fmt;
use std::sync::PoisonError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerHandleError {
    UnknownMachine(String),
    UnknownPoint(String),
    ReadOnly(String),
    InvalidValue(String),
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

    /// Sets `point_name` on `machine_name` to `raw_value` (the same text
    /// shapes `transactions/`/a direct FUSE write already accept — decimal
    /// or `0x`-hex for registers, `0`/`1` for coils, whitespace-tolerant hex
    /// for file records), after validating it exists and is writable.
    /// Discrete inputs and input registers are never writable anywhere in
    /// this project (no Modbus function code lets a master write them
    /// either) and are rejected the same way a read-only register is.
    pub fn set(
        &self,
        machine_name: &str,
        point_name: &str,
        raw_value: &str,
    ) -> Result<(), ServerHandleError> {
        let machine = self.machine(machine_name)?;
        let description = &machine.description;

        if let Some(register) = description
            .registers
            .iter()
            .find(|register| register.name == point_name)
        {
            if register.access != AccessRight::ReadWrite {
                return Err(ServerHandleError::ReadOnly(point_name.to_string()));
            }
            let value = parse_register_value(register.data_type, raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
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
            return Ok(());
        }

        if description.coils.iter().any(|coil| coil.name == point_name) {
            let value = parse_coil_value(raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
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
            return Ok(());
        }

        if description
            .discrete_inputs
            .iter()
            .any(|entry| entry.name == point_name)
            || description
                .input_registers
                .iter()
                .any(|entry| entry.name == point_name)
        {
            return Err(ServerHandleError::ReadOnly(point_name.to_string()));
        }

        if let Some((file_number, record_number)) = parse_file_record_name(point_name)
            && description.file_records.iter().any(|entry| {
                entry.file_number == file_number && entry.record_number == record_number
            })
        {
            let value = parse_file_record_value(raw_value)
                .ok_or_else(|| ServerHandleError::InvalidValue(raw_value.to_string()))?;
            machine
                .stores
                .file_records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .set(file_number, record_number, value);
            return Ok(());
        }

        Err(ServerHandleError::UnknownPoint(point_name.to_string()))
    }

    /// Reads `point_name`'s current value on `machine_name`, formatted the
    /// same way its FUSE/flatfile file content already is — an unset point
    /// reads back as its typed default (`datafs::default_register_value`,
    /// `false`/`0`, or `2 * record_length` zero bytes), never an error.
    /// Unlike `set`, every point kind is readable, including discrete
    /// inputs/input registers.
    pub fn get(&self, machine_name: &str, point_name: &str) -> Result<String, ServerHandleError> {
        let machine = self.machine(machine_name)?;
        let description = &machine.description;

        if let Some(register) = description
            .registers
            .iter()
            .find(|register| register.name == point_name)
        {
            let value = machine
                .stores
                .registers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(point_name)
                .unwrap_or_else(|| default_register_value(register.data_type));
            return Ok(value.to_string());
        }

        if description.coils.iter().any(|coil| coil.name == point_name) {
            let value = machine
                .stores
                .coils
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(point_name)
                .unwrap_or(CoilValue(false));
            return Ok(value.to_string());
        }

        if description
            .discrete_inputs
            .iter()
            .any(|entry| entry.name == point_name)
        {
            let value = machine
                .stores
                .discrete_inputs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(point_name)
                .unwrap_or(CoilValue(false));
            return Ok(value.to_string());
        }

        if let Some(input_register) = description
            .input_registers
            .iter()
            .find(|entry| entry.name == point_name)
        {
            let value = machine
                .stores
                .input_registers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(point_name)
                .unwrap_or_else(|| default_register_value(input_register.data_type));
            return Ok(value.to_string());
        }

        if let Some((file_number, record_number)) = parse_file_record_name(point_name)
            && let Some(entry) = description.file_records.iter().find(|entry| {
                entry.file_number == file_number && entry.record_number == record_number
            })
        {
            let value = machine
                .stores
                .file_records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(file_number, record_number)
                .cloned()
                .unwrap_or_else(|| vec![0u8; 2 * entry.record_length as usize]);
            return Ok(format_hex(&value));
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
    fn set_and_get_a_register_round_trips() {
        let handle = test_handle();
        handle.set("PumpA", "Tank_Temperature", "30").unwrap();
        assert_eq!(handle.get("PumpA", "Tank_Temperature").unwrap(), "30");
    }

    #[test]
    fn set_and_get_a_coil_round_trips() {
        let handle = test_handle();
        handle.set("PumpA", "Motor_Running", "1").unwrap();
        assert_eq!(handle.get("PumpA", "Motor_Running").unwrap(), "1");
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
    fn set_rejects_a_discrete_input() {
        let handle = test_handle();
        assert_eq!(
            handle.set("PumpA", "Door_Open", "1"),
            Err(ServerHandleError::ReadOnly("Door_Open".to_string()))
        );
    }

    #[test]
    fn set_rejects_an_input_register() {
        let handle = test_handle();
        assert_eq!(
            handle.set("PumpA", "Flow_Rate", "1.0"),
            Err(ServerHandleError::ReadOnly("Flow_Rate".to_string()))
        );
    }

    #[test]
    fn get_reads_a_discrete_input_and_input_register_fine() {
        let handle = test_handle();
        assert_eq!(handle.get("PumpA", "Door_Open").unwrap(), "0");
        assert_eq!(handle.get("PumpA", "Flow_Rate").unwrap(), "0");
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
