//! Assigns each Modbus data point (register/coil/discrete-input/input-
//! register/file-record) across every configured machine a Sparkplug B
//! metric alias. Spec requires alias uniqueness across the **whole Edge
//! Node**, not just within one Device — a name like `Motor_Running` can
//! legitimately exist in two different machines (see CLAUDE.md's
//! multi-machine example), so aliases have to be assigned centrally across
//! all machines at once, not independently per machine.

use protocol::device_description::MachineDescription;
use std::collections::HashMap;

/// Same synthetic naming convention already used elsewhere for file records
/// (`transactions/<file_number>:<record_number>`, the channel's own map key)
/// — file records have no `name` field of their own to reuse.
pub fn file_record_metric_name(file_number: u16, record_number: u16) -> String {
    format!("{file_number}:{record_number}")
}

#[derive(Debug, Clone, Default)]
pub struct AliasAllocator {
    aliases: HashMap<(String, String), u64>,
    reverse: HashMap<u64, (String, String)>,
}

impl AliasAllocator {
    /// Builds the allocator once from the full device description. Assigns
    /// aliases in a fixed, deterministic order (machine order, then
    /// registers/coils/discrete_inputs/input_registers/file_records, each in
    /// their own declared order) so building twice from the same
    /// `DeviceDescription` always produces the same aliases.
    pub fn build(machines: &[MachineDescription]) -> Self {
        let mut aliases = HashMap::new();
        let mut next_alias: u64 = 0;

        for machine in machines {
            for register in &machine.registers {
                aliases.insert((machine.name.clone(), register.name.clone()), next_alias);
                next_alias += 1;
            }
            for coil in &machine.coils {
                aliases.insert((machine.name.clone(), coil.name.clone()), next_alias);
                next_alias += 1;
            }
            for discrete_input in &machine.discrete_inputs {
                aliases.insert(
                    (machine.name.clone(), discrete_input.name.clone()),
                    next_alias,
                );
                next_alias += 1;
            }
            for input_register in &machine.input_registers {
                aliases.insert(
                    (machine.name.clone(), input_register.name.clone()),
                    next_alias,
                );
                next_alias += 1;
            }
            for file_record in &machine.file_records {
                let name =
                    file_record_metric_name(file_record.file_number, file_record.record_number);
                aliases.insert((machine.name.clone(), name), next_alias);
                next_alias += 1;
            }
        }

        let reverse = aliases
            .iter()
            .map(|(key, alias)| (*alias, key.clone()))
            .collect();
        Self { aliases, reverse }
    }

    /// Looks up the alias assigned to `metric_name` on `machine_name`. `None`
    /// means that combination was never registered by `build` — a genuine
    /// bug in the caller (looking up a metric that isn't in the
    /// `DeviceDescription` this allocator was built from), not something
    /// expected to happen in normal operation.
    pub fn alias_for(&self, machine_name: &str, metric_name: &str) -> Option<u64> {
        self.aliases
            .get(&(machine_name.to_string(), metric_name.to_string()))
            .copied()
    }

    /// The reverse of `alias_for` — looks up which `(machine_name,
    /// metric_name)` an incoming alias refers to. Needed for M7's DCMD write
    /// path: a real host application's write command identifies its target
    /// metric by alias alone (see `sparkplug::metric::decode_metric`'s
    /// alias-only decoding), so resolving it back to a name this project's
    /// own stores understand requires this direction too, not just the
    /// forward one BIRTH/DATA construction has needed so far.
    pub fn metric_for_alias(&self, alias: u64) -> Option<(&str, &str)> {
        self.reverse
            .get(&alias)
            .map(|(machine_name, metric_name)| (machine_name.as_str(), metric_name.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::device_description::{
        AccessRight, CoilDescription, DataType, DiscreteInputDescription, FileRecordDescription,
        InputRegisterDescription, MemLayout, RegisterDescription,
    };

    fn machine(name: &str, register_name: &str, coil_name: &str) -> MachineDescription {
        MachineDescription {
            name: name.to_string(),
            unit_id: 1,
            registers: vec![RegisterDescription {
                name: register_name.to_string(),
                address: 0,
                data_type: DataType::U16,
                access: AccessRight::ReadOnly,
            }],
            coils: vec![CoilDescription {
                name: coil_name.to_string(),
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

    #[test]
    fn assigns_an_alias_to_every_metric() {
        let machines = vec![machine("PumpA", "Tank_Temperature", "Motor_Running")];
        let allocator = AliasAllocator::build(&machines);

        assert!(allocator.alias_for("PumpA", "Tank_Temperature").is_some());
        assert!(allocator.alias_for("PumpA", "Motor_Running").is_some());
        assert!(allocator.alias_for("PumpA", "Door_Open").is_some());
        assert!(allocator.alias_for("PumpA", "Flow_Rate").is_some());
        assert!(
            allocator
                .alias_for("PumpA", &file_record_metric_name(4, 1))
                .is_some()
        );
    }

    #[test]
    fn every_alias_in_one_machine_is_unique() {
        let machines = vec![machine("PumpA", "Tank_Temperature", "Motor_Running")];
        let allocator = AliasAllocator::build(&machines);

        let aliases = [
            allocator.alias_for("PumpA", "Tank_Temperature").unwrap(),
            allocator.alias_for("PumpA", "Motor_Running").unwrap(),
            allocator.alias_for("PumpA", "Door_Open").unwrap(),
            allocator.alias_for("PumpA", "Flow_Rate").unwrap(),
            allocator
                .alias_for("PumpA", &file_record_metric_name(4, 1))
                .unwrap(),
        ];
        let mut sorted = aliases.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), aliases.len(), "expected all aliases unique");
    }

    #[test]
    fn the_same_metric_name_in_two_machines_gets_different_aliases() {
        let machines = vec![
            machine("PumpA", "Tank_Temperature", "Motor_Running"),
            machine("PumpB", "Other_Register", "Motor_Running"),
        ];
        let allocator = AliasAllocator::build(&machines);

        let alias_a = allocator.alias_for("PumpA", "Motor_Running").unwrap();
        let alias_b = allocator.alias_for("PumpB", "Motor_Running").unwrap();
        assert_ne!(alias_a, alias_b);
    }

    #[test]
    fn unknown_machine_or_metric_name_returns_none() {
        let machines = vec![machine("PumpA", "Tank_Temperature", "Motor_Running")];
        let allocator = AliasAllocator::build(&machines);

        assert_eq!(allocator.alias_for("PumpA", "Nonexistent"), None);
        assert_eq!(allocator.alias_for("Nonexistent", "Motor_Running"), None);
    }

    #[test]
    fn metric_for_alias_is_the_reverse_of_alias_for() {
        let machines = vec![
            machine("PumpA", "Tank_Temperature", "Motor_Running"),
            machine("PumpB", "Other_Register", "Motor_Running"),
        ];
        let allocator = AliasAllocator::build(&machines);

        let alias = allocator.alias_for("PumpB", "Motor_Running").unwrap();
        assert_eq!(
            allocator.metric_for_alias(alias),
            Some(("PumpB", "Motor_Running"))
        );
    }

    #[test]
    fn metric_for_alias_returns_none_for_an_unassigned_alias() {
        let machines = vec![machine("PumpA", "Tank_Temperature", "Motor_Running")];
        let allocator = AliasAllocator::build(&machines);

        assert_eq!(allocator.metric_for_alias(9999), None);
    }

    #[test]
    fn building_twice_from_the_same_description_is_deterministic() {
        let machines = vec![machine("PumpA", "Tank_Temperature", "Motor_Running")];
        let first = AliasAllocator::build(&machines);
        let second = AliasAllocator::build(&machines);

        assert_eq!(
            first.alias_for("PumpA", "Tank_Temperature"),
            second.alias_for("PumpA", "Tank_Temperature")
        );
        assert_eq!(
            first.alias_for("PumpA", "Motor_Running"),
            second.alias_for("PumpA", "Motor_Running")
        );
    }

    #[test]
    fn file_record_metric_name_uses_the_established_colon_separated_synthetic_key() {
        assert_eq!(file_record_metric_name(4, 1), "4:1");
    }
}
