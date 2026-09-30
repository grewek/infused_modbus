//! Translates this project's own Modbus data model (`protocol::
//! device_description`/`datafs` types) into Sparkplug B's data model
//! (`sparkplug::data_type`/`sparkplug::metric_value`). Lives in `client`, not
//! in the `sparkplug` crate — see CLAUDE.md's M2 revision note: `sparkplug`
//! stays a self-contained protocol implementation with no knowledge of
//! Modbus, and this translation is Modbus-specific glue code.

use crate::sparkplug_alias::{AliasAllocator, file_record_metric_name};
use datafs::{
    CoilValue, MachineStores, RegisterValue, StagedValue, default_register_value,
    parse_file_record_name,
};
use protocol::device_description::{DataType as ModbusDataType, MachineDescription};
use sparkplug::data_type::DataType as SparkplugDataType;
use sparkplug::metric::Metric;
use sparkplug::metric_value::MetricValue;
use std::sync::PoisonError;

/// Maps a register's declared Modbus data type onto the closest Sparkplug B
/// `DataType`. `U24`/`I24` have no Sparkplug equivalent (no native 24-bit
/// type) — mapped onto `UInt32`/`Int32`, the same wire width `DataType::
/// register_count()` already gives them, and `RegisterValue::U24`/`I24`
/// already store their value in a `u32`/`i32` internally, so no value-side
/// conversion is needed to match this type choice.
pub fn map_data_type(data_type: ModbusDataType) -> SparkplugDataType {
    match data_type {
        ModbusDataType::U8 => SparkplugDataType::UInt8,
        ModbusDataType::I8 => SparkplugDataType::Int8,
        ModbusDataType::U16 => SparkplugDataType::UInt16,
        ModbusDataType::I16 => SparkplugDataType::Int16,
        ModbusDataType::U24 => SparkplugDataType::UInt32,
        ModbusDataType::I24 => SparkplugDataType::Int32,
        ModbusDataType::U32 => SparkplugDataType::UInt32,
        ModbusDataType::I32 => SparkplugDataType::Int32,
        ModbusDataType::U64 => SparkplugDataType::UInt64,
        ModbusDataType::I64 => SparkplugDataType::Int64,
        ModbusDataType::F32 => SparkplugDataType::Float,
        ModbusDataType::F64 => SparkplugDataType::Double,
    }
}

/// Maps a `RegisterValue` onto the `MetricValue` variant matching its
/// mapped `DataType` (`map_data_type` above) — `Int` for every type up to 32
/// bits, `Long` for 64-bit types, `Float`/`Double` unchanged. Signed values
/// are sign-extended to their natural width, then the bit pattern is reused
/// unchanged as the corresponding unsigned type — the same "widen then
/// bit-reinterpret" convention every Sparkplug B implementation uses for
/// packing a signed value into `int_value`/`long_value`'s `uint32`/`uint64`
/// wire type (e.g. `Int8(-1)` becomes wire `int_value = 0xFFFFFFFF`, encoded
/// as a 5-byte varint — `encode_metric` already zero-extends rather than
/// sign-extends when it turns that `u32` into a varint, so this is the only
/// place sign-extension needs to happen at all).
pub fn map_register_value(value: RegisterValue) -> MetricValue {
    match value {
        RegisterValue::U8(value) => MetricValue::Int(u32::from(value)),
        RegisterValue::I8(value) => MetricValue::Int(value as i32 as u32),
        RegisterValue::U16(value) => MetricValue::Int(u32::from(value)),
        RegisterValue::I16(value) => MetricValue::Int(value as i32 as u32),
        RegisterValue::U24(value) => MetricValue::Int(value),
        RegisterValue::I24(value) => MetricValue::Int(value as u32),
        RegisterValue::U32(value) => MetricValue::Int(value),
        RegisterValue::I32(value) => MetricValue::Int(value as u32),
        RegisterValue::U64(value) => MetricValue::Long(value),
        RegisterValue::I64(value) => MetricValue::Long(value as u64),
        RegisterValue::F32(value) => MetricValue::Float(value),
        RegisterValue::F64(value) => MetricValue::Double(value),
    }
}

/// `CoilValue`/discrete-input values map directly onto `MetricValue::Boolean`
/// — no width/sign concerns, unlike registers.
pub fn map_coil_value(value: CoilValue) -> MetricValue {
    MetricValue::Boolean(value.0)
}

/// Inverts `map_register_value`: given a `MetricValue` received from a
/// `DCMD` write and the target register's declared `data_type`, recovers the
/// original `RegisterValue`. The narrowing back down from `Int`/`Long`'s
/// wide `u32`/`u64` slot is the exact mirror of `map_register_value`'s own
/// "widen then bit-reinterpret" convention: truncating to the narrower
/// type's bit width and reinterpreting as signed reproduces the original
/// value bit-for-bit, since two's complement truncation and sign-extension
/// are inverses of each other. Rejects a `MetricValue` whose shape doesn't
/// match `data_type` at all (e.g. a `Boolean` sent for a `U16` register) —
/// a real host application error, not something to silently coerce.
pub fn metric_value_to_register_value(
    value: &MetricValue,
    data_type: ModbusDataType,
) -> Result<RegisterValue, String> {
    match (data_type, value) {
        (ModbusDataType::U8, MetricValue::Int(raw)) => Ok(RegisterValue::U8(*raw as u8)),
        (ModbusDataType::I8, MetricValue::Int(raw)) => Ok(RegisterValue::I8(*raw as u8 as i8)),
        (ModbusDataType::U16, MetricValue::Int(raw)) => Ok(RegisterValue::U16(*raw as u16)),
        (ModbusDataType::I16, MetricValue::Int(raw)) => Ok(RegisterValue::I16(*raw as u16 as i16)),
        (ModbusDataType::U24, MetricValue::Int(raw)) => Ok(RegisterValue::U24(*raw)),
        (ModbusDataType::I24, MetricValue::Int(raw)) => Ok(RegisterValue::I24(*raw as i32)),
        (ModbusDataType::U32, MetricValue::Int(raw)) => Ok(RegisterValue::U32(*raw)),
        (ModbusDataType::I32, MetricValue::Int(raw)) => Ok(RegisterValue::I32(*raw as i32)),
        (ModbusDataType::U64, MetricValue::Long(raw)) => Ok(RegisterValue::U64(*raw)),
        (ModbusDataType::I64, MetricValue::Long(raw)) => Ok(RegisterValue::I64(*raw as i64)),
        (ModbusDataType::F32, MetricValue::Float(raw)) => Ok(RegisterValue::F32(*raw)),
        (ModbusDataType::F64, MetricValue::Double(raw)) => Ok(RegisterValue::F64(*raw)),
        _ => Err(format!(
            "value shape does not match declared data type {data_type:?}"
        )),
    }
}

/// Resolves an incoming `DCMD` write (a metric name local to one machine,
/// already resolved from its alias by the caller via `AliasAllocator::
/// metric_for_alias`, plus the value it carries) into a `StagedValue` ready
/// to hand to the same `transaction_consumer` infrastructure every other
/// write path already feeds. Mirrors `transactions/`'s own resolution order
/// (registers, then coils, then file records) — discrete inputs/input
/// registers are never writable on the client at all (see CLAUDE.md), so a
/// `DCMD` naming one of those is rejected exactly like every other write
/// path already rejects it, not silently accepted.
pub fn metric_value_to_staged_value(
    machine: &MachineDescription,
    metric_name: &str,
    value: &MetricValue,
) -> Result<StagedValue, String> {
    if let Some(register) = machine.registers.iter().find(|r| r.name == metric_name) {
        return metric_value_to_register_value(value, register.data_type)
            .map(StagedValue::Register);
    }

    if machine.coils.iter().any(|coil| coil.name == metric_name) {
        return match value {
            MetricValue::Boolean(flag) => Ok(StagedValue::Coil(CoilValue(*flag))),
            _ => Err(format!("coil {metric_name} needs a boolean value")),
        };
    }

    if machine
        .discrete_inputs
        .iter()
        .any(|entry| entry.name == metric_name)
        || machine
            .input_registers
            .iter()
            .any(|entry| entry.name == metric_name)
    {
        return Err(format!("{metric_name} is read-only and cannot be written"));
    }

    if let Some((file_number, record_number)) = parse_file_record_name(metric_name) {
        let is_known_file_record = machine
            .file_records
            .iter()
            .any(|entry| entry.file_number == file_number && entry.record_number == record_number);
        if is_known_file_record {
            return match value {
                MetricValue::Bytes(bytes) => Ok(StagedValue::FileRecord {
                    file_number,
                    record_number,
                    value: bytes.clone(),
                }),
                _ => Err(format!("file record {metric_name} needs a bytes value")),
            };
        }
    }

    Err(format!(
        "unknown metric {metric_name} on machine {}",
        machine.name
    ))
}

/// Builds the full metric list for one machine — every register, coil,
/// discrete input, input register, and file record it declares, each with
/// its assigned alias, mapped `DataType`, and current value (or the same
/// typed-zero default `datafs::default_register_value`/an unset `CoilValue`
/// already uses elsewhere for a value that hasn't been polled/written yet).
/// This is the actual metric list a `DBIRTH` for this machine carries.
pub fn build_machine_metrics(
    machine: &MachineDescription,
    stores: &MachineStores,
    aliases: &AliasAllocator,
) -> Vec<Metric> {
    let mut metrics = Vec::new();

    {
        let register_store = stores
            .registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for register in &machine.registers {
            let value = register_store
                .get(&register.name)
                .unwrap_or_else(|| default_register_value(register.data_type));
            metrics.push(Metric {
                name: register.name.clone(),
                alias: aliases.alias_for(&machine.name, &register.name),
                data_type: map_data_type(register.data_type),
                value: map_register_value(value),
            });
        }
    }

    {
        let coil_store = stores.coils.lock().unwrap_or_else(PoisonError::into_inner);
        for coil in &machine.coils {
            let value = coil_store.get(&coil.name).unwrap_or(CoilValue(false));
            metrics.push(Metric {
                name: coil.name.clone(),
                alias: aliases.alias_for(&machine.name, &coil.name),
                data_type: SparkplugDataType::Boolean,
                value: map_coil_value(value),
            });
        }
    }

    {
        let discrete_input_store = stores
            .discrete_inputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for discrete_input in &machine.discrete_inputs {
            let value = discrete_input_store
                .get(&discrete_input.name)
                .unwrap_or(CoilValue(false));
            metrics.push(Metric {
                name: discrete_input.name.clone(),
                alias: aliases.alias_for(&machine.name, &discrete_input.name),
                data_type: SparkplugDataType::Boolean,
                value: map_coil_value(value),
            });
        }
    }

    {
        let input_register_store = stores
            .input_registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for input_register in &machine.input_registers {
            let value = input_register_store
                .get(&input_register.name)
                .unwrap_or_else(|| default_register_value(input_register.data_type));
            metrics.push(Metric {
                name: input_register.name.clone(),
                alias: aliases.alias_for(&machine.name, &input_register.name),
                data_type: map_data_type(input_register.data_type),
                value: map_register_value(value),
            });
        }
    }

    {
        let file_record_store = stores
            .file_records
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for file_record in &machine.file_records {
            let name = file_record_metric_name(file_record.file_number, file_record.record_number);
            let value = file_record_store
                .get(file_record.file_number, file_record.record_number)
                .cloned()
                .unwrap_or_else(|| vec![0u8; 2 * file_record.record_length as usize]);
            metrics.push(Metric {
                name: name.clone(),
                alias: aliases.alias_for(&machine.name, &name),
                data_type: SparkplugDataType::Bytes,
                value: MetricValue::Bytes(value),
            });
        }
    }

    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_unsigned_integer_type() {
        assert_eq!(map_data_type(ModbusDataType::U8), SparkplugDataType::UInt8);
        assert_eq!(
            map_data_type(ModbusDataType::U16),
            SparkplugDataType::UInt16
        );
        assert_eq!(
            map_data_type(ModbusDataType::U32),
            SparkplugDataType::UInt32
        );
        assert_eq!(
            map_data_type(ModbusDataType::U64),
            SparkplugDataType::UInt64
        );
    }

    #[test]
    fn maps_every_signed_integer_type() {
        assert_eq!(map_data_type(ModbusDataType::I8), SparkplugDataType::Int8);
        assert_eq!(map_data_type(ModbusDataType::I16), SparkplugDataType::Int16);
        assert_eq!(map_data_type(ModbusDataType::I32), SparkplugDataType::Int32);
        assert_eq!(map_data_type(ModbusDataType::I64), SparkplugDataType::Int64);
    }

    #[test]
    fn maps_floating_point_types() {
        assert_eq!(map_data_type(ModbusDataType::F32), SparkplugDataType::Float);
        assert_eq!(
            map_data_type(ModbusDataType::F64),
            SparkplugDataType::Double
        );
    }

    #[test]
    fn maps_u24_and_i24_onto_the_32_bit_sparkplug_type() {
        assert_eq!(
            map_data_type(ModbusDataType::U24),
            SparkplugDataType::UInt32
        );
        assert_eq!(map_data_type(ModbusDataType::I24), SparkplugDataType::Int32);
    }

    #[test]
    fn maps_unsigned_register_values_to_int_or_long() {
        assert_eq!(
            map_register_value(RegisterValue::U8(200)),
            MetricValue::Int(200)
        );
        assert_eq!(
            map_register_value(RegisterValue::U16(60_000)),
            MetricValue::Int(60_000)
        );
        assert_eq!(
            map_register_value(RegisterValue::U24(16_000_000)),
            MetricValue::Int(16_000_000)
        );
        assert_eq!(
            map_register_value(RegisterValue::U32(4_000_000_000)),
            MetricValue::Int(4_000_000_000)
        );
        assert_eq!(
            map_register_value(RegisterValue::U64(10_000_000_000)),
            MetricValue::Long(10_000_000_000)
        );
    }

    #[test]
    fn maps_positive_signed_register_values_unchanged() {
        assert_eq!(
            map_register_value(RegisterValue::I8(100)),
            MetricValue::Int(100)
        );
        assert_eq!(
            map_register_value(RegisterValue::I32(123_456)),
            MetricValue::Int(123_456)
        );
        assert_eq!(
            map_register_value(RegisterValue::I64(123_456_789)),
            MetricValue::Long(123_456_789)
        );
    }

    #[test]
    fn maps_negative_signed_register_values_via_sign_extend_then_bit_reinterpret() {
        assert_eq!(
            map_register_value(RegisterValue::I8(-1)),
            MetricValue::Int(0xFFFF_FFFF)
        );
        assert_eq!(
            map_register_value(RegisterValue::I16(-1)),
            MetricValue::Int(0xFFFF_FFFF)
        );
        assert_eq!(
            map_register_value(RegisterValue::I24(-1)),
            MetricValue::Int(0xFFFF_FFFF)
        );
        assert_eq!(
            map_register_value(RegisterValue::I32(-1)),
            MetricValue::Int(0xFFFF_FFFF)
        );
        assert_eq!(
            map_register_value(RegisterValue::I64(-1)),
            MetricValue::Long(0xFFFF_FFFF_FFFF_FFFF)
        );
    }

    #[test]
    fn maps_floating_point_register_values_unchanged() {
        assert_eq!(
            map_register_value(RegisterValue::F32(1.5)),
            MetricValue::Float(1.5)
        );
        assert_eq!(
            map_register_value(RegisterValue::F64(2.5)),
            MetricValue::Double(2.5)
        );
    }

    #[test]
    fn maps_coil_value_to_boolean() {
        assert_eq!(map_coil_value(CoilValue(true)), MetricValue::Boolean(true));
        assert_eq!(
            map_coil_value(CoilValue(false)),
            MetricValue::Boolean(false)
        );
    }

    fn test_machine() -> MachineDescription {
        use protocol::device_description::{
            AccessRight, CoilDescription, DiscreteInputDescription, FileRecordDescription,
            InputRegisterDescription, MemLayout, RegisterDescription,
        };
        MachineDescription {
            name: "PumpA".to_string(),
            unit_id: 1,
            registers: vec![RegisterDescription {
                name: "Tank_Temperature".to_string(),
                address: 0,
                data_type: ModbusDataType::U16,
                access: AccessRight::ReadOnly,
            }],
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
                data_type: ModbusDataType::F32,
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
    fn builds_one_metric_per_declared_data_point() {
        let machine = test_machine();
        let stores = MachineStores::new();
        let aliases = crate::sparkplug_alias::AliasAllocator::build(std::slice::from_ref(&machine));

        let metrics = build_machine_metrics(&machine, &stores, &aliases);
        assert_eq!(metrics.len(), 5);

        let names: Vec<&str> = metrics.iter().map(|metric| metric.name.as_str()).collect();
        assert!(names.contains(&"Tank_Temperature"));
        assert!(names.contains(&"Motor_Running"));
        assert!(names.contains(&"Door_Open"));
        assert!(names.contains(&"Flow_Rate"));
        assert!(names.contains(&"4:1"));
    }

    #[test]
    fn every_metric_carries_its_allocated_alias() {
        let machine = test_machine();
        let stores = MachineStores::new();
        let aliases = crate::sparkplug_alias::AliasAllocator::build(std::slice::from_ref(&machine));

        let metrics = build_machine_metrics(&machine, &stores, &aliases);
        for metric in &metrics {
            assert_eq!(metric.alias, aliases.alias_for(&machine.name, &metric.name));
            assert!(metric.alias.is_some());
        }
    }

    #[test]
    fn unset_values_render_as_typed_defaults() {
        let machine = test_machine();
        let stores = MachineStores::new();
        let aliases = crate::sparkplug_alias::AliasAllocator::build(std::slice::from_ref(&machine));

        let metrics = build_machine_metrics(&machine, &stores, &aliases);
        let temperature = metrics
            .iter()
            .find(|metric| metric.name == "Tank_Temperature")
            .unwrap();
        assert_eq!(temperature.value, MetricValue::Int(0));

        let motor = metrics
            .iter()
            .find(|metric| metric.name == "Motor_Running")
            .unwrap();
        assert_eq!(motor.value, MetricValue::Boolean(false));

        let file_record = metrics.iter().find(|metric| metric.name == "4:1").unwrap();
        assert_eq!(file_record.value, MetricValue::Bytes(vec![0, 0, 0, 0]));
    }

    #[test]
    fn set_values_are_reflected_instead_of_defaults() {
        let machine = test_machine();
        let stores = MachineStores::new();
        stores
            .registers
            .lock()
            .unwrap()
            .set("Tank_Temperature", RegisterValue::U16(21));
        stores
            .coils
            .lock()
            .unwrap()
            .set("Motor_Running", CoilValue(true));
        stores
            .file_records
            .lock()
            .unwrap()
            .set(4, 1, vec![0x0D, 0xFE, 0x00, 0x20]);
        let aliases = crate::sparkplug_alias::AliasAllocator::build(std::slice::from_ref(&machine));

        let metrics = build_machine_metrics(&machine, &stores, &aliases);
        let temperature = metrics
            .iter()
            .find(|metric| metric.name == "Tank_Temperature")
            .unwrap();
        assert_eq!(temperature.value, MetricValue::Int(21));

        let motor = metrics
            .iter()
            .find(|metric| metric.name == "Motor_Running")
            .unwrap();
        assert_eq!(motor.value, MetricValue::Boolean(true));

        let file_record = metrics.iter().find(|metric| metric.name == "4:1").unwrap();
        assert_eq!(
            file_record.value,
            MetricValue::Bytes(vec![0x0D, 0xFE, 0x00, 0x20])
        );
    }

    #[test]
    fn metric_value_to_register_value_inverts_every_type_round_trip() {
        for (data_type, register_value) in [
            (ModbusDataType::U8, RegisterValue::U8(200)),
            (ModbusDataType::I8, RegisterValue::I8(-1)),
            (ModbusDataType::U16, RegisterValue::U16(60_000)),
            (ModbusDataType::I16, RegisterValue::I16(-1)),
            (ModbusDataType::U24, RegisterValue::U24(16_000_000)),
            (ModbusDataType::I24, RegisterValue::I24(-1)),
            (ModbusDataType::U32, RegisterValue::U32(4_000_000_000)),
            (ModbusDataType::I32, RegisterValue::I32(-1)),
            (ModbusDataType::U64, RegisterValue::U64(10_000_000_000)),
            (ModbusDataType::I64, RegisterValue::I64(-1)),
            (ModbusDataType::F32, RegisterValue::F32(1.5)),
            (ModbusDataType::F64, RegisterValue::F64(2.5)),
        ] {
            let metric_value = map_register_value(register_value);
            assert_eq!(
                metric_value_to_register_value(&metric_value, data_type),
                Ok(register_value)
            );
        }
    }

    #[test]
    fn metric_value_to_register_value_rejects_a_mismatched_shape() {
        assert!(
            metric_value_to_register_value(&MetricValue::Boolean(true), ModbusDataType::U16)
                .is_err()
        );
    }

    #[test]
    fn metric_value_to_staged_value_resolves_a_register_write() {
        let machine = test_machine();
        assert_eq!(
            metric_value_to_staged_value(&machine, "Tank_Temperature", &MetricValue::Int(30)),
            Ok(StagedValue::Register(RegisterValue::U16(30)))
        );
    }

    #[test]
    fn metric_value_to_staged_value_resolves_a_coil_write() {
        let machine = test_machine();
        assert_eq!(
            metric_value_to_staged_value(&machine, "Motor_Running", &MetricValue::Boolean(true)),
            Ok(StagedValue::Coil(CoilValue(true)))
        );
    }

    #[test]
    fn metric_value_to_staged_value_resolves_a_file_record_write() {
        let machine = test_machine();
        assert_eq!(
            metric_value_to_staged_value(&machine, "4:1", &MetricValue::Bytes(vec![1, 2])),
            Ok(StagedValue::FileRecord {
                file_number: 4,
                record_number: 1,
                value: vec![1, 2],
            })
        );
    }

    #[test]
    fn metric_value_to_staged_value_rejects_read_only_metrics() {
        let machine = test_machine();
        assert!(
            metric_value_to_staged_value(&machine, "Door_Open", &MetricValue::Boolean(true))
                .is_err()
        );
        assert!(
            metric_value_to_staged_value(&machine, "Flow_Rate", &MetricValue::Float(1.0)).is_err()
        );
    }

    #[test]
    fn metric_value_to_staged_value_rejects_an_unknown_metric_name() {
        let machine = test_machine();
        assert!(
            metric_value_to_staged_value(&machine, "Nonexistent", &MetricValue::Int(1)).is_err()
        );
    }
}
