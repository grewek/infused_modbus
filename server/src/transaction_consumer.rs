// Owns the receiving end of InfusedFilesystem's transaction_sender channel
// on the server side. Unlike the client's transaction_consumer, there's no
// real external device to round-trip with — this process's own
// RegisterStore *is* the state a real Modbus client reads/writes against,
// so applying a drained transaction directly *is* the confirmation
// (contrast with CLAUDE.md's "TRANSACTION_END confirmation semantics",
// which is specifically about the client talking to a real device).
//
// No async/Modbus-protocol involvement here at all, so this is plain
// blocking code — meant to run on its own dedicated OS thread, same as the
// client's version, just without needing a tokio runtime handle.
//
// One consumer thread services every configured machine's writes, reading a
// single shared channel tagged with the originating machine's *name* (see
// fuse-fs's multi-machine `InfusedFilesystem`/`MachineFs::commit_transaction`
// — every send is tagged this way, since that's how a machine identifies
// itself on the FUSE side; `unit_id`, by contrast, is only meaningful for
// wire dispatch in `handler.rs`/`connection.rs`, a completely different
// lookup key from this one).

use fuse_fs::{MachineStores, StagedValue, WriteStatus};
use std::collections::HashMap;
use std::sync::{PoisonError, mpsc};

pub fn run_transaction_consumer(
    machines: &HashMap<String, MachineStores>,
    transaction_receiver: mpsc::Receiver<(String, HashMap<String, StagedValue>)>,
) {
    for (machine_name, transaction) in transaction_receiver {
        let Some(stores) = machines.get(&machine_name) else {
            eprintln!("received a transaction for unknown machine {machine_name:?}, dropping it");
            continue;
        };
        let mut store = stores
            .registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut coil_store = stores.coils.lock().unwrap_or_else(PoisonError::into_inner);
        let mut discrete_input_store = stores
            .discrete_inputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut input_register_store = stores
            .input_registers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut file_record_store = stores
            .file_records
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut report = stores.report.lock().unwrap_or_else(PoisonError::into_inner);
        for (name, value) in transaction {
            match value {
                StagedValue::Register(value) => {
                    store.set(name.clone(), value);
                    report.set(name, WriteStatus::Ok);
                }
                StagedValue::Coil(value) => {
                    coil_store.set(name.clone(), value);
                    report.set(name, WriteStatus::Ok);
                }
                StagedValue::DiscreteInput(value) => {
                    discrete_input_store.set(name.clone(), value);
                    report.set(name, WriteStatus::Ok);
                }
                StagedValue::InputRegister(value) => {
                    input_register_store.set(name.clone(), value);
                    report.set(name, WriteStatus::Ok);
                }
                StagedValue::FileRecord {
                    file_number,
                    record_number,
                    value,
                } => {
                    file_record_store.set(file_number, record_number, value);
                    report.set(name, WriteStatus::Ok);
                }
                // Never actually produced on the server: MASK-format
                // staging only happens inside the transactions/ write path
                // (fuse_fs::filesystem::release), and transactions/ only
                // exists at all in WriteMode::Staged, which the server
                // never runs (see CLAUDE.md's "server direct-write
                // model"). Handled defensively rather than assumed
                // unreachable.
                StagedValue::MaskedRegister { .. } => {
                    report.set(
                        name,
                        WriteStatus::Failed(
                            "mask write staging is client-only, unreachable on the server"
                                .to_string(),
                        ),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_fs::{CoilValue, RegisterValue};

    const TEST_MACHINE_NAME: &str = "TestMachine";

    fn test_machines(stores: MachineStores) -> HashMap<String, MachineStores> {
        let mut machines = HashMap::new();
        machines.insert(TEST_MACHINE_NAME.to_string(), stores);
        machines
    }

    #[test]
    fn applies_a_staged_transaction_directly_and_marks_it_ok() {
        let stores = MachineStores::new();
        let store = stores.registers.clone();
        let report = stores.report.clone();
        let machines = test_machines(stores);
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
        sender
            .send((TEST_MACHINE_NAME.to_string(), transaction))
            .unwrap();
        drop(sender);

        run_transaction_consumer(&machines, receiver);

        assert_eq!(
            store.lock().unwrap().get("Stop_Process"),
            Some(RegisterValue::U16(1))
        );
        assert_eq!(
            report.lock().unwrap().get("Stop_Process"),
            Some(&WriteStatus::Ok)
        );
    }

    #[test]
    fn applies_f32_values_too_since_no_wire_encoding_is_involved_locally() {
        let stores = MachineStores::new();
        let store = stores.registers.clone();
        let machines = test_machines(stores);
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Flow_Rate".to_string(),
            StagedValue::Register(RegisterValue::F32(3.5)),
        );
        sender
            .send((TEST_MACHINE_NAME.to_string(), transaction))
            .unwrap();
        drop(sender);

        run_transaction_consumer(&machines, receiver);

        assert_eq!(
            store.lock().unwrap().get("Flow_Rate"),
            Some(RegisterValue::F32(3.5))
        );
    }

    #[test]
    fn applies_a_staged_coil_directly_and_marks_it_ok() {
        let stores = MachineStores::new();
        let coil_store = stores.coils.clone();
        let report = stores.report.clone();
        let machines = test_machines(stores);
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Motor_Running".to_string(),
            StagedValue::Coil(CoilValue(true)),
        );
        sender
            .send((TEST_MACHINE_NAME.to_string(), transaction))
            .unwrap();
        drop(sender);

        run_transaction_consumer(&machines, receiver);

        assert_eq!(
            coil_store.lock().unwrap().get("Motor_Running"),
            Some(CoilValue(true))
        );
        assert_eq!(
            report.lock().unwrap().get("Motor_Running"),
            Some(&WriteStatus::Ok)
        );
    }

    #[test]
    fn applies_a_staged_discrete_input_directly_and_marks_it_ok() {
        let stores = MachineStores::new();
        let discrete_input_store = stores.discrete_inputs.clone();
        let report = stores.report.clone();
        let machines = test_machines(stores);
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Door_Open_Sensor".to_string(),
            StagedValue::DiscreteInput(CoilValue(true)),
        );
        sender
            .send((TEST_MACHINE_NAME.to_string(), transaction))
            .unwrap();
        drop(sender);

        run_transaction_consumer(&machines, receiver);

        assert_eq!(
            discrete_input_store.lock().unwrap().get("Door_Open_Sensor"),
            Some(CoilValue(true))
        );
        assert_eq!(
            report.lock().unwrap().get("Door_Open_Sensor"),
            Some(&WriteStatus::Ok)
        );
    }

    #[test]
    fn applies_a_staged_input_register_directly_and_marks_it_ok() {
        let stores = MachineStores::new();
        let input_register_store = stores.input_registers.clone();
        let report = stores.report.clone();
        let machines = test_machines(stores);
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Flow_Rate".to_string(),
            StagedValue::InputRegister(RegisterValue::F32(3.5)),
        );
        sender
            .send((TEST_MACHINE_NAME.to_string(), transaction))
            .unwrap();
        drop(sender);

        run_transaction_consumer(&machines, receiver);

        assert_eq!(
            input_register_store.lock().unwrap().get("Flow_Rate"),
            Some(RegisterValue::F32(3.5))
        );
        assert_eq!(
            report.lock().unwrap().get("Flow_Rate"),
            Some(&WriteStatus::Ok)
        );
    }

    #[test]
    fn applies_a_staged_file_record_directly_and_marks_it_ok() {
        let stores = MachineStores::new();
        let file_record_store = stores.file_records.clone();
        let report = stores.report.clone();
        let machines = test_machines(stores);
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "4:1".to_string(),
            StagedValue::FileRecord {
                file_number: 4,
                record_number: 1,
                value: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
        );
        sender
            .send((TEST_MACHINE_NAME.to_string(), transaction))
            .unwrap();
        drop(sender);

        run_transaction_consumer(&machines, receiver);

        assert_eq!(
            file_record_store.lock().unwrap().get(4, 1),
            Some(&vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(report.lock().unwrap().get("4:1"), Some(&WriteStatus::Ok));
    }

    #[test]
    fn a_transaction_for_an_unknown_machine_is_dropped_without_affecting_a_real_machine() {
        let stores = MachineStores::new();
        let report = stores.report.clone();
        let machines = test_machines(stores);
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
        // Tagged with a machine name that isn't in `machines` — this must
        // be dropped (logged, not panicked on) rather than misrouted to
        // the one real configured machine, `TEST_MACHINE_NAME`.
        sender
            .send(("GhostMachine".to_string(), transaction))
            .unwrap();
        drop(sender);

        run_transaction_consumer(&machines, receiver);

        assert_eq!(report.lock().unwrap().get("Stop_Process"), None);
    }
}
