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

use fuse_fs::{
    CoilStore, DiscreteInputStore, FileRecordStore, InputRegisterStore, RegisterStore, StagedValue,
    WriteReport, WriteStatus,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, mpsc};

#[allow(clippy::too_many_arguments)]
pub fn run_transaction_consumer(
    store: &Arc<Mutex<RegisterStore>>,
    coil_store: &Arc<Mutex<CoilStore>>,
    discrete_input_store: &Arc<Mutex<DiscreteInputStore>>,
    input_register_store: &Arc<Mutex<InputRegisterStore>>,
    file_record_store: &Arc<Mutex<FileRecordStore>>,
    report: &Arc<Mutex<WriteReport>>,
    transaction_receiver: mpsc::Receiver<HashMap<String, StagedValue>>,
) {
    for transaction in transaction_receiver {
        let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut coil_store = coil_store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut discrete_input_store = discrete_input_store
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut input_register_store = input_register_store
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut file_record_store = file_record_store
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut report = report.lock().unwrap_or_else(PoisonError::into_inner);
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

    #[test]
    fn applies_a_staged_transaction_directly_and_marks_it_ok() {
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(
            &store,
            &coil_store,
            &discrete_input_store,
            &input_register_store,
            &file_record_store,
            &report,
            receiver,
        );

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
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Flow_Rate".to_string(),
            StagedValue::Register(RegisterValue::F32(3.5)),
        );
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(
            &store,
            &coil_store,
            &discrete_input_store,
            &input_register_store,
            &file_record_store,
            &report,
            receiver,
        );

        assert_eq!(
            store.lock().unwrap().get("Flow_Rate"),
            Some(RegisterValue::F32(3.5))
        );
    }

    #[test]
    fn applies_a_staged_coil_directly_and_marks_it_ok() {
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Motor_Running".to_string(),
            StagedValue::Coil(CoilValue(true)),
        );
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(
            &store,
            &coil_store,
            &discrete_input_store,
            &input_register_store,
            &file_record_store,
            &report,
            receiver,
        );

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
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Door_Open_Sensor".to_string(),
            StagedValue::DiscreteInput(CoilValue(true)),
        );
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(
            &store,
            &coil_store,
            &discrete_input_store,
            &input_register_store,
            &file_record_store,
            &report,
            receiver,
        );

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
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert(
            "Flow_Rate".to_string(),
            StagedValue::InputRegister(RegisterValue::F32(3.5)),
        );
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(
            &store,
            &coil_store,
            &discrete_input_store,
            &input_register_store,
            &file_record_store,
            &report,
            receiver,
        );

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
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
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
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(
            &store,
            &coil_store,
            &discrete_input_store,
            &input_register_store,
            &file_record_store,
            &report,
            receiver,
        );

        assert_eq!(
            file_record_store.lock().unwrap().get(4, 1),
            Some(&vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(report.lock().unwrap().get("4:1"), Some(&WriteStatus::Ok));
    }
}
