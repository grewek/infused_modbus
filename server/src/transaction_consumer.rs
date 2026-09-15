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

use fuse_fs::{RegisterStore, RegisterValue, WriteReport, WriteStatus};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, mpsc};

pub fn run_transaction_consumer(
    store: &Arc<Mutex<RegisterStore>>,
    report: &Arc<Mutex<WriteReport>>,
    transaction_receiver: mpsc::Receiver<HashMap<String, RegisterValue>>,
) {
    for transaction in transaction_receiver {
        let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut report = report.lock().unwrap_or_else(PoisonError::into_inner);
        for (name, value) in transaction {
            store.set(name.clone(), value);
            report.set(name, WriteStatus::Ok);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_a_staged_transaction_directly_and_marks_it_ok() {
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert("Stop_Process".to_string(), RegisterValue::U16(1));
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(&store, &report, receiver);

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
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let (sender, receiver) = mpsc::channel();

        let mut transaction = HashMap::new();
        transaction.insert("Flow_Rate".to_string(), RegisterValue::F32(3.5));
        sender.send(transaction).unwrap();
        drop(sender);

        run_transaction_consumer(&store, &report, receiver);

        assert_eq!(
            store.lock().unwrap().get("Flow_Rate"),
            Some(RegisterValue::F32(3.5))
        );
    }
}
