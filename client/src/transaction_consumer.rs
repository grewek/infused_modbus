// Owns the receiving end of InfusedFilesystem's transaction_sender channel
// and is where CLAUDE.md's "TRANSACTION_END confirmation semantics" are
// actually fulfilled: for every register in a drained transaction, attempt
// the real write and only then update `store`/`report`. `fuse-fs` itself
// never does this — see the module doc comment on InfusedFilesystem.
//
// The channel is `std::sync::mpsc` (see H2), so receiving is a blocking
// call — this is meant to run on its own dedicated OS thread (not as a
// tokio task), using `handle` to drive the async Modbus write to
// completion one register at a time.
//
// `stream` is shared (behind a tokio::sync::Mutex, not std::sync::Mutex —
// held across the .await inside confirm_write) with whoever else also
// talks to the device (the polling loop, see client/src/polling.rs): a
// generic Modbus device/gateway can't be assumed to accept more than one
// concurrent connection, so every use of the connection — a poll read or a
// confirmed write — takes the lock only for the duration of its own
// request/response, never holds it across unrelated work.

use crate::write_confirmation::confirm_write;
use fuse_fs::{RegisterStore, RegisterValue, WriteReport, WriteStatus};
use protocol::device_description::RegisterDescription;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Handle;
use tokio::sync::Mutex as AsyncMutex;

#[allow(clippy::too_many_arguments)]
pub fn run_transaction_consumer<S>(
    handle: &Handle,
    stream: &Arc<AsyncMutex<S>>,
    registers: &[RegisterDescription],
    store: &Arc<Mutex<RegisterStore>>,
    report: &Arc<Mutex<WriteReport>>,
    transaction_receiver: mpsc::Receiver<HashMap<String, RegisterValue>>,
    unit_id: u8,
    timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut next_transaction_id: u16 = 0;
    for transaction in transaction_receiver {
        for (name, value) in transaction {
            let status = match registers.iter().find(|register| register.name == name) {
                Some(register) => {
                    next_transaction_id = next_transaction_id.wrapping_add(1);
                    handle.block_on(async {
                        let mut stream = stream.lock().await;
                        confirm_write(
                            &mut *stream,
                            register,
                            value,
                            unit_id,
                            next_transaction_id,
                            timeout,
                        )
                        .await
                    })
                }
                None => WriteStatus::Failed(format!("unknown register: {name}")),
            };

            if status == WriteStatus::Ok {
                store.lock().unwrap().set(name.clone(), value);
            }
            report.lock().unwrap().set(name, status);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::device_description::{AccessRight, DataType};

    fn u16_register() -> RegisterDescription {
        RegisterDescription {
            name: "Stop_Process".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadWrite,
        }
    }

    #[tokio::test]
    async fn confirms_a_write_and_updates_store_and_report() {
        let (client, mut device) = tokio::io::duplex(1024);
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let mut response = header;
            response.extend_from_slice(&pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let handle = Handle::current();
        let stream = Arc::new(AsyncMutex::new(client));
        let consumer_store = Arc::clone(&store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &stream,
                &registers,
                &consumer_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert("Stop_Process".to_string(), RegisterValue::U16(1));
        transaction_sender.send(transaction).unwrap();
        // Dropping the sender closes the channel, so the consumer's
        // `for transaction in transaction_receiver` loop ends once drained.
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(
            store.lock().unwrap().get("Stop_Process"),
            Some(RegisterValue::U16(1))
        );
        assert_eq!(
            report.lock().unwrap().get("Stop_Process"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test]
    async fn a_failed_write_updates_report_but_not_store() {
        let (client, mut device) = tokio::io::duplex(1024);
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let exception = protocol::pdu::ExceptionResponse {
                function_code: 0x06,
                exception_code: 0x02,
            }
            .encode();
            let mut response = header;
            let length = (exception.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&exception);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let handle = Handle::current();
        let stream = Arc::new(AsyncMutex::new(client));
        let consumer_store = Arc::clone(&store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &stream,
                &registers,
                &consumer_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert("Stop_Process".to_string(), RegisterValue::U16(1));
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(store.lock().unwrap().get("Stop_Process"), None);
        assert!(matches!(
            report.lock().unwrap().get("Stop_Process"),
            Some(WriteStatus::Failed(_))
        ));
    }

    #[tokio::test]
    async fn an_unknown_register_is_reported_as_failed_without_sending_anything() {
        let (client, device) = tokio::io::duplex(1024);
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];

        let handle = Handle::current();
        let stream = Arc::new(AsyncMutex::new(client));
        let consumer_store = Arc::clone(&store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &stream,
                &registers,
                &consumer_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert("Unknown_Register".to_string(), RegisterValue::U16(1));
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        consumer_thread.join().unwrap();

        assert!(matches!(
            report.lock().unwrap().get("Unknown_Register"),
            Some(WriteStatus::Failed(_))
        ));

        // Nothing was ever sent to the "device" — dropping it without a
        // pending read (which would panic on EOF) confirms that.
        drop(device);
    }
}
