// Owns the receiving end of InfusedFilesystem's transaction_sender channel
// and is where CLAUDE.md's "TRANSACTION_END confirmation semantics" are
// actually fulfilled: for every register/coil in a drained transaction,
// attempt the real write and only then update `store`/`coil_store`/
// `report`. `fuse-fs` itself never does this — see the module doc comment
// on InfusedFilesystem.
//
// The channel is `std::sync::mpsc` (see H2), so receiving is a blocking
// call — this is meant to run on its own dedicated OS thread (not as a
// tokio task), using `handle` to drive each async Modbus write to
// completion.
//
// `connection` is shared (behind a tokio::sync::Mutex, not std::sync::Mutex
// — held across the .await inside confirm_write) with whoever else also
// talks to the device (the polling loop, see client/src/polling.rs): a
// generic Modbus device/gateway can't be assumed to accept more than one
// concurrent connection, so every use — a poll read or a confirmed write —
// takes the lock only for the duration of its own request/response, never
// holds it across unrelated work. `Connection` itself hides whether that's
// actually TCP or RTU underneath.
//
// Staged writes of the same kind (register or coil) whose addresses turn
// out to be contiguous are batched into one Write Multiple Registers/Coils
// request instead of one Write Single request per name — same grouping
// idea as `client::polling`'s read batching, just for writes. A batch of
// exactly one entry still goes out as a Write Single request rather than a
// one-element Write Multiple one, to keep behaving the same as before this
// batching existed for the (overwhelmingly common) single-value-transaction
// case, and for compatibility with devices that don't implement Write
// Multiple. Modbus gives no finer-grained outcome than "the whole batched
// request succeeded or failed" — there is no way to know which specific
// register/coil within a failed batch caused the rejection — so every name
// in a failed batch is reported `Failed` alike (confirmed with the project
// owner rather than guessed at).

use crate::batching::{Batch, build_batches};
use crate::connection::Connection;
use crate::write_confirmation::{
    confirm_coil_write, confirm_coil_write_multiple, confirm_write, confirm_write_multiple,
};
use fuse_fs::{
    CoilStore, CoilValue, RegisterStore, RegisterValue, StagedValue, WriteReport, WriteStatus,
};
use protocol::device_description::{CoilDescription, RegisterDescription};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::Mutex as AsyncMutex;

// Modbus's own limit on how many registers one Write Multiple Registers
// request may carry (function code 0x10) — lower than Read Holding
// Registers' 125, since the request PDU spends bytes on a byte-count field
// the read request doesn't need.
const MAX_REGISTER_WRITE_BATCH_SIZE: u16 = 123;

// Modbus's own limit on how many coils one Write Multiple Coils request
// may carry (function code 0x0F).
const MAX_COIL_WRITE_BATCH_SIZE: u16 = 1968;

type RegisterWriteBatch = Batch<(RegisterDescription, u16)>;
type CoilWriteBatch = Batch<(CoilDescription, bool)>;

/// Groups staged (register, value) pairs by contiguous address — see
/// `crate::batching` for the grouping algorithm itself, shared with
/// `client::polling`'s read batching.
fn build_register_write_batches(
    entries: Vec<(RegisterDescription, u16)>,
) -> Vec<RegisterWriteBatch> {
    build_batches(
        entries,
        |(register, _)| register.address,
        MAX_REGISTER_WRITE_BATCH_SIZE,
    )
}

/// Coil counterpart of `build_register_write_batches`.
fn build_coil_write_batches(entries: Vec<(CoilDescription, bool)>) -> Vec<CoilWriteBatch> {
    build_batches(entries, |(coil, _)| coil.address, MAX_COIL_WRITE_BATCH_SIZE)
}

#[allow(clippy::too_many_arguments)]
pub fn run_transaction_consumer(
    handle: &Handle,
    connection: &Arc<AsyncMutex<Connection>>,
    registers: &[RegisterDescription],
    store: &Arc<Mutex<RegisterStore>>,
    coils: &[CoilDescription],
    coil_store: &Arc<Mutex<CoilStore>>,
    report: &Arc<Mutex<WriteReport>>,
    transaction_receiver: mpsc::Receiver<HashMap<String, StagedValue>>,
    unit_id: u8,
    timeout: Duration,
) {
    for transaction in transaction_receiver {
        let mut register_entries: Vec<(RegisterDescription, u16)> = Vec::new();
        let mut coil_entries: Vec<(CoilDescription, bool)> = Vec::new();

        // Resolve every staged name against the known registers/coils
        // first, reporting anything unknown or not yet writable over the
        // wire (F32) immediately — only what's left gets batched below.
        for (name, value) in transaction {
            match value {
                StagedValue::Register(RegisterValue::U16(value)) => {
                    match registers.iter().find(|register| register.name == name) {
                        Some(register) => register_entries.push((register.clone(), value)),
                        None => {
                            let reason = format!("unknown register: {name}");
                            report
                                .lock()
                                .unwrap()
                                .set(name, WriteStatus::Failed(reason));
                        }
                    }
                }
                StagedValue::Register(RegisterValue::F32(_)) => {
                    report.lock().unwrap().set(
                        name,
                        WriteStatus::Failed(
                            "F32 writes not yet supported (32-bit word order over two registers hasn't been decided)"
                                .to_string(),
                        ),
                    );
                }
                StagedValue::Coil(value) => match coils.iter().find(|coil| coil.name == name) {
                    Some(coil) => coil_entries.push((coil.clone(), value.0)),
                    None => {
                        let reason = format!("unknown coil: {name}");
                        report
                            .lock()
                            .unwrap()
                            .set(name, WriteStatus::Failed(reason));
                    }
                },
            }
        }

        for batch in build_register_write_batches(register_entries) {
            let status = if let [(register, value)] = batch.items.as_slice() {
                handle.block_on(async {
                    let mut connection = connection.lock().await;
                    confirm_write(
                        &mut connection,
                        register,
                        RegisterValue::U16(*value),
                        unit_id,
                        timeout,
                    )
                    .await
                })
            } else {
                let values: Vec<u16> = batch.items.iter().map(|(_, value)| *value).collect();
                handle.block_on(async {
                    let mut connection = connection.lock().await;
                    confirm_write_multiple(
                        &mut connection,
                        batch.starting_address,
                        &values,
                        unit_id,
                        timeout,
                    )
                    .await
                })
            };

            for (register, value) in &batch.items {
                if status == WriteStatus::Ok {
                    store
                        .lock()
                        .unwrap()
                        .set(register.name.clone(), RegisterValue::U16(*value));
                }
                report
                    .lock()
                    .unwrap()
                    .set(register.name.clone(), status.clone());
            }
        }

        for batch in build_coil_write_batches(coil_entries) {
            let status = if let [(coil, value)] = batch.items.as_slice() {
                handle.block_on(async {
                    let mut connection = connection.lock().await;
                    confirm_coil_write(&mut connection, coil, CoilValue(*value), unit_id, timeout)
                        .await
                })
            } else {
                let values: Vec<bool> = batch.items.iter().map(|(_, value)| *value).collect();
                handle.block_on(async {
                    let mut connection = connection.lock().await;
                    confirm_coil_write_multiple(
                        &mut connection,
                        batch.starting_address,
                        &values,
                        unit_id,
                        timeout,
                    )
                    .await
                })
            };

            for (coil, value) in &batch.items {
                if status == WriteStatus::Ok {
                    coil_store
                        .lock()
                        .unwrap()
                        .set(coil.name.clone(), CoilValue(*value));
                }
                report
                    .lock()
                    .unwrap()
                    .set(coil.name.clone(), status.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_fs::{CoilValue, RegisterValue};
    use protocol::device_description::{AccessRight, DataType};

    fn u16_register() -> RegisterDescription {
        RegisterDescription {
            name: "Stop_Process".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadWrite,
        }
    }

    fn second_u16_register() -> RegisterDescription {
        RegisterDescription {
            name: "Setpoint".to_string(),
            address: 40002,
            data_type: DataType::U16,
            access: AccessRight::ReadWrite,
        }
    }

    fn a_coil() -> CoilDescription {
        CoilDescription {
            name: "Motor_Running".to_string(),
            address: 1,
        }
    }

    fn second_coil() -> CoilDescription {
        CoilDescription {
            name: "Alarm_Reset".to_string(),
            address: 2,
        }
    }

    async fn connected_pair() -> (Connection, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let connection = Connection::connect_tcp(&address).await.unwrap();
        let (device, _peer) = listener.accept().await.unwrap();
        (connection, device)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirms_a_write_and_updates_store_and_report() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];
        let coils: Vec<CoilDescription> = vec![];

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
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_write_updates_report_but_not_store() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];
        let coils: Vec<CoilDescription> = vec![];

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
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
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

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_register_is_reported_as_failed_without_sending_anything() {
        let (connection, device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];
        let coils: Vec<CoilDescription> = vec![];

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Unknown_Register".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
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

    #[tokio::test(flavor = "multi_thread")]
    async fn confirms_a_coil_write_and_updates_store_and_report() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers: Vec<RegisterDescription> = vec![];
        let coils = vec![a_coil()];

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
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Motor_Running".to_string(),
            StagedValue::Coil(CoilValue(true)),
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(
            coil_store.lock().unwrap().get("Motor_Running"),
            Some(CoilValue(true))
        );
        assert_eq!(
            report.lock().unwrap().get("Motor_Running"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batches_two_contiguous_registers_into_one_write_multiple_request() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register(), second_u16_register()];
        let coils: Vec<CoilDescription> = vec![];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            // A single Write Multiple Registers request PDU for 2
            // contiguous registers — if this were batched into two
            // separate Write Single Register requests instead, this
            // read_exact (and the second one that never comes) would hang
            // until the test's own timeout kills it.
            let mut pdu = vec![0u8; 10];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let response_pdu = protocol::pdu::WriteMultipleRegistersResponse {
                starting_address: 40001,
                quantity: 2,
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
        transaction.insert(
            "Setpoint".to_string(),
            StagedValue::Register(RegisterValue::U16(2)),
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(
            store.lock().unwrap().get("Stop_Process"),
            Some(RegisterValue::U16(1))
        );
        assert_eq!(
            store.lock().unwrap().get("Setpoint"),
            Some(RegisterValue::U16(2))
        );
        assert_eq!(
            report.lock().unwrap().get("Stop_Process"),
            Some(&WriteStatus::Ok)
        );
        assert_eq!(
            report.lock().unwrap().get("Setpoint"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_register_batch_marks_every_register_in_it_as_failed_and_leaves_the_store_untouched()
     {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register(), second_u16_register()];
        let coils: Vec<CoilDescription> = vec![];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 10];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let exception = protocol::pdu::ExceptionResponse {
                function_code: 0x10,
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
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::U16(1)),
        );
        transaction.insert(
            "Setpoint".to_string(),
            StagedValue::Register(RegisterValue::U16(2)),
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(store.lock().unwrap().get("Stop_Process"), None);
        assert_eq!(store.lock().unwrap().get("Setpoint"), None);
        assert!(matches!(
            report.lock().unwrap().get("Stop_Process"),
            Some(WriteStatus::Failed(_))
        ));
        assert!(matches!(
            report.lock().unwrap().get("Setpoint"),
            Some(WriteStatus::Failed(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batches_two_contiguous_coils_into_one_write_multiple_request() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers: Vec<RegisterDescription> = vec![];
        let coils = vec![a_coil(), second_coil()];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            // A single Write Multiple Coils request PDU for 2 contiguous
            // coils, not two separate Write Single Coil requests.
            let mut pdu = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let response_pdu = protocol::pdu::WriteMultipleCoilsResponse {
                starting_address: 1,
                quantity: 2,
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Motor_Running".to_string(),
            StagedValue::Coil(CoilValue(true)),
        );
        transaction.insert(
            "Alarm_Reset".to_string(),
            StagedValue::Coil(CoilValue(false)),
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(
            coil_store.lock().unwrap().get("Motor_Running"),
            Some(CoilValue(true))
        );
        assert_eq!(
            coil_store.lock().unwrap().get("Alarm_Reset"),
            Some(CoilValue(false))
        );
        assert_eq!(
            report.lock().unwrap().get("Motor_Running"),
            Some(&WriteStatus::Ok)
        );
        assert_eq!(
            report.lock().unwrap().get("Alarm_Reset"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_coil_batch_marks_every_coil_in_it_as_failed_and_leaves_the_store_untouched() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers: Vec<RegisterDescription> = vec![];
        let coils = vec![a_coil(), second_coil()];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let exception = protocol::pdu::ExceptionResponse {
                function_code: 0x0F,
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
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_store = Arc::clone(&store);
        let consumer_coil_store = Arc::clone(&coil_store);
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &consumer_store,
                &coils,
                &consumer_coil_store,
                &consumer_report,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Motor_Running".to_string(),
            StagedValue::Coil(CoilValue(true)),
        );
        transaction.insert(
            "Alarm_Reset".to_string(),
            StagedValue::Coil(CoilValue(false)),
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(coil_store.lock().unwrap().get("Motor_Running"), None);
        assert_eq!(coil_store.lock().unwrap().get("Alarm_Reset"), None);
        assert!(matches!(
            report.lock().unwrap().get("Motor_Running"),
            Some(WriteStatus::Failed(_))
        ));
        assert!(matches!(
            report.lock().unwrap().get("Alarm_Reset"),
            Some(WriteStatus::Failed(_))
        ));
    }
}
