// Owns the receiving end of InfusedFilesystem's transaction_sender channel
// and is where CLAUDE.md's "TRANSACTION_END confirmation semantics" are
// actually fulfilled: for every register/coil in a drained transaction,
// attempt the real write and update `report` with the outcome. `fuse-fs`
// itself never does this — see the module doc comment on
// InfusedFilesystem.
//
// Deliberately does *not* update `store`/`coil_store` itself on a
// confirmed write, even though it has the just-written value in hand —
// `client::polling` is the only writer of those stores (confirmed with the
// project owner 2026-09-16, after finding a real race: the shared
// connection only serializes requests on the wire, not the store-update
// step after each one, so a poll response already in flight before a
// commit could still land *after* it and overwrite the freshly-confirmed
// value with a stale one). Keeping exactly one writer removes that race
// entirely. The tradeoff: `holding-registers/<name>` can lag up to one
// poll interval behind `report/<name>` showing `OK` — accepted as simpler
// than either a full or a targeted re-poll-on-commit, both of which would
// add traffic and connection contention for a race that a single-writer
// design avoids for free.
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
// idea as `client::polling`'s read batching, just for writes. A register
// batch whose total wire-word quantity is exactly 1 (a single U8/I8/U16/I16
// register, alone) still goes out as a Write Single Register request
// rather than a one-word Write Multiple one — both because Write Single is
// the only function code that can carry a lone value narrower than a full
// batch, and to keep behaving the same as before batching existed for the
// (overwhelmingly common) single-value-transaction case. Anything wider
// than one register (U24 and up) can never go through Write Single at
// all — see write_confirmation.rs's own note on that. Modbus gives no
// finer-grained outcome than "the whole batched request succeeded or
// failed" — there is no way to know which specific register/coil within a
// failed batch caused the rejection — so every name in a failed batch is
// reported `Failed` alike (confirmed with the project owner rather than
// guessed at).

use crate::batching::{Batch, build_batches};
use crate::connection::Connection;
use crate::write_confirmation::{
    confirm_coil_write, confirm_coil_write_multiple, confirm_file_record_write, confirm_mask_write,
    confirm_write, confirm_write_multiple,
};
use fuse_fs::register_encoding::register_value_to_words;
use fuse_fs::{CoilValue, RegisterValue, StagedValue, WriteReport, WriteStatus};
use protocol::device_description::{
    CoilDescription, FileRecordDescription, MemLayout, RegisterDescription,
};
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

type RegisterWriteBatch = Batch<(RegisterDescription, RegisterValue)>;
type CoilWriteBatch = Batch<(CoilDescription, bool)>;

/// Groups staged (register, value) pairs by contiguous address — see
/// `crate::batching` for the grouping algorithm itself, shared with
/// `client::polling`'s read batching. Each entry counts as its own
/// `DataType::register_count()` wire words, same as the read side.
fn build_register_write_batches(
    entries: Vec<(RegisterDescription, RegisterValue)>,
) -> Vec<RegisterWriteBatch> {
    build_batches(
        entries,
        |(register, _)| register.address,
        |(register, _)| register.data_type.register_count(),
        MAX_REGISTER_WRITE_BATCH_SIZE,
    )
}

/// Coil counterpart of `build_register_write_batches`.
fn build_coil_write_batches(entries: Vec<(CoilDescription, bool)>) -> Vec<CoilWriteBatch> {
    build_batches(
        entries,
        |(coil, _)| coil.address,
        |_| 1,
        MAX_COIL_WRITE_BATCH_SIZE,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_transaction_consumer(
    handle: &Handle,
    connection: &Arc<AsyncMutex<Connection>>,
    registers: &[RegisterDescription],
    coils: &[CoilDescription],
    file_records: &[FileRecordDescription],
    report: &Arc<Mutex<WriteReport>>,
    mem_layout: MemLayout,
    transaction_receiver: mpsc::Receiver<HashMap<String, StagedValue>>,
    unit_id: u8,
    timeout: Duration,
) {
    for transaction in transaction_receiver {
        let mut register_entries: Vec<(RegisterDescription, RegisterValue)> = Vec::new();
        let mut coil_entries: Vec<(CoilDescription, bool)> = Vec::new();
        let mut masked_register_entries: Vec<(RegisterDescription, u16, u16)> = Vec::new();
        let mut file_record_entries: Vec<(String, u16, u16, Vec<u8>)> = Vec::new();

        // Resolve every staged name against the known registers/coils
        // first, reporting anything unknown or mismatched immediately —
        // only what's left gets batched below. A type mismatch shouldn't
        // actually happen (fuse_fs always stages a value parsed against
        // the register's own declared type), but is worth checking rather
        // than assuming.
        for (name, value) in transaction {
            match value {
                StagedValue::Register(value) => {
                    match registers.iter().find(|register| register.name == name) {
                        Some(register) if register.data_type == value.data_type() => {
                            register_entries.push((register.clone(), value));
                        }
                        Some(register) => {
                            let reason = format!(
                                "register {name}: expected a {:?} value but got a {:?} one",
                                register.data_type,
                                value.data_type()
                            );
                            report
                                .lock()
                                .unwrap()
                                .set(name, WriteStatus::Failed(reason));
                        }
                        None => {
                            let reason = format!("unknown register: {name}");
                            report
                                .lock()
                                .unwrap()
                                .set(name, WriteStatus::Failed(reason));
                        }
                    }
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
                // Never actually produced on the client — fuse-fs only
                // constructs these from its server-only direct-write path
                // (WriteMode::Direct), and the client always runs
                // WriteMode::Staged. Handled defensively rather than
                // assumed unreachable: no Modbus function code lets a
                // master write either kind at all, so there's nothing to
                // even attempt.
                StagedValue::DiscreteInput(_) => {
                    let reason = format!("discrete input {name}: never writable via Modbus");
                    report
                        .lock()
                        .unwrap()
                        .set(name, WriteStatus::Failed(reason));
                }
                StagedValue::InputRegister(_) => {
                    let reason = format!("input register {name}: never writable via Modbus");
                    report
                        .lock()
                        .unwrap()
                        .set(name, WriteStatus::Failed(reason));
                }
                // Unlike DiscreteInput/InputRegister above, this one *is*
                // real on the client — FC 0x15 (Write File Record) is the
                // whole point of exposing file records here at all (a
                // technician pushing data into a real device's file/record
                // slot), unlike FC17 where the client already had every
                // equivalent tool. Resolved against the known
                // `file_records` the same way registers/coils are above;
                // sent individually below (`file_record_entries`), never
                // batched — same reasoning as `masked_register_entries`,
                // Modbus has no "write multiple file records" function
                // code.
                StagedValue::FileRecord {
                    file_number,
                    record_number,
                    value,
                } => match file_records.iter().find(|description| {
                    description.file_number == file_number
                        && description.record_number == record_number
                }) {
                    Some(description) if value.len() == description.record_length as usize * 2 => {
                        file_record_entries.push((name, file_number, record_number, value));
                    }
                    Some(description) => {
                        let reason = format!(
                            "file record {file_number}:{record_number}: expected {} bytes but got {}",
                            description.record_length as usize * 2,
                            value.len()
                        );
                        report
                            .lock()
                            .unwrap()
                            .set(name, WriteStatus::Failed(reason));
                    }
                    None => {
                        let reason = format!("unknown file record: {file_number}:{record_number}");
                        report
                            .lock()
                            .unwrap()
                            .set(name, WriteStatus::Failed(reason));
                    }
                },
                // Collected separately from register_entries, not batched:
                // Mask Write Register (FC 0x16) has no "multiple" variant,
                // so each masked write always goes out as its own request
                // (see confirm_mask_write's doc comment).
                StagedValue::MaskedRegister { and_mask, or_mask } => {
                    match registers.iter().find(|register| register.name == name) {
                        Some(register) if register.data_type.register_count() == 1 => {
                            masked_register_entries.push((register.clone(), and_mask, or_mask));
                        }
                        Some(register) => {
                            let reason = format!(
                                "register {name}: {:?} needs {} registers, Mask Write Register can only target a single register",
                                register.data_type,
                                register.data_type.register_count()
                            );
                            report
                                .lock()
                                .unwrap()
                                .set(name, WriteStatus::Failed(reason));
                        }
                        None => {
                            let reason = format!("unknown register: {name}");
                            report
                                .lock()
                                .unwrap()
                                .set(name, WriteStatus::Failed(reason));
                        }
                    }
                }
            }
        }

        for batch in build_register_write_batches(register_entries) {
            // A batch that's exactly one wire word wide is always a
            // single one-register-wide value (U8/I8/U16/I16) — anything
            // wider, or more than one register batched together, has to
            // go through Write Multiple Registers instead (see the module
            // doc comment).
            let status = if batch.quantity() == 1 {
                let (register, value) = &batch.items[0];
                handle.block_on(async {
                    let mut connection = connection.lock().await;
                    confirm_write(
                        &mut connection,
                        register,
                        *value,
                        mem_layout,
                        unit_id,
                        timeout,
                    )
                    .await
                })
            } else {
                let values: Vec<u16> = batch
                    .items
                    .iter()
                    .flat_map(|(_, value)| register_value_to_words(*value, mem_layout))
                    .collect();
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

            for (register, _value) in &batch.items {
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

            for (coil, _value) in &batch.items {
                report
                    .lock()
                    .unwrap()
                    .set(coil.name.clone(), status.clone());
            }
        }

        for (register, and_mask, or_mask) in masked_register_entries {
            let status = handle.block_on(async {
                let mut connection = connection.lock().await;
                confirm_mask_write(
                    &mut connection,
                    &register,
                    and_mask,
                    or_mask,
                    unit_id,
                    timeout,
                )
                .await
            });
            report.lock().unwrap().set(register.name.clone(), status);
        }

        // Deliberately does not touch a local FileRecordStore on success,
        // same "single writer" discipline already established for
        // registers/coils (see this module's own doc comment): only
        // `client::polling::poll_file_records_once` ever writes the
        // client's mirror, so `file-records/<file>/<record>` can lag up to
        // one poll interval behind `report/<name>` showing `OK` — a
        // confirmed write landing here and a poll response already in
        // flight would otherwise be able to race the same way H2 already
        // ruled out for registers/coils.
        for (name, file_number, record_number, value) in file_record_entries {
            let status = handle.block_on(async {
                let mut connection = connection.lock().await;
                confirm_file_record_write(
                    &mut connection,
                    file_number,
                    record_number,
                    value,
                    unit_id,
                    timeout,
                )
                .await
            });
            report.lock().unwrap().set(name, status);
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

    fn f32_register() -> RegisterDescription {
        RegisterDescription {
            name: "Flow_Rate".to_string(),
            address: 40020,
            data_type: DataType::F32,
            access: AccessRight::ReadWrite,
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
    async fn confirms_a_write_and_updates_report() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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
            report.lock().unwrap().get("Stop_Process"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_write_updates_report_as_failed() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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

        assert!(matches!(
            report.lock().unwrap().get("Stop_Process"),
            Some(WriteStatus::Failed(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_register_is_reported_as_failed_without_sending_anything() {
        let (connection, device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];
        let coils: Vec<CoilDescription> = vec![];

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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
    async fn confirms_a_coil_write_and_updates_report() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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
            report.lock().unwrap().get("Motor_Running"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batches_two_contiguous_registers_into_one_write_multiple_request() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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
            report.lock().unwrap().get("Stop_Process"),
            Some(&WriteStatus::Ok)
        );
        assert_eq!(
            report.lock().unwrap().get("Setpoint"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_register_batch_marks_every_register_in_it_as_failed() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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
            report.lock().unwrap().get("Motor_Running"),
            Some(&WriteStatus::Ok)
        );
        assert_eq!(
            report.lock().unwrap().get("Alarm_Reset"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_coil_batch_marks_every_coil_in_it_as_failed() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
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

        assert!(matches!(
            report.lock().unwrap().get("Motor_Running"),
            Some(WriteStatus::Failed(_))
        ));
        assert!(matches!(
            report.lock().unwrap().get("Alarm_Reset"),
            Some(WriteStatus::Failed(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lone_wide_register_is_written_via_write_multiple_registers_not_write_single() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![f32_register()];
        let coils: Vec<CoilDescription> = vec![];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            // A single F32 register (2 registers wide) alone must still go
            // out as a Write Multiple Registers PDU (10 bytes: function
            // code + address + quantity + byte count + 2 values), not a
            // 5-byte Write Single Register one — if this read_exact reads
            // the wrong length, the test hangs instead of failing cleanly,
            // which is itself proof the wrong function code was used.
            let mut pdu = vec![0u8; 10];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            let response_pdu = protocol::pdu::WriteMultipleRegistersResponse {
                starting_address: 40020,
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
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Flow_Rate".to_string(),
            StagedValue::Register(RegisterValue::F32(3.5)),
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(
            report.lock().unwrap().get("Flow_Rate"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_type_mismatched_register_is_reported_as_failed_without_sending_anything() {
        let (connection, device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        // Stop_Process is declared U16, but the staged value is F32 — this
        // shouldn't happen via real FUSE staging (which always parses
        // against the register's own type), but is checked defensively
        // rather than trusted blindly.
        let registers = vec![u16_register()];
        let coils: Vec<CoilDescription> = vec![];

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::Register(RegisterValue::F32(3.5)),
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        consumer_thread.join().unwrap();

        assert!(matches!(
            report.lock().unwrap().get("Stop_Process"),
            Some(WriteStatus::Failed(_))
        ));

        // Nothing was ever sent to the "device" — dropping it without a
        // pending read (which would panic on EOF) confirms that.
        drop(device);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirms_a_masked_write_and_updates_report() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers = vec![u16_register()];
        let coils: Vec<CoilDescription> = vec![];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            // Mask Write Register request PDU: function code (1) +
            // reference address (2) + and_mask (2) + or_mask (2) = 7 bytes.
            let mut pdu = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            assert_eq!(pdu, vec![0x16, 0x9C, 0x41, 0x00, 0xF2, 0x00, 0x25]);
            let mut response = header;
            response.extend_from_slice(&pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Stop_Process".to_string(),
            StagedValue::MaskedRegister {
                and_mask: 0x00F2,
                or_mask: 0x0025,
            },
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(
            report.lock().unwrap().get("Stop_Process"),
            Some(&WriteStatus::Ok)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_masked_write_of_a_multi_register_type_is_reported_as_failed_without_sending_anything()
     {
        let (connection, device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        // Flow_Rate is F32 (2 registers wide) — Mask Write Register can
        // only ever carry one wire word, so this can never be sent no
        // matter the access rights.
        let registers = vec![f32_register()];
        let coils: Vec<CoilDescription> = vec![];

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Flow_Rate".to_string(),
            StagedValue::MaskedRegister {
                and_mask: 0x00F2,
                or_mask: 0x0025,
            },
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        consumer_thread.join().unwrap();

        assert!(matches!(
            report.lock().unwrap().get("Flow_Rate"),
            Some(WriteStatus::Failed(_))
        ));

        // Nothing was ever sent to the "device" — dropping it without a
        // pending read (which would panic on EOF) confirms that.
        drop(device);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_masked_register_is_reported_as_failed_without_sending_anything() {
        let (connection, device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers: Vec<RegisterDescription> = vec![];
        let coils: Vec<CoilDescription> = vec![];

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &[],
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "Ghost_Register".to_string(),
            StagedValue::MaskedRegister {
                and_mask: 0x00F2,
                or_mask: 0x0025,
            },
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        consumer_thread.join().unwrap();

        assert!(matches!(
            report.lock().unwrap().get("Ghost_Register"),
            Some(WriteStatus::Failed(_))
        ));

        drop(device);
    }

    fn a_file_record() -> FileRecordDescription {
        FileRecordDescription {
            file_number: 4,
            record_number: 1,
            record_length: 2,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirms_a_file_record_write_and_updates_report() {
        let (connection, mut device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers: Vec<RegisterDescription> = vec![];
        let coils: Vec<CoilDescription> = vec![];
        let file_records = vec![a_file_record()];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut header)
                .await
                .unwrap();
            let mut pdu = vec![0u8; 13];
            tokio::io::AsyncReadExt::read_exact(&mut device, &mut pdu)
                .await
                .unwrap();
            assert_eq!(
                pdu,
                vec![
                    0x15, 0x0B, 0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x0D, 0xFE, 0x00, 0x20,
                ]
            );
            let mut response = header;
            response.extend_from_slice(&pdu);
            tokio::io::AsyncWriteExt::write_all(&mut device, &response)
                .await
                .unwrap();
        });

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &file_records,
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "4:1".to_string(),
            StagedValue::FileRecord {
                file_number: 4,
                record_number: 1,
                value: vec![0x0D, 0xFE, 0x00, 0x20],
            },
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        device_task.await.unwrap();
        consumer_thread.join().unwrap();

        assert_eq!(report.lock().unwrap().get("4:1"), Some(&WriteStatus::Ok));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_file_record_is_reported_as_failed_without_sending_anything() {
        let (connection, device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers: Vec<RegisterDescription> = vec![];
        let coils: Vec<CoilDescription> = vec![];
        let file_records = vec![a_file_record()];

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &file_records,
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "999:1".to_string(),
            StagedValue::FileRecord {
                file_number: 999,
                record_number: 1,
                value: vec![0x00, 0x00, 0x00, 0x00],
            },
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        consumer_thread.join().unwrap();

        assert!(matches!(
            report.lock().unwrap().get("999:1"),
            Some(WriteStatus::Failed(_))
        ));

        drop(device);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wrong_length_file_record_is_reported_as_failed_without_sending_anything() {
        let (connection, device) = connected_pair().await;
        let (transaction_sender, transaction_receiver) = mpsc::channel();
        let report = Arc::new(Mutex::new(WriteReport::new()));
        let registers: Vec<RegisterDescription> = vec![];
        let coils: Vec<CoilDescription> = vec![];
        // a_file_record() declares record_length 2 (4 bytes), not 1 (2
        // bytes).
        let file_records = vec![a_file_record()];

        let handle = Handle::current();
        let connection = Arc::new(AsyncMutex::new(connection));
        let consumer_report = Arc::clone(&report);
        let consumer_thread = std::thread::spawn(move || {
            run_transaction_consumer(
                &handle,
                &connection,
                &registers,
                &coils,
                &file_records,
                &consumer_report,
                MemLayout::Abcd,
                transaction_receiver,
                0x01,
                Duration::from_secs(1),
            );
        });

        let mut transaction = HashMap::new();
        transaction.insert(
            "4:1".to_string(),
            StagedValue::FileRecord {
                file_number: 4,
                record_number: 1,
                value: vec![0x00, 0x00],
            },
        );
        transaction_sender.send(transaction).unwrap();
        drop(transaction_sender);

        consumer_thread.join().unwrap();

        assert!(matches!(
            report.lock().unwrap().get("4:1"),
            Some(WriteStatus::Failed(_))
        ));

        drop(device);
    }
}
