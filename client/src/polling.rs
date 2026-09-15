// Keeps `holding-registers/` fresh by periodically reading the real
// device — independent of, and sharing the connection with, the
// transaction write-confirmation path (see transaction_consumer.rs).
//
// A read is its own confirmation: unlike a write, there's no separate
// "did this actually happen" step — whatever the device reports in the
// response IS the current value, so `poll_once` updates `store` directly.
//
// Scope, matching write_confirmation.rs's boundary: only U16 registers are
// polled. F32 would need the same two-register word-order decision that's
// deferred on the write side — reading has the identical problem, so it's
// deferred here too rather than guessing.
//
// Traffic is reduced by batching contiguous register addresses into a
// single Read Holding Registers request instead of one request per
// register (see build_read_batches), plus the caller-supplied poll
// interval — real push/pub-sub from the device isn't possible with
// standard Modbus (the master always has to initiate), so this is as
// close to "efficient" as the protocol allows.

use crate::connection::Connection;
use fuse_fs::{RegisterStore, RegisterValue};
use protocol::device_description::{DataType, RegisterDescription};
use protocol::pdu::{ReadHoldingRegistersRequest, ReadHoldingRegistersResponse};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

// Modbus's own limit on how many registers one Read Holding Registers
// request may ask for (function code 0x03).
const MAX_READ_BATCH_SIZE: u16 = 125;

#[derive(Debug, Clone, PartialEq)]
pub struct RegisterBatch {
    pub starting_address: u16,
    pub registers: Vec<RegisterDescription>,
}

impl RegisterBatch {
    pub fn quantity(&self) -> u16 {
        self.registers.len() as u16
    }
}

/// Groups `registers` (U16 only — see module doc comment) into the fewest
/// Read Holding Registers requests needed to cover them all: registers at
/// consecutive addresses share one batch, capped at Modbus's 125-register
/// limit per request; any gap in the address range starts a new batch
/// rather than reading (and discarding) addresses nothing here describes.
pub fn build_read_batches(registers: &[RegisterDescription]) -> Vec<RegisterBatch> {
    let mut sorted: Vec<&RegisterDescription> = registers
        .iter()
        .filter(|register| register.data_type == DataType::U16)
        .collect();
    sorted.sort_by_key(|register| register.address);

    let mut batches: Vec<RegisterBatch> = Vec::new();
    for register in sorted {
        let extends_last_batch = match batches.last() {
            Some(batch) => {
                let expected_next_address = batch.starting_address.wrapping_add(batch.quantity());
                register.address == expected_next_address && batch.quantity() < MAX_READ_BATCH_SIZE
            }
            None => false,
        };
        if extends_last_batch {
            batches.last_mut().unwrap().registers.push(register.clone());
        } else {
            batches.push(RegisterBatch {
                starting_address: register.address,
                registers: vec![register.clone()],
            });
        }
    }
    batches
}

/// Reads every batch once and applies successful results directly to
/// `store`. A failed batch (I/O error, timeout, Modbus exception, or a
/// malformed/short response) is logged and skipped — it'll be retried on
/// the next poll tick rather than treated as fatal.
pub async fn poll_once(
    connection: &Arc<AsyncMutex<Connection>>,
    batches: &[RegisterBatch],
    store: &Arc<Mutex<RegisterStore>>,
    unit_id: u8,
    timeout: Duration,
) {
    for batch in batches {
        let request_pdu = ReadHoldingRegistersRequest {
            starting_address: batch.starting_address,
            quantity: batch.quantity(),
        }
        .encode();

        let result = {
            let mut connection = connection.lock().await;
            connection.request(unit_id, request_pdu, timeout).await
        };

        let response_pdu = match result {
            Ok(response_pdu) => response_pdu,
            Err(error) => {
                eprintln!(
                    "poll: read of {} register(s) at {} failed: {error}",
                    batch.quantity(),
                    batch.starting_address
                );
                continue;
            }
        };

        match ReadHoldingRegistersResponse::decode(&response_pdu) {
            Ok(decoded) if decoded.register_values.len() == batch.registers.len() => {
                let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
                for (register, value) in batch.registers.iter().zip(decoded.register_values) {
                    store.set(register.name.clone(), RegisterValue::U16(value));
                }
            }
            Ok(_) | Err(_) => {
                eprintln!(
                    "poll: unexpected response reading {} register(s) at {}: {:02X?}",
                    batch.quantity(),
                    batch.starting_address,
                    response_pdu
                );
            }
        }
    }
}

/// Polls every batch on a fixed interval, forever — meant to run as its
/// own tokio task alongside the transaction consumer, sharing the same
/// connection (`stream`).
pub async fn run_polling_loop(
    connection: Arc<AsyncMutex<Connection>>,
    registers: &[RegisterDescription],
    store: Arc<Mutex<RegisterStore>>,
    unit_id: u8,
    poll_interval: Duration,
    timeout: Duration,
) {
    let batches = build_read_batches(registers);
    let mut ticker = tokio::time::interval(poll_interval);
    loop {
        ticker.tick().await;
        poll_once(&connection, &batches, &store, unit_id, timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::device_description::AccessRight;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn register(name: &str, address: u16, data_type: DataType) -> RegisterDescription {
        RegisterDescription {
            name: name.to_string(),
            address,
            data_type,
            access: AccessRight::ReadOnly,
        }
    }

    #[test]
    fn contiguous_registers_are_grouped_into_one_batch() {
        let registers = vec![
            register("A", 40001, DataType::U16),
            register("B", 40002, DataType::U16),
            register("C", 40003, DataType::U16),
        ];
        let batches = build_read_batches(&registers);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].starting_address, 40001);
        assert_eq!(batches[0].quantity(), 3);
    }

    #[test]
    fn a_gap_in_addresses_starts_a_new_batch() {
        let registers = vec![
            register("A", 40001, DataType::U16),
            register("B", 40010, DataType::U16),
        ];
        let batches = build_read_batches(&registers);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].starting_address, 40001);
        assert_eq!(batches[1].starting_address, 40010);
    }

    #[test]
    fn f32_registers_are_excluded_entirely() {
        let registers = vec![
            register("A", 40001, DataType::U16),
            register("B", 40002, DataType::F32),
        ];
        let batches = build_read_batches(&registers);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].registers.len(), 1);
        assert_eq!(batches[0].registers[0].name, "A");
    }

    #[test]
    fn registers_are_grouped_regardless_of_input_order() {
        let registers = vec![
            register("B", 40002, DataType::U16),
            register("A", 40001, DataType::U16),
        ];
        let batches = build_read_batches(&registers);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].starting_address, 40001);
        assert_eq!(
            batches[0]
                .registers
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["A", "B"]
        );
    }

    #[test]
    fn a_batch_never_exceeds_the_modbus_read_limit() {
        let registers: Vec<RegisterDescription> = (0..130)
            .map(|offset| register(&format!("R{offset}"), 40001 + offset as u16, DataType::U16))
            .collect();
        let batches = build_read_batches(&registers);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].quantity(), 125);
        assert_eq!(batches[1].quantity(), 5);
    }

    async fn connected_pair() -> (Connection, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let connection = Connection::connect_tcp(&address).await.unwrap();
        let (device, _peer) = listener.accept().await.unwrap();
        (connection, device)
    }

    #[tokio::test]
    async fn poll_once_applies_a_successful_batch_to_the_store() {
        let (connection, mut device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let batches = build_read_batches(&[
            register("A", 40001, DataType::U16),
            register("B", 40002, DataType::U16),
        ]);

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            device.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            device.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadHoldingRegistersResponse {
                register_values: vec![11, 22],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            device.write_all(&response).await.unwrap();
        });

        poll_once(&connection, &batches, &store, 0x01, Duration::from_secs(1)).await;

        device_task.await.unwrap();
        assert_eq!(store.lock().unwrap().get("A"), Some(RegisterValue::U16(11)));
        assert_eq!(store.lock().unwrap().get("B"), Some(RegisterValue::U16(22)));
    }

    #[tokio::test]
    async fn poll_once_leaves_the_store_untouched_when_the_device_times_out() {
        let (connection, _device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let batches = build_read_batches(&[register("A", 40001, DataType::U16)]);

        poll_once(
            &connection,
            &batches,
            &store,
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert_eq!(store.lock().unwrap().get("A"), None);
    }
}
