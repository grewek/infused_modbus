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

use crate::batching::{Batch, build_batches};
use crate::connection::Connection;
use fuse_fs::{CoilStore, CoilValue, RegisterStore, RegisterValue};
use protocol::device_description::{CoilDescription, DataType, RegisterDescription};
use protocol::pdu::{
    ReadCoilsRequest, ReadCoilsResponse, ReadHoldingRegistersRequest, ReadHoldingRegistersResponse,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

// Modbus's own limit on how many registers one Read Holding Registers
// request may ask for (function code 0x03).
const MAX_READ_BATCH_SIZE: u16 = 125;

// Modbus's own limit on how many coils one Read Coils request may ask for
// (function code 0x01) — much higher than registers since coils are packed
// 8-to-a-byte on the wire instead of 2 bytes each.
const MAX_COIL_READ_BATCH_SIZE: u16 = 2000;

pub type RegisterBatch = Batch<RegisterDescription>;
pub type CoilBatch = Batch<CoilDescription>;

/// Groups `registers` (U16 only — see module doc comment) into the fewest
/// Read Holding Registers requests needed to cover them all — see
/// `crate::batching` for the grouping algorithm itself.
pub fn build_read_batches(registers: &[RegisterDescription]) -> Vec<RegisterBatch> {
    let u16_registers: Vec<RegisterDescription> = registers
        .iter()
        .filter(|register| register.data_type == DataType::U16)
        .cloned()
        .collect();
    build_batches(
        u16_registers,
        |register| register.address,
        MAX_READ_BATCH_SIZE,
    )
}

/// Coil counterpart of `build_read_batches`, capped at Modbus's much
/// higher per-request coil limit instead of the register one.
pub fn build_coil_read_batches(coils: &[CoilDescription]) -> Vec<CoilBatch> {
    build_batches(
        coils.to_vec(),
        |coil| coil.address,
        MAX_COIL_READ_BATCH_SIZE,
    )
}

/// Coil counterpart of `poll_once`: the same "apply successes, log and
/// skip failures" shape. The one real difference is the length check
/// against the decoded response — Read Coils packs bits 8-to-a-byte, so a
/// coil count that isn't a multiple of 8 comes back padded with extra
/// trailing bits (see `ReadCoilsResponse`'s own doc comment), hence `>=`
/// here instead of the exact `==` the register version can use.
pub async fn poll_coils_once(
    connection: &Arc<AsyncMutex<Connection>>,
    batches: &[CoilBatch],
    coil_store: &Arc<Mutex<CoilStore>>,
    unit_id: u8,
    timeout: Duration,
) {
    for batch in batches {
        let request_pdu = ReadCoilsRequest {
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
                    "poll: read of {} coil(s) at {} failed: {error}",
                    batch.quantity(),
                    batch.starting_address
                );
                continue;
            }
        };

        match ReadCoilsResponse::decode(&response_pdu) {
            Ok(decoded) if decoded.coil_values.len() >= batch.items.len() => {
                let mut coil_store = coil_store.lock().unwrap_or_else(PoisonError::into_inner);
                for (coil, value) in batch.items.iter().zip(decoded.coil_values) {
                    coil_store.set(coil.name.clone(), CoilValue(value));
                }
            }
            Ok(_) | Err(_) => {
                eprintln!(
                    "poll: unexpected response reading {} coil(s) at {}: {:02X?}",
                    batch.quantity(),
                    batch.starting_address,
                    response_pdu
                );
            }
        }
    }
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
            Ok(decoded) if decoded.register_values.len() == batch.items.len() => {
                let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
                for (register, value) in batch.items.iter().zip(decoded.register_values) {
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

/// Polls every register and coil batch on a fixed interval, forever —
/// meant to run as its own tokio task alongside the transaction consumer,
/// sharing the same connection (`stream`).
#[allow(clippy::too_many_arguments)]
pub async fn run_polling_loop(
    connection: Arc<AsyncMutex<Connection>>,
    registers: &[RegisterDescription],
    store: Arc<Mutex<RegisterStore>>,
    coils: &[CoilDescription],
    coil_store: Arc<Mutex<CoilStore>>,
    unit_id: u8,
    poll_interval: Duration,
    timeout: Duration,
) {
    let register_batches = build_read_batches(registers);
    let coil_batches = build_coil_read_batches(coils);
    let mut ticker = tokio::time::interval(poll_interval);
    loop {
        ticker.tick().await;
        poll_once(&connection, &register_batches, &store, unit_id, timeout).await;
        poll_coils_once(&connection, &coil_batches, &coil_store, unit_id, timeout).await;
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

    fn coil(name: &str, address: u16) -> CoilDescription {
        CoilDescription {
            name: name.to_string(),
            address,
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
        assert_eq!(batches[0].items.len(), 1);
        assert_eq!(batches[0].items[0].name, "A");
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
                .items
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

    #[test]
    fn contiguous_coils_are_grouped_into_one_batch() {
        let coils = vec![coil("A", 1), coil("B", 2), coil("C", 3)];
        let batches = build_coil_read_batches(&coils);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].starting_address, 1);
        assert_eq!(batches[0].quantity(), 3);
    }

    #[test]
    fn a_gap_in_coil_addresses_starts_a_new_batch() {
        let coils = vec![coil("A", 1), coil("B", 10)];
        let batches = build_coil_read_batches(&coils);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].starting_address, 1);
        assert_eq!(batches[1].starting_address, 10);
    }

    #[test]
    fn a_coil_batch_never_exceeds_the_modbus_read_limit() {
        let coils: Vec<CoilDescription> = (0..2005)
            .map(|offset| coil(&format!("C{offset}"), 1 + offset as u16))
            .collect();
        let batches = build_coil_read_batches(&coils);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].quantity(), 2000);
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

    #[tokio::test]
    async fn poll_coils_once_applies_a_successful_batch_to_the_store() {
        let (connection, mut device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let batches = build_coil_read_batches(&[coil("A", 1), coil("B", 2)]);

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            device.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            device.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadCoilsResponse {
                coil_values: vec![true, false],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            device.write_all(&response).await.unwrap();
        });

        poll_coils_once(
            &connection,
            &batches,
            &coil_store,
            0x01,
            Duration::from_secs(1),
        )
        .await;

        device_task.await.unwrap();
        assert_eq!(coil_store.lock().unwrap().get("A"), Some(CoilValue(true)));
        assert_eq!(coil_store.lock().unwrap().get("B"), Some(CoilValue(false)));
    }

    #[tokio::test]
    async fn poll_coils_once_leaves_the_store_untouched_when_the_device_times_out() {
        let (connection, _device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let batches = build_coil_read_batches(&[coil("A", 1)]);

        poll_coils_once(
            &connection,
            &batches,
            &coil_store,
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert_eq!(coil_store.lock().unwrap().get("A"), None);
    }
}
