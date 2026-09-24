// Keeps `holding-registers/` fresh by periodically reading the real
// device — independent of, and sharing the connection with, the
// transaction write-confirmation path (see transaction_consumer.rs).
//
// A read is its own confirmation: unlike a write, there's no separate
// "did this actually happen" step — whatever the device reports in the
// response IS the current value, so `poll_once` updates `store` directly.
//
// Every DataType is polled — a register batch's `quantity()` is the sum of
// each register's own `DataType::register_count()` wire-word width (see
// `crate::batching`), not just how many registers are in the batch, and
// `poll_once` walks the decoded response the same number of words at a
// time per register, reassembling each one via
// `fuse_fs::register_encoding::register_value_from_words` (which needs the
// device's `mem_layout` for anything wider than one register).
//
// Traffic is reduced by batching contiguous register addresses into a
// single Read Holding Registers request instead of one request per
// register (see build_read_batches), plus the caller-supplied poll
// interval — real push/pub-sub from the device isn't possible with
// standard Modbus (the master always has to initiate), so this is as
// close to "efficient" as the protocol allows.

use crate::batching::{Batch, build_batches};
use crate::connection::Connection;
use fuse_fs::register_encoding::register_value_from_words;
use fuse_fs::{
    CoilStore, CoilValue, DiscreteInputStore, FileRecordStore, InputRegisterStore, RegisterStore,
};
use protocol::device_description::{
    CoilDescription, DiscreteInputDescription, FileRecordDescription, InputRegisterDescription,
    MemLayout, RegisterDescription,
};
use protocol::pdu::{
    FileRecordSubRequest, ReadCoilsRequest, ReadCoilsResponse, ReadDiscreteInputsRequest,
    ReadDiscreteInputsResponse, ReadFileRecordRequest, ReadFileRecordResponse,
    ReadHoldingRegistersRequest, ReadHoldingRegistersResponse, ReadInputRegistersRequest,
    ReadInputRegistersResponse,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

// Modbus's own limit on how many registers one Read Holding Registers
// (0x03) or Read Input Registers (0x04) request may ask for — the same
// wire constraint applies identically to both function codes.
const MAX_READ_BATCH_SIZE: u16 = 125;

// Modbus's own limit on how many bits one Read Coils (0x01) or Read
// Discrete Inputs (0x02) request may ask for — much higher than registers
// since both pack values 8-to-a-byte on the wire instead of 2 bytes each,
// and the limit is identical for both function codes (same packed-bit
// response shape).
const MAX_PACKED_BIT_READ_BATCH_SIZE: u16 = 2000;

pub type RegisterBatch = Batch<RegisterDescription>;
pub type CoilBatch = Batch<CoilDescription>;
pub type DiscreteInputBatch = Batch<DiscreteInputDescription>;
pub type InputRegisterBatch = Batch<InputRegisterDescription>;

/// Groups `registers` into the fewest Read Holding Registers requests
/// needed to cover them all, each register counting as its own
/// `DataType::register_count()` wire words — see `crate::batching` for the
/// grouping algorithm itself.
pub fn build_read_batches(registers: &[RegisterDescription]) -> Vec<RegisterBatch> {
    build_batches(
        registers.to_vec(),
        |register| register.address,
        |register| register.data_type.register_count(),
        MAX_READ_BATCH_SIZE,
    )
}

/// Input-register counterpart of `build_read_batches` — same Read Holding
/// Registers wire limit applies to Read Input Registers too.
pub fn build_input_register_read_batches(
    input_registers: &[InputRegisterDescription],
) -> Vec<InputRegisterBatch> {
    build_batches(
        input_registers.to_vec(),
        |input_register| input_register.address,
        |input_register| input_register.data_type.register_count(),
        MAX_READ_BATCH_SIZE,
    )
}

/// Coil counterpart of `build_read_batches`, capped at Modbus's much
/// higher per-request coil limit instead of the register one — every coil
/// is exactly one wire slot, unlike registers.
pub fn build_coil_read_batches(coils: &[CoilDescription]) -> Vec<CoilBatch> {
    build_batches(
        coils.to_vec(),
        |coil| coil.address,
        |_| 1,
        MAX_PACKED_BIT_READ_BATCH_SIZE,
    )
}

/// Discrete-input counterpart of `build_coil_read_batches` — same Read
/// Coils wire limit applies to Read Discrete Inputs too.
pub fn build_discrete_input_read_batches(
    discrete_inputs: &[DiscreteInputDescription],
) -> Vec<DiscreteInputBatch> {
    build_batches(
        discrete_inputs.to_vec(),
        |discrete_input| discrete_input.address,
        |_| 1,
        MAX_PACKED_BIT_READ_BATCH_SIZE,
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

/// Discrete-input counterpart of `poll_coils_once`: identical shape, just
/// backed by DiscreteInputStore and Read Discrete Inputs instead of
/// CoilStore/Read Coils. No write path exists or is planned on the client
/// for these (see CLAUDE.md's "read-only Modbus data types" section) — this
/// is the only way their values ever reach `discrete-inputs/`.
pub async fn poll_discrete_inputs_once(
    connection: &Arc<AsyncMutex<Connection>>,
    batches: &[DiscreteInputBatch],
    discrete_input_store: &Arc<Mutex<DiscreteInputStore>>,
    unit_id: u8,
    timeout: Duration,
) {
    for batch in batches {
        let request_pdu = ReadDiscreteInputsRequest {
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
                    "poll: read of {} discrete input(s) at {} failed: {error}",
                    batch.quantity(),
                    batch.starting_address
                );
                continue;
            }
        };

        match ReadDiscreteInputsResponse::decode(&response_pdu) {
            Ok(decoded) if decoded.discrete_input_values.len() >= batch.items.len() => {
                let mut discrete_input_store = discrete_input_store
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                for (discrete_input, value) in batch.items.iter().zip(decoded.discrete_input_values)
                {
                    discrete_input_store.set(discrete_input.name.clone(), CoilValue(value));
                }
            }
            Ok(_) | Err(_) => {
                eprintln!(
                    "poll: unexpected response reading {} discrete input(s) at {}: {:02X?}",
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
/// the next poll tick rather than treated as fatal. A decoded response is
/// split back into one register's worth of words at a time, in address
/// order, since a batch can now mix registers of different widths.
pub async fn poll_once(
    connection: &Arc<AsyncMutex<Connection>>,
    batches: &[RegisterBatch],
    store: &Arc<Mutex<RegisterStore>>,
    mem_layout: MemLayout,
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
            Ok(decoded) if decoded.register_values.len() == batch.quantity() as usize => {
                let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
                let mut offset = 0usize;
                for register in &batch.items {
                    let register_count = register.data_type.register_count() as usize;
                    let words = &decoded.register_values[offset..offset + register_count];
                    if let Some(value) =
                        register_value_from_words(register.data_type, words, mem_layout)
                    {
                        store.set(register.name.clone(), value);
                    }
                    offset += register_count;
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

/// Input-register counterpart of `poll_once`: identical shape, just backed
/// by InputRegisterStore, Read Input Registers, and its own mem_layout
/// instead of RegisterStore/Read Holding Registers/the holding-register
/// mem_layout. No write path exists or is planned on the client for these,
/// same reasoning as `poll_discrete_inputs_once`.
pub async fn poll_input_registers_once(
    connection: &Arc<AsyncMutex<Connection>>,
    batches: &[InputRegisterBatch],
    input_register_store: &Arc<Mutex<InputRegisterStore>>,
    input_register_mem_layout: MemLayout,
    unit_id: u8,
    timeout: Duration,
) {
    for batch in batches {
        let request_pdu = ReadInputRegistersRequest {
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
                    "poll: read of {} input register(s) at {} failed: {error}",
                    batch.quantity(),
                    batch.starting_address
                );
                continue;
            }
        };

        match ReadInputRegistersResponse::decode(&response_pdu) {
            Ok(decoded) if decoded.register_values.len() == batch.quantity() as usize => {
                let mut input_register_store = input_register_store
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let mut offset = 0usize;
                for input_register in &batch.items {
                    let register_count = input_register.data_type.register_count() as usize;
                    let words = &decoded.register_values[offset..offset + register_count];
                    if let Some(value) = register_value_from_words(
                        input_register.data_type,
                        words,
                        input_register_mem_layout,
                    ) {
                        input_register_store.set(input_register.name.clone(), value);
                    }
                    offset += register_count;
                }
            }
            Ok(_) | Err(_) => {
                eprintln!(
                    "poll: unexpected response reading {} input register(s) at {}: {:02X?}",
                    batch.quantity(),
                    batch.starting_address,
                    response_pdu
                );
            }
        }
    }
}

/// File-record counterpart of the other `poll_*_once` functions — but
/// unlike registers/coils/discrete-inputs/input-registers, file records
/// are never batched into one request: each configured entry gets its own
/// Read File Record request, one sub-request each. Deliberately kept this
/// simple for now (see CLAUDE.md's "FC 0x14 (Read File Record)" section) —
/// batching several sub-requests into one PDU is possible per the spec,
/// but there's no concrete need for it yet with a rarely-used FC like this
/// one (per this project's extraction-based-programming convention).
/// Values are stored raw/uninterpreted, shown as a hex dump in
/// `file-records/<file_number>/<record_number>` — nothing decodes them.
/// No write path exists on the client for these (server direct-write
/// only, no Write File Record function code implemented), same reasoning
/// as `poll_discrete_inputs_once`/`poll_input_registers_once`.
pub async fn poll_file_records_once(
    connection: &Arc<AsyncMutex<Connection>>,
    file_records: &[FileRecordDescription],
    file_record_store: &Arc<Mutex<FileRecordStore>>,
    unit_id: u8,
    timeout: Duration,
) {
    for description in file_records {
        let request_pdu = ReadFileRecordRequest {
            sub_requests: vec![FileRecordSubRequest {
                file_number: description.file_number,
                record_number: description.record_number,
                record_length: description.record_length,
            }],
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
                    "poll: read of file record {}:{} failed: {error}",
                    description.file_number, description.record_number
                );
                continue;
            }
        };

        match ReadFileRecordResponse::decode(&response_pdu) {
            Ok(mut decoded) if decoded.records.len() == 1 => {
                let mut file_record_store = file_record_store
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                file_record_store.set(
                    description.file_number,
                    description.record_number,
                    decoded.records.remove(0),
                );
            }
            Ok(_) | Err(_) => {
                eprintln!(
                    "poll: unexpected response reading file record {}:{}: {:02X?}",
                    description.file_number, description.record_number, response_pdu
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
    discrete_inputs: &[DiscreteInputDescription],
    discrete_input_store: Arc<Mutex<DiscreteInputStore>>,
    input_registers: &[InputRegisterDescription],
    input_register_store: Arc<Mutex<InputRegisterStore>>,
    file_records: &[FileRecordDescription],
    file_record_store: Arc<Mutex<FileRecordStore>>,
    mem_layout: MemLayout,
    input_register_mem_layout: MemLayout,
    unit_id: u8,
    poll_interval: Duration,
    timeout: Duration,
) {
    let register_batches = build_read_batches(registers);
    let coil_batches = build_coil_read_batches(coils);
    let discrete_input_batches = build_discrete_input_read_batches(discrete_inputs);
    let input_register_batches = build_input_register_read_batches(input_registers);
    let mut ticker = tokio::time::interval(poll_interval);
    loop {
        ticker.tick().await;
        poll_once(
            &connection,
            &register_batches,
            &store,
            mem_layout,
            unit_id,
            timeout,
        )
        .await;
        poll_coils_once(&connection, &coil_batches, &coil_store, unit_id, timeout).await;
        poll_discrete_inputs_once(
            &connection,
            &discrete_input_batches,
            &discrete_input_store,
            unit_id,
            timeout,
        )
        .await;
        poll_input_registers_once(
            &connection,
            &input_register_batches,
            &input_register_store,
            input_register_mem_layout,
            unit_id,
            timeout,
        )
        .await;
        poll_file_records_once(
            &connection,
            file_records,
            &file_record_store,
            unit_id,
            timeout,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_fs::RegisterValue;
    use protocol::device_description::{AccessRight, DataType};
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

    fn discrete_input(name: &str, address: u16) -> DiscreteInputDescription {
        DiscreteInputDescription {
            name: name.to_string(),
            address,
        }
    }

    fn input_register(name: &str, address: u16, data_type: DataType) -> InputRegisterDescription {
        InputRegisterDescription {
            name: name.to_string(),
            address,
            data_type,
        }
    }

    fn file_record(
        file_number: u16,
        record_number: u16,
        record_length: u16,
    ) -> FileRecordDescription {
        FileRecordDescription {
            file_number,
            record_number,
            record_length,
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
    fn multi_register_types_occupy_more_than_one_wire_slot() {
        let registers = vec![
            register("A", 40001, DataType::U16),
            register("B", 40002, DataType::F32),
            register("C", 40004, DataType::U16),
        ];
        let batches = build_read_batches(&registers);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].items.len(), 3);
        assert_eq!(batches[0].quantity(), 4);
    }

    #[test]
    fn a_type_wider_than_one_register_can_still_start_a_new_batch_after_a_gap() {
        let registers = vec![
            register("A", 40001, DataType::F64),
            register("B", 40010, DataType::U16),
        ];
        let batches = build_read_batches(&registers);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].starting_address, 40001);
        assert_eq!(batches[0].quantity(), 4);
        assert_eq!(batches[1].starting_address, 40010);
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

    #[test]
    fn contiguous_discrete_inputs_are_grouped_into_one_batch() {
        let discrete_inputs = vec![
            discrete_input("A", 1),
            discrete_input("B", 2),
            discrete_input("C", 3),
        ];
        let batches = build_discrete_input_read_batches(&discrete_inputs);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].starting_address, 1);
        assert_eq!(batches[0].quantity(), 3);
    }

    #[test]
    fn a_gap_in_discrete_input_addresses_starts_a_new_batch() {
        let discrete_inputs = vec![discrete_input("A", 1), discrete_input("B", 10)];
        let batches = build_discrete_input_read_batches(&discrete_inputs);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].starting_address, 1);
        assert_eq!(batches[1].starting_address, 10);
    }

    #[test]
    fn a_discrete_input_batch_never_exceeds_the_modbus_read_limit() {
        let discrete_inputs: Vec<DiscreteInputDescription> = (0..2005)
            .map(|offset| discrete_input(&format!("D{offset}"), 1 + offset as u16))
            .collect();
        let batches = build_discrete_input_read_batches(&discrete_inputs);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].quantity(), 2000);
        assert_eq!(batches[1].quantity(), 5);
    }

    #[test]
    fn contiguous_input_registers_are_grouped_into_one_batch() {
        let input_registers = vec![
            input_register("A", 30001, DataType::U16),
            input_register("B", 30002, DataType::U16),
        ];
        let batches = build_input_register_read_batches(&input_registers);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].starting_address, 30001);
        assert_eq!(batches[0].quantity(), 2);
    }

    #[test]
    fn a_gap_in_input_register_addresses_starts_a_new_batch() {
        let input_registers = vec![
            input_register("A", 30001, DataType::U16),
            input_register("B", 30010, DataType::U16),
        ];
        let batches = build_input_register_read_batches(&input_registers);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].starting_address, 30001);
        assert_eq!(batches[1].starting_address, 30010);
    }

    #[test]
    fn an_input_register_batch_never_exceeds_the_modbus_read_limit() {
        let input_registers: Vec<InputRegisterDescription> = (0..130)
            .map(|offset| {
                input_register(&format!("R{offset}"), 30001 + offset as u16, DataType::U16)
            })
            .collect();
        let batches = build_input_register_read_batches(&input_registers);
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

        poll_once(
            &connection,
            &batches,
            &store,
            MemLayout::Abcd,
            0x01,
            Duration::from_secs(1),
        )
        .await;

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
            MemLayout::Abcd,
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert_eq!(store.lock().unwrap().get("A"), None);
    }

    #[tokio::test]
    async fn poll_once_reassembles_a_multi_register_value_using_mem_layout() {
        let (connection, mut device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        let batches = build_read_batches(&[register("A", 40001, DataType::U32)]);

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            device.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            device.read_exact(&mut pdu).await.unwrap();

            // 0x1234_5678 in CDAB order: word order swapped, each word's
            // own bytes left alone — see register_encoding's own tests for
            // the full byte-order mapping.
            let response_pdu = ReadHoldingRegistersResponse {
                register_values: vec![0x5678, 0x1234],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            device.write_all(&response).await.unwrap();
        });

        poll_once(
            &connection,
            &batches,
            &store,
            MemLayout::Cdab,
            0x01,
            Duration::from_secs(1),
        )
        .await;

        device_task.await.unwrap();
        assert_eq!(
            store.lock().unwrap().get("A"),
            Some(RegisterValue::U32(0x1234_5678))
        );
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

    #[tokio::test]
    async fn poll_discrete_inputs_once_applies_a_successful_batch_to_the_store() {
        let (connection, mut device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let batches =
            build_discrete_input_read_batches(&[discrete_input("A", 1), discrete_input("B", 2)]);

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            device.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            device.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadDiscreteInputsResponse {
                discrete_input_values: vec![true, false],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            device.write_all(&response).await.unwrap();
        });

        poll_discrete_inputs_once(
            &connection,
            &batches,
            &discrete_input_store,
            0x01,
            Duration::from_secs(1),
        )
        .await;

        device_task.await.unwrap();
        assert_eq!(
            discrete_input_store.lock().unwrap().get("A"),
            Some(CoilValue(true))
        );
        assert_eq!(
            discrete_input_store.lock().unwrap().get("B"),
            Some(CoilValue(false))
        );
    }

    #[tokio::test]
    async fn poll_discrete_inputs_once_leaves_the_store_untouched_when_the_device_times_out() {
        let (connection, _device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let discrete_input_store = Arc::new(Mutex::new(DiscreteInputStore::new()));
        let batches = build_discrete_input_read_batches(&[discrete_input("A", 1)]);

        poll_discrete_inputs_once(
            &connection,
            &batches,
            &discrete_input_store,
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert_eq!(discrete_input_store.lock().unwrap().get("A"), None);
    }

    #[tokio::test]
    async fn poll_input_registers_once_applies_a_successful_batch_to_the_store() {
        let (connection, mut device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let batches = build_input_register_read_batches(&[
            input_register("A", 30001, DataType::U16),
            input_register("B", 30002, DataType::U16),
        ]);

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            device.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            device.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadInputRegistersResponse {
                register_values: vec![11, 22],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            device.write_all(&response).await.unwrap();
        });

        poll_input_registers_once(
            &connection,
            &batches,
            &input_register_store,
            MemLayout::Abcd,
            0x01,
            Duration::from_secs(1),
        )
        .await;

        device_task.await.unwrap();
        assert_eq!(
            input_register_store.lock().unwrap().get("A"),
            Some(RegisterValue::U16(11))
        );
        assert_eq!(
            input_register_store.lock().unwrap().get("B"),
            Some(RegisterValue::U16(22))
        );
    }

    #[tokio::test]
    async fn poll_input_registers_once_leaves_the_store_untouched_when_the_device_times_out() {
        let (connection, _device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let input_register_store = Arc::new(Mutex::new(InputRegisterStore::new()));
        let batches =
            build_input_register_read_batches(&[input_register("A", 30001, DataType::U16)]);

        poll_input_registers_once(
            &connection,
            &batches,
            &input_register_store,
            MemLayout::Abcd,
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert_eq!(input_register_store.lock().unwrap().get("A"), None);
    }

    #[tokio::test]
    async fn poll_file_records_once_applies_a_successful_read_to_the_store() {
        let (connection, mut device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let file_records = vec![file_record(4, 1, 2)];

        let device_task = tokio::spawn(async move {
            let mut header = vec![0u8; 7];
            device.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 9];
            device.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadFileRecordResponse {
                records: vec![vec![0x0D, 0xFE, 0x00, 0x20]],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            device.write_all(&response).await.unwrap();
        });

        poll_file_records_once(
            &connection,
            &file_records,
            &file_record_store,
            0x01,
            Duration::from_secs(1),
        )
        .await;

        device_task.await.unwrap();
        assert_eq!(
            file_record_store.lock().unwrap().get(4, 1),
            Some(&vec![0x0D, 0xFE, 0x00, 0x20])
        );
    }

    #[tokio::test]
    async fn poll_file_records_once_sends_one_request_per_configured_record() {
        let (connection, mut device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let file_records = vec![file_record(4, 1, 1), file_record(3, 9, 1)];

        let device_task = tokio::spawn(async move {
            for value in [0x11u8, 0x22u8] {
                let mut header = vec![0u8; 7];
                device.read_exact(&mut header).await.unwrap();
                let mut pdu = vec![0u8; 9];
                device.read_exact(&mut pdu).await.unwrap();

                let response_pdu = ReadFileRecordResponse {
                    records: vec![vec![0x00, value]],
                }
                .encode();
                let mut response = header;
                let length = (response_pdu.len() + 1) as u16;
                response[4..6].copy_from_slice(&length.to_be_bytes());
                response.extend_from_slice(&response_pdu);
                device.write_all(&response).await.unwrap();
            }
        });

        poll_file_records_once(
            &connection,
            &file_records,
            &file_record_store,
            0x01,
            Duration::from_secs(1),
        )
        .await;

        device_task.await.unwrap();
        assert_eq!(
            file_record_store.lock().unwrap().get(4, 1),
            Some(&vec![0x00, 0x11])
        );
        assert_eq!(
            file_record_store.lock().unwrap().get(3, 9),
            Some(&vec![0x00, 0x22])
        );
    }

    #[tokio::test]
    async fn poll_file_records_once_leaves_the_store_untouched_when_the_device_times_out() {
        let (connection, _device) = connected_pair().await;
        let connection = Arc::new(AsyncMutex::new(connection));
        let file_record_store = Arc::new(Mutex::new(FileRecordStore::new()));
        let file_records = vec![file_record(4, 1, 2)];

        poll_file_records_once(
            &connection,
            &file_records,
            &file_record_store,
            0x01,
            Duration::from_millis(50),
        )
        .await;

        assert_eq!(file_record_store.lock().unwrap().get(4, 1), None);
    }
}
