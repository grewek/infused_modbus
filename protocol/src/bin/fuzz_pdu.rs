// This project's own fuzzer (per CLAUDE.md, not an off-the-shelf fuzzing crate).
// Run with `cargo run --bin fuzz_pdu` for a fresh random seed, or
// `cargo run --bin fuzz_pdu -- <seed>` to reproduce a specific run.

use protocol::EncodeError;
use protocol::adu::{RtuAdu, TcpAdu};
use protocol::pdu::{
    DeviceIdentificationObject, ExceptionResponse, FileRecordSubRequest, MaskWriteRegisterRequest,
    MaskWriteRegisterResponse, ReadCoilsRequest, ReadCoilsResponse,
    ReadDeviceIdentificationRequest, ReadDeviceIdentificationResponse, ReadDiscreteInputsRequest,
    ReadDiscreteInputsResponse, ReadFileRecordRequest, ReadFileRecordResponse,
    ReadHoldingRegistersRequest, ReadHoldingRegistersResponse, ReadInputRegistersRequest,
    ReadInputRegistersResponse, ReadWriteMultipleRegistersRequest,
    ReadWriteMultipleRegistersResponse, ReportServerIdRequest, ReportServerIdResponse,
    WriteFileRecordRequest, WriteFileRecordResponse, WriteFileRecordSubRequest,
    WriteMultipleCoilsRequest, WriteMultipleCoilsResponse, WriteMultipleRegistersRequest,
    WriteMultipleRegistersResponse, WriteSingleCoilRequest, WriteSingleCoilResponse,
    WriteSingleRegisterRequest, WriteSingleRegisterResponse,
};
use std::panic::{self, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

const DECODE_FUZZ_ITERATIONS: usize = 20_000;
const ROUND_TRIP_FUZZ_ITERATIONS: usize = 5_000;
const MAX_FUZZ_BUFFER_LEN: usize = 300;

// Modbus spec limits, not just overflow avoidance: real devices reject requests
// asking for more registers than this. WriteMultipleRegistersRequest::encode
// enforces its own limit now (see the dedicated over-limit loop in
// fuzz_round_trips below), but ReadHoldingRegistersRequest has no equivalent
// check (it only ever carries a `quantity` field, never a value vec, so
// there's nothing for encode to validate the length of) — the fuzzer stays
// inside this limit for that one so round-trip decoding isn't exercising an
// address range no real request would.
const MAX_READ_HOLDING_REGISTERS_COUNT: usize = 125;
const MAX_WRITE_MULTIPLE_REGISTERS_COUNT: usize = 123;
// FC 0x17's write half has a lower spec limit than plain Write Multiple
// Registers (121, not 123) — its extra read-address/read-quantity/
// write-address fields eat further into the same 253-byte PDU budget. Also
// enforced by ReadWriteMultipleRegistersRequest::encode itself now, same as
// MAX_WRITE_MULTIPLE_REGISTERS_COUNT is for plain Write Multiple Registers.
const MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT: usize = 121;
// Modbus's own limit on how many coils one Read Coils/Read Discrete Inputs
// response, or one Write Multiple Coils request, may carry — coils pack
// 8-to-a-byte, so this is much higher than the register limits above.
const MAX_COIL_COUNT: usize = 1968;

// Small, comfortably-within-the-253-byte-PDU-budget caps for the nested/
// variable-shaped types below (file records, device identification objects)
// — not spec limits (those depend on how many bytes each entry actually
// carries, not a fixed count), just kept small enough that a handful of
// maximally-sized entries can never overflow the PDU on their own, so the
// fuzzer doesn't need to precisely track the running byte budget itself.
const MAX_FILE_RECORD_SUB_REQUESTS: usize = 10;
const MAX_FILE_RECORD_DATA_WORDS: usize = 10;
const MAX_DEVICE_ID_OBJECTS: usize = 5;
const MAX_DEVICE_ID_OBJECT_VALUE_LEN: usize = 20;

// Modbus's own PDU size limit (253 bytes), which bounds how large a PDU an ADU
// can realistically carry.
const MAX_ADU_PDU_LEN: usize = 253;

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn next_u16(&mut self) -> u16 {
        self.next_u64() as u16
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn next_usize_below(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }

    fn next_u16_vec(&mut self, len: usize) -> Vec<u16> {
        (0..len).map(|_| self.next_u16()).collect()
    }

    fn next_bool_vec(&mut self, len: usize) -> Vec<bool> {
        (0..len).map(|_| self.next_bool()).collect()
    }
}

fn seed_from_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

type NamedDecoder = (&'static str, fn(&[u8]));

fn fuzz_decoders(rng: &mut Xorshift64) {
    // Every `decode()` this crate exposes — one entry per PDU/ADU type, not
    // just the ones round-tripped below. Decode is where untrusted wire
    // bytes actually get parsed, so it's the half of this fuzzer that
    // matters most for CLAUDE.md's "harden against malicious peers" stance;
    // round-tripping (fuzz_round_trips below) only ever feeds decode
    // already-valid bytes, so it can't exercise this on its own.
    let decoders: Vec<NamedDecoder> = vec![
        ("ReadCoilsRequest", |bytes| {
            let _ = ReadCoilsRequest::decode(bytes);
        }),
        ("ReadDiscreteInputsRequest", |bytes| {
            let _ = ReadDiscreteInputsRequest::decode(bytes);
        }),
        ("ReadHoldingRegistersRequest", |bytes| {
            let _ = ReadHoldingRegistersRequest::decode(bytes);
        }),
        ("ReadInputRegistersRequest", |bytes| {
            let _ = ReadInputRegistersRequest::decode(bytes);
        }),
        ("ReadCoilsResponse", |bytes| {
            let _ = ReadCoilsResponse::decode(bytes);
        }),
        ("ReadDiscreteInputsResponse", |bytes| {
            let _ = ReadDiscreteInputsResponse::decode(bytes);
        }),
        ("ReadHoldingRegistersResponse", |bytes| {
            let _ = ReadHoldingRegistersResponse::decode(bytes);
        }),
        ("ReadInputRegistersResponse", |bytes| {
            let _ = ReadInputRegistersResponse::decode(bytes);
        }),
        ("WriteSingleCoilRequest", |bytes| {
            let _ = WriteSingleCoilRequest::decode(bytes);
        }),
        ("WriteSingleCoilResponse", |bytes| {
            let _ = WriteSingleCoilResponse::decode(bytes);
        }),
        ("WriteSingleRegisterRequest", |bytes| {
            let _ = WriteSingleRegisterRequest::decode(bytes);
        }),
        ("WriteSingleRegisterResponse", |bytes| {
            let _ = WriteSingleRegisterResponse::decode(bytes);
        }),
        ("MaskWriteRegisterRequest", |bytes| {
            let _ = MaskWriteRegisterRequest::decode(bytes);
        }),
        ("MaskWriteRegisterResponse", |bytes| {
            let _ = MaskWriteRegisterResponse::decode(bytes);
        }),
        ("ReportServerIdRequest", |bytes| {
            let _ = ReportServerIdRequest::decode(bytes);
        }),
        ("ReportServerIdResponse", |bytes| {
            let _ = ReportServerIdResponse::decode(bytes);
        }),
        ("WriteMultipleCoilsRequest", |bytes| {
            let _ = WriteMultipleCoilsRequest::decode(bytes);
        }),
        ("WriteMultipleCoilsResponse", |bytes| {
            let _ = WriteMultipleCoilsResponse::decode(bytes);
        }),
        ("WriteMultipleRegistersRequest", |bytes| {
            let _ = WriteMultipleRegistersRequest::decode(bytes);
        }),
        ("WriteMultipleRegistersResponse", |bytes| {
            let _ = WriteMultipleRegistersResponse::decode(bytes);
        }),
        ("ReadWriteMultipleRegistersRequest", |bytes| {
            let _ = ReadWriteMultipleRegistersRequest::decode(bytes);
        }),
        ("ReadWriteMultipleRegistersResponse", |bytes| {
            let _ = ReadWriteMultipleRegistersResponse::decode(bytes);
        }),
        ("ReadFileRecordRequest", |bytes| {
            let _ = ReadFileRecordRequest::decode(bytes);
        }),
        ("ReadFileRecordResponse", |bytes| {
            let _ = ReadFileRecordResponse::decode(bytes);
        }),
        ("WriteFileRecordRequest", |bytes| {
            let _ = WriteFileRecordRequest::decode(bytes);
        }),
        ("WriteFileRecordResponse", |bytes| {
            let _ = WriteFileRecordResponse::decode(bytes);
        }),
        ("ExceptionResponse", |bytes| {
            let _ = ExceptionResponse::decode(bytes);
        }),
        ("ReadDeviceIdentificationRequest", |bytes| {
            let _ = ReadDeviceIdentificationRequest::decode(bytes);
        }),
        ("ReadDeviceIdentificationResponse", |bytes| {
            let _ = ReadDeviceIdentificationResponse::decode(bytes);
        }),
        ("TcpAdu", |bytes| {
            let _ = TcpAdu::decode(bytes);
        }),
        ("RtuAdu", |bytes| {
            let _ = RtuAdu::decode(bytes);
        }),
    ];

    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    for (name, decode) in decoders {
        for _ in 0..DECODE_FUZZ_ITERATIONS {
            let length = rng.next_usize_below(MAX_FUZZ_BUFFER_LEN + 1);
            let bytes = rng.next_bytes(length);
            if panic::catch_unwind(AssertUnwindSafe(|| decode(&bytes))).is_err() {
                panic::set_hook(previous_hook);
                eprintln!("fuzz_pdu: {name}::decode panicked on input {bytes:?}");
                std::process::exit(1);
            }
        }
        println!("{name}::decode: {DECODE_FUZZ_ITERATIONS} random inputs, no panics");
    }

    panic::set_hook(previous_hook);
}

fn fuzz_round_trips(rng: &mut Xorshift64) {
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = ReadCoilsRequest {
            starting_address: rng.next_u16(),
            quantity: rng.next_u16(),
        };
        let decoded = ReadCoilsRequest::decode(&request.encode())
            .unwrap_or_else(|error| panic!("ReadCoilsRequest failed to decode: {error:?}"));
        assert_eq!(request, decoded, "ReadCoilsRequest round trip mismatch");
    }
    println!("ReadCoilsRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = ReadDiscreteInputsRequest {
            starting_address: rng.next_u16(),
            quantity: rng.next_u16(),
        };
        let decoded =
            ReadDiscreteInputsRequest::decode(&request.encode()).unwrap_or_else(|error| {
                panic!("ReadDiscreteInputsRequest failed to decode: {error:?}")
            });
        assert_eq!(
            request, decoded,
            "ReadDiscreteInputsRequest round trip mismatch"
        );
    }
    println!("ReadDiscreteInputsRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = ReadHoldingRegistersRequest {
            starting_address: rng.next_u16(),
            quantity: rng.next_u16(),
        };
        let decoded =
            ReadHoldingRegistersRequest::decode(&request.encode()).unwrap_or_else(|error| {
                panic!("ReadHoldingRegistersRequest failed to decode: {error:?}")
            });
        assert_eq!(
            request, decoded,
            "ReadHoldingRegistersRequest round trip mismatch"
        );
    }
    println!("ReadHoldingRegistersRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = ReadInputRegistersRequest {
            starting_address: rng.next_u16(),
            quantity: rng.next_u16(),
        };
        let decoded =
            ReadInputRegistersRequest::decode(&request.encode()).unwrap_or_else(|error| {
                panic!("ReadInputRegistersRequest failed to decode: {error:?}")
            });
        assert_eq!(
            request, decoded,
            "ReadInputRegistersRequest round trip mismatch"
        );
    }
    println!("ReadInputRegistersRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    // ReadCoilsResponse/ReadDiscreteInputsResponse pack bits 8-to-a-byte and
    // expose every bit the byte_count implies (see their own doc comments) —
    // unlike WriteMultipleCoilsRequest (which has an explicit `quantity`
    // field to trim padding against), a coil count that isn't a multiple of
    // 8 would round-trip back with extra trailing `false` padding bits, not
    // the original vec. Generating only multiples of 8 keeps this an exact
    // round trip.
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let bit_count = rng.next_usize_below(MAX_COIL_COUNT / 8 + 1) * 8;
        let response = ReadCoilsResponse {
            coil_values: rng.next_bool_vec(bit_count),
        };
        let decoded = ReadCoilsResponse::decode(&response.encode())
            .unwrap_or_else(|error| panic!("ReadCoilsResponse failed to decode: {error:?}"));
        assert_eq!(response, decoded, "ReadCoilsResponse round trip mismatch");
    }
    println!("ReadCoilsResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let bit_count = rng.next_usize_below(MAX_COIL_COUNT / 8 + 1) * 8;
        let response = ReadDiscreteInputsResponse {
            discrete_input_values: rng.next_bool_vec(bit_count),
        };
        let decoded =
            ReadDiscreteInputsResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("ReadDiscreteInputsResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "ReadDiscreteInputsResponse round trip mismatch"
        );
    }
    println!("ReadDiscreteInputsResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let register_count = rng.next_usize_below(MAX_READ_HOLDING_REGISTERS_COUNT + 1);
        let response = ReadHoldingRegistersResponse {
            register_values: rng.next_u16_vec(register_count),
        };
        let decoded =
            ReadHoldingRegistersResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("ReadHoldingRegistersResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "ReadHoldingRegistersResponse round trip mismatch"
        );
    }
    println!("ReadHoldingRegistersResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let register_count = rng.next_usize_below(MAX_READ_HOLDING_REGISTERS_COUNT + 1);
        let response = ReadInputRegistersResponse {
            register_values: rng.next_u16_vec(register_count),
        };
        let decoded =
            ReadInputRegistersResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("ReadInputRegistersResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "ReadInputRegistersResponse round trip mismatch"
        );
    }
    println!("ReadInputRegistersResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = WriteSingleCoilRequest {
            coil_address: rng.next_u16(),
            coil_value: rng.next_bool(),
        };
        let decoded = WriteSingleCoilRequest::decode(&request.encode())
            .unwrap_or_else(|error| panic!("WriteSingleCoilRequest failed to decode: {error:?}"));
        assert_eq!(
            request, decoded,
            "WriteSingleCoilRequest round trip mismatch"
        );
    }
    println!("WriteSingleCoilRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let response = WriteSingleCoilResponse {
            coil_address: rng.next_u16(),
            coil_value: rng.next_bool(),
        };
        let decoded = WriteSingleCoilResponse::decode(&response.encode())
            .unwrap_or_else(|error| panic!("WriteSingleCoilResponse failed to decode: {error:?}"));
        assert_eq!(
            response, decoded,
            "WriteSingleCoilResponse round trip mismatch"
        );
    }
    println!("WriteSingleCoilResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = WriteSingleRegisterRequest {
            register_address: rng.next_u16(),
            register_value: rng.next_u16(),
        };
        let decoded =
            WriteSingleRegisterRequest::decode(&request.encode()).unwrap_or_else(|error| {
                panic!("WriteSingleRegisterRequest failed to decode: {error:?}")
            });
        assert_eq!(
            request, decoded,
            "WriteSingleRegisterRequest round trip mismatch"
        );
    }
    println!("WriteSingleRegisterRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let response = WriteSingleRegisterResponse {
            register_address: rng.next_u16(),
            register_value: rng.next_u16(),
        };
        let decoded =
            WriteSingleRegisterResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("WriteSingleRegisterResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "WriteSingleRegisterResponse round trip mismatch"
        );
    }
    println!("WriteSingleRegisterResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = MaskWriteRegisterRequest {
            reference_address: rng.next_u16(),
            and_mask: rng.next_u16(),
            or_mask: rng.next_u16(),
        };
        let decoded = MaskWriteRegisterRequest::decode(&request.encode())
            .unwrap_or_else(|error| panic!("MaskWriteRegisterRequest failed to decode: {error:?}"));
        assert_eq!(
            request, decoded,
            "MaskWriteRegisterRequest round trip mismatch"
        );
    }
    println!("MaskWriteRegisterRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let response = MaskWriteRegisterResponse {
            reference_address: rng.next_u16(),
            and_mask: rng.next_u16(),
            or_mask: rng.next_u16(),
        };
        let decoded =
            MaskWriteRegisterResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("MaskWriteRegisterResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "MaskWriteRegisterResponse round trip mismatch"
        );
    }
    println!("MaskWriteRegisterResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = ReportServerIdRequest;
        let decoded = ReportServerIdRequest::decode(&request.encode())
            .unwrap_or_else(|error| panic!("ReportServerIdRequest failed to decode: {error:?}"));
        assert_eq!(
            request, decoded,
            "ReportServerIdRequest round trip mismatch"
        );
    }
    println!("ReportServerIdRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        // byte_count (server_id.len() + 1) must fit a u8, so server_id itself
        // is capped at 254 bytes — stay comfortably under that.
        let server_id_len = rng.next_usize_below(200);
        let response = ReportServerIdResponse {
            server_id: rng.next_bytes(server_id_len),
            run_indicator_status: rng.next_bool(),
        };
        let decoded = ReportServerIdResponse::decode(&response.encode())
            .unwrap_or_else(|error| panic!("ReportServerIdResponse failed to decode: {error:?}"));
        assert_eq!(
            response, decoded,
            "ReportServerIdResponse round trip mismatch"
        );
    }
    println!("ReportServerIdResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    // WriteMultipleCoilsRequest's decode trims to the wire's own explicit
    // `quantity` field (unlike ReadCoilsResponse/ReadDiscreteInputsResponse
    // above, which expose every padding bit) — see its own decode doc
    // comment — so any coil_values length round-trips exactly, no
    // multiple-of-8 constraint needed here.
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let coil_count = rng.next_usize_below(MAX_COIL_COUNT + 1);
        let request = WriteMultipleCoilsRequest {
            starting_address: rng.next_u16(),
            coil_values: rng.next_bool_vec(coil_count),
        };
        let decoded =
            WriteMultipleCoilsRequest::decode(&request.encode()).unwrap_or_else(|error| {
                panic!("WriteMultipleCoilsRequest failed to decode: {error:?}")
            });
        assert_eq!(
            request, decoded,
            "WriteMultipleCoilsRequest round trip mismatch"
        );
    }
    println!("WriteMultipleCoilsRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let response = WriteMultipleCoilsResponse {
            starting_address: rng.next_u16(),
            quantity: rng.next_u16(),
        };
        let decoded =
            WriteMultipleCoilsResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("WriteMultipleCoilsResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "WriteMultipleCoilsResponse round trip mismatch"
        );
    }
    println!("WriteMultipleCoilsResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let register_count = rng.next_usize_below(MAX_WRITE_MULTIPLE_REGISTERS_COUNT + 1);
        let request = WriteMultipleRegistersRequest {
            starting_address: rng.next_u16(),
            register_values: rng.next_u16_vec(register_count),
        };
        let encoded = request.encode().unwrap_or_else(|error| {
            panic!("WriteMultipleRegistersRequest failed to encode: {error:?}")
        });
        let decoded = WriteMultipleRegistersRequest::decode(&encoded).unwrap_or_else(|error| {
            panic!("WriteMultipleRegistersRequest failed to decode: {error:?}")
        });
        assert_eq!(
            request, decoded,
            "WriteMultipleRegistersRequest round trip mismatch"
        );
    }
    println!("WriteMultipleRegistersRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    // The known-gap check this fuzzer used to just avoid (see
    // MAX_WRITE_MULTIPLE_REGISTERS_COUNT's own comment) — now that
    // WriteMultipleRegistersRequest::encode validates its input, exercise the
    // rejection path itself: any length past the spec limit must come back as
    // an error, never a silently-truncated/wrapped PDU.
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let register_count =
            MAX_WRITE_MULTIPLE_REGISTERS_COUNT + 1 + rng.next_usize_below(MAX_FUZZ_BUFFER_LEN);
        let request = WriteMultipleRegistersRequest {
            starting_address: rng.next_u16(),
            register_values: rng.next_u16_vec(register_count),
        };
        match request.encode() {
            Err(EncodeError::TooManyRegisters { count, max }) => {
                assert_eq!(count, register_count);
                assert_eq!(max, MAX_WRITE_MULTIPLE_REGISTERS_COUNT);
            }
            other => panic!(
                "WriteMultipleRegistersRequest with {register_count} registers should have been rejected, got {other:?}"
            ),
        }
    }
    println!(
        "WriteMultipleRegistersRequest: {ROUND_TRIP_FUZZ_ITERATIONS} over-limit encodes correctly rejected"
    );

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let response = WriteMultipleRegistersResponse {
            starting_address: rng.next_u16(),
            quantity: rng.next_u16(),
        };
        let decoded =
            WriteMultipleRegistersResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("WriteMultipleRegistersResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "WriteMultipleRegistersResponse round trip mismatch"
        );
    }
    println!("WriteMultipleRegistersResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let write_count = rng.next_usize_below(MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT + 1);
        let request = ReadWriteMultipleRegistersRequest {
            read_starting_address: rng.next_u16(),
            read_quantity: rng.next_u16(),
            write_starting_address: rng.next_u16(),
            write_values: rng.next_u16_vec(write_count),
        };
        let encoded = request.encode().unwrap_or_else(|error| {
            panic!("ReadWriteMultipleRegistersRequest failed to encode: {error:?}")
        });
        let decoded = ReadWriteMultipleRegistersRequest::decode(&encoded).unwrap_or_else(|error| {
            panic!("ReadWriteMultipleRegistersRequest failed to decode: {error:?}")
        });
        assert_eq!(
            request, decoded,
            "ReadWriteMultipleRegistersRequest round trip mismatch"
        );
    }
    println!("ReadWriteMultipleRegistersRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    // Same known-gap-turned-real-check as WriteMultipleRegistersRequest
    // above, for FC17's own (lower, 121) write limit.
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let write_count = MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT
            + 1
            + rng.next_usize_below(MAX_FUZZ_BUFFER_LEN);
        let request = ReadWriteMultipleRegistersRequest {
            read_starting_address: rng.next_u16(),
            read_quantity: rng.next_u16(),
            write_starting_address: rng.next_u16(),
            write_values: rng.next_u16_vec(write_count),
        };
        match request.encode() {
            Err(EncodeError::TooManyRegisters { count, max }) => {
                assert_eq!(count, write_count);
                assert_eq!(max, MAX_READ_WRITE_MULTIPLE_REGISTERS_WRITE_COUNT);
            }
            other => panic!(
                "ReadWriteMultipleRegistersRequest with {write_count} write values should have been rejected, got {other:?}"
            ),
        }
    }
    println!(
        "ReadWriteMultipleRegistersRequest: {ROUND_TRIP_FUZZ_ITERATIONS} over-limit encodes correctly rejected"
    );

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let register_count = rng.next_usize_below(MAX_READ_HOLDING_REGISTERS_COUNT + 1);
        let response = ReadWriteMultipleRegistersResponse {
            register_values: rng.next_u16_vec(register_count),
        };
        let decoded = ReadWriteMultipleRegistersResponse::decode(&response.encode())
            .unwrap_or_else(|error| {
                panic!("ReadWriteMultipleRegistersResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "ReadWriteMultipleRegistersResponse round trip mismatch"
        );
    }
    println!("ReadWriteMultipleRegistersResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        // At least 1: unlike ReadFileRecordResponse/WriteFileRecordRequest/
        // WriteFileRecordResponse below (all fine with an empty list —
        // "here are zero records" is a meaningful answer/echo), a *request*
        // asking for zero sub-requests is nonsensical, and decode() rejects
        // it outright (InvalidFileRecordByteCount) even though encode()
        // itself doesn't stop you building one — discovered by this fuzzer
        // extension itself, see this session's own follow-up notes.
        let sub_request_count = 1 + rng.next_usize_below(MAX_FILE_RECORD_SUB_REQUESTS);
        let request = ReadFileRecordRequest {
            sub_requests: (0..sub_request_count)
                .map(|_| FileRecordSubRequest {
                    file_number: rng.next_u16(),
                    record_number: rng.next_u16(),
                    record_length: rng.next_u16(),
                })
                .collect(),
        };
        let decoded = ReadFileRecordRequest::decode(&request.encode())
            .unwrap_or_else(|error| panic!("ReadFileRecordRequest failed to decode: {error:?}"));
        assert_eq!(
            request, decoded,
            "ReadFileRecordRequest round trip mismatch"
        );
    }
    println!("ReadFileRecordRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let record_count = rng.next_usize_below(MAX_FILE_RECORD_SUB_REQUESTS + 1);
        let response = ReadFileRecordResponse {
            records: (0..record_count)
                .map(|_| {
                    let word_count = rng.next_usize_below(MAX_FILE_RECORD_DATA_WORDS + 1);
                    rng.next_bytes(word_count * 2)
                })
                .collect(),
        };
        let decoded = ReadFileRecordResponse::decode(&response.encode())
            .unwrap_or_else(|error| panic!("ReadFileRecordResponse failed to decode: {error:?}"));
        assert_eq!(
            response, decoded,
            "ReadFileRecordResponse round trip mismatch"
        );
    }
    println!("ReadFileRecordResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    // record_data's length must be even: encode derives the wire's own
    // record_length field as `record_data.len() / 2`, so an odd length is
    // rejected outright by encode() rather than silently dropping the last
    // byte's worth of precision from that field while still writing every
    // byte (see the dedicated rejection-path checks below). Round-trip
    // generation here stays even-only, matching the type's actual valid
    // domain.
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let sub_request_count = rng.next_usize_below(MAX_FILE_RECORD_SUB_REQUESTS + 1);
        let request = WriteFileRecordRequest {
            sub_requests: (0..sub_request_count)
                .map(|_| {
                    let word_count = rng.next_usize_below(MAX_FILE_RECORD_DATA_WORDS + 1);
                    WriteFileRecordSubRequest {
                        file_number: rng.next_u16(),
                        record_number: rng.next_u16(),
                        record_data: rng.next_bytes(word_count * 2),
                    }
                })
                .collect(),
        };
        let encoded = request
            .encode()
            .unwrap_or_else(|error| panic!("WriteFileRecordRequest failed to encode: {error:?}"));
        let decoded = WriteFileRecordRequest::decode(&encoded)
            .unwrap_or_else(|error| panic!("WriteFileRecordRequest failed to decode: {error:?}"));
        assert_eq!(
            request, decoded,
            "WriteFileRecordRequest round trip mismatch"
        );
    }
    println!("WriteFileRecordRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    // Dedicated rejection-path check, mirroring the TooManyRegisters ones
    // for FC16/FC17 above — an odd-length record_data must always come back
    // as EncodeError::OddFileRecordDataLength, never a silently-truncated
    // PDU.
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let file_number = rng.next_u16();
        let record_number = rng.next_u16();
        let word_count = rng.next_usize_below(MAX_FILE_RECORD_DATA_WORDS + 1);
        let mut record_data = rng.next_bytes(word_count * 2);
        record_data.push(rng.next_u16() as u8);
        let length = record_data.len();
        let request = WriteFileRecordRequest {
            sub_requests: vec![WriteFileRecordSubRequest {
                file_number,
                record_number,
                record_data,
            }],
        };
        match request.encode() {
            Err(EncodeError::OddFileRecordDataLength {
                file_number: actual_file_number,
                record_number: actual_record_number,
                length: actual_length,
            }) => {
                assert_eq!(actual_file_number, file_number);
                assert_eq!(actual_record_number, record_number);
                assert_eq!(actual_length, length);
            }
            other => panic!(
                "WriteFileRecordRequest with odd-length record_data ({length} bytes) should have been rejected, got {other:?}"
            ),
        }
    }
    println!(
        "WriteFileRecordRequest: {ROUND_TRIP_FUZZ_ITERATIONS} odd-length encodes correctly rejected"
    );

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let sub_request_count = rng.next_usize_below(MAX_FILE_RECORD_SUB_REQUESTS + 1);
        let response = WriteFileRecordResponse {
            sub_requests: (0..sub_request_count)
                .map(|_| {
                    let word_count = rng.next_usize_below(MAX_FILE_RECORD_DATA_WORDS + 1);
                    WriteFileRecordSubRequest {
                        file_number: rng.next_u16(),
                        record_number: rng.next_u16(),
                        record_data: rng.next_bytes(word_count * 2),
                    }
                })
                .collect(),
        };
        let encoded = response
            .encode()
            .unwrap_or_else(|error| panic!("WriteFileRecordResponse failed to encode: {error:?}"));
        let decoded = WriteFileRecordResponse::decode(&encoded)
            .unwrap_or_else(|error| panic!("WriteFileRecordResponse failed to decode: {error:?}"));
        assert_eq!(
            response, decoded,
            "WriteFileRecordResponse round trip mismatch"
        );
    }
    println!("WriteFileRecordResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let file_number = rng.next_u16();
        let record_number = rng.next_u16();
        let word_count = rng.next_usize_below(MAX_FILE_RECORD_DATA_WORDS + 1);
        let mut record_data = rng.next_bytes(word_count * 2);
        record_data.push(rng.next_u16() as u8);
        let length = record_data.len();
        let response = WriteFileRecordResponse {
            sub_requests: vec![WriteFileRecordSubRequest {
                file_number,
                record_number,
                record_data,
            }],
        };
        match response.encode() {
            Err(EncodeError::OddFileRecordDataLength {
                file_number: actual_file_number,
                record_number: actual_record_number,
                length: actual_length,
            }) => {
                assert_eq!(actual_file_number, file_number);
                assert_eq!(actual_record_number, record_number);
                assert_eq!(actual_length, length);
            }
            other => panic!(
                "WriteFileRecordResponse with odd-length record_data ({length} bytes) should have been rejected, got {other:?}"
            ),
        }
    }
    println!(
        "WriteFileRecordResponse: {ROUND_TRIP_FUZZ_ITERATIONS} odd-length encodes correctly rejected"
    );

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        // Real Modbus function codes are always below 0x80; the top bit is reserved
        // to mark a response as an exception, so that's the valid domain to fuzz.
        let response = ExceptionResponse {
            function_code: rng.next_u8() & 0x7F,
            exception_code: rng.next_u8(),
        };
        let decoded = ExceptionResponse::decode(&response.encode())
            .unwrap_or_else(|error| panic!("ExceptionResponse failed to decode: {error:?}"));
        assert_eq!(response, decoded, "ExceptionResponse round trip mismatch");
    }
    println!("ExceptionResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let request = ReadDeviceIdentificationRequest {
            read_device_id_code: rng.next_u8(),
            object_id: rng.next_u8(),
        };
        let decoded =
            ReadDeviceIdentificationRequest::decode(&request.encode()).unwrap_or_else(|error| {
                panic!("ReadDeviceIdentificationRequest failed to decode: {error:?}")
            });
        assert_eq!(
            request, decoded,
            "ReadDeviceIdentificationRequest round trip mismatch"
        );
    }
    println!("ReadDeviceIdentificationRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let object_count = rng.next_usize_below(MAX_DEVICE_ID_OBJECTS + 1);
        let response = ReadDeviceIdentificationResponse {
            read_device_id_code: rng.next_u8(),
            conformity_level: rng.next_u8(),
            more_follows: rng.next_bool(),
            next_object_id: rng.next_u8(),
            objects: (0..object_count)
                .map(|_| {
                    let value_len = rng.next_usize_below(MAX_DEVICE_ID_OBJECT_VALUE_LEN + 1);
                    DeviceIdentificationObject {
                        id: rng.next_u8(),
                        value: rng.next_bytes(value_len),
                    }
                })
                .collect(),
        };
        let decoded =
            ReadDeviceIdentificationResponse::decode(&response.encode()).unwrap_or_else(|error| {
                panic!("ReadDeviceIdentificationResponse failed to decode: {error:?}")
            });
        assert_eq!(
            response, decoded,
            "ReadDeviceIdentificationResponse round trip mismatch"
        );
    }
    println!("ReadDeviceIdentificationResponse: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let pdu_len = rng.next_usize_below(MAX_ADU_PDU_LEN + 1);
        let adu = TcpAdu {
            transaction_id: rng.next_u16(),
            unit_id: rng.next_u8(),
            pdu: rng.next_bytes(pdu_len),
        };
        let decoded = TcpAdu::decode(&adu.encode())
            .unwrap_or_else(|error| panic!("TcpAdu failed to decode: {error:?}"));
        assert_eq!(adu, decoded, "TcpAdu round trip mismatch");
    }
    println!("TcpAdu: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let pdu_len = rng.next_usize_below(MAX_ADU_PDU_LEN + 1);
        let adu = RtuAdu {
            unit_id: rng.next_u8(),
            pdu: rng.next_bytes(pdu_len),
        };
        let decoded = RtuAdu::decode(&adu.encode())
            .unwrap_or_else(|error| panic!("RtuAdu failed to decode: {error:?}"));
        assert_eq!(adu, decoded, "RtuAdu round trip mismatch");
    }
    println!("RtuAdu: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");
}

fn main() {
    let seed = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse::<u64>().ok())
        .unwrap_or_else(seed_from_time);
    println!("fuzz_pdu seed: {seed}");

    let mut rng = Xorshift64::new(seed);

    fuzz_decoders(&mut rng);
    fuzz_round_trips(&mut rng);

    println!("fuzz_pdu: all checks passed");
}
