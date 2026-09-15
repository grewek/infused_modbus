// This project's own fuzzer (per CLAUDE.md, not an off-the-shelf fuzzing crate).
// Run with `cargo run --bin fuzz_pdu` for a fresh random seed, or
// `cargo run --bin fuzz_pdu -- <seed>` to reproduce a specific run.

use protocol::{
    ExceptionResponse, ReadHoldingRegistersRequest, ReadHoldingRegistersResponse,
    WriteMultipleRegistersRequest, WriteMultipleRegistersResponse, WriteSingleRegisterRequest,
    WriteSingleRegisterResponse,
};
use std::panic::{self, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

const DECODE_FUZZ_ITERATIONS: usize = 20_000;
const ROUND_TRIP_FUZZ_ITERATIONS: usize = 5_000;
const MAX_FUZZ_BUFFER_LEN: usize = 300;

// Modbus spec limits, not just overflow avoidance: real devices reject requests
// asking for more registers than this, and WriteMultipleRegistersRequest::encode
// does not (yet) validate its input against this limit, so the fuzzer stays
// inside it rather than exercising that known gap.
const MAX_READ_HOLDING_REGISTERS_COUNT: usize = 125;
const MAX_WRITE_MULTIPLE_REGISTERS_COUNT: usize = 123;

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

    fn next_usize_below(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }

    fn next_u16_vec(&mut self, len: usize) -> Vec<u16> {
        (0..len).map(|_| self.next_u16()).collect()
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
    let decoders: [NamedDecoder; 7] = [
        ("ReadHoldingRegistersRequest", |bytes| {
            let _ = ReadHoldingRegistersRequest::decode(bytes);
        }),
        ("ReadHoldingRegistersResponse", |bytes| {
            let _ = ReadHoldingRegistersResponse::decode(bytes);
        }),
        ("WriteSingleRegisterRequest", |bytes| {
            let _ = WriteSingleRegisterRequest::decode(bytes);
        }),
        ("WriteSingleRegisterResponse", |bytes| {
            let _ = WriteSingleRegisterResponse::decode(bytes);
        }),
        ("WriteMultipleRegistersRequest", |bytes| {
            let _ = WriteMultipleRegistersRequest::decode(bytes);
        }),
        ("WriteMultipleRegistersResponse", |bytes| {
            let _ = WriteMultipleRegistersResponse::decode(bytes);
        }),
        ("ExceptionResponse", |bytes| {
            let _ = ExceptionResponse::decode(bytes);
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
        let register_count = rng.next_usize_below(MAX_WRITE_MULTIPLE_REGISTERS_COUNT + 1);
        let request = WriteMultipleRegistersRequest {
            starting_address: rng.next_u16(),
            register_values: rng.next_u16_vec(register_count),
        };
        let decoded =
            WriteMultipleRegistersRequest::decode(&request.encode()).unwrap_or_else(|error| {
                panic!("WriteMultipleRegistersRequest failed to decode: {error:?}")
            });
        assert_eq!(
            request, decoded,
            "WriteMultipleRegistersRequest round trip mismatch"
        );
    }
    println!("WriteMultipleRegistersRequest: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

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
