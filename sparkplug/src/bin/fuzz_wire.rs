// This project's own fuzzer (per CLAUDE.md, not an off-the-shelf fuzzing crate),
// mirroring protocol's fuzz_pdu.rs. Run with `cargo run -p sparkplug --bin
// fuzz_wire` for a fresh random seed, or `-- <seed>` to reproduce a specific run.

use sparkplug::wire::{
    Tag, WireType, decode_fixed32, decode_fixed64, decode_length_delimited, decode_tag,
    decode_varint, encode_fixed32, encode_fixed64, encode_length_delimited, encode_tag,
    encode_varint,
};
use std::panic::{self, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

const DECODE_FUZZ_ITERATIONS: usize = 20_000;
const ROUND_TRIP_FUZZ_ITERATIONS: usize = 5_000;
const MAX_FUZZ_BUFFER_LEN: usize = 300;
const MAX_ROUND_TRIP_BYTES_LEN: usize = 300;

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

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_usize_below(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u8()).collect()
    }

    fn next_wire_type(&mut self) -> WireType {
        match self.next_usize_below(4) {
            0 => WireType::Varint,
            1 => WireType::Fixed64,
            2 => WireType::LengthDelimited,
            _ => WireType::Fixed32,
        }
    }

    /// A field number is never allowed to be 0, per the protobuf spec.
    fn next_field_number(&mut self) -> u32 {
        self.next_u32().wrapping_add(1).max(1)
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
    // Every `decode_*` this module exposes. Decode is where untrusted wire
    // bytes actually get parsed, so it's the half of this fuzzer that matters
    // most for CLAUDE.md's "harden against malicious peers" stance; round-
    // tripping (fuzz_round_trips below) only ever feeds decode already-valid
    // bytes, so it can't exercise this on its own.
    let decoders: Vec<NamedDecoder> = vec![
        ("decode_varint", |bytes| {
            let _ = decode_varint(bytes);
        }),
        ("decode_tag", |bytes| {
            let _ = decode_tag(bytes);
        }),
        ("decode_length_delimited", |bytes| {
            let _ = decode_length_delimited(bytes);
        }),
        ("decode_fixed32", |bytes| {
            let _ = decode_fixed32(bytes);
        }),
        ("decode_fixed64", |bytes| {
            let _ = decode_fixed64(bytes);
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
                eprintln!("fuzz_wire: {name} panicked on input {bytes:?}");
                std::process::exit(1);
            }
        }
        println!("{name}: {DECODE_FUZZ_ITERATIONS} random inputs, no panics");
    }

    panic::set_hook(previous_hook);
}

fn fuzz_round_trips(rng: &mut Xorshift64) {
    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let value = rng.next_u64();
        let mut buffer = Vec::new();
        encode_varint(value, &mut buffer);
        let (decoded, consumed) = decode_varint(&buffer)
            .unwrap_or_else(|error| panic!("varint failed to decode: {error:?}"));
        assert_eq!(value, decoded, "varint round trip mismatch");
        assert_eq!(consumed, buffer.len(), "varint consumed length mismatch");
    }
    println!("varint: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let tag = Tag {
            field_number: rng.next_field_number(),
            wire_type: rng.next_wire_type(),
        };
        let mut buffer = Vec::new();
        encode_tag(tag, &mut buffer);
        let (decoded, consumed) =
            decode_tag(&buffer).unwrap_or_else(|error| panic!("tag failed to decode: {error:?}"));
        assert_eq!(tag, decoded, "tag round trip mismatch");
        assert_eq!(consumed, buffer.len(), "tag consumed length mismatch");
    }
    println!("tag: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let length = rng.next_usize_below(MAX_ROUND_TRIP_BYTES_LEN + 1);
        let value = rng.next_bytes(length);
        let mut buffer = Vec::new();
        encode_length_delimited(&value, &mut buffer);
        let (decoded, consumed) = decode_length_delimited(&buffer)
            .unwrap_or_else(|error| panic!("length-delimited failed to decode: {error:?}"));
        assert_eq!(value, decoded, "length-delimited round trip mismatch");
        assert_eq!(
            consumed,
            buffer.len(),
            "length-delimited consumed length mismatch"
        );
    }
    println!("length_delimited: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let value = rng.next_u32();
        let mut buffer = Vec::new();
        encode_fixed32(value, &mut buffer);
        let (decoded, consumed) = decode_fixed32(&buffer)
            .unwrap_or_else(|error| panic!("fixed32 failed to decode: {error:?}"));
        assert_eq!(value, decoded, "fixed32 round trip mismatch");
        assert_eq!(consumed, buffer.len(), "fixed32 consumed length mismatch");
    }
    println!("fixed32: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");

    for _ in 0..ROUND_TRIP_FUZZ_ITERATIONS {
        let value = rng.next_u64();
        let mut buffer = Vec::new();
        encode_fixed64(value, &mut buffer);
        let (decoded, consumed) = decode_fixed64(&buffer)
            .unwrap_or_else(|error| panic!("fixed64 failed to decode: {error:?}"));
        assert_eq!(value, decoded, "fixed64 round trip mismatch");
        assert_eq!(consumed, buffer.len(), "fixed64 consumed length mismatch");
    }
    println!("fixed64: {ROUND_TRIP_FUZZ_ITERATIONS} round trips ok");
}

fn main() {
    let seed = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse::<u64>().ok())
        .unwrap_or_else(seed_from_time);
    println!("fuzz_wire seed: {seed}");

    let mut rng = Xorshift64::new(seed);

    fuzz_decoders(&mut rng);
    fuzz_round_trips(&mut rng);

    println!("fuzz_wire: all checks passed");
}
