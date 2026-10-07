//! Baseline comparison: `protocol::pdu`/`protocol::adu` (the current,
//! `Vec`-based implementation) vs. `protocol_core::pdu`/`protocol_core::adu`
//! (the fixed-capacity port, not yet wired into `protocol`/`client`/
//! `server` -- see CLAUDE.md's "server-no-std initiative"). Run before
//! deciding whether/how to integrate the new implementation, per the user's
//! explicit request: get a real speed baseline first, not just a binary-size
//! one.
//!
//! `cargo bench -p protocol --bench pdu_codec`

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

// ---- old (Vec-based) ----
use protocol::adu::TcpAdu as OldTcpAdu;
use protocol::pdu::{
    ReadCoilsResponse as OldReadCoilsResponse,
    ReadHoldingRegistersResponse as OldReadHoldingRegistersResponse,
    WriteSingleRegisterRequest as OldWriteSingleRegisterRequest,
};

// ---- new (fixed-capacity) ----
use protocol_core::adu::TcpAdu as NewTcpAdu;
use protocol_core::bit_values::BitValues;
use protocol_core::pdu::{
    ReadCoilsResponse as NewReadCoilsResponse,
    ReadHoldingRegistersResponse as NewReadHoldingRegistersResponse,
    WriteSingleRegisterRequest as NewWriteSingleRegisterRequest,
};
use protocol_core::pdu_bytes::PduBytes;
use protocol_core::register_values::RegisterValues;

fn old_registers(count: usize) -> OldReadHoldingRegistersResponse {
    OldReadHoldingRegistersResponse {
        register_values: (0..count as u16).collect(),
    }
}

fn new_registers(count: usize) -> NewReadHoldingRegistersResponse {
    let mut register_values = RegisterValues::new();
    for value in 0..count as u16 {
        register_values.push(value).unwrap();
    }
    NewReadHoldingRegistersResponse { register_values }
}

fn old_bits(count: usize) -> OldReadCoilsResponse {
    OldReadCoilsResponse {
        coil_values: (0..count).map(|index| index % 3 == 0).collect(),
    }
}

fn new_bits(count: usize) -> NewReadCoilsResponse {
    let mut coil_values = BitValues::new();
    for index in 0..count {
        coil_values.push(index % 3 == 0).unwrap();
    }
    NewReadCoilsResponse { coil_values }
}

/// Small, fixed-size PDU with no container type involved on either side --
/// the control case, where old and new should perform near-identically
/// (both just write 5 bytes to a freshly allocated/initialized buffer).
fn bench_write_single_register(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_single_register");

    let old = OldWriteSingleRegisterRequest {
        register_address: 40001,
        register_value: 42,
    };
    group.bench_function("encode/old", |b| b.iter(|| black_box(&old).encode()));
    let old_encoded = old.encode();
    group.bench_function("decode/old", |b| {
        b.iter(|| OldWriteSingleRegisterRequest::decode(black_box(&old_encoded)))
    });

    let new = NewWriteSingleRegisterRequest {
        register_address: 40001,
        register_value: 42,
    };
    group.bench_function("encode/new", |b| b.iter(|| black_box(&new).encode()));
    let new_encoded = new.encode();
    group.bench_function("decode/new", |b| {
        b.iter(|| NewWriteSingleRegisterRequest::decode(black_box(&new_encoded)))
    });

    group.finish();
}

/// Register list responses at a few sizes, including the real spec maximum
/// (125) -- this is where old's `Vec::with_capacity`+heap-allocating
/// `collect()` and new's zero-allocation fixed array should diverge most.
fn bench_read_holding_registers_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_holding_registers_response");

    for count in [1usize, 10, 125] {
        let old = old_registers(count);
        group.bench_with_input(BenchmarkId::new("encode/old", count), &old, |b, value| {
            b.iter(|| black_box(value).encode())
        });
        let old_encoded = old.encode();
        group.bench_with_input(
            BenchmarkId::new("decode/old", count),
            &old_encoded,
            |b, bytes| b.iter(|| OldReadHoldingRegistersResponse::decode(black_box(bytes))),
        );

        let new = new_registers(count);
        group.bench_with_input(BenchmarkId::new("encode/new", count), &new, |b, value| {
            b.iter(|| black_box(value).encode())
        });
        let new_encoded = new.encode();
        group.bench_with_input(
            BenchmarkId::new("decode/new", count),
            &new_encoded,
            |b, bytes| b.iter(|| NewReadHoldingRegistersResponse::decode(black_box(bytes))),
        );
    }

    group.finish();
}

/// Packed-bit responses at a few sizes, including the real spec maximum
/// (2000) -- old's `Vec<bool>`/`unpack_bit`-into-`collect()` vs. new's
/// zero-allocation `BitValues`.
fn bench_read_coils_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_coils_response");

    for count in [8usize, 64, 2000] {
        let old = old_bits(count);
        group.bench_with_input(BenchmarkId::new("encode/old", count), &old, |b, value| {
            b.iter(|| black_box(value).encode())
        });
        let old_encoded = old.encode();
        group.bench_with_input(
            BenchmarkId::new("decode/old", count),
            &old_encoded,
            |b, bytes| b.iter(|| OldReadCoilsResponse::decode(black_box(bytes))),
        );

        let new = new_bits(count);
        group.bench_with_input(BenchmarkId::new("encode/new", count), &new, |b, value| {
            b.iter(|| black_box(value).encode())
        });
        let new_encoded = new.encode();
        group.bench_with_input(
            BenchmarkId::new("decode/new", count),
            &new_encoded,
            |b, bytes| b.iter(|| NewReadCoilsResponse::decode(black_box(bytes))),
        );
    }

    group.finish();
}

/// One full ADU round trip (MBAP header + PDU) wrapping a 10-register
/// response -- exercises the outer TcpAdu::encode/decode layer too, not
/// just the inner PDU.
fn bench_tcp_adu(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_adu");

    let old_pdu = old_registers(10).encode();
    let old_adu = OldTcpAdu {
        transaction_id: 1,
        unit_id: 1,
        pdu: old_pdu,
    };
    group.bench_function("encode/old", |b| b.iter(|| black_box(&old_adu).encode()));
    let old_encoded = old_adu.encode();
    group.bench_function("decode/old", |b| {
        b.iter(|| OldTcpAdu::decode(black_box(&old_encoded)))
    });

    let new_pdu_bytes = new_registers(10).encode();
    let mut new_pdu = PduBytes::new();
    new_pdu.extend_from_slice(&new_pdu_bytes).unwrap();
    let new_adu = NewTcpAdu {
        transaction_id: 1,
        unit_id: 1,
        pdu: new_pdu,
    };
    group.bench_function("encode/new", |b| b.iter(|| black_box(&new_adu).encode()));
    let new_encoded = new_adu.encode();
    group.bench_function("decode/new", |b| {
        b.iter(|| NewTcpAdu::decode(black_box(&new_encoded)))
    });

    group.finish();
}

/// Isolates construction cost alone (no pushes/extends) -- to check whether
/// `BitValues`/`RegisterValues`/`PduBytes`'s mandatory full-array zero-init
/// in `new()` is the fixed per-call cost dominating small-N decode
/// benchmarks above.
fn bench_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("construction");
    group.bench_function("BitValues::new", |b| b.iter(BitValues::new));
    group.bench_function("RegisterValues::new", |b| b.iter(RegisterValues::new));
    group.bench_function("PduBytes::new", |b| b.iter(PduBytes::new));
    group.bench_function("Vec::<bool>::new", |b| b.iter(Vec::<bool>::new));
    group.finish();
}

criterion_group!(
    benches,
    bench_construction,
    bench_write_single_register,
    bench_read_holding_registers_response,
    bench_read_coils_response,
    bench_tcp_adu
);
criterion_main!(benches);
