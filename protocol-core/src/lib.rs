//! The dependency-free, `#![no_std]` subset of this project's Modbus
//! wire-format logic — see this crate's `Cargo.toml` for why it's a
//! separate crate rather than a feature flag on `protocol`.

#![no_std]

pub mod bit_values;
pub mod device_identification;
pub mod file_record;
pub mod pdu_bytes;
pub mod register_values;
