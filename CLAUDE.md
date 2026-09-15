# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository is currently **greenfield** — no `Cargo.toml`, source files, or scaffolding exist yet. This document captures the architecture and design decisions agreed on with the project owner so implementation can start from a shared plan. Update this file as the design evolves or is refined; do not treat it as a finished spec — parts of the domain model (especially around the `transactions` mechanism and TOML schema) are still being fleshed out.

## What this project is

`infused_modbus` is a combined Modbus **client** and Modbus **server**, both of which expose the Modbus data they handle through a **FUSE filesystem** instead of (or in addition to) a conventional API. "Infused" refers to this live-updating FUSE projection of Modbus data.

- **Client**: acts as a Modbus master against a real PLC/device, continuously updates a local mirror of that device's data, and exposes it through FUSE.
- **Server**: acts as a Modbus slave that external Modbus masters (real PLCs) query/write against. Values it holds are mirrored into its own FUSE filesystem; when an external PLC writes a value, that change is reflected into FUSE so a local operator/process can see it.

Both Modbus TCP and Modbus RTU must be supported.

### Device description (TOML)

Each PLC/device has an associated TOML description supplied by the user (not auto-discovered). It describes the data the device offers:

- Register addresses and data types (e.g. holding register 40001, `u16`/`f32`, scaling/units)
- Human-readable names for registers (e.g. `Tank_Temperatur` instead of a raw address)
- Access rights per register (read-only vs read/write)

Connection details (IP/port for TCP, serial port/slave ID for RTU) are **not** part of this TOML file — they are supplied separately via a config file or CLI arguments when starting the client/server binary.

### FUSE filesystem layout

The mounted filesystem (per client or server instance) exposes at least:

- a `data`/`registers` directory — current live values as readable files, named/structured per the TOML description
- a `transactions` directory — the write mechanism (resolved 2026-09-15, after considering a single-file batch-write alternative — rejected because it's less filesystem-native: no `ls` to inspect what's staged, no `rm` to unstage a single value, and a comma-separated custom syntax to parse/report errors against):
  1. The user creates a file per value they want to change, named after the register's human-readable name from the TOML description, and writes the desired value as that file's **content** (e.g. `echo True > transactions/Stop_Process`) — not encoded in the filename. Staging happens on write, not on bare creation.
  2. Once all desired changes are staged, the user creates a sentinel file named `TRANSACTION_END`.
  3. Creating `TRANSACTION_END` triggers the actual batched Modbus write(s) for everything staged in the transaction.

This transactional, filesystem-native interface is the core "twist" of the project — treating Modbus reads/writes as file operations rather than requiring a dedicated client API.

## Planned architecture

The project will be a **Cargo workspace** with (at least) these crates:

- **`protocol`** — the Modbus protocol implementation itself (TCP + RTU). This is a **from-scratch implementation**, not a wrapper around `tokio-modbus` — full control over protocol details was a deliberate choice.
- **`fuse-fs`** — the FUSE filesystem layer shared by client and server: the `data`/`registers` and `transactions` directory logic, TOML device-description parsing, and the mapping between filesystem operations and Modbus reads/writes.
- **`client`** — binary crate; thin entry point wiring `protocol` (as Modbus master) + `fuse-fs` together, configured via CLI args/config file for target device connection info.
- **`server`** — binary crate; thin entry point wiring `protocol` (as Modbus slave) + `fuse-fs` together.

## Key technical decisions

- **Async runtime**: `tokio`, used across protocol I/O and FUSE update handling.
- **FUSE bindings**: `fuser` crate.
- **Modbus protocol**: implemented from scratch in the `protocol` crate (no `tokio-modbus` dependency).
- **Target platform**: Linux-only for now (FUSE is a Linux-specific dependency). Portability to other platforms (e.g. via WinFsp on Windows) is a desired future goal, not a current constraint — avoid over-engineering abstractions for it prematurely.
- **Device description vs. connection config**: kept deliberately separate — TOML describes *data shape*, CLI/config describes *how to connect*.

## Working conventions

- **Small, reviewable increments**: implement one method/function/struct (or similarly small unit) at a time, then stop for review before moving to the next one. Do not batch multiple units into one unreviewed change.
- **Extraction-Based Programming (Casey Muratori)**: write the concrete, specific solution first. Do not introduce an abstraction (generic function, trait, config-driven flexibility, etc.) speculatively — only extract one after the same concrete pattern has actually shown up and its real shape is known.
- **Testing**: most functions get regular unit tests. Interaction/integration-level behavior (e.g. protocol ⇄ FUSE interplay, transaction handling) is tested via a fuzzer that is itself part of this project — not an off-the-shelf fuzzing crate.

## Development commands

No code exists yet, so there is nothing to build/test/lint. Once the workspace is scaffolded, the standard Cargo workspace commands apply:

```sh
cargo build --workspace
cargo test --workspace
cargo test -p <crate-name> <test_name>   # run a single test in one crate
cargo clippy --workspace --all-targets
cargo fmt --all
```
