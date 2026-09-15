# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository is currently **greenfield** — no `Cargo.toml`, source files, or scaffolding exist yet. This document captures the architecture and design decisions agreed on with the project owner so implementation can start from a shared plan. Update this file as the design evolves or is refined; do not treat it as a finished spec — parts of the domain model (especially around the `transactions` mechanism and TOML schema) are still being fleshed out.

## What this project is

`infused_modbus` is a combined Modbus **client** and Modbus **server**, both of which expose the Modbus data they handle through a **FUSE filesystem** instead of (or in addition to) a conventional API. "Infused" refers to this live-updating FUSE projection of Modbus data.

- **Client**: acts as a Modbus master against a real PLC/device, continuously updates a local mirror of that device's data, and exposes it through FUSE.
- **Server**: acts as a Modbus slave that external Modbus masters (real PLCs) query/write against. Values it holds are mirrored into its own FUSE filesystem; when an external PLC writes a value, that change is reflected into FUSE so a local operator/process can see it.

Both Modbus TCP and Modbus RTU must be supported. **TCP is the first-class transport; RTU is supported but secondary** (resolved 2026-09-15) — TCP is the more common deployment today, so it gets the primary design/testing attention. RTU's framing in particular relaxes one part of the spec: frame boundaries are detected via the standard 3.5-character-time silence gap, but the stricter 1.5-character-time max-inter-byte-gap rule (a framing error if exceeded) is deliberately not enforced, since doing so reliably against a generic async runtime's scheduling would risk discarding valid frames over harmless jitter — see `protocol/src/rtu.rs`'s module doc comment.

### Device description (TOML)

Each PLC/device has an associated TOML description supplied by the user (not auto-discovered). It describes the data the device offers:

- Register addresses and data types (e.g. holding register 40001, `u16`/`f32`, scaling/units)
- Human-readable names for registers (e.g. `Tank_Temperatur` instead of a raw address)
- Access rights per register (read-only vs read/write)

Connection details (IP/port for TCP, serial port/slave ID for RTU) are **not** part of this TOML file — they are supplied separately via a config file or CLI arguments when starting the client/server binary.

### FUSE filesystem layout

The mounted filesystem (per client or server instance) exposes at least:

- a `holding-registers` directory — current live values as readable files, named/structured per the TOML description. Named after the specific Modbus data type rather than a generic `data`, since other Modbus data types (coils, discrete inputs, input registers) are meant to get their own sibling directories later.
- a `transactions` directory — the write mechanism (resolved 2026-09-15, after considering a single-file batch-write alternative — rejected because it's less filesystem-native: no `ls` to inspect what's staged, no `rm` to unstage a single value, and a comma-separated custom syntax to parse/report errors against):
  1. The user creates a file per value they want to change, named after the register's human-readable name from the TOML description, and writes the desired value as that file's **content** (e.g. `echo True > transactions/Stop_Process`) — not encoded in the filename. Staging happens on write, not on bare creation.
  2. Once all desired changes are staged, the user creates a sentinel file named `TRANSACTION_END`.
  3. Creating `TRANSACTION_END` triggers the actual batched Modbus write(s) for everything staged in the transaction.
- a `report` directory — one read-only file per register (`report/<name>`) showing the outcome of that register's most recent write attempt (resolved 2026-09-15, see "Write status reporting" below for the alternatives considered).

**`TRANSACTION_END` confirmation semantics (resolved 2026-09-15):** creating `TRANSACTION_END` clears the whole `transactions/` staging area immediately (matching a commit consuming its staging area — no partial/pending status is shown, see "Write status reporting" below), but this does **not** mean the write has happened yet. `fuse-fs` has no Modbus protocol knowledge, so it cannot itself confirm a write reached the real device — it only hands the drained transaction off (over an injected `std::sync::mpsc::Sender<HashMap<String, RegisterValue>>`) to whoever owns the receiving end. Values under `holding-registers/` must **not** change as a side effect of `TRANSACTION_END` — they only change once the actual write is confirmed by the device (client: after the Modbus write response / next poll confirms it; server: once it has actually applied and would echo the value to real Modbus clients), which is client/server-specific logic outside `fuse-fs`, wired up once those binaries integrate `protocol`.

**Write status reporting / Milestone H3 (resolved 2026-09-15):** the simplest of the considered shapes was chosen, deliberately deferring the richer alternatives until a real confirmed-write consumer exists to show what they'd actually need (extraction-based programming: don't build the structure before a concrete need has shown its real shape):
- **Granularity: per register**, not per transaction. `report/<register-name>` mirrors `holding-registers/<name>` and `transactions/<name>` exactly. This also sidesteps needing any transaction-identity concept (transactions are anonymous today — draining one doesn't produce an ID) and handles partial multi-register failures for free: `report/A` and `report/B` are independent, no aggregate transaction-level status needed.
- **Content: a plain status word.** `"OK"` or `"FAILED: <reason>"` (`fuse_fs::WriteStatus`), not a structured record with timestamp/Modbus exception code. `fuse-fs` deliberately has no `protocol` dependency for wire/error types; a richer format was judged premature before any real writer of these reports exists.
- **Lifecycle: overwritten by the next attempt**, not persisted until manually `rm`'d. `report/<name>` always reflects only the most recent write attempt for that register. Bounded by construction (at most one entry per register); no cleanup mechanism needed. Also in-memory only, same as `RegisterStore`/`PendingTransaction` — doesn't survive a process restart.
- Like `holding-registers/` and `transactions/`, `report/` is only ever updated by whoever owns the receiving end of `transaction_sender` (see confirmation semantics above) — `fuse-fs` itself never writes to it.

This transactional, filesystem-native interface is the core "twist" of the project — treating Modbus reads/writes as file operations rather than requiring a dedicated client API.

## Planned architecture

The project will be a **Cargo workspace** with (at least) these crates:

- **`protocol`** — the Modbus protocol implementation itself (TCP + RTU). This is a **from-scratch implementation**, not a wrapper around `tokio-modbus` — full control over protocol details was a deliberate choice.
- **`fuse-fs`** — the FUSE filesystem layer shared by client and server: the `holding-registers` and `transactions` directory logic, TOML device-description parsing, and the mapping between filesystem operations and Modbus reads/writes.
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
