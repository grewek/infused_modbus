# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository is implemented and functional, not greenfield: a Cargo workspace with `protocol`, `datafs` (renamed from `fuse-fs` 2026-09-29), `sparkplug`, `client`, and `server` crates, all building and tested. Modbus TCP and RTU are wired end to end for both binaries, covering transactions, FC43 device-description discovery, coils, discrete inputs (FC2), input registers (FC4), and the full register data-type set (`u8`/`i8` through `f64`/`i64`, configurable byte/word order). `tls+tcp://` (mutual TLS, fingerprint pinning, server-side client-approval workflow) is fully implemented — see "TLS transport security & client trust" below. The server writes directly into `holding-registers/`/`coils/`/`discrete-inputs/`/`input-registers/` (no `transactions/` staging — see "server direct-write model"); the client still stages writes via `transactions/`+`TRANSACTION_END`. A device description can declare **several machines** sharing one link, each dispatched by its own Modbus Unit ID and mounted under its own top-level directory (see "Multi-machine device description & FUSE layout"). Both binaries support **three interchangeable data-representation layers** via `--data-representation-layer fuse|files|mqtt`: the original FUSE mount, real flat files kept current via `inotify`/atomic `rename()` (the default), or an MQTT/Sparkplug B interface (`client` as a Sparkplug B Edge Node over an external MQTT broker reached via `--mqtt-broker`; `server` behind a local `ServerHandle`-backed Unix socket, `server-data.sock`). `fuse`/`files` are legacy (bugfixes only); new feature work targets `mqtt`. See the repo's `README.md` for the function-code support table and setup instructions, and `git log` for implementation history.

This document is the architecture and design-decision record — it captures *why* things are the way they are, not day-to-day implementation status, so treat it as authoritative for design rationale but check the actual code/tests for exact current behavior. Update it whenever a design decision is made or revised, including for features that are decided but not yet built — mark those explicitly as not-yet-implemented. **Condensed 2026-10-03:** this file had grown to ~177KB; verification logs, bug-hunt play-by-plays, and byte-exact worked examples were cut from the already-shipped sections below, keeping only the decision and its rationale. `git log` and the test suites are the record of exactly what happened and when — this file is the record of *why*.

## What this project is

`infused_modbus` is a combined Modbus **client** and Modbus **server**, both of which expose the Modbus data they handle through a **FUSE filesystem** instead of (or in addition to) a conventional API. "Infused" refers to this live-updating FUSE projection of Modbus data.

- **Client**: acts as a Modbus master against a real PLC/device, continuously updates a local mirror of that device's data, and exposes it through FUSE.
- **Server**: acts as a Modbus slave that external Modbus masters (real PLCs) query/write against. Values it holds are mirrored into its own FUSE filesystem; when an external PLC writes a value, that change is reflected into FUSE so a local operator/process can see it.

Both Modbus TCP and Modbus RTU are supported. **TCP is the first-class transport; RTU is supported but secondary** (resolved 2026-09-15). RTU's framing relaxes one part of the spec: frame boundaries are detected via the standard 3.5-character-time silence gap, but the stricter 1.5-character-time max-inter-byte-gap rule is deliberately not enforced, since enforcing it reliably against a generic async runtime's scheduling would risk discarding valid frames over harmless jitter — see `protocol/src/rtu.rs`'s module doc comment. Both binaries choose TCP or RTU via a scheme-prefixed connection string (`tcp://<address:port>` / `rtu://<serial-path>:<baud-rate>`); everything built on top of the transport (transactions, polling, FC43 device identification) works identically regardless of transport.

### Device description (TOML)

**Note (2026-09-28): this section predates multi-machine support and describes the shape of a single machine's data — see "Multi-machine device description & FUSE layout" below for the actual top-level TOML shape (`[[machines]]`, nesting each section one level down, e.g. `[machines.registers]`).**

Each PLC/device has an associated TOML description supplied by the user (not auto-discovered): register addresses/data types, human-readable names, and per-register access rights (read-only vs read/write). Connection details (IP/port, serial port/slave ID) are **not** part of this file — supplied separately via CLI/config when starting the binary.

**Server "introduces itself" via FC43 (resolved 2026-09-15):** rather than requiring the client to keep its own copy of the server's TOML in sync by hand, the client fetches it at startup via FC43 (MEI 0x0E, Read Device Identification, Extended access) — chosen specifically because its object model (arbitrary-length byte strings, keyed by ID) and built-in More-Follows/Next-Object-Id continuation already solve "transfer a string too long for one response" for free. Two private objects (0x80-0xFF is vendor-reserved): `0x80` — presence flag (one byte); `0x81`, `0x82`, ... — the raw TOML source, chunked (each ≤244 bytes, capped so a chunk+response overhead still fits one 253-byte PDU — see `server/src/device_identification.rs`). The client always requires a local `device-description.toml` as fallback (used if the server has none, doesn't support FC43, or the fetch fails for any reason) — never fatal. Progress is printed per round trip since a fetch can take several. Scope: only Extended access and these two object kinds; Basic/Regular/Individual access and the standard VendorName/etc. objects are deferred.

### FUSE filesystem layout

**Note (2026-09-28/29):** every directory below lives one level deeper under `/<machine-name>/` except `client-trust/` (server-only, root-level). A second, non-FUSE presentation exposes the identical shape as real flat files — see "Pluggable data-representation layer" below; everything about paths/semantics is unaffected, only *how* the tree is served differs.

The mounted filesystem exposes:

- `holding-registers/` — current live values as readable files, named per the TOML description. `coils`, `discrete-inputs`, and `input-registers` are sibling directories for the other Modbus data types.
- `transactions/` (client only — see "server direct-write model") — write mechanism (resolved 2026-09-15; a single-file batch-write alternative was rejected as less filesystem-native — no `ls` to inspect staged values, no `rm` to unstage one, a custom syntax to parse errors against):
  1. Create a file named after a register's human-readable name under `transactions/`, write the desired value as its **content** (staging happens on write, not bare creation).
  2. Create a sentinel file `TRANSACTION_END`.
  3. That triggers the actual batched Modbus write(s).
- `report/` — one read-only file per register (`report/<name>`) showing the outcome of its most recent write attempt.

**`TRANSACTION_END` confirmation semantics (resolved 2026-09-15):** creating `TRANSACTION_END` clears `transactions/` immediately, but does **not** mean the write has happened — `datafs` has no Modbus protocol knowledge, it only hands the drained transaction off (via an injected `mpsc::Sender`) to whoever owns the receiving end.
  - **Server** (superseded 2026-09-18, see "server direct-write model"): no longer has `transactions/` at all.
  - **Client (narrowed 2026-09-16):** the write response confirms the write happened, but only the *next poll tick* updates `holding-registers/` — never the write response directly. Originally either could update the store, but that admitted a real race: a poll response already in flight before a commit could land *after* it and silently overwrite the freshly-confirmed value with a stale one. Keeping the poll loop the *only* writer of `RegisterStore`/`CoilStore` removes the race outright, at the cost of `holding-registers/<name>` lagging up to one poll interval behind `report/<name>` already showing `OK`. A commit-triggered re-poll was considered and rejected — adds wire traffic/contention for a race a single-writer design avoids for free.

**Write status reporting (resolved 2026-09-15):** the simplest shape was chosen deliberately, per Extraction-Based Programming — richer alternatives deferred until a real confirmed-write consumer shows their actual needed shape.
- **Per register**, not per transaction — sidesteps needing any transaction-identity concept, and handles partial multi-register failures for free.
- **Content: a plain status word** (`"OK"` / `"FAILED: <reason>"`, `fuse_fs::WriteStatus`) — `datafs` deliberately has no `protocol` dependency for wire/error types.
- **Lifecycle: overwritten by the next attempt**, not persisted — in-memory only, doesn't survive a restart.
- Only ever updated by whoever owns the receiving end of `transaction_sender` — `datafs` itself never writes to it.

## Server direct-write model, replacing server-side transactions (resolved and implemented 2026-09-18)

**Revisits the server's half of "TRANSACTION_END confirmation semantics" above** (client's half is unchanged). The transactional model's real justification was always the *client's* round-trip-to-a-real-device axis (stage several edits, commit, confirm asynchronously via `report/` since a real device write can genuinely fail). The server never had that axis — its own in-memory state is authoritative, a "write" is just `store.set()`, there's no device to fail against. It only inherited staging because `datafs` built one shared mechanism for both roles. Also: staged writes were never wire-atomic even on the client (`transaction_consumer` sends one write per register sequentially) — so "staging" was always local UX, never a hard atomicity guarantee, weakening the case for keeping it server-side.

**Model:** `holding-registers/<name>`, `coils/<name>`, `discrete-inputs/<name>`, `input-registers/<name>` are **directly writable on the server only** (still strictly read-only on the client) — `echo 5 > holding-registers/Setpoint` applies immediately, no staging. A `WriteMode` enum (`Staged`/`Direct`) on `InfusedFilesystem` gates every FUSE method that needs to differ (`getattr`/`lookup` report `0o644` instead of `0o444` in `Direct` mode, necessary since `default_permissions` enforces this before `write` is called). A direct write is handed off over the same `transaction_sender` channel as an implicit one-item transaction.

**Race-safety:** every write, staged or direct, is applied by the one dedicated consumer thread reading from that one channel — nothing in `datafs` mutates stores directly. Same hand-off already accepted for `TRANSACTION_END`, just triggered per single write.

**`report/` was not extended** to discrete-inputs/input-registers — a direct write's own `write()`/`release()` return code is the only failure signal needed there; extending it would be scope creep.

**Accepted consequence:** this was a breaking change to previously-shipped server behavior — deliberate, per this project's "explicit/simple over preserving existing behavior while nothing is deployed" stance.

## Read-only Modbus data types — Discrete Inputs (FC2) & Input Registers (FC4) (resolved and implemented 2026-09-18)

**TOML schema**, structurally identical to `[coils]`/`[registers]`:

```toml
[discrete-inputs]
base_address = 10000

[[discrete-inputs.entries]]
name = "Door_Open_Sensor"
offset = 1

[input-registers]
base_address = 30000
mem-layout = "abcd"

[[input-registers.entries]]
name = "Flow_Rate"
offset = 1
data_type = "f32"
```

Discrete inputs mirror `CoilDescription` (name+offset only). Input registers mirror `RegisterDescription` minus `access` (always read-only), still need their own `mem-layout`.

**Stores:** `DiscreteInputStore`/`InputRegisterStore` mirror `CoilStore`/`RegisterStore` exactly, with no write method exposed to `protocol`/wire code — no Modbus FC ever lets a master write these; only server direct-write or client polling populates them.

**FUSE:** two sibling directories, read-only on the client, directly writable on the server, same machinery as `holding-registers/`/`coils/`. Server-side, each entry starts at a default (`false`/`0`) until directly written.

## FC 0x16 (Mask Write Register) (resolved and implemented 2026-09-23)

Server applies `result = (current AND and_mask) OR (or_mask AND (NOT and_mask))` to a single register in place, under the same lock as the preceding read. Same 1-register-wide scope as FC6 — only `register_count() == 1` types, `ReadWrite` only.

**Client-only FUSE mapping.** Exposing it on the server's own direct-write model was rejected: a local operator already has full read access and can compute+write a new value with no read-modify-write race to protect against (everything already serializes through `transaction_sender`) — masking only matters against a *real remote device* that might be written by another master concurrently, exclusively the client's situation.

`transactions/<name>` accepts a second content form: `MASK <and_mask> <or_mask>` (case-insensitive, `0x`-hex or decimal u16). Kept to one file per register, not one per mask component — the user explicitly rejected a three-file (value/and/or) scheme. An explicit keyword was chosen over sniffing content shape, matching this project's "explicit over implicit" stance. Staged as `StagedValue::MaskedRegister`; sent as the client's **own individual** FC16 request (never batched — no "mask write multiple registers" FC exists). A MASK against a register wider than one wire word is rejected at send time via `report/<name>`.

## FC 0x11 (Report Server ID) (resolved and implemented 2026-09-23)

**TOML:** optional `server-id: Option<String>` field, became per-machine 2026-09-28 (FC11 answers per Unit ID).

**Protocol/server:** `ReportServerIdResponse { server_id: Vec<u8>, run_indicator_status: bool }` — raw bytes not `String` (spec format is vendor-specific); `run_indicator_status` always `true`. Answers `ILLEGAL_FUNCTION` when `server_id` is absent — same exception as a never-implemented FC, since answering with nothing meaningful isn't really "supporting" it.

**Client-only, deliberately not exposed on the server at all** — the server's own `server_id` is config the technician already wrote themselves; mirroring it into the server's own FUSE tree would show a fact it already knows (`server`'s `InfusedFilesystem` is always constructed with `server_id: None`). The client is where this has real value: it shows whatever ended up in the client's own *effective* description (local fallback or FC43-fetched) — worth seeing since a technician running `client` didn't necessarily set it. **No wire round trip** — `client`'s `server-id` file is just `Display`-formatted from the already-parsed `DeviceDescription.server_id`, no new Modbus traffic. Sending its own FC11 request as a legacy-device fallback identification path was considered and deliberately deferred (no concrete need yet).

**First top-level regular file** in the FUSE tree (every other top-level entry before this was a directory) — `server_id_ino`, always allocated, same precedent as `client_trust_ino`. Read-only (`0o444`) unconditionally.

## FC 0x17 (Read/Write Multiple Registers) (resolved and implemented 2026-09-23)

**Server-only, no FUSE mapping — decided before implementation.** FC17's operation is nothing `client` can't already do: stage+commit via `transactions/`+`TRANSACTION_END` (confirmed via `report/`), read via `holding-registers/`. Shortcutting that into one wire round trip was rejected: it would need to update `holding-registers/` from a write response's own echoed read value — exactly the race already rejected for the client's register/coil store (see "TRANSACTION_END confirmation semantics"). `client` never sends FC17 — purely a "serve external masters correctly" feature.

**Server:** `handle_read_write_multiple_registers` resolves **both halves fully against static descriptions before touching `store` at all** — a problem with either half rejects the whole request with no partial write. Only once both are known-valid does it lock `store` once, write, then read — so a request reading back what it just wrote sees its own write, and no concurrent request interleaves.

## FC 0x14 (Read File Record) (resolved and implemented 2026-09-24)

Researched real-world FC20/21 usage before designing: rare compared to FC1-4/6/16; where implemented, "file"/"record" is almost never an actual filesystem file — usually a vendor-specific structured block (event/fault logs, historical/trend data). No part of the wire protocol defines what a record's bytes mean — confirmed against a pymodbus maintainer's own framing.

**Scope: raw bytes only, no field-level interpretation** — deferred to the (still design-only) custom-function-codes work. Client shows a read-only hex dump, nothing more.

**TOML schema — deliberately different shape**, `[[file-records]]`, flat array, no `base_address`/`offset`/`name`:

```toml
[[file-records]]
file_number = 20
record_number = 5
record_length = 9
```

`file_number`/`record_number` *are* the address; the FUSE path (`file-records/<file_number>/<record_number>`) is the identifier. `record_length` is in 16-bit words, fixed per entry — a mismatched request is `ILLEGAL_DATA_VALUE`.

**`FileRecordStore`** keyed by `(file_number, record_number)` tuple, raw `Vec<u8>` values. **First two-level-nested FUSE directory tree**, statically known from TOML at construction, same pattern as every other data type with an extra grouping level. Content is a hex dump, default `2 * record_length` zero bytes until written. Read-only on the client, directly writable on the server — **no `report/` coverage** (same precedent as discrete-inputs/input-registers: a direct write's own return code is the only failure signal needed).

**Gotcha worth remembering:** `client_trust`'s dynamic inode allocator previously started right after `rejected_log_ino` — coincidentally equal to `server_id_ino` too (never manifested since `server_id`/`client_trust` are mutually exclusive in practice). File records genuinely coexist with `client_trust` on the server, so this latent collision would have become real; fixed by allocating `file_records_ino`/`server_id_ino` before `client_trust.set_next_ino()` runs.

**FC backlog: FC20 done.** FC21 followed immediately. FC18 (Read FIFO Queue) remains hardest/last — no established FUSE representation for queue semantics exists yet.

## FC 0x15 (Write File Record) (resolved and implemented 2026-09-24)

**Scope corrected mid-design, not assumed from the start** — a reusable lesson: initial instinct was to mirror FC17's "server-only" reasoning, which the user caught as wrong ("isn't the whole point of FC21 that we change data *from* the client?"). FC17 was server-only because the client already had an equivalent mechanism; FC21 has no such existing client mechanism — pushing data into a real device's file/record slot is a genuinely new capability, not a shortcut around one that already exists. **Always check whether the client already has an equivalent before defaulting a new write-FC to server-only by analogy.**

Corrected design: client gets a real write path via `transactions/<file_number>:<record_number>` (hex content, colon-separated, same "extend `transactions/`'s own parsing" precedent `MASK` established). `report/` now covers file records too (reverses the earlier exclusion — a client-initiated FC21 write has a real device round trip that can genuinely fail, unlike the server's own always-succeeds direct write). Server validates every sub-request against static descriptions before touching `file_record_store`, same "no partial writes" invariant as FC17. Client's `confirm_file_record_write` compares the echoed sub-requests against what was sent (FC21 echoes the whole request, so a decodable-but-wrong echo must be caught, not just "not an exception"). **Deliberately does not update the client's own `FileRecordStore` on a confirmed write** — only `poll_file_records_once` ever writes that store, same single-writer discipline as the 2026-09-16 register/coil race fix.

**FC backlog: FC20 and FC21 both done.** FC18 (Read FIFO Queue) is the only one left.

## Planned: custom (vendor-specific) function codes (design resolved 2026-09-18, not yet implemented)

**Note (2026-09-28):** predates multi-machine support — whether `custom-function-codes.toml` should nest per-machine is an open question to resolve when implemented.

Motivation: real devices sometimes implement genuinely non-standard FCs (the user's own prior experience: an inverter with custom FC definitions, handled in Node-RED via `node-red-contrib-modbus`'s `flex-fc` JSON field-map). This adapts that idea, stricter.

**Scope: vendor-specific FC range only** (0x41-0x48, 0x64-0x6E, per spec's own reservation) — reinterpreting a *standard* FC is out of scope for now.

**Config: `custom-function-codes.toml`**, one file, `[[custom-function-codes]]`, each with `name`, `function_code`, nested `[request]`/`[response]` field lists (consolidated, not `flex-fc`'s separate request/response files):

```toml
[[custom-function-codes]]
name = "InverterStatus"
function_code = 65

[[custom-function-codes.request.fields]]
name = "Query_Type"
data_type = "u8"
value = 1

[[custom-function-codes.response.fields]]
name = "Frequency"
data_type = "u16"
```

**Stricter than `flex-fc`:** fields are **sequential and contiguous**, no explicit `offset` — eliminates overlapping/gapped layouts. Reuses the existing `DataType` enum. **Not yet resolved:** `DataType`'s multi-register byte-width padding convention may not apply to a raw custom-FC byte layout — needs its own mapping. Also not yet resolved: whether a custom FC also needs `server-options.toml` opt-in.

**Client (master):** builds the request from fixed `value`s, decodes the response into read-only FUSE files (`custom/<name>/<field-name>`), refreshed via polling.

**Server (never initiates):** dispatch recognizes the configured `function_code`, decodes the request into read-only files under `custom/<name>/`, and the **response fields become directly writable** (reuses the server direct-write model unchanged) — whatever was last written is what the server replies with next. New state: `CustomFunctionCodeStore` keyed by field name.

## Multi-machine device description & FUSE layout (resolved and implemented 2026-09-28)

Motivation: run several machines (one RTU multi-drop link, or several TCP targets) from one `client`/`server` instance instead of one process per machine.

**Schema: `[[machines]]` array-of-tables**, each with:
- `name` — unique, ASCII alphanumeric+`_`/`-` only (hard parse error otherwise — two machines sharing a name would collide on one FUSE inode).
- `unit_id` (`u8`) — **deliberate exception** to this file's "TOML describes data, CLI/config describes connection" separation: needed to tell multiple machines in one file apart.
- `server-id` (optional) — per-machine for the same reason (FC11 answers per Unit ID).
- Every other section nests one level down: `[machines.registers]`, `[machines.coils]`, `[machines.discrete-inputs]`, `[machines.input-registers]`, `[[machines.file-records]]`.

```toml
[[machines]]
name = "PumpA"
unit_id = 1
server-id = "pump-a-plc"

[machines.registers]
base_address = 40000
mem-layout = "abcd"

[[machines.registers.entries]]
name = "Tank_Temperature"
offset = 1
data_type = "u16"
access = "read_only"

[[machines]]
name = "PumpB"
unit_id = 2
```

**Breaking change** to the old single-machine format — accepted deliberately, no compatibility shim (nothing deployed yet).

**FUSE layout:** each machine gets its own top-level directory (`/PumpA/holding-registers/`, `/PumpB/transactions/`); `client-trust/` stays at the root, unaffected.

**`datafs` implementation:** `InfusedFilesystem` wraps a `Vec<MachineFs>` (`client-trust/` relocated unchanged). Each `MachineFs` computes inodes relative to its own `base: u64 = FIRST_MACHINE_INO + index * MACHINE_INO_STRIDE` (strides astronomically larger than any realistic dynamic growth, so machine ranges can never collide). `MachineFs` is no longer a `fuser::Filesystem` itself — `fuser::Reply*` types commit to the kernel the moment called, so inode rewriting must happen *before* dispatch, not by intercepting a reply after. `transaction_sender`'s channel item became `(machine_name, HashMap<String, StagedValue>)` — one consumer thread services every machine off one shared channel.

**Client:** mounts **all** machines by default — the concrete, simplest case first. A `--machines` subset allowlist remains a real, undecided follow-up (**still not implemented**). `run_polling_loop` needed zero changes (already fully per-machine parameterized) — `client::main` just spawns one polling task per machine.

**Server — the real non-trivial half.** `handler::handle_request` never received `unit_id` before this. **Confirmed with the user:** when an incoming request's `unit_id` matches no configured machine, the server sends **no response at all** — mirrors real RTU multi-drop behavior (an unaddressed slave stays silent) rather than synthesizing an exception for a case that isn't about the function code. FC43 answers with the whole multi-machine TOML **regardless of unit_id and without a machine lookup** — it's how a client bootstraps knowledge of every machine before knowing which unit_ids are valid. `transaction_consumer` is **name**-keyed (`HashMap<String, MachineStores>`), a deliberately *different* key from `handler.rs`'s **unit_id**-keyed map, since FUSE and wire addressing serve different purposes and must not be conflated.

**Relationship to FC43/FC20:** the one-file-many-machines schema is orthogonal to wire transfer — one multi-machine TOML is still served as one FC43 blob while under the ~31KB ceiling. **Revisited 2026-10-02 — see "Planned: grow FC43's device-description transfer capacity" below.**

## Client connection reconnect (resolved and implemented 2026-09-28)

Motivation: killing a running `server` left `client` spamming poll-failure logs forever with no recovery on restart — `Connection::connect_*` was only ever called once, at startup; every later I/O failure was logged/skipped, nothing ever redialed.

**Confirmed with the user:** exponential backoff, retries **forever** — no give-up cutoff.

**Detection is polling-only, deliberately not wired into the write path too.** Polling already runs continuously regardless of write activity, so it's the natural place to notice a break quickly — all 5 `poll_*_once` functions call `ReconnectSignal::mark_broken()` in their existing I/O-error branch. The write path needed no changes: a write against a broken connection already correctly reports `WriteStatus::Failed`, and the next write after polling heals the connection just succeeds — wiring reconnect-detection into the write path too would require distinguishing a genuine I/O failure from a Modbus exception/decode error inside an already-stringified reason, which isn't cleanly available there.

**`client::reconnect`:** `ReconnectSignal` (`Notify`+`AtomicBool`, `mark_broken()` idempotent — several simultaneous poll failures collapse into one reconnect attempt). `redial()` is the shared per-scheme connect dispatch (fallible, unlike the startup connect which still panics on the *first* failed attempt). `run_reconnect_loop()` backs off 1s→30s doubling, forever, then swaps the fresh `Connection` into the shared `Arc<Mutex<Connection>>` in place — no "retry the failed request" step needed.

**Accepted, self-correcting race:** failures landing against the old connection while a redial is in flight can cause one extra, instantly-successful "reconnect" right after a successful swap — shows up as one harmless extra log line, not worth a generation counter to fully close.

## Pluggable data-representation layer — FUSE vs. flat files (resolved and implemented 2026-09-29)

**Motivation:** FUSE carries real, structural problems inherent to how FUSE works, not implementation bugs: every `read()`/`write()`/`getattr()` round-trips kernel VFS ↔ userspace daemon, which has to hand-reimplement filesystem semantics a real filesystem already gets right. What's not given up: `holding-registers/Tank_Temperature` is still a real file any tool can `ls`/`cat`/`echo >` — both layers present the identical directory shape, only *how* it's served differs.

**Core idea: stop reimplementing what the kernel already does correctly.** `datafs::flatfile` renders Modbus data as real files on a real filesystem (any directory the operator points `--data-representation-layer files <root>` at), kept current via `inotify`/atomic `rename()` instead of a custom `fuser::Filesystem`.

**Confirmed: the Modbus-facing half of the codebase needed zero changes** — `transaction_consumer`/`polling`/`handler` and `protocol` only ever depended on `datafs`'s stores and the tagged channel, never knew FUSE existed. This was the design's central bet and it held through implementation.

**Crate rename:** `fuse-fs` → `datafs`, mechanical. No `datafs::stores`/`datafs::fuse` split happened — `flatfile.rs` was just added as a sibling module; revisit only if the flat layout becomes confusing in practice.

**Change detection — a plain poll, not the originally-planned `Notify`.** Push-based change detection would've meant touching every `store.set()` call site across `client`/`server`, well outside `datafs::flatfile`'s own scope. What shipped: every renderer exposes `render_once()`; `main.rs` calls it on a **200ms interval**, purely local, never gated on a Modbus round trip. Each renderer caches its last-rendered content per entry, so an unchanged value costs no syscalls.

**Write side — `inotify`, not `write()`/`release()`.** `FlatfileTransactionWatcher` (client) watches `transactions/` for `IN_CLOSE_WRITE` (stage)/`IN_CREATE` of `TRANSACTION_END` (commit), draining into the same channel — reuses parsing functions extracted out of `filesystem.rs` into free functions so both layers share identical staging logic. `FlatfileDirectWriteWatcher` (server) watches writable directories for `IN_CLOSE_WRITE`, sends each as its own implicit transaction immediately.

**The detail that prevents a feedback loop, without tagging event origin:** the renderers' own updates go through `rename()`, reported by the kernel as `IN_MOVED_TO`, never `IN_CLOSE_WRITE`. A genuine user write always goes through `open()+write()+close()` → `IN_CLOSE_WRITE`. Watching only `IN_CLOSE_WRITE` on writable paths structurally can't mistake the renderer's own writes for user input.

**Two documented, not-fixed capability gaps:** (1) FUSE's `create()` can reject an unknown `transactions/<name>` target immediately (`ENOENT`); a real filesystem has no such hook, so `echo` always succeeds under `files` and the stray file is removed only *after* the fact. (2) `AccessRight`-based read-only enforcement for `holding-registers/<name>` on the server is application-level only, for the same reason — unlike `client-trust/`'s permissions, which are genuinely kernel-enforced (a fixed mode set once, not a per-register right that must survive every atomic-rename swap).

**Permissions:** `fuse-permissions.toml`'s `mode`/`uid`/`gid` become real `chmod`+`chown` on the same scope `FusePermissions` always had. `client-trust/` is unconditionally `0o700`/`0o400`. **Gap:** `chown()` to a non-default uid/gid needs `CAP_CHOWN`, unlike FUSE's synthetic `getattr` — `EPERM`s unless the server process has that privilege (the common mode-only case never hits this).

**CLI:** `--data-representation-layer <fuse|files>`, **`files` is the default** (breaking change, same stance as every other breaking default here). The positional mountpoint argument was renamed `<root>`. On clean shutdown, `files` `remove_dir_all`s `<root>`, mirroring FUSE's unmount.

**Loose end:** `--fuse-permissions` kept its FUSE-specific name even though it now applies to both backends — a rename to something backend-neutral remains a candidate follow-up.

## MQTT (Sparkplug B) representation layer (design resolved 2026-09-30, M1-M10 implemented + TCK-conformant 2026-10-01, M11 docs done)

**Motivation:** after using both `fuse` and `files` in practice, the user judged that a local filesystem projection isn't the right representation for this data at all — real races/round-trip overhead persist under both. This is a genuinely different representation: MQTT with **Sparkplug B** as the wire schema.

**Architecture:** `MQTT Broker <-> client <-> server`. The `client`↔`server` link is unchanged real Modbus (TCP/RTU/TLS); `client` additionally translates the device description into Sparkplug B session/metric data. (Originally the broker was embedded in `client` itself — **removed 2026-10-02, see below.**)

**Server-side data-update problem — "Option C" (library core + thin daemon, FFI deferred):** researched how real Modbus slave implementations solve "how does the server's own dataset get updated cross-process" — `pymodbus`/`libmodbus` both assume same-process access; where cross-process was needed, real examples split into REST API or watched/polled files; no real example uses MQTT to feed a slave's own dataset (every MQTT↔Modbus bridge sits on the master/gateway side, our `client`'s role, never the slave/`server`'s). **Decision: `ServerHandle`**, a plain safe-Rust library (no `unsafe`, no FFI) wrapping the same `MachineStores`+validation logic already used elsewhere — one place implementing "set a register by name, validated, synchronous `Result`" instead of duplicated logic. `server`'s binary becomes a thin wrapper: `ServerHandle` + Modbus listener + a small Unix-socket daemon forwarding into the same handle. An FFI (`cdylib`) shim for embedding into a non-Rust host is **explicitly deferred, not ruled out** — no concrete non-Rust consumer exists yet, and it would mean real `unsafe extern "C"` boundary work (pointer lifetimes, `catch_unwind` at every entry point) for nothing yet needing it.

**TOML schema additions, motivated by MQTT but generally useful:** researched Homie 5/Sparkplug B/Home Assistant Discovery for self-description metadata beyond raw name+datatype. Adopted per-value: `unit`, `device_class` (reuses HA's controlled vocabulary), `format`/valid range, `display_name` (separate from the machine-safe `name`), `icon`, `precision`, `state_class`, `expire_after`. Per-machine (`[[machines]]`): `manufacturer`, `model`, plus availability fed by `ReconnectSignal` (maps onto Sparkplug NBIRTH/NDEATH). All optional, zero behavior change if omitted.

**`unit`, decided 2026-10-02: UN/ECE Recommendation 20 Common Codes, not free text.** OPC UA's own `EUInformation` uses exactly this standard for engineering units — a real, already-adopted precedent in this exact domain, same reasoning `device_class` reuses HA's vocabulary rather than inventing one. Licensing: multiple independent secondary sources cite the code lists as PDDL v1.0 (unece.org itself blocked automated fetching); independently, a code-to-meaning table is a list of facts, same practically-unencumbered category as ISO 4217/IATA codes. **Embed the complete Rec. 20 list** (from `datasets/unece-units-of-measure`, ~175KB raw CSV) and hard-validate at parse time — an intentionally incomplete subset would reject genuinely valid codes, undermining the point of validating at all.

**Schema format: Sparkplug B, chosen over Homie 5 and Home Assistant Discovery — from evidence.** Sparkplug B has an official FlowFuse implementation guide, actively-maintained Node-RED packages, and real integration guides tied to specific industrial PLC hardware — squarely this project's target audience. Homie's Node-RED ecosystem is more fragmented and smart-home-leaning; HA Discovery has no real industrial Node-RED presence at all. Reverses an earlier lean toward Homie (simpler, no protobuf) — ecosystem fit won over implementation simplicity.

**Dependencies:** embedded broker was `rumqttd` (pure Rust, purpose-built for embedding) — **since removed from production, see below.** Sparkplug B protocol itself (protobuf codec + session/topic/sequence semantics) is **self-implemented**, not `lb-sparkplugb-rs`/`sparkplug-rs`/`srad` — the first was judged genuinely immature; the other two are viable but the user chose to self-implement once informed, reasoning that (unlike TLS) Sparkplug's protobuf encoding is not cryptography, the specific danger class that justified reaching for `rustls` instead of hand-rolling. The harder conformance burden (seq/bdSeq sequencing, NBIRTH/NDEATH/rebirth) wouldn't have been solved by `sparkplug-rs` either way (raw bindings only) — only `srad` covers it, and that's exactly where its smaller community made self-implementing preferable.

**No pluggable schema-format abstraction yet, deliberately** — Sparkplug B is the only concrete implementation; a `SchemaTranslator`-style trait isn't built until a second real format needs it (Extraction-Based Programming).

**Implemented in 11 milestones** (protobuf wire primitives; Sparkplug `DataType`/`MetricValue`; topic namespace + broker plumbing; NBIRTH/NDEATH session lifecycle; DBIRTH/DDEATH per machine + the Modbus↔Sparkplug type mapping; NDATA/DDATA incremental publishing; DCMD write path reusing the transaction-consumer channel; rebirth handling; CLI wiring + `ServerHandle` daemon; TCK conformance testing; docs) — `sparkplug` crate has zero dependency on `protocol`/`datafs`, the Modbus↔Sparkplug mapping lives entirely in `client`. See git log for the module-by-module detail (`client::broker`/`edge_node`/`sparkplug_alias`/`sparkplug_translator`/`sparkplug_change_tracker`/`sparkplug_command`).

**M10 TCK conformance — real bugs found and fixed**, verified directly against the official Sparkplug TCK (built from source; its web console never reliably worked, bypassed by driving its MQTT control protocol directly from a throwaway example instead — see `client/examples/tck_control.rs`):
1. **`bdSeq` reused `0` on every process restart** instead of incrementing across sessions, defeating its whole purpose (letting a Host Application tell a new session's NBIRTH apart from a stale NDEATH). Fixed via `client::bd_seq_persistence` — a small file (`client-mqtt-bdseq`) persisted atomically, next-value-plus-one, falling back to `0` with a warning on I/O failure.
2. **QoS.** Active publishes (NBIRTH/DBIRTH/DDATA/NDATA/DDEATH) were sent at QoS 1; spec requires QoS 0 for every one. The Will-carried NDEATH correctly stays QoS 1.
3. **Missing `Node Control/Rebirth` metric in NBIRTH** — spec-required on every NBIRTH, `Boolean false`, deliberately **no alias**.
4. **Missing per-metric `timestamp`** — only the payload-level timestamp was modeled; spec requires one per metric too.
5. **A real missing capability, not a bug:** an Edge Node configured to wait for a Primary Host must verify it's online (via that host's retained `STATE` topic) before publishing NBIRTH/DBIRTH — previously never implemented (`sparkplug::topic` had assumed this project never needs to *subscribe* to a STATE topic, only reasoned about *publishing* one). Implemented as an opt-in `--mqtt-primary-host-id` that blocks on that host's `online:true` before birthing.

**Result: `OVERALL: PASS` — every assertion `SessionEstablishmentTest` runs now passes** ("INCOMPLETE" is the test harness self-ending after one birth cycle, not a gap on our side). Only the Edge Node/Device TCK profiles are applicable here (this project never builds a Host Application); only `SessionEstablishmentTest` has been run so far, not because of a known gap but because it's the only one exercised yet.

**Independent cross-check:** a persistent `nodered-sparkplug-test` Docker container (Node-RED + an independent Sparkplug B JS implementation, kept running for future ad hoc testing — see memory) round-tripped real server writes → decoded DDATA and a Node-RED DCMD → real Modbus write.

## Embedded MQTT broker removed — `client` now requires an external broker (resolved and implemented 2026-10-02)

**Revises the architecture above.** Revisited once the user wanted to reduce the dependency footprint and was unwilling to run any broker at all in production. Confirmed: Sparkplug B is pure MQTT plus a topic/payload convention — nothing requires the broker to live in the Edge Node's own process, and `--mqtt-external-broker` (built for the TCK) was already proof the Edge Node works fine against a broker it doesn't own.

**What changed:** that flag is renamed `--mqtt-broker <host:port>` and is now **required** under `mqtt` (panics with a clear message if missing) — no more embedded fallback. `--mqtt-broker-config` is removed entirely. `rumqttd`/`client::broker` are kept only for the test suite (`rumqttd` moved to `[dev-dependencies]`, `client::broker` is `#[cfg(test)]`) — not part of the production binary.

**Dependency impact (the actual motivation):** `rumqttd` was by far the heaviest dependency in `client`'s graph (its own storage engine, raft-adjacent clustering code, none of it used beyond loopback single-node). `rumqttc`'s default `use-rustls` feature was also dropped — the MQTT connection is always plaintext here (TLS exists only for the Modbus wire link via this project's own pinned `rustls`), so `rumqttc`'s TLS feature was dead weight transitively linking a second crypto provider. `cargo tree -p client -e normal` shrank from 883 to 260 lines; `aws-lc-rs`/`rumqttd` are both gone from production.

**For local testing without an embedded broker:** `examples/mqtt-broker` provides a disposable Mosquitto container.

## Planned: a Node-RED plugin that auto-builds dashboards from a device description (flagged 2026-10-02, details deferred)

Motivation: after hand-building `examples/nodered/`'s "Rolling Door" dashboard (hand-wired to one specific device), the user asked whether `device-description.toml` could drive *automatic* dashboard generation.

**Architectural call made:** `client` stays dashboard-agnostic (consistent with the broker-agnostic MQTT stance above). The generator is a **separate Node-RED plugin** consuming only standard Sparkplug B traffic (NBIRTH/DBIRTH/DDATA), never the TOML directly — usable against any Sparkplug Edge Node.

**A real blocking gap:** Sparkplug's `Metric.properties` (arbitrary per-metric key/value metadata — the spec's actual mechanism for units/display hints/etc.) is **not implemented** in the `sparkplug` crate yet. Without it, a generator has only name/datatype — not enough to choose gauge-vs-switch-vs-text or know units/ranges.

**Rough shape, to be planned in detail later:** (1) implement `Metric.properties` in `sparkplug`, populate it per metric from the TOML metadata fields above; (2) a genuine Dashboard 2.0 third-party widget (not flow-mutation via the Admin API, which was only ever a manual-testing shortcut) — one Vue component rendering a sub-widget per metric at runtime, with its own alias→name bookkeeping mirroring `AliasAllocator`'s reverse lookup. Package naming, the exact v1 property set, and multi-machine→multi-page layout are open questions for a dedicated planning session.

## Planned: grow FC43's device-description transfer capacity past its current ~31KB ceiling (flagged + fully designed 2026-10-02, not yet implemented)

Motivation: the planned per-value metadata fields make `device-description.toml` meaningfully bigger, pushing real deployments closer to FC43's existing ceiling.

**The numbers:** FC43's 127 private object IDs (0x81-0xFF) × 244-byte chunks ≈ **31KB ceiling** — a hard limit from the spec's own object-ID range, not something this project can widen. Today's demo file is well under 8% of that. A back-of-envelope check of a single moderately-equipped machine (50 points/table) already reaches **47%** of the budget for one device; scaled to a 255-device deployment it's roughly two orders of magnitude over. FC20 (Read File Record) has essentially the same per-message size (~249 bytes/response) but far deeper addressing (`u16` file/record numbers, ~65536 records/file) — it fixes the *ceiling* but not the *round-trip count* at scale (thousands of round trips for a large deployment, even with FC20). Compression (measured on real files via gzip) gets 2.85×-14× depending on repetitiveness, but can't fix the address-space ceiling alone — the large-scale case needs both FC20's address space *and* compression.

**Also a robustness gap, independent of size:** today's `build_objects` hits an `assert!` (process panic) once a description doesn't fit — not a clean Modbus exception. Worth fixing regardless of the capacity work (see Thread A2 in the milestone plan below).

**Candidate architecture, decided:** FC43 serves a small **manifest** (machine name, unit_id, a reserved `file_number` pointer, byte length) instead of the full blob; the client fetches only what it needs via FC20, using the manifest's length to compute `ceil(length / 249)` records up front — sidesteps FC20's lack of FC43's own continuation mechanism entirely. Manifest size scales with **machine count**, not **point count**.

**Two real limitations found, not yet resolved:** (1) selectivity has no payoff against today's "mount every machine" client behavior until either `--machines` or Sparkplug subscription (see next section) exists — until then, a manifest+per-machine fetch is a net round-trip *regression* for the common case. (2) whole-file compression and per-machine selective fetch are in direct tension — a compressed stream isn't randomly seekable, so compress-the-whole-blob (best ratio, all-or-nothing) and fetch-machines-selectively (needs independently-decodable units, worse ratio) can't cleanly both happen at once.

**Decided: compress the whole multi-machine blob as one unit (option "a"), with an explicit escape hatch to a shared-preset-dictionary per-machine scheme ("c") later if selective fetch ever gets a real consumer.** Fixes the measured problem (round-trip count) with the least complexity and matches today's actual client behavior. A plain independent-per-machine-compression middle option ("b") is dropped entirely, not deferred — it would only ever be a strictly-worse stepping stone to (c).

**Resolved detail decisions:**
- **Compression crate: `miniz_oxide` (DEFLATE), used directly, not via `flate2`.** Chosen over `ruzstd`/Zstandard: pure Rust (no C bindings, per the user's explicit criteria), far more mature/depended-upon (72.5M downloads/month vs. 6.2M), and its own docs admit the zstd compressor side doesn't yet match the reference implementation — a real maturity gap on exactly the side (compression) this project needs server-side. Used directly since this project only ever compresses one whole in-memory string at startup, never streams — `flate2`'s `Read`/`Write` adapters and extra `crc32fast` dependency buy nothing here. The ratios already measured via Python's `gzip` transfer directly (same DEFLATE format).
- **When: once, at server startup, cached for the process's lifetime** — the TOML never changes afterward, unlike `build_objects` which is cheap enough to recompute per request.
- **Scope: the new FC20 bulk-transfer path only** — the existing small-file FC43-inline-chunk path stays completely untouched.
- **Decompression failure** folds into FC43's existing fallback chain (any failure → client falls back to its local TOML) — no new failure philosophy needed.
- **Reserved `file_number` collision: hard parse-time validation**, not "unlikely enough" — a user's own `[[file-records]]` entry reusing the reserved number must be a hard TOML parse error. Same bug *class* already caught once during FC20's own implementation (the `file_records_ino`/`client_trust` inode collision) — worth remembering so it isn't repeated. Which specific number(s) to reserve is still unchosen.
- **`server-options.toml` gating: a brand-new dedicated toggle, `detect_machine_layout`** — considered tying it to `read_device_identification` (would need FC20's handler to sub-dispatch by `file_number` against two different gates, finer-grained than this project's gating has ever needed) or requiring both `read_device_identification`+`read_file_record` (conflates two independent technician choices) — a dedicated toggle avoids both.
- **Future idea, not scoped:** a build-time macro embedding `device-description.toml` directly into the binary — a real deployment-model change, worth its own design session later.

## Planned: dynamic per-machine subscription via Sparkplug B (flagged + spec-verified + fully designed 2026-10-02, not yet implemented)

Motivation: the manifest+per-machine-fetch idea above has no payoff while `client` mounts every machine by default. Since this project now has Sparkplug B, the user asked whether a Host Application could dynamically choose which machines to activate at runtime, making *that* the real consumer for selective fetch (scoped to the `mqtt` layer only).

**Key distinction:** *consumption-side* selectivity (any MQTT consumer can already subscribe to just the topics it wants) is free today but does nothing for `client`'s own Modbus/FC43/FC20 cost. *Production-side* selectivity — `client` itself only fetching/polling/publishing a subset — is what actually matters here and requires `client` to be told which machines to activate.

**Uses sanctioned Sparkplug extension points, not a protocol redefinition** — checked against the real spec text and the TCK's own test source, not recollection: free-form metric names inside NCMD/DCMD (only a handful of names are spec-reserved, structurally identical to FC43's private object range), `Metric.properties`, and DataSet-typed values are all legitimate places to carry this.

**A real conformance risk found by checking the spec, not assumed:** the original sketch (defer a machine's DBIRTH until "subscribed," while other machines already flow DDATA) collides with a literal spec MUST — once *any* DDATA has been published, no further DBIRTH is conformant for the rest of the session. The TCK's own `SessionEstablishmentTest` structurally can't catch a violation of this (it only tests a fixed device list and ends after one birth cycle), but a stricter real Host Application reasonably could. **Resolution, found in the same spec chapter:** DBIRTH must include *all* metrics a Device will ever publish, with `is_null=true` where there's no current value yet — the spec's own sanctioned mechanism for exactly this. Revised design: publish full DBIRTH for *every* machine immediately (`is_null=true` placeholders, no real Modbus fetch needed), and defer only the *expensive* part (FC20 fetch, Modbus polling, real DDATA) until subscribed. Achieves the original goal without touching DBIRTH ordering semantics. This requires `Metric.is_null`, also not yet implemented in `sparkplug`.

**Decided: build both, split by representation layer, not as alternatives.** A static `--machines <names>` flag (optional, defaults to everything, unknown name logs-and-continues) for `fuse`/`files` — both mount synchronously at startup, a natural fit for a static choice. Under `mqtt`, `--machines` is not required at all — selection happens entirely at runtime via a custom Subscribe/Unsubscribe NCMD metric instead.

**Bootstrapping:** `client` fetches every machine's *definition* at startup unconditionally (needed anyway, since DBIRTH must declare full metric shape up front) but starts polling/producing real DDATA for a machine only once subscribed. "Nobody ever subscribes" is a valid, inert default — no special-casing needed.

**Granularity: per-machine for v1, explicitly not the final word** — matches `run_polling_loop`'s existing one-task-per-machine architecture (subscribed just gates whether that task is spawned). The user has flagged per-register/per-value granularity as a near-certain future direction; the Subscribe payload shape should leave room for it (`{machine, points: [...]}` with empty/omitted `points` meaning "the whole machine") without building per-point activation now.

**Unsubscribe/DDEATH:** implemented symmetrically — stops that machine's polling task, publishes DDEATH. Unsubscribing the *last* subscribed machine returns the whole client to the dormant bootstrap state (zero Modbus traffic, waiting for a new Subscribe); the Edge Node's own Node session (NBIRTH) stays up throughout, since Node/Device lifecycles are already independent per spec.

**DataSet metric type: implement as a general `sparkplug` crate capability**, not scoped narrowly to the manifest — this project will need richer metric types regardless (per-value metadata, custom-FC structured fields); the manifest is simply its first concrete consumer.

**`--machines` unknown-name handling: log and continue**, not a hard startup error — matches the "unknown machine name: log and drop" precedent already established elsewhere (`transaction_consumer`, `sparkplug_command`).

## Implementation milestone plan for the three design threads above (planned 2026-10-02; Thread B implemented 2026-10-03)

Everything above (FC43 capacity + Sparkplug selective subscription + UN/ECE `unit`) is fully designed. **Thread B is done; Threads A/C/D have not started** — Thread A is next per the suggested order below.

**Four largely-independent threads, suggested execution order:**

### Thread B — `sparkplug` crate foundations (done 2026-10-03; was needed first since Thread C depends on it)
- **B1.** ✅ `Metric.is_null` (field 7) — wired into `encode_metric`/`decode_metric`, protobuf implicit-presence (omitted when `false`). `sparkplug/src/metric.rs`.
- **B2.** ✅ `Metric.properties` (field 9) — new `sparkplug::property` module (`PropertyDataType`, a genuinely different numbering from `Metric`'s own `DataType` — flagged explicitly in a doc comment and a dedicated test; `PropertyValue`/`Property`/`PropertySet`), wired into `Metric`.
- **B3.** ✅ DataSet metric value type (field 17 of `Metric.value`) — new `sparkplug::data_set` module (`DataSetValue`/`Row`/`DataSet`; `types` reuses `Metric`'s own `DataType`, unlike `PropertyDataType`), wired into `MetricValue`. `num_of_columns` deliberately not modeled (redundant with `columns.len()`, same convention as `WriteMultipleRegistersRequest`).

All three landed as separate reviewed commits (`36229bd`, `312b1ef`, `bd93e7b`, `2a20592`, `3140b0f`, `b046f41`); 961 workspace tests pass. Not yet exercised by any real consumer (no concrete need forced it yet, per Extraction-Based Programming) — Thread C (B1) and the Node-RED dashboard plugin (B2) are the planned first consumers.

### Thread A — FC43 capacity fix (server/protocol-level, applies to all three representation layers)
- **A1.** `detect_machine_layout` toggle: schema + parsing in `server::server_options`, wired into the gate.
- **A2.** Fix the existing `assert!` panic in `device_identification::build_objects` to a clean Modbus exception — independent of the rest of this thread's timing.
- **A3.** Decide and hard-validate the reserved `file_number`: parse-time rejection on collision with a user's own `[[file-records]]`.
- **A4.** Add `miniz_oxide`, compress the full TOML once at server startup (gated by `detect_machine_layout`), cache for the process's lifetime.
- **A5.** Server: when the full TOML exceeds FC43's budget, serve the small manifest via FC43's existing object mechanism instead — the existing inline-chunk path stays untouched for anything that still fits.
- **A6.** Server: FC20 dispatch for the reserved `file_number`, serving the cached compressed blob in chunks — a dedicated code path, not a reuse of `handle_read_file_record`'s static-declaration validation.
- **A7.** Client: detect which FC43 response shape it got; if manifest, fetch via FC20 using the known length, decompress, parse as the real TOML. Any failure at any step falls back to the local TOML file argument.

### Thread C — Sparkplug-driven selective subscription (`mqtt` layer only; needs B1 at minimum)
- **C1.** `--machines <names>` for `fuse`/`files` — simple, no dependency on anything else here; could land first if a quick win is wanted.
- **C2.** Client (`mqtt`): fetch every machine's full definition at startup (via Thread A once it exists, or today's plain FC43 fetch for small descriptions) and build each machine's full metric list.
- **C3.** Client: publish full DBIRTH per machine immediately with `is_null=true` (needs B1) — no polling yet.
- **C4.** Define the Subscribe/Unsubscribe NCMD metric convention — forward-compatible payload shape for later per-point granularity.
- **C5.** Wire Subscribe → spawn that machine's existing polling task (no changes to its batching logic).
- **C6.** Wire Unsubscribe → stop the polling task, publish DDEATH; unsubscribing the last machine returns to the dormant state.

### Thread D — UN/ECE `unit` field (mostly independent, can slot in anywhere)
- **D1.** Pull the code list from `datasets/unece-units-of-measure`, build an embedded Rust table (code → name), source comment crediting UN/CEFACT Rec. 20.
- **D2.** Add `unit` to the per-value TOML schema, hard-validated against the full embedded table at parse time.
- **D3. (later, depends on B2):** expose `unit` as a Sparkplug `Metric.properties` entry.

**Cross-thread note:** A and C are independent in principle, but C2 benefits directly from A for genuinely large deployments — build B → A → C in that order to avoid C needing its own throwaway "fetch a big description" before A provides the real one.

## Programmatic Rust API for `ServerHandle` — typed `set_*`/`get_*`, before any FFI layer (resolved and implemented 2026-10-01)

**Motivation:** build a pure Rust programmatic API first, deliberately without FFI (FFI comes later as its own step). Requirement: an embedding Rust application should get type safety — a `u16` register should only accept a `u16` value, not an arbitrary parseable string.

**Typed API added**, one pair per point kind, operating on `RegisterValue`/`CoilValue` instead of raw strings: `set_register`/`get_register`, `set_coil`/`get_coil`, `set_discrete_input`/`get_discrete_input`, `set_input_register`/`get_input_register`, `set_file_record`/`get_file_record` (still `Vec<u8>` — vendor-specific opaque blobs, no narrower type to enforce). A type mismatch gets its own `ServerHandleError::TypeMismatch`, distinct from `InvalidValue` (a string that doesn't parse at all). The original string-based `set`/`get` (still needed by `data_daemon`'s text socket) now just parse and delegate to the typed methods — one place parses, one place validates.

**Listing/introspection:** `registers`/`coils`/`discrete_inputs`/`input_registers`/`file_records`/`machine_names()` expose the declared descriptions directly, so a caller can discover what exists without hardcoding names.

**A real pre-existing bug caught and fixed along the way:** the original string-based `set` unconditionally rejected writes to discrete-inputs/input-registers with `ReadOnly` — directly contradicting the already-shipped server direct-write model, which makes both directly writable *locally on the server* (never over the wire, never on the client — the server has nothing else to populate them). Root cause: logic carried over unreviewed from before the typed API existed. Fixed by giving both real `set_discrete_input`/`set_input_register` methods.

**Scope: server-side only**, confirmed explicitly — no client-side equivalent exists or is planned. The `cdylib`/C-ABI FFI shim remains queued, unstarted, and explicitly not combined with this step.

## `server-options.toml` — explicit per-function-code opt-in (design resolved 2026-09-18, implemented 2026-09-24)

Motivation: every FC `server` implements is attack surface exposed to *any* reachable Modbus master, not just a trusted one (`server`-only concern — `client` only ever sends FCs it itself chooses). Surfaced concretely while discussing FC21: a generic file-write primitive is dangerous less because of what it does on the wire and more because of what "file" might eventually be backed by. Rather than deciding per-FC "implement or don't," every FC's *availability* becomes an explicit technician choice.

**Schema:** `server-options.toml`, `[function-codes]` table, one boolean per FC, named after the operation (e.g. `read_coils`, `write_single_register`, `report_server_id`, `read_file_record`, `write_file_record`, `mask_write_register`, `read_write_multiple_registers`, `read_fifo_queue`, `read_device_identification`). The four out-of-scope serial-diagnostic FCs never appear here.

**Default policy: strict default-deny, no legacy exemption** — even already-implemented FCs default to disabled unless explicitly `true`. A deliberate behavior-breaking decision: an existing deployment must list what it needs, or the server rejects everything. Unknown keys are a hard parse error (same discipline as `fuse-permissions.toml`'s `client-trust` rejection).

**CLI:** `--server-options <path>`, optional — omitted behaves like present-but-empty (everything disabled). `server` prints a loud startup warning if zero FCs end up enabled (a forgotten flag is a real footgun).

**Wire behavior:** a disabled FC gets the same `ILLEGAL_FUNCTION` exception as a never-implemented one — deliberately indistinguishable, so a remote peer can't fingerprint "implemented but disabled" from "never implemented." Composes cleanly with FC43's existing client-side fallback (a disabled FC43 just looks like any other fetch failure).

**This is what makes FC21 implementable at all** — its risk is mitigated by requiring explicit opt-in rather than the on-by-default posture every other FC had until now.

**Implementation:** `server::server_options::ServerOptions` (server-only module), parsing mirrors `FusePermissions`'s `deny_unknown_fields` pattern. The gate lives at the top of `handle_request`, before the FC `match`. `ServerOptions` is `Copy` (plain bools), threaded by value like `MemLayout` already was. `#[cfg(test)] ServerOptions::allow_all()` exists so the ~40 pre-existing handler tests didn't need a hand-written permissive TOML.

## TLS transport security & client trust (resolved and implemented 2026-09-17/18)

**Only incompletely verified piece: T4** — manual confirmation that `fuse-permissions.toml` enforcement is real under a genuinely *different* UID was never performed (needs a second real user account on the test machine, never available). Every other milestone's manual check was performed; the code is correct by inspection/review, but this one specific cross-UID check is still outstanding.

Motivation: Modbus TCP is unencrypted and trivially sniffable. A full CA-based setup was rejected as too much certificate-management burden for a technician — this design gets real TLS cryptography without a CA hierarchy, plus per-client connection control.

**Transport is mutually exclusive:** `tls+tcp://` sits alongside `tcp://`/`rtu://` — never combined, removing any plaintext-fallback path and ensuring RTU can't bypass an active TLS config on the same instance. TLS itself is `rustls`, not hand-rolled — this project's "from scratch" philosophy applies to Modbus, not cryptography.

**Identity: self-signed keys + fingerprint pinning instead of a CA.** Both sides generate a self-signed keypair on first run. Trust is based **only** on the raw SHA-256 public-key fingerprint — other certificate fields are attacker-controlled since a peer signs its own cert. Modeled on SSH host-key TOFU rather than PKI. Rejected alternatives: a custom ECDH+AEAD scheme (designing a correct handshake from scratch is exactly the failure-prone territory TLS exists to avoid, and would still need to keep MBAP length unencrypted / recompute RTU's CRC over ciphertext); TLS 1.3 PSK mode (viable, but gives no per-client connection control).

**Server authentication:** the client is given the server's expected fingerprint once, out of band, and verifies every connection against it.

**Client authentication — mutual TLS with a fail-closed, filesystem-visible approval workflow:** unknown/unapproved client fingerprints fail the handshake outright (observed/logged before rejection). `client-trust/` is a FUSE subtree that exists **only** in the server's filesystem (`Option<Arc<Mutex<ClientTrustState>>>`, `None` on the client) — the first asymmetric FUSE feature in the project.
- `connection_attempts/{approved,pending,rejected}.log` — three **fixed** ring-buffer logs, never one file per attempt (avoids unbounded inode growth from attacker-controlled input).
- `approved/` — read-only mirror of the approved fingerprint set; not a write target, unlike `transactions/` — granting network access was judged a different trust level than writing register data, so it doesn't share that write mechanism.
- **Approval/revocation channel:** a Unix socket (mode `0600`, `SO_PEERCRED`-verified in addition to file permissions), wrapped by `server admin approve|revoke|list <fingerprint>`. Revoking a fingerprint actively terminates any already-open connection using it, not just blocks future handshakes. Checking the approved count against `--max-clients` and inserting a new approval happens inside **one held lock** — never two separate acquisitions, to avoid a race past the configured limit.

**Capacity:** `--max-clients N` bounds concurrently-valid approved fingerprints (a connection/operational detail via CLI, not the device TOML).

**Persistence — the first durable server state.** Every other runtime state here (`RegisterStore`, `PendingTransaction`, `WriteReport`) is deliberately in-memory only. Approvals are the deliberate exception — losing them on every restart is a real availability problem. Persisted to a flat file via atomic temp-file-plus-rename, `0600`, read **once at startup only**, never hot-reloaded — all live changes must go through the approval channel that owns writing it.

**FUSE permissions:** `fuse-permissions.toml` lets the technician set `mode`/`uid`/`gid` per top-level directory, enforced via the `default_permissions` mount option. `client-trust/` **cannot appear in this schema at all** (hard parse error if attempted) — always hardcoded `0o700`, owned by the server's own real UID/GID.

**DoS hardening**, applied one layer earlier than existing PDU-length checks: a timeout on the TLS handshake itself (separate from per-I/O-step timeouts); a global cap on concurrent in-flight connections/handshakes; a **per-fingerprint** concurrent-connection cap (so one already-approved client can't exhaust the pool alone). Full protection against a distributed multi-source flood is explicitly out of scope — upstream infrastructure's job, not the application layer's.

## Planned architecture

The project is a **Cargo workspace** with these crates:

- **`protocol`** — the Modbus protocol implementation (TCP + RTU), from scratch, not a wrapper around `tokio-modbus`.
- **`datafs`** (renamed from `fuse-fs` 2026-09-29) — the data-representation layer shared by client and server: `holding-registers`/`transactions` logic, TOML device-description parsing, filesystem-op ↔ Modbus mapping, for both the FUSE and `files` backends.
- **`sparkplug`** — a from-scratch Sparkplug B implementation (protobuf wire format, `DataType`/`MetricValue`, `Metric`/`Payload`, topic namespace, session/sequence semantics). No dependency on `protocol`/`datafs` — the Modbus↔Sparkplug mapping is `client`-side glue.
- **`client`** — binary; thin entry point wiring `protocol` (master) + `datafs`/`sparkplug` together.
- **`server`** — binary; thin entry point wiring `protocol` (slave) + `datafs` together.

## Key technical decisions

- **Async runtime**: `tokio`, across protocol I/O and FUSE update handling.
- **FUSE bindings**: `fuser` crate.
- **Modbus protocol**: implemented from scratch in `protocol` (no `tokio-modbus`).
- **Target platform**: Linux-only for now (FUSE). Portability (e.g. WinFsp) is a desired future goal, not a current constraint — avoid over-engineering for it prematurely.
- **Device description vs. connection config**: kept deliberately separate — TOML describes *data shape*, CLI/config describes *how to connect*.

## Working conventions

- **Small, reviewable increments**: implement one method/function/struct at a time, then stop for review before moving to the next. Do not batch multiple units into one unreviewed change.
- **Extraction-Based Programming (Casey Muratori)**: write the concrete, specific solution first. Don't introduce an abstraction speculatively — only extract one after the same concrete pattern has actually shown up.
- **Testing**: most functions get regular unit tests. Interaction/integration-level behavior is tested via this project's own custom fuzzer, not an off-the-shelf fuzzing crate.

## Development commands

```sh
cargo build --workspace
cargo test --workspace
cargo test -p <crate-name> <test_name>   # run a single test in one crate
cargo clippy --workspace --all-targets
cargo fmt --all
```
