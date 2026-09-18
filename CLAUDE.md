# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

This repository is implemented and functional, not greenfield: a Cargo workspace with `protocol`, `fuse-fs`, `client`, and `server` crates, all building and tested. Both Modbus TCP and RTU are wired end to end for both binaries, covering transactions, FC 43 device-description discovery, coils, discrete inputs (FC 2), input registers (FC 4), and the full register data-type set (`u8`/`i8` through `f64`/`i64`, with configurable byte/word order). The server writes directly into `holding-registers/`/`coils/`/`discrete-inputs/`/`input-registers/` (no `transactions/` staging — see "server direct-write model" below); the client still stages writes via `transactions/`+`TRANSACTION_END`. See the repo's `README.md` for the current function-code support table and setup instructions, and `git log` for implementation history.

This document remains the architecture and design-decision record agreed on with the project owner — it captures *why* things are the way they are, not day-to-day implementation status, so treat it as authoritative for design rationale but check the actual code/tests for exact current behavior. Update it whenever a design decision is made or revised, including for features that are decided but not yet built (e.g. the TLS section below) — mark those explicitly as not-yet-implemented so they aren't mistaken for shipped behavior.

## What this project is

`infused_modbus` is a combined Modbus **client** and Modbus **server**, both of which expose the Modbus data they handle through a **FUSE filesystem** instead of (or in addition to) a conventional API. "Infused" refers to this live-updating FUSE projection of Modbus data.

- **Client**: acts as a Modbus master against a real PLC/device, continuously updates a local mirror of that device's data, and exposes it through FUSE.
- **Server**: acts as a Modbus slave that external Modbus masters (real PLCs) query/write against. Values it holds are mirrored into its own FUSE filesystem; when an external PLC writes a value, that change is reflected into FUSE so a local operator/process can see it.

Both Modbus TCP and Modbus RTU must be supported. **TCP is the first-class transport; RTU is supported but secondary** (resolved 2026-09-15) — TCP is the more common deployment today, so it gets the primary design/testing attention. RTU's framing in particular relaxes one part of the spec: frame boundaries are detected via the standard 3.5-character-time silence gap, but the stricter 1.5-character-time max-inter-byte-gap rule (a framing error if exceeded) is deliberately not enforced, since doing so reliably against a generic async runtime's scheduling would risk discarding valid frames over harmless jitter — see `protocol/src/rtu.rs`'s module doc comment. Both `client` and `server` support choosing TCP or RTU via a scheme-prefixed connection string (`tcp://<address:port>` / `rtu://<serial-path>:<baud-rate>`); everything built on top of the transport (transactions, polling, FC 43 device identification) works identically regardless of which one is chosen, since only the framing/transport layer differs between them.

### Device description (TOML)

Each PLC/device has an associated TOML description supplied by the user (not auto-discovered). It describes the data the device offers:

- Register addresses and data types (e.g. holding register 40001, `u16`/`f32`, scaling/units)
- Human-readable names for registers (e.g. `Tank_Temperatur` instead of a raw address)
- Access rights per register (read-only vs read/write)

Connection details (IP/port for TCP, serial port/slave ID for RTU) are **not** part of this TOML file — they are supplied separately via a config file or CLI arguments when starting the client/server binary.

**Server "introduces itself" via FC 43 (resolved 2026-09-15):** rather than requiring the client to keep its own copy of the server's TOML in sync by hand, the client fetches it over the wire at startup using Modbus function code 43 (Encapsulated Interface Transport), MEI type 0x0E (Read Device Identification), Extended access. This FC was chosen specifically because its object model (arbitrary-length byte strings, keyed by ID) and its built-in More-Follows/Next-Object-Id continuation mechanism already solve "transfer a string too long for one response" for free — no custom chunking protocol needed on top of what the FC already does. Two private objects are used (the 0x80-0xFF range is reserved by the spec for vendor-specific use):
- `0x80` — presence flag, one byte (`0x01` = server has a description, `0x00`/absent = it doesn't).
- `0x81`, `0x82`, ... — the raw TOML source, split into chunks (each object's own 255-byte length limit, further capped in practice so a chunk plus response overhead still fits in one 253-byte PDU — see `server/src/device_identification.rs`).

The client always still requires a local `device-description.toml` argument as a fallback: if the server has no description, doesn't support FC 43 at all (a Modbus exception — e.g. a simpler/older device), or the fetch fails for any other reason, the client falls back to it rather than treating this as fatal. Fetching can take several round trips (one per response that didn't fit everything), so progress is printed as it happens — otherwise a user watching the client start up has no way to tell "still fetching" apart from "hung". Scope of the current implementation: only Extended access and these two object kinds are supported; the rest of what FC 43 can do (Basic/Regular/Individual access, the standard VendorName/ProductCode/etc. objects) plus exposing these text objects through the FUSE filesystem itself is intentionally deferred to a later pass.

### FUSE filesystem layout

The mounted filesystem (per client or server instance) exposes at least:

- a `holding-registers` directory — current live values as readable files, named/structured per the TOML description. Named after the specific Modbus data type rather than a generic `data`, since other Modbus data types were meant to get their own sibling directories later — `coils`, `discrete-inputs`, and `input-registers` all now exist (see "read-only Modbus data types" below for the latter two).
- a `transactions` directory (client only as of "server direct-write model" below — this bullet describes the original, still-current client behavior) — the write mechanism (resolved 2026-09-15, after considering a single-file batch-write alternative — rejected because it's less filesystem-native: no `ls` to inspect what's staged, no `rm` to unstage a single value, and a comma-separated custom syntax to parse/report errors against):
  1. The user creates a file per value they want to change, named after the register's human-readable name from the TOML description, and writes the desired value as that file's **content** (e.g. `echo True > transactions/Stop_Process`) — not encoded in the filename. Staging happens on write, not on bare creation.
  2. Once all desired changes are staged, the user creates a sentinel file named `TRANSACTION_END`.
  3. Creating `TRANSACTION_END` triggers the actual batched Modbus write(s) for everything staged in the transaction.
- a `report` directory — one read-only file per register (`report/<name>`) showing the outcome of that register's most recent write attempt (resolved 2026-09-15, see "Write status reporting" below for the alternatives considered).

**`TRANSACTION_END` confirmation semantics (resolved 2026-09-15):** creating `TRANSACTION_END` clears the whole `transactions/` staging area immediately (matching a commit consuming its staging area — no partial/pending status is shown, see "Write status reporting" below), but this does **not** mean the write has happened yet. `fuse-fs` has no Modbus protocol knowledge, so it cannot itself confirm a write reached the real device — it only hands the drained transaction off (over an injected `std::sync::mpsc::Sender<HashMap<String, RegisterValue>>`) to whoever owns the receiving end. Values under `holding-registers/` must **not** change as a side effect of `TRANSACTION_END`, which is client/server-specific logic outside `fuse-fs`, wired up once those binaries integrate `protocol`:
  - **Server (superseded 2026-09-18 by "server direct-write model" below — this bullet describes the original TRANSACTION_END-triggered behavior, kept for history):** applies (and thus reflects) the write immediately — its own in-memory state *is* the authoritative data external Modbus masters read, so there's no separate device to round-trip with. The server no longer has a `transactions/` directory at all; the same "applies immediately, no round-trip" reasoning now drives direct writes to `holding-registers/`/`coils/`/`discrete-inputs/`/`input-registers/` instead.
  - **Client (narrowed 2026-09-16):** the Modbus write response confirms the write happened, but does **not** itself update `holding-registers/` — only the next `client::polling` tick does. This was originally "after the write response / next poll confirms it" (either could update the store), but that admitted a real race: the connection is only locked per-request, not across the later store-update step, so a poll response already in flight before a commit could still land *after* it and silently overwrite the freshly-confirmed value with a stale one. Keeping the poll loop as the *only* writer of `RegisterStore`/`CoilStore` on the client removes the race outright, at the cost of `holding-registers/<name>` lagging up to one poll interval behind `report/<name>` already showing `OK`. A full or targeted re-poll triggered by the commit itself was considered and rejected — both would add wire traffic and connection contention for a race a single-writer design avoids for free.

**Write status reporting / Milestone H3 (resolved 2026-09-15):** the simplest of the considered shapes was chosen, deliberately deferring the richer alternatives until a real confirmed-write consumer exists to show what they'd actually need (extraction-based programming: don't build the structure before a concrete need has shown its real shape):
- **Granularity: per register**, not per transaction. `report/<register-name>` mirrors `holding-registers/<name>` and `transactions/<name>` exactly. This also sidesteps needing any transaction-identity concept (transactions are anonymous today — draining one doesn't produce an ID) and handles partial multi-register failures for free: `report/A` and `report/B` are independent, no aggregate transaction-level status needed.
- **Content: a plain status word.** `"OK"` or `"FAILED: <reason>"` (`fuse_fs::WriteStatus`), not a structured record with timestamp/Modbus exception code. `fuse-fs` deliberately has no `protocol` dependency for wire/error types; a richer format was judged premature before any real writer of these reports exists.
- **Lifecycle: overwritten by the next attempt**, not persisted until manually `rm`'d. `report/<name>` always reflects only the most recent write attempt for that register. Bounded by construction (at most one entry per register); no cleanup mechanism needed. Also in-memory only, same as `RegisterStore`/`PendingTransaction` — doesn't survive a process restart.
- Like `holding-registers/` and `transactions/`, `report/` is only ever updated by whoever owns the receiving end of `transaction_sender` (see confirmation semantics above) — `fuse-fs` itself never writes to it.

This transactional, filesystem-native interface is the core "twist" of the project — treating Modbus reads/writes as file operations rather than requiring a dedicated client API.

## Server direct-write model, replacing server-side transactions (resolved and implemented 2026-09-18)

**This revises the server's half of "TRANSACTION_END confirmation semantics" above** — the client's half (staging, `report/`, poll-lag) is unchanged. Implemented and shipped; supersedes the server's previously-shipped `transactions/`+`TRANSACTION_END` behavior (Milestones H1–H3's server half), which has been removed.

**Why revisit an already-shipped decision:** questioning whether the transactional (`transactions/`+`TRANSACTION_END`) model actually earns its keep on the server surfaced two things on reflection: (1) the model's real justification was always the *client's* round-trip-to-a-real-device axis — stage several edits, commit, confirm asynchronously via `report/` since the write can genuinely fail against real hardware. The server has never had that axis: its own in-memory state is authoritative, a "write" is just a local `store.set()`, there is no device to fail against. It only inherited staging because `fuse-fs` built one shared mechanism for both roles, not because the server independently needed it. (2) Even on the client, staged writes were never wire-atomic — `transaction_consumer` sends one write per register sequentially, not a single bundled PDU — so "staging" was always local UX (assemble related edits, then commit in quick succession, each confirmed independently), never a hard atomicity guarantee. That weakens the case for keeping it server-side even for the "hide a coordinated multi-value change until it's fully applied" argument.

**Server model:** `holding-registers/<name>`, `coils/<name>`, `discrete-inputs/<name>`, and `input-registers/<name>` are **directly writable on the server only** (still strictly read-only on the client, unchanged) — `echo 5 > holding-registers/Setpoint` applies immediately, no staging step. A `WriteMode` enum (`Staged`/`Direct`) on `InfusedFilesystem`, set once at construction (`client` passes `Staged`, `server` passes `Direct`), gates every FUSE method that needs to behave differently: `getattr`/`lookup` report `0o644` instead of `0o444` for these files in `Direct` mode (necessary since the `default_permissions` mount option enforces this before `write` is ever called), and `write`/`release`/`setattr` accept these inodes alongside the `transactions/` staging path. A single direct write is handed off over the exact same `transaction_sender` channel as an implicit one-item transaction — `server::transaction_consumer` needed no restructuring, only two new `StagedValue` variants (`DiscreteInput`/`InputRegister`, alongside the existing `Register`/`Coil`) and matching store parameters, since it already dispatched purely by variant. `transactions/`/`TRANSACTION_END` are removed from the **server's** FUSE tree entirely (gated by a `transactions_enabled()` check mirroring the `client_trust_ino`-is-always-computed-but-conditionally-exposed precedent) — the client keeps them exactly as-is.

**Race-safety argument:** every write, staged or direct, is still applied by the one dedicated consumer thread reading from that one channel — nothing in `fuse-fs` mutates the stores directly. This is the exact same asynchronous hand-off already accepted for `TRANSACTION_END`-triggered server writes before this change, just triggered per single write instead of per drained batch, so no new race class was introduced.

**Resolved during implementation:** `report/` was **not** extended to cover `discrete-inputs/`/`input-registers/` — it stays scoped to registers/coils exactly as H3 defined it. Extending it wasn't needed for direct-write to work (a direct write's own `write()`/`release()` return code is the only failure signal for those two categories), and doing so would have been scope creep beyond what this change needed.

**Accepted consequence:** this was a breaking change to previously-shipped, tested server behavior (Milestones H1–H3's server half) — deliberate, per this project's established "explicit/simple over preserving existing behavior while nothing is deployed" stance (see the multi-machine schema and `server-options.toml` sections below for the same call made the same day).

## Read-only Modbus data types — Discrete Inputs (FC 2) & Input Registers (FC 4) (resolved and implemented 2026-09-18)

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

Discrete inputs mirror `CoilDescription` (`name`+`offset` only, always 1 bit). Input registers mirror `RegisterDescription` minus `access` (always read-only) — still need their own `mem-layout`, since values can span multiple registers exactly like holding registers.

**Stores:** `DiscreteInputStore` (reuses `CoilValue`) and `InputRegisterStore` (reuses `RegisterValue`) — mirror `CoilStore`/`RegisterStore` exactly. Neither exposes a write method to `protocol`/wire code, since no Modbus function code ever lets a master write these; only the server's direct-write path or client polling ever populates them.

**FUSE:** two new sibling directories, `discrete-inputs/` and `input-registers/` — read-only on the client, directly writable on the server (see "server direct-write model" above) via the same `lookup`/`getattr`/`read`/`readdir`/`write`/`release`/`setattr` machinery `holding-registers/`/`coils/` use.

**Client:** populated exclusively by polling (`build_discrete_input_read_batches`/`build_input_register_read_batches`, same batching approach as `build_read_batches`/`build_coil_read_batches`) — no write path exists on the client, consistent with [[feedback-no-optimistic-writes]] and the fact that these values only ever come from a real device.

**Server:** each configured entry starts at a default (`false`/`0`) until directly written into via `discrete-inputs/<name>`/`input-registers/<name>`, exactly like `holding-registers/`/`coils/`.

## Planned: custom (vendor-specific) function codes (design resolved 2026-09-18, not yet implemented)

Motivation: real devices sometimes implement genuinely non-standard function codes outside anything the Modbus spec's public FC table covers — the user's own concrete prior experience is an inverter encountered at work with entirely custom FC definitions, which he previously handled in Node-RED via `node-red-contrib-modbus`'s `flex-fc` node (a JSON-driven request/response field-map: `name`/`offset`/`type` per field, loaded from an external file). This section adapts that idea, stricter, for this project. Nothing in this section exists in code yet.

**Scope, for now: vendor-specific FC number range only** (0x41-0x48 / 65-72 and 0x64-0x6E / 100-110, per spec's own user-defined-function reservation) — reinterpreting an existing *standard* FC number (which some real devices, like the inverter, apparently do anyway) is deliberately out of scope for this first pass, revisit later if a real device actually needs it. `function_code` outside this range is a hard parse error.

**Config: new `custom-function-codes.toml`**, one file, `[[custom-function-codes]]` array-of-tables, each with `name`, `function_code`, and nested `[request]`/`[response]` field lists — consolidated into one file/one entry per FC (not separate request/response files, unlike `flex-fc`'s two separate map editors):

```toml
[[custom-function-codes]]
name = "InverterStatus"
function_code = 65

[[custom-function-codes.request.fields]]
name = "Query_Type"
data_type = "u8"
value = 1              # fixed value the client always sends for this field

[[custom-function-codes.response.fields]]
name = "Frequency"
data_type = "u16"

[[custom-function-codes.response.fields]]
name = "Status_Flags"
data_type = "u8"
```

**Stricter than `flex-fc` by design:** fields are **sequential and contiguous**, no explicit `offset` — field N+1's position is derived from field N's end, eliminating the whole class of overlapping/gapped/contradictory layouts an offset-per-field scheme like `flex-fc`'s permits. Field types reuse the existing `DataType` enum rather than inventing a narrower one. Not yet resolved: `DataType`'s multi-register byte width (e.g. `u24` occupying two padded 16-bit registers = 4 bytes) is a holding-register-framing convention that doesn't obviously apply to a raw custom-FC byte layout (a real device's `u24` field here might just be 3 raw bytes, no padding) — needs its own byte-width mapping, to be settled once this is actually implemented. Also not yet resolved: whether defining a custom FC here additionally requires enabling it via `server-options.toml`'s `[function-codes]` table for consistency with that section's explicit-opt-in stance, or whether being defined here is itself sufficient.

**Client role (master, always initiates):** builds the request PDU from the request fields' fixed `value`s, decodes the response fields into new read-only FUSE files (`custom/<name>/<field-name>`), refreshed via polling exactly like `holding-registers/` today.

**Server role (never initiates — Modbus stays strictly master-initiated, same constraint noted throughout this file):** dispatch recognizes the configured `function_code`, decodes the incoming request into read-only FUSE files under `custom/<name>/` (showing what was last asked), and the **response fields become directly writable** — reusing the exact "server direct-write model" above unchanged (an operator's write becomes an implicit one-item transaction over the same `transaction_sender` channel), so whatever was last written is what the server replies with on the next matching request. Only new state needed is a `CustomFunctionCodeStore` (keyed by field name, holding `RegisterValue`-shaped data) — no changes to the write-hand-off mechanism itself.

**FUSE layout:** a new top-level `custom/<fc-name>/` directory tree, since this data doesn't fit `holding-registers/`/`coils/`/`discrete-inputs/`/`input-registers/` at all — it isn't Modbus register/coil-addressed data, just named byte fields.

## Planned: multi-machine device description & FUSE layout (design resolved 2026-09-18, not yet implemented)

Motivation: the user's stated direction is for a single `server` (and eventually `client`) instance to manage several machines at once — e.g. one RTU multi-drop link or several TCP targets — from one file, rather than one process per machine. This supersedes the earlier open "Multi-machine TOML schema" question: instead of a discovery-layer-only solution (Milestone V's FC43-directory + FC20-per-machine idea further below), the schema itself now natively describes multiple machines. Nothing in this section exists in code yet.

**Schema: `[[machines]]` array-of-tables**, one entry per machine, each carrying:
- `name` — a String identifying the machine, used directly as its FUSE top-level directory name. Must be **unique across the file** and restricted to ASCII alphanumeric characters plus `_`/`-` (no other characters, no empty string) — enforced as a parse error, not a runtime surprise, since two machines sharing a name would collide on one FUSE inode and other characters could break path handling.
- `unit_id` (`u8`) — which Modbus Unit ID on the shared link this machine answers to. This is a deliberate, explicitly-flagged exception to this file's established "TOML describes data shape, CLI/config describes connection" separation (see "Key technical decisions" below): a Unit ID is normally connection/wire-addressing information, but it's needed here to tell multiple machines described in one file apart, so it lives in the device description rather than CLI/config.
- Nested per machine, structurally identical to today's single-machine sections just moved one level down: `[machines.registers]` (`base_address`, `mem-layout`, `[[machines.registers.entries]]`) and `[machines.coils]` (`base_address`, `[[machines.coils.entries]]`).

This is a **breaking change** to the existing single-machine TOML format (today's top-level `[registers]`/`[coils]` stop being valid) — accepted deliberately, no backward-compatibility shim, since the project isn't deployed anywhere yet.

**FUSE layout:** each machine gets its own top-level directory named after `name`, containing the existing per-machine directory set — `holding-registers/`, `coils/`, and whatever future sibling directories land for other Modbus data types (`discrete-inputs/`, `input-registers/`, ...), plus `transactions/`+`report/` **on the client only** (see "server direct-write model" above — the server writes directly into `holding-registers/<name>`/`coils/<name>` per machine instead) — e.g. `/PumpA/holding-registers/`, `/PumpB/transactions/` (client). The server's `client-trust/` subtree (see the TLS section below) stays exactly where it is at the filesystem root, unaffected — it's about which clients may connect at all, not about any one machine.

**Client mounting scope:** the `client` mounts **all** machines described in its (possibly FC43-fetched) TOML by default — the concrete, simplest case first, per this file's own Extraction-Based Programming convention. Letting the user choose a subset is a real desired feature but the mechanism isn't decided yet; a plain CLI allowlist flag (e.g. `--machines PumpA,PumpB`, all machines mounted if omitted) is the leading candidate, planned as a small additive follow-up once "mount all" works, not built alongside it.

**Unit-ID dispatch — asymmetric client/server effort:** `client/src/connection.rs`'s `Connection::request(unit_id, pdu, timeout)` already takes the Unit ID as a per-call parameter (confirmed 2026-09-18 by reading the code, not assumed) — so per-machine dispatch on the client side is a wiring task (routing each machine's requests through its own `unit_id`), not a protocol change. On the server side, `unit_id` is currently decoded off the incoming ADU only to be echoed back into the response — `handle_request` never receives it at all, so server-side multi-machine routing is real, non-trivial work. This confirms Milestone V1's original scope (below) rather than replacing it.

**Relationship to FC43/FC20 wire transfer (Milestone V below):** the on-disk schema shape (one file, multiple machines) is orthogonal to how it's transferred over the wire at client startup — a single multi-machine TOML could still be served either as one FC43 blob (while it stays under the ~31KB ceiling) or split server-side per machine behind an FC43-directory + FC20-per-machine fetch, independent of the fact that the source file itself is no longer split per machine on disk. Not yet decided which; revisit once FC20 itself (Write/Read File Record) has been discussed.

## Planned: `server-options.toml` — explicit per-function-code opt-in (design resolved 2026-09-18, not yet implemented)

Motivation: the goal is to eventually cover as much of the Modbus function-code space as practical (see the README's function-code support table for the full list and current status), but every function code `server` implements is attack surface it exposes to *any* reachable Modbus master, not just a trusted one — this is a `server`-only concern, since `client` only ever issues function codes it itself chooses to send, never accepts arbitrary incoming ones. This surfaced concretely while discussing FC 21 (Write File Record, 0x15): unlike every other FC implemented so far, a generic file-write primitive is dangerous less because of what it does on the wire and more because of what a server implementation might eventually back "file" with (e.g. if it were ever wired to something interpreted afterward, it becomes a remote config-injection primitive, not just a bad register value) — see the FC 21 discussion this section grew out of. Rather than deciding "implement it or don't" per FC, the resolution is to make *every* FC's availability an explicit technician choice.

**Schema:** a new `server-options.toml`, `[function-codes]` table, one boolean per function code, named after the operation rather than a code number (matches this project's existing snake_case TOML style, e.g. `mem-layout`, `access`):

```toml
[function-codes]
read_coils = false                     # 0x01
read_discrete_inputs = false           # 0x02
read_holding_registers = false         # 0x03
read_input_registers = false           # 0x04
write_single_coil = false              # 0x05
write_single_register = false          # 0x06
write_multiple_coils = false           # 0x0F
write_multiple_registers = false       # 0x10
report_server_id = false               # 0x11
read_file_record = false               # 0x14
write_file_record = false              # 0x15
mask_write_register = false            # 0x16
read_write_multiple_registers = false  # 0x17
read_fifo_queue = false                # 0x18
read_device_identification = false     # 0x2B / MEI 0x0E (FC 43)
```

The four out-of-scope serial-diagnostic FCs (0x07/0x08/0x0B/0x0C, see the FUSE/README notes on why they're excluded) never appear here — there's nothing to toggle for a FC that will never be implemented at all.

**Default policy: strict default-deny, explicit over implicit, no legacy exemption (confirmed 2026-09-18).** Every function code — including the ones already fully implemented today (Read/Write Coils, Read/Write Holding Registers, Write Multiple Coils/Registers, FC 43) — defaults to disabled unless its key is present and `true`. This is a deliberate behavior-breaking decision: an existing deployment adopting this feature must list what it actually needs, or the server rejects every single incoming request. Consistent with this project's general stance of accepting breaking changes rather than carrying compatibility shims while nothing is deployed yet (see the multi-machine schema section above for the same call made the same day).

**Unknown keys under `[function-codes]` are a hard parse error**, not silently ignored — same discipline as `fuse-permissions.toml`'s rejection of a `client-trust` key, so a typo doesn't leave a technician wrongly believing a function code is enabled (or disabled).

**CLI wiring:** `--server-options <path>`, optional — analogous to `--fuse-permissions <path>`. If omitted, behaves exactly like a present-but-empty file (everything disabled), not a startup error. Because "the server starts fine but answers nothing" is a real footgun for a forgotten flag, `server` prints a loud startup warning whenever zero function codes end up enabled.

**Wire behavior for a disabled FC:** the server responds with the same `ILLEGAL_FUNCTION` exception already used for a function code that isn't implemented at all — deliberately indistinguishable on the wire, so a remote peer can't fingerprint "implemented but disabled" apart from "never implemented" from the response alone.

**Composes cleanly with FC 43's existing fallback:** disabling `read_device_identification` needs no special-casing — the client's FC 43 fetch already treats every failure mode identically as "fall back to the local TOML", including an `ILLEGAL_FUNCTION` exception, which is exactly what a disabled FC 43 now produces.

**This is what makes FC 21 (Write File Record) implementable at all.** Its risk — a semantically-unscoped write primitive, more dangerous than an ordinary register write once/if "file" ever means something real — is mitigated by requiring an explicit technician opt-in rather than the on-by-default posture every other FC has had until now. No concrete use case for FC 21 exists yet; this mechanism just removes the reason it had to stay categorically out of scope.

## Planned: TLS transport security & client trust (design resolved 2026-09-17, not yet implemented)

Motivation: Modbus TCP is unencrypted and trivially sniffable. A full CA-based TLS setup was rejected as too much certificate-management burden for a technician just trying to get two devices talking — this design gets real TLS's cryptography without a CA hierarchy, plus a way for a technician to control *which* clients may connect to a `server`. This section is captured ahead of implementation, per this file's own "real design conversation before implementing" convention below — nothing in this section exists in code yet.

**Transport is mutually exclusive.** A new connection-string scheme `tls+tcp://<address:port>` sits alongside `tcp://`/`rtu://`. A given `client`/`server` instance runs in exactly one of `tcp://`, `rtu://`, or `tls+tcp://` — never combined. This removes any plaintext-fallback path that could undermine an otherwise-encrypted deployment, and means RTU (a different, physical-access threat model) can never be used to bypass an active TLS-secured TCP configuration on the same instance. TLS itself is implemented via `rustls`, not hand-rolled — the project's "from scratch" philosophy applies to the Modbus protocol layer, not to cryptography.

**Identity: self-signed keys + fingerprint pinning instead of a CA hierarchy.** Both `client` and `server` generate their own self-signed keypair/certificate automatically on first run if none exists, persisted locally. Trust decisions are based **only** on the raw public-key fingerprint (full SHA-256) — other certificate fields (Subject, validity period, ...) are attacker-controlled since a peer signs its own cert, and are never consulted. This deliberately trades a CA's automatic verification for a human-verified pairing step, modeled on SSH host-key TOFU / HomeKit-style device pairing rather than PKI infrastructure. Alternatives seriously considered and rejected for the underlying encryption problem itself: a custom non-TLS scheme (a private function code doing an ephemeral ECDH handshake, then wrapping PDUs in an AEAD envelope) — rejected because designing a correct handshake/nonce/replay scheme from scratch is exactly the failure-prone territory TLS exists to avoid, and it would also need to keep the MBAP length field unencrypted for TCP framing and recompute RTU's CRC over ciphertext; and a pure TLS 1.3 PSK mode (no certs, `psk_dhe_ke` for forward secrecy) — still valid in principle, but doesn't give a technician per-client control over who connects, so it was superseded once that requirement surfaced.

**Server authentication (client trusts server):** the client is given the server's expected fingerprint once, out of band (e.g. read off a physical label at commissioning, passed as a CLI argument), and verifies every connection against it — protects against MITM / connecting to the wrong device.

**Client authentication (server trusts client) — mutual TLS with a fail-closed, filesystem-visible approval workflow:**
- The server also requires a client certificate (mTLS). Unknown/unapproved client fingerprints fail the TLS handshake outright (fail-closed) — the offered fingerprint is still observed and logged before the handshake is rejected, since the server sees the client's certificate before its own verification decides accept/reject.
- A new `client-trust/` FUSE subtree exists **only in the server's `InfusedFilesystem`** — threaded in via an `Option<Arc<Mutex<ClientTrustState>>>` constructor parameter, `None` on the client, so the directory simply doesn't exist there. This is the first FUSE feature in the project that is not symmetric between client and server.
  - `client-trust/connection_attempts/{approved,pending,rejected}.log` — three **fixed** log files, never one file per attempt/fingerprint (avoids unbounded inode growth from attacker-controlled input, the same class of problem H3 avoided by staying per-register instead of per-transaction-ID). Each is a bounded ring buffer logging every connection attempt (timestamp, outcome, fingerprint, source address).
  - `client-trust/approved/` — a **read-only** mirror of the currently approved fingerprint set. Deliberately not a write target, unlike every other write-capable directory in this project (`transactions/`) — see the approval channel below for why.
- **Approval/revocation channel:** a Unix domain socket (fixed path, mode `0600`, owned by the server's own service account), additionally verified via `SO_PEERCRED` on every connection (kernel-verified caller UID, independent of and in addition to the socket file's own permissions — defense in depth if the file permissions were ever misconfigured). A built-in `server admin approve|revoke|list <fingerprint>` subcommand wraps this so a technician never talks the raw protocol directly. Kept deliberately separate from the general FUSE mount: reading register data and granting a remote peer network access to the whole industrial system were judged different trust levels that shouldn't share one write mechanism, unlike `transactions/`, where "can write to the mount" is already the accepted trust boundary for register writes.
- Revoking a fingerprint must actively terminate any already-open connection using it, not just block future handshakes — a passive block alone would leave an already-connected revoked peer live until it disconnects on its own.
- Checking the current approved count against `--max-clients` and inserting a newly-approved fingerprint must happen inside one held lock (a single critical section covering read-count + insert + persist-to-disk), never as two separate lock acquisitions — otherwise concurrent approvals could race past the configured limit.

**Capacity limit:** `--max-clients N` (a connection/operational detail, supplied via CLI/config like other connection info, not the device-description TOML) bounds the number of **currently valid** approved fingerprints at once — revoking one frees the slot for a new approval. Separate concern from the DoS hardening below: this protects the size of the trusted-device roster, not the server's ability to withstand traffic floods.

**Persistence — the first durable state the server itself writes to disk.** Every other piece of runtime state in this project (`RegisterStore`, `PendingTransaction`, `WriteReport`) is deliberately in-memory only, lost on restart. Client-trust approvals are the first deliberate exception: losing every approval on every restart is a real availability problem, not just an inconvenience. The approved set is persisted to a flat file (e.g. `approved-clients.toml`, atomic write via temp-file-plus-rename, `0600`/service-account-owned — same discipline as the private key file) written by the server itself whenever the approval channel changes it. The file is read **once, at startup only** — never hot-reloaded or watched for external changes at runtime, so all live changes must go through the approval channel that owns writing it. This is what makes "compromising this file requires compromising the server's own account" actually true, rather than merely assumed.

**FUSE directory permissions — technician-configurable, except `client-trust/` which is hardcoded to maximum restriction.** A separate `fuse-permissions.toml` (a third config category alongside device-description TOML and connection CLI/config, governing local filesystem exposure policy) lets the technician set `mode`/`uid`/`gid` per top-level directory (`holding-registers`, `transactions`, `report`, `coils`). Enforced via the FUSE `default_permissions` mount option so the kernel checks against what `getattr` reports, rather than every trait method re-implementing checks by hand. `client-trust/` cannot appear in this file's schema at all — attempting to configure it is a hard parse error at startup, not a silently-ignored setting — and its `getattr` always reports `mode = 0o700`, uid/gid = the server process's own real UID/GID, regardless of configuration.

**DoS hardening for the TLS layer**, same "validate/bound untrusted input before spending resources on it" instinct as [[feedback-harden-server-against-malicious-peers]], applied one layer earlier than existing PDU-length checks:
- A timeout on the TLS handshake itself, independent of and in addition to the existing per-I/O-step `with_timeout` used for Modbus request/response.
- A global cap on concurrent in-flight connections/handshakes.
- A **per-fingerprint** concurrent-connection cap, so an already-approved but compromised or buggy client can't exhaust the connection pool by itself.
- Full protection against a distributed flood from many source addresses is explicitly out of scope for `infused_modbus` itself — that is upstream infrastructure's job (firewall/rate-limiter), not something the application layer can solve.

This whole section should be treated like the rest of this file's "resolved" design decisions: a shared plan to implement from, not yet code. Implementation should proceed in the same small-increment style as "Working conventions" below — this is a large design and must not land as one commit.

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
