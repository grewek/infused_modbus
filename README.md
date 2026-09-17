# infused_modbus

A Modbus **client** (master) and Modbus **server** (slave) that expose the Modbus data they handle through a **FUSE filesystem** instead of — or in addition to — a conventional API. "Infused" refers to this live-updating FUSE projection of Modbus data: register values show up as readable files, and writes happen by writing to files, no client library required.

Both **Modbus TCP** and **Modbus RTU** (serial) are supported, symmetrically, for both the client and the server.

## ⚠️ This project was built entirely with AI assistance

This codebase was designed and implemented in collaboration with **Claude Code** (Anthropic's AI coding agent), end to end — architecture, protocol implementation, tests, and this README. If you have concerns about AI-assisted software, or simply prefer not to use or review AI-generated code, **please don't spend your time on this project**. This is stated plainly and upfront so nobody invests effort here under a false impression.

## ⚠️ Early-stage software — do not treat this as secure

This project is under active development and has **not** had a security review. Neither `client` nor `server` should be considered hardened, and `server` in particular accepts Modbus connections from any master that can reach it, with no authentication. Some individual inputs read from the wire are checked before use (see below), but that describes isolated pieces of the implementation, not an overall security guarantee. Do not expose either binary to an untrusted network, and do not use this project anywhere a security failure would have real consequences.

## How this project came to be

- **grewek** is the project owner and architect: every design decision — the FUSE filesystem layout, the transaction/confirmation semantics, the choice of Modbus function codes, protocol framing tradeoffs, scope boundaries, naming — was made or explicitly approved by him. Development proceeded in small, reviewable increments, with a deliberate house style (extraction-based programming: write the concrete solution first, only generalize once a real second case shows its actual shape; no speculative abstraction).
- **Claude** implemented each increment against that direction: wrote the Rust code, the test suites, ran manual verification, and iterated based on review feedback after every step.

Nothing here shipped without a human decision behind it, but essentially all of the code was written by an AI. See the point above if that matters to you.

## Design overview

- **No separate client API — the filesystem is the interface.** Reading a register's current value is `cat holding-registers/Tank_Temperature`. Writing one is `echo 55 > transactions/Stop_Process`.
- **Transactions are filesystem-native, multi-value commits.** Stage register writes as files under `transactions/`, then create a sentinel file `TRANSACTION_END` to commit them all as one batch. `ls`, `cat`, and `rm` work for inspecting or un-staging what's pending.
- **Writes are not applied optimistically.** On the client, `report/<name>` confirms a write immediately, but `holding-registers/<name>` only updates on the *next poll* of the connected device — polling is deliberately the client's only writer of its own mirror, to avoid a race where an in-flight poll response could otherwise land after a commit and overwrite the freshly-confirmed value with a stale one. On the server, its own in-memory state is the data an external Modbus master reads, so a locally staged write applies immediately; there's no separate device to wait on.
- **Per-register write status.** `report/<register-name>` shows the outcome of that register's most recent write attempt (`OK` or `FAILED: <reason>`), independent of every other register.
- **TCP and RTU use the same code paths.** Both `client` and `server` accept a connection string in the form `tcp://<address:port>` or `rtu://<serial-path>:<baud-rate>`; transactions, polling, and device-description discovery are implemented once and dispatch to whichever transport was chosen.
- **The server can advertise its own register description.** Instead of the client needing a hand-maintained copy of the server's register description, the client can fetch it at startup over Modbus function code 43 (Read Device Identification) — see [Device description discovery](#device-description-discovery-fc-43) below. A local fallback file is still required in case the server doesn't support this.
- **Modbus implemented from scratch.** The `protocol` crate implements Modbus TCP/RTU framing, CRC16, and PDU encode/decode directly, rather than wrapping an existing crate like `tokio-modbus`. Some individual inputs read from the wire (declared lengths/counts) are checked against the actual remaining buffer before being used for allocation or indexing — this reduces a few specific classes of bugs, but is not a substitute for a real security review, which this project has not had (see the warning above).
- **Polling batches register reads.** The client keeps its local mirror fresh by polling, grouping contiguous register addresses into a single `Read Holding Registers` request (up to Modbus's 125-register limit) instead of one request per register. Standard Modbus has no mechanism for a device to push updates on its own — polling is the only option the protocol allows.
- **Every register data type is read and written over the wire**, including ones spanning more than one 16-bit Modbus register (`u32`, `f64`, ...) — see [Device description TOML format](#device-description-toml-format) for the full type list and how `mem-layout` controls their byte order.

## Supported Modbus function codes

This lists every public function code defined by the Modbus Application Protocol specification, not just the ones this project implements — so the gaps are visible rather than silently omitted. "Decoded, not wired" means `protocol` can encode/decode the PDU, but `client`/`server` don't call it yet; support for everything else marked "Not implemented yet" will be added later. "Out of scope" means this project has decided not to implement it at all — see the note below the table.

| Code | Name | Status |
| ---- | ---- | ------ |
| 0x01 | Read Coils | Supported |
| 0x02 | Read Discrete Inputs | Decoded, not wired |
| 0x03 | Read Holding Registers | Supported |
| 0x04 | Read Input Registers | Not implemented yet |
| 0x05 | Write Single Coil | Supported |
| 0x06 | Write Single Register | Supported |
| 0x07 | Read Exception Status | Out of scope |
| 0x08 | Diagnostics | Out of scope |
| 0x0B | Get Comm Event Counter | Out of scope |
| 0x0C | Get Comm Event Log | Out of scope |
| 0x0F | Write Multiple Coils | Supported |
| 0x10 | Write Multiple Registers | Supported |
| 0x11 | Report Server ID | Not implemented yet |
| 0x14 | Read File Record | Not implemented yet |
| 0x15 | Write File Record | Not implemented yet |
| 0x16 | Mask Write Register | Not implemented yet |
| 0x17 | Read/Write Multiple Registers | Not implemented yet |
| 0x18 | Read FIFO Queue | Not implemented yet |
| 0x2B / MEI 0x0E | Encapsulated Interface Transport — Read Device Identification | Supported (Extended access only — see [Device description discovery](#device-description-discovery-fc-43)) |

**0x07, 0x08, 0x0B, 0x0C are deliberately out of scope.** All four are marked "(Serial Line only)" in the spec itself and exist to diagnose the physical RS-485/RTU link (CRC error counts, character overrun counts, a Listen Only Mode to silence a malfunctioning node on a multidrop bus, a rolling event log of send/receive activity). None of them read or write register/coil data, they have no equivalent over TCP, and implementing them would mean tracking link-level counters/state that serve no purpose for this project while adding attack surface to `server`. Not planned to be revisited.

## Client vs. server

- **`client`** acts as a Modbus master against a connected device. It polls the device to keep `holding-registers/` fresh, and turns `transactions/` commits into Modbus writes, updating the local mirror only once the device confirms them.
- **`server`** acts as a Modbus slave that external Modbus masters query and write against. Its own in-memory register store is the state being served: an external write applies immediately and is reflected into `holding-registers/`, and a locally staged `transactions/` commit is visible to external masters on their next read.

This has been tested against this project's own client/server implementations and against virtual serial ports, not against third-party PLC or SCADA hardware or software — whether it interoperates with a specific real-world device or system has not been verified.

## Getting started

### Build

```sh
cargo build --workspace
```

Requires Linux (FUSE is a Linux-specific dependency) and a FUSE-capable kernel/userspace (`libfuse`).

### Run the server

```sh
cargo run -p server -- <mountpoint> <device-description.toml> <connection>
```

`<connection>` is either:

- `tcp://<bind-address:port>` — e.g. `tcp://0.0.0.0:502`
- `rtu://<serial-path>:<baud-rate>` — e.g. `rtu:///dev/ttyUSB0:9600`

Example:

```sh
mkdir -p /tmp/modbus-server
cargo run -p server -- /tmp/modbus-server device.toml tcp://0.0.0.0:502
```

### Run the client

```sh
cargo run -p client -- <mountpoint> <device-description.toml> <connection> [unit-id] [poll-interval-ms]
```

`<connection>` uses the same `tcp://`/`rtu://` scheme as the server. `<device-description.toml>` is required as a fallback, but if the server it connects to supports FC 43 (see below), the client uses the server's own description instead.

Example:

```sh
mkdir -p /tmp/modbus-client
cargo run -p client -- /tmp/modbus-client device.toml tcp://127.0.0.1:502 1 1000
```

### Interacting with the filesystem

Once mounted:

```sh
ls holding-registers/                       # see all known registers
cat holding-registers/Tank_Temperature      # read the current value

echo 55 > transactions/Stop_Process         # stage a write
ls transactions/                            # see what's staged
rm transactions/Stop_Process                # ...or un-stage it
touch transactions/TRANSACTION_END          # commit everything staged

cat report/Stop_Process                     # OK, or FAILED: <reason>
```

Coils work the same way, under `coils/` instead of `holding-registers/` — `transactions/` and `report/` are shared across both (one register and one coil can even be staged in the same commit). A coil's value is `0` or `1`:

```sh
cat coils/Motor_Running                     # 0 or 1
echo 1 > transactions/Motor_Running         # stage turning it on
touch transactions/TRANSACTION_END
```

Unmount with Ctrl+C or `SIGTERM` — both `client` and `server` unmount cleanly on shutdown.

### Device description discovery (FC 43)

The client always requires a local `device-description.toml` path on the command line, but at startup it first asks the server for its own description over Modbus function code 43 (Encapsulated Interface Transport, MEI type 0x0E, Read Device Identification). If the server has one, the client uses it instead of the local file — printing progress as it fetches, since this can take a few round trips. If the server has none, doesn't support FC 43, or the fetch fails for any reason, the client transparently falls back to the local file.

## Device description TOML format

Registers live in a `[registers]` table with a required `base_address`, a required `mem-layout` (see below), and one `[[registers.entries]]` array entry per register:

```toml
[registers]
base_address = 40000
mem-layout = "abcd"

[[registers.entries]]
name = "Tank_Temperature"
offset = 1
data_type = "u16"
access = "read_only"

[[registers.entries]]
name = "Stop_Process"
offset = 2
data_type = "u16"
access = "read_write"
```

Each entry's actual Modbus address is `base_address + offset` — `Tank_Temperature` above lives at 40001.

- `name` — the human-readable name used as the filename under `holding-registers/`, `transactions/`, and `report/`.
- `offset` — added to the section's `base_address` to get the register's real Modbus address.
- `data_type` — one of `u8`, `i8`, `u16`, `i16`, `u24`, `i24`, `u32`, `i32`, `u64`, `i64`, `f32`, `f64`. Anything wider than one 16-bit register (`u24` and up) spans consecutive registers, in the byte order `mem-layout` describes. `u24`/`i24` have no native Modbus width — they occupy two registers (32 bits) with the top byte always zero (`u24`) or sign-extended (`i24`).
- `access` — `"read_only"` or `"read_write"`.

`mem-layout` describes how a device lays a multi-register value's bytes across the wire — real devices vary, and getting this wrong silently produces the wrong number rather than an error. It's one setting for the whole `[registers]` section (a device doesn't mix conventions internally), using the industry-standard four-letter names for a value's bytes A (most significant) through D (least significant):

| `mem-layout` | Byte order on the wire | Also known as |
| ------------- | ----------------------- | -------------- |
| `"abcd"` | A B C D | big-endian |
| `"dcba"` | D C B A | little-endian |
| `"badc"` | B A D C | byte-swapped |
| `"cdab"` | C D A B | word-swapped (e.g. some Schneider/Modicon PLCs) |

Coils use the same `base_address` + `offset` shape, but have no `data_type` or `access` (a coil is always exactly 1 bit and always read/write):

```toml
[coils]
base_address = 0

[[coils.entries]]
name = "Motor_Running"
offset = 1
```

Both `[registers]` and `[coils]` are optional — a device with only one kind doesn't need to declare an empty section for the other.

A complete example with a mix of types and access rights:

```toml
[registers]
base_address = 40000
mem-layout = "abcd"

[[registers.entries]]
name = "Tank_Temperature"
offset = 1
data_type = "u16"
access = "read_only"

[[registers.entries]]
name = "Flow_Rate"
offset = 2
data_type = "f32"
access = "read_only"

[[registers.entries]]
name = "Stop_Process"
offset = 4
data_type = "u16"
access = "read_write"

[[registers.entries]]
name = "Setpoint"
offset = 5
data_type = "u16"
access = "read_write"

[coils]
base_address = 0

[[coils.entries]]
name = "Motor_Running"
offset = 1

[[coils.entries]]
name = "Alarm_Reset"
offset = 2
```

## Current limitations

This project is under active development. As of now:

- Read Discrete Inputs (FC 0x02) is decoded by `protocol` but not wired into `client`/`server` yet — there's no discrete-input device model in the TOML schema (see the function code table above). The same goes for Input Registers (FC 0x04), which isn't implemented at the protocol level at all yet.
- `u8`/`i8` registers each occupy a whole 16-bit register (in the low byte) rather than two of them being packed into one — no real device was found that packs independent named values that way, so the simpler representation was kept.
- FC 43 (device identification) only supports "Extended" access serving custom private objects (the mechanism used for description discovery above) — the standard VendorName/ProductCode/etc. objects and Basic/Regular/Individual access aren't implemented yet.
- RTU serial parameters beyond baud rate (data bits, parity, stop bits) aren't configurable yet; fixed defaults (8 data bits, no parity, 1 stop bit) are used.

## Development

```sh
cargo build --workspace
cargo test --workspace
cargo test -p <crate-name> <test_name>   # run a single test in one crate
cargo clippy --workspace --all-targets
cargo fmt --all
```

See `CLAUDE.md` for the full architecture and design-decision history.
