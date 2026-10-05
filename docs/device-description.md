# Device description TOML format

A device description is a `[[machines]]` array — one entry per machine sharing the link this `client`/`server` instance connects to (a single-machine deployment is just an array with one entry). Each `[[machines]]` entry requires:

- `name` — a unique (across the file), ASCII-alphanumeric-plus-`_`/`-` string, used directly as that machine's top-level FUSE directory name (`PumpA/`, `PumpB/`, ...) — a parse error if it collides with another machine's name or uses any other character.
- `unit_id` — the Modbus Unit ID this machine answers to on the shared link. `client` dispatches each machine's register/coil/etc. traffic to its own `unit_id`; `server` resolves an incoming request's Unit ID back to the matching machine and stays silent (no response at all, mirroring how an unaddressed device on a real RTU bus behaves) if none matches.

and optionally:

- `server-id` — identifies this machine to a Modbus master asking via FC 0x11 (Report Server ID) — set once and not meant to be changed at runtime. `server` answers real FC 0x11 requests for this machine's Unit ID with it (and rejects the function code with `ILLEGAL_FUNCTION` if absent); `client` mirrors it read-only into that machine's own mount as `server-id` — see [Interacting with the filesystem](filesystem.md).

Every other section below is nested one level under `[[machines]]` (e.g. `[machines.registers]` instead of a top-level `[registers]`) and otherwise unchanged in shape.

Registers live in a `[machines.registers]` table with a required `base_address`, a required `mem-layout` (see below), and one `[[machines.registers.entries]]` array entry per register:

```toml
[[machines]]
name = "PumpA"
unit_id = 1

[machines.registers]
base_address = 40000
mem-layout = "abcd"

[[machines.registers.entries]]
name = "Tank_Temperature"
offset = 1
data_type = "u16"
access = "read_only"

[[machines.registers.entries]]
name = "Stop_Process"
offset = 2
data_type = "u16"
access = "read_write"
```

Each entry's actual Modbus address is `base_address + offset` — `Tank_Temperature` above lives at 40001.

- `name` — the human-readable name used as the filename under `holding-registers/` and, on the client, `transactions/`/`report/` too.
- `offset` — added to the section's `base_address` to get the register's real Modbus address.
- `data_type` — one of `u8`, `i8`, `u16`, `i16`, `u24`, `i24`, `u32`, `i32`, `u64`, `i64`, `f32`, `f64`. Anything wider than one 16-bit register (`u24` and up) spans consecutive registers, in the byte order `mem-layout` describes. `u24`/`i24` have no native Modbus width — they occupy two registers (32 bits) with the top byte always zero (`u24`) or sign-extended (`i24`).
- `access` — `"read_only"` or `"read_write"`.
- `unit` — optional. The register's engineering unit, as a [UN/ECE Recommendation 20](https://unece.org/trade/uncefact/cl-recommendations) common code (e.g. `"CEL"` for degree Celsius, `"KPA"` for kilopascal, `"MQH"` for cubic metre per hour) — hard-validated at parse time against the currently-active code list, so a typo or a deprecated/retired code is rejected rather than silently accepted. Omit it entirely for a register with no physical unit (a setpoint, a mode flag, ...).

`mem-layout` describes how a device lays a multi-register value's bytes across the wire — real devices vary, and getting this wrong silently produces the wrong number rather than an error. It's one setting for the whole `[machines.registers]` section (a device doesn't mix conventions internally), using the industry-standard four-letter names for a value's bytes A (most significant) through D (least significant):

| `mem-layout` | Byte order on the wire | Also known as |
| ------------- | ----------------------- | -------------- |
| `"abcd"` | A B C D | big-endian |
| `"dcba"` | D C B A | little-endian |
| `"badc"` | B A D C | byte-swapped |
| `"cdab"` | C D A B | word-swapped (e.g. some Schneider/Modicon PLCs) |

Coils use the same `base_address` + `offset` shape, but have no `data_type` or `access` (a coil is always exactly 1 bit and always read/write):

```toml
[machines.coils]
base_address = 0

[[machines.coils.entries]]
name = "Motor_Running"
offset = 1
```

Both `[machines.registers]` and `[machines.coils]` are optional — a machine with only one kind doesn't need to declare an empty section for the other.

A complete example, two machines sharing one link, with a mix of types and access rights:

```toml
[[machines]]
name = "PumpA"
unit_id = 1

[machines.registers]
base_address = 40000
mem-layout = "abcd"

[[machines.registers.entries]]
name = "Tank_Temperature"
offset = 1
data_type = "u16"
access = "read_only"

[[machines.registers.entries]]
name = "Flow_Rate"
offset = 2
data_type = "f32"
access = "read_only"

[[machines.registers.entries]]
name = "Stop_Process"
offset = 4
data_type = "u16"
access = "read_write"

[[machines.registers.entries]]
name = "Setpoint"
offset = 5
data_type = "u16"
access = "read_write"

[machines.coils]
base_address = 0

[[machines.coils.entries]]
name = "Motor_Running"
offset = 1

[[machines.coils.entries]]
name = "Alarm_Reset"
offset = 2

[[machines]]
name = "PumpB"
unit_id = 2

[machines.coils]
base_address = 0

[[machines.coils.entries]]
name = "Motor_Running"
offset = 1
```

Discrete inputs (FC 0x02) mirror coils — same `base_address`/`offset`/`name` shape, always exactly 1 bit — but are always read-only, since no Modbus function code ever lets a master write one:

```toml
[machines.discrete-inputs]
base_address = 10000

[[machines.discrete-inputs.entries]]
name = "Door_Open_Sensor"
offset = 1
```

Input registers (FC 0x04) mirror `[machines.registers]` minus `access` (always read-only) — they still need their own `mem-layout`, since a value can span multiple registers exactly like holding registers. `unit` works identically to `[machines.registers]`'s own:

```toml
[machines.input-registers]
base_address = 30000
mem-layout = "abcd"

[[machines.input-registers.entries]]
name = "Flow_Rate"
offset = 1
data_type = "f32"
unit = "MQH"
```

All four sections (`[machines.registers]`, `[machines.coils]`, `[machines.discrete-inputs]`, `[machines.input-registers]`) are independently optional per machine — a machine only declares the ones it actually has.

File records (FC 0x14/0x15) are a different shape from every other section: no `base_address`/`offset` and no `name` — `file_number`/`record_number` *are* the address, and the FUSE path itself (`file-records/<file_number>/<record_number>`) is the identifier. `record_length` is in 16-bit words, matching the wire field's own unit:

```toml
[[machines.file-records]]
file_number = 20
record_number = 5
record_length = 9
```

`[[machines.file-records]]` is a flat, independently-optional array per machine — no wrapping section. See [the function code table](function-codes.md) for how content is exposed (raw hex, no field decoding).
