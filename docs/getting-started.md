# Getting started

Want to skip straight to running something real? [`examples/`](../examples/) has a ready-to-use, two-machine `device-description.toml` (plus a matching `server-options.toml`) and a full copy-pasteable walkthrough — no edits needed.

## Build

```sh
cargo build --workspace
```

Requires Linux (both `libfuse`, for the `fuse` representation layer, and `inotify`, for the `files` one, are Linux-specific).

## Run the server

```sh
cargo run -p server -- <root> <device-description.toml> <connection> [--fuse-permissions <fuse-permissions.toml>] [--max-clients <n>] [--server-options <server-options.toml>] [--data-representation-layer fuse|files|mqtt]
```

`<connection>` is one of:

- `tcp://<bind-address:port>` — e.g. `tcp://0.0.0.0:502`
- `rtu://<serial-path>:<baud-rate>` — e.g. `rtu:///dev/ttyUSB0:9600`
- `tls+tcp://<bind-address:port>` — see [Connecting over TLS](tls.md) below.

`--data-representation-layer` picks how `<root>` exposes the data: `files` (the **default**) writes real files under `<root>`, kept current via `inotify` and atomic `rename()` — no FUSE mount at all; `fuse` mounts `<root>` as a synthetic FUSE filesystem, this project's original mechanism; `mqtt` ignores `<root>` entirely and serves a local socket instead — see [MQTT (Sparkplug B) layer](mqtt-sparkplug.md). `fuse`/`files` present the identical directory shape described in [Interacting with the filesystem](filesystem.md) — pick whichever fits your deployment, see `CLAUDE.md`'s "Pluggable data-representation layer" section for the full design rationale.

`--fuse-permissions` is optional — see [Directory permissions](directory-permissions.md). `--max-clients` is also optional (`tls+tcp://` only) and bounds how many client certificates can be approved at once — without it, there is no limit.

**`--server-options` controls which function codes this server will actually answer on the wire — and it's strict default-deny.** Without it (or with a present-but-empty file), *every* function code is disabled and every incoming request gets an `ILLEGAL_FUNCTION` exception, no matter how many function codes this project implements — `server` prints a loud startup warning if this ends up being the case, since "starts fine but answers nothing" is an easy flag to forget. Every function code this server can serve — including already-implemented ones like Read/Write Holding Registers — is attack surface exposed to any reachable Modbus master, so enabling one is an explicit technician choice, not an on-by-default assumption. Point it at a TOML file with a `[function-codes]` table, one boolean per function code, named after the operation:

```toml
[function-codes]
read_holding_registers = true
write_single_register = true
```

See the [function code table](function-codes.md) for every available key name, and [`server-options.toml`](server-options.md) for the full format.

Example:

```sh
mkdir -p /tmp/modbus-server
cargo run -p server -- /tmp/modbus-server device.toml tcp://0.0.0.0:502 --server-options server-options.toml
```

`server` also has a second, unrelated invocation form for managing TLS client approvals — see [Connecting over TLS](tls.md):

```sh
cargo run -p server -- admin approve|revoke <fingerprint>
cargo run -p server -- admin list
```

## Run the client

```sh
cargo run -p client -- <root> <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>] [--fuse-permissions <fuse-permissions.toml>] [--data-representation-layer fuse|files|mqtt] [--mqtt-broker <host:port>] [--mqtt-group-id <id>] [--mqtt-edge-node-id <id>]
```

`<connection>` uses the same `tcp://`/`rtu://`/`tls+tcp://` scheme as the server. `<device-description.toml>` is required as a fallback, but if the server it connects to supports FC 43 (see [Device description discovery](filesystem.md#device-description-discovery-fc-43)), the client uses the server's own description instead. `--data-representation-layer` (default `files`) and `--fuse-permissions` (see [Directory permissions](directory-permissions.md)) work identically to the server's own flags of the same name; `<root>` is ignored under `mqtt`. The `--mqtt-*` flags only apply under `--data-representation-layer mqtt` — see [MQTT (Sparkplug B) layer](mqtt-sparkplug.md). `client` mounts/writes **every** machine described in the effective device description — see [Device description TOML format](device-description.md) — each under its own top-level directory (`fuse`/`files`) or as its own Sparkplug B Device (`mqtt`).

`[unit-id]` is **only** used to address the initial FC 43 device-identification handshake — it's how the client asks *some* device on the link to introduce itself before it knows which Unit IDs are valid at all. Once the (possibly multi-machine) device description is known, each machine dispatches its own actual register/coil/etc. traffic via its own TOML-declared `unit_id`, not this CLI one. Defaults to `1` if omitted.

Example:

```sh
mkdir -p /tmp/modbus-client
cargo run -p client -- /tmp/modbus-client device.toml tcp://127.0.0.1:502 1 1000
```

## Next steps

- [Interacting with the filesystem](filesystem.md) — `ls`/`cat`/`echo` walkthrough once both are running.
- [Device description TOML format](device-description.md) — the full schema.
- [MQTT (Sparkplug B) layer](mqtt-sparkplug.md) — an alternative to the filesystem.
- [Connecting over TLS](tls.md) — mutual TLS with client approval.
