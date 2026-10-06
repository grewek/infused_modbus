# Getting started

Want to skip straight to running something real? [`examples/`](../examples/) has a ready-to-use, two-machine `device-description.toml` (plus a matching `server-options.toml`) and a full copy-pasteable walkthrough — no edits needed.

## Build

```sh
cargo build --workspace
```

Both `client` and `server` expose their data over MQTT/Sparkplug B — see [MQTT (Sparkplug B) layer](mqtt-sparkplug.md) — so there's no filesystem driver dependency to worry about; any already-running MQTT broker (Mosquitto, HiveMQ, EMQX, ...) works, this project doesn't run one itself. [`examples/mqtt-broker`](../examples/mqtt-broker/README.md) has a disposable one for local testing.

## Run the server

```sh
cargo run -p server -- <device-description.toml> <connection> [--max-clients <n>] [--server-options <server-options.toml>]
```

`<connection>` is one of:

- `tcp://<bind-address:port>` — e.g. `tcp://0.0.0.0:502`
- `rtu://<serial-path>:<baud-rate>` — e.g. `rtu:///dev/ttyUSB0:9600`
- `tls+tcp://<bind-address:port>` — see [Connecting over TLS](tls.md) below.

`--max-clients` is optional (`tls+tcp://` only) and bounds how many client certificates can be approved at once — without it, there is no limit.

**`--server-options` controls which function codes this server will actually answer on the wire — and it's strict default-deny.** Without it (or with a present-but-empty file), *every* function code is disabled and every incoming request gets an `ILLEGAL_FUNCTION` exception, no matter how many function codes this project implements — `server` prints a loud startup warning if this ends up being the case, since "starts fine but answers nothing" is an easy flag to forget. Every function code this server can serve — including already-implemented ones like Read/Write Holding Registers — is attack surface exposed to any reachable Modbus master, so enabling one is an explicit technician choice, not an on-by-default assumption. Point it at a TOML file with a `[function-codes]` table, one boolean per function code, named after the operation:

```toml
[function-codes]
read_holding_registers = true
write_single_register = true
```

See the [function code table](function-codes.md) for every available key name, and [`server-options.toml`](server-options.md) for the full format.

Example:

```sh
cargo run -p server -- device.toml tcp://0.0.0.0:502 --server-options server-options.toml
```

`server` also has a second, unrelated invocation form for managing TLS client approvals — see [Connecting over TLS](tls.md):

```sh
cargo run -p server -- admin approve|revoke <fingerprint>
cargo run -p server -- admin list
```

## Run the client

```sh
cargo run -p client -- <device-description.toml> <connection> [unit-id] [poll-interval-ms] [--expect-server-fingerprint <fingerprint>] [--mqtt-broker <host:port>] [--mqtt-group-id <id>] [--mqtt-edge-node-id <id>] [--mqtt-primary-host-id <id>]
```

`<connection>` uses the same `tcp://`/`rtu://`/`tls+tcp://` scheme as the server. `<device-description.toml>` is required as a fallback, but if the server it connects to supports FC 43 (see [Device description discovery](#device-description-discovery-fc-43) below), the client uses the server's own description instead. `--mqtt-broker <host:port>` is **required** — the already-running broker to connect to; see [MQTT (Sparkplug B) layer](mqtt-sparkplug.md) for `--mqtt-group-id`/`--mqtt-edge-node-id`/`--mqtt-primary-host-id`. `client` fetches every configured machine's description at startup (needed to publish its Sparkplug `DBIRTH`), but only starts polling a machine's real Modbus data once a Host Application subscribes to it — see [MQTT (Sparkplug B) layer](mqtt-sparkplug.md) for the Subscribe/Unsubscribe mechanism.

`[unit-id]` is **only** used to address the initial FC 43 device-identification handshake — it's how the client asks *some* device on the link to introduce itself before it knows which Unit IDs are valid at all. Once the (possibly multi-machine) device description is known, each machine dispatches its own actual register/coil/etc. traffic via its own TOML-declared `unit_id`, not this CLI one. Defaults to `1` if omitted.

Example:

```sh
cargo run -p client -- device.toml tcp://127.0.0.1:502 1 1000 --mqtt-broker 127.0.0.1:1883
```

## Device description discovery (FC 43)

The client always requires a local `device-description.toml` path on the command line, but at startup it first asks the server for its own description over Modbus function code 43 (Encapsulated Interface Transport, MEI type 0x0E, Read Device Identification). If the server has one, the client uses it instead of the local file — printing progress as it fetches, since this can take a few round trips. If the server has none, doesn't support FC 43, or the fetch fails for any reason, the client transparently falls back to the local file.

## Next steps

- [Device description TOML format](device-description.md) — the full schema.
- [MQTT (Sparkplug B) layer](mqtt-sparkplug.md) — how both binaries expose their data.
- [Connecting over TLS](tls.md) — mutual TLS with client approval.
