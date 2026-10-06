# infused_modbus

A Modbus **client** (master) and Modbus **server** (slave) that expose the Modbus data they handle over **MQTT**, using the **Sparkplug B** topic/payload conventions — register values are published as Sparkplug metrics, and writes arrive as Sparkplug `DCMD` commands, so any Sparkplug-aware consumer (Node-RED, an MES, a SCADA host) can integrate without a custom client library.

Both **Modbus TCP** and **Modbus RTU** (serial) are supported, symmetrically, for both the client and the server, plus a TLS-secured TCP transport with mutual TLS and a client-approval workflow. See [Documentation](#documentation) below for the details on all of this.

## Why "infused_modbus"?

The name comes from this project's original design: a live-updating **FUSE** filesystem projection of Modbus data — register values as readable files, writes as file writes, no client library required ("infused" referring to Modbus data infused into the filesystem). Two representation layers were built on that idea, a real FUSE mount and later a plain-files-on-disk variant meant to avoid some of FUSE's own overhead — both worked, but in practice both still carried real races and round-trip overhead that proved hard to eliminate cleanly. Rather than continuing to chase that, development moved to the MQTT/Sparkplug B layer instead — and once that layer had fully proven itself out, both filesystem-based layers were removed outright (see `CLAUDE.md`'s "FUSE and `files` representation layers removed" section for the full rationale). The name stuck anyway.

## ⚠️ This project was built entirely with AI assistance

This codebase was designed and implemented in collaboration with **Claude Code** (Anthropic's AI coding agent), end to end — architecture, protocol implementation, tests, and this README. If you have concerns about AI-assisted software, or simply prefer not to use or review AI-generated code, **please don't spend your time on this project**. This is stated plainly and upfront so nobody invests effort here under a false impression.

## ⚠️ Early-stage software — do not treat this as secure

This project is under active development and has **not** had a security review. Neither `client` nor `server` should be considered hardened, and `server` in particular accepts Modbus connections from any master that can reach it, with no authentication outside of `tls+tcp://` (see [Connecting over TLS](docs/tls.md)) — plain `tcp://`/`rtu://` have none at all. Some individual inputs read from the wire are checked before use, but that describes isolated pieces of the implementation, not an overall security guarantee. Do not expose either binary to an untrusted network, and do not use this project anywhere a security failure would have real consequences.

## What this is

- **Data is exposed over MQTT, using Sparkplug B.** `client` connects to an already-running MQTT broker (this project doesn't run one itself) as a Sparkplug B Edge Node, publishing each machine as its own Device (`NBIRTH`/`DBIRTH` once at startup, `NDATA`/`DDATA` on change); a write arrives as a `DCMD`. `server` exposes a small local socket an external system can use to read/update its own dataset directly. See [MQTT (Sparkplug B) layer](docs/mqtt-sparkplug.md).
- **Writes are confirmed, not optimistic.** The client only updates its own view of a register once a write is actually confirmed by the device; the server, having no separate device to confirm against, applies a direct write to its own state immediately.
- **TCP and RTU use the same code paths**, and the server can advertise its own register description to the client over the wire (FC 43) instead of relying on a hand-kept copy staying in sync.
- **Modbus implemented from scratch** — the `protocol` crate implements TCP/RTU framing, CRC16, and PDU encode/decode directly, rather than wrapping an existing crate.
- **One device description can describe several machines sharing one link** — e.g. several PLCs on one RTU multi-drop bus — each published as its own Sparkplug B Device. See [Device description TOML format](docs/device-description.md).
- **`client` reconnects automatically** with exponential backoff if the connection breaks, retrying forever — no manual restart needed.

See [Documentation](#documentation) below for the full picture, and `CLAUDE.md` for the design rationale behind all of it.

## Client vs. server

- **`client`** acts as a Modbus master against a connected device. It polls the device to keep its local mirror fresh, and turns staged writes into Modbus writes, updating the mirror only once the device confirms them.
- **`server`** acts as a Modbus slave that external Modbus masters query and write against. Its own in-memory state is what's being served — an external write applies immediately and is reflected locally, and a local write is visible to external masters on their very next read.

This has been tested against this project's own client/server implementations and against virtual serial ports, not against third-party PLC or SCADA hardware or software — whether it interoperates with a specific real-world device or system has not been verified.

## Supported connection types

| Scheme | Transport | Status |
| ------ | --------- | ------ |
| `tcp://<address:port>` | Plain Modbus TCP | Supported |
| `rtu://<serial-path>:<baud-rate>` | Modbus RTU over a serial link | Supported (secondary — TCP gets the primary design/testing attention) |
| `tls+tcp://<address:port>` | Modbus TCP over TLS (mutual TLS, fingerprint pinning, client approval) | Supported — see [Connecting over TLS](docs/tls.md) |

A given `client`/`server` instance uses exactly one of these at a time — they are never combined on the same instance.

## Getting started

```sh
cargo build --workspace
```

Requires Linux. [`examples/`](examples/) has a ready-to-use, two-machine setup with a full copy-pasteable walkthrough — no edits needed. See [Getting started](docs/getting-started.md) for the full command-line reference for both binaries.

## Documentation

- [MQTT (Sparkplug B) layer](docs/mqtt-sparkplug.md) — the primary data interface.
- [Getting started](docs/getting-started.md) — build, run the server, run the client.
- [Device description TOML format](docs/device-description.md) — the full schema for describing one or more machines.
- [Supported Modbus function codes](docs/function-codes.md) — every function code in the spec, and this project's status on each.
- [Connecting over TLS](docs/tls.md) — mutual TLS with client approval.
- [server-options.toml](docs/server-options.md) — explicitly enabling which function codes `server` answers.
- [Current limitations](docs/limitations.md).
- `CLAUDE.md` — full architecture and design-decision history.

## Development

```sh
cargo build --workspace
cargo test --workspace
cargo test -p <crate-name> <test_name>   # run a single test in one crate
cargo clippy --workspace --all-targets
cargo fmt --all
```
