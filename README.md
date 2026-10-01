# infused_modbus

A Modbus **client** (master) and Modbus **server** (slave) that expose the Modbus data they handle through a **FUSE filesystem** instead of — or in addition to — a conventional API. "Infused" refers to this live-updating FUSE projection of Modbus data: register values show up as readable files, and writes happen by writing to files, no client library required.

Both **Modbus TCP** and **Modbus RTU** (serial) are supported, symmetrically, for both the client and the server, plus a TLS-secured TCP transport with mutual TLS and a client-approval workflow. An alternative MQTT/Sparkplug B representation is also available, for integrating with Node-RED/SCADA-style tooling instead of a filesystem. See [Documentation](#documentation) below for the details on all of this.

## ⚠️ This project was built entirely with AI assistance

This codebase was designed and implemented in collaboration with **Claude Code** (Anthropic's AI coding agent), end to end — architecture, protocol implementation, tests, and this README. If you have concerns about AI-assisted software, or simply prefer not to use or review AI-generated code, **please don't spend your time on this project**. This is stated plainly and upfront so nobody invests effort here under a false impression.

## ⚠️ Early-stage software — do not treat this as secure

This project is under active development and has **not** had a security review. Neither `client` nor `server` should be considered hardened, and `server` in particular accepts Modbus connections from any master that can reach it, with no authentication outside of `tls+tcp://` (see [Connecting over TLS](docs/tls.md)) — plain `tcp://`/`rtu://` have none at all. Some individual inputs read from the wire are checked before use, but that describes isolated pieces of the implementation, not an overall security guarantee. Do not expose either binary to an untrusted network, and do not use this project anywhere a security failure would have real consequences.

## How this project came to be

- **grewek** is the project owner and architect: every design decision — the FUSE filesystem layout, the transaction/confirmation semantics, the choice of Modbus function codes, protocol framing tradeoffs, scope boundaries, naming — was made or explicitly approved by him. Development proceeded in small, reviewable increments, with a deliberate house style (extraction-based programming: write the concrete solution first, only generalize once a real second case shows its actual shape; no speculative abstraction).
- **Claude** implemented each increment against that direction: wrote the Rust code, the test suites, ran manual verification, and iterated based on review feedback after every step.

Nothing here shipped without a human decision behind it, but essentially all of the code was written by an AI. See the point above if that matters to you.

## What this is

- **No separate client API — the filesystem is the interface.** Reading a register's current value is `cat holding-registers/Tank_Temperature`. Writing one is `echo 55 > transactions/Stop_Process`.
- **Three interchangeable data-representation layers.** Real files on disk (the default), a synthetic FUSE mount, or an MQTT/Sparkplug B interface — same underlying data either way. See [Getting started](docs/getting-started.md).
- **Writes are staged and confirmed, not optimistic.** The client only updates its local mirror once a write is actually confirmed by the device; the server, having no separate device to confirm against, applies writes to its own directly-writable files immediately. See [Interacting with the filesystem](docs/filesystem.md).
- **TCP and RTU use the same code paths**, and the server can advertise its own register description to the client over the wire (FC 43) instead of relying on a hand-kept copy staying in sync.
- **Modbus implemented from scratch** — the `protocol` crate implements TCP/RTU framing, CRC16, and PDU encode/decode directly, rather than wrapping an existing crate.
- **One device description can describe several machines sharing one link** — e.g. several PLCs on one RTU multi-drop bus — each mounted under its own top-level directory. See [Device description TOML format](docs/device-description.md).
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

- [Getting started](docs/getting-started.md) — build, run the server, run the client.
- [Interacting with the filesystem](docs/filesystem.md) — the `ls`/`cat`/`echo` walkthrough, plus device description discovery (FC 43).
- [Device description TOML format](docs/device-description.md) — the full schema for describing one or more machines.
- [Supported Modbus function codes](docs/function-codes.md) — every function code in the spec, and this project's status on each.
- [MQTT (Sparkplug B) layer](docs/mqtt-sparkplug.md) — an alternative to the filesystem, for Node-RED/SCADA-style integration.
- [Connecting over TLS](docs/tls.md) — mutual TLS with client approval.
- [Directory permissions](docs/directory-permissions.md) — configuring `mode`/`uid`/`gid` per directory.
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
