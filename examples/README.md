# Runnable example

A ready-to-use, no-edits-needed setup demonstrating a two-machine device
description end to end — `server` serving two simulated pumps (`PumpA`,
`PumpB`) sharing one TCP link, and `client` connecting to it. See the
top-level [`README.md`](../README.md) for the full command-line reference
and [`CLAUDE.md`](../CLAUDE.md) for the design behind any of this.

- [`device-description.toml`](device-description.toml) — the two-machine
  description both binaries below are pointed at. `PumpA` exercises every
  data type this project supports (several register widths, coils, a
  discrete input, an input register, a file record, its own `server-id`);
  `PumpB` is deliberately minimal, to show a second machine doesn't need to
  repeat everything the first one declares.
- [`server-options.toml`](server-options.toml) — enables exactly the
  function codes `device-description.toml`'s data needs. Without
  `--server-options`, every function code defaults to disabled.

Both binaries expose their data over MQTT/Sparkplug B — see [MQTT
(Sparkplug B) layer](../docs/mqtt-sparkplug.md) — so you'll need an
already-running broker; [`mqtt-broker/`](mqtt-broker/README.md) has a
disposable one for exactly this.

## 1. Start a broker

```sh
docker build -t infused-modbus-mqtt-broker examples/mqtt-broker
docker run -d --name infused-modbus-mqtt-broker --network host \
    --restart unless-stopped infused-modbus-mqtt-broker
```

See [`mqtt-broker/README.md`](mqtt-broker/README.md) for details/teardown.

## 2. Start the server

```sh
cargo run -p server -- examples/device-description.toml tcp://127.0.0.1:15020 --server-options examples/server-options.toml
```

```
Starting infused_modbus server, serving via tcp://127.0.0.1:15020 — machines: PumpA, PumpB
Data socket listening at server-data.sock
```

## 3. Start the client, in another terminal

```sh
cargo run -p client -- examples/device-description.toml tcp://127.0.0.1:15020 1 500 --mqtt-broker 127.0.0.1:1883
```

The client fetches the device description from the server itself over FC 43
(printing progress as it does), so it ends up with the identical two-machine
setup without needing to trust its own local copy of the TOML stayed in
sync — see [Device description discovery](../docs/getting-started.md#device-description-discovery-fc-43).
Nobody has subscribed to either machine yet, so both are birthed (`DBIRTH`)
with placeholder values but neither is actually polled over Modbus — see
[Subscribe/Unsubscribe](../docs/mqtt-sparkplug.md#subscribeunsubscribe-activating-a-machine-at-runtime).

## 4. Poke at it, in a third terminal

The server's own writes are the easiest to try from a plain shell — its
local data socket speaks a small text protocol, no Sparkplug decoding
needed:

```sh
# Setpoint is read_write, so this works:
echo "SET PumpA Setpoint 72" | socat - UNIX-CONNECT:server-data.sock
echo "GET PumpA Setpoint" | socat - UNIX-CONNECT:server-data.sock

# Tank_Temperature is declared read_only — a real device would be the only
# thing that ever sets it, so even the server itself refuses this:
echo "SET PumpA Tank_Temperature 72" | socat - UNIX-CONNECT:server-data.sock   # ERROR ...
```

Sparkplug B payloads are protobuf-encoded, not human-readable through a
plain MQTT client — to actually watch/send decoded traffic (subscribe a
machine, see `DDATA` as values change, send a `DCMD` write from the client
side), use [`nodered/`](nodered/README.md)'s generic listener/sender tab
against a real, independent Sparkplug B implementation.

## 5. Shut down

Ctrl+C (or `SIGTERM`) either `client` or `server` — both disconnect
cleanly from the broker on their own.

## Trying it over RTU or TLS instead

Swap the `tcp://127.0.0.1:15020` above for `rtu://<serial-path>:<baud-rate>`
or `tls+tcp://<bind-address:port>` on both commands — everything else here
works identically regardless of transport. See
[Supported connection types](../README.md#supported-connection-types) and
[Connecting over TLS](../docs/tls.md) for the details
(TLS additionally needs an approval step before the client's first
connection succeeds).

## A custom Modbus server built on `ServerHandle`

See [`rolling_door/`](rolling_door/README.md) for a standalone Rust project
— a roller shutter door (emergency stop, light barrier, motor, remote
open/close) implemented as a real Modbus server whose own internal logic is
driven entirely through `server::server_handle::ServerHandle`'s typed Rust
API, not Modbus wire code.
