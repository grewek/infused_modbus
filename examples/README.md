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
- [`fuse-permissions.toml`](fuse-permissions.toml) — optional; shown here
  purely to demonstrate the format (locks `transactions/` down to its
  owner). Leave off `--fuse-permissions` entirely to skip this.

Run from the repository root. Both commands below default to
`--data-representation-layer files` — the same commands work identically
with `--data-representation-layer fuse` appended, mounting a real FUSE
filesystem instead of writing plain files; see [Directory
permissions](../docs/directory-permissions.md) and `CLAUDE.md`'s
"Pluggable data-representation layer" section for the difference.

## 1. Start the server

```sh
mkdir -p /tmp/infused-modbus-server
cargo run -p server -- /tmp/infused-modbus-server examples/device-description.toml tcp://127.0.0.1:15020 --server-options examples/server-options.toml
```

```
Mounting infused_modbus server (Files) at /tmp/infused-modbus-server, serving via tcp://127.0.0.1:15020 — machines: PumpA, PumpB
```

## 2. Start the client, in another terminal

```sh
mkdir -p /tmp/infused-modbus-client
cargo run -p client -- /tmp/infused-modbus-client examples/device-description.toml tcp://127.0.0.1:15020 1 500
```

The client fetches the device description from the server itself over FC 43
(printing progress as it does), so it ends up with the identical two-machine
setup without needing to trust its own local copy of the TOML stayed in
sync — see [Device description discovery](../docs/filesystem.md#device-description-discovery-fc-43).

## 3. Poke at it, in a third terminal

Every machine gets its own top-level directory — `PumpA/`, `PumpB/` — see
[Interacting with the filesystem](../docs/filesystem.md)
for the full picture. A few things to try:

```sh
# Write directly on the server (applies immediately, no staging) —
# Setpoint is read_write, so this works:
echo 72 > /tmp/infused-modbus-server/PumpA/holding-registers/Setpoint
echo 1 > /tmp/infused-modbus-server/PumpA/coils/Motor_Running

# ...and see it show up on the client's mirror after its next poll (< 1s later):
cat /tmp/infused-modbus-client/PumpA/holding-registers/Setpoint

# Tank_Temperature is declared read_only — a real device would be the only
# thing that ever sets it, so even the server itself refuses a direct write.
# Under --data-representation-layer fuse the kernel rejects the write
# outright (echo itself fails with "Permission denied"); under files (the
# default here) a real filesystem has no such hook, so echo succeeds but
# the rejected value is discarded and the file goes back to empty within
# a couple hundred milliseconds — same end state, briefer window either way:
echo 72 > /tmp/infused-modbus-server/PumpA/holding-registers/Tank_Temperature
sleep 1
cat /tmp/infused-modbus-server/PumpA/holding-registers/Tank_Temperature        # empty — nothing has set it

# Stage and commit a write from the client — this actually round-trips
# over the wire to the server and back:
echo 55 > /tmp/infused-modbus-client/PumpA/transactions/Stop_Process
touch /tmp/infused-modbus-client/PumpA/transactions/TRANSACTION_END
cat /tmp/infused-modbus-client/PumpA/report/Stop_Process     # OK, or FAILED: <reason>
cat /tmp/infused-modbus-server/PumpA/holding-registers/Stop_Process   # 55

# A machine's server-id, mirrored read-only on the client:
cat /tmp/infused-modbus-client/PumpA/server-id               # infused_modbus-pump-a

# PumpB is independent of PumpA — same directory shape, different Unit ID:
echo 1 > /tmp/infused-modbus-server/PumpB/coils/Motor_Running
cat /tmp/infused-modbus-client/PumpB/coils/Motor_Running

# An unconfigured machine name simply doesn't exist:
ls /tmp/infused-modbus-client/PumpC                          # No such file or directory
```

## 4. Shut down

Ctrl+C (or `SIGTERM`) either process — both clean up after themselves (unmounting, or removing the `files` root directory) on their own.

## Trying it over RTU or TLS instead

Swap the `tcp://127.0.0.1:15020` above for `rtu://<serial-path>:<baud-rate>`
or `tls+tcp://<bind-address:port>` on both commands — everything else here
works identically regardless of transport. See
[Supported connection types](../README.md#supported-connection-types) and
[Connecting over TLS](../docs/tls.md) for the details
(TLS additionally needs an approval step before the client's first
connection succeeds).

## Trying the MQTT/Sparkplug B layer instead

See [`nodered/`](nodered/README.md) for a Docker-based Node-RED test rig —
swap `--data-representation-layer mqtt` into the `client` command above and
watch/send Sparkplug B traffic from a real, independent Sparkplug
implementation.

## A custom Modbus server built on `ServerHandle`

See [`rolling_door/`](rolling_door/README.md) for a standalone Rust project
— a roller shutter door (emergency stop, light barrier, motor, remote
open/close) implemented as a real Modbus server whose own internal logic is
driven entirely through `server::server_handle::ServerHandle`'s typed Rust
API, not Modbus wire code.
