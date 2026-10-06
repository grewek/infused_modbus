# Rolling door (Rolltor) — a custom Modbus server built on `ServerHandle`

A self-contained Rust binary demonstrating `server::server_handle::ServerHandle`
— the typed, programmatic Rust API documented in `CLAUDE.md`'s "Programmatic
Rust API for `ServerHandle`" section — by implementing a real device: a
single roller shutter / industrial roll-up door, with an emergency stop, a
light barrier (safety interlock), a motor, and remote open/close commands.

It's a genuine Modbus TCP server (any real Modbus master can connect to
it), but its own internal "firmware" — the part that actually decides when
the motor runs, enforces the light-barrier interlock, and tracks
position — is implemented entirely through `ServerHandle`, not Modbus wire
code. This is the point of the example: `ServerHandle` lets you pull a real,
type-safe data layer directly into a process and drive it from plain Rust,
with the device description (`device-description.toml`) as the single
source of truth for what points exist and what type each one is.

## The data model

| Point | Kind | Who writes it | Meaning |
| ----- | ---- | -------------- | ------- |
| `Open_Command` | coil | any Modbus master | momentary "open" request |
| `Close_Command` | coil | any Modbus master | momentary "close" request |
| `Emergency_Stop` | discrete input | this program's console (`estop`) | local E-stop button |
| `Light_Barrier` | discrete input | this program's console (`block`) | obstruction detected |
| `Motor_Running` | discrete input | the simulation | motor currently driving the door |
| `Fully_Open` / `Fully_Closed` | discrete input | the simulation | limit switches |
| `Door_Position` | input register (`u8`) | the simulation | 0 (closed) – 100 (open) |

`Open_Command`/`Close_Command` are real coils because a remote system
(building automation, a SCADA panel) plausibly should be able to command
the door. Everything else is local panel/safety I/O — a real emergency stop
is hardwired directly to the controller, never a network-writable point,
which is exactly why this example writes it through `ServerHandle` (local,
in-process) rather than exposing it as a coil at all.

## Run it

```sh
cargo run -p rolling_door_server
```

```
Rolling door Modbus server listening on tcp://127.0.0.1:15502
Commands: estop | estop-clear | block | block-clear | status | help | quit (Ctrl+D also works)
```

Leave it running and, in another terminal, point this project's own
`client` at it — needs an already-running MQTT broker (see
[`examples/mqtt-broker/`](../mqtt-broker/README.md) for a disposable one):

```sh
cargo run -p client -- examples/rolling_door/device-description.toml tcp://127.0.0.1:15502 1 300 --mqtt-broker 127.0.0.1:1883
```

For a real point-and-click UI, see [`examples/nodered/`](../nodered/README.md)'s
"Rolling Door" dashboard tab — gauges/buttons wired to this exact server
over Sparkplug B: **Open**/**Close** buttons send a real Modbus write (a
Sparkplug `DCMD`), **Door Position** is a live gauge, and the limit
switches/motor/safety state show up as soon as they change. Try closing,
then block the light barrier from the server's own console (type `block`
there) while the door is mid-travel — it reverses back open.

Typing `estop` at the `rolling_door_server` console halts the motor
immediately regardless of what it was doing — `estop-clear` releases it.
`status` prints the current position/motor/safety state without needing a
second terminal at all.

## A couple of things worth noticing

- **The console is a convenience, not the server's lifetime.** Closing
  stdin (e.g. running this under a process supervisor with no TTY attached)
  stops the console from accepting commands, but the Modbus listener and
  the simulation keep running — shut the whole thing down with Ctrl+C/SIGTERM
  instead, same as this project's real `client`/`server` binaries.
- **Commands are momentary, not latched.** `Open_Command`/`Close_Command`
  are cleared back to `false` the instant the simulation consumes them —
  the same behavior a real momentary pushbutton contact has. Setting one
  while the door can't act on it yet (e.g. `Close_Command` while the light
  barrier is blocked) still gets cleared; it isn't queued for later.
- **Every data point here comes from `device-description.toml`.** Nothing
  in `src/main.rs` hardcodes a register's type or address — `ServerHandle`
  resolves names against the parsed description and rejects a value whose
  Rust type doesn't match what's declared (try changing `Door_Position`'s
  `data_type` to `u16` in the TOML without touching the Rust code: it still
  builds and runs correctly, since `RegisterValue::U8` is only ever
  constructed with the real declared type in mind — mismatch it
  deliberately and `set_input_register` returns `TypeMismatch` instead of
  silently doing the wrong thing).
