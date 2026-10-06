# MQTT (Sparkplug B) layer

Both `client` and `server` expose their Modbus data over MQTT using the [Sparkplug B](https://sparkplug.eclipse.org/) topic/payload conventions — no filesystem of any kind. The `client`↔`server` link itself is unaffected — still real Modbus over whatever `<connection>` was given; this is only about how the data is presented to the outside world.

A ready-to-use Node-RED test rig (Docker image + importable flow) for poking at this layer interactively is in [`examples/nodered/`](../examples/nodered/README.md).

## On `client`

`client` connects to an already-running MQTT broker as a Sparkplug B **Edge Node**, with each configured machine published as its own **Device** under that Edge Node. This project does not run a broker itself — point `--mqtt-broker` at any Sparkplug-capable broker (Mosquitto, HiveMQ, EMQX, ...); see [`examples/mqtt-broker`](../examples/mqtt-broker/README.md) for a disposable one to test against:

```sh
cargo run -p client -- device.toml tcp://127.0.0.1:502 --mqtt-broker 127.0.0.1:1883 --mqtt-group-id MyPlant --mqtt-edge-node-id Line1
```

- `NBIRTH`/`DBIRTH` are published once at startup (and again on a `Node Control/Rebirth` request) for **every** configured machine, with every register/coil/discrete-input/input-register/file-record as a metric — every value starts as an explicit `is_null` placeholder, since no real Modbus access has happened yet for a machine nobody has subscribed to (see "Subscribe/Unsubscribe" below).
- `NDATA`/`DDATA` publish only the metrics that actually changed since the last publish, checked on the same interval as `[poll-interval-ms]` — only for machines that are currently subscribed.
- `DCMD` is the write path — a metric write addressed to a Device is resolved against that machine's registers/coils/file-records (identified by alias once birth has established it, or by name) and applied over real Modbus, confirmed before anything is reported back as succeeded. Discrete inputs and input registers stay read-only, since no Modbus function code lets a master write either.
- `--mqtt-broker <host:port>` is **required** — the already-running broker to connect to. There is no embedded/default broker (see CLAUDE.md's "Embedded MQTT broker removed" for why).
- `--mqtt-group-id`/`--mqtt-edge-node-id` set this Edge Node's Sparkplug identity (defaults: `infused_modbus`/`client`) — **override `--mqtt-edge-node-id`** if more than one `client` instance connects to the same broker/host application, since it must be unique.
- `--mqtt-primary-host-id <id>` makes this Edge Node wait for the named Primary Host Application to report itself online (via its retained `spBv1.0/STATE/<id>` message) before publishing `NBIRTH`/`DBIRTH`, per spec. Omit it (the default) for the common case of no Primary Host Application at all — `NBIRTH` then publishes immediately, unchanged from before this flag existed.
- `bdSeq` (the Sparkplug session identifier distinguishing one connection from the next) is persisted across restarts in a small file, `client-mqtt-bdseq`, next to wherever `client` was started — this is required for spec conformance (a Host Application needs to tell a genuinely new session apart from a late-arriving death notice from an old one), not just an implementation detail.

### Subscribe/Unsubscribe — activating a machine at runtime

Every machine's shape is birthed immediately at startup (see above), but **real Modbus polling and `DDATA` only start once a Host Application actually subscribes to that machine** — fetching/polling/publishing data for machines nobody is watching would be wasted work, especially at scale. Subscribing/unsubscribing is a Node-level `NCMD` carrying one of two fixed, never-aliased metric names, same convention as `Node Control/Rebirth`:

- `Node Control/Subscribe` — value: the exact machine `name` (a Sparkplug `String`) to activate.
- `Node Control/Unsubscribe` — same shape, to deactivate it again (publishes `DDEATH` for that Device, stops its polling task).

Subscribing an already-active machine, or unsubscribing an inactive one, is a no-op, not an error. An unresolvable machine name is logged and skipped. Unsubscribing the last active machine doesn't tear down the Edge Node's own `NBIRTH`/Node session — only that one Device's lifecycle ends.

## On `server`

`server` exposes a local Unix domain socket (`server-data.sock`, created next to wherever the process was started) speaking a small line protocol — `SET <machine> <point> <value>` / `GET <machine> <point>`, e.g.:

```sh
echo "SET PumpA Tank_Temperature 55" | socat - UNIX-CONNECT:server-data.sock
echo "GET PumpA Tank_Temperature" | socat - UNIX-CONNECT:server-data.sock
```

The socket enforces the same validation (unknown point, read-only point, or a value that doesn't parse for that point's type all come back as `ERROR ...`) and applies successful writes straight to the same in-memory state an external Modbus master reads/writes. It is independent of, and never talks to, the client's MQTT side — a technician wiring up an external system to feed the server's own dataset (rather than reading it back out over Modbus) uses this socket directly, or a future host-process integration built on the same underlying `ServerHandle` library.
