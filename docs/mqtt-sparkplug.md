# MQTT (Sparkplug B) layer

`--data-representation-layer mqtt` replaces the filesystem (`fuse`/`files`) with an MQTT interface using the [Sparkplug B](https://sparkplug.eclipse.org/) topic/payload conventions. The `client`↔`server` link itself is unchanged — still real Modbus over whatever `<connection>` was given; only how the data is presented to the outside world differs.

A ready-to-use Node-RED test rig (Docker image + importable flow) for poking at this layer interactively is in [`examples/nodered/`](../examples/nodered/README.md).

## On `client`

`client` connects to an already-running MQTT broker as a Sparkplug B **Edge Node**, with each configured machine published as its own **Device** under that Edge Node. This project does not run a broker itself — point `--mqtt-broker` at any Sparkplug-capable broker (Mosquitto, HiveMQ, EMQX, ...); see [`docker/mqtt-broker`](../docker/mqtt-broker/README.md) for a disposable one to test against:

```sh
cargo run -p client -- ignored device.toml tcp://127.0.0.1:502 --data-representation-layer mqtt --mqtt-broker 127.0.0.1:1883 --mqtt-group-id MyPlant --mqtt-edge-node-id Line1
```

- `NBIRTH`/`DBIRTH` are published once at startup (and again on a `Node Control/Rebirth` request) with every register/coil/discrete-input/input-register/file-record as a metric.
- `NDATA`/`DDATA` publish only the metrics that actually changed since the last publish, checked on the same interval as `[poll-interval-ms]`.
- `DCMD` is the write path — a metric write addressed to a Device is resolved against that machine's registers/coils/file-records (identified by alias once birth has established it, or by name) and applied over real Modbus, the same way a staged `transactions/` write would be. Discrete inputs and input registers stay read-only, since no Modbus function code lets a master write either.
- `--mqtt-broker <host:port>` is **required** — the already-running broker to connect to. There is no embedded/default broker (see CLAUDE.md's "Embedded MQTT broker removed" for why).
- `--mqtt-group-id`/`--mqtt-edge-node-id` set this Edge Node's Sparkplug identity (defaults: `infused_modbus`/`client`) — **override `--mqtt-edge-node-id`** if more than one `client` instance connects to the same broker/host application, since it must be unique.
- `--mqtt-primary-host-id <id>` makes this Edge Node wait for the named Primary Host Application to report itself online (via its retained `spBv1.0/STATE/<id>` message) before publishing `NBIRTH`/`DBIRTH`, per spec. Omit it (the default) for the common case of no Primary Host Application at all — `NBIRTH` then publishes immediately, unchanged from before this flag existed.
- `<root>` is ignored — there's no directory to mount or write to.
- `bdSeq` (the Sparkplug session identifier distinguishing one connection from the next) is persisted across restarts in a small file, `client-mqtt-bdseq`, next to wherever `client` was started — this is required for spec conformance (a Host Application needs to tell a genuinely new session apart from a late-arriving death notice from an old one), not just an implementation detail.

## On `server`

The filesystem is replaced by a local Unix domain socket (`server-data.sock`, created next to wherever the process was started) speaking a small line protocol — `SET <machine> <point> <value>` / `GET <machine> <point>`, e.g.:

```sh
echo "SET PumpA Tank_Temperature 55" | socat - UNIX-CONNECT:server-data.sock
echo "GET PumpA Tank_Temperature" | socat - UNIX-CONNECT:server-data.sock
```

This is the server-side equivalent of `holding-registers/<name>` being directly writable under `fuse`/`files` — the socket enforces the same validation (unknown point, read-only point, or a value that doesn't parse for that point's type all come back as `ERROR ...`) and applies successful writes straight to the same in-memory state an external Modbus master reads/writes. It is independent of, and never talks to, the client's MQTT side — a technician wiring up an external system to feed the server's own dataset (rather than reading it back out over Modbus) uses this socket directly, or a future host-process integration built on the same underlying `ServerHandle` library.
