# Node-RED Sparkplug B test rig

A Docker image + a ready-to-import flow for exercising infused_modbus's
MQTT/Sparkplug B layer (`client --data-representation-layer mqtt`) against a
real, independent Sparkplug B implementation — Node-RED's
[`node-red-contrib-mqtt-sparkplug-plus`](https://flows.nodered.org/node/node-red-contrib-mqtt-sparkplug-plus)
palette, built on `sparkplug-payload` (the Eclipse reference codec). See
`CLAUDE.md`'s "MQTT (Sparkplug B) representation layer" section for why this
specific package was chosen, and its "Additional cross-check beyond the TCK"
note for what this rig already caught/confirmed.

Most of the documentation lives **on the canvas itself**, as comment nodes —
open the flow in the editor and read them before poking at anything. This
README only covers getting the container running.

## 1. Start a broker

`client` no longer runs an MQTT broker itself (see `CLAUDE.md`'s "Embedded
MQTT broker removed") — start the disposable test broker in
[`examples/mqtt-broker/`](../mqtt-broker/README.md) first, since both
Node-RED and `client` need one to connect to.

## 2. Build and run the container

```sh
docker build -t nodered-sparkplug-test examples/nodered
docker volume create nodered_sparkplug_data
docker run -d --name nodered-sparkplug-test --network host \
    -v nodered_sparkplug_data:/data --restart unless-stopped \
    nodered-sparkplug-test
```

`--network host` is what lets the container reach `127.0.0.1:1883` — where
the test broker above listens — without any port-mapping setup. This is
Linux-only, same constraint as the rest of this project (FUSE is
Linux-only too).

The editor is now at **http://localhost:1880**.

## 3. Import the flow

Either paste `flow.json`'s contents via the editor's menu
(**Import → paste**), or deploy it directly from the command line:

```sh
curl -s -X POST http://127.0.0.1:1880/flows \
    -H "Content-Type: application/json" \
    -H "Node-RED-Deployment-Type: full" \
    --data-binary @examples/nodered/flow.json
```

## 4. Point `client` at it

```sh
cargo run -p client -- ignored examples/device-description.toml tcp://127.0.0.1:15020 \
    --data-representation-layer mqtt --mqtt-broker 127.0.0.1:1883 \
    --mqtt-group-id MyPlant --mqtt-edge-node-id Line1
```

(Needs a running `server` too — see the top-level `examples/README.md` for
a complete server+client walkthrough; swap in `--data-representation-layer
mqtt` on the client command there.)

**Before anything shows up**, open the two function nodes on the canvas
("build Rebirth NCMD" and "set DCMD topic") and edit their `GROUP_ID`/
`EDGE_NODE_ID`/`DEVICE_ID` constants to match what you passed to `client`
above. This is the single most common reason nothing appears to be
happening — see the on-canvas comments for why it's not auto-discovered.

## 5. What's in the flow

- **Listener** (`mqtt sparkplug in` on `spBv1.0/#` → `debug`): shows every
  Sparkplug message from anything on the broker, decoded. The debug node
  also logs to the container's stdout (`docker logs nodered-sparkplug-test`),
  so this is scriptable/headlessly-checkable too, not just UI-only.
- **Request Rebirth**: an inject button that asks `client` to republish its
  current state (`NBIRTH`+`DBIRTH`) on demand — needed because births are
  not retained, see the on-canvas comment.
- **Send Data (DCMD)**: an inject node with an editable JSON payload — change
  which metrics/values it sends without touching any code, then watch the
  write land for real over Modbus.

## 6. Stop/remove

```sh
docker stop nodered-sparkplug-test      # keeps the container + flow state
docker rm nodered-sparkplug-test        # also drop the container (volume survives)
docker volume rm nodered_sparkplug_data # also drop the saved flow/settings
```

(Plus the broker from step 1 — see
[`examples/mqtt-broker/`](../mqtt-broker/README.md#3-stopremove).)
