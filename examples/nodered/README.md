# Node-RED Sparkplug B test rig

A Docker image + a ready-to-import flow for exercising infused_modbus's
MQTT/Sparkplug B layer against a real, independent Sparkplug B
implementation — Node-RED's
[`node-red-contrib-mqtt-sparkplug-plus`](https://flows.nodered.org/node/node-red-contrib-mqtt-sparkplug-plus)
palette, built on `sparkplug-payload` (the Eclipse reference codec). See
`CLAUDE.md`'s "MQTT (Sparkplug B) representation layer" section for why this
specific package was chosen, and its "Additional cross-check beyond the TCK"
note for what this rig already caught/confirmed.

`flow.json` has **two tabs**: a generic raw-Sparkplug listener/sender for
poking at any `client` instance (debug output, free-form DCMD), and a
"Rolling Door" tab with a real [`@flowfuse/node-red-dashboard`](https://dashboard.flowfuse.com/)
UI (gauges/buttons) wired specifically to
[`examples/rolling_door/`](../rolling_door/README.md)'s Modbus server — see
step 5 below.

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
the test broker above listens — without any port-mapping setup.

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
cargo run -p client -- examples/device-description.toml tcp://127.0.0.1:15020 \
    --mqtt-broker 127.0.0.1:1883 \
    --mqtt-group-id MyPlant --mqtt-edge-node-id Line1
```

(Needs a running `server` too — see the top-level `examples/README.md` for
a complete server+client walkthrough.)

**Before anything shows up**, open the two function nodes on the canvas
("build Rebirth NCMD" and "set DCMD topic") and edit their `GROUP_ID`/
`EDGE_NODE_ID`/`DEVICE_ID` constants to match what you passed to `client`
above. This is the single most common reason nothing appears to be
happening — see the on-canvas comments for why it's not auto-discovered.

## 5. What's in the flow

### Tab 1: "infused_modbus Sparkplug test" (generic, any device)

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

### Tab 2: "infused_modbus Rolling Door (Rolltor)" — a real dashboard

A ready-to-use UI for [`examples/rolling_door/`](../rolling_door/README.md)'s
roller-shutter-door Modbus server, at **http://localhost:1880/dashboard/rolling-door**
once deployed:

```sh
cargo run -p rolling_door_server
cargo run -p client -- examples/rolling_door/device-description.toml tcp://127.0.0.1:15502 \
    --mqtt-broker 127.0.0.1:1883 \
    --mqtt-group-id NodeRedTest --mqtt-edge-node-id ClaudeClient
```

(The function nodes on this tab's canvas default to exactly these
`GROUP_ID`/`EDGE_NODE_ID` values — edit them there only if you pass different
`--mqtt-group-id`/`--mqtt-edge-node-id` values to `client`. `RollingDoor`,
the device/machine name, is fixed — it comes straight from
`device-description.toml` and never needs editing.)

The dashboard shows:

- **Door Position** — a live gauge (0–100%).
- **Motor / Fully Open / Fully Closed / Emergency Stop / Light Barrier** —
  plain-text status, refreshed as soon as a metric changes (`DDATA`) or on
  a full snapshot (`DBIRTH`/Rebirth).
- **Open / Close** buttons — send a real, momentary `DCMD` that `client`
  resolves to a real Modbus write; watch **Door Position** move and the
  limit switches update in response.
- **Request Rebirth** — same purpose as Tab 1's version, scoped to this
  device: use it if you deployed this flow (or opened the dashboard) after
  `client` already published its one-time birth.

## 6. Stop/remove

```sh
docker stop nodered-sparkplug-test      # keeps the container + flow state
docker rm nodered-sparkplug-test        # also drop the container (volume survives)
docker volume rm nodered_sparkplug_data # also drop the saved flow/settings
```

(Plus the broker from step 1 — see
[`examples/mqtt-broker/`](../mqtt-broker/README.md#3-stopremove).)
