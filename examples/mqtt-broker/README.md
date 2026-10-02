# Disposable MQTT test broker

`client --data-representation-layer mqtt` connects to an already-running
MQTT broker (`--mqtt-broker <host:port>`) — it does not run one itself, see
`CLAUDE.md`'s "Embedded MQTT broker removed" section for why. Any real
deployment is expected to already have a broker; this container is just a
disposable one for local testing, plain [Eclipse
Mosquitto](https://mosquitto.org/) with anonymous access on 1883. No auth,
no TLS — not for production use.

## 1. Build and run

```sh
docker build -t infused-modbus-mqtt-broker examples/mqtt-broker
docker run -d --name infused-modbus-mqtt-broker --network host \
    --restart unless-stopped infused-modbus-mqtt-broker
```

`--network host` is what lets `client` (and, if you're using it,
[`examples/nodered/`](../nodered/README.md)) reach `127.0.0.1:1883` without
any port-mapping setup. Linux-only, same constraint as the rest of this
project.

## 2. Point `client` at it

```sh
cargo run -p client -- ignored examples/device-description.toml tcp://127.0.0.1:15020 \
    --data-representation-layer mqtt --mqtt-broker 127.0.0.1:1883 \
    --mqtt-group-id MyPlant --mqtt-edge-node-id Line1
```

(Needs a running `server` too — see the top-level
[`examples/README.md`](../README.md) for a complete server+client
walkthrough.)

## 3. Stop/remove

```sh
docker stop infused-modbus-mqtt-broker
docker rm infused-modbus-mqtt-broker
```

No volume is used — the broker holds no state worth keeping between runs
for this project's purposes (no retained messages/subscriptions this project
relies on surviving a restart; `client`'s own Sparkplug session state,
`bdSeq`, is persisted on the `client` side instead, not the broker's).
