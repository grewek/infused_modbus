# Disposable MQTT broker for local testing of infused_modbus's MQTT/
# Sparkplug B layer (`client --data-representation-layer mqtt`), which does
# not run a broker itself — see CLAUDE.md's "Embedded MQTT broker removed"
# for why. Plain Eclipse Mosquitto with anonymous access on 1883, nothing
# project-specific baked in beyond that config. Not for production use: no
# auth, no TLS.
FROM eclipse-mosquitto:2

COPY mosquitto.conf /mosquitto/config/mosquitto.conf
