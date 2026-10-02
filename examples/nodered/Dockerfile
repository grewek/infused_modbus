# Node-RED test container for infused_modbus's MQTT/Sparkplug B layer.
# Pre-installs the Sparkplug B palette this project's own CLAUDE.md research
# identified as the actively-maintained, industrial-focused choice
# (node-red-contrib-mqtt-sparkplug-plus) — see CLAUDE.md's "MQTT schema
# format: Sparkplug B" section for why this package specifically. Also
# installs @flowfuse/node-red-dashboard (Dashboard 2.0) — used by the
# "Rolling Door" flow's buttons/gauges/status indicators, see
# examples/rolling_door/README.md for the Rust side of that demo. The
# older `node-red-dashboard` package is explicitly unmaintained upstream
# (its own install warns to use this one instead) — same "actively
# maintained" bar this project already applied when choosing the Sparkplug
# palette itself.
FROM nodered/node-red:latest

RUN npm install --no-audit --no-update-notifier \
    node-red-contrib-mqtt-sparkplug-plus \
    @flowfuse/node-red-dashboard
