# Node-RED test container for infused_modbus's MQTT/Sparkplug B layer.
# Pre-installs the Sparkplug B palette this project's own CLAUDE.md research
# identified as the actively-maintained, industrial-focused choice
# (node-red-contrib-mqtt-sparkplug-plus) — see CLAUDE.md's "MQTT schema
# format: Sparkplug B" section for why this package specifically.
FROM nodered/node-red:latest

RUN npm install --no-audit --no-update-notifier \
    node-red-contrib-mqtt-sparkplug-plus
