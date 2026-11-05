#!/usr/bin/env bash
# Откат по факту: новый агент обязан оставаться активным. Свежесть state.json
# критерием не годится — при недоступном API состояние не переписывается, и
# исправный агент был бы откачен за то, что API молчал.
set -euo pipefail
bin=/usr/local/bin/novavpn-node-agent
if [ ! -x "$bin.prev" ]; then exit 0; fi
if systemctl is-active --quiet novavpn-node-agent; then exit 0; fi
systemctl stop novavpn-node-agent || true
mv -f "$bin.prev" "$bin"
systemctl start novavpn-node-agent
logger -t novavpn-rollback "агент не удержался активным; возвращён предыдущий бинарник"
