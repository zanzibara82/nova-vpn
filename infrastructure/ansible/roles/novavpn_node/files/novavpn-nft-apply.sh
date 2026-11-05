#!/usr/bin/env bash
# delete+add, а не только «nft -f»: повторный прогон с тем же шаблоном иначе
# накапливал бы правила в таблице, и вторая копия NAT-правила осталась бы жить.
set -euo pipefail
nft delete table inet novavpn 2>/dev/null || true
nft -f /etc/novavpn-node/novavpn.nft
