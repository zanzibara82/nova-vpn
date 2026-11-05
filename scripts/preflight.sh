#!/usr/bin/env bash
# Запускается на целевом хосте от root до установки: проверяет хост, а не роль.
set -euo pipefail
FAIL=0
ok()  { printf 'ok   %s\n' "$*"; }
bad() { FAIL=1; printf 'FAIL %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || bad "нужен root"
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ok "ОС: ${PRETTY_NAME:-$ID}" ;;
  *) bad "ОС ${PRETTY_NAME:-неизвестна}: роль рассчитана на Debian/Ubuntu" ;;
esac

KVER=$(uname -r | cut -d- -f1)
if printf '%s\n%s\n' "5.6" "$KVER" | sort -V -C; then
  ok "ядро $KVER не старше 5.6 (WireGuard в ядре)"
else
  bad "ядро $KVER старше 5.6: WireGuard в ядре недоступен"
fi

if modprobe wireguard 2>/dev/null; then ok "модуль wireguard загружается"; else bad "модуль wireguard недоступен"; fi

if ss -lunptH 2>/dev/null | grep -qE ':(53|51820)([[:space:]]|$)'; then
  bad "порт 53 или 51820 уже занят"
else
  ok "порты 53 и 51820 свободны"
fi

if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then
  ok "часы синхронизированы"
else
  bad "часы не синхронизированы: DNSSEC и TLS требуют верного времени"
fi

API_HOST=${1:-api.novavpn.example}
if getent hosts "$API_HOST" >/dev/null; then ok "имя $API_HOST разрешается"; else bad "имя $API_HOST не разрешается"; fi

# Прод-конфиг unbound намеренно без форвардера: узел рекурсирует сам от корня.
# Если хостинг режет исходящий UDP/53, роль отработает зелёной, а узел останется
# без DNS и без регистрации.
if ! command -v dig >/dev/null; then
  bad "нет команды dig: исходящая рекурсия не проверена"
elif [ -n "$(dig +tries=1 +time=3 +noall +answer @198.41.0.4 NS . 2>/dev/null)" ]; then
  ok "исходящий 53 работает: корневой сервер 198.41.0.4 (m.root-servers.net) ответил"
else
  bad "исходящий 53 не отвечает: рекурсия без форвардера не заработает, узел останется без DNS"
fi

command -v nft >/dev/null && ok "nftables есть" || bad "нет команды nft"
command -v ss  >/dev/null && ok "iproute2 есть" || bad "нет команды ss"

if [ -n "$(ls -A /var/lib/novavpn-node 2>/dev/null || true)" ]; then
  bad "/var/lib/novavpn-node не пуст: узел, возможно, уже установлен"
else
  ok "каталог состояния пуст"
fi

USED=$(df -P / | awk 'NR==2 { gsub("%", "", $5); print $5 }')
if [ "${USED:-100}" -lt 90 ]; then ok "корень занят на ${USED} %"; else bad "корень занят на ${USED} %: меньше 90 % обязательно"; fi

if [ "$FAIL" -ne 0 ]; then
  printf '\n%s\n' 'предварительная проверка не пройдена: установку не начинать' >&2
  exit 1
fi
printf '\n%s\n' 'хост готов'
