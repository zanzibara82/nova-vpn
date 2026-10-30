#!/usr/bin/env bash
# Оффлайн-проверки управляющей логики стенда E2E на подставных инструментах.
# Здесь не поднимается ни один контейнер стенда и не проверяется путь пакетов:
# проверяются только отказы и границы скриптов (неизвестная фаза, занятые ресурсы,
# чужой стенд, очистка, повреждённый ключ, неожиданный конфиг API, порядок NAT/DNS).
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
E2E="$ROOT/scripts/e2e.sh"
CLIENT_ENTRY="$ROOT/infrastructure/docker/e2e/client-entrypoint.sh"
NODE_ENTRY="$ROOT/infrastructure/docker/e2e/node-entrypoint.sh"

FAILS=0
CASES=0

ok()   { CASES=$((CASES + 1)); printf 'ok   %s\n' "$*"; }
bad()  { CASES=$((CASES + 1)); FAILS=$((FAILS + 1)); printf 'FAIL %s\n' "$*" >&2; }
check() { # код, описание
	local code=$1
	shift
	if [ "$code" -eq 0 ]; then ok "$*"; else bad "$*"; fi
}

TMPROOT=$(mktemp -d)
trap 'rm -rf "$TMPROOT"' EXIT

# fake_tools создаёт каталог подставных инструментов и файл состояния.
fake_tools() { # имя_каталога
	local dir=$1
	mkdir -p "$dir/bin" "$dir/state"
	: > "$dir/log"
	printf '%s\n' "$dir/state/ps" > "$dir/state/ps.path"
	: > "$dir/state/ps"
	: > "$dir/state/networks"
	: > "$dir/state/volumes"

	cat > "$dir/bin/docker" <<'FAKE'
#!/bin/sh
printf 'docker %s\n' "$*" >> "$FAKE_LOG"
state=$FAKE_STATE
case "$1" in
info|version) exit 0 ;;
ps) cat "$state/ps"; exit 0 ;;
inspect)
	# docker inspect --format ... имя: метка владельца контейнера
	printf '%s' "${FAKE_LABEL-novavpn-e2e}"
	exit 0 ;;
container)
	if [ "$2" = "inspect" ]; then
		grep -qx "$3" "$state/ps" && exit 0
		exit 1
	fi
	exit 0 ;;
network)
	shift
	case "$1" in
	inspect)
		for a in "$@"; do name=$a; done
		if grep -qx "$name" "$state/networks"; then
			printf '%s' "${FAKE_NET_LABEL-novavpn-e2e}"
			exit 0
		fi
		exit 1 ;;
	create) printf '%s\n' "$3" >> "$state/networks"; exit 0 ;;
	rm)
		name=$2
		[ "$name" = "-f" ] && name=$3
		grep -vx "$name" "$state/networks" > "$state/networks.tmp" || true
		mv "$state/networks.tmp" "$state/networks"
		[ "${FAKE_FAIL_NET_RM:-0}" = 1 ] && exit 1
		exit 0 ;;
	esac
	exit 0 ;;
volume)
	shift
	case "$1" in
	inspect)
		for a in "$@"; do name=$a; done
		if grep -qx "$name" "$state/volumes"; then
			case " $* " in
			*" -f "*|*" --format "*) printf '%s' "${FAKE_VOL_LABEL-novavpn-e2e}" ;;
			esac
			exit 0
		fi
		exit 1 ;;
	create) printf '%s\n' "$3" >> "$state/volumes"; exit 0 ;;
	rm)
		name=$2
		grep -vx "$name" "$state/volumes" > "$state/volumes.tmp" || true
		mv "$state/volumes.tmp" "$state/volumes"
		[ "${FAKE_FAIL_VOL_RM:-0}" = 1 ] && exit 1
		exit 0 ;;
	esac
	exit 0 ;;
rm)
	name=$3
	[ "$2" = "-f" ] || name=$2
	grep -vx "$name" "$state/ps" > "$state/ps.tmp" || true
	mv "$state/ps.tmp" "$state/ps"
	[ "${FAKE_FAIL_RM:-0}" = 1 ] && exit 1
	exit 0 ;;
compose)
	case "$*" in
	*" version"*) exit 0 ;;
	esac
	[ "${FAKE_FAIL_COMPOSE:-0}" = 1 ] && exit 1
	case "$*" in
	*" down"*) : > "$state/ps" ;;
	esac
	exit 0 ;;
esac
exit 0
FAKE

	cat > "$dir/bin/wg" <<'FAKE'
#!/bin/sh
printf 'wg %s\n' "$*" >> "$FAKE_LOG"
if [ "$1" = "pubkey" ]; then
	if [ "${FAKE_WG_PUBKEY_FAIL:-0}" = 1 ]; then exit 1; fi
	cat >/dev/null
	printf '%s\n' "${FAKE_WG_PUBKEY:-public-key-placeholder=}"
	exit 0
fi
if [ "$1" = "genkey" ]; then
	printf '%s\n' "generated-private-key-placeholder="
	exit 0
fi
exit 0
FAKE

	cat > "$dir/bin/wg-quick" <<'FAKE'
#!/bin/sh
printf 'wg-quick %s\n' "$*" >> "$FAKE_LOG"
exit 0
FAKE

	cat > "$dir/bin/nft" <<'FAKE'
#!/bin/sh
printf 'nft %s\n' "$*" >> "$FAKE_LOG"
case "$1" in
list)
	if [ -e "$FAKE_STATE/table" ]; then exit 0; fi
	: > "$FAKE_STATE/table"
	exit 1 ;;
-f)
	[ "${FAKE_FAIL_NFT_APPLY:-0}" = 1 ] && exit 1
	: > "$FAKE_STATE/table"
	exit 0 ;;
delete) exit 0 ;;
esac
exit 0
FAKE

	cat > "$dir/bin/unbound-checkconf" <<'FAKE'
#!/bin/sh
printf 'unbound-checkconf %s\n' "$*" >> "$FAKE_LOG"
exit 0
FAKE

	cat > "$dir/bin/unbound" <<'FAKE'
#!/bin/sh
printf 'unbound %s\n' "$*" >> "$FAKE_LOG"
# Путь pid-файла совпадает с тем, что ждёт точка входа узла; конфигурацию
# проверяет отдельный подставной unbound-checkconf.
printf '%s\n' "$$" > /run/unbound.pid
exit 0
FAKE

	cat > "$dir/bin/su-exec" <<'FAKE'
#!/bin/sh
printf 'su-exec %s\n' "$*" >> "$FAKE_LOG"
exit 0
FAKE

	chmod +x "$dir/bin"/*
}

# run_e2e — запуск scripts/e2e.sh с подставными инструментами.
run_e2e() { # каталог, состояние, аргументы...
	local dir=$1 state=$2
	shift 2
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	E2E_STATE_DIR="$state" bash "$E2E" "$@" > "$dir/out" 2>&1
}

# assert_no_mutation — в журнале подставного docker нет создающих/удаляющих команд.
assert_no_mutation() {
	if grep -Eq 'network create|volume create|compose .* (up|down|run|build)|network rm|volume rm|docker rm' "$1"; then
		return 1
	fi
	return 0
}

# 1. Неизвестная фаза отвергается до любых обращений к Docker.
dir="$TMPROOT/phase"; mkdir -p "$dir/state-run"; fake_tools "$dir"
run_e2e "$dir" "$dir/state-run" bogus
code=$?
[ "$code" -ne 0 ] && [ ! -s "$dir/log" ] && grep -q 'неизвестная фаза' "$dir/out"
check $? "неизвестная фаза отвергнута до вызова Docker (код $code)"

# 2. Неизвестный E2E_PHASE отвергается так же.
dir="$TMPROOT/envphase"; mkdir -p "$dir/state-run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
E2E_STATE_DIR="$dir/state-run" E2E_PHASE=dns bash "$E2E" > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && [ ! -s "$dir/log" ] && grep -q 'неизвестная фаза' "$dir/out"
check $? "E2E_PHASE=dns отвергнут до вызова Docker (код $code)"

# 3. Занятое имя проекта отвергается до создания ресурсов.
dir="$TMPROOT/busy"; mkdir -p "$dir/state-run"; fake_tools "$dir"
printf 'novavpn-e2e-postgres-1\n' > "$dir/state/ps"
run_e2e "$dir" "$dir/state-run" all
code=$?
[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" && grep -q 'занят' "$dir/out"
check $? "повторный запуск при занятом имени отвергнут без создания ресурсов (код $code)"

# 4. Маркер прошлого запуска в control-томе отвергает повтор.
dir="$TMPROOT/marker"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
printf 'novavpn-e2e previous-run\n' > "$dir/state-run/run/owner"
run_e2e "$dir" "$dir/state-run" all
code=$?
[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" && grep -q 'прошл' "$dir/out"
check $? "маркер прошлого запуска отвергнут без изменений (код $code)"

# 5. e2e-down не удаляет чужой контейнер без метки владельца.
dir="$TMPROOT/foreign"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
printf 'novavpn-e2e-runner\n' > "$dir/state/ps"
printf 'novavpn-e2e_harness\n' > "$dir/state/networks"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_LABEL="" \
E2E_STATE_DIR="$dir/state-run" bash "$E2E" down > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && ! grep -Eq 'docker rm|network rm|volume rm|compose .* down' "$dir/log" \
	&& grep -q 'чуж' "$dir/out"
check $? "чужой/прежний стенд без метки не удалён (код $code)"

# 6. Ошибка очистки Compose даёт ненулевой итог.
dir="$TMPROOT/cleanup"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
printf 'novavpn-e2e previous-run\n' > "$dir/state-run/run/owner"
printf 'novavpn-e2e_harness\n' > "$dir/state/networks"
printf 'novavpn-e2e-control\n' > "$dir/state/volumes"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
FAKE_FAIL_COMPOSE=1 E2E_STATE_DIR="$dir/state-run" bash "$E2E" down > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && grep -q 'очистк' "$dir/out"
check $? "ошибка очистки Compose даёт ненулевой код (код $code)"

# 7. Первоначальный отказ не затирается ошибкой журналирования.
dir="$TMPROOT/exitcode"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
FAKE_FAIL_COMPOSE=1 E2E_STATE_DIR="$dir/state-run" \
bash -c 'source "$0" || exit 9; trap on_exit EXIT; exit 7' "$E2E" > "$dir/out" 2>&1
code=$?
[ "$code" -eq 7 ]
check $? "исходный отказ 7 не затёрт отказом журналирования (код $code)"

# 8. Повреждённый клиентский ключ не перевыпускается и не меняется.
dir="$TMPROOT/genkey"; mkdir -p "$dir/state-run" "$dir/state-client"; fake_tools "$dir"
printf 'не-ключ\n' > "$dir/state-client/client.key"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_WG_PUBKEY_FAIL=1 \
CLIENT_STATE_DIR="$dir/state-client" timeout 10 sh "$CLIENT_ENTRY" genkey > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && [ "$(cat "$dir/state-client/client.key")" = "не-ключ" ] \
	&& ! grep -q '^wg genkey' "$dir/log"
check $? "повреждённый ключ клиента не перевыпущен (код $code)"

# 9. Клиентский конфиг с неожиданным полем или секцией отвергается до wg-quick.
valid_config() {
	cat <<'CONF'
[Interface]
Address = 10.99.7.2/32
DNS = 10.99.7.1
MTU = 1420

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 0.0.0.0/0
Endpoint = 172.31.99.2:51820
PersistentKeepalive = 25
CONF
}

reject_config() { # описание, тело-файл
	local what=$1 body=$2
	local dir print
	dir=$(mktemp -d "$TMPROOT/cfg.XXXXXX")
	fake_tools "$dir"
	mkdir -p "$dir/state-run" "$dir/state-client"
	printf '%s\n' "$body" > "$dir/state-client/client.conf"
	printf 'ключ-заглушка\n' > "$dir/state-client/client.key"
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	CLIENT_STATE_DIR="$dir/state-client" timeout 10 sh "$CLIENT_ENTRY" run > "$dir/out" 2>&1
	local code=$?
	[ "$code" -ne 0 ] && ! grep -q '^wg-quick' "$dir/log" 		&& grep -q 'клиент:' "$dir/out"
	check $? "конфиг с $what отвергнут до wg-quick (код $code)"
}

reject_config 'полем PostUp' "$(valid_config | sed 's/^MTU = 1420$/MTU = 1420\nPostUp = touch \/tmp\/hook/')"
reject_config 'секретным PrivateKey' "$(valid_config | sed 's/^MTU = 1420$/PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nMTU = 1420/')"
reject_config 'чужой секцией' "$(valid_config; printf '[Extra]\nKey = value\n')"
reject_config 'чужим AllowedIPs' "$(valid_config | sed 's#^AllowedIPs = 0.0.0.0/0$#AllowedIPs = 10.0.0.0/8#')"
reject_config 'отсутствующим PersistentKeepalive' "$(valid_config | grep -v '^PersistentKeepalive')"
reject_config 'чужим Endpoint' "$(valid_config | sed 's#^Endpoint = .*#Endpoint = 172.31.99.9:51820#')"

# 10. Канонический конфиг API проходит проверку.
dir="$TMPROOT/cfg-ok"; fake_tools "$dir"
valid_config > "$dir/client.conf"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
CLIENT_ENTRYPOINT_LIB=1 CLIENT_STATE_DIR="$dir/state-run" \
sh -c '. "$1"; validate_config "$2"' sh "$CLIENT_ENTRY" "$dir/client.conf" > "$dir/out" 2>&1
check $? "канонический конфиг API проходит проверку"

# 11. Ветка init узла не запускает NAT и DNS.
dir="$TMPROOT/node-init"; mkdir -p "$dir/state-run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
NOVAVPN_NODE_STATE_DIR="$dir/state-run" timeout 10 sh "$NODE_ENTRY" init > "$dir/out" 2>&1
code=$?
[ "$code" -eq 0 ] && ! grep -qE '^(nft|unbound)' "$dir/log" && grep -q '^su-exec .* init$' "$dir/log"
check $? "init узла не трогает NAT/DNS и передаёт команду агенту (код $code)"

# 12. Ветка run узла: NAT, проверка и старт unbound, затем агент.
dir="$TMPROOT/node-run"; mkdir -p "$dir/state-run"; fake_tools "$dir"
rm -f /run/unbound.pid
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
NOVAVPN_NODE_STATE_DIR="$dir/state-run" timeout 20 sh "$NODE_ENTRY" run > "$dir/out" 2>&1
code=$?
first_nft=$(grep -n '^nft -f' "$dir/log" | head -n 1 | cut -d: -f1)
first_unbound=$(grep -n '^unbound -c' "$dir/log" | head -n 1 | cut -d: -f1)
first_agent=$(grep -n '^su-exec .* run$' "$dir/log" | head -n 1 | cut -d: -f1)
[ "$code" -eq 0 ] && [ -n "$first_nft" ] && [ -n "$first_unbound" ] && [ -n "$first_agent" ] \
	&& [ "$first_nft" -lt "$first_unbound" ] && [ "$first_unbound" -lt "$first_agent" ] \
	&& grep -q '^unbound-checkconf' "$dir/log"
check $? "run узла: NAT, unbound, затем агент; ошибки не поглощены (код $code)"

# 13. Отказ применения NAT останавливает запуск до unbound и агента.
dir="$TMPROOT/node-nat-fail"; mkdir -p "$dir/state-run"; fake_tools "$dir"
rm -f /run/unbound.pid
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_FAIL_NFT_APPLY=1 \
NOVAVPN_NODE_STATE_DIR="$dir/state-run" timeout 20 sh "$NODE_ENTRY" run > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && ! grep -qE '^(unbound|su-exec)' "$dir/log" 	&& grep -q 'NAT' "$dir/out"
check $? "отказ NAT не поглощён и останавливает запуск (код $code)"

# 14. Успешный e2e-down удаляет только свои сети и подтверждает владение томом.
dir="$TMPROOT/down-ok"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
printf 'novavpn-e2e previous-run\n' > "$dir/state-run/run/owner"
printf 'novavpn-e2e_harness\nnovavpn-e2e_uplink\n' > "$dir/state/networks"
printf 'novavpn-e2e-control\n' > "$dir/state/volumes"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
E2E_STATE_DIR="$dir/state-run" bash "$E2E" down > "$dir/out" 2>&1
code=$?
[ "$code" -eq 0 ] && grep -q 'network rm novavpn-e2e_harness' "$dir/log" \
	&& grep -q 'network rm novavpn-e2e_uplink' "$dir/log" \
	&& ! grep -q 'prune' "$dir/log"
check $? "e2e-down снял только свои сети и подтвердил владение (код $code)"

printf '%s\n' "проверок: $CASES, отказов: $FAILS"
[ "$FAILS" -eq 0 ]