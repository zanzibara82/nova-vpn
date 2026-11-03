#!/usr/bin/env bash
# Оффлайн-проверки управляющей логики стенда E2E на подставных инструментах.
# Здесь не поднимается ни один контейнер стенда и не проверяется путь пакетов:
# проверяются только отказы и границы скриптов (неизвестная и недопустимая фаза,
# занятые ресурсы, чужие подсети и ошибки чтения сетей, чужой стенд, очистка,
# повреждённый ключ, неожиданный конфиг API, порядок NAT/DNS, чтение списка
# пиеров и ожидание пиера в туннеле, порядок фаз dns и limit, порядок перехвата
# DNS-трафика, чувствительность положительного контроля и лимит устройств по коду
# ошибки). Путь пакетов доказывает живой прогон.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# Скрипт стенда тоже подставляемый: доказательство чувствительности прогоняет
# набор против копии с намеренно возвращённым дефектом.
E2E=${E2E_UNDER_TEST:-$ROOT/scripts/e2e.sh}
# Точки входа подставляемые: доказательство чувствительности запускает набор
# против намеренно испорченной копии, не трогая настоящий файл.
CLIENT_ENTRY=${CLIENT_ENTRY:-$ROOT/infrastructure/docker/e2e/client-entrypoint.sh}
NODE_ENTRY=${NODE_ENTRY:-$ROOT/infrastructure/docker/e2e/node-entrypoint.sh}
# Состав образа клиента и права контейнера тоже подставляемые: проверки
# перехвата DNS гоняются против копии Dockerfile и копии compose с убранной
# capability, не трогая настоящие файлы.
CLIENT_IMAGE=${CLIENT_IMAGE:-$ROOT/infrastructure/docker/e2e/client1.Dockerfile}
E2E_COMPOSE=${E2E_COMPOSE:-$ROOT/infrastructure/docker/docker-compose.e2e.yml}

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
	: > "$dir/state/subnets"

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
	ls)
		[ "${FAKE_FAIL_NET_LS:-0}" = 1 ] && exit 1
		cat "$state/networks"
		exit 0 ;;
	inspect)
		ipam=0
		for a in "$@"; do
			case "$a" in *IPAM.Config*) ipam=1 ;; esac
			name=$a
		done
		if grep -qx "$name" "$state/networks"; then
			if [ "$ipam" = 1 ]; then
				[ "${FAKE_FAIL_IPAM:-0}" = 1 ] && exit 1
				sed -n "s/^$name  *//p" "$state/subnets"
			else
				printf '%s' "${FAKE_NET_LABEL-novavpn-e2e}"
			fi
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
	*"wg show wg0 public-key"*)
		printf '%s\n' "${FAKE_CLIENT_PUB:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}"
		exit 0 ;;
	*"wg show wg0 peers"*)
		case "${FAKE_PEERS:-key}" in
		error) exit 1 ;;
		empty) exit 0 ;;
		key) printf '%s\n' "${FAKE_PEER_KEY:-}"; exit 0 ;;
		esac ;;
	*" down"*) : > "$state/ps" ;;
	# Порядок case важен: сниппет запуска перехвата содержит и слово tcpdump, и
	# путь файла, а чтение снимка содержит только путь. Сначала разбирается запуск
	# (его код выхода решением не используется), затем чтение снимка, и только
	# потом — чистые запросы к резолверу.
	*"wg genkey | wg pubkey"*)
		# Без двоеточия: пустое значение передаётся как пустое и проверка
		# формата на стороне оркестратора обязана сработать.
		printf '%s\n' "${FAKE_DEV_PUB-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}"
		exit 0 ;;
	*"logs --no-color node1"*)
		[ -n "${FAKE_NODE_LOG:-}" ] && printf '%s\n' "$FAKE_NODE_LOG"
		exit 0 ;;
	# Файл resolv.conf читается фазой dns построчно: подстановка даёт как
	# резолвер узла, так и чужой адрес — проверка не должна проходить по инерции.
	*"/etc/resolv.conf"*)
		printf '%s\n' "${FAKE_RESOLV_CONF-nameserver 10.99.7.1}"
		exit 0 ;;
	# Запуск перехвата: код выхода не используется решением. Busybox-`timeout`
	# (образ клиента) возвращает статус дочерней команды, а tcpdump по SIGTERM
	# выходит с нулём, поэтому по умолчанию здесь 143 — как у убитого процесса.
	*"tcpdump -i eth0"*) exit "${FAKE_CAPTURE_RC:-143}" ;;
	*"/state/leak.log"*)
		printf '%s\n' "${FAKE_LEAK_CAPTURE-0 packets captured}"
		exit 0 ;;
	*"/state/control.log"*)
		# Единственное число — живой вывод tcpdump на стенде: «1 packet captured».
		printf '%s\n' "${FAKE_CONTROL_CAPTURE-1 packet captured}"
		exit 0 ;;
	*"dig "*@10.99.7.1*)
		# A-запрос клиента через резолвер узла: rcode NOERROR и адрес стенда в
		# answer-секции. Значения — по живому выводу dig из контейнера клиента
		# (TTL 0, один A-запись), код выхода 0.
		printf '%s\n' "${FAKE_DIG_TUNNEL_OUT-;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51889
probe.e2e.test.		0	IN	A	172.31.98.3}"
		exit "${FAKE_DIG_TUNNEL_RC:-0}" ;;
	*"dig "*@172.31.99.2*)
		# Живой замер на стенде: dig печатает REFUSED и уходит с кодом 0, а на
		# таймауте — с кодом 9. Поэтому код выхода по умолчанию — 0: проверка
		# обязана принимать решение по rcode из ответа, а не по коду. Молчание
		# (нет ответа) и ответ с rcode здесь разделены, иначе проверка утечки
		# прошла бы на файрволе, а не на access-control.
		printf '%s\n' "${FAKE_DIG_OUT-;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 4242}"
		exit "${FAKE_DIG_RC:-0}" ;;
	*"ip -6 addr show"*) exit "${FAKE_IP6_ADDR_RC:-1}" ;;
	*"ip -6 route show default"*) exit "${FAKE_IP6_ROUTE_RC:-1}" ;;
	*"ping -6"*) exit "${FAKE_IP6_PING_RC:-1}" ;;
	esac
	exit 0 ;;
esac
exit 0
FAKE

	# Подставной curl отвечает кодом и телом по имени файла-ответа: так
	# управляющая логика лимита проверяется без настоящего API.
	cat > "$dir/bin/curl" <<'FAKE'
#!/bin/sh
printf 'curl %s\n' "$*" >> "$FAKE_LOG"
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "-o" ]; then out="$2"; shift 2; continue; fi
	shift
done
code=${FAKE_DEVICE_CODE:-201}
if [ -n "${FAKE_DEVICE_BODY:-}" ]; then body=$FAKE_DEVICE_BODY; else body='{"id":"e2e-device"}'; fi
case "$out" in
*device-4*)
	code=${FAKE_DEVICE4_CODE:-409}
	if [ -n "${FAKE_DEVICE4_BODY:-}" ]; then
		body=$FAKE_DEVICE4_BODY
	else
		body='{"error":{"code":"device_limit_reached","message":"достигнут лимит устройств"}}'
	fi
	;;
esac
if [ -n "$out" ]; then printf '%s\n' "$body" > "$out"; fi
printf '%s' "$code"
exit "${FAKE_CURL_EXIT:-0}"
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

	cat > "$dir/bin/ip" <<'FAKE'
#!/bin/sh
printf 'ip %s\n' "$*" >> "$FAKE_LOG"
exit 0
FAKE

	# Клиент завершает настройку через exec sleep infinity; подставной sleep
	# возвращает управление, иначе проверка запуска висела бы до timeout.
	cat > "$dir/bin/sleep" <<'FAKE'
#!/bin/sh
printf 'sleep %s\n' "$*" >> "$FAKE_LOG"
exit 0
FAKE

	# Подставной sysctl успешен и пишет в журнал: иначе вызов sysctl из
	# клиентской точки входа остался бы незаметным там, где настоящий бинарник
	# есть и молча отрабатывает.
	cat > "$dir/bin/sysctl" <<'FAKE'
#!/bin/sh
printf 'sysctl %s\n' "$*" >> "$FAKE_LOG"
exit 0
FAKE

	cat > "$dir/bin/nft" <<'FAKE'
#!/bin/sh
printf 'nft %s\n' "$*" >> "$FAKE_LOG"
case "$1" in
list)
	case "$2" in
	tables)
		[ "${FAKE_FAIL_NFT_LIST:-0}" = 1 ] && exit 1
		if [ -e "$FAKE_STATE/table" ]; then printf 'table ip novavpn\n'; fi
		exit 0 ;;
	table)
		[ -e "$FAKE_STATE/table" ] && exit 0
		exit 1 ;;
	esac
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
# Путь pid-файла задаёт проверка через UNBOUND_PID_FILE_WAIT: абсолютный /run
# на машине разработчика не используется. Конфигурацию проверяет отдельный
# подставной unbound-checkconf.
printf '%s\n' "$$" > "${UNBOUND_PID_FILE_WAIT:?}"
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

# 2. Недопустимая фаза окружения отвергается так же. Значение dns сюда больше не
# годится: с задачи 12 это настоящая фаза, поэтому берётся заведомо недопустимое.
dir="$TMPROOT/envphase"; mkdir -p "$dir/state-run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
E2E_STATE_DIR="$dir/state-run" E2E_PHASE=bogus bash "$E2E" > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && [ ! -s "$dir/log" ] && grep -q 'фаза окружения' "$dir/out"
check $? "E2E_PHASE=bogus отвергнут до вызова Docker (код $code)"

# 3. Фаза снятия через окружение не принимается: снимает только make e2e-down.
dir="$TMPROOT/envdown"; mkdir -p "$dir/state-run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
E2E_STATE_DIR="$dir/state-run" E2E_PHASE=down bash "$E2E" > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && [ ! -s "$dir/log" ] && grep -q 'фаза окружения' "$dir/out"
check $? "E2E_PHASE=down отвергнут до вызова Docker (код $code)"

# 3a. Фаза из окружения проверяется и при позиционном аргументе.
dir="$TMPROOT/envphase-arg"; mkdir -p "$dir/state-run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	E2E_STATE_DIR="$dir/state-run" E2E_PHASE=down timeout 15 bash "$E2E" all > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && [ ! -s "$dir/log" ] && grep -q 'фаза окружения' "$dir/out"
check $? "E2E_PHASE=down отвергнут и при позиционном all (код $code)"

# 4. Занятое имя проекта отвергается до создания ресурсов.
dir="$TMPROOT/busy"; mkdir -p "$dir/state-run"; fake_tools "$dir"
printf 'novavpn-e2e-postgres-1\n' > "$dir/state/ps"
run_e2e "$dir" "$dir/state-run" all
code=$?
[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" && grep -q 'занят' "$dir/out"
check $? "повторный запуск при занятом имени отвергнут без создания ресурсов (код $code)"

# 5. Маркер прошлого запуска в control-томе отвергает повтор.
dir="$TMPROOT/marker"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
printf 'novavpn-e2e previous-run\n' > "$dir/state-run/run/owner"
run_e2e "$dir" "$dir/state-run" all
code=$?
[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" && grep -q 'прошл' "$dir/out"
check $? "маркер прошлого запуска отвергнут без изменений (код $code)"

# 6. e2e-down не удаляет чужой контейнер без метки владельца.
dir="$TMPROOT/foreign"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
printf 'novavpn-e2e-runner\n' > "$dir/state/ps"
printf 'novavpn-e2e_harness\n' > "$dir/state/networks"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_LABEL="" \
E2E_STATE_DIR="$dir/state-run" bash "$E2E" down > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && ! grep -Eq 'docker rm|network rm|volume rm|compose .* down' "$dir/log" \
	&& grep -q 'чуж' "$dir/out"
check $? "чужой/прежний стенд без метки не удалён (код $code)"

# 7. Ошибка очистки Compose даёт ненулевой итог.
dir="$TMPROOT/cleanup"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
printf 'novavpn-e2e previous-run\n' > "$dir/state-run/run/owner"
printf 'novavpn-e2e_harness\n' > "$dir/state/networks"
printf 'novavpn-e2e-control\n' > "$dir/state/volumes"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
FAKE_FAIL_COMPOSE=1 E2E_STATE_DIR="$dir/state-run" bash "$E2E" down > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && grep -q 'очистк' "$dir/out"
check $? "ошибка очистки Compose даёт ненулевой код (код $code)"

# 8. Первоначальный отказ не затирается ошибкой журналирования.
dir="$TMPROOT/exitcode"; mkdir -p "$dir/state-run/run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
FAKE_FAIL_COMPOSE=1 E2E_STATE_DIR="$dir/state-run" \
bash -c 'source "$0" || exit 9; trap on_exit EXIT; exit 7' "$E2E" > "$dir/out" 2>&1
code=$?
[ "$code" -eq 7 ]
check $? "исходный отказ 7 не затёрт отказом журналирования (код $code)"

# 9. Повреждённый клиентский ключ не перевыпускается и не меняется.
dir="$TMPROOT/genkey"; mkdir -p "$dir/state-run" "$dir/state-client"; fake_tools "$dir"
printf 'не-ключ\n' > "$dir/state-client/client.key"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_WG_PUBKEY_FAIL=1 \
CLIENT_STATE_DIR="$dir/state-client" timeout 10 sh "$CLIENT_ENTRY" genkey > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && [ "$(cat "$dir/state-client/client.key")" = "не-ключ" ] \
	&& ! grep -q '^wg genkey' "$dir/log"
check $? "повреждённый ключ клиента не перевыпущен (код $code)"

# 10. Чужая сеть с нашей подсетью отвергается до создания ресурсов.
subnet_overlap_case() { # описание, имя чужой сети, её подсеть
	local what=$1 net=$2 sub=$3
	local dir code
	dir=$(mktemp -d "$TMPROOT/subnet.XXXXXX")
	fake_tools "$dir"
	mkdir -p "$dir/state-run"
	printf '%s\n' "$net" >> "$dir/state/networks"
	printf '%s %s\n' "$net" "$sub" >> "$dir/state/subnets"
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
		E2E_STATE_DIR="$dir/state-run" bash "$E2E" all > "$dir/out" 2>&1
	code=$?
	[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" && grep -q 'пересечение' "$dir/out"
	check $? "чужая подсеть $sub ($what) отвергнута без создания ресурсов (код $code)"
}

subnet_overlap_case 'та же сеть' 'foreign-same' '172.31.99.0/24'
subnet_overlap_case 'суперсеть' 'foreign-wide' '172.31.0.0/16'

# 11. Ошибка чтения подсетей Docker тоже отказ, а не пропуск проверки.
dir="$TMPROOT/subnet-fail"; fake_tools "$dir"
mkdir -p "$dir/state-run"
printf 'foreign-fail\n' >> "$dir/state/networks"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_FAIL_IPAM=1 \
E2E_STATE_DIR="$dir/state-run" bash "$E2E" all > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" && grep -q 'не удалось прочитать' "$dir/out"
check $? "ошибка чтения подсетей Docker отвергнута без создания ресурсов (код $code)"

# 11a. Своя оставшаяся сеть — это занятое имя, а совет ведёт к make e2e-down.
dir="$TMPROOT/subnet-own"; fake_tools "$dir"
mkdir -p "$dir/state-run"
printf 'novavpn-e2e_harness\n' >> "$dir/state/networks"
printf 'novavpn-e2e_harness 172.31.99.0/24\n' >> "$dir/state/subnets"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	E2E_STATE_DIR="$dir/state-run" bash "$E2E" all > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" \
	&& grep -q 'уже существует' "$dir/out" && ! grep -q 'пересечение' "$dir/out"
check $? "своя сеть даёт совет про занятое имя, а не про пересечение (код $code)"

# 11b. Ошибка чтения списка сетей Docker — отказ, а не пропуск проверки.
dir="$TMPROOT/subnet-ls"; fake_tools "$dir"
mkdir -p "$dir/state-run"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_FAIL_NET_LS=1 \
	E2E_STATE_DIR="$dir/state-run" bash "$E2E" all > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && assert_no_mutation "$dir/log" && grep -q 'не удалось прочитать' "$dir/out"
check $? "ошибка чтения списка сетей отвергнута без создания ресурсов (код $code)"

# 11c. Ошибка awk внутри проверки подсетей — отказ, а не молчаливый пропуск.
dir="$TMPROOT/subnet-awk"; fake_tools "$dir"
mkdir -p "$dir/state-run"
printf 'foreign-awk\n' >> "$dir/state/networks"
printf 'foreign-awk 10.0.0.0/8\n' >> "$dir/state/subnets"
awk() { return 1; }
export -f awk
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	bash -c 'source "$0"; check_subnets' "$E2E" > "$dir/out" 2>&1
code=$?
unset -f awk
[ "$code" -ne 0 ] && grep -q 'не удалось прочитать' "$dir/out" && assert_no_mutation "$dir/log"
check $? "ошибка awk в проверке подсетей отвергнута (код $code)"

# 11d. Оркестратор получает закреплённый адрес, а не первый свободный:
# динамическая выдача Docker отдаёт .99.2 — адрес узла, и init узла падает
# с «Address already in use».
dir="$TMPROOT/attach-ip"; fake_tools "$dir"
E2E_ORCHESTRATOR=1 E2E_ORCHESTRATOR_ID=runner-id \
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	bash -c 'source "$0"; attach_self' "$E2E" > "$dir/out" 2>&1
code=$?
[ "$code" -eq 0 ] \
	&& grep -qx 'docker network connect --ip 172.31.99.4 novavpn-e2e_harness runner-id' "$dir/log"
check $? "оркестратор подключён к harness с закреплённым адресом 172.31.99.4 (код $code)"

# 12. Клиентский конфиг с неожиданным полем или секцией отвергается до
# настройки интерфейса.
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

# config_body печатает одно из шести запрещённых тел конфигурации.
config_body() { # postup|privatekey|extrasection|allowedips|nokeepalive|endpoint
	case "$1" in
	postup) valid_config | sed 's/^MTU = 1420$/MTU = 1420\nPostUp = touch \/tmp\/hook/' ;;
	privatekey) valid_config | sed 's/^MTU = 1420$/PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nMTU = 1420/' ;;
	extrasection) valid_config; printf '[Extra]\nKey = value\n' ;;
	allowedips) valid_config | sed 's#^AllowedIPs = 0.0.0.0/0$#AllowedIPs = 10.0.0.0/8#' ;;
	nokeepalive) valid_config | grep -v '^PersistentKeepalive' ;;
	endpoint) valid_config | sed 's#^Endpoint = .*#Endpoint = 172.31.99.9:51820#' ;;
	esac
}

# reject_config: ключ правильного формата, чтобы отказ давал именно валидатор,
# и точный ожидаемый фрагмент сообщения валидатора.
reject_config() { # описание, тело-файл, ожидаемый фрагмент
	local what=$1 body=$2 expected=$3
	local dir code
	dir=$(mktemp -d "$TMPROOT/cfg.XXXXXX")
	fake_tools "$dir"
	mkdir -p "$dir/state-run" "$dir/state-client"
	printf '%s\n' "$body" > "$dir/state-client/client.conf"
	printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > "$dir/state-client/client.key"
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	CLIENT_STATE_DIR="$dir/state-client" timeout 10 sh "$CLIENT_ENTRY" run > "$dir/out" 2>&1
	code=$?
	[ "$code" -ne 0 ] && ! grep -qE '^(wg-quick|sysctl|ip |wg )' "$dir/log" \
		&& grep -q 'клиент:' "$dir/out" && grep -qF "$expected" "$dir/out"
	check $? "конфиг с $what отвергнут до настройки интерфейса по «$expected» (код $code)"
}

reject_config 'полем PostUp' "$(config_body postup)" \
	'недопустимый ключ [Interface]: PostUp'
reject_config 'секретным PrivateKey' "$(config_body privatekey)" \
	'недопустимый ключ [Interface]: PrivateKey'
reject_config 'чужой секцией' "$(config_body extrasection)" \
	'недопустимая секция: [Extra]'
reject_config 'чужим AllowedIPs' "$(config_body allowedips)" \
	'неверный AllowedIPs: 10.0.0.0/8'
reject_config 'отсутствующим PersistentKeepalive' "$(config_body nokeepalive)" \
	'нет обязательного поля PersistentKeepalive'
reject_config 'чужим Endpoint' "$(config_body endpoint)" \
	'неверный Endpoint: 172.31.99.9:51820'

# 13. Тот же валидатор отдельно от точки входа: ненулевой код и точный фрагмент.
validate_reject() { # описание, тело-файл, ожидаемый фрагмент
	local what=$1 body=$2 expected=$3
	local dir
	dir=$(mktemp -d "$TMPROOT/val.XXXXXX")
	printf '%s\n' "$body" > "$dir/client.conf"
	CLIENT_ENTRYPOINT_LIB=1 sh -c '. "$1"; validate_config "$2"' sh "$CLIENT_ENTRY" \
		"$dir/client.conf" > "$dir/out" 2>&1
	local code=$?
	[ "$code" -ne 0 ] && grep -qF "$expected" "$dir/out"
	check $? "валидатор напрямую отвергает $what (код $code)"
}

validate_reject 'поле PostUp' "$(config_body postup)" \
	'недопустимый ключ [Interface]: PostUp'
validate_reject 'поле PrivateKey' "$(config_body privatekey)" \
	'недопустимый ключ [Interface]: PrivateKey'
validate_reject 'чужую секцию' "$(config_body extrasection)" \
	'недопустимая секция: [Extra]'
validate_reject 'чужой AllowedIPs' "$(config_body allowedips)" \
	'неверный AllowedIPs: 10.0.0.0/8'
validate_reject 'отсутствующий PersistentKeepalive' "$(config_body nokeepalive)" \
	'нет обязательного поля PersistentKeepalive'
validate_reject 'чужой Endpoint' "$(config_body endpoint)" \
	'неверный Endpoint: 172.31.99.9:51820'

# 14. Канонический конфиг API проходит проверку.
dir="$TMPROOT/cfg-ok"; fake_tools "$dir"
valid_config > "$dir/client.conf"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
CLIENT_ENTRYPOINT_LIB=1 CLIENT_STATE_DIR="$dir/state-run" \
sh -c '. "$1"; validate_config "$2"' sh "$CLIENT_ENTRY" "$dir/client.conf" > "$dir/out" 2>&1
check $? "канонический конфиг API проходит проверку"

# 14a. Запуск клиента поднимает wg0 явными командами со значениями из
# проверенного конфига. wg-quick непригоден: он вызывает sysctl, а /proc/sys в
# контейнере только для чтения; src_valid_mark выставляет compose при старте.
dir="$TMPROOT/client-run"; fake_tools "$dir"
mkdir -p "$dir/state-client"
valid_config > "$dir/state-client/client.conf"
printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > "$dir/state-client/client.key"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	CLIENT_STATE_DIR="$dir/state-client" CLIENT_RESOLV_CONF="$dir/resolv.conf" \
	timeout 10 sh "$CLIENT_ENTRY" run > "$dir/out" 2>&1
code=$?
cat > "$dir/expected" <<EOF
ip link add wg0 type wireguard
wg setconf wg0 $dir/state-client/wg0.conf
ip -4 address add 10.99.7.2/32 dev wg0
ip link set mtu 1420 up dev wg0
wg set wg0 fwmark 51820
ip -4 route add 0.0.0.0/0 dev wg0 table 51820
ip -4 rule add not fwmark 51820 table 51820
ip -4 rule add table main suppress_prefixlength 0
sleep infinity
EOF
# NTFS не хранит POSIX-режимы: на Windows-хосте chmod 600 всё равно даёт 644,
# поэтому фактический режим проверяется только там, где файловая система его
# сохраняет. Права настоящего клиентского тома доказывает прогон в Alpine.
mode_ok=1
case "$(uname -s)" in
MINGW*|MSYS*|CYGWIN*) ;;
*) [ "$(stat -c %a "$dir/state-client/wg0.conf")" = 600 ] || mode_ok=0 ;;
esac
[ "$code" -eq 0 ] && diff -u "$dir/expected" "$dir/log" \
	&& ! grep -q '^Address' "$dir/state-client/wg0.conf" \
	&& ! grep -q '^MTU' "$dir/state-client/wg0.conf" \
	&& grep -qx 'PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
		"$dir/state-client/wg0.conf" \
	&& [ "$mode_ok" = 1 ] \
	&& grep -qx '\[Peer\]' "$dir/state-client/wg0.conf" \
	&& grep -qx 'nameserver 10.99.7.1' "$dir/resolv.conf"
check $? "клиент поднимает wg0 без wg-quick и sysctl, ключ в файле 600 (код $code)"

# 15. Ветка init узла не запускает NAT и DNS.
dir="$TMPROOT/node-init"; mkdir -p "$dir/state-run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
NOVAVPN_NODE_STATE_DIR="$dir/state-run" timeout 10 sh "$NODE_ENTRY" init > "$dir/out" 2>&1
code=$?
[ "$code" -eq 0 ] && ! grep -qE '^(nft|unbound)' "$dir/log" && grep -q '^su-exec .* init$' "$dir/log"
check $? "init узла не трогает NAT/DNS и передаёт команду агенту (код $code)"

# 16. Ветка run узла: NAT, проверка и старт unbound, затем агент.
dir="$TMPROOT/node-run"; mkdir -p "$dir/state-run" "$dir/run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
UNBOUND_PID_FILE_WAIT="$dir/run/unbound.pid" \
NOVAVPN_NODE_STATE_DIR="$dir/state-run" timeout 20 sh "$NODE_ENTRY" run > "$dir/out" 2>&1
code=$?
first_nft=$(grep -n '^nft -f' "$dir/log" | head -n 1 | cut -d: -f1)
first_unbound=$(grep -n '^unbound -c' "$dir/log" | head -n 1 | cut -d: -f1)
first_agent=$(grep -n '^su-exec .* run$' "$dir/log" | head -n 1 | cut -d: -f1)
[ "$code" -eq 0 ] && [ -n "$first_nft" ] && [ -n "$first_unbound" ] && [ -n "$first_agent" ] \
	&& [ "$first_nft" -lt "$first_unbound" ] && [ "$first_unbound" -lt "$first_agent" ] \
	&& grep -q '^unbound-checkconf' "$dir/log"
check $? "run узла: NAT, unbound, затем агент; ошибки не поглощены (код $code)"

# 17. Отказ применения NAT останавливает запуск до unbound и агента.
dir="$TMPROOT/node-nat-fail"; mkdir -p "$dir/state-run" "$dir/run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_FAIL_NFT_APPLY=1 \
UNBOUND_PID_FILE_WAIT="$dir/run/unbound.pid" \
NOVAVPN_NODE_STATE_DIR="$dir/state-run" timeout 20 sh "$NODE_ENTRY" run > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && ! grep -qE '^(unbound|su-exec)' "$dir/log" && grep -q 'NAT' "$dir/out"
check $? "отказ NAT не поглощён и останавливает запуск (код $code)"

# 18. Ошибка чтения списка таблиц nftables останавливает запуск до unbound и агента.
dir="$TMPROOT/node-nft-list"; mkdir -p "$dir/state-run" "$dir/run"; fake_tools "$dir"
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" FAKE_FAIL_NFT_LIST=1 \
UNBOUND_PID_FILE_WAIT="$dir/run/unbound.pid" \
NOVAVPN_NODE_STATE_DIR="$dir/state-run" timeout 20 sh "$NODE_ENTRY" run > "$dir/out" 2>&1
code=$?
[ "$code" -ne 0 ] && ! grep -qE '^(nft -f|unbound|su-exec)' "$dir/log" \
	&& grep -q 'nftables' "$dir/out"
check $? "ошибка чтения таблиц nftables останавливает запуск (код $code)"

# 19. Ошибка чтения списка пиеров узла отличается от отсутствия пиера.
dir="$TMPROOT/peers"; fake_tools "$dir"
peer_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
peer_code() { # режим: error|empty|key
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	FAKE_PEERS="$1" FAKE_PEER_KEY="$peer_key" \
	bash -c 'source "$0"; node_peer_present "$1"' "$E2E" "$peer_key"
}
peer_code error
code=$?
[ "$code" -eq 2 ]
check $? "ошибка чтения списка пиеров узла даёт код 2 (код $code)"
peer_code empty
code=$?
[ "$code" -eq 1 ]
check $? "пустой прочитанный список пиеров узла даёт код 1 (код $code)"
peer_code key
code=$?
[ "$code" -eq 0 ]
check $? "найденный пиер узла даёт код 0 (код $code)"

# 19a. wait_peer при ошибке чтения прекращает ожидание сразу и читает один раз.
dir="$TMPROOT/wait-peer"; fake_tools "$dir"
peer_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
wait_peer_code() { # режим: error|key
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	FAKE_PEERS="$1" FAKE_PEER_KEY="$peer_key" \
	bash -c 'source "$0"; wait_peer "$1"' "$E2E" "$peer_key"
}
start=$(date +%s)
wait_peer_code error
code=$?
elapsed=$(( $(date +%s) - start ))
reads=$(grep -c 'exec -T node1 wg show wg0 peers' "$dir/log")
[ "$code" -eq 2 ] && [ "$elapsed" -lt 20 ] && [ "$reads" -eq 1 ]
check $? "wait_peer при ошибке чтения: код 2, одно чтение, секунд $elapsed (код $code)"
wait_peer_code key
code=$?
[ "$code" -eq 0 ]
check $? "wait_peer находит пиер с первого чтения (код $code)"

# 19b. tunnel вызывает wait_peer: код 2 даёт отдельный отказ сразу, а не
# «за 90 с не выполнено». Проверка ловит возврат к wait_for 90 с node_peer_present.
dir="$TMPROOT/tunnel-peer"; fake_tools "$dir"
peer_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
start=$(date +%s)
PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	FAKE_PEERS=error FAKE_PEER_KEY="$peer_key" FAKE_CLIENT_PUB="$peer_key" \
	bash -c 'source "$0"; tunnel' "$E2E" > "$dir/out" 2>&1
code=$?
elapsed=$(( $(date +%s) - start ))
reads=$(grep -c 'exec -T node1 wg show wg0 peers' "$dir/log")
[ "$code" -ne 0 ] && [ "$elapsed" -lt 20 ] && [ "$reads" -eq 1 ] \
	&& grep -q 'не удалось прочитать список пиеров узла' "$dir/out"
check $? "tunnel при ошибке чтения пиеров отказывает сразу и отдельно (код $code, секунд $elapsed)"

# 20. Успешный e2e-down удаляет только свои сети и подтверждает владение томом.
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

# --- Задача 12: порядок фаз, DNS-утечка, IPv6 и лимит устройств ---

# phase_plan вызывает run_main с подменёнными фазами: каждая фаза записывает своё
# имя в план-файл. Сверка плана — это проверка фактического порядка вызова, а не
# текста скрипта, поэтому потерянная ветка (negative_control или cleanup) ломает
# сравнение, даже если скрипт по-прежнему завершается успешно.
phase_plan() { # каталог, файл плана, позиционная фаза, фаза окружения
	local dir=$1 plan=$2 arg=$3 envphase=$4
	mkdir -p "$dir/state-run"
	cat > "$dir/plan-stub" <<'STUB'
setup() { printf 'setup\n' >> "$PLAN_FILE"; }
negative_control() { printf 'negative_control\n' >> "$PLAN_FILE"; }
tunnel() { printf 'tunnel\n' >> "$PLAN_FILE"; }
dns() { printf 'dns\n' >> "$PLAN_FILE"; }
limit() { printf 'limit\n' >> "$PLAN_FILE"; }
cleanup() { printf 'cleanup\n' >> "$PLAN_FILE"; }
e2e_down() { printf 'e2e_down\n' >> "$PLAN_FILE"; }
STUB
	: > "$plan"
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	PLAN_STUB="$dir/plan-stub" PLAN_FILE="$plan" E2E_STATE_DIR="$dir/state-run" \
	E2E_PHASE="$envphase" timeout 20 bash -c '
		source "$0" || exit 9
		. "$PLAN_STUB"
		run_main "${1:-}"
	' "$E2E" "$arg" > "$dir/out" 2>&1
}

# 21. Фаза all: обе новые фазы стоят между tunnel и cleanup, контроль обхода и
# очистка не потеряны, итоговая строка — последняя.
dir="$TMPROOT/plan-all"; fake_tools "$dir"
phase_plan "$dir" "$dir/plan" all ''
code=$?
cat > "$dir/expected" <<'EOF'
setup
negative_control
tunnel
dns
limit
cleanup
EOF
[ "$code" -eq 0 ] && diff -q "$dir/expected" "$dir/plan" >/dev/null \
	&& [ "$(tail -n 1 "$dir/out")" = "ok   фаза all пройдена" ]
check $? "фаза all: setup, negative_control, tunnel, dns, limit, cleanup (код $code)"

# 22. Одиночная фаза dns идёт как setup, negative_control, tunnel, dns, cleanup.
dir="$TMPROOT/plan-dns"; fake_tools "$dir"
phase_plan "$dir" "$dir/plan" dns ''
code=$?
cat > "$dir/expected" <<'EOF'
setup
negative_control
tunnel
dns
cleanup
EOF
[ "$code" -eq 0 ] && diff -q "$dir/expected" "$dir/plan" >/dev/null \
	&& ! grep -qx 'limit' "$dir/plan"
check $? "одиночная фаза dns: limit не вызывается, контроль и очистка на месте (код $code)"

# 23. Одиночная фаза limit: dns не вызывается.
dir="$TMPROOT/plan-limit"; fake_tools "$dir"
phase_plan "$dir" "$dir/plan" limit ''
code=$?
cat > "$dir/expected" <<'EOF'
setup
negative_control
tunnel
limit
cleanup
EOF
[ "$code" -eq 0 ] && diff -q "$dir/expected" "$dir/plan" >/dev/null
check $? "одиночная фаза limit: dns не вызывается, очистка на месте (код $code)"

# 24. Фаза tunnel осталась в прежнем составе: dns и limit к ней не добавлены.
dir="$TMPROOT/plan-tunnel"; fake_tools "$dir"
phase_plan "$dir" "$dir/plan" tunnel ''
code=$?
cat > "$dir/expected" <<'EOF'
setup
negative_control
tunnel
cleanup
EOF
[ "$code" -eq 0 ] && diff -q "$dir/expected" "$dir/plan" >/dev/null
check $? "фаза tunnel: dns и limit не вызываются (код $code)"

# 25. Единожды пройденная фаза dns не оставляет за собой стенда: cleanup в плане
# есть всегда, а unknown-фаза не запускает ни одной фазы.
dir="$TMPROOT/plan-bad"; fake_tools "$dir"
phase_plan "$dir" "$dir/plan" bogus ''
code=$?
[ "$code" -ne 0 ] && [ ! -s "$dir/plan" ] && [ ! -s "$dir/log" ] \
	&& grep -q 'неизвестная фаза' "$dir/out"
check $? "неизвестная фаза не вызывает ни одной фазы и не трогает Docker (код $code)"

# 26. dns и limit принимаются и как фаза из окружения: именно так их передаёт
# одноразовый контейнер-оркестратор.
dir="$TMPROOT/plan-env-dns"; fake_tools "$dir"
phase_plan "$dir" "$dir/plan" '' dns
code=$?
cat > "$dir/expected" <<'EOF'
setup
negative_control
tunnel
dns
cleanup
EOF
[ "$code" -eq 0 ] && diff -q "$dir/expected" "$dir/plan" >/dev/null \
	&& ! grep -q 'фаза окружения' "$dir/out"
check $? "E2E_PHASE=dns принят и выполнен (код $code)"

dir="$TMPROOT/plan-env-limit"; fake_tools "$dir"
phase_plan "$dir" "$dir/plan" '' limit
code=$?
cat > "$dir/expected" <<'EOF'
setup
negative_control
tunnel
limit
cleanup
EOF
[ "$code" -eq 0 ] && diff -q "$dir/expected" "$dir/plan" >/dev/null \
	&& ! grep -q 'фаза окружения' "$dir/out"
check $? "E2E_PHASE=limit принят и выполнен (код $code)"

# 27. Образ клиента: без bind-tools нет dig, без tcpdump нет перехвата, и
# проверка утечки молча проходила бы как пустая.
grep -E 'apk add' "$CLIENT_IMAGE" | grep -q 'bind-tools' \
	&& grep -E 'apk add' "$CLIENT_IMAGE" | grep -q 'tcpdump'
check $? "в образе клиента установлены bind-tools и tcpdump"

# 28. Контейнер клиента: NET_RAW для сокета перехвата и по-прежнему без privileged.
client_block=$(awk '/^  client1:/{f=1; next} /^  [a-z]/{f=0} f' "$E2E_COMPOSE")
printf '%s\n' "$client_block" | grep -q 'NET_RAW' \
	&& ! printf '%s\n' "$client_block" | grep -Eq '^[[:space:]]*privileged:' \
	&& printf '%s\n' "$client_block" | grep -q '172.31.99.3'
check $? "у client1 есть NET_RAW, нет ключа privileged и адрес 172.31.99.3 закреплён"

# 29. После запуска контейнера клиента временных клиентов не поднимается:
# статический адрес 172.31.99.3 конфликтует с уже работающим клиентом.
client_start=$(grep -n 'up -d --no-deps client1' "$E2E" | head -n 1 | cut -d: -f1)
[ -n "$client_start" ] \
	&& [ "$(awk -v n="$client_start" 'NR>n && /client_run/' "$E2E" | wc -l)" -eq 0 ]
check $? "после запуска клиента нет ни одного client_run (строка $client_start)"

# dns_run — вызов фазы dns на подставном докере; состояние контейнера задаётся
# переменными FAKE_*, ответ резолвера и код перехвата читаются из журнала.
dns_run() { # каталог
	local dir=$1
	mkdir -p "$dir/state-run"
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	E2E_STATE_DIR="$dir/state-run" timeout 60 bash -c 'source "$0"; dns' "$E2E" \
		> "$dir/out" 2>&1
}

# 30. Фаза dns проходит целиком и печатает все шесть доказательств.
dir="$TMPROOT/dns-ok"; fake_tools "$dir"
dns_run "$dir"
code=$?
[ "$code" -eq 0 ] \
	&& grep -q '^ok   resolv.conf клиента' "$dir/out" \
	&& grep -q '^ok   на eth0 клиента нет ни одного DNS-пакета' "$dir/out" \
	&& grep -q '^ok   тот же резолвер отвергает запрос не из туннельной сети' "$dir/out" \
	&& grep -q '^ok   перехват чувствителен' "$dir/out" \
	&& grep -q '^ok   журнала DNS-запросов в выводе контейнера узла нет' "$dir/out" \
	&& grep -q '^ok   IPv6 на клиенте отключён' "$dir/out"
check $? "фаза dns проходит на подставном стенде и печатает шесть доказательств (код $code)"

# 31. Перехват начинается ДО резолва и останавлиётся ПОСЛЕ: иначе окно захвата
# пустое по построению и проверка утечки проходит всегда.
leak_line=$(grep -m1 '/state/leak.log' "$dir/log")
order=$(printf '%s\n' "$leak_line" | awk '{
	a = index($0, "tcpdump -i eth0"); b = index($0, "dig "); c = index($0, "wait")
	if (a == 0 || b == 0 || c == 0) { print "нет"; exit }
	if (a < b && b < c) print "порядок"; else print "нет"
}')
[ "$order" = "порядок" ] \
	&& printf '%s\n' "$leak_line" | grep -q -- '-c 1 udp port 53'
check $? "захват tcpdump стартует до резолва и дожидается после (код $code)"

# 32. Положительный контроль чувствительности читает статистика снимка: «пакет
# пойман» без разобранного числа ничего не доказывает.
control_line=$(grep -m1 'timeout 10 tcpdump -i eth0 -n -q -c 1 udp port 53 > /state/control.log' "$dir/log")
[ -n "$control_line" ] && grep -qF "packets? captured' /state/control.log" "$dir/log" \
	&& printf '%s\n' "$control_line" | grep -q 'dig .*@172.31.99.2 probe.e2e.test'
check $? "положительный контроль разбирает снимок и шлёт запрос мимо туннеля"

# 33. Отказ фазы dns, когда резолвер не ответил: проверка не проходит по инерции.
# Молчание (таймаут dig) отделено от ответа с отвергающим rcode: код выхода dig
# сам по себе ничего не доказывает, решение принимается по разобранному ответу.
dir="$TMPROOT/dns-noanswer"; fake_tools "$dir"
FAKE_DIG_TUNNEL_RC=9 FAKE_DIG_TUNNEL_OUT=';; connection timed out; no servers could be reached' \
	dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out"
check $? "без ответа резолвера фаза dns отвергнута (код $code)"

# 34. Отказ фазы dns, когда перехват поймал пакет: утечка. Решение берётся по
# числу пойманных пакетов из снимка, а не по коду выхода захвата.
dir="$TMPROOT/dns-leak"; fake_tools "$dir"
FAKE_LEAK_CAPTURE='1 packet captured' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& grep -q '/state/leak.log' "$dir/out" && ! grep -q 'нет ни одного DNS-пакета' "$dir/out"
check $? "пойманный на eth0 DNS-пакет даёт отказ с путём файла перехвата (код $code)"

# 35. Отказ фазы dns, когда положительный контроль ничего не поймал: перехват
# не работает, и «ноль пакетов» из проверки утечки не отличим от пустого окна.
dir="$TMPROOT/dns-control"; fake_tools "$dir"
FAKE_CONTROL_CAPTURE='0 packets captured' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" && ! grep -q 'перехват чувствителен' "$dir/out"
check $? "пустой положительный контроль отвергнут фазой dns (код $code)"

# 36. Отказ фазы dns, когда в снимке нет строки статистики: это не «ноль
# пакетов», а нечитаемый или досрочно умерший перехват.
dir="$TMPROOT/dns-empty"; fake_tools "$dir"
FAKE_CONTROL_CAPTURE='' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" && ! grep -q 'перехват чувствителен' "$dir/out"
check $? "снимок без статистики отвергнут (код $code)"

# 37. Отказ фазы dns, когда резолвер ответил запросу из сети без туннеля.
# Ответом считается rcode NOERROR в пакете dig, а не код выхода: правило
# access-control проверяется по содержимому ответа.
dir="$TMPROOT/dns-foreign"; fake_tools "$dir"
FAKE_DIG_RC=0 FAKE_DIG_OUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7
;; ANSWER SECTION:
probe.e2e.test.		60	IN	A	172.31.98.3' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& ! grep -q 'отвергает запрос не из туннельной сети' "$dir/out"
check $? "ответ резолвера из чужой сети даёт отказ (код $code)"

# 38. Отказ фазы dns, когда журнал узла содержит строки запросов.
dir="$TMPROOT/dns-node-log"; fake_tools "$dir"
FAKE_NODE_LOG='info: query: (172.31.99.3@43211) probe.e2e.test A IN' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& ! grep -q 'журнала DNS-запросов' "$dir/out"
check $? "строка запроса unbound в журнале узла даёт отказ (код $code)"

# 39-41. Отказ фазы dns на каждом из трёх IPv6-признаков: адрес, маршрут, путь.
ipv6_fail_case() { # описание, имя переменной состояния без префикса FAKE_
	local dir="$TMPROOT/dns-$2" code
	fake_tools "$dir"
	export "FAKE_$2=0"
	dns_run "$dir"
	code=$?
	unset "FAKE_$2"
	[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" && ! grep -q 'IPv6 на клиенте отключён' "$dir/out"
	check $? "$1 даёт отказ фазы dns (код $code)"
}

ipv6_fail_case 'глобальный IPv6-адрес у клиента' 'IP6_ADDR_RC'
ipv6_fail_case 'IPv6 default route у клиента' 'IP6_ROUTE_RC'
ipv6_fail_case 'работающий IPv6-путь наружу' 'IP6_PING_RC'

# limit_run — вызов фазы limit на подставном докере и curl. Сессия пользователя
# готовится заранее, как это делает setup; приватный ключ в оффлайн-прогоне не
# появляется ни в одном аргументе.
limit_run() { # каталог
	local dir=$1
	mkdir -p "$dir/state-run/run"
	printf '{"access_token":"e2e-offline-token"}\n' > "$dir/state-run/run/user-session.json"
	PATH="$dir/bin:$PATH" FAKE_LOG="$dir/log" FAKE_STATE="$dir/state" \
	E2E_STATE_DIR="$dir/state-run" timeout 60 bash -c 'source "$0"; limit' "$E2E" \
		> "$dir/out" 2>&1
}

# 42. Лимит проходит: устройства 2 и 3 создаются с 201, четвёртое получает 409 с
# кодом device_limit_reached; ключи читаются внутри клиента, а не на хосте.
dir="$TMPROOT/limit-ok"; fake_tools "$dir"
limit_run "$dir"
code=$?
[ "$code" -eq 0 ] \
	&& grep -q '^ok   лимит 3: четвёртое устройство отклонено с device_limit_reached' "$dir/out" \
	&& grep -q 'exec -T client1 sh -c wg genkey | wg pubkey' "$dir/log" \
	&& ! grep -q '^wg genkey' "$dir/log" \
	&& grep -q 'Idempotency-Key: e2e-device-2' "$dir/state-run/run/device-2.hdr" \
	&& grep -q 'Idempotency-Key: e2e-device-3' "$dir/state-run/run/device-3.hdr" \
	&& grep -q 'Idempotency-Key: e2e-device-4' "$dir/state-run/run/device-4.hdr"
check $? "лимит проходит: 201, 201, 409 с device_limit_reached (код $code)"

# 43. Отказ, когда четвёртое устройство принят (201): лимит не проверяется.
dir="$TMPROOT/limit-accepted"; fake_tools "$dir"
FAKE_DEVICE4_CODE=201 FAKE_DEVICE4_BODY='{"id":"e2e-extra-4"}' limit_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" && ! grep -q 'device_limit_reached' "$dir/out"
check $? "принятое четвёртое устройство даёт отказ (код $code)"

# 44. Отказ, когда 409 пришёл с другим кодом ошибки: проверка смотрит именно на
# device_limit_reached, а не на любой конфликт.
dir="$TMPROOT/limit-othercode"; fake_tools "$dir"
FAKE_DEVICE4_CODE=409 FAKE_DEVICE4_BODY='{"error":{"code":"conflict_key","message":"другой конфликт"}}' \
	limit_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" && ! grep -q 'отклонено с device_limit_reached' "$dir/out"
check $? "409 с чужим кодом ошибки отвергнут (код $code)"

# 45. Отказ, когда второе устройство не создано: фаза не считает лимит
# проверенным на неполном наборе.
dir="$TMPROOT/limit-second-fail"; fake_tools "$dir"
FAKE_DEVICE_CODE=500 FAKE_DEVICE_BODY='{"error":{"code":"internal","message":"сбой"}}' \
	limit_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" && ! grep -q 'device_limit_reached' "$dir/out"
check $? "сбой создания устройства 2 даёт отказ (код $code)"

# 46. Отказ, когда клиент не выдал публичный ключ: фаза не отправляет пустой ключ.
dir="$TMPROOT/limit-nokey"; fake_tools "$dir"
FAKE_DEV_PUB='' limit_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out"
check $? "пустой публичный ключ клиента отвергнут (код $code)"

# 47. Клиент вернул неключ: фаза отказывает и не печатает полученное значение —
# так же ведёт себя и настоящая приватная часть, которой в выводе быть не должно.
dir="$TMPROOT/limit-badkey"; fake_tools "$dir"
FAKE_DEV_PUB='не-ключ' limit_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" && ! grep -q 'не-ключ' "$dir/out"
check $? "неключ клиента отвергнут и не попал в вывод (код $code)"

# 48. Отказ фазы dns, когда перехват поймал пакет, не печатает содержимого
# снимка: в тексте отказа есть путь, но нет строк перехвата.
dir="$TMPROOT/dns-content"; fake_tools "$dir"
FAKE_LEAK_CAPTURE='1 packet captured' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& ! grep -qiE 'privatekey|private key' "$dir/out" && ! grep -q 'FROM' "$dir/out"
check $? "отказ фазы dns не печатает приватный ключ и содержимое снимка (код $code)"

# 49. Молчание резолвера не принимается за отвержение: если dig не дождался
# ответа (пакет уронил файрвол), правило access-control не проверено, и фаза
# обязана отказать, а не засчитать ok. Отказ должен называть причину — ожидаемый
# rcode, а не «резолвер ответил»: иначе молчание и ответ различить нельзя.
dir="$TMPROOT/dns-silent"; fake_tools "$dir"
FAKE_DIG_RC=9 FAKE_DIG_OUT=';; connection timed out; no servers could be reached' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& ! grep -q 'отвергает запрос не из туннельной сети' "$dir/out" \
	&& grep -q 'REFUSED' "$dir/out"
check $? "молчание резолвера вместо REFUSED даёт отказ (код $code)"

# 50. Отвержение проверяется обращением к резолверу по адресу узла: в журнале
# вызова есть dig на 172.31.99.2, а в выводе фазы — напечатанный rcode.
dir="$TMPROOT/dns-rcode"; fake_tools "$dir"
dns_run "$dir"
code=$?
[ "$code" -eq 0 ] \
	&& grep -q 'dig .*@172.31.99.2 probe.e2e.test' "$dir/log" \
	&& grep -q '^ok   тот же резолвер отвергает запрос не из туннельной сети: rcode REFUSED' \
		"$dir/out"
check $? "отказ резолвера доказан rcode из ответа dig (код $code)"

# 51. Чужой nameserver в файле клиента: адрес в ответе стенда ещё не означает,
# что резолвит узел — проверка читает resolv.conf, а не только ответ dig.
dir="$TMPROOT/dns-resolv"; fake_tools "$dir"
FAKE_RESOLV_CONF='nameserver 8.8.8.8' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& ! grep -q '^ok   resolv.conf клиента' "$dir/out"
check $? "resolv.conf без 10.99.7.1 даёт отказ фазы dns (код $code)"

# 52. NOERROR с адресом вне стенда: rcode сам по себе не доказательство, фаза
# сверяет и answer-секцию.
dir="$TMPROOT/dns-badanswer"; fake_tools "$dir"
FAKE_DIG_TUNNEL_OUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11
;; ANSWER SECTION:
probe.e2e.test.		60	IN	A	8.8.8.8' dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& ! grep -q '^ok   resolv.conf клиента' "$dir/out"
check $? "NOERROR с чужим адресом даёт отказ (код $code)"

# 53. SERVFAIL от резолвера узла: ответ есть, но он не положительный. Код выхода
# dig здесь игнорируется намеренно, поэтому отказ обязан называть rcode.
dir="$TMPROOT/dns-servfail"; fake_tools "$dir"
FAKE_DIG_TUNNEL_RC=2 FAKE_DIG_TUNNEL_OUT=';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 13' \
	dns_run "$dir"
code=$?
[ "$code" -ne 0 ] && grep -q 'FAIL' "$dir/out" \
	&& grep -q 'SERVFAIL' "$dir/out" && ! grep -q '^ok   resolv.conf клиента' "$dir/out"
check $? "SERVFAIL от резолвера узла даёт отказ с названием rcode (код $code)"

# 54. Код выхода захвата не участвует в решении: в образе клиента `timeout` из
# busybox возвращает статус дочерней команды, и tcpdump по сигналу уходит с нулём,
# тогда как GNU `timeout` дал бы 124. Фаза обязана проходить при любом из них,
# если снимок говорит «ноль пакетов».
capture_rc_case() { # код выхода перехвата
	local dir="$TMPROOT/dns-rc-$1" code
	fake_tools "$dir"
	FAKE_CAPTURE_RC=$1 dns_run "$dir"
	code=$?
	[ "$code" -eq 0 ] && grep -q '^ok   на eth0 клиента нет ни одного DNS-пакета' "$dir/out" \
		&& grep -q '^ok   перехват чувствителен' "$dir/out"
	check $? "перехват с кодом $1 не влияет на решение фазы dns (код $code)"
}

capture_rc_case 0
capture_rc_case 124
capture_rc_case 143

printf '%s\n' "проверок: $CASES, отказов: $FAILS"
[ "$FAILS" -eq 0 ]
