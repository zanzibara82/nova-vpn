#!/usr/bin/env bash
# Оркестратор стенда E2E. Скрипт исполняется внутри одноразового контейнера
# novavpn-e2e-runner, которому смонтированы исходники только для чтения, Docker
# socket и защищённый том novavpn-e2e-control в /state.
#
# Фазы: all выполняет установку, контроль обхода, проверки туннеля, DNS,
# жизненный цикл доступа и лимит устройств; tunnel, dns, limit и lifecycle проходят
# тот же путь, но проверяют только своё утверждение; down снимает только собственный
# стенд этого проекта. Неизвестная фаза отвергается до любых обращений к Docker. На
# успехе стенд снимается, на отказе остаётся для разбора; снять его можно только
# целью make e2e-down.
set -uo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT=novavpn-e2e
HARNESS=${PROJECT}_harness
UPLINK=${PROJECT}_uplink
CONTROL_VOLUME=${PROJECT}-control
RUNNER_NAME=${PROJECT}-runner
COMPOSE_FILE=$ROOT/infrastructure/docker/docker-compose.e2e.yml

# CONTROL — корень защищённого тома. E2E_STATE_DIR подменяет его только в
# оффлайн-проверках управляющей логики; в настоящем прогоне это /state.
CONTROL=${E2E_STATE_DIR:-/state}
RUN_DIR=$CONTROL/run
OWNER=$RUN_DIR/owner
COMPOSE_ENV=$RUN_DIR/compose.env
API=http://172.31.99.10:8080
# Адрес оркестратора в harness закреплён: без него Docker выдаёт первый
# свободный .99.2 — адрес узла, и создание узла падает с «Address already in
# use». Остальные адреса сети перечислены в docker-compose.e2e.yml.
ORCHESTRATOR_IP=172.31.99.4
# NODE_STATE_FILE — файл состояния агента внутри контейнера узла (том node1-state).
NODE_STATE_FILE=/var/lib/novavpn-node/state.json
ATTACHED=0

say() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok   %s\n' "$*"; }
fail() {
	printf 'FAIL %s\n' "$*" >&2
	exit 1
}

# on_exit не меняет код завершения: исходный отказ важнее сообщения о сохранении.
on_exit() {
	local rc=$?
	trap - EXIT INT TERM
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' 'стенд сохранён для разбора. Снять: make e2e-down' >&2 || true
	fi
	exit "$rc"
}

compose() {
	local args=(--project-name "$PROJECT" -f "$COMPOSE_FILE")
	if [ -f "$COMPOSE_ENV" ]; then
		args+=(--env-file "$COMPOSE_ENV")
	fi
	E2E_CONTROL_DIR="$CONTROL" docker compose "${args[@]}" "$@"
}

self_id() {
	if [ -n "${E2E_ORCHESTRATOR_ID:-}" ]; then
		printf '%s\n' "$E2E_ORCHESTRATOR_ID"
		return 0
	fi
	hostname 2>/dev/null || printf 'unknown\n'
}

need() {
	command -v "$1" >/dev/null 2>&1 || fail "нет команды $1"
}

jget() { # файл путь.через.точку
	python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
for part in sys.argv[2].split("."):
    d = d[int(part)] if part.isdigit() else d[part]
print(d)
PY
}

wait_for() { # секунды, описание, команда...
	local seconds=$1 what=$2
	shift 2
	local deadline=$(( $(date +%s) + seconds ))
	until "$@" >/dev/null 2>&1; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			fail "за ${seconds} с не выполнено: ${what}"
		fi
		sleep 2
	done
}

node_exec() { compose exec -T node1 "$@"; }
client_exec() { compose exec -T client1 "$@"; }
node_run() { compose run --rm -T --no-deps node1 "$@"; }
client_run() { compose run --rm -T --no-deps client1 "$@"; }

# client_bg запускает команду в контейнере клиента откреплённо (exec -d): фоновое
# наблюдение обязано пережить сессию запуска, а его отказ — быть различим.
client_bg() { # текст команды для sh внутри контейнера
	local rc=0
	compose exec -d client1 sh -c "$1" >/dev/null || rc=$?
	[ "$rc" -eq 0 ] || fail "откреплённый запуск команды в контейнере клиента не удался (код $rc)"
}

http_status() { # метод, адрес, файл-тела или -, файл-ответа, файл-заголовков или -
	local method=$1 url=$2 body=$3 out=$4 hdr=$5
	local args=(-sS -o "$out" -w '%{http_code}' --max-time 20 -X "$method")
	if [ "$hdr" != "-" ]; then
		args+=(-H "@$hdr")
	fi
	if [ "$body" != "-" ]; then
		args+=(--data-binary "@$body")
		if [ "$hdr" = "-" ]; then
			args+=(-H 'Content-Type: application/json')
		fi
	fi
	curl "${args[@]}" "$url"
}

expect_status() { # полученный, ожидаемый, что
	if [ "$1" != "$2" ]; then
		fail "$3: код $1, ожидался $2"
	fi
	ok "$3"
}

# http_secret_post выполняет запрос с телом, содержащим пароль, и печатает код
# ответа. Файл тела снимается до вердикта о коде: на отказе стенд и том управления
# сохраняются для разбора, и секрет не должен пережить запрос ни на одной дорожке,
# включая сам сбой curl.
http_secret_post() { # метод, адрес, файл-тела, файл-ответа
	local out rc
	out=$(http_status "$1" "$2" "$3" "$4" -)
	rc=$?
	rm -f "$3"
	printf '%s' "$out"
	return "$rc"
}

write_auth_header() { # json-сессии, файл-заголовков, необязательный Idempotency-Key
	python3 - "$1" "$2" "${3:-}" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write("Authorization: Bearer " + d["access_token"] + "\n")
    f.write("Content-Type: application/json\n")
    if sys.argv[3]:
        f.write("Idempotency-Key: " + sys.argv[3] + "\n")
PY
	chmod 600 "$2"
}

json_login() { # email, файл-пароля, файл-ответа
	python3 - "$1" "$2" "$3" <<'PY'
import json, sys
with open(sys.argv[2], encoding="utf-8") as f:
    password = f.read().strip()
with open(sys.argv[3], "w", encoding="utf-8") as f:
    json.dump({"email": sys.argv[1], "password": password}, f)
PY
	chmod 600 "$3"
}

check_no_private_key() { # файл
	if grep -qi 'PrivateKey' "$1"; then
		fail "API вернул конфиг с приватным ключом"
	fi
	ok "в конфиге API нет приватного ключа"
}

attach_self() {
	if [ "${E2E_ORCHESTRATOR:-0}" != "1" ]; then
		return 0
	fi
	docker network connect --ip "$ORCHESTRATOR_IP" "$HARNESS" "$(self_id)" >/dev/null ||
		fail "не удалось подключить оркестратор к сети $HARNESS"
	ATTACHED=1
}

release_self() {
	if [ "$ATTACHED" != "1" ]; then
		return 0
	fi
	docker network disconnect -f "$HARNESS" "$(self_id)" >/dev/null 2>&1 || true
	ATTACHED=0
}

remove_network() { # имя
	if ! docker network inspect "$1" >/dev/null 2>&1; then
		return 0
	fi
	local label
	label=$(docker network inspect --format '{{ index .Labels "novavpn.e2e.project" }}' "$1" 2>/dev/null || true)
	if [ "$label" != "$PROJECT" ]; then
		fail "сеть $1 существует без метки владельца; удаление не выполняется"
	fi
	docker network rm "$1" >/dev/null ||
		fail "не удалось снять сеть $1: остались активные подключения"
}

api_ready() { curl -fsS -o /dev/null --max-time 2 "$API/debug/health"; }
db_ready() { compose exec -T postgres pg_isready -h 127.0.0.1 -U nova -d novavpn -q; }
redis_ready() { compose exec -T redis redis-cli ping >/dev/null; }
node_wg_up() { node_exec ip link show wg0; }
client_wg_up() { client_exec ip link show wg0; }
# node_peer_present различает три исхода: 0 — пиер есть, 1 — пиера нет при
# успешно прочитанном списке, 2 — список не прочитан. Pipeline здесь не годится:
# он потерял бы код чтения и выдал отказ за отсутствие пиера.
node_peer_present() { # публичный ключ клиента
	local peers
	peers=$(node_exec wg show wg0 peers) || return 2
	printf '%s\n' "$peers" | grep -qx -- "$1"
}

# peer_address_owner печатает ключ пиера, которому выдан адрес: в WireGuard адрес
# принадлежит одному пиеру. Код 1 — allowed-ips узла не прочитаны, пустой вывод при
# коде 0 — адрес ни у кого.
peer_address_owner() { # адрес
	local list
	list=$(node_exec wg show wg0 allowed-ips) || return 1
	printf '%s\n' "$list" | awk -v a="$1" '$2 == a { print $1 }'
}

# peers_none, peers_at_least_one, peer_absent и peer_count различают исходы так же,
# как node_peer_present: непрочитанный список не доказывает ни наличие, ни отсутствие
# пиеров.
peers_none() {
	local peers
	peers=$(node_exec wg show wg0 peers) || return 2
	[ -z "$(printf '%s' "$peers" | tr -d '[:space:]')" ]
}

peers_at_least_one() {
	local peers
	peers=$(node_exec wg show wg0 peers) || return 2
	printf '%s\n' "$peers" | grep -q .
}

peer_absent() { # публичный ключ клиента
	local rc=0
	node_peer_present "$1" || rc=$?
	case "$rc" in
	0) return 1 ;;
	1) return 0 ;;
	*) return 2 ;;
	esac
}

peer_count() { # печатает число пиеров; код 1 — список не прочитан
	local peers count
	peers=$(node_exec wg show wg0 peers) || return 1
	count=$(printf '%s\n' "$peers" | grep -c .) || count=0
	printf '%s\n' "$count"
}

# wait_peer_state — ожидание с различимым кодом 2: непрочитанное состояние узла
# даёт немедленный отдельный отказ, а не «за N с не выполнено».
wait_peer_state() { # секунды, описание, команда...
	local seconds=$1 what=$2
	shift 2
	local deadline=$(( $(date +%s) + seconds )) rc=0
	while :; do
		"$@" >/dev/null 2>&1
		rc=$?
		case "$rc" in
		0) return 0 ;;
		2) fail "не удалось прочитать состояние пиеров узла; ${what} не доказано" ;;
		esac
		if [ "$(date +%s)" -ge "$deadline" ]; then
			fail "за ${seconds} с не выполнено: ${what}"
		fi
		sleep 2
	done
}
probe_healthy_from_node() {
	[ "$(node_exec wget -qO- -T 3 http://172.31.98.3:8080/healthz 2>/dev/null | tr -d '\r\n')" = "ok" ]
}

# subnet_overlap печатает 1 при пересечении двух IPv4-подсетей, 0 — без
# пересечения и 2 — если запись не распознана. Сеть с префиксом p занимает
# [int(ip/2^(32-p))*2^(32-p), +2^(32-p)-1].
subnet_overlap() { # наша подсеть, чужая подсеть
	awk -v x="$1" -v y="$2" '
	function bounds(s, p, ip, i, n, base, bits) {
		if (s ~ /[^0-9.\/]/) return 0
		n = split(s, p, "/")
		if (n != 2) return 0
		if (p[2] + 0 > 32) return 0
		if (split(p[1], ip, ".") != 4) return 0
		for (i = 1; i <= 4; i++) {
			if (ip[i] == "" || ip[i] + 0 > 255) return 0
		}
		base = 0
		for (i = 1; i <= 4; i++) base = base * 256 + ip[i]
		bits = 2 ^ (32 - p[2])
		lo = int(base / bits) * bits
		hi = lo + bits - 1
		return 1
	}
	BEGIN {
		if (!bounds(x)) { print 2; exit }
		xl = lo; xh = hi
		if (!bounds(y)) { print 2; exit }
		if (xl <= hi && lo <= xh) { print 1 } else { print 0 }
	}'
}

# check_subnets отказывает до создания ресурсов, если чужая сеть Docker занимает
# нашу подсеть, а также если список сетей или их подсети прочитать не удалось:
# непрочитанная подсеть не доказывает свободу.
check_subnets() {
	local nets net subnets subnet ours rc
	nets=$(docker network ls --format '{{.Name}}') ||
		fail "не удалось прочитать подсети Docker"
	for net in $nets; do
		# Судьбу своих сетей решают проверки имён ниже.
		case "$net" in
		"$HARNESS" | "$UPLINK") continue ;;
		esac
		subnets=$(docker network inspect \
			--format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$net") ||
			fail "не удалось прочитать подсети Docker"
		for subnet in $subnets; do
			case "$subnet" in
			'' | *:*) continue ;;
			esac
			for ours in 172.31.99.0/24 172.31.98.0/24; do
				rc=$(subnet_overlap "$ours" "$subnet") || rc=2
				case "$rc" in
				0) ;;
				1) fail "сеть $net занимает подсеть $subnet; пересечение с нашей подсетью $ours" ;;
				*) fail "не удалось прочитать подсети Docker" ;;
				esac
			done
		done
	done
	ok "подсети чужих сетей Docker не пересекаются с 172.31.98.0/24 и 172.31.99.0/24"
}

preflight() {
	need docker
	docker info >/dev/null 2>&1 || fail "Docker недоступен"
	check_subnets

	if [ -e "$OWNER" ]; then
		fail "найден маркер прошлого запуска в $OWNER; сначала выполните make e2e-down"
	fi

	local occupied
	occupied=$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' 2>/dev/null || true)
	if [ -n "$occupied" ]; then
		fail "имена проекта $PROJECT заняты: $(printf '%s' "$occupied" | tr '\n' ' ')"
	fi

	local net
	for net in "$HARNESS" "$UPLINK"; do
		if docker network inspect "$net" >/dev/null 2>&1; then
			fail "сеть $net уже существует; чужой или прежний стенд не переиспользуется"
		fi
	done

	local vol label
	for vol in "${PROJECT}-postgres-data" "${PROJECT}-node1-state" "${PROJECT}-client1-state"; do
		if docker volume inspect "$vol" >/dev/null 2>&1; then
			label=$(docker volume inspect --format '{{ index .Labels "novavpn.e2e.project" }}' "$vol" 2>/dev/null || true)
			fail "том $vol уже существует (метка: $label); сначала выполните make e2e-down"
		fi
	done

	if docker volume inspect "$CONTROL_VOLUME" >/dev/null 2>&1; then
		label=$(docker volume inspect --format '{{ index .Labels "novavpn.e2e.project" }}' "$CONTROL_VOLUME" 2>/dev/null || true)
		if [ "$label" != "$PROJECT" ]; then
			fail "том $CONTROL_VOLUME существует без нашей метки владельца"
		fi
	fi
	ok "предварительные проверки пройдены, ресурсы $PROJECT свободны"
}

write_state() {
	mkdir -p "$RUN_DIR"
	chmod 700 "$RUN_DIR"

	# Маркер принадлежности создаётся исключительно новым файлом.
	( set -C; printf 'project=%s\nrun=%s\nstarted=%s\n' \
		"$PROJECT" "$$" "$(date -u +%Y%m%dT%H%M%SZ)" > "$OWNER" ) 2>/dev/null ||
		fail "не удалось создать маркер владения $OWNER"

	printf 'E2E_CONTROL_DIR=%s\nE2E_ADMIN_EMAIL=admin@e2e.test\nE2E_USER_EMAIL=user@e2e.test\n' \
		"$CONTROL" > "$COMPOSE_ENV"

	python3 - "$RUN_DIR/postgres.env" <<'PY'
import secrets, sys
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write("POSTGRES_PASSWORD=" + secrets.token_hex(24) + "\n")
PY
	python3 - "$RUN_DIR/admin.pass" <<'PY'
import secrets, sys
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write(secrets.token_hex(24) + "\n")
PY
	python3 - "$RUN_DIR/user.pass" <<'PY'
import secrets, sys
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write(secrets.token_hex(24) + "\n")
PY
	python3 - "$RUN_DIR/api.env" "$RUN_DIR/postgres.env" <<'PY'
import base64, secrets, sys
with open(sys.argv[2], encoding="utf-8") as f:
    password = f.read().strip().removeprefix("POSTGRES_PASSWORD=")
jwt = base64.b64encode(secrets.token_bytes(48)).decode()
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write("NOVAVPN_ENV=dev\n")
    f.write("NOVAVPN_LISTEN_ADDR=:8080\n")
    f.write("NOVAVPN_DATABASE_URL=postgres://nova:" + password +
            "@172.31.99.11:5432/novavpn?sslmode=disable\n")
    f.write("NOVAVPN_REDIS_ADDR=172.31.99.12:6379\n")
    f.write("NOVAVPN_JWT_SECRET=" + jwt + "\n")
PY
	chmod 600 "$COMPOSE_ENV" "$RUN_DIR/postgres.env" "$RUN_DIR/admin.pass" \
		"$RUN_DIR/user.pass" "$RUN_DIR/api.env"
	ok "защищённое состояние создано в $RUN_DIR"
}

setup() {
	say "установка стенда: образы, БД, администратор, узел, клиент"
	preflight
	need python3
	need curl
	write_state

	compose build || fail "сборка образов стенда не удалась"
	ok "образы стенда собраны"

	compose up -d --no-deps postgres redis || fail "не удалось запустить postgres/redis"
	wait_for 120 "postgres принимает соединения" db_ready
	wait_for 60 "redis отвечает" redis_ready
	ok "postgres и redis готовы"

	attach_self
	ok "оркестратор подключён к сети $HARNESS"

	compose run --rm -T --no-deps migrate || fail "миграции не применились"
	compose run --rm -T --no-deps api admin create admin@e2e.test \
		< "$RUN_DIR/admin.pass" >/dev/null || fail "не удалось создать администратора"
	ok "схема обновлена, администратор создан"

	compose up -d --no-deps api || fail "не удалось запустить API"
	wait_for 120 "API отвечает на /debug/health" api_ready
	ok "API готов"

	json_login admin@e2e.test "$RUN_DIR/admin.pass" "$RUN_DIR/admin-login.json"
	local status
	status=$(http_secret_post POST "$API/api/v1/admin/login" "$RUN_DIR/admin-login.json" \
		"$RUN_DIR/admin-session.json") || fail "вход администратора не выполнен"
	expect_status "$status" 200 "администратор вошёл"
	write_auth_header "$RUN_DIR/admin-session.json" "$RUN_DIR/admin.hdr"

	local out node_pub
	out=$(node_run init 2>"$RUN_DIR/node-init.err") ||
		fail "init узла не выполнен; stderr: $RUN_DIR/node-init.err"
	node_pub=$(printf '%s\n' "$out" | sed -n 's/^public_key //p' | head -n 1)
	[ -n "$node_pub" ] || fail "init узла не напечатал public_key"
	python3 - "$node_pub" "$RUN_DIR/server.json" <<'PY'
import json, sys
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({
        "name": "e2e-1",
        "advertised_host": "172.31.99.2",
        "listen_port": 51820,
        "public_key": sys.argv[1],
        "address_pool_v4": "10.99.7.0/24",
        "provider": "e2e",
        "reason": "стенд E2E",
        "location": {"country_code": "DE", "city": "Test", "lat": "52.5",
                     "lon": "13.4", "timezone": "UTC"},
    }, f)
PY
	status=$(http_status POST "$API/api/v1/admin/servers" "$RUN_DIR/server.json" \
		"$RUN_DIR/server-created.json" "$RUN_DIR/admin.hdr") || fail "создание сервера не выполнено"
	expect_status "$status" 201 "сервер создан"
	local server_id
	server_id=$(jget "$RUN_DIR/server-created.json" id)

	printf '{"status":"online","reason":"стенд E2E"}\n' > "$RUN_DIR/online.json"
	status=$(http_status POST "$API/api/v1/admin/servers/$server_id/maintenance" \
		"$RUN_DIR/online.json" "$RUN_DIR/online-resp.json" "$RUN_DIR/admin.hdr") ||
		fail "перевод сервера в online не выполнен"
	expect_status "$status" 200 "сервер переведён в online"

	printf '{}\n' > "$RUN_DIR/empty.json"
	status=$(http_status POST "$API/api/v1/admin/servers/$server_id/bootstrap-tokens" \
		"$RUN_DIR/empty.json" "$RUN_DIR/bootstrap.json" "$RUN_DIR/admin.hdr") ||
		fail "выдача bootstrap-токена не выполнена"
	expect_status "$status" 201 "bootstrap-токен выдан"
	python3 - "$RUN_DIR/bootstrap.json" "$RUN_DIR/bootstrap.token" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    token = json.load(f)["token"]
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(token + "\n")
PY
	chmod 600 "$RUN_DIR/bootstrap.token"
	rm -f "$RUN_DIR/bootstrap.json"

	node_run enroll < "$RUN_DIR/bootstrap.token" || fail "регистрация узла не выполнена"
	ok "узел зарегистрирован"

	compose up -d --no-deps node1 || fail "не удалось запустить узел"
	wait_for 120 "узел поднял интерфейс wg0" node_wg_up
	ok "узел работает и поднял wg0"

	local client_pub
	client_pub=$(client_run genkey 2>/dev/null |
		sed -n 's/.*\([A-Za-z0-9+/]\{43\}=\).*/\1/p' | tail -n 1) ||
		fail "генерация ключа клиента не выполнена"
	[ -n "$client_pub" ] || fail "клиент не напечатал публичный ключ"

	json_login user@e2e.test "$RUN_DIR/user.pass" "$RUN_DIR/register.json"
	status=$(http_secret_post POST "$API/api/v1/auth/register" "$RUN_DIR/register.json" \
		"$RUN_DIR/user-session.json") || fail "регистрация пользователя не выполнена"
	expect_status "$status" 201 "пользователь зарегистрирован"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/user.hdr"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/device.hdr" e2e-device-1
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/profile.hdr" e2e-profile-1

	python3 - "$client_pub" "$RUN_DIR/device.json" <<'PY'
import json, sys
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"public_key": sys.argv[1], "platform": "linux",
               "name": "e2e-client"}, f)
PY
	status=$(http_status POST "$API/api/v1/devices" "$RUN_DIR/device.json" \
		"$RUN_DIR/device-created.json" "$RUN_DIR/device.hdr") ||
		fail "регистрация устройства не выполнена"
	expect_status "$status" 201 "устройство зарегистрировано"
	local device_id
	device_id=$(jget "$RUN_DIR/device-created.json" id)

	python3 - "$server_id" "$RUN_DIR/profile.json" <<'PY'
import json, sys
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"server_id": sys.argv[1]}, f)
PY
	status=$(http_status POST "$API/api/v1/devices/$device_id/profiles" \
		"$RUN_DIR/profile.json" "$RUN_DIR/profile-created.json" "$RUN_DIR/profile.hdr") ||
		fail "выдача профиля не выполнена"
	expect_status "$status" 201 "профиль выдан"

	status=$(http_status GET "$API/api/v1/devices/$device_id/profiles/$server_id/config" \
		- "$RUN_DIR/client.conf" "$RUN_DIR/user.hdr") ||
		fail "получение конфига не выполнено"
	expect_status "$status" 200 "конфиг получен"
	check_no_private_key "$RUN_DIR/client.conf"

	# Конфиг кладётся в клиентский том до старта client1: проверка формы идёт
	# внутри точки входа клиента, а приватный ключ остаётся только в томе.
	client_run saveconfig < "$RUN_DIR/client.conf" ||
		fail "клиент не принял конфиг API"
	ok "конфиг API сохранён в клиентском томе"

	status=$(http_status GET "$API/api/v1/me" - "$RUN_DIR/me.json" "$RUN_DIR/user.hdr") ||
		fail "проверка сессии пользователя не выполнена"
	expect_status "$status" 200 "сессия пользователя действует"

	compose up -d --no-deps probe || fail "не удалось запустить probe"
	wait_for 60 "probe здоров с узла по uplink" probe_healthy_from_node
	ok "probe здоров и доступен с узла по uplink"
}

negative_control() {
	say "контроль обхода: до туннеля probe обязан быть недостижим"
	local rc=0
	client_run sh -c '
		if ip link show wg0 >/dev/null 2>&1; then
			echo "у клиента уже есть wg0" >&2
			exit 42
		fi
		curl -fsS --max-time 5 http://172.31.98.3:8080/whoami >/dev/null 2>&1
	' || rc=$?
	if [ "$rc" -eq 42 ]; then
		fail "во временном клиенте уже существует wg0; контроль обхода недостоверен"
	fi
	if [ "$rc" -eq 0 ]; then
		fail "без туннеля клиент достиг probe по адресу; обходной маршрут существует"
	fi
	ok "без туннеля probe по IP недостижим, DNS-ошибка сюда не засчитана"
}

node_transfer() { # публичный ключ клиента
	node_exec wg show wg0 transfer | awk -v k="$1" '$1 == k { print $2, $3 }'
}

client_transfer_sum() {
	client_exec wg show wg0 transfer | awk '{ r += $2; t += $3 } END { print r + 0, t + 0 }'
}

peer_allowed_ips() { # публичный ключ клиента
	node_exec wg show wg0 allowed-ips | awk -v k="$1" '$1 == k { print $2 }'
}

# peer_holds_address — 0 адрес у ключа, 1 адрес другой или пуст, 2 allowed-ips не
# прочитаны: именно код 2 нужен ожиданию, иначе сбой чтения выглядел бы как «адреса
# ещё нет».
peer_holds_address() { # публичный ключ клиента, адрес
	local allowed
	allowed=$(peer_allowed_ips "$1") || return 2
	[ "$allowed" = "$2" ]
}

peer_handshake() { # публичный ключ клиента
	node_exec wg show wg0 latest-handshakes | awk -v k="$1" '$1 == k { print $2 }'
}

wait_handshake() { # публичный ключ клиента; 2 — не удалось прочитать состояние
	local key=$1 deadline=$(( $(date +%s) + 60 )) value
	while :; do
		if ! value=$(peer_handshake "$key"); then
			return 2
		fi
		case "$value" in
		''|0) ;;
		*) return 0 ;;
		esac
		if [ "$(date +%s)" -ge "$deadline" ]; then
			return 1
		fi
		sleep 2
	done
}

# wait_peer ждёт пиера клиента до 90 с: 0 — пиер найден, 1 — не появился,
# 2 — список пиеров не прочитан, ожидание прекращается сразу.
wait_peer() { # публичный ключ клиента
	local key=$1 deadline=$(( $(date +%s) + 90 )) rc
	while :; do
		node_peer_present "$key"
		rc=$?
		case "$rc" in
		0) return 0 ;;
		2) return 2 ;;
		esac
		if [ "$(date +%s)" -ge "$deadline" ]; then
			return 1
		fi
		sleep 2
	done
}

trigger_traffic() {
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		if client_exec ping -c 1 -W 2 172.31.98.3 >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	return 1
}

# proxy_egress печатает адрес egress из HTTP-запроса клиента к probe по имени либо
# завершается не нулём, если сам запрос не выполнен.
proxy_egress() {
	client_exec curl -fsS --max-time 10 http://probe.e2e.test:8080/whoami | tr -d '\r\n'
}

# proxy_ok — тот же запрос с проверкой адреса; вердикт и формулировку отказа
# печатает вызывающая фаза, поэтому туннель и жизненный цикл не расходятся.
proxy_ok() {
	local egress
	egress=$(proxy_egress) || return 1
	[ "$egress" = "172.31.98.2" ]
}

tunnel() {
	say "туннель: пиер, handshake, HTTP, ICMP, маршрут и счётчики"

	compose up -d --no-deps client1 || fail "не удалось запустить клиент"
	wait_for 90 "клиент поднял интерфейс wg0" client_wg_up
	ok "клиент подключил wg0"

	local client_pub
	client_pub=$(client_exec wg show wg0 public-key 2>/dev/null | tr -d '\r\n')
	[ -n "$client_pub" ] || fail "не удалось прочитать публичный ключ клиента"
	# Агент опрашивает API раз в 25 с: до первого трафика убеждаемся, что новый
	# пиер уже применён, иначе короткое ожидание ping не докажет ничего.
	# Ошибка чтения списка пиеров не выдаётся за их отсутствие.
	local peer_rc=0
	wait_peer "$client_pub" || peer_rc=$?
	if [ "$peer_rc" -eq 2 ]; then
		fail "не удалось прочитать список пиеров узла; отсутствие пиера не доказано"
	fi
	[ "$peer_rc" -eq 0 ] || fail "пиер клиента не появился на узле за 90 с"
	ok "узел получил пиера клиента"

	trigger_traffic || fail "трафик по IP не инициировал handshake"
	local hs_rc=0
	wait_handshake "$client_pub" || hs_rc=$?
	if [ "$hs_rc" -eq 2 ]; then
		fail "не удалось прочитать handshake узла; отсутствие handshake не доказано"
	fi
	[ "$hs_rc" -eq 0 ] || fail "handshake с клиентом не появился"

	local peers allowed handshake
	peers=$(node_exec wg show wg0 peers) ||
		fail "не удалось прочитать список пиеров узла; отсутствие пиера не доказано"
	printf '%s\n' "$peers" | grep -qx "$client_pub" ||
		fail "на узле нет пиера с публичным ключом клиента"
	ok "на узле найден именно CLIENT_PUB"

	allowed=$(peer_allowed_ips "$client_pub") ||
		fail "не удалось прочитать allowed-ips узла"
	[ "$allowed" = "10.99.7.2/32" ] ||
		fail "allowed-ips клиента $allowed, ожидался 10.99.7.2/32"
	ok "allowed-ips клиента = 10.99.7.2/32"

	handshake=$(peer_handshake "$client_pub") ||
		fail "не удалось прочитать handshake узла"
	[ -n "$handshake" ] && [ "$handshake" != "0" ] ||
		fail "handshake клиента отсутствует"
	ok "handshake клиента ненулевой"

	client_exec wg show wg0 >/dev/null || fail "состояние wg0 клиента недоступно"
	node_exec wg show wg0 >/dev/null || fail "состояние wg0 узла недоступно"
	ok "интерфейсы wg0 клиента и узла доступны"

	local nrx0 ntx0 nrx1 ntx1 crx0 ctx0 crx1 ctx1 ntrans ctrans
	ntrans=$(node_transfer "$client_pub") ||
		fail "wg show transfer узла не выполнен; счётчики не доказаны"
	read -r nrx0 ntx0 <<< "$ntrans"
	ctrans=$(client_transfer_sum) ||
		fail "wg show transfer клиента не выполнен; счётчики не доказаны"
	read -r crx0 ctx0 <<< "$ctrans"
	[ -n "${nrx0:-}" ] && [ -n "${ntx0:-}" ] || fail "счётчики узла не прочитаны"
	[ -n "${crx0:-}" ] && [ -n "${ctx0:-}" ] || fail "счётчики клиента не прочитаны"

	local egress
	egress=$(proxy_egress) ||
		fail "HTTP-запрос к probe через имя не выполнен"
	[ "$egress" = "172.31.98.2" ] ||
		fail "egress = $egress, ожидался адрес узла 172.31.98.2"
	ok "HTTP через имя вернул ровно 172.31.98.2"

	client_exec ping -c 3 -W 2 -q 172.31.98.3 >/dev/null ||
		fail "ICMP через туннель не проходит"
	ok "ICMP -c 3 через туннель проходит"

	local route
	route=$(client_exec ip route get 172.31.98.3) ||
		fail "маршрут до probe не прочитан"
	printf '%s\n' "$route" | grep -q 'dev wg0' ||
		fail "маршрут до probe не идёт через wg0: $route"
	ok "маршрут до probe идёт через wg0"

	ntrans=$(node_transfer "$client_pub") ||
		fail "wg show transfer узла не выполнен; счётчики не доказаны"
	read -r nrx1 ntx1 <<< "$ntrans"
	ctrans=$(client_transfer_sum) ||
		fail "wg show transfer клиента не выполнен; счётчики не доказаны"
	read -r crx1 ctx1 <<< "$ctrans"
	[ -n "${nrx1:-}" ] && [ -n "${ntx1:-}" ] || fail "счётчики узла не прочитаны"
	[ -n "${crx1:-}" ] && [ -n "${ctx1:-}" ] || fail "счётчики клиента не прочитаны"
	[ "$nrx1" -gt "$nrx0" ] && [ "$ntx1" -gt "$ntx0" ] ||
		fail "счётчики узла не выросли: было $nrx0/$ntx0, стало $nrx1/$ntx1"
	[ "$crx1" -gt "$crx0" ] && [ "$ctx1" -gt "$ctx0" ] ||
		fail "счётчики клиента не выросли: было $crx0/$ctx0, стало $crx1/$ctx1"
	ok "счётчики передачи выросли на узле и на клиенте"
}

# capture_count читает итоговую строку tcpdump из снимка в /state клиента и
# печатает число пойманных пакетов. Пустое значение означает, что статистики нет
# и снимок нечитаем — это не «ноль пакетов». Живой tcpdump печатает единственное
# число без «s» («1 packet captured»), поэтому шаблон покрывает обе формы.
capture_count() { # имя_файла_снимка
	client_exec sh -c "grep -oE '[0-9]+ packets? captured' /state/$1 | tail -n 1" 2>/dev/null |
		tr -d '\r' | awk '{print $1}'
}

# dns — три разных утверждения о DNS, и каждое проверяется отдельно: клиент
# получает ответ резолвера узла; ни один DNS-пакет не уходит с eth0 клиента мимо
# туннеля; тот же резолвер отвергает запрос из сети без туннеля. Первое без
# второго и третьего не доказывает ничего. Порядок внутри фазы: резолв через
# туннель, положительный контроль перехвата, перехват-утечка, отказ из чужой
# сети, журнал узла, IPv6. Контроль стоит перед вердиктом об утечке: ok-строка
# «пакетов нет» должна печататься уже после того, как доказано, что перехват
# вообще способен поймать пакет.
dns() {
	say "DNS: резолвер узла, отсутствие утечки, отказ из чужой сети, IPv6"

	# resolv.conf читается явно: ответ стенда сам по себе не означает, что
	# резолвит узел — адрес резолвера проверяется по файлу клиента. Строк
	# nameserver обязана быть ровно одна: второй адрес был бы каналом утечки,
	# который окном перехвата ниже не наблюдается, и наличие нужной строки среди
	# прочих этого не исключает.
	local resolv ns_count
	resolv=$(client_exec cat /etc/resolv.conf 2>/dev/null | tr -d '\r')
	ns_count=$(printf '%s\n' "$resolv" | grep -cE '^[[:space:]]*nameserver')
	[ "$ns_count" = 1 ] ||
		fail "в /etc/resolv.conf клиента $ns_count строк nameserver, ожидалась ровно одна"
	printf '%s\n' "$resolv" | grep -Eq '^[[:space:]]*nameserver[[:space:]]+10\.99\.7\.1([[:space:]]|$)' ||
		fail "в /etc/resolv.conf клиента нет nameserver 10.99.7.1"

	# Запрос — A-запись через dig с явным адресом резолвера. nslookup для этой
	# проверки непригоден: он дополнительно шлёт AAAA, форвардер стенда на AAAA
	# отвергает, и у bind-ной версии nslookup код выхода 1 при верной A-записи.
	# Решение берётся из разобранного rcode и answer-секции, а не из кода выхода.
	local dig_out rcode
	dig_out=$(client_exec dig +tries=1 +time=3 +noedns @10.99.7.1 probe.e2e.test 2>/dev/null | tr -d '\r')
	rcode=$(printf '%s\n' "$dig_out" | grep -o 'status: [A-Z]*' | tail -n 1)
	[ "$rcode" = "status: NOERROR" ] ||
		fail "резолвер узла не ответил NOERROR на A-запрос клиента (получено: '${rcode:-нет ответа}')"
	printf '%s\n' "$dig_out" | grep -qE 'IN[[:space:]]+A[[:space:]]+172\.31\.98\.3([[:space:]]|$)' ||
		fail "имя probe.e2e.test разрешилось не в адрес стенда (rcode NOERROR, ответ без 172.31.98.3)"
	ok "resolv.conf клиента → 10.99.7.1, имя probe.e2e.test резолвится в 172.31.98.3"

	# R63: положительный контроль чувствительности идёт раньше вердикта об
	# утечке. Тот же интерфейс, тот же захват, но запрос идёт НЕ через туннель —
	# пакет обязан быть пойман. Без этого шага «ноль пакетов» ниже неотличим от
	# неработающего tcpdump.
	local control_snippet='timeout 10 tcpdump -i eth0 -n -q -c 1 '"'"'( port 53 or port 853 or port 5353 )'"'"' > /state/control.log 2>&1 &'
	control_snippet="$control_snippet"' cap=$!; sleep 1;'
	control_snippet="$control_snippet"' dig +tries=1 +time=3 +noedns @172.31.99.2 probe.e2e.test >/dev/null 2>&1;'
	control_snippet="$control_snippet"' wait $cap'
	client_exec sh -c "$control_snippet" >/dev/null 2>&1
	local control_count
	control_count=$(capture_count control.log)
	[ -n "$control_count" ] ||
		fail "положительный контроль перехвата не дал статистики: /state/control.log в контейнере client1"
	[ "$control_count" -gt 0 ] 2>/dev/null ||
		fail "перехват не поймал DNS-пакет мимо туннеля (поймано $control_count): проверка утечки недостоверна"
	ok "перехват чувствителен: запрос мимо туннеля пойман на eth0"

	# DNS-пакет на eth0 клиента, ушедший мимо wg0, — это утечка. Окно захвата
	# обязано охватывать запрос: tcpdump поднимается в фоне ДО резолва и
	# дожидается ПОСЛЕ него. Решением служит число пойманных пакетов из итоговой
	# строки снимка, а не код выхода захвата: в образе клиента `timeout` из
	# busybox возвращает статус дочерней команды, а tcpdump по сигналу выходит с
	# нулём (замер на стенде), так что по коду «пусто» неотличимо от «пойман».
	# Фильтр не привязан к udp и накрывает 53, 853 и 5353: ok-строка обещает
	# отсутствие DNS-трафика, и TCP-53, DoT и mDNS мимо туннеля тоже относятся к
	# нему. Снимок живёт в /state клиента; в тексте отказа печатаются путь и
	# число, но не содержимое пакетов.
	local leak_snippet='timeout 10 tcpdump -i eth0 -n -q -c 1 '"'"'( port 53 or port 853 or port 5353 )'"'"' > /state/leak.log 2>&1 &'
	leak_snippet="$leak_snippet"' cap=$!; sleep 1;'
	leak_snippet="$leak_snippet"' dig +tries=1 +time=3 +noedns @10.99.7.1 probe.e2e.test >/dev/null 2>&1;'
	leak_snippet="$leak_snippet"' wait $cap'
	client_exec sh -c "$leak_snippet" >/dev/null 2>&1
	local leak_count
	leak_count=$(capture_count leak.log)
	[ -n "$leak_count" ] ||
		fail "перехват на eth0 клиента не дал статистики: /state/leak.log в контейнере client1"
	[ "$leak_count" = 0 ] ||
		fail "на eth0 клиента захвачен DNS-пакет (поймано $leak_count); снимок — /state/leak.log в контейнере client1"
	ok "на eth0 клиента нет ни одного DNS-пакета"

	# Ожидается именно rcode REFUSED в ответе резолвера, а не молчание: таймаут
	# означал бы, что пакет уронил файрвол, и тогда правило access-control этой
	# проверкой не доказано. Код выхода dig не учитывается: живой замер на стенде
	# дал REFUSED при коде 0, поэтому решение берётся только из разобранного
	# rcode, а пустое значение (нет ответа) даёт отказ.
	local refused
	refused=$(client_exec dig +tries=1 +time=3 +noedns @172.31.99.2 probe.e2e.test 2>/dev/null |
		tr -d '\r' | grep -o 'status: [A-Z]*' | tail -n 1)
	[ "$refused" = "status: REFUSED" ] ||
		fail "резолвер узла не ответил REFUSED на запрос без туннеля (получено: '${refused:-нет ответа}')"
	ok "тот же резолвер отвергает запрос не из туннельной сети: rcode REFUSED"

	# Непрочитанный журнал — не «журнал чист»: отсутствие строк доказывает
	# только успешно прочитанный вывод контейнера.
	local nodelog
	if ! nodelog=$(compose logs --no-color node1 2>/dev/null); then
		fail "не удалось прочитать журнал контейнера узла; отсутствие строк запросов не доказано"
	fi
	if printf '%s\n' "$nodelog" | grep -qE 'query:|reply:'; then
		fail "в журнале контейнера узла есть строки запросов unbound"
	fi
	ok "журнала DNS-запросов в выводе контейнера узла нет"

	# ADR-007: IPv6 на клиенте отключён. Сначала сверяется сам механизм — флаг
	# ядра: три отрицательных признака без него читались бы как «отключено» и
	# при сломанном инструменте. Затем три независимых признака — адрес, маршрут
	# и путь наружу: маршрут по умолчанию без адреса был бы тихой чёрной дырой, и
	# его тоже быть не должно.
	local ip6_flag
	ip6_flag=$(client_exec cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null | tr -d '\r')
	[ "$ip6_flag" = 1 ] ||
		fail "net.ipv6.conf.all.disable_ipv6 на клиенте не равен 1 (получено: '${ip6_flag:-нет значения}')"
	if client_exec sh -c 'ip -6 addr show | grep -q "inet6 .*global"'; then
		fail "у клиента есть глобальный IPv6-адрес"
	fi
	if client_exec sh -c 'ip -6 route show default | grep -q .'; then
		fail "у клиента есть IPv6-маршрут по умолчанию (ADR-007: тихая чёрная дыра)"
	fi
	if client_exec sh -c 'ping -6 -c 1 -W 1 2001:db8::1' >/dev/null 2>&1; then
		fail "IPv6-путь наружу существует"
	fi
	ok "IPv6 на клиенте отключён: адреса, маршрута и пути наружу нет"
}

# device_register создаёт дополнительное устройство. Публичный ключ считается
# внутри уже запущенного контейнера клиента: приватная часть не покидает
# контейнер и не печатается ни в журнале, ни в ok, ни в отказе. Идемпотентный
# ключ — отдельный на каждое устройство и лежит в файле заголовков, который
# curl читает через -H @файл.
device_register() { # номер устройства, ожидаемый код
	local n=$1 want=$2 pub status
	pub=$(client_exec sh -c 'wg genkey | wg pubkey' 2>/dev/null | tr -d '\r\n') ||
		fail "клиент не выдал ключ для устройства $n"
	printf '%s\n' "$pub" | grep -Eq '^[A-Za-z0-9+/]{43}=$' ||
		fail "клиент выдал некорректный публичный ключ для устройства $n"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/device-$n.hdr" "e2e-device-$n"
	python3 - "$pub" "$n" "$RUN_DIR/device-$n.json" <<'PY'
import json, sys
with open(sys.argv[3], "w", encoding="utf-8") as f:
    json.dump({"public_key": sys.argv[1], "platform": "linux",
               "name": "e2e-extra-" + sys.argv[2]}, f)
PY
	chmod 600 "$RUN_DIR/device-$n.hdr" "$RUN_DIR/device-$n.json"
	status=$(http_status POST "$API/api/v1/devices" "$RUN_DIR/device-$n.json" \
		"$RUN_DIR/device-$n.out" "$RUN_DIR/device-$n.hdr") ||
		fail "запрос на создание устройства $n не выполнен"
	[ "$status" = "$want" ] || fail "устройство $n: HTTP $status, ожидался $want"
}

# limit проверяет жёсткий лимит устройств ровно на том же стенде, где уже
# зарегистрировано первое: третье устройство проходит, четвёртое отклоняется 409
# с кодом device_limit_reached. Код ошибки читается из тела ответа, а не из
# статуса: любой другой 409 лимит не доказывает.
limit() {
	say "лимит устройств: третье проходит, четвёртое — 409"
	# Access-токен живёт десять минут, а между выдачей сессии в setup и этой
	# фазой стоят контроль обхода, туннель и dns. На стенде проекта журнал уже
	# показывал 401 в лимите, поэтому сессия обновляется здесь: тело входа
	# собирается из файла пароля, а не из аргументов команды.
	local fresh status
	fresh="$RUN_DIR/limit-login.json"
	json_login user@e2e.test "$RUN_DIR/user.pass" "$fresh"
	status=$(http_secret_post POST "$API/api/v1/auth/login" "$fresh" \
		"$RUN_DIR/user-session.json") || fail "вход за свежей сессией не выполнен"
	expect_status "$status" 200 "свежая сессия для фазы лимита получена"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/user.hdr"
	local n
	for n in 2 3; do
		device_register "$n" 201
	done
	ok "устройства 2 и 3 созданы: HTTP 201"
	device_register 4 409
	if ! python3 - "$RUN_DIR/device-4.out" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        code = json.load(f)["error"]["code"]
except Exception:
    sys.exit(2)
sys.exit(0 if code == "device_limit_reached" else 1)
PY
	then
		fail "четвёртое устройство отклонено не по коду device_limit_reached"
	fi
	ok "лимит 3: четвёртое устройство отклонено с device_limit_reached"
}

# ping_pause печатает паузу трафика в секундах: 0 — отказов не было, -1 — отказ был
# и трафик не вернулся, 2 — строк наблюдения нет (пустой или нечитаемый журнал).
ping_pause() { # файл журнала пингов
	python3 - "$1" <<'PY'
import sys
try:
    lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
except OSError:
    sys.exit(2)
rows = [ln.split() for ln in lines if ln.strip()]
if not rows:
    sys.exit(2)
first_fail = resume = None
for row in rows:
    if len(row) != 2 or not row[1].isdigit():
        continue
    state, ts = row[0], int(row[1])
    if first_fail is None and state == "fail":
        first_fail = ts
    elif first_fail is not None and state == "ok":
        resume = ts
        break
if first_fail is None:
    print(0)
elif resume is None:
    print(-1)
else:
    print(resume - first_fail)
PY
}

# node_state_etag печатает ETag применённого набора из состояния узла. Разбор —
# JSON, а не регулярка: значение записано с экранированными кавычками, и шаблон по
# "etag":"[^"]*" совпадал бы с префиксом всегда, то есть проверка была бы пустой.
node_state_etag() {
	local raw
	raw=$(node_exec cat "$NODE_STATE_FILE") || return 1
	printf '%s\n' "$raw" | python3 -c 'import json, sys
try:
    print(json.load(sys.stdin)["applied"]["etag"])
except Exception:
    sys.exit(2)'
}

# lifecycle проверяет обещания, которые иначе проверяют только временем: пауза при
# смене ключа, эксклюзивность адреса, draining, отказ API, рестарт узла и отзыв не
# дольше 30 с. Каждое измерение печатается числом, а число вне критерия — отказ фазы.
lifecycle() {
	# Access-токен живёт десять минут, а до этой фазы стоят контроль обхода, туннель
	# и dns с лимитом, поэтому входится заново: draining и online идут под админской
	# сессией, а ротация, конфиг и отзыв — под пользовательской. Тело входа
	# собирается из файла пароля, а не из аргументов команды.
	local status server_id device_id old_pub new_pub new_device pause
	json_login user@e2e.test "$RUN_DIR/user.pass" "$RUN_DIR/lifecycle-login.json"
	status=$(http_secret_post POST "$API/api/v1/auth/login" "$RUN_DIR/lifecycle-login.json" \
		"$RUN_DIR/user-session.json") || fail "вход за свежей сессией жизненного цикла не выполнен"
	expect_status "$status" 200 "свежая сессия жизненного цикла получена"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/user.hdr"
	json_login admin@e2e.test "$RUN_DIR/admin.pass" "$RUN_DIR/lifecycle-admin-login.json"
	status=$(http_secret_post POST "$API/api/v1/admin/login" "$RUN_DIR/lifecycle-admin-login.json" \
		"$RUN_DIR/admin-session.json") || fail "вход за свежей админской сессией не выполнен"
	expect_status "$status" 200 "свежая админская сессия получена"
	write_auth_header "$RUN_DIR/admin-session.json" "$RUN_DIR/admin.hdr"

	# Идентификаторы setup живут в его локальных переменных, поэтому читаются из
	# сохранённых ответов.
	server_id=$(jget "$RUN_DIR/server-created.json" id) || fail "идентификатор сервера не прочитан"
	device_id=$(jget "$RUN_DIR/device-created.json" id) || fail "идентификатор устройства не прочитан"

	say "ротация: смена ключа на том же интерфейсе"
	if ! old_pub=$(peer_address_owner '10.99.7.2/32'); then
		fail "не удалось прочитать allowed-ips узла; владение адресом не доказано"
	fi
	[ -n "$old_pub" ] || fail "не найден старый ключ с адресом 10.99.7.2/32"
	# Приватная половина остаётся в клиентском томе, наружу выходит только публичный
	# ключ — по образцу device_register.
	new_pub=$(client_exec sh -c \
		'umask 077; wg genkey > /state/rotate.key; wg pubkey < /state/rotate.key' 2>/dev/null |
		tr -d '\r\n') || fail "клиент не выдал ключ для ротации"
	printf '%s\n' "$new_pub" | grep -Eq '^[A-Za-z0-9+/]{43}=$' ||
		fail "клиент выдал некорректный публичный ключ для ротации"
	python3 - "$new_pub" "$RUN_DIR/rotate.json" <<'PY'
import json, sys
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"public_key": sys.argv[1]}, f)
PY
	chmod 600 "$RUN_DIR/rotate.json"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/rotate.hdr" e2e-rotate-1
	status=$(http_status POST "$API/api/v1/devices/$device_id/keys/rotate" \
		"$RUN_DIR/rotate.json" "$RUN_DIR/rotate-created.json" "$RUN_DIR/rotate.hdr") ||
		fail "запрос ротации ключа не выполнен"
	expect_status "$status" 200 "ротация ключа принята API"
	# Ответ ротации — устройство-потомок со своим идентификатором: с ним сверяется
	# адрес и отзывается доступ дальше, а не с идентификатором предка.
	new_device=$(jget "$RUN_DIR/rotate-created.json" id) ||
		fail "ответ ротации не содержит идентификатора устройства-потомка"
	status=$(http_status GET "$API/api/v1/devices/$new_device/profiles/$server_id/config" \
		- "$RUN_DIR/rotate-config.conf" "$RUN_DIR/user.hdr") ||
		fail "получение конфига потомка ротации не выполнено"
	expect_status "$status" 200 "конфиг потомка ротации получен"
	grep -q '^Address = 10\.99\.7\.2/32$' "$RUN_DIR/rotate-config.conf" ||
		fail "после ротации у нового ключа другой адрес — профиль не унаследован"

	# Наблюдение живёт до стоп-файла: exec -d отвязывает цикл от сессии запуска, а
	# стоп-файл делает остановку детерминированной — никакого pkill по шаблону.
	client_bg 'rm -f /state/ping.log /state/ping.stop
while [ ! -e /state/ping.stop ]; do
  if ping -c1 -W1 -q probe.e2e.test >/dev/null 2>&1; then
    echo "ok $(date +%s)" >> /state/ping.log
  else
    echo "fail $(date +%s)" >> /state/ping.log
  fi
  sleep 1
done'
	sleep 3
	client_exec sh -c 'wg set wg0 private-key /state/rotate.key' >/dev/null ||
		fail "клиент не применил новый приватный ключ"
	# 40 с: худший случай появления нового ключа на узле — 27,5 с (интервал 25 с плюс
	# jitter) и первый handshake.
	sleep 40
	client_exec sh -c 'touch /state/ping.stop' >/dev/null || fail "не удалось остановить цикл пингов"
	sleep 2
	if ! client_exec cat /state/ping.log > "$RUN_DIR/ping.log"; then
		fail "не удалось прочитать журнал пингов клиента: /state/ping.log в контейнере client1"
	fi
	if ! pause=$(ping_pause "$RUN_DIR/ping.log"); then
		fail "пауза при смене ключа не измерена: в журнале пингов нет ни одной строки наблюдения"
	fi
	[ "$pause" != "-1" ] || fail "трафик не вернулся после смены ключа: возврата в журнале пингов нет"
	printf 'ok   измеренная пауза при смене ключа: %s с (разрешение 1 с)\n' "$pause"

	wait_peer_state 60 "новый ключ получил адрес 10.99.7.2/32" peer_holds_address "$new_pub" '10.99.7.2/32'
	local old_allowed
	old_allowed=$(peer_allowed_ips "$old_pub") ||
		fail "не удалось прочитать allowed-ips узла; эксклюзивность адреса не доказана"
	[ "$old_allowed" != "10.99.7.2/32" ] ||
		fail "адрес остался у старого ключа: ядро отдаёт его только одному пиеру"
	ok "адрес 10.99.7.2/32 у активного ключа, старый ключ без адреса"

	wait_peer_state 120 "старый ключ снят после handshake нового" peer_absent "$old_pub"
	ok "старый ключ снят после того, как API увидел handshake нового"

	say "draining: desired пуст, пиеры сняты, возврат в online"
	printf '{"status":"draining","reason":"стенд E2E: draining"}\n' > "$RUN_DIR/draining.json"
	status=$(http_status POST "$API/api/v1/admin/servers/$server_id/maintenance" \
		"$RUN_DIR/draining.json" "$RUN_DIR/draining-resp.json" "$RUN_DIR/admin.hdr") ||
		fail "перевод сервера в draining не выполнен"
	expect_status "$status" 200 "сервер переведён в draining"
	wait_peer_state 60 "все пиеры сняты при draining" peers_none
	ok "draining: узел снял всех пиеров"
	printf '{"status":"online","reason":"стенд E2E: возврат из draining"}\n' > \
		"$RUN_DIR/online-after-draining.json"
	status=$(http_status POST "$API/api/v1/admin/servers/$server_id/maintenance" \
		"$RUN_DIR/online-after-draining.json" "$RUN_DIR/online-after-draining-resp.json" \
		"$RUN_DIR/admin.hdr") || fail "возврат сервера в online не выполнен"
	expect_status "$status" 200 "сервер возвращён в online"
	wait_peer_state 90 "пиер вернулся после online" peers_at_least_one
	wait_for 90 "трафик вернулся после online" proxy_ok
	ok "online: пиер и трафик вернулись"

	say "отказ API: набор сохраняется, трафик не останавливается"
	compose stop api >/dev/null || fail "не удалось остановить API"
	# 35 с: больше худшего интервала опроса (27,5 с), чтобы узел успел записать
	# недоступность desired set в журнал.
	sleep 35
	proxy_ok || fail "трафик остановился, пока API недоступен"
	local count
	if ! count=$(peer_count); then
		fail "не удалось прочитать список пиеров узла; их сохранность при отказе API не доказана"
	fi
	[ "$count" -ge 1 ] || fail "пиеры сняты, пока API недоступен (пиеров: $count)"
	local nodelog
	if ! nodelog=$(compose logs --no-color node1 2>/dev/null); then
		fail "не удалось прочитать журнал контейнера узла; запись о недоступности набора не доказана"
	fi
	printf '%s\n' "$nodelog" | grep -q 'получение желаемого набора не удалось' ||
		fail "узел не записал в журнал недоступность desired set"
	compose start api >/dev/null || fail "не удалось снова запустить API"
	wait_for 90 "API снова отвечает" api_ready
	ok "узел пережил отказ API: пиеров $count, трафик не прерывался"

	say "рестарт узла: интерфейс пуст, набор применяется заново"
	local etag_before etag_after
	etag_before=$(node_state_etag) || fail "не удалось прочитать ETag набора узла до рестарта"
	compose restart node1 >/dev/null || fail "рестарт контейнера узла не выполнен"
	wait_peer_state 120 "пиер вернулся после рестарта узла" peers_at_least_one
	wait_for 90 "трафик вернулся после рестарта узла" proxy_ok
	etag_after=$(node_state_etag) || fail "не удалось прочитать ETag набора узла после рестарта"
	[ -n "$etag_before" ] || fail "ETag до рестарта пуст: состояние узла не прочитано"
	[ "$etag_before" = "$etag_after" ] ||
		fail "ETag изменился ($etag_before → $etag_after): набор на сервере менялся, проверка не та"
	ok "после рестарта узел применил тот же набор, хотя ETag не менялся"

	say "отзыв: профиль снят, пиер уходит, трафик останавливается ≤ 30 с"
	local revoked_at watch first_fail elapsed
	# Отсчёт ведётся от момента запроса отзыва, и отказ, зафиксированный раньше, в
	# измерение не входит: иначе уже упавший туннель выглядел бы мгновенным отзывом.
	revoked_at=$(date +%s)
	watch='rm -f /state/first_fail
while [ ! -e /state/first_fail ]; do
  if ! ping -c1 -W1 -q probe.e2e.test >/dev/null 2>&1; then
    now=$(date +%s)
    if [ "$now" -ge "$start" ]; then echo "$now" > /state/first_fail; fi
  fi
  sleep 1
done'
	client_bg "start=$revoked_at
$watch"
	status=$(http_status DELETE "$API/api/v1/devices/$new_device/profiles/$server_id" \
		- "$RUN_DIR/revoke-resp.json" "$RUN_DIR/user.hdr") ||
		fail "запрос отзыва профиля не выполнен"
	expect_status "$status" 204 "профиль отозван"
	wait_peer_state 120 "пиер снят после отзыва" peers_none
	# 60 с, а не 30: ожидание лишь дожидается записи наблюдения, а критерий
	# «≤ 30 с» проверяет измеренное число. При коротком ожидании отказ дольше 30 с
	# отсекался бы раньше и сам критерий никогда не срабатывал.
	wait_for 60 "ping зафиксировал остановку трафика" client_exec test -s /state/first_fail
	if ! first_fail=$(client_exec cat /state/first_fail | tr -dc '0-9'); then
		fail "не удалось прочитать момент остановки трафика: /state/first_fail в контейнере client1"
	fi
	[ -n "$first_fail" ] || fail "клиент не записал момент остановки трафика в /state/first_fail"
	elapsed=$(( first_fail - revoked_at ))
	printf 'ok   отзыв применился за %s с\n' "$elapsed"
	[ "$elapsed" -ge 0 ] ||
		fail "момент остановки трафика опережает отзыв (${elapsed} с): часы оркестратора и клиента расходятся"
	[ "$elapsed" -le 30 ] || fail "отзыв занял ${elapsed} с, критерий ≤ 30 с"
	ok "отзыв уложился в критерий"
}

cleanup() {
	say "очистка собственного стенда"
	release_self
	compose down -v --remove-orphans >/dev/null ||
		fail "compose down не удался; стенд сохранён"
	remove_network "$HARNESS"
	remove_network "$UPLINK"
	rm -f "$OWNER"
	ok "контейнеры, сети и тома проекта $PROJECT сняты"
}

e2e_down() {
	need docker
	docker info >/dev/null 2>&1 || fail "Docker недоступен"

	local owned=0 label
	if docker container inspect "$RUNNER_NAME" >/dev/null 2>&1; then
		label=$(docker inspect --format '{{ index .Config.Labels "novavpn.e2e.project" }}' \
			"$RUNNER_NAME" 2>/dev/null || true)
		if [ "$label" != "$PROJECT" ]; then
			fail "чужой контейнер $RUNNER_NAME без метки владельца; удаление не выполняется"
		fi
		docker rm -f "$RUNNER_NAME" >/dev/null || fail "не удалось снять $RUNNER_NAME"
		owned=1
	fi

	if [ -f "$OWNER" ]; then
		if grep -q "$PROJECT" "$OWNER"; then
			owned=1
		else
			fail "маркер $OWNER не принадлежит проекту $PROJECT"
		fi
	fi

	local names name
	names=$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
		--format '{{.Names}}' 2>/dev/null || true)
	for name in $names; do
		label=$(docker inspect --format '{{ index .Config.Labels "novavpn.e2e.project" }}' \
			"$name" 2>/dev/null || true)
		if [ "$label" != "$PROJECT" ]; then
			fail "чужой контейнер $name без метки владельца; удаление не выполняется"
		fi
		owned=1
	done

	local nets=0
	for name in "$HARNESS" "$UPLINK"; do
		if docker network inspect "$name" >/dev/null 2>&1; then
			nets=1
		fi
	done
	if [ "$nets" = 1 ] && [ "$owned" != 1 ]; then
		fail "сети проекта существуют, но маркера владения нет; удаление не выполняется"
	fi

	if [ "$owned" = 1 ]; then
		compose down -v --remove-orphans >/dev/null ||
			fail "очистка compose не удалась; стенд сохранён"
		remove_network "$HARNESS"
		remove_network "$UPLINK"
		rm -f "$OWNER"
		ok "ресурсы проекта $PROJECT сняты"
	else
		ok "собственных ресурсов проекта $PROJECT не найдено"
	fi
}

run_main() {
	if [ "$#" -gt 1 ]; then
		printf 'лишние аргументы; допустима одна фаза\n' >&2
		exit 2
	fi
	# Позиционный аргумент принимает all, tunnel, dns, limit, lifecycle и down.
	# Фаза из окружения, если задана, проверяется всегда и принимает all, tunnel,
	# dns, limit и lifecycle: снятие стенда идёт исключительно через make e2e-down
	# с его проверками тома и контейнеров.
	local phase=${1:-}
	if [ -n "${E2E_PHASE:-}" ]; then
		case "$E2E_PHASE" in
		all | tunnel | dns | limit | lifecycle) ;;
		*)
			printf 'недопустимая фаза окружения: %s (допустимы all, tunnel, dns, limit, lifecycle)\n' \
				"${E2E_PHASE}" >&2
			exit 2
			;;
		esac
	fi
	if [ -z "$phase" ]; then
		phase=${E2E_PHASE:-all}
	fi
	case "$phase" in
	all | tunnel | dns | limit | lifecycle | down) ;;
	*)
		printf 'неизвестная фаза: %s (допустимы all, tunnel, dns, limit, lifecycle, down)\n' "$phase" >&2
		exit 2
		;;
	esac

	trap on_exit EXIT
	trap 'exit 130' INT TERM

	# Одиночная фаза всегда идёт полным прогоном: установка, контроль обхода,
	# туннель, сама проверка и очистка. Без контроля обхода и очистки фаза
	# теряла бы и доказательство, и стенд.
	case "$phase" in
	# Фазы all идут в порядке setup, контроль обхода, туннель, DNS, жизненный
	# цикл и лимит. Жизненный цикл впереди лимита, потому что он отзывает
	# профиль устройства, созданного установкой: после отзыва счётчик активных
	# устройств свободен, и лимит создаёт свои без конфликта с профилем.
	all)
		setup
		negative_control
		tunnel
		dns
		lifecycle
		limit
		cleanup
		ok "фаза $phase пройдена"
		;;
	tunnel)
		setup
		negative_control
		tunnel
		cleanup
		ok "фаза $phase пройдена"
		;;
	dns)
		setup
		negative_control
		tunnel
		dns
		cleanup
		ok "фаза $phase пройдена"
		;;
	lifecycle)
		setup
		negative_control
		tunnel
		lifecycle
		cleanup
		ok "фаза $phase пройдена"
		;;
	limit)
		setup
		negative_control
		tunnel
		limit
		cleanup
		ok "фаза $phase пройдена"
		;;
	down)
		e2e_down
		;;
	esac
}

# При source (оффлайн-проверки) скрипт только определяет функции. Проверка через
# return, а не сравнение BASH_SOURCE с $0: источник может быть запущен как
# `bash -c 'source "$0"' скрипт`, и тогда эти значения совпадают.
if ! (return 0 2>/dev/null); then
	run_main "$@"
fi
