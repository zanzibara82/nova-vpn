#!/usr/bin/env bash
# Оркестратор стенда E2E. Скрипт исполняется внутри одноразового контейнера
# novavpn-e2e-runner, которому смонтированы исходники только для чтения, Docker
# socket и защищённый том novavpn-e2e-control в /state.
#
# Фазы: all и tunnel выполняют установку и проверки туннеля, down снимает только
# собственный стенд этого проекта. Неизвестная фаза отвергается до любых обращений
# к Docker. На успехе стенд снимается, на отказе остаётся для разбора; снять его
# можно только целью make e2e-down.
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
	docker network connect "$HARNESS" "$(self_id)" >/dev/null ||
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
node_peer_present() { # публичный ключ клиента
	node_exec wg show wg0 peers | grep -qx "$1"
}
probe_healthy_from_node() {
	[ "$(node_exec wget -qO- -T 3 http://172.31.98.3:8080/healthz 2>/dev/null | tr -d '\r\n')" = "ok" ]
}

preflight() {
	need docker
	docker info >/dev/null 2>&1 || fail "Docker недоступен"

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
	status=$(http_status POST "$API/api/v1/admin/login" "$RUN_DIR/admin-login.json" \
		"$RUN_DIR/admin-session.json" -) || fail "вход администратора не выполнен"
	expect_status "$status" 200 "администратор вошёл"
	write_auth_header "$RUN_DIR/admin-session.json" "$RUN_DIR/admin.hdr"
	rm -f "$RUN_DIR/admin-login.json"

	local out node_pub
	out=$(node_run init 2>/dev/null) || fail "init узла не выполнен"
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
	status=$(http_status POST "$API/api/v1/auth/register" "$RUN_DIR/register.json" \
		"$RUN_DIR/user-session.json" -) || fail "регистрация пользователя не выполнена"
	expect_status "$status" 201 "пользователь зарегистрирован"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/user.hdr"
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/device.hdr" e2e-device-1
	write_auth_header "$RUN_DIR/user-session.json" "$RUN_DIR/profile.hdr" e2e-profile-1
	rm -f "$RUN_DIR/register.json"

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
	wait_for 90 "узел получил пиера клиента после опроса API" \
		node_peer_present "$client_pub"
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
	egress=$(client_exec curl -fsS --max-time 10 http://probe.e2e.test:8080/whoami | tr -d '\r\n') ||
		fail "HTTP к probe через имя не выполнена"
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
	local phase=${1:-${E2E_PHASE:-all}}
	case "$phase" in
	all | tunnel | down) ;;
	*)
		printf 'неизвестная фаза: %s (допустимы all, tunnel, down)\n' "$phase" >&2
		exit 2
		;;
	esac

	trap on_exit EXIT
	trap 'exit 130' INT TERM

	case "$phase" in
	all | tunnel)
		setup
		negative_control
		tunnel
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
