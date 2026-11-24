#!/usr/bin/env bash
# Живой E2E клиентского ядра против dev-стенда. Секреты — только stdin и переменные
# процесса: в argv, файлах и выводе их нет. Стенд postgres/redis поднимается, но не
# снимается: это dev-окружение разработчика, а не собственность прогона.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Порты экспортируются, а не только присваиваются: их читают и compose, и make
# migrate-up (через DB_URL_INTEG), а переменные, не попавшие в окружение, make
# заменил бы значениями по умолчанию из своего файла — то есть ушёл бы в чужой
# локальный PostgreSQL на 5432.
export POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
export REDIS_HOST_PORT="${REDIS_HOST_PORT:-6379}"
API_PORT=${CLIENT_E2E_API_PORT:-18080}
BASE_URL="http://127.0.0.1:${API_PORT}"
ENV_FILE=infrastructure/docker/.env.dev
API_CONTAINER=novavpn-client-e2e-api
GO_IMAGE=golang:1.26-alpine
DB_URL="postgres://nova:nova@host.docker.internal:${POSTGRES_HOST_PORT}/novavpn?sslmode=disable"
REDIS_ADDR="host.docker.internal:${REDIS_HOST_PORT}"
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/novavpn-e2e-state.XXXXXX")
OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/novavpn-e2e-out.XXXXXX")
SUFFIX=$(date +%s)
USER_EMAIL="e2e-${SUFFIX}@example.test"
ADMIN_EMAIL="e2e-admin-${SUFFIX}@example.test"
ADMIN_PASSWORD="E2e-a-${SUFFIX}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
USER_PASSWORD="E2e-u-${SUFFIX}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

psql_exec() {
  MSYS_NO_PATHCONV=1 docker compose -f infrastructure/docker/docker-compose.dev.yml \
    exec -T postgres psql -U nova -d novavpn -v ON_ERROR_STOP=1 -c "$1"
}

# Значение одной колонки без заголовка и рамки: счётчики в отчёте прогона —
# числа, а не фрагмент таблицы psql.
psql_value() {
  MSYS_NO_PATHCONV=1 docker compose -f infrastructure/docker/docker-compose.dev.yml \
    exec -T postgres psql -U nova -d novavpn -v ON_ERROR_STOP=1 -tAc "$1"
}

cleanup() {
  set +e
  MSYS_NO_PATHCONV=1 docker rm -f "$API_CONTAINER" >/dev/null 2>&1
  psql_exec "DELETE FROM users WHERE email LIKE 'e2e-%@example.test'" >/dev/null
  psql_exec "DELETE FROM vpn_servers WHERE name LIKE 'e2e-%'" >/dev/null
  psql_exec "DELETE FROM admin_users WHERE email LIKE 'e2e-admin-%@example.test'" >/dev/null
  rm -rf "$STATE_DIR" "$OUT_DIR"
}
trap cleanup EXIT

test -f "$ENV_FILE" || { echo "нет $ENV_FILE: скопируйте .env.dev.example и заполните секрет" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker недоступен" >&2; exit 1; }

echo "== стенд =="
# Стенд поднимается теми же командами, что и цели make up-dev / make migrate-up:
# на хосте без GNU make скрипт обязан работать и сам, иначе прогон превращается
# в «нужен ещё один инструмент поверх Docker и .NET». Порты приходят из
# экспортированных переменных — compose читает их из окружения процесса.
COMPOSE_DEV="docker compose -f infrastructure/docker/docker-compose.dev.yml"
MSYS_NO_PATHCONV=1 $COMPOSE_DEV up -d --wait postgres redis
MSYS_NO_PATHCONV=1 $COMPOSE_DEV exec -T postgres pg_isready -U nova -d novavpn -q
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$PWD:/src" -w /src -v novavpn-gomod:/go/pkg/mod -v novavpn-gocache:/root/.cache/go-build \
  -e GOFLAGS=-mod=mod -e CGO_ENABLED=0 --env-file "$ENV_FILE" \
  --add-host=host.docker.internal:host-gateway \
  -e NOVAVPN_DATABASE_URL="$DB_URL" -e NOVAVPN_REDIS_ADDR="$REDIS_ADDR" \
  "$GO_IMAGE" go run -mod=mod ./services/api/cmd/novavpn-api migrate up

echo "== администратор =="
printf '%s' "$ADMIN_PASSWORD" | MSYS_NO_PATHCONV=1 docker run --rm -i \
  -v "$PWD:/src" -w /src -v novavpn-gomod:/go/pkg/mod -v novavpn-gocache:/root/.cache/go-build \
  -e GOFLAGS=-mod=mod -e CGO_ENABLED=0 --env-file "$ENV_FILE" \
  --add-host=host.docker.internal:host-gateway \
  -e NOVAVPN_DATABASE_URL="$DB_URL" -e NOVAVPN_REDIS_ADDR="$REDIS_ADDR" \
  "$GO_IMAGE" go run -mod=mod ./services/api/cmd/novavpn-api admin create "$ADMIN_EMAIL"

echo "== API =="
MSYS_NO_PATHCONV=1 docker run -d --name "$API_CONTAINER" \
  -v "$PWD:/src" -w /src -v novavpn-gomod:/go/pkg/mod -v novavpn-gocache:/root/.cache/go-build \
  -e GOFLAGS=-mod=mod -e CGO_ENABLED=0 --env-file "$ENV_FILE" \
  --add-host=host.docker.internal:host-gateway -p "${API_PORT}:8080" \
  -e NOVAVPN_LISTEN_ADDR=:8080 -e NOVAVPN_DATABASE_URL="$DB_URL" -e NOVAVPN_REDIS_ADDR="$REDIS_ADDR" \
  "$GO_IMAGE" go run -mod=mod ./services/api/cmd/novavpn-api serve >/dev/null

ready=0
for _ in $(seq 1 180); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/v1/servers" || true)
  if [ "$code" = "401" ]; then ready=1; break; fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "API не поднялся; журнал контейнера:" >&2
  MSYS_NO_PATHCONV=1 docker logs "$API_CONTAINER" >&2 || true
  exit 1
fi

echo "== фаза 1: администратор, сервер, регистрация =="
prepare_out=$(printf '%s\n%s\n' "$ADMIN_PASSWORD" "$USER_PASSWORD" \
  | dotnet run --project client/tests/NovaVpn.Client.E2E -c Debug -- \
      prepare "$BASE_URL" "$ADMIN_EMAIL" "$USER_EMAIL" "$STATE_DIR")
echo "$prepare_out"
USER_ID=$(printf '%s\n' "$prepare_out" | sed -n 's/^E2E_USER=//p')
SERVER_ID=$(printf '%s\n' "$prepare_out" | sed -n 's/^E2E_SERVER=//p')
if [ -z "$USER_ID" ] || [ -z "$SERVER_ID" ]; then
  echo "не получены идентификаторы пользователя или сервера" >&2
  exit 1
fi
printf '%s\n' "$prepare_out" | grep -qx 'E2E PREPARE OK'

# Вставки в subscriptions здесь нет: регистрация сама выдаёт план internal-default
# (router.go:60, internal/auth/handlers.go:131, internal/entitlements/entitlements.go:76).
# E2E_USER остаётся только проверкой масштаба прогона и в SQL не попадает.

echo "== фаза 2: устройство, выдача, экспорт, отзыв =="
run_out=$(printf '%s\n' "$USER_PASSWORD" \
  | dotnet run --project client/tests/NovaVpn.Client.E2E -c Debug -- \
      run "$BASE_URL" "$USER_EMAIL" "$SERVER_ID" "$STATE_DIR" "$OUT_DIR")
echo "$run_out"
printf '%s\n' "$run_out" | grep -qx 'E2E OK'

echo "== создано за прогон =="
users_made=$(psql_value "SELECT count(*) FROM users WHERE email LIKE 'e2e-%@example.test'" | tr -d ' ')
servers_made=$(psql_value "SELECT count(*) FROM vpn_servers WHERE name LIKE 'e2e-%'" | tr -d ' ')
echo "users=$users_made servers=$servers_made"
