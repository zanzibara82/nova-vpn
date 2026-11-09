#!/usr/bin/env bash
# Восстановление дампа в одноразовую базу: проверяется не «дамп создан», а «из него
# поднимается схема с данными». Формат — custom (pg_dump -Fc).
set -euo pipefail
export MSYS_NO_PATHCONV=1
dump=${1:?укажите путь к дампу}
[ -s "$dump" ] || { printf 'дамп не найден или пуст: %s\n' "$dump" >&2; exit 1; }

name="novavpn-verify-$$"
plain=$(mktemp)
trap 'rm -f "$plain"; docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

# Дамп в custom-формате сжат, и grep по файлу нашёл бы ноль совпадений при любом
# содержимом. Поэтому он распаковывается в SQL-поток тем же pg_restore, а не читается
# как двоичный файл: проверка обязана уметь упасть, иначе это не проверка. Сбой самого
# pg_restore не глушится внутри `if` — он обязан остановить скрипт.
docker run --rm -i postgres:17 pg_restore -f - < "$dump" > "$plain"
if grep -aqE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "$plain"; then
  printf 'в дампе найдены приватные ключи: дамп не годится\n' >&2
  exit 1
fi

# POSTGRES_PASSWORD=verify — пароль одноразовой локальной контейнерной базы, которую
# скрипт создаёт и удавляет сам; это проверка восстановления дампа, а не секрет продукта.
docker run -d --rm --name "$name" -e POSTGRES_PASSWORD=verify -e POSTGRES_DB=verify \
  postgres:17 >/dev/null
# Ожидание базы с явным отказом: молчаливое истечение цикла уронило бы скрипт уже на
# pg_restore и psql текстом контейнера, и по нему нельзя было бы отличить «база не
# поднялась за 60 попыток» от «в дампе ошибка схемы».
ready=no
for _ in $(seq 1 60); do
  if docker exec "$name" pg_isready -U postgres -q >/dev/null 2>&1; then ready=yes; break; fi
  sleep 1
done
if [ "$ready" != yes ]; then
  printf 'база не поднялась за 60 попыток: pg_isready не ответил, дамп не восстановлен\n' >&2
  exit 1
fi
docker exec -i "$name" pg_restore -U postgres -d verify --no-owner --exit-on-error < "$dump"
users=$(docker exec "$name" psql -U postgres -d verify -tAc 'select count(*) from users')
servers=$(docker exec "$name" psql -U postgres -d verify -tAc 'select count(*) from vpn_servers')
printf 'ok   дамп восстановлен: users=%s vpn_servers=%s\n' "$users" "$servers"
