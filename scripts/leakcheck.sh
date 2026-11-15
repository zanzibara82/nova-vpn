#!/usr/bin/env bash
# Ищет в отслеживаемых файлах то, чего там быть не должно: приватные ключи,
# значения секретов, флаг отключения TLS и рабочие env-файлы.
set -euo pipefail
FAIL=0
ok()  { printf 'ok   %s\n' "$*"; }
bad() { FAIL=1; printf 'FAIL %s\n' "$*" >&2; }

# Документы цитируют сами маркеры (runbook'и и docs/testing-status.md пишут, что
# именно ловит проверка), поэтому каталог docs не входит в поиск ключей: проверка
# обязана ловить ключ в конфиге, скрипте или дампе, а не упоминание в прозе.
keys=$(git grep -nIE -- 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' -- . ':!docs/**' || true)
if [ -n "$keys" ]; then printf '%s\n' "$keys"; bad "приватный ключ в отслеживаемых файлах"; else ok "PEM-ключей нет"; fi

wg=$(git grep -nIE -- '^[[:space:]]*PrivateKey[[:space:]]*=' -- . || true)
if [ -n "$wg" ]; then printf '%s\n' "$wg"; bad "WireGuard PrivateKey в файле репозитория"; else ok "PrivateKey в конфигах нет"; fi

envs=$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -vE 'example$' || true)
if [ -n "$envs" ]; then printf '%s\n' "$envs"; bad "рабочий env-файл под контролем версий"; else ok "рабочих env-файлов нет"; fi

# Граница [A-Za-z0-9_+/-]{8,} обязательна: без неё образец ловит строку
# scripts/e2e.sh, где значение секрета собирается склейкой python-строки, и
# проверка падала бы на чистом дереве.
jwt=$(git grep -nIE -- 'NOVAVPN_JWT_SECRET=[A-Za-z0-9_+/-]{8,}' -- . ':!*.example' ':!docs/**' || true)
if [ -n "$jwt" ]; then printf '%s\n' "$jwt"; bad "значение JWT-секрета в репозитории"; else ok "значений JWT-секрета нет"; fi

# Область поиска ограничена прод-конфигурацией: в dev и на стенде флаг легален и
# живёт в compose-файлах, а ловить здесь нечего, кроме прод-пути.
insecure=$(git grep -nIE -- 'NOVAVPN_NODE_ALLOW_INSECURE_API' -- infrastructure/ansible infrastructure/docker/Caddyfile.example || true)
if [ -n "$insecure" ]; then printf '%s\n' "$insecure"; bad "флаг отключения TLS в прод-конфигурации"; else ok "флага отключения TLS в проде нет"; fi

if [ "$FAIL" -ne 0 ]; then printf '\n%s\n' "проверка не пройдена" >&2; exit 1; fi
ok "утечек не найдено"
