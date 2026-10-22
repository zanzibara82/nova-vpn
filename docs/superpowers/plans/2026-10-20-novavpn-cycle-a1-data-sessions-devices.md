# NovaVPN — цикл A-1: схема, сессии, устройства. План имплементации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Рабочий control plane NovaVPN, который держит схему цикла A, выдаёт и отзывает сессии
(password + access JWT + refresh с ротацией и детектом переиспользования) и регистрирует
устройства по публичному ключу с жёстким лимитом устройств по тарифу.

**Architecture:** Модульный монолит `novavpn-api` (один Go-процесс, модули `internal/*`) +
PostgreSQL 17 как единственный источник истины + Redis 7 для rate limit и denylist
access-токенов. Миграции — артефакты `migrations/*.sql`, вшитые в бинарник через `embed` и
навигаемые `golang-migrate`; запросы — `sqlc`. Обработка HTTP идёт через `internal/httpx`
(convelope ошибок, request id, rate limit, идемпотентность), бизнес-правила — через
`internal/{auth,devices,entitlements}`. Привилегированная сетевая часть (узел, provisioner,
E2E-стенд) в этот план не входит — см. разбивку ниже.

**Tech Stack:** Go (статическая сборка, `CGO_ENABLED=0`), pgx/v5 + sqlc, golang-migrate/v4,
golang-jwt/jwt/v5, redis/go-redis/v9, `golang.org/x/crypto/argon2`, testcontainers не
используется — интеграционные тесты идут против compose-стэка с фиксированным
`NOVAVPN_DATABASE_URL`.

**Spec:** [docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md](../specs/2026-10-20-novavpn-cycle-a-access-core-design.md)
— разделы 1, 2, 3, 5, 6, 9.1, 9.2 в первую очередь.
Смежные: карта ADR — раздел 14 спецификации; ADR-003 (сессии) отдельного файла пока не
имеет и живёт только строкой в этой карте, а из файлов ADR в репозитории есть
[ADR-004](../../adr/0004-wireguard-peer-apply.md) (его статус — в
[индексе](../../adr/README.md)). Файла с текстом технических требований заказчика в
репозитории нет, но спецификация переносит нужные пункты своими разделами (2, 5.2, 6, 9, 13),
и номера «ТЗ §…»
в этом плане — те же, что цитирует спецификация.

---

## Разбивка цикла A на планы

Спецификация покрывает три процесса с разными границами доверия и разными способами
проверки. Один план на всё — это 35+ задач, где задачи 20-й страницы ссылаются на сигнатуры,
которых ещё нет. Поэтому:

| План | Граница | Готовый, тестируемый результат |
|---|---|---|
| **A-1 (этот)** | Схема + сессии + устройства | `POST /auth/*`, `GET /me`, `POST/GET /devices` против реального PostgreSQL и Redis; миграции `up→down→up`; лимит устройств как ограничение БД |
| A-2 | Выдача/отзыв доступа + контракт с узлом | Аллокация адресов, desired set, `/internal/v1/*`, конфиг `[Interface]/[Peer]`; сходимость контракта проверяется fake-узлом по настоящему HTTP |
| A-3 | Узел и стенд | `novavpn-node-agent` с настоящим netlink diff-apply (ADR-004), compose-harness с привилегированным узлом, E2E с инвариантом «неизменённый пиер не переподключается», Ansible-роль, CI, `docs/testing-status.md` |

A-1 ничего не знает про netlink и не создаёт для него заглушек (ТЗ §19.3). Критерии приёмки
спецификации §1.3, которые закрывает A-1: **1** (сессии), **2** (устройства по публичному
ключу, приватного ключа нет в HTTP), **5** (лимит устройств → `409 device_limit_reached`),
**9** (миграции `up→down→up`). Критерии 3, 4, 6 (wire-часть), 7, 8, 10, 11 — в A-2/A-3.

---

## Global Constraints

Значения дословно из спецификации и ТЗ; каждая задача неявно включает этот раздел.

- Go: `golang:1.25-alpine`; если тег недоступен при первой сборке — ближайший доступный
  stable, зафиксировать **и** в `go.mod`, **и** в `Makefile`/`Dockerfile` (спецификация §11).
  PostgreSQL 17, Redis 7.x.
- На хосте нет Go, PostgreSQL, Terraform и Ansible (спецификация, строка окружения).
  **Любая** команда сборки/теста идёт через `make` → `docker run`. Прямой `go test` на хосте
  не является проверкой.
- Префиксы маршрутов: `/api/v1` (публичный), `/internal/v1` (узловой, в A-2).
- Единый формат ошибки: `{"error":{"code":"…","message":"…","details":{…},"request_id":"…"}}`;
  коды стабильны, `request_id` совпадает с journal entry (спецификация §5.2).
- Access-токен: JWT, TTL **10 минут**, обязательный `jti`. Refresh: непрозрачный токен,
  ротация, повторное использование → отзыв **всей семьи** (спецификация §5.2–5.3).
- Пароли: **argon2id**, никакого самописного крипто (ТЗ §19.6). Хэш — в формате PHC-строки.
- Rate limiting публичных маршрутов: Redis token bucket, при отказе Redis — **fail-open** с
  записью в журнал (спецификация §4.3).
- Неизмеренные поля каталога (`latency_ms`, `load`, `availability`) — `null`, никогда `0`
  (спецификация §13.4). В A-1 это касается только ответов `GET /devices` и будущих каталожных
  маршрутов; чисел «по умолчанию» не выдумываем.
- В HTTP-ответах, фикстурах и журналах не появляются: приватные ключи, пароли, токены,
  заголовки авторизации, query-строки с секретами (ТЗ §10, §15).
- В перенесённых частях (B–F) не создаётся ни заглушек, ни пустых директорий (спецификация
  §1.2, ТЗ §19.3). Невыполненный тест помечается `not-run`, а не зелёным (ТЗ §14).
- Файлы — LF (`.gitattributes` уже в репозитории); `.env.example` без значений секретов.
- Коммиты, пока не задана личность пользователя:
  `git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" commit …`.
- Путь Go-модуля — `github.com/novavpn/novavpn`. Если фейк будет на другом хосте, заменить
  **до** первого коммита этого плана: позже это переименование всего репозитория.

---

## Карта файлов A-1

```
go.mod  go.sum  Makefile  .dockerignore                     # тулчейн в контейнерах
migrations/embed.go                                         # package migrations, //go:embed *.sql
migrations/0001_identity.up.sql|.down.sql                   # users, refresh_token_families, devices
migrations/0002_network.up.sql|.down.sql                    # server_locations, vpn_servers, node_credentials,
                                                            #   vpn_profiles, tunnel_addresses
migrations/0003_plans_telemetry_audit.up.sql|.down.sql      # subscription_plans, subscriptions, server_health,
                                                            #   connection_events, device_day_traffic, admin_users,
                                                            #   admin_audit_logs, idempotency_keys, bootstrap_tokens
sqlc.yaml
internal/db/query/{identity,plans,devices}.sql              # человек пишет запросы
internal/db/{models.go,identity.sql.go,plans.sql.go,…}      # генерирует sqlc
internal/db/migrate/migrate.go                              # embed → golang-migrate
internal/config/{config.go,config_test.go}
internal/httpx/{envelope.go,requestid.go,json.go,ratelimit.go,idempotency.go,idempotency_pg.go,
                context.go,decorators.go,mux.go,logging.go}                # задача 15 — decorators, 18 — mux/logging
internal/httpx/{*_test.go}
internal/auth/{password.go,token.go,denylist.go,refresh.go,login_guard.go,middleware.go,handlers.go}
internal/auth/{*_test.go}
internal/entitlements/{entitlements.go,entitlements_test.go}
internal/devices/{key.go,service.go,handlers.go,errors.go,key_test.go}
services/api/cmd/novavpn-api/main.go                        # подкоманды serve | migrate
services/api/router.go                                      # сборка http.Handler из модулей (задача 18)
infrastructure/docker/docker-compose.dev.yml                # postgres:17 + redis:7 (узел/клиент/probe — A-3)
infrastructure/docker/.env.dev.example
tests/integration/{helpers_test.go,migrations_test.go,idempotency_test.go,refresh_test.go,
                   entitlements_test.go,devices_test.go,auth_flow_test.go,router_test.go,
                   contract_test.go}
docs/testing-status.md
```

Ответственность модулей (спецификация §3): `config` — только чтение окружения и валидация;
`httpx` — транспортные сквозные требования, ничего не знает о VPN; `auth` — пароль, токены,
семьи refresh; `devices` — публичные ключи и лимит; `entitlements` — план → права;
`db` — схема и запросы. `internal/httpx` не импортирует `internal/auth` (иначе возникнет
цикл: auth хочет envelope, httpx не должен знать про auth).

---

## Что план нашёл в спецификации (правки, а не тихие расхождения)

Две таблицы, требуемые §5.2 и §4.1, отсутствуют в перечне §6. Они добавлены в миграции 0003,
и это надо внести в спецификацию правкой §6 (задача 4, шаг 5), чтобы схему и документ не
разъезжались:

1. `idempotency_keys` — нужна для `Idempotency-Key` (§5.2), без неё идемпотентность
   негде хранить.
2. `bootstrap_tokens` — нужна для `POST /internal/v1/nodes/enroll` (§4.1): одноразовый
   bootstrap-токен, выдаваемый админом.

Ещё одно уточнение: §5.2 знает только `409 idempotency_key_conflict`, но повтор запроса во
время выполнения первого — другой случай. Введён код `409 idempotency_key_in_progress`
(задача 9), а в перечень кодов §5.2 он попадает правкой спецификации в задаче 16, шаг 5 —
контракт и §5.2 обязаны описывать один набор кодов: иначе расхождение заметит только
клиент по жалобе, а не автор плана.

---

## Задачи

### Task 1: Контейнерный тулчейн, конфигурация и скелет API-процесса

**Files:**
- Create: `go.mod`, `Makefile`, `.dockerignore`, `internal/config/config.go`,
  `internal/config/config_test.go`, `services/api/cmd/novavpn-api/main.go`

**Interfaces:**
- Consumes: ничего (первая задача).
- Produces: `config.Config`, поля: `Env string`, `ListenAddr string`, `DatabaseURL string`,
  `RedisAddr string`, `JWTSecret []byte`, `AccessTTL time.Duration`,
  `RefreshTTL time.Duration`, `AllowInsecureAPI bool`;
  `config.Load(getenv func(string) string) (Config, error)`;
  константы `config.EnvDev`, `config.EnvProd`; make-цели `unit`, `vet`, `integration`,
  `migrate-up`, `migrate-down`, `run-dev`, `sqlc-generate`, `up-dev`, `down-dev`.

- [ ] **Step 1: Написать падающий тест на валидацию конфигурации**

`internal/config/config_test.go`:

```go
package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func valid() map[string]string {
	return map[string]string{
		"NOVAVPN_ENV":          "dev",
		"NOVAVPN_DATABASE_URL": "postgres://nova:nova@localhost:5432/nova?sslmode=disable",
		"NOVAVPN_REDIS_ADDR":   "localhost:6379",
		"NOVAVPN_JWT_SECRET":   "dj2u6QzU1TgZ0yQxT1dHQ0h6T0ZObDNnNXE3czE1VDZlcTV6M3E9", // 32 б, base64
	}
}

func TestLoadAcceptsDevDefaults(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AccessTTL != 10*time.Minute {
		t.Errorf("AccessTTL = %v, want 10m", c.AccessTTL)
	}
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
}

func TestInsecureAPIRefusedOutsideDev(t *testing.T) {
	m := valid()
	m["NOVAVPN_ENV"] = "prod"
	m["NOVAVPN_ALLOW_INSECURE_API"] = "1"
	_, err := Load(env(m))
	if err == nil || !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("prod+insecure must be refused, got %v", err)
	}
}

func TestJWTSecretMustBe32Bytes(t *testing.T) {
	m := valid()
	m["NOVAVPN_JWT_SECRET"] = "c2hvcnQ=" // 5 байт
	if _, err := Load(env(m)); err == nil {
		t.Fatal("short JWT secret accepted")
	}
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `make unit`
Expected: FAIL — `undefined: Load`, `unknown field Env` (пакета ещё нет).

- [ ] **Step 3: Реализовать `internal/config/config.go`**

```go
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	EnvDev  = "dev"
	EnvProd = "prod"
)

type Config struct {
	Env        string
	ListenAddr string
	DatabaseURL string
	RedisAddr  string
	JWTSecret  []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	// AllowInsecureAPI существует для dev-harness (спецификация §4.4) и жёстко
	// отказывается вне dev — это проверка ТЗ §19.8, а не настройка.
	AllowInsecureAPI bool
}

func Load(getenv func(string) string) (Config, error) {
	c := Config{
		Env:         getenv("NOVAVPN_ENV"),
		ListenAddr:  getenv("NOVAVPN_LISTEN_ADDR"),
		DatabaseURL: getenv("NOVAVPN_DATABASE_URL"),
		RedisAddr:   getenv("NOVAVPN_REDIS_ADDR"),
		AccessTTL:   10 * time.Minute,
		RefreshTTL:  30 * 24 * time.Hour,
	}
	if c.Env == "" {
		return c, errors.New("NOVAVPN_ENV must be dev or prod")
	}
	if c.Env != EnvDev && c.Env != EnvProd {
		return c, fmt.Errorf("NOVAVPN_ENV = %q, want dev|prod", c.Env)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.DatabaseURL == "" {
		return c, errors.New("NOVAVPN_DATABASE_URL is required")
	}
	if c.RedisAddr == "" {
		return c, errors.New("NOVAVPN_REDIS_ADDR is required")
	}
	secret, err := base64.StdEncoding.DecodeString(getenv("NOVAVPN_JWT_SECRET"))
	if err != nil {
		return c, fmt.Errorf("NOVAVPN_JWT_SECRET: %w", err)
	}
	if len(secret) < 32 {
		return c, fmt.Errorf("NOVAVPN_JWT_SECRET must decode to >= 32 bytes, got %d", len(secret))
	}
	c.JWTSecret = secret
	if v := getenv("NOVAVPN_ACCESS_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > 30*time.Minute {
			return c, fmt.Errorf("NOVAVPN_ACCESS_TTL = %q: want 1s..30m", v)
		}
		c.AccessTTL = d
	}
	if v := getenv("NOVAVPN_REFRESH_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("NOVAVPN_REFRESH_TTL = %q", v)
		}
		c.RefreshTTL = d
	}
	insecure, err := strconv.ParseBool(orDefault(getenv("NOVAVPN_ALLOW_INSECURE_API"), "false"))
	if err != nil {
		return c, fmt.Errorf("NOVAVPN_ALLOW_INSECURE_API: %w", err)
	}
	if insecure && c.Env != EnvDev {
		return c, errors.New("insecure API transport is refused outside dev: TLS verification is not optional in prod (NOVAVPN_ALLOW_INSECURE_API)")
	}
	c.AllowInsecureAPI = insecure
	return c, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
```

Слово `insecure` в тексте отказа написано строчными намеренно: шаг 1 проверяет
`strings.Contains(err.Error(), "insecure")`, а это сравнение регистрозависимо, и одно только
имя переменной `NOVAVPN_ALLOW_INSECURE_API` его не удовлетворяет (заглавные к строчным не
равны). Имя переменной оставлено в конце сообщения, чтобы по тексту ошибки было понятно,
какую именно настройку отклонили.

- [ ] **Step 4: Makefile — единственный способ собрать и протестировать**

`Makefile` (хост Windows + Git Bash; пути внутри контейнера абсолютные, поэтому
`MSYS_NO_PATHCONV=1` обязателен):

```make
GO_IMAGE ?= golang:1.25-alpine
DB_IMAGE ?= postgres:17
REDIS_IMAGE ?= redis:7

# Хостовы порты dev-стека. Занятые по умолчанию — не гипотеза: на этой машине 5432
# держит служба postgresql-x64-17, а 6379 — локальный redis, и connect с тестового
# контейнера уходит в чужой сервер (SASL-ошибка на несуществующую роль). Порты
# переопределяют одной строкой: make integration POSTGRES_HOST_PORT=5433.
POSTGRES_HOST_PORT ?= 5432
REDIS_HOST_PORT ?= 6379
# Compose читает порты из окружения процесса, поэтому их передают именно ему.
DEV_ENV = POSTGRES_HOST_PORT=$(POSTGRES_HOST_PORT) REDIS_HOST_PORT=$(REDIS_HOST_PORT)
COMPOSE   := docker compose -f infrastructure/docker/docker-compose.dev.yml
ENV_FILE  := infrastructure/docker/.env.dev

# Интеграционные тесты и миграции бегут внутри контейнера, а localhost внутри
# контейнера — это сам контейнер, а не хост. Поэтому адреса для них задаются
# отдельно: .env.dev описывает запуск бинарника с хоста. Флаг -e важнее
# --env-file, так что значения из файла не перебивают эти.
# host-gateway нужен Linux-движку; Docker Desktop резолвит имя и без него.
DB_URL_INTEG     := postgres://nova:nova@host.docker.internal:$(POSTGRES_HOST_PORT)/novavpn?sslmode=disable
REDIS_ADDR_INTEG := host.docker.internal:$(REDIS_HOST_PORT)

DOCKER_FLAGS := -v "$(CURDIR):/src" -w /src \
	-v novavpn-gomod:/go/pkg/mod -v novavpn-gocache:/root/.cache/go-build \
	-e GOFLAGS=-mod=mod -e CGO_ENABLED=0

docker-go = MSYS_NO_PATHCONV=1 docker run --rm $(DOCKER_FLAGS) $(GO_IMAGE) go

docker-go-int = MSYS_NO_PATHCONV=1 docker run --rm $(DOCKER_FLAGS) \
	--add-host=host.docker.internal:host-gateway \
	-e NOVAVPN_DATABASE_URL=$(DB_URL_INTEG) \
	-e NOVAVPN_REDIS_ADDR=$(REDIS_ADDR_INTEG) \
	$(GO_IMAGE) go

# Бинарник требует NOVAVPN_ENV / NOVAVPN_JWT_SECRET: они читаются из .env.dev,
# а не из Makefile — секрет в командной строке попал бы в историю shell'а и
# в описания процессов, а захардкоженный в Makefile — в репозиторий (ТЗ §15).
docker-go-app = MSYS_NO_PATHCONV=1 docker run --rm $(DOCKER_FLAGS) \
	--env-file $(ENV_FILE) \
	--add-host=host.docker.internal:host-gateway \
	-e NOVAVPN_DATABASE_URL=$(DB_URL_INTEG) \
	-e NOVAVPN_REDIS_ADDR=$(REDIS_ADDR_INTEG) \
	$(GO_IMAGE) go

.PHONY: unit vet integration mod sqlc-generate migrate-up migrate-down run-dev up-dev down-dev
unit:
	$(docker-go) test -count=1 ./...

# Без тегов: интеграционные тесты компилируются и проверяются целью integration,
# а здесь важна обычная сборка пакетов.
vet:
	$(docker-go) vet ./...

mod:
	$(docker-go) mod tidy

up-dev:
	# --wait обязателен: без него `up -d` возвращается сразу, а `pg_isready` в следующей
	# строке застает инициализацию кластера и уходит с кодом 2 (проверено на этом стеке).
	$(DEV_ENV) $(COMPOSE) up -d --wait postgres redis
	$(DEV_ENV) $(COMPOSE) exec -T postgres pg_isready -U nova -d novavpn -q

down-dev:
	$(COMPOSE) down -v

# ./... а не ./tests/integration/...: тегированные тесты живут и внутри пакетов
# (internal/httpx — лимитер задачи 8), цель обязана гнать все.
integration:
	$(docker-go-int) test -count=1 -tags=integration ./...

migrate-up: $(ENV_FILE)
	$(docker-go-app) run -mod=mod ./services/api/cmd/novavpn-api migrate up

migrate-down: $(ENV_FILE)
	$(docker-go-app) run -mod=mod ./services/api/cmd/novavpn-api migrate all

# Ручная дымовая проверка (задача 18): -it нужен, чтобы Ctrl-C дошёл до процесса
# и сработал srv.Shutdown; -p — чтобы curl с хоста видел порт. listen-адрес
# переопределяется на :8080, потому что внутри контейнера адрес слушает именно
# контейнерный интерфейс.
run-dev: $(ENV_FILE)
	@MSYS_NO_PATHCONV=1 docker run --rm -it $(DOCKER_FLAGS) \
		--env-file $(ENV_FILE) \
		--add-host=host.docker.internal:host-gateway -p 8080:8080 \
		-e NOVAVPN_LISTEN_ADDR=:8080 \
		-e NOVAVPN_DATABASE_URL=$(DB_URL_INTEG) \
		-e NOVAVPN_REDIS_ADDR=$(REDIS_ADDR_INTEG) $(GO_IMAGE) \
		run -mod=mod ./services/api/cmd/novavpn-api serve

# Файл создаёт разработчик один раз; цель не генерирует секрет молча.
$(ENV_FILE):
	@echo "cp infrastructure/docker/.env.dev.example $(ENV_FILE) && fill NOVAVPN_JWT_SECRET" >&2
	@exit 1

sqlc-generate:
	docker run --rm -v "$(CURDIR):/src" -w /src sqlc/sqlc:1.27.0 generate

```

`go.mod` создаётся одной строкой внутри контейнера (на хосте Go нет):

```
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/src" -w /src -e CGO_ENABLED=0 golang:1.25-alpine \
  go mod init github.com/novavpn/novavpn
```

`.dockerignore`: `.git`, `.scratch`, `out`, `node_modules`, `*.log`.

- [ ] **Step 5: Скелет `services/api/cmd/novavpn-api/main.go`**

Только то, что существует в A-1: разбор подкоманды `serve` (HTTP-сервер со
`GET /debug/health`) и подкоманда `migrate`. Здесь `migrate` — заглушка
`errors.New("migrations land in task 5")`: она падает громко, а не молча делает вид.
Реализацию (`up|all|version` поверх пакета `internal/db/migrate`, который появляется в
задаче 5) пишет задача 5, там же в этот `switch` вставляется ветка; задача 18 к
`migrate` не притрагивается.

```go
package main

import (
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/novavpn/novavpn/internal/config"
)

func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string) error {
	fs := flag.NewFlagSet("novavpn-api", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := fs.Arg(0)
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	switch cmd {
	case "serve":
		return serve(cfg)
	case "migrate":
		return errors.New("migrations land in task 5")
	case "":
		return errors.New("usage: novavpn-api serve|migrate <up|all>")
	default:
		return errors.New("usage: novavpn-api serve|migrate <up|all>")
	}
}

func serve(cfg config.Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	slog.Info("listening", "addr", cfg.ListenAddr, "env", cfg.Env)
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 5e9}
	return srv.ListenAndServe()
}
```

- [ ] **Step 6: Прогнать тесты и коммит**

Run: `make unit`
Expected: PASS (3 теста `internal/config`).

```bash
git add go.mod Makefile .dockerignore internal/config services/api
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "build: контейнерный Go-тулчейн и конфигурация API с отказом от insecure TLS вне dev"
```

---

### Task 2: Миграция 0001 — пользователи, refresh-семьи, устройства

**Files:**
- Create: `migrations/0001_identity.up.sql`, `migrations/0001_identity.down.sql`

**Interfaces:**
- Consumes: PostgreSQL 17 (образ `postgres:17`, пользователь `nova`, БД `novavpn`).
- Produces: таблицы `users`, `refresh_token_families`, `devices`; типы `user_status`,
  `device_platform`. Имена колонок — источник имён для sqlc-моделей (задача 6).

- [ ] **Step 1: Написать up-миграцию**

`migrations/0001_identity.up.sql`:

```sql
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_status AS ENUM ('active', 'locked', 'deleted');
CREATE TYPE device_platform AS ENUM ('android', 'ios', 'windows', 'macos', 'linux', 'other');

CREATE TABLE users (
    id                uuid PRIMARY KEY,
    email             citext NOT NULL UNIQUE,
    password_hash     text   NOT NULL,
    display_name      text,
    status            user_status NOT NULL DEFAULT 'active',
    locked_reason     text,
    email_verified_at timestamptz,
    locale            text   NOT NULL DEFAULT 'en',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    -- Блокировка без причины невозможна: ТЗ §9 требует, чтобы админ указывал причину.
    CONSTRAINT users_lock_reason CHECK (status <> 'locked' OR locked_reason IS NOT NULL),
    -- Самописных форматов хэша быть не может: только argon2id в PHC-нотации.
    CONSTRAINT users_hash_shape  CHECK (password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$'),
    CONSTRAINT users_locale_shape CHECK (locale ~ '^[a-z]{2}(-[A-Z]{2})?$')
);

CREATE TABLE refresh_token_families (
    id                 uuid PRIMARY KEY,
    user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    current_token_hash bytea NOT NULL UNIQUE,
    issued_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz,
    revoke_reason      text,
    -- Только для анти-злоупотреблений; retention 90 дней (спецификация §6).
    ip                 inet,
    CONSTRAINT refresh_window  CHECK (expires_at > issued_at),
    CONSTRAINT refresh_reason  CHECK (revoked_at IS NULL OR revoke_reason IS NOT NULL)
);
CREATE INDEX refresh_family_user ON refresh_token_families (user_id) WHERE revoked_at IS NULL;

CREATE TABLE devices (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key   text NOT NULL,
    platform     device_platform NOT NULL,
    name         text NOT NULL,
    rotation_of  uuid REFERENCES devices(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    revoked_at   timestamptz,
    -- Форма ключа (44 символа base64, '=' в конце). Каноничность проверяется в Go:
    -- SQL не перекодирует base64, а неканонический ключ — это другой ключ.
    CONSTRAINT devices_key_shape CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    CONSTRAINT devices_name_len  CHECK (char_length(name) BETWEEN 1 AND 64)
);
CREATE UNIQUE INDEX devices_user_key ON devices (user_id, public_key);
CREATE INDEX devices_live ON devices (user_id) WHERE revoked_at IS NULL;
```

- [ ] **Step 2: Написать down-миграцию в обратном порядке**

`migrations/0001_identity.down.sql`:

```sql
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS refresh_token_families;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS device_platform;
DROP TYPE IF EXISTS user_status;
```

`citext` не удаляется: расширение может принадлежать другой схеме этого кластера, и его
удаление — избыточно деструктивный шаг для `migrate down`.

- [ ] **Step 3: Проверить синтаксис на живом PostgreSQL**

Run:
```bash
# `infrastructure/docker/docker-compose.dev.yml` создаёт задача 5, поэтому до неё база
# поднимается одноразовым контейнером с тем же пользователем и той же БД. С задачи 5
# вместо этих двух строк — `make up-dev`.
docker rm -f novavpn-pg-a1 2>/dev/null; docker run -d --name novavpn-pg-a1 \
  -e POSTGRES_USER=nova -e POSTGRES_PASSWORD=nova -e POSTGRES_DB=novavpn postgres:17
docker exec -i novavpn-pg-a1 psql -U nova -d novavpn -v ON_ERROR_STOP=1 \
  -f - < migrations/0001_identity.up.sql
```
Expected: без ошибок, `CREATE TABLE` ×3. Состояние контейнера — одноразовое, в дерево
репозитория не попадает; после проверки его можно удалить `docker rm -f novavpn-pg-a1`.

Run (обратный порядок, чтобы down не упал на зависимостях):
```bash
docker exec -i novavpn-pg-a1 psql -U nova -d novavpn -v ON_ERROR_STOP=1 \
  -f - < migrations/0001_identity.down.sql
```
Expected: без ошибок.

- [ ] **Step 4: Проверить, что констрейнты действительно отсекают мусор**

Run: применить up-миграцию к одноразовому контейнеру из шага 3 (с задачи 5 — после
`make up-dev`), затем тот же `psql` с тремя запросами:

```sql
-- (a) блокировка без причины
INSERT INTO users (id, email, password_hash, status)
VALUES ('00000000-0000-4000-8000-000000000001', 'a@b.c',
        '$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0aW9uZQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'locked');
-- (b) неканоническая форма ключа
INSERT INTO devices (id, user_id, public_key, platform, name)
VALUES ('00000000-0000-4000-8000-000000000002',
        '00000000-0000-4000-8000-000000000001', 'short', 'linux', 'x');
-- (c) refresh без revoke_reason при отозванном
INSERT INTO refresh_token_families (id, user_id, current_token_hash, expires_at, revoked_at)
VALUES ('00000000-0000-4000-8000-000000000003',
        '00000000-0000-4000-8000-000000000001', decode('00','hex'), now() + interval '1 day', now());
```
Expected: **три ошибки** `users_lock_reason`, `devices_key_shape`, `refresh_reason`. Если
хотя бы одна вставляется — констрейнт написан неверно, чинить до коммита.

- [ ] **Step 5: Коммит**

```bash
git add migrations/0001_identity.up.sql migrations/0001_identity.down.sql
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(db): схема идентификации — пользователи, refresh-семьи, устройства"
```

---

### Task 3: Миграция 0002 — узлы, адреса, профили

**Files:**
- Create: `migrations/0002_network.up.sql`, `migrations/0002_network.down.sql`

**Interfaces:**
- Consumes: `users`, `devices` (0001).
- Produces: `server_locations`, `vpn_servers`, `node_credentials`, `vpn_profiles`,
  `tunnel_addresses`; тип `profile_status` с значениями `active`, `superseded`, `revoked`,
  `expired` и `peer_state` = `rotating_old_key`. Индекс `profiles_one_active_per_device_server`
  — механизм, на котором держится «двойная выдача невозможна» (спецификация §6).

- [ ] **Step 1: Написать up-миграцию**

`migrations/0002_network.up.sql`:

```sql
CREATE TYPE maintenance_status AS ENUM ('online', 'draining', 'maintenance', 'retired');
CREATE TYPE dns_mode AS ENUM ('local_recursor');
CREATE TYPE profile_status AS ENUM ('active', 'superseded', 'revoked', 'expired');
CREATE TYPE peer_state AS ENUM ('active', 'rotating_old_key');

CREATE TABLE server_locations (
    id           uuid PRIMARY KEY,
    country_code text NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
    city         text NOT NULL CHECK (char_length(city) BETWEEN 1 AND 64),
    lat          numeric(9,6) NOT NULL CHECK (lat BETWEEN -90 AND 90),
    lon          numeric(9,6) NOT NULL CHECK (lon BETWEEN -180 AND 180),
    timezone     text   NOT NULL,
    UNIQUE (country_code, city, lat, lon)
);

CREATE TABLE vpn_servers (
    id                 uuid PRIMARY KEY,
    location_id        uuid NOT NULL REFERENCES server_locations(id),
    name               text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 64),
    advertised_host    text NOT NULL,
    listen_port        integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    public_key         text  NOT NULL UNIQUE CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    address_pool_v4    cidr  NOT NULL,
    mtu                integer NOT NULL DEFAULT 1420 CHECK (mtu BETWEEN 1280 AND 1420),
    dns_mode           dns_mode NOT NULL DEFAULT 'local_recursor',
    keepalive_sec      integer NOT NULL DEFAULT 25 CHECK (keepalive_sec BETWEEN 5 AND 120),
    config_version     bigint  NOT NULL DEFAULT 0 CHECK (config_version >= 0),
    -- Узел появляется в maintenance и уходит в online только после первого heartbeat:
    -- «зарегистрирован» ≠ «работает».
    maintenance_status maintenance_status NOT NULL DEFAULT 'maintenance',
    provider           text NOT NULL,
    region             text,
    -- Заявленная пропускная способность, не измеренная (ADR-006). NULL — «не заявлена».
    capacity_mbps      integer CHECK (capacity_mbps IS NULL OR capacity_mbps > 0),
    CONSTRAINT servers_host_shape CHECK (advertised_host ~ '^[A-Za-z0-9.-]{1,253}$')
);

CREATE TABLE node_credentials (
    id           uuid PRIMARY KEY,
    server_id    uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    -- sha256 от высокоэнтропийного секрета. Приватного ключа узла в БД нет и не будет.
    token_hash   bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    issued_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz,
    -- Ротация токена узлом: новый активен, предок отзывается одним запросом.
    rotated_from uuid REFERENCES node_credentials(id) ON DELETE SET NULL
);
CREATE INDEX node_cred_live ON node_credentials (server_id) WHERE revoked_at IS NULL;

CREATE TABLE vpn_profiles (
    id                   uuid PRIMARY KEY,
    device_id            uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    server_id            uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    address_v4           inet NOT NULL,
    status               profile_status NOT NULL DEFAULT 'active',
    issued_at            timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    -- Ротация ключа: предок живёт в overlap-окне (спецификация §7.3).
    overlap_valid_until  timestamptz,
    revoked_at           timestamptz,
    rotate_from          uuid REFERENCES vpn_profiles(id) ON DELETE SET NULL,
    -- Состояние пиера в desired set; отдельное от статуса профиля, потому что
    -- 'superseded' внутри overlap всё ещё отдаётся узлу.
    peer_state           peer_state NOT NULL DEFAULT 'active',
    CONSTRAINT profiles_window CHECK (expires_at > issued_at),
    CONSTRAINT profiles_overlap CHECK (overlap_valid_until IS NULL OR overlap_valid_until > issued_at),
    CONSTRAINT profiles_revoked_at CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
    CONSTRAINT profiles_peer_state CHECK (peer_state <> 'rotating_old_key'
                                          OR overlap_valid_until IS NOT NULL)
);
-- Двойная выдача невозможна на уровне БД, а не в коде (спецификация §6).
CREATE UNIQUE INDEX profiles_one_active_per_device_server
    ON vpn_profiles (device_id, server_id) WHERE status = 'active';

CREATE TABLE tunnel_addresses (
    server_id    uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    address      inet NOT NULL,
    -- Первичный ключ — пара (сервер, адрес), а не адрес: пулы разных серверов могут
    -- совпадать, и один и тот же адрес в двух пулах — норма (спецификация §6).
    -- Назначение хранится здесь, чтобы аллокация шла под блокировкой строки сервера:
    -- коллизия адреса невозможна конструктивно (спецификация §6).
    allocated_to uuid REFERENCES vpn_profiles(id) ON DELETE SET NULL,
    -- Освобождается не сразу, а по истечении окна переиспользования (§7.2).
    released_at  timestamptz,
    reusable_at  timestamptz,
    PRIMARY KEY (server_id, address),
    CONSTRAINT addresses_window CHECK (released_at IS NULL OR reusable_at IS NULL
                                       OR reusable_at >= released_at)
);
CREATE INDEX addresses_free ON tunnel_addresses (server_id) WHERE allocated_to IS NULL;
```

- [ ] **Step 2: down-миграция**

`migrations/0002_network.down.sql`:

```sql
DROP TABLE IF EXISTS tunnel_addresses;
DROP TABLE IF EXISTS vpn_profiles;
DROP TABLE IF EXISTS node_credentials;
DROP TABLE IF EXISTS vpn_servers;
DROP TABLE IF EXISTS server_locations;
DROP TYPE IF EXISTS peer_state;
DROP TYPE IF EXISTS profile_status;
DROP TYPE IF EXISTS dns_mode;
DROP TYPE IF EXISTS maintenance_status;
```

- [ ] **Step 3: Проверить синтаксис и констрейнты**

Run: поднять базу (до задачи 5 — одноразовый контейнер `novavpn-pg-a1`, команда в задаче 2,
шаг 3; с задачи 5 — `make up-dev`), затем прогнать up → down → up через `psql -v ON_ERROR_STOP=1 -f - < …sql`
(команда из задачи 2, шаг 3) и нижеуказанный скрипт проверок. Он сам создаёт себе
родительские строки, поэтому запускается одним куском:

```sql
BEGIN;
SAVEPOINT seed;
INSERT INTO server_locations (id, country_code, city, lat, lon, timezone)
VALUES ('00000000-0000-4000-8000-000000000f01', 'NL', 'Amsterdam', 52.3738, 4.8910, 'Europe/Amsterdam');
INSERT INTO vpn_servers (id, location_id, name, advertised_host, listen_port, public_key,
                         address_pool_v4, provider)
VALUES ('00000000-0000-4000-8000-000000000f02', '00000000-0000-4000-8000-000000000f01',
        'nl-ams-1', 'nl-ams-1.novavpn.example', 51820,
        'wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iA=', '10.99.7.0/24', 'example-hosting');
-- второй узел в той же локации и с тем же пулом: нужен для блока (d)
INSERT INTO vpn_servers (id, location_id, name, advertised_host, listen_port, public_key,
                         address_pool_v4, provider)
VALUES ('00000000-0000-4000-8000-000000000f0a', '00000000-0000-4000-8000-000000000f01',
        'nl-ams-2', 'nl-ams-2.novavpn.example', 51820,
        'qTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iB=', '10.99.7.0/24', 'example-hosting');
INSERT INTO users (id, email, password_hash)
VALUES ('00000000-0000-4000-8000-000000000f03', 'seed@novavpn.example',
        '$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0aW9uZQ$aGFzaGFzaGFzaGFzaGFzaGFzaA');
INSERT INTO devices (id, user_id, public_key, platform, name)
VALUES ('00000000-0000-4000-8000-000000000f04', '00000000-0000-4000-8000-000000000f03',
        'wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iI=', 'linux', 'seed');

-- (a) второй активный профиль на пару (device, server) должен падать:
SAVEPOINT a;
INSERT INTO vpn_profiles (id, device_id, server_id, address_v4, expires_at)
VALUES ('00000000-0000-4000-8000-000000000f05', '00000000-0000-4000-8000-000000000f04',
        '00000000-0000-4000-8000-000000000f02', '10.99.7.42/32', now() + interval '1 day');
INSERT INTO vpn_profiles (id, device_id, server_id, address_v4, expires_at)
VALUES ('00000000-0000-4000-8000-000000000f06', '00000000-0000-4000-8000-000000000f04',
        '00000000-0000-4000-8000-000000000f02', '10.99.7.43/32', now() + interval '1 day');
ROLLBACK TO a;   -- ← здесь обязана быть ошибка profiles_one_active_per_device_server

-- (b) revoked без revoked_at:
SAVEPOINT b;
INSERT INTO vpn_profiles (id, device_id, server_id, address_v4, expires_at, status)
VALUES ('00000000-0000-4000-8000-000000000f07', '00000000-0000-4000-8000-000000000f04',
        '00000000-0000-4000-8000-000000000f02', '10.99.7.44/32', now() + interval '1 day', 'revoked');
ROLLBACK TO b;   -- ← profiles_revoked_at

-- (c) rotating_old_key без overlap-окна:
SAVEPOINT c;
INSERT INTO vpn_profiles (id, device_id, server_id, address_v4, expires_at,
                          status, peer_state)
VALUES ('00000000-0000-4000-8000-000000000f08', '00000000-0000-4000-8000-000000000f04',
        '00000000-0000-4000-8000-000000000f02', '10.99.7.45/32', now() + interval '1 day',
        'superseded', 'rotating_old_key');
ROLLBACK TO c;   -- ← profiles_peer_state

-- (d) адрес уникален в пределах сервера (PK), но одинаковый адрес на двух серверах — норма:
--     вторая вставка (другой сервер) обязана пройти, третья (тот же сервер и адрес) — упасть.
SAVEPOINT d;
INSERT INTO tunnel_addresses (server_id, address)
VALUES ('00000000-0000-4000-8000-000000000f02', '10.99.7.42/32');
INSERT INTO tunnel_addresses (server_id, address)
VALUES ('00000000-0000-4000-8000-000000000f0a', '10.99.7.42/32');
INSERT INTO tunnel_addresses (server_id, address)
VALUES ('00000000-0000-4000-8000-000000000f02', '10.99.7.42/32');
ROLLBACK TO d;   -- ← третья вставка того же (server, address) падает на PRIMARY KEY

-- (e) координаты вне диапазона:
SAVEPOINT e;
INSERT INTO server_locations (id, country_code, city, lat, lon, timezone)
VALUES ('00000000-0000-4000-8000-000000000f09', 'XX', 'Nowhere', 95, 0, 'UTC');
ROLLBACK TO e;   -- ← server_locations_lat_check (имя констрейнта сверить с выводом)

ROLLBACK;
```

Run: сохранить скрипт в `out/constraints.sql` (каталог игнорируется) и выполнить:
```bash
# До задачи 5 база — одноразовый контейнер `novavpn-pg-a1` (задача 2, шаг 3);
# с задачи 5 те же два шага делаются через compose-service `postgres`.
# Флаг MSYS_NO_PATHCONV=1 обязателен обоим командам: без него Git Bash превращает
# /tmp/constraints.sql в путь Windows, и psql сообщает «No such file or directory».
MSYS_NO_PATHCONV=1 docker cp out/constraints.sql novavpn-pg-a1:/tmp/constraints.sql
MSYS_NO_PATHCONV=1 docker exec -i novavpn-pg-a1 psql -U nova -d novavpn -f /tmp/constraints.sql
```
(Без `-v ON_ERROR_STOP=1`: нам нужно увидеть все пять ошибок, а не остановиться на первой.)

Expected: **пять ошибок**, по одной на блоки (a)–(e), и чистый `ROLLBACK` в конце:
`duplicate key value violates unique constraint "profiles_one_active_per_device_server"`,
`profiles_revoked_at`, `profiles_peer_state`,
`duplicate key value violates unique constraint "tunnel_addresses_pkey"`,
`server_locations_lat_check`. Блок (d) обязан упасть на **третьем** INSERT (первые два —
валидные вставки: один и тот же адрес на двух разных серверах), блок (e) — на `lat = 95`.

- [ ] **Step 4: Коммит**

```bash
git add migrations/0002_network.up.sql migrations/0002_network.down.sql
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(db): узлы, креды узла, профили с уникальной активной выдачей, таблица адресов"
```

---

### Task 4: Миграция 0003 — планы, телеметрия, аудит, идемпотентность, bootstrap

**Files:**
- Create: `migrations/0003_plans_telemetry_audit.up.sql`, `migrations/0003_plans_telemetry_audit.down.sql`
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§6 — добавить
  `idempotency_keys` и `bootstrap_tokens`, см. шаг 5)

**Interfaces:**
- Consumes: `users`, `devices`, `vpn_servers`.
- Produces: `subscription_plans` с предопределённой строкой `internal-default`,
  `subscriptions`, `server_health`, `connection_events`, `device_day_traffic`, `admin_users`,
  `admin_audit_logs`, `idempotency_keys`, `bootstrap_tokens`.
  `entitlements` (задача 13) читает `subscription_plans`/`subscriptions`; `httpx`
  (задача 9) — `idempotency_keys`; A-2 — `bootstrap_tokens`.

- [ ] **Step 1: Написать up-миграцию**

`migrations/0003_plans_telemetry_audit.up.sql`:

```sql
CREATE TYPE subscription_status AS ENUM ('active', 'canceled', 'expired');
CREATE TYPE subscription_source AS ENUM ('manual', 'trial', 'billing');
CREATE TYPE health_status AS ENUM ('ok', 'stale', 'error');
CREATE TYPE event_type AS ENUM ('profile_issued', 'profile_revoked', 'profile_expired',
                               'peer_applied', 'peer_removed', 'handshake_observed',
                               'handshake_failed', 'node_stale', 'connection_error');
CREATE TYPE audit_action AS ENUM ('server_created', 'server_updated', 'node_token_revoked',
                                 'node_enrolled', 'user_locked', 'user_unlocked',
                                 'profile_revoked_now', 'server_drained', 'admin_created');

CREATE TABLE subscription_plans (
    id                  uuid PRIMARY KEY,
    slug                text NOT NULL UNIQUE,
    device_limit        integer NOT NULL CONSTRAINT plans_device_limit CHECK (device_limit > 0),
    -- Набор серверов планом; в A — 'all'.
    server_selector     text NOT NULL DEFAULT 'all',
    -- NULL = безлимит.
    traffic_quota_bytes bigint CHECK (traffic_quota_bytes IS NULL OR traffic_quota_bytes > 0),
    trial_days          integer NOT NULL DEFAULT 0 CHECK (trial_days BETWEEN 0 AND 365),
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE subscriptions (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id    uuid NOT NULL REFERENCES subscription_plans(id),
    status     subscription_status NOT NULL DEFAULT 'active',
    starts_at  timestamptz NOT NULL DEFAULT now(),
    ends_at    timestamptz,
    source     subscription_source NOT NULL DEFAULT 'manual',
    CONSTRAINT subscriptions_window CHECK (ends_at IS NULL OR ends_at > starts_at)
);
CREATE INDEX subscriptions_active ON subscriptions (user_id, plan_id) WHERE status = 'active';

CREATE TABLE server_health (
    server_id              uuid PRIMARY KEY REFERENCES vpn_servers(id) ON DELETE CASCADE,
    observed_at            timestamptz NOT NULL,
    peers_configured       integer NOT NULL DEFAULT 0 CHECK (peers_configured >= 0),
    peers_handshaked       integer NOT NULL DEFAULT 0 CHECK (peers_handshaked >= 0),
    interface_rx_bytes     bigint  NOT NULL DEFAULT 0 CHECK (interface_rx_bytes >= 0),
    interface_tx_bytes     bigint  NOT NULL DEFAULT 0 CHECK (interface_tx_bytes >= 0),
    load1                  numeric(6,3),
    cpu_pct                numeric(5,2) CHECK (cpu_pct IS NULL OR (cpu_pct >= 0 AND cpu_pct <= 100)),
    applied_config_version bigint  NOT NULL,
    status                 health_status NOT NULL DEFAULT 'ok'
);

CREATE TABLE connection_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    uuid,
    device_id  uuid,
    server_id  uuid REFERENCES vpn_servers(id) ON DELETE SET NULL,
    event      event_type NOT NULL,
    -- Только коды ошибок и версии. Никакого содержимого трафика (ТЗ §9, §11).
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX connection_events_created ON connection_events (created_at);
CREATE INDEX connection_events_user ON connection_events (user_id, created_at);

-- Единственный персистентный след объёмов: агрегат на устройство-сутки (ADR-006).
CREATE TABLE device_day_traffic (
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    day       date NOT NULL,
    rx_bytes  bigint NOT NULL DEFAULT 0 CHECK (rx_bytes >= 0),
    tx_bytes  bigint NOT NULL DEFAULT 0 CHECK (tx_bytes >= 0),
    PRIMARY KEY (user_id, device_id, day)
);

CREATE TABLE admin_users (
    id            uuid PRIMARY KEY,
    email         citext NOT NULL UNIQUE,
    password_hash text   NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT admin_hash_shape CHECK (password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$')
);

CREATE TABLE admin_audit_logs (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    admin_id    uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    action      audit_action NOT NULL,
    target_type text NOT NULL,
    target_id   text NOT NULL,
    -- Причина обязательна: ТЗ §9 «действия администратора с указанием причины».
    reason      text NOT NULL CONSTRAINT admin_audit_reason CHECK (char_length(reason) BETWEEN 3 AND 500),
    request_id  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX admin_audit_time ON admin_audit_logs (created_at DESC);

-- Добавлено планом: без этой таблицы Idempotency-Key (§5.2) негде хранить.
CREATE TABLE idempotency_keys (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    route           text NOT NULL,
    idem_key        text NOT NULL,
    request_hash    bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_status integer,
    response_body   jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    UNIQUE (user_id, route, idem_key)
);

-- Добавлено планом: одноразовый bootstrap-токен для enroll (§4.1).
CREATE TABLE bootstrap_tokens (
    id         uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    server_id  uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    created_by uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    CONSTRAINT bootstrap_window CHECK (expires_at > created_at)
);

-- Один план на цикл A: internal-default. Это данные, а не заглушка: A не продаёт тарифы (D).
INSERT INTO subscription_plans (id, slug, device_limit, server_selector, traffic_quota_bytes, trial_days)
VALUES ('00000000-0000-4000-8000-000000000a01', 'internal-default', 3, 'all', NULL, 0);
```

- [ ] **Step 2: down-миграция**

`migrations/0003_plans_telemetry_audit.down.sql`:

```sql
DROP TABLE IF EXISTS bootstrap_tokens;
DROP TABLE IF EXISTS idempotency_keys;
DROP TABLE IF EXISTS admin_audit_logs;
DROP TABLE IF EXISTS admin_users;
DROP TABLE IF EXISTS device_day_traffic;
DROP TABLE IF EXISTS connection_events;
DROP TABLE IF EXISTS server_health;
DROP TABLE IF EXISTS subscriptions;
DROP TABLE IF EXISTS subscription_plans;
DROP TYPE IF EXISTS audit_action;
DROP TYPE IF EXISTS event_type;
DROP TYPE IF EXISTS health_status;
DROP TYPE IF EXISTS subscription_source;
DROP TYPE IF EXISTS subscription_status;
```

- [ ] **Step 3: Проверить up/down/up и констрейнты**

Run (после применения 0001 и 0002): `psql -v ON_ERROR_STOP=1 -f - < migrations/0003_plans_telemetry_audit.up.sql`,
затем down, затем up; затем скрипт проверок (тот же порядок `docker compose cp` +
`psql -f /tmp/plans_checks.sql`, что в задаче 3):

Проверки ссылаются на родителей из задач 2–3 (пользователь `…f03`, устройство `…f04`, узел
`…f02`), поэтому сначала прогоняется и коммитится сид `out/seed.sql`, затем идёт скрипт ниже.
Сид нужен отдельным файлом, а не «seed-блоком задачи 3»: `out/constraints.sql` заканчивается
`ROLLBACK` и родителей после себя не оставляет.

```sql
-- out/seed.sql — родители для проверок задач 3 и 4. ON CONFLICT, чтобы запускать дважды
-- на уже наполненной базе.
INSERT INTO server_locations (id, country_code, city, lat, lon, timezone)
VALUES ('00000000-0000-4000-8000-000000000f01', 'NL', 'Amsterdam', 52.3738, 4.8910, 'Europe/Amsterdam')
ON CONFLICT (id) DO NOTHING;
INSERT INTO vpn_servers (id, location_id, name, advertised_host, listen_port, public_key,
                         address_pool_v4, provider)
VALUES ('00000000-0000-4000-8000-000000000f02', '00000000-0000-4000-8000-000000000f01',
        'nl-ams-1', 'nl-ams-1.novavpn.example', 51820,
        'wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iA=', '10.99.7.0/24', 'example-hosting')
ON CONFLICT (id) DO NOTHING;
INSERT INTO users (id, email, password_hash)
VALUES ('00000000-0000-4000-8000-000000000f03', 'seed@novavpn.example',
        '$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0aW9uZQ$aGFzaGFzaGFzaGFzaGFzaGFzaA')
ON CONFLICT (id) DO NOTHING;
INSERT INTO devices (id, user_id, public_key, platform, name)
VALUES ('00000000-0000-4000-8000-000000000f04', '00000000-0000-4000-8000-000000000f03',
        'wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iI=', 'linux', 'seed')
ON CONFLICT (id) DO NOTHING;
```

```sql
BEGIN;
SAVEPOINT a;
INSERT INTO admin_audit_logs (admin_id, action, target_type, target_id, reason, request_id)
VALUES (NULL, 'server_created', 'vpn_server', '00000000-0000-4000-8000-000000000f02', '', 'req-1');
ROLLBACK TO a;   -- ← admin_audit_reason

SAVEPOINT b;
INSERT INTO bootstrap_tokens (id, token_hash, server_id, expires_at)
VALUES ('00000000-0000-4000-8000-000000000b01', decode(repeat('00', 32), 'hex'),
        '00000000-0000-4000-8000-000000000f02', now() - interval '1 hour');
ROLLBACK TO b;   -- ← bootstrap_window

SAVEPOINT c;
INSERT INTO subscription_plans (id, slug, device_limit)
VALUES ('00000000-0000-4000-8000-000000000b02', 'zero', 0);
ROLLBACK TO c;   -- ← plans_device_limit

SAVEPOINT d;
INSERT INTO device_day_traffic (user_id, device_id, day, rx_bytes, tx_bytes)
VALUES ('00000000-0000-4000-8000-000000000f03', '00000000-0000-4000-8000-000000000f04',
        current_date, -1, 0);
ROLLBACK TO d;   -- ← device_day_traffic_rx_bytes_check
ROLLBACK;
```

Expected: **четыре ошибки** — `admin_audit_reason`, `bootstrap_window`,
`plans_device_limit`, `device_day_traffic_rx_bytes_check` (имя последней генерирует
PostgreSQL, проверено на живом сервере 17.11). `repeat`/`decode` существуют в
PostgreSQL 17 и возвращают 32 нулевых байта — ровно столько, сколько требует
`octet_length(token_hash) = 32`.

- [ ] **Step 4: Проверить, что `internal-default` пережил down/up ровно один раз**

Run: `psql -c "SELECT count(*) FROM subscription_plans WHERE slug = 'internal-default'"`
после up → down → up.
Expected: `1`. (Иначе предзаполнение неидемпотентно и упрётся в UNIQUE при втором up.)

- [ ] **Step 5: Внести правку в спецификацию**

В [спецификацию §6](../specs/2026-10-20-novavpn-cycle-a-access-core-design.md) добавить две
строки таблицы — `idempotency_keys` (`unique(user_id, route, idem_key)`, `request_hash` для
конфликта тела, `response_*` для повтора) и `bootstrap_tokens` (одноразовый, `expires_at`,
`used_at`), с пометкой, что они появились на этапе планирования. Коммитить правку вместе с
миграцией, чтобы документ и схема разъезжались не дольше одного коммита.

- [ ] **Step 6: Коммит**

```bash
git add migrations/0003_plans_telemetry_audit.*.sql docs/superpowers/specs
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(db): планы, телеметрия, аудит, идемпотентность, bootstrap-токены и правка спецификации §6"
```

---

### Task 5: Миграционный раннер в бинарнике и тест `up → down → up`

**Files:**
- Create: `migrations/embed.go`, `internal/db/migrate/migrate.go`,
  `infrastructure/docker/docker-compose.dev.yml`,
  `infrastructure/docker/.env.dev.example`, `tests/integration/migrations_test.go`
- Modify: `services/api/cmd/novavpn-api/main.go` (подкоманда `migrate`),
  `.gitignore` (исключение для `.env.dev.example`)

**Interfaces:**
- Consumes: `migrations/*.sql`, `config.Config.DatabaseURL`.
- Produces: `migrate.Up(ctx, url string) (uint, error)` и
  `migrate.Steps(ctx, url string, n int) (uint, error)` — оба возвращают применённую версию;
  `Steps` считает концы цепочки достижимыми: `n = -1<<31` откатывает до нуля и на чистой базе,
  и с недосчитанными шагами (`ErrShortLimit`), а не возвращает ошибку;
  `migrations.FS embed.FS`; CLI-команда `novavpn-api migrate up|all|version`.

- [ ] **Step 1: compose-стэк для разработки и тестов**

`infrastructure/docker/docker-compose.dev.yml` (имя и порты — не косметика: без `name:`
Compose берёт имя каталога первого файла, то есть `docker`, а `make down-dev` снимает тома
`-v` — в общем пространстве имён это чужие данные; порты параметризуются, потому что на
машине разработчика 5432 и 6379 уже заняты локальными службами):

```yaml
# Имя обязательно: без него Compose берёт имя каталога первого файла, то есть «docker».
# `make down-dev` снимает `-v`, а в общем пространстве имён уже есть чужие
# docker-compose.dev.yml (на этом хосте — проект cms) — без имени удалились бы чужие тома.
name: novavpn-dev

services:
  postgres:
    image: postgres:17
    environment:
      POSTGRES_USER: nova
      POSTGRES_PASSWORD: nova
      POSTGRES_DB: novavpn
    ports: ["${POSTGRES_HOST_PORT:-5432}:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nova -d novavpn"]
      interval: 2s
      timeout: 3s
      retries: 30
  redis:
    image: redis:7
    command: ["redis-server", "--save", "", "--appendonly", "no"]
    ports: ["${REDIS_HOST_PORT:-6379}:6379"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 3s
      retries: 30
```

`infrastructure/docker/.env.dev.example` — без значений секретов, только имена и пустые
значения. `.env.dev` коммититься не должен, и `.gitignore` это уже покрывает; но тот же
шаблон `.env.*` накрывает и сам пример, поэтому в `.gitignore` добавляется исключение —
иначе единственный отслеживаемый шаблон окружения не попадёт в репозиторий:

```
# Примеры окружения отслеживаются, рабочие файлы — нет
!.env.dev.example
```

```
NOVAVPN_ENV=dev
NOVAVPN_LISTEN_ADDR=:8080
NOVAVPN_DATABASE_URL=postgres://nova:nova@localhost:5432/novavpn?sslmode=disable
NOVAVPN_REDIS_ADDR=localhost:6379
NOVAVPN_JWT_SECRET=
```

- [ ] **Step 2: Написать падающий интеграционный тест**

`tests/integration/migrations_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/novavpn/novavpn/internal/db/migrate"
)

func databaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("NOVAVPN_DATABASE_URL")
	if url == "" {
		t.Skip("NOVAVPN_DATABASE_URL is not set; run `make up-dev` first")
	}
	return url
}

func TestMigrationsUpToDownToUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if _, err := migrate.Steps(ctx, databaseURL(t), -1<<31); err != nil {
		t.Fatalf("migrate down all: %v", err)
	}
	v, err := migrate.Up(ctx, databaseURL(t))
	if err != nil {
		t.Fatalf("first up: %v", err)
	}
	v2, err := migrate.Up(ctx, databaseURL(t))
	if err != nil {
		t.Fatalf("second up (must be no-op): %v", err)
	}
	if v != v2 {
		t.Errorf("version changed on no-op up: %d -> %d", v, v2)
	}

	conn, err := pgx.Connect(ctx, databaseURL(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	for _, table := range []string{"users", "devices", "vpn_profiles", "tunnel_addresses", "subscription_plans"} {
		var exists bool
		err := conn.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
			table).Scan(&exists)
		if err != nil || !exists {
			t.Errorf("table %q missing after up: err=%v exists=%v", table, err, exists)
		}
	}
	// Предзаполненный план обязан дожить до конца прогона.
	var plans int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM subscription_plans WHERE slug='internal-default'`).Scan(&plans); err != nil || plans != 1 {
		t.Errorf("internal-default plan: count=%d err=%v", plans, err)
	}
	// down → up не должен оставить висящих типов: иначе 0001/0002/0003 разойдутся.
	var types int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM pg_type WHERE typcategory='E' AND typname IN ('user_status','device_platform','profile_status','peer_state')`).Scan(&types); err != nil || types != 4 {
		t.Errorf("enum types after up: got %d want 4 (err=%v)", types, err)
	}
}
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `make integration`
Expected: FAIL — `no required module provides package github.com/novavpn/novavpn/internal/db/migrate`.

- [ ] **Step 4: Реализовать embed + раннер**

`migrations/embed.go`:

```go
// Package migrations держит SQL-артефакты рядом с бинарником: миграции применяются
// из embedded FS, поэтому и в контейнере, и в CI нужен один и тот же артефакт сборки.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
```

`internal/db/migrate/migrate.go`:

```go
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/novavpn/novavpn/migrations"
)

func open(ctx context.Context, url string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("migration source: %w", err)
	}
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("postgres handle: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	// WithInstance, а не Open(url): golang-migrate ожидает драйвер с именем
	// "postgres" (lib/pq), а pgx/v5/stdlib регистрируется как "pgx".
	driver, err := migratepg.WithInstance(sqlDB, &migratepg.Config{})
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("postgres driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return m, nil
}

// Up применяет все недостающие миграции и возвращает итоговую версию.
func Up(ctx context.Context, url string) (uint, error) {
	m, err := open(ctx, url)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return 0, err
	}
	return version(m)
}

// Steps делает n шагов: отрицательное n откатывает (n = -1<<31 — до чистой базы).
func Steps(ctx context.Context, url string, n int) (uint, error) {
	m, err := open(ctx, url)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	if n < 0 {
		// На чистой базе откатывать нечего, а golang-migrate при шаге вниз читает
		// down-файл версии 0 и возвращает fs.ErrNotExist («file does not exist»),
		// а не ErrNoChange. Проверено на postgres:17 с пустой schema_migrations.
		if _, _, verr := m.Version(); errors.Is(verr, migrate.ErrNilVersion) {
			return 0, nil
		}
	}
	if err := m.Steps(n); err != nil && !errors.Is(err, migrate.ErrNoChange) && !isLimit(err) {
		return 0, err
	}
	return version(m)
}

// isLimit — «шагов запрошено больше, чем есть файлов». О значении судят по обоим
// концам цепочки: n = -1<<31 означает «до нуля» и упирается в этот случай штатно
// (проверено: `migrate all` на версии 3 давал «limit 2147483645 short» с кодом 1).
// Поэтому он не ошибка, а достигнутый конец схемы.
func isLimit(err error) bool {
	var short migrate.ErrShortLimit
	return errors.As(err, &short)
}

func version(m *migrate.Migrate) (uint, error) {
	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		// Схема без единой миграции — это версия 0, а не ошибка.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if dirty {
		return v, fmt.Errorf("schema is dirty at version %d", v)
	}
	return v, nil
}
```

Тип ошибки — `migrate.ErrShortLimit{Short uint}` (в v4.20.1; `ErrLimitSteps` его именем не
называется, `errors.Is` не срабатывает, нужен `errors.As`).

Блокировку параллельных применений `golang-migrate` берёт на себя сама (`Lock()` внутри
`m.Up()`/`m.Steps()` через advisory lock PostgreSQL); отдельный `m.Lock()` в коде не нужен
и был бы ошибкой — метод вызывается драйвером.

Подкоманда в `main.go` (заменяет заглушку задачи 1):

```go
case "migrate":
	if fs.NArg() < 2 {
		return errors.New("usage: novavpn-api migrate up|all|version")
	}
	ctx := context.Background()
	switch fs.Arg(1) {
	case "up":
		v, err := migrate.Up(ctx, cfg.DatabaseURL)
		fmt.Println("version", v)
		return err
	case "all":
		v, err := migrate.Steps(ctx, cfg.DatabaseURL, -1<<31)
		fmt.Println("reverted to", v)
		return err
	case "version":
		v, err := migrate.Steps(ctx, cfg.DatabaseURL, 0)
		fmt.Println("version", v)
		return err
	default:
		return errors.New("usage: novavpn-api migrate up|all|version")
	}
```

`make mod` подтянет `golang-migrate/v4`, `pgx/v5`; версии зафиксировать в `go.mod` и
больше не менять молча.

- [ ] **Step 5: Прогнать и коммитить**

Run: `make up-dev && make integration`
Expected: PASS. Если первый `migrate down all` падает на зависимостях между 0002 и 0003 —
порядок `DROP` в down-файлах неверен, чинить там, а не в тесте. Если SASL-ошибка на роли
`nova` — порт 5432 на хосте занят локальной службой postgres, и ответ уходит не в dev-стек;
тогда `make up-dev integration POSTGRES_HOST_PORT=5433 REDIS_HOST_PORT=16379`. Проверено на
такой машине: с дефолтным портом тест падал на «role "nova" …», с 5433 — зелёный.

```bash
git add migrations/embed.go internal/db/migrate infrastructure/docker tests/integration services/api go.mod go.sum Makefile
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(db): встроенный миграционный раннер и интеграционный тест up-down-up"
```

---

### Task 6: sqlc — запросы к идентификации и планам

**Files:**
- Create: `sqlc.yaml`, `internal/db/query/identity.sql`, `internal/db/query/plans.sql`,
  `internal/db/query/devices.sql`, `internal/db/pool.go` (конструктор пула — не `db.go`:
  файл с таким именем генерирует сам sqlc, и он затирает чужое содержимое)

**Interfaces:**
- Consumes: схема из задач 2–4.
- Produces: пакет `internal/db` (генерация) с методами `Queries`:
  `InsertUser`, `UserByEmail`, `UserByID`, `LockUser`, `UnlockUser`, `InsertRefreshFamily`,
  `RefreshByID`, `RotateRefresh`, `RevokeRefreshFamily`, `RevokeAllFamiliesForUser`,
  `LiveSubscriptionByUser`, `PlanBySlug`, `InsertSubscription`,
  `InsertDevice`, `DeviceByID`, `LiveDevicesByUser`,
  `CountLiveDevices`, `DeviceByUserAndKey`, `MarkDeviceSeen`, `RevokeDevice`.
  Все сигнатуры — `func (q *Queries) X(ctx context.Context, arg XParams) (Y, error)`;
  где аргумент один, sqlc оставляет скаляр (`UserByEmail(ctx, string)`,
  `CountLiveDevices(ctx, uuid.UUID)`). `New(*pgxpool.Pool) *Queries`.
  Маппинг типов задан overrides в `sqlc.yaml` и сверен с генерацией 1.27.0:
  `uuid` → `github.com/google/uuid.UUID` (зависимость приходит уже задачей 6, а не 9),
  `timestamptz` → `time.Time`, nullable `timestamptz` → `*time.Time`, `inet`/`cidr` →
  `netip.Addr`/`netip.Prefix`, `citext` → `string`. Nullable `uuid` остаётся
  `pgtype.UUID` — в цикле A ни один запрос его не читает.
  Тип `db.Queries` принимает `DBTX`, поэтому тесты могут подменять слой БД.
  Перечисления из схемы приходят как `db.UserStatus`, `db.DevicePlatform`
  (определённые строки): в параметры — приведением `db.DevicePlatform(in.Platform)`,
  наружу — `string(d.Platform)`.
  У `RotateRefresh` поля параметров — `ID`, `NewHash`, `OldHash`, `Ip`: они заданы
  именованными плейсхолдерами в самом запросе (см. шаг 2), потому что позиционные `$2`
  и `$3` обращаются к одной колонке и sqlc не смог бы дать два разных имени.

- [ ] **Step 1: Конфигурация sqlc**

`sqlc.yaml`:

```yaml
version: "2"
sql:
  - engine: "postgresql"
    schema: "migrations"
    queries: "internal/db/query"
    gen:
      go:
        package: "db"
        out: "internal/db"
        sql_package: "pgx/v5"
        emit_interface: true
        emit_json_tags: false
        emit_prepared_queries: false
        # NULL-колонки обязаны стать указателями (*time.Time, *int64, *netip.Addr),
        # иначе «значение по умолчанию» и «значения нет» будут неотличимы — а это ровно
        # та подмена, которую запрещает ТЗ §19.3 (метрики без замера = null).
        emit_pointers_for_null_types: true
        overrides:
          # Встроенный Go-тип — плоской строкой; тип из stdlib — вложенной формой.
          - db_type: "citext"
            go_type: "string"
          # Без override uuid генерируется как pgtype.UUID, но все слои выше (задачи 7+)
          # работают с google/uuid.UUID, а pgx/v5 умеет кодировать его нативно.
          - db_type: "uuid"
            go_type: "github.com/google/uuid.UUID"
          # Без override timestamptz генерируется как pgtype.Timestamptz, а план задач
          # 12/13/15 сравнивает и присваивает time.Time (ExpiresAt, CreatedAt, RevokedAt).
          - db_type: "timestamptz"
            go_type: "time.Time"
          # Nullable-колонки sqlc ищет отдельным ключом и берёт тип дословно, поэтому
          # указатель задаётся явно: иначе «значения нет» слилось бы с нулевым временем.
          - db_type: "timestamptz"
            nullable: true
            go_type:
              type: "time.Time"
              pointer: true
          - db_type: "cidr"
            go_type:
              import: "net/netip"
              type: "Prefix"
          - db_type: "inet"
            go_type:
              import: "net/netip"
              type: "Addr"
```

`inet` — адрес (`netip.Addr`), `cidr` — сеть (`netip.Prefix`); `refresh_token_families.ip`
и `vpn_profiles.address_v4` хранят адрес, а не сеть, поэтому дальнейшие задачи
(задачи 12, 17) работают с `*netip.Addr`. Проверено генерацией 1.27.0: `citext`
распознан как `string`, `inet`/`cidr` легли в `netip` без переделок. Если в более
новом sqlc `inet` или `cidr` упорно мапится в `[]byte` — убрать оба вложенных
override и преобразовать в `netip.Prefix` в слое, который их читает (`connections`
появится в A-2). Любое из этих решений фиксируется комментарием над `overrides:` в том
же коммите, что и сгенерированный код, чтобы следующий сборщик не гадал, почему
конфиг такой.

`internal/db/pool.go`:

```go
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Pool(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MaxConnLifetime = time.Hour
	return pgxpool.NewWithConfig(ctx, cfg)
}
```

- [ ] **Step 2: Написать запросы**

`internal/db/query/identity.sql`:

```sql
-- name: InsertUser :one
INSERT INTO users (id, email, password_hash, display_name, locale)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, email, password_hash, display_name, status, locked_reason,
          email_verified_at, locale, created_at, updated_at;

-- name: UserByEmail :one
SELECT id, email, password_hash, display_name, status, locked_reason,
       email_verified_at, locale, created_at, updated_at
FROM users WHERE email = $1;

-- name: UserByID :one
SELECT id, email, password_hash, display_name, status, locked_reason,
       email_verified_at, locale, created_at, updated_at
FROM users WHERE id = $1;

-- name: LockUser :exec
UPDATE users
   SET status = 'locked', locked_reason = $2, updated_at = now()
 WHERE id = $1;

-- name: UnlockUser :exec
UPDATE users
   SET status = 'active', locked_reason = NULL, updated_at = now()
 WHERE id = $1;

-- name: InsertRefreshFamily :one
INSERT INTO refresh_token_families (id, user_id, current_token_hash, expires_at, ip)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: RefreshByID :one
-- Ротация ищет семью по идентификатору из токена, а не по хэшу: именно это даёт
-- детект переиспользования (секрет есть, но он не текущий → семья предательски отзывается).
SELECT id, user_id, current_token_hash, issued_at, last_used_at, expires_at,
       revoked_at, revoke_reason, ip
FROM refresh_token_families WHERE id = $1;

-- name: RotateRefresh :one
-- Условие по старому хэшу — это и детект переиспользования, и атомарность ротации:
-- второй запрос того же токена не найдёт семью как активную.
-- Именованные параметры обязательны: $2 и $3 стоят у одной колонки
-- (current_token_hash), и sqlc выдал бы два одинаковых имени поля. Через @name
-- имена задаёт автор запроса.
UPDATE refresh_token_families
   SET current_token_hash = @new_hash, last_used_at = now(),
       ip = COALESCE(@ip, ip)
 WHERE id = @id AND revoked_at IS NULL
   AND current_token_hash = @old_hash AND expires_at > now()
 RETURNING id, user_id;

-- name: RevokeRefreshFamily :exec
UPDATE refresh_token_families
   SET revoked_at = now(), revoke_reason = $2
 WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAllFamiliesForUser :exec
UPDATE refresh_token_families
   SET revoked_at = now(), revoke_reason = 'logout_all'
 WHERE user_id = $1 AND revoked_at IS NULL;
```

`internal/db/query/plans.sql`:

```sql
-- name: LiveSubscriptionByUser :one
SELECT s.id AS subscription_id, s.user_id, s.status, s.starts_at, s.ends_at, s.source,
       p.id AS plan_id, p.slug, p.device_limit, p.server_selector,
       p.traffic_quota_bytes, p.trial_days
FROM subscriptions s
JOIN subscription_plans p ON p.id = s.plan_id
WHERE s.user_id = $1 AND s.status = 'active'
  AND (s.ends_at IS NULL OR s.ends_at > now())
ORDER BY s.starts_at DESC
LIMIT 1;

-- name: PlanBySlug :one
SELECT id, slug, device_limit, server_selector, traffic_quota_bytes, trial_days
FROM subscription_plans WHERE slug = $1;

-- name: InsertSubscription :one
INSERT INTO subscriptions (id, user_id, plan_id, status, starts_at, ends_at, source)
VALUES ($1, $2, $3, 'active', $4, $5, 'manual')
RETURNING id;
```

`internal/db/query/devices.sql`:

```sql
-- name: InsertDevice :one
INSERT INTO devices (id, user_id, public_key, platform, name, rotation_of)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, public_key, platform, name, rotation_of, created_at, last_seen_at, revoked_at;

-- name: DeviceByID :one
SELECT id, user_id, public_key, platform, name, rotation_of, created_at, last_seen_at, revoked_at
FROM devices WHERE id = $1;

-- name: DeviceByUserAndKey :one
SELECT id, user_id, public_key, platform, name, rotation_of, created_at, last_seen_at, revoked_at
FROM devices WHERE user_id = $1 AND public_key = $2;

-- name: LiveDevicesByUser :many
SELECT id, user_id, public_key, platform, name, rotation_of, created_at, last_seen_at, revoked_at
FROM devices
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY created_at;

-- name: CountLiveDevices :one
SELECT count(*) FROM devices WHERE user_id = $1 AND revoked_at IS NULL;

-- name: MarkDeviceSeen :exec
UPDATE devices SET last_seen_at = now() WHERE id = $1;

-- name: RevokeDevice :exec
UPDATE devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;
```

- [ ] **Step 3: Сгенерировать код**

Run: `make sqlc-generate`
Expected: в `internal/db/` появляются `db.go`, `models.go`, `identity.sql.go`,
`plans.sql.go`, `devices.sql.go`; команда завершается с кодом 0. Если sqlc ругается на
override для `citext` — убрать override и принять `string` из типовой генерации; не
домучивать конфигурацию ради косметики.

Run: `make unit`
Expected: PASS (сгенерированный пакет компилируется).

- [ ] **Step 4: Коммит вместе с генерацией**

Генерируемый код коммитится: сборка не должна зависеть от наличия образа sqlc.

```bash
git add sqlc.yaml internal/db
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(db): sqlc-конфигурация и запросы к пользователям, refresh-семьям, устройствам, планам"
```

---

### Task 7: httpx — envelope ошибки, request id, запись JSON

**Files:**
- Create: `internal/httpx/envelope.go`, `internal/httpx/requestid.go`, `internal/httpx/json.go`,
  `internal/httpx/httpx_test.go`

**Interfaces:**
- Consumes: ничего — транспортный слой не знает бизнес-модулей.
- Produces: `httpx.ErrorCode` со стабильными константами (§5.2),
  `httpx.WriteError(w http.ResponseWriter, r *http.Request, status int, code ErrorCode, message string, details map[string]any)`,
  `httpx.WriteJSON(w http.ResponseWriter, status int, v any) error`,
  `httpx.NewRequestID(next http.Handler) http.Handler`,
  `httpx.RequestIDFromContext(ctx context.Context) string`,
  `httpx.DecodeJSON(r *http.Request, dst any, maxBytes int64) error`.

- [ ] **Step 1: Написать падающие тесты на формат ошибки и request id**

`internal/httpx/httpx_test.go`:

```go
package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestErrorEnvelopeShape(t *testing.T) {
	var captured string
	handler := NewRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = RequestIDFromContext(r.Context())
		WriteError(w, r, http.StatusConflict, ErrDeviceLimitReached, "device limit reached",
			map[string]any{"limit": 3})
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	var got struct {
		Error struct {
			Code      string         `json:"code"`
			Message   string         `json:"message"`
			Details   map[string]any `json:"details"`
			RequestID string         `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not the documented envelope: %v (%s)", err, w.Body)
	}
	if got.Error.Code != "device_limit_reached" || got.Error.Message == "" {
		t.Errorf("bad code/message: %+v", got.Error)
	}
	if got.Error.RequestID == "" || got.Error.RequestID != captured {
		t.Errorf("request_id in body %q must equal middleware value %q", got.Error.RequestID, captured)
	}
	if w.Header().Get("X-Request-Id") != captured {
		t.Errorf("X-Request-Id header %q != body %q", w.Header().Get("X-Request-Id"), captured)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(captured) {
		t.Errorf("request id %q is not 16 lowercase hex chars", captured)
	}
}

func TestErrorEnvelopeWithoutRequestContext(t *testing.T) {
	// Вызовы WriteError без контекста (например, из юнита или из сборщика ошибок)
	// не должны ронять сервер и не должны рисовать пустой request_id,
	// как будто он существует.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	WriteError(w, r, http.StatusInternalServerError, ErrInternal, "boom", nil)
	if !regexp.MustCompile(`"request_id":"[0-9a-f]{16}"`).MatchString(w.Body.String()) {
		t.Fatalf("missing synthesized request_id: %s", w.Body)
	}
}

func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
	body := "[" + repeatX("a", 5000) + "]"
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	var dst struct{ A string }
	if err := DecodeJSON(r, &dst, 64); err == nil {
		t.Fatal("oversized body accepted")
	}
}
```

`repeatX` и `strings` — дописать в файл: `import "strings"` и
`func repeatX(s string, n int) string { return strings.Repeat(s, n) }`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `make unit`
Expected: FAIL — `undefined: NewRequestID`, `undefined: WriteError`, `undefined: ErrDeviceLimitReached`.

- [ ] **Step 3: Реализовать envelope**

`internal/httpx/envelope.go`:

```go
package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorCode — стабильный контракт (спецификация §5.2). Переименование значения
// ломает клиентов, поэтому коды добавляются, а не правятся.
type ErrorCode string

const (
	ErrInvalidRequest         ErrorCode = "invalid_request"
	ErrUnauthenticated        ErrorCode = "unauthenticated"
	ErrAccountLocked          ErrorCode = "account_locked"
	ErrForbidden              ErrorCode = "forbidden"
	ErrNotFound               ErrorCode = "not_found"
	ErrConflict               ErrorCode = "conflict"
	ErrDeviceLimitReached     ErrorCode = "device_limit_reached"
	ErrDuplicateDevice        ErrorCode = "duplicate_device"
	ErrIdempotencyKeyRequired ErrorCode = "idempotency_key_required"
	ErrIdempotencyConflict    ErrorCode = "idempotency_key_conflict"
	ErrIdempotencyInProgress  ErrorCode = "idempotency_key_in_progress"
	ErrRateLimited            ErrorCode = "rate_limited"
	ErrInternal               ErrorCode = "internal"
)

type errorBody struct {
	Code      ErrorCode      `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id"`
}

type envelope struct {
	Error errorBody `json:"error"`
}

// WriteError пишет тело в документированном формате и никогда не пишет секретные
// детали: message — человекочитаемое объяснение, details — только коды и лимиты.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code ErrorCode, message string, details map[string]any) {
	id := ""
	if r != nil {
		id = RequestIDFromContext(r.Context())
	}
	if id == "" {
		// Случай без middleware (тесты, внутренние вызовы): request_id обязан
		// существовать всегда, иначе лог и тело не сопоставить.
		id = newRequestID()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Request-Id", id)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(envelope{Error: errorBody{
		Code: code, Message: message, Details: details, RequestID: id,
	}}); err != nil {
		slog.Error("httpx: error write failed", "err", err, "request_id", id)
	}
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand отказывает только при сломанном системном entropy;
		// падать из-за этого в обработчике ошибок нельзя.
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}
```

- [ ] **Step 4: Реализовать request id и JSON-хелперы**

`internal/httpx/requestid.go`:

```go
package httpx

import (
	"context"
	"net/http"
	"time"
)

type ctxKey int

const requestIDKey ctxKey = 1

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// NewRequestID присваивает идентификатор и пишет доступный для клиента заголовок.
// Клиентский X-Request-Id принимается только если он уже правильного формата:
// иначе заголовок становится каналом для подстановки в логи.
func NewRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !isHex16(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(withRequestID(r.Context(), id)))
		slog.Info("http",
			"request_id", id, "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "dur_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr)
	})
}

func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
```

`internal/httpx/json.go`:

```go
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// DecodeJSON читает тело с ограничением по размеру (отказ от DoS через огромное
// тело) и требует application/json.
func DecodeJSON(r *http.Request, dst any, maxBytes int64) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("content-type must be application/json")
	}
	body := http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON after object")
	}
	return nil
}
```

- [ ] **Step 5: Прогнать тесты и коммитить**

Run: `make unit`
Expected: PASS. Замечание по `TestErrorEnvelopeWithoutRequestContext`: он проверяет
синтез идентификатора, а не поведение middleware — оба должны быть зелёные.

```bash
git add internal/httpx
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(httpx): единый конверт ошибки, request id и ограничение тела"
```

---

### Task 8: httpx — token bucket в Redis с fail-open

**Files:**
- Create: `internal/httpx/ratelimit.go`, `internal/httpx/ratelimit_test.go`
- Modify: `infrastructure/docker/docker-compose.dev.yml` (redis уже есть — проверить, что
  порт 6379 опубликован)

**Interfaces:**
- Consumes: `github.com/redis/go-redis/v9`, `httpx.WriteError`/`ErrRateLimited` (задача 7).
- Produces: `httpx.Limiter` c методом
  `Allow(ctx context.Context, key string, rate float64, burst int) (bool, time.Duration, error)`
  (третий возврат — `retry_after`), конструктор
  `httpx.NewLimiter(rdb *redis.Client, log *slog.Logger) *Limiter`,
  middleware `func (l *Limiter) Middleware(name string, rate float64, burst int, key func(*http.Request) string) func(http.Handler) http.Handler`
  (rate — токенов за миллисекунду), и `httpx.RatePerMinute(perMin float64) float64` —
  единственный способ передать в Middleware оконную норму.
  Ошибка Redis → разрешить и записать WARN (спецификация §4.3: отказ Redis не должен
  отрезать уже выданный доступ).

- [ ] **Step 1: Написать интеграционный тест лимитера**

`internal/httpx/ratelimit_test.go` — тест требует живой Redis, поэтому тег `integration`
и обход через `miniredis` не используется: фоллбэк на in-memory заглушке проверял бы не
тот код, что идёт в прод.

```go
//go:build integration

package httpx_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/httpx"
)

func redisFromEnv(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis at %s unreachable: %v", addr, err)
	}
	return c
}

func TestTokenBucketAllowsBurstThenBlocks(t *testing.T) {
	ctx := context.Background()
	c := redisFromEnv(t)
	l := httpx.NewLimiter(c, slog.New(slog.DiscardHandler))
	key := "test:burst:" + time.Now().Format("150405.000000")

	for i := 0; i < 5; i++ {
		ok, _, err := l.Allow(ctx, key, 0.01, 5)
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("burst exhausted at %d/5", i)
		}
	}
	ok, retry, err := l.Allow(ctx, key, 0.01, 5)
	if err != nil {
		t.Fatalf("Allow after burst: %v", err)
	}
	if ok {
		t.Fatal("6th request allowed with burst=5")
	}
	if retry <= 0 {
		t.Errorf("retry_after = %v, want > 0", retry)
	}
}

func TestFailOpenWhenRedisGone(t *testing.T) {
	// Клиент наведён на несуществующий порт: поведение при отказе Redis — пустить
	// запрос и записать WARN, а не отказать (спецификация §4.3).
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	l := httpx.NewLimiter(dead, slog.New(slog.DiscardHandler))
	ok, _, err := l.Allow(context.Background(), "test:dead", 1, 1)
	if !ok {
		t.Fatalf("fail-open must allow, got ok=%v err=%v", ok, err)
	}
	if err == nil {
		t.Error("fail-open must still report the Redis error for the log")
	}
}

func TestMiddlewareReturns429WithEnvelope(t *testing.T) {
	c := redisFromEnv(t)
	l := httpx.NewLimiter(c, slog.New(slog.DiscardHandler))
	name := "login:" + time.Now().Format("150405.000000")
	h := l.Middleware(name, 0.01, 1, func(*http.Request) string { return name })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if w.Code != 200 {
		t.Fatalf("first request: %d", w.Code)
	}
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: %d, want 429", w2.Code)
	}
	if body := w2.Body.String(); !containsAll(body, `"code":"rate_limited"`, `"request_id"`) {
		t.Fatalf("429 body is not the documented envelope: %s", body)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
```

`strings` — добавить в импорты.

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `make integration`
Expected: FAIL — `undefined: httpx.NewLimiter`.

- [ ] **Step 3: Реализовать лимитер**

`internal/httpx/ratelimit.go`:

```go
package httpx

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// bucketLua — атомарный token bucket. Один EVAL на запрос, без WATCH-гонок:
// при 1,7 rps на desired-опрос это не узкое место, а корректность важнее.
const bucketLua = `
local rate  = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now   = tonumber(ARGV[3])
local v = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(v[1])
local ts = tonumber(v[2])
if tokens == nil then tokens = burst end
if ts == nil then ts = now end
local elapsed = math.max(0, now - ts)
if rate > 0 then tokens = math.min(burst, tokens + elapsed * rate) end
local allowed = 0
local wait_ms = 0
if tokens >= 1 then allowed = 1; tokens = tokens - 1
elseif rate > 0 then wait_ms = math.ceil((1 - tokens) / rate * 1000) end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
local ttl = 1000
if rate > 0 then ttl = math.ceil(burst / rate * 1000) end
redis.call('PEXPIRE', KEYS[1], ttl)
return {allowed, wait_ms}
`

type Limiter struct {
	rdb    *redis.Client
	log    *slog.Logger
	script *redis.Script
}

func NewLimiter(rdb *redis.Client, log *slog.Logger) *Limiter {
	return &Limiter{rdb: rdb, log: log, script: redis.NewScript(bucketLua)}
}

// Allow возвращает разрешение, задержку до следующего разрешения и исходную ошибку
// Redis. Вызов обязан смотреть на err даже когда allowed == true: fail-open должен быть
// виден в журнале.
func (l *Limiter) Allow(ctx context.Context, key string, rate float64, burst int) (bool, time.Duration, error) {
	now := float64(time.Now().UnixMilli())
	res, err := l.script.Run(ctx, l.rdb, []string{key}, rate, burst, now).Result()
	if err != nil {
		// Fail-open по спецификации §4.3.
		l.log.Warn("rate limiter unavailable, allowing request", "key", key, "err", err)
		return true, 0, err
	}
	arr, ok := res.([]any)
	if !ok || len(arr) != 2 {
		l.log.Warn("rate limiter returned garbage, allowing request", "key", key, "got", res)
		return true, 0, nil
	}
	allowed := toInt(arr[0]) == 1
	wait := time.Duration(toInt(arr[1])) * time.Millisecond
	return allowed, wait, nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

// RatePerMinute переводит «запросов в минуту» в единицы Middleware (токенов/мс).
// Нужен, чтобы ни один вызов не передал «20» и не получил 20 000 запросов в секунду.
func RatePerMinute(perMin float64) float64 { return perMin / 60_000.0 }

// Middleware пишет 429 в документированном конверте и ставит Retry-After.
// name участвует в имени ключа, чтобы разные маршруты не отъедали бюджет друг у друга.
// ВНИМАНИЕ К ЕДИНИЦАМ: rate — это токенов за МИЛЛИСЕКУНДУ, потому что bucketLua
// считает elapsed в мс. 0.01 = 10 в секунду = 600 в минуту. Наружу передают результат
// httpx.RatePerMinute (она объявлением выше), а не голое число: «20 в минуту», записанное
// как 20, дало бы 20 000 запросов в секунду и молча отключило бы лимит.
func (l *Limiter) Middleware(name string, rate float64, burst int, key func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, wait, _ := l.Allow(r.Context(), "rl:"+name+":"+key(r), math.Max(0, rate), max(burst, 1))
			if !allowed {
				if wait < time.Second {
					wait = time.Second
				}
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				WriteError(w, r, http.StatusTooManyRequests, ErrRateLimited,
					"too many requests", map[string]any{"retry_after_ms": wait.Milliseconds()})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

`math.Max`/`max` требуют Go ≥ 1.21 (есть). Если сборка на `golang:1.25-alpine` ругается на
`math.Max` с неконвертированной константой — заменить на `math.Max(0.0, rate)`.

- [ ] **Step 4: Прогнать**

Run: `make up-dev && make integration`
Expected: PASS (3 теста). `TestFailOpenWhenRedisGone` обязан пройти даже при живом Redis:
он не использует окружение.

- [ ] **Step 5: Коммит**

```bash
git add internal/httpx/ratelimit.go internal/httpx/ratelimit_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(httpx): token bucket в Redis с fail-open на отказе"
```

---

### Task 9: httpx — идемпотентность критических операций

**Files:**
- Create: `internal/httpx/idempotency.go`, `internal/db/query/idempotency.sql`,
  `internal/httpx/context.go`, `tests/integration/helpers_test.go`,
  `tests/integration/idempotency_test.go`
- Modify: `internal/httpx/envelope.go` (коды уже объявлены — проверить, что
  `ErrIdempotencyKeyRequired`, `ErrIdempotencyConflict`, `ErrIdempotencyInProgress` на месте)

**Interfaces:**
- Consumes: `internal/db` (sqlc), `idempotency_keys` (задача 4), `httpx.WriteError` (задача 7).
- Produces: `httpx.WithUserID(ctx context.Context, id uuid.UUID) context.Context`,
  `httpx.UserIDFromContext(ctx context.Context) (uuid.UUID, bool)`,
  `httpx.NewIdempotency(store httpx.IdempotencyStore) *httpx.Idempotency`,
  `(*Idempotency).Middleware(route string) func(http.Handler) http.Handler`,
  `httpx.IdempotencyStore` — интерфейс из трёх методов:
  `Claim(ctx, userID uuid.UUID, route, key string, hash []byte) (existing db.IdempotencyKey, found bool, err error)`,
  `Complete(ctx, userID uuid.UUID, route, key string, status int, body []byte) error`,
  `Abandon(ctx, userID uuid.UUID, route, key string) error`.
  `route` — стабильное имя операции (`device_create`), а не URL-паттерн: он попадает в
  `UNIQUE (user_id, route, idem_key)` и не должен меняться от переименования маршрута.

- [ ] **Step 1: Запросы к таблице идемпотентности**

`internal/db/query/idempotency.sql`:

```sql
-- name: ClaimIdempotencyKey :execrows
-- ON CONFLICT DO NOTHING вместо SELECT-then-INSERT: два одновременных повтора
-- одного ключа не должны оба дойти до бизнес-логики.
INSERT INTO idempotency_keys (id, user_id, route, idem_key, request_hash)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, route, idem_key) DO NOTHING;

-- name: LoadIdempotencyKey :one
SELECT id, user_id, route, idem_key, request_hash, response_status, response_body,
       created_at, completed_at
FROM idempotency_keys
WHERE user_id = $1 AND route = $2 AND idem_key = $3;

-- name: CompleteIdempotencyKey :exec
UPDATE idempotency_keys
   SET response_status = $4, response_body = $5, completed_at = now()
 WHERE user_id = $1 AND route = $2 AND idem_key = $3 AND completed_at IS NULL;

-- name: DeleteIdempotencyKey :exec
DELETE FROM idempotency_keys
 WHERE user_id = $1 AND route = $2 AND idem_key = $3 AND completed_at IS NULL;

-- name: PurgeExpiredIdempotencyKeys :exec
DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours';
```

Run: `make sqlc-generate && make unit`
Expected: в `internal/db/idempotency.sql.go` появляются `ClaimIdempotencyKey`,
`LoadIdempotencyKey`, `CompleteIdempotencyKey`, `DeleteIdempotencyKey`,
`PurgeExpiredIdempotencyKeys` и модель `IdempotencyKey`.

- [ ] **Step 2: Написать падающий интеграционный тест**

`tests/integration/idempotency_test.go`:

```go
//go:build integration

package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/httpx"
)

// mkIdempotency строит middleware поверх счётного обработчика: счётчик показывает,
// что повтор не дошёл до бизнес-логики.
func mkIdempotency(t *testing.T, calls *int) http.Handler {
	t.Helper()
	store := httpx.NewPGIdempotency(pool(t))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": "first-result", "call": *calls})
	})
	return httpx.NewIdempotency(store).Middleware("device_create")(h)
}

func withUser(r *http.Request, id uuid.UUID) *http.Request {
	return r.Clone(httpx.WithUserID(r.Context(), id))
}

func TestIdempotentReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	user, idemKey := uuid.New(), uuid.NewString()
	calls := 0
	h := mkIdempotency(t, &calls)
	body := []byte(`{"public_key":"wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iJ=","platform":"linux","name":"laptop"}`)

	run := func(payload []byte, withKey bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(payload)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		if withKey {
			req.Header.Set("Idempotency-Key", idemKey)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withUser(req, user))
		return w
	}

	first, second := run(body, true), run(body, true)
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("statuses: %d / %d", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Errorf("replay body differs:\n  %s\n  %s", first.Body, second.Body)
	}
	if calls != 1 {
		t.Errorf("handler calls = %d, want 1", calls)
	}
	if !strings.Contains(second.Body.String(), `"call":1`) {
		t.Errorf("replay did not return the stored first result: %s", second.Body)
	}

	// Тот же ключ, другое тело → 409 idempotency_key_conflict.
	other := []byte(`{"public_key":"wTpNl3mZ3GJdF0nQ2hK2sV7pR9uX1yB4cD6eF8gH0iK=","platform":"linux","name":"phone"}`)
	w := run(other, true)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"code":"idempotency_key_conflict"`) {
		t.Fatalf("conflict body = %d %s", w.Code, w.Body)
	}

	// Отсутствие обязательного ключа → 400 idempotency_key_required.
	w = run(other, false)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"idempotency_key_required"`) {
		t.Fatalf("missing key: %d %s", w.Code, w.Body)
	}

	// Другой пользователь с тем же ключом — не чужой результат (изолированный скоуп).
	w = run(body, true)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"call":2`) {
		t.Fatalf("same key, second user must run fresh: %d %s", w.Code, w.Body)
	}
}
```

`pool(t)` — общий хелпер интеграционных пакетов; он создаёт
`tests/integration/helpers_test.go` (файл уже перечислен в **Files** этой задачи), а
`databaseURL(t)` взят из `migrations_test.go` (задача 5). Дальнейшие задачи только
дописывают в `helpers_test.go` свои хелперы, не создавая второй:

```go
//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/db"
)

// Один пул на весь прогон: интеграционные тесты их создают десятки, а
// pg_max_connections на dev-стеке конечен.
var sharedPool *pgxpool.Pool

func pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if sharedPool == nil {
		p, err := db.Pool(context.Background(), databaseURL(t))
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		sharedPool = p
	}
	return sharedPool
}
```

- [ ] **Step 3: Убедиться, что тест не компилируется**

Run: `make integration`
Expected: FAIL — `undefined: httpx.NewIdempotency`, `undefined: httpx.WithUserID`.

- [ ] **Step 4: Реализовать middleware**

`internal/httpx/context.go`:

```go
package httpx

import (
	"context"

	"github.com/google/uuid"
)

type userIDKey struct{}

func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey{}, id)
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey{}).(uuid.UUID)
	return id, ok
}
```

`internal/httpx/idempotency.go`:

```go
package httpx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

type IdempotencyStore interface {
	Claim(ctx context.Context, userID uuid.UUID, route, key string, hash []byte) (db.IdempotencyKey, bool, error)
	Complete(ctx context.Context, userID uuid.UUID, route, key string, status int, body []byte) error
	Abandon(ctx context.Context, userID uuid.UUID, route, key string) error
}

type Idempotency struct {
	store IdempotencyStore
}

func NewIdempotency(store IdempotencyStore) *Idempotency { return &Idempotency{store: store} }

// Middleware защищает критическую операцию (спецификация §5.2): повтор с тем же
// Idempotency-Key возвращает первый результат; конфликт тела — 409; незавершённый
// первый вызов — 409 in_progress, а не тихое ожидание.
func (i *Idempotency) Middleware(route string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := UserIDFromContext(r.Context())
			if !ok {
				// Middleware обязан стоять после аутентификации: без субъекта
				// ключ не имеет смысла (чужой ключ стал бы чужим результатом).
				WriteError(w, r, http.StatusUnauthorized, ErrUnauthenticated,
					"authentication required before idempotency", nil)
				return
			}
			key := r.Header.Get("Idempotency-Key")
			if key == "" || len(key) > 200 {
				WriteError(w, r, http.StatusBadRequest, ErrIdempotencyKeyRequired,
					"Idempotency-Key header is required for this operation", nil)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				WriteError(w, r, http.StatusBadRequest, ErrInvalidRequest, "cannot read body", nil)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			hash := sha256.Sum256(body)

			existing, found, err := i.store.Claim(r.Context(), userID, route, key, hash[:])
			if err != nil {
				WriteError(w, r, http.StatusInternalServerError, ErrInternal, "idempotency claim failed", nil)
				return
			}
			if found {
				if !bytes.Equal(existing.RequestHash, hash[:]) {
					WriteError(w, r, http.StatusConflict, ErrIdempotencyConflict,
						"Idempotency-Key was already used with a different request body", nil)
					return
				}
				if existing.CompletedAt == nil {
					WriteError(w, r, http.StatusConflict, ErrIdempotencyInProgress,
						"the first request with this key is still running", nil)
					return
				}
				// Повтор: отдать сохранённый результат, бизнес-логику не трогать.
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(existing.ResponseStatus)
				_, _ = w.Write(existing.ResponseBody)
				return
			}

			rec := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				if rec.completed {
					_ = i.store.Complete(context.WithoutCancel(r.Context()), userID, route, key, rec.status, rec.body.Bytes())
				} else {
					// Отказ/паника: слот освобождается, чтобы клиент мог повторить.
					_ = i.store.Abandon(context.WithoutCancel(r.Context()), userID, route, key)
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

type captureWriter struct {
	http.ResponseWriter
	status   int
	body     bytes.Buffer
	completed bool
}

func (c *captureWriter) WriteHeader(status int) {
	c.status = status
	c.completed = status < 500
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	// Сохраняем тело для повтора и одновременно отдаём его клиенту.
	c.body.Write(p)
	c.completed = true
	return c.ResponseWriter.Write(p)
}
```

`internal/httpx/idempotency_pg.go` — реализация `IdempotencyStore` поверх sqlc:

```go
package httpx

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
)

type PGIdempotency struct{ q *db.Queries }

func NewPGIdempotency(pool db.DBTX) *PGIdempotency { return &PGIdempotency{q: db.New(pool)} }

func (p *PGIdempotency) Claim(ctx context.Context, userID uuid.UUID, route, key string, hash []byte) (db.IdempotencyKey, bool, error) {
	if err := p.q.ClaimIdempotencyKey(ctx, db.ClaimIdempotencyKeyParams{
		ID: uuid.New(), UserID: userID, Route: route, IdemKey: key, RequestHash: hash,
	}); err != nil {
		return db.IdempotencyKey{}, false, err
	}
	existing, err := p.q.LoadIdempotencyKey(ctx, db.LoadIdempotencyKeyParams{
		UserID: userID, Route: route, IdemKey: key,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Вставка прошла → повтор не найден → слот наш.
		return db.IdempotencyKey{}, false, nil
	}
	if err != nil {
		return db.IdempotencyKey{}, false, err
	}
	return existing, true, nil
}

func (p *PGIdempotency) Complete(ctx context.Context, userID uuid.UUID, route, key string, status int, body []byte) error {
	statusCode := int32(status)
	return p.q.CompleteIdempotencyKey(ctx, db.CompleteIdempotencyKeyParams{
		UserID: userID, Route: route, IdemKey: key, ResponseStatus: &statusCode, ResponseBody: body,
	})
}

func (p *PGIdempotency) Abandon(ctx context.Context, userID uuid.UUID, route, key string) error {
	return p.q.DeleteIdempotencyKey(ctx, db.DeleteIdempotencyKeyParams{
		UserID: userID, Route: route, IdemKey: key,
	})
}
```

Одновременные Claim/Load не атомарны (между `:execrows` и `SELECT` теоретически влезает
другой повторыш) — поэтому `CompleteIdempotencyKey` имеет `AND completed_at IS NULL`, а
`response_status`/`response_body` в схеме nullable: при гонке победителя определяет БД по
первой записанной версии, а не угадайка в Go. Если тест на гонку из шага 5 нестабилен,
переносить Claim+Load в одну SQL-функцию (`RETURNING` через CTE) — но только после того,
как нестабильность наблюдалась, а не заранее.

- [ ] **Step 5: Прогнать и коммитить**

Run: `make up-dev && make integration`
Expected: PASS — `TestIdempotentReplay` зелёный, `calls == 1` на втором запросе.

```bash
git add internal/httpx internal/db tests/integration/idempotency_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(httpx): идемпотентность критических операций с конфликтом тела"
```

---

### Task 10: auth — argon2id для паролей

**Files:**
- Create: `internal/auth/password.go`, `internal/auth/password_test.go`

**Interfaces:**
- Consumes: `golang.org/x/crypto/argon2`, `crypto/subtle`.
- Produces: `auth.HashPassword(password string) (string, error)`,
  `auth.VerifyPassword(phc, password string) bool`,
  `auth.ErrWeakPassword`, константы `auth.MinPasswordLen = 10`, `auth.MaxPasswordLen = 1024`.
  Формат — PHC-строка `$argon2id$v=19$m=65536,t=3,p=4.<b64salt>$<b64hash>`; он же
  инвариант CHECK-констрейнта `users_hash_shape` из задачи 2.

- [ ] **Step 1: Написать падающие тесты**

`internal/auth/password_test.go`:

```go
package auth

import (
	"regexp"
	"strings"
	"testing"
)

var phc = regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)

func TestHashProducesVerifiablePHC(t *testing.T) {
	h, err := HashPassword("корректный-пароль-длинный")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !phc.MatchString(h) {
		t.Fatalf("hash is not the documented PHC form: %q", h)
	}
	if !VerifyPassword(h, "корректный-пароль-длинный") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(h, "корректный-пароль-длинны") {
		t.Fatal("wrong password accepted")
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same-password-12345")
	b, _ := HashPassword("same-password-12345")
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt is missing or fixed")
	}
}

func TestRejectsEmptyAndShort(t *testing.T) {
	for _, pw := range []string{"", "short", strings.Repeat("x", MaxPasswordLen+1)} {
		if _, err := HashPassword(pw); err == nil {
			t.Errorf("HashPassword(%q) accepted", truncate(pw))
		}
	}
}

// Пропущенный параметр в строке хэша не должен превращаться в «тихо посчитали по умолчанию»:
// это путь к проверке пароля с чужими настройками стойкости.
func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",     // не argon2id
		"$argon2id$v=19$m=1024,t=3,p=4$c2FsdA$aGFzaA",     // слабый параметр
		"$argon2id$v=19$m=65536,t=3,p=4$!!$aGFzaA",        // мусор в соли
	} {
		if VerifyPassword(bad, "anything-long-enough") {
			t.Errorf("VerifyPassword accepted %q", truncate(bad))
		}
	}
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}
```

`truncate` — только для сообщений об ошибке; в журнал хэши и пароли не пишутся (ТЗ §15).

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `make unit`
Expected: FAIL — `undefined: HashPassword`, `undefined: VerifyPassword`.

- [ ] **Step 3: Реализовать**

`internal/auth/password.go`:

```go
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Параметры — OWASP argon2id: 64 MiB, 3 прохода, 4 потока.
	// Меньше — дешевле брутфорс; больше — узел падает на малой RAM при всплеске логина.
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16

	MinPasswordLen = 10
	MaxPasswordLen = 1024
)

var (
	ErrWeakPassword = errors.New("password is too short or too long")
	phcPrefix       = "$argon2id$v=19$"
)

func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return "", ErrWeakPassword
	}
	// MinPasswordLen считается в байтах: для UTF-8 это нижняя граница, а не «10 символов».
	// Увеличивать без замера стоимости проверки на целевом узле нельзя.
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("%sm=%d,t=%d,p=%d$%s$%s",
		phcPrefix, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword возвращает false на любом malformed-хэше, не паникуя и не
// подставляя параметры по умолчанию.
func VerifyPassword(phc, password string) bool {
	if !strings.HasPrefix(phc, phcPrefix) || len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return false
	}
	rest := strings.TrimPrefix(phc, phcPrefix)
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return false
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[0], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if m < argonMemory || t < argonTime || p == 0 || p > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil || len(salt) < 8 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(want) < 16 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
```

`len(password) < MinPasswordLen*1` — опечатка-страховка в коде плана; заменить на
`len(password) < MinPasswordLen` при наборе (пояснение про UTF-8 остаётся).

- [ ] **Step 4: Прогнать**

Run: `make unit`
Expected: PASS. Время `TestHashProducesVerifiablePHC` ≈ 100–300 мс на одну хеш-операцию —
это ожидаемо (64 MiB), и в CI тест не помечается `short`.

- [ ] **Step 5: Коммит**

```bash
git add internal/auth
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(auth): argon2id с фиксированными параметрами и отказом на malformed-хэше"
```

---

### Task 11: auth — access JWT и denylist в Redis

**Files:**
- Create: `internal/auth/token.go`, `internal/auth/denylist.go`,
  `internal/auth/token_test.go`, `internal/auth/denylist_test.go`

**Interfaces:**
- Consumes: `config.Config.JWTSecret`, `config.Config.AccessTTL` (задача 1), `redis/go-redis/v9`.
- Produces: `auth.NewIssuer(secret []byte, ttl time.Duration) *auth.Issuer`,
  `(*Issuer).Issue(ctx context.Context, userID uuid.UUID) (auth.AccessToken, error)` где
  `auth.AccessToken{Value string; JTI string; ExpiresAt time.Time}`,
  `(*Issuer).Parse(value string) (auth.Claims, error)` где
  `auth.Claims{UserID uuid.UUID; JTI string; ExpiresAt time.Time}`,
  `auth.Denylist` — интерфейс `Add(ctx, jti string, exp time.Time) error` /
  `Contains(ctx, jti string) (bool, error)`,
  `auth.NewRedisDenylist(rdb *redis.Client, log *slog.Logger) auth.Denylist`.

- [ ] **Step 1: Написать падающие тесты на выдачу и разбор токена**

`internal/auth/token_test.go`:

```go
package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	return NewIssuer(bytes32("jwt-secret-for-tests-000000000000"), 10*time.Minute)
}

func bytes32(s string) []byte {
	b := make([]byte, 32)
	copy(b, s)
	return b
}

func TestIssueAndParseRoundTrip(t *testing.T) {
	iss := newTestIssuer(t)
	user := uuid.New()
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(tok.Value, "eyJ") {
		t.Fatalf("access token is not a JWT: %q", tok.Value)
	}
	if _, err := uuid.Parse(tok.JTI); err != nil {
		t.Fatalf("jti is not a uuid: %q", tok.JTI)
	}
	if tok.ExpiresAt.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("TTL too short: %v", tok.ExpiresAt)
	}
	cl, err := iss.Parse(tok.Value)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cl.UserID != user || cl.JTI != tok.JTI {
		t.Errorf("claims mismatch: %+v", cl)
	}
}

func TestParseRejectsForeignSignature(t *testing.T) {
	good := newTestIssuer(t)
	tok, _ := good.Issue(context.Background(), uuid.New())
	bad := NewIssuer(bytes32("a-completely-different-secret!!!"), 10*time.Minute)
	if _, err := bad.Parse(tok.Value); err == nil {
		t.Fatal("token from another secret accepted")
	}
}

func TestParseRejectsExpiredAndWrongAlg(t *testing.T) {
	expired := NewIssuer(bytes32("jwt-secret-for-tests-000000000000"), time.Millisecond)
	tok, err := expired.Issue(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := expired.Parse(tok.Value); err == nil {
		t.Error("expired token accepted")
	}
	// Токен с alg=none (классическая подмена): подпись не должна «проходить по инерции».
	if _, err := expired.Parse("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."); err == nil {
		t.Error("alg=none token accepted")
	}
}

func TestIssueRefusesEmptyUserID(t *testing.T) {
	if _, err := newTestIssuer(t).Issue(context.Background(), uuid.Nil); err == nil {
		t.Fatal("nil user id issued a token")
	}
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `make unit`
Expected: FAIL — `undefined: NewIssuer`, `undefined: Issuer`.

- [ ] **Step 3: Реализовать issuer**

`internal/auth/token.go`:

```go
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessToken struct {
	Value     string
	JTI       string
	ExpiresAt time.Time
}

type Claims struct {
	UserID uuid.UUID
	JTI    string
}

type Issuer struct {
	secret []byte
	ttl    time.Duration
	iss    string
}

var ErrInvalidToken = errors.New("access token is invalid")

func NewIssuer(secret []byte, ttl time.Duration) *Issuer {
	if len(secret) < 32 {
		// config.Load уже это проверяет; проверка здесь — защита от прямого вызова
		// (тесты, будущие внутренние команды), а не от пользователя.
		panic("auth: JWT secret must be at least 32 bytes")
	}
	return &Issuer{secret: secret, ttl: ttl, iss: "novavpn-api"}
}

func (i *Issuer) Issue(_ context.Context, userID uuid.UUID) (AccessToken, error) {
	if userID == uuid.Nil {
		return AccessToken{}, errors.New("auth: nil user id")
	}
	now := time.Now()
	exp := now.Add(i.ttl)
	jti := uuid.NewString()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    i.iss,
		Subject:   userID.String(),
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
	}).SignedString(i.secret)
	if err != nil {
		return AccessToken{}, fmt.Errorf("sign access token: %w", err)
	}
	return AccessToken{Value: signed, JTI: jti, ExpiresAt: exp}, nil
}

func (i *Issuer) Parse(value string) (Claims, error) {
	// Ограничение алгоритма на уровне разбора: токен с alg=RS256 или none не
	// проверяется тем же ключом, которым он не подписан.
	tok, err := jwt.ParseWithClaims(value, &jwt.RegisteredClaims{},
		func(*jwt.Token) (any, error) { return i.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(i.iss),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !tok.Valid {
		return Claims{}, ErrInvalidToken
	}
	rc := tok.Claims.(*jwt.RegisteredClaims)
	userID, err := uuid.Parse(rc.Subject)
	if err != nil || rc.ID == "" {
		return Claims{}, ErrInvalidToken
	}
	if rc.ExpiresAt == nil {
		return Claims{}, ErrInvalidToken
	}
	return Claims{UserID: userID, JTI: rc.ID, ExpiresAt: rc.ExpiresAt.Time}, nil
}
```

- [ ] **Step 4: Написать тест denylist, затем реализовать**

`internal/auth/denylist_test.go`:

```go
package auth_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
)

func redisOrNil(t *testing.T) *redis.Client {
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis unreachable: %v", err)
	}
	return c
}

func TestDenylistAddAndContains(t *testing.T) {
	d := auth.NewRedisDenylist(redisOrNil(t), slog.New(slog.DiscardHandler))
	ctx := context.Background()
	jti := "jti-" + t.Name()
	if err := d.Add(ctx, jti, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ok, err := d.Contains(ctx, jti)
	if err != nil || !ok {
		t.Fatalf("revoked jti not visible: ok=%v err=%v", ok, err)
	}
	miss, err := d.Contains(ctx, jti+"-never-added")
	if err != nil || miss {
		t.Fatalf("unknown jti reported as revoked: ok=%v err=%v", miss, err)
	}
}

func TestDenylistFailOpenOnDeadRedis(t *testing.T) {
	// Пустой список отзыва при отказе Redis — сознательный fail-open (спецификация
	// §4.3, §5.3): access-токен живёт не дольше 10 минут, и отзыв доступа делает
	// снятие пиера на узле, а не этот список.
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	d := auth.NewRedisDenylist(dead, slog.New(slog.DiscardHandler))
	ok, err := d.Contains(context.Background(), "any")
	if ok {
		t.Fatal("fail-open must report not-revoked, not revoked")
	}
	if err == nil {
		t.Error("fail-open must surface the Redis error for the log")
	}
}
```

`internal/auth/denylist.go`:

```go
package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

type Denylist interface {
	Add(ctx context.Context, jti string, exp time.Time) error
	Contains(ctx context.Context, jti string) (bool, error)
}

type redisDenylist struct {
	rdb *redis.Client
	log *slog.Logger
}

func NewRedisDenylist(rdb *redis.Client, log *slog.Logger) Denylist {
	return &redisDenylist{rdb: rdb, log: log}
}

// Add пишет запись с TTL по exp: список не растёт бесконечно и не требует чистильщика.
func (d *redisDenylist) Add(ctx context.Context, jti string, exp time.Time) error {
	ttl := time.Until(exp)
	if ttl <= 0 {
		return nil // токен и так мёртв — записывать нечего
	}
	return d.rdb.Set(ctx, "deny:"+jti, "1", ttl).Err()
}

func (d *redisDenylist) Contains(ctx context.Context, jti string) (bool, error) {
	n, err := d.rdb.Exists(ctx, "deny:"+jti).Result()
	if err != nil {
		d.log.Warn("denylist unavailable, failing open", "err", err, "jti", jti)
		return false, err
	}
	return n > 0, nil
}
```

- [ ] **Step 5: Прогнать и коммитить**

Run: `make unit && make up-dev && make integration`
Expected: `make unit` зелёный; `TestDenylistAddAndContains` и
`TestDenylistFailOpenOnDeadRedis` проходят в интеграционном прогоне (первый требует Redis).
Обе проверки denylist используют ключ `deny:<jti>` — совпадение с планом восстановления S5.

```bash
git add internal/auth
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(auth): короткоживущий access JWT с jti и denylist в Redis"
```

---

### Task 12: auth — refresh с ротацией и детектом переиспользования

**Files:**
- Create: `internal/auth/refresh.go`, `internal/auth/refresh_test.go`,
  `tests/integration/refresh_test.go`

**Interfaces:**
- Consumes: `db.RefreshByID`, `db.RotateRefresh`, `db.RevokeRefreshFamily`,
  `db.InsertRefreshFamily` (задача 6); `auth.Issuer` (задача 11).
- Produces: `auth.RefreshToken` — строка вида `<familyID>.<secret>`, обе части base64url
  без паддинга; `auth.NewSessionService(q *db.Queries, iss *auth.Issuer, deny auth.Denylist,
  refreshTTL time.Duration, log *slog.Logger) *auth.SessionService`;
  `(*SessionService).NewSession(ctx, userID uuid.UUID, ip *netip.Addr) (auth.Session, error)`,
  `(*SessionService).Rotate(ctx, raw string, ip *netip.Addr) (auth.Session, error)`,
  `(*SessionService).Revoke(ctx, raw string) error`,
  `auth.Session{AccessToken string; RefreshToken string; AccessExpiresAt, RefreshExpiresAt time.Time}`,
  `auth.ErrInvalidRefreshToken`, `auth.ErrExpiredRefreshToken`, `auth.ErrAccountLocked`.
  Повторное использование отозванного токена → `RevokeRefreshFamily(..., 'reuse_detected')`.

- [ ] **Step 1: Написать unit-тесты на формат токена и чистую математику ротации**

`internal/auth/refresh_test.go`:

```go
package auth

import (
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestRefreshTokenEncodingIsReversible(t *testing.T) {
	fam, secret := newFamilyID(), newSecret()
	raw := encodeRefresh(fam, secret)
	parsedFam, parsedSecret, err := parseRefresh(raw)
	if err != nil {
		t.Fatalf("parseRefresh(%q): %v", raw, err)
	}
	if parsedFam != fam || string(parsedSecret) != string(secret) {
		t.Fatal("round-trip lost data")
	}
	// Family-часть обязана быть uuid: на неё ищется семья в БД.
	if _, err := uuid.Parse(parsedFam); err != nil {
		t.Errorf("family part is not a uuid: %v", err)
	}
	if len(parsedSecret) != refreshSecretLen {
		t.Errorf("secret length = %d, want %d", len(parsedSecret), refreshSecretLen)
	}
}

func TestParseRefreshRejectsJunk(t *testing.T) {
	for _, bad := range []string{
		"", "a", "a.b", ".", "###.###",
		base64.URLEncoding.EncodeToString([]byte("not-a-uuid")) + ".AAAAAAAA",
		uuid.NewString() + ".",     // пустой секрет
		uuid.NewString() + ".a.b",  // лишняя часть
		uuid.NewString() + ".AAAAAAA=", // base64url с паддингом — другая каноническая форма
	} {
		if _, _, err := parseRefresh(bad); err == nil {
			t.Errorf("parseRefresh accepted %q", truncate(bad))
		}
	}
}
```

`truncate` берётся из `password_test.go` того же пакета. Проверка с паддингом важна:
`RawURLEncoding` отказывает на любом `=`, и это держит один секрет в одной форме — иначе
повторно предъявленный токен в другой кодировке обошёл бы сравнение хэшей.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `make unit`
Expected: FAIL — `undefined: newFamilyID`, `undefined: parseRefresh`.

- [ ] **Step 3: Реализовать токен и сервис**

`internal/auth/refresh.go`:

```go
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
)

const refreshSecretLen = 32

var (
	ErrInvalidRefreshToken = errors.New("refresh token is invalid")
	ErrExpiredRefreshToken = errors.New("refresh token expired")
	ErrAccountLocked       = errors.New("account is locked")
)

// refresh-токен непрозрачен, но носит идентификатор семьи: это позволяет
// обнаружить переиспользование, не заводя таблицу истории токенов.
func newFamilyID() string { return uuid.NewString() }

func newSecret() []byte {
	b := make([]byte, refreshSecretLen)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("auth: random secret: %v", err))
	}
	return b
}

var b64 = base64.RawURLEncoding

func encodeRefresh(familyID string, secret []byte) string {
	return familyID + "." + b64.EncodeToString(secret)
}

func parseRefresh(raw string) (string, []byte, error) {
	fam, secretB64, ok := strings.Cut(raw, ".")
	if !ok || fam == "" || secretB64 == "" {
		return "", nil, ErrInvalidRefreshToken
	}
	if _, err := uuid.Parse(fam); err != nil {
		return "", nil, ErrInvalidRefreshToken
	}
	// RawURLEncoding отказывает на любом паддинге → одна каноническая форма секрета.
	secret, err := b64.DecodeString(secretB64)
	if err != nil || len(secret) != refreshSecretLen {
		return "", nil, ErrInvalidRefreshToken
	}
	return fam, secret, nil
}

func hashSecret(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

type Session struct {
	AccessToken     string
	RefreshToken    string
	AccessExpiresAt time.Time
	RefreshExpiresAt time.Time
}

type SessionService struct {
	q         *db.Queries
	iss       *Issuer
	deny      Denylist
	refreshTTL time.Duration
	log       *slog.Logger
}

func NewSessionService(q *db.Queries, iss *Issuer, deny Denylist, refreshTTL time.Duration, log *slog.Logger) *SessionService {
	return &SessionService{q: q, iss: iss, deny: deny, refreshTTL: refreshTTL, log: log}
}

func (s *SessionService) ParseAccess(value string) (Claims, error) { return s.iss.Parse(value) }

func (s *SessionService) NewSession(ctx context.Context, userID uuid.UUID, ip *netip.Addr) (Session, error) {
	fam := newFamilyID()
	secret := newSecret()
	expires := time.Now().Add(s.refreshTTL)
	if _, err := s.q.InsertRefreshFamily(ctx, db.InsertRefreshFamilyParams{
		ID: uuid.MustParse(fam), UserID: userID, CurrentTokenHash: hashSecret(secret),
		ExpiresAt: expires, Ip: ip,
	}); err != nil {
		return Session{}, fmt.Errorf("create refresh family: %w", err)
	}
	return s.mint(ctx, userID, fam, secret, expires)
}

// Rotate меняет секрет семьи. Старый секрет перестаёт быть текущим, и любое его
// повторное предъявление уходит в ветку переиспользования.
func (s *SessionService) Rotate(ctx context.Context, raw string, ip *netip.Addr) (Session, error) {
	fam, secret, err := parseRefresh(raw)
	if err != nil {
		return Session{}, err
	}
	family, err := s.q.RefreshByID(ctx, uuid.MustParse(fam))
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("load refresh family: %w", err)
	}
	if family.RevokedAt != nil {
		// Семья уже сожжена; повторный вход тем же токеном — тоже сигнал.
		return Session{}, ErrInvalidRefreshToken
	}
	if time.Now().After(family.ExpiresAt) {
		reason := "expired"
		_ = s.q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{ID: family.ID, RevokeReason: &reason})
		return Session{}, ErrExpiredRefreshToken
	}
	if subtle.ConstantTimeCompare(family.CurrentTokenHash, hashSecret(secret)) != 1 {
		// Секрет не текущий, а семья живая → этот токен уже поменяли. Отзываем всех.
		reason := "reuse_detected"
		if err := s.q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{ID: family.ID, RevokeReason: &reason}); err != nil {
			s.log.Error("revoke family on reuse", "err", err)
		}
		s.log.Warn("refresh token reuse detected, family revoked", "user_id", family.UserID)
		return Session{}, ErrInvalidRefreshToken
	}
	next := newSecret()
	rotated, err := s.q.RotateRefresh(ctx, db.RotateRefreshParams{
		ID: family.ID, NewHash: hashSecret(next), OldHash: hashSecret(secret), Ip: ip,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Условие current_token_hash = $3 не прошло: конкурентная ротация уже состоялась.
		return Session{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("rotate refresh: %w", err)
	}	// rotated.UserID — тот же пользователь, что и у семьи: mint подписывает access
	// на субъекта, а не на идентификатор семьи.
	return s.mint(ctx, rotated.UserID, fam, next, family.ExpiresAt)
}

// Revoke отзывает семью. access передаётся, когда его надо вынять из оборота
// немедленно (logout); при отзыве снаружи активный access доживает не дольше TTL —
// см. спецификацию §5.3.
func (s *SessionService) Revoke(ctx context.Context, raw, access string) error {
	fam, _, err := parseRefresh(raw)
	if err != nil {
		return err
	}
	if access != "" {
		if cl, err := s.iss.Parse(access); err == nil {
			if err := s.deny.Add(ctx, cl.JTI, cl.ExpiresAt); err != nil {
				s.log.Warn("denylist add failed", "err", err)
			}
		}
		// Невалидный access не блокирует отзыв семьи: logout обязан сработать и
		// когда клиент принёс просроченный access.
	}
	reason := "logout"
	return s.q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{
		ID: uuid.MustParse(fam), RevokeReason: &reason,
	})
}

func (s *SessionService) mint(ctx context.Context, userID uuid.UUID, fam string, secret []byte, refreshExp time.Time) (Session, error) {
	access, err := s.iss.Issue(ctx, userID)
	if err != nil {
		return Session{}, err
	}
	return Session{
		AccessToken:      access.Value,
		RefreshToken:     encodeRefresh(fam, secret),
		AccessExpiresAt:  access.ExpiresAt,
		RefreshExpiresAt: refreshExp,
	}, nil
}
```

Запрос ротации лежит в `internal/db/query/identity.sql` (задача 6) уже в именованной
форме: `@new_hash`, `@old_hash`, `@ip`, `@id` — потому что два аргумента обращены к одной
колонке `current_token_hash`, и позиционные `$2`/`$3` дали бы sqlc два одинаковых имени
поля. `Ip` — `*netip.Addr` (nullable-колонка, `emit_pointers_for_null_types: true`),
`COALESCE(@ip, ip)` сохраняет предыдущий адрес, когда ротация пришла без него.
После правки запроса — `make sqlc-generate`, затем `make unit`.

- [ ] **Step 4: Интеграционный тест ротации и переиспользования**

`tests/integration/refresh_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

func TestRefreshRotationAndReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	user := seedUser(t, ctx, q)
	svc := auth.NewSessionService(q, auth.NewIssuer(bytes32ForTests(), 10*time.Minute),
		auth.NewRedisDenylist(redisClient(t), slog.New(slog.DiscardHandler)),
		24*time.Hour, slog.New(slog.DiscardHandler))

	first, err := svc.NewSession(ctx, user, nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	second, err := svc.Rotate(ctx, first.RefreshToken, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("rotation returned the same refresh token")
	}
	if second.AccessToken == first.AccessToken {
		t.Fatal("rotation returned the same access token")
	}

	// Переиспользование первого токена → семья отозвана, и второй тоже не работает.
	if _, err := svc.Rotate(ctx, first.RefreshToken, nil); err == nil {
		t.Fatal("reused refresh token accepted")
	}
	if _, err := svc.Rotate(ctx, second.RefreshToken, nil); err == nil {
		t.Fatal("family was not revoked after reuse detection")
	}

	// Отозванный access попадает в denylist: Revoke обязан вызвать Add.
	s3, err := svc.NewSession(ctx, user, nil)
	if err != nil {
		t.Fatalf("NewSession 2: %v", err)
	}
	if err := svc.Revoke(ctx, s3.RefreshToken, ""); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Rotate(ctx, s3.RefreshToken, nil); err == nil {
		t.Fatal("revoked family still rotates")
	}
}

func TestRevokeAddsAccessJtiToDenylist(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	user := seedUser(t, ctx, q)
	deny := auth.NewRedisDenylist(redisClient(t), slog.New(slog.DiscardHandler))
	svc := auth.NewSessionService(q, auth.NewIssuer(bytes32ForTests(), 10*time.Minute),
		deny, 24*time.Hour, slog.New(slog.DiscardHandler))
	sess, err := svc.NewSession(ctx, user, nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	claims, err := svc.ParseAccess(sess.AccessToken)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if err := svc.Revoke(ctx, sess.RefreshToken, sess.AccessToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	ok, err := deny.Contains(ctx, claims.JTI)
	if err != nil {
		t.Fatalf("Contains: %v", err)
	}
	if !ok {
		t.Error("logout must add the current access jti to the denylist")
	}
}
```

`Revoke(ctx, raw, access string)` принимает access-токен вторым аргументом потому, что
`jti` живёт только в самом JWT: прочитать его из семьи нельзя. Пустая строка `access`
означает «отзываю семью, активный access не трогай» — этим вызовом воспользуется
админский отзыв, он появится в A-2 вместе с админскими маршрутами. Logout-хендлер
(задача 17) передаёт оба токена и смонтирован **до** middleware аутентификации: отзыв
обязан сработать и тогда, когда предъявлен просроченный access (спецификация §5.2
освобождает от авторизации register/login/refresh, а logout по смыслу принадлежит той же
группе — он принимает на себя доказательство владения сессией в теле запроса).

Хелперы `bytes32ForTests`, `redisClient`, `seedUser` дописываются в
`tests/integration/helpers_test.go` (файл создан в задаче 9, `pool` там уже есть).
Ниже — файл целиком после этого шага, поэтому импорты объединяют то, что уже
написано, и новое:

```go
//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

func bytes32ForTests() []byte { return []byte("integration-secret-0000000000000000") }

func redisClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func seedUser(t *testing.T, ctx context.Context, q *db.Queries) uuid.UUID {
	t.Helper()
	id := uuid.New()
	hash, err := auth.HashPassword("integration-password-123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := q.InsertUser(ctx, db.InsertUserParams{
		ID: id, Email: "seed-" + id.String()[:8] + "@novavpn.test",
		PasswordHash: hash, Locale: "en",
	}); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if _, err := q.InsertSubscription(ctx, db.InsertSubscriptionParams{
		ID: uuid.New(), UserID: id,
		PlanID:  uuid.MustParse("00000000-0000-4000-8000-000000000a01"),
		StartsAt: time.Now(), 
	}); err != nil {
		t.Fatalf("InsertSubscription: %v", err)
	}
	return id
}
```

`pool(t)` в этом файле уже лежит (задача 9, шаг 4) — вторая копия недопустима:
в одном пакете две функции с одним именем не компилируются.

- [ ] **Step 5: Прогнать и коммитить**

Run: `make unit && make integration`
Expected: PASS. Если `TestRefreshRotationAndReuse` падает на «family was not revoked»,
проверить, что `RotateRefresh` в `identity.sql` имеет `AND revoked_at IS NULL` — без него
ветка переиспользования не закрывает доступ.

```bash
git add internal/auth tests/integration internal/db/query/identity.sql
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(auth): ротация refresh с отзывом семьи при переиспользовании"
```

---

### Task 13: entitlements — план как набор прав

**Files:**
- Create: `internal/entitlements/entitlements.go`, `internal/entitlements/entitlements_test.go`,
  `internal/db/tx.go`, `tests/integration/entitlements_test.go`

**Interfaces:**
- Consumes: `db.LiveSubscriptionByUser`, `db.PlanBySlug`, `db.InsertSubscription` (задача 6).
- Produces: `entitlements.Entitlement{UserID, PlanID uuid.UUID; Slug string; DeviceLimit int;
  ServerSelector string; TrafficQuotaBytes *int64}`,
  `entitlements.New(q *db.Queries) *entitlements.Service`,
  `(*Service).ForUser(ctx context.Context, userID uuid.UUID) (Entitlement, error)`,
  `entitlements.GrantDefaultPlanTx(ctx context.Context, q *db.Queries, userID uuid.UUID, slug string) error`,
  `entitlements.ErrNoActiveSubscription`,
  `db.RunInTx(ctx context.Context, pool *pgxpool.Pool, fn func(*db.Queries) error) error`.
  `ServerSelector` в A принимает только `"all"` — права на конкретные узлы появляются в A-2
  вместе с каталогом, здесь поле только читается и передаётся дальше.

- [ ] **Step 1: Написать падающий unit-тест на права**

`internal/entitlements/entitlements_test.go`:

```go
package entitlements

import (
	"testing"

	"github.com/google/uuid"
)

func TestAllowsDeviceCountsAgainstLimit(t *testing.T) {
	e := Entitlement{PlanID: uuid.New(), Slug: "internal-default", DeviceLimit: 3, ServerSelector: "all"}
	for live, want := range map[int]bool{0: true, 2: true, 3: false, 4: false} {
		if got := e.AllowsDevice(live); got != want {
			t.Errorf("AllowsDevice(%d) = %v, want %v", live, got, want)
		}
	}
}

// Нулевой лимит — сломанные данные, а не «неограниченно»: тихое «всем можно» здесь
// хуже отказа.
func TestZeroDeviceLimitIsRejected(t *testing.T) {
	if _, err := normalize(Entitlement{DeviceLimit: 0, ServerSelector: "all"}); err == nil {
		t.Fatal("device_limit = 0 accepted")
	}
	if _, err := normalize(Entitlement{DeviceLimit: 3, ServerSelector: "nonsense"}); err == nil {
		t.Fatal("unknown server_selector accepted")
	}
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `make unit`
Expected: FAIL — `undefined: Entitlement`, `undefined: normalize`.

- [ ] **Step 3: Реализовать**

`internal/entitlements/entitlements.go`:

```go
package entitlements

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
)

var ErrNoActiveSubscription = errors.New("no active subscription")

// Entitlement — то, что может спросить код: сколько устройств, какие серверы,
// сколько трафика. Платежей здесь нет (цикл D), поэтому структура читается из
// subscriptions + subscription_plans и всё.
type Entitlement struct {
	UserID            uuid.UUID
	PlanID            uuid.UUID
	Slug              string
	DeviceLimit       int
	ServerSelector    string
	TrafficQuotaBytes *int64
}

func (e Entitlement) AllowsDevice(liveCount int) bool { return liveCount < e.DeviceLimit }

func normalize(e Entitlement) (Entitlement, error) {
	if e.DeviceLimit <= 0 {
		return e, fmt.Errorf("entitlements: plan %q has device_limit=%d", e.Slug, e.DeviceLimit)
	}
	switch e.ServerSelector {
	case "all":
	default:
		return e, fmt.Errorf("entitlements: server_selector %q is not implemented in cycle A", e.ServerSelector)
	}
	return e, nil
}

type Service struct{ q *db.Queries }

func New(q *db.Queries) *Service { return &Service{q: q} }

func (s *Service) ForUser(ctx context.Context, userID uuid.UUID) (Entitlement, error) {
	row, err := s.q.LiveSubscriptionByUser(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entitlement{}, ErrNoActiveSubscription
	}
	if err != nil {
		return Entitlement{}, fmt.Errorf("live subscription: %w", err)
	}
	return normalize(Entitlement{
		UserID:            userID,
		PlanID:            row.PlanID,
		Slug:              row.Slug,
		DeviceLimit:       int(row.DeviceLimit),
		ServerSelector:    row.ServerSelector,
		TrafficQuotaBytes: row.TrafficQuotaBytes,
	})
}

// GrantDefaultPlanTx вызывается при регистрации: в A у пользователя нет выбора
// тарифа, но права на устройства должны существовать с первой секунды.
// Функция, а не метод: той же выдаче нужно работать внутри транзакции регистрации
// (задача 17), где Queries другая — *db.Queries передаётся аргументом.
// ends_at берётся из plan.trial_days: два места, решающие когда кончится подписка,
// обязательно разойдутся.
func GrantDefaultPlanTx(ctx context.Context, q *db.Queries, userID uuid.UUID, slug string) error {
	plan, err := q.PlanBySlug(ctx, slug)
	if err != nil {
		return fmt.Errorf("plan %q: %w", slug, err)
	}
	var endsAt *time.Time
	if plan.TrialDays > 0 {
		e := time.Now().Add(time.Duration(plan.TrialDays) * 24 * time.Hour)
		endsAt = &e
	}
	_, err = q.InsertSubscription(ctx, db.InsertSubscriptionParams{
		ID: uuid.New(), UserID: userID, PlanID: plan.ID, EndsAt: endsAt,
	})
	return err
}
```

Типы sqlc: `TrafficQuotaBytes` — `*int64` (`bigint NULL`), `EndsAt` — `*time.Time`. Обе
указательные формы обеспечивает `emit_pointers_for_null_types: true`, включённый в
`sqlc.yaml` в задаче 6; если генерация всё же даёт `pgtype.Int8`/`pgtype.Timestamptz`,
проверить этот флаг в том же файле, а не добавлять его здесь.

`internal/db/tx.go`:

```go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RunInTx выполняет fn в одном транзакционном контексте. sqlc-методы вызываются
// через q.WithTx(tx), поэтому транзакция — единственный способ собрать
// «advisory lock + count + insert» в один атомарный шаг.
func RunInTx(ctx context.Context, pool *pgxpool.Pool, fn func(*Queries) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) // no-op после Commit
	if err := fn(New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

`tx` удовлетворяет `DBTX` (pgx.Tx), поэтому `New(tx)` компилируется без прослоек.

- [ ] **Step 4: Интеграционный тест**

`tests/integration/entitlements_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
)

func TestEntitlementsForUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := db.New(pool(t))
	svc := entitlements.New(q)

	// Пользователь без подписки → явная ошибка, а не дефолтный лимит.
	userless := seedUserWithoutPlan(t, ctx, q)
	if _, err := svc.ForUser(ctx, userless); err == nil || !errorsIs(err, entitlements.ErrNoActiveSubscription) {
		t.Fatalf("ForUser(no subscription) = %v, want ErrNoActiveSubscription", err)
	}

	user := seedUser(t, ctx, q) // создаёт подписку internal-default (см. задачу 12, helpers)
	e, err := svc.ForUser(ctx, user)
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	if e.Slug != "internal-default" || e.DeviceLimit != 3 || e.ServerSelector != "all" {
		t.Errorf("unexpected entitlement: %+v", e)
	}
	if e.TrafficQuotaBytes != nil {
		t.Errorf("internal-default must be unlimited, quota = %d", *e.TrafficQuotaBytes)
	}
	if !e.AllowsDevice(2) || e.AllowsDevice(3) {
		t.Error("device counting is wrong at the boundary")
	}
}

func TestUnknownSelectorIsAnErrorNotATicket(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	if err := q.InsertPlan(ctx, db.InsertPlanParams{
		ID: uuid.New(), Slug: "selector-test-" + uuid.NewString()[:8],
		DeviceLimit: 5, ServerSelector: "country=DE",
	}); err != nil {
		t.Fatalf("InsertPlan: %v", err)
	}
	user := seedUserWithPlan(t, ctx, q, "selector-test-…")
	if _, err := entitlements.New(q).ForUser(ctx, user); err == nil {
		t.Fatal("selector 'country=DE' accepted in cycle A")
	}
}
```

`errorsIs` — `errors.Is`; `seedUserWithoutPlan`, `seedUserWithPlan` и запрос `InsertPlan`
дописываются в `tests/integration/helpers_test.go` и `internal/db/query/plans.sql`:

```sql
-- name: InsertPlan :one
INSERT INTO subscription_plans (id, slug, device_limit, server_selector, traffic_quota_bytes)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: PlanIDBySlug :one
SELECT id FROM subscription_plans WHERE slug = $1;
```

`seedUserWithPlan` берёт `PlanIDBySlug` и вставляет подписку; `seedUserWithoutPlan` —
`seedUser` без блока `InsertSubscription` (вынести в хелпере флаг `withPlan bool`).

- [ ] **Step 5: Прогнать и коммитить**

Run: `make unit && make sqlc-generate && make integration`
Expected: PASS. `TestUnknownSelectorIsAnErrorNotATicket` обязан упасть на нормализации, а
не на вставке: в этом смысл проверки.

```bash
git add internal/entitlements internal/db/tx.go internal/db tests/integration/entitlements_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(entitlements): права из плана с явной отказкой на неизвестный selector"
```

---

### Task 14: devices — каноничность публичного ключа WireGuard

**Files:**
- Create: `internal/devices/key.go`, `internal/devices/key_test.go`

**Interfaces:**
- Consumes: `encoding/base64`, `crypto/curve25519` (из stdlib, `crypto_curve25519` нет —
  используется `golang.org/x/crypto/curve25519`, там есть `X25519PublicKey`; в A-1 она **не**
  вызывается, см. примечание ниже).
- Produces: `devices.ParsePublicKey(b64 string) ([32]byte, error)`,
  `devices.ErrKeyNotBase64`, `devices.ErrKeyNotCanonical`, `devices.ErrKeyLength`,
  `devices.ValidPlatform(s string) bool`.

- [ ] **Step 1: Написать падающие тесты с конкретными векторами**

`internal/devices/key_test.go`:

```go
package devices

import (
	"encoding/base64"
	"strings"
	"testing"
)

// 32 байта нулей → канонический ключ из 43 'A' и '='.
const canonicalZeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestParseCanonicalKey(t *testing.T) {
	k, err := ParsePublicKey(canonicalZeros)
	if err != nil {
		t.Fatalf("canonical key rejected: %v", err)
	}
	if k != [32]byte{} {
		t.Fatalf("decoded key = %x", k)
	}
}

// 256 бит не делятся на 6: у последнего символа 2 spare-бита, и они обязаны быть нулём.
// 'A'→'B' выставляет бит — base64-декодер Go это молча проглатывает, поэтому
// повторное кодирование и есть проверка каноничности (спецификация §5.2).
func TestRejectsNonCanonicalLastChar(t *testing.T) {
	non := canonicalZeros[:42] + "B="
	if _, err := ParsePublicKey(non); err != ErrKeyNotCanonical {
		t.Fatalf("err = %v, want ErrKeyNotCanonical", err)
	}
	// Тот же трюк на предпоследнем символе: spare-битов нет, ключ валиден.
	if _, err := ParsePublicKey(canonicalZeros[:41] + "B" + canonicalZeros[42:]); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "   ", "not-base64-!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=",
		canonicalZeros[:42],            // без '=' → длина 43
		canonicalZeros + "=",           // длина 45
		strings.ToLower(canonicalZeros),
		base64.URLEncoding.EncodeToString(make([]byte, 32)) + "==", // url-safe форма
	} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRejectsNewlineAndWhitespaceInside(t *testing.T) {
	// Ключ с переносом строки — классика «пропустили из буфера обмена»:
	// StdEncoding.DecodeString его не примет, но проверка длины обязана отработать раньше.
	if _, err := ParsePublicKey(canonicalZeros[:20] + "\n" + canonicalZeros[20:]); err == nil {
		t.Fatal("key with newline accepted")
	}
}

func TestValidPlatform(t *testing.T) {
	for _, ok := range []string{"android", "ios", "windows", "macos", "linux", "other"} {
		if !ValidPlatform(ok) {
			t.Errorf("platform %q rejected", ok)
		}
	}
	for _, bad := range []string{"", "Android", "android ", "iphone", "WINDOWS"} {
		if ValidPlatform(bad) {
			t.Errorf("platform %q accepted", bad)
		}
	}
}
```

Вектор `canonicalZeros` в файле — 43 символа `A` и один `=`; при наборе проверить длиной
(`len(canonicalZeros) == 44`), иначе тест проверяет не каноничность, а опечатку.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `make unit`
Expected: FAIL — `undefined: ParsePublicKey`.

- [ ] **Step 3: Реализовать**

`internal/devices/key.go`:

```go
package devices

import (
	"encoding/base64"
	"errors"
)

const keyLen = 32

var (
	ErrKeyLength     = errors.New("wireguard public key must be 32 bytes")
	ErrKeyNotBase64  = errors.New("wireguard public key is not valid base64")
	ErrKeyNotCanonical = errors.New("wireguard public key is not canonical base64")
)

// platform — значение из ENUM device_platform (миграция 0001). Сверка здесь даёт
// 400 вместо 500 от БД; оба списка обязаны быть синхронны, и тест
// TestValidPlatform покрывает эту синхронизацию.
var platforms = map[string]struct{}{
	"android": {}, "ios": {}, "windows": {}, "macos": {}, "linux": {}, "other": {},
}

func ValidPlatform(s string) bool {
	_, ok := platforms[s]
	return ok
}

// ParsePublicKey принимает только канонический std-base64 публичного ключа.
// Повторное кодирование — не косметика: Go-декодер не смотрит на spare-биты, и
// два разных входа дали бы один и тот же ключ, а UNIQUE(user_id, public_key)
// в БД сравнивает строки.
func ParsePublicKey(b64 string) ([32]byte, error) {
	var out [32]byte
	if len(b64) != 44 || b64[43] != '=' {
		return out, ErrKeyLength
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return out, ErrKeyNotBase64
	}
	if len(raw) != keyLen {
		return out, ErrKeyLength
	}
	if base64.StdEncoding.EncodeToString(raw) != b64 {
		return out, ErrKeyNotCanonical
	}
	copy(out[:], raw)
	return out, nil
}
```

Проверка «ключ — валидная точка curve25519» в A-1 **не** делается: WireGuard принимает
любые 32 байта, а `ScalarMult` с малым порядком — это вопрос анализа ключа, который в
цикле A не используется (ядро отвергает недопустимые public values само). Если появится
требование валидации точек, оно попадёт в A-2 вместе с регистрацией узлов, где ключ узла
используется для расшифровки.

- [ ] **Step 4: Прогнать и коммитить**

Run: `make unit`
Expected: PASS.

```bash
git add internal/devices
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(devices): строгая каноничность публичного ключа и enum платформ"
```

---

### Task 15: devices — регистрация, список, жёсткий лимит устройств

**Files:**
- Create: `internal/devices/service.go`, `internal/devices/handlers.go`,
  `internal/httpx/decorators.go`, `internal/db/query/devices_lock.sql`,
  `tests/integration/devices_test.go`
- Modify: `internal/httpx/envelope.go` (коды `ErrDuplicateDevice`, `ErrDeviceLimitReached`
  уже объявлены — проверить)

**Interfaces:**
- Consumes: `devices.ParsePublicKey`/`ValidPlatform` (задача 14),
  `entitlements.Service.ForUser` (задача 13), `db.CountLiveDevices`, `db.InsertDevice`,
  `db.LiveDevicesByUser`, `db.DeviceByUserAndKey`, `db.DeviceByID`, `db.RunInTx`,
  `httpx.WithUserID`/`UserIDFromContext` (задача 9).
- Produces: `devices.NewService(pool *pgxpool.Pool, ent *entitlements.Service) *devices.Service`,
  `(*Service).Register(ctx, userID uuid.UUID, in devices.RegisterInput) (db.Device, error)`,
  `(*Service).List(ctx, userID uuid.UUID) ([]db.Device, error)`,
  `(*Service).OwnedBy(ctx, deviceID, userID uuid.UUID) (db.Device, error)`,
  `devices.RegisterInput{PublicKey string; Platform string; Name string}`,
  `devices.ErrDeviceLimit`, `devices.ErrDuplicateKey`, `devices.ErrForbiddenDevice`,
  `devices.NewHandler(svc *Service, idem *httpx.Idempotency) *devices.Handler`,
  `httpx.Decorators{Auth func(http.Handler) http.Handler; Anonymous func(http.Handler) http.Handler}`
  — контракт монтирования для всех модулей: сборщик передаёт две обёртки, модуль решает
  только, закрыт его маршрут или нет,
  `(*Handler).RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators)` —
  монтирует `POST /api/v1/devices` и `GET /api/v1/devices` под `dec.Auth`;
  запрос `db.LockUserForDeviceCount(ctx, userID uuid.UUID) error`
  (`pg_advisory_xact_lock(hashtextextended($1, 0))`).

`internal/httpx/decorators.go` — пять строк, но именно они закрывают вопрос «кто решает,
что публично»:

```go
package httpx

import "net/http"

// Decorators — обёртки, которые сборщик навешивает на маршруты модуля.
// Auth означает «доступ только аутентифицированному», Anonymous — «доступен всем,
// но не без лимита» (§5.2). Модуль не знает ни про JWT, ни про token bucket:
// он только выбирает, к какому классу относится маршрут.
//
// Контракт с двумя обёртками, а не с одной, появился из-за лимитов: если бы
// публичные маршруты монтировал сам модуль без обёртки, сборщику пришлось бы
// перемонтировать их второй раз — а ServeMux на повторный шаблон паникует.
type Decorators struct {
	Auth      func(http.Handler) http.Handler
	Anonymous func(http.Handler) http.Handler
}
```

`DELETE /devices/{id}` в этой задаче **не** появляется: отзыв устройства обязан снять
профили (§6, §7.2), а профилей в A-1 ещё нет. Заглушка с `revoked_at = now()` без снятия
выдачи была бы фиктивной реализацией (ТЗ §19.3), поэтому маршрут перенесён в A-2 целиком.

- [ ] **Step 1: Написать падающий интеграционный тест лимита**

`tests/integration/devices_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

func newDeviceSvc(t *testing.T) (*devices.Service, *db.Queries) {
	t.Helper()
	q := db.New(pool(t))
	return devices.NewService(pool(t), entitlements.New(q)), q
}

func keyAt(i int) string {
	// Ключ собирается из 32 raw-байт, а не правкой готовой строки. Причина ровно та
	// же, из-за которой валидатор задачи 14 существует: у 44-символьного base64
	// последнего символа два младших бита — spare, и в канонической кодировке они
	// нулевые. «Поменять букву» в строке — способ получить неканонический ключ,
	// который Register отклонит 400 вместо ожидаемого 201 или 409.
	raw := make([]byte, 32)
	copy(raw, "novavpn-integration-key-")
	raw[30], raw[31] = byte(i>>8), byte(i)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestDeviceLimitIsHard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	svc, q := newDeviceSvc(t)
	user := seedUser(t, ctx, q) // подписка internal-default, device_limit = 3

	for i := 0; i < 3; i++ {
		if _, err := svc.Register(ctx, user, devices.RegisterInput{
			PublicKey: keyAt(i), Platform: "linux", Name: "dev"}); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	_, err := svc.Register(ctx, user, devices.RegisterInput{
		PublicKey: keyAt(3), Platform: "linux", Name: "fourth"})
	if err == nil || !errorsIs(err, devices.ErrDeviceLimit) {
		t.Fatalf("4th device: err = %v, want ErrDeviceLimit", err)
	}

	// Тот же публичный ключ второй раз → duplicate, а не «тихо вернули первое устройство».
	if _, err := svc.Register(ctx, user, devices.RegisterInput{
		PublicKey: keyAt(0), Platform: "linux", Name: "dup"}); !errorsIs(err, devices.ErrDuplicateKey) {
		t.Errorf("duplicate key: err = %v, want ErrDuplicateKey", err)
	}

	// Чужое устройство недоступно по ID.
	other := seedUser(t, ctx, q)
	list, err := svc.List(ctx, other)
	if err != nil || len(list) != 0 {
		t.Errorf("other user sees %d devices (err=%v)", len(list), err)
	}
	if _, err := svc.OwnedBy(ctx, list0ID(t, ctx, user), other); !errorsIs(err, devices.ErrForbiddenDevice) {
		t.Errorf("OwnedBy cross-user = %v, want ErrForbiddenDevice", err)
	}
}

func list0ID(t *testing.T, ctx context.Context, user uuid.UUID) uuid.UUID {
	t.Helper()
	svc, _ := newDeviceSvc(t)
	list, err := svc.List(ctx, user)
	if err != nil || len(list) == 0 {
		t.Fatalf("no devices to reference: %v", err)
	}
	return list[0].ID
}

// Гонка на лимит: advisory lock в транзакции обязан не пустить четвёртого,
// сколько горутин ни пришло одновременно.
func TestConcurrentRegistrationRespectsLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	svc, q := newDeviceSvc(t)
	user := seedUser(t, ctx, q)

	var wg sync.WaitGroup
	var mu sync.Mutex
	limiterHits := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.Register(ctx, user, devices.RegisterInput{
				PublicKey: keyAt(100 + i), Platform: "linux", Name: "race"})
			if errorsIs(err, devices.ErrDeviceLimit) {
				mu.Lock()
				limiterHits++
				mu.Unlock()
				return
			}
			if err != nil {
				t.Errorf("register %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	live, err := db.New(pool(t)).CountLiveDevices(ctx, user)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if live != 3 {
		t.Errorf("live devices = %d, want exactly 3 (limit 3, 10 concurrent attempts)", live)
	}
	if limiterHits != 7 {
		t.Errorf("ErrDeviceLimit hits = %d, want 7", limiterHits)
	}
}

func TestHandlerMapsErrorsToCodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	svc, q := newDeviceSvc(t)
	user := seedUser(t, ctx, q)
	// dec здесь — сквозные обёртки: тест проверяет маппинг ошибок хендлера,
	// а не аутентификацию и не лимиты (они — в задачах 17 и 18).
	passthrough := func(next http.Handler) http.Handler { return next }
	dec := httpx.Decorators{Auth: passthrough, Anonymous: passthrough}
	mux := http.NewServeMux()
	devices.NewHandler(svc, nil).RegisterRoutes(mux, dec)
	var h http.Handler = mux
	post := func(body string, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		req = req.Clone(httpx.WithUserID(req.Context(), user))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	w := post(`{"public_key":"`+keyAt(0)+`","platform":"linux","name":"laptop"}`, uuid.NewString())
	if w.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", w.Code, w.Body)
	}
	// Невалидный ключ → 400 invalid_request с полем в details.
	w = post(`{"public_key":"not-a-key","platform":"linux","name":"x"}`, uuid.NewString())
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"public_key"`) {
		t.Fatalf("bad key: %d %s", w.Code, w.Body)
	}
	// Неизвестная платформа → 400.
	w = post(`{"public_key":"`+keyAt(1)+`","platform":"toaster","name":"x"}`, uuid.NewString())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad platform: %d %s", w.Code, w.Body)
	}
	// Отсутствие Idempotency-Key на POST /devices → 400 (спецификация §5.2).
	w = post(`{"public_key":"`+keyAt(2)+`","platform":"linux","name":"x"}`, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"idempotency_key_required"`) {
		t.Fatalf("missing idempotency key: %d %s", w.Code, w.Body)
	}
}
```

Тест `TestHandlerMapsErrorsToCodes` передаёт `nil` идемпотентность-хранилище; последний
блок обязан упасть именно на требовании ключа, поэтому `NewHandler` строит middleware
идемпотентности только когда `idem != nil`, а **проверку наличия заголовка** делает всегда
(см. шаг 3). Проверка с `nil` — не ленивость: она отделяет «ключ требуется» от
«ключ сохранён», и обе границы должны быть видны отдельно.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `make integration`
Expected: FAIL — `undefined: devices.NewService`, `undefined: devices.ErrDeviceLimit`.

- [ ] **Step 3: Реализовать сервис и хендлеры**

`internal/db/query/devices_lock.sql`:

```sql
-- name: LockUserForDeviceCount :exec
-- hashtextextended даёт bigint-ключ из uuid; lock держится до конца транзакции.
SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0));
```

Run: `make sqlc-generate` → метод `db.Queries.LockUserForDeviceCount(ctx, uuid.UUID)`;
если sqlc не выводит `$1::text` в `uuid`, передать `user.String()` и убрать каст —
главное, чтобы аргументом был один `uuid`/`text`, а не пара.

`internal/devices/service.go`:

```go
package devices

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
)

var (
	ErrDeviceLimit     = errors.New("device limit reached")
	ErrDuplicateKey    = errors.New("device with this public key already exists")
	ErrForbiddenDevice = errors.New("device belongs to another user")
	ErrInvalidKey      = errors.New("public key is invalid")
	ErrInvalidPlatform = errors.New("platform is invalid")
	ErrInvalidName     = errors.New("name must be 1..64 characters")
)

type RegisterInput struct {
	PublicKey string
	Platform  string
	Name      string
}

type Service struct {
	pool *pgxpool.Pool
	q    *db.Queries // читает без транзакции; пишущие пути берут tx внутри RunInTx
	ent  *entitlements.Service
}

func NewService(pool *pgxpool.Pool, ent *entitlements.Service) *Service {
	return &Service{pool: pool, q: db.New(pool), ent: ent}
}

// Register — единственное место, где жёсткая часть лимита устройств (спецификация §7.4):
// count и insert в одной транзакции под advisory lock пользователя. Без lock два
// параллельных запроса оба увидели бы «место есть».
func (s *Service) Register(ctx context.Context, userID uuid.UUID, in RegisterInput) (db.Device, error) {
	if _, err := ParsePublicKey(in.PublicKey); err != nil {
		return db.Device{}, ErrInvalidKey
	}
	if !ValidPlatform(in.Platform) {
		return db.Device{}, ErrInvalidPlatform
	}
	if l := len(in.Name); l < 1 || l > 64 {
		return db.Device{}, ErrInvalidName
	}

	ent, err := s.ent.ForUser(ctx, userID)
	if err != nil {
		return db.Device{}, err
	}

	var created db.Device
	err = db.RunInTx(ctx, s.pool, func(tx *db.Queries) error {
		if err := tx.LockUserForDeviceCount(ctx, userID); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}
		live, err := tx.CountLiveDevices(ctx, userID)
		if err != nil {
			return fmt.Errorf("count devices: %w", err)
		}
		if !ent.AllowsDevice(int(live)) {
			return ErrDeviceLimit
		}
		if existing, err := tx.DeviceByUserAndKey(ctx, db.DeviceByUserAndKeyParams{
			UserID: userID, PublicKey: in.PublicKey,
		}); err == nil && existing.RevokedAt == nil {
			return ErrDuplicateKey
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("lookup by key: %w", err)
		}
		created, err = tx.InsertDevice(ctx, db.InsertDeviceParams{
			ID: uuid.New(), UserID: userID, PublicKey: in.PublicKey,
			Platform: db.DevicePlatform(in.Platform), Name: in.Name,
		})
		if isUniqueViolation(err) {
			// Гонка между двумя запросами на (user_id, public_key).
			return ErrDuplicateKey
		}
		return err
	})
	if err != nil {
		return db.Device{}, err
	}
	return created, nil
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]db.Device, error) {
	return s.q.LiveDevicesByUser(ctx, userID)
}

// OwnedBy — проверка права на объект, а не только факта аутентификации (спецификация §5.2).
// Чужой устройство отдаётся той же ошибкой, что и несуществующий, чтобы не строить
// оракул «есть ли у кого-то такой id».
func (s *Service) OwnedBy(ctx context.Context, deviceID, userID uuid.UUID) (db.Device, error) {
	d, err := s.q.DeviceByID(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.Device{}, ErrForbiddenDevice
	}
	if err != nil {
		return db.Device{}, err
	}
	if d.UserID != userID {
		return db.Device{}, ErrForbiddenDevice
	}
	return d, nil
}
```

`isUniqueViolation` — в `internal/devices/errors.go` (`db.DevicePlatform` генерирует
sqlc в `internal/db/models.go`, здесь он только используется как тип поля
`InsertDeviceParams.Platform`):

```go
package devices

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// devices_user_key приходит как 23505. Это единственный уникальный индекс, в который
// может упереться вставка устройства, поэтому различать имена ограничений нечем —
// текст PgError.Constraint оставляем в логе, коду ошибки он не соответствует.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
```

`internal/devices/handlers.go`:

```go
package devices

import (
	"errors"
	"net/http"
	"time"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

type Handler struct {
	svc  *Service
	idem *httpx.Idempotency
}

func NewHandler(svc *Service, idem *httpx.Idempotency) *Handler {
	return &Handler{svc: svc, idem: idem}
}

type deviceView struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"public_key"`
	Platform  string    `json:"platform"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  *time.Time `json:"last_seen_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func toView(d db.Device) deviceView {
	return deviceView{ID: d.ID.String(), PublicKey: d.PublicKey, Platform: string(d.Platform),
		Name: d.Name, CreatedAt: d.CreatedAt, LastSeen: d.LastSeenAt, RevokedAt: d.RevokedAt}
}
// RegisterRoutes — единый для всех модулей способ монтирования (контракт и файл
// internal/httpx/decorators.go — в начале этой задачи): сборщик передаёт ServeMux и
// две обёртки, модуль решает только то, какой из его маршрутов закрыт. Оба маршрута
// устройств закрыты, поэтому оба под dec.Auth.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	mux.Handle("POST /api/v1/devices", dec.Auth(http.HandlerFunc(h.register)))
	mux.Handle("GET /api/v1/devices", dec.Auth(http.HandlerFunc(h.list)))
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	// Идемпотентность включается только с реальным хранилищем; требование заголовка
	// при этом проверяется всегда — иначе тест с nil-хранилищем проходил бы молча.
	if r.Header.Get("Idempotency-Key") == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrIdempotencyKeyRequired,
			"Idempotency-Key is required for device registration", nil)
		return
	}
	var wrapped http.Handler = http.HandlerFunc(h.registerInner)
	if h.idem != nil {
		wrapped = h.idem.Middleware("device_create")(http.HandlerFunc(h.registerInner))
	}
	wrapped.ServeHTTP(w, r)
}

func (h *Handler) registerInner(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "authentication required", nil)
		return
	}
	var in struct {
		PublicKey string `json:"public_key"`
		Platform  string `json:"platform"`
		Name      string `json:"name"`
	}
	if err := httpx.DecodeJSON(r, &in, 1<<14); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest, "invalid request body", nil)
		return
	}
	d, err := h.svc.Register(r.Context(), userID, RegisterInput{
		PublicKey: in.PublicKey, Platform: in.Platform, Name: in.Name,
	})
	switch {
	case err == nil:
		_ = httpx.WriteJSON(w, http.StatusCreated, toView(d))
	case errors.Is(err, ErrInvalidKey):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"public_key must be canonical base64 of 32 bytes",
			map[string]any{"field": "public_key"})
	case errors.Is(err, ErrInvalidPlatform):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"unsupported platform", map[string]any{"field": "platform"})
	case errors.Is(err, ErrInvalidName):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"name must be 1..64 characters", map[string]any{"field": "name"})
	case errors.Is(err, ErrDeviceLimit):
		lim := 0
		if e, err := h.svc.ent.ForUser(r.Context(), userID); err == nil {
			lim = e.DeviceLimit
		}
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrDeviceLimitReached,
			"device limit reached for this plan", map[string]any{"limit": lim})
	case errors.Is(err, ErrDuplicateKey):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrDuplicateDevice,
			"a device with this public key already exists", nil)
	case errors.Is(err, entitlements.ErrNoActiveSubscription):
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrForbidden,
			"no active subscription", nil)
	default:
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "internal error", nil)
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "authentication required", nil)
		return
	}
	items, err := h.svc.List(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "internal error", nil)
		return
	}
	out := make([]deviceView, 0, len(items))
	for _, d := range items {
		out = append(out, toView(d))
	}
	_ = httpx.WriteJSON(w, http.StatusOK, map[string]any{"devices": out})
}
```

- [ ] **Step 4: Прогнать**

Run: `make up-dev && make sqlc-generate && make unit && make integration`
Expected: PASS. В `TestConcurrentRegistrationRespectsLimit` `live == 3` обязан выполняться
при `-race`; `make integration` ниже запускается с `-race`.

- [ ] **Step 5: Коммит**

```bash
git add internal/devices internal/db/query/devices_lock.sql internal/db
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(devices): регистрация с жёстким лимитом под advisory lock и списком"
```

---

### Task 16: Публичный контракт API (OpenAPI) до реализации маршрутов

**Files:**
- Create: `api-spec/openapi.yaml`, `api-spec/contract_test.go`
- Modify: `internal/httpx/envelope.go` (три кода, которых требует контракт),
  `Makefile` (цель `api-lint`), `go.mod`/`go.sum` (`gopkg.in/yaml.v3`)

**Interfaces:**
- Consumes: envelope из задачи 7 (`WriteError`), коды `httpx.ErrorCode`, формы ответов
  задач 12–15.
- Produces: файл `api-spec/openapi.yaml` — источник истины для маршрутов A-1; коды
  `httpx.ErrInvalidCredentials`, `httpx.ErrRefreshTokenInvalid`, `httpx.ErrEmailTaken`;
  цель `make api-lint`.

Спецификация §9 требует contract-first (`api-spec/openapi.yaml`, ТЗ §10). Это значит, что
на момент этой задачи контракта **больше**, чем кода: `POST /auth/login` уже описан, а
хендлера ещё нет. Следующая задача обязана отдать ровно то, что обещано здесь, и проверка
этого — не глаз, а тест (задача 19 сравнивает живые ответы со схемами).

Отступление от строки «генерация через `oapi-codegen`» (спецификация §5.1) фиксируется
открыто, а не тихо:

> `oapi-codegen` в режиме `strict-server` генерирует и маршрутизацию, и собственный слой
> валидации, который отдаёт ошибки в **своём** формате. Спецификация §5.2 требует единый
> envelope `{"error":{code,message,details,request_id}}` на всех маршрутах, включая
> транспортные отказы. Поэтому контракт в этом плане — источник истины по **формам и кодам**
> (он линчуется и проверяется тестами соответствия), а маршрутизация остаётся на
> `net/http.ServeMux`. Правка строки §5.1 «генерация через oapi-codegen» в
> спецификацию вносится этим же коммитом.

- [ ] **Step 1: Написать контракт**

`api-spec/openapi.yaml`:

```yaml
openapi: "3.1.0"
info:
  title: NovaVPN control plane — публичный API цикла A
  version: "1.0.0"
  description: >
    Контракт первой поставки. Маршруты узла (/internal/v1) и выдачи профилей появляются
    в A-2; здесь только идентификация, сессии и устройства. Числовые поля каталога
    (задержка, загрузка, доступность) здесь отсутствуют сознательно: до замеров на реальном
    узле их нечем наполнить, а спецификация §13.4 запрещает подставлять вместо них ноль.
servers:
  - url: https://api.novavpn.local
tags:
  - name: auth
  - name: devices
paths:
  /api/v1/auth/register:
    post:
      tags: [auth]
      operationId: register
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/Credentials" }
      responses:
        "201":
          description: Аккаунт создан, сессия выдана.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Session" }
        "400": { $ref: "#/components/responses/InvalidRequest" }
        "409":
          description: Email уже зарегистрирован.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [email_taken] }
        "429": { $ref: "#/components/responses/RateLimited" }
        "500": { $ref: "#/components/responses/Internal" }
  /api/v1/auth/login:
    post:
      tags: [auth]
      operationId: login
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/Credentials" }
      responses:
        "200":
          description: Сессия выдана.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Session" }
        "400": { $ref: "#/components/responses/InvalidRequest" }
        "401":
          description: Неверный email или пароль — один ответ на оба случая.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [invalid_credentials] }
        "403":
          description: Учётная запись заблокирована администратором.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [account_locked] }
        "429": { $ref: "#/components/responses/RateLimited" }
        "500": { $ref: "#/components/responses/Internal" }
  /api/v1/auth/refresh:
    post:
      tags: [auth]
      operationId: refresh
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RefreshRequest" }
      responses:
        "200":
          description: Новая пара токенов; предъявленный refresh перестал быть действующим.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Session" }
        "400": { $ref: "#/components/responses/InvalidRequest" }
        "401":
          description: >
            Refresh не принят: токен не разобран, семья не найдена, семья отозвана или
            секрет переиспользован. Различия в журнале, наружу — один код, чтобы по
            ответу нельзя было определить, какой семьи существуют.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [refresh_token_invalid] }
        # 403 здесь обязателен: Rotate читает статус пользователя (задача 17, шаг 4), и
        # заблокированный аккаунт не продлевает доступ. Без этой строки живой ответ 403
        # не был бы описан контрактом, а контракт-first на этом маршруте теряет смысл.
        "403":
          description: Учётная запись заблокирована — новая пара не выдаётся.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [account_locked] }
        "429": { $ref: "#/components/responses/RateLimited" }
        "500": { $ref: "#/components/responses/Internal" }
  /api/v1/auth/logout:
    post:
      tags: [auth]
      operationId: logout
      description: >
        Отзыв семьи refresh. Аутентификации по access-токену не требует: отзыв обязан
        сработать и когда access уже просрочен. Действующее доказательство владения
        сессией — сам refresh-токен в теле.
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RefreshRequest" }
      responses:
        "204": { description: Семья отозвана. Тело отсутствует. }
        "400": { $ref: "#/components/responses/InvalidRequest" }
        "401":
          description: Refresh не разобран или семья не найдена.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [refresh_token_invalid] }
        # 429 есть у всех четырёх публичных маршрутов, включая logout: он тоже
        # монтируется под dec.Anonymous (задача 18), и «отзыв на скорость» лимитируется
        # наравне с перебором семей.
        "429": { $ref: "#/components/responses/RateLimited" }
        "500": { $ref: "#/components/responses/Internal" }
  /api/v1/me:
    get:
      tags: [auth]
      operationId: getMe
      security: [{ bearerAuth: [] }]
      responses:
        "200":
          description: Пользователь, план и использование устройств.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Me" }
        "401": { $ref: "#/components/responses/Unauthenticated" }
        # 429 — окно на пользователя (dec.Auth в задаче 18): закрытые маршруты тоже
        # лимитируются, и контракт обязан это показывать.
        "429": { $ref: "#/components/responses/RateLimited" }
        "500": { $ref: "#/components/responses/Internal" }
  /api/v1/devices:
    post:
      tags: [devices]
      operationId: createDevice
      security: [{ bearerAuth: [] }]
      parameters:
        - $ref: "#/components/parameters/IdempotencyKey"
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/DeviceCreate" }
      responses:
        "201":
          description: Устройство зарегистрировано.
          headers:
            Idempotency-Replayed:
              description: Присутствует при повторе того же ключа.
              schema: { type: string, enum: ["true"] }
          content:
            application/json:
              schema: { $ref: "#/components/schemas/Device" }
        "400": { $ref: "#/components/responses/InvalidRequest" }
        "401": { $ref: "#/components/responses/Unauthenticated" }
        "403":
          description: Активной подписки нет — прав на устройства не кому дать.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [forbidden] }
        "409":
          description: >
            Лимит устройств по тарифу, дубликат публичного ключа либо конфликт
            Idempotency-Key.
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code:
                            enum:
                              - device_limit_reached
                              - duplicate_device
                              - idempotency_key_conflict
                              - idempotency_key_in_progress
        "429": { $ref: "#/components/responses/RateLimited" }
        "500": { $ref: "#/components/responses/Internal" }
    get:
      tags: [devices]
      operationId: listDevices
      security: [{ bearerAuth: [] }]
      responses:
        "200":
          description: Все устройства пользователя, включая отозванные.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/DeviceList" }
        "401": { $ref: "#/components/responses/Unauthenticated" }
        # 429 — окно на пользователя (dec.Auth в задаче 18): закрытые маршруты тоже
        # лимитируются, и контракт обязан это показывать.
        "429": { $ref: "#/components/responses/RateLimited" }
        "500": { $ref: "#/components/responses/Internal" }
components:
  securitySchemes:
    bearerAuth: { type: http, scheme: bearer, bearerFormat: JWT }
  parameters:
    IdempotencyKey:
      name: Idempotency-Key
      in: header
      required: true
      description: Ключ повторозащищённости (спецификация §5.2). Без него запрос отклоняется.
      schema: { type: string, minLength: 1, maxLength: 200 }
  responses:
    InvalidRequest:
      description: Тело или поле не прошло валидацию.
      content:
        application/json:
          schema:
            allOf:
              - $ref: "#/components/schemas/Error"
              - properties:
                  error:
                    properties:
                      code: { enum: [invalid_request, idempotency_key_required] }
    Unauthenticated:
      description: Access-токен отсутствует, недействителен или в denylist.
      content:
        application/json:
          schema:
            allOf:
              - $ref: "#/components/schemas/Error"
              - properties:
                  error:
                    properties:
                      code: { enum: [unauthenticated] }
    RateLimited:
      description: Превышен token bucket. Повторять раньше Retry-After нельзя.
      headers:
        Retry-After: { schema: { type: integer } }
      content:
        application/json:
          schema:
            allOf:
              - $ref: "#/components/schemas/Error"
              - properties:
                  error:
                    properties:
                      code: { enum: [rate_limited] }
    Internal:
      description: Внутренняя ошибка. Детали — только в журнале по request_id.
      content:
        application/json:
          schema:
            allOf:
              - $ref: "#/components/schemas/Error"
              - properties:
                  error:
                    properties:
                      code: { enum: [internal] }
  schemas:
    Error:
      type: object
      required: [error]
      properties:
        error:
          type: object
          # details отсутствует, когда уточнять нечего; потому его нет в required.
          required: [code, message, request_id]
          properties:
            code: { $ref: "#/components/schemas/ErrorCode" }
            message: { type: string }
            details: { type: object, additionalProperties: true }
            request_id: { type: string, pattern: "^[0-9a-f]{16}$" }
    ErrorCode:
      type: string
      enum:
        - invalid_request
        - unauthenticated
        - account_locked
        - forbidden
        - not_found
        - method_not_allowed
        - conflict
        - device_limit_reached
        - duplicate_device
        - idempotency_key_required
        - idempotency_key_conflict
        - idempotency_key_in_progress
        - rate_limited
        - internal
        - invalid_credentials
        - refresh_token_invalid
        - email_taken
    Credentials:
      type: object
      required: [email, password]
      properties:
        email: { type: string, format: email, maxLength: 254 }
        password: { type: string, minLength: 10, maxLength: 1024 }
    RefreshRequest:
      type: object
      required: [refresh_token]
      properties:
        refresh_token: { type: string, minLength: 40, maxLength: 512 }
    Session:
      type: object
      # token_type зафиксирован: клиент не должен угадывать схему Authorization.
      required: [access_token, refresh_token, token_type, access_expires_at, refresh_expires_at]
      properties:
        access_token: { type: string }
        refresh_token: { type: string }
        token_type: { type: string, enum: [Bearer] }
        access_expires_at: { type: string, format: date-time }
        refresh_expires_at: { type: string, format: date-time }
    DeviceCreate:
      type: object
      required: [public_key, platform, name]
      properties:
        public_key: { type: string, pattern: "^[A-Za-z0-9+/]{43}=$" }
        platform:
          type: string
          enum: [android, ios, windows, macos, linux, other]
        name: { type: string, minLength: 1, maxLength: 64 }
    Device:
      type: object
      required: [id, public_key, platform, name, created_at]
      properties:
        id: { type: string, format: uuid }
        public_key: { type: string, pattern: "^[A-Za-z0-9+/]{43}=$" }
        platform:
          type: string
          enum: [android, ios, windows, macos, linux, other]
        name: { type: string }
        created_at: { type: string, format: date-time }
        last_seen_at: { type: ["string", "null"], format: date-time }
        revoked_at: { type: ["string", "null"], format: date-time }
    DeviceList:
      type: object
      required: [devices]
      properties:
        devices:
          type: array
          items: { $ref: "#/components/schemas/Device" }
    Me:
      type: object
      required: [user, plan, devices]
      properties:
        user:
          type: object
          required: [id, email, status, locale, created_at]
          properties:
            id: { type: string, format: uuid }
            email: { type: string }
            display_name: { type: ["string", "null"] }
            status: { type: string, enum: [active, locked, deleted] }
            locale: { type: string }
            created_at: { type: string, format: date-time }
        plan:
          # null — активной подписки нет (истекла или не была выдана). /me описывает
          # состояние аккаунта, а не выдаёт право, поэтому здесь данные, а не отказ:
          # 403 на «подписка кончилась» был бы неправдой про доступ.
          type: ["object", "null"]
          required: [slug, device_limit, traffic_quota_bytes]
          properties:
            slug: { type: string }
            device_limit: { type: integer, minimum: 1 }
            # NULL = без квоты. Именно null, а не 0: ноль читается как «трафик кончился».
            traffic_quota_bytes: { type: ["integer", "null"] }
        devices:
          type: object
          required: [live, limit]
          properties:
            live: { type: integer, minimum: 0 }
            # 0 — подписки нет, и права на устройства тоже (ср. POST /devices: 403).
            # Минимум не может быть 1, иначе истёкший аккаунт не описывается контрактом.
            limit: { type: integer, minimum: 0 }
```

Оговорка по `password.minLength: 10`: JSON Schema считает символы, `auth.HashPassword` —
байты (UTF-8). Для кириллицы и иероглифов байтов больше, поэтому проверка в Go строже, а
не мягче: контракт обещает нижнюю границу, код её держит с запасом. Менять `MinPasswordLen`
на «символы» нельзя без замера стоимости argon2-проверки на целевом узле (задача 10).

Здесь нет маршрутов `/devices/{id}`, `/devices/{id}/keys/rotate`, `/servers`,
`/devices/{id}/profiles*` и `/api/v1/admin/*`: их не на чем описать в A-1 (профилей,
узлов и админ-роли ещё нет), а пустая схема-обещание была бы ровно той фиктивной
реализацией, которую запрещает ТЗ §19.3. A-2 и последующие планы допишут контракт тем же
порядком — сначала файл, потом код.

- [ ] **Step 2: Тест, что контракт не расходится с транспортным слоем**

`api-spec/contract_test.go` — три проверки, ни одна не требует живой базы:

```go
package api_spec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/novavpn/novavpn/internal/httpx"
)

type spec struct {
	Paths    map[string]map[string]any `yaml:"paths"`
	Comp struct {
		Schemas map[string]struct {
			Type       string `yaml:"type"`
			Required   []string `yaml:"required"`
			Properties map[string]any `yaml:"properties"`
			Enum       []string `yaml:"enum"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func load(t *testing.T) spec {
	t.Helper()
	// Тест запускается из каталога пакета (go test ./...), поэтому путь относительный.
	raw, err := os.ReadFile(filepath.Join("openapi.yaml"))
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse contract: %v", err)
	}
	return s
}

// 1. Каждый задекларированный код существует как константа httpx. Переименование
// в Go сломает компиляцию теста, удаление из контракта — этот тест.
func TestContractCodesAreDeclared(t *testing.T) {
	s := load(t)
	declared := map[string]httpx.ErrorCode{
		"invalid_request":            httpx.ErrInvalidRequest,
		"unauthenticated":            httpx.ErrUnauthenticated,
		"account_locked":             httpx.ErrAccountLocked,
		"forbidden":                  httpx.ErrForbidden,
		"not_found":                  httpx.ErrNotFound,
		"method_not_allowed":         httpx.ErrMethodNotAllowed,
		"conflict":                   httpx.ErrConflict,
		"device_limit_reached":       httpx.ErrDeviceLimitReached,
		"duplicate_device":           httpx.ErrDuplicateDevice,
		"idempotency_key_required":   httpx.ErrIdempotencyKeyRequired,
		"idempotency_key_conflict":   httpx.ErrIdempotencyConflict,
		"idempotency_key_in_progress": httpx.ErrIdempotencyInProgress,
		"rate_limited":               httpx.ErrRateLimited,
		"internal":                   httpx.ErrInternal,
		"invalid_credentials":        httpx.ErrInvalidCredentials,
		"refresh_token_invalid":      httpx.ErrRefreshTokenInvalid,
		"email_taken":                httpx.ErrEmailTaken,
	}
	for _, name := range s.Comp.Schemas["ErrorCode"].Enum {
		v, ok := declared[name]
		if !ok {
			t.Errorf("contract declares code %q with no httpx constant", name)
			continue
		}
		if string(v) != name {
			t.Errorf("code %q: httpx constant is %q", name, v)
		}
	}
	for name, v := range declared {
		if string(v) != name {
			t.Errorf("httpx constant %q drifted from contract name %q", v, name)
		}
	}
}

// 2. Фактический вывод WriteError совпадает с обязательными полями схемы Error.
func TestErrorEnvelopeMatchesContract(t *testing.T) {
	s := load(t)
	errSchema := s.Comp.Schemas["Error"]
	// Вложенный object в yaml.v3 лежит в Properties["error"]; required читаем с него.
	var nested struct {
		Required []string `yaml:"required"`
	}
	raw, _ := yaml.Marshal(errSchema.Properties["error"])
	if err := yaml.Unmarshal(raw, &nested); err != nil {
		t.Fatalf("nested error: %v", err)
	}
	want := map[string]bool{}
	for _, f := range nested.Required {
		want[f] = true
	}
	if len(want) == 0 {
		t.Fatal("Error.error has no required fields in the contract")
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r = r.WithContext(withRequestID(t, r.Context()))
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrInvalidCredentials, "nope", nil)

	var body struct {
		Error map[string]json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	for f := range want {
		if _, ok := body.Error[f]; !ok {
			t.Errorf("contract requires error.%s, WriteError did not emit it", f)
		}
	}
	for f := range body.Error {
		if !want[f] && f != "details" {
			t.Errorf("WriteError emitted error.%s, which the contract does not document", f)
		}
	}
}

// 3. Все пути публичные: /internal/v1 в этом файлу неоткуда взяться (узловой контракт — A-2).
func TestAllPathsArePublicV1(t *testing.T) {
	s := load(t)
	if len(s.Paths) == 0 {
		t.Fatal("contract has no paths")
	}
	for p := range s.Paths {
		if len(p) < 8 || p[:8] != "/api/v1/" {
			t.Errorf("path %q is not under /api/v1/", p)
		}
	}
	// 6 маршрутов A-1: register, login, refresh, logout, me, devices.
	if len(s.Paths) != 6 {
		t.Errorf("paths = %d, want 6 for cycle A-1", len(s.Paths))
	}
}
```

`withRequestID` — в том же файле; `requestIDKey` неэкспортируем, поэтому тест берёт
готовый middleware, а не конструирует контекст в обход него.

```go
func withRequestID(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	var got context.Context
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	httpx.NewRequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), req)
	if httpx.RequestIDFromContext(got) == "" {
		t.Fatal("request id middleware produced no request id")
	}
	return got
}
```

- [ ] **Step 3: Добавить четыре кода в httpx**

`internal/httpx/envelope.go`, в тот же `const`-блок:

```go
	// Auth-коды (задача 17) и регистрация (задача 16). Добавляются, а не заменяются:
	// клиент, который видел invalid_credentials, не должен получить вместо него generic.
	ErrInvalidCredentials   ErrorCode = "invalid_credentials"
	ErrRefreshTokenInvalid  ErrorCode = "refresh_token_invalid"
	ErrEmailTaken           ErrorCode = "email_taken"
	// 405 пишет сборщик из задачи 18: ServeMux отвечает 405 без тела, а §5.2 требует
	// конверт на любой ошибке. Код объявляется здесь, вместе с перечнем в контракте,
	// иначе тест «код контракта == константа Go» не увидит расхождение до задачи 18.
	ErrMethodNotAllowed     ErrorCode = "method_not_allowed"
```

- [ ] **Step 4: Линт контракта и `make api-lint`**

`Makefile`, добавить цель (образ pinned — тег, который реально разрешился при первом
запуске, записывается в файл, а не остаётся `latest`):

```make
API_IMAGE ?= redocly/cli:1.34

api-lint:
	docker run --rm -v "$(CURDIR)/api-spec:/spec" $(API_IMAGE) lint /spec/openapi.yaml
```

Run: `make api-lint`
Expected: `openapi.yaml: parsed` без ошибок; если линт требует `operationId` на каждом
методе или жалуется на `3.1.0` — править YAML, а не отключать правило в конфиге:
отключённое правило — это контракт, который перестали проверять.

Run: `make mod && make unit`
Expected: PASS (три теста пакета `api-spec`; `gopkg.in/yaml.v3` добавлен в `go.mod`).

- [ ] **Step 5: Правка спецификации тем же коммитом**

В [docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md](../specs/2026-10-20-novavpn-cycle-a-access-core-design.md)
в §5.1 после строки про `api-spec/openapi.yaml` записать фактическое разграничение:
контракт — источник истины по формам, кодам и обязательности заголовков; маршрутизацию
генерировать не через `oapi-codegen`, потому что §5.2 требует единый envelope ошибок,
а генератор добавляет свой слой валидации; соответствие живых ответов схемам проверяется
тестом (задача 19), а не eyeball-ревью.

Там же, в §5.2, в пункте про идемпотентность дописать второй код: повтор с тем же ключом,
пока первый запрос не завершён, — `409 idempotency_key_in_progress` (код введён задачей 9,
в контракте он с шага 1 этой задачи). Список кодов в §5.2 и перечень в `responses` контракта
после этого шага обязаны совпадать буквально: расхождение в документах — это обещание,
которого код не выполняет.

```bash
git add api-spec internal/httpx/envelope.go Makefile go.mod go.sum \
  docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(api): openapi-контракт маршрутов A-1 и проверка соответствия envelope"
```

---

### Task 17: auth — HTTP-слой: регистрация, вход, refresh, logout, `/me`

**Files:**
- Create: `internal/auth/login_guard.go`, `internal/auth/middleware.go`,
  `internal/auth/handlers.go`, `internal/auth/middleware_test.go`,
  `tests/integration/auth_flow_test.go`
- Modify: `internal/auth/refresh.go` (ротация обязана проверять статус пользователя —
  иначе блокировка из ТЗ §9 не останавливает продление сессий)

**Interfaces:**
- Consumes: `auth.SessionService`, `auth.Session` (задача 12), `auth.Denylist`, `auth.Issuer`,
  `auth.Claims` (задача 11), `auth.HashPassword`/`VerifyPassword`/`ErrWeakPassword`/
  `MinPasswordLen` (задача 10), `db.InsertUser`, `db.UserByEmail`, `db.UserByID`,
  `db.LockUser`, `db.PlanBySlug`, `db.InsertSubscription`, `db.CountLiveDevices`,
  `db.RunInTx` (задачи 6, 13),
  `httpx.{WriteError,WriteJSON,DecodeJSON,WithUserID,UserIDFromContext,NewRequestID,RequestIDFromContext}`
  и коды `ErrInvalidCredentials`, `ErrRefreshTokenInvalid`, `ErrEmailTaken` (задача 16).
- Produces:
  `auth.NewLoginGuard(rdb *redis.Client, log *slog.Logger) *auth.LoginGuard`,
  `(*LoginGuard).Delay(ctx context.Context, email, ip string) time.Duration`,
  `(*LoginGuard).Reset(ctx context.Context, email, ip string)`,
  `auth.Middleware(sess *SessionService, deny Denylist) func(http.Handler) http.Handler`,
  `auth.ClientIP(r *http.Request) *netip.Addr`,
  `auth.Bearer(r *http.Request) string`,
  `auth.NewHandler(sess *SessionService, pool *pgxpool.Pool, ent *entitlements.Service, guard *LoginGuard, planSlug string, log *slog.Logger) *auth.Handler`,
  `(*Handler).RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators)` —
  `POST /api/v1/auth/{register,login,refresh,logout}` под `dec.Anonymous`,
  `GET /api/v1/me` под `dec.Auth` (контракт `httpx.Decorators` — из задачи 15).
- Потребляется, но остаётся наружу (задачи 15/18 монтируют свои маршруты тем же способом):
  `entitlements.GrantDefaultPlanTx(ctx, q *db.Queries, userID uuid.UUID, slug string) error`
  из задачи 13, `auth.ErrInvalidRefreshToken` / `ErrExpiredRefreshToken` / `ErrAccountLocked`
  из задачи 12 — последний теперь возвращает `Rotate`.

Формы ответов и коды ошибок уже обещаны контрактом из задачи 16 — здесь они не
придумываются, а выполняются.

Форма регистрации маршрутов выбрана одна для всех модулей и она же правит задачу 15:
модуль сам объявляет, какие его маршруты требуют аутентификации, через параметр `authz`,
а `*http.ServeMux` ему передаёт сборщик (задача 18). Причина, по которой нельзя отдать
каждому модулю `Routes() http.Handler` и смонтировать их рядом: `ServeMux` падает на
второй регистрации шаблона `"/"`, а без него смонтировать готовый `http.Handler` нельзя.
Предпочтительнее падение паникой, чем тихий перехват чужих путей, поэтому вариант
отклонён, а не обходится.

- [ ] **Step 1: Сквозной интеграционный тест пути сессий**

`tests/integration/auth_flow_test.go` требует живой PostgreSQL и Redis, поэтому тег
`integration`. Тест идёт через `httptest.NewServer`, то есть по настоящему HTTP, а не
вызовом хендлеров: заодно проверяются заголовок `Authorization`, коды статусов и форма
envelope (критерии приёмки §1.3.1 и §1.3.2).

```go
//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

const testPassword = "integration-password-1"

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newAuthServer собирает ровно тот граф, который соберёт задача 18: единый ServeMux,
// публичные маршруты под dec.Anonymous, приватные — под dec.Auth. В этом тесте обе
// обёртки сквозные, кроме Auth: без проверки access JWT тест не мог бы отличить 401
// от «забыли обёртку».
func newAuthServer(t *testing.T) (*httptest.Server, *db.Queries) {
	t.Helper()
	p := pool(t)
	q := db.New(p)
	iss := auth.NewIssuer(bytes32ForTests(), 10*time.Minute)
	deny := auth.NewRedisDenylist(redisClient(t), discardLog())
	sess := auth.NewSessionService(q, iss, deny, 24*time.Hour, discardLog())
	guard := auth.NewLoginGuard(redisClient(t), discardLog())
	h := auth.NewHandler(sess, p, entitlements.New(q), guard, "internal-default", discardLog())

	passthrough := func(next http.Handler) http.Handler { return next }
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, httpx.Decorators{
		Auth:      auth.Middleware(sess, deny),
		Anonymous: passthrough,
	})
	srv := httptest.NewServer(httpx.NewRequestID(mux))
	t.Cleanup(srv.Close)
	return srv, q
}
```

Дальше — хелперы ответа и тело теста:

```go
type sessionResp struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func decodeSession(t *testing.T, body map[string]any) sessionResp {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	var s sessionResp
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("session shape: %v", err)
	}
	if s.AccessToken == "" || s.RefreshToken == "" {
		t.Fatalf("empty session: %+v", s)
	}
	return s
}

func jsonBody(v any) io.Reader {
	raw, _ := json.Marshal(v)
	return bytes.NewReader(raw)
}

func do(t *testing.T, method, url string, body any, bearer string) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = jsonBody(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("body %q is not JSON", data)
		}
	}
	return resp, out
}

// 16 hex символов — формат request_id из httpx.newRequestID.
func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}

func errorCode(t *testing.T, body map[string]any) string {
	t.Helper()
	e, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no error envelope: %v", body)
	}
	if id, ok := e["request_id"].(string); !ok || !isHex16(id) {
		t.Errorf("error envelope request_id %v must be 16 hex chars", e["request_id"])
	}
	code, _ := e["code"].(string)
	return code
}

// envelopePair — «code|message» из конверта без request_id. Нужен ровно для одного:
// сравнить два отказа как «одинаковый ответ», не сравнив при этом случайное.
func envelopePair(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	return fmt.Sprint(e["code"], "|", e["message"])
}
```

Тело первого теста — весь путь сессии, включая переиспользование refresh и отзыв:

```go
func TestRegisterThenRotateThenLogoutDeniesAccess(t *testing.T) {
	srv, q := newAuthServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base := srv.URL + "/api/v1"

	email := "flow-" + uuid.NewString()[:8] + "@novavpn.test"
	resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, body)
	}
	sess := decodeSession(t, body)
	if sess.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", sess.TokenType)
	}
	// Access обязан истекать раньше refresh, иначе TTL 10 минут нигде не проверяется.
	if !sess.AccessExpiresAt.Before(sess.RefreshExpiresAt) {
		t.Errorf("access_expires_at %v not before refresh_expires_at %v",
			sess.AccessExpiresAt, sess.RefreshExpiresAt)
	}

	resp, body = do(t, http.MethodGet, base+"/me", nil, sess.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: %d %v", resp.StatusCode, body)
	}
	user := body["user"].(map[string]any)
	if user["email"] != email || user["status"] != "active" {
		t.Errorf("me.user = %v", user)
	}
	plan := body["plan"].(map[string]any)
	if plan["slug"] != "internal-default" || plan["device_limit"].(float64) != 3 {
		t.Errorf("plan after register = %v", plan)
	}
	// Внутренний план без квоты: null, а не 0 (спецификация §13.4, ТЗ §19.3).
	if q, ok := plan["traffic_quota_bytes"]; !ok || q != nil {
		t.Errorf("internal-default is unlimited: traffic_quota_bytes = %v (ok=%v), want null", q, ok)
	}
	usage := body["devices"].(map[string]any)
	if usage["live"].(float64) != 0 || usage["limit"].(float64) != 3 {
		t.Errorf("devices usage = %v, want live=0 limit=3", usage)
	}

	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": sess.RefreshToken}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", resp.StatusCode, body)
	}
	rotated := decodeSession(t, body)
	if rotated.RefreshToken == sess.RefreshToken || rotated.AccessToken == sess.AccessToken {
		t.Error("refresh returned the same pair")
	}

	// Старый refresh = предъявление не текущего секрета живущей семьи → гасится вся семья.
	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": sess.RefreshToken}, "")
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "refresh_token_invalid" {
		t.Fatalf("reuse of old refresh: %d %v", resp.StatusCode, body)
	}
	resp, _ = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": rotated.RefreshToken}, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Error("family survived reuse detection")
	}

	// Отдельная сессия через login: logout обязан отозвать её, а не семью из теста выше.
	resp, body = do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %v", resp.StatusCode, body)
	}
	re := decodeSession(t, body)
	req, err := http.NewRequest(http.MethodPost, base+"/auth/logout",
		jsonBody(map[string]string{"refresh_token": re.RefreshToken}))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+re.AccessToken)
	lr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	lr.Body.Close()
	if lr.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", lr.StatusCode)
	}
	if resp, body := do(t, http.MethodGet, base+"/me", nil, re.AccessToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked access token still authorized: %d %v", resp.StatusCode, body)
	}
	// Пользователь остаётся: отзыв сессии ≠ удаление учётной записи (ТЗ §11 делает это
	// отдельной операцией, цикл D).
	if _, err := q.UserByEmail(ctx, email); err != nil {
		t.Fatalf("user vanished after logout: %v", err)
	}
}
```

Второй тест закрывает отказные ветки: слабый пароль, дубликат email, одинаковость
ответов на неизвестный email и неверный пароль (нет оракула перечисления), блокировку,
отсутствие заголовка.

```go
func TestAuthRejectedPaths(t *testing.T) {
	srv, q := newAuthServer(t)
	ctx := context.Background()
	base := srv.URL + "/api/v1"
	email := "reject-" + uuid.NewString()[:8] + "@novavpn.test"

	resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": "short"}, "")
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Fatalf("weak password: %d %v", resp.StatusCode, body)
	}
	if _, err := q.UserByEmail(ctx, email); err == nil {
		t.Error("user created despite rejected password")
	}

	if resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": testPassword}, ""); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, body)
	}
	// citext: регистр в email не различается, и повтор обязан быть 409, а не вторым аккаунтом.
	resp, body = do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": strings.ToUpper(email), "password": testPassword}, "")
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "email_taken" {
		t.Fatalf("duplicate email: %d %v", resp.StatusCode, body)
	}

	_, badPass := do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": email, "password": "wrong-password-123"}, "")
	_, unknown := do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": "nobody-" + uuid.NewString()[:8] + "@novavpn.test",
			"password": testPassword}, "")
	// Разница в message или details выдаёт, что email существует.
	// Сравнивается пара «code|message», а не whole map: request_id различается по
	// определению, и сравнение карт целиком было бы всегда красным.
	if envelopePair(badPass) != envelopePair(unknown) {
		t.Errorf("login answers differ: %v vs %v", badPass, unknown)
	}
	if errorCode(t, badPass) != "invalid_credentials" {
		t.Errorf("code = %v, want invalid_credentials", badPass)
	}

	user := userIDByEmail(t, ctx, q, email)
	// Форма «указатель на строку» — как у всех nullable-параметров этого плана при
	// emit_pointers_for_null_types: true (ср. DisplayName в InsertUserParams). Если
	// sqlc сгенерировал скаляр, правь эту строку, строку в тесте блокировки ниже и
	// вызов в задаче 19 одним коммитом: две формы в одном пакете не компилируются.
	lockedReason := "manual review"
	if err := q.LockUser(ctx, db.LockUserParams{ID: user, LockedReason: &lockedReason}); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	resp, body = do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusForbidden || errorCode(t, body) != "account_locked" {
		t.Fatalf("locked account: %d %v", resp.StatusCode, body)
	}

	resp, body = do(t, http.MethodGet, base+"/me", nil, "")
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "unauthenticated" {
		t.Fatalf("me without token: %d %v", resp.StatusCode, body)
	}
}

func userIDByEmail(t *testing.T, ctx context.Context, q *db.Queries, email string) uuid.UUID {
	t.Helper()
	u, err := q.UserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("UserByEmail(%s): %v", email, err)
	}
	return u.ID
}
```

Сравнение ведётся по паре «code|message», а не по карте целиком: `request_id` различается
по определению, и с ним эта проверка была бы всегда красной — ровно тот класс молчаливого
«теста», который ничего не проверяет. Жёсткое соответствие контракту по всем полям —
задача 19.

Run: `make integration`
Expected: FAIL — `undefined: auth.NewHandler`, `undefined: auth.Middleware`,
`undefined: auth.NewLoginGuard`, `undefined: auth.ClientIP`.

- [ ] **Step 2: Unit-тест middleware — он проверяется без базы**

`internal/auth/middleware_test.go`. `SessionService` здесь собирается напрямую полями:
`ParseAccess` — обёртка над `Issuer`, и `q` в этом пути не участвует. Это не подмена
бизнес-логики, а использование того же кода с нулевой зависимостью от БД; настоящие
значения полей приватные, поэтому тест лежит в пакете `auth`.

```go
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/httpx"
)

type stubDenylist struct {
	denied map[string]bool
	err    error
	seen   []string
}

func (s *stubDenylist) Add(_ context.Context, jti string, _ time.Time) error {
	s.seen = append(s.seen, jti)
	return s.err
}

func (s *stubDenylist) Contains(_ context.Context, jti string) (bool, error) {
	return s.denied[jti], s.err
}

// newProtectedHandler — middleware поверх обработчика, который проверяет, что субъект
// действительно лёг в контекст. httpx импортируется напрямую: обёртка тут не нужна.
func newProtectedHandler(t *testing.T, deny Denylist) (http.Handler, *Issuer, uuid.UUID) {
	t.Helper()
	iss := NewIssuer(bytes32("unit-middleware-secret-0000"), time.Minute)
	user := uuid.New()
	sess := &SessionService{iss: iss, deny: deny, refreshTTL: time.Hour, log: slog.New(slog.DiscardHandler)}
	wrapped := Middleware(sess, deny)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := httpx.UserIDFromContext(r.Context())
		if !ok || got != user {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	return wrapped, iss, user
}

func TestMiddlewareAcceptsValidToken(t *testing.T) {
	h, iss, user := newProtectedHandler(t, &stubDenylist{denied: map[string]bool{}})
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body)
	}
}

func TestMiddlewareRejects(t *testing.T) {
	cases := map[string]func(*http.Request){
		"no header":    func(*http.Request) {},
		"wrong scheme": func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") },
		"empty bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"junk token":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc.def.ghi") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h, _, _ := newProtectedHandler(t, &stubDenylist{denied: map[string]bool{}})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			mutate(req)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assertUnauthenticated(t, w)
		})
	}
}
```

Хелпер проверки envelope — тот же файл:

```go
func assertUnauthenticated(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var body struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("envelope is not JSON: %s", w.Body)
	}
	if body.Error.Code != "unauthenticated" {
		t.Errorf("code = %q, want unauthenticated", body.Error.Code)
	}
	if len(body.Error.RequestID) != 16 {
		t.Errorf("request_id = %q, want 16 chars", body.Error.RequestID)
	}
}
```

`bytes32` уже объявлен в `token_test.go` (задача 11) — в этом файле его объявлять
нельзя. `SessionService` собирается напрямую, потому что `ParseAccess` не трогает `q`;
два оставшихся теста используют те же хелперы. Второй из них — это запись решения, а не
удобства: при недоступном Redis отозванный access живёт до своего TTL; осознанный
fail-open из §4.3, и он обязан появиться в §13 спецификации (шаг 6, пункт 9).

```go
func TestMiddlewareRejectsDeniedJTI(t *testing.T) {
	deny := &stubDenylist{denied: map[string]bool{}}
	h, iss, user := newProtectedHandler(t, deny)
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	deny.denied[tok.JTI] = true
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assertUnauthenticated(t, w)
}

func TestMiddlewareFailsOpenWhenDenylistIsDown(t *testing.T) {
	deny := &stubDenylist{err: errors.New("redis: connection refused")}
	h, iss, user := newProtectedHandler(t, deny)
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", w.Code)
	}
}
```

Run: `make unit`
Expected: FAIL — `undefined: Middleware`.

- [ ] **Step 3: Реализовать middleware, `ClientIP`, `Bearer`**

`internal/auth/middleware.go`:

```go
package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/httpx"
)

// Middleware проверяет access-токен и кладёт субъекта в контекст. Проверка права на
// конкретный объект (чужое устройство, чужой профиль) — не здесь, а в сервисе
// (спецификация §5.2: «проверка права на объект, а не только факта аутентификации»).
// Журналирование запроса делает сквозной middleware из задачи 18 — поэтому у Middleware
// нет параметра log: отказ denylist пишет сам (задача 11).
func Middleware(sess *SessionService, deny Denylist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			value := Bearer(r)
			if value == "" {
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "authentication required", nil)
				return
			}
			claims, err := sess.ParseAccess(value)
			if err != nil || claims.UserID == uuid.Nil {
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "authentication required", nil)
				return
			}
			blocked, err := deny.Contains(r.Context(), claims.JTI)
			if err != nil {
				// Contains уже записал отказ в журнал. Продолжаем с blocked == false:
				// это тот же fail-open, что у rate limiter (§4.3), и он означает, что
				// при недоступном Redis отозванный access доживает свой TTL. Доступ к
				// трафику забирает не токен, а снятие пиера на узле (§5.3), и оно от
				// Redis не зависит.
				blocked = false
			}
			if blocked {
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "authentication required", nil)
				return
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithUserID(r.Context(), claims.UserID)))
		})
	}
}

// Bearer возвращает токен из заголовка Authorization; "" — если заголовка нет, схема
// не Bearer или после схемы пусто. Регистр схемы не значим (RFC 9110), но сравнивать
// только слово «Bearer» без завершающего пробела нельзя: «BearerX abc» обязан быть отвергнут.
func Bearer(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(v[len(prefix):])
}

// ClientIP берёт адрес из RemoteAddr. X-Forwarded-For не читается: этот заголовок
// контролирует клиента, и доверять ему — значит отдать ему возможность подделать ключ
// rate limit (спецификация §6: ip хранится только для анти-злоупотреблений).
// Оператор, ставящий TLS-терминатор перед API, обязан передать настоящий адрес
// источником (proxy protocol или связка 1:1), а не заголовком.
func ClientIP(r *http.Request) *netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsUnspecified() {
		return nil
	}
	if addr.Is4In6() {
		addr = addr.Addr4()
	}
	return &addr
}

func ipString(a *netip.Addr) string {
	if a == nil {
		return "unknown"
	}
	return a.String()
}
```

`Middleware` намеренно не принимает `*slog.Logger`: отказ `Denylist.Contains` пишется в
журнал внутри denylist (задача 11), а журнал каждого запроса делает сквозной middleware из
задачи 18. Невостребованный параметр — это обещание, которого никто не даёт.

`internal/auth/login_guard.go`:

```go
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	failWindow    = 15 * time.Minute
	failBaseDelay = 250 * time.Millisecond
	// Потолок 4 с: без него каждый отказ вешает горутину сервера на растущий срок,
	// и атака превращается в отказ по ресурсам.
	failMaxShift = 4
)

// LoginGuard — прогрессивная задержка ответа на неудачный вход (спецификация §2, §5.2).
// Счётчик живёт в Redis, а не в памяти процесса: экземпляров API несколько, и
// «прогрессивность» обязана переживать рестарт.
type LoginGuard struct {
	rdb *redis.Client
	log *slog.Logger
}

func NewLoginGuard(rdb *redis.Client, log *slog.Logger) *LoginGuard {
	return &LoginGuard{rdb: rdb, log: log}
}

// Ключ — хэш пары email+ip: email в ключ не кладётся в открытом виде, чтобы
// перебор не читался по журналу Redis, и чтобы длинный email не раздувал ключ.
func failKey(email, ip string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email) + "|" + ip))
	return "loginfail:" + hex.EncodeToString(sum[:])
}

// Delay фиксирует неудачу и возвращает паузу: 250, 500, 1000, 2000, 4000 мс, дальше —
// 4000 мс. Возвращается Duration, а не происходит sleep: хендлер решает сам, слушать ли
// контекст запроса.
func (g *LoginGuard) Delay(ctx context.Context, email, ip string) time.Duration {
	if g.rdb == nil {
		return 0
	}
	key := failKey(email, ip)
	n, err := g.rdb.Incr(ctx, key).Result()
	if err != nil {
		g.log.Warn("login guard unavailable, failing open", "err", err)
		return 0
	}
	if n == 1 {
		if err := g.rdb.Expire(ctx, key, failWindow).Err(); err != nil {
			g.log.Warn("login guard window", "err", err)
		}
	}
	shift := n - 1
	if shift > failMaxShift {
		shift = failMaxShift
	}
	return failBaseDelay << shift
}

func (g *LoginGuard) Reset(ctx context.Context, email, ip string) {
	if g.rdb == nil {
		return
	}
	if err := g.rdb.Del(ctx, failKey(email, ip)).Err(); err != nil {
		g.log.Warn("login guard reset", "err", err)
	}
}
```

`failBaseDelay << shift` законен: `time.Duration` — целой тип, а сдвиг на `int64`
даёт удвоение. Окно `failWindow` обновляется только на первой неудаче, счётчик не
обнуляется бесконечными попытками, и после 15 минут тишины задержка снова начинается
с 250 мс.

- [ ] **Step 4: Тест: заблокированный аккаунт не продлевает сессию**

`Rotate` из задачи 12 про статус пользователя ничего не спрашивает, поэтому
блокировка из ТЗ §9 останавливала бы только новый вход: живой refresh-токен
продолжал бы выдавать access-токены вечно (семья продлевается). Это тот случай,
когда реализация «работает», но право администратора не исполняется, — поэтому
проверка статуса добавляется здесь, и начинается с падающего теста.

Конец `tests/integration/auth_flow_test.go`:

```go
func TestLockedAccountCannotRefresh(t *testing.T) {
	srv, q := newAuthServer(t)
	ctx := context.Background()
	base := srv.URL + "/api/v1"
	email := "lockref-" + uuid.NewString()[:8] + "@novavpn.test"

	resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, body)
	}
	first := decodeSession(t, body)

	// До блокировки ротация обязана работать — иначе тест проверял бы не блокировку.
	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": first.RefreshToken}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh before lock: %d %v", resp.StatusCode, body)
	}
	rotated := decodeSession(t, body)

	locked := "manual review"
	if err := q.LockUser(ctx, db.LockUserParams{
		ID: userIDByEmail(t, ctx, q, email), LockedReason: &locked,
	}); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": rotated.RefreshToken}, "")
	if resp.StatusCode != http.StatusForbidden || errorCode(t, body) != "account_locked" {
		t.Fatalf("refresh on locked account: %d %v", resp.StatusCode, body)
	}
	// Блокировка ≠ удаление и ≠ отзыв семей: админский отзыв
	// (db.RevokeAllFamiliesForUser) — маршрут /api/v1/admin/* из A-2. Здесь важно,
	// что учётная запись цела и её можно разблокировать.
	if _, err := q.UserByEmail(ctx, email); err != nil {
		t.Fatalf("user vanished after lock: %v", err)
	}
}
```

Run: `make integration`
Expected: FAIL — `refresh on locked account: 200`.

- [ ] **Step 5: Реализовать HTTP-слой**

Сначала — правка `internal/auth/refresh.go`. В `Rotate` между проверкой секрета
(`subtle.ConstantTimeCompare`) и `RotateRefresh` вставить чтение пользователя:

```go
	user, err := s.q.UserByID(ctx, family.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Семья указывает на пользователя, которого нет (в A удаление — это
		// status='deleted', поэтому случай теоретический, но дешёвый).
		return Session{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("load user for rotation: %w", err)
	}
	if user.Status != db.UserStatusActive {
		return Session{}, ErrAccountLocked
	}
```

Проверка стоит до сравнения секрета? Нет — порядок обратный: неверный токен обязан
остаться `refresh_token_invalid`, иначе ответ «аккаунт заблокирован» станет
подтверждением того, что токен подошёл. Разница между «семья отозвана» и «аккаунт
заблокирован» наружу не раскрывает ни email, ни причину, поэтому `ErrAccountLocked`
возвращается только после успешного совпадения секрета — и до `RotateRefresh`, чтобы
отказ по блокировке не сжигал семью и не оставлял клиента с уже недействительным
токеном.

`internal/auth/handlers.go`:

```go
package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

// maxAuthBody: пара email+password физически маленькая. 16 KiB с запасом — и тело
// не превращается в способ купить серверу память.
const maxAuthBody = 1 << 14

type Handler struct {
	sess     *SessionService
	pool     *pgxpool.Pool
	ent      *entitlements.Service
	guard    *LoginGuard
	planSlug string
	log      *slog.Logger
}

func NewHandler(sess *SessionService, pool *pgxpool.Pool, ent *entitlements.Service,
	guard *LoginGuard, planSlug string, log *slog.Logger) *Handler {
	return &Handler{sess: sess, pool: pool, ent: ent, guard: guard, planSlug: planSlug, log: log}
}

// RegisterRoutes монтирует маршруты модуля в общий ServeMux. Публичные — под
// dec.Anonymous, приватные — под dec.Auth, который передаёт сборщик (задача 18):
// модуль не решает, как устроены аутентификация и лимиты, он только объявляет,
// какой из его маршрутов закрыт.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	// Все четыре анонимны по смыслу, но не «без лимита»: лимит по IP навешивает
	// сборщик через dec.Anonymous. refresh/logout без него — это бесплатный
	// перебор семей refresh-токенов и отзыв чужих сессий на скорость.
	mux.Handle("POST /api/v1/auth/register", dec.Anonymous(http.HandlerFunc(h.register)))
	mux.Handle("POST /api/v1/auth/login", dec.Anonymous(http.HandlerFunc(h.login)))
	mux.Handle("POST /api/v1/auth/refresh", dec.Anonymous(http.HandlerFunc(h.refresh)))
	// logout НЕ под Auth (контракт, задача 16): отзыв обязан сработать и когда
	// access уже истёк. Доказательство владения сессией — refresh-токен в теле.
	mux.Handle("POST /api/v1/auth/logout", dec.Anonymous(http.HandlerFunc(h.logout)))
	mux.Handle("GET /api/v1/me", dec.Auth(http.HandlerFunc(h.me)))
}

// credentials = components/schemas/Credentials из контракта. Полей больше нет:
// httpx.DecodeJSON стоит на DisallowUnknownFields, и «лишний» display_name в
// запросе обязан быть отвергнут, а не тихо проигнорирован.
type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpx.DecodeJSON(r, dst, maxAuthBody); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"body must be a single JSON object with the documented fields", nil)
		return false
	}
	return true
}

// internal — единый выход в 500. Причина уходит в журнал с request id, наружу
// не уходит никогда: текст ошибки PostgreSQL описывает схему и столбцы.
func (h *Handler) internal(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("auth: internal error",
		"err", err, "request_id", httpx.RequestIDFromContext(r.Context()))
	httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "internal error", nil)
}

func (h *Handler) writeSession(w http.ResponseWriter, status int, s Session) {
	// Токены в теле — no-store: без этого промежуточный кэш может оставить
	// действующую сессию там, где её не ждали.
	w.Header().Set("Cache-Control", "no-store")
	if err := httpx.WriteJSON(w, status, sessionView{
		AccessToken: s.AccessToken, RefreshToken: s.RefreshToken, TokenType: "Bearer",
		AccessExpiresAt: s.AccessExpiresAt, RefreshExpiresAt: s.RefreshExpiresAt,
	}); err != nil {
		h.log.Error("auth: write session", "err", err)
	}
}

type sessionView struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !h.decode(w, r, &in) {
		return
	}
	email, ok := normalizeEmail(in.Email)
	if !ok {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"email must be a single address of at most 254 characters",
			map[string]any{"field": "email"})
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		// Пока не создан ни пользователь, ни подписка: до HashPassword доходить
		// не должно — иначе слабый пароль уже оставил бы строку в users.
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"password must be 10..1024 bytes", map[string]any{"field": "password"})
		return
	}
	userID := uuid.New()
	err = db.RunInTx(r.Context(), h.pool, func(q *db.Queries) error {
		if _, err := q.InsertUser(r.Context(), db.InsertUserParams{
			ID: userID, Email: email, PasswordHash: hash, DisplayName: nil, Locale: "en",
		}); err != nil {
			return err
		}
		return entitlements.GrantDefaultPlanTx(r.Context(), q, userID, h.planSlug)
	})
	if err != nil {
		if isEmailTaken(err) {
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrEmailTaken,
				"email is already registered", map[string]any{"field": "email"})
			return
		}
		h.internal(w, r, err)
		return
	}
	sess, err := h.sess.NewSession(r.Context(), userID, ClientIP(r))
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.writeSession(w, http.StatusCreated, sess)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !h.decode(w, r, &in) {
		return
	}
	// Нормализация та же, что при регистрации, но без отказа на «странности»:
	// форма email здесь не тема ответа.
	email := strings.ToLower(strings.TrimSpace(in.Email))
	ip := ClientIP(r)
	ipStr := ipString(ip)

	q := db.New(h.pool)
	user, err := q.UserByEmail(r.Context(), email)
	if errors.Is(err, pgx.ErrNoRows) {
		h.penalize(w, r, email, ipStr)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	if !VerifyPassword(user.PasswordHash, in.Password) {
		h.penalize(w, r, email, ipStr)
		return
	}
	// Про блокировку сообщаем только после верного пароля: иначе ответ сам по себе
	// становится оракулом «такой аккаунт есть».
	if user.Status != db.UserStatusActive {
		h.log.Warn("login on non-active account", "user_id", user.ID, "status", string(user.Status))
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrAccountLocked,
			"account is locked", nil)
		return
	}
	h.guard.Reset(r.Context(), email, ipStr)
	sess, err := h.sess.NewSession(r.Context(), user.ID, ip)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.writeSession(w, http.StatusOK, sess)
}

// penalize — отказ по креденшелам. И неизвестный email, и неверный пароль дают
// одно и то же тело, и обе ветки проходят через одну задержку. Фиктивную
// argon2-проверку для неизвестного email не делаем сознательно: 64 MiB на каждый
// запрос к любому адресу — это подарок тому, кто умеет слать запросы.
// Оставшийся канал (тайминг) документирован в спецификации §13.10.
func (h *Handler) penalize(w http.ResponseWriter, r *http.Request, email, ip string) {
	d := h.guard.Delay(r.Context(), email, ip)
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return // клиент ушёл: писать некому, горутину на 4 секунды не держим
		}
	}
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrInvalidCredentials,
		"email or password is incorrect", nil)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var in refreshRequest
	if !h.decode(w, r, &in) {
		return
	}
	// Границы из контракта (minLength 40, maxLength 512) — здесь, а не в parseRefresh:
	// «слишком короткий» — это нарушение схемы, а не «токена нет».
	if n := len(in.RefreshToken); n < 40 || n > 512 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"refresh_token must be 40..512 characters", map[string]any{"field": "refresh_token"})
		return
	}
	sess, err := h.sess.Rotate(r.Context(), in.RefreshToken, ClientIP(r))
	switch {
	case err == nil:
		h.writeSession(w, http.StatusOK, sess)
	case errors.Is(err, ErrInvalidRefreshToken), errors.Is(err, ErrExpiredRefreshToken):
		// Один код и одно сообщение для «не разобран», «семьи нет», «семья отозвана»,
		// «секрет переиспользован» и «истёк». Причины — только в журнале.
		h.log.Warn("refresh rejected", "err", err,
			"request_id", httpx.RequestIDFromContext(r.Context()))
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrRefreshTokenInvalid,
			"refresh token is invalid", nil)
	case errors.Is(err, ErrAccountLocked):
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrAccountLocked,
			"account is locked", nil)
	default:
		h.internal(w, r, err)
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var in refreshRequest
	if !h.decode(w, r, &in) {
		return
	}
	// access передаём, но не требуем: если он притащен и разобран — его jti уходит
	// в denylist, и активный токен перестаёт пускать немедленно.
	if err := h.sess.Revoke(r.Context(), in.RefreshToken, Bearer(r)); err != nil {
		if errors.Is(err, ErrInvalidRefreshToken) {
			h.log.Warn("logout with undecodable refresh token",
				"request_id", httpx.RequestIDFromContext(r.Context()))
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrRefreshTokenInvalid,
				"refresh token is invalid", nil)
			return
		}
		h.internal(w, r, err)
		return
	}
	// 204 и для уже отозванной, и для несуществующей семьи: отзыв идемпотентен,
	// а различие «такой семьи нет» / «мы её уже сожгли» — ещё один оракул.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

type userView struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName *string    `json:"display_name"`
	Status      string     `json:"status"`
	Locale      string     `json:"locale"`
	CreatedAt   time.Time  `json:"created_at"`
}

type planView struct {
	Slug              string `json:"slug"`
	DeviceLimit       int    `json:"device_limit"`
	TrafficQuotaBytes *int64 `json:"traffic_quota_bytes"`
}

type usageView struct {
	Live  int `json:"live"`
	Limit int `json:"limit"`
}

type meView struct {
	User    userView   `json:"user"`
	Plan    *planView  `json:"plan"`
	Devices usageView  `json:"devices"`
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated,
			"authentication required", nil)
		return
	}
	q := db.New(h.pool)
	user, err := q.UserByID(r.Context(), userID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Подписанный jti живой, пользователя нет: это не «нет права», а «нет
		// субъекта» — 401, и denylist тут не при чём.
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated,
			"authentication required", nil)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	live, err := q.CountLiveDevices(r.Context(), userID)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	out := meView{
		User: userView{ID: user.ID.String(), Email: user.Email, DisplayName: user.DisplayName,
			Status: string(user.Status), Locale: user.Locale, CreatedAt: user.CreatedAt},
		Devices: usageView{Live: int(live)},
	}
	ent, err := h.ent.ForUser(r.Context(), userID)
	switch {
	case err == nil:
		out.Plan = &planView{Slug: ent.Slug, DeviceLimit: ent.DeviceLimit,
			TrafficQuotaBytes: ent.TrafficQuotaBytes}
		out.Devices.Limit = ent.DeviceLimit
	case errors.Is(err, entitlements.ErrNoActiveSubscription):
		// plan: null, limit: 0. /me описывает состояние аккаунта, а не выдаёт право,
		// поэтому отсутствие подписки здесь — данные, а не отказ (403 был бы
		// неправдой про «нет доступа» там, где нужно «кончилось»).
		out.Plan = nil
	default:
		h.internal(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := httpx.WriteJSON(w, http.StatusOK, out); err != nil {
		h.log.Error("auth: write me", "err", err)
	}
}

// normalizeEmail — каноническая форма для uniqueness-ключа и для ключа задержки.
// citext делает UNIQUE независимым от регистра, но счётчик неудач должен считаться
// по одному и тому же адресу, а не по каждому его написанию.
func normalizeEmail(s string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(s))
	if !validEmail(v) {
		return "", false
	}
	return v, true
}

// validEmail — структурная проверка, а не валидация адреса. Настоящее подтверждение
// — письмо (цикл D); здесь цель другая: не пустить мусор, не дать email быть
// бесконечным ключом и не оставить «@» внутри local-part.
func validEmail(s string) bool {
	if len(s) == 0 || len(s) > 254 || strings.Count(s, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(s, "@")
	if len(local) == 0 || len(local) > 64 || len(domain) < 4 || len(domain) > 253 {
		return false
	}
	if strings.IndexFunc(local, func(r rune) bool {
		return !isLocalRune(r)
	}) >= 0 {
		return false
	}
	if strings.IndexFunc(domain, func(r rune) bool {
		return !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) >= 0 {
		return false
	}
	labels := strings.Split(domain, ".")
	for i, l := range labels {
		if len(l) == 0 || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		// TLD из цифр не бывает доменом: «host.123» — опечатка, а не адрес.
		if i == len(labels)-1 {
			if len(l) < 2 || strings.IndexFunc(l, func(r rune) bool {
				return r < 'a' || r > 'z'
			}) >= 0 {
				return false
			}
		}
	}
	return true
}

func isLocalRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '.' || r == '_' || r == '%' || r == '+' || r == '-':
		return true
	default:
		return false
	}
}

// isEmailTaken — UNIQUE-констрейнт на citext-колонке. Имя constraint берём из
// PostgreSQL (`\d users` в контейнере с миграциями), а не из предположения: на
// колонке «email citext NOT NULL UNIQUE» имя по умолчанию — users_email_key.
// Проверяется и код 23505, и имя: без второго условия любой другой UNIQUE
// (например, кривой seed планов) выглядел бы как занятый email.
func isEmailTaken(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return pgErr.Constraint == "users_email_key"
}
```

Несколько решений, которые надо держать именно такими:

- **Проверка weak-пароля до вставки.** `HashPassword` возвращает `ErrWeakPassword`
  ещё до `RunInTx`, поэтому ветка 400 не оставляет строки в `users`. Если
  переставить, тест `TestAuthRejectedPaths` («user created despite rejected password»)
  станет гонкой, а не проверкой.
- **Дубликат email — через нарушение UNIQUE, а не через предварительный
  `UserByEmail`.** Проверка «есть ли такой» перед вставкой не атомарна: два
  параллельных запроса создали бы двух пользователей с одним адресом, а
  `citext UNIQUE` — единственный, что этому мешает.
- **`users_email_key` и `db.UserStatusActive`** появляются в плане, только если
  задача 2 именовала constraint сама. Имя constraint из `NOT NULL UNIQUE` на
  колонке — `users_email_key`; перед прогоном убедиться `\d users` в контейнере
  PostgreSQL и при расхождении — правку нести в миграцию, а не в `isEmailTaken`
  («подстроить код под фактическое имя» означало бы потерять проверку).
- **`/me` не требует подписки.** Цикл D приносит платежи, и подписка может
  кончиться раньше, чем пользователь успеет зайти. Ответ с `plan: null` честнее,
  чем 403: маршрут показывает состояние, а право на выдачу профиля проверяет A-2.

- [ ] **Step 6: Привести контракт и спецификацию в соответствие**

Контракт задачи 16 писался до того, как появились `account_locked` на refresh и
идемпотентность logout. Правки в `api-spec/openapi.yaml` — в том же коммите:

1. `POST /auth/refresh` — добавить ответ:

```yaml
        "403":
          description: Аккаунт заблокирован; продление сессии остановлено (ТЗ §9).
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [account_locked] }
```

2. `POST /auth/logout` — заменить текст ответа `401`, чтобы он описывал только
   нераспаршиваемый токен:

```yaml
        "401":
          description: >
            Refresh не разобран (не формат семьи). Уже отозванная или несуществующая
            семья отвечает 204: отзыв идемпотентен, а различение этих случаев —
            оракул «какие семьи существовали».
          content:
            application/json:
              schema:
                allOf:
                  - $ref: "#/components/schemas/Error"
                  - properties:
                      error:
                        properties:
                          code: { enum: [refresh_token_invalid] }
```

3. `GET /me` — план становится nullable, лимит устройств — с нулём:

```yaml
        plan:
          anyOf:
            - $ref: "#/components/schemas/PlanView"
            - type: "null"
        devices:
          type: object
          required: [live, limit]
          properties:
            live: { type: integer, minimum: 0 }
            # 0 — план кончился или его никогда не было; именно поэтому здесь
            # больше нет minimum: 1.
            limit: { type: integer, minimum: 0 }
```

и в `components/schemas` добавить `PlanView` с теми же полями, что `planView` в Go
(`slug`, `device_limit` с `minimum: 1`, `traffic_quota_bytes` — `["integer","null"]`).
`required` у `Me` остаётся `[user, plan, devices]`: поле обязательно, но его значение
может быть `null` — в OpenAPI 3.1 это разные вещи, и путать их нельзя.

4. Заодно — `POST /auth/register` уже обещает `409 email_taken` (задача 16), а
   `POST /auth/login` — `403 account_locked`: проверить, что оба присутствуют, и
   ничего не добавлять.

Спецификация, §5.2, пункт «Авторизация на всех маршрутах, кроме register/login/refresh»:
дописать `/auth/logout` в перечень исключений и объяснить почему — отзыв обязан сработать и
когда access уже истёк (иначе украденный refresh нельзя погасить постфактум), доказательство
владения сессией — refresh-токен в теле, а не заголовок. Анонимность маршрута не означает
«без лимита»: token bucket по IP на все четыре маршрута навешивает сборщик (задача 18), и
именно поэтому перебор семей и отзыв чужих сессий на скорость не бесплатны. Точка истины —
контракт задачи 16 и `RegisterRoutes` выше; без этой правки §5.2 обещает то, чего код не
делает.

Спецификация, §13 «Известные ограничения»: дописать три пункта —

- **9.** Denylist access-токенов живёт в Redis и при недоступном Redis работает по
  fail-open: отозванный logout-ом access доживает свой TTL (не больше 10 минут).
  Отзыв refresh и снятие пиера на узле от Redis не зависят, поэтому «забрать доступ
  к трафику» fail-open не отменяется.
- **10.** Ответ на вход при неизвестном email и при неверном пароле одинаков по телу,
  но не по времени: проверка argon2id выполняется только для существующего аккаунта.
  Добавочная задержка (`LoginGuard`) начинается с 250 мс и потому тайминг-канал
  полностью не закрывается; он ограничивается rate limit по IP и аккаунту.
  Искусственная фиктивная проверка не введена: 64 MiB памяти и ~100 мс CPU на любой
  запросы были бы хуже, чем утечка перечисления.
- **11.** Блокировка аккаунта не обслуживается мгновенно уже выданным токеном:
  middleware проверяет подпись, срок и denylist, но `users.status` на каждый запрос
  не перечитывает, — access, выданный до блокировки, живёт до истечения TTL
  (не больше 10 минут). Новые выдачи и ротация refresh блокировка останавливает
  сразу, а «забрать доступ к трафику» делает снятие пиера на узле (§7.4), а не токен.
  Матрица задачи 19 фиксирует это как замеренное ограничение (`200` на
  `GET /devices` токеном, выданным до блокировки), а не как обещание мгновенного отзыва.

Run: `make api-lint && make unit`
Expected: PASS (контракт линтуется, тесты задачи 16 проходят с новым кодом `account_locked`
на refresh).

- [ ] **Step 7: Прогон и коммит**

Run: `make integration`
Expected: PASS — `TestRegisterThenRotateThenLogoutDeniesAccess`,
`TestAuthRejectedPaths`, `TestLockedAccountCannotRefresh`.

Run: `make unit && make vet`
Expected: PASS.

```bash
git add internal/auth tests/integration/auth_flow_test.go api-spec/openapi.yaml \
  docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git commit -m "feat(auth): HTTP слой сессий, прогрессивная задержка входа и закрытие блокировкой"
```

Этого хватает, чтобы цикл A-1 был проверяем сквозным HTTP-путём; маршруты устройств
монтируются в задаче 18 вместе со сборкой приложения.

---

### Task 18: Сборка приложения — конверт для 404/405, журнал запроса, graceful shutdown

**Files:**
- Create: `services/api/router.go`, `internal/httpx/mux.go`, `internal/httpx/logging.go`,
  `internal/httpx/mux_test.go`, `tests/integration/router_test.go`
- Modify: `internal/httpx/requestid.go` (журнальная строка уходит, `statusWriter`
  переезжает в `logging.go`), `internal/httpx/context.go` (`WithUserID` сообщает
  субъекта журналу), `services/api/cmd/novavpn-api/main.go` (`serve` собирает граф и
  останавливается по сигналу)

**Interfaces:**
- Consumes: `auth.NewHandler`, `(*auth.Handler).RegisterRoutes`, `auth.Middleware`,
  `auth.ClientIP` (задача 17), `devices.NewService`, `devices.NewHandler`,
  `(*devices.Handler).RegisterRoutes` и `httpx.Decorators` (задача 15),
  `entitlements.New`, `db.New`, `db.Pool`, `httpx.NewLimiter`, `httpx.RatePerMinute`,
  `httpx.NewIdempotency`, `httpx.NewPGIdempotency`, `httpx.NewRequestID`,
  `httpx.WriteError`, `httpx.WithUserID`, `httpx.UserIDFromContext`, `config.Config`.
- Produces:
  `api.NewRouter(deps api.Deps) http.Handler`,
  `api.Deps{Cfg config.Config; Pool *pgxpool.Pool; RDB *redis.Client; Ent *entitlements.Service; Log *slog.Logger}`,
  `httpx.PatternResolver` — `interface{ Handler(*http.Request) (http.Handler, string) }`
  (его удовлетворяет `*http.ServeMux`),
  `httpx.Envelope(routes httpx.PatternResolver) http.Handler`,
  `httpx.Logging(next http.Handler, routes httpx.PatternResolver, log *slog.Logger) http.Handler`,
  `withJournal(ctx) (context.Context, *journal)`, `noteRoute(ctx, pattern)`,
  `noteUserID(ctx, id)` — три неэкспортируемых помощника того же пакета `httpx`;
  снаружи у них нет потребителей, поэтому и наружу они не выходят.

Поведение `net/http.ServeMux`, на котором держится этот шаг. Оно замерено на том же
`golang:1.25-alpine`, на котором собирается проект, и ниже закреплено тестами: если Go
изменит поведение, упадёт тест, а не продакшн.

| запрос | зарегистрированный `/` отсутствует | зарегистрированный `/` есть |
| --- | --- | --- |
| путь ни на что не похож | 404, тело `404 page not found`, `Handler(r)` → pattern `""` | уходит в catch-all, pattern `"/"` |
| путь есть, метод другой | 405, заголовок `Allow`, тело `Method Not Allowed`, pattern `""` | уходит в catch-all, pattern `"/"` |
| `HEAD` на зарегистрированный `GET` | сматчен, pattern — как у `GET` | то же |
| путь с косой чертой на конце (`/api/v1/devices/`) | 404, pattern `""` — Go не делает из этого редирект | не замерялось: `/` мы не регистрируем |
| путь нужно почистить (`//`, `./`, `..`) | 301 + `Location`, pattern — зарегистрированный маршрут, редирект пишет сам `ServeMux` | не замерялось: `/` мы не регистрируем |

Последние две строки важны для формы `Envelope`: диспетч идёт по непустому pattern,
поэтому «грязный» путь с лишней косой чертой превращается в документированный 404, а
путь, который Go чистит, — в штатный 301. Первое полезно (клиент получает конверт, а не
тихую переадресацию), второе безвредно (в журнал попадает шаблон, а не путь клиента).
Проверяется это тестами `TestEnvelopeTrailingSlashIsNotFound` и
`TestEnvelopeKeepsServeMuxPathCleanupRedirect`.

Ещё одна замеренная деталь: `POST /api/v1/{name}` заставил `GET /api/v1/Boom` отдать 405,
а не 404. То есть перебор методов в `allowedMethods` работает и на wildcard-шаблонах —
это пригодится в A-2, где появятся `/servers/{id}` и `/profiles/{id}`.

Отсюда два правила сборки, и оба проверяются тестами:

1. `/` не регистрируется вообще. С catch-all'ом 404 и 405 неразличимы, а значит
   «единый формат ошибки» (§5.2) пришлось бы восстанавливать угадыванием.
2. Имя маршрута и список разрешённых методов спрашивают у `mux.Handler(r)`; для `Allow` —
   с копией запроса, у которого подменён `Method`. Другого публичного способа спросить у
   `ServeMux` про другой метод нет: ни `Clone`'а, ни перечисления маршрутов у него нет.
3. Имя маршрута в журнал пишет `Logging`, а не `Envelope`. Лимитер и проверка JWT стоят
   выше конверта, и их отказы (429, 401) иначе попали бы в журнал как `unmatched` — ops
   начал бы чинить маршрутизацию там, где сработал лимит. `mux.Handler` — чистый поиск,
   он не меняет состояния, поэтому второй вызов (внутри `Envelope`, уже ради диспетчера)
   безвреден.

Задача 17 оставила два открытых места: `RegisterRoutes` ждёт `*http.ServeMux` и
`httpx.Decorators` извне, а `auth.Middleware` не пишет журнал. Здесь появляется и то, и
другое.

- [ ] **Step 1: Написать падающие unit-тесты конверта и журнала**

`internal/httpx/mux_test.go` — без тегов, живая инфраструктура не нужна:

```go
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// chain — тот же порядок, что соберёт api.NewRouter, минус базовый лимитер по IP
// (он проверяется интеграционным тестом сборки): request id, журнал, конверт.
// mux передаётся дважды: журналу он нужен, чтобы назвать маршрут до диспетчера,
// а Envelope — чтобы этот диспетчер найти.
func chain(mux *http.ServeMux, log *slog.Logger) http.Handler {
	return NewRequestID(Logging(Envelope(mux), mux, log))
}

// jsonLine читает первую строку журнала: паника и предупреждения добавляют свои
// строки, и тесты про журнал обязаны отличаться от тестов про панику именно этим.
func jsonLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := bytes.TrimSpace(buf.Bytes())
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("journal must start with one JSON line: %v (%q)", err, buf.String())
	}
	return entry
}

func envelopeCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var got struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q is not the documented envelope: %v", w.Body, err)
	}
	if !isHex16(got.Error.RequestID) {
		t.Errorf("request_id %q must be 16 hex chars", got.Error.RequestID)
	}
	return got.Error.Code
}

func TestLoggingNamesRouteStatusUserAndWritesOneLine(t *testing.T) {
	var buf bytes.Buffer
	user := uuid.New()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		// Так делает auth.Middleware: subject известен только внутри обработчика.
		// Новый контекст здесь не обязателен: аккумулятор живёт в старом ctx
		// и доступен по указателю.
		_ = WithUserID(r.Context(), user)
		_, _ = w.Write([]byte("ok"))
	})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("matched route: %d %q", w.Code, w.Body.String())
	}

	// Ровно одна строка: если NewRequestID всё ещё пишет свою «http», тест ловит
	// это здесь, а не через неделю, когда журнал начнут парсить.
	if n := bytes.Count(bytes.TrimSpace(buf.Bytes()), []byte("\n")) + 1; n != 1 {
		t.Fatalf("journal lines = %d, want 1: %s", n, buf.String())
	}

	entry := jsonLine(t, &buf)
	want := map[string]string{
		"msg":     "request",
		"method":  "GET",
		"route":   "GET /api/v1/me",
		"user_id": user.String(),
	}
	for k, v := range want {
		if got, _ := entry[k].(string); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if entry["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200", entry["status"])
	}
	if id, _ := entry["request_id"].(string); !isHex16(id) {
		t.Errorf("request_id = %q, want 16 hex chars", id)
	}
	if _, ok := entry["dur_ms"].(float64); !ok {
		t.Error("dur_ms must be a number: §5.2 требует длительность")
	}
}

func TestEnvelopeNotFoundHasEnvelopeAndUnmatchedRoute(t *testing.T) {
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/nothing?token=super-secret-value", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if code := envelopeCode(t, w); code != "not_found" {
		t.Errorf("code = %q, want not_found", code)
	}
	// 404 не имеет права врать про Allow: этот путь не принимает никакой метод.
	if w.Header().Get("Allow") != "" {
		t.Errorf("Allow = %q, want empty for 404", w.Header().Get("Allow"))
	}

	entry := jsonLine(t, &buf)
	// Путь клиента в журнале отсутствует намеренно: это единственное место, где
	// чужой запрос мог бы протащить в лог токен из query-строки.
	if entry["route"] != "unmatched" {
		t.Errorf("route = %v, want unmatched", entry["route"])
	}
	if entry["status"] != float64(http.StatusNotFound) {
		t.Errorf("status = %v, want 404", entry["status"])
	}
	if _, ok := entry["user_id"]; ok {
		t.Error("user_id must be absent when nobody is authenticated")
	}

	lower := strings.ToLower(buf.String())
	if strings.Contains(lower, "super-secret-value") {
		t.Error("journal contains the query string")
	}
	for _, forbidden := range []string{"authorization", "password", "refresh_token", "token="} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("journal mentions %q", forbidden)
		}
	}
}

func TestEnvelopeMethodNotAllowedListsAllowedMethods(t *testing.T) {
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/devices", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /api/v1/devices", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodPut, "/api/v1/devices", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if code := envelopeCode(t, w); code != "method_not_allowed" {
		t.Errorf("code = %q, want method_not_allowed", code)
	}
	// HEAD обязателен: ServeMux принимает HEAD на зарегистрированный GET, и Allow
	// без HEAD обещал бы меньше, чем сервер действительно принимает.
	allow := w.Header().Get("Allow")
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		if !strings.Contains(allow, m) {
			t.Errorf("Allow = %q, missing %s", allow, m)
		}
	}
	if strings.Contains(allow, http.MethodPut) {
		t.Errorf("Allow = %q contains the rejected method", allow)
	}
	if entry := jsonLine(t, &buf); entry["status"] != float64(http.StatusMethodNotAllowed) {
		t.Errorf("journal status = %v, want 405", entry["status"])
	}
}

func TestEnvelopeTrailingSlashIsNotFound(t *testing.T) {
	// Go не делает из "/api/v1/devices/" редирект на "/api/v1/devices": pattern
	// пустой. Значит ответ формирует Envelope, и это конверт, а не текст.
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/devices/", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d %q, want 404", w.Code, w.Body.String())
	}
	if code := envelopeCode(t, w); code != "not_found" {
		t.Errorf("code = %q, want not_found", code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, API не должен делать из маршрута тихую переадресацию", loc)
	}
}

func TestEnvelopeKeepsServeMuxPathCleanupRedirect(t *testing.T) {
	// "/api/v1//devices" Go чистит и отвечает 301 сам; pattern при этом —
	// зарегистрированный маршрут. Envelope обязан пропустить этот handler:
	// редирект не скрывает токенов и не ломает формат ошибок (тела у 301 нет).
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices", func(http.ResponseWriter, *http.Request) {})

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1//devices", nil))
	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d %q, want 301", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/api/v1/devices" {
		t.Errorf("Location = %q, want /api/v1/devices", loc)
	}
	// В журнале — шаблон, а не путь клиента: двойная косая черта туда не попадает.
	if entry := jsonLine(t, &buf); entry["route"] != "GET /api/v1/devices" {
		t.Errorf("route = %v, want GET /api/v1/devices", entry["route"])
	}
}

func TestLoggingRecoversPanicWithEnvelope(t *testing.T) {
	// http.Server переживает панику сам, но соединение при этом обрывается, а
	// журнал не пишется вовсе. Клиент обязан получить конверт, а ops — строку.
	var buf bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })

	w := httptest.NewRecorder()
	chain(mux, slog.New(slog.NewJSONHandler(&buf, nil))).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/api/v1/boom", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("panic must answer 500, got %d", w.Code)
	}
	if code := envelopeCode(t, w); code != "internal" {
		t.Errorf("code = %q, want internal", code)
	}
	line := buf.String()
	if !strings.Contains(line, `"route":"GET /api/v1/boom"`) {
		t.Errorf("journal must name the route of the crashed handler: %s", line)
	}
	if !strings.Contains(line, `"status":500`) {
		t.Errorf("journal must record 500: %s", line)
	}
	if !strings.Contains(line, "boom") {
		t.Errorf("panic reason must reach the journal: %s", line)
	}
}

func TestEnvelopeWorksWithoutLogging(t *testing.T) {
	// noteRoute обязан молчать без журнала: Envelope используется и в тестах
	// модулей, где Logging не подключён.
	mux := http.NewServeMux()
	w := httptest.NewRecorder()
	Envelope(mux).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestWithUserIDWithoutJournalDoesNotPanic(t *testing.T) {
	id := uuid.New()
	ctx := WithUserID(context.Background(), id)
	got, ok := UserIDFromContext(ctx)
	if !ok || got != id {
		t.Errorf("UserIDFromContext = (%v, %v), want (%v, true)", got, ok, id)
	}
}
```

Run: `make unit`
Expected: FAIL — `undefined: Envelope`, `undefined: Logging`. Пакет не компилируется
целиком, поэтому остальные падения станут видны только после шага 2 — это и есть
ожидаемое «красное» состояние.

- [ ] **Step 2: Реализовать конверт и журнал**

`internal/httpx/mux.go`:

```go
package httpx

import (
	"net/http"
	"strings"
)

// PatternResolver — то, что умеет сказать, каким шаблоном будет обслужен запрос.
// *http.ServeMux удовлетворяет ему методом Handler(r); matching делает сам mux, и
// снаружи его восстановить нечем.
type PatternResolver interface {
	Handler(*http.Request) (http.Handler, string)
}

// probeMethods — чем Envelope спрашивает «принимает ли этот путь другой метод».
// HEAD здесь не лишняя строка: ServeMux матчит HEAD на зарегистрированный GET, и
// Allow без HEAD противоречил бы тому, что сервер действительно принимает.
var probeMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost,
	http.MethodPut, http.MethodPatch, http.MethodDelete,
}

// Envelope превращает «такого маршрута нет» и «метод не тот» в документированный
// конверт (§5.2): на оба случая ServeMux пишет plain text без request_id и
// возвращает пустой pattern — при условии, что "/" не зарегистрирован.
//
// Сборщик обязан НЕ регистрировать "/": с catch-all'ом и отсутствующий путь, и
// несовпадение метода уходят в него, pattern перестаёт быть пустым, и отличить
// 404 от 405 становится нечем.
//
// Имя маршрута в журнал здесь не пишется — это делает Logging (правило 3 выше).
func Envelope(routes PatternResolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, pattern := routes.Handler(r)
		if pattern != "" {
			handler.ServeHTTP(w, r)
			return
		}
		// Ветка «метод не тот» обязана проверяться до 404: у ServeMux оба случая
		// выглядят одинаково (pattern ""), различает их только перебор методов.
		if allow := allowedMethods(routes, r); len(allow) > 0 {
			w.Header().Set("Allow", strings.Join(allow, ", "))
			WriteError(w, r, http.StatusMethodNotAllowed, ErrMethodNotAllowed,
				"method not allowed for this route", map[string]any{"allowed": allow})
			return
		}
		WriteError(w, r, http.StatusNotFound, ErrNotFound, "route not found", nil)
	})
}

func allowedMethods(routes PatternResolver, r *http.Request) []string {
	var allow []string
	for _, m := range probeMethods {
		// Текущий метод уже проверен: раз мы сюда дошли, pattern для него пустой.
		if m == r.Method {
			continue
		}
		// Clone, а не правка r: подменённый метод не имеет права просочиться в
		// основной запрос.
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, p := routes.Handler(probe); p != "" {
			allow = append(allow, m)
		}
	}
	return allow
}
```

`internal/httpx/logging.go`:

```go
package httpx

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
)

// routeUnmatched — значение поля route в журнале, когда не совпал ни один шаблон.
// Путь клиента не пишется никогда: в нём бывают токены в query-строке.
const routeUnmatched = "unmatched"

// journal — изменяемый аккумулятор одной строки журнала. Поля дописываются
// изнутри (route — из Envelope, subject — из WithUserID), а строка пишется снаружи
// после next.ServeHTTP: иначе user id, который появляется только после проверки
// JWT, в журнал не попал бы никогда.
type journal struct {
	mu      sync.Mutex
	route   string
	userID  uuid.UUID
	hasUser bool
}

type journalKey struct{}

func withJournal(ctx context.Context) (context.Context, *journal) {
	j := &journal{}
	return context.WithValue(ctx, journalKey{}, j), j
}

// noteRoute запоминает имя совпавшего шаблона. Вызывается ровно один раз — из
// Logging, до диспетчера, чтобы отказ лимитера и 401 тоже получили настоящее имя.
func noteRoute(ctx context.Context, pattern string) {
	if j, ok := ctx.Value(journalKey{}).(*journal); ok {
		j.mu.Lock()
		j.route = pattern
		j.mu.Unlock()
	}
}

// noteUserID — то же для субъекта. Вызывается из WithUserID (задача 9) и обязан
// быть безопасен без журнала: тесты хендлеров строят контекст сами.
func noteUserID(ctx context.Context, id uuid.UUID) {
	if j, ok := ctx.Value(journalKey{}).(*journal); ok {
		j.mu.Lock()
		j.userID, j.hasUser = id, true
		j.mu.Unlock()
	}
}

func (j *journal) attrs() []any {
	j.mu.Lock()
	defer j.mu.Unlock()
	route := j.route
	if route == "" {
		route = routeUnmatched
	}
	attrs := []any{"route", route}
	if j.hasUser {
		attrs = append(attrs, "user_id", j.userID.String())
	}
	return attrs
}

// statusWriter запоминает код ответа и то, отправлены ли уже заголовки. Переехал
// из requestid.go: единственный читатель статуса теперь Logging.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(p)
}

// Logging пишет ровно одну строку на запрос: request id, маршрут, статус,
// длительность и user id (спецификация §5.2). Заголовки, query-строка, путь и
// тело не пишутся никогда: в них живут токены, а ТЗ §10 и §15 запрещают их в
// журнале. Поэтому несуществующий маршрут записывается как "unmatched", а не тем
// путём, который прислал клиент.
//
// routes — тот же ServeMux, что отдаёт запрос ниже: журнал должен назвать маршрут
// до диспетчера, иначе 429 и 401 записались бы как "unmatched".
func Logging(next http.Handler, routes PatternResolver, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, j := withJournal(r.Context())
		req := r.WithContext(ctx)
		_, pattern := routes.Handler(r)
		noteRoute(ctx, pattern)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		// Порядок отложенных вызовов значим: они исполняются в обратном порядке,
		// поэтому recover (ниже) успевает поставить 500 до записи строки (выше).
		defer func() {
			attrs := append([]any{
				"request_id", RequestIDFromContext(ctx),
				"method", r.Method,
				"status", sw.status,
				"dur_ms", time.Since(start).Milliseconds(),
			}, j.attrs()...)
			log.Info("request", attrs...)
		}()

		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// Стек в журнал можно: он описывает наш код, а не запрос клиента.
			log.Error("handler panic",
				"request_id", RequestIDFromContext(ctx),
				"panic", fmt.Sprint(rec),
				"stack", string(debug.Stack()))
			if !sw.wrote {
				// Если обработчик уже начал писать тело, дописывать конверт
				// нельзя: клиент получил бы JSON в середине ответа.
				WriteError(sw, req, http.StatusInternalServerError, ErrInternal,
					"internal error", nil)
			}
		}()

		next.ServeHTTP(sw, req)
	})
}
```

`internal/httpx/requestid.go` — после переезда `statusWriter` и удаления журнальной
строки файл выглядит целиком так (`time` больше не нужен):

```go
package httpx

import (
	"context"
	"net/http"
)

type ctxKey int

const requestIDKey ctxKey = 1

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// NewRequestID присваивает идентификатор и пишет доступный для клиента заголовок.
// Клиентский X-Request-Id принимается только если он уже правильного формата:
// иначе заголовок становится каналом для подстановки в логи.
//
// Журнал запроса здесь больше не пишется: строка обязана быть одна, и её делает
// Logging. Здесь остаются контекст и заголовок.
func NewRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !isHex16(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), id)))
	})
}

func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
```

Два следствия, которые легко промотреть:

1. `NewRequestID` больше не оборачивает `w` в `statusWriter`, потому что единственный
   читатель статуса стоит внутри и оборачивает сам. Если позже понадобится статус на
   уровне `NewRequestID`, обёртку надо возвращать целиком, а не две вложенные:
   `statusWriter` пишет `WriteHeader` ровно один раз и не знает о соседях.
2. `X-Request-Id` ставится до вызова `next`, поэтому он есть и в успешном ответе, и в
   конверте, который пишет `Envelope` (тот же `w`).

`internal/httpx/context.go` — `WithUserID` дополнить сообщением в журнал:

```go
func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	// Журналу нужен сам субъект, а не новый контекст: аккумулятор живёт в
	// предыдущем ctx и доступен по указателю.
	noteUserID(ctx, id)
	return context.WithValue(ctx, userIDKey{}, id)
}
```

Run: `make unit && make vet`
Expected: PASS.

- [ ] **Step 3: Написать падающий интеграционный тест сборки**

`tests/integration/router_test.go`. Хелперы `pool`, `bytes32ForTests`, `do`,
`errorCode`, `decodeSession`, `testPassword` уже объявлены в этом же пакете (задачи 9,
12 и 17) — повторять их здесь нельзя, пакет не скомпилируется. Добавляется только
`isolatedRedis`, и он нужен по делу: token bucket живёт в общем Redis, а тест лимитов,
запущенный после `auth_flow_test.go`, иначе ловил бы чужой 429 (или не ловил бы свой).
Девятая база — отдельное пространство именно для этого теста; dev-Redis в compose
настроен на 16 баз, и их больше никто не трогает.

```go
//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/services/api"
)

// isolatedRedis — чистый Redis для тестов сборки: бакеты лимитеров и denylist
// не переходят между тестами.
func isolatedRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr, DB: 9})
	ctx := context.Background()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis db 9 at %s: %v", addr, err)
	}
	// FlushDB бьёт только по девятой базе: её использует исключительно этот файл.
	if err := c.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush db 9: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newRouter(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	h := api.NewRouter(api.Deps{
		Cfg: config.Config{
			Env:        config.EnvDev,
			JWTSecret:  bytes32ForTests(),
			AccessTTL:  10 * time.Minute,
			RefreshTTL: 24 * time.Hour,
		},
		Pool: pool(t),
		RDB:  isolatedRedis(t),
		Ent:  entitlements.New(db.New(pool(t))),
		Log:  slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, &buf
}

func TestRouterServesDocumentedRoutes(t *testing.T) {
	srv, _ := newRouter(t)
	base := srv.URL

	// Несуществующий путь — тот же конверт, что и все остальные ошибки (§5.2).
	resp, body := do(t, http.MethodGet, base+"/api/v1/nothing-here", nil, "")
	if resp.StatusCode != http.StatusNotFound || errorCode(t, body) != "not_found" {
		t.Fatalf("unknown path = %d %v, want 404 not_found", resp.StatusCode, body)
	}

	// Закрытый маршрут без токена — 401, и это НЕ 404: маршрут существует и
	// смонтирован. Именно так тест отличает «забыли подключить devices» от
	// «подключили, но требовательно».
	resp, body = do(t, http.MethodGet, base+"/api/v1/devices", nil, "")
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "unauthenticated" {
		t.Fatalf("devices without token = %d %v", resp.StatusCode, body)
	}

	// Health живёт вне /api/v1 и не требует аутентификации.
	resp, _ = do(t, http.MethodGet, base+"/debug/health", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", resp.StatusCode)
	}
	// Сквозной путь (register → me → devices) здесь не повторяется: он
	// в auth_flow_test.go. Здесь проверяется именно сборка, а не правила.
}

func TestRouterRejectsMethodWithEnvelope(t *testing.T) {
	srv, _ := newRouter(t)
	// ServeMux на PUT к login ответил бы текстом без request_id; «единый формат
	// ошибки» соблюдается только если сборщик дописывает конверт сам.
	resp, body := do(t, http.MethodPut, srv.URL+"/api/v1/auth/login", nil, "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d %v, want 405", resp.StatusCode, body)
	}
	if errorCode(t, body) != "method_not_allowed" {
		t.Errorf("body = %v, want code method_not_allowed", body)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, "POST") {
		t.Errorf("Allow = %q, must list POST", allow)
	}
}

func TestRouterJournalHasNoSecrets(t *testing.T) {
	srv, buf := newRouter(t)
	base := srv.URL
	email := "journal-" + uuid.NewString()[:8] + "@novavpn.test"

	resp, body := do(t, http.MethodPost, base+"/api/v1/auth/register",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d %v", resp.StatusCode, body)
	}
	sess := decodeSession(t, body)

	lower := strings.ToLower(buf.String())
	if strings.Contains(lower, strings.ToLower(testPassword)) {
		t.Error("journal contains the password")
	}
	if strings.Contains(lower, strings.ToLower(sess.AccessToken)) ||
		strings.Contains(lower, strings.ToLower(sess.RefreshToken)) {
		t.Error("journal contains a token")
	}
	if strings.Contains(lower, "authorization") {
		t.Error("journal mentions the Authorization header")
	}
	if !strings.Contains(buf.String(), `"route":"POST /api/v1/auth/register"`) {
		t.Errorf("journal must carry the matched route, got %s", buf.String())
	}

	// /me — здесь появляется user id: без него матрицу «роль × маршрут» из задачи 19
	// нечем проверять, кроме статуса.
	buf.Reset()
	resp, body = do(t, http.MethodGet, base+"/api/v1/me", nil, sess.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me = %d %v", resp.StatusCode, body)
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("journal line: %v (%s)", err, buf.String())
	}
	if entry["route"] != "GET /api/v1/me" {
		t.Errorf("route = %v", entry["route"])
	}
	if uid, _ := entry["user_id"].(string); len(uid) != 36 {
		t.Errorf("user_id = %q, want uuid of the authenticated user", uid)
	}
	if id, _ := entry["request_id"].(string); len(id) != 16 {
		t.Errorf("request_id = %q, want 16 hex chars", id)
	}
}

func TestRouterRateLimitsAnonymousRoutes(t *testing.T) {
	srv, _ := newRouter(t)
	base := srv.URL

	// Анонимный register обязан упереться в bucket по IP: burst = 5, так что 429
	// приходит не позже шестого запроса. Email каждый раз новый — значит 409
	// исключён, и 429 нельзя объяснить конфликтом.
	var codes []int
	for i := 0; i < 40; i++ {
		resp, _ := do(t, http.MethodPost, base+"/api/v1/auth/register",
			map[string]string{"email": "rl-" + uuid.NewString()[:8] + "@novavpn.test",
				"password": testPassword}, "")
		codes = append(codes, resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
	}
	limited := false
	for i, c := range codes {
		if c == http.StatusTooManyRequests {
			limited = true
			break
		}
		if c != http.StatusCreated {
			t.Fatalf("attempt %d = %d, want 201 before the limit, all=%v", i, c, codes)
		}
	}
	if !limited {
		t.Fatalf("anonymous register must hit the per-IP bucket, got %v", codes)
	}
}
```

Run: `make integration`
Expected: FAIL — `undefined: api.NewRouter`, `undefined: api.Deps`. Если падают
`undefined: httpx.Envelope` или `httpx.Logging`, шаг 2 не закоммичен.

- [ ] **Step 4: Реализовать `services/api/router.go`**

```go
// Package api собирает http.Handler из модулей. Бизнес-логики здесь нет: auth,
// devices и entitlements отвечают за правила, этот пакет решает, что с чем
// соединить и какие лимиты навесить.
package api

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

// Окна лимитов. Спецификация §5.2 требует «register/login — по IP и по аккаунту»,
// но не задаёт чисел: числа — решение A-1, и правка умещается в одну строку.
// Осью «по аккаунту» для login заведует LoginGuard (прогрессивная задержка),
// поэтому здесь остаётся IP.
const (
	// anyPerMin — базовое окно на IP для любого запроса, включая те, что не
	// совпали ни с одним маршрутом: 404/405 обслуживает Envelope вне decorators,
	// и без этого окна «несуществующий путь» оставался бы единственным
	// endpoint'ом без лимита.
	anyPerMin = 300.0
	anyBurst  = 60
	// Анонимные маршруты: bucket на пару (маршрут, IP) — register, login,
	// refresh и logout не съедают бюджет друг у друга.
	anonPerMin = 20.0
	anonBurst  = 5
	// Закрытые маршруты: bucket на пользователя.
	userPerMin = 600.0
	userBurst  = 50
)

// planSlug — единственный план A-1; он же seed из миграции 0003 (задача 4).
const planSlug = "internal-default"

type Deps struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
	RDB  *redis.Client
	Ent  *entitlements.Service
	Log  *slog.Logger
}

func NewRouter(d Deps) http.Handler {
	q := db.New(d.Pool)
	lim := httpx.NewLimiter(d.RDB, d.Log)
	deny := auth.NewRedisDenylist(d.RDB, d.Log)
	iss := auth.NewIssuer(d.Cfg.JWTSecret, d.Cfg.AccessTTL)
	sess := auth.NewSessionService(q, iss, deny, d.Cfg.RefreshTTL, d.Log)
	guard := auth.NewLoginGuard(d.RDB, d.Log)

	// "/" здесь нет намеренно: с catch-all'ом Envelope теряет отличие 404 от 405.
	mux := http.NewServeMux()

	dec := httpx.Decorators{
		// Закрытый маршрут: сначала проверка access JWT и denylist, потом bucket
		// на пользователя. Порядок важен — userKey читает user id из контекста,
		// а появляется он только после auth.Middleware.
		Auth: func(next http.Handler) http.Handler {
			return auth.Middleware(sess, deny)(
				lim.Middleware("user", httpx.RatePerMinute(userPerMin), userBurst, userKey)(next))
		},
		Anonymous: lim.Middleware("anon", httpx.RatePerMinute(anonPerMin), anonBurst, routeIPKey(mux)),
	}

	mux.HandleFunc("GET /debug/health", health)

	// Модуль объявляет маршруты и то, закрыт ли каждый; политика (JWT, лимиты,
	// числа) — здесь. Поэтому register и login не монтируются второй раз:
	// повторный mux.Handle на тот же шаблон — паника, а не ошибка компиляции.
	auth.NewHandler(sess, d.Pool, d.Ent, guard, planSlug, d.Log).RegisterRoutes(mux, dec)
	devices.NewHandler(devices.NewService(d.Pool, d.Ent),
		httpx.NewIdempotency(httpx.NewPGIdempotency(d.Pool))).RegisterRoutes(mux, dec)

	// Порядок цепочки: request id (чтобы конверт 404 имел что поставить в
	// request_id), журнал (видит и 429, и панику, и называет маршрут до диспетчера),
	// базовое окно по IP, конверт.
	baseline := lim.Middleware("any", httpx.RatePerMinute(anyPerMin), anyBurst, ipKey)
	return httpx.NewRequestID(httpx.Logging(baseline(httpx.Envelope(mux)), mux, d.Log))
}

// health — статический ответ: жив ли процесс. Проверок БД и Redis здесь нет
// сознательно: readiness с зависимостями и метрики появляются в цикле C, а
// «health» с таймаутом на базу сам становится источником отказов.
func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// routeIPKey — bucket на пару (маршрут, IP). Имя маршрута спрашивается у самого
// ServeMux: Handler(r) — единственная публичная возможность это сделать, и она
// безопасна для параллельных запросов, потому что регистрация всех маршрутов
// закончена до старта сервера.
func routeIPKey(mux *http.ServeMux) func(*http.Request) string {
	return func(r *http.Request) string {
		_, pattern := mux.Handler(r)
		return pattern + "|" + ipKey(r)
	}
}

func ipKey(r *http.Request) string {
	// Единственный источник IP — auth.ClientIP (задача 17): он берёт RemoteAddr и
	// намеренно не верит X-Forwarded-For, потому что доверять заголовку без
	// настроенного списка прокси — это способ обойти собственный лимит. Решению
	// «сервер стоит за reverse proxy, где RemoteAddr у всех один» посвящён
	// отдельный пункт в цикле A-3 (Ansible + балансировщик), здесь оно было бы
	// догадкой.
	if ip := auth.ClientIP(r); ip != nil {
		return ip.String()
	}
	return "unknown"
}

func userKey(r *http.Request) string {
	id, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		return "anonymous"
	}
	return id.String()
}
```

Три замечания к коду выше:

1. `routeIPKey(mux)` захватывает `mux` до того, как в него что-либо смонтировано. Это
   правильно: `Handler` вызывается во время запроса, а все `Handle` завершены до
   `http.Server.Serve`. Если маршруты начнут регистрироваться после старта — это станет
   гонкой, и `TestRouterRateLimitsAnonymousRoutes` её поймает.
2. Запросы, которым не нашлось маршрута, проходят через `baseline`, но не через `dec`:
   404 и 405 лимитируются общим окном по IP. Именно поэтому `anyPerMin` больше
   `anonPerMin`, а не наоборот.
3. `Deps.Log` обязателен и не проверяется на `nil`: `NewLimiter`,
   `NewRedisDenylist` и `Logging` обращаются к логгеру сразу, а инициализация
   `main.go` и все интеграционные тесты передают его. Проверка `if d.Log == nil`
   здесь была бы защитой от случая, который не может наступить.

- [ ] **Step 5: Собрать процесс и остановить его по сигналу**

`services/api/cmd/novavpn-api/main.go` — заменить только `serve` из задачи 1.
`case "migrate":` из задачи 5 не трогаем: он уже реализован (`up|all|version`), покрыт
`make migrate-up`/`make migrate-down` и интеграционным тестом, а `case "serve":
return serve(cfg)` остаётся прежним — сигнатура `serve(config.Config) error` не меняется.

```go
func serve(cfg config.Config) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Pool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	defer rdb.Close()

	handler := api.NewRouter(api.Deps{
		Cfg: cfg, Pool: pool, RDB: rdb,
		Ent: entitlements.New(db.New(pool)), Log: log,
	})
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.ListenAddr, "env", cfg.Env)

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
	}

	// Активные соединения дозаписывают ответ: kill switch у HTTP-сервера без
	// Shutdown означает «оборви чужую выдачу токенов на середине тела».
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}
```

Импорты файла целиком: `context`, `errors`, `flag`, `fmt`, `log/slog`, `net/http`, `os`,
`os/signal`, `syscall`, `time`, `github.com/redis/go-redis/v9`,
`github.com/novavpn/novavpn/internal/api`, `internal/config`, `internal/db`,
`internal/db/migrate`, `internal/entitlements`. Из задачи 1 в списке остаётся `net/http`
(он нужен `http.Server`), а `errors` и `flag` нужны `run` и ветке `migrate` из задачи 5.

Два следствия, их стоит проговорить:

1. `ctx` из `signal.NotifyContext` передаётся в `db.Pool` — пул получает корректный
   startup-контекст, и `Ctrl-C` во время первого соединения не оставляет процесс
   «висящим на подключении». Для `srv.Shutdown` контекст берётся отдельный и новый:
   завершающий сигнал уже получен, и старый `ctx` к этому моменту в состоянии `Done`,
   поэтому переиспользовать его означало бы отменить shutdown немедленно.
2. `defer pool.Close()` и `defer rdb.Close()` исполняются после `Shutdown`, а не до:
   Go разворачивает отложенные вызовы в конце функции, и активные запросы уже
   дозаписали ответы. Если переставить `Close` в ветку `errCh`, соединение с базой
   закроется у запроса на середине тела.

- [ ] **Step 6: Прогнать и коммитить**

Run: `make up-dev && make migrate-up`, затем `make run-dev`; в другом окне —
`curl -i localhost:8080/debug/health` и `curl -i localhost:8080/api/v1/devices`, затем
`Ctrl-C` в окне процесса.
Expected: процесс стартует с `"msg":"listening"`; health отвечает `ok`; `/api/v1/devices`
без токена — конверт 401 с заголовком `X-Request-Id`; несуществующий путь — конверт 404,
а не `404 page not found`; `PUT /api/v1/auth/login` — 405 с `Allow: POST` и конвертом.
По `Ctrl-C` появляется `"msg":"stopped"` и процесс выходит с кодом 0 (проверяется
`echo $?` сразу после выхода). Если выход по сигналу не происходит за 10 секунд —
`Shutdown` не получил контекст или обработчик завис; это дефект сборки, а не тестовой
среды.

Run: `make integration`
Expected: PASS — все тесты сборки, включая `TestRouterJournalHasNoSecrets` и
`TestRouterRateLimitsAnonymousRoutes`.

Run: `make unit && make vet`
Expected: PASS.

```bash
git add services/api internal/httpx tests/integration/router_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(api): сборка маршрутов, журнал запроса в конверте и graceful shutdown"
```
---

### Task 19: Приёмка A-1 — матрица «роль × маршрут», живое соответствие контракту, статус тестов

**Files:**
- Create: `tests/integration/matrix_test.go`, `tests/integration/contract_test.go`,
  `docs/testing-status.md`

**Interfaces:**
- Consumes: `api.NewRouter`/`api.Deps` и `newRouter(t)` (задача 18), `pool` (9),
  `bytes32ForTests`, `seedUser` (12), `keyAt` (15), `jsonBody`, `decodeSession`,
  `testPassword`, `isHex16`, `discardLog` (17), `auth.NewIssuer`,
  `auth.NewSessionService` (11–13), `db.New` (6), константы `httpx.Err*` (7 и 16),
  `gopkg.in/yaml.v3` (16).
- Produces: `raw(t, e, method, path, body, hdr) (*http.Response, []byte)`, `newIdem()`,
  `idem()`, `idemWith(key)` и `type env` с актёрами состояний — всё это использует
  `contract_test.go` в этом же пакете; `validate(n node, v any, s *spec, path string)
  []string` — минимальный валидатор подмножества JSON Schema; `docs/testing-status.md`.

Три вещи, которые без этой задачи остаются «на словах»:

1. **Матрица «роль × маршрут».** Спецификация §5.2 требует проверки права на объект, а
   не только факта аутентификации, и §7.4 — жёсткого лимита устройств. По одному тесту на
   маршрут есть в задачах 15–18, но нигде нет таблицы «что видит аноним, участник,
   человек с истёкшей подпиской и заблокированный аккаунт на каждом документе маршруте».
2. **Живое соответствие контракту.** Задача 16 обещала: «следующая задача обязана отдать
   ровно то, что обещано здесь, и проверка этого — не глаз, а тест». Здесь этот тест.
3. **Что не проверялось.** ТЗ §19.10 прямо запрещает объявлять механизмы проверенными без
   прогонов. Значит состояние прогонов — часть поставки, а не примечание в коммите.

Четыре ограничения, которые определяют форму этого теста и править их «по ходу» нельзя:

- `seedUser` (задача 12) может называться `seedUserWithPlan`, если переименование из
  задачи 13 до неё дожило. Бери то имя, что живёт в `helpers_test.go` сейчас, и не
  переименовывай обратно ради этого теста.
- Подготовка состояний идёт **не** через HTTP-логин, а через `SessionService.NewSession`
  напрямую: `dec.Anonymous` — bucket на пару (маршрут, IP) с burst 5 (задача 18), и
  матрица, которая заводит участников публичным register, съедала бы собственный лимит и
  падала 429 в зависимости от порядка тестов. Считай в одном тесте вызовы на один
  анонимный маршрут — не больше четырёх; списки ниже составлены с этим счётом.
- Заголовки — только ASCII: `net/http` отказывается писать значение заголовка с байтом
  выше 0x7F, а `t.Name()` подтеста с русским именем — ровно такой случай. Поэтому ключ
  идемпотентности берётся из `newIdem()`, а не из имени теста.
- Каждый `run` обязан заканчиваться **целевым** вызовом: `TestAccessMatrix` читает
  конверт из последней записанной пары `(status, body)`, и «проверка после проверки»
  сдвинула бы её на чужой ответ.

- [ ] **Step 1: Написать матрицу «роль × маршрут» со сбором доказательств**

`tests/integration/matrix_test.go`:

```go
//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

// captured — один прогнанный запрос с сырым ответом. Тело не распаковывается в
// словари: проверка секрета по строке обязана видеть ровно те байты, что ушли
// клиенту, включая те, что не влезли бы в map.
type captured struct {
	method, path string
	status       int
	body         []byte
}

// secret — значение, которое не имеет права оказаться в чужом ответе или в журнале.
// allow — единственные пути, где оно законно (так session-ответ имеет право содержать
// выданный им токен, а журнал — не имеет никогда).
type secret struct {
	label string
	value string
	allow []string
}

type evidence struct {
	calls   []captured
	secrets []secret
}

func (ev *evidence) addSecret(label, value string, allow ...string) {
	ev.secrets = append(ev.secrets, secret{label: label, value: value, allow: allow})
}

// env — собранный роутер (тот же, что в задаче 18) плюс способ получать состояния
// аккаунта, не дёргая публичные маршруты лишний раз.
type env struct {
	srv  *httptest.Server
	log  *bytes.Buffer
	q    *db.Queries
	sess *auth.SessionService
	ev   *evidence
}

// seedPassword — пароль, который кладёт в users хелпер seedUser (задача 12). Он не
// testPassword, и матрица обязана это различать: login по seed-аккаунту с testPassword
// был бы 401, и проверка «верный пароль» ничего не проверяла бы.
const seedPassword = "integration-password-123"

func newEnv(t *testing.T) *env {
	t.Helper()
	srv, buf := newRouter(t)
	q := db.New(pool(t))
	iss := auth.NewIssuer(bytes32ForTests(), 10*time.Minute)
	// Denylist этому сервису не нужен (nil): здесь он только выпускает сессии, а
	// NewSession его не читает. Отзыв семей идёт через сам HTTP, где denylist стоит в
	// роутере на девятой базе Redis; свой клиент с нулевой базы приплёл бы в тест
	// состояние, которого в проде нет.
	sess := auth.NewSessionService(q, iss, nil, 24*time.Hour, discardLog())
	// srv.Close уже зарегистрирован в newRouter (задача 18) — второй cleanup не нужен.
	e := &env{srv: srv, log: buf, q: q, sess: sess, ev: &evidence{}}
	e.ev.addSecret("test password", testPassword)
	e.ev.addSecret("seed password", seedPassword)
	return e
}

type actor struct {
	userID  uuid.UUID
	email   string
	access  string
	refresh string
}

// mint — состояние «пользователь есть в базе, подписка активна» без единого
// HTTP-запроса: seedUser создаёт аккаунт с подпиской internal-default, NewSession
// выпускает ему живую пару токенов. Ip = nil: колонка nullable, и анти-фрод-столбец
// проверяется в задаче 12, не здесь.
func (e *env) mint(t *testing.T) actor {
	t.Helper()
	ctx := context.Background()
	id := seedUser(t, ctx, e.q)
	s, err := e.sess.NewSession(ctx, id, nil)
	if err != nil {
		t.Fatalf("NewSession(%s): %v", id, err)
	}
	u, err := e.q.UserByID(ctx, id)
	if err != nil {
		t.Fatalf("UserByID(%s): %v", id, err)
	}
	e.ev.addSecret("access/"+id.String()[:8], s.AccessToken, issuePaths...)
	e.ev.addSecret("refresh/"+id.String()[:8], s.RefreshToken, issuePaths...)
	return actor{userID: id, email: u.Email, access: s.AccessToken, refresh: s.RefreshToken}
}

// issuePaths — единственные маршруты, ответ которых имеет право содержать выданный
// токен. Всё остальное (журнал, чужой ответ, 4xx-конверт) содержать токен не должно.
var issuePaths = []string{
	"/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh",
}

// lapse — подписка закончилась час назад: права на устройства нет, но аккаунт
// по-прежнему описывается /me. Оба поля меняются вместе, иначе падает CHECK
// subscriptions_window (ends_at > starts_at): seedUser вставляет starts_at = now(), и
// «now() − 1 час» оказался бы раньше собственного начала.
func (e *env) lapse(t *testing.T, a actor) actor {
	t.Helper()
	_, err := pool(t).Exec(context.Background(),
		`UPDATE subscriptions
		    SET starts_at = now() - interval '3 hours',
		        ends_at   = now() - interval '1 hour'
		  WHERE user_id = $1`, a.userID)
	if err != nil {
		t.Fatalf("lapse: %v", err)
	}
	return a
}

// block — статус locked. Причина обязательна (CHECK users_lock_reason), а её Go-форма
// зависит от того, как sqlc разметил nullable-параметр: здесь *string, как у всех
// nullable-параметров этого плана при emit_pointers_for_null_types (ср. DisplayName в
// InsertUserParams). Если сгенерирован скаляр — правь это место и оба вызова LockUser в
// задаче 17 тем же коммитом: в одном пакете две формы не компилируются.
func (e *env) block(t *testing.T, a actor) actor {
	t.Helper()
	reason := "acceptance-matrix"
	if err := e.q.LockUser(context.Background(), db.LockUserParams{
		ID: a.userID, LockedReason: &reason,
	}); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	return a
}

// register — участник, заведённый через сам API: этот путь обязан работать end-to-end,
// и только ради него матрица тратит анонимный bucket.
func (e *env) register(t *testing.T) actor {
	t.Helper()
	email := "matrix-" + uuid.NewString()[:8] + "@novavpn.test"
	resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/register",
		map[string]string{"email": email, "password": testPassword}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("register body: %v (%s)", err, body)
	}
	s := decodeSession(t, out)
	e.ev.addSecret("access/register", s.AccessToken, issuePaths...)
	e.ev.addSecret("refresh/register", s.RefreshToken, issuePaths...)
	e.ev.addSecret("email/register", email, "/api/v1/me")
	// ID участника берём из /me: ответ регистрации id не содержит (контракт — Session),
	// и это тоже проверка — /me по выданному токену обязан пускать.
	resp, body = raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(s.AccessToken))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me after register = %d %s", resp.StatusCode, body)
	}
	var me struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("me body: %v (%s)", err, body)
	}
	return actor{userID: uuid.MustParse(me.User.ID), email: email,
		access: s.AccessToken, refresh: s.RefreshToken}
}

// raw — то же, что do (задача 17), но с произвольными заголовками и сырым телом:
// сверка с контрактом идёт по байтам ответа, а не по уже распакованной карте.
// Каждый вызов попадает в evidence — и успешный, и провальный.
func raw(t *testing.T, e *env, method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = jsonBody(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	e.ev.calls = append(e.ev.calls, captured{
		method: method, path: path, status: resp.StatusCode, body: data,
	})
	return resp, data
}

// codeOf разбирает конверт и возвращает error.code; для пустого тела (204) — "".
func codeOf(t *testing.T, body []byte) string {
	t.Helper()
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("not an envelope: %v (%s)", err, body)
	}
	return v.Error.Code
}

// codeAndMessage — пара «code|message» из байт ответа, без request_id. Нужна ровно для
// одного: сравнить два отказа как «одинаковый ответ», не сравнив при этом случайное.
// Map-версия этого лежит в задаче 17 (envelopePair); здесь тело ещё не распаковано, и
// вторая функция дешевле, чем переписывать helper на байты.
func codeAndMessage(t *testing.T, body []byte) string {
	t.Helper()
	var v struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("not an envelope: %v (%s)", err, body)
	}
	return v.Error.Code + "|" + v.Error.Message
}

type routeCase struct {
	name string
	want int
	code string // "" — успешный ответ, тела-конверта нет
	run  func(t *testing.T, e *env) int
}

// Матрица. Строки сгруппированы по маршруту, чтобы читалось как таблица, а не как
// пересказ тестов задач 15–18. Числа в want/code — не «как удобно», а как обещано в
// api-spec/openapi.yaml; расхождение ловит Step 3, а не этот список.
func matrixCases() []routeCase {
	return []routeCase{
		{"GET /devices аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, nil)
			return resp.StatusCode
		}},
		{"GET /devices участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices без подписки", http.StatusOK, "", func(t *testing.T, e *env) int {
			// Список устройств — не право на новую выдачу: он остаётся доступен,
			// иначе человек не сможет посмотреть, что у него было.
			a := e.lapse(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /devices заблокированный (токен выдан до блокировки)", http.StatusOK, "", func(t *testing.T, e *env) int {
			// Замеренное ограничение, а не ошибка: middleware проверяет подпись, срок
			// и denylist, статус пользователя он не перечитывает. Окно = AccessTTL
			// (10 минут); срочный отзыв access — только denylist при logout.
			// Спецификация §13.11 это описывает, и описывает именно так.
			a := e.block(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"POST /devices аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(1), "platform": "linux", "name": "d"},
				idem())
			return resp.StatusCode
		}},
		{"POST /devices участник", http.StatusCreated, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(11), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices второй раз тем же ключом", http.StatusConflict, "duplicate_device", func(t *testing.T, e *env) int {
			a := e.mint(t)
			raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(12), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(12), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices тот же Idempotency-Key, другое тело", http.StatusConflict, "idempotency_key_conflict", func(t *testing.T, e *env) int {
			a := e.mint(t)
			key := newIdem()
			raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(13), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idemWith(key)))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(14), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idemWith(key)))
			return resp.StatusCode
		}},
		{"POST /devices без Idempotency-Key", http.StatusBadRequest, "idempotency_key_required", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(15), "platform": "linux", "name": "d"},
				authHdr(a.access))
			return resp.StatusCode
		}},
		{"POST /devices некорректный public_key", http.StatusBadRequest, "invalid_request", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": "not-a-key", "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"POST /devices без подписки", http.StatusForbidden, "forbidden", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(16), "platform": "linux", "name": "d"},
				merge(authHdr(a.access), idem()))
			return resp.StatusCode
		}},
		{"GET /me участник", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(a.access))
			return resp.StatusCode
		}},
		{"GET /me без подписки (plan null, limit 0)", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.lapse(t, e.mint(t))
			resp, body := raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(a.access))
			var me struct {
				Plan    *json.RawMessage `json:"plan"`
				Devices struct {
					Limit int `json:"limit"`
				} `json:"devices"`
			}
			if err := json.Unmarshal(body, &me); err != nil {
				t.Fatalf("me body: %v (%s)", err, body)
			}
			if me.Plan != nil {
				t.Errorf("lapsed plan must be null, got %s", *me.Plan)
			}
			if me.Devices.Limit != 0 {
				t.Errorf("lapsed limit = %d, want 0 (права на устройства нет)", me.Devices.Limit)
			}
			return resp.StatusCode
		}},
		{"GET /me аноним", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, nil)
			return resp.StatusCode
		}},
		{"GET /me произвольной подписью", http.StatusUnauthorized, "unauthenticated", func(t *testing.T, e *env) int {
			// Подпись HS256 проверяется на секрет сервера: «Bearer» со случайной
			// строкой — это 401, а не 500 и не «пустой субъект».
			resp, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil,
				map[string]string{"Authorization": "Bearer " + strings.Repeat("x", 64)})
			return resp.StatusCode
		}},
		{"POST /login правильный пароль", http.StatusOK, "", func(t *testing.T, e *env) int {
			// seed-аккаунт, а не register: этот случай ничего не должен анонимному
			// bucket'у register и берёт ровно один свой вызов.
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return resp.StatusCode
		}},
		{"POST /login неверный пароль", http.StatusUnauthorized, "invalid_credentials", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": "wrong-password-123"}, nil)
			return resp.StatusCode
		}},
		{"POST /login несуществующий адрес неотличим", http.StatusUnauthorized, "invalid_credentials", func(t *testing.T, e *env) int {
			// Целевой вызов — этот, сравнение берёт предыдущий (неверный пароль).
			// Различаются код и сообщение; request_id различаться обязан, поэтому в
			// сравнение не входит.
			resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": "ghost-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": seedPassword}, nil)
			prev := e.ev.calls[len(e.ev.calls)-2].body
			if codeAndMessage(t, prev) != codeAndMessage(t, body) {
				t.Errorf("unknown email differs from wrong password: %s vs %s", body, prev)
			}
			return resp.StatusCode
		}},
		{"POST /login заблокированного", http.StatusForbidden, "account_locked", func(t *testing.T, e *env) int {
			// Пароль верный: ответ «заблокирован» выдаётся только после проверки пароля
			// (задача 17), иначе сама блокировка стала бы оракулом существования адреса.
			a := e.block(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return resp.StatusCode
		}},
		{"POST /register повтор адреса", http.StatusConflict, "email_taken", func(t *testing.T, e *env) int {
			a := e.register(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": a.email, "password": testPassword}, nil)
			return resp.StatusCode
		}},
		{"POST /register слабый пароль", http.StatusBadRequest, "invalid_request", func(t *testing.T, e *env) int {
			resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": "weak-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": "short"}, nil)
			// Поле в details обязательно: без него клиент получает «что-то не так» и
			// угадывает, какое из двух полей портить.
			var v struct {
				Error struct {
					Details map[string]any `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(body, &v); err != nil {
				t.Fatalf("register 400 body: %v (%s)", err, body)
			}
			if v.Error.Details["field"] != "password" {
				t.Errorf("details = %v, want field=password", v.Error.Details)
			}
			return resp.StatusCode
		}},
		{"POST /refresh действующим", http.StatusOK, "", func(t *testing.T, e *env) int {
			a := e.mint(t)
			resp, body := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			var out map[string]any
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("refresh body: %v (%s)", err, body)
			}
			s := decodeSession(t, out)
			e.ev.addSecret("access/refreshed", s.AccessToken, issuePaths...)
			e.ev.addSecret("refresh/refreshed", s.RefreshToken, issuePaths...)
			// Переиспользование старого refresh здесь не проверяется: оно проверено
			// через HTTP в auth_flow_test.go (задача 17), а второй вызов на этот
			// маршрут был бы пятым в bucket'е — ровно тем запасом, который тест
			// не имеет права съедать.
			if s.RefreshToken == a.refresh || s.AccessToken == a.access {
				t.Error("refresh выдал ту же пару")
			}
			return resp.StatusCode
		}},
		{"POST /refresh мусором", http.StatusUnauthorized, "refresh_token_invalid", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": strings.Repeat("z", 48)}, nil)
			return resp.StatusCode
		}},
		{"POST /refresh заблокированного", http.StatusForbidden, "account_locked", func(t *testing.T, e *env) int {
			// Продление сессии — это доступ, а не «посмотреть состояние»: blocked
			// аккаунт нового доступа не получает (задача 17, шаг 4).
			a := e.block(t, e.mint(t))
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			return resp.StatusCode
		}},
		{"POST /logout своим refresh и повтор", http.StatusNoContent, "", func(t *testing.T, e *env) int {
			// Два вызова вместо двух строк: отзыв идемпотентен, и второй 204 — то же
			// доказательство, что отдельный случай, только дешевле по bucket'у.
			a := e.mint(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": a.refresh}, nil)
			if resp.StatusCode != http.StatusNoContent {
				return resp.StatusCode
			}
			again, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": a.refresh}, nil)
			return again.StatusCode
		}},
		{"POST /logout чужим access не отзывает не свою семью", http.StatusOK, "", func(t *testing.T, e *env) int {
			// Целевой вызов здесь — refresh: logout(x-заголовок, refresh y) обязан
			// отозвать семью y и не тронуть семью x. Access в заголовке — только
			// источник jti для denylist, и доказательством владения семьёй он быть не
			// может.
			x := e.mint(t)
			y := e.mint(t)
			lr, body := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": y.refresh}, authHdr(x.access))
			if lr.StatusCode != http.StatusNoContent {
				t.Fatalf("logout = %d %s, want 204", lr.StatusCode, body)
			}
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": x.refresh}, nil)
			return resp.StatusCode
		}},
		{"POST /logout мусором", http.StatusUnauthorized, "refresh_token_invalid", func(t *testing.T, e *env) int {
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": strings.Repeat("q", 48)}, nil)
			return resp.StatusCode
		}},
	}
}

func authHdr(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func newIdem() string { return "idem-" + uuid.NewString() }

// idem — свежий ключ на каждый вызов. Повтор ключа нужен ровно одному случаю (конфликт
// тела), и тот берёт его через idemWith.
func idem() map[string]string { return map[string]string{"Idempotency-Key": newIdem()} }

func idemWith(key string) map[string]string { return map[string]string{"Idempotency-Key": key} }

func merge(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func TestAccessMatrix(t *testing.T) {
	e := newEnv(t)
	for _, c := range matrixCases() {
		t.Run(c.name, func(t *testing.T) {
			status := c.run(t, e)
			if status != c.want {
				t.Fatalf("%s: status = %d, want %d", c.name, status, c.want)
			}
			last := e.ev.calls[len(e.ev.calls)-1]
			if c.code == "" {
				if last.status < 200 || last.status >= 300 {
					t.Fatalf("%s: want success, got %d %s", c.name, last.status, last.body)
				}
				return
			}
			if got := codeOf(t, last.body); got != c.code {
				t.Errorf("%s: code = %q, want %q (body %s)", c.name, got, c.code, last.body)
			}
		})
	}
	// 429 в матрице — не «так и задумано»: значит тест съел собственный лимит, и
	// вывод матрицы в этом прогоне недействителен.
	for _, c := range e.ev.calls {
		if c.status == http.StatusTooManyRequests {
			t.Fatalf("%s %s hit the rate limit — reduce anonymous calls below five",
				c.method, c.path)
		}
	}
	checkEvidence(t, e)
}

// checkEvidence — то, ради чего собирался evidence. ТЗ §10 и §15: токены, пароли и
// письма не попадают ни в журнал, ни в чужие ответы; §19.6 запрещает ключевой материал
// в ответах и логах вовсе.
func checkEvidence(t *testing.T, e *env) {
	t.Helper()
	journal := e.log.String()

	for _, s := range e.ev.secrets {
		if len(s.value) < 8 {
			t.Fatalf("secret %q is too short to check meaningfully", s.label)
		}
		// (1) журнал: ни одного секрета, никогда.
		if strings.Contains(journal, s.value) {
			t.Errorf("journal contains %s", s.label)
		}
		// (2) ответ: секрет разрешён только на тех маршрутах, где он выдаётся.
		for _, c := range e.ev.calls {
			if !bytes.Contains(c.body, []byte(s.value)) {
				continue
			}
			allowed := false
			for _, p := range s.allow {
				if c.path == p {
					allowed = true
				}
			}
			if !allowed {
				t.Errorf("%s appears in the answer of %s %s (%d)",
					s.label, c.method, c.path, c.status)
			}
		}
	}

	lower := strings.ToLower(journal)
	for _, marker := range []string{"authorization", "password", "bearer", "private_key",
		"-----begin", "refresh_token"} {
		if strings.Contains(lower, marker) {
			t.Errorf("journal mentions %q", marker)
		}
	}
	// Ответы: приватные ключи и хэши не возвращаются никогда — ни на 2xx, ни на 4xx
	// (в деталях ошибки их тоже быть не должно). Само слово «password» в список не
	// входит осознанно: его содержат разрешённые контрактом сообщения вида
	// «email or password is incorrect» и details «field: password» — а значение
	// пароля проверяется выше, циклом по secrets.
	for _, c := range e.ev.calls {
		lb := strings.ToLower(string(c.body))
		for _, marker := range []string{"private_key", "password_hash", "-----begin"} {
			if strings.Contains(lb, marker) {
				t.Errorf("%s %s (%d) body mentions %q: %s",
					c.method, c.path, c.status, marker, c.body)
			}
		}
		// Письмо — только в /me (контракт Me.user.email). В чужих и ошибочных ответах
		// его быть не может: это оракул «такой адрес есть».
		if c.path != "/api/v1/me" {
			for _, s := range e.ev.secrets {
				if !strings.Contains(s.label, "email") {
					continue
				}
				if bytes.Contains(c.body, []byte(s.value)) {
					t.Errorf("%s %s (%d) leaks %s: %s", c.method, c.path, c.status, s.label, c.body)
				}
			}
		}
	}

	// Журнал обязан содержать маршруты: без них проверка «ops видит, что случилось»
	// превращается в надежду.
	for _, p := range []string{"/api/v1/devices", "/api/v1/me"} {
		if !strings.Contains(journal, p) {
			t.Errorf("journal has no line for %s", p)
		}
	}
}
```

Run: `make integration` (можно сузить: `-run TestAccessMatrix`)
Expected: PASS по почти всем строкам. Что имеет право упасть и что это значит:

- `POST /logout чужим access не отзывает не свою семью` → refresh даёт 401. Значит
  `Revoke` берёт семью из контекста, а не из тела, либо logout смонтирован под
  `dec.Auth`. Это дыра: контракт (задача 16) прямо говорит, что отзыв доказывает
  refresh-токен в теле.
- `GET /me без подписки` → 403: контракт и код разошлись (шаг 3 ловит то же расхождение
  формально).
- `POST /refresh заблокированного` → 200: сломана проверка статуса в `Rotate` (задача 17,
  шаг 4) — это дыра, а не «тест придрался».
- `POST /login несуществующий адрес неотличим` → пары кода и сообщения различаются:
  `penalize` для двух веток разная, и ответ стал оракулом существования адреса.
- Любая строка → 429: значит на один анонимный маршрут в этом тесте пришлось больше
  четырёх вызовов. Правь список случаев, а не лимиты в задаче 18.
- `POST /devices ... ` строки падают на компиляции из-за `LockedReason`: см. комментарий
  к `block` — форма параметра одна на весь пакет.

- [ ] **Step 2: Написать тест живой сверки с контрактом**

`tests/integration/contract_test.go` читает `api-spec/openapi.yaml` и сверяет с ним
настоящие ответы настоящего роутера. Это и есть обещание задачи 16 («проверка этого — не
глаз, а тест»).

```go
//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/httpx"
)

// node — подмножество JSON Schema, которое действительно встречается в нашем контракте:
// type (скаляр или список), required, properties, items, enum, minimum, pattern,
// additionalProperties, $ref, allOf. Формат (date-time, uuid, email) здесь не
// проверяется сознательно: `format` — аннотация, а настоящие проверки дат и UUID делают
// time.Time и uuid при маршализации (задачи 15 и 17). maxLength/minLength тоже не
// проверяются: они относятся к телам ЗАПРОСОВ, а этот тест читает ответы.
type node struct {
	Ref     string `yaml:"$ref"`
	AllOf   []node `yaml:"allOf"`
	Type     any             `yaml:"type"`
	// Значения в properties — всегда схемы (объекты), поэтому map[string]node, а не
	// map[string]any: раскодировка узлов происходит здесь, а не на уровне any.
	Required   []string        `yaml:"required"`
	Properties map[string]node `yaml:"properties"`
	Items      *node           `yaml:"items"`
	Enum       []any           `yaml:"enum"`
	Minimum    *float64        `yaml:"minimum"`
	Pattern    string          `yaml:"pattern"`
	// additionalProperties бывает и булевым, и схемой; здесь нужна только булева
	// форма («чужие поля запрещены»), а схемная форма в контракте не встречается.
	AdditionalProperties any `yaml:"additionalProperties"`
}

// response — описание кода ответа: либо $ref на components/responses, либо inline
// description+content. Ключ content — media type, внутри него схема.
type response struct {
	Ref         string `yaml:"$ref"`
	Description string `yaml:"description"`
	Content     map[string]struct {
		Schema node `yaml:"schema"`
	} `yaml:"content"`
}

// jsonSchema — схема application/json этого ответа. has=false означает «ответ без тела»
// (204), а не «контракт сломан»: путать эти два случая — значит валить тест на
// правильном коде.
func (r response) jsonSchema() (node, bool) {
	c, ok := r.Content["application/json"]
	if !ok {
		return node{}, false
	}
	return c.Schema, true
}

// operation — один метод одного пути; ключи YAML здесь строчные (post, get).
type operation struct {
	Responses map[string]response `yaml:"responses"`
}

type spec struct {
	Paths      map[string]map[string]operation `yaml:"paths"`
	Components struct {
		Schemas   map[string]node     `yaml:"schemas"`
		Responses map[string]response `yaml:"responses"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) *spec {
	t.Helper()
	// Тест живёт в tests/integration, контракт — в api-spec: два уровня вверх.
	raw, err := os.ReadFile("../../api-spec/openapi.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse contract: %v", err)
	}
	return &s
}

func (s *spec) resolve(ref string) (node, bool) {
	const p = "#/components/schemas/"
	if strings.HasPrefix(ref, p) {
		n, ok := s.Components.Schemas[strings.TrimPrefix(ref, p)]
		return n, ok
	}
	return node{}, false
}

// responseFor — описание кода ответа из контракта. $ref на components/responses
// разворачивается здесь же: иначе общая ошибка «InvalidRequest» была бы невидима для
// сверки, а именно таких в контракте большинство.
func (s *spec) responseFor(path, method string, status int) (response, bool) {
	op, ok := s.Paths[path][strings.ToLower(method)]
	if !ok {
		return response{}, false
	}
	resp, ok := op.Responses[strconv.Itoa(status)]
	if !ok {
		return response{}, false
	}
	if resp.Ref == "" {
		return resp, true
	}
	const r = "#/components/responses/"
	if !strings.HasPrefix(resp.Ref, r) {
		return response{}, false
	}
	target, ok := s.Components.Responses[strings.TrimPrefix(resp.Ref, r)]
	return target, ok
}

// validate проверяет значение по подмножеству схемы и возвращает список расхождений
// (пусто = соответствует). path — только для сообщения, чтобы провал показывал поле, а
// не «ответ не совпал».
func validate(n node, v any, s *spec, path string) []string {
	var out []string
	if len(n.Ref) > 0 {
		target, ok := s.resolve(n.Ref)
		if !ok {
			return []string{path + ": dangling $ref " + n.Ref}
		}
		return validate(target, v, s, path)
	}
	// allOf у нас используется ровно в одном виде: Error + уточнение enum для кода.
	// Каждая ветка проверяется по всему значению, поэтому порядок веток не важен.
	for _, sub := range n.AllOf {
		out = append(out, validate(sub, v, s, path)...)
	}

	types := []string{}
	switch t := n.Type.(type) {
	case string:
		types = []string{t}
	case []any:
		for _, x := range t {
			if str, ok := x.(string); ok {
				types = append(types, str)
			}
		}
	}
	if len(types) > 0 && !typeMatches(types, v) {
		return append(out, fmt.Sprintf("%s: value %T is not one of %v", path, v, types))
	}

	if len(n.Enum) > 0 {
		found := false
		for _, e := range n.Enum {
			if fmt.Sprint(e) == fmt.Sprint(v) {
				found = true
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: %v not in enum %v", path, v, n.Enum))
		}
	}

	switch val := v.(type) {
	case map[string]any:
		for _, req := range n.Required {
			if _, ok := val[req]; !ok {
				out = append(out, fmt.Sprintf("%s: missing required %q", path, req))
			}
		}
		for k, sub := range n.Properties {
			if x, ok := val[k]; ok {
				out = append(out, validate(sub, x, s, path+"."+k)...)
			}
		}
		if b, ok := n.AdditionalProperties.(bool); ok && !b {
			for k := range val {
				if _, declared := n.Properties[k]; !declared {
					out = append(out, fmt.Sprintf("%s: unexpected property %q", path, k))
				}
			}
		}
	case []any:
		if n.Items != nil {
			for i, x := range val {
				out = append(out, validate(*n.Items, x, s, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	case float64:
		if n.Minimum != nil && val < *n.Minimum {
			out = append(out, fmt.Sprintf("%s: %v < minimum %v", path, val, *n.Minimum))
		}
	case string:
		if n.Pattern != "" {
			re, err := regexp.Compile(n.Pattern)
			if err != nil {
				out = append(out, path+": bad pattern in contract: "+err.Error())
			} else if !re.MatchString(val) {
				out = append(out, fmt.Sprintf("%s: %q does not match %s", path, val, n.Pattern))
			}
		}
	}
	return out
}

func typeMatches(types []string, v any) bool {
	for _, want := range types {
		switch want {
		case "object":
			if _, ok := v.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := v.([]any); ok {
				return true
			}
		case "string":
			if _, ok := v.(string); ok {
				return true
			}
		case "integer":
			if f, ok := v.(float64); ok && f == float64(int64(f)) {
				return true
			}
		case "number":
			if _, ok := v.(float64); ok {
				return true
			}
		case "boolean":
			if _, ok := v.(bool); ok {
				return true
			}
		case "null":
			if v == nil {
				return true
			}
		}
	}
	return false
}

// liveCase — маршрут, до которого матрица умеет достучаться, и способ это сделать.
type liveCase struct {
	path, method string
	status       int
	run          func(t *testing.T, e *env) *http.Response
}

func TestLiveResponsesMatchContract(t *testing.T) {
	s := loadSpec(t)
	e := newEnv(t)

	cases := []liveCase{
		{"/api/v1/auth/register", http.MethodPost, 201, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": "c-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": testPassword}, nil)
			return r
		}},
		{"/api/v1/auth/register", http.MethodPost, 400, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": "no-at-sign", "password": testPassword}, nil)
			return r
		}},
		{"/api/v1/auth/register", http.MethodPost, 409, func(t *testing.T, e *env) *http.Response {
			// Два вызова на один bucket: с двумя выше это четыре из пяти разрешённых,
			// и пятый случай на register в этом тесте уже не влезет.
			mail := "c-" + uuid.NewString()[:8] + "@novavpn.test"
			raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": mail, "password": testPassword}, nil)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": mail, "password": testPassword}, nil)
			return r
		}},
		{"/api/v1/auth/login", http.MethodPost, 200, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return r
		}},
		{"/api/v1/auth/login", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": "wrong-password-123"}, nil)
			return r
		}},
		{"/api/v1/auth/login", http.MethodPost, 403, func(t *testing.T, e *env) *http.Response {
			a := e.block(t, e.mint(t))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return r
		}},
		{"/api/v1/auth/refresh", http.MethodPost, 200, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			return r
		}},
		{"/api/v1/auth/refresh", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": strings.Repeat("z", 48)}, nil)
			return r
		}},
		{"/api/v1/auth/refresh", http.MethodPost, 403, func(t *testing.T, e *env) *http.Response {
			a := e.block(t, e.mint(t))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			return r
		}},
		{"/api/v1/auth/logout", http.MethodPost, 204, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": a.refresh}, nil)
			return r
		}},
		{"/api/v1/auth/logout", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": strings.Repeat("q", 48)}, nil)
			return r
		}},
		{"/api/v1/me", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(e.mint(t).access))
			return r
		}},
		{"/api/v1/me", http.MethodGet, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, nil)
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 201, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(21), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 400, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(22), "platform": "linux", "name": "c"},
				authHdr(a.access))
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(23), "platform": "linux", "name": "c"},
				idem())
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 403, func(t *testing.T, e *env) *http.Response {
			a := e.lapse(t, e.mint(t))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(24), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 409, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(25), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(25), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			return r
		}},
		{"/api/v1/devices", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(e.mint(t).access))
			return r
		}},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path+" -> "+strconv.Itoa(c.status), func(t *testing.T) {
			doc, ok := s.responseFor(c.path, c.method, c.status)
			if !ok {
				t.Fatalf("contract documents neither %s %s nor its %d response",
					c.method, c.path, c.status)
			}
			schema, hasSchema := doc.jsonSchema()
			resp := c.run(t, e)
			if resp.StatusCode != c.status {
				t.Fatalf("live status = %d, case expects %d (%s)",
					resp.StatusCode, c.status, lastBody(t, e))
			}

			// Сквозные требования, которые контракт описывает, а код обязан держать.
			if id := resp.Header.Get("X-Request-Id"); !isHex16(id) {
				t.Errorf("X-Request-Id = %q, must be 16 hex chars on every response", id)
			}

			data := lastBody(t, e)
			if c.status == http.StatusNoContent {
				if hasSchema {
					t.Errorf("contract gives %d a schema, but 204 has no body", c.status)
				}
				if len(bytes.TrimSpace(data)) != 0 {
					t.Errorf("204 must have no body, got %s", data)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "" {
					t.Errorf("204 must not declare Content-Type, got %q", ct)
				}
				return
			}
			if !hasSchema {
				t.Fatalf("contract declares no application/json schema for %d", c.status)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			var v any
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatalf("body is not JSON: %v (%s)", err, data)
			}
			where := fmt.Sprintf("%s %s %d", c.method, c.path, c.status)
			if problems := validate(schema, v, s, where); len(problems) > 0 {
				t.Errorf("response does not match contract:\n  %s\n  body: %s",
					strings.Join(problems, "\n  "), data)
			}
			if c.status >= 400 {
				checkErrorCodeKnown(t, v)
			}
		})
	}
}

// checkErrorCodeKnown: любой код, который живой сервер кладёт в конверт, обязан быть
// константой httpx, а значит — и значением из перечня контракта (равенство констант и
// перечня закрепляет TestContractCodesAreDeclared из задачи 16). Иначе клиент получает
// значение, которого «не существует».
func checkErrorCodeKnown(t *testing.T, v any) {
	t.Helper()
	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("error body must be an object, got %T (%v)", v, v)
	}
	errNode, ok := obj["error"].(map[string]any)
	if !ok {
		t.Fatalf(`error body must have an "error" object: %v`, obj)
	}
	for _, k := range []string{"code", "message", "request_id"} {
		if _, ok := errNode[k]; !ok {
			t.Errorf("envelope is missing %q: %v", k, errNode)
		}
	}
	code, _ := errNode["code"].(string)
	for _, known := range []httpx.ErrorCode{
		httpx.ErrInvalidRequest, httpx.ErrUnauthenticated, httpx.ErrAccountLocked,
		httpx.ErrForbidden, httpx.ErrNotFound, httpx.ErrMethodNotAllowed,
		httpx.ErrConflict, httpx.ErrDeviceLimitReached, httpx.ErrDuplicateDevice,
		httpx.ErrIdempotencyKeyRequired, httpx.ErrIdempotencyConflict,
		httpx.ErrIdempotencyInProgress, httpx.ErrRateLimited, httpx.ErrInternal,
		httpx.ErrInvalidCredentials, httpx.ErrRefreshTokenInvalid, httpx.ErrEmailTaken,
	} {
		if string(known) == code {
			return
		}
	}
	t.Errorf("code %q is not a known httpx error code", code)
}

func lastBody(t *testing.T, e *env) []byte {
	t.Helper()
	if len(e.ev.calls) == 0 {
		t.Fatal("no requests captured")
	}
	return e.ev.calls[len(e.ev.calls)-1].body
}
```

Run: `make integration` (можно сузить: `-run TestLiveResponsesMatchContract`)
Expected: PASS. Что имеет право упасть и что это значит:

- «contract documents neither … nor its 403 response» на refresh — значит задаче 16 не
  хватило строки `"403"` у `/api/v1/auth/refresh`, хотя код (задача 17) и матрица его
  отдают. Это пробел контракта, и правится контракт.
- Расхождение на `plan`/`limit` (истёкшая подписка) — ровно та пара, из-за которой
  контракт в задаче 16 получил `type: ["object","null"]` и `minimum: 0`.
- Непустой `Content-Type` у 204 — виноват `WriteError`/`WriteJSON` (они обязаны не
  объявлять тип у ответа без тела), а не контракт.
- Пустой `X-Request-Id` — `NewRequestID` не в начале цепочки (задача 18).
- «contract declares no application/json schema for 4xx» — в контракте у этого кода
  только description: общий ответ не развёрнут, либо развёрнут как `text/plain`.

- [ ] **Step 3: Закрыть расхождения, которые нашёл тест**

Правило этого шага: **подгонять ожидаемое значение под фактический ответ запрещено.**
Единственные допустимые правки — код (если поведение неверно) или контракт со
спецификацией (если поведение верно, но обещание было неточным), и тогда:

1. правка в `api-spec/openapi.yaml`;
2. та же правка в `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md`
   (§5.2, §7.4 или §13 — по месту);
3. строка в этом плане в разделе «Что план нашёл в спецификации».

Коммит обязан содержать все три.

- [ ] **Step 4: `docs/testing-status.md` — чем подтверждено и что не проверялось**

Файл нужен потому, что ТЗ §19.10 запрещает объявлять механизмы проверенными без
прогонов, а спецификация §9.6 предписывает непроверенное носить в этом файле со
статусом `not-run`. Таблица ниже — не оценка, а запись того, что реально
происходило в этом цикле; пустая строка в `not-run` честнее красивого «готово».

```markdown
# Статус проверок NovaVPN

Правило чтения: механизм называется проверенным только если его строка стоит в таблице
«проверено» с командой прогона. Всё остальное — «not-run», и полагаться на это нельзя.
Файл обновляется вместе с кодом, который меняет покрытие: когда механизм появляется в
коде раньше, чем в прогоне, он приходит сюда строкой в «not-run», а не молчанием.

## Проверено

| что | чем подтверждено | как повторить |
| --- | --- | --- |
| Конфигурация: отказ от insecure TLS вне dev, требование JWT-секрета ≥ 32 байт | `internal/config/config_test.go` | `make unit` |
| Схема: применение, откат до нуля, повторное применение | `tests/integration/migrations_test.go` | `make up-dev && make integration` |
| argon2id: формат PHC, порог слабости, проверка пароля | `internal/auth/password_test.go` | `make unit` |
| Refresh: ротация, отзыв семьи при переиспользовании, заблокированный аккаунт не продлевает | `tests/integration/refresh_test.go`, `auth_flow_test.go` | `make integration` |
| Denylist: отзыв access по jti, TTL по expires | `internal/auth/denylist_test.go` | `make unit` |
| Жёсткий лимит устройств, в том числе при параллельных запросах | `tests/integration/devices_test.go` (advisory lock, 10 горутин на лимит 3) | `make integration` |
| Идемпотентность: повтор, конфликт тела, in_progress | `tests/integration/idempotency_test.go` | `make integration` |
| Права из плана, неизвестный selector — ошибка, а не «выбрать любой» | `tests/integration/entitlements_test.go` | `make integration` |
| WireGuard-ключ: каноничность base64, 32 байта, spare-биты | `internal/devices/key_test.go` | `make unit` |
| Единый конверт ошибки, request id, 404/405 с Allow | `internal/httpx/mux_test.go`, `tests/integration/router_test.go` | `make unit && make integration` |
| Журнал: одна строка на запрос, маршрут по шаблону, без токенов и писем | `internal/httpx/mux_test.go`, `TestRouterJournalHasNoSecrets` | `make unit && make integration` |
| Матрица «роль × маршрут» (аноним, участник, истёкшая подписка, блокировка) | `tests/integration/matrix_test.go` | `make integration` |
| Ответы не содержат токенов, паролей, писем и ключей | `checkEvidence` в `tests/integration/matrix_test.go` | `make integration` |
| Живые ответы соответствуют `api-spec/openapi.yaml` | `tests/integration/contract_test.go` | `make integration` |
| Лимитер: token bucket, 429 с Retry-After, fail-open при отказе Redis | `internal/httpx/ratelimit_test.go` (fail-open — unit на fake-клиенте) | `make unit` |
| Узел: WireGuard в привилегированном контейнере, применение набора пиеров без потери handshake | спайки S1 и S3, `docs/adr/0004-wireguard-peer-apply.md` | см. `docs/spikes/2026-10-20-s1-s3-wireguard-netlink.md` |

## not-run (не проверено — и не заявляется как проверенное)

| что | почему не проверялось | где появится |
| --- | --- | --- |
| Работа с реальным VPS (78.17.192.147): публикация узла, MTU, пропускная способность, поведение при потере peering | доступа к узлу нет; метрики без замера по спецификации §13.4 пишутся `null`, а не нулями | цикл A-3, повторный прогон S1/S3 на реальном железе |
| Остальные маршруты §5.1: выдача и отзыв профилей, `DELETE /devices/{id}`, `keys/rotate`, `/servers`, `/api/v1/admin/*`, контракт узла `/internal/v1` | в объём A-1 не входят: описывать их не на чем (профилей, узлов и админ-роли ещё нет), а заглушка запрещена ТЗ §19.3 | цикл A-2 (кроме admin — там же, но после админ-модуля) |
| node-agent как демон, Ansible-раскатка, systemd-юнит, TLS между узлом и API-шлюзом | сборка узла — отдельная задача | цикл A-3 |
| Клиенты (Windows первым), отключение IPv6, split tunnel, kill switch на реальной ОС | клиентских приложений в A-1 нет; на Windows-хосте GUI из агента не запускается | цикл E, спайк S4 (ADR-008) |
| DNS: локальный recursor unbound, отсутствие утечек DNS, наблюдение по SNI | спайк S2 не запускался | цикл A-3, спайк S2 (ADR-005) |
| Восстановление denylist после отказа Redis (окно, в котором отозванный access живёт до истечения TTL) | сценарий не проигрывался; в A-1 проверен только fail-open на уровне unit-теста | спайк S5 (ADR-003) |
| Чистота журнала при отказе Redis: предупреждение лимитера кладёт ключ бакета, в котором есть IP клиента | ветка отказа Redis в интеграционном прогоне не играется, а unit-тест журнала не проверяет | спайк S5 (ADR-003) |
| Платежи, продление подписки после оплаты, возврат средств | провайдера нет, sandbox не подключался | цикл B |
| Подтверждение email, восстановление доступа | письмо не отправлялось ни разу | цикл D |
| Панель администратора, роли, аудит-лог в UI | не входит в A-1 | цикл C/D |
| Нагрузочные характеристики: rps, латентность под нагрузкой, размер пула при N узлов | замеры не делались; заявлять числа нечем | цикл C (метрики) + отдельный замер |
| Бэкапы и восстановление PostgreSQL/Redis, раскатка миграций на продакшен-базе | такого прогона не было; локально проверены только up/down в контейнере | цикл C (runbook) |
| Сканирование зависимостей и SBOM в CI, подпись образов | CI нет до A-3 | цикл A-3 |
| TLS-терминация и передача реального IP балансировщиком (X-Forwarded-For намеренно не доверяется — задача 18) | конфигурация фронта не существует | цикл A-3 |
| Полное совпадение контракта со всеми состояниями кода: сверяются маршруты, до которых матрица дотягивается; `/debug/health`, 429 и 500 здесь не проверяются | живой 500 нельзя вызвать, не подменив код, а 429 проверяется в задаче 18 | цикл A-2 (маршруты узла) + фоллаут-тесты |
```

- [ ] **Step 5: Прогнать всё и коммитить**

Run: `make unit && make vet && make api-lint && make integration`
Expected: PASS по всем четырём. `make integration` на этом шаге — полный прогон: матрица,
контракт и тесты задач 9–18 в их числе.

Run: `git grep -n -P "[\x{4e00}-\x{9fff}\x{3000}-\x{303f}\x{ac00}-\x{d7af}]" -- docs tests services internal api-spec migrations`
Expected: пусто. Проверка нужна потому, что в этом плане кириллица соседствует с
символами, которые в русский текст не приходят никогда: любая иероглифная строка —
опечатка автора, а не содержание. Найденное чинится в этом же коммите, а не «потом».

```bash
git add tests/integration/matrix_test.go tests/integration/contract_test.go docs/testing-status.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "test(a1): матрица роль×маршрут, живая сверка с контрактом и статус проверок"
```

- [ ] **Step 6: Итоговая сверка объёма A-1**

Чеклист против спецификации и ТЗ — каждый пункт либо закрыт задачей, либо открыто
записан в `docs/testing-status.md` как не этот цикл. Источник в первой колонке назван
явно («спецификация §…» или «ТЗ §…»): у них сквозная нумерация разная, и ссылка
«§10» без имени документа читается двояко.

| Обещание | чем закрыт |
| --- | --- |
| спецификация §5.1 contract-first (OpenAPI) | задача 16 + живая сверка задачи 19 |
| спецификация §5.2 (ТЗ §10) единый конверт, request id, права, `Idempotency-Key`, лимиты register/login | задачи 7, 9, 11, 16, 18, 19 |
| спецификация §6 (ТЗ §11) хранение минимума (ip — анти-злоупотребление, email не в журнале) | задачи 2–3, 12, проверка журнала в 18 и 19 |
| спецификация §7.4 (ТЗ §5) жёсткий лимит устройств | задачи 4, 6, 15, 19 (включая гонку) |
| ТЗ §5 (спецификация §3, пункт 1) приватные ключи серверов не уходят клиентам; ключи пользователей — только публичные | задачи 13–15 (в A-1 нет ни выдачи профилей, ни приватных ключей в ответе), проверка `private_key` в `checkEvidence` |
| ТЗ §15 (спецификация §11) тулчейн в контейнерах, pinned-образы | задача 1 |
| спецификация §13.4 неизмеренное — `null` | задача 4 (seed), задача 17 (`/me`), контракт (`type: ["integer","null"]`) |
| спецификация §13.9 (добавлен задачей 17) окно отзыва access при недоступном Redis | задача 11 (fail-open на unit-уровне); полное восстановление — строка `not-run` в статусе |
| спецификация §13.10 (добавлен задачей 17) тайминг-оракул входа | задача 17 (`penalize`: одно тело на обе ветки, задержка от 250 мс, фиктивная argon2-проверка сознательно отсутствует) |
| спецификация §13.11 (добавлен задачей 17) окно блокировки для уже выданного access | задача 17 (блокировка останавливает выдачу и ротацию), строка матрицы задачи 19 |
| ТЗ §19.10 не объявлять механизмы проверенными без прогонов | `docs/testing-status.md` целиком (спецификация §9.6), шаг 6 |

Ничего из строк выше не «считается готовым» без PASS в шаге 5: ТЗ §19.10 об этом.
