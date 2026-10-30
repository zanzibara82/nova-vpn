GO_IMAGE ?= golang:1.25-alpine
DB_IMAGE ?= postgres:17
REDIS_IMAGE ?= redis:7
API_IMAGE ?= redocly/cli:1.34.22

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

.PHONY: unit vet integration mod sqlc-generate migrate-up migrate-down run-dev up-dev down-dev api-lint
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

api-lint:
	docker run --rm -v "$(CURDIR)/api-spec:/spec" $(API_IMAGE) lint /spec/openapi.yaml

AGENT_VERSION ?= dev

.PHONY: api-image node-image node-help
api-image:
	MSYS_NO_PATHCONV=1 docker build -t novavpn-api:dev -f Dockerfile.api .

node-image:
	MSYS_NO_PATHCONV=1 docker build --build-arg AGENT_VERSION=$(AGENT_VERSION) -t novavpn-node-agent:dev -f Dockerfile.node-agent .

node-help:
	MSYS_NO_PATHCONV=1 docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW novavpn-node-agent:dev --help

# Стенд E2E. Оркестратор — одноразовый доверенный контейнер alpine:3.20:
# исходники только для чтения, Docker socket только ему, защищённый том
# novavpn-e2e-control в /state. Службы стенда socket не получают. run-make.sh
# передаёт CURDIR путём хоста Docker, поэтому том исходников строится от него.
E2E_CONTROL_VOL  := novavpn-e2e-control
E2E_RUNNER       := novavpn-e2e-runner
E2E_RUNNER_DOWN  := novavpn-e2e-runner-down
E2E_ORCH_IMAGE   := alpine:3.20
E2E_ORCH_PACKAGES := make bash python3 curl docker-cli docker-cli-compose docker-cli-buildx
E2E_ORCH_FLAGS   := --label novavpn.e2e.project=novavpn-e2e \
	-v "$(CURDIR):/work:ro" \
	-v "$(E2E_CONTROL_VOL):/state" \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-w /work

.PHONY: e2e e2e-down
e2e:
	@if MSYS_NO_PATHCONV=1 docker ps -a \
		--filter "label=com.docker.compose.project=novavpn-e2e" \
		--format '{{.Names}}' | grep -q .; then \
		echo "проект novavpn-e2e занят; сначала выполните make e2e-down" >&2; exit 1; \
	fi
	@for net in novavpn-e2e_harness novavpn-e2e_uplink; do \
		if MSYS_NO_PATHCONV=1 docker network inspect "$$net" >/dev/null 2>&1; then \
			echo "сеть $$net уже существует; сначала выполните make e2e-down" >&2; exit 1; \
		fi; \
	done
	@if MSYS_NO_PATHCONV=1 docker container inspect $(E2E_RUNNER) >/dev/null 2>&1; then \
		echo "контейнер $(E2E_RUNNER) уже существует; сначала выполните make e2e-down" >&2; exit 1; \
	fi
	@if MSYS_NO_PATHCONV=1 docker volume inspect $(E2E_CONTROL_VOL) >/dev/null 2>&1; then \
		label=$$(MSYS_NO_PATHCONV=1 docker volume inspect --format \
			'{{ index .Labels "novavpn.e2e.project" }}' $(E2E_CONTROL_VOL) 2>/dev/null || true); \
		if [ "$$label" != "novavpn-e2e" ]; then \
			echo "том $(E2E_CONTROL_VOL) существует без метки владельца" >&2; exit 1; \
		fi; \
	else \
		MSYS_NO_PATHCONV=1 docker volume create \
			--label novavpn.e2e.project=novavpn-e2e $(E2E_CONTROL_VOL) >/dev/null; \
	fi
	@MSYS_NO_PATHCONV=1 docker run --rm --name $(E2E_RUNNER) $(E2E_ORCH_FLAGS) \
		-e E2E_ORCHESTRATOR=1 $(E2E_ORCH_IMAGE) sh -ec \
		'apk add --no-cache $(E2E_ORCH_PACKAGES) >/dev/null && exec bash scripts/e2e.sh all'; \
	rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		MSYS_NO_PATHCONV=1 docker volume rm $(E2E_CONTROL_VOL) >/dev/null || rc=1; \
	fi; \
	exit $$rc

# Снимает только собственный проект, runner и control-том при подтверждённых
# метках. Если защищённого тома нет, снимать нечего; чужой runner не трогается.
e2e-down:
	@if MSYS_NO_PATHCONV=1 docker container inspect $(E2E_RUNNER) >/dev/null 2>&1; then \
		label=$$(MSYS_NO_PATHCONV=1 docker inspect --format \
			'{{ index .Config.Labels "novavpn.e2e.project" }}' $(E2E_RUNNER)); \
		if [ "$$label" = "novavpn-e2e" ]; then \
			MSYS_NO_PATHCONV=1 docker rm -f $(E2E_RUNNER) >/dev/null; \
		else \
			echo "чужой контейнер $(E2E_RUNNER) без метки владельца" >&2; exit 1; \
		fi; \
	fi
	@if ! MSYS_NO_PATHCONV=1 docker volume inspect $(E2E_CONTROL_VOL) >/dev/null 2>&1; then \
		echo "том $(E2E_CONTROL_VOL) отсутствует; снимать нечего" >&2; exit 0; \
	fi
	@label=$$(MSYS_NO_PATHCONV=1 docker volume inspect --format \
		'{{ index .Labels "novavpn.e2e.project" }}' $(E2E_CONTROL_VOL) 2>/dev/null || true); \
	if [ "$$label" != "novavpn-e2e" ]; then \
		echo "том $(E2E_CONTROL_VOL) существует без метки владельца" >&2; exit 1; \
	fi
	@MSYS_NO_PATHCONV=1 docker run --rm --name $(E2E_RUNNER_DOWN) $(E2E_ORCH_FLAGS) \
		$(E2E_ORCH_IMAGE) sh -ec \
		'apk add --no-cache $(E2E_ORCH_PACKAGES) >/dev/null && exec bash scripts/e2e.sh down'; \
	rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		MSYS_NO_PATHCONV=1 docker volume rm $(E2E_CONTROL_VOL) >/dev/null || rc=1; \
	fi; \
	exit $$rc
