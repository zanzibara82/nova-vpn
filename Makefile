GO_IMAGE ?= golang:1.25-alpine
DB_IMAGE ?= postgres:17
REDIS_IMAGE ?= redis:7
COMPOSE   := docker compose -f infrastructure/docker/docker-compose.dev.yml
ENV_FILE  := infrastructure/docker/.env.dev

# Интеграционные тесты и миграции бегут внутри контейнера, а localhost внутри
# контейнера — это сам контейнер, а не хост. Поэтому адреса для них задаются
# отдельно: .env.dev описывает запуск бинарника с хоста. Флаг -e важнее
# --env-file, так что значения из файла не перебивают эти.
# host-gateway нужен Linux-движку; Docker Desktop резолвит имя и без него.
DB_URL_INTEG     := postgres://nova:nova@host.docker.internal:5432/novavpn?sslmode=disable
REDIS_ADDR_INTEG := host.docker.internal:6379

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

.PHONY: unit vet integration mod tidy sqlc-generate migrate-up migrate-down run-dev up-dev down-dev
unit:
	$(docker-go) test -count=1 ./...

# Без тегов: интеграционные тесты компилируются и проверяются целью integration,
# а здесь важна обычная сборка пакетов.
vet:
	$(docker-go) vet ./...

mod:
	$(docker-go) mod tidy

up-dev:
	$(COMPOSE) up -d postgres redis
	$(COMPOSE) exec -T postgres pg_isready -U nova -d novavpn -q

down-dev:
	$(COMPOSE) down -v

integration:
	$(docker-go-int) test -count=1 -tags=integration ./tests/integration/...

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
