# NovaVPN — цикл A-3: узел, стенд E2E, развёртывание. План имплементации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Работающий `novavpn-node-agent`, который сам получает desired set, приводит
WireGuard-интерфейс в соответствие дельтой (ADR-004), отчитывается о наблюдениях и
переживает недоступность API; стенд E2E, где трафик действительно идёт через узел и
DNS-запросы не утекают мимо туннеля; Ansible-роли, TLS-фронт и CI, которыми этот узел
можно поставить на реальную машину.

**Architecture:** Отдельный процесс `novavpn-node-agent` (не часть API), три слоя:
`wg` (netlink и `wgctrl`, чистая дельта), `api` (HTTPS-клиент узла), `runtime`
(цикл опроса 25 с, применение, отчёты, состояние). Состояние и приватный ключ — файлы
`0600` в каталоге состояния. Сеть узла делится на две части: агент владеет только
`wg0` и пиерами, а NAT, `ip_forward`, unbound и systemd-обвязка — Ansible-роль.
Стенд E2E — compose с настоящим туннелем, клиентом и сервисом-эхом за узлом.

**Tech Stack:** Go `CGO_ENABLED=0`; `golang.zx2c4.com/wireguard/wgctrl`
`v0.0.0-20241231184526-a9ab2273dd10` (зафиксирована ADR-004);
`github.com/vishvananda/netlink` для rtnetlink (создание устройства, адрес); Docker
Compose для стенда; Ansible для раскатки; Caddy для TLS-фронта; GitHub Actions для CI.

**Spec:** [docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md](../specs/2026-10-20-novavpn-cycle-a-access-core-design.md)
— §1.3 (критерии 3, 4, 6, 7, 8, 11), §3 (границы доверия), §4.1–4.4 (контракт узла,
применение, отказы, TLS), §7.3–7.5, §8 (DNS и IPv6), §9.3 (E2E), §9.4 (безопасность),
§10 (S2), §11 (развёртывание), §13 (ограничения).

---

## Разбивка цикла A на планы

| План | Граница | Готовый, тестируемый результат |
|---|---|---|
| A-1 (**закрыт**, 33d19d0) | Схема + сессии + устройства | `POST /auth/*`, `GET /me`, `POST/GET /devices`, миграции `up→down→up`, лимит устройств |
| A-2 (**закрыт**, 886b39e) | Выдача доступа + контракт с узлом | Профили с аллокацией адреса, `DELETE /devices/{id}`, `keys/rotate`, `/servers`, desired set, `/internal/v1/*` против fake-узла, admin с аудитом, телеметрия |
| **A-3 (этот)** | Узел, стенд, развёртывание | `novavpn-node-agent` с netlink diff-apply, compose-стенд с настоящим туннелем, S2 (unbound), Ansible-роли, systemd, TLS-фронт, CI, прогон на VPS (при доступе) |

Критерии приёмки §1.3, которые закрывает A-3: **3** (туннель фактически передаёт трафик,
egress = адрес узла), **4** (отзыв снимает пиера ≤ 30 с, трафик останавливается),
**6** (ротация с overlap не рвёт поток), **7** (DNS через recursor узла, off-tunnel резолв
не наблюдается), **8** (IPv6-путь отсутствует), **11** (E2E и CI с явным `not-run` там,
где прогон не выполнялся).

Что A-3 **не** делает: не выпускает Windows-клиент (цикл E), не рисует панель (C), не
занимается платежами (D), не замеряет пропускную способность на нагрузке (F). Клиент в
стенде — контейнер с `wireguard-tools`, а не приложение; это проверка механики туннеля,
а не пользовательского опыта.

---

## Global Constraints

Значения дословно из спецификации и ТЗ; каждая задача неявно включает этот раздел.

- Все сборки и тесты — только через `make` → `docker run` (на хосте нет Go). Прямой
  `go test` на хосте проверкой не является.
- Узловой контракт — только HTTPS в проде. Проверка сертификата обязательна; флаг
  `NOVAVPN_NODE_ALLOW_INSECURE_API` существует только для dev-стенда и обязан отказывать
  при `NOVAVPN_NODE_ENV != dev` (ТЗ §19.8, спецификация §4.4).
- Приватный ключ узла генерируется на узле и никогда его не покидает; в API уходит только
  публичный (спецификация §3, правило 1). Права файлов — `0600`, каталог — `0700`.
- `Config.ReplacePeers` — всегда `false`; отзыв — `PeerConfig{Remove: true}`; счётчики
  снимаются **до** применения (ADR-004). Неизменённый пиер не попадает в netlink.
- Desired set содержит только `state` равный `active` или `rotating_old_key`; просроченный и
  отозванный отсутствует всегда (§4.1).
- Интервал опроса узла — **25 с** с jitter ±10 % (§4.3 спецификации): ожидание до 27,5 с
  оставляет бюджет 2,5 с на доставку, обработку и применение, включая остаток текущего шага
  и планирование. Критерий «отзыв ≤ 30 с» требует доступного API и соблюдения бюджета;
  до сквозного замера от фиксации отзыва до удаления пиера в runtime/E2E SLA не подтверждён.
- Неизмеренные величины — `null`, никогда `0` (ADR-006, §13.4). `load1`/`cpu_pct` при
  недоступном `/proc` — `null`.
- Содержимое трафика и DNS-запросы не пишутся ни в одну базу и ни в один журнал; unbound
  конфигурируется `log-queries: no`, и это проверяется тестом, а не декларацией (§8).
- Никакого самописного крипто: ключи — `wgtypes.GeneratePrivateKey`, TLS — стандартная
  библиотека, токены — `crypto/rand`. Строки конфигурации не попадают в shell: всё через
  типизированные вызовы netlink.
- Язык: сообщения CLI и журналов для человека — по-русски; имена полей, коды ошибок и
  ключи JSON — английские. В русском тексте ноль посторонних символов (проверка алфавита
  перед коммитом).
- Секреты — только через env-файлы, никогда в argv, Makefile или репозитории. В
  репозитории лежит `.env.example` без значений.
- На каждом `docker run` в Git Bash — инлайн `MSYS_NO_PATHCONV=1`; вывод с кириллицей — в
  файл через `PYTHONIOENCODING=utf-8`.
- Коммиты: `git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" commit …`,
  всегда новые коммиты, не `--amend`. Пуш — только по явному разрешению пользователя.
- Невыполненная проверка помечается `not-run` в `docs/testing-status.md`, а не зелёным
  (ТЗ §14, §19.12).

### Соглашение о блоках кода в этом плане

- **«Дословный исходник»** — файл обязан совпасть с блоком байт-в-байт: чистые функции,
  типы, миграции, тесты. Реализацию проверяет тест, а не глаз.
- **«Схема, не исходник»** — интерфейс, таблица соответствий, маршруты, поля. Исполнитель
  пишет реализацию по требованиям; проверяют её тесты этой же задачи.

---

## Карта файлов A-3

```
go.mod, go.sum                                          # + wgctrl, + vishvananda/netlink
api-spec/openapi.yaml                                   # DesiredSet += tunnel_address; Heartbeat += stale
internal/servers/desired.go                             # TunnelAddress(pool)
internal/servers/desired_test.go                        # адрес узла для /24 и /29
internal/telemetry/service.go                           # Heartbeat.Stale → health_status
internal/db/query/telemetry.sql                         # MarkServerHealth принимает status
internal/nodeagent/wg/diff.go                           # чистая дельта desired и live
internal/nodeagent/wg/diff_test.go
internal/nodeagent/wg/link.go                           # rtnetlink: устройство, адрес
internal/nodeagent/wg/config.go                         # Target → wgtypes.Config
internal/nodeagent/wg/config_test.go
internal/nodeagent/wg/device.go                         # обёртка wgctrl: Snapshot/Configure
internal/nodeagent/wg/applier.go                        # порядок применения и снимок до
internal/nodeagent/wg/applier_test.go
internal/nodeagent/state/state.go                       # ключ 0600 + state.json атомарно
internal/nodeagent/state/state_test.go
internal/nodeagent/api/client.go                        # HTTPS-клиент узла
internal/nodeagent/api/client_test.go                   # httptest, TLS, 304, отказы
internal/nodeagent/runtime/runner.go                    # цикл 25 с, отказы, ротация токена
internal/nodeagent/runtime/runner_test.go               # fake API + fake Applier
services/node-agent/cmd/novavpn-node-agent/main.go      # init, enroll, run, status
services/node-agent/cmd/novavpn-node-agent/main_test.go
Dockerfile.api                                          # образ control plane
Dockerfile.node-agent                                   # образ агента, non-root
infrastructure/docker/docker-compose.dev.yml            # сервис node-agent
infrastructure/docker/docker-compose.e2e.yml            # api, node1, client1, probe
infrastructure/docker/e2e/node1.Dockerfile              # alpine + wg + unbound + агент
infrastructure/docker/e2e/client1.Dockerfile            # alpine + wg-tools + bind-tools + ping + tcpdump
infrastructure/docker/e2e/probe.Dockerfile              # эхо адреса клиента + dnsmasq
infrastructure/docker/e2e/unbound.conf                  # log-queries: no, restricted CIDR
infrastructure/docker/e2e/nat.nft                       # отдельная таблица novavpn
infrastructure/docker/e2e/node-entrypoint.sh            # root-шаг, затем su-exec novavpn
infrastructure/docker/e2e/client-entrypoint.sh          # сборка wg0.conf из конфига API
infrastructure/docker/e2e/dnsmasq.conf                  # имена e2e.test на probe
tests/e2e/probe/main.go                                 # эхо адреса клиента
scripts/e2e.sh                                          # сценарии стенда, exit code
scripts/preflight.sh                                    # проверка хоста перед раскаткой
scripts/backup-verify.sh                                # восстановление дампа в пустую базу
scripts/leakcheck.sh                                    # поиск ключей и секретов
infrastructure/ansible/{ansible.cfg,site.yml,inventory.example.ini}
infrastructure/ansible/roles/novavpn_node/**            # пакеты, юнит, sysctl, nftables, откат
infrastructure/ansible/roles/unbound/**                 # конфиг без журнала запросов
docs/runbooks/{node-deploy,node-drain,revoke-a-key-now,incident}.md
infrastructure/docker/Caddyfile.example                 # TLS-фронт
.github/workflows/ci.yml                                # lint, unit, integration, security, e2e
docs/adr/0009-node-network-operations.md                # netlink для link/addr, wgctrl для пиров
docs/testing-status.md                                  # закрытые и новые not-run строки
```

### Порядок и зависимости

1 → 2 → 3 → 4 → 5 (слой `wg` целиком) → 6 (состояние) → 7 (клиент API) → 8 (цикл) →
9 (CLI) → 10 (образы) → 11–13 (стенд) → 14–15 (раскатка) → 16 (TLS и проверки) →
17 (CI) → 18 (приёмка) → 19 (VPS, при доступе).

Каждая задача заканчивается зелёным прогоном и коммитом. Задачи 11–13 требуют Docker с
модулем `wireguard` на хосте (проверено S1); если модуль не загружен, E2E честно падает и
это записывается в журнал, а не обходится.

---

### Task 1: Контракт узла — адрес в туннеле, признак `stale`, интервал 25 с

Адрес узла в туннеле вычисляется в API, но в контракт не попадал. Без него агент не может
назначить адрес и построить маршрут: `dns_servers[0]` даёт адрес без маски, а пул бывает
от /24 до /29. Второе расхождение — §4.3 обещает `stale=true` в отчёте, а поля в
`Heartbeat` нет. Третье — 30 с с jitter ±10 % дают 33 с в худшем случае и несовместимы с
критерием «отзыв ≤ 30 с».

**Files:**
- Modify: `api-spec/openapi.yaml` (схемы `DesiredSet`, `Heartbeat`)
- Modify: `internal/servers/desired.go`, `internal/servers/desired_test.go`
- Modify: `internal/telemetry/service.go`, `internal/nodeapi/handlers.go`
- Modify: `internal/db/query/telemetry.sql`; регенерация `internal/db/telemetry.sql.go` и `internal/db/querier.go`
- Modify: `tests/integration/desired_test.go`, `tests/integration/telemetry_test.go`,
  `tests/integration/contract_test.go`; при необходимости `nodeapi_test.go`, `sweeper_test.go`
  и корректные фикстуры `matrix_test.go`
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§4.1, §4.3)

**Interfaces:**
- Produces: `servers.TunnelAddress(pool netip.Prefix) string`; поле
  `servers.DesiredSet.TunnelAddress string` (JSON `tunnel_address`);
  `telemetry.Heartbeat.Stale bool` (JSON `stale`);
  `db.MarkServerHealthParams.Status db.HealthStatus`.

- [ ] **Step 1: Написать падающие unit-тесты адреса**

В `internal/servers/desired_test.go` добавить:

```go
func TestTunnelAddressUsesPoolMask(t *testing.T) {
	cases := map[string]struct{ pool, want string }{
		"10.99.7.0/24": {"10.99.7.0/24", "10.99.7.1/24"},
		"10.99.8.0/29": {"10.99.8.0/29", "10.99.8.1/29"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			pool := netip.MustParsePrefix(c.pool)
			if got := TunnelAddress(pool); got != c.want {
				t.Fatalf("TunnelAddress(%s) = %q, want %q", c.pool, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Прогнать и убедиться, что не компилируется**

Run: `make unit`
Expected: FAIL — `undefined: TunnelAddress`.

- [ ] **Step 3: Реализовать поле и функцию**

В `internal/servers/desired.go` в `DesiredSet` добавить поле после `ListenPort`:

```go
	TunnelAddress string    `json:"tunnel_address"`
```

и функцию рядом с `Compute`:

```go
// TunnelAddress — адрес узла в туннеле с маской пула. Маска нужна агенту: без неё
// нельзя ни назначить адрес на интерфейс, ни понять, какие адреса достижимы
// напрямую. dns_servers[0] содержит тот же адрес, но без префикса.
func TunnelAddress(pool netip.Prefix) string {
	return netip.PrefixFrom(connections.NodeTunnelAddress(pool), pool.Bits()).String()
}
```

В `Compute` после заполнения `ListenPort`:

```go
		TunnelAddress: TunnelAddress(srv.AddressPoolV4),
```

- [ ] **Step 4: Прогнать unit-тесты**

Run: `make unit`
Expected: PASS, включая `TestTunnelAddressUsesPoolMask`.

- [ ] **Step 5: Обновить контракт и спека**

В `api-spec/openapi.yaml` в `DesiredSet.required` добавить `tunnel_address` после
`listen_port`, в `properties` — строку:

```yaml
        tunnel_address:
          type: string
          description: "Адрес узла в туннеле с маской пула, например 10.99.7.1/24"
```

В `Heartbeat.required` добавить `stale`, в `properties`:

```yaml
        stale:
          type: boolean
          description: >
            true — последний desired set не удалось получить дольше интервала опроса;
            узел продолжает обслуживать текущих клиентов на последнем применённом наборе.
```

В спецификации §4.1 в примере ответа добавить `"tunnel_address": "10.99.7.1/24"` после
`listen_port`; в §4.3 установить интервал desired-poll 25 с с jitter ±10 %.
Ожидание до 27,5 с оставляет бюджет 2,5 с на доставку, обработку и применение,
включая остаток текущего шага и планирование. При интервале 30 с ожидание достигало бы 33 с.
Не объявлять критерий «отзыв ≤ 30 с» выполненным до runtime/E2E-замера от фиксации
отзыва до удаления пиера при доступном API: отзыв сразу после снимка desired,
максимальный jitter, контролируемые задержки ответа и применения. Здесь меняется
формулировка контракта, а не реализуются будущие задачи.

- [ ] **Step 6: Написать падающий тест `stale` в телеметрии**

В `tests/integration/telemetry_test.go` использовать существующие `newEnv`, `env.server`,
`env.node`, `raw`, `authHdr`, `nodePath` из `matrix_test.go` и `env.q.ServerHealthOf`.
Не добавлять обёртки `postNode`/`healthStatus`.

Через настоящий HTTP и БД проверить:
- `heartbeat(true)` устанавливает `stale`; следующий `observed` обновляет ненулевые
  счётчики и применённую версию, но сохраняет `stale`, нагрузку, версию агента и uptime;
  только `heartbeat(false)` возвращает `ok`, сохраняя счётчики observed.
- Устаревший `observed_at` и штатный `connections.Store.SweepStale` устанавливают `stale`;
  свежий `observed` его не снимает, `heartbeat(false)` восстанавливает `ok`.
- После `heartbeat(true)` тела без `stale`, с `null` и неверным типом дают HTTP 400
  `invalid_request`, не меняя ни одного поля health, включая `observed_at`.
  Явные `true` и `false` принимаются с HTTP 204.

Сохранить исходную проверку взаимного сохранения полей
`TestTelemetryHeartbeatPreservesObservedAndViceVersa`: heartbeat владеет нагрузкой,
версией агента, uptime и статусом, observed — счётчиками; применённая версия и время
обновляются каждым корректным отчётом. Корректные HTTP-фикстуры обязаны передавать `stale`.

- [ ] **Step 7: Прогнать и убедиться, что падает**

Run: `make integration`
Expected: FAIL — отсутствие реализации `stale`, observed снимает установленный `stale`
или heartbeat без boolean принимается и изменяет health. Новые регрессии сначала RED.

- [ ] **Step 8: Реализовать `stale`**

В `internal/telemetry/service.go` в `Heartbeat` добавить:

```go
	Stale bool `json:"stale"`
```

В `IngestHeartbeat` перед вызовом:

```go
	status := db.HealthStatusOk
	if hb.Stale {
		status = db.HealthStatusStale
	}
```

и передать `Status: status` в `db.MarkServerHealthParams`.

В `internal/nodeapi/handlers.go` декодировать heartbeat в локальный HTTP DTO с
`Stale *bool` и остальными полями отчёта. До вызова сервиса отклонять `nil` существующим
путём `invalid_report`/`invalid_request` с HTTP 400; неверный тип отклоняет декодер.
После проверки передать `*Stale` в `telemetry.Heartbeat.Stale`, сохранив его тип `bool`.
Не ослаблять обязательность boolean в OpenAPI.

В `internal/db/query/telemetry.sql` у `MarkObservedHealth` убрать присвоение `status`
из `ON CONFLICT DO UPDATE`, сохранив вставку с `ok` и обновление измеренных полей.
Восстановлением статуса владеет `heartbeat(false)`, в том числе после sweeper;
закрепить это одной короткой строкой SQL-комментария. Generated-файлы менять только sqlc.

В `internal/db/query/telemetry.sql` заменить `MarkServerHealth`:

```sql
-- name: MarkServerHealth :exec
INSERT INTO server_health (server_id, observed_at, load1, cpu_pct,
                           applied_config_version, status, agent_version, agent_uptime_sec)
VALUES ($1, $2, $3, $4, $5, sqlc.arg(status)::health_status, $6, $7)
ON CONFLICT (server_id) DO UPDATE SET
    observed_at = EXCLUDED.observed_at,
    load1 = EXCLUDED.load1,
    cpu_pct = EXCLUDED.cpu_pct,
    applied_config_version = EXCLUDED.applied_config_version,
    status = EXCLUDED.status,
    agent_version = EXCLUDED.agent_version,
    agent_uptime_sec = EXCLUDED.agent_uptime_sec;
```

Run: `make sqlc-generate`
Expected: `internal/db/telemetry.sql.go` содержит `Status db.HealthStatus` и `$6`
(сдвиг параметров) — сверить сгенерированный код глазами, потому что правки в
сгенерированном файле руками запрещены.

Тем же шагом дописать комментарий к `UpsertServerHealth` в `telemetry.sql`: запрос
существует только как наполнение состояния в интеграционных тестах, а не как путь
записи отчётов. Он единственный обнуляет `agent_version`/`agent_uptime_sec` — и это
ровно то, что случится, если следующий вызывающий примет его за обработчик observed.
Боевые пути — `MarkObservedHealth` и `MarkServerHealth`; комментарий фиксирует это
рядом с SQL, а не в голове автора.

- [ ] **Step 9: Добавить живой случай в контрактный тест**

В `tests/integration/contract_test.go` в набор `TestLiveResponsesMatchContract` добавить
проверку `GET …/desired`: тело обязано содержать `tunnel_address` с маской (проверка
`netip.ParsePrefix`), а `Heartbeat` в телеметрии — поле `stale`. Схемная проверка уже
поймает пропуск `required`; явный разбор нужен, чтобы ошибка говорила «нет адреса», а не
«не совпало с oneOf».

- [ ] **Step 10: Прогнать ворота**

Run: `make unit && make vet && make integration && make api-lint`
Expected: все команды с кодом 0.

- [ ] **Step 11: Коммит**

```bash
git add api-spec/openapi.yaml internal/servers internal/telemetry internal/db \
  tests/integration docs/superpowers/specs
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): адрес узла в туннеле, признак stale и интервал опроса 25 с"
```

---

### Task 2: Зависимость `wgctrl` и чистая дельта `desired` и `live`

Дельта — единственное место, где решается, тронуть пиера или нет. Ошибка здесь означает
либо пересоздание всех пиеров каждые 25 с (то, что запретил ADR-004), либо неснятый
отозванный ключ. Поэтому она пишется как чистая функция и проверяется без netlink.

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/nodeagent/wg/diff.go`, `internal/nodeagent/wg/diff_test.go`
- Modify: `docs/adr/0004-wireguard-peer-apply.md` (сравнение без endpoint)

**Interfaces:**
- Produces: `wg.PeerState`, `wg.LiveState`, `wg.TargetPeer`, `wg.PeerKind`, `wg.StateActive`,
  `wg.StateRotatingOldKey`, `wg.OpKind`, `wg.Op`,
  `wg.Diff(live LiveState, target []TargetPeer) ([]Op, error)`, `wg.ErrDuplicatePeer`,
  `wg.ErrDuplicateAddress`, `wg.ErrUnknownPeerState`.

- [ ] **Step 1: Отложить неиспользуемую зависимость до задачи 3**

Чистая дельта не использует `wgctrl`: `go mod tidy` удалит эту зависимость.
Не добавлять фиктивный blank import. Закрепить `wgctrl` версии
`v0.0.0-20241231184526-a9ab2273dd10` в Task 3 Step 1 вместе с `netlink`
и первым реальным использованием `wgtypes`.

Run: `make mod`
Expected: код 0; `go.mod` и `go.sum` могут остаться без изменений.

- [ ] **Step 2: Написать падающий тест дельты**

`internal/nodeagent/wg/diff_test.go`:

```go
package wg

import (
	"errors"
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			t.Fatalf("parse %q: %v", v, err)
		}
		out = append(out, p)
	}
	return out
}

func TestDiffUnchangedPeerProducesNoOperations(t *testing.T) {
	live := LiveState{Peers: map[string]PeerState{
		"a": {PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.2/32", "10.0.0.0/24"), KeepaliveSec: 25},
	}}
	target := []TargetPeer{
		{PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.0/24", "10.0.0.2/32"), KeepaliveSec: 25, State: StateActive},
	}
	ops, err := Diff(live, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("ops = %+v, want none", ops)
	}
}

func TestDiffReportsAddUpdateRemove(t *testing.T) {
	live := LiveState{Peers: map[string]PeerState{
		"keep":    {PublicKey: "keep", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
		"change":  {PublicKey: "change", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 25},
		"removed": {PublicKey: "removed", AllowedIPs: prefixes(t, "10.0.0.4/32"), KeepaliveSec: 25},
	}}
	target := []TargetPeer{
		{PublicKey: "keep", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25, State: StateActive},
		{PublicKey: "change", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 30, State: StateActive},
		{PublicKey: "added", AllowedIPs: prefixes(t, "10.0.0.5/32"), KeepaliveSec: 25, State: StateActive},
	}
	ops, err := Diff(live, target)
	if err != nil {
		t.Fatal(err)
	}
	want := []Op{
		{Kind: OpAdd, PublicKey: "added", AllowedIPs: prefixes(t, "10.0.0.5/32"), KeepaliveSec: 25},
		{Kind: OpUpdate, PublicKey: "change", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 30},
		{Kind: OpRemove, PublicKey: "removed"},
	}
	if len(ops) != len(want) {
		t.Fatalf("ops = %+v, want %+v", ops, want)
	}
	for i := range want {
		if ops[i].Kind != want[i].Kind || ops[i].PublicKey != want[i].PublicKey ||
			ops[i].KeepaliveSec != want[i].KeepaliveSec || len(ops[i].AllowedIPs) != len(want[i].AllowedIPs) {
			t.Fatalf("ops[%d] = %+v, want %+v", i, ops[i], want[i])
		}
	}
}

// TestDiffGivesSharedAddressToActiveKey — ротация: в наборе оба ключа с одним
// адресом. Ядро разрешает адрес только одному пиеру (проверено: добавление
// второго пиера с тем же /32 отнимает его у первого), поэтому дельта обязана
// выбрать владельца сама, иначе каждый цикл «чинит» проигравшего и перекидывает
// адрес между ключами.
func TestDiffGivesSharedAddressToActiveKey(t *testing.T) {
	live := LiveState{Peers: map[string]PeerState{
		"old": {PublicKey: "old", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
	}}
	target := []TargetPeer{
		{PublicKey: "old", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25, State: StateRotatingOldKey},
		{PublicKey: "new", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25, State: StateActive},
	}
	ops, err := Diff(live, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("ops = %+v, want update old + add new", ops)
	}
	for _, op := range ops {
		switch op.PublicKey {
		case "old":
			if op.Kind != OpUpdate || len(op.AllowedIPs) != 0 {
				t.Fatalf("old op = %+v, want update with no allowed ips", op)
			}
		case "new":
			if op.Kind != OpAdd || len(op.AllowedIPs) != 1 || op.AllowedIPs[0].String() != "10.0.0.2/32" {
				t.Fatalf("new op = %+v, want add 10.0.0.2/32", op)
			}
		default:
			t.Fatalf("unexpected op %+v", op)
		}
	}
	// После применения владелец адреса — новый ключ; следующий цикл обязан быть пустым.
	live = LiveState{Peers: map[string]PeerState{
		"old": {PublicKey: "old", KeepaliveSec: 25},
		"new": {PublicKey: "new", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
	}}
	ops, err = Diff(live, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 0 {
		t.Fatalf("second diff = %+v, want none", ops)
	}
}

func TestDiffRejectsDuplicateAndEmptyKeys(t *testing.T) {
	_, err := Diff(LiveState{}, []TargetPeer{
		{PublicKey: "a", State: StateActive}, {PublicKey: "a", State: StateActive},
	})
	if !errors.Is(err, ErrDuplicatePeer) {
		t.Fatalf("duplicate err = %v, want ErrDuplicatePeer", err)
	}
	_, err = Diff(LiveState{}, []TargetPeer{{PublicKey: " ", State: StateActive}})
	if err == nil {
		t.Fatal("empty key accepted")
	}
}

func TestDiffRejectsTwoPeersOfOneKindOnOneAddress(t *testing.T) {
	_, err := Diff(LiveState{}, []TargetPeer{
		{PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.2/32"), State: StateActive},
		{PublicKey: "b", AllowedIPs: prefixes(t, "10.0.0.2/32"), State: StateActive},
	})
	if !errors.Is(err, ErrDuplicateAddress) {
		t.Fatalf("err = %v, want ErrDuplicateAddress", err)
	}
}

func TestDiffRejectsUnknownState(t *testing.T) {
	_, err := Diff(LiveState{}, []TargetPeer{{PublicKey: "a", State: "expired"}})
	if !errors.Is(err, ErrUnknownPeerState) {
		t.Fatalf("err = %v, want ErrUnknownPeerState", err)
	}
}
```

- [ ] **Step 3: Прогнать и убедиться, что не компилируется**

Run: `make unit`
Expected: FAIL — `undefined: Diff`.

- [ ] **Step 4: Реализовать дельту (дословный исходник)**

`internal/nodeagent/wg/diff.go`:

```go
// Package wg — слой узла, который приводит живой WireGuard-интерфейс к desired set.
// Дельта здесь чистая: ни netlink, ни HTTP, поэтому её можно проверить без
// привилегий, а дорогой путь «отправить в ядро» остаётся тонким.
package wg

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// PeerState — пиер в том виде, в каком его видит ядро. Endpoint и LastHandshake
// нужны отчёту, но в сравнение не входят: desired set их не содержит.
type PeerState struct {
	PublicKey     string
	AllowedIPs    []netip.Prefix
	KeepaliveSec  int
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
}

// LiveState — снимок устройства до применения. PublicKey и ListenPort нужны,
// чтобы отличить «устройство уже настроено этим ключом» от «ключ сменился».
// IfaceRxBytes/IfaceTxBytes — счётчики интерфейса из sysfs: wgctrl их не отдаёт,
// а heartbeat без них не отличит «узел жив, но трафика нет» от «счётчик не снят».
type LiveState struct {
	PublicKey     string
	ListenPort    int
	IfaceRxBytes  int64
	IfaceTxBytes  int64
	Peers         map[string]PeerState
}

// PeerKind — роль ключа в desired set. Различать их нужно только из-за адреса:
// при ротации оба ключа претендуют на один и тот же /32, а ядро отдаёт адрес
// ровно одному пиеру.
type PeerKind string

const (
	StateActive         PeerKind = "active"
	StateRotatingOldKey PeerKind = "rotating_old_key"
)

// TargetPeer — пиер, который обязан быть на устройстве. AllowedIPs — то, что
// узел хочет видеть у ключа; при совпадении адресов с ключом другого вида дельта
// отдаёт адрес активному и оставляет старому пустое множество.
type TargetPeer struct {
	PublicKey    string
	AllowedIPs   []netip.Prefix
	KeepaliveSec int
	State        PeerKind
}

type OpKind string

const (
	OpAdd    OpKind = "add"
	OpUpdate OpKind = "update"
	OpRemove OpKind = "remove"
)

// Op — одно изменение. Для OpRemove AllowedIPs и KeepaliveSec пусты: указание
// полей при удалении бессмысленно и маскирует ошибку «удалили и заодно поменяли».
type Op struct {
	Kind         OpKind
	PublicKey    string
	AllowedIPs   []netip.Prefix
	KeepaliveSec int
}

var (
	ErrDuplicatePeer    = errors.New("wg: duplicate public key in target")
	ErrDuplicateAddress = errors.New("wg: two peers of one kind claim one address")
	ErrUnknownPeerState = errors.New("wg: unknown peer state")
)

// Diff сравнивает desired с живым состоянием. Пиер, у которого совпали множество
// allowed-IP и keepalive, не попадает в результат: именно это свойство проверяет
// ADR-004 (неизменённый пиер не пересоздаётся). Endpoint не сравнивается — desired
// его не содержит, а ядро обновляет endpoint само по входящему handshake.
//
// Адрес в WireGuard эксклюзивен: если двум пиерам назначить один /32, ядро
// оставит его только последнему, а у первого станет пусто (измерено). Поэтому
// владелец каждого префикса вычисляется здесь, до сравнения: при ротации адрес
// получает активный ключ, старый остаётся без адреса и ждёт снятия по handshake
// потомка. Без этого правила дельта каждый цикл «чинила» бы проигравшего и
// перекидывала адрес между ключами, теряя handshake у обоих.
func Diff(live LiveState, target []TargetPeer) ([]Op, error) {
	type entry struct {
		key  string
		kind PeerKind
		ips  []netip.Prefix
		keep int
	}
	entries := make([]entry, 0, len(target))
	seen := make(map[string]bool, len(target))
	for _, p := range target {
		key := strings.TrimSpace(p.PublicKey)
		if key == "" {
			return nil, errors.New("wg: empty public key in target")
		}
		if seen[key] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicatePeer, key)
		}
		if p.State != StateActive && p.State != StateRotatingOldKey {
			return nil, fmt.Errorf("%w: %q", ErrUnknownPeerState, p.State)
		}
		seen[key] = true
		entries = append(entries, entry{key: key, kind: p.State, ips: p.AllowedIPs, keep: p.KeepaliveSec})
	}
	owner := make(map[netip.Prefix]string, len(entries))
	kinds := make(map[string]PeerKind, len(entries))
	for _, e := range entries {
		kinds[e.key] = e.kind
		for _, prefix := range e.ips {
			masked := prefix.Masked()
			prev, taken := owner[masked]
			switch {
			case !taken:
				owner[masked] = e.key
			case kinds[prev] == e.kind:
				return nil, fmt.Errorf("%w: %s claimed by %s and %s", ErrDuplicateAddress, masked, prev, e.key)
			case e.kind == StateActive:
				owner[masked] = e.key
			}
		}
	}
	effective := make(map[string][]netip.Prefix, len(entries))
	for prefix, key := range owner {
		effective[key] = append(effective[key], prefix)
	}
	for key := range effective {
		slices.SortFunc(effective[key], func(a, b netip.Prefix) int {
			return cmp.Compare(a.String(), b.String())
		})
	}
	ops := make([]Op, 0, len(entries))
	for _, e := range entries {
		cur, exists := live.Peers[e.key]
		if !exists {
			ops = append(ops, Op{Kind: OpAdd, PublicKey: e.key, AllowedIPs: effective[e.key], KeepaliveSec: e.keep})
			continue
		}
		if !samePrefixes(cur.AllowedIPs, effective[e.key]) || cur.KeepaliveSec != e.keep {
			ops = append(ops, Op{Kind: OpUpdate, PublicKey: e.key, AllowedIPs: effective[e.key], KeepaliveSec: e.keep})
		}
	}
	for key := range live.Peers {
		if !seen[key] {
			ops = append(ops, Op{Kind: OpRemove, PublicKey: key})
		}
	}
	slices.SortFunc(ops, func(a, b Op) int {
		if c := cmp.Compare(a.PublicKey, b.PublicKey); c != 0 {
			return c
		}
		return cmp.Compare(a.Kind, b.Kind)
	})
	return ops, nil
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	as := make([]string, len(a))
	bs := make([]string, len(b))
	for i := range a {
		as[i] = a[i].Masked().String()
	}
	for i := range b {
		bs[i] = b[i].Masked().String()
	}
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}
```

- [ ] **Step 5: Прогнать тесты**

Run: `make unit`
Expected: PASS.

- [ ] **Step 6: Поправить ADR-004**

В `docs/adr/0004-wireguard-peer-apply.md` пункт 2 сейчас требует сравнения по endpoint.
Desired set endpoint не содержит, поэтому в решении заменить перечень полей на: публичный
ключ, множество allowed-IP, persistent-keepalive; добавить строку «endpoint в сравнение не
входит: он не передаётся узлу в desired set и обновляется ядром по входящему handshake;
сравнение по нему всегда давало бы расхождение». В «Последствия» добавить, что это
уточнение не меняет измеренный вывод S3.

- [ ] **Step 7: Ворота и коммит**

Run: `make unit && make vet`
Expected: код 0.

```bash
git add go.mod go.sum internal/nodeagent docs/adr/0004-wireguard-peer-apply.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): wgctrl и чистая дельта пиеров по правилам ADR-004"
```

---

### Task 3: rtnetlink — устройство и адрес; сборка `wgtypes.Config`

**Files:**
- Modify: `go.mod`, `go.sum`, `docs/adr/README.md`
- Create: `internal/nodeagent/wg/link.go`, `internal/nodeagent/wg/config.go`,
  `internal/nodeagent/wg/config_test.go`, `docs/adr/0009-node-network-operations.md`

**Interfaces:**
- Produces: `wg.LinkManager` (`EnsureLink(name string, mtu int) error`,
  `EnsureAddress(name string, addr netip.Prefix) error`), `wg.Netlink`,
  `wg.Target`, `wg.ConfigFor(t Target, ops []Op) (wgtypes.Config, error)`.

- [ ] **Step 1: Добавить зависимости вместе с первым использованием**

В `go.mod` одновременно с первым реальным использованием `wgtypes` и `netlink`
добавить обе зависимости (закрепление `wgctrl` перенесено из задачи 2):

```
	github.com/vishvananda/netlink v1.3.1
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
```

Run: `make mod` после появления реальных импортов; фиктивный blank import запрещён.
Expected: код 0; обе зависимости сохранены в `go.mod`, `go.sum` дополнен.

- [ ] **Step 2: Написать падающий тест сборки конфига**

`internal/nodeagent/wg/config_test.go`:

```go
package wg

import (
	"net/netip"
	"testing"
	"time"
)

func TestConfigForNeverReplacesPeers(t *testing.T) {
	priv := "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	target := Target{PrivateKey: priv, ListenPort: 51820, MTU: 1420,
		TunnelAddress: netip.MustParsePrefix("10.99.0.1/24")}
	cfg, err := ConfigFor(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReplacePeers {
		t.Fatal("ReplacePeers must be false: full replace recreates unchanged peers")
	}
	if cfg.ListenPort == nil || *cfg.ListenPort != 51820 {
		t.Fatalf("listen port = %v", cfg.ListenPort)
	}
	if cfg.PrivateKey == nil || cfg.PrivateKey.String() != priv {
		t.Fatalf("private key = %v", cfg.PrivateKey)
	}
}

func TestConfigForMapsOperations(t *testing.T) {
	pub := "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	ops := []Op{
		{Kind: OpAdd, PublicKey: pub, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")}, KeepaliveSec: 25},
		{Kind: OpRemove, PublicKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="},
	}
	cfg, err := ConfigFor(Target{PrivateKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", ListenPort: 51820}, ops)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("peers = %d", len(cfg.Peers))
	}
	if !cfg.Peers[0].ReplaceAllowedIPs || len(cfg.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("add op = %+v", cfg.Peers[0])
	}
	if cfg.Peers[0].PersistentKeepalive == nil || *cfg.Peers[0].PersistentKeepalive != 25*time.Second {
		t.Fatalf("keepalive = %v", cfg.Peers[0].PersistentKeepalive)
	}
	if !cfg.Peers[1].Remove {
		t.Fatalf("remove op = %+v", cfg.Peers[1])
	}
}

func TestConfigForRejectsBrokenKey(t *testing.T) {
	_, err := ConfigFor(Target{PrivateKey: "not-a-key"}, nil)
	if err == nil {
		t.Fatal("broken private key accepted")
	}
}
```

- [ ] **Step 3: Прогнать и убедиться, что не компилируется**

Run: `make unit`
Expected: FAIL — `undefined: ConfigFor`.

- [ ] **Step 4: Реализовать `config.go` (дословный исходник)**

```go
package wg

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Target — всё, что агент обязан иметь на устройстве. Приватный ключ здесь
// строкой, потому что он приходит из файла состояния; в API он не ходит.
type Target struct {
	PrivateKey    string
	ListenPort    int
	MTU           int
	TunnelAddress netip.Prefix
	Peers         []TargetPeer
}

// ConfigFor переводит операции в формат wgtypes. ReplacePeers здесь жёстко
// false: настройка вынесена в одну функцию, чтобы её нельзя было случайно
// включить в другом месте (ADR-004).
func ConfigFor(t Target, ops []Op) (wgtypes.Config, error) {
	key, err := wgtypes.ParseKey(t.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("wg: private key: %w", err)
	}
	port := t.ListenPort
	cfg := wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &port,
		ReplacePeers: false,
		Peers:        make([]wgtypes.PeerConfig, 0, len(ops)),
	}
	for _, op := range ops {
		pub, err := wgtypes.ParseKey(op.PublicKey)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("wg: peer key %q: %w", op.PublicKey, err)
		}
		peer := wgtypes.PeerConfig{PublicKey: pub}
		switch op.Kind {
		case OpRemove:
			peer.Remove = true
		case OpAdd, OpUpdate:
			peer.ReplaceAllowedIPs = true
			peer.AllowedIPs = toIPNets(op.AllowedIPs)
			keepalive := time.Duration(op.KeepaliveSec) * time.Second
			peer.PersistentKeepalive = &keepalive
		default:
			return wgtypes.Config{}, fmt.Errorf("wg: unknown operation %q", op.Kind)
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	return cfg, nil
}

func toIPNets(prefixes []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, len(prefixes))
	for i, p := range prefixes {
		out[i] = net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
	}
	return out
}
```

- [ ] **Step 5: Реализовать `link.go` (схема, не исходник)**

Требования к `Netlink`:

- `EnsureLink(name, mtu)`: найденное устройство сначала проверить на тип `wireguard`;
  чужой тип с тем же именем — ошибка без изменений. Затем сравнить MTU и при отличии
  вызвать `netlink.LinkSetMTU`. Только `netlink.LinkNotFoundError` разрешает создание
  через `netlink.LinkAdd(&netlink.Wireguard{LinkAttrs:
  netlink.LinkAttrs{Name: name, MTU: mtu}})`; прочие ошибки поиска вернуть с контекстом.
  Новый или существующий интерфейс без флага UP поднять через `netlink.LinkSetUp`.
- `EnsureAddress(name, addr)`: найти устройство, проверить тип `wireguard` до изменений,
  затем `netlink.ParseAddr(addr.String())` и `netlink.AddrReplace` (идемпотентно;
  `AddrAdd` на существующем адресе дал бы EEXIST).
- Свойства: ни одного `os/exec`, ни одной строки shell; маршрут для пула не добавляется —
  адрес с маской создаёт connected route, а лишний маршрут дублировал бы его.
- Методы — на значении (`func (Netlink) EnsureLink(...)`, `func (Netlink)
  EnsureAddress(...)`): в задаче 9 в `Applier.Link` передаётся `wg.Netlink{}` значением, и
  при указателе это не собралось бы.

- [ ] **Step 6: Проверить компиляцию и тесты**

Run: `make unit && make vet`
Expected: PASS. `link.go` на этом шаге не тестируется без привилегий; его прогон —
задача 11 (E2E).

- [ ] **Step 7: Записать ADR-0009 о сетевых операциях узла**

`docs/adr/0009-node-network-operations.md`, формат как у ADR-004 (заголовок, «Статус»,
«Обусловлен», «Касается», «Контекст», «Решение», «Последствия», «Отклонено»):

- **Статус:** принят (2026-10-28).
- **Касается:** `internal/nodeagent/wg/link.go`, Ansible-роль `novavpn_node`, harness E2E.
- **Контекст:** узлу нужны устройство, адрес, NAT и `ip_forward`. Готовые `ip`, `wg`,
  `iptables-save` в управляющем коде означали бы shell-вызовы из долгоживущего процесса
  против ТЗ §5; правка чужого ruleset на хосте делает откат невоспроизводимым.
- **Решение:** (1) устройство и адрес — только `rtnetlink` в процессе (`LinkAdd`,
  `LinkSetMTU`, `AddrReplace`), без `os/exec`; (2) маршрут пула не добавляется — его даёт
  connected route от адреса с маской пула; (3) `sysctl` и `modprobe wireguard` остаются
  отдельным root-шагом провижининга, агент их не выполняет; (4) NAT и forward-политика
  живут в **отдельной nftables-таблице `novavpn`**, чужие таблицы не читаются и не
  правятся, поэтому откат — удаление одной таблицы.
- **Последствия:** агент не требует root: достаточно `CAP_NET_ADMIN` (измерено S1);
  конфигурация NAT проверяется в E2E задачей 11, откат — в runbook задачи 15.
- **Отклонено:** `wg-quick`/`syncconf` через subprocess (shell из управляющего кода, нет
  живых метрик); правка `iptables`/`nft` в общем ruleset (нечего откатывать);
  маршрут `AddressPool` через `netlink.RouteAdd` (дублирует connected route).

В `docs/adr/README.md` добавить в таблицу строку
`| 009 | [0009-node-network-operations.md](0009-node-network-operations.md) | принят |`,
а в абзаце над таблицей убрать `0009` из перечня «существуют только как строки ADR-карты»
(сейчас там `0001`–`0003` и `0005`–`0008`).

- [ ] **Step 8: Коммит**

```bash
git add go.mod go.sum internal/nodeagent/wg docs/adr/0009-node-network-operations.md docs/adr/README.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): rtnetlink для устройства и адреса, сборка wgtypes.Config"
```

---

### Task 4: Клиент ядра — снимок состояния и применение

**Files:**
- Create: `internal/nodeagent/wg/device.go`
- Create: `internal/nodeagent/wg/device_test.go`
- Modify: `go.mod`, `go.sum` — корневой пакет `wgctrl` импортируется впервые,
  `make mod` добавляет косвенные `mdlayher/netlink`, `mdlayher/genetlink`,
  `mdlayher/socket`, `josharian/native`, `golang.org/x/net`,
  `golang.zx2c4.com/wireguard`, `github.com/google/go-cmp` (R23)

**Interfaces:**
- Produces: `wg.DeviceClient` (`Snapshot(iface string) (LiveState, error)`,
  `Configure(iface string, cfg wgtypes.Config) error`), `wg.WG`, `wg.Open() (*WG, error)`.

- [x] **Step 1: Написать тесты вспомогательных функций и получить RED**

`device_test.go`: ошибка чтения (нет файла, вместо файла каталог), пустое,
неверное, отрицательное и переполненное значение счётчика с различимостью
`strconv.ErrSyntax` и `strconv.ErrRange` через `errors.Is`; настоящий ноль,
пробелы и максимальный `int64`. Ошибка содержит путь и русский контекст.
Преобразование адресов: IPv4 в 4 и 16 байтах, IPv6, `/0`, host-биты,
обратное преобразование через `toIPNets`, отсутствие мутаций входа.
Неподдерживаемые адреса и маски пропускаются; порядок и повторы сохраняются.
При 32-битной маске IPv4 преобразуется через `Unmap`; при 128-битной маске
сохраняется семейство IPv6, включая mapped-префиксы.
Сосредоточенный запуск через `run-make.sh unit`: переопределить `DOCKER_FLAGS`
с `-w /src/internal/nodeagent/wg` и фильтром `TestReadCounter|TestFromIPNets`.

- [x] **Step 2: Реализовать `device.go`**

R5: `readCounter` возвращает `(int64, error)`, ошибка не является нулевым
измерением. `Snapshot` возвращает полный снимок только после успешного чтения
обоих интерфейсных счётчиков. Любой отказ возвращает `LiveState{}` и ошибку
с контекстом; интерфейс и пиры не изменяются, `Configure` не вызывается.
Сбой sysfs приостанавливает применение, не меняя форму отчёта API.

```go
package wg

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type DeviceClient interface {
	Snapshot(iface string) (LiveState, error)
	Configure(iface string, cfg wgtypes.Config) error
}

type WG struct{ c *wgctrl.Client }

func Open() (*WG, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wg: управляющий сокет: %w", err)
	}
	return &WG{c: c}, nil
}

func (w *WG) Close() error {
	if err := w.c.Close(); err != nil {
		return fmt.Errorf("wg: закрытие управляющего сокета: %w", err)
	}
	return nil
}

// Snapshot не возвращает частичный снимок: без обоих счётчиков применение приостанавливается (R5).
func (w *WG) Snapshot(iface string) (LiveState, error) {
	dev, err := w.c.Device(iface)
	if err != nil {
		return LiveState{}, fmt.Errorf("wg: устройство %s: %w", iface, err)
	}
	rx, err := readCounter("/sys/class/net/" + iface + "/statistics/rx_bytes")
	if err != nil {
		return LiveState{}, fmt.Errorf("wg: снимок %s: %w", iface, err)
	}
	tx, err := readCounter("/sys/class/net/" + iface + "/statistics/tx_bytes")
	if err != nil {
		return LiveState{}, fmt.Errorf("wg: снимок %s: %w", iface, err)
	}
	out := LiveState{
		PublicKey:    dev.PublicKey.String(),
		ListenPort:   dev.ListenPort,
		IfaceRxBytes: rx,
		IfaceTxBytes: tx,
		Peers:        make(map[string]PeerState, len(dev.Peers)),
	}
	for _, p := range dev.Peers {
		key := p.PublicKey.String()
		out.Peers[key] = PeerState{
			PublicKey:     key,
			AllowedIPs:    fromIPNets(p.AllowedIPs),
			KeepaliveSec:  int(p.PersistentKeepaliveInterval.Seconds()),
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
			LastHandshake: p.LastHandshakeTime,
		}
	}
	return out, nil
}

func (w *WG) Configure(iface string, cfg wgtypes.Config) error {
	if err := w.c.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("wg: настройка %s: %w", iface, err)
	}
	return nil
}

func fromIPNets(nets []net.IPNet) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits == 32 {
			addr = addr.Unmap()
		}
		if bits != addr.BitLen() {
			continue
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out
}

func readCounter(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("wg: чтение счётчика %s: %w", path, err)
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("wg: неверный счётчик %s: %w", path, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("wg: отрицательный счётчик %s", path)
	}
	return v, nil
}
```

- [ ] **Step 3: Проверить сборку и тесты**

Run: `run-make.sh mod`, затем `run-make.sh unit` и `run-make.sh vet` из каталога постановки.
Expected: PASS, включая повторный строгий прогон с `-mod=readonly`: модульные
файлы полны, `go mod tidy` больше ничего не меняет. Сосредоточенный GREEN
не заменяет полные unit/vet.
Настоящий путь `Snapshot`/`Configure` проверяется в E2E задачи 11;
до этого он отмечается `not-run`, компиляция не считается запуском туннеля.

- [x] **Step 4: Коммит**

```bash
git add internal/nodeagent/wg/device.go internal/nodeagent/wg/device_test.go \
  go.mod go.sum docs/superpowers/plans/2026-10-27-novavpn-cycle-a3-node-runtime.md
GIT_AUTHOR_NAME='NovaVPN Dev' GIT_AUTHOR_EMAIL='dev@novavpn.local' \
GIT_COMMITTER_NAME='NovaVPN Dev' GIT_COMMITTER_EMAIL='dev@novavpn.local' \
git commit -m "$(cat <<'EOF'
feat(a3): не подменять ошибки снимка WireGuard нулевыми измерениями
EOF
)"
```

---

### Task 5: Применение набора — порядок, снимок до изменений, ноль обращений при пустой дельте

**Files:**
- Create: `internal/nodeagent/wg/applier.go`
- Create: `internal/nodeagent/wg/applier_test.go`
- Modify: `docs/superpowers/plans/2026-10-27-novavpn-cycle-a3-node-runtime.md` — только фрагмент Task 5

**Interfaces:**
- Consumes: `wg.LinkManager`, `wg.DeviceClient`, `wg.Diff`, `wg.ConfigFor`.
- Produces: `wg.Applier{Link LinkManager; Device DeviceClient; Iface string}`,
  `wg.ApplyResult{Before LiveState; Ops int}`,
  `(*Applier).Apply(t Target) (ApplyResult, error)`.

Порядок шагов задан ADR-004: интерфейс и адрес, затем снимок, затем дельта, затем
`Configure`. Снимок обязан быть до `Configure`, потому что пересоздание пиера
обнуляет счётчики в ядре. Пустая дельта не вызывает `Configure` вовсе, но
`ConfigFor` вызывается всегда: он проверяет приватный ключ и при неизменных пирах.

- [ ] **Step 1: Написать падающий тест**

Используй ровно этот исходник `internal/nodeagent/wg/applier_test.go`:

```go
package wg

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type journal struct{ calls []string }

func (j *journal) add(name string) { j.calls = append(j.calls, name) }

type fakeLink struct {
	links, addrs int
	failLink     bool
	failAddr     bool
	log          *journal
}

func (f *fakeLink) record(name string) {
	if f.log == nil {
		f.log = &journal{}
	}
	f.log.add(name)
}

func (f *fakeLink) EnsureLink(string, int) error {
	f.links++
	f.record("link")
	if f.failLink {
		return errTest
	}
	return nil
}

func (f *fakeLink) EnsureAddress(string, netip.Prefix) error {
	f.addrs++
	f.record("address")
	if f.failAddr {
		return errTest
	}
	return nil
}

type fakeDevice struct {
	state         LiveState
	snapshots     int
	configure     int
	last          wgtypes.Config
	failSnapshot  bool
	failConfigure bool
	log           *journal
}

func (f *fakeDevice) record(name string) {
	if f.log == nil {
		f.log = &journal{}
	}
	f.log.add(name)
}

func (f *fakeDevice) Snapshot(string) (LiveState, error) {
	f.snapshots++
	f.record("snapshot")
	if f.failSnapshot {
		return LiveState{}, errTest
	}
	return f.state, nil
}

func (f *fakeDevice) Configure(_ string, cfg wgtypes.Config) error {
	f.configure++
	f.record("configure")
	f.last = cfg
	if f.failConfigure {
		return errTest
	}
	return nil
}

type testError struct{}

func (testError) Error() string { return "boom" }

var errTest = testError{}

func newKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func peerFrom(key wgtypes.Key, prefix string, keepalive int) TargetPeer {
	return TargetPeer{
		PublicKey:    key.PublicKey().String(),
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix(prefix)},
		KeepaliveSec: keepalive, State: StateActive,
	}
}

func targetFor(private wgtypes.Key, peers ...TargetPeer) Target {
	return Target{
		PrivateKey: private.String(), ListenPort: 51820, MTU: 1420,
		TunnelAddress: netip.MustParsePrefix("10.99.0.1/24"), Peers: peers,
	}
}

func TestApplyDoesNotTouchUnchangedPeers(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	target := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	log := &journal{}
	dev := &fakeDevice{log: log, state: LiveState{Peers: map[string]PeerState{
		peer.PublicKey().String(): {
			PublicKey:    peer.PublicKey().String(),
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			KeepaliveSec: 25,
		},
	}}}
	link := &fakeLink{log: log}
	res, err := (&Applier{Link: link, Device: dev, Iface: "wg0"}).Apply(target)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ops != 0 || dev.configure != 0 {
		t.Fatalf("операций %d, вызовов configure %d; ожидалось 0/0", res.Ops, dev.configure)
	}
	if link.links != 1 || link.addrs != 1 || dev.snapshots != 1 {
		t.Fatalf("интерфейс %d, адрес %d, снимков %d; ожидалось 1/1/1", link.links, link.addrs, dev.snapshots)
	}
	if got := strings.Join(log.calls, ","); got != "link,address,snapshot" {
		t.Fatalf("порядок вызовов %q; ожидался link,address,snapshot", got)
	}
}

func TestApplyRemovesAndAdds(t *testing.T) {
	priv := newKey(t)
	add := newKey(t)
	drop := newKey(t)
	log := &journal{}
	dev := &fakeDevice{log: log, state: LiveState{Peers: map[string]PeerState{
		drop.PublicKey().String(): {
			PublicKey:  drop.PublicKey().String(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.3/32")},
		},
	}}}
	link := &fakeLink{log: log}
	res, err := (&Applier{Link: link, Device: dev, Iface: "wg0"}).
		Apply(targetFor(priv, peerFrom(add, "10.99.0.2/32", 25)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Ops != 2 || dev.configure != 1 {
		t.Fatalf("операций %d, configure %d; ожидалось 2/1", res.Ops, dev.configure)
	}
	if got := strings.Join(log.calls, ","); got != "link,address,snapshot,configure" {
		t.Fatalf("порядок вызовов %q; ожидался link,address,snapshot,configure", got)
	}
	if dev.last.ReplacePeers {
		t.Fatal("ReplacePeers должен оставаться false")
	}
	if len(dev.last.Peers) != 2 {
		t.Fatalf("пиров в конфигурации %d; ожидалось 2", len(dev.last.Peers))
	}
	removed := 0
	for _, p := range dev.last.Peers {
		if p.Remove {
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("снятых пиров %d; ожидался 1", removed)
	}
}

func TestApplyStopsBeforeKernelWhenLinkFails(t *testing.T) {
	dev := &fakeDevice{}
	link := &fakeLink{failLink: true}
	_, err := (&Applier{Link: link, Device: dev, Iface: "wg0"}).
		Apply(targetFor(newKey(t)))
	if err == nil {
		t.Fatal("отказ интерфейса проигнорирован")
	}
	if link.addrs != 0 || dev.snapshots != 0 || dev.configure != 0 {
		t.Fatalf("адресов %d, снимков %d, configure %d; ожидалось 0/0/0", link.addrs, dev.snapshots, dev.configure)
	}
}

func TestApplyStopsOnAddressFailure(t *testing.T) {
	dev := &fakeDevice{}
	_, err := (&Applier{Link: &fakeLink{failAddr: true}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(newKey(t)))
	if err == nil {
		t.Fatal("отказ адреса проигнорирован")
	}
	if dev.snapshots != 0 || dev.configure != 0 {
		t.Fatalf("снимков %d, configure %d; ожидалось 0/0", dev.snapshots, dev.configure)
	}
}

func TestApplyStopsOnSnapshotFailure(t *testing.T) {
	dev := &fakeDevice{failSnapshot: true}
	res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(newKey(t)))
	if err == nil {
		t.Fatal("отказ снимка проигнорирован")
	}
	if dev.configure != 0 || res.Ops != 0 {
		t.Fatalf("configure %d, операций %d; ожидалось 0/0", dev.configure, res.Ops)
	}
}

func TestApplyStopsOnDiffFailure(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	dev := &fakeDevice{}
	dup := peerFrom(peer, "10.99.0.2/32", 25)
	_, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(priv, dup, dup))
	if err == nil {
		t.Fatal("повтор ключа в целевом наборе проигнорирован")
	}
	if !errors.Is(err, ErrDuplicatePeer) {
		t.Fatalf("ожидалась ErrDuplicatePeer, получено %v", err)
	}
	if dev.configure != 0 {
		t.Fatal("configure вызван после ошибки дельты")
	}
}

func TestApplyStopsOnConfigFailure(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	dev := &fakeDevice{}
	bad := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	bad.PrivateKey = "не-ключ"
	_, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).Apply(bad)
	if err == nil {
		t.Fatal("неверный приватный ключ проигнорирован")
	}
	if dev.configure != 0 {
		t.Fatal("configure вызван после ошибки конфигурации")
	}
}

func TestApplyReportsConfigureFailureWithBefore(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	target := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	dev := &fakeDevice{
		state: LiveState{Peers: map[string]PeerState{
			peer.PublicKey().String(): {
				PublicKey:  peer.PublicKey().String(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			},
		}},
		failConfigure: true,
	}
	res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).Apply(target)
	if err == nil {
		t.Fatal("отказ configure проигнорирован")
	}
	if res.Ops != 1 || res.Before.Peers == nil {
		t.Fatalf("операций %d, снимок %v; ожидался 1 и непустой Before", res.Ops, res.Before.Peers)
	}
}

func TestApplyRejectsBrokenKeyWithEmptyDelta(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	target := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	target.PrivateKey = "не-ключ"
	dev := &fakeDevice{state: LiveState{Peers: map[string]PeerState{
		peer.PublicKey().String(): {
			PublicKey:    peer.PublicKey().String(),
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			KeepaliveSec: 25,
		},
	}}}
	ops, err := Diff(dev.state, target.Peers)
	if err != nil || len(ops) != 0 {
		t.Fatalf("предусловие нарушено: дельта %d операций, ошибка %v", len(ops), err)
	}
	res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).Apply(target)
	if err == nil {
		t.Fatal("неверный ключ принят при пустой дельте")
	}
	if dev.configure != 0 || res.Ops != 0 {
		t.Fatalf("configure %d, операций %d; ожидалось 0/0", dev.configure, res.Ops)
	}
}
```

Ключи генерируются при выполнении через `wgtypes.GeneratePrivateKey`; литеральных
ключей в тесте нет. Оба фейка пишут в один общий журнал `journal`, поэтому сверка
`link,address,snapshot` и `link,address,snapshot,configure` доказывает взаимный
порядок вызовов интерфейса и устройства, а не только порядок внутри каждого фейка.
Тест отказа адреса доказывает, что `EnsureAddress` останавливает применение до
снимка. Тест пустой дельты сначала проверяет предусловие через `Diff`: дельта
обязана быть пустой, иначе падение на ключе ничего не доказывает.

- [ ] **Step 2: Прогнать и убедиться, что не компилируется**

Run: focused `make unit` по пакету `internal/nodeagent/wg` с `-mod=readonly`.
Expected: FAIL — `undefined: Applier`, `undefined: Target` уже существует, поэтому
ошибка должна быть именно про `Applier` и `ApplyResult`.

- [ ] **Step 3: Реализовать `applier.go`**

```go
package wg

import "fmt"

// Applier задаёт порядок шагов явно: интерфейс и адрес, снимок, дельта.
// Снимок обязан быть до Configure: пересоздание пиера обнуляет счётчики в ядре,
// и отчёт, снятый после применения, потерял бы байты (ADR-004, правило 4).
type Applier struct {
	Link   LinkManager
	Device DeviceClient
	Iface  string
}

// ApplyResult — что известно после вызова. Before это снимок ядра до изменений,
// он значим и при ошибке настройки. Ops — число операций дельты: при ошибке
// настройки ядро могло измениться, поэтому непустой Ops нельзя прочитать как
// «набор применён».
type ApplyResult struct {
	Before LiveState
	Ops    int
}

func (a *Applier) Apply(t Target) (ApplyResult, error) {
	if err := a.Link.EnsureLink(a.Iface, t.MTU); err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: интерфейс: %w", err)
	}
	if err := a.Link.EnsureAddress(a.Iface, t.TunnelAddress); err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: адрес: %w", err)
	}
	before, err := a.Device.Snapshot(a.Iface)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: снимок: %w", err)
	}
	ops, err := Diff(before, t.Peers)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: дельта: %w", err)
	}
	// ConfigFor проверяет приватный ключ, поэтому вызывается и при пустой дельте:
	// иначе один и тот же Target принимался бы по-разному в зависимости от того,
	// совпали ли пиры, а ошибка ключа всплыла бы только на первом изменении.
	cfg, err := ConfigFor(t, ops)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: конфигурация: %w", err)
	}
	if len(ops) == 0 {
		return ApplyResult{Before: before}, nil
	}
	if err := a.Device.Configure(a.Iface, cfg); err != nil {
		return ApplyResult{Before: before, Ops: len(ops)}, fmt.Errorf("wg: применение: настройка: %w", err)
	}
	return ApplyResult{Before: before, Ops: len(ops)}, nil
}
```

Тексты ошибок в пакете `wg` русские; префикс `wg: применение: ...` согласован
с `device.go` и `link.go`.

- [ ] **Step 4: Прогнать тесты**

Run: focused `make unit` по пакету с `-mod=readonly`, затем полные `unit` и `vet`.
Expected: PASS, девять тестов `Applier`: проверены порядок вызовов, отказ адреса и
отказ неверного ключа при пустой дельте; полный прогон без новых падений.

- [ ] **Step 5: Коммит**

```bash
git add internal/nodeagent/wg/applier.go internal/nodeagent/wg/applier_test.go \
  docs/superpowers/plans/2026-10-27-novavpn-cycle-a3-node-runtime.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): применение набора — снимок до изменений и пустая дельта без netlink"
```

Один новый локальный коммит, без amend и push. `go.mod`/`go.sum` меняться не должны:
новых импортов нет.

---

### Task 6: Состояние узла — ключ `0600` и атомарная запись

Состояние переживает рестарт и недоступность API: последний применённый набор и узловой
токен лежат на диске. Потеря токена означает повторный enroll, а потеря ключа — новый
публичный ключ и правку сервера у администратора, поэтому ключ не перевыпускается молча,
а запись атомарная: оборванный процесс не оставляет половину файла. Каталог ужесточается до
`0700` при записи файлов, а существующий ключ — до `0600` при `EnsureKey`; пустой `Dir`
отвергается, иначе `chmod` задел бы каталог, из которого запущен процесс.

**Files:**
- Create: `internal/nodeagent/state/state.go`
- Create: `internal/nodeagent/state/state_test.go`
- Modify: `docs/superpowers/plans/2026-10-27-novavpn-cycle-a3-node-runtime.md` — только фрагмент Task 6

**Interfaces:**
- Produces: `state.Store{Dir string}`, `state.NodeState`, `state.Applied`,
  `(*Store).EnsureKey() (pub string, created bool, err error)`,
  `(*Store).PrivateKey() (wgtypes.Key, error)`, `(*Store).Load() (NodeState, error)`,
  `(*Store).Save(NodeState) error`; файлы `node.key` и `state.json`.

- [ ] **Step 1: Написать падающий тест**

Используй ровно этот исходник `internal/nodeagent/state/state_test.go`:

```go
package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestEnsureKeyCreatesOnceAndKeepsMode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() == 0o700 {
		t.Fatal("исходный каталог уже 0700: проверка ужесточения не различает")
	}
	s := Store{Dir: dir}
	pub, created, err := s.EnsureKey()
	if err != nil || !created || pub == "" {
		t.Fatalf("первый вызов: ключ %q, создан %v, ошибка %v", pub, created, err)
	}
	pub2, created2, err := s.EnsureKey()
	if err != nil || created2 || pub2 != pub {
		t.Fatalf("повторный вызов: ключ %q, создан %v, ошибка %v", pub2, created2, err)
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("права ключа %o; ожидались 600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("права каталога %o; ожидались 700", got)
	}
}

func TestEnsureKeyDoesNotRegenerateBrokenKey(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	path := filepath.Join(dir, "node.key")
	if err := os.WriteFile(path, []byte("не-ключ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.EnsureKey(); err == nil {
		t.Fatal("испорченный ключ молча перевыпущен")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "не-ключ" {
		t.Fatal("файл ключа изменён при отказе")
	}
}

func TestEnsureKeyTightensExistingKeyMode(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.key")
	if err := os.WriteFile(path, []byte(key.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	pub, created, err := s.EnsureKey()
	if err != nil || created {
		t.Fatalf("существующий ключ: создан %v, ошибка %v", created, err)
	}
	if want := key.PublicKey().String(); pub != want {
		t.Fatal("публичный ключ не совпал с существующим")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("права ключа %o; ожидались 600", got)
	}
}

func TestEmptyDirRejected(t *testing.T) {
	s := Store{}
	if _, _, err := s.EnsureKey(); !errors.Is(err, errNoDir) {
		t.Fatalf("EnsureKey: ошибка %v", err)
	}
	if _, err := s.PrivateKey(); !errors.Is(err, errNoDir) {
		t.Fatalf("PrivateKey: ошибка %v", err)
	}
	if _, err := s.Load(); !errors.Is(err, errNoDir) {
		t.Fatalf("Load: ошибка %v", err)
	}
	if err := s.Save(NodeState{}); !errors.Is(err, errNoDir) {
		t.Fatalf("Save: ошибка %v", err)
	}
}

func TestSaveAndLoadRoundTripWithoutPrivateKey(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	if _, _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	want := NodeState{
		ServerID:      "8f0c0000-0000-4000-8000-000000000001",
		NodeToken:     "tok",
		TokenIssuedAt: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
		Applied: Applied{
			ConfigVersion: 7,
			ETag:          `"x"`,
			AppliedAt:     time.Date(2026, 10, 27, 11, 30, 0, 0, time.UTC),
			Peers:         2,
		},
	}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerID != want.ServerID {
		t.Fatalf("ServerID %q; ожидался %q", got.ServerID, want.ServerID)
	}
	if got.NodeToken != want.NodeToken {
		t.Fatal("узловой токен не совпал с сохранённым")
	}
	if got.Applied.ConfigVersion != want.Applied.ConfigVersion {
		t.Fatalf("версия конфигурации %d; ожидалась %d", got.Applied.ConfigVersion, want.Applied.ConfigVersion)
	}
	if got.Applied.ETag != want.Applied.ETag {
		t.Fatalf("ETag %q; ожидался %q", got.Applied.ETag, want.Applied.ETag)
	}
	if got.Applied.Peers != want.Applied.Peers {
		t.Fatalf("пиеров %d; ожидалось %d", got.Applied.Peers, want.Applied.Peers)
	}
	if !got.Applied.AppliedAt.Equal(want.Applied.AppliedAt) {
		t.Fatalf("время применения %v; ожидалось %v", got.Applied.AppliedAt, want.Applied.AppliedAt)
	}
	if !got.TokenIssuedAt.Equal(want.TokenIssuedAt) {
		t.Fatalf("время выдачи токена %v; ожидалось %v", got.TokenIssuedAt, want.TokenIssuedAt)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("права состояния %o; ожидались 600", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), key.String()) {
		t.Fatal("приватный ключ попал в state.json")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("временные файлы остались: %v", leftovers)
	}
}

func TestLoadMissingReturnsEmptyAndBrokenReturnsError(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	got, err := s.Load()
	if err != nil || got.ServerID != "" {
		t.Fatalf("отсутствующий файл: %+v %v", got, err)
	}
	if _, _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("испорченное состояние принято: узел молча потерял бы токен")
	}
}
```

- [ ] **Step 2: Прогнать и убедиться, что не компилируется**

Run: focused `make unit` по пакету `internal/nodeagent/state` с `-mod=readonly`.
Expected: FAIL — `undefined: Store`.

- [ ] **Step 3: Реализовать `state.go` (дословный исходник)**

```go
// Package state хранит то, что узел не имеет права потерять между рестартами:
// приватный ключ и последний применённый набор вместе с узловым токеном.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	privateKeyFile = "node.key"
	stateFile      = "state.json"
)

var errNoDir = errors.New("state: каталог не задан")

type Store struct{ Dir string }

type Applied struct {
	ConfigVersion int64     `json:"config_version"`
	ETag          string    `json:"etag"`
	AppliedAt     time.Time `json:"applied_at"`
	Peers         int       `json:"peers"`
}

type NodeState struct {
	ServerID      string    `json:"server_id"`
	NodeToken     string    `json:"node_token"`
	TokenIssuedAt time.Time `json:"token_issued_at"`
	Applied       Applied   `json:"applied"`
}

// EnsureKey создаёт ключ при первом запуске и возвращает публичную половину.
// Повторный вызов не перевыпускает ключ: смена ключа требует правки сервера у
// администратора, поэтому «сгенерировать заново» — не восстановление, а поломка.
func (s *Store) EnsureKey() (string, bool, error) {
	if s.Dir == "" {
		return "", false, errNoDir
	}
	path := filepath.Join(s.Dir, privateKeyFile)
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return "", false, fmt.Errorf("state: права ключа: %w", err)
		}
		key, err := s.PrivateKey()
		if err != nil {
			return "", false, err
		}
		return key.PublicKey().String(), false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("state: ключ: %w", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", false, fmt.Errorf("state: генерация ключа: %w", err)
	}
	if err := writeAtomic(path, []byte(key.String())); err != nil {
		return "", false, err
	}
	return key.PublicKey().String(), true, nil
}

func (s *Store) PrivateKey() (wgtypes.Key, error) {
	if s.Dir == "" {
		return wgtypes.Key{}, errNoDir
	}
	raw, err := os.ReadFile(filepath.Join(s.Dir, privateKeyFile))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("state: чтение ключа: %w", err)
	}
	key, err := wgtypes.ParseKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("state: разбор ключа: %w", err)
	}
	return key, nil
}

// Load возвращает пустое состояние, если файла ещё нет (узел не зарегистрирован),
// и ошибку, если файл испорчен. Второе важно: молча начать с нуля значило бы
// отправить узел в enroll без bootstrap-токена и оставить без доступа.
func (s *Store) Load() (NodeState, error) {
	if s.Dir == "" {
		return NodeState{}, errNoDir
	}
	raw, err := os.ReadFile(filepath.Join(s.Dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return NodeState{}, nil
	}
	if err != nil {
		return NodeState{}, fmt.Errorf("state: чтение: %w", err)
	}
	var out NodeState
	if err := json.Unmarshal(raw, &out); err != nil {
		return NodeState{}, fmt.Errorf("state: файл состояния повреждён: %w", err)
	}
	return out, nil
}

func (s *Store) Save(ns NodeState) error {
	if s.Dir == "" {
		return errNoDir
	}
	raw, err := json.Marshal(ns)
	if err != nil {
		return fmt.Errorf("state: сериализация: %w", err)
	}
	return writeAtomic(filepath.Join(s.Dir, stateFile), raw)
}

// writeAtomic пишет через временный файл в том же каталоге: rename в пределах
// одной файловой системы атомарен, поэтому читатель видит либо старую версию,
// либо новую, но не половину. Права ставятся до записи секрета.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state: каталог: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("state: права каталога: %w", err)
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("state: временный файл: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("state: права: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("state: запись: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("state: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("state: закрытие: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("state: переименование: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Прогнать тесты**

Run: focused `make unit` по пакету с `-mod=readonly`, затем полные `unit` и `vet`.
Expected: PASS, шесть тестов `state`; полный прогон без новых падений.

- [ ] **Step 5: Коммит**

```bash
git add internal/nodeagent/state \
  docs/superpowers/plans/2026-10-27-novavpn-cycle-a3-node-runtime.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): состояние узла — ключ 0600 и атомарная запись"
```

---

### Task 7: HTTPS-клиент узла — enroll, desired с ETag, отчёты, ротация

**Files:**
- Create: `internal/nodeagent/api/client.go`
- Create: `internal/nodeagent/api/client_test.go`
- Modify: `docs/superpowers/plans/2026-10-27-novavpn-cycle-a3-node-runtime.md` — только фрагмент Task 7

**Interfaces:**
- Produces: `api.Config{BaseURL, CAFile, Env string; AllowInsecure bool; Timeout time.Duration}`,
  `api.New(Config) (*Client, error)`, `(*Client).SetToken(string)`,
  `(*Client).Enroll(ctx, bootstrap, publicKey string) (NodeToken, error)`,
  `(*Client).Desired(ctx, serverID, etag string) (DesiredSet, string, bool, error)`,
  `(*Client).Observed(ctx, serverID string, rep ObservedReport) error`,
  `(*Client).Heartbeat(ctx, serverID string, hb Heartbeat) error`,
  `(*Client).RotateToken(ctx, serverID string) (NodeToken, error)`,
  `api.StatusError`, `api.DesiredSet`, `api.DesiredPeer`, `api.EnrollRequest`, `api.ObservedReport`,
  `api.ObservedPeer`, `api.Heartbeat`, `api.NodeToken`.

Узел разговаривает с сервером только по документированному контракту `/internal/v1`
(`api-spec/openapi.yaml`). Клиент обязан проверять сертификат в проде, различать 304 от
ошибки, не читать бесконечное тело и не превращать неизмеренное в ноль.

- [ ] **Step 1: Написать падающие тесты**

Используй ровно этот исходник `internal/nodeagent/api/client_test.go` (R30):

```go
package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewValidatesConfig(t *testing.T) {
	bad := []struct {
		name string
		cfg  Config
	}{
		{"пустой адрес", Config{Env: "dev", AllowInsecure: true}},
		{"http вне dev", Config{BaseURL: "http://example.com", Env: "prod"}},
		{"пропуск проверки вне dev", Config{BaseURL: "https://example.com", Env: "prod", AllowInsecure: true}},
		{"пропуск проверки без окружения", Config{BaseURL: "https://example.com", AllowInsecure: true}},
		{"адрес без хоста", Config{BaseURL: "https:///x", Env: "prod"}},
		{"неподдерживаемая схема", Config{BaseURL: "ftp://example.com", Env: "prod"}},
		{"http в dev без пропуска проверки", Config{BaseURL: "http://127.0.0.1:1", Env: "dev"}},
		{"параметры в адресе", Config{BaseURL: "https://example.com/?a=1", Env: "prod"}},
		{"фрагмент в адресе", Config{BaseURL: "https://example.com/#f", Env: "prod"}},
		{"учётные данные в адресе", Config{BaseURL: "https://user:pass@example.com", Env: "prod"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("недопустимая конфигурация принята")
			}
		})
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:1", Env: "dev", AllowInsecure: true}); err != nil {
		t.Fatalf("dev-стенд по http отвергнут: %v", err)
	}
}

func TestNewDefaultsAndTrimsBaseURL(t *testing.T) {
	c, err := New(Config{BaseURL: "https://example.com/", Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://example.com" {
		t.Fatalf("базовый адрес %q; ожидался без завершающей косой черты", c.baseURL)
	}
	if c.hc.Timeout != 15*time.Second {
		t.Fatalf("таймаут %s; ожидалось 15s", c.hc.Timeout)
	}
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("минимальная версия TLS не 1.2")
	}
	c, err = New(Config{BaseURL: "https://example.com", Env: "prod", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if c.hc.Timeout != 3*time.Second {
		t.Fatalf("таймаут %s; ожидалось 3s", c.hc.Timeout)
	}
}

func TestNewRejectsCAFileWithoutCertificates(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("не сертификат"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BaseURL: "https://example.com", Env: "prod", CAFile: ca}); err == nil {
		t.Fatal("файл CA без сертификатов принят")
	}
	if _, err := New(Config{BaseURL: "https://example.com", Env: "prod", CAFile: filepath.Join(dir, "нет.pem")}); err == nil {
		t.Fatal("отсутствующий файл CA принят")
	}
}

func TestDesiredDistinguishesNotModified(t *testing.T) {
	var gotETag, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotETag = r.Header.Get("If-None-Match")
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/internal/v1/nodes/s/desired" {
			t.Errorf("путь запроса %q", r.URL.Path)
		}
		w.Header().Set("ETag", `"abc"`)
		if gotETag == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(`{"server_id":"s","config_version":1,"mtu":1420,"listen_port":51820,` +
			`"tunnel_address":"10.99.0.1/24","dns_servers":["10.99.0.1"],"keepalive_sec":25,` +
			`"peers":[{"public_key":"k","allowed_ips":["10.99.0.2/32"],` +
			`"expires_at":"2026-11-27T10:00:00Z","state":"active"}],` +
			`"measured_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("токен-узла")
	set, etag, notModified, err := c.Desired(context.Background(), "s", "")
	if err != nil || notModified || etag != `"abc"` || set.TunnelAddress != "10.99.0.1/24" {
		t.Fatalf("первый ответ: набор %+v, etag %q, notModified %v, ошибка %v", set, etag, notModified, err)
	}
	if gotETag != "" {
		t.Fatalf("первый запрос отправлен с If-None-Match %q", gotETag)
	}
	if gotAuth != "Bearer токен-узла" {
		t.Fatal("запрос отправлен без токена узла")
	}
	if set.ConfigVersion != 1 || set.MTU != 1420 || set.ListenPort != 51820 || set.KeepaliveSec != 25 {
		t.Fatalf("числовые поля набора: %+v", set)
	}
	if len(set.DNSServers) != 1 || set.DNSServers[0] != "10.99.0.1" {
		t.Fatalf("DNS-серверы %v", set.DNSServers)
	}
	if len(set.Peers) != 1 || set.Peers[0].State != "active" || set.Peers[0].PublicKey != "k" {
		t.Fatalf("пиры %+v", set.Peers)
	}
	if set.MeasuredAt.IsZero() || set.MeasuredAt.UTC().Format(time.RFC3339) != "2026-10-27T10:00:00Z" {
		t.Fatalf("measured_at %s", set.MeasuredAt)
	}
	_, etag, notModified, err = c.Desired(context.Background(), "s", `"abc"`)
	if err != nil || !notModified || etag != `"abc"` {
		t.Fatalf("второй ответ: etag %q, notModified %v, ошибка %v", etag, notModified, err)
	}
	if gotETag != `"abc"` {
		t.Fatalf("второй запрос отправлен с If-None-Match %q", gotETag)
	}
}

func TestDesiredRejectsBrokenJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server_id":`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	if _, _, _, err := c.Desired(context.Background(), "s", ""); err == nil {
		t.Fatal("битый JSON принят за набор")
	}
}

func TestStatusErrorCarriesCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"нет"}}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	_, _, _, err := c.Desired(context.Background(), "s", "")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 401 || se.Code != "unauthenticated" {
		t.Fatalf("ошибка %v; ожидался StatusError 401 unauthenticated", err)
	}
}

func TestTLSVerificationAndCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte(`{"server_id":"s","config_version":1,"mtu":1420,"listen_port":51820,` +
			`"tunnel_address":"10.99.0.1/24","dns_servers":[],"keepalive_sec":25,"peers":[],` +
			`"measured_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	if _, _, _, err := mustClient(t, Config{BaseURL: srv.URL, Env: "prod"}).Desired(context.Background(), "s", ""); err == nil {
		t.Fatal("самоподписанный сертификат принят без CA")
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o600); err != nil {
		t.Fatal(err)
	}
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "prod", CAFile: ca})
	if _, _, _, err := c.Desired(context.Background(), "s", ""); err != nil {
		t.Fatalf("файл CA не применён: %v", err)
	}
}

func TestEnrollSendsNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/nodes/enroll" {
			t.Errorf("запрос %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("enroll отправлен с заголовком авторизации")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type enroll %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept enroll %q", r.Header.Get("Accept"))
		}
		var in struct {
			BootstrapToken string `json:"bootstrap_token"`
			PublicKey      string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("тело enroll не разобрано: %v", err)
		}
		if in.BootstrapToken != "стартовый" || in.PublicKey != "ключ" {
			t.Errorf("тело enroll: стартовый токен %q, ключ %q", in.BootstrapToken, in.PublicKey)
		}
		_, _ = w.Write([]byte(`{"server_id":"srv","node_token":"новый-токен"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("прежний-токен")
	nt, err := c.Enroll(context.Background(), "стартовый", "ключ")
	if err != nil {
		t.Fatal(err)
	}
	if nt.ServerID != "srv" || nt.NodeToken != "новый-токен" {
		t.Fatalf("ответ enroll: сервер %q", nt.ServerID)
	}
}

func TestReportExpects204(t *testing.T) {
	status := http.StatusNoContent
	var seen []string
	var hb, obs map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer токен-узла" {
			t.Error("отчёт отправлен без токена узла")
		}
		if r.URL.Path == "/internal/v1/nodes/srv/heartbeat" {
			if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
				t.Errorf("тело heartbeat не разобрано: %v", err)
			}
		}
		if r.URL.Path == "/internal/v1/nodes/srv/observed" {
			if err := json.NewDecoder(r.Body).Decode(&obs); err != nil {
				t.Errorf("тело observed не разобрано: %v", err)
			}
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("токен-узла")
	rep := ObservedReport{
		ConfigVersion: 3,
		Peers:         []ObservedPeer{{PublicKey: "k", RxBytes: 1, TxBytes: 2}},
	}
	if err := c.Observed(context.Background(), "srv", rep); err != nil {
		t.Fatalf("отчёт отклонён: %v", err)
	}
	if len(seen) != 1 || seen[0] != "POST /internal/v1/nodes/srv/observed" {
		t.Fatalf("запросы %v", seen)
	}
	peers, ok := obs["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("пиры observed %v; ожидался массив из одного элемента", obs["peers"])
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		t.Fatalf("пиер observed %v", peers[0])
	}
	if hs, exists := peer["latest_handshake"]; !exists || hs != nil {
		t.Fatalf("latest_handshake %v; ожидался ключ со значением null", hs)
	}
	load := 0.5
	if err := c.Heartbeat(context.Background(), "srv", Heartbeat{
		AgentVersion: "1.0", AgentUptimeSec: 60, Load1: &load, AppliedConfigVersion: 3,
	}); err != nil {
		t.Fatalf("heartbeat отклонён: %v", err)
	}
	if len(seen) != 2 || seen[1] != "POST /internal/v1/nodes/srv/heartbeat" {
		t.Fatalf("запросы %v", seen)
	}
	if _, ok := hb["cpu_pct"]; !ok || hb["cpu_pct"] != nil {
		t.Fatalf("cpu_pct %v; ожидался ключ со значением null", hb["cpu_pct"])
	}
	if hb["load1"] != 0.5 {
		t.Fatalf("load1 %v; ожидалось 0.5", hb["load1"])
	}
	status = http.StatusOK
	err := c.Heartbeat(context.Background(), "srv", Heartbeat{
		AgentVersion: "1.0", AgentUptimeSec: 60, Load1: &load, AppliedConfigVersion: 3,
	})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 200 {
		t.Fatalf("ответ 200 принят за успешный heartbeat: %v", err)
	}
	if err.Error() != "api: отказ 200" {
		t.Fatalf("текст ошибки %q; ожидался %q", err.Error(), "api: отказ 200")
	}
	err = c.Observed(context.Background(), "srv", rep)
	if !errors.As(err, &se) || se.Status != 200 {
		t.Fatalf("ответ 200 принят за успешный отчёт: %v", err)
	}
}

func TestRotateTokenSendsCurrentToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/nodes/srv/token/rotate" {
			t.Errorf("запрос %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"server_id":"srv","node_token":"следующий"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("текущий")
	nt, err := c.RotateToken(context.Background(), "srv")
	if err != nil {
		t.Fatal(err)
	}
	if nt.ServerID != "srv" || nt.NodeToken != "следующий" {
		t.Fatalf("ответ ротации: сервер %q, токен %q", nt.ServerID, nt.NodeToken)
	}
	if gotAuth != "Bearer текущий" {
		t.Fatal("ротация отправлена не с текущим токеном")
	}
}

func TestResponseBodyLimit(t *testing.T) {
	big := strings.Repeat("а", 1<<20)
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"server_id":"` + big + `"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	if _, _, _, err := c.Desired(context.Background(), "s", ""); err == nil {
		t.Fatal("тело больше 1 МиБ принято")
	}
	status = http.StatusUnauthorized
	_, _, _, err := c.Desired(context.Background(), "s", "")
	if err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("ошибка ошибочного ответа %v; ожидалось превышение предела", err)
	}
	var se *StatusError
	if errors.As(err, &se) {
		t.Fatalf("предел тела подменён StatusError: %v", err)
	}
}

func TestDesiredEscapesServerID(t *testing.T) {
	var escaped string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped = r.URL.EscapedPath()
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte(`{"server_id":"a/b","config_version":1,"mtu":1420,"listen_port":51820,` +
			`"tunnel_address":"10.99.0.1/24","dns_servers":[],"keepalive_sec":25,"peers":[],` +
			`"measured_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	if _, _, _, err := c.Desired(context.Background(), "a/b", ""); err != nil {
		t.Fatal(err)
	}
	if escaped != "/internal/v1/nodes/a%2Fb/desired" {
		t.Fatalf("путь запроса %q; идентификатор сервера не закодирован", escaped)
	}
}

func TestRedirectRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/other", http.StatusFound)
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	_, _, _, err := c.Desired(context.Background(), "s", "")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusFound {
		t.Fatalf("перенаправление не отвергнуто: %v", err)
	}
}

func TestTokenEndpointsRequireOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("текущий")
	var se *StatusError
	if _, err := c.Enroll(context.Background(), "стартовый", "ключ"); !errors.As(err, &se) || se.Status != http.StatusNoContent {
		t.Fatalf("enroll принял 204: %v", err)
	}
	if _, err := c.RotateToken(context.Background(), "srv"); !errors.As(err, &se) || se.Status != http.StatusNoContent {
		t.Fatalf("ротация приняла 204: %v", err)
	}
}
```

R30: диагностика тестов в плане была английской; здесь она русская. Строка
`_ = x509.NewCertPool()` и импорт `crypto/x509` из плана удалены: пул там создавался и
выбрасывался, то есть ничего не проверял. Литеральных ключей WireGuard в этом пакете нет.

- [ ] **Step 2: Прогнать и убедиться, что не компилируется**

Run: сосредоточенный `make unit` по пакету `internal/nodeagent/api` с `-mod=readonly`.
Expected: FAIL — `undefined: New`, `undefined: Config`, `undefined: Client`.

- [ ] **Step 3: Реализовать `client.go`**

Требования к `New` (R31):

- `BaseURL` обязателен; разбирается через `url.Parse`; завершающая `/` срезается.
- Адрес не должен содержать query, fragment или userinfo: такой `BaseURL` — ошибка.
- Редиректы не выполняются: `CheckRedirect` возвращает `http.ErrUseLastResponse`;
  ответ `3xx` — `*StatusError`.
- Вне dev допустим только `https`: `http` принимается лишь при `Env == "dev"` и
  `AllowInsecure == true`.
- `AllowInsecure == true` при `Env != "dev"` — ошибка конфигурации.
- `CAFile`: файл читается, `x509.NewCertPool` + `AppendCertsFromPEM`; `false` — ошибка.
  Отсутствующий файл — ошибка с `%w`.
- `MinVersion: tls.VersionTLS12`; `AllowInsecure` ставит `InsecureSkipVerify`.
- `Timeout` по умолчанию 15 с (при `<= 0`).

Дословно — тип клиента, конфигурация и тип ошибки:

```go
// maxBody ограничивает ответ: сломанный сервер не вынудит узел вычитать гигабайты.
const maxBody = 1 << 20

const defaultTimeout = 15 * time.Second

type Config struct {
	BaseURL       string
	CAFile        string
	Env           string
	AllowInsecure bool
	Timeout       time.Duration
}

type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

type StatusError struct {
	Status int
	Code   string
}

func (e *StatusError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("api: отказ %d", e.Status)
	}
	return fmt.Sprintf("api: отказ %d (%s)", e.Status, e.Code)
}
```

`SetToken` сохраняет токен для последующих запросов; вызывается из одного горутины
цикла (задача 8), поэтому мьютекс не нужен.

`do` (R32):

```go
func (c *Client) do(ctx context.Context, method, path string, in, out any, token string, header http.Header) (int, http.Header, error)
```

- Тело `in` кодируется JSON; заголовки `Accept: application/json`,
  `Content-Type: application/json` при теле, `Authorization: Bearer <token>` при непустом
  токене, затем заголовки из `header`.
- Ответ читается через `io.LimitReader` не более чем `maxBody+1` байт; больше
  `maxBody` — ошибка, тело не разбирается.
- `304` — не ошибка: статус и заголовки возвращаются, тело не читается и `out` не
  разбирается.
- `204` — тело не читается: статус и заголовки возвращаются, `out` не разбирается.
- Статус `>= 300` (кроме обработанного выше `304`) — `*StatusError`; `Code` берётся из
  `{"error":{"code":...}}`, при неразбираемом теле остаётся пустым.
- Иной статус с `out != nil` — разбор JSON; ошибка разбора возвращается, а не глотается.

Методы:

- `Enroll`: `POST /internal/v1/nodes/enroll`, тело `EnrollRequest`, токен не передаётся
  (даже если `SetToken` уже вызывался), ответ — `NodeToken`; требуется ровно `200`,
  иной код — `*StatusError`.
- `Desired`: `GET /internal/v1/nodes/{server_id}/desired`; при непустом `etag` —
  заголовок `If-None-Match`; при 304 — `(DesiredSet{}, etag из заголовка, true, nil)`,
  иначе разобранный набор и `etag` из заголовка.
- `Observed`, `Heartbeat`: `POST` соответственно `/observed` и `/heartbeat` с текущим
  токеном; ожидается ровно `204`; другой успешный код — `*StatusError` с пустым `Code`.
- `RotateToken`: `POST /internal/v1/nodes/{server_id}/token/rotate` с текущим токеном,
  ответ `NodeToken`; требуется ровно `200`, иной код — `*StatusError`; сам клиент токен
  не подменяет — это решение цикла (задача 8).
- `serverID` в пути кодируется `url.PathEscape`.

Типы ответов повторяют JSON сервера один в один:

```go
type EnrollRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	PublicKey      string `json:"public_key"`
}

type NodeToken struct {
	ServerID  string `json:"server_id"`
	NodeToken string `json:"node_token"`
}

type DesiredSet struct {
	ServerID      string        `json:"server_id"`
	ConfigVersion int64         `json:"config_version"`
	MTU           int           `json:"mtu"`
	ListenPort    int           `json:"listen_port"`
	TunnelAddress string        `json:"tunnel_address"`
	DNSServers    []string      `json:"dns_servers"`
	KeepaliveSec  int           `json:"keepalive_sec"`
	Peers         []DesiredPeer `json:"peers"`
	MeasuredAt    time.Time     `json:"measured_at"`
}

type DesiredPeer struct {
	PublicKey  string    `json:"public_key"`
	AllowedIPs []string  `json:"allowed_ips"`
	ExpiresAt  time.Time `json:"expires_at"`
	State      string    `json:"state"`
}

type ObservedReport struct {
	ConfigVersion    int64          `json:"config_version"`
	InterfaceRxBytes int64          `json:"interface_rx_bytes"`
	InterfaceTxBytes int64          `json:"interface_tx_bytes"`
	Peers            []ObservedPeer `json:"peers"`
}

type ObservedPeer struct {
	PublicKey       string     `json:"public_key"`
	LatestHandshake *time.Time `json:"latest_handshake"`
	RxBytes         int64      `json:"rx_bytes"`
	TxBytes         int64      `json:"tx_bytes"`
}

type Heartbeat struct {
	AgentVersion         string   `json:"agent_version"`
	AgentUptimeSec       int64    `json:"agent_uptime_sec"`
	Load1                *float64 `json:"load1"`
	CPUPct               *float64 `json:"cpu_pct"`
	AppliedConfigVersion int64    `json:"applied_config_version"`
	Stale                bool     `json:"stale"`
}
```

`State` в `DesiredPeer` не отбрасывается: сервер его отдаёт, и без него узел не отличит
активный ключ от старого при ротации (задача 2). `LatestHandshake`, `Load1`, `CPUPct` —
указатели: «не измеряли» приходит как `null`, и ноль вместо `null` был бы ложью
(ADR-006). Тексты ошибок русские с префиксом `api:`; токен и содержимое файлов в тексты
ошибок не попадают.

- [ ] **Step 4: Прогнать тесты**

Run: сосредоточенный `make unit` по пакету, затем полные `unit` и `vet`.
Expected: PASS, четырнадцать тестов; полный прогон без новых падений, `go.mod`/`go.sum`
не менялись (новых внешних зависимостей нет).

- [ ] **Step 5: Коммит**

```bash
git add internal/nodeagent/api docs/superpowers/plans/2026-10-27-novavpn-cycle-a3-node-runtime.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): HTTPS-клиент узла с ETag, отчётами и проверкой сертификата"
```

Один новый локальный коммит, без amend и push.

---

### Task 8: Цикл узла — опрос, применение, отчёты, `stale`, ротация токена

**Files:**
- Create: `internal/nodeagent/runtime/runner.go`, `internal/nodeagent/runtime/runner_test.go`

**Interfaces:**
- Consumes: `api.Client`, `wg.Applier`, `state.Store`.
- Produces: `runtime.API`, `runtime.Applier`, `runtime.Store` (интерфейсы),
  `runtime.Runner`, `(*Runner).Step(ctx) error`, `(*Runner).Run(ctx) error`.

- [ ] **Step 1: Написать падающие тесты**

`internal/nodeagent/runtime/runner_test.go` — fake-реализации и шесть сценариев:

```go
package runtime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/novavpn/novavpn/internal/nodeagent/api"
	"github.com/novavpn/novavpn/internal/nodeagent/state"
	"github.com/novavpn/novavpn/internal/nodeagent/wg"
)

type fakeAPI struct {
	set         api.DesiredSet
	etag        string
	notModified bool
	desiredErr  error
	observed    int
	heartbeats  []api.Heartbeat
	rotated     int
	etags       []string
}

func (f *fakeAPI) Desired(_ context.Context, _ string, etag string) (api.DesiredSet, string, bool, error) {
	f.etags = append(f.etags, etag)
	return f.set, f.etag, f.notModified, f.desiredErr
}
func (f *fakeAPI) Observed(context.Context, string, api.ObservedReport) error {
	f.observed++
	return nil
}
func (f *fakeAPI) Heartbeat(_ context.Context, _ string, hb api.Heartbeat) error {
	f.heartbeats = append(f.heartbeats, hb)
	return nil
}
func (f *fakeAPI) RotateToken(context.Context, string) (api.NodeToken, error) {
	f.rotated++
	return api.NodeToken{ServerID: "s", NodeToken: "new"}, nil
}

type fakeApplier struct {
	calls int
	err   error
}

func (f *fakeApplier) Apply(wg.Target) (wg.ApplyResult, error) {
	f.calls++
	return wg.ApplyResult{}, f.err
}

type fakeStore struct {
	ns    state.NodeState
	saves int
}

func (f *fakeStore) Load() (state.NodeState, error) { return f.ns, nil }
func (f *fakeStore) Save(ns state.NodeState) error  { f.ns = ns; f.saves++; return nil }
func (f *fakeStore) PrivateKey() (wgtypes.Key, error) {
	return wgtypes.GeneratePrivateKey()
}

func newRunner(a *fakeAPI, ap *fakeApplier, s *fakeStore) *Runner {
	return &Runner{
		API: a, Applier: ap, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Iface: "wg0", Interval: 25 * time.Second, TokenTTL: 24 * time.Hour,
		Version: "test", Now: time.Now, started: time.Now(),
	}
}

func validSet() api.DesiredSet {
	return api.DesiredSet{
		ServerID: "s", ConfigVersion: 7, MTU: 1420, ListenPort: 51820,
		TunnelAddress: "10.99.0.1/24", DNSServers: []string{"10.99.0.1"}, KeepaliveSec: 25,
		Peers: []api.DesiredPeer{{
			PublicKey:  "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
			AllowedIPs: []string{"10.99.0.2/32"}, State: "active",
		}},
	}
}

// TestStepFirstPollIgnoresStoredETag — сохранённый ETag относится к прошлому
// запуску. После перезагрузки интерфейс пуст, и ответ 304 оставил бы узел без
// пиеров до следующего изменения набора на сервере. Первый опрос обязан идти
// без ETag, второй — с полученным.
func TestStepFirstPollIgnoresStoredETag(t *testing.T) {
	a := &fakeAPI{set: validSet(), etag: `"e2"`}
	ap := &fakeApplier{}
	s := &fakeStore{ns: state.NodeState{
		ServerID: "s", NodeToken: "t", TokenIssuedAt: time.Now(),
		Applied: state.Applied{ConfigVersion: 6, ETag: `"e1"`},
	}}
	r := newRunner(a, ap, s)
	for i := 0; i < 2; i++ {
		if err := r.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.etags) != 2 || a.etags[0] != "" || a.etags[1] != `"e2"` {
		t.Fatalf("etags = %q, want [\"\", \"e2\"]", a.etags)
	}
	if ap.calls != 2 {
		t.Fatalf("apply calls = %d, want 2: полный набор обязан примениться на первом опросе", ap.calls)
	}
}

func TestStepAppliesAndSaves(t *testing.T) {
	a := &fakeAPI{set: validSet(), etag: `"e1"`}
	ap := &fakeApplier{}
	s := &fakeStore{ns: state.NodeState{ServerID: "s", NodeToken: "t", TokenIssuedAt: time.Now()}}
	if err := newRunner(a, ap, s).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ap.calls != 1 || a.observed != 1 || s.ns.Applied.ConfigVersion != 7 || s.ns.Applied.ETag != `"e1"` {
		t.Fatalf("calls=%d observed=%d state=%+v", ap.calls, a.observed, s.ns.Applied)
	}
	if len(a.heartbeats) != 1 || a.heartbeats[0].Stale {
		t.Fatalf("heartbeats = %+v", a.heartbeats)
	}
}

func TestStepOnNotModifiedDoesNotTouchDevice(t *testing.T) {
	a := &fakeAPI{notModified: true, etag: `"e1"`}
	ap := &fakeApplier{}
	s := &fakeStore{ns: state.NodeState{ServerID: "s", NodeToken: "t", TokenIssuedAt: time.Now()}}
	if err := newRunner(a, ap, s).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ap.calls != 0 || a.observed != 0 || len(a.heartbeats) != 1 {
		t.Fatalf("calls=%d observed=%d hb=%d", ap.calls, a.observed, len(a.heartbeats))
	}
}

func TestStepReportsStaleWhenDesiredFails(t *testing.T) {
	a := &fakeAPI{desiredErr: errors.New("нет сети")}
	ap := &fakeApplier{}
	s := &fakeStore{ns: state.NodeState{ServerID: "s", NodeToken: "t", TokenIssuedAt: time.Now()}}
	if err := newRunner(a, ap, s).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ap.calls != 0 || len(a.heartbeats) != 1 || !a.heartbeats[0].Stale {
		t.Fatalf("calls=%d heartbeats=%+v", ap.calls, a.heartbeats)
	}
}

func TestStepDoesNotReportObservedWhenApplyFails(t *testing.T) {
	a := &fakeAPI{set: validSet(), etag: `"e1"`}
	ap := &fakeApplier{err: errors.New("нет прав")}
	s := &fakeStore{ns: state.NodeState{ServerID: "s", NodeToken: "t", TokenIssuedAt: time.Now()}}
	if err := newRunner(a, ap, s).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.observed != 0 || s.ns.Applied.ConfigVersion != 0 {
		t.Fatalf("observed=%d state=%+v", a.observed, s.ns.Applied)
	}
}

func TestStepRotatesTokenAfterTTL(t *testing.T) {
	a := &fakeAPI{notModified: true, etag: `"e1"`}
	ap := &fakeApplier{}
	s := &fakeStore{ns: state.NodeState{ServerID: "s", NodeToken: "old", TokenIssuedAt: time.Now().Add(-25 * time.Hour)}}
	if err := newRunner(a, ap, s).Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.rotated != 1 || s.ns.NodeToken != "new" {
		t.Fatalf("rotated=%d token=%q", a.rotated, s.ns.NodeToken)
	}
}
```

- [ ] **Step 2: Прогнать и убедиться, что не компилируется**

Run: `make unit`
Expected: FAIL — `undefined: Runner`.

- [ ] **Step 3: Реализовать `runner.go` (дословный исходник)**

`delay` задаёт только ожидание между шагами: при 25 с и jitter ±10 % оно не превышает
27,5 с. В бюджет 2,5 с для отзыва входят остаток текущего `Step`, доставка, обработка
и применение следующего набора. Длительность `delay` не доказывает SLA: в runtime/E2E
нужен сквозной замер от фиксации отзыва сразу после снимка desired до удаления пиера
при максимальном jitter и контролируемых задержках ответа и применения (§4.3).

```go
// Package runtime — цикл жизни узла: получить desired set, применить дельту,
// отчитаться, пережить недоступность API. Никакой сети и никакого netlink здесь
// нет: оба спрятаны за интерфейсами, поэтому весь цикл проверяется на fake.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/novavpn/novavpn/internal/nodeagent/api"
	"github.com/novavpn/novavpn/internal/nodeagent/state"
	"github.com/novavpn/novavpn/internal/nodeagent/wg"
)

type API interface {
	Desired(ctx context.Context, serverID, etag string) (api.DesiredSet, string, bool, error)
	Observed(ctx context.Context, serverID string, rep api.ObservedReport) error
	Heartbeat(ctx context.Context, serverID string, hb api.Heartbeat) error
	RotateToken(ctx context.Context, serverID string) (api.NodeToken, error)
}

type Applier interface {
	Apply(t wg.Target) (wg.ApplyResult, error)
}

type Store interface {
	Load() (state.NodeState, error)
	Save(state.NodeState) error
	PrivateKey() (wgtypes.Key, error)
}

type Runner struct {
	API       API
	Applier   Applier
	Store     Store
	Log       *slog.Logger
	Iface     string
	Interval  time.Duration
	TokenTTL  time.Duration
	Version   string
	Now       func() time.Time
	started   time.Time
	// reconciled — набор уже применён в этом процессе. До первого применения
	// сохранённый ETag не отправляется: он описывает прошлый запуск, а интерфейс
	// после перезагрузки может быть пуст.
	reconciled bool
}

func (r *Runner) Run(ctx context.Context) error {
	if r.started.IsZero() {
		r.started = r.Now()
	}
	for {
		if err := r.Step(ctx); err != nil {
			r.Log.Error("шаг узла не выполнен", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.delay()):
		}
	}
}

// delay — ожидание 25 с ±10 %, до 27,5 с; это не сквозное время отзыва (§4.3).
func (r *Runner) delay() time.Duration {
	base := r.Interval
	if base <= 0 {
		base = 25 * time.Second
	}
	return base + time.Duration(rand.Int64N(int64(base)/5)) - base/10
}

func (r *Runner) Step(ctx context.Context) error {
	st, err := r.Store.Load()
	if err != nil {
		return err
	}
	if st.ServerID == "" || st.NodeToken == "" {
		return errors.New("runtime: узел не зарегистрирован: выполните enroll")
	}
	sentETag := st.Applied.ETag
	if !r.reconciled {
		sentETag = ""
	}
	set, etag, notModified, err := r.API.Desired(ctx, st.ServerID, sentETag)
	if err != nil {
		r.Log.Warn("desired set недоступен, держим последний набор", "error", err)
		r.sendHeartbeat(ctx, st, true)
		return nil
	}
	if notModified {
		r.reconciled = true
		r.sendHeartbeat(ctx, st, false)
		return r.maybeRotate(ctx, &st)
	}
	key, err := r.Store.PrivateKey()
	if err != nil {
		return err
	}
	target, err := targetFrom(set, key.String())
	if err != nil {
		return err
	}
	res, err := r.Applier.Apply(target)
	if err != nil {
		r.Log.Error("применение набора не удалось", "error", err)
		r.sendHeartbeat(ctx, st, false)
		return nil
	}
	r.reconciled = true
	st.Applied = state.Applied{
		ConfigVersion: set.ConfigVersion, ETag: etag, AppliedAt: r.Now().UTC(), Peers: len(set.Peers),
	}
	if err := r.Store.Save(st); err != nil {
		return err
	}
	if err := r.API.Observed(ctx, st.ServerID, report(set.ConfigVersion, res.Before)); err != nil {
		r.Log.Warn("отчёт observed не принят", "error", err)
	}
	r.sendHeartbeat(ctx, st, false)
	return r.maybeRotate(ctx, &st)
}

// maybeRotate меняет узловой токен заранее, а не после отказа: отозванный токен
// не даёт выполнить ротацию, и узел остался бы без доступа до ручного enroll.
func (r *Runner) maybeRotate(ctx context.Context, st *state.NodeState) error {
	ttl := r.TokenTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if r.Now().Sub(st.TokenIssuedAt) < ttl {
		return nil
	}
	tok, err := r.API.RotateToken(ctx, st.ServerID)
	if err != nil {
		return fmt.Errorf("runtime: ротация токена: %w", err)
	}
	st.NodeToken = tok.NodeToken
	st.TokenIssuedAt = r.Now().UTC()
	return r.Store.Save(*st)
}

func (r *Runner) sendHeartbeat(ctx context.Context, st state.NodeState, stale bool) {
	hb := api.Heartbeat{
		AgentVersion: r.Version, AppliedConfigVersion: st.Applied.ConfigVersion, Stale: stale,
		AgentUptimeSec: int64(r.Now().Sub(r.started).Seconds()),
		Load1:          load1(),
		// CPUPct остаётся null: честный процент требует окна между двумя замерами
		// /proc/stat, а подставлять «примерно» запрещено ADR-006.
	}
	if err := r.API.Heartbeat(ctx, st.ServerID, hb); err != nil {
		r.Log.Warn("heartbeat не принят", "error", err)
	}
}

func targetFrom(set api.DesiredSet, privateKey string) (wg.Target, error) {
	addr, err := netip.ParsePrefix(set.TunnelAddress)
	if err != nil {
		return wg.Target{}, fmt.Errorf("runtime: tunnel_address %q: %w", set.TunnelAddress, err)
	}
	peers := make([]wg.TargetPeer, 0, len(set.Peers))
	for _, p := range set.Peers {
		ips := make([]netip.Prefix, 0, len(p.AllowedIPs))
		for _, raw := range p.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return wg.Target{}, fmt.Errorf("runtime: allowed ip %q: %w", raw, err)
			}
			ips = append(ips, prefix)
		}
		kind := wg.PeerKind(p.State)
		if kind != wg.StateActive && kind != wg.StateRotatingOldKey {
			return wg.Target{}, fmt.Errorf("runtime: пиер %s: неизвестное состояние %q", p.PublicKey, p.State)
		}
		peers = append(peers, wg.TargetPeer{
			PublicKey: p.PublicKey, AllowedIPs: ips, KeepaliveSec: set.KeepaliveSec, State: kind,
		})
	}
	return wg.Target{
		PrivateKey: privateKey, ListenPort: set.ListenPort, MTU: set.MTU,
		TunnelAddress: addr, Peers: peers,
	}, nil
}

func report(version int64, before wg.LiveState) api.ObservedReport {
	out := api.ObservedReport{
		ConfigVersion: version, InterfaceRxBytes: before.IfaceRxBytes,
		InterfaceTxBytes: before.IfaceTxBytes, Peers: make([]api.ObservedPeer, 0, len(before.Peers)),
	}
	for _, p := range before.Peers {
		var hs *time.Time
		if !p.LastHandshake.IsZero() {
			t := p.LastHandshake.UTC()
			hs = &t
		}
		out.Peers = append(out.Peers, api.ObservedPeer{
			PublicKey: p.PublicKey, LatestHandshake: hs, RxBytes: p.RxBytes, TxBytes: p.TxBytes,
		})
	}
	slices.SortFunc(out.Peers, func(a, b api.ObservedPeer) int { return strings.Compare(a.PublicKey, b.PublicKey) })
	return out
}

func load1() *float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	return &v
}
```

Добавить импорт `slices` к списку выше; в блоке кода он пропущен намеренно, чтобы
исполнитель не забыл: без него `report` не компилируется.

Остаточное ограничение, которое надо записать в задаче 13 (спецификация §13) и в
`docs/testing-status.md` (задача 18), а не «починить» здесь: если набор на сервере не
менялся, узел получает 304 и устройство не трогает. Внешняя правка интерфейса руками при
живом агенте поэтому живёт до следующего изменения набора. Проверять живое состояние
каждый цикл — это уже другой режим (полный опрос вместо ETag) и лишний netlink каждые
25 с; в A-3 его нет.

- [ ] **Step 4: Прогнать тесты**

Run: `make unit`
Expected: PASS, включая шесть тестов `Step`.

- [ ] **Step 5: Коммит**

```bash
git add internal/nodeagent/runtime
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): цикл узла — опрос 25 с, применение, stale и ротация токена"
```

---

### Task 9: Бинарник — `init`, `enroll`, `run`, `status`

**Files:**
- Create: `services/node-agent/cmd/novavpn-node-agent/main.go`,
  `services/node-agent/cmd/novavpn-node-agent/main_test.go`
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§4.4 —
  имена env агента)

**Interfaces:**
- Consumes: `state.Store`, `api.New`, `runtime.Runner`, `wg.Open`, `wg.Applier`, `wg.Netlink`.
- Produces: исполняемый файл с командами и env-конфигурацией.

- [ ] **Step 1: Написать падающий тест**

`main_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestRunRejectsUnknownAndMissingCommand(t *testing.T) {
	env := func(string) string { return "" }
	if err := run(nil, env, strings.NewReader("")); err == nil {
		t.Fatal("empty args accepted")
	}
	if err := run([]string{"nope"}, env, strings.NewReader("")); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestRunRefusesInsecureOutsideDev(t *testing.T) {
	env := map[string]string{
		"NOVAVPN_NODE_ENV":                "prod",
		"NOVAVPN_NODE_ALLOW_INSECURE_API": "true",
		"NOVAVPN_NODE_API_URL":            "https://api.example.com",
	}
	err := run([]string{"status"}, func(k string) string { return env[k] }, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("err = %v", err)
	}
}

func TestInitPrintsPublicKey(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"NOVAVPN_NODE_STATE_DIR": dir}
	if err := run([]string{"init"}, func(k string) string { return env[k] }, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
}
```

Тест `TestInitPrintsPublicKey` проверяет только успешный код: вывод идёт в `os.Stdout`,
и подменять его ради одного теста не стоит — публичный ключ проверяется тестом
`state.EnsureKey`, а формат вывода — глазами в Step 4.

- [ ] **Step 2: Прогнать и убедиться, что не компилируется**

Run: `make unit`
Expected: FAIL — `undefined: run`.

- [ ] **Step 3: Реализовать `main.go` (схема; обязательные требования)**

- `run(args []string, getenv func(string) string, stdin io.Reader) error`; `main` печатает
  ошибку в stderr и выходит с кодом 1.
- Конфигурация из env: `NOVAVPN_NODE_ENV` (по умолчанию `prod`),
  `NOVAVPN_NODE_API_URL`, `NOVAVPN_NODE_STATE_DIR` (по умолчанию
  `/var/lib/novavpn-node`), `NOVAVPN_NODE_CA_FILE`,
  `NOVAVPN_NODE_ALLOW_INSECURE_API`, `NOVAVPN_NODE_INTERFACE` (по умолчанию `wg0`),
  `NOVAVPN_NODE_POLL_INTERVAL` (по умолчанию `25s`). Неизвестный env не читается —
  секретов в argv нет ни у одной команды. Префикс `NOVAVPN_NODE_` отличается от
  спецификации §4.4 (`NOVAVPN_ENV`, `NOVAVPN_API_CA_FILE`): агент и API живут на разных
  машинах и могут читать общий env-файл, а одинаковые имена связали бы их значения.
  Правка §4.4 входит в коммит Step 5 вместе с кодом, чтобы спецификация и бинарник не
  расходились.
- `init`: `Store.EnsureKey`, печатает ровно две строки: `public_key <BASE64>` и
  «передайте его администратору при создании сервера». Первая строка — машинный
  формат: на неё опирается `scripts/e2e.sh` (`sed -n 's/^public_key //p'`), поэтому
  префикс, регистр и один пробел фиксированы.
- `enroll`: читает bootstrap-токен из stdin (обрезает `\r\n`), берёт публичный ключ из
  состояния, вызывает `Enroll`, сохраняет `ServerID`, `NodeToken`, `TokenIssuedAt`.
  Пустой токен — ошибка до сетевого вызова.
- `run`: `signal.NotifyContext` (SIGINT, SIGTERM), `wg.Open`, `wg.Applier{Link:
  wg.Netlink{}, Device: client, Iface: cfg.Iface}`, `store := &state.Store{Dir:
  cfg.StateDir}` (методы `Load`/`Save`/`PrivateKey` объявлены на `*Store`, задача 6),
  загрузка `NodeState`, `SetToken`,
  затем `runtime.Runner` со **всеми** полями (у структуры нет конструктора, и
  пропущенные `Log`/`Now` дают панику на первом же шаге):
  `API: client, Applier: applier, Store: store, Iface: cfg.Iface,
  Interval: cfg.Interval, TokenTTL: 24 * time.Hour, Version: version,
  Now: time.Now, Log: logger`, где `logger` — `slog.New(slog.NewJSONHandler(os.Stderr,
  nil))`, `cfg.Interval` — разобранный `NOVAVPN_NODE_POLL_INTERVAL`, `version` —
  переменная, заполняемая `-ldflags "-X main.version=…"` при сборке (по умолчанию
  `"dev"`); последний шаг — `Runner.Run(ctx)`. Код выхода при отмене контекста — 0.
- `status`: печатает `server_id`, `applied.config_version`, `applied.peers`,
  `applied.applied_at`, `token_issued_at`; отсутствие состояния — понятная ошибка
  «узел не инициализирован».
- `--help` и пустая команда — usage со всеми четырьмя командами, код 0 для `--help`.

- [ ] **Step 4: Собрать и прогнать**

Run: `make unit && make vet`
Expected: PASS. Затем вручную:
`make unit` собирает пакеты; для проверки usage — `docker run --rm … go run ./services/node-agent/cmd/novavpn-node-agent --help`
через тот же контейнер (`make node-help` добавляется в задаче 10).

- [ ] **Step 5: Коммит**

```bash
git add services/node-agent docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): бинарник агента — init, enroll, run, status"
```

---

### Task 10: Образы и dev-сервис

**Files:**
- Create: `Dockerfile.api`, `Dockerfile.node-agent`
- Modify: `infrastructure/docker/docker-compose.dev.yml`
- Modify: `Makefile` (цели `api-image`, `node-image`, `node-help`)

**Interfaces:**
- Produces: образы `novavpn-api:dev`, `novavpn-node-agent:dev`; профиль compose `node`.

- [ ] **Step 1: `Dockerfile.api`**

```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/novavpn-api ./services/api/cmd/novavpn-api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/novavpn-api /usr/local/bin/novavpn-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/novavpn-api"]
CMD ["serve"]
```

- [ ] **Step 2: `Dockerfile.node-agent`**

```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Версия уходит в heartbeat (agent_version): без -X она осталась бы "dev" и в проде.
ARG AGENT_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${AGENT_VERSION}" \
    -o /out/novavpn-node-agent ./services/node-agent/cmd/novavpn-node-agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates libcap wireguard-tools iproute2 \
 && adduser -D -H -u 65532 novavpn
COPY --from=build /out/novavpn-node-agent /usr/local/bin/novavpn-node-agent
RUN setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/novavpn-node-agent
USER novavpn
VOLUME ["/var/lib/novavpn-node"]
ENTRYPOINT ["/usr/local/bin/novavpn-node-agent"]
CMD ["run"]
```

`setcap` стоит после `COPY` и без `|| true`: копирование сбрасывает расширенные атрибуты
файла, поэтому до него команда бессмысленна, а проглоченная ошибка дала бы «контейнер
стартует и падает на первом применении» вместо отказа сборки.

- [ ] **Step 3: Добавить сервис в dev-compose**

В `infrastructure/docker/docker-compose.dev.yml`:

```yaml
  node-agent:
    profiles: ["node"]
    build:
      context: ../..
      dockerfile: Dockerfile.node-agent
    cap_add: [NET_ADMIN, NET_RAW]
    environment:
      NOVAVPN_NODE_ENV: dev
      NOVAVPN_NODE_API_URL: http://api:8080
      NOVAVPN_NODE_ALLOW_INSECURE_API: "true"
      NOVAVPN_NODE_STATE_DIR: /var/lib/novavpn-node
    volumes:
      - novavpn-node-state:/var/lib/novavpn-node

volumes:
  novavpn-node-state:
```

Профиль `node` нужен, чтобы обычный `make up-dev` не поднимал узел без ключа и сервера.

- [ ] **Step 4: Цели Makefile**

```make
api-image:
	MSYS_NO_PATHCONV=1 docker build -t novavpn-api:dev -f Dockerfile.api .

node-image:
	MSYS_NO_PATHCONV=1 docker build -t novavpn-node-agent:dev -f Dockerfile.node-agent .

node-help:
	MSYS_NO_PATHCONV=1 docker run --rm novavpn-node-agent:dev --help
```

- [ ] **Step 5: Собрать и проверить**

Run: `make api-image && make node-image && make node-help`
Expected: три команды с кодом 0; `--help` печатает четыре команды.

- [ ] **Step 6: Коммит**

```bash
git add Dockerfile.api Dockerfile.node-agent infrastructure/docker/docker-compose.dev.yml Makefile
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): образы API и агента, профиль node в dev-стеке"
```

---

### Task 11: Стенд E2E — две сети, настоящий туннель, egress = адрес узла

Юнит-тесты не отвечают на вопрос «идёт ли трафик». Для этого нужен стенд, где у узла
есть вторая сеть с сервисом-эхом, а у клиента нет маршрута в неё, кроме туннеля: тогда
ответ эха с адресом узла — это факт про путь пакета, а не про запись в конфиге.

Две сети, а не одна: `harness` (172.31.99.0/24) — управляющая, в ней API, узел и клиент;
`uplink` (172.31.98.0/24) — «интернет» за узлом, в ней только узел и `probe`. Клиент не
имеет адреса в `uplink` и маршрута туда, поэтому единственный путь к `probe` — `wg0`.
NAT — отдельной таблицей `novavpn` (ADR-0009), `ip_forward` — через `sysctls` compose, а не
записью в `/proc` из скрипта.

**Files:**
- Create: `infrastructure/docker/docker-compose.e2e.yml`,
  `infrastructure/docker/e2e/node1.Dockerfile`,
  `infrastructure/docker/e2e/client1.Dockerfile`,
  `infrastructure/docker/e2e/probe.Dockerfile`,
  `infrastructure/docker/e2e/unbound.conf`,
  `infrastructure/docker/e2e/nat.nft`,
  `infrastructure/docker/e2e/node-entrypoint.sh`,
  `infrastructure/docker/e2e/client-entrypoint.sh`,
  `infrastructure/docker/e2e/dnsmasq.conf`,
  `tests/e2e/probe/main.go`,
  `scripts/e2e.sh`
- Modify: `Makefile` (цели `e2e`, `e2e-down`)

**Interfaces:**
- Produces: `make e2e` — код 0 только если все проверки фазы прошли; стек остаётся на
  месте при отказе (разбор), снимается на успехе.

- [ ] **Step 1: Сервис-эхо (дословный исходник)**

`tests/e2e/probe/main.go`:

```go
// probe отвечает адресом клиента, каким его видит сеть за узлом. Это проверка
// «пакет прошёл через узел и NAT», а не «пиер записан в конфиг»: адрес в ответе —
// адрес узла в uplink-сети, и получить его иначе, чем через туннель, клиент не может.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
)

func main() {
	http.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "плохой RemoteAddr", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, host)
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

- [ ] **Step 2: Образ probe и его DNS**

`infrastructure/docker/e2e/probe.Dockerfile`:

```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probe ./tests/e2e/probe

FROM alpine:3.20
RUN apk add --no-cache dnsmasq
COPY --from=build /out/probe /usr/local/bin/probe
COPY infrastructure/docker/e2e/dnsmasq.conf /etc/dnsmasq.conf
ENTRYPOINT ["/bin/sh", "-c", "dnsmasq --conf-file=/etc/dnsmasq.conf && exec /usr/local/bin/probe"]
```

`infrastructure/docker/e2e/dnsmasq.conf` — единственный резолвер, доступный узлу, и только
из `uplink`; `no-resolv` обязателен, иначе dnsmasq полез бы во внешний DNS контейнера и
проверка «запрос ушёл через туннель» стала бы неправдой:

```
no-resolv
no-hosts
address=/probe.e2e.test/172.31.98.3
address=/dns.e2e.test/172.31.98.3
```

- [ ] **Step 3: Образ узла**

`infrastructure/docker/e2e/node1.Dockerfile`:

```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG AGENT_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${AGENT_VERSION}" \
    -o /out/novavpn-node-agent ./services/node-agent/cmd/novavpn-node-agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates unbound nftables iproute2 su-exec libcap wireguard-tools \
 && adduser -D -H -u 65532 novavpn
COPY --from=build /out/novavpn-node-agent /usr/local/bin/novavpn-node-agent
RUN setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/novavpn-node-agent
COPY infrastructure/docker/e2e/unbound.conf /etc/unbound/unbound.conf
COPY infrastructure/docker/e2e/nat.nft /etc/novavpn/nat.nft
COPY infrastructure/docker/e2e/node-entrypoint.sh /usr/local/bin/node-entrypoint.sh
RUN chmod 0755 /usr/local/bin/node-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/node-entrypoint.sh"]
CMD ["run"]
```

- [ ] **Step 4: unbound и NAT узла**

`infrastructure/docker/e2e/unbound.conf` — слушает все адреса, но отвечает только
туннельной сети; запросы из `harness` (например, на 172.31.99.2) обязаны получить `REFUSED`,
и это проверяется в задаче 12, а не подразумевается:

```
server:
    verbosity: 1
    log-queries: no
    interface: 0.0.0.0
    access-control: 10.99.7.0/24 allow
    access-control: 0.0.0.0/0 refuse
    do-ip6: no
    do-daemonize: no
    username: "unbound"
    chroot: ""
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    minimal-responses: yes

forward-zone:
    name: "."
    forward-addr: 172.31.98.3
```

`forward-zone "."` на probe-dnsmasq — не «настоящая рекурсия»: в стенде нет внешнего DNS,
и честная формулировка результата — «запрос клиента дошёл до резолвера узла и ушёл с узла
настроенным форвардером», а не «рекурсия в интернете проверена».

`infrastructure/docker/e2e/nat.nft`:

```
table ip novavpn {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.99.7.0/24 oifname "eth1" masquerade
    }
}
```

- [ ] **Step 5: Точки входа контейнеров**

`infrastructure/docker/e2e/node-entrypoint.sh` — root-шаг ровно один и только для `run`:
каталог состояния принадлежит `novavpn`, дальше процесс идёт без root (capabilities на
бинарнике, ADR-0009 правила 1 и 3):

```sh
#!/bin/sh
set -eu
mkdir -p /var/lib/novavpn-node
chown -R novavpn:novavpn /var/lib/novavpn-node

case "${1:-run}" in
  run)
    nft delete table ip novavpn 2>/dev/null || true
    nft -f /etc/novavpn/nat.nft
    unbound -c /etc/unbound/unbound.conf
    exec su-exec novavpn /usr/local/bin/novavpn-node-agent run
    ;;
  *)
    exec su-exec novavpn /usr/local/bin/novavpn-node-agent "$@"
    ;;
esac
```

`infrastructure/docker/e2e/client-entrypoint.sh` — конфиг из API попадает в контейнер без
приватного ключа; ключ генерируется здесь же и здесь остаётся. `DNS =` вырезается, потому
что `wg-quick` позвал бы `resolvconf`, которого в alpine нет; резолвер ставится явно:

```sh
#!/bin/sh
set -eu
STATE=/state

case "${1:-run}" in
  genkey)
    path="${2:-$STATE/client.key}"
    [ -f "$path" ] || wg genkey > "$path"
    chmod 600 "$path"
    wg pubkey < "$path"
    ;;
  run)
    [ -f "$STATE/client.conf" ] || { echo "нет $STATE/client.conf" >&2; exit 1; }
    [ -f "$STATE/client.key" ] || { echo "нет $STATE/client.key" >&2; exit 1; }
    mkdir -p /etc/wireguard
    {
      echo "[Interface]"
      echo "PrivateKey = $(cat "$STATE/client.key")"
      grep -v '^DNS = ' "$STATE/client.conf" | grep -v '^\[Interface\]$'
    } > /etc/wireguard/wg0.conf
    chmod 600 /etc/wireguard/wg0.conf
    printf 'nameserver 10.99.7.1\n' > /etc/resolv.conf
    wg-quick up wg0
    exec sleep infinity
    ;;
  *)
    exec "$@"
    ;;
esac
```

`infrastructure/docker/e2e/client1.Dockerfile`:

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 bash curl iputils tcpdump bind-tools
COPY infrastructure/docker/e2e/client-entrypoint.sh /usr/local/bin/client-entrypoint.sh
RUN chmod 0755 /usr/local/bin/client-entrypoint.sh
VOLUME ["/state"]
ENTRYPOINT ["/usr/local/bin/client-entrypoint.sh"]
CMD ["run"]
```

- [ ] **Step 6: Compose стенда**

`infrastructure/docker/docker-compose.e2e.yml`:

```yaml
# Отдельное имя: `down -v` стенда не должен снимать тома dev-стека.
name: novavpn-e2e

services:
  postgres:
    image: postgres:17
    environment:
      POSTGRES_USER: nova
      POSTGRES_PASSWORD: nova
      POSTGRES_DB: novavpn
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nova -d novavpn"]
      interval: 2s
      timeout: 3s
      retries: 30
    networks:
      harness: {ipv4_address: 172.31.99.11}

  redis:
    image: redis:7
    command: ["redis-server", "--save", "", "--appendonly", "no"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 3s
      retries: 30
    networks:
      harness: {ipv4_address: 172.31.99.12}

  api:
    build:
      context: ../..
      dockerfile: Dockerfile.api
    environment:
      NOVAVPN_ENV: dev
      NOVAVPN_LISTEN_ADDR: ":8080"
      NOVAVPN_DATABASE_URL: postgres://nova:nova@172.31.99.11:5432/novavpn?sslmode=disable
      NOVAVPN_REDIS_ADDR: 172.31.99.12:6379
      # Значение приходит из .scratch/e2e/.env через --env-file скрипта. Пустое
      # значение не «дефолт»: API откажется стартовать с понятной ошибкой конфигурации.
      NOVAVPN_JWT_SECRET: ${NOVAVPN_JWT_SECRET:-}
    ports:
      - "127.0.0.1:18080:8080"
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}
    networks:
      harness: {ipv4_address: 172.31.99.10}

  node1:
    build:
      context: ../..
      dockerfile: infrastructure/docker/e2e/node1.Dockerfile
    cap_add: [NET_ADMIN, NET_RAW]
    sysctls:
      net.ipv4.ip_forward: "1"
    environment:
      NOVAVPN_NODE_ENV: dev
      NOVAVPN_NODE_API_URL: http://172.31.99.10:8080
      NOVAVPN_NODE_ALLOW_INSECURE_API: "true"
      NOVAVPN_NODE_STATE_DIR: /var/lib/novavpn-node
      NOVAVPN_NODE_INTERFACE: wg0
      NOVAVPN_NODE_POLL_INTERVAL: 25s
    volumes:
      - node1-state:/var/lib/novavpn-node
    networks:
      harness: {ipv4_address: 172.31.99.2}
      uplink: {ipv4_address: 172.31.98.2}

  client1:
    build:
      context: ../..
      dockerfile: infrastructure/docker/e2e/client1.Dockerfile
    cap_add: [NET_ADMIN]
    sysctls:
      # Политика §8: на время подключения IPv6 на клиенте отключается.
      net.ipv6.conf.all.disable_ipv6: "1"
    volumes:
      - client1-state:/state
    networks:
      harness: {ipv4_address: 172.31.99.3}

  probe:
    build:
      context: ../..
      dockerfile: infrastructure/docker/e2e/probe.Dockerfile
    networks:
      uplink: {ipv4_address: 172.31.98.3}

networks:
  harness:
    ipam:
      config: [{subnet: 172.31.99.0/24}]
  uplink:
    ipam:
      config: [{subnet: 172.31.98.0/24}]

volumes:
  node1-state:
  client1-state:
```

- [ ] **Step 7: Скрипт стенда — установка и проверка туннеля**

`scripts/e2e.sh` (дословный исходник; задачи 12–13 дописывают в него фазы):

```bash
#!/usr/bin/env bash
# Стенд E2E: настоящий туннель между client1 и node1, probe за узлом в отдельной
# сети. Каждая проверка печатает `ok` со своим именем; отказ — `FAIL` и код 1.
# На успехе стек снимается, на отказе остаётся для разбора (make e2e-down).
set -euo pipefail
export MSYS_NO_PATHCONV=1

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRATCH="$ROOT/.scratch/e2e"
COMPOSE_FILE="$ROOT/infrastructure/docker/docker-compose.e2e.yml"
API=http://127.0.0.1:18080
DC=(docker compose -f "$COMPOSE_FILE")
STATUS=0

say()  { printf '\n== %s\n' "$*"; }
pass() { printf 'ok   %s\n' "$*"; }
fail() { STATUS=1; printf 'FAIL %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "нет команды $1"; }

finish() {
  local code=$?
  if [ "$code" -ne 0 ] || [ "$STATUS" -ne 0 ]; then
    mkdir -p "$SCRATCH/logs"
    "${DC[@]}" logs --no-color > "$SCRATCH/logs/stack.log" 2>&1 || true
    printf '\nстек оставлен для разбора: %s (снять: make e2e-down)\n' "$SCRATCH/logs/stack.log" >&2
    return
  fi
  "${DC[@]}" down -v --remove-orphans >/dev/null
  rm -rf "$SCRATCH"
}
trap finish EXIT

jget() { # файл путь.через.точку
  python - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
for part in sys.argv[2].split("."):
    d = d[int(part)] if part.isdigit() else d[part]
print(d)
PY
}

wait_for() { # секунды, что ждём, команда...
  local seconds=$1 what=$2 deadline
  shift 2
  deadline=$(( $(date +%s) + seconds ))
  until "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      fail "за ${seconds} с не выполнено: ${what}"
    fi
    sleep 2
  done
}

node_exec()   { "${DC[@]}" exec -T node1 "$@"; }
client_exec() { "${DC[@]}" exec -T client1 "$@"; }
node_run()    { "${DC[@]}" run --rm -T node1 "$@"; }
client_run()  { "${DC[@]}" run --rm -T client1 "$@"; }
# -d, а не «&»: фоновая задача должна пережить завершение exec-сессии.
client_bg()   { "${DC[@]}" exec -d -T client1 sh -c "$1"; }
# Ключ генерируется внутри работающего клиента: compose run поднял бы второй
# контейнер с тем же статическим адресом 172.31.99.3 и получил бы конфликт.
client_key()  { client_exec sh -c "wg genkey > '$1' && chmod 600 '$1' && wg pubkey < '$1'"; }

api_ready() { curl -fsS -o /dev/null --max-time 2 "$API/debug/health"; }
proxy_ok()  { client_exec curl -fsS --max-time 5 http://probe.e2e.test:8080/whoami; }
peer_count() { node_exec wg show wg0 peers 2>/dev/null | grep -c . || true; }
peers_at_least_one() { [ "$(peer_count)" -ge 1 ]; }
peers_none()         { [ "$(peer_count)" = 0 ]; }
handshake_seen() { node_exec wg show wg0 latest-handshakes | awk '$2 > 0 { seen = 1 } END { exit seen ? 0 : 1 }'; }
peer_absent()  { ! node_exec wg show wg0 peers 2>/dev/null | grep -qx "$1"; }
peer_address() { node_exec wg show wg0 allowed-ips | awk -v k="$1" '$1 == k { print $2 }'; }

setup() {
  say "стенд: секреты, БД, администратор, сервер, узел, клиент"
  need docker
  need python
  need curl
  rm -rf "$SCRATCH"
  mkdir -p "$SCRATCH"
  chmod 700 "$SCRATCH"

  python - > "$SCRATCH/.env" <<'PY'
import base64, secrets
print("NOVAVPN_JWT_SECRET=" + base64.b64encode(secrets.token_bytes(32)).decode())
PY
  python - > "$SCRATCH/admin.pass" <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
  chmod 600 "$SCRATCH/.env" "$SCRATCH/admin.pass"

  "${DC[@]}" --env-file "$SCRATCH/.env" up -d --wait postgres redis
  "${DC[@]}" --env-file "$SCRATCH/.env" run --rm -T api migrate up
  "${DC[@]}" --env-file "$SCRATCH/.env" run --rm -T api admin create admin@e2e.test \
    < "$SCRATCH/admin.pass" >/dev/null
  "${DC[@]}" --env-file "$SCRATCH/.env" up -d api
  wait_for 90 "API отвечает на /debug/health" api_ready
  pass "API и база готовы, администратор создан"

  python - "$SCRATCH/admin.pass" > "$SCRATCH/admin-login.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    password = f.read().strip()
print(json.dumps({"email": "admin@e2e.test", "password": password}))
PY
  chmod 600 "$SCRATCH/admin-login.json"
  curl -fsS -X POST "$API/api/v1/admin/login" -H 'Content-Type: application/json' \
    --data-binary @"$SCRATCH/admin-login.json" > "$SCRATCH/admin-session.json"
  printf 'Authorization: Bearer %s\nContent-Type: application/json\n' \
    "$(jget "$SCRATCH/admin-session.json" access_token)" > "$SCRATCH/admin.hdr"
  chmod 600 "$SCRATCH/admin.hdr"
  rm -f "$SCRATCH/admin-login.json"

  NODE_PUB=$(node_run init 2>/dev/null | sed -n 's/^public_key //p')
  [ -n "$NODE_PUB" ] || fail "init узла не напечатал public_key"
  python - "$NODE_PUB" > "$SCRATCH/server.json" <<'PY'
import json, sys
print(json.dumps({
    "name": "e2e-1",
    "advertised_host": "172.31.99.2",
    "listen_port": 51820,
    "public_key": sys.argv[1],
    "address_pool_v4": "10.99.7.0/24",
    "provider": "e2e",
    "reason": "стенд E2E",
    "location": {"country_code": "DE", "city": "Test", "lat": "52.5",
                 "lon": "13.4", "timezone": "UTC"},
}))
PY
  curl -fsS -X POST "$API/api/v1/admin/servers" -H @"$SCRATCH/admin.hdr" \
    --data-binary @"$SCRATCH/server.json" > "$SCRATCH/server-created.json"
  SERVER_ID=$(jget "$SCRATCH/server-created.json" id)
  printf '{"status":"online","reason":"стенд E2E"}\n' > "$SCRATCH/online.json"
  curl -fsS -X POST "$API/api/v1/admin/servers/$SERVER_ID/maintenance" \
    -H @"$SCRATCH/admin.hdr" --data-binary @"$SCRATCH/online.json" >/dev/null
  printf '{}\n' > "$SCRATCH/empty.json"
  curl -fsS -X POST "$API/api/v1/admin/servers/$SERVER_ID/bootstrap-tokens" \
    -H @"$SCRATCH/admin.hdr" --data-binary @"$SCRATCH/empty.json" > "$SCRATCH/bootstrap.json"
  jget "$SCRATCH/bootstrap.json" token > "$SCRATCH/bootstrap.token"
  chmod 600 "$SCRATCH/bootstrap.token"
  pass "сервер $SERVER_ID создан и переведён в online"

  node_run enroll < "$SCRATCH/bootstrap.token"
  "${DC[@]}" --env-file "$SCRATCH/.env" up -d node1
  pass "узел зарегистрирован и запущен"

  CLIENT_PUB=$(client_run genkey /state/client.key)
  python - > "$SCRATCH/user.pass" <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
  chmod 600 "$SCRATCH/user.pass"
  python - "$SCRATCH/user.pass" > "$SCRATCH/register.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    password = f.read().strip()
print(json.dumps({"email": "user@e2e.test", "password": password}))
PY
  chmod 600 "$SCRATCH/register.json"
  curl -fsS -X POST "$API/api/v1/auth/register" -H 'Content-Type: application/json' \
    --data-binary @"$SCRATCH/register.json" >/dev/null
  curl -fsS -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
    --data-binary @"$SCRATCH/register.json" > "$SCRATCH/user-session.json"
  printf 'Authorization: Bearer %s\nContent-Type: application/json\n' \
    "$(jget "$SCRATCH/user-session.json" access_token)" > "$SCRATCH/user.hdr"
  chmod 600 "$SCRATCH/user.hdr"
  rm -f "$SCRATCH/register.json"

  python - "$CLIENT_PUB" > "$SCRATCH/device.json" <<'PY'
import json, sys
print(json.dumps({"public_key": sys.argv[1], "platform": "linux", "name": "e2e-client"}))
PY
  curl -fsS -X POST "$API/api/v1/devices" -H @"$SCRATCH/user.hdr" \
    -H "Idempotency-Key: e2e-device-1" --data-binary @"$SCRATCH/device.json" \
    > "$SCRATCH/device-created.json"
  DEVICE_ID=$(jget "$SCRATCH/device-created.json" id)
  python - "$SERVER_ID" > "$SCRATCH/profile.json" <<'PY'
import json, sys
print(json.dumps({"server_id": sys.argv[1]}))
PY
  curl -fsS -X POST "$API/api/v1/devices/$DEVICE_ID/profiles" -H @"$SCRATCH/user.hdr" \
    -H "Idempotency-Key: e2e-profile-1" --data-binary @"$SCRATCH/profile.json" \
    > "$SCRATCH/profile-created.json"

  curl -fsS "$API/api/v1/devices/$DEVICE_ID/profiles/$SERVER_ID/config" \
    -H @"$SCRATCH/user.hdr" > "$SCRATCH/client.conf"
  if grep -q '^PrivateKey' "$SCRATCH/client.conf"; then
    fail "API вернул конфиг с приватным ключом (§3 нарушен)"
  fi
  pass "профиль выдан, конфиг получен и приватного ключа в нём нет"

  # Конфиг кладётся в том до старта клиента: client1 ещё не запущен, и exec к нему
  # невозможен, а run поднимает одноразовый контейнер с тем же томом /state.
  client_run sh -c 'cat > /state/client.conf' < "$SCRATCH/client.conf"
  "${DC[@]}" --env-file "$SCRATCH/.env" up -d client1
}

tunnel() {
  say "туннель: handshake, трафик, egress"
  wait_for 120 "пиер клиента появился на узле" peers_at_least_one
  wait_for 90 "handshake с клиентом" handshake_seen
  pass "узел видит пиера и handshake"

  wait_for 90 "ответ probe через туннель" proxy_ok
  EGRESS=$(client_exec curl -fsS --max-time 5 http://probe.e2e.test:8080/whoami | tr -d '\r\n')
  [ "$EGRESS" = "172.31.98.2" ] || fail "egress = $EGRESS, ожидался адрес узла 172.31.98.2"
  pass "egress = $EGRESS (адрес узла, не клиента)"

  client_exec ping -c 3 -W 2 -q probe.e2e.test >/dev/null || fail "ICMP через туннель не ходит"
  pass "ICMP через туннель проходит"

  node_exec wg show wg0 allowed-ips | grep -q '10\.99\.7\.2/32' \
    || fail "у узла нет allowed-ips клиента 10.99.7.2/32"
  pass "адрес клиента на узле — 10.99.7.2/32"
}

main() {
  local phase="${1:-all}"
  case "$phase" in
    all)    setup; tunnel ;;
    tunnel) setup; tunnel ;;
    *) fail "неизвестная фаза: $phase" ;;
  esac
  pass "фаза $phase пройдена"
}

main "$@"
```

- [ ] **Step 8: Цели Makefile**

В `Makefile` рядом с остальными целями:

```makefile
# Стенд E2E требует загруженного модуля wireguard на хосте (S1). На успехе снимает
# стек сам; при отказе оставляет его и печатает путь к журналу — разбор важнее чистоты.
e2e:
	bash scripts/e2e.sh all

e2e-down:
	docker compose -f infrastructure/docker/docker-compose.e2e.yml down -v --remove-orphans
```

Добавить `e2e e2e-down` в `.PHONY`. Файл скрипта сделать исполняемым
(`chmod +x scripts/e2e.sh`).

- [ ] **Step 9: Прогнать**

Run: `make e2e`
Expected: код 0; в выводе пять строк `ok` фазы setup/tunnel, включая
`egress = 172.31.98.2 (адрес узла, не клиента)`.

Если прогон падает на `modprobe` или `Operation not permitted` при `wg`, это не повод
обходить проверку: модуль `wireguard` загружается на хосте (S1), и строка об этом идёт в
`docs/testing-status.md` как незакрытая, а не в комментарий «должно работать».

- [ ] **Step 10: Коммит**

```bash
chmod +x scripts/e2e.sh
git add infrastructure/docker/docker-compose.e2e.yml infrastructure/docker/e2e \
  tests/e2e scripts/e2e.sh Makefile
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "test(a3): стенд E2E — две сети, настоящий туннель, egress = адрес узла"
```

---

### Task 12: DNS через узел, отсутствие утечки, IPv6, лимит устройств

Проверка DNS — это три отдельных утверждения, и путать их нельзя: клиент **получает
ответ** от резолвера узла; **ни один** DNS-пакет не уходит с интерфейса клиента мимо
туннеля; запросы из сети без туннеля резолвер **отвергает**. Первое без второго и
третьего не доказывает ничего.

**Files:**
- Modify: `scripts/e2e.sh` (фазы `dns`, `limit`; `all` их включает)
- Create: `docs/spikes/2026-10-28-s2-unbound-harness.md`
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§10, §14)

- [ ] **Step 1: Дописать фазы в `scripts/e2e.sh`**

Вставить обе функции после `tunnel`, затем заменить `main` на версию с четырьмя
ветками (он же меняется в задаче 13):

```bash
main() {
  local phase="${1:-all}"
  case "$phase" in
    all)    setup; tunnel; dns; limit ;;
    tunnel) setup; tunnel ;;
    dns)    setup; tunnel; dns ;;
    limit)  setup; tunnel; limit ;;
    *) fail "неизвестная фаза: $phase" ;;
  esac
  pass "фаза $phase пройдена"
}

main "$@"
```

```bash
dns() {
  say "DNS: резолвер узла, отсутствие утечки, отказ из чужой сети"
  client_exec nslookup probe.e2e.test | grep -q '172.31.98.3' \
    || fail "клиент не получил ответ от резолвера узла"
  pass "resolv.conf клиента → 10.99.7.1, имя probe.e2e.test резолвится"

  # tcpdump на eth0 клиента: DNS-пакет, ушедший мимо wg0, — это утечка. Таймаут
  # значит «пакетов не было»; любой захваченный пакет — отказ.
  client_exec sh -c 'timeout 6 tcpdump -i eth0 -n -q udp port 53 > /state/leak.log 2>&1; echo $?' \
    > "$SCRATCH/leak.code"
  [ "$(cat "$SCRATCH/leak.code" | tr -d '\r\n')" = "124" ] \
    || fail "на eth0 клиента захвачен DNS-трафик (см. /state/leak.log в client1)"
  pass "на eth0 клиента нет ни одного DNS-пакета"

  if client_exec nslookup probe.e2e.test 172.31.99.2 >/dev/null 2>&1; then
    fail "резолвер узла ответил запросу из сети без туннеля"
  fi
  pass "тот же резолвер отвергает запрос не из туннельной сети"

  if "${DC[@]}" logs --no-color node1 2>/dev/null | grep -qE 'query:|reply:'; then
    fail "в журнале контейнера узла есть строки запросов unbound"
  fi
  pass "журнала DNS-запросов в выводе контейнера узла нет"

  if client_exec sh -c 'ip -6 addr show | grep -q "inet6 .*global"'; then
    fail "у клиента есть глобальный IPv6-адрес"
  fi
  if client_exec sh -c 'ip -6 route show default | grep -q .'; then
    fail "у клиента есть IPv6 default route (ADR-007: тихий blackhole)"
  fi
  if client_exec sh -c 'ping -6 -c 1 -W 1 2001:db8::1' >/dev/null 2>&1; then
    fail "IPv6-путь наружу существует"
  fi
  pass "IPv6 на клиенте отключён: адреса, маршрута и пути наружу нет"
}

limit() {
  say "лимит устройств: третье проходит, четвёртое — 409"
  local n pub status body
  for n in 2 3; do
    pub=$(client_key "/state/dev$n.key")
    python - "$pub" "$n" > "$SCRATCH/device-$n.json" <<'PY'
import json, sys
print(json.dumps({"public_key": sys.argv[1], "platform": "linux", "name": "e2e-extra-" + sys.argv[2]}))
PY
    status=$(curl -sS -o "$SCRATCH/device-$n.out" -w '%{http_code}' -X POST "$API/api/v1/devices" \
      -H @"$SCRATCH/user.hdr" -H "Idempotency-Key: e2e-device-$n" \
      --data-binary @"$SCRATCH/device-$n.json")
    [ "$status" = "201" ] || fail "устройство $n: HTTP $status, ожидался 201"
  done
  pub=$(client_key /state/dev4.key)
  python - "$pub" > "$SCRATCH/device-4.json" <<'PY'
import json, sys
print(json.dumps({"public_key": sys.argv[1], "platform": "linux", "name": "e2e-extra-4"}))
PY
  status=$(curl -sS -o "$SCRATCH/device-4.out" -w '%{http_code}' -X POST "$API/api/v1/devices" \
    -H @"$SCRATCH/user.hdr" -H "Idempotency-Key: e2e-device-4" \
    --data-binary @"$SCRATCH/device-4.json")
  [ "$status" = "409" ] || fail "четвёртое устройство: HTTP $status, ожидался 409"
  python - "$SCRATCH/device-4.out" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    code = json.load(f)["error"]["code"]
sys.exit(0 if code == "device_limit_reached" else 1)
PY
  pass "лимит 3: четвёртое устройство отклонено с device_limit_reached"
}
```

`unbound` в этой конфигурации не открывает файл журнала: `logfile` не задан, процесс
пишет в stdout, а `log-queries: no` означает, что строк `query:`/`reply:` там нет вовсе.
Поэтому единственная осмысленная проверка — `docker compose logs node1`. Файл
`/var/log/unbound.log` не создаётся, и `grep` по нему был бы пустой проверкой под видом
проверки; в блоке выше его нет.

- [ ] **Step 2: Прогнать**

Run: `make e2e`
Expected: код 0; фазы `setup`, `tunnel`, `dns`, `limit` — все `ok`, включая
`на eth0 клиента нет ни одного DNS-пакета` и `лимит 3: четвёртое устройство отклонено`.

- [ ] **Step 3: Записать спайк S2**

`docs/spikes/2026-10-28-s2-unbound-harness.md`, по образцу
`docs/spikes/2026-10-20-s1-s3-wireguard-netlink.md`: вопрос, стенд, команды, вывод.
Заполнять **только фактическими строками прогона** (эта задача не закрывается, если
прогон не делался). Обязательные пункты:

- unbound стартует в контейнере без `NET_ADMIN` (он не трогает сеть) и отвечает клиенту
  в туннеле по адресу `10.99.7.1:53`;
- `access-control: 0.0.0.0/0 refuse` действительно отвергает запрос из `harness`
  (привести вывод `nslookup` из client1 на 172.31.99.2);
- `log-queries: no` не оставляет строк запросов ни в выводе контейнера, ни в файле;
- чем форвард отличается от рекурсии в этом стенде (форвардер `172.31.98.3`) и почему
  это ограничение стенда, а не свойства unbound.

- [ ] **Step 4: Обновить спецификацию**

В §10 (таблица спайков) строка S2: `выполнен 2026-10-28`, исход — со ссылкой на файл
спайка, блокировал «DNS-часть E2E» — **разблокировано**. В §14 (ADR-005) добавить к
решению «проверено на harness 2026-10-28»; если прогон показал расхождение (например,
нужен `interface: 0.0.0.0` вместо адреса туннеля из-за порядка старта), это фиксируется
как уточнение ADR-005, а не замалчивается.

- [ ] **Step 5: Коммит**

```bash
git add scripts/e2e.sh docs/spikes/2026-10-28-s2-unbound-harness.md \
  docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "test(a3): DNS через узел, отсутствие утечки, IPv6 и лимит устройств на стенде"
```

---

### Task 13: Жизненный цикл — отзыв, ротация, draining, отказ API, рестарт узла

Здесь проверяются обещания, которые нельзя проверить иначе, чем временем: «отзыв ≤ 30 с»,
«ротация не рвёт поток», «узел переживает недоступность API», «рестарт узла не оставляет
его без пиеров». Каждое измерение печатается числом; если число не уложилось в критерий,
это отказ задачи, а не «почти».

**Files:**
- Modify: `scripts/e2e.sh` (фаза `lifecycle`)
- Modify: `docs/adr/0004-wireguard-peer-apply.md` (последствия: адрес эксклюзивен)
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§7.3, §13)

- [ ] **Step 1: Дописать фазу `lifecycle`**

Вставить после `limit` и заменить `main` на версию с пятью ветками.

```bash
peer_key_at() { node_exec wg show wg0 allowed-ips | awk -v a="$1" '$2 == a { print $1 }'; }
state_etag() {
  node_exec cat /var/lib/novavpn-node/state.json |
    python -c 'import json, sys; print(json.load(sys.stdin)["applied"]["etag"])'
}

lifecycle() {
  say "ротация: смена ключа на том же интерфейсе"
  local new_pub old_pub new_device pause
  old_pub=$(peer_key_at 10.99.7.2/32)
  [ -n "$old_pub" ] || fail "не найден старый ключ с адресом 10.99.7.2/32"
  new_pub=$(client_key /state/client2.key)
  python - "$new_pub" > "$SCRATCH/rotate.json" <<'PY'
import json, sys
print(json.dumps({"public_key": sys.argv[1]}))
PY
  curl -fsS -X POST "$API/api/v1/devices/$DEVICE_ID/keys/rotate" -H @"$SCRATCH/user.hdr" \
    -H "Idempotency-Key: e2e-rotate-1" --data-binary @"$SCRATCH/rotate.json" \
    > "$SCRATCH/rotate.out"
  new_device=$(jget "$SCRATCH/rotate.out" id)

  curl -fsS "$API/api/v1/devices/$new_device/profiles/$SERVER_ID/config" -H @"$SCRATCH/user.hdr" \
    > "$SCRATCH/client2.conf"
  grep -q '^Address = 10\.99\.7\.2/32$' "$SCRATCH/client2.conf" \
    || fail "после ротации у нового ключа другой адрес — профиль не унаследован"

  # Цикл живёт до появления стоп-файла: exec -d в контейнере не зависит от сессии,
  # а стоп-файл делает остановку детерминированной (никаких pkill по шаблону).
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
  client_exec sh -c 'wg set wg0 private-key /state/client2.key'
  # 40 с: худший случай появления нового ключа на узле — 27,5 с (интервал 25 с +
  # jitter) плюс первый handshake; сорок секунд покрывают это с запасом.
  sleep 40
  client_exec sh -c 'touch /state/ping.stop'
  sleep 2

  client_exec cat /state/ping.log > "$SCRATCH/ping.log"
  pause=$(python - "$SCRATCH/ping.log" <<'PY'
import sys
rows = [line.split() for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
first_fail = resume = None
for state, ts in rows:
    ts = int(ts)
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
)
  [ "$pause" != "-1" ] || fail "трафик не вернулся после смены ключа: возврата в журнале пингов нет"
  printf 'ok   измеренная пауза при смене ключа: %s с (разрешение 1 с)\n' "$pause"

  [ "$(peer_address "$new_pub")" = "10.99.7.2/32" ] \
    || fail "адрес у активного ключа не 10.99.7.2/32: $(peer_address "$new_pub")"
  [ "$(peer_address "$old_pub")" != "10.99.7.2/32" ] \
    || fail "адрес остался у старого ключа: ядро отдаёт его только одному пиеру"
  pass "адрес 10.99.7.2/32 у активного ключа, старый ключ без адреса"

  wait_for 120 "старый ключ снят после handshake нового" peer_absent "$old_pub"
  pass "старый ключ снят после того, как API увидел handshake нового"

  say "draining: desired пуст, пиеры сняты, возврат в online"
  printf '{"status":"draining","reason":"стенд E2E: draining"}\n' > "$SCRATCH/drain.json"
  curl -fsS -X POST "$API/api/v1/admin/servers/$SERVER_ID/maintenance" \
    -H @"$SCRATCH/admin.hdr" --data-binary @"$SCRATCH/drain.json" >/dev/null
  wait_for 60 "все пиеры сняты при draining" peers_none
  pass "draining: узел снял всех пиеров"

  curl -fsS -X POST "$API/api/v1/admin/servers/$SERVER_ID/maintenance" \
    -H @"$SCRATCH/admin.hdr" --data-binary @"$SCRATCH/online.json" >/dev/null
  wait_for 90 "пиер вернулся после online" peers_at_least_one
  wait_for 90 "трафик вернулся после online" proxy_ok
  pass "online: пиер и трафик вернулись"

  say "отказ API: набор сохраняется, трафик не останавливается"
  "${DC[@]}" stop api >/dev/null
  sleep 35
  proxy_ok || fail "трафик остановился, пока API недоступен"
  [ "$(peer_count)" -ge 1 ] || fail "пиеры сняты, пока API недоступен"
  "${DC[@]}" logs --no-color node1 2>/dev/null | grep -q 'desired set недоступен' \
    || fail "узел не записал в журнал недоступность desired set"
  "${DC[@]}" start api >/dev/null
  wait_for 90 "API снова отвечает" api_ready
  pass "узел пережил отказ API: пиеры на месте, трафик не прерывался"

  say "рестарт узла: интерфейс пуст, набор применяется заново"
  local etag_before etag_after
  etag_before=$(state_etag)
  "${DC[@]}" restart node1 >/dev/null
  wait_for 120 "пиер вернулся после рестарта узла" peers_at_least_one
  wait_for 90 "трафик вернулся после рестарта узла" proxy_ok
  etag_after=$(state_etag)
  [ "$etag_before" = "$etag_after" ] \
    || fail "ETag изменился ($etag_before → $etag_after): набор на сервере менялся, проверка не та"
  pass "после рестарта узел применил тот же набор, хотя ETag не менялся"

  say "отзыв: профиль снят, пиер уходит, трафик останавливается ≤ 30 с"
  client_bg 'rm -f /state/first_fail
while [ ! -e /state/first_fail ]; do
  if ping -c1 -W1 -q probe.e2e.test >/dev/null 2>&1; then :; else date +%s > /state/first_fail; fi
  sleep 1
done'
  local revoked_at elapsed
  revoked_at=$(date +%s)
  curl -fsS -X DELETE "$API/api/v1/devices/$new_device/profiles/$SERVER_ID" \
    -H @"$SCRATCH/user.hdr" -o /dev/null
  wait_for 120 "пиер снят после отзыва" peers_none
  wait_for 30 "ping зафиксировал остановку трафика" client_exec test -s /state/first_fail
  elapsed=$(( $(client_exec cat /state/first_fail) - revoked_at ))
  printf 'ok   отзыв применился за %s с\n' "$elapsed"
  [ "$elapsed" -le 30 ] || fail "отзыв занял ${elapsed} с, критерий ≤ 30 с"
  pass "отзыв уложился в критерий"
}

main() {
  local phase="${1:-all}"
  case "$phase" in
    all)       setup; tunnel; dns; limit; lifecycle ;;
    tunnel)    setup; tunnel ;;
    dns)       setup; tunnel; dns ;;
    limit)     setup; tunnel; limit ;;
    lifecycle) setup; tunnel; lifecycle ;;
    *) fail "неизвестная фаза: $phase" ;;
  esac
  pass "фаза $phase пройдена"
}

main "$@"
```

Три места, где легко соврать, и как этого не делать:

- **пауза при ротации** измеряется с разрешением 1 с (`ping` раз в секунду) и печатается
  как есть, включая `0`. Утверждение «ноль потерь» из §7.3 недостижимо физически: адрес
  `/32` принадлежит одному пиеру (измерено), и на время смены ключа трафик останавливается
  до первого handshake нового. Это фиксируется в спецификации на шаге 3, а не
  подгоняется формулировкой.
- **`old_pub` без адреса** — ожидаемое поведение, а не ошибка: правило «адрес активному»
  реализовано в `wg.Diff`. Проверять надо именно отсутствие адреса, а не «пиер удалён».
- **снятие старого ключа** происходит не мгновенно: API видит handshake нового из отчёта
  узла. Ожидание 120 с — это два интервала опроса с запасом; если ключ не снялся за это
  время, значит условие «handshake нового» не выполняется, и это отказ.
- **фон и остановка** — только `client_bg` (это `exec -d`) и стоп-файл: `&` внутри
  `exec` умирает вместе с сессией, а `pkill` по шаблону может задеть чужой процесс.
  Окно наблюдения 40 с покрывает худший случай появления нового ключа (27,5 с) и первый
  handshake; `-1` из разбора пингов означает «отказ был, возврата не было» и валит фазу.
- **`etag_before`/`etag_after`** читаются разбором JSON (`state_etag`), а не `grep`:
  в `state.json` ETag записан с экранированными кавычками (`"etag":"\"e2\""`), и
  регулярка `"etag":"[^"]*"` совпала бы на префиксе всегда, то есть была бы пустой
  проверкой. Отзыв после ротации идёт по `$new_device`: ротация вернула устройство
  с тем же id, но привязка проверки к ответу ротации не даёт ей разъехаться молча.

- [ ] **Step 2: Прогнать**

Run: `make e2e`
Expected: код 0; в выводе две строки с измеренными числами — `измеренная пауза при смене
ключа: …` и `отзыв применился за … с` — плюс строки `draining`, `отказ API`, `рестарт
узла` с `ok`. Конкретные секунды зависят от прогона: они вносятся в ADR, спецификацию и
`docs/testing-status.md` из вывода, а не подставляются ожиданием.

- [ ] **Step 3: Записать в ADR-004 и спецификацию то, что измерено**

В `docs/adr/0004-wireguard-peer-apply.md` в «Последствия» добавить пункт: адрес
(allowed-ips) эксклюзивен, ядро отдаёт его одному пиеру; при ротации адрес принадлежит
активному ключу, старый ждёт снятия без адреса; поэтому overlap гарантирует
восстановление по новому ключу, а не отсутствие паузы, и измеренная пауза — числом из
вывода фазы `lifecycle` на стенде.

В спецификации §7.3 убрать формулировку, обещающую нулевой разрыв при одном адресе,
и заменить на: «в окне overlap в desired оба ключа; адрес принадлежит активному; пауза
ограничена интервалом опроса и первым handshake нового ключа; измерено на стенде — число
из вывода фазы `lifecycle`».
В §13 добавить два ограничения:

14. **Ротация ключа даёт паузу до первого handshake нового ключа** (измерено на стенде,
    число — из вывода фазы `lifecycle`):
    адрес `/32` в WireGuard может принадлежать только одному пиеру, поэтому старый и
    новый ключи не проходимы одновременно. «Нулевого разрыва» при одном адресе не
    существует; вариант без паузы требует второго адреса или второго узла.
15. **Внешняя правка интерфейса при живом агенте не чинится до изменения набора:**
    ответ 304 означает «набор уже применён», и полный опрос не выполняется. Правка
    руками (или сброс интерфейса вне агента) живёт до следующего изменения desired set
    или рестарта агента — рестарт лечится первым полным опросом.

- [ ] **Step 4: Коммит**

```bash
git add scripts/e2e.sh docs/adr/0004-wireguard-peer-apply.md \
  docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "test(a3): отзыв, ротация, draining, отказ API и рестарт узла на стенде"
```

---

### Task 14: Ansible — установка узла, systemd, sysctl, nftables, авто-откат

Роль ставит узел с нуля и обновляет бинарник, не притворяясь, что проверила сеть: она
не запускает туннель и не проверяет трафик (это делает стенд), а гарантирует четыре
вещи — процесс живёт под непривилегированным пользователем с двумя capabilities,
`ip_forward` и NAT включены, IPv6 выключен, а неудачное обновление откатывается само.

NAT и форвардинг живут в **своей** таблице `inet novavpn`: роль заменяет её целиком
(`delete table` + `nft -f`) и не касается чужого набора. Политика `forward` — `accept`,
потому что главный фильтр входящего — хостовый firewall оператора; роль не имеет права
молча менять чужую политику.

**Files:**
- Create: `infrastructure/ansible/ansible.cfg`, `infrastructure/ansible/site.yml`,
  `infrastructure/ansible/inventory.example.ini`
- Create: `infrastructure/ansible/roles/novavpn_node/defaults/main.yml`,
  `.../meta/main.yml`, `.../tasks/main.yml`, `.../tasks/install.yml`,
  `.../tasks/enroll.yml`, `.../tasks/deploy.yml`, `.../handlers/main.yml`,
  `.../files/novavpn-nft-apply.sh`, `.../files/novavpn-rollback.sh`,
  `.../templates/agent.env.j2`, `.../templates/novavpn-node.service.j2`,
  `.../templates/90-novavpn.conf.j2`, `.../templates/novavpn.nft.j2`
- Modify: `Makefile` (цель `ansible-lint`), `.gitignore` (`inventory.ini`, `artifacts/`)

**Interfaces:**
- Produces: `ansible-playbook -i inventory.example.ini site.yml --syntax-check` и
  `ansible-lint` проходят без хоста; повторный прогон роли не меняет файлов и настроек
  (ожидаемые `changed` — перезапуск агента и таймер отката), бинарник обновляется с
  транзиентным таймером отката.
- Consumes: бинарник `novavpn-node-agent` (задача 9), его env-имена (задача 9).

- [ ] **Step 1: `ansible.cfg` и пример инвентаря**

`infrastructure/ansible/ansible.cfg`:

```ini
[defaults]
inventory = inventory.ini
roles_path = roles
host_key_checking = True
retry_files_enabled = False
interpreter_python = auto_silent
stdout_callback = yaml
callbacks_enabled = profile_tasks

[ssh_connection]
pipelining = True
```

`infrastructure/ansible/inventory.example.ini`:

```ini
[novavpn_nodes]
node1 ansible_host=203.0.113.10 ansible_user=deploy \
      ansible_ssh_private_key_file=~/.ssh/novavpn_node_ed25519

[novavpn_nodes:vars]
ansible_python_interpreter=/usr/bin/python3
novavpn_node_api_url=https://api.novavpn.example
novavpn_node_pool=10.99.7.0/24
novavpn_node_uplink_iface=eth0
novavpn_node_binary_src={{ playbook_dir }}/../artifacts/novavpn-node-agent-linux-amd64
novavpn_node_bootstrap_file=/root/novavpn-bootstrap.token
novavpn_node_enroll=false
```

`host_key_checking = True` — не стиль, а отказ от MITM: ключ хоста при первом
подключении принимается руками (`ssh-keyscan` + сверка отпечатка с панелью хостера).
`novavpn_node_enroll=false` по умолчанию: публичный ключ узла нужен администратору
**до** выдачи bootstrap-токена, поэтому первый прогон не регистрирует узел.

- [ ] **Step 2: `defaults/main.yml` и `meta/main.yml`**

`defaults/main.yml`:

```yaml
novavpn_node_user: novavpn
novavpn_node_state_dir: /var/lib/novavpn-node
novavpn_node_config_dir: /etc/novavpn-node
novavpn_node_lib_dir: /usr/local/lib/novavpn
novavpn_node_bin: /usr/local/bin/novavpn-node-agent
novavpn_node_interface: wg0
novavpn_node_ca_file: /etc/ssl/certs/ca-certificates.crt
novavpn_node_rollback_delay_sec: 180
# Обязательные, без значений по умолчанию: пул и адрес API нельзя угадать.
# novavpn_node_api_url
# novavpn_node_pool
# novavpn_node_uplink_iface
# novavpn_node_binary_src
# novavpn_node_bootstrap_file
novavpn_node_enroll: false
```

`meta/main.yml` — только `galaxy_info` (роль, автор, минимальная версия Ansible 2.15)
и `dependencies: []`; внешних ролей у узла нет, `unbound` ставится отдельной ролью в
задаче 15.

Четыре пути из `defaults/main.yml` — не свободные настройки: они повторены строкой в
`novavpn-rollback.sh`, в `novavpn-nft-apply.sh` и в юните (`StateDirectory=novavpn-node`).
Переопределение переменной развело бы её с файлами молча, поэтому задача 1 в
`install.yml` сверяет значения и отказывается работать при расхождении.

- [ ] **Step 3: `tasks/main.yml` и `tasks/install.yml`**

`tasks/main.yml`:

```yaml
- name: Проверить обязательные переменные и запрет http
  ansible.builtin.assert:
    that:
      - novavpn_node_api_url is defined
      - novavpn_node_pool is defined
      - novavpn_node_uplink_iface is defined
      - novavpn_node_binary_src is defined
      - novavpn_node_api_url is match('^https://')
    fail_msg: >-
      нужны novavpn_node_api_url (только https), novavpn_node_pool,
      novavpn_node_uplink_iface, novavpn_node_binary_src

- name: Пакеты, каталоги, sysctl, nftables, юнит, первый бинарник
  ansible.builtin.import_tasks: install.yml

- name: Применить sysctl и nftables до первого запуска
  ansible.builtin.meta: flush_handlers

- name: Регистрация узла и ключ
  ansible.builtin.import_tasks: enroll.yml

- name: Обновление бинарника, запуск, откат
  ansible.builtin.import_tasks: deploy.yml
```

`tasks/install.yml`:

```yaml
- name: Пути совпадают с вписанными в скрипты и юнит
  ansible.builtin.assert:
    that:
      - novavpn_node_bin == '/usr/local/bin/novavpn-node-agent'
      - novavpn_node_config_dir == '/etc/novavpn-node'
      - novavpn_node_state_dir == '/var/lib/novavpn-node'
      - novavpn_node_lib_dir == '/usr/local/lib/novavpn'
    fail_msg: >-
      эти пути повторены в novavpn-rollback.sh, novavpn-nft-apply.sh и в юните
      (StateDirectory=novavpn-node); менять их только вместе с файлами роли

- name: Пакеты
  ansible.builtin.apt:
    name: [ca-certificates, nftables, procps, wireguard-tools]
    state: present
    update_cache: true

- name: Группа узла
  ansible.builtin.group:
    name: "{{ novavpn_node_user }}"
    system: true

- name: Пользователь узла без входа в систему
  ansible.builtin.user:
    name: "{{ novavpn_node_user }}"
    group: "{{ novavpn_node_user }}"
    system: true
    shell: /usr/sbin/nologin
    create_home: false
    home: "{{ novavpn_node_state_dir }}"

- name: Каталоги конфигурации, состояния и скриптов
  ansible.builtin.file:
    path: "{{ item.path }}"
    state: directory
    owner: "{{ item.owner }}"
    group: "{{ item.group }}"
    mode: "{{ item.mode }}"
  loop:
    - {path: "{{ novavpn_node_config_dir }}", owner: root, group: root, mode: "0750"}
    - {path: "{{ novavpn_node_state_dir }}", owner: "{{ novavpn_node_user }}", group: "{{ novavpn_node_user }}", mode: "0700"}
    - {path: "{{ novavpn_node_lib_dir }}", owner: root, group: root, mode: "0755"}

- name: sysctl-файл
  ansible.builtin.template:
    src: 90-novavpn.conf.j2
    dest: /etc/sysctl.d/90-novavpn.conf
    owner: root
    group: root
    mode: "0644"
  notify: Применить sysctl

- name: Таблица nftables
  ansible.builtin.template:
    src: novavpn.nft.j2
    dest: "{{ novavpn_node_config_dir }}/novavpn.nft"
    owner: root
    group: root
    mode: "0640"
  notify: Применить nftables

- name: Скрипты применения nft и отката
  ansible.builtin.copy:
    src: "{{ item }}"
    dest: "{{ novavpn_node_lib_dir }}/{{ item }}"
    owner: root
    group: root
    mode: "0755"
  loop: [novavpn-nft-apply.sh, novavpn-rollback.sh]
  notify: Применить nftables

- name: Исходный бинарник на управляющей машине
  ansible.builtin.stat:
    path: "{{ novavpn_node_binary_src }}"
  delegate_to: localhost
  become: false
  register: node_bin_src

- name: Без бинарника регистрация невозможна
  ansible.builtin.assert:
    that: node_bin_src.stat.exists
    fail_msg: "нет файла {{ novavpn_node_binary_src }} (соберите make node-image или cross-build)"

- name: Бинарник агента на узле
  ansible.builtin.stat:
    path: "{{ novavpn_node_bin }}"
  register: node_bin_dst

- name: Первый бинарник агента
  ansible.builtin.copy:
    src: "{{ novavpn_node_binary_src }}"
    dest: "{{ novavpn_node_bin }}"
    owner: root
    group: root
    mode: "0755"
  when: not node_bin_dst.stat.exists

- name: Окружение агента
  ansible.builtin.template:
    src: agent.env.j2
    dest: "{{ novavpn_node_config_dir }}/agent.env"
    owner: root
    group: root
    mode: "0600"
  notify: Перезагрузить systemd

- name: Юнит агента
  ansible.builtin.template:
    src: novavpn-node.service.j2
    dest: /etc/systemd/system/novavpn-node-agent.service
    owner: root
    group: root
    mode: "0644"
  notify: Перезагрузить systemd
```

Первичная установка бинарника живёт здесь, а не в `deploy.yml`: `enroll.yml` вызывает
`init` и `enroll` раньше `deploy.yml`, и на первом прогоне команда падала бы на
отсутствующем файле. `deploy.yml` остаётся обновлением — `.prev`, `.new`, замена,
перезапуск и таймер отката. На самом первом прогоне `.prev` получается копией только что
установленного бинарника, и откат вернёт тот же файл: отдельная ветка «первый прогон»
не нужна, потому что вреда в этом нет, а путей установки остаётся один.

`templates/agent.env.j2`:

```jinja
NOVAVPN_NODE_ENV=prod
NOVAVPN_NODE_API_URL={{ novavpn_node_api_url }}
NOVAVPN_NODE_CA_FILE={{ novavpn_node_ca_file }}
NOVAVPN_NODE_STATE_DIR={{ novavpn_node_state_dir }}
NOVAVPN_NODE_INTERFACE={{ novavpn_node_interface }}
NOVAVPN_NODE_POLL_INTERVAL=25s
```

Флага `NOVAVPN_NODE_ALLOW_INSECURE_API` здесь нет ни в каком виде. Он существует только
для dev-стенда и вне `NOVAVPN_NODE_ENV=dev` обязан отказывать (задача 9 проверяет это
тестом); в прод-шаблоне его отсутствие — не «настройка», а граница.

`templates/90-novavpn.conf.j2`:

```jinja
# Форвардинг нужен только для туннеля; IPv6 выключен целиком (§8, ADR-007).
# rp_filter=2: обратный путь пакетов из интернета идёт не тем интерфейсом, что
# прямой (ответ приходит с uplink, а маршрут до пула — через {{ novavpn_node_interface }}),
# и строгая проверка 1 отсортировала бы такой трафик молча.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
```

`templates/novavpn.nft.j2`:

```jinja
# Своя таблица целиком, политика forward — accept: главный фильтр входящего —
# хостовый firewall оператора, и роль не меняет чужую политику молча.
table inet novavpn {
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct state established,related accept
    iifname "{{ novavpn_node_interface }}" oifname "{{ novavpn_node_uplink_iface }}" accept
    iifname "{{ novavpn_node_uplink_iface }}" oifname "{{ novavpn_node_interface }}" accept
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {{ novavpn_node_pool }} oifname "{{ novavpn_node_uplink_iface }}" masquerade
  }
}
```

`files/novavpn-nft-apply.sh`:

```bash
#!/usr/bin/env bash
# delete+add, а не только «nft -f»: повторный прогон с тем же шаблоном иначе
# накапливал бы правила в таблице, и вторая копия NAT-правила осталась бы жить.
set -euo pipefail
nft delete table inet novavpn 2>/dev/null || true
nft -f /etc/novavpn-node/novavpn.nft
```

- [ ] **Step 4: Юнит и обработчики**

`templates/novavpn-node.service.j2`:

```ini
[Unit]
Description=NovaVPN node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{ novavpn_node_user }}
Group={{ novavpn_node_user }}
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
EnvironmentFile={{ novavpn_node_config_dir }}/agent.env
StateDirectory=novavpn-node
StateDirectoryMode=0700
UMask=0077
ExecStart={{ novavpn_node_bin }} run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`StateDirectory` создаёт каталог с нужным владельцем и правами сам; `ProtectSystem=strict`
запрещает запись вне `StateDirectory`, поэтому состояние и ключ не могут оказаться в
`/tmp` или рядом с бинарником. `CAP_NET_RAW` нужен `wgctrl` для сокета, `CAP_NET_ADMIN` —
для создания устройства и пиеров.

`handlers/main.yml`:

```yaml
- name: Применить sysctl
  ansible.builtin.command: sysctl --system
  changed_when: true

- name: Применить nftables
  ansible.builtin.command: "{{ novavpn_node_lib_dir }}/novavpn-nft-apply.sh"
  changed_when: true

- name: Перезагрузить systemd
  ansible.builtin.systemd:
    daemon_reload: true
```

Обработчик **не** перезапускает агент: на первом прогоне узел ещё не зарегистрирован, и
`restart` дал бы цикл падений «узел не зарегистрирован». Перезапуск делает `deploy.yml`
после enroll и только при наличии `state.json` — при `novavpn_node_enroll=false` (умолчание
первого прогона) агент не стартует вовсе.

- [ ] **Step 5: Регистрация узла**

`tasks/enroll.yml`:

```yaml
- name: Состояние узла
  ansible.builtin.stat:
    path: "{{ novavpn_node_state_dir }}/state.json"
  register: node_state

- name: Показать публичный ключ для создания сервера
  ansible.builtin.command: "{{ novavpn_node_bin }} init"
  become: true
  become_user: "{{ novavpn_node_user }}"
  register: node_init
  changed_when: false
  when: not node_state.stat.exists

- name: Публичный ключ узла
  ansible.builtin.debug:
    msg: "{{ node_init.stdout_lines }}"
  when: not node_state.stat.exists

- name: Прочитать bootstrap-токен
  ansible.builtin.slurp:
    src: "{{ novavpn_node_bootstrap_file }}"
  register: node_bootstrap
  no_log: true
  when: not node_state.stat.exists and novavpn_node_enroll | bool

- name: Зарегистрировать узел токеном из stdin
  ansible.builtin.command:
    cmd: "{{ novavpn_node_bin }} enroll"
    stdin: "{{ node_bootstrap.content | b64decode }}"
    creates: "{{ novavpn_node_state_dir }}/state.json"
  become: true
  become_user: "{{ novavpn_node_user }}"
  no_log: true
  when: not node_state.stat.exists and novavpn_node_enroll | bool
```

Токен идёт в stdin, а не в argv: `argv` виден в `ps` любому пользователю хоста. Команда
выполняется от `novavpn`, поэтому `state.json` получает нужного владельца; `slurp` читает
файл от root, и права `0600 root:root` у токена не приходится ослаблять.

- [ ] **Step 6: Обновление бинарника и авто-откат**

`files/novavpn-rollback.sh`:

```bash
#!/usr/bin/env bash
# Откат по факту: новый агент обязан оставаться активным. Свежесть state.json
# критерием не годится — при недоступном API состояние не переписывается, и
# исправный агент был бы откачен за то, что API молчал.
set -euo pipefail
bin=/usr/local/bin/novavpn-node-agent
if [ ! -x "$bin.prev" ]; then exit 0; fi
if systemctl is-active --quiet novavpn-node-agent; then exit 0; fi
systemctl stop novavpn-node-agent || true
mv -f "$bin.prev" "$bin"
systemctl start novavpn-node-agent
logger -t novavpn-rollback "агент не удержался активным; возвращён предыдущий бинарник"
```

`tasks/deploy.yml`:

```yaml
- name: Текущий бинарник на узле
  ansible.builtin.stat:
    path: "{{ novavpn_node_bin }}"
  register: node_bin_current

- name: Сохранить предыдущий бинарник для отката
  ansible.builtin.copy:
    src: "{{ novavpn_node_bin }}"
    dest: "{{ novavpn_node_bin }}.prev"
    remote_src: true
    mode: "0755"
  when: node_bin_current.stat.exists
  changed_when: false

- name: Положить новый бинарник рядом
  ansible.builtin.copy:
    src: "{{ novavpn_node_binary_src }}"
    dest: "{{ novavpn_node_bin }}.new"
    owner: root
    group: root
    mode: "0755"

- name: Заменить бинарник
  ansible.builtin.copy:
    src: "{{ novavpn_node_bin }}.new"
    dest: "{{ novavpn_node_bin }}"
    remote_src: true
    mode: "0755"
  register: node_bin_installed

- name: Убрать временную копию
  ansible.builtin.file:
    path: "{{ novavpn_node_bin }}.new"
    state: absent

- name: Включить агент в автозапуск
  ansible.builtin.systemd:
    name: novavpn-node-agent
    enabled: true
    daemon_reload: true

- name: Состояние регистрации узла
  ansible.builtin.stat:
    path: "{{ novavpn_node_state_dir }}/state.json"
  register: node_registration

- name: Перезапустить агент
  ansible.builtin.systemd:
    name: novavpn-node-agent
    state: restarted
  when: node_registration.stat.exists

- name: Взвести таймер отката
  ansible.builtin.command:
    cmd: >-
      systemd-run --unit=novavpn-rollback-{{ ansible_facts.date_time.epoch }}
      --on-active={{ novavpn_node_rollback_delay_sec }}
      {{ novavpn_node_lib_dir }}/novavpn-rollback.sh
  changed_when: true
  when: node_registration.stat.exists

- name: Дождаться активного состояния
  ansible.builtin.command: systemctl is-active --quiet novavpn-node-agent
  register: node_active
  until: node_active.rc == 0
  retries: 20
  delay: 3
  changed_when: false
  when: node_registration.stat.exists

- name: Локальное состояние узла
  ansible.builtin.command: "{{ novavpn_node_bin }} status"
  register: node_status
  changed_when: false
  when: node_registration.stat.exists

- name: Состояние узла
  ansible.builtin.debug:
    msg: "{{ node_status.stdout_lines }}"
  when: node_registration.stat.exists

- name: Снять таймер отката после успешного старта
  ansible.builtin.systemd:
    name: "novavpn-rollback-{{ ansible_facts.date_time.epoch }}.timer"
    state: stopped
  failed_when: false
  when: node_registration.stat.exists
```

Порядок здесь — суть отката: таймер взводится **после** `restart`, поэтому отсчёт идёт
от новой попытки, а снимается только после того, как юнит стал `active` и `status`
прочитал состояние. Если новый бинарник падает, таймер через 180 с вернёт `.prev` и
поднимет агент — без участия человека и без «зайти и посмотреть». На первом прогоне этот
же `restart` подхватывает `state.json`, созданный в `enroll.yml`: до него агент не
запускался вовсе.

Флаг `node_registration` отделяет два первых прогона друг от друга. Первый идёт с
`novavpn_node_enroll=false`: бинарник ставится, `init` печатает публичный ключ, агент не
стартует — и `is-active` не ждёт `active` у юнита, который заведомо падает. Второй прогон
(после выдачи токена) регистрирует узел, и тогда `restart`, таймер отката и `status`
выполняются. Без этого условия прогон с умолчаниями висел бы 60 с и падал на ожидании.

`tasks/deploy.yml` не проверяет трафик и не смотрит в API: это работа стенда E2E и
телеметрии. Роль честно проверяет только то, что может проверить локально.

- [ ] **Step 7: `site.yml`**

```yaml
- name: NovaVPN — узел
  hosts: novavpn_nodes
  become: true
  gather_facts: true
  roles:
    - novavpn_node
```

Роль `unbound` добавляется в список в задаче 15 — после того, как у неё появляется
конфиг без журнала запросов.

- [ ] **Step 8: `.gitignore` и цель `ansible-lint`**

В `.gitignore` рядом со строкой про `*.retry`:

```
infrastructure/ansible/inventory.ini
artifacts/
```

В `Makefile`:

```make
# Статическая проверка без хоста: syntax-check всего playbook и линт роли.
# Версии закреплены, чтобы «линт прошёл» не означало «прошёл на другой версии».
ansible-lint:
	MSYS_NO_PATHCONV=1 docker run --rm -v "$(CURDIR):/work" -w /work python:3.12-slim \
	  sh -c 'pip install --quiet ansible-core==2.17.6 ansible-lint==24.10.0 && \
	    ansible-playbook -i infrastructure/ansible/inventory.example.ini \
	      infrastructure/ansible/site.yml --syntax-check && \
	    ansible-lint infrastructure/ansible'
```

Добавить `ansible-lint` в `.PHONY`.

- [ ] **Step 9: Прогнать**

Run: `make ansible-lint`
Expected: `--syntax-check` печатает `playbook: infrastructure/ansible/site.yml` и
завершается с кодом 0; `ansible-lint` завершается с кодом 0 без `Failed`/`Error`.
Если линт требует правок стиля (например, `no-changed-when` на `command`), правки
вносятся в роль, а не в список исключений.

Реальный прогон роли на хосте здесь **не** выполняется: узла нет до задачи 19. Строка
`not-run` добавляется в `docs/testing-status.md` в задаче 18 вместе с остальными.

- [ ] **Step 10: Коммит**

```bash
git add .gitignore Makefile infrastructure/ansible
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): роль узла — systemd, sysctl, nftables и авто-откат по таймеру"
```

---

### Task 15: unbound в проде, проверки хоста, runbooks

На стенде unbound форвардит в dnsmasq, потому что интернет-выход стенда не гарантирован.
В проде он обязан рекурсивно разрешать сам: форвардер — это чужой резолвер, который видит
все запросы пользователей, и §8 запрещает отдавать их наружу. Роль ставит рекурсию с
DNSSEC, тот же запрет журнала запросов и тот же ACL, что проверен на стенде; разница
между стендом и продом записывается явно, а не замалчивается.

`scripts/preflight.sh` проверяет хост **до** установки (ядро, порты, время, занятость
каталога), потому что «роль отработала» и «хост годится» — разные утверждения.

**Files:**
- Create: `infrastructure/ansible/roles/unbound/defaults/main.yml`,
  `.../tasks/main.yml`, `.../handlers/main.yml`, `.../templates/unbound.conf.j2`
- Modify: `infrastructure/ansible/site.yml` (роль `unbound`), `Makefile` (цель
  `unbound-check`)
- Create: `scripts/preflight.sh`, `scripts/backup-verify.sh`
- Create: `docs/runbooks/node-deploy.md`, `docs/runbooks/node-drain.md`,
  `docs/runbooks/revoke-a-key-now.md`, `docs/runbooks/incident.md`
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§13)

- [ ] **Step 1: Роль `unbound`**

`roles/unbound/defaults/main.yml`:

```yaml
unbound_num_threads: 2
unbound_msg_cache: 32m
unbound_rrset_cache: 64m
```

`roles/unbound/tasks/main.yml`:

```yaml
- name: Пакет unbound
  ansible.builtin.apt:
    name: unbound
    state: present
    update_cache: true

- name: Каталог доверенного ключа DNSSEC
  ansible.builtin.file:
    path: /var/lib/unbound
    state: directory
    owner: unbound
    group: unbound
    mode: "0755"

- name: Начальный файл доверенного ключа
  ansible.builtin.command: unbound-anchor -a /var/lib/unbound/root.key
  args:
    creates: /var/lib/unbound/root.key
  register: unbound_anchor
  # Код 1 — «якорь записан», а не отказ: проверено на alpine:3.20 с unbound 1.20,
  # первый вызов вернул 1 и оставил валидный root.key, повторный — 0. Модуль command
  # считает любой непустой код ошибкой, и без failed_when роль падала бы на первом
  # прогоне при уже созданном файле.
  failed_when: unbound_anchor.rc not in [0, 1]
  changed_when: unbound_anchor.rc == 1

- name: Якорь DNSSEC на месте
  ansible.builtin.stat:
    path: /var/lib/unbound/root.key
  register: unbound_anchor_file

- name: Без якоря валидация DNSSEC не поднимется
  ansible.builtin.assert:
    that:
      - unbound_anchor_file.stat.exists
      - unbound_anchor_file.stat.size > 0
    fail_msg: "unbound-anchor не создал /var/lib/unbound/root.key"

- name: Отключить stub-резолвер systemd (он занимает 127.0.0.53:53)
  ansible.builtin.copy:
    dest: /etc/systemd/resolved.conf.d/novavpn-no-stub.conf
    content: |
      [Resolve]
      DNSStubListener=no
    owner: root
    group: root
    mode: "0644"
  notify: Перезапустить systemd-resolved

- name: Тип файла resolv.conf
  ansible.builtin.stat:
    path: /etc/resolv.conf
    follow: false
  register: unbound_resolv

- name: Убрать символическую ссылку resolv.conf
  ansible.builtin.file:
    path: /etc/resolv.conf
    state: absent
  when: unbound_resolv.stat.islnk | default(false)

- name: Резолвер хоста — собственный unbound
  ansible.builtin.copy:
    dest: /etc/resolv.conf
    content: |
      nameserver 127.0.0.1
      options edns0 trust-ad
    owner: root
    group: root
    mode: "0644"

- name: Конфигурация unbound
  ansible.builtin.template:
    src: unbound.conf.j2
    dest: /etc/unbound/unbound.conf
    owner: root
    group: root
    mode: "0644"
  notify: Перезагрузить unbound

- name: Служба unbound
  ansible.builtin.systemd:
    name: unbound
    enabled: true
    state: started
```

`roles/unbound/templates/unbound.conf.j2`:

```jinja
# Рекурсия от корня, DNSSEC включён. Форвардера нет: на стенде он есть только
# потому, что у стенда нет гарантированного выхода в интернет, и это ограничение
# стенда, а не свойство unbound.
server:
    verbosity: 1
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    prefer-ip4: yes
    do-udp: yes
    do-tcp: yes
    username: "unbound"
    directory: "/etc/unbound"
    chroot: ""
    logfile: ""
    use-syslog: no
    # §8: содержимое запросов не журналируется ни в какой форме.
    log-queries: no
    log-replies: no
    log-local-actions: no
    log-servfail: no
    extended-statistics: no
    # Отвечаем только клиентам туннеля; всё остальное — отказ.
    access-control: {{ novavpn_node_pool }} allow
    access-control: 0.0.0.0/0 refuse
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    minimal-responses: yes
    prefetch: yes
    rrset-roundrobin: yes
    edns-buffer-size: 1232
    max-udp-size: 1232
    num-threads: {{ unbound_num_threads }}
    msg-cache-size: {{ unbound_msg_cache }}
    rrset-cache-size: {{ unbound_rrset_cache }}
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    val-clean-additional: yes

remote-control:
    control-enable: no
```

`interface: 0.0.0.0` выбран сознательно: адрес туннеля появляется только после того, как
агент создаст устройство, а bind на ещё не существующий адрес — это startup-гонка.
Цена решения — сокет слушает и на публичном адресе, поэтому **хостовый firewall обязан
дропать 53/udp и 53/tcp с uplink**, а ACL отвечает `refuse` всем не из пула. Оба слоя
проверяются: ACL — стендом, firewall — preflight и runbook.

`roles/unbound/handlers/main.yml`:

```yaml
- name: Проверить конфигурацию unbound
  ansible.builtin.command: unbound-checkconf /etc/unbound/unbound.conf
  changed_when: false
  listen: Перезагрузить unbound

- name: Перезапустить unbound
  ansible.builtin.systemd:
    name: unbound
    state: restarted
  listen: Перезагрузить unbound

- name: Перезапустить systemd-resolved
  ansible.builtin.systemd:
    name: systemd-resolved
    state: restarted
  failed_when: false
```

Два обработчика на один `listen` выполняются в порядке объявления: сначала проверка, потом
перезапуск. Иначе опечатка в шаблоне гасит DNS на узле — а с ним и разрешение имени API.

- [ ] **Step 2: Добавить роль в `site.yml`**

```yaml
  roles:
    - novavpn_node
    - unbound
```

- [ ] **Step 3: Рендер и проверка конфигурации**

В `Makefile`:

```make
# Рендер шаблона реальным Jinja и проверка синтаксиса настоящим unbound-checkconf:
# так «конфиг валиден» означает проверку, а не чтение глазами.
unbound-check:
	MSYS_NO_PATHCONV=1 docker run --rm -v "$(CURDIR):/work" -w /work python:3.12-slim \
	  sh -c 'pip install --quiet ansible-core==2.17.6 && mkdir -p .scratch && \
	    ansible localhost -c local -m ansible.builtin.template \
	      -a "src=/work/infrastructure/ansible/roles/unbound/templates/unbound.conf.j2 dest=/work/.scratch/unbound.rendered.conf" \
	      -e @/work/infrastructure/ansible/roles/unbound/defaults/main.yml \
      -e novavpn_node_pool=10.99.7.0/24'
	MSYS_NO_PATHCONV=1 docker run --rm \
	  -v "$(CURDIR)/.scratch/unbound.rendered.conf:/conf/unbound.conf:ro" alpine:3.20 \
	  sh -c 'apk add --no-cache unbound >/dev/null && \
	    mkdir -p /var/lib/unbound && \
	    unbound-anchor -a /var/lib/unbound/root.key; \
	    [ $$? -le 1 ] && \
	    grep -qE "^[[:space:]]*log-queries:[[:space:]]*no[[:space:]]*$$" /conf/unbound.conf && \
	    grep -qE "^[[:space:]]*log-replies:[[:space:]]*no[[:space:]]*$$" /conf/unbound.conf && \
	    unbound-checkconf /conf/unbound.conf'
```

Два `grep` перед `unbound-checkconf` — это и есть требование §9.4 «unbound в роли
конфигурируется без журнала запросов»: синтаксически верный конфиг с `log-queries: yes`
прошёл бы проверку синтаксиса и провалил бы это утверждение. `$$` в конце регулярки —
экранирование для make; в shell остаётся один `$`.

`-e @.../defaults/main.yml` подставляет значения роли: шаблон использует
`unbound_num_threads`, `unbound_msg_cache` и `unbound_rrset_cache`, и без этого файла
рендер падал бы на неопределённой переменной, не дойдя до `unbound-checkconf`.

`unbound-anchor` перед проверкой обязателен, и это измерено, а не предположено: без
`root.key` шаблонный `auto-trust-anchor-file` даёт `fatal error: ...
does not exist`, с пустым файлом — `failed to read ... error in trustanchors config`,
и оба раза код 1. Настоящий якорь даёт `no errors`. Первый вызов `unbound-anchor`
возвращает 1 (якорь записан), повторный — 0, поэтому `[ $$? -le 1 ]` пропускает оба
кода и валит всё остальное.

Добавить `unbound-check` в `.PHONY`.

- [ ] **Step 4: `scripts/preflight.sh`**

```bash
#!/usr/bin/env bash
# Запускается на целевом хосте от root до установки: проверяет хост, а не роль.
set -euo pipefail
FAIL=0
ok()  { printf 'ok   %s\n' "$*"; }
bad() { FAIL=1; printf 'FAIL %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || bad "нужен root"
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ok "ОС: ${PRETTY_NAME:-$ID}" ;;
  *) bad "ОС ${PRETTY_NAME:-неизвестна}: роль рассчитана на Debian/Ubuntu" ;;
esac

KVER=$(uname -r | cut -d- -f1)
if printf '%s\n%s\n' "5.6" "$KVER" | sort -V -C; then
  ok "ядро $KVER не старше 5.6 (WireGuard в ядре)"
else
  bad "ядро $KVER старше 5.6: WireGuard в ядре недоступен"
fi

if modprobe wireguard 2>/dev/null; then ok "модуль wireguard загружается"; else bad "модуль wireguard недоступен"; fi

if ss -lunptH 2>/dev/null | grep -qE ':(53|51820)([[:space:]]|$)'; then
  bad "порт 53 или 51820 уже занят"
else
  ok "порты 53 и 51820 свободны"
fi

if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then
  ok "часы синхронизированы"
else
  bad "часы не синхронизированы: DNSSEC и TLS требуют верного времени"
fi

API_HOST=${1:-api.novavpn.example}
if getent hosts "$API_HOST" >/dev/null; then ok "имя $API_HOST разрешается"; else bad "имя $API_HOST не разрешается"; fi

command -v nft >/dev/null && ok "nftables есть" || bad "нет команды nft"
command -v ss  >/dev/null && ok "iproute2 есть" || bad "нет команды ss"

if [ -n "$(ls -A /var/lib/novavpn-node 2>/dev/null || true)" ]; then
  bad "/var/lib/novavpn-node не пуст: узел, возможно, уже установлен"
else
  ok "каталог состояния пуст"
fi

USED=$(df -P / | awk 'NR==2 { gsub("%", "", $5); print $5 }')
if [ "${USED:-100}" -lt 90 ]; then ok "корень занят на ${USED} %"; else bad "корень занят на ${USED} %: меньше 90 % обязательно"; fi

if [ "$FAIL" -ne 0 ]; then
  printf '\nпредварительная проверка не пройдена: установку не начинать\n' >&2
  exit 1
fi
printf '\nхост готов\n'
```

Параметр — имя API-хоста, чтобы проверка резолва не была привязана к примеру. `ss` без
`-H` на старых версиях печатает заголовок; `-H` есть в iproute2 с 4.11, и preflight
проверяет наличие `ss` отдельно.

- [ ] **Step 5: `scripts/backup-verify.sh`**

```bash
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

docker run -d --rm --name "$name" -e POSTGRES_PASSWORD=verify -e POSTGRES_DB=verify \
  postgres:17 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name" pg_isready -U postgres -q && break
  sleep 1
done
docker exec -i "$name" pg_restore -U postgres -d verify --no-owner --exit-on-error < "$dump"
users=$(docker exec "$name" psql -U postgres -d verify -tAc 'select count(*) from users')
servers=$(docker exec "$name" psql -U postgres -d verify -tAc 'select count(*) from vpn_servers')
printf 'ok   дамп восстановлен: users=%s vpn_servers=%s\n' "$users" "$servers"
```

- [ ] **Step 6: Runbooks**

Четыре файла, каждый — короткая последовательность с командами и **ожидаемым** выводом;
ни один шаг не говорит «убедитесь, что работает» без команды.

`docs/runbooks/node-deploy.md`:

1. Предусловия: VPS Debian 12/Ubuntu 24.04, DNS-имя API, SSH-ключ (`ssh-ed25519`, файл
   вне репозитория), доступ администратора API.
2. `ssh root@HOST 'bash -s' -- api.novavpn.example < scripts/preflight.sh` — ожидается
   `хост готов`, код 0.
3. Сборка артефакта на сборочной машине (в контейнере `golang:1.25-alpine`, как в
   `Dockerfile.node-agent`; `GOOS`/`GOARCH` — потому что сборка идёт с Windows/WSL, а не
   на узле): `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w
   -X main.version=$(git rev-parse --short HEAD)" -o artifacts/novavpn-node-agent-linux-amd64
   ./services/node-agent/cmd/novavpn-node-agent`.
   Без `-X` узел отчитывается версией `dev`, и «какая версия стоит на узле» не отвечает
   ни на что.
4. Инвентарь: `cp inventory.example.ini inventory.ini`, заполнить хост, `schema` и
   отпечаток ключа сверить с панелью хостера.
5. Первый прогон с `novavpn_node_enroll=false`: ставит пакеты, sysctl, nft, юнит и
   бинарник, печатает `public_key <BASE64>`; агент не запускается — регистрации ещё нет.
6. Администратор создаёт сервер с этим ключом и выдаёт bootstrap-токен; токен
   копируется на узел файлом `0600 root:root`; в инвентаре `novavpn_node_enroll=true`.
7. Второй прогон регистрирует узел, обновляет бинарник, взводит таймер отката, запускает
   агент и печатает `status`.
8. Проверка: `journalctl -u novavpn-node-agent -n 30 --no-pager` без `узел не
   зарегистрирован`; `wg show wg0` содержит listen-port 51820; `unbound-checkconf` — 0;
   `dig @10.99.7.1 example.com` отвечает; `curl ifconfig.me` с клиента даёт адрес узла.
9. Если через 180 с агент не активен — в журнале `novavpn-rollback` запись о возврате
   `.prev`; разбор начинается с `journalctl -u novavpn-node-agent` **до** повторного
   прогона, иначе улики затираются.
10. Строка о прогоне — в `docs/testing-status.md`: либо `проверено <дата> <команда>`,
    либо `not-run`.

`docs/runbooks/node-drain.md`:

1. `POST /api/v1/admin/servers/{id}/maintenance {"status":"draining"}` — узел снимает
   пиеров на следующем опросе (≤ 27,5 с, замер — стенд).
2. Проверка: `wg show wg0 peers` пуст; `GET /admin/servers/{id}` показывает `draining`.
3. Пользователям: переключиться на другой сервер (выдача профиля — новый сервер).
4. Только после этого `systemctl stop novavpn-node-agent`; сервер не удалять, пока у
   профилей есть адреса — `DELETE /admin/servers/{id}` отказывает, если профили живы.
5. Возврат: `{"status":"online"}` — тот же набор возвращается на следующем опросе.

`docs/runbooks/revoke-a-key-now.md`:

1. Владелец устройства: `DELETE /api/v1/devices/{id}` (или
   `DELETE /api/v1/devices/{id}/profiles/{server_id}`); критерий — пиер исчезает
   ≤ 30 с (измерено стендом в задаче 13).
2. Проверка: `wg show wg0 peers` без ключа; в API — `connections` события
   `handshake_observed` прекращаются; трафик с устройства не идёт.
3. Если владелец недоступен: администратор переводит **сервер** в `draining` — это
   снимает всех пиеров сервера и является единственной немедленной мерой в контракте
   A-2. Точечного отзыва чужого устройства у администратора нет (ограничение §13).
4. После закрытия инцидента: сервер `online`, владельцу — новый профиль (старый
   отозван; новый ключ — `keys/rotate`).

`docs/runbooks/incident.md`:

1. Зафиксировать факты до действий: `systemctl status novavpn-node-agent --no-pager`,
   `journalctl -u novavpn-node-agent -n 100 --no-pager`, `wg show wg0`,
   `GET /api/v1/admin/servers/{id}` (поле `health.status`). Любое действие до снятия
   этих данных затирает улики.
2. Узел не выходит на связь: `health.status = stale` при живом процессе — проверить
   `journalctl` на `desired set недоступен` и TLS-ошибки; **не** перезапускать агент
   до прочтения журнала: после перезапуска причина первого сбоя уже не в журнале.
3. Узел потерян или скомпрометирован: `POST /api/v1/admin/servers/{id}/node-token/revoke`
   — гасит узловые токены, поднимает `config_version` и переводит сервер в `draining`.
   Ответ `204`, в аудите `node_token_revoked`. Новый узел ставится по
   `node-deploy.md` с **новым** ключом: старый серверный `public_key` менять нельзя,
   поэтому под новый узел создаётся новый сервер, а старый удаляется, когда у его
   профилей не осталось адресов.
4. Скомпрометирован ключ устройства пользователя — `revoke-a-key-now.md`; вход в
   аккаунт — `POST /api/v1/admin/users/{id}/lock`.
5. Итог инцидента: строка в журнал операций с временем, `server_id`, `reason` из аудита;
   если проверка не выполнялась — в `docs/testing-status.md` она остаётся `not-run`.

`docs/runbooks` не содержит секретов: только команды и пути; токены и ключи — в файлах
`0600` вне репозитория.

- [ ] **Step 7: Внести ограничение в спецификацию**

В §13 добавить пункт 16:

> 16. **Администратор не может отозвать отдельное устройство пользователя:** контракт
>     A-2 даёт отзыв устройства только владельцу. Немедленная мера администратора —
>     `draining` сервера (снимает всех пиеров), она и описана в runbook. Точечный отзыв
>     появится вместе с административной панелью; до этого обещать его в runbook было бы
>     ложью.

- [ ] **Step 8: Прогнать**

Run: `make ansible-lint && make unbound-check`
Expected: оба кода 0; `unbound-checkconf: no errors in /conf/unbound.conf`.

Run: `bash -n scripts/preflight.sh && bash -n scripts/backup-verify.sh`
Expected: код 0, вывода нет. Содержательная проверка preflight возможна только на
целевом хосте — это `not-run` до задачи 19.

- [ ] **Step 9: Коммит**

```bash
chmod +x scripts/preflight.sh scripts/backup-verify.sh
git add infrastructure/ansible Makefile scripts/preflight.sh scripts/backup-verify.sh \
  docs/runbooks docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): unbound в проде, preflight хоста, проверка дампов и runbooks"
```

---

### Task 16: TLS-фронт и проверка на утечки секретов

Контракт узла — только HTTPS, и `NOVAVPN_NODE_ALLOW_INSECURE_API` вне dev обязан
отказывать. Значит фронт обязан давать настоящий сертификат, а не «TLS внутри сети с
самоподписанным». Caddy выбран потому, что ACME и продление — не код, который мы
пишем: `caddy validate` проверяет конфигурацию без сети, а сам сертификат появляется
только на реальном домене.

Второй пункт — честный ответ на вопрос «а секретов в репозитории нет?»: скрипт, который
падает на приватном ключе, токене и флаге `ALLOW_INSECURE_API` вне стенда.

**Files:**
- Create: `infrastructure/docker/Caddyfile.example`
- Create: `scripts/leakcheck.sh`
- Modify: `Makefile` (цели `caddy-validate`, `leakcheck`)
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§13)

- [ ] **Step 1: `Caddyfile.example`**

```caddyfile
{
	# ACME без явного email не регистрируется: адрес нужен для уведомлений о
	# продлении и для отзыва сертификата.
	email ops@novavpn.example
	admin off
}

# Публичный API и внутренний контракт узла — один и тот же хост: у узла нет
# отдельного «доверенного» порта без TLS, он ходит на https:// и проверяет
# сертификат обычным образом (спецификация §4.4).
api.novavpn.example {
	encode zstd gzip

	reverse_proxy api:8080 {
		# API намеренно не читает X-Forwarded-For: этот заголовок контролирует
		# клиент, и доверие к нему позволило бы подделать ключ rate limit.
		# Заголовки ниже оставлены для журналов и диагностики, но IP в API —
		# адрес прокси (см. ограничение §13).
		header_up X-Real-IP {remote_host}
	}

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		-Server
	}

	log {
		output file /var/log/caddy/api.log {
			roll_size 10MiB
			roll_keep 5
		}
		format json
	}
}
```

Ни `tls internal`, ни `skip_verify`, ни `http://`-сайта здесь нет: стенд использует
`NOVAVPN_NODE_ALLOW_INSECURE_API` и только в `dev`, а прод получает сертификат от ACME.
Порт 80/tcp должен быть открыт для HTTP-01; если он закрыт — переходят на DNS-01
(`tls { dns … }`), и это изменение конфигурации, а не кода.

- [ ] **Step 2: `scripts/leakcheck.sh`**

```bash
#!/usr/bin/env bash
# Ищет в отслеживаемых файлах то, чего там быть не должно: приватные ключи,
# значения секретов, флаг отключения TLS и рабочие env-файлы.
set -euo pipefail
FAIL=0
ok()  { printf 'ok   %s\n' "$*"; }
bad() { FAIL=1; printf 'FAIL %s\n' "$*" >&2; }

keys=$(git grep -nIE -- 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' -- . || true)
if [ -n "$keys" ]; then printf '%s\n' "$keys"; bad "приватный ключ в отслеживаемых файлах"; else ok "PEM-ключей нет"; fi

wg=$(git grep -nIE -- '^[[:space:]]*PrivateKey[[:space:]]*=' -- . || true)
if [ -n "$wg" ]; then printf '%s\n' "$wg"; bad "WireGuard PrivateKey в файле репозитория"; else ok "PrivateKey в конфигах нет"; fi

envs=$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -vE 'example$' || true)
if [ -n "$envs" ]; then printf '%s\n' "$envs"; bad "рабочий env-файл под контролем версий"; else ok "рабочих env-файлов нет"; fi

jwt=$(git grep -nIE -- 'NOVAVPN_JWT_SECRET=[^[:space:]]+' -- . ':!*.example' ':!docs/**' || true)
if [ -n "$jwt" ]; then printf '%s\n' "$jwt"; bad "значение JWT-секрета в репозитории"; else ok "значений JWT-секрета нет"; fi

insecure=$(git grep -nIE -- 'NOVAVPN_NODE_ALLOW_INSECURE_API' -- infrastructure/ansible infrastructure/docker/Caddyfile.example || true)
if [ -n "$insecure" ]; then printf '%s\n' "$insecure"; bad "флаг отключения TLS в прод-конфигурации"; else ok "флага отключения TLS в проде нет"; fi

if [ "$FAIL" -ne 0 ]; then printf '\nпроверка не пройдена\n' >&2; exit 1; fi
ok "утечек не найдено"
```

Скрипт проверяет **рабочее дерево**, а не всю историю: `git log -p` по большому
репозиторию занимает минуты и в CI не годится. История проверяется отдельно перед
публикацией репозитория — это записано в runbook развёртывания.

- [ ] **Step 3: Цели Makefile**

```make
# Проверка конфигурации фронта без сети: сертификат здесь не выпускается.
caddy-validate:
	MSYS_NO_PATHCONV=1 docker run --rm \
	  -v "$(CURDIR)/infrastructure/docker:/etc/caddy:ro" caddy:2.8.4-alpine \
	  caddy validate --config /etc/caddy/Caddyfile.example --adapter caddyfile

leakcheck:
	bash scripts/leakcheck.sh
```

Добавить `caddy-validate leakcheck` в `.PHONY`.

- [ ] **Step 4: Ограничение про адрес за прокси**

В §13 добавить пункт 17:

> 17. **Rate limit по IP за TLS-фронтом считается по адресу прокси:** API не читает
>     `X-Forwarded-For` (заголовок контролирует клиент), а PROXY protocol в A-3 не
>     реализован. Пользовательские лимиты (по пользователю и по токену) работают как
>     раньше; лимит по IP превращается в общий на всех клиентов. Это осознанная цена
>     отказа доверять заголовку; настоящий адрес появится вместе с разбором PROXY
>     protocol в цикле B.

- [ ] **Step 5: Прогнать**

Run: `make caddy-validate && make leakcheck`
Expected: `Valid configuration` (код 0); `leakcheck` печатает шесть строк `ok` и
`утечек не найдено`, код 0.

- [ ] **Step 6: Коммит**

```bash
chmod +x scripts/leakcheck.sh
git add infrastructure/docker/Caddyfile.example scripts/leakcheck.sh Makefile \
  docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "feat(a3): TLS-фронт с ACME и проверка утечек секретов"
```

---

### Task 17: CI — линт, юнит, интеграция, уязвимости, E2E по требованию

CI повторяет локальные ворота, а не придумывает новые: те же `make`-цели, тот же
контейнер. E2E не идёт на hosted-раннере: там не гарантированы ни модуль `wireguard`,
ни `NET_ADMIN` у вложенного Docker, а «зелёный прогон, который ничего не проверил» хуже
честного `not-run`. Поэтому E2E — только `workflow_dispatch` на self-hosted раннере с
метками; отсутствие прогона фиксируется в `docs/testing-status.md`.

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `Makefile` (цели `vulncheck`, `actionlint`, агрегат `lint`)

- [ ] **Step 1: Цели `vulncheck`, `actionlint`, `lint`**

```make
# govulncheck закреплён по версии: «уязвимостей нет» должно означать проверку
# конкретным инструментом, а не тем, что скачалось сегодня.
vulncheck:
	MSYS_NO_PATHCONV=1 docker run --rm $(DOCKER_FLAGS) $(GO_IMAGE) \
	  sh -c 'go install golang.org/x/vuln/cmd/govulncheck@v1.1.3 && /go/bin/govulncheck ./...'

actionlint:
	MSYS_NO_PATHCONV=1 docker run --rm -v "$(CURDIR):/repo" -w /repo rhysd/actionlint:1.7.7

lint: vet api-lint actionlint ansible-lint unbound-check caddy-validate
```

Добавить `vulncheck actionlint lint fmt-check` в `.PHONY`.

- [ ] **Step 2: `.github/workflows/ci.yml`**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Форматирование
        run: make fmt-check
      - name: Вет
        run: make vet
      - name: Контракт API
        run: make api-lint
      - name: Workflow-файлы
        run: make actionlint
      - name: Ansible
        run: make ansible-lint
      - name: unbound
        run: make unbound-check
      - name: Caddy
        run: make caddy-validate

  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make unit

  integration:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_USER: nova
          POSTGRES_PASSWORD: nova
          POSTGRES_DB: novavpn
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U nova -d novavpn"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 20
      redis:
        image: redis:7
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 20
    steps:
      - uses: actions/checkout@v4
      # Схему создают миграции, а не тесты: интеграционные тесты пишут в готовые
      # таблицы (helpers_test.go), и на пустой базе первый же INSERT упал бы.
      # Файл окружения собирается из примера, секрет генерируется здесь и в
      # репозиторий не попадает.
      - name: Окружение
        run: |
          cp infrastructure/docker/.env.dev.example infrastructure/docker/.env.dev
          printf 'NOVAVPN_JWT_SECRET=%s\n' "$(head -c 32 /dev/urandom | base64)" \
            >> infrastructure/docker/.env.dev
      - name: Миграции
        run: make migrate-up
      - run: make integration

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Утечки секретов
        run: make leakcheck
      - name: Известные уязвимости
        run: make vulncheck

  e2e:
    # Только по требованию и только на машине с модулем wireguard: hosted-раннер
    # не даёт гарантий ни по модулю, ни по NET_ADMIN во вложенном Docker.
    if: github.event_name == 'workflow_dispatch'
    runs-on: [self-hosted, linux, novavpn-e2e]
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - name: Модуль wireguard
        run: sudo modprobe wireguard
      - name: Стенд E2E
        run: make e2e
```

`fmt-check` добавляется в `Makefile` рядом с `vet`:

```make
# gofmt, а не goimports: критерий — форматирование, а не порядок групп импортов,
# и лишний инструмент в воротах не должен решать, что считать правильным.
fmt-check:
	MSYS_NO_PATHCONV=1 docker run --rm $(DOCKER_FLAGS) $(GO_IMAGE) \
	  sh -c 'out=$$(gofmt -l .); if [ -n "$$out" ]; then printf "%s\n" "$$out"; exit 1; fi'
```

`fmt-check` — отдельный шаг CI, а не часть агрегата `lint`: при неотформатированном
файле он обязан падать, и это падение не должно маскировать остальные проверки.

Отличие от перечня работ §11: `migrations` не отдельный job, а шаг того же
`integration` — тот же образ, та же база, а сам цикл `up→down→up` проверяется тестом
`tests/integration/migrations_test.go` внутри `make integration`. Двух job'ов на одну
базу было бы два разных прогона миграций, и расхождение между ними ничего не значило бы.

- [ ] **Step 3: Прогнать локально то, что проверяемо локально**

Run: `make actionlint`
Expected: код 0, вывода нет (при ошибке — файл, строка и правило).

Run: `make vulncheck`
Expected: код 0 и строка `No vulnerabilities found.`; при находке — список с
`GO-2024-…` и код 1.

Run: `make lint`
Expected: код 0 по всем шести целям.

Сам workflow на GitHub в этой задаче **не** запускается: пуш — только по явному
разрешению пользователя. Строка `CI: not-run` идёт в `docs/testing-status.md` в задаче 18,
а не в отчёт «CI зелёный».

- [ ] **Step 4: Коммит**

```bash
git add .github/workflows/ci.yml Makefile
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "ci(a3): линт, юнит, интеграция, уязвимости и E2E по требованию"
```

---

### Task 18: Приёмка — полный прогон, матрица критериев, честный статус

Приёмка не пишет «готово»: она перечисляет критерии §1.3, для каждого — команду и её
вывод, и отдельно — то, что не запускалось. Строка переезжает из «not-run» в
«проверено» **только** после успешного прогона в этой задаче; если прогон упал,
строка остаётся на месте с причиной, а задача не закрывается.

**Files:**
- Modify: `docs/testing-status.md`
- Modify: `docs/adr/README.md` (таблица ADR: 0009)
- Modify: `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (только
  если прогон выявил расхождение с §7.3/§13 — правки уже внесены в задачах 13–16)

- [ ] **Step 1: Полный прогон ворот**

```bash
make fmt-check
make vet
make unit
make up-dev && make integration && make down-dev
make api-lint
make actionlint
make ansible-lint
make unbound-check
make caddy-validate
make leakcheck
make vulncheck
```

Expected: каждая команда — код 0. `make vulncheck` печатает `No vulnerabilities found.`
(`Vulnerability #0` при находке). Вывод каждой команды сохраняется в
`.scratch/acceptance/<имя>.log`, потому что в таблицу идёт не «прошло», а команда.

- [ ] **Step 2: Прогон стенда**

```bash
make e2e
```

Expected: код 0; в выводе фазы `setup`, `tunnel`, `dns`, `limit`, `lifecycle`; строки
`egress = 172.31.98.2 (адрес узла, не клиента)`, `на eth0 клиента нет ни одного
DNS-пакета` и две строки с числами из замера — `измеренная пауза при смене ключа: …`,
`отзыв применился за … с`.
Если модуль `wireguard` на хосте не загружен, стенд падает — и это фиксируется как
`not-run` с текстом ошибки, а не как «стенд есть, но не запускался».

- [ ] **Step 3: Обновить `docs/testing-status.md` — перенос строк**

Правило: строка переезжает в «Проверено» только если команда из Step 1–2 прошла в этом
прогоне. Переносятся:

| что | чем подтверждено | как повторить |
| --- | --- | --- |
| Реальная работа туннеля: handshake, ICMP, трафик через узел, egress = адрес узла | `make e2e`, фаза `tunnel` | `make e2e` |
| Ротация ключа: адрес у активного ключа, старый без адреса, пауза измерена числом | `make e2e`, фаза `lifecycle` | `make e2e` |
| Отзыв: пиер снят, трафик остановился, время ≤ 30 с | `make e2e`, фаза `lifecycle` | `make e2e` |
| `draining` и возврат в `online`: пиеры 0, затем пиер и трафик вернулись | `make e2e`, фаза `lifecycle` | `make e2e` |
| Отказ API: пиеры на месте, трафик идёт, журнал узла фиксирует недоступность desired set | `make e2e`, фаза `lifecycle` | `make e2e` |
| Рестарт узла: тот же ETag, набор применён заново, пиер и трафик вернулись | `make e2e`, фаза `lifecycle` | `make e2e` |
| DNS: ответ от резолвера узла, ноль DNS-пакетов на eth0 клиента, отказ из сети без туннеля | `make e2e`, фаза `dns`; спайк S2 | `make e2e` |
| IPv6 на клиенте: нет глобального адреса, нет default route, нет пути наружу | `make e2e`, фаза `dns` | `make e2e` |
| Лимит устройств: третье 201, четвёртое 409 `device_limit_reached` | `make e2e`, фаза `limit` | `make e2e` |
| `agent_version`/`agent_uptime_sec` переживают observed-отчёт | `TestTelemetryHeartbeatPreservesObservedAndViceVersa` | `make integration` |
| Дельта пиеров: неизменённый пиер не попадает в netlink, отзыв — `Remove: true` | `internal/nodeagent/wg/diff_test.go`, `applier_test.go` | `make unit` |
| Состояние узла: ключ `0600`, атомарная запись, нет приватного ключа в `state.json` | `internal/nodeagent/state/state_test.go` | `make unit` |
| Клиент узла: проверка TLS, отказ `ALLOW_INSECURE_API` вне dev, 304, отказы API | `internal/nodeagent/api/client_test.go`, `services/node-agent/cmd/.../main_test.go` | `make unit` |
| Конфигурация Ansible, unbound и Caddy: синтаксис и линт | `make ansible-lint`, `make unbound-check`, `make caddy-validate` | те же команды |
| Утечки секретов в рабочем дереве | `make leakcheck` | `make leakcheck` |
| Известные уязвимости зависимостей | `make vulncheck` | `make vulncheck` |

Удаляются из «not-run» строки, которые эти заменяют: «Реальная работа туннеля»,
«Поведение узла при `draining` и при снятии пиера», «`agent_version`/`agent_uptime_sec`
в каталоге» (исходная причина была неверной: `MarkObservedHealth` эти поля не трогает,
что и доказывает тест; `UpsertServerHealth` — наполнение тестов, а не боевой путь),
«DNS: локальный recursor unbound…».

Строка «node-agent как демон, Ansible-раскатка, systemd-юнит, TLS между узлом и API»
заменяется двумя:

| что | почему не проверялось | где появится |
| --- | --- | --- |
| Раскатка Ansible на реальный хост, systemd-юнит в бою, повторный прогон без изменений | роль проверена линтом и `--syntax-check`; хоста не было | цикл A-3, при доступе к VPS (задача 19) |
| Сертификат ACME на реальном домене и TLS-фронт в бою | `caddy validate` проверяет конфигурацию, а не выпуск сертификата | цикл A-3, при доступе к VPS (задача 19) |

- [ ] **Step 4: Добавить новые `not-run` строки**

| что | почему не проверялось | где появится |
| --- | --- | --- |
| Прогон CI на GitHub | workflow проверен `actionlint`; пуш не делался | после разрешения на пуш |
| E2E на self-hosted раннере | раннера с меткой `novavpn-e2e` нет | после появления раннера |
| Пауза при ротации на реальной сети и VPS | измерена только на стенде (число — из вывода фазы `lifecycle`) | задача 19 |
| Внешняя правка интерфейса при живом агенте (ограничение §13.15) | поведение 304 задокументировано, отдельного теста нет | цикл B (периодический полный сверочный опрос) |
| Rate limit по IP за TLS-фронтом (ограничение §13.17) | PROXY protocol не реализован; стенд работает без прокси | цикл B |
| SBOM и подпись образов | в A-3 только `govulncheck` и `leakcheck` | цикл C |
| Восстановление дампа на боевом объёме | `scripts/backup-verify.sh` проверяет структуру и восстановление в пустую базу, не объём | цикл C |

- [ ] **Step 5: Матрица критериев A-3**

В конец `docs/testing-status.md` — раздел с шестью критериями §1.3, каждый строкой
«критерий → чем подтверждён → где не подтверждён»:

```markdown
## Критерии цикла A-3 (§1.3)

| критерий | подтверждение | не подтверждено |
| --- | --- | --- |
| 3. Туннель передаёт трафик, egress = адрес узла | `make e2e`, фаза `tunnel` | на реальном VPS — задача 19 |
| 4. Отзыв снимает пиера ≤ 30 с | `make e2e`, фаза `lifecycle` — секунды из вывода прогона | на реальной сети — задача 19 |
| 6. Ротация: адрес у активного ключа, пауза измерена | `make e2e`, фаза `lifecycle` — пауза из вывода прогона | нулевого разрыва не обещается (§13.14) |
| 7. DNS через узел, утечки нет, чужой сети отказ | `make e2e`, фаза `dns`; S2 | — |
| 8. IPv6-путь отсутствует | `make e2e`, фаза `dns` | — |
| 11. E2E и CI с явным `not-run` | этот файл; `make e2e`; `make actionlint` | прогон CI на GitHub — после пуша |
```

- [ ] **Step 6: Проверить алфавит в изменённых текстах**

```bash
python - <<'PY'
import pathlib, subprocess, unicodedata
files = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
bad = []
for name in files:
    if not name.endswith((".md", ".go", ".sh", ".yml", ".yaml", ".sql", ".j2", ".ini", ".example")):
        continue
    for ch in pathlib.Path(name).read_text(encoding="utf-8", errors="replace"):
        if not ch.isalpha():
            continue
        script = unicodedata.name(ch, "")
        if "CYRILLIC" in script or "LATIN" in script:
            continue
        bad.append((name, ch, unicodedata.name(ch, "?")))
print("чужих букв нет" if not bad else bad[:20])
PY
```

Expected: `чужих букв нет`. Проверка ищет буквы чужих письменностей, а не пунктуацию:
типографские кавычки и тире — часть русского текста, а иероглиф или арабская буква —
нет.

- [ ] **Step 7: Коммит**

```bash
git add docs/testing-status.md docs/adr/README.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "docs(a3): приёмка — матрица критериев и честный статус проверок"
```

---

### Task 19: Реальный VPS — только с явного согласия

Здесь заканчивается всё, что нельзя проверить на стенде: настоящее ядро, настоящий
интернет, ACME, systemd, повторный прогон роли. И начинается то, что нельзя делать
молча: действия на удалённом хосте.

**Правило входа:** ни одна команда на удалённом хосте не выполняется без явного
согласия пользователя на **конкретную операцию** (установка пакетов, правка sysctl и
nft, выпуск сертификата, публикация DNS-записи). Если согласия нет — задача
закрывается строкой `not-run` с причиной, а не отчётом «проверено».

**Files:**
- Modify: `docs/testing-status.md` (строки VPS: из «not-run» в «проверено» только
  фактическим прогоном, с числами)

- [ ] **Step 1: Спросить согласие и собрать вводные**

Нужны: адрес хоста, SSH-пользователь и ключ (файлом вне репозитория), домен API и
подтверждение, что DNS-запись для него управляется (сломанное делегирование
`cp.regruhosting.ru` ломает CAA и Let's Encrypt — сертификат берётся только на домен,
чей DNS действительно отвечает). Согласие фиксируется в задаче явно: какие действия
разрешены.

- [ ] **Step 2: Preflight и первый прогон без регистрации**

```bash
ssh root@HOST 'bash -s' -- api.DOMAIN < scripts/preflight.sh
ansible-playbook -i inventory.ini site.yml   # novavpn_node_enroll=false
```

Expected: `хост готов`; playbook завершается `failed=0`, печатает `public_key <BASE64>`.
Ключ передаётся администратору API; сервер создаётся с этим ключом, выдаётся
bootstrap-токен.

- [ ] **Step 3: Регистрация и запуск**

Токен — файлом `0600 root:root` на узле, `novavpn_node_enroll=true`, повторный прогон.

Expected: `status` печатает `server_id`, `applied.applied_at` не пуст; сервер в каталоге
`online`; `wg show wg0` содержит listen-port и хотя бы одного пиера после подключения
клиента.

Повторный прогон роли без изменений: в `changed` только три задачи, которые меняются по
своей природе, — «Положить новый бинарник рядом» (временный `.new`), «Перезапустить агент»
и «Взвести таймер отката». Любая другая задача в `changed` — дефект роли, а не «так
получилось»; `changed=0` целиком здесь недостижим и обещать его нельзя.

- [ ] **Step 4: Проверки через интернет**

С клиента (контейнер со стенда с профилем от этого сервера):

```bash
wg-quick up wg0
curl -sS https://ifconfig.me                       # адрес узла
dig +short example.com @10.99.7.1                  # ответ от unbound узла
ping -c 3 -W 2 1.1.1.1                             # ICMP через туннель
```

Затем — те же сценарии, что на стенде, но числом: отзыв (время до снятия пиера),
ротация (пауза), `draining` (время до нуля пиеров). Числа записываются в
`docs/testing-status.md` рядом с командой; если число хуже критерия — это дефект,
и он попадает в план исправлений, а не подгоняется.

- [ ] **Step 5: Откат и его проверка**

Смена бинарника на узле: повторный прогон с новой версией, затем имитация отказа
(`systemctl stop` сразу после старта или битый артефакт в тестовой ветке) — таймер
через 180 с обязан вернуть `.prev`, в журнале — запись `novavpn-rollback`.
Если проверка не делалась, строка «авто-откат проверен» **не** появляется.

- [ ] **Step 6: Статус и коммит**

В `docs/testing-status.md`: строки VPS переезжают в «Проверено» с датой, командами и
числами (egress, время отзыва, пауза ротации, idempotency). Всё, что не запускалось,
остаётся `not-run`. Секреты, ключи и токены в отчёт не попадают.

```bash
git add docs/testing-status.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
  commit -m "docs(a3): прогон на VPS — числа и честный статус"
```






