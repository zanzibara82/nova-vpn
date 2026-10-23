# NovaVPN — цикл A-2: профили, каталог, desired set, контракт узла, admin. План имплементации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Control plane, который выдаёт и отзывает VPN-профили (аллокация адреса под
блокировкой, готовый `[Interface]`/`[Peer]`), ротирует ключ устройства с overlap-окном без
разрыва, отдаёт узлу desired set по контракту `/internal/v1/*` с `ETag`/`304`, ведёт каталог
`/servers` с честными `null` вместо неизмеренных чисел, принимает от узла наблюдения и
сворачивает их в телеметрию, и даёт админу отдельную роль с аудитом каждой операции.

**Architecture:** Тот же модульный монолит `novavpn-api`. Новые модули: `servers` (каталог +
вычисление desired set), `connections` (выдача/отзыв профилей, аллокация адресов, рендер
конфига, sweeper), `nodeapi` (контракт с узлом: enroll, desired, observed, heartbeat,
token/rotate), `telemetry` (свёртка наблюдений в `server_health`, `device_day_traffic` и
события), `audit` (журнал админ-действий). `devices` дополняется отзывом устройства и ротацией
ключа. Ни netlink, ни агента в этом плане нет: сходимость контракта проверяется fake-узлом,
который говорит по настоящему HTTP против настоящего роутера (спецификация §9.2), а
фактическая передача трафика через туннель — цикл A-3.

**Tech Stack:** без изменений относительно A-1: Go `CGO_ENABLED=0`, pgx/v5 + sqlc 1.27.0,
golang-migrate/v4, golang-jwt/jwt/v5, go-redis/v9, `golang.org/x/crypto/argon2`. Новый
внешний код отсутствует намеренно: разбор и сборка WireGuard-конфига пишутся в `internal/`
своими силами (спец-раздел 9.1 требует round-trip и инъекционной стойкости, а не новой
зависимости).

**Spec:** [docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md](../specs/2026-10-20-novavpn-cycle-a-access-core-design.md)
— в первую очередь §4.1 (контракт узла и answer `desired`), §4.3 (тайминги и отказы), §5.1–5.2
(маршруты и сквозные требования), §6 (модель данных), §7.1–7.6 (последовательности), §9.1–9.2
(тест-стратегия), §13 (известные ограничения).

---

## Разбивка цикла A на планы

| План | Граница | Готовый, тестируемый результат |
|---|---|---|
| A-1 (**закрыт**, 33d19d0) | Схема + сессии + устройства | `POST /auth/*`, `GET /me`, `POST/GET /devices`, миграции `up→down→up`, лимит устройств |
| **A-2 (этот)** | Выдача/отзыв доступа + контракт с узлом | Выдача и отзыв профилей с аллокацией адреса, `DELETE /devices/{id}`, `keys/rotate` с overlap, `/servers`, desired set, `/internal/v1/*` против fake-узла по настоящему HTTP, admin-модуль с аудитом, телеметрия и retention |
| A-3 | Узел и стенд | `novavpn-node-agent` с настоящим netlink diff-apply (ADR-004), compose-harness с привилегированным узлом, E2E с инвариантом «неизменённый пиер не переподключается», Ansible-роль, CI, закрытие not-run строк wire-части |

Критерии приёмки спецификации §1.3, которые закрывает A-2: **3** (кроме wire-части: профиль
выдан, адрес уникален, конфиг собран), **4** (кроме wire-части: отзыв removes из desired set
за один цикл опроса), **6** (overlap-окно и снятие предка по наблюдаемому handshake — на
fake-узле), **10** (свойство desired set на случайных данных), **11** (в объёме A-2).
Критерии 7, 8 и wire-половина 3/4/6 — A-3; 1, 2, 5, 9 уже закрыты A-1.

Что A-2 **не** делает, чтобы это не потерялось по дороге: не поднимает WireGuard-устройство,
не трогает netlink, не ставит unbound, не раскатывает узел, не объявляет «туннель работает».
API сообщает, что профиль выдан (спецификация §7.1), и ни чем больше.

---

## Global Constraints

Значения дословно из спецификации и ТЗ; каждая задача неявно включает этот раздел.

- Все команды сборки и теста — только через `make` → `docker run` (на хосте нет Go).
  `make unit`, `make vet`, `make api-lint`, `make integration`; генерация запросов —
  `make sqlc-generate`. Прямой `go test` на хосте проверкой не является.
- Префиксы: `/api/v1` (публичный и admin), `/internal/v1` (узловой). Узловой контракт —
  **только** HTTPS в проде; проверка сертификата обязательна, флаг пропуска существует
  только в dev-harness и отказывается вне dev (ТЗ §19.8, спецификация §4.4).
- Единый формат ошибки `{"error":{"code":…,"message":…,"details":…,"request_id":…}}` на всех
  маршрутах, включая `/internal/v1` и admin; коды стабильны и добавляются, а не переименовываются.
- Язык сообщений: продукт русскоязычный. Сообщения прикладного HTTP-слоя — по-русски;
  инфраструктурные строки middleware (идемпотентность, лимиты) — по-английски; клиенты
  ориентируются на коды (спецификация §5.2, решение 2026-10-22).
- `Idempotency-Key` обязателен на `POST /devices`, `POST …/profiles`, `POST …/keys/rotate`
  (§5.2). Повтор → первый результат; конфликт тела → `409 idempotency_key_conflict`; повтор
  во время выполнения → `409 idempotency_key_in_progress`.
- Выдача профилей — 30/мин на пользователя; узловый префикс — по узлу (§5.2). Числа окон,
  которых в спецификации нет, — решение плана, зафиксированное одной строкой в коде
  (как в A-1: узловой префикс 120/мин, burst 10).
- Никаких приватных ключей нигде наружу: ни в HTTP-ответах, ни в desired set, ни в журнале,
  ни в фикстурах (ТЗ §10, §15, спецификация §3 правило 1). Приватного ключа узла в БД нет и
  быть не может; клиент приватный ключ устройства не присылает и не получает.
- Неизмеренные поля каталога (`latency_ms`, `load`) — `null`, никогда `0` и никогда
  «правдоподобное число» (§13.4). `availability` — из `server_health`, а не из догадки.
- Desired set содержит только `state ∈ {active, rotating_old_key}`; просроченный, отозванный
  и `superseded` с закрытым overlap отсутствует **ни при каких условиях** (§4.1) — это
  проверяется свойством на случайных данных, а не примером (§9.1).
- Интервал опроса desired — 30 с; отзыв, сделанный пока узел недоступен, применяется при его
  возврате (§4.3) — ограничение фиксируется, а не замалчивается.
- Retention: `connection_events` и `refresh_token_families.ip` — 90 дней, ежедневная задача
  (§6). Пер-пиерные счётчики байт — только Redis с TTL, в БД не лежат (ADR-006).
- В перенесённых частях (A-3, B–F) не создаётся ни заглушек, ни пустых директорий (ТЗ §19.3);
  невыполненная проверка помечается `not-run`, а не зелёным (ТЗ §14).
- Файлы — LF; `.env.example` без значений секретов; секреты только через env-файлы.
- Коммиты: `git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" commit …`,
  всегда новые коммиты, не `--amend`.
- Пуш в `origin` — только по явному разрешению пользователя.

### Соглашение о блоках кода в этом плане

Два вида, и различие надо читать, а не угадывать:

- **«Дословный исходник»** — файл обязан после коммита совпадать с блоком байт-в-байт
  (SQL-запросы, миграции, чистые функции и их тесты, конфиг). Для них работает проверка
  `.scratch/check_taskNN.py`.
- **«Схема, не исходник»** — интерфейс, таблицы соответствия «ошибка → код», маршруты и
  поля ответов. Реализацию пишет исполнитель по требованиям, а проверяют её тесты этой же
  задачи, а не eyeball-сверка с планом.

---

## Карта файлов A-2

```
migrations/0006_node_telemetry_admin.up.sql|.down.sql   # audit_action += 3 значения, server_health += agent_*
sqlc.yaml                                               # numeric → string, uuid nullable → *uuid.UUID
internal/db/query/{servers,addresses,profiles,nodeapi,telemetry,admin,maintenance}.sql
internal/db/{models.go,servers.sql.go,…}                # генерирует sqlc
internal/servers/{catalog.go,desired.go,desired_test.go,handlers.go}
internal/connections/{address.go,address_test.go,wgconfig.go,wgconfig_test.go,
                      service.go,handlers.go,sweeper.go,sweeper_test.go}
internal/devices/{service.go,handlers.go}               # DELETE устройства + keys/rotate
internal/nodeapi/{auth.go,handlers.go,enroll.go}
internal/telemetry/{delta.go,delta_test.go,service.go}
internal/audit/audit.go                                 # запись admin-действий (reason обязателен)
internal/admin/{auth.go,handlers.go,servers.go,tokens.go,users.go}
internal/httpx/{context.go,logging.go,envelope.go}      # server_id в контексте и журнале; новый код ошибки
services/api/router.go                                  # монтаж servers/connections/nodeapi/admin + лимиты
services/api/cmd/novavpn-api/main.go                    # подкоманда `admin create`; wiring sweeper'а
api-spec/openapi.yaml                                   # публичные + admin + /internal/v1 пути
tests/integration/{helpers_test.go,net_queries_test.go,catalog_test.go,address_test.go,
                   profiles_test.go,rotation_test.go,desired_test.go,
                   telemetry_test.go,nodeapi_test.go,admin_test.go,sweeper_test.go,
                   matrix_test.go,contract_test.go}
docs/testing-status.md
```

Ответственность модулей (спецификация §3): `servers` — каталог и вычисление desired set,
ничего не знает про HTTP-форматы клиента; `connections` — права на выдачу, аллокация адреса,
текст конфига, события жизненного цикла; `nodeapi` — только контракт узла, токены и ETag;
`telemetry` — свёртка фактов в агрегаты; `admin` — отдельная роль и маршруты управления;
`audit` — единственная точка записи админ-журнала. `internal/httpx` по-прежнему не импортирует
`internal/auth` и `internal/admin`.

Порядок задач не произволен: 1 (запросы) → 2 (каталог) → 3 (конфиг) → 4 (адрес) → 5–6 (выдача
и HTTP) → 7–8 (отзыв и ротация) → 9 (desired set) → 10 (телеметрия) → 11 (контракт узла,
которому нужны 9 и 10) → 12 (admin, который управляет 2 и 11) → 13 (sweeper) → 14 (контракт)
→ 15 (приёмка).

---

## Что план нашёл в спецификации и в установленной практике репозитория (правки, а не тихие расхождения)

1. **§5.1 не содержит маршрута входа админа.** Таблица перечисляет `POST /api/v1/admin/…` как
   «серверы, отзыв токена узла, блокировка пользователя с причиной, аудит», но вход
   администратора не описан, а без него admin-токен неоткуда взять. A-2 вводит
   `POST /api/v1/admin/login` и правит §5.1 (задача 12, шаг «правка спецификации»).
2. **§6 не перечисляет полей heartbeat'а.** `server_health` описана без `agent_version` и
   `agent_uptime_sec`, хотя §4.1 требует, чтобы heartbeat передавал версию агента и uptime.
   Миграция 0006 добавляет обе колонки, правка §6 — строку перечисления (задача 1, шаг 6).
3. **§7.6 не решает, что делать с профилями при удалении сервера.** Фраза «удаление сервера
   возможно только при `peers_active = 0`» не говорит, куда деть строки `vpn_profiles`, а FK
   `server_id … ON DELETE RESTRICT` без этого делает удаление невозможным. A-2 фиксирует
   semantics: сначала отзыв активных (и leftover superseded), затем удаление строк профилей и
   сервера, — и дописывает полутпредложение в §7.6 (задача 12).
4. **§7.3 не определяет, что происходит с лимитом устройств при ротации.** Потомок — новое
   устройство, и на лимите 3 ротация четвёртого устройства молча его превысила бы. A-2 решает:
   предок отзывается в той же транзакции (`revoked_at = now()`), поэтому «живых» устройств не
   прибавляется, а overlap пиера живёт в профиле, а не в устройстве. Решение записано в
   задаче 8 и в §13 как поведение, а не как догадка исполнителя.
5. **§5.2 требует «узловый префикс — по узлу», не называя чисел.** Число (120/мин, burst 10 на
   бакет `server_id`) — решение плана; оно в одной константе `services/api/router.go` и
   повторяется в комментарии, как это сделано с числами A-1.
6. **Код `server_not_available` в §5.2 отсутствует**, хотя §7.1 требует отказа «сервер не
   online», а конверт обязан нести стабильный код. Добавляется в `internal/httpx/envelope.go`
   и в перечисление `ErrorCode` контракта (задачи 6 и 14).
7. **§5.1 называет ответ конфига «готовым `[Interface]/[Peer]` текстом», но приватного ключа в
   нём быть не может.** По §3 правило 1 и ТЗ §5 приватный ключ устройства не покидает
   устройство, а control plane его вообще не видит. План фиксирует формат: текст **без
   строки `PrivateKey`**, клиент вставляет свой ключ локально; это описано в контракте
   (задача 14) и проверяется тестом (`TestRenderHasNoPrivateKey`, задача 6), а не молчанием.

8. **У администратора нет способа быть отозванным.** `admin_users` (миграция 0003) не
   содержит ни `revoked_at`, ни `status`, а `admin_audit_logs.admin_id … ON DELETE SET
   NULL`: `DELETE FROM admin_users` обезличил бы прошлые записи аудита, то есть ровно то,
   ради чего аудит существует. A-2 осознанно не делает ни отзыва, ни удаления админа
   (задача 12, шаг 12 и строка «not-run» в задаче 15); разделение прав внутри роли — цикл C.
9. **«Выданный и забытый» профиль нигде не описан.** §7.2 снимает профиль по воле
   пользователя, §7.1 ограничивает его срок, но активный профиль, под которым никогда не
   было handshake, остаётся в desired set и держит адрес в пуле. A-2 вводит
   `DormantAfter = 7 суток` (константа задачи 13) и снимает такой профиль событием
   `profile_revoked` с detail `{"reason":"dormant"}` — иначе число жило бы только в SQL.
10. **sqlc 1.27.0 без override'а на `interval` даёт `pgtype.Interval`.** Два запроса этого
    плана (`InsertBootstrapToken`, `DormantActiveProfiles`) изначально принимали срок как
    `interval`-параметр; оба переведены на явный `timestamptz`, вычисленный в Go, потому что
    задача 1 обещает, что рукописные слои `pgtype` не касаются, а проверка grep по `pgtype`
    это обязана подтвердить.
11. **Тест контракта A-1 запрещает маршруты этой поставки.** `TestAllPathsArePublicV1`
    (`api-spec/contract_test.go`) утверждает, что все пути начинаются с `/api/v1/`, и что
    путей ровно шесть. Контракт узла (`/internal/v1`) и admin-группа ломают оба утверждения,
    поэтому задача 14 начинается с правки этого теста, а не с правки YAML: иначе первое, что
    увидит исполнитель, — падение чужой проверки без объяснения.

Находки задачи 1 — они же правки её же блоков, записаны здесь, чтобы не выглядеть тихими
расхождениями плана с кодом:

12. **`ANY($n)` без каста массива даёт скаляр.** sqlc 1.27.0 не выводит `[]uuid.UUID` из
    `allocated_to = ANY($1)`: в сгенерированном `Params` поле становится `*uuid.UUID`, то есть
    вызов уйдёт в PostgreSQL со скаляром вместо массива. Два запроса плана (`ReleaseAddressesByProfiles`,
    `HandshakedDevicesAfter`) были в этом виде и сломались бы молча — сейчас каст `::uuid[]`
    в них восстановлен, а тест `TestArrayParamsMatchRows` вызывает оба вживую. Плата за
    корректный тип — безымянные поля `Column3` и `dollar_1`: генератор не может связать
    параметр с колонкой, когда тот массив.
13. **Ключ override'а для `numeric` — `pg_catalog.numeric`, а не `numeric`.** С просто
    `numeric` override не применяется **молча**: ни ошибки, ни изменения типа, колонка
    остаётся `pgtype.Numeric`. Проверено прогоном генератора на `numeric`, `numeric(9,6)`
    и `numeric(6,3)`.
14. **Для `date` тот же механизм ведёт себя наоборот: ключ — `date`.** С `pg_catalog.date`
    override не применяется. Единственная date-колонка схемы — `device_day_traffic.day`, и в
    исходном списке override'ов её не было вовсе, то есть задача 10 получила бы `pgtype.Date`
    там, где план обещал отсутствие pgtype. Override добавлен, комментарий в `sqlc.yaml`
    фиксирует оба асимметричных случая рядом.
15. **Каст на колонке в SELECT объявляет её NOT NULL.** `p.rotate_from::text`,
    `rotated_from::text`, `load1::text`, `status::text` заставляли генератор считать nullable-
    колонку обязательной, и `Scan` падал бы на отсутствующем значении — ровно там, где «данных
    нет» является рабочим состоянием (health ещё не прислан, ротации не было). Все эти касты
    сняты: `rotate_from` приходит `*uuid.UUID` (благодаря override'у из задачи 1, а не pgtype),
    `health_status` — честным `NullHealthStatus`, `load1`/`cpu_pct` — `*string`. Сняты и
    `$n::numeric`/`$n::cidr` в позициях параметров, где тип берётся из колонки: они лишь
    порождают `ColumnN` (см. находку 12).
16. **Окно переиспользования адреса в `ClaimAddress` не работало.** Условие
    `WHERE allocated_to IS NULL OR (reusable_at IS NOT NULL AND reusable_at <= now())`
    соединяло «свободен» и «окно истекло» союзом «ИЛИ», поэтому только что освобождённый
    адрес был доступен немедленно и защита Go-выборки обходилась на каждом конкурентном
    заходе. `TestClaimAddressIsExclusive` поймал это на первом же прогоне; условие стало
    дополнением `BusyAddresses` (см. шаг 5).
17. **Проверка «рукописные слои не касаются pgtype» не может быть grep'ом по слову.** Слово
    `pgtype` живёт в двух комментариях, объясняющих, почему срок жизни bootstrap-токена
    считается в Go (находка 10), и grep по слову выдавал бы ложное совпадение в
    сгенерированном коде. Обе проверки задачи 1 переведены на grep по import'у
    `jackc/pgx/v5/pgtype` — он пуст, что и есть утверждение о типах.

---

## Задачи

### Task 1: sqlc-запросы сетевого слоя, миграция 0006 и три override'а генератора

**Files:**
- Create: `migrations/0006_node_telemetry_admin.up.sql`, `migrations/0006_node_telemetry_admin.down.sql`,
  `internal/db/query/servers.sql`, `internal/db/query/addresses.sql`, `internal/db/query/profiles.sql`,
  `internal/db/query/nodeapi.sql`, `internal/db/query/telemetry.sql`, `internal/db/query/admin.sql`,
  `internal/db/query/maintenance.sql`, `tests/integration/net_queries_test.go`
- Modify: `sqlc.yaml`, `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§6)
- Regenerates: `internal/db/models.go`, `internal/db/*.sql.go`

**Interfaces:**
- Consumes: схема миграций 0001–0005.
- Produces: методы `db.Queries`, на которые опираются задачи 2–13 (имена и сигнатуры —
  ровно те, что объявлены SQL ниже: `CatalogServers`, `ServerByID`, `LockServerRow`,
  `BumpServerConfigVersion`, `BusyAddresses`, `ClaimAddress`, `ReleaseAddressByProfile`,
  `InsertProfile`, `DesiredCandidates`, `HandshakedDevicesAfter`, `SupersedeProfile`,
  `RevokeProfile`, `RevokeProfilesForDevices`, `NodeCredentialByHash`, `ConsumeBootstrapToken`,
  `UpsertServerHealth`, `UpsertDeviceDayTraffic`, `InsertConnectionEvent`, `AdminByEmail`,
  `InsertAdminAudit`, `ExpiredActiveProfiles`, `MarkStaleHealth`, …).
- Типы после override'ов: `numeric` → `string` (nullable → `*string`), `date` → `time.Time`,
  nullable `uuid` → `*uuid.UUID`. Все три нужны, чтобы в задачах 9/10/12 не писать ручной
  мост через `pgtype`. Ключи поиска у sqlc 1.27.0 выдержаны непоследовательно: `numeric`
  ищется с префиксом схемы (`pg_catalog.numeric`), а `date` — без него; оба проверены
  прогоном, и в комментарии к каждому записано, какой именно вариант работает.

- [ ] **Step 1: Миграция 0006 — дословный исходник `migrations/0006_node_telemetry_admin.up.sql`**

```sql
-- Цикл A-2: значения аудита для управления узлами и серверами плюс поля heartbeat'а.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'bootstrap_token_issued';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'bootstrap_token_revoked';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'server_deleted';

-- §4.1: heartbeat приносит версию агента и uptime. Без этих колонок принятому
-- сообщению некуда ложиться, а «версия агента» — то, по чему оператор понимает,
-- какой код крутится на узле (ТЗ §15).
ALTER TABLE server_health
    ADD COLUMN agent_version    text   CHECK (agent_version    IS NULL OR char_length(agent_version) BETWEEN 1 AND 64),
    ADD COLUMN agent_uptime_sec bigint CHECK (agent_uptime_sec IS NULL OR agent_uptime_sec >= 0);
```

- [ ] **Step 2: Откат — дословный исходник `migrations/0006_node_telemetry_admin.down.sql`**

```sql
-- Postgres не умеет вычёркивать значение из enum, поэтому enum пересобирается.
-- USING-каст падёт (22P02), если в аудите уже есть действие, которого в прежней
-- схеме не существовало: тихая потеря записей аудита хуже ошибки отката.

ALTER TABLE server_health DROP COLUMN IF EXISTS agent_uptime_sec;
ALTER TABLE server_health DROP COLUMN IF EXISTS agent_version;

CREATE TYPE audit_action_old AS ENUM ('server_created', 'server_updated', 'node_token_revoked',
                                      'node_enrolled', 'user_locked', 'user_unlocked',
                                      'profile_revoked_now', 'server_drained', 'admin_created');

ALTER TABLE admin_audit_logs
    ALTER COLUMN action TYPE audit_action_old USING action::text::audit_action_old;

DROP TYPE audit_action;
ALTER TYPE audit_action_old RENAME TO audit_action;
```

- [ ] **Step 3: Override'ы генератора — дословная правка `sqlc.yaml`**

В конец блока `overrides:` добавить четыре элемента (три ключа `db_type`:
`pg_catalog.numeric`, `pg_catalog.numeric` + `nullable`, `date`, `uuid` + `nullable`) —
перед `cidr`, не трогая существующие:

```yaml
          # numeric(9,6) координат и numeric load1/cpu_pct: в задачах 2 и 10 значения
          # читаются и сравниваются, а pgtype.Numeric для этого — лишний слой. Строка
          # сохраняет ровно ту точность, которую даёт numeric в фикстуре, и честно
          # показывает «значения нет» указателем (emit_pointers_for_null_types).
          # Ключ — "pg_catalog.numeric": с просто "numeric" override молча не применяется
          # (проверено прогоном sqlc 1.27.0 на numeric, numeric(9,6) и numeric(6,3)).
          - db_type: "pg_catalog.numeric"
            go_type: "string"
          - db_type: "pg_catalog.numeric"
            nullable: true
            go_type:
              type: "string"
              pointer: true
          # Единственная date-колонка схемы — device_day_traffic.day. Без override она
          # приходит pgtype.Date, и задаче 10 пришлось бы руками собирать дату в
          # pgtype-обёртку ради одного поля; pgx/v5 кодирует time.Time в date нативно.
          # Ключ — "date": для date sqlc 1.27.0 имя ищет без схемы, и с "pg_catalog.date"
          # колонка остаётся pgtype.Date (проверено тем же прогоном, что и numeric).
          - db_type: "date"
            go_type:
              import: "time"
              type: "Time"
          # NULL-uuid без этого остаётся pgtype.UUID, и каждую nullable-ссылку
          # (rotate_from, admin_id, user_id события) приходится оборачивать руками.
          # pgx/v5 кодирует *uuid.UUID нативно.
          - db_type: "uuid"
            nullable: true
            go_type:
              import: "github.com/google/uuid"
              type: "UUID"
              pointer: true
```

Run: `make sqlc-generate && make unit && make vet`
Expected: PASS. Ожидаемый шум — `internal/db/models.go`, `internal/db/devices.sql.go` и
`internal/db/querier.go`: `RotationOf pgtype.UUID` становится `*uuid.UUID`, а в интерфейсе
`Querier` добавляются методы новых файлов запросов. Ни один рукописный файл `pgtype` не
использует, и после регенерации его не использует ни один сгенерированный: проверить
`grep -rn "jackc/pgx/v5/pgtype" --include=*.go .` — пусто. (Слово `pgtype` остаётся в двух
комментариях, объясняющих, почему срок жизни bootstrap-токена считается в Go, — это текст, а
не тип, и grep по import'у потому и точнее grep по слову.) `devices.Register` поле `RotationOf`
не заполняет, поэтому `nil` там и был.

- [ ] **Step 4: `internal/db/query/servers.sql` — дословный исходник**

```sql
-- name: CatalogServers :many
-- Каталог: только выведенные в online. health берётся LEFT JOIN'ом — узел может ещё
-- ни разу не прислать heartbeat, и «неизвестно» здесь честнее, чем «ошибка».
-- status идёт без каста в text: LEFT JOIN делает его nullable-enum, и `h.status::text`
-- объявил бы колонку обязательной — Scan падал бы ровно там, где health ещё нет.
-- NullHealthStatus слой каталога (задача 2) разворачивает в *string одним явным
-- преобразованием, и «значения нет» остаётся отличием от «значение ok».
SELECT s.id, s.name, s.advertised_host, s.listen_port, s.mtu, s.keepalive_sec,
       s.provider, s.region, s.capacity_mbps,
       l.country_code, l.city, l.lat, l.lon, l.timezone,
       h.status         AS health_status,
       h.observed_at    AS health_observed_at
FROM vpn_servers s
JOIN server_locations l ON l.id = s.location_id
LEFT JOIN server_health h ON h.server_id = s.id
WHERE s.maintenance_status = 'online'
ORDER BY l.country_code, l.city, s.name;

-- name: ServerByID :one
SELECT id, location_id, name, advertised_host, listen_port, public_key,
       address_pool_v4, mtu, dns_mode, keepalive_sec, config_version,
       maintenance_status, provider, region, capacity_mbps
FROM vpn_servers WHERE id = $1;

-- name: LockServerRow :exec
-- Advisory lock на строку сервера: аллокация адреса обязана быть сериализованной
-- по серверу, иначе две горутины выберут один свободный адрес (§6, §9.1).
SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0));

-- name: BumpServerConfigVersion :one
-- Каждая смена набора пиеров поднимает версию: узел по ней отличает «ничего нового»
-- от «надо перечитать» и по ней же работает If-None-Match (§4.1).
UPDATE vpn_servers SET config_version = config_version + 1 WHERE id = $1
RETURNING config_version;

-- name: ServerConfigVersion :one
SELECT config_version FROM vpn_servers WHERE id = $1;

-- name: SetServerMaintenance :one
UPDATE vpn_servers SET maintenance_status = $2 WHERE id = $1
RETURNING id, name, maintenance_status;

-- name: LocationByKey :one
SELECT id, country_code, city, lat, lon, timezone
FROM server_locations
WHERE country_code = $1 AND city = $2 AND lat = $3 AND lon = $4;

-- name: InsertServerLocation :one
INSERT INTO server_locations (id, country_code, city, lat, lon, timezone)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, country_code, city, lat, lon, timezone;

-- name: InsertServer :one
INSERT INTO vpn_servers (id, location_id, name, advertised_host, listen_port, public_key,
                         address_pool_v4, mtu, keepalive_sec, provider, region, capacity_mbps,
                         maintenance_status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'maintenance')
RETURNING id, location_id, name, advertised_host, listen_port, public_key,
          address_pool_v4, mtu, dns_mode, keepalive_sec, config_version,
          maintenance_status, provider, region, capacity_mbps;

-- name: UpdateServerFields :one
-- Не COALESCE по каждому полю: `capacity_mbps = null` означает «заявленная ёмкость
-- снята», а не «не присылали». Обновление приходит полным набором (задача 12),
-- поэтому явный набор полей честнее, чем различие «пропуск / null».
UPDATE vpn_servers
   SET name = $2, advertised_host = $3, listen_port = $4, mtu = $5,
       keepalive_sec = $6, capacity_mbps = $7
 WHERE id = $1
 RETURNING id, location_id, name, advertised_host, listen_port, public_key,
           address_pool_v4, mtu, dns_mode, keepalive_sec, config_version,
           maintenance_status, provider, region, capacity_mbps;

-- name: CountActiveProfilesOnServer :one
-- §7.6: «удаление сервера возможно только при peers_active = 0».
SELECT count(*) FROM vpn_profiles WHERE server_id = $1 AND status = 'active';

-- name: DeleteProfilesByServer :many
-- Остатки superseded/revoked/expired мешают удалению по FK RESTRICT; до этой точки
-- активных уже нет (проверка выше), поэтому здесь удаляется всё, что осталось.
DELETE FROM vpn_profiles WHERE server_id = $1 RETURNING id;

-- name: DeleteServer :exec
DELETE FROM vpn_servers WHERE id = $1;
```

- [ ] **Step 5: `internal/db/query/addresses.sql` — дословный исходник**

```sql
-- name: BusyAddresses :many
-- Занято = «назначено сейчас» ИЛИ «освобождено, но окно переиспользования (§7.2)
-- ещё не истекло». Окно считается по часам сервера, а не по переданному now():
-- Go-выборка и DB-защита должны судить об одном и том же моменте.
SELECT address FROM tunnel_addresses
WHERE server_id = $1
  AND (allocated_to IS NOT NULL
       OR (reusable_at IS NOT NULL AND reusable_at > now()));

-- name: ClaimAddress :one
-- INSERT..ON CONFLICT DO UPDATE с условием: если адрес успели занять между выборкой
-- в Go и этим запросом, строка не возвращается, и аллокатор отказывается, а не
-- перетирает чужое назначение. Это второй слой защиты поверх LockServerRow.
-- Условие — ровно дополнение BusyAddresses: адрес свободен, только если он никому
-- не назначен И окно переиспользования (§7.2) закрыто. Раздельные «ИЛИ» здесь
-- означали бы, что освобождённый адрес можно взять мгновенно, а проверка Go-выборки
-- обходилась бы на каждом конкурентном заходе.
INSERT INTO tunnel_addresses (server_id, address, allocated_to)
VALUES ($1, $2, $3)
ON CONFLICT (server_id, address) DO UPDATE
    SET allocated_to = EXCLUDED.allocated_to,
        released_at  = NULL,
        reusable_at  = NULL
  WHERE tunnel_addresses.allocated_to IS NULL
    AND (tunnel_addresses.reusable_at IS NULL
         OR tunnel_addresses.reusable_at <= now())
RETURNING address;

-- name: ReleaseAddressByProfile :exec
UPDATE tunnel_addresses
   SET allocated_to = NULL, released_at = now(),
       reusable_at  = now() + interval '5 minutes'
 WHERE allocated_to = $1;

-- name: ReleaseAddressesByProfiles :exec
UPDATE tunnel_addresses
   SET allocated_to = NULL, released_at = now(),
       reusable_at  = now() + interval '5 minutes'
 WHERE allocated_to = ANY($1::uuid[]);

-- name: AddressOfProfile :one
SELECT address FROM tunnel_addresses WHERE allocated_to = $1;
```

- [ ] **Step 6: `internal/db/query/profiles.sql` — дословный исходник**

```sql
-- name: InsertProfile :one
-- Статус и peer_state фиксированы 'active': другой вариант здесь был бы
-- догадкой о том, что делает вызывающий код.
INSERT INTO vpn_profiles (id, device_id, server_id, address_v4, status, issued_at,
                          expires_at, peer_state)
VALUES ($1, $2, $3, $4, 'active', now(), $5, 'active')
RETURNING id, device_id, server_id, address_v4, status, issued_at, expires_at,
          overlap_valid_until, revoked_at, rotate_from, peer_state;

-- name: ActiveProfileByDeviceServer :one
SELECT id, device_id, server_id, address_v4, status, issued_at, expires_at,
       overlap_valid_until, revoked_at, rotate_from, peer_state
FROM vpn_profiles
WHERE device_id = $1 AND server_id = $2 AND status = 'active';

-- name: LatestProfileByDeviceServer :one
-- GET …/profiles/{server_id} обязан показать и отозванный профиль: человек имеет
-- право видеть, что с его доступом случилось.
SELECT id, device_id, server_id, address_v4, status, issued_at, expires_at,
       overlap_valid_until, revoked_at, rotate_from, peer_state
FROM vpn_profiles
WHERE device_id = $1 AND server_id = $2
ORDER BY issued_at DESC LIMIT 1;

-- name: ProfilesByDevice :many
SELECT id, device_id, server_id, address_v4, status, issued_at, expires_at,
       overlap_valid_until, revoked_at, rotate_from, peer_state
FROM vpn_profiles WHERE device_id = $1 ORDER BY issued_at;

-- name: ProfilesByUser :many
-- GET /me и админ-просмотр: список профилей всех устройств пользователя.
SELECT p.id, p.device_id, p.server_id, p.address_v4, p.status, p.issued_at, p.expires_at
FROM vpn_profiles p
JOIN devices d ON d.id = p.device_id
WHERE d.user_id = $1
ORDER BY p.issued_at;

-- name: DesiredCandidates :many
-- Всё, что узел может иметь право увидеть: активные и superseded профили сервера
-- вместе с ключом устройства. Правила отсечения (окно overlap, преемник, handshake)
-- живут в servers.Compute (задача 9), потому что проверять их хочется чистой
-- функцией на случайных данных, а не через БД (§9.1).
SELECT p.id, p.device_id, p.server_id, p.address_v4, p.status, p.expires_at,
       p.overlap_valid_until, p.peer_state, p.rotate_from,
       d.public_key, d.revoked_at AS device_revoked_at
FROM vpn_profiles p
JOIN devices d ON d.id = p.device_id
WHERE p.server_id = $1 AND p.status IN ('active', 'superseded')
ORDER BY p.address_v4;

-- name: HandshakedDevicesAfter :many
-- «Старый ключ снимается, как только наблюдался handshake нового» (§7.3).
-- Источник истины — событие, а не Redis: при недоступном Redis снятие предка
-- не должно откладываться до закрытия окна.
SELECT DISTINCT device_id FROM connection_events
WHERE server_id = $1 AND event = 'handshake_observed'
  AND created_at >= $2 AND device_id = ANY($3::uuid[]);

-- name: SupersedeProfile :one
UPDATE vpn_profiles
   SET status = 'superseded', peer_state = 'rotating_old_key', overlap_valid_until = $2
 WHERE id = $1 AND status = 'active'
 RETURNING id, device_id, server_id, address_v4, status, issued_at, expires_at,
           overlap_valid_until, revoked_at, rotate_from, peer_state;

-- name: RevokeProfile :one
-- overlap_valid_until не обнуляется: констрейнт profiles_peer_state требует
-- ненулевого окна при peer_state='rotating_old_key', а тихое «починить» констрейнт
-- правкой данных — это способ потерять настоящее состояние.
UPDATE vpn_profiles
   SET status = 'revoked', revoked_at = now()
 WHERE id = $1 AND status IN ('active', 'superseded')
 RETURNING id, server_id, address_v4, device_id;

-- name: RevokeProfilesForDevices :many
-- Отзыв устройства = отзыв всех его профилей (§5.1). Возвращает server_id, потому
-- что именно по нему вызывающий код поднимает config_version: забыть сервер —
-- значит оставить пиера в desired set живым.
UPDATE vpn_profiles
   SET status = 'revoked', revoked_at = now()
 WHERE device_id = ANY($1::uuid[]) AND status IN ('active', 'superseded')
 RETURNING id, server_id, device_id;

-- name: CountActiveProfilesByDevice :one
SELECT count(*) FROM vpn_profiles WHERE device_id = $1 AND status = 'active';

-- name: MarkProfileExpired :one
-- Просроченный профиль становится 'expired' отдельной операцией (sweeper, задача 13),
-- а не «тихо не отдаётся»: событие profile_expired обязано существовать (§6).
UPDATE vpn_profiles SET status = 'expired'
 WHERE id = $1 AND status = 'active'
 RETURNING id, server_id, device_id;

-- name: RevokeAllActiveByDeviceServer :many
-- Ротация переносит профили предка на потомка; список нужен сразу, потому что
-- перенос обязан быть атомарным по всем серверам, где устройство сидит.
SELECT id, server_id, address_v4, expires_at FROM vpn_profiles
WHERE device_id = $1 AND status = 'active';
```

- [ ] **Step 7: `internal/db/query/nodeapi.sql` — дословный исходник**

```sql
-- name: NodeCredentialByHash :one
SELECT id, server_id, issued_at, last_used_at, revoked_at,
       rotated_from
FROM node_credentials WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: TouchNodeCredential :exec
-- last_used_at — доказательство жизни токена: отзыв «неиспользуемого» без этого поля
-- был бы слепым.
UPDATE node_credentials SET last_used_at = now() WHERE id = $1;

-- name: InsertNodeCredential :one
INSERT INTO node_credentials (id, server_id, token_hash, rotated_from)
VALUES ($1, $2, $3, $4)
RETURNING id, server_id, issued_at;

-- name: RevokeNodeCredentialsForServer :execrows
UPDATE node_credentials SET revoked_at = now()
 WHERE server_id = $1 AND revoked_at IS NULL;

-- name: BootstrapTokenByHash :one
-- Здесь нет `revoked_at IS NULL` и `expires_at > now()`: различить «нет такого токена»,
-- «просрочен» и «израсходован» должен сервис, чтобы в журнал попали разные причины,
-- а наружу уйти один отказ (задача 11).
SELECT id, server_id, created_at, expires_at, used_at, revoked_at
FROM bootstrap_tokens WHERE token_hash = $1;

-- name: ConsumeBootstrapToken :one
-- Одноразовость на уровне БД: UPDATE с условием used_at IS NULL отдаёт строку ровно
-- одному из двух параллельных enroll.
UPDATE bootstrap_tokens SET used_at = now()
 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
 RETURNING server_id;

-- name: InsertBootstrapToken :one
-- Срок жизни считается в Go (now.Add(ttl)), а не в SQL: в sqlc.yaml нет override на
-- interval, и `now() + $5::interval` породил бы аргумент pgtype.Interval — тип, которого
-- рукописные слои этого плана не видят (см. проверку задачи 1 на grep по pgtype).
INSERT INTO bootstrap_tokens (id, token_hash, server_id, created_by, created_at, expires_at)
VALUES ($1, $2, $3, $4, now(), $5)
RETURNING id, server_id, created_at, expires_at;

-- name: RevokeBootstrapToken :one
UPDATE bootstrap_tokens SET revoked_at = now()
 WHERE id = $1 AND revoked_at IS NULL AND used_at IS NULL
 RETURNING id, server_id;

-- name: LiveBootstrapTokensOfServer :many
SELECT id, created_at, expires_at
FROM bootstrap_tokens
WHERE server_id = $1 AND revoked_at IS NULL AND used_at IS NULL
ORDER BY created_at;
```

- [ ] **Step 8: `internal/db/query/telemetry.sql` — дословный исходник**

```sql
-- name: UpsertServerHealth :exec
-- Один узел = одна строка наблюдаемого состояния; heartbeat и observed пишут её
-- одними руками, поэтому наивный INSERT убивал бы второй отчёт того же узла.
INSERT INTO server_health (server_id, observed_at, peers_configured, peers_handshaked,
                           interface_rx_bytes, interface_tx_bytes, load1, cpu_pct,
                           applied_config_version, status, agent_version, agent_uptime_sec)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (server_id) DO UPDATE SET
    observed_at            = EXCLUDED.observed_at,
    peers_configured       = EXCLUDED.peers_configured,
    peers_handshaked       = EXCLUDED.peers_handshaked,
    interface_rx_bytes     = EXCLUDED.interface_rx_bytes,
    interface_tx_bytes     = EXCLUDED.interface_tx_bytes,
    load1                  = EXCLUDED.load1,
    cpu_pct                = EXCLUDED.cpu_pct,
    applied_config_version = EXCLUDED.applied_config_version,
    status                 = EXCLUDED.status,
    agent_version          = EXCLUDED.agent_version,
    agent_uptime_sec       = EXCLUDED.agent_uptime_sec;

-- name: InsertConnectionEvent :exec
-- detail — jsonb из «только коды и версии»: содержимое трафика сюда не кладёт
-- ни один путь этого плана (ТЗ §11).
INSERT INTO connection_events (user_id, device_id, server_id, event, detail)
VALUES ($1, $2, $3, $4, $5);

-- name: UpsertDeviceDayTraffic :exec
-- Прирост, а не абсолют: узел репортирует счётчики, дельту считает telemetry.Delta
-- (задача 10), а здесь она складывается в агрегат устройство-сутки (ADR-006).
INSERT INTO device_day_traffic (user_id, device_id, day, rx_bytes, tx_bytes)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, device_id, day) DO UPDATE SET
    rx_bytes = device_day_traffic.rx_bytes + EXCLUDED.rx_bytes,
    tx_bytes = device_day_traffic.tx_bytes + EXCLUDED.tx_bytes;

-- name: DevicesByPublicKeys :many
-- Узел называет пиеров публичным ключом; пользователь и устройство — то, чем
-- этот ключ был выдан. Ключи, которых нет в базе (снятый, но ещё видимый на узле),
-- просто не возвращаются.
SELECT id, user_id, public_key FROM devices WHERE public_key = ANY($1::text[]);

-- name: ServerHealthOf :one
SELECT server_id, observed_at, peers_configured, peers_handshaked,
       interface_rx_bytes, interface_tx_bytes, load1, cpu_pct,
       applied_config_version, status,
       agent_version, agent_uptime_sec
FROM server_health WHERE server_id = $1;
```

- [ ] **Step 9: `internal/db/query/admin.sql` — дословный исходник**

```sql
-- name: InsertAdminUser :one
INSERT INTO admin_users (id, email, password_hash)
VALUES ($1, $2, $3)
RETURNING id, email, created_at;

-- name: AdminByEmail :one
SELECT id, email, password_hash, created_at FROM admin_users WHERE email = $1;

-- name: AdminByID :one
SELECT id, email, created_at FROM admin_users WHERE id = $1;

-- name: InsertAdminAudit :exec
-- reason и request_id NOT NULL уже в схеме: аудит без причины — не аудит (ТЗ §9).
INSERT INTO admin_audit_logs (admin_id, action, target_type, target_id, reason, request_id)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: RecentAdminAudit :many
-- Поклаговая разбивка (limit/offset) — то, ради чего §5.1 обещает «аудит»: список
-- длиннее одного экрана, а фильтра по админу в A-2 нет намеренно (задача 12).
SELECT id, admin_id, action, target_type, target_id, reason, request_id, created_at
FROM admin_audit_logs
ORDER BY created_at DESC, id DESC
LIMIT $1 OFFSET $2;
```

- [ ] **Step 10: `internal/db/query/maintenance.sql` — дословный исходник**

```sql
-- name: ExpiredActiveProfiles :many
-- Профиль, у которого expires_at прошёл, но статус ещё 'active', — дыра: desired
-- обязан его не отдавать (условие по времени в задаче 9), а «просрочено» как факт
-- появляется только здесь (§6: событие profile_expired).
-- d.user_id нужен sweeper'у (задача 13): событие без пользователя рвёт выборку
-- «мои соединения» в §6, а доставать user_id отдельным запросом на профиль —
-- способ видеть между двумя запросами чужое изменение.
SELECT p.id, p.server_id, p.device_id, d.user_id
FROM vpn_profiles p
JOIN devices d ON d.id = p.device_id
WHERE p.status = 'active' AND p.expires_at <= now()
ORDER BY p.id;

-- name: MarkStaleHealth :many
-- «Узел не присылал heartbeat 3 интервала» (3 × 30 с = 90 с, §4.3). Возвращает
-- server_id, чтобы на каждый переход записать событие node_stale.
UPDATE server_health SET status = 'stale'
 WHERE status = 'ok' AND observed_at < now() - interval '90 seconds'
 RETURNING server_id;

-- name: DeleteOldConnectionEvents :execrows
-- Retention 90 дней (§6).
DELETE FROM connection_events WHERE created_at < now() - interval '90 days';

-- name: NullOldRefreshIPs :execrows
-- Анти-фрод-столбец живёт 90 дней, сама семья при этом остаётся (§6).
UPDATE refresh_token_families SET ip = NULL
 WHERE issued_at < now() - interval '90 days' AND ip IS NOT NULL;

-- name: PurgeOldIdempotencyKeys :execrows
-- Завершённые ключи хранятся сутки — окно, в котором разумен повтор запроса
-- клиентом; незавершённые (abandoned) удаляются через неделю, потому что слот
-- незавершённого ключа и так освобождается Abandon'ом (задача 9 A-1).
DELETE FROM idempotency_keys
 WHERE (completed_at IS NOT NULL AND completed_at < now() - interval '24 hours')
    OR (completed_at IS NULL AND created_at < now() - interval '7 days');
```

- [ ] **Step 11: Убедиться, что запросы генерируются и компилируются**

Run: `make sqlc-generate && make vet`
Expected: PASS. Проверить, что появились `internal/db/{servers,addresses,profiles,nodeapi,telemetry,admin,maintenance}.sql.go`, а в `models.go` все nullable-uuid стали `*uuid.UUID` и ни одного `pgtype.UUID` не осталось (`grep -c pgtype.UUID internal/db/models.go` → `0`). Отдельно — что `pgtype` не импортируется вообще (`grep -rn "jackc/pgx/v5/pgtype" --include=*.go .` → пусто): именно это, а не совпадение имён полей, означает, что рукописные слои задач 2–13 не касаются pgtype. И ещё одно, что видно только по сгенерированным сигнатурам: массивный параметр обязан остаться массивом (`ReleaseAddressesByProfiles(ctx, []uuid.UUID)`), см. находку 12 в конце раздела «Что план нашёл».

- [ ] **Step 12: Интеграционный тест запросов — `tests/integration/net_queries_test.go`**

Схема, не исходник. Тест обязан покрывать ровно те инварианты, на которые позже
ссылается план, и проверять их против реальной БД (спецификация §9.2), а не mock'ом:

| тест | что доказывает | как |
|---|---|---|
| `TestClaimAddressIsExclusive` | `ClaimAddress` не отдаёт занятый адрес и не перетирает чужой | занять адрес за профилем P1, тот же адрес попробовать за P2 → ноль строк; после `ReleaseAddressByProfile(P1)` сразу → по-прежнему занят (окно 5 мин), `reusable_at` задвинуть UPDATE'ом в прошлое → теперь берётся |
| `TestBusyAddressesCoversBothKinds` | заняты и `allocated_to IS NOT NULL`, и неистёкшее `reusable_at` | три строки: назначен, освобождён с будущим окном, освобождён с прошлым окном → `BusyAddresses` вернул 2 |
| `TestArrayParamsMatchRows` | массивные параметры доживают до вызова массивами, а не скалярами | `DevicesByPublicKeys` (два известных ключа + один несуществующий → ровно 2 строки), `ReleaseAddressesByProfiles` одним вызовом на два профиля, `HandshakedDevicesAfter` с окном и чужим устройством в списке |
| `TestConsumeBootstrapTokenIsOnce` | одноразовость под конкурентным вызовом | два `ConsumeBootstrapToken` одного id → второй `pgx.ErrNoRows` |
| `TestDesiredCandidatesOnlyActiveSuperseded` | в выборку не попадают revoked/expired | по одному профилю каждого статуса → ровно 2 строки |
| `TestRevokeProfilesForDevicesReturnsServers` | отзыв возвращает `server_id` для bump | два профиля на разных серверах → 2 строки с разными `server_id` |
| `TestUpsertServerHealthReplaces` | повторный heartbeat не создаёт вторую строку | два upsert → `count(*)=1`, поля второго |
| `TestNumericFieldsReadAsStrings` | override numeric работает в обе стороны, а не только на запись | upsert с `load1="1.250"`, `cpu_pct="12.50"` → `ServerHealthOf` отдал те же строки с той же точностью (numeric(6,3) и numeric(5,2)) |
| `TestUpsertDeviceDayTrafficSums` | агрегат складывает приросты | два upsert на одну пару/сутки → rx=сумма |
| `TestMarkStaleHealthReturnsServer` | переход ok→stale отдаёт id для события | upsert со `observed_at` = now−200s → ровно 1 id, повторный вызов → 0 |
| `TestAuditActionNewValuesExist` | значения enum из 0006 реально работают | `InsertAdminAudit` с `server_deleted`, `bootstrap_token_issued` |
| `TestMigration0006UpDownUp` | 0006 откатывается и применяется снова | тот же путь, что `migrations_test.go` (задача 5 A-1) |

Компоненты фикстур — хелперы этой же задачи из `helpers_test.go` (шаг 13).

Две вещи, которые стали ясны только на прогоне и без них тест был бы самообманом:

- Освобождение адреса нельзя моделировать одной строкой `released_at = now(),
  `reusable_at = <прошлое>`: CHECK `addresses_window` требует `reusable_at >= released_at`,
  и вставка падает с 23514. Окно «истекло» моделируют сдвигом **обеих** границ
  (`released_at = now() − 10 min`, `reusable_at = now() − 5 min`) — иначе первый же прогон
  превращается в отладку фикстуры вместо проверки инварианта.
- `connection_events.device_id` nullable, поэтому `HandshakedDevicesAfter` приходит как
  `[]*uuid.UUID`. Задача 9 обязана отбрасывать nil-элементы, а не считать их устройствами:
  событие без устройства — это событие о сервере, и в выборку «снять предка» оно не входит.

- [ ] **Step 13: Хелперы узлов и серверов — правка `tests/integration/helpers_test.go`**

Схема, не исходник. Добавить (используются задачами 2, 4, 5, 7, 8, 9, 11, 12, 15):

```go
// keyFromSeed собирает канонический публичный ключ из произвольной строки: sha256
// от сида, младшие два бита последнего байта обнулены (spare-биты), иначе ключ
// упрётся в CHECK формы из 0001 ровно тем вариантом, из-за которого существует
// devices.ValidateKey. Глобальный UNIQUE на devices.public_key делает «i-й по счёту»
// ключ столкновением между прогонами, поэтому сид — строка, а не счётчик.
func keyFromSeed(seed string) string

func seedLocation(t *testing.T, ctx context.Context, q *db.Queries) uuid.UUID
// lat/lon строками ("52.5200", "13.4050") — тип после override'а numeric. Город
// несёт суффикс id: UNIQUE (country_code, city, lat, lon) из 0002, а dev-база между
// прогонами одна и та же.

// seedServer создаёт сервер с maintenance_status='maintenance' (дефолт схемы):
// «зарегистрирован» ≠ «работает», и перевод в online — отдельный явный шаг теста.
func seedServer(t *testing.T, ctx context.Context, q *db.Queries, poolV4 string) db.VpnServer
// poolV4 вида "10.99.1.0/24"; advertised_host — из TEST-NET-3 (203.0.113.0/24),
// чтобы в базе никогда не оказался адрес реального хоста.

func setServerOnline(t *testing.T, ctx context.Context, q *db.Queries, id uuid.UUID)
func seedProfile(t *testing.T, ctx context.Context, q *db.Queries, deviceID, serverID uuid.UUID,
                 addr string, expiresIn time.Duration) db.VpnProfile
func seedDevice(t *testing.T, ctx context.Context, q *db.Queries, user uuid.UUID, i int) db.Device

// seededKey отдаёт публичный ключ устройства по id — нужен там, где запрос принимает
// массив ключей (DevicesByPublicKeys), а фикстура знает только id.
func seededKey(t *testing.T, ctx context.Context, q *db.Queries, id uuid.UUID) string
```

- [ ] **Step 14: Правка спецификации §6**

В строке таблицы `server_health` после `status enum('ok','stale','error')` дописать
`agent_version`, `agent_uptime_sec` и пояснение «приходят heartbeat'ом (§4.1)». Правка
обязана быть в том же коммите, что и миграция: схема и документ не должны разъезжаться
ни на один коммит.

- [ ] **Step 15: Прогон**

Run: `make unit && make vet && make up-dev && make migrate-up && make integration`
Expected: PASS — включая существующие тесты A-1 (регенерация моделей не должна их сломать).

- [ ] **Step 16: Коммит**

```bash
git add migrations/0006_node_telemetry_admin.up.sql migrations/0006_node_telemetry_admin.down.sql \
        sqlc.yaml internal/db docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md \
        tests/integration/net_queries_test.go tests/integration/helpers_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(db): запросы сетевого слоя, аудит-значения и колонки heartbeat (0006)"
```

---

### Task 2: Каталог серверов — `GET /api/v1/servers` и честная `availability`

**Files:**
- Create: `internal/servers/catalog.go`, `internal/servers/catalog_test.go`,
  `internal/servers/handlers.go`, `tests/integration/catalog_test.go`
- Modify: `services/api/router.go` (монтаж модуля)

**Interfaces:**
- Consumes: `CatalogServers` (задача 1), `db.VpnServer`, `httpx.Decorators`, `httpx.WriteJSON`.
- Produces:
  - `servers.Availability` (`"available" | "unknown"`), `servers.Available(status *string, observedAt *time.Time, now time.Time) Availability`;
  - `servers.NewService(q *db.Queries) *Service`, `(s *Service) Catalog(ctx) ([]Summary, error)`;
  - `type Summary struct{ ID, Name, CountryCode, City, Host string; Port, MTU int;
    Latitude, Longitude float64; Availability Availability; LatencyMS *int64; Load *float64;
    CapacityMbps *int32; Provider, Region string }` — JSON-имена: `id`, `name`, `country_code`,
    `city`, `host`, `port`, `latitude`, `longitude`, `availability`, `latency_ms`, `load`,
    `capacity_mbps`, `provider`, `region`;
  - `servers.NewHandler(svc *Service) *Handler` с `RegisterRoutes(mux, dec)`;
  - константу `servers.DefaultStaleAfter = 90 * time.Second`.

- [ ] **Step 1: Падающий unit-тест на `Available` — `internal/servers/catalog_test.go`**

Дословный исходник:

```go
package servers

import (
	"testing"
	"time"
)

func TestAvailableRequiresFreshOK(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	ok := "ok"
	fresh := now.Add(-30 * time.Second)
	stale := now.Add(-91 * time.Second)
	errStatus := "error"
	staleStatus := "stale"

	cases := []struct {
		name    string
		status  *string
		at      *time.Time
		want    Availability
	}{
		{"нет строки health вообще", nil, nil, AvailabilityUnknown},
		{"health есть, но статус не пришёл", nil, &fresh, AvailabilityUnknown},
		{"heartbeat не был", &ok, nil, AvailabilityUnknown},
		{"ok свежий", &ok, &fresh, AvailabilityAvailable},
		{"ok на границе окна", &ok, &stale, AvailabilityUnknown},
		{"error", &errStatus, &fresh, AvailabilityUnknown},
		{"stale", &staleStatus, &fresh, AvailabilityUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Available(c.status, c.at, now); got != c.want {
				t.Errorf("Available = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCatalogHasNoMeasuredNumbers(t *testing.T) {
	// Смысл теста — не формат, а обещание: latency_ms и load никогда не становятся
	// нулём и никогда не «правдоподобным числом» (спецификация §13.4, ADR-006).
	if s := (Summary{}); s.LatencyMS != nil || s.Load != nil {
		t.Fatal("latency/load должны быть nil по умолчанию")
	}
}
```

Run: `make unit`
Expected: FAIL — `undefined: Available`, `undefined: Summary`.

- [ ] **Step 2: Реализовать `internal/servers/catalog.go`**

Схема, не исходник. Требования:

- `type Availability string`; значения `available`, `unknown`. Значения
  «unavailable» нет сознательно: в каталог попадает только `maintenance_status='online'`,
  а всё остальное — «неизвестно», потому что API не измерял связность (спецификация §1.2).
- `Available` — чистая функция по таблице из шага 1; окно `DefaultStaleAfter = 90*time.Second`
  и почему именно 90 (3 интервала опроса по §4.3) — в комментарии над константой.
- `(*Service) Catalog(ctx)` читает `CatalogServers` и собирает `[]Summary`:
  `Latitude/Longitude` парсятся из `string` (numeric-override) через `strconv.ParseFloat`
  с `bitsize=64`; ошибка парсинга — `fmt.Errorf("servers: server %s: bad lat: %w", …)`,
  потому что тихий `0` был бы ровно той подменой, которую запрещает ТЗ §19.3.
  Координаты — декларативные данные оператора, а не замер, поэтому числом, а не строкой:
  карте цикла C нужен `number`.
- `CapacityMbps` отдаётся как есть (`*int32`): заявленная ёмкость, не измеренная (ADR-006).
- `Region` — `string` (пусто, если NULL): `*string` в ответе дал бы `null` там, где у нас
  «не заполнено оператором», и клиент не отличил бы это от «поле не попросили».

- [ ] **Step 3: Handler — `internal/servers/handlers.go`**

Схема, не исходник:

```go
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	mux.Handle("GET /api/v1/servers", dec.Auth(http.HandlerFunc(h.list)))
}
```

- Ответ `200` вида `{"servers":[ … ]}` (массив `Summary`), `Content-Type: application/json; charset=utf-8`.
- Пустой каталог — `{"servers":[]}`, а не `404`: «серверов нет» это состояние, а не
  отсутствие объекта; матрица (задача 15) проверяет это отдельно.
- Ошибка БД → `500 internal` (конверт), отсутствие субъекта → `401 unauthenticated`.
- Сообщение 500 — по-русски: `"внутренняя ошибка"` (как в `devices/handlers.go`).

- [ ] **Step 4: Монтаж в `services/api/router.go`**

В `NewRouter`, сразу за `devices.NewHandler(...)`:

```go
servers.NewHandler(servers.NewService(q)).RegisterRoutes(mux, dec)
```

Run: `make unit && make vet`
Expected: PASS.

- [ ] **Step 5: Интеграционный тест — `tests/integration/catalog_test.go`**

Схема, не исходник. Собирается как `devices_test.go`: `passthrough` декораторы,
`http.NewServeMux()`, `httptest`.

| случай | ожидание |
|---|---|
| серверов нет | `200 {"servers":[]}` |
| сервер в `maintenance` (дефолт `seedServer`) | в каталоге отсутствует |
| `online` без `server_health` | присутствует, `availability == "unknown"`, `latency_ms == null`, `load == null` |
| `online` + health `ok`, `observed_at` свежий | `availability == "available"` |
| `online` + health `ok`, `observed_at` = now−200s | `availability == "unknown"` |
| `online` + health `error` | `availability == "unknown"` |
| `capacity_mbps` не задан | в JSON ровно `"capacity_mbps":null`, а не `0` (проверка по `map[string]any`, не по struct) |
| `draining`/`retired` | отсутствуют в каталоге (выведенный узел не должен светиться как выбор) |
| анонимный запрос через `e.Anonymous == nil`-сценарий | не тестируется здесь: закрытость маршрута доказывает матрица задачи 15 |

Run: `make up-dev && make integration`
Expected: PASS.

- [ ] **Step 6: Коммит**

```bash
git add internal/servers tests/integration/catalog_test.go services/api/router.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(servers): каталог GET /servers с availability из health"
```

---

### Task 3: WireGuard-конфиг — рендер `[Interface]/[Peer]` и разбор с инъекционной стойкостью

**Files:**
- Create: `internal/connections/wgconfig.go`, `internal/connections/wgconfig_test.go`

**Interfaces:**
- Consumes: `db.VpnServer` ( advertised_host, listen_port, public_key, mtu, keepalive_sec), `netip.Addr`.
- Produces:
  - `type Config struct{ Address netip.Prefix; DNS []netip.Addr; MTU, Keepalive int;
    PeerPublicKey string; PeerHost string; PeerPort int; AllowedIPs []netip.Prefix }` —
    поля `PrivateKey` в структуре нет намеренно: то, чего в этом пакете не может быть,
    не может и утечь (спецификация §3 правило 1);
  - `Render(srv db.VpnServer, address netip.Addr) (string, error)` — текст клиента **без
    строки `PrivateKey`**;
  - `Parse(text string) (Config, error)`;
  - `(Config) SerializeNoPrivateKey() (string, error)` — каноническая пересборка (именно она
    идёт наружу после round-trip в тестах) и она же отказывается от невалидных значений.
- Ни `net/http`, ни БД: модуль чистый, чтобы инъекционные тесты (шаг 3) не зависели от стека.

- [ ] **Step 1: Тест round-trip — `internal/connections/wgconfig_test.go`, дословный исходник**

```go
package connections

import (
	"net/netip"
	"strings"
	"testing"
)

func serverRow() Config {
	return Config{
		Address: netip.MustParsePrefix("10.99.7.42/32"),
		DNS:     []netip.Addr{netip.MustParseAddr("10.99.7.1")},
		MTU:     1420, Keepalive: 25,
		PeerPublicKey: "bm92YXZwbi1wbGFuLWZpeHR1cmUta2V5LTAwMDAwMDA=",
		PeerHost:      "de1.novavpn.local", PeerPort: 51820,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
}

func TestParseRoundTripIsStable(t *testing.T) {
	in := serverRow()
	text, err := in.SerializeNoPrivateKey()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	back, err := Parse(text)
	if err != nil {
		t.Fatalf("parse: %v (%s)", err, text)
	}
	again, err := back.SerializeNoPrivateKey()
	if err != nil {
		t.Fatalf("reserialize: %v", err)
	}
	if again != text {
		t.Fatalf("round-trip разъехался:\n--- первое\n%s\n--- второе\n%s", text, again)
	}
	if strings.Contains(text, "PrivateKey") {
		t.Fatalf("в тексте клиента появился приватный ключ: %s", text)
	}
}

func TestParseKeepsAddressAndAllowedIPs(t *testing.T) {
	text, err := serverRow().SerializeNoPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if c.Address.String() != "10.99.7.42/32" {
		t.Errorf("Address = %v, want 10.99.7.42/32", c.Address)
	}
	if len(c.AllowedIPs) != 1 || c.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Errorf("AllowedIPs = %v", c.AllowedIPs)
	}
	if c.PeerPort != 51820 || c.PeerHost != "de1.novavpn.local" {
		t.Errorf("endpoint = %s:%d", c.PeerHost, c.PeerPort)
	}
}

func TestParseRejectsPrivateKeyLine(t *testing.T) {
	// Клиентский приватный ключ не проходит через API ни в какую сторону, и разбор
	// это закрепляет: конфиг с такой строкой — не наш конфиг.
	text, err := serverRow().SerializeNoPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(text, "[Interface]\n", "[Interface]\nPrivateKey = SKM= \n", 1)
	if _, err := Parse(bad); err == nil {
		t.Fatal("конфиг с PrivateKey принят")
	}
}
```

Run: `make unit`
Expected: FAIL — `undefined: Config`.

- [ ] **Step 2: Реализовать рендер и разбор**

Схема, не исходник. Формат вывода (канон, порядок ключей фиксирован):

```
[Interface]
Address = 10.99.7.42/32
DNS = 10.99.7.1
MTU = 1420

[Peer]
PublicKey = <44 символа>
AllowedIPs = 0.0.0.0/0
Endpoint = de1.novavpn.local:51820
PersistentKeepalive = 25
```

Требования к `Parse`:

- Разрешены ровно две секции в этом порядке: одна `[Interface]`, одна `[Peer]`. Третья
  секция, повтор секции, ключ вне секции, дубликат ключа, пустое значение, неизвестный ключ —
  ошибка.
- Значения проверяются по типу, а не «на всякий случай строкой»: `Address` → `netip.Prefix`
  с маской `/32` и IPv4; `DNS` → список `netip.Addr`; `MTU` → 1280..1420; `PersistentKeepalive`
  → 5..120; `PublicKey` → паттерн формы `^[A-Za-z0-9+/]{43}=$` (тот же, что `devices_key_shape`
  в схеме): каноничность проверяет единственная запись ключа — `devices.Register` и
  `RotateKey` (задача 8), а `connections` не импортирует `devices`, потому что оба модуля
  должны ходить только в `db` — иначе через две задачи появится цикл; `Endpoint` →
  `host:port` с паттерном host `^[A-Za-z0-9.-]{1,253}$` и портом 1..65535; `AllowedIPs` →
  список `netip.Prefix`.
- `PrivateKey`, `PresharedKey`, `Table`, `FwMark`, `SaveConfig`, `LogConf` — запрещённые
  ключи: ошибка с именем ключа в сообщении. Причина в комментарии: приватный ключ не
  покидает устройство (спецификация §3 правило 1), `PresharedKey`/`Table`/`FwMark`
  меняют поведение ядра и не входят в контракт A.
- Никакого `strings.Split` по пробелам: разбор `Key = value` идёт по первому `=`, значения
  режутся по запятой только там, где список. CRLF внутри значения обязан быть отвергнут
  (символы `\r`, `\n`, `\x00`, `\t` в значении — ошибка).
- `Render(srv db.VpnServer, address netip.Addr) (string, error)` собирает `Config` из строки
  сервера (host/port/mtu/keepalive/pubkey), DNS — `NodeTunnelAddress(srv.AddressPoolV4)`
  (база пула + 1, см. задачу 4) и вызывает `SerializeNoPrivateKey`.

- [ ] **Step 3: Инъекционная стойкость — добавить в `wgconfig_test.go`**

Дословный исходник:

```go
package connections

// Таблица гостевых значений, каждое из которых должно быть отвергнуто. Это проверка
// модели угроз (спецификация §2, строка «скомпрометированный ответ API»): серверные
// строки не имеют права попасть ни в shell, ни в чужую секцию конфига.
var hostile = []struct {
	name string
	mutate func(*Config)
}{
	{"CRLF в host", func(c *Config) { c.PeerHost = "ok.example.com\r\nPrivateKey = SKA=" }},
	{"shell-метасимволы в host", func(c *Config) { c.PeerHost = "a;rm -rf /" }},
	{"обратные кавычки", func(c *Config) { c.PeerHost = "$(whoami).example.com" }},
	{"вложенная секция в host", func(c *Config) { c.PeerHost = "x.example.com\n[Peer]" }},
	{"неканонический pubkey", func(c *Config) { c.PeerPublicKey = "AAA=" }},
	{"unicode-обфускация host", func(c *Config) { c.PeerHost = "арьтм.-com" }},
	{"порт вне диапазона", func(c *Config) { c.PeerPort = 70000 }},
	{"порт нулевой", func(c *Config) { c.PeerPort = 0 }},
	{"маска не /32", func(c *Config) { c.Address = netip.MustParseAddr("10.99.7.0") }},
	{"IPv6 allow-all без адреса", func(c *Config) {
		c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
	}},
	{"MTU за пределами", func(c *Config) { c.MTU = 9000 }},
	{"пустой endpoint host", func(c *Config) { c.PeerHost = "" }},
}

func TestSerializeRefusesHostileValues(t *testing.T) {
	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			c := serverRow()
			h.mutate(&c)
			// Сериализатор обязан отказаться, а не записать: «собери и проверь потом»
			// здесь означало бы, что отказ ловит только парсер.
			text, err := c.SerializeNoPrivateKey()
			if err == nil {
				if _, perr := Parse(text); perr == nil {
					t.Fatalf("враждебное значение принято: %s", text)
				}
			}
		})
	}
}
```

Замечания по двум случаям, чтобы их не «починили» ослаблением:

- `IPv6 allow-all без адреса` отвергается по ADR-007: `::/0` без IPv6-адреса в `[Interface]`
  — это тихий blackhole, а не нейтральное значение.
- `маска не /32` отвергается и сериализатором, и парсером: адрес клиента в туннеле — ровно
  один `/32`, любое другое значение означает, что конфигурацию собрали не мы.

- [ ] **Step 4: Прогон и коммит**

Run: `make unit && make vet`
Expected: PASS.

```bash
git add internal/connections/wgconfig.go internal/connections/wgconfig_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(connections): рендер и безопасный разбор конфига WireGuard"
```

---

### Task 4: Аллокация адреса — выбор минимального свободного и занятие под блокировкой

**Files:**
- Create: `internal/connections/address.go`, `internal/connections/address_test.go`,
  `tests/integration/address_test.go`
- Modify: `internal/entitlements/entitlements.go` (поле `EndsAt` — нужно задаче 5, а
  читается из того же запроса, что и права)

**Interfaces:**
- Consumes: `LockServerRow`, `BusyAddresses`, `ClaimAddress`, `db.VpnServer.AddressPoolV4`.
- Produces:
  - `connections.NodeTunnelAddress(pool netip.Prefix) netip.Addr` — база пула + 1; это адрес
    `wg0` узла и он же recursor в туннеле (спецификация §8, пример `10.99.0.1` в §4.1 —
    это ровно база пула `10.99.0.0/24`);
  - `connections.PickAddress(pool netip.Prefix, busy map[netip.Addr]bool) (netip.Addr, error)`
    и `ErrPoolExhausted`;
  - `connections.Allocate(ctx context.Context, q *db.Queries, srv db.VpnServer, profileID uuid.UUID) (netip.Addr, error)`;
  - `entitlements.Entitlement.EndsAt *time.Time` (nil — бессрочная подписка).

- [ ] **Step 1: Падающий unit-тест на `PickAddress` — `internal/connections/address_test.go`, дословный исходник**

```go
package connections

import (
	"net/netip"
	"testing"
)

func TestNodeTunnelAddressIsFirstUsable(t *testing.T) {
	if got := NodeTunnelAddress(netip.MustParsePrefix("10.99.7.0/24")); got.String() != "10.99.7.1" {
		t.Errorf("NodeTunnelAddress = %v", got)
	}
	if got := NodeTunnelAddress(netip.MustParsePrefix("10.99.0.0/24")); got.String() != "10.99.0.1" {
		t.Errorf("пример спецификации §4.1 должен совпасть: %v", got)
	}
}

func TestPickAddressIsLowestFree(t *testing.T) {
	pool := netip.MustParsePrefix("10.99.7.0/28")
	busy := map[netip.Addr]bool{
		netip.MustParseAddr("10.99.7.1"): true, // узел всегда зарезервирован
		netip.MustParseAddr("10.99.7.2"): true,
	}
	got, err := PickAddress(pool, busy)
	if err != nil {
		t.Fatalf("PickAddress: %v", err)
	}
	if got.String() != "10.99.7.3" {
		t.Errorf("адрес = %v, want 10.99.7.3 (минимальный свободный)", got)
	}
}

func TestPickAddressExcludesNetworkAndBroadcast(t *testing.T) {
	// /30: 10.99.7.0 сеть, .1 узел, .2 — единственный клиент, .3 broadcast.
	pool := netip.MustParsePrefix("10.99.7.0/30")
	got, err := PickAddress(pool, map[netip.Addr]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.99.7.2" {
		t.Errorf("адрес = %v, want 10.99.7.2", got)
	}
	if _, err := PickAddress(pool, map[netip.Addr]bool{
		netip.MustParseAddr("10.99.7.2"): true,
	}); err != ErrPoolExhausted {
		t.Errorf("исчерпание пула: err = %v, want ErrPoolExhausted", err)
	}
}

func TestPickAddressRejectsNonIPv4Prefix(t *testing.T) {
	for _, p := range []string{"2001:db8::/64", "10.99.7.1/32"} {
		if _, err := PickAddress(netip.MustParsePrefix(p), nil); err == nil {
			t.Errorf("пул %s принят как пул клиентов", p)
		}
	}
}
```

Run: `make unit`
Expected: FAIL — `undefined: PickAddress`.

- [ ] **Step 2: Реализовать `internal/connections/address.go`**

Схема, не исходник. Правила:

- Пул обязан быть IPv4 и `/29…/24` (проверка маски даёт внятную ошибку вместо «пула нет»:
  `/31` и `/32` не содержат клиентских адресов, `/8` — 16 млн адресов и маскирует ошибку
  конфигурации).
- Диапазон кандидатов: `base+2 … last-1` (сеть, адрес узла, broadcast). Это и есть
  обоснование теста `/30`.
- `busy` включает адрес узла принудительно (`NodeTunnelAddress`), даже если в `busy` его
  нет: узел не может получить клиентский адрес, и наоборот — иначе `DNS = 10.99.7.42`
  означал бы, что рекурсор живёт у клиента.
- `PickAddress` детерминирован: обход по числовому порядку (`Addr.As4()` → `binary.BigEndian`),
  а не по итератору `netip.Prefix.Range` в случайном порядке.
- `Allocate(ctx, q, srv, profileID)` вызывается **внутри транзакции вызывающего** (задача 5):
  `LockServerRow(srv.ID)` → `BusyAddresses(srv.ID)` → `PickAddress` → `ClaimAddress`.
  Если `ClaimAddress` вернул `pgx.ErrNoRows` — это гонка с параллельной выдачей: вернуть
  `ErrAddressRace`, чтобы вызывающий ретраил выборку (не весь запрос) до 3 раз.
  Комментарий обязан объяснять, зачем ретрай, если уже стоит advisory lock: lock сериализует
  выдачу *этого* сервера, а `ClaimAddress` — последняя линия, если кто-то обошёл lock
  (будущий скрипт, прямой вызов).

- [ ] **Step 3: `EndsAt` в entitlements — дословная правка `internal/entitlements/entitlements.go`**

В struct `Entitlement` после `TrafficQuotaBytes` добавить поле и в `ForUser` — присваивание:

```go
	// Когда подписка кончается. Профили выдаются ровно до этой отметки (задача 5):
	// право не должно пережить источник права.
	EndsAt *time.Time
```

```go
		TrafficQuotaBytes: row.TrafficQuotaBytes,
		EndsAt:            row.SubscriptionEndsAt,
```

`LiveSubscriptionByUser` уже выбирает `s.ends_at`; после `make sqlc-generate` поле
называется `SubscriptionEndsAt` (`s.id AS subscription_id` даёт префикс, `ends_at` — без
конфликта). Если генератор выдал другое имя — брать его дословно, а не переименовывать SQL.

- [ ] **Step 4: Интеграционный тест конкурентной выдачи — `tests/integration/address_test.go`**

Схема, не исходник.

| случай | ожидание |
|---|---|
| 10 горутин на пул `/28` (11 клиентских адресов) с разными profile id | 10 успех, **все адреса различны**; `SELECT count(DISTINCT address)` = 10 |
| 12 горутин на тот же пул | 2 отказа `ErrPoolExhausted` (или `ErrAddressRace`, исчерпавший ретраи), живых назначений ≤ 11 |
| адрес только что освобождён | `Allocate` его **не** берёт (окно §7.2), после сдвига `reusable_at` в прошлое — берёт |
| попытка взять адрес узла (`base+1`) | никогда не выдаётся; в `tunnel_addresses` строки с ним нет |
| два разных сервера с одинаковым пулом | один и тот же адрес выдаётся обоим: PK — пара `(server_id, address)` (спецификация §6) |

Хелпер `seedProfile` из задачи 1 здесь не нужен: `Allocate` принимает произвольный
`profileID`, а существование строки профиля проверяет FK на пути задачи 5 — здесь важно
именно конкурентное поведение аллокации.

Run: `make up-dev && make integration`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add internal/connections/address.go internal/connections/address_test.go \
        tests/integration/address_test.go internal/entitlements/entitlements.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(connections): аллокация адреса под блокировкой строки сервера"
```

---

### Task 5: Выдача, отзыв и конфиг профиля — бизнес-правила §7.1–7.2

**Files:**
- Create: `internal/connections/service.go`, `tests/integration/profiles_test.go`
- Modify: `internal/db/query/profiles.sql` (если тесты вскроют недостающую выборку —
  только добавить запрос, а не переписывать существующие)

**Interfaces:**
- Consumes: `devices`-доменные проверки **не** импортируются (правило задачи 3: оба модуля
  ходят в `db`); `entitlements.Service`, `db.Queries`, `pgxpool`, `Allocate` (задача 4),
  `Render` (задача 3), `InsertConnectionEvent`.
- Produces (пакет `connections`):
  - `type Service struct{ pool *pgxpool.Pool; q *db.Queries; ent *entitlements.Service }`,
    `NewService(pool *pgxpool.Pool, ent *entitlements.Service) *Service`;
  - `func (s *Service) Issue(ctx context.Context, userID, deviceID, serverID uuid.UUID) (db.VpnProfile, error)`;
  - `func (s *Service) Revoke(ctx context.Context, userID, deviceID, serverID uuid.UUID) (db.VpnProfile, error)`;
  - `func (s *Service) List(ctx context.Context, userID, deviceID uuid.UUID) ([]db.VpnProfile, error)`;
  - `func (s *Service) Profile(ctx context.Context, userID, deviceID, serverID uuid.UUID) (db.VpnProfile, error)`;
  - `func (s *Service) ConfigText(ctx context.Context, userID, deviceID, serverID uuid.UUID) (string, error)`;
  - `func ProfileExpiry(ent entitlements.Entitlement, now time.Time) time.Time`;
  - ошибки-стражи: `ErrForbiddenDevice`, `ErrDeviceRevoked`, `ErrServerUnknown`,
    `ErrServerNotAvailable`, `ErrAlreadyActive`, `ErrNotActive`, `ErrNoSubscription`,
    `ErrPoolExhausted`, `ErrAddressRace` (`errors.New`, как в `devices/service.go`);
  - константу `DefaultProfileTTL = 30 * 24 * time.Hour`;
  - константу `RotationOverlap = 10 * time.Minute` — её читают `devices` (задача 8) и
    `servers` (задача 9); объявлена здесь, а не в `devices`, потому что окном владеет
    профиль: §7.3 пишет `overlap_valid_until = now() + 10 min` про строку `vpn_profiles`,
    и desired set сравнивает с ней же.

- [ ] **Step 1: Чистая функция срока жизни — дословный исходник (в `service.go`)**

```go
// DefaultProfileTTL — потолок жизни профиля без подписки-ограничителя. Спецификация
// §7.1 говорит «выдать профиль», но не говорит, на сколько: 30 суток — решение A-2,
// и оно в одной константе. Смысл числа: профиль переживает обычный перезапуск клиента,
// но не переживает молчаливо забытую подписку.
const DefaultProfileTTL = 30 * 24 * time.Hour

// ProfileExpiry — профиль не может жить дольше права, которое его выдало.
// Два места, решающих «когда кончится доступ», обязательно разошлись бы, поэтому
// источник истины один: ends_at подписки (задача 4 перенёс её в Entitlement).
func ProfileExpiry(ent entitlements.Entitlement, now time.Time) time.Time {
	expiry := now.Add(DefaultProfileTTL)
	if ent.EndsAt != nil && ent.EndsAt.Before(expiry) {
		return *ent.EndsAt
	}
	return expiry
}

// RotationOverlap — окно, в котором узел держит и старый, и новый ключ (спецификация
// §7.3). Число объявлено один раз здесь, а не по месту в devices и в servers: расхождение
// двух копий рвёт соединение — предок снимется раньше, чем клиент поднимет новый ключ.
const RotationOverlap = 10 * time.Minute
```

Unit-тест `TestProfileExpiry` (в `internal/connections/service_test.go`, дословный
исходник — три случая): подписка бессрочная → `now+30d`; подписка кончается через 2 суток
→ `EndsAt`; подписка кончается через 60 суток → всё равно `now+30d` (потолок плана, а не
подписки).

- [ ] **Step 2: `Issue` — схема, не исходник (порядок проверок = §7.1, менять нельзя)**

| # | шаг | отказ |
|---|---|---|
| 1 | `q.DeviceByID(deviceID)`, `d.UserID == userID` | `ErrForbiddenDevice` (чужой и несуществующий отвечают одинаково — оракула не будет, как в `devices.OwnedBy`) |
| 2 | `d.RevokedAt == nil` | `ErrDeviceRevoked` |
| 3 | `s.ent.ForUser(ctx, userID)` | `ErrNoSubscription` (обернуть `entitlements.ErrNoActiveSubscription`) |
| 4 | `q.ServerByID(serverID)` | `ErrServerUnknown` |
| 5 | `srv.MaintenanceStatus == db.MaintenanceStatusOnline` | `ErrServerNotAvailable` — §7.1 буквально: «сервер online». `draining` ещё работает, но новому клиенту туда идти нельзя: он получит туннель, который через минуту опустеет |
| 6 | транзакция: `LockServerRow` → `Allocate` → `InsertProfile` → `BumpServerConfigVersion` → `InsertConnectionEvent(profile_issued)` | `ErrPoolExhausted`, `ErrAddressRace`, unique-violation → `ErrAlreadyActive` |
| 7 | вернуть вставленный профиль | — |

Обязательные детали, каждая из которых без комментария выглядит избыточной:

- Всё, что меняет набор пиеров, поднимает `config_version` **в той же транзакции**, что и
  изменение: версия, обновлённая после коммита, на секунду отстаёт от desired set, и узел
  успевает отдать `304` на устаревшей версии (задача 11).
- Событие `profile_issued` пишется внутри транзакции: событие о выдаче, которая не
  состоялась, хуже, чем отсутствие события; наоборот — нельзя.
- `detail` события: `{"server_id":…,"address":…,"expires_at":…}` — коды и версии, ничего
  про трафик (ТЗ §11).
- unique-violation (`profiles_one_active_per_device_server`) ловится через
  `isUniqueViolation(err)` (хелпер `devices`-пакета не импортируется — скопировать
  реализацию `errors.As(*pgconn.PgError)` и `Code == "23505"` в `connections`, а вызов
  `devices` из `connections` запрещён задачей 3). Комментарий обязан говорить, что это
  гонка двух параллельных выдач, а не «неизвестная ошибка БД».
- `ProfileExpiry` вызывается **до** транзакции (нужен `ent`), и подписка, истёкшая между
  проверкой и вставкой, остаётся действующей на весь TTL профиля — это ограничение §13,
  и оно зафиксировано в комментарии, а не замалчивается.

- [ ] **Step 3: `Revoke` — схема, не исходник (§7.2)**

`DeviceByID`+владелец → `ActiveProfileByDeviceServer` (`pgx.ErrNoRows` → `ErrNotActive`) →
транзакция: `RevokeProfile` → `ReleaseAddressByProfile` → `BumpServerConfigVersion` →
`InsertConnectionEvent(profile_revoked)`. Возвращает отозванный профиль (нужен статус `204`
без тела, но сервис возвращает данные — handler их не печатает, зато тест доказывает адрес).
Окно переиспользования в 5 минут задаёт SQL (задача 1), а не Go: два места с одним числом
обязаны разойтись.

- [ ] **Step 4: `List`, `Profile`, `ConfigText`**

Схема, не исходник. `ConfigText`: только активный и непросроченный профиль; `superseded`
внутри overlap — **не** отдаётся (у клиента уже есть новый ключ; старый конфиг не должен
появляться в HTTP второй раз) → `ErrNotActive`; `revoked`/`expired` → `ErrNotActive`;
`expires_at <= now` → `ErrNotActive`. Сборка текста — `Render(srv, profile.AddressV4)`.
`Profile` читает `LatestProfileByDeviceServer`, чтобы показать и отозванный.

- [ ] **Step 5: Интеграционный тест — `tests/integration/profiles_test.go`**

Схема, не исходник. Фикстуры: `seedUser`, `seedDevice`, `seedServer` + `setServerOnline`.

| случай | ожидание |
|---|---|
| выдача на online-сервер | `201`-подобный профиль: статус `active`, адрес ∈ пула и ≠ адрес узла, `expires_at = ProfileExpiry(...)`, `config_version` сервера +1, событие `profile_issued` |
| выдача на сервер в `maintenance` | `ErrServerNotAvailable` (и **не** израсходован адрес: `count(*) from tunnel_addresses` тот же) |
| повтор выдачи на тот же сервер | `ErrAlreadyActive`, `config_version` не изменился |
| выдача на чужое устройство | `ErrForbiddenDevice` |
| выдача на отозванное устройство | `ErrDeviceRevoked` |
| выдача без подписки | `ErrNoSubscription` |
| отзыв | статус `revoked`, `revoked_at` выставлен, адрес освобождён с `reusable_at ≈ now+5min`, `config_version` +1, событие `profile_revoked` |
| повтор отзыва | `ErrNotActive` |
| конфиг | содержит `[Interface]`, `Address = <выданный>/32`, `Endpoint`, `PersistentKeepalive`, **не** содержит `PrivateKey` и `PresharedKey` |
| два профиля на двух серверах одного пользователя | адреса из разных пулов, оба активны: лимит устройств не путается с числом серверов |
|Параллельно — 10 горутин на выдачу одному устройству разных серверов | ровно 10 профилей, все `server_id` различны (проверяет, что lock берётся по серверу, а не глобально) |

Run: `make up-dev && make integration`
Expected: PASS.

- [ ] **Step 6: Коммит**

```bash
git add internal/connections/service.go internal/connections/service_test.go \
        internal/db/query/profiles.sql tests/integration/profiles_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(connections): выдача и отзыв профиля с аллокацией и событиями"
```

---

### Task 6: HTTP-слой профилей — маршруты §5.1, лимит 30/мин и новый код ошибки

**Files:**
- Create: `internal/connections/handlers.go`, `tests/integration/profiles_http_test.go`
- Modify: `internal/httpx/envelope.go` (константа), `services/api/router.go` (монтаж +
  отдельный лимитер выдачи), `internal/servers/handlers.go` (если каталог монтировался без
  `q` — нет, правки не нужны)

**Interfaces:**
- Consumes: `connections.Service` (задача 5), `httpx.Idempotency.Middleware("profile_issue")`,
  `httpx.WriteError`, `httpx.DecodeJSON`, `httpx.UserIDFromContext`, `r.PathValue`.
- Produces:
  - `connections.NewHandler(svc *Service, idem *httpx.Idempotency, issueLimiter func(http.Handler) http.Handler) *Handler`;
  - `(*Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators)`;
  - `type profileView` — JSON: `id`, `device_id`, `server_id`, `address_v4`, `status`,
    `issued_at`, `expires_at`, `overlap_valid_until`, `revoked_at` (nullable → `*time.Time`);
  - константу `httpx.ErrServerNotAvailable ErrorCode = "server_not_available"`;
  - константы сборщика `profileIssuePerMin = 30.0`, `profileIssueBurst = 5` в
    `services/api/router.go`.

- [ ] **Step 1: Код ошибки — дословная правка `internal/httpx/envelope.go`**

После `ErrDuplicateDevice` добавить:

```go
	// 409 server_not_available — §7.1 требует отказа «сервер не online» при выдаче, а
	// §5.2 требует стабильного кода. Отдельный от `conflict`: клиент по коду понимает,
	// что стоит выбрать другой сервер, а не повторять тот же запрос.
	ErrServerNotAvailable ErrorCode = "server_not_available"
```

- [ ] **Step 2: Таблица маршрутов и ответов**

Схема, не исходник. Все пять закрыты (`dec.Auth`), параметр пути — `r.PathValue("id")` для
устройства и `r.PathValue("serverID")` для сервера (`http.NewServeMux` с Go 1.22+).

| метод и путь | успех | ошибки (кроме `401`/`429`/`500`) |
|---|---|---|
| `POST /api/v1/devices/{id}/profiles` | `201 profileView` | `400 invalid_request` (`server_id` не uuid или тело битое), `400 idempotency_key_required`, `403 forbidden` (нет подписки), `403 forbidden` (устройство отозвано), `404 not_found` (чужое/нет такого устройства или сервера), `409 conflict` (уже выдан), `409 server_not_available`, `409 conflict` + details `{"reason":"pool_exhausted"}` |
| `GET /api/v1/devices/{id}/profiles` | `200 {"profiles":[…]}` | `404 not_found` (чужое устройство) |
| `GET /api/v1/devices/{id}/profiles/{serverID}` | `200 profileView` | `404 not_found` |
| `DELETE /api/v1/devices/{id}/profiles/{serverID}` | `204` без тела | `404 not_found`, `409 conflict` (уже отозван; details `{"status":…}`) |
| `GET /api/v1/devices/{id}/profiles/{serverID}/config` | `200 text/plain; charset=utf-8` | `404 not_found`, `409 conflict` (`not_active`) |

Правила, которые нельзя потерять:

- `POST` оборачивается в `h.idem.Middleware("profile_issue")` ровно так же, как
  `devices.register` (задача 15 A-1): требование заголовка проверяется **до** обёртки,
  иначе тест с `nil`-хранилищем проходил бы молча.
- Выдача дополнительно лимитируется `issueLimiter` — **внутри** `dec.Auth`, снаружи
  идемпотентности: порядок важен, потому что `429` обязан возникать до записи слота
  идемпотентности, иначе отклонённый запрос оставил бы занятой ключ.
- Ответ конфига — `text/plain`, а не JSON: клиент сохраняет
  его как файл профиля и отдёт напрямую утилитам `
  `wg-quick` и `wg showconf`; оборачивание в JSON вынудило бы клиента развернуть
  строку с экранированием переводов строк. Контракт (задача 14) описывает это явно.
- Проверка права на объект — в сервисе (`DeviceByID` + сравнение владельца), не в
  middleware (спецификация §5.2).
- Русские сообщения: `"требуется аутентификация"`, `"сервер недоступен для выдачи"`,
  `"профиль уже выдан"`, `"профиль не активен"`, `"нет активной подписки"`,
  `"внутренняя ошибка"`. Инфраструктурные строки (`Idempotency-Key is required`, лимитер)
  остаются английскими.

- [ ] **Step 3: Монтаж в `services/api/router.go`**

Схема, не исходник:

```go
	profileIssue := lim.Middleware("profile_issue", httpx.RatePerMinute(profileIssuePerMin),
		profileIssueBurst, userKey)
	connections.NewHandler(connections.NewService(d.Pool, d.Ent),
		httpx.NewIdempotency(httpx.NewPGIdempotency(d.Pool)), profileIssue).RegisterRoutes(mux, dec)
```

Константы рядом с `userPerMin` — с комментарием «число из §5.2, окно на пользователя» и
объяснением, почему бакет отдельный от `user`: общий бюджет закрытых маршрутов (600/мин)
не должен позволять одному пользователю удерживать 30 выдач в минуту, одновременно делая
600 списаний.

- [ ] **Step 4: Интеграционный тест — `tests/integration/profiles_http_test.go`**

Схема, не исходник. Как `devices_test.go`: `passthrough` для `Auth`/`Anonymous`, отдельный
`limiter`-декоратор = `passthrough` (лимитер проверяется в `matrix_test.go` задачи 15 и в
`internal/httpx/ratelimit_test.go`, а здесь важна маршрутизация и коды).

- `POST` без `Idempotency-Key` → `400` + `"idempotency_key_required"` в теле.
- `POST` с плохим `server_id` (`"not-a-uuid"`) → `400` + details `{"field":"server_id"}`.
- `POST` → `201`, повтор с тем же ключом → тот же `201`-ответ + заголовок
  `Idempotency-Replayed: true`; повтор с тем же ключом и другим телом → `409
  idempotency_key_conflict`.
- `POST` на сервер в `maintenance` → `409` + `"server_not_available"`.
- `GET` списка → массив с `status`; `GET` профиля → тот же `profileView`; `DELETE` → `204`
  пустое тело; второй `DELETE` → `409`.
- `GET …/config` → `Content-Type: text/plain`, тело содержит `[Peer]`, не содержит
  `PrivateKey`; `GET …/config` после отзыва → `409`.
- Чужое устройство (токен пользователя B, `id` устройства A) → `404` на всех пяти маршрутах
  и **одинаковым** телом, чтобы по ответу нельзя было отличить «нет такого» от «не твоё».

Run: `make unit && make vet && make integration`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add internal/connections/handlers.go internal/httpx/envelope.go \
        services/api/router.go tests/integration/profiles_http_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(connections): HTTP-слой профилей, лимит выдачи и код server_not_available"
```

---

### Task 7: Отзыв устройства — `DELETE /api/v1/devices/{id}`

**Files:**
- Create: `internal/devices/delete_test.go` (unit — не нужен, если тест только на БД; тогда
  случай остаётся в интеграционном), `tests/integration/device_delete_test.go`
- Modify: `internal/devices/service.go`, `internal/devices/handlers.go`,
  `internal/db/query/devices.sql` (`RevokeDevices` пакетно), `internal/db/query/profiles.sql`
  (`RotationChainIDs` — да, в `devices.sql`: это запрос про устройства)

**Interfaces:**
- Consumes: `RevokeProfilesForDevices`, `ReleaseAddressesByProfiles`,
  `BumpServerConfigVersion`, `InsertConnectionEvent`, `DeviceByID`.
- Produces:
  - `(s *Service) DeleteDevice(ctx context.Context, userID, deviceID uuid.UUID) (int, error)`
    — число отозванных профилей;
  - маршрут `DELETE /api/v1/devices/{id}`;
  - запрос `RotationChainIDs :many` (рекурсивный CTE в обе стороны) и
    `RevokeDevices :exec` (`WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL`).

- [ ] **Step 1: Запросы — дословный исходник, добавить в `internal/db/query/devices.sql`**

```sql
-- name: RevokeDevices :exec
-- revoked_at IS NULL: повторный отзыв не должен двигать отметку времени — по ней судят,
-- когда доступ действительно перестал существовать.
UPDATE devices SET revoked_at = now()
 WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL;

-- name: RotationChainIDs :many
-- Цепочка ротации в обе стороны. Вверх — потому что отзыв потомка обязан закрыть
-- overlap предка (§7.3): иначе ключ, от которого человек уже отказался, останется в
-- desired set ещё на окно. Вниз — потому что потомок без предка для пользователя
-- «то же самое устройство с новым ключом», и отзыв родителя обязан гасить его тоже.
WITH RECURSIVE up AS (
    SELECT id, rotation_of FROM devices WHERE id = $1
  UNION ALL
    SELECT d.id, d.rotation_of FROM devices d JOIN up ON d.id = up.rotation_of
), down AS (
    SELECT id, rotation_of FROM devices WHERE id = $1
  UNION ALL
    SELECT d.id, d.rotation_of FROM devices d JOIN down ON d.rotation_of = down.id
), chain AS (
    SELECT id FROM up
  UNION
    SELECT id FROM down
)
SELECT id FROM chain;
```

Правка `profiles.sql`: у `RevokeProfilesForDevices` (задача 1) возврата `user_id` нет —
добавить `RETURNING id, server_id, device_id` уже есть; события требуют `user_id`, поэтому
в запрос вводится JOIN с `devices` и возврат `d.user_id`:

```sql
-- name: RevokeProfilesForDevices :many
UPDATE vpn_profiles p
   SET status = 'revoked', revoked_at = now()
  FROM devices d
 WHERE p.id IN (SELECT id FROM vpn_profiles
                 WHERE device_id = ANY($1::uuid[]) AND status IN ('active','superseded'))
   AND p.device_id = d.id
 RETURNING p.id, p.server_id, p.device_id, d.user_id;
```

Эта правка — единственное место, где план меняет запрос задачи 1 после его коммита:
потребность в `user_id` стала видна только когда запись событий оказалась в транзакции
отзыва устройства.

- [ ] **Step 2: `DeleteDevice` — схема, не исходник**

Транзакция (`db.RunInTx`), порядок фиксирован:

1. `DeviceByID` → владелец → `ErrForbiddenDevice` (404 на HTTP);
2. `RotationChainIDs`;
3. `RevokeDevices(chain)`;
4. `RevokeProfilesForDevices(chain)` → rows;
5. `ReleaseAddressesByProfiles(ids(row))`;
6. по каждому различному `server_id` из rows → `BumpServerConfigVersion`;
7. на каждый row → `InsertConnectionEvent(profile_revoked, user_id, device_id, server_id,
   detail {"reason":"device_deleted"})`.

Вне транзакции проверок прав делать нельзя: между шагом 1 и шагом 4 пользователь мог
получить ещё один профиль, и он остался бы активным при «удалённом» устройстве.

- [ ] **Step 3: Handler — схема, не исходник**

`DELETE /api/v1/devices/{id}` под `dec.Auth`; `204` без тела; `400 invalid_request` на
не-uuid в пути; `404 not_found` на чужое/несуществующее (сообщение `"устройство не
найдено"`); `500` на прочее. Идемпотентность не требуется: `DELETE` по определению
повторозащищён (второй вызов даёт `404`), а `§5.2` требует заголовок только на трёх POST.

- [ ] **Step 4: Интеграционный тест — `tests/integration/device_delete_test.go`**

| случай | ожидание |
|---|---|
| устройство с 2 профилями на разных серверах | `204`; оба профиля `revoked`; `config_version` обоих серверов вырос; 2 события `profile_revoked` |
| отзыв устройства, у которого есть потомок по ротации | отозваны оба устройства и все профили обоих; адрес не освобождён дважды (в `tunnel_addresses` одна строка на адрес) |
| отзыв родителя, у которого есть superseded-профиль в overlap | профиль предка `revoked`, `desired` (задача 9) на него не отдаёт пиера |
| чужое `id` | `404`, при этом состояние чужого устройства не изменилось (SELECT до/после) |
| повтор `DELETE` | `404` |
| `List` после отзыва | отозванное устройство по-прежнему возвращается (A-1: `LiveDevicesByUser` фильтрует, а handler `GET /devices` отдаёт живых; проверить, что отзыв **не** исчезает из БД) |

Последний случай уточняет контракт: `GET /devices` возвращает живых (реализация A-1),
поэтому после удаления устройства список пустеет, а строки остаются в базе — тест обязан
проверять именно это, а не «записей нет».

Run: `make up-dev && make integration`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add internal/db/query internal/devices tests/integration/device_delete_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(devices): DELETE устройства — цепочка ротации, отзыв профилей и bump"
```

---

### Task 8: Ротация ключа с overlap — `POST /api/v1/devices/{id}/keys/rotate`

**Files:**
- Modify: `internal/devices/service.go`, `internal/devices/handlers.go`,
  `internal/db/query/addresses.sql`, `internal/db/query/profiles.sql`,
  `services/api/router.go` (idem-маршрут не нужен — `Idempotency-Key` читает handler)
- Create: `tests/integration/rotation_test.go`

**Interfaces:**
- Consumes: `ParsePublicKey`, `CountLiveDevices`, `RevokeDevice`, `SupersedeProfile`,
  `InsertProfile`, `RevokeAllActiveByDeviceServer`, `ReassignAddress` (новый),
  `BumpServerConfigVersion`, `InsertConnectionEvent`, `httpx.Idempotency.Middleware("key_rotate")`,
  `connections.RotationOverlap` (задача 5). Направление импорта `devices → connections`
  разрешено: запрет задачи 3 стоит на `connections → devices`, и именно поэтому ротация
  живёт в `devices`, а окно overlap — в профиле.
- Produces:
  - `(s *Service) RotateKey(ctx context.Context, userID, parentID uuid.UUID, newPublicKey string) (db.Device, error)`;
  - ошибку `ErrNotLiveDevice` (ротация отозванного устройства);
  - маршрут `POST /api/v1/devices/{id}/keys/rotate`;
  - запрос `ReassignAddress :exec`.

- [ ] **Step 1: Перевод строки аллокации — дословный исходник, добавить в `addresses.sql`**

```sql
-- name: ReassignAddress :exec
-- §7.3: смена ключа не меняет IP клиента, поэтому профиль потомка получает тот же
-- address_v4. Строка аллокации обязана перейти к потомку: иначе отзыв предка
-- (или закрытие overlap) освободил бы адрес, по которому клиент уже ходит, и
-- следующий клиент получил бы адрес живого соединения.
UPDATE tunnel_addresses SET allocated_to = $4
 WHERE server_id = $1 AND address = $2 AND allocated_to = $3;
```

- [ ] **Step 2: `RotateKey` — схема, не исходник**

1. `ParsePublicKey(new)` → `ErrInvalidKey`; `DeviceByID`+владелец → `ErrForbiddenDevice`;
   `RevokedAt != nil` → `ErrNotLiveDevice`.
2. Дубликат ключа: `DeviceByUserAndKey` — живое устройство с таким ключом → `ErrDuplicateKey`
   (проверка **до** лимита, как в `Register`, иначе повтор на исчерпанном лимите ответил бы
   `device_limit_reached`).
3. Транзакция:
   a. `CountLiveDevices` и сравнение с лимитом **не** выполняется: предок отзывается в этой
      же транзакции, поэтому число живых устройств не растёт. Это и есть решение §4 из
      «Что план нашёл» — без него ротация на исчерпанном лимите была бы невозможна, а
      «потомок как четвёртое устройство» ломал бы обещание ТЗ §5 о совместимости.
   b. `InsertDevice{ID: new, UserID, PublicKey: new, Platform: parent.Platform,
      Name: parent.Name, RotationOf: &parent.ID}` — платформа и имя наследуются: это то же
      устройство с новым ключом, и требовать их в теле значило бы дать клиенту способ
      соврать про себя;
   c. для каждого профиля из `RevokeAllActiveByDeviceServer(parentID)`:
      `SupersedeProfile(old.ID, now.Add(connections.RotationOverlap))` → `InsertProfile` потомка (тот же
      `server_id`, тот же `address_v4`, `rotate_from = old.ID`, `expires_at` — **тот же**,
      что у предка: ротация ключа не продлевает доступ) → `ReassignAddress`;
   d. `RevokeDevice(parentID)`;
   e. по каждому затронутому серверу — `BumpServerConfigVersion`;
   f. событие `profile_issued` на каждый новый профиль, `detail {"rotated_from": old.ID}`;
   g. если у предка не было активных профилей — потомок создаётся, bump не делается,
      событие не пишется (менять нечего), ответ всё равно `200`.
4. `unique_violation` на `devices_user_key` → `ErrDuplicateKey` (гонка двух ротаций).

- [ ] **Step 3: Handler — схема, не исходник**

Тело `{"public_key": "…"}`; `Idempotency-Key` обязателен (§5.2) и проверяется до
idem-обёртки; ответ `200 deviceView` (не `201`: создаётся не новый объект в терминах
пользователя, а новое состояние того же устройства — и это надо записать в контракте
задачи 14, чтобы клиент не ждал `201`); `400 invalid_request` + details `{"field":
"public_key"}`; `409 duplicate_device`; `409 conflict` (`device_revoked` — details
`{"reason":"device_revoked"}`); `404 not_found` на чужой `id`.

- [ ] **Step 4: Интеграционный тест — `tests/integration/rotation_test.go`**

| случай | ожидание |
|---|---|
| ротация устройства с одним профилем | потомок `rotation_of = предок`, предок `revoked_at` выставлен, профиль предка `superseded` + `peer_state='rotating_old_key'` + `overlap_valid_until ≈ now+10min`, профиль потомка `active` с **тем же адресом**, `rotate_from` = id предка, `tunnel_addresses.allocated_to` = профиль потомка, `config_version` +1, событие `profile_issued` |
| ротация на лимите 3 (3 живых устройства, одно из них ротится) | `200`: живых осталось 3 (предок отозван) — это и есть проверка решения §4 |
| ротация устройства без профилей | `200`, профилей не появилось, `config_version` не изменился |
| ротация отозванного устройства | `409 conflict` + `device_revoked` |
| тот же публичный ключ, что у другого живого устройства | `409 duplicate_device`, и **не** создан потомок (проверка SELECT) |
| неканонический ключ (spare-биты nonzero) | `400 invalid_request` — фикстура строится как в `devices_test.keyAt` |
| повтор с тем же `Idempotency-Key` | тот же ответ + `Idempotency-Replayed: true`; потомок **один** (второй ротацией был бы другой id) |
| два последовательных rotate (цепочка из трёх устройств) | `RotationChainIDs` (задача 7) возвращает все три; отзыв среднего гасит крайние — проверить вызовом `DeleteDevice` |

Run: `make unit && make vet && make integration`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add internal/db/query internal/devices services/api/router.go tests/integration/rotation_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(devices): ротация ключа с overlap-окном и переносом адреса"
```

---
### Task 9: Desired set — кто имеет право быть на узле и проверка этого свойства

**Files:**
- Create: `internal/servers/desired.go`, `internal/servers/desired_test.go`,
  `tests/integration/desired_test.go`

**Interfaces:**
- Consumes: `DesiredCandidates`, `HandshakedDevicesAfter`, `ServerByID` (задача 1),
  `connections.NodeTunnelAddress` и `connections.RotationOverlap` (задачи 4 и 5).
  Направление `servers → connections` разрешено и является единственным: запрет задачи 3
  стоит на `connections → devices`, а зацикливание `servers ↔ connections` появилось бы,
  умри адресная арифметика в другом месте.
- Produces (пакет `servers`):
  - `type Peer struct` — JSON ровно как в примере спецификации §4.1: `public_key`,
    `allowed_ips` (массив строк CIDR), `expires_at` (RFC 3339 UTC), `state`
    (`active | rotating_old_key`);
  - `type DesiredSet struct` — `server_id`, `config_version`, `mtu`, `listen_port`,
    `dns_servers`, `keepalive_sec`, `peers`, `measured_at`;
  - `func Compute(ctx context.Context, q *db.Queries, serverID uuid.UUID, now time.Time) (DesiredSet, error)`;
  - ошибку `ErrServerUnknown`;
  - непубличный `type candidate struct` и чистую `selectPeers`.

- [ ] **Step 1: Чистое отсечение — дословный исходник (часть `internal/servers/desired.go`)**

```go
package servers

import (
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
)

// candidate — срез строки DesiredCandidates, достаточный для правила отсечения.
// Отдельный тип нужен, чтобы чистая часть не зависела ни от sqlc, ни от БД: §9.1
// требует проверять свойство desired set на случайных данных, а случайные данные
// проще строить как структури, чем как строки результата запроса.
type candidate struct {
	ProfileID       uuid.UUID
	DeviceID        uuid.UUID
	PublicKey       string
	Address         netip.Addr
	Status          db.ProfileStatus
	ExpiresAt       time.Time
	OverlapUntil    *time.Time
	RotateFrom      *uuid.UUID
	DeviceRevokedAt *time.Time
}

// selectPeers — единственное место, где решается, кто имеет право попасть в desired
// set (спецификация §4.1). Порядок ответа — по адресу, а не по порядку строк: узел
// сравнивает наборы как отсортированный список, и детерминированный порядок нужен
// хотя бы для того, чтобы ETag не менялся от перестановки одинаковых пиеров.
func selectPeers(cands []candidate, handshaked map[uuid.UUID]bool, now time.Time) []Peer {
	successor := make(map[uuid.UUID]candidate, len(cands))
	for _, c := range cands {
		if c.RotateFrom != nil {
			successor[*c.RotateFrom] = c
		}
	}

	peers := make([]Peer, 0, len(cands))
	for _, c := range cands {
		// Мёртвое устройство не имеет права быть в наборе, даже если его профиль по
		// какой-то причине остался active: критерий приёмки 10 сформулирован как
		// «ни при каких условиях», и проверка здесь дешевле дыры в туннеле.
		if c.DeviceRevokedAt != nil {
			continue
		}
		if !c.ExpiresAt.After(now) {
			continue
		}
		switch c.Status {
		case db.ProfileStatusActive:
			peers = append(peers, newPeer(c, string(db.PeerStateActive)))
		case db.ProfileStatusSuperseded:
			succ, ok := successor[c.ProfileID]
			if !ok || succ.DeviceRevokedAt != nil || !succ.ExpiresAt.After(now) {
				continue
			}
			if c.OverlapUntil == nil || !c.OverlapUntil.After(now) {
				continue
			}
			// Наблюдённый handshake нового ключа снимает старый немедленно (§7.3),
			// не дожидаясь конца окна.
			if handshaked[succ.DeviceID] {
				continue
			}
			peers = append(peers, newPeer(c, string(db.PeerStateRotatingOldKey)))
		}
	}

	sorted := slices.Clone(cands)
	slices.SortFunc(sorted, func(a, b candidate) int { return a.Address.Compare(b.Address) })
	byAddr := make(map[string]Peer, len(peers))
	for _, p := range peers {
		byAddr[p.AllowedIPs[0]] = p
	}
	out := make([]Peer, 0, len(peers))
	for _, c := range sorted {
		if p, ok := byAddr[c.Address.String()+"/32"]; ok {
			out = append(out, p)
		}
	}
	return out
}

func newPeer(c candidate, state string) Peer {
	return Peer{
		PublicKey: c.PublicKey,
		// /32 — единственная разрешённая маска клиентского адреса: 32-битный хост в
		// туннеле, а не подсеть (задача 3 проверяет это и на разборе).
		AllowedIPs: []string{c.Address.String() + "/32"},
		ExpiresAt:  c.ExpiresAt.UTC(),
		State:      state,
	}
}
```

Сортировка через `byAddr`, а не `sort` по готовым `Peer`, потому что адрес есть у
кандидата и он уникален в пределах узла (PK `tunnel_addresses`), а `Peer` адреса не
хранит: дублировать адрес в ответе значило бы дать два источника одного факта.

- [ ] **Step 2: Падающий unit-тест — `internal/servers/desired_test.go`, схема, не исходник**

Тест `TestDesiredSetNeverContainsRemovedAccess` — свойство, а не пример (§9.1,
критерий приёмки 10). Требования к нему:

- перебор 1000 итераций на генераторе с фиксированным зерном (`rand.NewSource`), чтобы
  падение воспроизводилось;
- генератор строит от 1 до 12 кандидатов: `ProfileID` и `DeviceID` — детерминированные из
  индекса (`uuid.MustParse` из `fmt.Sprintf` с фиксированным префиксом), `PublicKey` —
  уникальный по индексу строка вида `k007` (чистая функция ключ не валидирует: каноничность
  проверяет `devices`, задача 14 A-1), `Address` — `10.99.<i/250>.<i%250>`, уникальный;
- `Status` — случайно из четырёх значений `db.ProfileStatus` (включая `revoked` и
  `expired`, хотя SQL их не отдаёт: функция обязана быть безопасной и без фильтра БД);
- `ExpiresAt` — случайное «в прошлом» или «now+1с…30 сут»; `OverlapUntil` — `nil`,
  «в прошлом» или «в будущем»; `DeviceRevokedAt` — `nil` или «в прошлом»;
- `RotateFrom`: с вероятностью 1/3 указывает на **предыдущий** кандидат (`out[i-1]`), иначе
  `nil`. Два правила, оба из-за ловушек: указатель брать нельзя (адрес элемента растущего
  среза инвалидируется `append`, и `RotateFrom` указывал бы в мусор — копировать id в
  локальную переменную), и цель обязана быть одна на предка (иначе карта `successor` выбрала
  бы одного из двух преемников, а проверка-оракул в тесте видела бы другого);
- `handshaked` — случайно помеченные `DeviceID` из тех же кандидатов.

Инварианты, которые обязана проверять каждая итерация (проверка идёт по исходным
кандидатам, а не по повторной реализации правил — иначе тест просто второй раз пишет
ту же функцию):

1. каждый выданный `Peer` имеет `State` из `{active, rotating_old_key}`;
2. у источника каждого выданного пиера `DeviceRevokedAt == nil` и `ExpiresAt.After(now)`;
3. если источник — `superseded`: у него есть живой `active`-преемник (тот же критерий
   времени и отзыва), окно открыто (`OverlapUntil != nil && After(now)`) и преемник **не**
   в множестве наблюденных handshake;
4. ни один пиер не выдан дважды (по `PublicKey`) и ни один `AllowedIPs` не содержит ничего,
   кроме одного `/32`;
5. `selectPeers` на **перевёрнутом** входе даёт результат, побайтово равный результату на
   исходном (детерминированность и порядок);
6. пиеров не больше кандидатов.

Run: `make unit`
Expected: FAIL до реализации (`undefined: selectPeers`), PASS после.

- [ ] **Step 3: `Compute` — схема, не исходник**

1. `srv, err := q.ServerByID(ctx, serverID)`; `pgx.ErrNoRows` → `ErrServerUnknown` (для
   nodeapi это `404`, и узел по нему уходит на повторный enroll, а не на пустой набор).
2. `cands, err := q.DesiredCandidates(ctx, serverID)` → перекладывание в `[]candidate`:
   `RotateFrom` (`*string` из-за `::text`) парсится `uuid.Parse`, ошибка парсинга —
   `fmt.Errorf("servers: profile %s: bad rotate_from: %w", …)`, а не «пустой предок»:
   молча потерять ссылку означало бы снять предка раньше окна.
3. handshake-свидетельство: `ids` — `DeviceID` кандидатов с `RotateFrom != nil`; если
   `len(ids) > 0`, один вызов
   `q.HandshakedDevicesAfter(ctx, serverID, now.Add(-connections.RotationOverlap), ids)` →
   `map[uuid.UUID]bool`. Почему порога достаточно: любое открытое окно длится ровно
   `RotationOverlap`, значит любое релевантное событие не старше `now − RotationOverlap`;
   более старые события (от уже закрытых ротаций) в выборку не попадают. Граница
   сравнивается по `created_at` базы, а не по времени из отчёта узла: часы узла нам не
   свидетели (задача 10).
4. `srv.MaintenanceStatus != db.MaintenanceStatusOnline` → `Peers` = пустой **слайс**
   (`[]Peer{}`, не `nil`: `nil` сериализуется в `null`, а контракт §4.1 обещает массив) и
   никаких запросов за кандидатами. §7.6: `draining` → desired пуст; `maintenance` и
   `retired` — тем более. MTU, порт, keepalive и версия при этом отдаются настоящие: узел
   обязан видеть, что набор опустел именно по решению оператора.
5. `DNSServers = []string{connections.NodeTunnelAddress(srv.AddressPoolV4).String()}` —
   адрес рекурсора в туннеле это адрес `wg0` узла (§8, пример §4.1 `10.99.0.1` при пуле
   `10.99.0.0/24`); вторых DNS в цикле A нет, и выдумывать `8.8.8.8` запрещает §8 же.
6. `ConfigVersion: srv.ConfigVersion`, `MTU: int(srv.Mtu)`, `ListenPort: int(srv.ListenPort)`,
   `KeepaliveSec: int(srv.KeepaliveSec)`, `MeasuredAt: now.UTC()`,
   `ServerID: serverID.String()`.
7. `Peers: selectPeers(cands, handshaked, now)` для online-узла.

- [ ] **Step 4: Интеграционный тест — `tests/integration/desired_test.go`, схема, не исходник**

Фикстуры — `seedServer`/`setServerOnline`/`seedDevice`/`seedProfile` из задачи 1, события —
прямой `INSERT INTO connection_events … ('handshake_observed', …)` в тесте (создавать их
через телеметрию здесь незачем: проверяется отсечение).

| случай | ожидание |
|---|---|
| активный профиль | один пиер, `state=active`, `allowed_ips=["<адрес>/32"]`, `expires_at` = срок профиля |
| два активных профиля + один `revoked` | двух пиеров, отозванного нет; `DesiredCandidates` его строки не возвращает вообще |
| `active`, но `expires_at` в прошлом | пиера нет (это и есть «просроченный не попадает», до свиппера) |
| `superseded` с открытым окном и живым преемником, handshake нет | **два** пиера: предок в состоянии `rotating_old_key` |
| тот же набор + событие `handshake_observed` на преемника | предка нет, преемник есть |
| `superseded` с закрытым окном | предка нет |
| `superseded` без преемника вообще | предка нет (иначе снятый ключ жил бы вечно) |
| предок жив, преемник отозван (`revoked` профиль) | предка нет |
| событие handshake **старше** `now − RotationOverlap` | предок остался: порог отсекает свидетельства закрытых ротаций |
| `draining` | `peers` сериализуется в `[]`, версия и MTU — из строки сервера |
| два вызова `Compute` подряд без изменений | побайтово одинаковый JSON (условие стабильности ETag, задача 11) |
| сервер из `seedServer` в `maintenance` | `dns_servers = ["<база+1>"]`, `keepalive_sec` и `listen_port` совпадают со строкой |

Run: `make unit && make vet && make integration`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add internal/servers/desired.go internal/servers/desired_test.go \
        tests/integration/desired_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(servers): desired set с отсечением снятого доступа и свойством"
```

---

### Task 10: Телеметрия — дельты счётчиков, health узла и события handshake

**Files:**
- Create: `internal/telemetry/delta.go`, `internal/telemetry/delta_test.go`,
  `internal/telemetry/service.go`, `tests/integration/telemetry_test.go`
- Modify: `internal/db/query/telemetry.sql` (добавить `MarkServerHealth`, `SetDeviceSeen`)

**Interfaces:**
- Consumes: `UpsertServerHealth`, `UpsertDeviceDayTraffic`, `DevicesByPublicKeys`,
  `InsertConnectionEvent`, `redis.Client`.
- Produces (пакет `telemetry`):
  - `func Delta(lastRx, lastTx, curRx, curTx int64, haveBase bool) (rx, tx int64, reset bool)`;
  - `func DayOf(now time.Time) time.Time`;
  - `func CountHandshaked(peers []PeerStat, at time.Time, fresh time.Duration) int`;
  - `type PeerStat struct { PublicKey string; LatestHandshake *time.Time; RxBytes, TxBytes int64 }`
    (JSON-имена: `public_key`, `latest_handshake`, `rx_bytes`, `tx_bytes`);
  - `type ObservedReport struct` — `config_version`, `interface_rx_bytes`,
    `interface_tx_bytes`, `peers []PeerStat`, `applied_at` (JSON: `config_version`, …);
  - `type Heartbeat struct` — `agent_version`, `agent_uptime_sec`, `load1 *float64`,
    `cpu_pct *float64`, `applied_config_version`;
  - `func NewService(q *db.Queries, rdb *redis.Client, log *slog.Logger) *Service`;
  - `(s *Service) IngestObserved(ctx context.Context, serverID uuid.UUID, rep ObservedReport, now time.Time) error`;
  - `(s *Service) IngestHeartbeat(ctx context.Context, serverID uuid.UUID, hb Heartbeat, now time.Time) error`;
  - константы `PeerCountersTTL = 48 * time.Hour`, `HandshakeFresh = 3 * time.Minute`.

- [ ] **Step 1: Чистые функции — дословный исходник `internal/telemetry/delta.go`**

```go
package telemetry

import "time"

// Delta — прирост счётчиков пиера между двумя отчётами узла.
//
// Отрицательного трафика не бывает, а счётчик WireGuard обнуляется при рестарте агента,
// перезагрузке узла и при удалении пиера. Поэтому «cur < last» — это not «клиент отдал
// байты назад», а reset: прирост считаем нулём и запоминаем новое основание. Складывать
// отрицательную дельту в device_day_traffic значило бы тихо уменьшать чужую квоту.
//
// Последний аргумент — «основания не было вообще» (первый отчёт пиера или TTL бакета
// истёк): он тоже даёт ноль, потому что отсутствие предыдущего замера не доказывает,
// что трафика не было, но и не доказывает, что он был.
func Delta(lastRx, lastTx, curRx, curTx int64, haveBase bool) (rx, tx int64, reset bool) {
	switch {
	case !haveBase:
		return 0, 0, false
	case curRx < lastRx || curTx < lastTx:
		return 0, 0, true
	default:
		return curRx - lastRx, curTx - lastTx, false
	}
}

// DayOf — сутки агрегата `device_day_traffic` всегда в UTC: ключ (user, device, day)
// не должен зависеть от часового пояса ни сервера, ни клиента.
func DayOf(now time.Time) time.Time {
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// CountHandshaked — сколько пиеров действительно живы на момент отчёта.
// Считать «у latest_handshake вообще есть значение» нельзя: снятый, но ещё видимый
// ядром пиер имеет старый handshake, и узел выглядел бы нагруженным чужими
// соединениями.
func CountHandshaked(peers []PeerStat, at time.Time, fresh time.Duration) int {
	n := 0
	for _, p := range peers {
		if p.LatestHandshake != nil && p.LatestHandshake.After(at.Add(-fresh)) {
			n++
		}
	}
	return n
}
```

Unit-тест `internal/telemetry/delta_test.go` — схема, не исходник. Таблица `Delta`
обязана содержать: `haveBase=false` → `(0,0,false)`; рост `100→180`, `50→50` → `(80,0,false)`;
падение обоих → `(0,0,true)`; падение только `tx` → `(0,0,true)` (основание сбрасывается по
обоим счётчикам разом — иначе `rx` следующего цикла сравнится с «прошлым» из другой эпохи);
нулевой прирост → `(0,0,false)`. `DayOf` — случай «16:30 +0500» обязан дать ту же дату, что
«11:30 UTC», и случай перехода через полночь UTC. `CountHandshaked` — три пиера
(свежий, старый, `nil`) → `1`.

Run: `make unit`
Expected: FAIL до реализации (`undefined: Delta`), PASS после.

- [ ] **Step 2: Запросы — дословный исходник, добавить в `internal/db/query/telemetry.sql`**

```sql
-- name: MarkServerHealth :exec
-- Heartbeat не приносит пиерных статистик, поэтому его upsert трогает только свои
-- колонки. Двойка 0,0 в peers_* при самой первой строке — честное «наблюдений ещё не
-- было», а не «пиеров нет»: их перетрёт первый observed. Один общий upsert на оба
-- сообщения (задача 1) для observed, здесь — второй, потому что иначе heartbeat каждый
-- раз обнулял бы счётчики, принесённые observed три секундой раньше.
INSERT INTO server_health (server_id, observed_at, peers_configured, peers_handshaked,
                           interface_rx_bytes, interface_tx_bytes, load1, cpu_pct,
                           applied_config_version, status, agent_version, agent_uptime_sec)
VALUES ($1, $2, 0, 0, 0, 0, $3::numeric, $4::numeric, $5, 'ok', $6, $7)
ON CONFLICT (server_id) DO UPDATE SET
    observed_at            = EXCLUDED.observed_at,
    load1                  = EXCLUDED.load1,
    cpu_pct                = EXCLUDED.cpu_pct,
    applied_config_version = EXCLUDED.applied_config_version,
    status                 = 'ok',
    agent_version          = EXCLUDED.agent_version,
    agent_uptime_sec       = EXCLUDED.agent_uptime_sec;

-- name: SetDeviceSeen :one
-- last_seen_at — и поле ответа /devices (контракт A-1), и единственный дешёвый способ
-- понять, что handshake устройства наблюдаем ВПЕРВЫЕ: UPDATE с условием «пришёл момент
-- свежее уже записанного» возвращает строку ровно один раз на каждый новый handshake,
-- и событие handshake_observed не размножается каждым опросом узла. Дедупликация в БД,
-- а не в Redis, обязательна: снятие предка (§7.3) читает события, и отказ Redis не
-- имеет права превращать это в вечный overlap.
UPDATE devices SET last_seen_at = $2
 WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at < $2)
 RETURNING id, user_id;
```

Run: `make sqlc-generate && make vet`
Expected: PASS; в `internal/db/telemetry.sql.go` появились оба метода, у `SetDeviceSeen`
параметры `ID, LastSeenAt`.

- [ ] **Step 3: `IngestObserved` — схема, не исходник (порядок шагов менять нельзя)**

1. `DevicesByPublicKeys(keys)` → карта `public_key → (device_id, user_id)`. Ключей, которых
   нет в базе, в карте нет: узел мог ещё не снять пиера после отзыва (окно применения), и
   это не ошибка отчёта.
2. `UpsertServerHealth` **до** разбора пиеров: `peers_configured = len(rep.Peers)`,
   `peers_handshaked = CountHandshaked(rep.Peers, now, HandshakeFresh)`, интерфейсные
   счётчики как есть, `applied_config_version = rep.ConfigVersion`, `status = 'ok'`,
   `observed_at = now`, `agent_version`/`agent_uptime_sec` — `nil` (heartbeat их не
   приносил, выдумывать нечем).
3. События `handshake_observed` — по каждому известному пиеру с `LatestHandshake != nil`:
   `SetDeviceSeen(deviceID, *LatestHandshake)`; вернул строку → `InsertConnectionEvent`
   (`handshake_observed`, `device_id`, `server_id`, `user_id`,
   `detail {"handshake_at": …,"config_version": …}`). Не вернул (строка не новее) → ничего:
   дедупликация уже случилась в условии UPDATE.
4. Дельты по байтам: для каждого известного пиера прочитать основание из Redis
   (`HGETALL tsc:<server_id>:<device_id>`), посчитать `Delta`, записать текущие счётчики
   (`HSET` + `PEXPIRE PeerCountersTTL` одним `Pipeline`). Если `rx+tx > 0` —
   `UpsertDeviceDayTraffic(user_id, device_id, DayOf(now), rx, tx)`.
5. `peer_applied` / `peer_removed` — diff множества публичных ключей против предыдущего
   отчёта, сохранённого в Redis (`SMEMBERS`/`SADD`/`SREM peers:<server_id>` с тем же TTL).
   Событие пишет только код и версию, без адресов и байт (§6).

Правила отказов, которые обязана реализовать именно эта функция:

- Ошибка Redis (шаги 4 и 5) — `s.log.Warn("telemetry: redis unavailable, counters skipped", …)`
  и продолжение: health и события handshake уже записаны, а агрегат по байтам просто
  не пополняется. Это то же решение, что и fail-open лимитера (§4.3): отказ кэша не должен
  отрезать доступ, и не должен врать про трафик.
- Ошибка БД на шаге 2 — вернуть: health этого отчёта не записан, и узел по своей стороне
  повторит отчёт на следующем опросе (он шлёт его каждый цикл, а не один раз).
- `RxBytes`/`TxBytes` `< 0` в отчёте — отклонить отчёт целиком (`validationError`, задача 11
  отдаст `400`): отрицательный счётчик в дельте означает, что узел прислал не то, что мы
  думаем, а молча сложить его в агрегат — испортить чужую статистику.
- Пиер, absent в базе (ключ не известен), байты не агрегирует: без `user_id` некуда писать,
  и придумывать пользователя по адресу — ровно та выдумка, которую запрещает ТЗ §19.3.

- [ ] **Step 4: `IngestHeartbeat` — схема, не исходник**

`MarkServerHealth(serverID, now, load1, cpu_pct, applied_config_version, agent_version,
agent_uptime_sec)`. Отчёт отклоняется **до** обращения к БД, если `agent_version` длиннее 64
символов, `agent_uptime_sec < 0`, `load1` вне `[0, 999]` или `cpu_pct` вне `[0, 100]`: на
этих колонках уже стоят CHECK (миграции 0003 и 0006), и внятный `400` клиенту лучше, чем
`22P02`/`22003`, которые наружу уйдут как `500` и затрут настоящий смысл отказа. Heartbeat
ничего не знает про пиеров и не трогает `device_day_traffic`. Оба метода пишут журнал без
содержимого отчёта: только `server_id`, версия и число пиеров (§5.2 про журнал, ТЗ §15).

- [ ] **Step 5: Интеграционный тест — `tests/integration/telemetry_test.go`, схема, не исходник**

| случай | ожидание |
|---|---|
| первый observed одного пиера | `server_health`: `peers_configured=1`, `peers_handshaked=1` (свежий handshake), `applied_config_version` = из отчёта; `device_day_traffic` пусто (основания не было → дельта 0); событие `handshake_observed` **есть** |
| второй observed, rx+1000, tx+500 | агрегат прибавил ровно `1000/500`; `handshake_observed` **не** продублирован, если `latest_handshake` тот же; продублирован, если стал новее (проверка `count(*)` по событиям) |
| счётчики упали (`rx` 5000 → 10) | дельта нулевая, агрегат не уменьшился, `reset` в журнале отладочным уровнем, `server_health.interface_rx_bytes` = новое значение |
| пиер с неизвестным ключом | health посчитан, событий по нему нет, агрегат пуст |
| observed → heartbeat | `agent_version` и `uptime` заполнены, `peers_configured` сохранилось из observed (не обнулилось) |
| heartbeat на узле без observed вообще | `server_health` создан, `peers_configured=0`, `status='ok'` |
| `load1=nil`, `cpu_pct=nil` | в БД `NULL`, а не `0`; каталог (задача 2) по-прежнему отдаёт `load: null` |
| Redis остановлен (тест: адрес `127.0.0.1:1`) | `IngestObserved` завершился без ошибки, health и `handshake_observed` записаны, `device_day_traffic` пусто; в журнале предупреждение |
| diff множества 2 → 1 | ровно одно событие `peer_removed` на снятый ключ, одно `peer_applied` на добавленный в обратном переходе |

Run: `make unit && make vet && make integration`
Expected: PASS.

- [ ] **Step 6: Коммит**

```bash
git add internal/telemetry internal/db/query/telemetry.sql tests/integration/telemetry_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(telemetry): дельты пиерных счётчиков, health узла и события handshake"
```

---

### Task 11: Контракт узла — `/internal/v1/*` против fake-узла

**Files:**
- Create: `internal/nodeapi/{auth.go,enroll.go,handlers.go}`,
  `tests/integration/nodeapi_test.go`
- Modify: `internal/httpx/context.go`, `internal/httpx/logging.go` (server_id в контексте и
  журнале), `internal/httpx/decorators.go` (третья обёртка — `Node`),
  `services/api/router.go` (монтаж `/internal/v1` и узловой лимитер).
  Правки `internal/config` нет: узловой токен бессрочен до отзыва и ротации, поэтому
  отдельного TTL в конфигурации не появляется.

**Interfaces:**
- Consumes: `auth.Bearer`, `db.Queries`, `devices.ParsePublicKey` (каноничность — единственный
  источник, задача 14 A-1), `servers.Compute`, `servers.DesiredSet`, `telemetry.Service`,
  `httpx.Limiter`, `httpx.Decorators.Node`.
- Produces (пакет `nodeapi`):
  - `func NewAuthenticator(q *db.Queries) *Authenticator` с
    `(a *Authenticator) Middleware(next http.Handler) http.Handler`;
  - `httpx.WithServerID(ctx, uuid.UUID) context.Context` и
    `httpx.ServerIDFromContext(ctx) (uuid.UUID, bool)`;
  - `type Handler` c `RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators)` и
    `NewHandler(q *db.Queries, tel *telemetry.Service, log *slog.Logger) *Handler`;
  - ошибки `ErrUnknownNode`, `ErrServerMismatch`, `ErrBootstrapInvalid`;
  - JSON-типы контракта: `EnrollRequest{BootstrapToken, PublicKey string}`,
    `NodeTokenResponse{ServerID, NodeToken string}`;
  - константу `maxNodePeers = 4096` (потолок разбора отчёта) и константы сборщика
    `nodePerMin = 120.0`, `nodeBurst = 10` в `services/api/router.go`.

- [ ] **Step 1: Узловая аутентификация — схема, не исходник**

1. `Bearer(r)` пусто → `401 unauthenticated` («требуется токен узла»).
2. `sum := sha256.Sum256([]byte(token))`, `NodeCredentialByHash(hex)`. `pgx.ErrNoRows` →
   `401 unauthenticated` **одинаковым** ответом для «не знаем такого», «отозван» и «битый
   формат»: узел-самозванец не должен по ответу понимать, что его токен хотя бы
   зарегистрирован (§2, строка «Узел-самозванец»).
3. `TouchNodeCredential(id)` — одна запись на запрос, без кэша: `last_used_at` нужен
   отзыву «неиспользуемого» токена (задача 12), и «примерно последний раз» для этого не
   годится.
4. `httpx.WithServerID(r.Context(), cred.ServerID)` → дальше в `r.WithContext`.
5. `Authenticator` не проверяет прав по маршрутам: «какой сервер» — всё, что знает узел, и
   это уже в контексте.

Тест `internal/nodeapi/auth_test.go` (unit, fake-хранилище не нужен — проверяются только
ветки отказа на реальной БД в шаге 5) остаётся интеграционным; здесь достаточно
проверить, что журнал не содержит переданный токен (см. задачу 15, `checkEvidence`).

- [ ] **Step 2: enroll — схема, не исходник**

`POST /internal/v1/nodes/enroll` — **единственный** маршрут префикса, доступный без
узлового токена (иначе enroll невозможен физически); монтируется под `dec.Node`, где
`Node` для него = `dec.Anonymous`-подобная обёртка по IP (шаг 4).

1. Тело ≤ 1 MiB (`httpx.DecodeJSON`), `bootstrap_token` и `public_key` обязательны;
   `devices.ParsePublicKey(public_key)` → `400 invalid_request` + details `{"field":
   "public_key"}`.
2. `BootstrapTokenByHash(sha256(token))` → четыре причины отказа различаются **в журнале**
   (`log.Warn("node enroll refused", "reason", …, "server_id", …)`), а наружу уходит один
   `401 unauthenticated` с `"стартовый токен не принят"`: различение по ответу — оракул
   «какие токены существуют» для чужого узла.
   Причины: `unknown`, `expired`, `used`, `revoked`.
3. `ConsumeBootstrapToken(id)` → `pgx.ErrNoRows` означает «равно одновременно выиграл
   другой enroll»: тот же `401`, причина `race` в журнале.
6. `srv, err := q.ServerByID(serverID)`; `pgx.ErrNoRows` здесь означает «токен валиден, а
   сервера нет» — то есть испорченную операцию админа (FK на `vpn_servers` теоретически это
   исключает, а на практике это значит, что сервер удалили, не отозвав его токен). Ответ —
   `401 unauthenticated` (для узла это ровно одно: «пере-зарегистрируйся»), в журнал —
   `log.Error` с `server_id`: оставить такое состояние без сигнала значило бы, что оператор
   узнает о нём из «узел молчит».
7. `node_token = 32 байта crypto/rand → base64.RawURLEncoding`; в БД — только
   `sha256` (`InsertNodeCredential`, `rotated_from = nil`). Ответ содержит сам токен
   **один раз** и больше нигде его не возвращает: это секрет доступа узла, и recover
   его из журнала или из повтора ответа был бы способом переписать чужой узел.
8. `RevokeNodeCredentialsForServer(serverID)` **перед** вставкой нового: перевыпуск
   обязан гасить прежний, иначе украденный старый токен живёт вечно рядом с новым.
9. Событие соединения на enroll не пишется: enroll — не событие туннеля, а
   `connection_events` описывает пиеров и доступ (§6). След административного действия —
   `node_enrolled` в `admin_audit_logs` на выдаче bootstrap-токена (задача 12), плюс
   `last_used_at` у строки токена.

- [ ] **Step 3: desired / observed / heartbeat / token rotate — схема, не исходник**

| маршрут | поведение |
|---|---|
| `GET /internal/v1/nodes/{server_id}/desired` | `serverID != ServerIDFromContext` → `403 forbidden` («несовпадение сервера», §2 узел-самозванец). Иначе `servers.Compute(q, serverID, now)`, а `ETag` — `fmt.Sprintf("%q", "v"+strconv.FormatInt(set.ConfigVersion, 10))`: кавычки обязательны по RFC 9110, сравнение — строгое равенство строки заголовка. Совпавший `If-None-Match` → `304` без тела и без `Content-Type`. Полный ответ при этом всё равно собран, и это осознанно: версия живёт в той же строке сервера, что и `Compute`, а отдельный путь «только ETag» дал бы вторую реализацию одного правила отсечения ради экономии одной сериализации |
| `POST …/observed` | `httpx.DecodeJSON` в `telemetry.ObservedReport`, `IngestObserved` → `204`; `400 invalid_request` на битое тело, на отрицательные счётчики и на `peers` больше `maxNodePeers = 4096` (потолок тела — единственная защита от «узел прислал мегабайты и мы их разобрали») |
| `POST …/heartbeat` | `telemetry.Heartbeat`, `IngestHeartbeat` → `204`, `400` на битое тело и `403` на чужой `server_id` |
| `POST …/token/rotate` | новый токен тем же способом, что и на enroll; `InsertNodeCredential(rotated_from = текущий id)` → `RevokeNodeCredential(id)` ровно текущего → `200 NodeTokenResponse`. Порядок «вставил, потом отозвал предъявленный» обязателен: обратный порядок оставлял бы узел без доступа при ошибке вставки. Узел, потерявший ответ, уходит в enroll заново — цена conscious: висящие валидными оба токена удваивали бы поверхность украденного токена |
| всё, кроме enroll | под `dec.Node`: аутентификация узла **до** лимитера по `server_id` (как `dec.Auth` в A-1: ключ бакета читает контекст, появляющийся только после проверки токена) |

- [ ] **Step 4: Третья обёртка в `httpx.Decorators` — схема, не исходник**

В `internal/httpx/decorators.go` добавить поле `Node func(http.Handler) http.Handler` и
объясняющий комментарий в том же стиле, что и существующий: модуль выбирает **класс**
защиты, а не реализует её; третья обёртка нужна, потому что узловая аутентификация не
является ни пользовательской (`auth.Middleware` + denylist), ни анонимной, а `ServeMux`
на повторный шаблон паникует, поэтому перемонтировать маршрут «в обходку» нельзя.
`Auth` и `Anonymous` не меняются ни поведением, ни порядком — существующие тесты A-1
обязаны пройти без правок (проверка: `make unit && make integration` на этом шаге).

В `services/api/router.go`:

```go
	Node: func(next http.Handler) http.Handler {
		return nodeapi.NewAuthenticator(q)(
			lim.Middleware("node", httpx.RatePerMinute(nodePerMin), nodeBurst, nodeKey)(next))
	},
```

`nodeKey` — `server_id` из контекста, иначе `"unknown"`; enroll монтируется отдельно под
`dec.Anonymous` (по IP), потому что у ещё не зарегистрированного узла `server_id` нет.

- [ ] **Step 5: Интеграционный тест — `tests/integration/nodeapi_test.go`, схема, не исходник**

Стенд: `httptest.NewServer(api.NewRouter(...))`? — нет, в существующей практике A-1
тесты дёргают `mux` напрямую через `httptest.NewRecorder`; здесь так же, но **сквозь**
настоящий роутер задачи 6 (чтобы проверка 404/405 и конверт были те же, что в проде).
Fake-узел = последовательность HTTP-вызовов из теста.

| случай | ожидание |
|---|---|
| enroll битым bootstrap | `401`, тело-конверт, в журнале причина `unknown`; второй enroll с просроченным токеном даёт **такой же** ответ (проверка по телу, а не по журналу) |
| enroll валидным токеном | `200`, `node_token` совпадает с `^[A-Za-z0-9_-]{43}$` (32 байта в base64url без дополнений), `server_id` = сервер токена; в `node_credentials` — только `sha256` от него, а не сам токен; повторный enroll тем же токеном → `401`, в журнале причина `used` |
| два параллельных enroll одним токеном (10 горутин) | ровно один `200`, остальные `401`; в `node_credentials` одна активная строка на сервер |
| desired с чужим токеном (`server_id` в пути ≠ токену) | `403 forbidden` |
| desired без токена / с битым | `401` |
| desired, первый вызов | `200`, `ETag` присутствует, JSON совпадает с §4.1 по именам полей, `peers` — массив (пустой, если профилей нет), приватных ключей нет (`checkEvidence`) |
| desired с тем же `If-None-Match` | `304`, пустое тело |
| desired после выдачи профиля | `config_version` вырос, `ETag` другой, пиер появился |
| observed c `peers` (один известный ключ) | `204`, `server_health` заполнен, событие `handshake_observed` одно |
| observed с отрицательным `rx_bytes` | `400 invalid_request` |
| heartbeat после observed | `204`, `agent_version` в health, `peers_configured` сохранился |
| token/rotate | `200` новый токен; старый → `401` на desired; новый → `200`; в `node_credentials` `rotated_from` = id первого |
| 130 запросов desired одним узлом подряд | хотя бы один `429` с `Retry-After` (окно 120/мин, burst 10 — числа сборщика) |
| журнал всех вызовов | нет ни одного из переданных токенов, есть `server_id` |

Run: `make unit && make vet && make integration`
Expected: PASS.

- [ ] **Step 6: Коммит**

```bash
git add internal/nodeapi internal/httpx/context.go internal/httpx/logging.go \
        internal/httpx/decorators.go services/api/router.go tests/integration/nodeapi_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(nodeapi): контракт /internal/v1 — enroll, desired+ETag, отчёты, ротация токена"
```

---

### Task 12: Admin — отдельная роль, серверы, bootstrap-токены, пользователи и аудит

**Files:**
- Create: `internal/audit/audit.go`, `internal/audit/audit_test.go`,
  `internal/admin/{auth.go,handlers.go,servers.go,tokens.go,users.go}`,
  `tests/integration/admin_test.go`
- Modify: `internal/auth/token.go`, `internal/auth/token_test.go`,
  `internal/db/query/admin.sql`, `internal/httpx/{context.go,logging.go,decorators.go}`,
  `services/api/router.go`, `services/api/cmd/novavpn-api/main.go`,
  `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§5.1, §7.6, §13)

**Interfaces:**
- Consumes: запросы задачи 1 (`ServerByID`, `InsertServer`, `UpdateServerFields`,
  `SetServerMaintenance`, `BumpServerConfigVersion`, `LockServerRow`,
  `CountActiveProfilesOnServer`, `DeleteProfilesByServer`, `DeleteServer`,
  `InsertServerLocation`, `LocationByKey`, `InsertBootstrapToken`, `RevokeBootstrapToken`,
  `LiveBootstrapTokensOfServer`, `RevokeNodeCredentialsForServer`, `InsertAdminUser`,
  `AdminByEmail`, `AdminByID`, `RecentAdminAudit`); запросы A-1 (`UserByID`, `LockUser`,
  `UnlockUser`, `RevokeAllFamiliesForUser`, `LiveDevicesByUser`); `auth.HashPassword`,
  `auth.VerifyPassword`, `auth.LoginGuard`, `auth.Bearer`, `devices.ParsePublicKey`,
  `ServerHealthOf` (задача 1), `db.RunInTx`,
  `httpx.{WriteJSON,DecodeJSON,WriteError,RequestIDFromContext,WithAdminID,AdminIDFromContext}`,
  `httpx.Decorators.Admin`.
- Produces (пакет `admin`):
  - `func Middleware(iss *auth.Issuer, log *slog.Logger) func(http.Handler) http.Handler`;
  - `type Handler struct{ … }`, `NewHandler(pool *pgxpool.Pool, q *db.Queries, iss *auth.Issuer,
    guard *auth.LoginGuard, log *slog.Logger) *Handler` и
    `(h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators)`;
  - ошибки `ErrAdminNotFound`, `ErrServerUnknown`, `ErrPeersActive`, `ErrNotLocked`,
    `ErrAlreadyLocked`, `ErrTokenNotLive`, `ErrEmailTakenAdmin` (`errors.New`);
  - JSON-типы ответов: `AdminSession{AccessToken, TokenType, ExpiresIn}`,
    `AdminServerView`, `BootstrapTokenView{ID, Token string, ExpiresAt time.Time}`,
    `AdminUserView{Email, Status, LockedReason, Devices, Traffic}`;
  - константы `minTTLsec = 60`, `maxTTLsec = 86400`, `defaultTTLsec = 3600`,
    `maxAuditPage = 500`, `maxAuditOffset = 10000`, `TrafficWindowDays = 30` (окно
    объёмов в просмотре пользователя; ограничено тем же retention, что и события —
    больше 90 суток показывать нечего).
- Produces (пакет `audit`): `type Action`, `func Do(...) error`, `ErrReasonRequired` (шаг 4).
- Produces (пакет `auth`): `NewAdminIssuer`; `iss` у пользовательского токена не меняется.

- [ ] **Step 1: Второй Issuer в `internal/auth/token.go` — дословный исходник**

Существующие `Issuer.Issue` и `Issuer.Parse` не меняются ни на символ: роль в токене —
это `Issuer` (значение claim'а `iss`), а не отдельный тип, и проверка уже идёт через
`jwt.WithIssuer(i.iss)`. Заменяются объявление `Issuer`, `ErrInvalidToken` и `NewIssuer`:

```go
type Issuer struct {
	secret []byte
	ttl    time.Duration
	iss    string
}

var ErrInvalidToken = errors.New("access token is invalid")

// Два значения iss на одном секрете. Различить «это id пользователя» и «это id
// администратора» по форме невозможно — оба uuid, — поэтому админский токен обязан
// отклоняться пользовательской проверкой и наоборот на уровне claim'а, а не по догадке.
// Иначе токен участника с id, совпавшим по длине, открывал бы /api/v1/admin/*.
const (
	issUser  = "novavpn-api"
	issAdmin = "novavpn-admin"
)

func newIssuer(secret []byte, ttl time.Duration, iss string) *Issuer {
	if len(secret) < 32 {
		// config.Load уже это проверяет; проверка здесь — защита от прямого вызова
		// (тесты, будущие внутренние команды), а не от пользователя.
		panic("auth: JWT secret must be at least 32 bytes")
	}
	return &Issuer{secret: secret, ttl: ttl, iss: iss}
}

func NewIssuer(secret []byte, ttl time.Duration) *Issuer {
	return newIssuer(secret, ttl, issUser)
}

// NewAdminIssuer — токен администратора. Refresh-пары у него нет: срок равен AccessTTL
// (конфигурация не допускает больше 30 минут), а вход — маршрут под LoginGuard.
// Срочного отзыва admin-токена в A-2 тоже нет: см. «чего сознательно нет в A-2» ниже.
func NewAdminIssuer(secret []byte, ttl time.Duration) *Issuer {
	return newIssuer(secret, ttl, issAdmin)
}
```

- [ ] **Step 2: Тест взаимного отторжения — дословный исходник, добавить в `internal/auth/token_test.go`**

Хелперы `bytes32` и пакетные импорты (`context`, `errors`? — `errors` в файле уже есть,
`strings` есть; при отсутствии `errors` добавить) переиспользуются как есть.

```go
func TestAdminAndUserIssuersRejectEachOther(t *testing.T) {
	secret := bytes32("shared-secret-for-issuer-split-test")
	user := NewIssuer(secret, 10*time.Minute)
	admin := NewAdminIssuer(secret, 10*time.Minute)

	uc, err := user.Issue(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("user issue: %v", err)
	}
	ac, err := admin.Issue(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("admin issue: %v", err)
	}

	if _, err := admin.Parse(uc.Value); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("admin issuer accepted a user token: %v", err)
	}
	if _, err := user.Parse(ac.Value); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("user issuer accepted an admin token: %v", err)
	}
	//Обратная проверка: свой токен обязан проходить, иначе две проверки выше проходили бы «на пустоте».
	if _, err := admin.Parse(ac.Value); err != nil {
		t.Errorf("admin issuer rejected its own token: %v", err)
	}
	if _, err := user.Parse(uc.Value); err != nil {
		t.Errorf("user issuer rejected its own token: %v", err)
	}
}
```

Run: `make unit`
Expected: PASS.

- [ ] **Step 3: Четвёртая обёртка и `admin_id` в журнале — схема, не исходник**

1. `internal/httpx/decorators.go`: поле `Admin func(http.Handler) http.Handler` плюс
   абзац комментария в том же стиле: админ — не «пользователь с другим id», а другой
   класс доступа (другой `iss`, другой бакет лимитера, право на чужие данные), и
   `internal/httpx` по-прежнему не импортирует ни `auth`, ни `admin`.
2. `internal/httpx/context.go`: `WithAdminID`/`AdminIDFromContext` — копия пары
   `WithUserID`/`UserIDFromContext` с собственным ключом. Никакой «универсальной»
   структуры субъекта: пользователь и админ не должны были бы перепутаться в типе,
   иначе опечатка в хендлере читала бы id админа как id пользователя.
3. `internal/httpx/logging.go`: в `journal` поля `adminID`/`hasAdmin`, `noteAdminID`
   (безопасен без журнала — вызывается из `WithAdminID`), в `attrs()` пара
   `"admin_id", …`. Email админа в журнал не кладётся: §10 и §15 запрещают личности в
   журнале там, где есть id, а `admin_id` достаточно для сопоставления с аудитом.
   Писать `user_id` и `admin_id` в одной строке разрешено: маршрут не может иметь оба
   субъекта, так что одновременно их не бывает.
4. `admin.Middleware(iss, log)`: `auth.Bearer(r)` → `iss.Parse` → ошибка —
   `401 unauthenticated` с `"требуется токен администратора"`; иначе
   `httpx.WithAdminID` → `next`. Проверки «есть ли у этого admin id право» нет: в A-2
   все админы равны, и это решение, а не недосмотр (§5.1 не знает ролей внутри роли;
   разделение прав — цикл C).
5. В `services/api/router.go`: `Admin: admin.Middleware(issAdmin, cfg.Log)(lim.Middleware(
   "admin", httpx.RatePerMinute(userPerMin), userBurst, adminKey)(next))`, где `adminKey` —
   `admin_id` из контекста, иначе IP. `issAdmin := auth.NewAdminIssuer(cfg.JWTSecret,
   cfg.AccessTTL)`; отдельного env-параметра для срока админ-токена не появляется —
   второе число, которое никто не просил, обязано было бы разъезжаться с первым.

`Auth` и `Anonymous` не меняются; тесты A-1 обязаны пройти без правок.

- [ ] **Step 4: `internal/audit/audit.go` — дословный исходник**

```go
// Package audit — единственная точка записи административного журнала (спецификация §3:
// «у права есть след»). Ответственность пакета: не давать изменить что-то, не записав
// причину, а не «уметь писать в admin_audit_logs».
package audit

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/db"
)

// Окно причины совпадает с CHECK admin_audit_reason (миграция 0003). Проверка в Go нужна
// не для красоты: без неё запрос с причиной из двух символов получил бы 500 из-за отката
// транзакции вместо 400 на собственное поле.
const (
	minReason = 3
	maxReason = 500
)

var ErrReasonRequired = errors.New("audit: reason must be 3..500 characters")

// Action — действие с обязательной причиной. TargetID — текст, а не uuid: целями бывают
// и сервер, и пользователь, и bootstrap-токен, и различаются они только полем target_type.
type Action struct {
	AdminID    uuid.UUID
	Action     db.AuditAction
	TargetType string
	TargetID   string
	Reason     string
	RequestID  string
}

// Do исполняет изменение и его запись в аудит одной транзакцией. «Изменили, но не
// записали» — состояние, которого не должно существовать: ТЗ §9 требует причину у каждого
// действия, а без атомарности её нет ровно тогда, когда она нужнее всего (отказ в момент
// отзыва). mutate получает транзакционные запросы и не имеет права трогать pool.
func Do(ctx context.Context, pool *pgxpool.Pool, a Action, mutate func(*db.Queries) error) error {
	if err := check(a); err != nil {
		return err
	}
	return db.RunInTx(ctx, pool, func(q *db.Queries) error {
		if err := mutate(q); err != nil {
			return err
		}
		return q.InsertAdminAudit(ctx, db.InsertAdminAuditParams{
			AdminID:    &a.AdminID,
			Action:     a.Action,
			TargetType: a.TargetType,
			TargetID:   a.TargetID,
			Reason:     a.Reason,
			RequestID:  a.RequestID,
		})
	})
}

func check(a Action) error {
	n := utf8.RuneCountInString(a.Reason)
	if n < minReason || n > maxReason {
		return fmt.Errorf("%w: got %d", ErrReasonRequired, n)
	}
	if a.AdminID == uuid.Nil {
		return errors.New("audit: action without subject")
	}
	if a.RequestID == "" || a.TargetType == "" || a.TargetID == "" {
		return errors.New("audit: action without request id or target")
	}
	return nil
}
```

Unit-тест `internal/audit/audit_test.go` (дословный исходник, `check` — он же покрывает
границы окна):

```go
func TestCheckAction(t *testing.T) {
	ok := Action{AdminID: uuid.New(), Action: db.AuditActionServerCreated,
		TargetType: "server", TargetID: uuid.NewString(),
		Reason: "узел переведён в draining", RequestID: "0000deadbeef0000"}
	if err := check(ok); err != nil {
		t.Fatalf("valid action rejected: %v", err)
	}
	// rune-счёт, не байтовый: три кириллических символа — 6 байт, и отказывать им нельзя.
	short := ok
	short.Reason = "да"
	if err := check(short); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("short reason: err = %v, want ErrReasonRequired", err)
	}
	long := ok
	long.Reason = strings.Repeat("п", maxReason+1)
	if err := check(long); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("long reason: err = %v, want ErrReasonRequired", err)
	}
	noSubject := ok
	noSubject.AdminID = uuid.Nil
	if err := check(noSubject); err == nil {
		t.Error("action without subject accepted")
	}
	noTarget := ok
	noTarget.TargetID = ""
	if err := check(noTarget); err == nil {
		t.Error("action without target accepted")
	}
}
```

Ошибку самого `Do` (запись в аудит упала → изменение откачено) проверить нечем без
настоящей БД — она в интеграционной таблице шага 10.

- [ ] **Step 5: Новые запросы в `internal/db/query/admin.sql` — дословный исходник**

```sql
-- name: AdminUserView :one
-- Не UserByID: тот выбирает password_hash, а админ-просмотр не имеет права его
-- даже читать. Отдельный запрос — способ «не создать возможность», а не «не забыть
-- не показывать».
SELECT id, email, display_name, status, locked_reason, locale, created_at
FROM users WHERE id = $1;

-- name: ListAllServers :many
-- Админский список серверов: то же, что каталог (§7 задачи 2), плюс служебное —
-- maintenance_status, config_version и число активных профилей («сколько пиеров
-- сорвётся при удалении», §7.6).
SELECT s.id, s.name, s.advertised_host, s.listen_port, s.public_key,
       s.address_pool_v4, s.mtu, s.keepalive_sec, s.config_version,
       s.maintenance_status, s.provider, s.region, s.capacity_mbps,
       l.country_code, l.city,
       (SELECT count(*) FROM vpn_profiles p
         WHERE p.server_id = s.id AND p.status = 'active')::int AS peers_active
FROM vpn_servers s
JOIN server_locations l ON l.id = s.location_id
ORDER BY s.name, s.id;

-- name: ServersOfUserProfiles :many
-- Порядок задаёт админ, а не планировщик: advisory-блокировки серверов в задаче 8
-- берутся ровно в этом порядке, и у двух параллельных блокировок разных пользователей
-- не будет способа зайти в клинч.
SELECT DISTINCT p.server_id
FROM vpn_profiles p
JOIN devices d ON d.id = p.device_id
WHERE d.user_id = $1 AND p.status IN ('active', 'superseded')
ORDER BY 1;

-- name: RevokeAllProfilesOfUser :many
-- Все профили пользователя, включая устройства, отозванные раньше: у предка из цепочки
-- ротации мог остаться незакрытым overlap-окно, и «заблокировали — а пиер живёт» для
-- заблокированного аккаунта недопустимо.
UPDATE vpn_profiles p
   SET status = 'revoked', revoked_at = now()
  FROM devices d
 WHERE p.device_id = d.id
   AND d.user_id = $1
   AND p.status IN ('active', 'superseded')
 RETURNING p.id, p.server_id, p.device_id, d.user_id;

-- name: TrafficByUserSince :many
-- Суммарный объём на устройство за окно (окно передаёт хендлер: 30 суток по умолчанию).
-- Абсолюты за произвольное окно, а не «весь срок»: весь срок — это device_day_traffic
-- без границы, и он растёт быстрее, чем экран админа.
SELECT device_id, SUM(rx_bytes)::bigint AS rx_bytes, SUM(tx_bytes)::bigint AS tx_bytes,
       count(*)::int AS days
FROM device_day_traffic
WHERE user_id = $1 AND day >= $2
GROUP BY device_id
ORDER BY device_id;
```

Run: `make sqlc-generate && make vet`
Expected: PASS. В `internal/db/admin.sql.go` типы `peers_active`/`days` — `int32`,
`rx_bytes`/`tx_bytes` — `int64`, `address_pool_v4` — `netip.Prefix`, `locked_reason` —
`*string`.

- [ ] **Step 6: Вход и CRUD серверов — схема, не исходник**

| маршрут | поведение |
|---|---|
| `POST /api/v1/admin/login` | под `dec.Anonymous`. `AdminByEmail` → `pgx.ErrNoRows` \| `VerifyPassword(hash, password) == false` → **один и тот же** `401 invalid_credentials` (`"email или пароль не подходят"`) плюс `guard.Delay(ctx, email, ip)`; различие видно только в журнале (`"admin login failed", "reason", "unknown_email"`), иначе ответ стал бы оракулом «есть ли такой админ». Успех → `guard.Reset`, `issAdmin.Issue(ctx, adminID)`, `200 AdminSession{access_token, token_type:"bearer", expires_in: int(ttl.Seconds())}`. Тело ответа не содержит id админа: он в `sub` токена, а второй источник того же значения обязан когда-нибудь разойтись |
| `GET /api/v1/admin/servers` | под `dec.Admin`. `ListAllServers` → `200` массивом; `address_pool_v4` строкой (`Prefix.String()`), `peers_active` числом |
| `POST /api/v1/admin/servers` | `{location{country_code,city,lat,lon,timezone}, name, advertised_host, listen_port, public_key, address_pool_v4, mtu?, keepalive_sec?, provider, region?, capacity_mbps?}`. Валидация границ — та же, что CHECK в 0002 (`name` 1..64, `listen_port` 1..65535, `mtu` 1280..1420, `keepalive_sec` 5..120, `advertised_host` по форме), `lat`/`lon` — числа-строки после override'а, `public_key` обязан пройти `devices.ParsePublicKey` и вернуться в канонической форме (неканонический ключ узла потом не совпадёт с собой же в `peer public-key`), `address_pool_v4` — маска `/24`..`/29`: больше /29 — это уже не «узел на 512 клиентов», а /23 — пул, в котором аллокатор задачи 4 переберёт половину пространства до первого отказа. Локаль: `InsertServerLocation` только после того, как `LocationByKey` вернул `pgx.ErrNoRows` (уникальность `(country_code, city, lat, lon)` — в БД, а не в коде). `audit.Do(server_created)`: внутри — `InsertServer` с `maintenance_status='maintenance'` (схемный дефолт: «зарегистрирован» ≠ «работает») и `config_version = 0` |
| `GET /api/v1/admin/servers/{id}` | `ServerByID` + `ServerHealthOf` (задача 10). Здоровья нет → `health: null`, а не нули: неизмеренное остаётся неизмеренным (§13.4) |
| `PATCH /api/v1/admin/servers/{id}` | полный набор через `UpdateServerFields` (не COALESCE — см. комментарий запроса в задаче 1), затем `BumpServerConfigVersion`: MTU и keepalive живут в `[Peer]` каждого клиента, и не поднять версию — значит оставить желаемый набор прежним, но не отдавать его никому. `audit.Do(server_updated)` |
| `POST /api/v1/admin/servers/{id}/maintenance` | `{status: online\|draining\|maintenance\|retired, reason}`. `SetServerMaintenance` + `BumpServerConfigVersion`. При `draining`/`retired` действие пишется как `server_drained`, иначе `server_updated` — §9 различает «вытеснение» от «правки», и по аудит-логу оператор должен видеть, что именно началось. `online` из `retired` запрещён: retired — конец, а не пауза; отказ — `409 conflict` |
| `DELETE /api/v1/admin/servers/{id}` | шаг 7 |

Идемпотентный ключ на этих маршрутах не требуется, и это не забыто, а решено:
`httpx.Idempotency` (задача 9 A-1) индексирует ключ тройкой `(user_id, route, key)`, а
у админа пользователя нет. Повторы безопасно гасит сама схема: `name` и `public_key` —
`UNIQUE`, `maintenance` и `PATCH` идемпотентны по значению, а отзыв токена — по условию
`revoked_at IS NULL`.

- [ ] **Step 7: Удаление сервера — правка §7.6 и её реализация (схема, не исходник)**

Порядок внутри одного `audit.Do(server_deleted)`:

1. `ServerByID` → `pgx.ErrNoRows` = `404 not_found` («сервер не найден»).
2. `CountActiveProfilesOnServer` → `> 0` = `409 conflict` с `"на сервере ещё N активных
   профилей"` (ошибка `ErrPeersActive`, чтобы хендлер различал её по `errors.Is`, а не по
   тексту) и details `{"peers_active": N}`. Именно это число §7.6 обещает админу до
   подтверждения, и именно оно — причина отказа, а не «что-то пошло не так».
3. `DeleteProfilesByServer` → остатки в терминальных статусах. Событий на них не
   пишется: `superseded` без живого преемника desired set уже не отдаёт (задача 9), а
   `revoked`/`expired` не дают доступа вовсе; писать `profile_revoked` о профиле, который
   мёртв, значило бы научить аудит лгать.
4. `DeleteServer`. `server_health`, `tunnel_addresses`, `node_credentials`,
   `bootstrap_tokens` уходят каскадом (`ON DELETE CASCADE`), `connection_events.server_id`
   — `SET NULL`: история событий принадлежит пользователям и устройствам, а не серверу.
   Приватного ключа узла в базе нет (0002), поэтому при удалении нечего «потерять».
5. Узловой токен трогать не нужно: строка `node_credentials` удалена вместе с сервером,
   `NodeCredentialByHash` не найдёт ничего, и старый узел получит ровно тот же
   `401`, что и незарегистрированный. Отдельный «отзыв» здесь был бы второй реализацией
   одного факта.

Риск, записанный честно: удаление строки сервера вручную (не маршрутом) унесёт каскадом
и `bootstrap_tokens` — выданный, но ещё не использованный токен исчезнет молча, а
`admin_audit_logs` останутся с `target_id` на несуществующий id. Маршрут — единственный
штатный путь, и это граница, а не гарантия.

- [ ] **Step 8: Блокировка, разблокировка, просмотр — схема, не исходник**

`POST /api/v1/admin/users/{id}/lock`, тело `{reason}` (3..500 символов — проверка `audit.check`
до любого изменения; ошибочная причина = `400 invalid_request` с details `{"field":"reason"}`).
Внутри `audit.Do(user_locked)`:

1. `UserByID` → `pgx.ErrNoRows` = `404`; `status == 'locked'` = `409 conflict`
   («учётная запись уже заблокирована») — иначе второй вызов молча перезаписал бы
   причину, а причина первого исчезла бы из единственного места, где её видно.
2. `ServersOfUserProfiles(id)` → по каждому серверу `LockServerRow` **в порядке
   сортировки** (см. комментарий запроса). Тот же advisory-замок держит аллокация адреса
   (задача 4), поэтому выдача профиля этому пользователю не может «проскочить» между
   чтением списка и отзывом.
3. `LockUser(id, reason)` → `refresh_token_families` отзываются `RevokeAllFamiliesForUser`
   (запрос A-1 уже есть): продлиться нельзя, а текущий access-токен доживает `AccessTTL` —
   замеренное ограничение A-1 (§13.11), и план его не прячет: denylist в A-1 индексируется по
   `jti`, а `jti` заблокированного пользователя нигде не собраны. Для §13 это отдельная
   строка (шаг 12).
4. `RevokeAllProfilesOfUser(id)` → rows; на каждый row — `ReleaseAddressByProfile` +
   `InsertConnectionEvent(profile_revoked, detail {"reason":"user_locked"})`; по каждому
   различному `server_id` — `BumpServerConfigVersion`. Последовательность повторяет шаги
   4–7 `DeleteDevice` (задача 7) с той разницей, что отзыв идёт по пользователю, а не по
   цепочке устройств.
5. `audit.Do` дописывает запись аудита в этой же транзакции.

`POST …/users/{id}/unlock`: `status != 'locked'` = `409 conflict`; `UnlockUser`
(он обнуляет `locked_reason` — запрос A-1); `audit.Do(user_unlocked)`. Профили не
восстанавливаются: разблокировка возвращает право войти, а не возвращает выданные
конфиги — иначе аудит «был отозван» расходился бы с реальным набором пиеров. Клиент
получит их заново обычным `POST …/profiles`.

`GET …/users/{id}`: `AdminUserView` + `LiveDevicesByUser` + `TrafficByUserSince(user, today-TrafficWindowDays)`. Поля хэша нет ни в запросе, ни в типе ответа (шаг 10 проверяет это по
байтам журнала и ответа).

`POST /api/v1/admin/admins`: `{email, password}`; `HashPassword` уже отказывает на
коротком пароле (`auth.MinPasswordLen`); `unique_violation` по `citext` = `409 conflict`
(«администратор с таким email уже есть») — `email_taken` зарезервирован контрактом A-1 за
регистрацией участников, и второй смысл тому же коду давать нельзя: клиенты различают
маршруты по коду, а не по тексту. `audit.Do(admin_created)`.

`GET /api/v1/admin/audit?limit=50&offset=0`: `limit` 1..`maxAuditPage`, `offset`
0..`maxAuditOffset` (иначе `400`); `RecentAdminAudit(limit, offset)`; фильтра по
админу и по действию нет намеренно — §5.1 обещает «аудит», а не «поиск по аудитам».

- [ ] **Step 9: Bootstrap-токены и «убить доступ узла» — схема, не исходник**

| маршрут | поведение |
|---|---|
| `POST …/servers/{id}/bootstrap-tokens` | `{ttl_sec?}` (60..86400, по умолчанию 3600) → `32` байта `crypto/rand` → `base64.RawURLEncoding`, `sha256` в `token_hash`, `expires_at = now.Add(ttl)` (не `now() + $5::interval`: override'а на `interval` в sqlc.yaml нет, и параметром стал бы `pgtype.Interval` — см. правку задачи 1), `created_by = admin_id`. Ответ содержит сам токен один раз; `audit.Do(bootstrap_token_issued)` с `target_type="bootstrap_token"`. Сервера нет → `404`; сервер в `retired` → `409 conflict` («сервер выведен, выдавать ему токен бессмысленно») |
| `GET …/servers/{id}/bootstrap-tokens` | `LiveBootstrapTokensOfServer`: `id`, `created_at`, `expires_at`. Ни `token_hash`, ни, тем более, секрета — восстановить выданный токен нельзя по построению, и список обязан это показывать отсутствием поля |
| `DELETE /api/v1/admin/bootstrap-tokens/{id}` | `RevokeBootstrapToken` (ноль строк = уже использован или отозван) → `409 conflict` (`ErrTokenNotLive`): «токен уже сожжён» и «токена нет» для админа — разные ситуации, и первая требует не повторного отзыва, а поиска узла, который его использовал. `audit.Do(bootstrap_token_revoked)` |
| `POST …/servers/{id}/node-token/revoke` | `RevokeNodeCredentialsForServer` (`:execrows`, ноль — не ошибка: у ещё не зарегистрированного сервера отзывов нет) + `BumpServerConfigVersion` + `SetServerMaintenance(draining)` и `audit.Do(node_token_revoked)`; если сервер был `online`, второй записью того же `audit.Do` идёт `server_drained` — «узел отрезан» и «набор пиеров снят» должны читаться из журнала как одно решение, а не как два разных действия, разнесённых по времени |

- [ ] **Step 10: CLI первого администратора — схема, не исходник**

`run(args, getenv)` в `services/api/cmd/novavpn-api/main.go` получает `case "admin"` с
подкомандой `create <email>`: пароль читается со stdin, не из argv и не из env-файла.
Причина ровно та же, что запрещает секрет в CLI-аргументах: argv виден в `ps` и
попадает в историю shell'а, а пароль администратора — единственный фактор, которого
не отзовёшь (в отличие от токена).

1. `fs := flag.NewFlagSet("admin", …)`, далее `fs.Arg(0) == "create"`, `fs.Arg(1)` — email;
   без email — ошибка usage.
2. Seam для тестов: в `run` добавляется параметр `input func() ([]byte, error)` (или поле
   пакета `os.Stdin` через замыкание — что удобнее тому, кто правит файл), чтобы тест
   мог подать байты без процесса. Правка обязана оставить существующие вызовы
   `run(args, getenv)` рабочими: `main` передаёт `readStdin`, тест — свою функцию.
3. `config.Load(getenv)` → `pgxpool.New` → `HashPassword` (отказ короткого парола —
   ошибка, а не «создадим и пусть сам разберётся») → `InsertAdminUser(uuid.New(), email,
   hash)` → id и email на stdout, `0`.
4. `unique_violation` → ненулевой выход с сообщением «администратор с таким email уже
   есть» — скрипт раскатки (цикл A-3) обязан замечать провал, а не молча считать его
   успехом.
5. Аудит-записи у CLI-создания нет: `admin_audit_logs.admin_id` — это `REFERENCES
   admin_users(id)`, и записывать «создал себя сам» в момент, когда админа ещё нет,
   нечем. След — строка stdout и `created_at`. Это ограничение, и оно в §13 (шаг 12).

- [ ] **Step 11: Интеграционный тест — `tests/integration/admin_test.go`, схема, не исходник**

Стенд как в задаче 11 (тот же `api.NewRouter`, чтобы конверт, лимитеры и 404/405 были
продовыми). Фикстуры: `seedLocation`/`seedServer`/`setServerOnline` (задача 1),
`seedProfile` (задача 1), хелпер `seedAdmin(t, ctx, q) (uuid.UUID, string)` —
`InsertAdminUser` с `auth.HashPassword` от тестового пароля, и `adminToken(t, e, email,
password) string` — вход через настоящий маршрут (не `Issuer` напрямую: иначе проверка
«токен админа принимается роутером» ничего не проверяет).

| случай | ожидание |
|---|---|
| вход неизвестным email и вход верным email с неверным паролем | байтово одинаковые `401 invalid_credentials`; в журнале причины разные |
| `GET /servers` без токена, с пользовательским токеном, с админ-токеном | `401`, `401`, `200` — пользовательский токен не открывает admin-маршрут (тот же тест, что шаг 2, но сквозь HTTP) |
| вход, потом `GET /api/v1/admin/servers` | `200`, `peers_active` = числу `active`-профилей |
| `POST /servers` неканоническим `public_key` | `400 invalid_request`, details `field=public_key` |
| `POST /servers` валидным телом | `201`, `maintenance_status="maintenance"`, `config_version=0`; локация не продублировалась (тот же город → одна строка в `server_locations`) |
| `PATCH /servers/{id}` | `200`, `config_version` вырос на 1, MTU изменён в desired set (проверка через `servers.Compute`, не по ответу) |
| `POST …/maintenance` в `draining` | `200`; `servers.Compute` → пустой `peers` (задача 9); в аудите — `server_drained` |
| `POST …/maintenance` `retired → online` | `409 conflict` |
| `DELETE …/servers/{id}` при активном профиле | `409 conflict`, details `{"peers_active":1}`, сервер жив, профиль жив |
| `DELETE …/servers/{id}` после отзыва профиля | `204`; сервера, его `tunnel_addresses`, `server_health`, `node_credentials`, остатков `vpn_profiles` — нет; `connection_events` его сервера остались с `server_id = null`; в аудите `server_deleted` с причиной |
| `POST …/bootstrap-tokens` | `201`, токен `^[A-Za-z0-9_-]{43}$`, `expires_at ≈ now+3600s`; в `bootstrap_tokens` — только sha256; enroll этим токеном (маршрут задачи 11) даёт `200` |
| `ttl_sec = 30` и `ttl_sec = 100000` | `400 invalid_request` |
| `DELETE /bootstrap-tokens/{id}` дважды | первый `204`, второй `409` |
| `POST …/node-token/revoke` на `online`-сервере | `204`; предъявленный узлом токен → `401` на desired; сервер в `draining`; в аудите две записи — `node_token_revoked` и `server_drained`, один и тот же `request_id` |
| `POST …/users/{id}/lock` | `200`; у всех профилей `status='revoked'`, адреса освобождены, `config_version` вырос, событие `profile_revoked` на каждый профиль, refresh-семьи отозваны (продление сессии → `401`), в аудите `user_locked` с причиной и `request_id` |
| причина из 2 символов | `400 invalid_request`, и в базе нет ни одной новой записи аудита, ни изменения пользователя |
| lock уже заблокированного | `409 conflict` |
| `unlock` → `lock` | `200`, вход пользователя снова возможен; профилей как раньше — нет (`GET /devices/{id}/profiles` пуст) |
| `GET …/users/{id}` | email, статус, устройства и трафик; ни `password_hash`, ни argon2-префикса в байтах ответа |
| `POST /admins` коротким паролем | `400 invalid_request`; в `admin_users` строк не прибавилось |
| `POST /admins` дубликатом email | `409 conflict` |
| `GET /audit?limit=500&offset=10001` | `400 invalid_request` |
| `GET /audit` после всех действий | записи упорядочены по `created_at DESC`, у каждой непустая `reason` и `request_id`, совпадающий с журналом соответствующего запроса |
| `audit.Do` с причиной из 2 символов | `mutate` не вызвана ни разу, в базе нет ни изменения, ни записи аудита: валидация причины происходит до начала транзакции, а не «после, и тогда откат» |
| журнал всех admin-запросов | есть `admin_id`, нет email ни одного админа, нет bootstrap-токенов, нет паролей (`checkEvidence` задачи 15) |

Run: `make unit && make vet && make integration`
Expected: PASS.

- [ ] **Step 12: Правки спецификации — §5.1, §7.6, §13**

1. §5.1: строка `POST | /api/v1/admin/…` заменяется на перечень: `POST /api/v1/admin/login`,
   `GET|POST /api/v1/admin/servers`, `GET|PATCH|DELETE /api/v1/admin/servers/{id}`,
   `POST /api/v1/admin/servers/{id}/maintenance`, `POST|GET
   /api/v1/admin/servers/{id}/bootstrap-tokens`, `DELETE /api/v1/admin/bootstrap-tokens/{id}`,
   `POST /api/v1/admin/servers/{id}/node-token/revoke`,
   `POST /api/v1/admin/users/{id}/lock|unlock`, `GET /api/v1/admin/users/{id}`,
   `POST /api/v1/admin/admins`, `GET /api/v1/admin/audit` — с примечанием «вход админа
   отсутствует в исходном ТЗ; добавлен планом A-2, потому что без него admin-токен
   неоткуда взять».
2. §7.6: дописать «удаление сервера возможно только при `peers_active = 0`; остаточные
   профили в терминальных статусах удаляются вместе с сервером, узевой токен гасится
   каскадом, `connection_events` сохраняются с `server_id = null`».
3. §13 (Известные ограничения), три новые строки: доступность отблокированного access-токена
   заблокированного пользователя ≤ `AccessTTL`; отзыва администраторов в A-2 нет
   (у `admin_users` нет `revoked_at`, а `DELETE` каскадом `SET NULL` обезличил бы
   прошлые записи аудита); создания админа через CLI не оставляют записи в аудите.

- [ ] **Step 13: Прогон**

Run: `make unit && make vet && make api-lint && make integration`
Expected: PASS. Контракт ещё не описывает admin-маршруты (это задача 14), и `api-lint`
не знает ни одного нового маршрута — правило «контракт и код расходятся» ловит задача 15,
а не этот прогон; расхождение запрещено держать дольше следующей задачи.

- [ ] **Step 14: Коммит**

```bash
git add internal/audit internal/admin internal/auth/token.go internal/auth/token_test.go \
        internal/db/query/admin.sql internal/db \
        internal/httpx/context.go internal/httpx/logging.go internal/httpx/decorators.go \
        services/api/router.go services/api/cmd/novavpn-api/main.go \
        docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md \
        tests/integration/admin_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(admin): роль администратора, CRUD серверов, bootstrap-токены, блокировка и аудит"
```

---

### Task 13: Sweeper — просроченные профили, спящие, stale-узлы и retention

**Files:**
- Create: `internal/connections/sweeper.go`, `internal/connections/sweeper_test.go`,
  `tests/integration/sweeper_test.go`
- Modify: `internal/db/query/maintenance.sql` (одна выборка), `services/api/cmd/novavpn-api/main.go`
  (запуск в `serve`)

**Interfaces:**
- Consumes: `ExpiredActiveProfiles`, `MarkProfileExpired`, `ReleaseAddressByProfile`,
  `BumpServerConfigVersion`, `InsertConnectionEvent`, `MarkStaleHealth`,
  `DeleteOldConnectionEvents`, `NullOldRefreshIPs`, `PurgeOldIdempotencyKeys` (задача 1);
  `RevokeProfile` (задача 1); `db.RunInTx`; `DefaultProfileTTL` (задача 5).
- Produces (пакет `connections`):
  - константы `DefaultSweepInterval = time.Hour`, `DormantAfter = 7 * 24 * time.Hour`,
    `TrafficWindowDays = 30` (её читает admin-просмотр задачи 12);
  - `type Store interface { SweepExpired; SweepDormant; SweepStale; SweepRetention }` (шаг 1);
  - `type Retention struct{ EventsDeleted, IPsCleared, KeysPurged int64 }`,
    `type Report struct{ Expired, Dormant, Stale int; Retention Retention }`;
  - `func NewStore(pool *pgxpool.Pool) Store`;
  - `func sweepAll(ctx context.Context, st Store, log *slog.Logger, now time.Time) Report`;
  - `func Run(ctx context.Context, st Store, log *slog.Logger, interval time.Duration)`;
  - `func (s *pgStore) …` — четыре метода.

- [ ] **Step 1: Константы, Store и Report — дословный исходник (`internal/connections/sweeper.go`)**

```go
// Окна «жизни без клиента». Оба числа — решение плана, а не строка из ТЗ:
// спецификация §7.2 описывает отзыв по инициативе пользователя, а что делать с
// выданным и забытым профилем — не говорит.
const (
	// DefaultSweepInterval — как часто метать просрочку. Час: DesiredTTL в месяцах,
	// и опаздывать на час с profile_expired ничего не стоит, а чаще — значит гонять
	// три DELETE'а по полным таблицам на каждом такте.
	DefaultSweepInterval = time.Hour

	// DormantAfter — профиль, под которым ни разу не наблюдали handshake, живёт
	// столько. Смысл числа: «выдал и забыл» становится мусором в desired set, а
	// каждый лишний пиер — это строка в конфиге узла и адрес, занявший пул.
	DormantAfter = 7 * 24 * time.Hour

)

// Retention — сколько строк метла убрала из каждого стола. Это не «для статистики»:
// оператор по числам судит, метла работает или молча падает каждый такт.
type Retention struct {
	EventsDeleted int64
	IPsCleared    int64
	KeysPurged    int64
}

type Report struct {
	Expired   int
	Dormant   int
	Stale     int
	Retention Retention
}

// Store — то, что делает метель. Интерфейс нужен не для «слоя»: порождать просроченный
// профиль в проде можно только временем, а ждать его в тесте нельзя, поэтому тест
// подставляет хранилище, а интеграционный прогон играет настоящей БД (шаг 7 этой задачи).
type Store interface {
	SweepExpired(ctx context.Context, now time.Time) (int, error)
	SweepDormant(ctx context.Context, now time.Time) (int, error)
	SweepStale(ctx context.Context, now time.Time) (int, error)
	SweepRetention(ctx context.Context, now time.Time) (Retention, error)
}

type pgStore struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) Store { return &pgStore{pool: pool} }
```

- [ ] **Step 2: `sweepAll` — дословный исходник**

```go
// sweepAll метёт четыре вида работы и не даёт одному виду остановить остальные.
// Причина не в вежливости: retention — самый дорогой и самый «внешний» шаг (полные
// таблицы), и его падение из-за отвалившегося соединения не имеет права означать
// «просроченный профиль ещё час сидел в desired set».
func sweepAll(ctx context.Context, st Store, log *slog.Logger, now time.Time) Report {
	var r Report
	n, err := st.SweepExpired(ctx, now)
	if err != nil {
		log.Error("sweep expired", "err", err)
	} else {
		r.Expired = n
	}
	n, err = st.SweepDormant(ctx, now)
	if err != nil {
		log.Error("sweep dormant", "err", err)
	} else {
		r.Dormant = n
	}
	n, err = st.SweepStale(ctx, now)
	if err != nil {
		log.Error("stale mark", "err", err)
	} else {
		r.Stale = n
	}
	ret, err := st.SweepRetention(ctx, now)
	if err != nil {
		log.Error("retention sweep", "err", err)
	} else {
		r.Retention = ret
	}
	if r.Expired+r.Dormant+r.Stale != 0 || r.Retention != (Retention{}) {
		log.Info("sweep", "expired", r.Expired, "dormant", r.Dormant,
			"stale", r.Stale, "events_deleted", r.Retention.EventsDeleted,
			"ips_cleared", r.Retention.IPsCleared, "keys_purged", r.Retention.KeysPurged)
	}
	return r
}

// Run — тактовый цикл. Первый проход сразу после старта: профиль мог протухнуть,
// пока API был выключен, а час молчания desired set с уже снятым доступом — это
// обещание (§7.2 «узел снимает пиера»), которое никто не выполнил.
func Run(ctx context.Context, st Store, log *slog.Logger, interval time.Duration) {
	sweepAll(ctx, st, log, time.Now())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepAll(ctx, st, log, time.Now())
		}
	}
}
```

- [ ] **Step 3: Просроченные и спящие — правка запроса и схема, не исходник**

Добавить в `internal/db/query/maintenance.sql` (дословный исходник):

```sql
-- name: DormantActiveProfiles :many
-- Порог приходит timestamptz'ом, вычисленным в Go (now.Add(-DormantAfter)), а не
-- interval-параметром: override'а на interval в sqlc.yaml нет, и $1::interval стал бы
-- pgtype.Interval — тот же сюрприз, что с InsertBootstrapToken в задаче 1.
-- Окно привязано к issued_at, а не к порогу: профиль, выданный вчера, обязан иметь
-- право быть новым, а handshake полгода назад для недельного dormancy — не доказательство.
SELECT p.id, p.server_id, p.device_id, d.user_id
FROM vpn_profiles p
JOIN devices d ON d.id = p.device_id
WHERE p.status = 'active' AND p.issued_at < $1
  AND NOT EXISTS (
      SELECT 1 FROM connection_events e
       WHERE e.server_id = p.server_id AND e.device_id = p.device_id
         AND e.event = 'handshake_observed' AND e.created_at >= p.issued_at)
ORDER BY p.id;
```

`SweepExpired` — одна транзакция **на профиль**, не одна на всю выборку:

1. `ExpiredActiveProfiles(now)` → rows (запрос уже отдаёт `user_id`);
2. на каждый row в `db.RunInTx`: `MarkProfileExpired(id)` → `ReleaseAddressByProfile(id)`
   → `BumpServerConfigVersion(server_id)` → `InsertConnectionEvent(profile_expired,
   user_id, device_id, server_id, detail {})`.

`SweepDormant(now)` — та же форма, `DormantActiveProfiles(now.Add(-DormantAfter))`,
и вместо `MarkProfileExpired` — `RevokeProfile(id)` (статус `revoked`, `revoked_at` —
профиль снят решением, а не временем) с событием `profile_revoked` и detail
`{"reason":"dormant"}`.

Почему транзакция на профиль, а не одна большая: `BumpServerConfigVersion` и отзыв идут
под тем же advisory-замком сервера, что и выдача (задача 4), и одна транзакция на
тысячи профилей держала бы все замки сразу — выдача встала бы на минуты. По профилю —
замок живёт миллисекунды, а порядок (`ORDER BY p.id`) один и тот же, поэтому параллельные
метлы двух реплик не входят в клинч.

`MarkProfileExpired` и `RevokeProfile` — `:one`, и при несовпадении статуса вернут
`pgx.ErrNoRows`. Его обязан отличить от настоящей ошибки вызывающий код
(`errors.Is(err, pgx.ErrNoRows)` → следующий профиль, без bump'а и без события): ноль
строк означает, что профиль успел отозвать пользователь или другая метла, и это не
поломка. Ошибка соединения при этом обязана остановить проход — иначе метла сделает
вид, что пометла, и на следующем такте повторит ту же выборку.

- [ ] **Step 4: Stale-узлы и retention — схема, не исходник**

`SweepStale(now)`: в одной транзакции `MarkStaleHealth()` → на каждый возвращённый `server_id`
`InsertConnectionEvent(node_stale, user_id=nil, device_id=nil, server_id, detail {})`.
Возвращает число переходов `ok → stale`. Условие `status = 'ok'` в самом запросе —
почему событие пишется ровно один раз на зависание, а не каждый такт: иначе за сутки
на одном замолчавшем узле накопится 24 одинаковые записи, и «узел завис» превратится
в шум, который никто не читает.

`SweepRetention(now)`: три `:execrows` подряд, вне общей транзакции. Аргументов у
этих запросов нет — границы («90 дней», «24 hours», «7 days») уже написаны в SQL
задачи 1, поэтому `now` сюда не приходит и второй источник времени не появляется. Каждый — отдельный оператор, своя ошибка, счётчики
в `Retention`. Здесь нет общей атомарности сознательно: три стола retention независимы,
а «два очистились, третий упал» для оператора лучше, чем «ничего не очистилось, но
транзакция была красивая».

Отдельно: `DeleteOldConnectionEvents` стирает события старше 90 суток, а `SweepDormant`
ищет handshake по `connection_events`. Это не конфликт, а граница: dormancy требует
отсутствия событий с `issued_at`, а профиль старше 90 суток уже снят по `expires_at`
(`DefaultProfileTTL = 30 суток`) — до возраста, когда события успеют стереться, профиль
не доживает. Оставить это невысказанным значило бы оставить в коде ловушку на будущее
изменение TTL, поэтому она написана здесь и в §13.

- [ ] **Step 5: Монтаж в `serve()` — схема, не исходник**

В `services/api/cmd/novavpn-api/main.go` в `serve(cfg)`, после построения пула и до
`srv.Serve`:

```go
	go connections.Run(ctx, connections.NewStore(pool), log, connections.DefaultSweepInterval)
```

`ctx` — тот же, что уходит в `signal.NotifyContext`, поэтому graceful shutdown
останавливает метлу без второго механизма. Работы в пол-транзакции при этом не
обрывается: `RunInTx` либо уже закоммитил, либо откатится, а все четыре шага
идемпотентны по состоянию — следующий такт доделает.

Две реплики API с метлой — допустимое состояние, а не ошибка: каждый шаг защищён
условием по статусу, так что повторная метель видит ноль строк. Цена — возможны два
bump'а `config_version` подряд, и это безобидно (версия обязана быть монотонной, а не
непрерывной). Отдельная «выборка лидера» — это A-3, когда топология станет известна.

- [ ] **Step 6: Unit-тест изоляции видов работы — дословный исходник (`internal/connections/sweeper_test.go`)**

Файл лежит в `package connections`: `sweepAll` не экспортируется, и экспортировать его
ради теста нельзя — наружу метла обязана быть видна только как `Run`.

```go
type fakeStore struct {
	expiredFn func(context.Context, time.Time) (int, error)
	dormantFn func(context.Context, time.Time) (int, error)
	staleFn   func(context.Context, time.Time) (int, error)
	retFn     func(context.Context, time.Time) (Retention, error)
	calls     []string
}

func (f *fakeStore) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	f.calls = append(f.calls, "expired")
	if f.expiredFn == nil {
		return 0, nil
	}
	return f.expiredFn(ctx, now)
}

func (f *fakeStore) SweepDormant(ctx context.Context, now time.Time) (int, error) {
	f.calls = append(f.calls, "dormant")
	if f.dormantFn == nil {
		return 0, nil
	}
	return f.dormantFn(ctx, now)
}

func (f *fakeStore) SweepStale(ctx context.Context, now time.Time) (int, error) {
	f.calls = append(f.calls, "stale")
	if f.staleFn == nil {
		return 0, nil
	}
	return f.staleFn(ctx, now)
}

func (f *fakeStore) SweepRetention(ctx context.Context, now time.Time) (Retention, error) {
	f.calls = append(f.calls, "retention")
	if f.retFn == nil {
		return Retention{}, nil
	}
	return f.retFn(ctx, now)
}

func TestSweepAllRunsEveryKindDespiteErrors(t *testing.T) {
	boom := errors.New("boom")
	st := &fakeStore{
		expiredFn: func(context.Context, time.Time) (int, error) { return 0, boom },
		staleFn:   func(context.Context, time.Time) (int, error) { return 0, boom },
		dormantFn: func(_ context.Context, _ time.Time) (int, error) { return 3, nil },
		retFn: func(_ context.Context, _ time.Time) (Retention, error) {
			return Retention{EventsDeleted: 7}, nil
		},
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	r := sweepAll(context.Background(), st, log, time.Unix(0, 0))
	if r.Dormant != 3 || r.Retention.EventsDeleted != 7 || r.Expired != 0 || r.Stale != 0 {
		t.Errorf("report = %+v", r)
	}
	if strings.Join(st.calls, ",") != "expired,dormant,stale,retention" {
		t.Errorf("kinds = %v, want all four in order", st.calls)
	}
	// Упавшие виды работы обязаны быть слышны, а не проглочены: ровно две Error-строки.
	if n := strings.Count(buf.String(), `"lvl":"ERROR"`); n != 2 {
		t.Errorf("journal has %d error lines, want 2 (%s)", n, buf.String())
	}
}
```

Порядок вызовов проверяется потому, что он и есть смысл изоляции: если `SweepExpired`
упал, а `SweepDormant` не вызван, «упавший вид работы» превращается в «остановленную
метлу», и тест этого бы не увидел.

- [ ] **Step 7: Интеграционный тест — `tests/integration/sweeper_test.go`, схема, не исходник**

Хранилище — настоящее (`connections.NewStore(pool)`), время подставляется в явные
аргументы методов: просрочку играют UPDATE'ом `expires_at` в прошлое (иначе «подождать
30 суток» — тест, который никто не запускал), а dormancy — `issued_at` в прошлое. Это
не «подмена логики»: пороги живут в SQL-условиях и в константе, а тест двигает данные.

| случай | ожидание |
|---|---|
| профиль с `expires_at` в прошлом, `status='active'` | `SweepExpired` = 1; в БД `status='expired'`, адрес освобождён с окном 5 минут, `config_version` сервера +1, одно событие `profile_expired` с `user_id` профиля |
| тот же профиль повторно | 0 строк, ни bump'а, ни второго события |
| профиль active, `issued_at` = now−8d, событий handshake нет | `SweepDormant(now)` = 1; `status='revoked'`, `revoked_at` выставлен, адрес освобождён, событие `profile_revoked` с detail `{"reason":"dormant"}` |
| профиль active, `issued_at` = now−8d, но есть `handshake_observed` | `SweepDormant(now)` = 0: соединение было — это не «выдал и забыл», а клиент, который спит |
| профиль active, `issued_at` = now−2d, handshake нет | 0: моложе порога — у клиента есть право подняться впервые |
| `server_health` с `observed_at` = now−200s, `status='ok'` | `SweepStale` = 1, `status='stale'`, одно `node_stale`; повторный вызов = 0 и второго события нет |
| события старше 90 суток (вставить `created_at` UPDATE'ом) | `SweepRetention` → `EventsDeleted` ≥ 1; молодые события целы |
| refresh-семья старше 90 суток с `ip` | `IPsCleared` ≥ 1, `ip` стал NULL, сама семья цела (детект переиспользования не должен ослепнуть) |
| завершённый idempotency-ключ старше 24 часов и незавершённый старше 7 суток | `KeysPurged` = 2 |
| `sweepAll` на стенде со всеми четырьмя видами | `Report` содержит все четыре числа, в журнале одна `sweep`-строка с ними же |
| два параллельных `SweepExpired` (2 горутинки) на одном профиле | суммарно ровно 1 (не 2): `MarkProfileExpired` защищён условием статуса, и вторая транзакция видит уже `expired` |

Run: `make unit && make vet && make integration`
Expected: PASS.

- [ ] **Step 8: Коммит**

```bash
git add internal/connections/sweeper.go internal/connections/sweeper_test.go \
        internal/db/query/maintenance.sql internal/db \
        services/api/cmd/novavpn-api/main.go tests/integration/sweeper_test.go
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "feat(connections): метель — просрочка, спящие профили, stale-узлы и retention"
```

---

### Task 14: Контракт A-2 — публичные маршруты, admin и `/internal/v1`

**Files:**
- Modify: `api-spec/openapi.yaml`, `api-spec/contract_test.go`,
  `docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md` (§5.1, §5.2)

**Interfaces:**
- Consumes: фактические хендлеры задач 2, 5–8, 11–12 (маршруты берутся из кода, а не из
  фантазии: расхождение ловит задача 15 живым сверением ответов).
- Produces: полный контракт цикла A; `server_not_available` в перечислении `ErrorCode`.

- [ ] **Step 1: Правка `api-spec/contract_test.go` — сначала она, потом YAML**

Тест A-1 (задача 16) запрещает то, что эта задача обязана сделать:

1. `TestAllPathsArePublicV1` проверяет, что **каждый** путь начинается с `/api/v1/`, и
   что путей ровно 6. Оба утверждения ломятся в A-2: `/internal/v1/*` — не публичный
   путь, а число путей растёт. Тест переписывается на `TestPathsArePartitioned`:
   множество путей сверяется с литеральным списком этой задачи (не с числом: число
   не говорит, какой именно путь потеряли), а каждый путь обязан попадать ровно в один
   префикс — `/api/v1/` или `/internal/v1/`.
2. В `declared` добавляется `"server_not_available": httpx.ErrServerNotAvailable` —
   иначе тест 1 (`TestContractCodesAreDeclared`) упадёт на новом коде из enum, и это
   правильный порядок: сначала константа в Go, потом строка в контракте.
3. Новое утверждение `TestInternalPathsUseNodeScheme`: у каждого `/internal/v1/*`
   маршрута, кроме `nodes/enroll`, объявлен `security: [{nodeBearerAuth: []}]`; у каждого
   `/api/v1/admin/*` — `adminBearerAuth`. Смысл: документировать «кто имеет право
   спрашивать» — то, из-за чего два `iss` в токенах вообще раздельные.

- [ ] **Step 2: Публичные маршруты — схема, не исходник**

Добавить в `paths:` (префиксы, как в A-1, — путь с `/api/v1/` целиком):

| путь | методы и коды |
|---|---|
| `/api/v1/servers` | `GET` → 200 `ServerList`, `GET` под `bearerAuth`; 401, 429 |
| `/api/v1/devices/{id}` | `DELETE` → 204; 400, 401, 404, 429 |
| `/api/v1/devices/{id}/keys/rotate` | `POST` с `IdempotencyKey` → 201 `RotateResponse`; 400 `invalid_request` (в том числе неканонический `new_public_key` — задача 8), 401, 404, 409 `device_limit_reached`, 429 |
| `/api/v1/devices/{id}/profiles` | `POST` с `IdempotencyKey` → 201 `ProfileView`; `GET` → 200 массив `ProfileView`; 400, 401, 404, 409 (`conflict`, `device_limit_reached`, `server_not_available`), 429. `503` в контракте нет намеренно: §7.1 отказывает «сервера нет в вашем плане» и «сервер не онлайн» стабильным кодом, а `503` обещал бы клиенту «повтори позже», которого админ не выполнял |
| `/api/v1/devices/{id}/profiles/{server_id}` | `DELETE` → 200 `ProfileView` (отозванный, чтобы клиент увидел `revoked_at`), 401, 404, 409; `GET` → 200 `ProfileView` |
| `/api/v1/devices/{id}/profiles/{server_id}/config` | `GET` → 200 **`text/plain`**, `x-wg-config`; описание обязано содержать: «текст без строки `PrivateKey` — приватный ключ устройства не покидает устройство (ТЗ §5); клиент вставляет его локально перед применением» |

- [ ] **Step 3: Маршруты управления — схема, не исходник**

Все `/api/v1/admin/*` под `adminBearerAuth`, кроме `POST /api/v1/admin/login`
(`security: []`). Набор — ровно таблица задачи 12 (шаг 6, 8, 9): вход, `servers` (список
и создание), `servers/{id}` (чтение, правка, удаление), `servers/{id}/maintenance`,
`servers/{id}/bootstrap-tokens` (выдача и список), `bootstrap-tokens/{id}` (отзыв),
`servers/{id}/node-token/revoke`, `users/{id}/lock`, `users/{id}/unlock`, `users/{id}`
(чтение), `admins` (создание), `audit` (чтение). У каждого — минимум один 4xx по факту
(401 почти везде, плюс 404/409/400 там, где задача их возвращает).

`GET /api/v1/admin/servers/{id}` описывается как `{server, health}` с
`health: {nullable: true}` — то же правило, что §13.4: неизмеренное не превращается в ноль.

- [ ] **Step 4: Узловой контракт — схема, не исходник**

| путь | методы |
|---|---|
| `/internal/v1/nodes/enroll` | `POST`, `security: []`, тело `NodeEnrollRequest` → 201 `NodeToken`; 400, 401, 429 |
| `/internal/v1/nodes/{server_id}/desired` | `GET` под `nodeBearerAuth`; 200 `DesiredSet` + заголовок `ETag`, 304 **без тела** (отдельный response без `content`), 401, 403, 404, 429 |
| `/internal/v1/nodes/{server_id}/observed` | `POST` → 204; 400, 401, 403, 429 |
| `/internal/v1/nodes/{server_id}/heartbeat` | `POST` → 204; 400, 401, 403, 429 |
| `/internal/v1/nodes/{server_id}/token/rotate` | `POST` → 200 `NodeToken`; 401, 403, 429 |

Схемы: `DesiredSet{server_id, config_version, mtu, keepalive_sec, endpoint_host,
endpoint_port, dns_servers[], allowed_ips[], peers[]}`, `Peer{public_key,
allowed_ips[], endpoint_hint?, presplit?, persistent_keepalive?, comment}` — набор полей
обязан совпасть с `servers.Peer` задачи 9 **по именам json-тегов**, а не по памяти;
`NodeEnrollRequest{bootstrap_token, public_key}`, `NodeToken{server_id, node_token}`,
`ObservedReport{server_id, applied_config_version, interface_rx_bytes, interface_tx_bytes,
peers[{public_key, rx_bytes, tx_bytes, last_handshake_unix}]}`,
`Heartbeat{server_id, agent_version, agent_uptime_sec, applied_config_version}`.

`304` — единственный случай «ответ без тела» во всём контракте, и он обязан быть
описан явно: клиент, который читает спецификацию как список тел, иначе станет искать
JSON в пустом ответе.

- [ ] **Step 5: Схемы ответов пользователя — схема, не исходник**

`ServerSummary{id, name, country_code, city, advertised_host?, listen_port?,
availability, latency_ms, load_pct, peers_active, capacity_mbps}` — пропуски измеренного
выражаются `null` и в описании поля, а не отсутствием поля (задача 2 выбрала `null`
именно поэтому). `ProfileView{id, device_id, server_id, address_v4, status, issued_at,
expires_at, overlap_valid_until?, revoked_at?}`. `RotateResponse{device_id,
new_public_key, superseded_profile_id?, overlap_valid_until}`. `AdminServerView`,
`BootstrapToken{token?}` (поле присутствует только в ответе выдачи — в контракте это
отдельная схема `BootstrapTokenIssued`), `AuditEntry{...}`, `AdminUserView{email, status,
locked_reason, devices[], traffic[]}`, `TrafficEntry{device_id, rx_bytes, tx_bytes, days}`.

Ни одна схема не содержит `private_key`, `password_hash`, `token_hash`: проверка —
задача 15 (живое сравнение ответов), а не молчание автора контракта.

- [ ] **Step 6: `info.description` и теги**

Обновить: убрать фразу «маршруты узла (`/internal/v1`) … появляются в A-2» (они здесь),
добавить теги `servers`, `profiles`, `node`, `admin`. Описание `servers`-пути обязано
повторить правило `null`, а описание `node` — что контракт внутренний, доступ к нему
имеет только узел с узловым токеном, и он не является частью публичного API.

- [ ] **Step 7: Правка спецификации §5.1 и §5.2**

§5.1 — ссылка на контракт (маршруты узла и admin перечислены там же, где они теперь в
OpenAPI); §5.2 — в перечень кодов добавлен `server_not_available` (находка 6 уже
предупреждала, что число в envelope должно быть стабильным).

- [ ] **Step 8: Прогон**

Run: `make api-lint && make unit`
Expected: PASS (redocly по умолчанию требует `summary` и `operationId` у каждой операции —
стиль A-1 это уже соблюдает; правила «как минимум один 4xx» в новой версии redocly —
предупреждение, а не ошибка, и ни один маршрут из шагов 2–4 не должен до него доходить).

- [ ] **Step 9: Коммит**

```bash
git add api-spec/openapi.yaml api-spec/contract_test.go \
        docs/superpowers/specs/2026-10-20-novavpn-cycle-a-access-core-design.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "docs(api): контракт A-2 — профили, каталог, admin и /internal/v1"
```

---

### Task 15: Приёмка A-2 — матрица с узлом и админом, живая сверка контракта, статус проверок

**Files:**
- Modify: `tests/integration/matrix_test.go`, `tests/integration/contract_test.go`,
  `tests/integration/helpers_test.go` (если не хватает фикстур), `docs/testing-status.md`

**Interfaces:**
- Consumes: собранный роутер (задачи 6, 11, 12), контракты задач 14, `api-spec/openapi.yaml`.
- Produces: замкнутый цикл A-2; строки «не проверено» только для того, чего проверить
  нельзя (wire-половина, реальный узел).

- [ ] **Step 1: Матрица — новые актёры и маршруты, схема, не исходник**

К `env` (задача 19 A-1) добавляются два источника состояний, каждый — ровно один раз,
иначе тесты начнут строить доступ в обход роутера:

```go
func (e *env) admin(t *testing.T) adminActor      // seedAdmin + настоящий POST /admin/login
func (e *env) node(t *testing.T, serverID uuid.UUID) nodeActor // bootstrap-токен через admin-маршрут + enroll
```

`matrixCases()` дополняется группами по каждому новому маршруту. Минимальный набор
утверждений на маршрут: `аноним`, `участник`, `истёкшая подписка`, `заблокированный`
для публичных; `аноним`, `участник с пользовательским токеном`, `админ` для admin-маршрутов;
`без токена`, `с пользовательским токеном`, `чужой узел`, `свой узел` для `/internal/v1/*`.
Три последних — это проверка находки задачи 11: узел-самозванец обязан получить `403`,
а не «чужой desired set».

Бюджет запросов (правило A-1 остаётся: любая 429 в матрице обрывает прогон как «тест
съел свой лимит»). В A-2 матрица растёт, и правило требует учёта: `userPerMin = 600` и
`anyPerMin = 300` считаются на IP и на пользователя, `admin`-бакет — на админа, `node` —
на `server_id`. Поэтому: анонимных вызовов одного маршрута ≤ 4 (это единственное жёсткое
число — бакет 5 на пару (маршрут, IP)), всех вызовов прогона < 250 на IP, и узловые
маршруты дёргаются одним `server_id` не чаще 10 раз подряд. Проверка — существующий
цикл по `e.ev.calls` в конце `TestAccessMatrix`, новый помощник не нужен.

- [ ] **Step 2: `checkEvidence` — новые секреты, схема, не исходник**

Список `e.ev.secrets` пополняется: пароль админа из `seedAdmin`, выданный bootstrap-токен,
`node_token` из enroll и из `token/rotate`. Правила те же: ни в журнале, ни в чужом
ответе; единственный маршрут, где `node_token` законен, — тот, что его выдал.
Дополняются и «маркеры» (строки, которых в журнале быть не должно): `private_key` уже
есть, добавить `bootstrap_token` и `node_token`.

Отдельное утверждение, которого в A-1 быть не могло, и оно не то же самое, что
существующее: цикл `checkEvidence` ищет в байтах ответа маркер `"private_key"` (с
подчёркиванием, как в колонке `private_key`), а WireGuard-конфиг пишет `PrivateKey=` —
без подчёркивания. После `strings.ToLower` это `"privatekey="`, и нынешний список его не
ловит, то есть текст конфига прошёл бы проверку молча. Значит в список маркеров
`checkEvidence` добавляются `"privatekey"` (именно так, без подчёркивания) и `"presharedkey"`,
а desired set обязан не содержать никакого ключевого материала кроме публичных ключей —
проверка по байтам ответа, а не по типу ответа.

- [ ] **Step 3: Живая сверка контракта — `tests/integration/contract_test.go`, схема**

`TestLiveResponsesMatchContract` дополняется случаями (сверка с `openapi.yaml` этой же
задачи, как в A-1: живые байты против объявленной схемы):

- `GET /api/v1/servers` — форма `ServerSummary`, и обязательная тройка
  `latency_ms`/`load_pct`/`peers_active` присутствует даже когда значения `null`;
- `POST/GET/DELETE` профилей — `ProfileView`;
- `GET …/config` — тип ответа `text/plain`, схема не JSON, и проверка отсутствия
  `PrivateKey`;
- `POST …/keys/rotate` — `RotateResponse`;
- `GET /internal/v1/nodes/{id}/desired` — `DesiredSet`, наличие `ETag`, и `304`
  обязан быть **пустым** (для него в контракте нет `content`, и живой ответ должен
  совпасть);
- `POST …/observed` и `…/heartbeat` — `204` без тела;
- `POST /api/v1/admin/login` — `AdminSession`;
- `GET /api/v1/admin/servers/{id}` — `{server, health}` с `health: null` на сервере,
  который никогда не отвечал heartbeat'ом (то самое §13.4 в живом ответе);
- отказы: каждый новый код (`server_not_available` хотя бы) встречается в живом
  прогоне, иначе `checkErrorCodeKnown` проверяет enum, которого никто не видел.

- [ ] **Step 4: Правка `docs/testing-status.md`**

1. В «Проверено» — новые строки: каталог и `availability` по свежести health (задача 2);
   аллокация адреса под advisory-замком и окно переиспользования (задача 4, 10 горутин);
   выдача/отзыв/ротация профиля с overlap (задачи 5, 7, 8); desired set и его
   инвариантное свойство на 1000 случайных наборов (задача 9); свёртка телеметрии и
   детект сброса счётчиков (задача 10); контракт узла против fake-узла, включая
   `ETag`/`304` и одноразовость bootstrap-токена (задача 11); admin-роль, CRUD серверов,
   блокировка с причиной и обязательность аудита (задача 12); метель по всем четырём
   видам работ (задача 13); совпадение новых ответов с контрактом (задача 14, этот шаг).
2. Строку A-1 «Остальные маршруты §5.1 …» закрыть: маршруты есть, и они проверены —
   кроме wire-половины.
3. В «not-run» — перенести и добавить:
   - реальная работа туннеля: handshake, трафик через узел, `allowed_ips`, MTU на
     реальном интерфейсе — нечем, кроме A-3 (harness на VPS);
   - поведение узла при `draining` и при снятии пиера — control plane проверен,
     применение конфига нет (A-3, спайк S1/S3 на реальном железе);
   - отзыв администратора и разделение прав внутри admin-роли (в A-2 нет ни колонки
     `revoked_at`, ни второго субъекта права, ни UI);
   - срочный отзыв access-токена заблокированного пользователя (denylist индексируется по
     `jti`, `jti` заблокированного нигде не собраны — окно = `AccessTTL`);
   - метель на двух репликах API одновременно (логика идемпотентности проверена
     конкурентным тестом одной выборки, распределённой блокировки лидера нет);
   - `agent_version`/`agent_uptime_sec` в каталоге: heartbeat пишет их, `UpsertServerHealth`
     из observed — обнуляет (задача 10, ограничение §13);
   - retention на объёмах, сравнимых с продакшеном (числа DELETE'ов не замерялись).
4. Финальное предложение файла — как в A-1: ни одна строка «Проверено» не имеет права
   ссылаться на механизм, которого нет в коде.

- [ ] **Step 5: Полные ворота**

Run: `make unit && make vet && make api-lint && make integration`
Expected: PASS. Затем сканеры чистоты текста этого плана и репозитория: CJK = 0,
U+FFFD = 0, склеенных слов латиницы с кириллицей = 0 (тот же regex, что применялся к
плану), `gofmt -l` пустой, `grep -rn "TODO(" --include=*.go internal services tests` пустой.

- [ ] **Step 6: Коммит**

```bash
git add tests/integration/matrix_test.go tests/integration/contract_test.go \
        tests/integration/helpers_test.go docs/testing-status.md
git -c user.name="NovaVPN Dev" -c user.email="dev@novavpn.local" \
    commit -m "test(a2): приёмка — матрица с узлом и админом, живая сверка контракта, статус"
```

---

## Чек-лист самопроверки плана (перед прогоном)

1. Каждая находка спецификации (§ «Что план нашёл») закрыта задачей, а не обещанием.
2. Ни один блок «дословный исходник» не ссылается на имя, которого нет в плане или в
   репозитории: `RotationOverlap`, `NodeTunnelAddress`, `DefaultProfileTTL`, имена
   sqlc-запросов, константы лимитеров.
3. Ни одна задача не требует «подтвердить, что работает» без команды прогона.
4. `not-run` строки в задаче 15 перечисляют всё, что в этом цикле проверить нельзя, и
   не молчат ни об одном ограничении, упомянутом внутри задач.
