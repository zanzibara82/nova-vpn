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
| Матрица «роль × маршрут» (аноним, участник, истёкшая подписка, блокировка, администратор, узел) | `tests/integration/matrix_test.go` | `make integration` |
| Ответы не содержат токенов, паролей, писем и ключей | `checkEvidence` в `tests/integration/matrix_test.go` | `make integration` |
| Живые ответы соответствуют `api-spec/openapi.yaml`, включая `text/plain`, 304, отказы и admin-схемы | `tests/integration/contract_test.go` | `make integration` |
| Лимитер: token bucket, 429 с Retry-After, fail-open при отказе Redis | `internal/httpx/ratelimit_test.go` (fail-open — unit на fake-клиенте) | `make unit` |
| Каталог: только online-серверы, availability по свежести heartbeat, `latency_ms`/`load`/`capacity_mbps` — `null`, а не ноль | `internal/servers/catalog_test.go`, `tests/integration/catalog_test.go` | `make unit && make integration` |
| Аллокация адреса под advisory-замком и окно переиспользования выпущенного адреса | `tests/integration/address_test.go` (10 горутин на пул /28), `internal/connections/address_test.go` | `make unit && make integration` |
| WireGuard-конфиг: рендер и разбор, `PrivateKey` отвергается и не рендерится | `internal/connections/wgconfig_test.go`, `tests/integration/profiles_test.go`, `contract_test.go` | `make unit && make integration` |
| Выдача, чтение и отзыв профиля; не-online сервер — `server_not_available`, а не 503 | `tests/integration/profiles_test.go`, `profiles_http_test.go` | `make integration` |
| Отзыв устройства: профили и overlap-цепочка, чужое и несуществующее неразличимы | `tests/integration/device_delete_test.go` | `make integration` |
| Ротация ключа: overlap-окно, лимит устройств не тратится, идемпотентность | `tests/integration/rotation_test.go` | `make integration` |
| Desired set: права на пиер, ротация и инвариант «снятый доступ не попадает» на 1000 случайных наборов | `internal/servers/desired_test.go`, `tests/integration/desired_test.go` | `make unit && make integration` |
| Телеметрия: дельты, детект сброса счётчиков, handshake и health | `internal/telemetry/delta_test.go`, `tests/integration/telemetry_test.go` | `make unit && make integration` |
| Контракт узла `/internal/v1`: `ETag`/304, одноразовый bootstrap-токен, отказ чужому `server_id`, лимит на сервер | `tests/integration/nodeapi_test.go` | `make integration` |
| Admin-роль: вход без оракула, CRUD серверов, bootstrap-токены, блокировка с причиной, аудит, секреты вне журнала | `tests/integration/admin_test.go` | `make integration` |
| Sweeper: просрочка, спящие, stale-узлы и retention по всем четырём видам работ | `tests/integration/sweeper_test.go`, `internal/connections/sweeper_test.go` | `make unit && make integration` |
| Узел: WireGuard в привилегированном контейнере, применение набора пиеров без потери handshake | спайки S1 и S3, `docs/adr/0004-wireguard-peer-apply.md` | см. `docs/spikes/2026-10-20-s1-s3-wireguard-netlink.md` |

## not-run (не проверено — и не заявляется как проверенное)

| что | почему не проверялось | где появится |
| --- | --- | --- |
| Работа с реальным VPS (78.17.192.147): публикация узла, MTU, пропускная способность, поведение при потере peering | доступа к узлу нет; метрики без замера по спецификации §13.4 пишутся `null`, а не нулями | цикл A-3, повторный прогон S1/S3 на реальном железе |
| Реальная работа туннеля: handshake, трафик через узел, `allowed_ips` и MTU на настоящем интерфейсе | control plane проверен, а применить набор негде: harness на VPS появится в A-3 | цикл A-3 (S1/S3 на реальном железе) |
| Поведение узла при `draining` и при снятии пиера | control plane отвечает и обновляет desired set, применение конфига на живом интерфейсе не проверялось | цикл A-3 (спайки S1/S3 на реальном железе) |
| Отзыв администратора и разделение прав внутри admin-роли | в A-2 нет ни колонки `revoked_at`, ни второго субъекта права, ни UI | цикл C/D |
| Срочный отзыв access-токена заблокированного пользователя | denylist индексируется по `jti`, а `jti` заблокированного нигде не собраны: окно = `AccessTTL` | цикл C (событие блокировки в denylist) |
| Sweeper на двух репликах API одновременно | идемпотентность проверена конкурентным тестом одной выборки, распределённой блокировки лидера нет | цикл C (лидер в кластере) |
| `agent_version`/`agent_uptime_sec` в каталоге | heartbeat пишет их, `UpsertServerHealth` из observed обнуляет (ограничение §13) | цикл A-3 (расширение health) |
| Retention на объёмах, сравнимых с продакшеном | числа DELETE'ов на больших таблицах не замерялись | цикл C (метрики и нагрузка) |
| node-agent как демон, Ansible-раскатка, systemd-юнит, TLS между узлом и API-шлюзом | сборка узла — отдельная задача | цикл A-3 |
| Клиенты (Windows первым), отключение IPv6, split tunnel, kill switch на реальной ОС | клиентских приложений нет; на Windows-хосте GUI из агента не запускается | цикл E, спайк S4 (ADR-008) |
| DNS: локальный recursor unbound, отсутствие утечек DNS, наблюдение по SNI | спайк S2 не запускался | цикл A-3, спайк S2 (ADR-005) |
| Восстановление denylist после отказа Redis (окно, в котором отозванный access живёт до истечения TTL) | сценарий не проигрывался; в A-1 проверен только fail-open на уровне unit-теста | спайк S5 (ADR-003) |
| Чистота журнала при отказе Redis: предупреждение лимитера кладёт ключ бакета, в котором есть IP клиента | ветка отказа Redis в интеграционном прогоне не играется, а unit-тест журнала не проверяет | спайк S5 (ADR-003) |
| Платежи, продление подписки после оплаты, возврат средств | провайдера нет, sandbox не подключался | цикл B |
| Подтверждение email, восстановление доступа | письмо не отправлялось ни разу | цикл D |
| Панель администратора, роли и аудит-лог в UI | API админ-контура есть в A-2, интерфейса и управления ролями нет | цикл C/D |
| Нагрузочные характеристики: rps, латентность под нагрузкой, размер пула при N узлов | замеры не делались; заявлять числа нечем | цикл C (метрики) + отдельный замер |
| Бэкапы и восстановление PostgreSQL/Redis, раскатка миграций на продакшен-базе | такого прогона не было; локально проверены только up/down в контейнере | цикл C (runbook) |
| Сканирование зависимостей и SBOM в CI, подпись образов | CI нет до A-3 | цикл A-3 |
| TLS-терминация и передача реального IP балансировщиком (X-Forwarded-For намеренно не доверяется — задача 18) | конфигурация фронта не существует | цикл A-3 |
| Полное совпадение контракта со всеми состояниями кода: сверяются ответы маршрутов, до которых дотягиваются матрица и контракт-тест; `/debug/health`, 429 и 500 здесь не проверяются | живой 500 нельзя вызвать, не подменив код, а 429 проверяется в задаче 18 | фоллаут-тесты |

Ни одна строка «Проверено» не ссылается на механизм, которого нет в коде: единственное
доказательство — тест или команда, названные в строке.
