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
UPDATE vpn_profiles p
   SET status = 'revoked', revoked_at = now()
  FROM devices d
 WHERE p.id IN (SELECT id FROM vpn_profiles
                 WHERE device_id = ANY($1::uuid[]) AND status IN ('active','superseded'))
   AND p.device_id = d.id
 RETURNING p.id, p.server_id, p.device_id, d.user_id;
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

-- name: ProfileByID :one
-- Нужен после отзыва: RevokeProfile возвращает четыре колонки, а выдаче обязано
-- верить прочитанному состоянию, а не предположению о том, каким стал профиль.
-- Правка существующего запроса вместо этого изменила бы контракт задачи 1, а он
-- проверен её тестом.
SELECT id, device_id, server_id, address_v4, status, issued_at, expires_at,
       overlap_valid_until, revoked_at, rotate_from, peer_state
FROM vpn_profiles WHERE id = $1;
