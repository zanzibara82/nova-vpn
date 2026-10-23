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

-- name: RevokeDevices :exec
-- revoked_at IS NULL: повторный отзыв не должен двигать отметку времени — по ней судят,
-- когда доступ действительно перестал существовать.
UPDATE devices SET revoked_at = now()
 WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL;

-- name: RotationAncestorIDs :many
-- Цепочка ротации в обе стороны — два запроса, а не одно UNION-выражение: отзыв
-- потомка обязан закрыть overlap предка (§7.3), а отзыв родителя обязан погасить
-- потомка (для пользователя это то же устройство с новым ключом), и множества нужно
-- объединить. Вариант «один CTE, объединяющий up и down» PostgreSQL принимает, а
-- sqlc 1.27.0 — нет («column reference \"id\" is ambiguous»); вариант «два рекурсивных
-- рекурсивных ветвей в одном CTE» отклоняет сам сервер. Колонки в якоре квалифицированы явно — без
-- этого генератор теряется в тех же CTE.
WITH RECURSIVE up AS (
    SELECT devices.id, devices.rotation_of FROM devices WHERE devices.id = $1
  UNION ALL
    SELECT d.id, d.rotation_of FROM devices AS d JOIN up ON d.id = up.rotation_of
)
SELECT up.id FROM up;

-- name: RotationDescendantIDs :many
-- Нижний ход той же цепочки (см. комментарий у RotationAncestorIDs).
WITH RECURSIVE down AS (
    SELECT devices.id, devices.rotation_of FROM devices WHERE devices.id = $1
  UNION ALL
    SELECT d.id, d.rotation_of FROM devices AS d JOIN down ON d.rotation_of = down.id
)
SELECT down.id FROM down;
