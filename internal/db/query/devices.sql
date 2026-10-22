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
