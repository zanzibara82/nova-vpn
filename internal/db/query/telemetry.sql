-- name: UpsertServerHealth :exec
-- Только тестовые данные; отчёты пишут MarkObservedHealth и MarkServerHealth, сохраняя независимые поля.
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

-- name: MarkObservedHealth :exec
-- Восстанавливает status только heartbeat(false), в том числе после sweeper.
INSERT INTO server_health (server_id, observed_at, peers_configured, peers_handshaked,
                           interface_rx_bytes, interface_tx_bytes, applied_config_version, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'ok')
ON CONFLICT (server_id) DO UPDATE SET
    observed_at = EXCLUDED.observed_at,
    peers_configured = EXCLUDED.peers_configured,
    peers_handshaked = EXCLUDED.peers_handshaked,
    interface_rx_bytes = EXCLUDED.interface_rx_bytes,
    interface_tx_bytes = EXCLUDED.interface_tx_bytes,
    applied_config_version = EXCLUDED.applied_config_version;

-- name: MarkServerHealth :exec
INSERT INTO server_health (server_id, observed_at, load1, cpu_pct,
                           applied_config_version, status, agent_version, agent_uptime_sec)
VALUES (sqlc.arg(server_id), sqlc.arg(observed_at), sqlc.arg(load1), sqlc.arg(cpu_pct),
        sqlc.arg(applied_config_version), sqlc.arg(status)::health_status,
        sqlc.arg(agent_version), sqlc.arg(agent_uptime_sec))
ON CONFLICT (server_id) DO UPDATE SET
    observed_at = EXCLUDED.observed_at,
    load1 = EXCLUDED.load1,
    cpu_pct = EXCLUDED.cpu_pct,
    applied_config_version = EXCLUDED.applied_config_version,
    status = EXCLUDED.status,
    agent_version = EXCLUDED.agent_version,
    agent_uptime_sec = EXCLUDED.agent_uptime_sec;

-- name: ObservedDevicesByPublicKeys :many
SELECT d.id, d.user_id, d.public_key FROM devices d
WHERE d.public_key = ANY(sqlc.arg(public_keys)::text[])
  AND EXISTS (SELECT 1 FROM vpn_profiles p WHERE p.device_id = d.id AND p.server_id = sqlc.arg(server_id));

-- name: RecordHandshake :exec
-- Блокировка сервера в вызывающей транзакции сериализует проверку и вставку события.
WITH inserted AS (
    INSERT INTO connection_events (user_id, device_id, server_id, event, detail)
    SELECT d.user_id, d.id, sqlc.arg(server_id)::uuid, 'handshake_observed',
           jsonb_build_object('handshake_at', sqlc.arg(handshake_at)::timestamptz,
                              'config_version', sqlc.arg(config_version)::bigint)
    FROM devices d
    WHERE d.id = sqlc.arg(device_id)
      AND NOT EXISTS (
          SELECT 1 FROM connection_events e
          WHERE e.server_id = sqlc.arg(server_id)::uuid AND e.device_id = d.id
            AND e.event = 'handshake_observed'
            AND (e.detail->>'handshake_at')::timestamptz >= sqlc.arg(handshake_at)::timestamptz
      )
    RETURNING device_id
)
UPDATE devices SET last_seen_at = GREATEST(last_seen_at, sqlc.arg(handshake_at)::timestamptz)
WHERE id IN (SELECT device_id FROM inserted);

-- name: ClaimTelemetryPacket :execrows
-- Квитанция живёт дольше неподтверждённого пакета в Redis (48 часов).
WITH expired AS (
    DELETE FROM telemetry_receipts
    WHERE server_id = $2 AND processed_at < now() - interval '49 hours'
)
INSERT INTO telemetry_receipts (id, server_id) VALUES ($1, $2)
ON CONFLICT (id) DO NOTHING;
