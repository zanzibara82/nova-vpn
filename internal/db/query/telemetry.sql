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
