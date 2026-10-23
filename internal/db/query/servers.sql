-- name: CatalogServers :many
-- Каталог: только выведенные в online. health берётся LEFT JOIN'ом — узел может ещё
-- ни разу не прислать heartbeat, и «неизвестно» здесь честнее, чем «ошибка».
-- status кастится в text, чтобы nullable-enum не превращался в NullHealthStatus:
-- слой каталога работает со строкой статуса.
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
