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
