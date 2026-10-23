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
