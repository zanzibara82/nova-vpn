-- name: LockUserForDeviceCount :exec
-- hashtextextended даёт bigint-ключ из uuid; lock держится до конца транзакции.
SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0));
