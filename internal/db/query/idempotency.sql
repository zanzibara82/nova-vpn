-- name: ClaimIdempotencyKey :execrows
-- ON CONFLICT DO NOTHING вместо SELECT-then-INSERT: два одновременных повтора
-- одного ключа не должны оба дойти до бизнес-логики.
INSERT INTO idempotency_keys (id, user_id, route, idem_key, request_hash)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, route, idem_key) DO NOTHING;

-- name: LoadIdempotencyKey :one
SELECT id, user_id, route, idem_key, request_hash, response_status, response_body,
       created_at, completed_at
FROM idempotency_keys
WHERE user_id = $1 AND route = $2 AND idem_key = $3;

-- name: CompleteIdempotencyKey :exec
UPDATE idempotency_keys
   SET response_status = $4, response_body = $5, completed_at = now()
 WHERE user_id = $1 AND route = $2 AND idem_key = $3 AND completed_at IS NULL;

-- name: DeleteIdempotencyKey :exec
DELETE FROM idempotency_keys
 WHERE user_id = $1 AND route = $2 AND idem_key = $3 AND completed_at IS NULL;

-- name: PurgeExpiredIdempotencyKeys :exec
DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours';
