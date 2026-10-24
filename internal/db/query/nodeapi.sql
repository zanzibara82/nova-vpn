-- name: NodeCredentialByHash :one
SELECT id, server_id, issued_at, last_used_at, revoked_at,
       rotated_from
FROM node_credentials WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: TouchNodeCredential :exec
-- last_used_at — доказательство жизни токена: отзыв «неиспользуемого» без этого поля
-- был бы слепым.
UPDATE node_credentials SET last_used_at = now() WHERE id = $1;

-- name: InsertNodeCredential :one
INSERT INTO node_credentials (id, server_id, token_hash, rotated_from)
VALUES ($1, $2, $3, $4)
RETURNING id, server_id, issued_at;

-- name: RevokeNodeCredentialsForServer :execrows
UPDATE node_credentials SET revoked_at = now()
 WHERE server_id = $1 AND revoked_at IS NULL;

-- name: RevokeNodeCredential :execrows
-- Ротация гасит ровно предъявленный токен, а не «самый свежий токен узла»: у узла
-- может быть два процесса, и отзыв по server_id лишил бы доступа тот, который
-- ничего не просил.
UPDATE node_credentials SET revoked_at = now()
 WHERE id = $1 AND revoked_at IS NULL;

-- name: BootstrapTokenByHash :one
-- Здесь нет `revoked_at IS NULL` и `expires_at > now()`: различить «нет такого токена»,
-- «просрочен» и «израсходован» должен сервис, чтобы в журнал попали разные причины,
-- а наружу уйти один отказ (задача 11).
SELECT id, server_id, created_at, expires_at, used_at, revoked_at
FROM bootstrap_tokens WHERE token_hash = $1;

-- name: ConsumeBootstrapToken :one
-- Одноразовость на уровне БД: UPDATE с условием used_at IS NULL отдаёт строку ровно
-- одному из двух параллельных enroll.
UPDATE bootstrap_tokens SET used_at = now()
 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
 RETURNING server_id;

-- name: InsertBootstrapToken :one
-- Срок жизни считается в Go (now.Add(ttl)), а не в SQL: в sqlc.yaml нет override на
-- interval, и `now() + $5::interval` породил бы аргумент pgtype.Interval — тип, которого
-- рукописные слои этого плана не видят (см. проверку задачи 1 на grep по pgtype).
INSERT INTO bootstrap_tokens (id, token_hash, server_id, created_by, created_at, expires_at)
VALUES ($1, $2, $3, $4, now(), $5)
RETURNING id, server_id, created_at, expires_at;

-- name: RevokeBootstrapToken :one
UPDATE bootstrap_tokens SET revoked_at = now()
 WHERE id = $1 AND revoked_at IS NULL AND used_at IS NULL
 RETURNING id, server_id;

-- name: LiveBootstrapTokensOfServer :many
SELECT id, created_at, expires_at
FROM bootstrap_tokens
WHERE server_id = $1 AND revoked_at IS NULL AND used_at IS NULL
ORDER BY created_at;
