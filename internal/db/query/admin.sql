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
