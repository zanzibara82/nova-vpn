-- name: InsertUser :one
INSERT INTO users (id, email, password_hash, display_name, locale)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, email, password_hash, display_name, status, locked_reason,
          email_verified_at, locale, created_at, updated_at;

-- name: UserByEmail :one
SELECT id, email, password_hash, display_name, status, locked_reason,
       email_verified_at, locale, created_at, updated_at
FROM users WHERE email = $1;

-- name: UserByID :one
SELECT id, email, password_hash, display_name, status, locked_reason,
       email_verified_at, locale, created_at, updated_at
FROM users WHERE id = $1;

-- name: LockUser :exec
UPDATE users
   SET status = 'locked', locked_reason = $2, updated_at = now()
 WHERE id = $1;

-- name: UnlockUser :exec
UPDATE users
   SET status = 'active', locked_reason = NULL, updated_at = now()
 WHERE id = $1;

-- name: InsertRefreshFamily :one
INSERT INTO refresh_token_families (id, user_id, current_token_hash, expires_at, ip)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: RefreshByID :one
-- Ротация ищет семью по идентификатору из токена, а не по хэшу: именно это даёт
-- детект переиспользования (секрет есть, но он не текущий → семья предательски отзывается).
SELECT id, user_id, current_token_hash, issued_at, last_used_at, expires_at,
       revoked_at, revoke_reason, ip
FROM refresh_token_families WHERE id = $1;

-- name: RotateRefresh :one
-- Условие по старому хэшу — это и детект переиспользования, и атомарность ротации:
-- второй запрос того же токена не найдёт семью как активную.
-- Именованные параметры обязательны: $2 и $3 стоят у одной колонки
-- (current_token_hash), и sqlc выдал бы два одинаковых имени поля. Через @name
-- имена задаёт автор запроса.
UPDATE refresh_token_families
   SET current_token_hash = @new_hash, last_used_at = now(),
       ip = COALESCE(@ip, ip)
 WHERE id = @id AND revoked_at IS NULL
   AND current_token_hash = @old_hash AND expires_at > now()
 RETURNING id, user_id;

-- name: RevokeRefreshFamily :exec
UPDATE refresh_token_families
   SET revoked_at = now(), revoke_reason = $2
 WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAllFamiliesForUser :exec
UPDATE refresh_token_families
   SET revoked_at = now(), revoke_reason = 'logout_all'
 WHERE user_id = $1 AND revoked_at IS NULL;
