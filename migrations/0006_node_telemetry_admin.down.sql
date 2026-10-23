-- Postgres не умеет вычёркивать значение из enum, поэтому enum пересобирается.
-- USING-каст падёт (22P02), если в аудите уже есть действие, которого в прежней
-- схеме не существовало: тихая потеря записей аудита хуже ошибки отката.

ALTER TABLE server_health DROP COLUMN IF EXISTS agent_uptime_sec;
ALTER TABLE server_health DROP COLUMN IF EXISTS agent_version;

CREATE TYPE audit_action_old AS ENUM ('server_created', 'server_updated', 'node_token_revoked',
                                      'node_enrolled', 'user_locked', 'user_unlocked',
                                      'profile_revoked_now', 'server_drained', 'admin_created');

ALTER TABLE admin_audit_logs
    ALTER COLUMN action TYPE audit_action_old USING action::text::audit_action_old;

DROP TYPE audit_action;
ALTER TYPE audit_action_old RENAME TO audit_action;
