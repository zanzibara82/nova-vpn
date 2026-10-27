-- Цикл A-2: значения аудита для управления узлами и серверами плюс поля heartbeat'а.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'bootstrap_token_issued';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'bootstrap_token_revoked';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'server_deleted';

-- §4.1: heartbeat приносит версию агента и uptime. Без этих колонок принятому
-- сообщению некуда ложиться, а «версия агента» — то, по чему оператор понимает,
-- какой код крутится на узле (ТЗ §15).
ALTER TABLE server_health
    ADD COLUMN agent_version    text   CHECK (agent_version    IS NULL OR char_length(agent_version) BETWEEN 1 AND 64),
    ADD COLUMN agent_uptime_sec bigint CHECK (agent_uptime_sec IS NULL OR agent_uptime_sec >= 0);
