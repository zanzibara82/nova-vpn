CREATE TYPE subscription_status AS ENUM ('active', 'canceled', 'expired');
CREATE TYPE subscription_source AS ENUM ('manual', 'trial', 'billing');
CREATE TYPE health_status AS ENUM ('ok', 'stale', 'error');
CREATE TYPE event_type AS ENUM ('profile_issued', 'profile_revoked', 'profile_expired',
                               'peer_applied', 'peer_removed', 'handshake_observed',
                               'handshake_failed', 'node_stale', 'connection_error');
CREATE TYPE audit_action AS ENUM ('server_created', 'server_updated', 'node_token_revoked',
                                 'node_enrolled', 'user_locked', 'user_unlocked',
                                 'profile_revoked_now', 'server_drained', 'admin_created');

CREATE TABLE subscription_plans (
    id                  uuid PRIMARY KEY,
    slug                text NOT NULL UNIQUE,
    device_limit        integer NOT NULL CONSTRAINT plans_device_limit CHECK (device_limit > 0),
    -- Набор серверов планом; в A — 'all'.
    server_selector     text NOT NULL DEFAULT 'all',
    -- NULL = безлимит.
    traffic_quota_bytes bigint CHECK (traffic_quota_bytes IS NULL OR traffic_quota_bytes > 0),
    trial_days          integer NOT NULL DEFAULT 0 CHECK (trial_days BETWEEN 0 AND 365),
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE subscriptions (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id    uuid NOT NULL REFERENCES subscription_plans(id),
    status     subscription_status NOT NULL DEFAULT 'active',
    starts_at  timestamptz NOT NULL DEFAULT now(),
    ends_at    timestamptz,
    source     subscription_source NOT NULL DEFAULT 'manual',
    CONSTRAINT subscriptions_window CHECK (ends_at IS NULL OR ends_at > starts_at)
);
CREATE INDEX subscriptions_active ON subscriptions (user_id, plan_id) WHERE status = 'active';

CREATE TABLE server_health (
    server_id              uuid PRIMARY KEY REFERENCES vpn_servers(id) ON DELETE CASCADE,
    observed_at            timestamptz NOT NULL,
    peers_configured       integer NOT NULL DEFAULT 0 CHECK (peers_configured >= 0),
    peers_handshaked       integer NOT NULL DEFAULT 0 CHECK (peers_handshaked >= 0),
    interface_rx_bytes     bigint  NOT NULL DEFAULT 0 CHECK (interface_rx_bytes >= 0),
    interface_tx_bytes     bigint  NOT NULL DEFAULT 0 CHECK (interface_tx_bytes >= 0),
    load1                  numeric(6,3),
    cpu_pct                numeric(5,2) CHECK (cpu_pct IS NULL OR (cpu_pct >= 0 AND cpu_pct <= 100)),
    applied_config_version bigint  NOT NULL,
    status                 health_status NOT NULL DEFAULT 'ok'
);

CREATE TABLE connection_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    uuid,
    device_id  uuid,
    server_id  uuid REFERENCES vpn_servers(id) ON DELETE SET NULL,
    event      event_type NOT NULL,
    -- Только коды ошибок и версии. Никакого содержимого трафика (ТЗ §9, §11).
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX connection_events_created ON connection_events (created_at);
CREATE INDEX connection_events_user ON connection_events (user_id, created_at);

-- Единственный персистентный след объёмов: агрегат на устройство-сутки (ADR-006).
CREATE TABLE device_day_traffic (
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    day       date NOT NULL,
    rx_bytes  bigint NOT NULL DEFAULT 0 CHECK (rx_bytes >= 0),
    tx_bytes  bigint NOT NULL DEFAULT 0 CHECK (tx_bytes >= 0),
    PRIMARY KEY (user_id, device_id, day)
);

CREATE TABLE admin_users (
    id            uuid PRIMARY KEY,
    email         citext NOT NULL UNIQUE,
    password_hash text   NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT admin_hash_shape CHECK (password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$')
);

CREATE TABLE admin_audit_logs (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    admin_id    uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    action      audit_action NOT NULL,
    target_type text NOT NULL,
    target_id   text NOT NULL,
    -- Причина обязательна: ТЗ §9 «действия администратора с указанием причины».
    reason      text NOT NULL CONSTRAINT admin_audit_reason CHECK (char_length(reason) BETWEEN 3 AND 500),
    request_id  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX admin_audit_time ON admin_audit_logs (created_at DESC);

-- Добавлено планом: без этой таблицы Idempotency-Key (§5.2) негде хранить.
CREATE TABLE idempotency_keys (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    route           text NOT NULL,
    idem_key        text NOT NULL,
    request_hash    bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_status integer,
    response_body   jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    UNIQUE (user_id, route, idem_key)
);

-- Добавлено планом: одноразовый bootstrap-токен для enroll (§4.1).
CREATE TABLE bootstrap_tokens (
    id         uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    server_id  uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    created_by uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    CONSTRAINT bootstrap_window CHECK (expires_at > created_at)
);

-- Один план на цикл A: internal-default. Это данные, а не заглушка: A не продаёт тарифы (D).
INSERT INTO subscription_plans (id, slug, device_limit, server_selector, traffic_quota_bytes, trial_days)
VALUES ('00000000-0000-4000-8000-000000000a01', 'internal-default', 3, 'all', NULL, 0);
