CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_status AS ENUM ('active', 'locked', 'deleted');
CREATE TYPE device_platform AS ENUM ('android', 'ios', 'windows', 'macos', 'linux', 'other');

CREATE TABLE users (
    id                uuid PRIMARY KEY,
    email             citext NOT NULL UNIQUE,
    password_hash     text   NOT NULL,
    display_name      text,
    status            user_status NOT NULL DEFAULT 'active',
    locked_reason     text,
    email_verified_at timestamptz,
    locale            text   NOT NULL DEFAULT 'en',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    -- Блокировка без причины невозможна: ТЗ §9 требует, чтобы админ указывал причину.
    CONSTRAINT users_lock_reason CHECK (status <> 'locked' OR locked_reason IS NOT NULL),
    -- Самописных форматов хэша быть не может: только argon2id в PHC-нотации.
    CONSTRAINT users_hash_shape  CHECK (password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$'),
    CONSTRAINT users_locale_shape CHECK (locale ~ '^[a-z]{2}(-[A-Z]{2})?$')
);

CREATE TABLE refresh_token_families (
    id                 uuid PRIMARY KEY,
    user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    current_token_hash bytea NOT NULL UNIQUE,
    issued_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz,
    revoke_reason      text,
    -- Только для анти-злоупотреблений; retention 90 дней (спецификация §6).
    ip                 inet,
    CONSTRAINT refresh_window  CHECK (expires_at > issued_at),
    CONSTRAINT refresh_reason  CHECK (revoked_at IS NULL OR revoke_reason IS NOT NULL)
);
CREATE INDEX refresh_family_user ON refresh_token_families (user_id) WHERE revoked_at IS NULL;

CREATE TABLE devices (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key   text NOT NULL,
    platform     device_platform NOT NULL,
    name         text NOT NULL,
    rotation_of  uuid REFERENCES devices(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    revoked_at   timestamptz,
    -- Форма ключа (44 символа base64, '=' в конце). Каноничность проверяется в Go:
    -- SQL не перекодирует base64, а неканонический ключ — это другой ключ.
    CONSTRAINT devices_key_shape CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    CONSTRAINT devices_name_len  CHECK (char_length(name) BETWEEN 1 AND 64)
);
CREATE UNIQUE INDEX devices_user_key ON devices (user_id, public_key);
CREATE INDEX devices_live ON devices (user_id) WHERE revoked_at IS NULL;
