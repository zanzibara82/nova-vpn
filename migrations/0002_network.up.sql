CREATE TYPE maintenance_status AS ENUM ('online', 'draining', 'maintenance', 'retired');
CREATE TYPE dns_mode AS ENUM ('local_recursor');
CREATE TYPE profile_status AS ENUM ('active', 'superseded', 'revoked', 'expired');
CREATE TYPE peer_state AS ENUM ('active', 'rotating_old_key');

CREATE TABLE server_locations (
    id           uuid PRIMARY KEY,
    country_code text NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
    city         text NOT NULL CHECK (char_length(city) BETWEEN 1 AND 64),
    lat          numeric(9,6) NOT NULL CHECK (lat BETWEEN -90 AND 90),
    lon          numeric(9,6) NOT NULL CHECK (lon BETWEEN -180 AND 180),
    timezone     text   NOT NULL,
    UNIQUE (country_code, city, lat, lon)
);

CREATE TABLE vpn_servers (
    id                 uuid PRIMARY KEY,
    location_id        uuid NOT NULL REFERENCES server_locations(id),
    name               text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 64),
    advertised_host    text NOT NULL,
    listen_port        integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    public_key         text  NOT NULL UNIQUE CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    address_pool_v4    cidr  NOT NULL,
    mtu                integer NOT NULL DEFAULT 1420 CHECK (mtu BETWEEN 1280 AND 1420),
    dns_mode           dns_mode NOT NULL DEFAULT 'local_recursor',
    keepalive_sec      integer NOT NULL DEFAULT 25 CHECK (keepalive_sec BETWEEN 5 AND 120),
    config_version     bigint  NOT NULL DEFAULT 0 CHECK (config_version >= 0),
    -- Узел появляется в maintenance и уходит в online только после первого heartbeat:
    -- «зарегистрирован» ≠ «работает».
    maintenance_status maintenance_status NOT NULL DEFAULT 'maintenance',
    provider           text NOT NULL,
    region             text,
    -- Заявленная пропускная способность, не измеренная (ADR-006). NULL — «не заявлена».
    capacity_mbps      integer CHECK (capacity_mbps IS NULL OR capacity_mbps > 0),
    CONSTRAINT servers_host_shape CHECK (advertised_host ~ '^[A-Za-z0-9.-]{1,253}$')
);

CREATE TABLE node_credentials (
    id           uuid PRIMARY KEY,
    server_id    uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    -- sha256 от высокоэнтропийного секрета. Приватного ключа узла в БД нет и не будет.
    token_hash   bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    issued_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz,
    -- Ротация токена узлом: новый активен, предок отзывается одним запросом.
    rotated_from uuid REFERENCES node_credentials(id) ON DELETE SET NULL
);
CREATE INDEX node_cred_live ON node_credentials (server_id) WHERE revoked_at IS NULL;

CREATE TABLE vpn_profiles (
    id                   uuid PRIMARY KEY,
    device_id            uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    server_id            uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    address_v4           inet NOT NULL,
    status               profile_status NOT NULL DEFAULT 'active',
    issued_at            timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    -- Ротация ключа: предок живёт в overlap-окне (спецификация §7.3).
    overlap_valid_until  timestamptz,
    revoked_at           timestamptz,
    rotate_from          uuid REFERENCES vpn_profiles(id) ON DELETE SET NULL,
    -- Состояние пиера в desired set; отдельное от статуса профиля, потому что
    -- 'superseded' внутри overlap всё ещё отдаётся узлу.
    peer_state           peer_state NOT NULL DEFAULT 'active',
    CONSTRAINT profiles_window CHECK (expires_at > issued_at),
    CONSTRAINT profiles_overlap CHECK (overlap_valid_until IS NULL OR overlap_valid_until > issued_at),
    CONSTRAINT profiles_revoked_at CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
    CONSTRAINT profiles_peer_state CHECK (peer_state <> 'rotating_old_key'
                                          OR overlap_valid_until IS NOT NULL)
);
-- Двойная выдача невозможна на уровне БД, а не в коде (спецификация §6).
CREATE UNIQUE INDEX profiles_one_active_per_device_server
    ON vpn_profiles (device_id, server_id) WHERE status = 'active';

CREATE TABLE tunnel_addresses (
    server_id    uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    address      inet NOT NULL,
    -- Первичный ключ — пара (сервер, адрес), а не адрес: пулы разных серверов могут
    -- совпадать, и один и тот же адрес в двух пулах — норма (спецификация §6).
    -- Назначение хранится здесь, чтобы аллокация шла под блокировкой строки сервера:
    -- коллизия адреса невозможна конструктивно (спецификация §6).
    allocated_to uuid REFERENCES vpn_profiles(id) ON DELETE SET NULL,
    -- Освобождается не сразу, а по истечении окна переиспользования (§7.2).
    released_at  timestamptz,
    reusable_at  timestamptz,
    PRIMARY KEY (server_id, address),
    CONSTRAINT addresses_window CHECK (released_at IS NULL OR reusable_at IS NULL
                                       OR reusable_at >= released_at)
);
CREATE INDEX addresses_free ON tunnel_addresses (server_id) WHERE allocated_to IS NULL;
