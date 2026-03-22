-- +goose Up
CREATE TABLE users (
    id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    email         varchar(255) UNIQUE NOT NULL,
    password_hash varchar(255) NOT NULL,
    display_name  varchar(100),
    created_at    timestamptz  NOT NULL DEFAULT now(),
    updated_at    timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         varchar(100),
    fingerprint  varchar(255),
    last_seen_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id         uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id  uuid         REFERENCES devices(id) ON DELETE SET NULL,
    key_hash   varchar(255) NOT NULL,
    label      varchar(100),
    revoked_at timestamptz,
    expires_at timestamptz,
    created_at timestamptz  NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;
