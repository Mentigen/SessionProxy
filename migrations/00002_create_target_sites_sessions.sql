-- +goose Up
CREATE TABLE target_sites (
    id          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    base_domain varchar(255)  NOT NULL,
    name        varchar(100)  NOT NULL,
    base_url    varchar(2048) NOT NULL,
    created_at  timestamptz   NOT NULL DEFAULT now()
);

CREATE TABLE original_sessions (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_site_id uuid        NOT NULL REFERENCES target_sites(id) ON DELETE RESTRICT,
    device_id      uuid        REFERENCES devices(id) ON DELETE SET NULL,
    status         varchar(20) NOT NULL DEFAULT 'active',
    label          varchar(100),
    imported_at    timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz
);

CREATE TABLE session_cookies (
    id                  uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    original_session_id uuid          NOT NULL REFERENCES original_sessions(id) ON DELETE CASCADE,
    name                varchar(255)  NOT NULL,
    value_encrypted     text          NOT NULL,
    domain              varchar(255),
    path                varchar(1024) NOT NULL DEFAULT '/',
    secure              boolean       NOT NULL DEFAULT false,
    http_only           boolean       NOT NULL DEFAULT false,
    same_site           varchar(10),
    expires_at          timestamptz,
    created_at          timestamptz   NOT NULL DEFAULT now()
);

CREATE TABLE session_tokens (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    original_session_id uuid        NOT NULL REFERENCES original_sessions(id) ON DELETE CASCADE,
    token_type          varchar(50) NOT NULL,
    header_name         varchar(100),
    value_encrypted     text        NOT NULL,
    expires_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS session_tokens;
DROP TABLE IF EXISTS session_cookies;
DROP TABLE IF EXISTS original_sessions;
DROP TABLE IF EXISTS target_sites;
