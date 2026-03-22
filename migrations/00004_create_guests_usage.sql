-- +goose Up
CREATE TABLE guests (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address          varchar(45),
    user_agent          text,
    browser_fingerprint varchar(255),
    first_seen_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz
);

CREATE TABLE guest_sessions (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    shared_link_id  uuid        NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    guest_id        uuid        REFERENCES guests(id) ON DELETE SET NULL,
    status          varchar(20) NOT NULL DEFAULT 'active',
    started_at      timestamptz NOT NULL DEFAULT now(),
    last_request_at timestamptz,
    terminated_at   timestamptz
);

CREATE TABLE usage_counters (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    shared_link_id    uuid        UNIQUE NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    request_count     int         NOT NULL DEFAULT 0,
    bytes_transferred bigint      NOT NULL DEFAULT 0,
    violation_count   int         NOT NULL DEFAULT 0,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS usage_counters;
DROP TABLE IF EXISTS guest_sessions;
DROP TABLE IF EXISTS guests;
