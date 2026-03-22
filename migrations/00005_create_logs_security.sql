-- +goose Up
CREATE TABLE proxy_access_logs (
    id               bigserial     PRIMARY KEY,
    guest_session_id uuid          REFERENCES guest_sessions(id) ON DELETE SET NULL,
    shared_link_id   uuid          NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    target_url       varchar(2048) NOT NULL,
    http_method      varchar(10)   NOT NULL,
    response_status  int,
    bytes_transferred int,
    response_time_ms  int,
    requested_at     timestamptz   NOT NULL DEFAULT now()
);

CREATE TABLE revocation_reasons (
    id          serial      PRIMARY KEY,
    code        varchar(50) UNIQUE NOT NULL,
    description text
);

INSERT INTO revocation_reasons (code, description) VALUES
    ('ttl_expired',     'Link TTL has expired'),
    ('request_limit',   'Request count limit reached'),
    ('traffic_limit',   'Traffic volume limit reached'),
    ('violation_limit', 'Maximum violation count reached'),
    ('manual',          'Manually terminated by owner');

CREATE TABLE link_terminations (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    shared_link_id uuid        NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    reason_id      int         NOT NULL REFERENCES revocation_reasons(id),
    terminated_by  uuid        REFERENCES users(id) ON DELETE SET NULL,
    notes          text,
    terminated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE security_events (
    id               bigserial   PRIMARY KEY,
    guest_session_id uuid        REFERENCES guest_sessions(id) ON DELETE SET NULL,
    shared_link_id   uuid        NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    event_type       varchar(50) NOT NULL,
    target_url       varchar(2048),
    http_method      varchar(10),
    details          jsonb,
    occurred_at      timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS link_terminations;
DROP TABLE IF EXISTS revocation_reasons;
DROP TABLE IF EXISTS proxy_access_logs;
