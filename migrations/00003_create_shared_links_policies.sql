-- +goose Up
CREATE TABLE shared_links (
    id                  uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    original_session_id uuid          NOT NULL REFERENCES original_sessions(id) ON DELETE CASCADE,
    token               varchar(255)  UNIQUE NOT NULL,
    status              varchar(20)   NOT NULL DEFAULT 'active',
    label               varchar(100),
    created_at          timestamptz   NOT NULL DEFAULT now(),
    expires_at          timestamptz
);

CREATE TABLE access_policies (
    id                  uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                varchar(100) NOT NULL,
    max_requests        int,
    max_bytes_transferred bigint,
    max_ttl_seconds     int,
    max_violation_count int          DEFAULT 3,
    created_at          timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE link_policies (
    link_id   uuid NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    policy_id uuid NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (link_id, policy_id)
);

CREATE TABLE blacklisted_endpoints (
    id           uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pattern      varchar(1024) NOT NULL,
    pattern_type varchar(20)   NOT NULL DEFAULT 'prefix',
    description  text,
    created_at   timestamptz   NOT NULL DEFAULT now()
);

CREATE TABLE endpoint_blocked_methods (
    endpoint_id uuid        NOT NULL REFERENCES blacklisted_endpoints(id) ON DELETE CASCADE,
    http_method varchar(10) NOT NULL,
    PRIMARY KEY (endpoint_id, http_method)
);

CREATE TABLE site_endpoint_rules (
    target_site_id uuid NOT NULL REFERENCES target_sites(id) ON DELETE CASCADE,
    endpoint_id    uuid NOT NULL REFERENCES blacklisted_endpoints(id) ON DELETE CASCADE,
    PRIMARY KEY (target_site_id, endpoint_id)
);

CREATE TABLE link_endpoint_rules (
    link_id     uuid NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL REFERENCES blacklisted_endpoints(id) ON DELETE CASCADE,
    PRIMARY KEY (link_id, endpoint_id)
);

-- +goose Down
DROP TABLE IF EXISTS link_endpoint_rules;
DROP TABLE IF EXISTS site_endpoint_rules;
DROP TABLE IF EXISTS endpoint_blocked_methods;
DROP TABLE IF EXISTS blacklisted_endpoints;
DROP TABLE IF EXISTS link_policies;
DROP TABLE IF EXISTS access_policies;
DROP TABLE IF EXISTS shared_links;
