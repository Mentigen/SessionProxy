INSERT INTO access_policies (id, user_id, name, max_requests, max_bytes_transferred, max_ttl_seconds, max_violation_count)
SELECT
    gen_random_uuid(),
    u.id,
    'Default Policy',
    100 * :seed_count,
    1000000 * :seed_count,
    3600,
    3
FROM (SELECT id FROM users ORDER BY created_at LIMIT :seed_count) u
WHERE NOT EXISTS (
    SELECT 1 FROM access_policies ap WHERE ap.user_id = u.id
);

INSERT INTO shared_links (id, original_session_id, token, status, label, created_at, expires_at)
SELECT
    gen_random_uuid(),
    os.id,
    md5(os.id::text || '_share_' || row_number() OVER (ORDER BY os.id)),
    CASE WHEN random() > 0.2 THEN 'active' ELSE 'terminated' END,
    'Share link ' || row_number() OVER (ORDER BY os.id),
    now() - (random() * interval '30 days'),
    now() + (random() * interval '7 days')
FROM (SELECT id FROM original_sessions ORDER BY imported_at LIMIT :seed_count * 3) os
WHERE NOT EXISTS (
    SELECT 1 FROM shared_links sl WHERE sl.original_session_id = os.id
);

INSERT INTO blacklisted_endpoints (id, user_id, pattern, pattern_type, description)
SELECT
    gen_random_uuid(),
    u.id,
    ep.pattern,
    'prefix',
    ep.description
FROM
    (SELECT id FROM users ORDER BY created_at LIMIT :seed_count) u
    CROSS JOIN (VALUES
        ('/settings',       'Block account settings'),
        ('/billing',        'Block billing page'),
        ('/account/delete', 'Block account deletion')
    ) AS ep(pattern, description)
WHERE NOT EXISTS (
    SELECT 1 FROM blacklisted_endpoints be
    WHERE be.user_id = u.id AND be.pattern = ep.pattern
);

INSERT INTO endpoint_blocked_methods (endpoint_id, http_method)
SELECT
    be.id,
    m.method
FROM blacklisted_endpoints be
    CROSS JOIN (VALUES ('DELETE'), ('POST')) AS m(method)
WHERE be.pattern = '/account/delete'
ON CONFLICT DO NOTHING;

INSERT INTO site_endpoint_rules (target_site_id, endpoint_id)
SELECT DISTINCT os.target_site_id, be.id
FROM
    original_sessions os
    JOIN blacklisted_endpoints be ON be.user_id = os.user_id
WHERE NOT EXISTS (
    SELECT 1 FROM site_endpoint_rules ser
    WHERE ser.target_site_id = os.target_site_id AND ser.endpoint_id = be.id
)
LIMIT :seed_count * 5;

INSERT INTO link_endpoint_rules (link_id, endpoint_id)
SELECT DISTINCT sl.id, be.id
FROM
    shared_links sl
    JOIN original_sessions os ON os.id = sl.original_session_id
    JOIN blacklisted_endpoints be ON be.user_id = os.user_id
WHERE NOT EXISTS (
    SELECT 1 FROM link_endpoint_rules ler
    WHERE ler.link_id = sl.id AND ler.endpoint_id = be.id
)
LIMIT :seed_count * 5;

INSERT INTO link_policies (link_id, policy_id)
SELECT DISTINCT sl.id, ap.id
FROM
    shared_links sl
    JOIN original_sessions os ON os.id = sl.original_session_id
    JOIN access_policies ap ON ap.user_id = os.user_id
WHERE NOT EXISTS (
    SELECT 1 FROM link_policies lp WHERE lp.link_id = sl.id AND lp.policy_id = ap.id
);
