INSERT INTO target_sites (id, base_domain, name, base_url, created_at)
SELECT gen_random_uuid(), t.domain, t.name, t.url, now()
FROM (VALUES
    ('github.com',   'GitHub',     'https://github.com'),
    ('gitlab.com',   'GitLab',     'https://gitlab.com'),
    ('reddit.com',   'Reddit',     'https://reddit.com'),
    ('twitter.com',  'Twitter/X',  'https://twitter.com'),
    ('linkedin.com', 'LinkedIn',   'https://linkedin.com')
) AS t(domain, name, url)
WHERE NOT EXISTS (SELECT 1 FROM target_sites ts WHERE ts.base_domain = t.domain);

INSERT INTO original_sessions (id, user_id, target_site_id, status, label, imported_at)
SELECT
    gen_random_uuid(),
    u.id,
    ts.id,
    'active',
    'Session on ' || ts.name,
    now() - (random() * interval '90 days')
FROM
    (SELECT id FROM users ORDER BY created_at LIMIT :seed_count * 2) u
    CROSS JOIN (SELECT id, name FROM target_sites LIMIT 3) ts
WHERE NOT EXISTS (
    SELECT 1 FROM original_sessions os
    WHERE os.user_id = u.id AND os.target_site_id = ts.id
);

INSERT INTO session_cookies (id, original_session_id, name, value_encrypted, domain, path)
SELECT
    gen_random_uuid(),
    os.id,
    'session_id',
    md5(os.id::text || '_cookie'),
    ts.base_domain,
    '/'
FROM original_sessions os
JOIN target_sites ts ON ts.id = os.target_site_id
WHERE NOT EXISTS (
    SELECT 1 FROM session_cookies sc WHERE sc.original_session_id = os.id
);

INSERT INTO session_tokens (id, original_session_id, token_type, header_name, value_encrypted)
SELECT
    gen_random_uuid(),
    os.id,
    'bearer',
    'Authorization',
    'Bearer ' || md5(os.id::text || '_token')
FROM original_sessions os
WHERE random() > 0.4
  AND NOT EXISTS (
    SELECT 1 FROM session_tokens st WHERE st.original_session_id = os.id
);
