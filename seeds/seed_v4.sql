INSERT INTO guests (id, ip_address, user_agent, browser_fingerprint, first_seen_at, last_seen_at)
SELECT
    gen_random_uuid(),
    '192.168.' || (i / 256) || '.' || (i % 256),
    'Mozilla/5.0 (SessionProxy Guest/' || i || ') AppleWebKit/537.36',
    md5(i::text || '_guest_fp'),
    now() - (random() * interval '90 days'),
    now() - (random() * interval '7 days')
FROM generate_series(1, :seed_count * 3) AS i
WHERE NOT EXISTS (SELECT 1 FROM guests LIMIT 1);

INSERT INTO guest_sessions (id, shared_link_id, guest_id, status, started_at, last_request_at)
SELECT
    gen_random_uuid(),
    sl.id,
    g.id,
    CASE WHEN random() > 0.3 THEN 'active' ELSE 'terminated' END,
    now() - (random() * interval '30 days'),
    now() - (random() * interval '7 days')
FROM
    (SELECT id FROM shared_links WHERE status = 'active' LIMIT :seed_count * 2) sl
    CROSS JOIN (SELECT id FROM guests ORDER BY random() LIMIT 3) g
WHERE NOT EXISTS (
    SELECT 1 FROM guest_sessions gs
    WHERE gs.shared_link_id = sl.id AND gs.guest_id = g.id
);

INSERT INTO usage_counters (id, shared_link_id, request_count, bytes_transferred, violation_count, updated_at)
SELECT
    gen_random_uuid(),
    sl.id,
    floor(random() * 100 * :seed_count)::int,
    floor(random() * 1000000 * :seed_count)::bigint,
    floor(random() * 5)::int,
    now() - (random() * interval '7 days')
FROM shared_links sl
WHERE NOT EXISTS (
    SELECT 1 FROM usage_counters uc WHERE uc.shared_link_id = sl.id
);
