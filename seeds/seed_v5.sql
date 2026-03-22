INSERT INTO link_terminations (id, shared_link_id, reason_id, terminated_by, notes, terminated_at)
SELECT
    gen_random_uuid(),
    sl.id,
    rr.id,
    NULL,
    'Automatically terminated',
    now() - (random() * interval '14 days')
FROM
    (SELECT id FROM shared_links WHERE status = 'terminated') sl
    CROSS JOIN (SELECT id FROM revocation_reasons WHERE code = 'ttl_expired' LIMIT 1) rr
WHERE NOT EXISTS (
    SELECT 1 FROM link_terminations lt WHERE lt.shared_link_id = sl.id
);

INSERT INTO proxy_access_logs (
    guest_session_id, shared_link_id, target_url, http_method,
    response_status, bytes_transferred, response_time_ms, requested_at
)
SELECT
    gs.id,
    gs.shared_link_id,
    'https://example.com/path/' || floor(random() * 100)::text,
    (ARRAY['GET','GET','GET','POST','PUT'])[floor(random() * 5 + 1)::int],
    (ARRAY[200, 200, 201, 404, 500])[floor(random() * 5 + 1)::int],
    floor(random() * 50000)::int,
    floor(random() * 500)::int,
    now() - (random() * interval '30 days')
FROM
    (SELECT id, shared_link_id FROM guest_sessions LIMIT :seed_count * 20) gs
    CROSS JOIN generate_series(1, 3)
WHERE NOT EXISTS (SELECT 1 FROM proxy_access_logs LIMIT 1);

INSERT INTO security_events (
    guest_session_id, shared_link_id, event_type,
    target_url, http_method, details, occurred_at
)
SELECT
    gs.id,
    gs.shared_link_id,
    (ARRAY['blacklist_violation', 'rate_limit_exceeded', 'traffic_limit_exceeded'])[floor(random() * 3 + 1)::int],
    '/settings',
    'GET',
    jsonb_build_object('blocked', true, 'pattern', '/settings'),
    now() - (random() * interval '30 days')
FROM (SELECT id, shared_link_id FROM guest_sessions LIMIT :seed_count * 5) gs
WHERE NOT EXISTS (SELECT 1 FROM security_events LIMIT 1);
