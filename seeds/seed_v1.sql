INSERT INTO users (id, email, password_hash, display_name, created_at, updated_at)
SELECT
    gen_random_uuid(),
    'user' || i || '@example.com',
    md5(i::text || '_pwd_salt'),
    'User ' || i,
    now() - (random() * interval '365 days'),
    now()
FROM generate_series(1, :seed_count * 5) AS i
ON CONFLICT (email) DO NOTHING;

INSERT INTO devices (id, user_id, name, fingerprint, last_seen_at, created_at)
SELECT
    gen_random_uuid(),
    u.id,
    CASE (row_number() OVER (ORDER BY u.id) % 3)
        WHEN 0 THEN 'MacBook Pro'
        WHEN 1 THEN 'Windows Desktop'
        ELSE 'Linux Laptop'
    END,
    md5(u.id::text || '_fp'),
    now() - (random() * interval '30 days'),
    now() - (random() * interval '365 days')
FROM (SELECT id FROM users ORDER BY created_at LIMIT :seed_count * 3) u
WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.id);

INSERT INTO api_keys (id, user_id, key_hash, label, created_at)
SELECT
    gen_random_uuid(),
    u.id,
    md5(u.id::text || '_apikey'),
    'Default API Key',
    now() - (random() * interval '180 days')
FROM (SELECT id FROM users ORDER BY created_at LIMIT :seed_count * 2) u
WHERE NOT EXISTS (SELECT 1 FROM api_keys k WHERE k.user_id = u.id);
