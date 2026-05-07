-- name: oltp_active_link_by_token
SELECT sl.id,
       sl.status,
       sl.label,
       sl.expires_at,
       sl.original_session_id
FROM shared_links sl
WHERE sl.token = 'abc123token'
  AND sl.status = 'active';

-- name: oltp_active_links_for_session
SELECT sl.id,
       sl.token,
       sl.label,
       sl.status,
       sl.created_at,
       sl.expires_at
FROM shared_links sl
WHERE sl.original_session_id = '00000000-0000-0000-0000-000000000001'::uuid
  AND sl.status = 'active'
ORDER BY sl.created_at DESC;

-- name: log_recent_requests_for_link
SELECT pal.id,
       pal.target_url,
       pal.http_method,
       pal.response_status,
       pal.bytes_transferred,
       pal.response_time_ms,
       pal.requested_at
FROM proxy_access_logs pal
WHERE pal.shared_link_id = '00000000-0000-0000-0000-000000000001'::uuid
ORDER BY pal.requested_at DESC
LIMIT 100;

-- name: log_error_requests_recent
SELECT pal.shared_link_id,
       pal.target_url,
       pal.http_method,
       pal.response_status,
       pal.bytes_transferred,
       pal.requested_at
FROM proxy_access_logs pal
WHERE pal.response_status >= 400
  AND pal.requested_at >= now() - interval '7 days'
ORDER BY pal.requested_at DESC
LIMIT 500;

-- name: olap_traffic_per_site_30d
SELECT ts.name AS site_name,
       ts.base_domain,
       COUNT(pal.id)                  AS total_requests,
       SUM(pal.bytes_transferred)     AS total_bytes,
       AVG(pal.response_time_ms)      AS avg_response_ms
FROM proxy_access_logs pal
JOIN shared_links sl      ON sl.id = pal.shared_link_id
JOIN original_sessions os ON os.id = sl.original_session_id
JOIN target_sites ts      ON ts.id = os.target_site_id
WHERE pal.requested_at >= now() - interval '30 days'
GROUP BY ts.id, ts.name, ts.base_domain
ORDER BY total_bytes DESC NULLS LAST;

-- name: olap_top_links_by_traffic_window
SELECT ts.name                                  AS site_name,
       sl.id                                    AS link_id,
       sl.label,
       uc.bytes_transferred,
       uc.request_count,
       RANK() OVER (
           PARTITION BY ts.id
           ORDER BY uc.bytes_transferred DESC
       )                                        AS traffic_rank
FROM usage_counters uc
JOIN shared_links sl      ON sl.id = uc.shared_link_id
JOIN original_sessions os ON os.id = sl.original_session_id
JOIN target_sites ts      ON ts.id = os.target_site_id
ORDER BY ts.name, traffic_rank;

-- name: join_owner_session_link_traffic
SELECT u.id                       AS user_id,
       u.email,
       COUNT(DISTINCT sl.id)      AS active_link_count,
       SUM(uc.bytes_transferred)  AS total_bytes,
       SUM(uc.request_count)      AS total_requests
FROM users u
JOIN original_sessions os ON os.user_id = u.id
JOIN shared_links sl      ON sl.original_session_id = os.id AND sl.status = 'active'
JOIN usage_counters uc    ON uc.shared_link_id = sl.id
GROUP BY u.id, u.email
ORDER BY total_bytes DESC NULLS LAST
LIMIT 20;
