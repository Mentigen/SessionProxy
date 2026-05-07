-- +goose Up
CREATE MATERIALIZED VIEW mv_link_stats AS
SELECT
    ts.id                                       AS target_site_id,
    ts.name                                     AS site_name,
    ts.base_domain,
    sl.id                                       AS shared_link_id,
    COUNT(pal.id)                               AS total_requests,
    COALESCE(SUM(pal.bytes_transferred), 0)     AS total_bytes,
    COALESCE(AVG(pal.response_time_ms), 0)      AS avg_response_ms,
    MIN(pal.requested_at)                       AS first_request_at,
    MAX(pal.requested_at)                       AS last_request_at
FROM target_sites ts
JOIN original_sessions os  ON os.target_site_id = ts.id
JOIN shared_links sl       ON sl.original_session_id = os.id
LEFT JOIN proxy_access_logs pal ON pal.shared_link_id = sl.id
GROUP BY ts.id, ts.name, ts.base_domain, sl.id;

CREATE UNIQUE INDEX uix_mv_link_stats
    ON mv_link_stats (target_site_id, shared_link_id);

-- +goose Down
DROP MATERIALIZED VIEW IF EXISTS mv_link_stats;
