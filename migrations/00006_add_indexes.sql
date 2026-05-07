-- +goose Up
CREATE INDEX idx_proxy_access_logs_link_time
    ON proxy_access_logs (shared_link_id, requested_at DESC);

CREATE INDEX idx_shared_links_active_by_session
    ON shared_links (original_session_id)
    WHERE status = 'active';

-- +goose Down
DROP INDEX IF EXISTS idx_shared_links_active_by_session;
DROP INDEX IF EXISTS idx_proxy_access_logs_link_time;
