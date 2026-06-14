-- +goose Up

-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'debezium') THEN
    CREATE USER debezium WITH REPLICATION LOGIN PASSWORD 'debezium_secret';
  END IF;
END $$;
-- +goose StatementEnd

GRANT SELECT ON proxy_access_logs TO debezium;

-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'metabase_ro') THEN
    CREATE USER metabase_ro WITH LOGIN PASSWORD 'metabase_secret';
  END IF;
END $$;
-- +goose StatementEnd

GRANT SELECT ON proxy_access_logs TO metabase_ro;

-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'pub_proxy_logs') THEN
    CREATE PUBLICATION pub_proxy_logs FOR TABLE proxy_access_logs;
  END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE proxy_access_logs REPLICA IDENTITY FULL;

-- +goose Down

DROP PUBLICATION IF EXISTS pub_proxy_logs;
ALTER TABLE proxy_access_logs REPLICA IDENTITY DEFAULT;
REVOKE SELECT ON proxy_access_logs FROM debezium;
REVOKE SELECT ON proxy_access_logs FROM metabase_ro;
