-- +goose Up
--
-- In HA mode, migrate-ha applies every migration as the Patroni superuser
-- (postgres), so every table/sequence/materialized view created by
-- migrations 00001-00007 is owned by postgres, not by the application role
-- (sessionproxy). Owning the database (see ha/post_init.sh) does not grant
-- privileges on objects a different role created inside it - those need an
-- explicit GRANT. In the non-HA profile, `migrate` already runs as
-- sessionproxy, so sessionproxy is already the owner there.
--
-- The whole block is gated on "is sessionproxy already the owner of a
-- representative table (users)?" rather than just "does the role exist?".
-- This matters for goose's own down-up-down self-test (seqwall), which
-- diffs information_schema.role_table_grants before Up and after Down:
-- an explicit self-GRANT from an owner to itself is *not* a no-op at the
-- ACL level - it converts relacl from NULL (implicit owner privileges,
-- covering SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER, all
-- grantable) into an explicit array covering only the 4 privileges this
-- migration names, non-grantable - and a plain REVOKE afterwards does not
-- reliably restore the original NULL/implicit state. Skipping the block
-- entirely when sessionproxy already owns the tables (the non-HA profile)
-- avoids touching relacl at all there, which is what keeps Up and Down
-- byte-for-byte symmetric in both profiles.
--
-- mv_link_stats additionally needs its OWNER changed outright: REFRESH
-- MATERIALIZED VIEW CONCURRENTLY can only be run by the view's owner (or a
-- superuser), and the app (internal/repository/pgx StatsRepo) needs to run
-- it, not just read from it.

-- +goose StatementBegin
DO $$
DECLARE
  users_owner text;
BEGIN
  SELECT tableowner INTO users_owner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users';
  IF users_owner IS DISTINCT FROM 'sessionproxy' AND EXISTS (SELECT FROM pg_roles WHERE rolname = 'sessionproxy') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sessionproxy';
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sessionproxy';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sessionproxy';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO sessionproxy';
    EXECUTE 'ALTER MATERIALIZED VIEW mv_link_stats OWNER TO sessionproxy';
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
--
-- Mirrors Up's own gate exactly (same "is sessionproxy already the owner
-- of users?" check, which Up's statements never change) so the down step
-- runs the reverse statements in precisely the profile where Up ran
-- anything at all, and skips in the profile where Up was a no-op.
--
-- mv_link_stats' owner is not reverted: seqwall's MatViewDefinition
-- snapshot tracks only definition and population state, not ownership, so
-- there is nothing to keep symmetric there, and picking a "previous
-- owner" to restore would be guesswork that differs between profiles.

-- +goose StatementBegin
DO $$
DECLARE
  users_owner text;
BEGIN
  SELECT tableowner INTO users_owner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users';
  IF users_owner IS DISTINCT FROM 'sessionproxy' AND EXISTS (SELECT FROM pg_roles WHERE rolname = 'sessionproxy') THEN
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM sessionproxy';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM sessionproxy';
    EXECUTE 'REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM sessionproxy';
    EXECUTE 'REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM sessionproxy';
  END IF;
END $$;
-- +goose StatementEnd
