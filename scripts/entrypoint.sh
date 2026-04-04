#!/bin/sh
set -e

echo "==> Recreating test database '${TEST_POSTGRES_DB}'..."
PGPASSWORD="${POSTGRES_PASSWORD}" psql \
    -h postgres \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    -c "DROP DATABASE IF EXISTS \"${TEST_POSTGRES_DB}\";" 2>/dev/null
PGPASSWORD="${POSTGRES_PASSWORD}" psql \
    -h postgres \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    -c "CREATE DATABASE \"${TEST_POSTGRES_DB}\";"

if [ -n "${POSTGRES_EXPORTER_USER}" ] && [ -n "${POSTGRES_EXPORTER_PASSWORD}" ]; then
    echo "==> Creating exporter user '${POSTGRES_EXPORTER_USER}'..."
    PGPASSWORD="${POSTGRES_PASSWORD}" psql \
        -h postgres \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        -c "CREATE USER ${POSTGRES_EXPORTER_USER} WITH PASSWORD '${POSTGRES_EXPORTER_PASSWORD}';" 2>/dev/null \
        || echo "    Exporter user already exists, skipping."
    PGPASSWORD="${POSTGRES_PASSWORD}" psql \
        -h postgres \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        -c "GRANT pg_monitor TO ${POSTGRES_EXPORTER_USER};" 2>/dev/null \
        || echo "    pg_monitor grant already set, skipping."
fi

echo "==> Running Seqwall staircase tests..."
seqwall staircase \
    --postgres-url    "${TEST_DATABASE_URL}" \
    --migrations-path /migrations \
    --upgrade         "/scripts/ci-up-one.sh" \
    --downgrade       "/scripts/ci-down-one.sh"
echo "==> Seqwall tests passed."

echo "==> Applying migrations to main database..."
if [ -n "${MIGRATION_VERSION}" ]; then
    goose -dir /migrations postgres "${DATABASE_URL}" up-to "${MIGRATION_VERSION}"
else
    goose -dir /migrations postgres "${DATABASE_URL}" up
fi
echo "==> Migrations applied successfully."
