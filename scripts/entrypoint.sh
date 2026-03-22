#!/bin/sh
set -e

echo "==> Creating test database '${TEST_POSTGRES_DB}'..."
PGPASSWORD="${POSTGRES_PASSWORD}" psql \
    -h postgres \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    -c "CREATE DATABASE \"${TEST_POSTGRES_DB}\";" 2>/dev/null \
    || echo "    Test database already exists, skipping."

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
