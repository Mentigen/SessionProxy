#!/bin/sh
set -e

if [ "${APP_ENV}" = "prod" ]; then
    echo "Seeding skipped: APP_ENV=prod"
    exit 0
fi

SEED_COUNT="${SEED_COUNT:-10}"

CURRENT_VERSION=$(psql "${DATABASE_URL}" -t -c \
    "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = true;" \
    2>/dev/null | tr -d ' \n')

if [ -z "${CURRENT_VERSION}" ] || [ "${CURRENT_VERSION}" -eq 0 ]; then
    echo "No migrations applied yet, skipping seeding."
    exit 0
fi

echo "Schema version: ${CURRENT_VERSION}. Applying seeds 1..${CURRENT_VERSION} with SEED_COUNT=${SEED_COUNT}..."

i=1
while [ "${i}" -le "${CURRENT_VERSION}" ]; do
    SEED_FILE="/seeds/seed_v${i}.sql"
    if [ -f "${SEED_FILE}" ]; then
        echo "  Applying ${SEED_FILE}..."
        psql "${DATABASE_URL}" -v "seed_count=${SEED_COUNT}" -f "${SEED_FILE}"
    fi
    i=$((i + 1))
done

echo "Seeding complete."
