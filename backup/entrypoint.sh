#!/bin/sh
set -e

mc alias set minio "${MINIO_ENDPOINT}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}"
mc mb --ignore-existing "minio/${BUCKET_BACKUP_NAME}"
mc anonymous set none "minio/${BUCKET_BACKUP_NAME}"

printf '%s /backup/backup.sh >> /var/log/backup.log 2>&1\n' "${BACKUP_INTERVAL}" \
    > /var/spool/cron/crontabs/root

/backup/backup.sh

crond -b -l 8

exec python3 /backup/metrics.py
