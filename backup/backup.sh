#!/bin/sh
set -e

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_FILE="/tmp/backup_${TIMESTAMP}.sql.gz"

pg_dump "${DATABASE_URL}" | gzip > "${BACKUP_FILE}"
SIZE=$(stat -c%s "${BACKUP_FILE}")

mc cp "${BACKUP_FILE}" "minio/${BUCKET_BACKUP_NAME}/backup_${TIMESTAMP}.sql.gz"
rm "${BACKUP_FILE}"

printf '%s' "$(date -u +%s)" > /var/backup/last_timestamp
printf '%s' "${SIZE}"         > /var/backup/last_size

python3 << EOF
import subprocess, json

bucket = "${BUCKET_BACKUP_NAME}"
keep   = int("${BACKUP_RETENTION_COUNT:-7}")

result = subprocess.run(
    ["mc", "ls", "--json", f"minio/{bucket}/"],
    capture_output=True, text=True
)
files = sorted(
    obj["key"]
    for line in result.stdout.splitlines()
    if line.strip()
    for obj in [json.loads(line)]
    if obj.get("type") == "file"
)
for f in files[:max(0, len(files) - keep)]:
    subprocess.run(["mc", "rm", f"minio/{bucket}/{f}"])
EOF
