#!/bin/sh
set -e
mkdir -p /var/lib/postgresql/data
chown -R postgres:postgres /var/lib/postgresql/data
envsubst '$PATRONI_NAME $POSTGRES_USER $POSTGRES_PASSWORD $POSTGRES_DB $REPLICATION_PASSWORD $PATRONI_SUPERUSER_PASSWORD' \
  < /etc/patroni.yml.tmpl > /tmp/patroni.yml
exec gosu postgres patroni /tmp/patroni.yml
