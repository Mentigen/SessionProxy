FROM minio/mc:latest AS mc

FROM python:3.11-alpine3.19

RUN apk add --no-cache postgresql16-client

RUN mkdir -p /var/spool/cron/crontabs /var/backup

COPY --from=mc /usr/bin/mc /usr/local/bin/mc

COPY backup/ /backup/

RUN chmod +x /backup/entrypoint.sh /backup/backup.sh

ENTRYPOINT ["/backup/entrypoint.sh"]
