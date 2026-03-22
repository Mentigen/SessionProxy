FROM golang:1.22-alpine AS tools

RUN apk add --no-cache git

RUN go install github.com/pressly/goose/v3/cmd/goose@v3.19.2
RUN go install github.com/realkarych/seqwall@latest

FROM alpine:3.19

RUN apk add --no-cache bash postgresql-client

COPY --from=tools /go/bin/goose   /usr/local/bin/goose
COPY --from=tools /go/bin/seqwall /usr/local/bin/seqwall

COPY migrations/ /migrations/
COPY scripts/    /scripts/

RUN chmod +x /scripts/ci-up-one.sh /scripts/ci-down-one.sh /scripts/entrypoint.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
