CREATE DATABASE IF NOT EXISTS bi;

CREATE TABLE IF NOT EXISTS bi.kafka_proxy_logs (payload String)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'kafka:9092',
    kafka_topic_list  = 'sessionproxy.public.proxy_access_logs',
    kafka_group_name  = 'clickhouse-bi',
    kafka_format      = 'JSONAsString';

CREATE TABLE IF NOT EXISTS bi.proxy_access_logs (
    id                Int64,
    http_method       LowCardinality(String),
    response_status   Int32,
    bytes_transferred Int32,
    response_time_ms  Int32,
    requested_at      DateTime('UTC')
) ENGINE = MergeTree()
ORDER BY (requested_at, id);

CREATE MATERIALIZED VIEW IF NOT EXISTS bi.mv_kafka_to_logs
TO bi.proxy_access_logs AS
SELECT
    JSONExtractInt(payload, 'after', 'id')                AS id,
    JSONExtractString(payload, 'after', 'http_method')    AS http_method,
    JSONExtractInt(payload, 'after', 'response_status')   AS response_status,
    JSONExtractInt(payload, 'after', 'bytes_transferred') AS bytes_transferred,
    JSONExtractInt(payload, 'after', 'response_time_ms')  AS response_time_ms,
    parseDateTimeBestEffort(
        JSONExtractString(payload, 'after', 'requested_at')
    )                                                     AS requested_at
FROM bi.kafka_proxy_logs
WHERE JSONExtractString(payload, 'after') != '';
