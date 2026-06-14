# BI-конвейер: proxy_access_logs

CDC-конвейер: PostgreSQL (Patroni) -> Debezium -> Kafka -> ClickHouse -> Metabase.

Таблица: `proxy_access_logs` - одна строка на каждый проксированный HTTP-запрос (bigserial PK, самая быстрорастущая).

---

## Предварительные требования

Профиль `bi` требует запущенного HA-кластера. Профиль `ha` должен быть поднят и миграции применены до старта `bi`.

### 1. Установить wal_level в logical (работающий кластер)

При свежем деплое `ha/patroni.yml` уже содержит `wal_level: logical`. Если кластер уже загружен с `wal_level: replica`, нужно обновить через Patroni:

```sh
# Обновить конфиг в DCS (живёт в etcd, не в файле после bootstrap)
# -p - сокращение для postgresql.parameters.*
docker compose --profile ha exec patroni1 \
  patronictl -c /tmp/patroni.yml edit-config --force -p 'wal_level=logical'

# Перезапустить оба узла, чтобы Postgres подхватил новый параметр
docker compose --profile ha restart patroni1 patroni2

# Проверить
docker compose --profile ha exec patroni1 \
  patronictl -c /tmp/patroni.yml show-config | grep wal_level
```

### 2. Применить миграции

Запустить `migrate-ha` для применения миграции `00008_bi_setup.sql`:

```sh
docker compose --profile ha run --rm migrate-ha
```

Создаёт:
- пользователя `debezium` с привилегией REPLICATION
- пользователя `metabase_ro` с SELECT на `proxy_access_logs`
- публикацию `pub_proxy_logs` для `proxy_access_logs`
- `REPLICA IDENTITY FULL` на `proxy_access_logs` (необходимо для полного захвата строк при UPDATE/DELETE)

---

## Запуск BI-стека

```sh
docker compose --profile ha --profile monitoring --profile bi up -d
```

Сервисы профиля `bi`:
- `kafka` (KRaft, без ZooKeeper) на внутреннем порту 9092
- `kafka-connect` (Debezium) на порту 8083
- `clickhouse` на порту 8123 (HTTP API; нативный порт 9000 только внутри сети)
- `metabase-db` (Postgres, метаданные Metabase)
- `metabase-plugin-init` (скачивает драйвер ClickHouse, одноразовый)
- `metabase` на порту 3030 (образ v0.50.14 с драйвером ClickHouse 1.50.7)
- `seeder-ha` (заполняет данными кластер Patroni)

---

## Регистрация коннектора Debezium

После того как Kafka Connect стал healthy (~60 с), зарегистрировать коннектор:

```sh
sh debezium/register.sh
```

Проверить статус:
```sh
curl -s http://localhost:8083/connectors/postgres-connector/status | python3 -m json.tool
```

Ожидаемо: `"state": "RUNNING"` для коннектора и задачи.

---

## Проверка потока данных

```sh
# Проверить, что в ClickHouse есть строки
docker compose --profile bi exec clickhouse \
  clickhouse-client -q "SELECT count() FROM bi.proxy_access_logs"
```

Если count равен 0, проверить Kafka-топик:
```sh
docker compose --profile bi exec kafka \
  kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic sessionproxy.public.proxy_access_logs \
  --from-beginning --max-messages 3
```

---

## Настройка Metabase

1. Открыть http://localhost:3030
2. Пройти мастер начальной настройки.
3. Добавить источник данных ClickHouse:
   - Database type: **ClickHouse**
   - Host: `clickhouse`, Port: `8123`
   - Database: `bi`, Username: `default`, Password: (пусто)
4. Создать три вопроса по таблице `proxy_access_logs`:

**Визуализация 1 - Запросы по дням (линейный график)**
- Метрика: Count of rows
- Разбивка: `requested_at` по дням
- Тип графика: Line

**Визуализация 2 - Распределение по HTTP-методам (столбчатая диаграмма)**
- Метрика: Count of rows
- Разбивка: `http_method`
- Тип графика: Bar

**Визуализация 3 - Среднее время ответа (число)**
- Метрика: Average of `response_time_ms`
- Тип графика: Scalar / Number

5. Добавить все три на новый дашборд "Proxy Access Logs".

---

## Известное ограничение: слот репликации после failover

Слоты логической репликации (`debezium_slot`) создаются на primary и не переносятся автоматически на новый primary после failover в Patroni (ограничение PostgreSQL 16; синхронизация слотов на standby требует PG17).

После failover Debezium выдаст ошибку "slot not found". Восстановление:

```sh
# Удалить коннектор
curl -s -X DELETE http://localhost:8083/connectors/postgres-connector

# Удалить зависший слот с того узла, где он остался
for node in patroni1 patroni2; do
  docker compose --profile ha exec $node \
    psql -U postgres -c "SELECT pg_drop_replication_slot('debezium_slot');" 2>/dev/null || true
done

# Перерегистрировать (создаст новый слот и снапшот)
sh debezium/register.sh
```
