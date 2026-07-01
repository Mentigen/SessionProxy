# Chaos-тестирование: сценарии отказа

Сценарии охватывают два типа отказов в HA-кластере: падение primary-узла и потеря DCS (etcd).

Перед запуском поднять стек HA + мониторинг:

```sh
docker compose --profile ha --profile monitoring up -d
```

Открыть Grafana: http://localhost:3000, дашборд "HA Cluster Health". Наблюдать во время каждого сценария.

---

## Сценарий 1 - Падение primary-узла (Pumba)

**Инструмент**: [Pumba](https://github.com/alexei-led/pumba) - инъекция отказов для Docker-контейнеров.

### Ожидаемое поведение

Patroni на выжившем узле обнаруживает потерю лидера после истечения `ttl=30s`, захватывает блокировку в DCS и повышает себя до primary. Общее окно недоступности - около 30-45 с.

### Команды

```fish
# Определить, какой контейнер сейчас является primary
hacluster

# Убить primary через Pumba (SIGKILL, без graceful shutdown)
# fish-синтаксис: set вместо VAR=$(...)
set PRIMARY_CONTAINER (docker compose --profile ha ps -q patroni1)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gaiaadm/pumba kill --signal SIGKILL $PRIMARY_CONTAINER

# Или через функцию hapumba (если добавлена в user-config.fish):
hapumba patroni1
```

### Наблюдение

1. Grafana, панель "Patroni role per node": `master - patroni1` падает до 0.
2. Примерно через 30 с `master - patroni2` поднимается до 1 (или наоборот, в зависимости от того, кто был primary).
3. Панель "Cluster unlocked" кратковременно краснеет в окне выборов.
4. HAProxy health check (`http://localhost:7000`) показывает один backend удалённым.

### Восстановление

```sh
# Поднять упавший узел обратно
docker compose --profile ha start patroni1
# patroni1 возвращается как replica, панель "Postgres running" возвращается к 2
```

### Анализ

Patroni использует etcd как DCS. При падении primary реплика опрашивает `/leader` в etcd и обнаруживает, что TTL истёк. Она захватывает ключ лидера и повышает локальный Postgres из standby до primary через `pg_ctl promote`. Полный цикл выборов ограничен `ttl` (30 с) + `loop_wait` (10 с). Наблюдаемое время простоя: 35-45 с в зависимости от момента отказа.

---

## Сценарий 2 - Потеря etcd

**Инструмент**: `docker compose stop` (отказ DCS - штатный сценарий лабы; инъекция на уровне сети потребовала бы `pumba netem` partition, но остановка etcd демонстрирует то же поведение Patroni).

### Ожидаемое поведение

Patroni логирует ошибки DCS. После истечения TTL=30s Patroni **останавливает Postgres** на primary - это намеренное поведение: без DCS невозможно подтвердить лидерство, и продолжать принимать запись опасно (split-brain). Failover невозможен - нового лидера выбирать не из чего. Система недоступна до восстановления etcd.

### Команды

```sh
# Остановить etcd
docker compose --profile ha stop etcd

# HAProxy сразу перестаёт видеть primary (Patroni возвращает 503 на /primary без DCS).
# Через ~30 с Patroni останавливает Postgres - pg_ctl stop. Логи:
docker compose --profile ha logs --tail=30 patroni1
# Ожидаемо: "DCS is not accessible", "failed to update leader key", "pg_ctl stop"

# После 30s оба пути недоступны:
# 1. psql через HAProxy - connection refused (HAProxy убрал бэкенды)
# 2. exec напрямую - "No such file or directory" (сокет не существует, Postgres не запущен)
docker compose --profile ha exec patroni1 \
  psql -U postgres -c "SELECT 1;"
# psql: error: ... /var/run/postgresql/.s.PGSQL.5432 ... No such file or directory
```

### Наблюдение

1. В логах Patroni: `DCS is not accessible`, `failed to update leader key`.
2. Через ~30s Patroni останавливает Postgres: `pg_ctl stop`.
3. HAProxy снимает бэкенд - `GET /primary` возвращает 503 (или не отвечает).
4. Grafana: "Postgres running" падает до 0, "etcd health failures" растёт.

### Восстановление

```sh
docker compose --profile ha start etcd
# Patroni переподключается, обновляет ключ лидера, "Cluster unlocked" зеленеет
```

### Анализ

Patroni без `failsafe_mode: true` предпочитает консистентность доступности. Не имея возможности подтвердить лидерство через DCS, primary останавливает Postgres - это предотвращает ситуацию split-brain, когда два узла могут начать принимать запись независимо. После восстановления etcd Patroni перезапускает Postgres и восстанавливает кластер.

---

## Панели дашборда

| Панель | Метрика | Что показывает при отказе |
|--------|---------|--------------------------|
| Primary node | `patroni_master` | Меняется на нового primary |
| Postgres running | `patroni_postgres_running` | Падает до 1 при смерти узла |
| Cluster unlocked | `patroni_cluster_unlocked` | Скачет до 1 в окне выборов |
| etcd leader | `etcd_server_is_leader` | Падает до 0 при остановке etcd |
| etcd health failures | `etcd_server_health_failures_total` | Растёт во время отказа etcd |
| Replication WAL position | `patroni_xlog_location` | Позиция WAL лидера (реплики сообщают 0) |
