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

```sh
# Определить, какой контейнер сейчас является primary
docker compose --profile ha exec patroni1 \
  patronictl -c /tmp/patroni.yml list

# Убить primary через Pumba (SIGKILL, без graceful shutdown)
PRIMARY_CONTAINER=$(docker compose --profile ha ps -q patroni1)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gaiaadm/pumba kill --signal SIGKILL "$PRIMARY_CONTAINER"
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

Primary продолжает обслуживать чтение и запись (процесс Postgres жив, без кворума DCS он не останавливается). Однако обновить ключ лидера он не может, поэтому после истечения TTL переходит в режим "unlocked". Failover невозможен - нечего захватывать.

### Команды

```sh
# Остановить etcd
docker compose --profile ha stop etcd

# Через ~30 с проверить логи primary
docker compose --profile ha logs --tail=30 patroni1
# Ожидаемо: предупреждения "DCS is not accessible" или "failed to update leader key"

# Убедиться, что Postgres ещё доступен через HAProxy
docker compose --profile ha exec patroni1 \
  pg_isready -h haproxy -p 5432
```

### Наблюдение

1. Grafana: счётчик "etcd health failures" начинает расти.
2. "Cluster unlocked" краснеет после истечения TTL.
3. В логах Patroni повторяющиеся ошибки DCS, но без самодеградации.
4. HAProxy продолжает маршрутизировать на тот же primary - чтение и запись работают.

### Восстановление

```sh
docker compose --profile ha start etcd
# Patroni переподключается, обновляет ключ лидера, "Cluster unlocked" зеленеет
```

### Анализ

Patroni предпочитает доступность строгой консистентности при недоступном DCS. Primary не уступает роль, пока не превышен `master_start_timeout` или не задействован `failsafe_mode`. Это означает, что запись продолжается, но кластер не может избрать нового лидера в окне отказа. После восстановления etcd Patroni синхронизирует блокировку лидера без перезапуска Postgres.

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
