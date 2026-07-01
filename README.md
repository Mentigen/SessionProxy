# SessionProxy - временный безопасный шаринг веб-сессий через reverse proxy

## 1. Предметная область

SessionProxy - self-hosted утилита на Go, позволяющая владельцу аккаунта на любом веб-сайте временно делиться доступом к своей сессии через специальную прокси-ссылку, не раскрывая логин, пароль и реальные куки. Гость работает с сайтом «как будто залогинен» владельцем, но не видит настоящих кук/токенов, ограничен по времени, количеству запросов и трафику, не может попасть на чувствительные страницы (настройки, биллинг и т.п.), так как при попытке доступ автоматически истекает.

---

## 2. Функциональные требования

1. Система должна позволять владельцу импортировать сессию для произвольного HTTPS-сайта (cookies, при необходимости токены) и ассоциировать её с конкретным «целевым сайтом».
2. Система должна позволять создать одну или несколько «расшаренных ссылок» для этой сессии с параметрами: время жизни (TTL), лимит количества HTTP-запросов, лимит объёма переданных данных (трафика).
3. При переходе гостя по ссылке все его запросы должны идти на прокси-сервер, а не напрямую на целевой сайт, и получать подменённые заголовки/куки так, чтобы целевой сайт воспринимал их как запросы владельца.
4. Гость не должен иметь технической возможности увидеть реальные куки и токены владельца.
5. Система должна поддерживать возможность задания «чёрных списков» путей (endpoint blacklist) для каждой расшаренной ссылки (запрет на переходы к `/settings`, `/billing`, `/account/delete` и т.п.; возможность запрета отдельных HTTP-методов).
6. При нарушении правил (попытка доступа к запрещённому пути, превышение лимита запросов/трафика/времени) ссылка должна автоматически становиться недействительной (статус «terminated»), а гостю возвращаться соответствующая ошибка.
7. Система должна вести: журнал обращений к прокси (гость, ссылка, URL, метод, статус ответа, объём, время) и журнал событий безопасности (попытки в запрещённые зоны, превышение лимитов).
8. Система должна предоставлять владельцу API/интерфейс для просмотра активных и завершённых ссылок, базовой статистики использования и ручного досрочного отключения ссылок.

---

## 3. Бизнес-правила

1. Одна оригинальная сессия (`original_session`) может использоваться для создания нескольких расшаренных ссылок (`shared_links`), каждая с независимыми лимитами и сроком жизни.
2. Расшаренная ссылка не может существовать без привязки к конкретной оригинальной сессии и владельцу.
3. Одна расшаренная ссылка может иметь несколько активных гостевых сессий (`guest_sessions`) одновременно.
4. При первом запросе гостя создаётся запись `guest_session`, к которой привязываются все последующие `proxy_access_logs`.
5. Если запись в `usage_counters` превышает разрешённые значения (из `access_policies`), ссылка переводится в состояние «terminated», и все новые запросы по ней отклоняются.
6. Доступ к любому пути, попадающему под `blacklisted_endpoints`, логируется в `security_events`. После достижения порога нарушений (`max_violation_count` из `access_policies`) ссылка также переводится в «terminated».

---

## 4. Описание логической модели и нормализация (3НФ)

### Группа 1: Пользователи и устройства

- `users` - владельцы прокси-сервера.
- `devices` - устройства, с которых владелец импортирует сессии (ноутбук, ПК и т.п.). Связь: `devices.user_id → users.id` (N:1).
- `api_keys` - ключи доступа для браузерных расширений/CLI. Привязаны к пользователю и опционально к устройству. Связь: `api_keys.user_id → users.id`, `api_keys.device_id → devices.id`.

### Группа 2: Целевые сайты и сессии

- `target_sites` - описание сайтов, к которым предоставляется доступ.
- `original_sessions` - авторизационные сессии владельца для конкретного сайта. Связь: `original_sessions.user_id → users.id`, `original_sessions.target_site_id → target_sites.id`.
- `session_cookies` - нормализованное хранилище отдельных кук. Значение куки хранится в зашифрованном виде. Связь: `session_cookies.original_session_id → original_sessions.id`.
- `session_tokens` - хранилище для bearer-токенов и иных типов авторизационных данных. Связь: `session_tokens.original_session_id → original_sessions.id`.

### Группа 3: Расшаренные ссылки и политики доступа

- `shared_links` - расшаренные ссылки с уникальным токеном. Владелец определяется через `original_session_id`. Связь: `shared_links.original_session_id → original_sessions.id`.
- `access_policies` - шаблоны ограничений (`max_requests`, `max_bytes_transferred`, `max_ttl_seconds`, `max_violation_count`). Связь: `access_policies.user_id → users.id`.
- `link_policies` - таблица связи M:N между `shared_links` и `access_policies`. PK: `(link_id, policy_id)`.
- `blacklisted_endpoints` - запрещённые пути/шаблоны (regex или prefix), принадлежащие конкретному пользователю (`user_id`). Связь: `blacklisted_endpoints.user_id → users.id`.
- `endpoint_blocked_methods` - нормализованное хранилище блокируемых HTTP-методов для конкретного `blacklisted_endpoint`. PK: `(endpoint_id, http_method)`. Связь: `endpoint_blocked_methods.endpoint_id → blacklisted_endpoints.id`.
- `site_endpoint_rules` - привязка `blacklisted_endpoints` к конкретному целевому сайту (site-level блэклист). PK: `(target_site_id, endpoint_id)`.
- `link_endpoint_rules` - привязка `blacklisted_endpoints` к конкретной расшаренной ссылке (link-level блэклист). PK: `(link_id, endpoint_id)`.

### Группа 4: Гости, сессии гостей и счётчики использования

- `guests` - логическое представление гостевых клиентов (IP, user agent, fingerprint).
- `guest_sessions` - конкретные сессии гостя, привязанные к `shared_links`. Связь: `guest_sessions.shared_link_id → shared_links.id`, `guest_sessions.guest_id → guests.id`.
- `usage_counters` - накопленные счётчики запросов, трафика и нарушений для расшаренной ссылки. Отношение 1:1 к `shared_links`. Связь: `usage_counters.shared_link_id → shared_links.id`.

### Группа 5: Логи и безопасность

- `proxy_access_logs` - логи всех запросов через прокси. Связь: `proxy_access_logs.guest_session_id → guest_sessions.id`, `proxy_access_logs.shared_link_id → shared_links.id`.
- `revocation_reasons` - справочник причин отключения ссылок (`ttl_expired`, `request_limit`, `traffic_limit`, `violation_limit`, `manual`).
- `link_terminations` - факты завершения расшаренных ссылок. Связь: `link_terminations.shared_link_id → shared_links.id`, `link_terminations.reason_id → revocation_reasons.id`, `link_terminations.terminated_by → users.id`.
- `security_events` - события безопасности (попытки в запрещённые зоны, превышение лимитов). Связь: `security_events.guest_session_id → guest_sessions.id`, `security_events.shared_link_id → shared_links.id`.

---

**Соответствие 3НФ:**
Схема приведена к третьей нормальной форме. Каждая таблица имеет единственный первичный ключ (суррогатный UUID или составной PK в таблицах-связках). Все неключевые атрибуты зависят только от первичного ключа (нет транзитивных зависимостей). Примеры решений, обеспечивающих нормализацию:
- куки и токены не хранятся в `original_sessions`, а вынесены в `session_cookies` и `session_tokens`;
- HTTP-методы блокировки не хранятся строкой в `blacklisted_endpoints`, а вынесены в отдельную таблицу-связку `endpoint_blocked_methods` (PK: `(endpoint_id, http_method)`), что устраняет нарушение 1НФ;
- столбец `user_id` удалён из `shared_links`: владелец ссылки выводится через `shared_links.original_session_id → original_sessions.user_id`, иное нарушило бы 3НФ (транзитивная зависимость через `original_session_id`);
- счётчики использования вынесены в `usage_counters`, а не денормализованы в `shared_links`;
- справочник причин отключения вынесен в `revocation_reasons`;
- таблицы-связки `link_policies`, `site_endpoint_rules`, `link_endpoint_rules` и `endpoint_blocked_methods` корректно реализуют отношения M:N.

**Семантика опциональных внешних ключей:**
- `api_keys.device_id` - `NULL`, если ключ создан без привязки к конкретному устройству (например, из веб-интерфейса).
- `original_sessions.device_id` - `NULL`, если сессия импортирована без отслеживания устройства.
- `guest_sessions.guest_id` - `NULL`, если гость не был идентифицирован до создания сессии (идентификация происходит по первому запросу).
- `link_terminations.terminated_by` - `NULL`, если ссылка была отключена автоматически (истечение TTL, лимиты).

**Намеренные отступления от нормализации:**

1. `proxy_access_logs` и `security_events` содержат одновременно `guest_session_id` (nullable) и `shared_link_id` (NOT NULL). Когда `guest_session_id` не `NULL`, значение `shared_link_id` теоретически можно вывести через JOIN. Однако `guest_session_id` намеренно nullable: запись лога должна создаваться даже в случае ошибки до установки сессии (атака, сбой). Прямое хранение `shared_link_id` - осознанная денормализация для надёжности и производительности логирования.

2. `details jsonb` в `security_events` - произвольные метаданные события (например, заголовки запроса, параметры URL при нарушении). Осознанный компромисс между гибкостью и нормализацией; структурированная часть полей остаётся нормализованной.

**Примечание по бизнес-правилам 5 и 6 (контроль лимитов):**
Сравнение значений `usage_counters` с порогами из `access_policies` и последующий перевод `shared_links.status` в `'terminated'` не может быть реализован декларативно средствами PostgreSQL (данные находятся в разных таблицах). Схема обеспечивает необходимые структуры данных и связи; сама логика принудительного применения лимитов реализуется на уровне приложения.

---

## 5. Высокая доступность PostgreSQL (Patroni + etcd + HAProxy)

Два узла PostgreSQL под управлением Patroni, etcd как DCS, HAProxy как точка входа.

- `patroni1`, `patroni2` - два инстанса Postgres, один primary, один standby
- `etcd` - хранит состояние кластера, через него Patroni выбирает нового лидера при падении
- `haproxy` - слушает на порту 5433, стучится на `:8008/primary` каждые 3 секунды и шлёт трафик только на тот узел, который ответил 200

### Запуск

```bash
docker compose --profile ha up -d --build
docker compose --profile ha logs -f patroni1 patroni2

# убедиться, что primary доступен через HAProxy:
PGPASSWORD=change_me psql -h localhost -p 5433 -U sessionproxy -d sessionproxy \
  -c "SELECT pg_is_in_recovery();"
# → f (не реплика = primary)

docker compose --profile ha run --rm migrate-ha
```

Статистика HAProxy: http://localhost:7000

### Проверка failover

```bash
# убиваем текущий primary
docker compose --profile ha stop patroni1

# через ~15 сек patroni2 стал primary, HAProxy уже переключил трафик:
PGPASSWORD=change_me psql -h localhost -p 5433 -U sessionproxy -d sessionproxy \
  -c "SELECT pg_is_in_recovery();"
# → f

# возвращаем patroni1 - он поднимается как реплика и догоняет patroni2
docker compose --profile ha start patroni1
```

---

## 6. CDC-пайплайн (Debezium + Kafka + ClickHouse)

### Выбор таблицы

Источник CDC - `proxy_access_logs`. Это единственная таблица, которая растёт пропорционально трафику через прокси, а не числу созданных объектов. Пока сессии, ссылки и пользователи практически не меняются, логи пишутся на каждый HTTP-запрос. `seed_v5.sql` заполняет её через `SELECT ... FROM guest_sessions`, так что данные для тестирования есть сразу.

Для метрик используются:

| Поле | Роль |
|------|------|
| `requested_at` | группировка по времени |
| `http_method`, `response_status` | категории (распределение методов, доля ошибок) |
| `response_time_ms` | latency |
| `bytes_transferred` | трафик |

`target_url`, `guest_session_id`, `shared_link_id` в ClickHouse не передаются - они нужны для операционных запросов в Postgres, для агрегатов не нужны.

### Пайплайн

```
PostgreSQL (wal_level=logical, publication pub_proxy_logs)
  -> Debezium 2.7.3 (replication slot debezium_slot, pgoutput)
  -> Kafka 3.7.0 KRaft (топик sessionproxy.public.proxy_access_logs)
  -> ClickHouse Kafka Engine + Materialized View
  -> bi.proxy_access_logs (MergeTree)
  -> Metabase
```

INSERT в Postgres появляется в ClickHouse через 1-3 секунды.

### Запуск

```bash
docker compose --profile ha --profile bi up -d
sh debezium/register.sh
```

---

## 7. Application layer (Go)

Каталог `app/` - реализация бизнес-логики, которую README раздела 4 явно называет незакрытой на уровне БД (сравнение `usage_counters` с `access_policies`, перевод `shared_links.status` в `terminated`). Схема и миграции не менялись, кроме одной новой (`00009_grant_app_role.sql` - см. ниже).

### Data plane и control plane

- **Data plane** (`app/internal/proxy`) - реверс-прокси на `net/http/httputil.ReverseProxy`. Гость идёт на `/r/{token}/...`, прокси резолвит `shared_link` по токену, расшифровывает куки/токены владельца (AES-256-GCM, `app/internal/crypto`) непосредственно перед запросом к целевому сайту, проксирует и вырезает `Set-Cookie` и другие идентифицирующие заголовки из ответа до того, как они дойдут до гостя. Это FR3/FR4 из раздела 2.
- **Control plane** (`app/internal/transport/http`, REST на `chi`) - импорт сессии, создание/терминейт ссылок, политики, blacklist, просмотр логов/статистики. Контракт описан в `app/api/openapi.yaml`.
- **gRPC** (`app/internal/transport/grpc`) - `ImportService` (тот же путь шифрования, что и REST, но auth через `api_keys` вместо JWT - под CLI/расширения) и `AdminService.StreamLinkActivity` (server-streaming живых событий: нарушения blacklist, auto-terminate).
- **Веб-дашборд** (`app/internal/transport/webui`, `templ` + `htmx` + SSE) - на `/dashboard`: логин, список ссылок с terminate-в-один-клик, форма импорта, живой security-фид.

### Лимиты и blacklist

`usage_counters` - лимиты проверяются в Redis (`app/internal/limiter`) на каждый запрос гостя: там быстрый путь принятия решения, а Postgres - источник истины для отчётности и восстановления счётчиков после перезапуска Redis (warm load при первом обращении к ссылке). Несколько `access_policies`, привязанных к одной ссылке через `link_policies`, схлопываются в один эффективный лимит по правилу "самый строгий выигрывает" (минимум по каждому полю, `NULL` не участвует).

Blacklist (`blacklisted_endpoints` + `endpoint_blocked_methods` + `site_endpoint_rules`/`link_endpoint_rules`) проверяется до похода на целевой сайт, по пути **на целевом сайте** (`/settings`), а не по гостевому URL (`/r/{token}/settings`). Пустой список методов у правила означает "блокировать все методы", непустой - блокировать только перечисленные.

**Границы FR4**: вырезание `Set-Cookie` из заголовков ответа - надёжная гарантия. Утечка токена внутри тела ответа (HTML/JSON от целевого сайта) не перехватывается - это осознанно не решается на уровне прокси и не заявляется как гарантия.

### Миграция 00009 и права роли приложения

В HA-профиле `migrate-ha` применяет миграции от имени суперпользователя `postgres` (см. `DATABASE_URL` в `docker-compose.yml`), поэтому таблицы 00001-00007 создаются с владельцем `postgres`. Роль `sessionproxy`, которой подключается приложение, владением базы (`ha/post_init.sh`) прав на уже существующие объекты внутри неё не получает - нужен явный `GRANT`. `migrations/00009_grant_app_role.sql` выдаёт `sessionproxy` `SELECT/INSERT/UPDATE/DELETE` на все таблицы и передаёт владение `mv_link_stats` (только владелец может делать `REFRESH ... CONCURRENTLY`). Без этой миграции первый же запрос приложения на свежем кластере упал бы с `permission denied`.

### Запуск

```bash
docker compose --profile ha --profile app up -d --build
# приложение слушает :8080 (REST+webui), :9090 (gRPC), :6060 (/metrics, /debug/pprof)

curl http://localhost:8080/healthz
curl -X POST http://localhost:8080/api/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"owner@example.com","password":"correct-horse-battery"}'
```

Стенд для ручной проверки инъекции кук - сервис `echo-target` (профиль `app`), эхо-сервер, показывающий заголовки, которые он получил.

### Тесты

```bash
cd app
make test-unit          # crypto, blacklist matching, policy resolver, auth, async logger - без Docker
make test-integration    # testcontainers-go: реальный Postgres+Redis, настоящие миграции из ../migrations
make lint
```

Ключевой сценарий интеграционных тестов (`app/test/integration/proxy_e2e_test.go` и соседние файлы): владелец импортирует сессию → создаёт ссылку → гость проходит по ссылке → цель получает расшифрованную куку владельца → гость не получает `Set-Cookie` → превышение лимита или blacklist переводит ссылку в `terminated` с верной причиной → строка долетает до `proxy_access_logs` (и далее по уже существующему CDC-пайплайну в ClickHouse/Metabase).
