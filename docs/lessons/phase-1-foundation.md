# Phase 1 Lesson Notes: The Foundation

Read these alongside the code. Each section says **what** we built, **why**, and **where to look**.

## 1. Layered architecture
```
HTTP request -> api/ (routes) -> services/ (logic) -> models/ (tables) -> PostgreSQL
                    |
                schemas/ (validation of data crossing the boundary)
```
- **api/** is thin: it only handles HTTP concerns (status codes, query params).
- **services/** holds business logic and knows nothing about HTTP. Because of that, the rule engine and ML code can reuse it later.
- **models/** describe tables. **schemas/** describe the *shape of data on the wire*. They are separate on purpose: you never want an API response to accidentally expose a database column.

*OOP link:* each class has one job (single responsibility). `EventParser` normalizes; `EventIngestionService` orchestrates; neither knows about the other's internals beyond a small interface.

## 2. Input validation is security (`schemas/event.py`)
Every field has a type, length limit, or pattern. `extra="forbid"` rejects unknown fields. The attributes blob is size-capped. This blocks oversized payloads and malformed data before they touch our logic. *Try it:* send `"source_ip": "bad"` and read the 422 response.

## 3. Hashing for deduplication (`services/event_parser.py`)
A SHA-256 hash of an event's canonical form is its **fingerprint**. Same event => same hash. We use it two ways:
1. A Python `set` removes duplicates inside a batch in O(N).
2. A database `UNIQUE` constraint removes duplicates across requests, even when two requests race. The code catches `IntegrityError` and retries once.

*Why canonical form?* `{"a":1,"b":2}` and `{"b":2,"a":1}` are the same event, so we sort keys before hashing.

## 4. Relational design (`models/`)
- **One-to-many:** an alert has many investigation notes (`investigations.alert_id`).
- **Many-to-many:** alerts <-> events through the `alert_evidence` link table (composite primary key).
- **Indexes:** `(event_type, timestamp)`, `(source_ip, timestamp)`, `(username, timestamp)` match our common filters. Try `EXPLAIN ANALYZE SELECT ... WHERE source_ip = '...'` in `psql` with and without the index once you have lots of rows (Phase 2 includes a data generator).
- **JSONB:** flexible attributes without schema changes, but we keep hot-path fields as real columns.

## 5. Migrations (`backend/migrations/`)
A migration is version control for your database schema. `alembic upgrade head` applies changes; `alembic downgrade base` reverses them. Rule: **never edit the production schema by hand.**
Workflow when you change a model:
```bash
cd backend
alembic revision --autogenerate -m "describe the change"
# review the generated file! autogenerate is a draft, not gospel
alembic upgrade head
```

## 6. Testing strategy
- **Unit tests** (fast, SQLite in memory) cover parsing, validation, API behaviour.
- **CI** (GitHub Actions) also runs migrations against real PostgreSQL.
- *Real lesson from building this:* SQLite and PostgreSQL disagree. PostgreSQL returned timestamps in its session timezone (`-04:00`) while SQLite returned naive values. Unit tests passed; only a live PostgreSQL run exposed it. That is why we test on both.

## 7. Configuration & secrets
`core/config.py` reads environment variables. `.env` is git-ignored; `.env.example` documents what is needed. In AWS, these values come from Secrets Manager, not files.

## Known gap (intentional)
`POST /api/v1/events` is **unauthenticated** right now. Phase 2 adds JWT login, roles, and API keys. Do not deploy publicly before then.

## Exercises
1. Add an `event_type` of `password_reset` via the API and fetch it with a filter.
2. Write a test proving two events differing only in `outcome` get different fingerprints.
3. Add a `GET /api/v1/events/{id}` route with a 404 for missing ids (with a test).
