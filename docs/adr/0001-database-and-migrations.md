# ADR 0001: PostgreSQL + SQLAlchemy + Alembic

**Status:** Accepted

## Context
We need durable relational storage for events, alerts, evidence links, and investigations, with flexible event metadata and fast time-range queries.

## Decision
- **PostgreSQL** for storage; JSONB for flexible event `attributes`, typed columns for fields we filter on.
- **SQLAlchemy 2.0** as the ORM, **Alembic** for versioned schema migrations.
- Unit tests run on in-memory SQLite for speed; CI additionally runs migrations against real PostgreSQL.
- Event deduplication uses a SHA-256 `fingerprint` with a UNIQUE constraint, so the database enforces it even under concurrent requests.

## Consequences
+ Real SQL practice, strong integrity guarantees, AWS RDS compatibility.
- SQLite and PostgreSQL differ (e.g. JSONB, timezone handling), so integration tests against PostgreSQL are required and run in CI.
