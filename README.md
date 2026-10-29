# SecurlyQ

**AI-powered security analytics for small IT teams.**
SecurlyQ ingests security events, detects suspicious activity with rules and machine learning, and explains each finding in plain English.

> Status: early development. Phase 1 (foundation) complete. See [docs/roadmap.md](docs/roadmap.md).

## What it does

1. **Collect** authentication, application, and network events through an API.
2. **Analyze** events with deterministic security rules and an anomaly detection model.
3. **Explain** each alert with evidence and recommended investigation steps.
4. **Investigate** alerts in a dashboard: filter, acknowledge, annotate, and track metrics.

SecurlyQ labels findings as *potentially suspicious*. It never claims an attack definitely occurred, and it never takes automated action.

## Target AWS architecture

![Target AWS architecture](docs/images/aws-architecture-target.png)

## Repository layout

```
securlyq/
├── backend/            FastAPI service (API, rules, ML, persistence)
│   ├── app/
│   │   ├── api/        HTTP routes (thin: validate, call services, return)
│   │   ├── core/       Configuration and shared settings
│   │   ├── db/         Database engine, session, base class
│   │   ├── models/     SQLAlchemy table definitions
│   │   ├── schemas/    Pydantic request/response shapes
│   │   └── services/   Business logic (parsing, dedup; later rules, ML, LLM)
│   ├── migrations/     Alembic database migrations
│   ├── tests/          Automated tests
│   └── Dockerfile
├── frontend/           React + TypeScript dashboard (Phase 5)
├── infra/              Terraform for AWS (Phase 6)
├── docs/               Product brief, roadmap, ADRs, lesson notes
└── .github/workflows/  CI pipeline
```

## Quick start (local)

Requirements: Python 3.11+, Docker Desktop.

```bash
cp .env.example .env
docker compose up -d db            # start PostgreSQL
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head               # create the database tables
uvicorn app.main:app --reload
```

Open http://localhost:8000/docs for the interactive API documentation.

Try it:

```bash
curl -X POST localhost:8000/api/v1/events -H 'content-type: application/json' -d '[{
  "source": "auth-service", "event_type": "login", "outcome": "failure",
  "timestamp": "2026-10-28T12:00:00Z", "source_ip": "203.0.113.7", "username": "alice"
}]'
```

Run the tests and linter:

```bash
cd backend
pytest
ruff check .
```

## Tech stack

Python, FastAPI, Pydantic, SQLAlchemy, Alembic, PostgreSQL, scikit-learn, React, TypeScript, Docker, GitHub Actions, AWS (App Runner/ECS, RDS, S3, CloudWatch, Secrets Manager), Terraform.

## Documentation

- [Product brief](docs/product-brief.md)
- [Roadmap](docs/roadmap.md)
- [Architecture decisions](docs/adr/)
- [Phase 1 lesson notes](docs/lessons/phase-1-foundation.md)

## Known limitations

- Detection quality is evaluated on sample and synthetic data and does not establish real-world accuracy.
- The ingestion API is not yet authenticated (added in Phase 2). Do not expose publicly yet.
