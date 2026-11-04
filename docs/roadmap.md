# Roadmap

| Phase | Focus | Status |
|---|---|---|
| 1 | Foundation: repo, schema, migrations, event ingestion, dedup, tests, CI | **Done** |
| 2 | Auth (JWT + roles), rule engine, risk scoring, alerts API | **Done** |
| 3 | Data science + ML: feature engineering, Isolation Forest, risk scoring, evaluation | Planned |
| 4 | LLM explanations (structured JSON, schema validation, fallback) | Planned |
| 5 | React + TypeScript dashboard (alerts, timelines, investigations, metrics) | Planned |
| 6 | AWS deployment (RDS, App Runner/ECS, S3, CloudWatch, Secrets Manager, Terraform) | Planned |
| 7 | Hardening: rate limiting, audit log, load tests, threat model, demo | Planned |

## Release levels
- **Level 1 (must have):** secure API, PostgreSQL, ingestion, deterministic rules, dashboard, tests, live AWS deployment.
- **Level 2 (differentiator):** anomaly detection, evidence-based LLM explanations, investigations, model evaluation.
- **Level 3 (advanced):** SQS async processing, Terraform, richer audit logging, drift monitoring.
