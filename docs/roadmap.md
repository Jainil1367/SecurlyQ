# Roadmap

| Phase | Focus | Status |
|---|---|---|
| 1 | Foundation: repo, schema, migrations, event ingestion, dedup, tests, CI | **Done** |
| 2 | Auth (JWT + roles), rule engine, risk scoring, alerts API | **Done** |
| 3 | Data science + ML: simulator, features, Isolation Forest, hybrid risk scoring, evaluation | **Done** |
| 4 | LLM explanations on Amazon Bedrock (sanitized input, schema + safety validation, template fallback) | **Done** (live Bedrock call untested) |
| 5 | React + TypeScript dashboard (alerts, evidence timeline, explanations, notes, metrics, dark/light themes) | **Done** (events, model health pages and trend chart deferred) |
| 6 | AWS deployment (RDS, App Runner/ECS, S3, CloudWatch, Secrets Manager, Terraform) | Planned |
| 7 | Hardening: rate limiting, audit log, load tests, threat model, demo | Planned |

## Release levels
- **Level 1 (must have):** secure API, PostgreSQL, ingestion, deterministic rules, dashboard, tests, live AWS deployment.
- **Level 2 (differentiator):** anomaly detection, evidence-based LLM explanations, investigations, model evaluation.
- **Level 3 (advanced):** SQS async processing, Terraform, richer audit logging, drift monitoring.
