# Phase 2 Lesson Notes: Authentication and Detection

## 1. Authentication vs authorization
- **Authentication:** proving who you are (email + password -> token).
- **Authorization:** what you may do (roles). `api/deps.py` expresses this as one line per route: `Depends(analyst_or_admin)`.

| Role | Can do |
|---|---|
| viewer | read events, alerts, summary |
| analyst | + ingest events, run analysis, change alert status, add notes |
| admin | + list users, change roles |

## 2. Password storage (`core/security.py`)
- We store an **Argon2 hash**, never the password. Argon2 is deliberately slow and uses a random salt, so identical passwords hash differently and a stolen database is expensive to crack.
- Unknown email on login? We still burn the same CPU on a dummy hash, so response time doesn't reveal which emails exist. Error messages are identical too (**user enumeration defense**).

## 3. JSON Web Tokens
A JWT is a signed note: `sub=42, exp=3pm`. The server checks the signature with a secret.
- We **pin the algorithm** on decode (defends against `alg: none` forgery). Tests prove forged, expired, and tampered tokens are rejected.
- The token holds only the user id. The **role is read from the database each request**, so demoting someone takes effect immediately (tested). Tradeoff: one DB lookup per request.
- `JWT_SECRET` is validated at startup. Outside development the app **refuses to boot** with the default or a short secret. Failing fast beats silently running insecurely.

## 4. Rate limiting with a deque (`core/rate_limit.py`)
Five failed logins from the same IP+email in five minutes -> HTTP 429 + `Retry-After`. Each key stores a `deque` of failure times; new ones append right, expired ones pop left, both O(1). Honest limitation: in-process memory, so multiple containers each keep their own counts. Production fix: Redis or AWS WAF.

## 5. Mass-assignment defense
Registration schemas use `extra="forbid"`: sending `{"role": "admin"}` is a 422, so users can't promote themselves. The role is decided only by server logic.

## 6. Sliding windows (`services/rules.py`)
Question: "did this IP fail 10+ times within 5 minutes?"
- Naive: for every event, rescan earlier events -> O(N^2).
- Sliding window: a `deque` holds only events inside the window. Each event enters once and leaves once -> **O(N)**.

Three rules, one class each, all subclassing `Rule`:
| Rule | Signal | Severity |
|---|---|---|
| `failed_login_burst` | >=10 failures from one IP in 5 min | medium, high at 30+ |
| `failure_then_success` | success from an IP after >=5 recent failures | high, critical at 20+ |
| `multi_ip_login` | one user from >=3 IPs in 60 min | medium, high if any success |

Design details worth studying:
- **Episode merging:** a 500-failure attack is *one* alert, not fifty. Without this, dashboards drown in noise ("alert fatigue").
- Thresholds live in settings, not code, so they're tunable per environment.
- Rules return `Finding` objects containing **evidence with a reason per event**. Every alert is traceable (a core product principle).

## 7. Idempotency (`dedup_key`)
Each finding has a key (rule + entity + first evidence event). A UNIQUE constraint means re-running analysis can never create duplicate alerts. *Idempotent* = safe to repeat. It matters for retries, schedulers, and later SQS workers.

## 8. Patterns used
- **Repository** (`AlertRepository`): the only code that writes alerts.
- **Service** (`AnalysisService`): orchestrates load -> evaluate -> save.
- **Strategy/Polymorphism** (`Rule` subclasses): the engine runs any rule without knowing which.

## 9. SQL you can study in `api/alerts.py`
- `GROUP BY` for dashboard counts and "top IPs".
- **N+1 query trap avoided:** evidence counts for a page of alerts come from one grouped query, not one query per alert.
- Joins for evidence + events, and an outer join for note authors.

## 10. Risk score
`severity base (25/50/75/90) + min(10, 0.5 x evidence count)`, capped at 100. It's a **ranking heuristic, not a probability**. Phase 3 blends in the ML score and measures how well it separates attacks from noise.

## Bugs we hit (read these, they're the best lessons)
1. Test helper used fake fingerprints `000...1`, `000...2`; our dedup key used the first 16 characters, so keys collided. Test data should look like real data.
2. Phase 1: PostgreSQL returned timestamps in its session timezone; SQLite didn't. Only a live PostgreSQL run exposed it.

## Exercises
1. Add a rule `OffHoursLogin` (successful login between 01:00-05:00 UTC) with unit tests.
2. Change `burst_threshold` via `.env` and watch alert counts change.
3. Add `GET /api/v1/alerts?username=` filtering with a test.
4. Why must the rate limiter count failures only, and why reset on success?
