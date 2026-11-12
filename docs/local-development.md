# Running SecurlyQ locally (VS Code)

Total time: about 15 minutes. You will run three things: PostgreSQL (in Docker), the API (Python), and the dashboard (Node).

## 0. Install once

| Tool | Version | Check |
|---|---|---|
| Git | any | `git --version` |
| Python | 3.11 or newer | `python --version` (Windows: `py --version`) |
| Node.js | 20 or newer (22 recommended) | `node -v` |
| Docker Desktop | any (must be **running**) | `docker --version` |
| VS Code | with the extensions it recommends on first open | |

## 1. Get the code

```bash
git clone https://github.com/Jainil1367/SecurlyQ.git
cd SecurlyQ
code .
```

The repo is private, so sign in to GitHub when Git asks (or use GitHub Desktop / `gh auth login`). When VS Code offers to install the recommended extensions, accept.

## 2. Configuration and database

Open a VS Code terminal (**Terminal > New Terminal**).

```bash
cp .env.example .env            # Windows PowerShell: Copy-Item .env.example .env
docker compose up -d db         # starts PostgreSQL 16 on port 5432
```

The defaults in `.env` already match the database in `docker-compose.yml`; nothing to edit for local use.

## 3. Backend (API)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-ml.txt
alembic upgrade head            # creates the tables
python -m app.ml.train          # ~5 s: trains the anomaly model (optional, but unlocks the ML detections)
python -m app.ml.seed_demo      # ~3 days of realistic traffic, then runs detection
uvicorn app.main:app --reload
```

In VS Code press **Ctrl/Cmd+Shift+P > Python: Select Interpreter** and choose `backend/.venv`. Check http://localhost:8000/health shows `{"status":"ok"}` and http://localhost:8000/docs loads.

> Windows PowerShell may block the activate script. Run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

## 4. Dashboard

In a **second** terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Vite forwards `/api` to port 8000, so no CORS setup is needed.

## 5. Create your account and look around

The first account you register becomes the **admin**. Register it once, from a third terminal (or the Authorize button at http://localhost:8000/docs):

```bash
curl -X POST localhost:8000/api/v1/auth/register -H 'content-type: application/json' \
  -d '{"email":"admin@securlyq.dev","password":"a-long-passphrase"}'
```

(PowerShell: use `curl.exe`, and put the JSON in a file or escape the quotes.)

Then sign in at http://localhost:5173 and try this checklist:

- [ ] The queue lists alerts with severity pills; the first is the highest risk.
- [ ] Change the **Status** and **Severity** filters. Page with Next / Previous.
- [ ] Open an alert: the evidence timeline shows failures (dots) and the success (diamond).
- [ ] Click **Explain this alert**: a "Template explanation" appears (set up Bedrock later for model-written text).
- [ ] Save a note, then **Acknowledge**. Go back: the "Mean time to acknowledge" card now shows a value.
- [ ] Press **Run analysis**: it reports events scanned and 0 new alerts (alerts are not duplicated).
- [ ] Switch **light / dark** theme in the sidebar; reload and confirm it remembers.
- [ ] Sign out. Register a second account via `/docs`: it becomes an *analyst*. A viewer role has no write buttons.

## VS Code shortcuts

**Terminal > Run Task...** offers `Dev: API + dashboard` (starts both), `Test: backend`, and `Test: frontend`. The **Testing** sidebar discovers the pytest tests, and **Run and Debug > Debug API (uvicorn)** lets you set breakpoints in the backend.

## Run the tests

```bash
cd backend && pytest && ruff check .        # 208 tests
cd ../frontend && npm run typecheck && npm test   # 19 tests
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `connection refused` on port 5432 | Docker Desktop is not running, or run `docker compose up -d db` again |
| `port is already allocated` / address in use | Another program uses 5432 / 8000 / 5173; stop it or change the port |
| `alembic: command not found` | The virtual environment is not active (look for `(.venv)` in the prompt) |
| Dashboard shows "Cannot reach the SecurlyQ API" | The API is not running on port 8000 |
| Sign-in says incorrect email or password | Register first (step 5); email is case-insensitive |
| No anomaly alerts | You skipped `python -m app.ml.train`; run it, then press Run analysis |
| Fonts look different offline | Fonts load from Google Fonts; the layout still works with system fonts |
| Start over with an empty database | `docker compose down -v` then repeat step 2 and `alembic upgrade head` |
