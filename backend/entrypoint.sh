#!/bin/sh
# Container start-up: apply any pending database migrations, then run the API.
# `set -e` stops here if a migration fails, so a broken deploy never serves traffic.
# `exec` makes uvicorn PID 1 so it receives shutdown signals from the platform.
set -e
alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
