FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

# Install dependencies first so Docker can cache this layer between code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train the anomaly model at build time (seeded, ~5 s) so every image ships a known, reproducible model.
RUN python -m app.ml.train --no-report

# Never run as root inside a container (least privilege).
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000
CMD ["./entrypoint.sh"]
