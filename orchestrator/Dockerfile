# Vantage read-only API service (FastAPI + uvicorn).
# Build context is ./orchestrator (so the `orchestrator.api` package is copied).
FROM python:3.12-slim

WORKDIR /app

# The read API needs only FastAPI + uvicorn. The full orchestrator
# requirements.txt pulls heavy, system-dependency-laden packages (weasyprint,
# temporalio, psycopg) that this service doesn't use — install the lean subset.
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn[standard]>=0.29"

# Copy the orchestrator package to /app/orchestrator so `orchestrator.api.main`
# is importable (orchestrator is a namespace package; api has __init__.py).
COPY . /app/orchestrator

ENV PYTHONUNBUFFERED=1
EXPOSE 8138

# 0.0.0.0 so the published port is reachable from the host/browser.
CMD ["uvicorn", "orchestrator.api.main:app", "--host", "0.0.0.0", "--port", "8138"]
