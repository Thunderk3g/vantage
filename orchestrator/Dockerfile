# Vantage read-only API service (FastAPI + uvicorn).
# Build context is ./orchestrator (so the `orchestrator.api` package is copied).
FROM python:3.12-slim

WORKDIR /app

# The API needs FastAPI + uvicorn + psycopg (for the audit-log persistence),
# plus the reporting engine's deps (openpyxl/python-docx/reportlab/pikepdf) so
# the /api/reports endpoint can generate xlsx/docx and dual-password PDFs. The
# full orchestrator requirements.txt pulls heavier packages (temporalio) this
# service doesn't use — install the lean subset.
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn[standard]>=0.29" "psycopg[binary]>=3.2" \
    openpyxl python-docx reportlab pikepdf

# Copy the orchestrator package to /app/orchestrator so `orchestrator.api.main`
# is importable (orchestrator is a namespace package; api has __init__.py).
COPY . /app/orchestrator

ENV PYTHONUNBUFFERED=1
EXPOSE 8138

# 0.0.0.0 so the published port is reachable from the host/browser.
CMD ["uvicorn", "orchestrator.api.main:app", "--host", "0.0.0.0", "--port", "8138"]
