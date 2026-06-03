# Vantage read-only API service (FastAPI + uvicorn).
# Build context is ./orchestrator (so the `orchestrator.api` package is copied).
#
# Base pinned by digest for reproducibility/supply-chain hardening.
# python@sha256:090b... == python:3.12-slim (resolved via `docker pull` +
# `docker inspect --format "{{index .RepoDigests 0}}"`).
FROM python@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

WORKDIR /app

# nmap for the live-scan endpoint (POST /api/scans/live). The endpoint is
# RBAC-gated + scope-gated (fail-closed) at the app layer, and the scan is
# non-intrusive (-sT connect + version + safe NSE, argv/no-shell), run as the
# non-root appuser below.
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

# The API needs FastAPI + uvicorn + psycopg (for the audit-log persistence),
# plus the reporting engine's deps (openpyxl/python-docx/reportlab/pikepdf) so
# the /api/reports endpoint can generate xlsx/docx and dual-password PDFs. The
# full orchestrator requirements.txt pulls heavier packages (temporalio) this
# service doesn't use — install the lean subset. Runs as root so installs land
# in the system site-packages, then we drop privileges before CMD.
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn[standard]>=0.29" "psycopg[binary]>=3.2" \
    openpyxl python-docx reportlab pikepdf \
    "authlib>=1.3" "httpx>=0.27" "itsdangerous>=2.2" "ldap3>=2.9" \
    defusedxml

# Create an unprivileged user to run the service (debian slim ships useradd).
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

# Copy the orchestrator package to /app/orchestrator so `orchestrator.api.main`
# is importable (orchestrator is a namespace package; api has __init__.py).
# Owned by appuser so the dropped-privilege process can read it.
COPY --chown=appuser:appuser . /app/orchestrator

ENV PYTHONUNBUFFERED=1
EXPOSE 8138

# Liveness probe via Python stdlib (curl isn't in slim; no extra packages).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8138/api/health',timeout=4).status==200 else 1)"

# Drop privileges; uvicorn on 8138 is an unprivileged port so this is fine.
USER appuser

# 0.0.0.0 so the published port is reachable from the host/browser.
CMD ["uvicorn", "orchestrator.api.main:app", "--host", "0.0.0.0", "--port", "8138"]
