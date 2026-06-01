# Vantage API (read-only, v0)

A dependency-light FastAPI app that serves the Vantage console's seed dataset
(ported from `frontend/data.js`) over the read-only REST interface. No Postgres
or Temporal required. From the repo root, install deps with
`pip install -r orchestrator/requirements.txt` (or just
`pip install fastapi "uvicorn[standard]"`), then run
`uvicorn orchestrator.api.main:app --port 8138`. "Today" is pinned to
`2026-06-01` so SLA/escalation fields are stable. CORS is enabled for the
console dev server at `http://localhost:8137`. The frozen interface is defined
in [`docs/api-contract.md`](../../docs/api-contract.md).
