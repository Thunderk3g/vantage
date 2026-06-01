"""Vantage read-only REST API (FastAPI).

Implements the frozen contract in ``docs/api-contract.md``. Serves the Python
seed dataset ported from ``frontend/data.js`` -- no Postgres / Temporal needed.

Run:
    uvicorn orchestrator.api.main:app --port 8138
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from . import seed

app = FastAPI(title="Vantage API", version="0", description="Read-only vulnerability-scanner console API.")

# Allow the console dev server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8137"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TODAY_ISO = seed.TODAY.isoformat()
DUE_SOON_DAYS = 7  # daysLeft within [0, 7] counts as "due soon"


def _sla_bucket(f: dict) -> str:
    """Classify a finding into an SLA bucket: met | overdue | due_soon | ok.

    - met: finding is closed/risk_accepted.
    - overdue: deadline passed (daysLeft < 0).
    - due_soon: 0 <= daysLeft <= DUE_SOON_DAYS.
    - ok: otherwise (comfortably within SLA, or Info with no deadline).
    """
    if f["isClosed"]:
        return "met"
    dl = f["daysLeft"]
    if dl is None:
        return "ok"
    if dl < 0:
        return "overdue"
    if dl <= DUE_SOON_DAYS:
        return "due_soon"
    return "ok"


def _csv_set(value: Optional[str]) -> Optional[set]:
    if not value:
        return None
    return {v.strip().lower() for v in value.split(",") if v.strip()}


@app.get("/api/health")
def health():
    return {"status": "ok", "today": TODAY_ISO}


@app.get("/api/findings")
def list_findings(
    severity: Optional[str] = Query(None, description="csv: critical,high,medium,low,info"),
    status: Optional[str] = Query(None, description="csv of statuses"),
    assetId: Optional[str] = Query(None),
    pipeline: Optional[str] = Query(None, description="web|infra"),
    framework: Optional[str] = Query(None),
    sla: Optional[str] = Query(None, description="overdue|due_soon|ok|met"),
    q: Optional[str] = Query(None, description="substring of id/title/asset"),
    sort: Optional[str] = Query(None),
    dir: str = Query("asc", description="asc|desc"),
):
    items = seed.findings()

    sev_set = _csv_set(severity)
    if sev_set is not None:
        items = [f for f in items if f["severity"].lower() in sev_set]

    status_set = _csv_set(status)
    if status_set is not None:
        items = [f for f in items if f["status"].lower() in status_set]

    if assetId:
        items = [f for f in items if f["assetId"].lower() == assetId.lower()]

    if pipeline:
        items = [f for f in items if f["pipeline"].lower() == pipeline.lower()]

    if framework:
        items = [f for f in items if f["framework"].lower() == framework.lower()]

    if sla:
        want = sla.strip().lower()
        items = [f for f in items if _sla_bucket(f) == want]

    if q:
        needle = q.lower()
        items = [
            f for f in items
            if needle in f["id"].lower()
            or needle in f["title"].lower()
            or needle in f["asset"].lower()
        ]

    if sort:
        if sort not in (items[0] if items else seed.findings()[0]):
            raise HTTPException(status_code=400, detail=f"Unknown sort field: {sort}")
        reverse = dir.lower() == "desc"
        items.sort(key=lambda f: (f[sort] is None, f[sort]), reverse=reverse)

    return {"findings": items, "total": len(items)}


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str):
    for f in seed.findings():
        if f["id"] == finding_id:
            return {"finding": f}
    raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")


@app.get("/api/assets")
def list_assets():
    return {"assets": seed.assets()}


@app.get("/api/scans")
def list_scans():
    return {"scans": seed.scans()}


@app.get("/api/exceptions")
def list_exceptions():
    return {"exceptions": seed.exceptions()}


@app.get("/api/trend")
def get_trend():
    return {"trend": seed.trend()}


@app.get("/api/dashboard")
def dashboard():
    items = seed.findings()
    open_items = [f for f in items if not f["isClosed"]]

    open_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in open_items:
        sev = f["severity"]
        if sev in open_by_severity:
            open_by_severity[sev] += 1

    overdue = sum(1 for f in open_items if _sla_bucket(f) == "overdue")
    due_soon = sum(1 for f in open_items if _sla_bucket(f) == "due_soon")
    scans_running = sum(1 for s in seed.scans() if s["status"] == "running")

    return {
        "today": TODAY_ISO,
        "openBySeverity": open_by_severity,
        "counts": {
            "open": len(open_items),
            "overdue": overdue,
            "dueSoon": due_soon,
            "scansRunning": scans_running,
        },
        "trend": seed.trend(),
    }
