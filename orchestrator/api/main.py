"""Vantage read-only REST API (FastAPI).

Implements the frozen contract in ``docs/api-contract.md``. Serves the Python
seed dataset ported from ``frontend/data.js`` -- no Postgres / Temporal needed.

Run:
    uvicorn orchestrator.api.main:app --port 8138
"""

from __future__ import annotations

import os
import secrets
import tempfile
from datetime import datetime, timezone
from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import seed
from orchestrator.reporting.export import build_xlsx, build_docx, build_pdf

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

# Statuses a human may set via PATCH /api/findings/{id}/status. risk_accepted is
# reachable ONLY via an approved exception (out of scope for v0.1); confirmed_fp
# is not human-settable here either.
ALLOWED_STATUSES = {"open", "triaged", "in_progress", "retest", "closed"}


def _err(status_code: int, error: str, detail: str) -> JSONResponse:
    """Contract error body: {"error","detail"} with the given status code."""
    return JSONResponse(status_code=status_code, content={"error": error, "detail": detail})


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


# ---------------------------------------------------------------------------
# Write endpoints (v0.1) — human-gated. Every mutation requires a human actor
# and appends an audit entry; scope-gate denials are audited too. Error bodies
# follow the {"error","detail"} contract shape.
# ---------------------------------------------------------------------------


@app.patch("/api/findings/{finding_id}/status")
def set_finding_status(finding_id: str, body: dict = Body(...)):
    status = body.get("status")
    actor = body.get("actor")

    if not actor or not str(actor).strip():
        return _err(422, "missing_actor", "A human 'actor' is required for this mutation")
    if status not in ALLOWED_STATUSES:
        return _err(
            422,
            "invalid_status",
            f"status must be one of {sorted(ALLOWED_STATUSES)}; got {status!r}",
        )

    updated = seed.update_finding_status(finding_id, status, str(actor), TODAY_ISO)
    if updated is None:
        return _err(404, "not_found", f"Finding not found: {finding_id}")

    seed.record_audit(
        actor=str(actor),
        action="FINDING_STATUS_CHANGED",
        entity_type="finding",
        entity_id=finding_id,
        summary=f"status set to {status} by {actor}",
    )
    return {"finding": updated}


@app.post("/api/scans")
def request_scan(body: dict = Body(...)):
    asset_id = body.get("assetId")
    pipeline = body.get("pipeline")
    mode = body.get("mode")
    auth_context = body.get("authContext")
    by = body.get("by")

    # SCOPE GATE — fail closed. Unknown / non-approved asset is denied first and
    # audited, before any other validation.
    asset = seed.asset_by_id(asset_id) if asset_id else None
    if asset is None:
        seed.record_audit(
            actor=str(by) if by else "unknown",
            action="SCAN_DENIED_OUT_OF_SCOPE",
            entity_type="asset",
            entity_id=str(asset_id),
            summary=f"scan denied: {asset_id} not in approved inventory",
        )
        return _err(
            403,
            "out_of_scope",
            f"{asset_id} is not in the approved asset inventory",
        )

    if not by or not str(by).strip():
        return _err(422, "missing_actor", "A human 'by' is required for this mutation")
    if pipeline not in ("web", "infra"):
        return _err(422, "invalid_pipeline", "pipeline must be 'web' or 'infra'")
    if pipeline != asset["type"]:
        return _err(
            422,
            "pipeline_mismatch",
            f"pipeline {pipeline!r} does not match asset type {asset['type']!r}",
        )
    if mode == "gray-box" and (not auth_context or not str(auth_context).strip()):
        return _err(422, "missing_auth_context", "gray-box scans require 'authContext'")

    scan = seed.add_scan(asset, pipeline, mode, auth_context, str(by))
    seed.record_audit(
        actor=str(by),
        action="SCAN_REQUESTED",
        entity_type="scan",
        entity_id=scan["id"],
        summary=f"{mode} scan queued for {asset['name']} by {by}",
    )
    return JSONResponse(status_code=201, content={"scan": scan})


@app.post("/api/exceptions")
def request_exception(body: dict = Body(...)):
    finding_id = body.get("findingId")
    requested_by = body.get("requestedBy")
    duration_months = body.get("durationMonths")
    documented_risk = body.get("documentedRisk")

    if not requested_by or not str(requested_by).strip():
        return _err(422, "missing_actor", "A human 'requestedBy' is required for this mutation")
    if not documented_risk or not str(documented_risk).strip():
        return _err(422, "missing_documented_risk", "'documentedRisk' is required")
    if not isinstance(duration_months, int) or isinstance(duration_months, bool) or duration_months <= 0:
        return _err(422, "invalid_duration", "'durationMonths' must be a positive integer")

    finding = seed.find_finding(finding_id) if finding_id else None
    if finding is None:
        return _err(404, "not_found", f"Finding not found: {finding_id}")

    exc, tier = seed.add_exception(dict(finding), str(requested_by), duration_months, str(documented_risk))
    seed.record_audit(
        actor=str(requested_by),
        action="EXCEPTION_REQUESTED",
        entity_type="exception",
        entity_id=exc["id"],
        summary=f"{tier} exception requested for {finding_id} ({duration_months}mo) by {requested_by}",
    )
    return JSONResponse(status_code=201, content={"exception": exc, "tier": tier})


@app.get("/api/audit")
def get_audit(limit: Optional[int] = Query(None, ge=1)):
    return {"audit": seed.audit(limit)}


# ---------------------------------------------------------------------------
# Reporting (v0.1) — expose the Vantage reporting engine. POST generates the
# requested formats from scope-filtered findings into a fresh temp dir; the
# in-memory registry maps reportId -> {fmt: filesystem path}; GET streams a
# file back as a download. The PDF is AES-256 encrypted with a dual password.
# ---------------------------------------------------------------------------

ALLOWED_FORMATS = {"xlsx", "docx", "pdf"}

# Media types per requested format, used on download.
_REPORT_MEDIA = {
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}

# In-memory report registry: {reportId: {fmt: absolute_path}}.
_REPORTS: dict[str, dict[str, str]] = {}


def _new_report_id() -> str:
    """Unique-ish report id like 'RPT-XXXXXX' (6 hex uppercase chars)."""
    return "RPT-" + secrets.token_hex(3).upper()


@app.post("/api/reports")
def create_report(body: dict = Body(...)):
    by = body.get("by")
    scope = body.get("scope", "all")
    formats = body.get("formats")
    open_password = body.get("openPassword")
    owner_password = body.get("ownerPassword")
    template = body.get("template")

    if not by or not str(by).strip():
        return _err(422, "missing_actor", "A human 'by' is required for this mutation")

    if not isinstance(formats, list) or not formats:
        return _err(422, "invalid_formats", "'formats' must be a non-empty list")
    fmt_list = [str(f).strip().lower() for f in formats]
    if not set(fmt_list) <= ALLOWED_FORMATS:
        return _err(
            422,
            "invalid_formats",
            f"'formats' must be a subset of {sorted(ALLOWED_FORMATS)}",
        )

    if "pdf" in fmt_list:
        if not open_password or not owner_password:
            return _err(
                422,
                "missing_pdf_passwords",
                "pdf format requires both 'openPassword' and 'ownerPassword'",
            )
        if str(open_password) == str(owner_password):
            return _err(
                422,
                "pdf_passwords_equal",
                "'openPassword' and 'ownerPassword' must differ",
            )

    # Filter findings by scope: "all" -> everything; else an assetId.
    items = seed.findings()
    if scope and scope != "all":
        items = [f for f in items if f["assetId"].lower() == str(scope).lower()]

    meta = {"title": f"Vantage {template or 'audit'} report"} if template else None

    report_id = _new_report_id()
    outdir = tempfile.mkdtemp(prefix=f"vantage-{report_id}-")

    files: dict[str, str] = {}
    paths: dict[str, str] = {}
    # Generate ONLY the requested formats (dedup, preserve canonical order).
    for fmt in ("xlsx", "docx", "pdf"):
        if fmt not in fmt_list:
            continue
        path = os.path.join(outdir, f"vantage-{report_id}.{fmt}")
        if fmt == "xlsx":
            build_xlsx(items, path, meta=meta)
        elif fmt == "docx":
            build_docx(items, path, meta=meta)
        else:  # pdf
            build_pdf(items, path, str(open_password), str(owner_password), meta=meta)
        paths[fmt] = path
        files[fmt] = f"/api/reports/{report_id}/{fmt}"

    _REPORTS[report_id] = paths

    generated_at = datetime.now(timezone.utc).isoformat()
    seed.record_audit(
        actor=str(by),
        action="REPORT_GENERATED",
        entity_type="report",
        entity_id=report_id,
        summary=f"{','.join(files)} report generated for scope {scope} by {by}",
    )

    return JSONResponse(
        status_code=201,
        content={"reportId": report_id, "generatedAt": generated_at, "files": files},
    )


@app.get("/api/reports/{report_id}/{fmt}")
def download_report(report_id: str, fmt: str):
    fmt = fmt.lower()
    paths = _REPORTS.get(report_id)
    if not paths or fmt not in paths:
        raise HTTPException(status_code=404, detail=f"Report not found: {report_id}/{fmt}")
    return FileResponse(
        paths[fmt],
        media_type=_REPORT_MEDIA[fmt],
        headers={
            "Content-Disposition": f'attachment; filename="vantage-{report_id}.{fmt}"'
        },
    )
