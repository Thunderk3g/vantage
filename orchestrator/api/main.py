"""Vantage REST API (FastAPI).

Implements the frozen contract in ``docs/api-contract.md``. Serves the Python
seed dataset ported from ``frontend/data.js`` -- no Postgres / Temporal needed.

Auth/RBAC per ``docs/auth-contract.md``: all reads require an authenticated
user (``/api/health`` stays public); mutations are role-gated via
``require_role``. The write ``actor`` is now derived **server-side** from the
session (``session_actor(user)``) and is never taken from the request body.

Run:
    uvicorn orchestrator.api.main:app --port 8138
"""

from __future__ import annotations

import os
import secrets
import tempfile
from datetime import datetime, timezone
from typing import Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import seed
from .auth import Role, User, get_current_user, require_role, session_actor, router as auth_router
from orchestrator.reporting.export import build_xlsx, build_docx, build_pdf
from orchestrator import escalation, notifications, scheduler, diff, pipeline

app = FastAPI(title="Vantage API", version="0", description="Read-only vulnerability-scanner console API.")

# Allow the console dev server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8137"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the OIDC/auth router (prefix="/api/auth").
app.include_router(auth_router)

TODAY_ISO = seed.TODAY.isoformat()
DUE_SOON_DAYS = 7  # daysLeft within [0, 7] counts as "due soon"

# Statuses a human may set via PATCH /api/findings/{id}/status. risk_accepted is
# reachable ONLY via an approved exception (out of scope for v0.1); confirmed_fp
# is not human-settable here either.
ALLOWED_STATUSES = {"open", "triaged", "in_progress", "retest", "closed"}

# Exception approval tier -> the role authorized to decide it. ADMIN is always a
# wildcard. risk_accepted is reachable ONLY via an approved exception (below).
_TIER_ROLE = {
    "CISO": Role.APPROVER_CISO,
    "RMC": Role.APPROVER_RMC,
    "Board": Role.APPROVER_BOARD,
}


def _err(status_code: int, error: str, detail: str) -> JSONResponse:
    """Contract error body: {"error","detail"} with the given status code."""
    return JSONResponse(status_code=status_code, content={"error": error, "detail": detail})


@app.exception_handler(HTTPException)
def _normalize_http_exception(request, exc: HTTPException):
    """Keep every error body in the contract shape {"error","detail"}.

    The auth dependencies (`get_current_user`/`require_role`) raise
    `HTTPException(detail={"error","detail"})` so they can share the contract
    shape. FastAPI's default handler would nest that under another "detail" key
    ({"detail":{"error":...}}), which breaks the console's error reader. Surface
    such dict-details at the TOP level; fall back to the default {"detail": ...}
    for plain-string HTTPExceptions (e.g. the 404s raised elsewhere here).
    """
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


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
    user: User = Depends(get_current_user),
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
def get_finding(finding_id: str, user: User = Depends(get_current_user)):
    for f in seed.findings():
        if f["id"] == finding_id:
            return {"finding": f}
    raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")


@app.get("/api/assets")
def list_assets(user: User = Depends(get_current_user)):
    return {"assets": seed.assets()}


@app.get("/api/scans")
def list_scans(user: User = Depends(get_current_user)):
    return {"scans": seed.scans()}


@app.get("/api/exceptions")
def list_exceptions(user: User = Depends(get_current_user)):
    return {"exceptions": seed.exceptions()}


@app.get("/api/trend")
def get_trend(user: User = Depends(get_current_user)):
    return {"trend": seed.trend()}


@app.get("/api/dashboard")
def dashboard(user: User = Depends(get_current_user)):
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
# Write endpoints (v0.1) — human-gated + role-gated (see docs/auth-contract.md
# §3). The acting identity is derived SERVER-SIDE from the authenticated
# session via session_actor(user) and used for both the seed store call and the
# audit `actor=`; the request body NO LONGER supplies actor/by/requestedBy
# (older clients may still send them — they are ignored). Every mutation appends
# an audit entry; scope-gate denials are audited too (with the session actor).
# Error bodies follow the {"error","detail"} contract shape.
# ---------------------------------------------------------------------------


@app.patch("/api/findings/{finding_id}/status")
def set_finding_status(
    finding_id: str,
    body: dict = Body(...),
    user: User = Depends(require_role(Role.ANALYST)),
):
    status = body.get("status")
    actor = session_actor(user)

    if status not in ALLOWED_STATUSES:
        return _err(
            422,
            "invalid_status",
            f"status must be one of {sorted(ALLOWED_STATUSES)}; got {status!r}",
        )

    updated = seed.update_finding_status(finding_id, status, actor, TODAY_ISO)
    if updated is None:
        return _err(404, "not_found", f"Finding not found: {finding_id}")

    seed.record_audit(
        actor=actor,
        action="FINDING_STATUS_CHANGED",
        entity_type="finding",
        entity_id=finding_id,
        summary=f"status set to {status} by {actor}",
    )
    return {"finding": updated}


@app.post("/api/scans")
def request_scan(
    body: dict = Body(...),
    user: User = Depends(require_role(Role.ANALYST)),
):
    asset_id = body.get("assetId")
    pipeline = body.get("pipeline")
    mode = body.get("mode")
    auth_context = body.get("authContext")
    by = session_actor(user)

    # SCOPE GATE — fail closed. Unknown / non-approved asset is denied first and
    # audited (with the session actor), before any other validation.
    asset = seed.asset_by_id(asset_id) if asset_id else None
    if asset is None:
        seed.record_audit(
            actor=by,
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

    scan = seed.add_scan(asset, pipeline, mode, auth_context, by)
    seed.record_audit(
        actor=by,
        action="SCAN_REQUESTED",
        entity_type="scan",
        entity_id=scan["id"],
        summary=f"{mode} scan queued for {asset['name']} by {by}",
    )
    return JSONResponse(status_code=201, content={"scan": scan})


@app.post("/api/exceptions")
def request_exception(
    body: dict = Body(...),
    user: User = Depends(require_role(Role.ANALYST)),
):
    finding_id = body.get("findingId")
    requested_by = session_actor(user)
    duration_months = body.get("durationMonths")
    documented_risk = body.get("documentedRisk")

    if not documented_risk or not str(documented_risk).strip():
        return _err(422, "missing_documented_risk", "'documentedRisk' is required")
    if not isinstance(duration_months, int) or isinstance(duration_months, bool) or duration_months <= 0:
        return _err(422, "invalid_duration", "'durationMonths' must be a positive integer")

    finding = seed.find_finding(finding_id) if finding_id else None
    if finding is None:
        return _err(404, "not_found", f"Finding not found: {finding_id}")

    exc, tier = seed.add_exception(dict(finding), requested_by, duration_months, str(documented_risk))
    seed.record_audit(
        actor=requested_by,
        action="EXCEPTION_REQUESTED",
        entity_type="exception",
        entity_id=exc["id"],
        summary=f"{tier} exception requested for {finding_id} ({duration_months}mo) by {requested_by}",
    )
    return JSONResponse(status_code=201, content={"exception": exc, "tier": tier})


# ---------------------------------------------------------------------------
# Governance workflows (v0.1) — false-positive confirm/clear and exception
# approve/reject. Same human-gating contract as above: the acting identity is
# server-derived via session_actor(user) (never from the body); every mutation
# is audited; error bodies follow {"error","detail"}. risk_accepted is reachable
# ONLY through an approved exception (set_finding_risk_accepted, below) — the
# generic PATCH /status still rejects it.
# ---------------------------------------------------------------------------


@app.post("/api/findings/{finding_id}/false-positive")
def decide_false_positive(
    finding_id: str,
    body: dict = Body(...),
    user: User = Depends(require_role(Role.ANALYST)),
):
    decision = body.get("decision")
    if decision not in ("confirm", "clear"):
        return _err(422, "invalid_decision", "decision must be 'confirm' or 'clear'")

    actor = session_actor(user)
    updated = seed.set_false_positive(finding_id, decision == "confirm", actor, TODAY_ISO)
    if updated is None:
        return _err(404, "not_found", f"Finding not found: {finding_id}")

    if decision == "confirm":
        action = "FINDING_FP_CONFIRMED"
        summary = f"false positive confirmed (status confirmed_fp) by {actor}"
    else:
        action = "FINDING_FP_CLEARED"
        summary = f"false positive cleared (status triaged) by {actor}"
    seed.record_audit(
        actor=actor,
        action=action,
        entity_type="finding",
        entity_id=finding_id,
        summary=summary,
    )
    return {"finding": updated}


@app.post("/api/exceptions/{exception_id}/decision")
def decide_exception(
    exception_id: str,
    body: dict = Body(...),
    user: User = Depends(get_current_user),
):
    decision = body.get("decision")
    if decision not in ("approve", "reject"):
        return _err(422, "invalid_decision", "decision must be 'approve' or 'reject'")

    exc = seed.find_exception(exception_id)
    if exc is None:
        return _err(404, "not_found", f"Exception not found: {exception_id}")

    if exc["status"] not in ("requested", "pending"):
        return _err(422, "not_decidable", f"exception already {exc['status']}")

    # RBAC by tier: only the tier's approver role (or admin) may decide.
    required = _TIER_ROLE.get(exc["tier"])
    if Role.ADMIN.value not in user.roles and (required is None or required.value not in user.roles):
        return _err(403, "forbidden", f"requires the {exc['tier']} approver role")

    actor = session_actor(user)
    today = TODAY_ISO

    if decision == "approve":
        updated = seed.update_exception(exception_id, "approved", today)
        fin = seed.set_finding_risk_accepted(exc["finding"], actor, today)
        seed.record_audit(
            actor=actor,
            action="EXCEPTION_APPROVED",
            entity_type="exception",
            entity_id=exception_id,
            summary=f"{exc['tier']} exception {exception_id} approved by {actor}",
        )
        seed.record_audit(
            actor=actor,
            action="FINDING_RISK_ACCEPTED",
            entity_type="finding",
            entity_id=exc["finding"],
            summary=f"{exc['finding']} risk_accepted via approved exception {exception_id} by {actor}",
        )
        return {"exception": updated, "finding": fin}

    # reject
    updated = seed.update_exception(exception_id, "rejected", today)
    seed.record_audit(
        actor=actor,
        action="EXCEPTION_REJECTED",
        entity_type="exception",
        entity_id=exception_id,
        summary=f"{exc['tier']} exception {exception_id} rejected by {actor}",
    )
    return {"exception": updated, "finding": None}


@app.get("/api/audit")
def get_audit(limit: Optional[int] = Query(None, ge=1), user: User = Depends(get_current_user)):
    return {"audit": seed.audit(limit)}


# ---------------------------------------------------------------------------
# Scan diff / closure verification (v0.1) — wires the pure diff engine
# (orchestrator/diff.py) to the two deterministic triage pipelines. The
# "request retest" action is the explicit, human-gated mutation the console
# button maps to: it flips a finding to status "retest" and audits it. Neither
# endpoint launches a scan or touches a target.
# ---------------------------------------------------------------------------


@app.get("/api/scan-diff")
def get_scan_diff(user: User = Depends(get_current_user)):
    """Diff two scan registers — the licensed engine set (baseline / 'previous
    scan') vs the OSS engine set (current / 'latest scan') — by finding
    signature. Read-only; computes from the deterministic reference pipelines.
    Resolved = in baseline, gone in current (closure-verified); new = only in
    current; persisting = both; regressed = persisting + severity increased."""
    base = pipeline.run_reference_pipeline(seed.TODAY)
    head = pipeline.run_oss_pipeline(seed.TODAY)
    result = diff.diff_scans(base, head)
    return {"baseLabel": "licensed", "headLabel": "oss", "today": TODAY_ISO, **result}


@app.post("/api/findings/{finding_id}/retest")
def request_retest(finding_id: str, user: User = Depends(require_role(Role.ANALYST))):
    actor = session_actor(user)
    updated = seed.update_finding_status(finding_id, "retest", actor, TODAY_ISO)
    if updated is None:
        return _err(404, "not_found", f"Finding not found: {finding_id}")
    seed.record_audit(actor=actor, action="RETEST_REQUESTED", entity_type="finding",
                      entity_id=finding_id, summary=f"retest requested for {finding_id} by {actor}")
    return {"finding": updated}


# ---------------------------------------------------------------------------
# Escalation staircase (Day 0→2→4→8-10→15-20) + notification sweep.
# GET reports the current ladder/rollup (read). POST runs a sweep: it computes
# which findings are DUE for escalation and dispatches notifications via the
# notification service (log + in-memory sinks; a webhook/ITSM sink is the
# production plug-in). This NEVER acts on a target — it only notifies humans.
# ---------------------------------------------------------------------------


def _derive_last_runs() -> dict:
    """Build {assetId: <ISO date>} anchors from COMPLETED seed scans.

    Maps each completed scan's `target` (a name) to its asset id, using the
    scan's `started` date (first 10 chars). Skips entries whose started date is
    "—"/unparseable. If an asset has multiple completed scans, keeps the most
    recent. Assets with no completed scan are simply absent (the engine then
    treats them as due now). This anchors the planning view in realistic
    last-run dates without launching anything.
    """
    name_to_id = {a["name"]: a["id"] for a in seed.assets()}
    last_runs: dict[str, str] = {}
    for s in seed.scans():
        if s.get("status") != "completed":
            continue
        asset_id = name_to_id.get(s.get("target"))
        if asset_id is None:
            continue
        d = scheduler._to_date(s.get("started"))
        if d is None:
            continue
        iso = d.isoformat()
        prev = last_runs.get(asset_id)
        if prev is None or iso > prev:
            last_runs[asset_id] = iso
    return last_runs


@app.get("/api/schedule")
def get_schedule(user: User = Depends(get_current_user)):
    """Cadence + blackout-aware scan schedule across the approved inventory.
    Read-only planning view — does NOT launch scans (that stays human/scope
    gated)."""
    return scheduler.build_schedule(seed.assets(), seed.TODAY, last_runs=_derive_last_runs())


@app.get("/api/escalations")
def list_escalations(user: User = Depends(get_current_user)):
    roll = escalation.build_escalations(seed.findings(), seed.TODAY)
    return {"today": TODAY_ISO, **roll}


@app.post("/api/escalations/run")
def run_escalations(user: User = Depends(require_role(Role.ADMIN))):
    """Compute due escalations and dispatch notifications (admin-gated, audited).

    Deterministic + side-effect-light: the sweep emits to a log sink and an
    in-memory sink; wiring a real ITSM/webhook sink (Jira/ServiceNow) is a
    config change in the notification service. Returns what was dispatched.
    """
    roll = escalation.build_escalations(seed.findings(), seed.TODAY)
    notifier = notifications.Notifier([notifications.LogSink(), notifications.InMemorySink()])
    results = notifier.notify_escalations(roll["due"])

    dispatched = []
    for r in results:
        n = r.get("notification", {})
        dispatched.append({
            "findingId": n.get("finding_id"),
            "stage": n.get("stage"),
            "role": n.get("role"),
            "severity": n.get("severity"),
            "kind": n.get("kind"),
            "message": n.get("message"),
            "channels": r.get("channels", []),
            "deduped": r.get("deduped", False),
        })

    ran_at = datetime.now(timezone.utc).isoformat()
    seed.record_audit(
        actor=session_actor(user),
        action="ESCALATION_SWEEP",
        entity_type="escalation",
        entity_id="sweep",
        summary=f"escalation sweep dispatched {len(dispatched)} notification(s)",
    )
    return {"dispatched": dispatched, "count": len(dispatched), "ranAt": ran_at}


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

# In-memory report registry: {reportId: {"owner", "paths": {fmt: path}, "created"}}.
#
# SECURITY: download is now gated by an authenticated, owner-scoped check
# (download_report enforces `entry["owner"] == user.sub` or admin). The
# high-entropy, unguessable `report_id` is retained as *defense in depth*:
#   * Reports must NOT be enumerable -> the id carries ~192 bits of entropy.
#   * `owner` is the session subject id (user.sub), set at creation.
# Entries expire after _REPORT_TTL to bound the exposure window.
_REPORTS: dict[str, dict] = {}
_REPORT_TTL = 3600  # seconds


def _new_report_id() -> str:
    """Opaque, high-entropy report id (~192 bits) used as a capability token."""
    return "RPT-" + secrets.token_urlsafe(24)


def _prune_reports() -> None:
    """Drop reports past their TTL (bounds how long a leaked URL stays live)."""
    now = datetime.now(timezone.utc).timestamp()
    for rid in [r for r, e in _REPORTS.items() if now - e["created"] > _REPORT_TTL]:
        _REPORTS.pop(rid, None)


@app.post("/api/reports")
def create_report(
    body: dict = Body(...),
    user: User = Depends(require_role(
        Role.ANALYST, Role.APPROVER_CISO, Role.APPROVER_RMC, Role.APPROVER_BOARD
    )),
):
    # SECURITY: the acting identity is derived SERVER-SIDE from the authenticated
    # session (session_actor) — the request body no longer supplies the actor.
    by = session_actor(user)
    scope = body.get("scope", "all")
    formats = body.get("formats")
    open_password = body.get("openPassword")
    owner_password = body.get("ownerPassword")
    template = body.get("template")

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

    _REPORTS[report_id] = {
        "owner": user.sub,   # session subject id; enforced on download (authz)
        "paths": paths,
        "created": datetime.now(timezone.utc).timestamp(),
    }
    _prune_reports()

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
def download_report(report_id: str, fmt: str, user: User = Depends(get_current_user)):
    # SECURITY: download requires an authenticated caller and is owner-scoped —
    # the report owner (entry["owner"] == user.sub) or an admin may download.
    # The unguessable, TTL-bounded report_id is now defense in depth, not the
    # sole access gate.
    _prune_reports()
    fmt = fmt.lower()
    entry = _REPORTS.get(report_id)
    if not entry or fmt not in entry["paths"]:
        raise HTTPException(status_code=404, detail=f"Report not found: {report_id}/{fmt}")
    if entry["owner"] != user.sub and Role.ADMIN.value not in user.roles:
        return _err(403, "forbidden", "not the report owner")
    return FileResponse(
        entry["paths"][fmt],
        media_type=_REPORT_MEDIA[fmt],
        # Don't echo the capability token into the saved filename.
        headers={"Content-Disposition": f'attachment; filename="vantage-report.{fmt}"'},
    )
