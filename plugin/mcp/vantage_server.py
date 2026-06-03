"""Vantage MCP server — drive the vulnerability console from Claude.

Exposes the Vantage REST API (see ``docs/api-contract.md``) as MCP tools. It is
a THIN, read/triage-oriented client: every tool maps to one API call. The hard
boundaries of the platform are preserved because they live on the SERVER, not
here:

  * **Scan-and-report only.** There is no exploit / attack / lateral-movement
    tool. The verbs are: read, check-scope, request-scan, triage, diff, report.
  * **Scope gate stays server-side.** ``request_scan`` calls ``POST /api/scans``,
    which fails closed (HTTP 403 ``out_of_scope``) for any asset not in the
    HOD-approved inventory. This MCP layer cannot bypass it — it only forwards
    the request and surfaces the gate's verdict.
  * **Mutations are human-gated + role-gated server-side.** This client simply
    forwards them; the API derives the actor from the authenticated session and
    enforces RBAC.

Config (env):
  * ``VANTAGE_API_BASE``  — API base URL (default ``http://localhost:8138``).
  * ``VANTAGE_BEARER``    — optional bearer token (OIDC id_token) for a
    production deployment with ``AUTH_REQUIRED=true``. Omit in the local/dev
    reference build (the API treats unauthenticated callers as a dev admin).

Run:  python plugin/mcp/vantage_server.py   (stdio transport; launched by Claude)
"""
from __future__ import annotations

import os
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = os.environ.get("VANTAGE_API_BASE", "http://localhost:8138").rstrip("/")
BEARER = os.environ.get("VANTAGE_BEARER", "").strip()

mcp = FastMCP("vantage")

_CLIENT: Optional[httpx.Client] = None


def _client() -> httpx.Client:
    """Lazily-created shared HTTP client (tests can swap its transport)."""
    global _CLIENT
    if _CLIENT is None:
        headers = {"Accept": "application/json"}
        if BEARER:
            headers["Authorization"] = "Bearer " + BEARER
        _CLIENT = httpx.Client(base_url=API_BASE, headers=headers, timeout=30.0)
    return _CLIENT


def _request(method: str, path: str, *, params: dict | None = None,
             json: dict | None = None) -> dict:
    """One API call → a JSON-safe dict. Never raises into MCP: on any error it
    returns a structured ``{"_error", "_status", "detail"}`` so Claude gets a
    readable message instead of a traceback. The server's contract error body
    ``{error, detail}`` is passed through on non-2xx."""
    try:
        resp = _client().request(method, path, params=params, json=json)
    except Exception as exc:  # noqa: BLE001 — network/DNS/timeout
        return {"_error": "unreachable",
                "detail": f"Vantage API not reachable at {API_BASE}: {exc}"}
    body: dict
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 — non-JSON (e.g. a file download)
        body = {"_raw": resp.text[:500]}
    if resp.status_code >= 400:
        return {"_error": body.get("error", "http_error") if isinstance(body, dict) else "http_error",
                "_status": resp.status_code,
                "detail": (body.get("detail") if isinstance(body, dict) else None) or resp.text[:300]}
    return body


def _csv(value: str) -> Optional[str]:
    v = (value or "").strip()
    return v or None


# =====================================================================
# READ — register, dashboards, scope, lifecycle views
# =====================================================================
@mcp.tool()
def dashboard() -> dict:
    """Vantage rollup: open findings by severity, overdue/due-soon/running
    counts, and the severity trend. Start here for a posture snapshot."""
    return _request("GET", "/api/dashboard")


@mcp.tool()
def list_findings(severity: str = "", status: str = "", pipeline: str = "",
                  sla: str = "", asset_id: str = "", q: str = "") -> dict:
    """List/triage findings with optional filters (all AND-combined).

    severity: csv of critical,high,medium,low,info · status: csv of
    open,triaged,in_progress,retest,closed,risk_accepted,confirmed_fp ·
    pipeline: web|infra · sla: overdue|due_soon|ok|met · asset_id: AST-… ·
    q: substring of id/title/asset. Returns {findings, total}."""
    params = {k: v for k, v in {
        "severity": _csv(severity), "status": _csv(status), "pipeline": _csv(pipeline),
        "sla": _csv(sla), "assetId": _csv(asset_id), "q": _csv(q),
    }.items() if v is not None}
    return _request("GET", "/api/findings", params=params)


@mcp.tool()
def get_finding(finding_id: str) -> dict:
    """Full detail for one finding (id like VLN-2087): severity, CVSS, asset,
    framework mapping, SLA/escalation, status, human-validation."""
    return _request("GET", f"/api/findings/{finding_id}")


@mcp.tool()
def list_assets() -> dict:
    """The HOD-approved asset inventory (the authorized scope allowlist). Any
    target NOT here is out of scope and a scan request for it is refused."""
    return _request("GET", "/api/assets")


@mcp.tool()
def scope_check(target: str) -> dict:
    """Check whether a target (asset id, hostname, or name) is in the approved
    inventory BEFORE requesting a scan. Returns {inScope, match?, candidates}.

    This mirrors the server-side scope gate (which is the real, fail-closed
    authority). Use it to confirm authorization rather than guessing."""
    assets = _request("GET", "/api/assets")
    if "_error" in assets:
        return assets
    t = (target or "").strip().lower()
    rows = assets.get("assets", [])
    for a in rows:
        if t and t in (str(a.get("id", "")).lower(), str(a.get("host", "")).lower(),
                       str(a.get("name", "")).lower()):
            return {"inScope": True, "match": a}
    candidates = [
        {"id": a.get("id"), "name": a.get("name"), "host": a.get("host"), "type": a.get("type")}
        for a in rows
        if t and (t in str(a.get("name", "")).lower() or t in str(a.get("host", "")).lower())
    ]
    return {"inScope": False, "match": None, "candidates": candidates,
            "note": "Not in the approved inventory — a scan request would be refused (403 out_of_scope)."}


@mcp.tool()
def scan_diff() -> dict:
    """Diff two scan registers (licensed engine set = previous scan vs OSS set =
    latest): resolved (closure-verified) / new / persisting / regressed + counts."""
    return _request("GET", "/api/scan-diff")


@mcp.tool()
def schedule() -> dict:
    """The cadence + blackout-calendar scan schedule across the approved
    inventory (web 2x/yr · internal VA 2x/yr · CIS 1x/yr). Planning view only."""
    return _request("GET", "/api/schedule")


@mcp.tool()
def escalations() -> dict:
    """The SLA escalation staircase rollup (Day 0->2->4->9->18): who each overdue
    finding is currently with, and which are due for escalation."""
    return _request("GET", "/api/escalations")


@mcp.tool()
def audit(limit: int = 50) -> dict:
    """Recent audit-trail entries (most recent first). The API mirrors the
    hash-chained, append-only audit_log."""
    return _request("GET", "/api/audit", params={"limit": max(1, int(limit))})


# =====================================================================
# WRITE — human-gated, scope-gated, role-gated (all enforced server-side)
# =====================================================================
@mcp.tool()
def request_scan(asset_id: str, pipeline: str, mode: str = "black-box",
                 auth_context: str = "") -> dict:
    """Request a scan of an APPROVED asset. The server enforces the scope gate
    (fail-closed): an asset not in the approved inventory is refused with
    403 out_of_scope. NOTHING here exploits — it queues an authorized scan.

    asset_id: AST-… (must be approved) · pipeline: web|infra (must match the
    asset) · mode: black-box|gray-box · auth_context: unauthenticated|
    min-privilege|max-privilege (required for gray-box). Run scope_check first."""
    body = {"assetId": asset_id, "pipeline": pipeline, "mode": mode}
    if auth_context.strip():
        body["authContext"] = auth_context.strip()
    return _request("POST", "/api/scans", json=body)


@mcp.tool()
def set_finding_status(finding_id: str, status: str, note: str = "") -> dict:
    """Move a finding through the human workflow: open|triaged|in_progress|
    retest|closed. (risk_accepted is reachable ONLY via an approved exception;
    confirmed_fp via the false-positive flow.) Role-gated (analyst) server-side."""
    body: dict = {"status": status}
    if note.strip():
        body["note"] = note.strip()
    return _request("PATCH", f"/api/findings/{finding_id}/status", json=body)


@mcp.tool()
def request_retest(finding_id: str) -> dict:
    """Request a retest of a finding (status -> retest). Closure is then verified
    by scan_diff (the finding showing under 'resolved' = the re-scan no longer
    reports it). Role-gated (analyst)."""
    return _request("POST", f"/api/findings/{finding_id}/retest", json={})


@mcp.tool()
def confirm_false_positive(finding_id: str, decision: str = "confirm",
                           note: str = "") -> dict:
    """Confirm or clear a finding as a false positive. decision: confirm|clear.
    Role-gated (analyst). confirm -> status confirmed_fp; clear -> triaged."""
    body: dict = {"decision": decision}
    if note.strip():
        body["note"] = note.strip()
    return _request("POST", f"/api/findings/{finding_id}/false-positive", json=body)


@mcp.tool()
def request_exception(finding_id: str, duration_months: int,
                      documented_risk: str) -> dict:
    """Request a time-boxed risk exception. The server routes the approval tier
    by duration (<=3mo CISO, <=12mo RMC, >12mo Board). Role-gated (analyst).
    documented_risk is required."""
    return _request("POST", "/api/exceptions", json={
        "findingId": finding_id, "durationMonths": int(duration_months),
        "documentedRisk": documented_risk})


@mcp.tool()
def decide_exception(exception_id: str, decision: str) -> dict:
    """Approve or reject an exception. decision: approve|reject. Gated to the
    exception's tier role (CISO/RMC/Board) server-side. Approval is the ONLY
    path to risk_accepted (it sets the linked finding to risk_accepted)."""
    return _request("POST", f"/api/exceptions/{exception_id}/decision",
                    json={"decision": decision})


@mcp.tool()
def generate_report(template: str = "audit", scope: str = "all",
                    formats: str = "xlsx,docx", open_password: str = "",
                    owner_password: str = "") -> dict:
    """Generate a report. template: audit|exec|asset|sla · scope: all|<assetId> ·
    formats: csv subset of xlsx,docx,pdf. If pdf is requested, open_password and
    owner_password are required and must differ (dual-password AES-256 PDF).
    Returns {reportId, files:{fmt: download_path}}; downloads are owner-scoped."""
    fmts = [f.strip().lower() for f in formats.split(",") if f.strip()]
    body: dict = {"template": template, "scope": scope, "formats": fmts}
    if open_password:
        body["openPassword"] = open_password
    if owner_password:
        body["ownerPassword"] = owner_password
    return _request("POST", "/api/reports", json=body)


if __name__ == "__main__":
    mcp.run()
