"""Vantage seed data + derivation logic.

Ported faithfully from ``frontend/data.js`` (the single source of truth).
TODAY is pinned to 2026-06-01 so SLA countdowns are stable and match the design.
Dates are converted to ISO ``YYYY-MM-DD`` strings (or None) per the API contract,
whereas data.js keeps native Date objects.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Optional

from . import db
from . import store

# ---- "Today" pinned (data.js: new Date("2026-06-01T09:00:00")) ----
# We only need the calendar date for ISO output and day-diff math.
TODAY: date = date(2026, 6, 1)

# ---- SLA policy (matches db/schema.sql sla_days_for()) ----
# Critical & High = 30 days, Medium & Low = 60, Info = null.
SLA_DAYS = {"critical": 30, "high": 30, "medium": 60, "low": 60, "info": None}


# ---- Date helpers (port of data.js addDays / daysBetween / fmtDate) ----
def add_days(d: date, n: int) -> date:
    return d + timedelta(days=n)


def days_between(a: date, b: date) -> int:
    # data.js: Math.round((b - a) / 86400000) -- whole-day diff.
    return (b - a).days


def fmt_date(d: Optional[date]) -> Optional[str]:
    """ISO YYYY-MM-DD string (or None). Contract requires ISO, not en-GB."""
    return d.isoformat() if d is not None else None


# ---- Approved asset inventory ----
ASSETS = [
    {"id": "AST-PORTAL", "name": "Policyholder Portal",        "type": "web",   "env": "Production", "owner": "Digital Channels",  "crit": "Tier-1", "host": "portal.lifeco.internal"},
    {"id": "AST-AGENT",  "name": "Agent Mobile App (API)",     "type": "web",   "env": "Production", "owner": "Distribution Tech", "crit": "Tier-1", "host": "api.agent.lifeco.internal"},
    {"id": "AST-CLAIMS", "name": "Claims Processing API",      "type": "web",   "env": "Production", "owner": "Claims Platform",   "crit": "Tier-1", "host": "api.claims.lifeco.internal"},
    {"id": "AST-PAY",    "name": "Premium Payment Gateway",    "type": "web",   "env": "Production", "owner": "Payments",          "crit": "Tier-1", "host": "pay.lifeco.internal"},
    {"id": "AST-UW",     "name": "Underwriting Engine",        "type": "web",   "env": "Production", "owner": "Underwriting",      "crit": "Tier-1", "host": "uw.lifeco.internal"},
    {"id": "AST-PAS",    "name": "Core Policy Admin System",   "type": "infra", "env": "Production", "owner": "Core Platform",     "crit": "Tier-1", "host": "10.20.4.0/24"},
    {"id": "AST-DWH",    "name": "Customer Data Warehouse",    "type": "infra", "env": "Production", "owner": "Data Platform",     "crit": "Tier-1", "host": "10.20.8.12"},
    {"id": "AST-IDP",    "name": "Identity Provider (SSO)",    "type": "infra", "env": "Production", "owner": "IAM",               "crit": "Tier-1", "host": "sso.lifeco.internal"},
    {"id": "AST-DMS",    "name": "Document Management Server", "type": "infra", "env": "Production", "owner": "Enterprise Content","crit": "Tier-2", "host": "10.20.6.40"},
    {"id": "AST-REINS",  "name": "Reinsurance Settlement Svc", "type": "web",   "env": "Production", "owner": "Reinsurance",       "crit": "Tier-2", "host": "api.reins.lifeco.internal"},
    {"id": "AST-VPN",    "name": "Branch VPN Gateway",         "type": "infra", "env": "Production", "owner": "Network Ops",       "crit": "Tier-2", "host": "10.10.0.1"},
    {"id": "AST-HR",     "name": "Internal HR Portal",         "type": "web",   "env": "Staging",    "owner": "People Systems",    "crit": "Tier-3", "host": "hr.staging.lifeco.internal"},
]

_ASSET_BY_ID = {a["id"]: a for a in ASSETS}

# ---- Findings (curated). discovered = days ago from TODAY ----
# [id, title, severity, status, assetId, fw, code, catName, cvss, daysAgo, owner]
RAW = [
    ["VLN-2087", "BOLA on /v1/claims/{id} exposes other policyholders' claims", "critical", "triaged",       "AST-CLAIMS", "OWASP API", "API1:2023", "Broken Object Level Authorization",      9.3, 26, "R. Iyer"],
    ["VLN-2081", "SQL injection in policy search parameter",                     "critical", "in_progress",   "AST-PORTAL", "OWASP Web", "A03:2021",  "Injection",                              9.1, 18, "A. Mehta"],
    ["VLN-2074", "Default admin credentials on document server",                "critical", "open",          "AST-DMS",    "CIS",       "CIS-5.2",   "Account Management",                     9.8, 36, "Unassigned"],
    ["VLN-2069", "Unauthenticated premium calculation endpoint leaks PII",      "critical", "open",          "AST-PAY",    "OWASP API", "API2:2023", "Broken Authentication",                  8.9, 1,  "Unassigned"],
    ["VLN-2061", "Hardcoded encryption key in agent app build",                 "high",     "triaged",       "AST-AGENT",  "SANS",      "CWE-798",   "Use of Hard-coded Credentials",          8.1, 24, "S. Khan"],
    ["VLN-2058", "Sensitive policyholder PII written to application logs",      "high",     "in_progress",   "AST-DWH",    "OWASP Web", "A09:2021",  "Security Logging Failures",              7.6, 33, "D. Bose"],
    ["VLN-2052", "Missing rate limiting on OTP verification",                   "high",     "triaged",       "AST-AGENT",  "OWASP API", "API4:2023", "Unrestricted Resource Consumption",      7.4, 40, "S. Khan"],
    ["VLN-2049", "Unpatched OpenSSL CVE-2025-XXXX on VPN gateway",              "high",     "open",          "AST-VPN",    "CIS",       "CIS-7.4",   "Continuous Vuln Mgmt",                   7.9, 72, "P. Nair"],
    ["VLN-2044", "No MFA enforced on underwriting admin console",               "high",     "open",          "AST-UW",     "OWASP Web", "A07:2021",  "Identification & Auth Failures",         7.2, 66, "Unassigned"],
    ["VLN-2040", "Server-side request forgery in document fetch",               "high",     "triaged",       "AST-CLAIMS", "OWASP Web", "A10:2021",  "Server-Side Request Forgery",            8.2, 9,  "R. Iyer"],
    ["VLN-2031", "TLS 1.0/1.1 enabled on payment gateway",                      "medium",   "in_progress",   "AST-PAY",    "CIS",       "CIS-3.10",  "Data Protection",                        5.9, 28, "P. Nair"],
    ["VLN-2028", "IDOR allows download of others' policy documents",            "medium",   "triaged",       "AST-PORTAL", "OWASP API", "API1:2023", "Broken Object Level Authorization",      6.5, 15, "A. Mehta"],
    ["VLN-2024", "Verbose stack traces exposed on 500 errors",                  "medium",   "in_progress",   "AST-UW",     "OWASP Web", "A05:2021",  "Security Misconfiguration",              5.3, 64, "R. Iyer"],
    ["VLN-2019", "Session cookie missing Secure/HttpOnly flags",                "medium",   "open",          "AST-HR",     "OWASP Web", "A05:2021",  "Security Misconfiguration",              5.1, 44, "Unassigned"],
    ["VLN-2015", "Outdated jQuery with known XSS in portal",                    "medium",   "triaged",       "AST-PORTAL", "OWASP Web", "A06:2021",  "Vulnerable & Outdated Components",       6.1, 38, "A. Mehta"],
    ["VLN-2011", "Reinsurance API returns excessive data fields",               "medium",   "open",          "AST-REINS",  "OWASP API", "API3:2023", "Broken Object Property Level Auth",      5.6, 7,  "Unassigned"],
    ["VLN-2003", "Directory listing enabled on static assets",                  "low",      "open",          "AST-PORTAL", "CIS",       "CIS-4.1",   "Secure Configuration",                   3.7, 20, "Unassigned"],
    ["VLN-1998", "Missing security headers (CSP, HSTS)",                        "low",      "triaged",       "AST-AGENT",  "OWASP Web", "A05:2021",  "Security Misconfiguration",              3.1, 30, "S. Khan"],
    ["VLN-1994", "Weak password policy on HR portal",                           "low",      "open",          "AST-HR",     "OWASP Web", "A07:2021",  "Identification & Auth Failures",         4.0, 55, "Unassigned"],
    ["VLN-1990", "Banner discloses server software version",                    "info",     "open",          "AST-VPN",    "CIS",       "CIS-4.8",   "Information Disclosure",                 2.0, 12, "Unassigned"],
    ["VLN-1985", "Deprecated API version still reachable",                      "info",     "triaged",       "AST-REINS",  "OWASP API", "API9:2023", "Improper Inventory Management",          2.4, 26, "R. Iyer"],
    # closed / risk-accepted examples
    ["VLN-1979", "XSS in claims status comment field",                         "high",     "closed",        "AST-CLAIMS", "OWASP Web", "A03:2021",  "Injection",                              7.0, 70, "R. Iyer"],
    ["VLN-1972", "Cleartext internal service on legacy subnet",                "medium",   "risk_accepted", "AST-PAS",    "CIS",       "CIS-3.10",  "Data Protection",                        5.0, 80, "P. Nair"],
    ["VLN-1965", "Open redirect on login return URL",                          "low",      "closed",        "AST-PORTAL", "OWASP Web", "A01:2021",  "Broken Access Control",                  3.4, 90, "A. Mehta"],
]


def _derive_findings():
    out = []
    for i, r in enumerate(RAW):
        (fid, title, severity, status, asset_id, fw, code, cat_name,
         cvss, days_ago, owner) = r
        asset = _ASSET_BY_ID[asset_id]
        discovered = add_days(TODAY, -days_ago)
        sla_days = SLA_DAYS[severity]
        deadline = add_days(discovered, sla_days) if sla_days is not None else None
        is_closed = status in ("closed", "risk_accepted")
        days_left = days_between(TODAY, deadline) if deadline is not None else None

        # Escalation stage: derived exactly as in frontend/data.js.
        esc_stage = 0
        if not is_closed and deadline is not None:
            overdue_by = -days_left
            if overdue_by >= 18:
                esc_stage = 4
            elif overdue_by >= 9:
                esc_stage = 3
            elif overdue_by >= 4:
                esc_stage = 2
            elif overdue_by >= 2:
                esc_stage = 1
            elif overdue_by >= 0:
                esc_stage = 1
            else:
                # not overdue yet: stage by elapsed since discovery
                elapsed = days_ago
                if elapsed >= 18:
                    esc_stage = 2
                elif elapsed >= 4:
                    esc_stage = 1
                else:
                    esc_stage = 0

        out.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "status": status,
            "assetId": asset_id,
            "asset": asset["name"],
            "assetType": asset["type"],
            "assetCrit": asset["crit"],
            "assetOwner": asset["owner"],
            "pipeline": "infra" if asset["type"] == "infra" else "web",
            "framework": fw,
            "catCode": code,
            "catName": cat_name,
            "cvss": cvss,
            "discovered": fmt_date(discovered),
            "deadline": fmt_date(deadline),
            "slaDays": sla_days,
            "daysLeft": days_left,
            "isClosed": is_closed,
            "escStage": esc_stage,
            "owner": owner,
            "scan": "SCAN-0" + str(98 - (i % 6)),
            # ---- human-gating fields (v0.1) ----
            "humanValidatedBy": None,
            "humanValidatedAt": None,
        })
    return out


_FINDINGS = _derive_findings()

_SCANS = [
    {"id": "SCAN-0098", "target": "Claims Processing API",   "pipeline": "web",   "type": "gray-box",  "auth": "min-privilege",   "status": "running",   "progress": 62,  "started": "2026-06-01 08:14", "findings": 7, "by": "A. Mehta"},
    {"id": "SCAN-0097", "target": "Policyholder Portal",     "pipeline": "web",   "type": "black-box", "auth": "unauthenticated", "status": "running",   "progress": 28,  "started": "2026-06-01 08:40", "findings": 3, "by": "S. Khan"},
    {"id": "SCAN-0096", "target": "Branch VPN Gateway",      "pipeline": "infra", "type": "gray-box",  "auth": "max-privilege",   "status": "queued",    "progress": 0,   "started": "—",            "findings": 0, "by": "P. Nair"},
    {"id": "SCAN-0095", "target": "Premium Payment Gateway", "pipeline": "web",   "type": "gray-box",  "auth": "min-privilege",   "status": "completed", "progress": 100, "started": "2026-05-31 22:10", "findings": 5, "by": "P. Nair"},
    {"id": "SCAN-0094", "target": "Customer Data Warehouse", "pipeline": "infra", "type": "gray-box",  "auth": "max-privilege",   "status": "completed", "progress": 100, "started": "2026-05-30 02:00", "findings": 9, "by": "D. Bose"},
]

_EXCEPTIONS = [
    {"id": "EXC-044", "finding": "VLN-1972", "title": "Cleartext internal service on legacy subnet", "asset": "Core Policy Admin System", "severity": "medium", "duration": 2,  "tier": "CISO",  "status": "approved", "requestedBy": "P. Nair",        "approver": "CISO",                  "reviewDate": "2026-08-01", "reason": "Legacy PAS migration in progress; compensating network segmentation in place."},
    {"id": "EXC-046", "finding": "VLN-2044", "title": "No MFA on underwriting admin console",        "asset": "Underwriting Engine",      "severity": "high",   "duration": 5,  "tier": "RMC",   "status": "pending",  "requestedBy": "Underwriting",   "approver": "Risk Mgmt Committee",   "reviewDate": "—",     "reason": "Vendor MFA module delivery scheduled Q3; interim IP allow-listing applied."},
    {"id": "EXC-041", "finding": "VLN-2019", "title": "Session cookie flags on HR portal",           "asset": "Internal HR Portal",       "severity": "medium", "duration": 14, "tier": "Board", "status": "pending",  "requestedBy": "People Systems", "approver": "Board Risk Committee",  "reviewDate": "—",     "reason": "Full HR platform replacement planned next FY; staging only."},
    {"id": "EXC-039", "finding": "VLN-1990", "title": "Server version banner disclosure",            "asset": "Branch VPN Gateway",       "severity": "info",   "duration": 1,  "tier": "CISO",  "status": "rejected", "requestedBy": "Network Ops",    "approver": "CISO",                  "reviewDate": "2026-05-20", "reason": "Low effort to remediate; exception not justified."},
]

_TREND = [
    {"wk": "Apr 6",  "critical": 6, "high": 14, "medium": 22, "low": 11},
    {"wk": "Apr 13", "critical": 5, "high": 13, "medium": 20, "low": 12},
    {"wk": "Apr 20", "critical": 7, "high": 15, "medium": 19, "low": 10},
    {"wk": "Apr 27", "critical": 6, "high": 12, "medium": 18, "low": 9},
    {"wk": "May 4",  "critical": 5, "high": 11, "medium": 17, "low": 9},
    {"wk": "May 11", "critical": 4, "high": 10, "medium": 16, "low": 8},
    {"wk": "May 18", "critical": 5, "high": 9,  "medium": 15, "low": 7},
    {"wk": "May 25", "critical": 4, "high": 9,  "medium": 14, "low": 6},
]


# ---- Audit log (v0.1). DB-backed when available; in-memory fallback. ----
# Each in-memory entry mirrors the API shape:
#   {seq, ts, actor, action, entityType, entityId, summary}.
# When a Postgres DB is configured (db.py / DATABASE_URL), record_audit ALSO
# INSERTs into the hash-chained, append-only ``audit_log`` table and GET /api/audit
# reads back from it. The human entity id (e.g. "VLN-2074") and summary go into
# the ``after`` JSONB — ``entity_id`` (a uuid column) is left NULL since our ids
# are not uuids. The in-memory list is always kept as a fallback cache.
_AUDIT: list[dict] = []
_AUDIT_SEQ = 0

# SQL helpers for the DB-backed path. psycopg is imported lazily inside db.py.
import json as _json  # local alias; only used by the DB audit path

_AUDIT_INSERT_SQL = (
    "INSERT INTO audit_log (actor, action, entity_type, after) "
    "VALUES (%s, %s, %s, %s::jsonb)"
)
_AUDIT_SELECT_SQL = (
    "SELECT seq, ts, actor, action, entity_type, after "
    "FROM audit_log ORDER BY seq DESC"
)


def _now_ts() -> str:
    """Wall-clock timestamp for audit/scan rows ('YYYY-MM-DD HH:MM')."""
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _audit_db_insert(actor: str, action: str, entity_type: str,
                     entity_id: str, summary: str) -> bool:
    """INSERT one audit row into Postgres. Returns True on success, else False.

    Never raises: any DB/driver error is swallowed so the API keeps serving via
    the in-memory cache. The BEFORE INSERT trigger fills prev_hash/row_hash.
    """
    conn = db.get_conn()
    if conn is None:
        return False
    try:
        after = _json.dumps({"entityId": entity_id, "summary": summary})
        with conn:
            with conn.cursor() as cur:
                cur.execute(_AUDIT_INSERT_SQL, (actor, action, entity_type, after))
        return True
    except Exception:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _audit_db_fetch(limit: Optional[int]) -> Optional[list[dict]]:
    """Read audit rows from Postgres (most-recent first), mapped to API shape.

    Returns the list on success, or ``None`` if the DB is unavailable / errors
    (so the caller falls back to the in-memory list). Never raises.
    """
    conn = db.get_conn()
    if conn is None:
        return None
    try:
        sql = _AUDIT_SELECT_SQL
        params: tuple = ()
        if limit is not None:
            sql += " LIMIT %s"
            params = (limit,)
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass

    out: list[dict] = []
    for seq, ts, actor, action, entity_type, after in rows:
        after = after or {}
        out.append({
            "seq": seq,
            "ts": ts.strftime("%Y-%m-%d %H:%M") if hasattr(ts, "strftime") else str(ts),
            "actor": actor,
            "action": action,
            "entityType": entity_type,
            "entityId": after.get("entityId"),
            "summary": after.get("summary"),
        })
    return out


def record_audit(actor: str, action: str, entity_type: str, entity_id: str, summary: str) -> dict:
    """Append an audit entry; persist to Postgres when available.

    Always appends to the in-memory cache (fallback) and, when a DB is
    configured/reachable, also INSERTs into the hash-chained ``audit_log`` table.
    Returns the in-memory entry.
    """
    global _AUDIT_SEQ
    _AUDIT_SEQ += 1
    entry = {
        "seq": _AUDIT_SEQ,
        "ts": _now_ts(),
        "actor": actor,
        "action": action,
        "entityType": entity_type,
        "entityId": entity_id,
        "summary": summary,
    }
    _AUDIT.append(entry)
    _audit_db_insert(actor, action, entity_type, entity_id, summary)
    return entry


def audit(limit: Optional[int] = None) -> list[dict]:
    """Return audit entries most-recent first (optionally capped to ``limit``).

    Reads from Postgres when available; otherwise returns the in-memory list.
    """
    db_rows = _audit_db_fetch(limit)
    if db_rows is not None:
        return db_rows
    rows = sorted(_AUDIT, key=lambda e: e["seq"], reverse=True)
    if limit is not None:
        rows = rows[:limit]
    return [dict(e) for e in rows]


def asset_by_id(asset_id: str) -> Optional[dict]:
    """Look up an asset in the approved inventory (None if not approved)."""
    a = _ASSET_BY_ID.get(asset_id)
    return dict(a) if a is not None else None


def find_finding(finding_id: str) -> Optional[dict]:
    """Return the LIVE finding dict (mutable) or None. For writers only."""
    for f in _FINDINGS:
        if f["id"] == finding_id:
            return f
    return None


def update_finding_status(finding_id: str, status: str, actor: str, validated_at: str) -> Optional[dict]:
    """Mutate the underlying finding so subsequent reads reflect it. Returns a copy.

    Write-through to the persistence overlay (``store``): DB-backed when a
    Postgres DB is configured (so the mutation survives an API restart), and a
    silent no-op otherwise — mirroring the audit fallback pattern above.
    """
    f = find_finding(finding_id)
    if f is None:
        return None
    f["status"] = status
    f["isClosed"] = status in ("closed", "risk_accepted")
    f["humanValidatedBy"] = actor
    f["humanValidatedAt"] = validated_at
    store.save_finding_state(finding_id, status, actor, validated_at)
    return dict(f)


def _max_id_num(rows) -> int:
    """Largest numeric suffix across rows whose ids look like ``PREFIX-####``."""
    mx = 0
    for row in rows:
        try:
            n = int(str(row["id"]).split("-", 1)[1])
        except (IndexError, ValueError, KeyError):
            continue
        mx = max(mx, n)
    return mx


def _next_scan_id() -> str:
    """Next SCAN-#### id (4-digit zero-padded) after the current max.

    Considers BOTH the in-memory seed scans AND any persisted scans from the
    overlay (``store.load_scans()``), so a restart never reuses an id that was
    already persisted. Empty/no-op when no DB is configured.
    """
    mx = max(_max_id_num(_SCANS), _max_id_num(store.load_scans()))
    return f"SCAN-{mx + 1:04d}"


def add_scan(asset: dict, pipeline: str, mode: str, auth_context: Optional[str], by: str) -> dict:
    """Append a new queued scan to the underlying store; returns a copy."""
    scan = {
        "id": _next_scan_id(),
        "target": asset["name"],
        "pipeline": pipeline,
        "type": mode,
        "auth": auth_context if auth_context else "—",
        "status": "queued",
        "progress": 0,
        "started": _now_ts(),
        "findings": 0,
        "by": by,
    }
    _SCANS.append(scan)
    store.save_scan(scan)
    return dict(scan)


# Full-name approver per exception tier (mirrors seed exception rows).
_TIER_APPROVER = {
    "CISO": "CISO",
    "RMC": "Risk Mgmt Committee",
    "Board": "Board Risk Committee",
}


def tier_for_duration(duration_months: int) -> str:
    """Resolve approval tier from duration (mirrors DB CHECK)."""
    if duration_months <= 3:
        return "CISO"
    if duration_months <= 12:
        return "RMC"
    return "Board"


def _next_exception_id() -> str:
    """Next EXC-### id (3-digit zero-padded) after the current max.

    Considers BOTH the in-memory seed exceptions AND any persisted exceptions
    from the overlay (``store.load_exceptions()``), so a restart never reuses a
    persisted id. Empty/no-op when no DB is configured.
    """
    mx = max(_max_id_num(_EXCEPTIONS), _max_id_num(store.load_exceptions()))
    return f"EXC-{mx + 1:03d}"


def add_exception(finding: dict, requested_by: str, duration_months: int, documented_risk: str) -> tuple[dict, str]:
    """Append a new requested exception; returns (copy, tier)."""
    tier = tier_for_duration(duration_months)
    exc = {
        "id": _next_exception_id(),
        "finding": finding["id"],
        "title": finding["title"],
        "asset": finding["asset"],
        "severity": finding["severity"],
        "duration": duration_months,
        "tier": tier,
        "status": "requested",
        "requestedBy": requested_by,
        "approver": _TIER_APPROVER[tier],
        "reviewDate": "—",
        "reason": documented_risk,
    }
    _EXCEPTIONS.append(exc)
    store.save_exception(exc)
    return dict(exc), tier


def _merge_by_id(seed_rows: list[dict], persisted_rows: list[dict]) -> list[dict]:
    """Merge seed + persisted rows de-duped by ``id``, persisted version winning.

    Order is stable: seed rows first (in their existing order, but with their
    content overridden by any persisted row of the same id), then persisted-only
    rows appended in their load order.
    """
    by_id = {r["id"]: dict(r) for r in persisted_rows}
    out: list[dict] = []
    seen: set = set()
    for r in seed_rows:
        rid = r["id"]
        seen.add(rid)
        out.append(dict(by_id.get(rid, r)))
    for r in persisted_rows:
        if r["id"] not in seen:
            out.append(dict(r))
    return out


def findings():
    """Return a fresh shallow copy of the derived findings list.

    Overlay: persisted finding state (``store.load_finding_state()``) is applied
    on top of the seed defaults — DB-backed when available, empty/no-op fallback
    otherwise. Persisted state WINS (it represents a later human action): it
    overrides ``status``, recomputes ``isClosed`` and sets the human-validation
    fields. Mirrors the audit DB-backed/in-memory pattern above.
    """
    state = store.load_finding_state()
    out = []
    for f in _FINDINGS:
        f = dict(f)
        rec = state.get(f["id"]) if state else None
        if rec is not None:
            f["status"] = rec["status"]
            f["isClosed"] = rec["status"] in ("closed", "risk_accepted")
            f["humanValidatedBy"] = rec.get("humanValidatedBy")
            f["humanValidatedAt"] = rec.get("humanValidatedAt")
        out.append(f)
    return out


def assets():
    return [dict(a) for a in ASSETS]


def scans():
    """Seed scans merged with the persistence overlay (``store.load_scans()``).

    De-duplicated by ``id`` with the persisted version winning (a persisted
    update to a seed scan overrides; brand-new persisted scans are appended).
    DB-backed when available; in-memory seed-only fallback otherwise.
    """
    return _merge_by_id(_SCANS, store.load_scans())


def exceptions():
    """Seed exceptions merged with the overlay (``store.load_exceptions()``).

    Same merge-by-``id`` as ``scans()``: persisted wins, new persisted rows
    appended. DB-backed when available; in-memory seed-only fallback otherwise.
    """
    return _merge_by_id(_EXCEPTIONS, store.load_exceptions())


def trend():
    return [dict(t) for t in _TREND]
