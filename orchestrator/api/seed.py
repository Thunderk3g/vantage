"""Vantage seed data + derivation logic.

Ported faithfully from ``frontend/data.js`` (the single source of truth).
TODAY is pinned to 2026-06-01 so SLA countdowns are stable and match the design.
Dates are converted to ISO ``YYYY-MM-DD`` strings (or None) per the API contract,
whereas data.js keeps native Date objects.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Optional

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


def findings():
    """Return a fresh shallow copy of the derived findings list."""
    return [dict(f) for f in _FINDINGS]


def assets():
    return [dict(a) for a in ASSETS]


def scans():
    return [dict(s) for s in _SCANS]


def exceptions():
    return [dict(e) for e in _EXCEPTIONS]


def trend():
    return [dict(t) for t in _TREND]
