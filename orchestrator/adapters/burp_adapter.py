"""
Burp Suite Professional adapter — REST API (Burp's REST/Enterprise API).

Two modes:
  * mode="crawl", auth_context in {unauth, min_priv, max_priv}
        -> spider/crawl in a specific authentication context. Each context
           uses a distinct session/login profile leased from the vault.
  * mode="scan" -> automated active scan over the crawled surface.

The active scan is Burp's audit; it detects issues. It does NOT perform
manual exploitation — that is downstream, human-gated PT. Burp issues map
to OWASP Web/API and SANS/CWE via triage/maps.py.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity, AuthContextName
from .base import assert_targets_in_scope

BURP_BASE = "https://burp.internal:1337"   # on-prem

# Burp severity strings -> normalized band. Burp emits info|low|medium|high
# (it has NO "critical" tier), so "high" maps to Severity.HIGH, not CRITICAL.
_SEVERITY_MAP = {
    "info": Severity.INFO,
    "information": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}

_CWE_RE = re.compile(r"CWE-\d+")


class BurpAdapter:
    name = "burp"

    def __init__(self, mode: str = "scan", auth_context: str | None = None):
        assert mode in ("crawl", "scan")
        self.mode = mode
        self.auth_context = auth_context

    def preflight(self, token: AuthToken) -> None:
        # Web targets are the approved base URLs only.
        assert_targets_in_scope(token.target_addrs, token)
        if self.mode == "crawl":
            # validate auth_context and lease its session profile:
            AuthContextName(self.auth_context)        # raises if invalid
            # _vault_lease(f"webapp/{...}/{self.auth_context}")

    def launch(self, targets: list[str], **kw) -> str:
        # POST /v0.1/scan  with scan_configurations:
        #   crawl -> "Crawl strategy ..." + application_logins[context]
        #   scan  -> "Audit checks - ..." (no manual/exploit modules)
        raise NotImplementedError("wire to Burp REST: POST /v0.1/scan")

    def wait(self, handle: str) -> None:
        # poll GET /v0.1/scan/{task_id} until scan_status == succeeded
        raise NotImplementedError

    def fetch_raw(self, handle: str) -> RawArtifact:
        # GET issues from /v0.1/scan/{id}; persist JSON immutably
        raise NotImplementedError

    # -- parsing --------------------------------------------------------
    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        """Burp REST issues JSON -> CanonicalFinding list.

        The artifact is local JSON (not XML), so XXE does not apply — a plain
        ``json.load`` is fine; we never eval. We accept either the REST
        ``{"issue_events": [{"issue": {...}}, ...]}`` shape or a flat
        ``{"issues": [{...}, ...]}`` array, normalizing both to a list of
        issue dicts. Every field access is defensive (``.get``) so missing
        optional keys never raise.

        Taxonomy enrichment (owasp_web/owasp_api/sans25 via triage/maps.py) is
        a later slice; we leave those lists empty here.
        """
        with open(raw.uri, "r", encoding="utf-8") as fh:
            doc = json.load(fh)

        auth = self._auth_context()

        findings: list[CanonicalFinding] = []
        for issue in _iter_issues(doc):
            if not isinstance(issue, dict):
                continue
            origin = issue.get("origin", "") or ""
            path = issue.get("path", "") or ""
            type_index = issue.get("type_index")
            serial = issue.get("serial_number")
            native_id = str(type_index) if type_index is not None else (
                str(serial) if serial is not None else None
            )
            findings.append(CanonicalFinding(
                asset_id=_asset_id_for(origin),
                source_tool="burp",
                native_id=native_id,
                title=issue.get("name", "") or "",
                description=issue.get("description"),
                severity_normalized=_severity(issue.get("severity")),
                dedup_key=_dedup_key(origin, path, type_index),
                auth_context=auth,
            ))
        return findings

    def _auth_context(self) -> AuthContextName | None:
        """self.auth_context (a str) -> AuthContextName, or None if absent /
        not a recognized value. Never raises on bad input."""
        try:
            return AuthContextName(self.auth_context)
        except (ValueError, KeyError):
            return None


def _iter_issues(doc: object):
    """Yield issue dicts from either supported top-level shape."""
    if isinstance(doc, dict):
        if isinstance(doc.get("issue_events"), list):
            for ev in doc["issue_events"]:
                if isinstance(ev, dict):
                    issue = ev.get("issue")
                    if isinstance(issue, dict):
                        yield issue
            return
        if isinstance(doc.get("issues"), list):
            for issue in doc["issues"]:
                yield issue
            return
    elif isinstance(doc, list):
        for issue in doc:
            yield issue


def _severity(burp_sev: str | None) -> Severity:
    """Burp severity string -> normalized band. Unknown/None -> INFO."""
    if not burp_sev:
        return Severity.INFO
    return _SEVERITY_MAP.get(str(burp_sev).strip().lower(), Severity.INFO)


def _host_of(origin: str) -> str:
    """Host portion of a Burp ``origin`` URL (scheme://host[:port])."""
    if not origin:
        return "unknown"
    host = urlsplit(origin).hostname
    return host or "unknown"


def _asset_id_for(origin: str) -> str:
    return "AST-" + _host_of(origin)


def _dedup_key(origin: str, path: str, type_index: object) -> str:
    """Stable sha256 over origin + path + issue type."""
    sig = f"{origin or ''}|{path or ''}|{type_index if type_index is not None else ''}"
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()
