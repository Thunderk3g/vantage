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

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity, AuthContextName
from .base import assert_targets_in_scope

BURP_BASE = "https://burp.internal:1337"   # on-prem


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

    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        # JSON issues -> CanonicalFinding; carry auth_context + confidence;
        # map issue type_index -> owasp_web/owasp_api/sans25 via maps.py
        raise NotImplementedError
