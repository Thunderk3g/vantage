"""
Temporal activities — the side-effecting work of the pipelines.

These are skeletons (Phase 0/1 reference implementation). Each one:
  * documents its security responsibility,
  * shows where the scope re-verification, vault credential lease, audit
    write, and datastore write go,
  * leaves the actual engine call / parsing to the adapters package.

Nothing here exploits a target. The verbs are: authorize, discover,
enumerate, detect, normalize, triage, report.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from temporalio import activity

from shared import (
    ScanRequest, AuthToken, RawArtifact, CanonicalFinding,
)

log = logging.getLogger("scanner.activities")


# =====================================================================
# SCOPE GATE — the single authorization chokepoint.
# =====================================================================
@activity.defn
async def scope_gate_authorize(req: ScanRequest) -> AuthToken:
    """Resolve the target query against the HOD-approved inventory and mint
    a signed, time-boxed authorization token.

    HARD RULE: a target absent from `assets WHERE approved_in_inventory` is
    refused. If ANY resolved target is out of scope, the whole request is
    denied (fail closed). Writes an audit row either way.
    """
    # 1. Resolve target_query -> approved assets only.
    #    SELECT asset_id, ip, app_base_url FROM assets
    #    WHERE approved_in_inventory AND <target_query predicates>;
    approved = _resolve_approved_targets(req.target_query)
    if not approved:
        _audit("system", "SCOPE_DENIED", "scan_request", req.scan_request_id,
               after={"reason": "no approved targets matched"})
        raise activity.ApplicationError(
            "Scope gate: no approved in-scope targets.", non_retryable=True
        )

    # 2. Mint signed token (Ed25519 sign over canonical claims), store hash.
    claims = {
        "scan_request_id": req.scan_request_id,
        "targets": [a["asset_id"] for a in approved],
        "window_start": req.window_start,
        "window_end": req.window_end,
        "mode": req.mode.value,
    }
    signed_token = _sign_token(claims)            # vault-held signing key
    token_hash = hashlib.sha256(signed_token).hexdigest()

    authz_id = _persist_authorization(req, approved, token_hash)
    _audit("system", "SCOPE_AUTHORIZED", "scope_authorization", authz_id,
           after={"target_count": len(approved)})

    return AuthToken(
        authz_id=authz_id,
        scan_request_id=req.scan_request_id,
        pipeline=req.pipeline,
        mode=req.mode,
        target_asset_ids=[a["asset_id"] for a in approved],
        target_addrs=[a["addr"] for a in approved],   # the runtime allowlist
        window_start=req.window_start,
        window_end=req.window_end,
        token_hash=token_hash,
        signed_by=req.requested_by,
    )


def _enforce_scope(token: AuthToken) -> None:
    """Re-verify the authorization at the moment of use (TOCTOU defense).

    Called by every scanning activity before any packet is sent. Checks:
      * token not expired / revoked / consumed-out-of-window,
      * the addresses about to be scanned are all in token.target_addrs.
    Raises (fail closed) on any mismatch.
    """
    now = datetime.now(timezone.utc).isoformat()
    if not (token.window_start <= now <= token.window_end):
        raise activity.ApplicationError(
            "Authorization window expired.", non_retryable=True)
    if not _authorization_still_valid(token.authz_id):
        raise activity.ApplicationError(
            "Authorization revoked or consumed.", non_retryable=True)
    # adapters must additionally intersect their target list with
    # token.target_addrs and refuse anything outside it.


# =====================================================================
# SCAN BOOKKEEPING
# =====================================================================
@activity.defn
async def create_scan_record(req: ScanRequest, token: AuthToken) -> str:
    scan_id = _insert_scan(req, token)
    _audit("system", "SCAN_CREATED", "scan", scan_id,
           after={"pipeline": req.pipeline.value, "mode": req.mode.value})
    return scan_id


@activity.defn
async def record_phase(scan_id: str, phase: str) -> None:
    # There is no 'exploit' phase to record; the workflow guards this too.
    _update_scan_phase(scan_id, phase)
    _audit("system", "PHASE_ENTERED", "scan", scan_id, after={"phase": phase})


@activity.defn
async def finalize_scan(scan_id: str) -> None:
    _update_scan_status(scan_id, "completed")
    _audit("system", "SCAN_COMPLETED", "scan", scan_id,
           after={"note": "stopped before exploitation; human review pending"})


# =====================================================================
# INFRA ENGINE ACTIVITIES
# =====================================================================
@activity.defn
async def run_recon(scan_id: str, token: AuthToken) -> RawArtifact:
    _enforce_scope(token)
    from adapters.nmap_adapter import NmapAdapter      # footprinting subset
    return _run_adapter(NmapAdapter(), scan_id, token, mode="recon")


@activity.defn
async def run_nmap(scan_id: str, token: AuthToken) -> RawArtifact:
    _enforce_scope(token)
    from adapters.nmap_adapter import NmapAdapter
    return _run_adapter(NmapAdapter(), scan_id, token, mode="full")


@activity.defn
async def run_nessus_va(scan_id: str, token: AuthToken) -> RawArtifact:
    _enforce_scope(token)
    from adapters.nessus_adapter import NessusAdapter
    return _run_adapter(NessusAdapter(policy="VA"), scan_id, token)


@activity.defn
async def run_cis_review(scan_id: str, token: AuthToken) -> RawArtifact:
    _enforce_scope(token)
    from adapters.nessus_adapter import NessusAdapter
    # Credentialed compliance scan; creds leased from vault inside adapter.
    return _run_adapter(NessusAdapter(policy="CIS"), scan_id, token)


# =====================================================================
# WEBAPP ENGINE ACTIVITIES
# =====================================================================
@activity.defn
async def run_nikto(scan_id: str, token: AuthToken) -> RawArtifact:
    _enforce_scope(token)
    from adapters.nikto_adapter import NiktoAdapter
    return _run_adapter(NiktoAdapter(), scan_id, token)


@activity.defn
async def run_burp_crawl(scan_id: str, token: AuthToken, ctx: str) -> RawArtifact:
    _enforce_scope(token)
    from adapters.burp_adapter import BurpAdapter
    # Each auth context uses a distinct session profile leased from vault.
    return _run_adapter(BurpAdapter(mode="crawl", auth_context=ctx),
                        scan_id, token)


@activity.defn
async def run_burp_scan(scan_id: str, token: AuthToken) -> RawArtifact:
    _enforce_scope(token)
    from adapters.burp_adapter import BurpAdapter
    return _run_adapter(BurpAdapter(mode="scan"), scan_id, token)


# =====================================================================
# TRIAGE — deterministic first, LLM second. See triage/ package.
# =====================================================================
@activity.defn
async def normalize_and_triage(scan_id: str) -> int:
    """Normalize raw artifacts -> CanonicalFinding, then:
       1. deterministic dedup + severity-band + SLA + OWASP/SANS/CIS map,
       2. LLM batch pass (redacted) for fuzzy dedup, FP scoring, notes.
    Returns the number of canonical findings persisted.
    """
    from triage.engine import run_triage           # see §2 of architecture
    findings: list[CanonicalFinding] = run_triage(scan_id)
    _persist_findings_and_slas(scan_id, findings)
    _audit("system", "TRIAGE_COMPLETED", "scan", scan_id,
           after={"finding_count": len(findings)})
    return len(findings)


# =====================================================================
# REPORTING — xlsx / docx / dual-password pdf
# =====================================================================
@activity.defn
async def generate_reports(scan_id: str) -> None:
    from reporting.export import build_reports       # see reporting package
    bundle = build_reports(scan_id)                   # pdf is 2-password
    _audit("system", "REPORTS_GENERATED", "scan", scan_id,
           after={"pdf": bundle.pdf_uri})


# ---------------------------------------------------------------------
# Internal helpers (stubs — wired to Postgres / vault / object store in
# the real build). Left as functions so the activity bodies read clearly.
# ---------------------------------------------------------------------
def _run_adapter(adapter, scan_id, token, **kw) -> RawArtifact:
    adapter.preflight(token)                          # re-checks scope again
    handle = adapter.launch(token.target_addrs, **kw)
    adapter.wait(handle)
    raw = adapter.fetch_raw(handle)                   # stored immutably
    _audit("system", "ENGINE_RUN", "scan", scan_id,
           after={"tool": raw.source_tool, "uri": raw.uri})
    return raw


def _resolve_approved_targets(query: dict) -> list[dict]: ...
def _sign_token(claims: dict) -> bytes: ...
def _persist_authorization(req, approved, token_hash) -> str: ...
def _authorization_still_valid(authz_id: str) -> bool: ...
def _insert_scan(req, token) -> str: ...
def _update_scan_phase(scan_id: str, phase: str) -> None: ...
def _update_scan_status(scan_id: str, status: str) -> None: ...
def _persist_findings_and_slas(scan_id, findings) -> None: ...
def _audit(actor, action, entity_type, entity_id, *, after=None, before=None) -> None: ...
