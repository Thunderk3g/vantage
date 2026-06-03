"""Scan diff / closure verification — compare two triaged registers.

Pure and deterministic. Given a *baseline* scan register and a *current*
(retest) register — each a list of triaged finding dicts (the pipeline/triage
output, which already carries a stable ``dedup_key``) — it reports which
findings were RESOLVED (present in baseline, gone in current), which PERSIST
(in both), which are NEW (only in current), and which REGRESSED (still present
but the severity band went up). It also verifies closure for a single finding.

This reads data only — it never launches a scan or acts on a target, so it
stays inside the scan-and-report boundary. "Closure verification vs a prior
scan" is exactly a diff where the finding's signature is absent from the latest
register.
"""
from __future__ import annotations

import hashlib

# Severity ordering for regression detection (matches triage bands).
_BAND = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def signature(finding: dict) -> str:
    """Stable cross-scan identity for a finding.

    Prefers the triage ``dedup_key`` (asset + location + CVE/title hash, already
    stable across runs and across tools). Falls back to a hash of asset + CVE(s)
    or normalized title for raw dicts that predate triage.
    """
    dk = finding.get("dedup_key")
    if dk:
        return str(dk)
    asset = str(finding.get("asset_id") or finding.get("assetId") or "").strip().lower()
    cves = finding.get("cve") or []
    if cves:
        key = "cve:" + ",".join(sorted(str(c).strip().upper() for c in cves if c))
    else:
        title = " ".join(str(finding.get("title") or "").lower().split())
        key = "ttl:" + title
    return hashlib.sha256((asset + "\x1f" + key).encode("utf-8")).hexdigest()


def _band(finding: dict) -> int:
    sev = str(finding.get("severity_normalized") or finding.get("severity") or "info").lower()
    return _BAND.get(sev, 0)


def _summary(finding: dict) -> dict:
    """The compact, JSON-safe view of a finding used in diff output."""
    return {
        "title": finding.get("title"),
        "assetId": finding.get("asset_id") or finding.get("assetId"),
        "severity": str(finding.get("severity_normalized") or finding.get("severity") or "info").lower(),
        "sourceTool": finding.get("source_tool"),
        "cve": finding.get("cve") or [],
        "signature": signature(finding),
    }


def diff_scans(baseline: list[dict], current: list[dict]) -> dict:
    """Diff two registers by signature.

    Returns ``{resolved, new, persisting, regressed, counts}`` where each list
    holds compact finding summaries. ``regressed`` entries also carry
    ``fromSeverity`` (the baseline band). Deterministic: stable input order is
    preserved within each bucket.
    """
    b = {signature(f): f for f in baseline}
    c = {signature(f): f for f in current}

    resolved = [_summary(b[k]) for k in b if k not in c]
    new = [_summary(c[k]) for k in c if k not in b]

    persisting: list[dict] = []
    regressed: list[dict] = []
    for k, bf in b.items():
        cf = c.get(k)
        if cf is None:
            continue
        persisting.append(_summary(cf))
        if _band(cf) > _band(bf):
            entry = _summary(cf)
            entry["fromSeverity"] = str(bf.get("severity_normalized") or bf.get("severity") or "info").lower()
            regressed.append(entry)

    counts = {
        "baseline": len(b),
        "current": len(c),
        "resolved": len(resolved),
        "new": len(new),
        "persisting": len(persisting),
        "regressed": len(regressed),
    }
    return {"resolved": resolved, "new": new, "persisting": persisting,
            "regressed": regressed, "counts": counts}


def verify_closure(finding: dict, current: list[dict]) -> dict:
    """Closure verification for one finding against the latest register.

    ``verifiedResolved`` is True iff the finding's signature is absent from
    ``current`` (i.e. the re-scan no longer reports it). Never auto-closes — a
    human still makes the closure decision; this only provides the evidence.
    """
    sig = signature(finding)
    keys = {signature(f) for f in current}
    present = sig in keys
    return {"signature": sig, "stillPresent": present, "verifiedResolved": not present}
