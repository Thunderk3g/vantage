"""
Nuclei adapter — community template-based scanner (OSS set).

Nuclei runs a library of YAML detection templates against a target and
reports matches. It detects exposures/misconfigs/CVEs; it does NOT exploit
anything — matching a template is a detection, full stop. There is no
"exploit" verb here, by construction.

This adapter only PARSES already-captured Nuclei output. The live
launch/wait/fetch_raw verbs are intentionally left unimplemented; a separate
slice wires them to the engine. Nuclei findings map to OWASP/SANS/CWE via
triage/maps.py downstream.

Native format: Nuclei ``-jsonl`` (a.k.a. ``-json``) — ONE JSON object per
line (JSON Lines), e.g.:

    {"template-id":"CVE-2021-44228","info":{"name":"...","severity":"critical",
     "classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0,
     "cvss-metrics":"CVSS:3.1/AV:N/..."}},"host":"https://app.internal",
     "matched-at":"https://app.internal/api","type":"http"}
"""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity
from .base import assert_targets_in_scope

# Nuclei severity strings -> normalized band. Unlike Burp/ZAP, Nuclei DOES
# emit a "critical" tier. Unknown / missing -> INFO (fail to noise-floor).
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class NucleiAdapter:
    name = "nuclei"

    def preflight(self, token: AuthToken) -> None:
        # Nuclei targets are the approved hosts/URLs only. Fail closed.
        assert_targets_in_scope(token.target_addrs, token)

    def launch(self, targets: list[str], **kw) -> str:
        # nuclei -u <targets> -jsonl -o <out> with the approved template set
        # (no intrusive/exploit templates). Engine wiring is a later slice.
        raise NotImplementedError("wire to nuclei engine: nuclei -jsonl")

    def wait(self, handle: str) -> None:
        # block until the nuclei process reaches a terminal state
        raise NotImplementedError

    def fetch_raw(self, handle: str) -> RawArtifact:
        # collect the JSONL output and persist it immutably (object store)
        raise NotImplementedError

    # -- parsing --------------------------------------------------------
    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        """Nuclei JSONL -> CanonicalFinding list.

        The artifact is a local JSONL file (plain JSON, not XML), so XXE does
        not apply — we read line by line and ``json.loads`` each line; we
        never eval. Parsing is defensive at two levels:

          * blank lines are skipped,
          * each line's ``json.loads`` is wrapped in try/except so one
            malformed line never kills the whole batch.

        Every field access is via ``.get`` (including the nested ``info`` and
        ``info.classification`` objects, which may be entirely absent) so a
        record missing optional keys parses cleanly.

        Taxonomy enrichment (owasp_web/owasp_api/sans25 via triage/maps.py) is
        a later slice; we leave those lists empty here.
        """
        findings: list[CanonicalFinding] = []
        path = _local_copy(raw.uri)
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (ValueError, TypeError):
                    # one bad line must not sink the batch
                    continue
                if not isinstance(rec, dict):
                    continue

                info = rec.get("info") or {}
                if not isinstance(info, dict):
                    info = {}
                classification = info.get("classification") or {}
                if not isinstance(classification, dict):
                    classification = {}

                template_id = rec.get("template-id")
                host = rec.get("host", "") or ""
                matched_at = rec.get("matched-at", "") or ""

                title = info.get("name") or template_id or ""

                cve = classification.get("cve-id") or []
                if not isinstance(cve, list):
                    cve = [cve]

                findings.append(CanonicalFinding(
                    asset_id=_asset_id_for(host),
                    source_tool="nuclei",
                    native_id=template_id,
                    title=title,
                    description=info.get("description"),
                    cve=list(cve),
                    cvss_base=_cvss_base(classification.get("cvss-score")),
                    cvss_vector=classification.get("cvss-metrics"),
                    severity_normalized=_severity(info.get("severity")),
                    dedup_key=_dedup_key(host, matched_at, template_id),
                ))
        return findings


def _local_copy(uri: str) -> str:
    """Resolve the artifact URI to a readable local path.

    In this slice artifacts are already local (the fetch step persisted them),
    so the URI is the path. A future slice can fetch from the object store.
    """
    return uri


def _severity(nuclei_sev: str | None) -> Severity:
    """Nuclei severity string -> normalized band. Unknown/None -> INFO."""
    if not nuclei_sev:
        return Severity.INFO
    return _SEVERITY_MAP.get(str(nuclei_sev).strip().lower(), Severity.INFO)


def _cvss_base(score: object) -> float | None:
    """Coerce a Nuclei ``cvss-score`` to float, or None if absent/bad."""
    if score is None:
        return None
    try:
        return float(score)
    except (ValueError, TypeError):
        return None


def _host_of(host: str) -> str:
    """Host portion of a Nuclei ``host`` value.

    ``host`` may be a full URL (``https://app.internal``), a bare host, or a
    ``host:port`` pair. Strip any scheme and any :port, returning just the
    host label.
    """
    if not host:
        return ""
    # If it carries a scheme, urlsplit gives us the hostname cleanly.
    if "://" in host:
        h = urlsplit(host).hostname
        return h or ""
    # Otherwise strip a trailing :port if present (host:port).
    return host.split(":", 1)[0]


def _asset_id_for(host: str) -> str:
    """Deterministic asset id from a Nuclei ``host``. Empty -> AST-unknown."""
    h = _host_of(host)
    if not h:
        return "AST-unknown"
    return "AST-" + h.replace(".", "-")


def _dedup_key(host: str, matched_at: str, template_id: object) -> str:
    """Stable sha256 over host + matched-at + template-id."""
    sig = f"{host or ''}|{matched_at or ''}|{template_id if template_id is not None else ''}"
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()
