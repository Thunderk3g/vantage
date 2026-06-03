"""
OWASP ZAP adapter — OSS web DAST (the license-free counterpart to Burp).

This adapter PARSES an already-captured ZAP JSON report into the canonical
finding shape. It NEVER launches a live scan, spiders, or exploits anything —
the launch/wait/fetch_raw verbs are intentionally left unimplemented.

Real ZAP JSON report (``-r`` / report generation) is shaped like:

    {
      "@version": "2.14.0",
      "site": [
        { "@name": "https://app.internal", "@host": "app.internal",
          "@port": "443",
          "alerts": [
            { "pluginid": "40012", "alertRef": "40012-1",
              "name": "Cross Site Scripting (Reflected)",
              "riskcode": "3", "confidence": "2", "riskdesc": "High (Medium)",
              "desc": "<p>...</p>", "solution": "<p>...</p>",
              "cweid": "79", "wascid": "8",
              "instances": [ {"uri": ".../search", "method": "GET",
                              "param": "q"} ] },
            ...
          ] } ] }

``riskcode`` is the severity band: 3=High, 2=Medium, 1=Low, 0=Informational.
ZAP has NO "critical" tier, so riskcode 3 maps to Severity.HIGH (never
CRITICAL). ZAP reports CWE (not CVE), so ``cve`` is always left empty here;
OWASP/SANS taxonomy is enriched downstream by triage from the title keyword,
so this adapter does not import triage/maps.py.
"""
from __future__ import annotations

import hashlib
import json

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity
from .base import assert_targets_in_scope

# ZAP riskcode -> normalized severity band. ZAP has NO "critical" tier, so the
# top band (3=High) maps to Severity.HIGH, not CRITICAL. Unknown -> INFO.
_RISKCODE_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}


class ZapAdapter:
    name = "zap"

    def preflight(self, token: AuthToken) -> None:
        # Web targets are the approved base URLs only (fail closed).
        assert_targets_in_scope(token.target_addrs, token)

    def launch(self, targets: list[str], **kw) -> str:
        # Live DAST is out of scope for this adapter: it only parses an
        # already-captured report. Would wire to the ZAP daemon API
        # (POST /JSON/ascan/action/scan) — deliberately not implemented.
        raise NotImplementedError("zap adapter parses captured reports only")

    def wait(self, handle: str) -> None: ...
    def fetch_raw(self, handle: str) -> RawArtifact: ...

    # -- parsing --------------------------------------------------------
    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        """ZAP JSON report -> CanonicalFinding list.

        The artifact is local JSON (not XML), so XXE does not apply — a plain
        ``json.load`` is fine; we never eval. We iterate ``site[]`` -> each
        site's ``alerts[]`` and emit one finding per alert. Every field access
        is defensive (``.get``) so a missing ``alerts``, missing ``instances``,
        or any missing field never raises.
        """
        with open(_local_copy(raw.uri), "r", encoding="utf-8") as fh:
            doc = json.load(fh)

        sites = doc.get("site") if isinstance(doc, dict) else None
        if not isinstance(sites, list):
            sites = []

        findings: list[CanonicalFinding] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            asset_id = _asset_id_for(site)
            host = _host_of(site)
            alerts = site.get("alerts")
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                pluginid = alert.get("pluginid")
                first_uri = _first_instance_uri(alert)
                findings.append(CanonicalFinding(
                    asset_id=asset_id,
                    source_tool=self.name,
                    native_id=pluginid,
                    title=alert.get("name", "") or "",
                    description=alert.get("desc"),
                    severity_normalized=_severity(alert.get("riskcode")),
                    dedup_key=_dedup_key(host, first_uri, pluginid),
                ))
        return findings


def _local_copy(uri: str) -> str:
    """Resolve the raw artifact URI to a local, parseable path.

    The artifact is already materialized locally for parsing, so the URI is
    the path. Returned unchanged.
    """
    return uri


def _severity(riskcode: object) -> Severity:
    """ZAP riskcode -> normalized band. Unknown/None -> INFO."""
    if riskcode is None:
        return Severity.INFO
    return _RISKCODE_MAP.get(str(riskcode).strip(), Severity.INFO)


def _host_of(site: dict) -> str:
    """Host of a ZAP ``site`` entry: prefer ``@host``, else parse ``@name``."""
    host = (site.get("@host") or "").strip()
    if host:
        return host
    name = (site.get("@name") or "").strip()
    if name:
        # @name is a base URL like "https://app.internal[:443]"; strip the
        # scheme and any port to recover the bare host.
        rest = name.split("://", 1)[-1]
        rest = rest.split("/", 1)[0]
        rest = rest.split(":", 1)[0]
        if rest:
            return rest
    return ""


def _asset_id_for(site: dict) -> str:
    """Deterministic, host-derived asset id. Empty host -> AST-unknown."""
    host = _host_of(site)
    if not host:
        return "AST-unknown"
    return "AST-" + host.replace(".", "-")


def _first_instance_uri(alert: dict) -> str:
    """URI of the first ``instances`` entry, or "" if none/malformed."""
    instances = alert.get("instances")
    if isinstance(instances, list) and instances:
        first = instances[0]
        if isinstance(first, dict):
            return first.get("uri", "") or ""
    return ""


def _dedup_key(host: str, first_uri: str, pluginid: object) -> str:
    """Stable sha256 over host + first-instance-uri + pluginid."""
    sig = f"{host or ''}|{first_uri or ''}|{pluginid if pluginid is not None else ''}"
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()
