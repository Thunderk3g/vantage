"""
Nessus Professional adapter — REST API.

Drives two policy templates from one adapter:
  * policy="VA"  -> vulnerability assessment
  * policy="CIS" -> credentialed CIS compliance/config review

Auth: Nessus access-key + secret-key leased from the vault (never in config).
CIS scans additionally lease a least-privilege credentialed audit account
(Windows local-audit / Linux sudo-restricted audit role) per target class.

Result parsing: export `.nessus` XML, map plugins -> CanonicalFinding,
CVSS base -> normalized severity band, plugin family -> CIS control /
asset-class tag via lookup tables (triage/maps.py).
"""
from __future__ import annotations

# defusedxml hardens against XXE / billion-laughs. Scanner output is
# semi-trusted (it embeds attacker-controlled banners/headers), so never
# parse it with the stdlib parser.
import defusedxml.ElementTree as ET

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity
from .base import assert_targets_in_scope

NESSUS_BASE = "https://nessus.internal:8834"   # on-prem, egress-controlled


class NessusAdapter:
    name = "nessus"

    def __init__(self, policy: str = "VA"):
        assert policy in ("VA", "CIS")
        self.policy = policy
        self.name = "nessus" if policy == "VA" else "nessus-cis"

    # -- lifecycle ------------------------------------------------------
    def preflight(self, token: AuthToken) -> None:
        # Nessus targets are the resolved in-scope addresses only.
        assert_targets_in_scope(token.target_addrs, token)
        # _vault_lease("nessus/api"); for CIS also _vault_lease("audit/<class>")

    def launch(self, targets: list[str], **kw) -> str:
        # POST /scans  with policy_id + text_targets = ",".join(targets)
        # POST /scans/{id}/launch  -> returns scan_uuid
        # Targets are exactly the allowlist; Nessus never sees anything else.
        raise NotImplementedError("wire to Nessus REST: create + launch scan")

    def wait(self, handle: str) -> None:
        # poll GET /scans/{id} until status in {completed, canceled}
        raise NotImplementedError

    def fetch_raw(self, handle: str) -> RawArtifact:
        # POST /scans/{id}/export (format=nessus) -> download token -> file
        # store to MinIO object-lock bucket; return pointer
        raise NotImplementedError

    # -- parsing --------------------------------------------------------
    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        tree = ET.parse(_local_copy(raw.uri))
        findings: list[CanonicalFinding] = []
        for host in tree.iterfind(".//ReportHost"):
            addr = host.get("name", "") or ""
            for item in host.iterfind("ReportItem"):
                # CVSS may be absent (e.g. compliance/info items); fall back to
                # the Nessus 0..4 `severity` attribute inside _band.
                cvss = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score")
                cvss_f = _to_float(cvss)
                # cve may appear zero, once, or many times.
                cves = [e.text.strip() for e in item.iterfind("cve")
                        if e.text and e.text.strip()]
                # description may be missing entirely.
                desc = item.findtext("description")
                if desc is not None:
                    desc = desc.strip() or None
                findings.append(CanonicalFinding(
                    asset_id=_asset_id_for(addr),
                    source_tool=self.name,
                    native_id=item.get("pluginID"),
                    title=item.get("pluginName", "") or "",
                    description=desc,
                    cve=cves,
                    cvss_base=cvss_f,
                    cvss_vector=item.findtext("cvss3_vector"),
                    severity_normalized=_band(cvss_f, item.get("severity")),
                    cis_control=(_cis_control(item) if self.policy == "CIS" else None),
                    dedup_key=_dedup_key(addr, item),
                ))
        return findings


def _band(cvss: float | None, nessus_sev: str | None) -> Severity:
    """CVSS base -> normalized band. Deterministic; never LLM-decided."""
    if cvss is not None:
        if cvss >= 9.0:
            return Severity.CRITICAL
        if cvss >= 7.0:
            return Severity.HIGH
        if cvss >= 4.0:
            return Severity.MEDIUM
        if cvss > 0.0:
            return Severity.LOW
    # fall back to Nessus severity (0..4) when no CVSS present
    return {"4": Severity.CRITICAL, "3": Severity.HIGH, "2": Severity.MEDIUM,
            "1": Severity.LOW}.get(nessus_sev or "0", Severity.INFO)


def _dedup_key(addr: str, item) -> str:
    import hashlib
    sig = f"{addr}|{item.get('port')}|{item.get('pluginID')}"
    return hashlib.sha256(sig.encode()).hexdigest()


def _to_float(value: str | None) -> float | None:
    """Parse a CVSS string defensively; messy/blank scores -> None."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _local_copy(uri: str) -> str:
    """Resolve the raw-artifact pointer to a local filesystem path.

    In production this would pull the object out of the object store to a
    temp file. Here the artifact is already local, so the uri *is* the path.
    """
    return uri


def _asset_id_for(addr: str) -> str:
    """Deterministic asset id from a host address (IPv4/IPv6/hostname).

    Same address -> same id on every run (no DB round-trip, no randomness),
    so findings dedup/correlate across scans.
    """
    addr = (addr or "").strip()
    if not addr:
        return "AST-unknown"
    return "AST-" + addr.replace(".", "-").replace(":", "-")


def _cis_control(item) -> str | None:
    """Best-effort CIS control reference from a Nessus compliance ReportItem.

    Credentialed CIS-audit plugins emit `cm:`-namespaced compliance children
    (e.g. <cm:compliance-reference>CIS|5.2</cm:compliance-reference> or
    <cm:compliance-control-id>...). defusedxml keeps namespaced tags as
    `{uri}local` (or bare `cm:local` when undeclared), so we match on the
    local part of the tag rather than a fixed namespace.

    Defensive by contract: VA items (and any item with no compliance data)
    return None instead of raising.
    """
    if item is None:
        return None

    def _localname(tag) -> str:
        if not isinstance(tag, str):
            return ""
        # Strip an `{namespace}` prefix and/or a `prefix:` prefix.
        if "}" in tag:
            tag = tag.rsplit("}", 1)[-1]
        if ":" in tag:
            tag = tag.rsplit(":", 1)[-1]
        return tag.lower()

    # 1) Direct compliance-reference / control-id children.
    for child in list(item):
        local = _localname(getattr(child, "tag", ""))
        text = (child.text or "").strip() if child.text else ""
        if not text:
            continue
        if "compliance" in local and "cis" in text.lower():
            return _normalize_cis(text)
        if "control-id" in local or local in ("compliance-control-id", "cis_control"):
            return _normalize_cis(text)

    # 2) A see_also / plugin field that references a CIS control.
    for tagname in ("cis_control", "see_also"):
        text = item.findtext(tagname)
        if text and "cis" in text.lower():
            ref = _normalize_cis(text)
            if ref:
                return ref

    return None


def _normalize_cis(text: str) -> str | None:
    """Pull a `CIS-<n.n>` token out of a free-text compliance reference.

    Accepts 'CIS|5.2', 'CIS 5.2', 'CIS-5.2', 'CIS Control 5.2 ...' and
    normalizes to 'CIS-5.2'. Returns the trimmed text if no number is found
    but the string still mentions CIS, else None.
    """
    import re
    if not text:
        return None
    m = re.search(r"CIS[\s|:_-]*(?:control[\s:#-]*)?(\d+(?:\.\d+)*)", text, re.I)
    if m:
        return "CIS-" + m.group(1)
    if "cis" in text.lower():
        return text.strip()
    return None
