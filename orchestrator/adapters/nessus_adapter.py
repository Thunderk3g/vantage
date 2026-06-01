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
            addr = host.get("name", "")
            for item in host.iterfind("ReportItem"):
                cvss = item.findtext("cvss3_base_score") or item.findtext("cvss_base_score")
                cvss_f = float(cvss) if cvss else None
                findings.append(CanonicalFinding(
                    asset_id=_asset_id_for(addr),
                    source_tool=self.name,
                    native_id=item.get("pluginID"),
                    title=item.get("pluginName", ""),
                    description=item.findtext("description"),
                    cve=[e.text for e in item.iterfind("cve") if e.text],
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


def _local_copy(uri: str) -> str: ...
def _asset_id_for(addr: str) -> str: ...
def _cis_control(item) -> str | None: ...
