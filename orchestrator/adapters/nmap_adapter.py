"""
Nmap adapter — CLI (XML output).

Phases: recon (footprinting subset) and full (live-host discovery, port
scan, service & version enumeration). No script-based exploitation:
`--script` is restricted to a safe allowlist (discovery/version only);
`exploit`/`intrusive`/`dos`/`vuln`-exploit categories are forbidden.

Parsing: nmap -oX XML -> defusedxml -> CanonicalFinding (one per
open service; severity Info — these are inventory facts, not vulns).
"""
from __future__ import annotations

import defusedxml.ElementTree as ET

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity
from .base import assert_targets_in_scope

# Only safe, non-intrusive NSE categories are ever permitted.
_ALLOWED_NSE = {"default", "discovery", "version", "safe"}
_FORBIDDEN_NSE = {"exploit", "intrusive", "dos", "brute", "malware"}


class NmapAdapter:
    name = "nmap"

    def preflight(self, token: AuthToken) -> None:
        assert_targets_in_scope(token.target_addrs, token)

    def launch(self, targets: list[str], mode: str = "full", **kw) -> str:
        scripts = "default,discovery,version,safe" if mode == "full" else "discovery"
        self._assert_safe_scripts(scripts)
        # subprocess: nmap -sV -O --script <scripts> -oX <out> <targets...>
        # targets are exactly the allowlist; rate limits applied centrally.
        raise NotImplementedError("wire to nmap CLI (subprocess, -oX)")

    def _assert_safe_scripts(self, scripts: str) -> None:
        cats = {c.strip() for c in scripts.split(",")}
        if cats & _FORBIDDEN_NSE or not cats <= _ALLOWED_NSE:
            raise PermissionError(
                f"Nmap NSE categories not permitted: {cats - _ALLOWED_NSE}")

    def wait(self, handle: str) -> None: ...
    def fetch_raw(self, handle: str) -> RawArtifact: ...

    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        tree = ET.parse(_local_copy(raw.uri))
        out: list[CanonicalFinding] = []
        for host in tree.iterfind("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else ""
            for port in host.iterfind(".//port"):
                svc = port.find("service")
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                out.append(CanonicalFinding(
                    asset_id=_asset_id_for(addr),
                    source_tool=self.name,
                    native_id=f"{port.get('portid')}/{port.get('protocol')}",
                    title=f"Open service {svc.get('name') if svc is not None else '?'}"
                          f" on {port.get('portid')}",
                    description=(svc.get("product", "") + " " +
                                 svc.get("version", "")).strip() if svc is not None else None,
                    severity_normalized=Severity.INFO,
                    dedup_key=f"{addr}|{port.get('portid')}|svc",
                ))
        return out


def _local_copy(uri: str) -> str: ...
def _asset_id_for(addr: str) -> str: ...
