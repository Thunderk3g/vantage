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
        # defusedxml hardens against XXE/entity-expansion in untrusted scanner
        # output. We never use the stdlib XML parser here.
        tree = ET.parse(_local_copy(raw.uri))
        out: list[CanonicalFinding] = []
        for host in tree.iterfind("host"):
            addr = _host_addr(host)
            for port in host.iterfind(".//port"):
                state = port.find("state")
                # Only OPEN services are inventory facts. Skip closed/filtered
                # (and ports with no <state> at all — state unknown != open).
                if state is None or state.get("state") != "open":
                    continue

                svc = port.find("service")
                portid = port.get("portid") or "?"
                proto = port.get("protocol") or "tcp"

                # <service> and any of its attributes may be absent on a
                # bare port scan (no -sV) or on services nmap couldn't fp.
                svc_name = (svc.get("name") if svc is not None else None) or "unknown"
                product = (svc.get("product") if svc is not None else None) or ""
                version = (svc.get("version") if svc is not None else None) or ""
                banner = (product + " " + version).strip()

                out.append(CanonicalFinding(
                    asset_id=_asset_id_for(addr),
                    source_tool=self.name,
                    native_id=f"{portid}/{proto}",
                    title=f"Open service {svc_name} on {portid}/{proto}",
                    description=banner or None,
                    severity_normalized=Severity.INFO,
                    dedup_key=f"{addr}|{portid}/{proto}|svc",
                ))
        return out


def _host_addr(host) -> str:
    """Best-effort host identifier from an nmap <host> element.

    Prefers an IP/MAC <address addr=...>; falls back to the first
    <hostnames><hostname name=...> if no address is present. Returns ""
    when nothing identifies the host (parse() stays robust either way)."""
    for addr_el in host.iterfind("address"):
        addr = addr_el.get("addr")
        if addr:
            return addr
    hn = host.find(".//hostname")
    if hn is not None and hn.get("name"):
        return hn.get("name")
    return ""


def _local_copy(uri: str) -> str:
    """Resolve the raw-artifact URI to a path the parser can open.

    For VA we never fetch over the network in parse(): the uri is treated as
    a local filesystem path to the already-materialized nmap -oX output."""
    return uri


def _asset_id_for(addr: str) -> str:
    """Deterministic asset id from a host address.

    Identical addresses MUST map to identical asset ids — dedup depends on
    it. Empty/missing addresses collapse to a single stable sentinel."""
    if not addr:
        return "AST-unknown"
    return "AST-" + addr.replace(".", "-").replace(":", "-")
