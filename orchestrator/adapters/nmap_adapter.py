"""
Nmap adapter — CLI (XML output).

Phases: recon (footprinting subset) and full (live-host discovery, port
scan, service & version enumeration). No script-based exploitation:
`--script` is restricted to a safe allowlist (discovery/version only);
`exploit`/`intrusive`/`dos`/`vuln`-exploit categories are forbidden.

Parsing: nmap -oX XML -> defusedxml -> CanonicalFinding (one per
open service; severity Info — these are inventory facts, not vulns).

Live-engine safety notes (launch/wait/fetch_raw):
  * Non-intrusive by construction: TCP connect scan (-sT, unprivileged —
    never -sS/-O/--privileged), service/version detection (-sV), and ONLY
    safe NSE categories (default/discovery/version/safe). Forbidden NSE
    (exploit/intrusive/dos/brute/malware) is rejected by
    `_assert_safe_scripts` before any process starts.
  * argv-based, NEVER a shell: subprocess.Popen is called with an argument
    LIST and no shell=True. Targets are passed as separate argv items and
    are validated (non-empty, must not start with '-') to prevent option/
    argument injection.
  * Scope is enforced by the CALLER: the orchestrator restricts `targets`
    to the token allowlist and `preflight(token)` re-verifies scope via
    `assert_targets_in_scope`. This adapter only ever scans what it is given.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid

import defusedxml.ElementTree as ET

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity
from .base import assert_targets_in_scope

# Module-level registry of running/finished jobs, keyed by opaque handle id.
# value: {"proc", "out_path", "targets", "scan_id", "returncode"}
_JOBS: dict[str, dict] = {}

# Bounded waits so a hung engine can never block the activity indefinitely.
_HOST_TIMEOUT = "120s"      # per-host nmap cap (passed to nmap)
_WAIT_TIMEOUT_S = 300       # our communicate() cap on the whole run

# Only safe, non-intrusive NSE categories are ever permitted.
_ALLOWED_NSE = {"default", "discovery", "version", "safe"}
_FORBIDDEN_NSE = {"exploit", "intrusive", "dos", "brute", "malware"}


class NmapAdapter:
    name = "nmap"

    def preflight(self, token: AuthToken) -> None:
        assert_targets_in_scope(token.target_addrs, token)

    def launch(self, targets: list[str], mode: str = "full", **kw) -> str:
        # 1) Safe NSE set first — reject forbidden categories before anything else.
        scripts = "default,discovery,version,safe" if mode == "full" else "discovery"
        self._assert_safe_scripts(scripts)

        # 2) Validate targets BEFORE locating/launching anything. They are passed
        #    as separate argv items (never a shell), but we still refuse empties
        #    and anything that looks like an option ('-...') to block argument
        #    injection into the nmap command line.
        if not isinstance(targets, list) or not targets:
            raise ValueError("nmap launch requires a non-empty list of targets")
        for t in targets:
            if not isinstance(t, str) or not t or t.startswith("-"):
                raise ValueError(f"refusing unsafe nmap target: {t!r}")

        # 3) Locate the binary. Clear, actionable error if missing.
        binary = shutil.which("nmap")
        if not binary:
            raise RuntimeError("nmap binary not found on PATH")

        # 4) Materialize the -oX output path.
        fd, out_xml_path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)

        # 5) Build argv. -sT = TCP connect (no root); -sV = version; -Pn = no
        #    ping (treat host as up); safe NSE only; bounded per-host timeout.
        #    Deliberately NO -sS / -O / --privileged.
        argv = [
            binary,
            "-sT", "-sV", "-Pn",
            "--script", scripts,
            "-oX", out_xml_path,
            "--host-timeout", _HOST_TIMEOUT,
            *targets,
        ]

        # 6) Start the process. argv list + NO shell=True (no shell injection).
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        handle = uuid.uuid4().hex
        _JOBS[handle] = {
            "proc": proc,
            "out_path": out_xml_path,
            "targets": list(targets),
            "scan_id": kw.get("scan_id", "LIVE"),
            "returncode": None,
        }
        return handle

    def _assert_safe_scripts(self, scripts: str) -> None:
        cats = {c.strip() for c in scripts.split(",")}
        if cats & _FORBIDDEN_NSE or not cats <= _ALLOWED_NSE:
            raise PermissionError(
                f"Nmap NSE categories not permitted: {cats - _ALLOWED_NSE}")

    def wait(self, handle: str) -> None:
        job = _JOBS.get(handle)
        if job is None:
            raise KeyError(f"unknown nmap job handle: {handle!r}")
        proc = job["proc"]
        try:
            _stdout, stderr = proc.communicate(timeout=_WAIT_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise RuntimeError(
                f"nmap job {handle} exceeded {_WAIT_TIMEOUT_S}s; killed")
        job["returncode"] = proc.returncode

        # nmap returns 0 on success. A non-zero exit with no usable output file
        # is a hard error (e.g. bad args, permission, abort).
        out_path = job["out_path"]
        produced = os.path.exists(out_path) and os.path.getsize(out_path) > 0
        if proc.returncode != 0 and not produced:
            detail = (stderr or b"").decode("utf-8", "replace").strip()
            raise RuntimeError(
                f"nmap job {handle} failed (rc={proc.returncode}): {detail}")

    def fetch_raw(self, handle: str) -> RawArtifact:
        job = _JOBS.get(handle)
        if job is None:
            raise KeyError(f"unknown nmap job handle: {handle!r}")
        out_path = job["out_path"]
        if not (os.path.exists(out_path) and os.path.getsize(out_path) > 0):
            raise RuntimeError(
                f"nmap job {handle} produced no output at {out_path}")
        # Do NOT delete the file — the caller / parse() reads it.
        return RawArtifact(
            scan_id=job.get("scan_id", "LIVE"),
            source_tool=self.name,
            uri=out_path,
            native_format="nmap-xml",
        )

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
