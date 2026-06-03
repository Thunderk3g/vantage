#!/usr/bin/env python3
"""Vantage PreToolUse scope-guard hook — enforce the approved-scope boundary
at the AGENT layer.

Vantage's #1 rule: never touch a target that is not in the HOD-approved
inventory. The MCP server + REST API already scope-gate ``request_scan``
server-side (fail-closed 403 ``out_of_scope``). This hook is DEFENSE-IN-DEPTH
one layer earlier: it inspects every ``Bash`` / ``WebFetch`` /
``mcp__vantage__request_scan`` tool call BEFORE it runs and BLOCKS any attempt
to point a recon/scanner tool (or a Vantage scan) at a host that is not in the
approved scope.

I/O contract (Claude Code PreToolUse hook):
  * stdin  : one JSON object
             ``{"hook_event_name","tool_name","tool_input":{...}, ...}``.
  * stdout : to BLOCK, print the hookSpecificOutput JSON (deny/ask) and exit 0.
             To ALLOW / not interfere, print NOTHING and exit 0 (staying silent
             lets the normal flow continue — we never emit ``allow`` because
             that would auto-approve and bypass the human).
  * Never raise / traceback. On any internal error: exit 0 silently
    (fail-OPEN on hook bugs) — EXCEPT once a scan target has been positively
    identified and we cannot confirm it is in scope, in which case we DENY
    (fail-CLOSED on an identified out-of-scope scan).

Pure Python stdlib only — the hook must run anywhere.

Run (wired by hooks.json):
    python "${CLAUDE_PLUGIN_ROOT}/hooks/scope_guard.py"
"""
from __future__ import annotations

import ipaddress
import json
import os
import shlex
import sys
import urllib.request

# --- config -----------------------------------------------------------------
API_BASE = os.environ.get("VANTAGE_API_BASE", "http://localhost:8138").rstrip("/")
_HERE = os.path.dirname(os.path.abspath(__file__))
_SCOPE_FILE = os.path.join(_HERE, "approved_scope.txt")
_API_TIMEOUT = 3.0

# Recon / scanner tool basenames. If a Bash command invokes one of these (as
# the command, or appears as a bare token), it is treated as a scan and its
# target hosts are scope-checked.
SCANNERS = {
    "nmap", "masscan", "nikto", "nuclei", "sqlmap", "gobuster", "dirb",
    "dirbuster", "feroxbuster", "ffuf", "wpscan", "hydra", "medusa",
    "msfconsole", "openvas", "wfuzz", "amass", "subfinder", "httprobe",
    "naabu", "zap-cli", "zaproxy",
}

# Hosts that are never "external" recon targets for WebFetch (doc fetches etc).
_LOCALHOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


# --- output helpers ---------------------------------------------------------
def _emit(decision: str, reason: str) -> None:
    """Print the PreToolUse hookSpecificOutput (deny|ask) and exit 0."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def _allow() -> None:
    """Stay silent (no output) so normal flow continues; exit 0."""
    sys.exit(0)


# --- target extraction ------------------------------------------------------
def _basename(tok: str) -> str:
    """Last path component, lower-cased, without a .exe suffix."""
    b = tok.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    if b.endswith(".exe"):
        b = b[:-4]
    return b


def _is_ipv4(tok: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(tok), ipaddress.IPv4Address)
    except ValueError:
        return False


def _looks_like_host(tok: str) -> bool:
    """A bare hostname (a.b.c…) or an IPv4 literal — a plausible scan target."""
    if _is_ipv4(tok):
        return True
    # hostname: dotted, no scheme, no slash, label chars only.
    if "://" in tok or "/" in tok or "@" in tok:
        return False
    if "." not in tok:
        return False
    labels = tok.split(".")
    if any(not lab for lab in labels):
        return False
    for lab in labels:
        if not all(c.isalnum() or c == "-" for c in lab):
            return False
    # require at least one alphabetic label so we don't catch e.g. "1.2" floats
    if not any(any(c.isalpha() for c in lab) for lab in labels):
        return _is_ipv4(tok)  # all-numeric dotted -> only ok if a real IPv4
    return True


def _host_from_url(tok: str) -> str | None:
    """Extract the host from an http(s):// URL token (strip user/port/path)."""
    low = tok.lower()
    if not (low.startswith("http://") or low.startswith("https://")):
        return None
    rest = tok.split("://", 1)[1]
    # strip path/query/fragment
    for sep in ("/", "?", "#"):
        rest = rest.split(sep, 1)[0]
    # strip userinfo
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    # strip port (but keep IPv6 brackets intact)
    if rest.startswith("["):
        rest = rest.split("]", 1)[0].lstrip("[")
    elif ":" in rest:
        rest = rest.rsplit(":", 1)[0]
    rest = rest.strip()
    return rest or None


def _split_command(cmd: str) -> list[str]:
    """shlex.split, falling back to whitespace split on parse error."""
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def _bash_targets(cmd: str) -> tuple[bool, list[str]]:
    """For a Bash command: (is_scan, [candidate target hosts]).

    A scan is detected when the first token's basename is a scanner, or any
    token is exactly a scanner name. Targets are http(s) URL hosts + bare
    hostname/IPv4 tokens; flags (``-…``) and the scanner token itself ignored.
    """
    toks = _split_command(cmd)
    if not toks:
        return False, []

    is_scan = _basename(toks[0]) in SCANNERS or any(
        _basename(t) in SCANNERS or t.lower() in SCANNERS for t in toks
    )
    if not is_scan:
        return False, []

    targets: list[str] = []
    for t in toks:
        if not t or t.startswith("-"):
            continue
        if _basename(t) in SCANNERS or t.lower() in SCANNERS:
            continue
        host = _host_from_url(t)
        if host:
            targets.append(host)
            continue
        if _looks_like_host(t):
            targets.append(t)
    # de-dup, preserve order
    seen: set = set()
    uniq = []
    for h in targets:
        k = h.lower()
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    return True, uniq


# --- approved inventory -----------------------------------------------------
def _load_from_api() -> tuple[set, set]:
    """(hosts, ids) from GET {API_BASE}/api/assets. Empty sets if unreachable."""
    hosts: set = set()
    ids: set = set()
    try:
        req = urllib.request.Request(
            API_BASE + "/api/assets", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for a in (data or {}).get("assets", []) or []:
            h = str(a.get("host", "")).strip()
            i = str(a.get("id", "")).strip()
            if h:
                hosts.add(h)
            if i:
                ids.add(i)
    except Exception:
        return set(), set()
    return hosts, ids


def _load_from_file() -> tuple[set, set]:
    """(hosts/CIDRs, AST- ids) from approved_scope.txt. Empty if missing."""
    hosts: set = set()
    ids: set = set()
    try:
        with open(_SCOPE_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                entry = line.split("#", 1)[0].strip()
                if not entry:
                    continue
                if entry.upper().startswith("AST-"):
                    ids.add(entry)
                else:
                    hosts.add(entry)
    except Exception:
        return set(), set()
    return hosts, ids


def load_scope() -> tuple[set, set, bool]:
    """Union API + file. Returns (hosts, ids, loaded).

    ``loaded`` is True if ANY source produced at least one entry — when False
    we could not confirm scope at all (fail-closed for an identified scan).
    """
    api_hosts, api_ids = _load_from_api()
    file_hosts, file_ids = _load_from_file()
    hosts = api_hosts | file_hosts
    ids = api_ids | file_ids
    return hosts, ids, bool(hosts or ids)


# --- approval check ---------------------------------------------------------
def _approved_host(host: str, hosts: set, ids: set) -> bool:
    """Is ``host`` approved? Exact (case-insensitive) host/id match, or IP
    inside an approved CIDR."""
    h = host.strip()
    if not h:
        return False
    low = h.lower()

    # exact host / id match (case-insensitive)
    if any(low == x.strip().lower() for x in hosts):
        return True
    if any(low == x.strip().lower() for x in ids):
        return True

    # IP inside an approved CIDR / equal to an approved IP
    target_ip = None
    try:
        target_ip = ipaddress.ip_address(h)
    except ValueError:
        target_ip = None
    if target_ip is not None:
        for x in hosts:
            x = x.strip()
            try:
                net = ipaddress.ip_network(x, strict=False)
            except ValueError:
                continue
            try:
                if target_ip in net:
                    return True
            except TypeError:
                continue  # v4/v6 mismatch
    return False


def _approved_id(asset_id: str, hosts: set, ids: set) -> bool:
    aid = asset_id.strip().lower()
    if not aid:
        return False
    if any(aid == x.strip().lower() for x in ids):
        return True
    # an AST- id might also be listed under hosts in the file union; accept it
    if any(aid == x.strip().lower() for x in hosts):
        return True
    return False


# --- main -------------------------------------------------------------------
def _handle(event: dict) -> None:
    tool = event.get("tool_name") or ""
    ti = event.get("tool_input") or {}
    if not isinstance(ti, dict):
        _allow()

    # --- Vantage scan request (and any mcp__vantage__*scan* variant) -------
    if tool.startswith("mcp__vantage__") and "scan" in tool.lower():
        asset_id = str(ti.get("asset_id") or ti.get("assetId") or "").strip()
        if not asset_id:
            _allow()
        hosts, ids, loaded = load_scope()
        if not loaded:
            _emit("deny",
                  f"Vantage scope-guard: cannot confirm {asset_id} is in the "
                  f"approved scope (inventory unavailable). Refusing the scan "
                  f"(fail-closed).")
        if _approved_id(asset_id, hosts, ids):
            _allow()
        _emit("deny",
              f"Vantage scope-guard: {asset_id} is NOT in the approved asset "
              f"inventory. Scans are restricted to HOD-approved scope; this "
              f"request is blocked (out_of_scope, fail-closed).")

    # --- Bash: detect a scanner/recon tool ---------------------------------
    if tool == "Bash":
        cmd = str(ti.get("command") or "")
        is_scan, targets = _bash_targets(cmd)
        if not is_scan or not targets:
            _allow()  # no scanner, or scanner with no identifiable host
        hosts, ids, loaded = load_scope()
        if not loaded:
            bad = ", ".join(targets)
            _emit("deny",
                  f"Vantage scope-guard: cannot confirm {bad} is in the "
                  f"approved scope (inventory unavailable). Refusing to run a "
                  f"scanner against an unconfirmed host (fail-closed).")
        not_approved = [t for t in targets if not _approved_host(t, hosts, ids)]
        if not_approved:
            bad = ", ".join(not_approved)
            _emit("deny",
                  f"Vantage scope-guard: {bad} is NOT in the approved scan "
                  f"inventory. Running a scanner/recon tool against an "
                  f"out-of-scope host is blocked (fail-closed).")
        _allow()  # every identified target approved

    # --- WebFetch: soft-gate external recon --------------------------------
    if tool == "WebFetch":
        url = str(ti.get("url") or "")
        host = _host_from_url(url)
        if not host:
            _allow()
        if host.lower() in _LOCALHOSTS:
            _allow()  # local docs/dev — never interfere
        hosts, ids, loaded = load_scope()
        if loaded and _approved_host(host, hosts, ids):
            _allow()  # an approved host is fine
        # external / unknown host -> let the human decide (softer than deny)
        _emit("ask",
              f"Vantage scope-guard: WebFetch targets {host}, which is not in "
              f"the approved inventory. Confirm this is an authorized "
              f"recon/lookup target before proceeding.")

    # --- anything else -> don't interfere ----------------------------------
    _allow()


def main() -> int:
    try:
        raw = sys.stdin.read()
    except Exception:
        return 0
    if not raw or not raw.strip():
        return 0
    try:
        event = json.loads(raw)
    except Exception:
        return 0
    if not isinstance(event, dict):
        return 0
    try:
        _handle(event)  # calls sys.exit(0) on every path
    except SystemExit:
        raise
    except Exception:
        # fail-OPEN on an unexpected internal error (never block normal work
        # on a hook bug). The fail-CLOSED scan paths above exit before here.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
