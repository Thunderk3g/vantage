"""
Vantage live scan-runner — CLI/worker, scope-gated, scan-and-report only.

This is the thin end-to-end glue that ties ONE adapter to a single authorized
target and produces a triaged finding register:

    scope-check the target
        -> _auth_token(target)              # minimal single-target allowlist
        -> adapter.preflight(token)         # adapter re-verifies scope (fail closed)
        -> adapter.launch/wait/fetch_raw/parse
        -> normalization.normalize_and_triage   # merge -> dedup -> SLA -> taxonomy
        -> {"target", "mode", "tool", "findingCount", "register"}

Authorized internal tool. It is CLI/worker ONLY — there is NO web endpoint, so
it is not remotely triggerable. It scans ONLY loopback (your own host) and the
HOD-approved asset inventory (``api/seed.py`` ``assets()``); any other target is
refused, fail-closed, BEFORE a token is built or the adapter is touched.

The runner never runs a shell: the adapter owns the subprocess and enforces the
safe-NSE allowlist, argv-list (no shell=True) invocation, and target validation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Bootstrap the orchestrator dir onto sys.path so ``from shared import ...``,
# ``import normalization`` and ``from adapters.nmap_adapter import NmapAdapter``
# resolve regardless of the caller's cwd (mirrors pipeline.py's bootstrap).
_ORCH_DIR = os.path.dirname(os.path.abspath(__file__))
if _ORCH_DIR not in sys.path:
    sys.path.insert(0, _ORCH_DIR)

import normalization  # noqa: E402
from shared import (  # noqa: E402
    AuthToken,
    Pipeline,
    ScanMode,
)
from api import seed  # noqa: E402

# Loopback is always authorized — scanning your own host needs no inventory entry.
LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def authorized_targets() -> set[str]:
    """Approved scan targets: loopback UNION the approved-inventory hosts.

    Loopback is always in scope (you may scan your own host). Everything else
    must be an explicit ``host`` from the HOD-approved asset inventory
    (``seed.assets()``)."""
    targets = set(LOOPBACK)
    for asset in seed.assets():
        host = asset.get("host")
        if host:
            targets.add(host)
    return targets


def is_authorized(target: str) -> bool:
    """True iff ``target`` is loopback or an approved-inventory host."""
    return target in authorized_targets()


def _auth_token(target: str, mode: str = "full") -> AuthToken:
    """Build a minimal, single-target AuthToken (``target_addrs=[target]``).

    This token IS the scope allowlist the adapter's ``preflight`` re-verifies:
    the adapter will refuse anything not in ``target_addrs``. We mint it only
    after ``is_authorized`` has already passed, so it can only ever carry an
    in-scope target."""
    return AuthToken(
        authz_id="LIVE-AUTHZ",
        scan_request_id="LIVE",
        pipeline=Pipeline.INFRA,
        mode=ScanMode.BLACKBOX,
        target_asset_ids=[],
        target_addrs=[target],
        window_start="",
        window_end="",
        token_hash="",
        signed_by="run_scan.cli",
    )


def run_live_scan(target: str, mode: str = "full", adapter=None, today=None) -> dict:
    """Scope-gated single-target live scan -> triaged register.

    Fails CLOSED: if the target is not in the approved scope we raise
    ``PermissionError`` BEFORE building a token or touching the adapter, so an
    unauthorized target is never scanned. On success, runs the adapter
    end-to-end and returns the triaged register plus a small summary."""
    # 1) Scope gate FIRST — fail closed before any token/adapter work.
    if not is_authorized(target):
        raise PermissionError(
            f"{target} is not in the approved scan scope (loopback + HOD inventory)"
        )

    # 2) Lazily resolve the default adapter so importing this module never
    #    requires the nmap adapter (and tests can inject a fake).
    if adapter is None:
        from adapters.nmap_adapter import NmapAdapter
        adapter = NmapAdapter()

    # 3) Mint the single-target token; the adapter re-verifies scope.
    token = _auth_token(target, mode)
    adapter.preflight(token)

    # 4) Run the engine end-to-end. The adapter owns the subprocess (argv-list,
    #    no shell, safe-NSE only) — we never run a shell here.
    handle = adapter.launch([target], mode=mode, scan_id="LIVE")
    adapter.wait(handle)
    raw = adapter.fetch_raw(handle)
    findings = adapter.parse(raw)

    # 5) Normalize + triage: merge -> dedup -> SLA -> taxonomy.
    register = normalization.normalize_and_triage(
        {adapter.name: findings}, today=today
    )

    # 6) Hand back the triaged register + a compact summary.
    return {
        "target": target,
        "mode": mode,
        "tool": adapter.name,
        "findingCount": len(register),
        "register": register,
    }


def main(argv=None) -> int:
    """CLI entry point. ``--target`` (required), ``--mode`` full|recon (default
    full), ``--json <path>`` (optional register dump).

    Prints a one-line summary on success and returns 0. On an out-of-scope
    target it prints a clear refusal to stderr and returns exit code 2 — it
    NEVER scans an unauthorized target."""
    parser = argparse.ArgumentParser(
        prog="run_scan",
        description="Vantage scope-gated live scan-runner (loopback + HOD inventory only).",
    )
    parser.add_argument("--target", required=True,
                        help="single target host/IP to scan (must be in approved scope)")
    parser.add_argument("--mode", choices=["full", "recon"], default="full",
                        help="scan mode (default: full)")
    parser.add_argument("--json", dest="json_path", default=None,
                        help="optional path to write the triaged register as JSON")
    args = parser.parse_args(argv)

    try:
        result = run_live_scan(args.target, mode=args.mode)
    except PermissionError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        # Authorized target, but the engine couldn't run (e.g. nmap not installed
        # or a scan error). Clean message instead of a traceback.
        print(f"SCAN ERROR: {exc}", file=sys.stderr)
        return 3

    print(
        f"{result['target']}: {result['tool']} ({result['mode']}) -> "
        f"{result['findingCount']} finding(s)"
    )

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(result["register"], fh, indent=2, default=str)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
