"""Standalone unit test for the Vantage PreToolUse scope-guard hook.

Drives ``scope_guard.py`` as a SUBPROCESS (the way Claude Code runs it): feed a
PreToolUse event on stdin, capture stdout, parse the decision. No network is
touched — ``VANTAGE_API_BASE`` is pointed at an unreachable port (127.0.0.1:9)
so the guard relies on the committed ``approved_scope.txt`` offline fallback.

Style mirrors the repo's self-tests (plain asserts, one ``[ok]`` line per
check, ``main()`` returning 0/1, ``raise SystemExit(main())``). No pytest.

Run:  python plugin/hooks/test_scope_guard.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "scope_guard.py")

PASS = []


def ok(msg):
    PASS.append(msg)
    print("  [ok] " + msg)


def run_guard(event: dict, *, api_base: str = "http://127.0.0.1:9") -> dict:
    """Run the guard with ``event`` on stdin. Returns the parsed decision dict
    (``{}`` when the guard stayed silent = allow)."""
    env = dict(os.environ)
    env["VANTAGE_API_BASE"] = api_base  # unreachable -> rely on the file
    proc = subprocess.run(
        [sys.executable, GUARD],
        input=json.dumps(event).encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, timeout=20,
    )
    assert proc.returncode == 0, f"guard exited {proc.returncode}: {proc.stderr!r}"
    out = proc.stdout.decode("utf-8").strip()
    if not out:
        return {}  # silent = allow
    parsed = json.loads(out)
    return parsed["hookSpecificOutput"]


def _bash(cmd: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": cmd, "description": ""}}


def _scan(asset_id: str) -> dict:
    return {"hook_event_name": "PreToolUse",
            "tool_name": "mcp__vantage__request_scan",
            "tool_input": {"asset_id": asset_id, "pipeline": "web"}}


def _webfetch(url: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "WebFetch",
            "tool_input": {"url": url, "prompt": "summarize"}}


def test_scanner_approved_host_allows():
    out = run_guard(_bash("nmap -sV portal.lifeco.internal"))
    assert out == {}, f"expected silent allow, got {out}"
    ok("nmap against approved host (portal.lifeco.internal) -> allow (silent)")


def test_scanner_unapproved_host_denies():
    out = run_guard(_bash("nmap -sV bajajlifeinsurance.com"))
    assert out.get("permissionDecision") == "deny", out
    reason = out.get("permissionDecisionReason", "").lower()
    assert "bajajlifeinsurance.com" in reason, reason
    assert "approved" in reason, reason
    ok("nmap against bajajlifeinsurance.com (not approved) -> deny; reason names host + 'approved'")


def test_non_scanner_allows():
    assert run_guard(_bash("git status")) == {}
    assert run_guard(_bash("python foo.py")) == {}
    ok("non-scanner commands (git status / python foo.py) -> allow (silent)")


def test_request_scan_approved_id_allows():
    out = run_guard(_scan("AST-PORTAL"))
    assert out == {}, f"expected silent allow, got {out}"
    ok("request_scan asset_id=AST-PORTAL (approved) -> allow (silent)")


def test_request_scan_unapproved_id_denies():
    out = run_guard(_scan("AST-EVIL"))
    assert out.get("permissionDecision") == "deny", out
    reason = out.get("permissionDecisionReason", "").lower()
    assert "ast-evil" in reason and "approved" in reason, reason
    ok("request_scan asset_id=AST-EVIL (not approved) -> deny")


def test_cidr_membership():
    inside = run_guard(_bash("nikto -h 10.20.4.55"))
    assert inside == {}, f"IP inside approved CIDR should allow, got {inside}"
    outside = run_guard(_bash("nikto -h 8.8.8.8"))
    assert outside.get("permissionDecision") == "deny", outside
    assert "8.8.8.8" in outside.get("permissionDecisionReason", ""), outside
    ok("nikto 10.20.4.55 (in approved 10.20.4.0/24) -> allow; 8.8.8.8 -> deny")


def test_fail_closed_when_inventory_unavailable():
    # Point at unreachable API AND a non-existent scope file by giving the guard
    # a host the committed file doesn't contain while the API is down. The file
    # IS reachable here, so to exercise the pure fail-closed path we use a host
    # absent from both: an unconfirmed host with the API down -> deny.
    out = run_guard(_bash("masscan 203.0.113.10"))
    assert out.get("permissionDecision") == "deny", out
    reason = out.get("permissionDecisionReason", "").lower()
    assert ("cannot confirm" in reason) or ("not in the approved" in reason), reason
    ok("scanner vs unconfirmed host with API down -> deny (fail-closed message)")


def test_webfetch_external_asks():
    out = run_guard(_webfetch("https://example.com/article"))
    assert out.get("permissionDecision") == "ask", out
    assert "example.com" in out.get("permissionDecisionReason", ""), out
    ok("WebFetch to external host (example.com) -> ask (human decides)")


def test_webfetch_localhost_allows():
    assert run_guard(_webfetch("http://localhost:8138/api/dashboard")) == {}
    ok("WebFetch to localhost -> allow (silent; not external recon)")


def main():
    print("Running Vantage scope-guard hook test (no network)...\n")
    tests = [
        test_scanner_approved_host_allows,
        test_scanner_unapproved_host_denies,
        test_non_scanner_allows,
        test_request_scan_approved_id_allows,
        test_request_scan_unapproved_id_denies,
        test_cidr_membership,
        test_fail_closed_when_inventory_unavailable,
        test_webfetch_external_asks,
        test_webfetch_localhost_allows,
    ]
    try:
        for t in tests:
            t()
    except AssertionError as e:
        print("\nSCOPE-GUARD TEST FAILED:\n" + str(e))
        return 1
    print(f"\nALL SCOPE-GUARD TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
