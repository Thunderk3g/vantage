"""Smoke test for the Vantage MCP server — no live API needed.

Verifies the FastMCP tools are registered and that the thin client correctly
forwards calls, passes through the contract error body (e.g. the scope gate's
403 out_of_scope), and implements scope_check. Uses httpx.MockTransport so no
network is touched.

Run:  python plugin/mcp/test_server_smoke.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx  # noqa: E402

import vantage_server as server  # noqa: E402

PASS = []


def ok(msg):
    PASS.append(msg)
    print("  [ok] " + msg)


def _install_mock(handler):
    """Point the server's shared client at a MockTransport."""
    server._CLIENT = httpx.Client(transport=httpx.MockTransport(handler),
                                  base_url=server.API_BASE)


def test_tools_registered():
    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}
    expected = {
        "dashboard", "list_findings", "get_finding", "list_assets", "scope_check",
        "scan_diff", "schedule", "escalations", "audit", "request_scan",
        "set_finding_status", "request_retest", "confirm_false_positive",
        "request_exception", "decide_exception", "generate_report",
    }
    missing = expected - names
    assert not missing, f"MCP tools not registered: {missing}"
    assert server.mcp.name == "vantage"
    # No offensive verb leaked into the toolset (scan-and-report boundary).
    forbidden = {"exploit", "attack", "lateral", "weaponize", "pwn", "bruteforce"}
    assert not any(any(b in n.lower() for b in forbidden) for n in names), names
    ok(f"all {len(expected)} tools registered; no offensive verb in the toolset")


def test_read_passthrough():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/findings"
        assert req.url.params.get("severity") == "critical"
        return httpx.Response(200, json={"findings": [{"id": "VLN-1"}], "total": 1})
    _install_mock(handler)
    out = server.list_findings(severity="critical")
    assert out == {"findings": [{"id": "VLN-1"}], "total": 1}, out
    ok("list_findings forwards filters and returns the parsed register")


def test_scope_gate_error_passthrough():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "POST" and req.url.path == "/api/scans"
        body = json.loads(req.content)
        assert body["assetId"] == "AST-EVIL"
        return httpx.Response(403, json={"error": "out_of_scope",
                                         "detail": "AST-EVIL is not in the approved asset inventory"})
    _install_mock(handler)
    out = server.request_scan(asset_id="AST-EVIL", pipeline="web")
    assert out["_error"] == "out_of_scope" and out["_status"] == 403, out
    assert "not in the approved" in out["detail"], out
    ok("request_scan surfaces the server scope gate's 403 out_of_scope verdict")


def test_scope_check():
    assets = {"assets": [
        {"id": "AST-PORTAL", "name": "Policyholder Portal", "host": "portal.lifeco.internal", "type": "web"},
        {"id": "AST-PAS", "name": "Core Policy Admin System", "host": "10.20.4.0/24", "type": "infra"},
    ]}

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/assets"
        return httpx.Response(200, json=assets)
    _install_mock(handler)

    inscope = server.scope_check("portal.lifeco.internal")
    assert inscope["inScope"] is True and inscope["match"]["id"] == "AST-PORTAL", inscope

    out = server.scope_check("bajajlifeinsurance.com")
    assert out["inScope"] is False and out["match"] is None, out
    assert "refused" in out["note"].lower(), out
    ok("scope_check: approved host -> inScope; unknown host -> refused (no scan)")


def test_unreachable_api():
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")
    _install_mock(handler)
    out = server.dashboard()
    assert out["_error"] == "unreachable", out
    ok("unreachable API -> structured {_error: unreachable}, never a traceback")


def main():
    print("Running Vantage MCP server smoke test...\n")
    for t in (test_tools_registered, test_read_passthrough, test_scope_gate_error_passthrough,
              test_scope_check, test_unreachable_api):
        t()
    print(f"\nALL MCP SMOKE TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
