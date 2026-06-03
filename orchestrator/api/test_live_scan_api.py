"""Integration test for the UI-triggerable live-scan endpoints.

Boots the real app (api.main) via TestClient and checks the async live-scan
job model end-to-end WITHOUT needing nmap installed: the actual scan is
monkeypatched on ``orchestrator.run_scan`` (the background worker imports
``from orchestrator import run_scan`` and calls ``run_scan.run_live_scan``, so
patching the module attribute is enough).

Covers:
  * dev (admin) happy path: POST -> 202 queued, poll GET -> done w/ register;
  * out-of-scope refusal (403) for public IP + external domain (no job made);
  * bad mode -> 422;
  * engine error path (nmap missing) -> job status "error";
  * prod RBAC: viewer 403, analyst 202, unknown jobId 404.

Standalone:  python orchestrator/api/test_live_scan_api.py
"""
from __future__ import annotations

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))      # orchestrator/api
ORCH = os.path.dirname(HERE)                            # orchestrator
ROOT = os.path.dirname(ORCH)                            # repo root
for p in (ROOT, ORCH):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi.testclient import TestClient               # noqa: E402

import api.main as m                                    # noqa: E402
from api.main import app                                # noqa: E402
from api.auth import User, mint_session, SESSION_COOKIE  # noqa: E402
import orchestrator.run_scan as rs                      # noqa: E402

PASS = []


def ok(msg: str) -> None:
    PASS.append(msg)
    print("  [ok] " + msg)


def _set(client, user):
    client.cookies.set(SESSION_COOKIE, mint_session(user))


def _fake_scan(target, mode="full", today=None):
    """Stand-in for run_scan.run_live_scan — no nmap needed. Returns a small
    triaged register shaped like the real one (severity_normalized/dedup_key)."""
    return {
        "target": target,
        "mode": mode,
        "tool": "nmap",
        "findingCount": 2,
        "register": [
            {"id": "F-1", "title": "open ssh", "severity_normalized": "medium",
             "dedup_key": "nmap:%s:22/tcp:ssh" % target},
            {"id": "F-2", "title": "open http", "severity_normalized": "low",
             "dedup_key": "nmap:%s:80/tcp:http" % target},
        ],
    }


def _poll(client, job_id, tries=30, delay=0.1):
    """Poll GET until status leaves queued/running (the mock is fast)."""
    last = None
    for _ in range(tries):
        r = client.get("/api/scans/live/%s" % job_id)
        assert r.status_code == 200, r.text
        last = r.json()
        if last["status"] in ("done", "error"):
            return last
        time.sleep(delay)
    return last


def test_dev_happy_path():
    os.environ.pop("AUTH_REQUIRED", None)
    orig = rs.run_live_scan
    rs.run_live_scan = _fake_scan
    try:
        c = TestClient(app)
        c.cookies.clear()

        r = c.post("/api/scans/live", json={"target": "127.0.0.1"})
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "queued" and body["jobId"], body
        assert body["target"] == "127.0.0.1" and body["mode"] == "full", body
        job_id = body["jobId"]
        ok("dev: POST /api/scans/live (127.0.0.1) -> 202 queued w/ jobId")

        final = _poll(c, job_id)
        assert final is not None and final["status"] == "done", final
        assert final["findingCount"] == 2, final
        assert final["register"] and len(final["register"]) == 2, final
        assert final["error"] is None, final
        ok("dev: polled job to status=done, findingCount=2, register present")
    finally:
        rs.run_live_scan = orig


def test_out_of_scope_refused():
    os.environ.pop("AUTH_REQUIRED", None)
    c = TestClient(app)
    c.cookies.clear()

    before = len(m._LIVE_JOBS)
    for bad in ("8.8.8.8", "bajajlifeinsurance.com"):
        r = c.post("/api/scans/live", json={"target": bad})
        assert r.status_code == 403, (bad, r.text)
        assert r.json()["error"] == "out_of_scope", r.text
    # fail-closed: no job is created for an out-of-scope target
    assert len(m._LIVE_JOBS) == before, "out-of-scope must not create a job"
    ok("scope: 8.8.8.8 + bajajlifeinsurance.com -> 403 out_of_scope (no job)")


def test_bad_mode():
    os.environ.pop("AUTH_REQUIRED", None)
    c = TestClient(app)
    c.cookies.clear()
    r = c.post("/api/scans/live", json={"target": "127.0.0.1", "mode": "aggressive"})
    assert r.status_code == 422, r.text
    assert r.json()["error"] == "invalid_mode", r.text
    ok("mode: bad mode 'aggressive' -> 422 invalid_mode")


def test_error_path():
    os.environ.pop("AUTH_REQUIRED", None)
    orig = rs.run_live_scan

    def _boom(target, mode="full", today=None):
        raise RuntimeError("nmap binary not found on PATH")

    rs.run_live_scan = _boom
    try:
        c = TestClient(app)
        c.cookies.clear()
        r = c.post("/api/scans/live", json={"target": "127.0.0.1"})
        assert r.status_code == 202, r.text
        job_id = r.json()["jobId"]
        final = _poll(c, job_id)
        assert final is not None and final["status"] == "error", final
        assert "nmap" in (final["error"] or ""), final
        ok("error: engine failure -> job status=error, error mentions nmap")
    finally:
        rs.run_live_scan = orig


def test_prod_rbac():
    os.environ["AUTH_REQUIRED"] = "true"
    os.environ["SESSION_SECRET"] = "test-live-secret"
    orig = rs.run_live_scan
    rs.run_live_scan = _fake_scan
    try:
        c = TestClient(app)
        c.cookies.clear()
        viewer = User(sub="v", name="Vera", email="v@corp", roles=["viewer"], groups=[])
        analyst = User(sub="an", name="Ana", email="an@corp", roles=["analyst"], groups=[])

        # cookieless -> 401
        assert c.post("/api/scans/live", json={"target": "127.0.0.1"}).status_code == 401

        _set(c, viewer)
        r = c.post("/api/scans/live", json={"target": "127.0.0.1"})
        assert r.status_code == 403, r.text
        assert r.json()["error"] == "forbidden", r.text
        ok("prod: viewer POST /api/scans/live -> 403 forbidden")

        _set(c, analyst)
        r = c.post("/api/scans/live", json={"target": "127.0.0.1"})
        assert r.status_code == 202, r.text
        job_id = r.json()["jobId"]
        ok("prod: analyst POST /api/scans/live -> 202 queued")

        # an authenticated user can read; unknown jobId -> 404
        r = c.get("/api/scans/live/LSCAN-does-not-exist")
        assert r.status_code == 404, r.text
        assert r.json()["error"] == "not_found", r.text
        ok("prod: unknown jobId GET -> 404 not_found")

        # the real job is pollable too
        final = _poll(c, job_id)
        assert final is not None and final["status"] == "done", final
        ok("prod: analyst's job polls to done")
    finally:
        rs.run_live_scan = orig
        os.environ.pop("AUTH_REQUIRED", None)
        os.environ.pop("SESSION_SECRET", None)


def main() -> int:
    print("Running Vantage live-scan-API integration test...\n")
    test_dev_happy_path()
    test_out_of_scope_refused()
    test_bad_mode()
    test_error_path()
    test_prod_rbac()
    print("\nALL LIVE-SCAN API TESTS PASSED (%d checks)" % len(PASS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
