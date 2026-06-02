"""Integration test for the escalation endpoints wired into the Vantage API.

Boots the real app (api.main) via TestClient and checks:
  * GET  /api/escalations  — the ladder/rollup (any authenticated user);
  * POST /api/escalations/run — admin-gated sweep that dispatches notifications
    and writes an ESCALATION_SWEEP audit row; a non-admin (viewer) gets 403.

Standalone:  python orchestrator/api/test_escalations_api.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))      # orchestrator/api
ORCH = os.path.dirname(HERE)                            # orchestrator
ROOT = os.path.dirname(ORCH)                            # repo root
for p in (ROOT, ORCH):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi.testclient import TestClient               # noqa: E402

from api.main import app                                # noqa: E402
from api.auth import User, mint_session, SESSION_COOKIE  # noqa: E402

PASS = []


def ok(msg: str) -> None:
    PASS.append(msg)
    print("  [ok] " + msg)


def _set(client, user):
    client.cookies.set(SESSION_COOKIE, mint_session(user))


def test_dev_mode():
    os.environ.pop("AUTH_REQUIRED", None)
    c = TestClient(app)
    c.cookies.clear()

    r = c.get("/api/escalations")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["ladder"]) == 5 and len(body["stageCounts"]) == 5, body["stageCounts"]
    assert body["ladder"][4]["role"] == "CISO", body["ladder"][4]
    assert set(body["counts"]) == {"active", "overdue", "due"}, body["counts"]
    # 'due' is a subset of the active findings
    fids = {f["id"] for f in body["findings"]}
    assert all(d["id"] in fids for d in body["due"])
    # there ARE overdue findings in the seed, so the sweep will dispatch some
    assert body["counts"]["active"] > 0
    ok("dev: GET /api/escalations returns a 5-stage ladder + rollup")

    r = c.post("/api/escalations/run")
    assert r.status_code == 200, r.text
    run = r.json()
    assert isinstance(run["dispatched"], list) and run["count"] == len(run["dispatched"])
    assert run["count"] == body["counts"]["due"], (run["count"], body["counts"]["due"])
    if run["dispatched"]:
        n = run["dispatched"][0]
        assert n["findingId"] and n["role"] and n["message"]
        assert "memory" in " ".join(n["channels"]) or n["channels"]  # at least one sink accepted
    ok("dev: POST /api/escalations/run dispatched %d notification(s)" % run["count"])

    # the sweep is audited with the server actor
    a = c.get("/api/audit?limit=20").json()["audit"]
    assert any(e["action"] == "ESCALATION_SWEEP" for e in a), "sweep must be audited"
    ok("dev: escalation sweep wrote an ESCALATION_SWEEP audit row")


def test_prod_rbac():
    os.environ["AUTH_REQUIRED"] = "true"
    os.environ["SESSION_SECRET"] = "test-esc-secret"
    try:
        c = TestClient(app)
        c.cookies.clear()
        viewer = User(sub="v", name="Vera", email="v@corp", roles=["viewer"], groups=[])
        admin = User(sub="a", name="Ada", email="a@corp", roles=["admin"], groups=[])

        # cookieless -> 401 on the read
        assert c.get("/api/escalations").status_code == 401

        _set(c, viewer)
        assert c.get("/api/escalations").status_code == 200          # viewer may read
        assert c.post("/api/escalations/run").status_code == 403      # but not run the sweep
        ok("prod: viewer reads escalations (200) but run-sweep is 403")

        _set(c, admin)
        assert c.post("/api/escalations/run").status_code == 200
        ok("prod: admin can run the escalation sweep (200)")
    finally:
        os.environ.pop("AUTH_REQUIRED", None)
        os.environ.pop("SESSION_SECRET", None)


def main() -> int:
    print("Running Vantage escalation-API integration test...\n")
    test_dev_mode()
    test_prod_rbac()
    print(f"\nALL ESCALATION API TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
