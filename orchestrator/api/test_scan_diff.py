"""Integration test for the scan-diff + request-retest endpoints.

Boots the real app (api.main) via TestClient and checks:
  * GET  /api/scan-diff — read-only diff of the two deterministic pipelines
    (licensed baseline vs OSS current), any authenticated user; deterministic.
  * POST /api/findings/{id}/retest — analyst-gated mutation flipping a finding
    to status "retest" and writing a RETEST_REQUESTED audit row; a viewer gets
    403, an analyst gets 200, an unknown id gets 404.

Standalone:  python orchestrator/api/test_scan_diff.py
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

    # --- scan-diff ---------------------------------------------------------
    r = c.get("/api/scan-diff")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["baseLabel"] == "licensed", body["baseLabel"]
    assert body["headLabel"] == "oss", body["headLabel"]

    for key in ("resolved", "new", "persisting", "regressed"):
        assert isinstance(body[key], list), key

    counts = body["counts"]
    assert set(counts) == {"baseline", "current", "resolved", "new",
                           "persisting", "regressed"}, counts
    assert counts["baseline"] > 0 and counts["current"] > 0, counts

    # the four list lengths equal their reported counts
    for key in ("resolved", "new", "persisting", "regressed"):
        assert len(body[key]) == counts[key], (key, len(body[key]), counts[key])

    # every summary item carries the compact shape
    for key in ("resolved", "new", "persisting", "regressed"):
        for item in body[key]:
            for field in ("title", "assetId", "severity", "signature"):
                assert field in item, (key, field, item)
    ok("dev: GET /api/scan-diff returns labelled diff + counts (baseline=%d current=%d)"
       % (counts["baseline"], counts["current"]))

    # determinism: identical JSON across two calls
    r2 = c.get("/api/scan-diff")
    assert r2.status_code == 200, r2.text
    assert r2.json() == body, "scan-diff must be deterministic"
    ok("dev: GET /api/scan-diff is deterministic (two calls identical)")

    # --- retest (dev mode) + audit ----------------------------------------
    fid = c.get("/api/findings").json()["findings"][0]["id"]
    r = c.post("/api/findings/%s/retest" % fid)
    assert r.status_code == 200, r.text
    assert r.json()["finding"]["status"] == "retest", r.json()["finding"]
    ok("dev: POST /api/findings/%s/retest set status to 'retest'" % fid)

    a = c.get("/api/audit?limit=20").json()["audit"]
    assert any(e["action"] == "RETEST_REQUESTED" for e in a), "retest must be audited"
    ok("dev: retest wrote a RETEST_REQUESTED audit row")


def test_prod_rbac():
    os.environ["AUTH_REQUIRED"] = "true"
    prev_secret = os.environ.get("SESSION_SECRET")
    os.environ["SESSION_SECRET"] = "test-diff-secret"
    try:
        c = TestClient(app)
        c.cookies.clear()
        viewer = User(sub="v", name="Vera", email="v@corp", roles=["viewer"], groups=[])
        analyst = User(sub="n", name="Nia", email="n@corp", roles=["analyst"], groups=[])

        # pick a real finding id (analyst may read)
        _set(c, analyst)
        fid = c.get("/api/findings").json()["findings"][0]["id"]

        # viewer cannot request a retest
        _set(c, viewer)
        assert c.post("/api/findings/%s/retest" % fid).status_code == 403
        ok("prod: viewer request-retest is 403")

        # analyst can, and the finding flips to 'retest'
        _set(c, analyst)
        r = c.post("/api/findings/%s/retest" % fid)
        assert r.status_code == 200, r.text
        assert r.json()["finding"]["status"] == "retest", r.json()["finding"]
        ok("prod: analyst request-retest is 200 with status 'retest'")

        # unknown id -> 404
        r = c.post("/api/findings/NOPE-DOES-NOT-EXIST/retest")
        assert r.status_code == 404, r.text
        ok("prod: unknown finding id request-retest is 404")
    finally:
        os.environ.pop("AUTH_REQUIRED", None)
        if prev_secret is None:
            os.environ.pop("SESSION_SECRET", None)
        else:
            os.environ["SESSION_SECRET"] = prev_secret


def main() -> int:
    print("Running Vantage scan-diff + retest API integration test...\n")
    test_dev_mode()
    test_prod_rbac()
    print(f"\nALL SCAN-DIFF API TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
