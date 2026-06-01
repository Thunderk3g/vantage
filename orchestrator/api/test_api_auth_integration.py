"""End-to-end auth/RBAC integration test for the wired Vantage API.

Boots the real FastAPI app (api.main, with auth.py wired in) through Starlette's
TestClient and exercises the whole contract in BOTH modes:

  * dev   (AUTH_REQUIRED unset) — synthetic admin; reads/writes work cookieless;
           the audit actor is the SERVER-DERIVED session actor (never a client
           string).
  * prod  (AUTH_REQUIRED=true)  — 401 without a session; viewer can read but not
           mutate (403); analyst can mutate; report download is owner-scoped
           (a different user gets 403; admin overrides).

This is the coordinator-level proof that auth.py + main.py + the RBAC matrix in
docs/auth-contract.md actually hold together. Standalone runnable:

    python orchestrator/api/test_api_auth_integration.py
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
from api.auth import User, mint_session, session_actor, SESSION_COOKIE  # noqa: E402

DEV_ACTOR = "Vantage Dev <dev@vantage.local>"
PASS = []


def ok(msg: str) -> None:
    PASS.append(msg)
    print("  [ok] " + msg)


def _set_session(client: TestClient, user: User) -> None:
    client.cookies.set(SESSION_COOKIE, mint_session(user))


def _clear(client: TestClient) -> None:
    client.cookies.clear()


def _a_finding_id(client: TestClient) -> str:
    r = client.get("/api/findings")
    assert r.status_code == 200, r.text
    items = r.json()["findings"]
    assert items, "seed has at least one finding"
    return items[0]["id"]


# =====================================================================
# DEV MODE — AUTH_REQUIRED unset
# =====================================================================
def test_dev_mode() -> None:
    os.environ.pop("AUTH_REQUIRED", None)
    client = TestClient(app)
    _clear(client)

    # health is public
    assert client.get("/api/health").status_code == 200
    ok("dev: GET /api/health is public (200)")

    # /me returns the synthetic dev admin
    me = client.get("/api/auth/me")
    assert me.status_code == 200, me.text
    u = me.json()["user"]
    assert u["sub"] == "dev" and u["roles"] == ["admin"], u
    ok("dev: /api/auth/me is the synthetic admin dev user")

    # reads work cookieless
    assert client.get("/api/findings").status_code == 200
    assert client.get("/api/audit").status_code == 200
    ok("dev: reads succeed without a cookie (synthetic admin)")

    # a mutation works AND the actor is server-derived (note: NO actor in body)
    fid = _a_finding_id(client)
    r = client.patch(f"/api/findings/{fid}/status", json={"status": "triaged"})
    assert r.status_code == 200, r.text
    fin = r.json()["finding"]
    assert fin["humanValidatedBy"] == DEV_ACTOR, fin["humanValidatedBy"]
    ok("dev: PATCH status works with NO body actor; humanValidatedBy is server-derived")

    # the audit row carries the server actor, not a client string
    a = client.get("/api/audit?limit=10").json()["audit"]
    changed = [e for e in a if e["action"] == "FINDING_STATUS_CHANGED"]
    assert changed and changed[0]["actor"] == DEV_ACTOR, changed[:1]
    ok("dev: audit actor is the session actor (spoofable-actor gap closed)")

    # report generate + download (admin owns it)
    r = client.post("/api/reports", json={"template": "audit", "scope": "all", "formats": ["xlsx"]})
    assert r.status_code == 201, r.text
    files = r.json()["files"]
    dl = client.get(files["xlsx"])
    assert dl.status_code == 200 and dl.content[:2] == b"PK", dl.status_code
    ok("dev: report generate (201) + owner download (200, real xlsx)")


# =====================================================================
# PROD MODE — AUTH_REQUIRED=true
# =====================================================================
def test_prod_mode() -> None:
    os.environ["AUTH_REQUIRED"] = "true"
    os.environ["SESSION_SECRET"] = "test-prod-secret-fixed"  # mint+verify share it
    try:
        client = TestClient(app)
        _clear(client)

        # health public; everything else 401 without a session
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/findings").status_code == 401
        assert client.get("/api/auth/me").status_code == 401
        ok("prod: cookieless reads are 401; health stays public")

        viewer = User(sub="v1", name="Vera Viewer", email="vera@corp", roles=["viewer"], groups=[])
        analyst = User(sub="a1", name="Anu Analyst", email="anu@corp", roles=["analyst"], groups=[])
        other = User(sub="a2", name="Otto Other", email="otto@corp", roles=["analyst"], groups=[])
        admin = User(sub="ad1", name="Ada Admin", email="ada@corp", roles=["admin"], groups=[])

        # viewer: can read, cannot mutate
        _set_session(client, viewer)
        assert client.get("/api/findings").status_code == 200
        fid = _a_finding_id(client)
        r = client.patch(f"/api/findings/{fid}/status", json={"status": "triaged"})
        assert r.status_code == 403, r.status_code
        assert r.json()["error"] == "forbidden", r.text
        assert client.post("/api/reports", json={"formats": ["xlsx"]}).status_code == 403
        ok("prod: viewer reads (200) but PATCH + reports are 403 forbidden")

        # analyst: can mutate; actor is the analyst's session identity
        _set_session(client, analyst)
        r = client.patch(f"/api/findings/{fid}/status", json={"status": "in_progress"})
        assert r.status_code == 200, r.text
        assert r.json()["finding"]["humanValidatedBy"] == session_actor(analyst)
        ok("prod: analyst PATCH (200); actor == analyst session identity")

        # analyst generates a report -> owns it
        r = client.post("/api/reports", json={"template": "audit", "scope": "all", "formats": ["xlsx"]})
        assert r.status_code == 201, r.text
        xlsx_path = r.json()["files"]["xlsx"]
        assert client.get(xlsx_path).status_code == 200      # owner downloads
        ok("prod: analyst generates report (201) and can download it (owner, 200)")

        # a DIFFERENT analyst cannot download it; admin can
        _set_session(client, other)
        assert client.get(xlsx_path).status_code == 403
        _set_session(client, admin)
        assert client.get(xlsx_path).status_code == 200
        ok("prod: non-owner download 403; admin override 200 (owner-scoping enforced)")
    finally:
        os.environ.pop("AUTH_REQUIRED", None)
        os.environ.pop("SESSION_SECRET", None)


def main() -> int:
    print("Running Vantage API auth/RBAC integration test...\n")
    test_dev_mode()
    test_prod_mode()
    print(f"\nALL API AUTH INTEGRATION TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
