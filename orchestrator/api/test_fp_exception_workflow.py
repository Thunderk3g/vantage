"""Backend test for the two governance workflows on the Vantage API.

Boots the real FastAPI app (api.main) through Starlette's TestClient and proves:

  1. FALSE POSITIVE confirm/clear (dev/admin): confirm -> status confirmed_fp +
     isClosed true (and it shows up that way in GET /api/findings); clear ->
     status triaged; an invalid decision is 422.
  2. risk_accepted is reachable ONLY via an approved exception: the generic
     PATCH /api/findings/{id}/status STILL rejects {status:"risk_accepted"} (422).
  3. EXCEPTION decision RBAC (prod): the WRONG / non-approver role is 403; the
     tier-matching approver role approves (200) and the linked finding flips to
     risk_accepted (isClosed true); reject path is 200/rejected; re-deciding an
     already-decided exception is 422 not_decidable.

Standalone runnable:

    python orchestrator/api/test_fp_exception_workflow.py
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
from api import seed                                    # noqa: E402

PASS = []


def ok(msg: str) -> None:
    PASS.append(msg)
    print("  [ok] " + msg)


def _set_session(client: TestClient, user: User) -> None:
    client.cookies.set(SESSION_COOKIE, mint_session(user))


def _clear(client: TestClient) -> None:
    client.cookies.clear()


def _finding(client: TestClient, fid: str) -> dict:
    r = client.get(f"/api/findings/{fid}")
    assert r.status_code == 200, r.text
    return r.json()["finding"]


def _an_open_finding_id(client: TestClient) -> str:
    """Pick a real seed finding that is NOT already closed/accepted/FP."""
    r = client.get("/api/findings")
    assert r.status_code == 200, r.text
    for f in r.json()["findings"]:
        if not f["isClosed"]:
            return f["id"]
    raise AssertionError("seed has at least one open finding")


def _pending_exception(tier: str) -> dict:
    """A real seed exception of the given tier in a decidable state."""
    for e in seed.exceptions():
        if e["tier"] == tier and e["status"] in ("requested", "pending"):
            return e
    raise AssertionError(f"seed has a decidable {tier} exception")


# =====================================================================
# (1) FALSE POSITIVE confirm/clear — dev mode (synthetic admin)
# =====================================================================
def test_false_positive_dev() -> None:
    os.environ.pop("AUTH_REQUIRED", None)
    client = TestClient(app)
    _clear(client)

    fid = _an_open_finding_id(client)

    # confirm -> confirmed_fp + isClosed true
    r = client.post(f"/api/findings/{fid}/false-positive", json={"decision": "confirm"})
    assert r.status_code == 200, r.text
    fin = r.json()["finding"]
    assert fin["status"] == "confirmed_fp", fin
    assert fin["isClosed"] is True, fin
    ok("fp confirm: status confirmed_fp + isClosed true")

    # GET /api/findings reflects it
    listed = _finding(client, fid)
    assert listed["status"] == "confirmed_fp" and listed["isClosed"] is True, listed
    ok("fp confirm: GET /api/findings shows the finding confirmed_fp")

    # clear -> triaged
    r = client.post(f"/api/findings/{fid}/false-positive", json={"decision": "clear"})
    assert r.status_code == 200, r.text
    fin = r.json()["finding"]
    assert fin["status"] == "triaged", fin
    assert fin["isClosed"] is False, fin
    ok("fp clear: status back to triaged")

    # invalid decision -> 422 invalid_decision
    r = client.post(f"/api/findings/{fid}/false-positive", json={"decision": "nope"})
    assert r.status_code == 422, r.text
    assert r.json()["error"] == "invalid_decision", r.text
    ok("fp: invalid decision -> 422 invalid_decision")

    # unknown finding -> 404
    r = client.post("/api/findings/VLN-DOES-NOT-EXIST/false-positive", json={"decision": "confirm"})
    assert r.status_code == 404, r.text
    assert r.json()["error"] == "not_found", r.text
    ok("fp: unknown finding -> 404 not_found")


# =====================================================================
# (2) risk_accepted ONLY via approval — generic PATCH still rejects it
# =====================================================================
def test_risk_accepted_not_via_patch() -> None:
    os.environ.pop("AUTH_REQUIRED", None)
    client = TestClient(app)
    _clear(client)

    fid = _an_open_finding_id(client)
    r = client.patch(f"/api/findings/{fid}/status", json={"status": "risk_accepted"})
    assert r.status_code == 422, r.text
    assert r.json()["error"] == "invalid_status", r.text
    ok("patch: risk_accepted still rejected (422 invalid_status) — approval-only")

    # confirmed_fp is likewise not settable via the generic PATCH
    r = client.patch(f"/api/findings/{fid}/status", json={"status": "confirmed_fp"})
    assert r.status_code == 422, r.text
    assert r.json()["error"] == "invalid_status", r.text
    ok("patch: confirmed_fp still rejected (422 invalid_status)")


# =====================================================================
# (3) EXCEPTION decision RBAC — prod mode (minted cookies)
# =====================================================================
def test_exception_decision_prod() -> None:
    os.environ["AUTH_REQUIRED"] = "true"
    os.environ["SESSION_SECRET"] = "test-prod-secret-fixed"  # mint+verify share it
    try:
        client = TestClient(app)
        _clear(client)

        analyst = User(sub="a1", name="Anu Analyst", email="anu@corp", roles=["analyst"], groups=[])
        ciso = User(sub="c1", name="Cara CISO", email="cara@corp", roles=["approver_ciso"], groups=[])
        rmc = User(sub="r1", name="Raj RMC", email="raj@corp", roles=["approver_rmc"], groups=[])
        board = User(sub="b1", name="Bea Board", email="bea@corp", roles=["approver_board"], groups=[])

        # --- RMC-tier exception: analyst 403, wrong-tier 403, RMC approves 200 ---
        rmc_exc = _pending_exception("RMC")
        eid = rmc_exc["id"]
        linked = rmc_exc["finding"]

        _set_session(client, analyst)
        r = client.post(f"/api/exceptions/{eid}/decision", json={"decision": "approve"})
        assert r.status_code == 403, r.text
        assert r.json()["error"] == "forbidden", r.text
        ok(f"exc {eid} (RMC): analyst approve -> 403 forbidden")

        _set_session(client, ciso)
        r = client.post(f"/api/exceptions/{eid}/decision", json={"decision": "approve"})
        assert r.status_code == 403, r.text
        assert r.json()["error"] == "forbidden", r.text
        ok(f"exc {eid} (RMC): CISO (wrong tier) approve -> 403 forbidden")

        _set_session(client, rmc)
        r = client.post(f"/api/exceptions/{eid}/decision", json={"decision": "approve"})
        assert r.status_code == 200, r.text
        payload = r.json()
        assert payload["exception"]["status"] == "approved", payload
        assert payload["finding"] is not None, payload
        assert payload["finding"]["status"] == "risk_accepted", payload
        ok(f"exc {eid} (RMC): matching approver approve -> 200, exception approved")

        # the linked finding is now risk_accepted + closed in GET
        fin = _finding(client, linked)
        assert fin["status"] == "risk_accepted" and fin["isClosed"] is True, fin
        ok(f"exc {eid} (RMC): linked finding {linked} -> risk_accepted + isClosed true")

        # re-deciding an already-decided exception -> 422 not_decidable
        r = client.post(f"/api/exceptions/{eid}/decision", json={"decision": "approve"})
        assert r.status_code == 422, r.text
        assert r.json()["error"] == "not_decidable", r.text
        ok(f"exc {eid}: re-decide already-approved -> 422 not_decidable")

        # --- Board-tier exception: reject path ---
        board_exc = _pending_exception("Board")
        beid = board_exc["id"]

        # invalid decision -> 422 invalid_decision
        _set_session(client, board)
        r = client.post(f"/api/exceptions/{beid}/decision", json={"decision": "maybe"})
        assert r.status_code == 422, r.text
        assert r.json()["error"] == "invalid_decision", r.text
        ok(f"exc {beid} (Board): invalid decision -> 422 invalid_decision")

        # wrong tier (CISO) reject -> 403
        _set_session(client, ciso)
        r = client.post(f"/api/exceptions/{beid}/decision", json={"decision": "reject"})
        assert r.status_code == 403, r.text
        ok(f"exc {beid} (Board): CISO (wrong tier) reject -> 403 forbidden")

        # matching Board approver reject -> 200, rejected, no finding change
        _set_session(client, board)
        r = client.post(f"/api/exceptions/{beid}/decision", json={"decision": "reject"})
        assert r.status_code == 200, r.text
        payload = r.json()
        assert payload["exception"]["status"] == "rejected", payload
        assert payload["finding"] is None, payload
        ok(f"exc {beid} (Board): Board approver reject -> 200, status rejected, finding None")

        # unknown exception -> 404
        r = client.post("/api/exceptions/EXC-DOES-NOT-EXIST/decision", json={"decision": "approve"})
        assert r.status_code == 404, r.text
        assert r.json()["error"] == "not_found", r.text
        ok("exc: unknown exception -> 404 not_found")
    finally:
        os.environ.pop("AUTH_REQUIRED", None)
        os.environ.pop("SESSION_SECRET", None)


def main() -> int:
    print("Running Vantage FP + exception governance workflow test...\n")
    test_false_positive_dev()
    test_risk_accepted_not_via_patch()
    test_exception_decision_prod()
    print(f"\nALL FP/EXCEPTION WORKFLOW TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
