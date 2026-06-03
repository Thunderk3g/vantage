"""Integration test for the scan-schedule endpoint wired into the Vantage API.

Boots the real app (api.main) via TestClient and checks:
  * GET /api/schedule — cadence + blackout-aware planning view (read-only; any
    authenticated user). Verifies the response shape (blackouts/entries/counts),
    that infra assets contribute BOTH an infra-va and a cis-review entry, and
    that prod auth is enforced (cookieless 401, viewer 200).

This endpoint only PLANS — it never launches a scan.

Standalone:  python orchestrator/api/test_schedule_api.py
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

    r = c.get("/api/schedule")
    assert r.status_code == 200, r.text
    body = r.json()

    # blackouts: non-empty list of {start,end,reason}
    blackouts = body["blackouts"]
    assert isinstance(blackouts, list) and blackouts, blackouts
    for b in blackouts:
        assert set(b) >= {"start", "end", "reason"}, b

    # entries: non-empty; counts has total/overdue/dueSoon; total == len(entries)
    entries = body["entries"]
    assert isinstance(entries, list) and entries, entries
    counts = body["counts"]
    assert set(counts) >= {"total", "overdue", "dueSoon"}, counts
    assert counts["total"] == len(entries), (counts["total"], len(entries))

    # every entry carries the planning fields with the right types
    for e in entries:
        assert e["assetId"] and e["scanType"] and e["cadence"] and e["nextDue"], e
        assert isinstance(e["overdue"], bool), e
        assert isinstance(e["dueSoon"], bool), e
    ok("dev: GET /api/schedule returns blackouts + entries + counts (total == len(entries))")

    # infra assets contribute 2 entries each (VA + CIS). Pick one infra asset id
    # from the response and assert BOTH scan types are present for it.
    by_asset: dict = {}
    for e in entries:
        by_asset.setdefault(e["assetId"], set()).add(e["scanType"])
    infra_ids = [aid for aid, types in by_asset.items() if "infra-va" in types]
    assert infra_ids, "expected at least one infra asset (infra-va) in the schedule"
    aid = infra_ids[0]
    assert "infra-va" in by_asset[aid] and "cis-review" in by_asset[aid], by_asset[aid]
    # since infra assets contribute 2 entries each, there are more entries than assets
    assert len(entries) > len(by_asset), (len(entries), len(by_asset))
    ok("dev: infra asset %s has both infra-va and cis-review entries" % aid)


def test_prod_rbac():
    os.environ["AUTH_REQUIRED"] = "true"
    os.environ["SESSION_SECRET"] = "test-sched-secret"
    try:
        c = TestClient(app)
        c.cookies.clear()
        viewer = User(sub="v", name="Vera", email="v@corp", roles=["viewer"], groups=[])

        # cookieless -> 401 on the read
        assert c.get("/api/schedule").status_code == 401

        _set(c, viewer)
        assert c.get("/api/schedule").status_code == 200   # read allowed for any auth user
        ok("prod: cookieless schedule is 401; viewer reads schedule (200)")
    finally:
        os.environ.pop("AUTH_REQUIRED", None)
        os.environ.pop("SESSION_SECRET", None)


def main() -> int:
    print("Running Vantage schedule-API integration test...\n")
    test_dev_mode()
    test_prod_rbac()
    print(f"\nALL SCHEDULE API TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
