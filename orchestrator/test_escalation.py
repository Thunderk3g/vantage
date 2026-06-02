"""
Runnable self-test for the deterministic escalation-staircase engine.

Plain asserts + a __main__ block -- no pytest required. Run either of:

    python orchestrator/test_escalation.py
    python -m test_escalation            # with orchestrator/ on sys.path

Covers the behaviours called out in the build spec:
  * closed findings and deadline-None (Info) findings are excluded,
  * stageCounts sums to counts.active,
  * role/nextRole/nextDay map correctly to LADDER for a couple of stages,
  * overdue / dueForEscalation flags are correct per case,
  * due is exactly the dueForEscalation subset, sorted by daysLeft ascending,
  * determinism (run twice -> identical output),
  * input finding dicts are never mutated.
"""
from __future__ import annotations

import os
import sys

# Make the engine importable whether run as a script or a module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # orchestrator/

from escalation import (  # noqa: E402
    LADDER,
    build_escalations,
    escalation_for,
)


def sample_findings():
    """A small hand-made list covering every branch the spec calls out."""
    return [
        # Closed finding -> excluded (even though it has a deadline).
        {
            "id": "F-CLOSED", "title": "Patched XSS", "severity": "high",
            "assetId": "AST-PORTAL", "asset": "Policy Portal",
            "owner": "alice", "assetOwner": "alice",
            "status": "closed", "isClosed": True,
            "deadline": "2026-05-10", "daysLeft": -20, "escStage": 4,
        },
        # Info finding with deadline None -> excluded (not under active SLA).
        {
            "id": "F-INFO", "title": "Server banner discloses version",
            "severity": "info", "assetId": "AST-VPN", "asset": "VPN Gateway",
            "owner": "bob", "assetOwner": "bob",
            "status": "open", "isClosed": False,
            "deadline": None, "daysLeft": None, "escStage": 0,
        },
        # Open, well within SLA: escStage 0, not overdue, not due.
        {
            "id": "F-FRESH", "title": "Missing security headers",
            "severity": "low", "assetId": "AST-AGENT", "asset": "Agent App",
            "owner": "carol", "assetOwner": "carol",
            "status": "open", "isClosed": False,
            "deadline": "2026-07-01", "daysLeft": 29, "escStage": 0,
        },
        # Overdue: daysLeft negative, escStage 4 -> overdue + due.
        {
            "id": "F-OVERDUE", "title": "BOLA on /v1/claims/{id}",
            "severity": "critical", "assetId": "AST-CLAIMS", "asset": "Claims API",
            "owner": "dave", "assetOwner": "dave",
            "status": "open", "isClosed": False,
            "deadline": "2026-05-05", "daysLeft": -28, "escStage": 4,
        },
        # escStage 3, not yet overdue -> due via the escStage >= 3 rule.
        {
            "id": "F-STAGE3", "title": "Verbose stack traces on 500",
            "severity": "medium", "assetId": "AST-UW", "asset": "Underwriting",
            "owner": "erin", "assetOwner": "erin",
            "status": "open", "isClosed": False,
            "deadline": "2026-06-05", "daysLeft": 3, "escStage": 3,
        },
        # escStage 2, not overdue -> active but NOT due (used for role mapping).
        {
            "id": "F-STAGE2", "title": "Missing rate limiting on OTP",
            "severity": "high", "assetId": "AST-AUTH", "asset": "Auth Service",
            "owner": "frank", "assetOwner": "frank",
            "status": "open", "isClosed": False,
            "deadline": "2026-06-10", "daysLeft": 8, "escStage": 2,
        },
    ]


def _by_id(report):
    return {r["id"]: r for r in report["findings"]}


def test_exclusions():
    report = build_escalations(sample_findings())
    ids = {r["id"] for r in report["findings"]}
    assert "F-CLOSED" not in ids, "closed finding must be excluded"
    assert "F-INFO" not in ids, "deadline-None finding must be excluded"
    # 4 active out of 6 input.
    assert report["counts"]["active"] == 4, report["counts"]
    assert len(report["findings"]) == 4
    # escalation_for returns None directly for the excluded ones.
    assert escalation_for(sample_findings()[0]) is None   # closed
    assert escalation_for(sample_findings()[1]) is None    # deadline None
    print("  [ok] closed + deadline-None findings excluded from findings/counts")


def test_stagecounts_sum_matches_active():
    report = build_escalations(sample_findings())
    assert sum(report["stageCounts"]) == report["counts"]["active"]
    # Spread: stage 0 (fresh), stage 2 (otp), stage 3 (stack traces), stage 4 (bola).
    assert report["stageCounts"] == [1, 0, 1, 1, 1], report["stageCounts"]
    print("  [ok] stageCounts sums to counts.active")


def test_role_mapping():
    recs = _by_id(build_escalations(sample_findings()))

    # escStage 2 -> role AppSec Lead, nextRole Security Manager, nextDay 9.
    s2 = recs["F-STAGE2"]
    assert s2["escStage"] == 2
    assert s2["role"] == "AppSec Lead"
    assert s2["stageLabel"] == "Team Lead"
    assert s2["nextRole"] == "Security Manager"
    assert s2["nextDay"] == 9

    # escStage 4 -> nextRole stays CISO, nextDay 18 (clamped at top of ladder).
    s4 = recs["F-OVERDUE"]
    assert s4["escStage"] == 4
    assert s4["role"] == "CISO"
    assert s4["stageLabel"] == "CISO escalation"
    assert s4["nextRole"] == "CISO"
    assert s4["nextDay"] == 18

    # escStage 0 -> role Asset Owner, nextRole Asset Owner, nextDay 2.
    s0 = recs["F-FRESH"]
    assert s0["role"] == "Asset Owner"
    assert s0["nextRole"] == "Asset Owner"
    assert s0["nextDay"] == 2

    # Sanity: records mirror LADDER role for their stage.
    for r in recs.values():
        assert r["role"] == LADDER[r["escStage"]]["role"]
    print("  [ok] role/nextRole/nextDay map correctly to LADDER")


def test_overdue_and_due_flags():
    recs = _by_id(build_escalations(sample_findings()))

    fresh = recs["F-FRESH"]
    assert fresh["overdue"] is False
    assert fresh["dueForEscalation"] is False

    overdue = recs["F-OVERDUE"]
    assert overdue["overdue"] is True
    assert overdue["dueForEscalation"] is True

    stage3 = recs["F-STAGE3"]
    assert stage3["overdue"] is False           # daysLeft 3, not overdue
    assert stage3["dueForEscalation"] is True   # due via escStage >= 3 rule

    stage2 = recs["F-STAGE2"]
    assert stage2["overdue"] is False
    assert stage2["dueForEscalation"] is False   # not overdue, escStage < 3

    assert build_escalations(sample_findings())["counts"]["overdue"] == 1
    print("  [ok] overdue / dueForEscalation flags correct per case")


def test_due_subset_and_sort():
    report = build_escalations(sample_findings())
    due_ids = [r["id"] for r in report["due"]]

    # Exactly the dueForEscalation subset.
    expected_due = {r["id"] for r in report["findings"] if r["dueForEscalation"]}
    assert set(due_ids) == expected_due == {"F-OVERDUE", "F-STAGE3"}, due_ids
    assert report["counts"]["due"] == 2

    # Sorted by daysLeft ascending (most overdue first): -28 then 3.
    assert due_ids == ["F-OVERDUE", "F-STAGE3"], due_ids

    # The full findings list is also sorted ascending with None last.
    days = [r["daysLeft"] for r in report["findings"]]
    assert days == [-28, 3, 8, 29], days
    print("  [ok] due is the dueForEscalation subset, sorted by daysLeft asc")


def test_determinism():
    a = build_escalations(sample_findings())
    b = build_escalations(sample_findings())
    assert a == b, "build_escalations must be deterministic"
    print("  [ok] build_escalations is deterministic")


def test_no_input_mutation():
    findings = sample_findings()
    snapshot = [dict(f) for f in findings]
    build_escalations(findings)
    assert findings == snapshot, "build_escalations must not mutate input dicts"
    print("  [ok] caller finding dicts are not mutated")


def test_empty_input():
    report = build_escalations([])
    assert report["findings"] == []
    assert report["due"] == []
    assert report["stageCounts"] == [0, 0, 0, 0, 0]
    assert report["counts"] == {"active": 0, "overdue": 0, "due": 0}
    assert report["ladder"] == LADDER
    print("  [ok] empty input yields a well-formed empty rollup")


def main():
    tests = [
        test_exclusions,
        test_stagecounts_sum_matches_active,
        test_role_mapping,
        test_overdue_and_due_flags,
        test_due_subset_and_sort,
        test_determinism,
        test_no_input_mutation,
        test_empty_input,
    ]
    print("Running deterministic escalation engine self-test...\n")
    for t in tests:
        t()
    print("\nALL ESCALATION TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
