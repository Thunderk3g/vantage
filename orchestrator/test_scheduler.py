"""Runnable self-test for the scan scheduler engine (no pytest).

Covers: per-asset cadence selection (web 2x/yr; infra VA 2x/yr + CIS 1x/yr),
next-due computation from last-run + cadence, overdue detection, blackout-window
shifting, and the rollup counts. Deterministic.

Run:  python orchestrator/test_scheduler.py
"""
from __future__ import annotations

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # orchestrator/

import scheduler  # noqa: E402
from scheduler import build_schedule, cadences_for, shift_out_of_blackout, SEMIANNUAL  # noqa: E402

TODAY = date(2026, 6, 2)
PASS = []


def ok(msg):
    PASS.append(msg)
    print("  [ok] " + msg)


WEB = {"id": "AST-PORTAL", "name": "Portal", "type": "web"}
INFRA = {"id": "AST-PAS", "name": "Core PAS", "type": "infra"}


def test_cadences():
    assert cadences_for(WEB) == [("web-pentest", "2x/yr", SEMIANNUAL)]
    infra = cadences_for(INFRA)
    types = {c[0] for c in infra}
    assert types == {"infra-va", "cis-review"}, types
    # CIS review is annual
    cis = [c for c in infra if c[0] == "cis-review"][0]
    assert cis[2] == 365, cis
    ok("cadence: web -> 1 plan (semiannual); infra -> VA semiannual + CIS annual")


def test_next_due_and_overdue():
    # last run 200 days ago, cadence 182 -> due 18 days ago -> overdue, scheduled now.
    last = {("AST-PAS", "infra-va"): (TODAY.fromordinal(TODAY.toordinal() - 200)).isoformat()}
    sched = build_schedule([INFRA], today=TODAY, last_runs=last, blackouts=[])
    va = [e for e in sched["entries"] if e["scanType"] == "infra-va"][0]
    assert va["overdue"] is True, va
    assert va["nextDue"] == TODAY.isoformat(), va["nextDue"]   # overdue -> now
    # CIS had no last-run -> baseline due now, not overdue
    cis = [e for e in sched["entries"] if e["scanType"] == "cis-review"][0]
    assert cis["overdue"] is False and cis["dueSoon"] is True, cis
    ok("next-due: overdue VA scheduled now; no-history CIS is a baseline due-soon")


def test_future_due():
    # last run 10 days ago, cadence 182 -> due in 172 days (not overdue, not soon).
    last = {("AST-PORTAL", "web-pentest"): (TODAY.fromordinal(TODAY.toordinal() - 10)).isoformat()}
    sched = build_schedule([WEB], today=TODAY, last_runs=last, blackouts=[])
    e = sched["entries"][0]
    assert e["overdue"] is False and e["dueSoon"] is False, e
    assert e["daysUntil"] == 172, e["daysUntil"]
    ok("next-due: recent run -> far-future window (not overdue/soon)")


def test_blackout_shift():
    blk = [{"start": "2026-06-01", "end": "2026-06-30", "reason": "freeze"}]
    # No last run -> due today (2026-06-02) which is INSIDE the freeze -> shifted to Jul 1.
    sched = build_schedule([WEB], today=TODAY, last_runs={}, blackouts=blk)
    e = sched["entries"][0]
    assert e["shiftedByBlackout"] is True and e["blackoutReason"] == "freeze", e
    assert e["nextDue"] == "2026-07-01", e["nextDue"]
    # direct helper: a date outside any window is unchanged
    d2, hit = shift_out_of_blackout(date(2026, 7, 5), blk)
    assert d2 == date(2026, 7, 5) and hit is None
    ok("blackout: a due date inside a freeze shifts to the day after it closes")


def test_counts_and_determinism():
    s1 = build_schedule([WEB, INFRA], today=TODAY)
    s2 = build_schedule([WEB, INFRA], today=TODAY)
    assert s1 == s2, "build_schedule must be deterministic"
    # web(1) + infra(2) = 3 entries
    assert s1["counts"]["total"] == 3, s1["counts"]
    assert s1["counts"]["total"] == len(s1["entries"])
    assert s1["blackouts"] == scheduler.DEFAULT_BLACKOUTS  # default calendar applied
    ok("rollup: counts total == entries; default blackout calendar; deterministic")


def main():
    print("Running scan-scheduler self-test...\n")
    for t in (test_cadences, test_next_due_and_overdue, test_future_due,
              test_blackout_shift, test_counts_and_determinism):
        t()
    print(f"\nALL SCHEDULER TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
