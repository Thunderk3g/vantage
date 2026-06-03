"""Runnable self-test for the scan-diff / closure-verification engine.

Run:  python orchestrator/test_diff.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # orchestrator/

import diff  # noqa: E402
from diff import diff_scans, verify_closure, signature  # noqa: E402

PASS = []


def ok(msg):
    PASS.append(msg)
    print("  [ok] " + msg)


def F(dedup, sev, title="x", asset="AST-1", tool="nessus", cve=None):
    return {"dedup_key": dedup, "severity_normalized": sev, "title": title,
            "asset_id": asset, "source_tool": tool, "cve": cve or []}


def test_resolved_new_persisting():
    base = [F("k1", "high", "SQLi"), F("k2", "medium", "XSS"), F("k3", "low", "banner")]
    # current: k1 gone (resolved), k2 persists, k3 persists, k4 new
    cur = [F("k2", "medium", "XSS"), F("k3", "low", "banner"), F("k4", "critical", "RCE")]
    d = diff_scans(base, cur)
    assert d["counts"]["resolved"] == 1 and d["resolved"][0]["signature"] == "k1", d["resolved"]
    assert d["counts"]["new"] == 1 and d["new"][0]["signature"] == "k4", d["new"]
    assert d["counts"]["persisting"] == 2, d["counts"]
    assert d["counts"]["baseline"] == 3 and d["counts"]["current"] == 3
    ok("diff: resolved (k1) / new (k4) / persisting (k2,k3) classified correctly")


def test_regression():
    base = [F("k2", "low", "XSS")]
    cur = [F("k2", "critical", "XSS")]   # same finding, severity jumped
    d = diff_scans(base, cur)
    assert d["counts"]["regressed"] == 1, d["counts"]
    r = d["regressed"][0]
    assert r["severity"] == "critical" and r["fromSeverity"] == "low", r
    # a same-severity persisting finding is NOT a regression
    d2 = diff_scans([F("k2", "high")], [F("k2", "high")])
    assert d2["counts"]["regressed"] == 0
    ok("diff: regressed = persisting finding whose band increased (low -> critical)")


def test_verify_closure():
    cur = [F("k2", "medium"), F("k3", "low")]
    gone = F("k1", "high")          # not in current -> resolved
    still = F("k2", "medium")       # in current -> still present
    vc1 = verify_closure(gone, cur)
    assert vc1["verifiedResolved"] is True and vc1["stillPresent"] is False, vc1
    vc2 = verify_closure(still, cur)
    assert vc2["verifiedResolved"] is False and vc2["stillPresent"] is True, vc2
    ok("closure: absent-from-current -> verifiedResolved; present -> stillPresent")


def test_signature_fallback_and_determinism():
    # No dedup_key -> falls back to asset+cve, stable across calls.
    a = {"asset_id": "AST-9", "cve": ["CVE-2024-1", "CVE-2024-2"], "title": "t"}
    b = {"asset_id": "AST-9", "cve": ["CVE-2024-2", "CVE-2024-1"], "title": "different wording"}
    assert signature(a) == signature(b), "same asset+CVE set -> same signature (order-free)"
    d1 = diff_scans([F("k1", "high")], [F("k1", "high")])
    d2 = diff_scans([F("k1", "high")], [F("k1", "high")])
    assert d1 == d2, "diff_scans must be deterministic"
    ok("signature: dedup_key-less fallback is order-free; diff is deterministic")


def main():
    print("Running scan-diff engine self-test...\n")
    for t in (test_resolved_new_persisting, test_regression, test_verify_closure,
              test_signature_fallback_and_determinism):
        t()
    print(f"\nALL DIFF TESTS PASSED ({len(PASS)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
