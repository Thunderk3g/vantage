"""Unit test for the seed.py persistence overlay — NO real DB needed.

Injects a FAKE in-memory ``store`` (the same 7-function interface as
``api.store``) into ``seed.store`` to prove:

  a. write-through + overlay on finding status (survives across ``findings()``
     calls because the overlay re-reads the store every call),
  b. scans/exceptions merge-by-id (write-through + persisted-only rows appear),
  c. id-collision safety (``_next_*_id`` accounts for persisted high ids),
  d. ZERO behavior change when the store is "unavailable" (real no-DB store).

Standalone runnable:  python orchestrator/api/test_seed_overlay.py
"""
from __future__ import annotations

import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))      # orchestrator/api
ORCH = os.path.dirname(HERE)                            # orchestrator
ROOT = os.path.dirname(ORCH)                            # repo root
for p in (ROOT, ORCH):
    if p not in sys.path:
        sys.path.insert(0, p)

from api import seed                                    # noqa: E402

PASS = []


def ok(msg: str) -> None:
    PASS.append(msg)
    print("  [ok] " + msg)


class FakeStore:
    """In-memory stand-in for ``api.store`` (round-trips dicts, never raises)."""

    def __init__(self) -> None:
        self.finding_state: dict[str, dict] = {}
        self._scans: dict[str, dict] = {}      # id -> dict (preserves insert order)
        self._exceptions: dict[str, dict] = {}

    def available(self) -> bool:
        return True

    def load_finding_state(self) -> dict[str, dict]:
        return {k: dict(v) for k, v in self.finding_state.items()}

    def save_finding_state(self, finding_id, status, validated_by, validated_at) -> None:
        self.finding_state[finding_id] = {
            "status": status,
            "humanValidatedBy": validated_by,
            "humanValidatedAt": validated_at,
        }

    def load_scans(self) -> list:
        return [dict(v) for v in self._scans.values()]

    def save_scan(self, scan: dict) -> None:
        self._scans[scan["id"]] = dict(scan)

    def load_exceptions(self) -> list:
        return [dict(v) for v in self._exceptions.values()]

    def save_exception(self, exc: dict) -> None:
        self._exceptions[exc["id"]] = dict(exc)


def _snapshot():
    """Capture the module-level lists seed mutates so we can restore them."""
    return (
        copy.deepcopy(seed._FINDINGS),
        copy.deepcopy(seed._SCANS),
        copy.deepcopy(seed._EXCEPTIONS),
    )


def _restore(snap) -> None:
    findings, scans, exceptions = snap
    seed._FINDINGS[:] = copy.deepcopy(findings)
    seed._SCANS[:] = copy.deepcopy(scans)
    seed._EXCEPTIONS[:] = copy.deepcopy(exceptions)


def _find(rows, rid):
    for r in rows:
        if r["id"] == rid:
            return r
    return None


# =====================================================================
# (a) write-through + overlay on finding status
# =====================================================================
def test_finding_write_through_and_overlay(fake: FakeStore) -> None:
    res = seed.update_finding_status("VLN-2074", "closed", "Ada <ada@corp>", "2026-06-01")
    assert res is not None and res["status"] == "closed", res

    # The fake store captured the save (write-through).
    rec = fake.finding_state.get("VLN-2074")
    assert rec is not None, "store did not capture save_finding_state"
    assert rec["status"] == "closed", rec
    assert rec["humanValidatedBy"] == "Ada <ada@corp>", rec
    assert rec["humanValidatedAt"] == "2026-06-01", rec
    ok("finding write-through: fake store captured VLN-2074 -> closed")

    # A FRESH findings() overlays the persisted record.
    f = _find(seed.findings(), "VLN-2074")
    assert f is not None
    assert f["status"] == "closed", f
    assert f["isClosed"] is True, f
    assert f["humanValidatedBy"] == "Ada <ada@corp>", f
    assert f["humanValidatedAt"] == "2026-06-01", f
    ok("finding overlay: findings() shows VLN-2074 closed/isClosed/validatedBy")

    # Overlay reads the store EVERY call: clear the in-memory mutation effect
    # (simulate a 'restart' where _FINDINGS is the pristine seed) and prove the
    # persisted state still wins.
    pristine = seed._derive_findings()
    seed._FINDINGS[:] = pristine
    f2 = _find(seed.findings(), "VLN-2074")
    assert f2["status"] == "closed", "overlay must survive across calls via store"
    assert f2["isClosed"] is True
    assert f2["humanValidatedBy"] == "Ada <ada@corp>"
    ok("finding overlay survives a simulated restart (store re-read each call)")

    # Persisted overrides seed default for risk_accepted too.
    seed.update_finding_status("VLN-2087", "risk_accepted", "Bo <bo@corp>", "2026-06-01")
    f3 = _find(seed.findings(), "VLN-2087")
    assert f3["status"] == "risk_accepted" and f3["isClosed"] is True, f3
    ok("finding overlay: risk_accepted also flips isClosed True")


# =====================================================================
# (b) scans / exceptions merge-by-id
# =====================================================================
def test_scans_merge(fake: FakeStore) -> None:
    asset = seed.asset_by_id("AST-PORTAL")
    created = seed.add_scan(asset, "web", "gray-box", "min-privilege", "Anu")
    assert created["id"] in fake._scans, "add_scan did not write through to store"
    ok("scan write-through: fake store captured " + created["id"])

    rows = seed.scans()
    assert _find(rows, created["id"]) is not None, "created scan missing from scans()"
    ok("scan merge: scans() includes the newly-created scan")

    # A persisted-only scan (never added via seed) must also appear.
    fake.save_scan({"id": "SCAN-0150", "target": "Injected", "pipeline": "web",
                    "type": "black-box", "auth": "—", "status": "queued",
                    "progress": 0, "started": "—", "findings": 0, "by": "X"})
    rows = seed.scans()
    inj = _find(rows, "SCAN-0150")
    assert inj is not None and inj["target"] == "Injected", rows
    ok("scan merge: persisted-only SCAN-0150 appears in scans()")

    # Persisted update to a SEED scan id wins.
    fake.save_scan({"id": "SCAN-0096", "target": "OVERRIDDEN", "pipeline": "infra",
                    "type": "gray-box", "auth": "max-privilege", "status": "completed",
                    "progress": 100, "started": "—", "findings": 1, "by": "X"})
    rows = seed.scans()
    seed_scan = _find(rows, "SCAN-0096")
    assert seed_scan["target"] == "OVERRIDDEN", "persisted must override seed scan"
    # de-dup: only one SCAN-0096
    assert sum(1 for r in rows if r["id"] == "SCAN-0096") == 1, "duplicate id in merge"
    ok("scan merge: persisted override of seed SCAN-0096 wins, de-duped")


def test_exceptions_merge(fake: FakeStore) -> None:
    finding = _find(seed.findings(), "VLN-2049")
    exc, tier = seed.add_exception(finding, "Anu", 2, "documented reason")
    assert exc["id"] in fake._exceptions, "add_exception did not write through"
    ok("exception write-through: fake store captured " + exc["id"])

    rows = seed.exceptions()
    assert _find(rows, exc["id"]) is not None, "created exception missing"
    ok("exception merge: exceptions() includes the newly-created exception")

    fake.save_exception({"id": "EXC-090", "finding": "VLN-1", "title": "Injected",
                         "asset": "A", "severity": "low", "duration": 1, "tier": "CISO",
                         "status": "pending", "requestedBy": "X", "approver": "CISO",
                         "reviewDate": "—", "reason": "r"})
    rows = seed.exceptions()
    inj = _find(rows, "EXC-090")
    assert inj is not None and inj["title"] == "Injected", rows
    ok("exception merge: persisted-only EXC-090 appears in exceptions()")


# =====================================================================
# (c) id-collision safety
# =====================================================================
def test_id_collision_safety(fake: FakeStore) -> None:
    fake.save_scan({"id": "SCAN-0200", "target": "hi", "pipeline": "web",
                    "type": "black-box", "auth": "—", "status": "queued",
                    "progress": 0, "started": "—", "findings": 0, "by": "X"})
    nid = seed._next_scan_id()
    assert nid == "SCAN-0201", "expected SCAN-0201 (persisted-aware), got " + nid
    ok("id-collision: _next_scan_id() -> SCAN-0201 (accounts for persisted 0200)")

    fake.save_exception({"id": "EXC-200", "finding": "VLN-1", "title": "t", "asset": "a",
                         "severity": "low", "duration": 1, "tier": "CISO",
                         "status": "pending", "requestedBy": "X", "approver": "CISO",
                         "reviewDate": "—", "reason": "r"})
    eid = seed._next_exception_id()
    assert eid == "EXC-201", "expected EXC-201 (persisted-aware), got " + eid
    ok("id-collision: _next_exception_id() -> EXC-201 (accounts for persisted 200)")


# =====================================================================
# (d) fallback unchanged — real (no-DB) store: ZERO behavior change
# =====================================================================
def test_fallback_unchanged() -> None:
    # seed.store is the REAL module here (no DB configured in this env), so all
    # load_* return {}/[] and save_* are no-ops.
    pristine = seed._derive_findings()
    seed._FINDINGS[:] = pristine

    fs = seed.findings()
    # Untouched finding keeps its seed-derived status / null validation fields.
    untouched = _find(fs, "VLN-2081")
    seed_untouched = _find(pristine, "VLN-2081")
    assert untouched["status"] == seed_untouched["status"], untouched
    assert untouched["isClosed"] == seed_untouched["isClosed"], untouched
    assert untouched["humanValidatedBy"] is None, untouched
    assert untouched["humanValidatedAt"] is None, untouched
    ok("fallback: findings() == seed-derived for an untouched finding (no DB)")

    # scans()/exceptions() equal the seed lists exactly.
    assert seed.scans() == [dict(s) for s in seed._SCANS], "scans() changed with no DB"
    assert seed.exceptions() == [dict(e) for e in seed._EXCEPTIONS], "exceptions() changed"
    ok("fallback: scans()/exceptions() equal seed lists (no DB, zero change)")

    # ids fall back to the seed-only max.
    assert seed._next_scan_id() == "SCAN-0099", seed._next_scan_id()
    assert seed._next_exception_id() == "EXC-047", seed._next_exception_id()
    ok("fallback: _next_*_id() use seed-only max (SCAN-0099 / EXC-047)")


def main() -> int:
    real_store = seed.store
    snap = _snapshot()
    try:
        # --- DB-present cases: inject the fake store ---
        fake = FakeStore()
        seed.store = fake
        test_finding_write_through_and_overlay(fake)
        test_scans_merge(fake)
        test_exceptions_merge(fake)
        test_id_collision_safety(fake)
    finally:
        seed.store = real_store
        _restore(snap)

    # --- Fallback case: real (no-DB) store restored ---
    try:
        test_fallback_unchanged()
    finally:
        _restore(snap)

    print("\nALL PASS ({} checks)".format(len(PASS)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
