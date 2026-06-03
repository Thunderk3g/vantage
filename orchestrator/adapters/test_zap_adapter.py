"""
Runnable self-test for the ZAP adapter's parse().

Plain asserts + a __main__ block — no pytest required. Run either of:

    python orchestrator/adapters/test_zap_adapter.py
    python -m adapters.test_zap_adapter      # with orchestrator/ on sys.path

Covers:
  * one CanonicalFinding per fixture alert,
  * ZAP riskcode mapping: 3 -> HIGH (NOT critical — ZAP has no critical
    tier), 0 -> INFO,
  * source_tool == "zap" for every finding,
  * asset_id deterministic and host-derived (AST-app-internal),
  * dedup_key populated and distinct across findings,
  * the alert with an empty/missing ``instances`` parses without crashing.
"""
from __future__ import annotations

import os
import sys

# Make the adapter + shared types importable whether run as a script or module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters.zap_adapter import ZapAdapter  # noqa: E402
from shared import RawArtifact, Severity      # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "zap_sample.json"
)
EXPECTED_COUNT = 4  # riskcode 3, 2, 1, 0 in the fixture


def _raw() -> RawArtifact:
    return RawArtifact(
        scan_id="Z1",
        source_tool="zap",
        uri=FIXTURE,
        native_format="zap-json",
    )


def test_count_matches_alerts():
    findings = ZapAdapter().parse(_raw())
    assert len(findings) == EXPECTED_COUNT, (
        f"expected {EXPECTED_COUNT} findings, got {len(findings)}"
    )
    print(f"  [ok] finding count matches alert count ({len(findings)})")


def test_source_tool():
    findings = ZapAdapter().parse(_raw())
    assert all(f.source_tool == "zap" for f in findings), (
        [f.source_tool for f in findings]
    )
    print("  [ok] source_tool == 'zap' for every finding")


def test_riskcode_severity_mapping():
    by_title = {f.title: f for f in ZapAdapter().parse(_raw())}

    xss = by_title["Cross Site Scripting (Reflected)"]
    # riskcode 3 -> HIGH, NOT critical (ZAP has no critical tier).
    assert xss.severity_normalized is Severity.HIGH, xss.severity_normalized
    assert xss.severity_normalized is not Severity.CRITICAL
    assert xss.native_id == "40012", xss.native_id

    csrf = by_title["Absence of Anti-CSRF Tokens"]
    assert csrf.severity_normalized is Severity.MEDIUM, csrf.severity_normalized

    cookie = by_title["Cookie No HttpOnly Flag"]
    assert cookie.severity_normalized is Severity.LOW, cookie.severity_normalized

    info = by_title["Information Disclosure - Sensitive Information in URL"]
    assert info.severity_normalized is Severity.INFO, info.severity_normalized

    print("  [ok] riskcode 3->HIGH (not critical), 2->MEDIUM, 1->LOW, 0->INFO")


def test_asset_id_deterministic_from_host():
    findings = ZapAdapter().parse(_raw())
    asset_ids = {f.asset_id for f in findings}
    # Single site -> single host -> single asset id.
    assert len(asset_ids) == 1, f"expected one asset_id, got {asset_ids}"
    asset_id = asset_ids.pop()
    assert asset_id == "AST-app-internal", asset_id
    # Deterministic across repeated parses.
    again = {f.asset_id for f in ZapAdapter().parse(_raw())}
    assert again == {asset_id}, "asset_id must be deterministic"
    print(f"  [ok] asset_id deterministic + host-derived ({asset_id})")


def test_dedup_keys_populated_and_distinct():
    findings = ZapAdapter().parse(_raw())
    keys = [f.dedup_key for f in findings]
    assert all(keys), "every finding must have a populated dedup_key"
    assert len(set(keys)) == len(keys), f"dedup_keys not distinct: {keys}"
    print("  [ok] dedup_key populated and distinct across findings")


def test_cve_empty():
    # ZAP reports CWE, not CVE — cve is always left empty here.
    findings = ZapAdapter().parse(_raw())
    assert all(f.cve == [] for f in findings), [f.cve for f in findings]
    print("  [ok] cve empty for every finding (ZAP reports CWE, not CVE)")


def test_missing_instances_did_not_crash():
    """The Information Disclosure alert has instances=[]; parse() must still
    emit it cleanly with a well-formed dedup_key (empty uri segment)."""
    info = next(
        f for f in ZapAdapter().parse(_raw())
        if f.native_id == "10094"
    )
    assert info.severity_normalized is Severity.INFO, info.severity_normalized
    assert info.dedup_key, "dedup_key must be computed even with no instances"
    assert info.title == "Information Disclosure - Sensitive Information in URL"
    print("  [ok] alert with empty/missing instances parsed without crashing")


def main():
    tests = [
        test_count_matches_alerts,
        test_source_tool,
        test_riskcode_severity_mapping,
        test_asset_id_deterministic_from_host,
        test_dedup_keys_populated_and_distinct,
        test_cve_empty,
        test_missing_instances_did_not_crash,
    ]
    print("Running ZAP adapter self-test...\n")
    for t in tests:
        t()
    print("\nALL ZAP ADAPTER TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
