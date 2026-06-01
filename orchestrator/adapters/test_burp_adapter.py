"""
Runnable self-test for the Burp adapter's parse().

Plain asserts + a __main__ block — no pytest required. Run either of:

    python orchestrator/adapters/test_burp_adapter.py
    python -m adapters.test_burp_adapter      # with orchestrator/ on sys.path

Covers:
  * one CanonicalFinding per fixture issue,
  * Burp severity mapping: high -> HIGH (NOT critical), info -> INFO,
  * source_tool == "burp" and dedup_key populated for every finding,
  * auth_context="min_priv" flows through to AuthContextName.MIN_PRIV,
  * the issue missing optional fields (no path/description) parses cleanly.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters.burp_adapter import BurpAdapter  # noqa: E402
from shared import RawArtifact, Severity, AuthContextName  # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "burp_sample.json"
)
EXPECTED_COUNT = 4  # high, medium, low, info in the fixture


def _raw() -> RawArtifact:
    return RawArtifact(
        scan_id="scan-test-burp",
        source_tool="burp",
        uri=FIXTURE,
        native_format="burp-json",
    )


def test_count_and_basic_shape():
    findings = BurpAdapter(mode="scan").parse(_raw())
    assert len(findings) == EXPECTED_COUNT, (
        f"expected {EXPECTED_COUNT} findings, got {len(findings)}"
    )
    for f in findings:
        assert f.source_tool == "burp", f.source_tool
        assert f.dedup_key, f"dedup_key empty for {f.title!r}"
        assert f.asset_id.startswith("AST-"), f.asset_id
    print("  [ok] one finding per issue; source_tool/dedup_key/asset_id set")


def test_severity_mapping():
    by_title = {f.title: f for f in BurpAdapter(mode="scan").parse(_raw())}

    xss = by_title["Cross-site scripting (reflected)"]
    assert xss.severity_normalized == Severity.HIGH, xss.severity_normalized
    assert xss.native_id == "2097920", xss.native_id

    med = by_title["Cleartext submission of password"]
    assert med.severity_normalized == Severity.MEDIUM, med.severity_normalized

    low = by_title["Cacheable HTTPS response"]
    assert low.severity_normalized == Severity.LOW, low.severity_normalized

    info = by_title["Robots.txt file"]
    assert info.severity_normalized == Severity.INFO, info.severity_normalized
    print("  [ok] high->HIGH (not critical), medium, low, info->INFO")


def test_missing_optional_fields_do_not_crash():
    # The "Robots.txt file" issue has no path and no description.
    info = next(
        f for f in BurpAdapter(mode="scan").parse(_raw())
        if f.title == "Robots.txt file"
    )
    assert info.description is None, info.description
    assert info.dedup_key, "dedup_key must still be computed without a path"
    assert info.asset_id == "AST-shop.demo.internal", info.asset_id
    print("  [ok] issue missing optional fields parsed without crashing")


def test_auth_context_flows_through():
    findings = BurpAdapter(mode="crawl", auth_context="min_priv").parse(_raw())
    assert findings, "expected findings"
    for f in findings:
        assert f.auth_context == AuthContextName.MIN_PRIV, f.auth_context
    print("  [ok] auth_context='min_priv' -> AuthContextName.MIN_PRIV on findings")


def test_auth_context_none_and_invalid():
    # No auth_context (default) -> None, no crash.
    for f in BurpAdapter(mode="scan").parse(_raw()):
        assert f.auth_context is None, f.auth_context
    # Bogus auth_context value -> None, no crash.
    for f in BurpAdapter(mode="scan", auth_context="superuser").parse(_raw()):
        assert f.auth_context is None, f.auth_context
    print("  [ok] absent/invalid auth_context -> None (no crash)")


def main():
    tests = [
        test_count_and_basic_shape,
        test_severity_mapping,
        test_missing_optional_fields_do_not_crash,
        test_auth_context_flows_through,
        test_auth_context_none_and_invalid,
    ]
    print("Running Burp adapter self-test...\n")
    for t in tests:
        t()
    print("\nALL BURP ADAPTER TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
