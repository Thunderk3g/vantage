"""
Runnable self-test for the Nessus adapter's `.nessus` XML parser.

Plain asserts + a __main__ block — no pytest required. Run either of:

    python orchestrator/adapters/test_nessus_adapter.py
    python -m adapters.test_nessus_adapter     # with orchestrator/ on sys.path

Covers the behaviours called out in the build spec:
  * one ReportItem -> one CanonicalFinding (count matches the fixture),
  * cvss >= 9 item -> Severity.CRITICAL,
  * no-cvss severity="1" item -> Severity.LOW (the _band fallback path),
  * multi-<cve> item -> populated cve list,
  * policy="VA"  -> source_tool "nessus", cis_control always None,
  * policy="CIS" -> source_tool "nessus-cis", compliance item -> cis_control set.

Parsing is via defusedxml (XXE-safe); the fixture is benign synthetic data.
"""
from __future__ import annotations

import os
import sys

# Make the adapter importable whether run as a script or a module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters.nessus_adapter import NessusAdapter  # noqa: E402
from shared import RawArtifact, Severity            # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "nessus_sample.nessus"
)

# Number of <ReportItem> elements across all hosts in the fixture.
EXPECTED_COUNT = 4


def _raw() -> RawArtifact:
    return RawArtifact(
        scan_id="scan-synthetic-1",
        source_tool="nessus",
        uri=os.path.abspath(FIXTURE),
        native_format="nessus-xml",
    )


def _by_title(findings):
    return {f.title: f for f in findings}


def test_fixture_present():
    assert os.path.isfile(FIXTURE), f"missing fixture: {FIXTURE}"
    print("  [ok] fixture present:", os.path.basename(FIXTURE))


def test_finding_count_matches_fixture():
    fs = NessusAdapter(policy="VA").parse(_raw())
    assert len(fs) == EXPECTED_COUNT, f"expected {EXPECTED_COUNT}, got {len(fs)}"
    print(f"  [ok] one finding per ReportItem ({EXPECTED_COUNT})")


def test_critical_band_and_multi_cve():
    fs = _by_title(NessusAdapter(policy="VA").parse(_raw()))
    crit = fs["OpenSSL Remote Code Execution"]
    assert crit.cvss_base is not None and crit.cvss_base >= 9.0
    assert crit.severity_normalized == Severity.CRITICAL
    # multi-<cve> item -> both CVEs captured, in order.
    assert crit.cve == ["CVE-2024-0001", "CVE-2024-0002"], crit.cve
    assert crit.cvss_vector and crit.cvss_vector.startswith("CVSS:3.1")
    print("  [ok] cvss>=9 -> CRITICAL; 2 CVEs captured")


def test_no_cvss_severity_one_falls_back_to_low():
    fs = _by_title(NessusAdapter(policy="VA").parse(_raw()))
    banner = fs["HTTP Server Banner Disclosure"]
    # No CVSS in the fixture for this item: cvss_base must be None and the
    # band must come from the Nessus severity="1" attribute -> LOW.
    assert banner.cvss_base is None
    assert banner.severity_normalized == Severity.LOW
    # Missing <description> and zero <cve> must not crash and stay empty.
    assert banner.description is None
    assert banner.cve == []
    print("  [ok] no-cvss severity=1 -> LOW via _band fallback (no crash)")


def test_medium_band():
    fs = _by_title(NessusAdapter(policy="VA").parse(_raw()))
    med = fs["Web Server Allows Directory Listing"]
    assert med.severity_normalized == Severity.MEDIUM
    assert med.cve == ["CVE-2023-9999"]
    print("  [ok] mid-band cvss -> MEDIUM")


def test_va_policy_source_and_no_cis():
    fs = NessusAdapter(policy="VA").parse(_raw())
    assert all(f.source_tool == "nessus" for f in fs)
    # VA never sets a CIS control, even on the compliance-shaped item.
    assert all(f.cis_control is None for f in fs)
    print("  [ok] VA: source_tool 'nessus', cis_control None on every finding")


def test_cis_policy_source_and_control():
    fs = NessusAdapter(policy="CIS").parse(_raw())
    assert all(f.source_tool == "nessus-cis" for f in fs)
    by_title = _by_title(fs)
    compliance = by_title[
        "CIS Benchmark: Ensure 'Minimum password length' is set"
    ]
    assert compliance.cis_control == "CIS-5.2", compliance.cis_control
    # Non-compliance items still carry no CIS control under the CIS policy.
    assert by_title["OpenSSL Remote Code Execution"].cis_control is None
    print("  [ok] CIS: source_tool 'nessus-cis'; compliance item -> CIS-5.2")


def test_deterministic_dedup_keys():
    a = NessusAdapter(policy="VA").parse(_raw())
    b = NessusAdapter(policy="VA").parse(_raw())
    assert [f.dedup_key for f in a] == [f.dedup_key for f in b]
    assert all(f.dedup_key for f in a), "dedup_key must be populated"
    # Asset id is deterministic from the host address.
    assert a[0].asset_id == "AST-10-0-0-5"
    print("  [ok] dedup keys stable; asset_id deterministic (AST-10-0-0-5)")


def main():
    tests = [
        test_fixture_present,
        test_finding_count_matches_fixture,
        test_critical_band_and_multi_cve,
        test_no_cvss_severity_one_falls_back_to_low,
        test_medium_band,
        test_va_policy_source_and_no_cis,
        test_cis_policy_source_and_control,
        test_deterministic_dedup_keys,
    ]
    print("Running Nessus adapter self-test...\n")
    for t in tests:
        t()
    print("\nALL NESSUS ADAPTER TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
