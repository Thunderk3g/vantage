"""
Runnable self-test for the Trivy adapter's JSON report parser.

Plain asserts + a __main__ block — no pytest required. Run either of:

    python orchestrator/adapters/test_trivy_adapter.py
    python -m adapters.test_trivy_adapter     # with orchestrator/ on sys.path

Covers the behaviours called out in the build spec:
  * total findings == (vulnerabilities + misconfigurations) across results,
  * CRITICAL CVE vuln -> Severity.CRITICAL, cve ["CVE-..."], cvss_base 9.8,
  * no-CVSS vuln -> its Trivy severity band with cvss_base None (no crash),
  * Misconfiguration -> finding with native_id "DS002", cve [],
  * source_tool == "trivy" on every finding,
  * asset_id deterministic + artifact-derived,
  * dedup_key populated + distinct,
  * a Result with empty Vulnerabilities[] does not crash.

Parsing is via stdlib json (no XML/XXE surface); the fixture is benign
synthetic data — no real registries.
"""
from __future__ import annotations

import os
import sys

# Make the adapter importable whether run as a script or a module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters.trivy_adapter import TrivyAdapter  # noqa: E402
from shared import RawArtifact, Severity          # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "trivy_sample.json"
)

# 2 vulnerabilities (os-pkgs) + 1 misconfiguration (config). The lang-pkgs
# result has an empty Vulnerabilities[] and must contribute nothing.
EXPECTED_COUNT = 3


def _raw() -> RawArtifact:
    return RawArtifact(
        scan_id="T1",
        source_tool="trivy",
        uri=os.path.abspath(FIXTURE),
        native_format="trivy-json",
    )


def _by_native_id(findings):
    return {f.native_id: f for f in findings}


def test_fixture_present():
    assert os.path.isfile(FIXTURE), f"missing fixture: {FIXTURE}"
    print("  [ok] fixture present:", os.path.basename(FIXTURE))


def test_total_count_vulns_plus_misconfigs():
    fs = TrivyAdapter().parse(_raw())
    assert len(fs) == EXPECTED_COUNT, f"expected {EXPECTED_COUNT}, got {len(fs)}"
    print(f"  [ok] total findings == vulns + misconfigs ({EXPECTED_COUNT})")


def test_critical_cve_vuln():
    fs = _by_native_id(TrivyAdapter().parse(_raw()))
    crit = fs["CVE-2023-1234"]
    assert crit.severity_normalized == Severity.CRITICAL
    assert crit.cve == ["CVE-2023-1234"], crit.cve
    assert crit.cvss_base == 9.8, crit.cvss_base
    # nvd is preferred over the redhat (8.1) score, with the matching vector.
    assert crit.cvss_vector and crit.cvss_vector.startswith("CVSS:3.1")
    print("  [ok] CRITICAL CVE -> CRITICAL, cve set, cvss_base 9.8 (nvd preferred)")


def test_no_cvss_vuln_falls_back():
    fs = _by_native_id(TrivyAdapter().parse(_raw()))
    med = fs["CVE-2023-5678"]
    # No CVSS block in the fixture for this vuln: must not crash.
    assert med.cvss_base is None
    assert med.cvss_vector is None
    # Severity band still comes straight from the Trivy "MEDIUM" string.
    assert med.severity_normalized == Severity.MEDIUM
    assert med.cve == ["CVE-2023-5678"]
    print("  [ok] no-CVSS vuln -> MEDIUM band, cvss_base None (no crash)")


def test_misconfiguration_finding():
    fs = _by_native_id(TrivyAdapter().parse(_raw()))
    misc = fs["DS002"]
    assert misc.native_id == "DS002"
    assert misc.severity_normalized == Severity.HIGH
    assert misc.cve == [], misc.cve
    assert misc.cvss_base is None
    assert misc.title and "root" in misc.title.lower()
    print("  [ok] misconfiguration -> native_id 'DS002', cve [] (HIGH)")


def test_source_tool_and_asset_id():
    fs = TrivyAdapter().parse(_raw())
    assert all(f.source_tool == "trivy" for f in fs)
    # Asset id is deterministic + derived from ArtifactName (slugified).
    expected = "AST-registry-internal-claims-api-1-4-2"
    assert all(f.asset_id == expected for f in fs), {f.asset_id for f in fs}
    print(f"  [ok] source_tool 'trivy'; asset_id deterministic ({expected})")


def test_dedup_keys_populated_and_distinct():
    a = TrivyAdapter().parse(_raw())
    b = TrivyAdapter().parse(_raw())
    # Stable across runs.
    assert [f.dedup_key for f in a] == [f.dedup_key for f in b]
    # Populated and distinct per finding.
    keys = [f.dedup_key for f in a]
    assert all(keys), "dedup_key must be populated"
    assert len(set(keys)) == len(keys), "dedup_keys must be distinct"
    print("  [ok] dedup keys stable, populated, and distinct")


def test_empty_vulnerabilities_result_no_crash():
    # The lang-pkgs result has Vulnerabilities: [] — parsing it contributes
    # zero findings and does not raise. If we got here with EXPECTED_COUNT
    # findings, the empty result was handled defensively.
    fs = TrivyAdapter().parse(_raw())
    assert len(fs) == EXPECTED_COUNT
    print("  [ok] empty-Vulnerabilities result handled defensively (no crash)")


def main():
    tests = [
        test_fixture_present,
        test_total_count_vulns_plus_misconfigs,
        test_critical_cve_vuln,
        test_no_cvss_vuln_falls_back,
        test_misconfiguration_finding,
        test_source_tool_and_asset_id,
        test_dedup_keys_populated_and_distinct,
        test_empty_vulnerabilities_result_no_crash,
    ]
    print("Running Trivy adapter self-test...\n")
    for t in tests:
        t()
    print("\nALL TRIVY ADAPTER TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
