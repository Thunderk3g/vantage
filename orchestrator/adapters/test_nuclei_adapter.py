"""
Runnable self-test for the Nuclei adapter's parse().

Plain asserts + a __main__ block — no pytest required. Run either of:

    python orchestrator/adapters/test_nuclei_adapter.py
    python -m adapters.test_nuclei_adapter      # with orchestrator/ on sys.path

Covers:
  * one CanonicalFinding per VALID JSON line (blank line skipped),
  * Nuclei severity mapping: critical -> CRITICAL, info -> INFO,
  * the Log4j record carries cve ["CVE-2021-44228"] and cvss_base 10.0,
  * source_tool == "nuclei", native_id == template-id, dedup_key populated,
  * asset_id is deterministic and host-derived (AST-<host with dots->dashes>),
  * the blank line and the record missing `classification` don't crash.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters.nuclei_adapter import NucleiAdapter  # noqa: E402
from shared import RawArtifact, Severity  # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "nuclei_sample.jsonl"
)
EXPECTED_COUNT = 5  # critical, high, medium, low, info (the blank line is skipped)


def _raw() -> RawArtifact:
    return RawArtifact(
        scan_id="N1",
        source_tool="nuclei",
        uri=FIXTURE,
        native_format="nuclei-jsonl",
    )


def test_count_and_basic_shape():
    findings = NucleiAdapter().parse(_raw())
    assert len(findings) == EXPECTED_COUNT, (
        f"expected {EXPECTED_COUNT} findings, got {len(findings)}"
    )
    for f in findings:
        assert f.source_tool == "nuclei", f.source_tool
        assert f.dedup_key, f"dedup_key empty for {f.title!r}"
        assert f.asset_id.startswith("AST-"), f.asset_id
        assert f.native_id, f"native_id (template-id) empty for {f.title!r}"
    print("  [ok] one finding per valid line (blank skipped); core fields set")


def test_severity_mapping():
    by_id = {f.native_id: f for f in NucleiAdapter().parse(_raw())}

    crit = by_id["CVE-2021-44228"]
    assert crit.severity_normalized == Severity.CRITICAL, crit.severity_normalized

    high = by_id["jenkins-exposed-panel"]
    assert high.severity_normalized == Severity.HIGH, high.severity_normalized

    med = by_id["http-missing-security-headers"]
    assert med.severity_normalized == Severity.MEDIUM, med.severity_normalized

    low = by_id["weak-cipher-suites"]
    assert low.severity_normalized == Severity.LOW, low.severity_normalized

    info = by_id["tls-version"]
    assert info.severity_normalized == Severity.INFO, info.severity_normalized
    print("  [ok] critical->CRITICAL, high, medium, low, info->INFO")


def test_log4j_cve_and_cvss():
    log4j = next(
        f for f in NucleiAdapter().parse(_raw())
        if f.native_id == "CVE-2021-44228"
    )
    assert log4j.cve == ["CVE-2021-44228"], log4j.cve
    assert log4j.cvss_base == 10.0, log4j.cvss_base
    assert log4j.cvss_vector and log4j.cvss_vector.startswith("CVSS:3.1/"), log4j.cvss_vector
    assert log4j.title == "Apache Log4j RCE (Log4Shell)", log4j.title
    print("  [ok] Log4j carries cve ['CVE-2021-44228'] + cvss_base 10.0 + vector")


def test_asset_id_deterministic_and_host_derived():
    by_id = {f.native_id: f for f in NucleiAdapter().parse(_raw())}

    # host "https://app.internal" -> strip scheme -> AST-app-internal
    assert by_id["CVE-2021-44228"].asset_id == "AST-app-internal", \
        by_id["CVE-2021-44228"].asset_id
    # host "https://ci.internal" -> AST-ci-internal
    assert by_id["jenkins-exposed-panel"].asset_id == "AST-ci-internal", \
        by_id["jenkins-exposed-panel"].asset_id
    # host "app.internal:443" (no scheme, with port) -> strip :port -> AST-app-internal
    assert by_id["weak-cipher-suites"].asset_id == "AST-app-internal", \
        by_id["weak-cipher-suites"].asset_id

    # Determinism: parsing twice yields identical asset_id + dedup_key.
    again = {f.native_id: f for f in NucleiAdapter().parse(_raw())}
    for tid, f in by_id.items():
        assert again[tid].asset_id == f.asset_id, tid
        assert again[tid].dedup_key == f.dedup_key, tid
    print("  [ok] asset_id host-derived (scheme/port stripped) + deterministic")


def test_missing_classification_does_not_crash():
    # "jenkins-exposed-panel" (high) has NO classification block at all.
    high = next(
        f for f in NucleiAdapter().parse(_raw())
        if f.native_id == "jenkins-exposed-panel"
    )
    assert high.cve == [], high.cve
    assert high.cvss_base is None, high.cvss_base
    assert high.cvss_vector is None, high.cvss_vector
    assert high.dedup_key, "dedup_key must still be computed"

    # "http-missing-security-headers" has classification but no cve/cvss.
    med = next(
        f for f in NucleiAdapter().parse(_raw())
        if f.native_id == "http-missing-security-headers"
    )
    assert med.cve == [], med.cve
    assert med.cvss_base is None, med.cvss_base
    print("  [ok] missing classification / blank line parsed without crashing")


def main():
    tests = [
        test_count_and_basic_shape,
        test_severity_mapping,
        test_log4j_cve_and_cvss,
        test_asset_id_deterministic_and_host_derived,
        test_missing_classification_does_not_crash,
    ]
    print("Running Nuclei adapter self-test...\n")
    for t in tests:
        t()
    print("\nALL NUCLEI ADAPTER TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
