"""
Runnable end-to-end self-test for the reference pipeline (no pytest).

Drives the committed sample fixtures through the full pipeline
(``pipeline.run_reference_pipeline`` -> adapters -> ``normalize_and_triage``)
and asserts the contract:

  * all four adapters parse their fixture into >= 1 finding;
  * the triaged register is non-empty and every severity band is a canonical
    lower-case value — proving the enum-coercion fix (NOT everything collapsed
    to 'info': the Burp 'high' and the Nessus critical survive);
  * SLA stamping is correct (non-info -> slaDays in {30,60} + deadline;
    info -> slaDays is None);
  * taxonomy is populated for at least the web findings;
  * cross-tool dedup collapses two same-CVE findings from different tools to a
    single canonical finding (built in-test, no fixture edits).

Run directly:  python orchestrator/test_pipeline_e2e.py
"""
from __future__ import annotations

import os
import sys
from datetime import date

# Bootstrap the orchestrator dir onto sys.path so ``import pipeline`` (and the
# adapters/shared it pulls in) resolves regardless of cwd.
_ORCH_DIR = os.path.dirname(os.path.abspath(__file__))
if _ORCH_DIR not in sys.path:
    sys.path.insert(0, _ORCH_DIR)

import pipeline  # noqa: E402
import normalization  # noqa: E402
from shared import CanonicalFinding  # noqa: E402

TODAY = date(2026, 6, 1)
_BANDS = {"critical", "high", "medium", "low", "info"}


def test_load_fixture_findings_all_tools():
    raw_by_tool = pipeline.load_fixture_findings()
    for tool in ("nmap", "nessus", "burp", "nikto"):
        assert tool in raw_by_tool, f"missing tool {tool!r} in {list(raw_by_tool)}"
        assert len(raw_by_tool[tool]) >= 1, f"{tool} produced no findings"
    print("  [ok] load_fixture_findings: nmap/nessus/burp/nikto each >= 1 finding")


def test_register_non_empty_and_bands_normalized():
    register = pipeline.run_reference_pipeline(today=TODAY)
    assert register, "reference pipeline produced an empty register"

    bands = {f["severity_normalized"] for f in register}
    # Every band is a canonical lower-case value (enum-coercion fix in effect).
    assert bands <= _BANDS, f"non-canonical severity band(s): {bands - _BANDS}"
    # NOT everything collapsed to 'info' — at least one non-info band survives.
    assert bands - {"info"}, "every finding collapsed to 'info' (enum fix broken)"
    # Specifically the Burp 'high' and the Nessus critical survive.
    assert "high" in bands, f"expected a 'high' band (Burp high), got {bands}"
    assert "critical" in bands, f"expected a 'critical' band (Nessus), got {bands}"
    print("  [ok] register non-empty; bands normalized; high + critical survive")


def test_sla_stamping():
    register = pipeline.run_reference_pipeline(today=TODAY)
    for f in register:
        if f["severity_normalized"] == "info":
            assert f["slaDays"] is None, f"info finding has slaDays {f['slaDays']}"
        else:
            assert f["slaDays"] in (30, 60), \
                f"non-info finding has slaDays {f['slaDays']}"
            assert f["deadline"] is not None, \
                f"non-info finding {f['title']!r} has null deadline"
    print("  [ok] SLA: non-info -> {30,60} + deadline; info -> slaDays None")


def test_taxonomy_populated_for_web():
    register = pipeline.run_reference_pipeline(today=TODAY)
    has_taxonomy = any(
        f.get("owasp_web") or f.get("sans25") or f.get("owasp_api")
        for f in register
    )
    assert has_taxonomy, "no finding carried any OWASP/SANS taxonomy"
    print("  [ok] taxonomy populated for at least one (web) finding")


def test_cross_tool_dedup_same_cve():
    """Two findings with the SAME cve from two different source_tools collapse
    to ONE canonical finding (duplicates == 1)."""
    a = CanonicalFinding(
        asset_id="AST-PORTAL", source_tool="nessus", native_id="11111",
        title="Outdated component with known RCE",
        description=None, cve=["CVE-2024-9999"], cvss_base=8.6,
    )
    b = CanonicalFinding(
        asset_id="AST-PORTAL", source_tool="nuclei", native_id=None,
        title="Vulnerable dependency (different wording)",
        description=None, cve=["CVE-2024-9999"], cvss_base=9.1,
    )
    register = normalization.normalize_and_triage(
        {"nessus": [a], "nuclei": [b]}, today=TODAY
    )
    assert len(register) == 1, f"expected 1 canonical finding, got {len(register)}"
    canonical = register[0]
    assert canonical["duplicates"] == 1, \
        f"expected duplicates == 1, got {canonical['duplicates']}"
    merged = canonical.get("merged_from") or []
    assert "nessus" in merged and "nuclei" in merged, \
        f"both tools should be merged_from, got {merged}"
    print("  [ok] cross-tool same-CVE (nessus + nuclei) collapses to 1 canonical")


def main():
    tests = [
        test_load_fixture_findings_all_tools,
        test_register_non_empty_and_bands_normalized,
        test_sla_stamping,
        test_taxonomy_populated_for_web,
        test_cross_tool_dedup_same_cve,
    ]
    print("Running reference pipeline end-to-end self-test...\n")
    for t in tests:
        t()
    print("\nALL PIPELINE E2E TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
