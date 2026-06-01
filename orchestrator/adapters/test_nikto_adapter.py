"""
Runnable self-test for the Nikto adapter's parse().

Plain asserts + a __main__ block — no pytest required. Run:

    python orchestrator/adapters/test_nikto_adapter.py

Covers:
  * parse() reads the real nikto XML shape (<item> under <scandetails>),
  * finding count matches the number of <item> elements in the fixture,
  * source_tool / severity normalization (every finding LOW, refined later),
  * asset_id is deterministic and derived from the <scandetails> target host,
  * native_id values match the item ids in the fixture,
  * an <item> with an empty/missing <uri> does not crash parse().
"""
from __future__ import annotations

import os
import sys

# Make the adapter + shared types importable whether run as a script or module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters.nikto_adapter import NiktoAdapter  # noqa: E402
from shared import RawArtifact, Severity          # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "nikto_sample.xml")

# Item ids present in fixtures/nikto_sample.xml, in document order.
EXPECTED_IDS = ["999957", "999103", "999970", "999986"]


def _raw() -> RawArtifact:
    return RawArtifact(
        scan_id="S7",
        source_tool="nikto",
        uri=FIXTURE,
        native_format="nikto-xml",
    )


def test_count_matches_items():
    findings = NiktoAdapter().parse(_raw())
    assert len(findings) == len(EXPECTED_IDS), (
        f"expected {len(EXPECTED_IDS)} findings, got {len(findings)}"
    )
    print(f"  [ok] finding count matches item count ({len(findings)})")


def test_source_tool_and_severity():
    findings = NiktoAdapter().parse(_raw())
    assert all(f.source_tool == "nikto" for f in findings)
    assert all(f.severity_normalized is Severity.LOW for f in findings), (
        "every nikto finding is LOW (refined in triage)"
    )
    print("  [ok] source_tool == 'nikto' and every severity is LOW")


def test_asset_id_deterministic_from_host():
    findings = NiktoAdapter().parse(_raw())
    asset_ids = {f.asset_id for f in findings}
    # Single artifact -> single host -> single asset id.
    assert len(asset_ids) == 1, f"expected one asset_id, got {asset_ids}"
    asset_id = asset_ids.pop()
    assert asset_id, "asset_id must not be empty"
    # Derived from <scandetails targethostname="app.internal">.
    assert asset_id == "AST-app-internal", asset_id
    # Deterministic across repeated parses.
    again = {f.asset_id for f in NiktoAdapter().parse(_raw())}
    assert again == {asset_id}, "asset_id must be deterministic"
    print(f"  [ok] asset_id deterministic + host-derived ({asset_id})")


def test_native_ids_match_fixture():
    findings = NiktoAdapter().parse(_raw())
    assert [f.native_id for f in findings] == EXPECTED_IDS, (
        [f.native_id for f in findings]
    )
    print("  [ok] native_id values match fixture item ids")


def test_missing_uri_did_not_crash():
    """Item 999970 has an empty <uri>; parse() must still emit it cleanly."""
    findings = NiktoAdapter().parse(_raw())
    no_uri = next(f for f in findings if f.native_id == "999970")
    # dedup_key still well-formed: "<id>|<uri>" with an empty uri segment.
    assert no_uri.dedup_key == "999970|", no_uri.dedup_key
    assert no_uri.title, "title still derived from description"
    print("  [ok] item with missing/empty uri parsed without crashing")


def main():
    tests = [
        test_count_matches_items,
        test_source_tool_and_severity,
        test_asset_id_deterministic_from_host,
        test_native_ids_match_fixture,
        test_missing_uri_did_not_crash,
    ]
    print("Running Nikto adapter self-test...\n")
    for t in tests:
        t()
    print("\nALL NIKTO ADAPTER TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
