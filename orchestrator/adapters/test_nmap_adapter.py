"""
Runnable self-test for the Nmap adapter's parse() path.

Plain asserts + a __main__ block — no pytest required. Run either of:

    python orchestrator/adapters/test_nmap_adapter.py
    python -m adapters.test_nmap_adapter      # with orchestrator/ on sys.path

Covers:
  * only OPEN ports become findings (closed/filtered are skipped),
  * source_tool is 'nmap' and every severity is Info (inventory facts),
  * asset_id is stable/deterministic for a given address,
  * dedup_key is populated,
  * a service element with no product/version does not crash parsing.
"""
from __future__ import annotations

import os
import sys

# Make the adapter + shared types importable whether run as a script or module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters.nmap_adapter import NmapAdapter, _asset_id_for  # noqa: E402
from shared import RawArtifact, Severity  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "nmap_sample.xml")


def _parse():
    raw = RawArtifact(
        scan_id="S1",
        source_tool="nmap",
        uri=os.path.abspath(FIXTURE),
        native_format="nmap-xml",
    )
    return NmapAdapter().parse(raw)


def test_only_open_ports():
    findings = _parse()
    # Fixture has 5 ports on one host: 22/443/8080 open, 23 closed, 3389 filtered.
    assert len(findings) == 3, f"expected 3 open-service findings, got {len(findings)}"
    ports = sorted(f.native_id for f in findings)
    assert ports == ["22/tcp", "443/tcp", "8080/tcp"], ports
    print("  [ok] only OPEN ports -> findings (closed/filtered skipped)")


def test_source_and_severity():
    findings = _parse()
    assert findings, "no findings parsed"
    for f in findings:
        assert f.source_tool == "nmap", f.source_tool
        assert f.severity_normalized is Severity.INFO, f.severity_normalized
    print("  [ok] source_tool == 'nmap' and every severity is Info")


def test_asset_id_deterministic():
    findings = _parse()
    asset_ids = {f.asset_id for f in findings}
    # All ports belong to one host (10.0.0.5) -> one stable asset id.
    assert asset_ids == {"AST-10-0-0-5"}, asset_ids
    # The id function is pure/deterministic and dots/colons are normalized.
    assert _asset_id_for("10.0.0.5") == _asset_id_for("10.0.0.5") == "AST-10-0-0-5"
    assert _asset_id_for("") == "AST-unknown"
    assert _asset_id_for("fe80::1") == "AST-fe80--1"
    print("  [ok] asset_id is stable/deterministic (AST-10-0-0-5)")


def test_dedup_key_populated():
    findings = _parse()
    for f in findings:
        assert f.dedup_key, f"empty dedup_key on {f.native_id}"
        assert "10.0.0.5" in f.dedup_key, f.dedup_key
    # Distinct ports -> distinct dedup keys.
    keys = [f.dedup_key for f in findings]
    assert len(set(keys)) == len(keys), keys
    print("  [ok] dedup_key populated and distinct per port")


def test_productless_service_ok():
    findings = _parse()
    proxy = next(f for f in findings if f.native_id == "8080/tcp")
    # No product/version in the fixture -> description is None, title still set.
    assert proxy.description is None, proxy.description
    assert "http-proxy" in proxy.title and "8080" in proxy.title, proxy.title
    # And a richly-described service carries its banner.
    ssh = next(f for f in findings if f.native_id == "22/tcp")
    assert ssh.description and "OpenSSH" in ssh.description, ssh.description
    print("  [ok] product-less service parses (description None, no crash)")


def main():
    tests = [
        test_only_open_ports,
        test_source_and_severity,
        test_asset_id_deterministic,
        test_dedup_key_populated,
        test_productless_service_ok,
    ]
    print("Running Nmap adapter parse() self-test...\n")
    for t in tests:
        t()
    print("\nALL NMAP ADAPTER TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
