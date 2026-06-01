"""
Runnable self-test for the normalization bridge (no pytest).

Feeds SAMPLE raw multi-tool findings through ``normalization.normalize_and_triage``
and asserts the deterministic triage contract:

  * a cross-tool duplicate (Nessus SQLi + Burp SQLi on the same asset/location)
    collapses to a single canonical finding;
  * severity bands are derived correctly from CVSS;
  * SLA windows are correct (critical/high = 30 days, medium/low = 60 days);
  * framework taxonomy is mapped (at least one OWASP/SANS/CIS code present).

Run directly:  python test_normalization.py
"""
from __future__ import annotations

from datetime import date

from shared import CanonicalFinding
import normalization


# Fixed anchor date so daysLeft / deadline are deterministic.
TODAY = date(2026, 6, 1)


def _by_title(findings, needle):
    needle = needle.lower()
    hits = [f for f in findings if needle in (f.get("title") or "").lower()]
    assert hits, f"expected a finding with title containing {needle!r}"
    return hits[0]


def build_sample() -> dict[str, list]:
    """SAMPLE raw multi-tool findings, as adapters' parse() would emit them.

    Nessus and Burp both report SQL injection on the SAME asset + location;
    those must dedup to one. ZAP reports a distinct XSS, and Nessus reports a
    distinct TLS issue, with varied CVSS so severity bands differ.
    """
    nessus = [
        # SQLi seen by Nessus (dataclass form, critical CVSS) — same asset/loc
        # as the Burp SQLi below; these two must collapse to one canonical row.
        CanonicalFinding(
            asset_id="asset-001",
            source_tool="nessus",
            native_id="98765",
            title="SQL injection in policy search parameter",
            description="Error-based SQLi in /search?policy=",
            cvss_base=9.1,                      # -> critical
            detected_at="2026-05-20",
        ),
        # Distinct TLS finding (medium) — exercises medium band + 60-day SLA
        # and a native-id taxonomy hit (Nessus plugin 104743 -> CIS-3.10).
        CanonicalFinding(
            asset_id="asset-002",
            source_tool="nessus",
            native_id="104743",
            title="TLS 1.0 / 1.1 protocol detection",
            description="Legacy TLS enabled",
            cvss_base=5.3,                      # -> medium
            detected_at="2026-05-20",
        ),
    ]

    burp = [
        # SQLi seen by Burp — SAME asset + location, plain-dict form, slightly
        # lower CVSS. Same title => same signature => dedups with the Nessus row.
        {
            "asset_id": "asset-001",
            "native_id": "1049088",
            "title": "SQL injection in policy search parameter",
            "description": "Confirmed via boolean payload",
            "cvss_base": 8.6,                   # -> high (still dedups under crit)
            "detected_at": "2026-05-20",
            # source_tool intentionally omitted -> tagged from map key "burp".
        },
    ]

    zap = [
        # Distinct reflected XSS (high) — exercises high band + 30-day SLA and a
        # tag-map taxonomy hit (zap family "Cross Site Scripting" -> A03/CWE-79).
        {
            "asset_id": "asset-003",
            "source_tool": "zap",
            "native_id": None,
            "title": "Reflected Cross Site Scripting",
            "issue_type": "Cross Site Scripting",
            "cvss_base": 7.4,                   # -> high
            "detected_at": "2026-05-20",
        },
    ]

    return {"nessus": nessus, "burp": burp, "zap": zap}


def main() -> None:
    raw_by_tool = build_sample()
    findings = normalization.normalize_and_triage(raw_by_tool, today=TODAY)

    # ---- determinism / shape ------------------------------------------------
    # 4 raw rows in (2 nessus + 1 burp + 1 zap); the SQLi pair dedups -> 3.
    assert len(findings) == 3, f"expected 3 canonical findings, got {len(findings)}"

    # ---- cross-tool duplicate collapsed to one ------------------------------
    sqli = _by_title(findings, "sql injection")
    sqli_rows = [f for f in findings if "sql injection" in (f.get("title") or "").lower()]
    assert len(sqli_rows) == 1, "cross-tool SQLi did not collapse to a single row"
    assert sqli.get("duplicates") == 1, \
        f"expected duplicates=1 on canonical SQLi, got {sqli.get('duplicates')}"
    assert sqli.get("dup_of") is None, "canonical SQLi must not be a duplicate"
    assert set(sqli.get("merged_from") or []) == {"nessus", "burp"}, \
        f"expected merged_from nessus+burp, got {sqli.get('merged_from')}"

    # ---- severity bands correct (from CVSS) ---------------------------------
    assert sqli["severity_normalized"] == "critical", \
        f"SQLi (cvss 9.1) should be critical, got {sqli['severity_normalized']}"
    tls = _by_title(findings, "tls 1.0")
    assert tls["severity_normalized"] == "medium", \
        f"TLS (cvss 5.3) should be medium, got {tls['severity_normalized']}"
    xss = _by_title(findings, "cross site scripting")
    assert xss["severity_normalized"] == "high", \
        f"XSS (cvss 7.4) should be high, got {xss['severity_normalized']}"

    # ---- SLA days correct (crit/high = 30, med/low = 60) --------------------
    assert sqli["slaDays"] == 30, f"critical SLA should be 30, got {sqli['slaDays']}"
    assert xss["slaDays"] == 30, f"high SLA should be 30, got {xss['slaDays']}"
    assert tls["slaDays"] == 60, f"medium SLA should be 60, got {tls['slaDays']}"

    # deadline = detected_at (2026-05-20) + slaDays
    assert sqli["deadline"] == "2026-06-19", f"crit deadline wrong: {sqli['deadline']}"
    assert tls["deadline"] == "2026-07-19", f"med deadline wrong: {tls['deadline']}"

    # ---- a category mapping present -----------------------------------------
    # SQLi -> Injection (A03:2021) + CWE-89, via native id and/or keyword.
    assert "A03:2021" in sqli["owasp_web"], \
        f"SQLi should map to OWASP A03:2021, got {sqli['owasp_web']}"
    assert "CWE-89" in sqli["sans25"], \
        f"SQLi should map to CWE-89, got {sqli['sans25']}"
    # TLS -> Cryptographic Failures (A02:2021) + CIS-3.10 via Nessus native id.
    assert "A02:2021" in tls["owasp_web"], \
        f"TLS should map to OWASP A02:2021, got {tls['owasp_web']}"
    assert tls["cis_control"] == "CIS-3.10", \
        f"TLS should map to CIS-3.10, got {tls['cis_control']}"
    # XSS -> Injection (A03:2021) + CWE-79 via zap tag map.
    assert "A03:2021" in xss["owasp_web"], \
        f"XSS should map to OWASP A03:2021, got {xss['owasp_web']}"
    assert "CWE-79" in xss["sans25"], \
        f"XSS should map to CWE-79, got {xss['sans25']}"

    print("ALL NORMALIZATION TESTS PASSED")


if __name__ == "__main__":
    main()
