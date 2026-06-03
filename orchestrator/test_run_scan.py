"""
Runnable self-test for the Vantage live scan-runner (``run_scan.py``).

Plain asserts + ``[ok]`` prints + a ``__main__`` block — no pytest, and NO real
nmap required: a ``FakeAdapter`` stands in for the engine so the whole scope-gate
-> adapter -> normalize/triage flow is exercised hermetically.

Covers:
  * authorized loopback scan runs end-to-end and triage stamps the register;
  * out-of-scope targets are refused FAIL-CLOSED (PermissionError) and the
    adapter is NEVER touched;
  * is_authorized: loopback + an approved seed host True, public IP False;
  * the CLI returns 0 for an authorized target and 2 (refusal) for an
    out-of-scope one — with the default adapter monkeypatched to the fake.

Run directly:  python orchestrator/test_run_scan.py
"""
from __future__ import annotations

import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import date

# Bootstrap the orchestrator dir onto sys.path so ``import run_scan`` (and the
# shared/adapters it pulls in) resolves regardless of cwd.
_ORCH_DIR = os.path.dirname(os.path.abspath(__file__))
if _ORCH_DIR not in sys.path:
    sys.path.insert(0, _ORCH_DIR)

import run_scan  # noqa: E402
from shared import CanonicalFinding, RawArtifact, Severity  # noqa: E402
from adapters.base import assert_targets_in_scope  # noqa: E402
from adapters import nmap_adapter as _nmap_adapter_mod  # noqa: E402
from api import seed  # noqa: E402

TODAY = date(2026, 6, 2)


class FakeAdapter:
    """Stand-in for NmapAdapter — no real nmap, no subprocess, no network.

    ``preflight`` calls the REAL ``assert_targets_in_scope`` so the scope guard
    is genuinely honored; ``launch/wait/fetch_raw`` are no-ops; ``parse`` returns
    hand-built CanonicalFindings with a CVE + cvss so triage builds a real
    register. Every call is recorded so tests can assert it was (or was NOT) hit.
    """

    name = "nmap"

    def __init__(self):
        self.calls: list[str] = []

    def preflight(self, token):
        self.calls.append("preflight")
        # Prove the scope guard is honored exactly as the real adapter does.
        assert_targets_in_scope(token.target_addrs, token)

    def launch(self, targets, mode="full", **kw):
        self.calls.append("launch")
        self._targets = list(targets)
        self._mode = mode
        return "FAKE-HANDLE"

    def wait(self, handle):
        self.calls.append("wait")

    def fetch_raw(self, handle):
        self.calls.append("fetch_raw")
        return RawArtifact(
            scan_id="LIVE",
            source_tool=self.name,
            uri="memory://fake",
            native_format="nmap-xml",
        )

    def parse(self, raw):
        self.calls.append("parse")
        return [
            CanonicalFinding(
                asset_id="AST-127-0-0-1",
                source_tool=self.name,
                native_id="443/tcp",
                title="Outdated TLS stack with known CVE",
                description="vulnerable openssl",
                cve=["CVE-2025-0001"],
                cvss_base=9.1,
                dedup_key="127.0.0.1|443/tcp|tls",
                detected_at=TODAY.isoformat(),
            ),
            CanonicalFinding(
                asset_id="AST-127-0-0-1",
                source_tool=self.name,
                native_id="22/tcp",
                title="SSH weak ciphers",
                description="weak kex",
                cve=["CVE-2025-0002"],
                cvss_base=6.5,
                dedup_key="127.0.0.1|22/tcp|ssh",
                detected_at=TODAY.isoformat(),
            ),
        ]


def test_authorized_loopback_runs_and_triages():
    adapter = FakeAdapter()
    result = run_scan.run_live_scan("127.0.0.1", adapter=adapter, today=TODAY)

    assert result["tool"] == "nmap", result["tool"]
    assert result["target"] == "127.0.0.1", result["target"]
    assert result["findingCount"] >= 1, result["findingCount"]

    register = result["register"]
    assert register, "expected a non-empty triaged register"
    for f in register:
        # Triage actually ran: bands normalized + SLA + dedup key present.
        assert "severity_normalized" in f, f
        assert "slaDays" in f, f
        assert "dedup_key" in f, f
    # The adapter ran the full sequence in order.
    assert adapter.calls == ["preflight", "launch", "wait", "fetch_raw", "parse"], \
        adapter.calls
    print("  [ok] authorized loopback: end-to-end scan, triage stamped the register")


def test_scope_refusal_fail_closed():
    # A public IP and an internet domain are BOTH out of scope.
    for bad in ("8.8.8.8", "bajajlifeinsurance.com"):
        adapter = FakeAdapter()
        try:
            run_scan.run_live_scan(bad, adapter=adapter, today=TODAY)
        except PermissionError as exc:
            assert "approved scan scope" in str(exc), str(exc)
        else:
            raise AssertionError(f"expected PermissionError for target {bad!r}")
        # Fail-closed: the adapter must NEVER have been touched.
        assert adapter.calls == [], \
            f"adapter was called for out-of-scope {bad!r}: {adapter.calls}"
    print("  [ok] scope refusal: out-of-scope targets fail closed, adapter never called")


def test_is_authorized():
    assert run_scan.is_authorized("127.0.0.1") is True
    assert run_scan.is_authorized("localhost") is True
    # Pick a real approved host from the seed inventory at runtime.
    approved_host = seed.assets()[0]["host"]
    assert run_scan.is_authorized(approved_host) is True, approved_host
    assert run_scan.is_authorized("8.8.8.8") is False
    print(f"  [ok] is_authorized: loopback + approved host ({approved_host}) True, 8.8.8.8 False")


def test_cli_authorized_and_refusal(monkeypatch_default_adapter):
    # CLI on an authorized target -> 0, with the default adapter patched to the
    # fake so no real nmap is needed.
    with monkeypatch_default_adapter(FakeAdapter):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc_ok = run_scan.main(["--target", "127.0.0.1"])
        assert rc_ok == 0, rc_ok
        assert "nmap" in out.getvalue(), out.getvalue()

        # CLI on an out-of-scope target -> 2 (refusal). The default adapter is
        # patched but must never be reached (fail-closed before adapter build).
        out2, err2 = io.StringIO(), io.StringIO()
        with redirect_stdout(out2), redirect_stderr(err2):
            rc_refuse = run_scan.main(["--target", "8.8.8.8"])
        assert rc_refuse == 2, rc_refuse
        assert "REFUSED" in err2.getvalue(), err2.getvalue()
    print("  [ok] CLI: authorized target -> exit 0; out-of-scope target -> exit 2 (refused)")


# ----- tiny local helper: patch the lazily-imported default adapter ----------

import contextlib  # noqa: E402


@contextlib.contextmanager
def _patch_default_adapter(fake_cls):
    """Swap NmapAdapter on the adapters.nmap_adapter module — that's the symbol
    run_live_scan's lazy ``from adapters.nmap_adapter import NmapAdapter`` reads,
    so main() builds the fake instead of the real engine."""
    real = _nmap_adapter_mod.NmapAdapter
    _nmap_adapter_mod.NmapAdapter = fake_cls
    try:
        yield
    finally:
        _nmap_adapter_mod.NmapAdapter = real


def main():
    monkeypatch_default_adapter = _patch_default_adapter
    print("Running Vantage scan-runner self-test...\n")
    test_authorized_loopback_runs_and_triages()
    test_scope_refusal_fail_closed()
    test_is_authorized()
    test_cli_authorized_and_refusal(monkeypatch_default_adapter)
    print("\nALL RUN_SCAN TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
