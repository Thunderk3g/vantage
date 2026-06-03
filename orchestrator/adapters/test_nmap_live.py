"""
Runnable self-test for the Nmap adapter's LIVE engine path
(launch / wait / fetch_raw) — and that it stays SAFE by construction.

Plain asserts + a __main__ block — no pytest required, and it passes
WITHOUT nmap installed (subprocess.Popen is mocked for the end-to-end case).
Run either of:

    python orchestrator/adapters/test_nmap_live.py
    python -m adapters.test_nmap_live      # with orchestrator/ on sys.path

Covers:
  * safe-NSE guard: discovery/version pass, exploit/intrusive -> PermissionError,
  * argument-injection guard: '-...' / empty targets rejected BEFORE any subprocess,
  * no-nmap path: missing binary -> clear RuntimeError,
  * mocked end-to-end: launch->wait->fetch_raw->parse yields >=1 Info finding,
  * optional REAL smoke against loopback, cleanly skipped when nmap is absent.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

# Make the adapter + shared types importable whether run as a script or module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from adapters import nmap_adapter  # noqa: E402
from adapters.nmap_adapter import NmapAdapter  # noqa: E402
from shared import Severity  # noqa: E402


# A minimal but valid nmap -oX document: one host, one open port 22/tcp ssh.
_FAKE_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="0" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


def test_safe_nse_guard():
    a = NmapAdapter()
    # Safe categories pass silently.
    a._assert_safe_scripts("default,discovery")
    a._assert_safe_scripts("discovery")
    a._assert_safe_scripts("default,discovery,version,safe")
    # Offensive categories are rejected — proves no exploit/intrusive NSE.
    for bad in ("exploit", "intrusive", "default,brute"):
        try:
            a._assert_safe_scripts(bad)
        except PermissionError:
            pass
        else:
            raise AssertionError(f"expected PermissionError for scripts={bad!r}")
    print("  [ok] safe-NSE guard: discovery/version pass, exploit/intrusive rejected")


def test_arg_injection_guard(monkeypatch_which):
    a = NmapAdapter()
    # Pretend nmap IS present so we prove TARGET validation fires, not the
    # binary-missing path. A '-...' or empty target must raise BEFORE Popen.
    with monkeypatch_which("/usr/bin/nmap"), _no_subprocess() as started:
        for bad in (["-oG", "x"], [""], ["127.0.0.1", "-sS"], []):
            try:
                a.launch(bad)
            except (ValueError, TypeError):
                pass
            else:
                raise AssertionError(f"expected rejection for targets={bad!r}")
        assert not started, "subprocess must NOT start for rejected targets"
    print("  [ok] arg-injection guard: '-...'/empty targets rejected before any subprocess")


def test_no_nmap_path(monkeypatch_which):
    a = NmapAdapter()
    with monkeypatch_which(None):
        try:
            a.launch(["127.0.0.1"])
        except RuntimeError as e:
            assert "nmap" in str(e).lower() and "not found" in str(e).lower(), str(e)
        else:
            raise AssertionError("expected RuntimeError when nmap binary is absent")
    print("  [ok] no-nmap path: missing binary -> clear RuntimeError")


def test_mocked_end_to_end(monkeypatch_which):
    a = NmapAdapter()

    class _FakeProc:
        """Stands in for subprocess.Popen — writes the -oX file, exits 0."""
        def __init__(self, argv, **kw):
            # No shell: argv must be a list and never contain a shell string.
            assert isinstance(argv, list), "Popen must receive an argv LIST"
            assert "shell" not in kw or kw["shell"] is False, "no shell=True allowed"
            # Engine is unprivileged connect scan, never -sS/-O/--privileged.
            assert "-sT" in argv and "-sV" in argv, argv
            for forbidden in ("-sS", "-O", "--privileged"):
                assert forbidden not in argv, f"forbidden flag {forbidden} in argv"
            out_path = argv[argv.index("-oX") + 1]
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(_FAKE_XML)
            self.returncode = 0

        def communicate(self, timeout=None):
            return ("", "")

    real_popen = subprocess.Popen
    nmap_adapter.subprocess.Popen = _FakeProc
    try:
        with monkeypatch_which("/usr/bin/nmap"):
            h = a.launch(["127.0.0.1"], scan_id="UNIT")
            a.wait(h)
            raw = a.fetch_raw(h)
            assert raw.source_tool == "nmap", raw.source_tool
            assert raw.native_format == "nmap-xml", raw.native_format
            assert raw.scan_id == "UNIT", raw.scan_id
            findings = a.parse(raw)
    finally:
        nmap_adapter.subprocess.Popen = real_popen
        # Clean up the temp -oX file we created.
        try:
            os.unlink(raw.uri)  # type: ignore[name-defined]
        except Exception:
            pass

    assert len(findings) >= 1, f"expected >=1 finding, got {len(findings)}"
    f0 = findings[0]
    assert f0.source_tool == "nmap", f0.source_tool
    assert f0.severity_normalized is Severity.INFO, f0.severity_normalized
    assert f0.native_id == "22/tcp", f0.native_id
    print("  [ok] mocked end-to-end: launch->wait->fetch_raw->parse -> Info finding")


def test_real_smoke_optional():
    if not shutil.which("nmap"):
        print("  [skip] real nmap smoke: nmap not on PATH")
        return
    a = NmapAdapter()
    h = a.launch(["127.0.0.1"], scan_id="SMOKE")
    a.wait(h)
    raw = a.fetch_raw(h)
    try:
        findings = a.parse(raw)
        assert isinstance(findings, list)
        print(f"  [ok] real nmap smoke vs loopback: parsed {len(findings)} finding(s)")
    finally:
        try:
            os.unlink(raw.uri)
        except Exception:
            pass


# ----- tiny local helpers (no pytest / monkeypatch dependency) ---------------

import contextlib  # noqa: E402


def _make_which_patcher():
    """Returns a context-manager factory that swaps shutil.which used by the
    adapter. The adapter imported `shutil`, so we patch `shutil.which`."""
    @contextlib.contextmanager
    def patch(return_value):
        real = shutil.which
        shutil.which = lambda name: return_value
        try:
            yield
        finally:
            shutil.which = real
    return patch


@contextlib.contextmanager
def _no_subprocess():
    """Guard: fail loudly if Popen is invoked. Yields a list that stays empty
    unless a subprocess was (wrongly) started."""
    started: list = []
    real = nmap_adapter.subprocess.Popen

    def _boom(*a, **k):
        started.append(True)
        raise AssertionError("subprocess.Popen must not be called here")

    nmap_adapter.subprocess.Popen = _boom
    try:
        yield started
    finally:
        nmap_adapter.subprocess.Popen = real


def main():
    monkeypatch_which = _make_which_patcher()
    print("Running Nmap adapter LIVE-engine self-test...\n")
    test_safe_nse_guard()
    test_arg_injection_guard(monkeypatch_which)
    test_no_nmap_path(monkeypatch_which)
    test_mocked_end_to_end(monkeypatch_which)
    test_real_smoke_optional()
    print("\nALL NMAP LIVE TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
