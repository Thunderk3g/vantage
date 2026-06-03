"""
Reference end-to-end pipeline for Vantage — fixtures -> adapters -> triage.

This is the pure, import-safe glue that runs the *reference* scan-and-report
pipeline over the committed sample fixtures. It NEVER launches a scanner, never
touches the network, and never exploits anything: it only replays already
captured scanner output (the committed fixtures) through each adapter's
``parse()`` and then through the deterministic triage bridge
(``normalization.normalize_and_triage``).

There is deliberately NO ``temporalio`` import here — importing this module is
cheap and side-effect free, so both the standalone e2e test and the Temporal
activity (which imports it lazily) can rely on it.

Flow::

    committed fixtures
        -> RawArtifact (uri = local fixture path)
        -> <Tool>Adapter().parse(raw)          # CanonicalFinding list per tool
        -> normalization.normalize_and_triage  # merge -> dedup -> SLA -> taxonomy
        -> triaged canonical register (list[dict])

Real scans persist their raw adapter artifacts to the object store and load
them keyed by source_tool; that persistence slice is future work. Until then
the fixtures are the reference/demo source.
"""
from __future__ import annotations

import os
import sys
from datetime import date

# Bootstrap the orchestrator dir onto sys.path so the adapter modules — which
# import ``from shared import ...`` and ``from .base import ...`` — resolve
# regardless of the caller's cwd. (The adapters must be imported via the
# ``adapters`` package so their relative imports work.)
_ORCH_DIR = os.path.dirname(os.path.abspath(__file__))
if _ORCH_DIR not in sys.path:
    sys.path.insert(0, _ORCH_DIR)

import normalization  # noqa: E402
from shared import RawArtifact  # noqa: E402
from adapters.nmap_adapter import NmapAdapter  # noqa: E402
from adapters.nessus_adapter import NessusAdapter  # noqa: E402
from adapters.burp_adapter import BurpAdapter  # noqa: E402
from adapters.nikto_adapter import NiktoAdapter  # noqa: E402
from adapters.zap_adapter import ZapAdapter  # noqa: E402
from adapters.nuclei_adapter import NucleiAdapter  # noqa: E402
from adapters.trivy_adapter import TrivyAdapter  # noqa: E402

_FIXTURE_DIR = os.path.join(_ORCH_DIR, "adapters", "fixtures")

# (adapter instance, fixture filename, native_format). The tool key matches each
# adapter's ``.name`` so ``raw_by_tool`` is keyed consistently.
#
# Two interchangeable engine sets (the OSS variant is a config swap, not a code
# change — both feed the SAME normalize->triage path):
#   * LICENSED: Nessus Pro / Burp Pro / Nmap / Nikto
#   * OSS:      ZAP / Nuclei / Trivy (license-free, at parity)
_REFERENCE_SOURCES = (
    (NmapAdapter(), "nmap_sample.xml", "nmap-xml"),
    (NessusAdapter(policy="VA"), "nessus_sample.nessus", "nessus-xml"),
    (BurpAdapter(mode="scan"), "burp_sample.json", "burp-json"),
    (NiktoAdapter(), "nikto_sample.xml", "nikto-xml"),
)

_OSS_SOURCES = (
    (ZapAdapter(), "zap_sample.json", "zap-json"),
    (NucleiAdapter(), "nuclei_sample.jsonl", "nuclei-jsonl"),
    (TrivyAdapter(), "trivy_sample.json", "trivy-json"),
)


def _fixture_path(name: str) -> str:
    """Absolute path to a committed fixture, resolved relative to THIS file."""
    return os.path.join(_FIXTURE_DIR, name)


def _load_sources(sources) -> dict[str, list]:
    """Run each (adapter, fixture, format) source's parse() over its committed
    fixture → {tool_name: [CanonicalFinding, ...]}. Reference/demo source —
    real scans persist raw artifacts (future slice)."""
    raw_by_tool: dict[str, list] = {}
    for adapter, fixture_name, native_format in sources:
        raw = RawArtifact(
            scan_id="DEMO",
            source_tool=adapter.name,
            uri=_fixture_path(fixture_name),
            native_format=native_format,
        )
        raw_by_tool[adapter.name] = adapter.parse(raw)
    return raw_by_tool


def load_fixture_findings() -> dict[str, list]:
    """Licensed engine set (nmap, nessus, burp, nikto) parsed from fixtures."""
    return _load_sources(_REFERENCE_SOURCES)


def load_oss_fixture_findings() -> dict[str, list]:
    """OSS engine set (zap, nuclei, trivy) parsed from fixtures — the
    license-free variant, feeding the same normalize->triage path at parity."""
    return _load_sources(_OSS_SOURCES)


def _stamp_detected_at(raw_by_tool: dict[str, list], when: str) -> dict[str, list]:
    """Plain-dict copy of each finding with ``detected_at`` defaulted.

    The committed fixtures carry no detection timestamp (the adapters default
    ``detected_at`` to ""), so the triage engine cannot derive an SLA deadline
    from them. A real scan records when each issue was first detected; for the
    reference/demo run we anchor any timestamp-less finding to the scan date so
    deadlines compute. Findings that already carry a ``detected_at`` keep it.
    Conversion is via ``normalization.to_dict`` (which also unwraps the enum
    severity), and the input findings are never mutated.
    """
    stamped: dict[str, list] = {}
    for tool, findings in raw_by_tool.items():
        rows = []
        for finding in findings or []:
            d = normalization.to_dict(finding)
            if not d.get("detected_at"):
                d["detected_at"] = when
            rows.append(d)
        stamped[tool] = rows
    return stamped


def _run(raw_by_tool: dict[str, list], today=None) -> list[dict]:
    # Anchor detection to the scan date so the demo findings get SLA deadlines.
    when = (today or date.today()).isoformat()
    raw_by_tool = _stamp_detected_at(raw_by_tool, when)
    return normalization.normalize_and_triage(raw_by_tool, today=today)


def run_reference_pipeline(today=None) -> list[dict]:
    """Licensed fixtures -> adapters.parse() -> normalize -> triage register."""
    return _run(load_fixture_findings(), today=today)


def run_oss_pipeline(today=None) -> list[dict]:
    """OSS (zap/nuclei/trivy) fixtures through the SAME normalize->triage path —
    demonstrates the license-free variant at parity with the licensed set."""
    return _run(load_oss_fixture_findings(), today=today)


if __name__ == "__main__":  # pragma: no cover - manual smoke run
    register = run_reference_pipeline()
    print(f"reference pipeline produced {len(register)} canonical findings")
