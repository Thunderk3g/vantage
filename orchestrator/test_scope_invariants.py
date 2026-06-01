"""
Executable encoding of Vantage's HARD security boundary.

Vantage is a scan-and-report vulnerability tool for a regulated insurer. The
non-negotiable product guarantee is:

    The system SCANS and REPORTS ONLY. It detects, triages, and reports
    vulnerabilities. It does NOT exploit, perform lateral / multi-level
    attacks, or auto-fix anything.

This self-test turns that guarantee into CI-enforced invariants so that a
future code change which violates the boundary FAILS CI. Each assertion
message documents WHY the invariant exists — it is the note a future engineer
sees the moment they trip the guard.

Style mirrors orchestrator/triage/test_triage.py: plain asserts, one
``[ok] ...`` line per check, a ``main()`` returning 0/1, and a
``raise SystemExit(main())`` at the bottom. No pytest required:

    python orchestrator/test_scope_invariants.py
    python -m test_scope_invariants            # with orchestrator/ on sys.path

The four invariant groups:
  1. The Phase state machine can never NAME an offensive phase.
  2. No scanner adapter exposes an offensive method (verbs are a tight
     allowlist: preflight / launch / wait / fetch_raw / parse / name).
  3. activities.py defines no offensive activity verb and no offensive phase
     assignment (kept aligned with the CI grep guard in ci.yml).
  4. XXE guard: XML adapters use defusedxml, never the stdlib XML parser.
"""
from __future__ import annotations

import inspect
import os
import re
import sys

# Bootstrap imports so this runs from any cwd. HERE is orchestrator/.
HERE = os.path.dirname(os.path.abspath(__file__))            # orchestrator/
sys.path.insert(0, HERE)

# Tokens that must never appear in a phase name/value, an adapter method name,
# or an activity verb name. Case-insensitive. "weaponi" deliberately catches
# both weaponize and weaponise. These describe OFFENSIVE actions the product
# guarantees it will never take.
FORBIDDEN = (
    "exploit",
    "post_exploit",
    "postexploit",
    "lateral",
    "weaponi",          # weaponize / weaponise
    "remediate",        # auto-fix verb (note: free-text "remediation_note" is
                        # a report FIELD, not a verb — we never scan free text)
    "auto-fix",
    "autofix",
    "bruteforce",
    "brute_force",
    "pwn",
    "payload_delivery",
    "reverse_shell",
    "metasploit",
)

# The COMPLETE permitted verb vocabulary an adapter may expose publicly. Any
# public name outside this set must trip the guard so a human reviews it. This
# is the ScannerAdapter Protocol's verbs (adapters/base.py) plus the `name`
# attribute. Kept intentionally TIGHT.
ALLOWED_ADAPTER_VERBS = {"preflight", "launch", "wait", "fetch_raw", "parse", "name"}

# The four concrete adapter source files (for text-level inspection).
ADAPTER_FILES = {
    "nmap": os.path.join(HERE, "adapters", "nmap_adapter.py"),
    "nessus": os.path.join(HERE, "adapters", "nessus_adapter.py"),
    "burp": os.path.join(HERE, "adapters", "burp_adapter.py"),
    "nikto": os.path.join(HERE, "adapters", "nikto_adapter.py"),
}
# Adapters whose native format is XML and which therefore MUST use defusedxml.
XML_ADAPTERS = ("nmap", "nessus", "nikto")

ACTIVITIES_FILE = os.path.join(HERE, "activities.py")


def _forbidden_hits(text: str) -> list[str]:
    """Return the FORBIDDEN tokens present in ``text`` (lower-cased compare)."""
    low = text.lower()
    return [tok for tok in FORBIDDEN if tok.lower() in low]


# =====================================================================
# 1. The Phase state machine can never NAME an offensive phase.
# =====================================================================
def test_phase_enum_has_no_offensive_phase():
    from shared import Phase

    for member in Phase:
        for surface in (member.name, str(member.value)):
            hits = _forbidden_hits(surface)
            assert not hits, (
                f"Phase.{member.name} (={member.value!r}) names an offensive "
                f"concept {hits!r}. The Phase enum must NEVER name an "
                f"exploitation / lateral-movement / remediation phase — the "
                f"state machine cannot advance into a state that does not "
                f"exist by construction. Scan-and-report boundary."
            )

    names = {m.name for m in Phase}
    # The safe terminal phases must exist: we report and we are DONE — we never
    # advance past reporting into action-on-target.
    assert "REPORT" in names, (
        "Phase.REPORT must exist — REPORT is the safe terminal product phase "
        "(scan-and-report boundary)."
    )
    assert "DONE" in names, (
        "Phase.DONE must exist — DONE is the safe terminal phase after "
        "reporting (scan-and-report boundary)."
    )
    # SCOPE must be the FIRST phase: every run begins at authorization, never
    # at a scanning/offensive step.
    first = list(Phase)[0]
    assert first.name == "SCOPE", (
        f"Phase.SCOPE must be the FIRST phase (got {first.name}). The pipeline "
        f"must always begin at the authorization/scope gate before any host is "
        f"touched — scan-and-report boundary."
    )
    print("  [ok] Phase enum names no offensive phase; SCOPE first, REPORT+DONE terminal")


# =====================================================================
# 2. No scanner adapter exposes an offensive method.
# =====================================================================
def test_adapters_expose_no_offensive_method():
    from adapters.nmap_adapter import NmapAdapter
    from adapters.nessus_adapter import NessusAdapter
    from adapters.burp_adapter import BurpAdapter
    from adapters.nikto_adapter import NiktoAdapter

    for cls in (NmapAdapter, NessusAdapter, BurpAdapter, NiktoAdapter):
        # Public surface = names not starting with '_'.
        public = [n for n in dir(cls) if not n.startswith("_")]

        for name in public:
            hits = _forbidden_hits(name)
            assert not hits, (
                f"{cls.__name__}.{name} is an offensive verb {hits!r}. Adapters "
                f"may only DISCOVER / ENUMERATE / DETECT / FETCH / PARSE — never "
                f"exploit, brute-force, weaponize, or remediate. Scan-and-report "
                f"boundary."
            )

        # The public surface must be a SUBSET of the tight allowed vocabulary.
        # A new public method outside the allowlist fails so a human reviews it.
        extra = set(public) - ALLOWED_ADAPTER_VERBS
        assert not extra, (
            f"{cls.__name__} exposes public name(s) {sorted(extra)!r} outside the "
            f"permitted adapter verb vocabulary {sorted(ALLOWED_ADAPTER_VERBS)!r}. "
            f"Adapters must expose ONLY scan/report verbs; any new public method "
            f"requires human review against the scan-and-report boundary."
        )

        # And it must actually expose the real callable verbs (not be empty),
        # so the guard can never be defeated by hiding everything behind _ .
        callables = [n for n in public if callable(getattr(cls, n, None))]
        assert "preflight" in callables and "parse" in callables, (
            f"{cls.__name__} must implement the safe ScannerAdapter verbs "
            f"(preflight + parse seen as the contract anchor) — scan-and-report "
            f"boundary."
        )
    print("  [ok] adapters expose only {preflight,launch,wait,fetch_raw,parse,name}; no offensive verb")


# =====================================================================
# 3. activities.py defines no offensive verb and no offensive phase.
#    Inspected by READING the file text (temporalio may be absent in CI).
# =====================================================================
# The exact regex used by the CI "Guard — no exploitation phase" step in
# .github/workflows/ci.yml. Kept byte-for-byte aligned so the two guards
# reinforce each other.
CI_PHASE_GUARD_RE = re.compile(
    r"""phase\s*=\s*['"]?(exploit|post_exploit|lateral|remediate)""",
    re.IGNORECASE,
)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def test_activities_define_no_offensive_verb_or_phase():
    src = _read(ACTIVITIES_FILE)

    # (a) No FORBIDDEN token in any @activity.defn-decorated function NAME.
    # Walk the lines; when we see an @activity.defn decorator, the next
    # `def <name>` (possibly `async def`) is the activity verb we must vet.
    lines = src.splitlines()
    activity_defn_names: list[str] = []
    pending = False
    def_re = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)")
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("@activity.defn"):
            pending = True
            continue
        if pending:
            m = def_re.match(line)
            if m:
                activity_defn_names.append(m.group(1))
                pending = False
            # other decorators between @activity.defn and def: keep waiting
            elif stripped.startswith("@"):
                continue
            elif stripped:
                # a non-decorator, non-def line broke the pairing; reset
                pending = False

    assert activity_defn_names, (
        "Parsed zero @activity.defn function names from activities.py — the "
        "parser or the file changed shape; the offensive-verb guard would be "
        "silently disabled. Investigate before trusting CI."
    )
    for fname in activity_defn_names:
        hits = _forbidden_hits(fname)
        assert not hits, (
            f"@activity.defn '{fname}' is an offensive verb {hits!r}. Activities "
            f"may only authorize / discover / enumerate / detect / normalize / "
            f"triage / report — never exploit, move laterally, weaponize, or "
            f"auto-remediate. Scan-and-report boundary."
        )

    # (b) The CI phase-assignment regex must find NO match. This is the same
    #     guard CI runs; we assert it here so the boundary is enforced even if
    #     someone edits the workflow.
    m = CI_PHASE_GUARD_RE.search(src)
    assert m is None, (
        f"activities.py assigns an offensive phase value: {m.group(0)!r}. "
        f"No phase = 'exploit'|'post_exploit'|'lateral'|'remediate' assignment "
        f"is permitted (this mirrors the CI 'no exploitation phase' grep "
        f"guard). Scan-and-report boundary."
    )

    # NOTE: we deliberately do NOT scan free-text docstrings/comments for the
    # FORBIDDEN tokens — the file legitimately says things like "Nothing here
    # exploits a target" and "stopped before exploitation". Only IDENTIFIERS
    # (activity verb names) and PHASE-ASSIGNMENT data are inspected, so prose
    # never produces a false positive.

    print("  [ok] activities.py: no offensive @activity.defn verb, no offensive phase assignment (CI-aligned)")


# =====================================================================
# 4. XXE guard: adapters use defusedxml, never the stdlib XML parser.
# =====================================================================
def test_adapters_use_defusedxml_not_stdlib_xml():
    for tool, path in ADAPTER_FILES.items():
        src = _read(path)
        assert "import xml.etree" not in src, (
            f"{tool}_adapter.py uses 'import xml.etree' — the stdlib XML parser "
            f"is vulnerable to XXE / entity expansion against semi-trusted "
            f"scanner output. Adapters MUST parse with defusedxml. (XXE guard)"
        )
        assert "from xml.etree" not in src, (
            f"{tool}_adapter.py uses 'from xml.etree' — the stdlib XML parser "
            f"is vulnerable to XXE / entity expansion against semi-trusted "
            f"scanner output. Adapters MUST parse with defusedxml. (XXE guard)"
        )

    for tool in XML_ADAPTERS:
        src = _read(ADAPTER_FILES[tool])
        assert "defusedxml" in src, (
            f"{tool}_adapter.py parses XML but does not reference 'defusedxml'. "
            f"XML scanner output is semi-trusted (embeds attacker-controlled "
            f"banners/headers); it MUST be parsed with defusedxml to block XXE / "
            f"billion-laughs. (XXE guard)"
        )

    print("  [ok] XML adapters (nmap/nessus/nikto) use defusedxml; no stdlib xml.etree anywhere")


def main():
    tests = [
        test_phase_enum_has_no_offensive_phase,
        test_adapters_expose_no_offensive_method,
        test_activities_define_no_offensive_verb_or_phase,
        test_adapters_use_defusedxml_not_stdlib_xml,
    ]
    print("Running Vantage scope-invariant self-test (scan-and-report boundary)...\n")
    try:
        for t in tests:
            t()
    except AssertionError as e:
        print("\nSCOPE INVARIANT VIOLATED:\n" + str(e))
        return 1
    print("\nALL SCOPE INVARIANTS HOLD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
