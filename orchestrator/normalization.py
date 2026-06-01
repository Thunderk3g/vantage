"""
Normalization bridge — raw multi-tool adapter output -> deterministic triage.

This module is the thin, side-effect-free seam between the scanner adapters
(each of which produces ``shared.CanonicalFinding`` objects via ``parse()``)
and the deterministic triage engine (``triage.engine.run_triage``, which works
on plain finding dicts).

Responsibilities (all deterministic, NO LLM):

    1. ``to_dict``            — coerce a CanonicalFinding (dataclass) OR a plain
                                dict into a plain dict the engine can read.
    2. ``merge_tool_findings`` — flatten the per-tool lists produced by the
                                adapters (``{"nessus": [...], "burp": [...]}``)
                                into a single list of dicts, tagging each row
                                with its ``source_tool`` when the adapter did
                                not already set it.
    3. ``normalize_and_triage`` — merge then call the engine, returning the
                                deduped / severity-normalized / SLA-stamped /
                                taxonomy-mapped canonical list.

The triage engine is treated strictly as a library: this module never reaches
into it beyond its public ``run_triage`` entry point, and it never mutates the
caller's input findings (``to_dict`` always returns a fresh dict).
"""
from __future__ import annotations

import dataclasses
import enum

from triage.engine import run_triage


def _coerce_enum(value):
    """Replace any ``enum.Enum`` with its ``.value``; recurse into lists.

    ``dataclasses.asdict`` leaves ``str, Enum`` members (e.g. ``Severity.HIGH``)
    as enum instances, and ``str(member)`` yields ``"Severity.HIGH"`` — which
    the triage engine's band normalizer cannot map, silently collapsing the
    finding to 'info'. Unwrapping the member to its scalar value
    (``Severity.HIGH`` -> ``"High"``, ``AuthContextName.MIN_PRIV`` ->
    ``"min_priv"``) makes the engine receive the value it expects.
    """
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, list):
        return [_coerce_enum(v) for v in value]
    return value


def to_dict(finding) -> dict:
    """Return a plain dict for a finding.

    Accepts either a ``shared.CanonicalFinding`` (any dataclass instance) or a
    plain ``dict``. Dataclasses are converted with ``dataclasses.asdict`` (which
    also unwraps nested dataclasses); dicts are shallow-copied so callers never
    have their input mutated downstream. Any other mapping-like value is coerced
    via ``dict(...)``.

    Enum-valued fields (and enum members inside list-valued fields) are coerced
    to their scalar ``.value`` so the downstream triage engine receives e.g.
    ``"High"`` rather than the ``Severity.HIGH`` enum member. The conversion is
    pure — the input finding is never mutated.
    """
    if dataclasses.is_dataclass(finding) and not isinstance(finding, type):
        d = dataclasses.asdict(finding)
    elif isinstance(finding, dict):
        d = dict(finding)
    else:
        # Last resort: anything dict()-able (e.g. another mapping type).
        d = dict(finding)
    return {k: _coerce_enum(v) for k, v in d.items()}


def merge_tool_findings(raw_by_tool: dict[str, list]) -> list[dict]:
    """Flatten per-tool finding lists into one list of plain dicts.

    ``raw_by_tool`` maps a tool name to that tool's findings, e.g.::

        {"nessus": [<CanonicalFinding>, ...], "burp": [<dict>, ...]}

    Each finding is converted to a plain dict (see ``to_dict``) and tagged with
    its ``source_tool``: the dict's own ``source_tool`` wins when present and
    truthy, otherwise the map key is used. Iteration is in stable dict order so
    the merged list — and therefore the triage output — is deterministic.
    """
    merged: list[dict] = []
    for tool, findings in raw_by_tool.items():
        for finding in findings or []:
            d = to_dict(finding)
            if not d.get("source_tool"):
                d["source_tool"] = tool
            merged.append(d)
    return merged


def normalize_and_triage(raw_by_tool: dict[str, list], today=None) -> list[dict]:
    """Merge per-tool raw findings then run the deterministic triage engine.

    Returns the canonical finding list: cross-tool duplicates collapsed,
    severity bands normalized, SLA days/deadline stamped, and OWASP/SANS/CIS
    taxonomy mapped. Fully deterministic — same input always yields the same
    output. ``today`` (optional) anchors the engine's ``daysLeft`` countdown.
    """
    merged = merge_tool_findings(raw_by_tool)
    return run_triage(merged, today=today)
