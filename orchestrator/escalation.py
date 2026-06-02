"""
Deterministic escalation-staircase engine for Vantage.

Pure stdlib, no side effects, no network. This module only ANALYZES findings to
report who an overdue finding should escalate to -- it never exploits or acts on
anything.

The escalation staircase has 5 stages, indexed 0..4. This mirrors
``frontend/data.js`` ``window.ESCALATION`` exactly:

    stage 0: day 0,  label "Owner notified",  role "Asset Owner"
    stage 1: day 2,  label "Reminder",        role "Asset Owner"
    stage 2: day 4,  label "Team Lead",       role "AppSec Lead"
    stage 3: day 9,  label "Sec Manager",     role "Security Manager"
    stage 4: day 18, label "CISO escalation", role "CISO"

Findings arrive as plain dicts from the API (seed.findings() shape). ``escStage``
is ALREADY computed upstream -- we TRUST it and never recompute it.
"""
from __future__ import annotations

# Mirror frontend/data.js window.ESCALATION exactly, with explicit stage index.
LADDER = [
    {"stage": 0, "day": 0,  "label": "Owner notified",  "role": "Asset Owner"},
    {"stage": 1, "day": 2,  "label": "Reminder",        "role": "Asset Owner"},
    {"stage": 2, "day": 4,  "label": "Team Lead",       "role": "AppSec Lead"},
    {"stage": 3, "day": 9,  "label": "Sec Manager",     "role": "Security Manager"},
    {"stage": 4, "day": 18, "label": "CISO escalation", "role": "CISO"},
]

_MAX_STAGE = len(LADDER) - 1  # 4


def _clamp_stage(stage: int) -> int:
    """Clamp an arbitrary stage value into the valid 0..4 ladder range."""
    if stage < 0:
        return 0
    if stage > _MAX_STAGE:
        return _MAX_STAGE
    return stage


def escalation_for(finding: dict) -> dict | None:
    """Per-finding escalation record, or None if the finding is not under active
    SLA (closed, or no deadline).

    The returned record is a fresh dict -- the input finding is never mutated.
    Missing keys are handled defensively via ``.get`` with sane defaults; a
    finding missing ``escStage`` is treated as stage 0.
    """
    if not isinstance(finding, dict):
        return None

    is_closed = bool(finding.get("isClosed", False))
    deadline = finding.get("deadline", None)

    # Not under active SLA: closed, or no deadline.
    if is_closed or deadline is None:
        return None

    esc_stage = finding.get("escStage", 0)
    if not isinstance(esc_stage, int):
        esc_stage = 0
    esc_stage = _clamp_stage(esc_stage)

    next_stage = _clamp_stage(esc_stage + 1)

    days_left = finding.get("daysLeft", None)
    overdue = days_left is not None and days_left < 0

    due_for_escalation = (
        (not is_closed)
        and (deadline is not None)
        and (overdue or esc_stage >= 3)
    )

    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "assetId": finding.get("assetId"),
        "asset": finding.get("asset"),
        "owner": finding.get("owner"),
        "assetOwner": finding.get("assetOwner"),
        "deadline": deadline,
        "daysLeft": days_left,
        "escStage": esc_stage,
        "stageLabel": LADDER[esc_stage]["label"],
        "role": LADDER[esc_stage]["role"],
        "nextRole": LADDER[next_stage]["role"],
        "nextDay": LADDER[next_stage]["day"],
        "overdue": overdue,
        "dueForEscalation": due_for_escalation,
    }


def _sort_key(record: dict):
    """Sort by daysLeft ascending (most overdue first); None sorts last.

    Returns a (is_none, value) tuple so ``None`` always orders after any real
    integer. Ties are stable thanks to Python's stable sort.
    """
    days_left = record.get("daysLeft", None)
    if days_left is None:
        return (1, 0)
    return (0, days_left)


def build_escalations(findings: list[dict], today=None) -> dict:
    """Rollup over all findings.

    ``today`` is accepted for signature symmetry / forward use; the engine reads
    ``daysLeft`` / ``escStage`` off the findings so it stays deterministic.

    Active = not ``isClosed`` AND ``deadline`` is not None.
    """
    if not findings:
        findings = []

    stage_counts = [0, 0, 0, 0, 0]
    records: list[dict] = []

    for finding in findings:
        record = escalation_for(finding)
        if record is None:
            continue
        records.append(record)
        stage_counts[record["escStage"]] += 1

    records.sort(key=_sort_key)

    due = [r for r in records if r["dueForEscalation"]]

    overdue_count = sum(1 for r in records if r["overdue"])

    return {
        "ladder": LADDER,
        "stageCounts": stage_counts,
        "findings": records,
        "due": due,
        "counts": {
            "active": len(records),
            "overdue": overdue_count,
            "due": len(due),
        },
    }
