"""
Vantage deterministic triage package.

The rules-first layer of the two-stage triage pipeline: dedup, severity
normalization, SLA assignment, and OWASP/SANS/CIS mapping — NO LLM. See
``engine.run_triage``.
"""
from __future__ import annotations

from .engine import (
    SLA_DAYS,
    assign_sla,
    dedup_key,
    deduplicate,
    deduplicate_full,
    map_categories,
    run_triage,
    severity_from_cvss,
)

__all__ = [
    "SLA_DAYS",
    "assign_sla",
    "dedup_key",
    "deduplicate",
    "deduplicate_full",
    "map_categories",
    "run_triage",
    "severity_from_cvss",
]
