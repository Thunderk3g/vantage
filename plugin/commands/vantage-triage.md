---
description: Triage open Vantage findings by severity and recommend next actions
argument-hint: [severity|assetId]
---

Triage the current open findings in Vantage. This is a READ + RECOMMEND task:
you summarize posture and propose next actions, but you do NOT apply any change.
Status moves, exceptions, and false-positive calls are human-gated and role-gated
on the server; only recommend them and tell the human which gated tool applies.

If `$ARGUMENTS` is given, treat it as a filter: a severity (critical|high|medium|
low|info) narrows by severity, an `AST-...` id narrows by asset.

Plan:
1. Call `mcp__vantage__dashboard` for the posture snapshot (open-by-severity,
   overdue / due-soon / running counts, trend).
2. Call `mcp__vantage__list_findings` with `status="open,triaged"` and apply any
   `$ARGUMENTS` filter (`severity=...` or `asset_id=...`). Order/sort your
   summary worst-first (critical -> high -> ...).
3. For overdue items, cross-reference SLA: also call `mcp__vantage__list_findings`
   with `sla="overdue"` (plus the same filter) and flag those findings.
4. Present: the worst findings up top, then a count grouped by severity, then a
   clearly-labelled "Overdue" list.
5. Propose next actions per finding as RECOMMENDATIONS only -- e.g. "move to
   in_progress" (-> `mcp__vantage__set_finding_status`), "request a time-boxed
   exception" (-> `mcp__vantage__request_exception`), or "confirm false positive"
   (-> `mcp__vantage__confirm_false_positive`). State plainly that these require a
   human with the right role; do not call them yourself.
