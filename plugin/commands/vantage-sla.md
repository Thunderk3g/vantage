---
description: SLA and escalation status for overdue Vantage findings
argument-hint:
---

Report SLA and escalation status. This is read-only: surface what is overdue and
what is due for escalation, but run NOTHING automatically -- the escalation sweep
is admin-gated on the server.

Plan:
1. Call `mcp__vantage__escalations` for the SLA staircase rollup
   (Day 0->2->4->9->18): which findings are overdue, who each is currently with,
   and which are due for the next escalation step.
2. Call `mcp__vantage__list_findings` with `sla="overdue"` for the full overdue
   register (id, title, severity, asset, current status).
3. Present:
   - An "Overdue" list, worst-first, with the current owner/holder per finding.
   - A "Due for escalation" list (those at or past the next staircase threshold).
4. Note that the actual escalation sweep is admin-gated and is NOT triggered by
   this command. If action is wanted, point the human to the appropriate role and
   tool (e.g. a status move via `mcp__vantage__set_finding_status` or an exception
   via `mcp__vantage__request_exception`) -- recommend only; do not call them.
