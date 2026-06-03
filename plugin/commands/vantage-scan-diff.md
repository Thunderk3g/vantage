---
description: Diff the last two scans and verify closure
argument-hint:
---

Diff the last two scan registers and verify closure. This is read-only triage:
report what changed and offer a retest where appropriate -- you do not close
anything yourself.

Plan:
1. Call `mcp__vantage__scan_diff` (previous scan vs latest).
2. Report four buckets with counts:
   - Resolved (closure-verified: the latest scan no longer reports it).
   - New (appears only in the latest scan).
   - Persisting (present in both).
   - Regressed (was resolved earlier but is back) -- HIGHLIGHT these.
3. Lead with regressions, then new, then persisting; summarize resolved as
   confirmed closures.
4. For findings believed fixed but still showing (or to re-verify a fix), offer
   to request a retest via `mcp__vantage__request_retest` (status -> retest;
   closure is then re-confirmed by a future scan_diff). This is role-gated
   (analyst): ask the human to confirm before calling it.
