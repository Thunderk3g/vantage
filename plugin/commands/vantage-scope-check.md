---
description: Check a target against the approved scope before any scan
argument-hint: [target]
---

Check whether `$ARGUMENTS` (an asset id, hostname, or name) is in the
HOD-approved inventory BEFORE any scan is considered. This command exists to
PREVENT unauthorized scanning: it never scans an out-of-scope target.

Plan:
1. Call `mcp__vantage__scope_check` with the target `$ARGUMENTS`.
2. If `inScope` is `true`:
   - State clearly that the target is in the approved inventory and show the
     matched asset (id, name, host, type).
   - Offer to queue an AUTHORIZED scan via `mcp__vantage__request_scan`. First
     ask the human for `pipeline` (web|infra, must match the asset) and `mode`
     (black-box|gray-box; gray-box also needs auth_context: unauthenticated|
     min-privilege|max-privilege). Do not request the scan until they confirm.
3. If `inScope` is `false`:
   - REFUSE to scan. Say explicitly that the target is NOT in the HOD-approved
     inventory and that a scan request would be refused server-side
     (403 out_of_scope).
   - Show any `candidates` returned so the human can pick a legitimate in-scope
     asset instead, then STOP. Do not call `mcp__vantage__request_scan` for an
     out-of-scope target under any circumstances.
