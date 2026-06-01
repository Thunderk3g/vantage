<!-- Every PR should advance a ROADMAP.md item or a tracked issue. -->

## What & why

Closes #
Roadmap item:  <!-- e.g. Phase 1 → "Deterministic triage" -->

## Changes

-

## Scope-boundary checklist

- [ ] Does **not** add exploitation, lateral movement, or auto-remediation.
- [ ] Keeps validation / manual PT downstream and human-gated.
- [ ] Scope gate still fail-closed; targets re-verified at use time.
- [ ] No exploitation phase introduced (`scan_phase` / `Phase` unchanged or additive-only).
- [ ] Secrets only from the vault; no credentials committed.
- [ ] Any XML parsing uses `defusedxml`.
- [ ] `ROADMAP.md` updated (box checked / item added) if scope changed.

## Verification

<!-- Paste the command output you ran. Evidence before assertions. -->
```
```
