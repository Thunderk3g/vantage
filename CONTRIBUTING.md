# Contributing to Vantage

## The one rule that overrides everything

Vantage **scans and reports**. It must never gain the ability to exploit,
move laterally, or auto-remediate. Any contribution that adds such a
capability is out of scope and will be closed — no exceptions. Validation of
findings and manual penetration testing stay **downstream and human-gated**.

## How we track and work on scope

Scope is deliberately small and explicit so it can't drift.

1. **`ROADMAP.md` is the source of truth.** It lists phases 0–5, each with a
   checklist and exit criteria. If it isn't on the roadmap, it isn't in scope.
2. **Open a Scope item issue** (`.github/ISSUE_TEMPLATE/scope-item.yml`) to
   propose anything new. It forces you to name the phase, the definition of
   done, and which security invariants are touched.
3. **One PR → one (or few) checklist items.** The PR template requires you to
   link the roadmap item and tick the scope-boundary checklist.
4. **Check the box only when verified.** A `[x]` in `ROADMAP.md` means the exit
   criteria were met and you have command output proving it.

```
idea ──▶ Scope-item issue ──▶ accepted? ──▶ PR (links roadmap item)
                                  │                    │
                                  ▼                    ▼
                          update ROADMAP.md      CI green + review
                                  │                    │
                                  └──────▶ merge ◀─────┘ ──▶ tick the box
```

## Labels

`scope` · `adapter` · `bug` · `phase-0` … `phase-5` · `security-invariant`.
Use the phase labels to filter the board by where work sits in the roadmap.

## Branching & commits

- Branch off `main`: `feature/<phase>-<short-desc>` or `fix/<short-desc>`.
- Keep commits focused; reference the issue (`#123`).
- CI must be green: orchestrator compiles, `schema.sql` applies to Postgres 16
  (incl. the SLA-trigger / audit-immutability smoke tests), the architecture
  doc generates, and the **exploitation-phase guard** passes.

## Security invariants — preserve all seven

1. Scope gate is the only entry (fail closed; re-verified at use time).
2. No exploitation phase (`report` is terminal).
3. SLAs computed by trigger, not hand-edited.
4. Exceptions route by duration (CISO / RMC / Board).
5. Audit log append-only and hash-chained.
6. LLM advisory and offline to targets, behind the redaction proxy.
7. All scanner XML parsed with `defusedxml`.

A PR that weakens any of these needs an explicit, reviewed justification in the
PR description — and most of the time the right answer is "don't."

## Never commit

Live credentials, real asset inventories, raw scan output, or generated
reports. `.gitignore` covers the common cases; you are still responsible.
