# Vantage — AI-Augmented Vulnerability Scanner

> Scan-and-report orchestrator for a regulated Indian life insurer
> (BFSI · IRDAI-regulated · ISO 27001:2022). Internal InfoSec / AppSec tooling.

[![CI](https://github.com/Thunderk3g/vantage/actions/workflows/ci.yml/badge.svg)](https://github.com/Thunderk3g/vantage/actions/workflows/ci.yml)
![status](https://img.shields.io/badge/status-Phase%200%2F1%20reference-blue)
![license](https://img.shields.io/badge/license-Internal-lightgrey)

Vantage **detects, triages, and reports** vulnerabilities across infrastructure
and web applications. It orchestrates existing scanning engines, normalizes and
deduplicates their output, and uses an LLM triage layer to reduce false
positives, normalize severity, assign IRDAI-mandated SLAs, and draft reports.

> [!IMPORTANT]
> **Vantage scans and reports only.** It does **not** exploit, perform lateral
> movement, or auto-fix anything. Manual penetration testing and validation of
> findings remain **human-gated and downstream**. A scope allowlist (the
> HOD-approved asset inventory) is enforced at every stage — the scanner
> refuses any target not in the approved inventory.

---

## What it does

| Capability | How |
|---|---|
| **Two SOP pipelines** | Infrastructure (Nmap + Nessus VA + CIS config review) and Web App (Nikto + Burp, three auth contexts). OSS variant swaps in ZAP / Nuclei / Trivy — identical phases. |
| **Scope gate** | Single authorization chokepoint. Targets are resolved against the approved inventory and a signed, time-boxed token is minted; absence from the inventory is a hard deny. Re-checked at use time (TOCTOU defense). |
| **AI triage** | Deterministic rules first (dedup, CVSS→severity band, SLA, OWASP/SANS/CIS mapping), then a redacted LLM batch pass for fuzzy dedup, false-positive scoring, and impact/remediation drafting. The LLM is advisory — it cannot suppress findings or change severity outside the band. |
| **SLA automation** | Closure deadlines per IRDAI SLA — Critical/High = 30 days, Medium/Low = 60 days from detection — computed by a DB trigger, not hand-edited. |
| **Governance** | Escalation staircase (Day 0 → 2 → 4 → 8–10 → 15–20) and exception routing (CISO ≤3mo · RMC >3–12mo · Board >12mo) enforced in the schema. |
| **Reporting** | Excel, Word, and a dual-password (open + copy/modify) PDF. |
| **Audit** | Append-only, hash-chained audit log; UPDATE/DELETE blocked by trigger. |

## Repository layout

```
db/
  schema.sql              Postgres 16 DDL: assets, scope authorizations, scans,
                          findings, SLAs, escalations, exceptions, retests,
                          and a hash-chained append-only audit log.
orchestrator/
  shared.py               Canonical types incl. CanonicalFinding + AuthToken.
  workflows.py            Temporal pipelines (Infra / WebApp). Terminal phase is
                          REPORT — no exploitation phase exists by construction.
  activities.py           Scope gate, engine activities, triage, reporting.
  worker.py               Registers workflows + activities.
  adapters/               ScannerAdapter protocol + Nmap / Nessus / Burp / Nikto.
  requirements.txt
docs/
  architecture.docx/.pdf  Full architecture & build plan.
  generate_architecture_docx.js
.github/
  workflows/ci.yml        CI: compile, schema apply, doc smoke-test.
  ISSUE_TEMPLATE/         Scope-item, engine-adapter, and finding templates.
ROADMAP.md                Phase-by-phase scope tracker (the source of truth for scope).
CONTRIBUTING.md           How we track and work on scope.
```

## Security invariants (enforced, not just documented)

1. **Scope gate is the only entry.** Fail-closed authorization against the
   approved inventory; re-verified at use time; adapters intersect their
   targets with the token allowlist.
2. **No exploitation phase.** Neither the `scan_phase` DB enum nor the `Phase`
   code enum has an exploit / lateral / remediate value; `report` is terminal.
3. **SLAs are computed, not typed** (DB trigger from severity).
4. **Exceptions route by duration** (CHECK constraint).
5. **Audit log is append-only and hash-chained** (SHA-256; UPDATE/DELETE
   blocked by trigger).
6. **LLM is advisory and offline to targets**, behind a redaction proxy that
   pseudonymizes hosts and strips credentials and payloads.
7. **Hardened XML parsing** (`defusedxml`) for all scanner output (XXE-safe).

## Getting started (dev)

```bash
# 1. Provision the schema
psql -f db/schema.sql

# 2. Orchestrator
pip install -r orchestrator/requirements.txt
python orchestrator/worker.py            # needs a Temporal cluster

# 3. Regenerate the architecture doc (optional)
npm install
node docs/generate_architecture_docx.js
```

> The adapter / vault / datastore calls are `NotImplementedError` stubs. This is
> a **Phase 0/1 structural reference skeleton**, wired up over the roadmap below.

## Scope & roadmap

Project scope is tracked in **[ROADMAP.md](ROADMAP.md)** (phases 0–5, each with a
checklist) and on the GitHub issue tracker via the templates in
`.github/ISSUE_TEMPLATE/`. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for how we
keep scope honest — every change maps to a roadmap item or a tracked issue.

## Disclaimer

Internal tool. All scanning targets are assets the organization owns and is
authorized to scan. This repository contains a reference skeleton with no live
credentials, no real asset inventory, and no exploit capability.
