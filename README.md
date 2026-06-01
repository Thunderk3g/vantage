# Vantage — AI-Augmented Vulnerability Scanner

> Scan-and-report orchestrator for a regulated Indian life insurer
> (BFSI · IRDAI-regulated · ISO 27001:2022). Internal InfoSec / AppSec tooling.

[![CI](https://github.com/Thunderk3g/vantage/actions/workflows/ci.yml/badge.svg)](https://github.com/Thunderk3g/vantage/actions/workflows/ci.yml)
![status](https://img.shields.io/badge/status-console%2BAPI%20integrated%20%C2%B7%20engines%20stubbed-blue)
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

## Status — what's built vs. what's left

This is a **reference build**: the architecture, data model, API, and console are
real and verified; the scanning engines, triage, reporting, and security plumbing
are designed and scaffolded but not yet wired to live systems.

| Component | State | Notes |
|---|---|---|
| Architecture & data model | ✅ Done | `docs/architecture.*`; reviewed end-to-end. |
| Database schema (`db/schema.sql`) | ✅ Done | Applies on Postgres 16; SLA trigger, audit hash-chain, exception-routing CHECK all **verified** (and smoke-tested in CI + Docker). |
| Console API (`orchestrator/api/`) | ✅ Done | FastAPI; reads, **human-gated writes** (status, scope-gated scans, exceptions), and **report generation/download** — per `docs/api-contract.md`. **Audit trail persists to the hash-chained Postgres `audit_log`**; finding/scan state is still in-memory. |
| Triage engine (`orchestrator/triage/`) | ✅ Done (det.) | Deterministic dedup + CVSS→severity + SLA + OWASP/SANS/CIS mapping, unit-tested, **wired into the pipeline** via `orchestrator/normalization.py`. LLM layer still designed. |
| Reporting (`orchestrator/reporting/` + `/api/reports`) | ✅ Done | xlsx + docx + **dual-password PDF** (reportlab→pikepdf, AES-256), unit-tested, **wired to `POST /api/reports` + the Reports screen** (generate → download). |
| Web console — 8 screens | ✅ Done | Built from the design handoff; all screens read-wired, plus **write flows** on Finding detail (status), Start-a-scan (scope gate), and Exceptions (request). Loading/error states + offline read fallback. |
| Docker stack (web + api + db) | ✅ Done | `docker compose up`; CI builds + boots + smoke-tests it. |
| Orchestrator workflows (Temporal) | 🟡 Skeleton | Phase gating + hard stop before exploitation are real; activities are `NotImplementedError` stubs. |
| Scanner adapters | 🟡 Skeleton | Contracts + result parsers exist; engine calls + vault creds stubbed. |
| Scope gate / scheduler | 🟡 Skeleton | API scope gate enforces approved-inventory on console scans; orchestrator-side inventory resolution + token signing still stubbed. |
| AI triage — LLM layer | ⬜ Designed | Deterministic engine is done (above); the redacted-batch LLM pass is designed, not implemented. |
| Auth / RBAC / SSO | ⬜ Designed | Console role switcher is a **mock**; no real authz yet. |
| Secrets / vault | ⬜ Designed | CyberArk/Vault integration designed; not wired. |

## What's left for integration

Ordered roughly by dependency. Tracked live in **[ROADMAP.md](ROADMAP.md)**.

1. ✅ **Write path (human-gated mutations).** *Done* — `PATCH` finding status,
   scope-gated `POST /api/scans` (fail-closed), `POST /api/exceptions` (tier
   routing). Every mutation needs a human `actor`.
2. 🟡 **Persistence.** *Audit trail done* — mutations persist to the hash-chained
   Postgres `audit_log` (DB-backed with in-memory fallback). **Left:** persist the
   finding/scan/exception *state* itself via `psycopg` against the schema (still
   an in-memory store today).
3. 🟡 **Triage.** *Deterministic engine done + wired* (`orchestrator/triage/` via
   `orchestrator/normalization.py` into `activities.normalize_and_triage`,
   unit-tested). **Left:** the redacted **LLM** pass, and feeding it real adapter
   output (depends on #5).
4. ✅ **Reporting.** *Done* — `orchestrator/reporting/` (xlsx/docx/dual-password
   PDF) exposed via `POST /api/reports` + `GET /api/reports/{id}/{fmt}` and wired
   to the Reports screen (generate → download).
5. **Scanner adapter bodies.** Wire Nmap / Nessus / Burp / Nikto (and the OSS
   ZAP / Nuclei / Trivy variant) engine calls + least-privilege vault creds.
   This produces the real findings that flow into triage (#3).
6. **Scope gate + scheduler (engine side).** The orchestrator's own scope gate
   (Ed25519 token signing via vault) and the scan cadence (internal/public 2×/yr,
   CIS 1×/yr) — the API's scope gate already guards console-initiated scans.
7. **Auth.** SSO + RBAC replacing the role switcher; per-role API authorization.
8. **Hardening.** Non-root images, vault-sourced secrets, TLS/reverse proxy,
   pen-test of Vantage itself, ISO 27001 evidence pack.

> **Boundary that never moves:** none of the above adds exploitation, lateral
> movement, or auto-remediation. Validation and manual PT stay human-gated and
> downstream. See [CONTRIBUTING.md](CONTRIBUTING.md).

### Security posture (reference build — read before deploying)

The API has **no authentication yet** — auth/RBAC (#7) is the headline security
slice. Until it lands, two known, tracked gaps exist by design:

- **Actor is client-supplied.** Every write sends a `by`/`actor` placeholder
  (the console sends `"A. Mehta"`); audit attribution is therefore *advisory*,
  not authenticated. When auth lands, the actor is derived from the session.
- **Report downloads are capability-token-gated.** `GET /api/reports/{id}/{fmt}`
  is protected only by an opaque ~192-bit `reportId` (TTL-bounded), not per-user
  authz. When auth lands, downloads become owner/role-scoped.

Do not expose this build outside a trusted network until #7 is done. The
remaining write endpoints inherit the same no-auth caveat.

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
  triage/                 Deterministic triage: dedup, severity, SLA, OWASP/SANS/CIS maps.
  normalization.py        Bridges raw multi-tool adapter output into the triage engine.
  reporting/              xlsx / docx / dual-password PDF export engine.
  api/                    FastAPI console API: reads, writes, reports, audit (per
                          docs/api-contract.md). api/db.py persists audit to Postgres.
  Dockerfile              API service image (FastAPI + uvicorn + psycopg + report libs).
  requirements.txt
frontend/
  index.html + *.jsx      Vulnerability Console UI (zero-build React + Babel):
                          Dashboard, Findings, Finding detail, Start a scan,
                          SLA tracker, Exceptions, Reports, Design system.
  api.js                  REST client (date hydration + offline fallback).
  Dockerfile              Static console image (nginx).
docker-compose.yml        Whole stack: web + api + db (schema auto-applied).
docs/
  architecture.docx/.pdf  Full architecture & build plan.
  api-contract.md         Frozen REST contract between API and console.
  crawler-integration.md  Note on reusing the seo-repo crawler logic in recon.
  generate_architecture_docx.js
.github/
  workflows/ci.yml        CI: orchestrator compile + scope guard, schema apply
                          + smoke tests, frontend JSX, docs, Docker build + boot.
  ISSUE_TEMPLATE/         Scope-item, engine-adapter, and bug templates.
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

## Getting started

### Docker (whole stack, recommended)

```bash
docker compose up --build
#  web : Vulnerability Console (nginx)  -> http://localhost:8137
#  api : read-only FastAPI (seed-backed) -> http://localhost:8138
#  db  : Postgres 16, schema.sql applied -> localhost:5432
```

The console (8137) talks to the API (8138); both ports are published to the
host so the browser reaches each directly (CORS is scoped to the console
origin). The API serves seed data today; `db` provisions and validates the
schema for the next phase.

### Manual (dev)

```bash
# 1. Provision the schema
psql -f db/schema.sql

# 2. Orchestrator
pip install -r orchestrator/requirements.txt
python orchestrator/worker.py            # needs a Temporal cluster

# 3. Console API (read-only)
uvicorn orchestrator.api.main:app --port 8138

# 4. Web console (Vulnerability Console UI)
cd frontend && python -m http.server 8137   # open http://localhost:8137

# 5. Regenerate the architecture doc (optional)
npm install
node docs/generate_architecture_docx.js
```

All 8 console screens fetch from the API (8138) with a graceful **offline
fallback** to the bundled mock data (`frontend/data.js`), so the console still
renders if the API is down. The API currently serves a seed dataset that maps
1:1 to the schema; see [`frontend/README.md`](frontend/README.md) and
[`docs/api-contract.md`](docs/api-contract.md).

> The orchestrator's adapter / vault / datastore calls are `NotImplementedError`
> stubs — see the [status table](#status--whats-built-vs-whats-left) for exactly
> what's live vs. scaffolded.

## Scope & roadmap

Project scope is tracked in **[ROADMAP.md](ROADMAP.md)** (phases 0–5, each with a
checklist) and on the GitHub issue tracker via the templates in
`.github/ISSUE_TEMPLATE/`. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for how we
keep scope honest — every change maps to a roadmap item or a tracked issue.

## Disclaimer

Internal tool. All scanning targets are assets the organization owns and is
authorized to scan. This repository contains a reference skeleton with no live
credentials, no real asset inventory, and no exploit capability.
