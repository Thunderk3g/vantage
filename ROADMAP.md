# Vantage — Roadmap & Scope Tracker

This file is the **source of truth for application scope**. Every PR should
advance one or more checklist items here (or a tracked issue that maps to one).
Keep it honest: check a box only when the exit criteria are met and verified.

**Legend:** `[ ]` not started · `[~]` in progress · `[x]` done & verified

---

## Guardrails (apply to every phase — never descoped)

- [x] Scan-and-report only; **no** exploitation / lateral movement / auto-fix.
- [x] Scope gate enforced at every stage (HOD-approved inventory; fail closed).
- [x] Human-gated validation and manual PT remain downstream.
- [x] All XML parsed with `defusedxml`; secrets only from the vault.

---

## Phase 0 — Foundations  `target: 2–3 wks`
**Exit:** a target can be authorized/denied and every action is audited.

- [x] Postgres schema (`db/schema.sql`)
- [x] `scan_phase` enum has no exploitation value; `report` terminal
- [x] SLA due-date trigger (Crit/High 30d · Med/Low 60d)
- [x] Exception duration→approver CHECK (CISO/RMC/Board)
- [x] Append-only hash-chained audit log
- [ ] Scope gate wired to a real inventory source (`_resolve_approved_targets`)
- [ ] Ed25519 token signing via vault (`_sign_token`)
- [ ] Datastore layer (psycopg) behind the activity stubs
- [ ] RBAC / SSO (AD/LDAP + SAML/OIDC)
- [ ] Temporal cluster + worker deployed in the enclave

## Phase 1 — Infra MVP  `target: 3–4 wks`
**Exit:** end-to-end internal black-box scan → triaged register with SLAs, human-validated.

- [x] Workflow skeleton (`InfraScanWorkflow`)
- [x] Nmap adapter (safe NSE categories only)
- [x] Nessus adapter (VA) with hardened parsing
- [ ] Normalization engine (raw → `CanonicalFinding`)
- [ ] Deterministic triage: dedup + CVSS→severity + SLA assignment
- [ ] Excel report export
- [~] Human-review UI: validate / confirm-FP
      (console scaffold built in `frontend/`; not yet wired to mutate state)

## UI — Vulnerability Console (`frontend/`)  `spans phases 1–4`
**Exit:** each screen is wired to the API and replaces its mock data source.

- [x] Console scaffold: shell, nav, role switcher, design system, tweaks
- [x] All 8 screens laid out on mock data (`data.js`), SLA reconciled to backend
- [x] Read-only API (`orchestrator/api/`, FastAPI) per `docs/api-contract.md`
- [x] Dashboard + Findings wired to `GET /api/findings` (graceful offline fallback)
- [ ] Remaining screens (detail, SLA, exceptions, reports, scan) wired to API
- [ ] Finding detail status workflow → API mutations (human-gated)
- [ ] Start-a-scan posts to the scope gate (approved inventory only)
- [ ] Reports screen triggers real export (incl. dual-password PDF step)
- [ ] SLA tracker + Exceptions wired to live data
- [ ] Auth/RBAC: real role from SSO replaces the role switcher

## Phase 2 — Web MVP  `target: 3–4 wks`
**Exit:** web pipeline parity.

- [x] Workflow skeleton (`WebAppScanWorkflow`)
- [x] Burp adapter (crawl in 3 auth contexts + scan)
- [x] Nikto adapter
- [ ] OWASP Web / OWASP API / SANS-25 mapping tables
- [ ] CIS config review (credentialed Nessus compliance)
- [ ] Word + dual-password PDF export

## Phase 3 — AI triage  `target: 3 wks`
**Exit:** measurable FP reduction with explainability; humans still gate.

- [ ] Redaction proxy (host pseudonymization; strip creds/payloads)
- [ ] Self-hosted LLM endpoint integration
- [ ] Batch structured-output: fuzzy dedup + FP scoring + impact/remediation notes
- [ ] Reconcile LLM output against deterministic severity bands
- [ ] Low-confidence → human queue

## Phase 4 — Governance & lifecycle  `target: 3 wks`
**Exit:** full SLA / escalation / exception lifecycle running.

- [ ] Escalation staircase automation (Day 0 → 2 → 4 → 8–10 → 15–20)
- [ ] Exception routing UI + approvals (CISO / RMC / Board)
- [ ] Retest / diff flow (closure verification vs prior scan)
- [ ] Notification service + ITSM integration (Jira / ServiceNow)
- [ ] Scheduler with cadence + blackout calendars
      (internal 2×/yr · public 2×/yr · CIS 1×/yr)

## Phase 5 — OSS variant & hardening  `target: 2–3 wks`
**Exit:** license-free pipeline at parity; audit-ready.

- [ ] ZAP / Nuclei / Trivy adapters at parity
- [ ] Pen-test of Vantage itself
- [ ] ISO 27001:2022 evidence pack
- [ ] DR / backup; role attestation

---

## How scope changes are made

1. Propose the change as a **Scope item** issue (template in `.github/ISSUE_TEMPLATE/`).
2. If accepted, add/adjust a checklist item here in the same PR.
3. Anything that would add exploitation, lateral movement, or auto-remediation
   is **out of scope by definition** and must be rejected.
