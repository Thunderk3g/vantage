---
name: vuln-triage
description: Use when triaging Vantage findings, setting severity/SLA, deciding escalation, or handling exceptions/false-positives for the vulnerability console. Encodes the IRDAI SLA + escalation-staircase + exception-tier governance.
---

# Vantage vulnerability-triage playbook

Deterministic governance rules for triaging findings in the **Vantage** console.
Apply this whenever you set or explain a severity/SLA, decide where an overdue
finding escalates, route an exception, or confirm a false positive.

> **Hard boundary — scan-and-report ONLY.** Vantage detects, triages, and
> reports. It NEVER exploits, attacks, moves laterally, or auto-fixes. Never
> scan a target that is not in the HOD-approved inventory — run `scope_check`
> first (the server scope gate fails closed with `403 out_of_scope`).
>
> This skill only **recommends** the right band/SLA/stage/tier and the right
> tool to call. Every mutation is **human-gated + role-gated server-side**, and
> the report actor is **server-derived**. The skill never bypasses a gate and
> never claims to act as a role it is only recommending for.

These numbers are the single source of truth and must match the code
(`orchestrator/triage/engine.py`, `orchestrator/api/seed.py`,
`frontend/data.js`). See [reference.md](reference.md) for worked examples,
the full OWASP/SANS/CIS mapping intent, and the decision trees.

## 1. Severity bands (CVSS v3 base score)

| CVSS base | Severity |
|-----------|----------|
| >= 9.0    | critical |
| >= 7.0    | high     |
| >= 4.0    | medium   |
| > 0       | low      |
| 0 / none  | info     |

If CVSS is missing/unparseable, fall back to the tool-provided severity
(normalized), else `info`. Bands are lower-case.

## 2. IRDAI closure SLAs (severity -> window)

| Severity | SLA (days) |
|----------|------------|
| critical | 30         |
| high     | 30         |
| medium   | 60         |
| low      | 60         |
| info     | no SLA     |

`deadline = detected_at + sla_days`. Info has no deadline (`None`).

## 3. Escalation staircase (days open / overdue -> role)

| Day | Stage              | Role             |
|-----|--------------------|------------------|
| 0   | Owner notified     | Asset Owner      |
| 2   | Reminder           | Asset Owner      |
| 4   | Team Lead          | AppSec Lead      |
| 9   | Sec Manager        | Security Manager |
| 18  | CISO escalation    | CISO             |

The staircase advances by **days overdue** once past the SLA deadline (a
not-yet-overdue finding sits at an early stage based on elapsed time since
discovery). A `closed` / `risk_accepted` / `confirmed_fp` finding does not
escalate.

## 4. Exception approval tiers (by requested duration)

| Requested duration | Approver tier                  |
|--------------------|--------------------------------|
| <= 3 months        | CISO                           |
| <= 12 months       | RMC (Risk Management Committee) |
| > 12 months        | Board (Board Risk Committee)   |

## 5. State machine

Generic path: `open -> triaged -> in_progress -> retest -> closed`.

Two terminal states are reachable ONLY via their dedicated flow:

- `risk_accepted` — ONLY when an exception is **approved** (server flips the
  linked finding). Never set it directly.
- `confirmed_fp` — ONLY via the false-positive flow.

## How to apply with the Vantage tools (`mcp__vantage__*`)

| Decision / need | Tool | Notes |
|-----------------|------|-------|
| Posture snapshot, overdue/due-soon counts | `dashboard` | Start here. |
| Severity + SLA + escalation come back already computed | `list_findings` / `get_finding` | Read the band/`slaDays`/`deadline`/`daysLeft`/`escStage`; do NOT recompute by hand unless explaining. |
| Confirm a target is authorized BEFORE any scan | `scope_check` then `list_assets` | Out-of-scope targets are refused server-side (`403 out_of_scope`). |
| Queue an authorized scan | `request_scan` | Scope-gated server-side; only for approved assets. Never an exploit. |
| Move a finding through the workflow | `set_finding_status` | open/triaged/in_progress/retest/closed only. Analyst role-gated. |
| Request a retest (-> retest, closure verified by diff) | `request_retest` + `scan_diff` | Closure = the re-scan no longer reports it. |
| False positive (confirm/clear) | `confirm_false_positive` | Only path to `confirmed_fp`. |
| Request a time-boxed exception | `request_exception` | Server routes the tier by duration (3/12 cutoffs). `documented_risk` required. |
| Approve/reject an exception | `decide_exception` | Tier-role-gated. Approval is the ONLY path to `risk_accepted`. |
| Who an overdue finding is currently with | `escalations` | The Day 0->2->4->9->18 staircase rollup. |
| Produce a report | `generate_report` | Actor is server-derived; PDF needs dual passwords. |
| Review the hash-chained trail | `audit` | Append-only. |

**Recommend, don't bypass.** When a step needs a role (analyst action, CISO/RMC/
Board approval), say which role must act and call the forwarding tool — the
server enforces RBAC and human-gating. If a tool returns `403`/`out_of_scope`,
surface the gate's verdict; do not work around it.
