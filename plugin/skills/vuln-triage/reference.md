# Vantage triage — reference

Longer worked examples and decision trees for the [vuln-triage skill](SKILL.md).
The governance numbers (bands, 30/30/60/60 SLAs, the 0/2/4/9/18 staircase, the
3/12-month tier cutoffs) live in SKILL.md and are the source of truth; this file
shows how to *apply* them. All examples assume "today" is the pinned demo date
used by the seed data and that the asset is in the HOD-approved inventory
(confirm with `scope_check` first).

---

## Worked triage examples

### A. CVSS 9.3 BOLA on a Tier-1 claims API (VLN-2087)

Finding: *"BOLA on `/v1/claims/{id}` exposes other policyholders' claims"* on
`AST-CLAIMS` (Claims Processing API, Tier-1, Production), CVSS 9.3.

1. **Severity.** 9.3 >= 9.0 -> **critical**.
2. **SLA.** critical -> **30 days**. `deadline = discovered + 30`.
3. **Taxonomy.** "BOLA" / broken-object-level-authorization keyword ->
   **OWASP API1:2023** (and OWASP Web A01:2021). This is an authorization flaw,
   not injection.
4. **Escalation timeline** (once overdue, by days overdue):
   - Day 0: Owner notified — **Asset Owner** (Claims Platform).
   - Day 2: Reminder — Asset Owner.
   - Day 4: **AppSec Lead** (Team Lead stage).
   - Day 9: **Security Manager**.
   - Day 18: **CISO escalation**.
   A Tier-1 production claims API leaking other policyholders' data is exactly
   the case the staircase exists for — flag it as a top overdue critical.
5. **Tools.** Read it with `get_finding("VLN-2087")` (severity/SLA/escStage come
   back computed). Move it with `set_finding_status` as the analyst works it
   (`triaged -> in_progress -> retest -> closed`). Use `escalations` to see who
   it is currently with.

### B. CVSS 9.8 default admin credentials on a document server (VLN-2074)

CVSS 9.8 -> **critical** -> **30-day** SLA. Maps to OWASP A07:2021 (Auth
failures) / CWE-798 (hard-coded credentials) / CIS-5.2. Status `open` and
unassigned: recommend assigning an owner and moving to `triaged`/`in_progress`
via `set_finding_status`. Never "fix" it — Vantage reports, humans remediate.

### C. CVSS 7.4 missing rate limiting on OTP (VLN-2052)

7.4 >= 7.0 -> **high** -> **30-day** SLA. Maps to OWASP **API4:2023**
(Unrestricted Resource Consumption) / CWE-770.

### D. CVSS 5.9 TLS 1.0/1.1 on the payment gateway (VLN-2031)

5.9 >= 4.0 -> **medium** -> **60-day** SLA. Maps to OWASP A02:2021 (Crypto
failures) / CIS-3.10 (encrypt in transit).

### E. CVSS 2.0 server-version banner disclosure (VLN-1990)

2.0 > 0 -> **low**? No — the seed labels it **info** (informational banner
disclosure). When a tool-provided severity says info and the CVSS is a low
informational score, prefer the band the engine emits. **Info has no SLA**, so
there is no deadline and no escalation. This is the kind of low-value finding
where a remediate-or-document call is reasonable — and where an exception
request is usually overkill (see EXC-039 below, which was rightly rejected).

### Severity-band boundary reminders

- 9.0 is **critical** (not high). 8.9 is **high**.
- 7.0 is **high** (not medium). 6.9 is **medium**.
- 4.0 is **medium** (not low). 3.9 is **low**.
- Anything `> 0` but `< 4.0` is **low**; only `0`/none/unparseable -> **info**.

---

## OWASP / SANS / CIS mapping intent

The engine attaches framework taxonomy deterministically (no LLM), in this
precedence order — the first level that matches wins:

1. **Native id** `(source_tool, native_id)` — e.g. a Nessus plugin id, a Burp
   issue type, a Nuclei template slug. Most specific.
2. **Tool tag / family** `(source_tool, tag)` — e.g. a Nessus plugin family, a
   Nuclei tag, a ZAP alert family, a Trivy class.
3. **CIS control id** carried on a config/compliance finding (`CIS-x.y`) ->
   mapped to the closest OWASP class so config findings still light up the
   web/API dashboards.
4. **Title keyword** (last resort, conservative) — only fires when nothing more
   authoritative matched.

Intent of each framework field:

- **`owasp_web`** — OWASP Web Top 10 2021 (e.g. A01 Broken Access Control, A03
  Injection, A02 Cryptographic Failures, A05 Misconfiguration, A06 Vulnerable
  Components, A07 Auth Failures, A09 Logging, A10 SSRF).
- **`owasp_api`** — OWASP API Top 10 2023 (e.g. API1 BOLA, API2 Broken Auth,
  API3 Broken Object Property Level Auth, API4 Unrestricted Resource
  Consumption, API7 SSRF, API9 Improper Inventory Management).
- **`sans25`** — CWE Top 25 ids (e.g. CWE-89 SQLi, CWE-79 XSS, CWE-918 SSRF,
  CWE-798 hard-coded creds, CWE-22 path traversal, CWE-601 open redirect).
- **`cis_control`** — CIS Controls v8 id (e.g. CIS-3.10 encrypt-in-transit,
  CIS-4.1 secure config, CIS-4.8 disable unneeded services, CIS-5.2 unique
  passwords, CIS-7.4 patch management).

A single finding can carry several at once (e.g. an SSRF is A10:2021 +
API7:2023 + CWE-918). Read the mapping off `get_finding`; do not re-derive it by
hand unless you are explaining a result.

---

## Exception-routing examples (duration -> tier)

Tier is decided purely by **requested duration**, and the server routes it — you
recommend the duration and the documented risk, never the approver.

| Example | Duration | Tier | Approver |
|---------|----------|------|----------|
| Cleartext internal service, 2-month compensating-control window (EXC-044) | 2 mo | **CISO** | CISO |
| No-MFA admin console, vendor module due Q3, 5-month bridge (EXC-046) | 5 mo | **RMC** | Risk Mgmt Committee |
| Session-cookie flags on a staging HR portal, full replacement next FY (EXC-041) | 14 mo | **Board** | Board Risk Committee |
| Server banner disclosure, 1 month — low effort to fix (EXC-039) | 1 mo | CISO | **Rejected** — remediate instead |

Boundary cases: exactly **3 months -> CISO**; exactly **12 months -> RMC**;
**13+ months -> Board**. The 1-month banner request shows tier routing does not
imply approval — a cheap-to-fix info finding should be remediated, not excepted.

Flow:

1. `request_exception(finding_id, duration_months, documented_risk)` — server
   sets `tier` and `status=requested`. `documented_risk` is mandatory.
2. The matching tier role reviews and calls
   `decide_exception(exception_id, "approve"|"reject")`.
3. **On approve only**, the server flips the linked finding to `risk_accepted`
   (the sole path to that state). On reject, the finding stays in its workflow.

---

## False-positive vs risk-acceptance decision tree

```
Is the finding actually exploitable / real?
├─ NO  → it's a false positive
│        → confirm_false_positive(finding_id, "confirm")  → status confirmed_fp
│          (clearing later: decision "clear" → back to triaged)
│
└─ YES → it's a real risk. Remediate within SLA if possible.
         ├─ Can it be fixed within the SLA window?
         │   └─ YES → work the normal path:
         │            set_finding_status: triaged → in_progress → retest → closed
         │            (retest closure verified by scan_diff)
         │
         └─ NO (needs a time-boxed acceptance) → request an exception
             → request_exception(finding_id, duration_months, documented_risk)
             → tier by duration: ≤3mo CISO · ≤12mo RMC · >12mo Board
             → tier role: decide_exception(...)
             → if approved, server sets the finding to risk_accepted
```

Key distinctions:

- **`confirmed_fp`** means "not a real issue" — reached only through the
  false-positive flow. Do not use a risk exception to dispose of a false
  positive.
- **`risk_accepted`** means "real, but consciously accepted for a bounded time
  by the right authority" — reached only through an **approved** exception.
- A `closed` finding is a real issue that was **remediated** and verified.
- All three are "not an open risk" for dashboard/SLA purposes, but they are NOT
  interchangeable — pick the one that matches reality.

Never set `risk_accepted` or `confirmed_fp` directly via `set_finding_status`
(the server only accepts open/triaged/in_progress/retest/closed there). Use the
dedicated flow, and remember the actor and role-gating are enforced server-side.
