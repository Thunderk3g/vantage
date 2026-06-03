# Vantage API contract v0 (read-only)

Frozen interface between the orchestrator API and the web console. Both the
backend and frontend implement to **this document**. Don't change shapes
without updating this file.

- Base URL (dev): `http://localhost:8138`
- All endpoints prefixed `/api`. JSON only. Read-only in v0 (no writes yet).
- **CORS:** allow `http://localhost:8137` (the console dev server).
- **"Today" is pinned to `2026-06-01`** so SLA countdowns are stable and match
  the design. Server computes all SLA/escalation fields from this date.
- The **single source of truth for the seed data and all derivation logic is
  `frontend/data.js`** — the API must reproduce its objects field-for-field.

## SLA policy (server-computed; matches db/schema.sql)

`slaDays`: Critical 30 · High 30 · Medium 60 · Low 60 · Info `null`.
`deadline = discovered + slaDays days` (null if Info).
`daysLeft = round((deadline - TODAY) / 1 day)` (null if Info/closed).
`isClosed = status in {closed, risk_accepted}`.
`escStage`: integer 0–4, derived exactly as in `frontend/data.js` (overdue-by
thresholds 18/9/4/2/0, else elapsed-since-discovery 18/4).

## Endpoints

### `GET /api/health` → `{ "status": "ok", "today": "2026-06-01" }`

### `GET /api/findings`
Optional query params (all combine with AND):
`severity` (csv: critical,high,…), `status` (csv), `assetId`, `pipeline`
(web|infra), `framework`, `sla` (overdue|due_soon|ok|met), `q` (substring of
id/title/asset), `sort` (field), `dir` (asc|desc).

Response: `{ "findings": [ Finding, … ], "total": <int> }`

`Finding` (dates are ISO `YYYY-MM-DD` strings or null):
```json
{
  "id": "VLN-2087",
  "title": "BOLA on /v1/claims/{id} …",
  "severity": "critical",
  "status": "triaged",
  "assetId": "AST-CLAIMS",
  "asset": "Claims Processing API",
  "assetType": "web",
  "assetCrit": "Tier-1",
  "assetOwner": "Claims Platform",
  "pipeline": "web",
  "framework": "OWASP API",
  "catCode": "API1:2023",
  "catName": "Broken Object Level Authorization",
  "cvss": 9.3,
  "discovered": "2026-05-06",
  "deadline": "2026-06-05",
  "slaDays": 30,
  "daysLeft": 4,
  "isClosed": false,
  "escStage": 2,
  "owner": "R. Iyer",
  "scan": "SCAN-098"
}
```

> `escStage`/`scan` above are the exact values `frontend/data.js` derives (the
> source of truth). `sla` filter buckets: `met` = closed/risk-accepted,
> `overdue` = daysLeft<0, `due_soon` = 0..7, `ok` = otherwise.

### `GET /api/findings/{id}` → `{ "finding": Finding }` (404 if unknown)

### `GET /api/assets` → `{ "assets": [ Asset, … ] }`
`Asset` = the objects in `window.ASSETS` (id, name, type, env, owner, crit, host).

### `GET /api/scans` → `{ "scans": [ Scan, … ] }`
`Scan` = the objects in `window.SCANS`.

### `GET /api/exceptions` → `{ "exceptions": [ Exception, … ] }`
`Exception` = the objects in `window.EXCEPTIONS`.

### `GET /api/trend` → `{ "trend": [ {wk,critical,high,medium,low}, … ] }`
= `window.TREND`.

### `GET /api/dashboard` (convenience rollup)
```json
{
  "today": "2026-06-01",
  "openBySeverity": { "critical": 3, "high": 5, "medium": 5, "low": 3, "info": 2 },
  "counts": { "open": 18, "overdue": 4, "dueSoon": 6, "scansRunning": 2 },
  "trend": [ … ]
}
```

## Frontend integration rule

`window.SLA_DAYS`, `window.ESCALATION`, `window.exceptionTier` are **policy
constants** and stay client-side in `data.js`. Everything else (findings,
assets, scans, exceptions, trend) is fetched. The console must **degrade
gracefully**: if the API is unreachable, fall back to the in-file mock data so
the prototype still renders offline.

---

# Write endpoints (v0.1) — human-gated

> **Auth update (v1, see `docs/auth-contract.md`).** Auth/RBAC is now wired.
> All reads require an authenticated user (`/api/health` stays public);
> mutations are **role-gated** (`require_role`). The write **`actor` is derived
> server-side** from the session (`session_actor(user)`) — the `actor` / `by` /
> `requestedBy` body fields below are **ignored** (kept optional for one release).
> In the reference build (`AUTH_REQUIRED` unset) an unauthenticated caller is the
> synthetic `dev` admin, so the contract below behaves unchanged offline; in
> production (`AUTH_REQUIRED=true`) unauthenticated → **401**, wrong role → **403
> `forbidden`**. Error bodies for auth are normalized to the same `{error,detail}`
> shape. RBAC: status/scan/exception require `analyst`; report generation requires
> `analyst` or an approver role; `admin` is a wildcard.

Every mutation appends an **audit entry** (and scope-gate denials are audited too).
Writes are applied to the in-memory store so subsequent reads reflect them
(persistence to Postgres is a later slice). Error bodies are
`{ "error": "<code>", "detail": "<human message>" }`; the client throws on any
non-2xx (no silent fallback for writes).

**Boundary:** none of these triggers exploitation or auto-remediation. No
endpoint sets `risk_accepted` or auto-closes by time — `risk_accepted` is only
reachable via an *approved* exception (out of scope for v0.1, so unreachable).

### `PATCH /api/findings/{id}/status`
Body: `{ "status": "open|triaged|in_progress|retest|closed", "actor": "<name>", "note"?: "<text>" }`
- Allowed: any move within `open → triaged → in_progress → retest → closed`,
  forward or backward (reopen). **Reject** `risk_accepted`/`confirmed_fp` here (422).
- On success: set `status`, `humanValidatedBy = actor`, `humanValidatedAt = today`;
  audit `FINDING_STATUS_CHANGED`. Returns `{ "finding": Finding }`.
- Errors: 404 unknown id; 422 missing `actor` or disallowed `status`.
- `Finding` gains two fields going forward: `humanValidatedBy` (nullable),
  `humanValidatedAt` (ISO date, nullable) — included on all finding reads.

### `POST /api/scans`  — SCOPE GATE (fail closed)
Body: `{ "assetId": "AST-…", "pipeline": "web|infra", "mode": "black-box|gray-box", "authContext"?: "unauthenticated|min-privilege|max-privilege", "by": "<name>" }`
- **Scope gate:** `assetId` MUST be in the approved inventory. Unknown or
  non-approved → **403** `{ "error": "out_of_scope", "detail": "<id> is not in the approved asset inventory" }` (audited as `SCAN_DENIED_OUT_OF_SCOPE`).
- `pipeline` must match the asset's type (web↔web, infra↔infra) → 422 if not.
- `gray-box` requires `authContext` → 422 if missing. `by` required → 422.
- On success (**201**): create `Scan` `{id:"SCAN-####", target:<asset name>,
  pipeline, type:<mode>, auth:<authContext or "—">, status:"queued", progress:0,
  started:"<now>", findings:0, by}`; audit `SCAN_REQUESTED`. Returns `{ "scan": Scan }`.

### `POST /api/exceptions`
Body: `{ "findingId": "VLN-…", "requestedBy": "<name>", "durationMonths": <int>, "documentedRisk": "<text>" }`
- Tier resolved from duration (mirrors the DB CHECK): `≤3 → CISO`, `≤12 → RMC`,
  `>12 → Board`.
- `documentedRisk` required (422 if empty); `durationMonths > 0` (422); `findingId`
  must exist (404).
- On success (**201**): create an `Exception` `{id:"EXC-###", finding, title,
  asset, severity, duration, tier, status:"requested", requestedBy,
  approver:<tier full name>, reviewDate:"—", reason:<documentedRisk>}`; audit
  `EXCEPTION_REQUESTED`. Returns `{ "exception": Exception, "tier": "<CISO|RMC|Board>" }`.

### `POST /api/findings/{id}/false-positive` — FP confirm/clear (role: `analyst`)
Body: `{ "decision": "confirm" | "clear", "note"?: "<text>" }`.
- `confirm` → status `confirmed_fp` (treated as **closed** — excluded from open
  counts); `clear` → status `triaged`. Sets `humanValidatedBy/At` (server actor).
- Audited `FINDING_FP_CONFIRMED` / `FINDING_FP_CLEARED`. Returns `{ "finding": Finding }`.
- 422 invalid `decision`; 404 unknown id; 403 if not `analyst`/`admin`.

### `POST /api/exceptions/{id}/decision` — approve/reject (role: the exception's tier)
Body: `{ "decision": "approve" | "reject", "note"?: "<text>" }`.
- **Authorized by the exception's tier:** CISO→`approver_ciso`, RMC→`approver_rmc`,
  Board→`approver_board` (`admin` always). Wrong role → **403**.
- Only `requested`/`pending` exceptions are decidable → else **422** `not_decidable`.
- `approve` → exception `approved` (+ `reviewDate` today) **and the linked finding
  becomes `risk_accepted`** — this is the ONLY path to `risk_accepted` (the generic
  status PATCH still rejects it). Audited `EXCEPTION_APPROVED` + `FINDING_RISK_ACCEPTED`.
- `reject` → exception `rejected`. Audited `EXCEPTION_REJECTED`.
- Returns `{ "exception": Exception, "finding": Finding | null }`. 404 unknown id.

### `GET /api/audit?limit=N`
Returns `{ "audit": [ { "seq", "ts", "actor", "action", "entityType", "entityId", "summary" }, … ] }`, most-recent first. Simplified in-memory mirror of the
hash-chained `audit_log` table.

### `GET /api/escalations` — escalation staircase rollup (any authenticated user)
Returns the Day 0→2→4→9→18 ladder and per-finding escalation state:
```json
{ "today": "2026-06-02",
  "ladder": [ {"stage":0,"day":0,"label":"Owner notified","role":"Asset Owner"}, … 5 ],
  "stageCounts": [n0,n1,n2,n3,n4],
  "findings": [ {"id","title","severity","assetId","asset","owner","assetOwner",
    "deadline","daysLeft","escStage","stageLabel","role","nextRole","nextDay",
    "overdue":bool,"dueForEscalation":bool}, … ],
  "due": [ …subset where dueForEscalation… ],
  "counts": { "active": N, "overdue": M, "due": K } }
```
Derived deterministically from the findings (server reuses `escStage`/`daysLeft`).

### `POST /api/escalations/run` — run a notification sweep (role: `admin`)
Computes the `due` escalations and dispatches a notification per finding via the
notification service (log + in-memory sinks; a webhook/ITSM sink is the prod
plug-in). **Notifies humans only — never acts on a target.** Audited
`ESCALATION_SWEEP`. **200** →
```json
{ "dispatched": [ {"findingId","stage","role","severity","kind","message","channels":[…],"deduped":bool}, … ],
  "count": K, "ranAt": "<iso>" }
```
Dedupe: a `(finding, stage)` already dispatched in the run is skipped. 403 if not `admin`.

### `GET /api/schedule` — scan schedule (cadence + blackout calendar; any authenticated user)
Cadence-driven plan across the approved inventory — web pentest 2×/yr · internal
infra VA 2×/yr · CIS config review 1×/yr — with freeze windows honoured (a due
date inside a blackout shifts to the day after it closes). **Planning view only;
launches nothing.**
```json
{ "today": "2026-06-02",
  "blackouts": [ {"start":"2026-03-25","end":"2026-04-10","reason":"FY-end change freeze"}, … ],
  "entries": [ {"assetId","asset","pipeline","scanType","cadence","cadenceDays","lastRun",
    "nextDue","overdue":bool,"dueSoon":bool,"shiftedByBlackout":bool,"blackoutReason":str|null,
    "daysUntil":int}, … ],
  "counts": { "total": N, "overdue": M, "dueSoon": K } }
```
`scanType` ∈ `web-pentest|infra-va|cis-review`. `lastRun` is derived from the most
recent *completed* scan of that asset (else a baseline scan is due now). Actually
running the plan on a timer is the Temporal/cron layer; any launched scan still
passes the human/scope gate.

### `POST /api/reports` — generate a report
Body: `{ "template": "audit|exec|asset|sla", "scope": "all|<assetId>", "formats": ["xlsx","docx","pdf"], "openPassword"?: "<str>", "ownerPassword"?: "<str>", "by": "<name>" }`
- `by` required (human actor) → 422.
- `formats` ⊆ `{xlsx,docx,pdf}`, non-empty → 422.
- **If `pdf` ∈ formats:** `openPassword` and `ownerPassword` are required and must
  **differ** (422) — the open password unlocks viewing; the owner password lifts
  the copy/modify/print restriction. (The dual-password PDF is the whole point.)
- Generates the requested formats from the current findings filtered by `scope`,
  using `orchestrator/reporting/`. Audited `REPORT_GENERATED`.
- **201** → `{ "reportId": "RPT-<opaque>", "generatedAt": "<iso>", "files": { "xlsx": "/api/reports/RPT-<opaque>/xlsx", … } }` (only requested formats).
- `reportId` is an **opaque, high-entropy capability token** (~192 bits), not a
  sequential id — the download is gated only by its unguessability **until the
  auth/RBAC slice lands**, after which download becomes owner/role-scoped.
  Reports expire after a TTL (≈1h).

### `GET /api/reports/{reportId}/{fmt}` — download
- Streams the file (`fmt` ∈ `xlsx|docx|pdf`) as an attachment with the right
  content-type and `Content-Disposition`. 404 if unknown/expired id/fmt.
- **Owner-scoped (v1):** requires an authenticated caller; the report's `owner`
  is the creator's `user.sub`. A non-owner gets **403 `forbidden`** unless they
  hold `admin`. The unguessable, TTL-bounded capability token is now defence in
  depth, no longer the sole gate — closing the earlier `TODO(auth)`.

## Client write methods (`frontend/api.js`)
`window.api.setFindingStatus(id, body)`, `.startScan(body)`,
`.requestException(body)`, `.audit(limit)`, `.generateReport(body)`,
`.reportDownloadUrl(reportId, fmt)`. Write methods **throw** on failure
(Error carries `.status` and `.data`); screens must show the error, not fake success.
