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
