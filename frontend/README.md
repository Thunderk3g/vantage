# Vantage — Web Console (frontend)

The **Vulnerability Console** for Vantage: a calm, auditable, role-aware UI for
triage, SLA tracking, and reporting. Implemented from the Claude Design handoff
("Sentinel — Vulnerability Console") and rebranded to Vantage.

> Detection, triage, and tracking console — it surfaces findings and SLAs.
> It does **not** exploit or auto-fix. Validation stays human-gated.

## Stack

Zero-build React 18 + Babel-standalone (loaded from CDN), plain CSS design
tokens (oklch), IBM Plex Sans / IBM Plex Mono. No bundler — every screen is a
`.jsx` file loaded by `index.html`. This keeps the reference UI dependency-free
and trivially serveable; it can be migrated to a Vite/Next build later without
changing the visual layer.

## Screens

| Route | Screen | Notes |
|---|---|---|
| `dashboard` | Dashboard | Severity donut, 8-week trend, KPI row, overdue/escalating, live scans; CISO role adds a per-asset risk rollup. |
| `scan` | Start a scan | Approved-inventory targets only (no free text) → pipeline → type → gray-box auth context. |
| `findings` | Findings | Filter bar, sortable columns, selection + bulk actions, empty state. |
| `detail` | Finding detail | Evidence, OWASP/SANS/CIS mapping, status stepper, SLA countdown, escalation staircase, history. |
| `sla` | SLA & escalation | Day 0 → 2 → 4 → 8–10 → 15–20 pipeline + per-finding staircase. |
| `exception` | Exceptions | Approval tier resolves from duration (CISO ≤3mo · RMC >3–12mo · Board >12mo). |
| `reports` | Reports | Template + scope + format (Excel/Word/PDF) with the **PDF password-protection step**. |
| `system` | Design system | Severity scale (color **+ shape + letter**), palette, type, spacing, component specs. |

Header has a **role switcher** (Analyst / Team Lead / CISO) and a **Tweaks**
panel (accent, density, contrast).

## Run

Babel fetches the `.jsx` files, so it must be served over HTTP (not `file://`):

```bash
cd frontend
python -m http.server 8137
# open http://localhost:8137
```

Verify all modules parse (CI-friendly, no browser):

```bash
npm install --no-save @babel/standalone
node frontend/verify-jsx.js
```

## Data & backend wiring

Currently driven by **mock data** in `data.js` (insurance-flavored, "today"
pinned to 2026-06-01 for stable countdowns). It maps 1:1 onto the backend model
in `db/schema.sql` — when the API lands, replace the `window.*` data globals with
`fetch()` calls to the orchestrator:

| UI global | Backend source |
|---|---|
| `window.FINDINGS` | `GET /findings` (view `v_open_findings_sla`) |
| `window.ASSETS` | `GET /assets` (approved inventory) |
| `window.SCANS` | `GET /scans` |
| `window.EXCEPTIONS` | `GET /exceptions` |
| `SLA_DAYS` / deadlines | computed server-side by the `slas` trigger |

> **SLA reconciliation:** `SLA_DAYS` was changed from the prototype's 30/60/60/90
> to **Critical/High = 30, Medium/Low = 60** to match `schema.sql` and the IRDAI
> mandate, so on-screen countdowns equal what the backend computes.

## Files

```
index.html        CDN React + Babel; loads everything in order.
styles.css        Design tokens + all component styles.
data.js           Mock data + SLA/escalation logic + helpers (window globals).
icons.jsx         Line-icon set.
components.jsx    Severity badge, SLA chip, status pill, stepper, donut, trend…
tweaks-panel.jsx  Accent/density/contrast tweak panel.
app.jsx           Shell: sidebar nav, header, role switcher, router.
screens/*.jsx     One file per screen.
verify-jsx.js     Dev syntax check (Babel transform of every module).
```
