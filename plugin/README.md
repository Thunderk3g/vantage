# Vantage — Claude Code plugin

An MCP server that lets Claude drive the **Vantage** vulnerability console
(`docs/api-contract.md`) from a chat: read the finding register, check a target
against the approved-scope inventory, request *authorized* scans, diff scans /
verify closure, run the human-gated triage / exception / escalation workflows,
and generate dual-password reports.

> **Scan-and-report only.** There is **no** exploit/attack tool here. The
> platform's hard boundaries live on the **server**, so this plugin can't bypass
> them:
> - `request_scan` calls the API's scope gate, which **fails closed** (403
>   `out_of_scope`) for any asset not in the HOD-approved inventory.
> - mutations are **role-gated + human-gated** server-side; the actor is derived
>   from the authenticated session, not from this client.
> - `confirm_false_positive` / exception approval are the only paths to
>   `confirmed_fp` / `risk_accepted` — enforced by the API.

## Plugin surfaces

| Surface | What it adds |
|---------|-------------|
| **MCP server** (`mcp/`) | 16 tools wrapping the API (below). |
| **Scope-guard hook** (`hooks/`) | A `PreToolUse` hook that **blocks** any `Bash` scanner/recon command (nmap, nikto, nuclei, sqlmap, …) or `request_scan` aimed at a host **not** in the approved inventory — fail-closed when scope can't be confirmed; `WebFetch` to an external host becomes "ask". Makes "never touch an unauthorized target" something the agent itself can't violate. |
| **Slash commands** (`commands/`) | `/vantage-triage`, `/vantage-scope-check`, `/vantage-sla`, `/vantage-report`, `/vantage-scan-diff`. |
| **Skill** (`skills/vuln-triage/`) | The governance playbook: CVSS→severity bands, IRDAI SLAs (Crit/High 30d · Med/Low 60d), the Day 0→18 escalation staircase, exception tiers (CISO/RMC/Board), and the FP / risk-acceptance state rules. |

> The hook is defense-in-depth on top of the server scope gate. Its allowlist
> is `hooks/approved_scope.txt` (seeded with the reference inventory) unioned with
> a live `GET /api/assets`; edit the file or point at your real API to set scope.

## Tools

| Read | Write (server-gated) |
|------|----------------------|
| `dashboard`, `list_findings`, `get_finding`, `list_assets`, `scope_check`, `scan_diff`, `schedule`, `escalations`, `audit` | `request_scan` (scope-gated), `set_finding_status`, `request_retest`, `confirm_false_positive`, `request_exception`, `decide_exception`, `generate_report` |

`scope_check(target)` mirrors the server scope gate so you can confirm a target
is authorized **before** requesting a scan — e.g. an external site that isn't in
the approved inventory comes back `inScope: false` with a "would be refused"
note, never a scan.

## Install

The plugin runs the MCP server with `python ${CLAUDE_PLUGIN_ROOT}/mcp/vantage_server.py`.

1. Install the runtime deps (Python 3.10+):
   ```bash
   pip install -r plugin/mcp/requirements.txt   # mcp, httpx
   ```
2. Start the Vantage API (e.g. `docker compose up` → API on `:8138`, or
   `uvicorn orchestrator.api.main:app --port 8138`).
3. Add the plugin to Claude Code (point it at this `plugin/` directory, or install
   from the marketplace once published). The manifest is `.claude-plugin/plugin.json`.

## Config (env, set in the manifest's `mcpServers.vantage.env` or your shell)

| Var | Default | Meaning |
|-----|---------|---------|
| `VANTAGE_API_BASE` | `http://localhost:8138` | Vantage API base URL |
| `VANTAGE_BEARER` | *(unset)* | Bearer **id_token** for a production API with `AUTH_REQUIRED=true`. Omit for the local/dev reference build (the API treats unauthenticated callers as a dev admin). |

## Example prompts

- *"Show me the Vantage dashboard and the top 5 overdue criticals."*
- *"Is `portal.lifeco.internal` in scope? If so, queue a gray-box web scan with min-privilege auth."*
- *"Diff the last two scans and tell me which findings are closure-verified."*
- *"Generate an `sla` report for AST-CLAIMS as xlsx + a dual-password pdf."*

## Test

```bash
python plugin/mcp/test_server_smoke.py   # mocks the API; no network/live server
```
Verifies tool registration, filter forwarding, the scope-gate 403 passthrough,
`scope_check`, and graceful handling when the API is unreachable.
