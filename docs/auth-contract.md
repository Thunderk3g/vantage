# Vantage auth contract v1 — AD/LDAP + OIDC (frozen)

This is the **frozen interface** for the authentication / RBAC slice. The backend
auth core, the API wiring, the console, and the DB schema all implement to *this*
document. Don't change a signature or a role name without updating this file.

Identity provider: **OIDC** (Authorization Code + PKCE) federated to **Active
Directory** (Entra ID / on-prem AD via ADFS), with optional **LDAP** group
resolution. The console is a browser SPA at `http://localhost:8137`; the API is at
`http://localhost:8138`.

---

## 0. Reference-build switch — `AUTH_REQUIRED`

The real OIDC/LDAP code path is always present and is exercised when
`AUTH_REQUIRED=true`. The **default reference/dev build runs with
`AUTH_REQUIRED` unset/false** so the offline console and CI smoke tests keep
working **without a live tenant**.

- `AUTH_REQUIRED` **false/unset (dev):** `get_current_user` returns a synthetic
  user `dev@vantage.local` (name `"Vantage Dev"`) with role **ADMIN** when there
  is no valid session. Every write is still attributed **server-side** to this
  user — the client can no longer choose the actor.
- `AUTH_REQUIRED` **true (prod):** a request with no valid session/bearer is
  rejected **401**. Roles come from the IdP; the dev user is never minted.

The security property we are buying — **`actor` is derived server-side, never
from the request body** — holds in *both* modes.

---

## 1. Roles (the single source of truth)

`orchestrator/api/auth.py :: class Role(str, Enum)` — value strings are the wire
form used everywhere (DB `group_role_map`, session cookie, `/api/auth/me`, the
console):

| `Role` value        | Who                         | May …                                                              |
|---------------------|-----------------------------|--------------------------------------------------------------------|
| `viewer`            | Read-only auditor           | read every GET; **no** mutations                                   |
| `analyst`           | AppSec engineer / triager   | reads + request scans + change finding status + request exceptions + generate reports |
| `approver_ciso`     | CISO                        | reads + generate reports (+ approve ≤3-mo exceptions — future)     |
| `approver_rmc`      | Risk Mgmt Committee         | reads + generate reports (+ approve >3–12-mo exceptions — future)  |
| `approver_board`    | Board                       | reads + generate reports (+ approve >12-mo exceptions — future)    |
| `admin`             | Vantage administrator       | everything; implicitly satisfies every `require_role` check        |

`admin` is a wildcard: any `require_role(...)` check passes if the user has
`admin`. A user may hold multiple roles.

### AD-group → role mapping
Configured by env `VANTAGE_GROUP_ROLE_MAP` — a JSON object mapping an AD group
(group name or DN, matched case-insensitively) to a `Role` value, e.g.:
```json
{"CN=SEC-AppSec,OU=Groups,DC=corp,DC=bajajlife,DC=com": "analyst",
 "SEC-CISO": "approver_ciso", "SEC-Auditors": "viewer", "SEC-VantageAdmins": "admin"}
```
Group claims come from the OIDC `groups` claim when present; otherwise they are
resolved over **LDAP** (see §4). A user with **no** mapped group gets `viewer`
(least privilege) — never empty/none, never admin.

---

## 2. `auth.py` — exported interface (frozen)

```python
class Role(str, Enum): VIEWER="viewer"; ANALYST="analyst"; APPROVER_CISO="approver_ciso"
                       APPROVER_RMC="approver_rmc"; APPROVER_BOARD="approver_board"; ADMIN="admin"

@dataclass(frozen=True)
class User:
    sub: str            # stable IdP subject id (or "dev" in dev mode)
    name: str           # display name
    email: str
    roles: list[str]    # Role values
    groups: list[str]   # raw AD groups (for audit/debug)

# FastAPI dependency. Returns the authenticated User from the signed session
# cookie (primary) or an `Authorization: Bearer <id_token>` (API clients,
# validated via OIDC JWKS). In dev mode (AUTH_REQUIRED off) returns the synthetic
# ADMIN dev user when no session. In prod mode raises HTTPException(401) when
# there is no valid session/token.
def get_current_user(request: Request) -> User: ...

# Returns a FastAPI dependency that calls get_current_user and asserts the user
# holds at least one of `roles` (ADMIN always passes). Else HTTPException(403,
# {"error":"forbidden","detail":...}). 401 still wins when unauthenticated.
def require_role(*roles: Role) -> Callable[..., User]: ...

# Canonical audit actor string for a user (used as the `actor`/`by` in audits).
def session_actor(user: User) -> str: ...      # e.g. "Vantage Dev <dev@vantage.local>"

# The OIDC router, mounted by main.py at import.
router: APIRouter   # prefix="/api/auth"
```

`get_current_user` and `require_role` raise the **contract error body**
`{"error","detail"}` (401 `unauthenticated`, 403 `forbidden`) — same shape as the
rest of the API.

### Auth endpoints (on `router`, prefix `/api/auth`)
- `GET /api/auth/login?next=<path>` → 302 to the IdP authorize URL. Generates
  `state`, `nonce`, PKCE `code_verifier`; stashes them in a short-lived **signed,
  httpOnly** `vantage_oidc_tx` cookie. In dev mode (`AUTH_REQUIRED` off) it may
  short-circuit by minting the dev session and redirecting to `next`.
- `GET /api/auth/callback?code=&state=` → verify `state`, exchange `code` at the
  token endpoint (PKCE), **validate the `id_token`** (RS256 against the IdP JWKS,
  `iss`/`aud`/`exp`/`nonce`), resolve groups→roles, mint the session cookie,
  302 to the original `next` (default the console origin). On any failure: 401.
- `POST /api/auth/logout` → clear the session cookie (204). (Optionally redirect
  to the OIDC end-session endpoint when configured.)
- `GET /api/auth/me` → `{ "user": User }` for the current caller; **200** with the
  dev user in dev mode, **401** when unauthenticated in prod mode. The console
  calls this on load to learn who it is and what it may do.

### Session cookie
Name `vantage_session`; httpOnly; `SameSite=Lax`; `Secure` when
`SESSION_COOKIE_SECURE=true` (prod). Value is **signed** (itsdangerous, key
`SESSION_SECRET`) over `{sub,name,email,roles,groups,exp}` with a max age of
`SESSION_MAX_AGE` seconds (default 8h). The server **never trusts an unsigned or
expired cookie**. CORS already sets `allow_credentials=true` for the console
origin; the console must send `credentials:"include"`.

---

## 3. RBAC matrix — applied in `main.py`

| Endpoint                                   | Dependency                                                        |
|--------------------------------------------|------------------------------------------------------------------|
| all `GET /api/*` reads + `/api/audit`      | `Depends(get_current_user)` (any authenticated; viewer+)         |
| `PATCH /api/findings/{id}/status`          | `Depends(require_role(Role.ANALYST))`                            |
| `POST /api/scans`                          | `Depends(require_role(Role.ANALYST))` (scope gate still applies) |
| `POST /api/exceptions`                     | `Depends(require_role(Role.ANALYST))`                            |
| `POST /api/reports`                        | `Depends(require_role(Role.ANALYST, Role.APPROVER_CISO, Role.APPROVER_RMC, Role.APPROVER_BOARD))` |
| `GET /api/reports/{id}/{fmt}` (download)   | `Depends(get_current_user)` **+** owner check: `entry["owner"]==user.sub` **or** `admin`, else **403** |

**Actor derivation:** mutation handlers **no longer read `actor`/`by` from the
request body.** They use `session_actor(user)`. The body fields are ignored if
present (kept optional in the schema for one release, then removed). The scope
gate on `POST /api/scans` is unchanged and still runs **before** anything else;
its denial audit uses the session actor.

**Report ownership:** `_REPORTS[id]["owner"]` is set to `user.sub` (not a
client string). Download enforces it. This closes the `TODO(auth)` capability-
token caveat: the unguessable id is now *defense in depth*, not the only gate.

---

## 4. LDAP (group resolution) — `auth.py`

When the OIDC `id_token` carries no `groups` claim (common with on-prem AD unless
configured), resolve them over LDAP with `ldap3`:
- bind with service creds `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` to `LDAP_URL`
  (ldaps://…), search `LDAP_USER_BASE` for the user (`LDAP_USER_FILTER`, default
  `(userPrincipalName={email})`), read `memberOf`. Lazily; cache per request.
- LDAP is **optional**: if `LDAP_URL` is unset, rely solely on the `groups` claim.
- Credentials come only from env/vault, never logged.

---

## 5. Config (env)

| Var | Meaning |
|-----|---------|
| `AUTH_REQUIRED` | `true` enforces real auth; default off (dev) |
| `OIDC_ISSUER` | IdP issuer URL (discovery at `/.well-known/openid-configuration`) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | confidential client creds |
| `OIDC_REDIRECT_URI` | must equal the registered callback (`…/api/auth/callback`) |
| `OIDC_SCOPES` | default `openid profile email groups` |
| `SESSION_SECRET` | signing key for the session cookie (required when AUTH_REQUIRED) |
| `SESSION_MAX_AGE` | session lifetime seconds (default 28800 = 8h) |
| `SESSION_COOKIE_SECURE` | `true` in prod (HTTPS) |
| `VANTAGE_GROUP_ROLE_MAP` | JSON AD-group → Role map (§1) |
| `CONSOLE_ORIGIN` | console URL for post-login redirect (default `http://localhost:8137`) |
| `LDAP_URL` / `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` / `LDAP_USER_BASE` / `LDAP_USER_FILTER` | optional LDAP group resolution (§4) |

---

## 6. Console contract (`frontend/`)

- `api.js`: all `fetch` calls send `credentials:"include"`. New methods:
  `api.me()` → `{user}|null`, `api.loginUrl(next)` → string, `api.logout()`.
  Write methods **stop sending `actor`/`by`** in the body.
- `app.jsx`: on load, `api.me()`; show the **real** user (name + roles) in the
  header instead of the hardcoded "AM"/role-switcher. The role switcher becomes a
  read-only identity/role display (admins may still impersonate for *view* only,
  but the server enforces real roles regardless). Controls the role can't use are
  hidden/disabled per §3. A "Sign in" affordance appears when `me()` is 401.
- Screens drop the `const BY = "A. Mehta"` placeholders; they call the write
  methods without an actor (server attributes it).

> The console's role display is advisory; **enforcement is entirely server-side**
> (`require_role`). A user editing client state cannot escalate.

---

## 7. What this build verifies vs. needs a tenant

- **Verified here (no tenant):** id_token validation against a self-signed mock
  JWKS, group→role mapping, session sign/verify round-trip, `require_role`
  allow/deny, owner-scoped download, dev-mode synthetic actor. (`api/test_auth.py`.)
- **Needs a real IdP + browser to fully exercise:** the interactive redirect, real
  AD `groups` claims / LDAP `memberOf`, end-session. These are config + deploy.
