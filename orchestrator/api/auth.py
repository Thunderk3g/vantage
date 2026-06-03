"""Vantage authentication / RBAC core — AD/LDAP + OIDC.

Implements the **frozen** interface in ``docs/auth-contract.md`` (§0-§5). This
module is wired into ``main.py`` by another component; this file only provides
the exported surface:

  * ``Role``            — the role enum (wire-form string values).
  * ``User``            — frozen dataclass identity carried in the session.
  * ``get_current_user``— FastAPI dependency: signed session cookie (primary) or
                          ``Authorization: Bearer <id_token>`` (OIDC JWKS).
  * ``require_role``    — RBAC dependency factory (``admin`` is a wildcard).
  * ``session_actor``   — canonical audit actor string.
  * ``router``          — the ``/api/auth`` OIDC login/callback/logout/me router.

Design notes honoured for testability (§7):
  * Nothing touches the network or LDAP at import time. OIDC discovery, the JWKS
    fetch, the token exchange and the LDAP connection are all behind small
    private helpers (``_http_get_json``, ``_token_exchange``, ``_discover``,
    ``_ldap_connect``) that the self-test monkeypatches — no live tenant needed.
  * ``AUTH_REQUIRED`` (§0) switches dev (synthetic admin) vs prod (401) behaviour.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

# ---------------------------------------------------------------------------
# §1 Roles
# ---------------------------------------------------------------------------


class Role(str, Enum):
    """Single source of truth for roles. The *value* is the wire form used in the
    DB group_role_map, the session cookie, /api/auth/me and the console."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER_CISO = "approver_ciso"
    APPROVER_RMC = "approver_rmc"
    APPROVER_BOARD = "approver_board"
    ADMIN = "admin"


_ROLE_VALUES = {r.value for r in Role}


@dataclass(frozen=True)
class User:
    """Authenticated identity carried in the signed session / derived from a token."""

    sub: str            # stable IdP subject id (or "dev" in dev mode)
    name: str           # display name
    email: str
    roles: list[str]    # Role values
    groups: list[str]   # raw AD groups (for audit/debug)


# ---------------------------------------------------------------------------
# §5 Config (all read lazily, never cached at import — tests flip env per case)
# ---------------------------------------------------------------------------

SESSION_COOKIE = "vantage_session"
OIDC_TX_COOKIE = "vantage_oidc_tx"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _auth_required() -> bool:
    return _env("AUTH_REQUIRED").strip().lower() in ("1", "true", "yes", "on")


def _session_secret() -> str:
    # In dev a fixed fallback keeps the offline console usable; prod MUST set it.
    # Fail closed: when AUTH_REQUIRED is on, refuse to sign/verify with the known
    # insecure dev key (that would make sessions forgeable). A loud 500 on a
    # misconfigured prod deploy is the correct, safe failure.
    secret = _env("SESSION_SECRET")
    if secret:
        return secret
    if _auth_required():
        raise RuntimeError(
            "SESSION_SECRET must be set when AUTH_REQUIRED is enabled "
            "(refusing to sign sessions with the insecure dev fallback)"
        )
    return "vantage-dev-insecure-session-secret"


def _session_max_age() -> int:
    try:
        return int(_env("SESSION_MAX_AGE", "28800"))
    except ValueError:
        return 28800


def _cookie_secure() -> bool:
    return _env("SESSION_COOKIE_SECURE").strip().lower() in ("1", "true", "yes", "on")


def _console_origin() -> str:
    return _env("CONSOLE_ORIGIN", "http://localhost:8137")


DEV_USER = User(
    sub="dev",
    name="Vantage Dev",
    email="dev@vantage.local",
    roles=[Role.ADMIN.value],
    groups=[],
)


# ---------------------------------------------------------------------------
# Contract error helpers — {"error","detail"} bodies (§2)
# ---------------------------------------------------------------------------


def _unauthenticated(detail: str = "authentication required") -> HTTPException:
    return HTTPException(status_code=401, detail={"error": "unauthenticated", "detail": detail})


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=403, detail={"error": "forbidden", "detail": detail})


# ---------------------------------------------------------------------------
# Session cookie sign / verify (itsdangerous, key=SESSION_SECRET) (§2 cookie)
# ---------------------------------------------------------------------------


def _session_serializer() -> URLSafeTimedSerializer:
    # Salt namespaces the token so an OIDC-tx cookie can never be replayed as a
    # session and vice-versa even under the same secret.
    return URLSafeTimedSerializer(_session_secret(), salt="vantage-session")


def _oidc_tx_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_session_secret(), salt="vantage-oidc-tx")


def mint_session(user: User, *, max_age: Optional[int] = None) -> str:
    """Sign a session token over {sub,name,email,roles,groups,exp}."""
    ttl = max_age if max_age is not None else _session_max_age()
    payload = {
        "sub": user.sub,
        "name": user.name,
        "email": user.email,
        "roles": list(user.roles),
        "groups": list(user.groups),
        "exp": int(time.time()) + ttl,
    }
    return _session_serializer().dumps(payload)


def _user_from_session(token: str) -> Optional[User]:
    """Verify+decode a session token → User, or None if unsigned/expired/invalid.

    We enforce *both* the itsdangerous max_age (cookie age) and the embedded
    ``exp`` so a forged/replayed payload cannot outlive its stated expiry.
    """
    try:
        payload = _session_serializer().loads(token, max_age=_session_max_age())
    except (BadSignature, SignatureExpired, Exception):  # noqa: BLE001 — any decode failure = no session
        return None
    if not isinstance(payload, dict):
        return None
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        return None
    try:
        return User(
            sub=str(payload["sub"]),
            name=str(payload.get("name", "")),
            email=str(payload.get("email", "")),
            roles=[str(r) for r in payload.get("roles", [])],
            groups=[str(g) for g in payload.get("groups", [])],
        )
    except (KeyError, TypeError):
        return None


# ---------------------------------------------------------------------------
# §4 / OIDC indirection points — monkeypatched in tests, lazy at runtime
# ---------------------------------------------------------------------------

# A single module-level client so connection pooling is shared; created lazily.
_HTTP_CLIENT: Optional[httpx.Client] = None


def _client() -> httpx.Client:
    global _HTTP_CLIENT
    if _HTTP_CLIENT is None:
        _HTTP_CLIENT = httpx.Client(timeout=10.0)
    return _HTTP_CLIENT


def _http_get_json(url: str) -> dict:
    """GET a URL and return parsed JSON. Single indirection point for discovery
    and JWKS fetch so the self-test can monkeypatch it (no network)."""
    resp = _client().get(url)
    resp.raise_for_status()
    return resp.json()


def _token_exchange(token_endpoint: str, data: dict) -> dict:
    """POST the authorization-code exchange to the IdP token endpoint. Separate
    indirection point so tests can inject a fake token response."""
    resp = _client().post(token_endpoint, data=data)
    resp.raise_for_status()
    return resp.json()


def _discover() -> dict:
    """OIDC discovery document for ``OIDC_ISSUER``. Lazy — never at import."""
    issuer = _env("OIDC_ISSUER").rstrip("/")
    if not issuer:
        raise RuntimeError("OIDC_ISSUER is not configured")
    return _http_get_json(issuer + "/.well-known/openid-configuration")


def _jwks() -> dict:
    """Fetch the IdP JWKS (RS256 signing keys)."""
    conf = _discover()
    jwks_uri = conf.get("jwks_uri")
    if not jwks_uri:
        raise RuntimeError("discovery document has no jwks_uri")
    return _http_get_json(jwks_uri)


def validate_id_token(id_token: str, *, nonce: Optional[str] = None) -> dict:
    """Validate an OIDC id_token (RS256) against the IdP JWKS and claims.

    Checks signature, ``iss`` == OIDC_ISSUER, ``aud`` contains OIDC_CLIENT_ID,
    ``exp`` not past, and (when supplied) ``nonce`` match. Returns the verified
    claims dict. Raises on any failure. Uses authlib's JOSE for JWKS validation.
    """
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from authlib.jose import JsonWebToken, JsonWebKey

    issuer = _env("OIDC_ISSUER").rstrip("/")
    client_id = _env("OIDC_CLIENT_ID")

    jwks_data = _jwks()
    key_set = JsonWebKey.import_key_set(jwks_data)

    claims_options = {
        "iss": {"essential": True, "value": issuer} if issuer else {"essential": True},
        "exp": {"essential": True},
    }
    if client_id:
        claims_options["aud"] = {"essential": True, "values": [client_id]}

    jwt = JsonWebToken(["RS256"])
    claims = jwt.decode(
        id_token,
        key=key_set,
        claims_options=claims_options,
    )
    claims.validate(now=int(time.time()), leeway=60)  # validates exp/iss/aud per options

    if nonce is not None and claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")

    return dict(claims)


# ---------------------------------------------------------------------------
# §1 / §4 group → role mapping
# ---------------------------------------------------------------------------


def _group_role_map() -> dict[str, str]:
    raw = _env("VANTAGE_GROUP_ROLE_MAP")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def _first_rdn_value(group: str) -> Optional[str]:
    """For a DN like ``CN=SEC-AppSec,OU=...`` return ``SEC-AppSec``; else None."""
    head = group.split(",", 1)[0].strip()
    if "=" in head:
        return head.split("=", 1)[1].strip()
    return None


def map_groups_to_roles(groups: list[str]) -> list[str]:
    """Map raw AD groups → a de-duplicated list of Role values.

    Each configured map entry is matched case-insensitively against the group's
    full string AND against the value of its first ``CN=...`` RDN (so both the
    bare name and the DN form resolve). Unknown/invalid mapped values are
    ignored. With **no** match the user gets ``["viewer"]`` — least privilege,
    never empty, never admin by default (§1)."""
    mapping = _group_role_map()
    # Normalise the map for case-insensitive lookup by full string and by CN.
    norm: dict[str, str] = {}
    for key, role in mapping.items():
        if role not in _ROLE_VALUES:
            continue
        norm[key.strip().lower()] = role
        cn = _first_rdn_value(key)
        if cn:
            norm.setdefault(cn.strip().lower(), role)

    roles: list[str] = []
    for g in groups or []:
        candidates = [g.strip().lower()]
        cn = _first_rdn_value(g)
        if cn:
            candidates.append(cn.strip().lower())
        for c in candidates:
            role = norm.get(c)
            if role and role not in roles:
                roles.append(role)
                break

    if not roles:
        return [Role.VIEWER.value]
    return roles


# ---------------------------------------------------------------------------
# §4 LDAP group resolution (optional, fail-soft)
# ---------------------------------------------------------------------------

# An LDAP filter value is attacker-influenceable (the email/UPN comes from the
# IdP claims, which a user may control). Reject anything carrying LDAP/DN
# metacharacters BEFORE it ever reaches a filter — defence in depth on top of
# escaping. Must contain exactly one '@' and no , \ * ( ) NUL.
_LDAP_SAFE_EMAIL_RE = re.compile(r"^[^,\\*()\x00]+@[^,\\*()\x00]+$")


def _ldap_connect():
    """Bind a service connection to LDAP_URL. Private so tests can monkeypatch
    it (no live directory). Returns an ``ldap3.Connection`` (already bound)."""
    import ldap3

    server = ldap3.Server(_env("LDAP_URL"), get_info=ldap3.NONE)
    conn = ldap3.Connection(
        server,
        user=_env("LDAP_BIND_DN") or None,
        password=_env("LDAP_BIND_PASSWORD") or None,
        auto_bind=True,
    )
    return conn


def resolve_groups_via_ldap(email: str) -> list[str]:
    """Resolve a user's ``memberOf`` groups over LDAP. Returns [] on any failure
    (never crashes login). Only meaningful when ``LDAP_URL`` is set."""
    if not _env("LDAP_URL").strip():
        return []
    # Validate the shape first: bail (no search) on anything with LDAP/DN
    # metacharacters, so a crafted IdP email can never alter the filter tree.
    if not email or not _LDAP_SAFE_EMAIL_RE.match(email):
        return []
    try:
        from ldap3.utils.conv import escape_filter_chars

        conn = _ldap_connect()
        try:
            # LDAP_USER_FILTER is trusted operator config; the interpolated
            # `email` is NOT — escape it (RFC 4515) before formatting.
            user_filter = _env("LDAP_USER_FILTER") or "(userPrincipalName={email})"
            search_filter = user_filter.format(email=escape_filter_chars(email))
            conn.search(
                search_base=_env("LDAP_USER_BASE"),
                search_filter=search_filter,
                attributes=["memberOf"],
            )
            groups: list[str] = []
            for entry in getattr(conn, "entries", []) or []:
                member_of = getattr(entry, "memberOf", None)
                values = getattr(member_of, "values", None)
                if values:
                    groups.extend(str(v) for v in values)
            return groups
        finally:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001 — LDAP must never break login
        return []


def _resolve_roles(claims: dict) -> tuple[list[str], list[str]]:
    """From validated id_token claims, derive (groups, roles). Uses the ``groups``
    claim if present, else LDAP (§4)."""
    groups = claims.get("groups")
    if isinstance(groups, list) and groups:
        groups = [str(g) for g in groups]
    else:
        email = str(claims.get("email") or claims.get("preferred_username") or "")
        groups = resolve_groups_via_ldap(email) if email else []
    roles = map_groups_to_roles(groups)
    return groups, roles


def _user_from_claims(claims: dict) -> User:
    groups, roles = _resolve_roles(claims)
    return User(
        sub=str(claims.get("sub", "")),
        name=str(claims.get("name") or claims.get("preferred_username") or ""),
        email=str(claims.get("email") or ""),
        roles=roles,
        groups=groups,
    )


# ---------------------------------------------------------------------------
# §2 get_current_user / require_role / session_actor
# ---------------------------------------------------------------------------


def get_current_user(request: Request) -> User:
    """FastAPI dependency. Resolve the caller's identity.

    Order: signed ``vantage_session`` cookie (primary) → ``Authorization: Bearer
    <id_token>`` (API clients, OIDC-validated). Dev mode → synthetic admin when
    none; prod mode → 401 when none.
    """
    # 1) Signed session cookie (primary).
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        user = _user_from_session(cookie)
        if user is not None:
            return user

    # 2) Bearer id_token (API clients).
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            claims = validate_id_token(token)
            return _user_from_claims(claims)
        except Exception:  # noqa: BLE001 — invalid token = no identity
            pass

    # 3) No valid identity.
    if _auth_required():
        raise _unauthenticated("no valid session or bearer token")
    return DEV_USER


def require_role(*roles: Role) -> Callable[..., User]:
    """Return a FastAPI dependency asserting the caller holds at least one of
    ``roles`` (``admin`` is a wildcard). Depends on ``get_current_user`` so a 401
    (unauthenticated) always wins over a 403 (forbidden)."""
    wanted = {r.value if isinstance(r, Role) else str(r) for r in roles}

    def _dep(request: Request) -> User:
        user = get_current_user(request)  # 401 fires here first if unauthenticated
        held = set(user.roles)
        if Role.ADMIN.value in held or (wanted & held):
            return user
        raise _forbidden("requires one of: " + ", ".join(sorted(wanted) or ["<none>"]))

    return _dep


def session_actor(user: User) -> str:
    """Canonical audit actor string, e.g. ``Vantage Dev <dev@vantage.local>``."""
    return f"{user.name} <{user.email}>"


# ---------------------------------------------------------------------------
# §2 OIDC router — /api/auth/{login,callback,logout,me}
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _pkce_pair() -> tuple[str, str]:
    """(code_verifier, code_challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _safe_next(next_param: Optional[str]) -> str:
    """Only allow same-origin relative paths as the post-login redirect target;
    fall back to the console origin otherwise (open-redirect guard).

    Must be a path starting with a single '/'. We reject:
      * absolute / protocol-relative URLs ('//host', 'http://...');
      * backslashes — a browser normalizes '\\' to '/', so '/\\evil.com' would
        resolve to '//evil.com' (off-origin); and
      * anything that parses to a non-empty network location.
    """
    if not next_param or not next_param.startswith("/") or next_param.startswith("//"):
        return _console_origin()
    if "\\" in next_param or "\t" in next_param or "\n" in next_param or "\r" in next_param:
        return _console_origin()
    # Defence in depth: after normalization it must have no scheme/host.
    parsed = urlsplit(next_param)
    if parsed.scheme or parsed.netloc:
        return _console_origin()
    return next_param


def _set_cookie(resp: Response, name: str, value: str, max_age: int) -> None:
    resp.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(),
        path="/",
    )


@router.get("/login")
def login(request: Request):
    """Begin the OIDC Authorization-Code + PKCE flow. In dev mode short-circuits
    by minting the dev session and redirecting to ``next``."""
    next_target = _safe_next(request.query_params.get("next"))

    if not _auth_required():
        # Dev short-circuit: mint dev session, go straight to next.
        resp = RedirectResponse(url=next_target, status_code=302)
        _set_cookie(resp, SESSION_COOKIE, mint_session(DEV_USER), _session_max_age())
        return resp

    try:
        conf = _discover()
        authorize_endpoint = conf["authorization_endpoint"]
    except Exception:  # noqa: BLE001
        raise _unauthenticated("OIDC discovery failed")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()

    scopes = _env("OIDC_SCOPES") or "openid profile email groups"
    params = {
        "response_type": "code",
        "client_id": _env("OIDC_CLIENT_ID"),
        "redirect_uri": _env("OIDC_REDIRECT_URI"),
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    authorize_url = authorize_endpoint + ("&" if "?" in authorize_endpoint else "?") + urlencode(params)

    tx = _oidc_tx_serializer().dumps(
        {"state": state, "nonce": nonce, "code_verifier": verifier, "next": next_target}
    )
    resp = RedirectResponse(url=authorize_url, status_code=302)
    _set_cookie(resp, OIDC_TX_COOKIE, tx, 600)  # 10-min transaction window
    return resp


@router.get("/callback")
def callback(request: Request):
    """Complete the OIDC flow: verify state, exchange code (PKCE), validate the
    id_token, map groups→roles, mint the session. Any failure → 401."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    tx_cookie = request.cookies.get(OIDC_TX_COOKIE)

    if not code or not state or not tx_cookie:
        raise _unauthenticated("missing code/state/transaction")

    try:
        tx = _oidc_tx_serializer().loads(tx_cookie, max_age=600)
    except Exception:  # noqa: BLE001
        raise _unauthenticated("invalid or expired transaction")

    if not secrets.compare_digest(str(tx.get("state", "")), str(state)):
        raise _unauthenticated("state mismatch")

    try:
        conf = _discover()
        token_endpoint = conf["token_endpoint"]
        token_resp = _token_exchange(
            token_endpoint,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _env("OIDC_REDIRECT_URI"),
                "client_id": _env("OIDC_CLIENT_ID"),
                "client_secret": _env("OIDC_CLIENT_SECRET"),
                "code_verifier": tx.get("code_verifier", ""),
            },
        )
        id_token = token_resp.get("id_token")
        if not id_token:
            raise ValueError("no id_token in token response")
        claims = validate_id_token(id_token, nonce=tx.get("nonce"))
        user = _user_from_claims(claims)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001
        raise _unauthenticated("OIDC callback failed")

    next_target = _safe_next(tx.get("next"))
    resp = RedirectResponse(url=next_target, status_code=302)
    _set_cookie(resp, SESSION_COOKIE, mint_session(user), _session_max_age())
    # Clear the one-shot transaction cookie.
    resp.delete_cookie(OIDC_TX_COOKIE, path="/")
    return resp


@router.post("/logout")
def logout():
    """Clear the session cookie (204)."""
    resp = Response(status_code=204)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/me")
def me(request: Request):
    """Identity of the current caller: ``{"user": User}``. 200 with the dev user
    in dev mode; 401 when unauthenticated in prod mode."""
    user = get_current_user(request)  # raises 401 in prod when unauthenticated
    return JSONResponse(content={"user": asdict(user)})
