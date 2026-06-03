"""
Runnable self-test for the Vantage auth core (``api/auth.py``).

Plain asserts + a __main__ block — no pytest, no live IdP / LDAP / network. Run:

    python orchestrator/api/test_auth.py
    python -m api.test_auth          # with orchestrator/ on sys.path

Covers the behaviours the auth contract (§7) says are verifiable offline:
  1. a valid id_token (groups:["SEC-AppSec"]) validates against a self-signed
     mock JWKS and maps to roles ["analyst"];
  2. an id_token signed by a DIFFERENT key is rejected;
  3. map_groups_to_roles: [] -> ["viewer"]; admin group -> ["admin"]; CN-DN form;
  4. session cookie sign/verify round-trip via a fake Request (+ tamper falls
     back in dev / 401 in prod);
  5. require_role allow/deny (viewer->403, analyst->pass, admin->any);
  6. dev mode synthetic admin vs prod mode 401 on a cookieless request.

OIDC is mocked with a self-signed RSA keypair (cryptography) → a fake id_token
(authlib JOSE, RS256, with a ``kid``) + a matching local JWKS dict; we monkeypatch
``auth._jwks`` so no discovery/network happens. LDAP is never reached (the tests
that map roles always carry a ``groups`` claim), and ``LDAP_URL`` is left unset.
"""
from __future__ import annotations

import json
import os
import sys
import time
import warnings

warnings.simplefilter("ignore")  # quiet deprecation noise (authlib.jose) where honoured

# Make ``from api.auth import ...`` work when run as a script from the repo root
# (insert the ``orchestrator`` dir on sys.path; ``api`` has an __init__.py).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # orchestrator/

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from authlib.jose import JsonWebKey, JsonWebToken  # noqa: E402

from api.auth import (  # noqa: E402
    DEV_USER,
    Role,
    User,
    get_current_user,
    map_groups_to_roles,
    mint_session,
    require_role,
    resolve_groups_via_ldap,
    session_actor,
    validate_id_token,
)
import api.auth as auth  # noqa: E402

_ORIG_LDAP_CONNECT = auth._ldap_connect  # restored after the injection-guard test

ISSUER = "https://idp.vantage.test"
CLIENT_ID = "vantage-client"

# Two independent keypairs: one the mock IdP "owns", one an attacker's.
_GOOD_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_BAD_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_GOOD_JWK = JsonWebKey.import_key(_GOOD_KEY, {"kty": "RSA", "kid": "good-1", "use": "sig", "alg": "RS256"})
_GOOD_JWKS = {"keys": [_GOOD_JWK.as_dict(is_private=False)]}


def _mint_id_token(claims: dict, key=_GOOD_KEY, kid: str = "good-1") -> str:
    """Mint a signed id_token with the given key/kid (authlib JOSE, RS256)."""
    jwt = JsonWebToken(["RS256"])
    header = {"alg": "RS256", "kid": kid}
    tok = jwt.encode(header, claims, key)
    return tok.decode("ascii") if isinstance(tok, bytes) else tok


def _base_claims(**over) -> dict:
    c = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "name": "Asha Rao",
        "email": "asha.rao@corp.bajajlife.com",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
    }
    c.update(over)
    return c


class _FakeRequest:
    """Minimal stand-in for starlette.Request exposing ``.cookies`` / ``.headers``
    and ``.query_params`` — all get_current_user / require_role touch."""

    def __init__(self, cookies=None, headers=None, query=None):
        self.cookies = cookies or {}
        # headers lookups in auth.py use .get(...) case-variants; a dict suffices.
        self.headers = headers or {}
        self.query_params = query or {}


# ---------------------------------------------------------------------------
# env helper — set within a test and restore afterwards
# ---------------------------------------------------------------------------


class _Env:
    """Context manager: temporarily set/unset env vars, restore on exit."""

    def __init__(self, **vals):
        self._vals = vals
        self._saved = {}

    def __enter__(self):
        for k, v in self._vals.items():
            self._saved[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, old in self._saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old
        return False


def _with_good_jwks(fn):
    """Run fn with auth._jwks monkeypatched to the local mock JWKS."""
    orig = auth._jwks
    auth._jwks = lambda: _GOOD_JWKS
    try:
        return fn()
    finally:
        auth._jwks = orig


# ---------------------------------------------------------------------------
# 1. valid id_token validates + maps to ["analyst"]
# ---------------------------------------------------------------------------


def test_valid_id_token_maps_to_analyst():
    with _Env(
        OIDC_ISSUER=ISSUER,
        OIDC_CLIENT_ID=CLIENT_ID,
        VANTAGE_GROUP_ROLE_MAP=json.dumps({"SEC-AppSec": "analyst"}),
        LDAP_URL=None,
    ):
        token = _mint_id_token(_base_claims(groups=["SEC-AppSec"], nonce="n-1"))
        claims = _with_good_jwks(lambda: validate_id_token(token, nonce="n-1"))
        assert claims["sub"] == "user-123"
        assert claims["groups"] == ["SEC-AppSec"]
        roles = map_groups_to_roles(claims["groups"])
        assert roles == ["analyst"], roles

        # Through the higher-level claims→User path too.
        user = _with_good_jwks(lambda: auth._user_from_claims(claims))
        assert user.roles == ["analyst"]
        assert user.email == "asha.rao@corp.bajajlife.com"
    print("  [ok] valid id_token validates against mock JWKS -> roles ['analyst']")


# ---------------------------------------------------------------------------
# 2. bad-signature id_token is rejected
# ---------------------------------------------------------------------------


def test_bad_signature_rejected():
    with _Env(OIDC_ISSUER=ISSUER, OIDC_CLIENT_ID=CLIENT_ID):
        # Signed by the attacker's key but claims kid of the good key.
        forged = _mint_id_token(_base_claims(groups=["SEC-AppSec"]), key=_BAD_KEY, kid="good-1")
        rejected = False
        try:
            _with_good_jwks(lambda: validate_id_token(forged))
        except Exception:
            rejected = True
        assert rejected, "id_token with a bad signature must be rejected"

        # An expired token is also rejected.
        expired = _mint_id_token(_base_claims(exp=int(time.time()) - 3600))
        rej2 = False
        try:
            _with_good_jwks(lambda: validate_id_token(expired))
        except Exception:
            rej2 = True
        assert rej2, "expired id_token must be rejected"
    print("  [ok] bad-signature and expired id_tokens are rejected")


# ---------------------------------------------------------------------------
# 3. group → role mapping
# ---------------------------------------------------------------------------


def test_group_role_mapping():
    with _Env(VANTAGE_GROUP_ROLE_MAP=json.dumps({
        "CN=SEC-AppSec,OU=Groups,DC=corp,DC=bajajlife,DC=com": "analyst",
        "SEC-CISO": "approver_ciso",
        "SEC-Auditors": "viewer",
        "SEC-VantageAdmins": "admin",
    })):
        # No groups -> least privilege viewer (never empty, never admin).
        assert map_groups_to_roles([]) == ["viewer"]
        # An admin group maps to admin.
        assert map_groups_to_roles(["SEC-VantageAdmins"]) == ["admin"]
        # CN-DN form matches by full DN string.
        assert map_groups_to_roles(
            ["CN=SEC-AppSec,OU=Groups,DC=corp,DC=bajajlife,DC=com"]
        ) == ["analyst"]
        # Bare CN matches a DN-keyed entry (first-RDN match), case-insensitive.
        assert map_groups_to_roles(["sec-appsec"]) == ["analyst"]
        # Unknown group -> viewer fallback.
        assert map_groups_to_roles(["SEC-Unknown"]) == ["viewer"]
        # Multiple groups accumulate distinct roles.
        roles = map_groups_to_roles(["SEC-CISO", "SEC-Auditors"])
        assert set(roles) == {"approver_ciso", "viewer"}, roles
    print("  [ok] map_groups_to_roles: [] -> viewer, admin group, CN/DN forms")


# ---------------------------------------------------------------------------
# 4. session cookie round-trip + tamper
# ---------------------------------------------------------------------------


def test_session_cookie_round_trip():
    user = User(
        sub="user-9",
        name="Asha Rao",
        email="asha.rao@corp.bajajlife.com",
        roles=["analyst", "viewer"],
        groups=["SEC-AppSec"],
    )
    with _Env(SESSION_SECRET="unit-test-secret", AUTH_REQUIRED=None, LDAP_URL=None):
        token = mint_session(user)
        req = _FakeRequest(cookies={auth.SESSION_COOKIE: token})
        got = get_current_user(req)
        assert got.sub == user.sub
        assert got.email == user.email
        assert got.roles == user.roles
        assert got.groups == user.groups

        # Tamper one character -> signature fails. In DEV mode (AUTH_REQUIRED
        # unset) this falls back to the synthetic dev admin.
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        req_t = _FakeRequest(cookies={auth.SESSION_COOKIE: tampered})
        fallback = get_current_user(req_t)
        assert fallback == DEV_USER, "tampered cookie in dev mode -> dev user"

    # In PROD mode the tampered cookie -> 401.
    with _Env(SESSION_SECRET="unit-test-secret", AUTH_REQUIRED="true", LDAP_URL=None):
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        req_t = _FakeRequest(cookies={auth.SESSION_COOKIE: tampered})
        raised = None
        try:
            get_current_user(req_t)
        except Exception as e:  # HTTPException
            raised = e
        assert raised is not None and getattr(raised, "status_code", None) == 401
        assert raised.detail["error"] == "unauthenticated"
    print("  [ok] session cookie round-trips; tamper -> dev fallback / prod 401")


# ---------------------------------------------------------------------------
# 5. require_role allow / deny
# ---------------------------------------------------------------------------


def _req_for(user: User) -> _FakeRequest:
    with _Env(SESSION_SECRET="unit-test-secret"):
        token = mint_session(user)
    return _FakeRequest(cookies={auth.SESSION_COOKIE: token})


def test_require_role():
    viewer = User("u-v", "V", "v@x", ["viewer"], [])
    analyst = User("u-a", "A", "a@x", ["analyst"], [])
    admin = User("u-ad", "Ad", "ad@x", ["admin"], [])

    with _Env(SESSION_SECRET="unit-test-secret", AUTH_REQUIRED="true", LDAP_URL=None):
        gate = require_role(Role.ANALYST)

        # viewer hitting an analyst-gated dep -> 403.
        forbidden = None
        try:
            gate(_FakeRequest(cookies={auth.SESSION_COOKIE: mint_session(viewer)}))
        except Exception as e:
            forbidden = e
        assert forbidden is not None and forbidden.status_code == 403
        assert forbidden.detail["error"] == "forbidden"

        # analyst passes and gets the User back.
        u = gate(_FakeRequest(cookies={auth.SESSION_COOKIE: mint_session(analyst)}))
        assert u.sub == "u-a"

        # admin passes ANY gate (wildcard).
        admin_only = require_role(Role.APPROVER_BOARD)
        u2 = admin_only(_FakeRequest(cookies={auth.SESSION_COOKIE: mint_session(admin)}))
        assert u2.sub == "u-ad"

        # 401 wins over 403: cookieless prod request to a role gate -> 401.
        unauth = None
        try:
            gate(_FakeRequest())
        except Exception as e:
            unauth = e
        assert unauth is not None and unauth.status_code == 401
    print("  [ok] require_role: viewer->403, analyst->pass, admin->any, 401>403")


# ---------------------------------------------------------------------------
# 6. dev vs prod cookieless
# ---------------------------------------------------------------------------


def test_dev_and_prod_cookieless():
    # Dev mode (AUTH_REQUIRED unset): synthetic admin dev user.
    with _Env(AUTH_REQUIRED=None):
        u = get_current_user(_FakeRequest())
        assert u == DEV_USER
        assert u.roles == ["admin"] and u.email == "dev@vantage.local"

    # Prod mode (AUTH_REQUIRED=true): cookieless -> 401.
    with _Env(AUTH_REQUIRED="true"):
        raised = None
        try:
            get_current_user(_FakeRequest())
        except Exception as e:
            raised = e
        assert raised is not None and raised.status_code == 401
        assert raised.detail == {"error": "unauthenticated", "detail": "no valid session or bearer token"}
    print("  [ok] dev cookieless -> synthetic admin; prod cookieless -> 401")


# ---------------------------------------------------------------------------
# 7. session_actor sanity (cheap, contract-named)
# ---------------------------------------------------------------------------


def test_session_actor():
    assert session_actor(DEV_USER) == "Vantage Dev <dev@vantage.local>"
    print("  [ok] session_actor renders 'Name <email>'")


def test_safe_next_open_redirect_guard():
    """_safe_next must only allow same-origin relative paths; off-origin targets
    (incl. the backslash-normalization bypass) fall back to the console origin."""
    origin = auth._console_origin()
    # allowed: plain relative paths
    assert auth._safe_next("/findings") == "/findings"
    assert auth._safe_next("/sla?tab=overdue") == "/sla?tab=overdue"
    # blocked: absolute, protocol-relative, backslash bypass, CR/LF, empty/None
    for bad in ("//evil.com", "/\\evil.com", "/\\/evil.com", "http://evil.com",
                "https://evil.com", "\\\\evil.com", "/\tevil", "/a\nb", "", None):
        assert auth._safe_next(bad) == origin, f"_safe_next allowed {bad!r}"
    print("  [ok] _safe_next blocks open-redirect (incl. '/\\' backslash bypass)")


# ---------------------------------------------------------------------------
# 8. LDAP filter-injection guard (security review)
# ---------------------------------------------------------------------------


def test_ldap_injection_guard():
    """A crafted IdP email must never reach the LDAP filter unescaped, and an
    email carrying LDAP/DN metacharacters is rejected before any search."""

    class _FakeEntry:
        memberOf = type("MO", (), {"values": ["CN=SEC-AppSec,OU=G,DC=corp"]})()

    class _FakeConn:
        last_filter = None

        def search(self, search_base, search_filter, attributes):
            type(self).last_filter = search_filter

        @property
        def entries(self):
            return [_FakeEntry()]

        def unbind(self):
            pass

    auth._ldap_connect = lambda: _FakeConn()  # monkeypatch: no live directory
    try:
        with _Env(LDAP_URL="ldaps://dc.test:636", LDAP_USER_BASE="DC=corp", LDAP_USER_FILTER=None):
            # 1) Injection attempt: metacharacters -> rejected, NO search issued.
            _FakeConn.last_filter = None
            evil = "x)(uid=*))(|(memberOf=*"
            assert resolve_groups_via_ldap(evil) == []
            assert _FakeConn.last_filter is None, "search must not run on a metachar email"

            # 2) Benign email -> search runs with the expected, intact filter.
            groups = resolve_groups_via_ldap("user@corp.com")
            assert _FakeConn.last_filter == "(userPrincipalName=user@corp.com)", _FakeConn.last_filter
            assert groups == ["CN=SEC-AppSec,OU=G,DC=corp"]
    finally:
        auth._ldap_connect = _ORIG_LDAP_CONNECT
    print("  [ok] LDAP filter-injection guard: metachar email rejected; benign email intact")


def main():
    tests = [
        test_valid_id_token_maps_to_analyst,
        test_bad_signature_rejected,
        test_group_role_mapping,
        test_session_cookie_round_trip,
        test_require_role,
        test_dev_and_prod_cookieless,
        test_session_actor,
        test_ldap_injection_guard,
        test_safe_next_open_redirect_guard,
    ]
    print("Running Vantage auth core self-test...\n")
    for t in tests:
        t()
    print("\nALL AUTH TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
