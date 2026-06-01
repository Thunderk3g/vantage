"""Vantage API DB connection helper.

Optional Postgres backing for the audit trail. The API must NEVER crash because
of the database: if ``DATABASE_URL`` is unset or the server is unreachable, every
helper here degrades to a no-op (returns ``None`` / ``False``) and callers fall
back to the in-memory store in ``seed.py``.

Only the audit trail uses this for now; the rest of the API stays seed-backed.
"""

from __future__ import annotations

import os
from typing import Optional

try:  # psycopg is optional at import time (lean dev installs may lack it).
    import psycopg
except Exception:  # pragma: no cover - import guard
    psycopg = None  # type: ignore[assignment]


def database_url() -> Optional[str]:
    """The configured ``DATABASE_URL`` (None/empty when unset)."""
    url = os.environ.get("DATABASE_URL")
    return url if url else None


def get_conn():
    """Return a live psycopg connection, or ``None`` if unconfigured/unreachable.

    Never raises: any connection / driver error is swallowed and reported as
    ``None`` so the API keeps serving with the in-memory fallback.
    """
    url = database_url()
    if not url or psycopg is None:
        return None
    try:
        # autocommit so each audit INSERT is durable immediately and we don't
        # leave open transactions on the shared connection.
        return psycopg.connect(url, autocommit=True, connect_timeout=3)
    except Exception:
        return None


def db_available() -> bool:
    """True iff a DB is configured AND we can currently open a connection."""
    conn = get_conn()
    if conn is None:
        return False
    try:
        conn.close()
    except Exception:
        pass
    return True
