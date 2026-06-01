"""Console-state persistence — findings status + API-created scans / exceptions.

**Overlay model.** The seed catalog (``seed.py``) stays the base dataset; this
module persists the *mutations* the console makes (a finding's status change, a
newly-requested scan, a newly-requested exception) so they survive an API
restart **when a Postgres DB is configured** (``DATABASE_URL`` via ``db.py``).

It deliberately mirrors the audit pattern already in ``seed.py``: DB-backed when
available, silent **in-memory/no-op fallback** otherwise. **Never raises** — any
driver/DB error degrades to the fallback so the API keeps serving. These are
*console-facing* state tables (keyed by the API's string ids, e.g. ``VLN-2087`` /
``SCAN-0099`` / ``EXC-047``), distinct from the normalized scanner tables that
the real pipeline will eventually populate.

Backing tables (see ``db/schema.sql`` → "Console state" section):
  * ``console_finding_state(finding_id PK, status, validated_by, validated_at)``
  * ``console_scans(scan_id PK, data jsonb)``
  * ``console_exceptions(exception_id PK, data jsonb)``
"""
from __future__ import annotations

import json as _json
from typing import Optional

from . import db


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------
def available() -> bool:
    """True iff a Postgres connection can be obtained right now (else fallback)."""
    conn = db.get_conn()
    if conn is None:
        return False
    try:
        return True
    finally:
        _close(conn)


def _close(conn) -> None:
    try:
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Finding status state  (overlaid on the derived seed findings)
# ---------------------------------------------------------------------------
_FS_UPSERT = (
    "INSERT INTO console_finding_state (finding_id, status, validated_by, validated_at) "
    "VALUES (%s, %s, %s, %s::date) "
    "ON CONFLICT (finding_id) DO UPDATE SET "
    "status = EXCLUDED.status, validated_by = EXCLUDED.validated_by, "
    "validated_at = EXCLUDED.validated_at, updated_at = now()"
)
_FS_SELECT = "SELECT finding_id, status, validated_by, validated_at FROM console_finding_state"


def load_finding_state() -> dict[str, dict]:
    """Return ``{finding_id: {"status", "humanValidatedBy", "humanValidatedAt"}}``.

    Empty dict when no DB / on any error (caller then sees the seed defaults).
    """
    conn = db.get_conn()
    if conn is None:
        return {}
    try:
        with conn.cursor() as cur:
            cur.execute(_FS_SELECT)
            rows = cur.fetchall()
    except Exception:
        return {}
    finally:
        _close(conn)

    out: dict[str, dict] = {}
    for finding_id, status, validated_by, validated_at in rows:
        out[finding_id] = {
            "status": status,
            "humanValidatedBy": validated_by,
            "humanValidatedAt": (
                validated_at.isoformat() if hasattr(validated_at, "isoformat") else
                (str(validated_at) if validated_at is not None else None)
            ),
        }
    return out


def save_finding_state(finding_id: str, status: str,
                       validated_by: Optional[str], validated_at: Optional[str]) -> None:
    """Upsert one finding's mutable state. No-op when no DB; never raises."""
    conn = db.get_conn()
    if conn is None:
        return
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(_FS_UPSERT, (finding_id, status, validated_by, validated_at))
    except Exception:
        return
    finally:
        _close(conn)


# ---------------------------------------------------------------------------
# API-created scans / exceptions  (whole dict persisted as JSONB)
# ---------------------------------------------------------------------------
def _load_jsonb_rows(table: str, order_col: str) -> list[dict]:
    conn = db.get_conn()
    if conn is None:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT data FROM {table} ORDER BY {order_col} ASC")
            rows = cur.fetchall()
    except Exception:
        return []
    finally:
        _close(conn)
    out: list[dict] = []
    for (data,) in rows:
        # psycopg returns jsonb as a parsed dict; tolerate a raw string too.
        out.append(data if isinstance(data, dict) else _json.loads(data))
    return out


def _save_jsonb_row(table: str, id_col: str, row_id: str, data: dict) -> None:
    conn = db.get_conn()
    if conn is None:
        return
    sql = (
        f"INSERT INTO {table} ({id_col}, data) VALUES (%s, %s::jsonb) "
        f"ON CONFLICT ({id_col}) DO UPDATE SET data = EXCLUDED.data"
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, (row_id, _json.dumps(data)))
    except Exception:
        return
    finally:
        _close(conn)


def load_scans() -> list[dict]:
    """API-created scans (oldest-first); [] when no DB. Overlaid on seed scans."""
    return _load_jsonb_rows("console_scans", "created_at")


def save_scan(scan: dict) -> None:
    """Persist a newly-created scan dict (keyed by its ``id``). No-op without DB."""
    _save_jsonb_row("console_scans", "scan_id", scan["id"], scan)


def load_exceptions() -> list[dict]:
    """API-created exceptions (oldest-first); [] when no DB."""
    return _load_jsonb_rows("console_exceptions", "created_at")


def save_exception(exc: dict) -> None:
    """Persist a newly-requested exception dict (keyed by its ``id``)."""
    _save_jsonb_row("console_exceptions", "exception_id", exc["id"], exc)
