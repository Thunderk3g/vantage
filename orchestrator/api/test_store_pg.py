"""Real-Postgres integration test for the console-state store (store.py).

Proves the overlay-persistence layer ROUND-TRIPS through a live Postgres: a
finding's status change, an API-created scan, and an API-created exception are
written by ``store.save_*`` and read back by ``store.load_*`` from the actual
``console_finding_state`` / ``console_scans`` / ``console_exceptions`` tables in
``db/schema.sql``. Because store.py keeps NO in-process cache, re-calling the
load_* helpers after the saves re-reads from Postgres — that is the proof the
state survives an API restart.

Connection strategy (two paths):
  * CI path — if ``DATABASE_URL`` is set in the env, use it as-is and assume the
    schema is ALREADY applied (CI applies db/schema.sql to its service DB).
  * Local path — otherwise spin a THROWAWAY ``postgres:16`` container via the
    docker CLI on host port 55433 (NOT 5432, to avoid colliding with a running
    stack / CI service), wait for readiness, point DATABASE_URL at it, apply
    db/schema.sql, run, and ALWAYS ``docker rm -f`` it in a finally.
  * If docker is unavailable AND DATABASE_URL is unset, print a SKIP and exit 0
    so a machine without docker never fails this test.

Style mirrors the other repo self-tests (orchestrator/api/test_auth.py,
test_scope_invariants.py): plain asserts, one ``[ok]`` line per check, a
``main()`` returning 0/1, and ``raise SystemExit(main())``. No pytest required:

    python orchestrator/api/test_store_pg.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

# --- sys.path bootstrap: put the orchestrator dir first so ``from api import
#     store, db`` resolves regardless of cwd. ---------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))      # orchestrator/api
ORCH = os.path.dirname(HERE)                            # orchestrator
ROOT = os.path.dirname(ORCH)                            # repo root
for p in (ORCH, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

SCHEMA_SQL = os.path.join(ROOT, "db", "schema.sql")

CONTAINER = "vantage-store-pgtest"
PG_IMAGE = "postgres:16"
PG_PORT = 55433                                         # host port; NOT 5432
PG_DSN = f"postgresql://postgres:postgres@localhost:{PG_PORT}/postgres"

PASS: list[str] = []


def ok(msg: str) -> None:
    PASS.append(msg)
    print("  [ok] " + msg)


# ---------------------------------------------------------------------------
# docker helpers (local path only)
# ---------------------------------------------------------------------------
def _have_docker() -> bool:
    try:
        subprocess.run(
            ["docker", "version"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
        )
        return True
    except Exception:
        return False


def _docker_rm() -> None:
    subprocess.run(
        ["docker", "rm", "-f", CONTAINER],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _start_container() -> None:
    # Remove any stale container from a previous aborted run first.
    _docker_rm()
    subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", CONTAINER,
            "-e", "POSTGRES_PASSWORD=postgres",
            "-p", f"{PG_PORT}:5432",
            PG_IMAGE,
        ],
        check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    print(f"  [..] started throwaway {PG_IMAGE} as {CONTAINER} on :{PG_PORT}")


def _wait_ready(timeout_s: int = 60) -> None:
    """Poll pg_isready inside the container, then confirm a real connect."""
    import psycopg

    deadline = time.time() + timeout_s
    # 1) server process accepting connections
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "exec", CONTAINER, "pg_isready", "-U", "postgres"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if r.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("postgres pg_isready never succeeded")

    # 2) a real client connect actually works (port mapped, auth ok)
    while time.time() < deadline:
        try:
            with psycopg.connect(PG_DSN, connect_timeout=3) as c:
                with c.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            print("  [..] postgres is ready and accepting client connections")
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("postgres never accepted a client connection")


def _apply_schema() -> None:
    """Stream db/schema.sql into the container's psql; assert it applies."""
    with open(SCHEMA_SQL, "r", encoding="utf-8") as fh:
        sql = fh.read()
    proc = subprocess.run(
        ["docker", "exec", "-i", CONTAINER,
         "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"],
        input=sql.encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "schema.sql failed to apply:\n" + proc.stdout.decode("utf-8", "replace")
        )
    print("  [..] APPLY: OK (db/schema.sql)")


# ---------------------------------------------------------------------------
# The actual assertions — exercise store.py's public API end to end.
# ---------------------------------------------------------------------------
def run_assertions() -> None:
    # Imported here so the path/env are set up first (DATABASE_URL must be set
    # before db.get_conn() is exercised).
    from api import store, db

    # (a) availability
    assert db.get_conn() is not None, "db.get_conn() should connect to the test PG"
    assert store.available() is True, "store.available() must be True once connected"
    ok("store.available() is True once connected to Postgres")

    # (b) finding state: insert, read back exact shape, then UPSERT-update
    store.save_finding_state("VLN-TEST", "in_progress", "Anu <anu@corp>", "2026-06-01")
    state = store.load_finding_state()
    assert "VLN-TEST" in state, "saved finding state must be loadable"
    assert state["VLN-TEST"] == {
        "status": "in_progress",
        "humanValidatedBy": "Anu <anu@corp>",
        "humanValidatedAt": "2026-06-01",
    }, state["VLN-TEST"]
    ok("save/load_finding_state round-trips exact shape (status/by/at)")

    # upsert SAME id -> UPDATE in place (no duplicate row, status now closed)
    store.save_finding_state("VLN-TEST", "closed", "Anu <anu@corp>", "2026-06-01")
    state = store.load_finding_state()
    matches = [k for k in state if k == "VLN-TEST"]
    assert len(matches) == 1, f"finding_id must be unique (PK upsert), got {matches}"
    assert state["VLN-TEST"]["status"] == "closed", state["VLN-TEST"]
    ok("re-save same finding_id UPDATES in place (status->closed, no duplicate)")

    # (c) scan: dict round-trips through jsonb; upsert updates not duplicates
    scan = {"id": "SCAN-9001", "target": "X", "status": "queued", "by": "Anu"}
    store.save_scan(scan)
    scans = store.load_scans()
    got = [s for s in scans if s.get("id") == "SCAN-9001"]
    assert len(got) == 1, f"SCAN-9001 must appear exactly once, got {len(got)}"
    assert got[0] == scan, f"scan dict must round-trip through jsonb: {got[0]}"
    ok("save/load_scan round-trips the full dict through jsonb")

    scan2 = {"id": "SCAN-9001", "target": "X", "status": "running", "by": "Anu"}
    store.save_scan(scan2)
    scans = store.load_scans()
    got = [s for s in scans if s.get("id") == "SCAN-9001"]
    assert len(got) == 1, f"upsert must not duplicate SCAN-9001, got {len(got)}"
    assert got[0]["status"] == "running", got[0]
    ok("re-save same scan_id UPDATES jsonb in place (status->running, no duplicate)")

    # (d) exception: dict round-trips through jsonb
    exc = {"id": "EXC-901", "finding": "VLN-1", "tier": "CISO"}
    store.save_exception(exc)
    excs = store.load_exceptions()
    got = [e for e in excs if e.get("id") == "EXC-901"]
    assert len(got) == 1, f"EXC-901 must appear exactly once, got {len(got)}"
    assert got[0] == exc, f"exception dict must round-trip through jsonb: {got[0]}"
    ok("save/load_exception round-trips the full dict through jsonb")

    # (e) persistence across a simulated restart: store keeps NO in-process
    #     cache, so a fresh round of load_* re-reads straight from Postgres.
    fresh_state = store.load_finding_state()
    fresh_scans = store.load_scans()
    fresh_excs = store.load_exceptions()
    assert fresh_state.get("VLN-TEST", {}).get("status") == "closed"
    assert any(s.get("id") == "SCAN-9001" for s in fresh_scans)
    assert any(e.get("id") == "EXC-901" for e in fresh_excs)
    ok("data is re-read from Postgres on reload (survives an API restart)")


def main() -> int:
    print("Running Vantage console-state store Postgres integration test...\n")

    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        # CI path: schema already applied to the configured DB.
        print(f"  [..] using DATABASE_URL from env (CI path): {env_url}")
        try:
            run_assertions()
        except AssertionError as e:
            print("\nSTORE PG TEST FAILED:\n" + str(e))
            return 1
        print(f"\nALL STORE PG TESTS PASSED ({len(PASS)} checks)")
        return 0

    # Local path: need docker to spin a throwaway PG.
    if not _have_docker():
        print(
            "  [skip] no DATABASE_URL and docker is unavailable — skipping the "
            "real-Postgres store test (exit 0)."
        )
        return 0

    try:
        _start_container()
        _wait_ready()
        os.environ["DATABASE_URL"] = PG_DSN     # store/db read this
        _apply_schema()
        try:
            run_assertions()
        except AssertionError as e:
            print("\nSTORE PG TEST FAILED:\n" + str(e))
            return 1
        print(f"\nALL STORE PG TESTS PASSED ({len(PASS)} checks)")
        return 0
    except Exception as e:
        print(f"\nSTORE PG TEST ERRORED: {type(e).__name__}: {e}")
        return 1
    finally:
        _docker_rm()
        print(f"  [..] torn down throwaway container {CONTAINER}")


if __name__ == "__main__":
    raise SystemExit(main())
