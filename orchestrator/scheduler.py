"""Scan scheduler — cadence + blackout calendar (Phase 4 governance).

Pure, deterministic planning engine. Given the approved assets, a per-asset scan
cadence (web pentest 2×/yr · internal infra VA 2×/yr · CIS config review 1×/yr),
a **blackout calendar** (freeze windows when no scans run — FY-end, festive
peak), and the last-run date per (asset, scan type), it computes the NEXT
scheduled scan window for each, shifted out of any blackout.

It NEVER launches a scan — it only plans. Driving the plan on a timer is the
Temporal/cron layer (deployment), and any scan it eventually triggers STILL
passes the human/scope gate. So this stays firmly inside the scan-and-report
boundary: no exploitation, no auto-action on a target.
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Optional

# Cadence in days. Twice a year ≈ 182 days; once a year = 365 days.
SEMIANNUAL = 182
ANNUAL = 365

# Default freeze windows — no scans scheduled inside these; a due scan is pushed
# to the day after the window closes. Dates are inclusive ISO YYYY-MM-DD.
DEFAULT_BLACKOUTS = [
    {"start": "2026-03-25", "end": "2026-04-10", "reason": "FY-end change freeze"},
    {"start": "2026-10-15", "end": "2026-11-12", "reason": "Festive peak-load freeze"},
]


def cadences_for(asset: dict) -> list[tuple[str, str, int]]:
    """The scan plan for one asset: list of (scanType, cadenceLabel, days).

    - web assets: a web pentest twice a year.
    - infra assets: an internal VA twice a year AND a CIS config review once a
      year (credentialed compliance) — mirrors 'internal 2×/yr · CIS 1×/yr'.
    """
    if asset.get("type") == "web":
        return [("web-pentest", "2x/yr", SEMIANNUAL)]
    return [("infra-va", "2x/yr", SEMIANNUAL), ("cis-review", "1x/yr", ANNUAL)]


def _to_date(v) -> Optional[date]:
    if v is None or v == "":
        return None
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def _in_blackout(d: date, blackouts) -> Optional[dict]:
    for b in blackouts:
        s, e = _to_date(b.get("start")), _to_date(b.get("end"))
        if s and e and s <= d <= e:
            return b
    return None


def shift_out_of_blackout(d: date, blackouts) -> tuple[date, Optional[dict]]:
    """If ``d`` lands in a freeze window, move to the day after it closes
    (repeating for adjacent windows). Returns (adjusted_date, first_window_hit)."""
    hit = None
    cur = d
    for _ in range(12):  # bounded; windows are few
        b = _in_blackout(cur, blackouts)
        if not b:
            break
        hit = hit or b
        end = _to_date(b.get("end"))
        cur = (end + timedelta(days=1)) if end else cur + timedelta(days=1)
    return cur, hit


def schedule_entry(asset: dict, scan_type: str, label: str, cadence_days: int,
                   last_run, today: date, blackouts) -> dict:
    """One schedule row for an (asset, scan type)."""
    lr = _to_date(last_run)
    base = (lr + timedelta(days=cadence_days)) if lr else today
    overdue = base < today
    candidate = base if base >= today else today   # overdue → schedule now
    next_d, hit = shift_out_of_blackout(candidate, blackouts)
    days_until = (next_d - today).days
    return {
        "assetId": asset.get("id"),
        "asset": asset.get("name"),
        "pipeline": "infra" if asset.get("type") == "infra" else "web",
        "scanType": scan_type,
        "cadence": label,
        "cadenceDays": cadence_days,
        "lastRun": lr.isoformat() if lr else None,
        "nextDue": next_d.isoformat(),
        "overdue": overdue,
        "dueSoon": (0 <= days_until <= 30) and not overdue,
        "shiftedByBlackout": hit is not None,
        "blackoutReason": hit.get("reason") if hit else None,
        "daysUntil": days_until,
    }


def build_schedule(assets: list[dict], today=None, last_runs=None, blackouts=None) -> dict:
    """Compute the scan schedule across all approved assets.

    ``last_runs`` maps (assetId, scanType) → ISO date (or assetId → ISO date as a
    fallback) of the most recent completed run; absent → a baseline scan is due
    now. ``blackouts`` defaults to DEFAULT_BLACKOUTS. Deterministic; never
    launches anything. Returns {today, blackouts, entries, counts}.
    """
    today = today or date.today()
    blackouts = blackouts if blackouts is not None else DEFAULT_BLACKOUTS
    last_runs = last_runs or {}

    entries: list[dict] = []
    for a in assets:
        for scan_type, label, days in cadences_for(a):
            lr = last_runs.get((a.get("id"), scan_type))
            if lr is None:
                lr = last_runs.get(a.get("id"))
            entries.append(schedule_entry(a, scan_type, label, days, lr, today, blackouts))

    # Most urgent first: overdue, then soonest due.
    entries.sort(key=lambda e: (not e["overdue"], e["daysUntil"]))
    counts = {
        "total": len(entries),
        "overdue": sum(1 for e in entries if e["overdue"]),
        "dueSoon": sum(1 for e in entries if e["dueSoon"]),
    }
    return {"today": today.isoformat(), "blackouts": blackouts, "entries": entries, "counts": counts}
