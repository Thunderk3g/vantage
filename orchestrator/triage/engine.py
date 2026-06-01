"""
Deterministic triage engine for Vantage  —  the rules-first layer.

This is the FIRST pass of the two-stage triage described in the architecture
(see orchestrator/activities.normalize_and_triage). It is 100% deterministic
and uses NO LLM: given the canonical findings produced by the scanner adapters
it performs

    1. severity normalization     (CVSS base score -> severity band)
    2. deduplication              (collapse the same issue seen by many tools)
    3. SLA assignment             (severity -> closure window + deadline)
    4. taxonomy mapping           (OWASP Web / OWASP API / SANS-25 / CIS)

The dedup signature prefers CVE then title (then native id only for
title-less rows) precisely so the same issue seen by different tools — whose
native ids never agree — still collapses to one canonical finding.

and returns a cleaned, canonical list of finding dicts. The same input always
produces the same output (stable hashing, sorted iteration), which the LLM
second pass and the audit log both rely on.

Findings are plain dicts — the canonical shape from the adapters, mirroring
shared.CanonicalFinding / the ``findings`` table in db/schema.sql. Relevant
keys this engine reads / writes::

    reads : asset_id, source_tool, native_id, title, cve (list),
            cvss_base (float|None), severity_normalized (str|None),
            detected_at (ISO date/datetime str), port, location/url,
            family, issue_type, tags (list)        # tool-specific, optional
    writes: severity_normalized (normalized band, lower-case),
            dedup_key, dup_of, duplicates (count on canonical),
            slaDays, deadline (ISO date|None), daysLeft (int|None),
            owasp_web, owasp_api, sans25, cis_control

Severity bands and SLA windows match orchestrator/api/seed.py and
db/schema.sql exactly.
"""
from __future__ import annotations

import hashlib
from datetime import date, datetime, timedelta

try:                                # package import (orchestrator on path)
    from triage import maps
except ImportError:                 # direct/script execution from this dir
    import maps                     # type: ignore


# Canonical severity vocabulary (lower-case, matches seed.py SLA_DAYS keys).
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# SLA closure window (days) per band — IRDAI policy, matches seed.SLA_DAYS
# and db/schema.sql sla_days_for(). Info has no SLA (None).
SLA_DAYS = {"critical": 30, "high": 30, "medium": 60, "low": 60, "info": None}


# =====================================================================
# 1. SEVERITY  — CVSS base score -> band
# =====================================================================
def severity_from_cvss(cvss: float | None, fallback: str | None = None) -> str:
    """Map a CVSS v3 base score to a Vantage severity band (lower-case).

    Bands (match seed.py / schema):
        >= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0 low, else info.

    If ``cvss`` is None/unparseable, fall back to a tool-provided severity
    string (normalized) when given, else 'info'.
    """
    if cvss is None:
        return _normalize_band(fallback) if fallback else "info"
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return _normalize_band(fallback) if fallback else "info"

    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _normalize_band(value: str | None) -> str:
    """Coerce an arbitrary severity label to the canonical lower-case band."""
    if not value:
        return "info"
    v = str(value).strip().lower()
    if v in _SEVERITY_ORDER:
        return v
    # common synonyms / vendor spellings
    aliases = {
        "crit": "critical",
        "informational": "info",
        "information": "info",
        "none": "info",
        "moderate": "medium",
        "med": "medium",
        "warning": "low",
        "note": "info",
    }
    return aliases.get(v, "info")


# =====================================================================
# 2. DEDUP  — composite key + merge
# =====================================================================
def _signature(finding: dict) -> str:
    """The 'what' of a finding, independent of which tool reported it.

    Precedence is chosen so the SAME issue seen by DIFFERENT tools collapses:
      1. CVE(s)            — the strongest cross-tool identity (order-free set);
      2. normalized title  — tools describe the same flaw with the same words
                             ("SQL injection in policy search parameter");
      3. native id         — ONLY when there is no CVE and no title. native_ids
                             are tool-specific (Nessus plugin id != ZAP alert
                             id), so keying on them would *prevent* cross-tool
                             dedup; they are a last resort for title-less rows.

    This is why a Nessus finding (native_id=plugin) and a ZAP finding
    (native_id=None) for the same titled SQLi produce the same signature.
    """
    cves = finding.get("cve") or []
    if cves:
        # order-independent set of CVEs
        return "cve:" + ",".join(sorted({str(c).strip().upper() for c in cves if c}))
    title = (finding.get("title") or "").strip().lower()
    if title:
        return "ttl:" + " ".join(title.split())
    native = finding.get("native_id")
    if native:
        return "nid:" + str(native).strip().lower()
    return "ttl:"


def _location(finding: dict) -> str:
    """The 'where' of a finding: port and/or path, normalized.

    Two tools hitting the same endpoint should agree here. Missing location
    parts collapse to empty so a port-only infra finding and a path-only web
    finding each key cleanly.
    """
    port = finding.get("port")
    loc = finding.get("location") or finding.get("url") or finding.get("path") or ""
    parts = []
    if port not in (None, "", 0):
        parts.append(f"port={str(port).strip().lower()}")
    if loc:
        parts.append("loc=" + str(loc).strip().lower())
    return "|".join(parts)


def dedup_key(finding: dict) -> str:
    """Stable composite dedup key: asset + location + signature.

    Returns a hex sha-256 digest so it is fixed-width, opaque, and stable
    across processes/runs (no salting, no per-run randomness). This is the
    value stored in findings.dedup_key.
    """
    asset = str(finding.get("asset_id") or "").strip().lower()
    composite = "\x1f".join((asset, _location(finding), _signature(finding)))
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()


def _rank(finding: dict) -> tuple[int, float]:
    """Sort key for picking the canonical finding within a dup group:
    highest severity band, then highest CVSS. Deterministic ties broken by
    caller's stable ordering."""
    sev = _SEVERITY_ORDER.get(_normalize_band(finding.get("severity_normalized")), 0)
    cvss = finding.get("cvss_base")
    try:
        cvss = float(cvss) if cvss is not None else -1.0
    except (TypeError, ValueError):
        cvss = -1.0
    return (sev, cvss)


def deduplicate(findings: list[dict]) -> list[dict]:
    """Collapse findings that share a dedup_key into one canonical finding.

    Strategy (documented choice): **keep-canonical, drop-duplicates**.
      * Findings are grouped by ``dedup_key``.
      * Within a group the highest (severity, cvss) finding is the canonical
        one. Ties are broken deterministically by original input order, so
        the result is reproducible.
      * The canonical finding gets ``duplicates`` = (group size - 1) and a
        ``merged_from`` list of the source_tools that also saw it (handy for
        the report: "confirmed by nessus + zap").
      * Duplicates are NOT returned in the canonical list, but each is
        stamped with ``dup_of`` = canonical dedup_key and ``is_duplicate`` =
        True before being dropped — this mirrors db/schema.sql where
        suppressed rows carry ``dup_of`` and only ``dup_of IS NULL`` rows are
        canonical. (Callers that need the suppressed rows can use
        ``deduplicate_full`` below.)

    Returns only the canonical findings, in stable (input) order.
    """
    canonical, _dropped = deduplicate_full(findings)
    return canonical


def deduplicate_full(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Same as ``deduplicate`` but also returns the suppressed duplicates.

    Returns ``(canonical, duplicates)``. Useful for persistence/audit where
    the suppressed rows are still written (with ``dup_of`` set)."""
    # Group, preserving first-seen order for stable output.
    groups: dict[str, list[int]] = {}
    order: list[str] = []
    enriched: list[dict] = []
    for idx, f in enumerate(findings):
        g = dict(f)                              # never mutate caller's dicts
        g["dedup_key"] = g.get("dedup_key") or dedup_key(g)
        enriched.append(g)
        key = g["dedup_key"]
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(idx)

    canonical: list[dict] = []
    duplicates: list[dict] = []
    for key in order:
        members = groups[key]
        # Pick canonical: best (severity, cvss); tie -> earliest input index.
        best_idx = min(members, key=lambda i: (-_rank(enriched[i])[0],
                                                -_rank(enriched[i])[1], i))
        winner = enriched[best_idx]
        others = [enriched[i] for i in members if i != best_idx]

        merged_tools = sorted({
            str(enriched[i].get("source_tool") or "").lower()
            for i in members
            if enriched[i].get("source_tool")
        })
        winner["duplicates"] = len(others)
        winner["merged_from"] = merged_tools
        winner["dup_of"] = None
        winner["is_duplicate"] = False
        canonical.append(winner)

        for d in others:
            d["dup_of"] = key
            d["is_duplicate"] = True
            duplicates.append(d)

    return canonical, duplicates


# =====================================================================
# 3. SLA  — severity -> window + deadline
# =====================================================================
def _to_date(value) -> date | None:
    """Parse an ISO date / datetime string (or pass through a date)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    s = str(value).strip()
    # tolerate trailing 'Z' and a time component
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        try:
            return date.fromisoformat(s[:10])
        except ValueError:
            return None


def assign_sla(severity: str, detected_at) -> tuple[int | None, date | None]:
    """Return ``(sla_days, deadline)`` for a severity band + detection date.

    deadline = detected_at + sla_days. Info has no SLA -> ``(None, None)``.
    Matches db/schema.sql sla_days_for() and seed.SLA_DAYS, except that —
    like seed.py — Info is treated as "no deadline" (None) rather than the
    schema's 60-day fallback; the engine never emits an Info SLA row.
    """
    band = _normalize_band(severity)
    days = SLA_DAYS.get(band)
    if days is None:
        return None, None
    d = _to_date(detected_at)
    deadline = d + timedelta(days=days) if d is not None else None
    return days, deadline


# =====================================================================
# 4. TAXONOMY  — OWASP Web / OWASP API / SANS-25 / CIS
# =====================================================================
def _merge_categories(into: dict, src: dict) -> None:
    """Union the list fields and set cis_control if not already set."""
    for k in ("owasp_web", "owasp_api", "sans25"):
        if src.get(k):
            existing = into.setdefault(k, [])
            for v in src[k]:
                if v not in existing:
                    existing.append(v)
    if src.get("cis_control") and not into.get("cis_control"):
        into["cis_control"] = src["cis_control"]


def map_categories(finding: dict) -> dict:
    """Resolve a finding to framework taxonomy using maps.py.

    Precedence (most specific first): native id -> tool tag/family ->
    CIS control id -> title keyword. The first level that yields anything
    short-circuits the cheaper fallbacks, but if a finding already carries
    adapter-provided codes those are preserved and unioned in.

    Returns a dict with ``owasp_web``, ``owasp_api``, ``sans25`` (lists) and
    ``cis_control`` (str|None). Deterministic for a given finding.
    """
    result: dict = {"owasp_web": [], "owasp_api": [], "sans25": [], "cis_control": None}

    # Seed with any taxonomy the adapter already attached (preserve, don't lose).
    for k in ("owasp_web", "owasp_api", "sans25"):
        vals = finding.get(k)
        if vals:
            result[k] = list(dict.fromkeys(vals))   # de-dup, keep order
    if finding.get("cis_control"):
        result["cis_control"] = finding["cis_control"]

    tool = str(finding.get("source_tool") or "").strip().lower()

    # 1. native id (source_tool, native_id)
    native = finding.get("native_id")
    if tool and native is not None:
        hit = maps.NATIVE_ID_MAP.get((tool, str(native).strip().lower()))
        if hit:
            _merge_categories(result, hit)
            return result

    # 2. tool tag / family. Nessus -> family; Nuclei -> tags list; generic.
    tags: list[str] = []
    for key in ("family", "issue_type", "category"):
        v = finding.get(key)
        if v:
            tags.append(str(v))
    raw_tags = finding.get("tags")
    if isinstance(raw_tags, (list, tuple)):
        tags.extend(str(t) for t in raw_tags)
    elif raw_tags:
        tags.extend(str(raw_tags).split(","))

    matched_tag = False
    for t in tags:
        hit = maps.TAG_MAP.get((tool, t.strip().lower()))
        if hit:
            _merge_categories(result, hit)
            matched_tag = True
    if matched_tag:
        return result

    # 3. CIS control id carried on the finding (config / compliance scans).
    cis_id = finding.get("cis_control")
    if cis_id:
        hit = maps.CIS_CONTROL_MAP.get(str(cis_id).strip())
        if hit:
            _merge_categories(result, hit)
            return result

    # 4. keyword over the title (last resort, conservative).
    title = (finding.get("title") or "").lower()
    if title:
        for needle, cats in maps.KEYWORD_MAP:
            if needle in title:
                _merge_categories(result, cats)
                break

    return result


# =====================================================================
# ORCHESTRATION
# =====================================================================
def run_triage(findings: list[dict], today: date | None = None) -> list[dict]:
    """Run the full deterministic triage pass over canonical findings.

    Steps, in order:
        1. normalize severity      (CVSS band, fallback to tool severity)
        2. deduplicate             (collapse cross-tool duplicates)
        3. assign SLA              (slaDays / deadline / daysLeft)
        4. map taxonomy            (owasp_web / owasp_api / sans25 / cis_control)

    ``today`` (defaults to date.today()) anchors the ``daysLeft`` countdown.
    Returns the cleaned canonical list (duplicates suppressed), in stable
    order. Deterministic and reproducible: same input -> same output.

    NOTE: this overload accepts a list of finding dicts. The activity stub in
    orchestrator/activities.py calls ``run_triage(scan_id)`` — wiring the
    scan_id -> raw-artifact -> canonical-findings load is the activity's job
    (persistence layer), and is intentionally out of scope for this pure,
    side-effect-free engine.
    """
    if today is None:
        today = date.today()

    # 1. normalize severity (in copies; do not mutate caller input).
    normalized: list[dict] = []
    for f in findings:
        g = dict(f)
        band = severity_from_cvss(
            g.get("cvss_base"),
            fallback=g.get("severity_normalized"),
        )
        g["severity_normalized"] = band
        g["dedup_key"] = g.get("dedup_key") or dedup_key(g)
        normalized.append(g)

    # 2. deduplicate.
    canonical = deduplicate(normalized)

    # 3 + 4. SLA + taxonomy on each canonical finding.
    for g in canonical:
        sla_days, deadline = assign_sla(g["severity_normalized"], g.get("detected_at"))
        g["slaDays"] = sla_days
        g["deadline"] = deadline.isoformat() if deadline is not None else None
        g["daysLeft"] = (deadline - today).days if deadline is not None else None

        cats = map_categories(g)
        g["owasp_web"] = cats["owasp_web"]
        g["owasp_api"] = cats["owasp_api"]
        g["sans25"] = cats["sans25"]
        g["cis_control"] = cats["cis_control"]

    return canonical
