"""
Trivy adapter — OSS SCA / container-image / IaC-config scanner.

This adapter is parse-only: it ingests an already-captured `trivy -f json`
report (`trivy image -f json` / `trivy fs -f json`) and normalizes it into
the canonical finding shape. It NEVER launches a live scan and has no
"exploit" verb — the only real behaviour here is `parse()`.

A single Trivy report carries two kinds of results:
  * `Vulnerabilities[]` — SCA/package CVEs (os-pkgs / lang-pkgs results),
  * `Misconfigurations[]` — IaC/config checks (Dockerfile, k8s, etc.).
Both are mapped to CanonicalFinding here. Severity comes straight from
Trivy's CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN band via `_band`; CVSS base score
is pulled from `CVSS.<vendor>.V3Score` (nvd preferred).

JSON is loaded with the stdlib `json` module (no eval, no XML/XXE surface);
the report is semi-trusted (it embeds package names / titles), so we use
defensive `.get()` access throughout and never trust shape.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity
from .base import assert_targets_in_scope


class TrivyAdapter:
    name = "trivy"

    # -- lifecycle ------------------------------------------------------
    def preflight(self, token: AuthToken) -> None:
        # Trivy operates on the resolved in-scope targets only (image refs /
        # filesystem paths land in the allowlist). Fail closed.
        assert_targets_in_scope(token.target_addrs, token)
        # _vault_lease("trivy/registry") for private-registry pulls.

    def launch(self, targets: list[str], **kw: Any) -> str:
        # `trivy image -f json <ref>` / `trivy fs -f json <path>`; the scan
        # set is exactly the allowlist — Trivy never sees anything else.
        raise NotImplementedError("wire to Trivy CLI/server: launch scan")

    def wait(self, handle: str) -> None:
        # poll the scan job until it reaches a terminal state
        raise NotImplementedError

    def fetch_raw(self, handle: str) -> RawArtifact:
        # capture the `-f json` report and store it immutably (object store)
        raise NotImplementedError

    # -- parsing --------------------------------------------------------
    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        with open(_local_copy(raw.uri), "r", encoding="utf-8") as fh:
            report = json.load(fh)

        artifact_name = report.get("ArtifactName") or ""
        asset_id = _asset_id_for(artifact_name)

        findings: list[CanonicalFinding] = []
        for result in report.get("Results") or []:
            target = result.get("Target") or ""

            # Package vulnerabilities (SCA / CVEs).
            for vuln in result.get("Vulnerabilities") or []:
                vid = vuln.get("VulnerabilityID") or ""
                pkg = vuln.get("PkgName") or ""
                title = vuln.get("Title") or (f"{pkg} {vid}".strip())
                desc = vuln.get("Description")
                if desc is not None:
                    desc = desc.strip() or None
                cves = [vid] if vid.startswith("CVE-") else []
                score, vector = _cvss_score(vuln.get("CVSS") or {})
                findings.append(CanonicalFinding(
                    asset_id=asset_id,
                    source_tool=self.name,
                    native_id=vid or None,
                    title=title,
                    description=desc,
                    cve=cves,
                    cvss_base=score,
                    cvss_vector=vector,
                    severity_normalized=_band(vuln.get("Severity")),
                    dedup_key=_dedup_key(artifact_name, target, vid),
                ))

            # IaC / config misconfigurations (no CVE).
            for misc in result.get("Misconfigurations") or []:
                mid = misc.get("ID") or ""
                desc = misc.get("Description")
                if desc is not None:
                    desc = desc.strip() or None
                findings.append(CanonicalFinding(
                    asset_id=asset_id,
                    source_tool=self.name,
                    native_id=mid or None,
                    title=misc.get("Title") or mid,
                    description=desc,
                    cve=[],
                    cvss_base=None,
                    cvss_vector=None,
                    severity_normalized=_band(misc.get("Severity")),
                    dedup_key=_dedup_key(artifact_name, target, mid),
                ))
        return findings


def _band(severity: str | None) -> Severity:
    """Trivy severity string -> normalized band. Deterministic.

    Trivy emits CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN; anything we don't recognize
    (UNKNOWN, blank, missing) maps to INFO.
    """
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get((severity or "").strip().upper(), Severity.INFO)


def _cvss_score(cvss: dict) -> tuple[float | None, str | None]:
    """Pull a CVSS v3 base score + vector from Trivy's CVSS block.

    Trivy nests scores per vendor: `{"nvd": {"V3Score": 9.8, "V3Vector": ...},
    "redhat": {...}}`. We prefer the NVD entry; if it has no V3Score we fall
    back to the first vendor that does. Returns (score, vector) where the
    vector is the one paired with the chosen score. Missing/messy -> (None, None).
    """
    if not isinstance(cvss, dict) or not cvss:
        return None, None

    def _read(entry: Any) -> tuple[float | None, str | None]:
        if not isinstance(entry, dict):
            return None, None
        raw = entry.get("V3Score")
        if raw is None:
            return None, None
        try:
            return float(raw), entry.get("V3Vector")
        except (TypeError, ValueError):
            return None, None

    # Prefer NVD.
    score, vector = _read(cvss.get("nvd"))
    if score is not None:
        return score, vector
    # Else first vendor exposing a V3Score.
    for vendor, entry in cvss.items():
        if vendor == "nvd":
            continue
        score, vector = _read(entry)
        if score is not None:
            return score, vector
    return None, None


def _dedup_key(artifact_name: str, target: str, native_id: str) -> str:
    sig = f"{artifact_name}|{target}|{native_id}"
    return hashlib.sha256(sig.encode()).hexdigest()


def _local_copy(uri: str) -> str:
    """Resolve the raw-artifact pointer to a local filesystem path.

    In production this pulls the object out of the object store to a temp
    file. Here the artifact is already local, so the uri *is* the path.
    """
    return uri


def _asset_id_for(artifact_name: str) -> str:
    """Deterministic asset id from a Trivy ArtifactName (image ref / path).

    Same artifact -> same id on every run (no DB round-trip, no randomness),
    so findings dedup/correlate across scans. Slugifies non-alphanumerics.
    """
    name = (artifact_name or "").strip()
    if not name:
        return "AST-unknown"
    return "AST-" + re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")
