"""
Shared types for the scanner orchestrator.

These dataclasses are the contract between the Temporal workflows and the
activities. Keep them JSON-serializable (Temporal serializes activity
arguments and return values).

The CanonicalFinding here is the single normalized shape every scanner
adapter must produce. It mirrors the `findings` table in db/schema.sql.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Pipeline(str, Enum):
    INFRA = "infra"
    WEBAPP = "webapp"


class ScanMode(str, Enum):
    BLACKBOX = "blackbox"
    GRAYBOX = "graybox"


class Phase(str, Enum):
    """Pipeline phases. There is deliberately NO exploitation phase.

    The terminal phase is `report`. The state machine cannot advance into
    exploitation, lateral movement, or remediation — those states do not
    exist by construction.
    """
    SCOPE = "scope"
    RECON = "recon"
    MAPPING = "mapping"
    DETECTION = "detection"
    CIS = "cis"
    TRIAGE = "triage"
    REPORT = "report"
    DONE = "done"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AuthContextName(str, Enum):
    UNAUTH = "unauth"
    MIN_PRIV = "min_priv"
    MAX_PRIV = "max_priv"


@dataclass
class ScanRequest:
    """Emitted by the scheduler (or a user) — NOT yet authorized."""
    scan_request_id: str
    pipeline: Pipeline
    profile: str               # SOP profile name
    mode: ScanMode
    target_query: dict         # e.g. {"is_internal": True, "asset_class": [...]}
    requested_by: str          # 'scheduler' or user principal
    window_start: str          # ISO8601
    window_end: str            # ISO8601


@dataclass
class AuthToken:
    """Minted by the scope gate. Adapters MUST present and re-verify this
    before touching any host. Time-boxed and target-bound."""
    authz_id: str
    scan_request_id: str
    pipeline: Pipeline
    mode: ScanMode
    target_asset_ids: list[str]
    target_addrs: list[str]    # resolved IPs/URLs in scope (the allowlist)
    window_start: str
    window_end: str
    token_hash: str            # sha256 hex of the signed token
    signed_by: str


@dataclass
class CanonicalFinding:
    """The normalized finding shape produced by every adapter's parse()."""
    asset_id: str
    source_tool: str
    native_id: Optional[str]
    title: str
    description: Optional[str]
    cve: list[str] = field(default_factory=list)
    cvss_base: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity_normalized: Severity = Severity.INFO
    dedup_key: str = ""                 # asset + port + signature hash
    owasp_web: list[str] = field(default_factory=list)
    owasp_api: list[str] = field(default_factory=list)
    sans25: list[str] = field(default_factory=list)
    cis_control: Optional[str] = None
    asset_class_tag: Optional[str] = None
    auth_context: Optional[AuthContextName] = None
    # Populated by the triage engine, not the adapters:
    fp_likelihood: Optional[float] = None
    fp_reason: Optional[str] = None
    dup_of: Optional[str] = None
    impact_note: Optional[str] = None
    remediation_note: Optional[str] = None
    detected_at: str = ""               # ISO8601; set when first detected


@dataclass
class RawArtifact:
    """Pointer to the immutable raw output of a scanner run."""
    scan_id: str
    source_tool: str
    uri: str                            # object-store (MinIO/S3) location
    native_format: str                  # 'nessus-xml', 'burp-json', etc.


@dataclass
class ReportBundle:
    scan_id: str
    xlsx_uri: str
    docx_uri: str
    pdf_uri: str                        # dual-password protected
