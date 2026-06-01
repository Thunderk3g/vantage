"""
Nikto adapter — CLI (XML output) for web recon / fingerprinting.

Detection only (server/version/known-misconfig). Parses XML with defusedxml.
"""
from __future__ import annotations

import defusedxml.ElementTree as ET

from shared import AuthToken, RawArtifact, CanonicalFinding, Severity
from .base import assert_targets_in_scope


class NiktoAdapter:
    name = "nikto"

    def preflight(self, token: AuthToken) -> None:
        assert_targets_in_scope(token.target_addrs, token)

    def launch(self, targets: list[str], **kw) -> str:
        # subprocess: nikto -h <url> -o out.xml -Format xml  (per target)
        raise NotImplementedError("wire to nikto CLI")

    def wait(self, handle: str) -> None: ...
    def fetch_raw(self, handle: str) -> RawArtifact: ...

    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        tree = ET.parse(_local_copy(raw.uri))
        out: list[CanonicalFinding] = []
        for item in tree.iterfind(".//item"):
            out.append(CanonicalFinding(
                asset_id=_asset_id_for(raw),
                source_tool=self.name,
                native_id=item.get("id"),
                title=(item.findtext("description") or "").strip()[:120],
                description=item.findtext("description"),
                severity_normalized=Severity.LOW,   # refined in triage
                dedup_key=f"{item.get('id')}|{item.findtext('uri')}",
            ))
        return out


def _local_copy(uri: str) -> str: ...
def _asset_id_for(raw: RawArtifact) -> str: ...
