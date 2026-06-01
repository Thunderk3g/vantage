"""
Nikto adapter — CLI (XML output) for web recon / fingerprinting.

Detection only (server/version/known-misconfig). Parses XML with defusedxml.

Real `nikto -Format xml` output is shaped like:

    <niktoscan>
      <scandetails targetip="10.0.0.7" targethostname="app.internal"
                   targetport="443" ...>
        <item id="999957" osvdbid="..." method="GET">
          <description>...</description>
          <uri>/admin/</uri>
          <namelink>...</namelink>
        </item>
        ...
      </scandetails>
    </niktoscan>

So <item> lives under <scandetails>, and the scanned host/ip/port are
attributes on <scandetails> (not on each item). The target host is read
once from <scandetails> and used to derive a stable asset id for every
finding in the artifact.
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
        root = tree.getroot()

        # The scanned host lives on <scandetails>. Read it once and reuse it
        # for every finding. Fall back to a slug of the scan id if the
        # element/attrs are missing so parse() never crashes on odd input.
        scandetails = root.find(".//scandetails")
        host = ""
        if scandetails is not None:
            host = (
                scandetails.get("targethostname")
                or scandetails.get("targetip")
                or ""
            ).strip()
        asset_id = ("AST-" + host.replace(".", "-")) if host else _asset_id_for(raw)

        out: list[CanonicalFinding] = []
        for item in tree.iterfind(".//item"):
            native_id = item.get("id")
            description = item.findtext("description")
            uri = item.findtext("uri") or ""           # may be missing/empty
            title = (description or "").strip()[:120]
            out.append(CanonicalFinding(
                asset_id=asset_id,
                source_tool=self.name,
                native_id=native_id,
                title=title,
                description=description,
                severity_normalized=Severity.LOW,   # refined in triage
                dedup_key=f"{native_id}|{uri}",
            ))
        return out


def _local_copy(uri: str) -> str:
    """Resolve the raw artifact URI to a local, parseable path.

    The artifact is already materialized locally for parsing, so the URI is
    the path. Returned unchanged.
    """
    return uri


def _asset_id_for(raw: RawArtifact) -> str:
    """Deterministic asset-id fallback when the target host can't be read
    from the nikto XML. Derived purely from the artifact's scan id so it is
    stable and crash-free."""
    return "AST-" + (raw.scan_id or "unknown")
