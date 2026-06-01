"""
ScannerAdapter contract.

Every engine (Nmap, Nessus, Burp, Nikto, and the OSS set ZAP/Nuclei/Trivy)
implements this. The orchestrator only knows this interface — swapping the
licensed set for the OSS set is a config change, not a code change.

Security contract every adapter MUST honor:
  * preflight(token): re-verify scope at the moment of use; refuse any
    target not in token.target_addrs (fail closed).
  * never expose an "exploit" verb. The only verbs are discover / enumerate
    / detect / fetch / parse.
  * lease credentials from the vault at launch; never read them from config
    or persist them.
"""
from __future__ import annotations

from typing import Any, Protocol

from shared import AuthToken, RawArtifact, CanonicalFinding


class ScannerAdapter(Protocol):
    name: str

    def preflight(self, token: AuthToken) -> None:
        """Re-verify authorization + intersect targets with the allowlist.
        Raise (fail closed) if anything is out of scope or expired."""
        ...

    def launch(self, targets: list[str], **kwargs: Any) -> str:
        """Start the scan. Returns an opaque job handle."""
        ...

    def wait(self, handle: str) -> None:
        """Block until the engine job reaches a terminal state."""
        ...

    def fetch_raw(self, handle: str) -> RawArtifact:
        """Retrieve native output and store it immutably (object store)."""
        ...

    def parse(self, raw: RawArtifact) -> list[CanonicalFinding]:
        """Parse native output into the canonical finding schema."""
        ...


def assert_targets_in_scope(targets: list[str], token: AuthToken) -> None:
    """Shared guard: every target must be in the token allowlist."""
    allow = set(token.target_addrs)
    rogue = [t for t in targets if t not in allow]
    if rogue:
        raise PermissionError(
            f"Out-of-scope targets refused by adapter: {rogue}"
        )
