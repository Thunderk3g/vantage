"""
Notification-dispatch service for the Vantage vulnerability-scanner platform.

Takes governance events (e.g. an overdue-finding escalation produced by the
escalation engine) and dispatches them to pluggable *sinks*:

  * ``LogSink``      — logs via ``logging.getLogger("vantage.notifications")``.
  * ``InMemorySink`` — appends to ``.sent`` (audit / UI / tests).
  * ``WebhookSink``  — an ITSM/webhook stub that builds a Jira/ServiceNow-style
                       JSON payload. If a URL is configured AND a real POST is
                       requested it POSTs via ``urllib`` (short timeout); on ANY
                       error it returns ``False`` (FAIL SOFT). With no URL it just
                       records the intended payload and returns ``True`` — no
                       network.

Design rules:
  * Pure stdlib (``urllib``/``json``/``logging``/``dataclasses``/``datetime``).
  * No real network calls unless a URL is configured.
  * Nothing here ever raises into the caller — a sink failure is swallowed and
    that sink simply isn't listed in the result's ``channels``.
  * The ``Notifier`` carries a per-instance dedupe ledger: a ``(finding_id,
    stage)`` already dispatched in this Notifier's lifetime is skipped.
  * Decoupled from the escalation module: it consumes plain ``dict`` records.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib import error as urlerror
from urllib import request as urlrequest

logger = logging.getLogger("vantage.notifications")


def _now_iso() -> str:
    """UTC ISO8601 timestamp, seconds precision, Z-suffixed."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


@dataclass
class Notification:
    """A single governance event ready for dispatch."""

    kind: str            # e.g. "escalation"
    finding_id: str
    stage: int
    role: str            # who it escalates to ("Security Manager", "CISO", ...)
    severity: str
    deadline: str | None
    message: str
    ts: str = ""         # ISO8601; filled at creation if empty

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = _now_iso()


# --------------------------------------------------------------------------- #
# Sinks. Each implements emit(n) -> bool (True on success) and never raises.
# --------------------------------------------------------------------------- #
class LogSink:
    """Logs each notification via the ``vantage.notifications`` logger."""

    name = "log"

    def __init__(self, level: int = logging.INFO):
        self.level = level

    def emit(self, n: Notification) -> bool:
        try:
            logger.log(
                self.level,
                "vantage.notification kind=%s finding=%s stage=%s role=%s "
                "severity=%s :: %s",
                n.kind, n.finding_id, n.stage, n.role, n.severity, n.message,
            )
            return True
        except Exception:  # pragma: no cover - logging shouldn't fail
            return False


class InMemorySink:
    """Collects notifications in ``.sent`` for tests / audit / UI."""

    name = "memory"

    def __init__(self):
        self.sent: list[Notification] = []

    def emit(self, n: Notification) -> bool:
        try:
            self.sent.append(n)
            return True
        except Exception:  # pragma: no cover
            return False


class WebhookSink:
    """ITSM/webhook stub (Jira / ServiceNow style).

    * ``build_payload(n)`` produces a Jira-ish dict regardless of network.
    * If no ``url`` is set (or ``post=False``), the intended payload is recorded
      in ``.payloads`` / ``.last_payload`` and ``emit`` returns ``True`` WITHOUT
      touching the network.
    * If ``url`` is set and ``post=True``, it POSTs via ``urllib`` with a short
      timeout. On ANY error it returns ``False`` (fail soft) — never raises.
    """

    name = "webhook"

    def __init__(
        self,
        url: str | None = None,
        *,
        post: bool = False,
        timeout: float = 0.001,
        labels: list[str] | None = None,
    ):
        self.url = url
        self.post = post
        self.timeout = timeout
        self.labels = labels or ["vantage", "governance"]
        self.payloads: list[dict] = []
        self.last_payload: dict | None = None

    def build_payload(self, n: Notification) -> dict:
        """Build a Jira/ServiceNow-ish JSON payload from a Notification."""
        return {
            "summary": f"[{n.kind}] {n.finding_id} ({n.severity}) -> {n.role}",
            "description": n.message,
            "labels": list(self.labels) + [n.severity, n.kind],
            "fields": {
                "severity": n.severity,
                "finding": n.finding_id,
                "stage": n.stage,
                "role": n.role,
                "deadline": n.deadline,
                "kind": n.kind,
                "ts": n.ts,
            },
        }

    def emit(self, n: Notification) -> bool:
        # Always build + record the intended payload (useful for audit/UI/tests).
        try:
            payload = self.build_payload(n)
            self.last_payload = payload
            self.payloads.append(payload)
        except Exception:
            return False

        # No URL, or POST not requested -> stub mode, no network.
        if not self.url or not self.post:
            return True

        # Real POST path — FAIL SOFT on anything.
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urlrequest.Request(
                self.url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlrequest.urlopen(req, timeout=self.timeout) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
                return 200 <= int(code) < 300
        except (urlerror.URLError, urlerror.HTTPError, OSError, ValueError,
                Exception):
            # Swallow EVERYTHING — never raise into the caller.
            logger.warning(
                "webhook POST failed for %s (fail-soft, no raise)", n.finding_id
            )
            return False


# --------------------------------------------------------------------------- #
# Notifier
# --------------------------------------------------------------------------- #
class Notifier:
    """Dispatches notifications to all sinks with per-instance idempotency."""

    def __init__(self, sinks: list):
        self.sinks = list(sinks)
        # Dedupe ledger: (finding_id, stage) pairs already dispatched.
        self._seen: set[tuple[str, int]] = set()

    def _sink_name(self, sink, idx: int) -> str:
        return getattr(sink, "name", None) or f"{type(sink).__name__}#{idx}"

    def notify(self, n: Notification) -> dict:
        """Dispatch ONE notification to all sinks, with idempotency.

        A ``(finding_id, stage)`` already sent in this Notifier's lifetime is
        SKIPPED (deduped) and NOT re-emitted. Returns::

            {"notification": <asdict>, "channels": [accepted sink names],
             "deduped": bool}
        """
        key = (n.finding_id, n.stage)
        if key in self._seen:
            return {
                "notification": asdict(n),
                "channels": [],
                "deduped": True,
            }

        self._seen.add(key)
        channels: list[str] = []
        for idx, sink in enumerate(self.sinks):
            name = self._sink_name(sink, idx)
            try:
                ok = sink.emit(n)
            except Exception:
                # A sink that raises despite the contract: swallow it.
                logger.warning("sink %s raised; swallowed (fail-soft)", name)
                ok = False
            if ok:
                channels.append(name)

        return {
            "notification": asdict(n),
            "channels": channels,
            "deduped": False,
        }

    def notify_escalations(self, due_records: list[dict]) -> list[dict]:
        """Build + dispatch an 'escalation' Notification per due record.

        Each record is the dict shape produced by the escalation engine:
        keys ``id`` / ``escStage`` / ``role`` / ``severity`` / ``deadline`` /
        ``title`` / ``daysLeft``. Records are read defensively with ``.get()``.
        Returns the per-notification results (deduped ones included, marked).
        """
        results: list[dict] = []
        for rec in due_records or []:
            rec = rec or {}
            finding_id = str(rec.get("id", "") or "")
            stage = rec.get("escStage", 0) or 0
            try:
                stage = int(stage)
            except (TypeError, ValueError):
                stage = 0
            role = rec.get("role", "") or "owner"
            severity = rec.get("severity", "") or "unknown"
            deadline = rec.get("deadline")
            title = rec.get("title", "") or finding_id
            days_left = rec.get("daysLeft")

            message = self._compose_message(
                finding_id, severity, role, days_left, title
            )

            n = Notification(
                kind="escalation",
                finding_id=finding_id,
                stage=stage,
                role=role,
                severity=severity,
                deadline=deadline,
                message=message,
            )
            results.append(self.notify(n))
        return results

    @staticmethod
    def _compose_message(
        finding_id: str, severity: str, role: str, days_left, title: str
    ) -> str:
        """Craft a clear escalation message from the record's daysLeft.

        e.g. 'VLN-2074 (critical) is 6d overdue -- escalate to CISO'
             'VLN-3300 (high) is due in 2d -- escalate to Security Manager'
        """
        try:
            dl = int(days_left)
        except (TypeError, ValueError):
            dl = None

        if dl is None:
            timing = "is due"
        elif dl < 0:
            timing = f"is {abs(dl)}d overdue"
        elif dl == 0:
            timing = "is due today"
        else:
            timing = f"is due in {dl}d"

        return f"{finding_id} ({severity}) {timing} -- escalate to {role}"
