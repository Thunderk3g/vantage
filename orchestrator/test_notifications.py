"""
Runnable self-test for the notification-dispatch service.

Plain asserts + a __main__ block -- no pytest required. Run either of:

    python orchestrator/test_notifications.py
    python -m test_notifications          # with orchestrator/ on sys.path

Covers the behaviours called out in the build spec:
  * a Notifier([InMemorySink()]) dispatches -> sink.sent has 1, channel listed,
  * idempotency: same (finding_id, stage) -> deduped True, no re-emit; a
    different stage for the same finding is NOT deduped,
  * WebhookSink with no URL -> success + Jira-ish build_payload, no network,
  * WebhookSink with a bogus URL + post=True -> emit False (fail soft), no raise,
    and the Notifier still returns a result (sink absent from channels),
  * notify_escalations over 2 due records (one overdue, one due-not-overdue) ->
    2 notifications mentioning the role + overdue/due wording; a duplicate
    record in the list is deduped.

No real *successful* network call is made -- only the fail-soft bogus-URL path
with a tiny timeout, asserted to return False without raising.
"""
from __future__ import annotations

import os
import sys

# Make the service importable whether run as a script or a module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # orchestrator/

from notifications import (  # noqa: E402
    InMemorySink,
    LogSink,
    Notification,
    Notifier,
    WebhookSink,
)


def _mk(finding_id="VLN-2074", stage=1, role="Security Manager",
        severity="critical", deadline="2026-05-26",
        message="VLN-2074 (critical) is 6d overdue -- escalate to Security Manager"):
    return Notification(
        kind="escalation", finding_id=finding_id, stage=stage, role=role,
        severity=severity, deadline=deadline, message=message,
    )


def test_dispatch_to_inmemory():
    mem = InMemorySink()
    notifier = Notifier([mem])
    res = notifier.notify(_mk())

    assert res["deduped"] is False
    assert len(mem.sent) == 1, f"expected 1 sent, got {len(mem.sent)}"
    assert mem.name in res["channels"], res["channels"]
    # ts auto-filled, and the asdict round-trips.
    assert res["notification"]["finding_id"] == "VLN-2074"
    assert mem.sent[0].ts, "ts should be auto-filled at creation"
    print("  [ok] Notifier([InMemorySink]) dispatches -> sent=1, channel listed")


def test_idempotency():
    mem = InMemorySink()
    notifier = Notifier([mem])

    first = notifier.notify(_mk(finding_id="VLN-2074", stage=1))
    assert first["deduped"] is False
    assert len(mem.sent) == 1

    # SAME (finding_id, stage) -> deduped, no re-emit.
    again = notifier.notify(_mk(finding_id="VLN-2074", stage=1))
    assert again["deduped"] is True, again
    assert again["channels"] == [], again["channels"]
    assert len(mem.sent) == 1, "deduped dispatch must NOT re-emit to the sink"

    # DIFFERENT stage, same finding -> NOT deduped.
    diff = notifier.notify(_mk(finding_id="VLN-2074", stage=2))
    assert diff["deduped"] is False, diff
    assert mem.name in diff["channels"]
    assert len(mem.sent) == 2, "a new (finding_id, stage) must emit"
    print("  [ok] dedupe on (finding_id, stage); different stage re-emits")


def test_webhook_no_url_payload_shape():
    hook = WebhookSink(url=None)  # stub mode, no network
    notifier = Notifier([hook])
    res = notifier.notify(_mk(finding_id="VLN-9001", severity="high",
                              role="CISO"))

    assert res["deduped"] is False
    assert hook.name in res["channels"], "no-URL webhook should succeed"

    payload = hook.build_payload(_mk(finding_id="VLN-9001", severity="high",
                                     role="CISO"))
    # Jira-ish shape.
    assert set(["summary", "description", "labels", "fields"]) <= set(payload)
    assert payload["fields"]["finding"] == "VLN-9001"
    assert payload["fields"]["severity"] == "high"
    assert "high" in payload["labels"]
    assert "VLN-9001" in payload["summary"]
    # The emit recorded the intended payload (audit/UI), no network attempted.
    assert hook.last_payload is not None
    assert hook.last_payload["fields"]["finding"] == "VLN-9001"
    assert len(hook.payloads) == 1
    print("  [ok] WebhookSink no-URL: success + Jira-ish payload, no network")


def test_webhook_bogus_url_fail_soft():
    # Unreachable address + tiny timeout. post=True forces the real POST path.
    # http://127.0.0.1:9 -> the 'discard' port; nothing listens. Must FAIL SOFT.
    hook = WebhookSink(url="http://127.0.0.1:9/vantage", post=True,
                       timeout=0.001)
    # emit must NOT raise and must return False.
    raised = False
    try:
        ok = hook.emit(_mk())
    except Exception as exc:  # pragma: no cover - this is the bug we guard
        raised = True
        ok = None
        print("    !! emit raised:", exc)
    assert raised is False, "emit must never raise (fail soft)"
    assert ok is False, "bogus-URL POST must return False"

    # The Notifier still returns a clean result; the sink is just absent.
    notifier = Notifier([hook, InMemorySink()])
    res = notifier.notify(_mk(finding_id="VLN-7777"))
    assert res["deduped"] is False
    assert hook.name not in res["channels"], "failed webhook must not be listed"
    assert "memory" in res["channels"], "the in-memory sink still accepts"
    print("  [ok] WebhookSink bogus URL: fail-soft False, no raise, result OK")


def test_notify_escalations():
    # Records in the escalation-engine shape. daysLeft < 0 == overdue.
    overdue_rec = {
        "id": "VLN-2074", "escStage": 2, "role": "CISO", "severity": "critical",
        "deadline": "2026-05-26", "title": "BOLA on /v1/claims/{id}",
        "daysLeft": -6,
    }
    due_rec = {
        "id": "VLN-3300", "escStage": 1, "role": "Security Manager",
        "severity": "high", "deadline": "2026-06-05",
        "title": "Missing rate limiting on OTP", "daysLeft": 3,
    }
    # A duplicate of the first record -> must be deduped.
    dup_of_overdue = dict(overdue_rec)

    mem = InMemorySink()
    notifier = Notifier([mem, LogSink()])
    results = notifier.notify_escalations([overdue_rec, due_rec, dup_of_overdue])

    assert len(results) == 3, f"one result per record, got {len(results)}"

    # First record is the overdue one; the third is its duplicate. Index by
    # position so the duplicate doesn't shadow the original in a dict.
    over = results[0]
    due = results[1]
    assert over["notification"]["finding_id"] == "VLN-2074"
    assert due["notification"]["finding_id"] == "VLN-3300"

    # Overdue one: message mentions role + 'overdue'.
    assert over["deduped"] is False
    msg = over["notification"]["message"]
    assert "CISO" in msg and "overdue" in msg, msg
    assert "6d overdue" in msg, msg
    assert over["notification"]["stage"] == 2

    # Due-not-overdue: message mentions role + 'due' wording, not 'overdue'.
    dmsg = due["notification"]["message"]
    assert "Security Manager" in dmsg, dmsg
    assert "due" in dmsg and "overdue" not in dmsg, dmsg

    # Third record (duplicate of overdue) -> deduped, no re-emit.
    assert results[2]["deduped"] is True, results[2]
    assert results[2]["channels"] == []

    # Only the two unique escalations actually hit the in-memory sink.
    assert len(mem.sent) == 2, f"expected 2 emitted, got {len(mem.sent)}"
    print("  [ok] notify_escalations: 2 dispatched + role/overdue wording, dup deduped")


def main():
    tests = [
        test_dispatch_to_inmemory,
        test_idempotency,
        test_webhook_no_url_payload_shape,
        test_webhook_bogus_url_fail_soft,
        test_notify_escalations,
    ]
    print("Running notification-dispatch self-test...\n")
    for t in tests:
        t()
    print("\nALL NOTIFICATION TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
