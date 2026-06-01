"""
Temporal workflows — the SOP pipelines.

Two durable workflows, one per SOP:
  * InfraScanWorkflow : Nmap + Nessus(VA) + CIS config review
  * WebAppScanWorkflow: Nikto + Burp (3 auth contexts)
  (OSS variant swaps the engine_set; phases are identical.)

HARD BOUNDARY
-------------
Both workflows terminate at Phase.REPORT. There is no activity, signal, or
branch that performs exploitation, lateral movement, or auto-remediation.
The phase sequence is fixed and validated; `report` is terminal. This is the
in-code expression of "stop before any exploitation phase".

Every phase transition is persisted and audited via activities so the scan
state is fully reconstructable for IRDAI / ISO 27001 evidence.
"""
from __future__ import annotations

from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared import (
        ScanRequest, AuthToken, Pipeline, Phase, AuthContextName,
    )
    import activities as act


# Phases that may ever run, in order. `report` is terminal; nothing follows
# except the bookkeeping `done`. Enforced by _advance() below.
_INFRA_PHASES = [
    Phase.SCOPE, Phase.RECON, Phase.MAPPING, Phase.DETECTION, Phase.CIS,
    Phase.TRIAGE, Phase.REPORT,
]
_WEBAPP_PHASES = [
    Phase.SCOPE, Phase.RECON, Phase.MAPPING, Phase.DETECTION,
    Phase.TRIAGE, Phase.REPORT,
]

_DEFAULT_RETRY = RetryPolicy(maximum_attempts=3, backoff_coefficient=2.0)
_SHORT = timedelta(minutes=10)
_LONG = timedelta(hours=6)            # scans can run long


def _assert_no_exploit(phase: Phase) -> None:
    """Defense in depth: there is no exploit phase, but assert it loudly
    in case someone adds one to the enum later."""
    forbidden = {"exploit", "post_exploit", "lateral", "remediate"}
    if phase.value in forbidden:
        raise workflow.ApplicationError(
            f"Phase '{phase.value}' is forbidden: this system scans and "
            f"reports only.", non_retryable=True,
        )


@workflow.defn
class InfraScanWorkflow:
    """Infrastructure SOP pipeline (Nessus VA + CIS + Nmap)."""

    @workflow.run
    async def run(self, req: ScanRequest) -> str:
        # --- Phase: SCOPE GATE (mandatory first gate) -------------------
        token: AuthToken = await workflow.execute_activity(
            act.scope_gate_authorize, req,
            start_to_close_timeout=_SHORT, retry_policy=_DEFAULT_RETRY,
        )
        scan_id = await workflow.execute_activity(
            act.create_scan_record, args=[req, token],
            start_to_close_timeout=_SHORT,
        )

        async def advance(phase: Phase) -> None:
            _assert_no_exploit(phase)
            await workflow.execute_activity(
                act.record_phase, args=[scan_id, phase.value],
                start_to_close_timeout=_SHORT,
            )

        # --- Phase: RECON / footprinting --------------------------------
        await advance(Phase.RECON)
        await workflow.execute_activity(
            act.run_recon, args=[scan_id, token],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: MAPPING (Nmap live-host + port + service/version) ---
        await advance(Phase.MAPPING)
        await workflow.execute_activity(
            act.run_nmap, args=[scan_id, token],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: DETECTION (Nessus VA) -------------------------------
        await advance(Phase.DETECTION)
        await workflow.execute_activity(
            act.run_nessus_va, args=[scan_id, token],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: CIS configuration review (credentialed) -------------
        await advance(Phase.CIS)
        await workflow.execute_activity(
            act.run_cis_review, args=[scan_id, token],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: TRIAGE (normalize -> dedup -> FP -> SLA) ------------
        await advance(Phase.TRIAGE)
        await workflow.execute_activity(
            act.normalize_and_triage, args=[scan_id],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: REPORT (terminal) -----------------------------------
        await advance(Phase.REPORT)
        await workflow.execute_activity(
            act.generate_reports, args=[scan_id],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # NOTE: workflow ends here. No exploitation/PT phase exists.
        # Human validation + manual PT happen downstream, human-gated.
        await workflow.execute_activity(
            act.finalize_scan, args=[scan_id],
            start_to_close_timeout=_SHORT,
        )
        return scan_id


@workflow.defn
class WebAppScanWorkflow:
    """Web application SOP pipeline (Nikto + Burp, 3 auth contexts)."""

    @workflow.run
    async def run(self, req: ScanRequest) -> str:
        token: AuthToken = await workflow.execute_activity(
            act.scope_gate_authorize, req,
            start_to_close_timeout=_SHORT, retry_policy=_DEFAULT_RETRY,
        )
        scan_id = await workflow.execute_activity(
            act.create_scan_record, args=[req, token],
            start_to_close_timeout=_SHORT,
        )

        async def advance(phase: Phase) -> None:
            _assert_no_exploit(phase)
            await workflow.execute_activity(
                act.record_phase, args=[scan_id, phase.value],
                start_to_close_timeout=_SHORT,
            )

        # --- Phase: RECON (Nikto + tech fingerprinting) -----------------
        await advance(Phase.RECON)
        await workflow.execute_activity(
            act.run_nikto, args=[scan_id, token],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: MAPPING (Burp spider crawl in 3 auth contexts) ------
        await advance(Phase.MAPPING)
        for ctx in (AuthContextName.UNAUTH,
                    AuthContextName.MIN_PRIV,
                    AuthContextName.MAX_PRIV):
            await workflow.execute_activity(
                act.run_burp_crawl, args=[scan_id, token, ctx.value],
                start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
            )

        # --- Phase: DETECTION (automated Burp scan) ---------------------
        await advance(Phase.DETECTION)
        await workflow.execute_activity(
            act.run_burp_scan, args=[scan_id, token],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: TRIAGE (dedup, FP reduction, OWASP/SANS mapping) ----
        await advance(Phase.TRIAGE)
        await workflow.execute_activity(
            act.normalize_and_triage, args=[scan_id],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # --- Phase: REPORT (terminal) -----------------------------------
        await advance(Phase.REPORT)
        await workflow.execute_activity(
            act.generate_reports, args=[scan_id],
            start_to_close_timeout=_LONG, retry_policy=_DEFAULT_RETRY,
        )

        # Stops before manual penetration testing — human-gated downstream.
        await workflow.execute_activity(
            act.finalize_scan, args=[scan_id],
            start_to_close_timeout=_SHORT,
        )
        return scan_id
