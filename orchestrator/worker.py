"""
Temporal worker — registers the two pipeline workflows and all activities.

Run (Phase 0/1 dev):
    python worker.py

In production this runs as a hardened service account inside the security
enclave, talking to an on-prem Temporal cluster. Task queue is split so
infra and webapp scans can be scaled / isolated independently.
"""
from __future__ import annotations

import asyncio
import logging

from temporalio.client import Client
from temporalio.worker import Worker

import activities as act
from workflows import InfraScanWorkflow, WebAppScanWorkflow

TASK_QUEUE = "scanner-pipelines"
TEMPORAL_TARGET = "temporal.internal:7233"   # on-prem

ACTIVITIES = [
    act.scope_gate_authorize,
    act.create_scan_record,
    act.record_phase,
    act.finalize_scan,
    act.run_recon,
    act.run_nmap,
    act.run_nessus_va,
    act.run_cis_review,
    act.run_nikto,
    act.run_burp_crawl,
    act.run_burp_scan,
    act.normalize_and_triage,
    act.generate_reports,
]


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    client = await Client.connect(TEMPORAL_TARGET, namespace="scanner")
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[InfraScanWorkflow, WebAppScanWorkflow],
        activities=ACTIVITIES,
    )
    logging.info("Scanner worker started on %s / %s", TEMPORAL_TARGET, TASK_QUEUE)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
