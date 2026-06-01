// Generates docs/architecture.docx — the architecture & build plan.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, LevelFormat, HeadingLevel, BorderStyle, WidthType, ShadingType,
  TableOfContents, PageBreak, Header, Footer, PageNumber,
} = require("docx");

const CONTENT_W = 9360; // US Letter, 1" margins
const NAVY = "1F3864", BLUE = "2E75B6", LIGHT = "D9E2F3", GREY = "F2F2F2";

// ---- helpers ---------------------------------------------------------
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)] });
const P = (t, opts = {}) => new Paragraph({ spacing: { after: 120 }, children: runs(t), ...opts });
function runs(t) {
  if (Array.isArray(t)) return t;
  return [new TextRun(t)];
}
const B = (t) => new TextRun({ text: t, bold: true });
const T = (t) => new TextRun(t);
const bullet = (t) => new Paragraph({ numbering: { reference: "bul", level: 0 }, spacing: { after: 60 }, children: runs(t) });
const num = (t) => new Paragraph({ numbering: { reference: "num", level: 0 }, spacing: { after: 60 }, children: runs(t) });
const mono = (t) => new Paragraph({ spacing: { after: 120 }, shading: { fill: GREY, type: ShadingType.CLEAR },
  children: [new TextRun({ text: t, font: "Consolas", size: 18 })] });

function codeBlock(text) {
  return text.split("\n").map((line) => new Paragraph({
    spacing: { after: 0 }, shading: { fill: "1B1B1B", type: ShadingType.CLEAR },
    children: [new TextRun({ text: line || " ", font: "Consolas", size: 16, color: "D6E9C6" })],
  }));
}

const cellBorder = { style: BorderStyle.SINGLE, size: 1, color: "BFBFBF" };
const borders = { top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder };
function cell(text, w, { head = false, fill } = {}) {
  return new TableCell({
    borders, width: { size: w, type: WidthType.DXA },
    shading: { fill: fill || (head ? BLUE : "FFFFFF"), type: ShadingType.CLEAR },
    margins: { top: 60, bottom: 60, left: 110, right: 110 },
    children: (Array.isArray(text) ? text : [text]).map((t) =>
      new Paragraph({ children: [new TextRun({ text: t, bold: head, color: head ? "FFFFFF" : "000000", size: 18 })] })),
  });
}
function table(widths, rows) {
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: widths,
    rows: rows.map((r, i) => new TableRow({
      tableHeader: i === 0,
      children: r.map((c, j) => cell(c, widths[j], { head: i === 0, fill: i === 0 ? undefined : (i % 2 ? GREY : "FFFFFF") })),
    })),
  });
}

// ===== document =======================================================
const children = [];

// Cover
children.push(
  new Paragraph({ spacing: { before: 2400, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "AI-Augmented Vulnerability Scanner", bold: true, size: 56, color: NAVY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
    children: [new TextRun({ text: "Architecture & Reference Implementation Plan", size: 30, color: BLUE })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "Internal InfoSec / AppSec Tooling", italics: true, size: 22 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "BFSI · IRDAI-regulated · ISO 27001:2022", size: 22 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 1600 },
    children: [new TextRun({ text: "CONFIDENTIAL — Internal Use Only", bold: true, size: 20, color: "C00000" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 240 },
    children: [new TextRun({ text: "Scan-and-report system. No exploitation. Human-gated validation.", italics: true, size: 18 })] }),
  new Paragraph({ children: [new PageBreak()] }),
);

// TOC
children.push(H1("Table of Contents"),
  new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-2" }),
  new Paragraph({ children: [new PageBreak()] }));

// 1. Scope & boundaries
children.push(H1("1. Scope, Boundaries & Assumptions"));
children.push(H2("1.1 Hard scope (non-negotiable)"));
children.push(
  bullet([B("Scan and report only. "), T("Detects, triages, reports. No exploitation, lateral movement, or auto-fix.")]),
  bullet([B("Human-gated validation. "), T("Produces a first-pass triaged result; human testers validate and perform any manual PT downstream.")]),
  bullet([B("Scope allowlist at every stage. "), T("Refuses any target absent from the HOD-approved asset inventory.")]),
  bullet([B("Authorized assets only. "), T("All targets are owned by the organization and approved for scanning.")]),
);
children.push(H2("1.2 Load-bearing assumptions"));
children.push(
  num([B("On-prem / private-VPC deployment "), T("inside the data centre — BFSI + IRDAI residency + ISO 27001 push this; egress is allowlisted (SMTP + ITSM only).")]),
  num([B("Self-hosted LLM "), T("(or a dedicated private endpoint) behind a redaction proxy — finding data does not leave the security enclave.")]),
  num([B("Hundreds–low-thousands of hosts, "), T("single insurer entity — Postgres-class datastore, not big-data.")]),
  num([B("Existing identity + vault "), T("(AD/LDAP + SSO, and CyberArk or HashiCorp Vault).")]),
  num([B("Permanent boundary: "), T("exploitation / lateral movement / auto-remediation are absent from the design, not feature-flagged off.")]),
);

// 2. Component diagram & data flow
children.push(new Paragraph({ children: [new PageBreak()] }), H1("2. Component Diagram & Data Flow"));
children.push(P([B("Components: "), T("Scope Gate (authorization service), Scheduler, Orchestrator (durable workflow state machine), Scanner Adapters, Normalization Engine, AI Triage Engine (+ redaction proxy + LLM), Datastore (Postgres + object store), Report Engine, SLA/Escalation Engine, Human Review UI, Notification Service, and an append-only hash-chained Audit Log.")]));
children.push(...codeBlock(
`             HOD-approved Asset Inventory  (system of record)
                         |
                    [ SCOPE GATE ]  <-- single chokepoint; no row = hard deny
                         |  signed, time-boxed authorization token
   SCHEDULER --> [ ORCHESTRATOR ] ----> [ SCANNER ADAPTERS ]
   (cadence)     durable DAG,           Nmap | Nessus(VA) | Nessus(CIS)
                 per-SOP phase          Burp | Nikto   (OSS: ZAP/Nuclei/Trivy)
                 gating; STOPS                 |  raw results (immutable)
                 at REPORT                     v
                         |             [ NORMALIZATION ENGINE ] -> canonical
                         v                     |
                 [ AI TRIAGE ENGINE ] <----> [ LLM (self-hosted) ]
                 dedup / FP / severity        via redaction proxy
                 OWASP-SANS-CIS map /
                 SLA assign / notes
                         |
            +------------+-------------------------------+
            v            v               v               v
     [ DATASTORE ]  [ REPORT ENG ]  [ SLA/ESCAL ]  [ HUMAN REVIEW UI ]
     PG + objstore  xlsx/docx/2pw   staircase       validate / FP / exception
            |            pdf             |
            v                            v
     [ AUDIT LOG ]              [ NOTIFICATION SVC ] -> email / Teams / ITSM
     append-only, hash-chained, WORM-anchored`));
children.push(H2("2.1 Primary data flow (one scan)"));
children.push(
  num("Scheduler fires a scan request (still unauthorized)."),
  num("Scope Gate resolves targets against the approved inventory; mints a signed, time-boxed authorization token (fail closed)."),
  num("Orchestrator runs SOP phases in order; each adapter re-verifies scope at use time (TOCTOU defense)."),
  num("Raw results land in the immutable object store; Normalization canonicalizes them."),
  num("AI Triage runs deterministic rules first, then a redacted LLM batch pass; findings are deduped, FP-scored, severity-normalized, SLA-stamped, and mapped."),
  num("Human review gate; then Report and SLA/Escalation engines run. Every transition is audited."),
);

// 3. Tech stack & LLM
children.push(new Paragraph({ children: [new PageBreak()] }), H1("3. Tech Stack & LLM Invocation"));
children.push(table([2400, 2600, 4360], [
  ["Layer", "Choice", "Justification"],
  ["Orchestration", "Python 3.12 + FastAPI; Temporal", "Durable, resumable, auditable workflow state; native phase gating and hard stops."],
  ["Datastore", "PostgreSQL 16 (pgcrypto, RLS)", "Relational integrity across assets-scans-findings-SLAs-exceptions; on-prem, auditable."],
  ["Object store", "MinIO (S3-compatible) + object-lock", "Immutable raw artifacts and reports (evidence)."],
  ["Reporting", "openpyxl, python-docx, WeasyPrint/ReportLab, pikepdf", "Pure-Python, no SaaS; pikepdf gives AES-256 dual-password PDF."],
  ["Secrets", "CyberArk or HashiCorp Vault", "Leased, short-lived credentials for gray-box auth contexts."],
  ["Identity", "AD/LDAP + SAML/OIDC SSO, RBAC", "Maps to analyst / manager / CISO / HOD roles."],
  ["LLM", "Self-hosted model behind redaction proxy", "Keeps sensitive recon in-enclave; satisfies ISO 27001 A.5.14 / A.8.12."],
  ["Audit", "Append-only hash-chained PG table -> WORM", "Tamper-evidence for IRDAI / ISO evidence."],
]));
children.push(H2("3.1 How the LLM is invoked"));
children.push(P([B("Deterministic-first, two-stage. "), T("The LLM is not the source of truth.")]));
children.push(
  bullet([B("Stage A (no LLM): "), T("dedup by composite key, severity from CVSS bands, SLA from severity, and OWASP/SANS/CIS mapping via lookup tables. ~80% of the work, fully reproducible.")]),
  bullet([B("Stage B (LLM, batch structured-output): "), T("fuzzy cross-tool dedup, false-positive likelihood + rationale, and drafting impact/remediation notes. Constrained JSON schema — not an autonomous tool-calling agent.")]),
);
children.push(P([B("Redaction proxy — what is stripped before the prompt: "), T("internal IPs/hostnames are pseudonymized (HOST_7, ASSET_42), credentials/sessions are never included, and raw exploit/PoC payloads are excluded (issue type + metadata only). Pseudonyms are re-expanded on return. The LLM cannot upgrade/downgrade severity outside the deterministic band — it can only flag for human review.")]));

// 4. Adapter design
children.push(new Paragraph({ children: [new PageBreak()] }), H1("4. Scanner Adapter Design"));
children.push(P([T("Common contract — "), B("preflight"), T(" (re-verify scope), "), B("launch"), T(", "), B("wait"), T(", "), B("fetch_raw"), T(" (store immutably), "), B("parse"), T(" (-> canonical finding). Every adapter re-checks scope at launch, not just at schedule time.")]));
children.push(table([1700, 1500, 1700, 4460], [
  ["Engine", "Interface", "Auth", "Notes"],
  ["Nmap", "CLI (-oX XML)", "none", "Host discovery, port scan, service/version. Safe NSE categories only — no exploit/intrusive/dos."],
  ["Nessus Pro", "REST API", "API keys (vault)", "Drives both VA and CIS compliance policies; .nessus XML parsed with defusedxml."],
  ["CIS review", "Nessus compliance", "least-priv audit creds (vault)", "Credentialed; annual cadence; results carry CIS control IDs."],
  ["Burp Pro", "REST API", "session profiles per context (vault)", "Spider/crawl in 3 auth contexts + automated scan; maps to OWASP."],
  ["Nikto", "CLI (XML)", "optional", "Recon + fingerprinting."],
  ["OSS variant", "ZAP/Nuclei/Trivy", "varies", "Same phases; swap is config, not code."],
]));

// 5. Data model
children.push(new Paragraph({ children: [new PageBreak()] }), H1("5. Data Model"));
children.push(P("Core tables (full DDL in db/schema.sql). Invariants are enforced at the DB layer, not just in app code:"));
children.push(table([2200, 7160], [
  ["Table", "Purpose & enforced invariant"],
  ["assets", "HOD-approved inventory; the scope gate's source of truth."],
  ["scope_authorizations", "The gate's ledger; one valid, time-boxed token per scan; stores token hash only."],
  ["scans", "One pipeline run. phase enum has NO exploit value; report is terminal."],
  ["findings", "Canonical deduped finding; dup_of links suppressed duplicates; unique dedup_key per scan."],
  ["slas", "due_date set by TRIGGER from severity (Crit/High +30d, Med/Low +60d). Not hand-editable."],
  ["escalations", "Day0->Day2->Day4->Day8-10->Day15-20 staircase as trackable rows."],
  ["exceptions", "Duration->approver routing enforced by CHECK (CISO <=3mo, RMC >3-12mo, Board >12mo)."],
  ["retests", "Closure verification by diff against the prior scan."],
  ["audit_log", "Append-only, hash-chained (SHA-256); UPDATE/DELETE blocked by trigger."],
]));
children.push(H2("5.1 SLA rule (encoded as a trigger)"));
children.push(...codeBlock(
`due_date := detected_at + (sla_days_for(severity) || ' days')::interval
   Critical -> 30   High -> 30   Medium -> 60   Low -> 60`));

// 6. Secrets
children.push(new Paragraph({ children: [new PageBreak()] }), H1("6. Secrets, Gray-box Creds & Least Privilege"));
children.push(
  bullet([B("No secret in DB, config, or code. "), T("Adapters lease short-lived credentials from the vault at launch (referenced by creds_ref); leases auto-revoke at scan end.")]),
  bullet([B("Three web auth contexts "), T("-> three vault paths (unauth [none], min_priv, max_priv). Min/max accounts are purpose-built scanner identities, IP-pinned, rotated per window.")]),
  bullet([B("Credentialed infra/CIS scans "), T("use least-privilege audit accounts (Windows local-audit, Linux sudo-restricted) — never Domain Admin, never write/exploit rights.")]),
  bullet([B("Segregated service identities: "), T("the orchestrator can request scan creds but not report-signing keys; the report engine can read PDF passwords but not host creds.")]),
  bullet([B("PDF passwords "), T("generated per report from the vault and delivered out-of-band.")]),
);

// 7. Scheduler
children.push(H1("7. Scheduler (Cadence)"));
children.push(table([4680, 4680], [
  ["Cadence rule", "Schedule"],
  ["Internal IPs — black-box VA", "2x / year (H1 + H2 windows)"],
  ["Public IPs — gray-box VA", "2x / year, offset from internal"],
  ["CIS configuration review", "1x / year"],
  ["Web app scans", "Per SOP cadence, configurable per app"],
]));
children.push(P([T("Schedule is not authorization — every scheduled job still passes the scope gate. Target lists resolve against the live inventory at fire time, so newly-approved assets are included and de-approved ones drop out automatically. Blackout calendars protect peak settlement windows.")]));

// 8. HITL
children.push(new Paragraph({ children: [new PageBreak()] }), H1("8. Human-in-the-Loop Gates & Keeping Exploitation Out"));
children.push(
  num([B("Scope gate "), T("is the only entry; re-checked at launch.")]),
  num([B("Pipeline ends at REPORT. "), T("No exploitation phase exists in the state machine — it is absent, not disabled.")]),
  num([B("AI triage is advisory. "), T("It cannot suppress findings, change severity outside the band, or close anything.")]),
  num([B("Manual PT / validation is downstream and human-owned. "), T("The scanner produces inputs to PT, never performs it.")]),
  num([B("Risk acceptance "), T("requires the correct human approver (CISO / RMC / Board) by duration.")]),
  num([B("Everything is audited "), T("in the hash-chained log.")]),
);
children.push(H2("8.1 Escalation staircase"));
children.push(table([1700, 1700, 5960], [
  ["Stage", "Level", "Action"],
  ["Day 0", "Stakeholders", "Initial report to stakeholders."],
  ["Day 2", "Stakeholders", "First reminder."],
  ["Day 4", "+ Manager", "Second reminder + manager escalation."],
  ["Day 8–10", "+ HOD", "Third reminder + HOD escalation."],
  ["Day 15–20", "+ C-suite (ManCom)", "HOD + C-suite escalation."],
]));
children.push(H2("8.2 Exception routing"));
children.push(table([3120, 3120, 3120], [
  ["Duration", "Approver", "Notes"],
  ["Up to 3 months", "CISO", "—"],
  ["More than 3 months", "Risk Management Committee", "—"],
  ["More than 12 months", "Board of Directors", "Requires reassessment + reapproval, documented risk."],
]));

// 9. Reassessment + reports
children.push(H1("9. Reassessment / Retest & Report Export"));
children.push(P([B("Retest flow: "), T("a retest scan diffs new findings against the prior scan by dedup_key — fixed -> closure confirmed; still-present -> reopened (SLA clock continues from original detection, no reset); new -> fresh finding + SLA.")]));
children.push(P([B("Report export: "), T("Excel (findings register + SLA dashboard), Word (SOP-format narrative), and PDF. The PDF is encrypted with two passwords — a user password to open and an owner password (copy/modify/print disabled). Passwords are vault-sourced and delivered out-of-band.")]));

// 10. Phased plan
children.push(new Paragraph({ children: [new PageBreak()] }), H1("10. Phased Build Plan"));
children.push(table([1500, 1500, 6360], [
  ["Phase", "Duration", "Deliverable / exit criteria"],
  ["0 — Foundations", "2–3 wks", "Schema, scope gate + inventory import, vault, hash-chained audit, RBAC/SSO, Temporal skeleton. Exit: authorize/deny works; all actions audited."],
  ["1 — Infra MVP", "3–4 wks", "Nmap + Nessus(VA), normalization, deterministic triage (dedup+severity+SLA), Excel report. Exit: end-to-end internal black-box scan, human-validated."],
  ["2 — Web MVP", "3–4 wks", "Nikto + Burp, 3 auth contexts, OWASP/SANS maps, Word + 2-password PDF. Exit: web pipeline parity."],
  ["3 — AI triage", "3 wks", "Redaction proxy + self-hosted LLM, batch dedup/FP/notes reconciled to bands. Exit: measurable FP reduction with explainability."],
  ["4 — Governance", "3 wks", "Escalation staircase, exception routing, retest/diff, notifications + ITSM, scheduler cadence. Exit: full lifecycle running."],
  ["5 — OSS + hardening", "2–3 wks", "ZAP/Nuclei/Trivy at parity, pen-test of the tool itself, ISO 27001 evidence pack, DR/backup. Exit: audit-ready."],
]));

children.push(new Paragraph({ spacing: { before: 240 },
  children: [new TextRun({ text: "Open item that could change the architecture: ", bold: true }),
    new TextRun("the design assumes a self-hosted LLM inside the enclave. A managed/cloud LLM would make the redaction proxy a hard compliance control and add a DPIA + no-train/no-retain attestation, but the component shape is unchanged.")] }));

// ---- assemble --------------------------------------------------------
const doc = new Document({
  styles: {
    default: { document: { run: { font: "Calibri", size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, color: NAVY, font: "Calibri" },
        paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 25, bold: true, color: BLUE, font: "Calibri" },
        paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, color: "404040", font: "Calibri" },
        paragraph: { spacing: { before: 160, after: 80 }, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bul", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 540, hanging: 260 } } } }] },
      { reference: "num", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 540, hanging: 260 } } } }] },
    ],
  },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
      border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: BLUE, space: 2 } },
      children: [new TextRun({ text: "AI-Augmented Vulnerability Scanner — Architecture", size: 16, color: "808080" })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: "CONFIDENTIAL — Internal Use Only   |   Page ", size: 16, color: "808080" }),
        new TextRun({ children: [PageNumber.CURRENT], size: 16, color: "808080" })] })] }) },
    children,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(__dirname + "/architecture.docx", buf);
  console.log("WROTE architecture.docx (" + buf.length + " bytes)");
});
