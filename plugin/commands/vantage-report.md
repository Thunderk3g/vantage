---
description: Generate a Vantage report (audit|exec|asset|sla) for a scope
argument-hint: [template] [scope]
---

Generate a Vantage report. Parse `$ARGUMENTS` as `[template] [scope]`:
`$1` is the template (audit|exec|asset|sla) and `$2` is the scope
(`all` or an `AST-...` asset id).

Plan:
1. Confirm the template and scope from `$ARGUMENTS`. If either is missing or
   ambiguous, ask the human before generating. Default template `audit`,
   default scope `all`.
2. Confirm the formats wanted (subset of xlsx, docx, pdf). If a PDF is requested,
   REMIND the human that an open password and an owner password are both required
   and MUST differ (dual-password AES-256 PDF), then collect both before calling.
3. Call `mcp__vantage__generate_report` with `template`, `scope`, `formats`, and
   (for PDF) `open_password` / `owner_password`.
4. Return the `reportId` and the download path for each format. Note that
   downloads are owner-scoped (tied to the requesting owner).
