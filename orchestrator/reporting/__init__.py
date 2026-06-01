"""Vantage reporting engine.

Exports findings to three artifacts:
  * Excel  (.xlsx) — register + SLA summary, via openpyxl
  * Word   (.docx) — SOP-style report, via python-docx
  * PDF    (.pdf)  — dual-password (user + owner), AES-256, via reportlab + pikepdf

Public surface:
  build_xlsx, build_docx, build_pdf, build_reports
"""

from .export import build_xlsx, build_docx, build_pdf, build_reports

__all__ = ["build_xlsx", "build_docx", "build_pdf", "build_reports"]
