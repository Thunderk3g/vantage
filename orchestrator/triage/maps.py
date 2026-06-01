"""
Deterministic lookup tables for the Vantage triage engine.

These are the rules-first knowledge base used by ``engine.map_categories`` to
attach framework taxonomy (OWASP Web Top 10 2021, OWASP API Top 10 2023, SANS/
CWE Top 25, CIS Controls v8) to a canonical finding WITHOUT any LLM.

Everything here is data, not logic. The engine resolves a finding to a
category in this order of precedence (most specific first):

    1. an explicit native id    (source_tool + native_id)   -> NATIVE_ID_MAP
    2. a tool-specific tag/type  (source_tool + tag/family)  -> TAG_MAP
    3. a CIS control id          (CIS-x.y on the finding)    -> CIS_CONTROL_MAP
    4. a keyword in the title    (last-resort heuristic)     -> KEYWORD_MAP

Each category value is a small dict with any of:
    owasp_web   : list[str]   e.g. ["A03:2021"]
    owasp_api   : list[str]   e.g. ["API1:2023"]
    sans25      : list[str]   CWE ids, e.g. ["CWE-89"]
    cis_control : str | None  e.g. "CIS-3.10"

To extend coverage you only add rows here; the engine needs no changes.
This deliberately mirrors the seed taxonomy in orchestrator/api/seed.py and
the ``findings`` columns (owasp_web/owasp_api/sans25/cis_control) in
db/schema.sql.
"""
from __future__ import annotations

# ---------------------------------------------------------------------
# Canonical framework code -> human-readable name (for notes / reports).
# Not used for matching; handy for downstream rendering and tests.
# ---------------------------------------------------------------------
OWASP_WEB_NAMES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

OWASP_API_NAMES = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server-Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

CIS_CONTROL_NAMES = {
    "CIS-3.10": "Encrypt Sensitive Data in Transit",
    "CIS-4.1": "Establish and Maintain a Secure Configuration Process",
    "CIS-4.8": "Uninstall or Disable Unnecessary Services",
    "CIS-5.2": "Use Unique Passwords",
    "CIS-7.4": "Perform Automated Application Patch Management",
}


# =====================================================================
# 1. NATIVE-ID MAP  — keyed on (source_tool, native_id)
#    Most specific: a known plugin id / issue type / template id maps
#    straight to its taxonomy. source_tool is lower-cased by the engine;
#    native_id is matched case-insensitively too.
#
#    Examples seeded:
#      * Nessus plugin ids (numeric strings)
#      * Burp issue types (numeric hex/int issue codes as strings)
#      * Nuclei template ids (slugs)
# =====================================================================
NATIVE_ID_MAP: dict[tuple[str, str], dict] = {
    # ---- Nessus (infra VA) plugin ids ----
    ("nessus", "11411"): {"cis_control": "CIS-4.8",
                          "owasp_web": ["A05:2021"]},            # backup files / dir listing
    ("nessus", "10107"): {"cis_control": "CIS-4.8"},             # HTTP server type / banner
    ("nessus", "104743"): {"cis_control": "CIS-3.10",
                           "owasp_web": ["A02:2021"]},           # TLS v1.0/1.1 detected
    ("nessus", "51192"): {"cis_control": "CIS-3.10",
                          "owasp_web": ["A02:2021"]},            # SSL cert cannot be trusted
    ("nessus", "57582"): {"cis_control": "CIS-3.10",
                          "owasp_web": ["A02:2021"]},            # self-signed cert
    ("nessus", "default-creds"): {"cis_control": "CIS-5.2",
                                  "owasp_web": ["A07:2021"],
                                  "sans25": ["CWE-798"]},        # default credentials

    # ---- Burp (web DAST) issue types ----
    ("burp", "1049088"): {"owasp_web": ["A03:2021"],
                          "sans25": ["CWE-89"]},                 # SQL injection
    ("burp", "2097920"): {"owasp_web": ["A03:2021"],
                          "sans25": ["CWE-79"]},                 # XSS (reflected)
    ("burp", "2097936"): {"owasp_web": ["A03:2021"],
                          "sans25": ["CWE-79"]},                 # XSS (stored)
    ("burp", "5243392"): {"owasp_web": ["A10:2021"],
                          "owasp_api": ["API7:2023"],
                          "sans25": ["CWE-918"]},                # SSRF
    ("burp", "8389120"): {"owasp_web": ["A01:2021"],
                          "owasp_api": ["API1:2023"]},           # IDOR / direct object ref

    # ---- Nuclei template ids (slugs) ----
    ("nuclei", "tls-version"): {"cis_control": "CIS-3.10",
                                "owasp_web": ["A02:2021"]},
    ("nuclei", "sqli-error-based"): {"owasp_web": ["A03:2021"],
                                     "sans25": ["CWE-89"]},
    ("nuclei", "open-redirect"): {"owasp_web": ["A01:2021"],
                                  "sans25": ["CWE-601"]},
    ("nuclei", "missing-csp-header"): {"owasp_web": ["A05:2021"]},
}


# =====================================================================
# 2. TAG MAP  — keyed on (source_tool, tag)
#    A tool-specific family / tag / category bucket. Coarser than a
#    native id but still authoritative. The engine looks at
#    finding["family"] (Nessus plugin family), finding["tags"]
#    (Nuclei tags list), and finding["issue_type"]/"family" generally.
#    Keys are lower-cased.
# =====================================================================
TAG_MAP: dict[tuple[str, str], dict] = {
    # Nessus plugin families
    ("nessus", "general"): {"cis_control": "CIS-4.1"},
    ("nessus", "service detection"): {"cis_control": "CIS-4.8"},
    ("nessus", "web servers"): {"owasp_web": ["A05:2021"],
                                "cis_control": "CIS-4.1"},
    ("nessus", "gain a shell remotely"): {"owasp_web": ["A06:2021"],
                                          "cis_control": "CIS-7.4",
                                          "sans25": ["CWE-1395"]},
    ("nessus", "misc."): {"cis_control": "CIS-4.1"},
    ("nessus", "settings"): {"cis_control": "CIS-4.1"},

    # Nuclei tags
    ("nuclei", "sqli"): {"owasp_web": ["A03:2021"], "sans25": ["CWE-89"]},
    ("nuclei", "xss"): {"owasp_web": ["A03:2021"], "sans25": ["CWE-79"]},
    ("nuclei", "ssrf"): {"owasp_web": ["A10:2021"],
                         "owasp_api": ["API7:2023"], "sans25": ["CWE-918"]},
    ("nuclei", "rce"): {"owasp_web": ["A03:2021"], "sans25": ["CWE-94"]},
    ("nuclei", "lfi"): {"owasp_web": ["A01:2021"], "sans25": ["CWE-22"]},
    ("nuclei", "redirect"): {"owasp_web": ["A01:2021"], "sans25": ["CWE-601"]},
    ("nuclei", "exposure"): {"owasp_web": ["A05:2021"], "sans25": ["CWE-200"]},
    ("nuclei", "default-login"): {"owasp_web": ["A07:2021"],
                                  "sans25": ["CWE-798"], "cis_control": "CIS-5.2"},
    ("nuclei", "tls"): {"owasp_web": ["A02:2021"], "cis_control": "CIS-3.10"},
    ("nuclei", "ssl"): {"owasp_web": ["A02:2021"], "cis_control": "CIS-3.10"},
    ("nuclei", "misconfig"): {"owasp_web": ["A05:2021"]},

    # ZAP alert families (open-source web DAST in the OSS engine set)
    ("zap", "sql injection"): {"owasp_web": ["A03:2021"], "sans25": ["CWE-89"]},
    ("zap", "cross site scripting"): {"owasp_web": ["A03:2021"],
                                      "sans25": ["CWE-79"]},
    ("zap", "external redirect"): {"owasp_web": ["A01:2021"],
                                   "sans25": ["CWE-601"]},
    ("zap", "path traversal"): {"owasp_web": ["A01:2021"], "sans25": ["CWE-22"]},
    ("zap", "remote os command injection"): {"owasp_web": ["A03:2021"],
                                             "sans25": ["CWE-78"]},

    # Trivy (SCA / image scanning) classes
    ("trivy", "vulnerability"): {"owasp_web": ["A06:2021"],
                                 "sans25": ["CWE-1395"]},
    ("trivy", "misconfiguration"): {"owasp_web": ["A05:2021"],
                                    "cis_control": "CIS-4.1"},
    ("trivy", "secret"): {"owasp_web": ["A07:2021"], "sans25": ["CWE-798"]},
}


# =====================================================================
# 3. CIS-CONTROL MAP  — keyed on the bare CIS control id present on the
#    finding (config / compliance findings from a credentialed CIS scan).
#    Maps the control to the OWASP class it most closely corresponds to,
#    so config findings still light up the web/api dashboards.
# =====================================================================
CIS_CONTROL_MAP: dict[str, dict] = {
    "CIS-3.10": {"owasp_web": ["A02:2021"], "cis_control": "CIS-3.10"},
    "CIS-4.1": {"owasp_web": ["A05:2021"], "cis_control": "CIS-4.1"},
    "CIS-4.8": {"owasp_web": ["A05:2021"], "cis_control": "CIS-4.8"},
    "CIS-5.2": {"owasp_web": ["A07:2021"], "sans25": ["CWE-798"],
                "cis_control": "CIS-5.2"},
    "CIS-7.4": {"owasp_web": ["A06:2021"], "sans25": ["CWE-1395"],
                "cis_control": "CIS-7.4"},
}


# =====================================================================
# 4. KEYWORD MAP  — last-resort heuristic over the finding title.
#    Ordered: the engine takes the FIRST substring that matches, so put
#    more specific phrases before generic ones. Lower-cased matching.
#    This is intentionally conservative — it only fires when nothing more
#    authoritative matched.
# =====================================================================
KEYWORD_MAP: list[tuple[str, dict]] = [
    ("bola",                  {"owasp_api": ["API1:2023"], "owasp_web": ["A01:2021"]}),
    ("broken object level",   {"owasp_api": ["API1:2023"], "owasp_web": ["A01:2021"]}),
    ("idor",                  {"owasp_api": ["API1:2023"], "owasp_web": ["A01:2021"]}),
    ("insecure direct object",{"owasp_api": ["API1:2023"], "owasp_web": ["A01:2021"]}),
    ("excessive data",        {"owasp_api": ["API3:2023"]}),
    ("object property level", {"owasp_api": ["API3:2023"]}),
    ("rate limit",            {"owasp_api": ["API4:2023"], "sans25": ["CWE-770"]}),
    ("resource consumption",  {"owasp_api": ["API4:2023"], "sans25": ["CWE-770"]}),
    ("deprecated api",        {"owasp_api": ["API9:2023"]}),
    ("api version",           {"owasp_api": ["API9:2023"]}),
    ("inventory management",  {"owasp_api": ["API9:2023"]}),

    ("sql injection",         {"owasp_web": ["A03:2021"], "sans25": ["CWE-89"]}),
    ("sqli",                  {"owasp_web": ["A03:2021"], "sans25": ["CWE-89"]}),
    ("command injection",     {"owasp_web": ["A03:2021"], "sans25": ["CWE-78"]}),
    ("xss",                   {"owasp_web": ["A03:2021"], "sans25": ["CWE-79"]}),
    ("cross-site scripting",  {"owasp_web": ["A03:2021"], "sans25": ["CWE-79"]}),
    ("cross site scripting",  {"owasp_web": ["A03:2021"], "sans25": ["CWE-79"]}),

    ("server-side request",   {"owasp_web": ["A10:2021"], "owasp_api": ["API7:2023"],
                               "sans25": ["CWE-918"]}),
    ("ssrf",                  {"owasp_web": ["A10:2021"], "owasp_api": ["API7:2023"],
                               "sans25": ["CWE-918"]}),

    ("hard-coded",            {"owasp_web": ["A07:2021"], "sans25": ["CWE-798"]}),
    ("hardcoded",             {"owasp_web": ["A07:2021"], "sans25": ["CWE-798"]}),
    ("encryption key",        {"owasp_web": ["A02:2021"], "sans25": ["CWE-798"]}),
    ("default admin",         {"owasp_web": ["A07:2021"], "sans25": ["CWE-798"],
                               "cis_control": "CIS-5.2"}),
    ("default credential",    {"owasp_web": ["A07:2021"], "sans25": ["CWE-798"],
                               "cis_control": "CIS-5.2"}),
    ("weak password",         {"owasp_web": ["A07:2021"], "sans25": ["CWE-521"]}),
    ("no mfa",                {"owasp_web": ["A07:2021"], "sans25": ["CWE-308"]}),
    ("mfa",                   {"owasp_web": ["A07:2021"]}),
    ("authentication",        {"owasp_web": ["A07:2021"], "owasp_api": ["API2:2023"]}),

    ("open redirect",         {"owasp_web": ["A01:2021"], "sans25": ["CWE-601"]}),
    ("access control",        {"owasp_web": ["A01:2021"]}),

    ("logged",                {"owasp_web": ["A09:2021"], "sans25": ["CWE-532"]}),
    ("logging",               {"owasp_web": ["A09:2021"]}),

    ("outdated",              {"owasp_web": ["A06:2021"], "sans25": ["CWE-1395"]}),
    ("vulnerable component",  {"owasp_web": ["A06:2021"], "sans25": ["CWE-1395"]}),
    ("unpatched",             {"owasp_web": ["A06:2021"], "cis_control": "CIS-7.4",
                               "sans25": ["CWE-1395"]}),
    ("cve-",                  {"owasp_web": ["A06:2021"], "cis_control": "CIS-7.4"}),

    ("tls 1.0",               {"owasp_web": ["A02:2021"], "cis_control": "CIS-3.10"}),
    ("tls 1.1",               {"owasp_web": ["A02:2021"], "cis_control": "CIS-3.10"}),
    ("cleartext",             {"owasp_web": ["A02:2021"], "cis_control": "CIS-3.10",
                               "sans25": ["CWE-319"]}),
    ("ssl",                   {"owasp_web": ["A02:2021"], "cis_control": "CIS-3.10"}),

    ("directory listing",     {"owasp_web": ["A05:2021"], "cis_control": "CIS-4.1"}),
    ("stack trace",           {"owasp_web": ["A05:2021"], "sans25": ["CWE-209"]}),
    ("security header",       {"owasp_web": ["A05:2021"]}),
    ("csp",                   {"owasp_web": ["A05:2021"]}),
    ("hsts",                  {"owasp_web": ["A05:2021"]}),
    ("cookie",                {"owasp_web": ["A05:2021"], "sans25": ["CWE-614"]}),
    ("misconfiguration",      {"owasp_web": ["A05:2021"]}),
    ("banner",                {"owasp_web": ["A05:2021"], "cis_control": "CIS-4.8",
                               "sans25": ["CWE-200"]}),
    ("version disclosure",    {"owasp_web": ["A05:2021"], "sans25": ["CWE-200"]}),
    ("information disclosure", {"owasp_web": ["A05:2021"], "sans25": ["CWE-200"]}),
]
