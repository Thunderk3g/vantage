/* ============================================================
   InfoSec Scanner — sample data
   "Today" is pinned to 2026-06-01 for stable countdowns.
   ============================================================ */
(function () {
  const TODAY = new Date("2026-06-01T09:00:00");
  window.TODAY = TODAY;

  // ---- SLA policy (IRDAI-mandated; matches db/schema.sql sla_days_for()) ----
  // Reconciled with the backend: Critical & High = 30 days, Medium & Low = 60.
  // (The original design prototype assumed 30/60/60/90; corrected here so the
  //  UI countdowns match what the scanner's SLA trigger actually computes.)
  const SLA_DAYS = { critical: 30, high: 30, medium: 60, low: 60, info: null };

  // ---- Escalation staircase (Day 0 -> 2 -> 4 -> 8-10 -> 15-20) ----
  const ESCALATION = [
    { day: 0,  label: "Owner notified", role: "Asset Owner" },
    { day: 2,  label: "Reminder",       role: "Asset Owner" },
    { day: 4,  label: "Team Lead",      role: "AppSec Lead" },
    { day: 9,  label: "Sec Manager",    role: "Security Manager" },
    { day: 18, label: "CISO escalation",role: "CISO" },
  ];
  window.ESCALATION = ESCALATION;
  window.SLA_DAYS = SLA_DAYS;

  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  window.SEVERITY_ORDER = SEVERITY_ORDER;

  function daysBetween(a, b) {
    return Math.round((b - a) / 86400000);
  }
  function addDays(d, n) { const x = new Date(d); x.setDate(x.getDate() + n); return x; }
  function fmtDate(d) {
    return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
  }
  window.fmtDate = fmtDate;
  window.daysBetween = daysBetween;

  // ---- Approved asset inventory (no free-text targets allowed) ----
  const ASSETS = [
    { id: "AST-PORTAL",   name: "Policyholder Portal",        type: "web",   env: "Production", owner: "Digital Channels", crit: "Tier-1", host: "portal.lifeco.internal" },
    { id: "AST-AGENT",    name: "Agent Mobile App (API)",     type: "web",   env: "Production", owner: "Distribution Tech", crit: "Tier-1", host: "api.agent.lifeco.internal" },
    { id: "AST-CLAIMS",   name: "Claims Processing API",      type: "web",   env: "Production", owner: "Claims Platform",   crit: "Tier-1", host: "api.claims.lifeco.internal" },
    { id: "AST-PAY",      name: "Premium Payment Gateway",    type: "web",   env: "Production", owner: "Payments",          crit: "Tier-1", host: "pay.lifeco.internal" },
    { id: "AST-UW",       name: "Underwriting Engine",        type: "web",   env: "Production", owner: "Underwriting",      crit: "Tier-1", host: "uw.lifeco.internal" },
    { id: "AST-PAS",      name: "Core Policy Admin System",   type: "infra", env: "Production", owner: "Core Platform",     crit: "Tier-1", host: "10.20.4.0/24" },
    { id: "AST-DWH",      name: "Customer Data Warehouse",    type: "infra", env: "Production", owner: "Data Platform",     crit: "Tier-1", host: "10.20.8.12" },
    { id: "AST-IDP",      name: "Identity Provider (SSO)",    type: "infra", env: "Production", owner: "IAM",               crit: "Tier-1", host: "sso.lifeco.internal" },
    { id: "AST-DMS",      name: "Document Management Server", type: "infra", env: "Production", owner: "Enterprise Content",crit: "Tier-2", host: "10.20.6.40" },
    { id: "AST-REINS",    name: "Reinsurance Settlement Svc", type: "web",   env: "Production", owner: "Reinsurance",       crit: "Tier-2", host: "api.reins.lifeco.internal" },
    { id: "AST-VPN",      name: "Branch VPN Gateway",         type: "infra", env: "Production", owner: "Network Ops",       crit: "Tier-2", host: "10.10.0.1" },
    { id: "AST-HR",       name: "Internal HR Portal",         type: "web",   env: "Staging",    owner: "People Systems",    crit: "Tier-3", host: "hr.staging.lifeco.internal" },
  ];
  window.ASSETS = ASSETS;

  const PEOPLE = ["A. Mehta", "R. Iyer", "S. Khan", "P. Nair", "D. Bose", "Unassigned"];

  // ---- Findings (curated, insurance-flavored) ----
  // discovered = days ago from TODAY
  const RAW = [
    ["VLN-2087","BOLA on /v1/claims/{id} exposes other policyholders' claims","critical","triaged","AST-CLAIMS","OWASP API","API1:2023","Broken Object Level Authorization",9.3,26,"R. Iyer"],
    ["VLN-2081","SQL injection in policy search parameter","critical","in_progress","AST-PORTAL","OWASP Web","A03:2021","Injection",9.1,18,"A. Mehta"],
    ["VLN-2074","Default admin credentials on document server","critical","open","AST-DMS","CIS","CIS-5.2","Account Management",9.8,36,"Unassigned"],
    ["VLN-2069","Unauthenticated premium calculation endpoint leaks PII","critical","open","AST-PAY","OWASP API","API2:2023","Broken Authentication",8.9,1,"Unassigned"],
    ["VLN-2061","Hardcoded encryption key in agent app build","high","triaged","AST-AGENT","SANS","CWE-798","Use of Hard-coded Credentials",8.1,24,"S. Khan"],
    ["VLN-2058","Sensitive policyholder PII written to application logs","high","in_progress","AST-DWH","OWASP Web","A09:2021","Security Logging Failures",7.6,33,"D. Bose"],
    ["VLN-2052","Missing rate limiting on OTP verification","high","triaged","AST-AGENT","OWASP API","API4:2023","Unrestricted Resource Consumption",7.4,40,"S. Khan"],
    ["VLN-2049","Unpatched OpenSSL CVE-2025-XXXX on VPN gateway","high","open","AST-VPN","CIS","CIS-7.4","Continuous Vuln Mgmt",7.9,72,"P. Nair"],
    ["VLN-2044","No MFA enforced on underwriting admin console","high","open","AST-UW","OWASP Web","A07:2021","Identification & Auth Failures",7.2,66,"Unassigned"],
    ["VLN-2040","Server-side request forgery in document fetch","high","triaged","AST-CLAIMS","OWASP Web","A10:2021","Server-Side Request Forgery",8.2,9,"R. Iyer"],
    ["VLN-2031","TLS 1.0/1.1 enabled on payment gateway","medium","in_progress","AST-PAY","CIS","CIS-3.10","Data Protection",5.9,28,"P. Nair"],
    ["VLN-2028","IDOR allows download of others' policy documents","medium","triaged","AST-PORTAL","OWASP API","API1:2023","Broken Object Level Authorization",6.5,15,"A. Mehta"],
    ["VLN-2024","Verbose stack traces exposed on 500 errors","medium","in_progress","AST-UW","OWASP Web","A05:2021","Security Misconfiguration",5.3,64,"R. Iyer"],
    ["VLN-2019","Session cookie missing Secure/HttpOnly flags","medium","open","AST-HR","OWASP Web","A05:2021","Security Misconfiguration",5.1,44,"Unassigned"],
    ["VLN-2015","Outdated jQuery with known XSS in portal","medium","triaged","AST-PORTAL","OWASP Web","A06:2021","Vulnerable & Outdated Components",6.1,38,"A. Mehta"],
    ["VLN-2011","Reinsurance API returns excessive data fields","medium","open","AST-REINS","OWASP API","API3:2023","Broken Object Property Level Auth",5.6,7,"Unassigned"],
    ["VLN-2003","Directory listing enabled on static assets","low","open","AST-PORTAL","CIS","CIS-4.1","Secure Configuration",3.7,20,"Unassigned"],
    ["VLN-1998","Missing security headers (CSP, HSTS)","low","triaged","AST-AGENT","OWASP Web","A05:2021","Security Misconfiguration",3.1,30,"S. Khan"],
    ["VLN-1994","Weak password policy on HR portal","low","open","AST-HR","OWASP Web","A07:2021","Identification & Auth Failures",4.0,55,"Unassigned"],
    ["VLN-1990","Banner discloses server software version","info","open","AST-VPN","CIS","CIS-4.8","Information Disclosure",2.0,12,"Unassigned"],
    ["VLN-1985","Deprecated API version still reachable","info","triaged","AST-REINS","OWASP API","API9:2023","Improper Inventory Management",2.4,26,"R. Iyer"],
    // closed / risk-accepted examples
    ["VLN-1979","XSS in claims status comment field","high","closed","AST-CLAIMS","OWASP Web","A03:2021","Injection",7.0,70,"R. Iyer"],
    ["VLN-1972","Cleartext internal service on legacy subnet","medium","risk_accepted","AST-PAS","CIS","CIS-3.10","Data Protection",5.0,80,"P. Nair"],
    ["VLN-1965","Open redirect on login return URL","low","closed","AST-PORTAL","OWASP Web","A01:2021","Broken Access Control",3.4,90,"A. Mehta"],
  ];

  const FINDINGS = RAW.map((r, i) => {
    const [id, title, severity, status, assetId, fw, code, catName, cvss, daysAgo, owner] = r;
    const asset = ASSETS.find(a => a.id === assetId);
    const discovered = addDays(TODAY, -daysAgo);
    const slaDays = SLA_DAYS[severity];
    const deadline = slaDays != null ? addDays(discovered, slaDays) : null;
    const isClosed = status === "closed" || status === "risk_accepted";
    let daysLeft = deadline ? daysBetween(TODAY, deadline) : null;
    // escalation stage derived from how long open + overdue
    let escStage = 0;
    if (!isClosed && deadline) {
      const overdueBy = -daysLeft;
      if (overdueBy >= 18) escStage = 4;
      else if (overdueBy >= 9) escStage = 3;
      else if (overdueBy >= 4) escStage = 2;
      else if (overdueBy >= 2) escStage = 1;
      else if (overdueBy >= 0) escStage = 1;
      else {
        // not overdue yet: stage by elapsed since discovery
        const elapsed = daysAgo;
        if (elapsed >= 18) escStage = 2;
        else if (elapsed >= 4) escStage = 1;
        else escStage = 0;
      }
    }
    return {
      id, title, severity, status,
      assetId, asset: asset.name, assetType: asset.type, assetCrit: asset.crit, assetOwner: asset.owner,
      pipeline: asset.type === "infra" ? "infra" : "web",
      framework: fw, catCode: code, catName,
      cvss, discovered, deadline, slaDays, daysLeft, isClosed, escStage,
      owner, scan: "SCAN-0" + (98 - (i % 6)),
    };
  });
  window.FINDINGS = FINDINGS;

  // ---- Scans ----
  window.SCANS = [
    { id: "SCAN-0098", target: "Claims Processing API", pipeline: "web", type: "gray-box", auth: "min-privilege", status: "running", progress: 62, started: "2026-06-01 08:14", findings: 7, by: "A. Mehta" },
    { id: "SCAN-0097", target: "Policyholder Portal", pipeline: "web", type: "black-box", auth: "unauthenticated", status: "running", progress: 28, started: "2026-06-01 08:40", findings: 3, by: "S. Khan" },
    { id: "SCAN-0096", target: "Branch VPN Gateway", pipeline: "infra", type: "gray-box", auth: "max-privilege", status: "queued", progress: 0, started: "—", findings: 0, by: "P. Nair" },
    { id: "SCAN-0095", target: "Premium Payment Gateway", pipeline: "web", type: "gray-box", auth: "min-privilege", status: "completed", progress: 100, started: "2026-05-31 22:10", findings: 5, by: "P. Nair" },
    { id: "SCAN-0094", target: "Customer Data Warehouse", pipeline: "infra", type: "gray-box", auth: "max-privilege", status: "completed", progress: 100, started: "2026-05-30 02:00", findings: 9, by: "D. Bose" },
  ];

  // ---- Exceptions ----
  window.EXCEPTIONS = [
    { id: "EXC-044", finding: "VLN-1972", title: "Cleartext internal service on legacy subnet", asset: "Core Policy Admin System", severity: "medium", duration: 2, tier: "CISO", status: "approved", requestedBy: "P. Nair", approver: "CISO", reviewDate: "2026-08-01", reason: "Legacy PAS migration in progress; compensating network segmentation in place." },
    { id: "EXC-046", finding: "VLN-2044", title: "No MFA on underwriting admin console", asset: "Underwriting Engine", severity: "high", duration: 5, tier: "RMC", status: "pending", requestedBy: "Underwriting", approver: "Risk Mgmt Committee", reviewDate: "—", reason: "Vendor MFA module delivery scheduled Q3; interim IP allow-listing applied." },
    { id: "EXC-041", finding: "VLN-2019", title: "Session cookie flags on HR portal", asset: "Internal HR Portal", severity: "medium", duration: 14, tier: "Board", status: "pending", requestedBy: "People Systems", approver: "Board Risk Committee", reviewDate: "—", reason: "Full HR platform replacement planned next FY; staging only." },
    { id: "EXC-039", finding: "VLN-1990", title: "Server version banner disclosure", asset: "Branch VPN Gateway", severity: "info", duration: 1, tier: "CISO", status: "rejected", requestedBy: "Network Ops", approver: "CISO", reviewDate: "2026-05-20", reason: "Low effort to remediate; exception not justified." },
  ];

  // ---- Trend (open findings by severity over last 8 weeks) ----
  window.TREND = [
    { wk: "Apr 6",  critical: 6, high: 14, medium: 22, low: 11 },
    { wk: "Apr 13", critical: 5, high: 13, medium: 20, low: 12 },
    { wk: "Apr 20", critical: 7, high: 15, medium: 19, low: 10 },
    { wk: "Apr 27", critical: 6, high: 12, medium: 18, low: 9 },
    { wk: "May 4",  critical: 5, high: 11, medium: 17, low: 9 },
    { wk: "May 11", critical: 4, high: 10, medium: 16, low: 8 },
    { wk: "May 18", critical: 5, high: 9,  medium: 15, low: 7 },
    { wk: "May 25", critical: 4, high: 9,  medium: 14, low: 6 },
  ];

  // exception tier helper
  window.exceptionTier = function (months) {
    if (months <= 3) return { tier: "CISO", note: "≤ 3 months" };
    if (months <= 12) return { tier: "RMC", note: "> 3 months" };
    return { tier: "Board", note: "> 12 months" };
  };
})();
