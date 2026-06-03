/* ============================================================
   Vantage console — REST API client (plain browser JS, no JSX)
   - Talks to the orchestrator at API_BASE.
   - Degrades gracefully: on ANY error (network / non-200) each
     call falls back to the in-file mock on window.* so the
     prototype still renders offline.
   - Hydrates ISO date strings (discovered/deadline) back into
     Date objects so SLAChip / fmtDate keep working unchanged.
   ============================================================ */
(function () {
  window.API_BASE = "http://localhost:8138";

  // Convert a value that may be an ISO "YYYY-MM-DD" string (from the API)
  // or already a Date (from the mock) into a Date — or null/undefined as-is.
  function toDate(v) {
    if (v == null) return v;
    if (v instanceof Date) return v;
    // Parse at local noon to avoid TZ rollover affecting day math.
    return new Date(String(v) + "T09:00:00");
  }

  // Hydrate a single finding's date fields in place (returns a new object).
  function hydrateFinding(f) {
    if (!f) return f;
    return Object.assign({}, f, {
      discovered: toDate(f.discovered),
      deadline: toDate(f.deadline),
    });
  }

  function hydrateFindings(list) {
    return Array.isArray(list) ? list.map(hydrateFinding) : list;
  }

  let warned = false;
  function warnOnce(what, err) {
    // One concise warning per fallback so offline mode stays quiet-ish.
    console.warn("[api] " + what + " — using offline mock data", err && err.message ? "(" + err.message + ")" : "");
  }

  // Core fetch wrapper: GET JSON, throw on non-2xx.
  async function getJSON(path) {
    const res = await fetch(window.API_BASE + path, {
      headers: { Accept: "application/json" },
      credentials: "include",
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }

  // Mutating request. Unlike reads, writes do NOT fall back to mock — a failed
  // write must surface so the UI never fakes success. Throws an Error carrying
  // .status and .data (the parsed JSON error body, when present).
  async function sendJSON(path, body, method) {
    let res;
    try {
      res = await fetch(window.API_BASE + path, {
        method: method || "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body || {}),
        credentials: "include",
      });
    } catch (e) {
      const err = new Error("Network error — the API is unreachable.");
      err.status = 0;
      throw err;
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty/non-JSON body */ }
    if (!res.ok) {
      const msg = (data && (data.detail || data.error || data.message)) || ("HTTP " + res.status);
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function buildQuery(params) {
    if (!params) return "";
    const usp = new URLSearchParams();
    Object.keys(params).forEach(function (k) {
      const v = params[k];
      if (v == null || v === "") return;
      usp.append(k, Array.isArray(v) ? v.join(",") : v);
    });
    const s = usp.toString();
    return s ? "?" + s : "";
  }

  const api = {
    // ---- Auth / identity -----------------------------------------------------
    // Who am I? GET /api/auth/me → the User on 200, or null on 401/any error so
    // the console can render a signed-out state. Never fabricates a fake user.
    async me() {
      try {
        const data = await getJSON("/api/auth/me");
        return (data && data.user) || null;
      } catch (err) {
        return null;
      }
    },
    // Absolute URL that starts the OIDC redirect; bounces back to `next` (or the
    // current page) after login. The browser navigates here directly.
    loginUrl(next) {
      return window.API_BASE + "/api/auth/login?next=" + encodeURIComponent(next || window.location.href);
    },
    // Clear the session server-side. Ignores the (empty) response body.
    async logout() {
      try { await sendJSON("/api/auth/logout", {}, "POST"); } catch (e) { /* best-effort */ }
    },

    async findings(params) {
      try {
        const data = await getJSON("/api/findings" + buildQuery(params));
        return {
          findings: hydrateFindings(data.findings),
          total: data.total != null ? data.total : (data.findings || []).length,
        };
      } catch (err) {
        warnOnce("GET /api/findings", err);
        const all = window.FINDINGS || [];
        return { findings: hydrateFindings(all), total: all.length };
      }
    },

    async finding(id) {
      try {
        const data = await getJSON("/api/findings/" + encodeURIComponent(id));
        return hydrateFinding(data.finding);
      } catch (err) {
        warnOnce("GET /api/findings/" + id, err);
        const f = (window.FINDINGS || []).find(function (x) { return x.id === id; });
        return f ? hydrateFinding(f) : null;
      }
    },

    async assets() {
      try {
        const data = await getJSON("/api/assets");
        return data.assets;
      } catch (err) {
        warnOnce("GET /api/assets", err);
        return window.ASSETS || [];
      }
    },

    async scans() {
      try {
        const data = await getJSON("/api/scans");
        return data.scans;
      } catch (err) {
        warnOnce("GET /api/scans", err);
        return window.SCANS || [];
      }
    },

    async exceptions() {
      try {
        const data = await getJSON("/api/exceptions");
        return data.exceptions;
      } catch (err) {
        warnOnce("GET /api/exceptions", err);
        return window.EXCEPTIONS || [];
      }
    },

    async trend() {
      try {
        const data = await getJSON("/api/trend");
        return data.trend;
      } catch (err) {
        warnOnce("GET /api/trend", err);
        return window.TREND || [];
      }
    },

    async dashboard() {
      try {
        return await getJSON("/api/dashboard");
      } catch (err) {
        warnOnce("GET /api/dashboard", err);
        return computeDashboardFromMock();
      }
    },

    async health() {
      try {
        return await getJSON("/api/health");
      } catch (err) {
        warnOnce("GET /api/health", err);
        return { status: "offline", today: "2026-06-01" };
      }
    },

    // ---- Schedule ------------------------------------------------------------
    // GET /api/schedule → the cadence + blackout-aware scan plan
    // { today, blackouts, entries, counts }. On any error, fall back to a
    // client-computed object of the SAME shape (from window.ASSETS) so the
    // Schedule screen still renders offline.
    async schedule() {
      try { return await getJSON("/api/schedule"); }
      catch (err) { warnOnce("GET /api/schedule", err); return computeScheduleFromMock(); }
    },

    // ---- Escalations ---------------------------------------------------------
    // GET /api/escalations → the server-side rollup { today, ladder, stageCounts,
    // findings, due, counts }. On any error, fall back to a client-computed object
    // of the SAME shape (from window.FINDINGS + window.ESCALATION) so the SLA
    // tracker still renders offline.
    async escalations() {
      try {
        return await getJSON("/api/escalations");
      } catch (err) {
        warnOnce("GET /api/escalations", err);
        return computeEscalationsFromMock();
      }
    },
    // POST /api/escalations/run (admin only) — fires the escalation sweep. Throws
    // on failure (incl. 403 for non-admins); never fakes success. Returns
    // { dispatched, count, ranAt }.
    runEscalations() {
      return sendJSON("/api/escalations/run", {}, "POST");
    },

    // ---- Writes (human-gated; throw on failure, NO silent fallback) --------
    // PATCH a finding's status. Returns the updated (hydrated) finding.
    setFindingStatus(id, body) {
      return sendJSON("/api/findings/" + encodeURIComponent(id) + "/status", body, "PATCH")
        .then(function (d) { return hydrateFinding(d && d.finding); });
    },
    // POST a new scan. The server enforces the scope gate (approved inventory).
    // On out-of-scope/invalid input the thrown Error carries .status (403/422)
    // and .data ({error, detail}). Returns the created scan on success.
    startScan(body) {
      return sendJSON("/api/scans", body, "POST").then(function (d) { return d && d.scan; });
    },
    // POST an exception request. Server resolves the approver tier from
    // duration. Returns { exception, tier }.
    requestException(body) {
      return sendJSON("/api/exceptions", body, "POST");
    },
    // Confirm/clear a finding as a false positive. Returns the updated finding.
    setFalsePositive(id, body) {
      return sendJSON("/api/findings/" + encodeURIComponent(id) + "/false-positive", body, "POST")
        .then(function (d) { return hydrateFinding(d && d.finding); });
    },
    // Approve/reject an exception. Returns { exception, finding }.
    decideException(id, body) {
      return sendJSON("/api/exceptions/" + encodeURIComponent(id) + "/decision", body, "POST");
    },
    // ---- Scan diff -----------------------------------------------------------
    // GET /api/scan-diff → the two-register comparison
    // { baseLabel, headLabel, today, resolved, new, persisting, regressed, counts }.
    // On any error, fall back to a minimal empty-shaped object so the Scan diff
    // screen still renders offline.
    async scanDiff() {
      try {
        return await getJSON("/api/scan-diff");
      } catch (err) {
        warnOnce("GET /api/scan-diff", err);
        return {
          baseLabel: "licensed", headLabel: "oss", today: "2026-06-02",
          resolved: [], new: [], persisting: [], regressed: [],
          counts: { baseline: 0, current: 0, resolved: 0, new: 0, persisting: 0, regressed: 0 },
        };
      }
    },
    // POST /api/findings/{id}/retest (role analyst) — request a retest. Server
    // derives the actor; send no body. Returns the updated (hydrated) finding
    // (status becomes "retest"). Throws on failure (incl. 403/404).
    requestRetest(id) {
      return sendJSON("/api/findings/" + encodeURIComponent(id) + "/retest", {}, "POST")
        .then(function (d) { return hydrateFinding(d && d.finding); });
    },
    // Recent audit-trail entries (read; falls back to [] offline).
    async audit(limit) {
      try {
        const d = await getJSON("/api/audit" + (limit ? "?limit=" + limit : ""));
        return d.audit || [];
      } catch (err) { warnOnce("GET /api/audit", err); return []; }
    },
    // Generate a report (xlsx/docx/pdf). Throws on failure (no faked success).
    // Returns { reportId, generatedAt, files: { <fmt>: "<download path>" } }.
    generateReport(body) {
      return sendJSON("/api/reports", body, "POST");
    },
    // Absolute URL to download a generated report file (xlsx|docx|pdf).
    reportDownloadUrl(reportId, fmt) {
      return window.API_BASE + "/api/reports/" + encodeURIComponent(reportId) + "/" + encodeURIComponent(fmt);
    },
  };

  // Build the convenience rollup from the mock, matching /api/dashboard shape.
  function computeDashboardFromMock() {
    const all = window.FINDINGS || [];
    const open = all.filter(function (f) { return !f.isClosed; });
    const openBySeverity = (window.SEVERITY_ORDER || []).reduce(function (m, s) {
      m[s] = open.filter(function (f) { return f.severity === s; }).length;
      return m;
    }, {});
    const overdue = open.filter(function (f) { return f.daysLeft != null && f.daysLeft < 0; }).length;
    const dueSoon = open.filter(function (f) { return f.daysLeft != null && f.daysLeft >= 0 && f.daysLeft <= 7; }).length;
    const scansRunning = (window.SCANS || []).filter(function (s) { return s.status === "running"; }).length;
    return {
      today: "2026-06-01",
      openBySeverity: openBySeverity,
      counts: { open: open.length, overdue: overdue, dueSoon: dueSoon, scansRunning: scansRunning },
      trend: window.TREND || [],
    };
  }

  // Build the escalation rollup from the mock, matching /api/escalations shape.
  // Mirrors the server: ladder/stageCounts/findings/due/counts derived from
  // window.FINDINGS + window.ESCALATION. Dates stay as-is (the screen reads
  // daysLeft/role text, and hydrates chip data from api.findings() separately).
  function computeEscalationsFromMock() {
    const ESC = window.ESCALATION || [];
    const all = window.FINDINGS || [];
    const lastStage = Math.max(ESC.length - 1, 0);

    const ladder = ESC.map(function (s, i) {
      return { stage: i, day: s.day, label: s.label, role: s.role };
    });

    const records = all.map(function (f) {
      const stage = f.escStage || 0;
      const next = ESC[Math.min(stage + 1, lastStage)] || {};
      const overdue = f.daysLeft != null && f.daysLeft < 0;
      const dueForEscalation = !f.isClosed && !!f.deadline && (overdue || stage >= 3);
      return {
        id: f.id,
        title: f.title,
        severity: f.severity,
        assetId: f.assetId,
        asset: f.asset,
        owner: f.owner,
        assetOwner: f.assetOwner,
        deadline: f.deadline,
        daysLeft: f.daysLeft,
        escStage: stage,
        stageLabel: (ESC[stage] && ESC[stage].label) || "",
        role: (ESC[stage] && ESC[stage].role) || "",
        nextRole: next.role || "",
        nextDay: next.day != null ? next.day : null,
        overdue: overdue,
        dueForEscalation: dueForEscalation,
      };
    });

    // Only findings actually under SLA (open + has a deadline) belong in the
    // pipeline; matches what the server counts.
    const active = records.filter(function (r) { return !!r.deadline; })
      .filter(function (r) {
        const f = all.find(function (x) { return x.id === r.id; });
        return f && !f.isClosed;
      });
    const stageCounts = ESC.map(function (_s, i) {
      return active.filter(function (r) { return r.escStage === i; }).length;
    });
    const due = active.filter(function (r) { return r.dueForEscalation; });
    const overdueCount = active.filter(function (r) { return r.overdue; }).length;

    return {
      today: "2026-06-02",
      ladder: ladder,
      stageCounts: stageCounts,
      findings: active,
      due: due,
      counts: { active: active.length, overdue: overdueCount, due: due.length },
    };
  }

  // Build the schedule plan from the mock, matching /api/schedule shape.
  // web assets → one web-pentest (2x/yr); infra → infra-va (2x/yr) + cis-review
  // (1x/yr). Offline placeholder: lastRun null, nextDue today, dueSoon today.
  function computeScheduleFromMock() {
    const TODAY = "2026-06-02";
    const blackouts = [
      { start: "2026-03-25", end: "2026-04-10", reason: "FY-end change freeze" },
      { start: "2026-12-20", end: "2027-01-02", reason: "Year-end peak freeze" },
    ];
    const entries = [];
    (window.ASSETS || []).forEach(function (a) {
      function entry(scanType, cadence, cadenceDays) {
        entries.push({
          assetId: a.id, asset: a.name, pipeline: a.type, scanType: scanType,
          cadence: cadence, cadenceDays: cadenceDays, lastRun: null, nextDue: TODAY,
          overdue: false, dueSoon: true, shiftedByBlackout: false,
          blackoutReason: null, daysUntil: 0,
        });
      }
      if (a.type === "web") {
        entry("web-pentest", "2x/yr", 182);
      } else {
        entry("infra-va", "2x/yr", 182);
        entry("cis-review", "1x/yr", 365);
      }
    });
    const overdue = entries.filter(function (e) { return e.overdue; }).length;
    const dueSoon = entries.filter(function (e) { return e.dueSoon; }).length;
    return {
      today: TODAY,
      blackouts: blackouts,
      entries: entries,
      counts: { total: entries.length, overdue: overdue, dueSoon: dueSoon },
    };
  }

  window.api = api;

  // ---- Advisory role gate (server still enforces via require_role) -----------
  // can(user, ...roles) → true if the user holds any of `roles` or is `admin`.
  // Used to hide/disable controls the role can't use; NOT a security boundary.
  window.can = function (user, ...roles) {
    if (!user || !Array.isArray(user.roles)) return false;
    if (user.roles.indexOf("admin") !== -1) return true;
    return roles.some(function (r) { return user.roles.indexOf(r) !== -1; });
  };

  // ---- Tiny async hook helper (React is global) -----------------------------
  // Usage: const { data, loading, error } = window.useAsync(() => api.findings(), []);
  window.useAsync = function (fn, deps) {
    const [state, setState] = React.useState({ data: null, loading: true, error: null });
    React.useEffect(function () {
      let alive = true;
      setState(function (s) { return { data: s.data, loading: true, error: null }; });
      Promise.resolve()
        .then(fn)
        .then(function (data) {
          if (alive) setState({ data: data, loading: false, error: null });
        })
        .catch(function (error) {
          // fn already falls back internally, so this is rare; surface it anyway.
          if (alive) setState({ data: null, loading: false, error: error });
        });
      return function () { alive = false; };
    }, deps || []);
    return state;
  };
})();
