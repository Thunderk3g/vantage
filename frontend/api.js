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
    // Recent audit-trail entries (read; falls back to [] offline).
    async audit(limit) {
      try {
        const d = await getJSON("/api/audit" + (limit ? "?limit=" + limit : ""));
        return d.audit || [];
      } catch (err) { warnOnce("GET /api/audit", err); return []; }
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

  window.api = api;

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
