/* SLA & escalation tracker — staircase per finding, who it's with, overdue */
(function () {
  const { useState, useMemo } = React;
  const { Icon, SeverityBadge, SLAChip, EscalationStepper, AssetCell, Empty } = window;

  function SLATracker({ go, user }) {
    // Fetch BOTH the server escalation rollup and the full findings list.
    // - escalations() drives the pipeline staircase + per-row escalation fields
    //   (role/nextRole/stage/overdue); it falls back to a client computation
    //   offline, so `esc` is always shaped like /api/escalations.
    // - findings() gives the FULL hydrated finding (Date deadline, cvss,
    //   framework, slaDays, discovered…) that SLAChip / AssetCell expect. We
    //   index it by id and merge per row.
    const { data, loading } = window.useAsync(() => Promise.all([
      window.api.escalations(),
      window.api.findings(),
    ]).then(([esc, fnd]) => ({ esc: esc, findings: (fnd && fnd.findings) || [] })), []);

    if (loading && !data) {
      return (
        <div>
          <div className="page-head"><div>
            <h1 className="t-h1">SLA &amp; escalation tracker</h1>
            <div className="page-sub">Day 0 → 2 → 4 → 8–10 → 15–20 escalation staircase. Closure SLAs: Critical 30d · High 60d · Medium 60d.</div>
          </div></div>
          <div className="card"><Empty icon={Icon.clock} title="Loading SLA tracker…">Fetching escalations from the orchestrator.</Empty></div>
        </div>
      );
    }

    const esc = (data && data.esc) || null;
    const fullFindings = (data && data.findings) || window.FINDINGS;
    return <SLATrackerView esc={esc} fullFindings={fullFindings} go={go} user={user} />;
  }

  function SLATrackerView({ esc, fullFindings, go, user }) {
    const [tab, setTab] = useState("all"); // all | overdue | at_risk
    const ESC = window.ESCALATION;

    // Server-driven staircase. `ladder` carries label/day/role per stage; fall
    // back to the static ESCALATION ladder if the rollup is missing.
    const ladder = (esc && esc.ladder) || ESC.map((s, i) => ({ stage: i, day: s.day, label: s.label, role: s.role }));
    const stageCounts = (esc && esc.stageCounts) || ESC.map(() => 0);
    const escFindings = (esc && esc.findings) || [];

    // Index the full hydrated findings by id so each escalation row can render
    // chips (SLAChip needs a real Date `deadline`, AssetCell needs asset fields).
    const byId = useMemo(() => {
      const m = {};
      (fullFindings || []).forEach(f => { m[f.id] = f; });
      return m;
    }, [fullFindings]);

    // Tabs filter the SERVER escalation list (overdue flag from server; at_risk
    // = daysLeft 0..7). Rows merge: escalation record + the full finding.
    const rows = useMemo(() => {
      let r = escFindings.slice();
      if (tab === "overdue") r = r.filter(e => e.overdue);
      if (tab === "at_risk") r = r.filter(e => e.daysLeft != null && e.daysLeft >= 0 && e.daysLeft <= 7);
      return r.sort((a, b) => (a.daysLeft == null ? Infinity : a.daysLeft) - (b.daysLeft == null ? Infinity : b.daysLeft));
    }, [escFindings, tab]);

    const activeCount = (esc && esc.counts && esc.counts.active != null) ? esc.counts.active : escFindings.length;

    return (
      <div>
        <div className="page-head"><div>
          <h1 className="t-h1">SLA &amp; escalation tracker</h1>
          <div className="page-sub">Day 0 → 2 → 4 → 8–10 → 15–20 escalation staircase. Closure SLAs: Critical 30d · High 60d · Medium 60d.</div>
        </div>
          <RunSweep user={user} />
        </div>

        {/* Staircase overview — rendered from the server ladder + stageCounts */}
        <div className="card mb5">
          <div className="card-head"><h3>Escalation pipeline</h3><div className="spacer" /><span className="t-xs faint">{activeCount} active findings under SLA</span></div>
          <div className="card-pad">
            <div className="row" style={{ alignItems: "stretch", gap: 0 }}>
              {ladder.map((s, i) => (
                <div key={i} className="col" style={{ flex: 1, alignItems: "center", textAlign: "center", gap: 8, position: "relative" }}>
                  {i > 0 && <div style={{ position: "absolute", left: "-50%", right: "50%", top: 22, height: 2, background: "var(--border)" }} />}
                  <div className="center" style={{ width: 46, height: 46, borderRadius: "50%", zIndex: 1,
                    background: i >= 3 ? "var(--danger-bg)" : "var(--accent-soft)", color: i >= 3 ? "var(--danger)" : "var(--accent-text)",
                    border: "2px solid " + (i >= 3 ? "var(--sev-critical-border)" : "var(--accent-soft-border)"), fontWeight: 700, fontSize: 18, fontVariantNumeric: "tabular-nums" }}>
                    {stageCounts[i] || 0}
                  </div>
                  <div className="t-sm" style={{ fontWeight: 600 }}>{s.label}</div>
                  <div className="t-xs faint">Day {s.day} · {s.role}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="row gap3 mb4">
          <div className="seg">
            {[["all","All under SLA"],["overdue","Overdue"],["at_risk","Due ≤ 7 days"]].map(([k,l]) =>
              <button key={k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>{l}</button>)}
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => go("reports")}><Icon.download size={15} /> SLA report</button>
        </div>

        <div className="card">
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr>
                <th>Finding</th><th>Sev</th><th>Asset</th><th>SLA</th>
                <th style={{ minWidth: 200 }}>Escalation stage</th><th>Currently with</th><th>Next action</th>
              </tr></thead>
              <tbody>
                {rows.map(e => {
                  // Full hydrated finding for the chips (real Date deadline, cvss,
                  // framework…). Fall back to the escalation record if missing.
                  const f = byId[e.id] || e;
                  const lastStage = ladder.length - 1;
                  return (
                    <tr key={e.id} onClick={() => go("detail", { id: e.id })}>
                      <td><div className="cell-strong" style={{ maxWidth: 240 }}>{e.title}</div><div className="cell-sub mono">{e.id}</div></td>
                      <td><SeverityBadge sev={e.severity} variant="dot" /></td>
                      <td><AssetCell finding={f} /></td>
                      <td><SLAChip finding={f} /></td>
                      <td><window.MiniStair stage={e.escStage} overdue={e.overdue} /></td>
                      <td><span className="t-sm" style={{ fontWeight: 500 }}>{e.role}</span></td>
                      <td>{e.escStage < lastStage
                        ? <span className="t-xs faint">→ {e.nextRole}{e.overdue ? " (now)" : ` (day ${e.nextDay})`}</span>
                        : <span className="chip" style={{ color: "var(--danger)", background: "var(--sev-critical-bg)", borderColor: "var(--sev-critical-border)" }}>CISO review</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  // Admin-only header action: fires POST /api/escalations/run and reports the
  // real dispatch result. Hidden controls for non-admins are still gated
  // server-side (403). Never fakes success — surfaces err.message on failure.
  function RunSweep({ user }) {
    const isAdmin = window.can(user, "admin");
    const [busy, setBusy] = useState(false);
    const [result, setResult] = useState(null); // { count, dispatched, ranAt }
    const [error, setError] = useState(null);

    async function run() {
      if (!isAdmin || busy) return;
      setBusy(true); setError(null); setResult(null);
      try {
        const res = await window.api.runEscalations();
        setResult(res || { count: 0, dispatched: [] });
      } catch (err) {
        setError(err && err.message ? err.message : "Escalation sweep failed.");
      } finally {
        setBusy(false);
      }
    }

    return (
      <div className="col gap2" style={{ alignItems: "flex-end" }}>
        <button className="btn primary" disabled={!isAdmin || busy}
          title={isAdmin ? "Run the escalation sweep now" : "requires admin"}
          onClick={run}>
          <Icon.bell size={15} /> {busy ? "Running sweep…" : "Run escalation sweep"}
        </button>
        {result && (
          <div className="card" style={{ padding: "8px 12px", borderColor: "var(--accent-soft-border)", maxWidth: 360 }}>
            <div className="t-sm" style={{ fontWeight: 600 }}>
              Dispatched {result.count != null ? result.count : (result.dispatched || []).length} escalation notification(s).
            </div>
            {(result.dispatched || []).length > 0 && (
              <ul className="t-xs faint" style={{ margin: "4px 0 0", paddingLeft: 16 }}>
                {result.dispatched.slice(0, 6).map((d, i) => (
                  <li key={i}>{d.findingId} → {d.role}{d.severity ? ` (${d.severity})` : ""}</li>
                ))}
                {result.dispatched.length > 6 && <li>…and {result.dispatched.length - 6} more</li>}
              </ul>
            )}
          </div>
        )}
        {error && (
          <div className="card" style={{ padding: "8px 12px", borderColor: "var(--sev-critical-border)", background: "var(--sev-critical-bg)", maxWidth: 360 }}>
            <span className="t-sm" style={{ color: "var(--danger)", fontWeight: 600 }}>{error}</span>
          </div>
        )}
      </div>
    );
  }

  window.SLATracker = SLATracker;
})();
