/* SLA & escalation tracker — staircase per finding, who it's with, overdue */
(function () {
  const { useState, useMemo } = React;
  const { Icon, SeverityBadge, SLAChip, EscalationStepper, AssetCell, Empty } = window;

  function SLATracker({ go }) {
    // Fetch findings via the API (falls back to window.FINDINGS offline).
    const { data, loading } = window.useAsync(() => window.api.findings(), []);
    if (loading && !data) {
      return (
        <div>
          <div className="page-head"><div>
            <h1 className="t-h1">SLA &amp; escalation tracker</h1>
            <div className="page-sub">Day 0 → 2 → 4 → 8–10 → 15–20 escalation staircase. Closure SLAs: Critical 30d · High 60d · Medium 60d.</div>
          </div></div>
          <div className="card"><Empty icon={Icon.clock} title="Loading SLA tracker…">Fetching the latest findings from the scanner.</Empty></div>
        </div>
      );
    }
    return <SLATrackerView findings={(data && data.findings) || window.FINDINGS} go={go} />;
  }

  function SLATrackerView({ findings, go }) {
    const F = findings;
    const open = F.filter(f => !f.isClosed && f.deadline);
    const [tab, setTab] = useState("all"); // all | overdue | at_risk
    const ESC = window.ESCALATION;

    const rows = useMemo(() => {
      let r = [...open];
      if (tab === "overdue") r = r.filter(f => f.daysLeft < 0);
      if (tab === "at_risk") r = r.filter(f => f.daysLeft >= 0 && f.daysLeft <= 7);
      return r.sort((a, b) => a.daysLeft - b.daysLeft);
    }, [open, tab]);

    // counts per escalation stage
    const stageCounts = ESC.map((s, i) => open.filter(f => f.escStage === i).length);

    return (
      <div>
        <div className="page-head"><div>
          <h1 className="t-h1">SLA &amp; escalation tracker</h1>
          <div className="page-sub">Day 0 → 2 → 4 → 8–10 → 15–20 escalation staircase. Closure SLAs: Critical 30d · High 60d · Medium 60d.</div>
        </div></div>

        {/* Staircase overview */}
        <div className="card mb5">
          <div className="card-head"><h3>Escalation pipeline</h3><div className="spacer" /><span className="t-xs faint">{open.length} active findings under SLA</span></div>
          <div className="card-pad">
            <div className="row" style={{ alignItems: "stretch", gap: 0 }}>
              {ESC.map((s, i) => (
                <div key={i} className="col" style={{ flex: 1, alignItems: "center", textAlign: "center", gap: 8, position: "relative" }}>
                  {i > 0 && <div style={{ position: "absolute", left: "-50%", right: "50%", top: 22, height: 2, background: "var(--border)" }} />}
                  <div className="center" style={{ width: 46, height: 46, borderRadius: "50%", zIndex: 1,
                    background: i >= 3 ? "var(--danger-bg)" : "var(--accent-soft)", color: i >= 3 ? "var(--danger)" : "var(--accent-text)",
                    border: "2px solid " + (i >= 3 ? "var(--sev-critical-border)" : "var(--accent-soft-border)"), fontWeight: 700, fontSize: 18, fontVariantNumeric: "tabular-nums" }}>
                    {stageCounts[i]}
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
                {rows.map(f => {
                  const overdue = f.daysLeft < 0;
                  const next = ESC[Math.min(f.escStage + 1, ESC.length - 1)];
                  return (
                    <tr key={f.id} onClick={() => go("detail", { id: f.id })}>
                      <td><div className="cell-strong" style={{ maxWidth: 240 }}>{f.title}</div><div className="cell-sub mono">{f.id}</div></td>
                      <td><SeverityBadge sev={f.severity} variant="dot" /></td>
                      <td><AssetCell finding={f} /></td>
                      <td><SLAChip finding={f} /></td>
                      <td><window.MiniStair stage={f.escStage} overdue={overdue} /></td>
                      <td><span className="t-sm" style={{ fontWeight: 500 }}>{ESC[f.escStage].role}</span></td>
                      <td>{f.escStage < ESC.length - 1
                        ? <span className="t-xs faint">→ {next.role}{overdue ? " (now)" : ` (day ${next.day})`}</span>
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
  window.SLATracker = SLATracker;
})();
