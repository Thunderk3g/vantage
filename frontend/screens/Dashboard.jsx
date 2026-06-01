/* Dashboard — severity rollup, SLA countdowns, scans, escalations, trend */
(function () {
  const { useMemo } = React;
  const { Icon, SeverityBadge, SLAChip, StatusPill, Donut, SevBar, TrendChart, AssetCell, MiniStair } = window;

  function Kpi({ label, value, icon, foot, tone }) {
    const I = icon;
    return (
      <div className="card kpi">
        <div className="kpi-label">{I && <I size={15} />}{label}</div>
        <div className="kpi-val" style={tone ? { color: tone } : null}>{value}</div>
        {foot && <div className="kpi-foot">{foot}</div>}
      </div>
    );
  }

  function Dashboard({ role, go }) {
    // Fetch findings via the API (falls back to window.FINDINGS offline).
    // Rollups are computed locally from this array so numbers match exactly.
    const { data, loading } = window.useAsync(() => window.api.findings(), []);
    if (loading && !data) {
      return (
        <div>
          <div className="page-head">
            <div>
              <div className="page-title-row"><h1 className="t-h1">Security posture</h1></div>
              <div className="page-sub">Loading the latest security posture…</div>
            </div>
          </div>
          <div className="card"><div className="card-pad" style={{ textAlign: "center", color: "var(--ink-3)", padding: "48px 0" }}>Loading…</div></div>
        </div>
      );
    }
    return <DashboardView findings={(data && data.findings) || window.FINDINGS} role={role} go={go} />;
  }

  function DashboardView({ findings, role, go }) {
    const F = findings;
    const open = useMemo(() => F.filter(f => !f.isClosed), [F]);
    const counts = window.countBy(open, "severity");
    const overdue = open.filter(f => f.daysLeft != null && f.daysLeft < 0)
      .sort((a, b) => a.daysLeft - b.daysLeft);
    const atRisk = open.filter(f => f.daysLeft != null && f.daysLeft >= 0 && f.daysLeft <= 7)
      .sort((a, b) => a.daysLeft - b.daysLeft);
    const escalated = open.filter(f => f.escStage >= 2)
      .sort((a, b) => b.escStage - a.escStage);
    const scans = window.SCANS;
    const running = scans.filter(s => s.status === "running");
    const queued = scans.filter(s => s.status === "queued");

    const sevColors = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)" };

    return (
      <div>
        <div className="page-head">
          <div>
            <div className="page-title-row"><h1 className="t-h1">Security posture</h1></div>
            <div className="page-sub">
              {role === "ciso" ? "Executive rollup across all Tier-1 and Tier-2 assets." :
               role === "lead" ? "Team workload and SLA health across owned assets." :
               "Your active triage queue and SLA deadlines."} · As of {window.fmtDate(window.TODAY)}
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => go("reports")}><Icon.reports size={15} />Export report</button>
          <button className="btn primary" onClick={() => go("scan")}><Icon.scan size={15} />Start a scan</button>
        </div>

        {/* KPI row */}
        <div className="grid mb5" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <Kpi label="Open findings" value={open.length} icon={Icon.findings}
            foot={<><span className="trend-down"><Icon.arrowDown size={13} /></span> 6 fewer than last week</>} />
          <Kpi label="Overdue (SLA breached)" value={overdue.length} icon={Icon.alert} tone="var(--danger)"
            foot={<span className="muted">{overdue.filter(f => f.severity === "critical").length} critical · escalating</span>} />
          <Kpi label="Due within 7 days" value={atRisk.length} icon={Icon.clock} tone="oklch(0.55 0.13 70)"
            foot={<span className="muted">across {new Set(atRisk.map(f => f.assetId)).size} assets</span>} />
          <Kpi label="Scans running" value={running.length} icon={Icon.scan}
            foot={<span className="muted">{queued.length} queued</span>} />
        </div>

        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignItems: "start" }}>
          {/* Severity distribution */}
          <div className="card">
            <div className="card-head"><h3>Open findings by severity</h3><div className="spacer" />
              <button className="btn ghost sm" onClick={() => go("findings")}>View all <Icon.chevRight size={14} /></button>
            </div>
            <div className="card-pad row gap5">
              <Donut counts={counts} />
              <div className="col gap3 flex1">
                {window.SEVERITY_ORDER.map(k => counts[k] ? (
                  <button key={k} className="row gap3 between" style={{ border: "none", background: "none", cursor: "pointer", padding: "4px 0", width: "100%" }}
                    onClick={() => go("findings", { severity: k })}>
                    <span className="row gap2">
                      <span className="sw" style={{ width: 10, height: 10, borderRadius: 3, background: sevColors[k] }} />
                      <span className="t-sm" style={{ fontWeight: 500 }}>{window.SEV_META[k].label}</span>
                    </span>
                    <span className="mono tnum" style={{ fontWeight: 600 }}>{counts[k]}</span>
                  </button>
                ) : null)}
                <div className="divider" style={{ margin: "4px 0" }} />
                <div className="t-xs faint">Click a severity to filter the findings list.</div>
              </div>
            </div>
          </div>

          {/* Trend */}
          <div className="card">
            <div className="card-head"><h3>Open findings — 8-week trend</h3><div className="spacer" />
              <span className="chip"><Icon.trend size={13} /> improving</span>
            </div>
            <div className="card-pad">
              <TrendChart data={window.TREND} />
              <div className="legend mt3">
                {[["critical","Critical"],["high","High"],["medium","Medium"],["low","Low"]].map(([k,l]) =>
                  <span key={k} className="li"><span className="sw" style={{ background: sevColors[k] }} />{l}</span>)}
              </div>
            </div>
          </div>
        </div>

        {/* Overdue + escalations */}
        <div className="grid mt5" style={{ gridTemplateColumns: "1.4fr 1fr", alignItems: "start" }}>
          <div className="card">
            <div className="card-head">
              <h3>Overdue &amp; escalating</h3>
              <span className="chip" style={{ color: "var(--danger)", borderColor: "var(--sev-critical-border)", background: "var(--sev-critical-bg)" }}>{overdue.length} breached</span>
              <div className="spacer" />
              <button className="btn ghost sm" onClick={() => go("sla")}>SLA tracker <Icon.chevRight size={14} /></button>
            </div>
            <div className="table-wrap">
              <table className="tbl">
                <thead><tr>
                  <th>Finding</th><th>Sev</th><th>Asset</th><th>SLA</th><th>Escalation</th>
                </tr></thead>
                <tbody>
                  {overdue.slice(0, 6).map(f => (
                    <tr key={f.id} onClick={() => go("detail", { id: f.id })}>
                      <td><div className="cell-strong nowrap" style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis" }}>{f.title}</div><div className="cell-sub mono">{f.id}</div></td>
                      <td><SeverityBadge sev={f.severity} variant="dot" /></td>
                      <td><AssetCell finding={f} /></td>
                      <td><SLAChip finding={f} /></td>
                      <td><div className="row gap2"><MiniStair stage={f.escStage} overdue /><span className="t-xs faint nowrap">{window.ESCALATION[f.escStage].role}</span></div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Scans in progress */}
          <div className="card">
            <div className="card-head"><h3>Scans in progress</h3><div className="spacer" />
              <button className="btn ghost sm" onClick={() => go("scan")}><Icon.plus size={14} /> New</button>
            </div>
            <div className="card-pad col gap4">
              {running.concat(queued).map(s => (
                <div key={s.id} className="col gap2">
                  <div className="row between">
                    <span className="row gap2">
                      <span style={{ color: "var(--ink-3)" }}>{s.pipeline === "infra" ? <Icon.server size={15} /> : <Icon.globe size={15} />}</span>
                      <span className="t-sm" style={{ fontWeight: 500 }}>{s.target}</span>
                    </span>
                    <span className="t-xs mono faint">{s.status === "queued" ? "queued" : s.progress + "%"}</span>
                  </div>
                  <div className="bar-track"><div className="bar-fill" style={{ width: s.progress + "%", background: s.status === "queued" ? "var(--border-strong)" : "var(--accent)" }} /></div>
                  <div className="row gap2 t-xs faint">
                    <span className="mono">{s.id}</span>·<span>{s.type}</span>·<span>{s.auth}</span>
                  </div>
                </div>
              ))}
              <div className="divider" style={{ margin: 0 }} />
              <div className="row between t-xs faint"><span>Last completed</span><span className="mono">SCAN-0095 · 5 findings</span></div>
            </div>
          </div>
        </div>

        {/* CISO-only: asset risk rollup */}
        {role === "ciso" && (
          <div className="card mt5">
            <div className="card-head"><h3>Risk by asset (Tier-1)</h3><div className="spacer" /><span className="t-xs faint">Open findings, weighted by severity</span></div>
            <div className="card-pad col gap4">
              {window.ASSETS.filter(a => a.crit === "Tier-1").map(a => {
                const fs = open.filter(f => f.assetId === a.id);
                const c = window.countBy(fs, "severity");
                return (
                  <div key={a.id} className="row gap4">
                    <div style={{ width: 200 }} className="t-sm">{a.name}</div>
                    <div className="flex1"><SevBar counts={c} /></div>
                    <div className="mono tnum t-sm" style={{ width: 30, textAlign: "right" }}>{fs.length}</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    );
  }
  window.Dashboard = Dashboard;
})();
