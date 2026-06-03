/* Scan schedule — cadence-driven plan, blackout-aware, across the inventory */
(function () {
  const { Icon, Empty } = window;

  // Pretty label per scan type (kept ASCII).
  const SCAN_LABEL = {
    "web-pentest": "Web pentest",
    "infra-va": "Internal VA",
    "cis-review": "CIS config review",
  };

  function Schedule({ go }) {
    const { data, loading } = window.useAsync(() => window.api.schedule(), []);

    if (loading && !data) {
      return (
        <div>
          <div className="page-head"><div>
            <h1 className="t-h1">Scan schedule</h1>
            <div className="page-sub">Cadence-driven plan across the approved inventory. Freeze windows are honoured.</div>
          </div></div>
          <div className="card"><Empty icon={Icon.clock} title="Loading schedule...">Fetching the scan plan from the orchestrator.</Empty></div>
        </div>
      );
    }

    return <ScheduleView data={data} go={go} />;
  }

  function ScheduleView({ data, go }) {
    const blackouts = (data && data.blackouts) || [];
    const entries = (data && data.entries) || [];
    const counts = (data && data.counts) || { total: entries.length, overdue: 0, dueSoon: 0 };

    return (
      <div>
        <div className="page-head"><div>
          <h1 className="t-h1">Scan schedule</h1>
          <div className="page-sub">Cadence-driven plan across the approved inventory -- web 2x/yr · internal VA 2x/yr · CIS config review 1x/yr. Freeze windows are honoured.</div>
        </div></div>

        {/* Summary cards */}
        <div className="row gap3 mb5">
          <SummaryCard label="Scheduled scans" value={counts.total} icon={Icon.clock} />
          <SummaryCard label="Overdue" value={counts.overdue} icon={Icon.scan} danger={counts.overdue > 0} />
          <SummaryCard label="Due soon" value={counts.dueSoon} icon={Icon.check} />
        </div>

        {/* Blackout / freeze windows */}
        <div className="card mb5">
          <div className="card-head"><h3>Freeze windows</h3><div className="spacer" /><span className="t-xs faint">{blackouts.length} blackout window(s)</span></div>
          <div className="card-pad">
            {blackouts.length ? (
              <div className="row gap2" style={{ flexWrap: "wrap" }}>
                {blackouts.map((b, i) => (
                  <span key={i} className="chip" style={{ background: "var(--accent-soft)", borderColor: "var(--accent-soft-border)", color: "var(--accent-text)" }}>
                    <span className="mono">{b.start}</span> -&gt; <span className="mono">{b.end}</span> · {b.reason}
                  </span>
                ))}
              </div>
            ) : (
              <span className="t-sm faint">No freeze windows configured.</span>
            )}
          </div>
        </div>

        {/* Schedule table */}
        <div className="card">
          <div className="card-head"><h3>Scan plan</h3><div className="spacer" /><span className="t-xs faint">{entries.length} entries</span></div>
          {entries.length ? (
            <div className="table-wrap">
              <table className="tbl">
                <thead><tr>
                  <th>Asset</th><th>Pipeline</th><th>Scan type</th><th>Cadence</th>
                  <th>Last run</th><th>Next due</th><th>Status</th>
                </tr></thead>
                <tbody>
                  {entries.map((e, i) => (
                    <tr key={(e.assetId || "") + "-" + e.scanType + "-" + i}>
                      <td>
                        <div className="cell-strong" style={{ maxWidth: 240 }}>{e.asset}</div>
                        <div className="cell-sub mono">{e.assetId}</div>
                      </td>
                      <td><span className="chip">{e.pipeline}</span></td>
                      <td><span className="t-sm">{SCAN_LABEL[e.scanType] || e.scanType}</span></td>
                      <td><span className="t-sm">{e.cadence}</span></td>
                      <td>{e.lastRun ? <span className="mono t-sm">{e.lastRun}</span> : <span className="faint">—</span>}</td>
                      <td><span className="mono t-sm">{e.nextDue || "—"}</span></td>
                      <td><StatusCell e={e} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty icon={Icon.clock} title="No scheduled scans">The cadence plan is empty.</Empty>
          )}
        </div>
      </div>
    );
  }

  function SummaryCard({ label, value, icon, danger }) {
    const Ico = icon;
    return (
      <div className="card card-pad" style={{ flex: 1, minWidth: 0 }}>
        <div className="row gap2" style={{ alignItems: "center" }}>
          <span className="center" style={{ width: 36, height: 36, borderRadius: 9,
            background: danger ? "var(--danger-bg)" : "var(--accent-soft)",
            color: danger ? "var(--danger)" : "var(--accent-text)" }}>
            {Ico ? <Ico size={18} /> : null}
          </span>
          <div className="col" style={{ lineHeight: 1.2 }}>
            <span style={{ fontSize: 24, fontWeight: 700, fontVariantNumeric: "tabular-nums", color: danger ? "var(--danger)" : "var(--ink)" }}>{value}</span>
            <span className="t-xs faint">{label}</span>
          </div>
        </div>
      </div>
    );
  }

  function StatusCell({ e }) {
    let chip;
    if (e.overdue) {
      chip = <span className="chip" style={{ color: "var(--danger)", background: "var(--sev-critical-bg)", borderColor: "var(--sev-critical-border)" }}>Overdue</span>;
    } else if (e.dueSoon) {
      chip = <span className="chip" style={{ background: "var(--accent-soft)", borderColor: "var(--accent-soft-border)", color: "var(--accent-text)" }}>Due soon</span>;
    } else {
      chip = <span className="chip">Scheduled</span>;
    }
    return (
      <div className="row gap1" style={{ flexWrap: "wrap", alignItems: "center" }}>
        {chip}
        {e.shiftedByBlackout && (
          <span className="chip t-xs" title={e.blackoutReason || "shifted by freeze window"} style={{ background: "var(--surface-2, var(--accent-soft))" }}>
            shifted: {e.blackoutReason || "freeze window"}
          </span>
        )}
      </div>
    );
  }

  window.Schedule = Schedule;
})();
