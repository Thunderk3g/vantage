/* Scan diff — compares two scan registers (previous "licensed" vs latest
   "oss"). Resolved = closed in the latest scan (closure-verified); new = only
   in latest; persisting = in both; regressed = persisting at a higher band. */
(function () {
  const { useMemo } = React;
  const { Icon, SeverityBadge, Empty } = window;

  function ScanDiff({ go }) {
    const { data, loading } = window.useAsync(() => window.api.scanDiff(), []);

    if (loading && !data) {
      return (
        <div>
          <div className="page-head"><div>
            <h1 className="t-h1">Scan diff</h1>
            <div className="page-sub">Compares the previous scan register against the latest one.</div>
          </div></div>
          <div className="card"><Empty icon={Icon.history} title="Loading scan diff...">Fetching the scan-register comparison from the orchestrator.</Empty></div>
        </div>
      );
    }

    return <ScanDiffView diff={data} go={go} />;
  }

  function ScanDiffView({ diff, go }) {
    const d = diff || {};
    const counts = d.counts || { baseline: 0, current: 0, resolved: 0, new: 0, persisting: 0, regressed: 0 };
    const baseLabel = d.baseLabel || "licensed";
    const headLabel = d.headLabel || "oss";

    // Flatten the four buckets into one row list, tagging each with a `change`.
    const rows = useMemo(() => {
      const out = [];
      (d.resolved || []).forEach(r => out.push(Object.assign({}, r, { change: "resolved" })));
      (d.new || []).forEach(r => out.push(Object.assign({}, r, { change: "new" })));
      (d.persisting || []).forEach(r => out.push(Object.assign({}, r, { change: "persisting" })));
      (d.regressed || []).forEach(r => out.push(Object.assign({}, r, { change: "regressed" })));
      return out;
    }, [d.resolved, d.new, d.persisting, d.regressed]);

    return (
      <div>
        <div className="page-head"><div>
          <h1 className="t-h1">Scan diff</h1>
          <div className="page-sub">
            Previous scan ({baseLabel}, {counts.baseline} findings) vs latest scan ({headLabel}, {counts.current} findings);
            resolved findings are closure-verified.
          </div>
        </div></div>

        {/* Summary cards */}
        <div className="row gap3 mb5 wrap">
          <SummaryCard label="Resolved" value={counts.resolved} tone="success" />
          <SummaryCard label="New" value={counts.new} tone="accent" />
          <SummaryCard label="Persisting" value={counts.persisting} tone="neutral" />
          <SummaryCard label="Regressed" value={counts.regressed} tone={counts.regressed > 0 ? "danger" : "neutral"} />
        </div>

        <div className="card">
          <div className="card-head">
            <h3>Register comparison</h3>
            <div className="spacer" />
            <span className="t-xs faint">{rows.length} finding(s) across both registers</span>
          </div>
          {rows.length === 0 ? (
            <Empty icon={Icon.check} title="No differences">The two scan registers match — nothing resolved, new, persisting, or regressed.</Empty>
          ) : (
            <div className="table-wrap" style={{ maxHeight: 560 }}>
              <table className="tbl">
                <thead><tr>
                  <th>Finding</th><th>Asset</th><th>Sev</th><th>Source</th><th>Change</th>
                </tr></thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={(r.signature || r.title || "row") + "-" + i}>
                      <td>
                        <div className="cell-strong" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.title}</div>
                        {r.signature && <div className="cell-sub mono" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.signature}</div>}
                      </td>
                      <td><span className="t-sm mono">{r.assetId || "-"}</span></td>
                      <td><SeverityBadge sev={r.severity} variant="dot" /></td>
                      <td><span className="t-sm">{r.sourceTool || "-"}</span></td>
                      <td><ChangeChip row={r} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    );
  }

  function SummaryCard({ label, value, tone }) {
    const palette = {
      success: { color: "var(--success, var(--ok, #16a34a))", bg: "var(--accent-soft)", border: "var(--accent-soft-border)" },
      accent: { color: "var(--accent-text)", bg: "var(--accent-soft)", border: "var(--accent-soft-border)" },
      danger: { color: "var(--danger)", bg: "var(--sev-critical-bg)", border: "var(--sev-critical-border)" },
      neutral: { color: "var(--ink)", bg: "var(--surface)", border: "var(--border)" },
    };
    const p = palette[tone] || palette.neutral;
    return (
      <div className="card card-pad" style={{ flex: 1, minWidth: 150, borderColor: p.border, background: p.bg }}>
        <div className="t-label">{label}</div>
        <div className="t-h1 mono" style={{ color: p.color, fontVariantNumeric: "tabular-nums" }}>{value || 0}</div>
      </div>
    );
  }

  function ChangeChip({ row }) {
    if (row.change === "resolved") {
      return <span className="chip" style={{ color: "var(--success, var(--ok, #16a34a))", background: "var(--accent-soft)", borderColor: "var(--accent-soft-border)" }}>Resolved</span>;
    }
    if (row.change === "new") {
      return <span className="chip" style={{ color: "var(--accent-text)", background: "var(--accent-soft)", borderColor: "var(--accent-soft-border)" }}>New</span>;
    }
    if (row.change === "regressed") {
      return <span className="chip" style={{ color: "var(--danger)", background: "var(--sev-critical-bg)", borderColor: "var(--sev-critical-border)" }}>Regressed {row.fromSeverity}-&gt;{row.severity}</span>;
    }
    return <span className="chip">Persisting</span>;
  }

  window.ScanDiff = ScanDiff;
})();
