/* Findings list — filter bar, multi-sort, selection + bulk actions */
(function () {
  const { useState, useMemo } = React;
  const { Icon, SeverityBadge, SLAChip, StatusPill, FrameworkChip, AssetCell, Checkbox, MiniStair, Empty } = window;

  const STATUS_OPTS = ["open", "triaged", "in_progress", "retest", "closed", "risk_accepted"];
  const SLA_STATES = [["overdue", "Overdue"], ["at_risk", "≤ 7 days"], ["on_track", "On track"], ["met", "Met / closed"]];

  function slaState(f) {
    if (f.isClosed) return "met";
    if (f.daysLeft == null) return "on_track";
    if (f.daysLeft < 0) return "overdue";
    if (f.daysLeft <= 7) return "at_risk";
    return "on_track";
  }

  function Findings({ initial, go }) {
    const F = window.FINDINGS;
    const [q, setQ] = useState("");
    const [sev, setSev] = useState(initial && initial.severity ? [initial.severity] : []);
    const [status, setStatus] = useState([]);
    const [pipeline, setPipeline] = useState("all");
    const [asset, setAsset] = useState("all");
    const [slaFilter, setSlaFilter] = useState([]);
    const [sort, setSort] = useState({ key: "severity", dir: "asc" });
    const [sel, setSel] = useState(new Set());

    const toggle = (arr, set, v) => set(arr.includes(v) ? arr.filter(x => x !== v) : [...arr, v]);

    const filtered = useMemo(() => {
      let r = F.filter(f => {
        if (q && !(f.title.toLowerCase().includes(q.toLowerCase()) || f.id.toLowerCase().includes(q.toLowerCase()) || f.asset.toLowerCase().includes(q.toLowerCase()))) return false;
        if (sev.length && !sev.includes(f.severity)) return false;
        if (status.length && !status.includes(f.status)) return false;
        if (pipeline !== "all" && f.pipeline !== pipeline) return false;
        if (asset !== "all" && f.assetId !== asset) return false;
        if (slaFilter.length && !slaFilter.includes(slaState(f))) return false;
        return true;
      });
      const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      r.sort((a, b) => {
        let av, bv;
        switch (sort.key) {
          case "severity": av = sevRank[a.severity]; bv = sevRank[b.severity]; break;
          case "sla": av = a.daysLeft == null ? 9999 : a.daysLeft; bv = b.daysLeft == null ? 9999 : b.daysLeft; break;
          case "cvss": av = a.cvss; bv = b.cvss; break;
          case "asset": av = a.asset; bv = b.asset; break;
          case "status": av = a.status; bv = b.status; break;
          default: av = a.id; bv = b.id;
        }
        if (av < bv) return sort.dir === "asc" ? -1 : 1;
        if (av > bv) return sort.dir === "asc" ? 1 : -1;
        return 0;
      });
      return r;
    }, [F, q, sev, status, pipeline, asset, slaFilter, sort]);

    const setSortKey = (key) => setSort(s => s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "cvss" ? "desc" : "asc" });
    const sortInd = (key) => sort.key === key ? (sort.dir === "asc" ? <Icon.arrowUp size={12} /> : <Icon.arrowDown size={12} />) : null;

    const allSel = filtered.length > 0 && filtered.every(f => sel.has(f.id));
    const someSel = filtered.some(f => sel.has(f.id)) && !allSel;
    const toggleAll = () => { const n = new Set(sel); if (allSel) filtered.forEach(f => n.delete(f.id)); else filtered.forEach(f => n.add(f.id)); setSel(n); };
    const toggleOne = (id) => { const n = new Set(sel); n.has(id) ? n.delete(id) : n.add(id); setSel(n); };

    const activeFilters = sev.length + status.length + slaFilter.length + (pipeline !== "all" ? 1 : 0) + (asset !== "all" ? 1 : 0);
    const clearAll = () => { setSev([]); setStatus([]); setSlaFilter([]); setPipeline("all"); setAsset("all"); setQ(""); };

    return (
      <div>
        <div className="page-head">
          <div>
            <div className="page-title-row"><h1 className="t-h1">Findings</h1><span className="chip mono">{filtered.length}</span></div>
            <div className="page-sub">Triage, assign, and track remediation across the approved asset inventory.</div>
          </div>
          <div className="spacer" />
          <button className="btn"><Icon.download size={15} /> Export view</button>
        </div>

        {/* Filter bar */}
        <div className="card card-pad mb4">
          <div className="row gap3 wrap">
            <div className="input-wrap" style={{ flex: "1 1 260px", minWidth: 200 }}>
              <span className="ico-lead"><Icon.search size={15} /></span>
              <input className="input" placeholder="Search title, ID, or asset…" value={q} onChange={e => setQ(e.target.value)} />
            </div>
            <select className="select" style={{ width: "auto" }} value={pipeline} onChange={e => setPipeline(e.target.value)}>
              <option value="all">All pipelines</option><option value="web">Web Application</option><option value="infra">Infrastructure</option>
            </select>
            <select className="select" style={{ width: "auto", maxWidth: 220 }} value={asset} onChange={e => setAsset(e.target.value)}>
              <option value="all">All assets</option>
              {window.ASSETS.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
            {activeFilters > 0 && <button className="btn ghost sm" onClick={clearAll}><Icon.x size={13} /> Clear ({activeFilters})</button>}
          </div>

          <div className="divider" />

          <div className="row gap5 wrap" style={{ rowGap: 12 }}>
            <div className="row gap2 wrap">
              <span className="t-label" style={{ marginRight: 2 }}>Severity</span>
              {window.SEVERITY_ORDER.map(s => (
                <button key={s} className={`chip${sev.includes(s) ? "" : ""}`} onClick={() => toggle(sev, setSev, s)}
                  style={{ cursor: "pointer", borderColor: sev.includes(s) ? "var(--accent)" : "var(--border)", background: sev.includes(s) ? "var(--accent-soft)" : "var(--surface-3)", color: sev.includes(s) ? "var(--accent-text)" : "var(--ink-2)" }}>
                  <SeverityBadge sev={s} variant="dot" /> {window.SEV_META[s].label}
                </button>
              ))}
            </div>
            <div className="row gap2 wrap">
              <span className="t-label" style={{ marginRight: 2 }}>SLA</span>
              {SLA_STATES.map(([k, l]) => (
                <button key={k} className="chip" onClick={() => toggle(slaFilter, setSlaFilter, k)}
                  style={{ cursor: "pointer", borderColor: slaFilter.includes(k) ? "var(--accent)" : "var(--border)", background: slaFilter.includes(k) ? "var(--accent-soft)" : "var(--surface-3)", color: slaFilter.includes(k) ? "var(--accent-text)" : "var(--ink-2)" }}>{l}</button>
              ))}
            </div>
            <div className="row gap2 wrap">
              <span className="t-label" style={{ marginRight: 2 }}>Status</span>
              {STATUS_OPTS.map(s => (
                <button key={s} className="chip" onClick={() => toggle(status, setStatus, s)}
                  style={{ cursor: "pointer", borderColor: status.includes(s) ? "var(--accent)" : "var(--border)", background: status.includes(s) ? "var(--accent-soft)" : "var(--surface-3)", color: status.includes(s) ? "var(--accent-text)" : "var(--ink-2)" }}>{window.STATUS_LABEL[s]}</button>
              ))}
            </div>
          </div>
        </div>

        {/* Bulk action bar */}
        {sel.size > 0 && (
          <div className="bulkbar mb4">
            <Checkbox checked mixed={someSel} onChange={() => setSel(new Set())} />
            <span className="count">{sel.size} selected</span>
            <div className="spacer" />
            <button className="btn sm"><Icon.user size={14} /> Assign owner</button>
            <button className="btn sm"><Icon.flag size={14} /> Set status</button>
            <button className="btn sm"><Icon.exception size={14} /> Request exception</button>
            <button className="btn sm"><Icon.download size={14} /> Export selected</button>
          </div>
        )}

        {/* Table */}
        <div className="card">
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th className="col-check"><Checkbox checked={allSel} mixed={someSel} onChange={toggleAll} /></th>
                  <th className="sortable" onClick={() => setSortKey("severity")}>Severity {sortInd("severity")}</th>
                  <th>Finding</th>
                  <th className="sortable" onClick={() => setSortKey("asset")}>Asset {sortInd("asset")}</th>
                  <th>Category</th>
                  <th className="sortable col-num" onClick={() => setSortKey("cvss")}>CVSS {sortInd("cvss")}</th>
                  <th className="sortable" onClick={() => setSortKey("status")}>Status {sortInd("status")}</th>
                  <th className="sortable" onClick={() => setSortKey("sla")}>SLA {sortInd("sla")}</th>
                  <th>Owner</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(f => (
                  <tr key={f.id} className={sel.has(f.id) ? "selected" : ""} onClick={() => go("detail", { id: f.id })}>
                    <td className="col-check" onClick={e => e.stopPropagation()}><Checkbox checked={sel.has(f.id)} onChange={() => toggleOne(f.id)} /></td>
                    <td><SeverityBadge sev={f.severity} variant="compact" /></td>
                    <td><div className="cell-strong" style={{ maxWidth: 320 }}>{f.title}</div><div className="cell-sub mono">{f.id}</div></td>
                    <td><AssetCell finding={f} /></td>
                    <td><div className="col gap1"><FrameworkChip finding={f} /><span className="t-xs faint nowrap" style={{ marginTop: 3 }}>{f.framework}</span></div></td>
                    <td className="col-num mono">{f.cvss.toFixed(1)}</td>
                    <td><StatusPill status={f.status} /></td>
                    <td><SLAChip finding={f} /></td>
                    <td><span className="t-sm nowrap" style={{ color: f.owner === "Unassigned" ? "var(--ink-3)" : "var(--ink)" }}>{f.owner}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length === 0 && <Empty icon={Icon.search} title="No findings match these filters" action={<button className="btn" onClick={clearAll}>Clear filters</button>}>Try widening the severity, SLA, or status filters.</Empty>}
        </div>
      </div>
    );
  }
  window.Findings = Findings;
})();
