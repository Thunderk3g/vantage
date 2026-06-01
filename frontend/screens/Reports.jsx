/* Reports — configure, generate, export (Excel/Word/PDF + password step) */
(function () {
  const { useState } = React;
  const { Icon, Empty } = window;

  const TEMPLATES = [
    { id: "exec", name: "Executive summary", desc: "Posture, SLA health, trend — for CISO / Board", icon: Icon.trend },
    { id: "audit", name: "Audit & compliance pack", desc: "Full findings, evidence, mappings, exceptions", icon: Icon.shield },
    { id: "asset", name: "Per-asset report", desc: "Findings & remediation for one application", icon: Icon.server },
    { id: "sla", name: "SLA & escalation report", desc: "Overdue, escalated, exceptions register", icon: Icon.clock },
  ];
  const FORMATS = [
    { id: "pdf", name: "PDF", desc: "Final, distribution-ready", icon: Icon.file, protect: true },
    { id: "xlsx", name: "Excel", desc: "Findings register (.xlsx)", icon: Icon.grid },
    { id: "docx", name: "Word", desc: "Editable report (.docx)", icon: Icon.detail },
  ];

  function Reports({ go, user }) {
    // Fetch the approved asset inventory and findings register via the API.
    // Both fall back to window.ASSETS / window.FINDINGS offline (api.js handles
    // the per-call fallback internally; the `||` here guards a hard failure).
    const { data, loading } = window.useAsync(() => Promise.all([
      window.api.assets(),
      window.api.findings(),
    ]).then(([assets, findings]) => ({ assets, findings })), []);

    if (loading && !data) {
      return (
        <div className="content-narrow" style={{ margin: "0 auto" }}>
          <div className="page-head"><div>
            <h1 className="t-h1">Reports</h1>
            <div className="page-sub">Generate and export findings reports. Final PDFs are password-protected before distribution.</div>
          </div></div>
          <div className="card"><Empty icon={Icon.file} title="Loading report data…">Fetching the asset inventory and findings register.</Empty></div>
        </div>
      );
    }

    const assets = (data && data.assets) || window.ASSETS;
    const findings = (data && data.findings && data.findings.findings) || window.FINDINGS;
    return <ReportsView go={go} assets={assets} findings={findings} user={user} />;
  }

  function ReportsView({ go, assets, findings, user }) {
    // Advisory gate: analyst / approver_* / admin may generate reports (server enforces).
    const allowed = window.can(user, "analyst", "approver_ciso", "approver_rmc", "approver_board");
    const [tpl, setTpl] = useState("audit");
    const [fmt, setFmt] = useState("pdf");
    const [scope, setScope] = useState("all");
    const [stage, setStage] = useState("config"); // config | password | generating | done
    const [openPw, setOpenPw] = useState("");   // password to open the PDF
    const [ownerPw, setOwnerPw] = useState(""); // owner password (prevents copy/modify)
    const [err, setErr] = useState("");         // surfaced error message (server or client)
    const [result, setResult] = useState(null); // { reportId, generatedAt, files }

    const fmtMeta = FORMATS.find(f => f.id === fmt);
    const needsPw = fmtMeta.protect;

    // Single-format picker on this screen: send [fmt]. (Array shape supports
    // multi-format if the picker ever becomes multi-select.)
    const formats = [fmt];

    const generate = () => {
      setErr("");
      if (needsPw) { setStage("password"); return; }
      run();
    };

    const run = async () => {
      // Client-side guard for the PDF contract: two NON-EMPTY, DIFFERING
      // passwords. The server still enforces this (422) — we never fake it.
      if (needsPw) {
        if (!openPw || !ownerPw) { setErr("Both passwords are required."); return; }
        if (openPw === ownerPw) { setErr("Passwords must differ."); return; }
      }
      setErr("");
      setStage("generating");
      try {
        const res = await window.api.generateReport({
          template: tpl,
          scope,
          formats,
          openPassword: needsPw ? openPw : undefined,
          ownerPassword: needsPw ? ownerPw : undefined,
        });
        setResult(res);
        setStage("done");
      } catch (e) {
        // Surface the server message on the stage we came from so the user can
        // correct input and retry. Never advance to "done".
        setErr((e && e.message) || "Report generation failed.");
        setStage(needsPw ? "password" : "config");
      }
    };

    return (
      <div className="content-narrow" style={{ margin: "0 auto" }}>
        <div className="page-head"><div>
          <h1 className="t-h1">Reports</h1>
          <div className="page-sub">Generate and export findings reports. Final PDFs are password-protected before distribution.</div>
        </div></div>

        <div className="grid" style={{ gridTemplateColumns: "1fr 300px", alignItems: "start" }}>
          <div className="col gap5">
            <div className="card">
              <div className="card-head"><h3>Report template</h3></div>
              <div className="card-pad grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {TEMPLATES.map(t => {
                  const I = t.icon, active = tpl === t.id;
                  return <button key={t.id} onClick={() => setTpl(t.id)} className="card" style={{
                    textAlign: "left", padding: 14, cursor: "pointer", display: "flex", gap: 12, alignItems: "flex-start",
                    borderColor: active ? "var(--accent)" : "var(--border)", background: active ? "var(--accent-soft)" : "var(--surface)",
                    boxShadow: active ? "0 0 0 1px var(--accent)" : "var(--sh-1)",
                  }}>
                    <span style={{ color: active ? "var(--accent-text)" : "var(--ink-3)" }}><I size={18} /></span>
                    <span className="col gap1"><span className="t-sm" style={{ fontWeight: 600 }}>{t.name}</span><span className="t-xs faint">{t.desc}</span></span>
                  </button>;
                })}
              </div>
            </div>

            <div className="card">
              <div className="card-head"><h3>Scope</h3></div>
              <div className="card-pad col gap3">
                <div className="seg">
                  {[["all","All open findings"],["overdue","Overdue only"],["tier1","Tier-1 assets"],["range","Date range"]].map(([k,l]) =>
                    <button key={k} className={scope === k ? "active" : ""} onClick={() => setScope(k)}>{l}</button>)}
                </div>
                <div className="row gap3 mt2 t-xs faint"><Icon.findings size={13} /> Estimated {scope === "overdue" ? 6 : scope === "tier1" ? 18 : 21} findings · {scope === "tier1" ? "8" : "12"} assets</div>
              </div>
            </div>

            <div className="card">
              <div className="card-head"><h3>Export format</h3></div>
              <div className="card-pad row gap3">
                {FORMATS.map(ff => {
                  const I = ff.icon, active = fmt === ff.id;
                  return <button key={ff.id} onClick={() => setFmt(ff.id)} className="card" style={{
                    flex: 1, textAlign: "left", padding: 14, cursor: "pointer", display: "flex", gap: 12, alignItems: "center",
                    borderColor: active ? "var(--accent)" : "var(--border)", background: active ? "var(--accent-soft)" : "var(--surface)",
                    boxShadow: active ? "0 0 0 1px var(--accent)" : "var(--sh-1)",
                  }}>
                    <span style={{ color: active ? "var(--accent-text)" : "var(--ink-3)" }}><I size={20} /></span>
                    <span className="col gap1"><span className="t-sm" style={{ fontWeight: 600 }}>{ff.name}{ff.protect && <span className="faint" style={{ marginLeft: 6, fontWeight: 400 }}><Icon.lock size={11} /></span>}</span><span className="t-xs faint">{ff.desc}</span></span>
                  </button>;
                })}
              </div>
            </div>
          </div>

          {/* Preview / action rail */}
          <div className="col gap4">
            <div className="card card-pad col gap3">
              <div className="ph" style={{ height: 200 }}>report preview — {tpl}</div>
              <div className="t-label">Document</div>
              <div className="row between t-sm"><span className="faint">Template</span><span style={{ fontWeight: 500 }}>{TEMPLATES.find(t => t.id === tpl).name}</span></div>
              <div className="row between t-sm"><span className="faint">Format</span><span style={{ fontWeight: 500 }}>{fmtMeta.name}</span></div>
              <div className="row between t-sm"><span className="faint">Protection</span><span style={{ fontWeight: 500 }}>{needsPw ? "Password" : "None"}</span></div>
              <div className="row between t-sm"><span className="faint">Classification</span><span className="chip" style={{ color: "var(--danger)", background: "var(--sev-critical-bg)", borderColor: "var(--sev-critical-border)" }}>Confidential</span></div>
              <button className="btn primary full mt2" onClick={generate} disabled={!allowed} title={allowed ? undefined : "requires the analyst or an approver role"}><Icon.download size={15} /> Generate {fmtMeta.name}</button>
              {!allowed && <span className="t-xs faint">Generating reports requires the analyst or an approver role.</span>}
              {err && stage === "config" && <span className="t-xs" style={{ color: "var(--danger)" }}>{err}</span>}
            </div>
            <div className="card card-pad t-xs faint col gap2">
              <span className="row gap2"><Icon.lock size={13} /> Final PDFs are AES-256 encrypted.</span>
              <span className="row gap2"><Icon.history size={13} /> Every export is logged for audit.</span>
            </div>
          </div>
        </div>

        {/* Password modal */}
        {stage === "password" && (
          <>
            <div className="scrim" onClick={() => setStage("config")} />
            <div className="modal" style={{ width: 440 }}>
              <div className="modal-head"><span className="center" style={{ width: 38, height: 38, borderRadius: 10, background: "var(--accent-soft)", color: "var(--accent-text)" }}><Icon.lock size={18} /></span>
                <div><h3 className="t-h2" style={{ margin: 0 }}>Protect final PDF</h3><div className="t-xs faint mt1">Required for confidential distribution. Share the password over a separate channel.</div></div>
              </div>
              <div className="modal-body col gap4">
                <div className="col gap2"><label className="t-label">Password to open</label><input className="input" type="password" value={openPw} onChange={e => { setOpenPw(e.target.value); setErr(""); }} placeholder="Min 12 chars, 1 symbol" /></div>
                <div className="col gap2"><label className="t-label">Owner password (prevents copy/modify)</label><input className="input" type="password" value={ownerPw} onChange={e => { setOwnerPw(e.target.value); setErr(""); }} placeholder="Must differ from the open password" /></div>
                {openPw && ownerPw && openPw === ownerPw && <span className="t-xs" style={{ color: "var(--danger)" }}>Passwords must differ.</span>}
                {err && <span className="t-xs" style={{ color: "var(--danger)" }}>{err}</span>}
                <label className="row gap2 t-sm"><span className="checkbox on"><Icon.check size={11} strokeWidth={3} /></span> Log this export to the audit trail</label>
              </div>
              <div className="modal-foot">
                <button className="btn" onClick={() => { setErr(""); setStage("config"); }}>Cancel</button>
                <button className="btn primary" disabled={openPw.length < 12 || !ownerPw || openPw === ownerPw || !allowed} title={allowed ? undefined : "requires the analyst or an approver role"} onClick={run}><Icon.lock size={14} /> Encrypt &amp; generate</button>
              </div>
            </div>
          </>
        )}

        {(stage === "generating" || stage === "done") && (
          <>
            <div className="scrim" onClick={() => stage === "done" && setStage("config")} />
            <div className="modal" style={{ width: 400 }}>
              <div className="modal-body center col gap4" style={{ padding: 40, textAlign: "center" }}>
                {stage === "generating" ? <>
                  <span className="center" style={{ width: 48, height: 48, borderRadius: 12, background: "var(--accent-soft)", color: "var(--accent-text)" }}><Icon.settings size={24} /></span>
                  <div><h3 className="t-h2" style={{ margin: 0 }}>Generating {fmtMeta.name}…</h3><p className="t-sm faint mt1">Compiling findings, evidence and mappings.</p></div>
                  <div className="bar-track full"><div className="bar-fill" style={{ width: "70%" }} /></div>
                </> : <>
                  <span className="center" style={{ width: 48, height: 48, borderRadius: 12, background: "var(--ok-bg)", color: "var(--ok)" }}><Icon.check size={26} strokeWidth={2.5} /></span>
                  <div>
                    <h3 className="t-h2" style={{ margin: 0 }}>Report ready</h3>
                    {result && <p className="t-xs faint mt1 mono">{result.reportId} · {result.generatedAt}{needsPw ? " · encrypted" : ""}</p>}
                  </div>
                  <div className="col gap2 full">
                    {result && Object.keys(result.files || {}).map(f => {
                      const I = (FORMATS.find(ff => ff.id === f) || {}).icon || Icon.download;
                      return <a key={f} className="btn primary full" href={window.api.reportDownloadUrl(result.reportId, f)} target="_blank" rel="noopener noreferrer">
                        <I size={14} /> Download {(FORMATS.find(ff => ff.id === f) || { name: f }).name}
                      </a>;
                    })}
                  </div>
                  <div className="row gap3"><button className="btn" onClick={() => setStage("config")}>Close</button></div>
                </>}
              </div>
            </div>
          </>
        )}
      </div>
    );
  }
  window.Reports = Reports;
})();
