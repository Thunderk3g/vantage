/* Exception management — request/track with approval tier + risk docs */
(function () {
  const { useState } = React;
  const { Icon, SeverityBadge } = window;

  const TIERS = [
    { tier: "CISO", note: "≤ 3 months", who: "Chief Information Security Officer" },
    { tier: "RMC", note: "> 3 months", who: "Risk Management Committee" },
    { tier: "Board", note: "> 12 months", who: "Board Risk Committee" },
  ];

  function tierFor(months) {
    if (months <= 3) return "CISO";
    if (months <= 12) return "RMC";
    return "Board";
  }

  function ExcStatus({ s }) {
    const map = { approved: ["closed", "Approved"], pending: ["in_progress", "Pending approval"], rejected: ["risk_accepted", "Rejected"] };
    const [cls, label] = map[s] || ["open", s];
    return <span className={`status ${cls}`}><span className="sdot" />{label}</span>;
  }

  function Exceptions({ initial, go }) {
    const [showForm, setShowForm] = useState(!!(initial && initial.finding));
    const [months, setMonths] = useState(2);
    const tier = tierFor(months);

    return (
      <div>
        <div className="page-head"><div>
          <h1 className="t-h1">Exception management</h1>
          <div className="page-sub">Risk-accepted findings and time-boxed exceptions. Approval tier is set by requested duration.</div>
        </div><div className="spacer" />
          <button className="btn primary" onClick={() => setShowForm(true)}><Icon.plus size={15} /> Request exception</button>
        </div>

        {/* Approval tiers */}
        <div className="grid mb5" style={{ gridTemplateColumns: "repeat(3,1fr)" }}>
          {TIERS.map((t, i) => (
            <div key={t.tier} className="card card-pad col gap2">
              <div className="row between"><span className="t-h2">{t.tier}</span><span className="chip mono">{t.note}</span></div>
              <span className="t-sm faint">{t.who}</span>
              <div className="divider" style={{ margin: "8px 0" }} />
              <span className="t-xs faint">{window.EXCEPTIONS.filter(e => e.tier === t.tier).length} exception(s) at this tier</span>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="card-head"><h3>Exception register</h3><div className="spacer" /><span className="t-xs faint">{window.EXCEPTIONS.length} total</span></div>
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr>
                <th>Exception</th><th>Finding</th><th>Sev</th><th>Asset</th><th>Duration</th><th>Approval tier</th><th>Status</th><th>Review by</th>
              </tr></thead>
              <tbody>
                {window.EXCEPTIONS.map(e => (
                  <tr key={e.id} onClick={() => go("detail", { id: e.finding })}>
                    <td><div className="cell-strong mono">{e.id}</div><div className="cell-sub" style={{ maxWidth: 220 }}>{e.title}</div></td>
                    <td><span className="mono t-sm">{e.finding}</span></td>
                    <td><SeverityBadge sev={e.severity} variant="dot" /></td>
                    <td><span className="t-sm">{e.asset}</span></td>
                    <td><span className="t-sm mono">{e.duration} mo</span></td>
                    <td><span className="chip" style={{ borderColor: "var(--accent-soft-border)", background: "var(--accent-soft)", color: "var(--accent-text)" }}>{e.tier}</span></td>
                    <td><ExcStatus s={e.status} /></td>
                    <td><span className="t-sm faint mono">{e.reviewDate}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Request form modal */}
        {showForm && (
          <>
            <div className="scrim" onClick={() => setShowForm(false)} />
            <div className="modal" style={{ width: 560 }}>
              <div className="modal-head">
                <div className="flex1"><h3 className="t-h2" style={{ margin: 0 }}>Request exception</h3>
                  <div className="t-xs faint mt1">{initial && initial.finding ? `For finding ${initial.finding}` : "Select a finding to risk-accept or time-box."}</div></div>
                <button className="icon-btn" onClick={() => setShowForm(false)}><Icon.x size={18} /></button>
              </div>
              <div className="modal-body col gap4">
                {!(initial && initial.finding) && <div className="col gap2"><label className="t-label">Finding</label>
                  <select className="select"><option>VLN-2044 — No MFA on underwriting admin console</option>{window.FINDINGS.slice(0, 8).map(f => <option key={f.id}>{f.id} — {f.title}</option>)}</select></div>}

                <div className="col gap2">
                  <label className="t-label">Requested duration</label>
                  <div className="row gap4">
                    <input type="range" min="1" max="24" value={months} onChange={e => setMonths(+e.target.value)} style={{ flex: 1, accentColor: "var(--accent)" }} />
                    <span className="mono" style={{ fontWeight: 600, width: 70, textAlign: "right" }}>{months} month{months > 1 ? "s" : ""}</span>
                  </div>
                </div>

                {/* Tier resolves from duration */}
                <div className="card card-pad row gap3" style={{ background: "var(--surface-2)", alignItems: "center" }}>
                  <span className="center" style={{ width: 36, height: 36, borderRadius: 9, background: "var(--accent-soft)", color: "var(--accent-text)", flexShrink: 0 }}><Icon.users size={18} /></span>
                  <div className="col gap1 flex1">
                    <span className="t-sm" style={{ fontWeight: 600 }}>Requires <b>{tier}</b> approval</span>
                    <span className="t-xs faint">{TIERS.find(t => t.tier === tier).who} · {TIERS.find(t => t.tier === tier).note}</span>
                  </div>
                  <div className="row gap1">{TIERS.map(t => <span key={t.tier} className="chip" style={{ opacity: t.tier === tier ? 1 : 0.4, borderColor: t.tier === tier ? "var(--accent)" : "var(--border)" }}>{t.tier}</span>)}</div>
                </div>

                <div className="col gap2"><label className="t-label">Risk justification <span className="faint" style={{ textTransform: "none", letterSpacing: 0 }}>(required)</span></label>
                  <textarea className="input" rows={3} placeholder="Business reason, compensating controls, and residual-risk assessment…" /></div>

                <div className="col gap2"><label className="t-label">Compensating controls</label>
                  <input className="input" placeholder="e.g. network segmentation, IP allow-listing, monitoring" /></div>

                <div className="row gap3">
                  <div className="ph" style={{ flex: 1, height: 56, fontSize: 11 }}>attach risk doc (.pdf)</div>
                  <div className="ph" style={{ flex: 1, height: 56, fontSize: 11 }}>attach owner sign-off</div>
                </div>
              </div>
              <div className="modal-foot">
                <button className="btn" onClick={() => setShowForm(false)}>Cancel</button>
                <button className="btn primary" onClick={() => setShowForm(false)}>Submit to {tier}</button>
              </div>
            </div>
          </>
        )}
      </div>
    );
  }
  window.Exceptions = Exceptions;
})();
