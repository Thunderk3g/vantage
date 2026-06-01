/* Exception management — request/track with approval tier + risk docs */
(function () {
  const { useState } = React;
  const { Icon, SeverityBadge, Empty } = window;

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

  // Advisory role required to decide an exception at a given approval tier.
  // The server enforces the same mapping (admin always allowed via window.can).
  function roleForTier(tier) {
    return { CISO: "approver_ciso", RMC: "approver_rmc", Board: "approver_board" }[tier];
  }

  function ExcStatus({ s }) {
    const map = { approved: ["closed", "Approved"], pending: ["in_progress", "Pending approval"], rejected: ["risk_accepted", "Rejected"] };
    const [cls, label] = map[s] || ["open", s];
    return <span className={`status ${cls}`}><span className="sdot" />{label}</span>;
  }

  function Exceptions({ initial, go, user }) {
    // Fetch the exception register via the API (falls back to window.EXCEPTIONS offline).
    const { data, loading } = window.useAsync(() => window.api.exceptions(), []);
    if (loading && !data) {
      return (
        <div>
          <div className="page-head"><div>
            <h1 className="t-h1">Exception management</h1>
            <div className="page-sub">Risk-accepted findings and time-boxed exceptions. Approval tier is set by requested duration.</div>
          </div></div>
          <div className="card"><Empty icon={Icon.exception} title="Loading exceptions…">Fetching the exception register.</Empty></div>
        </div>
      );
    }
    return <ExceptionsView exceptions={data || window.EXCEPTIONS} initial={initial} go={go} user={user} />;
  }

  function ExceptionsView({ exceptions, initial, go, user }) {
    // Advisory gate: only analyst/admin may request an exception (server enforces).
    const allowed = window.can(user, "analyst");
    const [showForm, setShowForm] = useState(!!(initial && initial.finding));
    const [months, setMonths] = useState(2);
    const tier = tierFor(months);

    // Local copy of the register so a successful request shows immediately.
    const [rows, setRows] = useState(exceptions);
    // The finding the request targets: fixed when launched from a finding,
    // otherwise driven by the in-modal select. Default to the first option.
    const initialFinding = initial && initial.finding ? initial.finding : "VLN-2044";
    const [findingId, setFindingId] = useState(initialFinding);
    const [risk, setRisk] = useState("");
    const [pending, setPending] = useState(false);
    const [error, setError] = useState(null);
    const [result, setResult] = useState(null); // { exception, tier } from the server
    // Per-row decision in flight, keyed by exception id, so only that row's
    // buttons disable while approving/rejecting.
    const [deciding, setDeciding] = useState({});

    // Approve / reject an exception. `decision` is "approve" | "reject". On
    // success the row is replaced with the server's authoritative exception
    // (status -> approved/rejected, reviewDate set) and a banner is shown.
    // On failure the row is unchanged and the error surfaces — never faked.
    function decide(ev, exc, decision) {
      ev.stopPropagation(); // don't trigger the row's navigate-to-detail
      if (deciding[exc.id]) return;
      setDeciding(prev => Object.assign({}, prev, { [exc.id]: true }));
      setError(null);
      setResult(null);
      window.api.decideException(exc.id, { decision: decision })
        .then(res => {
          setRows(prev => prev.map(r => (r.id === exc.id ? res.exception : r)));
          const verb = res.exception.status === "approved" ? "approved" : "rejected";
          const tail = res.finding
            ? (verb === "approved"
                ? " — finding " + res.finding.id + " risk-accepted."
                : " — finding " + res.finding.id + " returned to triage.")
            : ".";
          setResult({ message: "Exception " + res.exception.id + " " + verb + tail });
        })
        .catch(err => {
          setError(err && err.message ? err.message : "Decision failed");
        })
        .finally(() => {
          setDeciding(prev => { const n = Object.assign({}, prev); delete n[exc.id]; return n; });
        });
    }

    function openForm() {
      setError(null);
      setResult(null);
      setRisk("");
      setFindingId(initialFinding);
      setShowForm(true);
    }
    function closeForm() {
      setShowForm(false);
      setError(null);
      setPending(false);
    }

    async function submit() {
      if (pending) return;
      setPending(true);
      setError(null);
      try {
        const res = await window.api.requestException({
          findingId: findingId,
          durationMonths: months,
          documentedRisk: risk,
        });
        // Server resolves the authoritative tier; prepend the created row.
        setRows(prev => [res.exception, ...prev]);
        setResult(res);
        setShowForm(false);
      } catch (err) {
        setError(err && err.message ? err.message : "Request failed");
      } finally {
        setPending(false);
      }
    }

    return (
      <div>
        <div className="page-head"><div>
          <h1 className="t-h1">Exception management</h1>
          <div className="page-sub">Risk-accepted findings and time-boxed exceptions. Approval tier is set by requested duration.</div>
        </div><div className="spacer" />
          <button className="btn primary" onClick={openForm} disabled={!allowed} title={allowed ? undefined : "requires the analyst role"}><Icon.plus size={15} /> Request exception</button>
        </div>

        {/* Server-confirmed request / decision banner */}
        {result && (
          <div className="card card-pad row gap3 mb5" style={{ alignItems: "center", borderColor: "var(--accent-soft-border)", background: "var(--accent-soft)" }}>
            <Icon.check size={18} />
            {result.message ? (
              <span className="t-sm flex1">{result.message}</span>
            ) : (
              <span className="t-sm flex1">Exception <b className="mono">{result.exception.id}</b> requested for <span className="mono">{result.exception.finding}</span> — routed to <b>{result.tier}</b> for approval.</span>
            )}
            <button className="icon-btn" onClick={() => setResult(null)}><Icon.x size={16} /></button>
          </div>
        )}
        {/* Decision error banner (request errors render inside the modal) */}
        {error && !showForm && (
          <div className="card card-pad row gap3 mb5" style={{ alignItems: "center", borderColor: "var(--danger-soft-border, var(--danger))", background: "var(--danger-soft, var(--surface-2))", color: "var(--danger-text, var(--ink))" }}>
            <Icon.alert size={18} />
            <span className="t-sm flex1">{error}</span>
            <button className="icon-btn" onClick={() => setError(null)}><Icon.x size={16} /></button>
          </div>
        )}

        {/* Approval tiers */}
        <div className="grid mb5" style={{ gridTemplateColumns: "repeat(3,1fr)" }}>
          {TIERS.map((t, i) => (
            <div key={t.tier} className="card card-pad col gap2">
              <div className="row between"><span className="t-h2">{t.tier}</span><span className="chip mono">{t.note}</span></div>
              <span className="t-sm faint">{t.who}</span>
              <div className="divider" style={{ margin: "8px 0" }} />
              <span className="t-xs faint">{rows.filter(e => e.tier === t.tier).length} exception(s) at this tier</span>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="card-head"><h3>Exception register</h3><div className="spacer" /><span className="t-xs faint">{rows.length} total</span></div>
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr>
                <th>Exception</th><th>Finding</th><th>Sev</th><th>Asset</th><th>Duration</th><th>Approval tier</th><th>Status</th><th>Actions</th><th>Review by</th>
              </tr></thead>
              <tbody>
                {rows.map(e => {
                  const decidable = e.status === "requested" || e.status === "pending";
                  const canDecide = window.can(user, roleForTier(e.tier));
                  const busy = !!deciding[e.id];
                  return (
                  <tr key={e.id} onClick={() => go("detail", { id: e.finding })}>
                    <td><div className="cell-strong mono">{e.id}</div><div className="cell-sub" style={{ maxWidth: 220 }}>{e.title}</div></td>
                    <td><span className="mono t-sm">{e.finding}</span></td>
                    <td><SeverityBadge sev={e.severity} variant="dot" /></td>
                    <td><span className="t-sm">{e.asset}</span></td>
                    <td><span className="t-sm mono">{e.duration} mo</span></td>
                    <td><span className="chip" style={{ borderColor: "var(--accent-soft-border)", background: "var(--accent-soft)", color: "var(--accent-text)" }}>{e.tier}</span></td>
                    <td><ExcStatus s={e.status} /></td>
                    <td onClick={ev => ev.stopPropagation()}>
                      {decidable ? (
                        <div className="row gap2" style={{ flexWrap: "nowrap" }}>
                          <button className="btn sm primary" disabled={busy || !canDecide}
                            title={canDecide ? undefined : "requires the " + e.tier + " approver role"}
                            onClick={ev => decide(ev, e, "approve")}>
                            <Icon.check size={13} /> {busy ? "…" : "Approve"}
                          </button>
                          <button className="btn sm" disabled={busy || !canDecide}
                            title={canDecide ? undefined : "requires the " + e.tier + " approver role"}
                            onClick={ev => decide(ev, e, "reject")}
                            style={{ color: "var(--danger)", borderColor: "var(--danger-soft-border, var(--border))" }}>
                            <Icon.x size={13} /> Reject
                          </button>
                        </div>
                      ) : (
                        <span className="t-xs faint">—</span>
                      )}
                    </td>
                    <td><span className="t-sm faint mono">{e.reviewDate}</span></td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Request form modal */}
        {showForm && (
          <>
            <div className="scrim" onClick={closeForm} />
            <div className="modal" style={{ width: 560 }}>
              <div className="modal-head">
                <div className="flex1"><h3 className="t-h2" style={{ margin: 0 }}>Request exception</h3>
                  <div className="t-xs faint mt1">{initial && initial.finding ? `For finding ${initial.finding}` : "Select a finding to risk-accept or time-box."}</div></div>
                <button className="icon-btn" onClick={closeForm}><Icon.x size={18} /></button>
              </div>
              <div className="modal-body col gap4">
                {!(initial && initial.finding) && <div className="col gap2"><label className="t-label">Finding</label>
                  <select className="select" value={findingId} onChange={e => setFindingId(e.target.value)}><option value="VLN-2044">VLN-2044 — No MFA on underwriting admin console</option>{window.FINDINGS.slice(0, 8).map(f => <option key={f.id} value={f.id}>{f.id} — {f.title}</option>)}</select></div>}

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
                  <textarea className="input" rows={3} value={risk} onChange={e => setRisk(e.target.value)} placeholder="Business reason, compensating controls, and residual-risk assessment…" /></div>

                <div className="col gap2"><label className="t-label">Compensating controls</label>
                  <input className="input" placeholder="e.g. network segmentation, IP allow-listing, monitoring" /></div>

                <div className="row gap3">
                  <div className="ph" style={{ flex: 1, height: 56, fontSize: 11 }}>attach risk doc (.pdf)</div>
                  <div className="ph" style={{ flex: 1, height: 56, fontSize: 11 }}>attach owner sign-off</div>
                </div>
              </div>
              {error && (
                <div className="modal-body" style={{ paddingTop: 0 }}>
                  <div className="card card-pad row gap2" style={{ alignItems: "center", borderColor: "var(--danger-soft-border, var(--border))", background: "var(--danger-soft, var(--surface-2))", color: "var(--danger-text, var(--text))" }}>
                    <Icon.alert size={16} />
                    <span className="t-sm">{error}</span>
                  </div>
                </div>
              )}
              <div className="modal-foot">
                <button className="btn" onClick={closeForm} disabled={pending}>Cancel</button>
                <button className="btn primary" onClick={submit} disabled={pending || !allowed} title={allowed ? undefined : "requires the analyst role"}>{pending ? "Submitting…" : `Submit to ${tier}`}</button>
              </div>
            </div>
          </>
        )}
      </div>
    );
  }
  window.Exceptions = Exceptions;
})();
