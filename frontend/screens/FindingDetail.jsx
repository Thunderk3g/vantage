/* Finding detail — evidence, mapping, SLA, status workflow, history */
(function () {
  const { useState } = React;
  const { Icon, SeverityBadge, SLAChip, StatusPill, FrameworkChip, EscalationStepper, Empty } = window;

  const FLOW = ["open", "triaged", "in_progress", "retest", "closed"];

  function MetaRow({ label, children }) {
    return <div className="row between" style={{ padding: "9px 0", borderBottom: "1px solid var(--border)" }}>
      <span className="t-sm faint">{label}</span><span className="t-sm" style={{ fontWeight: 500, textAlign: "right" }}>{children}</span>
    </div>;
  }

  function FindingDetail({ id, go, role }) {
    // Fetch the single finding via the API (falls back to window.FINDINGS offline).
    const { data, loading } = window.useAsync(() => window.api.finding(id), [id]);
    if (loading && !data) {
      return (
        <div>
          <div className="row gap2 mb4 t-sm faint">
            <button className="btn ghost sm" onClick={() => go("findings")}><Icon.chevLeft size={15} /> Findings</button>
            <Icon.chevRight size={14} /> <span className="mono">{id}</span>
          </div>
          <div className="card"><Empty icon={Icon.search} title="Loading finding…">Fetching this finding from the scanner.</Empty></div>
        </div>
      );
    }
    const finding = data || window.FINDINGS.find(f => f.id === id);
    return <FindingDetailView finding={finding} id={id} go={go} role={role} />;
  }

  const ACTOR = "A. Mehta"; // TODO: real user from auth

  function FindingDetailView({ finding, id, go, role }) {
    const f = finding || window.FINDINGS[0];
    // `status` is the committed/displayed status; `pick` is the user's candidate
    // selection in the stepper. Nothing mutates until they deliberately Save.
    const [status, setStatus] = useState(f.status);
    const [pick, setPick] = useState(f.status);
    const [saving, setSaving] = useState(false);
    const [saveErr, setSaveErr] = useState(null);
    const [saved, setSaved] = useState(false);
    const [validatedBy, setValidatedBy] = useState(f.humanValidatedBy || null);
    const [validatedAt, setValidatedAt] = useState(f.humanValidatedAt ? new Date(f.humanValidatedAt) : null);
    const [note, setNote] = useState("");

    function saveStatus() {
      if (saving || pick === status) return; // deliberate, no-op when unchanged
      setSaving(true);
      setSaveErr(null);
      setSaved(false);
      window.api.setFindingStatus(f.id, { status: pick, actor: ACTOR, note: note.trim() ? note.trim() : undefined })
        .then(updated => {
          setStatus(updated.status);
          setPick(updated.status);
          if (updated.humanValidatedBy) setValidatedBy(updated.humanValidatedBy);
          if (updated.humanValidatedAt) setValidatedAt(new Date(updated.humanValidatedAt));
          setSaved(true);
        })
        .catch(err => {
          // Never fake success: keep the displayed status, surface the message.
          setSaveErr(err && err.message ? err.message : "Failed to update status.");
        })
        .finally(() => setSaving(false));
    }

    const evidence = `POST /v1/claims/4821 HTTP/2
Host: api.claims.lifeco.internal
Authorization: Bearer <policyholder-A token>

→ 200 OK   { "claimId": 4821, "policyholder": "B. Sharma", ... }
   Expected 403 — token belongs to a different policyholder.`;

    const history = [
      { icon: Icon.scan, t: "Detected by automated scan", who: "SCAN-0098 · gray-box / min-privilege", when: window.fmtDate(f.discovered), tag: "detected" },
      { icon: Icon.flag, t: "Triaged — confirmed true positive", who: f.owner, when: window.fmtDate(window.daysBetween ? new Date(f.discovered.getTime() + 86400000) : f.discovered), tag: "triaged" },
      { icon: Icon.user, t: "Assigned to " + f.owner, who: "AppSec Lead", when: window.fmtDate(new Date(f.discovered.getTime() + 86400000)), tag: "assigned" },
      ...(f.escStage >= 2 ? [{ icon: Icon.escalate, t: "Escalated to " + window.ESCALATION[f.escStage].role, who: "SLA engine", when: window.fmtDate(window.TODAY), tag: "escalated" }] : []),
    ];

    return (
      <div>
        <div className="row gap2 mb4 t-sm faint">
          <button className="btn ghost sm" onClick={() => go("findings")}><Icon.chevLeft size={15} /> Findings</button>
          <Icon.chevRight size={14} /> <span className="mono">{f.id}</span>
        </div>

        <div className="page-head">
          <div style={{ maxWidth: 720 }}>
            <div className="row gap3 mb2"><SeverityBadge sev={f.severity} lg /><FrameworkChip finding={f} /><span className="chip">{f.framework}</span></div>
            <h1 className="t-h1" style={{ textWrap: "balance" }}>{f.title}</h1>
            <div className="page-sub mono">{f.id} · CVSS {f.cvss.toFixed(1)} · discovered {window.fmtDate(f.discovered)} by {f.scan}</div>
          </div>
          <div className="spacer" />
          <SLAChip finding={f} showDate />
        </div>

        <div className="grid" style={{ gridTemplateColumns: "1fr 320px", alignItems: "start" }}>
          {/* LEFT column */}
          <div className="col gap5">
            {/* Status workflow */}
            <div className="card">
              <div className="card-head"><h3>Status workflow</h3><div className="spacer" /><StatusPill status={status} /></div>
              <div className="card-pad">
                <div className="seg" style={{ width: "100%" }}>
                  {FLOW.map(s => (
                    <button key={s} className={pick === s ? "active" : ""} style={{ flex: 1 }} disabled={saving} onClick={() => { setPick(s); setSaveErr(null); setSaved(false); }}>{window.STATUS_LABEL[s]}</button>
                  ))}
                </div>
                <div className="row gap3 mt4 wrap">
                  <button className="btn sm" disabled={saving}><Icon.user size={14} /> Reassign</button>
                  <button className="btn sm" disabled={saving} onClick={() => go("exception", { finding: f.id })}><Icon.exception size={14} /> Request exception</button>
                  <button className="btn sm" disabled={saving}><Icon.history size={14} /> Request retest</button>
                  <div className="spacer" />
                  <button className="btn primary sm" disabled={saving || pick === status} onClick={saveStatus}>
                    {saving ? <span><Icon.scan size={14} /> Saving…</span> : <span><Icon.check size={14} /> Save status</span>}
                  </button>
                </div>
                {saved && !saveErr && (
                  <div className="row gap2 mt3 t-sm" style={{ color: "var(--success, var(--ok, #16a34a))", fontWeight: 500 }}>
                    <Icon.check size={14} /> Status saved — now {window.STATUS_LABEL[status]}.
                  </div>
                )}
                {saveErr && (
                  <div className="mt3 t-sm" style={{ color: "var(--danger)", background: "var(--danger-soft, rgba(220,38,38,0.08))", border: "1px solid var(--danger)", borderRadius: "var(--r-md)", padding: "8px 12px", fontWeight: 500 }}>
                    {saveErr}
                  </div>
                )}
                {(validatedBy || validatedAt) && (
                  <div className="t-xs faint mt3">
                    Human-validated{validatedBy ? " by " + validatedBy : ""}{validatedAt ? " · " + window.fmtDate(validatedAt) : ""}
                  </div>
                )}
              </div>
            </div>

            {/* Description + evidence */}
            <div className="card">
              <div className="card-head"><h3>Description &amp; evidence</h3></div>
              <div className="card-pad col gap4">
                <p className="t-body" style={{ margin: 0, color: "var(--ink-2)" }}>
                  The endpoint authorises requests by token validity but does not verify that the requested
                  object belongs to the calling principal. A policyholder can enumerate <span className="mono">claimId</span> values
                  and retrieve claims, PII, and settlement amounts belonging to other customers.
                </p>
                <div>
                  <div className="t-label mb2">Reproduction / evidence</div>
                  <pre className="mono" style={{ background: "var(--surface-3)", border: "1px solid var(--border)", borderRadius: "var(--r-md)", padding: "14px 16px", fontSize: 12, overflowX: "auto", margin: 0, lineHeight: 1.6, color: "var(--ink)" }}>{evidence}</pre>
                </div>
                <div className="ph" style={{ height: 180 }}>screenshot — Burp Suite request/response capture</div>
                <div>
                  <div className="t-label mb2">Remediation guidance</div>
                  <p className="t-sm" style={{ margin: 0, color: "var(--ink-2)" }}>
                    Enforce object-level authorisation on every request: derive the owning policyholder from the
                    object and compare against the authenticated principal. Add an access-control test to the
                    claims service CI pipeline. Map to OWASP API1:2023.
                  </p>
                </div>
              </div>
            </div>

            {/* Remediation note */}
            <div className="card">
              <div className="card-head"><h3>Remediation notes</h3></div>
              <div className="card-pad">
                <textarea className="input" rows={3} placeholder="Add a remediation note, PR link, or owner comment…" value={note} onChange={e => setNote(e.target.value)} />
                <div className="row between mt3">
                  <span className="t-xs faint">Notes are recorded in the audit history.</span>
                  <button className="btn sm primary" disabled={!note.trim()}>Add note</button>
                </div>
              </div>
            </div>

            {/* History */}
            <div className="card">
              <div className="card-head"><h3>History &amp; audit trail</h3></div>
              <div className="card-pad">
                <div className="timeline">
                  {history.map((h, i) => {
                    const I = h.icon;
                    return <div key={i} className="tl-item">
                      <div className="tl-dot"><I size={14} /></div>
                      <div className="tl-body">
                        <div className="t-sm" style={{ fontWeight: 500 }}>{h.t}</div>
                        <div className="tl-meta">{h.who} · {h.when}</div>
                      </div>
                    </div>;
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* RIGHT rail */}
          <div className="col gap5">
            <div className="card card-pad">
              <div className="t-label mb2">Details</div>
              <MetaRow label="Affected asset">{f.asset}</MetaRow>
              <MetaRow label="Asset tier">{f.assetCrit}</MetaRow>
              <MetaRow label="Asset owner">{f.assetOwner}</MetaRow>
              <MetaRow label="Pipeline">{f.pipeline === "infra" ? "Infrastructure" : "Web Application"}</MetaRow>
              <MetaRow label="Category"><span className="mono">{f.catCode}</span></MetaRow>
              <MetaRow label={f.framework}>{f.catName}</MetaRow>
              <MetaRow label="CVSS v3.1"><span className="mono">{f.cvss.toFixed(1)}</span></MetaRow>
              <MetaRow label="Current owner">{f.owner}</MetaRow>
              <div className="row between" style={{ padding: "9px 0" }}><span className="t-sm faint">SLA</span><SLAChip finding={f} /></div>
            </div>

            {/* SLA / escalation */}
            <div className="card card-pad">
              <div className="row between mb3"><span className="t-label">SLA &amp; escalation</span>{f.deadline && <span className="t-xs faint mono">due {window.fmtDate(f.deadline)}</span>}</div>
              <div className="row between mb4">
                <div className="col"><span className="t-xs faint">Closure deadline</span><span className="t-h2 mono" style={{ color: f.daysLeft != null && f.daysLeft < 0 ? "var(--danger)" : "var(--ink)" }}>
                  {f.isClosed ? "Met" : f.daysLeft == null ? "—" : f.daysLeft < 0 ? Math.abs(f.daysLeft) + "d overdue" : f.daysLeft + "d left"}</span></div>
                <div className="col" style={{ textAlign: "right" }}><span className="t-xs faint">SLA window</span><span className="t-h2 mono">{f.slaDays ? f.slaDays + "d" : "—"}</span></div>
              </div>
              <EscalationStepper stage={f.escStage} compact />
              <div className="row between mt3 t-xs faint">
                <span>Currently with</span><span style={{ fontWeight: 600, color: "var(--ink-2)" }}>{window.ESCALATION[f.escStage].role}</span>
              </div>
              <button className="btn sm full mt3" onClick={() => go("sla")}>Open in SLA tracker</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
  window.FindingDetail = FindingDetail;
})();
