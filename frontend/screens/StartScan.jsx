/* Start a scan — approved-inventory targets only, pipeline/type/auth config */
(function () {
  const { useState } = React;
  const { Icon, Empty } = window;

  function Field({ label, hint, children, num }) {
    return (
      <div className="col gap2">
        <div className="row gap2">
          {num && <span className="center mono" style={{ width: 20, height: 20, borderRadius: 6, background: "var(--accent-soft)", color: "var(--accent-text)", fontSize: 11, fontWeight: 600 }}>{num}</span>}
          <span className="t-h3">{label}</span>
        </div>
        {hint && <span className="t-xs faint" style={{ marginLeft: num ? 28 : 0 }}>{hint}</span>}
        <div style={{ marginLeft: num ? 28 : 0, marginTop: 4 }}>{children}</div>
      </div>
    );
  }

  function OptionCard({ active, onClick, icon, title, desc }) {
    const I = icon;
    return (
      <button onClick={onClick} className="card" style={{
        textAlign: "left", padding: 14, cursor: "pointer", display: "flex", gap: 12, alignItems: "flex-start",
        borderColor: active ? "var(--accent)" : "var(--border)", background: active ? "var(--accent-soft)" : "var(--surface)",
        boxShadow: active ? "0 0 0 1px var(--accent)" : "var(--sh-1)", flex: 1,
      }}>
        {I && <span style={{ color: active ? "var(--accent-text)" : "var(--ink-3)", marginTop: 1 }}><I size={18} /></span>}
        <span className="col gap1">
          <span className="t-sm" style={{ fontWeight: 600, color: active ? "var(--accent-text)" : "var(--ink)" }}>{title}</span>
          <span className="t-xs faint">{desc}</span>
        </span>
      </button>
    );
  }

  function StartScan({ go, user }) {
    // Fetch the approved asset inventory via the API (falls back to window.ASSETS offline).
    const { data, loading } = window.useAsync(() => window.api.assets(), []);
    if (loading && !data) {
      return (
        <div className="content-narrow" style={{ margin: "0 auto" }}>
          <div className="page-head"><div>
            <h1 className="t-h1">Start a scan</h1>
            <div className="page-sub">Targets are restricted to the approved asset inventory — free-text hosts are not permitted.</div>
          </div></div>
          <div className="card"><Empty icon={Icon.shield} title="Loading inventory…">Fetching the approved asset inventory from the scanner.</Empty></div>
        </div>
      );
    }
    return <StartScanView assets={data || window.ASSETS} go={go} user={user} />;
  }

  function StartScanView({ assets: ASSETS, go, user }) {
    // Advisory gate: only analyst/admin may queue a scan (server enforces).
    const allowed = window.can(user, "analyst");
    const [target, setTarget] = useState(null);
    const [pipeline, setPipeline] = useState("web");
    const [type, setType] = useState("gray-box");
    const [auth, setAuth] = useState("min-privilege");
    const [pending, setPending] = useState(false);   // request in flight
    const [created, setCreated] = useState(null);     // the queued scan on success
    const [err, setErr] = useState(null);             // { message, status } on failure

    const assets = ASSETS.filter(a => pipeline === "web" ? a.type === "web" : a.type === "infra");
    const sel = ASSETS.find(a => a.id === target);

    function reset() {
      // Configure another: keep config, clear result/error state.
      setCreated(null);
      setErr(null);
    }

    function submit() {
      if (!target || pending) return;
      setPending(true);
      setErr(null);
      // SCOPE GATE: server validates the target is in the approved inventory.
      window.api.startScan({
        assetId: target,
        pipeline: pipeline,
        mode: type,
        authContext: type === "gray-box" ? auth : undefined,
      }).then(function (scan) {
        setCreated(scan);
      }).catch(function (e) {
        setErr({ message: (e && e.message) || "The scan could not be queued.", status: e && e.status });
      }).then(function () {
        setPending(false);
      });
    }

    if (created) {
      return (
        <div className="content-narrow" style={{ margin: "0 auto" }}>
          <div className="card card-pad center col gap4" style={{ padding: 56, textAlign: "center" }}>
            <span className="center" style={{ width: 56, height: 56, borderRadius: 14, background: "var(--ok-bg)", color: "var(--ok)" }}><Icon.check size={28} strokeWidth={2.5} /></span>
            <div>
              <h2 className="t-h1">Scan {created.id} queued for {created.target}</h2>
              <p className="page-sub">{(sel && sel.name) || created.target} · {type} · {pipeline === "web" ? "Web Application" : "Infrastructure"}{type === "gray-box" ? " · " + auth : ""} · status {created.status || "queued"}</p>
            </div>
            <div className="row gap3">
              <button className="btn primary" onClick={() => go("dashboard")}><Icon.play size={14} /> View scan</button>
              <button className="btn" onClick={reset}>Start another</button>
              <button className="btn" onClick={() => go("dashboard")}>Back to dashboard</button>
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="content-narrow" style={{ margin: "0 auto" }}>
        <div className="page-head"><div>
          <h1 className="t-h1">Start a scan</h1>
          <div className="page-sub">Targets are restricted to the approved asset inventory — free-text hosts are not permitted.</div>
        </div></div>

        <div className="col gap6">
          {/* 1. Pipeline */}
          <div className="card card-pad">
            <Field num="1" label="Pipeline" hint="Determines the engine and check library.">
              <div className="row gap3">
                <OptionCard active={pipeline === "web"} onClick={() => { setPipeline("web"); setTarget(null); }} icon={Icon.globe} title="Web Application" desc="OWASP Web & API Top 10, auth flows, business logic" />
                <OptionCard active={pipeline === "infra"} onClick={() => { setPipeline("infra"); setTarget(null); }} icon={Icon.server} title="Infrastructure" desc="Network, hosts, CIS benchmarks, patch levels" />
              </div>
            </Field>
          </div>

          {/* 2. Target */}
          <div className="card card-pad">
            <Field num="2" label="Target" hint="Pick from the approved inventory only.">
              <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {assets.map(a => (
                  <button key={a.id} onClick={() => setTarget(a.id)} className="card" style={{
                    textAlign: "left", padding: "12px 14px", cursor: "pointer", display: "flex", gap: 10, alignItems: "center",
                    borderColor: target === a.id ? "var(--accent)" : "var(--border)", background: target === a.id ? "var(--accent-soft)" : "var(--surface)",
                    boxShadow: target === a.id ? "0 0 0 1px var(--accent)" : "var(--sh-1)",
                  }}>
                    <span className={`center checkbox${target === a.id ? " on" : ""}`} style={{ borderRadius: "50%" }}>{target === a.id && <Icon.check size={11} strokeWidth={3} />}</span>
                    <span className="col gap1 flex1" style={{ minWidth: 0 }}>
                      <span className="t-sm" style={{ fontWeight: 600 }}>{a.name}</span>
                      <span className="t-xs faint mono" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.host}</span>
                    </span>
                    <span className="chip" style={{ flexShrink: 0 }}>{a.crit}</span>
                  </button>
                ))}
              </div>
              <div className="row gap2 mt3 t-xs faint"><Icon.lock size={13} /> Need a new target? Submit it to the asset inventory for approval first.</div>
            </Field>
          </div>

          {/* 3. Scan type */}
          <div className="card card-pad">
            <Field num="3" label="Scan type" hint="Black-box simulates an external attacker; gray-box uses provided context.">
              <div className="row gap3">
                <OptionCard active={type === "black-box"} onClick={() => setType("black-box")} icon={Icon.eye} title="Black-box" desc="No credentials or internal knowledge" />
                <OptionCard active={type === "gray-box"} onClick={() => setType("gray-box")} icon={Icon.shield} title="Gray-box" desc="Authenticated context provided below" />
              </div>
            </Field>
          </div>

          {/* 4. Auth context (gray-box only) */}
          {type === "gray-box" && (
            <div className="card card-pad">
              <Field num="4" label="Authentication context" hint="Privilege level the scanner authenticates with.">
                <div className="row gap3">
                  <OptionCard active={auth === "unauthenticated"} onClick={() => setAuth("unauthenticated")} title="Unauthenticated" desc="Public surface only" />
                  <OptionCard active={auth === "min-privilege"} onClick={() => setAuth("min-privilege")} title="Min-privilege" desc="Standard policyholder / agent role" />
                  <OptionCard active={auth === "max-privilege"} onClick={() => setAuth("max-privilege")} title="Max-privilege" desc="Admin / elevated role" />
                </div>
              </Field>
            </div>
          )}
        </div>

        {/* Error banner — server scope-gate refusal (403) or validation/other failure */}
        {err && (
          <div className="card card-pad mt5 row gap3" style={{
            alignItems: "flex-start",
            borderColor: "var(--danger)",
            background: "var(--danger-bg, var(--err-bg, var(--accent-soft)))",
          }}>
            <span style={{ color: "var(--danger)", marginTop: 1, flexShrink: 0 }}>
              {err.status === 403 ? <Icon.lock size={18} /> : <Icon.alert size={18} />}
            </span>
            <div className="col gap1">
              <span className="t-sm" style={{ fontWeight: 700, color: "var(--danger)" }}>
                {err.status === 403
                  ? "Refused: target rejected by the scope gate"
                  : err.status === 422
                    ? "Scan request invalid"
                    : "Scan could not be queued"}
              </span>
              <span className="t-sm">
                {err.status === 403 ? "Refused: " : ""}{err.message}
              </span>
              {err.status === 403 && (
                <span className="t-xs faint">Only assets in the approved inventory can be scanned. Submit this target for approval first.</span>
              )}
            </div>
          </div>
        )}

        {/* Sticky summary footer */}
        <div className="card card-pad mt5 row between" style={{ position: "sticky", bottom: 0 }}>
          <div className="row gap3 wrap t-sm">
            <span className="faint">Summary:</span>
            <span className="chip">{pipeline === "web" ? "Web Application" : "Infrastructure"}</span>
            <span className="chip">{sel ? sel.name : "no target"}</span>
            <span className="chip">{type}</span>
            {type === "gray-box" && <span className="chip">{auth}</span>}
          </div>
          <div className="row gap3">
            <button className="btn" disabled={pending} onClick={() => go("dashboard")}>Cancel</button>
            <button className="btn primary" disabled={!target || pending || !allowed} onClick={submit}
              title={allowed ? undefined : "requires the analyst role"}>
              {pending ? <><Icon.shield size={14} /> Queueing…</> : <><Icon.play size={14} /> Queue scan</>}
            </button>
          </div>
        </div>
      </div>
    );
  }
  window.StartScan = StartScan;
})();
