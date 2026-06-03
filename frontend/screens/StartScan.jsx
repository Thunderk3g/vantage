/* Start a scan — approved-inventory targets only, pipeline/type/auth config */
(function () {
  const { useState, useEffect, useRef } = React;
  const { Icon, Empty } = window;

  // ---- Live scan (real nmap) -------------------------------------------------
  // Kicks off a REAL nmap scan via POST /api/scans/live and polls the job until
  // it finishes. Targets are limited (in the UI) to loopback / host.docker.internal
  // / approved infra hosts; the server is the real scope gate and refuses the rest
  // with 403. Never fakes success — surfaces refusals and engine errors verbatim.
  const POLL_MS = 2000;
  const POLL_MAX = 60; // ~2 min cap so polling can never run forever.

  function LiveScanPanel({ assets, user }) {
    const allowed = window.can(user, "analyst");

    // Build the authorized target list: loopback + docker host + approved infra hosts.
    const infraHosts = (assets || [])
      .filter((a) => a.type === "infra" && a.host)
      .map((a) => ({ host: a.host, label: a.host + " — " + a.name }));
    const targetOptions = [
      { host: "127.0.0.1", label: "127.0.0.1 — loopback" },
      { host: "host.docker.internal", label: "host.docker.internal — your host" },
    ].concat(infraHosts);

    const [target, setTarget] = useState("127.0.0.1");
    const [mode, setMode] = useState("full");
    const [job, setJob] = useState(null);     // latest job poll result
    const [jobId, setJobId] = useState(null); // active job id (drives polling)
    const [starting, setStarting] = useState(false);
    const [refused, setRefused] = useState(null); // { target, message } on 403
    const [startErr, setStartErr] = useState(null); // other start failures

    const timerRef = useRef(null);
    const triesRef = useRef(0);

    function clearTimer() {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }

    // Poll the active job every POLL_MS until done/error or the try-cap is hit.
    // Cleans up on unmount and whenever jobId changes.
    useEffect(() => {
      if (!jobId) return undefined;
      let alive = true;
      triesRef.current = 0;

      async function tick() {
        triesRef.current += 1;
        try {
          const j = await window.api.getLiveScan(jobId);
          if (!alive) return;
          setJob(j);
          if (j.status === "done" || j.status === "error") {
            clearTimer();
          }
        } catch (e) {
          if (!alive) return;
          // Surface the polling failure (e.g. 404 unknown job) and stop.
          setJob({ status: "error", target: target, mode: mode, findingCount: null, register: null, error: (e && e.message) || "Lost contact with the scan job." });
          clearTimer();
        }
        if (alive && triesRef.current >= POLL_MAX && timerRef.current) {
          clearTimer();
          setJob((prev) => (prev && (prev.status === "queued" || prev.status === "running"))
            ? Object.assign({}, prev, { status: "error", error: "Timed out waiting for the scan to finish." })
            : prev);
        }
      }

      tick(); // poll immediately, then on an interval
      timerRef.current = setInterval(tick, POLL_MS);
      return () => { alive = false; clearTimer(); };
      // eslint-disable-next-line
    }, [jobId]);

    function run() {
      if (!allowed || starting) return;
      // A scan is "in flight" while queued/running — block re-runs until it ends.
      if (job && (job.status === "queued" || job.status === "running")) return;
      setStarting(true);
      setRefused(null);
      setStartErr(null);
      setJob(null);
      setJobId(null);
      clearTimer();
      window.api.startLiveScan({ target: target, mode: mode })
        .then((res) => {
          setJob({ jobId: res.jobId, status: res.status || "queued", target: res.target || target, mode: res.mode || mode, findingCount: null, register: null, error: null });
          setJobId(res.jobId);
        })
        .catch((e) => {
          const oos = (e && e.status === 403) || (e && e.data && e.data.error === "out_of_scope");
          if (oos) {
            setRefused({ target: target, message: "Refused: " + target + " is not in the approved scan scope." });
          } else {
            setStartErr((e && e.message) || "The live scan could not be started.");
          }
        })
        .then(() => { setStarting(false); });
    }

    const inFlight = job && (job.status === "queued" || job.status === "running");
    const running = starting || inFlight;
    const reg = (job && Array.isArray(job.register)) ? job.register : [];

    return (
      <div className="card card-pad col gap4">
        <div className="row gap2" style={{ alignItems: "center" }}>
          <span style={{ color: "var(--accent-text)" }}><Icon.target size={18} /></span>
          <span className="t-h3">Live scan (nmap)</span>
          <span className="chip" style={{ marginLeft: "auto" }}>real engine</span>
        </div>
        <div className="page-sub" style={{ marginTop: -4 }}>
          Run a real nmap scan against an authorized host and watch the register populate.
          Only loopback, the Docker host, and approved infrastructure hosts may be scanned.
        </div>

        <div className="grid" style={{ gridTemplateColumns: "2fr 1fr", gap: 12, alignItems: "end" }}>
          <div className="col gap2">
            <span className="t-xs faint">Target</span>
            <select className="select" value={target} onChange={(e) => setTarget(e.target.value)} disabled={running}>
              {targetOptions.map((o) => (
                <option key={o.host} value={o.host}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="col gap2">
            <span className="t-xs faint">Mode</span>
            <div className="seg">
              <button className={mode === "full" ? "on" : ""} disabled={running} onClick={() => setMode("full")}>full</button>
              <button className={mode === "recon" ? "on" : ""} disabled={running} onClick={() => setMode("recon")}>recon</button>
            </div>
          </div>
        </div>

        <div className="row gap3" style={{ alignItems: "center" }}>
          <button className="btn primary" onClick={run}
            disabled={!allowed || running}
            title={allowed ? undefined : "requires the analyst role"}>
            {running ? <><Icon.shield size={14} /> Scanning…</> : <><Icon.play size={14} /> Run live scan</>}
          </button>
          {running && <span className="t-xs faint mono">{job && job.jobId ? job.jobId : "starting…"}</span>}
        </div>

        {/* Refusal banner — server scope gate (403 / out_of_scope) */}
        {refused && (
          <div className="card card-pad row gap3" style={{ alignItems: "flex-start", borderColor: "var(--danger)", background: "var(--danger-bg, var(--err-bg, var(--accent-soft)))" }}>
            <span style={{ color: "var(--danger)", marginTop: 1, flexShrink: 0 }}><Icon.lock size={18} /></span>
            <div className="col gap1">
              <span className="t-sm" style={{ fontWeight: 700, color: "var(--danger)" }}>Out of scope</span>
              <span className="t-sm">{refused.message}</span>
            </div>
          </div>
        )}

        {/* Other start failures (network / 422 / unexpected) */}
        {startErr && (
          <div className="card card-pad row gap3" style={{ alignItems: "flex-start", borderColor: "var(--danger)", background: "var(--danger-bg, var(--err-bg, var(--accent-soft)))" }}>
            <span style={{ color: "var(--danger)", marginTop: 1, flexShrink: 0 }}><Icon.alert size={18} /></span>
            <div className="col gap1">
              <span className="t-sm" style={{ fontWeight: 700, color: "var(--danger)" }}>Scan could not be started</span>
              <span className="t-sm">{startErr}</span>
            </div>
          </div>
        )}

        {/* Live job state */}
        {job && (
          <div className="col gap3">
            <div className="row gap2 wrap t-sm" style={{ alignItems: "center" }}>
              <span className="faint">Status:</span>
              <span className="chip">{job.status}</span>
              <span className="chip mono">{job.target}</span>
              <span className="chip">{job.mode}</span>
              {inFlight && <span className="t-xs faint">Scanning {job.target}… polling every {POLL_MS / 1000}s.</span>}
            </div>

            {/* Engine error — phrased as a scan-engine fault (e.g. nmap not on PATH) */}
            {job.status === "error" && (
              <div className="card card-pad row gap3" style={{ alignItems: "flex-start", borderColor: "var(--danger)", background: "var(--danger-bg, var(--err-bg, var(--accent-soft)))" }}>
                <span style={{ color: "var(--danger)", marginTop: 1, flexShrink: 0 }}><Icon.alert size={18} /></span>
                <div className="col gap1">
                  <span className="t-sm" style={{ fontWeight: 700, color: "var(--danger)" }}>Scan engine error</span>
                  <span className="t-sm">{job.error || "The scan engine reported an error."}</span>
                </div>
              </div>
            )}

            {/* Completed — findingCount + register table, or a friendly 0-result line */}
            {job.status === "done" && (
              <div className="col gap3">
                <div className="row gap2 t-sm" style={{ alignItems: "center" }}>
                  <span className="center" style={{ width: 24, height: 24, borderRadius: 7, background: "var(--ok-bg)", color: "var(--ok)", flexShrink: 0 }}><Icon.check size={14} strokeWidth={2.5} /></span>
                  <span style={{ fontWeight: 600 }}>
                    {job.findingCount > 0
                      ? job.findingCount + (job.findingCount === 1 ? " finding" : " findings")
                      : "0 findings"}
                  </span>
                </div>
                {job.findingCount > 0 ? (
                  <div className="card" style={{ overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr className="t-xs faint">
                          <th style={{ textAlign: "left", padding: "8px 12px" }}>Title</th>
                          <th style={{ textAlign: "left", padding: "8px 12px", width: 120 }}>Severity</th>
                          <th style={{ textAlign: "left", padding: "8px 12px", width: 160 }}>Asset</th>
                        </tr>
                      </thead>
                      <tbody>
                        {reg.map((f, i) => (
                          <tr key={f.dedup_key || i} style={{ borderTop: "1px solid var(--border)" }}>
                            <td className="t-sm" style={{ padding: "8px 12px" }}>{f.title}</td>
                            <td style={{ padding: "8px 12px" }}><window.SeverityBadge sev={f.severity_normalized} variant="compact" /></td>
                            <td className="t-sm mono faint" style={{ padding: "8px 12px" }}>{f.asset_id}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <span className="t-sm faint">0 findings — no open services detected on {job.target}.</span>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

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

          {/* Live scan (real nmap) — start + poll a real engine run, separate flow */}
          <LiveScanPanel assets={ASSETS} user={user} />
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
