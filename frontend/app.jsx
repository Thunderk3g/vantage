/* App shell — sidebar nav, header, role switcher, router, tweaks */
(function () {
  const { useState, useEffect, useMemo } = React;
  const { Icon } = window;

  const ACCENTS = { blue: 255, teal: 200, indigo: 285, violet: 320 };

  const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
    "accent": "blue",
    "density": "regular",
    "contrast": "normal"
  }/*EDITMODE-END*/;

  const NAV = [
    { id: "dashboard", label: "Dashboard", icon: Icon.dashboard },
    { id: "scan", label: "Start a scan", icon: Icon.scan },
    { id: "findings", label: "Findings", icon: Icon.findings, count: "open" },
    { id: "sla", label: "SLA tracker", icon: Icon.sla, count: "overdue" },
    { id: "exception", label: "Exceptions", icon: Icon.exception },
    { id: "reports", label: "Reports", icon: Icon.reports },
  ];

  const CRUMB = {
    dashboard: "Dashboard", scan: "Start a scan", findings: "Findings",
    detail: "Findings · Detail", sla: "SLA & escalation", exception: "Exceptions",
    reports: "Reports", system: "Design system",
  };

  // Initials from a display name, e.g. "Vantage Dev" → "VD", "A. Mehta" → "AM".
  function initials(name) {
    if (!name) return "?";
    const parts = String(name).trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return "?";
    const first = parts[0][0] || "";
    const last = parts.length > 1 ? parts[parts.length - 1][0] || "" : "";
    return (first + last).toUpperCase();
  }

  // Pretty label for the primary role (admin wins; else first role; viewer default).
  function primaryRole(user) {
    const roles = (user && user.roles) || [];
    if (roles.indexOf("admin") !== -1) return "admin";
    return roles[0] || "viewer";
  }

  // Real identity control: shows the signed-in user (name + role badge + avatar)
  // with a Sign out action, or a Sign in button when signed out (prod 401).
  function Identity({ user }) {
    const [open, setOpen] = useState(false);

    if (!user) {
      return (
        <button className="btn primary" style={{ gap: 8 }}
          onClick={() => { window.location.href = window.api.loginUrl(); }}>
          <Icon.user size={15} /> <span>Sign in</span>
        </button>
      );
    }

    async function signOut() {
      try { await window.api.logout(); } catch (e) { /* ignore */ }
      window.location.reload();
    }

    return (
      <div style={{ position: "relative" }}>
        <button className="btn" onClick={() => setOpen(o => !o)} style={{ gap: 8 }} title={user.email || user.name}>
          <span className="col" style={{ lineHeight: 1.15, alignItems: "flex-end" }}>
            <span style={{ fontWeight: 600 }}>{user.name}</span>
            <span className="t-xs faint" style={{ textTransform: "capitalize" }}>{primaryRole(user)}</span>
          </span>
          <span className="center" style={{ width: 34, height: 34, borderRadius: "50%", background: "var(--accent-soft)", color: "var(--accent-text)", fontWeight: 600, fontSize: 13 }}>{initials(user.name)}</span>
        </button>
        {open && <>
          <div style={{ position: "fixed", inset: 0, zIndex: 20 }} onClick={() => setOpen(false)} />
          <div className="card" style={{ position: "absolute", right: 0, top: 48, width: 240, zIndex: 21, boxShadow: "var(--sh-3)", padding: 6 }}>
            <div className="col gap1" style={{ padding: "8px 10px" }}>
              <span style={{ fontWeight: 600 }}>{user.name}</span>
              {user.email && <span className="t-xs faint">{user.email}</span>}
              <div className="row gap1" style={{ marginTop: 4, flexWrap: "wrap" }}>
                {((user.roles && user.roles.length) ? user.roles : ["viewer"]).map(r => (
                  <span key={r} className="chip" style={{ textTransform: "capitalize" }}>{r}</span>
                ))}
              </div>
            </div>
            <div className="divider" style={{ margin: "4px 0" }} />
            <button className="nav-item" onClick={signOut} style={{ width: "100%" }}>
              <span className="nav-ico"><Icon.lock size={16} /></span>
              <span style={{ fontWeight: 600 }}>Sign out</span>
            </button>
          </div>
        </>}
      </div>
    );
  }

  function App() {
    const [t, setTweak] = window.useTweaks(TWEAK_DEFAULTS);
    const [page, setPage] = useState("dashboard");
    const [params, setParams] = useState({});
    const [collapsed, setCollapsed] = useState(false);

    // Who am I? Resolved once on load from the session cookie. null = signed out.
    const { data: user } = window.useAsync(() => window.api.me(), []);

    const go = (p, prm = {}) => { setPage(p); setParams(prm); document.querySelector(".content").scrollTop = 0; };

    // apply tweaks to :root
    useEffect(() => {
      document.documentElement.style.setProperty("--accent-h", ACCENTS[t.accent] || 255);
      document.documentElement.setAttribute("data-density", t.density === "regular" ? "" : t.density);
      document.documentElement.style.setProperty("--border", t.contrast === "high" ? "oklch(0.84 0.01 250)" : "oklch(0.918 0.004 250)");
      document.documentElement.style.setProperty("--border-strong", t.contrast === "high" ? "oklch(0.74 0.012 250)" : "oklch(0.86 0.006 250)");
    }, [t.accent, t.density, t.contrast]);

    const counts = useMemo(() => {
      const open = window.FINDINGS.filter(f => !f.isClosed);
      return { open: open.length, overdue: open.filter(f => f.daysLeft != null && f.daysLeft < 0).length };
    }, []);

    let Screen;
    switch (page) {
      case "dashboard": Screen = <window.Dashboard go={go} />; break;
      case "scan": Screen = <window.StartScan go={go} user={user} />; break;
      case "findings": Screen = <window.Findings initial={params} go={go} />; break;
      case "detail": Screen = <window.FindingDetail id={params.id} go={go} user={user} />; break;
      case "sla": Screen = <window.SLATracker go={go} />; break;
      case "exception": Screen = <window.Exceptions initial={params} go={go} user={user} />; break;
      case "reports": Screen = <window.Reports go={go} user={user} />; break;
      case "system": Screen = <window.DesignSystem />; break;
      default: Screen = <window.Dashboard go={go} />;
    }

    return (
      <div className={`app${collapsed ? " nav-collapsed" : ""}`}>
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="brand">
            <div className="brand-mark"><Icon.shield size={17} /></div>
            <div className="brand-text col" style={{ lineHeight: 1.2 }}>
              <span className="brand-name">Vantage</span>
              <span className="brand-sub">Vulnerability Console</span>
            </div>
          </div>
          <nav className="nav">
            <div className="nav-section">Operations</div>
            {NAV.map(n => {
              const NI = n.icon;
              // Advisory gate: only analyst/admin may start a scan. Hide the nav
              // entry for everyone else (server still enforces require_role).
              if (n.id === "scan" && !window.can(user, "analyst")) return null;
              return (
              <button key={n.id} className={`nav-item${page === n.id || (page === "detail" && n.id === "findings") ? " active" : ""}`} onClick={() => go(n.id)} title={n.label}>
                <span className="nav-ico"><NI size={17} /></span>
                <span className="nav-label">{n.label}</span>
                {n.count && counts[n.count] > 0 && <span className="nav-count" style={n.count === "overdue" ? { color: "var(--danger)" } : null}>{counts[n.count]}</span>}
              </button>
            ); })}
            <div className="nav-section">Reference</div>
            <button className={`nav-item${page === "system" ? " active" : ""}`} onClick={() => go("system")} title="Design system">
              <span className="nav-ico"><Icon.system size={17} /></span><span className="nav-label">Design system</span>
            </button>
          </nav>
          <div style={{ padding: "12px", borderTop: "1px solid var(--border)" }}>
            <button className="nav-item" onClick={() => setCollapsed(c => !c)} title="Collapse">
              <span className="nav-ico">{collapsed ? <Icon.chevRight size={17} /> : <Icon.chevLeft size={17} />}</span>
              <span className="nav-label">Collapse</span>
            </button>
          </div>
        </aside>

        {/* Main */}
        <div className="main">
          <header className="topbar">
            <button className="icon-btn" onClick={() => setCollapsed(c => !c)}><Icon.menu size={18} /></button>
            <span className="crumb"><b>{CRUMB[page]}</b></span>
            <div className="spacer" />
            <div className="input-wrap" style={{ width: 240 }}>
              <span className="ico-lead"><Icon.search size={15} /></span>
              <input className="input" placeholder="Search findings…" onKeyDown={e => { if (e.key === "Enter") go("findings"); }} />
            </div>
            <button className="icon-btn" title="Alerts" style={{ position: "relative" }}>
              <Icon.bell size={18} />
              <span style={{ position: "absolute", top: 7, right: 8, width: 7, height: 7, borderRadius: "50%", background: "var(--danger)", border: "1.5px solid var(--surface)" }} />
            </button>
            <Identity user={user} />
          </header>

          <main className="content">{Screen}</main>
        </div>

        {/* Tweaks */}
        <window.TweaksPanel>
          <window.TweakSection label="Theme" />
          <div style={{ padding: "4px 0 10px" }}>
            <div className="t-xs faint mb2" style={{ fontWeight: 600 }}>Accent</div>
            <div className="row gap2">
              {Object.keys(ACCENTS).map(k => (
                <button key={k} onClick={() => setTweak("accent", k)} title={k}
                  style={{ width: 30, height: 30, borderRadius: 8, cursor: "pointer", background: `oklch(0.55 0.15 ${ACCENTS[k]})`,
                    border: t.accent === k ? "2px solid var(--ink)" : "2px solid transparent", boxShadow: "var(--sh-1)" }} />
              ))}
            </div>
          </div>
          <window.TweakRadio label="Density" value={t.density} options={["compact", "regular", "comfortable"]} onChange={v => setTweak("density", v)} />
          <window.TweakRadio label="Contrast" value={t.contrast} options={["normal", "high"]} onChange={v => setTweak("contrast", v)} />
        </window.TweaksPanel>
      </div>
    );
  }
  window.App = App;
})();
