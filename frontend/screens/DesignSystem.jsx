/* Design System — palette, severity scale, type, spacing, components specs */
(function () {
  const { Icon, SeverityBadge, StatusPill, SLAChip, FrameworkChip, MiniStair } = window;

  function Swatch({ name, varName, hex, text }) {
    return (
      <div className="col gap2">
        <div style={{ height: 56, borderRadius: "var(--r-md)", background: `var(${varName})`, border: "1px solid var(--border)" }} />
        <div className="col"><span className="t-xs" style={{ fontWeight: 600 }}>{name}</span><span className="t-xs faint mono">{varName}</span></div>
      </div>
    );
  }

  function Block({ title, children, sub }) {
    return (
      <div className="card mb5">
        <div className="card-head"><h3>{title}</h3>{sub && <><div className="spacer" /><span className="t-xs faint">{sub}</span></>}</div>
        <div className="card-pad">{children}</div>
      </div>
    );
  }

  function Spec({ children }) { return <span className="chip mono" style={{ fontSize: 10 }}>{children}</span>; }

  function DesignSystem() {
    const sevs = ["critical", "high", "medium", "low", "info"];
    return (
      <div>
        <div className="page-head"><div>
          <h1 className="t-h1">Design system</h1>
          <div className="page-sub">Tokens and component specs powering the console. Severity uses colour <b>and</b> a shape/letter cue; targets meet WCAG AA.</div>
        </div></div>

        {/* Severity scale */}
        <Block title="Severity scale" sub="colour + glyph + letter — never colour alone">
          <div className="grid" style={{ gridTemplateColumns: "repeat(5,1fr)", gap: 16 }}>
            {sevs.map(s => (
              <div key={s} className="col gap3 center" style={{ padding: 16, border: "1px solid var(--border)", borderRadius: "var(--r-md)" }}>
                <SeverityBadge sev={s} lg />
                <window.SevGlyph sev={s} size={28} />
                <div className="col center gap1"><span className="t-xs" style={{ fontWeight: 600 }}>{window.SEV_META[s].label}</span>
                  <span className="t-xs faint">{s === "critical" ? "30d SLA" : s === "high" || s === "medium" ? "60d SLA" : s === "low" ? "90d" : "best-effort"}</span></div>
              </div>
            ))}
          </div>
          <div className="row gap4 mt4 wrap t-xs faint">
            <span className="row gap2"><b style={{ color: "var(--ink)" }}>Diamond</b> Critical</span>
            <span className="row gap2"><b style={{ color: "var(--ink)" }}>Triangle</b> High</span>
            <span className="row gap2"><b style={{ color: "var(--ink)" }}>Square</b> Medium</span>
            <span className="row gap2"><b style={{ color: "var(--ink)" }}>Circle</b> Low</span>
            <span className="row gap2"><b style={{ color: "var(--ink)" }}>Bar</b> Info</span>
          </div>
        </Block>

        {/* Neutral + accent palette */}
        <Block title="Palette" sub="cool neutrals · trust-blue accent">
          <div className="grid" style={{ gridTemplateColumns: "repeat(6,1fr)", gap: 14 }}>
            <Swatch name="Background" varName="--bg" />
            <Swatch name="Surface 2" varName="--surface-2" />
            <Swatch name="Surface 3" varName="--surface-3" />
            <Swatch name="Border" varName="--border" />
            <Swatch name="Ink" varName="--ink" />
            <Swatch name="Ink 2" varName="--ink-2" />
            <Swatch name="Accent" varName="--accent" />
            <Swatch name="Accent hover" varName="--accent-hover" />
            <Swatch name="Accent soft" varName="--accent-soft" />
            <Swatch name="Success" varName="--ok" />
            <Swatch name="Warning" varName="--warn" />
            <Swatch name="Danger" varName="--danger" />
          </div>
        </Block>

        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignItems: "start", gap: 24 }}>
          {/* Type */}
          <Block title="Type scale" sub="IBM Plex Sans + Mono">
            <div className="col gap3">
              <div className="row between" style={{ alignItems: "baseline" }}><span className="t-display">Display</span><Spec>28 / 600</Spec></div>
              <div className="row between" style={{ alignItems: "baseline" }}><span className="t-h1">Heading 1</span><Spec>22 / 600</Spec></div>
              <div className="row between" style={{ alignItems: "baseline" }}><span className="t-h2">Heading 2</span><Spec>17 / 600</Spec></div>
              <div className="row between" style={{ alignItems: "baseline" }}><span className="t-h3">Heading 3</span><Spec>14 / 600</Spec></div>
              <div className="row between" style={{ alignItems: "baseline" }}><span className="t-body">Body text</span><Spec>14 / 400</Spec></div>
              <div className="row between" style={{ alignItems: "baseline" }}><span className="t-xs">Small / caption</span><Spec>12 / 400</Spec></div>
              <div className="row between" style={{ alignItems: "baseline" }}><span className="t-label">Label</span><Spec>11 / 600 · caps</Spec></div>
              <div className="row between" style={{ alignItems: "baseline" }}><span className="mono">VLN-2087 · 9.3</span><Spec>mono · tnum</Spec></div>
            </div>
          </Block>

          {/* Spacing + radius + elevation */}
          <Block title="Spacing, radius, elevation" sub="8px base">
            <div className="t-label mb3">Spacing</div>
            <div className="row gap3 mb4" style={{ alignItems: "flex-end" }}>
              {[["1",4],["2",8],["3",12],["4",16],["5",24],["6",32]].map(([n,px]) =>
                <div key={n} className="col center gap1"><div style={{ width: px, height: px, background: "var(--accent)", borderRadius: 2 }} /><span className="t-xs faint mono">{px}</span></div>)}
            </div>
            <div className="t-label mb3">Radius</div>
            <div className="row gap3 mb4">
              {[["sm",4],["md",6],["lg",10],["xl",14]].map(([n,px]) =>
                <div key={n} className="col center gap1"><div style={{ width: 40, height: 40, background: "var(--surface-3)", border: "1px solid var(--border-strong)", borderRadius: px }} /><span className="t-xs faint mono">{n}</span></div>)}
            </div>
            <div className="t-label mb3">Elevation</div>
            <div className="row gap4">
              {[["sh-1","--sh-1"],["sh-2","--sh-2"],["sh-3","--sh-3"]].map(([n,v]) =>
                <div key={n} className="col center gap2"><div style={{ width: 56, height: 40, background: "var(--surface)", borderRadius: 8, boxShadow: `var(${v})` }} /><span className="t-xs faint mono">{n}</span></div>)}
            </div>
          </Block>
        </div>

        {/* Components */}
        <Block title="Components" sub="the triage primitives">
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 24 }}>
            <div className="col gap3">
              <span className="t-label">Severity badge</span>
              <div className="row gap2 wrap">{sevs.map(s => <SeverityBadge key={s} sev={s} />)}</div>
              <div className="row gap2 wrap mt2">{sevs.map(s => <SeverityBadge key={s} sev={s} variant="compact" />)}</div>
            </div>
            <div className="col gap3">
              <span className="t-label">SLA countdown chip</span>
              <div className="row gap2 wrap">
                <SLAChip finding={{ daysLeft: 24, deadline: window.TODAY }} />
                <SLAChip finding={{ daysLeft: 4, deadline: window.TODAY }} />
                <SLAChip finding={{ daysLeft: -6, deadline: window.TODAY }} />
                <SLAChip finding={{ isClosed: true }} />
              </div>
            </div>
            <div className="col gap3">
              <span className="t-label">Status pill</span>
              <div className="row gap2 wrap">{["open","triaged","in_progress","retest","closed","risk_accepted"].map(s => <StatusPill key={s} status={s} />)}</div>
            </div>
            <div className="col gap3">
              <span className="t-label">Category mapping</span>
              <div className="row gap2 wrap">
                <FrameworkChip finding={{ framework: "OWASP Web", catCode: "A03:2021", catName: "Injection" }} />
                <FrameworkChip finding={{ framework: "OWASP API", catCode: "API1:2023", catName: "BOLA" }} />
                <FrameworkChip finding={{ framework: "SANS", catCode: "CWE-798", catName: "Hardcoded" }} />
                <FrameworkChip finding={{ framework: "CIS", catCode: "CIS-5.2", catName: "Accounts" }} />
              </div>
            </div>
            <div className="col gap3">
              <span className="t-label">Escalation staircase</span>
              <div className="row gap3"><MiniStair stage={1} /><MiniStair stage={2} /><MiniStair stage={4} overdue /></div>
            </div>
            <div className="col gap3">
              <span className="t-label">Buttons</span>
              <div className="row gap2 wrap"><button className="btn primary sm">Primary</button><button className="btn sm">Default</button><button className="btn ghost sm">Ghost</button><button className="btn danger sm">Danger</button></div>
            </div>
          </div>
        </Block>

        <Block title="States & accessibility">
          <div className="grid" style={{ gridTemplateColumns: "repeat(3,1fr)", gap: 16 }}>
            <div className="col gap2"><span className="t-label">Loading</span><div className="card card-pad col gap2"><div className="skel" style={{ height: 12, width: "70%" }} /><div className="skel" style={{ height: 12, width: "90%" }} /><div className="skel" style={{ height: 12, width: "50%" }} /></div></div>
            <div className="col gap2"><span className="t-label">Empty</span><div className="card" style={{ minHeight: 120 }}><window.Empty icon={Icon.inbox} title="No findings">Queue clear.</window.Empty></div></div>
            <div className="col gap2"><span className="t-label">Principles</span>
              <ul className="t-sm muted" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.9 }}>
                <li>Severity = colour + shape + letter</li>
                <li>AA contrast on all text</li>
                <li>Focus rings on every control</li>
                <li>Tabular numerals for counts</li>
              </ul>
            </div>
          </div>
        </Block>
      </div>
    );
  }
  window.DesignSystem = DesignSystem;
})();
