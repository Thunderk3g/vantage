/* Shared primitives — severity, status, SLA, chips, stepper, charts */
(function () {
  const { Icon } = window;
  const SEV_META = {
    critical: { label: "Critical", letter: "C" },
    high:     { label: "High",     letter: "H" },
    medium:   { label: "Medium",   letter: "M" },
    low:      { label: "Low",      letter: "L" },
    info:     { label: "Info",     letter: "I" },
  };
  window.SEV_META = SEV_META;

  // Non-color cue: each severity has a distinct shape glyph + letter.
  function SevGlyph({ sev, size = 13 }) {
    const c = "currentColor";
    const wrap = (ch) => <svg width={size} height={size} viewBox="0 0 16 16">{ch}</svg>;
    switch (sev) {
      case "critical": return wrap(<path d="M8 1l7 7-7 7-7-7 7-7z" fill={c} />); // diamond
      case "high":     return wrap(<path d="M8 2l6.5 11.5h-13L8 2z" fill={c} />); // triangle
      case "medium":   return wrap(<rect x="3" y="3" width="10" height="10" rx="1.5" fill={c} />); // square
      case "low":      return wrap(<circle cx="8" cy="8" r="5.5" fill={c} />); // circle
      default:         return wrap(<rect x="2.5" y="6.5" width="11" height="3" rx="1.5" fill={c} />); // bar
    }
  }
  window.SevGlyph = SevGlyph;

  function SeverityBadge({ sev, variant = "full", lg }) {
    const m = SEV_META[sev] || SEV_META.info;
    if (variant === "dot") {
      return <span className={`sev ${sev} dot`} title={m.label} aria-label={m.label}><SevGlyph sev={sev} /></span>;
    }
    return (
      <span className={`sev ${sev}${lg ? " lg" : ""}`} aria-label={`${m.label} severity`}>
        <span className="glyph"><SevGlyph sev={sev} /></span>
        {variant === "compact" ? m.letter : m.label}
      </span>
    );
  }
  window.SeverityBadge = SeverityBadge;

  const STATUS_LABEL = {
    open: "Open", triaged: "Triaged", in_progress: "In Progress",
    retest: "Awaiting Retest", closed: "Closed", risk_accepted: "Risk Accepted",
  };
  window.STATUS_LABEL = STATUS_LABEL;
  function StatusPill({ status }) {
    return <span className={`status ${status}`}><span className="sdot" />{STATUS_LABEL[status] || status}</span>;
  }
  window.StatusPill = StatusPill;

  // SLA countdown chip
  function SLAChip({ finding, showDate }) {
    const { Icon } = window;
    if (finding.isClosed || finding.daysLeft == null) {
      return <span className="sla closed"><span className="sla-ico"><Icon.check size={13} /></span>{finding.isClosed ? "Met" : "—"}</span>;
    }
    const d = finding.daysLeft;
    let cls = "ok", text;
    if (d < 0) { cls = "danger"; text = `${Math.abs(d)}d overdue`; }
    else if (d <= 7) { cls = "warn"; text = `${d}d left`; }
    else { cls = "ok"; text = `${d}d left`; }
    return (
      <span className={`sla ${cls}`} title={finding.deadline ? "Due " + window.fmtDate(finding.deadline) : ""}>
        <span className="sla-ico">{d < 0 ? <Icon.alert size={13} /> : <Icon.clock size={13} />}</span>
        <span className="sla-num">{text}</span>
        {showDate && finding.deadline && <span className="faint" style={{ fontWeight: 400 }}>· {window.fmtDate(finding.deadline)}</span>}
      </span>
    );
  }
  window.SLAChip = SLAChip;

  function FrameworkChip({ finding }) {
    return (
      <span className="chip framework" title={finding.framework + " — " + finding.catName}>
        {finding.catCode}
      </span>
    );
  }
  window.FrameworkChip = FrameworkChip;

  function AssetCell({ finding }) {
    const { Icon } = window;
    const Ic = finding.assetType === "infra" ? Icon.server : Icon.globe;
    return (
      <div className="row gap2" style={{ minWidth: 0 }}>
        <span style={{ color: "var(--ink-3)", flexShrink: 0 }}><Ic size={15} /></span>
        <span style={{ minWidth: 0 }}>
          <div className="cell-strong nowrap" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{finding.asset}</div>
        </span>
      </div>
    );
  }
  window.AssetCell = AssetCell;

  function Checkbox({ checked, mixed, onChange }) {
    const { Icon } = window;
    return (
      <button type="button" className={`checkbox${checked ? " on" : ""}${mixed ? " mixed" : ""}`}
        onClick={(e) => { e.stopPropagation(); onChange && onChange(!checked); }}
        role="checkbox" aria-checked={mixed ? "mixed" : checked}>
        {checked && !mixed && <Icon.check size={12} strokeWidth={3} />}
        {mixed && <Icon.minus size={12} strokeWidth={3} />}
      </button>
    );
  }
  window.Checkbox = Checkbox;

  // Escalation stepper (vertical-day staircase shown horizontally)
  function EscalationStepper({ stage, compact }) {
    const ESC = window.ESCALATION;
    return (
      <div className="stepper">
        {ESC.map((s, i) => {
          let cls = "";
          if (i < stage) cls = "done";
          else if (i === stage) cls = "current";
          const node = i < stage ? <window.Icon.check size={14} strokeWidth={3} /> : (i + 1);
          return (
            <div key={i} className={`step ${cls}`}>
              <div className="bar" />
              <div className="node">{node}</div>
              {!compact && <>
                <div className="step-label">{s.label}</div>
                <div className="step-day">Day {s.day}</div>
              </>}
            </div>
          );
        })}
      </div>
    );
  }
  window.EscalationStepper = EscalationStepper;

  function MiniStair({ stage, overdue }) {
    const ESC = window.ESCALATION;
    return (
      <div className="stair" title={`Stage ${stage + 1} of ${ESC.length}: ${ESC[stage] ? ESC[stage].label : ""}`}>
        {ESC.map((s, i) => {
          let cls = "";
          if (i < stage) cls = "done";
          else if (i === stage) cls = overdue ? "overdue" : "current";
          return <span key={i} className={`rung ${cls}`} />;
        })}
      </div>
    );
  }
  window.MiniStair = MiniStair;

  // Stacked severity bar
  function SevBar({ counts }) {
    const order = window.SEVERITY_ORDER;
    const total = order.reduce((s, k) => s + (counts[k] || 0), 0) || 1;
    return (
      <div className="sevbar">
        {order.map(k => counts[k] ? <span key={k} className={`b-${k}`} style={{ width: (counts[k] / total * 100) + "%" }} /> : null)}
      </div>
    );
  }
  window.SevBar = SevBar;

  // Trend area/line chart (simple SVG, multi-series)
  function TrendChart({ data, height = 180, series }) {
    const W = 640, H = height, padL = 32, padB = 24, padT = 12, padR = 8;
    const keys = series || [
      { k: "critical", color: "var(--sev-critical)" },
      { k: "high", color: "var(--sev-high)" },
      { k: "medium", color: "var(--sev-medium)" },
      { k: "low", color: "var(--sev-low)" },
    ];
    const max = Math.max(...data.flatMap(d => keys.map(s => d[s.k]))) * 1.15 || 1;
    const x = (i) => padL + (i / (data.length - 1)) * (W - padL - padR);
    const y = (v) => padT + (1 - v / max) * (H - padT - padB);
    return (
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="xMidYMid meet" style={{ display: "block" }}>
        {[0, 0.25, 0.5, 0.75, 1].map((t, i) => {
          const yy = padT + t * (H - padT - padB);
          return <g key={i}>
            <line x1={padL} y1={yy} x2={W - padR} y2={yy} stroke="var(--border)" strokeWidth="1" />
            <text x={padL - 6} y={yy + 3} textAnchor="end" fontSize="9" fill="var(--ink-3)">{Math.round(max * (1 - t))}</text>
          </g>;
        })}
        {data.map((d, i) => <text key={i} x={x(i)} y={H - 6} textAnchor="middle" fontSize="9" fill="var(--ink-3)">{d.wk}</text>)}
        {keys.map(s => {
          const pts = data.map((d, i) => `${x(i)},${y(d[s.k])}`).join(" ");
          return <polyline key={s.k} points={pts} fill="none" stroke={s.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />;
        })}
        {keys.map(s => data.map((d, i) => <circle key={s.k + i} cx={x(i)} cy={y(d[s.k])} r="2.5" fill={s.color} />))}
      </svg>
    );
  }
  window.TrendChart = TrendChart;

  // Donut for severity distribution
  function Donut({ counts, size = 132 }) {
    const order = window.SEVERITY_ORDER;
    const colors = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)" };
    const total = order.reduce((s, k) => s + (counts[k] || 0), 0);
    const r = size / 2 - 12, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
    let off = 0;
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--surface-3)" strokeWidth="14" />
        {order.map(k => {
          const v = counts[k] || 0; if (!v) return null;
          const frac = v / (total || 1);
          const dash = `${frac * C} ${C}`;
          const el = <circle key={k} cx={cx} cy={cy} r={r} fill="none" stroke={colors[k]} strokeWidth="14"
            strokeDasharray={dash} strokeDashoffset={-off * C} transform={`rotate(-90 ${cx} ${cy})`} strokeLinecap="butt" />;
          off += frac; return el;
        })}
        <text x={cx} y={cy - 2} textAnchor="middle" fontSize="26" fontWeight="600" fill="var(--ink)">{total}</text>
        <text x={cx} y={cy + 15} textAnchor="middle" fontSize="10" fill="var(--ink-3)" style={{ letterSpacing: "0.05em" }}>OPEN</text>
      </svg>
    );
  }
  window.Donut = Donut;

  function Empty({ icon, title, children, action }) {
    const I = icon || window.Icon.inbox;
    return (
      <div className="empty">
        <div className="empty-ico"><I size={22} /></div>
        <h3 className="t-h3">{title}</h3>
        {children && <p className="t-sm">{children}</p>}
        {action}
      </div>
    );
  }
  window.Empty = Empty;

  // counts helper
  window.countBy = function (arr, key) {
    return arr.reduce((m, x) => { m[x[key]] = (m[x[key]] || 0) + 1; return m; }, {});
  };
})();
