/* Icons — minimal 1.6px line set, 18px default. Kept geometric/simple. */
(function () {
  const S = ({ d, size = 18, fill, vb = 24, sw = 1.7, children, ...p }) => (
    <svg width={size} height={size} viewBox={`0 0 ${vb} ${vb}`} fill={fill || "none"}
      stroke="currentColor" strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" {...p}>
      {d ? <path d={d} /> : children}
    </svg>
  );

  const Icon = {
    dashboard: (p) => <S {...p}><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></S>,
    scan: (p) => <S {...p}><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M3 12h18"/></S>,
    findings: (p) => <S {...p}><path d="M4 5h16M4 12h16M4 19h10"/></S>,
    detail: (p) => <S {...p}><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></S>,
    reports: (p) => <S {...p}><path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M5 3h9l5 5v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 1-2z"/><path d="M9 13h6M9 17h4"/></S>,
    sla: (p) => <S {...p}><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2.5M9 2h6"/></S>,
    exception: (p) => <S {...p}><path d="M10.3 3.3 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.3a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></S>,
    system: (p) => <S {...p}><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M5 5l2 2M17 17l2 2M2 12h3M19 12h3M5 19l2-2M17 7l2-2"/></S>,
    search: (p) => <S {...p}><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></S>,
    filter: (p) => <S {...p}><path d="M3 5h18l-7 8v5l-4 2v-7L3 5z"/></S>,
    bell: (p) => <S {...p}><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0"/></S>,
    chevDown: (p) => <S {...p}><path d="m6 9 6 6 6-6"/></S>,
    chevRight: (p) => <S {...p}><path d="m9 6 6 6-6 6"/></S>,
    chevLeft: (p) => <S {...p}><path d="m15 6-6 6 6 6"/></S>,
    arrowUp: (p) => <S {...p}><path d="M12 19V5M5 12l7-7 7 7"/></S>,
    arrowDown: (p) => <S {...p}><path d="M12 5v14M5 12l7 7 7-7"/></S>,
    check: (p) => <S {...p}><path d="M20 6 9 17l-5-5"/></S>,
    x: (p) => <S {...p}><path d="M18 6 6 18M6 6l12 12"/></S>,
    plus: (p) => <S {...p}><path d="M12 5v14M5 12h14"/></S>,
    minus: (p) => <S {...p}><path d="M5 12h14"/></S>,
    clock: (p) => <S {...p}><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></S>,
    alert: (p) => <S {...p}><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></S>,
    flag: (p) => <S {...p}><path d="M4 21V4h13l-2 4 2 4H4"/></S>,
    escalate: (p) => <S {...p}><path d="M12 19V5M5 12l7-7 7 7"/><path d="M5 20h14" opacity="0.4"/></S>,
    user: (p) => <S {...p}><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></S>,
    users: (p) => <S {...p}><circle cx="9" cy="8" r="3.5"/><path d="M2 20c0-3.5 3-5 7-5s7 1.5 7 5"/><path d="M16 5a3.5 3.5 0 0 1 0 6.5M17 20c0-2-.6-3.4-1.6-4.4"/></S>,
    shield: (p) => <S {...p}><path d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6l-7-3z"/></S>,
    server: (p) => <S {...p}><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/></S>,
    globe: (p) => <S {...p}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18"/></S>,
    lock: (p) => <S {...p}><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></S>,
    download: (p) => <S {...p}><path d="M12 3v12M7 11l5 5 5-5M4 21h16"/></S>,
    file: (p) => <S {...p}><path d="M14 3v5h5"/><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-5z"/></S>,
    play: (p) => <S {...p}><path d="M6 4l14 8-14 8V4z"/></S>,
    pause: (p) => <S {...p}><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></S>,
    history: (p) => <S {...p}><path d="M3 12a9 9 0 1 0 3-6.7L3 8m0-5v5h5"/><path d="M12 8v4l3 2"/></S>,
    menu: (p) => <S {...p}><path d="M4 6h16M4 12h16M4 18h16"/></S>,
    settings: (p) => <S {...p}><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 7 19.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H3a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 4.7 7l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H10a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 2.7 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V10a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z"/></S>,
    external: (p) => <S {...p}><path d="M15 3h6v6M21 3l-9 9M19 14v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5"/></S>,
    copy: (p) => <S {...p}><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></S>,
    eye: (p) => <S {...p}><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></S>,
    target: (p) => <S {...p}><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5"/></S>,
    trend: (p) => <S {...p}><path d="M3 17l6-6 4 4 7-7M14 8h6v6"/></S>,
    grid: (p) => <S {...p}><rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/></S>,
    inbox: (p) => <S {...p}><path d="M3 12h5l2 3h4l2-3h5"/><path d="M5 5h14l2 7v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-6l2-7z"/></S>,
  };

  window.Icon = Icon;
})();
