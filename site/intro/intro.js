// Lantern landing intro — one continuous 20 s composition (from the Claude Design handoff, lantern-intro.jsx; runs on runtime.js).
const {
  CompositionStage,
  useComposition,
  Captions,
  Easing,
  clamp,
  useTweaks,
  TweaksPanel,
  TweakSection,
  TweakToggle
} = window;
const FONT = "'DM Sans', system-ui, sans-serif";
const MONO = "'JetBrains Mono', ui-monospace, Menlo, monospace";
const INK = '#F3F3F1',
  MUTED = '#8C8C92',
  TEAL = '#4FC3BA',
  FLAME = '#FFB547',
  RED = '#FF8A8A',
  REDBG = 'rgba(208,59,59,.26)',
  GOOD = '#5BD15B',
  GOODBG = 'rgba(12,163,12,.22)',
  SURF = '#161618',
  LINE = 'rgba(255,255,255,.1)';
const MOTION = {
  enter: (T, start, dur = 0.7) => {
    const e = Easing.easeOutCubic(clamp((T - start) / dur, 0, 1));
    return {
      opacity: e,
      transform: `translateY(${(1 - e) * 26}px)`
    };
  },
  draw: (T, start, dur = 1) => Easing.easeInOutCubic(clamp((T - start) / dur, 0, 1)),
  pop: (T, start, dur = 0.6) => {
    const p = clamp((T - start) / dur, 0, 1);
    return {
      opacity: Math.min(1, p * 3),
      transform: `scale(${0.55 + 0.45 * Easing.easeOutBack(p)})`
    };
  }
};
const hex = c => [1, 3, 5].map(i => parseInt(c.slice(i, i + 2), 16));
const mix = (a, b, t) => {
  const A = hex(a),
    B = hex(b);
  return `rgb(${A.map((v, i) => Math.round(v + (B[i] - v) * t)).join(',')})`;
};

// ── Lantern mark with a deterministic flicker (pure function of T) ──
function Lantern({
  T,
  CUES,
  x,
  y,
  size
}) {
  const pop = MOTION.pop(T, CUES.Dark + 0.4, 0.9);
  const lit = MOTION.draw(T, CUES.Dark + 1.0, 1.4);
  const fs = 1 + 0.08 * Math.sin(T * 17.3) + 0.05 * Math.sin(T * 29.1);
  const fx = 1 + 0.06 * Math.sin(T * 23.7 + 1);
  const glow = lit * (0.55 + 0.1 * Math.sin(T * 9.1));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: x - size / 2,
      top: y - size / 2,
      width: size,
      height: size,
      ...pop,
      transformOrigin: 'center'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: '50%',
      top: '50%',
      width: size * 9,
      height: size * 9,
      transform: 'translate(-50%,-50%)',
      borderRadius: '50%',
      background: `radial-gradient(closest-side, rgba(255,181,71,${0.22 * glow}), rgba(255,181,71,0))`,
      pointerEvents: 'none'
    }
  }), /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 64 64",
    style: {
      position: 'absolute',
      inset: 0,
      width: '100%',
      height: '100%'
    }
  }, /*#__PURE__*/React.createElement("rect", {
    width: "64",
    height: "64",
    rx: "15",
    fill: "#141416",
    stroke: LINE
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "32",
    cy: "35",
    r: "21",
    fill: `rgba(255,196,92,${0.5 * glow})`,
    style: {
      filter: 'blur(6px)'
    }
  }), /*#__PURE__*/React.createElement("path", {
    d: "M26 13h12M25 51h14",
    stroke: INK,
    strokeWidth: "3",
    strokeLinecap: "round"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M22 19h20l-2.5 27h-15z",
    fill: "none",
    stroke: INK,
    strokeWidth: "3",
    strokeLinejoin: "round"
  }), /*#__PURE__*/React.createElement("g", {
    transform: `translate(32 39.1) scale(${fx * (0.15 + 0.85 * lit)} ${fs * (0.15 + 0.85 * lit)}) translate(-32 -39.1)`
  }, /*#__PURE__*/React.createElement("path", {
    d: "M32 25.5c3.2 3.6 4.8 6.3 4.8 8.8a4.8 4.8 0 0 1-9.6 0c0-2.5 1.6-5.2 4.8-8.8z",
    fill: FLAME
  }), /*#__PURE__*/React.createElement("path", {
    d: "M32 30.5c1.6 1.9 2.4 3.3 2.4 4.6a2.4 2.4 0 0 1-4.8 0c0-1.3.8-2.7 2.4-4.6z",
    fill: "#FFE3A6"
  }))));
}

// ── crumb's real bug: api/export.py 36–41 ──
const LINES = [['36', '@router.post("/orders/export")'], ['37', 'def export_orders(range, db):'], ['38', '    rows = db.orders_between(range)'], ['39', '    path = f"/tmp/o-{range}.csv"'], ['40', '    return run_export(rows, path)'], ['41', '    subprocess.run(f"zip {path}", shell=True)']];
const CODE = {
  x: 120,
  y: 300,
  step: 58,
  size: 27
};
function Code({
  T,
  CUES
}) {
  const intro = MOTION.enter(T, CUES.Dark + 0.2, 1.2);
  const lightY = CODE.y + 20 + MOTION.draw(T, CUES.Lit + 0.15, 2.0) * CODE.step * 5.3;
  const lit0 = MOTION.draw(T, CUES.Lit, 0.4);
  const redIn = MOTION.draw(T, CUES.Lit + 2.2, 0.5);
  const fixIn = MOTION.draw(T, CUES.Ready + 0.5, 0.7);
  const badge = MOTION.pop(T, CUES.Lit + 2.6, 0.5);
  const card = MOTION.enter(T, CUES.Lit + 3.0, 0.7);
  const cardOut = 1 - MOTION.draw(T, CUES.Ready - 0.6, 0.5);
  const fixedBadge = MOTION.pop(T, CUES.Ready + 1.1, 0.5);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: CODE.x,
      top: CODE.y - 56,
      width: 980,
      ...intro
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: -200,
      top: lightY - CODE.y + 56 - 200,
      width: 1300,
      height: 400,
      borderRadius: '50%',
      background: 'radial-gradient(closest-side, rgba(255,181,71,.16), rgba(255,181,71,0))',
      opacity: lit0 * (1 - 0.6 * redIn),
      pointerEvents: 'none'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      font: `500 18px ${MONO}`,
      color: MUTED,
      marginBottom: 14
    }
  }, "api/export.py", /*#__PURE__*/React.createElement("span", {
    style: {
      font: `600 13px ${MONO}`,
      padding: '2px 7px',
      borderRadius: 5,
      background: 'rgba(255,255,255,.08)',
      color: MUTED,
      letterSpacing: '.04em'
    }
  }, "py"), /*#__PURE__*/React.createElement("span", {
    style: {
      font: `400 16px ${FONT}`,
      whiteSpace: 'nowrap'
    }
  }, "· the server side of crumb")), LINES.map(([n, txt], i) => {
    const y = CODE.y + 20 + i * CODE.step;
    const last = i === 5;
    const passed = clamp(1 - (y - lightY) / 110, 0, 1) * lit0;
    const base = 0.2 + 0.8 * passed;
    const color = last ? mix('#F3F3F1', '#FF8A8A', redIn) : INK;
    const bg = last ? fixIn > 0 ? `rgba(208,59,59,${0.26 * (1 - fixIn)})` : `rgba(208,59,59,${0.26 * redIn})` : 'transparent';
    return /*#__PURE__*/React.createElement("div", {
      key: n,
      style: {
        position: 'relative',
        display: 'flex',
        gap: 22,
        height: CODE.step,
        alignItems: 'center',
        padding: '0 18px',
        margin: '0 -18px',
        borderRadius: 10,
        background: bg,
        opacity: base,
        font: `500 ${CODE.size}px/1 ${MONO}`,
        color,
        textDecoration: last && fixIn > 0.4 ? 'line-through' : 'none'
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: MUTED,
        width: 44,
        textAlign: 'right',
        fontWeight: 400
      }
    }, n), /*#__PURE__*/React.createElement("span", {
      style: {
        whiteSpace: 'pre'
      }
    }, txt), last && /*#__PURE__*/React.createElement("div", {
      style: {
        position: 'absolute',
        left: 860,
        top: '50%',
        marginTop: -16,
        ...badge,
        transformOrigin: 'left center',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        font: `700 15px ${FONT}`,
        letterSpacing: '.06em',
        color: '#fff',
        background: '#D03B3B',
        padding: '6px 12px',
        borderRadius: 8,
        whiteSpace: 'nowrap',
        opacity: badge.opacity * (1 - fixIn)
      }
    }, "CRITICAL · reachable · uses visitor input"));
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'relative',
      display: 'flex',
      gap: 22,
      height: CODE.step,
      alignItems: 'center',
      padding: '0 18px',
      margin: '0 -18px',
      borderRadius: 10,
      background: `rgba(12,163,12,${0.22 * fixIn})`,
      opacity: fixIn,
      font: `500 ${CODE.size}px/1 ${MONO}`,
      color: GOOD
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: MUTED,
      width: 44,
      textAlign: 'right',
      fontWeight: 400
    }
  }, "41"), /*#__PURE__*/React.createElement("span", {
    style: {
      whiteSpace: 'pre'
    }
  }, '    subprocess.run(["zip", path], check=True)'), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 860,
      top: '50%',
      marginTop: -16,
      ...fixedBadge,
      transformOrigin: 'left center',
      font: `700 15px ${FONT}`,
      letterSpacing: '.06em',
      color: '#0E0E10',
      background: GOOD,
      padding: '6px 12px',
      borderRadius: 8,
      whiteSpace: 'nowrap'
    }
  }, "FIXED · no finding")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 1040,
      top: 40,
      width: 640,
      boxSizing: 'border-box',
      ...card,
      opacity: card.opacity * cardOut,
      padding: '20px 24px',
      borderRadius: 16,
      background: SURF,
      border: `1px solid ${LINE}`,
      font: `400 25px/1.45 ${FONT}`,
      color: '#BEBEC3'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      font: `600 13px ${FONT}`,
      letterSpacing: '.08em',
      textTransform: 'uppercase',
      color: TEAL,
      marginBottom: 6
    }
  }, "In plain words · written in Python, runs on your server"), "The date range a visitor typed goes straight into a shell command. A crafted value could run anything on your server."));
}

// ── the browser window where the click happens ──
const BR = {
  x: 1160,
  y: 250,
  w: 640,
  h: 390
};
const BTN = {
  x: BR.x + 400,
  y: BR.y + 252,
  w: 200,
  h: 54
};
function Browser({
  T,
  CUES
}) {
  const inn = MOTION.enter(T, CUES.Click + 0.1, 0.8);
  const out = 1 - MOTION.draw(T, CUES.Lit, 0.5);
  const cursorP = Easing.easeInOutCubic(clamp((T - (CUES.Click + 0.4)) / 1.0, 0, 1));
  const cx = 1780 + (BTN.x + BTN.w * 0.55 - 1780) * cursorP,
    cy = 700 + (BTN.y + BTN.h * 0.6 - 700) * cursorP;
  const click = clamp((T - (CUES.Click + 1.5)) / 0.25, 0, 1);
  const press = click > 0 && click < 1 ? 0.95 : 1;
  const ripple = clamp((T - (CUES.Click + 1.5)) / 0.7, 0, 1);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: BR.x,
      top: BR.y,
      width: BR.w,
      height: BR.h,
      ...inn,
      opacity: inn.opacity * out
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      borderRadius: 16,
      background: '#FFFFFF',
      border: '1px solid rgba(0,0,0,.08)',
      boxShadow: '0 30px 80px -30px rgba(0,0,0,.8)',
      overflow: 'hidden',
      color: '#161618',
      fontFamily: FONT
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: 44,
      background: '#F5F5F2',
      borderBottom: '1px solid rgba(0,0,0,.08)',
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      padding: '0 16px'
    }
  }, ['#E5655D', '#E9B64A', '#5FC96B'].map(c => /*#__PURE__*/React.createElement("i", {
    key: c,
    style: {
      width: 11,
      height: 11,
      borderRadius: 99,
      background: c
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 14,
      font: `500 14px ${MONO}`,
      color: '#6E6E74',
      background: '#fff',
      border: '1px solid rgba(0,0,0,.08)',
      borderRadius: 7,
      padding: '4px 12px'
    }
  }, "crumb.app/admin")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '26px 30px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      font: `600 24px ${FONT}`,
      letterSpacing: '-.01em'
    }
  }, "Admin ", /*#__PURE__*/React.createElement("span", {
    style: {
      font: `500 13px ${FONT}`,
      color: '#6E6E74',
      background: '#EEEEEA',
      padding: '3px 9px',
      borderRadius: 99
    }
  }, "any logged-in user")), [0, 1, 2, 3].map(i => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      height: 14,
      borderRadius: 7,
      background: i % 2 ? '#F0F0EC' : '#E6E6E1',
      width: ['78%', '62%', '70%', '48%'][i],
      marginTop: i ? 16 : 26
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 30,
      top: BTN.y - BR.y - 8,
      font: `500 14px ${FONT}`,
      color: '#6E6E74'
    }
  }, "Date range", /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 6,
      width: 300,
      height: 46,
      borderRadius: 10,
      border: '1px solid rgba(0,0,0,.14)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 14px',
      font: `500 17px ${MONO}`,
      color: '#161618'
    }
  }, "2026-10-01..2026-10-31")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: BTN.x - BR.x,
      top: BTN.y - BR.y + 14,
      width: BTN.w,
      height: BTN.h,
      borderRadius: 12,
      background: '#161618',
      color: '#fff',
      display: 'grid',
      placeItems: 'center',
      font: `600 18px ${FONT}`,
      transform: `scale(${press})`
    }
  }, "Export orders"))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: BTN.x - BR.x + BTN.w * 0.55,
      top: BTN.y - BR.y + 14 + BTN.h * 0.6,
      width: 160 * ripple,
      height: 160 * ripple,
      borderRadius: '50%',
      border: `3px solid ${TEAL}`,
      transform: 'translate(-50%,-50%)',
      opacity: ripple > 0 ? 1 - ripple : 0,
      pointerEvents: 'none'
    }
  }), /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 24 24",
    style: {
      position: 'absolute',
      left: cx - BR.x,
      top: cy - BR.y,
      width: 34,
      height: 34,
      opacity: inn.opacity,
      filter: 'drop-shadow(0 2px 4px rgba(0,0,0,.4))'
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M5 3l14 8-6 1.5L10 20z",
    fill: "#fff",
    stroke: "#161618",
    strokeWidth: "1.6",
    strokeLinejoin: "round"
  })));
}

// ── the seven hops ──
const NODES = [{
  x: 80,
  w: 170,
  k: 'page',
  l: 'Admin',
  side: 'b'
}, {
  x: 283,
  w: 230,
  k: 'component',
  l: 'ExportButton',
  side: 'b'
}, {
  x: 546,
  w: 200,
  k: 'function',
  l: 'exportCsv',
  side: 'b'
}, {
  x: 779,
  w: 290,
  k: 'http',
  l: 'POST /orders/export',
  side: 'h'
}, {
  x: 1102,
  w: 230,
  k: 'route',
  l: 'export_orders',
  side: 's'
}, {
  x: 1365,
  w: 200,
  k: 'function',
  l: 'run_export',
  side: 's'
}, {
  x: 1598,
  w: 240,
  k: 'call',
  l: 'subprocess.run',
  side: 's'
}];
const PY = 840,
  NH = 76;
function Path({
  T,
  CUES
}) {
  const base = MOTION.enter(T, CUES.Click + 0.2, 0.8);
  const out = 1 - MOTION.draw(T, CUES.Ready, 0.6);
  const p = MOTION.draw(T, CUES.Click + 1.6, 3.0) * 6;
  const redIn = MOTION.draw(T, CUES.Lit + 2.2, 0.5);
  const dotI = Math.floor(p),
    dotF = p - dotI;
  const a = NODES[Math.min(dotI, 6)],
    b = NODES[Math.min(dotI + 1, 6)];
  const dotX = dotI >= 6 ? a.x + a.w / 2 : a.x + a.w + (b.x - a.x - a.w) * dotF;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 0,
      top: PY,
      width: 1920,
      height: NH,
      ...base,
      opacity: base.opacity * out
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 80,
      top: -54,
      display: 'flex',
      gap: 28,
      font: `500 16px ${FONT}`,
      color: MUTED
    }
  }, /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      display: 'inline-block',
      width: 9,
      height: 9,
      borderRadius: 99,
      background: TEAL,
      marginRight: 8
    }
  }), "in the browser"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      display: 'inline-block',
      width: 9,
      height: 9,
      borderRadius: 99,
      background: INK,
      marginRight: 8
    }
  }), "on your server")), NODES.map((n, i) => {
    const lit = clamp(p - i + 1, 0, 1);
    const isLast = i === 6;
    const col = n.side === 'b' ? TEAL : INK;
    const border = isLast ? mix('#F3F3F1', '#D03B3B', redIn) : n.side === 'h' ? 'rgba(255,255,255,.25)' : col;
    const bg = isLast ? `rgba(208,59,59,${0.26 * redIn})` : n.side === 'h' ? 'rgba(255,255,255,.06)' : SURF;
    const seg = i < 6 ? clamp(p - i, 0, 1) : 0;
    const nx = NODES[i + 1];
    return /*#__PURE__*/React.createElement(React.Fragment, {
      key: n.l
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: 'absolute',
        left: n.x,
        top: 0,
        width: n.w,
        height: NH,
        boxSizing: 'border-box',
        borderRadius: n.side === 'h' ? 99 : 12,
        background: bg,
        border: `${isLast ? 2 : 1.5}px solid ${border}`,
        opacity: 0.3 + 0.7 * lit,
        transform: `scale(${0.96 + 0.04 * lit})`,
        boxShadow: isLast ? `0 0 0 ${10 * redIn}px rgba(208,59,59,.2)` : lit > 0 && lit < 1 ? `0 0 0 4px rgba(79,195,186,.25)` : 'none',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        padding: '0 16px',
        color: INK,
        fontFamily: MONO
      }
    }, n.side !== 'h' && /*#__PURE__*/React.createElement("div", {
      style: {
        font: `700 11px ${FONT}`,
        letterSpacing: '.08em',
        textTransform: 'uppercase',
        color: isLast ? mix('#8C8C92', '#FF8A8A', redIn) : col,
        marginBottom: 4
      }
    }, isLast && redIn > 0.5 ? 'critical' : n.k), /*#__PURE__*/React.createElement("div", {
      style: {
        font: `600 ${n.side === 'h' ? 19 : 21}px ${MONO}`,
        whiteSpace: 'nowrap',
        textAlign: n.side === 'h' ? 'center' : 'left'
      }
    }, n.l)), i < 6 && /*#__PURE__*/React.createElement("div", {
      style: {
        position: 'absolute',
        left: n.x + n.w,
        top: NH / 2 - 1,
        width: nx.x - n.x - n.w,
        height: 2,
        background: 'rgba(255,255,255,.14)'
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        width: `${seg * 100}%`,
        height: '100%',
        background: n.side === 'b' && nx.side === 'b' ? TEAL : INK
      }
    })));
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: dotX - 9,
      top: NH / 2 - 9,
      width: 18,
      height: 18,
      borderRadius: 99,
      background: FLAME,
      boxShadow: `0 0 24px 6px rgba(255,181,71,.55)`,
      opacity: p > 0 && p < 6 ? 1 : 0
    }
  }));
}

// ── before/after: readiness and the evidence packet ──
function Readiness({
  T,
  CUES
}) {
  const inn = MOTION.enter(T, CUES.Ready + 0.2, 0.8);
  const k = MOTION.draw(T, CUES.Ready + 0.7, 2.2);
  const score = Math.round(24 + (78 - 24) * k);
  const grade = k < 0.3 ? 'F' : k < 0.55 ? 'D' : k < 0.8 ? 'C' : 'B';
  const col = mix('#D03B3B', '#0CA30C', k);
  const r = 150,
    C = 2 * Math.PI * r,
    cx = 1490,
    cy = 440;
  const stamp = MOTION.pop(T, CUES.Ready + 3.4, 0.5);
  const card = MOTION.enter(T, CUES.Ready + 2.8, 0.7);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 1160,
      top: 250,
      width: 660,
      height: 560,
      ...inn,
      fontFamily: FONT,
      color: INK
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      font: `600 13px ${FONT}`,
      letterSpacing: '.08em',
      textTransform: 'uppercase',
      color: MUTED
    }
  }, "Ready to ship?"), /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 660 400",
    style: {
      position: 'absolute',
      left: 0,
      top: 10,
      width: 660,
      height: 400
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: cx - 1160,
    cy: cy - 250,
    r: r,
    fill: "none",
    stroke: "rgba(255,255,255,.1)",
    strokeWidth: "18"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: cx - 1160,
    cy: cy - 250,
    r: r,
    fill: "none",
    stroke: col,
    strokeWidth: "18",
    strokeLinecap: "round",
    strokeDasharray: `${C * score / 100} ${C}`,
    transform: `rotate(-90 ${cx - 1160} ${cy - 250})`
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: cx - 1160 - 150,
      top: cy - 250 - 70,
      width: 300,
      textAlign: 'center'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      font: `700 96px/1 ${FONT}`,
      letterSpacing: '-.04em',
      fontVariantNumeric: 'tabular-nums'
    }
  }, score, /*#__PURE__*/React.createElement("span", {
    style: {
      font: `600 30px ${FONT}`,
      color: MUTED,
      letterSpacing: 0
    }
  }, " /100")), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      display: 'inline-block',
      font: `700 26px ${FONT}`,
      color: '#0E0E10',
      background: col,
      padding: '4px 16px',
      borderRadius: 10
    }
  }, grade)), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 0,
      top: 410,
      width: 660,
      boxSizing: 'border-box',
      padding: '20px 24px',
      borderRadius: 16,
      background: SURF,
      border: `1px solid ${LINE}`,
      ...card
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      font: `500 14px ${MONO}`,
      color: MUTED
    }
  }, /*#__PURE__*/React.createElement("span", null, "EVIDENCE REPORT · crumb"), /*#__PURE__*/React.createElement("span", null, "commit a3f9c1e")), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      font: `500 24px/1.3 ${FONT}`
    }
  }, "3 fixed · 0 critical open · readiness 24 → 78"), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 8,
      font: `500 15px ${MONO}`,
      color: MUTED
    }
  }, "sha256:7c1e…9a40 · lantern verify matches"), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      right: 22,
      top: -22,
      ...stamp,
      transform: `${stamp.transform} rotate(-8deg)`,
      font: `800 20px ${FONT}`,
      letterSpacing: '.1em',
      color: GOOD,
      border: `3px solid ${GOOD}`,
      padding: '6px 14px',
      borderRadius: 10,
      background: 'rgba(14,14,16,.85)'
    }
  }, "VERIFIED ✓")));
}
const TAGLINE = 'Ship your vibe-coded app like a senior engineer built it.',
  SUBLINE = 'Build with vibes. Ship with confidence.';
function useSound(T, CUES, enabled) {
  const ctxRef = React.useRef(null),
    lastRef = React.useRef(T);
  React.useEffect(() => {
    const prev = lastRef.current;
    lastRef.current = T;
    if (!enabled || T < prev || T - prev > 0.5) return;
    const marks = [[CUES.Dark + 1.0, 196, 1.2], [CUES.Click + 1.5, 587, 0.25], [CUES.Lit + 2.2, 175, 0.9], [CUES.Ready + 1.1, 523, 0.4], [CUES.Ready + 3.4, 784, 0.6], [CUES.Tagline + 0.3, 392, 1.4]];
    for (const [at, f, d] of marks) if (prev < at && T >= at) {
      try {
        const ctx = ctxRef.current || (ctxRef.current = new (window.AudioContext || window.webkitAudioContext)());
        const o = ctx.createOscillator(),
          g = ctx.createGain();
        o.type = 'sine';
        o.frequency.value = f;
        g.gain.setValueAtTime(0.0001, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.06, ctx.currentTime + 0.03);
        g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + d);
        o.connect(g);
        g.connect(ctx.destination);
        o.start();
        o.stop(ctx.currentTime + d + 0.05);
      } catch (e) {}
    }
  }, [T, enabled]);
}
function Piece({
  captions,
  sound,
  onDone
}) {
  const {
    T,
    CUES,
    time,
    duration,
    playing
  } = useComposition();
  useSound(T, CUES, sound);
  const doneRef = React.useRef(false);
  React.useEffect(() => {
    if (time < 1) doneRef.current = false;
    if (!doneRef.current && !playing && time >= duration - 0.03) {
      doneRef.current = true;
      onDone && onDone();
    }
  }, [time, playing, duration]);
  const sceneFade = 1 - MOTION.draw(T, CUES.Tagline - 0.4, 0.7);
  const tag = MOTION.enter(T, CUES.Tagline - 0.1, 0.9);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      background: '#0E0E10',
      fontFamily: FONT,
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      opacity: sceneFade
    }
  }, /*#__PURE__*/React.createElement(Code, {
    T: T,
    CUES: CUES
  }), /*#__PURE__*/React.createElement(Browser, {
    T: T,
    CUES: CUES
  }), /*#__PURE__*/React.createElement(Path, {
    T: T,
    CUES: CUES
  }), /*#__PURE__*/React.createElement(Readiness, {
    T: T,
    CUES: CUES
  })), /*#__PURE__*/React.createElement(Lantern, {
    T: T,
    CUES: CUES,
    x: 960,
    y: 130,
    size: 96
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 260,
      right: 260,
      top: 0,
      // centred at 38 % of the height, so the page's end card (bottom 30 %) never covers the tagline
      bottom: '24%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      textAlign: 'center',
      ...tag
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      font: `600 64px/1.15 ${FONT}`,
      letterSpacing: '-.03em',
      color: INK,
      textWrap: 'pretty'
    }
  }, TAGLINE), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 22,
      font: `500 30px/1.3 ${FONT}`,
      color: MUTED
    }
  }, SUBLINE))), captions && /*#__PURE__*/React.createElement(Captions, {
    style: {
      font: `500 34px/1.3 ${FONT}`,
      color: INK,
      bottom: '8%',
      textShadow: 'none'
    },
    items: [{
      at: CUES.Dark + 0.9,
      text: 'Somewhere in your app, one line is waiting.'
    }, {
      at: CUES.Click + 0.3,
      text: 'A click in the browser travels seven hops into your server.'
    }, {
      at: CUES.Lit + 0.3,
      text: 'Lantern lights the hop that can hurt you, and says why in plain words.'
    }, {
      at: CUES.Ready + 0.3,
      until: CUES.Tagline - 0.4,
      text: 'Fix it. Prove it. An evidence packet pinned to your commit.'
    }]
  }));
}
function LanternIntro(props) {
  const [t, setTweak] = useTweaks(window.TWEAK_DEFAULTS);
  const sound = props.sound === true || props.sound === 'true';
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0
    }
  }, /*#__PURE__*/React.createElement(CompositionStage, {
    width: 1920,
    height: 1080,
    scenes: window.OM_SCENES,
    control: props.control,
    bg: "#0E0E10"
  }, /*#__PURE__*/React.createElement(Piece, {
    captions: t.captions !== false,
    sound: sound,
    onDone: props.onDone
  })), /*#__PURE__*/React.createElement(TweaksPanel, null, /*#__PURE__*/React.createElement(TweakSection, {
    label: "Intro"
  }), /*#__PURE__*/React.createElement(TweakToggle, {
    label: "Motion editor",
    value: !!t.motionEditor,
    onChange: v => setTweak('motionEditor', v)
  }), /*#__PURE__*/React.createElement(TweakToggle, {
    label: "Captions",
    value: t.captions !== false,
    onChange: v => setTweak('captions', v)
  })));
}
window.LanternIntro = LanternIntro;
