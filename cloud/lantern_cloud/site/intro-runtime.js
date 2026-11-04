// Minimal composition runtime for the landing intro (replaces the design tool's animations-v3 stage).
// The intro itself (intro.js, compiled from the handoff's lantern-intro.jsx) is a pure function of T,
// so all this has to do is keep a clock, scale a 1920x1080 stage into the viewport, and provide
// useComposition / Captions / Easing / clamp with the same contract.
(function () {
  const Easing = {
    linear: t => t,
    easeOutCubic: t => (--t) * t * t + 1,
    easeInOutCubic: t => (t < 0.5 ? 4 * t * t * t : (t - 1) * (2 * t - 2) * (2 * t - 2) + 1),
    easeOutBack: t => { const c1 = 1.70158, c3 = c1 + 1; return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2); },
  };
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const Ctx = React.createContext(null);
  function useComposition() { return React.useContext(Ctx); }

  function Captions(props) {
    const c = useComposition(); const t = c.T;
    const items = (props.items || []).filter(it => it && isFinite(+it.at)).sort((a, b) => a.at - b.at);
    let active = null, end = Infinity;
    for (let i = 0; i < items.length; i++) {
      if (t < items[i].at) break;
      active = items[i];
      end = typeof active.until === 'number' && isFinite(active.until) ? active.until : (i + 1 < items.length ? items[i + 1].at : Infinity);
    }
    if (!active || t >= end) return null;
    let o = Math.min(1, (t - active.at) / 0.18);
    if (isFinite(end)) o = Math.min(o, (end - t) / 0.18);
    o = clamp(o, 0, 1);
    return React.createElement('div', { style: Object.assign({ position: 'absolute', left: '8%', right: '8%', bottom: '7%', textAlign: 'center', opacity: o, pointerEvents: 'none', font: '500 30px system-ui, sans-serif', color: '#f6f4ef' }, props.style) }, active.text);
  }

  // scenes: [{name, dur}] in order; CUES[name] = the second that scene starts.
  function CompositionStage(props) {
    const scenes = typeof props.scenes === 'string' ? JSON.parse(props.scenes) : props.scenes;
    const { CUES, duration } = React.useMemo(() => {
      const cues = {}; let t = 0;
      for (const s of scenes) { cues[s.name] = t; t += +s.dur; }
      return { CUES: cues, duration: t };
    }, [scenes]);
    const [time, setTime] = React.useState(0);
    const [playing, setPlaying] = React.useState(true);
    const startRef = React.useRef(null), rafRef = React.useRef(0), fromRef = React.useRef(0);   // fromRef: where the clock restarts
    const control = props.control;
    React.useEffect(() => {
      // seekToEnd: the clock jumps to the last 0.1 s, so the piece finishes (and calls its onDone) the normal way.
      if (control) control.current = {
        restart() { fromRef.current = 0; startRef.current = null; setTime(0); setPlaying(true); },
        seekToEnd() { fromRef.current = Math.max(0, duration - 0.1); startRef.current = null; setTime(fromRef.current); setPlaying(true); },
      };
    }, [control, duration]);
    React.useEffect(() => {
      if (!playing) return;
      const tick = now => {
        if (startRef.current == null) startRef.current = now - fromRef.current * 1000;
        const t = (now - startRef.current) / 1000;
        if (t >= duration) { setTime(duration); setPlaying(false); return; }
        setTime(t); rafRef.current = requestAnimationFrame(tick);
      };
      rafRef.current = requestAnimationFrame(tick);
      return () => cancelAnimationFrame(rafRef.current);
    }, [playing, duration]);
    const [scale, setScale] = React.useState(1);
    const hostRef = React.useRef(null);
    React.useEffect(() => {
      const fit = () => { const el = hostRef.current; if (!el) return; const r = el.getBoundingClientRect(); setScale(Math.min(r.width / props.width, r.height / props.height)); };
      fit(); window.addEventListener('resize', fit); return () => window.removeEventListener('resize', fit);
    }, [props.width, props.height]);
    const value = { T: time, time, CUES, duration, authoredTotal: duration, playing };
    return React.createElement('div', { ref: hostRef, style: { position: 'absolute', inset: 0, background: props.bg || '#0E0E10', overflow: 'hidden' } },
      React.createElement('div', { style: { position: 'absolute', left: '50%', top: '50%', width: props.width, height: props.height, transform: `translate(-50%,-50%) scale(${scale})`, transformOrigin: 'center' } },
        React.createElement(Ctx.Provider, { value }, props.children)));
  }
  // The handoff's tweak panel is a design-time tool; here it is inert.
  const useTweaks = d => [d || {}, () => {}];
  const Nothing = () => null;
  Object.assign(window, { CompositionStage, useComposition, Captions, Easing, clamp, useTweaks, TweaksPanel: Nothing, TweakSection: Nothing, TweakToggle: Nothing });
})();
