// Accessibility pass shared by the browser smoke tests: runs axe-core (the checker Google, Microsoft and GitHub use)
// on the page as it stands and walks it with the keyboard. Every serious or critical axe violation, and a keyboard
// walk that gets stuck, is pushed into `errs` so the smoke test fails.
// axe-core is loaded from the npm package next to Playwright (CI: `npm i --no-save playwright axe-core`); when it is
// not installed the pass says so once and does nothing, so the smoke tests still run on a machine without it.
const path = require('path');
let AXE = null;
try { AXE = require('fs').readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8'); } catch (e) { AXE = null; }
let warned = false;

// Which checks: WCAG 2.1 A and AA plus axe's best practices for names and roles. Colour contrast is included.
// preload: false keeps axe from fetching cross-origin stylesheets (the fonts), which the content policy rightly refuses
const RUN = { iframes: false, preload: false, runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] },
  rules: { 'region': { enabled: false }, 'landmark-one-main': { enabled: false }, 'page-has-heading-one': { enabled: false } } };

async function axe(p, tag, errs, opts = {}) {
  if (!AXE) { if (!warned) { console.log('a11y: axe-core not installed (npm i axe-core); skipping the accessibility scan'); warned = true; } return []; }
  // the report's content policy allows no injected script, so axe is handed to the page through evaluate (Playwright's
  // channel, outside the policy); a frame (the Atlas inside the app) is scanned the same way
  const targets = [p, ...(opts.frames ? p.frames().filter(f => f !== p.mainFrame()) : [])];
  const all = [];
  for (const t of targets) {
    const where = t === p ? '' : ` (frame ${path.basename((t.url && t.url()) || '')})`;
    try {
      await t.evaluate(AXE);   // a string: Playwright runs it in the page itself, as a function would be
      // inside a frame the report is transparent and the host page's backdrop shows through, which axe cannot see
      // (it would measure every colour against white); contrast is measured on the report opened by itself instead
      const run = t === p ? RUN : { ...RUN, rules: { ...RUN.rules, 'color-contrast': { enabled: false } } };
      const r = await t.evaluate(async run => await window.axe.run(document, run), run);
      for (const v of r.violations) {
        if (!['serious', 'critical'].includes(v.impact)) continue;
        const sample = v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(', ');
        const line = `${tag}${where}: a11y ${v.impact} ${v.id}: ${v.help} (${v.nodes.length}: ${sample})`;
        errs.push(line); all.push(line);
      }
    } catch (e) { errs.push(`${tag}${where}: the accessibility scan could not run: ${e.message.split('\n')[0]}`); }
  }
  return all;
}

// Keyboard walk: Tab moves focus through visible controls (never stuck on <body>, never on something hidden), Escape
// closes whatever opened. `steps` Tabs are pressed; the sequence of focused elements is returned for the log.
async function keyboard(p, tag, errs, steps = 12) {
  const seen = [];
  await p.keyboard.press('Tab');
  for (let i = 0; i < steps; i++) {
    const f = await p.evaluate(() => {
      const a = document.activeElement; if (!a || a === document.body) return null;
      const r = a.getBoundingClientRect(); const cs = getComputedStyle(a);
      const visible = r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
      const name = a.getAttribute('aria-label') || a.getAttribute('title') || (a.labels && a.labels[0] && a.labels[0].innerText) || a.innerText || a.getAttribute('placeholder') || '';
      return { tag: a.tagName.toLowerCase(), id: a.id, visible, name: name.trim().slice(0, 30), focusRing: cs.outlineStyle !== 'none' || cs.boxShadow !== 'none' };
    });
    if (!f) { errs.push(`${tag}: keyboard: Tab ${i + 1} left focus on the page body (nothing focusable, or a focus trap)`); break; }
    if (!f.visible) errs.push(`${tag}: keyboard: Tab ${i + 1} focused a hidden ${f.tag}#${f.id}`);
    if (!f.name && !['input', 'textarea'].includes(f.tag)) errs.push(`${tag}: keyboard: Tab ${i + 1} focused a ${f.tag}#${f.id} with no name a screen reader could say`);
    seen.push(`${f.tag}${f.id ? '#' + f.id : ''}${f.name ? '(' + f.name + ')' : ''}`);
    await p.keyboard.press('Tab');
  }
  return seen;
}

module.exports = { axe, keyboard, installed: !!AXE };
