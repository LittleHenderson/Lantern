// Viewer smoke test: drives the report at desktop and phone sizes, saves screenshots, and exits
// non-zero on any JavaScript error, on a dialog, if the map is empty, or if any of the report's data landed in
// the page as markup (an element with data-pwn, or a changed title: see tools/poison_report.py).
// Works on any report (it clicks whatever is on screen).
// Usage: node tools/viewer_smoke.js path/to/report.html /tmp/shot   (needs `npm i playwright`)
const { chromium } = require('playwright');

(async () => {
  const [file, out] = process.argv.slice(2);
  if (!file || !out) { console.error('usage: node tools/viewer_smoke.js REPORT.html OUT_PREFIX'); process.exit(2); }
  const b = await chromium.launch();
  const errs = [];
  for (const [name, vp] of [['desk', { width: 1440, height: 900 }], ['phone', { width: 390, height: 844 }]]) {
    const p = await b.newPage({ viewport: vp });
    try {
    p.on('pageerror', e => errs.push(`${name}: ${e.message}`));
    p.on('dialog', d => { errs.push(`${name}: a dialog opened (script from the data ran): ${d.message()}`); d.dismiss(); });
    p.on('console', m => { if (m.type() === 'error') errs.push(`${name} console: ${m.text()}`); });
    const pwned = async where => {
      const n = await p.$$eval('[data-pwn]', els => els.length);
      if (n) errs.push(`${name} ${where}: ${n} element(s) from the data landed in the page as markup`);
      const t = await p.title();
      if (t !== 'Lantern report') errs.push(`${name} ${where}: the page title changed to "${t}" (script from the data ran)`);
    };
    await p.goto('file://' + require('path').resolve(file));
    await p.waitForSelector('#center');
    await pwned('load');
    if (await p.$('#expand')) { await p.click('#expand'); await p.waitForTimeout(150); }
    await p.screenshot({ path: `${out}-${name}-map.png` });
    const nodes = await p.$$('.node');
    if (!nodes.length) errs.push(`${name}: the map is empty (did the report's data load?)`);
    if (nodes.length) {
      // open a node (prefer one with an explanation, so all three lenses render), then every lens.
      // Clicking re-renders the tree, so the list is queried again each time.
      let picked = Math.min(nodes.length - 1, 2);
      for (let i = 0; i < Math.min(nodes.length, 12); i++) {
        const list = await p.$$('.node'); if (!list[i]) break;
        await list[i].click(); await p.waitForTimeout(60);
        const found = !!(await p.$('.lens'));
        const close = await p.$('#close');   // the detail sheet covers the map on phones
        if (close && await close.isVisible()) { await close.click(); await p.waitForTimeout(100); }
        if (found) { picked = i; break; }
      }
      const list = await p.$$('.node');
      await list[Math.min(picked, list.length - 1)].click();
      await p.waitForTimeout(150);
      for (const l of ['1', '2', '3']) {
        const btn = await p.$(`.lenses button[data-l="${l}"]`);
        if (btn) { await btn.click(); await p.waitForTimeout(60); }
        if (l === '3') { const pair = await p.$('.pair'); if (pair) { await pair.click(); await p.waitForTimeout(60); } }
      }
      await pwned('detail');
      await p.screenshot({ path: `${out}-${name}-detail.png` });
      if (name === 'phone' && await p.$('#close')) { await p.click('#close'); await p.waitForTimeout(250); }
    }
    if (name === 'desk' && await p.$('.seg button[data-v="chart"]')) {
      await p.click('.seg button[data-v="chart"]'); await p.waitForTimeout(150);
      await p.screenshot({ path: `${out}-${name}-chart.png` });
    }
    await p.click('#tabs button[data-t="findings"]'); await p.waitForTimeout(150);
    await pwned('findings');
    await p.screenshot({ path: `${out}-${name}-findings.png` });
    if (await p.$('#tabs button[data-t="ready"]')) {
      await p.click('#tabs button[data-t="ready"]'); await p.waitForTimeout(150);
      await pwned('readiness');
      await p.screenshot({ path: `${out}-${name}-ready.png`, fullPage: true });
    }
    await p.click('#tabs button[data-t="about"]'); await p.waitForTimeout(150);
    await pwned('about');
    if (name === 'desk') {
      // the search box renders arbitrary function names
      await p.click('#tabs button[data-t="map"]'); await p.waitForTimeout(100);
      await p.fill('#q', 'a'); await p.waitForTimeout(150);
      await pwned('search');
    }
    } catch (e) { errs.push(`${name}: the smoke test could not drive the page: ${e.message.split('\n')[0]}`); }
    await p.close();
  }
  console.log(errs.length ? errs.join('\n') : 'no JS errors');
  if (errs.length) process.exitCode = 1;
  await b.close();
})();
