// Viewer smoke test: drives the report at desktop and phone sizes, saves screenshots, and exits
// non-zero on any JavaScript error. Works on any report (it clicks whatever is on screen).
// Usage: node tools/viewer_smoke.js path/to/report.html /tmp/shot   (needs `npm i playwright`)
const { chromium } = require('playwright');

(async () => {
  const [file, out] = process.argv.slice(2);
  if (!file || !out) { console.error('usage: node tools/viewer_smoke.js REPORT.html OUT_PREFIX'); process.exit(2); }
  const b = await chromium.launch();
  const errs = [];
  for (const [name, vp] of [['desk', { width: 1440, height: 900 }], ['phone', { width: 390, height: 844 }]]) {
    const p = await b.newPage({ viewport: vp });
    p.on('pageerror', e => errs.push(`${name}: ${e.message}`));
    p.on('dialog', d => { errs.push(`${name}: a dialog opened (script from the data ran): ${d.message()}`); d.dismiss(); });
    p.on('console', m => { if (m.type() === 'error') errs.push(`${name} console: ${m.text()}`); });
    await p.goto('file://' + require('path').resolve(file));
    await p.waitForSelector('#center');
    if (await p.$('#expand')) { await p.click('#expand'); await p.waitForTimeout(150); }
    await p.screenshot({ path: `${out}-${name}-map.png` });
    const nodes = await p.$$('.node');
    if (!nodes.length) errs.push(`${name}: the map is empty (did the report's data load?)`);
    if (nodes.length) {
      await nodes[Math.min(nodes.length - 1, 2)].click();
      await p.waitForTimeout(150);
      for (const l of ['1', '2', '3']) {
        const btn = await p.$(`.lenses button[data-l="${l}"]`);
        if (btn) { await btn.click(); await p.waitForTimeout(60); }
      }
      await p.screenshot({ path: `${out}-${name}-detail.png` });
      if (name === 'phone' && await p.$('#close')) { await p.click('#close'); await p.waitForTimeout(250); }
    }
    if (name === 'desk' && await p.$('.seg button[data-v="chart"]')) {
      await p.click('.seg button[data-v="chart"]'); await p.waitForTimeout(150);
      await p.screenshot({ path: `${out}-${name}-chart.png` });
    }
    await p.click('#tabs button[data-t="findings"]'); await p.waitForTimeout(150);
    await p.screenshot({ path: `${out}-${name}-findings.png` });
    if (await p.$('#tabs button[data-t="ready"]')) {
      await p.click('#tabs button[data-t="ready"]'); await p.waitForTimeout(150);
      await p.screenshot({ path: `${out}-${name}-ready.png`, fullPage: true });
    }
    await p.click('#tabs button[data-t="about"]'); await p.waitForTimeout(150);
    await p.close();
  }
  console.log(errs.length ? errs.join('\n') : 'no JS errors');
  if (errs.length) process.exitCode = 1;
  await b.close();
})();
