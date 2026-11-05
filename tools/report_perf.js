// Does a big report open and respond on a phone? (test checklist 4.3)
//   node tools/report_perf.js REPORT.html [--budget-ms 8000] [--phone]
// Opens the report in Chromium with a phone viewport (Pixel 5 size, CPU slowed 4x to stand in for a mid-range phone),
// measures the time until the map is drawn (#center has content), then clicks the Findings tab and the first finding and
// measures how long each takes to paint. Fails (exit 1) when the first paint takes longer than the budget, when a click
// takes longer than 2 s, or when the page throws. Prints one JSON line with the numbers for the step summary.
const { chromium, devices } = require('playwright');
const fs = require('fs');

const args = process.argv.slice(2);
const file = args.find(a => !a.startsWith('--'));
const budget = Number((args.find(a => a.startsWith('--budget-ms=')) || '--budget-ms=8000').split('=')[1]);
if (!file) { console.error('usage: node tools/report_perf.js REPORT.html [--budget-ms=8000]'); process.exit(2); }

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ...devices['Pixel 5'] });
  const p = await ctx.newPage();
  const errors = [];
  p.on('pageerror', e => errors.push(String(e)));
  const cdp = await ctx.newCDPSession(p);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
  const sizeMb = Math.round(fs.statSync(file).size / 1024 / 1024 * 10) / 10;
  const t0 = Date.now();
  await p.goto('file://' + require('path').resolve(file));
  await p.waitForFunction(() => { const c = document.querySelector('#center'); return c && c.children.length > 0; }, null, { timeout: budget * 3 }).catch(() => {});
  const firstPaintMs = Date.now() - t0;
  const timed = async (label, fn) => { const t = Date.now(); await fn(); await p.waitForTimeout(50); return Date.now() - t; };
  const findingsMs = await timed('findings', async () => { const tab = await p.$('#tabs button[data-t="findings"]'); if (tab) { await tab.click(); await p.waitForSelector('.finding, .fcard, [data-f], .empty', { timeout: 10000 }).catch(() => {}); } });
  const detailMs = await timed('detail', async () => { const f = await p.$('.finding, .fcard, [data-f]'); if (f) { await f.click(); await p.waitForTimeout(100); } });
  const mapMs = await timed('map', async () => { const tab = await p.$('#tabs button[data-t="map"]'); if (tab) { await tab.click(); await p.waitForTimeout(100); } });
  const jsHeapMb = await p.evaluate(() => performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1048576) : null);
  await b.close();
  const out = { file, sizeMb, firstPaintMs, findingsMs, detailMs, mapMs, jsHeapMb, errors: errors.length, budgetMs: budget };
  console.log(JSON.stringify(out));
  const slow = firstPaintMs > budget || findingsMs > 2000 || detailMs > 2000 || mapMs > 2000;
  if (errors.length) console.error('page errors:\n' + errors.join('\n'));
  if (slow) console.error(`TOO SLOW on a phone: first paint ${firstPaintMs} ms (budget ${budget}), findings ${findingsMs}, detail ${detailMs}, map ${mapMs}`);
  process.exit(slow || errors.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
