// Viewer smoke test: drives the report at desktop and phone sizes, saves screenshots, and exits
// non-zero on any JavaScript error, on a dialog, if the map is empty, or if any of the report's data landed in
// the page as markup (an element with data-pwn, or a changed title: see tools/poison_report.py).
// Works on any report (it clicks whatever is on screen).
// Usage: node tools/viewer_smoke.js path/to/report.html /tmp/shot   (needs `npm i playwright`)
// App mode: node tools/viewer_smoke.js --app 'http://127.0.0.1:8765/?token=…' OUT_PREFIX [--image shot.png --expect-text WORD]
//   drives a live `lantern serve` with one analyzed project: "Watch my tests run" (confirm and run in the sandbox,
//   wait for the result), the terminal drawer (a Lantern command runs; a shell command is refused), a screenshot
//   dropped into Ask Lantern (read on this computer), and Settings → Analysis packs (one pack off, then on again).
//   Fails on any JavaScript error or when one of those does not answer as it should. The phone pass loads the
//   same screens.
const { chromium } = require('playwright');

// page.waitForFunction polls through eval in older Playwright, which the app's script-src policy (rightly) refuses;
// poll with page.evaluate instead, which the policy allows.
async function until(p, fn, timeout) {
  const end = Date.now() + timeout;
  for (;;) {
    if (await p.evaluate(fn).catch(() => false)) return;
    if (Date.now() > end) throw new Error(`timed out after ${timeout} ms waiting for ${fn.toString().slice(0, 90)}`);
    await p.waitForTimeout(250);
  }
}

async function appSmoke(url, out, image, expectText) {
  const b = await chromium.launch();
  const errs = [];
  let allow400 = false;   // the terminal's refusal answers 400 on purpose; Chromium logs that as a console error
  const step = (name, what) => console.log(`${name}: ${what}`);
  for (const [name, vp] of [['desk', { width: 1440, height: 900 }], ['phone', { width: 390, height: 844 }]]) {
    const p = await b.newPage({ viewport: vp });
    p.on('pageerror', e => errs.push(`${name}: ${e.message}`));
    p.on('console', m => { if (m.type() === 'error' && !(allow400 && /status of 400/.test(m.text()))) errs.push(`${name} console: ${m.text()}`); });
    p.on('dialog', d => { errs.push(`${name}: a dialog opened: ${d.message()}`); d.dismiss(); });
    const api = (path, body) => p.evaluate(([path, body]) => fetch(path, body === undefined ? {} : {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Lantern-Token': TOKEN}, body: JSON.stringify(body)}).then(r => r.json()), [path, body]);
    try {
      await p.goto(url);
      await p.waitForSelector('[data-open]', { timeout: 180000 });
      if (name === 'desk') await api('/api/settings', { view_mode: 'advanced' });
      await p.reload(); await p.waitForSelector('[data-open]');
      await p.click('[data-open]'); await p.waitForTimeout(1500);
      await p.screenshot({ path: `${out}-${name}-project.png` });
      if (name === 'desk') {
        // 1. the sheet: confirm the test command, run it in the sandbox, wait for the toast
        await p.click('#watchtests'); await p.waitForSelector('#shrun');
        const sbx = await p.$eval('.sheet', el => el.innerText);
        if (!/sandbox|Docker|restricted/i.test(sbx)) errs.push('desk: the sheet does not say which sandbox runs the tests');
        await p.screenshot({ path: `${out}-${name}-sheet.png` });
        await p.click('#shrun');
        await p.waitForSelector('.toastin.ok, .toastin.bad', { timeout: 300000 });
        const toast = (await p.$eval('#toast', el => el.innerText)).replace(/\s+/g, ' ').trim();
        step(name, `sheet → ${toast.slice(0, 160)}`);
        if (!(await p.$('.toastin.ok'))) errs.push(`desk: the tests did not finish cleanly in the sandbox: ${toast.slice(0, 200)}`);
        await p.screenshot({ path: `${out}-${name}-tests-ran.png` });
        // 2. the terminal drawer: a Lantern command runs, a shell command is refused
        await p.click('#termbtn'); await p.waitForSelector('#tcmd');
        await p.fill('#tcmd', 'analyze --offline'); await p.press('#tcmd', 'Enter');
        await until(p, () => /ready\s+\d+\/100/.test(document.getElementById('tout').innerText), 180000);
        allow400 = true;
        await p.fill('#tcmd', 'rm -rf /'); await p.press('#tcmd', 'Enter');
        await until(p, () => /not an allowed command|not a Lantern command/.test(document.getElementById('tout').innerText), 20000);
        await p.waitForTimeout(300); allow400 = false;
        const lines = (await p.$eval('#tout', el => el.innerText)).split('\n').filter(l => /ready|allowed command|Lantern command/.test(l));
        step(name, `terminal → ${lines.slice(0, 3).join(' | ')}`);
        await p.screenshot({ path: `${out}-${name}-terminal.png` });
        await p.click('#termclose');
      }
      // 3. a screenshot dropped into Ask Lantern is read on this computer
      await p.click('#askpill'); await p.waitForSelector('#ask .win');
      if (image) {
        await p.setInputFiles('#askfile', image);
        await until(p, () => { const s = document.querySelector('#ask .shot .sm'); return s && !/reading on this computer/.test(s.textContent); }, 30000);
        const info = await p.$eval('#ask .shot .sm', el => el.textContent);
        step(name, `screenshot → ${info}`);
        if (expectText) {
          const read = await p.evaluate(() => (typeof ASK !== 'undefined' && ASK.shot && ASK.shot.text) || '');
          if (!read.toUpperCase().includes(expectText.toUpperCase())) errs.push(`${name}: the screenshot's text "${expectText}" was not read (got: ${info})`);
        } else if (!/×/.test(info)) errs.push(`${name}: the screenshot was not opened (${info})`);
      }
      await p.screenshot({ path: `${out}-${name}-ask.png` });
      await p.click('#askclose');
      // 4. Settings → Analysis packs: turn one off, check the project goes stale, turn it back on
      await p.evaluate(() => go('settings')); await p.waitForTimeout(800);
      if (name === 'desk') {
        const sw = '#packlist [data-pack="django"]';
        await p.waitForSelector(sw);
        await p.click(sw); await p.waitForSelector(`${sw}[aria-checked="false"]`);
        const st = await api('/api/state');
        step(name, `pack toggle → django off; project card stale=${st.projects.map(x => x.stale).join(',')}`);
        if (!st.projects.some(x => x.stale === 'packs')) errs.push('desk: turning a pack off did not mark the project "Re-check to apply"');
        await p.locator('#packs').screenshot({ path: `${out}-${name}-packs-off.png` });
        await p.click(sw); await p.waitForSelector(`${sw}[aria-checked="true"]`);
        await api('/api/settings', { view_mode: 'simple' });
      }
      await p.screenshot({ path: `${out}-${name}-settings.png`, fullPage: true });
    } catch (e) { errs.push(`${name}: the smoke test could not drive the app: ${e.message.split('\n')[0]}`); }
    await p.close();
  }
  console.log(errs.length ? errs.join('\n') : 'no JS errors');
  if (errs.length) process.exitCode = 1;
  await b.close();
}

(async () => {
  if (process.argv[2] === '--app') {
    const a = process.argv.slice(3), opt = k => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : null; };
    if (!a[0] || !a[1]) { console.error('usage: node tools/viewer_smoke.js --app URL OUT_PREFIX [--image PNG --expect-text WORD]'); process.exit(2); }
    return appSmoke(a[0], a[1], opt('--image'), opt('--expect-text'));
  }
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
    // Simple opens the Lanes view (an SVG); the rest of the smoke walks the Path list, so switch to it
    if (await p.$('.seg [data-v="lanes"].on') && !(await p.$('.node'))) { await p.click('.seg [data-v="tree"]'); await p.waitForTimeout(150); if (await p.$('#expand')) { await p.click('#expand'); await p.waitForTimeout(150); } }
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
