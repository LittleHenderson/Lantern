// Viewer smoke test: drives the report at desktop and phone sizes, saves screenshots, and exits
// non-zero on any JavaScript error, on a dialog, if the map is empty, or if any of the report's data landed in
// the page as markup (an element with data-pwn, or a changed title: see tools/poison_report.py).
// Works on any report (it clicks whatever is on screen).
// Usage: node tools/viewer_smoke.js path/to/report.html /tmp/shot   (needs `npm i playwright`)
// App mode: node tools/viewer_smoke.js --app 'http://127.0.0.1:8765/?token=…' OUT_PREFIX [--image shot.png --expect-text WORD]
//                                        [--slow-tests 'python -m pytest -q tests/stop_check.py']
//   drives a live `lantern serve` with one analyzed project: "Watch my tests run" (confirm and run in the sandbox,
//   wait for the result; with --slow-tests, a test command of the project that would go on for minutes is started
//   and ended with the "Stop the tests" button), the terminal drawer (a Lantern command runs; a shell command is refused), a screenshot
//   dropped into Ask Lantern (read on this computer), and Settings → Analysis packs (one pack off, then on again).
//   Fails on any JavaScript error or when one of those does not answer as it should. The phone pass loads the
//   same screens.
// PW_BROWSER=firefox|webkit runs the same smoke in another engine (CI runs all three on the report and the app's home).
const BROWSER = process.env.PW_BROWSER || 'chromium';
const chromium = require('playwright')[BROWSER];
const a11y = require('./a11y.js');
const outside = require('./outside.js');   // no page under test reaches the internet

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

async function appSmoke(url, out, image, expectText, slowTests) {
  const b = await outside.launch(chromium);   // its only way out is a proxy on this computer that refuses
  const errs = [];
  let allow400 = false;   // the terminal's refusal answers 400 on purpose; Chromium logs that as a console error
  const step = (name, what) => console.log(`${name}: ${what}`);
  for (const [name, vp] of [['desk', { width: 1440, height: 900 }], ['phone', { width: 390, height: 844 }]]) {
    const p = await b.newPage({ viewport: vp });
    await outside.watch(p, errs, outside.FONTS);
    p.on('pageerror', e => errs.push(`${name}: ${e.message}`));
    p.on('console', m => { if (m.type() === 'error' && !outside.refusedFont(m) && !(allow400 && /status of 400/.test(m.text()))) errs.push(`${name} console: ${m.text()}${outside.where(m)}`); });
    p.on('dialog', d => { errs.push(`${name}: a dialog opened: ${d.message()}`); d.dismiss(); });
    const api = (path, body) => p.evaluate(([path, body]) => fetch(path, body === undefined ? {} : {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Lantern-Token': TOKEN}, body: JSON.stringify(body)}).then(r => r.json()), [path, body]);
    try {
      await p.goto(url);
      await p.waitForSelector('[data-open]', { timeout: 180000 });
      await a11y.axe(p, `${name} home`, errs);
      // onboarding (directive: user first): one button, then one plain question per screen
      await p.click('#showus'); await p.waitForSelector('.onb .pick');
      if (await p.$$eval('.onb .pick', a => a.length) !== 3) errs.push(`${name}: "Show us your project" should offer three places`);
      await p.click('.onb .pick[data-to="computer"]'); await p.waitForSelector('#pickfolder');
      await a11y.axe(p, `${name} onboarding`, errs);
      await p.click('[data-back="where"]'); await p.click('[data-back=""]'); await p.waitForSelector('#showus');
      step(name, `keyboard: ${(await a11y.keyboard(p, `${name} home`, errs, 8)).join(' > ')}`);
      if (name === 'desk') await api('/api/settings', { view_mode: 'advanced' });
      await p.reload(); await p.waitForSelector('[data-open]');
      // the terminal is pulled up from the tab at the bottom of every screen (here, before any project is open):
      // drag the tab up, list the projects, and open the first one from it
      {
        const tb = await (await p.$('#termtab')).boundingBox();
        await p.mouse.move(tb.x + tb.width / 2, tb.y + 8); await p.mouse.down();
        await p.mouse.move(tb.x + tb.width / 2, tb.y - 260, { steps: 8 }); await p.mouse.up();
        const h = await p.$eval('#term', t => t.hidden ? 0 : t.getBoundingClientRect().height);
        if (h < 200) errs.push(`${name}: dragging the Terminal tab up did not pull the terminal up (${h} px)`);
        await p.fill('#tcmd', 'projects'); await p.press('#tcmd', 'Enter');
        await until(p, () => /^\s*1\s/m.test(document.getElementById('tout').innerText), 10000);
        await a11y.axe(p, `${name} terminal`, errs);
        await p.screenshot({ path: `${out}-${name}-terminal-home.png` });
        await p.fill('#tcmd', 'open 1'); await p.press('#tcmd', 'Enter');
        await until(p, () => S.view === 'project', 10000);
        step(name, `terminal pulled up to ${Math.round(h)} px, projects listed, open 1 → project`);
        await p.click('#termclose');
        if (!(await p.$eval('#term', t => t.hidden))) errs.push(`${name}: the terminal did not close`);
        await p.waitForTimeout(1500);
      }
      await p.screenshot({ path: `${out}-${name}-project.png` });
      await a11y.axe(p, `${name} project`, errs, { frames: true });
      {
        // inside the app the report draws no backdrop of its own; the app's shows through
        const fr = p.frames().find(f => /report\.html/.test(f.url()));
        const own = fr ? await fr.evaluate(() => !!document.querySelector('.backdrop')).catch(() => null) : null;
        const app = await p.evaluate(() => document.querySelectorAll('#bg svg').length);
        if (own !== false || app !== 3) errs.push(`${name}: backdrop wrong inside the app (report draws its own: ${own}, app layers: ${app})`);
      }
      if (name === 'phone') {
        // phones get Simple only, even though the desktop pass saved Advanced
        const mode = await p.evaluate(() => document.body.dataset.mode);
        if (mode !== 'simple') errs.push(`phone: the app shows ${mode} (phones must get Simple only)`);
        const fr = p.frames().find(f => /report\.html/.test(f.url()));
        const rs = fr ? await fr.evaluate(() => S.simple).catch(() => null) : null;
        if (rs !== true) errs.push(`phone: the Atlas frame is not Simple (${rs})`);
        step(name, `view mode ${mode}, Atlas simple ${rs}`);
      }
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
        if (slowTests) {
          // 1b. tests that would go on for minutes are ended with the button, and the app says that they were
          await p.click('#watchtests'); await p.waitForSelector('#shrun');
          await p.fill('#testcmd', slowTests);
          await p.click('#shrun');
          await p.waitForSelector('[data-stop]', { timeout: 30000 });
          await a11y.axe(p, `${name} tests running`, errs);
          await p.screenshot({ path: `${out}-${name}-tests-running.png` });
          const began = Date.now();
          await p.click('[data-stop]');
          const during = await p.evaluate(() => { const b = document.querySelector('[data-stop]'); return b ? `${b.textContent}${b.disabled ? ' (off)' : ''}` : 'already over'; });
          await until(p, () => /You stopped the tests/.test(document.getElementById('toast').innerText), 90000);
          const said = (await p.$eval('#toast', el => el.innerText)).replace(/\s+/g, ' ').trim();
          step(name, `stop → button "${during}", then after ${((Date.now() - began) / 1000).toFixed(1)} s: ${said.slice(0, 120)}`);
          if (!/^Stopping…|^already over/.test(during)) errs.push(`desk: the Stop button did not change when pressed (${during})`);
          await p.screenshot({ path: `${out}-${name}-tests-stopped.png` });
          // 1c. a run that could not end everything it started (the answer is a stand-in: the real case needs a
          // process that cannot be ended): each message says so, none says beside it that everything was ended,
          // and the words arrive as text
          const planted = '1 process(es) this run started could not be ended <img src=x onerror=alert(1)>';
          for (const [kind, result, never] of [
            ['stopped', { cancelled: true }, /everything they started were ended/],   // the words of a stop that left nothing
            ['time limit', { timed_out: true }, /and everything they started/],
            ['ended', { returncode: 0, traced: true, observed: 3, recall: 1 }, null]]) {
            await p.route('**/api/jobs/left-check', route => route.fulfill({ status: 200, contentType: 'application/json',
              body: JSON.stringify({ id: 'left-check', status: 'done', log: [], result: { blocked: [], not_ended: [planted], ...result } }) }));
            await p.evaluate(() => watchTrace('left-check', S.state.projects.find(x => x.id === S.project), 'x'));
            await p.unroute('**/api/jobs/left-check');
            const told = (await p.$eval('#toast', el => el.innerText)).replace(/\s+/g, ' ').trim();
            const drawn = await p.evaluate(() => ({ img: document.querySelectorAll('#toast img').length, ok: document.querySelectorAll('#toast .toastin.ok').length }));
            step(name, `not ended (${kind}) → ${told.slice(0, 150)}`);
            if (!/may still be running on this computer: 1 process\(es\) this run started could not be ended <img/.test(told)) errs.push(`desk: a run that could not end everything (${kind}) does not say so: ${told.slice(0, 200)}`);
            if (never && never.test(told)) errs.push(`desk: a run that could not end everything (${kind}) still says that it did: ${told.slice(0, 200)}`);
            if (drawn.img || drawn.ok) errs.push(`desk: the message of a run that could not end everything (${kind}) is drawn wrong (${JSON.stringify(drawn)})`);
          }
          await a11y.axe(p, `${name} tests not ended`, errs);
          await p.screenshot({ path: `${out}-${name}-tests-not-ended.png` });
        }
        // 2. the terminal drawer: a Lantern command runs, a shell command is refused
        await p.click('#termtab'); await p.waitForSelector('#tcmd');
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
      await a11y.axe(p, `${name} ask`, errs);
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
      await a11y.axe(p, `${name} settings`, errs);
    } catch (e) { errs.push(`${name}: the smoke test could not drive the app: ${e.message.split('\n')[0]}`); }
    await p.close();
  }
  console.log(await outside.close(b, errs));   // closes the browser, then says what was asked of the outside
  console.log(errs.length ? errs.join('\n') : 'no JS errors');
  if (errs.length) process.exitCode = 1;
}

(async () => {
  if (process.argv[2] === '--app') {
    const a = process.argv.slice(3), opt = k => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : null; };
    if (!a[0] || !a[1]) { console.error('usage: node tools/viewer_smoke.js --app URL OUT_PREFIX [--image PNG --expect-text WORD --slow-tests COMMAND]'); process.exit(2); }
    return appSmoke(a[0], a[1], opt('--image'), opt('--expect-text'), opt('--slow-tests'));
  }
  const [file, out] = process.argv.slice(2);
  if (!file || !out) { console.error('usage: node tools/viewer_smoke.js REPORT.html OUT_PREFIX'); process.exit(2); }
  const b = await outside.launch(chromium);   // its only way out is a proxy on this computer that refuses
  const errs = [];
  for (const [name, vp] of [['desk', { width: 1440, height: 900 }], ['phone', { width: 390, height: 844 }]]) {
    // the phone pass runs in dark mode, so both appearances get the accessibility checks
    const p = await b.newPage({ viewport: vp, colorScheme: name === 'phone' ? 'dark' : 'light' });
    await outside.watch(p, errs);   // a report is one self-contained file: it asks the outside for nothing
    try {
    p.on('pageerror', e => errs.push(`${name}: ${e.message}`));
    p.on('dialog', d => { errs.push(`${name}: a dialog opened (script from the data ran): ${d.message()}`); d.dismiss(); });
    p.on('console', m => { if (m.type() === 'error') errs.push(`${name} console: ${m.text()}${outside.where(m)}`); });
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
    await a11y.axe(p, `${name} map`, errs);
    { const walk = await a11y.keyboard(p, `${name} map`, errs, 8); console.log(`${name} keyboard: ${walk.join(' > ')}`); }
    // the backdrop (design directive): three drifting layers, quiet behind the map, full behind About
    const bd = await p.evaluate(() => { const el = document.querySelector('body>.backdrop'); return el ? {n: el.querySelectorAll(':scope>svg').length, quiet: el.hasAttribute('data-quiet'), hidden: el.getAttribute('aria-hidden')} : null; });
    if (!bd || bd.n !== 3 || !bd.quiet || bd.hidden !== 'true') errs.push(`${name}: the backdrop is missing or not quiet on the map (${JSON.stringify(bd)})`);
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
      for (const l of ['1', '2', '3', '4']) {
        const btn = await p.$(`.lenses button[data-l="${l}"]`);
        if (btn) { await btn.click(); await p.waitForTimeout(60); }
        if (l === '3') { const pair = await p.$('.pair'); if (pair) { await pair.click(); await p.waitForTimeout(60); } }
      }
      await pwned('detail');
      await p.screenshot({ path: `${out}-${name}-detail.png` });
      await a11y.axe(p, `${name} detail`, errs);
      // every function has three lenses from the map alone, before any model writes one: open one no model explained
      const mapLens = await p.evaluate(() => { const n = G.nodes.find(x => x.kind === 'callable' && !EXP[x.id]); if (!n) return 'none'; select(n.id, true); S.lens = 2; renderRight();
        const el = document.querySelector('#right'); return (el.querySelector('.lens.l2') ? 'lens ' : 'nolens ') + (el.innerText.includes('Built from the map') ? 'byline' : 'nobyline'); });
      if (mapLens !== 'none' && mapLens !== 'lens byline') errs.push(`${name}: a function no model explained has no lenses from the map (${mapLens})`);
      await pwned('maplens');
      if (name === 'phone' && await p.$('#close')) { await p.click('#close'); await p.waitForTimeout(250); }
    }
    // the Graph view is a camera on an endless canvas: it fills the panel, zooms far past the old 35%-250%, drags, and goes full screen
    if (await p.$('.seg button[data-v="graph"]')) {
      await p.click('.seg button[data-v="graph"]'); await p.waitForTimeout(200);
      if (await p.$('#graph .vp')) {
        const zoom = () => p.evaluate(() => +document.querySelector('#graph .vp').dataset.zoom);
        const view = () => p.evaluate(() => document.querySelector('#graph svg').getAttribute('viewBox'));
        const filled = await p.evaluate(() => { const v = document.querySelector('#graph .vp').getBoundingClientRect(), s = document.querySelector('#graph svg').getBoundingClientRect(), c = document.querySelector('#center').getBoundingClientRect(); return Math.abs(v.width - s.width) < 2 && Math.abs(v.height - s.height) < 2 && v.width >= c.width - 2 && (innerWidth < 720 || v.bottom >= c.bottom - 2); });
        if (!filled) errs.push(`${name}: the graph does not fill its panel`);
        await p.screenshot({ path: `${out}-${name}-graph.png` });
        // the breadcrumb says where you are, and the minimap shows the whole map with the screen's box on it
        if (!await p.$('.crumbs [aria-current="location"]')) errs.push(`${name}: the map has no breadcrumb saying where you are`);
        if (!await p.$('#graph .mmap .mmview')) errs.push(`${name}: the graph has no minimap`);
        else {
          await p.click('#graph .mmhead [data-o="30"]'); await p.waitForTimeout(60);
          if (await p.evaluate(() => getComputedStyle(document.querySelector('#graph .mmsvg')).opacity) !== '0.3') errs.push(`${name}: the minimap's 30% button did not make it see-through`);
          await p.click('#graph .mmhead [data-o="off"]'); await p.waitForTimeout(60);
          if (await p.evaluate(() => getComputedStyle(document.querySelector('#graph .mmap')).display) !== 'none') errs.push(`${name}: the minimap did not hide`);
          await p.click('#graph .mmshow'); await p.waitForTimeout(60);
          if (await p.evaluate(() => getComputedStyle(document.querySelector('#graph .mmap')).display) === 'none') errs.push(`${name}: the minimap did not come back`);
          await p.click('#graph .mmhead [data-o="100"]'); await p.waitForTimeout(60);
          const before = await view(), m = await (await p.$('#graph .mmsvg')).boundingBox();
          await p.mouse.click(m.x + 6, m.y + m.height - 6); await p.waitForTimeout(80);
          if (await view() === before) errs.push(`${name}: a click on the minimap did not move the map`);
        }
        if (name === 'desk') {
          const r = await (await p.$('#graph .vp')).boundingBox(), cx = r.x + r.width / 2, cy = r.y + r.height / 2;
          await p.click('#graph [data-z="fit"]'); await p.waitForTimeout(80);
          await p.screenshot({ path: `${out}-${name}-graph-fit.png` });
          await p.mouse.move(cx, cy);
          for (let i = 0; i < 12; i++) await p.mouse.wheel(0, 900);
          await p.waitForTimeout(300);
          if (await zoom() >= .05) errs.push(`${name}: the graph stops zooming out at ${await zoom()}`);
          for (let i = 0; i < 28; i++) await p.mouse.wheel(0, -900);
          await p.waitForTimeout(300);
          if (await zoom() <= 25) errs.push(`${name}: the graph stops zooming in at ${await zoom()}`);
          await p.click('#graph [data-z="fit"]'); await p.waitForTimeout(80);
          const before = await view();
          await p.mouse.move(r.x + 12, r.y + 12); await p.mouse.down(); await p.mouse.move(r.x + 212, r.y + 112, { steps: 4 }); await p.mouse.up(); await p.waitForTimeout(80);
          if (await view() === before) errs.push(`${name}: dragging the graph did not move it`);
          const width = async () => p.evaluate(() => document.querySelector('#graph .vp').getBoundingClientRect().width);
          const small = await width();
          await p.click('#graph [data-z="max"]'); await p.waitForTimeout(250);
          if (await width() <= small) errs.push(`${name}: full screen did not make the graph bigger`);
          await p.screenshot({ path: `${out}-${name}-graph-full.png` });
          await p.click('#graph [data-z="max"]'); await p.waitForTimeout(250);
          if (await p.evaluate(() => document.body.classList.contains('gmax'))) errs.push(`${name}: could not leave full screen`);
        }
        await pwned('graph');
      }
    }
    if (name === 'desk' && await p.$('.seg button[data-v="chart"]')) {
      await p.click('.seg button[data-v="chart"]'); await p.waitForTimeout(150);
      await p.screenshot({ path: `${out}-${name}-chart.png` });
    }
    await p.click('#tabs button[data-t="findings"]'); await p.waitForTimeout(150);
    await pwned('findings');
    await p.screenshot({ path: `${out}-${name}-findings.png` });
    await a11y.axe(p, `${name} findings`, errs);
    // scenarios: open the first finding's story, then its Fix page (which shows the story as a card)
    const scen = await p.$('details.scenbox summary');
    if (scen) { await scen.click(); await p.waitForTimeout(60); await pwned('scenario'); }
    const fixb = await p.$('[data-fix]');
    if (fixb) {
      await fixb.click(); await p.waitForTimeout(150); await pwned('fix');
      await p.screenshot({ path: `${out}-${name}-fix.png`, fullPage: true });
      await a11y.axe(p, `${name} fix`, errs);
      await p.click('#tabs button[data-t="findings"]'); await p.waitForTimeout(100);
    }
    if (await p.$('#tabs button[data-t="ready"]')) {
      await p.click('#tabs button[data-t="ready"]'); await p.waitForTimeout(150);
      await pwned('readiness');
      await p.screenshot({ path: `${out}-${name}-ready.png`, fullPage: true });
      await a11y.axe(p, `${name} readiness`, errs);
    }
    await p.click('#tabs button[data-t="about"]'); await p.waitForTimeout(150);
    await pwned('about');
    if (await p.evaluate(() => document.querySelector('body>.backdrop').hasAttribute('data-quiet'))) errs.push(`${name}: the backdrop stays quiet on About (should be full)`);
    if (name === 'desk') {
      // reduced motion: the shapes are drawn, nothing moves (two frames 2 s apart)
      await p.emulateMedia({ reducedMotion: 'reduce' });
      const tf = () => p.evaluate(() => [...document.querySelectorAll('body>.backdrop svg')].map(x => getComputedStyle(x).transform).join('|'));
      const t1 = await tf(); await p.waitForTimeout(2000); const t2 = await tf();
      if (t1 !== t2) errs.push('desk: the backdrop still moves under prefers-reduced-motion');
      await p.screenshot({ path: `${out}-${name}-about-still.png` });
      await p.emulateMedia({ reducedMotion: 'no-preference' });
    }
    if (name === 'desk') {
      // the search box renders arbitrary function names
      await p.click('#tabs button[data-t="map"]'); await p.waitForTimeout(100);
      await p.fill('#q', 'a'); await p.waitForTimeout(150);
      await pwned('search');
    }
    } catch (e) { errs.push(`${name}: the smoke test could not drive the page: ${e.message.split('\n')[0]}`); }
    await p.close();
  }
  console.log(await outside.close(b, errs));   // closes the browser, then says what was asked of the outside
  console.log(errs.length ? errs.join('\n') : 'no JS errors');
  if (errs.length) process.exitCode = 1;
})();
