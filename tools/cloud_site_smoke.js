// Cloud website smoke test: drives the website served by tools/cloud_site_demo.py at desktop and phone sizes, in
// light and dark, signed out and signed in. Exits non-zero on any JavaScript error, on a dialog, if run data reached
// the page as markup (an element with data-pwn, or a changed title: see tools/poison_report.py), or if a screen
// the website promises is missing (sign-in buttons, the run cards, the progress page, the report in its frame), or
// if sharing, stopping sharing, deleting a run or deleting the account does not do what it says.
// Usage: node tools/cloud_site_smoke.js http://127.0.0.1:8872/ TOKEN_FILE OUT_PREFIX   (needs `npm i playwright`)
const { chromium } = require('playwright');
const fs = require('fs');

async function until(p, fn, timeout) {
  const end = Date.now() + timeout;
  for (;;) {
    if (await p.evaluate(fn).catch(() => false)) return;
    if (Date.now() > end) throw new Error(`timed out after ${timeout} ms waiting for ${fn.toString().slice(0, 90)}`);
    await p.waitForTimeout(200);
  }
}

(async () => {
  const [base, tokenFile, out] = process.argv.slice(2);
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  const b = await chromium.launch();
  const errs = [];
  let allow503 = false, allow409 = false, allow404 = false;
  const token2 = fs.readFileSync(tokenFile + '.2', 'utf8').trim();
  const sizes = [['desk', { width: 1360, height: 880 }], ['phone', { width: 390, height: 844 }]];
  for (const [name, viewport] of sizes) for (const scheme of ['light', 'dark']) {
    const tag = `${name}-${scheme}`;
    const ctx = await b.newContext({ viewport, colorScheme: scheme });
    const watch = p => {
      p.on('pageerror', e => errs.push(`${tag}: ${e.message}`));
      p.on('console', m => { if (m.type() === 'error' && !/status of 401/.test(m.text()) && !(allow503 && /status of 503/.test(m.text())) && !(allow409 && /status of 409/.test(m.text())) && !(allow404 && /status of 404/.test(m.text())) && !/status of 401/.test(m.text())) errs.push(`${tag} console: ${m.text()}`); });
      p.on('dialog', d => { errs.push(`${tag}: a dialog opened: ${d.message()}`); d.dismiss(); });
    };
    const clean = async (p, where) => {
      const bad = await p.evaluate(() => ({ pwn: document.querySelectorAll('[data-pwn]').length, title: document.title,
        frame: (() => { try { const d = document.querySelector('iframe')?.contentDocument; return d ? d.querySelectorAll('[data-pwn]').length + (d.title === 'PWNED' ? 1 : 0) : 0; } catch (e) { return 0; } })() }));
      if (bad.pwn || bad.frame || bad.title === 'PWNED') errs.push(`${tag} ${where}: run data became markup (${JSON.stringify(bad)})`);
    };
    // signed out: the home page and the sign-in sheet
    let p = await ctx.newPage(); watch(p);
    await p.goto(base); await p.waitForSelector('#signin');
    await p.screenshot({ path: `${out}-${tag}-signed-out.png` });
    await p.click('#signin'); await p.waitForSelector('.signbtns [data-p="github"]');
    await p.screenshot({ path: `${out}-${tag}-sign-in.png` });
    await clean(p, 'signed out'); await p.close();
    // signed in: My runs, a run in progress, a failed run, the report
    await ctx.addCookies([{ name: 'lt', value: token, url: base }]);
    p = await ctx.newPage(); watch(p);
    await p.goto(base); await p.waitForSelector('article.app');
    const cards = await p.$$eval('article.app', a => a.length);
    if (cards !== 3) errs.push(`${tag}: expected 3 run cards, saw ${cards}`);
    await p.screenshot({ path: `${out}-${tag}-runs.png`, fullPage: true });
    await clean(p, 'my runs');
    if (name === 'desk') {
      await p.click('#viewmode [data-m="advanced"]'); await p.waitForSelector('.ptable');
      await p.screenshot({ path: `${out}-${tag}-runs-advanced.png` });
      await clean(p, 'advanced');
      await p.click('#viewmode [data-m="simple"]'); await p.waitForSelector('article.app');
    }
    await p.goto(base + '#/run/going1'); await p.waitForSelector('.progress .running-steps'); await p.waitForSelector('.progress .indeterminate');
    await p.screenshot({ path: `${out}-${tag}-progress.png` });
    await clean(p, 'progress');
    await p.goto(base + '#/run/failed1'); await p.reload(); await p.waitForSelector('.progress [data-again]');
    await clean(p, 'failed run');
    // "Try again" starts the same link again (the demo server has no worker, so it answers 503: that is fine here)
    allow503 = true;
    const again = p.waitForRequest(rq => rq.url().endsWith('/v1/repos') && rq.method() === 'POST', { timeout: 5000 }).catch(() => null);
    await p.click('.progress [data-again]');
    if (!(await again)) errs.push(`${tag}: "Try again" on a failed run sent nothing`);
    await p.waitForTimeout(300); allow503 = false;
    await p.goto(base + '#/run/done1'); await p.reload();
    await until(p, () => { try { return !!document.querySelector('#pbody iframe')?.contentDocument?.querySelector('#tabs'); } catch (e) { return false; } }, 20000);
    await p.waitForTimeout(800);
    await p.screenshot({ path: `${out}-${tag}-report.png` });
    await clean(p, 'report');
    await p.click('.sub [data-t="evidence"]'); await p.waitForTimeout(1200);
    await clean(p, 'evidence');
    // Share: a link anyone can open, read-only; Stop sharing turns it off
    await p.click('#share'); await p.waitForSelector('#doshare');
    await p.screenshot({ path: `${out}-${tag}-share.png` });
    await p.click('#doshare'); await p.waitForSelector('#shareurl');
    const shareUrl = await p.$eval('#shareurl', i => i.value);
    await p.screenshot({ path: `${out}-${tag}-shared.png` });
    const anon = await b.newContext({ viewport, colorScheme: scheme }); const q = await anon.newPage(); watch(q);
    const got = await q.goto(shareUrl);
    if (!got || got.status() !== 200) errs.push(`${tag}: the share link did not open (${got && got.status()})`);
    await q.waitForSelector('#tabs'); await clean(q, 'shared report');
    await p.click('#unshare'); await p.waitForSelector('#doshare');
    allow404 = true; const off = await q.goto(shareUrl); await q.waitForTimeout(200); allow404 = false;
    if (!off || off.status() !== 404) errs.push(`${tag}: the share link still opens after Stop sharing (${off && off.status()})`);
    await anon.close();
    await p.click('.sheet [data-close]');
    await p.click('#who'); await p.waitForSelector('#signout');
    await p.screenshot({ path: `${out}-${tag}-account.png` });
    if (name === 'phone' && scheme === 'dark') {   // last pass: delete a run, then the whole account
      await p.click('.sheet [data-close]');
      await p.goto(base + '#/'); await p.waitForSelector('article.app');
      await p.click('[data-del="failed1"]'); await p.waitForSelector('#dodel');
      await p.screenshot({ path: `${out}-${tag}-delete-run.png` });
      await p.click('#dodel'); await until(p, () => document.querySelectorAll('article.app').length === 2, 5000);
      await p.click('#who'); await p.click('#delme'); await p.waitForSelector('#sure');
      await p.check('#sure'); await p.screenshot({ path: `${out}-${tag}-delete-account.png` });
      // this account still has a check running, so the account is kept and the sheet says why
      allow409 = true;
      await p.click('#dodel'); await p.waitForSelector('#delmsg .note');
      const why = await p.$eval('#delmsg', d => d.textContent);
      if (!/still going/.test(why)) errs.push(`${tag}: deleting an account with a check running said "${why}"`);
      await p.screenshot({ path: `${out}-${tag}-delete-account-refused.png` });
      allow409 = false;
      // the second demo account has nothing running: deleting it signs the browser out and the account is gone
      const ctx2 = await b.newContext({ viewport, colorScheme: scheme });
      await ctx2.addCookies([{ name: 'lt', value: token2, url: base }]);
      const r = await ctx2.newPage(); watch(r);
      await r.goto(base); await r.waitForSelector('article.app');
      await r.click('#who'); await r.click('#delme'); await r.waitForSelector('#sure');
      await r.check('#sure'); await r.click('#dodel'); await r.waitForSelector('#signin');
      await r.reload(); await r.waitForSelector('#signin');
      const me = await r.evaluate(() => fetch('/v1/me').then(x => x.status));
      if (me !== 401) errs.push(`${tag}: after deleting the account /v1/me answered ${me}`);
      await r.screenshot({ path: `${out}-${tag}-account-deleted.png` });
      await ctx2.close();
    }
    await p.close(); await ctx.close();
  }
  await b.close();
  if (errs.length) { console.error(errs.join('\n')); process.exit(1); }
  console.log('cloud website: no JS errors, no dialogs, run data stayed text (desktop + phone, light + dark)');
})().catch(e => { console.error(e); process.exit(1); });
