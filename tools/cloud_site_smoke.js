// Cloud website smoke test: drives the website served by tools/cloud_site_demo.py at desktop and phone sizes, in
// light and dark, signed out and signed in. Exits non-zero on any JavaScript error, on a dialog, if run data reached
// the page as markup (an element with data-pwn, or a changed title: see tools/poison_report.py), or if a screen
// the website promises is missing (sign-in buttons, the run cards, the progress page, the report in its frame), or
// if sharing, stopping sharing, deleting a run or deleting the account does not do what it says.
// Usage: node tools/cloud_site_smoke.js http://127.0.0.1:8872/ TOKEN_FILE OUT_PREFIX   (needs `npm i playwright`)
const chromium = require('playwright')[process.env.PW_BROWSER || 'chromium'];
const fs = require('fs');
const a11y = require('./a11y.js');
const outside = require('./outside.js');   // no page under test reaches the internet

async function fresh(p, url) { await p.goto('about:blank'); await p.goto(url); await p.waitForLoadState('load'); }
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
  const site = base.replace(/\/?$/, '/') + '?intro=0';   // the site itself, without the landing intro (checked once below)
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  const b = await outside.launch(chromium);   // its only way out is a proxy on this computer that refuses
  const errs = [];
  let allow503 = false, allow409 = false, allow404 = false;
  const token2 = fs.readFileSync(tokenFile + '.2', 'utf8').trim();
  const sizes = [['desk', { width: 1360, height: 880 }], ['phone', { width: 390, height: 844 }]];
  for (const [name, viewport] of sizes) for (const scheme of ['light', 'dark']) {
    const tag = `${name}-${scheme}`;
    const ctx = await b.newContext({ viewport, colorScheme: scheme });
    await outside.watch(ctx, errs, outside.FONTS);
    const watch = p => {
      p.on('pageerror', e => errs.push(`${tag}: ${e.message}`));
      // Firefox-only noise, not page code: its favicon loader reporting the page's own content policy
      // (resource:///modules/FaviconLoader), and the live-progress stream being cut when the smoke leaves the page
      const browserNoise = m => /resource:\/\/\//.test((m.location && m.location().url) || '') || /resource:\/\/\/modules/.test(m.text()) || /establish a connection to the server at .*\/stream/.test(m.text());
      p.on('console', m => { if (m.type() === 'error' && !browserNoise(m) && !outside.refusedFont(m) && !/status of 401/.test(m.text()) && !(allow503 && /status of 503/.test(m.text())) && !(allow409 && /status of 409/.test(m.text())) && !(allow404 && /status of 404/.test(m.text())) && !/status of 401/.test(m.text())) errs.push(`${tag} console: ${m.text()}${outside.where(m)}`); });
      p.on('dialog', d => { errs.push(`${tag}: a dialog opened: ${d.message()}`); d.dismiss(); });
    };
    const clean = async (p, where) => {
      const bad = await p.evaluate(() => ({ pwn: document.querySelectorAll('[data-pwn]').length, title: document.title,
        frame: (() => { try { const d = document.querySelector('iframe')?.contentDocument; return d ? d.querySelectorAll('[data-pwn]').length + (d.title === 'PWNED' ? 1 : 0) : 0; } catch (e) { return 0; } })() }));
      if (bad.pwn || bad.frame || bad.title === 'PWNED') errs.push(`${tag} ${where}: run data became markup (${JSON.stringify(bad)})`);
    };
    // signed out: the home page and the sign-in sheet
    let p = await ctx.newPage(); watch(p);
    // the landing intro plays on every visit to the home page; Escape jumps to its end card, "Add your app" lands on the page
    await p.goto(base); await p.waitForSelector('#intro:not(.hidden)');
    await p.waitForTimeout(400); await p.keyboard.press('Escape'); await p.waitForSelector('#introend.on');
    await p.click('#end-start'); await p.waitForSelector('#intro.hidden', { state: 'attached' });
    await p.goto(site); await p.waitForSelector('#signin');
    await p.screenshot({ path: `${out}-${tag}-signed-out.png` });
    await a11y.axe(p, `${tag} signed-out`, errs);
    if (scheme === 'light') console.log(`${tag} keyboard: ${(await a11y.keyboard(p, `${tag} signed-out`, errs, 6)).join(' > ')}`);
    await p.click('#signin'); await p.waitForSelector('.signbtns [data-p="github"]');
    await p.screenshot({ path: `${out}-${tag}-sign-in.png` });
    await a11y.axe(p, `${tag} sign-in`, errs);
    await clean(p, 'signed out'); await p.close();
    // signed in: My runs, a run in progress, a failed run, the report
    await ctx.addCookies([{ name: 'lt', value: token, url: base }]);
    p = await ctx.newPage(); watch(p);
    await p.goto(site); await p.waitForSelector('article.app');
    const cards = await p.$$eval('article.app', a => a.length);
    if (cards !== 3) errs.push(`${tag}: expected 3 run cards, saw ${cards}`);
    await p.screenshot({ path: `${out}-${tag}-runs.png`, fullPage: true });
    await a11y.axe(p, `${tag} my runs`, errs);
    await clean(p, 'my runs');
    // onboarding (directive: user first): one button, then one plain question per screen, and no jargon on it
    await p.click('#showus'); await p.waitForSelector('.onb .pick');
    if (await p.$$eval('.onb .pick', a => a.length) !== 3) errs.push(`${tag}: "Show us your project" should offer three places`);
    if (/repositor/i.test(await p.$eval('main', m => m.innerText))) errs.push(`${tag}: the word repository shows in Simple onboarding`);
    await a11y.axe(p, `${tag} onboarding`, errs);
    await p.click('.onb .pick[data-to="github"]'); await p.waitForSelector('.onb details.why');
    await p.screenshot({ path: `${out}-${tag}-onboarding-github.png` });
    await p.click('[data-back="where"]'); await p.click('[data-back=""]'); await p.waitForSelector('#showus');
    if (name === 'desk') {
      await p.click('#viewmode [data-m="advanced"]'); await p.waitForSelector('.ptable');
      await p.screenshot({ path: `${out}-${tag}-runs-advanced.png` });
      await clean(p, 'advanced');
      await p.click('#viewmode [data-m="simple"]'); await p.waitForSelector('article.app');
    }
    await p.goto(site + '#/run/going1'); await p.waitForSelector('.progress .running-steps'); await p.waitForSelector('.progress .runbar, .progress .indeterminate');
    await p.screenshot({ path: `${out}-${tag}-progress.png` });
    await a11y.axe(p, `${tag} progress`, errs);
    await clean(p, 'progress');
    // a fresh load at the run's address (not a hash change plus reload: Firefox and WebKit can reload the page before the
    // hash has moved, and the old run stays on screen)
    await fresh(p, site + '#/run/failed1');
    try { await p.waitForSelector('.progress [data-again]'); }
    catch (e) { errs.push(`${tag}: no "Try again" on the failed run at ${p.url()}: ${(await p.$eval('#view', v => v.innerText).catch(() => '?')).slice(0, 300).replace(/\s+/g, ' ')}`); await p.close(); await ctx.close(); continue; }
    await clean(p, 'failed run');
    // "Try again" starts the same link again (the demo server has no worker, so it answers 503: that is fine here)
    allow503 = true;
    const again = p.waitForRequest(rq => rq.url().endsWith('/v1/repos') && rq.method() === 'POST', { timeout: 5000 }).catch(() => null);
    await p.click('.progress [data-again]');
    if (!(await again)) errs.push(`${tag}: "Try again" on a failed run sent nothing`);
    await p.waitForTimeout(300); allow503 = false;
    await fresh(p, site + '#/run/done1');
    await until(p, () => { try { return !!document.querySelector('#pbody iframe')?.contentDocument?.querySelector('#tabs'); } catch (e) { return false; } }, 20000);
    await p.waitForTimeout(800);
    await p.screenshot({ path: `${out}-${tag}-report.png` });
    await a11y.axe(p, `${tag} report`, errs, { frames: true });
    await clean(p, 'report');
    await p.click('.sub [data-t="evidence"]'); await p.waitForTimeout(1200);
    await clean(p, 'evidence');
    // Explain: the demo run is explained already; the button says so and opens a summary
    const xl = await p.$eval('#explain', b => b.textContent);
    if (!/Explained/.test(xl)) errs.push(`${tag}: the Explain button says "${xl}" on an explained run`);
    await p.click('#explain'); await p.waitForSelector('#again'); await p.click('.sheet [data-close]');
    // Ask Lantern: the pill opens the assistant; the first question asks for consent, then the answer cites a finding
    await p.click('#askpill'); await p.waitForSelector('#ask .win');
    await p.click('#ask [data-chip]');
    const asked = await Promise.race([p.waitForSelector('#agree').then(() => 'consent'), p.waitForSelector('#ask .bot code').then(() => 'answer')]);
    if (asked === 'consent') {
      if (!(await p.$eval('.sheet', s => /DeepSeek/.test(s.textContent) && /40 functions/.test(s.textContent)))) errs.push(`${tag}: the consent sheet does not say where the code goes`);
      await p.screenshot({ path: `${out}-${tag}-consent.png` });
      await p.click('#agree');
    }
    await p.waitForSelector('#ask .bot code');
    // a screenshot: the attach button, its card with what was read, then Remove
    if (!(await p.$('#askatt'))) errs.push(`${tag}: Ask Lantern has no screenshot button`);
    await p.setInputFiles('#askfile', `${out}-${tag}-report.png`);
    await until(p, () => /text found|cannot read|text not read/.test(document.querySelector('#ask .shot .sm')?.textContent || ''), 90000);   // Tesseract on a busy CI runner can take over 30 s
    await p.screenshot({ path: `${out}-${tag}-ask-screenshot.png` });
    await p.click('#askrm');
    await clean(p, 'ask');
    await p.screenshot({ path: `${out}-${tag}-ask.png` });
    await a11y.axe(p, `${tag} ask`, errs);
    await p.click('#askclose');
    if (name === 'desk') {   // the report's own "Ask Lantern" button opens the same assistant, on that page
      await p.click('.sub [data-t="findings"]');
      const fr = p.frameLocator('#pbody iframe');
      await fr.locator('#pageask').click(); await p.waitForSelector('#ask .win');
      await p.click('#askclose');
    }
    // Share: a link anyone can open, read-only; Stop sharing turns it off
    await p.click('#share'); await p.waitForSelector('#doshare');
    await p.screenshot({ path: `${out}-${tag}-share.png` });
    await p.click('#doshare'); await p.waitForSelector('#shareurl');
    const shareUrl = await p.$eval('#shareurl', i => i.value);
    await p.screenshot({ path: `${out}-${tag}-shared.png` });
    const anon = await b.newContext({ viewport, colorScheme: scheme }); await outside.watch(anon, errs, outside.FONTS);
    const q = await anon.newPage(); watch(q);
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
    await a11y.axe(p, `${tag} account`, errs);
    if (tag === 'desk-light') {
      // team workspaces (directive: user first, step 3): make one, invite with a one-time link, add a report;
      // the second account joins with the link and can open the report, read-only
      await p.click('.sheet [data-close]');
      await p.click('#viewmode [data-m="advanced"]');
      await p.goto(site + '#/team'); await p.waitForSelector('#teamname');
      await p.fill('#teamname', 'Smoke team'); await p.click('#maketeam'); await p.waitForSelector('#invite');
      await a11y.axe(p, `${tag} team`, errs);
      await p.click('#invite'); await p.waitForSelector('#invurl');
      const inv = await p.$eval('#invurl', i => i.value);
      if (!/#\/join\/[A-Za-z0-9_-]{20,}$/.test(inv)) errs.push(`${tag}: the invite link looks wrong (${inv})`);
      await p.screenshot({ path: `${out}-${tag}-invite.png` });
      await p.click('#invdone');
      await p.click('#addrun'); await p.click('.sheet [data-add="done1"]'); await p.waitForSelector('.apps [data-open="done1"]');
      await p.screenshot({ path: `${out}-${tag}-team.png`, fullPage: true });
      const ctxT = await b.newContext({ viewport, colorScheme: scheme });
      await outside.watch(ctxT, errs, outside.FONTS);
      await ctxT.addCookies([{ name: 'lt', value: token2, url: base }]);
      const t = await ctxT.newPage(); watch(t);
      await t.goto(site + '#/join/' + inv.split('#/join/')[1]); await t.waitForSelector('#dojoin');
      if (/join\/[A-Za-z0-9_-]{20,}/.test(await t.evaluate(() => location.href))) errs.push(`${tag}: the invite's secret stayed in the address bar`);
      await a11y.axe(t, `${tag} join`, errs);
      await t.click('#dojoin'); await t.waitForSelector('.person + .person');
      // per-layer permissions (step 4): the owner lets the teammate see only the Browser and Frontend layers
      await p.reload(); await p.waitForSelector('[data-layers]');
      await p.click('[data-layers]'); await p.waitForSelector('#savelayers');
      await a11y.axe(p, `${tag} layers`, errs);
      await p.uncheck('.layer input[value="server"]'); await p.uncheck('.layer input[value="data"]');
      await p.screenshot({ path: `${out}-${tag}-layers.png` });
      await p.click('#savelayers'); await until(p, () => /Browser and Frontend/.test(document.querySelector('[data-layers]')?.textContent || ''), 5000);
      await t.reload(); await t.waitForSelector('[data-open="done1"]');
      await t.click('[data-open="done1"]');
      await until(t, () => { try { return !!document.querySelector('#pbody iframe')?.contentDocument?.querySelector('#tabs'); } catch (e) { return false; } }, 20000);
      if (await t.$('#share') || await t.$('.sub [data-del]')) errs.push(`${tag}: a teammate can share or delete someone else's report`);
      if (await t.$('.sub [data-t="evidence"]')) errs.push(`${tag}: a teammate who sees only some layers is offered the whole-app evidence report`);
      if (!await t.evaluate(() => !!document.querySelector('#pbody iframe')?.contentDocument?.querySelector('.scopenote'))) errs.push(`${tag}: the scoped report does not say which layers it shows`);
      // notes on the map (step 5): the teammate opens a function and leaves a note; it shows as plain words
      const fr = t.frameLocator('#pbody iframe');
      await t.evaluate(() => { const d = document.querySelector('#pbody iframe').contentDocument; d.querySelector('#tabs [data-t="map"]')?.click(); });
      await fr.locator('#center [data-id^="js:"]').first().click();
      await fr.locator('#notesopen').click();
      await fr.locator('#notein').fill('<img src=x onerror="window.__noted=1"> check this one');
      await fr.locator('#noteadd').click();
      await fr.locator('.notecard').first().waitFor({ timeout: 8000 });
      const noteOk = await t.evaluate(() => { const d = document.querySelector('#pbody iframe').contentDocument; const c = d.querySelector('.notecard p'); return !!c && !c.querySelector('img') && /check this one/.test(c.textContent) && !d.defaultView.__noted; });
      if (!noteOk) errs.push(`${tag}: a note on the map did not show as plain words`);
      await a11y.axe(t, `${tag} notes`, errs);
      await ctxT.close();
      await p.click('#viewmode [data-m="simple"]');
      await p.click('#who'); await p.waitForSelector('#signout');
    }
    if (name === 'phone' && scheme === 'dark') {   // last pass: delete a run, then the whole account
      await p.click('.sheet [data-close]');
      await p.goto(site + '#/'); await p.waitForSelector('article.app');
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
      await outside.watch(ctx2, errs, outside.FONTS);
      await ctx2.addCookies([{ name: 'lt', value: token2, url: base }]);
      const r = await ctx2.newPage(); watch(r);
      await r.goto(site); await r.waitForSelector('article.app');
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
  console.log(await outside.close(b, errs));   // closes the browser, then says what was asked of the outside
  if (errs.length) { console.error(errs.join('\n')); process.exit(1); }
  console.log('cloud website: no JS errors, no dialogs, run data stayed text (desktop + phone, light + dark)');
})().catch(e => { console.error(e); process.exit(1); });
