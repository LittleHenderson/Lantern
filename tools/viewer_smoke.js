// Viewer smoke test: screenshots the report at desktop and phone sizes and fails on JS errors.
// Usage: node tools/viewer_smoke.js path/to/report.html /tmp/shot   (needs `npm i playwright`)
const { chromium } = require('playwright');
(async () => {
  const [file, outPrefix] = process.argv.slice(2);
  const b = await chromium.launch();
  const errs = [];
  for (const [name, vp] of [['desk', {width: 1440, height: 900}], ['phone', {width: 390, height: 844}]]) {
    const p = await b.newPage({viewport: vp, deviceScaleFactor: 1});
    p.on('pageerror', e => errs.push(name + ': ' + e.message));
    p.on('console', m => { if (m.type() === 'error') errs.push(name + ' console: ' + m.text()); });
    await p.goto('file://' + file);
    await p.waitForTimeout(300);
    // open the tree fully and select UserRepo.get
    await p.click('#expand');
    await p.waitForTimeout(100);
    await p.screenshot({path: `${outPrefix}-${name}-1.png`, fullPage: false});
    await p.click('.node:has-text("Session.login")'); await p.waitForTimeout(100);
    if (name === 'phone') { await p.click('#close'); await p.waitForTimeout(250); }
    await p.click('.node:has-text("UserRepo.get")'); await p.waitForTimeout(150);
    await p.click('.lenses button[data-l="3"]'); await p.waitForTimeout(100);
    await p.click('.pair >> nth=1'); await p.waitForTimeout(100);
    await p.screenshot({path: `${outPrefix}-${name}-2.png`});
    if (name === 'desk') {
      await p.click('.seg button[data-v="chart"]'); await p.waitForTimeout(150);
      await p.screenshot({path: `${outPrefix}-${name}-3.png`});
      await p.click('#tabs button[data-t="findings"]'); await p.waitForTimeout(150);
      await p.screenshot({path: `${outPrefix}-${name}-4.png`});
    }
    await p.close();
  }
  console.log(errs.length ? errs.join('\n') : 'no JS errors');
  if (errs.length) process.exitCode = 1;
  await b.close();
})();
