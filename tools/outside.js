// A page under test never reaches the internet. Every request a page makes for an address that is not this
// computer is answered here, inside the browser, so nothing is sent and the smoke runs the same with or without a
// network. The app, the website and the guide ask the outside for one thing, their font stylesheet (FONTS): it gets
// an empty one, and the page shows the system fonts, as it does offline. Anything else a page asks for is refused
// and fails the smoke with the address. A report must ask for nothing at all: it is one self-contained file.
//
//   const outside = require('./outside.js');
//   await outside.watch(pageOrContext, errs, outside.FONTS);   // right after the page or context is made
//   console.log(outside.summary());                            // at the end
//
//   node tools/outside.js      checks this file itself in a real browser (PW_BROWSER=firefox|webkit for another
//                              engine): the font stylesheet is answered here, a picture and a script from two other
//                              addresses are refused and reported, and a page on this computer is left alone.
const FONTS = ['fonts.googleapis.com'];
const HERE = ['localhost', '127.0.0.1', '[::1]'];
const asked = { fonts: 0, refused: [] };

const leaves = u => /^https?:$/.test(u.protocol) && !HERE.includes(u.hostname);

async function watch(target, errs, fonts = []) {
  await target.route(leaves, route => {
    const request = route.request(), u = new URL(request.url());
    if (fonts.includes(u.hostname) && request.resourceType() === 'stylesheet') {
      asked.fonts++;
      return route.fulfill({ status: 200, contentType: 'text/css', body: '' });
    }
    const what = `${u.origin}${u.pathname} (${request.resourceType()})`;
    asked.refused.push(what);
    errs.push(`a page asked for ${what}: ${fonts.length ? 'these pages may ask the outside for their font stylesheet and nothing else' : 'a report must ask for nothing outside this computer'}`);
    return route.abort();
  });
}

function summary() {
  const fonts = asked.fonts ? `the pages asked for their font stylesheet ${asked.fonts} time(s), answered inside the browser (nothing was sent)` : 'no page asked for a font stylesheet';
  return `outside: ${fonts}; ${asked.refused.length ? `${asked.refused.length} other request(s) refused: ${[...new Set(asked.refused)].join(', ')}` : 'nothing else was asked of the outside'}`;
}

module.exports = { FONTS, watch, summary };

if (require.main === module) (async () => {
  const http = require('http');
  const engine = process.env.PW_BROWSER || 'chromium';
  const PAGE = '<!doctype html><meta charset="utf-8"><title>t</title>' +
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans">' +
    '<link rel="stylesheet" href="/own.css"><img src="https://pictures.example/a.png" alt=""><p>hello</p>' +
    '<script src="https://scripts.example/x.js"></script>';
  let own = 0;
  const server = http.createServer((q, r) => {
    if (q.url === '/own.css') { own++; r.writeHead(200, { 'Content-Type': 'text/css' }); r.end('p{color:#000}'); return; }
    r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(PAGE);
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const b = await require('playwright')[engine].launch();
  const wrong = [];
  try {
    // a page that may ask for its fonts: the stylesheet is answered here, the picture and the script are refused
    let errs = [];
    let p = await b.newPage(); await watch(p, errs, FONTS);
    await p.goto(`http://127.0.0.1:${server.address().port}/`); await p.waitForLoadState('load'); await p.close();
    if (asked.fonts !== 1) wrong.push(`the font stylesheet was answered ${asked.fonts} time(s), not 1`);
    // (sorted: which of the two a browser asks for first is its own business)
    if ([...asked.refused].sort().join(' | ') !== 'https://pictures.example/a.png (image) | https://scripts.example/x.js (script)') wrong.push(`refused: ${asked.refused.join(' | ') || 'nothing'}`);
    if (errs.length !== 2 || !errs.every(e => /font stylesheet and nothing else/.test(e))) wrong.push(`reported: ${JSON.stringify(errs)}`);
    if (own !== 1) wrong.push(`the page's own stylesheet on this computer was fetched ${own} time(s), not 1`);
    // a report may ask for nothing: the same font stylesheet is refused too
    errs = []; asked.fonts = 0; asked.refused.length = 0;
    p = await b.newPage(); await watch(p, errs);
    await p.goto(`http://127.0.0.1:${server.address().port}/`); await p.waitForLoadState('load'); await p.close();
    if (asked.fonts !== 0 || asked.refused.length !== 3 || errs.length !== 3 || !errs.every(e => /a report must ask for nothing/.test(e))) wrong.push(`for a report: ${JSON.stringify({ asked, errs })}`);
  } finally { await b.close(); server.close(); }
  if (wrong.length) { console.error(`outside.js in ${engine}: ` + wrong.join('\n')); process.exit(1); }
  console.log(`outside.js in ${engine}: the font stylesheet is answered inside the browser, a picture and a script from elsewhere are refused and reported, a report may ask for nothing, pages on this computer are left alone`);
})().catch(e => { console.error(e); process.exit(1); });
