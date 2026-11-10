// A page under test never reaches the internet. Two layers, the second for what the first cannot see, so the smoke
// runs the same with or without a network:
//
//   1. Every request a page makes for an address that is not this computer is answered here, inside the browser
//      (watch). The app, the website and the guide ask the outside for one thing, their font stylesheet (FONTS): it
//      gets an empty one, and the page shows the system fonts, as it does offline. Anything else a page asks for is
//      refused and fails the smoke with the address. A report must ask for nothing at all: it is one self-contained
//      file.
//   2. A browser has more ways out than a page's requests: a connection it opens ahead of time because a page hinted
//      at an address (<link rel="preconnect">, which the app, the guide and the website have for their font host), a
//      page nobody watched, its own housekeeping. So every browser under test is started (launch) with a proxy on
//      this computer as its only way out. The proxy forwards nothing: it answers 403 and keeps what was asked for.
//      A try for a font host is counted and nothing more; any other fails the smoke with the address (close).
//
//   const outside = require('./outside.js');
//   const b = await outside.launch(chromium);                  // in place of chromium.launch()
//   await outside.watch(pageOrContext, errs, outside.FONTS);   // right after the page or context is made
//   console.log(await outside.close(b, errs));                 // in place of b.close(), before errs decides the result
//
//   node tools/outside.js      checks this file itself in a real browser (PW_BROWSER=firefox|webkit for another
//                              engine): the font stylesheet is answered here, a picture and a script from two other
//                              addresses are refused and reported, a page on this computer is left alone, and a page
//                              nobody watched ends at the proxy on this computer.
const net = require('net');

const FONTS = ['fonts.googleapis.com'];
const HERE = ['localhost', '127.0.0.1', '[::1]'];
const asked = { fonts: 0, refused: [], stopped: [], mayTry: new Set() };
let proxyAt = null;

const leaves = u => /^https?:$/.test(u.protocol) && !HERE.includes(u.hostname);

// The only way out a browser under test is given. One for the whole run; it stops with the program.
function proxy() {
  if (!proxyAt) proxyAt = new Promise((ready, failed) => {
    const server = net.createServer(socket => {
      socket.on('error', () => {});
      socket.once('data', data => {
        const [, verb, target] = /^(\S+)\s+(\S+)/.exec(String(data)) || [];   // "CONNECT host:443 HTTP/1.1", "GET http://host/path HTTP/1.1"
        let host = target || '(nothing readable)';
        try { host = verb === 'CONNECT' ? host.replace(/:\d+$/, '') : new URL(host).hostname; } catch (e) { /* kept as it was written */ }
        asked.stopped.push(host);
        socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
      });
    });
    server.on('error', failed);
    server.listen(0, '127.0.0.1', () => { server.unref(); ready(`http://127.0.0.1:${server.address().port}`); });
  });
  return proxyAt;
}

async function launch(browserType, options = {}) {
  return browserType.launch({ ...options, proxy: { server: await proxy(), bypass: 'localhost,127.0.0.1' } });
}

async function watch(target, errs, fonts = []) {
  for (const host of fonts) asked.mayTry.add(host);
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

// What the browser tried past the pages' own requests. A font host the pages were allowed is counted; any other is an error.
function stray(errs) {
  const counts = new Map();
  for (const host of asked.stopped) counts.set(host, (counts.get(host) || 0) + 1);
  for (const [host, n] of counts) {
    if (!asked.mayTry.has(host)) errs.push(`a browser under test tried to reach ${host} (${n} time(s)) past what its pages were watched for; it was stopped at this computer: a page nobody watched, or the browser itself`);
  }
  return counts;
}

function summary(errs = []) {
  const counts = stray(errs);
  const fonts = asked.fonts ? `the pages asked for their font stylesheet ${asked.fonts} time(s), answered inside the browser (nothing was sent)` : 'no page asked for a font stylesheet';
  const refused = asked.refused.length ? `${asked.refused.length} other request(s) refused: ${[...new Set(asked.refused)].join(', ')}` : 'nothing else was asked of the outside';
  const tried = counts.size ? `the browser tried ${asked.stopped.length} connection(s) past that (${[...counts].map(([host, n]) => `${host} x${n}`).join(', ')}), each stopped at this computer` : 'the browser tried nothing past that';
  return `outside: ${fonts}; ${refused}; ${tried}`;
}

// In place of b.close(): what is still on its way to the proxy arrives first, then the count is final.
async function close(browser, errs) {
  await browser.close();
  await new Promise(done => setTimeout(done, 100));
  return summary(errs);
}

module.exports = { FONTS, launch, watch, close, summary };

if (require.main === module) (async () => {
  const http = require('http');
  const engine = process.env.PW_BROWSER || 'chromium';
  const PAGE = '<!doctype html><meta charset="utf-8"><title>t</title>' +
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans">' +
    '<link rel="stylesheet" href="/own.css"><img src="https://pictures.example/a.png" alt=""><p>hello</p>' +
    '<script src="https://scripts.example/x.js"></script>';
  const UNWATCHED = '<!doctype html><meta charset="utf-8"><title>u</title><link rel="preconnect" href="https://hinted.example">' +
    '<link rel="stylesheet" href="/own.css"><img src="http://unwatched.example/a.png" alt=""><p>nobody watches this page</p>';
  let own = 0;
  const server = http.createServer((q, r) => {
    if (q.url === '/own.css') { own++; r.writeHead(200, { 'Content-Type': 'text/css' }); r.end('p{color:#000}'); return; }
    r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(q.url === '/unwatched' ? UNWATCHED : PAGE);
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const at = `http://127.0.0.1:${server.address().port}`;
  const wrong = [];
  // the proxy by itself: whatever it is asked, it answers 403, forwards nothing and keeps the host
  const ask = first => new Promise(done => {
    const s = net.connect(Number(new URL(proxyUrl).port), '127.0.0.1', () => s.write(first + '\r\nHost: x\r\n\r\n'));
    let got = ''; s.on('data', d => { got += d; }); s.on('close', () => done(got)); s.on('error', () => done(got));
  });
  const proxyUrl = await proxy();
  const answers = [await ask('CONNECT tunnel.example:443 HTTP/1.1'), await ask('GET http://plain.example/x HTTP/1.1')];
  if (!answers.every(a => a.startsWith('HTTP/1.1 403')) || asked.stopped.join(' ') !== 'tunnel.example plain.example') wrong.push(`the proxy by itself: ${JSON.stringify({ answers, stopped: asked.stopped })}`);
  asked.stopped.length = 0;
  const b = await launch(require('playwright')[engine]);
  let hint = 'no';
  try {
    // a page that may ask for its fonts: the stylesheet is answered here, the picture and the script are refused
    let errs = [];
    let p = await b.newPage(); await watch(p, errs, FONTS);
    await p.goto(`${at}/`); await p.waitForLoadState('load'); await p.close();
    if (asked.fonts !== 1) wrong.push(`the font stylesheet was answered ${asked.fonts} time(s), not 1`);
    // (sorted: which of the two a browser asks for first is its own business)
    if ([...asked.refused].sort().join(' | ') !== 'https://pictures.example/a.png (image) | https://scripts.example/x.js (script)') wrong.push(`refused: ${asked.refused.join(' | ') || 'nothing'}`);
    if (errs.length !== 2 || !errs.every(e => /font stylesheet and nothing else/.test(e))) wrong.push(`reported: ${JSON.stringify(errs)}`);
    if (own !== 1) wrong.push(`the page's own stylesheet on this computer was fetched ${own} time(s), not 1 (does this browser send this computer's own addresses to its proxy?)`);
    if (asked.stopped.length) wrong.push(`a watched page still got as far as the proxy: ${asked.stopped.join(', ')}`);
    // a report may ask for nothing: the same font stylesheet is refused too
    errs = []; asked.fonts = 0; asked.refused.length = 0; asked.mayTry.clear();
    p = await b.newPage(); await watch(p, errs);
    await p.goto(`${at}/`); await p.waitForLoadState('load'); await p.close();
    if (asked.fonts !== 0 || asked.refused.length !== 3 || errs.length !== 3 || !errs.every(e => /a report must ask for nothing/.test(e))) wrong.push(`for a report: ${JSON.stringify({ asked, errs })}`);
    if (asked.stopped.length) wrong.push(`a watched report still got as far as the proxy: ${asked.stopped.join(', ')}`);
    // the shape that would let a page out, a page nobody watches: it ends at the proxy on this computer, and that
    // fails the smoke. (A connection hint is acted on by some browsers and not by others: said below, not required.)
    errs = []; asked.refused.length = 0;
    p = await b.newPage();
    await p.goto(`${at}/unwatched`); await p.waitForLoadState('load'); await p.waitForTimeout(300); await p.close();
    if (own !== 3) wrong.push(`the unwatched page's own stylesheet was not fetched from this computer (${own} fetches in all, not 3)`);
    if (!asked.stopped.includes('unwatched.example')) wrong.push(`the unwatched page's picture did not end at the proxy: ${asked.stopped.join(', ') || 'nothing arrived'}`);
    if (asked.stopped.some(h => !['unwatched.example', 'hinted.example'].includes(h))) wrong.push(`the browser tried something of its own: ${asked.stopped.join(', ')}`);
    hint = asked.stopped.includes('hinted.example') ? 'yes' : 'no';
    stray(errs);
    if (!errs.some(e => /tried to reach unwatched\.example/.test(e))) wrong.push(`an unwatched page's try was not reported: ${JSON.stringify(errs)}`);
    // a try for a font host the pages were allowed is counted and is not an error
    errs = []; asked.stopped.length = 0; asked.mayTry.add(FONTS[0]);
    await ask(`CONNECT ${FONTS[0]}:443 HTTP/1.1`);
    const line = summary(errs);
    if (errs.length || !line.includes(`${FONTS[0]} x1`)) wrong.push(`a try for the font host: ${JSON.stringify({ errs, line })}`);
  } finally { await b.close(); server.close(); }
  if (wrong.length) { console.error(`outside.js in ${engine}: ` + wrong.join('\n')); process.exit(1); }
  console.log(`outside.js in ${engine}: the font stylesheet is answered inside the browser, a picture and a script from elsewhere are refused and reported, a report may ask for nothing, pages on this computer are left alone, a page nobody watched ends at the proxy on this computer (this browser acts on a connection hint: ${hint})`);
})().catch(e => { console.error(e); process.exit(1); });
