// A page under test never reaches the internet. Two layers, the second for what the first cannot see, so the smoke
// runs the same with or without a network:
//
//   1. Every request a page makes for an address that is not this computer is answered here, inside the browser
//      (watch). The app, the website and the guide ask the outside for one thing, their font stylesheet (FONTS): it
//      gets an empty one, and the page shows the system fonts, as it does offline. Anything else a page asks for is
//      refused and fails the smoke with the address. A report must ask for nothing at all: it is one self-contained
//      file.
//   2. A browser has more ways out than the requests the first layer sees: a connection it opens ahead of time
//      because a page hinted at an address (<link rel="preconnect">, which the app, the guide and the website have
//      for their font host), a page nobody watched, a request the browser does not show the watcher (CI, 2026-11-10:
//      on the website WebKit made 17 font requests the watcher never saw; the check below says for each browser
//      whether that is what a page with a service worker does, which the app and the website are), and the
//      browser's own housekeeping (Firefox asks its maker for a newer Firefox). So every browser under test is
//      started (launch) with a proxy on this computer as its only way out. The proxy forwards nothing: it answers
//      403 and keeps what was asked for. A try for a font host the pages were allowed, or for an address the browser
//      itself is known to ask (OWN), is counted and nothing more; any other fails the smoke with the address
//      (close). Where a page's font request ended at the proxy the browser may say so in the page's console: that
//      line is the count again, not an error of the page (refusedFont).
//
//   const outside = require('./outside.js');
//   const b = await outside.launch(chromium);                  // in place of chromium.launch()
//   await outside.watch(pageOrContext, errs, outside.FONTS);   // right after the page or context is made
//   p.on('console', m => { if (m.type() === 'error' && !outside.refusedFont(m)) errs.push(m.text() + outside.where(m)); });
//   console.log(await outside.close(b, errs));                 // in place of b.close(), before errs decides the result
//
//   node tools/outside.js      checks this file itself in a real browser (PW_BROWSER=firefox|webkit for another
//                              engine): the font stylesheet is answered here, a picture and a script from two other
//                              addresses are refused and reported, a page on this computer is left alone, a page
//                              nobody watched ends at the proxy on this computer, a console line about a refused
//                              font request is told from one about anything else, and it says what this browser
//                              does with the font request of a page a service worker controls.
const net = require('net');

const FONTS = ['fonts.googleapis.com'];
// What a browser asks of its own maker, whatever page is open. Stopped at the proxy like everything else and counted,
// but not held against the pages. An address that is not listed here fails the check, so a new one is seen the day it
// appears. (Seen in CI on 2026-11-10: Firefox asking whether there is a newer Firefox.)
const OWN = { firefox: ['aus5.mozilla.org'] };
const HERE = ['localhost', '127.0.0.1', '[::1]'];
// This computer's own addresses do not go to the proxy. Chromium keeps them out by itself, and Playwright switches
// that off whenever a proxy is given: up to at least 1.48 (the version CI installs) it writes "<-loopback>" after the
// list, where it overrules the two addresses, so on 2026-11-10 CI's Chromium sent the app's own pages to the proxy
// and got its 403 (Playwright 1.63 does not, which is why it passed on a developer's computer). Written first, it
// is the two addresses that overrule it, in both. Firefox and WebKit take the plain list (seen passing in CI).
const BYPASS = { chromium: '<-loopback>,localhost,127.0.0.1' };
const asked = { fonts: 0, refused: [], stopped: [], mayTry: new Set(), own: new Set(), said: 0 };
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
  for (const host of OWN[browserType.name()] || []) asked.own.add(host);
  return browserType.launch({ ...options, proxy: { server: await proxy(), bypass: BYPASS[browserType.name()] || 'localhost,127.0.0.1' } });
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

// Where a console line came from, without what follows a "?" (an address can carry a key there).
function where(message) {
  try { const u = new URL(message.location().url); return ` [${u.origin}${u.pathname}]`; } catch (e) { return ''; }
}

// A page's console line saying that a request for one of its font hosts was refused. The watcher answers such a
// request before the page sees anything; one that went past the watcher ended at the proxy, and this line is the
// browser telling the page so. It is counted (the summary says how many) and is not an error of the page. A line about
// any other address, or about anything other than a failed load, is not one of these.
function refusedFont(message, fonts = FONTS) {
  let host = '';
  try { host = new URL(message.location().url).hostname; } catch (e) { return false; }
  if (message.type() !== 'error' || !fonts.includes(host) || !/^Failed to load resource/.test(message.text())) return false;
  asked.said++;
  return true;
}

// What the browser tried past the requests the watcher saw. A font host the pages were allowed and an address the
// browser itself is known to ask are counted; any other is an error.
function stray(errs) {
  const counts = new Map();
  for (const host of asked.stopped) counts.set(host, (counts.get(host) || 0) + 1);
  for (const [host, n] of counts) {
    if (!asked.mayTry.has(host) && !asked.own.has(host)) errs.push(`a browser under test tried to reach ${host} (${n} time(s)) past what its pages were watched for; it was stopped at this computer: a page nobody watched, or the browser itself (what a browser asks of its own maker is listed in OWN, tools/outside.js)`);
  }
  return counts;
}

function summary(errs = []) {
  const counts = stray(errs);
  const fonts = asked.fonts ? `the pages asked for their font stylesheet ${asked.fonts} time(s), answered inside the browser (nothing was sent)` : 'no page asked for a font stylesheet';
  const refused = asked.refused.length ? `${asked.refused.length} other request(s) refused: ${[...new Set(asked.refused)].join(', ')}` : 'nothing else was asked of the outside';
  const whose = host => asked.own.has(host) ? ', the browser asking its own maker' : asked.mayTry.has(host) ? '' : ', NOT EXPECTED';
  const said = asked.said ? `; ${asked.said} of them the browser reported to the page as a refused font request` : '';
  const tried = counts.size ? `the browser tried ${asked.stopped.length} connection(s) past that (${[...counts].map(([host, n]) => `${host} x${n}${whose(host)}`).join('; ')}), each stopped at this computer${said}` : 'the browser tried nothing past that';
  return `outside: ${fonts}; ${refused}; ${tried}`;
}

// In place of b.close(): what is still on its way to the proxy arrives first, then the count is final.
async function close(browser, errs) {
  await browser.close();
  await new Promise(done => setTimeout(done, 100));
  return summary(errs);
}

module.exports = { FONTS, OWN, BYPASS, launch, watch, close, summary, refusedFont, where };

if (require.main === module) (async () => {
  const http = require('http');
  const engine = process.env.PW_BROWSER || 'chromium';
  const PAGE = '<!doctype html><meta charset="utf-8"><title>t</title>' +
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans">' +
    '<link rel="stylesheet" href="/own.css"><img src="https://pictures.example/a.png" alt=""><p>hello</p>' +
    '<script src="https://scripts.example/x.js"></script>';
  const UNWATCHED = '<!doctype html><meta charset="utf-8"><title>u</title><link rel="preconnect" href="https://hinted.example">' +
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans">' +
    '<link rel="stylesheet" href="/own.css"><img src="http://unwatched.example/a.png" alt=""><p>nobody watches this page</p>';
  // like the app's and the website's: a service worker that leaves a request for another computer to the browser
  const CONTROLLED = '<!doctype html><meta charset="utf-8"><title>s</title>' +
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans"><p>a service worker controls this page</p>' +
    '<script>if (navigator.serviceWorker) navigator.serviceWorker.register("/sw.js").catch(() => {});</script>';
  const WORKER = "self.addEventListener('install', () => self.skipWaiting());" +
    "self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));self.addEventListener('fetch', () => {});";
  let fetched = 0;
  const server = http.createServer((q, r) => {
    if (q.url === '/own.css') { fetched++; r.writeHead(200, { 'Content-Type': 'text/css' }); r.end('p{color:#000}'); return; }
    if (q.url === '/sw.js') { r.writeHead(200, { 'Content-Type': 'text/javascript' }); r.end(WORKER); return; }
    if (q.url === '/controlled') { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(CONTROLLED); return; }
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
  const own = OWN[engine] || [];
  const pages = () => asked.stopped.filter(host => !own.includes(host));   // what reached the proxy, less the browser's own housekeeping
  let hint = 'no', ahead = 'no', told = 'no', shown = 'no service worker took control of the page here';
  try {
    // a page that may ask for its fonts: the stylesheet is answered here, the picture and the script are refused
    let errs = [];
    let p = await b.newPage(); await watch(p, errs, FONTS);
    await p.goto(`${at}/`); await p.waitForLoadState('load'); await p.close();
    if (asked.fonts !== 1) wrong.push(`the font stylesheet was answered ${asked.fonts} time(s), not 1`);
    // (sorted: which of the two a browser asks for first is its own business)
    if ([...asked.refused].sort().join(' | ') !== 'https://pictures.example/a.png (image) | https://scripts.example/x.js (script)') wrong.push(`refused: ${asked.refused.join(' | ') || 'nothing'}`);
    if (errs.length !== 2 || !errs.every(e => /font stylesheet and nothing else/.test(e))) wrong.push(`reported: ${JSON.stringify(errs)}`);
    if (fetched !== 1) wrong.push(`the page's own stylesheet on this computer was fetched ${fetched} time(s), not 1 (does this browser send this computer's own addresses to its proxy?)`);
    // (a browser may open a connection for a request before the watcher has answered it: said below, not required;
    // what is required is that nothing reaches the proxy but the addresses the page itself names)
    if (pages().some(host => !['fonts.googleapis.com', 'pictures.example', 'scripts.example'].includes(host))) wrong.push(`a watched page's browser tried an address the page does not name: ${pages().join(', ')}`);
    if (pages().length) ahead = 'yes';
    // a report may ask for nothing: the same font stylesheet is refused too
    errs = []; asked.fonts = 0; asked.refused.length = 0; asked.mayTry.clear();
    p = await b.newPage(); await watch(p, errs);
    await p.goto(`${at}/`); await p.waitForLoadState('load'); await p.close();
    if (asked.fonts !== 0 || asked.refused.length !== 3 || errs.length !== 3 || !errs.every(e => /a report must ask for nothing/.test(e))) wrong.push(`for a report: ${JSON.stringify({ asked, errs })}`);
    if (pages().some(host => !['fonts.googleapis.com', 'pictures.example', 'scripts.example'].includes(host))) wrong.push(`a watched report's browser tried an address the page does not name: ${pages().join(', ')}`);
    // the shape that would let a page out, a page nobody watches: it ends at the proxy on this computer, and that
    // fails the smoke. (A connection hint is acted on by some browsers and not by others: said below, not required.)
    // Its font stylesheet goes past the watcher too, the way WebKit sends it on a page a service worker controls: where
    // the browser tells the page so in its console, that line is known for what it is, and the picture's line is not.
    errs = []; asked.refused.length = 0; asked.stopped.length = 0; asked.said = 0;
    const lines = [];
    p = await b.newPage();
    p.on('console', m => { if (m.type() === 'error') lines.push({ at: where(m), font: refusedFont(m), load: /^Failed to load resource/.test(m.text()) }); });
    await p.goto(`${at}/unwatched`); await p.waitForLoadState('load'); await p.waitForTimeout(300); await p.close();
    if (fetched !== 3) wrong.push(`the unwatched page's own stylesheet was not fetched from this computer (${fetched} fetches in all, not 3)`);
    if (!asked.stopped.includes('unwatched.example')) wrong.push(`the unwatched page's picture did not end at the proxy: ${asked.stopped.join(', ') || 'nothing arrived'}`);
    if (!asked.stopped.includes('fonts.googleapis.com')) wrong.push(`the unwatched page's font stylesheet did not end at the proxy: ${asked.stopped.join(', ') || 'nothing arrived'}`);
    if (pages().some(h => !['unwatched.example', 'hinted.example', 'fonts.googleapis.com'].includes(h))) wrong.push(`the browser tried something of its own that is not in OWN: ${asked.stopped.join(', ')}`);
    hint = asked.stopped.includes('hinted.example') ? 'yes' : 'no';
    if (lines.some(l => l.font !== (l.load && l.at.startsWith(' [https://fonts.googleapis.com/'))) || asked.said !== lines.filter(l => l.font).length) wrong.push(`console lines about refused requests were told apart wrongly: ${JSON.stringify(lines)}`);
    // (a browser that reports a failed load without saying which address would leave nothing to tell the lines apart by)
    if (lines.some(l => l.load && !l.at)) wrong.push(`this browser reports a failed load in the console without its address: ${JSON.stringify(lines)}`);
    told = `${lines.filter(l => l.font).length} of ${lines.length} console line(s)`;
    stray(errs);
    if (!errs.some(e => /tried to reach unwatched\.example/.test(e))) wrong.push(`an unwatched page's try was not reported: ${JSON.stringify(errs)}`);
    // the same telling apart on lines written out here, so it is checked where a browser says nothing in its console
    const said = (type, text, url) => ({ type: () => type, text: () => text, location: () => ({ url }) });
    const refusal = 'Failed to load resource: the server responded with a status of 403 (Forbidden)';
    asked.said = 0;
    const verdicts = [
      refusedFont(said('error', refusal, 'https://fonts.googleapis.com/css2?family=DM+Sans')),   // the one that is
      refusedFont(said('error', refusal, 'https://pictures.example/a.png')),                    // another address
      refusedFont(said('error', refusal, `${at}/v1/me`)),                                        // this computer's own server saying no
      refusedFont(said('error', 'TypeError: x is not a function', 'https://fonts.googleapis.com/css2')),   // not a failed load
      refusedFont(said('warning', refusal, 'https://fonts.googleapis.com/css2')),               // not an error line
      refusedFont(said('error', refusal, '')),                                                  // no address given
      refusedFont(said('error', refusal, 'https://fonts.googleapis.com/css2'), []),             // a report may ask for nothing
    ];
    if (verdicts.join() !== 'true,false,false,false,false,false,false' || asked.said !== 1) wrong.push(`written-out console lines were told apart wrongly: ${verdicts.join()} (${asked.said} counted)`);
    if (where(said('error', 'x', 'https://host.example/a/b?k=made-up#f')) !== ' [https://host.example/a/b]' || where(said('error', 'x', '')) !== '') wrong.push('where() does not cut an address at its "?"');
    // a page a service worker controls: some browsers do not show the watcher what such a page asks for. Either way
    // its font request ends in this computer (answered by the watcher, or stopped at the proxy, the browser's only
    // way out), and where the browser tells the page about the refusal, that line is known for what it is.
    errs = []; asked.fonts = 0; asked.refused.length = 0; asked.stopped.length = 0; asked.said = 0;
    const ctx = await b.newContext(); await watch(ctx, errs, FONTS);
    p = await ctx.newPage();
    const other = [];
    p.on('console', m => { if (m.type() === 'error' && !refusedFont(m)) other.push(m.text() + where(m)); });
    await p.goto(`${at}/controlled`); await p.waitForLoadState('load');
    if (await p.waitForFunction(() => !!(navigator.serviceWorker && navigator.serviceWorker.controller), null, { timeout: 8000 }).then(() => true, () => false)) {
      const answered = asked.fonts;
      await p.reload(); await p.waitForLoadState('load'); await p.waitForTimeout(300);
      shown = asked.fonts > answered ? 'yes' : pages().includes(FONTS[0]) ? `no, it ended at the proxy (${asked.said} console line(s) told the page)` : 'no, and nothing was asked of the proxy either';
    }
    await ctx.close();
    if (errs.length || other.length || pages().some(host => host !== FONTS[0])) wrong.push(`a page a service worker controls: ${JSON.stringify({ errs, other, stopped: asked.stopped })}`);
    // a try for a font host the pages were allowed is counted and is not an error
    errs = []; asked.stopped.length = 0; asked.said = 0; asked.mayTry.add(FONTS[0]);
    await ask(`CONNECT ${FONTS[0]}:443 HTTP/1.1`);
    let line = summary(errs);
    if (errs.length || !line.includes(`${FONTS[0]} x1`)) wrong.push(`a try for the font host: ${JSON.stringify({ errs, line })}`);
    // so is a try for an address the browser itself is known to ask; one that is not known is an error and is marked
    asked.own.add('maker.example');
    await ask('CONNECT maker.example:443 HTTP/1.1'); await ask('CONNECT stranger.example:443 HTTP/1.1');
    line = summary(errs);
    asked.own.delete('maker.example');
    if (errs.length !== 1 || !/tried to reach stranger\.example/.test(errs[0]) || !line.includes('maker.example x1, the browser asking its own maker') || !line.includes('stranger.example x1, NOT EXPECTED')) wrong.push(`a browser's own address and a stranger's: ${JSON.stringify({ errs, line })}`);
  } finally { await b.close(); server.close(); }
  if (wrong.length) { console.error(`outside.js in ${engine}: ` + wrong.join('\n')); process.exit(1); }
  console.log(`outside.js in ${engine}: the font stylesheet is answered inside the browser, a picture and a script from elsewhere are refused and reported, a report may ask for nothing, pages on this computer are left alone, a page nobody watched ends at the proxy on this computer, a console line about a refused font request is told from any other (this browser acts on a connection hint: ${hint}; opens a connection for a request the watcher answers: ${ahead}; shows the watcher the font request of a page a service worker controls: ${shown}; told the unwatched page about its refused font request in ${told})`);
})().catch(e => { console.error(e); process.exit(1); });
