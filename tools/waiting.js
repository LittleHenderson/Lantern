// What a browser check waits for when a card fills in later.
//
// The website's screenshot card shows one line while Lantern's server reads the picture and another when the answer
// is there. Until 2026-11-13 the check (tools/cloud_site_smoke.js) waited for three wordings of a good answer and
// for nothing else: any other answer (the server refusing the picture, a request that failed) left it waiting its
// whole 90 seconds, and then it said only that it had timed out. Now it waits for any answer, and one that is no
// reading is said at once, in the card's own words. Checked without a browser by tests/test_smoke_waits.py.
const WAITING = 'reading the text…';   // what the card shows until the answer is there (askAttach in the website's page)

// What the card's line says about the reading: `done` once it holds an answer, `ok` when that answer is a reading
// or the server saying that it reads no pictures (a computer without Tesseract), `said` the line itself.
function shotAnswer(text) {
  const said = String(text == null ? '' : text).trim();
  if (!said || said === WAITING) return { done: false, ok: false, said };
  return { done: true, ok: /text found|cannot read|text not read/.test(said), said };
}

// Ask `read()` for the card's line until it holds an answer or `timeout` milliseconds have passed.
async function settled(read, timeout, sleep, now = Date.now) {
  const end = now() + timeout;
  for (;;) {
    const a = shotAnswer(await read());
    if (a.done || now() > end) return a;
    await sleep(200);
  }
}

// The line for the check's list of errors, or '' when the screenshot was read.
function shotProblem(a, timeout) {
  if (a.done && a.ok) return '';
  if (a.done) return `the screenshot was not read: its card says "${a.said}"`;
  return `the screenshot's card still said "${a.said || 'nothing'}" after ${Math.round(timeout / 1000)} seconds`;
}

module.exports = { WAITING, shotAnswer, settled, shotProblem };
