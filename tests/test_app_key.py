"""The local app's key (`lantern serve`): where it is kept, what opens with it, and what the browser keeps.

A browser sends a cookie to every server on a computer, whatever its port, so a key kept in a cookie reaches any other
program that serves a page on that computer. The key therefore lives only in the page (the browser keeps a page's own
storage apart by port) and is sent with each request; a file the browser opens by its address (a report in a frame)
takes a pass that works once. The service worker keeps nothing but the two fixed files of the app. Each dangerous
case here stands beside the case that must keep working."""
from __future__ import annotations

import http.cookiejar
import json
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from lantern import server
from lantern.server import App, Handler, Store

VIEWER = Path(server.__file__).parent / "viewer"       # the package in use (a release's tests run on the installed one)
KEY = "k" * 32


@pytest.fixture
def app(tmp_path):
    store = Store(tmp_path / "home")
    store.root.mkdir()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    Handler.app = App(store, KEY, port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", store
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def other():
    """Another program on this computer that serves pages on a port of its own and writes down what it is sent."""
    seen = []

    class Other(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append({k: v for k, v in self.headers.items()})
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", seen
    httpd.shutdown()
    httpd.server_close()


class _Stay(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def ask(base, path, method="GET", body=None, headers=None):
    """(status, headers, text) of one request, as sent: no cookie, no key, nothing followed."""
    req = urllib.request.Request(base + path, method=method, headers=headers or {},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), _Stay).open(req, timeout=20) as r:
            return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")


def _a_project_with_a_badge(store, tmp_path):
    repo = tmp_path / "proj"
    repo.mkdir()
    p = store.add_project(repo)
    out = Handler.app.out(p)
    out.mkdir(parents=True, exist_ok=True)
    (out / "readiness.json").write_text(json.dumps({"score": 91, "grade": "A"}), encoding="utf-8")
    return p


def test_another_program_on_this_computer_is_sent_nothing_that_opens_the_app(app, other):
    base, _ = app
    there, seen = other
    jar = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
    for link in (f"{base}/?token={KEY}", f"{base}/"):          # the link in its older form, then the app's page
        with browser.open(link, timeout=20) as r:
            assert r.status == 200
    assert not list(jar), [c.name for c in jar]                 # nothing a browser would send on to another port
    with browser.open(there + "/a-page", timeout=20) as r:      # the same browser visits the other program
        r.read()
    assert "cookie" not in {k.lower() for k in seen[-1]} and KEY not in json.dumps(seen[-1])
    # the way in that a cookie used to be is closed, for reading and for changing
    cookie = {"Cookie": f"lantern_token={KEY}"}
    assert ask(base, "/api/state", headers=cookie)[0] == 403
    assert ask(base, "/api/settings", "POST", {}, headers=cookie)[0] == 403
    # the twin: the page that holds the key sends it with each request, and that opens the app
    assert ask(base, "/api/state", headers={"X-Lantern-Token": KEY})[0] == 200
    assert ask(base, "/api/state", headers={"X-Lantern-Token": "k" * 31 + "x"})[0] == 403


def test_the_apps_page_holds_no_key_and_the_link_hands_the_key_to_the_page_only(app):
    base, _ = app
    code, headers, page = ask(base, "/")
    assert code == 200 and "<title>Lantern</title>" in page
    assert KEY not in page and "__LANTERN_TOKEN__" not in page and headers.get("Set-Cookie") is None
    assert headers["Cache-Control"] == "no-store"
    # the link's older form is sent on to the same page with the key after the "#": that part of an address stays in
    # the browser, which sends it to no server
    code, headers, _ = ask(base, f"/?token={KEY}")
    assert code == 303 and headers["Location"] == f"/#token={KEY}" and headers.get("Set-Cookie") is None
    # a wrong key in a link is turned away as before, and so is one that is no text a key can be
    assert ask(base, "/?token=wrong")[0] == 403
    assert ask(base, "/?token=%C3%A9")[0] == 403
    # the page reads the key from the address, keeps it in its own storage and takes it out of the address bar
    js = (VIEWER / "app.html").read_text(encoding="utf-8")
    assert "location.hash" in js and "history.replaceState" in js and "'lantern.k'" in js
    # the report's own requests carry the key too (they used to count on the cookie)
    for line in (VIEWER / "report.html").read_text(encoding="utf-8").splitlines():
        if "fetch(" in line and ("'/api/" in line or "LIVE.api" in line):
            assert "X-Lantern-Token" in line or "liveHeaders" in line, line.strip()[:160]


def test_a_file_opened_by_its_address_takes_a_pass_that_works_once(app, tmp_path):
    base, store = app
    p = _a_project_with_a_badge(store, tmp_path)
    file, key = f"/p/{p['id']}/badge.svg", {"X-Lantern-Token": KEY}
    assert ask(base, file)[0] == 403                                             # by its address alone: no
    assert ask(base, file, headers={"Cookie": f"lantern_token={KEY}"})[0] == 403
    assert ask(base, file + "?k=" + "x" * 43)[0] == 403                          # a pass nobody made

    def a_pass(path=file):
        code, _, got = ask(base, "/api/view", "POST", {"path": path}, headers=key)
        assert code == 200, got
        url = json.loads(got)["url"]
        assert re.fullmatch(re.escape(path) + r"\?k=[A-Za-z0-9_-]{40,}", url), url
        return url

    url = a_pass()
    code, headers, body = ask(base, url)
    assert code == 200 and "<svg" in body and headers.get("Set-Cookie") is None  # once
    assert ask(base, url)[0] == 403                                              # not twice
    # a pass is for one file: shown at another file it opens nothing, and it is used up by the try
    url = a_pass()
    assert ask(base, f"/p/{p['id']}/evidence.json?k=" + url.split("?k=")[1])[0] == 403
    assert ask(base, url)[0] == 403
    # a pass runs out
    url = a_pass()
    for k, (path, _until) in list(Handler.app.passes.items()):
        Handler.app.passes[k] = (path, 0.0)
    assert ask(base, url)[0] == 403
    # only whoever holds the key gets a pass, and only for a result file of a project the app has
    assert ask(base, "/api/view", "POST", {"path": file})[0] == 403
    assert ask(base, "/api/view", "POST", {"path": file}, headers={"Cookie": f"lantern_token={KEY}"})[0] == 403
    for bad in ("/", "/api/state", f"/p/{p['id']}/../../etc", f"/p/{p['id']}/report.htm", "/p/nobody/report.html", 7, None):
        assert ask(base, "/api/view", "POST", {"path": bad}, headers=key)[0] in (400, 404), bad
    # the twin: the page's own requests, which carry the key, read the same file with no pass
    assert ask(base, file, headers=key)[0] == 200
    # passes do not pile up: old ones go when new ones are made
    for _ in range(300):
        a_pass()
    assert len(Handler.app.passes) <= 64


def test_the_app_is_used_under_the_address_it_listens_on(app):
    """`localhost` is a name, and another program may answer for it at the same port on the computer's other own
    address. The app's page (and so the key it keeps) is only ever at the address the app itself listens on."""
    base, _ = app
    port = base.rsplit(":", 1)[1]
    code, headers, _ = ask(base, "/", headers={"Host": f"localhost:{port}"})
    assert code == 307 and headers["Location"] == f"http://127.0.0.1:{port}/"
    code, headers, _ = ask(base, f"/?token={KEY}", headers={"Host": f"localhost:{port}"})
    assert code == 307 and headers["Location"] == f"http://127.0.0.1:{port}/#token={KEY}"
    # a wrong key gets the page that says the app is locked, under either name, and is sent nowhere
    code, headers, text = ask(base, "/?token=wrong&next=//elsewhere.example", headers={"Host": f"localhost:{port}"})
    assert code == 403 and headers["Location"] is None and KEY not in text and "elsewhere" not in text
    # the twins: under its own address the page is served; requests that carry the key work under either name; an app
    # that listens on another address than this computer's own sends nobody anywhere
    assert ask(base, "/")[0] == 200
    assert ask(base, "/api/state", headers={"Host": f"localhost:{port}", "X-Lantern-Token": KEY})[0] == 200
    Handler.app.own_address = ""
    assert ask(base, "/", headers={"Host": f"localhost:{port}"})[0] == 200


SW_HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8');
const AT = 'http://127.0.0.1:8765';
class Response {
  constructor(body, init) { this.body = String(body); this.status = (init || {}).status || 200; this.ok = this.status < 400; }
  clone() { return this; }
}
// what an earlier version of the worker left behind in this browser
const stores = {'lantern-v2': new Map([[AT + '/p/abc/report.html', new Response('an old report')], [AT + '/', new Response('the old page')]])};
const puts = [];
const urlOf = req => typeof req === 'string' ? new URL(req, AT).href : req.url;
const cacheOf = name => {
  const m = stores[name] = stores[name] || new Map();
  const keep = (req, res) => { puts.push(urlOf(req)); m.set(urlOf(req), res); };
  return {put: async (req, res) => keep(req, res), add: async u => keep(u, new Response('kept ' + u)),
          addAll: async list => list.forEach(u => keep(u, new Response('kept ' + u))), match: async req => m.get(urlOf(req))};
};
const caches = {open: async n => cacheOf(n), keys: async () => Object.keys(stores), delete: async n => delete stores[n],
  match: async req => { for (const m of Object.values(stores)) if (m.has(urlOf(req))) return m.get(urlOf(req)); }};
const handlers = {};
let online = true;
const self = {addEventListener: (t, f) => { handlers[t] = f; }, skipWaiting: async () => {}, clients: {claim: async () => {}}};
const fetch = async req => { if (!online) throw new Error('offline'); return new Response('live ' + urlOf(req)); };
vm.runInNewContext(src, {self, caches, location: new URL(AT + '/sw.js'), URL, Response, Promise, fetch});
const fire = async (type, ev) => {
  const waits = []; let answer;
  ev.waitUntil = p => waits.push(p); ev.respondWith = p => { answer = p; };
  if (handlers[type]) handlers[type](ev);
  await Promise.all(waits);
  const got = answer === undefined ? undefined : await answer;
  await new Promise(done => setTimeout(done, 5));       // let a copy that is put aside afterwards land
  return got;
};
const get = async (path, mode) => {
  const r = await fire('fetch', {request: {url: AT + path, method: 'GET', mode}});
  return r === undefined ? 'left to the browser' : r.status + ' ' + r.body;
};
(async () => {
  await fire('install', {});
  await fire('activate', {});
  const out = {after_activate: Object.keys(stores), online: {}, offline: {}};
  const pages = ['/', '/p/abc/report.html', '/p/abc/evidence.html', '/p/abc/report.html?k=a-pass', '/guide'];
  const files = ['/api/state', '/p/abc/evidence.json', '/icon.svg', '/manifest.webmanifest'];
  for (const p of pages) out.online[p] = await get(p, 'navigate');
  for (const p of files) out.online[p] = await get(p, 'cors');
  online = false;
  for (const p of pages) out.offline[p] = await get(p, 'navigate');
  for (const p of files) out.offline[p] = await get(p, 'cors');
  out.puts = puts;
  out.kept = {};
  for (const [n, m] of Object.entries(stores)) out.kept[n] = [...m.keys()];
  console.log(JSON.stringify(out));
})();
"""


def test_the_browser_keeps_no_copy_of_a_page_or_a_report(tmp_path):
    """The worker used to put aside a copy of every page it fetched, the reports with the project's source among
    them, under the address `127.0.0.1:<port>`: whatever program serves a page at that address later can read them.
    Run with Node against a stand-in for the browser's store: what it holds after pages were opened, and offline."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    harness = tmp_path / "harness.js"
    harness.write_text(SW_HARNESS, encoding="utf-8")
    r = subprocess.run([node, str(harness), str(VIEWER / "sw.js")], capture_output=True, text=True, encoding="utf-8",
                       timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    got = json.loads(r.stdout)
    fixed = {"http://127.0.0.1:8765/icon.svg", "http://127.0.0.1:8765/manifest.webmanifest"}
    # what an earlier version kept is deleted when this one takes over, and one store is left
    assert len(got["after_activate"]) == 1 and "lantern-v2" not in got["after_activate"], got["after_activate"]
    # nothing but the two fixed files is ever put aside
    assert set(got["puts"]) <= fixed, got["puts"]
    assert {u for kept in got["kept"].values() for u in kept} == fixed, got["kept"]
    # with the app stopped, a page says so and no report comes back from a store
    for path in ("/", "/p/abc/report.html", "/p/abc/evidence.html"):
        assert got["offline"][path].startswith("503 ") and "lantern serve" in got["offline"][path], (path, got["offline"])
    assert "an old report" not in json.dumps(got) and "the old page" not in json.dumps(got)
    # the twins: with the app running every page comes from the app, and the app's icon is at hand without it
    for path in ("/", "/p/abc/report.html", "/guide"):
        assert got["online"][path] in ("left to the browser", "200 live http://127.0.0.1:8765" + path), got["online"]
    assert got["offline"]["/icon.svg"].startswith("200 ") and got["offline"]["/manifest.webmanifest"].startswith("200 ")
    assert got["online"]["/api/state"] == "left to the browser"


def test_the_start_check_opens_the_app_with_the_key_and_prints_the_link(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    assert server.serve([], port=0, open_browser=False, check=True) == 0
    said = capsys.readouterr().out
    link = re.search(r"http://127\.0\.0\.1:\d+/#token=[A-Za-z0-9_-]{20,}", said)
    assert link and "?token=" not in said and "the app answered" in said, said
