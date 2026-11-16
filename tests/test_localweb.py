"""What a browser keeps for a site, read from the code: a login a server for this computer only puts in a cookie
(`LW-LOOPBACK-COOKIE`), and a service worker that puts aside every page it fetches (`LW-SW-KEEPS-PAGES`). Each
dangerous example stands beside safe twins and look-alikes that must stay quiet."""
from lantern.engine import build_graph
from lantern.security import scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _named(root, rule):
    g = build_graph(root)
    return sorted((f["file"], f["line"], f["snippet"]) for f in scan(g)["findings"] if f["rule"] == rule)


# ------------------------------------------------------------------ a login in a cookie, on this computer only

VIEWER_PY = '''"""A small viewer for this computer."""
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = secrets.token_urlsafe(32)


class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/?key=" + KEY:
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"viewer_session={KEY}; HttpOnly; SameSite=Strict; Path=/")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()


def serve(host: str = "127.0.0.1", port: int = 8700):
    ThreadingHTTPServer((host, port), Page).serve_forever()
'''

BOARD_PY = '''from flask import Flask, make_response

app = Flask(__name__)
TOKEN = "made-at-start"


@app.get("/open")
def open_board():
    resp = make_response("ok")
    resp.set_cookie("auth_token", TOKEN, httponly=True)
    return resp


def main():
    app.run(host="localhost", port=5123)
'''

TOOL_CLI = '''import uvicorn

from .web import app


def start(port: int = 8000):
    uvicorn.run(app, host="127.0.0.1", port=port)
'''

TOOL_WEB = '''from fastapi import FastAPI, Response

app = FastAPI()


@app.get("/enter")
def enter(response: Response):
    sid = "made-for-this-run"
    response.set_cookie(key="session_id", value=sid)
    return {"ok": True}
'''

DESK_JS = '''const express = require('express');
const app = express();

app.get('/open', (req, res) => {
  res.cookie('sid', makeId(), { httpOnly: true });
  res.redirect('/');
});

app.listen(4310, '127.0.0.1');
'''

NOTES_PY = '''from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = make_key()


@app.post("/enter")
def enter():
    session["user"] = request.form["name"]
    return redirect("/")


def main():
    app.run(host="127.0.0.1", port=5200)
'''

KIOSK_JS = '''const express = require('express');
const session = require('express-session');
const app = express();
app.use(session({ secret: makeSecret(), resave: false, saveUninitialized: false }));
app.post('/enter', (req, res) => {
  req.session.userId = lookUp(req.body.name);
  res.redirect('/');
});
app.listen({ port: 4400, host: '127.0.0.1' });
'''

PANEL_JS = '''const http = require('http');
const HOST = 'localhost';

http.createServer((req, res) => {
  res.setHeader('Set-Cookie', `tool_token=${token}; HttpOnly`);
  res.end('ok');
}).listen(8123, HOST);
'''


def test_a_login_cookie_on_a_server_for_this_computer_only_is_named(tmp_path):
    """A browser keeps cookies by host name and not by port, so a cookie that a server on this computer's own
    address sets goes to every other program that serves pages on this computer. Seven shapes: Python's own server
    with a host that is this computer by default, a Flask tool started from a function, a server started in one
    file with the cookie set in the file beside it, Express, Node's own server with the host under a name, and the
    framework's own session (which it keeps in a cookie) in Flask and in Express."""
    _write(tmp_path, {
        "viewer/serve.py": VIEWER_PY,
        "board/app.py": BOARD_PY,
        "tool/__init__.py": "", "tool/cli.py": TOOL_CLI, "tool/web.py": TOOL_WEB,
        "desk/package.json": '{"dependencies": {"express": "^4.19.0"}}', "desk/server.js": DESK_JS,
        "panel/server.js": PANEL_JS, "notes/app.py": NOTES_PY,
        "kiosk/package.json": '{"dependencies": {"express": "^4.19.0", "express-session": "^1.18.0"}}',
        "kiosk/server.js": KIOSK_JS,
    })
    assert _named(tmp_path, "LW-LOOPBACK-COOKIE") == [
        ("board/app.py", 10, 'resp.set_cookie("auth_token", TOKEN, httponly=True)'),
        ("desk/server.js", 5, "res.cookie('sid', makeId(), { httpOnly: true });"),
        ("kiosk/server.js", 6, "req.session.userId = lookUp(req.body.name);"),
        ("notes/app.py", 9, 'session["user"] = request.form["name"]'),
        ("panel/server.js", 5, "res.setHeader('Set-Cookie', `tool_token=${token}; HttpOnly`);"),
        ("tool/web.py", 9, 'response.set_cookie(key="session_id", value=sid)'),
        ("viewer/serve.py", 13,
         'self.send_header("Set-Cookie", f"viewer_session={KEY}; HttpOnly; SameSite=Strict; Path=/")'),
    ]
    g = build_graph(tmp_path)
    found = {f["file"]: f for f in scan(g)["findings"] if f["rule"] == "LW-LOOPBACK-COOKIE"}
    one = found["viewer/serve.py"]
    assert one["tool_confidence"] == "LOW" and one["rank"] == "medium" and one["cwe"] == 287
    assert "`viewer_session`" in one["title"] and "Heuristic" in one["more_info"]
    assert "viewer/serve.py, line 21" in one["more_info"] and "by port" in one["more_info"]
    assert "tool/cli.py, line 7" in found["tool/web.py"]["more_info"]
    story = one["scenario"]
    assert "another program on the same computer" in " ".join(story["steps"]), story
    assert "heuristic" in story["harm"]
    assert "KEY" not in one["title"] and "made-for-this-run" not in str(found["tool/web.py"])


KEYED_PY = '''"""The same viewer, with the key sent by the page in a header: nothing for the browser to hand on."""
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = "made-at-start"


class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        # an older version did: self.send_header("Set-Cookie", f"viewer_session={KEY}; HttpOnly")
        if not hmac.compare_digest(self.headers.get("X-Viewer-Key") or "", KEY):
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Set-Cookie", "theme=dark; Path=/")
        self.send_header("Set-Cookie", f"csrf_token={KEY[:4]}; Path=/")
        self.end_headers()


def serve(host: str = "127.0.0.1", port: int = 8700):
    ThreadingHTTPServer((host, port), Page).serve_forever()
'''

SITE_PY = '''from flask import Flask, make_response

app = Flask(__name__)


@app.post("/login")
def login():
    resp = make_response("ok")
    resp.set_cookie("session", new_session(), httponly=True, secure=True)
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
'''

HOSTED_PY = '''import os

import uvicorn
from fastapi import FastAPI, Response

app = FastAPI()


@app.post("/login")
def login(response: Response):
    response.set_cookie("session_id", make())
    return {"ok": True}


def main():
    uvicorn.run(app, host=os.environ.get("HOST", "0.0.0.0"), port=8000)


def also():
    uvicorn.run(app, host="0.0.0.0", port=8001)
'''

SHOP_JS = '''const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  res.cookie('session', makeId(), { httpOnly: true, secure: true });
  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000);
'''

DEV_PY = '''from http.server import HTTPServer, SimpleHTTPRequestHandler


def preview():
    HTTPServer(("127.0.0.1", 9000), SimpleHTTPRequestHandler).serve_forever()
'''

ELSEWHERE_PY = '''from flask import Flask, make_response

app = Flask(__name__)


@app.post("/login")
def login():
    resp = make_response("ok")
    resp.set_cookie("session", new_session())
    return resp
'''


BASKET_PY = '''from flask import Flask, flash, redirect, request, session

app = Flask(__name__)
app.secret_key = make_key()


@app.post("/add")
def add():
    session["basket"] = session.get("basket", []) + [request.form["item"]]
    session["_flashes"] = [("message", "added")]
    flash("added")
    return redirect("/")


def main():
    app.run(host="127.0.0.1", port=5300)
'''

LOOKS_JS = '''const express = require('express');
const app = express();

app.post('/looks', (req, res) => {
  req.session.theme = req.body.theme;
  req.session.lastPage = req.body.page;
  res.redirect('/');
});

app.listen(5400, '127.0.0.1');
'''


def test_the_safe_twins_of_a_login_cookie_stay_quiet(tmp_path):
    """No finding for: a server on this computer that takes its key in a header (a cookie that is no login, a
    comment that names the older way); a website whose only start on this computer's address is its own trial run
    under `__main__` with debug on; a server started on every address, or on the address a setting names; Express
    with no host written; a start-up file and a cookie that are in different folders; test code; and a
    server on this computer whose session keeps only what says nothing of who is signed in (a basket, the
    framework's own messages, a colour theme: the one false alarm of the first measurement)."""
    _write(tmp_path, {
        "viewer/serve.py": KEYED_PY,
        "site/app.py": SITE_PY,
        "hosted/app.py": HOSTED_PY,
        "shop/package.json": '{"dependencies": {"express": "^4.19.0"}}', "shop/server.js": SHOP_JS,
        "tools/preview.py": DEV_PY, "web/app.py": ELSEWHERE_PY,
        "tests/test_viewer.py": VIEWER_PY, "viewer/tests/helper_server.py": VIEWER_PY,
        "basket/app.py": BASKET_PY,
        "looks/package.json": '{"dependencies": {"express": "^4.19.0"}}', "looks/server.js": LOOKS_JS,
    })
    assert _named(tmp_path, "LW-LOOPBACK-COOKIE") == []


# ------------------------------------------------------------------ a service worker that keeps every page

ACCOUNT_JS = '''const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  res.cookie('session', makeId(), { httpOnly: true, secure: true });
  res.json({ ok: true });
});
app.get('/account', (req, res) => res.send(pageFor(req.cookies.session)));

app.listen(process.env.PORT || 3000);
'''

KEEPS_ALL = '''const NAME = 'app-v1';
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request).then(response => {
      const copy = response.clone();
      caches.open(NAME).then(cache => cache.put(event.request, copy));
      return response;
    }).catch(() => caches.match(event.request))
  );
});
'''

KEEPS_ASYNC = '''self.addEventListener('fetch', (e) => {
  const { request } = e;
  if (new URL(request.url).pathname.startsWith('/api/')) return;
  e.respondWith((async () => {
    const cache = await caches.open('pages');
    const hit = await cache.match(request);
    if (hit) return hit;
    const fresh = await fetch(request);
    cache.put(request, fresh.clone());
    return fresh;
  })());
});
'''

KEEPS_ADD = '''self.addEventListener("fetch", function (evt) {
  evt.respondWith(caches.match(evt.request).then(function (hit) {
    if (hit) return hit;
    return caches.open("v3").then(function (c) {
      return c.add(evt.request).then(function () { return c.match(evt.request); });
    });
  }));
});
'''

KEEPS_BY_HELPER = '''async function networkFirst(request) {
  const cache = await caches.open('runtime');
  try {
    const fresh = await fetch(request);
    cache.put(request, fresh.clone());
    return fresh;
  } catch (err) {
    return cache.match(request);
  }
}

self.addEventListener('fetch', event => {
  event.respondWith(networkFirst(event.request));
});
'''

HELPER_FOR_FILES = '''async function keep(request) {
  const cache = await caches.open('files');
  const fresh = await fetch(request);
  cache.put(request, fresh.clone());
  return fresh;
}

self.addEventListener('fetch', event => {
  const kind = event.request.destination;
  if (kind === 'script' || kind === 'style') event.respondWith(keep(event.request));
});
'''

FIXED_ONLY = '''const NAME = 'shell-v1';
const FIXED = ['/icon.svg', '/manifest.webmanifest'];
self.addEventListener('install', e => e.waitUntil(caches.open(NAME).then(c => c.addAll(FIXED))));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (FIXED.includes(u.pathname)) e.respondWith(caches.match(u.pathname).then(r => r || fetch(e.request)));
});
'''

BY_KIND = '''self.addEventListener('fetch', event => {
  const kind = event.request.destination;
  if (kind !== 'image' && kind !== 'style' && kind !== 'font') return;
  event.respondWith(caches.open('static').then(cache => cache.match(event.request).then(hit => hit ||
    fetch(event.request).then(r => { cache.put(event.request, r.clone()); return r; }))));
});
'''

BY_ENDING = '''self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (!/\\.(?:css|js|png|svg|woff2)$/.test(url.pathname)) return;
  event.respondWith(fetch(event.request).then(r => {
    const copy = r.clone();
    caches.open('files').then(cache => cache.put(event.request, copy));
    return r;
  }));
});
'''

BY_LIST = '''const KEEP = new Set(['/', '/about', '/prices']);
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (!KEEP.has(url.pathname)) return;
  event.respondWith(fetch(event.request).then(r => {
    const copy = r.clone();
    caches.open('public').then(cache => cache.put(event.request, copy));
    return r;
  }));
});
'''

BY_FOLDER = '''self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (!url.pathname.startsWith('/static/')) return;
  event.respondWith(fetch(event.request).then(r => {
    const copy = r.clone();
    caches.open('static').then(cache => cache.put(event.request, copy));
    return r;
  }));
});
'''

PAGE_CODE = '''export async function saveForLater(address) {
  const cache = await caches.open('saved-by-the-reader');
  const answer = await fetch(address);
  await cache.put(address, answer);
}
'''

ONLY_WRITTEN_ABOUT = '''// an older version did: caches.open(NAME).then(cache => cache.put(event.request, copy));
self.addEventListener('fetch', event => {
  event.respondWith(fetch(event.request));
});
'''


def test_a_service_worker_that_keeps_every_page_of_a_site_with_a_login_is_named(tmp_path):
    """Four shapes of the same thing: the answer of every GET put aside on the way through, the same with
    `await` and the request under a name of its own (leaving `/api/` out leaves the pages in), `cache.add` of the
    request, and a function of the file that the handler hands the request to."""
    _write(tmp_path, {
        "package.json": '{"dependencies": {"express": "^4.19.0"}}', "server.js": ACCOUNT_JS,
        "public/sw.js": KEEPS_ALL, "public/app/service-worker.js": KEEPS_ASYNC, "public/old/worker.js": KEEPS_ADD,
        "public/new/sw.js": KEEPS_BY_HELPER,
    })
    assert _named(tmp_path, "LW-SW-KEEPS-PAGES") == [
        ("public/app/service-worker.js", 9, "cache.put(request, fresh.clone());"),
        ("public/new/sw.js", 5, "cache.put(request, fresh.clone());"),
        ("public/old/worker.js", 5, "return c.add(evt.request).then(function () { return c.match(evt.request); });"),
        ("public/sw.js", 7, "caches.open(NAME).then(cache => cache.put(event.request, copy));"),
    ]
    g = build_graph(tmp_path)
    one = next(f for f in scan(g)["findings"] if f["rule"] == "LW-SW-KEEPS-PAGES" and f["file"] == "public/sw.js")
    assert one["tool_confidence"] == "LOW" and one["rank"] == "medium" and one["cwe"] == 525
    assert "Heuristic" in one["more_info"] and "signed out" in one["more_info"]
    assert "server.js" in one["more_info"]                      # where Lantern saw that the site has a login
    story = one["scenario"]
    assert "same browser" in " ".join(story["steps"]) and "heuristic" in story["harm"], story


def test_the_safe_twins_of_a_service_worker_stay_quiet(tmp_path):
    """No finding for a service worker that keeps a fixed list of files only, one that keeps by kind of file (in
    the handler, or before it hands the request to a function), by the file's ending, by a list of addresses or by a
    folder of static files; for page code that saves one address the reader asked for; for a comment; for test
    code; and for a built file of a library that Lantern does not read."""
    _write(tmp_path, {
        "package.json": '{"dependencies": {"express": "^4.19.0"}}', "server.js": ACCOUNT_JS,
        "public/a/sw.js": FIXED_ONLY, "public/b/sw.js": BY_KIND, "public/c/sw.js": BY_ENDING,
        "public/d/sw.js": BY_LIST, "public/e/sw.js": BY_FOLDER, "public/f/save.js": PAGE_CODE,
        "public/g/sw.js": ONLY_WRITTEN_ABOUT, "tests/sw.js": KEEPS_ALL, "public/__tests__/sw.js": KEEPS_ALL,
        "public/i/sw.js": HELPER_FOR_FILES,
        "public/h/sw.js": "importScripts('workbox-sw.js');\nworkbox.routing.registerRoute(/.*/, "
                          "new workbox.strategies.NetworkFirst());\n" + KEEPS_ALL.replace("cache.put", "void"),
    })
    assert _named(tmp_path, "LW-SW-KEEPS-PAGES") == []


def test_a_site_with_no_login_may_keep_its_pages(tmp_path):
    """The same service worker on a site where Lantern sees no login: the pages are everybody's, nothing is said."""
    _write(tmp_path, {
        "index.html": "<!doctype html><title>Notes on birds</title><script src=\"app.js\"></script>\n",
        "app.js": "navigator.serviceWorker.register('/sw.js');\ndocument.title = 'Birds';\n",
        "sw.js": KEEPS_ALL,
    })
    assert _named(tmp_path, "LW-SW-KEEPS-PAGES") == []


def test_both_checks_read_hostile_files_in_bounded_time(tmp_path):
    """Files built to make a pattern go back and forth: long runs of brackets, quotes and half-written calls."""
    import time

    from lantern import localweb
    hostile_py = ("HTTPServer((" * 4000 + "\n" + "x.set_cookie(" * 4000 + "\n" + 'host = "127.0.0.1"\n'
                  + "app.run(" + "host=" * 6000 + "\n" + '"Set-Cookie", ' * 3000 + "\n")
    hostile_js = ("self.addEventListener('fetch', e => {" * 2000 + "\n" + "cache.put(" * 5000 + "\n"
                  + ".listen(" * 5000 + "'" * 9001 + "\n" + "res.cookie(" * 4000 + "\n")
    _write(tmp_path, {"a/serve.py": hostile_py, "b/sw.js": hostile_js, "b/server.js": hostile_js,
                      "b/login.js": "res.cookie('session', id);\n"})
    t = time.perf_counter()
    g = build_graph(tmp_path)
    localweb.loopback_cookies(tmp_path)
    localweb.keeps_pages(tmp_path)
    assert time.perf_counter() - t < 30
    assert g is not None
