"""Security headers: "in place" only where the code shows them set for every response (2026-11-12).

Until then the card read "in place" when one of a few words stood anywhere in the code. On a real static site it did
so for two reasons, neither of which sends a header: one exported document carried its own
`<meta http-equiv="Content-Security-Policy">`, and the word "helmet" stood in a search pattern as the name of an HTML
tag. The site was served with no security header at all.

Each case that must not read "in place" stands beside the same app with the headers really set for every response.
None of the examples is copied from that site."""

import subprocess
import sys

import pytest

from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _headers(root):
    g = build_graph(root)
    prot = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}
    assert "security-headers" in prot, sorted(prot)
    return prot["security-headers"]


PAGE = ("<!doctype html><html><head><title>Shelf</title><script src=\"app.js\"></script></head>"
        "<body><main id=\"out\"></main><script>function start() { draw(); }\nstart();</script></body></html>\n")
STATIC = {"index.html": PAGE,
          "app.js": "export function draw() {\n  document.getElementById('out').textContent = 'ready';\n}\n"}

EXPRESS_PKG = '{"name": "shelf", "version": "1.0.0", "dependencies": {"express": "4.19.2", "helmet": "7.1.0"}}\n'
EXPRESS = ("const express = require('express');\nconst app = express();\n"
           "app.get('/books', (req, res) => {\n  res.json([]);\n});\n"
           "app.post('/books', (req, res) => {\n  res.json({ok: true});\n});\n"
           "app.listen(3000);\n")

FASTAPI_PKG = '[project]\nname = "shelf"\nversion = "0.1"\ndependencies = ["fastapi"]\n'
FASTAPI = ("from fastapi import FastAPI, Response\n\napp = FastAPI()\n\n"
           "@app.get('/books')\ndef books():\n    return []\n")

FLASK_PKG = '[project]\nname = "shelf"\nversion = "0.1"\ndependencies = ["flask"]\n'
FLASK = ("from flask import Flask\n\napp = Flask(__name__)\n\n"
         "@app.route('/books')\ndef books():\n    return 'none yet'\n")

CSP = "default-src 'self'"


# ---------------------------------------------------------------- nothing that sends a header: "add"

NOTHING = {
    "the word helmet as the name of a tag in a search pattern": {
        **STATIC,
        "clean.js": ("export function clean(html) {\n"
                     "  html = html.replace(/<helmet(\\s|>)/gi, '<x-helmet$1');\n"
                     "  return html.replace(/<\\/helmet\\s*>/gi, '</x-helmet>');\n}\n")},
    "a header named in a comment": {
        "package.json": EXPRESS_PKG,
        "server.js": EXPRESS + "// TODO: send Content-Security-Policy and X-Frame-Options one day\n"},
    "helmet loaded and never put on the app": {
        "package.json": EXPRESS_PKG,
        "server.js": "const helmet = require('helmet');\n" + EXPRESS},
    "a function that happens to be called helmet": {
        "package.json": EXPRESS_PKG,
        "server.js": EXPRESS + "function helmet() {\n  return 'a hat';\n}\napp.use(express.json());\nhelmet();\n"},
    "a pattern that looks for a header in what another site sent": {
        "pyproject.toml": FASTAPI_PKG,
        "svc/main.py": FASTAPI + "\nimport re\n\ndef has_policy(text):\n"
                                 "    return bool(re.search(r'talisman|SecurityMiddleware', text))\n"},
}


@pytest.mark.parametrize("case", sorted(NOTHING))
def test_a_word_is_not_a_header(tmp_path, case):
    _write(tmp_path, NOTHING[case])
    h = _headers(tmp_path)
    assert h["status"] == "add", (case, h)
    assert h["found"] == [] and h["evidence"], (case, h)


# ---------------------------------------------------------------- a header for a part: "check"

PART = {
    "a policy written into one exported document as a meta tag": ({
        **STATIC,
        "export.js": ("export function exportPage(svg) {\n"
                      "  return `<!doctype html><html><head><meta charset=\"utf-8\">"
                      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\">"
                      "<title>Diagram</title></head><body>${svg}</body></html>`;\n}\n")}, "export.js:2"),
    "a page that carries its own policy in a meta tag": ({
        **STATIC, "embed.html": ("<!doctype html><html><head>\n<meta http-equiv=\"Content-Security-Policy\" "
                                 "content=\"default-src 'none'\">\n<title>Embed</title></head><body></body></html>\n")},
        "embed.html:2"),
    "a header set by one route on its own answer": ({
        "package.json": EXPRESS_PKG,
        "server.js": EXPRESS.replace("app.listen", "app.get('/report', (req, res) => {\n"
                                     "  res.setHeader('Content-Security-Policy', \"default-src 'none'\");\n"
                                     "  res.send('<p>report</p>');\n});\napp.listen")}, "server.js:10"),
    "helmet put on one path": ({
        "package.json": EXPRESS_PKG,
        "server.js": ("const helmet = require('helmet');\n" + EXPRESS)
        .replace("app.get('/books'", "app.use('/admin', helmet());\napp.get('/books'")}, "server.js:4"),
    "a hosting rule for one folder": ({
        **STATIC, "_headers": "/admin/*\n  X-Frame-Options: DENY\n  Content-Security-Policy: default-src 'self'\n"},
        "_headers:2"),
    "a Vercel rule for the API only": ({
        **STATIC, "vercel.json": ('{"headers": [{"source": "/api/(.*)", "headers": [\n'
                                  '  {"key": "X-Frame-Options", "value": "DENY"}]}]}\n')}, "vercel.json:"),
    "Next.js headers for the admin pages only": ({
        "package.json": '{"name": "shelf", "dependencies": {"next": "14.2.3", "react": "18.3.1"}}\n',
        "app/page.tsx": "export default function Home() {\n  return <main>Shelf</main>;\n}\n",
        "next.config.js": ("const wanted = [\n  { key: 'X-Frame-Options', value: 'DENY' },\n]\n\n"
                           "module.exports = {\n  async headers() {\n"
                           "    return [{ source: '/admin/:path*', headers: wanted }]\n  },\n}\n")}, "next.config.js:2"),
    "a Netlify rule for one page": ({
        **STATIC, "netlify.toml": ('[[headers]]\n  for = "/embed.html"\n  [headers.values]\n'
                                   '    X-Frame-Options = "DENY"\n')}, "netlify.toml:"),
    "a Python route that sets a header on its own answer": ({
        "pyproject.toml": FASTAPI_PKG,
        "svc/main.py": FASTAPI + ("\n@app.get('/report')\ndef report():\n    r = Response('<p>report</p>')\n"
                                  f"    r.headers['Content-Security-Policy'] = \"{CSP}\"\n    return r\n")},
        "svc/main.py:12"),
    "a table of headers nothing sends": ({
        "pyproject.toml": FASTAPI_PKG,
        "svc/main.py": FASTAPI + f"\nWANTED = {{'X-Frame-Options': 'DENY', 'Content-Security-Policy': \"{CSP}\"}}\n"},
        "svc/main.py:9"),
    "a named function for one route": ({
        "package.json": EXPRESS_PKG,
        "server.js": EXPRESS.replace("app.listen", "function framed(req, res, next) {\n"
                                     "  res.setHeader('X-Frame-Options', 'DENY');\n  next();\n}\n"
                                     "app.get('/embed', framed, (req, res) => {\n  res.send('x');\n});\napp.listen")},
        "server.js:10"),
}


@pytest.mark.parametrize("case", sorted(PART))
def test_a_header_for_a_part_is_to_be_checked(tmp_path, case):
    files, where = PART[case]
    _write(tmp_path, files)
    h = _headers(tmp_path)
    assert h["status"] == "check", (case, h)
    assert any(w.startswith(where) for w in h["found"]), (case, h["found"])
    assert "every" in h["why"], (case, h["why"])          # the words say what is missing: every response


# ---------------------------------------------------------------- set for every response: "in place"

WHOLE = {
    "a hosting rule for every path": ({
        **STATIC, "_headers": "/*\n  X-Frame-Options: DENY\n  Content-Security-Policy: default-src 'self'\n"},
        "_headers:2"),
    "a Netlify rule for every path": ({
        **STATIC, "netlify.toml": ('[[headers]]\n  for = "/*"\n  [headers.values]\n'
                                   '    X-Frame-Options = "DENY"\n')}, "netlify.toml:"),
    "a Vercel rule for every path": ({
        **STATIC, "vercel.json": ('{"headers": [{"source": "/(.*)", "headers": [\n'
                                  '  {"key": "X-Frame-Options", "value": "DENY"}]}]}\n')}, "vercel.json:"),
    "Next.js headers for every path": ({
        "package.json": '{"name": "shelf", "dependencies": {"next": "14.2.3", "react": "18.3.1"}}\n',
        "app/page.tsx": "export default function Home() {\n  return <main>Shelf</main>;\n}\n",
        "next.config.js": ("module.exports = {\n  async headers() {\n    return [{ source: '/(.*)', headers: [\n"
                           "      { key: 'X-Frame-Options', value: 'DENY' }] }];\n  },\n};\n")}, "next.config.js:"),
    "Next.js headers kept in a list and named in the rule for every path": ({
        "package.json": '{"name": "shelf", "dependencies": {"next": "14.2.3", "react": "18.3.1"}}\n',
        "app/page.tsx": "export default function Home() {\n  return <main>Shelf</main>;\n}\n",
        "next.config.js": ("const wanted = [\n  { key: 'X-Frame-Options', value: 'DENY' },\n]\n\n"
                           "module.exports = {\n  async headers() {\n"
                           "    return [{ source: '/(.*)', headers: wanted }]\n  },\n}\n")}, "next.config.js:2"),
    "helmet put on the app": ({
        "package.json": EXPRESS_PKG,
        "server.js": ("const helmet = require('helmet');\n" + EXPRESS)
        .replace("app.get('/books'", "app.use(helmet());\napp.get('/books'")}, "server.js:4"),
    "helmet under another name, imported": ({
        "package.json": EXPRESS_PKG,
        "server.mjs": ("import express from 'express';\nimport guard from 'helmet';\nconst app = express();\n"
                       "app.use(guard({ contentSecurityPolicy: false }));\n"
                       "app.get('/books', (req, res) => {\n  res.json([]);\n});\napp.listen(3000);\n")}, "server.mjs:4"),
    "the app's own function put before every route": ({
        "package.json": EXPRESS_PKG,
        "server.js": EXPRESS.replace("app.get('/books'", "app.use((req, res, next) => {\n"
                                     "  res.setHeader('X-Frame-Options', 'DENY');\n  next();\n});\napp.get('/books'")},
        "server.js:4"),
    "a named function put on the app": ({
        "package.json": EXPRESS_PKG,
        "server.js": EXPRESS.replace("app.get('/books'", "function framed(req, res, next) {\n"
                                     "  res.setHeader('X-Frame-Options', 'DENY');\n  next();\n}\n"
                                     "app.use(framed);\napp.get('/books'")}, "server.js:4"),
    "a FastAPI middleware": ({
        "pyproject.toml": FASTAPI_PKG,
        "svc/main.py": FASTAPI + ("\n@app.middleware('http')\nasync def headers(request, call_next):\n"
                                  "    r = await call_next(request)\n"
                                  f"    r.headers['Content-Security-Policy'] = \"{CSP}\"\n    return r\n")},
        "svc/main.py:12"),
    "a table of headers a middleware sends": ({
        "pyproject.toml": FASTAPI_PKG,
        "svc/main.py": FASTAPI + (f"\nWANTED = {{'X-Frame-Options': 'DENY', 'Content-Security-Policy': \"{CSP}\"}}\n"
                                  "\n@app.middleware('http')\nasync def headers(request, call_next):\n"
                                  "    r = await call_next(request)\n    r.headers.update(WANTED)\n    return r\n")},
        "svc/main.py:9"),
    "a Flask function run after every request": ({
        "pyproject.toml": FLASK_PKG,
        "svc/main.py": FLASK + ("\n@app.after_request\ndef headers(resp):\n"
                                "    resp.headers['X-Frame-Options'] = 'DENY'\n    return resp\n")}, "svc/main.py:11"),
    "Flask-Talisman on the app": ({
        "pyproject.toml": FLASK_PKG.replace('"flask"', '"flask", "flask-talisman"'),
        "svc/main.py": FLASK.replace("app = Flask(__name__)\n", "app = Flask(__name__)\nTalisman(app)\n")
        .replace("from flask import Flask\n", "from flask import Flask\nfrom flask_talisman import Talisman\n")},
        "svc/main.py:5"),
    "Django's own middleware in the settings": ({
        "pyproject.toml": '[project]\nname = "shelf"\nversion = "0.1"\ndependencies = ["django"]\n',
        "shelf/settings.py": ("MIDDLEWARE = [\n    'django.middleware.security.SecurityMiddleware',\n"
                              "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n]\n"),
        "shelf/urls.py": "from django.urls import path\nfrom . import views\n\nurlpatterns = [path('books/', views.books)]\n",
        "shelf/views.py": "from django.http import JsonResponse\n\ndef books(request):\n    return JsonResponse([], safe=False)\n"},
        "shelf/settings.py:2"),
}


@pytest.mark.parametrize("case", sorted(WHOLE))
def test_headers_set_for_every_response_are_in_place(tmp_path, case):
    files, where = WHOLE[case]
    _write(tmp_path, files)
    h = _headers(tmp_path)
    assert h["status"] == "in place", (case, h)
    assert any(w.startswith(where) for w in h["found"]), (case, h["found"])


# ---------------------------------------------------------------- one app of several is not every response

MIDDLEWARE = ("\n@app.middleware('http')\nasync def headers(request, call_next):\n"
              "    r = await call_next(request)\n    r.headers['X-Frame-Options'] = 'DENY'\n    return r\n")
HELMET_ON = ("const helmet = require('helmet');\n" + EXPRESS).replace("app.get('/books'",
                                                                      "app.use(helmet());\napp.get('/books'")
VERCEL_ALL = '{"headers": [{"source": "/(.*)", "headers": [\n  {"key": "X-Frame-Options", "value": "DENY"}]}]}\n'
HEADERS_ALL = "/*\n  X-Frame-Options: DENY\n"
WEB = {"web/package.json": '{"name": "shelf-web", "version": "1.0.0", "devDependencies": {"vite": "5.2.0"}}\n',
       **{f"web/{k}": v for k, v in STATIC.items()}}
API = {"api/package.json": EXPRESS_PKG, "api/server.js": HELMET_ON}
API_BARE = {"api/package.json": EXPRESS_PKG, "api/server.js": EXPRESS}

ONE_OF_SEVERAL = {
    "helmet on the API, and a site of pages beside it": ({**API, **WEB}, "`web/`"),
    "a Vercel rule in the site's folder, and an API beside it": (
        {**WEB, "web/vercel.json": VERCEL_ALL, **API_BARE}, "`api/`"),
    "a `_headers` file in the site's public folder, and an API beside it": (
        {**WEB, "web/public/_headers": HEADERS_ALL, **API_BARE}, "`api/`"),
    "a middleware in one of two services": ({
        "services/api/pyproject.toml": FASTAPI_PKG, "services/api/main.py": FASTAPI + MIDDLEWARE,
        "services/admin/pyproject.toml": FLASK_PKG, "services/admin/main.py": FLASK}, "`services/admin/`"),
    "a rule in the site's folder, and a server at the top of the project": (
        {**WEB, "web/vercel.json": VERCEL_ALL, "package.json": EXPRESS_PKG, "server.js": EXPRESS}, "the top folder"),
}


@pytest.mark.parametrize("case", sorted(ONE_OF_SEVERAL))
def test_headers_for_one_app_of_several_are_to_be_checked(tmp_path, case):
    # full-stack projects keep a site and an API side by side: helmet on the API sends nothing with the site's pages
    files, left = ONE_OF_SEVERAL[case]
    _write(tmp_path, files)
    h = _headers(tmp_path)
    assert h["status"] == "check", (case, h)
    assert left in h["why"] and "one part" in h["why"], (case, h["why"])
    assert h["found"], (case, h)


EVERY_APP = {
    "helmet on the API and a Vercel rule for the site": {**API, **WEB, "web/vercel.json": VERCEL_ALL},
    "helmet on the API and a `_headers` file in the site's public folder": {
        **API, **WEB, "web/public/_headers": HEADERS_ALL},
    "a rule at the top of the project, the apps in folders beneath it": {**API_BARE, **WEB, "vercel.json": VERCEL_ALL},
    "one app whose routes are in another folder than its middleware": {
        "pyproject.toml": FASTAPI_PKG, "svc/__init__.py": "", "svc/routers/__init__.py": "",
        "svc/main.py": ("from fastapi import FastAPI\n\nfrom .routers import books\n\napp = FastAPI()\n"
                        "app.include_router(books.router)\n" + MIDDLEWARE),
        "svc/routers/books.py": ("from fastapi import APIRouter\n\nrouter = APIRouter()\n\n"
                                 "@router.get('/books')\ndef books():\n    return []\n")},
    "two services, each with its own": {
        "services/api/pyproject.toml": FASTAPI_PKG, "services/api/main.py": FASTAPI + MIDDLEWARE,
        "services/admin/pyproject.toml": FLASK_PKG,
        "services/admin/main.py": FLASK + ("\n@app.after_request\ndef headers(resp):\n"
                                           "    resp.headers['X-Frame-Options'] = 'DENY'\n    return resp\n")},
}


@pytest.mark.parametrize("case", sorted(EVERY_APP))
def test_headers_for_every_app_of_several_are_in_place(tmp_path, case):
    _write(tmp_path, EVERY_APP[case])
    h = _headers(tmp_path)
    assert h["status"] == "in place", (case, h)


NEXT_APP = {"package.json": '{"name": "shelf", "dependencies": {"next": "14.2.3", "react": "18.3.1"}}\n',
            "app/page.tsx": "export default function Home() {\n  return <main>Shelf</main>;\n}\n"}
NEXT_RULE = ("module.exports = {\n  async headers() {\n    return [{ source: '/(.*)', headers: [\n"
             "      { key: 'X-Frame-Options', value: 'DENY' }] }];\n  },\n};\n")


@pytest.mark.parametrize("name", ["next.config.js.tmpl", "next.config.js.bak", "starter/next.config.js.txt"])
def test_a_copy_or_a_template_of_a_hosting_file_is_not_the_one_in_force(tmp_path, name):
    # Lantern's own headers card read "in place" for the sample `next.config.js.tmpl` of a starter app
    _write(tmp_path, {**NEXT_APP, name: NEXT_RULE})
    h = _headers(tmp_path)
    assert h["status"] == "add", (name, h)

    twin = tmp_path / "twin"
    _write(twin, {**NEXT_APP, "next.config.js": NEXT_RULE})
    assert _headers(twin)["status"] == "in place", _headers(twin)


# ---------------------------------------------------------------- what is a comment is read in one pass

TEXT_KEPT = '\nHELP = """\nHow the shelf answers.\n"""\n'
ABOUT = '\n\ndef about():\n    """{words}"""\n    return HELP\n'


def test_a_header_set_below_a_text_that_closes_at_the_start_of_a_line_is_set(tmp_path):
    # a text kept under a name is no docstring; read from its closing quotes on as if one began there, the setting
    # below it was taken for words about a header
    _write(tmp_path, {
        "pyproject.toml": FLASK_PKG,
        "svc/main.py": FLASK + TEXT_KEPT + ("\n@app.after_request\ndef headers(resp):\n"
                                            "    resp.headers['X-Frame-Options'] = 'DENY'\n    return resp\n")
        + ABOUT.format(words="What this service is.")})
    h = _headers(tmp_path)
    assert h["status"] == "in place", h

    # its twin: below the same text, the header is only written about
    twin = tmp_path / "twin"
    _write(twin, {"pyproject.toml": FLASK_PKG,
                  "svc/main.py": FLASK + TEXT_KEPT + ABOUT.format(words="Sets X-Frame-Options: DENY some day.")})
    assert _headers(twin)["status"] == "add", _headers(twin)


BUSY = r'''
from lantern.headers import _not_code, _within
back = "\\" * 4000
for text in ("x = '" + back, 'x = "' + back + "\n", "/* " * 200000, "`" + "\\`" * 200000, "` " * 200000,
             "'" * 3 + "' " * 200000, "// x-frame-options\n" * 100000, "# x-frame-options\n" * 100000):
    for js in (True, False):
        off = _not_code(text, js)
        for pos in range(0, len(text), 7):
            _within(off, pos)
print("ok")
'''


def test_no_line_keeps_the_reading_of_comments_busy():
    # a quote followed by backslashes and no closing quote, comments and texts that nothing closes, a header named
    # on every line: each is read once (the pattern this replaced took days over sixty characters of the first)
    r = subprocess.run([sys.executable, "-c", BUSY], capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0 and r.stdout.strip() == "ok", (r.returncode, r.stderr[-500:])
