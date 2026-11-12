"""Is a request limit on this route? (directive point 4, 2026-11-11.)

Until this date a rate-limiting library in the dependencies, or its name in an import, made the "Rate limiting"
protection read "in place" and kept the wallet-drain finding quiet. A library that is installed protects nothing: the
limit has to be put on the route, or on the app in a way the code shows covers the route. Each case that must not count
stands beside one that does. None of these files comes from an app of the held-out benchmark."""

import pytest

from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _limit(root, files):
    _write(root, files)
    g = build_graph(root)
    return {p["id"]: p for p in assess(g, scan(g, offline=True), {})["protections"]}["rate-limit"]


def _py(deps, head, login_deco="", login_sig="email: str, password: str", login_body="    return email\n", more=""):
    return {
        "pyproject.toml": f'[project]\nname = "svc"\nversion = "0.1"\ndependencies = [{deps}]\n',
        "svc/__init__.py": "",
        "svc/main.py": ("from fastapi import Depends, FastAPI, Request\n" + head + "\napp = FastAPI()\n" + more +
                        f"\n\n@app.post('/login'){login_deco}\ndef login({login_sig}):\n{login_body}"
                        "\n\n@app.get('/items')\ndef items(limit: int = 20):\n    return db.query(Item).limit(limit).all()\n"),
    }


SLOWAPI = "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
MADE = "limiter = Limiter(key_func=get_remote_address)\n"
OWN_EMPTY = ("\n\ndef rate_limit(fn):\n    def inner(*args, **kwargs):\n        return fn(*args, **kwargs)\n"
             "    return inner\n")
OWN_COUNTS = ("\n\nSEEN = {}\n\n\ndef rate_limit(fn):\n    def inner(request, *args, **kwargs):\n"
              "        now = time.time()\n        hits = [t for t in SEEN.get(request.client.host, []) if now - t < 60]\n"
              "        if len(hits) >= 5:\n            raise HTTPException(429)\n"
              "        SEEN[request.client.host] = hits + [now]\n        return fn(request, *args, **kwargs)\n"
              "    return inner\n")
PYTHON = {
    "add: the library is only installed":
        (_py('"fastapi", "slowapi"', ""), "add"),
    "add: a limiter is made and never put on anything":
        (_py('"fastapi", "slowapi"', SLOWAPI, more=MADE), "add"),
    "in place: the limiter is on the sign-in route":
        (_py('"fastapi", "slowapi"', SLOWAPI, more=MADE, login_deco="\n@limiter.limit('5/minute')",
             login_sig="request: Request, email: str, password: str"), "in place"),
    "check: a default limit for the whole app":
        (_py('"fastapi", "slowapi"', SLOWAPI + "from slowapi.middleware import SlowAPIMiddleware\n",
             more="limiter = Limiter(key_func=get_remote_address, default_limits=['200/minute'])\n"
                  "app.state.limiter = limiter\napp.add_middleware(SlowAPIMiddleware)\n"), "check"),
    "add: a default limit that is an empty list":
        (_py('"fastapi", "slowapi"', SLOWAPI,
             more="limiter = Limiter(key_func=get_remote_address, default_limits=[])\n"), "add"),
    "in place: a limiter handed to the route as a dependency":
        (_py('"fastapi", "fastapi-limiter"', "from fastapi_limiter.depends import RateLimiter\n",
             login_deco="", login_sig="email: str, password: str, _=Depends(RateLimiter(times=5, seconds=60))"),
         "in place"),
    "check: the project's own decorator named rate_limit, which counts nothing":
        (_py('"fastapi"', "", more=OWN_EMPTY, login_deco="\n@rate_limit"), "check"),
    "in place: the project's own decorator, which counts requests":
        (_py('"fastapi"', "import time\n\nfrom fastapi import HTTPException\n", more=OWN_COUNTS,
             login_deco="\n@rate_limit", login_sig="request: Request, email: str, password: str"), "in place"),
    "add: a query that takes twenty rows and a parameter named limit are no request limit":
        (_py('"fastapi"', ""), "add"),
}


@pytest.mark.parametrize("case", sorted(PYTHON))
def test_a_limit_counts_where_it_is_put_on_the_route(tmp_path, case):
    files, want = PYTHON[case]
    p = _limit(tmp_path, files)
    assert p["status"] == want, p
    assert any("/login" in e for e in p["evidence"]) or want == "in place", p


def test_what_the_reader_is_told(tmp_path):
    files, _ = PYTHON["add: the library is only installed"]
    p = _limit(tmp_path / "a", files)
    assert p["found"] == [] and "slowapi" in p["why"] and "installed" in p["why"], p
    assert "can be called as fast" in p["why"], p
    files, _ = PYTHON["in place: the limiter is on the sign-in route"]
    p = _limit(tmp_path / "b", files)
    assert p["found"] == ["POST /login: `limiter.limit` on the route (svc/main.py:9)"], p
    assert "can be called as fast" not in p["why"], p
    files, _ = PYTHON["check: a default limit for the whole app"]
    p = _limit(tmp_path / "c", files)
    assert p["found"] == ["a default limit for every route (svc/main.py:7)"], p
    assert "tight enough" in p["why"] and any("/login" in e for e in p["evidence"]), p
    files, _ = PYTHON["check: the project's own decorator named rate_limit, which counts nothing"]
    p = _limit(tmp_path / "d", files)
    assert "`rate_limit`" in p["why"] and "count" in p["why"], p


def test_one_sign_in_route_with_a_limit_and_one_without(tmp_path):
    files, _ = PYTHON["in place: the limiter is on the sign-in route"]
    files = dict(files)
    files["svc/main.py"] += "\n\n@app.post('/signup')\ndef signup(email: str, password: str):\n    return email\n"
    p = _limit(tmp_path, files)
    assert p["status"] == "check" and "1 of 2" in p["why"], p
    assert p["evidence"][0].startswith("POST /signup"), p                # the one without comes first


PACKAGE = '{"dependencies": {"express": "4.19.2"%s}}'
LIB = ', "express-rate-limit": "7.1.0"'
HEAD = "const express = require('express')\nconst app = express()\n"
RL = "const rateLimit = require('express-rate-limit')\n"
LOGIN = "app.post('/auth/login', %sasync (req, res) => {\n  res.json({ ok: true })\n})\n"
EXPRESS = {
    "add: the library is only installed":
        ({"package.json": PACKAGE % LIB, "server.js": HEAD + LOGIN % ""}, "add"),
    "add: the library is loaded and a limiter is made, and nothing uses it":
        ({"package.json": PACKAGE % LIB,
          "server.js": HEAD + RL + "const limiter = rateLimit({ windowMs: 60000, max: 5 })\n" + LOGIN % ""}, "add"),
    "in place: a limiter for the whole app, before the routes":
        ({"package.json": PACKAGE % LIB,
          "server.js": HEAD + RL + "app.use(rateLimit({ windowMs: 60000, max: 100 }))\n" + LOGIN % ""}, "in place"),
    "in place: a limiter for the part of the app the route is in":
        ({"package.json": PACKAGE % LIB,
          "server.js": HEAD + RL + "app.use('/auth/', rateLimit({ windowMs: 60000, max: 5 }))\n" + LOGIN % ""},
         "in place"),
    "add: the limiter is for another part of the app":
        ({"package.json": PACKAGE % LIB,
          "server.js": HEAD + RL + "app.use('/api/', rateLimit({ windowMs: 60000, max: 5 }))\n" + LOGIN % ""}, "add"),
    "add: the limiter is put on the app after the route, so it never runs for it":
        ({"package.json": PACKAGE % LIB,
          "server.js": HEAD + RL + LOGIN % "" + "app.use(rateLimit({ windowMs: 60000, max: 5 }))\n"}, "add"),
    "in place: the limiter is handed to the route":
        ({"package.json": PACKAGE % LIB,
          "server.js": HEAD + RL + "const loginLimiter = rateLimit({ windowMs: 60000, max: 5 })\n" +
          LOGIN % "loginLimiter, "}, "in place"),
    "check: the project's own middleware named loginLimiter, which counts nothing":
        ({"package.json": PACKAGE % "",
          "server.js": HEAD + "function loginLimiter (req, res, next) {\n  next()\n}\n" + LOGIN % "loginLimiter, "},
         "check"),
    "check: the limiter is put on the app in another file":
        ({"package.json": PACKAGE % LIB,
          "app.js": HEAD + RL + "app.use(rateLimit({ windowMs: 60000, max: 100 }))\n"
                    "app.use('/auth', require('./routes/auth'))\n",
          "routes/auth.js": "const router = require('express').Router()\n"
                            "router.post('/login', async (req, res) => {\n  res.json({ ok: true })\n})\n"
                            "module.exports = router\n"}, "check"),
    "add: a size limit for request bodies is no request limit":
        ({"package.json": PACKAGE % "",
          "server.js": HEAD + "app.use(express.json({ limit: '1mb' }))\n" + LOGIN % ""}, "add"),
    "in place: the handler asks a limiter itself":
        ({"package.json": '{"dependencies": {"express": "4.19.2", "rate-limiter-flexible": "5.0.0"}}',
          "server.js": HEAD + "const { RateLimiterMemory } = require('rate-limiter-flexible')\n"
                       "const limiter = new RateLimiterMemory({ points: 5, duration: 60 })\n"
                       "app.post('/auth/login', async (req, res) => {\n  await limiter.consume(req.ip)\n"
                       "  res.json({ ok: true })\n})\n"}, "in place"),
}


@pytest.mark.parametrize("case", sorted(EXPRESS))
def test_express_a_limit_counts_where_it_covers_the_route(tmp_path, case):
    files, want = EXPRESS[case]
    p = _limit(tmp_path, files)
    assert p["status"] == want, p


def test_express_says_why_a_limiter_does_not_count(tmp_path):
    files, _ = EXPRESS["add: the limiter is for another part of the app"]
    p = _limit(tmp_path / "a", files)
    assert "/api/" in p["why"] and "express-rate-limit" in p["why"], p
    files, _ = EXPRESS["add: the limiter is put on the app after the route, so it never runs for it"]
    p = _limit(tmp_path / "b", files)
    assert "after" in p["why"], p
    files, _ = EXPRESS["in place: a limiter for the whole app, before the routes"]
    p = _limit(tmp_path / "c", files)
    assert p["found"] == ["POST /auth/login: `rateLimit` put on the app before this route (server.js:4)"], p


def test_a_route_that_spends_money_needs_the_limit_on_itself(tmp_path):
    app = ('from fastapi import FastAPI, Depends, Request\nimport anthropic\nfrom slowapi import Limiter\n\n'
           'app = FastAPI()\nlimiter = Limiter(key_func=lambda: "ip")\n\n\ndef get_current_user():\n    return "u"\n\n\n'
           '@app.post("/ask")%s\ndef ask(request: Request, q: str, user=Depends(get_current_user)):\n'
           '    return anthropic.Anthropic().messages.create(model="claude-haiku-5-5", max_tokens=100, '
           'messages=[{"role": "user", "content": q}])\n')
    # the library is installed and a limiter is made, and the route that pays for a model call has none
    _write(tmp_path / "a", {"requirements.txt": "fastapi\nslowapi\nanthropic\n", "app.py": app % ""})
    sec = scan(build_graph(tmp_path / "a"), offline=True)
    wd = [f for f in sec["findings"] if f["rule"] == "LA-WALLET-DRAIN"]
    assert len(wd) == 1 and "no rate limit" in wd[0]["title"] and wd[0]["rank"] == "medium", wd
    assert "slowapi" in wd[0]["more_info"] and "installed" in wd[0]["more_info"], wd[0]
    # the same route with the limiter on it
    _write(tmp_path / "b", {"requirements.txt": "fastapi\nslowapi\nanthropic\n",
                            "app.py": app % '\n@limiter.limit("5/minute")'})
    sec = scan(build_graph(tmp_path / "b"), offline=True)
    assert not [f for f in sec["findings"] if f["rule"] == "LA-WALLET-DRAIN"]
