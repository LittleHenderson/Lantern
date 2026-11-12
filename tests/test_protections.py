import pytest

from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _prot(root):
    g = build_graph(root)
    return {p["id"]: p for p in assess(g, scan(g), {})["protections"]}


BARE = {
    "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi", "requests"]\n',
    "svc/main.py": (
        "import hashlib\nimport requests\nfrom fastapi import FastAPI, UploadFile\n\napp = FastAPI()\n\n"
        "@app.post('/login')\ndef login(email: str, password: str):\n"
        "    return hashlib.sha256(password.encode()).hexdigest()\n\n"
        "@app.post('/preview')\ndef preview(url: str):\n    return requests.get(url).text\n\n"
        "@app.post('/avatar')\nasync def avatar(file: UploadFile):\n    return await file.read()\n"),
}


def test_missing_protections_come_with_evidence(tmp_path):
    _write(tmp_path, BARE)
    p = _prot(tmp_path)
    for k in ("rate-limit", "security-headers", "ssrf-allowlist", "password-hashing", "upload-checks"):
        assert p[k]["status"] == "add" and p[k]["how"] and p[k]["heuristic"], k
    assert any("/login" in e for e in p["rate-limit"]["evidence"])
    assert p["password-hashing"]["evidence"] == ["svc/main.py:9"]
    assert p["ssrf-allowlist"]["evidence"] == ["svc/main.py:13"]


def test_protections_in_place_are_recognized(tmp_path):
    files = dict(BARE)
    files["pyproject.toml"] = files["pyproject.toml"].replace('"requests"]', '"requests", "slowapi", "bcrypt"]')
    files["svc/main.py"] = (files["svc/main.py"].replace("hashlib.sha256(password.encode()).hexdigest()",
                                                         "bcrypt.hashpw(password.encode(), bcrypt.gensalt())")
                            .replace("import hashlib", "import bcrypt")
                            # 2026-11-11: `slowapi` in the dependencies alone read "in place" here. A library that
                            # is installed limits nothing, so the limiter is now put on the sign-in route
                            # (tests/test_ratelimit.py has the installed-only case, which reads "add").
                            .replace("app = FastAPI()\n", "app = FastAPI()\nlimiter = Limiter(key_func=lambda: 'ip')\n")
                            .replace("@app.post('/login')\n", "@app.post('/login')\n@limiter.limit('5/minute')\n")
                            .replace("import requests\n", "import requests\nfrom slowapi import Limiter\n")
                            .replace("return requests.get(url).text", "assert host_of(url) in ALLOWED_HOSTS\n"
                                     "    return requests.get(url).text")
                            .replace("return await file.read()", "assert file.content_type == 'image/png'\n"
                                     "    return await file.read()")
                            + "\n@app.middleware('http')\nasync def headers(request, call_next):\n"
                              "    r = await call_next(request)\n    r.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                              "    return r\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)
    for k in ("rate-limit", "security-headers", "ssrf-allowlist", "password-hashing", "upload-checks"):
        assert p[k]["status"] == "in place", (k, p[k])


def test_managed_auth_and_fixed_urls_raise_nothing(tmp_path):
    _write(tmp_path, {
        "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi", "fastapi-users"]\n',
        "svc/main.py": ("import requests\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n"
                        "@app.get('/rate')\ndef rate(password_hint: str):\n"
                        "    return requests.get('https://api.example.com/rate').json()\n"),
    })
    p = _prot(tmp_path)
    assert "password-hashing" not in p and "ssrf-allowlist" not in p and "upload-checks" not in p


# No frontend at all: nothing for LW-AUTH-MISSING to link, yet the routes are open to anyone.
BACKEND_ONLY = {
    "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi"]\n',
    "svc/main.py": (
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.post('/items')\ndef create_item(name: str):\n    return {'name': name}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int):\n    return item_id\n\n"
        "@app.get('/items')\ndef list_items():\n    return []\n"),
}


def test_route_auth_is_missing_without_a_frontend(tmp_path):
    _write(tmp_path, BACKEND_ONLY)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add"
    assert p["evidence"] == ["POST /items (svc/main.py:5)", "DELETE /items/{item_id} (svc/main.py:9)"]
    assert "2 route(s)" in p["why"] and p["found"] == []


def test_route_auth_in_place_when_every_route_checks(tmp_path):
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import Depends, FastAPI, Request\n\napp = FastAPI()\n\n"
        "def get_current_user():\n    return 1\n\n"
        "@app.post('/items')\ndef create_item(name: str, user=Depends(get_current_user)):\n    return {'name': name}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int, request: Request):\n"
        "    if not request.user.is_admin:\n        raise ValueError('no')\n    return item_id\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "in place", p
    assert p["found"] == ["POST /items: `user=Depends(get_current_user)` in its parameters",
                          "DELETE /items/{item_id}: handler mentions `request.user`"]


def test_route_auth_needs_checking_when_only_middleware_exists(tmp_path):
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] += (
        "\n@app.middleware('http')\nasync def require_login(request, call_next):\n"
        "    if not request.headers.get('authorization'):\n        return deny()\n    return await call_next(request)\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "check", p
    assert p["evidence"][0].startswith("POST /items") and p["found"] == ["svc/main.py:17"]
    assert "confirm" in p["why"]


def test_public_write_routes_need_no_login(tmp_path):
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = ("from fastapi import FastAPI\n\napp = FastAPI()\n\n"
                            "@app.post('/login')\ndef login(email: str, password: str):\n    return email\n\n"
                            "@app.post('/webhooks/stripe')\ndef hook(payload: dict):\n    return payload\n")
    _write(tmp_path, files)
    assert "route-auth" not in _prot(tmp_path)


def test_a_route_path_is_not_a_login_check(tmp_path):
    """'/authors' contains 'auth'; neither the decorator's path nor the route name counts as a check."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = files["svc/main.py"].replace("/items", "/authors")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add" and len(p["evidence"]) == 2


def test_a_comment_or_docstring_is_not_a_login_check(tmp_path):
    """Strings and comments are blanked before the handler's lines are read for login words."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.post('/items')\ndef create_item(name: str):\n    # TODO: add auth here later\n    return {'name': name}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int):\n"
        "    \"\"\"Delete an item.\n\n    Needs a permission check and current_user once login exists.\n    \"\"\"\n"
        "    msg = 'authorized by nobody'\n    return item_id\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add", p
    assert p["evidence"] == ["POST /items (svc/main.py:5)", "DELETE /items/{item_id} (svc/main.py:10)"]


def test_a_payload_field_named_like_an_auth_word_is_data(tmp_path):
    """`permissions = payload.get("permissions")` reads what the caller claims, the opposite of a check. Request data,
    the names that hold it, assignment targets and plain parameters never count; a check is a call or an attribute."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import Body, Depends, FastAPI\nfrom sqlmodel import Session\n\napp = FastAPI()\n\n"
        "def get_session():\n    return 1\n\n"
        "@app.post('/settings')\ndef save_settings(payload: dict):\n    permissions = payload.get('permissions')\n"
        "    protected = payload['protected']\n    auth_enabled = payload.get('auth_enabled', False)\n"
        "    if 'admin' in permissions and protected:\n        return auth_enabled\n    return permissions\n\n"
        "@app.put('/settings')\ndef set_flags(settings_in: dict, payload: dict):\n"
        "    settings.protected = payload['protected']\n    settings.is_admin = True\n    return settings\n\n"
        "@app.patch('/roles')\ndef set_roles(permissions: list[str] = Body(), session: Session = Depends(get_session)):\n"
        "    permissions.append('x')\n    session.add(permissions)\n    return permissions\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add", p
    assert [e.split(" (")[0] for e in p["evidence"]] == ["POST /settings", "PUT /settings", "PATCH /roles"]
    # the same words as a call or an attribute of something that is not request data do count
    files["svc/main.py"] = files["svc/main.py"].replace(
        "    permissions = payload.get('permissions')\n",
        "    permissions = payload.get('permissions')\n    authorize(request_user(), 'settings')\n",
    ).replace(
        "    settings.is_admin = True\n", "    if not current_user.is_admin:\n        raise ValueError\n",
    ).replace(
        # until 2026-11-11 `jwt.decode(token)`: a token read with no key is checked by nothing, and since the flow
        # step reads a login from what the code does the route is listed as open (the cards at the end of this file)
        "    permissions.append('x')\n", "    permissions.append('x')\n    jwt.decode(token, KEY, algorithms=['HS256'])\n",
    )
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "in place", p
    assert p["found"] == ["POST /settings: handler calls `authorize(...)`",
                          "PUT /settings: handler mentions `current_user.is_admin`",
                          "PATCH /roles: handler calls `jwt.decode(...)`"]


def test_finding_and_protection_tell_one_story_on_a_tested_lookup(tmp_path):
    """A route the app calls whose only sign is a tested user lookup: the finding names the lookup, and so does the
    protection, which no longer claims there was no sign at all."""
    files = {
        "package.json": '{"dependencies": {"express": "4"}}',
        "server.js": (
            "const express = require('express')\nconst { getUser } = require('./users')\nconst app = express()\n"
            "app.delete('/notes/:id', async (req, res) => {\n  const owner = await getUser(req.body.owner)\n"
            "  if (!owner) return res.status(404).end()\n  res.send('ok')\n})\napp.listen(3000)\n"),
        "users.js": "export function getUser(id) { return id }\n",
        "web/app.js": "export async function remove(id) { await fetch('/notes/' + id, {method: 'DELETE'}) }\n",
    }
    _write(tmp_path, files)
    g = build_graph(tmp_path)
    sec = scan(g)
    (f,) = [x for x in sec["findings"] if x["rule"] == "LW-AUTH-MISSING"]
    p = {x["id"]: x for x in assess(g, sec, {})["protections"]}["route-auth"]
    assert p["status"] == "add"
    assert "no sign of a login check" not in p["why"] and "record's owner" in p["why"]
    assert p["evidence"] == ["DELETE /notes/:id (server.js:4): `getUser(req.body.owner)` looks up a user by "
                             "`req.body.owner`, not by who is calling"]
    assert "`getUser(req.body.owner)` looks up a user by `req.body.owner`, not by who is calling" in f["more_info"]


def test_looking_up_the_target_user_is_not_a_login_check(tmp_path):
    """`who = get_user(payload['owner'])` fetches the record's owner, not the caller (the IDOR shape). With the
    result tested it is a weak sign, so the status is `check`, never `in place`. `get_user(token)` is a real check."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import FastAPI, Header\n\napp = FastAPI()\n\n"
        "def get_user(key):\n    return {'id': key}\n\n"
        "@app.post('/items')\ndef create_item(payload: dict):\n    who = get_user(payload.get('owner'))\n"
        "    if not who:\n        raise ValueError('no such user')\n    return {'owner': who['id']}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int, x_key: str = Header()):\n"
        "    who = get_user(token=x_key)\n    return who\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "check", p
    assert p["evidence"] == ["POST /items (svc/main.py:8): `get_user(payload.get('owner'))` looks up a user by "
                             "`payload.get('owner')`, not by who is calling"]
    assert p["found"] == ["DELETE /items/{item_id}: handler calls `get_user(token=x_key)`"]
    assert "record's owner" in p["why"]
    # the same lookup without testing the result is no sign at all
    files["svc/main.py"] = files["svc/main.py"].replace("    if not who:\n        raise ValueError('no such user')\n", "")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add" and p["evidence"] == ["POST /items (svc/main.py:8)"], p


def test_a_helper_named_like_an_auth_word_is_not_a_login_check(tmp_path):
    """`words = tokenize(payload.get("text"))` gave "in place" with the evidence "calls `tokenize`" (the substring
    `token`); so did `load_permissions(...)` and `protect_zone(...)`. Auth words now match whole name segments, so
    these are nothing, while `get_token()`, `has_permission(...)` and `protect()` still count."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "def tokenize(text):\n    return text.split()\n\n"
        "def load_permissions(owner):\n    return [owner]\n\n"
        "def protect_zone(zone):\n    return zone\n\n"
        "@app.post('/index')\ndef index_text(payload: dict):\n    words = tokenize(payload.get('text'))\n"
        "    return words\n\n"
        "@app.put('/zones')\ndef set_zone(payload: dict):\n    perms = load_permissions(payload.get('owner'))\n"
        "    if not perms:\n        raise ValueError\n    return perms\n\n"
        "@app.patch('/zones')\ndef guard_zone(payload: dict):\n    protect_zone(payload)\n    return 1\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add", p
    assert [e.split(" (")[0] for e in p["evidence"]] == ["POST /index", "PUT /zones", "PATCH /zones"]
    files["svc/main.py"] = (files["svc/main.py"]
                            .replace("def tokenize(text):", "def get_token(text):")
                            .replace("tokenize(payload", "get_token(payload")
                            .replace("def load_permissions(owner):", "def has_permission(owner):")
                            .replace("load_permissions(payload", "has_permission(payload")
                            .replace("def protect_zone(zone):", "def protect(zone):")
                            .replace("protect_zone(payload)", "protect(payload)"))
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "in place", p
    assert p["found"] == ["POST /index: calls `get_token`", "PUT /zones: calls `has_permission`",
                          "PATCH /zones: calls `protect`"]


def test_verify_counts_only_with_the_caller_as_its_object(tmp_path):
    """`verify_payment(...)`, `verify_signature(...)` and `verify_age(...)` gave "in place": a checkout route that
    verifies a payment was told it already had a login check. `verify` now needs the caller as its object."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "def verify_payment(p):\n    return p\n\n"
        "def verify_signature(s):\n    return s\n\n"
        "def verify_age(a):\n    return a\n\n"
        "@app.post('/checkout')\ndef checkout(payload: dict):\n    verify_payment(payload.get('payment'))\n    return 1\n\n"
        "@app.put('/orders')\ndef sign(payload: dict):\n    verify_signature(payload.get('sig'))\n    return 1\n\n"
        "@app.patch('/orders')\ndef age(payload: dict):\n    verify_age(payload.get('dob'))\n    return 1\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add", p
    assert [e.split(" (")[0] for e in p["evidence"]] == ["POST /checkout", "PUT /orders", "PATCH /orders"]
    files["svc/main.py"] = (files["svc/main.py"]
                            .replace("verify_payment", "verify_token").replace("verify_signature", "verify_session")
                            .replace("verify_age", "verify_password"))
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "in place", p
    assert p["found"] == ["POST /checkout: calls `verify_token`", "PUT /orders: calls `verify_session`",
                          "PATCH /orders: calls `verify_password`"]


def test_an_api_key_check_counts(tmp_path):
    """`verify_api_key(...)`, `check_api_key(...)` and `require_api_key(...)` identify the caller by its key."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import FastAPI, Header\n\napp = FastAPI()\n\n"
        "def verify_api_key(k):\n    return k\n\n"
        "def check_api_key(k):\n    return k\n\n"
        "def require_api_key(k):\n    return k\n\n"
        "@app.post('/a')\ndef a(payload: dict, x_key: str = Header()):\n    verify_api_key(x_key)\n    return 1\n\n"
        "@app.put('/b')\ndef b(payload: dict, x_key: str = Header()):\n    check_api_key(x_key)\n    return 1\n\n"
        "@app.patch('/c')\ndef c(payload: dict, x_key: str = Header()):\n    require_api_key(x_key)\n    return 1\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "in place", p
    assert p["found"] == ["POST /a: calls `verify_api_key`", "PUT /b: calls `check_api_key`", "PATCH /c: calls `require_api_key`"]


def test_words_in_strings_and_pattern_lists_are_not_protections(tmp_path):
    # Lantern read itself and marked rate limiting and upload checks "in place" from its own advice text and its own
    # pattern lists (`UPLOAD = re.compile(r"...UploadFile...")`), with the same line listed three times.
    files = dict(BARE)
    files["svc/rules.py"] = (
        "import re\n"
        "UPLOAD = re.compile(r\"\\bUploadFile\\b|request\\.files|multer\\(\")\n"
        "UPLOAD_LIMIT = re.compile(r\"MAX_CONTENT_LENGTH|max_size|content_type\")\n"
        "ALLOW = re.compile(r\"allow_?list|ALLOWED_HOSTS\")\n"
        "ADVICE = 'add a per-user and per-IP rate limit (slowapi, express-rate-limit)'\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)
    for k in ("rate-limit", "ssrf-allowlist", "upload-checks"):
        assert p[k]["status"] == "add", (k, p[k])
    assert p["upload-checks"]["evidence"] == ["svc/main.py:3", "svc/main.py:16"]   # the real upload, not the list
    assert all("svc/rules.py" not in e for k in p for e in p[k]["evidence"] + p[k]["found"])


def test_in_place_protections_say_what_was_found(tmp_path):
    # Until 2026-11-11 this test held the opposite: `slowapi` in the dependencies, used nowhere, read "in place" with
    # `found == ["slowapi in the dependencies"]`. A library that is installed protects nothing (directive point 4), so
    # that case is now "add" and says the library is not put to work; "in place" names the route and the limiter.
    files = dict(BARE)
    files["pyproject.toml"] = files["pyproject.toml"].replace('"requests"]', '"requests", "slowapi"]')
    _write(tmp_path / "installed", files)
    p = _prot(tmp_path / "installed")["rate-limit"]
    assert p["status"] == "add" and p["found"] == [], p
    assert "`slowapi` is installed" in p["why"] and "can be called as fast" in p["why"], p
    files["svc/main.py"] = (files["svc/main.py"]
                            .replace("app = FastAPI()\n", "app = FastAPI()\nlimiter = Limiter(key_func=lambda: 'ip')\n")
                            .replace("@app.post('/login')\n", "@app.post('/login')\n@limiter.limit('5/minute')\n")
                            .replace("import requests\n", "import requests\nfrom slowapi import Limiter\n"))
    _write(tmp_path / "used", files)
    p = _prot(tmp_path / "used")["rate-limit"]
    assert p["status"] == "in place" and p["found"] == ["POST /login: `limiter.limit` on the route (svc/main.py:9)"], p
    assert "puts a request limit on it" in p["why"] and "can be called as fast" not in p["why"], p


def test_routes_in_test_code_are_not_the_apps_routes(tmp_path):
    # Lantern's own sample apps under tests/fixtures were listed as "anyone on the internet can call them"
    _write(tmp_path, {
        "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi"]\n',
        "svc/main.py": "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/health')\ndef health():\n    return 1\n",
        "tests/fixtures/notes/api.py": ("from fastapi import FastAPI\napp = FastAPI()\n\n"
                                        "@app.delete('/api/notes/{id}')\ndef drop(id: int):\n    return id\n"),
    })
    p = _prot(tmp_path)
    assert "route-auth" not in p and "rate-limit" not in p


def test_a_host_allow_list_is_not_an_allow_list_for_outgoing_requests(tmp_path):
    # ALLOWED_HOSTS in a settings file names the hosts the server answers to, not the ones it calls
    files = dict(BARE)
    files["svc/settings.py"] = "import os\nALLOWED_HOSTS = os.environ.get('HOSTS', '').split(',')\n"
    _write(tmp_path, files)
    assert _prot(tmp_path)["ssrf-allowlist"]["status"] == "add"


def test_a_hook_that_only_counts_requests_is_not_an_app_wide_login_check(tmp_path):
    # the session check in the function after the hook used to be read as part of the hook
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] += (
        "\n@app.middleware('http')\nasync def seen(request, call_next):\n    touch()\n"
        "    return await call_next(request)\n\n"
        "def me(request):\n    return current_user(request.cookies.get('session'))\n")
    _write(tmp_path, files)
    assert _prot(tmp_path)["route-auth"]["status"] == "add"


def test_signing_out_needs_no_login(tmp_path):
    from lantern.websec import is_public_route
    for d in ("POST /v1/signout", "POST /api/sign-out", "POST /log-out", "POST /logout"):
        assert is_public_route(d), d
    assert not is_public_route("POST /v1/notes")


# --- the card and the findings tell one story about a login (2026-11-11) ---------------------------------------------
# The whole suite showed it. Since the flow step reads a login from what the code does (`lantern/flow.py`), a route
# behind a check with a plain name gets no "no login check was found" finding, and this card still said "add" or
# "check" for it; and a route whose only login is a token check that lets a failed token on gets that finding, while
# the card named the same route among those that show a login. Each dangerous example stands beside the same lines
# with a real check.
CARD_SHOWN = "the code on the way to this route turns away whoever is not signed in"
CARD_PKG = ('{"name": "notes", "version": "1.0.0", "dependencies": {"express": "^4.19.0", '
            '"express-session": "^1.18.0", "jsonwebtoken": "^9.0.0"}}\n')
CARD_JS_HEAD = ("const express = require('express')\nconst session = require('express-session')\n"
                "const jwt = require('jsonwebtoken')\nconst db = require('./db')\nconst app = express()\n"
                "app.use(express.json())\napp.use(session({ secret: process.env.SESSION_SECRET }))\n")
CARD_JS_ROUTE = ("app.delete('/notes/:id', async (req, res) => {\n"
                 "  await db.notes.destroy({ where: { id: req.params.id } })\n  res.status(204).end()\n})\n"
                 "app.listen(3000)\n")
CARD_FLASK = '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["flask", "flask-jwt-extended"]\n'
CARD_FL_HEAD = ("import sqlite3\nfrom flask import Flask, abort, g, request, session\n"
                "from flask_jwt_extended import jwt_required\n\napp = Flask(__name__)\ndb = sqlite3.connect('notes.db')\n\n\n")
CARD_FL_ROUTE = ("@app.route('/notes/<int:note_id>', methods=['DELETE'])\ndef drop(note_id):\n"
                 "    db.execute('DELETE FROM notes WHERE id = ?', (note_id,))\n    db.commit()\n    return '', 204\n")
CARD_FASTAPI = '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi", "pyjwt"]\n'
CARD_FA_HEAD = ("import os\nimport sqlite3\nimport jwt\nfrom fastapi import Depends, FastAPI, Header, HTTPException, "
                "Request\n\napp = FastAPI()\ndb = sqlite3.connect('notes.db')\nKEY = os.environ['JWT_KEY']\n\n\n")
CARD_FA_DROP = ("@app.delete('/notes/{note_id}')\ndef drop(note_id: int, authorization: str = Header()):\n"
                "    who = WHO\n    db.execute('DELETE FROM notes WHERE id = ?', (note_id,))\n    return {'ok': who}\n")
CARD_READ = "jwt.decode(authorization, options={'verify_signature': False})"
CARD_CHECKED = "jwt.decode(authorization, KEY, algorithms=['HS256'])"
CARD_JS = "DELETE /notes/:id"
CARD_FL = "DELETE /notes/<int:note_id>"
CARD_FA = "DELETE /notes/{note_id}"
# name -> (files, the file the route is in, the text its first line begins with, the route, the card's status, what
# the card says was found for the route when it shows a login)
CARD = {
    "express, in place: a check with a plain name put on with use":
        ({"package.json": CARD_PKG, "server.js": CARD_JS_HEAD + "function restrict(req, res, next) {\n"
          "  if (!req.session.userId) return res.status(401).end()\n  next()\n}\napp.use(restrict)\n" + CARD_JS_ROUTE},
         "server.js", "app.delete(", CARD_JS, "in place", CARD_SHOWN),
    "express, add: the same name, and it turns nobody away":
        ({"package.json": CARD_PKG, "server.js": CARD_JS_HEAD + "function restrict(req, res, next) {\n"
          "  res.set('X-Seen', '1')\n  next()\n}\napp.use(restrict)\n" + CARD_JS_ROUTE},
         "server.js", "app.delete(", CARD_JS, "add", None),
    "express, in place: a check written in place":
        ({"package.json": CARD_PKG, "server.js": CARD_JS_HEAD + "app.use((req, res, next) => {\n"
          "  if (!req.session.userId) return res.status(401).end()\n  next()\n})\n" + CARD_JS_ROUTE},
         "server.js", "app.delete(", CARD_JS, "in place", CARD_SHOWN),
    "express, add: a check named for a login that lets a failed token on":
        ({"package.json": CARD_PKG, "server.js": CARD_JS_HEAD + "function authenticate(req, res, next) {\n  try {\n"
          "    req.user = jwt.verify(req.headers.authorization, process.env.JWT_KEY)\n  } catch (e) {}\n  next()\n}\n"
          "app.use(authenticate)\n" + CARD_JS_ROUTE},
         "server.js", "app.delete(", CARD_JS, "add", None),
    "express, in place: the same check turns a failed token away":
        ({"package.json": CARD_PKG, "server.js": CARD_JS_HEAD + "function authenticate(req, res, next) {\n  try {\n"
          "    req.user = jwt.verify(req.headers.authorization, process.env.JWT_KEY)\n  } catch (e) {\n"
          "    return res.status(401).end()\n  }\n  next()\n}\napp.use(authenticate)\n" + CARD_JS_ROUTE},
         "server.js", "app.delete(", CARD_JS, "in place", "middleware `authenticate` put on before this route (server.js:16)"),
    "flask, in place: a hook that turns visitors away":
        ({"pyproject.toml": CARD_FLASK, "app.py": CARD_FL_HEAD + "@app.before_request\ndef gate():\n"
          "    if 'user_id' not in session:\n        abort(401)\n\n\n" + CARD_FL_ROUTE},
         "app.py", "@app.route('/notes", CARD_FL, "in place", CARD_SHOWN),
    "flask, add: a hook that only counts":
        ({"pyproject.toml": CARD_FLASK, "app.py": CARD_FL_HEAD + "@app.before_request\ndef gate():\n"
          "    g.seen = 1\n\n\n" + CARD_FL_ROUTE},
         "app.py", "@app.route('/notes", CARD_FL, "add", None),
    "flask, add: the library's login made optional":
        ({"pyproject.toml": CARD_FLASK, "app.py": CARD_FL_HEAD +
          CARD_FL_ROUTE.replace("def drop", "@jwt_required(optional=True)\ndef drop")},
         "app.py", "@app.route('/notes", CARD_FL, "add", None),
    "flask, in place: the library's login as it comes":
        ({"pyproject.toml": CARD_FLASK, "app.py": CARD_FL_HEAD +
          CARD_FL_ROUTE.replace("def drop", "@jwt_required()\ndef drop")},
         "app.py", "@app.route('/notes", CARD_FL, "in place", "decorator @jwt_required"),
    "fastapi, in place: a dependency with a plain name":
        ({"pyproject.toml": CARD_FASTAPI, "main.py": CARD_FA_HEAD + "def caller(request: Request):\n"
          "    if not request.session.get('uid'):\n        raise HTTPException(401)\n    return request.session['uid']\n\n\n"
          "@app.delete('/notes/{note_id}')\ndef drop(note_id: int, who=Depends(caller)):\n"
          "    db.execute('DELETE FROM notes WHERE id = ?', (note_id,))\n    return {'ok': True}\n"},
         "main.py", "@app.delete(", CARD_FA, "in place", CARD_SHOWN),
    "fastapi, add: a token that is only read":
        ({"pyproject.toml": CARD_FASTAPI, "main.py": CARD_FA_HEAD + CARD_FA_DROP.replace("WHO", CARD_READ)},
         "main.py", "@app.delete(", CARD_FA, "add", None),
    "fastapi, in place: the same token checked with the server's key":
        ({"pyproject.toml": CARD_FASTAPI, "main.py": CARD_FA_HEAD + CARD_FA_DROP.replace("WHO", CARD_CHECKED)},
         "main.py", "@app.delete(", CARD_FA, "in place", "calls `jwt.decode`"),
}


@pytest.mark.parametrize("case", sorted(CARD))
def test_the_login_card_and_the_findings_tell_one_story(tmp_path, case):
    """A route the findings call open ("no login check was found", "nothing that turns away a request whose login
    token does not hold") is one the card lists as open, by its name, and never among those that show a login; a
    route whose code shows a login gets no such finding and the card counts it as checked."""
    files, name, begins, route, status, found = CARD[case]
    _write(tmp_path, files)
    at = files[name].split(begins)[0].count("\n") + 1
    g = build_graph(tmp_path)
    sec = scan(g)
    card = {p["id"]: p for p in assess(g, sec, {})["protections"]}["route-auth"]
    said_open = [(f["file"], f["line"]) for f in sec["findings"] if f["rule"] == "LW-AUTH-MISSING"]
    assert card["status"] == status, card
    if status == "add":
        assert said_open == [(name, at)]
        assert card["evidence"] == [f"{route} ({name}:{at})"]
        assert card["found"] == []
    else:
        assert said_open == []
        assert card["evidence"] == []
        assert card["found"] == [f"{route}: {found}"]


def test_the_login_card_names_the_open_route_beside_one_that_checks(tmp_path):
    """Two routes in one file: one only reads the token, one checks it with the server's key. The card names the
    first as open and the second as checked, as the findings do."""
    text = CARD_FA_HEAD + CARD_FA_DROP.replace("WHO", CARD_READ) + "\n\n" + \
        CARD_FA_DROP.replace("WHO", CARD_CHECKED).replace("@app.delete(", "@app.put(").replace("def drop", "def keep")
    _write(tmp_path, {"pyproject.toml": CARD_FASTAPI, "main.py": text})
    at = text.split("@app.delete(")[0].count("\n") + 1
    g = build_graph(tmp_path)
    sec = scan(g)
    card = {p["id"]: p for p in assess(g, sec, {})["protections"]}["route-auth"]
    assert [(f["file"], f["line"]) for f in sec["findings"] if f["rule"] == "LW-AUTH-MISSING"] == [("main.py", at)]
    assert card["status"] == "add", card
    assert card["evidence"] == [f"{CARD_FA} (main.py:{at})"]
    assert card["found"] == ["PUT /notes/{note_id}: calls `jwt.decode`"]


def test_results_written_before_the_scan_named_the_logins_read_as_before(tmp_path):
    """A `security.json` an older Lantern wrote has no `logins_shown`: the card reads the names, as it did."""
    files, *_ = CARD["express, in place: a check with a plain name put on with use"]
    _write(tmp_path, files)
    g = build_graph(tmp_path)
    sec = scan(g)
    assert g.nodes[sec["logins_shown"][0]].entry["detail"] == CARD_JS and len(sec["logins_shown"]) == 1
    old = {k: v for k, v in sec.items() if k != "logins_shown"}
    card = {p["id"]: p for p in assess(g, old, {})["protections"]}["route-auth"]
    assert card["status"] == "check" and card["evidence"] == [f"{CARD_JS} (server.js:13)"], card


CARD_NEW_KEY = ("import secrets\nimport sqlite3\nfrom fastapi import FastAPI\n\napp = FastAPI()\n"
                "db = sqlite3.connect('keys.db')\n\n\n@app.post('/keys')\ndef new_key(name: str):\n"
                "    key = secrets.token_urlsafe(32)\n    db.execute('INSERT INTO keys (key, name) VALUES (?, ?)', "
                "(key, name))\n    return {'key': key}\n")


def test_a_route_that_makes_a_random_key_does_not_read_as_checked(tmp_path):
    """`secrets.token_urlsafe` makes random text. Until 2026-11-11 the word `token` in its name made the card say
    "in place: calls `secrets.token_urlsafe`" for a route anybody may call."""
    _write(tmp_path, {"pyproject.toml": CARD_FASTAPI, "main.py": CARD_NEW_KEY})
    at = CARD_NEW_KEY.split("@app.post(")[0].count("\n") + 1
    g = build_graph(tmp_path)
    card = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}["route-auth"]
    assert card["status"] == "add", card
    assert card["evidence"] == [f"POST /keys (main.py:{at})"]
