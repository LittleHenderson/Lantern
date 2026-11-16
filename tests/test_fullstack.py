import base64
import json
from pathlib import Path

import pytest

from lantern.bridge import match
from lantern.engine import build_graph
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def edge(g, src, dst):
    for e in g.call_edges():
        if e.src == src and e.dst == dst:
            return e
    return None


def entries(g):
    return {n.id: n.entry for n in g.entry_points()}


# ---------------------------------------------------------------- React + FastAPI (shop)

@pytest.fixture(scope="module")
def shop():
    g = build_graph(FIX / "shop")
    return g, scan(g)


def test_languages_detected(shop):
    g, _ = shop
    assert set(g.meta["languages"]) == {"python", "typescript/javascript"}


def test_spa_entries(shop):
    g, _ = shop
    e = entries(g)
    assert e["js:web/src/main"]["kind"] == "main"
    assert e["js:web/src/pages/UserPage::UserPage"] == {"kind": "page", "detail": "/users/:id"}
    assert e["js:web/src/pages/Admin::Admin"] == {"kind": "page", "detail": "/admin"}


def test_component_tree_and_alias_imports(shop):
    g, _ = shop
    assert edge(g, "js:web/src/App::App", "js:web/src/pages/UserPage::UserPage").via == "jsx-render"   # @/ alias
    assert edge(g, "js:web/src/pages/Admin::Admin", "js:web/src/pages/Admin::BackupButton").via == "jsx-render"
    e = edge(g, "js:web/src/pages/Admin::BackupButton", "js:web/src/pages/Admin::BackupButton.start")
    assert e.via == "ui-event" and e.detail == "onClick"
    assert edge(g, "js:web/src/pages/Admin::BackupButton.start", "js:web/src/api::runBackup") is not None  # ../ import


def test_http_bridge_to_python(shop):
    g, _ = shop
    e = edge(g, "js:web/src/api::runBackup", "py:shop.app.backup")
    assert e.confidence == "resolved" and e.via == "http-exact" and e.detail == "POST /backup"
    e = edge(g, "js:web/src/api::getUser", "py:shop.app.read_user")
    assert e.confidence == "inferred" and e.via == "http-suffix"     # /api prefix added elsewhere
    assert edge(g, "js:web/src/api::getWeather", "ext:HTTP GET api.weather.example.com") is not None


def test_backend_finding_has_ui_path(shop):
    _, s = shop
    (f,) = [f for f in s["findings"] if f["rule"] == "B602"]
    assert f["ui_path"] == ["js:web/src/pages/Admin::Admin", "js:web/src/pages/Admin::BackupButton",
                            "js:web/src/pages/Admin::BackupButton.start", "js:web/src/api::runBackup",
                            "py:shop.app.backup"]


def test_frontend_findings(shop):
    _, s = shop
    rules = {(f["rule"], f["file"]) for f in s["findings"]}
    assert ("LJ-XSS-HTML", "web/src/components/Bio.tsx") in rules
    assert ("LW-PUBLIC-SECRET", "web/src/pages/Admin.tsx") in rules
    assert ("LW-AUTH-MISSING", "shop/app.py") in rules        # POST /backup, no login check


# ---------------------------------------------------------------- Next.js + Supabase

@pytest.fixture(scope="module")
def nextapp():
    g = build_graph(FIX / "nextapp")
    return g, scan(g)


def test_next_routes_and_pages(nextapp):
    g, _ = nextapp
    e = entries(g)
    assert e["js:app/page::Home"] == {"kind": "page", "detail": "/"}
    assert e["js:app/todos/[id]/page::TodoPage"] == {"kind": "page", "detail": "/todos/[id]"}
    assert e["js:app/api/todos/route::POST"] == {"kind": "route", "detail": "POST /api/todos"}
    assert e["js:app/api/todos/[id]/route::DELETE"] == {"kind": "route", "detail": "DELETE /api/todos/[id]"}


def test_next_bridge(nextapp):
    g, _ = nextapp
    assert edge(g, "js:components/TodoList::TodoList.addTodo", "js:app/api/todos/route::POST").confidence == "resolved"
    assert edge(g, "js:components/TodoList::TodoList.removeTodo", "js:app/api/todos/[id]/route::DELETE") is not None
    assert edge(g, "js:app/todos/[id]/page::TodoPage", "js:app/api/todos/[id]/route::GET") is not None  # localhost URL


def test_next_security(nextapp):
    _, s = nextapp
    by_rule = {}
    for f in s["findings"]:
        by_rule.setdefault(f["rule"], []).append(f)
    (auth,) = by_rule["LW-AUTH-MISSING"]
    assert auth["file"] == "app/api/todos/[id]/route.ts"              # DELETE has no check
    assert "POST" not in auth["title"]                                 # POST calls getSessionUser
    assert auth["ui_path"][0] == "js:app/page::Home"
    (rls,) = by_rule["LW-NO-RLS"]
    assert "'todos'" in rls["title"]                                   # profiles has RLS, todos doesn't
    assert any("SERVICE_ROLE" in f["title"] for f in by_rule["LW-PUBLIC-SECRET"])


# ---------------------------------------------------------------- focused cases

def _jwt(payload):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.{'s' * 43}"


def test_service_role_key_and_open_firebase(tmp_path):
    _write(tmp_path, {
        "package.json": '{"dependencies": {"@supabase/supabase-js": "2"}}',
        "src/supabase.ts": f'export const admin = createClient(url, "{_jwt({"role": "service_role"})}")\n'
                           f'export const anon = createClient(url, "{_jwt({"role": "anon"})}")\n',
        "firestore.rules": "service cloud.firestore {\n  match /{doc=**} {\n    allow read, write: if true;\n  }\n}\n",
    })
    s = scan(build_graph(tmp_path))
    ranks = {(f["rule"], f["rank"]) for f in s["findings"]}
    assert ("LW-SERVICE-ROLE", "critical") in ranks
    assert ("LW-DB-OPEN", "critical") in ranks
    assert not any(f["rule"] == "LW-JWT" for f in s["findings"])      # anon key is public by design


def test_cors_wildcard_with_credentials(tmp_path):
    _write(tmp_path, {"main.py": (
        "from fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\napp = FastAPI()\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n")})
    (f,) = [f for f in scan(build_graph(tmp_path))["findings"] if f["rule"] == "LW-CORS-ANY"]
    assert f["rank"] == "high"


def test_express_server_and_barrel_exports(tmp_path):
    _write(tmp_path, {
        "package.json": '{"dependencies": {"express": "4"}}',
        "server/index.js": (
            "const express = require('express')\nconst { listUsers } = require('./users')\n"
            "import { audit } from './lib'\n"
            "const app = express()\n"
            "app.get('/users', listUsers)\n"
            "app.post('/users/:id/ban', async (req, res) => { audit(req.params.id); res.send('ok') })\n"
            "app.listen(3000)\n"),
        "server/lib/index.js": "export * from './audit'\n",
        "server/lib/audit.js": "export function audit(id) { return id }\n",
        "server/users.js": "export function listUsers(req, res) { res.json([]) }\n",
    })
    g = build_graph(tmp_path)
    e = entries(g)
    ban = next(k for k, v in e.items() if v["detail"] == "POST /users/:id/ban")
    assert edge(g, ban, "js:server/lib/audit::audit") is not None      # through `export *` barrel
    assert e["js:server/index"]["kind"] == "main"


def test_tanstack_file_route_and_generated_client(tmp_path):
    _write(tmp_path, {
        "frontend/package.json": '{"dependencies": {"@tanstack/react-router": "1"}}',
        "frontend/tsconfig.json": '{"compilerOptions": {"paths": {"@/*": ["./src/*"]}}}',
        "frontend/src/client/sdk.gen.ts": (
            "export class ItemsService {\n"
            "  public static readItem(options: any) {\n"
            "    return (options.client ?? client).get<any>({ url: '/api/v1/items/{id}', ...options })\n"
            "  }\n}\n"),
        "frontend/src/client/index.ts": "export * from './sdk.gen'\n",
        "frontend/src/routes/_layout/items.tsx": (
            "import { createFileRoute } from '@tanstack/react-router'\nimport { ItemsService } from '@/client'\n"
            "export const Route = createFileRoute('/_layout/items')({ component: Items })\n"
            "function Items() { const q = ItemsService.readItem({ path: { id: 1 } }); return <div/> }\n"),
        "backend/app/items.py": (
            "from fastapi import APIRouter\nrouter = APIRouter(prefix='/items')\n\n"
            "@router.get('/{id}')\ndef read_item(id: int):\n    return id\n"),
    })
    g = build_graph(tmp_path)
    assert entries(g)["js:frontend/src/routes/_layout/items::Items"] == {"kind": "page", "detail": "/items"}
    assert edge(g, "js:frontend/src/routes/_layout/items::Items",
                "js:frontend/src/client/sdk.gen::ItemsService.readItem") is not None
    e = edge(g, "js:frontend/src/client/sdk.gen::ItemsService.readItem", "py:backend.app.items.read_item")
    assert e is not None and e.detail == "GET /api/v1/items/{}"


@pytest.mark.parametrize("call,routes,want,conf", [
    (("GET", "/api/v1/users/{}", False), ["GET /users/{user_id}", "GET /users/me"], ["GET /users/{user_id}"], "inferred"),
    (("GET", "/users/me", False), ["GET /users/{user_id}", "GET /users/me"], ["GET /users/me"], "resolved"),
    (("POST", "/items", False), ["GET /items"], [], ""),                       # wrong method
    (("GET", "/x", True), ["GET /api/x"], ["GET /api/x"], "inferred"),         # ${API}/x
    (("GET", "/{}", False), ["GET /{id}"], [], ""),                           # all-wildcard proves nothing
    (("ANY", "/things/{}", False), ["GET /things/{id}", "DELETE /things/{id}"],   # verb unreadable: both,
     ["GET /things/{id}", "DELETE /things/{id}"], "possible"),                   # never a confirmed link
    (("ANY", "/things/{}", False), ["GET /things/{id}"], ["GET /things/{id}"], "inferred"),
])
def test_bridge_matching(call, routes, want, conf):
    rs = []
    for r in routes:
        verb, path = r.split(" ")
        from lantern.bridge import _segs
        rs.append({"id": r, "verbs": {verb}, "segs": _segs(path), "detail": r})
    hits, c, _ = match({"method": call[0], "path": call[1], "prefix_unknown": call[2]}, rs)
    assert [h["id"] for h in hits] == want and c == conf


def test_public_secret_only_in_env_contexts(tmp_path):
    _write(tmp_path, {
        "rules.py": 'PUBLIC_SECRET_RE = 1\nVITE_PASSWORD_HINT_TEXT = "x"\n',            # identifiers: no
        "src/a.ts": "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\n",               # yes
        "src/b.ts": "const u = import.meta.env.VITE_SUPABASE_ANON_KEY\n",                 # anon is public: no
        "src/c.svelte": "<script>import { PUBLIC_API_SECRET } from '$env/static/public'</script>\n",  # yes
        "src/d.ts": "const o = import.meta.env.VITE_OPENAI_API_KEY\n",                     # a paid key: yes
        "src/e.ts": ("const f = import.meta.env.VITE_FIREBASE_API_KEY\n"                   # browser keys: no
                     "const m = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY\n"),
        ".env.local": "VITE_ADMIN_PASSWORD=hunter2\nVITE_APP_NAME=x\n",                   # yes, once
    })
    found = sorted((f["file"], f["snippet"]) for f in scan(build_graph(tmp_path))["findings"]
                   if f["rule"] == "LW-PUBLIC-SECRET")
    assert found == [(".env.local", "VITE_ADMIN_PASSWORD"), ("src/a.ts", "NEXT_PUBLIC_STRIPE_SECRET_KEY"),
                     ("src/c.svelte", "PUBLIC_API_SECRET"), ("src/d.ts", "VITE_OPENAI_API_KEY")]


def test_unreadable_http_verb_is_not_guessed_as_get(tmp_path):
    """`fetch(url, opts)` with opts defined elsewhere: the verb is unknown, so no confirmed link to the GET route."""
    _write(tmp_path, {
        "web/package.json": '{"dependencies": {"react": "18"}}',
        "web/src/api.ts": (
            "const deleteOpts = { method: 'DELETE' }\n"
            "export const deleteThing = (id) => fetch(`/things/${id}`, deleteOpts)\n"
            "export const getThing = (id) => fetch(`/things/${id}`)\n"
            "export const postThing = (b) => fetch('/things', { method: 'POST', body: b })\n"),
        "app/main.py": (
            "from fastapi import FastAPI\napp = FastAPI()\n\n"
            "@app.get('/things/{thing_id}')\ndef get_thing(thing_id: int):\n    return 1\n\n"
            "@app.delete('/things/{thing_id}')\ndef delete_thing(thing_id: int):\n    return 1\n\n"
            "@app.post('/things')\ndef make_thing():\n    return 1\n"),
    })
    g = build_graph(tmp_path)
    d = [e for e in g.call_edges() if e.src == "js:web/src/api::deleteThing" and e.dst.startswith("py:")]
    assert {e.dst for e in d} == {"py:app.main.get_thing", "py:app.main.delete_thing"}
    assert all(e.confidence == "possible" for e in d)
    assert edge(g, "js:web/src/api::getThing", "py:app.main.get_thing").confidence == "resolved"
    assert edge(g, "js:web/src/api::postThing", "py:app.main.make_thing").confidence == "resolved"


def test_missing_auth_reads_the_handler_not_its_comments(tmp_path):
    """LW-AUTH-MISSING and the protections advisor share one reading of a route: a comment or a user lookup by a
    request value is not a login check, `req.user` in the body is."""
    _write(tmp_path, {
        "package.json": '{"dependencies": {"express": "4"}}',
        "server.js": (
            "const express = require('express')\nconst { getUser } = require('./users')\nconst app = express()\n"
            "app.post('/notes', async (req, res) => {\n  // auth: TODO add a session check\n  res.send('ok')\n})\n"
            "app.delete('/notes/:id', async (req, res) => {\n  const owner = await getUser(req.body.owner)\n"
            "  if (!owner) return res.status(404).end()\n  res.send('ok')\n})\n"
            "app.put('/notes/:id', async (req, res) => {\n  if (!req.user.isAdmin) return res.status(403).end()\n"
            "  res.send('ok')\n})\n"
            "app.listen(3000)\n"),
        "users.js": "export function getUser(id) { return id }\n",
        "web/app.js": (
            "export async function save(text) { await fetch('/notes', {method: 'POST', body: text}) }\n"
            "export async function remove(id) { await fetch('/notes/' + id, {method: 'DELETE'}) }\n"
            "export async function rename(id) { await fetch('/notes/' + id, {method: 'PUT'}) }\n"),
    })
    s = scan(build_graph(tmp_path))
    auth = {f["line"]: f for f in s["findings"] if f["rule"] == "LW-AUTH-MISSING"}
    assert sorted(auth) == [4, 8], auth.keys()                          # POST (comment only) and DELETE (lookup)
    assert ("The only sign in the handler is that `getUser(req.body.owner)` looks up a user by `req.body.owner`, "
            "not by who is calling: that finds a record, not the caller.") in auth[8]["more_info"]
    assert "only sign" not in auth[4]["more_info"]


def test_a_login_put_on_the_app_counts_for_the_routes_written_after_it(tmp_path):
    """`app.use(requireLogin)` runs before every route written after it, and before none written above it. Until
    2026-11-11 it counted for no route, so every changing route of such an app read as open."""
    _write(tmp_path, {
        "package.json": '{"dependencies": {"express": "4"}}',
        "server.js": (
            "const express = require('express')\nconst app = express()\n"
            "function requireLogin (req, res, next) {\n  if (!req.session.userId) return res.status(401).end()\n"
            "  next()\n}\n"
            "app.post('/feedback', async (req, res) => {\n  res.send('ok')\n})\n"
            "app.use(requireLogin)\n"
            "app.post('/notes', async (req, res) => {\n  res.send('ok')\n})\n"
            "app.delete('/notes/:id', async (req, res) => {\n  res.send('ok')\n})\n"
            "app.listen(3000)\n"),
        "web/app.js": (
            "export async function tell(text) { await fetch('/feedback', {method: 'POST', body: text}) }\n"
            "export async function save(text) { await fetch('/notes', {method: 'POST', body: text}) }\n"
            "export async function remove(id) { await fetch('/notes/' + id, {method: 'DELETE'}) }\n"),
    })
    from lantern.readiness import assess
    g = build_graph(tmp_path)
    s = scan(g)
    auth = [(f["line"], f["title"]) for f in s["findings"] if f["rule"] == "LW-AUTH-MISSING"]
    assert auth == [(7, "POST /feedback changes data, is called by the app, and no login check was found")], auth
    p = next(p for p in assess(g, s, {})["protections"] if p["id"] == "route-auth")
    assert p["found"] == ["POST /notes: middleware `requireLogin` put on before this route (server.js:10)",
                          "DELETE /notes/:id: middleware `requireLogin` put on before this route (server.js:10)"], p
    assert p["status"] == "add" and p["evidence"] == ["POST /feedback (server.js:7)"], p


def test_what_counts_as_a_login_check_in_a_handler():
    """The rules behind `LW-AUTH-MISSING` and the `route-auth` protection, read straight from a handler's lines.
    Request data and the names that hold it are data, an auth word is a check only as a call or an attribute, and a
    user lookup identifies the caller only through a token, session, request, header or cookie (or no argument)."""
    from lantern.websec import body_auth_sign

    def sign(src, signature="def f(payload)", js=False):
        got = body_auth_sign(src, 1, src.count("\n"), js, signature=signature)
        return got[0] if got else None

    # what the caller sent is never a check, however it is named
    assert sign("def f(payload: dict):\n    permissions = payload.get('permissions')\n    if 'admin' in permissions:\n"
                "        return 1\n", "def f(payload: dict)") is None
    assert sign("def f(payload):\n    scopes = []\n    scopes += payload['scopes']\n    if permission in scopes:\n"
                "        return 1\n") is None
    assert sign("def f(permissions: list[str] = Body(), session: Session = Depends(get_session)):\n"
                "    permissions.append('x')\n    session.add(permissions)\n",
                "def f(permissions: list[str] = Body(), session: Session = Depends(get_session))") is None
    assert sign("app.post('/x', (req, res) => {\n  const auth = req.body.auth\n  if (auth) res.send('ok')\n})\n",
                "(req, res) =>", js=True) is None
    # a call or an attribute is
    assert sign("def f(request):\n    if not request.user.is_admin:\n        raise X\n", "def f(request)") == "strong"
    assert sign("def f(payload):\n    authorize(request_user(), 'x')\n") == "strong"
    assert sign("def f(payload):\n    token = payload['token']\n    verify_token(token)\n") == "strong"
    assert sign("export async function DELETE(req) {\n  const session = await getServerSession(authOptions)\n"
                "  if (!session) return new Response('no', {status: 401})\n}\n", "async function DELETE(req)",
                js=True) == "strong"
    # a user lookup: by the caller's credential (strong), by a request value with a test (weak), untested (nothing)
    assert sign("def f(request):\n    kind = 'admin'\n    token = request.headers['Authorization']\n"
                "    user = get_user(token)\n    if not user:\n        abort(401)\n", "def f(request)") == "strong"
    assert sign("def f(token: str = Header()):\n    user = get_user(token)\n    if not user: abort(401)\n",
                "def f(token: str = Header())") == "strong"
    assert sign("def f(payload):\n    token = payload.get('token')\n    user = get_user_by_token(token)\n"
                "    if not user:\n        abort(401)\n") == "strong"
    assert sign("def f(payload):\n    u = get_user()\n    if not u: abort(401)\n") == "strong"
    assert sign("def f(payload):\n    token = payload.get('token')\n    user = get_user(token)\n    if not user:\n"
                "        abort(401)\n") == "weak"
    assert sign("def f(user_id: int):\n    u = get_user(user_id)\n    if not u: abort(404)\n", "def f(user_id: int)") == "weak"
    assert sign("def f(payload):\n    who = get_user(payload['owner'])\n    if not who:\n        abort(404)\n") == "weak"
    assert sign("def f(payload):\n    token = payload.get('token')\n    user = get_user(token)\n    return user\n") is None


def test_a_handlers_own_name_is_not_a_login_check():
    """What a route's function is called says what it is for, not that it asks who is calling. The line that defines
    a handler was read like any other line of it, so `def revoke_token(...)` "called" `revoke_token` and the route
    counted as asking for a login. The dangerous handlers first, each with the twin that does ask."""
    from lantern.websec import body_auth_sign, own_name

    def sign(src, signature, js=False):
        got = body_auth_sign(src, 1, src.count("\n"), js, signature=signature)
        return got[0] if got else None

    # Python: one line, async, a signature over several lines
    assert sign("def revoke_token(key_id: int):\n    db.delete(key_id)\n", "def revoke_token(key_id: int)") is None
    assert sign("async def auth_pickup(code: str):\n    return {'t': store.take(code)}\n",
                "async def auth_pickup(code: str)") is None
    assert sign("def reset_permissions(\n    team: int,\n    kind: str,\n):\n    db.wipe(team)\n",
                "def reset_permissions(team: int, kind: str)") is None
    # JavaScript and TypeScript: a declared function, a method of a class or an object
    assert sign("export async function logoutUser(req, res) {\n  db.sessions.clear(req.body.id)\n}\n",
                "logoutUser(req, res)", js=True) is None
    assert sign("  async refreshToken(req, res) {\n    res.json(await this.store.next(req.body.id))\n  }\n",
                "refreshToken(req, res)", js=True) is None
    # the other languages come the same way (the name before the parameters, after whatever stands before it)
    assert sign("public ResponseEntity<Void> deleteToken(@PathVariable long id) {\n    repo.deleteById(id);\n}\n",
                "public ResponseEntity<Void> deleteToken(@PathVariable long id)", js=True) is None
    assert sign("func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {\n\th.db.Delete(id)\n}\n",
                "func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request)", js=True) is None
    assert sign("pub async fn delete_token(Path(id): Path<i64>) -> StatusCode {\n    db::delete(id).await\n}\n",
                "pub async fn delete_token(Path(id): Path<i64>) -> StatusCode", js=True) is None
    # the twins: the same handlers with a check in them keep their sign
    assert sign("def revoke_token(key_id: int):\n    authorize(request_user(), 'keys')\n    db.delete(key_id)\n",
                "def revoke_token(key_id: int)") == "strong"
    assert sign("export async function logoutUser(req, res) {\n  if (!req.user) return res.sendStatus(401)\n"
                "  db.sessions.clear(req.user.id)\n}\n", "logoutUser(req, res)", js=True) == "strong"
    assert sign("func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {\n\tif !h.isAdmin(r) {\n"
                "\t\treturn\n\t}\n}\n", "func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request)",
                js=True) == "strong"
    # only the defining line: a handler that calls a function of that name further down is read as before
    assert sign("def check_auth(x):\n    return 1\n\n\ndef f(payload):\n    check_auth(payload)\n", "def f(payload)") == "strong"
    assert sign("def require_login(depth: int):\n    return require_login(depth - 1)\n",
                "def require_login(depth: int)") == "strong"
    # the name a first line gives
    assert [own_name(x) for x in ("def revoke_token(key_id: int)", "async def a(b)", "POST(req: Request)",
                                  "func (h *Handler) DeleteToken(w, r)", "pub async fn delete_token(x: i64) -> S",
                                  "public ResponseEntity<Void> deleteToken(long id)", "fun deleteToken(id: Long)")] == \
        ["revoke_token", "a", "POST", "DeleteToken", "delete_token", "deleteToken", "deleteToken"]
    assert [own_name(x) for x in ("(req, res) =>", "async (req, res) =>", "function (req, res)", "", "x = 1")] == [""] * 5


PICKUP_PY = """import hmac
from fastapi import Depends, FastAPI, HTTPException

from .store import current_user, fingerprint, issue_token, store

app = FastAPI()


@app.get("/pickup")
def pickup(code: str):
    tok = store.take(code)
    if tok is None:
        raise HTTPException(404)
    return {"token": tok}


@app.get("/pickup-inline")
def pickup_inline(code: str):
    return {"access_token": store.take(code)}


@app.post("/redeem")
def redeem(code: str, verifier: str):
    row = store.take(code)
    if row is None or not hmac.compare_digest(row.challenge, fingerprint(verifier)):
        raise HTTPException(400)
    return {"token": issue_token(row.account)}


@app.post("/login")
def login(username: str, password: str):
    user = store.user(username)
    if not user or not user.check(password):
        raise HTTPException(401)
    return {"token": issue_token(user)}


@app.get("/my-key")
def my_key(name: str, user=Depends(current_user)):
    key = store.key(name)
    return {"api_key": key}


@app.post("/refresh")
def refresh(refresh_token: str):
    tok = store.next(refresh_token)
    return {"token": tok}


@app.post("/guest")
def guest(name: str):
    tok = issue_token(name)
    return {"token": tok}


@app.get("/note")
def note(note_id: str):
    title = store.title(note_id)
    return {"title": title}


@app.get("/pair")
def pair(code: str, device: str):
    tok = store.take(code)
    return {"token": tok, "device": device}
"""
PICKUP_FLASK = """from flask import Flask, jsonify, request, session

app = Flask(__name__)
PENDING = {}


@app.route("/claim")
def claim():
    code = request.args.get("code")
    return jsonify(token=PENDING.pop(code, None))


@app.route("/mine")
def mine():
    code = request.args.get("code")
    if session.get("user") is None:
        return "", 401
    return jsonify(token=PENDING.pop(code, None))


@app.route("/handed-on", methods=["POST"])
def handed_on():
    return jsonify(token=finish(request.get_json()))
"""
PICKUP_JS = """const express = require('express')
const app = express()
const pending = new Map()

app.get('/pickup', async (req, res) => {
  const token = await pending.get(req.query.code)
  if (!token) return res.status(404).end()
  res.json({ token })
})

app.get('/pickup2', (req, res) => {
  const { code } = req.query
  const found = pending.get(code)
  res.json({ access_token: found })
})

app.post('/redeem', (req, res) => {
  const { code, verifier } = req.body
  const row = pending.get(code)
  if (!row || !crypto.timingSafeEqual(row.challenge, hash(verifier))) return res.status(400).end()
  res.json({ token: issue(row.account) })
})

app.get('/me/key', (req, res) => {
  const key = keys.get(req.query.name)
  if (!req.session.userId) return res.status(401).end()
  res.json({ apiKey: key })
})

app.post('/login', (req, res) => {
  const user = users.get(req.body.email)
  res.json({ token: jwt.sign({ id: user.id }, SECRET) })
})

app.listen(3000)
"""


def test_a_login_handed_to_whoever_sends_one_value_is_named_and_its_safe_twins_are_not(tmp_path):
    """`LW-TOKEN-PICKUP`: a route that fetches a stored credential with one plain value of the request and sends it
    back, asking for nothing else. The safe twins: a second proof (a verifier compared, a password), a caller the
    route identifies (a dependency, a session), a value that is itself a credential (a refresh token), a credential
    made on the spot, something that is no credential, two values asked for, and a body handed on unread."""
    _write(tmp_path, {"server/__init__.py": "", "server/api.py": PICKUP_PY, "server/web.py": PICKUP_FLASK,
                      "api/package.json": '{"dependencies": {"express": "^4.19.0"}}', "api/server.js": PICKUP_JS})
    g = build_graph(tmp_path)
    found = sorted((f["file"], f["line"], f["title"].partition(" hands back")[0], f["snippet"])
                   for f in scan(g)["findings"] if f["rule"] == "LW-TOKEN-PICKUP")
    assert found == [
        ("api/server.js", 6, "GET /pickup", "const token = await pending.get(req.query.code)"),
        ("api/server.js", 13, "GET /pickup2", "const found = pending.get(code)"),
        ("server/api.py", 11, "GET /pickup", "tok = store.take(code)"),
        ("server/api.py", 19, "GET /pickup-inline", 'return {"access_token": store.take(code)}'),
        ("server/web.py", 10, "GET /claim", "return jsonify(token=PENDING.pop(code, None))"),
    ], found
    one = next(f for f in scan(g)["findings"] if f["rule"] == "LW-TOKEN-PICKUP" and f["file"] == "server/api.py")
    assert one["tool_confidence"] == "LOW" and one["rank"] == "medium" and one["cwe"] == 639
    assert "one value the caller sends (`code`)" in one["title"] and "Heuristic" in one["more_info"]
    assert "`store.take`" in one["more_info"] and "second thing only they hold" in one["more_info"]
    story = one["scenario"]
    assert "whoever sends" in story["harm"] and "POST" not in story["harm"], story


def test_login_check_reads_hostile_code_in_bounded_time():
    """The handler-reading regexes (strings, request-data chains, name blanking, lookups) must stay linear on code
    built to make them backtrack: unbalanced brackets, long attribute chains, escaped quotes, thousands of names."""
    import time
    from lantern.websec import body_auth_sign

    hostile = ["def f(payload, params):"]
    hostile.append("    x = payload" + ".a" * 3000)
    hostile.append("    y = payload(" + "(" * 2000)
    hostile.append("    z = \"" + "\\\"" * 5000)
    hostile.append("    w = params[" + "[" * 3000)
    hostile.append("    v = params" + "(a)" * 1500)
    hostile.append("    u = `" + "${payload." * 500)
    hostile += [f"    a{i} = a{i - 1} if a{i - 1} else payload.get('k')" for i in range(1, 1500)]
    hostile += [f"    who{i} = get_user(a{i})" for i in range(0, 1500, 5)]
    hostile.append("    if not who5:\n        raise ValueError")
    src = "\n".join(hostile) + "\n"
    assert len(src) > 100_000
    t = time.perf_counter()
    for js in (False, True):
        body_auth_sign(src, 1, src.count("\n"), js, signature="def f(payload, params)")
    took = time.perf_counter() - t
    assert took < 5, f"{took:.1f}s on {len(src):,} bytes"


# ---- script written inside HTML files (the app's own pages, Jinja/Django templates, a plain index.html) ----
HTML_APP = {
    "app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/api/items')\ndef list_items():\n    return []\n",
    "app/templates/index.html": """<!doctype html>
<title>Shop</title>
<script type="application/json" id="cfg">{"notScript": function(){}}</script>
<script src="/static/vendor.js"></script>
<div id="list"></div>
<script>
function render(items) {
  document.getElementById('list').innerHTML = items.map(i => i.name).join(', ');
}
async function load() {
  const r = await fetch('/api/items');
  render(await r.json());
}
document.getElementById('list').onclick = () => load();
load();
</script>
""",
    "app/static/vendor.min.js": "x=1",
}


def test_script_inside_html_is_read_and_linked_to_the_backend(tmp_path):
    _write(tmp_path, HTML_APP)
    g = build_graph(tmp_path)
    page, load, render = "js:app/templates/index.html", "js:app/templates/index.html::load", "js:app/templates/index.html::render"
    assert {page, load, render} <= set(g.nodes)
    assert g.nodes[load].file == "app/templates/index.html" and g.nodes[load].start_line == 10   # the HTML file's own line numbers
    assert g.nodes[page].entry == {"kind": "page", "detail": "app/templates/index.html"}
    assert g.nodes[page].lane == "browser" and g.nodes[load].lane == "frontend"
    assert edge(g, load, render) is not None
    assert g.meta["http_calls"][0]["src"] == load and g.meta["http_calls"][0]["path"] == "/api/items"
    assert edge(g, load, "py:app.main.list_items").via == "http-exact"                        # the bridge
    assert g.meta["lanes"]["browser"] == 1 and g.meta["lanes"]["frontend"] == 2
    assert not any("notScript" in n or "vendor" in n for n in g.nodes)        # JSON blocks, src= tags and .min.js are left out
    # the pattern rules still read only .js/.ts files (running them on pages is a separate decision: a page that
    # builds itself with innerHTML from escaped values would light up on every line)
    assert not any(f["rule_id"].startswith("LJ-") for f in scan(g)["findings"])


def test_a_function_wrapped_in_as_or_parentheses_is_read_without_a_crash(tmp_path):
    """From the mobile benchmark: a React Native app (mattermost-mobile) wrote `const X = ((p) => …) as Fn` and
    the reader crashed looking for the wrapper call's name."""
    _write(tmp_path, {
        "package.json": '{"dependencies": {"react": "18"}}',
        "src/a.tsx": "type P = {n: number};\nexport const A = ((p: P) => <b>{p.n}</b>) as React.FC<P>;\n"
                     "export const B = (function () { return 1; });\nconst C = (() => A({n: 1})) satisfies () => unknown;\n"
                     "export default function App() { return <A n={1}/>; }\n",
    })
    g = build_graph(tmp_path)
    assert {"js:src/a::A", "js:src/a::B", "js:src/a::C"} <= set(g.nodes)
    assert edge(g, "js:src/a::C", "js:src/a::A") is not None
