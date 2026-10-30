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
        p.write_text(text)


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
])
def test_bridge_matching(call, routes, want, conf):
    rs = []
    for i, r in enumerate(routes):
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
        ".env.local": "VITE_ADMIN_PASSWORD=hunter2\nVITE_APP_NAME=x\n",                   # yes, once
    })
    found = sorted((f["file"], f["snippet"]) for f in scan(build_graph(tmp_path))["findings"]
                   if f["rule"] == "LW-PUBLIC-SECRET")
    assert found == [(".env.local", "VITE_ADMIN_PASSWORD"), ("src/a.ts", "NEXT_PUBLIC_STRIPE_SECRET_KEY"),
                     ("src/c.svelte", "PUBLIC_API_SECRET")]
