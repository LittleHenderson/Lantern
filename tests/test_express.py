"""CommonJS and Express (2026-11-09 directive, stage 3): `require()`, `module.exports`, routers mounted with
`app.use`, route handlers and middleware handed to the router, and the framework's `req`/`res`/`next`.

Before stage 3 the JavaScript reader knew only ES `import`/`export`, so an Express app written with `require()` had
almost every call unresolved (four public Express apps: 78-98%) and its route handlers were not linked to the routes.
Each case below has a twin that must not be linked: a name Lantern cannot follow stays unresolved, with its reason."""

import pytest

from lantern.engine import build_graph


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _g(tmp_path, files):
    _write(tmp_path, {"package.json": '{"dependencies": {"express": "4.19.2", "mysql2": "3.9.7", "joi": "17.13.1"}}',
                      **files})
    return build_graph(tmp_path)


def _sites(g, callee, file=None, group="written"):
    return [s for s in g.sites if s["group"] == group and s["callee"] == callee and (file is None or s["file"] == file)]


def _one(g, callee, file=None, group="written"):
    hits = _sites(g, callee, file, group)
    assert len(hits) == 1, (callee, hits)
    return hits[0]


def _edge(g, src, dst):
    return next((e for e in g.call_edges() if e.src == src and e.dst == dst), None)


NOTES = {
    "lib/pool.js": "const mysql = require('mysql2')\nmodule.exports = mysql.createPool({ host: 'localhost' })\n",
    "lib/guard.js": ("exports.signedIn = function (req, res, next) {\n  if (req.session && req.session.user) return next()\n"
                     "  res.status(401).end()\n}\n"),
    "lib/notes.js": (
        "const { join } = require('path')\n"
        "const run = require('child_process').execFile\n"
        "const pool = require('./pool')\n"
        "\n"
        "function list (req, res) {\n"
        "  pool.query('SELECT id FROM notes', function (err, rows) {\n"
        "    res.json(rows.map((r) => r.id))\n"
        "  })\n"
        "}\n"
        "\n"
        "const destroy = (req, res) => {\n"
        "  run('rm', [join('/tmp', req.params.id)])\n"
        "  res.status(204).end()\n"
        "}\n"
        "\n"
        "module.exports = { list, remove: destroy }\n"),
    "lib/view.js": "module.exports.show = function (req, res) {\n  res.send(req.query.id)\n}\n",
    "routes/notes.js": (
        "const express = require('express')\n"
        "const notes = require('../lib/notes')\n"
        "const view = require('../lib/view')\n"
        "const guard = require('../lib/guard')\n"
        "const router = express.Router()\n"
        "\n"
        "router.get('/', guard.signedIn, notes.list)\n"
        "router.get('/:id', view.show)\n"
        "router.delete('/:id', guard.signedIn, notes.remove)\n"
        "module.exports = router\n"),
    "routes/admin.js": (
        "module.exports = function (r) {\n"
        "  r.post('/reset', function (req, res) { res.send('ok') })\n"
        "  return r\n"
        "}\n"),
    "server.js": (
        "const express = require('express')\n"
        "const app = express()\n"
        "app.use(express.json())\n"
        "app.use('/api/notes', require('./routes/notes'))\n"
        "app.use('/admin', require('./routes/admin')(express.Router()))\n"
        "app.listen(8080)\n"),
}


@pytest.fixture
def notes(tmp_path):
    return _g(tmp_path, NOTES)


def test_require_binds_packages_and_repo_modules(notes):
    assert _one(notes, "join")["to"] == ["ext:path.join"]
    assert _one(notes, "run")["to"] == ["ext:child_process.execFile"]
    q = _one(notes, "pool.query")       # pool.js exports what mysql.createPool() returned
    assert (q["outcome"], q["to"], q["via"]) == ("external", ["ext:mysql2.createPool().query"], "library-value")
    assert _one(notes, "express", file="server.js")["to"] == ["ext:express"]
    assert len(_sites(notes, "app.use", "server.js")) == 3
    assert all(s["outcome"] == "external" and s["to"] == ["ext:express().use"] for s in _sites(notes, "app.use", "server.js"))


def test_module_exports_functions_become_nodes(notes):
    assert notes.nodes["js:lib/view::show"].kind == "callable"
    for name in ("list", "destroy"):
        assert notes.nodes[f"js:lib/notes::{name}"].kind == "callable"
    assert notes.nodes["js:lib/guard::signedIn"].kind == "callable"


def test_router_handlers_get_their_full_paths_and_a_link(notes):
    det = {n.id: n.entry["detail"] for n in notes.nodes.values() if n.entry and n.entry["kind"] == "route"}
    assert det["js:lib/notes::list"] == "GET /api/notes"
    assert det["js:lib/view::show"] == "GET /api/notes/:id"
    assert det["js:lib/notes::destroy"] == "DELETE /api/notes/:id"
    assert det["js:routes/admin::default.post_reset"] == "POST /admin/reset"
    e = _edge(notes, "js:routes/notes", "js:lib/notes::list")
    assert e is not None and e.via == "route-handler" and e.confidence == "resolved"
    assert _edge(notes, "js:routes/notes", "js:lib/notes::destroy").via == "route-handler"


def test_middleware_is_linked_and_listed_on_the_route(notes):
    e = _edge(notes, "js:routes/notes", "js:lib/guard::signedIn")
    assert e is not None and e.via == "middleware"
    assert notes.nodes["js:lib/notes::destroy"].entry["middleware"] == ["js:lib/guard::signedIn"]
    assert "middleware" not in notes.nodes["js:lib/view::show"].entry


def test_a_router_factory_is_called_and_its_routes_mounted(notes):
    e = _edge(notes, "js:server", "js:routes/admin::default")
    assert e is not None and e.via == "require-call"


def test_express_request_response_and_next_are_framework_calls(notes):
    s = _one(notes, "res.send", file="lib/view.js")
    assert (s["outcome"], s["to"], s["via"], s["confidence"]) == (
        "external", ["ext:express.Response.send"], "express-param", "inferred")
    assert _one(notes, "next", file="lib/guard.js")["to"] == ["ext:express.next"]
    chained = _one(notes, "res.status(204).end", file="lib/notes.js")
    assert chained["outcome"] == "external" and chained["via"] == "library-result"


def test_inline_callback_parameters_stay_unresolved_with_a_reason(notes):
    # `rows` is a parameter of a callback handed to pool.query: Lantern does not pretend to know what the library passes
    s = _one(notes, "rows.map", file="lib/notes.js")
    assert (s["outcome"], s["reason"]) == ("unresolved", "parameter")
    assert _one(notes, "res.json", file="lib/notes.js")["outcome"] == "external"   # res is still the handler's response
    w = notes.meta["calls"]["written"]
    assert w["outcomes"]["unresolved"] == sum(1 for x in notes.sites if x["group"] == "written" and not x["test"]
                                              and x["outcome"] == "unresolved")
    assert sum(w["outcomes"].values()) == w["total"]


def test_unknown_values_are_not_linked_by_name(tmp_path):
    g = _g(tmp_path, {
        "lib/a.js": "module.exports.list = function () { return 1 }\n",
        "lib/b.js": "module.exports.other = function () { return 2 }\n",
        "app.js": ("const b = require('./lib/b')\n"
                   "const make = require('./lib/factory-that-is-missing')\n"
                   "function go (svc) {\n  b.list()\n  make().list()\n  svc.list()\n}\n"
                   "module.exports = go\n"),
    })
    assert _one(g, "b.list")["reason"] == "missing-member"   # b.js exports no `list`; a.js's is not borrowed
    assert _one(g, "make().list")["outcome"] == "unresolved"
    assert _one(g, "svc.list")["reason"] == "parameter"
    assert not any(e.dst == "js:lib/a::list" for e in g.call_edges())


def test_a_require_outside_the_repo_or_built_at_run_time_is_not_guessed(tmp_path):
    g = _g(tmp_path, {"app.js": "const name = process.env.MOD\nconst mod = require(name)\nmod.start()\n"})
    s = _one(g, "mod.start")
    assert (s["outcome"], s["reason"]) == ("unresolved", "dynamic-require")


def test_a_path_alias_that_finds_no_file_names_a_project_file_not_a_library(tmp_path):
    """The tsconfig's `paths` says `generated/api` and `gen/...` are files of this project. When they are not there to
    read (a generated folder that is not committed), what the code imports from them is unknown, not "a library", and
    nothing is built on it. The twins: an alias that finds its file is followed; a package stays a library, also
    when a catch-all `*` alias or an alias into node_modules covers its name, and when an alias covers the name of a
    package the project depends on (`@acme/*` for its own packages beside `@acme/published` from npm; `joi` aliased to
    a shim that is not there: what runs is then the package)."""
    g = _g(tmp_path, {
        "package.json": '{"dependencies": {"express": "4.19.2", "joi": "17.13.1", "@acme/published": "1.0.0"}}',
        "tsconfig.json": ('{"compilerOptions": {"baseUrl": ".", "paths": {"generated/api": ["./.gen/api"], '
                          '"gen/*": ["./.gen/*"], "lib/*": ["./src/lib/*"], "@acme/*": ["./packages/*/src"], '
                          '"joi": ["./shims/joi"], "joi/extra": ["./shims/joi-extra"], '
                          '"compat": ["./node_modules/compat/index.js"], "*": ["./types/*"]}}}'),
        "src/lib/text.ts": "export function shout (s: string) { return s.toUpperCase() }\n",
        "src/page.ts": ("import { allPosts, load } from 'generated/api'\n"
                        "import { client } from 'gen/client'\n"
                        "import { shout } from 'lib/text'\n"
                        "import compat from 'compat'\n"
                        "import Joi from 'joi'\n"
                        "import { more } from 'joi/extra'\n"
                        "import { publish } from '@acme/published'\n"
                        "import { draft } from '@acme/unbuilt'\n\n"
                        "export function page () {\n"
                        "  const posts = allPosts.filter(p => p.ok)\n"
                        "  posts.map(p => p.title)\n"
                        "  load()\n"
                        "  client.fetchAll()\n"
                        "  shout('a')\n"
                        "  compat.run()\n"
                        "  publish()\n"
                        "  draft()\n"
                        "  more()\n"
                        "  return Joi.string().min(2)\n"
                        "}\n"),
    })
    for callee in ("allPosts.filter", "load", "client.fetchAll", "draft", "more"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "missing-module", []), (callee, s)
    assert "cannot find in the repository" in _one(g, "load")["why"]
    s = _one(g, "posts.map")   # a value that came from the missing file: unknown, not a library's
    assert (s["outcome"], s["to"]) == ("unresolved", []), s
    assert _one(g, "shout")["to"] == ["js:src/lib/text::shout"]
    assert _one(g, "compat.run")["outcome"] == "external"
    assert _one(g, "publish")["to"] == ["ext:@acme/published.publish"]
    s = _one(g, "Joi.string().min")
    assert (s["outcome"], s["via"]) == ("external", "library-result"), s
    # the map keeps the link the older rule drew (so counts compare across versions); only the inventory changed
    assert any(e.dst == "ext:generated/api.load" and e.via == "import" for e in g.edges)


def test_typescript_parameter_types_are_followed(tmp_path):
    g = _g(tmp_path, {"src/h.ts": (
        "import { Request, Response } from 'express'\n"
        "class Store {\n  save () { return 1 }\n}\n"
        "export function handle (req: Request, res: Response, store: Store) {\n"
        "  store.save()\n  res.send(req.body)\n}\n")})
    assert _one(g, "store.save")["to"] == ["js:src/h::Store.save"] and _one(g, "store.save")["via"] == "param-type"
    s = _one(g, "res.send")
    assert (s["to"], s["via"]) == (["ext:express.Response.send"], "param-type")


def test_library_values_and_chains(tmp_path):
    g = _g(tmp_path, {"schema.js": (
        "const Joi = require('joi')\n"
        "const user = Joi.object({ name: Joi.string().min(2).required() })\n"
        "module.exports = user\n")})
    assert _one(g, "Joi.object")["to"] == ["ext:joi.object"]
    chain = _one(g, "Joi.string().min(2).required")
    assert chain["outcome"] == "external" and chain["via"] == "library-result" and chain["to"] == ["ext:joi.string().min"]


def test_constructor_functions_and_prototype_methods(tmp_path):
    g = _g(tmp_path, {"dao.js": (
        "function NotesDAO (db) {\n"
        "  this.find = function (id) { return db.get(id) }\n"
        "}\n"
        "NotesDAO.prototype.save = function (n) { return n }\n"
        "module.exports.NotesDAO = NotesDAO\n"),
        "use.js": (
        "const NotesDAO = require('./dao').NotesDAO\n"
        "const dao = new NotesDAO(null)\n"
        "dao.find(1)\n"
        "dao.save({})\n")})
    assert _one(g, "dao.find")["to"] == ["js:dao::NotesDAO.find"]
    assert _one(g, "dao.save")["to"] == ["js:dao::NotesDAO.save"]
    assert _one(g, "db.get")["reason"] == "parameter"


def test_a_function_wrapped_by_a_helper_is_still_a_node(tmp_path):
    g = _g(tmp_path, {
        "util/wrap.js": "module.exports = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)\n",
        "ctrl.js": ("const wrap = require('./util/wrap')\n"
                    "const create = wrap(async (req, res) => {\n  res.status(201).send(req.body)\n})\n"
                    "module.exports = { create }\n"),
        "routes.js": ("const router = require('express').Router()\nconst ctrl = require('./ctrl')\n"
                      "router.post('/things', ctrl.create)\nmodule.exports = router\n"),
    })
    assert g.nodes["js:ctrl::create"].entry["detail"] == "POST /things"
    assert _one(g, "wrap")["to"] == ["js:util/wrap::default"]


def test_dom_and_fetch_values_are_built_in(tmp_path):
    g = _g(tmp_path, {"web/tabs.js": (
        "const tabs = document.querySelectorAll('.tab')\n"
        "tabs.forEach(function (tab) {\n"
        "  tab.addEventListener('click', function (event) {\n"
        "    event.preventDefault()\n"
        "    tab.classList.add('on')\n"
        "  })\n"
        "})\n"
        "fetch('/api/tabs').then(function (r) { return r.json() })\n")})
    for callee in ("tabs.forEach", "tab.addEventListener", "event.preventDefault", "tab.classList.add", "r.json"):
        assert _one(g, callee)["outcome"] == "builtin", callee


def test_elements_of_a_plain_array_are_not_taken_for_built_ins(tmp_path):
    g = _g(tmp_path, {"web/list.js": (
        "class Item {\n  ship () { return 1 }\n}\n"
        "const items = [new Item()]\n"
        "items.forEach(function (item) { item.ship() })\n")})
    assert _one(g, "items.forEach")["outcome"] == "builtin"
    s = _one(g, "item.ship")
    assert s["outcome"] in ("unresolved", "name-only") and s["outcome"] != "builtin"


def test_route_middleware_counts_as_a_login_check_only_when_it_is_one(tmp_path):
    from lantern import websec
    g = _g(tmp_path, {
        "lib/guard.js": ("exports.requireLogin = function (req, res, next) { next() }\n"
                         "exports.logRequest = function (req, res, next) { next() }\n"),
        "lib/notes.js": ("exports.remove = function (req, res) { res.end() }\n"
                         "exports.update = function (req, res) { res.end() }\n"),
        "routes.js": ("const router = require('express').Router()\nconst guard = require('./lib/guard')\n"
                      "const notes = require('./lib/notes')\n"
                      "router.delete('/notes/:id', guard.requireLogin, notes.remove)\n"
                      "router.put('/notes/:id', guard.logRequest, notes.update)\nmodule.exports = router\n"),
        "web/app.js": ("export function drop (id) { return fetch(`/notes/${id}`, { method: 'DELETE' }) }\n"
                       "export function edit (id) { return fetch(`/notes/${id}`, { method: 'PUT' }) }\n"),
    })
    flagged = {f["title"].split(" changes data")[0] for f in websec.missing_auth(g)}
    assert "PUT /notes/:id" in flagged            # logRequest is not a login check
    assert "DELETE /notes/:id" not in flagged     # requireLogin is


def test_a_route_whose_handler_is_not_the_projects_own_code_is_not_put_on_a_library(tmp_path):
    """`app.get('/metrics', prom.handler)`: the handler is a library's function, so the project has no function to put
    the route on, and a library is never an entry point of the app. The same for a handler that comes from a file of
    the project that is not there, which is not counted as a library's function either. The twin: a handler of the
    project's own is the route, and its middleware list keeps the names the code wrote."""
    g = _g(tmp_path, {
        "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"gen/*": ["./.gen/*"]}}}',
        "lib/notes.js": "module.exports.list = function (req, res) { res.json([]) }\n",
        "app.js": ("const express = require('express')\n"
                   "const prom = require('prom-bundle')\n"
                   "const auth = require('./middleware/auth-that-is-missing')\n"
                   "const gen = require('gen/handlers')\n"
                   "const notes = require('./lib/notes')\n"
                   "const app = express()\n"
                   "app.get('/metrics', prom.handler)\n"
                   "app.get('/gen', gen.list)\n"
                   "app.get('/gone', auth.requireLogin, auth.page)\n"
                   "app.delete('/notes', auth.requireLogin, gen.audit, prom.count, notes.list)\n"
                   "module.exports = app\n"),
    })
    assert not [n.id for n in g.nodes.values() if n.entry and (n.kind == "external" or n.id.startswith("ext:"))]
    routes = {n.entry["detail"]: n for n in g.nodes.values() if n.entry and n.entry["kind"] == "route"}
    assert set(routes) == {"DELETE /notes"}
    assert routes["DELETE /notes"].id == "js:lib/notes::list"
    assert routes["DELETE /notes"].entry["middleware"] == [
        "ext:./middleware/auth-that-is-missing.requireLogin", "ext:gen/handlers.audit", "ext:prom-bundle.count"]
    s = _one(g, "prom.handler", group="handed")
    assert (s["outcome"], s["to"]) == ("external", ["ext:prom-bundle.handler"]), s
    for callee in ("gen.list", "auth.page", "gen.audit"):
        s = _one(g, callee, group="handed")
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "missing-module", []), (callee, s)
    twice = _sites(g, "auth.requireLogin", group="handed")
    assert [(s["outcome"], s["reason"]) for s in twice] == [("unresolved", "missing-module")] * 2, twice
    h = g.meta["calls"]["handed"]
    assert sum(h["outcomes"].values()) == h["total"] and h["reasons"] == {"missing-module": 5}


def test_a_middleware_lantern_cannot_read_is_judged_by_its_own_name_not_its_folder(tmp_path):
    """The login check reads the names of a route's middleware. For one that comes from a file that is not in the repo
    it has only the import to go on: the name imported, or the file's own name for a default export, never the
    folders on the way (`./auth/rate-limit` limits requests; it does not check who is calling)."""
    from lantern import websec
    g = _g(tmp_path, {
        "lib/notes.js": ("exports.remove = function (req, res) { res.end() }\n"
                         "exports.update = function (req, res) { res.end() }\n"
                         "exports.rename = function (req, res) { res.end() }\n"),
        "routes.js": ("const router = require('express').Router()\n"
                      "const limit = require('./auth/rate-limit')\n"
                      "const requireLogin = require('./middleware/require-login')\n"
                      "const guards = require('./auth/guards')\n"
                      "const notes = require('./lib/notes')\n"
                      "router.put('/notes/:id', limit, notes.update)\n"
                      "router.delete('/notes/:id', requireLogin, notes.remove)\n"
                      "router.patch('/notes/:id', guards.logRequest, notes.rename)\n"
                      "module.exports = router\n"),
        "web/app.js": ("export function drop (id) { return fetch(`/notes/${id}`, { method: 'DELETE' }) }\n"
                       "export function edit (id) { return fetch(`/notes/${id}`, { method: 'PUT' }) }\n"
                       "export function name (id) { return fetch(`/notes/${id}`, { method: 'PATCH' }) }\n"),
    })
    flagged = {f["title"].split(" changes data")[0] for f in websec.missing_auth(g)}
    assert "PUT /notes/:id" in flagged            # a rate limiter kept in a folder called auth is not a login check
    assert "PATCH /notes/:id" in flagged          # nor is logRequest, wherever its file is
    assert "DELETE /notes/:id" not in flagged     # require-login is, by its own name


def test_a_wrapped_handler_is_linked_as_likely_not_certain(tmp_path):
    g = _g(tmp_path, {
        "util/wrap.js": "module.exports = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)\n",
        "ctrl.js": "const wrap = require('./util/wrap')\nconst create = wrap(async (req, res) => { res.end() })\n"
                   "module.exports = { create }\n",
        "routes.js": ("const router = require('express').Router()\nconst ctrl = require('./ctrl')\n"
                      "router.post('/things', ctrl.create)\nmodule.exports = router\n"),
    })
    e = _edge(g, "js:routes", "js:ctrl::create")
    assert (e.via, e.confidence) == ("wrapped-function", "inferred")
    assert _one(g, "ctrl.create", group="handed")["outcome"] == "likely"


def test_calls_that_return_values_are_not_taken_for_wrapped_functions(tmp_path):
    g = _g(tmp_path, {"web/view.js": (
        "import { useMemo } from 'react'\n"
        "export function View ({ list }) {\n"
        "  const doubled = list.map((x) => x * 2)\n"
        "  const total = useMemo(() => doubled.length, [doubled])\n"
        "  const later = setTimeout(() => total, 10)\n"
        "  return later\n}\n")})
    for name in ("doubled", "total", "later"):
        assert f"js:web/view::View.{name}" not in g.nodes, name


def test_a_router_mounted_in_two_places_keeps_its_written_paths(tmp_path):
    g = _g(tmp_path, {
        "routes/items.js": ("const router = require('express').Router()\n"
                            "router.get('/list', function (req, res) { res.end() })\nmodule.exports = router\n"),
        "server.js": ("const app = require('express')()\nconst items = require('./routes/items')\n"
                      "app.use('/v1', items)\napp.use('/v2', items)\n"),
    })
    assert [n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry["kind"] == "route"] == ["GET /list"]


def test_a_function_hung_on_another_is_not_a_local_name(tmp_path):
    """`PostItem.Skeleton = function () { <Skeleton/> }`: the bare `Skeleton` is the imported component, not the
    function it sits in. In JavaScript a function stored as a property (`X.y = …`, `this.x = …`,
    `X.prototype.y = …`) is not a name in scope, and a function stored from module level does not see the locals of
    the function it hangs on. Found on a held-out app (taxonomy), where the link pointed back at its own function."""
    g = _g(tmp_path, {
        "ui/skeleton.jsx": "export function Skeleton () { return <div /> }\n",
        "post-item.jsx": ("import { Skeleton } from './ui/skeleton'\n"
                          "export function PostItem () { return <div /> }\n"
                          "PostItem.Skeleton = function PostItemSkeleton () {\n"
                          "  return <Skeleton />\n"
                          "}\n"),
        "dao.js": ("function load () { return 1 }\n"
                   "function secret () { return 3 }\n"
                   "function Dao () {\n"
                   "  function secret () { return 2 }\n"
                   "  this.load = function () { return load() + secret() }\n"
                   "}\n"
                   "Dao.prototype.save = function () { return secret() }\n"
                   "module.exports = Dao\n")})
    sk = _one(g, "Skeleton", "post-item.jsx")
    assert (sk["outcome"], sk["to"]) == ("resolved", ["js:ui/skeleton::Skeleton"])
    ld = _one(g, "load", "dao.js")
    assert (ld["outcome"], ld["to"]) == ("resolved", ["js:dao::load"])          # not this.load itself
    inner, outer = sorted(_sites(g, "secret", "dao.js"), key=lambda s: s["line"])
    assert inner["to"] == ["js:dao::Dao.secret"]       # inside the constructor: its own local function
    assert outer["to"] == ["js:dao::secret"]           # the prototype method at module level: the module's


def test_routes_registered_inside_a_function_find_the_router_declared_outside_it(tmp_path):
    """The router variable is looked up from the function outwards, the way JavaScript does: a route registered in
    `setup()` on a module-level router gets that router's mount prefix; one registered on a router that is only a
    parameter of the function does not borrow the prefix of a module-level router with the same name."""
    g = _g(tmp_path, {
        "app.js": ("const express = require('express')\n"
                   "const app = express()\n"
                   "const router = express.Router()\n"
                   "function ping (req, res) { res.send('pong') }\n"
                   "function stats (req, res) { res.send('0') }\n"
                   "function setup () {\n"
                   "  router.get('/ping', ping)\n"
                   "}\n"
                   "function other (router) {\n"
                   "  router.get('/stats', stats)\n"
                   "}\n"
                   "setup()\n"
                   "app.use('/api', router)\n")})
    det = {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry["kind"] == "route"}
    assert det["js:app::ping"] == "GET /api/ping"
    assert det["js:app::stats"] == "GET /stats"


CHAINED = {
    "lib/auth.js": "exports.required = function (req, res, next) { if (req.user) return next(); res.status(401).end() }\n",
    "lib/users.js": ("exports.create = function (req, res) { res.status(201).end() }\n"
                     "exports.list = function (req, res) { res.json([]) }\n"
                     "exports.remove = function (req, res) { res.status(204).end() }\n"),
    "routes/users.js": ("const express = require('express')\n"
                        "const auth = require('../lib/auth')\n"
                        "const users = require('../lib/users')\n"
                        "const router = express.Router()\n"
                        "router\n"
                        "  .route('/')\n"
                        "  .post(auth.required, users.create)\n"
                        "  .get(users.list)\n"
                        "router.route('/:id').delete(auth.required, users.remove)\n"
                        "module.exports = router\n"),
    "server.js": ("const express = require('express')\n"
                  "const app = express()\n"
                  "app.use('/api/users', require('./routes/users'))\n"
                  "app.listen(8080)\n"),
}


def test_routes_written_with_route_then_a_verb_are_routes(tmp_path):
    """`router.route('/x').post(mw, handler).get(handler)`: the path is written once, on `.route()`; every verb
    hung on it is a route with its own middleware and handler."""
    g = _g(tmp_path, CHAINED)
    det = {n.id: n.entry for n in g.nodes.values() if n.entry and n.entry["kind"] == "route"}
    assert det["js:lib/users::create"] == {"kind": "route", "detail": "POST /api/users",
                                           "middleware": ["js:lib/auth::required"]}
    assert det["js:lib/users::list"] == {"kind": "route", "detail": "GET /api/users"}
    assert det["js:lib/users::remove"] == {"kind": "route", "detail": "DELETE /api/users/:id",
                                           "middleware": ["js:lib/auth::required"]}
    h = _one(g, "users.create", group="handed")
    assert (h["outcome"], h["to"], h["via"]) == ("resolved", ["js:lib/users::create"], "route-handler")
    assert g.meta["http_calls"] == []       # none of this is an outgoing HTTP call


def test_a_route_call_without_a_written_path_or_a_handler_is_not_a_route(tmp_path):
    """The safe side of the rule above: a path held in a variable, or a verb given no function (an HTTP client
    builder such as `api.route('/x').get('/y')`), registers nothing."""
    g = _g(tmp_path, {"lib/users.js": CHAINED["lib/users.js"],
                      "routes/users.js": ("const express = require('express')\n"
                                          "const users = require('../lib/users')\n"
                                          "const router = express.Router()\n"
                                          "const where = process.env.USERS_PATH\n"
                                          "router.route(where).get(users.list)\n"
                                          "module.exports = router\n"),
                      "client.js": ("const api = require('./api-client')\n"
                                    "api.route('/users').get('/all')\n")})
    assert [n.id for n in g.nodes.values() if n.entry and n.entry["kind"] == "route"] == []


def test_a_factory_that_returns_its_modules_router_carries_the_mount_prefix(tmp_path):
    """`module.exports = function () { router.get(...); return router }` mounted with
    `app.use('/app', require('./routes/app')())`: the routes are under /app. A factory that returns a different
    router than the one the routes are on gives them no prefix."""
    files = {
        "lib/h.js": "exports.ping = function (req, res) { res.send('pong') }\nexports.stats = function (req, res) { res.send('0') }\n",
        "routes/app.js": ("const router = require('express').Router()\n"
                          "const h = require('../lib/h')\n"
                          "module.exports = function () {\n"
                          "  router.get('/ping', h.ping)\n"
                          "  return router\n"
                          "}\n"),
        "routes/other.js": ("const express = require('express')\n"
                            "const router = express.Router()\n"
                            "const admin = express.Router()\n"
                            "const h = require('../lib/h')\n"
                            "module.exports = function () {\n"
                            "  router.get('/stats', h.stats)\n"
                            "  return admin\n"
                            "}\n"),
        "server.js": ("const express = require('express')\n"
                      "const app = express()\n"
                      "app.use('/app', require('./routes/app')())\n"
                      "app.use('/other', require('./routes/other')())\n"
                      "app.listen(8080)\n"),
    }
    g = _g(tmp_path, files)
    det = {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry["kind"] == "route"}
    assert det["js:lib/h::ping"] == "GET /app/ping"
    assert det["js:lib/h::stats"] == "GET /stats"


def test_a_handler_reached_through_a_value_lantern_worked_out_is_likely_not_certain(tmp_path):
    """`const notes = new Notes(db); app.get('/notes', notes.list)`: the handler is found through the type of a
    local (worked out, not written at the call), so the link is `likely`, like a call written the same way; a
    handler named straight from a required module stays `resolved`."""
    g = _g(tmp_path, {
        "notes.js": ("function Notes (db) {\n"
                     "  this.list = function (req, res) { res.json([]) }\n"
                     "  this.guard = function (req, res, next) { next() }\n"
                     "}\n"
                     "module.exports = Notes\n"),
        "plain.js": "exports.ping = function (req, res) { res.send('pong') }\n",
        "server.js": ("const express = require('express')\n"
                      "const Notes = require('./notes')\n"
                      "const plain = require('./plain')\n"
                      "const app = express()\n"
                      "const notes = new Notes(null)\n"
                      "const guard = notes.guard\n"
                      "app.get('/notes', guard, notes.list)\n"
                      "app.get('/ping', plain.ping)\n")})
    h = _one(g, "notes.list", group="handed")
    assert (h["outcome"], h["to"], h["via"]) == ("likely", ["js:notes::Notes.list"], "route-handler")
    assert _edge(g, "js:server", "js:notes::Notes.list").confidence == "inferred"
    mw = _one(g, "guard", group="handed")
    assert (mw["outcome"], mw["to"], mw["via"]) == ("likely", ["js:notes::Notes.guard"], "middleware")
    p = _one(g, "plain.ping", group="handed")
    assert (p["outcome"], p["via"]) == ("resolved", "route-handler")
    assert g.nodes["js:notes::Notes.list"].entry == {"kind": "route", "detail": "GET /notes",
                                                     "middleware": ["js:notes::Notes.guard"]}


def test_a_route_whose_handler_is_made_by_a_call_is_not_an_outgoing_http_call(tmp_path):
    """`router.get('/', swaggerUi.setup(spec))` registers a route (its handler is what the call returns); it is not
    the app calling `GET /` on some server. Read as an outgoing call, the bridge linked it to another router's
    `GET /` route as an exact match (found on a held-out app). A real client call with the same shape stays one."""
    files = {
        "lib/users.js": "exports.list = function (req, res) { res.json([]) }\n",
        "routes/users.js": ("const router = require('express').Router()\n"
                            "const users = require('../lib/users')\n"
                            "router.get('/', users.list)\n"
                            "module.exports = router\n"),
        "routes/docs.js": ("const express = require('express')\n"
                           "const swaggerUi = require('swagger-ui-express')\n"
                           "const router = express.Router()\n"
                           "router.get('/', swaggerUi.setup({}))\n"
                           "module.exports = router\n"),
        "routes/hooks.js": ("module.exports = function (r, passport) {\n"
                            "  r.post('/done', function (req, res) { res.end() })\n"
                            "  r.post('/login', passport.authenticate('local'))\n"
                            "}\n"),
    }
    g = _g(tmp_path, files)
    assert g.meta["http_calls"] == []
    assert _edge(g, "js:routes/docs", "js:lib/users::list") is None
    assert not [n for n in g.nodes if n.startswith("ext:HTTP ")]
    # the safe side: an HTTP client called the same way is still an outgoing call
    g2 = _g(tmp_path / "client", {"client.js": ("const axios = require('axios')\n"
                                                 "const api = axios.create({ baseURL: '/api' })\n"
                                                 "function options () { return {} }\n"
                                                 "function load () { return api.get('/users', options()) }\n"
                                                 "module.exports = load\n")})
    assert [(c["method"], c["path"], c["file"]) for c in g2.meta["http_calls"]] == [("GET", "/users", "client.js")]


# ---- a "library" label is not given where the function may be the project's own (each with its safe twin) ----

def test_a_function_the_project_puts_on_a_library_value_is_not_called_the_librarys(tmp_path):
    g = _g(tmp_path, {
        "models/paginate.js": (
            "module.exports = function (schema) {\n"
            "  schema.statics.paginate = async function (filter) {\n    return this.find(filter)\n  }\n"
            "}\n"),
        "models/task.js": (
            "const mongoose = require('mongoose')\n"
            "const paginate = require('./paginate')\n"
            "const taskSchema = mongoose.Schema({ name: String })\n"
            "taskSchema.plugin(paginate)\n"
            "taskSchema.methods.isDone = function () {\n  return true\n}\n"
            "const Task = mongoose.model('Task', taskSchema)\n"
            "async function open (id) {\n"
            "  const pages = await Task.paginate({})\n"      # the plugin's function, reached through mongoose's model
            "  const task = await Task.findById(id)\n"       # mongoose's own
            "  return task.isDone() && pages\n"              # the project's method, on a document mongoose returned
            "}\n"
            "module.exports = { open }\n"),
    })
    for callee in ("Task.paginate", "task.isDone"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "library-or-repo", []), s
    assert "has its own `paginate`" in _one(g, "Task.paginate")["why"]
    s = _one(g, "Task.findById")
    assert (s["outcome"], s["to"], s["via"]) == ("external", ["ext:mongoose.model().findById"], "library-value"), s
    assert not [e for e in g.edges if e.dst.endswith((".paginate", ".isDone"))]   # and no link is drawn to a library


def test_express_objects_keep_their_own_members_unless_the_project_adds_one(tmp_path):
    g = _g(tmp_path, {
        "lib/mailer.js": ("class Mailer {\n  send (to) {\n    return to\n  }\n\n  can (what) {\n    return !!what\n  }\n\n"
                          "  post (what) {\n    return what\n  }\n}\nmodule.exports = Mailer\n"),
        "app.js": (
            "const express = require('express')\n"
            "const app = express()\n"
            "app.use(function (req, res, next) {\n"
            "  res.fail = function (code) {\n    res.sendStatus(code)\n  }\n"
            "  next()\n"
            "})\n"
            "app.post('/a', function (req, res) {\n"
            "  if (!req.user.can('read')) return res.fail(403)\n"
            "  res.send('ok')\n"
            "})\n"),
    })
    # `res` and `app` are Express's own objects: a class elsewhere with a `send` or a `post` changes nothing
    assert _one(g, "res.send")["to"] == ["ext:express.Response.send"]
    assert _one(g, "app.post")["outcome"] == "external"
    s = _one(g, "res.fail")   # the middleware above put it there
    assert (s["outcome"], s["reason"]) == ("unresolved", "library-or-repo"), s
    s = _one(g, "req.user.can")   # what Express hands over as req.user may be one of the project's own objects
    assert (s["outcome"], s["reason"]) == ("unresolved", "library-or-repo"), s


def test_a_class_handed_to_a_library_may_come_back_as_its_result(tmp_path):
    """`getRepository(User).findOne()` gives back a User: its `checkPassword` is the project's method, not the
    library's. `user.reload()` is the library's all the same: User has no `reload`, and the `reload` of another
    class, which was never handed to the library, says nothing about this value."""
    g = _g(tmp_path, {
        "src/user.ts": ("class Base {\n  touch () {\n    return 1\n  }\n}\n\n"
                        "export class User extends Base {\n  checkPassword (pw: string) {\n    return pw.length > 0\n  }\n}\n\n"
                        "export class Page {\n  reload () {\n    return 2\n  }\n}\n"),
        "src/login.ts": (
            "import { getRepository } from 'typeorm'\n"
            "import { User } from './user'\n"
            "export async function login (name: string, pw: string) {\n"
            "  const user = await getRepository(User).findOne({ name })\n"
            "  if (!user.checkPassword(pw)) return null\n"
            "  user.touch()\n"
            "  getRepository(User).create().checkPassword(pw)\n"
            "  return user.reload()\n"
            "}\n"),
    })
    for callee in ("user.checkPassword", "user.touch", "getRepository(User).create().checkPassword"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "library-or-repo", []), s
    assert (_one(g, "user.reload")["outcome"], _one(g, "user.reload")["via"]) == ("external", "library-value")


@pytest.mark.parametrize("attach", [
    "Note.prototype.shorten = function () { return 1 }",
    "function shorten () { return 1 }\nNote.prototype.shorten = shorten",
    "schema.methods = { shorten () { return 1 } }",
    "schema.method('shorten', function () { return 1 })",
    "Object.assign(schema.methods, { shorten: function () { return 1 } })",
    "const options = { methods: { shorten () { return 1 } } }",
])
def test_every_way_of_putting_a_function_on_a_library_value_is_seen(tmp_path, attach):
    g = _g(tmp_path, {"notes.js": (
        "const orm = require('someorm')\n"
        "const schema = orm.schema({})\n"
        "const Note = orm.define('note', schema)\n"
        f"{attach}\n"
        "async function first () {\n"
        "  const note = await Note.findOne()\n"
        "  return note.shorten() + note.reload()\n"
        "}\n"
        "module.exports = first\n")})
    s = _one(g, "note.shorten")
    assert (s["outcome"], s["reason"]) == ("unresolved", "library-or-repo"), (attach, s)
    assert _one(g, "note.reload")["outcome"] == "external"


def test_the_projects_own_objects_and_plain_values_do_not_make_a_library_call_doubtful(tmp_path):
    """Functions the project keeps on its own things (a module's exports, a plain object, a class, a constructor
    function) are not functions put on a library's object, and a value that is not a function is not one at all."""
    g = _g(tmp_path, {
        "lib/view.js": ("const view = {}\nview.render = function (name) {\n  return name\n}\n"
                        "class Mailer {\n  send (to) {\n    return to\n  }\n\n  post (to) {\n    return to\n  }\n}\n"
                        "function Store () {\n  var self = this\n  self.insert = function (row) {\n    return row\n  }\n"
                        "  this.tools = { render: function (x) {\n    return x\n  } }\n}\n"
                        "module.exports = { view, Mailer, Store }\n"
                        "Object.assign(module.exports, { post (to) {\n  return to\n} })\n"),
        "handlers.js": (
            "const axios = require('axios')\n"
            "const db = require('somedb')()\n"
            "const api = axios.create({ baseURL: 'https://api.example.com' })\n"
            "module.exports.redirect = function (req, res) {\n"
            "  const status = 302\n"
            "  const err = new Error('moved')\n"
            "  err.status = status\n"
            "  res.locals.title = req.query.title\n"
            "  res.status(status)\n"
            "  res.render('moved')\n"
            "  api.post('/moved', {})\n"
            "  db.insert({})\n"
            "  res.redirect('/login')\n"
            "}\n")})
    assert _one(g, "res.redirect")["to"] == ["ext:express.Response.redirect"]
    assert _one(g, "res.status")["to"] == ["ext:express.Response.status"]
    assert _one(g, "res.render")["to"] == ["ext:express.Response.render"]
    assert _one(g, "api.post")["to"] == ["ext:axios.create().post"]
    assert _one(g, "db.insert")["to"] == ["ext:somedb().insert"]


def test_a_function_added_to_a_built_in_type_is_not_called_built_in(tmp_path):
    g = _g(tmp_path, {"text.js": (
        "String.prototype.shout = function () {\n  return this.toUpperCase()\n}\n"
        "function greet () {\n  const s = 'hello'\n  return s.shout() + s.trim()\n}\n"
        "module.exports = greet\n")})
    s = _one(g, "s.shout")
    assert (s["outcome"], s["reason"]) == ("unresolved", "library-or-repo"), s
    assert _one(g, "s.trim")["outcome"] == "builtin"


def test_route_middleware_keeps_its_name_when_it_may_be_the_projects_own(tmp_path):
    g = _g(tmp_path, {
        "lib/checks.js": ("module.exports = function (guard) {\n"
                          "  guard.signedIn = function (req, res, next) {\n    next()\n  }\n}\n"),
        "app.js": (
            "const express = require('express')\n"
            "const guard = require('someguard')()\n"
            "const app = express()\n"
            "function list (req, res) {\n  res.json([])\n}\n"
            "app.get('/notes', guard.signedIn, list)\n"),
    })
    entry = g.nodes["js:app::list"].entry
    assert entry["detail"] == "GET /notes" and entry["middleware"] == ["ext:someguard().signedIn"]
    assert not [s for s in g.sites if s["group"] == "handed" and s["outcome"] == "external"]   # no library claim


def test_a_property_of_the_global_object_is_not_called_built_in(tmp_path):
    g = _g(tmp_path, {"public/app.js": (
        "window.App = { init () { return 1 } }\n"
        "function start () {\n"
        "  window.App.init()\n"
        "  globalThis.helper()\n"
        "  window.location.reload()\n"
        "  window.alert('hi')\n"
        "  window.localStorage.getItem('x')\n"
        "}\n"
        "start()\n")})
    for callee in ("window.App.init", "globalThis.helper"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "global-property", []), s
    assert "any script can add to" in _one(g, "window.App.init")["why"]
    for callee in ("window.location.reload", "window.alert", "window.localStorage.getItem"):
        assert _one(g, callee)["outcome"] == "builtin", callee


def test_a_service_workers_own_names_are_built_in(tmp_path):
    g = _g(tmp_path, {"public/sw.js": (
        "self.addEventListener('install', function (e) {\n  self.skipWaiting()\n})\n"
        "self.addEventListener('activate', function (e) {\n  e.waitUntil(self.clients.claim())\n  self.warmUp()\n})\n")})
    assert _one(g, "self.skipWaiting")["outcome"] == "builtin"
    assert _one(g, "self.clients.claim")["outcome"] == "builtin"
    assert _one(g, "self.warmUp")["reason"] == "global-property"


def test_a_method_the_project_adds_to_a_built_in_type_is_seen_on_results_too(tmp_path):
    g = _g(tmp_path, {"lists.js": (
        "Array.prototype.last = function () {\n  return this[this.length - 1]\n}\n"
        "function pick (items) {\n"
        "  return Array.from(items).last() + Array.from(items).indexOf(1) + Array.from(items).length\n"
        "}\n"
        "module.exports = pick\n")})
    s = _one(g, "Array.from(items).last")
    assert (s["outcome"], s["reason"]) == ("unresolved", "library-or-repo"), s
    assert _one(g, "Array.from(items).indexOf")["outcome"] == "builtin"
