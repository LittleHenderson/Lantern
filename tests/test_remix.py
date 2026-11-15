"""Remix routes, and React Router's framework mode that took Remix's place (roadmap of 2026-11-14, stage 1).

A Remix app's doors are the files of `app/routes` (and `app/root`): a file's name is its address (`notes.$noteId.tsx`
is `/notes/:noteId`), the `loader` it exports answers a GET there with the page's data, the `action` every other
verb, and what it exports by default is the page. A file whose name others begin with is their layout. Until now
none of them was an entry point: a loader or an action was a function nobody called.

Each shape sits beside twins that must stay as they were."""

import json

from lantern.engine import build_graph

PKG = json.dumps({"dependencies": {"@remix-run/node": "2.9.2", "@remix-run/react": "2.9.2", "@remix-run/serve": "2.9.2",
                                   "@prisma/client": "5.14.0", "pg": "8.11.5", "react": "18.2.0"},
                  "devDependencies": {"@remix-run/dev": "2.9.2", "vite": "5.1.0", "typescript": "5.4.0"}})
NO_REMIX = json.dumps({"dependencies": {"@prisma/client": "5.14.0", "pg": "8.11.5", "react": "18.2.0"}})
TSCONFIG = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"~/*": ["./app/*"]}}})
DB = 'import { PrismaClient } from "@prisma/client";\nexport const db = new PrismaClient();\n'
SESSION = '''import { createCookieSessionStorage, redirect } from "@remix-run/node";

const storage = createCookieSessionStorage({
  cookie: { name: "__session", httpOnly: true, sameSite: "lax", secrets: [process.env.SESSION_SECRET] },
});

export async function whoIs(request: Request) {
  const session = await storage.getSession(request.headers.get("Cookie"));
  return session.get("userId");
}

export async function needUser(request: Request) {
  const userId = await whoIs(request);
  if (!userId) throw redirect("/login");
  return userId;
}

export async function startSession(request: Request, userId: string) {
  const session = await storage.getSession(request.headers.get("Cookie"));
  session.set("userId", userId);
  return redirect("/notes", { headers: { "Set-Cookie": await storage.commitSession(session) } });
}

export async function endSession(request: Request) {
  const session = await storage.getSession(request.headers.get("Cookie"));
  return redirect("/", { headers: { "Set-Cookie": await storage.destroySession(session) } });
}
'''
ROOT = '''import type { LoaderFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";
import { Form, Links, Meta, Outlet, Scripts, useLoaderData } from "@remix-run/react";
import { whoIs } from "~/session.server";

export async function loader({ request }: LoaderFunctionArgs) {
  return json({ userId: await whoIs(request) });
}

export default function App() {
  const { userId } = useLoaderData<typeof loader>();
  return (
    <html lang="en">
      <head><Meta /><Links /></head>
      <body>
        {userId ? <Form method="post" action="/logout"><button>Sign out</button></Form> : null}
        <Outlet />
        <Scripts />
      </body>
    </html>
  );
}
'''
HOME = '''import { Form, Link, useFetcher } from "@remix-run/react";

async function peek(id: string) {
  const res = await fetch(`/api/notes/${id}.json`);
  return res.json();
}

async function wipe(id: string) {
  await fetch(`/notes/${id}`, { method: "DELETE" });
}

export default function Home() {
  const quick = useFetcher();
  return (
    <div>
      <Link to="/notes">Notes</Link>
      <quick.Form method="post" action="/notes/new"><input name="title" /></quick.Form>
      <Form action="/search"><input name="q" /></Form>
      <form method="post" action="/nowhere"><button>x</button></form>
      <button onClick={() => wipe("1")}>Wipe</button>
      <button onClick={() => peek("1")}>Peek</button>
    </div>
  );
}
'''
NOTES_FRAME = '''import type { LoaderFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";
import { Outlet, useLoaderData } from "@remix-run/react";
import { db } from "~/db.server";
import { needUser } from "~/session.server";

export async function loader({ request }: LoaderFunctionArgs) {
  const userId = await needUser(request);
  return json({ count: await db.note.count({ where: { ownerId: userId } }) });
}

export default function NotesFrame() {
  const { count } = useLoaderData<typeof loader>();
  return <main><h1>{count} notes</h1><Outlet /></main>;
}
'''
NOTE_LIST = '''import type { ActionFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";
import { Form, Link, useLoaderData } from "@remix-run/react";
import { db } from "~/db.server";
import { needUser } from "~/session.server";

export const loader = async ({ request }) => {
  const userId = await needUser(request);
  return json({ notes: await db.note.findMany({ where: { ownerId: userId } }) });
};

export async function action({ request }: ActionFunctionArgs) {
  const userId = await needUser(request);
  await db.note.deleteMany({ where: { ownerId: userId } });
  return json({ ok: true });
}

export default function NoteList() {
  const { notes } = useLoaderData<typeof loader>();
  return (
    <div>
      <ul>{notes.map((n) => <li key={n.id}><Link to={n.id}>{n.title}</Link></li>)}</ul>
      <Form method="post"><button>Remove all</button></Form>
    </div>
  );
}
'''
NOTE = '''import type { ActionFunctionArgs, LoaderFunctionArgs } from "@remix-run/node";
import { json, redirect } from "@remix-run/node";
import { Form, useLoaderData } from "@remix-run/react";
import { db } from "~/db.server";
import { needUser } from "~/session.server";

export async function loader({ request, params }: LoaderFunctionArgs) {
  const userId = await needUser(request);
  const note = await db.note.findFirst({ where: { id: params.noteId, ownerId: userId } });
  if (!note) throw new Response("Not found", { status: 404 });
  return json({ note });
}

export async function action({ request, params }: ActionFunctionArgs) {
  await needUser(request);
  await db.note.delete({ where: { id: params.noteId } });
  return redirect("/notes");
}

export default function Note() {
  const { note } = useLoaderData<typeof loader>();
  return (
    <Form method="post">
      <h2>{note.title}</h2>
      <button type="submit">Remove</button>
    </Form>
  );
}
'''
NEW = '''import type { ActionFunctionArgs } from "@remix-run/node";
import { redirect } from "@remix-run/node";
import { Form } from "@remix-run/react";
import { db } from "~/db.server";

export const action = async ({ request }: ActionFunctionArgs) => {
  const form = await request.formData();
  const note = await db.note.create({ data: { title: String(form.get("title")) } });
  return redirect(`/notes/${note.id}`);
};

export default function NewNote() {
  return (
    <Form method="post">
      <input name="title" />
      <button type="submit">Save</button>
    </Form>
  );
}
'''
LOGIN = '''import type { ActionFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";
import { Form, useActionData } from "@remix-run/react";
import { db } from "~/db.server";
import { startSession } from "~/session.server";

export async function action({ request }: ActionFunctionArgs) {
  const form = await request.formData();
  const user = await db.user.findUnique({ where: { email: String(form.get("email")) } });
  if (!user) return json({ error: "No such account" }, { status: 400 });
  return startSession(request, user.id);
}

export default function Login() {
  const said = useActionData<typeof action>();
  return (
    <Form method="post">
      <input name="email" />
      {said?.error ? <p>{said.error}</p> : null}
      <button type="submit">Sign in</button>
    </Form>
  );
}
'''
LOGOUT = '''import type { ActionFunctionArgs } from "@remix-run/node";
import { redirect } from "@remix-run/node";
import { endSession } from "~/session.server";

export const action = async ({ request }: ActionFunctionArgs) => endSession(request);

export const loader = async () => redirect("/");
'''
HEALTH = '''import { db } from "~/db.server";

export async function loader() {
  await db.note.count();
  return new Response("OK");
}
'''
API_NOTE = '''import type { LoaderFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";
import { db } from "~/db.server";

export async function loader({ params }: LoaderFunctionArgs) {
  return json(await db.note.findUnique({ where: { id: params.noteId } }));
}
'''
AUTH_FRAME = '''import { Outlet } from "@remix-run/react";

export default function AuthFrame() {
  return <section><Outlet /></section>;
}
'''
REGISTER = '''import type { ActionFunctionArgs } from "@remix-run/node";
import { Form } from "@remix-run/react";
import { db } from "~/db.server";
import { startSession } from "~/session.server";

export async function action({ request }: ActionFunctionArgs) {
  const form = await request.formData();
  const user = await db.user.create({ data: { email: String(form.get("email")) } });
  return startSession(request, user.id);
}

export default function Register() {
  return <Form method="post"><input name="email" /><button>Join</button></Form>;
}
'''
DASH = '''import { Chart } from "./chart";

export async function loader() {
  return { points: [1, 2, 3] };
}

export default function Dashboard() {
  return <Chart />;
}
'''
CHART = '''export async function loader() {
  return null;
}

export function Chart() {
  return <svg />;
}
'''
APP = {"tsconfig.json": TSCONFIG, "app/db.server.ts": DB, "app/session.server.ts": SESSION, "app/root.tsx": ROOT,
       "app/routes/_index.tsx": HOME, "app/routes/notes.tsx": NOTES_FRAME, "app/routes/notes._index.tsx": NOTE_LIST,
       "app/routes/notes.$noteId.tsx": NOTE, "app/routes/notes.new.tsx": NEW, "app/routes/login.tsx": LOGIN,
       "app/routes/logout.tsx": LOGOUT, "app/routes/healthcheck.tsx": HEALTH,
       "app/routes/api.notes.$noteId[.]json.ts": API_NOTE, "app/routes/_auth.tsx": AUTH_FRAME,
       "app/routes/_auth.register.tsx": REGISTER, "app/routes/dashboard/route.tsx": DASH,
       "app/routes/dashboard/chart.tsx": CHART}
# the same app with the helper under a name the check that goes by names reads
NAMED = {k: v.replace("needUser", "requireUser") for k, v in APP.items()}
R = "js:app/routes/"
ONE = R + "notes.$noteId::"
ROUTES = {
    "js:app/root::loader": "GET /*",
    R + "notes::loader": "GET /notes/*",
    R + "notes._index::loader": "GET /notes",
    R + "notes._index::action": "POST /notes?index",
    ONE + "loader": "GET /notes/:noteId",
    ONE + "action": "POST /notes/:noteId",
    R + "notes.new::action": "POST /notes/new",
    R + "login::action": "POST /login",
    R + "logout::action": "POST /logout",
    R + "logout::loader": "GET /logout",
    R + "healthcheck::loader": "GET /healthcheck",
    R + "api.notes.$noteId[.]json::loader": "GET /api/notes/:noteId.json",
    R + "_auth.register::action": "POST /register",
    R + "dashboard/route::loader": "GET /dashboard"}
PAGES = {R + "_index::Home": "/", R + "notes._index::NoteList": "/notes", ONE + "Note": "/notes/:noteId",
         R + "notes.new::NewNote": "/notes/new", R + "login::Login": "/login",
         R + "_auth.register::Register": "/register", R + "dashboard/route::Dashboard": "/dashboard"}


def _build(root, files, pkg=PKG):
    for rel, text in {"package.json": pkg, **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return build_graph(root)


def _entries(g, kind):
    return {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry["kind"] == kind}


def _edge(g, src, dst):
    return next((e for e in g.call_edges() if e.src == src and e.dst == dst), None)


# ------------------------------------------------------------------ the files of app/routes are routes
def test_each_door_of_a_remix_app_is_a_route(tmp_path):
    """A route file's `loader` answers a GET at the file's address, its `action` every other verb there (an index
    route's with `?index`, which is how Remix tells it from its layout's). A file whose name others begin with is
    their layout: its `loader` runs for every page below it, and the root's for every page. A folder with a
    `route.tsx` in it is the route of the folder's name."""
    g = _build(tmp_path, APP)
    assert _entries(g, "route") == ROUTES
    remove = g.nodes[ONE + "action"]
    assert remove.entry["remix"] == "action" and remove.lane == "server"
    assert (remove.file, remove.start_line) == ("app/routes/notes.$noteId.tsx", 14)
    assert g.nodes[ONE + "loader"].entry["remix"] == "loader"
    assert g.nodes[R + "notes::loader"].entry["remix"] == "layout loader"
    assert g.nodes["js:app/root::loader"].entry["remix"] == "layout loader"
    # a layout's loader runs beside its pages' own, not before them: it is nobody's middleware
    assert "middleware" not in remove.entry
    assert g.meta["remix"] == {"routes": 14, "pages": 7, "forms": 8, "linked": 7}


def test_the_twins_that_are_no_routes(tmp_path):
    """The same files where nothing depends on Remix; a file beside a `route.tsx` in its folder, a part under
    `app/components` and a file that only the server reads, each exporting the same names; a route folder inside a
    route folder; a `loader` that is not exported; the two that run in the browser (`clientLoader`,
    `clientAction`)."""
    plain = _build(tmp_path / "plain", APP, NO_REMIX)
    assert _entries(plain, "route") == {} and _entries(plain, "page") == {} and "remix" not in plain.meta
    other = {"app/components/list.tsx": HEALTH, "app/models/note.server.ts": HEALTH,
             "app/routes/dashboard/inner/route.tsx": DASH.replace("./chart", "../chart"),
             "app/routes/quiet.tsx": "async function loader() {\n  return null;\n}\nexport const meta = () => [];\n",
             "app/routes/local.tsx": ("export async function clientLoader() {\n  return null;\n}\n"
                                      "export async function clientAction() {\n  return null;\n}\n")}
    g = _build(tmp_path / "other", {**APP, **other})
    assert _entries(g, "route") == ROUTES


def test_a_files_name_is_its_address(tmp_path):
    """`.` in a name is `/` in the address; `_index` is its folder's own page; `$name` one part that changes and a
    bare `$` every part that is left; a part in round brackets may be missing; one that begins with `_` is a
    layout's name and no part of the address; one that ends with `_` keeps its address and leaves its layout; what
    stands in square brackets is meant as written."""
    names = {"_index": "GET /", "about": "GET /about", "concerts.trending": "GET /concerts/trending",
             "concerts.$city": "GET /concerts/:city", "files.$": "GET /files/*",
             "($lang).categories": "GET /:lang?/categories", "shop.(sale).items": "GET /shop/sale?/items",
             "admin": "GET /admin", "admin_.reports": "GET /admin/reports", "_auth.enter": "GET /enter",
             "sitemap[.]xml": "GET /sitemap.xml", "[robots.txt]": "GET /robots.txt",
             "odd.[_index]": "GET /odd/_index", "price-in-[$]": "GET /price-in-$", "[[so-odd]]": "GET /[so-odd]",
             "teams.$teamId.plan[.pdf]": "GET /teams/:teamId/plan.pdf", "reports/route": "GET /reports"}
    page = "export const loader = async () => null;\nexport default function Page() {\n  return <p>x</p>;\n}\n"
    g = _build(tmp_path, {f"app/routes/{name}.tsx": page for name in names})
    assert {i.removeprefix(R).removesuffix("::loader"): d for i, d in _entries(g, "route").items()} == names
    # `admin_.reports` has the address below `/admin` and is not drawn inside `admin.tsx`
    assert _edge(g, R + "admin_.reports::Page", R + "admin::Page") is None
    assert g.nodes[R + "admin::loader"].entry["remix"] == "loader"
    assert _entries(g, "page")[R + "($lang).categories::Page"] == "/:lang?/categories"


# ------------------------------------------------------------------ pages, and what they send
def test_what_a_route_shows_is_a_page_and_a_layout_is_its_frame(tmp_path):
    """What a route file exports by default is the page of its address. A layout's is the frame its pages are drawn
    in (a link from each of them), and so is the root's; a route with nothing to show (`logout`, `healthcheck`) is
    no page."""
    g = _build(tmp_path, APP)
    assert _entries(g, "page") == PAGES
    note = g.nodes[ONE + "Note"]
    assert (note.file, note.start_line, note.lane) == ("app/routes/notes.$noteId.tsx", 20, "browser")
    for frame in (R + "notes::NotesFrame", "js:app/root::App"):
        e = _edge(g, ONE + "Note", frame)
        assert e is not None and (e.confidence, e.via) == ("resolved", "remix-layout"), frame
        assert g.nodes[frame].entry is None
    assert _edge(g, R + "_auth.register::Register", R + "_auth::AuthFrame").via == "remix-layout"
    assert _edge(g, R + "login::Login", R + "notes::NotesFrame") is None
    # the twin: without Remix the files are still read, and nothing is a page
    plain = _build(tmp_path / "plain", APP, NO_REMIX)
    assert _entries(plain, "page") == {} and ONE + "Note" in plain.nodes


def test_a_page_is_linked_to_its_data_and_to_what_its_forms_post_to(tmp_path):
    """The framework's own wiring, so confirmed links: a page gets its data from its own `loader` and from the
    loaders of the layouts it is drawn in; a `<Form method="post">` posts to the `action` of the route it stands
    in, or of the route whose address its `action` writes (a fetcher's form too). The twins: a form that only
    searches (no method), and one that posts to an address no route has."""
    g = _build(tmp_path, APP)
    for dst, said in ((ONE + "loader", "GET /notes/:noteId"), (R + "notes::loader", "GET /notes/*"),
                      ("js:app/root::loader", "GET /*"), (ONE + "action", "POST /notes/:noteId")):
        e = _edge(g, ONE + "Note", dst)
        assert e is not None and (e.confidence, e.via, e.detail) == ("resolved", "http-remix", said), dst
    assert _edge(g, ONE + "Note", ONE + "action").lines == [23]
    sent = {(e.src, e.dst): e.lines for e in g.call_edges() if e.via == "http-remix" and e.dst.endswith("::action")}
    assert sent == {(ONE + "Note", ONE + "action"): [23],
                    (R + "notes._index::NoteList", R + "notes._index::action"): [23],
                    (R + "notes.new::NewNote", R + "notes.new::action"): [14],
                    (R + "login::Login", R + "login::action"): [17],
                    (R + "_auth.register::Register", R + "_auth.register::action"): [13],
                    ("js:app/root::App", R + "logout::action"): [16],
                    (R + "_index::Home", R + "notes.new::action"): [17]}
    # the sign-in page is drawn in no layout but the root: it gets no data from the notes
    assert sorted(e.dst for e in g.call_edges() if e.src == R + "login::Login" and e.via == "http-remix") == [
        "js:app/root::loader", R + "login::action"]


def test_a_request_the_browser_writes_itself_finds_the_route(tmp_path):
    """A `fetch` to a route's address is matched like any request: a GET to its `loader`, and every other verb to
    its `action` (which answers POST, PUT, PATCH and DELETE alike)."""
    g = _build(tmp_path, APP)
    e = _edge(g, R + "_index::peek", R + "api.notes.$noteId[.]json::loader")
    assert e is not None and (e.confidence, e.via) == ("resolved", "http-exact")
    e = _edge(g, R + "_index::wipe", ONE + "action")
    assert e is not None and (e.confidence, e.via) == ("resolved", "http-exact")
    assert _edge(g, R + "_index::wipe", ONE + "loader") is None


# ------------------------------------------------------------------ who may call a route
def test_the_login_check_reads_each_route_by_itself(tmp_path):
    """The check that goes by names, on a helper whose name it reads (`requireUser`). Asked: the actions the pages
    post to that change data. The one that removes a note asks who is signed in through the project's own helper.
    The one that adds a note asks nobody: its layout's loader does, but a layout's loader runs beside its pages'
    routes, not before them, and a request sent straight to the action never passes it. Signing in, signing up and
    signing out are open by their nature."""
    from lantern import websec
    g = _build(tmp_path, NAMED)
    assert sorted(f["title"] for f in websec.missing_auth(g)) == [
        "POST /notes/new changes data, is called by the app, and no login check was found"]
    adj = websec.call_adjacency(g)
    strong = {}
    for nid in (ONE + "action", R + "notes._index::action", R + "notes.new::action"):
        n = g.nodes[nid]
        got = websec.login_check(g, n, adj, (tmp_path / n.file).read_text(encoding="utf-8"))
        strong[n.entry["detail"]] = bool(got and got[0] == "strong")
    assert strong == {"POST /notes/:noteId": True, "POST /notes?index": True, "POST /notes/new": False}


def test_the_readiness_page_names_the_open_action(tmp_path):
    """The whole check, on the helper with a name that says nothing (`needUser`): by names alone three actions read
    as open; what the helper's code does shows the login of two, and one finding and one line of the card are left."""
    from lantern import websec
    from lantern.readiness import assess
    from lantern.security import scan
    g = _build(tmp_path, APP)
    assert len(websec.missing_auth(g)) == 3
    sec = scan(g, offline=True)
    assert [f["title"] for f in sec["findings"] if f["rule"] == "LW-AUTH-MISSING"] == [
        "POST /notes/new changes data, is called by the app, and no login check was found"]
    prot = {p["id"]: p for p in assess(g, sec, {})["protections"]}
    assert sorted(x.split(" (")[0] for x in prot["route-auth"]["evidence"]) == ["POST /notes/new"]


def test_a_session_cookie_the_server_signed_says_who_is_signed_in(tmp_path):
    """Read from what the code does: the helper reads the session out of the request's cookie with the storage the
    app made (`createCookieSessionStorage`, signed with the app's secret), and sends a request with nobody in it to
    the sign-in page. The routes that go through it show a login; the root's loader, which only looks who is there,
    the action that adds a note and the two that ask nobody do not. And the owner rule: the action that removes a
    note picks it by the id in the address alone; the loader beside it asks for the id and the owner."""
    from lantern.security import scan
    g = _build(tmp_path, APP)
    sec = scan(g, offline=True)
    assert sorted(g.nodes[i].entry["detail"] for i in sec["logins_shown"]) == [
        "GET /notes", "GET /notes/*", "GET /notes/:noteId", "POST /notes/:noteId", "POST /notes?index"]
    owner = [f for f in sec["findings"] if f["rule"] == "LT-AUTHZ-OWNER"]
    assert [(f["file"], f["line"], f["routes"]) for f in owner] == [
        ("app/routes/notes.$noteId.tsx", 16, ["POST /notes/:noteId"])]


SIGNED_IN = ["GET /notes", "GET /notes/*", "GET /notes/:noteId", "POST /notes/:noteId", "POST /notes?index"]
STORE = 'cookie: { name: "__session", httpOnly: true, sameSite: "lax", secrets: [process.env.SESSION_SECRET] },'
MADE = "const storage = createCookieSessionStorage({\n  " + STORE + "\n});\n"
ASKS = ('  const userId = await whoIs(request);\n  if (!userId) throw redirect("/login");\n'
        "  return userId;\n")
APART = "createCookie, createCookieSessionStorage, redirect"
ASKED_THERE = '  const session = await storage.getSession(request.headers.get("Cookie"));\n'
# the session as the library hands it back shows a login where the server alone can have written it ...
SIGNED = {
    "the cookie made apart, with secrets": lambda t: t.replace("createCookieSessionStorage, redirect", APART).replace(
        MADE, 'const kept = createCookie("__session", { httpOnly: true, secrets: [process.env.SESSION_SECRET] });\n'
              "const storage = createCookieSessionStorage({ cookie: kept });\n"),
    "the storage taken apart": lambda t: t.replace(
        "const storage = createCookieSessionStorage(",
        "const { getSession, commitSession, destroySession } = createCookieSessionStorage(")
    .replace("storage.getSession(", "getSession(").replace("storage.commitSession(", "commitSession(")
    .replace("storage.destroySession(", "destroySession("),
    "asked with has": lambda t: t.replace(
        ASKS, ASKED_THERE + '  if (!session.has("userId")) throw redirect("/login");\n'
                            '  return session.get("userId");\n'),
    "the key under a name": lambda t: t.replace('session.get("userId")', "session.get(KEY)")
    .replace("\nconst storage", '\nconst KEY = "userId";\nconst storage'),
    "kept in a file on the server": lambda t: t.replace("createCookieSessionStorage", "createFileSessionStorage")
    .replace(STORE, 'dir: "/var/sessions", cookie: { name: "__session" },'),
}
# ... and none where a visitor can write the cookie, or where what is asked says nothing of who it is
UNSIGNED = {
    "no secrets": lambda t: t.replace(", secrets: [process.env.SESSION_SECRET]", ""),
    "an empty list of secrets": lambda t: t.replace("secrets: [process.env.SESSION_SECRET]", "secrets: []"),
    "a secret that may be empty": lambda t: t.replace("[process.env.SESSION_SECRET]",
                                                      '[process.env.SESSION_SECRET || ""]'),
    "the cookie made apart, with none": lambda t: t.replace("createCookieSessionStorage, redirect", APART).replace(
        MADE, 'const kept = createCookie("__session", { httpOnly: true });\n'
              "const storage = createCookieSessionStorage({ cookie: kept });\n"),
    "a key that names nobody": lambda t: t.replace('return session.get("userId")', 'return session.get("theme")'),
    "the session itself": lambda t: t.replace(
        ASKS, ASKED_THERE + '  if (!session) throw redirect("/login");\n  return session.id;\n'),
}

HELD = "app/session.server.ts"


def _logins(root, files):
    from lantern import flow
    g = _build(root, files)
    res = flow.analyze(g)
    assert not res.errors
    return sorted(g.nodes[i].entry["detail"] for i in res.logins)


def test_a_session_shows_a_login_only_where_the_server_alone_wrote_it(tmp_path):
    """Each way of keeping the session, with the same routes around it. A cookie that holds the whole session and
    is not signed is the visitor's own to write, so `session.get("userId")` out of it says nothing; neither does a
    key that names nobody, nor the session itself, which a visitor has too."""
    assert _logins(tmp_path / "as-written", APP) == SIGNED_IN
    for i, (name, change) in enumerate(SIGNED.items()):
        text = change(SESSION)
        assert text != SESSION, name
        assert _logins(tmp_path / f"signed{i}", {**APP, HELD: text}) == SIGNED_IN, name
    for i, (name, change) in enumerate(UNSIGNED.items()):
        text = change(SESSION)
        assert text != SESSION, name
        assert _logins(tmp_path / f"unsigned{i}", {**APP, HELD: text}) == [], name


SESSIONS = '''import { createCookieSessionStorage } from "@remix-run/node";

export const { getSession, commitSession, destroySession } = createCookieSessionStorage({
  cookie: { name: "__session", httpOnly: true, secrets: [process.env.SESSION_SECRET] },
});
'''
ASKS_ITSELF = '''import type { LoaderFunctionArgs } from "@remix-run/node";
import { json, redirect } from "@remix-run/node";
import { db } from "~/db.server";
import { getSession } from "~/sessions.server";

export async function loader({ request }: LoaderFunctionArgs) {
  const session = await getSession(request.headers.get("Cookie"));
  if (!session.has("userId")) return redirect("/login");
  return json(await db.note.findMany({ where: { ownerId: session.get("userId") } }));
}
'''


def test_a_storage_made_in_another_file_is_that_storage(tmp_path):
    """As the framework's own guide writes it: one file makes the storage and exports its three functions, and a
    route asks the session itself. The twins: the same storage with no secrets, which shows nothing; and the file
    taken as a whole (`import * as`), where which storage is asked is not followed and nothing is shown either way."""
    files = {"tsconfig.json": TSCONFIG, "app/db.server.ts": DB, "app/sessions.server.ts": SESSIONS,
             "app/routes/notes._index.tsx": ASKS_ITSELF}
    plain = {**files, "app/sessions.server.ts": SESSIONS.replace(", secrets: [process.env.SESSION_SECRET]", "")}
    whole = ASKS_ITSELF.replace("import { getSession }", "import * as sessions").replace("await getSession(",
                                                                                        "await sessions.getSession(")
    assert plain != files and whole != ASKS_ITSELF
    assert _logins(tmp_path / "signed", files) == ["GET /notes"]
    assert _logins(tmp_path / "plain", plain) == []
    assert _logins(tmp_path / "whole", {**files, "app/routes/notes._index.tsx": whole}) == []
    assert _logins(tmp_path / "whole-plain", {**plain, "app/routes/notes._index.tsx": whole}) == []


# ------------------------------------------------------------------ what the caller sends
SENT = '''import { exec } from "child_process";
import { Pool } from "pg";
const pool = new Pool();

export async function loader({ request, params, context }) {
  const url = new URL(request.url);
  const one = await pool.query("select * from notes where id = '" + params.noteId + "'");
  const found = await pool.query("select * from notes where text like '" + url.searchParams.get("q") + "'");
  const mine = await pool.query("select * from notes where owner = '" + context.userId + "'");
  return { one, found, mine };
}

export async function action(args) {
  const form = await args.request.formData();
  exec("tar czf /backups/" + form.get("name") + ".tgz /data");
  await pool.query("select * from notes where text = $1", [form.get("text")]);
  return null;
}
'''


def test_what_the_caller_sends_is_followed_and_what_the_server_made_is_not(tmp_path):
    """The address's parts (`params`), its question (`new URL(request.url).searchParams`) and a form's fields
    arrive with the request, whether the route takes its one argument apart or whole; `context` is what the server
    itself put there, and a query with a placeholder is safe. The twin: the same file where nothing says Remix is
    no route. There only what the older reading takes for a request by its name is followed (`{ request, params }`),
    and an argument kept whole (`args`) is not."""
    from lantern import flow
    files = {"app/routes/notes.$noteId.tsx": SENT}
    res = flow.analyze(_build(tmp_path, files))
    assert not res.errors, res.errors
    assert sorted((f["class"], f["line"]) for f in res.flows) == [("shell", 15), ("sql", 7), ("sql", 8)]
    plain = flow.analyze(_build(tmp_path / "plain", files, NO_REMIX))
    assert sorted((f["class"], f["line"]) for f in plain.flows) == [("sql", 7), ("sql", 8)]


# ------------------------------------------------------------------ React Router's framework mode, and Remix 1
RR_PKG = json.dumps({"dependencies": {"react-router": "7.6.0", "@react-router/node": "7.6.0",
                                      "@react-router/fs-routes": "7.6.0", "@prisma/client": "5.14.0", "react": "19.0.0"},
                     "devDependencies": {"@react-router/dev": "7.6.0", "vite": "6.0.0", "typescript": "5.7.0"}})
BY_NAME = ('import { type RouteConfig } from "@react-router/dev/routes";\n'
           'import { flatRoutes } from "@react-router/fs-routes";\n\n'
           'export default flatRoutes() satisfies RouteConfig;\n')


def test_react_routers_framework_mode_reads_the_same_files(tmp_path):
    """React Router 7 took Remix's place and kept its route files. Where `app/routes.ts` says the routes are the
    files of `app/routes` (`flatRoutes()`), they are read by the same rules. The twin: the same app with no
    `app/routes.ts`, where nothing says which files are routes."""
    app = {k: v.replace("@remix-run/node", "react-router").replace("@remix-run/react", "react-router")
           for k, v in APP.items()}
    g = _build(tmp_path / "named", {**app, "app/routes.ts": BY_NAME}, RR_PKG)
    assert _entries(g, "route") == ROUTES and _entries(g, "page") == PAGES
    assert _edge(g, ONE + "Note", ONE + "action").via == "http-remix"
    bare = _build(tmp_path / "bare", app, RR_PKG)
    assert _entries(bare, "route") == {} and "remix" not in bare.meta


def test_remix_1_and_its_folders_are_not_guessed_at(tmp_path):
    """Remix 1 kept its routes in folders (`routes/notes/index.tsx`), and the same file names mean other
    addresses there. Such an app's routes are not read (the result says so) rather than read wrongly; with the
    switch that turns the newer names on (`v2_routeConvention`), they are, by the newer rules: the folder's
    `index.tsx` is then the route of the folder's name, and no index."""
    old = PKG.replace("2.9.2", "^1.19.3")
    files = {"app/root.tsx": ROOT, "app/session.server.ts": SESSION, "tsconfig.json": TSCONFIG,
             "app/routes/index.tsx": HOME, "app/routes/notes/index.tsx": NOTE_LIST, "app/routes/login.tsx": LOGIN}
    g = _build(tmp_path / "old", files, old)
    assert _entries(g, "route") == {} and _entries(g, "page") == {}
    assert g.meta["remix"] == {"routes": 0, "pages": 0, "forms": 0, "linked": 0, "not_read": "Remix 1 route folders"}
    config = 'module.exports = {\n  future: { v2_routeConvention: true },\n};\n'
    g = _build(tmp_path / "switched", {**files, "remix.config.js": config}, old)
    assert _entries(g, "route") == {"js:app/root::loader": "GET /*", R + "login::action": "POST /login",
                                    R + "notes/index::loader": "GET /notes", R + "notes/index::action": "POST /notes"}


# ------------------------------------------------------------------ doors that are not written in the route file
TAGS = '''import { db } from "~/db.server";

export async function loader({ params }) {
  return { tag: await db.tag.findUnique({ where: { id: params.tagId } }) };
}

async function wipe({ params }) {
  await db.tag.delete({ where: { id: params.tagId } });
  return null;
}

export { wipe as action };
'''
TAG_PAGE = '''export { loader, action } from "~/tags.server";

export default function Tag() {
  return <p>tag</p>;
}
'''
TAG_USES = '''import { loader as read } from "~/tags.server";

export async function loader(args) {
  return read(args);
}

export default function Tag() {
  return <p>tag</p>;
}
'''
S = "js:app/tags.server::"


def test_a_door_handed_on_from_another_file_is_that_routes(tmp_path):
    """`export { loader, action } from "~/tags.server"`: the route's doors are the functions of that file, under
    the route's address (written the two ways the language has: handed on in one line, or taken in and exported).
    The twins: the same file when no route hands it on, and a route that takes the function in and calls it from
    a loader of its own, which is then the door."""
    files = {**APP, "app/tags.server.ts": TAGS}
    two = TAG_PAGE.replace('export { loader, action } from "~/tags.server";',
                           'import { loader, action } from "~/tags.server";\n\nexport { loader, action };')
    assert two != TAG_PAGE
    for name, page in (("one-line", TAG_PAGE), ("two-lines", two)):
        g = _build(tmp_path / name, {**files, "app/routes/tags.$tagId.tsx": page})
        assert _entries(g, "route") == {**ROUTES, S + "loader": "GET /tags/:tagId", S + "wipe": "POST /tags/:tagId"}
        assert g.nodes[S + "wipe"].entry["remix"] == "action" and g.nodes[S + "wipe"].lane == "server"
        e = _edge(g, R + "tags.$tagId::Tag", S + "loader")
        assert e is not None and (e.confidence, e.via, e.detail) == ("resolved", "http-remix", "GET /tags/:tagId")
        # the file the doors stand in shows nothing: all of it is the server's
        assert "component" not in g.nodes[S + "loader"].entry
    alone = _build(tmp_path / "alone", files)
    assert _entries(alone, "route") == ROUTES
    used = _build(tmp_path / "used", {**files, "app/routes/tags.$tagId.tsx": TAG_USES})
    assert _entries(used, "route") == {**ROUTES, R + "tags.$tagId::loader": "GET /tags/:tagId"}


GUARD = '''import { needUser } from "~/session.server";

export function guarded(inner) {
  return async (args) => {
    const userId = await needUser(args.request);
    return inner({ ...args, userId });
  };
}

export function timed(inner) {
  return async (args) => {
    const began = Date.now();
    const out = await inner(args);
    console.log(Date.now() - began);
    return out;
  };
}
'''
TEAMS = '''import { redirect } from "@remix-run/node";
import { Form } from "@remix-run/react";
import { db } from "~/db.server";
import { guarded, timed } from "~/guard.server";

export const loader = timed(async ({ params }) => {
  return { team: await db.team.findUnique({ where: { id: params.teamId } }) };
});

export const action = guarded(async ({ request }) => {
  const form = await request.formData();
  await db.team.create({ data: { name: String(form.get("name")) } });
  return redirect("/teams");
});

export default function Teams() {
  return <Form method="post"><input name="name" /><button>Add</button></Form>;
}
'''
T = R + "teams::"
OPEN = "POST {} changes data, is called by the app, and no login check was found"


def test_the_login_of_a_helper_that_makes_a_door_is_seen(tmp_path):
    """`export const action = guarded(async (args) => …)`: what the helper hands back runs first on every request
    and calls the function written here, so the helper is kept as the route's middleware is, with a link to it,
    and the login it asks for is the route's (the helper's name says nothing; its code is read). The twin: the
    same action made by a helper that only measures time, which stays open."""
    from lantern import flow
    from lantern.security import scan
    files = {**APP, "app/guard.server.ts": GUARD, "app/routes/teams.tsx": TEAMS}
    g = _build(tmp_path / "guarded", files)
    assert {i: d for i, d in _entries(g, "route").items() if i.startswith(T)} == {
        T + "loader": "GET /teams", T + "action": "POST /teams"}
    assert g.nodes[T + "action"].entry["middleware"] == ["js:app/guard.server::guarded"]
    assert g.nodes[T + "loader"].entry["middleware"] == ["js:app/guard.server::timed"]
    e = _edge(g, T + "action", "js:app/guard.server::guarded")
    assert e is not None and (e.confidence, e.via) == ("inferred", "action-helper")
    res = flow.analyze(g)
    assert not res.errors
    shown = sorted(g.nodes[i].entry["detail"] for i in res.logins)
    assert "POST /teams" in shown and "GET /teams" not in shown
    titles = [f["title"] for f in scan(g, offline=True)["findings"] if f["rule"] == "LW-AUTH-MISSING"]
    assert titles == [OPEN.format("/notes/new")]
    # the twin
    bare = TEAMS.replace("export const action = guarded(", "export const action = timed(")
    assert bare != TEAMS
    g = _build(tmp_path / "timed", {**files, "app/routes/teams.tsx": bare})
    assert g.nodes[T + "action"].entry["middleware"] == ["js:app/guard.server::timed"]
    assert "POST /teams" not in sorted(g.nodes[i].entry["detail"] for i in flow.analyze(g).logins)
    titles = [f["title"] for f in scan(g, offline=True)["findings"] if f["rule"] == "LW-AUTH-MISSING"]
    assert sorted(titles) == [OPEN.format("/notes/new"), OPEN.format("/teams")]


SETTINGS = '''import { Form } from "@remix-run/react";
import { db } from "~/db.server";

export async function loader() {
  return { n: await db.setting.count() };
}

export async function action({ request }) {
  const form = await request.formData();
  await db.setting.create({ data: { name: String(form.get("name")) } });
  return null;
}

export default function Settings() {
  return <Form method="post"><input name="name" /></Form>;
}
'''


def test_an_index_file_in_a_route_folder_is_the_route_when_no_route_file_is_there(tmp_path):
    """`app/routes/settings/index.tsx`, the first name Remix gave a route folder's own file and still reads. The
    twins: beside a `route.tsx` it is one more file of the folder; one folder deeper it is no route; and a file
    named `index` among the route files themselves is the address `/index`, as it was."""
    at = R + "settings/index::"
    g = _build(tmp_path / "index", {**APP, "app/routes/settings/index.tsx": SETTINGS})
    assert _entries(g, "route") == {**ROUTES, at + "loader": "GET /settings", at + "action": "POST /settings"}
    assert _entries(g, "page") == {**PAGES, at + "Settings": "/settings"}
    assert _edge(g, at + "Settings", at + "action").via == "http-remix"
    both = _build(tmp_path / "both", {**APP, "app/routes/dashboard/index.tsx": SETTINGS})
    assert _entries(both, "route") == ROUTES and _entries(both, "page") == PAGES
    deep = _build(tmp_path / "deep", {**APP, "app/routes/settings/parts/index.tsx": SETTINGS})
    assert _entries(deep, "route") == ROUTES and _entries(deep, "page") == PAGES
    flat = _build(tmp_path / "flat", {**APP, "app/routes/index.tsx": SETTINGS})
    assert _entries(flat, "route") == {**ROUTES, R + "index::loader": "GET /index", R + "index::action": "POST /index"}


RELATIVE = '''import { Form } from "@remix-run/react";
import { db } from "~/db.server";
import { needUser } from "~/session.server";

export async function action({ request }) {
  const userId = await needUser(request);
  await db.note.deleteMany({ where: { ownerId: userId } });
  return null;
}

export default function NoteList() {
  return (
    <div>
      <Form method="post" action="new"><input name="title" /></Form>
      <Form method="post" action="./new"><input name="title" /></Form>
      <Form method="post" action="."><button>Remove all</button></Form>
      <Form method="post" action="?index"><button>Remove all</button></Form>
      <Form method="post" action="../logout"><button>Sign out</button></Form>
      <Form method="post" action="nowhere/at/all"><button>x</button></Form>
    </div>
  );
}
'''
FRAME_FORM = NOTES_FRAME.replace("<Outlet />", '<Form method="post" action="new"><input name="title" /></Form><Outlet />')
PART = '''import { Form } from "@remix-run/react";

export function QuickNote() {
  return <Form method="post" action="new"><input name="title" /></Form>;
}
'''


def test_a_form_whose_address_is_read_from_where_it_stands(tmp_path):
    """`action="new"` in the page of `/notes` posts to `/notes/new`; `.` is the route the form stands in and
    `?index` its index. The twins: an address that climbs (`..`: which route is one step up is not worked out), one
    no route has, and the same words in a part that is no route file, which stands wherever it is shown."""
    assert FRAME_FORM != NOTES_FRAME
    files = {**APP, "app/routes/notes._index.tsx": RELATIVE, "app/routes/notes.tsx": FRAME_FORM.replace(
        'import { Outlet, useLoaderData }', 'import { Form, Outlet, useLoaderData }'),
        "app/components/quick.tsx": PART}
    g = _build(tmp_path, files)
    page = R + "notes._index::NoteList"
    sent = sorted((e.dst, tuple(e.lines), e.confidence) for e in g.call_edges()
                  if e.via == "http-remix" and e.src == page and e.dst.endswith("::action"))
    assert sent == [(R + "notes._index::action", (16, 17), "resolved"), (R + "notes.new::action", (14, 15), "resolved")]
    assert _edge(g, R + "notes::NotesFrame", R + "notes.new::action").lines == [14]
    assert not [e for e in g.call_edges() if e.src.startswith("js:app/components/quick") and e.via == "http-remix"]
    # 8 forms in the app as it was: one of the page's replaced by six, one more in the frame, one in the part
    assert (g.meta["remix"]["forms"], g.meta["remix"]["linked"]) == (15, 11)
