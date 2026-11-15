"""SvelteKit routes (roadmap of 2026-11-14, stage 1).

A SvelteKit app's doors are files with fixed names under `src/routes`: `+server.ts` (one function per verb),
`+page.server.ts` (`load`, which hands the page its data, and `actions`, which a form posts to) and
`+layout.server.ts`; `src/hooks.server.ts` runs before every one of them. Until now none of them was an entry point,
`$lib/…` was read as a library, and a `.svelte` file was not read at all.

Each shape sits beside twins that must stay as they were."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from lantern import report
from lantern.engine import build_graph

PKG = json.dumps({"devDependencies": {"@sveltejs/kit": "2.5.0", "svelte": "5.0.0", "vite": "5.0.0", "typescript": "5.4.0"},
                  "dependencies": {"@prisma/client": "5.14.0", "pg": "8.11.5"}})
NO_KIT = json.dumps({"dependencies": {"@prisma/client": "5.14.0", "pg": "8.11.5"}})
CONFIG = 'import adapter from "@sveltejs/adapter-auto";\nexport default { kit: { adapter: adapter() } };\n'
DB = 'import { PrismaClient } from "@prisma/client";\nexport const db = new PrismaClient();\n'
AUTH = '''import { error } from "@sveltejs/kit";

export function requireUser(locals: App.Locals) {
  if (!locals.user) throw error(401, "sign in");
  return locals.user;
}
'''
HOOKS = '''import type { Handle } from "@sveltejs/kit";
import { readUser } from "$lib/server/session";

export const handle: Handle = async ({ event, resolve }) => {
  event.locals.user = await readUser(event.cookies.get("session"));
  return resolve(event);
};
'''
NOTES_SERVER = '''import { error } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { db } from "$lib/server/db";
import { requireUser } from "$lib/server/auth";

export const load: PageServerLoad = async ({ locals }) => {
  return { notes: await db.note.findMany({ where: { ownerId: locals.user?.id } }) };
};

export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    await db.note.create({ data: { text: String(data.get("text")) } });
  },
  remove: async ({ request, locals }) => {
    if (!locals.user) throw error(401, "sign in");
    const data = await request.formData();
    await db.note.delete({ where: { id: String(data.get("id")) } });
  },
  rename: async (event) => {
    const user = requireUser(event.locals);
    const data = await event.request.formData();
    await db.note.update({ where: { id: String(data.get("id")), ownerId: user.id }, data: { text: String(data.get("text")) } });
  },
} satisfies Actions;
'''
NOTES_PAGE = '''<script lang="ts">
  import Card from "$lib/Card.svelte";
  let { data } = $props();
  async function refresh() {
    const res = await fetch("/api/notes");
    return res.json();
  }
  async function add(text: string) {
    await fetch("/api/notes", { method: "POST", body: JSON.stringify({ text }) });
  }
  async function wipe(id: string) {
    await fetch(`/api/notes/${id}`, { method: "DELETE" });
  }
</script>

<h1>Notes</h1>
<form method="POST">
  <input name="text" /><button>Add</button>
</form>
{#each data.notes as note}
  <Card {note} />
  <form method="POST" action="?/remove"><input type="hidden" name="id" value={note.id} /><button>Remove</button></form>
  <form method="POST" action="?/rename"><input name="text" /><button>Rename</button></form>
  <button onclick={() => wipe(note.id)}>Wipe</button>
{/each}
<button on:click={refresh}>Again</button>
<form action="/search"><input name="q" /></form>
<form method="POST" action="?/missing"><button>x</button></form>
'''
CARD = '<script>\n  export let note;\n</script>\n<p>{note.text}</p>\n'
API = '''import { error, json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { db } from "$lib/server/db";

export const GET: RequestHandler = async ({ url }) => {
  return json(await db.note.findMany({ where: { text: { contains: url.searchParams.get("q") ?? "" } } }));
};

export async function POST({ request, locals }) {
  const session = await locals.auth();
  if (!session) throw error(401, "sign in");
  const body = await request.json();
  return json(await db.note.create({ data: { text: body.text } }));
}
'''
API_ID = '''import { json } from "@sveltejs/kit";
import { db } from "$lib/server/db";

export const DELETE = async ({ params }) => {
  await db.note.delete({ where: { id: params.id } });
  return json({ ok: true });
};
'''
SETTINGS_SERVER = '''import type { Actions } from "./$types";
import { db } from "$lib/server/db";

export async function load(event) {
  return { name: event.locals.user?.name };
}

async function save(event) {
  const data = await event.request.formData();
  await db.user.update({ where: { id: event.locals.user.id }, data: { name: String(data.get("name")) } });
}

export const actions: Actions = { save };
'''
SETTINGS_PAGE = '<script>\n  export let data;\n</script>\n<form method="POST" action="?/save"><input name="name" value={data.name} /></form>\n'
LAYOUT_SERVER = 'export const load = async ({ locals }) => ({ user: locals.user });\n'
APP = {"svelte.config.js": CONFIG, "src/hooks.server.ts": HOOKS, "src/lib/server/db.ts": DB,
       "src/lib/server/auth.ts": AUTH, "src/lib/Card.svelte": CARD, "src/routes/+page.svelte": "<h1>Home</h1>\n",
       "src/routes/notes/+page.server.ts": NOTES_SERVER, "src/routes/notes/+page.svelte": NOTES_PAGE,
       "src/routes/api/notes/+server.ts": API, "src/routes/api/notes/[id]/+server.ts": API_ID,
       "src/routes/(app)/+layout.server.ts": LAYOUT_SERVER, "src/routes/(app)/settings/+page.server.ts": SETTINGS_SERVER,
       "src/routes/(app)/settings/+page.svelte": SETTINGS_PAGE}
NOTES = "js:src/routes/notes/+page.server::"
PAGE = "js:src/routes/notes/+page.svelte::+page"


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


# ------------------------------------------------------------------ the files with fixed names are routes
def test_each_door_of_a_sveltekit_app_is_a_route(tmp_path):
    """`+server.ts`: one route per verb it exports. `+page.server.ts`: `load` answers the page's own address with
    its data, each of `actions` a form's POST (`?/name`; `default` is the address itself). `+layout.server.ts`:
    `load` runs for every page below it. `hooks.server.ts`: `handle` runs before all of them. A folder in round
    brackets is no part of the address (a layout's `load` keeps it: it runs for the pages of that group only)."""
    g = _build(tmp_path, APP)
    assert _entries(g, "route") == {
        "js:src/routes/api/notes/+server::GET": "GET /api/notes",
        "js:src/routes/api/notes/+server::POST": "POST /api/notes",
        "js:src/routes/api/notes/[id]/+server::DELETE": "DELETE /api/notes/[id]",
        NOTES + "load": "GET /notes",
        NOTES + "actions.default": "POST /notes",
        NOTES + "actions.remove": "POST /notes?/remove",
        NOTES + "actions.rename": "POST /notes?/rename",
        "js:src/routes/(app)/settings/+page.server::load": "GET /settings",
        "js:src/routes/(app)/settings/+page.server::save": "POST /settings?/save",
        "js:src/routes/(app)/+layout.server::load": "GET /(app)/*",
        "js:src/hooks.server::handle": "ANY /*"}
    remove = g.nodes[NOTES + "actions.remove"]
    assert remove.entry["sveltekit"] == "action" and remove.lane == "server"
    assert (remove.file, remove.start_line) == ("src/routes/notes/+page.server.ts", 15)
    assert g.nodes[NOTES + "load"].entry["sveltekit"] == "load"
    assert g.nodes["js:src/routes/(app)/+layout.server::load"].entry["sveltekit"] == "layout load"
    assert g.nodes["js:src/routes/api/notes/+server::POST"].entry["sveltekit"] == "endpoint"
    # the one function every request passes: marked, so that nothing counts it as a route that changes data
    handle = g.nodes["js:src/hooks.server::handle"]
    assert handle.entry["sveltekit"] == "handle" and handle.entry["serves"] == "sveltekit"
    # ... and it is named on every route as what runs before it
    assert remove.entry["middleware"] == ["js:src/hooks.server::handle"]
    assert g.meta["sveltekit"] == {"routes": 10, "pages": 3, "forms": 5, "linked": 4}


def test_the_twins_that_are_no_routes(tmp_path):
    """The same files where nothing depends on SvelteKit; a `+server.ts` that is not under `src/routes`; a file
    beside a route that exports the same names; a page's `load` that also runs in the browser (`+page.ts`); `actions`
    in a file that is no `+page.server`."""
    plain = _build(tmp_path / "plain", APP, NO_KIT)
    assert _entries(plain, "route") == {}
    other = {"src/lib/+server.ts": API, "src/routes/api/notes/helpers.ts": API_ID,
             "src/routes/notes/+page.ts": "export const load = async ({ fetch }) => ({ tags: await fetch('/api/tags') });\n",
             "src/routes/notes/forms.ts": "export const actions = { default: async () => 1 };\n"}
    g = _build(tmp_path / "other", {**APP, **other})
    assert len(_entries(g, "route")) == 11
    assert not [i for i in _entries(g, "route") if "helpers" in i or "/lib/" in i or "+page::" in i or "forms" in i]


def test_addresses_with_parts_that_change(tmp_path):
    """`[id]` is one part of the address, `[[lang]]` one that may be missing, `[...rest]` every part that is left,
    `[id=integer]` a part with a rule; `(group)` and a file's own name are no part of it."""
    verb = "export const GET = async () => new Response('ok');\n"
    files = {"svelte.config.js": CONFIG,
             "src/routes/[[lang]]/about/+server.ts": verb,
             "src/routes/files/[...rest]/+server.ts": verb,
             "src/routes/items/[id=integer]/+server.ts": verb,
             "src/routes/(shop)/(inner)/cart/+server.ts": verb,
             "src/routes/+server.ts": verb}
    assert sorted(_entries(_build(tmp_path, files), "route").values()) == [
        "GET /", "GET /[[lang]]/about", "GET /cart", "GET /files/[...rest]", "GET /items/[id]"]


# ------------------------------------------------------------------ pages, and what they send
def test_a_svelte_page_is_a_page_and_its_script_is_read(tmp_path):
    """`+page.svelte` is the page of its folder's address. Its `<script>` is read with the file's own line numbers
    (TypeScript too), a component it draws is a link, and so is a function its markup hands to a click."""
    g = _build(tmp_path, APP)
    assert _entries(g, "page") == {"js:src/routes/+page.svelte::+page": "/", PAGE: "/notes",
                                   "js:src/routes/(app)/settings/+page.svelte::+page": "/settings"}
    page = g.nodes[PAGE]
    assert (page.file, page.start_line, page.lane) == ("src/routes/notes/+page.svelte", 1, "browser")
    wipe = g.nodes[PAGE + ".wipe"]
    assert (wipe.start_line, wipe.end_line, wipe.lane) == (11, 13, "frontend")
    card = g.nodes["js:src/lib/Card.svelte::Card"]
    assert card.entry is None and card.lane == "frontend"
    assert _edge(g, PAGE, card.id) is not None                  # <Card {note} />
    assert _edge(g, PAGE, PAGE + ".wipe") is not None           # onclick={() => wipe(note.id)}
    assert _edge(g, PAGE, PAGE + ".refresh") is not None        # on:click={refresh}
    # the twin: without SvelteKit a .svelte file is still read, and is no page
    plain = _build(tmp_path / "plain", APP, NO_KIT)
    assert _entries(plain, "page") == {} and PAGE + ".wipe" in plain.nodes


def test_a_page_is_linked_to_its_data_and_to_what_its_forms_post_to(tmp_path):
    """The framework's own wiring, so confirmed links: a page gets its data from the `load` beside it and from the
    layouts above it, a form with `method="POST"` posts to the action its `action` names (none: `default`). A fetch
    in the script is matched to a `+server.ts` like any request. The twins: a form that only searches (no POST), and
    one that names an action that is not there."""
    g = _build(tmp_path, APP)
    for name, said in (("load", "GET /notes"), ("actions.default", "POST /notes"),
                       ("actions.remove", "POST /notes?/remove"), ("actions.rename", "POST /notes?/rename")):
        e = _edge(g, PAGE, NOTES + name)
        assert e is not None and (e.confidence, e.via, e.detail) == ("resolved", "http-sveltekit", said), name
    assert [e.dst for e in g.call_edges() if e.src == PAGE and e.via == "http-sveltekit"] == [
        NOTES + "load", NOTES + "actions.default", NOTES + "actions.remove", NOTES + "actions.rename"]
    settings = "js:src/routes/(app)/settings/+page.svelte::+page"
    assert sorted(e.dst for e in g.call_edges() if e.src == settings and e.via == "http-sveltekit") == [
        "js:src/routes/(app)/+layout.server::load", "js:src/routes/(app)/settings/+page.server::load",
        "js:src/routes/(app)/settings/+page.server::save"]
    e = _edge(g, PAGE + ".add", "js:src/routes/api/notes/+server::POST")
    assert e is not None and (e.confidence, e.via) == ("resolved", "http-exact")
    e = _edge(g, PAGE + ".wipe", "js:src/routes/api/notes/[id]/+server::DELETE")
    assert e is not None and (e.confidence, e.via) == ("resolved", "http-exact")


def test_lib_is_the_projects_own_folder(tmp_path):
    """`$lib/server/auth` is `src/lib/server/auth.ts`: a call into it is a link to the project's function, and a
    value it exports is followed. `$app/…` and `$env/…` are SvelteKit's own. The twin: where nothing says SvelteKit,
    `$lib` is left as it was read before."""
    g = _build(tmp_path, APP)
    e = _edge(g, NOTES + "actions.rename", "js:src/lib/server/auth::requireUser")
    assert e is not None and e.confidence == "resolved"
    assert _edge(g, NOTES + "actions.remove", "ext:@prisma/client.PrismaClient.note.delete") is not None
    assert g.nodes["js:src/lib/server/auth::requireUser"].lane == "server"
    plain = {k: v for k, v in APP.items() if k != "svelte.config.js"}
    g = _build(tmp_path / "plain", plain, NO_KIT)
    assert _edge(g, NOTES + "actions.rename", "js:src/lib/server/auth::requireUser") is None


# ------------------------------------------------------------------ who may call a route
def test_the_login_check_reads_what_the_server_knows_of_the_caller(tmp_path):
    """Asked: the routes the pages send to that change data. `locals` is what the server's own hook put there:
    a route that turns away a request with no `locals.user` checks who is asking, by its own lines, by a helper of
    the project, or by `locals.auth()`; one that only reads `locals.user` counts too, as `req.user` does on every
    other framework (nobody signed in: nothing there to read). The form's default action and the endpoint that
    removes a note ask nobody."""
    from lantern import websec
    g = _build(tmp_path, APP)
    assert sorted(f["title"] for f in websec.missing_auth(g)) == [
        "DELETE /api/notes/[id] changes data, is called by the app, and no login check was found",
        "POST /notes changes data, is called by the app, and no login check was found"]
    adj = websec.call_adjacency(g)
    strong = {}
    for nid in (NOTES + "actions.default", NOTES + "actions.remove", NOTES + "actions.rename",
                "js:src/routes/api/notes/+server::POST", "js:src/routes/(app)/settings/+page.server::save"):
        n = g.nodes[nid]
        got = websec.login_check(g, n, adj, (tmp_path / n.file).read_text(encoding="utf-8"))
        strong[nid.split("::")[1]] = bool(got and got[0] == "strong")
    assert strong == {"actions.default": False, "actions.remove": True, "actions.rename": True, "POST": True,
                      "save": True}


def test_the_readiness_page_counts_the_routes_and_not_the_hook(tmp_path):
    from lantern.readiness import assess
    from lantern.security import scan
    g = _build(tmp_path, APP)
    prot = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}
    assert sorted(x.split(" (")[0] for x in prot["route-auth"]["evidence"]) == [
        "DELETE /api/notes/[id]", "POST /notes"]
    assert not [x for p in prot.values() for x in [*p.get("evidence", []), *p.get("found", [])] if "ANY /*" in x]


# ------------------------------------------------------------------ what the caller sends
SENT = '''import { exec } from "child_process";
import { Pool } from "pg";
const pool = new Pool();

export const load = async ({ params, url, locals }) => {
  const one = await pool.query("select * from notes where id = '" + params.id + "'");
  const found = await pool.query("select * from notes where text like '" + url.searchParams.get("q") + "'");
  const mine = await pool.query("select * from notes where owner = '" + locals.user.id + "'");
  return { one, found, mine };
};

export const actions = {
  backup: async ({ request }) => {
    const data = await request.formData();
    exec("tar czf /backups/" + data.get("name") + ".tgz /data");
  },
  safe: async (event) => {
    const data = await event.request.formData();
    await pool.query("select * from notes where text = $1", [data.get("text")]);
  },
};
'''


def test_what_the_caller_sends_is_followed_and_what_the_server_made_is_not(tmp_path):
    """The address's parts (`params`), its question (`url.searchParams`) and a form's fields arrive with the request;
    `locals` is the server's own, and a query with a placeholder is safe. The twin: the same file where nothing
    says SvelteKit is no route, and nothing in it is request data."""
    from lantern import flow
    files = {"svelte.config.js": CONFIG, "src/routes/notes/[id]/+page.server.ts": SENT}
    res = flow.analyze(_build(tmp_path, files))
    assert not res.errors, res.errors
    assert sorted((f["class"], f["line"]) for f in res.flows) == [("shell", 15), ("sql", 6), ("sql", 7)]
    plain = flow.analyze(_build(tmp_path / "plain", files, NO_KIT))
    assert plain.flows == []


def test_who_is_signed_in_comes_from_locals(tmp_path):
    """A record reached by an id the caller sent, with nothing that compares its owner: found on the action that
    removes a note (it asks that somebody is signed in, not whose the note is). The twins: the action that asks for
    the id and the owner, who is `locals.user` handed back by the project's own helper; the one that reaches the
    signed-in person's own record; and the endpoint that asks nobody at all, which is the login rule's finding."""
    from lantern.security import scan
    g = _build(tmp_path, APP)
    found = scan(g)["findings"]
    owner = [f for f in found if f["rule"] == "LT-AUTHZ-OWNER"]
    assert [(f["file"], f["line"], f["routes"]) for f in owner] == [
        ("src/routes/notes/+page.server.ts", 18, ["POST /notes?/remove"])]
    assert owner[0]["title"].startswith("POST /notes?/remove reaches a record by an id from the request")
    assert [f["file"] for f in found if f["rule"] == "LW-AUTH-MISSING" and "DELETE /api/notes/[id]" in f["title"]] == [
        "src/routes/api/notes/[id]/+server.ts"]


HELPERS = {
    "src/lib/server/guard.ts": '''import { error, type RequestEvent } from "@sveltejs/kit";

export function signedIn(event: RequestEvent) {
  if (!event.locals.user) throw error(401, "sign in");
  return event.locals.user;
}

export function fromEvent(event) {
  return event.locals.user;
}
''',
    "src/routes/notes/[id]/+server.ts": '''import { json } from "@sveltejs/kit";
import { db } from "$lib/server/db";
import { fromEvent, signedIn } from "$lib/server/guard";

export async function PATCH(event) {
  const user = signedIn(event);
  const body = await event.request.json();
  return json(await db.note.update({ where: { id: event.params.id, ownerId: user.id }, data: { text: body.text } }));
}

export async function PUT(event) {
  const user = fromEvent(event);
  return json(await db.note.update({ where: { id: event.params.id, ownerId: user.id }, data: { done: true } }));
}

export async function DELETE(event) {
  signedIn(event);
  return json(await db.note.delete({ where: { id: event.params.id } }));
}
'''}


def test_a_helper_handed_the_event_says_who_is_signed_in(tmp_path):
    """A helper of the project that is handed SvelteKit's event (by its written type, or under the name `event` in
    a file that runs on the server) hands back who is signed in: a record picked by an id and that person is their
    own. The twin: the route that calls the helper and then picks the record by the id alone."""
    from lantern.security import scan
    g = _build(tmp_path, {"svelte.config.js": CONFIG, "src/lib/server/db.ts": DB, **HELPERS})
    owner = [f for f in scan(g)["findings"] if f["rule"] == "LT-AUTHZ-OWNER"]
    assert [(f["file"], f["line"], f["routes"]) for f in owner] == [
        ("src/routes/notes/[id]/+server.ts", 18, ["DELETE /notes/[id]"])]


# ------------------------------------------------------------------ what only looks like one
LOOKS = '''<script>
  import Card from "$lib/Card.svelte";
  export let data;
  function wipe() {}
  function pick() {}
</script>
<p>To empty the list write onclick={wipe} on a button.</p>
<!-- <form method="POST" action="?/gone"><button onclick={wipe}>x</button></form> -->
<style>
  p { color: red; }
</style>
<p>{data.total +}</p>
<Form method="POST" action="?/save"></Form>
{#each data.notes as note}
  <Card {note} on:pick={pick} />
{/each}
<button onclick={wipe}>empty</button>
'''


def test_markup_that_only_looks_like_an_event_a_form_or_a_tag(tmp_path):
    """Read as written, and no further: `onclick={wipe}` in a sentence is text (only inside a tag is it a button's
    event), a form inside a comment is not there, a `<Form>` with a capital is somebody's component and not the
    page's form, the braces of a `<style>` are no code, and a value that does not stand as code is passed over
    without a word. The real ones beside them are read: the event a component sends, and the button."""
    g = _build(tmp_path, {"svelte.config.js": CONFIG, "src/lib/Card.svelte": CARD, "src/routes/+page.svelte": LOOKS})
    page = "js:src/routes/+page.svelte::+page"
    assert _edge(g, page, page + ".wipe").lines == [17]
    assert _edge(g, page, page + ".pick").lines == [15]
    assert _edge(g, page, "js:src/lib/Card.svelte::Card").lines == [15]
    assert g.meta["sveltekit"] == {"routes": 0, "pages": 1, "forms": 0, "linked": 0}


RUNES = '''<script lang="ts">
  import { page } from "$app/stores";
  let { data } = $props();
  let count = $state(0);
  let twice = $derived(count * 2);
  $effect(() => { document.title = String(twice); });
  const q = $page.url.searchParams.get("q");
</script>
<p>{count}</p>
'''
COUNTER = 'export function counter() {\n  let n = $state(0);\n  return { up: () => { n += 1; } };\n}\n'
NO_RUNE = 'export function make() {\n  return $state(0);\n}\n'


def test_sveltes_own_words_are_no_calls_nobody_could_follow(tmp_path):
    """`$state(0)`, `$props()`, `$derived(…)`, `$effect(…)` are the language's own in a `.svelte` file and in a
    `.svelte.ts` file: the inventory says built-in. `$page` is what the store `page` holds right now: a call on
    it is on a value Lantern does not know. The twin: in a plain `.ts` file `$state` is a name nobody defined."""
    g = _build(tmp_path, {"svelte.config.js": CONFIG, "src/routes/+page.svelte": RUNES,
                          "src/lib/counter.svelte.ts": COUNTER, "src/lib/plain.ts": NO_RUNE})
    said = {(s["file"], s["callee"]): (s["outcome"], s["via"] or s["reason"]) for s in g.sites}
    for rune in ("$props", "$state", "$derived", "$effect"):
        assert said[("src/routes/+page.svelte", rune)] == ("builtin", "svelte-rune"), rune
    assert said[("src/lib/counter.svelte.ts", "$state")] == ("builtin", "svelte-rune")
    assert said[("src/routes/+page.svelte", "$page.url.searchParams.get")] == ("unresolved", "local-unknown")
    assert said[("src/lib/plain.ts", "$state")] == ("unresolved", "not-defined")
    assert g.unresolved.get("$state") == 1 and "$props" not in g.unresolved


# ------------------------------------------------------------------ data a page loads in the browser too
FEED_LOAD = '''import type { PageLoad } from "./$types";
export const load: PageLoad = async ({ fetch }) => {
  const res = await fetch("/api/notes");
  return { notes: await res.json() };
};
'''
FEED_PAGE = '<script>\n  export let data;\n</script>\n<p>{data.notes.length}</p>\n'
FEED = {**APP, "src/routes/feed/+page.ts": FEED_LOAD, "src/routes/feed/+page.svelte": FEED_PAGE,
        "src/routes/+layout.ts": 'export const load = async () => ({ theme: "dark" });\n',
        "src/routes/+layout.svelte": "<nav>notes</nav>\n<slot />\n"}


def test_a_load_that_also_runs_in_the_browser_is_called_by_its_page(tmp_path):
    """`+page.ts` and `+layout.ts` hold a `load` that runs on the server for the first view and in the browser
    after it: no route (nobody can ask for it from outside), a function the page calls. So what it fetches is
    reached from the page. A page is drawn inside the `+layout.svelte` above it. The twin: without SvelteKit these
    are files like any other."""
    g = _build(tmp_path, FEED)
    page, load = "js:src/routes/feed/+page.svelte::+page", "js:src/routes/feed/+page::load"
    for dst in (load, "js:src/routes/+layout::load"):
        e = _edge(g, page, dst)
        assert e is not None and (e.confidence, e.via) == ("resolved", "sveltekit-load"), dst
        assert g.nodes[dst].entry is None and g.nodes[dst].lane == "frontend"
    e = _edge(g, load, "js:src/routes/api/notes/+server::GET")
    assert e is not None and (e.confidence, e.via) == ("resolved", "http-exact")
    e = _edge(g, page, "js:src/routes/+layout.svelte::+layout")
    assert e is not None and (e.confidence, e.via) == ("resolved", "sveltekit-layout")
    plain = _build(tmp_path / "plain", FEED, NO_KIT)
    assert _edge(plain, page, load) is None and _edge(plain, page, "js:src/routes/+layout.svelte::+layout") is None


# ------------------------------------------------------------------ a hook made of several
HOOKS_SEQ = '''import { sequence } from "@sveltejs/kit/hooks";
import type { Handle } from "@sveltejs/kit";
import { readUser } from "$lib/server/session";

const populate: Handle = async ({ event, resolve }) => {
  event.locals.user = await readUser(event.cookies.get("sid"));
  return resolve(event);
};
const authGuard: Handle = async ({ event, resolve }) => {
  if (event.url.pathname.startsWith("/admin") && !event.locals.user) return new Response(null, { status: 401 });
  return resolve(event);
};
export const handle = sequence(populate, authGuard);
'''
SWEEP = '''import { json } from "@sveltejs/kit";
import { db } from "$lib/server/db";
export const POST = async () => {
  await db.note.deleteMany();
  return json({});
};
'''
HOOKS_LOG = '''export const handle = async ({ event, resolve }) => {
  console.log(event.url.pathname);
  return resolve(event);
};
'''


def test_a_hook_made_of_several_parts(tmp_path):
    """`export const handle = sequence(populate, authGuard)`: each part runs before every route, in that order, so
    each is the app's front door (`ANY /*`) and stands in every route's list. Its name is no login check for the
    routes behind it, whatever it is called: a hook looks at every address and usually turns away only some, so
    the two open routes stay findings. For a route that changes data and that no page of the app calls, the
    readiness page says "check" (an app-wide check is there, confirm it covers this route). The twin: a hook that
    only writes a log line is no sign of a login anywhere ("add")."""
    from lantern import websec
    from lantern.readiness import assess
    from lantern.security import scan
    g = _build(tmp_path, {**APP, "src/hooks.server.ts": HOOKS_SEQ})
    parts = ["js:src/hooks.server::populate", "js:src/hooks.server::authGuard"]
    for nid in parts:
        assert g.nodes[nid].entry == {"kind": "route", "detail": "ANY /*", "sveltekit": "handle", "serves": "sveltekit"}
    assert g.nodes[NOTES + "actions.default"].entry["middleware"] == parts
    assert g.meta["sveltekit"]["routes"] == 10
    assert sorted(f["title"] for f in websec.missing_auth(g)) == [
        "DELETE /api/notes/[id] changes data, is called by the app, and no login check was found",
        "POST /notes changes data, is called by the app, and no login check was found"]
    alone = {"svelte.config.js": CONFIG, "src/lib/server/db.ts": DB, "src/routes/api/sweep/+server.ts": SWEEP}
    said = {}
    for name, hook in (("several", HOOKS_SEQ), ("log", HOOKS_LOG)):
        g = _build(tmp_path / name, {**alone, "src/hooks.server.ts": hook})
        prot = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}
        said[name] = (prot["route-auth"]["status"], [x.split(" (")[0] for x in prot["route-auth"]["evidence"]])
    assert said == {"several": ("check", ["POST /api/sweep"]), "log": ("add", ["POST /api/sweep"])}


def test_a_hook_that_turns_everyone_away_is_a_login_for_every_route(tmp_path):
    """Read from the hook's code, not from its name: a part that answers 401 to every request with nobody in
    `locals.user` stands before every route, so no route behind it is open, and what is left to say is that the
    two routes which pick a record by an id never compare its owner. The twin: the same part turning away only the
    addresses under `/admin` leaves the two open routes open."""
    from lantern.security import scan
    said = {}
    everyone = HOOKS_SEQ.replace('if (event.url.pathname.startsWith("/admin") && !event.locals.user)',
                                 "if (!event.locals.user)")
    assert everyone != HOOKS_SEQ
    for name, hook in (("everyone", everyone), ("some", HOOKS_SEQ)):
        g = _build(tmp_path / name, {**APP, "src/hooks.server.ts": hook})
        said[name] = sorted((f["rule"], f["title"].split(" ")[0] + " " + f["title"].split(" ")[1])
                            for f in scan(g)["findings"] if f["rule"] in ("LW-AUTH-MISSING", "LT-AUTHZ-OWNER"))
    assert said == {
        "everyone": [("LT-AUTHZ-OWNER", "DELETE /api/notes/[id]"), ("LT-AUTHZ-OWNER", "POST /notes?/remove")],
        "some": [("LT-AUTHZ-OWNER", "POST /notes?/remove"), ("LW-AUTH-MISSING", "DELETE /api/notes/[id]"),
                 ("LW-AUTH-MISSING", "POST /notes")]}


# ------------------------------------------------------------------ a route written another way
GUARD = '''import { error } from "@sveltejs/kit";
export function withAuth(fn) {
  return async (event) => {
    if (!event.locals.user) throw error(401, "sign in");
    return fn(event);
  };
}
export function logged(fn) {
  return async (event) => { console.log(event.url.pathname); return fn(event); };
}
'''
WRAPPED_API = '''import { json } from "@sveltejs/kit";
import { db } from "$lib/server/db";
import { withAuth, logged } from "$lib/server/guard";
export const POST = withAuth(async (event) => {
  return json(await db.note.create({ data: { text: "a" } }));
});
export const DELETE = logged(async (event) => {
  await db.note.deleteMany();
  return json({});
});
'''
WRAPPED_ACTIONS = '''import type { Actions } from "./$types";
import { db } from "$lib/server/db";
import { withAuth, logged } from "$lib/server/guard";
export const actions = {
  save: withAuth(async (event) => { await db.note.create({ data: {} }); }),
  wipe: logged(async (event) => { await db.note.deleteMany(); }),
  async clear({ locals }) { await db.note.deleteMany(); },
} satisfies Actions;
'''
WRAPPED_PAGE = '''<script>
  async function add() { await fetch("/api/n", { method: "POST" }); }
  async function del() { await fetch("/api/n", { method: "DELETE" }); }
</script>
<button onclick={add}>a</button><button onclick={del}>d</button>
<form method="POST" action="?/save"></form>
<form method="POST" action="?/wipe"></form>
<form method="POST" action="?/clear"></form>
'''


def test_a_route_inside_a_helper_and_an_action_written_as_a_method(tmp_path):
    """`save: withAuth(async (event) => …)` and `export const POST = withAuth(…)`: the function inside is the
    route, and the helper around it runs first, so its name is read as a middleware's is. `async clear({ locals })`
    written as a method is an action like the others, and `{…} satisfies Actions` is the same object. The twins: a
    helper that only writes a log line is no login check, and neither is being written as a method."""
    from lantern import websec
    g = _build(tmp_path, {"svelte.config.js": CONFIG, "src/lib/server/db.ts": DB, "src/lib/server/guard.ts": GUARD,
                          "src/routes/api/n/+server.ts": WRAPPED_API, "src/routes/+page.server.ts": WRAPPED_ACTIONS,
                          "src/routes/+page.svelte": WRAPPED_PAGE})
    acts = "js:src/routes/+page.server::actions."
    assert {k: v for k, v in _entries(g, "route").items() if k.startswith(acts)} == {
        acts + "save": "POST /?/save", acts + "wipe": "POST /?/wipe", acts + "clear": "POST /?/clear"}
    assert g.nodes[acts + "save"].entry["middleware"] == ["js:src/lib/server/guard::withAuth"]
    assert g.nodes[acts + "wipe"].entry["middleware"] == ["js:src/lib/server/guard::logged"]
    assert sorted(f["title"] for f in websec.missing_auth(g)) == [
        "DELETE /api/n changes data, is called by the app, and no login check was found",
        "POST /?/clear changes data, is called by the app, and no login check was found",
        "POST /?/wipe changes data, is called by the app, and no login check was found"]


# ------------------------------------------------------------------ where a form posts
INBOX_SERVER = '''import { db } from "$lib/server/db";
export const actions = {
  default: async ({ request }) => { await db.note.create({ data: {} }); },
  archive: async ({ request }) => { await db.note.updateMany({ data: { archived: true } }); },
};
'''
ONE_ACTION = 'export const actions = { archive: async () => ({}) };\n'
INBOX_PAGE = '''<form method="POST">
  <button>save</button>
  <button formaction="?/archive">archive</button>
</form>
<form method="POST" action="/inbox/new?/archive"></form>
<form method="POST" action="/api/notes"></form>
<form method="POST" action={target}></form>
<form action="/search"></form>
'''
ROW = '<script>\n  export let note;\n</script>\n<form method="POST" action="/inbox/{note.id}?/archive"><button>x</button></form>\n'
INBOX = {**APP, "src/routes/inbox/+page.server.ts": INBOX_SERVER, "src/routes/inbox/+page.svelte": INBOX_PAGE,
         "src/routes/inbox/new/+page.server.ts": ONE_ACTION, "src/routes/inbox/[id]/+page.server.ts": ONE_ACTION,
         "src/lib/Row.svelte": ROW}


def test_where_a_form_posts(tmp_path):
    """A button's `formaction` posts to the action it names. A form that writes another page's address posts to
    that page's action, and an address written out in full is the page with that very address, not the one with a
    part that changes beside it. An address with a part worked out as the page runs (`/inbox/{note.id}`) may be
    either: possible, to both. A form that posts to an address with no page action is a request like any other,
    matched to the `+server.ts` there. The twins: a form whose address is worked out as the page runs is counted
    and linked to nothing, and a form that only searches is not counted."""
    g = _build(tmp_path, INBOX)
    page, inbox = "js:src/routes/inbox/+page.svelte::+page", "js:src/routes/inbox/+page.server::actions."
    new, by_id = "js:src/routes/inbox/new/+page.server::actions.archive", "js:src/routes/inbox/[id]/+page.server::actions.archive"
    got = {e.dst: (e.confidence, e.lines, e.detail) for e in g.call_edges() if e.src == page and e.via == "http-sveltekit"}
    assert got == {inbox + "default": ("resolved", [1], "POST /inbox"),
                   inbox + "archive": ("resolved", [3], "POST /inbox?/archive"),
                   new: ("resolved", [5], "POST /inbox/new?/archive")}
    row = "js:src/lib/Row.svelte::Row"
    assert {e.dst: e.confidence for e in g.call_edges() if e.src == row and e.via == "http-sveltekit"} == {
        new: "possible", by_id: "possible"}
    e = _edge(g, page, "js:src/routes/api/notes/+server::POST")
    assert e is not None and (e.confidence, e.via, e.lines) == ("resolved", "http-exact", [6])
    assert g.meta["sveltekit"]["forms"] - _build(tmp_path / "base", APP).meta["sveltekit"]["forms"] == 6
    assert g.meta["sveltekit"]["linked"] - _build(tmp_path / "base2", APP).meta["sveltekit"]["linked"] == 4


# ------------------------------------------------------------------ the session the server keeps
SESSION_API = '''import { error, json } from "@sveltejs/kit";
import { db } from "$lib/server/db";
export async function POST(event) {
  if (!event.locals.session) throw error(401, "sign in");
  return json(await db.note.create({ data: { text: "a" } }));
}
export async function PUT(event) {
  if (!event.locals.requestId) throw error(400, "no id");
  return json(await db.note.updateMany({ data: { text: "b" } }));
}
export async function DELETE(event) {
  const { session } = await event.request.json();
  if (!session) throw error(401, "sign in");
  return json(await db.note.deleteMany());
}
'''


def test_the_session_the_server_keeps_says_who_is_asking(tmp_path):
    """`locals.session` is the session the server's own hook found for this request, as `req.session` is elsewhere:
    a route that turns away a request without one checks who is asking. The twins: another thing kept in `locals`
    (`locals.requestId`) says nothing of the caller, and a `session` the request itself sends is what the caller
    claims."""
    from lantern import websec
    g = _build(tmp_path, {"svelte.config.js": CONFIG, "src/lib/server/db.ts": DB,
                          "src/routes/api/s/+server.ts": SESSION_API})
    adj = websec.call_adjacency(g)
    strong = {}
    for verb in ("POST", "PUT", "DELETE"):
        n = g.nodes["js:src/routes/api/s/+server::" + verb]
        got = websec.login_check(g, n, adj, (tmp_path / n.file).read_text(encoding="utf-8"))
        strong[verb] = bool(got and got[0] == "strong")
    assert strong == {"POST": True, "PUT": False, "DELETE": False}


# ------------------------------------------------------------------ the words a reader gets
ASK_API = '''import OpenAI from "openai";
import { exec } from "child_process";
import { json } from "@sveltejs/kit";
const openai = new OpenAI();
export const POST = async ({ request }) => {
  const body = await request.json();
  exec("say " + body.q);
  const out = await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: body.q }] });
  return json({ text: out.choices[0].message.content });
};
'''
ASK_PAGE = '''<script>
  let answer = "";
  async function ask() {
    const r = await fetch("/api/ask", { method: "POST", body: JSON.stringify({ q: "hi" }) });
    answer = (await r.json()).text;
  }
</script>
<button on:click={ask}>Ask</button>
<p>{@html answer}</p>
'''
ASK = {"svelte.config.js": CONFIG, "src/routes/api/ask/+server.ts": ASK_API, "src/routes/ask/+page.svelte": ASK_PAGE}


def _scan(root, files, pkg=PKG):
    from lantern.security import scan
    return [f for f in scan(_build(root, files, pkg), offline=True)["findings"] if not f["in_tests"]]


def test_a_story_on_a_svelte_page_names_no_file(tmp_path):
    """A page file has no name of its own (`+page`), so the tester's story says "a button on it" after the page
    they opened, and the heading says where the button is. Never a piece of the file's name ("the svelte::+page
    button"). A line of the page's markup is on the page: the story of `{@html answer}` starts by opening it."""
    found = {f["rule"]: f for f in _scan(tmp_path, ASK, PKG.replace('"@prisma/client": "5.14.0"', '"openai": "4.0.0"'))}
    open_route = found["LW-AUTH-MISSING"]
    assert open_route["scenario"]["steps"][:2] == [
        open_route["scenario"]["steps"][0], "They click a button on it."]
    assert "opens the /ask page" in open_route["scenario"]["steps"][0]
    for f in found.values():
        said = json.dumps([f.get("headline"), f.get("scenario"), f.get("title")])
        assert "svelte" not in said and "+page" not in said, said
    assert found["LJ-EXEC"]["headline"] == "A button on the /ask page can run shell commands on your server"
    raw = found["LJ-XSS-HTML"]
    assert (raw["file"], raw["line"]) == ("src/routes/ask/+page.svelte", 9)
    assert raw["reachable"]["entry"] == "js:src/routes/ask/+page.svelte::+page"
    assert "opens the /ask page" in raw["scenario"]["steps"][0]


ASKED = '''import { error, json } from "@sveltejs/kit";
import { Pool } from "pg";
const pool = new Pool();
export async function GET({ url, locals }) {
  if (!locals.user) throw error(401, "sign in");
  const id = url.searchParams.get("id");
  return json(await pool.query("select * from notes where id = '" + id + "'"));
}
export async function DELETE(event) {
  if (!event.locals.user) throw error(401, "sign in");
  const noteId = event.url.searchParams.get("noteId");
  await pool.query("delete from notes where id = $1", [noteId]);
  return json({});
}
export async function PUT({ request, locals }) {
  if (!locals.user) throw error(401, "sign in");
  const { searchParams } = new URL(request.url);
  await pool.query("update notes set seen = true where id = $1", [searchParams.get("noteId")]);
  return json({});
}
export async function POST({ url, locals }) {
  if (!locals.user) throw error(401, "sign in");
  return json(await pool.query("select * from notes where text = $1", [url.searchParams.get("q")]));
}
'''


def test_a_word_of_the_addresss_question_is_called_by_its_name(tmp_path):
    """`url.searchParams.get("id")` is `id`, as `req.query.id` is on Express: the finding says which word of the
    link a tester writes, and a record picked by it is a record picked by an id from the request (three ways to
    write it). The twin: a search word (`q`) picks no record."""
    found = _scan(tmp_path, {"svelte.config.js": CONFIG, "src/routes/api/n/+server.ts": ASKED},
                  PKG.replace('"@prisma/client": "5.14.0"', '"pg": "8.11.5"'))
    sql = next(f for f in found if f["rule"] == "LT-SQL")
    assert sql["input"]["via"] == "`id` in `url.searchParams` is what the request sent"
    assert sql["scenario"]["steps"][1].startswith("In the link they send they type: ")
    assert sorted((f["line"], f["title"].split(" reaches")[0]) for f in found if f["rule"] == "LT-AUTHZ-OWNER") == [
        (7, "GET /api/n"), (12, "DELETE /api/n"), (18, "PUT /api/n")]


TEXT_FORM = '''export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    return { name: String(data.get("name")) };
  },
};
'''
FILE_FORM = '''import { writeFile } from "fs/promises";
export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    const photo = data.get("photo") as File;
    await writeFile("/data/photo", Buffer.from(await photo.arrayBuffer()));
  },
};
'''


def test_a_form_with_text_fields_is_no_file_upload(tmp_path):
    """Every SvelteKit form action reads `request.formData()`: that is how a form's fields arrive, and says nothing
    of files. The readiness page speaks of uploads only where the code takes a file out of the form (a `File`, its
    `arrayBuffer()`). The twin: the same action taking a photo is an upload with no size or type check."""
    from lantern.readiness import assess
    from lantern.security import scan
    said = {}
    for name, action in (("text", TEXT_FORM), ("file", FILE_FORM)):
        g = _build(tmp_path / name, {"svelte.config.js": CONFIG, "src/routes/+page.server.ts": action})
        prot = {p["id"]: p for p in assess(g, scan(g, offline=True), {})["protections"]}
        said[name] = (prot.get("upload-checks") or {}).get("status")
    assert said == {"text": None, "file": "add"}


# ------------------------------------------------------------------ a group's shared load
def test_a_groups_shared_load_is_said_to_run_for_that_group(tmp_path):
    """`(app)/+layout.server.ts` runs for the pages inside the `(app)` folder, not for every address: what it is
    listed as keeps the group's name, which no address has. The twins: the layout at the top does run for every
    address, and a page inside the group keeps its address without the group."""
    g = _build(tmp_path, {**APP, "src/routes/+layout.server.ts": LAYOUT_SERVER,
                          "src/routes/(app)/admin/+layout.server.ts": LAYOUT_SERVER})
    assert {i: d for i, d in _entries(g, "route").items() if "+layout" in i} == {
        "js:src/routes/+layout.server::load": "GET /*",
        "js:src/routes/(app)/+layout.server::load": "GET /(app)/*",
        "js:src/routes/(app)/admin/+layout.server::load": "GET /(app)/admin/*"}
    assert _entries(g, "page")["js:src/routes/(app)/settings/+page.svelte::+page"] == "/settings"
    assert _entries(g, "route")["js:src/routes/(app)/settings/+page.server::save"] == "POST /settings?/save"


# ------------------------------------------------------------------ "I am an admin", written in the address
PEOPLE = '''import { error, json } from "@sveltejs/kit";
import { Pool } from "pg";
const pool = new Pool();
export async function GET({ url, locals }) {
  if (!locals.user) throw error(401, "sign in");
  CHECK
  return json(await pool.query("select * from people"));
}
'''
SAYS_SO = {
    "a word of the address compared": ('if (url.searchParams.get("admin") !== "1") throw error(403, "admins only");', 6),
    "a word of the address asked for": ('const isAdmin = url.searchParams.get("isAdmin");\n  if (!isAdmin) throw error(403, "no");', 6),
}
SAYS_NOTHING = {
    "the role the server keeps": 'if (locals.user.role !== "admin") throw error(403, "admins only");',
    "a word of the address nobody is turned away on":
        'const admin = url.searchParams.get("admin");\n  if (admin) console.log("asked for admins");',
}


def test_the_callers_own_word_in_the_address_is_no_proof(tmp_path):
    """`?admin=1` is written by whoever sends the request. A route that turns everyone else away on it lets anyone
    in: read with `url.searchParams.get("admin")` it is the same claim as `req.query.admin` on Express. The twins:
    the role the server itself keeps for the signed-in user, and the same word of the address where nobody is
    turned away on it."""
    pkg = PKG.replace('"@prisma/client": "5.14.0"', '"pg": "8.11.5"')
    for name, (check, line) in SAYS_SO.items():
        found = _scan(tmp_path / name.replace(" ", "-"),
                      {"svelte.config.js": CONFIG, "src/routes/api/people/+server.ts": PEOPLE.replace("CHECK", check)}, pkg)
        got = [(f["line"], f["title"]) for f in found if f["rule"] == "LT-AUTHZ-CLIENT-ROLE"]
        assert [x[0] for x in got] == [line], (name, got)
        assert got[0][1].startswith("GET /api/people decides what the caller may do from the address the caller sends"), got
    for name, check in SAYS_NOTHING.items():
        found = _scan(tmp_path / name.replace(" ", "-"),
                      {"svelte.config.js": CONFIG, "src/routes/api/people/+server.ts": PEOPLE.replace("CHECK", check)}, pkg)
        assert [f["rule"] for f in found if f["rule"].startswith("LT-AUTHZ")] == [], (name, found)


# ------------------------------------------------------------------ in the report page
def test_the_report_says_who_opens_a_page_and_which_page_calls(tmp_path):
    """The report page's own functions, run by Node on their text. "It runs when the page /notes." said nothing
    happened: a page runs when someone opens it (true of every page, not only SvelteKit's). And every SvelteKit
    page's component is called `+page`, so "It runs when +page call it" named nobody: a page whose only name is
    its file's is called by its address, and the verb goes with the names that are shown. The twins: a route, a
    phone screen, a page with a name of its own and a function inside a page read as they did."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    html = (Path(report.__file__).parent / "viewer" / "report.html").read_text(encoding="utf-8")
    parts = [re.search(pattern, html, re.S | re.M) for pattern in (
        r"^const short = q => \{.*?^\};\n", r"^const isScreen = [^\n]*\n", r"^const isIntent = [^\n]*\n",
        r"^const partName = [^\n]*\n", r"^const isAction = [^\n]*\n", r"^const actionName = [^\n]*\n",
        r"^const entryPhrase = [^\n]*\n[^\n]*\n", r"^const sayName = [^\n]*\n", r"^const calledBy = [^\n]*\n")]
    assert all(parts), "the page has no sayName or calledBy"
    nodes = {"home": {"qualname": "src/routes/+page.svelte::+page", "entry": {"kind": "page", "detail": "/"}},
             "feed": {"qualname": "src/routes/feed/+page.svelte::+page", "entry": {"kind": "page", "detail": "/feed"}},
             "app": {"qualname": "web/src/App::App", "entry": {"kind": "page", "detail": "/"}},
             "card": {"qualname": "src/lib/Card.svelte::Card"}, "card2": {"qualname": "src/lib/old/Card.svelte::Card"},
             "wipe": {"qualname": "src/routes/+page.svelte::+page.wipe"},
             "frame": {"qualname": "src/routes/+layout.svelte::+layout"}}
    asked = [{"kind": "page", "detail": "/notes/[id]"}, {"kind": "route", "detail": "POST /notes?/save"},
             {"kind": "page", "detail": "Home screen (Compose) · HomeScreen"}, {"kind": "route", "detail": "ACTION saveNote"}]
    calls = [["home", "feed"], ["home"], ["app"], ["card", "card2"], ["wipe", "frame", "card", "app"]]
    (tmp_path / "run.js").write_text(
        f"const N = {json.dumps(nodes)};\n" + "".join(p.group(0) for p in parts)
        + f"console.log(JSON.stringify([{json.dumps(asked)}.map(entryPhrase), {json.dumps(calls)}.map(calledBy)]));\n",
        encoding="utf-8")
    r = subprocess.run([node, str(tmp_path / "run.js")], capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    phrases, said = json.loads(r.stdout)
    assert phrases == ["someone opens the page /notes/[id]", "a request arrives at POST /notes?/save",
                       "someone opens the Home screen (Compose) on their phone",
                       "someone sends a form, or presses a button, that runs the Server Action saveNote"]
    assert said == ["It runs when the page / and the page /feed call it.", "It runs when the page / calls it.",
                    "It runs when App calls it.", "It runs when Card calls it.",
                    "It runs when +page.wipe, +layout and Card call it."]
    assert "${andList(names(callers).slice(0, 3))} call${callers.length === 1 ? 's' : ''} it." not in html


# ------------------------------------------------------------------ a hook that names the addresses it guards
AREA_HOOK = '''import { error, redirect } from "@sveltejs/kit";
import { readUser } from "$lib/server/session";

export const handle = async ({ event, resolve }) => {
  event.locals.user = await readUser(event.cookies.get("session"));
  CHECK
  return resolve(event);
};
'''
READ_USER = 'export async function readUser(token) {\n  return token ? { id: 1 } : null;\n}\n'
AREA_ACTION = '''import { db } from "$lib/server/db";
export const actions = { default: async () => { await db.note.deleteMany(); } };
'''
AREA_PAGE = '''<script>
  async function wipe() { await fetch("/api/notes/7", { method: "DELETE" }); }
</script>
<form method="POST"><button>Empty</button></form>
<button on:click={wipe}>x</button>
'''
AREA_API = '''import { json } from "@sveltejs/kit";
import { db } from "$lib/server/db";
export async function DELETE({ params }) {
  await db.note.delete({ where: { id: params.id } });
  return json({});
}
'''
AREA = {"svelte.config.js": CONFIG, "src/lib/server/db.ts": DB, "src/lib/server/session.ts": READ_USER,
        "src/routes/app/notes/+page.server.ts": AREA_ACTION, "src/routes/app/notes/+page.svelte": AREA_PAGE,
        "src/routes/api/notes/[id]/+server.ts": AREA_API}
BOTH, APP_ONLY = ["DELETE /api/notes/[id]", "POST /app/notes"], ["POST /app/notes"]
AREA_CASES = {
    # every address but the sign-in page: a login for every route
    "all but one page": ('if (event.url.pathname !== "/login" && !event.locals.user) redirect(303, "/login");', BOTH),
    "all but a list of pages": ('const open = ["/login", "/signup"];\n  if (!open.includes(event.url.pathname) && '
                                '!event.locals.user) redirect(303, "/login");', BOTH),
    # the addresses under /app: a login for the routes there, and for no other
    "one area, in the condition": ('if (event.url.pathname.startsWith("/app") && !event.locals.user) '
                                   'redirect(303, "/login");', APP_ONLY),
    "one area, in a branch of its own": ('if (event.url.pathname.startsWith("/app")) {\n    if (!event.locals.user) '
                                         'redirect(303, "/login");\n  }', APP_ONLY),
    "one area, the others sent on first": ('if (!event.url.pathname.startsWith("/app")) return resolve(event);\n'
                                           '  if (!event.locals.user) error(401, "sign in");', APP_ONLY),
    "two areas": ('if ((event.url.pathname.startsWith("/app") || event.url.pathname.startsWith("/api")) && '
                  '!event.locals.user) error(401, "sign in");', BOTH),
    "one page by its whole address": ('if (event.url.pathname === "/app/notes" && !event.locals.user) '
                                      'error(401, "sign in");', APP_ONLY),
    # the twins: nobody is turned away, another area, and a word that is not the address
    "an area where nobody is turned away": ('if (event.url.pathname.startsWith("/app") && event.locals.user) '
                                            'console.log("hello");', []),
    "another area": ('if (event.url.pathname.startsWith("/admin") && !event.locals.user) redirect(303, "/login");',
                     []),
    "a header that names an area": ('if (event.request.headers.get("x-area") === "/app" && !event.locals.user) '
                                    'error(401, "sign in");', []),
    "an area asked, and the check made of some": ('if (event.url.pathname.startsWith("/app")) {\n    if (event.request.'
                                                  'method === "POST" || Math.random() > 0.5) return resolve(event);\n'
                                                  '    if (!event.locals.user) error(401, "sign in");\n  }', []),
}


@pytest.mark.parametrize("case", sorted(AREA_CASES))
def test_a_hook_that_names_the_addresses_it_guards(tmp_path, case):
    """The usual SvelteKit guard stands in the hook and names addresses. One that turns away whoever is not signed
    in on every address but a few named ones (the sign-in page) is a login for every route, as the same check is in
    Express or Flask. One that guards the addresses under `/app` is a login for the routes whose own address is
    there, and for no other: read with the route's address, in the condition itself, in a branch of its own, or
    after the other addresses were sent on. Each route with no login shown, and only it, is reported as open."""
    from lantern.security import scan
    check, shown = AREA_CASES[case]
    g = _build(tmp_path, {**AREA, "src/hooks.server.ts": AREA_HOOK.replace("CHECK", check)})
    sec = scan(g, offline=True)
    routes = {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry.get("sveltekit") in (
        "action", "endpoint")}
    assert sorted(routes[i] for i in sec["logins_shown"] if i in routes) == shown
    open_ones = sorted(f["title"].split(" changes data")[0] for f in sec["findings"] if f["rule"] == "LW-AUTH-MISSING")
    assert open_ones == sorted(set(routes.values()) - set(shown))


# ------------------------------------------------------------------ the hook as the sign-in guides write it
GUIDE_HOOK = '''import { error, redirect } from "@sveltejs/kit";
import { readUser } from "$lib/server/session";

TOP
export const handle = async ({ event, resolve }) => {
  event.locals.user = await readUser(event.cookies.get("session"));
  CHECK
  return resolve(event);
};
'''
GUIDE_SEQUENCE = '''import { redirect } from "@sveltejs/kit";
import { sequence } from "@sveltejs/kit/hooks";
import { readUser } from "$lib/server/session";

const auth = async ({ event, resolve }) => {
  event.locals.user = await readUser(event.cookies.get("session"));
  return resolve(event);
};
const guard = async ({ event, resolve }) => {
  if (event.url.pathname.startsWith("/app") && !event.locals.user) redirect(303, "/login");
  return resolve(event);
};
export const handle = sequence(auth, guard);
'''
GUIDE_ANSWER_KEPT = '''import { redirect } from "@sveltejs/kit";
import { readUser } from "$lib/server/session";

export const handle = async ({ event, resolve }) => {
  event.locals.user = await readUser(event.cookies.get("session"));
  if (event.url.pathname.startsWith("/api")) {
    const response = await resolve(event);
    response.headers.set("x-api", "1");
    return response;
  }
  if (!event.locals.user) redirect(303, "/login");
  return resolve(event);
};
'''
API_ONLY = ["DELETE /api/notes/[id]"]
NOT_SIGNED_IN = '!event.locals.user) redirect(303, "/login");'
GUIDE_CASES = {
    # who is signed in, as the hook itself learns it: the libraries' own functions kept on `locals`
    "Auth.js: what locals.auth() hands back": (
        "", 'const session = await event.locals.auth();\n  if (!session) redirect(303, "/login");', BOTH),
    "Auth.js: the user in it": (
        "", 'const session = await event.locals.auth();\n  if (!session?.user) redirect(303, "/login");', BOTH),
    "Supabase: the session kept on locals": (
        "", 'const { session, user } = await event.locals.safeGetSession();\n  event.locals.session = session;\n'
            '  event.locals.user = user;\n  if (!event.locals.session) redirect(303, "/auth");', BOTH),
    "a cookie that is only there": ("", 'if (!event.cookies.get("session")) redirect(303, "/login");', []),
    # the two guides' own guards, each for one area
    "Supabase's guide": (
        "", 'const { session, user } = await event.locals.safeGetSession();\n  event.locals.session = session;\n'
            '  event.locals.user = user;\n  if (!event.locals.session && event.url.pathname.startsWith("/app")) {\n'
            '    redirect(303, "/auth");\n  }\n  if (event.locals.session && event.url.pathname === "/auth") {\n'
            '    redirect(303, "/app");\n  }', APP_ONLY),
    "Auth.js's guide": (
        "", 'if (event.url.pathname.startsWith("/app")) {\n    const session = await event.locals.auth();\n'
            '    if (!session) {\n      throw redirect(303, "/auth/signin");\n    }\n  }', APP_ONLY),
    # the address under a name, the route's id, a list at the file's top, a helper, the verb
    "the path kept under a name": (
        "", 'const { pathname } = event.url;\n  if (pathname.startsWith("/app") && ' + NOT_SIGNED_IN, APP_ONLY),
    "the path kept under another name": (
        "", 'const path = event.url.pathname;\n  if (path !== "/login" && ' + NOT_SIGNED_IN, BOTH),
    "the event taken apart": (
        "", 'const { url, locals } = event;\n  if (url.pathname.startsWith("/api") && !locals.user) error(401, "no");',
        API_ONLY),
    "a list of open pages at the file's top": (
        'const OPEN = ["/login", "/signup"];', 'if (!OPEN.includes(event.url.pathname) && ' + NOT_SIGNED_IN, BOTH),
    "the route's id": ("", 'if (event.route.id?.startsWith("/app") && ' + NOT_SIGNED_IN, APP_ONLY),
    "an open area first, the rest guarded": (
        "", 'if (event.url.pathname.startsWith("/public")) {\n    return resolve(event);\n  } else if ('
            '!event.locals.user) {\n    redirect(303, "/login");\n  }', BOTH),
    "a helper asked for one area": (
        'async function requireUser(event) {\n  if (!event.locals.user) redirect(303, "/login");\n}',
        'if (event.url.pathname.startsWith("/app")) await requireUser(event);', APP_ONLY),
    "an open corner inside the area": (
        "", 'if (event.url.pathname.startsWith("/app/public")) return resolve(event);\n'
            '  if (event.url.pathname.startsWith("/app") && ' + NOT_SIGNED_IN, APP_ONLY),
    "an area written with its slash": ("", 'if (event.url.pathname.startsWith("/app/") && ' + NOT_SIGNED_IN, APP_ONLY),
    "every address but one with a part that changes": (
        "", 'if (event.url.pathname !== "/api/notes/7" && ' + NOT_SIGNED_IN, APP_ONLY),
    "every verb but GET": ("", 'if (event.request.method !== "GET" && !event.locals.user) error(401, "no");', BOTH),
    "an area, or nobody signed in": ("", 'if (event.url.pathname.startsWith("/app") || ' + NOT_SIGNED_IN, BOTH),
    # the twins: the same words where the guard does not reach the route
    "the open area is where a route is": (
        "", 'if (event.url.pathname.startsWith("/app")) {\n    return resolve(event);\n  } else if ('
            '!event.locals.user) {\n    redirect(303, "/login");\n  }', API_ONLY),
    "the open corner is the route": (
        "", 'if (event.url.pathname.startsWith("/app/notes")) return resolve(event);\n'
            '  if (event.url.pathname.startsWith("/app") && ' + NOT_SIGNED_IN, []),
    "another route's id": ("", 'if (event.route.id?.startsWith("/(app)") && ' + NOT_SIGNED_IN, []),
    "an area longer than the route": ("", 'if (event.url.pathname.startsWith("/app/notes/") && ' + NOT_SIGNED_IN, []),
    "an area that names a part that changes": (
        "", 'if (event.url.pathname.startsWith("/api/notes/7") && ' + NOT_SIGNED_IN, []),
    "only GET": ("", 'if (event.request.method === "GET" && !event.locals.user) error(401, "no");', []),
    "the name set again": (
        "", 'let path = event.url.pathname;\n  path = path.slice(4);\n  if (path.startsWith("/app") && ' + NOT_SIGNED_IN,
        []),
    "contains, not begins": ("", 'if (event.url.pathname.includes("/app") && ' + NOT_SIGNED_IN, []),
    "ends with": ("", 'if (event.url.pathname.endsWith("/notes") && ' + NOT_SIGNED_IN, []),
    "the address's question, not its path": ("", 'if (event.url.search.startsWith("/app") && ' + NOT_SIGNED_IN, []),
    "another address's path": (
        "", 'const other = new URL(event.request.headers.get("referer"));\n'
            '  if (other.pathname.startsWith("/app") && ' + NOT_SIGNED_IN, []),
    # not read, and so reported as open (the safe side): the path changed first, a pattern, a list of areas
    "the path changed before it is asked": (
        "", 'const path = event.url.pathname.toLowerCase();\n  if (path.startsWith("/app") && ' + NOT_SIGNED_IN, []),
    "a pattern": ("", 'if (/^\\/app/.test(event.url.pathname) && ' + NOT_SIGNED_IN, []),
    "a list of areas": (
        'const AREAS = ["/app", "/api"];',
        'if (AREAS.some((p) => event.url.pathname.startsWith(p)) && ' + NOT_SIGNED_IN, []),
    # whole hooks: the guard as one part of `sequence(...)`; an area handed on with its answer kept under a name
    "the guard as a part of sequence()": (None, GUIDE_SEQUENCE, APP_ONLY),
    "an area handed on with its answer kept": (None, GUIDE_ANSWER_KEPT, APP_ONLY),
}


@pytest.mark.parametrize("case", sorted(GUIDE_CASES))
def test_a_hook_as_the_sign_in_guides_write_it(tmp_path, case):
    """The hook learns who is signed in from what the app keeps on `locals`: `locals.user`, `locals.session`, and
    what `await locals.auth()` (Auth.js) or `locals.safeGetSession()` (Supabase) hands back, under any name; a
    cookie that is merely there says nothing. The addresses it guards are read where the code names the request's
    whole address: `event.url.pathname` or `event.route.id`, also kept under a name as it is, against fixed text
    (`startsWith`, `===`, a list's `includes`). A request that is handed on (`return resolve(event)`, also with the
    answer kept under a name first) was not asked what comes after. A route takes the login only when its own
    address is certainly among those asked: a part that changes (`[id]`) counts for neither side. The path changed
    before it is asked, a pattern, a list of areas: not read, so those routes are reported as open."""
    from lantern.security import scan
    top, check, shown = GUIDE_CASES[case]
    hook = check if top is None else GUIDE_HOOK.replace("TOP", top).replace("CHECK", check)
    g = _build(tmp_path, {**AREA, "src/hooks.server.ts": hook})
    sec = scan(g, offline=True)
    routes = {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry.get("sveltekit") in (
        "action", "endpoint")}
    assert sorted(routes[i] for i in sec["logins_shown"] if i in routes) == shown
    open_ones = sorted(f["title"].split(" changes data")[0] for f in sec["findings"] if f["rule"] == "LW-AUTH-MISSING")
    assert open_ones == sorted(set(routes.values()) - set(shown))
