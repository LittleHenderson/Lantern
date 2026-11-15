"""SvelteKit routes (roadmap of 2026-11-14, stage 1).

A SvelteKit app's doors are files with fixed names under `src/routes`: `+server.ts` (one function per verb),
`+page.server.ts` (`load`, which hands the page its data, and `actions`, which a form posts to) and
`+layout.server.ts`; `src/hooks.server.ts` runs before every one of them. Until now none of them was an entry point,
`$lib/…` was read as a library, and a `.svelte` file was not read at all.

Each shape sits beside twins that must stay as they were."""

import json

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
    brackets is no part of the address."""
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
        "js:src/routes/(app)/+layout.server::load": "GET /*",
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
    assert _edge(g, NOTES + "actions.remove", "ext:@prisma/client.PrismaClient().note.delete") is not None
    assert g.nodes["js:src/lib/server/auth::requireUser"].lane == "server"
    plain = {k: v for k, v in APP.items() if k != "svelte.config.js"}
    g = _build(tmp_path / "plain", plain, NO_KIT)
    assert _edge(g, NOTES + "actions.rename", "js:src/lib/server/auth::requireUser") is None


# ------------------------------------------------------------------ who may call a route
def test_the_login_check_reads_what_the_server_knows_of_the_caller(tmp_path):
    """Asked: the routes the pages send to that change data. `locals` is what the server's own hook put there:
    a route that turns away a request with no `locals.user` checks who is asking, by its own lines, by a helper of
    the project, or by `locals.auth()`. The form's default action and the endpoint that removes a note ask nobody."""
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
                      "save": False}


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
    """A record reached by an id the caller sent, with nothing that compares its owner: found (the action that
    removes a note, and the endpoint). The twin asks for the id and the owner, who is `locals.user` handed back by
    the project's own helper."""
    from lantern.security import scan
    g = _build(tmp_path, APP)
    owner = sorted((f["file"], f["line"]) for f in scan(g)["findings"] if f["rule"] == "LT-AUTHZ-OWNER")
    assert owner == [("src/routes/api/notes/[id]/+server.ts", 5), ("src/routes/notes/+page.server.ts", 18)]
