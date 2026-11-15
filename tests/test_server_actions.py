"""Next.js Server Actions on the map (roadmap stage 1). A function a `"use server"` file exports, and a function
whose own body begins with `"use server"`, is run by the server for a request any visitor can send: the framework
gives it an address of its own, and a form or a client component calls it. So it is a `route` entry (`ACTION
<name>`), like a route written in a route file. Every shape stands beside look-alikes that must stay as they were."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from lantern import clientside, report
from lantern.engine import build_graph
from lantern.security import scan

NEXT = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0"}})
PLAIN = json.dumps({"dependencies": {"express": "4.19.0"}})
SPA = json.dumps({"dependencies": {"react": "18.3.0", "react-dom": "18.3.0"}, "devDependencies": {"vite": "5.4.0"}})
OTHER = json.dumps({"dependencies": {"react": "19.0.0", "react-server-dom-webpack": "19.0.0"}})

ACTIONS = '''"use server";
import { insert, remove } from "../lib/db";

export async function createTodo(formData: FormData) {
  await insert({ title: formData.get("title") });
}

export const removeTodo = async (id: string) => {
  await remove(id);
};

async function log(what: string) {   // not exported: the server's own helper
  console.log(what);
}

export const LIMIT = 20;              // no function
export type Todo = { id: string };
'''
DB = '''export async function insert(row: unknown) { return row; }
export async function remove(id: string) { return id; }
'''
FORM_PAGE = '''import { createTodo } from "./actions";

export default function Page() {
  return (
    <form action={createTodo}>
      <input name="title" />
      <button type="submit">Add</button>
    </form>
  );
}
'''
ROW = '''"use client";
import { removeTodo } from "../app/actions";

export function Row({ id }: { id: string }) {
  return <button onClick={() => removeTodo(id)}>Remove</button>;
}
'''
INLINE_PAGE = '''import { insert } from "../../lib/db";

export default function Page() {
  async function save(formData: FormData) {
    "use server";
    await insert({ title: formData.get("title") });
  }
  const rename = async (formData: FormData) => {
    "use server";
    await insert({ title: formData.get("name") });
  };
  async function plain(formData: FormData) {
    const said = "use server";      // a text further down is a text
    return said;
  }
  return (
    <form action={save}>
      <button formAction={rename}>Rename</button>
      <button onClick={plain}>Other</button>
    </form>
  );
}
'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _build(root, files, pkg=NEXT):
    return build_graph(_write(root, {"package.json": pkg, **files}))


def _routes(g):
    return {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry["kind"] == "route"}


def _edge(g, src, dst):
    for e in g.call_edges():
        if e.src == src and e.dst == dst:
            return e
    return None


def test_every_function_a_use_server_file_exports_is_a_route(tmp_path):
    g = _build(tmp_path, {"app/actions.ts": ACTIONS, "lib/db.ts": DB, "app/page.tsx": FORM_PAGE})
    assert _routes(g) == {"js:app/actions::createTodo": "ACTION createTodo",
                          "js:app/actions::removeTodo": "ACTION removeTodo"}
    for name in ("createTodo", "removeTodo"):
        assert g.nodes[f"js:app/actions::{name}"].lane == "server"
    assert g.nodes["js:app/actions::log"].entry is None


def test_a_function_whose_body_begins_with_use_server_is_a_route(tmp_path):
    g = _build(tmp_path, {"app/new/page.tsx": INLINE_PAGE, "lib/db.ts": DB})
    assert _routes(g) == {"js:app/new/page::Page.save": "ACTION save", "js:app/new/page::Page.rename": "ACTION rename"}
    assert g.nodes["js:app/new/page::Page.plain"].entry is None
    assert g.nodes["js:app/new/page::Page"].entry == {"kind": "page", "detail": "/new"}


def test_an_action_written_inside_a_page_leaves_the_page_where_it_was(tmp_path):
    """The action is the server's; the page around it, and the page's other functions, keep their place in the
    picture (a route written in a file makes the whole file the server's, which a page is not)."""
    g = _build(tmp_path, {"app/new/page.tsx": INLINE_PAGE, "lib/db.ts": DB})
    assert g.nodes["js:app/new/page::Page.save"].lane == "server"
    assert g.nodes["js:app/new/page::Page.rename"].lane == "server"
    assert g.nodes["js:app/new/page::Page"].lane == "browser"
    assert g.nodes["js:app/new/page::Page.plain"].lane == "frontend"
    without = _build(tmp_path / "twin", {"app/new/page.tsx": INLINE_PAGE.replace('    "use server";\n', ""),
                                         "lib/db.ts": DB})
    assert without.nodes["js:app/new/page::Page"].lane == "browser"
    assert without.nodes["js:app/new/page::Page.save"].lane == "frontend"


def test_the_twins_a_file_that_is_no_use_server_file(tmp_path):
    """The same functions with no directive, in a client file, with the words further down, and in a project with
    no framework that runs Server Actions (there the words do nothing): no route is made of them."""
    body = ACTIONS.split("\n", 1)[1]
    for name, text, pkg in (("none", body, NEXT), ("client", '"use client";\n' + body, NEXT),
                            ("later", 'import x from "./x";\n"use server";\n' + body, NEXT),
                            ("comment", '// "use server";\n' + body, NEXT),
                            ("no-react", ACTIONS, PLAIN), ("spa", ACTIONS, SPA)):
        g = _build(tmp_path / name, {"app/actions.ts": text, "lib/db.ts": DB, "app/x.ts": "export default 1;\n"}, pkg)
        assert _routes(g) == {}, name


def test_another_framework_that_runs_server_actions_counts_too(tmp_path):
    g = _build(tmp_path, {"src/actions.ts": ACTIONS, "lib/db.ts": DB}, OTHER)
    assert _routes(g) == {"js:src/actions::createTodo": "ACTION createTodo",
                          "js:src/actions::removeTodo": "ACTION removeTodo"}


def test_a_form_and_a_client_component_are_linked_to_the_action_they_run(tmp_path):
    g = _build(tmp_path, {"app/actions.ts": ACTIONS, "lib/db.ts": DB, "app/page.tsx": FORM_PAGE,
                          "components/Row.tsx": ROW, "app/new/page.tsx": INLINE_PAGE})
    e = _edge(g, "js:app/page::Page", "js:app/actions::createTodo")       # <form action={createTodo}>
    assert e is not None and e.detail == "action"
    e = _edge(g, "js:components/Row::Row", "js:app/actions::removeTodo")  # called in a click handler
    assert e is not None and e.confidence == "resolved"
    e = _edge(g, "js:app/new/page::Page", "js:app/new/page::Page.rename")  # <button formAction={rename}>
    assert e is not None and e.detail == "formAction"
    e = _edge(g, "js:app/new/page::Page", "js:app/new/page::Page.save")
    assert e is not None and e.detail == "action"
    # what the action itself calls is on the map as before
    assert _edge(g, "js:app/actions::createTodo", "js:lib/db::insert") is not None


def test_the_visitors_side_stops_at_an_action(tmp_path):
    """A client component that calls an action reaches it over the network: the action and what it calls are not
    code that runs in the browser."""
    g = _build(tmp_path, {"app/actions.ts": ACTIONS, "lib/db.ts": DB, "components/Row.tsx": ROW,
                          "app/new/page.tsx": INLINE_PAGE})
    side = clientside.where(g)
    assert "js:components/Row::Row" in side
    for nid in ("js:app/actions::removeTodo", "js:app/actions::createTodo", "js:lib/db::remove",
                "js:app/new/page::Page.save", "js:app/new/page::Page.rename"):
        assert nid not in side, nid


def test_the_twin_where_nothing_runs_server_actions_the_file_is_browser_code(tmp_path):
    """In a web app that runs in the browser and has no framework for Server Actions, `"use server"` does nothing:
    the file is bundled like any other, so what it holds is on the visitor's side."""
    g = _build(tmp_path, {"src/actions.ts": ACTIONS, "src/db.ts": DB,
                          "src/Row.tsx": ROW.replace("../app/actions", "./actions"),
                          "src/main.tsx": 'import { createRoot } from "react-dom/client";\n'
                                          'import { Row } from "./Row";\n'
                                          'createRoot(document.getElementById("root")!).render(<Row id="1" />);\n'}, SPA)
    side = clientside.where(g)
    for nid in ("js:src/Row::Row", "js:src/actions::removeTodo", "js:src/db::remove"):
        assert nid in side, nid


# ------------------------------------------------------------------ what a finding inside an action is told as
SHELL = '''"use server";
import { exec } from "child_process";

export async function makeBackup(formData: FormData) {
  const name = formData.get("name");
  exec("tar czf /backups/" + name + ".tgz /data");
}
'''
SHELL_PAGE = '''import { makeBackup } from "./actions";

export default function Page() {
  return (
    <form action={makeBackup}>
      <input name="name" />
      <button type="submit">Back up</button>
    </form>
  );
}
'''
SHELL_ROUTE = '''import { exec } from "child_process";

export async function POST(request: Request) {
  const { name } = await request.json();
  exec("tar czf /backups/" + name + ".tgz /data");
  return Response.json({ ok: true });
}
'''


def _shell(g):
    return next(f for f in scan(g)["findings"] if f["rule"] == "LJ-EXEC")


def test_the_story_of_a_finding_in_an_action_walks_the_page_and_its_form(tmp_path):
    g = _build(tmp_path, {"app/actions.ts": SHELL, "app/page.tsx": SHELL_PAGE})
    f = _shell(g)
    assert f["reachable"]["entry"] == "js:app/actions::makeBackup" and f["reachable"]["kind"] == "route"
    assert f["ui_path"] == ["js:app/page::Page", "js:app/actions::makeBackup"]
    steps = f["scenario"]["steps"]
    assert "opens the / page" in steps[0]
    assert steps[1] == "They send the form on it."
    assert "ACTION" not in json.dumps(f["scenario"])


def test_the_story_of_an_action_no_page_uses_names_it_as_an_action(tmp_path):
    """No page leads to it, and it can be run all the same: the story says how, in words, never `ACTION x`."""
    g = _build(tmp_path, {"app/actions.ts": SHELL})
    f = _shell(g)
    assert f["ui_path"] is None and f["reachable"]["entry"] == "js:app/actions::makeBackup"
    told = f["scenario"]
    assert "straight to the Server Action makeBackup" in told["steps"][0]
    assert "an address of its own" in told["steps"][0]
    assert "ACTION" not in json.dumps(told)


def test_the_twin_a_route_file_is_told_as_it_was(tmp_path):
    g = _build(tmp_path, {"app/api/backup/route.ts": SHELL_ROUTE})
    f = _shell(g)
    assert "sends a request straight to POST /api/backup. Anyone who knows the address can." in f["scenario"]["steps"][0]


# ------------------------------------------------------------------ what an action is handed is what was sent
WITH_PG = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0", "pg": "8.11.5"}})
SPA_PG = json.dumps({"dependencies": {"react": "18.3.0", "react-dom": "18.3.0", "pg": "8.11.5"}})
HANDED = '''"use server";
import { exec } from "child_process";
import { Pool } from "pg";
const pool = new Pool();

export async function makeBackup(formData: FormData) {
  const name = formData.get("name");
  exec("tar czf /backups/" + name + ".tgz /data");
}

export async function removeNote(id: string) {
  await pool.query("delete from notes where id = '" + id + "'");
}

export async function rename(prevState: unknown, data: FormData) {
  await pool.query("update notes set title = '" + data.get("title") + "'");
}

export async function page(n: number) {
  await pool.query("select * from notes limit " + n);
}

export async function fixed() {
  await pool.query("select * from notes where kind = '" + "todo" + "'");
}

async function helper(id: string) {
  await pool.query("select * from notes where id = '" + id + "'");
}
'''


def _flows(root, files, pkg):
    from lantern import flow
    res = flow.analyze(_build(root, files, pkg))
    assert not res.errors, res.errors
    return sorted((f["class"], f["line"]) for f in res.flows)


def test_what_an_action_is_handed_is_followed_like_any_request_value(tmp_path):
    """Form data under any name, the arguments a client component calls it with, the state a form hands back: the
    visitor's browser sends them all. A number carries no text, a fixed text is the code's own, and a function the
    file keeps to itself is handed only what the server gives it."""
    assert _flows(tmp_path, {"app/actions.ts": HANDED}, WITH_PG) == [("shell", 8), ("sql", 12), ("sql", 16)]


def test_the_twin_where_nothing_runs_server_actions_an_argument_is_no_request_value(tmp_path):
    """The same file where the words do nothing: these are plain functions, called by the app's own code, and
    what they are handed is not said to come from a request."""
    assert _flows(tmp_path, {"src/actions.ts": HANDED}, SPA_PG) == []


# ------------------------------------------------------------------ an action that changes data and asks nobody
PRISMA = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0", "@prisma/client": "5.14.0"}})
PRISMA_DB = '''import { PrismaClient } from "@prisma/client";
export const db = new PrismaClient();
'''
LOGIN = '''import { cookies } from "next/headers";
export async function requireUser() {
  const token = cookies().get("session");
  if (!token) throw new Error("Sign in first");
  return token.value;
}
'''
NOTE_ROW = '''"use client";
import { NAME } from "../app/actions";

export function Row({ id }: { id: string }) {
  return <button onClick={() => NAME(id)}>Go</button>;
}
'''
NOTE_PAGE = '''import { Row } from "../components/Row";
export default function Page() {
  return <Row id="1" />;
}
'''


def _action_file(name, body, head=""):
    return ('"use server";\nimport { db } from "../lib/db";\n' + head +
            f"\nexport async function {name}(id: string) {{\n{body}}}\n")


def _asked(root, name, body, head="", used=True, more=None):
    from lantern import websec
    files = {"app/actions.ts": _action_file(name, body, head), "lib/db.ts": PRISMA_DB, "lib/session.ts": LOGIN,
             "app/page.tsx": NOTE_PAGE if used else "export default function Page() { return <p>Hi</p>; }\n"}
    if used:
        files["components/Row.tsx"] = NOTE_ROW.replace("NAME", name)
    files.update(more or {})
    g = _build(root, files, PRISMA)
    return [f["title"] for f in websec.missing_auth(g)]


REMOVES = "  await db.note.delete({ where: { id } });\n"


def test_an_action_that_changes_data_and_checks_nobody_is_found(tmp_path):
    assert _asked(tmp_path, "removeNote", REMOVES) == [
        "The Server Action removeNote changes data, the app uses it, and no login check was found"]
    sql = "  await db.$executeRawUnsafe(\"delete from notes where id = '\" + id + \"'\");\n"
    assert len(_asked(tmp_path / "sql", "purgeNote", sql)) == 1


def test_the_twins_an_action_the_login_rule_leaves_alone(tmp_path):
    """One that checks who is asking, one that only reads, one that is public by its name, one the app does not
    use, and the same function where nothing runs Server Actions."""
    guarded = '  await requireUser();\n' + REMOVES
    assert _asked(tmp_path / "guarded", "removeNote", guarded, 'import { requireUser } from "../lib/session";\n') == []
    reads = "  return db.note.findMany({ where: { id } });\n"
    assert _asked(tmp_path / "reads", "findNotes", reads) == []
    assert _asked(tmp_path / "public", "subscribe", "  await db.reader.create({ data: { id } });\n") == []
    assert _asked(tmp_path / "unused", "removeNote", REMOVES, used=False) == []
    hashes = '  return createHash("sha256").update(id).digest("hex");\n'
    assert _asked(tmp_path / "hash", "fingerprint", hashes, 'import { createHash } from "crypto";\n') == []


NOTES = '''import { db } from "./db";
export async function dropNote(id: string) {
  await db.note.delete({ where: { id } });
}
export async function readNote(id: string) {
  return db.note.findUnique({ where: { id } });
}
'''
FROM_NOTES = 'import { dropNote, readNote } from "../lib/notes";\n'


def test_the_case_of_a_finding_names_the_action_in_plain_words(tmp_path):
    """The case says where the finding is reached from; for an action that is "the Server Action x", for a route
    file (the twin) the verb and path as before."""
    from lantern.security import scan
    files = {"app/actions.ts": _action_file("removeNote", REMOVES), "lib/db.ts": PRISMA_DB, "app/page.tsx": NOTE_PAGE,
             "components/Row.tsx": NOTE_ROW.replace("NAME", "removeNote")}
    found = [f for f in scan(_build(tmp_path, files, PRISMA))["findings"] if f["rule"] == "LW-AUTH-MISSING"]
    assert len(found) == 1
    facts = [e["fact"] for e in found[0]["case"]["evidence"]] + [c["why"] for c in found[0]["case"]["conditions"]]
    assert "It is an entry point itself: the Server Action removeNote" in facts
    assert "reached from the Server Action removeNote" in facts
    assert not any("ACTION " in x for x in facts)
    twin = [f for f in scan(_build(tmp_path / "twin", {"app/api/run/route.ts": SHELL_ROUTE}))["findings"]]
    said = [e["fact"] for f in twin for e in f["case"]["evidence"]]
    assert any(x.startswith("It is an entry point itself: route POST /api/run") for x in said), said


def test_the_protections_list_names_the_action_not_a_line_of_code(tmp_path):
    """"Login check on routes that change data" lists what a finding calls open; an action is named there as
    one, and a route file (the twin) by its verb and path as before."""
    from lantern.readiness import assess
    from lantern.security import scan
    files = {"app/actions.ts": _action_file("removeNote", REMOVES), "lib/db.ts": PRISMA_DB, "app/page.tsx": NOTE_PAGE,
             "components/Row.tsx": NOTE_ROW.replace("NAME", "removeNote")}
    g = _build(tmp_path, files, PRISMA)
    item = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}["route-auth"]
    assert item["status"] == "add"
    assert item["evidence"] == ["the Server Action removeNote (app/actions.ts:4)"]
    twin = {"app/api/notes/route.ts": 'export async function DELETE(request: Request) {\n  return Response.json({});\n}\n'}
    g = _build(tmp_path / "twin", twin)
    item = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}["route-auth"]
    assert item["evidence"] == ["DELETE /api/notes (app/api/notes/route.ts:1)"]


def test_a_change_made_by_a_function_the_action_calls_counts_too(tmp_path):
    """The action hands the work to a function of the project; the twin's function only reads."""
    more = {"lib/notes.ts": NOTES}
    assert _asked(tmp_path, "removeNote", "  await dropNote(id);\n", FROM_NOTES, more=more) == [
        "The Server Action removeNote changes data, the app uses it, and no login check was found"]
    assert _asked(tmp_path / "reads", "showNote", "  return readNote(id);\n", FROM_NOTES, more=more) == []


def test_the_twins_what_is_no_database_is_no_change(tmp_path):
    """`delete` on a set of the function's own, on the request's cookies and on a form's data: a name a database
    library uses, on things that are none. Beside them an SQL text that changes rows, handed to a library whose
    call has an everyday name (found), and the same written in a comment (not found)."""
    own = ('  const seen = new Set<string>();\n  seen.delete(id);\n  const jar = await cookies();\n'
           '  jar.delete("draft");\n  const form = new FormData();\n  form.delete("id");\n  return seen.size;\n')
    assert _asked(tmp_path, "tidy", own, 'import { cookies } from "next/headers";\n') == []
    words = '  await pool.query("delete from notes where id = $1", [id]);\n'
    assert _asked(tmp_path / "words", "clear", words, 'import { pool } from "../lib/pool";\n') == [
        "The Server Action clear changes data, the app uses it, and no login check was found"]
    said = '  // await db.$executeRawUnsafe("delete from notes")\n  return id;\n'
    assert _asked(tmp_path / "said", "clear", said) == []


# ------------------------------------------------------------------ a library that keeps none of the app's data
AI_HEAD = ('import OpenAI from "openai";\nimport Stripe from "stripe";\n'
           'const openai = new OpenAI();\nconst stripe = new Stripe("k");\n')


def test_a_call_into_a_library_that_keeps_none_of_the_apps_data_is_no_change(tmp_path):
    """`create` is how a database library adds a row, and how a model provider is asked for an answer and a payment
    provider for a customer. Where the map shows which library a call goes into, one that keeps none of the app's
    data is no change (the paid-call rule asks about those); the twin goes into a database library."""
    asks = '  return openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: id }] });\n'
    assert _asked(tmp_path, "summarize", asks, AI_HEAD) == []
    assert _asked(tmp_path / "pays", "enrol", "  return stripe.customers.create({ email: id });\n", AI_HEAD) == []
    own = 'import { PrismaClient } from "@prisma/client";\nconst prisma = new PrismaClient();\n'
    assert _asked(tmp_path / "twin", "addNote", "  return prisma.note.create({ data: { id } });\n", own) == [
        "The Server Action addNote changes data, the app uses it, and no login check was found"]


# ------------------------------------------------------------------ the map's word for an action stays on the map
WORDS_PKG = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0", "@prisma/client": "5.14.0",
                                         "openai": "4.52.0"}})
WORDS_ACTIONS = '''"use server";
import OpenAI from "openai";
import { db } from "../lib/db";
import { auth } from "../lib/session";

const openai = new OpenAI();

export async function signIn(formData: FormData) {
  const user = await db.user.findUnique({ where: { email: String(formData.get("email")) } });
  return user ? "ok" : "no";
}

export async function renameNote(id: string, title: string) {
  const session = await auth();
  if (!session) throw new Error("sign in");
  await db.note.update({ where: { id }, data: { title } });
}

export async function summarize(text: string) {
  const r = await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: text }] });
  return r.choices[0].message.content;
}
'''
WORDS_SESSION = '''import { cookies } from "next/headers";
export async function auth() {
  const jar = await cookies();
  return jar.get("session")?.value ? { user: 1 } : null;
}
'''
WORDS_PAGE = '''import { Row } from "../components/Row";
import { signIn } from "./actions";
export default function Page() {
  return (
    <main>
      <form action={signIn}><input name="email" /><button>Sign in</button></form>
      <Row id="1" />
    </main>
  );
}
'''
WORDS_ROW = '''"use client";
import { renameNote, summarize } from "../app/actions";
export function Row({ id }: { id: string }) {
  return <p><button onClick={() => renameNote(id, "x")}>Rename</button><button onClick={() => summarize(id)}>Sum</button></p>;
}
'''
SUM_ROUTE = '''import OpenAI from "openai";
const openai = new OpenAI();
export async function POST(request: Request) {
  const r = await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: await request.text() }] });
  return Response.json(r);
}
'''


def _strings(x, path=""):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(x, (list, tuple)):
        for i, v in enumerate(x):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(x, str):
        yield path, x


def test_route_words_say_an_action_in_plain_words_and_leave_every_other_route_as_it_is():
    from lantern.graph import action_name, route_words
    assert action_name("ACTION saveNote") == "saveNote"
    assert route_words("ACTION saveNote") == "the Server Action saveNote"
    assert route_words("ACTION saveNote", first=True) == "The Server Action saveNote"
    for other in ("POST /api/notes", "ANY /api/run", "INTENT NotesProvider provider (other apps can start it) · query",
                  "LINK DeepLink handles links (other apps and web pages can open it) · handle", "ACTION", "", None):
        assert action_name(other) is None
        assert route_words(other, first=True) == (other or "")


def test_no_sentence_a_reader_gets_holds_the_maps_word_for_an_action(tmp_path):
    """`ACTION summarize` is how the map writes an action down (it has no verb and no path). A finding's heading,
    story and case, and the lists of the readiness page, say "the Server Action summarize". The list of routes a
    finding keeps as data (`routes`) holds the map's word, as it holds `POST /api/notes` for a route file."""
    from lantern.readiness import assess
    files = {"app/actions.ts": WORDS_ACTIONS, "lib/db.ts": PRISMA_DB, "lib/session.ts": WORDS_SESSION,
             "app/page.tsx": WORDS_PAGE, "components/Row.tsx": WORDS_ROW}
    g = _build(tmp_path, files, WORDS_PKG)
    sec = scan(g)
    found = {f["rule"]: f for f in sec["findings"]}
    assert found["LA-WALLET-DRAIN"]["title"] == ("The Server Action summarize spends money (model call) and anyone can "
                                                 "call it as often as they like")
    assert found["LA-WALLET-DRAIN"]["snippet"] == "export async function summarize(text: string) {"
    assert found["LT-AUTHZ-OWNER"]["title"] == ("The Server Action renameNote reaches a record by an id from the "
                                                "request, and nothing compares the record's owner with who is signed in")
    assert found["LT-AUTHZ-OWNER"]["routes"] == ["ACTION renameNote"]
    ready = assess(g, sec, {})
    held = [(p, s) for p, s in [*_strings(sec["findings"]), *_strings(ready)]
            if "ACTION " in s and not re.search(r"\.routes\[\d+\]$", p)]
    assert held == []
    line = WORDS_ACTIONS.splitlines().index("export async function signIn(formData: FormData) {") + 1
    limit = {p["id"]: p for p in ready["protections"]}["rate-limit"]
    assert limit["evidence"] == [f"the Server Action signIn (app/actions.ts:{line})"]
    tests = next(c for cat in ready["categories"] for c in cat["checks"] if c["id"] == "tests-entries")
    assert "not reached: the Server Action signIn, the Server Action renameNote, the Server Action summarize" in tests["evidence"]
    # the twin: a route file is named by its verb and path, as before
    twin = scan(_build(tmp_path / "twin", {"app/api/sum/route.ts": SUM_ROUTE}, WORDS_PKG))
    drain = next(f for f in twin["findings"] if f["rule"] == "LA-WALLET-DRAIN")
    assert drain["title"] == "POST /api/sum spends money (model call) and anyone can call it as often as they like"
    assert drain["snippet"] == "POST /api/sum"


def test_an_action_that_changes_data_is_counted_among_the_routes_that_do(tmp_path):
    """The readiness page asks for a request limit and a login check on "routes that change data". An action that
    changes data is one, named as an action (before, an app written with actions alone got neither line); the twin
    only reads and is not counted."""
    from lantern.readiness import assess
    head = 'import { requireUser } from "../lib/session";\n'
    files = {"app/actions.ts": _action_file("removeNote", "  await requireUser();\n" + REMOVES, head),
             "lib/db.ts": PRISMA_DB, "lib/session.ts": LOGIN, "app/page.tsx": NOTE_PAGE,
             "components/Row.tsx": NOTE_ROW.replace("NAME", "removeNote")}
    g = _build(tmp_path, files, PRISMA)
    prot = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}
    assert prot["route-auth"]["status"] == "in place"
    assert [x.split(":")[0] for x in prot["route-auth"]["found"]] == ["the Server Action removeNote"]
    assert prot["rate-limit"]["status"] == "add"
    assert prot["rate-limit"]["evidence"] == ["the Server Action removeNote (app/actions.ts:5)"]
    assert prot["rate-limit"]["why"].startswith("1 route(s) that change data ")
    reads = dict(files, **{"app/actions.ts": _action_file("findNotes", "  return db.note.findMany({ where: { id } });\n"),
                           "components/Row.tsx": NOTE_ROW.replace("NAME", "findNotes")})
    g = _build(tmp_path / "reads", reads, PRISMA)
    prot = {p["id"]: p for p in assess(g, scan(g), {})["protections"]}
    assert "route-auth" not in prot and "rate-limit" not in prot


# ------------------------------------------------------------------ in the report page
def test_the_report_page_shows_an_action_by_its_name(tmp_path):
    """The page's own functions, run by Node on their text: what a row, a chip or a path shows for an entry. And the
    places that printed a route's detail as the map writes it print the label."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    html = (Path(report.__file__).parent / "viewer" / "report.html").read_text(encoding="utf-8")
    parts = [re.search(pattern, html, re.S | re.M) for pattern in (
        r"^const METHODS = [^\n]*\n", r"^function routeParts\(detail\) \{.*?^\}\n", r"^const isAction = [^\n]*\n",
        r"^const actionName = [^\n]*\n", r"^const entryLabel = [^\n]*\n")]
    assert all(parts), "the page has no entryLabel"
    asked = [{"kind": "route", "detail": "ACTION saveNote"}, {"kind": "route", "detail": "POST /api/notes"},
             {"kind": "page", "detail": "/todos"}, {"kind": "page", "detail": "ACTION figures"}, None]
    (tmp_path / "run.js").write_text(
        "".join(p.group(0) for p in parts) + f"const asked = {json.dumps(asked)};\n"
        "console.log(JSON.stringify([asked.map(entryLabel), asked.map(e => routeParts(e && e.detail))]));\n",
        encoding="utf-8")
    r = subprocess.run([node, str(tmp_path / "run.js")], capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    labels, split = json.loads(r.stdout)
    assert labels == ["Server Action saveNote", "POST /api/notes", "/todos", "ACTION figures", ""]
    assert split[:2] == [[None, "Server Action saveNote"], ["POST", "/api/notes"]]
    for raw in ("' · ' + esc(n.entry.detail)", "N[p].entry.detail ? N[p].entry.detail :",
                "n.entry.kind === 'route' ? n.entry.detail :", "N[reach.entry].entry.detail ? N[reach.entry].entry.detail :",
                "` · ${esc(n.entry.detail)}`"):
        assert raw not in html, raw
