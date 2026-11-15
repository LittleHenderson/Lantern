"""Next.js Server Actions on the map (roadmap stage 1). A function a `"use server"` file exports, and a function
whose own body begins with `"use server"`, is run by the server for a request any visitor can send: the framework
gives it an address of its own, and a form or a client component calls it. So it is a `route` entry (`ACTION
<name>`), like a route written in a route file. Every shape stands beside look-alikes that must stay as they were."""
import json

from lantern import clientside
from lantern.engine import build_graph

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
