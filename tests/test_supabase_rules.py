"""Row rules of a Supabase project, read with the code that reaches the tables (roadmap stage 1).

A Supabase database is reached straight from the browser with a key every visitor has, so what a visitor may read
or change is decided by the table's row-level security. `LW-NO-RLS` says where the project's SQL files leave a table
open, and is critical where code that runs in the browser or on the phone reaches that table. Each dangerous shape
stands beside twins that must stay as they are."""
import json

import pytest

from lantern import websec
from lantern.engine import build_graph
from lantern.security import scan

NEXT = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0", "@supabase/supabase-js": "2.45.0"}})
SPA = json.dumps({"dependencies": {"react": "18.3.0", "@supabase/supabase-js": "2.45.0"},
                  "devDependencies": {"vite": "5.4.0"}})
EXPO = json.dumps({"dependencies": {"expo": "51.0.0", "react-native": "0.74.0", "react": "18.2.0",
                                    "@supabase/supabase-js": "2.45.0"}})

CLIENT = '''import { createClient } from "@supabase/supabase-js";

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
);
'''

TODOS = '''"use client";
import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export function Todos() {
  const [rows, setRows] = useState<any[]>([]);
  async function load() {
    const { data } = await supabase.from("todos").select("*");
    setRows(data ?? []);
  }
  async function add(title: string) {
    await supabase.from("todos").insert({ title });
  }
  useEffect(() => { load(); }, []);
  return <ul onClick={() => add("new")}>{rows.map((r) => <li key={r.id}>{r.title}</li>)}</ul>;
}
'''

PAGE = '''import { Todos } from "../components/Todos";

export default function Home() {
  return <Todos />;
}
'''

TABLE = "create table public.todos (id bigint primary key, title text, user_id uuid);\n"
ON = "alter table public.todos enable row level security;\n"
OWN_ROWS = ('create policy "own rows" on public.todos for all to authenticated\n'
            "  using (auth.uid() = user_id) with check (auth.uid() = user_id);\n")
SQL = "supabase/migrations/20240101000000_init.sql"

BROWSER = {"package.json": NEXT, "lib/supabase.ts": CLIENT, "components/Todos.tsx": TODOS, "app/page.tsx": PAGE}

# a server that keeps the table to itself: the service key, in a route's own file
SERVER_DB = '''import { createClient } from "@supabase/supabase-js";

export const db = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function addTodo(title: string) {
  return db.from("todos").insert({ title });
}
'''
ROUTE = '''import { addTodo } from "../../../lib/db";

export async function POST(req: Request) {
  const { title } = await req.json();
  await addTodo(title);
  return Response.json({ ok: true });
}
'''
SERVER = {"package.json": NEXT, "lib/db.ts": SERVER_DB, "app/api/todos/route.ts": ROUTE}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _found(root, files):
    """Each `LW-NO-RLS` finding of the project as (file, line, rank, what its row rules say)."""
    s = scan(build_graph(_write(root, files)))
    return [(f["file"], f["line"], f["rank"], f["row_rules"]) for f in s["findings"] if f["rule"] == "LW-NO-RLS"], s


def test_an_open_table_the_browser_reaches_is_critical_and_its_twin_with_row_rules_is_clean(tmp_path):
    found, s = _found(tmp_path / "open", {**BROWSER, SQL: TABLE})
    ((file, line, rank, rules),) = found
    assert (file, line, rank) == (SQL, 1, "critical")
    assert (rules["table"], rules["state"]) == ("public.todos", "off")
    assert [(c["node"], c["does"]) for c in rules["client"]] == [
        ("js:components/Todos::Todos.add", ["insert"]), ("js:components/Todos::Todos.load", ["select"])]
    (f,) = [f for f in s["findings"] if f["rule"] == "LW-NO-RLS"]
    assert f["node"] == "db:todos"                       # the finding stands on the table the map shows
    assert "'todos'" in f["title"] and "browser" in f["rank_basis"][0]["why"]
    (raw,) = websec.database_rules(tmp_path / "open", build_graph(tmp_path / "open"))
    assert raw["id"] == websec._fid("lw", "LW-NO-RLS", SQL, 1)      # the id the rule gave this line before

    found, _ = _found(tmp_path / "ruled", {**BROWSER, SQL: TABLE + ON + OWN_ROWS})
    assert found == []


def test_an_open_table_only_the_server_reaches_or_nothing_reaches_stays_high(tmp_path):
    found, _ = _found(tmp_path / "server", {**SERVER, SQL: TABLE})
    ((file, line, rank, rules),) = found
    assert (file, line, rank, rules["state"], rules["client"]) == (SQL, 1, "high", "off", [])

    found, _ = _found(tmp_path / "nobody", {"package.json": NEXT, SQL: TABLE})
    assert [(f, ln, r, rr["client"]) for f, ln, r, rr in found] == [(SQL, 1, "high", [])]


HELPER = '''import { supabase } from "./supabase";

export async function addTodo(title: string) {
  return supabase.from("todos").insert({ title });
}
'''
BUTTON = '''"use client";
import { addTodo } from "../lib/todos";

export function Add() {
  return <button onClick={() => addTodo("new")}>Add</button>;
}
'''
ACTION_ROUTE = '''import { addTodo } from "../../../lib/todos";

export async function POST(req: Request) {
  await addTodo((await req.json()).title);
  return Response.json({ ok: true });
}
'''


def test_a_helper_runs_where_its_caller_runs(tmp_path):
    """A file with no directive of its own is in the browser when a client component calls into it, and on the
    server when only a route does, or when the file says it is the server's ("use server")."""
    base = {"package.json": NEXT, "lib/supabase.ts": CLIENT, SQL: TABLE}
    found, _ = _found(tmp_path / "client", {**base, "lib/todos.ts": HELPER, "components/Add.tsx": BUTTON})
    ((_, _, rank, rules),) = found
    assert rank == "critical"
    assert [c["node"] for c in rules["client"]] == ["js:lib/todos::addTodo"]
    assert "Add" in rules["client"][0]["why"]

    found, _ = _found(tmp_path / "route", {**base, "lib/todos.ts": HELPER, "app/api/todos/route.ts": ACTION_ROUTE})
    assert [(r, rr["client"]) for _, _, r, rr in found] == [("high", [])]

    found, _ = _found(tmp_path / "action", {**base, "lib/todos.ts": '"use server";\n' + HELPER,
                                            "components/Add.tsx": BUTTON})
    assert [(r, rr["client"]) for _, _, r, rr in found] == [("high", [])]


APP = '''import { supabase } from "./supabase";

export function App() {
  async function add() {
    await supabase.from("todos").insert({ title: "new" });
  }
  return <button onClick={add}>Add</button>;
}
'''
PAGES_INDEX = '''import { supabase } from "../lib/supabase";

export default function Index() {
  async function add() {
    await supabase.from("todos").insert({ title: "new" });
  }
  return <button onClick={add}>Add</button>;
}

export async function getServerSideProps() {
  const { data } = await supabase.from("todos").select("*");
  return { props: { rows: data } };
}
'''
PAGES_API = '''import { supabase } from "../../lib/supabase";

export default async function handler(req, res) {
  await supabase.from("todos").insert({ title: req.body.title });
  res.json({ ok: true });
}
'''
SCREEN = '''import { Button } from "react-native";
import { supabase } from "../lib/supabase";

export default function Index() {
  async function add() {
    await supabase.from("todos").insert({ title: "new" });
  }
  return <Button title="Add" onPress={add} />;
}
'''


def test_which_code_runs_in_the_browser_or_on_the_phone(tmp_path):
    """A plain web app with no server framework is browser code. Of a Next.js project the old pages folder is (its
    pages run in the browser too), without what runs only on the server; a phone app's code is on the phone."""
    found, _ = _found(tmp_path / "spa", {"package.json": SPA, "src/supabase.ts": CLIENT, "src/App.tsx": APP,
                                         SQL: TABLE})
    assert [(r, [c["node"] for c in rr["client"]]) for _, _, r, rr in found] == [
        ("critical", ["js:src/App::App.add"])]

    found, _ = _found(tmp_path / "pages", {"package.json": NEXT, "lib/supabase.ts": CLIENT,
                                           "pages/index.tsx": PAGES_INDEX, SQL: TABLE})
    assert [(r, [c["node"] for c in rr["client"]]) for _, _, r, rr in found] == [
        ("critical", ["js:pages/index::Index.add"])]            # not getServerSideProps

    found, _ = _found(tmp_path / "api", {"package.json": NEXT, "lib/supabase.ts": CLIENT,
                                         "pages/api/todos.ts": PAGES_API, SQL: TABLE})
    assert [(r, rr["client"]) for _, _, r, rr in found] == [("high", [])]

    found, _ = _found(tmp_path / "phone", {"package.json": EXPO, "app.json": '{"expo": {"name": "t"}}',
                                           "lib/supabase.ts": CLIENT, "app/index.tsx": SCREEN, SQL: TABLE})
    ((_, _, rank, rules),) = found
    assert rank == "critical" and "phone" in rules["client"][0]["why"]


POLICIES = [
    # (the policy as written after `create policy p on public.todos`, rank, state, for whom, what it lets them do)
    ("for all using (true)", "critical", "open-write", "everyone", ["insert", "update", "delete"]),
    ("using (true)", "critical", "open-write", "everyone", ["insert", "update", "delete"]),
    ("for update using (true)", "critical", "open-write", "everyone", ["update"]),
    ("for delete to anon using (true)", "critical", "open-write", "everyone", ["delete"]),
    ("for all using (true) with check (auth.uid() = user_id)", "critical", "open-write", "everyone",
     ["update", "delete"]),
    ("for all to authenticated using (true)", "high", "open-write", "signed-in", ["insert", "update", "delete"]),
    ("for update to authenticated using (true) with check (true)", "high", "open-write", "signed-in", ["update"]),
    ("for insert with check (true)", "medium", "open-write", "everyone", ["insert"]),
    ("for insert to authenticated with check (true)", "medium", "open-write", "signed-in", ["insert"]),
    ("for select using (true)", "medium", "open-read", "everyone", ["select"]),
    ("for select to authenticated using (true)", "medium", "open-read", "signed-in", ["select"]),
    # the twins: nothing is open
    ("for select to service_role using (true)", None, None, None, None),
    ("for all to service_role using (true) with check (true)", None, None, None, None),
    ("for all using (auth.uid() = user_id)", None, None, None, None),
    ("for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id)", None, None, None,
     None),
    ("for insert to authenticated with check (auth.uid() = user_id)", None, None, None, None),
    ("as restrictive for all using (true)", None, None, None, None),
    ("for update using (true) with check (true);\ncreate policy q on public.todos as restrictive for update "
     "using (auth.uid() = user_id)", None, None, None, None),
]


@pytest.mark.parametrize("policy,rank,state,who,lets", POLICIES, ids=[p[0][:48] for p in POLICIES])
def test_a_policy_that_lets_everyone_through_and_the_policies_that_do_not(tmp_path, policy, rank, state, who, lets):
    """Row-level security is on and a policy stands. What counts is whom it lets do what to any row: a policy for
    everyone that lets rows be changed or removed is critical where the browser reaches the table."""
    found, _ = _found(tmp_path, {**BROWSER, SQL: TABLE + ON + f"create policy p on public.todos {policy};\n"})
    if rank is None:
        assert found == []
        return
    ((file, line, got, rules),) = found
    assert (file, line, got) == (SQL, 3, rank)
    assert (rules["table"], rules["state"], rules["policy"], rules["for"], rules["lets"]) == (
        "public.todos", state, "p", who, lets)


def test_an_open_policy_is_high_where_only_the_server_reaches_the_table(tmp_path):
    found, _ = _found(tmp_path, {**SERVER, SQL: TABLE + ON + "create policy p on public.todos using (true);\n"})
    assert [(ln, r, rr["state"], rr["client"]) for _, ln, r, rr in found] == [(3, "high", "open-write", [])]


def test_row_rules_switched_on_in_a_later_file_count_and_in_a_comment_they_do_not(tmp_path):
    later = "supabase/migrations/20240202000000_rules.sql"
    found, _ = _found(tmp_path / "later", {**BROWSER, SQL: TABLE, later: ON + OWN_ROWS})
    assert found == []
    found, _ = _found(tmp_path / "said", {**BROWSER, SQL: TABLE + "-- " + ON + "/* " + ON + " */\n"})
    assert [(ln, r, rr["state"]) for _, ln, r, rr in found] == [(1, "critical", "off")]


IN_DATABASE = TABLE + '''create function public.lock_down() returns void language plpgsql as $$
begin
  execute 'alter table public.todos enable row level security';
end $$;
select public.lock_down();
'''


def test_row_rules_switched_on_by_code_in_the_database_are_not_known(tmp_path):
    """The files create the table and never switch row-level security on, but code that runs in the database names
    it. Lantern does not run that code: the finding stays, says so, and is a guess."""
    found, s = _found(tmp_path / "function", {**BROWSER, SQL: IN_DATABASE})
    ((file, line, rank, rules),) = found
    assert (file, line, rank, rules["state"]) == (SQL, 1, "medium", "off-in-the-files")
    (f,) = [f for f in s["findings"] if f["rule"] == "LW-NO-RLS"]
    assert f["tool_confidence"] == "LOW" and f"{SQL}:2" in f["more_info"]        # where that code begins
    # a text that names row-level security may be run as a statement: the same, and never "critical" on a guess
    found, _ = _found(tmp_path / "text", {**BROWSER, SQL: TABLE + "select 'alter table public.todos enable row "
                                                                  "level security';\n"})
    assert [(ln, r, rr["state"]) for _, ln, r, rr in found] == [(1, "medium", "off-in-the-files")]


def test_a_table_is_named_with_its_schema_and_a_table_no_file_creates_is_not_judged(tmp_path):
    sql = ("create table private.audit (id bigint primary key);\n"
           "create table auth.notes (id bigint primary key);\n"
           "-- create table ghosts (id bigint);\n")
    found, _ = _found(tmp_path / "schemas", {"package.json": NEXT, SQL: sql})
    assert [(ln, r, rr["table"]) for _, ln, r, rr in found] == [(1, "high", "private.audit"), (2, "high", "auth.notes")]

    # the browser reads `todos`, and no SQL file of the project creates it: whether it is open is not known
    found, _ = _found(tmp_path / "elsewhere", {**BROWSER, SQL: "create table public.other (id bigint);\n" + (
        "alter table public.other enable row level security;\n")})
    assert found == []


def test_the_sample_app_keeps_its_finding_and_its_rank():
    """The Next.js sample: `todos` has no row-level security and only the server's own file reaches it."""
    from pathlib import Path
    root = Path(__file__).parent / "fixtures" / "nextapp"
    s = scan(build_graph(root))
    (f,) = [f for f in s["findings"] if f["rule"] == "LW-NO-RLS"]
    assert (f["file"], f["line"], f["rank"], f["node"]) == ("supabase/migrations/001_init.sql", 1, "high", "db:todos")
    assert f["row_rules"]["client"] == [] and "'todos'" in f["title"]
    (raw,) = websec.database_rules(root)
    assert raw["id"] == websec._fid("lw", "LW-NO-RLS", "supabase/migrations/001_init.sql", 1)


def test_without_a_map_the_files_alone_are_read(tmp_path):
    root = _write(tmp_path, {"package.json": NEXT, SQL: TABLE})
    (f,) = websec.database_rules(root)
    assert (f["rule"], f["file"], f["line"], f["fixed_rank"]) == ("LW-NO-RLS", SQL, 1, "high")


def _told(root, files):
    """The one `LW-NO-RLS` finding of the project as a person reads it: the heading, the story as one text (the
    steps, what happens, what the fix changes), what the story rests on, and the case."""
    _, s = _found(root, files)
    (f,) = [f for f in s["findings"] if f["rule"] == "LW-NO-RLS"]
    sc = f["scenario"]
    return f["headline"], " ".join([*sc["steps"], sc["harm"], sc["after_fix"]]), sc["basis"], f["case"]


TOLD = [
    # (the SQL after the table is made, the heading, words the story holds, words it must not hold)
    ("", "Anyone can read and change every row of this database table",
     ["for every row of this table", "change or remove rows", "no rules saying who may read or change"],
     ["signs up", "a rule on the table"]),
    (ON + "create policy p on public.todos using (true);\n",
     "Anyone can change and remove any row of this database table",
     ["to change and remove rows of this table that are not theirs", "a rule on the table lets everyone"],
     ["signs up", "no rules saying", "answers with every row"]),
    (ON + "create policy p on public.todos for delete to anon using (true);\n",
     "Anyone can remove any row of this database table",
     ["to remove rows of this table that are not theirs"], ["change", "signs up"]),
    (ON + "create policy p on public.todos for all to authenticated using (true);\n",
     "Any signed-in user can change and remove any row of this database table",
     ["signs up", "only asks that somebody is signed in"], ["no rules saying", "lets everyone"]),
    (ON + "create policy p on public.todos for insert with check (true);\n",
     "Anyone can add rows to this database table",
     ["to add rows to this table", "as many as they like"],
     ["answers with every row", "that are not theirs", "signs up"]),
    (ON + "create policy p on public.todos for select using (true);\n",
     "Anyone can read every row of this database table",
     ["for every row of this table", "lets everyone read"],
     ["change", "remove", "signs up", "no rules saying"]),
    (ON + "create policy p on public.todos for select to authenticated using (true);\n",
     "Any signed-in user can read every row of this database table",
     ["signs up", "not only their own"], ["no rules saying", "change", "remove"]),
]


@pytest.mark.parametrize("sql,heading,holds,holds_not", TOLD, ids=[t[1][:60] for t in TOLD])
def test_the_story_of_an_open_table_says_what_is_open_and_for_whom(tmp_path, sql, heading, holds, holds_not):
    """One story was told for every open table: "the database answers with every row, because the table has no
    rules". For a table whose rule lets rows be added and nothing else, or lets any signed-in user change them,
    that story is not what happens. The heading and the story follow what the SQL files leave open."""
    head, story, basis, _ = _told(tmp_path, {**BROWSER, SQL: TABLE + sql})
    assert head == heading
    for words in holds:
        assert words in story, (words, story)
    for words in holds_not:
        assert words not in story, (words, story)
    assert "the project's SQL files" in basis and "from the browser" in basis


def test_the_story_says_where_the_key_is_taken_from_and_what_lantern_did_not_find(tmp_path):
    """On a phone app the key is read out of the app, not copied from a page. Where Lantern found no code on the
    visitor's side that reaches the table, the story says that this is no proof, and still tells what happens."""
    _, story, basis, _ = _told(tmp_path / "phone", {
        "package.json": EXPO, "app.json": '{"expo": {"name": "t"}}', "lib/supabase.ts": CLIENT,
        "app/index.tsx": SCREEN, SQL: TABLE})
    assert "installs your app" in story and "opens your site" not in story and "from the phone" in basis

    head, story, basis, _ = _told(tmp_path / "server", {**SERVER, SQL: TABLE})
    assert head == "Anyone can read and change every row of this database table"
    assert "opens your site" in story
    assert "found no code on the visitor's side that reaches this table, which is not proof that none does" in basis


def test_the_case_of_an_open_table_says_what_the_files_show_and_what_is_not_known(tmp_path):
    """What has to be true for harm, each with what Lantern saw: the files leave the table open (seen), the
    database is as the files leave it (never known: Lantern reads files), a visitor has the table's name and the
    key (seen where the visitor's side talks to the table, not known otherwise, never "no")."""
    def needs(case):
        return {c["need"]: c["met"] for c in case["conditions"]}

    *_, case = _told(tmp_path / "off", {**BROWSER, SQL: TABLE})
    assert needs(case) == {"Row-level security is off for this table": True,
                           "The database is as the project's SQL files leave it": None,
                           "A visitor has the table's name and the public key": True}
    assert [e["fact"] for e in case["evidence"] if e["from"] == "SQL files"] == [
        "Replayed in the order they are applied, the project's SQL files create public.todos and never switch "
        "row-level security on for it"]
    assert any("the dashboard" in u for u in case["unknown"])

    *_, case = _told(tmp_path / "server", {**SERVER, SQL: TABLE})
    assert needs(case)["A visitor has the table's name and the public key"] is None

    *_, case = _told(tmp_path / "policy", {
        **BROWSER, SQL: TABLE + ON + "create policy p on public.todos for all to authenticated using (true);\n"})
    assert needs(case) == {"A policy lets any signed-in user change and remove any row": True,
                           "The database is as the project's SQL files leave it": None,
                           "A visitor has the table's name and the public key": True}

    # the twin: code in the database names row-level security, so whether it is off is not known
    *_, case = _told(tmp_path / "guess", {
        **BROWSER, SQL: TABLE + "create function lock_down() returns void language plpgsql as $$\n"
                                "begin execute 'alter table todos enable row level security'; end $$;\n"})
    assert needs(case)["Row-level security is off for this table"] is None


def test_the_twins_other_open_databases_keep_the_story_they_had(tmp_path):
    """A finding that carries no row rules is told as before: Firebase's open rules, and an `LW-NO-RLS` finding an
    older Lantern wrote."""
    from lantern import scenarios
    old = scenarios.for_finding({"id": "lw-1", "rule": "LW-NO-RLS", "tool": "lantern-web", "category": "config",
                                 "title": "Table 'todos' has no row-level security"}, None)
    assert old["steps"][1] == "From their own computer they ask the database for every row of this table."
    assert old["harm"].startswith("The database answers with every row, because the table has no rules")
    assert scenarios.headline({"id": "lw-1", "rule": "LW-NO-RLS"}, None) == "Anyone can read this database table"

    root = _write(tmp_path, {"package.json": SPA, "firestore.rules":
                             "service cloud.firestore {\n match /{document=**} {\n  allow read, write: if true;\n }\n}\n"})
    s = scan(build_graph(root))
    (f,) = [f for f in s["findings"] if f["rule"] == "LW-DB-OPEN"]
    assert f["headline"] == "Anyone can read this database table"
    assert f["scenario"]["steps"][1] == "From their own computer they ask the database for every row of this table."
