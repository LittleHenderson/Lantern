"""Supabase calls on the map (roadmap stage 1): `<client>.from("<table>").<select|insert|update|upsert|delete>(…)`
is a call into that table, a node `db:<table>` in the Data lane. Every shape that is linked stands beside
look-alikes that must stay as they were."""
import json

from lantern.engine import build_graph
from lantern.graph import INFERRED, POSSIBLE

PKG = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0", "@supabase/supabase-js": "2.45.0",
                                   "@supabase/ssr": "0.5.0"}})

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
    const { data } = await supabase.from("todos").select("*").order("id");
    setRows(data ?? []);
  }
  async function add(title: string) {
    await supabase.from("todos").insert({ title });
  }
  async function done(id: number) {
    await supabase.from("todos").update({ done: true }).eq("id", id);
  }
  async function remove(id: number) {
    await supabase.from("todos").delete().eq("id", id);
  }
  useEffect(() => { load(); }, []);
  return (
    <ul>
      {rows.map((r) => <li key={r.id} onClick={() => remove(r.id)}>{r.title}</li>)}
      <button onClick={() => add("new")}>Add</button>
      <button onClick={() => done(1)}>Done</button>
    </ul>
  );
}
'''

PAGE = '''import { Todos } from "../components/Todos";

export default function Home() {
  return <Todos />;
}
'''

# The two files Supabase's own guide for Next.js has a project make.
BROWSER_CLIENT = '''import { createBrowserClient } from "@supabase/ssr";

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
  );
}
'''

SERVER_CLIENT = '''import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

export async function createClient() {
  const cookieStore = await cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
          } catch {}
        },
      },
    },
  );
}
'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _build(root, files):
    _write(root, {"package.json": PKG, **files})
    return build_graph(root)


def _edge(g, src, dst):
    for e in g.call_edges():
        if e.src == src and e.dst == dst:
            return e
    return None


def _tables(g):
    return sorted(n for n in g.nodes if n.startswith("db:"))


def _calls(g):
    return sorted((c["table"], c["op"], c["src"].split("::")[-1]) for c in g.meta.get("db_calls", []))


def test_a_page_that_reads_and_writes_a_table_is_linked_to_it(tmp_path):
    g = _build(tmp_path, {"lib/supabase.ts": CLIENT, "components/Todos.tsx": TODOS, "app/page.tsx": PAGE})
    assert _tables(g) == ["db:todos"]
    table = g.nodes["db:todos"]
    assert table.lane == "data" and table.name == "todos"
    for fn, op in (("load", "select"), ("add", "insert"), ("done", "update"), ("remove", "delete")):
        e = _edge(g, f"js:components/Todos::Todos.{fn}", "db:todos")
        assert e is not None, fn
        assert (e.via, e.confidence, e.detail) == ("supabase-from", INFERRED, f"{op} todos"), fn
    assert _calls(g) == [("todos", "delete", "Todos.remove"), ("todos", "insert", "Todos.add"),
                         ("todos", "select", "Todos.load"), ("todos", "update", "Todos.done")]
    # the call site itself says where it goes, and nothing written on the client is left "not worked out"
    (site,) = [s for s in g.sites if s["callee"].endswith('.from("todos").insert')]
    assert (site["outcome"], site["to"], site["via"]) == ("external", ["db:todos"], "supabase-from")
    assert not [k for k in g.unresolved if k.startswith("supabase")]


def test_several_calls_of_one_function_into_one_table_are_one_link_that_names_each(tmp_path):
    g = _build(tmp_path, {"lib/supabase.ts": CLIENT, "lib/board.ts": '''import { supabase } from "./supabase";

export async function swap(a: number, b: number) {
  const { data } = await supabase.from("cards").select("id, place").in("id", [a, b]);
  await supabase.from("cards").update({ place: data![1].place }).eq("id", a);
  await supabase.from("cards").update({ place: data![0].place }).eq("id", b);
  await supabase.from("moves").insert({ a, b });
}
'''})
    assert _tables(g) == ["db:cards", "db:moves"]
    e = _edge(g, "js:lib/board::swap", "db:cards")
    assert e.detail == "select, update cards" and e.lines == [4, 5, 6]
    assert _edge(g, "js:lib/board::swap", "db:moves").detail == "insert moves"
    assert [c["line"] for c in g.meta["db_calls"]] == [4, 5, 6, 7]


def test_a_client_that_a_function_of_the_project_hands_back(tmp_path):
    g = _build(tmp_path, {
        "tsconfig.json": json.dumps({"compilerOptions": {"paths": {"@/*": ["./*"]}}}),
        "utils/supabase/client.ts": BROWSER_CLIENT,
        "utils/supabase/server.ts": SERVER_CLIENT,
        "app/notes/page.tsx": '''import { createClient } from "@/utils/supabase/server";

export default async function Notes() {
  const supabase = await createClient();
  const { data: notes } = await supabase.from("notes").select();
  return <pre>{JSON.stringify(notes, null, 2)}</pre>;
}
''',
        "components/NoteForm.tsx": '''"use client";
import { createClient } from "@/utils/supabase/client";

export function NoteForm() {
  const supabase = createClient();
  async function save(text: string) {
    await supabase.from("notes").insert({ text });
  }
  return <button onClick={() => save("hi")}>Save</button>;
}
'''})
    assert _tables(g) == ["db:notes"]
    assert _edge(g, "js:app/notes/page::Notes", "db:notes").detail == "select notes"
    e = _edge(g, "js:components/NoteForm::NoteForm.save", "db:notes")
    assert (e.via, e.confidence, e.detail) == ("supabase-from", INFERRED, "insert notes")


def test_a_client_made_in_place_another_schema_a_written_type_and_a_table_named_by_a_constant(tmp_path):
    g = _build(tmp_path, {"server/admin.ts": '''import { createClient, SupabaseClient } from "@supabase/supabase-js";

const TABLE = "profiles";
const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function audit(row: object) {
  await admin.schema("private").from("audit_log").insert(row);
}

export async function count(db: SupabaseClient) {
  return db.from(TABLE).select("id", { count: "exact", head: true });
}

export async function purge() {
  await createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)
    .from("sessions").delete().lt("expires", "now");
}

export async function keep(row: object) {
  await admin.from("profiles").upsert(row);
}
'''})
    assert _tables(g) == ["db:private.audit_log", "db:profiles", "db:sessions"]
    assert _calls(g) == [("audit_log", "insert", "audit"), ("profiles", "select", "count"),
                         ("profiles", "upsert", "keep"), ("sessions", "delete", "purge")]
    assert [c["schema"] for c in g.meta["db_calls"] if c["table"] == "audit_log"] == ["private"]
    assert g.nodes["db:private.audit_log"].lane == "data"
    assert _edge(g, "js:server/admin::count", "db:profiles").confidence == INFERRED


def test_by_its_name_alone_the_link_is_a_possible_one(tmp_path):
    g = _build(tmp_path, {"lib/notes.js": '''export async function addNote(supabase, text) {
  await supabase.from("notes").insert({ text });
}

export class Store {
  constructor(client) {
    this.supabase = client;
  }

  async all() {
    return this.supabase.from("notes").select("*");
  }
}
'''})
    assert _tables(g) == ["db:notes"]
    for src in ("js:lib/notes::addNote", "js:lib/notes::Store.all"):
        e = _edge(g, src, "db:notes")
        assert e is not None and (e.via, e.confidence) == ("supabase-name", POSSIBLE), src
    (site,) = [s for s in g.sites if s["callee"].endswith('.from("notes").insert')]
    assert site["outcome"] == "external" and site["confidence"] == "possible"


def test_what_only_looks_like_a_call_into_a_table_is_not_linked(tmp_path):
    g = _build(tmp_path, {"lib/other.js": '''import knex from "knex";
import { createClient } from "@supabase/supabase-js";

const db = knex({ client: "pg" });
const sb = createClient(process.env.URL, process.env.KEY);

export async function users() {
  return db.from("users").select("*");                             // another library's query
}

export function letters() {
  return Array.from("abc").map((c) => c.toUpperCase());            // from() with no table call after it
}

export async function avatar(supabase, file) {
  return supabase.storage.from("avatars").upload("me.png", file);  // a storage bucket
}

export async function swapAvatar(file) {
  return sb.storage.from("avatars").update("me.png", file);        // a bucket, with a method named like a write
}

export async function anyTable(name) {
  return sb.from(name).select("*");                                // the table's name is not written
}

export async function orders(client) {
  return client.from("orders").select("*");                        // nothing says what `client` is
}

export async function shadowed(supabase) {
  supabase = knex({ client: "pg" });
  return supabase.from("users").select("*");                       // the name was given another library's value
}
'''})
    assert _tables(g) == []
    assert g.meta.get("db_calls", []) == []
    assert not [s for s in g.sites if any(t.startswith("db:") for t in s["to"])]


def test_the_map_of_a_project_without_supabase_is_as_it_was(tmp_path):
    files = {"package.json": json.dumps({"dependencies": {"express": "4"}}), "server.js": '''const express = require("express");
const app = express();

app.get("/items", function list(req, res) {
  res.json([]);
});

app.listen(3000);
'''}
    _write(tmp_path, files)
    g = build_graph(tmp_path)
    assert _tables(g) == [] and "db_calls" not in g.meta
