"""A value one file of the project exports and another imports (roadmap of 2026-11-14, stage 1).

`export const db = new PrismaClient()` in `lib/db.ts`, and `db.note.delete()` in a route or a Server Action: the call
was not followed (`missing-export`), because the JavaScript reader followed an import only to a function or a class.
CommonJS has had this since stage 3 (`module.exports = mysql.createPool()`); this is its ES-module twin, with the two
readings a real `lib/db.ts` needs: a variable's written type (`let prisma: PrismaClient`) and "the kept one or a new
one" (`cached ?? new PrismaClient()`). A sample project of the benchmark had 95 such calls.

Each case has a twin that must stay unlinked, with its reason."""

import json

from lantern.engine import build_graph

PKG = json.dumps({"dependencies": {"@prisma/client": "5.14.0", "stripe": "15.8.0", "drizzle-orm": "0.31.0",
                                   "pg": "8.11.5", "zod": "3.23.8"}})
DB = 'import { PrismaClient } from "@prisma/client";\nexport const db = new PrismaClient();\n'
STRIPE = 'import Stripe from "stripe";\nexport const stripe = new Stripe("k", { apiVersion: "2022-11-15" });\n'
ORM = ('import { drizzle } from "drizzle-orm/node-postgres";\nimport { Pool } from "pg";\n'
       'const pool = new Pool();\nexport const orm = drizzle(pool);\nexport default pool;\n')
SCHEMAS = 'import { z } from "zod";\nexport const noteSchema = z.object({ title: z.string() });\n'


def _g(tmp_path, files):
    for rel, text in {"package.json": PKG, **files}.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return build_graph(tmp_path)


def _said(g, callee, file="app/notes.ts"):
    hits = [s for s in g.sites if s["group"] == "written" and s["callee"] == callee and s["file"] == file]
    assert len(hits) == 1, (callee, hits)
    s = hits[0]
    return s["outcome"], s["to"], s["via"] or s["reason"]


def _edge(g, src, dst):
    return next((e for e in g.call_edges() if e.src == src and e.dst == dst), None)


def test_a_library_value_another_file_exports_is_followed_as_in_its_own_file(tmp_path):
    """The same five calls, once on values made in the file and once on values another file exports: the map names the
    same library function for both. Where the value was made in the file the link says how (`local-type` for
    `new X()`); across files it is a `library-value`, as it has been for CommonJS."""
    body = ('export async function removeNote(id: string) {\n'
            '  const body = noteSchema.parse({ title: id });\n'
            '  await db.note.delete({ where: { id } });\n'
            '  await stripe.customers.create({ email: id });\n'
            '  await orm.insert(body).values({ id });\n'
            '  return pool.query("select 1");\n'
            '}\n')
    g = _g(tmp_path, {
        "lib/db.ts": DB, "lib/stripe.ts": STRIPE, "lib/orm.ts": ORM, "lib/schemas.ts": SCHEMAS,
        "app/notes.ts": ('import { db } from "../lib/db";\nimport { stripe } from "../lib/stripe";\n'
                         'import pool, { orm } from "../lib/orm";\nimport { noteSchema } from "../lib/schemas";\n\n' + body),
        "app/same.ts": ('import { PrismaClient } from "@prisma/client";\nimport Stripe from "stripe";\n'
                        'import { z } from "zod";\nimport { drizzle } from "drizzle-orm/node-postgres";\n'
                        'import { Pool } from "pg";\nconst db = new PrismaClient();\nconst stripe = new Stripe("k");\n'
                        'const pool = new Pool();\nconst orm = drizzle(pool);\n'
                        'const noteSchema = z.object({ title: z.string() });\n' + body)})
    want = {"noteSchema.parse": "ext:zod.z.object().parse",
            "db.note.delete": "ext:@prisma/client.PrismaClient.note.delete",
            "stripe.customers.create": "ext:stripe.customers.create",
            "orm.insert": "ext:drizzle-orm/node-postgres.drizzle().insert",
            "orm.insert(body).values": "ext:drizzle-orm/node-postgres.drizzle().insert",
            "pool.query": "ext:pg.Pool.query"}
    for callee, to in want.items():
        assert _said(g, callee, "app/same.ts")[:2] == ("external", [to]), callee
        assert _said(g, callee)[:2] == ("external", [to]), callee
    assert _said(g, "db.note.delete")[2] == "library-value"
    assert _said(g, "orm.insert(body).values")[2] == "library-result"
    e = _edge(g, "js:app/notes::removeNote", "ext:@prisma/client.PrismaClient.note.delete")
    assert e is not None and (e.confidence, e.via) == ("inferred", "library-value")
    assert g.meta["calls"]["written"]["reasons"].get("missing-export") is None


def test_a_value_handed_on_by_another_file_and_a_default_export_are_followed(tmp_path):
    """`export { db } from "./db"`, `export * from "./stripe"`, a name imported and exported again, and
    `export default pool`."""
    g = _g(tmp_path, {
        "lib/db.ts": DB, "lib/stripe.ts": STRIPE, "lib/orm.ts": ORM,
        "lib/index.ts": ('export { db } from "./db";\nexport * from "./stripe";\nimport pool from "./orm";\n'
                         'export { pool as conn };\n'),
        "app/notes.ts": ('import { db as data, stripe as pay, conn } from "../lib";\n'
                         'export async function removeNote(id: string) {\n'
                         '  await data.note.update({ where: { id } });\n'
                         '  await pay.refunds.create({ charge: id });\n'
                         '  return conn.query("select 1");\n}\n')})
    assert _said(g, "data.note.update") == ("external", ["ext:@prisma/client.PrismaClient.note.update"], "library-value")
    assert _said(g, "pay.refunds.create") == ("external", ["ext:stripe.refunds.create"], "library-value")
    assert _said(g, "conn.query") == ("external", ["ext:pg.Pool.query"], "library-value")


def test_a_value_of_the_projects_own_class_is_followed_to_its_method(tmp_path):
    """`export const notes = new Notes()`: a call on it in another file is a likely link to the method, a link of the
    project's own code that the map did not have."""
    g = _g(tmp_path, {
        "lib/notes.ts": ('export class Notes {\n  find(id: string) { return id; }\n}\n'
                         'export const notes = new Notes();\nexport default notes;\n'),
        "app/notes.ts": ('import same, { notes } from "../lib/notes";\n'
                         'export function show(id: string) {\n  return notes.find(id) + same.find(id) + notes.gone(id);\n}\n')})
    for callee in ("notes.find", "same.find"):
        assert _said(g, callee) == ("likely", ["js:lib/notes::Notes.find"], "module-value"), callee
    e = _edge(g, "js:app/notes::show", "js:lib/notes::Notes.find")
    assert e is not None and (e.confidence, e.via) == ("inferred", "module-value")
    assert _said(g, "notes.gone")[0] == "unresolved"   # the twin: the class has no such method


def test_a_variables_written_type_says_what_it_is(tmp_path):
    """`let prisma: PrismaClient`, set in two branches: TypeScript holds every value of it to that type, so a call on it
    is a call on the library's class (in the file, and through `export const db = prisma` in another). The twins: a
    type that is one of two, and a type the file itself declares (no class to look in)."""
    g = _g(tmp_path, {
        "lib/db.ts": ('import { PrismaClient } from "@prisma/client";\nlet prisma: PrismaClient;\n'
                      'if (process.env.NODE_ENV === "production") {\n  prisma = new PrismaClient();\n} else {\n'
                      '  prisma = (global as any).cached;\n}\nexport const db = prisma;\n'
                      'interface Store { put(x: string): void }\n'
                      'let either: PrismaClient | null;\nlet store: Store;\n'
                      'export function count() {\n  either.note.count();\n  store.put("x");\n'
                      '  return prisma.note.count();\n}\n'),
        "app/notes.ts": ('import { db } from "../lib/db";\n'
                         'export async function removeNote(id: string) {\n  await db.note.delete({ where: { id } });\n}\n')})
    assert _said(g, "prisma.note.count", "lib/db.ts") == (
        "external", ["ext:@prisma/client.PrismaClient.note.count"], "local-type")
    assert _said(g, "db.note.delete") == ("external", ["ext:@prisma/client.PrismaClient.note.delete"], "library-value")
    assert _said(g, "either.note.count", "lib/db.ts") == ("unresolved", [], "repo-variable")
    assert _said(g, "store.put", "lib/db.ts") == ("unresolved", [], "repo-variable")


def test_the_kept_one_or_a_new_one_is_of_the_new_ones_class(tmp_path):
    """`export const prisma = globalForPrisma.prisma ?? new PrismaClient()`: how a Next.js app keeps one database
    client across reloads. Whichever side is taken, the code uses it as the class it would make. The twins: `&&`
    (the left side when it is falsy), and two calls with no `new`."""
    g = _g(tmp_path, {
        "lib/db.ts": ('import { PrismaClient } from "@prisma/client";\n'
                      'const globalForPrisma = globalThis as unknown as { prisma: PrismaClient | undefined };\n'
                      'export const kept = globalForPrisma.prisma ?? new PrismaClient();\n'
                      'export const orNew = globalForPrisma.prisma || new PrismaClient({ log: [] });\n'
                      'export const both = globalForPrisma.prisma && new PrismaClient();\n'
                      'export const either = globalForPrisma.one() ?? globalForPrisma.two();\n'),
        "app/notes.ts": ('import { kept, orNew, both, either } from "../lib/db";\n'
                         'export async function removeNote(id: string) {\n'
                         '  await kept.note.findFirst();\n  await orNew.note.count();\n'
                         '  await both.note.count();\n  await either.note.count();\n}\n')})
    assert _said(g, "kept.note.findFirst") == (
        "external", ["ext:@prisma/client.PrismaClient.note.findFirst"], "library-value")
    assert _said(g, "orNew.note.count") == ("external", ["ext:@prisma/client.PrismaClient.note.count"], "library-value")
    assert _said(g, "both.note.count") == ("unresolved", [], "missing-export")
    assert _said(g, "either.note.count") == ("unresolved", [], "missing-export")


def test_what_lantern_cannot_follow_stays_unlinked_with_its_reason(tmp_path):
    """An exported name that is set again, one built by a condition, a parameter and a local of the same name, a file
    that is not there, and a function the project itself puts on the value."""
    g = _g(tmp_path, {
        "lib/db.ts": ('import { PrismaClient } from "@prisma/client";\n'
                      'export let again = new PrismaClient();\nagain = wrap(again);\n'
                      'export const picked = process.env.A ? one() : two();\n'
                      'export const db = new PrismaClient();\n'
                      'import { make } from "some-lib";\nexport const ext = make();\n'
                      'ext.audit = function () { return 1; };\n'),
        "app/notes.ts": ('import { again, picked, db, ext } from "../lib/db";\nimport { lost } from "../lib/gone";\n'
                         'export async function removeNote(id: string) {\n'
                         '  await again.note.count();\n  await picked.note.count();\n  await lost.note.count();\n'
                         '  return ext.audit();\n}\n'
                         'export async function byParameter(db: any) {\n  return db.note.count();\n}\n'
                         'export async function byLocal() {\n  const db = await pick();\n  return db.note.findMany();\n}\n')})
    assert _said(g, "again.note.count") == ("unresolved", [], "missing-export")
    assert _said(g, "picked.note.count") == ("unresolved", [], "missing-export")
    assert _said(g, "lost.note.count") == ("unresolved", [], "missing-module")
    assert _said(g, "ext.audit") == ("unresolved", [], "library-or-repo")
    assert _said(g, "db.note.count") == ("unresolved", [], "parameter")
    assert _said(g, "db.note.findMany")[0] == "unresolved"
    assert not [e for e in g.call_edges() if e.src.startswith("js:app/notes::") and "PrismaClient" in e.dst]


def test_an_import_written_with_js_means_the_ts_file(tmp_path):
    """TypeScript's own rule where a project ships modules: the import says `./util.js` and the file is `util.ts`
    (`./view.jsx` for `view.tsx`, `./tool.mjs` for `tool.mts`). The twin: where no such file is there either, the
    call is into a file Lantern cannot find, as before."""
    g = _g(tmp_path, {"app/util.ts": "export function a() { return 1; }\n",
                      "app/view.tsx": "export function b() { return 2; }\n",
                      "app/tool.mts": "export function c() { return 3; }\n",
                      "app/notes.ts": 'import { a } from "./util.js";\nimport { b } from "./view.jsx";\n'
                                      'import { c } from "./tool.mjs";\nimport { d } from "./gone.js";\n'
                                      "export function run() { a(); b(); c(); d(); }\n"})
    assert _said(g, "a") == ("resolved", ["js:app/util::a"], "name")
    assert _said(g, "b") == ("resolved", ["js:app/view::b"], "name")
    assert _said(g, "c") == ("resolved", ["js:app/tool::c"], "name")
    assert _said(g, "d") == ("unresolved", [], "missing-module")
