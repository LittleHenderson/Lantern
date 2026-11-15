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


# ------------------------------------------------------------------ the project's own packages
OWN_ROOT = json.dumps({"name": "mono", "private": True, "workspaces": ["apps/*", "packages/*"]})
OWN_FILES = {
    "package.json": OWN_ROOT,
    # conditions: the built file is not committed, the source is
    "packages/store/package.json": json.dumps({
        "name": "@team/store", "dependencies": {"@prisma/client": "5.14.0"},
        "exports": {".": {"types": "./dist/index.d.ts", "default": "./src/index.ts"},
                    "./tables": {"types": "./dist/tables.d.ts", "default": "./src/tables.ts"}}}),
    "packages/store/src/index.ts": ('import { PrismaClient } from "@prisma/client";\n'
                                    'export const db = new PrismaClient();\n'
                                    'export function countNotes() {\n  return db.note.count();\n}\n'),
    "packages/store/src/tables.ts": 'export function tableName() {\n  return "notes";\n}\n',
    "packages/store/src/inner.ts": 'export function inner() {\n  return 1;\n}\n',
    # a pattern: every file of `src` under its own name
    "packages/parts/package.json": json.dumps({"name": "@team/parts", "exports": {"./*": "./src/*.tsx"}}),
    "packages/parts/src/button.tsx": "export function Button() {\n  return <button />;\n}\n",
    # `main` names the built file, which is not committed: the source beside it is what was written
    "packages/built/package.json": json.dumps({"name": "@team/built", "main": "./dist/index.js",
                                               "types": "./dist/index.d.ts"}),
    "packages/built/src/index.ts": "export function helper() {\n  return 2;\n}\n",
    # nothing but a name: the folder's `index`
    "packages/plain/package.json": json.dumps({"name": "plain-kit"}),
    "packages/plain/index.js": "export function go() {\n  return 3;\n}\n",
    "packages/plain/extra/more.js": "export function more() {\n  return 4;\n}\n",
    # what it names is made by a build step and is not in the project
    "packages/gen/package.json": json.dumps({"name": "@team/gen", "exports": {".": "./generated/index.js"}}),
    "packages/gen/src/make.ts": "export function make() {\n  return 5;\n}\n",
    "apps/web/package.json": json.dumps({"name": "web", "dependencies": {
        "@team/store": "workspace:*", "@team/parts": "workspace:*", "@team/built": "workspace:*",
        "plain-kit": "workspace:*", "@team/gen": "workspace:*", "left-pad": "1.3.0", "react": "19.0.0"}}),
    "apps/web/src/notes.ts": ('import { countNotes, db } from "@team/store";\n'
                              'import { tableName } from "@team/store/tables";\n'
                              'import { inner } from "@team/store/src/inner";\n'
                              'import { helper } from "@team/built";\nimport { go } from "plain-kit";\n'
                              'import { more } from "plain-kit/extra/more";\n'
                              'import { made } from "@team/gen";\nimport pad from "left-pad";\n\n'
                              'export async function run() {\n  await countNotes();\n  await db.note.count();\n'
                              '  tableName();\n  inner();\n  helper();\n  go();\n  more();\n  made();\n'
                              '  return pad("a", 2);\n}\n'),
    "apps/web/src/page.tsx": ('import { Button } from "@team/parts/button";\n\n'
                              'export function Page() {\n  return <Button />;\n}\n'),
}


def test_a_package_of_the_project_is_followed_to_its_file(tmp_path):
    """A monorepo: `packages/store/package.json` is named `@team/store`, and an app of the same project imports
    `@team/store`. That is the project's own code, found through what the package's manifest says: `exports` (a
    path, conditions, a `./*` pattern), `main` (the source beside a built file that is not committed), or the
    folder's `index`. Until 2026-11-15 every such import was read as a library: on one sample project 86 calls,
    among them every shared page part and the database handle."""
    g = _g(tmp_path, OWN_FILES)
    at = "apps/web/src/notes.ts"
    assert _said(g, "countNotes", at) == ("resolved", ["js:packages/store/src/index::countNotes"], "name")
    assert _said(g, "tableName", at) == ("resolved", ["js:packages/store/src/tables::tableName"], "name")
    assert _said(g, "helper", at) == ("resolved", ["js:packages/built/src/index::helper"], "name")
    assert _said(g, "go", at) == ("resolved", ["js:packages/plain/index::go"], "name")
    assert _said(g, "more", at) == ("resolved", ["js:packages/plain/extra/more::more"], "name")
    assert _said(g, "Button", "apps/web/src/page.tsx")[:2] == ("resolved", ["js:packages/parts/src/button::Button"])
    # a value the package exports is followed as one from a file beside the caller is
    assert _said(g, "db.note.count", at) == ("external", ["ext:@prisma/client.PrismaClient.note.count"],
                                             "library-value")
    # what the package names is not in the project: a file of the project that is not there, never a library
    assert _said(g, "made", at) == ("unresolved", [], "missing-module")
    # a path the package's `exports` does not list is refused by Node, and no file is taken for it
    assert _said(g, "inner", at) == ("unresolved", [], "missing-module")
    # the twin: a package that is not in the project
    assert _said(g, "pad", at)[0] == "external"
    # (for a file that is not there the map keeps its older `ext:` link, as it does for every such import)
    assert sorted(n for n in g.nodes if n.startswith(("ext:@team/", "ext:plain-kit"))) == [
        "ext:@team/gen.made", "ext:@team/store/src/inner.inner"]


def test_a_name_two_folders_of_the_project_carry_is_nobodys(tmp_path):
    """The twin: two folders whose manifests carry the same name (a copy kept as an example, a fixture). Which of
    them an import means is not written anywhere, so it is read as before."""
    files = {**OWN_FILES, "examples/plain/package.json": json.dumps({"name": "plain-kit"}),
             "examples/plain/index.js": "export function go() {\n  return 6;\n}\n"}
    g = _g(tmp_path, files)
    assert _said(g, "go", "apps/web/src/notes.ts") == ("external", ["ext:plain-kit.go"], "import")
    assert _said(g, "countNotes", "apps/web/src/notes.ts")[0] == "resolved"


OWN_ASKED = {
    # no workspace, and the manifest beside the import asks for a version: what runs is the copy npm installs
    "outside a workspace, by a version": ({"name": "site", "dependencies": {"plain-kit": "2.1.0"}}, "2.1.0", False),
    # no workspace, and the manifest says where the package lies
    "outside a workspace, by its folder": ({"name": "site", "dependencies": {"plain-kit": "file:./kit"}}, "2.1.0", True),
    # no workspace and nothing asked for: nothing says the folder is what the import means
    "outside a workspace, not asked for": ({"name": "site"}, "2.1.0", False),
    "in a workspace, any version": ({"name": "site", "workspaces": ["kit"], "dependencies": {"plain-kit": "*"}},
                                    "2.1.0", True),
    "in a workspace, a version it can be": ({"name": "site", "workspaces": ["kit"],
                                             "dependencies": {"plain-kit": "^2.0.4"}}, "2.1.0", True),
    "in a workspace, another version": ({"name": "site", "workspaces": ["kit"],
                                         "dependencies": {"plain-kit": "^1.4.0"}}, "2.1.0", False),
    "in a workspace, below 1.0 the second number counts": ({"name": "site", "workspaces": ["kit"],
                                                            "dependencies": {"plain-kit": "~0.3.1"}}, "0.4.0", False),
    "in a workspace, not asked for (kept at the top)": ({"name": "site", "workspaces": ["kit"]}, "2.1.0", True),
}


def test_when_a_folder_of_the_project_is_what_an_import_means(tmp_path):
    """A folder whose manifest carries the imported name is what the import means where the importing package
    says so itself (`file:`, `workspace:`), or where the project is a workspace and the version asked for, if one
    is, can be the folder's own. Otherwise what runs is the package npm installs, and the call is a library's."""
    for i, (case, (root, version, own)) in enumerate(sorted(OWN_ASKED.items())):
        g = _g(tmp_path / str(i), {
            "package.json": json.dumps(root),
            "kit/package.json": json.dumps({"name": "plain-kit", "version": version}),
            "kit/index.js": "export function go() {\n  return 3;\n}\n",
            "src/notes.ts": 'import { go } from "plain-kit";\nexport function run() {\n  return go();\n}\n'})
        want = ("resolved", ["js:kit/index::go"], "name") if own else ("external", ["ext:plain-kit.go"], "import")
        assert _said(g, "go", "src/notes.ts") == want, case
    # a workspace said the way pnpm says it, and the package taken in with `require`
    g = _g(tmp_path / "pnpm", {
        "package.json": json.dumps({"name": "site"}), "pnpm-workspace.yaml": "packages:\n  - kit\n",
        "kit/package.json": json.dumps({"name": "plain-kit", "version": "2.1.0"}),
        "kit/index.js": "exports.go = function go() {\n  return 3;\n};\n",
        "src/notes.js": 'const kit = require("plain-kit");\nexports.run = function run() {\n  return kit.go();\n};\n'})
    assert _said(g, "kit.go", "src/notes.js")[:2] == ("resolved", ["js:kit/index::go"])


def test_a_librarys_name_a_file_of_the_project_hands_on(tmp_path):
    """`export * from "drizzle-orm/sql"` in the project's own `lib/data.ts`, and `import { eq } from "../lib/data"`
    elsewhere: `eq` is that library's function, as if it were imported from the library. So is a name the file
    hands on by itself (`export { alias as named } from …`). Until 2026-11-15 both were "a name that file does not
    export". The twins: two libraries handed on whole (which of them holds the name is not written), and a file
    of the project that is not there among the sources (the name may be that file's)."""
    g = _g(tmp_path, {
        "lib/data.ts": ('export * from "drizzle-orm/sql";\nexport { alias as named } from "drizzle-orm/pg-core";\n'
                        'export * as zod from "zod";\nexport function own() {\n  return 1;\n}\n'),
        "lib/two.ts": 'export * from "pg";\nexport * from "stripe";\n',
        "lib/part.ts": 'export * from "./gone";\nexport * from "pg";\n',
        "app/notes.ts": ('import { eq, named, own } from "../lib/data";\nimport { x } from "../lib/two";\n'
                         'import { y } from "../lib/part";\n'
                         'export function run() {\n  eq(1, 2);\n  named();\n  own();\n  x();\n  y();\n}\n')})
    assert _said(g, "eq") == ("external", ["ext:drizzle-orm/sql.eq"], "import")
    assert _said(g, "named") == ("external", ["ext:drizzle-orm/pg-core.alias"], "import")
    assert _said(g, "own") == ("resolved", ["js:lib/data::own"], "name")
    assert _said(g, "x") == ("unresolved", [], "missing-export")
    assert _said(g, "y") == ("unresolved", [], "missing-export")
