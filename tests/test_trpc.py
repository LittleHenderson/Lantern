"""tRPC procedures as routes (roadmap of 2026-11-14, stage 1).

A tRPC app has no route files: `createTRPCRouter({ create: protectedProcedure.input(…).mutation(fn) })` makes
`post.create` an address any visitor can send to (`POST /api/trpc/post.create`), and the login check is the procedure
the route is built on, not a line of the handler. Until now the map showed one catch-all route for the whole API, and
every handler was a part of its file.

Each shape sits beside twins that must stay as they were."""

import json

from lantern.engine import build_graph

PKG = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0", "@trpc/server": "11.0.0", "@trpc/client": "11.0.0",
                                   "@trpc/react-query": "11.0.0", "@tanstack/react-query": "5.50.0", "zod": "3.23.8",
                                   "@prisma/client": "5.14.0", "pg": "8.11.5"}})
NO_TRPC = json.dumps({"dependencies": {"next": "14.2.0", "react": "18.3.0", "zod": "3.23.8"}})
TRPC = '''import { initTRPC, TRPCError } from "@trpc/server";
import { db } from "../db";

export const createTRPCContext = async (opts: { headers: Headers }) => ({ db, session: await readSession(opts.headers) });
const t = initTRPC.context<typeof createTRPCContext>().create();

export const createTRPCRouter = t.router;
export const mergeRouters = t.mergeRouters;
export const publicProcedure = t.procedure;
export const protectedProcedure = t.procedure.use(({ ctx, next }) => {
  if (!ctx.session?.user) {
    throw new TRPCError({ code: "UNAUTHORIZED" });
  }
  return next({ ctx: { session: ctx.session } });
});
export const adminProcedure = publicProcedure.use(async ({ ctx, next }) => {
  if (ctx.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" });
  return next();
});
export const timedProcedure = publicProcedure.use(async ({ next, path }) => {
  const began = Date.now();
  const result = await next();
  console.log(path, Date.now() - began);
  return result;
});
'''
DB = 'import { PrismaClient } from "@prisma/client";\nexport const db = new PrismaClient();\n'
POST = '''import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { adminProcedure, createTRPCRouter, protectedProcedure, publicProcedure, timedProcedure } from "../trpc";

export const postRouter = createTRPCRouter({
  hello: publicProcedure.input(z.object({ text: z.string() })).query(({ input }) => {
    return { greeting: "Hello " + input.text };
  }),
  create: protectedProcedure.input(z.object({ name: z.string().min(1) })).mutation(async ({ ctx, input }) => {
    return ctx.db.post.create({ data: { name: input.name } });
  }),
  remove: publicProcedure.input(z.object({ id: z.string() })).mutation(async ({ ctx, input }) => {
    return ctx.db.post.delete({ where: { id: input.id } });
  }),
  rename: timedProcedure.input(z.object({ id: z.string(), name: z.string() })).mutation(async ({ ctx, input }) => {
    return ctx.db.post.update({ where: { id: input.id }, data: { name: input.name } });
  }),
  hide: adminProcedure.input(z.object({ id: z.string() })).mutation(async ({ ctx, input }) => {
    return ctx.db.post.update({ where: { id: input.id }, data: { hidden: true } });
  }),
  mine: publicProcedure.mutation(async ({ ctx }) => {
    if (!ctx.session) throw new TRPCError({ code: "UNAUTHORIZED" });
    return ctx.db.post.deleteMany({ where: { owner: ctx.session.user.id } });
  }),
  feed: publicProcedure.subscription(() => listen()),
  admin: createTRPCRouter({
    purge: protectedProcedure.mutation(({ ctx }) => ctx.db.post.deleteMany({})),
  }),
});
'''
ROOT = '''import { createTRPCRouter, publicProcedure } from "./trpc";
import { postRouter } from "./routers/post";

export const appRouter = createTRPCRouter({
  post: postRouter,
  health: publicProcedure.query(() => "ok"),
});
export type AppRouter = typeof appRouter;
'''
HANDLER = '''import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { appRouter } from "../../../../server/api/root";
import { createTRPCContext } from "../../../../server/api/trpc";

const handler = (req: Request) =>
  fetchRequestHandler({ endpoint: "/api/trpc", req, router: appRouter, createContext: () => createTRPCContext(req) });
export { handler as GET, handler as POST };
'''
APP = {"server/db.ts": DB, "server/api/trpc.ts": TRPC, "server/api/routers/post.ts": POST, "server/api/root.ts": ROOT,
       "app/api/trpc/[trpc]/route.ts": HANDLER}
POST_ID = "js:server/api/routers/post::postRouter."


def _build(root, files, pkg=PKG):
    for rel, text in {"package.json": pkg, **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return build_graph(root)


def _procedures(g):
    return {n.id: n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry.get("trpc")}


def _edge(g, src, dst):
    return next((e for e in g.call_edges() if e.src == src and e.dst == dst), None)


# ------------------------------------------------------------------ procedures are routes
def test_each_procedure_is_a_route_named_by_its_path(tmp_path):
    """A query is sent with GET, a mutation with POST, to the mount and the procedure's path through the routers
    (also a router written inside another, and a procedure on the root)."""
    g = _build(tmp_path, APP)
    assert _procedures(g) == {
        POST_ID + "hello": "GET /api/trpc/post.hello",
        POST_ID + "create": "POST /api/trpc/post.create",
        POST_ID + "remove": "POST /api/trpc/post.remove",
        POST_ID + "rename": "POST /api/trpc/post.rename",
        POST_ID + "hide": "POST /api/trpc/post.hide",
        POST_ID + "mine": "POST /api/trpc/post.mine",
        POST_ID + "feed": "GET /api/trpc/post.feed",
        POST_ID + "admin.purge": "POST /api/trpc/post.admin.purge",
        "js:server/api/root::appRouter.health": "GET /api/trpc/health"}
    create = g.nodes[POST_ID + "create"]
    assert create.entry["kind"] == "route" and create.lane == "server"
    assert create.entry["trpc"] == {"path": "post.create", "type": "mutation", "procedures": ["protectedProcedure"],
                                    "mount": "/api/trpc"}
    assert (create.start_line, create.file) == (9, "server/api/routers/post.ts")
    # the function the procedure is built on runs before it: a function of its own, named in the route's list
    assert create.entry["middleware"] == ["js:server/api/trpc::protectedProcedure.use"]
    assert g.nodes["js:server/api/trpc::protectedProcedure.use"].start_line == 10
    assert "middleware" not in g.nodes[POST_ID + "remove"].entry
    assert g.meta["trpc"] == {"procedures": 9, "routers": 3, "client_calls": 0, "linked": 0}


def test_the_twins_that_are_no_procedures(tmp_path):
    """The same files where nothing depends on tRPC; an object handed to another function; Express's `Router({…})`
    in a project that has tRPC; a test file."""
    assert _procedures(_build(tmp_path / "plain", APP, NO_TRPC)) == {}
    other = {"lib/jobs.ts": ('import { defineJobs, job } from "some-queue";\n'
                             'export const jobs = defineJobs({ nightly: job.query(() => 1) });\n'),
             "lib/web.ts": ('import express from "express";\n'
                            'export const web = express.Router({ mergeParams: true });\n'
                            'export const other = makeRouter({ find: helper.query(() => 2) });\n'),
             "server/api/routers/post.test.ts": POST.replace("../trpc", "../trpc")}
    g = _build(tmp_path / "other", {**APP, **other})
    assert len(_procedures(g)) == 9
    assert not [i for i in _procedures(g) if i.startswith(("js:lib/", "js:server/api/routers/post.test"))]


def test_the_mount_says_where_the_procedures_are_served(tmp_path):
    """`endpoint: "/api/trpc"`; a Next.js route file with no endpoint written; Express's `app.use("/trpc", …)`; and
    with none of them the path as far as the code says it."""
    pages = dict(APP)
    del pages["app/api/trpc/[trpc]/route.ts"]
    pages["pages/api/rpc/[trpc].ts"] = ('import { createNextApiHandler } from "@trpc/server/adapters/next";\n'
                                        'import { appRouter } from "../../../server/api/root";\n'
                                        'export default createNextApiHandler({ router: appRouter });\n')
    assert _procedures(_build(tmp_path / "pages", pages))[POST_ID + "hello"] == "GET /api/rpc/post.hello"
    served = dict(APP)
    del served["app/api/trpc/[trpc]/route.ts"]
    served["server/main.ts"] = ('import express from "express";\n'
                                'import { createExpressMiddleware } from "@trpc/server/adapters/express";\n'
                                'import { appRouter } from "./api/root";\n'
                                'const app = express();\n'
                                'app.use("/trpc", createExpressMiddleware({ router: appRouter }));\n'
                                'app.listen(3000);\n')
    assert _procedures(_build(tmp_path / "express", served))[POST_ID + "create"] == "POST /trpc/post.create"
    bare = dict(APP)
    del bare["app/api/trpc/[trpc]/route.ts"]
    g = _build(tmp_path / "bare", bare)
    assert _procedures(g)[POST_ID + "create"] == "POST /post.create"
    assert g.nodes[POST_ID + "create"].entry["trpc"]["mount"] is None


def test_routers_put_together(tmp_path):
    """`mergeRouters(a, b)`, a router spread into another, a router under a default export and one imported under
    another name; a router nobody puts anywhere is a root of its own."""
    files = {
        "server/db.ts": DB, "server/api/trpc.ts": TRPC,
        "server/api/a.ts": ('import { createTRPCRouter, publicProcedure } from "./trpc";\n'
                            'export const aRouter = createTRPCRouter({ one: publicProcedure.query(() => 1) });\n'),
        "server/api/b.ts": ('import { createTRPCRouter, publicProcedure } from "./trpc";\n'
                            'export default createTRPCRouter({ two: publicProcedure.query(() => 2) });\n'),
        "server/api/c.ts": ('import { createTRPCRouter, publicProcedure } from "./trpc";\n'
                            'const shared = createTRPCRouter({ three: publicProcedure.query(() => 3) });\n'
                            'export const cRouter = createTRPCRouter({ ...shared, four: publicProcedure.query(() => 4) });\n'
                            'export const lonely = createTRPCRouter({ five: publicProcedure.query(() => 5) });\n'),
        "server/api/root.ts": ('import { createTRPCRouter, mergeRouters } from "./trpc";\n'
                               'import { aRouter } from "./a";\nimport second from "./b";\n'
                               'import { cRouter as third } from "./c";\n'
                               'const nested = createTRPCRouter({ b: second, c: third });\n'
                               'export const appRouter = mergeRouters(aRouter, nested);\n')}
    assert sorted(_procedures(_build(tmp_path, files)).values()) == [
        "GET /b.two", "GET /c.four", "GET /c.three", "GET /five", "GET /one"]


# ------------------------------------------------------------------ who may call a procedure
CLIENT = '''import { createTRPCReact } from "@trpc/react-query";
import type { AppRouter } from "../server/api/root";
export const api = createTRPCReact<AppRouter>();
'''
BUTTONS = '''"use client";
import { api } from "../trpc/react";

export function Buttons({ id }: { id: string }) {
  const create = api.post.create.useMutation();
  const remove = api.post.remove.useMutation();
  const rename = api.post.rename.useMutation();
  const hide = api.post.hide.useMutation();
  const mine = api.post.mine.useMutation();
  const purge = api.post.admin.purge.useMutation();
  const hello = api.post.hello.useQuery({ text: id });
  const gone = api.post.missing.useQuery();
  return (
    <p>
      <button onClick={() => create.mutate({ name: id })}>New</button>
      <button onClick={() => remove.mutate({ id })}>Remove</button>
      <button onClick={() => rename.mutate({ id, name: "x" })}>Rename</button>
      <button onClick={() => hide.mutate({ id })}>Hide</button>
      <button onClick={() => mine.mutate()}>Clear</button>
      <button onClick={() => purge.mutate()}>Purge</button>
      {hello.data?.greeting}{gone.data}
    </p>
  );
}
'''
PAGE = 'import { Buttons } from "../components/Buttons";\nexport default function Page() {\n  return <Buttons id="1" />;\n}\n'
WITH_PAGE = {**APP, "trpc/react.tsx": CLIENT, "components/Buttons.tsx": BUTTONS, "app/page.tsx": PAGE}


def test_a_page_that_calls_a_procedure_is_linked_to_it(tmp_path):
    """`api.post.create.useMutation()` on a client made by tRPC's own function is a confirmed link to the procedure,
    as a request to its address; a name that is no procedure is none."""
    g = _build(tmp_path, WITH_PAGE)
    for name, said in (("create", "POST /api/trpc/post.create"), ("hello", "GET /api/trpc/post.hello"),
                       ("admin.purge", "POST /api/trpc/post.admin.purge")):
        e = _edge(g, "js:components/Buttons::Buttons", POST_ID + name)
        assert e is not None and (e.confidence, e.via, e.detail) == ("resolved", "http-trpc", said), name
    assert g.meta["trpc"]["client_calls"] == 8 and g.meta["trpc"]["linked"] == 7
    site = next(s for s in g.sites if s["callee"] == "api.post.missing.useQuery")
    assert site["outcome"] != "resolved" and not [e for e in g.call_edges() if "missing" in e.dst]


def test_other_ways_to_call_and_things_that_only_look_like_it(tmp_path):
    """The plain client (`client.post.hello.query()`), and the newer hooks (`useQuery(trpc.post.hello.queryOptions())`)
    where the client comes out of a hook Lantern does not follow: likely. The twins: the same path on an object of
    the project's own, and `mutate` on a name Lantern cannot place."""
    files = {**APP, "lib/client.ts": (
        'import { createTRPCClient, httpBatchLink } from "@trpc/client";\n'
        'import type { AppRouter } from "../server/api/root";\n'
        'export const client = createTRPCClient<AppRouter>({ links: [httpBatchLink({ url: "/api/trpc" })] });\n'),
        "lib/load.ts": ('import { client } from "./client";\n'
                        'export async function load(text: string) {\n  return client.post.hello.query({ text });\n}\n'
                        'const store = { post: { create: { mutate() { return 1; } } } };\n'
                        'export function own() {\n  return store.post.create.mutate();\n}\n'
                        'export function unknown(thing: any) {\n  return thing.post.create.mutate();\n}\n'),
        "components/New.tsx": ('"use client";\nimport { useMutation, useQuery } from "@tanstack/react-query";\n'
                               'import { useTRPC } from "../trpc/hooks";\n'
                               'export function New() {\n  const trpc = useTRPC();\n'
                               '  const hello = useQuery(trpc.post.hello.queryOptions({ text: "x" }));\n'
                               '  const create = useMutation(trpc.post.create.mutationOptions());\n'
                               '  return <button onClick={() => create.mutate({ name: "n" })}>{hello.data?.greeting}</button>;\n}\n'),
        "trpc/hooks.ts": ('import { createTRPCContext } from "@trpc/tanstack-react-query";\n'
                          'import type { AppRouter } from "../server/api/root";\n'
                          'export const { useTRPC, TRPCProvider } = createTRPCContext<AppRouter>();\n')}
    g = _build(tmp_path, files)
    e = _edge(g, "js:lib/load::load", POST_ID + "hello")
    assert e is not None and (e.confidence, e.via) == ("resolved", "http-trpc")
    for name in ("hello", "create"):
        e = _edge(g, "js:components/New::New", POST_ID + name)
        assert e is not None and (e.confidence, e.via) == ("inferred", "http-trpc"), name
    assert _edge(g, "js:lib/load::own", POST_ID + "create") is None
    assert _edge(g, "js:lib/load::unknown", POST_ID + "create") is None


def test_the_login_check_reads_the_procedure_a_route_is_built_on(tmp_path):
    """Asked: the procedures the app calls that change data. `protectedProcedure` is a check by its name;
    `adminProcedure` by what its function does (it turns a caller away with FORBIDDEN); `mine` by its own lines.
    `remove` is built on the open procedure and `rename` on one that only measures time: both are found."""
    from lantern import websec
    g = _build(tmp_path, WITH_PAGE)
    assert sorted(f["title"] for f in websec.missing_auth(g)) == [
        "POST /api/trpc/post.remove changes data, is called by the app, and no login check was found",
        "POST /api/trpc/post.rename changes data, is called by the app, and no login check was found"]
    adj = websec.call_adjacency(g)
    signs = {}
    for name in ("create", "hide", "mine", "remove", "rename", "admin.purge"):
        n = g.nodes[POST_ID + name]
        text = (tmp_path / n.file).read_text(encoding="utf-8")
        got = websec.login_check(g, n, adj, text)
        signs[name] = got and (got[0], got[1])
    assert signs["create"] == ("strong", "the procedure `protectedProcedure` it is built on")
    assert signs["admin.purge"] == ("strong", "the procedure `protectedProcedure` it is built on")
    assert signs["hide"] == ("strong", "`adminProcedure` turns a caller away (TRPCError FORBIDDEN, server/api/trpc.ts:18)")
    assert signs["mine"] == ("strong", "it turns a caller away itself (TRPCError UNAUTHORIZED, line 24)")
    assert signs["remove"] is None and signs["rename"] is None


def test_the_readiness_page_counts_procedures_that_change_data(tmp_path):
    from lantern.protections import advise
    from lantern.security import scan
    g = _build(tmp_path, WITH_PAGE)
    prot = {p["id"]: p for p in advise(g, scan(g))}
    assert prot["route-auth"]["status"] == "add"
    assert sorted(x.split(" (")[0] for x in prot["route-auth"]["evidence"]) == [
        "POST /api/trpc/post.remove", "POST /api/trpc/post.rename"]


# ------------------------------------------------------------------ what the caller sends
SENT = '''import { z } from "zod";
import { exec } from "child_process";
import { Pool } from "pg";
import { createTRPCRouter, protectedProcedure, publicProcedure } from "./trpc";
const pool = new Pool();

export const appRouter = createTRPCRouter({
  find: publicProcedure.input(z.object({ name: z.string() })).query(async ({ input }) => {
    return pool.query("select * from notes where name = '" + input.name + "'");
  }),
  backup: protectedProcedure.input(z.string()).mutation(async (opts) => {
    exec("tar czf /backups/" + opts.input + ".tgz /data");
  }),
  mine: protectedProcedure.query(async ({ ctx }) => {
    return pool.query("select * from notes where owner = '" + ctx.session.user.id + "'");
  }),
  page: publicProcedure.input(z.object({ name: z.string() })).query(async ({ input }) => {
    return pool.query("select * from notes where name = $1", [input.name]);
  }),
});
'''


def test_what_the_caller_sends_is_followed_and_what_the_server_made_is_not(tmp_path):
    """`input` arrives with the request, also where the handler takes its one argument whole (`opts.input`). `ctx` is
    made by the server; a query with a placeholder is safe."""
    from lantern import flow
    g = _build(tmp_path, {"server/db.ts": DB, "server/api/trpc.ts": TRPC, "server/api/root.ts": SENT})
    res = flow.analyze(g)
    assert not res.errors, res.errors
    assert sorted((f["class"], f["line"]) for f in res.flows) == [("shell", 12), ("sql", 9)]
    plain = flow.analyze(_build(tmp_path / "plain", {"server/db.ts": DB, "server/api/trpc.ts": TRPC,
                                                      "server/api/root.ts": SENT}, NO_TRPC))
    assert plain.flows == []
