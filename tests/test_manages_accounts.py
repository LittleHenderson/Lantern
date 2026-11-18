"""A call into the management side of a sign-in service is no check of who is calling (roadmap of 2026-11-14, stage 5).

A sign-in service has two sides. One asks who sent this request (`supabase.auth.getUser()`, Clerk's `auth()`,
Firebase's `verifyIdToken`). The other makes, changes and removes accounts with the server's own key, for whichever
account it is handed (`supabase.auth.admin.deleteUser(id)`, `clerkClient.users.updateUserMetadata(id, …)`,
`getAuth().setCustomUserClaims(uid, …)`). Until this change the login check read both as "a login is there",
because both are calls into a library named for signing in: a route that removes whatever account the request
names, with nobody asked anything, was not listed.

Each open route stands beside the same route with the caller asked first, which must stay unlisted. Each is called
by a page of the project, because the rule that lists a route with no login asks the routes the project's own pages
call. Small made-up projects; none of these files comes from an app of a benchmark.
"""
import pytest

from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-AUTH-MISSING"
PKG = ('{"name": "desk", "dependencies": {"next": "15.0.0", "react": "19.0.0", "@supabase/supabase-js": "2.45.0", '
       '"@supabase/ssr": "0.5.0", "@clerk/nextjs": "6.0.0", "firebase-admin": "12.0.0"}}\n')
NEXT = {
    "package.json": PKG,
    "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n',
    "lib/admin.ts": ('import { createClient } from "@supabase/supabase-js";\n\n'
                     "export const supabase = createClient(process.env.SUPABASE_URL!, "
                     "process.env.SUPABASE_SERVICE_ROLE_KEY!);\n"),
    "lib/mine.ts": ('import { createServerClient } from "@supabase/ssr";\nimport { cookies } from "next/headers";\n\n'
                    "export function mine() {\n"
                    "  return createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, "
                    "{ cookies: cookies() });\n}\n\n"
                    "export async function whoIsCalling() {\n  const { data } = await mine().auth.getUser();\n"
                    "  return data.user;\n}\n"),
    "lib/accounts.ts": ('import { supabase } from "@/lib/admin";\n\n'
                        "export async function removeAccount(id: string) {\n"
                        "  await supabase.auth.admin.deleteUser(id);\n}\n"),
}
HEAD = ('import { NextResponse } from "next/server";\nimport { auth, clerkClient } from "@clerk/nextjs/server";\n'
        'import admin from "firebase-admin";\nimport { getAuth } from "firebase-admin/auth";\n'
        'import { supabase } from "@/lib/admin";\nimport { mine, whoIsCalling } from "@/lib/mine";\n'
        'import { removeAccount } from "@/lib/accounts";\n\n')
NO = 'return NextResponse.json({ error: "sign in" }, { status: 401 });'
DONE = "  return NextResponse.json({ ok: true });\n"


def _post(body):
    return HEAD + "export async function POST(req: Request) {\n" + body + DONE + "}\n"


# each: the route's file, its text, and whether it must be listed as a route with no login
ROUTES = {
    # --- Supabase: the admin side, made with the service key
    "Supabase: the account the request names is removed": (
        "app/api/accounts/remove/route.ts",
        _post("  const { id } = await req.json();\n  await supabase.auth.admin.deleteUser(id);\n"), True),
    "Supabase: the same, with the caller asked first": (
        "app/api/accounts/remove-mine/route.ts",
        _post("  const { data } = await mine().auth.getUser();\n"
              f"  if (!data.user) {{\n    {NO}\n  }}\n  await supabase.auth.admin.deleteUser(data.user.id);\n"), False),
    "Supabase: the admin call is in a helper of the project": (
        "app/api/accounts/remove-far/route.ts",
        _post("  const { id } = await req.json();\n  await removeAccount(id);\n"), True),
    "Supabase: the helper, with the caller asked first by another helper": (
        "app/api/accounts/remove-far-mine/route.ts",
        _post(f"  const user = await whoIsCalling();\n  if (!user) {{\n    {NO}\n  }}\n  await removeAccount(user.id);\n"),
        False),
    "Supabase: the caller's own account changed through the caller's own session": (
        "app/api/accounts/rename/route.ts",
        _post("  const { name } = await req.json();\n  const { error } = await mine().auth.updateUser({ data: { name } });\n"
              f"  if (error) {{\n    {NO}\n  }}\n"), False),
    # --- Clerk: the backend client
    "Clerk: the plan of the account the request names is changed": (
        "app/api/plans/set/route.ts",
        _post("  const { id, plan } = await req.json();\n"
              "  await clerkClient.users.updateUserMetadata(id, { publicMetadata: { plan } });\n"), True),
    "Clerk: the client made first, then an account removed": (
        "app/api/plans/drop/route.ts",
        _post("  const { id } = await req.json();\n  const client = await clerkClient();\n"
              "  await client.users.deleteUser(id);\n"), True),
    "Clerk: the same change, with the caller asked first": (
        "app/api/plans/set-mine/route.ts",
        _post(f"  const {{ userId }} = await auth();\n  if (!userId) {{\n    {NO}\n  }}\n"
              "  const { plan } = await req.json();\n"
              "  await clerkClient.users.updateUserMetadata(userId, { publicMetadata: { plan } });\n"), False),
    # --- Firebase's admin library
    "Firebase: the account the request names is made an admin": (
        "app/api/roles/grant/route.ts",
        _post("  const { uid } = await req.json();\n  await getAuth().setCustomUserClaims(uid, { admin: true });\n"), True),
    "Firebase: the older way of writing it": (
        "app/api/roles/drop/route.ts",
        _post("  const { uid } = await req.json();\n  await admin.auth().deleteUser(uid);\n"), True),
    "Firebase: the caller's token checked first": (
        "app/api/roles/grant-mine/route.ts",
        _post('  const token = (req.headers.get("authorization") ?? "").slice(7);\n'
              "  const who = await getAuth().verifyIdToken(token);\n"
              '  await getAuth().setCustomUserClaims(who.uid, { plan: "pro" });\n'), False),
}


def _page(rel):
    """A page of the project that calls the route written in `rel`."""
    path = "/" + rel.removeprefix("app/").removesuffix("/route.ts")
    return ('"use client";\n\nexport default function Page() {\n  async function go() {\n'
            f'    await fetch("{path}", {{ method: "POST", body: JSON.stringify({{ id: "1" }}) }});\n  }}\n'
            "  return <button onClick={go}>Go</button>;\n}\n")


def _scan(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    sec = scan(build_graph(root), offline=True)
    return [f for f in sec["findings"] if not f["in_tests"]]


@pytest.mark.parametrize("case", sorted(ROUTES))
def test_a_route_that_changes_an_account_and_whom_it_asked(tmp_path, case):
    rel, text, listed = ROUTES[case]
    fs = _scan(tmp_path, {**NEXT, rel: text, "app/page.tsx": _page(rel)})
    got = sorted(f["file"] for f in fs if f["rule"] == RULE)
    assert got == ([rel] if listed else []), [(f["rule"], f["file"], f["title"]) for f in fs]


FLASK = {
    "requirements.txt": "Flask==3.0.3\nfirebase-admin==6.5.0\nsupabase==2.7.0\n",
    "web/package.json": '{"name": "web", "dependencies": {"react": "19.0.0"}}\n',
    "web/src/api.js": ('export const remove = (id) => fetch("/accounts/remove", { method: "POST", '
                       "body: JSON.stringify({ id }) });\n"
                       'export const promote = (uid) => fetch("/accounts/promote", { method: "POST", '
                       "body: JSON.stringify({ uid }) });\n"
                       'export const promoteMine = () => fetch("/accounts/promote-mine", { method: "POST" });\n'),
    "app.py": '''import os

from firebase_admin import auth
from flask import Flask, jsonify, request
from supabase import create_client

app = Flask(__name__)
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE_KEY"])


@app.post("/accounts/remove")
def remove_account():
    supabase.auth.admin.delete_user(request.json["id"])
    return jsonify(removed=True)


@app.post("/accounts/promote")
def promote():
    auth.set_custom_user_claims(request.json["uid"], {"admin": True})
    return jsonify(ok=True)


@app.post("/accounts/promote-mine")
def promote_mine():
    who = auth.verify_id_token(request.headers.get("Authorization", "")[7:])
    auth.set_custom_user_claims(who["uid"], {"plan": "pro"})
    return jsonify(ok=True)
''',
}


def test_the_same_in_a_flask_app(tmp_path):
    fs = _scan(tmp_path, FLASK)
    assert sorted(f["title"].split(" ", 2)[1] for f in fs if f["rule"] == RULE) == [
        "/accounts/promote", "/accounts/remove"], [(f["rule"], f["title"]) for f in fs]
