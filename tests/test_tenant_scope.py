"""A record fetched by its number alone, where the data says the record has an owner (roadmap of 2026-11-14, stage 5).

The older check (`LT-AUTHZ-OWNER`, `tests/test_flow_authz.py`) follows who is signed in through the code. Here it is
given what the project's data model says (`lantern/datamodel.py`): which field of a record names its owner. Four
things follow, each beside twins that must stay as they were:

* who is signed in is known for more sign-in libraries (a route that asks for the owner is no longer listed);
* a query that asks for the record's owner field with a value the request did not choose is a scoped query, and so is
  an owner field compared after the read, also where Lantern does not know the sign-in helper;
* a finding says which field of the data names the owner, or the record it belongs to;
* a record with no owner anywhere in the data is said as that, and its read is ranked low.

Every finding here is a heuristic (`tool_confidence: LOW`). The files are made up for these tests; none is copied
from an app of a benchmark."""

import pytest

from lantern.engine import build_graph

SCHEMA = '''datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id       String    @id
  email    String
  orgId    String
  org      Org       @relation(fields: [orgId], references: [id])
  invoices Invoice[]
}

model Org {
  id       String    @id
  name     String
  invoices Invoice[]
  users    User[]
}

model Invoice {
  id       String    @id
  amount   Int
  status   String
  orgId    String
  org      Org       @relation(fields: [orgId], references: [id])
  userId   String
  user     User      @relation(fields: [userId], references: [id])
  notes    Note[]
}

model Note {
  id        String  @id
  text      String
  invoiceId String
  invoice   Invoice @relation(fields: [invoiceId], references: [id])
}

model Plan {
  id    String @id
  name  String
  price Int
}
'''

NEXT = {
    "package.json": '{"name": "books", "dependencies": {"next": "15.0.0", "react": "19.0.0", '
                    '"@prisma/client": "6.0.0", "next-auth": "5.0.0", "better-auth": "1.0.0", "lucia": "3.0.0", '
                    '"@auth0/nextjs-auth0": "4.0.0", "@kinde-oss/kinde-auth-nextjs": "2.0.0", '
                    '"@workos-inc/authkit-nextjs": "2.0.0", "@supabase/ssr": "0.6.0", "acme-auth": "1.0.0"}}\n',
    "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n',
    "prisma/schema.prisma": SCHEMA,
    "lib/db.ts": 'import { PrismaClient } from "@prisma/client";\nexport const prisma = new PrismaClient();\n',
}
HEAD = 'import { NextResponse } from "next/server";\nimport { prisma } from "@/lib/db";\n'
NO = 'return NextResponse.json({ error: "no" }, { status: 401 });'
FORBID = 'return NextResponse.json({ error: "no" }, { status: 403 });'
ARGS = "req: Request, { params }: { params: { id: string; orgId: string } }"


def _scan(root, files):
    from lantern.security import scan
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    sec = scan(build_graph(root), offline=True)
    flow = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert flow["state"] == "ok", flow
    return [f for f in sec["findings"] if not f["in_tests"]]


def _said(fs, rel=None):
    """(rule, the line it stands on) for what is said about who may reach what."""
    return sorted((f["rule"], f["snippet"]) for f in fs
                  if f["rule"].startswith(("LT-AUTHZ", "LW-AUTH")) and rel in (None, f["file"]))


# ------------------------------------------------------------------ who is signed in, for more sign-in libraries

def _three(head, ask, there, value, column="orgId"):
    """Three routes that ask who is signed in the same way: a query scoped by the owner, a read followed by a
    comparison of the owner, and a delete by the number alone."""
    return HEAD + head + f'''
export async function GET({ARGS}) {{
  {ask}
  if (!{there}) {NO}
  const invoice = await prisma.invoice.findFirst({{ where: {{ id: params.id, {column}: {value} }} }});
  return NextResponse.json({{ amount: invoice?.amount }});
}}

export async function PATCH({ARGS}) {{
  {ask}
  if (!{there}) {NO}
  const invoice = await prisma.invoice.findUnique({{ where: {{ id: params.id }} }});
  if (!invoice || invoice.{column} !== {value}) {FORBID}
  await prisma.invoice.update({{ where: {{ id: invoice.id }}, data: {{ amount: 0 }} }});
  return NextResponse.json({{ ok: true }});
}}

export async function DELETE({ARGS}) {{
  {ask}
  if (!{there}) {NO}
  await prisma.invoice.delete({{ where: {{ id: params.id }} }});
  return NextResponse.json({{ ok: true }});
}}
'''


AUTHJS = ('import NextAuth from "next-auth";\nimport GitHub from "next-auth/providers/github";\n\n'
          'export const { auth, handlers, signIn, signOut } = NextAuth({ providers: [GitHub] });\n')
LIBRARIES = {
    "Auth.js version 5, its helper taken out of what NextAuth() gives": (
        {"auth.ts": AUTHJS},
        'import { auth } from "@/auth";\n', "const session = await auth();",
        "session?.user", "session.user.orgId", "orgId"),
    "Auth.js version 5, its helper called on what NextAuth() gives": (
        {"auth.ts": 'import NextAuth from "next-auth";\nexport const nextAuth = NextAuth({ providers: [] });\n'},
        'import { nextAuth } from "@/auth";\n', "const session = await nextAuth.auth();",
        "session?.user", "session.user.orgId", "orgId"),
    "better-auth": (
        {"lib/auth.ts": 'import { betterAuth } from "better-auth";\n\n'
                        'export const auth = betterAuth({ emailAndPassword: { enabled: true } });\n'},
        'import { headers } from "next/headers";\nimport { auth } from "@/lib/auth";\n',
        "const session = await auth.api.getSession({ headers: await headers() });",
        "session", "session.user.id", "userId"),
    "Lucia, behind a function of the project": (
        {"lib/auth.ts": 'import { cookies } from "next/headers";\nimport { Lucia } from "lucia";\n'
                        'import { adapter } from "./adapter";\n\nexport const lucia = new Lucia(adapter);\n\n'
                        'export async function validateRequest() {\n'
                        '  const sessionId = (await cookies()).get(lucia.sessionCookieName)?.value ?? null;\n'
                        '  if (!sessionId) return { user: null, session: null };\n'
                        '  return await lucia.validateSession(sessionId);\n}\n',
         "lib/adapter.ts": "export const adapter = {} as any;\n"},
        'import { validateRequest } from "@/lib/auth";\n', "const { user } = await validateRequest();",
        "user", "user.id", "userId"),
    "Auth0 version 4": (
        {"lib/auth0.ts": 'import { Auth0Client } from "@auth0/nextjs-auth0/server";\n\n'
                         'export const auth0 = new Auth0Client();\n'},
        'import { auth0 } from "@/lib/auth0";\n', "const session = await auth0.getSession();",
        "session", "session.user.sub", "userId"),
    "Kinde": (
        {},
        'import { getKindeServerSession } from "@kinde-oss/kinde-auth-nextjs/server";\n',
        "const { getUser } = getKindeServerSession();\n  const user = await getUser();",
        "user", "user.id", "userId"),
    "WorkOS AuthKit": (
        {},
        'import { withAuth } from "@workos-inc/authkit-nextjs";\n', "const { user, organizationId } = await withAuth();",
        "user", "organizationId", "orgId"),
    "Supabase, the claims of the token": (
        {"lib/supabase.ts": 'import { createServerClient } from "@supabase/ssr";\n'
                            'import { cookies } from "next/headers";\n\nexport async function createClient() {\n'
                            '  const store = await cookies();\n'
                            '  return createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, {\n'
                            '    cookies: { getAll: () => store.getAll(), setAll: () => {} },\n  });\n}\n'},
        'import { createClient } from "@/lib/supabase";\n',
        "const supabase = await createClient();\n  const { data } = await supabase.auth.getClaims();\n"
        "  const claims = data?.claims;",
        "claims", "claims.sub", "userId"),
}


@pytest.mark.parametrize("library", sorted(LIBRARIES))
def test_who_is_signed_in_is_known_for_that_library(tmp_path, library):
    """The route that deletes by the number alone is named, as a record nobody asked the owner of; the two that ask
    for the owner are not, and no route is said to have no login."""
    more, head, ask, there, value, column = LIBRARIES[library]
    rel = "app/api/invoices/[id]/route.ts"
    fs = _scan(tmp_path, {**NEXT, **more, rel: _three(head, ask, there, value, column)})
    assert _said(fs) == [("LT-AUTHZ-OWNER", "await prisma.invoice.delete({ where: { id: params.id } });")]


def test_a_function_of_the_same_name_that_is_no_sign_in_library_is_not_taken_for_one(tmp_path):
    """`auth` out of something that is not NextAuth says nothing about who is signed in: the comparison with what it
    gave is no owner check by itself, and the delete by the number alone is still named."""
    files = {**NEXT, "auth.ts": 'import make from "acme-auth";\nexport const { auth } = make({ pages: 2 });\n',
             "app/api/invoices/[id]/route.ts": HEAD + 'import { auth } from "@/auth";\n' + f'''
export async function DELETE({ARGS}) {{
  const session = await auth();
  if (!session?.user) {NO}
  await prisma.invoice.delete({{ where: {{ id: params.id }} }});
  return NextResponse.json({{ ok: true }});
}}
'''}
    said = _said(_scan(tmp_path, files))
    assert [line for _rule, line in said] == ["await prisma.invoice.delete({ where: { id: params.id } });"] or \
        [rule for rule, _line in said] == ["LW-AUTH-MISSING"], said


# ------------------------------------------------------------------ the owner field in the query, or compared after

UNKNOWN = 'import { requireOrg, orgOf } from "acme-auth";\n'
ASK = "const ctx = await requireOrg();"


def _route(verb, body):
    return f'''
export async function {verb}({ARGS}) {{
  {ASK}
  if (!ctx.user) {NO}
{body}
}}
'''


def _file(*routes):
    return HEAD + UNKNOWN + "".join(routes)


SCOPED = {
    "the query asks for the org of whoever is signed in":
        "  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: ctx.orgId } });\n"
        "  return NextResponse.json({ amount: invoice?.amount });",
    "an update of the rows of that org only":
        "  await prisma.invoice.updateMany({ where: { id: params.id, orgId: ctx.orgId }, data: { amount: 0 } });\n"
        "  return NextResponse.json({ ok: true });",
    "the two conditions written as a list":
        "  await prisma.invoice.deleteMany({ where: { AND: [{ id: params.id }, { orgId: ctx.orgId }] } });\n"
        "  return NextResponse.json({ ok: true });",
    "the owner asked for through the record it leads to":
        "  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, org: { id: ctx.orgId } } });\n"
        "  return NextResponse.json({ amount: invoice?.amount });",
    "the owner field compared after the read, and the request turned away":
        "  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
        f"  if (!invoice || invoice.orgId !== ctx.orgId) {FORBID}\n"
        "  return NextResponse.json({ amount: invoice.amount });",
    "the same comparison the other way round, before the record is removed":
        "  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
        f"  if (!invoice) {FORBID}\n"
        f"  if (ctx.user.id != invoice.userId) {FORBID}\n"
        "  await prisma.invoice.delete({ where: { id: invoice.id } });\n"
        "  return NextResponse.json({ ok: true });",
}
OPEN = {
    "by the number alone":
        ("  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });"),
    "the org is the one the request names":
        ("  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: params.orgId } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: params.orgId } });"),
    "the org comes in a header of the request":
        ('  const org = req.headers.get("x-org-id");\n'
         "  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: org } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: org } });"),
    "the org was looked up by a library from what the request names":
        ("  const org = await orgOf(params.orgId);\n"
         "  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: org.id } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: org.id } });"),
    "a field that names no owner is asked for":
        ("  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, status: ctx.status } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { id: params.id, status: ctx.status } });"),
    "the owner field is only among the fields to bring back":
        ("  const invoice = await prisma.invoice.findFirst({ where: { id: params.id }, "
         "select: { orgId: true, amount: true } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { id: params.id }, "
         "select: { orgId: true, amount: true } });"),
    "the owner field is one of two ways in":
        ("  const invoice = await prisma.invoice.findFirst({ where: { OR: [{ id: params.id }, "
         "{ orgId: ctx.orgId }] } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { OR: [{ id: params.id }, "
         "{ orgId: ctx.orgId }] } });"),
    "the query asks for the records that are not that org's":
        ("  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, NOT: { orgId: ctx.orgId } } "
         "});\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { id: params.id, NOT: { orgId: ctx.orgId } } "
         "});"),
    "the owner field is given no value":
        ("  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: undefined } });\n"
         "  return NextResponse.json({ amount: invoice?.amount });",
         "const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: undefined } });"),
    "the owner field is given written text":
        ('  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: "org_1" } });\n'
         "  return NextResponse.json({ amount: invoice?.amount });",
         'const invoice = await prisma.invoice.findFirst({ where: { id: params.id, orgId: "org_1" } });'),
    "the owner field is among what is written onto the record":
        ("  await prisma.invoice.update({ where: { id: params.id }, data: { orgId: ctx.orgId } });\n"
         "  return NextResponse.json({ ok: true });",
         "await prisma.invoice.update({ where: { id: params.id }, data: { orgId: ctx.orgId } });"),
    "the owner field is compared with what the request names":
        ("  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
         f"  if (!invoice || invoice.orgId !== params.orgId) {FORBID}\n"
         "  return NextResponse.json({ amount: invoice.amount });",
         "const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });"),
    "a field that names no owner is compared":
        ("  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
         f"  if (!invoice || invoice.status !== ctx.status) {FORBID}\n"
         "  return NextResponse.json({ amount: invoice.amount });",
         "const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });"),
    "the owner field is compared and nothing is decided on it":
        ("  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
         "  const mine = invoice?.orgId === ctx.orgId;\n"
         "  return NextResponse.json({ amount: invoice?.amount, mine });",
         "const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });"),
}


@pytest.mark.parametrize("case", sorted(SCOPED))
def test_a_route_that_asks_for_the_owner_field_is_not_listed(tmp_path, case):
    """The sign-in helper is one Lantern knows nothing of. The data model says `orgId` and `userId` name an
    invoice's owner, and the route asks for one of them with a value the request did not choose."""
    verb = "DELETE" if ".delete" in SCOPED[case] else "PATCH" if "update" in SCOPED[case] else "GET"
    fs = _scan(tmp_path, {**NEXT, "app/api/orgs/[orgId]/invoices/[id]/route.ts": _file(_route(verb, SCOPED[case]))})
    assert _said(fs) == []


@pytest.mark.parametrize("case", sorted(OPEN))
def test_a_route_that_only_looks_as_if_it_asked_is_listed(tmp_path, case):
    body, line = OPEN[case]
    fs = _scan(tmp_path, {**NEXT, "app/api/orgs/[orgId]/invoices/[id]/route.ts": _file(_route("GET", body))})
    assert _said(fs) == [("LT-AUTHZ-OWNER", line)]


def test_with_no_data_model_nothing_is_read_into_a_field_name(tmp_path):
    """The same scoped query in a project whose data model Lantern cannot read: the field's name alone decides
    nothing, and the older reading stands."""
    files = {k: v for k, v in NEXT.items() if k != "prisma/schema.prisma"}
    files["app/api/orgs/[orgId]/invoices/[id]/route.ts"] = _file(_route(
        "GET", SCOPED["the query asks for the org of whoever is signed in"]))
    assert [rule for rule, _line in _said(_scan(tmp_path, files))] == ["LT-AUTHZ-OWNER"]


DJANGO = {
    "requirements.txt": "Django==5.1\nacme-tenancy==1.0\n",
    "manage.py": "import sys\n",
    "books/__init__.py": "",
    "books/models.py": '''from django.db import models


class Org(models.Model):
    name = models.CharField(max_length=80)


class Invoice(models.Model):
    org = models.ForeignKey(Org, on_delete=models.CASCADE)
    amount = models.IntegerField()
    status = models.CharField(max_length=20)


class Plan(models.Model):
    name = models.CharField(max_length=80)
''',
    "books/urls.py": '''from django.urls import path

from . import views

urlpatterns = [
    path("scoped/<int:pk>/", views.scoped),
    path("compared/<int:pk>/", views.compared),
    path("named/<int:pk>/", views.named),
    path("alone/<int:pk>/", views.alone),
    path("plan/<int:pk>/", views.plan),
]
''',
    "books/views.py": '''from acme_tenancy import current_org
from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse

from .models import Invoice, Plan


@login_required
def scoped(request, pk):
    inv = Invoice.objects.get(pk=pk, org=current_org())
    return JsonResponse({"amount": inv.amount})


@login_required
def compared(request, pk):
    inv = Invoice.objects.get(pk=pk)
    if inv.org_id != current_org().id:
        raise Http404()
    return JsonResponse({"amount": inv.amount})


@login_required
def named(request, pk):
    inv = Invoice.objects.get(pk=pk, org_id=request.GET["org"])
    return JsonResponse({"amount": inv.amount})


@login_required
def alone(request, pk):
    inv = Invoice.objects.get(pk=pk)
    return JsonResponse({"amount": inv.amount})


@login_required
def plan(request, pk):
    return JsonResponse({"name": Plan.objects.get(pk=pk).name})
''',
}


def test_the_same_in_a_django_project(tmp_path):
    fs = _scan(tmp_path, DJANGO)
    assert _said(fs) == [("LT-AUTHZ-OWNER", 'inv = Invoice.objects.get(pk=pk)'),
                         ("LT-AUTHZ-OWNER", 'inv = Invoice.objects.get(pk=pk, org_id=request.GET["org"])'),
                         ("LT-AUTHZ-OWNER", 'return JsonResponse({"name": Plan.objects.get(pk=pk).name})')]
    by = {f["snippet"]: f for f in fs if f["rule"] == "LT-AUTHZ-OWNER"}
    alone = by["inv = Invoice.objects.get(pk=pk)"]
    assert alone["owned"] == {"model": "Invoice", "kind": "django", "file": "books/models.py", "line": 8,
                              "fields": ["org"]}
    assert alone["rank"] == "medium" and "`org`" in alone["more_info"]
    plan = by['return JsonResponse({"name": Plan.objects.get(pk=pk).name})']
    assert plan["owned"] == {"model": "Plan", "kind": "django", "file": "books/models.py", "line": 14, "fields": []}
    assert plan["rank"] == "low" and "books/models.py:14" in plan["rank_basis"][-1]["why"]


# ------------------------------------------------------------------ what the finding says of the data

def _one(tmp_path, body, verb="GET", schema=SCHEMA):
    files = {**NEXT, "prisma/schema.prisma": schema,
             "app/api/orgs/[orgId]/invoices/[id]/route.ts": _file(_route(verb, body))}
    fs = [f for f in _scan(tmp_path, files) if f["rule"] == "LT-AUTHZ-OWNER"]
    assert len(fs) == 1, _said(fs)
    return fs[0]


def _line_of(schema, text):
    return schema.split("\n").index(text) + 1


def test_a_finding_names_the_field_that_says_whose_the_record_is(tmp_path):
    f = _one(tmp_path, "  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
                       "  return NextResponse.json({ amount: invoice?.amount });")
    assert f["owned"] == {"model": "Invoice", "kind": "prisma", "file": "prisma/schema.prisma",
                          "line": _line_of(SCHEMA, "model Invoice {"), "fields": ["orgId", "userId"]}
    assert f["rank"] == "medium" and f["tool_confidence"] == "LOW"
    assert "`orgId`" in f["more_info"] and "prisma/schema.prisma" in f["more_info"]


def test_the_case_for_the_finding_names_the_place_in_the_model_file(tmp_path):
    """An engineer who checks the finding is told where the data model says it: a fact of the case, with its place."""
    f = _one(tmp_path / "owned", "  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
                                 "  return NextResponse.json({ amount: invoice?.amount });")
    line = _line_of(SCHEMA, "model Invoice {")
    facts = [e["fact"] for e in f["case"]["evidence"] if e["from"] == "data model"]
    assert facts == [f"The project's data model names the owner of `Invoice` in `orgId`, `userId` "
                     f"(prisma/schema.prisma:{line})"]
    plan = _one(tmp_path / "nobodys", "  const plan = await prisma.plan.findUnique({ where: { id: params.id } });\n"
                                      "  return NextResponse.json({ name: plan?.name });")
    line = _line_of(SCHEMA, "model Plan {")
    assert [e["fact"] for e in plan["case"]["evidence"] if e["from"] == "data model"] == [
        f"The project's data model names no owner for `Plan`, and nothing it belongs to has one "
        f"(prisma/schema.prisma:{line})"]
    # ... and a finding with no model named on its line has no such fact
    none = _one(tmp_path / "none", "  const table = (prisma as any)[ctx.kind];\n"
                                   "  const row = await table.findUnique({ where: { id: params.id } });\n"
                                   "  return NextResponse.json({ row });")
    assert [e for e in none["case"]["evidence"] if e["from"] == "data model"] == []


def test_a_record_that_belongs_to_one_with_an_owner_is_said_through_it(tmp_path):
    f = _one(tmp_path, "  const note = await prisma.note.findUnique({ where: { id: params.id } });\n"
                       "  return NextResponse.json({ text: note?.text });")
    assert f["owned"] == {"model": "Note", "kind": "prisma", "file": "prisma/schema.prisma",
                          "line": _line_of(SCHEMA, "model Note {"), "fields": [], "through": "Invoice"}
    assert f["rank"] == "medium" and "Invoice" in f["more_info"]


def test_the_record_of_a_person_is_somebodys_own(tmp_path):
    """A user has no field that names an owner: it is the owner. Reading another person's stays what it was."""
    f = _one(tmp_path / "user", "  const user = await prisma.user.findUnique({ where: { id: params.id } });\n"
                                "  return NextResponse.json({ email: user?.email });")
    assert f["rank"] == "medium" and f["owned"]["model"] == "User" and "through" not in f["owned"]
    assert f["owned"]["fields"] == ["orgId"]
    org = _one(tmp_path / "org", "  const org = await prisma.org.findUnique({ where: { id: params.id } });\n"
                                 "  return NextResponse.json({ name: org?.name });")
    assert org["rank"] == "medium" and org["owned"] == {
        "model": "Org", "kind": "prisma", "file": "prisma/schema.prisma", "line": _line_of(SCHEMA, "model Org {"),
        "fields": [], "itself": True}


def test_a_record_with_no_owner_anywhere_in_the_data_is_said_as_that(tmp_path):
    read = "  const plan = await prisma.plan.findUnique({ where: { id: params.id } });\n" \
           "  return NextResponse.json({ name: plan?.name });"
    f = _one(tmp_path / "read", read)
    line = _line_of(SCHEMA, "model Plan {")
    assert f["owned"] == {"model": "Plan", "kind": "prisma", "file": "prisma/schema.prisma", "line": line,
                          "fields": []}
    assert f["rank"] == "low" and f["rank_basis"][-1]["step"] == "fixed"
    assert f"prisma/schema.prisma:{line}" in f["rank_basis"][-1]["why"]
    # ... but who may remove one is still a question, and the rank stays
    gone = _one(tmp_path / "gone", "  await prisma.plan.delete({ where: { id: params.id } });\n"
                                   "  return NextResponse.json({ ok: true });", "DELETE")
    assert gone["rank"] == "medium" and gone["owned"]["fields"] == []
    # ... and the same read once the data says whose a plan is
    owned = SCHEMA.replace("model Plan {\n  id    String @id\n", "model Plan {\n  id    String @id\n  teamId String\n")
    assert owned != SCHEMA
    mine = _one(tmp_path / "owned", read, schema=owned)
    assert mine["rank"] == "medium" and mine["owned"]["fields"] == ["teamId"]


CATALOG = """
model Category {
  id   String @id
  name String
}

model Product {
  id         String @id
  name       String
  categoryId String
}
"""
# each: (the models added to the schema, the model read by its number, what `owned` must say beside `fields: []`)
NOT_NOBODYS = {
    "a link to a record the project has no model for": (
        "\nmodel Order {\n  id         String @id\n  total      Int\n  customerId String\n}\n",
        "order", {"maybe": ["customerId"]}),
    "something of one person": (
        "\nmodel Subscriber {\n  id    String @id\n  email String\n}\n", "subscriber", {"maybe": ["email"]}),
    "a secret": (
        "\nmodel Device {\n  id        String @id\n  pushToken String\n}\n", "device", {"maybe": ["pushToken"]}),
    "a number another service gave": (
        "\nmodel Price {\n  id            String @id\n  name          String\n  stripePriceId String\n}\n",
        "price", {"maybe": ["stripePriceId"]}),
    "a link by its name alone to a record of one person": (
        "\nmodel Order {\n  id         String @id\n  customerId String\n}\n"
        "\nmodel Customer {\n  id    String @id\n  phone String\n}\n", "order", {"through": "Customer"}),
    "a link by its name alone to a record that has an owner": (
        "\nmodel Line {\n  id        String @id\n  invoiceId String\n}\n", "line", {"through": "Invoice"}),
}


@pytest.mark.parametrize("case", sorted(NOT_NOBODYS))
def test_a_record_that_may_be_somebodys_keeps_its_rank(tmp_path, case):
    """The lower rank is given on the safe side only: a record with any field that could say whose it is, under
    whatever name, is not said to be nobody's."""
    more, model, says = NOT_NOBODYS[case]
    f = _one(tmp_path, f"  const row = await prisma.{model}.findUnique({{ where: {{ id: params.id }} }});\n"
                       "  return NextResponse.json({ row });", schema=SCHEMA + more)
    assert f["rank"] == "medium" and f["rank_basis"][-1]["why"].startswith("Lantern gives this rule")
    assert {k: v for k, v in f["owned"].items() if k not in ("model", "kind", "file", "line")} == {"fields": [], **says}
    for name in says.get("maybe", [says.get("through")]):
        assert f"`{name}`" in f["more_info"]


def test_a_record_that_only_belongs_to_one_that_is_nobodys_is_nobodys_too(tmp_path):
    f = _one(tmp_path, "  const row = await prisma.product.findUnique({ where: { id: params.id } });\n"
                       "  return NextResponse.json({ row });", schema=SCHEMA + CATALOG)
    assert f["owned"]["model"] == "Product" and f["owned"]["fields"] == [] and len(f["owned"]) == 5
    assert f["rank"] == "low"
    # ... and what the finding tells a person asks for no owner
    assert "names no owner for `Product`" in f["more_info"]
    assert "the place to ask for the owner" not in f["more_info"]


def test_a_record_whose_model_lantern_cannot_tell_is_left_as_it_was(tmp_path):
    f = _one(tmp_path, "  const table = (prisma as any)[ctx.kind];\n"
                       "  const row = await table.findUnique({ where: { id: params.id } });\n"
                       "  return NextResponse.json({ row });")
    assert "owned" not in f and f["rank"] == "medium"


FASTAPI = {
    "requirements.txt": "fastapi==0.115.0\nsqlmodel==0.0.22\n",
    "app/__init__.py": "",
    "app/models.py": '''from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str


class Item(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    owner_id: int = Field(foreign_key="user.id")


class Tag(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
''',
    "app/deps.py": '''from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, create_engine

from .models import User

engine = create_engine("sqlite:///app.db")
oauth2 = OAuth2PasswordBearer(tokenUrl="/login")


def get_session():
    with Session(engine) as session:
        yield session


def get_current_user(token: str = Depends(oauth2), session=Depends(get_session)) -> User:
    user = session.get(User, int(token))
    if user is None:
        raise HTTPException(status_code=401)
    return user
''',
    "app/main.py": '''from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import select

from .deps import get_current_user, get_session
from .models import Item, Tag, User

app = FastAPI()


@app.get("/items/{item_id}")
def read_item(item_id: int, session=Depends(get_session), user: User = Depends(get_current_user)):
    item = session.get(Item, item_id)
    return {"title": item.title}


@app.get("/mine/{item_id}")
def read_mine(item_id: int, session=Depends(get_session), user: User = Depends(get_current_user)):
    item = session.get(Item, item_id)
    if item is None or item.owner_id != user.id:
        raise HTTPException(status_code=404)
    return {"title": item.title}


@app.get("/tags/{tag_id}")
def read_tag(tag_id: int, session=Depends(get_session), user: User = Depends(get_current_user)):
    tag = session.exec(select(Tag).where(Tag.id == tag_id)).first()
    return {"name": tag.name}
''',
}


def test_a_query_over_two_records_one_of_which_has_an_owner_keeps_its_rank(tmp_path):
    """The statement names a tag (nobody's) and an item (somebody's): the owner is asked for where there is one."""
    main = FASTAPI["app/main.py"].replace("select(Tag).where(Tag.id == tag_id)",
                                          "select(Tag).join(Item).where(Tag.id == tag_id)")
    assert main != FASTAPI["app/main.py"]
    fs = _scan(tmp_path, {**FASTAPI, "app/main.py": main})
    tag = [f for f in fs if f["rule"] == "LT-AUTHZ-OWNER" and "select(Tag)" in f["snippet"]]
    assert len(tag) == 1, _said(fs)
    assert tag[0]["owned"]["model"] == "Item" and tag[0]["owned"]["fields"] == ["owner_id"]
    assert tag[0]["rank"] == "medium"
    # ... and the same joined query once it asks whose the item is
    mine = main.replace(".where(Tag.id == tag_id)", ".where(Tag.id == tag_id, Item.owner_id == user.id)")
    assert mine != main
    fs = _scan(tmp_path / "mine", {**FASTAPI, "app/main.py": mine})
    assert [s for _rule, s in _said(fs) if "select(Tag)" in s] == []


def test_the_same_in_a_fastapi_project(tmp_path):
    fs = _scan(tmp_path, FASTAPI)
    assert _said(fs) == [("LT-AUTHZ-OWNER", "item = session.get(Item, item_id)"),
                         ("LT-AUTHZ-OWNER", "tag = session.exec(select(Tag).where(Tag.id == tag_id)).first()")]
    by = {f["snippet"]: f for f in fs if f["rule"] == "LT-AUTHZ-OWNER"}
    item = by["item = session.get(Item, item_id)"]
    assert item["owned"] == {"model": "Item", "kind": "sqlmodel", "file": "app/models.py", "line": 9,
                             "fields": ["owner_id"]}
    assert item["rank"] == "medium"
    tag = by["tag = session.exec(select(Tag).where(Tag.id == tag_id)).first()"]
    assert tag["owned"]["model"] == "Tag" and tag["owned"]["fields"] == [] and tag["rank"] == "low"


def test_a_query_built_to_hold_the_reading_up_does_not(tmp_path):
    """A `where` nested and filled far beyond what a person writes is read to an end, and decides nothing (how many
    of its parts are looked at is bounded: `flow.MOST_ASKED`)."""
    deep = "{ id: params.id, " + "AND: [{ ".join("" for _ in range(60)) + "status: ctx.status" + " }]" * 59 + " }"
    # 1,500 fields and not more: a file with one line over 50,000 characters is taken for a built bundle and is
    # not read at all (`js_frontend.built_bundle`), which would make this a test of that older rule
    wide = "{ id: params.id, " + ", ".join(f"f{i}: ctx.f{i}" for i in range(1500)) + " }"
    body = (f"  const a = await prisma.invoice.findFirst({{ where: {deep} }});\n"
            f"  const b = await prisma.invoice.findFirst({{ where: {wide} }});\n"
            "  return NextResponse.json({ a, b });")
    fs = _scan(tmp_path, {**NEXT, "app/api/orgs/[orgId]/invoices/[id]/route.ts": _file(_route("GET", body))})
    assert [rule for rule, _line in _said(fs)] == ["LT-AUTHZ-OWNER", "LT-AUTHZ-OWNER"]
