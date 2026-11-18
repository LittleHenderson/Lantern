"""`LW-SENSITIVE-COLUMN-RETURNED`: a record sent back whole, with a secret field in it (roadmap of 2026-11-14,
stage 5).

A query that asks for every column of a record whose model holds a password's hash, a reset token or a key, and an
answer that hands the record on as it came: the secret field is in what the caller gets, whether or not a page
shows it. Read from the project's own model files (`lantern/datamodel.py`) and from the code of each query and
each answer; nothing is run. A heuristic until it is measured, so each dangerous example stands beside twins that
must stay quiet.
"""
import pytest

from lantern import datamodel, wholerecord
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-SENSITIVE-COLUMN-RETURNED"

SCHEMA = '''model User {
  id           String  @id @default(cuid())
  email        String  @unique
  name         String?
  passwordHash String
  resetToken   String?
  posts        Post[]
}

model Post {
  id       Int    @id @default(autoincrement())
  title    String
  author   User   @relation(fields: [authorId], references: [id])
  authorId String
}

model Session {
  id           String @id
  sessionToken String @unique
  userId       String
}
'''

IMPORTS = 'import { NextResponse } from "next/server";\nimport { prisma } from "@/lib/db";\n\n'

NEXT = {
    "package.json": '{"name": "notes", "dependencies": {"next": "15.0.0", "@prisma/client": "6.0.0"}}\n',
    "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n',
    "prisma/schema.prisma": SCHEMA,
    "lib/db.ts": 'import { PrismaClient } from "@prisma/client";\nexport const prisma = new PrismaClient();\n',
    # ---- dangerous: the record as it came
    "app/api/users/[id]/route.ts": IMPORTS +
        "export async function GET(_req: Request, { params }: { params: { id: string } }) {\n"
        "  const user = await prisma.user.findUnique({ where: { id: params.id } });\n"
        '  if (!user) return NextResponse.json({ error: "not found" }, { status: 404 });\n'
        "  return NextResponse.json(user);\n}\n",
    # ---- dangerous: after the password was compared, the whole record goes back in an object
    "app/api/login/route.ts": IMPORTS + 'import { compare } from "bcryptjs";\n\n'
        "export async function POST(req: Request) {\n"
        "  const { email, password } = await req.json();\n"
        "  const user = await prisma.user.findFirst({ where: { email } });\n"
        "  if (!user || !(await compare(password, user.passwordHash))) {\n"
        '    return NextResponse.json({ error: "wrong" }, { status: 401 });\n  }\n'
        "  return NextResponse.json({ ok: true, user });\n}\n",
    # ---- dangerous: a record with no secret of its own, sent with the whole record it leads to
    "app/api/posts/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  return Response.json(await prisma.post.findMany({ include: { author: true } }));\n}\n",
    # ---- dangerous: Express, a list in an object, and a new record straight into the answer
    "server/users.js": 'const { prisma } = require("../lib/db");\nconst router = require("express").Router();\n\n'
        'router.get("/users", async (req, res) => {\n'
        "  const users = await prisma.user.findMany();\n"
        "  res.status(200).json({ data: users });\n});\n\n"
        'router.post("/users", async (req, res) => {\n'
        "  res.json(await prisma.user.create({ data: req.body }));\n});\n\nmodule.exports = router;\n",
    # ---- dangerous: a Server Action's answer goes to the page that called it
    "app/actions.ts": '"use server";\nimport { prisma } from "@/lib/db";\n\n'
        "export async function me(id: string) {\n"
        "  return prisma.user.findUnique({ where: { id } });\n}\n",
    # ---- dangerous: a tRPC procedure's answer, with a block and without
    "server/api/user.ts": 'import { z } from "zod";\n'
        'import { createTRPCRouter, protectedProcedure, publicProcedure } from "./trpc";\n\n'
        "export const userRouter = createTRPCRouter({\n"
        "  byId: publicProcedure.input(z.string()).query(({ ctx, input }) => {\n"
        "    return ctx.db.user.findFirst({ where: { id: input } });\n  }),\n"
        "  sessions: protectedProcedure.query(({ ctx }) => ctx.db.session.findMany()),\n});\n",
    # ---- dangerous: what getServerSideProps hands the page is written into the page
    "pages/profile.tsx": 'import { prisma } from "@/lib/db";\n\n'
        "export async function getServerSideProps(ctx: any) {\n"
        "  const user = await prisma.user.findUnique({ where: { id: ctx.params.id } });\n"
        "  return { props: { user } };\n}\n\n"
        "export default function Profile({ user }: any) {\n  return <p>{user.name}</p>;\n}\n",
    # ---- safe: the query says which fields
    "app/api/safe/select/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const user = await prisma.user.findFirst({ select: { id: true, name: true } });\n"
        "  return NextResponse.json(user);\n}\n",
    # ---- safe: the query leaves the secret fields out
    "app/api/safe/omit/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const user = await prisma.user.findFirst({ omit: { passwordHash: true, resetToken: true } });\n"
        "  return NextResponse.json(user);\n}\n",
    # ---- safe: the answer names the fields it sends
    "app/api/safe/fields/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const user = await prisma.user.findFirst();\n"
        "  return NextResponse.json({ id: user?.id, name: user?.name });\n}\n",
    # ---- safe: the secret fields are taken out before the rest is sent
    "app/api/safe/rest/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const user = await prisma.user.findFirstOrThrow();\n"
        "  const { passwordHash, resetToken, ...rest } = user;\n"
        "  return NextResponse.json(rest);\n}\n",
    "app/api/safe/deleted/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const user: any = await prisma.user.findFirstOrThrow();\n"
        "  delete user.passwordHash;\n  delete user.resetToken;\n"
        "  return NextResponse.json(user);\n}\n",
    # ---- safe: a record with no secret field
    "app/api/safe/posts/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const posts = await prisma.post.findMany();\n"
        "  return NextResponse.json(posts);\n}\n",
    # ---- safe: the record is used and not sent
    "app/api/safe/used/route.ts": IMPORTS + 'import { sendMail } from "@/lib/mail";\n\n'
        "export async function POST() {\n"
        "  const user = await prisma.user.findFirstOrThrow();\n"
        "  await sendMail(user);\n"
        "  return NextResponse.json({ ok: true });\n}\n",
    # ---- safe: a function of the project's decides what goes back (not followed, so not claimed)
    "app/api/safe/shaped/route.ts": IMPORTS + 'import { toPublic } from "@/lib/shape";\n\n'
        "export async function GET() {\n"
        "  const user = await prisma.user.findFirstOrThrow();\n"
        "  return NextResponse.json(toPublic(user));\n}\n",
    # ---- safe: a page that is made on the server shows one field
    "app/account/page.tsx": 'import { prisma } from "@/lib/db";\n\n'
        "export default async function Page() {\n"
        "  const user = await prisma.user.findFirstOrThrow();\n"
        "  return <p>{user.name}</p>;\n}\n",
    # ---- safe: a helper that hands the record to other server code
    "lib/users.ts": 'import { prisma } from "@/lib/db";\n\n'
        "export async function byEmail(email: string) {\n"
        "  return prisma.user.findUnique({ where: { email } });\n}\n",
}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return root


def ours(root):
    return sorted((f for f in scan(build_graph(root))["findings"] if f["rule"] == RULE),
                  key=lambda f: (f["file"], f["line"]))


def test_a_prisma_record_sent_back_whole_is_named(tmp_path):
    found = ours(_write(tmp_path, NEXT))
    assert [(f["file"], f["line"], f["columns"]["model"], f["columns"]["fields"], f["columns"]["sent"])
            for f in found] == [
        ("app/actions.ts", 5, "User", ["passwordHash", "resetToken"], 5),
        ("app/api/login/route.ts", 8, "User", ["passwordHash", "resetToken"], 12),
        ("app/api/posts/route.ts", 5, "Post", ["author.passwordHash", "author.resetToken"], 5),
        ("app/api/users/[id]/route.ts", 5, "User", ["passwordHash", "resetToken"], 7),
        ("pages/profile.tsx", 4, "User", ["passwordHash", "resetToken"], 5),
        ("server/api/user.ts", 6, "User", ["passwordHash", "resetToken"], 6),
        ("server/api/user.ts", 8, "Session", ["sessionToken"], 8),
        ("server/users.js", 5, "User", ["passwordHash", "resetToken"], 6),
        ("server/users.js", 10, "User", ["passwordHash", "resetToken"], 10),
    ]
    for f in found:
        assert f["tool_confidence"] == "LOW" and f["rank"] == "medium" and f["category"] == "exposure", f
        assert f["cwe"] == 200 and f["more_info"].startswith("Heuristic") and f["columns"]["via"] == "prisma"
        assert f["columns"]["defined"]["file"] == "prisma/schema.prisma" and f["snippet"] == f["columns"]["fields"][0]
        assert f["scenario"]["steps"] and "answer" in " ".join(f["scenario"]["steps"])
    by = {(f["file"], f["line"]): f for f in found}
    one = by[("app/api/users/[id]/route.ts", 5)]
    assert one["title"] == "A User record is sent back whole, with its passwordHash and resetToken"
    assert one["columns"]["defined"] == {"file": "prisma/schema.prisma", "line": 1}
    assert "select" in one["more_info"] and "omit" in one["more_info"] and "line 7" in one["more_info"]
    post = by[("app/api/posts/route.ts", 5)]
    assert post["title"] == "A Post record is sent back with the whole User it leads to (author), passwordHash and " \
                            "resetToken with it"


CHANGED = [
    # (the file that changes, the safe text, the dangerous text, the fields then named)
    ("app/api/safe/select/route.ts", "select: { id: true, name: true }", "select: { id: true, passwordHash: true }",
     ["passwordHash"]),
    ("app/api/safe/select/route.ts", "{ select: { id: true, name: true } }", "{ where: { id: \"1\" } }",
     ["passwordHash", "resetToken"]),
    ("app/api/safe/omit/route.ts", "omit: { passwordHash: true, resetToken: true }", "omit: { passwordHash: true }",
     ["resetToken"]),
    ("app/api/safe/fields/route.ts", "{ id: user?.id, name: user?.name }", "{ id: user?.id, user }",
     ["passwordHash", "resetToken"]),
    ("app/api/safe/rest/route.ts", "const { passwordHash, resetToken, ...rest } = user;",
     "const { passwordHash, ...rest } = user;", None),          # `rest` is another name: not followed, still quiet
    ("app/api/safe/deleted/route.ts", "  delete user.resetToken;\n", "", ["resetToken"]),
    ("app/api/safe/posts/route.ts", "prisma.post.findMany()", "prisma.post.findMany({ include: { author: true } })",
     ["author.passwordHash", "author.resetToken"]),
    ("app/api/safe/shaped/route.ts", "toPublic(user)", "user", ["passwordHash", "resetToken"]),
    ("lib/users.ts", 'import { prisma } from "@/lib/db";', '"use server";\nimport { prisma } from "@/lib/db";',
     ["passwordHash", "resetToken"]),
]


@pytest.mark.parametrize("rel,safe,dangerous,fields", CHANGED, ids=[f"{c[0]}:{i}" for i, c in enumerate(CHANGED)])
def test_one_changed_part_makes_a_safe_twin_dangerous(tmp_path, rel, safe, dangerous, fields):
    assert NEXT[rel].count(safe) == 1
    found = ours(_write(tmp_path, {**NEXT, rel: NEXT[rel].replace(safe, dangerous)}))
    here = [f["columns"]["fields"] for f in found if f["file"] == rel]
    assert here == ([fields] if fields else []) and len(found) == 9 + bool(fields)


# A link to another record whose name says a secret (`password Password?`) is no field of the record: Prisma brings
# the record it leads to only when the query asks for it (`include`, `select`), and that record keeps the secret in
# the field that holds the value, where its model's own name says it holds one (`Password.hash`, `ApiKey.key`).
APART_SCHEMA = '''model Member {
  id       String    @id @default(cuid())
  email    String    @unique
  password Password?
  apiKeys  ApiKey[]
}

model Password {
  hash     String
  member   Member @relation(fields: [memberId], references: [id])
  memberId String @unique
}

model ApiKey {
  id       String @id @default(cuid())
  label    String
  key      String @unique
  member   Member @relation(fields: [memberId], references: [id])
  memberId String
}
'''

APART = {
    "package.json": NEXT["package.json"],
    "tsconfig.json": NEXT["tsconfig.json"],
    "prisma/schema.prisma": APART_SCHEMA,
    "lib/db.ts": NEXT["lib/db.ts"],
    # ---- safe: the member as it came holds no secret of its own, and what it links to is not brought
    "app/api/members/[id]/route.ts": IMPORTS +
        "export async function GET(_req: Request, { params }: { params: { id: string } }) {\n"
        "  const member = await prisma.member.findUnique({ where: { id: params.id } });\n"
        "  return NextResponse.json(member);\n}\n",
    # ---- dangerous: the password's own record brought with the member
    "app/api/members/by-email/route.ts": IMPORTS +
        "export async function POST(req: Request) {\n"
        "  const { email } = await req.json();\n"
        "  const member = await prisma.member.findUnique({ where: { email }, include: { password: true } });\n"
        "  return NextResponse.json(member);\n}\n",
    # ---- dangerous: every key of every member brought whole
    "app/api/members/keys/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const members = await prisma.member.findMany({ include: { apiKeys: true } });\n"
        "  return NextResponse.json(members);\n}\n",
    # ---- safe: the keys brought by the fields that hold no secret
    "app/api/members/labels/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  const members = await prisma.member.findMany({\n"
        "    include: { apiKeys: { select: { id: true, label: true } } },\n  });\n"
        "  return NextResponse.json(members);\n}\n",
    # ---- dangerous: the keys asked for themselves
    "app/api/keys/route.ts": IMPORTS +
        "export async function GET() {\n"
        "  return NextResponse.json(await prisma.apiKey.findMany());\n}\n",
}


def test_a_secret_kept_in_a_record_of_its_own_is_named_only_when_it_is_brought(tmp_path):
    found = ours(_write(tmp_path, APART))
    assert [(f["file"], f["line"], f["columns"]["model"], f["columns"]["fields"]) for f in found] == [
        ("app/api/keys/route.ts", 5, "ApiKey", ["key"]),
        ("app/api/members/by-email/route.ts", 6, "Member", ["password.hash"]),
        ("app/api/members/keys/route.ts", 5, "Member", ["apiKeys.key"]),
    ]
    by = {f["file"]: f for f in found}
    key, member = by["app/api/keys/route.ts"], by["app/api/members/by-email/route.ts"]
    assert "the field key, which keeps the value in a model whose own name says it holds a secret (ApiKey)" \
        in key["more_info"]
    assert "`select: { id: true, label: true }`" in key["more_info"]          # an example made of its own fields
    assert member["title"] == "A Member record is sent back with the whole Password it leads to (password), hash " \
                              "with it"
    assert "`password: { select: { memberId: true } }`" in member["more_info"]


DRIZZLE = {
    "package.json": '{"name": "d", "dependencies": {"next": "15.0.0", "drizzle-orm": "0.36.0"}}\n',
    "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n',
    "db/schema.ts": 'import { integer, pgTable, serial, text } from "drizzle-orm/pg-core";\n\n'
                    'export const orgs = pgTable("orgs", { id: serial("id").primaryKey(), name: text("name") });\n'
                    'export const users = pgTable("users", {\n  id: serial("id").primaryKey(),\n'
                    '  email: text("email"),\n  passwordHash: text("password_hash"),\n'
                    '  orgId: integer("org_id"),\n});\n',
    "app/api/users/route.ts": 'import { NextResponse } from "next/server";\nimport { db } from "@/db";\n'
        'import { orgs, users } from "@/db/schema";\n\n'
        "export async function GET() {\n"
        "  const rows = await db.select().from(users);\n"
        "  return NextResponse.json(rows);\n}\n\n"
        "export async function POST(req: Request) {\n"
        "  const [user] = await db.insert(users).values(await req.json()).returning();\n"
        "  return NextResponse.json({ user });\n}\n\n"
        "export async function PUT() {\n"
        "  return NextResponse.json(await db.query.users.findFirst());\n}\n",
    "app/api/safe/route.ts": 'import { NextResponse } from "next/server";\nimport { db } from "@/db";\n'
        'import { orgs, users } from "@/db/schema";\n\n'
        "export async function GET() {\n"
        "  const rows = await db.select({ id: users.id, email: users.email }).from(users);\n"
        "  const all = await db.select().from(orgs);\n"
        "  return NextResponse.json({ rows, all });\n}\n\n"
        "export async function POST(req: Request) {\n"
        "  const [user] = await db.insert(users).values(await req.json()).returning({ id: users.id });\n"
        "  return NextResponse.json({ user });\n}\n\n"
        "export async function PUT() {\n"
        "  const one = await db.query.users.findFirst({ columns: { id: true, email: true } });\n"
        "  const two = await db.query.users.findFirst({ columns: { passwordHash: false } });\n"
        "  return NextResponse.json({ one, two });\n}\n",
}


def test_a_drizzle_row_sent_back_whole_is_named(tmp_path):
    found = ours(_write(tmp_path, DRIZZLE))
    assert [(f["file"], f["line"], f["columns"]["model"], f["columns"]["fields"], f["columns"]["via"])
            for f in found] == [
        ("app/api/users/route.ts", 6, "users", ["passwordHash"], "drizzle"),
        ("app/api/users/route.ts", 11, "users", ["passwordHash"], "drizzle"),
        ("app/api/users/route.ts", 16, "users", ["passwordHash"], "drizzle"),
    ]
    assert found[0]["title"] == "A users row is sent back whole, with its passwordHash"
    assert found[0]["columns"]["defined"] == {"file": "db/schema.ts", "line": 4}


MODELS_PY = '''from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import DeclarativeBase
from sqlmodel import Field, SQLModel


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String)
    hashed_password = Column(String)


class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    body = Column(String)


class Account(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    api_key: str
'''

FASTAPI = {
    "requirements.txt": "fastapi==0.115.0\nsqlalchemy==2.0.36\nsqlmodel==0.0.22\n",
    "app/__init__.py": "",
    "app/models.py": MODELS_PY,
    "app/schemas.py": "from pydantic import BaseModel\n\n\nclass UserOut(BaseModel):\n    id: int\n    email: str\n\n\n"
                      "class UserIn(BaseModel):\n    email: str\n    password: str\n",
    "app/deps.py": "from typing import Annotated\n\nfrom fastapi import Depends\n\nfrom .models import User\n\n\n"
                   "def get_db():\n    yield None\n\n\ndef current_user() -> User:\n    raise NotImplementedError\n\n\n"
                   "CurrentUser = Annotated[User, Depends(current_user)]\n",
    "app/crud.py": "from .models import Note, User\n\n\n"
                   "def by_email(db, email: str) -> User | None:\n"
                   "    return db.query(User).filter(User.email == email).first()\n\n\n"
                   "def note(db, note_id: int) -> Note | None:\n    return db.get(Note, note_id)\n",
    "app/main.py": "from fastapi import APIRouter, Depends, FastAPI\nfrom sqlalchemy import select\n\n"
                   "from . import crud\nfrom .deps import CurrentUser, current_user, get_db\n"
                   "from .models import Account, Note, User\nfrom .schemas import UserIn, UserOut\n\n"
                   "app = FastAPI()\nrouter = APIRouter()\n\n\n"
                   # ---- dangerous (line 13 on)
                   '@app.get("/users/{user_id}")\n'
                   "def read_user(user_id: int, db=Depends(get_db)):\n"
                   "    user = db.query(User).filter(User.id == user_id).first()\n"
                   "    return user\n\n\n"
                   '@app.get("/me")\n'
                   "def me(current: User = Depends(current_user)):\n"
                   "    return current\n\n\n"
                   '@app.get("/me2")\n'
                   "def me_again(current: CurrentUser):\n"
                   '    return {"user": current}\n\n\n'
                   '@app.post("/users")\n'
                   "def create(data: UserIn, db=Depends(get_db)):\n"
                   "    user = User(email=data.email, hashed_password=data.password)\n"
                   "    db.add(user)\n"
                   "    db.commit()\n"
                   "    return user\n\n\n"
                   '@router.get("/by-email")\n'
                   "async def by_email(email: str, db=Depends(get_db)):\n"
                   "    return crud.by_email(db, email)\n\n\n"
                   '@router.get("/accounts", response_model=list[Account])\n'
                   "def accounts(db=Depends(get_db)):\n"
                   "    return db.scalars(select(Account)).all()\n\n\n"
                   # ---- safe
                   '@app.get("/safe/users/{user_id}", response_model=UserOut)\n'
                   "def safe_user(user_id: int, db=Depends(get_db)):\n"
                   "    return db.query(User).filter(User.id == user_id).first()\n\n\n"
                   '@app.get("/safe/me")\n'
                   "def safe_me(current: CurrentUser) -> UserOut:\n"
                   "    return current\n\n\n"
                   '@app.get("/safe/id")\n'
                   "def safe_id(current: CurrentUser):\n"
                   '    return {"id": current.id, "email": current.email}\n\n\n'
                   '@app.get("/safe/shaped")\n'
                   "def safe_shaped(current: CurrentUser):\n"
                   "    return UserOut.model_validate(current)\n\n\n"
                   '@app.get("/safe/note/{note_id}")\n'
                   "def safe_note(note_id: int, db=Depends(get_db)):\n"
                   "    return crud.note(db, note_id)\n\n\n"
                   '@app.delete("/safe/users/{user_id}")\n'
                   "def safe_delete(user_id: int, db=Depends(get_db)):\n"
                   "    user = db.get(User, user_id)\n"
                   "    db.delete(user)\n"
                   '    return {"ok": True}\n\n\n'
                   "def helper(db, user_id: int):\n"
                   "    return db.get(User, user_id)\n",
}


def test_a_fastapi_route_that_hands_back_the_tables_own_object_is_named(tmp_path):
    found = ours(_write(tmp_path, FASTAPI))
    assert [(f["line"], f["columns"]["model"], f["columns"]["fields"], f["columns"]["sent"], f["columns"]["via"])
            for f in found if f["file"] == "app/main.py"] == [
        (15, "User", ["hashed_password"], 16, "sqlalchemy"),
        (20, "User", ["hashed_password"], 21, "sqlalchemy"),
        (25, "User", ["hashed_password"], 26, "sqlalchemy"),
        (31, "User", ["hashed_password"], 34, "sqlalchemy"),
        (39, "User", ["hashed_password"], 39, "sqlalchemy"),
        (42, "Account", ["api_key"], 44, "sqlmodel"),
    ]
    assert len(found) == 6
    assert found[0]["title"] == "A User record is sent back whole, with its hashed_password"
    assert "response_model" in found[0]["more_info"] and found[0]["columns"]["defined"] == {
        "file": "app/models.py", "line": 10}
    assert "response_model" in found[5]["more_info"] and "Account" in found[5]["more_info"]


DRF = {
    "requirements.txt": "django==5.1\ndjangorestframework==3.15.2\n",
    "team/__init__.py": "",
    "team/models.py": "from django.contrib.auth.models import AbstractUser\nfrom django.db import models\n\n\n"
                      "class Member(AbstractUser):\n    phone = models.CharField(max_length=20)\n\n\n"
                      "class Invite(models.Model):\n    token = models.CharField(max_length=64)\n"
                      "    uses_left = models.IntegerField(default=1)\n\n\n"
                      "class Team(models.Model):\n    name = models.CharField(max_length=80)\n",
    "team/serializers.py": "from django.contrib.auth import get_user_model\nfrom rest_framework import serializers\n\n"
                           "from .models import Invite, Member, Team\n\n\n"
                           # ---- dangerous
                           "class MemberSerializer(serializers.ModelSerializer):\n    class Meta:\n"
                           "        model = Member\n        fields = \"__all__\"\n\n\n"
                           "class InviteSerializer(serializers.ModelSerializer):\n    class Meta:\n"
                           "        model = Invite\n        exclude = [\"uses_left\"]\n\n\n"
                           "class UserSerializer(serializers.ModelSerializer):\n    class Meta:\n"
                           "        model = get_user_model()\n        fields = [\"id\", \"username\", \"password\"]\n\n\n"
                           # ---- safe
                           "class SafeFields(serializers.ModelSerializer):\n    class Meta:\n"
                           "        model = Member\n        fields = [\"id\", \"username\"]\n\n\n"
                           "class SafeWriteOnly(serializers.ModelSerializer):\n    class Meta:\n"
                           "        model = Member\n        fields = \"__all__\"\n"
                           "        extra_kwargs = {\"password\": {\"write_only\": True}}\n\n\n"
                           "class SafeExclude(serializers.ModelSerializer):\n    class Meta:\n"
                           "        model = Member\n        exclude = (\"password\",)\n\n\n"
                           "class SafeDeclared(serializers.ModelSerializer):\n"
                           "    token = serializers.CharField(write_only=True)\n\n    class Meta:\n"
                           "        model = Invite\n        fields = \"__all__\"\n\n\n"
                           "class SafeTeam(serializers.ModelSerializer):\n    class Meta:\n"
                           "        model = Team\n        fields = \"__all__\"\n",
}


def test_a_serializer_that_sends_every_field_of_a_model_with_a_secret_is_named(tmp_path):
    found = ours(_write(tmp_path, DRF))
    assert [(f["file"], f["line"], f["columns"]["model"], f["columns"]["fields"], f["columns"]["via"])
            for f in found] == [
        ("team/serializers.py", 10, "Member", ["password"], "django"),
        ("team/serializers.py", 16, "Invite", ["token"], "django"),
        ("team/serializers.py", 22, "Member", ["password"], "django"),
    ]
    assert found[0]["title"] == "MemberSerializer sends every field of Member, password with it"
    assert found[2]["title"] == "UserSerializer lists the field password of Member among what it sends"
    assert "write_only" in found[0]["more_info"]


def test_a_project_with_no_secret_field_or_no_model_is_not_read(tmp_path):
    plain = {k: v for k, v in NEXT.items() if k != "prisma/schema.prisma"}
    assert ours(_write(tmp_path / "a", plain)) == []
    schema = SCHEMA.replace("passwordHash", "nickname").replace("resetToken", "city").replace("sessionToken", "tag")
    assert ours(_write(tmp_path / "b", {**NEXT, "prisma/schema.prisma": schema})) == []
    assert wholerecord.sent_whole(build_graph(tmp_path / "a")) == []


HEAD = 'import { prisma } from "@/lib/db";\nimport { db } from "@/db";\nimport { users } from "@/db/schema";\n\n'

# More ways a record goes out, each beside twins that must stay quiet. A line that ends with `// here` is one the rule
# must name, and no other line of the file.
MORE = {
    "server/more.js": HEAD + '''
router.get("/both", async (req, res) => {
  const [user, posts] = await Promise.all([
    prisma.user.findFirst(), // here
    prisma.post.findMany(),
  ]);
  res.json({ user, posts });
});
router.get("/one-of-both", async (req, res) => {
  const [user, posts] = await Promise.all([prisma.user.findFirst(), prisma.post.findMany()]);
  res.json({ posts, name: user.name });
});
router.get("/send", async (req, res) => {
  const user = await prisma.user.findFirst(); // here
  res.status(200).send(user);
});
router.get("/mail", async (req, res) => {
  const user = await prisma.user.findFirst();
  mailer.send(user);
  res.json({ ok: true });
});
router.get("/text", async (req, res) => {
  const user = await prisma.user.findFirst(); // here
  return new Response(JSON.stringify(user));
});
router.get("/read-off", async (req, res) => {
  const posts = await prisma.user.findFirst().posts();
  res.json(posts);
});
router.get("/shaped-again", async (req, res) => {
  let user = await prisma.user.findFirst();
  user = toPublic(user);
  res.json(user);
});
router.get("/both-taken", async (req, res) => {
  const user = await prisma.user.findFirst();
  user.passwordHash = undefined;
  user["resetToken"] = undefined;
  res.json(user);
});
router.get("/taken-late", async (req, res) => {
  const user = await prisma.user.findFirst(); // here
  res.json(user);
  delete user.passwordHash;
  delete user.resetToken;
});
router.get("/a-text-says-it", async (req, res) => {
  const how = "res.json(await prisma.user.findFirst())";
  // res.json(await prisma.user.findFirst())
  res.json({ how });
});
router.get("/rows", async (req, res) => {
  const first = await db.select().from(users).then((rows) => rows[0].id);
  const rows = await db.select().from(users).where(eq(users.id, 1)).limit(1); // here
  res.json({ first, rows });
});
''',
    "app/save.tsx": HEAD + '''
export default function Page() {
  async function save() {
    "use server";
    return prisma.user.findFirst(); // here
  }
  async function quiet() {
    return prisma.user.findFirst();
  }
  return <form action={save}><button onClick={quiet}>go</button></form>;
}
''',
    "app/routes/users.tsx": HEAD + '''
export async function loader() {
  return { user: await prisma.user.findFirst() }; // here
}
async function helper() {
  return prisma.user.findFirst();
}
''',
    "lib/loader.ts": HEAD + '''
export async function loader() {
  return { user: await prisma.user.findFirst() };
}
''',
    "src/routes/account/+page.server.ts": HEAD + '''
export const load = async () => {
  const user = await prisma.user.findFirstOrThrow(); // here
  return { user };
};
''',
}


def _marked(text, mark):
    return [n for n, row in enumerate(text.split("\n"), 1) if row.rstrip().endswith(mark)]


def test_more_ways_a_record_goes_out_and_their_twins():
    models = datamodel.Models(datamodel.prisma(SCHEMA, "prisma/schema.prisma")
                              + datamodel.drizzle(DRIZZLE["db/schema.ts"], "db/schema.ts"))
    for rel, text in MORE.items():
        want = _marked(text, "// here")
        assert sorted(h["line"] for h in wholerecord.js_file(text, rel, models)) == want, rel
    assert sum(len(_marked(text, "// here")) for text in MORE.values()) == 8
    found = [h for h in wholerecord.js_file(MORE["server/more.js"], "server/more.js", models)
             if h["model"].name == "User"]
    assert [h["fields"] for h in found] == [["passwordHash", "resetToken"]] * 4     # also where taken off too late
    one = MORE["server/more.js"].replace('  user["resetToken"] = undefined;\n', "")
    found = [h for h in wholerecord.js_file(one, "server/more.js", models) if h["model"].name == "User"]
    assert len(found) == 5 and [h["fields"] for h in found if len(h["fields"]) == 1] == [["resetToken"]]


MORE_PY = '''from fastapi import APIRouter

from .models import Note, User
from .schemas import UserOut

router = APIRouter()


@router.get("/typed")
def typed(db) -> User:  # here
    return db.get(User, 1)


@router.get("/no-shape", response_model=None)
async def no_shape(db):
    user = await db.get(User, 1)  # here
    if user is None:
        return {"error": "none"}
    return [user]


@router.get("/shaped-again")
def shaped_again(db):
    user = db.get(User, 1)
    user = UserOut.model_validate(user)
    return user


@router.get("/count")
def count(db):
    return {"count": db.query(User).count(), "ids": db.query(User.id).all()}


@router.get("/notes")
def notes(db):
    return db.query(Note).all()


def no_route(db):
    return db.get(User, 1)
'''

MORE_DRF = '''from rest_framework import serializers

from .models import Invite, Member


class Made(serializers.ModelSerializer):
    token = serializers.SerializerMethodField()

    class Meta:
        model = Invite
        fields = "__all__"

    def get_token(self, obj):
        return obj.token[:4]


class Both(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ("id", "password")  # here
        extra_kwargs = {"password": {"write_only": False}}


class NoModel(serializers.Serializer):
    password = serializers.CharField()
'''


def test_more_routes_and_serializers_and_their_twins():
    models = datamodel.Models(datamodel.python(MODELS_PY, "app/models.py")
                              + datamodel.python(DRF["team/models.py"], "team/models.py"))
    assert [h["line"] for h in wholerecord.py_file(MORE_PY, "app/more.py", models, {})] == _marked(MORE_PY, "# here")
    assert len(_marked(MORE_PY, "# here")) == 2
    assert wholerecord.py_file(MORE_PY.replace("fastapi", "flask"), "app/more.py", models, {}) == []
    assert [h["line"] for h in wholerecord.py_file(MORE_DRF, "team/more.py", models, {})] == _marked(MORE_DRF, "# here")
    assert len(_marked(MORE_DRF, "# here")) == 1


def test_files_built_to_hold_the_check_up_are_read_in_bounded_time(tmp_path):
    import time
    models = datamodel.Models(datamodel.prisma(SCHEMA, "prisma/schema.prisma"))
    deep = "export async function GET() {\n  return NextResponse.json(" + "[" * 3000 + "await prisma.user.findMany()" \
           + "]" * 3000 + ");\n}\n"
    wide = "export async function GET() {\n" + "  const u = await prisma.user.findMany();\n" * 20000 + "}\n"
    t = time.perf_counter()
    assert wholerecord.js_file(deep, "a.ts", models) is not None
    assert wholerecord.js_file(wide, "b.ts", models) == []
    assert wholerecord.py_file("@app.get('/x')\ndef f(u: User):\n" + "    u = [u]\n" * 20000 + "    return u\n",
                               "m.py", models, {}) is not None
    assert time.perf_counter() - t < 20
