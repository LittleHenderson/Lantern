"""What a project's data looks like, read from the files that say so (roadmap of 2026-11-14, stage 5).

`lantern/datamodel.py` reads the models a project writes down: a Prisma schema, SQLAlchemy and SQLModel classes,
Django models, Drizzle tables and `create table` statements. For each: its fields with their lines, which of them
hold a secret by their names (a password's hash, a reset token, a key), which say whose the record is (`userId`,
`org_id`), and which lead to another model. It runs nothing and connects to nothing. The rules that need to know
what a record holds read it from here.
"""
import pytest

from lantern import datamodel

PRISMA = '''generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

/// a person who can sign in
model User {
  id            String   @id @default(cuid())
  email         String   @unique
  passwordHash  String
  resetToken    String?  // sent by mail
  posts         Post[]
  org           Org      @relation(fields: [orgId], references: [id])
  orgId         String
  // apiKey     String   (not a field: a remark)

  @@index([orgId])
}

model Post {
  id         Int    @id @default(autoincrement())
  title      String
  author     User   @relation(fields: [authorId], references: [id])
  authorId   String
  tokenCount Int
  @@map("posts")
}

model Org { id String @id
  name String }

enum Role {
  USER
  ADMIN
}
'''

SQLA = '''from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlmodel import Field, SQLModel


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str]
    hashed_password: Mapped[str] = mapped_column(String(200))
    api_key = Column(String)

    def greet(self):
        password = "not a field"
        return password


class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    body = Column(String)


class Card(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    secret_answer: str


class CardOut(SQLModel):
    id: int


class NoteOut:
    id: int
    password: str
'''

DJANGO = '''from django.contrib.auth.models import AbstractUser
from django.db import models


class Member(AbstractUser):
    phone = models.CharField(max_length=20)


class Invite(models.Model):
    token = models.CharField(max_length=64)
    team = models.ForeignKey("Team", on_delete=models.CASCADE)
    uses_left = models.IntegerField(default=1)

    class Meta:
        ordering = ["id"]


class Team(models.Model):
    name = models.CharField(max_length=80)
'''

DRIZZLE = '''import { integer, pgTable, serial, text } from "drizzle-orm/pg-core";

export const orgs = pgTable("orgs", { id: serial("id").primaryKey(), name: text("name") });

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  email: text("email").notNull(),
  passwordHash: text("password_hash").notNull(),
  // legacyToken: text("legacy_token"),
  orgId: integer("org_id").references(() => orgs.id),
}, (t) => ({ byOrg: index("by_org").on(t.orgId) }));
'''

SQL = '''-- profiles of the people who sign in
create table if not exists public.profiles (
  id uuid primary key references auth.users,
  user_id uuid not null,
  stripe_secret text,
  note text default 'a password, (not) a column',
  constraint fk foreign key (user_id) references auth.users (id)
);
CREATE TABLE "Invoice" ("id" serial PRIMARY KEY, "tenant_id" int, amount numeric(10, 2));
'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return root


def test_a_prisma_schema():
    got = {m.name: m for m in datamodel.prisma(PRISMA, "prisma/schema.prisma")}
    assert sorted(got) == ["Org", "Post", "User"]                       # an enum, a generator, a source: no models
    user, post = got["User"], got["Post"]
    assert (user.kind, user.file, user.line) == ("prisma", "prisma/schema.prisma", 11)
    assert user.fields == {"id": 12, "email": 13, "passwordHash": 14, "resetToken": 15, "posts": 16, "org": 17,
                           "orgId": 18}
    assert user.secret() == ["passwordHash", "resetToken"] and user.owner() == ["orgId"]
    assert user.leads == {"posts": "Post", "org": "Org"}
    assert post.secret() == [] and post.owner() == ["authorId"] and post.leads == {"author": "User"}
    assert post.table == "posts" and user.table is None
    assert got["Org"].fields == {"id": 33, "name": 34}


def test_sqlalchemy_and_sqlmodel_classes():
    got = {m.name: m for m in datamodel.python(SQLA, "app/models.py")}
    assert sorted(got) == ["Card", "Note", "User"]          # a base with no column, a schema, a plain class: none
    user = got["User"]
    assert (user.kind, user.line, user.table) == ("sqlalchemy", 10, "users")
    assert user.fields == {"id": 13, "email": 14, "hashed_password": 15, "api_key": 16}
    assert user.secret() == ["hashed_password", "api_key"] and user.owner() == []
    assert got["Note"].owner() == ["owner_id"] and got["Note"].secret() == []
    assert got["Card"].kind == "sqlmodel" and got["Card"].secret() == ["secret_answer"]
    assert got["Card"].owner() == ["workspace_id"]


def test_django_models():
    got = {m.name: m for m in datamodel.python(DJANGO, "team/models.py")}
    assert sorted(got) == ["Invite", "Member", "Team"]
    assert got["Member"].kind == "django" and got["Member"].fields == {"phone": 6}
    assert got["Member"].inherited == ["password"] and got["Member"].secret() == ["password"]
    assert got["Invite"].secret() == ["token"] and got["Invite"].owner() == ["team"]
    assert got["Invite"].leads == {"team": "Team"} and "Meta" not in got["Invite"].fields
    assert got["Team"].secret() == [] and got["Team"].inherited == []


def test_drizzle_tables():
    got = {m.name: m for m in datamodel.drizzle(DRIZZLE, "db/schema.ts")}
    assert sorted(got) == ["orgs", "users"]
    users = got["users"]
    assert (users.kind, users.table, users.line) == ("drizzle", "users", 5)
    assert users.fields == {"id": 6, "email": 7, "passwordHash": 8, "orgId": 10}
    assert users.secret() == ["passwordHash"] and users.owner() == ["orgId"]
    assert got["orgs"].fields == {"id": 3, "name": 3}


def test_create_table_statements():
    got = {m.name: m for m in datamodel.sql(SQL, "supabase/migrations/1_init.sql")}
    assert sorted(got) == ["Invoice", "profiles"]
    profiles = got["profiles"]
    assert (profiles.kind, profiles.table, profiles.line) == ("sql", "profiles", 2)
    assert profiles.fields == {"id": 3, "user_id": 4, "stripe_secret": 5, "note": 6}
    assert profiles.secret() == ["stripe_secret"] and profiles.owner() == ["user_id"]
    assert got["Invoice"].fields == {"id": 9, "tenant_id": 9, "amount": 9} and got["Invoice"].owner() == ["tenant_id"]


KEPT_APART = '''model Member {
  id       String    @id @default(cuid())
  email    String    @unique
  password Password?
  apiKeys  ApiKey[]
  tokens   Int       @default(0)
}

model Password {
  hash     String
  member   Member @relation(fields: [memberId], references: [id])
  memberId String @unique
}

model ApiKey {
  id         String    @id @default(cuid())
  label      String
  key        String    @unique
  lastUsedAt DateTime?
  member     Member    @relation(fields: [memberId], references: [id])
  memberId   String
}

model PasswordPolicy {
  id        Int @id
  value     Int
  minLength Int
}

model TokenUsage {
  id    Int @id
  value Int
}
'''

KEPT_APART_SQL = '''create table api_keys (id serial primary key, user_id int, key text not null, name text);
create table passwords (user_id int primary key, hash text not null);
create table sessions (id text primary key, data text);
create table password_policies (id int primary key, value int);
create table signing_keys (id int, `key` varchar(64), KEY idx_key (`key`), PRIMARY KEY (id));
'''


def test_a_secret_kept_in_a_record_of_its_own():
    """A link to another record is no field of the record: `password Password?` holds no secret, the record it leads
    to does, and a query brings that record only when it asks for it. A model whose own name says it holds a secret
    (`Password`, `ApiKey`, `api_keys`) keeps it in the field that holds the value (`hash`, `key`); one whose name only
    shares a word with a secret (`PasswordPolicy`, `TokenUsage`, `sessions`) keeps none."""
    got = {m.name: m for m in datamodel.prisma(KEPT_APART, "prisma/schema.prisma")}
    assert got["Member"].leads == {"password": "Password", "apiKeys": "ApiKey"} and got["Member"].secret() == []
    assert got["Password"].secret() == ["hash"] and got["ApiKey"].secret() == ["key"]
    assert got["PasswordPolicy"].secret() == [] and got["TokenUsage"].secret() == []
    assert got["Member"].owner() == [] and got["Password"].owner() == ["memberId"]
    tables = {m.name: m for m in datamodel.sql(KEPT_APART_SQL, "db/schema.sql")}
    assert tables["api_keys"].secret() == ["key"] and tables["passwords"].secret() == ["hash"]
    assert tables["sessions"].secret() == [] and tables["password_policies"].secret() == []
    # a column named `key` is a column where a type follows it; `KEY idx (col)` and `PRIMARY KEY (id)` are none
    assert list(tables["api_keys"].fields) == ["id", "user_id", "key", "name"]
    assert list(tables["signing_keys"].fields) == ["id", "key"] and tables["signing_keys"].secret() == ["key"]


@pytest.mark.parametrize("name,secret", [
    ("password", True), ("passwordHash", True), ("hashed_password", True), ("passwd", True), ("pwd_hash", True),
    ("resetToken", True), ("reset_password_token", True), ("verification_token", True), ("refresh_token", True),
    ("access_token", True), ("sessionToken", True), ("token", True), ("apiKey", True), ("api_key", True),
    ("secret", True), ("twoFactorSecret", True), ("totp_secret", True), ("privateKey", True), ("secret_key", True),
    ("otp", True), ("recoveryCodes", True), ("salt", True), ("stripe_secret", True), ("encryptionKey", True),
    # --- not secrets: counts, flags, dates and public things that share a word
    ("tokenCount", False), ("tokens", False), ("max_tokens", False), ("totalTokens", False), ("tokens_used", False),
    ("passwordUpdatedAt", False), ("password_changed_at", False), ("hasPassword", False), ("has_password", False),
    ("token_expires_at", False), ("resetTokenExpiry", False), ("publicKey", False), ("public_key", False),
    ("keyboard", False), ("key", False), ("apiKeyId", False), ("api_key_count", False), ("secretary", False),
    ("email", False), ("name", False), ("id", False), ("monkey", False), ("salted", False), ("is_secret", False),
])
def test_which_names_say_a_secret(name, secret):
    assert datamodel.secret_column(name) is secret


@pytest.mark.parametrize("name,owner", [
    ("userId", True), ("user_id", True), ("ownerId", True), ("owner_id", True), ("orgId", True), ("org_id", True),
    ("organizationId", True), ("organisation_id", True), ("workspaceId", True), ("tenant_id", True), ("teamId", True),
    ("accountId", True), ("authorId", True), ("created_by", True), ("createdById", True), ("owner", True),
    ("user", True), ("team", True), ("tenant", True), ("member_id", True), ("companyId", True),
    # --- not owners: other things with an id, and words that only look alike
    ("id", False), ("postId", False), ("parent_id", False), ("username", False), ("user_agent", False),
    ("teamName", False), ("account_type", False), ("userCount", False), ("ordering", False), ("authored_at", False),
    ("stripeCustomerId", False), ("external_id", False),
])
def test_which_names_say_whose_the_record_is(name, owner):
    assert datamodel.owner_column(name) is owner


def test_a_project_is_read_as_a_whole_and_only_its_own_files(tmp_path):
    root = _write(tmp_path, {
        "prisma/schema.prisma": PRISMA, "app/models.py": SQLA, "team/models.py": DJANGO, "db/schema.ts": DRIZZLE,
        "supabase/migrations/1_init.sql": SQL,
        "node_modules/x/schema.prisma": "model Hidden {\n  password String\n}\n",          # not the project's
        "tests/fixtures/models.py": SQLA.replace("class User", "class Fixture"),          # still read: a model is one
        "app/broken.py": "x = Column(\n",                                                         # does not parse: passed by
    })
    models = datamodel.read(root)
    names = sorted((m.kind, m.name) for m in models.all)
    assert ("prisma", "User") in names and ("sqlalchemy", "User") in names and ("django", "Invite") in names
    assert ("drizzle", "users") in names and ("sql", "profiles") in names
    assert not any(m.name == "Hidden" for m in models.all)
    assert [m.file for m in models.named("User", "prisma")] == ["prisma/schema.prisma"]
    assert models.named("user", "prisma")[0].name == "User"                 # as the client writes it: prisma.user
    assert models.named("Nobody") == []
    assert models.by_table("users", "drizzle")[0].name == "users"


def test_files_built_to_hold_the_reading_up_are_read_in_bounded_time():
    import time
    t = time.perf_counter()
    wide = "model Wide {\n" + "".join(f"  f{i} String\n" for i in range(50_000)) + "}\n"
    assert len(datamodel.prisma(wide, "schema.prisma")[0].fields) == datamodel.MOST_FIELDS
    assert datamodel.prisma("model X {\n" * 50_000, "schema.prisma") is not None
    assert datamodel.drizzle("export const t = pgTable('t', {" + "{" * 100_000, "s.ts") == []
    assert datamodel.sql("create table t (" + "(" * 100_000, "x.sql") is not None
    assert datamodel.python("class A(Base):\n" + "    x = Column(String)\n" * 50_000, "m.py")[0].fields
    assert time.perf_counter() - t < 20
