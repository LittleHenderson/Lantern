"""What a project's data looks like, read from the files that say so (roadmap of 2026-11-14, stage 5).

The models a project writes down: a Prisma schema (`*.prisma`), SQLAlchemy and SQLModel classes, Django models,
Drizzle tables (`pgTable("users", {…})`) and `create table` statements. For each model: its fields with their
lines, which of them hold a secret by their names (`secret_column`: a password's hash, a reset token, a key), which
say whose the record is (`owner_column`: `userId`, `org_id`, `tenant`), and which lead to another model.

It reads; it runs nothing, imports nothing of the project and connects to nothing. Python is read with Python's own
`ast`, the other kinds as text, each in bounded time. The rules that need to know what a record holds read it from
here: a record sent back whole (`lantern/wholerecord.py`), a record fetched by its number alone.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import listing
from .aiapp import read_as_code
from .python_frontend import project_text
from .rowrules import code_view

MOST_FILE = 1_000_000       # characters of a file that are read
MOST_FILES = 4_000          # files of a kind that are looked at
MOST_FIELDS = 400           # fields of one model that are kept
MOST_MODELS = 2_000         # models of one project
MOST_BODY = 200_000         # characters of one model's or table's body
ROUNDS = 6                  # classes that are a model because their base class is one, this many levels deep

_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
# a name with one of these words is about a secret and is not one: a count, a date, a flag, the public half
NOT_A_SECRET = frozenset("""count counts used usage limit max min total expires expiry expiration expire expired at
    date time updated changed created has is enabled required id ids length len hint policy strength public type
    name version attempts sent requested last prefix label""".split())
SECRET_WORDS = frozenset("password passwd pwd secret salt otp totp passphrase passcode".split())
KEY_OF = frozenset("api private secret signing encryption master license licence".split())
CODE_OF = frozenset("recovery backup".split())
OWNER_FORMS = frozenset({("user",), ("owner",), ("org",), ("organization",), ("organisation",), ("workspace",),
                         ("tenant",), ("team",), ("account",), ("author",), ("member",), ("company",), ("creator",),
                         ("created", "by")})


def words(name: str) -> list[str]:
    """A field's name as its words: `resetToken`, `reset_token` → reset, token."""
    return [w.lower() for w in _WORDS.findall(name)]


def secret_column(name: str) -> bool:
    """Does a field's name say it holds a secret: a password or its hash, a token that lets somebody in, a key?"""
    got = words(name)
    if not got or NOT_A_SECRET.intersection(got):
        return False
    have = set(got)
    return bool(have & SECRET_WORDS or "token" in have or ("key" in have and have & KEY_OF)
                or (have & {"code", "codes"} and have & CODE_OF))


def owner_column(name: str) -> bool:
    """Does a field's name say whose the record is (`userId`, `org_id`, `created_by`, `tenant`)?"""
    got = words(name)
    if got and got[-1] == "id":
        got = got[:-1]
    return tuple(got) in OWNER_FORMS


@dataclass
class Model:
    name: str                                   # as written: User, users, profiles
    kind: str                                   # prisma | sqlalchemy | sqlmodel | django | drizzle | sql
    file: str
    line: int
    fields: dict[str, int] = field(default_factory=dict)        # field → its line, in the order written
    leads: dict[str, str] = field(default_factory=dict)         # field → the model it leads to
    many: list[str] = field(default_factory=list)               # of `leads`: the fields that lead to a list of them
    table: str | None = None                    # the table's name, where the file says one
    inherited: list[str] = field(default_factory=list)          # fields a library's base class brings

    def secret(self) -> list[str]:
        """The fields that hold a secret by their names, a base class's first."""
        return [f for f in [*self.inherited, *self.fields] if secret_column(f)]

    def owner(self) -> list[str]:
        """The fields that say whose the record is. In a Prisma schema the field that leads to the owner (`org Org`)
        is no column; the one beside it is (`orgId`)."""
        return [f for f in self.fields if owner_column(f) and not (self.kind == "prisma" and f in self.leads)]


@dataclass
class Models:
    all: list[Model] = field(default_factory=list)
    left_out: list[str] = field(default_factory=list)           # files too large to read

    def named(self, name: str, kind: str | None = None) -> list[Model]:
        """The models of that name, as a client writes it too (`prisma.user` is the model `User`)."""
        low = name.lower()
        return [m for m in self.all if m.name.lower() == low and kind in (None, m.kind)]

    def by_table(self, table: str, kind: str | None = None) -> list[Model]:
        low = table.lower()
        return [m for m in self.all if (m.table or m.name).lower() == low and kind in (None, m.kind)]


def _line(text: str, at: int) -> int:
    return text.count("\n", 0, at) + 1


# ------------------------------------------------------------------------------------------------- Prisma

_PRISMA_MODEL = re.compile(r"^[ \t]*model[ \t]+([A-Za-z_]\w*)[ \t]*\{", re.M)
_PRISMA_FIELD = re.compile(r"[ \t]*([A-Za-z_]\w*)[ \t]+([A-Za-z_][\w.]*)(\[\])?\??")
_PRISMA_MAP = re.compile(r"@@map\(\s*\"([^\"\n]+)\"")
_PRISMA_TEXT = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"")
PRISMA_TYPES = frozenset("String Boolean Int BigInt Float Decimal DateTime Json Bytes Unsupported".split())


def prisma(text: str, rel: str) -> list[Model]:
    """The models of a Prisma schema. A field whose type is no built-in one leads to that model (or is an enum's,
    which the caller sees: no model of that name)."""
    code = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)
    shape = _PRISMA_TEXT.sub(lambda m: " " * len(m.group(0)), code)     # a brace inside a text is no brace
    out: list[Model] = []
    closes = opens = -2                                     # the next `}` and `{`: each is looked for once
    for m in _PRISMA_MODEL.finditer(shape):
        if closes != -1 and closes < m.end():
            closes = shape.find("}", m.end())
        if opens != -1 and opens < m.end():
            opens = shape.find("{", m.end())
        if closes == -1:
            break                                           # nothing after this is ever closed
        end = min(closes, opens if opens != -1 else closes, m.end() + MOST_BODY)
        body = code[m.end():end]                            # up to its end, or to the next thing that opens
        model = Model(m.group(1), "prisma", rel, _line(code, m.start(1)))
        at = m.end()
        for row in body.split("\n"):
            got = _PRISMA_FIELD.match(row)
            if got and not row.lstrip().startswith("@") and len(model.fields) < MOST_FIELDS:
                model.fields.setdefault(got.group(1), _line(code, at + got.start(1)))
                if got.group(2) not in PRISMA_TYPES:
                    model.leads[got.group(1)] = got.group(2)
                    if got.group(3) and got.group(1) not in model.many:
                        model.many.append(got.group(1))         # `invoices Invoice[]`: the other end of "belongs to"
            named = _PRISMA_MAP.search(row)
            if named:
                model.table = named.group(1)
            at += len(row) + 1
        out.append(model)
        if len(out) >= MOST_MODELS:
            break
    return out


# ------------------------------------------------------------------------------------------------- Python

DJANGO_AUTH = {"AbstractUser": ["password"], "AbstractBaseUser": ["password"]}
DJANGO_LEADS = frozenset({"ForeignKey", "OneToOneField", "ManyToManyField"})
SA_COLUMN = frozenset({"Column", "mapped_column", "column_property", "deferred"})
SA_LEADS = frozenset({"relationship", "backref", "Relationship"})


@dataclass
class _Class:
    """A class that may be a model: what its own lines say, before its base classes are asked."""
    model: Model
    bases: list[str]                            # the last part of each base's name
    kind: str | None                            # what its own lines show it to be, or None


def _last(node: ast.AST) -> str:
    """The last part of a name: `models.CharField` → CharField, `Mapped[int]` → Mapped."""
    while isinstance(node, (ast.Subscript, ast.Call)):
        node = node.value if isinstance(node, ast.Subscript) else node.func
    return node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else ""


def _first(node: ast.AST) -> str:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else ""


def _to(call: ast.Call) -> str:
    """The model a relation names: `ForeignKey("Team", …)`, `ForeignKey(Team)`, `relationship("User")`."""
    arg = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "to"), None)
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value.rsplit(".", 1)[-1]
    return _last(arg) if arg is not None else ""


def _classes(text: str, rel: str) -> list[_Class]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    out: list[_Class] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        model = Model(node.name, "", rel, node.lineno)
        bases = [_last(b) for b in node.bases]
        django = any(_last(b) in DJANGO_AUTH or (_last(b) == "Model" and _first(b) == "models") for b in node.bases)
        table = any(k.arg == "table" and isinstance(k.value, ast.Constant) and k.value.value is True
                    for k in node.keywords)
        alchemy = False
        for b in bases:
            model.inherited += DJANGO_AUTH.get(b, [])
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                name, value, hint = stmt.targets[0].id, stmt.value, None
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                name, value, hint = stmt.target.id, stmt.value, stmt.annotation
            else:
                continue
            if name == "__tablename__":
                alchemy = True
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    model.table = value.value
                continue
            if name.startswith("__") or len(model.fields) >= MOST_FIELDS:
                continue
            made = _last(value) if isinstance(value, ast.Call) else ""
            if made in SA_LEADS:
                alchemy = alchemy or made != "Relationship"
                to = _to(value)
                if to:
                    model.leads[name] = to
                continue                                        # no column: what it leads to is fetched apart
            mapped = hint is not None and _last(hint) == "Mapped"
            if made in SA_COLUMN or mapped:
                alchemy = True
                model.fields.setdefault(name, stmt.lineno)
            elif made in DJANGO_LEADS or made.endswith("Field") and (_first(value) == "models" or django):
                django = django or _first(value) == "models"
                model.fields.setdefault(name, stmt.lineno)
                if made in DJANGO_LEADS and _to(value):
                    model.leads[name] = _to(value)
                    if made == "ManyToManyField" and name not in model.many:
                        model.many.append(name)
            elif hint is not None and (table or "SQLModel" in bases or made == "Field"):
                model.fields.setdefault(name, stmt.lineno)      # a SQLModel field; counted only for `table=True`
        kind = "django" if django else "sqlmodel" if table else "sqlalchemy" if alchemy else None
        out.append(_Class(model, bases, kind))
        if len(out) >= MOST_MODELS:
            break
    return out


def _settled(classes: list[_Class]) -> list[Model]:
    """The classes that are models: by their own lines, or because a base class of that name is one (a project's
    own base class with the fields every table has; a SQLModel class is a table only where it says `table=True`
    itself). The secret fields of the project's own base classes are the class's too."""
    named: dict[str, _Class] = {}
    for c in classes:
        named.setdefault(c.model.name, c)
    for _ in range(ROUNDS):
        more = False
        for c in classes:
            if c.kind is None and c.model.fields:
                base = next((named[b] for b in c.bases if b in named and named[b].kind in ("django", "sqlalchemy")),
                            None)
                if base is not None:
                    c.kind, more = base.kind, True
        if not more:
            break
    out = []
    for c in classes:
        if not c.kind or not (c.model.fields or c.model.inherited):
            continue
        c.model.kind = c.kind
        seen, todo = {c.model.name}, list(c.bases)
        while todo and len(seen) < 50:                      # what the project's own base classes bring
            b = todo.pop()
            if b in named and b not in seen:
                seen.add(b)
                todo += named[b].bases
                c.model.inherited += [f for f in [*named[b].model.inherited, *named[b].model.fields]
                                      if secret_column(f) and f not in c.model.inherited and f not in c.model.fields]
        out.append(c.model)
    return out


def python(text: str, rel: str) -> list[Model]:
    """The SQLAlchemy, SQLModel and Django models one Python file writes."""
    return _settled(_classes(text, rel))


# ------------------------------------------------------------------------------------------------- Drizzle

_DRIZZLE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:pg|mysql|sqlite|singlestore)Table"
                      r"(?:Creator)?\s*\(\s*[\"'`]([\w.\-]+)[\"'`]\s*,\s*\{")
_KEY = re.compile(r"\s*[\"']?([A-Za-z_$][\w$]*)[\"']?\s*:")


def _top_parts(body: str, most: int = MOST_BODY):
    """The parts of `body` between commas that stand inside no bracket, each with where it starts; and where the
    bracket that was open at the start closes (None when it does not within `most` characters). Texts in quotes
    are passed over."""
    depth, start, quote, i, n = 0, 0, "", 0, min(len(body), most)
    parts: list[tuple[int, str]] = []
    while i < n:
        ch = body[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                parts.append((start, body[start:i]))
                return parts, i
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append((start, body[start:i]))
            start = i + 1
        i += 1
    return parts, None


def drizzle(text: str, rel: str) -> list[Model]:
    """The tables a JS/TS file makes with Drizzle: `export const users = pgTable("users", { … })`."""
    if "Table" not in text:
        return []
    code = "\n".join(read_as_code(text.split("\n"), rel)[0])
    out: list[Model] = []
    for m in _DRIZZLE.finditer(code):
        parts, end = _top_parts(code[m.end():m.end() + MOST_BODY])
        if end is None:
            continue
        model = Model(m.group(1), "drizzle", rel, _line(code, m.start(1)), table=m.group(2))
        for start, part in parts:
            key = _KEY.match(part)
            if key and len(model.fields) < MOST_FIELDS:
                model.fields.setdefault(key.group(1), _line(code, m.end() + start + key.start(1)))
        out.append(model)
        if len(out) >= MOST_MODELS:
            break
    return out


# ------------------------------------------------------------------------------------------------- SQL

_CREATE = re.compile(r"\bcreate\s+(?:(?:global\s+|local\s+)?(?:temp|temporary|unlogged)\s+)?table\s+"
                     r"(?:if\s+not\s+exists\s+)?((?:[\w$]+|\"[^\"\n]+\"|`[^`\n]+`|\[[^\]\n]+\])"
                     r"(?:\s*\.\s*(?:[\w$]+|\"[^\"\n]+\"|`[^`\n]+`|\[[^\]\n]+\]))*)\s*\(", re.I)
_COLUMN = re.compile(r"\s*(\"[^\"\n]+\"|`[^`\n]+`|\[[^\]\n]+\]|[A-Za-z_][\w$]*)")
NO_COLUMN = frozenset("constraint primary foreign unique check exclude like index key fulltext spatial period".split())


def sql(text: str, rel: str) -> list[Model]:
    """The tables a SQL file creates, each with its columns (a constraint is no column)."""
    code = code_view(text)[0]
    out: list[Model] = []
    for m in _CREATE.finditer(code):
        parts, end = _top_parts(code[m.end():m.end() + MOST_BODY])
        if end is None:
            continue
        name = m.group(1).split(".")[-1].strip().strip("\"`[]")
        model = Model(name, "sql", rel, _line(code, m.start()), table=name)
        for start, part in parts:
            col = _COLUMN.match(part)
            if not col or col.group(1).lower() in NO_COLUMN or len(model.fields) >= MOST_FIELDS:
                continue
            model.fields.setdefault(col.group(1).strip("\"`[]"), _line(code, m.end() + start + col.start(1)))
        out.append(model)
        if len(out) >= MOST_MODELS:
            break
    return out


# ------------------------------------------------------------------------------------------------- a project

PY_SIGNS = ("Column(", "mapped_column", "Mapped[", "models.", "SQLModel", "AbstractUser", "AbstractBaseUser")
JS_ENDS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")


def of(repo: Path | str) -> Models:
    """The project's models, read once in a run for every rule that asks (`listing.once`); to read, not to change."""
    return listing.once(repo, "datamodel", lambda: read(repo))


def read(repo: Path | str) -> Models:
    """Every model the project's files write down."""
    repo = Path(repo)
    models = Models()
    classes: list[_Class] = []
    seen = {"prisma": 0, "py": 0, "js": 0, "sql": 0}
    for p, _ in listing.files(repo):
        end = p.suffix.lower()
        kind = ("prisma" if end == ".prisma" else "py" if end == ".py" else "sql" if end == ".sql" else
                "js" if end in JS_ENDS and not p.name.endswith(".d.ts") else None)
        if kind is None or seen[kind] >= MOST_FILES or len(models.all) + len(classes) >= MOST_MODELS:
            continue
        rel = p.relative_to(repo).as_posix()
        try:
            text = project_text(p, repo, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE:
            if kind in ("prisma", "sql"):
                models.left_out.append(rel)
            continue
        if kind == "py":
            if any(sign in text for sign in PY_SIGNS):
                seen[kind] += 1
                classes += _classes(text, rel)
        elif kind == "js":
            if "Table(" in text or "TableCreator(" in text:
                seen[kind] += 1
                models.all += drizzle(text, rel)
        else:
            seen[kind] += 1
            models.all += prisma(text, rel) if kind == "prisma" else sql(text, rel)
    models.all += _settled(classes)
    models.all.sort(key=lambda m: (m.file, m.line, m.name))
    return models
