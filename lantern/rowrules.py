"""The row rules a project's SQL files write down (roadmap stage 1, 2026-11-14).

A Supabase project's database is reached straight from the browser with a key every visitor has. What a visitor may
then read or change is decided in the database: a table with row-level security off answers anyone, a table with it
on answers by its policies. This module reads the project's SQL files (Supabase migrations, Prisma migrations,
Drizzle's SQL, any other ``.sql`` file) in the order they are applied and says, for each table they create, whether
row-level security is on at the end and which policies stand.

It reads; it runs nothing and connects to nothing. What the files do not say (a table made in the dashboard, row-level
security switched on by code that runs in the database) is said as not known, never as off.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import listing
from .python_frontend import project_text

MAX_SQL = 4_000_000          # characters of one SQL file that are read; a larger file is named and left out
WRITES = ("insert", "update", "delete")
EVERYONE = {"public", "anon"}                 # roles a visitor who is not signed in has
SIGNED_IN = {"authenticated"}
NOT_VISITORS = {"service_role", "postgres", "supabase_admin", "supabase_auth_admin", "supabase_storage_admin",
                "dashboard_user", "authenticator", "pgbouncer"}

IDENT = r'(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)'
QNAME = rf"({IDENT})(?:\s*\.\s*({IDENT}))?"
_CREATE_TABLE = re.compile(
    rf"create\s+(?P<temp>(?:global\s+|local\s+)?(?:temporary|temp)\s+)?(?:unlogged\s+)?table\s+"
    rf"(?:if\s+not\s+exists\s+)?{QNAME}", re.I)
_ALTER_TABLE = re.compile(rf"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{QNAME}\s*\*?\s+(?P<rest>.*)", re.I | re.S)
_DROP_TABLE = re.compile(r"drop\s+table\s+(?:if\s+exists\s+)?(?P<names>.*?)(?:\s+(?:cascade|restrict))?\s*$", re.I | re.S)
_CREATE_POLICY = re.compile(rf"create\s+policy\s+(?P<name>{IDENT})\s+on\s+{QNAME}(?P<rest>.*)", re.I | re.S)
_ALTER_POLICY = re.compile(rf"alter\s+policy\s+(?P<name>{IDENT})\s+on\s+{QNAME}(?P<rest>.*)", re.I | re.S)
_DROP_POLICY = re.compile(rf"drop\s+policy\s+(?:if\s+exists\s+)?(?P<name>{IDENT})\s+on\s+{QNAME}", re.I)
_RLS = re.compile(r"\b(enable|disable)\s+row\s+level\s+security\b", re.I)
_RENAME = re.compile(rf"\brename\s+to\s+({IDENT})", re.I)
_SET_SCHEMA = re.compile(rf"\bset\s+schema\s+({IDENT})", re.I)
_IN_DATABASE = re.compile(r"row\s+level\s+security", re.I)


@dataclass
class Policy:
    name: str
    command: str                       # all | select | insert | update | delete
    roles: tuple[str, ...]             # as written, ("public",) when the policy names none
    restrictive: bool
    using: str | None                  # the expression as the file writes it
    check: str | None
    using_always: bool                 # the expression is `true` whatever the row and whoever asks
    check_always: bool
    file: str
    line: int

    def who(self) -> str | None:
        """Whom the policy is for: "everyone" (also a visitor who is not signed in), "signed-in", or None when it
        names only roles no visitor has."""
        roles = set(self.roles)
        if roles & EVERYONE:
            return "everyone"
        if roles - NOT_VISITORS:
            return "signed-in"
        return None

    def lets_read(self) -> bool:
        return not self.restrictive and self.command in ("select", "all") and self.using_always

    def lets_write(self) -> tuple[str, ...]:
        """The changes this policy lets every one of its roles make to any row: of insert, update, delete."""
        if self.restrictive:               # a restrictive policy only narrows what the others let through
            return ()
        out = []
        new_row = self.check_always or (self.check is None and self.using_always)   # no check written: `using` is it
        if self.command == "insert" and self.check_always or self.command == "all" and new_row:
            out.append("insert")
        if self.command in ("update", "all") and self.using_always:
            out.append("update")
        if self.command in ("delete", "all") and self.using_always:
            out.append("delete")
        return tuple(out)


@dataclass
class Table:
    name: str
    schema: str
    file: str | None = None            # where the table is created
    line: int | None = None
    rls: bool | None = False           # None: not known (the files do not create the table)
    rls_at: tuple[str, int] | None = None
    policies: list[Policy] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.schema}.{self.name}"

    def narrowed(self, command: str) -> bool:
        """A restrictive policy stands for this kind of change: what the other policies let through is cut down by
        it, and by how much is not read here."""
        return any(p.restrictive and p.command in (command, "all") for p in self.policies)

    def open_writes(self) -> list[tuple[Policy, tuple[str, ...], str]]:
        """(policy, the changes it lets anyone of its roles make to any row, for whom), for each policy that does."""
        out = []
        if self.rls is False:              # nothing is asked of a policy while row-level security is off
            return out
        for p in self.policies:
            who = p.who()
            ways = tuple(w for w in p.lets_write() if not self.narrowed(w))
            if who and ways:
                out.append((p, ways, who))
        return out

    def open_reads(self) -> list[tuple[Policy, str]]:
        if self.rls is False or self.narrowed("select"):
            return []
        return [(p, p.who()) for p in self.policies if p.lets_read() and p.who()]


@dataclass
class State:
    tables: dict[str, Table] = field(default_factory=dict)       # "schema.name" -> Table
    files: list[str] = field(default_factory=list)               # the SQL files, in the order they were applied
    left_out: list[str] = field(default_factory=list)            # SQL files too large to read
    in_database: list[tuple[str, int]] = field(default_factory=list)
    # ^ places where row-level security is named inside code that runs in the database (a function's body, a text
    #   that is executed): which tables that switches on is not known from the file

    def table(self, name: str, schema: str = "public") -> Table | None:
        return self.tables.get(f"{schema}.{name}")

    def off(self, t: Table) -> bool:
        """Whether the files say that row-level security is off for this table: they create it, nothing in them
        switches it on, and no code that runs in the database switches it on for tables the files do not name."""
        return t.file is not None and t.rls is False and not self.in_database


def ident(text: str | None) -> str | None:
    """A name as the database keeps it: a quoted one as written, any other in small letters."""
    if text is None:
        return None
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1].replace('""', '"')
    return text.lower()


def _qname(a: str, b: str | None) -> tuple[str, str]:
    return (ident(a), ident(b)) if b else ("public", ident(a))


def code_view(text: str) -> tuple[str, list[int]]:
    """`text` with every comment, every text in single quotes and every dollar-quoted body blanked (the same length,
    line ends kept), and the offsets where a blanked text or body names row-level security."""
    out = list(text)
    named: list[int] = []
    i, n = 0, len(text)

    def blank(a: int, b: int):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "-" and text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "'":
            escapes = i > 0 and text[i - 1] in "eE" and (i < 2 or not (text[i - 2].isalnum() or text[i - 2] == "_"))
            j = i + 1
            while j < n:
                if escapes and text[j] == "\\":
                    j += 2
                elif text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                    else:
                        break
                else:
                    j += 1
            if _IN_DATABASE.search(text, i + 1, min(j, n)):
                named.append(i)
            blank(i + 1, j)
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                    else:
                        break
                else:
                    j += 1
            i = j + 1
        elif c == "$":
            m = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$").match(text, i)
            if m and not (i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")):
                j = text.find(m.group(0), m.end())
                j = n if j < 0 else j
                if _IN_DATABASE.search(text, m.end(), j):
                    named.append(i)
                blank(m.end(), j)
                i = j + len(m.group(0))
            else:
                i += 1
        else:
            i += 1
    return "".join(out), named


def statements(code: str):
    """(offset of its first word, the statement) for each statement of a code view."""
    start = 0
    for m in re.finditer(r'"(?:[^"]|"")*"|;', code):      # a `;` inside a quoted name ends nothing
        if m.group(0) == ";":
            yield from _one(code, start, m.start())
            start = m.end()
    yield from _one(code, start, len(code))


def _one(code: str, a: int, b: int):
    s = code[a:b]
    lead = len(s) - len(s.lstrip())
    if s.strip():
        yield a + lead, s.strip()


def _closing(code: str, opened: int) -> int:
    """The offset of the bracket that closes the one at `opened`; the end of the text when none does."""
    depth = 0
    for k in range(opened, len(code)):
        if code[k] == "(":
            depth += 1
        elif code[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return len(code)


def always(expr: str | None) -> bool:
    """Whether an expression of a code view is true whatever the row and whoever asks: `true`, `(true)`, `1 = 1`."""
    if expr is None:
        return False
    s = re.sub(r"\s+", "", expr).lower()
    while len(s) >= 2 and s[0] == "(" and _closing(s, 0) == len(s) - 1:
        s = s[1:-1]
    return s in ("true", "1=1", "true::boolean", "true::bool")


def _clauses(code: str, text: str, base: int) -> dict:
    """What follows `on <table>` in a policy statement. `code` is the statement's code view from there, `text` the
    file as written and `base` the offset of `code` in it."""
    out: dict = {}
    depth, k, n = 0, 0, len(code)
    marks: list[tuple[int, str, re.Match]] = []
    word = re.compile(r"(?i)\b(?:(as)\s+(permissive|restrictive)|(for)\s+(all|select|insert|update|delete)|(to)\s+"
                      r"|(using)\s*\(|(with)\s+check\s*\(|(rename)\s+to\s+(" + IDENT + r"))")
    while k < n:
        ch = code[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and (ch.isalpha()) and (k == 0 or not (code[k - 1].isalnum() or code[k - 1] in '_"')):
            m = word.match(code, k)
            if m:
                kind = next(g for g in (m.group(1), m.group(3), m.group(5), m.group(6), m.group(7), m.group(8)) if g).lower()
                marks.append((k, kind, m))
                if kind in ("using", "with"):
                    close = _closing(code, m.end() - 1)
                    key = "using" if kind == "using" else "check"
                    out[key] = text[base + m.end(): base + close].strip()
                    out[key + "_always"] = always(code[m.end(): close])
                    k = close + 1
                    continue
                k = m.end()
                continue
        k += 1
    for idx, (_, kind, m) in enumerate(marks):
        if kind == "as":
            out["restrictive"] = m.group(2).lower() == "restrictive"
        elif kind == "for":
            out["command"] = m.group(4).lower()
        elif kind == "rename":
            out["rename"] = ident(m.group(9))
        elif kind == "to":
            end = marks[idx + 1][0] if idx + 1 < len(marks) else n
            roles = tuple(ident(r) for r in code[m.end(): end].split(",") if r.strip())
            if roles:
                out["roles"] = roles
    return out


def sql_files(repo: Path) -> list[Path]:
    """The project's SQL files in the order they are applied: by folder, then by name (migration tools name their
    files and folders so that this is the order), the seed files after all the others."""
    found = [p for p, _ in listing.files(repo) if p.suffix.lower() == ".sql"]
    return sorted(found, key=lambda p: (p.name.lower().startswith("seed"), p.parent.as_posix(), p.name))


def read(repo: Path | str) -> State:
    """The tables and policies the project's SQL files leave standing."""
    repo = Path(repo)
    st = State()
    for p in sql_files(repo):
        rel = p.relative_to(repo).as_posix()
        try:
            text = project_text(p, repo)
        except OSError:
            continue
        if len(text) > MAX_SQL:
            st.left_out.append(rel)
            continue
        st.files.append(rel)
        apply(st, text, rel)
    return st


def apply(st: State, text: str, rel: str) -> None:
    """Apply one SQL file's statements to the state, in the order written."""
    code, named = code_view(text)
    line = lambda pos: text.count("\n", 0, pos) + 1          # noqa: E731
    st.in_database += [(rel, line(pos)) for pos in named]
    for pos, s in statements(code):
        head = s[:7].lower()
        if head.startswith("create"):
            m = _CREATE_TABLE.match(s)
            if m and not m.group("temp"):
                schema, name = _qname(m.group(2), m.group(3))
                st.tables.setdefault(f"{schema}.{name}", Table(name, schema, rel, line(pos)))
                continue
            m = _CREATE_POLICY.match(s)
            if m:
                schema, name = _qname(m.group(2), m.group(3))
                t = st.tables.get(f"{schema}.{name}")
                if t is None:      # a policy on a table the files do not create (made in the dashboard): kept with it
                    t = st.tables[f"{schema}.{name}"] = Table(name, schema, rls=None)
                c = _clauses(m.group("rest"), text, pos + m.start("rest"))
                t.policies = [q for q in t.policies if q.name != ident(m.group("name"))]
                t.policies.append(Policy(
                    ident(m.group("name")), c.get("command", "all"), c.get("roles", ("public",)),
                    c.get("restrictive", False), c.get("using"), c.get("check"),
                    c.get("using_always", False), c.get("check_always", False), rel, line(pos)))
        elif head.startswith("alter"):
            m = _ALTER_TABLE.match(s)
            if m:
                schema, name = _qname(m.group(1), m.group(2))
                t = st.tables.get(f"{schema}.{name}")
                rest = m.group("rest")
                r = _RLS.search(rest)
                if r:
                    if t is None:
                        t = st.tables[f"{schema}.{name}"] = Table(name, schema, rls=None)
                    t.rls = r.group(1).lower() == "enable"
                    t.rls_at = (rel, line(pos))
                if t is not None:
                    r = _RENAME.search(rest)
                    s2 = _SET_SCHEMA.search(rest)
                    if r and not re.search(r"(?i)\brename\s+(column|constraint)\b", rest):
                        _move(st, t, t.schema, ident(r.group(1)))
                    elif s2:
                        _move(st, t, ident(s2.group(1)), t.name)
                continue
            m = _ALTER_POLICY.match(s)
            if m:
                schema, name = _qname(m.group(2), m.group(3))
                t = st.tables.get(f"{schema}.{name}")
                p = next((q for q in (t.policies if t else []) if q.name == ident(m.group("name"))), None)
                if p is not None:
                    c = _clauses(m.group("rest"), text, pos + m.start("rest"))
                    p.name = c.get("rename", p.name)
                    p.roles = c.get("roles", p.roles)
                    if "using" in c:
                        p.using, p.using_always = c["using"], c["using_always"]
                    if "check" in c:
                        p.check, p.check_always = c["check"], c["check_always"]
        elif head.startswith("drop"):
            m = _DROP_POLICY.match(s)
            if m:
                schema, name = _qname(m.group(2), m.group(3))
                t = st.tables.get(f"{schema}.{name}")
                if t is not None:
                    t.policies = [q for q in t.policies if q.name != ident(m.group("name"))]
                continue
            m = _DROP_TABLE.match(s)
            if m:
                for one in m.group("names").split(","):
                    q = re.fullmatch(rf"\s*{QNAME}\s*", one)
                    if q:
                        schema, name = _qname(q.group(1), q.group(2))
                        st.tables.pop(f"{schema}.{name}", None)


def _move(st: State, t: Table, schema: str, name: str) -> None:
    st.tables.pop(t.key, None)
    t.schema, t.name = schema, name
    st.tables[t.key] = t
