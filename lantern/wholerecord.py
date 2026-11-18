"""`LW-SENSITIVE-COLUMN-RETURNED`: a record sent back whole, with a secret field in it (roadmap of 2026-11-14,
stage 5).

A query that asks for every field of a record, and an answer that hands the record on as it came. Where the
record's model holds a password's hash, a reset token or a key, the secret field is in what the caller gets,
whether or not a page shows it: the browser's own tools show every answer in full. Which fields a model has, and
which of them hold a secret by their names, comes from the project's own model files (`lantern/datamodel.py`).

Read from one function's own code at a time; nothing is run:

* JS/TS (tree-sitter). A Prisma query (`<client>.<model>.findUnique|findFirst|findMany|create|update|upsert|delete`)
  that names no fields, selects a secret one, leaves one in beside an `omit`, or brings a record that has one with
  `include`; a Drizzle query that names no columns (`.select().from(<table>)`, `.query.<table>.findMany()`,
  `.insert|update|delete(<table>)….returning()`). It is a finding where what the query found goes out as it came:
  the query, or the name it was given, stands in an answer (`res.json(x)`, `NextResponse.json({ user })`,
  `new Response(JSON.stringify(x))`, `json(x)`), also inside an object or a list written there, or is returned by a
  function whose result goes to the caller (a file or a function that begins with `"use server"`, a tRPC
  procedure, `getServerSideProps`, a route's `loader`).
* Python (`ast`). A FastAPI route that returns the table's own object (a parameter written with the model's class,
  what a query for it gave, a function of the project written to return one) with no `response_model` and no return
  type that names another class, or whose `response_model` is the table's own class; a Django REST framework
  `ModelSerializer` whose `fields` are `"__all__"` or list the secret field, or whose `exclude` leaves it in, and
  that does not mark it `write_only`.

A heuristic. A name says a secret or it does not; a record handed to a function of the project is not followed
(what comes back may have the field taken out, so nothing is said); a record that reaches the answer under another
name, through another function or through a framework not listed here is not seen.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from tree_sitter import Parser

from . import datamodel, listing
from .js_frontend import LANGS
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import _finding

RULE = "LW-SENSITIVE-COLUMN-RETURNED"
MOST_FILE = 1_000_000       # characters of a file that are read
MOST_FILES = 4_000          # files of a kind that are looked at
MOST_KEPT = 20_000_000      # characters of Python files that are read a second time
MOST_LOOKED = 400           # queries of one file that are asked about
MOST_WALKED = 400_000       # parts of one file's functions gone through for where a record is sent
MOST_FOUND = 200            # findings of one project
MOST_LEAVES = 200           # names and queries read out of one answer
MOST_NAMES = 300            # models whose names are looked for; keys of one object that are read
MOST_SHOWN = 12             # fields of one finding that are listed
DEEP = 3                    # objects and lists inside one another in an answer; records brought with a record
CHAIN = 24                  # calls of one chain that are followed

FUNCS = frozenset({"function_declaration", "function_expression", "arrow_function", "method_definition",
                   "generator_function_declaration", "generator_function"})
WRAPS = frozenset({"await_expression", "parenthesized_expression", "as_expression", "satisfies_expression",
                   "non_null_expression"})
PRISMA_ASKS = ("findUniqueOrThrow", "findUnique", "findFirstOrThrow", "findFirst", "findMany",
               "createManyAndReturn", "updateManyAndReturn", "create", "update", "upsert", "delete")
RES = frozenset({"res", "response", "reply", "resp"})       # what a handler calls the answer it writes
PAGE_PROPS = frozenset({"getServerSideProps", "getStaticProps"})
REMIX = re.compile(r"(^|/)routes/")
SVELTE = re.compile(r"(^|/)\+(?:page|layout)\.server\.[cm]?[jt]s$")
ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete", "api_route"})
# what a query chain ends with where it gives records back (not a count, not a yes or no)
RECORD_ENDS = frozenset("""first one one_or_none all get scalars scalar scalar_one scalar_one_or_none unique
    first_or_404 get_or_404 one_or_404 fetchall fetchone""".split())
SERIALIZERS = frozenset({"ModelSerializer", "HyperlinkedModelSerializer"})
WAYS = {    # how what a function returns gets to the caller
    "action": "by a Server Action, and what a Server Action returns goes to the browser that called it",
    "procedure": "by a tRPC procedure, and what a procedure returns goes to whoever called it",
    "props": "as the page's props, and Next.js writes a page's props into the page it sends",
    "loader": "by the route's loader, and what a loader returns goes to the browser",
}


def _and(names, most: int = 3) -> str:
    names = list(names)
    if len(names) > most:
        names = [*names[:most], f"{len(names) - most} more"]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


# ------------------------------------------------------------------------------------------------- JS / TS

def _text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _line(node) -> int:
    return node.start_point[0] + 1


def _named(node) -> list:
    return [c for c in node.named_children if c.type != "comment"]


def _args(call) -> list:
    got = call.child_by_field_name("arguments")
    return _named(got) if got is not None and got.type == "arguments" else []


def _pairs(obj) -> dict | None:
    """An object written out, as key → the value's node. None where a part of it is not written there (a spread, a
    key worked out when the code runs), so that what it says is not known."""
    out: dict = {}
    for c in obj.named_children:
        if c.type == "pair":
            k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
            key = (_text(k) if k is not None and k.type == "property_identifier" else
                   _text(k)[1:-1] if k is not None and k.type == "string" else None)
            if key is None or v is None:
                return None
            out[key] = v
        elif c.type == "shorthand_property_identifier":
            out[_text(c)] = c
        elif c.type != "comment":
            return None
        if len(out) > MOST_NAMES:
            return None
    return out


def _prisma_brings(model, arg, by_name: dict, depth: int = 0) -> tuple[list[str], str] | None:
    """The secret fields a Prisma query's argument leaves in what comes back, a record's own first and then those
    of the records it brings (`author.passwordHash`), and how the query said it: it asked for fields by name
    (`named`), left some out (`left`), or said nothing and brings them all (`all`).
    None where the argument does not say (it is a name, or part of it is)."""
    secret = model.secret()
    if arg is None:
        return list(secret), "all"
    pairs = _pairs(arg) if arg.type == "object" else None
    if pairs is None:
        return None
    own: list[str] = []
    led: list[str] = []
    select = pairs.get("select")
    if select is not None:
        asked = _pairs(select) if select.type == "object" else None
        if asked is None:
            return None
        for key, value in asked.items():
            if key in model.leads:
                led += _led(model, key, value, by_name, depth)
            elif key in secret and value.type == "true":
                own.append(key)
        return [f for f in secret if f in own] + led, "named"
    left: set[str] = set()
    omit = pairs.get("omit")
    if omit is not None:
        out = _pairs(omit) if omit.type == "object" else None
        if out is None:
            return None
        left = {key for key, value in out.items() if value.type == "true"}
    include = pairs.get("include")
    with_it = _pairs(include) if include is not None and include.type == "object" else None
    for key, value in (with_it or {}).items():
        if key in model.leads:
            led += _led(model, key, value, by_name, depth)
    return [f for f in secret if f not in left] + led, "left" if left else "all"


def _led(model, key: str, value, by_name: dict, depth: int) -> list[str]:
    """The secret fields of the record `key` leads to, as the query brings it: whole (`author: true`), or as its
    own `select`, `omit` and `include` say."""
    to = by_name.get(model.leads[key])
    if to is None or depth >= DEEP:
        return []
    if value.type == "true":
        inner = to.secret()
    elif value.type == "object":
        inner = (_prisma_brings(to, value, by_name, depth + 1) or ([], ""))[0]
    else:
        return []
    return [f"{key}.{f}" for f in inner]


def _columns_named(model, arg, table: str) -> tuple[list[str], str] | None:
    """The secret columns `select({…})` or `returning({…})` names for a Drizzle table (`users.passwordHash`, or the
    whole table under one key); None where the columns are not written out there."""
    pairs = _pairs(arg) if arg.type == "object" else None
    if pairs is None:
        return None
    secret, out = model.secret(), []
    for value in pairs.values():
        if value.type in ("identifier", "shorthand_property_identifier") and _text(value) == table:
            return list(secret), "all"
        if value.type == "member_expression":
            o, p = value.child_by_field_name("object"), value.child_by_field_name("property")
            if o is not None and o.type == "identifier" and _text(o) == table and _text(p) in secret \
                    and _text(p) not in out:
                out.append(_text(p))
    return out, "named"


def _columns_kept(model, arg) -> tuple[list[str], str] | None:
    """The secret columns `<db>.query.<table>.findMany(arg)` brings: all of them, unless `columns` names the ones
    to bring (`id: true`) or the ones to leave (`passwordHash: false`)."""
    secret = model.secret()
    if arg is None:
        return list(secret), "all"
    pairs = _pairs(arg) if arg.type == "object" else None
    if pairs is None:
        return None
    columns = pairs.get("columns")
    if columns is None:
        return list(secret), "all"
    said = _pairs(columns) if columns.type == "object" else None
    if said is None:
        return None
    if any(v.type == "true" for v in said.values()):
        return [f for f in secret if f in said and said[f].type == "true"], "named"
    return [f for f in secret if not (f in said and said[f].type == "false")], "left"


def _below(call) -> list[tuple[str, object]]:
    """The calls a chain was built from, below `call`, the nearest first: for `.returning()` of
    `db.insert(users).values(x).returning()` they are `values` and `insert`."""
    out, cur = [], call
    for _ in range(CHAIN):
        fn = cur.child_by_field_name("function")
        obj = fn.child_by_field_name("object") if fn is not None and fn.type == "member_expression" else None
        inner = obj.child_by_field_name("function") if obj is not None and obj.type == "call_expression" else None
        if inner is None or inner.type != "member_expression":
            break
        out.append((_text(inner.child_by_field_name("property")), obj))
        cur = obj
    return out


def _whole_chain(call):
    """The whole chain `call` is a link of, which is what is waited for (`db.select().from(users).where(…)`). None
    where the code reads something off the result, or a `then` hands it to other code: what goes on is then not
    what the query found."""
    cur = call
    for _ in range(CHAIN):
        p = cur.parent
        if p is None or p.type != "member_expression":
            return cur
        up = p.parent
        if up is None or up.type != "call_expression" or \
                _text(p.child_by_field_name("property")) in ("then", "catch", "finally"):
            return None
        cur = up
    return None


class _Names:
    """The models a JS/TS file may ask for, by the names its code writes, and the pattern that finds the places."""

    def __init__(self, models):
        self.by_name: dict = {}                 # a Prisma model's name → the model
        self.drizzle: dict = {}                 # the name a Drizzle table is kept under → the table, if it has a secret
        for m in models.all:
            if m.kind == "prisma":
                self.by_name.setdefault(m.name, m)
            elif m.kind == "drizzle" and m.secret():
                self.drizzle.setdefault(m.name, m)
        matter = {name for name, m in self.by_name.items() if m.secret()}
        for _ in range(DEEP):                   # and the models that lead to one, which `include` brings with them
            matter |= {name for name, m in self.by_name.items() if matter.intersection(m.leads.values())}
        # the client names a model with its first letter small: `prisma.user`, `prisma.resetRequest`
        self.prisma = {name[:1].lower() + name[1:]: self.by_name[name] for name in sorted(matter)[:MOST_NAMES]}
        for name in sorted(self.drizzle)[MOST_NAMES:]:
            del self.drizzle[name]
        parts = []
        if self.prisma:
            parts.append(rb"\.\s*(?:" + self._any(self.prisma) + rb")\s*\.\s*(" + "|".join(PRISMA_ASKS).encode()
                         + rb")\s*\(")
        if self.drizzle:
            tables = self._any(self.drizzle)
            parts.append(rb"\.\s*query\s*\.\s*(?:" + tables + rb")\s*\.\s*(findMany|findFirst)\s*\(")
            parts.append(rb"\.\s*(from)\s*\(\s*(?:" + tables + rb")\s*[,)]")
            parts.append(rb"\.\s*(returning)\s*\(")
        self.asks = re.compile(b"|".join(parts)) if parts else None

    @staticmethod
    def _any(names) -> bytes:
        return b"|".join(re.escape(n.encode("utf-8")) for n in sorted(names, key=len, reverse=True))


def _query(prop, names: _Names):
    """The query a method's name is part of: the whole expression, its model, the secret fields it brings, whether
    how it said which fields, and how the model was written. None for anything else, and for a query that brings
    no secret field or does not say what it brings."""
    member = prop.parent
    call = member.parent if member is not None and member.type == "member_expression" else None
    if call is None or call.type != "call_expression" or call.child_by_field_name("function").id != member.id:
        return None
    name, args, obj = _text(prop), _args(call), member.child_by_field_name("object")
    via = "drizzle"
    if name == "from":
        table = _text(args[0]) if args and args[0].type == "identifier" else ""
        asked = next((c for n, c in _below(call) if n in ("select", "selectDistinct")), None)
        model = names.drizzle.get(table)
        if model is None or asked is None:
            return None
        cols = _args(asked)
        got = (list(model.secret()), "all") if not cols else _columns_named(model, cols[0], table)
    elif name == "returning":
        made = next((c for n, c in _below(call) if n in ("insert", "update", "delete")), None)
        first = _args(made) if made is not None else []
        table = _text(first[0]) if first and first[0].type == "identifier" else ""
        model = names.drizzle.get(table)
        if model is None:
            return None
        got = (list(model.secret()), "all") if not args else _columns_named(model, args[0], table)
    else:
        if obj is None or obj.type != "member_expression":
            return None
        owner, under = _text(obj.child_by_field_name("property")), obj.child_by_field_name("object")
        if name in ("findMany", "findFirst") and owner in names.drizzle and under is not None \
                and under.type == "member_expression" and _text(under.child_by_field_name("property")) == "query":
            model = names.drizzle[owner]
            got = _columns_kept(model, args[0] if args else None)
        elif owner in names.prisma and name in PRISMA_ASKS:
            model, via = names.prisma[owner], "prisma"
            got = _prisma_brings(model, args[0] if args else None, names.by_name)
        else:
            return None
    if not got or not got[0]:
        return None
    whole = _whole_chain(call) if via == "drizzle" else \
        None if call.parent is not None and call.parent.type == "member_expression" else call
    return None if whole is None else (whole, model, got[0], got[1], via)


def _begins_with(block, words: str) -> bool:
    """Does a file or a function's body begin with that directive (`"use server"`)?"""
    for c in block.named_children:
        if c.type == "comment":
            continue
        inner = c.named_children[0] if c.type == "expression_statement" and c.named_child_count == 1 else None
        if inner is None or inner.type != "string":
            return False
        if _text(inner)[1:-1] == words:
            return True
    return False


def _procedure(node) -> bool:
    """Is this what a tRPC procedure is built on (`publicProcedure.input(…)`, `t.procedure`)?"""
    cur = node
    for _ in range(CHAIN):
        if cur is None:
            return False
        if cur.type == "identifier":
            return "procedure" in _text(cur).lower()
        if cur.type == "member_expression":
            if "procedure" in _text(cur.child_by_field_name("property")).lower():
                return True
            cur = cur.child_by_field_name("object")
        elif cur.type == "call_expression":
            cur = cur.child_by_field_name("function")
        else:
            return False
    return False


def _sender(call):
    """What a call sends to the caller, if it is one that writes an answer: its first argument, or None."""
    fn, args = call.child_by_field_name("function"), _args(call)
    if fn is None or not args:
        return None
    if fn.type == "identifier":
        return args[0] if _text(fn) == "json" else None             # `json(x)`: SvelteKit, Remix
    if fn.type != "member_expression":
        return None
    name = _text(fn.child_by_field_name("property"))
    if name == "json":                                              # res.json(x), NextResponse.json(x), c.json(x)
        return args[0]
    if name in ("send", "end"):                                     # res.send(x), reply.code(200).send(x)
        cur = fn.child_by_field_name("object")
        for _ in range(CHAIN):
            if cur is None or cur.type == "identifier":
                break
            cur = cur.child_by_field_name("function" if cur.type == "call_expression" else "object") \
                if cur.type in ("call_expression", "member_expression") else None
        return args[0] if cur is not None and _text(cur) in RES else None
    return None


def _leaves(node) -> tuple[list[tuple[str, object]], int]:
    """What an answer hands on as it came: the names and the calls that stand in it by themselves, also as a value
    of an object or an item of a list written there (`DEEP` of them inside one another at most), under `await`,
    `JSON.stringify(…)` and `x ?? null`. A field read off a name (`user.id`) and a name handed to a function are
    not the record as it came."""
    out: list[tuple[str, object]] = []
    todo, steps = [(node, 0)], 0
    while todo and steps < 4 * MOST_LEAVES and len(out) < MOST_LEAVES:
        cur, depth = todo.pop()
        steps += 1
        kind = cur.type
        if kind in WRAPS:
            inner = cur.named_children[:1]
            todo += [(inner[0], depth)] if inner else []
        elif kind in ("identifier", "shorthand_property_identifier"):
            out.append(("name", cur))
        elif kind == "call_expression":
            fn, args = cur.child_by_field_name("function"), _args(cur)
            if fn is not None and fn.type == "member_expression" and args and fn.end_byte - fn.start_byte < 40 \
                    and "".join(_text(fn).split()) == "JSON.stringify":
                todo.append((args[0], depth))
            else:
                out.append(("call", cur))
        elif kind in ("object", "array") and depth < DEEP:
            for c in cur.named_children[:MOST_LEAVES]:
                if c.type == "pair":
                    c = c.child_by_field_name("value")
                elif c.type == "spread_element":
                    c = c.named_children[0] if c.named_child_count else None
                if c is not None and c.type != "comment":
                    todo.append((c, depth + 1))
        elif kind == "ternary_expression":
            todo += [(c, depth) for c in (cur.child_by_field_name("consequence"),
                                          cur.child_by_field_name("alternative")) if c is not None]
        elif kind == "binary_expression":
            op = cur.child_by_field_name("operator")
            if op is not None and op.type in ("??", "||"):
                todo += [(c, depth) for c in (cur.child_by_field_name("left"),
                                              cur.child_by_field_name("right")) if c is not None]
    return out, steps


class _Facts:
    """What one function's code does with what it has."""
    __slots__ = ("calls", "names", "given", "gone")

    def __init__(self):
        self.calls: dict[tuple[int, int], tuple[int, str]] = {}     # a call that is sent as it came → line, way
        self.names: dict[str, list[tuple[int, int, str]]] = {}      # a name that is sent → where, line, way
        self.given: dict[str, list[int]] = {}                       # where a name is given a value
        self.gone: dict[str, list[tuple[str, int]]] = {}            # fields taken off a name's record → where


class _File:
    """Where one JS/TS file sends what it has, read once for each function a query stands in."""

    def __init__(self, root, rel: str):
        self.root, self.rel = root, rel
        self.walked = 0
        self.read: dict[int, _Facts | None] = {}
        self.served = _begins_with(root, "use server")

    def sent(self, expr) -> tuple[int, str, set[str]] | None:
        """Where what `expr` found goes out as it came: the line, the way, and the fields taken off it before."""
        fn = expr.parent
        while fn is not None and fn.type not in FUNCS:
            fn = fn.parent
        fn = fn if fn is not None else self.root
        if fn.id not in self.read:
            self.read[fn.id] = self._facts(fn)
        facts = self.read[fn.id]
        if facts is None:
            return None
        direct = facts.calls.get((expr.start_byte, expr.end_byte))
        if direct is not None:
            return direct[0], direct[1], set()
        name, at = _kept_as(expr), expr.start_byte
        if name is None:
            return None
        again = min((p for p in facts.given.get(name, ()) if p > at), default=None)
        for where, line, way in facts.names.get(name, ()):
            if where > at and (again is None or where < again):
                return line, way, {f for f, p in facts.gone.get(name, ()) if at < p < where}
        return None

    def _to_caller(self, fn) -> str | None:
        """Does what this function returns go to whoever called the app, and how?"""
        if fn.type == "program":
            return None
        body, p = fn.child_by_field_name("body"), fn.parent
        if body is not None and body.type == "statement_block" and _begins_with(body, "use server"):
            return "action"
        name, exported = "", False
        if fn.type in ("function_declaration", "generator_function_declaration"):
            name, exported = _text(fn.child_by_field_name("name")), p is not None and p.type == "export_statement"
        elif p is not None and p.type == "variable_declarator":
            said = p.child_by_field_name("name")
            name = _text(said) if said is not None and said.type == "identifier" else ""
            outer = p.parent.parent if p.parent is not None else None
            exported = outer is not None and outer.type == "export_statement"
        elif p is not None and p.type == "arguments":
            call = p.parent
            callee = call.child_by_field_name("function") if call is not None and call.type == "call_expression" \
                else None
            if callee is not None and callee.type == "member_expression" \
                    and _text(callee.child_by_field_name("property")) in ("query", "mutation") \
                    and _procedure(callee.child_by_field_name("object")):
                return "procedure"
        if not exported:
            return None
        if self.served:
            return "action"
        if name in PAGE_PROPS:
            return "props"
        if (name in ("loader", "action") and REMIX.search(self.rel)) or (name == "load" and SVELTE.search(self.rel)):
            return "loader"
        return None

    def _sink(self, node, way: str, facts: _Facts) -> None:
        got, steps = _leaves(node)
        self.walked += steps
        for kind, leaf in got:
            if kind == "name":
                facts.names.setdefault(_text(leaf), []).append((leaf.start_byte, _line(leaf), way))
            else:
                facts.calls.setdefault((leaf.start_byte, leaf.end_byte), (_line(leaf), way))

    def _facts(self, fn) -> _Facts | None:
        """One walk of a function's code: what it sends, what it gives names to, what it takes off a record. Code
        of a function written inside it is gone through too (an answer may be written there), but what such a
        function returns is not what this one returns. None when the file's budget is used up: nothing is said
        from a part of a function."""
        facts, way = _Facts(), self._to_caller(fn)
        body = fn if fn.type == "program" else fn.child_by_field_name("body")
        if body is None:
            return facts
        if way and body.type != "statement_block":
            self._sink(body, way, facts)                    # an arrow function that is one expression
        todo = [(body, False)]
        while todo:
            node, inner = todo.pop()
            self.walked += 1
            if self.walked > MOST_WALKED:
                return None
            kind = node.type
            if kind == "call_expression":
                sent = _sender(node)
                if sent is not None:
                    self._sink(sent, "answer", facts)
            elif kind == "new_expression":
                made, args = node.child_by_field_name("constructor"), _args(node)
                if args and made is not None and made.type == "identifier" \
                        and _text(made) in ("Response", "NextResponse"):
                    self._sink(args[0], "answer", facts)
            elif kind == "return_statement":
                value = _named(node)[:1] if way and not inner else []
                if value:
                    self._sink(value[0], way, facts)
            elif kind == "unary_expression":
                op, arg = node.child_by_field_name("operator"), node.child_by_field_name("argument")
                if op is not None and op.type == "delete" and arg is not None:
                    self._taken(arg, facts)
            elif kind == "assignment_expression":
                left = node.child_by_field_name("left")
                if left is not None and left.type == "identifier":
                    facts.given.setdefault(_text(left), []).append(left.start_byte)
                elif left is not None:
                    self._taken(left, facts)
            elif kind == "variable_declarator":
                said = node.child_by_field_name("name")
                names, look = [], [said] if said is not None else []
                while look and len(names) < 40:
                    cur = look.pop()
                    if cur.type in ("identifier", "shorthand_property_identifier_pattern"):
                        names.append(cur)
                    elif cur.type.endswith("pattern"):
                        look += cur.named_children[:40]
                for n in names:
                    facts.given.setdefault(_text(n), []).append(n.start_byte)
            inner = inner or kind in FUNCS
            todo += [(c, inner) for c in node.named_children if c.child_count]
        for places in facts.names.values():
            places.sort()
        return facts

    @staticmethod
    def _taken(node, facts: _Facts) -> None:
        """`delete user.passwordHash`, `user.passwordHash = undefined`, `user["passwordHash"] = …`: the field is no
        longer on the record that name holds."""
        o = node.child_by_field_name("object")
        if o is None or o.type != "identifier":
            return
        if node.type == "member_expression":
            field = _text(node.child_by_field_name("property"))
        elif node.type == "subscript_expression":
            index = node.child_by_field_name("index")
            field = _text(index)[1:-1] if index is not None and index.type == "string" else ""
        else:
            return
        if field:
            facts.gone.setdefault(_text(o), []).append((field, node.start_byte))


def _kept_as(expr) -> str | None:
    """The name what a query found is given: `const user = await …`, `user = await …`, `const [user] = await …`
    (the first of the rows), and `const [user, posts] = await Promise.all([…, …])` for the query at that place."""
    cur, index = expr, None
    for _ in range(8):
        p = cur.parent
        if p is None:
            return None
        if p.type in WRAPS:
            cur = p
        elif p.type == "array" and index is None:
            up = p.parent
            call = up.parent if up is not None and up.type == "arguments" else None
            fn = call.child_by_field_name("function") if call is not None and call.type == "call_expression" \
                else None
            if fn is None or fn.end_byte - fn.start_byte > 40 or "".join(_text(fn).split()) != "Promise.all":
                return None
            index = next((i for i, c in enumerate(_named(p)[:MOST_NAMES]) if c.id == cur.id), None)
            if index is None:
                return None
            cur = call
        elif p.type == "variable_declarator":
            said, value = p.child_by_field_name("name"), p.child_by_field_name("value")
            if said is None or value is None or value.id != cur.id:
                return None
            if said.type == "identifier":
                return _text(said) if index is None else None
            if said.type == "array_pattern":
                items = said.named_children
                at = 0 if index is None else index
                if at < len(items) and items[at].type == "identifier" and (index is not None or len(items) == 1):
                    return _text(items[at])
            return None
        elif p.type == "assignment_expression":
            left, right = p.child_by_field_name("left"), p.child_by_field_name("right")
            ours = left is not None and right is not None and right.id == cur.id and left.type == "identifier"
            return _text(left) if ours and index is None else None
        else:
            return None
    return None


def js_file(text: str, rel: str, models, names: _Names | None = None) -> list[dict]:
    """The queries of one JS/TS file whose record, with a secret field in it, is sent back as it came. At most
    `MOST_LOOKED` places of a file are asked about, and `MOST_WALKED` parts of its functions gone through."""
    names = names or _Names(models)
    if names.asks is None:
        return []
    data = text.encode("utf-8", "replace")
    places = []
    for m in names.asks.finditer(data):
        places.append(m.start(m.lastindex))
        if len(places) >= MOST_LOOKED:
            break
    if not places:
        return []
    end = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    root = Parser(LANGS.get(end, LANGS[".tsx"])).parse(data).root_node
    file, out, seen = _File(root, rel), [], set()
    for at in places:
        prop = root.descendant_for_byte_range(at, at + 1)
        got = _query(prop, names) if prop is not None and prop.type == "property_identifier" else None
        if got is None or got[0].start_byte in seen:
            continue
        expr, model, fields, how, via = got
        seen.add(expr.start_byte)
        sent = file.sent(expr)
        if sent is None:
            continue
        line, way, gone = sent
        fields = [f for f in fields if f not in gone]
        if not fields:
            continue
        hit = {"line": _line(expr), "model": model, "fields": fields, "via": via, "sent": line, "way": way,
               "how": how}
        if "." in fields[0]:                    # nothing of its own: the record it leads to brings the secret field
            path = fields[0].rsplit(".", 1)[0]
            to = model
            for part in path.split("."):
                to = names.by_name.get(to.leads.get(part, "")) if to is not None else None
            hit["led"] = {"path": path, "to": to,
                          "fields": [f.rsplit(".", 1)[1] for f in fields if f.rsplit(".", 1)[0] == path]}
        out.append(hit)
    return out


# ------------------------------------------------------------------------------------------------- Python

def _cls(node) -> str:
    """The class a name stands for, by its last part: `User`, `models.User`."""
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""


def _type_names(node, known) -> str:
    """The one of `known` that a written type names: `User`, `User | None`, `Optional[User]`, `list[User]`,
    `Annotated[User, Depends(…)]`, `"User"`. Empty when it names none."""
    todo, steps = [node], 0
    while todo and steps < 40:
        cur = todo.pop()
        steps += 1
        if isinstance(cur, ast.Constant) and isinstance(cur.value, str):
            if cur.value in known:
                return cur.value
        elif isinstance(cur, (ast.Name, ast.Attribute)):
            if _cls(cur) in known:
                return _cls(cur)
        elif isinstance(cur, ast.BinOp):
            todo += [cur.right, cur.left]
        elif isinstance(cur, ast.Subscript):
            inner = cur.slice.elts[:1] if _cls(cur.value) == "Annotated" and isinstance(cur.slice, ast.Tuple) else \
                list(cur.slice.elts) if isinstance(cur.slice, ast.Tuple) else [cur.slice]
            todo += reversed(inner)
    return ""


def py_facts(tree: ast.Module, tables) -> tuple[dict[str, str], dict[str, str]]:
    """What a Python file says that other files build on: the names that stand for a table's class with what a
    route needs to get one (`CurrentUser = Annotated[User, Depends(current_user)]`), and its functions written to
    return one (`def by_email(…) -> User | None`)."""
    stand, give = {}, {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            name, value = node.target.id, node.value
        else:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None \
                    and not _routed(node):
                model = _type_names(node.returns, tables)
                if model:
                    give[node.name] = model
            continue
        if isinstance(value, ast.Subscript) and _cls(value.value) == "Annotated":
            model = _type_names(value, tables)
            if model:
                stand[name] = model
    return stand, give


def _routed(fn):
    """The decorator that makes a function a route (`@app.get("/users")`, `@router.post(…)`), or None."""
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_VERBS \
                and d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
            return d
    return None


def _record(expr, tables, give) -> str:
    """The table whose object an expression gives: `User(…)`, `db.get(User, id)`, a chain that asks for it and ends
    in records (`db.query(User).filter(…).first()`, `db.scalars(select(User)).all()`), or a function of the
    project written to return one. Empty for anything else."""
    if isinstance(expr, ast.Await):
        expr = expr.value
    if not isinstance(expr, ast.Call):
        return ""
    fn = expr.func
    if _cls(fn) in tables:
        return _cls(fn)
    if isinstance(fn, ast.Name):
        return give.get(fn.id, "")
    if not isinstance(fn, ast.Attribute):
        return ""
    if fn.attr == "get" and expr.args and _cls(expr.args[0]) in tables:
        return _cls(expr.args[0])
    if isinstance(fn.value, ast.Name) and give.get(fn.attr):
        return give[fn.attr]
    if fn.attr not in RECORD_ENDS:
        return ""
    todo, steps = [expr], 0
    while todo and steps < 2 * CHAIN:
        cur = todo.pop()
        steps += 1
        if isinstance(cur, ast.Await):
            todo.append(cur.value)
        elif isinstance(cur, ast.Call):
            if _cls(cur.func) in ("query", "select") and len(cur.args) == 1 and _cls(cur.args[0]) in tables:
                return _cls(cur.args[0])
            todo += [a for a in cur.args[:3] if isinstance(a, (ast.Call, ast.Await))]
            todo.append(cur.func)
        elif isinstance(cur, (ast.Attribute, ast.Subscript)):
            todo.append(cur.value)
    return ""


def _blocks(st) -> list:
    """The statements inside a statement, in the order written."""
    out = []
    for part in ("body", "handlers", "orelse", "finalbody", "cases"):
        for inner in getattr(st, part, None) or ():
            out += inner.body if isinstance(inner, (ast.ExceptHandler, ast.match_case)) else [inner]
    return out


def _routes(tree: ast.Module, tables, stand, give) -> list[dict]:
    out = []
    for fn in ast.walk(tree):
        deco = _routed(fn) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        if deco is None:
            continue
        returns = [st for st in ast.walk(fn) if isinstance(st, ast.Return) and st.value is not None][:MOST_LEAVES]
        shape = next((k.value for k in deco.keywords if k.arg == "response_model"), None)
        if isinstance(shape, ast.Constant) and shape.value is None:
            shape = None
        said = shape if shape is not None else fn.returns
        if said is not None:                    # the answer's shape is written: it is the table's own class, or not
            model = _type_names(said, tables)
            if model:
                out.append({"line": said.lineno, "model": tables[model], "fields": tables[model].secret(),
                            "how": "`response_model`" if shape is not None else "its return type",
                            "via": tables[model].kind, "sent": min((r.lineno for r in returns), default=said.lineno),
                            "way": "shape", "route": fn.lineno})
            continue
        held: dict[str, tuple[str, int, str]] = {}      # a name → the table whose object it holds, since where
        for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
            model = "" if a.annotation is None else \
                _type_names(a.annotation, tables) or stand.get(_cls(a.annotation), "")
            if model:
                held[a.arg] = (model, a.lineno, "a parameter")
        seen: set[int] = set()
        todo = list(reversed(fn.body))
        while todo:
            st = todo.pop()
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            target = st.targets[0] if isinstance(st, ast.Assign) and len(st.targets) == 1 else \
                st.target if isinstance(st, ast.AnnAssign) and st.value is not None else None
            if isinstance(target, ast.Name):
                model = _record(st.value, tables, give)
                if model:
                    held[target.id] = (model, st.lineno, "")
                else:
                    held.pop(target.id, None)
            elif isinstance(st, ast.Return) and st.value is not None:
                look, steps = [(st.value, 0)], 0
                while look and steps < MOST_LEAVES:
                    cur, depth = look.pop()
                    steps += 1
                    got = None
                    if isinstance(cur, ast.Await):
                        look.append((cur.value, depth))
                    elif isinstance(cur, ast.Name):
                        got = held.get(cur.id)
                    elif isinstance(cur, ast.Call):
                        model = _record(cur, tables, give)
                        got = (model, cur.lineno, "") if model else None
                    elif isinstance(cur, ast.Dict) and depth < DEEP:
                        look += [(v, depth + 1) for v in cur.values[:MOST_LEAVES] if v is not None]
                    elif isinstance(cur, (ast.List, ast.Tuple, ast.Set)) and depth < DEEP:
                        look += [(v, depth + 1) for v in cur.elts[:MOST_LEAVES]]
                    elif isinstance(cur, ast.IfExp):
                        look += [(cur.body, depth), (cur.orelse, depth)]
                    if got and got[1] not in seen:
                        seen.add(got[1])
                        model = tables[got[0]]
                        out.append({"line": got[1], "model": model, "fields": model.secret(), "via": model.kind,
                                    "sent": st.lineno, "way": "route", "route": fn.lineno, "how": got[2]})
            todo += reversed(_blocks(st))
    return out


def _true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _serializers(tree: ast.Module, django, users) -> list[dict]:
    """The Django REST framework serializers of a file that send a model's secret field. `users`: the project's
    models for who signs in, which `get_user_model()` stands for when there is one."""
    out = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not any(_cls(b) in SERIALIZERS for b in node.bases):
            continue
        meta = next((s for s in node.body if isinstance(s, ast.ClassDef) and s.name == "Meta"), None)
        said = {s.targets[0].id: s for s in (meta.body if meta is not None else ())
                if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name)}
        of = said.get("model")
        if of is None:
            continue
        if isinstance(of.value, ast.Call) and _cls(of.value.func) == "get_user_model":
            model = users[0] if len(users) == 1 else None
        else:
            model = django.get(_cls(of.value))
        if model is None:
            continue
        not_sent: set[str] = set()              # marked `write_only`, or a field the serializer makes itself
        extra = said.get("extra_kwargs")
        if extra is not None and isinstance(extra.value, ast.Dict):
            for key, value in zip(extra.value.keys, extra.value.values):
                if isinstance(key, ast.Constant) and isinstance(value, ast.Dict) and any(
                        isinstance(k, ast.Constant) and k.value == "write_only" and _true(v)
                        for k, v in zip(value.keys, value.values)):
                    not_sent.add(key.value)
        for s in node.body:
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) \
                    and isinstance(s.value, ast.Call):
                if any(k.arg == "write_only" and _true(k.value) for k in s.value.keywords) \
                        or _cls(s.value.func) == "SerializerMethodField":
                    not_sent.add(s.targets[0].id)
        fields, exclude = said.get("fields"), said.get("exclude")
        secret = model.secret()
        if fields is not None and isinstance(fields.value, ast.Constant) and fields.value.value == "__all__":
            shown, how, at = list(secret), "all", fields.lineno
        elif fields is not None and isinstance(fields.value, (ast.List, ast.Tuple)):
            listed = {e.value for e in fields.value.elts if isinstance(e, ast.Constant)}
            shown, how, at = [f for f in secret if f in listed], "listed", fields.lineno
        elif exclude is not None and isinstance(exclude.value, (ast.List, ast.Tuple)):
            left = {e.value for e in exclude.value.elts if isinstance(e, ast.Constant)}
            shown, how, at = [f for f in secret if f not in left], "left", exclude.lineno
        else:
            continue
        shown = [f for f in shown if f not in not_sent]
        if shown:
            out.append({"line": at, "model": model, "fields": shown, "via": "django", "sent": at, "way": how,
                        "by": node.name})
    return out


def py_file(text: str, rel: str, models, project: dict) -> list[dict]:
    """The routes and serializers of one Python file that send a table's own object, with a secret field in it.
    `project`: what the project's other files say (`py_facts` of each: `stand`, `give`)."""
    tables = {m.name: m for m in reversed(models.all) if m.kind in ("sqlalchemy", "sqlmodel") and m.secret()}
    django = {m.name: m for m in reversed(models.all) if m.kind == "django" and m.secret()}
    routes = bool(tables) and "fastapi" in text
    if not routes and not (django and "Serializer" in text):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    out = []
    if routes:
        stand, give = py_facts(tree, tables)
        out += _routes(tree, tables, {**(project.get("stand") or {}), **stand},
                       {**(project.get("give") or {}), **give})
    if django:
        out += _serializers(tree, django, [m for m in models.all if m.kind == "django" and "password" in m.inherited])
    return out


# ------------------------------------------------------------------------------------------------- a project

def _a(name: str) -> str:
    return ("An " if name[:1].lower() in "aeio" else "A ") + name


def _why(model, fields: list[str]) -> str:
    """Why these fields hold a secret: their own names say so, or the model's own name does and they keep its value
    (`Password.hash`, `ApiKey.key`)."""
    own, many = [f for f in fields if datamodel.secret_column(f)], len(fields) > 1
    if len(own) == len(fields):
        return "whose names say a secret" if many else "whose name says a secret"
    if not own:
        return (f"which keep{'' if many else 's'} the value in a model whose own name says it holds a secret "
                f"({model.name})")
    return f"whose names, or the name of {model.name} itself, say a secret"


def _plain(model, most: int) -> list[str]:
    """Fields of a model that hold no secret and lead nowhere, for an example a person can copy."""
    secret = set(model.secret())
    return [f for f in model.fields if f not in secret and f not in model.leads][:most] or ["id"]


def _words(rel: str, hit: dict) -> tuple[str, str]:
    """A finding's title and what it says, from what was read."""
    model, fields, via, sent, way = hit["model"], hit["fields"], hit["via"], hit["sent"], hit["way"]
    many = len(fields) > 1
    names = _and(fields, MOST_SHOWN)
    s, it = ("s", "these fields") if many else ("", "this field")
    no_harm = f"This is no problem only where {'a' if many else 'the'} field holds no secret after all, or where "
    if via == "django":
        by = hit["by"]
        title = {"all": f"{by} sends every field of {model.name}, {_and(fields)} with it",
                 "left": f"{by} sends every field of {model.name} it does not exclude, {_and(fields)} with it",
                 "listed": f"{by} lists the field{s} {_and(fields)} of {model.name} among what it sends"}[way]
        how = {"all": 'its `fields` are `"__all__"`', "left": f"its `exclude` does not name the secret field{s}",
               "listed": f"its `fields` list the secret field{s}"}[way]
        return title, (
            "Heuristic: read from the model file and from this serializer's own lines; nothing was run. "
            f"{by} is a serializer of {model.name} ({model.file} line {model.line}), and {how}. {model.name} has the "
            f"field{s} {names}, {_why(model, fields)}"
            + (" (Django keeps the password's hash there)" if "password" in fields else "") + ". A serializer is "
            f"what a view sends back, so {it} {'are' if many else 'is'} in the answer of every view that uses this "
            f"serializer. Take {'them' if many else 'it'} out of what the serializer sends, or mark "
            f'{"each" if many else "it"} `extra_kwargs = {{"{fields[0]}": {{"write_only": True}}}}`, which still '
            f"lets a request set it. {no_harm}no view uses this serializer for an answer; Lantern does not follow "
            "which views do.")
    if via in ("sqlalchemy", "sqlmodel"):
        title = f"{_a(model.name)} record is sent back whole, with its {_and(fields)}"
        if way == "shape":
            how = (f"The route on line {hit['route']} says on line {hit['line']} what its answer holds "
                   f"({hit['how']}), and names {model.name} itself, so the answer has every field of the table.")
        else:
            since = ("" if hit["line"] == sent else f" ({hit['how']} on line {hit['line']})" if hit["how"] else
                     f" (what line {hit['line']} gave it)")
            how = (f"The route on line {hit['route']} returns such an object on line {sent}{since}, and nothing says "
                   "what the answer may hold: no `response_model` on the route and no return type that names "
                   "another class. FastAPI then sends every field the object has loaded.")
        return title, (
            "Heuristic: read from the model file and from this route's own lines; nothing was run. "
            f"{model.name} is the table's own class ({model.file} line {model.line}) and has the field{s} {names}, "
            f"{_why(model, fields)}. {how} So whoever calls the route gets {it}, whether or not a page shows "
            f"{'them' if many else 'it'}. Give the answer a class of its own with only the fields a caller needs "
            f"(`response_model={model.name}Out`), and FastAPI leaves the rest out. "
            + (f"This is no problem only where {'a' if many else 'the'} field holds no secret after all."
               if way == "shape" else
               f"{no_harm}the object's fields are not loaded when it is returned (after a commit SQLAlchemy lets "
               "them go until they are asked for again); Lantern does not see that."))
    noun, field = ("row", "column") if via == "drizzle" else ("record", "field")
    holds = (f"{'The table ' if via == 'drizzle' else ''}{model.name} is written in {model.file} (line {model.line}) "
             f"and has the {field}{s} {names}, {_why(model, fields)}.")
    led, how = hit.get("led"), hit["how"]
    if led:
        to, inner = led["to"], led["fields"]
        whole = "the whole " if to is not None and how != "named" and set(inner) >= set(to.secret()) else "the "
        what = to.name if to is not None else noun
        last = led["path"].rsplit(".", 1)[-1]
        title = (f"{_a(model.name)} {noun} is sent back with {whole}{what} it leads to ({led['path']}), "
                 f"{_and(inner)} with it")
        brings = f"brings {whole}{what} each {model.name} leads to ({led['path']})"
        if to is not None:
            holds = (f"{to.name} is written in {to.file} (line {to.line}) and has the field"
                     f"{'s' if len(inner) > 1 else ''} {_and(inner, MOST_SHOWN)}, {_why(to, inner)}.")
        keep = _plain(to, 1)[0] if to is not None else "id"
        do = (f"Say which fields of it go back: `{last}: {{ select: {{ {keep}: true }} }}` in place of `{last}: true`, "
              f"or `{last}: {{ omit: {{ {', '.join(f'{f}: true' for f in inner[:3])} }} }}`, or build the answer "
              "from the fields a page needs.")
    elif via == "prisma":
        title = (f"{_a(model.name)} record is sent back with its {_and(fields)}, which the query asks for by name"
                 if how == "named" else f"{_a(model.name)} record is sent back whole, with its {_and(fields)}")
        brings = {"named": f"asks for {names} by name",
                  "left": f"leaves some fields out and brings every other field of {model.name}",
                  "all": f"names no fields, so it brings every field of {model.name}"}[how]
        do = ("Say which fields go back: `select: { " + ", ".join(f"{f}: true" for f in _plain(model, 2))
              + " }` in the query, or `omit: { " + ", ".join(f"{f}: true" for f in fields[:3] if "." not in f)
              + " }`, or build the answer from the fields a page needs.")
    else:
        title = (f"{_a(model.name)} row is sent back with its {_and(fields)}, which the query asks for by name"
                 if how == "named" else f"{_a(model.name)} row is sent back whole, with its {_and(fields)}")
        brings = {"named": f"asks for {names} by name",
                  "left": f"leaves some columns out and brings every other column of {model.name}",
                  "all": f"names no columns, so it brings every column of {model.name}"}[how]
        c = _plain(model, 1)[0]
        do = (f"Name the columns that go back (`db.select({{ {c}: {model.name}.{c} }})`, `columns: {{ {c}: true }}`, "
              f"`.returning({{ {c}: {model.name}.{c} }})`), or build the answer from the fields a page needs.")
    line = "the same line" if sent == hit["line"] else f"line {sent}"
    goes = (f"What it found goes into the answer written on {line} as it came." if way == "answer" else
            f"What it found is returned on {line} {WAYS[way]}.")
    return title, (
        f"Heuristic: read from the model file and from this function's own lines; nothing was run. The query on line "
        f"{hit['line']} {brings}. {holds} {goes} So whoever gets the answer gets {it}, whether or not a page shows "
        f"{'them' if many else 'it'}: a browser's own tools show every answer in full. {do} {no_harm}code Lantern "
        "did not follow takes the field out first (it reads this one function, and follows what the query found "
        "only under the name it was given there).")


def sent_whole(g) -> list[dict]:
    """LW-SENSITIVE-COLUMN-RETURNED: one finding for each query, route or serializer that sends back a record whose
    model has a secret field, with that field in it, on the line of the query (a route: where it has the object; a
    serializer: where it says which fields)."""
    repo = Path(g.repo_root)
    models = datamodel.of(repo)
    if not any(m.secret() for m in models.all):
        return []
    names = _Names(models)
    tables = [m.name for m in models.all if m.kind in ("sqlalchemy", "sqlmodel") and m.secret()]
    django = any(m.kind == "django" and m.secret() for m in models.all)
    a_table = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in sorted(set(tables))[:MOST_NAMES]) + r")\b") \
        if tables else None
    hits: list[tuple[str, dict]] = []
    python: list[tuple[str, str]] = []
    looked, kept = {"js": 0, "py": 0}, 0
    for p, _parts in listing.files(repo):
        end = p.suffix.lower()
        kind = "js" if end in datamodel.JS_ENDS and names.asks is not None else \
            "py" if end == ".py" and (tables or django) else None
        if kind is None or looked[kind] >= MOST_FILES or len(hits) >= MOST_FOUND:
            continue
        rel = p.relative_to(repo).as_posix()
        if NOT_THE_APP.search(rel):
            continue
        try:
            text = project_text(p, repo, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE:
            continue
        looked[kind] += 1
        if kind == "js":
            hits += [(rel, h) for h in js_file(text, rel, models, names)]
        elif kept + len(text) <= MOST_KEPT and (
                (django and "Serializer" in text) or (a_table is not None and ("fastapi" in text
                                                                                or a_table.search(text)))):
            python.append((rel, text))
            kept += len(text)
    project: dict = {"stand": {}, "give": {}}
    if a_table is not None:
        for _rel, text in python:               # first what every file says that the others build on
            if not a_table.search(text):
                continue
            try:
                stand, give = py_facts(ast.parse(text), set(tables))
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
            project["stand"].update(stand)
            for name, model in give.items():    # two functions of one name that give different things: not known
                project["give"][name] = model if project["give"].get(name, model) == model else ""
    for rel, text in python:
        hits += [(rel, h) for h in py_file(text, rel, models, project)]
    out, seen = [], set()
    for rel, hit in sorted(hits, key=lambda x: (x[0], x[1]["line"])):
        if (rel, hit["line"]) in seen or len(out) >= MOST_FOUND:
            continue
        seen.add((rel, hit["line"]))
        title, more = _words(rel, hit)
        model = hit["model"]
        out.append({**_finding(RULE, title, "MEDIUM", rel, hit["line"], category="exposure", conf="LOW", cwe=200,
                               more=more, snippet=hit["fields"][0], fixed_rank="medium"),
                    "columns": {"model": model.name, "fields": hit["fields"][:MOST_SHOWN], "via": hit["via"],
                                "defined": {"file": model.file, "line": model.line}, "sent": hit["sent"]}})
    return out
