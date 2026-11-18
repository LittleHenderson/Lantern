"""Whose a record is, by the project's own data model (roadmap of 2026-11-14, stage 5: a record fetched by its number
alone, where the data says the record has an owner).

The flow step follows who is signed in to the line a record is reached on and lists the line where no route asked
whose the record is (`LT-AUTHZ-OWNER`, `lantern/flow.py`, `lantern/flowscan.py`). It reads the code. This module puts
beside such a finding what the project's model files say of the record (`lantern/datamodel.py`: a Prisma schema,
SQLAlchemy, SQLModel and Django classes, Drizzle tables, SQL `create table`):

* which record the line reaches (`on`: read from the statement's own words, `prisma.invoice.findUnique(`,
  `Invoice.objects.get(`, `session.get(Item, …)`, `select(Item)`, `.from(invoices)`, `FROM invoices`), and
* whose that record is (`owned`): the fields that name its owner (`orgId`, `owner_id`, `created_by`), or the record
  it belongs to (a note of an invoice), or that it is itself what others belong to (an org, a user), or the fields
  that may say whose it is under another name (`customerId` where the project has no such model, an e-mail address,
  a secret).

The finding then says the field to ask for (`owned` on the finding, a sentence in `more_info`). Where the data model
gives the record none of these (a price plan, a tag), there is no owner to compare: a read of it is ranked low, with
the place in the model file as the reason (`fixed_rank`, `fixed_why`); a change or a removal keeps its rank, because
who may change it is still a question, of roles. That lower rank is given on the safe side only: every model the
statement names has to be such a record, and a record with any field that could say whose it is keeps its rank. A
record whose model Lantern cannot tell from the line is left exactly as it was.

It reads; it runs nothing of the project. The same data model is what lets the flow step take a query that asks for
the owner's field as a scoped one (`flow.Engine.asks_owner`, `owner_field`)."""
from __future__ import annotations

import re

from . import datamodel

MOST_LINE = 2_000       # characters of a line that are read
MOST_LINES = 8          # lines of one statement, above and below the line a record is reached on
MOST_NAMED = 6          # models named in one statement that are looked at
DEPTH = 3               # how far "belongs to" is followed

_PRISMA = re.compile(r"\.\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|"
                     r"findMany|update|updateMany|delete|deleteMany|upsert|count|aggregate)\s*\(")
_DRIZZLE = re.compile(r"\.\s*query\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*find(?:First|Many)\s*\(|"
                      r"\.\s*(?:from|update|delete|insert|innerJoin|leftJoin|rightJoin|fullJoin)\s*\(\s*"
                      r"([A-Za-z_$][\w$]*)\s*[,)]")
_DJANGO = re.compile(r"\b([A-Z]\w*)\s*\.\s*(?:objects|_default_manager)\b|"
                     r"\bget_(?:object|list)_or_404\s*\(\s*([A-Z]\w*)")
_ALCHEMY = re.compile(r"\.\s*(?:get|get_one|query|get_or_404|join|outerjoin)\s*\(\s*([A-Z]\w*)\s*[,)]|"
                      r"\b(?:select|delete|update)\s*\(\s*([A-Z]\w*)\s*[,).]|"
                      r"\b([A-Z]\w*)\s*\.\s*query\b")
_SQL = re.compile(r"\b(?:from|update|into|join)\s+[\"`\[]?([A-Za-z_]\w*)", re.I)
# (the pattern, the kinds of model it names: None = a table's name in SQL text, any kind)
WAYS = ((_PRISMA, ("prisma",)), (_DRIZZLE, ("drizzle",)), (_DJANGO, ("django",)),
        (_ALCHEMY, ("sqlalchemy", "sqlmodel")), (_SQL, None))
OPENS, CLOSES = "([{", ")]}"
# a field of a record's own (its key), which says nothing of whose the record is
OWN_KEY = frozenset({"id", "pk", "uuid", "guid", "slug"})
# words of a field that holds something of one person
PERSONAL = frozenset({"email", "mail", "phone", "mobile", "address", "birthday", "birth", "dob", "ssn", "passport"})


def _statement(src: list[str], line: int) -> list[str]:
    """The lines of the statement a record is reached in, the reached line first: the lines below it while a bracket
    of it is still open, the lines above it while it begins with a dot or a closing bracket (a call written over
    several lines). Read from brackets alone, which is enough to keep a neighbour's query out."""
    i = line - 1
    if not 0 <= i < len(src):
        return []
    out = [src[i][:MOST_LINE]]
    depth = sum(out[0].count(c) for c in OPENS) - sum(out[0].count(c) for c in CLOSES)
    j = i + 1
    while depth > 0 and j < len(src) and j - i <= MOST_LINES:
        row = src[j][:MOST_LINE]
        out.append(row)
        depth += sum(row.count(c) for c in OPENS) - sum(row.count(c) for c in CLOSES)
        j += 1
    k = i
    while k > 0 and i - k < MOST_LINES and src[k].lstrip()[:1] in (".", ")", "]", "}"):
        k -= 1
        out.append(src[k][:MOST_LINE])
    return out


def models_on(src: list[str], line: int, models: datamodel.Models) -> list[datamodel.Model]:
    """The models of the project the statement on `line` names, the reached line's first and each once, at most
    `MOST_NAMED`. Empty when it names none."""
    out: list[datamodel.Model] = []
    if not models.all:
        return out
    for row in _statement(src, line):
        named = []
        for rx, kinds in WAYS:
            for m in rx.finditer(row):
                name = next((x for x in m.groups() if x), None)
                if name:
                    named.append((m.start(), name, kinds))
        for _at, name, kinds in sorted(named, key=lambda n: n[0]):
            got = models.by_table(name) if kinds is None else [x for x in models.named(name) if x.kind in kinds]
            if got and got[0] not in out:
                out.append(got[0])
                if len(out) >= MOST_NAMED:
                    return out
    return out


def _named_owner(name: str) -> bool:
    """Is a model's own name a word for what records belong to (`User`, `users`, `Org`, `Team`)?"""
    got = datamodel.words(name)
    if got and len(got[-1]) > 3 and got[-1].endswith("s"):
        got = [*got[:-1], got[-1][:-1]]
    return tuple(got) in datamodel.OWNER_FORMS


def _written(m: datamodel.Model):
    """The models a record belongs to, as its model writes them: where a field leads, but not to a list."""
    return [(f, to) for f, to in m.leads.items() if f not in m.many]


def _stem(name: str) -> list[str]:
    """The words of a field named like a link to another record, without what says so (`customerId`, `plan_uuid`,
    `approved_by` → customer, plan, approved); empty for a field not named like one, and for the record's own key."""
    got = datamodel.words(name)
    if len(got) < 2 or got[-1] not in ("id", "ids", "uuid", "guid", "pk", "by", "key", "ref"):
        return []
    return got[:-1]


def _model_called(stem: list[str], models: datamodel.Models) -> datamodel.Model | None:
    """The model of the project a link's words name (`customer` → `Customer`, `customers`; `line`, `item` →
    `LineItem`, `line_items`), in the singular or the plural."""
    for joined in ("".join(stem), "_".join(stem)):
        ends = [joined, joined + "s", joined + "es"] + ([joined[:-1] + "ies"] if joined.endswith("y") else [])
        for name in ends:
            got = models.named(name) or models.by_table(name)
            if got:
                return got[0]
    return None


def _belongs(m: datamodel.Model, models: datamodel.Models) -> list[tuple[str, datamodel.Model]]:
    """The records a record belongs to: where its model says a field leads, and where a field is named like a link
    to a model of the project though the file writes no relation (`customerId` beside a model `Customer`)."""
    out, seen = [], set()
    for f, to in _written(m):
        for t in (models.named(to) or models.by_table(to))[:1]:
            if t is not m and id(t) not in seen:
                seen.add(id(t))
                out.append((f, t))
    for f in [*m.inherited, *m.fields]:
        t = _model_called(_stem(f), models) if _stem(f) else None
        if t is not None and t is not m and id(t) not in seen:
            seen.add(id(t))
            out.append((f, t))
    return out


def itself(m: datamodel.Model, models: datamodel.Models) -> bool:
    """Is this what other records belong to: another model's owner field leads to it, or its name says so?"""
    low = {m.name.lower(), (m.table or m.name).lower()}
    for other in models.all:
        if other is not m and any(to.lower() in low and datamodel.owner_column(f) for f, to in _written(other)):
            return True
    return _named_owner(m.name)


def maybe(m: datamodel.Model, models: datamodel.Models) -> list[str]:
    """The fields that may say whose a record is though their names are not the usual ones: a field named like a
    link to a record the project has no model for (`customerId`, `stripeCustomerId`, `approved_by`), something of
    one person (an e-mail address, a phone number), a secret. A record with one of these is never said to be
    nobody's."""
    out = []
    for f in [*m.inherited, *m.fields]:
        got = datamodel.words(f)
        if not got or f.lower() in OWN_KEY or f in m.leads:
            continue
        stem = _stem(f)
        if (stem and _model_called(stem, models) is None) or PERSONAL.intersection(got) or datamodel.secret_column(f):
            if f not in out:
                out.append(f)
    return out


def _somebodys(m: datamodel.Model, models: datamodel.Models) -> bool:
    return bool(m.owner() or itself(m, models) or maybe(m, models))


def through(m: datamodel.Model, models: datamodel.Models) -> datamodel.Model | None:
    """The nearest record this one belongs to that is somebody's (a note's invoice), at most `DEPTH` steps away. A
    relation whose direction the model file does not say (SQLAlchemy's `relationship`) is followed too, which can
    only keep a rank where it is."""
    seen, todo = {id(m)}, [(m, 0)]
    while todo:
        cur, depth = todo.pop(0)
        for _field, t in _belongs(cur, models):
            if id(t) in seen:
                continue
            seen.add(id(t))
            if _somebodys(t, models):
                return t
            if depth + 1 < DEPTH:
                todo.append((t, depth + 1))
            else:
                return t        # further than is followed: not known to be nobody's, so it is not said to be
    return None


def owned(m: datamodel.Model, models: datamodel.Models) -> dict:
    """What the data model says of whose such a record is: `fields` that name its owner; else `itself` (it is what
    others belong to), `through` (the record it belongs to) or `maybe` (fields that may say it under another name);
    else none of them, which is "nobody's"."""
    out = {"model": m.name, "kind": m.kind, "file": m.file, "line": m.line, "fields": m.owner()}
    if not out["fields"]:
        if itself(m, models):
            out["itself"] = True
        else:
            via = through(m, models)
            if via is not None:
                out["through"] = via.name
            else:
                may = maybe(m, models)
                if may:
                    out["maybe"] = may[:6]
    return out


def nobodys(o: dict) -> bool:
    return not o["fields"] and not o.get("itself") and not o.get("through") and not o.get("maybe")


def on(src: list[str], line: int, models: datamodel.Models) -> tuple[datamodel.Model, dict, bool] | None:
    """What the data model says of the record the statement on `line` reaches: (its model, `owned` of it, whether
    every model the statement names is nobody's). The model is the first one named that is somebody's (in a query
    over several tables that is where the owner has to be asked for), else the first. None when the statement names
    no model of the project."""
    got = models_on(src, line, models)
    if not got:
        return None
    said = [(m, owned(m, models)) for m in got]
    for m, o in said:
        if not nobodys(o):
            return m, o, False
    return said[0][0], said[0][1], len(got) < MOST_NAMED


def _fields(names: list[str]) -> str:
    said = [f"`{n}`" for n in names[:3]]
    return " and ".join(said) if len(said) < 3 else f"{said[0]}, {said[1]} and {said[2]}"


def words(m: datamodel.Model, o: dict, changes: bool = False) -> str:
    """The sentence of a finding's `more_info` that says what the data model says. `changes`: the record is changed
    or removed on a way to the line."""
    where = f"`{m.file}:{m.line}`"
    if o["fields"]:
        return (f"The project's data model ({where}) names the owner of `{m.name}` in {_fields(o['fields'])}: that "
                "is the field to ask for, with the value of whoever is signed in.")
    if o.get("itself"):
        return (f"By the project's data model ({where}) `{m.name}` is what other records belong to: what to ask "
                "here is whether whoever is signed in is one of its own.")
    if o.get("through"):
        return (f"The project's data model ({where}) gives `{m.name}` no owner of its own; it belongs to "
                f"`{o['through']}`: ask whose that record is.")
    if o.get("maybe"):
        return (f"The project's data model ({where}) names no owner for `{m.name}` in the usual words; "
                f"{_fields(o['maybe'])} may be what says whose it is.")
    if changes:
        return (f"The project's data model ({where}) names no owner for `{m.name}`, and nothing it belongs to has "
                "one. So the question on this line is not whose the record is but who may change it at all: a role.")
    return (f"The project's data model ({where}) names no owner for `{m.name}`, and nothing it belongs to has one: "
            "there is no owner to compare on this line, and the same record is every signed-in person's to read.")


def low_why(m: datamodel.Model) -> str:
    """Why the read of a record that is nobody's is ranked low (the finding's `fixed_why`)."""
    return (f"The project's data model (`{m.file}:{m.line}`) names no owner for `{m.name}`, and nothing it belongs "
            "to has one, so there is no owner to ask for on this line. A field that says whose it is would change "
            "this. Which record the line reaches is read from the line's own words, so this is a heuristic.")
