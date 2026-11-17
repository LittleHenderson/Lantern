"""A balance read and checked in one step and taken from in another (roadmap of 2026-11-14, stage 5). One heuristic,
`tool_confidence: LOW` and ranked medium; it reads a function's own lines and runs nothing.

`LW-NONATOMIC-BALANCE` (`taken_apart`): a function that checks a balance (credits, points, coins, a wallet's money, a
quota, stock: an `if` that compares it, or asks whether it is missing or zero), and after the check writes the
balance down taken away as a step of its own to the database: a store's update call that writes the field with a
decrement or a minus sign, the object's field set lower and the object then saved or committed, or SQL that sets the
column to a value with a minus sign in it. Two requests sent at the same moment both read the same balance before
either has written, both pass the check and both are taken: the balance goes below zero, or one write overwrites the
other and one spend is free.

It says nothing where the write itself carries the check: a condition that holds the field to the value that was
read (Prisma's and Sequelize's `where: { credits: user.credits }`, `.eq('coins', profile.coins)` of Supabase and
knex, Django's `filter(points=…)`, SQLAlchemy's `.where(… .credits == …)`, SQL's `WHERE … credits = $1`), or a
condition that bounds it (`gte`, `__gte`, `>=`, MongoDB's `$gte`, Drizzle's `gte(table.field, …)`) beside a write
that takes from the value the database holds (`decrement`, `F("credits") - cost`, `Model.credits - cost`,
`users.c.credits - cost`, `SET credits = credits - $1`). A bound beside a value worked out in the program from the
balance that was read (`credits: user.credits - cost` under `credits: { gte: cost }`) is named, with `how: "bounded"`:
both requests pass the bound and write the same value. A write chained over several lines (`.update(…)` on one,
`.eq(…)` on the next, knex's `.where(…).andWhere(…)`) is read as one statement. It is quiet where a lock or a
transaction is named in the function before the check, or on the lines that decorate it (`FOR UPDATE`,
`with_for_update()`, `select_for_update()`, `transaction.atomic`, `$transaction(async …)`, `BEGIN`), where nothing is
taken away, where the object is never saved, where another field is written, where `LW-LIMIT-COUNTED-LATER` names
the check already (`skip`), and in JavaScript where the function waits for nothing: code that never waits is not
cut in two by another request. It does not know that the check and the write are about the same record: they share
the field's name, and the finding says so.

Inside a transaction it is quiet, as the roadmap asks. That is quiet the wrong way at the usual isolation level of
PostgreSQL and MySQL (read committed, repeatable read): a transaction alone does not keep two requests from reading
the same balance, a lock or a condition in the write does. Not read: counters kept by Redis or another store's own
commands, fields named for an amount of goods (`quantity`), a check and a write in two functions."""
from __future__ import annotations

import re
from pathlib import Path

from .countlater import IF_LINE, NAME, STOP, WORD
from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import JS_EXTS, _finding, code_only

RULE = "LW-NONATOMIC-BALANCE"
MOST_BODY = 40_000          # characters of a function that are read
MOST_LINE = 2_000           # characters of a line that are read
MOST_LOOKS = 40             # checks of one function that are tried
MOST_WRITES = 40            # writes after one check that are tried
STATEMENT = 8               # lines of one write that are read
BEFORE = 400                # lines above a line in which a name it uses may be given

# a name with one of these words is a balance: `credits`, `walletBalance`, `points_left`, `monthly_quota`
BALANCE = frozenset("""balance balances credit credits coin coins point points quota quotas fund funds wallet
    wallets allowance allowances stock inventory""".split())
# a comparison, a negation, or a look for zero: `<`, `>=`, `!x`, `not x`, `== 0`
COMPARES = re.compile(r"(?<![=<>\-])(?:<=?|>=?)(?![<>=])|(?<![\w$])not\s|!(?!=)|===?\s*0(?![\w.$])")
# a call that writes stored data
WRITES = re.compile(r"(?<![\w$])(?:update|updateMany|updateOne|update_one|update_many|findOneAndUpdate|"
                    r"find_one_and_update|findByIdAndUpdate|upsert|decrement|values)\s*\(")
SQL_CALL = re.compile(r"(?<![\w$])(?:execute|executemany|query|run|exec|raw|unsafe|\$executeRaw|"
                      r"\$executeRawUnsafe|\$queryRaw)\s*[(`]")
SAVED = re.compile(r"(?<![\w$])(?:save|commit|flush|persistAndFlush|save_changes|saveChanges)\s*\(")
# the parts of a write that say which rows it changes
COND_KEY = re.compile(r"(?<![\w$])where\s*[:(]\s*\{")
COND_CALL = re.compile(r"(?<![\w$])(?:where|andWhere|whereRaw|andWhereRaw|filter|filter_by|match|eq|neq|gt|gte|lt|lte|"
                       r"in_|having|exclude)\s*\(")
FILTER_FIRST = re.compile(r"(?<![\w$])(?:updateOne|updateMany|update_one|update_many|findOneAndUpdate|"
                          r"find_one_and_update|replaceOne|replace_one)\s*\(")
SQL_WHERE = re.compile(r"(?i)\bwhere\b(.*)")
SQL_SET = re.compile(r"(?i)\bupdate\b.*?\bset\b(.*?)(?:\bwhere\b|$)")
LOCKED = re.compile(r"(?i)(?<![bc])lock|mutex|semaphore|transaction|atomic|for_?update|(?<![\w$])begin(?:_nested)?\s*\(")
LOCKED_SQL = re.compile(r"(?i)\bfor\s+update\b|\bserializable\b|[\"'`]\s*(?:begin|start\s+transaction)\b")
WAITS = re.compile(r"(?<![\w$])await(?![\w$])|\.\s*then\s*\(")
# a line that goes on with the chain of the line above it: `.eq('coins', profile.coins)`
CHAIN = re.compile(r"^\s*\??\.\s*[\w$]")
# conditions by name: those that only bound a field, and those that hold it to one value
BOUND_CALL = frozenset("gte gt lte lt neq".split())
EQUAL_CALL = frozenset("eq match equals".split())
BOUND_OP = re.compile(r"(?<![\w$])\$?(?:gte|gt|lte|lt|ne|not)\s*:")
EQUAL_OP = re.compile(r"(?<![\w$])(?:equals|\$eq)\s*:")


def _balance(name: str) -> bool:
    return any(w.lower() in BALANCE for w in WORD.findall(name))


def _names(line: str) -> set[str]:
    return {w for w in NAME.findall(line) if w not in STOP}


def _condition(line: str, js: bool) -> str:
    """The condition of an `if` line: inside the brackets in JS (or the rest of the line where they do not close on
    it), up to the last colon in Python."""
    m = IF_LINE.match(line)
    rest = line[m.end():] if m else line
    if js:
        at = rest.find("(")
        if at < 0:
            return rest
        end = _closes(rest, at)
        return rest[at + 1:end] if end > 0 else rest[at + 1:]
    end = rest.rfind(":")
    return rest[:end] if end > 0 else rest


def _closes(text: str, at: int) -> int:
    """Where the bracket at `at` closes, or -1."""
    pairs, depth = {"(": ")", "[": "]", "{": "}"}, 0
    opening = text[at]
    for i in range(at, min(len(text), at + MOST_BODY)):
        if text[i] == opening:
            depth += 1
        elif text[i] == pairs[opening]:
            depth -= 1
            if depth == 0:
                return i
    return -1


def _given(code: list[str], name: str, at: int, top: int) -> str:
    """The line above `at` (not above `top`) that gives `name` its value, or ""."""
    gives = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*(?::[^=\n]{0,60})?=(?!=)|"
                       r"[{(\[,][^}\n]{0,200}(?<![\w$.])" + re.escape(name) + r"(?![\w$])[^}\n]{0,200}[})\]]\s*=(?!=)")
    for j in range(at - 1, max(top - 1, at - BEFORE), -1):
        if gives.search(code[j]):
            return code[j]
    return ""


def _looked_at(code: list[str], i: int, js: bool) -> set[str]:
    """The balances an `if` line checks: the names in its condition that are one, and those of the line that gave
    each name of the condition its value (`const left = account.points - cost` before `if (left < 0)`)."""
    cond = _condition(code[i], js)
    if not COMPARES.search(cond):
        return set()
    names = _names(cond)
    found = {n for n in names if _balance(n)}
    for name in sorted(n for n in names if not _balance(n))[:6]:
        found |= {n for n in _names(_given(code, name, i, 0)) if _balance(n)}
    return found


def _statement(code: list[str], j: int) -> int:
    """The last line of the statement that begins on line `j`: where its brackets close and no line after it goes on
    with the chain (`.eq('coins', profile.coins)` on a line of its own), at most `STATEMENT` lines down."""
    depth = 0
    for k in range(j, min(len(code), j + STATEMENT)):
        depth += sum(code[k].count(c) for c in "([{") - sum(code[k].count(c) for c in ")]}")
        if depth <= 0 and not (k + 1 < len(code) and CHAIN.match(code[k + 1])):
            return k
    return min(len(code), j + STATEMENT) - 1


def _chain_start(code: list[str], j: int) -> int:
    """The first line of the chain line `j` goes on with: `knex('users').where(…).andWhere(…)` above `.update(…)`."""
    k = j
    while k > 0 and j - k < STATEMENT and CHAIN.match(code[k]):
        k -= 1
    return k


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    out = list(text)
    for a, b in spans:
        out[a:b] = " " * (b - a)
    return "".join(out)


def _conditions(code: str, raw: str) -> tuple[list[tuple[int, int]], str]:
    """The parts of a write (code view) that say which rows it changes, and the raw text of those parts: the object
    after `where:` / `where({`, the arguments of `where(…)`, `filter(…)`, `.eq(…)`, `.gte(…)` and their like, and
    MongoDB's filter (the first argument of `updateOne` and its like, unless that argument holds a `where`: Prisma's
    `updateMany({ where, data })`, where only the `where` is the condition)."""
    spans = []
    for m in COND_KEY.finditer(code):
        end = _closes(code, m.end() - 1)
        spans.append((m.end() - 1, end + 1 if end > 0 else len(code)))
    for m in COND_CALL.finditer(code):
        end = _closes(code, m.end() - 1)
        spans.append((m.end() - 1, end + 1 if end > 0 else len(code)))
    for m in FILTER_FIRST.finditer(code):
        at = m.end()
        while at < len(code) and code[at].isspace():
            at += 1
        if at < len(code) and code[at] == "{":
            end = _closes(code, at)
            if COND_KEY.search(code[at:end + 1] if end > 0 else code[at:]):
                continue                    # Prisma's one argument, `{ where: …, data: … }`: its `where` is the condition
            spans.append((at, end + 1 if end > 0 else len(code)))
    return spans, " ".join(raw[a:b] for a, b in spans)


def _word(name: str) -> re.Pattern:
    return re.compile(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])")


def _sql(raw: str, field: str) -> tuple[bool, bool]:
    """(the SQL in these lines sets `field`, it names `field` in its condition)."""
    sets = conditioned = False
    for m in SQL_SET.finditer(raw):
        if re.search(r"(?<![\w$.])" + re.escape(field) + r"\s*=", m.group(1)):
            sets = True
            after = SQL_WHERE.search(raw[m.end(1):])
            conditioned = conditioned or bool(after and _word(field).search(after.group(1)))
    return sets, conditioned


def _held_how(text: str, text_raw: str, spans: list[tuple[int, int]], field: str) -> str | None:
    """How the write's condition holds `field`: "equal" where a condition holds it to one value (`credits:
    user.credits`, `.eq('coins', profile.coins)`, `points=profile.points`, `User.credits == …`, `credits = :c`),
    "bound" where every condition on it only bounds it (`credits: { gte: cost }`, `.gte('coins', 50)`,
    `points__gte=700`, `User.credits >= 2`, `credits >= :n`), None where Lantern cannot tell."""
    f, word = re.escape(field), _word(field)
    kinds: set[str] = set()
    for a, b in spans:
        part, part_raw = text[a:b], text_raw[a:b]
        call = re.search(r"([\w$]+)\s*$", text[:a])
        call = call.group(1) if call else ""
        if word.search(part) or word.search(part_raw):
            if call in BOUND_CALL:
                kinds.add("bound")
                continue
            if call in EQUAL_CALL:
                kinds.add("equal")
                continue
        for m in re.finditer(r"(?<![\w$.])" + f + r"\s*:(?!:)\s*", part):     # an object: `credits: …`
            rest = part[m.end():]
            if rest.startswith("{"):
                inner = rest[:_closes(rest, 0) + 1] if _closes(rest, 0) > 0 else rest
                kinds |= {"bound"} if BOUND_OP.search(inner) else set()
                kinds |= {"equal"} if EQUAL_OP.search(inner) else set()
            else:
                kinds.add("equal")
        for m in re.finditer(r"(?<![\w$])" + f + r"(?:__(gte|gt|lte|lt|exact))?\s*(==|>=|<=|!=|>|<|=)(?!=)", part_raw):
            lookup, op = m.group(1), m.group(2)
            if lookup:
                kinds.add("equal" if lookup == "exact" else "bound")
            elif op in ("==", "="):
                kinds.add("equal")
            else:
                kinds.add("bound")
    return "equal" if "equal" in kinds else "bound" if "bound" in kinds else None


def _written_back(written: str, code: list[str], j: int, field: str) -> bool:
    """Is the value written for `field` worked out in the program from the balance that was read: `user.credits -
    cost`, `profile.points - 700`, or a name given above by a line that takes a balance away (`const left =
    account.points - cost`)? A model's own column (`User.credits - 1` in SQLAlchemy, a class's name) is the value the
    database holds, not one that was read, and so is a table's column in SQLAlchemy Core (`users.c.credits - 3`)."""
    f = re.escape(field)
    for m in re.finditer(r"(?<![\w$.])" + f + r"\s*(?::(?!:)|=(?!=))\s*([^,\n]{1,200})", written):
        value = m.group(1)
        read = re.search(r"(?<![\w$.])[a-z_$][\w$]*(?:\s*\??\.\s*[\w$]+)*\s*\??\.\s*" + f + r"(?![\w$])\s*-(?![->=])",
                         value)
        if read and not re.search(r"\.\s*c\s*\.\s*" + f + r"(?![\w$])", read.group(0)):
            return True
        name = re.match(r"\s*([A-Za-z_$][\w$]*)\s*(?:[,})\]]|$)", value)
        if name:
            given = _given(code, name.group(1), j, 0)
            if given and "-" in given and any(_balance(n) for n in _names(given)):
                return True
    return False


def _takes(written: str, code: list[str], j: int, field: str) -> bool:
    """Does the written part take away: a decrement, a minus sign, MongoDB's `$inc` with a negative number, or a
    value given above by a line that takes a balance away (`const left = account.points - cost`)?"""
    if "-" in written or re.search(r"(?<![\w$])(?:decrement|decr)(?![\w$])", written):
        return True
    for name in sorted(_names(written) - {field})[:6]:
        given = _given(code, name, j, 0)
        if given and "-" in given and any(_balance(n) for n in _names(given)):
            return True
    return False


def _write(code: list[str], raw: list[str], j: int, fields: set[str], js: bool) -> tuple[str, str] | None:
    """(the balance written, how) where the statement on line `j` writes one of `fields` down taken away with no
    condition on it; None for anything else."""
    first, last = _chain_start(code, j), _statement(code, j)
    text, text_raw = "\n".join(code[first:last + 1]), "\n".join(raw[first:last + 1])
    if WRITES.search(code[j]):
        spans, cond_raw = _conditions(text, text_raw)
        written, written_raw = _blank(text, spans), _blank(text_raw, spans)
        for field in sorted(fields):
            f = re.escape(field)
            key = re.compile(r"(?<![\w$.])" + f + (r"\s*:(?!:)" if js else r"\s*(?::(?!:)|=(?!=))")
                             + r"|[\"'`]" + f + r"[\"'`]\s*:(?!:)")
            named = re.compile(r"(?<![\w$])decrement\s*\(\s*[\"'`]" + f + r"[\"'`]")
            if not (key.search(written) or key.search(written_raw) or named.search(text_raw)):
                continue
            # SQL written as text beside the field (`sql`${users.credits} - 1``, `'credits - :units'`): a minus the
            # database works out from the value it holds
            minus = re.compile(r"(?<![\w$])" + f + r"(?![\w$])\}?\s*-(?!>)")
            in_text = any(not minus.match(written, m.start()) for m in minus.finditer(written_raw))
            takes = _takes(written, code, j, field) or bool(named.search(text_raw)) or in_text
            if _conditioned(text, spans, cond_raw, field):
                # a value worked out from what was read, written back under a condition that only bounds the field:
                # two requests both pass the bound and write the same value (a take from the value the database
                # holds, `decrement`, `F("points") - 1`, `users.c.credits - 1`, is never "written back")
                if takes and _written_back(written, code, j, field) and _held_how(text, text_raw, spans, field) == "bound":
                    return field, "bounded"
                return None
            if takes:
                return field, "update"
        return None
    if SQL_CALL.search(code[j]):
        for field in sorted(fields):
            sets, conditioned = _sql(text_raw, field)
            if sets and not conditioned:
                set_part = SQL_SET.search(text_raw)
                if set_part and "-" in set_part.group(1):
                    return field, "sql"
        return None
    for field in sorted(fields):
        m = re.search(r"(?<![\w$])[\w$]+(?:\s*\.\s*[\w$]+)*\s*\.\s*" + re.escape(field)
                      + r"\s*(-=|--|=(?!=))(.*)", code[j])
        if not m:
            continue
        if m.group(1) in ("-=", "--") or _takes(m.group(2), code, j, field):
            if any(SAVED.search(line) for line in code[j + 1:]):
                return field, "saved"
    return None


def _conditioned(text: str, spans: list[tuple[int, int]], cond_raw: str, field: str) -> bool:
    """Does the condition of the write name `field`: in its code (`credits: { gte: 1 }`, `User.credits >= 1`), as a
    text (`.gte('coins', 50)`), or as Django's lookup (`credits__gte=1`)?"""
    word = _word(field)
    if any(word.search(text[a:b]) for a, b in spans) or word.search(cond_raw):     # also as text: `'coins'`,
        return True                                                                 # `'credits >= :units'`
    return bool(re.search(r"(?<![\w$])" + re.escape(field) + r"__(?:gte|gt|lte|lt|exact)(?![\w$])", text))


def _read(code: list[str], raw: list[str], js: bool, above: list[str]) -> tuple[int, int, str, str] | None:
    """(check, write, the balance, how) as line indexes of this function, or None."""
    if js and not any(WAITS.search(line) for line in code):
        return None
    looks = 0
    for i, line in enumerate(code):
        if not IF_LINE.match(line):
            continue
        fields = _looked_at(code, i, js)
        if not fields:
            continue
        looks += 1
        if looks > MOST_LOOKS:
            return None
        guard = above + code[:i + 1]
        if any(LOCKED.search(x) for x in guard) or any(LOCKED_SQL.search(x) for x in above + raw[:i + 1]):
            return None
        tried, j = 0, i
        while j + 1 < len(code):
            j += 1
            if not (WRITES.search(code[j]) or SQL_CALL.search(code[j])
                    or any(f in code[j] for f in fields)):
                continue
            tried += 1
            if tried > MOST_WRITES:
                break
            got = _write(code, raw, j, fields, js)
            if got:
                return i, j, got[0], got[1]
            if WRITES.search(code[j]):          # a store's write judged whole: its later lines are not another one
                j = max(j, _statement(code, j))
    return None


HOW = {"update": "an update that writes `{f}` taken away",
       "sql": "SQL that sets `{f}` to a value with a minus sign in it",
       "saved": "`{f}` set lower on the object, which is then saved",
       "bounded": "an update that writes back `{f}` worked out from the balance that was read, under a condition "
                  "that only bounds `{f}`"}


def _more(field: str, how: str, js: bool, write: int) -> str:
    """What the finding says: what was read, what a person can do, and what Lantern does not know."""
    f = field
    head = ("Heuristic: read from this function's own lines. This line checks the balance in "
            f"`{f}`; line {write} then writes it down as a step of its own: " + HOW[how].format(f=f) + ". ")
    stored = (f"`updateMany({{ where: {{ id, {f}: {{ gte: cost }} }}, data: {{ {f}: {{ decrement: cost }} }} }})` "
              "in Prisma" if js else
              f"`filter(pk=…, {f}__gte=cost).update({f}=F(\"{f}\") - cost)` in Django, `update(Model).where("
              f"Model.id == id, Model.{f} >= cost).values({f}=Model.{f} - cost)` in SQLAlchemy")
    sql = f"`UPDATE … SET {f} = {f} - $1 WHERE id = $2 AND {f} >= $1` in SQL"  # nosec B608: fix text for a person, never run
    lock = ("lock the row from the read to the write (`SELECT … FOR UPDATE`, `select_for_update()`, "
            "`with_for_update()`). Lantern does not know that the check and the write are about the same record: "
            f"they share the name `{f}`. ")
    if how == "bounded":
        held = (f"`where: {{ id, {f}: row.{f} }}` in Prisma, `.eq('{f}', row.{f})` in Supabase" if js else
                f"`filter(pk=…, {f}=row.{f})` in Django, `.where(Model.{f} == row.{f})` in SQLAlchemy")
        return (head + "Two requests sent at the same moment both read the same balance before either has written; "
                "both pass the check and the condition, both write the same value worked out from what they read, "
                "and one spend is free. Take from the value the database holds in the write and keep the condition "
                f"({stored}, {sql}), or hold the write to the value that was read ({held}), and look at how many rows "
                "it changed; or " + lock + f"The write's condition on `{f}` only bounds it (it keeps the balance "
                "from going below zero), and Lantern found no lock or transaction before the check.")
    return (head + "Two requests sent at the same moment both read the same balance before either has written, so "
            "both pass the check and both are taken: the balance goes below zero, or one write overwrites the other "
            f"and one spend is free. Make the write carry the check and look at how many rows it changed ({stored}, "
            f"{sql}), or " + lock + f"It found no condition on `{f}` in the write, and no lock or transaction before "
            "the check.")


def taken_apart(g: Graph, skip: set) -> list[dict]:
    """Functions that check a balance and take from it in a step of their own (see the note above). Heuristic.
    `skip`: (file, line) of checks another rule names already."""
    by_file: dict[str, list] = {}
    for nid, n in g.nodes.items():
        if n.kind == "callable" and n.file and n.start_line and not outside(nid):
            by_file.setdefault(n.file, []).append(n)
    out = []
    for file in sorted(by_file):
        js = file.endswith(tuple(JS_EXTS) + (".mts", ".cts"))
        if not (js or file.endswith(".py")) or NOT_THE_APP.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root)
        except OSError:
            continue
        if not any(w in text.lower() for w in BALANCE):
            continue
        raw = [line if len(line) <= MOST_LINE else "" for line in text.splitlines()]
        code = [line if len(line) <= MOST_LINE else "" for line in code_only(text, js).splitlines()]
        code += [""] * (len(raw) - len(code))
        spans = sorted({(n.start_line, n.end_line or n.start_line) for n in by_file[file]})
        told: set[int] = set()
        for n in sorted(by_file[file], key=lambda n: ((n.end_line or n.start_line) - n.start_line, n.start_line)):
            a, b = n.start_line, min(n.end_line or n.start_line, len(raw))
            if b - a < 2:
                continue
            own_code, own_raw = code[a - 1:b], raw[a - 1:b]
            if sum(len(line) for line in own_code) > MOST_BODY:
                continue
            for s, e in spans:                    # a function written inside this one has its own lines
                if (s, e) != (a, b) and a <= s and e <= b:
                    for i in range(s - a, e - a + 1):
                        own_code[i] = own_raw[i] = ""
            above, k = [], a - 2                  # the lines that decorate it: `@transaction.atomic`
            while k >= 0 and k >= a - 12 and code[k].strip().startswith("@"):
                above.append(code[k])
                k -= 1
            got = _read(own_code, own_raw, js, above)
            if not got or a + got[0] in told or (file, a + got[0]) in skip:
                continue
            check, write, field, how = got
            told.add(a + check)
            more = _more(field, how, js, a + write)
            f = _finding(RULE,
                         f"`{n.name}` checks a balance and takes from it in a step of its own: requests sent at the "
                         "same moment can all pass",
                         "MEDIUM", file, a + check, category="code", conf="LOW", cwe=362, fixed_rank="medium",
                         more=more, snippet=raw[a + check - 1].strip())
            f["balance"] = {"field": field, "check": a + check, "write": a + write, "how": how}
            out.append(f)
    return out
