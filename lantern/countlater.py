"""A limit that is looked at before the work and counted after it (review stage, 2026-11-15). One heuristic,
`tool_confidence: LOW` and ranked medium; it reads a function's own lines and runs nothing.

`LW-LIMIT-COUNTED-LATER` (`counted_later`): a function that turns a request away with "payment required" or "too
many requests" (402, 429) where a condition says so, then waits for something (an awaited call, a call to a model
or to another service), and only after that writes the use down. Requests sent at the same moment all read the
number before any of them is counted, all pass and all get the work: the limit holds for one request at a time and
not for several at once.

It says nothing where the use is counted, held or taken between the look and the work (the look's own condition
included: `if not store.hold(...)`), where the function names a lock or a transaction, and where the count shares
no name with the look or with the line that gave the look its value. It does not know that the look and the count
are about the same number, nor what the work costs: it says "check"."""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from pathlib import Path

from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import JS_EXTS, _finding, code_only

RULE = "LW-LIMIT-COUNTED-LATER"
MOST_BODY = 40_000          # characters of a function that are read
MOST_LINE = 2_000           # characters of a line that are read
MOST_LOOKS = 40             # looks of one function that are tried
MOST_COUNTS = 40            # counts after the work that are tried for one look
ABOVE = 6                   # lines from an `if` down to the refusal it leads to
BEFORE = 400                # lines above a look in which the value it looks at may be given

REFUSES = re.compile(r"(?<![\w.$])(?:402|429)(?![\w.])|TOO_MANY_REQUESTS|PAYMENT_REQUIRED|TooManyRequests|"
                     r"PaymentRequired")
IF_LINE = re.compile(r"^\s*(?:\}\s*)?(?:el(?:se\s+)?if|if)(?![\w$])")
AWAITED = re.compile(r"(?<![\w$.])await\s+[\w$.\[\]~]{1,120}\(")
PAID = re.compile(r"(?<![\w$.])(?:openai|anthropic|stripe|client|model|llm|chain|agent|replicate|groq|mistral|cohere)"
                  r"(?:\s*\.\s*[\w$]{1,40}){1,5}\s*\(|"
                  r"(?<![\w$.])(?:requests|httpx)\s*\.\s*(?:get|post|put|request)\s*\(|"
                  r"(?<![\w$.])(?:urlopen|fetch)\s*\(")
CALL = re.compile(r"(?<![\w$])(?P<name>[A-Za-z_$][\w$]{0,60})\s*\(")
STEPPED = re.compile(r"[\w$\]\)]\s*(?:\+=|-=)|\+\+|--(?!>)|(?<![\w$])(?:increment|decrement)\s*:")
SQL_STEP = re.compile(r"(?i)\bupdate\b[^;\n]{0,200}\bset\b[^;\n]{0,200}?\b(\w{3,40})\s*=\s*\1\s*[-+]")
LOCKED = re.compile(r"(?i)(?<![bc])lock|mutex|semaphore|transaction|atomic")
LOCKED_SQL = re.compile(r"(?i)\bfor\s+update\b|\bserializable\b")
NAME = re.compile(r"[A-Za-z_$][\w$]*")
# a limiter counts in the step in which it is asked: `limiter.take(...)`, `ratelimit.limit(id)`, `bucket.consume()`
LIMITER = re.compile(r"(?i)(?<![\w$])[\w$.]{0,80}(?:limiter|ratelimit|rate_limit|throttl|bucket)[\w$]{0,20}\s*\.\s*"
                     r"[\w$]{1,40}\s*\(")
KEYED = re.compile(r"(?<![\w$])(?:increment|decrement)\s*:")
WORD = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")

# a call by one of these names writes a use down ...
COUNTS = frozenset({"record", "increment", "incr", "decrement", "decr", "charge", "debit", "deduct", "consume",
                    "settle"})
# ... and one of these also sets a share aside before the work
HOLDS = COUNTS | {"reserve", "hold", "acquire", "claim"}
# an everyday verb counts only with what it counts: `add_usage`, `logTokens`, `use_credit`
SOFT = frozenset({"add", "log", "track", "save", "update", "bump", "use", "spend", "count", "take", "bill", "meter",
                  "write", "set", "mark"})
OF = frozenset({"usage", "use", "uses", "used", "credit", "credits", "quota", "token", "tokens", "request",
                "requests", "call", "calls", "spend", "spent", "cost", "allowance", "balance"})
# names that say nothing about which number a line is about
STOP = frozenset("""if elif else not and or in is for while return raise throw new await async const let var def
    function typeof true false null undefined None True False self this try except catch finally with as from
    import lambda pass yield res req request response reply ctx status status_code json send error message detail
    HTTPException JSONResponse Response NextResponse jsonify abort headers code""".split())


def _counts(name: str, holds: bool) -> bool:
    words = [w.lower() for w in WORD.findall(name)]
    if words and words[0] == "try":
        words = words[1:]
    if not words:
        return False
    if holds and ({"ratelimit", "throttle", "limiter"} & set(words) or "rate limit" in " ".join(words)):
        return True                     # `checkRateLimit(ip)`: the limiter's own call
    return words[0] in (HOLDS if holds else COUNTS) or (words[0] in SOFT and any(w in OF for w in words[1:]))


def _count_on(code: str, raw: str, holds: bool) -> bool:
    """Does this line write a use down (`holds`: or set a share aside)? A call by name, a number stepped up or
    down in place, an update that says `increment:` / `decrement:`, SQL that sets a column to itself plus or minus."""
    if STEPPED.search(code) or SQL_STEP.search(raw) or (holds and LIMITER.search(code)):
        return True
    return any(_counts(m.group("name"), holds) for m in CALL.finditer(code))


def _names(line: str) -> set[str]:
    return {w for w in NAME.findall(line) if len(w) > 2 and w not in STOP}


def _statement(code: list[str], at: int, work: int) -> list[str]:
    """The lines of the statement that counts: the line itself and what its brackets still hold open below it; for
    a count written as a key (`decrement: 1`), also the few lines above it that open the call."""
    first = max(work + 1, at - 3) if KEYED.search(code[at]) and not CALL.search(code[at]) else at
    last, depth = at, 0
    for last in range(at, min(len(code), at + 5)):
        depth += sum(code[last].count(c) for c in "([{") - sum(code[last].count(c) for c in ")]}")
        if depth <= 0:
            break
    return code[first:last + 1]


def _look_names(code: list[str], look: int, refusal: int) -> set[str]:
    """The names a look is about: those of its condition, and those of the line that gave each of them its value
    (`r = remaining(user, day)`, `const { success } = await limiter.limit(id)`)."""
    cond = code[look:max(look + 1, min(refusal, look + 2))]
    names = set().union(*(_names(line) for line in cond))
    for given in sorted({w for line in cond for w in NAME.findall(line) if w not in STOP})[:6]:
        gives = re.compile(r"(?<![\w$.])" + re.escape(given) + r"\s*(?::[^=\n]{0,60})?=(?!=)|"
                           r"\{[^}\n]{0,200}(?<![\w$])" + re.escape(given) + r"(?![\w$])[^}\n]{0,200}\}\s*=")
        for j in range(look - 1, max(-1, look - BEFORE), -1):
            if gives.search(code[j]):
                names |= _names(code[j])
                break
    return names


def _read(code: list[str], raw: list[str]):
    """(look, work, count, a name they share) as line indexes of this function, or None."""
    refusals = [i for i, line in enumerate(code) if REFUSES.search(line)]
    if not refusals or any(LOCKED.search(line) for line in code) or any(LOCKED_SQL.search(line) for line in raw):
        return None
    counted = [i for i in range(len(code)) if _count_on(code[i], raw[i], False)]
    if not counted:
        return None
    held = [i for i in range(len(code)) if _count_on(code[i], raw[i], True)]
    kept = set(held)
    works = [i for i, line in enumerate(code) if i not in kept and (AWAITED.search(line) or PAID.search(line))]
    looks: list[tuple[int, int]] = []
    for r in refusals:
        for i in range(r, max(-1, r - ABOVE - 1), -1):
            if IF_LINE.match(code[i]):
                if not looks or looks[-1][0] != i:
                    looks.append((i, r))
                break
        if len(looks) >= MOST_LOOKS:
            break
    for look, refusal in looks:
        w = bisect_right(works, refusal)
        if w == len(works):
            continue
        work = works[w]
        h = bisect_left(held, look)
        if h < len(held) and held[h] < work:        # counted, held or taken before the work: the count comes first
            continue
        names = _look_names(code, look, refusal)
        c = bisect_right(counted, work)
        for at in counted[c:c + MOST_COUNTS]:
            said = set().union(*(_names(line) for line in _statement(code, at, work)))
            if SQL_STEP.search(raw[at]):
                said |= _names(raw[at])
            shared = sorted(names & said)
            if shared:
                return look, work, at, shared[0]
    return None


def counted_later(g: Graph) -> list[dict]:
    """Functions that look at a limit, wait for the work and count afterwards (see the note above). Heuristic."""
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
        if not REFUSES.search(text):
            continue
        raw = [line if len(line) <= MOST_LINE else "" for line in text.splitlines()]
        code = [line if len(line) <= MOST_LINE else "" for line in code_only(text, js).splitlines()]
        code += [""] * (len(raw) - len(code))
        spans = sorted({(n.start_line, n.end_line or n.start_line) for n in by_file[file]})
        told: set[int] = set()
        for n in sorted(by_file[file], key=lambda n: ((n.end_line or n.start_line) - n.start_line, n.start_line)):
            a, b = n.start_line, min(n.end_line or n.start_line, len(raw))
            if b - a < 3:
                continue
            own_code, own_raw = code[a - 1:b], raw[a - 1:b]
            if sum(len(line) for line in own_code) > MOST_BODY:
                continue
            for s, e in spans:                    # a function written inside this one has its own lines
                if (s, e) != (a, b) and a <= s and e <= b:
                    for i in range(s - a, e - a + 1):
                        own_code[i] = own_raw[i] = ""
            got = _read(own_code, own_raw)
            if not got or a + got[0] in told:
                continue
            look, work, count, shared = got
            told.add(a + look)
            waits = "waits for an answer" if AWAITED.search(own_code[work]) else "calls a service"
            out.append(_finding(
                RULE,
                f"`{n.name}` looks at a limit, does the work, and counts it afterwards: requests sent at the same "
                "moment all pass",
                "MEDIUM", file, a + look, category="code", conf="LOW", cwe=367, fixed_rank="medium",
                more=("Heuristic: read from this function's own lines. This line turns a request away where a "
                      f"limit is reached; line {a + work} then {waits}; line {a + count} writes the use down only "
                      "after that. Two requests sent at the same moment both read the number before either is "
                      "counted, so both get the work, and so do twenty. Count the request (or set its share aside) "
                      "in the same step as the look, before the work starts, and put the count right when the work "
                      "is done or has failed. Lantern does not know that the two lines are about the same number: "
                      f"they share the name `{shared}`. It found no lock, no transaction and nothing counted or "
                      "held between the look and the work."),
                snippet=raw[a + look - 1].strip()))
    return out
