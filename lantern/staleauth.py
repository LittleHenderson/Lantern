"""A sign-in checked under a lock that is let go before the change it allows (2026-11-19). One heuristic, `tool_confidence:
LOW`, ranked medium; Python only, read with Python's own `ast`; nothing is run.

**`LW-SIGN-IN-ENDED-MIDWAY`** (`ended_midway(g)`; `read(text)` is the reading of one file): a method of a class checks
a sign-in (it compares a field of the object, a token, a secret, a session's epoch, with what the caller sent) while it
holds a lock of the object, gives back its answer and lets the lock go; another method of the same class gives that
field a new value under the same lock (a sign-out, a token rotated, a session ended); and code that asks the check
goes on to change something after it, with the lock no longer held. Between the answer and the change the sign-in can
be ended, and the change is still made for it: ending a sign-in does not stop a request that was already let through.
Written after another review tool named that shape in a project Lantern was measured on, from examples of Lantern's own.

It does not know how long the change takes, nor whether ending a sign-in is meant to stop requests under way: it says
"check". `lantern behave` asks the same question of a running app (the kind `ended-midway`).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import _finding

RULE = "LW-SIGN-IN-ENDED-MIDWAY"
MOST_FILE = 600_000
MOST_USES = 12
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
WORD = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
LOCK_WORDS = {"lock", "rlock", "mutex", "guard"}
# a field that says who may come in
SIGN_IN_WORDS = {"token", "secret", "epoch", "session", "sessions", "bearer", "key", "nonce", "generation", "version",
                 "auth", "credential", "credentials", "password", "revoked", "grant", "lease"}
# a call that changes something: the words of its name
CHANGE = {"set", "update", "delete", "remove", "create", "add", "insert", "save", "commit", "confirm", "settle",
          "approve", "transfer", "withdraw", "pay", "place", "cancel", "submit", "execute", "apply", "enable",
          "disable", "register", "put", "post", "publish", "grant", "revoke", "rotate", "replace", "move", "drop",
          "store", "persist", "upsert", "select", "assign", "accept", "reject", "send", "buy", "sell", "trade", "order",
          "promote", "activate", "deactivate", "start", "stop", "kill", "close", "open", "reset", "mint", "issue"}
# what only answers the request or is the refusal itself
ANSWER = {"json", "response", "respond", "reply", "header", "headers", "unauthorized", "forbidden", "abort", "log",
          "logger", "debug", "info", "warning", "error", "notify", "status", "send_error", "end", "flush", "print"}
REFUSE = (ast.Return, ast.Raise, ast.Break, ast.Continue)


def _words(name: str) -> set[str]:
    return {w.lower() for w in WORD.findall(name or "")}


def _name(func) -> str:
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""


def _own(nodes):
    """Every node beneath, without going into a function or a class written inside."""
    stack = list(reversed(nodes))
    while stack:
        node = stack.pop()
        if isinstance(node, (*FUNCS, ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _self_field(node) -> str:
    """`self.x` (also `self.x.reveal()`, `self.x[...]`): the field's name; '' for anything else."""
    while isinstance(node, (ast.Call, ast.Subscript)) or \
            (isinstance(node, ast.Attribute) and not (isinstance(node.value, ast.Name) and node.value.id == "self")):
        node = node.func if isinstance(node, ast.Call) else node.value
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
        return node.attr
    return ""


def _locks(with_node) -> set[str]:
    """The lock fields a `with` takes: `with self._lock:`, `with outer._auth_lock:`."""
    out = set()
    for item in with_node.items:
        e = item.context_expr
        if isinstance(e, ast.Attribute) and _words(e.attr) & LOCK_WORDS:
            out.add(e.attr)
    return out


def _held_blocks(fn):
    """(lock, statements) for each `with self.<lock>:` of the function's own."""
    for node in _own(fn.body):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for lock in _locks(node):
                if isinstance(node.items[0].context_expr.value, ast.Name) and \
                        node.items[0].context_expr.value.id == "self":
                    yield lock, node.body


def _class_facts(cls):
    """Checks: name -> (lock, fields, line); writers: (lock, field) -> [method names]."""
    checks, writers = {}, {}
    for fn in cls.body:
        if not isinstance(fn, FUNCS):
            continue
        for lock, body in _held_blocks(fn):
            parts = list(_own(body))
            for node in parts:
                targets = node.targets if isinstance(node, ast.Assign) else \
                    [node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign)) else []
                for t in targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" and \
                            fn.name != "__init__":
                        writers.setdefault((lock, t.attr), []).append(fn.name)
            if not any(isinstance(n, ast.Return) and n.value is not None for n in parts):
                continue
            fields = set()
            for node in parts:
                if isinstance(node, ast.Compare):
                    sides = [node.left, *node.comparators]
                elif isinstance(node, ast.Call) and _name(node.func) in ("compare_digest", "timingSafeEqual", "equals"):
                    sides = list(node.args)
                else:
                    continue
                for side in sides:
                    field = _self_field(side)
                    if field and _words(field) & SIGN_IN_WORDS:
                        fields.add(field)
            if fields:
                checks[fn.name] = (lock, fields, fn.lineno)
    return checks, writers


def _calls_check(test, names: set[str]) -> tuple[str, bool] | None:
    """The check a condition asks, and whether it asks for its failure (`not check(...)`)."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        got = _calls_check(test.operand, names)
        return (got[0], not got[1]) if got else None
    if isinstance(test, ast.BoolOp):
        for v in test.values:
            got = _calls_check(v, names)
            if got and (got[1] == isinstance(test.op, ast.Or)):
                return got
        return None
    if isinstance(test, (ast.Call, ast.Await)):
        call = test.value if isinstance(test, ast.Await) else test
        if isinstance(call, ast.Call) and _name(call.func) in names:
            return _name(call.func), False
    return None


def _refuses(body) -> bool:
    return bool(body) and isinstance(body[-1], REFUSE)


def _change(stmts, held: set[str], lock: str, check: str):
    """The first call among the statements that changes something with `lock` not held: (line, name) or None."""
    stack = [(s, held) for s in reversed(stmts)]
    while stack:
        node, now = stack.pop()
        if isinstance(node, (*FUNCS, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, (ast.With, ast.AsyncWith)):
            now = now | _locks(node)
        if isinstance(node, ast.Call) and lock not in now:
            name = _name(node.func)
            words = _words(name)
            first = (WORD.findall(name) or [""])[0].lower()
            if name != check and words & CHANGE and not words & ANSWER and first not in ("is", "has", "get", "can"):
                return node.lineno, name
        stack.extend((c, now) for c in reversed(list(ast.iter_child_nodes(node))))
    return None


def _uses(fn, checks: dict) -> list[dict]:
    """Where a function asks a check and then changes something with its lock let go."""
    out = []
    names = set(checks)

    def block(stmts, held):
        for i, s in enumerate(stmts):
            if isinstance(s, (*FUNCS, ast.ClassDef)):
                continue
            now = held | _locks(s) if isinstance(s, (ast.With, ast.AsyncWith)) else held
            if isinstance(s, (ast.If, ast.While)):
                got = _calls_check(s.test, names)
                if got:
                    check, failed = got
                    lock = checks[check][0]
                    after = stmts[i + 1:] if failed and _refuses(s.body) else [] if failed else s.body
                    if lock not in held:
                        ch = _change(after, held, lock, check)
                        if ch:
                            out.append({"function": fn.name, "check_line": s.lineno, "change_line": ch[0],
                                        "change": ch[1], "check": check})
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(s, field, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], ast.stmt):
                    block(inner, now)
            for h in getattr(s, "handlers", []) or []:
                block(h.body, now)
            for c in getattr(s, "cases", []) or []:
                block(c.body, now)

    block(fn.body, set())
    return out


def read(text: str) -> list[dict]:
    """One file: each check that is let go before a change, with who ends it and where it is asked."""
    tree = ast.parse(text)
    found = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        checks, writers = _class_facts(cls)
        ended = {}
        for name, (lock, fields, line) in checks.items():
            enders = sorted({m for f in fields for m in writers.get((lock, f), []) if m != name})
            if enders:
                ended[name] = (lock, fields, line, enders)
        if not ended:
            continue
        uses = []
        for fn in ast.walk(tree):
            if isinstance(fn, FUNCS) and fn.name not in ended:
                uses += _uses(fn, {k: v[:3] for k, v in ended.items()})
        for name, (lock, fields, line, enders) in sorted(ended.items()):
            mine = sorted((u for u in uses if u["check"] == name), key=lambda u: u["check_line"])
            if mine:
                rotate = [e for e in enders if _words(e) & {"rotate", "revoke", "logout", "signout", "reset", "end",
                                                             "invalidate", "expire", "close", "clear"}] or enders
                found.append({"check": name, "line": line, "lock": lock, "fields": sorted(fields),
                              "ended_by": rotate[:3], "uses": mine})
    return found


def ended_midway(g: Graph) -> list[dict]:
    """Sign-in checks let go before the change they allow (see the note above). Heuristic."""
    files = sorted({n.file for nid, n in g.nodes.items() if n.file and n.file.endswith(".py") and not outside(nid)})
    out = []
    for file in files:
        if NOT_THE_APP.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or not re.search(r"(?i)with\s+self\.\w*(?:lock|mutex|guard)", text):
            continue
        try:
            found = read(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        raw = text.splitlines()
        for c in found:
            first = c["uses"][0]
            line = first["check_line"]
            more = len(c["uses"]) - 1
            f = _finding(
                RULE, f"A sign-in checked by `{c['check']}` can be ended before the change it lets through",
                "MEDIUM", file, line, category="code", conf="LOW", cwe=367, fixed_rank="medium",
                more=(f"Heuristic: read from this file's own code. `{c['check']}` (line {c['line']}) compares "
                      f"{', '.join('`' + x + '`' for x in c['fields'][:3])} with what the caller sent while it holds "
                      f"`{c['lock']}`, and lets the lock go when it answers; `{c['ended_by'][0]}` gives that field a new "
                      f"value under the same lock. `{first['function']}` asks the check here and then calls "
                      f"`{first['change']}` (line {first['change_line']}) with the lock no longer held"
                      + (f"; {more} more place{'s' if more != 1 else ''} in this file do{'' if more != 1 else 'es'} "
                         "the same" if more else "") +
                      ". A sign-in ended between the answer and the change does not stop it: the change is made for a "
                      "sign-in that no longer holds. Fix: hold the lock (or a lease the ending waits for) until the "
                      "change is written, or check the session again inside the change's own transaction. If the "
                      "ending is not meant to stop requests already under way, this is no problem. `lantern behave` "
                      "can ask the running app (the kind `ended-midway`)."),
                snippet=raw[line - 1].strip() if 0 < line <= len(raw) else "")
            f["ended_midway"] = {"check": c["check"], "check_line": c["line"], "lock": c["lock"],
                                 "fields": c["fields"], "ended_by": c["ended_by"],
                                 "uses": [{k: u[k] for k in ("function", "check_line", "change_line", "change")}
                                          for u in c["uses"][:MOST_USES]], "more": max(0, len(c["uses"]) - MOST_USES)}
            out.append(f)
    return out
