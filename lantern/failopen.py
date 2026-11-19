"""A safety limit read from the environment that gives way when its value is wrong (2026-11-19). One heuristic,
`tool_confidence: LOW` and ranked medium; it reads a Python file's own text and runs nothing.

`LW-LIMIT-FAILS-OPEN` (`fails_open(g)`; `read(text)` is the reading of one file): a value whose name says it is a
limit (`max_…`, `…_limit`, a cap, a budget, a quota, a ceiling) is read from the environment, and

  * `fallback`: a value that is set and cannot be read (a typo, `5O` for `50`, a negative number) turns into a
    default written in the code, by a condition that tests the text (`int(raw) if raw.isdigit() else 5000`) or by a
    handler that catches the error and gives the default (`except ValueError: limit = 5000`). The person who set a
    tighter limit gets the looser one, and nothing says so;
  * `infinite`: it is read as a `Decimal` or a `float`, which take `Infinity` and `NaN` as numbers, and nothing in
    the function or the file asks whether it is finite (`is_finite()`, `math.isfinite`, `isinf`, `isnan`): a spend
    limit of `Infinity` limits nothing, and every comparison with `NaN` is false.

Written after another review tool named both in a project Lantern was measured on, from examples of Lantern's own.
It says nothing where a value that is missing gets the default (`int(raw) if raw else 5000`: a wrong value still
raises), where a wrong value stops the program, and for a name that is no limit (a port, a page size, a threshold
for a warning is not read as one). It does not know whether the default is looser than what was meant: it says "check".
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import _finding

RULE = "LW-LIMIT-FAILS-OPEN"
MOST_FILE = 400_000
LIMIT_WORDS = {"max", "maximum", "limit", "limits", "cap", "budget", "quota", "ceiling", "allowance"}
NOT_LIMIT = {"port", "page", "retries", "retry", "workers", "width", "height", "len", "length", "size", "line", "lines",
             "timeout", "seconds", "minutes", "ms", "age", "cache", "log"}
CONVERT = {"int", "float", "Decimal"}
FINITE = re.compile(r"is_finite|isfinite|isinf|isnan|is_nan|is_infinite|\binf\b|Infinity")
VALIDITY = {"isdigit", "isdecimal", "isnumeric", "fullmatch", "match"}
ENV = re.compile(r"\bos\.(?:environ|getenv)\b|\bgetenv\(|\benviron\.get\(")


def _words(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return {w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w}


def _is_limit(name: str) -> bool:
    w = _words(name)
    return bool(w & LIMIT_WORDS) and not (w & NOT_LIMIT)


def _text(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:       # a tree Python cannot write back: nothing is read from it
        return ""


def _conv(node) -> ast.Call | None:
    """The first `int(...)`, `float(...)` or `Decimal(...)` call in `node`."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = sub.func.id if isinstance(sub.func, ast.Name) else sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
            if name in CONVERT and sub.args:
                return sub
    return None


def _constant(node) -> bool:
    """A number, a text, a name in capitals, or a conversion of one: a default written in the code."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, str)) and not isinstance(node.value, bool):
        return True
    if isinstance(node, ast.Name) and node.id.isupper():
        return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant):
        return True
    c = _conv(node)
    return bool(c and c is node and all(_constant(a) for a in c.args))


def _tests_the_text(test, raw: set[str]) -> bool:
    """The condition tests what the text says (a pattern, its digits, a number it gives), not only whether it is set."""
    for sub in ast.walk(test):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr in VALIDITY:
            return True
        if isinstance(sub, ast.Compare) and any(isinstance(c, ast.Constant) and isinstance(c.value, (int, float))
                                                and not isinstance(c.value, bool) for c in [sub.left, *sub.comparators]):
            if _conv(sub) is not None or set(re.findall(r"\w+", _text(sub))) & raw:
                return True
    return False


class _Scope:
    def __init__(self, body: list, text: str):
        self.body = body
        self.text = text
        self.from_env: set[str] = set()
        for node in self._walk():
            if isinstance(node, ast.Assign) and ENV.search(_text(node.value)):
                self.from_env |= {t.id for t in node.targets if isinstance(t, ast.Name)}

    def _walk(self):
        """Every part of this scope, not the functions written in it (each is a scope of its own)."""
        stack = list(reversed(self.body))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            yield node
            stack.extend(reversed(list(ast.iter_child_nodes(node))))

    def env_read(self, expr) -> set[str]:
        """The names of this scope given by the environment that `expr` reads, or {"env"} when it reads it itself."""
        t = _text(expr)
        if ENV.search(t):
            return {"env"}
        return set(re.findall(r"[A-Za-z_]\w*", t)) & self.from_env


def _finds(scope: _Scope) -> list[dict]:
    out = []
    finite = bool(FINITE.search(scope.text))
    for node in scope._walk():
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name, value = node.targets[0].id, node.value
            if not _is_limit(name):
                continue
            conv = _conv(value)
            if conv is None or not scope.env_read(conv.args[0]):
                continue
            raw = scope.env_read(conv.args[0])
            if isinstance(value, ast.IfExp) and _conv(value.body) is conv and _constant(value.orelse) \
                    and _tests_the_text(value.test, raw):
                out.append({"line": node.lineno, "name": name, "kind": "fallback", "default": _text(value.orelse)[:40]})
                continue
            fn = conv.func.id if isinstance(conv.func, ast.Name) else conv.func.attr
            if fn in ("Decimal", "float") and not finite:
                out.append({"line": node.lineno, "name": name, "kind": "infinite", "as": fn})
        elif isinstance(node, ast.Try):
            for stmt in node.body:
                if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):
                    continue
                name = stmt.targets[0].id
                conv = _conv(stmt.value)
                if not _is_limit(name) or conv is None or not scope.env_read(conv.args[0]):
                    continue
                for h in node.handlers:
                    if any(isinstance(s, ast.Raise) for s in ast.walk(h)) or any(
                            isinstance(s, ast.Call) and _text(s.func) in ("sys.exit", "exit", "SystemExit")
                            for s in ast.walk(h)):
                        continue
                    gives = [s for s in h.body if isinstance(s, ast.Assign) and len(s.targets) == 1
                             and isinstance(s.targets[0], ast.Name) and s.targets[0].id == name and _constant(s.value)]
                    gives += [s for s in h.body if isinstance(s, ast.Return) and s.value is not None and _constant(s.value)]
                    if gives:
                        out.append({"line": stmt.lineno, "name": name, "kind": "fallback",
                                    "default": _text(gives[0].value)[:40]})
                        break
    return out


def read(text: str) -> list[dict]:
    tree = ast.parse(text)
    lines = text.splitlines()
    out = _finds(_Scope(tree.body, text))
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = "\n".join(lines[fn.lineno - 1:(fn.end_lineno or fn.lineno)])
            scope = _Scope(fn.body, body)
            if FINITE.search(text):     # a check of finiteness anywhere in the file counts for its functions
                scope.text = text
            out += _finds(scope)
    seen, kept = set(), []
    for f in sorted(out, key=lambda f: f["line"]):
        if f["line"] not in seen:
            seen.add(f["line"])
            kept.append(f)
    return kept


def fails_open(g: Graph) -> list[dict]:
    files = sorted({n.file for nid, n in g.nodes.items() if n.file and n.file.endswith(".py") and not outside(nid)})
    out = []
    for file in files:
        if NOT_THE_APP.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or not ENV.search(text):
            continue
        try:
            found = read(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        raw = text.splitlines()
        for c in found:
            if c["kind"] == "fallback":
                title = f"A wrong value of the limit `{c['name']}` quietly becomes the default `{c['default']}`"
                more = ("Heuristic: read from this file's own lines. The limit is read from the environment, and a "
                        "value that is set and cannot be read (a typo, a negative number) turns into the default "
                        "written in the code, with no word said. Whoever set a tighter limit then runs with the "
                        "default. Fix: refuse a value that is set and wrong (stop the program with a message), and give "
                        "the default only when the setting is missing. If the default is the tightest safe value, "
                        "this is no problem.")
                cwe = 1188
            else:
                title = f"The limit `{c['name']}` is read as a {c['as']} with no check that it is finite"
                more = ("Heuristic: read from this file's own lines. A `Decimal` or a `float` read from text takes "
                        "`Infinity` and `NaN` as numbers. A limit of `Infinity` limits nothing, and every comparison "
                        "with `NaN` is false, so a check such as `if spent > limit` never stops anything. Fix: refuse "
                        "the value unless it is finite and in range (`value.is_finite()` for a Decimal, "
                        "`math.isfinite(value)` for a float).")
                cwe = 20
            out.append(_finding(RULE, title, "MEDIUM", file, c["line"], category="code", conf="LOW", cwe=cwe,
                                fixed_rank="medium", more=more,
                                snippet=raw[c["line"] - 1].strip() if 0 < c["line"] <= len(raw) else ""))
            out[-1]["limit"] = {k: v for k, v in c.items() if k != "line"}
    return out
