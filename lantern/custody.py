"""A secret taken from a file whose place comes from outside the code, with nothing asked about the file first
(2026-11-19). One heuristic, `tool_confidence: LOW` and ranked medium; it reads a Python file's own text and runs
nothing.

`LW-SECRET-FILE-UNCHECKED` (`unchecked(g)`; `read(text)` is the reading of one file): a function reads a whole file
(`Path.read_text()`, `read_bytes()`, `open(...).read()`) and keeps what it read as a secret (the name of the file's
path, of what is read into, or of the function says token, secret, key, password or credential), the file's place
comes from the environment or from a parameter (the program is told where the secret is; also a field of the object
that a method of its class set that way), and nothing in the
function asks who owns the file, who else may read or change it, or whether the name is a link: no `stat` of it
(`st_uid`, `st_mode`, `st_nlink`), no `lstat`/`fstat`, no `is_symlink()`, no `O_NOFOLLOW`. Whoever can put a file at
that place, or a link there, then chooses the secret: another user of the computer, a program that shares the
folder, a deploy step that left the file readable to all. Written after another review tool named that shape in a
project Lantern was measured on (a bearer token adopted from a file after `resolve()` and `is_file()` only), from
examples of Lantern's own.

It says nothing where a check of the file stands anywhere in the function, or where the function hands the path to
a function of the project whose name says it checks (`verify`, `check`, `ensure`, `owned`, `private`, `secure`,
`permission`), and it does not follow a check made by the caller: it says "check".
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import _finding

RULE = "LW-SECRET-FILE-UNCHECKED"
MOST_FILE = 400_000
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
SECRET_WORDS = {"token", "tokens", "secret", "secrets", "key", "keys", "password", "passwd", "credential",
                "credentials", "apikey", "bearer", "passphrase", "pem"}
NOT_SECRET = {"public", "pub", "keyboard", "monkey", "hotkey", "keymap", "keyword", "keywords"}
CHECKS = re.compile(r"\b(?:st_uid|st_mode|st_nlink|st_gid|S_IMODE|S_IRWX[GO]|S_I[RW](?:GRP|OTH)|O_NOFOLLOW|lstat|fstat|"
                    r"is_symlink|islink|geteuid|getuid|owner)\b")
CHECK_NAME = re.compile(r"(?i)verify|check|ensure|owned|owner|private|secure|permission|trusted|safe_read|custody")
ENV = re.compile(r"\bos\.(?:environ|getenv)\b|\bgetenv\(")


def _words(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return {w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w}


def _secretish(*names: str) -> bool:
    w = set().union(*(_words(n) for n in names))
    return bool(w & SECRET_WORDS) and not (w & NOT_SECRET)


def _text(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:       # a tree Python cannot write back: no name is read from it
        return ""


class _Function:
    """One function: where each name of it got its value, and the reads of whole files."""

    def __init__(self, fn, fields: frozenset = frozenset()):
        self.fn = fn
        self.fields = fields        # fields of `self` the class sets from outside (`_fields`)
        self.params = {a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs}
        self.given: dict[str, list[str]] = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.given.setdefault(t.id, []).append(_text(node.value))
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name) and node.value:
                self.given.setdefault(node.target.id, []).append(_text(node.value))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if isinstance(item.optional_vars, ast.Name):
                        self.given.setdefault(item.optional_vars.id, []).append(_text(item.context_expr))

    def from_outside(self, expr: str, depth: int = 0) -> bool:
        """The text of a path names the environment, or a parameter of the function, also through names given in it,
        or a field of the object that a method of its class set from outside (`self._token_file`, set in `__init__`
        from a parameter)."""
        if ENV.search(expr):
            return True
        if any(f in self.fields for f in re.findall(r"\bself\.(\w+)", expr)):
            return True
        names = set(re.findall(r"[A-Za-z_]\w*", expr))
        if names & self.params - {"self", "cls"}:
            return True
        if depth > 4:
            return False
        return any(self.from_outside(v, depth + 1) for n in names for v in self.given.get(n, []) if n not in self.params)


def _fields(tree) -> dict[int, frozenset]:
    """id of each method -> the fields of `self` that a method of its class sets from the environment or from a
    parameter of that method (`self.token_file = Path(token_file)` in `__init__`)."""
    out: dict[int, frozenset] = {}
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        methods = [m for m in cls.body if isinstance(m, FUNCS)]
        given: set[str] = set()
        for m in methods:
            look = _Function(m)
            for node in ast.walk(m):
                targets = node.targets if isinstance(node, ast.Assign) else \
                    [node.target] if isinstance(node, ast.AnnAssign) and node.value else []
                for t in targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" \
                            and look.from_outside(_text(node.value)):
                        given.add(t.attr)
        for m in methods:
            out[id(m)] = frozenset(given)
    return out


def _reads(fn) -> list[tuple[int, str, str]]:
    """(line, the path's text, the name read into) for each whole-file read in the function."""
    out = []
    kept: dict[int, str] = {}       # id of a call node -> the name its value is given to
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            for sub in ast.walk(node.value):
                kept[id(sub)] = node.targets[0].id
        if isinstance(node, ast.Return) and node.value is not None:
            for sub in ast.walk(node.value):
                kept.setdefault(id(sub), "")
    handles: dict[str, str] = {}    # `with open(p) as f`: f -> the text of p
    for node in ast.walk(fn):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                c = item.context_expr
                if (isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "open" and c.args
                        and isinstance(item.optional_vars, ast.Name) and not _writes(c)):
                    handles[item.optional_vars.id] = _text(c.args[0])
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr, base = node.func.attr, node.func.value
        if attr in ("read_text", "read_bytes"):
            out.append((node.lineno, _text(base), kept.get(id(node), "")))
        elif attr == "read":
            if isinstance(base, ast.Call) and isinstance(base.func, ast.Name) and base.func.id == "open" and base.args \
                    and not _writes(base):
                out.append((node.lineno, _text(base.args[0]), kept.get(id(node), "")))
            elif isinstance(base, ast.Name) and base.id in handles:
                out.append((node.lineno, handles[base.id], kept.get(id(node), "")))
    return out


def _writes(call: ast.Call) -> bool:
    mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"), None)
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+")


def read(text: str) -> list[dict]:
    """{line, function, path} for each secret read from a file whose place comes from outside, unchecked."""
    tree = ast.parse(text)
    lines = text.splitlines()
    out = []
    fields = _fields(tree)
    for fn in ast.walk(tree):
        if not isinstance(fn, FUNCS):
            continue
        body = "\n".join(lines[fn.lineno - 1:(fn.end_lineno or fn.lineno)])
        if CHECKS.search(body):
            continue
        called = {_text(c.func).rsplit(".", 1)[-1] for c in ast.walk(fn) if isinstance(c, ast.Call)}
        if any(CHECK_NAME.search(n) for n in called if n not in ("read_text", "read_bytes", "is_file", "exists")):
            continue
        here = _Function(fn, fields.get(id(fn), frozenset()))
        for line, path, into in _reads(fn):
            if not path or not _secretish(path, into, fn.name):
                continue
            if not here.from_outside(path):
                continue
            out.append({"line": line, "function": fn.name, "path": path[:80]})
            break       # one finding for a function
    return out


def unchecked(g: Graph) -> list[dict]:
    files = sorted({n.file for nid, n in g.nodes.items() if n.file and n.file.endswith(".py") and not outside(nid)})
    out = []
    for file in files:
        if NOT_THE_APP.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or not re.search(r"read_text|read_bytes|\.read\(", text):
            continue
        try:
            found = read(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        raw = text.splitlines()
        for c in found:
            out.append(_finding(
                RULE, f"`{c['function']}` takes a secret from a file without checking who owns it or whether it is a link",
                "MEDIUM", file, c["line"], category="code", conf="LOW", cwe=732, fixed_rank="medium",
                more=("Heuristic: read from this function's own lines. It reads a whole file and keeps it as a secret, "
                      f"and the file's place (`{c['path']}`) comes from the environment or from whoever calls it. "
                      "Nothing in the function asks who owns the file, who else may read or change it, or whether the "
                      "name is a link. Whoever can put a file or a link at that place chooses the secret: another user "
                      "of the computer, a program that shares the folder, a step that left the file open to all. "
                      "Fix: open the file without following a link (`os.open(path, os.O_RDONLY | os.O_NOFOLLOW)`), "
                      "`os.fstat` what was opened, and refuse it unless it is a plain file owned by this user that "
                      "nobody else may read or write (`st_uid == os.geteuid()`, `st_mode & 0o077 == 0`, `st_nlink == "
                      "1`). If the caller checks the file first, this is no problem."),
                snippet=raw[c["line"] - 1].strip() if 0 < c["line"] <= len(raw) else ""))
    return out
