"""What a flagged line is *for*: context that decides whether a scanner's pattern match is a real risk.

A pattern rule sees a name (`hashlib.md5`, an f-string next to `SELECT`) and cannot tell an S3 checksum from a stored
password, or a query that splices a fixed word from one that splices user input. This module reads the code around the
match, deterministically, and says what it found and how sure it is. It never deletes a finding: it can lower a rank
(with the reason written on the finding as `context`), and when it cannot tell, it says "unknown" and caps nothing
except what the evidence does not support (a weak hash of unknown purpose is not *critical*).

* `hash_purpose(...)`: a weak hash (MD5/SHA-1) is a vulnerability only when it protects something: a password, a
  token, a signature. Used as an identifier, a seed, a cache key or a protocol checksum (S3 `ContentMD5`) it is fine.
  Evidence is read from names only: the value hashed, where the result goes (variable, dict key, keyword), the
  enclosing function's name and parameters, and, for a small wrapper that returns the hash, the lines that call it.
  A security word anywhere wins over every other sign (the safe direction).
* `sql_splice(...)`: for an SQL string built in Python, which expressions are spliced into the text, and whether each
  one can only ever be fixed text (a literal, a choice between literals, a module constant). Values passed as driver
  parameters (`%s`, `?`, `:name`) are not spliced and are not counted.
* `password_hash_uses(...)`: the fast hashes in a repo that are applied to a password-named value, for the "Slow
  password hashing" protection.

Everything here reads names, not meaning, so it is labeled as such in the finding and the viewer: a password hidden
behind a neutral name everywhere it travels (`h(x)` called with `x = request.form["p"]`) reads as "unknown", and
stays ranked as before apart from the critical cap.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .python_frontend import project_text
from .websec import segments

# Whole lower-case words (websec.segments) that say a hash protects something.
SECURITY_WORDS = re.compile(
    r"\b(?:password|passwords|passwd|pwd|pw|pass phrase|passphrase|secret|secrets|token|tokens|signature|signatures|sign|"
    r"signed|signing|hmac|auth|authenticate|authentication|credential|credentials|session|sessions|otp|totp|salt|"
    r"api key|apikey|cookie|cookies|csrf|xsrf|login|nonce|cnonce|jwt|private key|pin|mac|verify|verification)\b")
PASSWORD_WORDS = re.compile(r"\b(?:password|passwords|passwd|pwd|pw|pass phrase|passphrase)\b")
# Every one of those words holds `pass` or `pw`, and a name's words are its own letters in lower case: a file whose
# text says neither, in any case, has no name the password check could count.
MAY_NAME_A_PASSWORD = re.compile(r"pass|pw", re.I)
# Words that say the hash is an identifier, a seed, a cache key or a checksum.
NON_SECURITY_WORDS = re.compile(
    r"\b(?:id|ids|uid|uuid|guid|seed|seeds|rng|random|cache|cached|etag|checksum|checksums|content md 5|fingerprint|"
    r"dedup|dedupe|shard|shards|bucket|buckets|slug|color|colour|partition|sample|sampling|variant|short hash|"
    r"stable id|cache key|file name|filename|row key|claim key|record key|dedup key)\b")
WEAK_HASH_RULES = re.compile(r"^(?:B303|B324)$|WEAK-HASH$|WEAK-PASSWORD-HASH$")
SQL_RULES = {"B608"}
# Fast (unsalted, unstretched) hashes: weak ones for findings, all of them for the password check
FAST_HASHES = {"md5", "sha1", "sha", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}


def _words(*names: str) -> str:
    return " ".join(segments(n) for n in names if n)


def _verdict(found: list[tuple[str, str]]) -> dict:
    """found: (where, words) pairs. A security word anywhere wins; then a non-security one; else unknown."""
    for where, w in found:
        m = SECURITY_WORDS.search(w)
        if m:
            return {"purpose": "security", "why": f"`{m.group(0)}` in {where}", "password": bool(PASSWORD_WORDS.search(w))}
    for where, w in found:
        m = NON_SECURITY_WORDS.search(w)
        if m:
            return {"purpose": "non-security", "why": f"`{m.group(0)}` in {where}", "password": False}
    return {"purpose": "unknown", "why": "no name around the hash says what it is for", "password": False}


# ---------------------------------------------------------------------------- Python (ast)

class _PyFile:
    """One parsed Python file with a parent map, cached per scan."""

    def __init__(self, text: str):
        self.tree = ast.parse(text)
        self.parent: dict[ast.AST, ast.AST] = {}
        self.hash_alias: set[str] = set()   # `from hashlib import md5 as fast` -> "fast"
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[-1] in ("hashlib", "MD5", "SHA", "SHA1", "Hash"):
                self.hash_alias |= {a.asname for a in node.names if a.asname and a.name.lower() in FAST_HASHES | {"new"}}
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node

    def enclosing_function(self, node: ast.AST):
        cur = self.parent.get(node)
        while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cur = self.parent.get(cur)
        return cur


def _py(path: Path, cache: dict, repo) -> _PyFile | None:
    key = str(path)
    if key not in cache:
        try:
            cache[key] = _PyFile(project_text(path, repo))
        except (OSError, SyntaxError, ValueError, RecursionError):
            cache[key] = None
    return cache[key]


def _names_in(node: ast.AST) -> list[str]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute):
            out.append(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) <= 40:
            out.append(n.value)      # a dict key such as "ContentMD5", an f-string's fixed parts are short words
    return out


def _target_names(t: ast.AST) -> list[str]:
    if isinstance(t, ast.Subscript):
        return _names_in(t.slice) + _target_names(t.value)
    return _names_in(t)


def _is_hash_call(node: ast.AST, aliases: set[str] = frozenset()) -> bool:
    """`hashlib.md5(...)`, `md5(...)`, `hashlib.sha1(...)`, `hashlib.new("md5", ...)`, `MD5.new(...)`, and a name
    imported as one of those (`from hashlib import md5 as fast`)."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name) and f.id in aliases:
        return True
    name = (f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else "").lower()
    if name in FAST_HASHES:
        return True
    if name == "new":
        owner = f.value.id.lower() if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
        first = node.args[0] if node.args else None
        algo = str(first.value).lower() if isinstance(first, ast.Constant) else ""
        return owner in FAST_HASHES or algo in FAST_HASHES
    return False


def _py_hash_context(pf: _PyFile, line: int) -> tuple[list[tuple[str, str]], ast.AST | None, bool]:
    """(evidence pairs, enclosing function, whether the function returns the hash) for the hash call on `line`."""
    calls = [n for n in ast.walk(pf.tree) if _is_hash_call(n, pf.hash_alias) and n.lineno <= line <= (n.end_lineno or n.lineno)]
    if not calls:
        return [], None, False
    call = min(calls, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)
    found = [("the value hashed", _words(*_names_in(ast.Module(body=[ast.Expr(a) for a in call.args], type_ignores=[]))))]
    shape = []
    cur, child, returned = pf.parent.get(call), call, False
    while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
        if isinstance(cur, ast.Subscript) and cur.value is child and isinstance(cur.slice, ast.Slice):
            shape.append("cut short")
        if isinstance(cur, ast.Call) and child is not cur.func:
            fname = cur.func.attr if isinstance(cur.func, ast.Attribute) else getattr(cur.func, "id", "")
            if fname in ("int", "from_bytes"):
                shape.append("turned into a number")
            found.append(("the call it is passed to", _words(fname)))
        if isinstance(cur, ast.keyword):
            found.append(("the argument it fills", _words(cur.arg or "")))
        if isinstance(cur, ast.Dict):
            for k, v in zip(cur.keys, cur.values):
                if v is child and k is not None:
                    found.append(("its dictionary key", _words(*_names_in(k))))
        if isinstance(cur, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = cur.targets if isinstance(cur, ast.Assign) else [cur.target]
            found.append(("where the result is stored", _words(*[x for t in targets for x in _target_names(t)])))
        if isinstance(cur, ast.Return):
            returned = True
        child, cur = cur, pf.parent.get(cur)
    fn = pf.enclosing_function(call)
    cls = pf.parent.get(fn) if fn is not None else None
    while cls is not None and not isinstance(cls, ast.ClassDef):
        cls = pf.parent.get(cls)
    if cls is not None:   # `HTTPDigestAuth.build_digest_header`: the class says what the method is for
        found.append((f"the class name `{cls.name}`", _words(cls.name)))
    if fn is not None:
        params = [a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs]
        found.append((f"the function name `{fn.name}`", _words(fn.name)))
        found.append(("the function's parameters", _words(*params)))
        if returned:
            body = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
            for s in body:   # a value prepared in the wrapper before it is hashed (`payload = f"{a}|{b}"`)
                if isinstance(s, ast.Assign):
                    found.append(("a value the function prepares", _words(*[x for t in s.targets for x in _target_names(t)])))
    if shape and not any(SECURITY_WORDS.search(w) for _, w in found):
        found.append((" and ".join(dict.fromkeys(shape)), "id"))   # a cut-short or numeric digest is an identifier
    return found, fn, returned


def _call_words(pf: "_PyFile", line: int, name: str) -> str | None:
    """The names in the arguments of the call to `name` on `line`, and where its result is stored; None when no such
    call is found (then the whole line is read)."""
    words = []
    for n in ast.walk(pf.tree):
        if isinstance(n, ast.Call) and n.lineno <= line <= (n.end_lineno or n.lineno):
            f = n.func
            if (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)) != name:
                continue
            words += [x for a in list(n.args) + [k.value for k in n.keywords] for x in _names_in(a)]
            words += [k.arg for k in n.keywords if k.arg]
            cur = pf.parent.get(n)
            while cur is not None and not isinstance(cur, (ast.stmt,)):
                cur = pf.parent.get(cur)
            if isinstance(cur, (ast.Assign, ast.AnnAssign)):
                targets = cur.targets if isinstance(cur, ast.Assign) else [cur.target]
                words += [x for t in targets for x in _target_names(t)]
    return _words(*words) if words else None


def _caller_lines(g, node_id: str, lines_for, py_cache: dict) -> list[tuple[str, str]]:
    """What a wrapper's callers hand it and where they keep the result, as evidence pairs (at most 20 callers)."""
    out = []
    callee = g.nodes.get(node_id)
    for e in g.callers(node_id)[:20]:
        src = g.nodes.get(e.src)
        if not src or not src.file:
            continue
        pf = _py(Path(g.repo_root) / src.file, py_cache, g.repo_root) if src.file.endswith(".py") else None
        text = lines_for(src.file)
        for ln in (e.lines or [])[:3]:
            w = _call_words(pf, ln, callee.name) if pf is not None and callee is not None else None
            if w is None and 0 < ln <= len(text):
                w = _words(*re.findall(r"[A-Za-z_]\w*", re.sub(r"#.*$", "", text[ln - 1])))
            if w is not None:
                out.append((f"a call to it at {src.file}:{ln}", w))
    return out


def _node_id_at(g, file: str, line: int) -> str | None:
    best, span = None, None
    for n in g.nodes_in(file):
        if n.start_line and n.start_line <= line <= (n.end_line or n.start_line) and n.kind != "module":
            s = (n.end_line or n.start_line) - n.start_line
            if span is None or s < span:
                best, span = n.id, s
    return best


def evidence(g, file: str, line: int, node_id: str | None, lines_for, py_cache: dict) -> list[tuple[str, str]]:
    """(where, words) pairs around the hash on `file:line`. For a small Python function that returns the hash (a
    wrapper), the lines that call it are read too, unless the wrapper itself already names a security use."""
    found: list[tuple[str, str]] = []
    if file.endswith(".py"):
        pf = _py(Path(g.repo_root) / file, py_cache, g.repo_root)
        if pf is not None:
            found, fn, returned = _py_hash_context(pf, line)
            small = fn is not None and ((fn.end_lineno or fn.lineno) - fn.lineno) <= 12
            node_id = node_id or _node_id_at(g, file, line)
            if found and returned and small and node_id and not any(SECURITY_WORDS.search(w) for _, w in found):
                found += _caller_lines(g, node_id, lines_for, py_cache)
    if not found:   # other languages, or Python that did not parse: the flagged line and the enclosing function
        text = lines_for(file)
        code = text[line - 1] if 0 < line <= len(text) else ""
        found = [("the flagged line", _words(*re.findall(r"[A-Za-z_][\w]*", code)))]
        n = g.nodes.get(node_id or "") or g.nodes.get(_node_id_at(g, file, line) or "")
        if n is not None:
            found.append((f"the function name `{n.name}`", _words(n.name or "")))
            found.append(("the function's parameters", _words(*re.findall(r"[A-Za-z_]\w*", n.signature or "")[1:])))
    return found


def hash_purpose(g, f: dict, lines_for, py_cache: dict) -> dict | None:
    """What a weak-hash finding's hash is for: {purpose: security|non-security|unknown, why, password}."""
    if not WEAK_HASH_RULES.search(f.get("rule") or "") or not f.get("file") or not f.get("line"):
        return None
    if "PASSWORD" in (f.get("rule") or ""):
        return {"purpose": "security", "why": "the rule matched a password hash", "password": True, "reads": "names"}
    v = _verdict(evidence(g, f["file"], f["line"], f.get("node"), lines_for, py_cache))
    v["reads"] = "names"
    return v


# ---------------------------------------------------------------------------- SQL built in Python

_SQL_WORD = re.compile(r"\b(?:select|insert|update|delete|from|where|values|into|join|order\s+by|group\s+by)\b", re.I)


def _const_value(node: ast.AST) -> bool:
    """A literal, a choice between literals, or an f-string/concatenation of literals."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, int, float, bool)) or node.value is None
    if isinstance(node, ast.IfExp):
        return _const_value(node.body) and _const_value(node.orelse)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _const_value(node.left) and _const_value(node.right)
    return False


def _assignments(scope: ast.AST, name: str) -> list[ast.AST] | None:
    """Every value `name` is given in `scope` (not descending into nested functions), or None when it is bound some
    other way (a parameter, a loop, `with … as`, `+=`, unpacking, a walrus, an import, a `match` capture, an
    `except … as`), or when a function inside `scope` (or, for a module, any function) may rebind it through
    `nonlocal`/`global`: what that function sets is not followed, so nothing can be called fixed."""
    for n in ast.walk(scope):
        if isinstance(n, (ast.Nonlocal, ast.Global)) and name in n.names:
            return None
        if isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name == name:
            return None
        if isinstance(n, ast.MatchMapping) and n.rest == name:
            return None
        if isinstance(n, ast.ExceptHandler) and n.name == name:
            return None
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    out.append(n.value)
                elif any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(t)):
                    return None
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
            if n.value is None:
                continue
            out.append(n.value)
        elif isinstance(n, (ast.AugAssign, ast.For, ast.AsyncFor, ast.withitem, ast.NamedExpr, ast.comprehension)):
            tgt = getattr(n, "target", None) or getattr(n, "optional_vars", None)
            if tgt is not None and any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(tgt)):
                return None
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            if any((a.asname or a.name.split(".")[0]) == name for a in n.names):
                return None
        stack.extend(ast.iter_child_nodes(n))
    return out


def _fixed_text(expr: ast.AST, fn, module: ast.Module) -> tuple[bool, str]:
    """(can only be fixed text, how we know)."""
    if _const_value(expr):
        return True, "a literal"
    if not isinstance(expr, ast.Name):
        return False, "an expression Lantern does not follow"
    name = expr.id
    if fn is not None:
        if name in {a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs} or \
                (fn.args.vararg and fn.args.vararg.arg == name) or (fn.args.kwarg and fn.args.kwarg.arg == name):
            return False, f"`{name}` is a parameter"
        vals = _assignments(fn, name)
        if vals is None:
            return False, f"`{name}` is set in a way Lantern does not follow"
        if vals:
            if all(_const_value(v) for v in vals):
                return True, f"`{name}` is only ever set to fixed text in this function"
            return False, f"`{name}` is set from a value that is not fixed text"
    vals = _assignments(module, name)
    if vals and all(_const_value(v) for v in vals):
        return True, f"`{name}` is a module constant"
    return False, f"`{name}` comes from outside this function"


def sql_splice(g, f: dict, py_cache: dict) -> dict | None:
    """For an SQL string built in Python: {fixed_only: bool, spliced: [{expr, fixed, why}], driver_params: bool}."""
    if f.get("rule") not in SQL_RULES or not (f.get("file") or "").endswith(".py") or not f.get("line"):
        return None
    pf = _py(Path(g.repo_root) / f["file"], py_cache, g.repo_root)
    if pf is None:
        return None
    line = f["line"]
    cands = []
    for n in ast.walk(pf.tree):
        if not (getattr(n, "lineno", 0) <= line <= (getattr(n, "end_lineno", 0) or 0)):
            continue
        if isinstance(n, ast.JoinedStr) and _SQL_WORD.search(" ".join(
                v.value for v in n.values if isinstance(v, ast.Constant) and isinstance(v.value, str))):
            cands.append((n, [v.value for v in n.values if isinstance(v, ast.FormattedValue)]))
        elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            parts, stack = [], [n]
            while stack:
                x = stack.pop()
                if isinstance(x, ast.BinOp) and isinstance(x.op, ast.Add):
                    stack += [x.left, x.right]
                else:
                    parts.append(x)
            if isinstance(n.op, ast.Mod):
                parts = [n.left] + (list(n.right.elts) if isinstance(n.right, ast.Tuple) else [n.right])
            text = " ".join(p.value for p in parts if isinstance(p, ast.Constant) and isinstance(p.value, str))
            if _SQL_WORD.search(text):
                cands.append((n, [p for p in parts if not (isinstance(p, ast.Constant) and isinstance(p.value, str))]))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and \
                isinstance(n.func.value, ast.Constant) and _SQL_WORD.search(str(n.func.value.value)):
            cands.append((n, list(n.args) + [k.value for k in n.keywords]))
    if not cands:
        return None
    node, spliced = min(cands, key=lambda c: (c[0].end_lineno or c[0].lineno) - c[0].lineno)
    fn = pf.enclosing_function(node)
    out = []
    for expr in spliced:
        ok, why = _fixed_text(expr, fn, pf.tree)
        out.append({"expr": ast.unparse(expr)[:60], "fixed": ok, "why": why})
    # values handed to the driver separately: the string is the first argument of a call with a second argument
    call = pf.parent.get(node)
    driver = isinstance(call, ast.Call) and len(call.args) >= 2 and call.args[0] is node
    return {"fixed_only": bool(out) and all(s["fixed"] for s in out), "spliced": out, "driver_params": driver,
            "reads": "this function and module constants"}


# ---------------------------------------------------------------------------- slow password hashing

def password_hash_uses(g, hits: list[tuple[str, int, str]], lines_for, py_cache: dict) -> list[tuple[str, int, str]]:
    """The fast-hash hits (file, line, text) that hash a password-named value, store the result as one, sit in a
    password-named function, or sit in a small wrapper that is called with one."""
    return [(file, line, text) for file, line, text in hits
            if any(PASSWORD_WORDS.search(w) for _, w in evidence(g, file, line, None, lines_for, py_cache))]


def _bundle(t: str) -> bool:
    """A built bundle (as js_frontend.built_bundle): libraries squeezed onto a few long lines, and slow to blank."""
    return len(t) > 50_000 and (len(t) / (t.count("\n") + 1) > 500 or max(map(len, t.split("\n"))) > 50_000)


def code_mentions(code_texts, rx: re.Pattern) -> tuple[str, int] | None:
    """The first place `rx` matches in code with strings and comments blanked (an import, a call), or None."""
    from .websec import code_only
    for f, t in code_texts:
        if _bundle(t) or not rx.search(t):
            continue
        code = code_only(t, not f.endswith(".py"))
        m = rx.search(code)
        if m:
            return f, code.count("\n", 0, m.start()) + 1
    return None


def handles_passwords(code_texts) -> list[tuple[str, int, str]]:
    """Places where code (strings and comments blanked) names a password value: `password`, `user.passwd`,
    `hashPassword(...)`. A word in a string or a regex list is not counted."""
    from .websec import code_only
    rx = re.compile(r"[A-Za-z_][\w]*")
    out = []
    for f, t in code_texts:
        if _bundle(t) or not MAY_NAME_A_PASSWORD.search(t):
            continue
        js = not f.endswith(".py")
        code = code_only(t, js)
        for m in rx.finditer(code):
            if PASSWORD_WORDS.search(segments(m.group(0))):
                ln = code.count("\n", 0, m.start()) + 1
                out.append((f, ln, t.splitlines()[ln - 1].strip()[:160]))
                break
        if len(out) >= 40:
            break
    return out


# ---------------------------------------------------------------------------- a browser-visible value: does the server trust it?

SERVER_EXTS = (".py", ".go", ".rs", ".java", ".kt", ".cs", ".php", ".rb")
_HEADER_KEY = re.compile(r"""['"`]((?:X-[A-Za-z0-9-]+)|Authorization)['"`]\s*:""")
_CONDITION = re.compile(r"^\s*(?:if|elif|else\s+if|unless)\b[^\n]*?\b((?:settings|config|conf|cfg|app\.config|"
                        r"process\.env|os\.environ)\s*(?:\.|\[\s*['\"])\s*([A-Za-z_]\w*))")


def _server_files(g) -> list[str]:
    from .js_frontend import TEST_RE as JS_TEST_RE
    from .python_frontend import TEST_FILE_RE
    files = {n.file for n in g.nodes.values() if n.file and (n.lane in ("server", "data") or n.file.endswith(SERVER_EXTS))}
    return sorted(f for f in files if not (TEST_FILE_RE.search(f) or JS_TEST_RE.search(f)))


def _routes_above(g, node_id: str, depth: int = 6) -> list[str]:
    """Route entry points from which `node_id` is called (the node itself included), nearest first."""
    out, seen, frontier = [], {node_id}, [node_id]
    for _ in range(depth + 1):
        nxt = []
        for nid in frontier:
            n = g.nodes.get(nid)
            if n is not None and (n.entry or {}).get("kind") == "route":
                out.append(nid)
            for e in g.callers(nid):
                if e.src not in seen:
                    seen.add(e.src)
                    nxt.append(e.src)
        frontier = nxt
    return out


def public_secret_trust(g, f: dict, lines_for) -> dict | None:
    """For a setting the build ships to every browser (LW-PUBLIC-SECRET): the four facts kept apart.
    1. browser: where the frontend reads it and the header it is sent in (if any);
    2. server_trusts: server code that reads the same setting, or reads that header, with the routes that reach it;
    3. stranger_access: never decided here (Lantern does not run the app or know production's settings);
    4. other_controls: other login checks on those routes, and the settings the checking code branches on.
    No finding is called a confirmed bypass from this: a value being visible is one fact, trust is another."""
    if f.get("rule") != "LW-PUBLIC-SECRET" or not f.get("snippet"):
        return None
    from .websec import PUBLIC_PREFIX, call_adjacency, login_check
    name = f["snippet"]
    base = re.sub("^" + PUBLIC_PREFIX, "", name)
    if not base or base == name:
        return None
    key = base.lower()
    # 1. the browser side: the header the value travels in, read from the function that reads it
    text = lines_for(f["file"])
    sent_as = None
    lo, hi = max(1, (f.get("line") or 1) - 15), (f.get("line") or 1) + 15
    nid = _node_id_at(g, f["file"], f.get("line") or 0)
    n = g.nodes.get(nid or "")
    if n is not None and n.start_line:
        lo, hi = n.start_line, n.end_line or n.start_line
    for ln in range(lo, min(hi, len(text)) + 1):
        m = _HEADER_KEY.search(text[ln - 1])
        if m:
            sent_as = m.group(1)
            break
    # 2. the server side
    env_rx = re.compile(r"\b[A-Z0-9_]*" + re.escape(base) + r"\b")
    attr_rx = re.compile(r"\b" + re.escape(key) + r"\b")
    hdr_rx = re.compile(r"""['"`]""" + re.escape(sent_as) + r"""['"`]""", re.I) if sent_as else None
    reads, checks = [], []
    servers = [s for s in _server_files(g) if s != f["file"]]
    for file in servers:
        raw = "\n".join(lines_for(file))
        if not (attr_rx.search(raw) or env_rx.search(raw) or (hdr_rx is not None and hdr_rx.search(raw))) or _bundle(raw):
            continue
        # comments and docstrings blanked; string literals kept apart so a header name in a string still counts
        js = not file.endswith((".py", ".rb"))
        doc_free = re.sub(r"(\"\"\"|\'\'\')[\s\S]*?\1", lambda m: re.sub(r"[^\n]", " ", m.group(0)), raw) if not js else raw
        doc_free = re.sub(r"#[^\n]*" if not js else r"//[^\n]*", "", doc_free)
        for i, code in enumerate(doc_free.split("\n"), 1):
            if hdr_rx is not None and hdr_rx.search(code):
                checks.append((file, i))
            elif env_rx.search(code) or attr_rx.search(code):
                reads.append((file, i))
    routes, controls, conditions = [], [], []
    adj = None
    for file, ln in checks[:5]:
        fn = _node_id_at(g, file, ln)
        if not fn:
            continue
        for rid in _routes_above(g, fn):
            r = g.nodes[rid]
            detail = (r.entry or {}).get("detail") or r.name
            if detail not in routes:
                routes.append(detail)
                adj = adj if adj is not None else call_adjacency(g)
                lc = login_check(g, r, adj, "\n".join(lines_for(r.file)) if r.file else None)
                controls.append({"route": detail, "login_check": lc[0] if lc else None, "why": lc[1] if lc else None})
        for nid2 in [fn] + _routes_above(g, fn):
            nn = g.nodes.get(nid2)
            if nn is None or not nn.file or not nn.start_line:
                continue
            body = lines_for(nn.file)[nn.start_line - 1:(nn.end_line or nn.start_line)]
            for line in body:
                m = _CONDITION.search(line)
                if m and m.group(2) not in conditions:
                    conditions.append(m.group(2))
    if checks:
        verdict = "server-checks-it"
    elif reads:
        verdict = "server-reads-it"
    elif servers:
        verdict = "not-seen-on-server"
    else:
        verdict = "no-server-code"
    unknown = ["whether a request carrying this value can reach anything protected: Lantern does not run the app"]
    if checks or reads:
        unknown.insert(0, f"whether production sets {', '.join(sorted({m.group(0) for fl, ln in reads[:20] for m in env_rx.finditer(lines_for(fl)[ln - 1])}) or [base])}")
    if conditions:
        unknown.append("which way production sets " + ", ".join(conditions[:6]) + " (the checking code depends on them)")
    if verdict == "no-server-code":
        unknown.append("the server is not in this repository, so whether it trusts the value cannot be read here")
    return {
        "browser": {"exposed": True, "where": f"{f['file']}:{f.get('line')}", "sent_as": sent_as},
        "server_trusts": verdict,
        "server_checks": [f"{a}:{b}" for a, b in checks[:5]],
        "server_reads": [f"{a}:{b}" for a, b in reads[:5]],
        "routes": routes[:6],
        "other_controls": controls[:6],
        "conditions": conditions[:6],
        "stranger_access": "not determined",
        "unknown": unknown,
        "reads": "names and strings in this repository",
    }
