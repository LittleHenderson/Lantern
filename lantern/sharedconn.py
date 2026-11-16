"""A database connection that every thread shares and that is used with no lock held (2026-11-16). One heuristic,
`tool_confidence: LOW` and ranked medium; it reads a Python file's own text and runs nothing.

`LW-SHARED-CONNECTION` (`shared_connections`): a file opens one SQLite connection for the whole program with the
library's own guard switched off (`sqlite3.connect(..., check_same_thread=False)`: the code's own word that more
than one thread will use it), keeps it on `self`, on its class or at the top of the file, and a function then uses
it with no lock held. Two requests that are answered on two threads at the same moment can then be on the one
connection together: one of them gets an error out of the library, or an answer that is empty ("nobody by that
name" for a person who is there) or that belongs to the other request.

It says nothing where a use stands under a lock (`with self.lock:`, a decorator with a lock's name, an `acquire()`
in the function), in the function that opens the connection and at the top of the file (before any thread has
it), for a bare `close()`, and in a function that this file only calls from such places. Where every use that is
left stands in `async def` functions, or in functions only they call, it says nothing either: those lines all run
on the one thread of the event loop. Beside a use on another thread they are named too, because the loop's
thread and that one are two. A connection that is opened for each call or kept for each thread is not shared and
not looked at, and neither is one that only a function hands out (`get_db().execute(...)`). It does not know how
the program is run (on one thread or on many), nor what calls a function from another file: it says "check"."""
from __future__ import annotations

import ast
import re
import warnings
from pathlib import Path

from .graph import Graph, outside
from .localweb import NOT_THE_APP
from .python_frontend import project_text
from .websec import _finding

RULE = "LW-SHARED-CONNECTION"
MOST_FILE = 400_000         # characters of a file that are read
MOST_NODES = 150_000        # parts of a file's tree that are walked
MOST_NAMED = 6              # further functions one finding names

SQLITE = frozenset({"sqlite3", "pysqlite3", "sqlean"})
LOCKS = frozenset({"Lock", "RLock", "Semaphore", "BoundedSemaphore", "Condition"})
LOCK_NAME = re.compile(r"(?i)(?<![bc])lock|mutex|semaphore|synchroni[sz]ed")
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
SELF = ("self", "cls")
ALONE, LOOP, THREADS = 0, 1, 2      # how a function is run, as far as its file shows (`_run_how`)


class _TooBig(Exception):
    pass


def _plain(node) -> str:
    """`a.b.c` for a name with its attributes, and "" for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _dotted(node) -> str:
    """As `_plain`, and through a call and a subscript: `self.locks[key]`, `guard()`, `self.lock.reader()`."""
    parts: list[str] = []
    for _ in range(60):
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            break
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _lockish(name: str, known) -> bool:
    return bool(name) and (name in known or any(LOCK_NAME.search(part) for part in name.split(".")))


class _Fn:
    """One function of the file: its name, what encloses it and the names that are its own."""
    __slots__ = ("name", "line", "is_async", "locked", "binds", "frees", "parent")

    def __init__(self, node, parent, known):
        self.name, self.line, self.parent = node.name, node.lineno, parent
        self.is_async = isinstance(node, ast.AsyncFunctionDef)
        self.locked = any(_lockish(_dotted(d), known) for d in node.decorator_list)
        a = node.args
        self.binds = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
        self.binds.update(x.arg for x in (a.vararg, a.kwarg) if x is not None)
        self.frees: set[str] = set()         # names it says are the file's own: `global conn`

    def owns(self, name: str) -> bool:
        """Is `name`, read in this function, a name of this function or of one around it (and not the file's)?"""
        fn = self
        while fn is not None:
            if name in fn.frees:
                return False
            if name in fn.binds:
                return True
            fn = fn.parent
        return False


class _Facts:
    def __init__(self):
        self.fns: list[_Fn] = []
        self.assigns: list[tuple] = []       # (targets, value, fn, class, in a class's own lines, line)
        self.returns: dict[_Fn, list] = {}
        self.names: list[tuple] = []         # (name, node, fn, lock held) for a name that is read
        self.attrs: list[tuple] = []         # (base, attribute, node, fn, class, lock held), read
        self.sites: dict[str, list] = {}     # a function's name -> the places it is called: (fn, lock held)
        self.called: set[int] = set()        # the nodes that are a call's function
        self.closed: set[int] = set()        # the nodes a bare `.close()` hangs on
        self.takers: set[_Fn] = set()        # functions that call `<lock>.acquire()` themselves


def _setup(tree):
    """The names this file gives to the SQLite library, to its `connect`, and to locks it makes."""
    sqlite, connects, known = set(SQLITE), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in SQLITE:
                    sqlite.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in SQLITE:
                connects.update(a.asname or a.name for a in node.names if a.name == "connect")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
            if _plain(node.value.func).rpartition(".")[2] in LOCKS:
                for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    if _plain(t):
                        known.add(_plain(t))
    return sqlite, connects, known


def _walk(tree, known) -> _Facts:
    """One pass over the file's tree with no recursion: each part with the function and the class it stands in and
    whether a lock is held there. A function written under a lock is not run under it."""
    facts = _Facts()
    stack = [(tree, None, None, False, False)]       # part, function, class, lock held, in a class's own lines
    seen = 0
    while stack:
        node, fn, cls, locked, in_class = stack.pop()
        seen += 1
        if seen > MOST_NODES:
            raise _TooBig()
        if isinstance(node, FUNCS):
            inner = _Fn(node, fn, known)
            facts.fns.append(inner)
            if fn is not None and not in_class:
                fn.binds.add(node.name)
            a = node.args
            for d in node.decorator_list + a.defaults + [k for k in a.kw_defaults if k is not None]:
                stack.append((d, fn, cls, locked, in_class))
            stack.extend((child, inner, cls, False, False) for child in node.body)
            continue
        if isinstance(node, ast.ClassDef):
            for d in node.decorator_list + node.bases + [k.value for k in node.keywords]:
                stack.append((d, fn, cls, locked, in_class))
            stack.extend((child, fn, node, locked, True) for child in node.body)
            continue
        if isinstance(node, (ast.With, ast.AsyncWith)):
            held = locked or any(_lockish(_dotted(i.context_expr), known) for i in node.items)
            for i in node.items:
                stack.append((i.context_expr, fn, cls, locked, in_class))
                if i.optional_vars is not None:
                    stack.append((i.optional_vars, fn, cls, locked, in_class))
            stack.extend((child, fn, cls, held, in_class) for child in node.body)
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            facts.assigns.append((targets, node.value, fn, cls, in_class, node.lineno))
        elif isinstance(node, ast.Return) and node.value is not None and fn is not None:
            facts.returns.setdefault(fn, []).append(node.value)
        elif isinstance(node, ast.Global) and fn is not None:
            fn.frees.update(node.names)
        elif isinstance(node, ast.Call):
            f = node.func
            facts.called.add(id(f))
            if isinstance(f, ast.Name):
                facts.sites.setdefault(f.id, []).append((fn, locked))
            elif isinstance(f, ast.Attribute):
                facts.sites.setdefault(f.attr, []).append((fn, locked))
                if f.attr == "close" and not node.args and not node.keywords:
                    facts.closed.add(id(f.value))
                elif f.attr == "acquire" and fn is not None and _lockish(_dotted(f.value), known):
                    facts.takers.add(fn)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                facts.names.append((node.id, node, fn, locked))
            elif fn is not None and not in_class:
                fn.binds.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and isinstance(node.ctx, ast.Load):
            facts.attrs.append((node.value.id, node.attr, node, fn, cls, locked))
        stack.extend((child, fn, cls, locked, in_class) for child in ast.iter_child_nodes(node))
    return facts


def _opens(node, sqlite, connects, makers) -> bool:
    """`sqlite3.connect(..., check_same_thread=False)`, or a call of a function of this file that returns one."""
    if not isinstance(node, ast.Call):
        return False
    parts = _plain(node.func).split(".")
    if len(parts) == 1 and parts[0] in makers or len(parts) == 2 and parts[0] in SELF and parts[1] in makers:
        return True
    if not (len(parts) > 1 and parts[0] in sqlite and parts[-1] == "connect"
            or len(parts) == 1 and parts[0] in connects):
        return False
    return any(k.arg == "check_same_thread" and isinstance(k.value, ast.Constant) and k.value.value is False
               for k in node.keywords)


def _connections(facts: _Facts, sqlite, connects) -> dict:
    """The connections this file keeps for the whole program: on `self`, on a class, or under a name of the file."""
    local: dict[_Fn, set[str]] = {}
    for targets, value, fn, _cls, in_class, _line in facts.assigns:
        if fn is not None and not in_class and _opens(value, sqlite, connects, ()):
            local.setdefault(fn, set()).update(t.id for t in targets
                                               if isinstance(t, ast.Name) and t.id not in fn.frees)
    makers = {fn.name for fn, values in facts.returns.items()
              if any(_opens(v, sqlite, connects, ()) or isinstance(v, ast.Name) and v.id in local.get(fn, ())
                     for v in values)}
    conns: dict[tuple, dict] = {}
    for targets, value, fn, cls, in_class, line in facts.assigns:
        if not _opens(value, sqlite, connects, makers):
            continue
        for t in targets:
            key = None
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in SELF:
                if cls is not None and fn is not None:
                    key, shown = ("attr", id(cls), t.attr), f"self.{t.attr}"
            elif isinstance(t, ast.Name):
                if in_class and cls is not None:
                    key, shown = ("attr", id(cls), t.id), f"{cls.name}.{t.id}"
                elif fn is None or t.id in fn.frees:
                    key, shown = ("name", t.id), t.id
            if key is None:
                continue
            c = conns.setdefault(key, {"shown": shown, "line": line, "homes": set(),
                                       "of": cls.name if key[0] == "attr" else None})
            c["line"] = min(c["line"], line)
            if fn is not None:
                c["homes"].add(fn)
    return conns


def _run_how(facts: _Facts, homes: set) -> dict:
    """How each function of the file is run, as far as the file shows. ALONE: it takes a lock itself, opens the
    connection, or is only called from where one thread at a time is (under a lock, at the top of the file, in
    another such function). LOOP: an `async def`, or a function only called from such: on the one thread of the
    event loop. THREADS: anything else. A function that is handed on by its name (a thread's target, a handler) or
    that this file never calls is called from somewhere the file does not show."""
    names = {f.name for f in facts.fns}
    handed = {name for name, node, _fn, _locked in facts.names if name in names and id(node) not in facts.called}
    handed.update(attr for base, attr, node, _fn, _cls, _locked in facts.attrs
                  if base in SELF and attr in names and id(node) not in facts.called)
    how, settled = {}, set()
    for f in facts.fns:
        if f.locked or f in facts.takers or f in homes:
            how[f] = ALONE
        elif f.is_async:
            how[f] = LOOP
        elif f.name in handed or not facts.sites.get(f.name):
            how[f] = THREADS
        else:
            how[f] = ALONE                  # until a place it is called from says otherwise
            continue
        settled.add(f)
    changed = True
    while changed:
        changed = False
        for f in facts.fns:
            if f in settled:
                continue
            worst = max(ALONE if locked or fn is None else how[fn] for fn, locked in facts.sites[f.name])
            if worst > how[f]:
                how[f], changed = worst, True
    return how


def read(text: str) -> list[dict]:
    """One record for each shared connection of a file that is used with no lock held: where it is opened
    (`opened`), how the code writes it (`shown`), the functions that use it that way with the first such line of
    each (`places`, in the file's order) and how many uses of it stand under a lock (`held`)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(text)
    sqlite, connects, known = _setup(tree)
    facts = _walk(tree, known)
    conns = _connections(facts, sqlite, connects)
    if not conns:
        return []
    homes = set().union(*(c["homes"] for c in conns.values()))
    how = _run_how(facts, homes)
    by_class = {(c["of"], key[2]): key for key, c in conns.items() if key[0] == "attr"}
    uses: dict[tuple, list] = {key: [] for key in conns}
    for base, attr, node, fn, cls, locked in facts.attrs:
        key = ("attr", id(cls), attr) if base in SELF and cls is not None else by_class.get((base, attr))
        if key in uses:
            uses[key].append((node.lineno, fn, locked, node))
    for name, node, fn, locked in facts.names:
        if ("name", name) in uses and fn is not None and not fn.owns(name):
            uses[("name", name)].append((node.lineno, fn, locked, node))
    out = []
    for key, c in sorted(conns.items(), key=lambda kv: kv[1]["line"]):
        places: dict[_Fn, int] = {}
        held = 0
        for line, fn, locked, node in sorted(uses[key], key=lambda u: u[0]):
            if locked or fn is not None and (fn.locked or fn in facts.takers):
                held += 1
            elif fn is not None and how[fn] != ALONE and id(node) not in facts.closed:
                places.setdefault(fn, line)
        # with every use that is left on the event loop's one thread, no two of them run at the same moment
        if any(how[fn] == THREADS for fn in places):
            out.append({"opened": c["line"], "shown": c["shown"], "held": held,
                        "places": [(fn.name, line) for fn, line in places.items()]})
    return out


def shared_connections(g: Graph) -> list[dict]:
    """Connections kept for the whole program and used with no lock held (see the note above). Heuristic."""
    files = sorted({n.file for nid, n in g.nodes.items()
                    if n.file and n.file.endswith(".py") and not outside(nid)})
    out = []
    for file in files:
        if NOT_THE_APP.search(file):
            continue
        try:
            text = project_text(Path(g.repo_root) / file, g.repo_root, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or "check_same_thread" not in text:
            continue
        try:
            found = read(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError, _TooBig):
            continue
        raw = text.splitlines()
        for c in found:
            (name, line), more = c["places"][0], c["places"][1:]
            also = ", ".join(f"`{n}` (line {at})" for n, at in more[:MOST_NAMED])
            if len(more) > MOST_NAMED:
                also += f" and {len(more) - MOST_NAMED} more"
            locks = (f"{c['held']} other use{'s' if c['held'] != 1 else ''} of it in this file "
                     f"stand{'s' if c['held'] == 1 else ''} under a lock; "
                     f"{'these do' if more else 'this one does'} not. " if c["held"] else
                     "Lantern found no lock around any use of it in this file. ")
            out.append(_finding(
                RULE,
                f"`{c['shown']}` is one database connection for every thread, and `{name}` uses it with no lock held",
                "MEDIUM", file, line, category="code", conf="LOW", cwe=567, fixed_rank="medium",
                more=("Heuristic: read from this file's own text. "
                      f"Line {c['opened']} opens one SQLite connection with the library's own guard switched off "
                      "(`check_same_thread=False`), which says that more than one thread will use it, and keeps it "
                      f"for the whole program. This line uses it with no lock held"
                      + (f", and so {'does' if len(more) == 1 else 'do'} {also}" if more else "") + ". "
                      "Where two requests are answered on two threads at the same moment, both can be on the one "
                      "connection together: one gets an error out of the library, or an answer that is empty or "
                      "that belongs to the other request. " + locks +
                      "Take one lock around every use of the connection, a read too (a lock a thread may take "
                      "again, `threading.RLock()`, where one locked step calls another), or open a connection for "
                      "each thread or each request. Lantern does not know whether this program answers on more "
                      "than one thread, nor what calls these functions from another file."),
                snippet=raw[line - 1].strip() if 0 < line <= len(raw) else ""))
    return out
