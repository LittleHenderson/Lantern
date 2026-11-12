"""Python frontend: discover files, parse them with tree-sitter, and resolve calls into the UCG.

Resolution is deliberately conservative. Each edge records *how* it was resolved (`via`) and a
confidence level, so the viewer and the reports can be honest about what is proven and what is
guessed. Phase 0 does not use a type checker; that is a planned upgrade (Pyright) for Phase 1.
"""

from __future__ import annotations

import builtins
import errno
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_python as tsp
from tree_sitter import Language, Node as TSNode, Parser

from . import calls, manifest
from .graph import (CALLABLE, CALLS, CLASS, CONTAINS, IMPLEMENTS, INFERRED, MAY_CALL, MODULE,
                    POSSIBLE, RESOLVED, Graph, Node)

PY_LANGUAGE = Language(tsp.language())

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", ".env", ".tox", ".nox",
    "node_modules", "build", "dist", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
    ".eggs", ".lantern", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel", ".expo", "coverage",
    ".parcel-cache", ".angular", "bower_components", "vendor",
}

# A folder named `env` is a Python environment in one project (`python -m venv env`) and the project's own code or
# settings in another (`config/env/`, `src/env/`). It is left out only where it holds what an environment holds;
# until 2026-11-11 the name alone was enough, and a project's own folder of that name was not read by any reader.
ENV_NAMES = {"env"}
ENV_SIGNS = ("pyvenv.cfg", "conda-meta", "bin/activate", "bin/python", "Scripts/activate", "Scripts/activate.bat",
             "Scripts/python.exe", "Lib/site-packages")


def is_environment(folder) -> bool:
    """Whether this folder is a Python environment, by what it holds: the file `venv` writes, conda's records, the
    programs that switch it on, its library folder. A link counts as being there and is never followed. What cannot
    be told is left out, as every folder of that name was before."""
    folder = Path(folder)
    try:
        return any(os.path.lexists(folder / sign) for sign in ENV_SIGNS) or any(folder.glob("lib/python*"))
    except OSError:
        return True


def skipped_dir(parent, name: str) -> bool:
    """Whether the folder `name` inside `parent` is left out: for a reader that walks the project folder by
    folder."""
    return name in SKIP_DIRS or (name in ENV_NAMES and is_environment(Path(parent) / name))


def skipped(parts, root) -> bool:
    """Whether a file under these folder names, counted from the project's root, is left out: for a reader that
    lists every file and looks at its path."""
    for i, name in enumerate(parts):
        if name in SKIP_DIRS or (name in ENV_NAMES and is_environment(Path(root, *parts[:i + 1]))):
            return True
    return False


BUILTIN_NAMES = set(dir(builtins))
STDLIB = set(getattr(__import__('sys'), 'stdlib_module_names', ()))

# Method names so common on builtins (list, dict, str, file...) that guessing a repo target from the
# name alone would mostly be wrong. Calls like `x.append()` on an unknown receiver are left unresolved.
GENERIC_METHODS = {
    "append", "extend", "insert", "pop", "remove", "clear", "copy", "count", "index", "sort",
    "reverse", "get", "items", "keys", "values", "update", "setdefault", "add", "discard", "join",
    "split", "rsplit", "strip", "lstrip", "rstrip", "replace", "format", "lower", "upper",
    "startswith", "endswith", "encode", "decode", "read", "write", "readline", "readlines",
    "close", "open", "find", "match", "search", "group", "sub", "send", "flush", "seek", "tell",
    "exists", "mkdir", "unlink", "is_file", "is_dir", "resolve", "info", "debug", "warning",
    "error", "exception", "critical", "log", "put", "run", "start", "stop", "wait", "set", "next",
    "__enter__", "__exit__", "__init__", "__call__", "__str__", "__repr__", "load", "loads", "dump",
    "dumps", "parse", "result", "cancel", "done", "isoformat", "splitlines",
}

STAR_UNKNOWN = ("unknown", "")   # Resolver._star_find: a star import Lantern cannot read may bring the name

# Marker bases that give a subclass no members of their own to call (Enum and NamedTuple do: `_replace`, `name`).
MEMBERLESS_BASES = {"abc.ABC", "typing.Generic", "typing.Protocol", "typing_extensions.Generic",
                    "typing_extensions.Protocol", "builtins.object"}

ROUTE_RE = re.compile(r"\.(route|get|post|put|delete|patch|head|options|websocket|api_route)\s*\(")
CLI_RE = re.compile(r"(^|[.\s])(command|group|callback)\b")
TEST_FILE_RE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test)\.py$|(^|/)tests?/")


# --------------------------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------------------------

def inside_repo(p: Path, repo: Path) -> bool:
    """Whether `p` is a file of the project: a plain file, or a link to one, that lies inside the project by whatever
    folders it is reached. False for a link that leads out of the project (a hostile repository could otherwise link
    to ~/.ssh or ~/.aws and get that file read and shown in a report), for a file reached through a folder that is
    such a link, for a pipe, a device or a folder under a file's name, and for a name nothing answers to. A project
    that is itself reached through a link (the person's own shortcut to it) is read as before.
    Until 2026-11-10 only the last name of the path was looked at, so `linked-folder/file` counted as the project's."""
    try:
        st = os.lstat(p)
        if stat.S_ISREG(st.st_mode) and not _reparse(st) and _plain_way(p, repo):
            return True   # the usual case: a file of its own, in folders of their own; nothing to follow
        real, root = os.path.realpath(p), os.path.realpath(repo)
        return Path(real).is_relative_to(root) and stat.S_ISREG(os.stat(real).st_mode)
    except (OSError, ValueError):
        return False


def _reparse(st: os.stat_result) -> bool:
    """Windows: a junction, a link or another name that stands for something else (never set anywhere else)."""
    return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


_SEPS = tuple(x for x in (os.sep, os.altsep) if x)


def _plain_way(p: Path, repo: Path) -> bool:
    """Every folder between the project and the file is a folder of its own, not a link: then the file lies where
    its path says. Anything else (a link on the way, `..`, a path that is not written under the project's own
    path) is for the slower look, which follows every link. Asked for every file of a project, so it works on the
    text of the two paths."""
    ps, cur = os.fspath(p), os.fspath(repo)
    rest = ps[len(cur):]
    if not ps.startswith(cur) or not cur or not (cur.endswith(_SEPS) or rest.startswith(_SEPS)):
        return False   # `/a/proj` is not the start of `/a/project/x`
    if os.altsep:
        rest = rest.replace(os.altsep, os.sep)
    for part in rest.split(os.sep)[:-1]:
        if part in ("", "."):
            continue
        if part == "..":
            return False
        cur = os.path.join(cur, part)
        st = os.lstat(cur)
        if not stat.S_ISDIR(st.st_mode) or _reparse(st):
            return False
    return True


def project_bytes(p, repo, limit: int | None = None) -> bytes:
    """What a file of the project holds (the first `limit` bytes of it): the one way Lantern opens a file of the
    project it analyses, with `project_text`. A path that is not such a file (`inside_repo`: a link that leads out of
    the project, a file behind a folder that is such a link, a pipe, a device, a folder, a path that leaves the
    project through `..` or begins at the top of the disk) is a file that is not there: FileNotFoundError, as for a
    name nothing answers to, so a reader that passes a missing file over passes these over in the same way. Until
    2026-11-10 only the readers that walk the project asked `inside_repo`; a file opened by its name (`package.json`,
    `go.mod`, a notebook, a path taken from an earlier result) was read wherever the name led."""
    if not inside_repo(p, repo):
        raise FileNotFoundError(errno.ENOENT, "not a file of the project", os.fspath(p))
    with open(p, "rb") as f:
        return f.read() if limit is None else f.read(limit)


def project_text(p, repo, limit: int | None = None) -> str:
    """The text of a file of the project (see `project_bytes`), read as UTF-8 with anything else replaced; `limit`
    is in characters."""
    if not inside_repo(p, repo):
        raise FileNotFoundError(errno.ENOENT, "not a file of the project", os.fspath(p))
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read() if limit is None else f.read(limit)


def discover(repo: Path) -> list[tuple[Path, str]]:
    """Return (path, dotted module name) for every Python file in the repo."""
    repo = repo.resolve()
    src_root = repo / "src" if (repo / "src").is_dir() else None
    out: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if not skipped_dir(dirpath, d) and not d.endswith(".egg-info"))
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            p = Path(dirpath) / fn
            if not inside_repo(p, repo):
                continue
            root = src_root if src_root and src_root in p.parents else repo
            rel = p.relative_to(root).with_suffix("")
            parts = list(rel.parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts:
                parts = [repo.name]
            if not all(part.isidentifier() for part in parts):
                # e.g. "my-scripts/foo.py": still analyze, with a sanitized module name
                parts = [re.sub(r"\W", "_", part) for part in parts]
            out.append((p, ".".join(parts)))
    return out


# --------------------------------------------------------------------------------------------
# Per-file parse results
# --------------------------------------------------------------------------------------------

@dataclass
class DefInfo:
    local: str                 # qualname inside the module, e.g. "Class.method"
    kind: str                  # "function" | "class"
    name: str
    start: int
    end: int
    parent_local: str          # "" for module level
    in_class: str | None       # local qualname of the directly enclosing class, if a method
    decorators: list[str]
    bases: list[str]           # class only: base expressions as text
    params: str
    docstring: str | None
    fingerprint: str
    param_names: list[str] = field(default_factory=list)   # the parameters' own names, in order


@dataclass
class CallSite:
    scope: str                 # local qualname of the calling def, "" = module level, "<main>"
    parts: list[str]           # callee chain, e.g. ["self", "repo", "get"]; "()" suffix = call result
    text: str
    line: int
    kind: str = "call"         # call | computed | depends | depends-alias | decorator-result | attr | with | with-obj
    at: tuple[int, int] | None = None   # (line, column from 1) of the call's "(" (or of the callee): its identity


@dataclass
class ImportBinding:
    module: str                # absolute dotted module
    name: str | None           # imported attribute, None for "import x"
    relative: bool = False     # written with leading dots: it names a file of the project, never a library


@dataclass
class ModuleInfo:
    name: str
    path: Path
    rel: str
    is_package: bool
    lines: int
    defs: dict[str, DefInfo] = field(default_factory=dict)
    imports: dict[str, ImportBinding] = field(default_factory=dict)
    calls: list[CallSite] = field(default_factory=list)
    # var name -> constructor callee parts, per scope ("" = module)
    local_types: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # var name -> built-in type ("list", "dict", "str"...) when EVERY binding of the name in that scope is a literal or
    # a built-in constructor of that one type; "" when any binding is something else (then nothing is assumed)
    literal_types: dict[str, dict[str, str]] = field(default_factory=dict)
    # var name -> built-in constructor names (`list`, `dict`...) whose call gave it its literal type, per scope; the
    # resolver trusts the type only when none of those names is rebound (a repo `def list()`, a parameter, an import)
    literal_ctors: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    # class local qualname -> attr -> constructor parts (from `self.attr = Foo(...)`)
    attr_types: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # module-level aliases: name -> {"type": chain | None, "depends": chain | None}
    aliases: dict[str, dict] = field(default_factory=dict)
    # router variable -> URL prefix, e.g. router = APIRouter(prefix="/items")
    route_prefix: dict[str, str] = field(default_factory=dict)
    # parent.include_router(child, prefix="/p") / register_blueprint(bp, url_prefix="/p"):
    # {"recv": parent var, "target": child chain, "prefix": the written string, or None when it is not one}
    includes: list[dict] = field(default_factory=list)
    # class local qualname -> every attribute the class sets on self (`self.x = ...`), whatever the value
    self_attrs: dict[str, set[str]] = field(default_factory=dict)
    # function local qualname -> what it returns: ("name", n) | ("ctor", chain) | ("ann", chain)
    returns: dict[str, list[tuple[str, object]]] = field(default_factory=dict)
    # `from x import *` lines, in order (name is None)
    stars: list[ImportBinding] = field(default_factory=list)
    # `__all__` when it is written once as a list or tuple of plain strings; `exports_unknown` when it is built any
    # other way (then a star import of this file is not followed: Lantern cannot say which names it brings)
    exports: set[str] | None = None
    exports_unknown: bool = False
    has_main_block: bool = False
    main_range: tuple[int, int] | None = None


def _text(n: TSNode | None) -> str:
    return n.text.decode("utf8", "replace") if n is not None else ""


def _fingerprint(n: TSNode) -> str:
    """Hash of the token stream without comments or whitespace, so formatting changes don't
    invalidate cached explanations."""
    toks: list[bytes] = []
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type == "comment":
            continue
        if cur.child_count == 0:
            toks.append(cur.text)
        else:
            stack.extend(reversed(cur.children))
    return hashlib.sha256(b"\x00".join(toks)).hexdigest()[:16]


def _chain(n: TSNode) -> list[str] | None:
    """Turn a callee expression into a name chain, or None if it's too dynamic to follow."""
    if n.type == "identifier":
        return [_text(n)]
    if n.type == "attribute":
        base = _chain(n.child_by_field_name("object"))
        if base is None:
            return None
        return base + [_text(n.child_by_field_name("attribute"))]
    if n.type == "call":
        fn = n.child_by_field_name("function")
        if fn is not None and fn.type == "identifier" and _text(fn) == "super":
            return ["super()"]
        base = _chain(fn) if fn is not None else None
        if base is None:
            return None
        base[-1] = base[-1] + "()"
        return base
    if n.type == "parenthesized_expression" and n.named_child_count == 1:
        return _chain(n.named_children[0])
    return None


def _docstring(body: TSNode | None) -> str | None:
    if body is None or body.named_child_count == 0:
        return None
    first = body.named_children[0]
    if first.type == "expression_statement" and first.named_child_count == 1 \
            and first.named_children[0].type == "string":
        s = _text(first.named_children[0])
        s = re.sub(r'^[rRbBuUfF]*("""|\'\'\'|"|\')', "", s)
        s = re.sub(r'("""|\'\'\'|"|\')$', "", s)
        return s.strip()[:600] or None
    return None


def _resolve_relative(modname: str, is_package: bool, rel: str) -> str:
    dots = len(rel) - len(rel.lstrip("."))
    rest = rel[dots:]
    base = modname.split(".") if is_package else modname.split(".")[:-1]
    if dots > 1:
        base = base[: len(base) - (dots - 1)] if dots - 1 <= len(base) else []
    return ".".join([p for p in base + ([rest] if rest else []) if p])


LITERAL_NODE_TYPE = {"list": "list", "list_comprehension": "list", "dictionary": "dict",
                     "dictionary_comprehension": "dict", "set": "set", "set_comprehension": "set", "tuple": "tuple",
                     "integer": "int", "float": "float"}
BUILTIN_CTORS = {"list": "list", "dict": "dict", "set": "set", "tuple": "tuple", "str": "str", "bytes": "bytes",
                 "frozenset": "frozenset", "bytearray": "bytearray", "sorted": "list", "repr": "str"}
STR_TO_STR = {"join", "format", "strip", "lstrip", "rstrip", "lower", "upper", "replace", "title", "casefold"}


def _unparen(n: TSNode) -> TSNode:
    while n.type == "parenthesized_expression" and n.named_child_count == 1:
        n = n.named_children[0]
    return n


def _ctor_name(n: TSNode) -> str | None:
    """`list` for `list(...)`: the built-in constructor name a right-hand side calls, if any."""
    n = _unparen(n)
    fn = n.child_by_field_name("function") if n.type == "call" else None
    return _text(fn) if fn is not None and fn.type == "identifier" and _text(fn) in BUILTIN_CTORS else None


def _string_list(n: TSNode) -> list[str] | None:
    """`['a', "b"]` or `('a', 'b')` -> the strings; None when it is anything else (a sum, a call, an f-string)."""
    n = _unparen(n)
    if n.type not in ("list", "tuple"):
        return None
    out = []
    for c in n.named_children:
        if c.type == "comment":
            continue
        m = re.fullmatch(r"""(?s)[rRuU]?(?:'([^'\\]*)'|"([^"\\]*)")""", _text(c)) if c.type == "string" else None
        if m is None:
            return None
        out.append(m.group(1) if m.group(1) is not None else m.group(2))
    return out


def _literal_type(n: TSNode) -> str | None:
    """The built-in type a right-hand side certainly has, read from its shape alone: `[]`, `{}`, `"..."`, f-strings,
    comprehensions, `list(...)`, `", ".join(...)`. None when the shape does not say (a call to anything else).
    `list(...)` is a built-in only if nothing rebinds `list`; the resolver checks that (`ModuleInfo.literal_ctors`)."""
    n = _unparen(n)
    if n.type in LITERAL_NODE_TYPE:
        return LITERAL_NODE_TYPE[n.type]
    if n.type in ("string", "concatenated_string"):
        first = n if n.type == "string" else n.named_children[0]
        return "bytes" if re.match(r"^[rRfFuU]*[bB]", _text(first)) else "str"
    if n.type == "call":
        fn = n.child_by_field_name("function")
        if fn is not None and fn.type == "identifier" and _text(fn) in BUILTIN_CTORS:
            return BUILTIN_CTORS[_text(fn)]
        if fn is not None and fn.type == "attribute":
            obj = fn.child_by_field_name("object")
            attr = _text(fn.child_by_field_name("attribute"))
            if obj is not None and obj.type in ("string", "concatenated_string") and attr in STR_TO_STR:
                return "str"
    return None


def _at(n: TSNode) -> tuple[int, int]:
    """(line, column from 1) where node `n` starts: a call site's identity is where its "(" is."""
    return n.start_point[0] + 1, n.start_point[1] + 1


def _call_at(call: TSNode) -> tuple[int, int]:
    args = call.child_by_field_name("arguments")
    return _at(args if args is not None else call)


LITERAL_NODES = {"string": "str", "concatenated_string": "str", "list": "list", "dictionary": "dict", "set": "set",
                 "tuple": "tuple", "integer": "int", "float": "float", "list_comprehension": "list",
                 "dictionary_comprehension": "dict", "set_comprehension": "set"}


def _computed_parts(fn: TSNode | None) -> list[str]:
    """A callee `_chain` cannot read: a method on a literal (`", ".join`) -> ["<literal:str>", "join"], else []."""
    if fn is not None and fn.type == "attribute":
        obj = fn.child_by_field_name("object")
        if obj is not None and obj.type in LITERAL_NODES:
            return [f"<literal:{LITERAL_NODES[obj.type]}>", _text(fn.child_by_field_name("attribute"))]
    return []


def _param_names(params: TSNode | None) -> list[str]:
    out = []
    for c in (params.named_children if params is not None else []):
        if c.type == "identifier":
            out.append(_text(c))
            continue
        nm = c.child_by_field_name("name")
        if nm is None:
            nm = next((x for x in c.named_children if x.type == "identifier"), None)
        if nm is not None and nm.type == "identifier":
            out.append(_text(nm))
    return out


def _names_in(n: TSNode) -> list[str]:
    if n.type == "identifier":
        return [_text(n)]
    return [x for c in n.named_children for x in _names_in(c)] if n.type in (
        "pattern_list", "tuple_pattern", "list_pattern", "list_splat_pattern", "parenthesized_expression",
        "tuple", "list", "as_pattern_target") else []


class _Visitor:
    def __init__(self, info: ModuleInfo):
        self.m = info

    def _is_main_guard(self, n: TSNode) -> bool:
        cond = _text(n.child_by_field_name("condition")).replace("'", '"').replace(" ", "")
        return cond in ('__name__=="__main__"', '"__main__"==__name__')

    def bind_literal(self, scope: str, name: str, typ: str | None) -> None:
        cur = self.m.literal_types.setdefault(scope, {})
        if typ is None or cur.get(name, typ) != typ:
            cur[name] = ""   # bound to something else, or to two types: assume nothing
        else:
            cur[name] = typ

    def _assignment(self, n: TSNode, scope: str, cls: str | None):
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        for tgt in ([left] if left is not None and left.type == "attribute" else
                    [c for c in left.named_children if c.type == "attribute"] if left is not None else []):
            obj = tgt.child_by_field_name("object")
            if obj is not None and _text(obj) == "self":
                owner = self._enclosing_class(scope)
                if owner:
                    self.m.self_attrs.setdefault(owner, set()).add(_text(tgt.child_by_field_name("attribute")))
        if left is not None and left.type == "identifier":
            self.bind_literal(scope, _text(left), _literal_type(right) if right is not None else None)
            ctor = _ctor_name(right) if right is not None else None
            if ctor:
                self.m.literal_ctors.setdefault(scope, {}).setdefault(_text(left), set()).add(ctor)
        elif left is not None:
            for name in _names_in(left):
                self.bind_literal(scope, name, None)
        if left is None or right is None:
            return
        if not scope and left.type == "identifier" and _text(left) == "__all__":
            names = _string_list(right)
            if names is None or self.m.exports is not None:
                self.m.exports_unknown = True
            self.m.exports = set(names or ())
        if not scope and left.type == "identifier" and right.type != "call":
            al = _annotated(right)
            if al is None and right.type in ("identifier", "attribute"):
                ch = _chain(right)
                al = {"type": ch, "depends": None} if ch else None
            if al:
                self.m.aliases[_text(left)] = al
            return
        if right.type != "call":
            return
        if not scope and left.type == "identifier":
            pref = _router_prefix(right)
            if pref is not None:
                self.m.route_prefix[_text(left)] = pref
        fn = right.child_by_field_name("function")
        ch = _chain(fn) if fn is not None else None
        if not ch:
            return
        if left.type == "identifier":
            self.m.local_types.setdefault(scope, {})[_text(left)] = ch
        elif left.type == "attribute":
            obj = left.child_by_field_name("object")
            if obj is not None and _text(obj) == "self":
                owner = self._enclosing_class(scope)
                if owner:
                    self.m.attr_types.setdefault(owner, {})[_text(left.child_by_field_name("attribute"))] = ch

    def _enclosing_class(self, scope: str) -> str | None:
        d = self.m.defs.get(scope)
        return d.in_class if d else None

    def _import(self, n: TSNode):
        if n.type == "import_statement":
            for c in n.named_children:
                if c.type == "dotted_name":
                    full = _text(c)
                    # `import a.b.c` binds `a`; record the full module too for attribute walks
                    self.m.imports[full.split(".")[0]] = ImportBinding(full.split(".")[0], None)
                    self.m.imports.setdefault(f"__full__{full}", ImportBinding(full, None))
                elif c.type == "aliased_import":
                    self.m.imports[_text(c.child_by_field_name("alias"))] = \
                        ImportBinding(_text(c.child_by_field_name("name")), None)
            return
        modnode = n.child_by_field_name("module_name")
        raw = _text(modnode)
        rel = raw.startswith(".")
        mod = _resolve_relative(self.m.name, self.m.is_package, raw) if rel else raw
        if any(c.type == "wildcard_import" for c in n.children):
            self.m.stars.append(ImportBinding(mod, None, rel))
        for c in n.children_by_field_name("name"):
            if c.type == "dotted_name":
                nm = _text(c)
                self.m.imports[nm.split(".")[-1]] = ImportBinding(mod, nm, rel)
            elif c.type == "aliased_import":
                self.m.imports[_text(c.child_by_field_name("alias"))] = \
                    ImportBinding(mod, _text(c.child_by_field_name("name")), rel)


def _visit_body(v: _Visitor, root: TSNode):
    """Walk the module, tracking the class a function is defined in (for `self` resolution)."""

    def walk(n: TSNode, scope: str, cls: str | None, decorators=None):
        t = n.type
        if t == "decorated_definition":
            decs = [_text(c)[1:].strip() for c in n.children if c.type == "decorator"]
            for c in n.children:
                if c.type == "decorator" and c.named_child_count:
                    expr = c.named_children[0]
                    line = c.start_point[0] + 1
                    if expr.type == "call":
                        walk(expr, scope, cls)   # the factory call, e.g. click.command()
                        fch = _chain(expr.child_by_field_name("function"))
                        if fch:   # ...then the function the factory returned is applied
                            v.m.calls.append(CallSite(scope, fch, _text(expr)[:120], line, "decorator-result",
                                                      _at(expr)))
                    else:
                        ch = _chain(expr)
                        if ch:    # @decorator: applying it calls it
                            v.m.calls.append(CallSite(scope, ch, _text(expr)[:120], line, at=_at(expr)))
            d = n.child_by_field_name("definition")
            if d is not None:
                walk(d, scope, cls, decs)
            return
        if t in ("function_definition", "class_definition"):
            is_class = t == "class_definition"
            name = _text(n.child_by_field_name("name"))
            local = f"{scope}.{name}" if scope and scope != "<main>" else name
            # direct children of a class body are methods of that class
            parent_is_class = scope in v.m.defs and v.m.defs[scope].kind == "class"
            method_of = scope if parent_is_class else (cls if not is_class else None)
            v._def_only(n, scope, method_of, decorators or [])
            if is_class:
                sup = n.child_by_field_name("superclasses")
                if sup is not None:
                    walk(sup, scope, cls)
            else:
                p = n.child_by_field_name("parameters")
                if p is not None:
                    walk(p, scope, cls)
                    _param_types(v.m, local, p)
                rt = n.child_by_field_name("return_type")
                if rt is not None:
                    ch = _chain(rt.named_children[0] if rt.named_child_count == 1 else rt)
                    if ch:
                        v.m.returns.setdefault(local, []).append(("ann", ch))
            body = n.child_by_field_name("body")
            if body is not None:
                for c in body.children:
                    walk(c, local, None if is_class else method_of)
            return
        if t == "if_statement" and not scope and v._is_main_guard(n):
            v.m.has_main_block = True
            v.m.main_range = (n.start_point[0] + 1, n.end_point[0] + 1)
            body = n.child_by_field_name("consequence")
            if body is not None:
                for c in body.children:
                    walk(c, "<main>", None)
            alt = n.child_by_field_name("alternative")
            if alt is not None:
                walk(alt, scope, cls)
            return
        if t in ("import_statement", "import_from_statement"):
            v._import(n)
            return
        if t == "call":
            fn = n.child_by_field_name("function")
            ch = _chain(fn) if fn is not None else None
            if ch:
                v.m.calls.append(CallSite(scope, ch, _text(fn)[:120], n.start_point[0] + 1, at=_call_at(n)))
                if len(ch) == 2 and ch[-1] in ("include_router", "register_blueprint"):
                    _include(v.m, n, ch[0], flask=ch[-1] == "register_blueprint")
            else:   # a callee the chain cannot name: still a call site, counted by the inventory only
                v.m.calls.append(CallSite(scope, _computed_parts(fn), _text(fn)[:120], n.start_point[0] + 1,
                                          "computed", _call_at(n)))
        elif t == "attribute":
            par = n.parent
            is_callee = par is not None and par.type == "call" and par.child_by_field_name("function") == n
            is_store = par is not None and par.type in ("assignment", "augmented_assignment") \
                and par.child_by_field_name("left") == n
            if not is_callee and not is_store:
                ch = _chain(n)
                if ch and len(ch) >= 2:   # possible property read; resolved only if it is one
                    v.m.calls.append(CallSite(scope, ch, _text(n)[:120], n.start_point[0] + 1, "attr", _at(n)))
        elif t == "return_statement" and scope and scope != "<main>" and n.named_child_count:
            e = n.named_children[0]
            if e.type == "identifier":
                v.m.returns.setdefault(scope, []).append(("name", _text(e)))
            elif e.type == "call":
                ch = _chain(e.child_by_field_name("function"))
                if ch:
                    v.m.returns.setdefault(scope, []).append(("ctor", ch))
        elif t == "with_item":
            val = n.child_by_field_name("value")
            alias = None
            if val is not None and val.type == "as_pattern":
                alias_node = val.child_by_field_name("alias")
                if alias_node is not None and alias_node.named_child_count:
                    alias_node = alias_node.named_children[0]
                alias = _text(alias_node) if alias_node is not None and alias_node.type == "identifier" else None
                val = val.named_children[0] if val.named_child_count else None
            if val is not None:
                line = n.start_point[0] + 1
                if val.type == "call":
                    ch = _chain(val.child_by_field_name("function"))
                    if ch:
                        v.m.calls.append(CallSite(scope, ch, _text(val)[:120], line, "with", _at(val)))
                        if alias:
                            v.m.local_types.setdefault(scope, {})[alias] = ch
                else:
                    ch = _chain(val)
                    if ch:
                        v.m.calls.append(CallSite(scope, ch, _text(val)[:120], line, "with-obj", _at(val)))
        if t == "assignment":
            v._assignment(n, scope, cls)
        elif t in ("for_statement", "for_in_clause"):
            left = n.child_by_field_name("left")
            for name in (_names_in(left) if left is not None else []):
                v.bind_literal(scope, name, None)
        elif t == "augmented_assignment":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "identifier" and \
                    v.m.literal_types.get(scope, {}).get(_text(left)) in ("int", "float"):
                v.bind_literal(scope, _text(left), None)   # 1 += 0.5 changes the type; [] += x and "" += s do not
        elif t == "lambda_parameters":
            for c in n.named_children:
                for name in ([_text(c)] if c.type == "identifier" else [_text(x) for x in c.named_children
                                                                         if x.type == "identifier"][:1]):
                    v.bind_literal(scope, name, None)
        elif t in ("global_statement", "nonlocal_statement"):
            # the name is rebound in another scope: the module's (global) or an enclosing function's (nonlocal)
            names = [_text(c) for c in n.named_children if c.type == "identifier"]
            parts = scope.split(".") if scope else []
            outer = [""] if t == "global_statement" else [".".join(parts[:i]) for i in range(len(parts) + 1)]
            for sc in outer + [scope]:
                for name in names:
                    v.bind_literal(sc, name, None)
        elif t == "case_pattern":
            def idents(x):
                return [_text(x)] if x.type == "identifier" else [i for c in x.named_children for i in idents(c)]
            for name in idents(n):
                v.bind_literal(scope, name, None)
        elif t in ("as_pattern", "named_expression", "except_clause"):
            for c in n.named_children:
                if c.type in ("identifier", "as_pattern_target"):
                    for name in _names_in(c):
                        v.bind_literal(scope, name, None)
        for c in n.children:
            walk(c, scope, cls)

    walk(root, "", None)


DEPENDS_NAMES = {"Depends", "Security"}


def _depends_target(n: TSNode | None) -> list[str] | None:
    """For `Depends(get_db)` / `Security(fn, ...)`, the chain of the dependency function."""
    if n is None or n.type != "call":
        return None
    fch = _chain(n.child_by_field_name("function"))
    if not fch or fch[-1] not in DEPENDS_NAMES:
        return None
    args = n.child_by_field_name("arguments")
    pos = [a for a in (args.named_children if args is not None else []) if a.type != "keyword_argument"]
    if not pos:
        kw = [a for a in args.named_children if a.type == "keyword_argument"
              and _text(a.child_by_field_name("name")) == "dependency"] if args is not None else []
        pos = [kw[0].child_by_field_name("value")] if kw else []
    return _chain(pos[0]) if pos else None


def _annotated(n: TSNode) -> dict | None:
    """`Annotated[T, Depends(f)]` -> {"type": chain(T), "depends": chain(f)}."""
    if n.type != "subscript":
        return None
    val = n.child_by_field_name("value")
    vch = _chain(val) if val is not None else None
    if not vch or vch[-1] != "Annotated":
        return None
    items = [c for c in n.named_children if c != val]
    if not items:
        return None
    dep = None
    for it in items[1:]:
        dep = dep or _depends_target(it)
    return {"type": _chain(items[0]), "depends": dep}


def _router_prefix(call: TSNode) -> str | None:
    fch = _chain(call.child_by_field_name("function"))
    if not fch or fch[-1] not in ("APIRouter", "Blueprint", "FastAPI", "Flask"):
        return None
    args = call.child_by_field_name("arguments")
    for a in (args.named_children if args is not None else []):
        if a.type == "keyword_argument" and _text(a.child_by_field_name("name")) in ("prefix", "url_prefix"):
            v = _text(a.child_by_field_name("value"))
            m = re.match(r"^[rbuf]?['\"]([^'\"]*)['\"]$", v)
            return m.group(1) if m else None
    return ""


def _include(m: ModuleInfo, call: TSNode, recv: str, flask: bool = False) -> None:
    """`parent.include_router(child, prefix="/p")` (FastAPI) or `app.register_blueprint(bp, url_prefix="/p")` (Flask):
    the child's routes live under the parent's prefix plus "/p". A prefix that is not a written string is None."""
    args = call.child_by_field_name("arguments")
    pos = [a for a in (args.named_children if args is not None else []) if a.type not in ("keyword_argument", "comment")]
    target = _chain(pos[0]) if pos else None
    if not target:
        return
    prefix: str | None = ""
    for a in (args.named_children if args is not None else []):
        if a.type == "keyword_argument" and _text(a.child_by_field_name("name")) in ("prefix", "url_prefix"):
            mm = re.match(r"^[rbu]?['\"]([^'\"{}]*)['\"]$", _text(a.child_by_field_name("value")))
            prefix = mm.group(1) if mm else None
    m.includes.append({"recv": recv, "target": target, "prefix": prefix, "flask": flask})


def _param_types(m: ModuleInfo, scope: str, params: TSNode) -> None:
    """Record `name: SomeClass` parameter hints as the variable's type for this scope, and
    FastAPI-style `Depends(fn)` defaults as calls the framework makes on the function's behalf."""
    for c in params.named_children:
        if c.type not in ("typed_parameter", "typed_default_parameter", "default_parameter"):
            continue
        line = c.start_point[0] + 1
        dep = _depends_target(c.child_by_field_name("value"))
        if dep:
            m.calls.append(CallSite(scope, dep, ".".join(dep), line, "depends", _at(c)))
        name_node = c.child_by_field_name("name")
        if name_node is None:
            name_node = next((x for x in c.named_children if x.type == "identifier"), None)
        t = c.child_by_field_name("type")
        if name_node is None or t is None:
            continue
        expr = t.named_children[0] if t.named_child_count == 1 else t
        al = _annotated(expr)
        if al:
            if al["depends"]:
                m.calls.append(CallSite(scope, al["depends"], ".".join(al["depends"]), line, "depends", _at(c)))
            ch = al["type"]
        else:
            ch = _chain(expr)
            if ch:   # may be an alias defined elsewhere that carries a Depends()
                m.calls.append(CallSite(scope, ch, ".".join(ch), line, "depends-alias", _at(c)))
        if ch and _text(name_node) not in ("self", "cls"):
            m.local_types.setdefault(scope, {}).setdefault(_text(name_node), ch)


def _def_only(self: _Visitor, n: TSNode, scope: str, method_of: str | None, decorators: list[str]):
    name = _text(n.child_by_field_name("name"))
    local = f"{scope}.{name}" if scope and scope != "<main>" else name
    is_class = n.type == "class_definition"
    body = n.child_by_field_name("body")
    bases: list[str] = []
    if is_class:
        sup = n.child_by_field_name("superclasses")
        if sup is not None:
            bases = [_text(c) for c in sup.named_children if c.type != "keyword_argument"]
    outer = n.parent if n.parent is not None and n.parent.type == "decorated_definition" else n
    self.m.defs[local] = DefInfo(
        local=local, kind="class" if is_class else "function", name=name,
        start=outer.start_point[0] + 1, end=n.end_point[0] + 1,
        parent_local=scope if scope != "<main>" else "",
        in_class=method_of if not is_class else None,
        decorators=decorators, bases=bases,
        params=_text(n.child_by_field_name("parameters"))[:200],
        docstring=_docstring(body), fingerprint=_fingerprint(n),
        param_names=[] if is_class else _param_names(n.child_by_field_name("parameters")),
    )


_Visitor._def_only = _def_only  # type: ignore[attr-defined]


def parse_module(path: Path, modname: str, repo: Path, parser: Parser) -> ModuleInfo:
    src = project_bytes(path, repo)
    tree = parser.parse(src)
    info = ModuleInfo(name=modname, path=path, rel=path.relative_to(repo).as_posix(),
                      is_package=path.name == "__init__.py", lines=src.count(b"\n") + 1)
    _visit_body(_Visitor(info), tree.root_node)
    if src.count(b"__all__") != (1 if info.exports is not None else 0):   # `__all__ += …`, `.extend(…)`, a second one
        info.exports_unknown = True
    return info


# --------------------------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------------------------

def nid(qual: str) -> str:
    return f"py:{qual}"


class Resolver:
    def __init__(self, mods: dict[str, ModuleInfo], g: Graph):
        self.mods = mods
        self.g = g
        # global qualname -> DefInfo
        self.defs: dict[str, tuple[ModuleInfo, DefInfo]] = {}
        self.methods_by_name: dict[str, list[str]] = {}
        for m in mods.values():
            for d in m.defs.values():
                q = f"{m.name}.{d.local}"
                self.defs[q] = (m, d)
                if d.in_class:
                    self.methods_by_name.setdefault(d.name, []).append(q)
        self._class_bases: dict[str, list[str]] = {}
        self._current: str | None = None
        self._ret_cache: dict[str, str | None] = {}
        self.fixtures: dict[str, str] = {}
        for q, (_m, d) in self.defs.items():
            if d.kind == "function" and any("fixture" in x for x in d.decorators):
                self.fixtures.setdefault(d.name, q)
        # Module-name suffix index, so `from app import crud` finds `backend.app.crud` when the
        # repo holds a subproject (backend/, services/x/) with its own import root.
        self._suffix: dict[str, list[str]] = {}
        for name in mods:
            parts = name.split(".")
            for k in range(1, len(parts)):
                self._suffix.setdefault(".".join(parts[k:]), []).append(name)
        # A relative import that finds no file names a file of the project that Lantern did not read (generated,
        # compiled, not committed): what comes from it is not a library's (`gone`). `_gone_ext` holds the library-style
        # names the older rules still give such calls, so the inventory can say what they are (`unread`).
        self._gone: set[str] = set()
        self._gone_ext: set[str] = set()
        folders = {".".join(n.split(".")[:k]) for n in mods for k in range(1, len(n.split(".")))}
        for m in mods.values():
            for b in m.imports.values():
                b.module = self.canon(b.module, m.name)
                sub = f"{b.module}.{b.name}" if b.module and b.name else b.module or b.name
                if b.relative and sub and sub not in mods and b.module not in mods:
                    self._gone.add(sub if not b.module or b.module in folders else b.module)
            for b in m.stars:
                b.module = self.canon(b.module, m.name)
        self._star_hits: dict[tuple[str, str], tuple | None] = {}
        self._subclasses: dict[str, list[str]] = {}
        self._lib_base: dict[str, tuple[str | None, bool]] = {}
        self._open: set[str] = set()   # classes with a base Lantern cannot look into (`open_base`)

    def canon(self, name: str, importer: str) -> str:
        if not name or name in self.mods:
            return name
        if name.split(".")[0] in STDLIB:
            return name
        head, rest = name, ""
        # find the longest prefix of `name` that matches a module suffix
        parts = name.split(".")
        for k in range(len(parts), 0, -1):
            head, rest = ".".join(parts[:k]), ".".join(parts[k:])
            cands = self._suffix.get(head)
            if cands:
                imp = importer.split(".")
                best = max(cands, key=lambda c: (_common_prefix(c.split("."), imp), -len(c)))
                return best + ("." + rest if rest else "")
        return name

    def gone(self, dotted: str) -> bool:
        """True when `dotted` (a name bind() calls "ext") comes from a project file Lantern did not read."""
        if not self._gone:
            return False
        parts = dotted.split(".")
        return any(".".join(parts[:k]) in self._gone for k in range(1, len(parts) + 1))

    def unread(self, target: str) -> bool:
        """True for a target id (`ext:app.missing.helper`) that names something in a project file Lantern did not
        read: the map keeps the older link, the call-site inventory says `missing-module`."""
        if not self._gone_ext or not target.startswith("ext:"):
            return False
        name = target[4:]
        return any(name == x or name.startswith((x + ".", x + "(")) for x in self._gone_ext)

    # ---- name binding ----
    def bind(self, m: ModuleInfo, scope: str, name: str, depth: int = 0):
        """Resolve a bare name in a scope. Returns ("def", qual) | ("module", mod) | ("ext", dotted) | ("var", dotted)
        (a variable of a repo file) | ("lost", dotted) (imported from a repo file that does not bind it) | None."""
        if depth > 6:
            return None
        # enclosing function scopes (class bodies are not enclosing scopes for their methods)
        s = scope if scope != "<main>" else ""
        while s:
            d = m.defs.get(s)
            if d is None:
                break
            cand = f"{s}.{name}"
            if cand in m.defs and d.kind != "class":
                return ("def", f"{m.name}.{cand}")
            s = d.parent_local
        if name in m.defs:
            return ("def", f"{m.name}.{name}")
        al = m.aliases.get(name)
        if al and al.get("type"):
            return self.resolve_chain(m, "", al["type"], depth + 1)
        b = m.imports.get(name)
        if b is not None:
            return self._follow_import(b, depth)
        if m.stars and self._name_kind(m, scope, name) is None:   # not a parameter, a local or a variable of the file
            hit = self._star(m, name, depth)
            if hit is not None:
                return hit
        if name in BUILTIN_NAMES and not self._shadowed(m, scope, name):   # `def f(list): list()` is not the built-in
            return ("ext", f"builtins.{name}")
        return None

    def _star(self, m: ModuleInfo, name: str, depth: int):
        """`from x import *` in `m`: what `name` is when a repo file it star-imports brings it. Python's rules: the
        names in `__all__`, or without one every name that does not start with an underscore; the last star import
        wins. None when no star import brings it, and also when one Lantern cannot read may bring it (a library's,
        a project file that is not there, an `__all__` built in a way Lantern does not read): then Lantern does not
        say which one runs."""
        hit = self._star_find(m, name, depth)
        return None if hit is STAR_UNKNOWN else hit

    def _star_find(self, m: ModuleInfo, name: str, depth: int):
        key = (m.name, name)
        if key in self._star_hits:
            return self._star_hits[key]
        self._star_hits[key] = out = STAR_UNKNOWN   # while it is being worked out: star imports that go in a circle
        if depth <= 6:
            out = None
            for b in reversed(m.stars):
                tm = self.mods.get(b.module)
                if tm is None or tm.exports_unknown:
                    out = STAR_UNKNOWN
                    break
                if name not in tm.exports if tm.exports is not None else name.startswith("_"):
                    continue
                if name in tm.defs:
                    out = ("def", f"{tm.name}.{name}")
                elif name in tm.imports:
                    out = self._follow_import(tm.imports[name], depth + 1) or STAR_UNKNOWN
                elif name in tm.aliases:
                    out = self.bind(tm, "", name, depth + 1) or STAR_UNKNOWN
                elif name in tm.literal_types.get("", {}) or name in tm.local_types.get("", {}):
                    out = ("var", f"{tm.name}.{name}")
                else:
                    out = self._star_find(tm, name, depth + 1)
                    if out is None:
                        continue
                break
        self._star_hits[key] = out
        return out

    def _follow_import(self, b: ImportBinding, depth: int):
        if depth > 12:   # re-exports that chase each other in a circle (Django's `from .a import x` / `from .b import x`)
            return None
        if b.name is None:
            return ("module", b.module) if b.module in self.mods else ("ext", b.module)
        sub = f"{b.module}.{b.name}" if b.module else b.name
        if sub in self.mods:
            return ("module", sub)
        tm = self.mods.get(b.module)
        if tm is None:
            return ("ext", sub)
        if b.name in tm.defs:
            return ("def", f"{tm.name}.{b.name}")
        if b.name in tm.imports:  # re-export, e.g. package __init__
            return self._follow_import(tm.imports[b.name], depth + 1)
        if b.name in tm.aliases:
            return self.bind(tm, "", b.name, depth + 1)
        if tm.stars and b.name not in tm.literal_types.get("", {}) and b.name not in tm.local_types.get("", {}):
            hit = self._star(tm, b.name, depth + 1)   # a package __init__ that says `from .users import *`
            if hit is not None:
                return hit
        if b.name in tm.literal_types.get("", {}) or b.name in tm.local_types.get("", {}):
            return ("var", sub)   # a module-level variable inside the repo: not an external library
        return ("lost", sub)      # the file is there, but nothing Lantern reads in it binds the name

    def resolve_chain(self, m: ModuleInfo, scope: str, ch: list[str], depth: int = 0):
        if depth > 6 or not ch or any(p.endswith("()") for p in ch):
            return None
        r = self.bind(m, scope, ch[0], depth)
        for p in ch[1:]:
            if r is None:
                return None
            if r[0] == "ext":
                r = ("ext", f"{r[1]}.{p}")
            elif r[0] in ("module", "def"):
                r = self.attr_of(r[0], r[1], p)
            else:
                return None
        return r

    def alias_record(self, m: ModuleInfo, name: str, depth: int = 0):
        """Follow imports to the module that defines alias `name`; return (module, record)."""
        if depth > 6:
            return None
        if name in m.aliases:
            return m, m.aliases[name]
        b = m.imports.get(name)
        if b is None or b.name is None:
            return None
        tm = self.mods.get(b.module)
        return self.alias_record(tm, b.name, depth + 1) if tm else None

    def attr_of(self, kind: str, target: str, attr: str):
        """Look up `attr` on a bound module or class."""
        if kind == "module":
            m = self.mods.get(target)
            if m is None:
                return None
            sub = f"{target}.{attr}"
            if sub in self.mods:
                return ("module", sub)
            if attr in m.defs:
                return ("def", f"{target}.{attr}")
            if attr in m.imports:
                return self._follow_import(m.imports[attr], 0)
            if m.stars and attr not in m.literal_types.get("", {}) and attr not in m.local_types.get("", {}):
                return self._star(m, attr, 1)
            return None
        if kind == "def":
            hit = self.lookup_method(target, attr)
            return ("def", hit) if hit else None
        return None

    # ---- classes ----
    def bases(self, cls_q: str) -> list[str]:
        if cls_q in self._class_bases:
            return self._class_bases[cls_q]
        out: list[str] = []
        self._class_bases[cls_q] = out
        m, d = self.defs[cls_q]
        scope = d.parent_local
        for b in d.bases:
            parts = b.split(".")
            if not all(p.isidentifier() for p in parts):
                continue
            r = self.bind(m, scope, parts[0])
            for p in parts[1:]:
                if r is None or r[0] not in ("module", "def"):
                    r = None
                    break
                r = self.attr_of(r[0], r[1], p)
            if r and r[0] == "def" and self.defs.get(r[1], (None, None))[1] \
                    and self.defs[r[1]][1].kind == "class":
                out.append(r[1])
        return out

    def mro(self, cls_q: str) -> list[str]:
        seen, order = set(), []
        stack = [cls_q]
        while stack:
            c = stack.pop(0)
            if c in seen:
                continue
            seen.add(c)
            order.append(c)
            stack.extend(self.bases(c))
        return order

    def lookup_method(self, cls_q: str, name: str, skip_self: bool = False) -> str | None:
        for c in self.mro(cls_q)[1 if skip_self else 0:]:
            q = f"{c}.{name}"
            if q in self.defs:
                return q
        return None

    def subclasses(self, cls_q: str) -> list[str]:
        if not self._subclasses:
            for q, (_, d) in self.defs.items():
                if d.kind == "class":
                    for b in self.bases(q):
                        self._subclasses.setdefault(b, []).append(q)
        out, stack = [], list(self._subclasses.get(cls_q, []))
        while stack:
            c = stack.pop()
            if c not in out:
                out.append(c)
                stack.extend(self._subclasses.get(c, []))
        return out

    def is_class(self, q: str) -> bool:
        return q in self.defs and self.defs[q][1].kind == "class"

    # ---- stage 3: routers included under a prefix (FastAPI include_router, Flask register_blueprint) ----
    def router_of(self, m: ModuleInfo, chain: list[str], depth: int = 0) -> tuple[str, str] | None:
        """The router object `chain` names where it is used, as (module, variable), when it is a router the repo
        creates at module level (`router = APIRouter(...)`): by name, through an import, or as `module.router`."""
        if depth > 6 or not chain:
            return None
        if len(chain) == 1:
            name = chain[0]
            if name in m.route_prefix:
                return (m.name, name)
            b = m.imports.get(name)
            if b is not None and b.name and b.module in self.mods:
                tm = self.mods[b.module]
                if b.name in tm.route_prefix:
                    return (tm.name, b.name)
                if b.name in tm.imports:
                    return self.router_of(tm, [b.name], depth + 1)
            return None
        if len(chain) == 2:
            r = self.bind(m, "", chain[0])
            if r and r[0] == "module" and chain[1] in self.mods[r[1]].route_prefix:
                return (r[1], chain[1])
        return None

    def mount_prefixes(self) -> dict[tuple[str, str], tuple[str, bool] | None]:
        """(module, router variable) -> (the path it is mounted under, whether that replaces its own prefix) for
        every router included somewhere; None when it is included in more than one place, or under a prefix that is
        not a written string (its routes keep the paths written on them)."""
        parents: dict[tuple[str, str], set] = {}
        for m in self.mods.values():
            for inc in m.includes:
                pk, ck = self.router_of(m, [inc["recv"]]), self.router_of(m, inc["target"])
                if pk is not None and ck is not None and pk != ck:
                    parents.setdefault(ck, set()).add((pk, inc["prefix"], bool(inc.get("flask"))))

        def mount(key, seen):
            ps = parents.get(key)
            if not ps:
                return ("", False)
            if len(ps) > 1 or key in seen or len(seen) > 8:
                return None
            (pk, pre, flask), = ps
            if pre is None:
                return None
            up = full(pk, (*seen, key))
            return None if up is None else (up.rstrip("/") + pre, flask and pre != "")

        def full(key, seen):
            mt = mount(key, seen)
            if mt is None:
                return None
            return mt[0] + ("" if mt[1] else self.mods[key[0]].route_prefix.get(key[1], ""))

        return {key: mount(key, ()) for key in parents}

    # ---- stage 3: what a class inherits from outside the repo ----
    def library_base(self, cls_q: str) -> str | None:
        """The first class outside the repo that `cls_q` inherits from (through its repo bases), named
        "<package>.<Class>": `django.Model`, `unittest.TestCase`, `builtins.dict`. Marker bases (abc, typing,
        enum, dataclasses, object) are skipped: their subclasses' methods are the repo's own. None when the class
        also has a base Lantern cannot identify: a member the repo does not define may be that base's, not the
        library's."""
        lib, unknown = self._outside(cls_q)
        return None if unknown else lib

    def open_base(self, cls_q: str) -> bool:
        """True when `cls_q` has a base class Lantern cannot look into: a library class (a marker with members of
        its own, such as Enum or NamedTuple, included), or one it cannot identify (a library's star import, a computed
        base, a class in a project file it did not read). A member the repo does not define may be defined there."""
        self._outside(cls_q)
        return cls_q in self._open

    def _outside(self, cls_q: str) -> tuple[str | None, bool]:
        """(the first library base along the MRO, whether any base along it is one Lantern cannot identify)."""
        if cls_q in self._lib_base:
            return self._lib_base[cls_q]
        self._lib_base[cls_q] = (None, False)
        lib, unknown, marker = None, False, False
        for c in self.mro(cls_q):
            cm, cd = self.defs[c]
            for b in cd.bases:
                text = b.strip()
                head = text.split("[", 1)[0].strip() if text.endswith("]") else text   # Generic[T], Repo[Note]
                parts = head.split(".")
                if not all(x.isidentifier() for x in parts):   # a call or another computed base
                    unknown = True
                    continue
                r = self.bind(cm, cd.parent_local, parts[0])
                for x in parts[1:]:
                    if r is None:
                        break
                    r = ("ext", f"{r[1]}.{x}") if r[0] == "ext" else \
                        self.attr_of(r[0], r[1], x) if r[0] in ("module", "def") else None
                if r is not None and r[0] == "def" and head == text and r[1] in self.defs and \
                        self.defs[r[1]][1].kind == "class":
                    continue   # a repo class: the MRO reads its bases in turn
                if r is None or r[0] != "ext" or self.gone(r[1]):
                    unknown = True   # a name Lantern cannot bind, a variable, `Repo[Note]`, a file it did not read
                    continue
                dotted = r[1].split(".")
                if dotted[0] in ("abc", "typing", "typing_extensions", "enum", "dataclasses") or \
                        r[1] in ("builtins.object", "builtins.type"):
                    marker = marker or r[1] not in MEMBERLESS_BASES
                    continue
                lib = lib or f"{dotted[0]}.{dotted[-1]}"
        if lib or unknown or marker:
            self._open.add(cls_q)
        self._lib_base[cls_q] = (lib, unknown)
        return lib, unknown

    def _repo_attr(self, cls_q: str, name: str) -> bool:
        """True when the repo itself gives instances of `cls_q` an attribute `name`: set on self anywhere in the
        class or its repo bases, or assigned in a class body. Then a call through it is not the library's."""
        for c in self.mro(cls_q):
            cm, cd = self.defs[c]
            if name in cm.self_attrs.get(cd.local, ()) or name in cm.literal_types.get(cd.local, {}) or \
                    name in cm.local_types.get(cd.local, {}):
                return True
        return False

    def library_member(self, cls_q: str, members: list[str]) -> list[tuple[str, str, str]]:
        """`members` used on an instance (or the class) `cls_q` that the repo does not define: the library base's,
        as "ext:<package>.<Class>.<at most two members>" (`ext:django.Model.objects.filter`)."""
        lib = self.library_base(cls_q)
        if not lib or not members or self._repo_attr(cls_q, members[0]) or members[0].startswith("__") and \
                members[0] not in ("__init__",):
            return []
        if len(members) == 1 and self._sibling_gives(cls_q, members[0]):
            return []   # a mixin beside the class gives a subclass this method: it may be the repo's own
        via = "inherited-builtin" if lib.startswith("builtins.") else "inherited-library"
        return [(f"ext:{lib}.{'.'.join(x.rstrip('()') for x in members[:2])}", INFERRED, via)]

    def _sibling_gives(self, cls_q: str, name: str) -> bool:
        """True when a repo subclass of `cls_q` gets a method `name` from another of its bases, a class that is
        neither above nor below `cls_q` (`class Page(Base, Tools)`: `Tools.helper` answers `self.helper()` in Base)."""
        subs = self.subclasses(cls_q)
        if not subs or name not in self.methods_by_name:
            return False
        skip = set(self.mro(cls_q)) | set(subs)
        return any(f"{k}.{name}" in self.defs for s in subs for k in self.mro(s) if k not in skip)

    def library_result(self, m: ModuleInfo, scope: str, parts: list[str],
                       guard: bool = True) -> list[tuple[str, str, str]]:
        """`pandas.read_csv(p).head()`: a call on what a library call returned is a library call, named up to the
        first call's result and the member used on it (`ext:pandas.read_csv().head`). Built-ins stay built-ins.
        Not (`guard`) when a class of the repo has a method of that name: the library may have handed back the
        repo's own object (`get_user_model().objects.create_member()`), so the older reading stands. Everyday names
        (GENERIC_METHODS: `get`, `items`, `read`) say nothing and do not count, and neither does a method called
        straight on what a built-in constructor made (`str(x).title()`)."""
        head = parts[0][:-2] if parts[0].endswith("()") else parts[0]
        r = self.bind(m, scope, head)
        if r is None or r[0] != "ext" or len(parts) < 2 or self.gone(r[1]):
            return []
        if guard and parts[-1] in self.methods_by_name and parts[-1] not in GENERIC_METHODS and not (
                len(parts) == 2 and r[1].startswith("builtins.") and r[1][len("builtins."):] in BUILTIN_CTORS):
            return []
        chain = [r[1] + ("()" if parts[0].endswith("()") else "")] + parts[1:]
        for i, x in enumerate(chain):
            if x.endswith("()"):
                tail = [t.rstrip("()") for t in chain[i + 1:i + 2]]
                return [("ext:" + ".".join(chain[:i + 1] + tail), INFERRED, "library-result")]
        return []

    # ---- call resolution ----
    def resolve_call(self, m: ModuleInfo, cs: CallSite) -> list[tuple[str, str, str]]:
        """Return [(target_node_id, confidence, via)]."""
        parts = cs.parts
        head = parts[0]
        self._current = f"{m.name}.{cs.scope}" if cs.scope and cs.scope != "<main>" else None
        enclosing = m.defs.get(cs.scope)
        method_cls = f"{m.name}.{enclosing.in_class}" if enclosing and enclosing.in_class else None

        # super().method()
        if head == "super()" and len(parts) == 2 and method_cls:
            hit = self.lookup_method(method_cls, parts[1], skip_self=True)
            return [(nid(hit), RESOLVED, "super")] if hit else self.library_member(method_cls, parts[1:])

        # self.method() / cls.method()
        if head in ("self", "cls") and method_cls:
            if len(parts) == 1:   # cls(...) builds the class; self(...) invokes __call__
                hit = self.lookup_method(method_cls, "__init__" if head == "cls" else "__call__")
                if hit:
                    return [(nid(hit), RESOLVED, "cls-constructor" if head == "cls" else "self-call")]
                return [(nid(method_cls), RESOLVED, "cls-constructor")] if head == "cls" else []
            if len(parts) == 2:
                hit = self.lookup_method(method_cls, parts[1])
                out = []
                if hit:
                    out.append((nid(hit), RESOLVED, "self-method"))
                # overrides in subclasses may run instead (dynamic dispatch)
                for sub in self.subclasses(method_cls):
                    q = f"{sub}.{parts[1]}"
                    if q in self.defs and q != hit:
                        out.append((nid(q), POSSIBLE, "override"))
                return out or self.library_member(method_cls, parts[1:])
            # self.attr.method(): use the type assigned to self.attr, if any
            cm, cd = self.defs[method_cls]
            ch = self._attr_type(method_cls, parts[1])
            if ch and len(parts) == 3:
                t = self._type_of_ctor(cm, cd.parent_local, ch)
                if t:
                    hit = self.lookup_method(t, parts[2])
                    if hit:
                        return [(nid(hit), INFERRED, "self-attr-type")]
                ext = self._ext_ctor(cm, cd.parent_local, ch)
                if ext:
                    return [("ext:" + f"{ext}().{parts[2]}", INFERRED, "self-attr-ext-type")]
                return []
            if ch:   # known type, deeper chain: don't guess
                return []
            # self.client.login(): the library base's client. Only one step deep, and only when no class in the repo
            # has a method of that name: the attribute may hold the repo's own object (Django's `self.object`), and
            # then the older reading stays (a name-only guess, or nothing).
            if len(parts) == 3 and not parts[1].endswith("()") and parts[2] not in self.methods_by_name:
                lib = self.library_member(method_cls, parts[1:])
                if lib:
                    return lib
            return self._duck(parts, cs)

        # local variable that is always a built-in literal: x = []; x.append(1)  (counted as a built-in call)
        if len(parts) == 2 and not head.endswith("()"):
            typ = m.literal_types.get(cs.scope, {}).get(head)
            d = m.defs.get(cs.scope)
            if typ and head not in m.imports and not (d and re.search(rf"\b{re.escape(head)}\b", d.params or "")) \
                    and hasattr(getattr(builtins, typ), parts[1]) \
                    and not any(self._shadowed(m, cs.scope, c)
                                for c in m.literal_ctors.get(cs.scope, {}).get(head, ())):
                return [(f"ext:builtins.{typ}.{parts[1]}", RESOLVED, "literal-type")]

        # local variable with a known constructor: x = Foo(); x.bar()
        if len(parts) == 2 and not head.endswith("()"):
            ch = self._local_type(m, cs.scope, head)
            if ch:
                t = self._type_of_ctor(m, cs.scope, ch)
                if t:
                    hit = self.lookup_method(t, parts[1])
                    if hit:
                        return [(nid(hit), INFERRED, "local-type")]
                    lib = self.library_member(t, parts[1:])   # n: Note; n.save() -> the model's save
                    if lib:
                        return lib
                ext = self._ext_ctor(m, cs.scope, ch)
                if ext:
                    return [("ext:" + f"{ext}().{parts[1]}", INFERRED, "local-ext-type")]

        # Foo().bar() -> method on Foo; make().bar() -> method on make's return type
        if head.endswith("()") and len(parts) == 2:
            r = self.bind(m, cs.scope, head[:-2])
            if r and r[0] == "def":
                if self.is_class(r[1]):
                    hit = self.lookup_method(r[1], parts[1])
                    if hit:
                        return [(nid(hit), RESOLVED, "ctor-result")]
                else:
                    t = self.return_type(r[1])
                    hit = self.lookup_method(t, parts[1]) if t else None
                    if hit:
                        return [(nid(hit), INFERRED, "return-type")]
        # fixture-typed parameter: def test_x(runner): runner.invoke()
        if len(parts) == 2 and not head.endswith("()") and head not in ("self", "cls"):
            fx = None if self._local_type(m, cs.scope, head) else self._fixture_type(m, cs.scope, head)
            if fx:
                hit = self.lookup_method(fx, parts[1])
                if hit:
                    return [(nid(hit), INFERRED, "fixture-type")]
                lib = self.library_member(fx, parts[1:])
                if lib:
                    return lib

        # plain name or dotted path through modules / classes
        if any(p.endswith("()") for p in parts):
            return self.library_result(m, cs.scope, parts) or self._duck(parts, cs)
        r = self.bind(m, cs.scope, head)
        walked = [head]
        for i, p in enumerate(parts[1:], 1):
            if r is None:
                break
            if r[0] == "ext":
                r = ("ext", f"{r[1]}.{p}")
            elif r[0] == "module":
                r = self.attr_of("module", r[1], p) or ("ext_unknown", f"{r[1]}.{p}")
            elif r[0] == "def":
                if self.is_class(r[1]):
                    hit = self.lookup_method(r[1], p)
                    if hit is None:   # Note.objects.filter(): the library base's manager
                        lib = self.library_member(r[1], parts[i:])
                        if lib:
                            return lib
                    r = ("def", hit) if hit else None
                else:
                    r = None
            else:
                r = None
            walked.append(p)
        if r is None:
            if head not in m.imports and len(parts) >= 2:
                return self._duck(parts, cs)
            return []
        kind, target = r
        if kind == "def":
            if self.is_class(target):
                init = self.lookup_method(target, "__init__")
                return [(nid(init), RESOLVED, "constructor")] if init else [(nid(target), RESOLVED, "constructor")]
            return [(nid(target), RESOLVED, "name")]
        if kind == "ext":
            if target.startswith("builtins."):
                return [("ext:" + target, RESOLVED, "builtin")]
            if self.gone(target):
                self._gone_ext.add(_ext_name(target))
            return [("ext:" + _ext_name(target), RESOLVED, "import")]
        if kind == "ext_unknown":
            return []
        return []

    def _duck(self, parts: list[str], cs: CallSite) -> list[tuple[str, str, str]]:
        """Unknown receiver: guess by method name, but only when the guess is meaningful."""
        meth = parts[-1].rstrip("()")
        if meth in GENERIC_METHODS or meth.startswith("__"):
            return []
        cands = [c for c in self.methods_by_name.get(meth, []) if c != self._current]
        if len(cands) == 1:   # measured 90-95% correct across click/flask/rich (bench/README.md)
            return [(nid(cands[0]), INFERRED, "unique-method-name")]
        if 2 <= len(cands) <= 4:
            return [(nid(c), POSSIBLE, "method-name") for c in cands]
        return []

    def _ext_ctor(self, m: ModuleInfo, scope: str, ch: list[str]) -> str | None:
        """If a constructor chain points outside the repo, return its collapsed external name."""
        if any(p.endswith("()") for p in ch):
            return None
        r = self.bind(m, scope, ch[0])
        if r is None or r[0] != "ext" or r[1].startswith("builtins."):
            return None
        name = _ext_name(".".join([r[1]] + ch[1:]))
        if self.gone(r[1]):
            self._gone_ext.add(name)
        return name

    def _attr_type(self, cls_q: str, attr: str) -> list[str] | None:
        for c in self.mro(cls_q):
            cm, cd = self.defs[c]
            t = cm.attr_types.get(cd.local, {}).get(attr)
            if t:
                return t
        return None

    @staticmethod
    def _shadowed(m: ModuleInfo, scope: str, name: str) -> bool:
        """True when `name` (say `list`) is rebound in `scope` or a scope around it: an import, a def or class of that
        name, a parameter, or any assignment. Then `list()` is not certainly the built-in."""
        if name in m.imports or name in m.literal_types.get(scope, {}):
            return True
        s = scope if scope != "<main>" else ""
        while True:
            if (f"{s}.{name}" if s else name) in m.defs or name in m.literal_types.get(s, {}):
                return True
            d = m.defs.get(s) if s else None
            # a parameter's own name, not a word in an annotation (`x: str` does not rebind `str`)
            if d is not None and re.search(rf"(?:^|[(,*])\s*{re.escape(name)}\s*(?:[:=,)]|$)", d.params or ""):
                return True
            if d is None:
                return False
            s = d.parent_local

    def _local_type(self, m: ModuleInfo, scope: str, var: str) -> list[str] | None:
        s = scope
        while True:
            t = m.local_types.get(s, {}).get(var)
            if t:
                return t
            d = m.defs.get(s)
            if not s or d is None:
                return m.local_types.get("", {}).get(var) if s else None
            s = d.parent_local

    def _type_of_ctor(self, m: ModuleInfo, scope: str, ch: list[str], depth: int = 0) -> str | None:
        """Class produced by calling `ch`: a class itself, or a function's inferred return type."""
        if depth > 4 or any(p.endswith("()") for p in ch):
            return None
        r = self.bind(m, scope, ch[0])
        for p in ch[1:]:
            if r is None or r[0] not in ("module", "def"):
                return None
            if r[0] == "def" and not self.is_class(r[1]):
                return None
            r = self.attr_of(r[0], r[1], p)
        if not r or r[0] != "def":
            return None
        if self.is_class(r[1]):
            return r[1]
        return self.return_type(r[1], depth + 1)

    def return_type(self, q: str, depth: int = 0) -> str | None:
        if q in self._ret_cache:
            return self._ret_cache[q]
        self._ret_cache[q] = None   # recursion guard
        mi, d = self.defs[q]
        out = None
        for kind, val in mi.returns.get(d.local, []):
            if kind in ("ann", "ctor"):
                out = self._type_of_ctor(mi, d.local if kind == "ctor" else d.parent_local, val, depth)
            if out:
                break
        self._ret_cache[q] = out
        return out

    def returned_closure(self, q: str) -> str | None:
        mi, d = self.defs[q]
        for kind, val in mi.returns.get(d.local, []):
            if kind == "name" and f"{d.local}.{val}" in mi.defs:
                return f"{mi.name}.{d.local}.{val}"
        return None

    def receiver_class(self, m: ModuleInfo, scope: str, recv: list[str]) -> tuple[str, str] | None:
        """Class of a receiver chain like ["self"], ["self", "repo"], ["user"] -> (class, confidence)."""
        enclosing = m.defs.get(scope)
        method_cls = f"{m.name}.{enclosing.in_class}" if enclosing and enclosing.in_class else None
        if recv[0] in ("self", "cls") and method_cls:
            if len(recv) == 1:
                return method_cls, RESOLVED
            if len(recv) == 2:
                ch = self._attr_type(method_cls, recv[1])
                if ch:
                    cm, cd = self.defs[method_cls]
                    t = self._type_of_ctor(cm, cd.parent_local, ch)
                    if t:
                        return t, INFERRED
            return None
        if len(recv) == 1:
            ch = self._local_type(m, scope, recv[0])
            if ch:
                t = self._type_of_ctor(m, scope, ch)
                return (t, INFERRED) if t else None
            fx = self._fixture_type(m, scope, recv[0])
            if fx:
                return fx, INFERRED
        return None

    def _fixture_type(self, m: ModuleInfo, scope: str, name: str) -> str | None:
        """pytest injects fixtures by parameter name; use the fixture's return type."""
        d = m.defs.get(scope)
        if d is None or not re.search(rf"\b{re.escape(name)}\b", d.params):
            return None
        q = self.fixtures.get(name)
        return self.return_type(q) if q else None

    def is_property(self, q: str) -> bool:
        d = self.defs[q][1]
        return any(x.split("(")[0].split(".")[-1] in ("property", "cached_property", "getter")
                   for x in d.decorators)

    # ---- why a call stayed unresolved (calls.REASONS) ----
    def _name_kind(self, m: ModuleInfo, scope: str, name: str) -> str | None:
        """"param", "local" (bound in a function around the call), "module" (a module-level variable) or None."""
        if scope == "<main>":
            if name in m.literal_types.get("<main>", {}) or name in m.local_types.get("<main>", {}):
                return "local"
            scope = ""
        s = scope
        while s:
            d = m.defs.get(s)
            if d is None:
                break
            if name in d.param_names:
                return "param"
            if name in m.literal_types.get(s, {}) or name in m.local_types.get(s, {}):
                return "local"
            s = d.parent_local
        if name in m.literal_types.get("", {}) or name in m.local_types.get("", {}) or name in m.aliases:
            return "module"
        return None

    def why(self, m: ModuleInfo, cs: CallSite) -> str:
        """The reason code (calls.REASONS) for a call resolve_call() found nothing for."""
        parts = cs.parts
        if cs.kind == "computed" or not parts:
            return "computed"
        head = parts[0]
        enclosing = m.defs.get(cs.scope)
        method_cls = f"{m.name}.{enclosing.in_class}" if enclosing and enclosing.in_class else None
        if head == "super()":
            return "unknown-base" if method_cls and self.open_base(method_cls) else "not-in-class"
        if head in ("self", "cls"):
            if not method_cls:
                return "this-outside-class"
            if len(parts) == 2:   # self.cb(): a value the repo stored on the object, or a method it lacks
                if self._repo_attr(method_cls, parts[1]):
                    return "self-attribute"
                return "unknown-base" if self.open_base(method_cls) else "not-in-class"
            if len(parts) == 3 and not parts[1].endswith("()") and parts[2] in self.methods_by_name and \
                    not self._attr_type(method_cls, parts[1]) and self.library_member(method_cls, parts[1:]):
                return "library-or-repo"   # the library base's attribute, and a method name the repo has too
            return "self-attribute"
        name = head[:-2] if head.endswith("()") else head
        if name.isidentifier():
            r0 = self.bind(m, cs.scope, name)
            if r0 is not None and r0[0] == "ext" and self.gone(r0[1]):
                return "missing-module"
        if any(p.endswith("()") for p in parts) and self.library_result(m, cs.scope, parts, guard=False):
            return "library-or-repo"   # what a library call returned, and a method name the repo has too
        if head.endswith("()"):
            return "call-result" if len(parts) > 1 else "computed"
        if any(p.endswith("()") for p in parts[1:-1]):
            return "call-result"
        r = self.bind(m, cs.scope, head)
        if r is None:
            kind = self._name_kind(m, cs.scope, head)
            if kind in ("param", "local") and len(parts) > 1:
                ch = self._local_type(m, cs.scope, head)
                if ch and self._type_of_ctor(m, cs.scope, ch):
                    return "missing-member"   # the type is known; it has no such method in the repo
            if kind == "param":
                return "callback-parameter" if len(parts) == 1 else "parameter"
            if kind == "local":
                return "local-unknown"
            if kind == "module":
                return "repo-variable"
            return "not-defined"
        if r[0] == "var":
            return "repo-variable"
        if r[0] == "lost":
            return "missing-export"
        if r[0] == "def" and not self.is_class(r[1]) and len(parts) > 1:
            return "function-member"
        if r[0] in ("module", "def"):
            return "missing-member"
        return "not-defined"

    def resolve_special(self, m: ModuleInfo, cs: CallSite) -> list[tuple[str, str, str]]:
        self._current = f"{m.name}.{cs.scope}" if cs.scope and cs.scope != "<main>" else None
        if cs.kind == "depends-alias":
            if len(cs.parts) != 1:
                return []
            hit = self.alias_record(m, cs.parts[0])
            if not hit or not hit[1].get("depends"):
                return []
            am, rec = hit
            dep = CallSite("", rec["depends"], ".".join(rec["depends"]), cs.line)
            return [(t, c, "fastapi-depends") for t, c, _ in self.resolve_call(am, dep)]
        if cs.kind == "attr":
            rc = self.receiver_class(m, cs.scope, cs.parts[:-1])
            if rc:
                hit = self.lookup_method(rc[0], cs.parts[-1])
                if hit and self.is_property(hit):
                    return [(nid(hit), rc[1], "property")]
            return []
        if cs.kind == "decorator-result":
            out = []
            for tgt, conf, _via in self.resolve_call(m, cs):
                q = tgt[3:] if tgt.startswith("py:") else None
                if q and q in self.defs and not self.is_class(q):
                    inner = self.returned_closure(q)
                    if inner:
                        out.append((nid(inner), conf, "decorator-closure"))
            return out
        cls_q, conf = None, RESOLVED
        if cs.kind == "with":
            cls_q = self._type_of_ctor(m, cs.scope, cs.parts)
            conf = INFERRED
        elif cs.kind == "with-obj":
            rc = self.receiver_class(m, cs.scope, cs.parts)
            if rc:
                cls_q, conf = rc
        if not cls_q:
            return []
        out = []
        for dunder in ("__enter__", "__exit__"):
            hit = self.lookup_method(cls_q, dunder)
            if hit:
                out.append((nid(hit), conf, "with"))
        if cs.kind == "with":
            init = self.lookup_method(cls_q, "__init__")
            if init:
                out.append((nid(init), conf, "constructor"))
        return out


def _common_prefix(a: list[str], b: list[str]) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def _ext_name(dotted: str) -> str:
    """Collapse external targets to package.function depth so the graph stays readable."""
    parts = dotted.split(".")
    return ".".join(parts[:3])


# --------------------------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------------------------

def _scripts_from_config(repo: Path) -> dict[str, str]:
    """console-script name -> "module:function" from pyproject.toml / setup.cfg / setup.py."""
    out: dict[str, str] = {}
    pp = repo / "pyproject.toml"
    if inside_repo(pp, repo):
        try:
            data = manifest.parse_toml(project_text(pp, repo))
        except OSError:
            data = {}
        # the file comes with the project: only a name with a "module:function" beside it is a script (manifest.py);
        # Poetry also writes one as a table, `app = { callable = "pkg.cli:main" }`
        for scripts in (manifest.table(data.get("project")).get("scripts"),
                        manifest.table(manifest.table(data.get("tool")).get("poetry")).get("scripts")):
            for name, target in manifest.table(scripts).items():
                target = target if isinstance(target, str) else manifest.text(manifest.table(target).get("callable"))
                if target:
                    out[name] = target
    for f in ("setup.cfg", "setup.py"):
        p = repo / f
        try:
            text = project_text(p, repo)
        except OSError:   # not there, or not a file of the project
            continue
        for m in re.finditer(r"([\w\-]+)\s*=\s*([\w\.]+:[\w\.]+)", text):
            out.setdefault(m.group(1), m.group(2))
    return out


def _entry_for(d: DefInfo, rel: str, mod: ModuleInfo | None = None, mounts: dict | None = None,
               resolver: Resolver | None = None) -> dict | None:
    if TEST_FILE_RE.search(rel):
        # routes and commands defined inside tests are fixtures, not the app's real entry points
        if d.kind == "function" and d.name.startswith("test") and not d.in_class or \
                (d.in_class and d.name.startswith("test")):
            return {"kind": "test", "detail": d.local}
        return None
    for dec in d.decorators:
        m = ROUTE_RE.search(dec)
        if m:
            path = re.search(r"\(\s*[rbuf]?['\"]([^'\"]*)['\"]", dec)
            verb = m.group(1).upper() if m.group(1) not in ("route", "api_route", "websocket") else m.group(1)
            if verb == "route":
                methods = re.search(r"methods\s*=\s*\[([^\]]*)\]", dec)
                verb = "/".join(re.findall(r"['\"](\w+)['\"]", methods.group(1))).upper() if methods else "GET"
            var = dec.split(".")[0].strip()
            prefix = (mod.route_prefix.get(var, "") if mod else "")
            key = resolver.router_of(mod, [var]) if resolver and mod else None
            mt = (mounts or {}).get(key) if key else None
            if mt is not None:   # included under a prefix: that path, then the router's own prefix
                prefix = mt[0].rstrip("/") + ("" if mt[1] else prefix)
            return {"kind": "route", "detail": f"{verb} {prefix}{path.group(1) if path else ''}".strip()}
        if CLI_RE.search(dec) and ("click" in dec or "app." in dec or "cli." in dec or "typer" in dec
                                   or dec.split("(")[0].endswith((".command", ".group"))):
            return {"kind": "cli", "detail": dec[:80]}
    return None


# --------------------------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------------------------

def build_graph(repo: str | Path) -> Graph:
    repo = Path(repo).resolve()
    parser = Parser(PY_LANGUAGE)
    mods: dict[str, ModuleInfo] = {}
    for path, modname in discover(repo):
        try:
            info = parse_module(path, modname, repo, parser)
        except (OSError, UnicodeDecodeError):
            continue
        if modname in mods:  # duplicate names (e.g. scripts in two folders): disambiguate
            modname = f"{modname}__{len(mods)}"
            info.name = modname
        mods[modname] = info

    g = Graph(str(repo))
    r = Resolver(mods, g)
    mounts = r.mount_prefixes()
    total_lines = 0
    for m in mods.values():
        total_lines += m.lines
        g.add_node(Node(id=nid(m.name), kind=MODULE, name=m.name.split(".")[-1], qualname=m.name,
                        file=m.rel, start_line=1, end_line=m.lines))
        for d in m.defs.values():
            q = f"{m.name}.{d.local}"
            parent = nid(f"{m.name}.{d.parent_local}") if d.parent_local else nid(m.name)
            g.add_node(Node(
                id=nid(q), kind=CLASS if d.kind == "class" else CALLABLE, name=d.name, qualname=q,
                file=m.rel, start_line=d.start, end_line=d.end, parent=parent,
                fingerprint=d.fingerprint,
                signature=(f"class {d.name}({', '.join(d.bases)})" if d.kind == "class"
                           else f"def {d.name}{d.params}"),
                docstring=d.docstring, decorators=d.decorators, entry=_entry_for(d, m.rel, m, mounts, r),
            ))
            g.add_edge(parent, nid(q), kind=CONTAINS, confidence=RESOLVED)
        if m.has_main_block:
            q = f"{m.name}.<main>"
            g.add_node(Node(id=nid(q), kind=CALLABLE, name="<main>", qualname=q, file=m.rel,
                            start_line=m.main_range[0], end_line=m.main_range[1],
                            parent=nid(m.name), signature='if __name__ == "__main__":',
                            entry={"kind": "main", "detail": f"python {m.rel}"}))
        if m.path.name == "__main__.py":
            g.nodes[nid(m.name)].entry = {"kind": "main", "detail": f"python -m {m.name.rsplit('.', 1)[0]}"}

    # inheritance edges
    for q, (_m, d) in r.defs.items():
        if d.kind == "class":
            for b in r.bases(q):
                g.add_edge(nid(q), nid(b), kind=IMPLEMENTS, confidence=RESOLVED)

    # calls, and the call-site inventory (calls.py): one record per call written, handed over, or made implicitly
    for m in mods.values():
        in_tests = bool(TEST_FILE_RE.search(m.rel))
        for cs in m.calls:
            if cs.scope == "<main>":
                src = nid(f"{m.name}.<main>")
            elif cs.scope and cs.scope in m.defs:
                src = nid(f"{m.name}.{cs.scope}")
                if m.defs[cs.scope].kind == "class":   # class-body statements run at import time
                    src = nid(m.name)
            else:
                src = nid(m.name)
            line, col = cs.at or (cs.line, 0)
            if cs.kind == "computed":   # inventory only: graph.call_sites() has never counted these
                lit = cs.parts[0][len("<literal:"):-1] if cs.parts and cs.parts[0].startswith("<literal:") else None
                calls.record(g.sites, file=m.rel, line=line, col=col, callee=cs.text, caller=src, lang="python",
                             group="written", test=in_tests, reason="computed",
                             targets=[(f"ext:builtins.{lit}.{cs.parts[1]}", RESOLVED, "literal")] if lit else None)
                continue
            if cs.kind in ("call", "depends"):
                targets = r.resolve_call(m, cs)
                if cs.kind == "depends":
                    targets = [(t, c, "fastapi-depends") for t, c, _ in targets]
            else:
                targets = r.resolve_special(m, cs)
            group = "written" if cs.kind == "call" else "handed" if cs.kind in ("depends", "depends-alias") else "implicit"
            found = [t for t in targets if (not r.unread(t[0]) if t[0].startswith("ext:") else t[0] in g.nodes)]
            if group == "written" or found or cs.kind == "depends":
                calls.record(g.sites, file=m.rel, line=line, col=col, callee=cs.text, caller=src, lang="python",
                             group=group, test=in_tests, targets=found, reason=None if found else r.why(m, cs))
            if not targets:
                if cs.kind in ("call", "depends"):
                    g.unresolved[cs.text] = g.unresolved.get(cs.text, 0) + 1
                    if TEST_FILE_RE.search(m.rel):   # counted, and said apart, so test code cannot hide in the total
                        g.unresolved_tests[cs.text] = g.unresolved_tests.get(cs.text, 0) + 1
                continue
            for tgt, conf, via in targets:
                if tgt.startswith("ext:"):
                    if tgt.startswith("ext:builtins."):
                        g.builtin_calls += 1   # noise in a call map, but a call site Lantern read: counted
                        continue
                    g.external(tgt[4:])
                elif tgt not in g.nodes:
                    continue
                if tgt == src:
                    via = (via or "") + "+recursive"
                kind = MAY_CALL if conf == "possible" else CALLS
                g.add_edge(src, tgt, kind=kind, confidence=conf, line=cs.line, via=via)

    # console scripts from packaging config
    for script, target in _scripts_from_config(repo).items():
        mod, _, fn = target.partition(":")
        n = g.nodes.get(nid(f"{mod}.{fn}"))
        if n is not None and not n.entry:
            n.entry = {"kind": "script", "detail": script}

    g.meta.update({"language": "python", "files": len(mods), "lines": total_lines})
    return g
