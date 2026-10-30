"""Python frontend: discover files, parse them with tree-sitter, and resolve calls into the UCG.

Resolution is deliberately conservative. Each edge records *how* it was resolved (`via`) and a
confidence level, so the viewer and the reports can be honest about what is proven and what is
guessed. Phase 0 does not use a type checker; that is a planned upgrade (Pyright) for Phase 1.
"""

from __future__ import annotations

import builtins
import hashlib
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_python as tsp
from tree_sitter import Language, Node as TSNode, Parser

from .graph import (CALLABLE, CALLS, CLASS, CONTAINS, IMPLEMENTS, INFERRED, MAY_CALL, MODULE,
                    POSSIBLE, RESOLVED, Graph, Node)

PY_LANGUAGE = Language(tsp.language())

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", ".env", ".tox", ".nox",
    "node_modules", "build", "dist", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
    ".eggs", ".lantern", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel", ".expo", "coverage",
    ".parcel-cache", ".angular", "bower_components", "vendor",
}

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
    "dumps", "parse", "copy", "items", "result", "cancel", "done", "isoformat", "splitlines",
}

ROUTE_RE = re.compile(r"\.(route|get|post|put|delete|patch|head|options|websocket|api_route)\s*\(")
CLI_RE = re.compile(r"(^|[.\s])(command|group|callback)\b")
TEST_FILE_RE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test)\.py$|(^|/)tests?/")


# --------------------------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------------------------

def discover(repo: Path) -> list[tuple[Path, str]]:
    """Return (path, dotted module name) for every Python file in the repo."""
    repo = repo.resolve()
    src_root = repo / "src" if (repo / "src").is_dir() else None
    out: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            p = Path(dirpath) / fn
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


@dataclass
class CallSite:
    scope: str                 # local qualname of the calling def, "" = module level, "<main>"
    parts: list[str]           # callee chain, e.g. ["self", "repo", "get"]; "()" suffix = call result
    text: str
    line: int
    kind: str = "call"         # call | depends | depends-alias | decorator-result | attr | with | with-obj


@dataclass
class ImportBinding:
    module: str                # absolute dotted module
    name: str | None           # imported attribute, None for "import x"


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
    # class local qualname -> attr -> constructor parts (from `self.attr = Foo(...)`)
    attr_types: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # module-level aliases: name -> {"type": chain | None, "depends": chain | None}
    aliases: dict[str, dict] = field(default_factory=dict)
    # router variable -> URL prefix, e.g. router = APIRouter(prefix="/items")
    route_prefix: dict[str, str] = field(default_factory=dict)
    # function local qualname -> what it returns: ("name", n) | ("ctor", chain) | ("ann", chain)
    returns: dict[str, list[tuple[str, object]]] = field(default_factory=dict)
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


class _Visitor:
    def __init__(self, info: ModuleInfo):
        self.m = info

    def _is_main_guard(self, n: TSNode) -> bool:
        cond = _text(n.child_by_field_name("condition")).replace("'", '"').replace(" ", "")
        return cond in ('__name__=="__main__"', '"__main__"==__name__')

    def _assignment(self, n: TSNode, scope: str, cls: str | None):
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        if left is None or right is None:
            return
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
        mod = _resolve_relative(self.m.name, self.m.is_package, raw) if raw.startswith(".") else raw
        for c in n.children_by_field_name("name"):
            if c.type == "dotted_name":
                nm = _text(c)
                self.m.imports[nm.split(".")[-1]] = ImportBinding(mod, nm)
            elif c.type == "aliased_import":
                self.m.imports[_text(c.child_by_field_name("alias"))] = \
                    ImportBinding(mod, _text(c.child_by_field_name("name")))


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
                            v.m.calls.append(CallSite(scope, fch, _text(expr)[:120], line, "decorator-result"))
                    else:
                        ch = _chain(expr)
                        if ch:    # @decorator: applying it calls it
                            v.m.calls.append(CallSite(scope, ch, _text(expr)[:120], line))
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
                v.m.calls.append(CallSite(scope, ch, _text(fn)[:120], n.start_point[0] + 1))
        elif t == "attribute":
            par = n.parent
            is_callee = par is not None and par.type == "call" and par.child_by_field_name("function") == n
            is_store = par is not None and par.type in ("assignment", "augmented_assignment") \
                and par.child_by_field_name("left") == n
            if not is_callee and not is_store:
                ch = _chain(n)
                if ch and len(ch) >= 2:   # possible property read; resolved only if it is one
                    v.m.calls.append(CallSite(scope, ch, _text(n)[:120], n.start_point[0] + 1, "attr"))
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
                        v.m.calls.append(CallSite(scope, ch, _text(val)[:120], line, "with"))
                        if alias:
                            v.m.local_types.setdefault(scope, {})[alias] = ch
                else:
                    ch = _chain(val)
                    if ch:
                        v.m.calls.append(CallSite(scope, ch, _text(val)[:120], line, "with-obj"))
        if t == "assignment":
            v._assignment(n, scope, cls)
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


def _param_types(m: ModuleInfo, scope: str, params: TSNode) -> None:
    """Record `name: SomeClass` parameter hints as the variable's type for this scope, and
    FastAPI-style `Depends(fn)` defaults as calls the framework makes on the function's behalf."""
    for c in params.named_children:
        if c.type not in ("typed_parameter", "typed_default_parameter", "default_parameter"):
            continue
        line = c.start_point[0] + 1
        dep = _depends_target(c.child_by_field_name("value"))
        if dep:
            m.calls.append(CallSite(scope, dep, ".".join(dep), line, "depends"))
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
                m.calls.append(CallSite(scope, al["depends"], ".".join(al["depends"]), line, "depends"))
            ch = al["type"]
        else:
            ch = _chain(expr)
            if ch:   # may be an alias defined elsewhere that carries a Depends()
                m.calls.append(CallSite(scope, ch, ".".join(ch), line, "depends-alias"))
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
    )


_Visitor._def_only = _def_only  # type: ignore[attr-defined]


def parse_module(path: Path, modname: str, repo: Path, parser: Parser) -> ModuleInfo:
    src = path.read_bytes()
    tree = parser.parse(src)
    info = ModuleInfo(name=modname, path=path, rel=str(path.relative_to(repo)),
                      is_package=path.name == "__init__.py", lines=src.count(b"\n") + 1)
    _visit_body(_Visitor(info), tree.root_node)
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
        for q, (m, d) in self.defs.items():
            if d.kind == "function" and any("fixture" in x for x in d.decorators):
                self.fixtures.setdefault(d.name, q)
        # Module-name suffix index, so `from app import crud` finds `backend.app.crud` when the
        # repo holds a subproject (backend/, services/x/) with its own import root.
        self._suffix: dict[str, list[str]] = {}
        for name in mods:
            parts = name.split(".")
            for k in range(1, len(parts)):
                self._suffix.setdefault(".".join(parts[k:]), []).append(name)
        for m in mods.values():
            for key, b in m.imports.items():
                b.module = self.canon(b.module, m.name)
        self._subclasses: dict[str, list[str]] = {}

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

    # ---- name binding ----
    def bind(self, m: ModuleInfo, scope: str, name: str, depth: int = 0):
        """Resolve a bare name in a scope. Returns ("def", qual) | ("module", mod) | ("ext", dotted) | None."""
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
        if name in BUILTIN_NAMES:
            return ("ext", f"builtins.{name}")
        return None

    def _follow_import(self, b: ImportBinding, depth: int):
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
        return ("var", sub)   # a module-level variable inside the repo: not an external library

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
            return [(nid(hit), RESOLVED, "super")] if hit else []

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
                return out
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
            return self._duck(parts, cs)

        # local variable with a known constructor: x = Foo(); x.bar()
        if len(parts) == 2 and not head.endswith("()"):
            ch = self._local_type(m, cs.scope, head)
            if ch:
                t = self._type_of_ctor(m, cs.scope, ch)
                if t:
                    hit = self.lookup_method(t, parts[1])
                    if hit:
                        return [(nid(hit), INFERRED, "local-type")]
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

        # plain name or dotted path through modules / classes
        if any(p.endswith("()") for p in parts):
            return self._duck(parts, cs)
        r = self.bind(m, cs.scope, head)
        walked = [head]
        for p in parts[1:]:
            if r is None:
                break
            if r[0] == "ext":
                r = ("ext", f"{r[1]}.{p}")
            elif r[0] == "module":
                r = self.attr_of("module", r[1], p) or ("ext_unknown", f"{r[1]}.{p}")
            elif r[0] == "def":
                if self.is_class(r[1]):
                    hit = self.lookup_method(r[1], p)
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
        return _ext_name(".".join([r[1]] + ch[1:]))

    def _attr_type(self, cls_q: str, attr: str) -> list[str] | None:
        for c in self.mro(cls_q):
            cm, cd = self.defs[c]
            t = cm.attr_types.get(cd.local, {}).get(attr)
            if t:
                return t
        return None

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
            for tgt, conf, via in self.resolve_call(m, cs):
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
    if pp.exists():
        try:
            data = tomllib.loads(pp.read_text())
            out.update(data.get("project", {}).get("scripts", {}) or {})
            out.update(data.get("tool", {}).get("poetry", {}).get("scripts", {}) or {})
        except Exception:
            pass
    for f in ("setup.cfg", "setup.py"):
        p = repo / f
        if p.exists():
            for m in re.finditer(r"([\w\-]+)\s*=\s*([\w\.]+:[\w\.]+)", p.read_text(errors="replace")):
                out.setdefault(m.group(1), m.group(2))
    return out


def _entry_for(d: DefInfo, rel: str, mod: ModuleInfo | None = None) -> dict | None:
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
                docstring=d.docstring, decorators=d.decorators, entry=_entry_for(d, m.rel, m),
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

    r = Resolver(mods, g)

    # inheritance edges
    for q, (m, d) in r.defs.items():
        if d.kind == "class":
            for b in r.bases(q):
                g.add_edge(nid(q), nid(b), kind=IMPLEMENTS, confidence=RESOLVED)

    # calls
    for m in mods.values():
        for cs in m.calls:
            if cs.scope == "<main>":
                src = nid(f"{m.name}.<main>")
            elif cs.scope and cs.scope in m.defs:
                src = nid(f"{m.name}.{cs.scope}")
                if m.defs[cs.scope].kind == "class":   # class-body statements run at import time
                    src = nid(m.name)
            else:
                src = nid(m.name)
            if cs.kind in ("call", "depends"):
                targets = r.resolve_call(m, cs)
                if cs.kind == "depends":
                    targets = [(t, c, "fastapi-depends") for t, c, _ in targets]
            else:
                targets = r.resolve_special(m, cs)
            if not targets:
                if cs.kind in ("call", "depends"):
                    g.unresolved[cs.text] = g.unresolved.get(cs.text, 0) + 1
                continue
            for tgt, conf, via in targets:
                if tgt.startswith("ext:"):
                    if tgt.startswith("ext:builtins."):
                        continue  # builtins are noise in a call map
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
