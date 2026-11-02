"""Go frontend: packages, functions and methods, calls, HTTP handlers and outgoing HTTP calls.

Everything downstream (bridge, security, readiness, explanations, viewer) reads the graph this builds and never
asks which language made it. Node ids: `go:<import path>::<Func>` or `go:<import path>::<Type>.<Method>`; each
file is a module node `go:<repo-relative path>`.

Resolution (each edge says how in `via`):
  * `name`             a bare call to a function of the same package                 -> resolved
  * `import`           `alias.Func()` through the file's imports, inside the module  -> resolved
                       (outside the module: an external node `ext:<alias>.<Func>`)
  * `receiver-type`    `x.Method()` where x's type is written down (parameter, field, `var x T`,
                       `x := T{}` / `&T{}`) or is the result type of a function already resolved -> resolved
                       (Go is statically typed: the written type is the type)
  * `interface`        `x.Method()` where x is an interface of this repo: one `possible` edge to each
                       repo type that has the method                                  -> possible
  * `callback`         a named function passed as an argument to a repo function     -> inferred
  * `pack:<name>`      added later by analysis packs
Anything else (`x.Method()` on an untyped or foreign receiver, function values, embedded methods) is counted
in `graph.unresolved`, never guessed.

Entries: `func main` in package main (`main`), `Test*` in `_test.go` files (`test`), and HTTP routes:
net/http `HandleFunc`/`Handle` (Go 1.22 `"GET /path"` patterns read), gin/echo/fiber `.GET(...)`,
chi `.Get(...)`, gorilla `.HandleFunc(...).Methods(...)`, with `Group`/`Route`/`PathPrefix(...).Subrouter()`
prefixes followed inside the function that creates them. Outgoing calls (`http.Get`, `http.NewRequest`,
`client.Post`) go to `g.meta["http_calls"]` for the bridge, like the JS frontend's.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_go as tsgo
from tree_sitter import Language, Node as TSNode, Parser

from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import SKIP_DIRS, inside_repo

GO = Language(tsgo.language())

BUILTINS = {
    "append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new",
    "panic", "print", "println", "real", "recover", "string", "int", "int8", "int16", "int32", "int64", "uint",
    "uint8", "uint16", "uint32", "uint64", "uintptr", "float32", "float64", "byte", "rune", "bool", "error", "any",
}
VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
ROUTER_METHODS = {v: v for v in VERBS} | {v.capitalize(): v for v in VERBS} | {"Any": "ANY", "ANY": "ANY", "All": "ANY"}
REGISTER_METHODS = {"HandleFunc", "Handle"}
GROUP_METHODS = {"Group", "Route", "PathPrefix"}
SERVE_CALLS = {"ListenAndServe", "ListenAndServeTLS", "Run", "RunTLS", "Start", "Listen", "Serve"}
CLIENT_VERBS = {"Get": "GET", "Post": "POST", "Head": "HEAD", "PostForm": "POST", "Put": "PUT", "Patch": "PATCH",
                "Delete": "DELETE"}


def _text(n: TSNode | None) -> str:
    return n.text.decode("utf8", "replace") if n is not None else ""


def _fingerprint(n: TSNode) -> str:
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


def _string(n: TSNode | None) -> str | None:
    if n is None:
        return None
    if n.type in ("interpreted_string_literal", "raw_string_literal"):
        t = _text(n)
        return t[1:-1] if len(t) >= 2 else ""
    return None


def _type_name(n: TSNode | None) -> tuple[str | None, str] | None:
    """(package alias or None, TypeName) for a type expression; pointers, slices and generics are looked through."""
    while n is not None and n.type in ("pointer_type", "slice_type", "array_type", "parenthesized_type",
                                        "generic_type", "channel_type"):
        n = n.child_by_field_name("element") or n.child_by_field_name("type") or next(
            (c for c in n.children if c.type.endswith("_type") or c.type == "type_identifier"), None)
    if n is None:
        return None
    if n.type == "type_identifier":
        return (None, _text(n))
    if n.type == "qualified_type":
        pkg = n.child_by_field_name("package")
        name = n.child_by_field_name("name")
        return (_text(pkg), _text(name))
    return None


@dataclass
class GoFunc:
    name: str                 # "Get" or "Store.Get"
    local: str                # same as name; the id's last part
    start: int
    end: int
    node: TSNode
    file: str
    receiver: str | None = None      # type name for methods
    receiver_var: str | None = None
    params: dict[str, tuple[str | None, str]] = field(default_factory=dict)   # var -> (alias, Type)
    result: tuple[str | None, str] | None = None
    signature: str = ""
    fingerprint: str = ""
    is_test: bool = False


@dataclass
class GoType:
    name: str
    start: int
    end: int
    file: str
    fields: dict[str, tuple[str | None, str]] = field(default_factory=dict)
    interface: bool = False
    methods: set[str] = field(default_factory=set)     # for interfaces: declared method names
    embedded: list[tuple[str | None, str]] = field(default_factory=list)


@dataclass
class GoFile:
    rel: str
    pkg_dir: str
    pkg_name: str
    lines: int
    imports: dict[str, str] = field(default_factory=dict)    # alias -> import path
    is_test: bool = False


@dataclass
class GoPackage:
    path: str                     # import path (module-relative when no go.mod)
    files: list[GoFile] = field(default_factory=list)
    funcs: dict[str, GoFunc] = field(default_factory=dict)
    types: dict[str, GoType] = field(default_factory=dict)
    vars: dict[str, tuple[str | None, str]] = field(default_factory=dict)      # package-level typed vars
    name: str = ""


def discover(repo: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and d != "testdata" and not d.startswith("."))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if fn.endswith(".go") and inside_repo(p, repo):
                out.append(p)
    return out


def module_path(repo: Path) -> str | None:
    try:
        for line in (repo / "go.mod").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("module "):
                return line.split(None, 1)[1].strip()
    except OSError:
        pass
    return None


def pkg_id(pkg: str, local: str | None = None) -> str:
    return f"go:{pkg}::{local}" if local else f"go:{pkg}"


# --------------------------------------------------------------------------------------------
# Pass 1: declarations
# --------------------------------------------------------------------------------------------

def _qual(f: GoFile, t: tuple[str | None, str] | None) -> tuple[str | None, str] | None:
    """Types are stored as (import path or None, Name) so every file reads them the same way, whatever alias it uses."""
    if t is None or t[0] is None:
        return t
    return (f.imports.get(t[0], t[0]), t[1])


def _params(n: TSNode | None, f: GoFile) -> dict[str, tuple[str | None, str]]:
    out: dict[str, tuple[str | None, str]] = {}
    if n is None:
        return out
    for pd in n.children:
        if pd.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        t = _qual(f, _type_name(pd.child_by_field_name("type")))
        names = [c for c in pd.children if c.type == "identifier"]
        if t:
            for nm in names:
                out[_text(nm)] = t
    return out


def _result_type(fn: TSNode, f: GoFile) -> tuple[str | None, str] | None:
    r = fn.child_by_field_name("result")
    if r is None:
        return None
    if r.type == "parameter_list":
        first = next((c for c in r.children if c.type == "parameter_declaration"), None)
        return _qual(f, _type_name(first.child_by_field_name("type"))) if first is not None else None
    return _qual(f, _type_name(r))


def _collect(pkg: GoPackage, f: GoFile, root: TSNode) -> None:
    for c in root.children:
        if c.type == "import_declaration":
            for spec in [x for x in c.children if x.type == "import_spec"] + \
                        [x for sl in c.children if sl.type == "import_spec_list" for x in sl.children if x.type == "import_spec"]:
                path = _string(spec.child_by_field_name("path"))
                if not path:
                    continue
                alias_n = spec.child_by_field_name("name")
                alias = _text(alias_n) if alias_n is not None else path.rsplit("/", 1)[-1]
                if alias in ("_", "."):
                    continue
                alias = re.sub(r"^go-|-go$|\.v\d+$", "", alias) if alias_n is None else alias
                f.imports[alias] = path
        elif c.type == "function_declaration":
            name = _text(c.child_by_field_name("name"))
            fn = GoFunc(name=name, local=name, start=c.start_point.row + 1, end=c.end_point.row + 1, node=c, file=f.rel,
                        params=_params(c.child_by_field_name("parameters"), f), result=_result_type(c, f),
                        signature=f"func {name}{_text(c.child_by_field_name('parameters'))}"[:200],
                        fingerprint=_fingerprint(c), is_test=f.is_test and name.startswith(("Test", "Benchmark", "Example")))
            pkg.funcs[name] = fn
        elif c.type == "method_declaration":
            recv = c.child_by_field_name("receiver")
            rdecl = next((x for x in recv.children if x.type == "parameter_declaration"), None) if recv else None
            rtype = _type_name(rdecl.child_by_field_name("type")) if rdecl is not None else None
            if not rtype:
                continue
            rvar = next((_text(x) for x in rdecl.children if x.type == "identifier"), None)
            mname = _text(c.child_by_field_name("name"))
            local = f"{rtype[1]}.{mname}"
            fn = GoFunc(name=mname, local=local, start=c.start_point.row + 1, end=c.end_point.row + 1, node=c, file=f.rel,
                        receiver=rtype[1], receiver_var=rvar, params=_params(c.child_by_field_name("parameters"), f),
                        result=_result_type(c, f),
                        signature=f"func ({_text(rdecl)}) {mname}{_text(c.child_by_field_name('parameters'))}"[:200],
                        fingerprint=_fingerprint(c))
            pkg.funcs[local] = fn
        elif c.type == "type_declaration":
            for spec in [x for x in c.children if x.type == "type_spec"]:
                tname = _text(spec.child_by_field_name("name"))
                tn = spec.child_by_field_name("type")
                gt = GoType(name=tname, start=spec.start_point.row + 1, end=spec.end_point.row + 1, file=f.rel)
                if tn is not None and tn.type == "struct_type":
                    fl = next((x for x in tn.children if x.type == "field_declaration_list"), None)
                    for fd in (fl.children if fl is not None else []):
                        if fd.type != "field_declaration":
                            continue
                        ft = _qual(f, _type_name(fd.child_by_field_name("type")))
                        names = [x for x in fd.children if x.type == "field_identifier"]
                        if ft and names:
                            for nm in names:
                                gt.fields[_text(nm)] = ft
                        elif ft and not names:
                            gt.embedded.append(ft)
                elif tn is not None and tn.type == "interface_type":
                    gt.interface = True
                    for me in tn.children:
                        if me.type in ("method_elem", "method_spec"):
                            gt.methods.add(_text(me.child_by_field_name("name")))
                pkg.types[tname] = gt
        elif c.type == "var_declaration":
            for spec in [x for x in c.children if x.type == "var_spec"]:
                names = [x for x in spec.children if x.type == "identifier"]
                t = _qual(f, _type_name(spec.child_by_field_name("type")))
                val = spec.child_by_field_name("value")
                if val is not None and val.type == "expression_list" and val.children and names:
                    first = val.children[0]
                    if first.type == "func_literal" and len(names) == 1:     # var handler = func(...) {...}
                        name = _text(names[0])
                        pkg.funcs[name] = GoFunc(name=name, local=name, start=spec.start_point.row + 1,
                                                 end=spec.end_point.row + 1, node=first, file=f.rel,
                                                 params=_params(first.child_by_field_name("parameters"), f),
                                                 result=_result_type(first, f),
                                                 signature=f"var {name} = func{_text(first.child_by_field_name('parameters'))}"[:200],
                                                 fingerprint=_fingerprint(first))
                        continue
                    if t is None:
                        t = _qual(f, _literal_type(first))
                if t:
                    for nm in names:
                        pkg.vars[_text(nm)] = t


def _literal_type(expr: TSNode | None) -> tuple[str | None, str] | None:
    """`T{...}` or `&T{...}` -> T."""
    if expr is None:
        return None
    if expr.type == "unary_expression":
        expr = expr.child_by_field_name("operand")
    if expr is not None and expr.type == "composite_literal":
        return _type_name(expr.child_by_field_name("type"))
    return None


# --------------------------------------------------------------------------------------------
# Pass 2: bodies
# --------------------------------------------------------------------------------------------

@dataclass
class Ref:
    kind: str                 # call | callback
    target: str               # node id
    line: int
    confidence: str
    via: str


@dataclass
class HttpOut:
    method: str
    path: str
    raw: str
    prefix_unknown: bool
    host: str | None
    line: int


class Linker:
    def __init__(self, pkgs: dict[str, GoPackage], module: str | None):
        self.pkgs = pkgs
        self.module = module
        self.unresolved: dict[str, int] = {}
        self.routes: list[dict] = []           # {"src", "handler_id", "method", "path", "line"}
        self.http: list[tuple[str, str, HttpOut]] = []    # (src id, file, call)
        self.serves: set[str] = set()
        self.inline_handlers: list[tuple[str, GoFunc, str, str]] = []   # (pkg path, func, method, path)
        self.consts: dict[tuple[str, str], str] = {}

    # ---- lookups ----
    def import_pkg(self, f: GoFile, alias: str) -> GoPackage | None:
        path = f.imports.get(alias)
        if not path:
            return None
        return self.pkgs.get(path)

    def type_in(self, pkg: GoPackage, f: GoFile, t: tuple[str | None, str]) -> tuple[GoPackage, GoType] | None:
        path, name = t
        p = pkg if path is None else self.pkgs.get(path)
        if p is None:
            return None
        gt = p.types.get(name)
        return (p, gt) if gt else None

    def implementers(self, iface: GoType) -> list[tuple[GoPackage, str]]:
        """Repo types that have every method the interface declares: (package, Type) pairs."""
        out = []
        for p in self.pkgs.values():
            by_type: dict[str, set[str]] = {}
            for fn in p.funcs.values():
                if fn.receiver:
                    by_type.setdefault(fn.receiver, set()).add(fn.name)
            for tname, methods in by_type.items():
                if iface.methods and iface.methods <= methods and not p.types.get(tname, GoType("", 0, 0, "")).interface:
                    out.append((p, tname))
        return out

    def func_result(self, pkg: GoPackage, f: GoFile, callee: TSNode) -> tuple[str | None, str] | None:
        """The declared result type of `Func()` or `alias.Func()` when it is a repo function."""
        if callee.type == "identifier":
            fn = pkg.funcs.get(_text(callee))
            return fn.result if fn else None
        if callee.type == "selector_expression":
            op = callee.child_by_field_name("operand")
            fld = _text(callee.child_by_field_name("field"))
            if op is not None and op.type == "identifier":
                p = self.import_pkg(f, _text(op))
                if p and fld in p.funcs:
                    r = p.funcs[fld].result
                    if r and r[0] is None:            # a type of that package
                        return (p.path, r[1])
                    return r
        return None

    # ---- the walk ----
    def walk_func(self, pkg: GoPackage, f: GoFile, fn: GoFunc, src_id: str, g: Graph) -> list[Ref]:
        env: dict[str, tuple[str | None, str]] = dict(fn.params)
        if fn.receiver and fn.receiver_var:
            env[fn.receiver_var] = (None, fn.receiver)
        prefixes: dict[str, str] = {}
        refs: list[Ref] = []
        body = fn.node.child_by_field_name("body")
        if body is not None:
            self._walk(pkg, f, fn, src_id, body, env, prefixes, refs, g)
        return refs

    def _walk(self, pkg, f, fn, src_id, n: TSNode, env, prefixes, refs, g, methods_for_inner: list[str] | None = None):
        t = n.type
        if t == "func_literal":
            inner_env = dict(env) | _params(n.child_by_field_name("parameters"), f)
            body = n.child_by_field_name("body")
            if body is not None:
                self._walk(pkg, f, fn, src_id, body, inner_env, dict(prefixes), refs, g)
            return
        if t == "short_var_declaration" or (t == "assignment_statement" and _text(n.child_by_field_name("operator") or n.children[1] if len(n.children) > 1 else None) == "="):
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            names = [c for c in left.children if c.type == "identifier"] if left is not None else []
            vals = [c for c in right.children if c.type not in (",",)] if right is not None else []
            if len(names) >= 1 and vals:
                v = vals[0]
                typ = _qual(f, _literal_type(v))
                if typ is None and v.type == "call_expression":
                    callee = v.child_by_field_name("function")
                    typ = self.func_result(pkg, f, callee)
                    # router groups: g := r.Group("/api")
                    if callee is not None and callee.type == "selector_expression":
                        fld = _text(callee.child_by_field_name("field"))
                        op = callee.child_by_field_name("operand")
                        arg0 = _first_arg(v)
                        if fld in GROUP_METHODS and arg0 is not None and _string(arg0) is not None:
                            base = prefixes.get(_text(op), "") if op is not None else ""
                            prefixes[_text(names[0])] = base + _string(arg0).rstrip("/")
                        elif fld == "Subrouter" and op is not None and op.type == "call_expression":
                            inner = op.child_by_field_name("function")
                            a0 = _first_arg(op)
                            if inner is not None and _text(inner.child_by_field_name("field")) == "PathPrefix" and _string(a0) is not None:
                                base = prefixes.get(_text(inner.child_by_field_name("operand")), "")
                                prefixes[_text(names[0])] = base + _string(a0).rstrip("/")
                        elif fld in GROUP_METHODS | {"Subrouter"} and op is not None and _text(op) in prefixes:
                            prefixes[_text(names[0])] = prefixes[_text(op)]
                if typ:
                    env[_text(names[0])] = typ
            for c in n.children:
                self._walk(pkg, f, fn, src_id, c, env, prefixes, refs, g)
            return
        if t == "var_declaration":
            for spec in [x for x in n.children if x.type == "var_spec"]:
                typ = _qual(f, _type_name(spec.child_by_field_name("type")))
                if typ:
                    for nm in [x for x in spec.children if x.type == "identifier"]:
                        env[_text(nm)] = typ
            for c in n.children:
                self._walk(pkg, f, fn, src_id, c, env, prefixes, refs, g)
            return
        if t == "call_expression":
            if self._call(pkg, f, fn, src_id, n, env, prefixes, refs, g, methods_for_inner):
                return                      # a registration or a Route block: its function literals were handled
            for c in n.children:
                self._walk(pkg, f, fn, src_id, c, env, prefixes, refs, g)
            return
        for c in n.children:
            self._walk(pkg, f, fn, src_id, c, env, prefixes, refs, g)

    def _resolve_callee(self, pkg, f, callee: TSNode, env, g) -> tuple[str, str, str] | None:
        """(node id, confidence, via) for the function being called; None when unknown."""
        if callee.type == "parenthesized_expression":
            inner = next((c for c in callee.children if c.type not in ("(", ")")), None)
            return self._resolve_callee(pkg, f, inner, env, g) if inner is not None else None
        if callee.type == "identifier":
            name = _text(callee)
            if name in pkg.funcs:
                return pkg_id(pkg.path, name), RESOLVED, "name"
            if name in BUILTINS or name in env or name in pkg.types:
                return None
            return None
        if callee.type == "selector_expression":
            op = callee.child_by_field_name("operand")
            fld = _text(callee.child_by_field_name("field"))
            if op is None:
                return None
            if op.type == "identifier":
                oname = _text(op)
                if oname not in env and oname not in pkg.vars:
                    p = self.import_pkg(f, oname)
                    if p is not None:
                        if fld in p.funcs:
                            return pkg_id(p.path, fld), RESOLVED, "import"
                        if fld in p.types:
                            return None                      # a conversion `pkg.Type(x)`
                        return None
                    if oname in f.imports:                   # a package outside the repo
                        return f"ext:{oname}.{fld}", RESOLVED, "import"
            if op.type == "call_expression":                     # a chain on a call: typed only when the call is ours
                root = self._resolve_callee(pkg, f, op.child_by_field_name("function"), env, g)
                if root is None or root[0].startswith("ext:") or root[0] in ("?", "iface"):
                    typ = self._expr_type(pkg, f, op, env)
                    if typ is None:
                        return None                               # `json.NewEncoder(w).Encode(...)`: not a repo call
            typ = self._expr_type(pkg, f, op, env)
            if typ is None:
                return "?", "", f"{_text(op)[:40]}.{fld}"
            found = self.type_in(pkg, f, typ)
            if found is None:
                if typ[0] is not None and typ[0] not in self.pkgs:
                    return f"ext:{typ[0].rsplit('/', 1)[-1]}.{typ[1]}.{fld}", RESOLVED, "receiver-type"
                return "?", "", f"{typ[1]}.{fld}"
            tp, gt = found
            if gt.interface:
                return "iface", tp.path, f"{gt.name}.{fld}"
            local = f"{gt.name}.{fld}"
            if local in tp.funcs:
                return pkg_id(tp.path, local), RESOLVED, "receiver-type"
            for emb in gt.embedded:                              # promoted method through an embedded struct
                ef = self.type_in(tp, f, emb)
                if ef and f"{ef[1].name}.{fld}" in ef[0].funcs:
                    return pkg_id(ef[0].path, f"{ef[1].name}.{fld}"), RESOLVED, "embedded"
            return "?", "", f"{gt.name}.{fld}"
        return None

    def _expr_type(self, pkg, f, e: TSNode, env) -> tuple[str | None, str] | None:
        if e.type == "identifier":
            return env.get(_text(e)) or pkg.vars.get(_text(e))
        if e.type == "selector_expression":
            base = self._expr_type(pkg, f, e.child_by_field_name("operand"), env)
            if base is None:
                return None
            found = self.type_in(pkg, f, base)
            if found is None:
                return None
            ft = found[1].fields.get(_text(e.child_by_field_name("field")))
            if ft and ft[0] is None and found[0] is not pkg:
                return (found[0].path, ft[1])          # a field typed with the owning package's own type
            return ft
        if e.type == "call_expression":
            return self.func_result(pkg, f, e.child_by_field_name("function"))
        if e.type in ("unary_expression", "parenthesized_expression"):
            inner = e.child_by_field_name("operand") or next((c for c in e.children if c.type not in ("(", ")", "&", "*")), None)
            return self._expr_type(pkg, f, inner, env) if inner is not None else None
        return _qual(f, _literal_type(e))

    def _call(self, pkg, f, fn, src_id, n: TSNode, env, prefixes, refs, g, methods_override) -> bool:
        """Record what this call means. Returns True when the call's function-literal arguments were already walked
        (a route registration with an inline handler, or a chi Route block) so the caller must not descend again."""
        callee = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        line = n.start_point.row + 1
        if callee is None:
            return False
        arglist = [c for c in args.children if c.type not in ("(", ")", ",")] if args is not None else []
        # gorilla: r.HandleFunc(...).Methods("GET") -> register the inner call with these verbs
        if callee.type == "selector_expression" and _text(callee.child_by_field_name("field")) == "Methods":
            op = callee.child_by_field_name("operand")
            verbs = [s.upper() for s in (_string(a) for a in arglist) if s]
            if op is not None and op.type == "call_expression" and verbs:
                return self._call(pkg, f, fn, src_id, op, env, prefixes, refs, g, verbs)
        if methods_override is None and callee.type == "selector_expression":
            op = callee.child_by_field_name("operand")
            # a registration whose result is consumed by .Methods() is handled from the outer call
            if n.parent is not None and n.parent.type == "selector_expression" and \
                    _text(n.parent.child_by_field_name("field")) == "Methods" and n.parent.parent is not None \
                    and n.parent.parent.type == "call_expression":
                return False
        # routes
        if callee.type == "selector_expression":
            fld = _text(callee.child_by_field_name("field"))
            op = callee.child_by_field_name("operand")
            pattern = _string(arglist[0]) if arglist else None
            if fld in SERVE_CALLS and fn.name == "main":
                self.serves.add(src_id)
            is_pkg = op is not None and op.type == "identifier" and _text(op) in f.imports and _text(op) not in env
            if pattern is not None and not is_pkg and (fld in ROUTER_METHODS or fld in REGISTER_METHODS) and len(arglist) >= 2 \
                    and (pattern.startswith("/") or re.match(r"^[A-Z]+ /", pattern)):
                method = ROUTER_METHODS.get(fld, "ANY")
                path = pattern
                m = re.match(r"^([A-Z]+) (/.*)$", pattern)
                if m:
                    method, path = m.group(1), m.group(2)
                if methods_override:
                    method = "/".join(methods_override)
                prefix = prefixes.get(_text(op), "") if op is not None else ""
                path = (prefix + path) if path != "/" or not prefix else prefix
                handler = arglist[-1]
                hid = self._handler_id(pkg, f, fn, handler, env, g, method, path)
                if hid:
                    self.routes.append({"src": src_id, "handler": hid, "method": method, "path": path, "line": line})
                    return handler.type == "func_literal"
            # chi: r.Route("/api", func(r chi.Router) {...})
            if fld in GROUP_METHODS and pattern is not None and len(arglist) >= 2 and arglist[-1].type == "func_literal":
                lit = arglist[-1]
                inner_params = _params(lit.child_by_field_name("parameters"), f)
                sub = dict(prefixes)
                base = prefixes.get(_text(op), "") if op is not None else ""
                for pname in inner_params:
                    sub[pname] = base + pattern.rstrip("/")
                body = lit.child_by_field_name("body")
                if body is not None:
                    self._walk(pkg, f, fn, src_id, body, dict(env) | inner_params, sub, refs, g)
                return True
            # outgoing HTTP
            if op is not None:
                self._http_out(pkg, f, src_id, fld, op, arglist, line)
        res = self._resolve_callee(pkg, f, callee, env, g)
        if res is None:
            pass
        elif res[0] == "?":
            key = res[2]
            self.unresolved[key] = self.unresolved.get(key, 0) + 1
        elif res[0] == "iface":
            _, ipath, tm = res
            tname, mname = tm.split(".", 1)
            iface = self.pkgs[ipath].types[tname]
            impls = self.implementers(iface)
            if not impls:
                self.unresolved[tm] = self.unresolved.get(tm, 0) + 1
            for p, rtype in impls:
                if f"{rtype}.{mname}" in p.funcs:
                    refs.append(Ref("call", pkg_id(p.path, f"{rtype}.{mname}"), line, POSSIBLE, "interface"))
        else:
            refs.append(Ref("call", res[0], line, res[1], res[2]))
            # callbacks: named repo functions passed as arguments to a repo function
            if not res[0].startswith("ext:"):
                for a in arglist:
                    if a.type in ("identifier", "selector_expression"):
                        tgt = self._resolve_callee(pkg, f, a, env, g)
                        if tgt and tgt[0] not in ("?", "iface") and not tgt[0].startswith("ext:"):
                            refs.append(Ref("callback", tgt[0], line, INFERRED, "callback"))
        return False

    def _handler_id(self, pkg, f, fn, h: TSNode, env, g, method, path) -> str | None:
        # http.HandlerFunc(x) / middleware(x): look inside
        while h.type == "call_expression" and h.child_by_field_name("arguments") is not None:
            inner = [c for c in h.child_by_field_name("arguments").children if c.type not in ("(", ")", ",")]
            if not inner:
                return None
            h = inner[-1]
        if h.type == "func_literal":
            local = f"{fn.local}.handler@{h.start_point.row + 1}"
            gf = GoFunc(name=f"handler ({method} {path})", local=local, start=h.start_point.row + 1,
                        end=h.end_point.row + 1, node=h, file=f.rel, params=_params(h.child_by_field_name("parameters"), f),
                        signature=f"func{_text(h.child_by_field_name('parameters'))}"[:200], fingerprint=_fingerprint(h))
            pkg.funcs[local] = gf
            self.inline_handlers.append((pkg.path, gf, method, path))
            return pkg_id(pkg.path, local)
        res = self._resolve_callee(pkg, f, h, env, g)
        if res and res[0] not in ("?", "iface") and not res[0].startswith("ext:"):
            return res[0]
        return None

    def _http_out(self, pkg, f, src_id, fld, op: TSNode, arglist: list[TSNode], line: int) -> None:
        url_n = None
        method = None
        oname = _text(op)
        is_http_pkg = oname == "http" and f.imports.get("http", "").endswith("net/http")
        if fld in CLIENT_VERBS and arglist and (is_http_pkg or self._looks_like_client(oname)):
            method, url_n = CLIENT_VERBS[fld], arglist[0]
        elif fld in ("NewRequest", "NewRequestWithContext") and is_http_pkg:
            idx = 0 if fld == "NewRequest" else 1
            if len(arglist) > idx + 1:
                m = _string(arglist[idx])
                method = m.upper() if m else "ANY"
                url_n = arglist[idx + 1]
        if url_n is None or method is None:
            return
        raw, prefix_unknown = self._url_text(pkg, f, url_n)
        if raw is None:
            return
        norm = _normalize(raw, prefix_unknown)
        if norm:
            path, host, pu = norm
            self.http.append((src_id, f.rel, HttpOut(method, path, raw, pu, host, line)))

    def _looks_like_client(self, oname: str) -> bool:
        return bool(re.search(r"client|http", oname, re.I))

    def _url_text(self, pkg, f, n: TSNode) -> tuple[str | None, bool]:
        """A URL from a literal, a `+` chain, fmt.Sprintf, or a package constant. Unknown pieces become "{}";
        an unknown leading piece marks the prefix unknown."""
        if n.type in ("interpreted_string_literal", "raw_string_literal"):
            return _string(n), False
        if n.type == "identifier":
            v = self.consts.get((pkg.path, _text(n)))
            return (v, False) if v is not None else ("{}", True)
        if n.type == "binary_expression" and _text(n.child_by_field_name("operator")) == "+":
            l, lp = self._url_text(pkg, f, n.child_by_field_name("left"))
            r, _ = self._url_text(pkg, f, n.child_by_field_name("right"))
            if l is None or r is None:
                return None, False
            return l + (r if r != "{}" or not l.endswith("{}") else ""), lp
        if n.type == "call_expression":
            callee = n.child_by_field_name("function")
            if callee is not None and callee.type == "selector_expression" and \
                    _text(callee.child_by_field_name("field")) == "Sprintf":
                args = [c for c in n.child_by_field_name("arguments").children if c.type not in ("(", ")", ",")]
                fmt = _string(args[0]) if args else None
                if fmt is not None:
                    return re.sub(r"%[-+# 0-9.]*[a-zA-Z]", "{}", fmt), fmt.startswith("%")
        if n.type == "parenthesized_expression":
            inner = next((c for c in n.children if c.type not in ("(", ")")), None)
            return self._url_text(pkg, f, inner) if inner is not None else (None, False)
        return "{}", True


def _first_arg(call: TSNode) -> TSNode | None:
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    return next((c for c in args.children if c.type not in ("(", ")", ",")), None)


def _normalize(raw: str, prefix_unknown: bool) -> tuple[str, str | None, bool] | None:
    url = raw.strip()
    host = None
    m = re.match(r"^(https?:)?//([^/{}]+)(/.*)?$", url)
    if m:
        host = m.group(2)
        url = m.group(3) or "/"
        if host.split(":")[0] in ("localhost", "127.0.0.1", "0.0.0.0"):  # nosec B104: a URL host, not a bind
            host = None
    elif url.startswith("{}"):
        prefix_unknown = True
        url = url[2:]
    if not url.startswith("/"):
        return None
    url = url.split("?")[0].split("#")[0]
    segs = [s for s in url.split("/") if s]
    norm = "/" + "/".join("{}" if ("{" in s or s.startswith(":")) else s for s in segs)
    return norm, host, prefix_unknown


# --------------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------------

def add_go(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo).resolve()
    paths = discover(repo)
    if not paths:
        return {"files": 0, "lines": 0}
    module = module_path(repo)
    parser = Parser(GO)
    pkgs: dict[str, GoPackage] = {}
    files: list[tuple[GoFile, TSNode]] = []
    total = 0
    for p in paths:
        rel = p.relative_to(repo).as_posix()
        try:
            src = p.read_bytes()
        except OSError:
            continue
        if len(src) > 1_500_000:
            continue
        lines = src.count(b"\n") + 1
        total += lines
        tree = parser.parse(src)
        root = tree.root_node
        pc = next((c for c in root.children if c.type == "package_clause"), None)
        pkg_name = _text(pc.child_by_field_name("name") if pc is not None and pc.child_by_field_name("name") is not None
                         else next((c for c in pc.children if c.type == "package_identifier"), None) if pc is not None else None) or "main"
        d = Path(rel).parent.as_posix()
        d = "" if d == "." else d
        pkg_path = (f"{module}/{d}" if d else module) if module else (d or pkg_name)
        if rel.endswith("_test.go") and pkg_name.endswith("_test"):
            pkg_path += "_test"
        f = GoFile(rel=rel, pkg_dir=d, pkg_name=pkg_name, lines=lines, is_test=rel.endswith("_test.go"))
        pkg = pkgs.setdefault(pkg_path, GoPackage(path=pkg_path, name=pkg_name))
        pkg.files.append(f)
        files.append((f, root))
    for f, root in files:
        _collect(pkgs[_pkg_of(f, pkgs)], f, root)

    link = Linker(pkgs, module)
    # package-level string constants, for URL building
    for f, root in files:
        pkg = pkgs[_pkg_of(f, pkgs)]
        for c in root.children:
            if c.type == "const_declaration":
                for spec in [x for x in c.children if x.type == "const_spec"]:
                    names = [x for x in spec.children if x.type == "identifier"]
                    val = spec.child_by_field_name("value")
                    first = val.children[0] if val is not None and val.children else None
                    s = _string(first)
                    if names and s is not None:
                        link.consts[(pkg.path, _text(names[0]))] = s

    # nodes: a module node per file, a callable per function/method, a class node per struct/interface
    for f, _root in files:
        pkg = pkgs[_pkg_of(f, pkgs)]
        g.add_node(Node(id=f"go:{f.rel}", kind=MODULE, name=Path(f.rel).name, qualname=f.rel, file=f.rel,
                        start_line=1, end_line=f.lines))
        if f.is_test:
            g.nodes[f"go:{f.rel}"].entry = {"kind": "test", "detail": f.rel}
    for pkg in pkgs.values():
        for gt in pkg.types.values():
            g.add_node(Node(id=pkg_id(pkg.path, gt.name), kind=CLASS, name=gt.name, qualname=f"{pkg.path}::{gt.name}",
                            file=gt.file, start_line=gt.start, end_line=gt.end, parent=f"go:{gt.file}",
                            signature=("interface " if gt.interface else "type ") + gt.name))
            g.add_edge(f"go:{gt.file}", pkg_id(pkg.path, gt.name), kind=CONTAINS)
    refs_by_src: dict[str, list[Ref]] = {}
    pending: list[tuple[GoPackage, GoFile, GoFunc]] = [(pkg, next(ff for ff in pkg.files if ff.rel == fn.file), fn)
                                                       for pkg in pkgs.values() for fn in list(pkg.funcs.values())]
    seen: set[str] = set()
    while pending:
        pkg, f, fn = pending.pop(0)
        nid = pkg_id(pkg.path, fn.local)
        if nid in seen:
            continue
        seen.add(nid)
        parent = pkg_id(pkg.path, fn.receiver) if fn.receiver and fn.receiver in pkg.types else f"go:{fn.file}"
        g.add_node(Node(id=nid, kind=CALLABLE, name=fn.name, qualname=f"{pkg.path}::{fn.local}", file=fn.file,
                        start_line=fn.start, end_line=fn.end, parent=parent, fingerprint=fn.fingerprint,
                        signature=fn.signature))
        g.add_edge(parent, nid, kind=CONTAINS)
        before = len(link.inline_handlers)
        refs_by_src[nid] = link.walk_func(pkg, f, fn, nid, g)
        for ppath, gf, _m, _p in link.inline_handlers[before:]:      # inline handlers found inside this body
            pending.append((pkgs[ppath], f, gf))

    # edges
    for src, refs in refs_by_src.items():
        for r in refs:
            if r.target.startswith("ext:"):
                g.external(r.target[4:])
            if r.target == src and r.kind == "callback":
                continue
            if r.target not in g.nodes:
                continue
            g.add_edge(src, r.target, kind=CALLS, confidence=r.confidence, line=r.line, via=r.via)
    for key, n in link.unresolved.items():
        g.unresolved[key[:120]] = g.unresolved.get(key[:120], 0) + n

    # entries
    for pkg in pkgs.values():
        if pkg.name == "main" and "main" in pkg.funcs:
            nid = pkg_id(pkg.path, "main")
            if nid in g.nodes:
                detail = "server start" if nid in link.serves else "program start"
                g.nodes[nid].entry = {"kind": "main", "detail": f"{detail} ({pkg.funcs['main'].file})"}
        for fn in pkg.funcs.values():
            if fn.is_test:
                nid = pkg_id(pkg.path, fn.local)
                if nid in g.nodes:
                    g.nodes[nid].entry = {"kind": "test", "detail": fn.file}
    for r in link.routes:
        n = g.nodes.get(r["handler"])
        if n is not None:
            n.entry = {"kind": "route", "detail": f"{r['method']} {r['path']}"}
            g.add_edge(r["src"], r["handler"], kind=CALLS, confidence=INFERRED, line=r["line"], via="route-registration")

    http_calls = [{"src": src, "method": h.method, "path": h.path, "raw": h.raw, "prefix_unknown": h.prefix_unknown,
                   "host": h.host, "line": h.line, "ui": None, "file": rel} for src, rel, h in link.http]
    g.meta.setdefault("http_calls", []).extend(http_calls)
    return {"files": len(files), "lines": total, "unresolved": sum(link.unresolved.values()),
            "packages": len(pkgs), "routes": len(link.routes), "http_calls": len(http_calls)}


def _pkg_of(f: GoFile, pkgs: dict[str, GoPackage]) -> str:
    for path, pkg in pkgs.items():
        if f in pkg.files:
            return path
    raise KeyError(f.rel)
