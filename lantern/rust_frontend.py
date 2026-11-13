"""Rust frontend: crates, modules, functions, impl blocks, traits, calls, HTTP handlers and outgoing HTTP calls.

Everything downstream reads the graph this builds and never asks which language made it. Node ids:
`rs:<crate>::<module path>::<fn>` and `rs:<crate>::<module path>::<Type>::<method>`; each file is a module node
`rs:<repo-relative path>`.

Resolution (each edge says how in `via`):
  * `name`             a call to a function of the same module                                    -> resolved
  * `use`              through a `use` import or a `crate::`/`self::`/`super::`/child-module path -> resolved
                       (a crate outside the repo: an external node `ext:<crate>.<name>`)
  * `assoc`            `Type::func()` on a type of this repo                                        -> resolved
  * `receiver-type`    `x.method()` where x's type is written down (parameter, field, `let x: T`,
                       `T { .. }`) or is the return type of a function already resolved             -> resolved
  * `trait`            `x.method()` where x is `dyn Trait` / `impl Trait` / `T: Trait`: one `possible` edge to
                       each `impl Trait for Type` of the repo that has the method                   -> possible
  * `callback`         a named function passed as an argument to a repo function                   -> inferred
Anything else (a method on an untyped receiver, closures, macros other than the ones named below) is counted in
`graph.unresolved`, never guessed.

Entries: `fn main` (`main`; "server start" when the body binds or serves), `#[test]` / `#[tokio::test]` functions and
files under `tests/` (`test`), and HTTP routes: axum `.route("/p", get(h).post(h2))` with `.nest("/api", …)`
prefixes (inline routers and `nest("/api", f())` where f builds the router), actix `#[get("/p")]` attributes,
`.route("/p", web::get().to(h))`, `.service(h)` under `web::scope("/api")`, rocket `#[get("/p")]` with
`.mount("/api", routes![h])`. Outgoing calls (`reqwest::get`, `client.post(url)`, `ureq::get`) go to
`g.meta["http_calls"]` for the bridge; URLs come from literals, `format!` and module constants.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_rust as tsrs
from tree_sitter import Language, Node as TSNode, Parser

from . import deep
from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import inside_repo, project_bytes, project_text, skipped_dir

RUST = Language(tsrs.language())

VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
ROUTE_ATTRS = VERBS | {"route", "any"}
WRAPPERS = {"Arc", "Box", "Rc", "RefCell", "Mutex", "RwLock", "Cell", "Pin", "State", "Extension", "Json", "Data",
            "Query", "Path", "Form", "web::Data"}
SERVE_WORDS = re.compile(r"\.(?:serve|bind|run|launch|listen)\s*\(|HttpServer::new|axum::serve|rocket::build")
HTTP_CLIENT_FNS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "head": "HEAD"}


def _text(n: TSNode | None) -> str:
    return n.text.decode("utf8", "replace") if n is not None else ""


def _fingerprint(n: TSNode) -> str:
    toks: list[bytes] = []
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type in ("line_comment", "block_comment"):
            continue
        if cur.child_count == 0:
            toks.append(cur.text)
        else:
            stack.extend(reversed(cur.children))
    return hashlib.sha256(b"\x00".join(toks)).hexdigest()[:16]


def _string(n: TSNode | None) -> str | None:
    if n is None:
        return None
    if n.type in ("string_literal", "raw_string_literal"):
        t = _text(n)
        m = re.match(r'^r#*"(.*)"#*$', t, re.S) or re.match(r'^"(.*)"$', t, re.S)
        return m.group(1) if m else None
    return None


def _children(n: TSNode, *types: str) -> list[TSNode]:
    return [c for c in n.children if c.type in types]


def _args(call: TSNode) -> list[TSNode]:
    a = call.child_by_field_name("arguments")
    return [c for c in a.children if c.type not in ("(", ")", ",")] if a is not None else []


def _type_path(n: TSNode | None) -> tuple[list[str], str] | None:
    """(path segments, kind) for a type expression: kind is "type" or "trait" (dyn / impl). Wrappers like Arc<T>,
    &T, Box<dyn T> are looked through."""
    while n is not None:
        if n.type in ("reference_type", "removed_trait_bound"):
            n = n.child_by_field_name("type") or next((c for c in n.children if c.type.endswith("type") or c.type.endswith("identifier")), None)
            continue
        if n.type == "generic_type":
            base = n.child_by_field_name("type")
            name = _text(base).split("::")[-1]
            if name in WRAPPERS:
                ta = n.child_by_field_name("type_arguments")
                inner = next((c for c in ta.children if c.type not in ("<", ">", ",")), None) if ta is not None else None
                if inner is not None:
                    n = inner
                    continue
            n = base
            continue
        if n.type == "dynamic_type" or n.type == "abstract_type":
            tr = n.child_by_field_name("trait")
            p = _type_path(tr)
            return (p[0], "trait") if p else None
        if n.type == "type_identifier":
            return ([_text(n)], "type")
        if n.type == "scoped_type_identifier":
            return (_text(n).split("::"), "type")
        if n.type == "primitive_type":
            return None
        if n.type == "tuple_type" or n.type == "array_type" or n.type == "function_type":
            return None
        if n.type == "bounded_type":
            return None
        return None
    return None


@dataclass
class RsFunc:
    name: str
    local: str                  # "name" or "Type::name"
    start: int
    end: int
    node: TSNode
    file: str
    impl_type: str | None = None
    trait: str | None = None
    params: dict[str, tuple[list[str], str]] = field(default_factory=dict)
    result: tuple[list[str], str] | None = None
    signature: str = ""
    fingerprint: str = ""
    is_test: bool = False
    attr_route: tuple[str, str] | None = None     # (VERB, path) from #[get("/p")]
    generics: dict[str, list[str]] = field(default_factory=dict)   # T -> trait path


@dataclass
class RsType:
    name: str
    start: int
    end: int
    file: str
    fields: dict[str, tuple[list[str], str]] = field(default_factory=dict)
    is_trait: bool = False
    methods: set[str] = field(default_factory=set)
    impls: list[str] = field(default_factory=list)    # traits implemented (by name)


@dataclass
class RsModule:
    crate: str
    path: tuple[str, ...]       # module path inside the crate
    file: str
    funcs: dict[str, RsFunc] = field(default_factory=dict)
    types: dict[str, RsType] = field(default_factory=dict)
    uses: dict[str, list[str]] = field(default_factory=dict)       # alias -> path segments
    globs: list[list[str]] = field(default_factory=list)           # `use x::*;` prefixes
    children: set[str] = field(default_factory=set)                # `mod x;` or inline mod names
    consts: dict[str, str] = field(default_factory=dict)
    is_test: bool = False

    @property
    def key(self) -> tuple[str, tuple[str, ...]]:
        return (self.crate, self.path)


def discover(repo: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if not skipped_dir(dirpath, d) and d != "target"
                             and not d.startswith("."))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if fn.endswith(".rs") and inside_repo(p, repo):
                out.append(p)
    return out


def crates(repo: Path) -> dict[str, str]:
    """crate root dir (repo-relative, "" for the repo root) -> crate name, from every Cargo.toml with a [package]."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if not skipped_dir(dirpath, d) and d != "target" and not d.startswith(".")]
        if "Cargo.toml" in filenames:
            try:
                text = project_text(Path(dirpath) / "Cargo.toml", repo)
            except OSError:
                continue
            m = re.search(r"(?ms)^\[package\].*?^name\s*=\s*\"([^\"]+)\"", text)
            if m:
                rel = Path(dirpath).relative_to(repo).as_posix()
                out["" if rel == "." else rel] = m.group(1).replace("-", "_")
    return out


def module_of(rel: str, crate_roots: dict[str, str]) -> tuple[str, tuple[str, ...], bool]:
    """(crate name, module path, is_test) for a file."""
    root = max((r for r in crate_roots if rel.startswith(r + "/") or r == ""), key=len, default=None)
    crate = crate_roots[root] if root is not None else "main"
    inner = rel[len(root) + 1:] if root else rel
    parts = inner.split("/")
    is_test = parts[0] == "tests" or rel.endswith("_test.rs")
    if parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] in ("main.rs", "lib.rs", "mod.rs"):
        parts = parts[:-1]
    elif parts:
        parts[-1] = parts[-1][:-3]
    if parts[:1] == ["bin"] and len(parts) == 2:
        parts = []
    return crate, tuple(p for p in parts if p), is_test


def nid(crate: str, path: tuple[str, ...], local: str | None = None) -> str:
    base = "::".join((crate, *path))
    return f"rs:{base}::{local}" if local else f"rs:{base}"


# --------------------------------------------------------------------------------------------
# Pass 1: declarations
# --------------------------------------------------------------------------------------------

def _use_paths(n: TSNode, prefix: list[str], out: dict[str, list[str]], globs: list[list[str]] | None = None) -> None:
    t = n.type
    if t == "use_wildcard":
        p = n.child_by_field_name("path") or next((c for c in n.children if c.type in ("identifier", "scoped_identifier", "crate", "self", "super")), None)
        if globs is not None:
            globs.append(prefix + (_text(p).split("::") if p is not None else []))
        return
    if t == "identifier":
        out[_text(n)] = prefix + [_text(n)]
    elif t in ("scoped_identifier", "scoped_type_identifier"):
        segs = _text(n).split("::")
        out[segs[-1]] = prefix + segs
    elif t == "scoped_use_list":
        p = n.child_by_field_name("path")
        lst = n.child_by_field_name("list")
        base = prefix + (_text(p).split("::") if p is not None else [])
        if lst is not None:
            for c in lst.children:
                if c.type not in ("{", "}", ","):
                    _use_paths(c, base, out, globs)
    elif t == "use_list":
        for c in n.children:
            if c.type not in ("{", "}", ","):
                _use_paths(c, prefix, out, globs)
    elif t == "use_as_clause":
        p = n.child_by_field_name("path")
        alias = n.child_by_field_name("alias")
        if p is not None and alias is not None:
            out[_text(alias)] = prefix + _text(p).split("::")
    elif t == "self":
        if prefix:
            out[prefix[-1]] = prefix


def _params(n: TSNode | None, generics: dict[str, list[str]]) -> dict[str, tuple[list[str], str]]:
    out: dict[str, tuple[list[str], str]] = {}
    if n is None:
        return out
    for pd in n.children:
        if pd.type != "parameter":
            continue
        pat = pd.child_by_field_name("pattern")
        tp = _type_path(pd.child_by_field_name("type"))
        if pat is None or tp is None:
            continue
        if pat.type == "tuple_struct_pattern":          # State(state): State<Arc<AppState>> -> state: AppState
            inner = [c for c in pat.children if c.type == "identifier"][1:]   # the first identifier is the wrapper
            if len(inner) != 1:
                continue
            pat = inner[0]
        name = _text(pat).lstrip("&mut ").strip()
        if not re.match(r"^[A-Za-z_]\w*$", name):
            continue
        if tp[1] == "type" and len(tp[0]) == 1 and tp[0][0] in generics:
            out[name] = (generics[tp[0][0]], "trait")
        else:
            out[name] = tp
    return out


def _generics(fn: TSNode) -> dict[str, list[str]]:
    """`fn f<T: Mailer>(…)` and `where T: Mailer` -> {"T": ["Mailer"]}."""
    out: dict[str, list[str]] = {}
    tp = fn.child_by_field_name("type_parameters")
    if tp is not None:
        for c in tp.children:
            if c.type in ("constrained_type_parameter", "type_parameter"):
                left = c.child_by_field_name("left") or c.child_by_field_name("name")
                bounds = c.child_by_field_name("bounds")
                if left is not None and bounds is not None:
                    first = next((b for b in bounds.children if b.type in ("type_identifier", "scoped_type_identifier")), None)
                    if first is not None:
                        out[_text(left)] = _text(first).split("::")
    wc = next((c for c in fn.children if c.type == "where_clause"), None)
    if wc is not None:
        for pred in _children(wc, "where_predicate"):
            left = pred.child_by_field_name("left")
            bounds = pred.child_by_field_name("bounds")
            if left is not None and bounds is not None:
                first = next((b for b in bounds.children if b.type in ("type_identifier", "scoped_type_identifier")), None)
                if first is not None:
                    out[_text(left)] = _text(first).split("::")
    return out


def _attr_route(attrs: list[TSNode]) -> tuple[str, str] | None:
    for a in attrs:
        at = next((c for c in a.children if c.type == "attribute"), None)
        if at is None:
            continue
        name = _text(at.children[0]).split("::")[-1] if at.children else ""
        args = at.child_by_field_name("arguments")
        if name in ROUTE_ATTRS and args is not None:
            tt = _text(args)
            m = re.search(r'"([^"]*)"', tt)
            if not m:
                continue
            path = m.group(1).split("?")[0]
            verb = name.upper()
            if name == "route":
                mm = re.search(r'method\s*=\s*"([A-Z]+)"', tt)
                verb = mm.group(1) if mm else "ANY"
            if name == "any":
                verb = "ANY"
            return verb, path
    return None


def _is_test_fn(attrs: list[TSNode]) -> bool:
    return any(re.search(r"\btest\b", _text(a)) for a in attrs)


def _collect(mod: RsModule, body: TSNode, mods: dict, crate: str, path: tuple[str, ...], file: str,
             in_test_mod: bool = False, left=None) -> None:
    attrs: list[TSNode] = []
    for c in body.children:
        t = c.type
        if t == "attribute_item":
            attrs.append(c)
            continue
        if t == "use_declaration":
            arg = c.child_by_field_name("argument")
            if arg is not None:
                _use_paths(arg, [], mod.uses, mod.globs)
        elif t == "mod_item":
            name = _text(c.child_by_field_name("name"))
            mod.children.add(name)
            inner = c.child_by_field_name("body")
            if inner is not None:
                sub = mods.setdefault((crate, path + (name,)), RsModule(crate=crate, path=path + (name,), file=file,
                                                                       is_test=mod.is_test or any("cfg(test)" in _text(a) for a in attrs)))
                try:
                    _collect(sub, inner, mods, crate, path + (name,), file, in_test_mod=sub.is_test, left=left)
                except RecursionError:
                    # a module inside more modules than this walk follows: left where it stands and written down
                    deep.leave(left, file, c)
        elif t == "function_item":
            fn = _function(c, file, None, None, attrs, mod.is_test or in_test_mod)
            mod.funcs[fn.local] = fn
        elif t == "impl_item":
            tp = _type_path(c.child_by_field_name("type"))
            tr = _type_path(c.child_by_field_name("trait"))
            tname = tp[0][-1] if tp else None
            if tname is None:
                attrs = []
                continue
            rt = mod.types.setdefault(tname, RsType(name=tname, start=c.start_point.row + 1, end=c.end_point.row + 1, file=file))
            if tr:
                rt.impls.append(tr[0][-1])
            decl = c.child_by_field_name("body")
            inner_attrs: list[TSNode] = []
            for m in (decl.children if decl is not None else []):
                if m.type == "attribute_item":
                    inner_attrs.append(m)
                    continue
                if m.type == "function_item":
                    fn = _function(m, file, tname, tr[0][-1] if tr else None, inner_attrs, mod.is_test or in_test_mod)
                    mod.funcs[fn.local] = fn
                    rt.methods.add(fn.name)
                inner_attrs = []
        elif t == "trait_item":
            name = _text(c.child_by_field_name("name"))
            rt = mod.types.setdefault(name, RsType(name=name, start=c.start_point.row + 1, end=c.end_point.row + 1, file=file))
            rt.is_trait = True
            decl = c.child_by_field_name("body")
            for m in (decl.children if decl is not None else []):
                if m.type in ("function_signature_item", "function_item"):
                    rt.methods.add(_text(m.child_by_field_name("name")))
                    if m.type == "function_item":                       # default method body
                        fn = _function(m, file, name, None, [], mod.is_test)
                        mod.funcs[fn.local] = fn
        elif t in ("struct_item", "enum_item", "type_item", "union_item"):
            name = _text(c.child_by_field_name("name"))
            rt = mod.types.setdefault(name, RsType(name=name, start=c.start_point.row + 1, end=c.end_point.row + 1, file=file))
            rt.start, rt.end = c.start_point.row + 1, c.end_point.row + 1
            fl = c.child_by_field_name("body")
            for fd in (fl.children if fl is not None and fl.type == "field_declaration_list" else []):
                if fd.type == "field_declaration":
                    tp = _type_path(fd.child_by_field_name("type"))
                    if tp:
                        rt.fields[_text(fd.child_by_field_name("name"))] = tp
        elif t in ("const_item", "static_item"):
            name = _text(c.child_by_field_name("name"))
            s = _string(c.child_by_field_name("value"))
            if s is not None:
                mod.consts[name] = s
        attrs = []


def _function(c: TSNode, file: str, impl_type: str | None, trait: str | None, attrs: list[TSNode], is_test_mod: bool) -> RsFunc:
    name = _text(c.child_by_field_name("name"))
    local = f"{impl_type}::{name}" if impl_type else name
    gens = _generics(c)
    ret = _type_path(c.child_by_field_name("return_type"))
    if ret and ret[0] == ["Self"] and impl_type:
        ret = ([impl_type], "type")
    sig = f"fn {name}{_text(c.child_by_field_name('parameters'))}"
    rt = c.child_by_field_name("return_type")
    if rt is not None:
        sig += f" -> {_text(rt)}"
    return RsFunc(name=name, local=local, start=c.start_point.row + 1, end=c.end_point.row + 1, node=c, file=file,
                  impl_type=impl_type, trait=trait, params=_params(c.child_by_field_name("parameters"), gens),
                  result=ret, signature=sig[:200], fingerprint=_fingerprint(c),
                  is_test=is_test_mod or _is_test_fn(attrs), attr_route=_attr_route(attrs), generics=gens)


# --------------------------------------------------------------------------------------------
# Pass 2: bodies
# --------------------------------------------------------------------------------------------

@dataclass
class Ref:
    kind: str
    target: str
    line: int
    confidence: str
    via: str


class Linker:
    left = None     # (map, "rust") once `add_rust` has a map: where a piece that was not read is written down

    def __init__(self, mods: dict[tuple[str, tuple[str, ...]], RsModule], crate_names: set[str]):
        self.mods = mods
        self.crate_names = crate_names
        self.unresolved: dict[str, int] = {}
        self.routes: list[dict] = []
        self.http: list[dict] = []
        self.serves: set[str] = set()
        self.nest_fn: dict[str, str] = {}          # fn node id building a router -> prefix it is nested under
        self.service_prefix: dict[str, str] = {}   # attribute-routed handler id -> scope prefix
        self.node_prefix: dict[tuple[int, int], str] = {}

    # ---- path resolution ----
    def resolve_path(self, mod: RsModule, segs: list[str]):
        """("fn", RsModule, local) | ("type", RsModule, RsType) | ("ext", name) | None."""
        if not segs:
            return None
        first = segs[0]
        cur: RsModule | None
        rest: list[str]
        if first == "crate":
            cur, rest = self.mods.get((mod.crate, ())), segs[1:]
        elif first == "self":
            cur, rest = mod, segs[1:]
        elif first == "super":
            cur, rest = self.mods.get((mod.crate, mod.path[:-1])), segs[1:]
            while rest and rest[0] == "super" and cur is not None:
                cur, rest = self.mods.get((cur.crate, cur.path[:-1])), rest[1:]
        elif first in self.crate_names and (mod.crate != first or len(segs) > 1) and first not in mod.types and first not in mod.funcs:
            cur, rest = self.mods.get((first, ())), segs[1:]
        elif first in mod.uses and mod.uses[first] != segs:
            return self.resolve_path(mod, mod.uses[first] + segs[1:])
        elif first in mod.children:
            cur, rest = self.mods.get((mod.crate, mod.path + (first,))), segs[1:]
        elif first in mod.funcs or first in mod.types:
            cur, rest = mod, segs
        elif first == "Self":
            return None
        else:
            for gl in mod.globs:                      # `use super::*;` and friends
                r = self.resolve_path(mod, gl + segs) if gl[:1] != [first] else None
                if r and r[0] != "ext":
                    return r
            return ("ext", ".".join(segs[-2:]) if len(segs) > 1 else segs[0])
        if cur is None:
            return None
        while rest:
            seg = rest[0]
            if seg in cur.children and len(rest) > 1:
                cur = self.mods.get((cur.crate, cur.path + (seg,)))
                rest = rest[1:]
                if cur is None:
                    return None
                continue
            if seg in cur.types:
                rt = cur.types[seg]
                if len(rest) == 1:
                    return ("type", cur, rt)
                local = f"{seg}::{rest[1]}"
                if local in cur.funcs:
                    return ("fn", cur, local)
                if rt.is_trait and rest[1] in rt.methods:
                    return ("trait", cur, rt, rest[1])
                return None
            if seg in cur.funcs and len(rest) == 1:
                return ("fn", cur, seg)
            if seg in cur.uses and len(rest) == 1 and cur is not mod:
                return self.resolve_path(cur, cur.uses[seg])
            return None
        return None

    def canon(self, mod: RsModule, tp: tuple[list[str], str] | None) -> tuple[list[str], str] | None:
        """A type path as written in `mod`, rewritten so any module can resolve it: ["crate", <mod path>, Name]
        inside the same crate, [<crate>, <mod path>, Name] across crates. Foreign types stay as written."""
        if tp is None:
            return None
        found = self.type_of_path(mod, tp)
        if found is None:
            return tp
        m, rt = found
        return ([m.crate, *m.path, rt.name], tp[1])

    def type_of_path(self, mod: RsModule, tp: tuple[list[str], str]):
        """(RsModule, RsType) for a type path, or None when the type is not in the repo."""
        segs, _kind = tp
        if len(segs) == 1 and segs[0] == "Self":
            return None
        r = self.resolve_path(mod, segs)
        if r and r[0] == "type":
            return r[1], r[2]
        return None

    def implementers(self, trait: RsType) -> list[tuple[RsModule, RsType]]:
        return [(m, t) for m in self.mods.values() for t in m.types.values()
                if trait.name in t.impls and not t.is_trait]

    # ---- bodies ----
    def walk_func(self, mod: RsModule, fn: RsFunc, src_id: str) -> list[Ref]:
        env: dict[str, tuple[list[str], str]] = {k: self.canon(mod, v) for k, v in fn.params.items()}
        if fn.impl_type:
            env["self"] = self.canon(mod, ([fn.impl_type], "type"))
        refs: list[Ref] = []
        body = fn.node.child_by_field_name("body")
        if body is not None:
            if fn.name == "main" and SERVE_WORDS.search(_text(body)):
                self.serves.add(src_id)
            self._walk(mod, fn, src_id, body, env, refs)
        return refs

    def _walk(self, mod, fn, src_id, n: TSNode, env, refs):
        t = n.type
        if t == "block":            # its statements one by one: one nested deeper than this walk follows is left and
            for c in n.children:    # written down, and the next one is read (`lantern/deep.py`)
                try:
                    self._walk(mod, fn, src_id, c, env, refs)
                except RecursionError:
                    deep.leave(self.left, fn.file, c, env)
            return
        if t == "closure_expression":
            inner = dict(env)
            params = n.child_by_field_name("parameters")
            if params is not None:
                for p in params.children:
                    if p.type == "parameter":
                        tp = self.canon(mod, _type_path(p.child_by_field_name("type")))
                        if tp:
                            inner[_text(p.child_by_field_name("pattern"))] = tp
            body = n.child_by_field_name("body")
            if body is not None:
                self._walk(mod, fn, src_id, body, inner, refs)
            return
        if t == "let_declaration":
            pat = n.child_by_field_name("pattern")
            tp = self.canon(mod, _type_path(n.child_by_field_name("type")))
            val = n.child_by_field_name("value")
            if tp is None and val is not None:
                tp = self._expr_type(mod, val, env)
            if pat is not None and pat.type == "identifier" and tp:
                env[_text(pat)] = tp
            for c in n.children:
                self._walk(mod, fn, src_id, c, env, refs)
            return
        if t == "call_expression":
            if self._call(mod, fn, src_id, n, env, refs):
                return
        if t == "macro_invocation":
            self._macro(mod, fn, src_id, n, env, refs)
        for c in n.children:
            self._walk(mod, fn, src_id, c, env, refs)

    def _unwrap(self, e: TSNode | None) -> TSNode | None:
        while e is not None and e.type in ("await_expression", "try_expression", "reference_expression", "unary_expression",
                                           "parenthesized_expression"):
            e = e.child_by_field_name("value") or next((c for c in e.children if c.type not in ("&", "*", "!", "(", ")", ".", "await", "?", "mut")), None)
        return e

    def _expr_type(self, mod: RsModule, e: TSNode | None, env) -> tuple[list[str], str] | None:
        e = self._unwrap(e)
        if e is None:
            return None
        if e.type == "identifier" or e.type == "self":
            return env.get(_text(e))
        if e.type == "struct_expression":
            return self.canon(mod, _type_path(e.child_by_field_name("name")))
        if e.type == "field_expression":
            base = self._expr_type(mod, e.child_by_field_name("value"), env)
            if base is None:
                return None
            found = self.type_of_path(mod, base)
            if found is None:
                return None
            ft = found[1].fields.get(_text(e.child_by_field_name("field")))
            return self.canon(found[0], ft)                 # the field's type, read where the struct is declared
        if e.type == "call_expression":
            callee = e.child_by_field_name("function")
            r = self._callee(mod, callee, env)
            if r and r[0] == "fn":
                return self.canon(r[1], r[1].funcs[r[2]].result)
            if callee is not None and callee.type == "field_expression":      # a method's return type
                m = self._method(mod, callee, env)
                if m and m[0] == "fn":
                    return self.canon(m[1], m[1].funcs[m[2]].result)
            return None
        return None

    def _callee(self, mod: RsModule, callee: TSNode | None, env):
        """Resolve a non-method callee: identifier, scoped path, generic function."""
        if callee is None:
            return None
        if callee.type == "generic_function":
            return self._callee(mod, callee.child_by_field_name("function"), env)
        if callee.type == "identifier":
            name = _text(callee)
            if name in env:
                return None                        # a closure or function value
            if name in mod.funcs:
                return ("fn", mod, name, "name")
            r = self.resolve_path(mod, [name])
            if r and r[0] == "fn":
                return (*r, "use")
            if r and r[0] == "type":
                return None                        # tuple-struct constructor
            if r and r[0] == "ext":
                return ("ext", r[1], None, "use")
            return None
        if callee.type == "scoped_identifier":
            segs = _text(callee).split("::")
            if segs[0] == "Self" and env.get("self"):
                segs = env["self"][0] + segs[1:]
            r = self.resolve_path(mod, segs)
            if r and r[0] == "fn":
                return (*r, "assoc" if "::" in r[2] else "use")
            if r and r[0] == "trait":
                return ("trait", r[1], r[2], r[3])
            if r and r[0] == "ext":
                return ("ext", r[1], None, "use")
            if r is None and segs[0] not in ("crate", "self", "super", "Self") and segs[0] not in mod.children \
                    and segs[0] not in mod.uses and segs[0] not in self.crate_names:
                return ("ext", ".".join(segs[-2:]), None, "use")
            return None
        return None

    def _method(self, mod: RsModule, fe: TSNode, env):
        """Resolve `x.method` through x's type. ("fn", mod, local) | ("trait", mod, RsType, name) | ("?", key)."""
        recv = fe.child_by_field_name("value")
        name = _text(fe.child_by_field_name("field"))
        tp = self._expr_type(mod, recv, env)
        if tp is None:
            base = self._unwrap(recv)
            while base is not None and base.type == "field_expression":
                base = base.child_by_field_name("value")
            if base is None or base.type not in ("identifier", "self"):
                return None                       # a chain on a call or a literal: nothing of ours to resolve
            return ("?", f"{_text(recv)[:40]}.{name}")
        found = self.type_of_path(mod, tp)
        if found is None:
            if tp[0][0] not in self.crate_names and tp[0][0] not in ("crate", "self", "super") and \
                    (len(tp[0]) > 1 or tp[0][0] not in mod.types) and self.resolve_path(mod, tp[0]) and self.resolve_path(mod, tp[0])[0] == "ext":
                return ("ext", f"{tp[0][-1]}.{name}")
            return ("?", f"{tp[0][-1]}.{name}")
        tmod, rt = found
        if rt.is_trait or tp[1] == "trait":
            if name in rt.methods:
                return ("trait", tmod, rt, name)
            return ("?", f"{rt.name}.{name}")
        local = f"{rt.name}::{name}"
        if local in tmod.funcs:
            return ("fn", tmod, local)
        for tr in rt.impls:                              # a trait default method
            r = self.resolve_path(tmod, [tr])
            if r and r[0] == "type" and f"{tr}::{name}" in r[1].funcs:
                return ("fn", r[1], f"{tr}::{name}")
        return ("?", f"{rt.name}.{name}")

    def _chain_prefix(self, n: TSNode) -> str:
        """For `.service(x)` / `.route(…)` in actix chains: the `web::scope("/p")` prefixes the chain is built on,
        plus any prefix an enclosing nest/scope gave this node."""
        prefix = self.node_prefix.get((n.start_byte, n.end_byte), "")
        cur = n
        scopes: list[str] = []
        while cur is not None and cur.type == "call_expression":
            f = cur.child_by_field_name("function")
            if f is None:
                break
            if f.type == "field_expression":
                cur = f.child_by_field_name("value")
                continue
            if f.type in ("scoped_identifier", "identifier") and _text(f).split("::")[-1] == "scope":
                s = _string(_args(cur)[0]) if _args(cur) else None
                if s:
                    scopes.append(s.rstrip("/"))
            break
        return prefix + "".join(reversed(scopes))

    def _call(self, mod, fn, src_id, n: TSNode, env, refs) -> bool:
        callee = n.child_by_field_name("function")
        args = _args(n)
        line = n.start_point.row + 1
        if callee is None:
            return False
        if callee.type == "field_expression":
            name = _text(callee.child_by_field_name("field"))
            recv = callee.child_by_field_name("value")
            # --- routers ---
            if name == "route" and args and _string(args[0]) is not None and len(args) >= 2:
                path = self._chain_prefix(n) + _string(args[0])
                for verb, h in self._handlers(mod, args[1], env):
                    hid = self._handler_id(mod, h, env)
                    if hid:
                        self.routes.append({"src": src_id, "handler": hid, "method": verb, "path": path or "/", "line": line})
                self._walk(mod, fn, src_id, recv, env, refs)       # the rest of the chain
                return True
            if name in ("nest", "nest_service", "mount") and args and _string(args[0]) is not None and len(args) >= 2:
                prefix = self._chain_prefix(n) + _string(args[0]).rstrip("/")
                target = self._unwrap(args[1])
                if target is not None and target.type == "call_expression":
                    r = self._callee(mod, target.child_by_field_name("function"), env)
                    if r and r[0] == "fn":
                        self.nest_fn[nid(r[1].crate, r[1].path, r[2])] = prefix
                    else:
                        self._mark_prefix(target, prefix)
                elif target is not None and target.type == "macro_invocation" and _text(target.child_by_field_name("macro")).endswith("routes"):
                    for ident in re.findall(r"[A-Za-z_][\w:]*", _text(next((c for c in target.children if c.type == "token_tree"), target))):
                        r = self.resolve_path(mod, ident.split("::"))
                        if r and r[0] == "fn":
                            self.service_prefix[nid(r[1].crate, r[1].path, r[2])] = prefix
                for a in args[1:]:
                    self._walk(mod, fn, src_id, a, env, refs)
                self._walk(mod, fn, src_id, recv, env, refs)
                return True
            if name == "service" and args:
                prefix = self._chain_prefix(n)
                target = self._unwrap(args[0])
                r = self._callee(mod, target, env) if target is not None and target.type in ("identifier", "scoped_identifier") else None
                if r and r[0] == "fn":
                    self.service_prefix[nid(r[1].crate, r[1].path, r[2])] = prefix
                elif target is not None and target.type == "call_expression":
                    self._mark_prefix(target, prefix)
                    self._walk(mod, fn, src_id, target, env, refs)
                self._walk(mod, fn, src_id, recv, env, refs)
                return True
            # --- outgoing HTTP ---
            if name in HTTP_CLIENT_FNS and args and re.search(r"client|http|agent", _text(recv), re.I):
                self._http_out(mod, src_id, HTTP_CLIENT_FNS[name], args[0], line)
            m = self._method(mod, callee, env)
            if m is None:
                pass
            elif m[0] == "?":
                self.unresolved[m[1]] = self.unresolved.get(m[1], 0) + 1
            elif m[0] == "ext":
                refs.append(Ref("call", f"ext:{m[1]}", line, RESOLVED, "receiver-type"))
            elif m[0] == "trait":
                self._trait_refs(m[1], m[2], m[3], line, refs)
            else:
                refs.append(Ref("call", nid(m[1].crate, m[1].path, m[2]), line, RESOLVED, "receiver-type"))
            return False
        # plain / scoped calls
        if callee.type in ("identifier", "scoped_identifier", "generic_function"):
            full = _text(callee)
            last = full.split("::")[-1]
            if full in ("reqwest::get", "ureq::get", "reqwest::blocking::get") and args:
                self._http_out(mod, src_id, "GET", args[0], line)
            elif full.startswith("ureq::") and last in HTTP_CLIENT_FNS and args:
                self._http_out(mod, src_id, HTTP_CLIENT_FNS[last], args[0], line)
            r = self._callee(mod, callee, env)
            if r is None:
                if callee.type == "identifier" and _text(callee) not in env:
                    self.unresolved[full[:60]] = self.unresolved.get(full[:60], 0) + 1
                return False
            if r[0] == "ext":
                refs.append(Ref("call", f"ext:{r[1]}", line, RESOLVED, "use"))
                return False
            if r[0] == "trait":
                self._trait_refs(r[1], r[2], r[3], line, refs)
                return False
            tid = nid(r[1].crate, r[1].path, r[2])
            refs.append(Ref("call", tid, line, RESOLVED, r[3]))
            for a in args:                                   # callbacks: named repo functions as arguments
                a = self._unwrap(a)
                if a is not None and a.type in ("identifier", "scoped_identifier"):
                    c = self._callee(mod, a, env)
                    if c and c[0] == "fn":
                        refs.append(Ref("callback", nid(c[1].crate, c[1].path, c[2]), line, INFERRED, "callback"))
        return False

    def _trait_refs(self, tmod: RsModule, trait: RsType, name: str, line: int, refs: list[Ref]) -> None:
        impls = [(m, t) for m, t in self.implementers(trait) if f"{t.name}::{name}" in m.funcs]
        if not impls:
            self.unresolved[f"{trait.name}.{name}"] = self.unresolved.get(f"{trait.name}.{name}", 0) + 1
        for m, t in impls:
            refs.append(Ref("call", nid(m.crate, m.path, f"{t.name}::{name}"), line, POSSIBLE, "trait"))

    def _mark_prefix(self, n: TSNode, prefix: str) -> None:
        stack = [n]
        while stack:
            cur = stack.pop()
            if cur.type == "call_expression":
                f = cur.child_by_field_name("function")
                if f is not None and f.type == "field_expression" and _text(f.child_by_field_name("field")) in ("route", "nest", "service", "mount"):
                    key = (cur.start_byte, cur.end_byte)
                    self.node_prefix[key] = prefix + self.node_prefix.get(key, "")
            stack.extend(cur.children)

    def _handlers(self, mod: RsModule, e: TSNode, env) -> list[tuple[str, TSNode]]:
        """`get(h).post(h2)` (axum) or `web::get().to(h)` (actix) -> [(VERB, handler expr)]."""
        out: list[tuple[str, TSNode]] = []
        e = self._unwrap(e)
        cur = e
        pending_verb: str | None = None
        while cur is not None and cur.type == "call_expression":
            f = cur.child_by_field_name("function")
            a = _args(cur)
            if f is None:
                break
            if f.type == "field_expression":
                name = _text(f.child_by_field_name("field"))
                if name in VERBS and a:
                    out.append((name.upper(), a[0]))
                elif name == "to" and a:
                    pending_verb = pending_verb or "ANY"
                    out.append(("__to__", a[0]))
                cur = f.child_by_field_name("value")
                continue
            name = _text(f).split("::")[-1]
            if name in VERBS or name == "any":
                verb = "ANY" if name == "any" else name.upper()
                if a:
                    out.append((verb, a[0]))
                else:
                    pending_verb = verb                 # actix: web::get() carries the verb for a later .to(h)
            break
        return [((pending_verb or "ANY") if v == "__to__" else v, h) for v, h in out]

    def _handler_id(self, mod: RsModule, h: TSNode, env) -> str | None:
        h = self._unwrap(h)
        if h is None:
            return None
        if h.type == "call_expression":                 # middleware wrappers: take the first function argument
            for a in _args(h):
                hid = self._handler_id(mod, a, env)
                if hid:
                    return hid
            return None
        if h.type in ("identifier", "scoped_identifier"):
            r = self._callee(mod, h, env)
            if r and r[0] == "fn":
                return nid(r[1].crate, r[1].path, r[2])
        return None

    def _macro(self, mod, fn, src_id, n: TSNode, env, refs) -> None:
        pass

    def _http_out(self, mod: RsModule, src_id: str, method: str, url: TSNode, line: int) -> None:
        raw, prefix_unknown = self._url(mod, url)
        if raw is None:
            return
        norm = _normalize(raw, prefix_unknown)
        if norm:
            path, host, pu = norm
            self.http.append({"src": src_id, "method": method, "path": path, "raw": raw, "prefix_unknown": pu,
                              "host": host, "line": line, "ui": None, "file": mod.file})

    def _url(self, mod: RsModule, n: TSNode | None) -> tuple[str | None, bool]:
        n = self._unwrap(n)
        if n is None:
            return None, False
        s = _string(n)
        if s is not None:
            return s, False
        if n.type == "identifier":
            v = mod.consts.get(_text(n))
            return (v, False) if v is not None else ("{}", True)
        if n.type == "scoped_identifier":
            r = self.resolve_path(mod, _text(n).split("::")[:-1])
            name = _text(n).split("::")[-1]
            if r and r[0] == "type":
                return "{}", True
            m = self.mods.get((mod.crate, tuple(_text(n).split("::")[1:-1]))) if _text(n).startswith("crate::") else None
            if m and name in m.consts:
                return m.consts[name], False
            return "{}", True
        if n.type == "macro_invocation" and _text(n.child_by_field_name("macro")).split("::")[-1] == "format":
            tt = next((c for c in n.children if c.type == "token_tree"), None)
            m = re.search(r'"((?:[^"\\]|\\.)*)"', _text(tt)) if tt is not None else None
            if m:
                rest = _text(tt)[m.end():].strip("() ")
                args = [a.strip() for a in rest.split(",") if a.strip()]
                vals = iter(args)
                def sub(_m, vals=vals):
                    a = next(vals, None)
                    return mod.consts.get(a, "{}") if a else "{}"
                fmt = re.sub(r"\{[^{}]*\}", sub, m.group(1))
                return fmt, fmt.startswith("{}")
        if n.type == "binary_expression":
            return "{}", True
        return "{}", True


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
    norm = "/" + "/".join("{}" if ("{" in s or s.startswith(":") or s.startswith("<")) else s for s in segs)
    return norm, host, prefix_unknown


# --------------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------------

def add_rust(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo).resolve()
    paths = discover(repo)
    if not paths:
        return {"files": 0, "lines": 0}
    roots = crates(repo)
    parser = Parser(RUST)
    mods: dict[tuple[str, tuple[str, ...]], RsModule] = {}
    files: list[tuple[str, int, RsModule, TSNode]] = []
    total = 0
    for p in paths:
        rel = p.relative_to(repo).as_posix()
        try:
            src = project_bytes(p, repo)
        except OSError:
            continue
        if len(src) > 1_500_000:
            continue
        lines = src.count(b"\n") + 1
        total += lines
        crate, path, is_test = module_of(rel, roots)
        tree = parser.parse(src)     # kept in `files`: a node outlives its tree only as a dangling pointer (segfault)
        root = tree.root_node
        mod = mods.get((crate, path))
        if mod is None:
            mod = mods[(crate, path)] = RsModule(crate=crate, path=path, file=rel, is_test=is_test)
        files.append((rel, lines, mod, root, tree))
    for rel, _lines, mod, root, _tree in files:
        deep.whole((g, "rust"), rel, _collect, mod, root, mods, mod.crate, mod.path, rel, left=(g, "rust"))
    # a file module declared by `mod x;` whose file exists is a child even when the parent never names it (bins)
    for (crate, path) in list(mods):
        if path:
            parent = mods.get((crate, path[:-1]))
            if parent is not None:
                parent.children.add(path[-1])
    crate_names = set(roots.values())
    link = Linker(mods, crate_names)
    link.left = (g, "rust")

    for rel, lines, _mod, _root, _tree in files:
        g.add_node(Node(id=f"rs:{rel}", kind=MODULE, name=Path(rel).name, qualname=rel, file=rel, start_line=1, end_line=lines))
    for mod in mods.values():
        for rt in mod.types.values():
            tid = nid(mod.crate, mod.path, rt.name)
            g.add_node(Node(id=tid, kind=CLASS, name=rt.name, qualname=tid[3:], file=rt.file, start_line=rt.start,
                            end_line=rt.end, parent=f"rs:{rt.file}", signature=("trait " if rt.is_trait else "struct ") + rt.name))
            g.add_edge(f"rs:{rt.file}", tid, kind=CONTAINS)
    refs_by_src: dict[str, list[Ref]] = {}
    for mod in mods.values():
        for fn in mod.funcs.values():
            fid = nid(mod.crate, mod.path, fn.local)
            parent = nid(mod.crate, mod.path, fn.impl_type) if fn.impl_type and fn.impl_type in mod.types else f"rs:{fn.file}"
            g.add_node(Node(id=fid, kind=CALLABLE, name=fn.name, qualname=fid[3:], file=fn.file, start_line=fn.start,
                            end_line=fn.end, parent=parent, fingerprint=fn.fingerprint, signature=fn.signature,
                            decorators=[f"#[{fn.attr_route[0].lower()}(\"{fn.attr_route[1]}\")]"] if fn.attr_route else []))
            g.add_edge(parent, fid, kind=CONTAINS)
    for mod in mods.values():
        for fn in mod.funcs.values():
            fid = nid(mod.crate, mod.path, fn.local)
            refs_by_src[fid] = link.walk_func(mod, fn, fid)

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
    for mod in mods.values():
        if mod.is_test and f"rs:{mod.file}" in g.nodes and not g.nodes[f"rs:{mod.file}"].entry:
            g.nodes[f"rs:{mod.file}"].entry = {"kind": "test", "detail": mod.file}
        for fn in mod.funcs.values():
            fid = nid(mod.crate, mod.path, fn.local)
            node = g.nodes.get(fid)
            if node is None:
                continue
            if fn.name == "main" and not mod.path and not fn.impl_type:
                node.entry = {"kind": "main", "detail": f"{'server start' if fid in link.serves else 'program start'} ({fn.file})"}
            elif fn.is_test:
                node.entry = {"kind": "test", "detail": fn.file}
            if fn.attr_route:
                verb, path = fn.attr_route
                node.entry = {"kind": "route", "detail": f"{verb} {link.service_prefix.get(fid, '') + path}"}
    for r in link.routes:
        n = g.nodes.get(r["handler"])
        if n is None:
            continue
        prefix = link.nest_fn.get(r["src"], "")
        n.entry = {"kind": "route", "detail": f"{r['method']} {prefix + r['path'] if r['path'] != '/' or not prefix else prefix}"}
        g.add_edge(r["src"], r["handler"], kind=CALLS, confidence=INFERRED, line=r["line"], via="route-registration")

    g.meta.setdefault("http_calls", []).extend(link.http)
    return {"files": len(files), "lines": total, "unresolved": sum(link.unresolved.values()),
            "crates": len(crate_names) or 1, "routes": len(link.routes) + sum(1 for m in mods.values() for f in m.funcs.values() if f.attr_route),
            "http_calls": len(link.http)}
