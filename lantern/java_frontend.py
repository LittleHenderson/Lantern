"""Java frontend: packages, classes, interfaces, methods, calls, Spring / JAX-RS / Javalin routes, outgoing HTTP.

Everything downstream reads the graph this builds and never asks which language made it. Node ids:
`jv:<package>.<Class>.<method>` (nested classes `Outer.Inner`), class nodes `jv:<package>.<Class>`, each file a
module node `jv:<repo-relative path>`. Overloads share one node (the first declaration's lines); a constructor is `Class.Class`.

Resolution (each edge says how in `via`):
  * `name`             an unqualified call to a method of the same class (or `this.m()`)            -> resolved
  * `inherited`        an unqualified / `super.` call found up the `extends` chain                     -> resolved
  * `static`           `Class.m()` on a class of this repo (same package, import, or wildcard import) -> resolved
  * `receiver-type`    `x.m()` where x's type is written down (field, parameter, local, `new T()`) or
                       is the return type of a method already resolved                                 -> resolved
  * `interface`        `x.m()` where x is an interface or abstract class of the repo: one `possible`
                       edge to each repo class that implements/extends it and defines m              -> possible
  * `constructor`      `new T(...)` to T's constructor when it is declared                              -> resolved
  * `callback`         a method reference `Class::m` / `this::m` passed as an argument                  -> inferred
Anything else (a method on an untyped receiver, chained calls on foreign results, lambdas) is counted in
`graph.unresolved`, never guessed.

Entries: `public static void main` (`main`; "server start" when it runs a Spring/Javalin/Quarkus app),
`@Test` methods and files under `src/test/` (`test`), routes: Spring (`@RequestMapping` on the class as prefix,
`@GetMapping`/`@PostMapping`/… and `@RequestMapping(method = …)` on methods), JAX-RS (`@Path` + `@GET`/…),
Micronaut (`@Controller` + `@Get`/…), Javalin/Spark (`app.get("/p", Class::handler)`). Outgoing calls
(`RestTemplate`, `WebClient`, `HttpRequest.newBuilder().uri(…)`, OkHttp `Request.Builder().url(…)`) go to
`g.meta["http_calls"]`; URLs from literals, `+` chains, `String.format` and `static final String` constants.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_java as tsjv
from tree_sitter import Language, Node as TSNode, Parser

from . import deep
from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import inside_repo, project_bytes, skipped_dir

JAVA = Language(tsjv.language())

VERB_ANNOTATIONS = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE",
                    "PatchMapping": "PATCH", "GET": "GET", "POST": "POST", "PUT": "PUT", "DELETE": "DELETE",
                    "PATCH": "PATCH", "HEAD": "HEAD", "OPTIONS": "OPTIONS", "Get": "GET", "Post": "POST", "Put": "PUT",
                    "Delete": "DELETE", "Patch": "PATCH"}
CLASS_PREFIX_ANNOTATIONS = {"RequestMapping", "Path", "Controller"}
JAVALIN_VERBS = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH", "head": "HEAD"}
SERVE_RE = re.compile(r"SpringApplication\.run|Javalin\.create|Quarkus\.run|Micronaut\.run|\.start\(\s*\d*\s*\)|HttpServer\.create")
REST_TEMPLATE = {"getForObject": "GET", "getForEntity": "GET", "postForObject": "POST", "postForEntity": "POST",
                 "postForLocation": "POST", "put": "PUT", "delete": "DELETE", "patchForObject": "PATCH"}
SKIP_JAVA_DIRS = {"target", "build", ".gradle", "out", "bin"}


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
    if n is not None and n.type == "string_literal":
        t = _text(n)
        if t.startswith('"""'):
            return t[3:-3].strip()
        return t[1:-1]
    return None


def _type_name(n: TSNode | None) -> str | None:
    """The simple or dotted class name of a type expression; generics, arrays and annotations are looked through."""
    while n is not None:
        if n.type == "generic_type":
            n = next((c for c in n.children if c.type in ("type_identifier", "scoped_type_identifier")), None)
            continue
        if n.type == "array_type":
            n = n.child_by_field_name("element")
            continue
        if n.type == "annotated_type":
            n = next((c for c in n.children if c.type.endswith("type") or c.type == "type_identifier"), None)
            continue
        if n.type in ("type_identifier", "scoped_type_identifier"):
            return _text(n)
        return None
    return None


def _args(call: TSNode) -> list[TSNode]:
    a = call.child_by_field_name("arguments")
    return [c for c in a.children if c.type not in ("(", ")", ",")] if a is not None else []


def _annotations(n: TSNode) -> list[TSNode]:
    mods = next((c for c in n.children if c.type == "modifiers"), None)
    return [c for c in mods.children if c.type in ("annotation", "marker_annotation")] if mods is not None else []


def _ann_name(a: TSNode) -> str:
    return _text(a.child_by_field_name("name")).split(".")[-1]


def _ann_path(a: TSNode) -> str | None:
    """The path string of a mapping annotation: @GetMapping("/x"), @RequestMapping(value = "/x"), @Path("/x")."""
    args = a.child_by_field_name("arguments")
    if args is None:
        return ""
    for c in args.children:
        if c.type == "string_literal":
            return _string(c)
        if c.type == "element_value_pair":
            key = _text(c.child_by_field_name("key"))
            val = c.child_by_field_name("value")
            if key in ("value", "path"):
                if val is not None and val.type == "string_literal":
                    return _string(val)
                if val is not None and val.type == "element_value_array_initializer":
                    first = next((x for x in val.children if x.type == "string_literal"), None)
                    return _string(first) if first is not None else ""
        if c.type == "element_value_array_initializer":
            first = next((x for x in c.children if x.type == "string_literal"), None)
            return _string(first) if first is not None else ""
    return ""


def _ann_methods(a: TSNode) -> list[str]:
    args = a.child_by_field_name("arguments")
    if args is None:
        return []
    for c in args.children:
        if c.type == "element_value_pair" and _text(c.child_by_field_name("key")) == "method":
            return re.findall(r"RequestMethod\.([A-Z]+)|\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
                              _text(c.child_by_field_name("value"))) and \
                [x or y for x, y in re.findall(r"RequestMethod\.([A-Z]+)|\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
                                               _text(c.child_by_field_name("value")))]
    return []


@dataclass
class JMethod:
    name: str
    local: str                   # "Class.method" or "Outer.Inner.method"
    start: int
    end: int
    node: TSNode
    file: str
    cls: str                     # the class local name
    params: dict[str, str] = field(default_factory=dict)       # var -> type name as written
    result: str | None = None
    signature: str = ""
    fingerprint: str = ""
    is_test: bool = False
    is_static: bool = False
    route: tuple[str, str] | None = None     # (VERB, path) from annotations (class prefix applied later)
    overloads: int = 1


@dataclass
class JClass:
    name: str                    # local name, "Outer.Inner" for nested
    start: int
    end: int
    file: str
    kind: str = "class"          # class | interface | enum | record | abstract
    fields: dict[str, str] = field(default_factory=dict)
    extends: str | None = None
    implements: list[str] = field(default_factory=list)
    methods: set[str] = field(default_factory=set)
    route_prefix: str = ""
    consts: dict[str, str] = field(default_factory=dict)


@dataclass
class JFile:
    rel: str
    pkg: str
    lines: int
    imports: dict[str, str] = field(default_factory=dict)      # simple name -> fully qualified
    wildcards: list[str] = field(default_factory=list)        # packages
    static_imports: dict[str, str] = field(default_factory=dict)   # method name -> fq class
    is_test: bool = False


@dataclass
class JPackage:
    name: str
    classes: dict[str, JClass] = field(default_factory=dict)    # local name -> class
    methods: dict[str, JMethod] = field(default_factory=dict)   # "Class.method" -> method
    files: list[JFile] = field(default_factory=list)


def discover(repo: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if not skipped_dir(dirpath, d) and d not in SKIP_JAVA_DIRS
                             and not d.startswith("."))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if fn.endswith(".java") and not fn.startswith("package-info") and inside_repo(p, repo):
                out.append(p)
    return out


def nid(pkg: str, local: str | None = None) -> str:
    base = f"{pkg}.{local}" if pkg and local else (local or pkg)
    return f"jv:{base}"


# --------------------------------------------------------------------------------------------
# Pass 1: declarations
# --------------------------------------------------------------------------------------------

def _collect_file(pkg: JPackage, f: JFile, root: TSNode, left=None) -> None:
    for c in root.children:
        if c.type == "import_declaration":
            path = next((x for x in c.children if x.type in ("scoped_identifier", "identifier")), None)
            if path is None:
                continue
            fq = _text(path)
            is_static = any(x.type == "static" for x in c.children)
            wildcard = any(x.type == "asterisk" for x in c.children)
            if wildcard and not is_static:
                f.wildcards.append(fq)
            elif is_static and not wildcard:
                cls, _, name = fq.rpartition(".")
                f.static_imports[name] = cls
            elif not wildcard:
                f.imports[fq.rsplit(".", 1)[-1]] = fq
        elif c.type in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
            _collect_class(pkg, f, c, None, left)


def _collect_class(pkg: JPackage, f: JFile, c: TSNode, outer: str | None, left=None) -> None:
    name = _text(c.child_by_field_name("name"))
    local = f"{outer}.{name}" if outer else name
    kind = {"class_declaration": "class", "interface_declaration": "interface", "enum_declaration": "enum",
            "record_declaration": "record"}[c.type]
    anns = _annotations(c)
    if kind == "class" and any(m.type == "abstract" for m in (next((x for x in c.children if x.type == "modifiers"), None) or c).children):
        kind = "abstract"
    jc = JClass(name=local, start=c.start_point.row + 1, end=c.end_point.row + 1, file=f.rel, kind=kind)
    sup = c.child_by_field_name("superclass")
    if sup is not None:
        jc.extends = _type_name(next((x for x in sup.children if x.type != "extends"), None))
    ifs = c.child_by_field_name("interfaces")
    if ifs is not None:
        tl = next((x for x in ifs.children if x.type == "type_list"), None)
        for t in (tl.children if tl is not None else []):
            tn = _type_name(t)
            if tn:
                jc.implements.append(tn)
    if kind == "interface":
        ext = next((x for x in c.children if x.type == "extends_interfaces"), None)
        if ext is not None:
            tl = next((x for x in ext.children if x.type == "type_list"), None)
            for t in (tl.children if tl is not None else []):
                tn = _type_name(t)
                if tn:
                    jc.implements.append(tn)
    for a in anns:
        an = _ann_name(a)
        if an in CLASS_PREFIX_ANNOTATIONS:
            p = _ann_path(a) or ""
            if p:
                jc.route_prefix = p.rstrip("/")
    pkg.classes[local] = jc
    body = c.child_by_field_name("body")
    if body is None:
        return
    for m in body.children:
        if m.type == "field_declaration":
            tn = _type_name(m.child_by_field_name("type"))
            for d in [x for x in m.children if x.type == "variable_declarator"]:
                fname = _text(d.child_by_field_name("name"))
                val = d.child_by_field_name("value")
                if val is not None and val.type == "object_creation_expression":
                    tn = _type_name(val.child_by_field_name("type")) or tn
                if tn:
                    jc.fields[fname] = tn
                s = _string(val)
                if s is not None and tn == "String":
                    jc.consts[fname] = s
        elif m.type in ("method_declaration", "constructor_declaration"):
            mname = _text(m.child_by_field_name("name"))
            if m.type == "constructor_declaration":
                mname = name                                   # Java's own name for a constructor
            mlocal = f"{local}.{mname}"
            params: dict[str, str] = {}
            fp = m.child_by_field_name("parameters")
            for p in (fp.children if fp is not None else []):
                if p.type in ("formal_parameter", "spread_parameter"):
                    tn = _type_name(p.child_by_field_name("type") or next((x for x in p.children if x.type.endswith("type") or x.type == "type_identifier"), None))
                    pn = p.child_by_field_name("name") or next((x for x in p.children if x.type == "variable_declarator"), None)
                    if tn and pn is not None:
                        params[_text(pn).split(" ")[-1]] = tn
            manns = _annotations(m)
            route = None
            for a in manns:
                an = _ann_name(a)
                if an in VERB_ANNOTATIONS:
                    route = (VERB_ANNOTATIONS[an], _ann_path(a) or "")
                elif an == "RequestMapping":
                    verbs = _ann_methods(a)
                    route = ("/".join(verbs) if verbs else "ANY", _ann_path(a) or "")
                elif an == "Path" and route is not None:
                    route = (route[0], _ann_path(a) or "")
            if route is not None and route[0] in VERB_ANNOTATIONS.values() and not route[1]:
                # JAX-RS: @GET with a separate @Path, in either order
                pth = next((_ann_path(a) for a in manns if _ann_name(a) == "Path"), "")
                route = (route[0], pth or "")
            mods = next((x for x in m.children if x.type == "modifiers"), None)
            is_static = mods is not None and any(x.type == "static" for x in mods.children)
            ret = _type_name(m.child_by_field_name("type"))
            if mlocal in pkg.methods:
                pkg.methods[mlocal].overloads += 1
                pkg.methods[mlocal].params.update({k: v for k, v in params.items() if k not in pkg.methods[mlocal].params})
                if route and not pkg.methods[mlocal].route:
                    pkg.methods[mlocal].route = route
                continue
            sig = f"{_text(m.child_by_field_name('type')) + ' ' if m.type == 'method_declaration' else ''}{_text(m.child_by_field_name('name'))}{_text(fp)}"
            pkg.methods[mlocal] = JMethod(
                name=mname, local=mlocal, start=m.start_point.row + 1, end=m.end_point.row + 1, node=m, file=f.rel,
                cls=local, params=params, result=ret if ret not in ("void",) else None, signature=sig[:200],
                fingerprint=_fingerprint(m), is_test=f.is_test or any(_ann_name(a) in ("Test", "ParameterizedTest") for a in manns),
                is_static=is_static, route=route)
            jc.methods.add(mname)
        elif m.type in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
            try:
                _collect_class(pkg, f, m, local, left)
            except RecursionError:
                # a class inside more classes than this walk follows: left where it stands and written down
                deep.leave(left, f.rel, m)


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


# The node types whose children are statements. `Linker._walk` reads them one by one, so a statement nested deeper than
# it follows costs that statement and not the rest of the method (`lantern/deep.py`).
STATEMENT_LISTS = ("block", "constructor_body", "switch_block_statement_group")


class Linker:
    left = None     # (map, "java") once `add_java` has a map: where a piece that was not read is written down

    def __init__(self, pkgs: dict[str, JPackage]):
        self.pkgs = pkgs
        self.by_fq: dict[str, tuple[JPackage, JClass]] = {}
        for p in pkgs.values():
            for c in p.classes.values():
                self.by_fq[f"{p.name}.{c.name}" if p.name else c.name] = (p, c)
                self.by_fq.setdefault(c.name.split(".")[-1], (p, c))      # simple-name fallback is checked last
        self.unresolved: dict[str, int] = {}
        self.routes: list[dict] = []
        self.http: list[dict] = []
        self.serves: set[str] = set()

    # ---- type lookup ----
    def find_class(self, pkg: JPackage, f: JFile, cls: JClass | None, name: str) -> tuple[JPackage, JClass] | None:
        if not name:
            return None
        if "." in name and name in self.by_fq and name[0].islower():
            return self.by_fq[name]
        simple = name.split(".")[-1] if name[0].islower() else name
        if cls is not None:
            if f"{cls.name}.{simple}" in pkg.classes:                        # a nested class of the current class
                return pkg, pkg.classes[f"{cls.name}.{simple}"]
            outer = cls.name.split(".")[0]
            if f"{outer}.{simple}" in pkg.classes:
                return pkg, pkg.classes[f"{outer}.{simple}"]
        if simple in pkg.classes:
            return pkg, pkg.classes[simple]
        fq = f.imports.get(simple.split(".")[0])
        if fq:
            tail = simple.split(".")[1:]
            key = fq + ("." + ".".join(tail) if tail else "")
            if key in self.by_fq and key[0].islower():
                return self.by_fq[key]
            p = self.pkgs.get(fq.rsplit(".", 1)[0]) if "." in fq else None
            if p and fq.rsplit(".", 1)[1] in p.classes:
                return p, p.classes[fq.rsplit(".", 1)[1]]
            return None
        for w in f.wildcards:
            p = self.pkgs.get(w)
            if p and simple in p.classes:
                return p, p.classes[simple]
        return None

    def method_in(self, pkg: JPackage, f: JFile, start: tuple[JPackage, JClass], name: str, depth: int = 0):
        """(JPackage, JMethod, via) looking up the extends chain; None when no class declares it."""
        p, c = start
        local = f"{c.name}.{name}"
        if local in p.methods:
            return p, p.methods[local], "name" if depth == 0 else "inherited"
        if c.extends and depth < 6:
            sup = self.find_class(p, next((ff for ff in p.files if ff.rel == c.file), f), c, c.extends)
            if sup:
                return self.method_in(pkg, f, sup, name, depth + 1)
        return None

    def implementers(self, target: tuple[JPackage, JClass]) -> list[tuple[JPackage, JClass]]:
        _tp, tc = target
        out = []
        for p in self.pkgs.values():
            for c in p.classes.values():
                if c.kind in ("interface",):
                    continue
                ff = next((x for x in p.files if x.rel == c.file), None)
                names = list(c.implements) + ([c.extends] if c.extends else [])
                for n in names:
                    r = self.find_class(p, ff, c, n) if ff else None
                    if r and r[1] is tc:
                        out.append((p, c))
                        break
        return out

    # ---- walk ----
    def walk_method(self, pkg: JPackage, f: JFile, cls: JClass, m: JMethod, src_id: str) -> list[Ref]:
        env: dict[str, str] = dict(m.params)
        refs: list[Ref] = []
        body = m.node.child_by_field_name("body")
        if body is not None:
            if m.name == "main" and m.is_static and SERVE_RE.search(_text(body)):
                self.serves.add(src_id)
            self._walk(pkg, f, cls, m, src_id, body, env, refs)
        return refs

    def _walk(self, pkg, f, cls, m, src_id, n: TSNode, env, refs):
        t = n.type
        if t in STATEMENT_LISTS:
            for c in n.children:
                try:
                    self._walk(pkg, f, cls, m, src_id, c, env, refs)
                except RecursionError:   # nested deeper than this walk follows: left and written down, the next one read
                    deep.leave(self.left, f.rel, c, env)
            return
        if t == "local_variable_declaration":
            tn = _type_name(n.child_by_field_name("type"))
            for d in [x for x in n.children if x.type == "variable_declarator"]:
                name = _text(d.child_by_field_name("name"))
                val = d.child_by_field_name("value")
                typ = tn if tn and tn != "var" else self._expr_type(pkg, f, cls, val, env)
                if typ:
                    env[name] = typ
        elif t == "resource":                                   # try (Statement st = conn.createStatement())
            tn = _type_name(n.child_by_field_name("type"))
            nm = n.child_by_field_name("name")
            if tn and nm is not None and tn != "var":
                env[_text(nm)] = tn
        elif t == "enhanced_for_statement":
            tn = _type_name(n.child_by_field_name("type"))
            nm = n.child_by_field_name("name")
            if tn and nm is not None and tn != "var":
                env[_text(nm)] = tn
        elif t == "lambda_expression":
            params = n.child_by_field_name("parameters")
            inner = dict(env)
            if params is not None:
                for p in params.children:
                    if p.type == "formal_parameter":
                        tn = _type_name(p.child_by_field_name("type"))
                        if tn:
                            inner[_text(p.child_by_field_name("name"))] = tn
            body = n.child_by_field_name("body")
            if body is not None:
                self._walk(pkg, f, cls, m, src_id, body, inner, refs)
            return
        elif t == "method_invocation":
            self._call(pkg, f, cls, m, src_id, n, env, refs)
        elif t == "object_creation_expression":
            tn = _type_name(n.child_by_field_name("type"))
            found = self.find_class(pkg, f, cls, tn) if tn else None
            if found:
                p, c = found
                ctor = f"{c.name}.{c.name.split('.')[-1]}"
                if ctor in p.methods:
                    refs.append(Ref("call", nid(p.name, ctor), n.start_point.row + 1, RESOLVED, "constructor"))
                for a in _args(n):
                    self._callback(pkg, f, cls, a, env, refs, n.start_point.row + 1)
            self._http_builder(pkg, f, cls, src_id, n, env)
        elif t == "method_reference":
            pass
        for c in n.children:
            self._walk(pkg, f, cls, m, src_id, c, env, refs)

    def _expr_type(self, pkg, f, cls, e: TSNode | None, env) -> str | None:
        if e is None:
            return None
        if e.type == "parenthesized_expression":
            return self._expr_type(pkg, f, cls, next((c for c in e.children if c.type not in ("(", ")")), None), env)
        if e.type == "cast_expression":
            return _type_name(e.child_by_field_name("type"))
        if e.type == "identifier":
            name = _text(e)
            if name in env:
                return env[name]
            if name in cls.fields:
                return cls.fields[name]
            return None
        if e.type == "this":
            return cls.name
        if e.type == "field_access":
            obj = e.child_by_field_name("object")
            fld = _text(e.child_by_field_name("field"))
            if obj is not None and obj.type == "this":
                return cls.fields.get(fld)
            bt = self._expr_type(pkg, f, cls, obj, env)
            found = self.find_class(pkg, f, cls, bt) if bt else None
            if found:
                return found[1].fields.get(fld)
            return None
        if e.type == "object_creation_expression":
            return _type_name(e.child_by_field_name("type"))
        if e.type == "method_invocation":
            r = self._resolve_invocation(pkg, f, cls, e, env)
            if r and r[0] == "fn":
                return r[1].methods[r[2]].result
            return None
        return None

    def _resolve_invocation(self, pkg, f, cls, n: TSNode, env):
        """("fn", JPackage, local, via) | ("iface", JPackage, JClass, name) | ("ext", name) | ("?", key) | None."""
        name = _text(n.child_by_field_name("name"))
        obj = n.child_by_field_name("object")
        if obj is None or obj.type == "this":
            r = self.method_in(pkg, f, (pkg, cls), name)
            if r:
                return ("fn", r[0], r[1].local, r[2])
            outer = cls.name.split(".")[0]
            if outer != cls.name and f"{outer}.{name}" in pkg.methods:         # a nested class calling the outer's method
                return ("fn", pkg, f"{outer}.{name}", "name")
            if name in f.static_imports:
                fq = f.static_imports[name]
                found = self.find_class(pkg, f, cls, fq.rsplit(".", 1)[-1]) if fq.rsplit(".", 1)[0] in self.pkgs or fq in self.by_fq else None
                if found and f"{found[1].name}.{name}" in found[0].methods:
                    return ("fn", found[0], f"{found[1].name}.{name}", "static")
                return ("ext", f"{fq.rsplit('.', 1)[-1]}.{name}")
            return ("?", f"{name}") if obj is None else ("?", f"this.{name}")
        if obj.type == "super":
            if cls.extends:
                sup = self.find_class(pkg, f, cls, cls.extends)
                if sup:
                    r = self.method_in(pkg, f, sup, name)
                    if r:
                        return ("fn", r[0], r[1].local, "inherited")
            return ("ext", f"{cls.extends or 'super'}.{name}")
        # a class name: static call
        if obj.type in ("identifier", "scoped_identifier", "field_access") and _text(obj).split(".")[-1][:1].isupper() \
                and _text(obj) not in env and _text(obj) not in cls.fields:
            found = self.find_class(pkg, f, cls, _text(obj))
            if found:
                r = self.method_in(pkg, f, found, name)
                if r:
                    return ("fn", r[0], r[1].local, "static")
                if found[1].kind in ("interface", "abstract"):
                    return ("iface", found[0], found[1], name)
                return ("?", f"{found[1].name}.{name}")
            return ("ext", f"{_text(obj).split('.')[-1]}.{name}")
        tn = self._expr_type(pkg, f, cls, obj, env)
        if tn is None:
            base = obj
            while base is not None and base.type == "field_access":
                base = base.child_by_field_name("object")
            if base is None or base.type not in ("identifier", "this"):
                return None                       # chains on foreign results, literals, lambdas: nothing of ours
            return ("?", f"{_text(obj)[:40]}.{name}")
        found = self.find_class(pkg, f, cls, tn)
        if found is None:
            return ("ext", f"{tn.split('.')[-1]}.{name}")
        if found[1].kind in ("interface", "abstract"):
            r = self.method_in(pkg, f, found, name)
            if r and found[1].kind == "abstract" and r[1].node.child_by_field_name("body") is not None:
                return ("fn", r[0], r[1].local, "receiver-type")
            return ("iface", found[0], found[1], name)
        r = self.method_in(pkg, f, found, name)
        if r:
            return ("fn", r[0], r[1].local, "receiver-type" if r[2] == "name" else "inherited")
        for iface in found[1].implements:                   # a default method of an implemented interface
            fi = self.find_class(found[0], next((ff for ff in found[0].files if ff.rel == found[1].file), f), found[1], iface)
            if fi and f"{fi[1].name}.{name}" in fi[0].methods and fi[0].methods[f"{fi[1].name}.{name}"].node.child_by_field_name("body") is not None:
                return ("fn", fi[0], f"{fi[1].name}.{name}", "inherited")
        return ("?", f"{found[1].name}.{name}")

    def _callback(self, pkg, f, cls, a: TSNode, env, refs, line: int) -> None:
        if a.type != "method_reference":
            return
        obj = a.children[0] if a.children else None
        name = _text(a.children[-1]) if a.children else ""
        target = None
        if obj is not None and obj.type == "this":
            r = self.method_in(pkg, f, (pkg, cls), name)
            target = (r[0], r[1].local) if r else None
        elif obj is not None:
            found = self.find_class(pkg, f, cls, _text(obj)) or (self.find_class(pkg, f, cls, self._expr_type(pkg, f, cls, obj, env) or "") if _text(obj) in env else None)
            if found:
                r = self.method_in(pkg, f, found, name)
                target = (r[0], r[1].local) if r else None
        if target:
            refs.append(Ref("callback", nid(target[0].name, target[1]), line, INFERRED, "callback"))

    def _call(self, pkg, f, cls, m, src_id, n: TSNode, env, refs) -> None:
        line = n.start_point.row + 1
        name = _text(n.child_by_field_name("name"))
        obj = n.child_by_field_name("object")
        args = _args(n)
        # Javalin / Spark: app.get("/p", Class::handler)
        if name in JAVALIN_VERBS and obj is not None and args and _string(args[0]) is not None and _string(args[0]).startswith("/") \
                and len(args) >= 2 and args[-1].type in ("method_reference", "lambda_expression"):
            h = args[-1]
            hid = None
            if h.type == "method_reference":
                before = len(refs)
                self._callback(pkg, f, cls, h, env, refs, line)
                if len(refs) > before:
                    hid = refs.pop().target
            if hid:
                self.routes.append({"src": src_id, "handler": hid, "method": JAVALIN_VERBS[name], "path": _string(args[0]), "line": line})
                return
        # outgoing HTTP
        if obj is not None:
            self._http_call(pkg, f, cls, src_id, name, obj, args, line, env)
        r = self._resolve_invocation(pkg, f, cls, n, env)
        if r is None:
            pass
        elif r[0] == "?":
            self.unresolved[r[1]] = self.unresolved.get(r[1], 0) + 1
        elif r[0] == "ext":
            refs.append(Ref("call", f"ext:{r[1]}", line, RESOLVED, "import"))
        elif r[0] == "iface":
            _, ip, ic, mname = r
            impls = [(p, c) for p, c in self.implementers((ip, ic)) if f"{c.name}.{mname}" in p.methods]
            if not impls:
                self.unresolved[f"{ic.name}.{mname}"] = self.unresolved.get(f"{ic.name}.{mname}", 0) + 1
            for p, c in impls:
                refs.append(Ref("call", nid(p.name, f"{c.name}.{mname}"), line, POSSIBLE, "interface"))
        else:
            _, p, local, via = r
            refs.append(Ref("call", nid(p.name, local), line, RESOLVED, via))
            for a in args:
                self._callback(pkg, f, cls, a, env, refs, line)

    # ---- outgoing HTTP ----
    def _url_text(self, pkg, f, cls, n: TSNode | None) -> tuple[str | None, bool]:
        if n is None:
            return None, False
        s = _string(n)
        if s is not None:
            return s, False
        if n.type == "identifier":
            v = cls.consts.get(_text(n))
            return (v, False) if v is not None else ("{}", True)
        if n.type == "field_access":
            found = self.find_class(pkg, f, cls, _text(n.child_by_field_name("object")))
            fld = _text(n.child_by_field_name("field"))
            if found and fld in found[1].consts:
                return found[1].consts[fld], False
            return "{}", True
        if n.type == "binary_expression" and _text(n.child_by_field_name("operator")) == "+":
            l, lp = self._url_text(pkg, f, cls, n.child_by_field_name("left"))
            r, _ = self._url_text(pkg, f, cls, n.child_by_field_name("right"))
            if l is None or r is None:
                return None, False
            return l + (r if not (r == "{}" and l.endswith("{}")) else ""), lp
        if n.type == "method_invocation" and _text(n.child_by_field_name("name")) == "format" and _args(n):
            fmt = _string(_args(n)[0])
            if fmt is not None:
                return re.sub(r"%[-+# 0-9.]*[a-zA-Z]", "{}", fmt), fmt.startswith("%")
        if n.type == "parenthesized_expression":
            return self._url_text(pkg, f, cls, next((c for c in n.children if c.type not in ("(", ")")), None))
        return "{}", True

    def _emit_http(self, pkg, f, cls, src_id, method: str, url_n: TSNode, line: int) -> None:
        raw, pu = self._url_text(pkg, f, cls, url_n)
        if raw is None:
            return
        norm = _normalize(raw, pu)
        if norm:
            path, host, pu = norm
            self.http.append({"src": src_id, "method": method, "path": path, "raw": raw, "prefix_unknown": pu,
                              "host": host, "line": line, "ui": None, "file": f.rel})

    def _http_call(self, pkg, f, cls, src_id, name: str, obj: TSNode, args: list[TSNode], line: int, env=None) -> None:
        recv = _text(obj) + " " + (self._expr_type(pkg, f, cls, obj, env or {}) or "")
        if name in REST_TEMPLATE and args and re.search(r"template|rest|client", recv, re.I):
            self._emit_http(pkg, f, cls, src_id, REST_TEMPLATE[name], args[0], line)
        elif name == "exchange" and len(args) >= 2 and re.search(r"template|rest", recv, re.I):
            mm = re.search(r"HttpMethod\.([A-Z]+)", _text(args[1]))
            self._emit_http(pkg, f, cls, src_id, mm.group(1) if mm else "ANY", args[0], line)
        elif name == "uri" and args and obj.type == "method_invocation":
            # webClient.get().uri("/x") and HttpRequest.newBuilder().uri(URI.create("/x"))
            verb_call = obj
            verb = _text(verb_call.child_by_field_name("name"))
            if verb in JAVALIN_VERBS and not _args(verb_call):
                self._emit_http(pkg, f, cls, src_id, JAVALIN_VERBS[verb], args[0], line)
            elif verb == "newBuilder":
                u = args[0]
                if u.type == "method_invocation" and _text(u.child_by_field_name("name")) == "create" and _args(u):
                    u = _args(u)[0]
                # the verb comes later in the chain: .GET() / .POST(...)
                chain = n_parent_chain(obj)
                mm = re.search(r"\.(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(", chain)
                self._emit_http(pkg, f, cls, src_id, mm.group(1) if mm else "ANY", u, line)
        elif name == "url" and args and obj.type == "object_creation_expression" and "Builder" in _text(obj):
            self._emit_http(pkg, f, cls, src_id, "ANY", args[0], line)

    def _http_builder(self, pkg, f, cls, src_id, n: TSNode, env) -> None:
        pass


def n_parent_chain(n: TSNode) -> str:
    """The text of the full call chain this node is part of (up to the statement)."""
    cur = n
    while cur.parent is not None and cur.parent.type in ("method_invocation", "field_access"):
        cur = cur.parent
    return _text(cur)[:400]


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

def add_java(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo).resolve()
    paths = discover(repo)
    if not paths:
        return {"files": 0, "lines": 0}
    parser = Parser(JAVA)
    pkgs: dict[str, JPackage] = {}
    files: list[tuple[JFile, TSNode, JPackage]] = []
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
        tree = parser.parse(src)     # kept in `files`: a node outlives its tree only as a dangling pointer (segfault)
        root = tree.root_node
        pd = next((c for c in root.children if c.type == "package_declaration"), None)
        pkg_name = _text(next((c for c in pd.children if c.type in ("scoped_identifier", "identifier")), None)) if pd is not None else ""
        f = JFile(rel=rel, pkg=pkg_name, lines=lines, is_test=bool(re.search(r"(^|/)src/test/|(^|/)tests?/", rel)))
        pkg = pkgs.setdefault(pkg_name, JPackage(name=pkg_name))
        pkg.files.append(f)
        files.append((f, root, pkg, tree))
    for f, root, pkg, _tree in files:
        deep.whole((g, "java"), f.rel, _collect_file, pkg, f, root, (g, "java"))

    link = Linker(pkgs)
    link.left = (g, "java")
    for f, _root, _pkg, _tree in files:
        g.add_node(Node(id=f"jv:{f.rel}", kind=MODULE, name=Path(f.rel).name, qualname=f.rel, file=f.rel, start_line=1, end_line=f.lines))
        if f.is_test:
            g.nodes[f"jv:{f.rel}"].entry = {"kind": "test", "detail": f.rel}
    for pkg in pkgs.values():
        for c in pkg.classes.values():
            cid = nid(pkg.name, c.name)
            parent = nid(pkg.name, c.name.rsplit(".", 1)[0]) if "." in c.name else f"jv:{c.file}"
            g.add_node(Node(id=cid, kind=CLASS, name=c.name.split(".")[-1], qualname=cid[3:], file=c.file, start_line=c.start,
                            end_line=c.end, parent=parent, signature=f"{c.kind} {c.name}"))
            g.add_edge(parent, cid, kind=CONTAINS)
        for m in pkg.methods.values():
            mid = nid(pkg.name, m.local)
            parent = nid(pkg.name, m.cls)
            sig = m.signature + (f"  (+{m.overloads - 1} overload{'s' if m.overloads > 2 else ''})" if m.overloads > 1 else "")
            g.add_node(Node(id=mid, kind=CALLABLE, name=m.name, qualname=mid[3:],
                            file=m.file, start_line=m.start, end_line=m.end, parent=parent, fingerprint=m.fingerprint,
                            signature=sig[:200], decorators=[f"@{m.route[0]} {m.route[1]}"] if m.route else []))
            g.add_edge(parent, mid, kind=CONTAINS)
    refs_by_src: dict[str, list[Ref]] = {}
    for pkg in pkgs.values():
        for m in pkg.methods.values():
            f = next(ff for ff in pkg.files if ff.rel == m.file)
            cls = pkg.classes[m.cls]
            refs_by_src[nid(pkg.name, m.local)] = link.walk_method(pkg, f, cls, m, nid(pkg.name, m.local))
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
    routes = 0
    for pkg in pkgs.values():
        for m in pkg.methods.values():
            mid = nid(pkg.name, m.local)
            node = g.nodes.get(mid)
            if node is None:
                continue
            if m.name == "main" and m.is_static:
                node.entry = {"kind": "main", "detail": f"{'server start' if mid in link.serves else 'program start'} ({m.file})"}
            elif m.is_test:
                node.entry = {"kind": "test", "detail": m.file}
            if m.route:
                verb, path = m.route
                prefix = pkg.classes[m.cls].route_prefix
                full = (prefix + path) if path and path != "/" else (prefix or path or "/")
                if not full.startswith("/"):
                    full = "/" + full
                node.entry = {"kind": "route", "detail": f"{verb} {full}"}
                routes += 1
    for r in link.routes:
        n = g.nodes.get(r["handler"])
        if n is None:
            continue
        n.entry = {"kind": "route", "detail": f"{r['method']} {r['path']}"}
        g.add_edge(r["src"], r["handler"], kind=CALLS, confidence=INFERRED, line=r["line"], via="route-registration")
        routes += 1

    g.meta.setdefault("http_calls", []).extend(link.http)
    return {"files": len(files), "lines": total, "unresolved": sum(link.unresolved.values()),
            "packages": len(pkgs), "classes": sum(len(p.classes) for p in pkgs.values()), "routes": routes,
            "http_calls": len(link.http)}
