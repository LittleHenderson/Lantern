"""C#: ASP.NET servers and .NET MAUI / Xamarin phone apps, mapped like the Java reader maps Java.

Node ids: type `cs:<namespace>.<Type>` (nested `Outer.Inner`), method `cs:<namespace>.<Type>.<Method>`, constructor
`cs:<namespace>.<Type>.<Type>` (like Java), file module `cs:<path>.cs`. Overloads share one node. A file of top-level
statements (`Program.cs` without a class) keeps its calls on the file module, which is a `main` entry.

Calls are resolved by:
  * `name`          `Helper()` → a method of the same type (or a repo type it inherits from)
  * `this`          `this.Helper()`
  * `assoc`         `Util.Run()`: a static call on a repo type
  * `receiver-type` `_repo.Find()` where `_repo` is a parameter, a field, a property, a primary-constructor parameter
                    or a local whose type is written (`NoteRepo r`) or comes from `new NoteRepo()` / `var r = new …` or a
                    repo method's written return type
  * `interface`     the receiver's type is an interface or abstract class in the repo: one `possible` edge to each type
                    that implements it (`INoteRepo` → `SqlNoteRepo.Find`)
  * `constructor`   `new NoteRepo(...)` → `NoteRepo.NoteRepo`
  * `callback`      a method group passed or attached by name (`button.Clicked += OnSave`, `app.MapGet("/n", List)`)
Library calls become `ext:<Type>.<Method>` nodes (`ext:Console.WriteLine`); an unknown receiver is counted in
`graph.unresolved`. Lambdas belong to the method they are written in.

Visibility follows C#: a type is found in its own namespace, its parent namespaces, and each `using` namespace.

Entries: `static Main` and top-level statement files (`main`), `[Fact]`/`[Theory]`/`[Test]`/`[TestMethod]` and test
projects (`test`), ASP.NET controller actions (`[Route("api/[controller]")]` + `[HttpGet("{id}")]` → `GET /api/notes/{id}`)
and minimal APIs (`app.MapGet("/notes/{id}", GetNote)`; an inline lambda becomes its own `GET /notes/{id}` node).
Phone screens and links come from `dotnet.add_entries` (MAUI / Xamarin), after this reader.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import SKIP_DIRS, inside_repo, project_bytes

MAX_BYTES = 1_500_000
SKIP = re.compile(r"(^|/)(bin|obj|packages|\.vs)/|\.(g|g\.i|designer|AssemblyInfo|AssemblyAttributes)\.cs$|"
                  r"(^|/)Migrations/\d+_|\.Designer\.cs$", re.I)
TEST_FILE_RE = re.compile(r"(^|/)[^/]*\.(Tests?|UnitTests|IntegrationTests|Specs)/|(^|/)tests?/", re.I)
TEST_ATTRS = {"Fact", "Theory", "Test", "TestMethod", "TestCase", "DataTestMethod"}
HTTP_METHODS = re.compile(r"^(Get|Post|Put|Patch|Delete)(?:Async|StringAsync|StreamAsync|ByteArrayAsync|FromJsonAsync|"
                          r"AsJsonAsync)$")
VERBS = {"HttpGet": "GET", "HttpPost": "POST", "HttpPut": "PUT", "HttpPatch": "PATCH", "HttpDelete": "DELETE"}
MAP_VERBS = {"MapGet": "GET", "MapPost": "POST", "MapPut": "PUT", "MapPatch": "PATCH", "MapDelete": "DELETE",
             "MapMethods": "ANY"}
TYPE_DECLS = ("class_declaration", "struct_declaration", "record_declaration", "record_struct_declaration",
              "interface_declaration", "enum_declaration")


def _parser():
    import tree_sitter as ts
    import tree_sitter_c_sharp as tc
    return ts.Parser(ts.Language(tc.language()))


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _kid(n, *types):
    return next((c for c in n.children if c.type in types), None) if n is not None else None


def _kids(n, *types):
    return [c for c in n.children if c.type in types] if n is not None else []


def _type_name(n) -> str | None:
    """`NoteRepo`, `NoteRepo?`, `Notes.Data.NoteRepo`, `Task<Note>` (→ Note), `List<Note>` (→ List) → a simple name."""
    if n is None:
        return None
    if n.type == "identifier":
        return _t(n)
    if n.type == "nullable_type":
        return _type_name(next((c for c in n.children if c.is_named), None))
    if n.type == "qualified_name":
        ids = _kids(n, "identifier", "generic_name")
        return _type_name(ids[-1]) if ids else None
    if n.type == "generic_name":
        base = _t(_kid(n, "identifier"))
        if base in ("Task", "ValueTask", "ActionResult"):
            args = _kid(n, "type_argument_list")
            inner = next((c for c in args.children if c.is_named), None) if args is not None else None
            return _type_name(inner)
        return base or None
    return None


def _attrs(n) -> list[tuple[str, str | None]]:
    """(name, first string argument) for each attribute on a declaration."""
    out = []
    for al in _kids(n, "attribute_list"):
        for a in _kids(al, "attribute"):
            name = _t(_kid(a, "identifier", "qualified_name")).rsplit(".", 1)[-1]
            name = name[:-9] if name.endswith("Attribute") else name
            arg = None
            args = _kid(a, "attribute_argument_list")
            for aa in _kids(args, "attribute_argument"):
                s = _kid(aa, "string_literal", "verbatim_string_literal")
                if s is not None:
                    arg = "".join(_t(c) for c in s.children if c.type == "string_literal_content") or \
                        _t(s).strip('@"')
                    break
            out.append((name, arg))
    return out


def _mods(n) -> set[str]:
    return {_t(m) for m in _kids(n, "modifier")}


@dataclass
class CFun:
    name: str
    cls: str | None
    file: str
    start: int
    end: int
    signature: str
    fingerprint: str
    params: dict[str, str] = field(default_factory=dict)
    returns: str | None = None
    route: tuple[str, str] | None = None
    is_test: bool = False
    static: bool = False
    nodes: list = field(default_factory=list)      # declaration nodes (overloads), or a lambda for a minimal API


@dataclass
class CClass:
    name: str
    file: str
    start: int
    end: int
    kind: str                  # class | interface | struct | record | enum | abstract
    supers: list[str] = field(default_factory=list)
    props: dict[str, str] = field(default_factory=dict)
    route_prefix: str | None = None
    attrs: list = field(default_factory=list)
    funs: set[str] = field(default_factory=set)
    consts: dict[str, str] = field(default_factory=dict)   # `const string Base = "…"` / `static readonly string`


@dataclass
class CFile:
    rel: str
    lines: int
    usings: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    namespaces: set[str] = field(default_factory=set)
    is_test: bool = False
    top_level: list = field(default_factory=list)  # global statements


class Model:
    def __init__(self):
        self.classes: dict[tuple[str, str], CClass] = {}
        self.funs: dict[tuple[str, str], CFun] = {}
        self.by_simple: dict[str, list[tuple[str, str]]] = {}
        self.unresolved: dict[str, int] = {}

    def add_class(self, ns: str, c: CClass):
        self.classes[(ns, c.name)] = c
        self.by_simple.setdefault(c.name, []).append((ns, c.name))

    def find_class(self, f: CFile, ns: str, cls: CClass | None, name: str) -> tuple[str, CClass] | None:
        if not name:
            return None
        if cls is not None:   # nested in the current type, or a sibling nested type
            for cand in (f"{cls.name}.{name}", f"{cls.name.rsplit('.', 1)[0]}.{name}" if "." in cls.name else None):
                if cand and (ns, cand) in self.classes:
                    return ns, self.classes[(ns, cand)]
        if name in f.aliases:
            name = f.aliases[name].rsplit(".", 1)[-1]
        scope = ns
        while True:           # own namespace, then each parent
            if (scope, name) in self.classes:
                return scope, self.classes[(scope, name)]
            if not scope:
                break
            scope = scope.rpartition(".")[0]
        for u in f.usings:
            if (u, name) in self.classes:
                return u, self.classes[(u, name)]
        hits = self.by_simple.get(name, [])
        if len(hits) == 1:    # one type of that name in the repo (global usings, implicit usings)
            return hits[0][0], self.classes[hits[0]]
        return None

    def fun_in(self, f: CFile, ns: str, c: CClass, name: str, depth: int = 0) -> tuple[str, str] | None:
        if name in c.funs:
            return ns, f"{c.name}.{name}"
        if depth > 6:
            return None
        for s in c.supers:
            hit = self.find_class(f, ns, None, s)
            if hit and hit[1] is not c:
                r = self.fun_in(f, hit[0], hit[1], name, depth + 1)
                if r:
                    return r
        return None

    def implementers(self, c: CClass) -> list[tuple[str, CClass]]:
        """Classes that implement an interface or extend an abstract class, directly or through other classes
        (and interfaces that extend it); matched by simple name."""
        out, seen, todo = [], {id(c)}, [c.name.split(".")[-1]]
        while todo:
            short = todo.pop()
            for (p, _), k in self.classes.items():
                if short in k.supers and id(k) not in seen:
                    seen.add(id(k))
                    todo.append(k.name.split(".")[-1])
                    if k.kind != "interface":
                        out.append((p, k))
        return out


def nid(ns: str, local: str) -> str:
    return f"cs:{ns}.{local}" if ns else f"cs:{local}"


def discover(repo: Path) -> list[Path]:
    out = []
    for p in repo.rglob("*.cs"):
        rel = p.relative_to(repo)
        if any(x in SKIP_DIRS for x in rel.parts[:-1]) or SKIP.search(rel.as_posix()) or not p.is_file() \
                or not inside_repo(p, repo):
            continue
        out.append(p)
    return sorted(out)


def _params(plist) -> dict[str, str]:
    out = {}
    for prm in _kids(plist, "parameter"):
        name = prm.child_by_field_name("name")
        typ = prm.child_by_field_name("type")
        if name is not None:
            out[_t(name)] = _type_name(typ) or ""
    return out


def _collect(model: Model, f: CFile, root) -> None:
    def walk(n, ns: str, outer: CClass | None):
        for c in n.children:
            if c.type == "namespace_declaration":
                name = _t(c.child_by_field_name("name"))
                inner = f"{ns}.{name}" if ns else name
                f.namespaces.add(inner)
                walk(_kid(c, "declaration_list") or c, inner, None)
            elif c.type == "file_scoped_namespace_declaration":
                name = _t(c.child_by_field_name("name"))
                f.namespaces.add(name)
                ns = name                                   # applies to everything after it in the file
                walk(c, ns, None)
            elif c.type in TYPE_DECLS:
                _class(c, ns, outer)
            elif c.type in ("method_declaration", "constructor_declaration", "local_function_statement") \
                    and outer is not None:
                _fun(c, ns, outer)
            elif c.type == "global_statement" and outer is None:
                f.top_level.append(c)
            elif c.type in ("declaration_list", "ERROR"):
                walk(c, ns, outer)

    def _class(c, ns, outer):
        name_n = c.child_by_field_name("name")
        if name_n is None:
            return
        local = f"{outer.name}.{_t(name_n)}" if outer else _t(name_n)
        mods = _mods(c)
        kind = {"interface_declaration": "interface", "enum_declaration": "enum", "struct_declaration": "struct",
                "record_declaration": "record", "record_struct_declaration": "record"}.get(c.type, "class")
        if kind == "class" and "abstract" in mods:
            kind = "abstract"
        k = CClass(name=local, file=f.rel, start=c.start_point.row + 1, end=c.end_point.row + 1, kind=kind,
                   attrs=_attrs(c))
        for b in _kids(_kid(c, "base_list"), "identifier", "qualified_name", "generic_name", "primary_constructor_base_type"):
            tn = _type_name(b if b.type != "primary_constructor_base_type" else next(
                (x for x in b.children if x.is_named), None))
            if tn:
                k.supers.append(tn)
        k.props.update({n: t for n, t in _params(_kid(c, "parameter_list")).items() if t})   # primary constructor
        for name, arg in k.attrs:
            if name == "Route":
                k.route_prefix = (arg or "").strip("/")
        body = _kid(c, "declaration_list")
        for fd in _kids(body, "field_declaration", "property_declaration", "event_field_declaration"):
            if fd.type == "property_declaration":
                pn, tn = fd.child_by_field_name("name"), _type_name(fd.child_by_field_name("type"))
                if pn is not None and tn:
                    k.props[_t(pn)] = tn
                continue
            vd = _kid(fd, "variable_declaration")
            if vd is None:
                continue
            tn = _type_name(vd.child_by_field_name("type"))
            for d in _kids(vd, "variable_declarator"):
                pn = _kid(d, "identifier")
                t = tn
                if t is None or t == "var":
                    oc = _kid(d, "object_creation_expression")
                    t = _type_name(oc.child_by_field_name("type")) if oc is not None else None
                if pn is not None and t:
                    k.props[_t(pn)] = t
                lit = next((ch for ch in d.children if ch.type == "string_literal"), None)
                if pn is not None and lit is not None and ({"const", "readonly"} & _mods(fd)):
                    k.consts[_t(pn)] = _t(lit)[1:-1]
        prev = model.classes.get((ns, local))
        if prev is not None:   # `partial class`: one type written across files (XAML code-behind, generated parts)
            prev.supers += [x for x in k.supers if x not in prev.supers]
            prev.props.update(k.props)
            prev.consts.update(k.consts)
            prev.attrs += k.attrs
            prev.route_prefix = prev.route_prefix or k.route_prefix
            if prev.kind == "class" and k.kind == "abstract":
                prev.kind = "abstract"
            k = prev
        else:
            model.add_class(ns, k)
        if body is not None:
            walk(body, ns, k)

    def _fun(c, ns, cls: CClass):
        name_n = c.child_by_field_name("name")
        if name_n is None:
            return
        name = _t(name_n)
        local = f"{cls.name}.{name}"
        params = _params(c.child_by_field_name("parameters"))
        ret = _type_name(c.child_by_field_name("returns") or c.child_by_field_name("type"))
        attrs = _attrs(c)
        route = None
        for an, arg in attrs:
            if an in VERBS:
                route = (VERBS[an], arg or "")
            elif an == "Route" and route is None:
                route = ("ANY", arg or "")
        is_test = any(an in TEST_ATTRS for an, _ in attrs)
        body = c.child_by_field_name("body") or _kid(c, "block", "arrow_expression_clause")
        sig_end = body.start_byte if body is not None else c.end_byte
        sig = c.text[: sig_end - c.start_byte].decode("utf-8", "replace")
        sig = re.sub(r"\s+", " ", re.sub(r"^\s*(\[[^\]]*\]\s*)+", "", sig)).strip()
        fp = hashlib.sha1(c.text, usedforsecurity=False).hexdigest()[:12]
        key = (ns, local)
        if key in model.funs:
            fn = model.funs[key]
            fn.nodes.append(c)
            fn.end = max(fn.end, c.end_point.row + 1)
            fn.params.update(params)
            fn.route = fn.route or route
            return
        model.funs[key] = CFun(name=name, cls=cls.name, file=f.rel, start=c.start_point.row + 1,
                               end=c.end_point.row + 1, signature=sig[:200], fingerprint=fp, params=params,
                               returns=ret, route=route, is_test=is_test, static="static" in _mods(c), nodes=[c])
        cls.funs.add(name)

    walk(root, "", None)


@dataclass
class Ref:
    target: str
    line: int
    confidence: str
    via: str
    kind: str = "call"


class Linker:
    def __init__(self, model: Model):
        self.m = model
        self.http: list[dict] = []

    def _type_of(self, f, ns, cls, env, e) -> str | None:
        if e is None:
            return None
        if e.type == "identifier":
            n = _t(e)
            if n in env:
                return env[n] or None
            c = cls
            while c is not None:
                if n in c.props:
                    return c.props[n]
                c = self.m.classes.get((ns, c.name.rsplit(".", 1)[0])) if "." in c.name else None
            return None
        if e.type == "this_expression" or e.type == "this":
            return cls.name.split(".")[-1] if cls else None
        if e.type == "object_creation_expression":
            return _type_name(e.child_by_field_name("type"))
        if e.type == "implicit_object_creation_expression":
            return None
        if e.type in ("await_expression", "parenthesized_expression", "cast_expression"):
            if e.type == "cast_expression":
                return _type_name(e.child_by_field_name("type"))
            inner = next((c for c in reversed(e.children) if c.is_named), None)
            return self._type_of(f, ns, cls, env, inner)
        if e.type == "member_access_expression":
            obj, name = e.child_by_field_name("expression"), _t(e.child_by_field_name("name"))
            tn = self._type_of(f, ns, cls, env, obj)
            hit = self.m.find_class(f, ns, cls, tn) if tn else None
            return hit[1].props.get(name) if hit else None
        if e.type == "invocation_expression":
            res = self._target(f, ns, cls, env, e.child_by_field_name("function"))
            if res and res[2]:
                fn = self.m.funs.get(res[2])
                return fn.returns if fn else None
        return None

    def _target(self, f, ns, cls, env, fn_n):
        """(target id, via, (ns, local) of the repo method, confidence, extra targets) for a call's function part."""
        if fn_n is None:
            return None
        if fn_n.type == "generic_name":
            fn_n = _kid(fn_n, "identifier")
        if fn_n is not None and fn_n.type == "identifier":
            name = _t(fn_n)
            if cls is not None:
                r = self.m.fun_in(f, ns, cls, name)
                if r:
                    return (nid(*r), "name", r, RESOLVED, [])
            return None
        if fn_n is None or fn_n.type != "member_access_expression":
            return None
        recv = fn_n.child_by_field_name("expression")
        name_n = fn_n.child_by_field_name("name")
        if name_n is not None and name_n.type == "generic_name":
            name_n = _kid(name_n, "identifier")
        name = _t(name_n)
        if recv is None:
            return None
        if recv.type == "base_expression":
            return ("", "super", None, None, [])
        if recv.type in ("this_expression", "this") and cls is not None:
            r = self.m.fun_in(f, ns, cls, name)
            return (nid(*r), "this", r, RESOLVED, []) if r else None
        if recv.type == "identifier" and _t(recv) not in env and not self._is_member(ns, cls, _t(recv)):
            hit = self.m.find_class(f, ns, cls, _t(recv))
            if hit:                                            # Util.Run(): a static call on a repo type
                r = self.m.fun_in(f, hit[0], hit[1], name)
                return (nid(*r), "assoc", r, RESOLVED, []) if r else None
            if _t(recv)[:1].isupper():                         # Console.WriteLine(), File.ReadAllText()
                return (f"ext:{_t(recv)}.{name}", "import", None, RESOLVED, [])
        tn = self._type_of(f, ns, cls, env, recv)
        if not tn:
            inner = recv
            while inner is not None and inner.type in ("await_expression", "parenthesized_expression",
                                                        "member_access_expression") and inner.named_child_count:
                inner = (inner.child_by_field_name("expression") if inner.type == "member_access_expression"
                         else inner.named_children[-1])
            if inner is None:
                return None
            if inner.type == "invocation_expression":
                ir = self._target(f, ns, cls, env, inner.child_by_field_name("function"))
                if ir is None or (ir[0] or "").startswith("ext:"):
                    return None                                # a chain on a library call: not counted
        if tn:
            hit = self.m.find_class(f, ns, cls, tn)
            if hit:
                hns, k = hit
                r = self.m.fun_in(f, hns, k, name)
                if k.kind in ("interface", "abstract"):
                    extra = []
                    for ins, impl in self.m.implementers(k):
                        ir = self.m.fun_in(f, ins, impl, name)
                        if ir and ir != r:
                            extra.append(nid(*ir))
                    if extra:
                        return ("", "interface", None, POSSIBLE, extra)
                return (nid(*r), "receiver-type", r, RESOLVED, []) if r else None
            return (f"ext:{tn}.{name}", "receiver-type", None, RESOLVED, [])
        return (None, None, None, None, [])

    # ---- outgoing HTTP (HttpClient) ----
    def _url_text(self, f, ns, cls, n) -> tuple[str | None, bool]:
        if n is None:
            return None, False
        if n.type == "string_literal":
            return _t(n)[1:-1], False
        if n.type == "verbatim_string_literal":
            return _t(n)[2:-1], False
        if n.type == "interpolated_string_expression":
            out, pu = "", False
            for ch in n.children:
                if ch.type == "string_content":
                    out += _t(ch)
                elif ch.type == "interpolation":
                    inner = next((x for x in ch.children if x.is_named and x.type != "interpolation_brace"), None)
                    v, _ = self._url_text(f, ns, cls, inner) if inner is not None and inner.type in (
                        "identifier", "member_access_expression") else ("{}", not out)
                    if v == "{}" and not out:
                        pu = True
                    out += v
            return out, pu
        if n.type == "identifier" and cls is not None:
            v = cls.consts.get(_t(n))
            return (v, False) if v is not None else ("{}", True)
        if n.type == "member_access_expression":
            hit = self.m.find_class(f, ns, cls, _t(n.child_by_field_name("expression")))
            v = hit[1].consts.get(_t(n.child_by_field_name("name"))) if hit else None
            return (v, False) if v is not None else ("{}", True)
        if n.type == "binary_expression" and _t(n.child_by_field_name("operator")) == "+":
            l, lp = self._url_text(f, ns, cls, n.child_by_field_name("left"))
            r, _ = self._url_text(f, ns, cls, n.child_by_field_name("right"))
            if l is None or r is None:
                return None, False
            return l + (r if not (r == "{}" and l.endswith("{}")) else ""), lp
        if n.type == "parenthesized_expression":
            return self._url_text(f, ns, cls, next((c for c in n.children if c.is_named), None))
        return "{}", True

    def _emit_http(self, f, ns, cls, src, method, url_n, line):
        from .java_frontend import _normalize
        raw, pu = self._url_text(f, ns, cls, url_n)
        if raw is None or raw == "{}":
            return
        if not re.match(r"(https?:)?//|/|\{", raw):   # relative to HttpClient.BaseAddress: "api/notes"
            raw, pu = "{}/" + raw, True
        norm = _normalize(raw, pu)
        if norm:
            path, host, pu = norm
            self.http.append({"src": src, "method": method, "path": path, "raw": raw, "prefix_unknown": pu,
                              "host": host, "line": line, "ui": None, "file": f.rel})

    def _http_call(self, f, ns, cls, x, env, src):
        fn_n = x.child_by_field_name("function")
        if fn_n is None or fn_n.type != "member_access_expression":
            return
        name = _t(fn_n.child_by_field_name("name")).split("<")[0]
        m = HTTP_METHODS.match(name)
        if not m:
            return
        recv = fn_n.child_by_field_name("expression")
        rt = (_t(recv) + " " + (self._type_of(f, ns, cls, env, recv) or "")) if recv is not None else ""
        if not re.search(r"http|client|api", rt, re.I):
            return
        args = [next((c for c in a.children if c.is_named), None) for a in _kids(_kid(x, "argument_list"), "argument")]
        if args and args[0] is not None:
            self._emit_http(f, ns, cls, src, m.group(1).upper(), args[0], x.start_point.row + 1)

    def _is_member(self, ns, cls, name) -> bool:
        c = cls
        while c is not None:
            if name in c.props:
                return True
            c = self.m.classes.get((ns, c.name.rsplit(".", 1)[0])) if "." in c.name else None
        return False

    def walk_nodes(self, f, ns, cls, nodes, env, src, stop_at_lambdas: set | None = None) -> list[Ref]:
        refs: list[Ref] = []
        for node in nodes:
            self._walk(f, ns, cls, node, dict(env), refs, src, stop_at_lambdas or set())
        return refs

    def _walk(self, f, ns, cls, n, env, refs, src, skip):
        stack = [n]
        while stack:
            x = stack.pop()
            if x.id in skip and x is not n:
                continue                                     # a minimal-API lambda: its own node
            if x.type == "variable_declaration":
                tn = _type_name(x.child_by_field_name("type"))
                for d in _kids(x, "variable_declarator"):
                    pn = _kid(d, "identifier")
                    if pn is None:
                        continue
                    t = tn if tn and tn != "var" else None
                    if t is None:
                        val = next((ch for ch in reversed(d.children) if ch.is_named and ch is not pn), None)
                        t = self._type_of(f, ns, cls, env, val)
                    env[_t(pn)] = t or ""
            elif x.type == "parameter" and x is not n:
                pn, tn = x.child_by_field_name("name"), _type_name(x.child_by_field_name("type"))
                if pn is not None:
                    env[_t(pn)] = tn or ""
            elif x.type == "invocation_expression":
                self._call(f, ns, cls, x, env, refs, src)
                self._http_call(f, ns, cls, x, env, src)
            elif x.type == "object_creation_expression":
                tn = _type_name(x.child_by_field_name("type"))
                if tn == "HttpRequestMessage":            # new HttpRequestMessage(HttpMethod.Post, url)
                    args = [next((c for c in a.children if c.is_named), None)
                            for a in _kids(_kid(x, "argument_list"), "argument")]
                    if len(args) >= 2 and args[0] is not None and _t(args[0]).startswith("HttpMethod."):
                        self._emit_http(f, ns, cls, src, _t(args[0]).split(".")[-1].upper(), args[1],
                                        x.start_point.row + 1)
                hit = self.m.find_class(f, ns, cls, tn) if tn else None
                if hit:
                    ctor = self.m.fun_in(f, hit[0], hit[1], hit[1].name.split(".")[-1])
                    if ctor:
                        refs.append(Ref(nid(*ctor), x.start_point.row + 1, RESOLVED, "constructor"))
            elif x.type == "assignment_expression":
                op = x.child_by_field_name("operator")
                right = x.child_by_field_name("right")
                if op is not None and _t(op) == "+=" and right is not None and right.type == "identifier" \
                        and cls is not None:
                    r = self.m.fun_in(f, ns, cls, _t(right))
                    if r:                                    # button.Clicked += OnSave
                        refs.append(Ref(nid(*r), x.start_point.row + 1, INFERRED, "callback", "callback"))
            elif x.type == "argument" and cls is not None:
                v = next((ch for ch in x.children if ch.is_named), None)
                if v is not None and v.type == "identifier" and _t(v) not in env and not self._is_member(ns, cls, _t(v)):
                    r = self.m.fun_in(f, ns, cls, _t(v))
                    if r:                                    # app.MapGet("/n", List), Task.Run(Work)
                        refs.append(Ref(nid(*r), x.start_point.row + 1, INFERRED, "callback", "callback"))
            elif x.type in TYPE_DECLS and x is not n:
                continue
            stack.extend(reversed(x.children))

    def _call(self, f, ns, cls, x, env, refs, src):
        fn_n = x.child_by_field_name("function")
        line = x.start_point.row + 1
        res = self._target(f, ns, cls, env, fn_n)
        if res is None:
            return
        target, via, _r, conf, extra = res
        if via == "super":
            return
        if target:
            refs.append(Ref(target, line, conf or RESOLVED, via))
        for t in extra:
            refs.append(Ref(t, line, POSSIBLE, via))
        if target is None and not extra and fn_n is not None and fn_n.type == "member_access_expression":
            key = f"{src}: {_t(fn_n.child_by_field_name('expression'))[:40]}.{_t(fn_n.child_by_field_name('name'))}"
            self.m.unresolved[key] = self.m.unresolved.get(key, 0) + 1


def _minimal_apis(model: Model, f: CFile, ns: str, scope_nodes, owner: str | None) -> list[tuple]:
    """`app.MapGet("/p", handler)` calls: (verb, path, handler node or name, line, group prefix)."""
    out = []
    groups: dict[str, str] = {}
    for top in scope_nodes:
        stack = [top]
        while stack:
            x = stack.pop()
            if x.type == "variable_declarator":                   # var api = app.MapGroup("/api");
                inv = _kid(x, "invocation_expression")
                fn_n = inv.child_by_field_name("function") if inv is not None else None
                if fn_n is not None and fn_n.type == "member_access_expression" \
                        and _t(fn_n.child_by_field_name("name")) == "MapGroup":
                    s = _first_string(inv)
                    recv = _t(fn_n.child_by_field_name("expression"))
                    if s is not None:
                        groups[_t(_kid(x, "identifier"))] = groups.get(recv, "") + "/" + s.strip("/")
            if x.type == "invocation_expression":
                fn_n = x.child_by_field_name("function")
                if fn_n is not None and fn_n.type == "member_access_expression":
                    verb = MAP_VERBS.get(_t(fn_n.child_by_field_name("name")))
                    args = _kids(x.child_by_field_name("arguments"), "argument")
                    if verb and len(args) >= 2:
                        path = _first_string(args[0])
                        h = next((c for c in args[-1].children if c.is_named), None)
                        prefix = groups.get(_t(fn_n.child_by_field_name("expression")), "")
                        if path is not None and h is not None:
                            out.append((verb, (prefix + "/" + path.strip("/")).rstrip("/") or "/", h,
                                        x.start_point.row + 1))
            stack.extend(reversed(x.children))
    return out


def _first_string(n) -> str | None:
    stack = [n]
    while stack:
        x = stack.pop()
        if x.type == "string_literal":
            return "".join(_t(c) for c in x.children if c.type == "string_literal_content")
        if x.type == "verbatim_string_literal":
            return _t(x)[2:-1]
        stack.extend(reversed(x.children))
    return None


def add_csharp(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    paths = discover(repo)
    if not paths:
        return {}
    try:
        parser = _parser()
    except ImportError:
        g.meta.setdefault("skipped_languages", []).append("c# (pip install tree-sitter-c-sharp)")
        return {}
    model = Model()
    files: list[tuple[CFile, object]] = []
    total = 0
    for p in paths:
        try:
            src = project_bytes(p, repo)
        except OSError:
            continue
        if len(src) > MAX_BYTES:
            continue
        rel = p.relative_to(repo).as_posix()
        tree = parser.parse(src)
        root = tree.root_node
        lines = src.count(b"\n") + 1
        total += lines
        f = CFile(rel=rel, lines=lines, is_test=bool(TEST_FILE_RE.search(rel)))
        for u in _kids(root, "using_directive"):
            text = _t(u)
            q = _kid(u, "qualified_name", "identifier")
            m = re.search(r"using\s+(?:static\s+)?(\w+)\s*=\s*([\w.]+)", text)
            if m:
                f.aliases[m.group(1)] = m.group(2)
            elif q is not None:
                f.usings.append(_t(q))
        files.append((f, tree))
        _collect(model, f, root)

    for f, _ in files:
        g.add_node(Node(id=f"cs:{f.rel}", kind=MODULE, name=Path(f.rel).name, qualname=f.rel, file=f.rel,
                        start_line=1, end_line=f.lines))
        if f.is_test:
            g.nodes[f"cs:{f.rel}"].entry = {"kind": "test", "detail": f.rel}
    for (ns, local), c in model.classes.items():
        cid = nid(ns, local)
        parent = nid(ns, local.rsplit(".", 1)[0]) if "." in local else f"cs:{c.file}"
        sup = f": {', '.join(c.supers)}" if c.supers else ""
        g.add_node(Node(id=cid, kind=CLASS, name=local.split(".")[-1], qualname=cid[3:], file=c.file, start_line=c.start,
                        end_line=c.end, parent=parent, signature=f"{c.kind} {local}{sup}"[:200]))
        g.add_edge(parent, cid, kind=CONTAINS)
    for (ns, local), fn in model.funs.items():
        mid = nid(ns, local)
        parent = nid(ns, fn.cls) if fn.cls else f"cs:{fn.file}"
        sig = fn.signature + (f"  (+{len(fn.nodes) - 1} overload{'s' if len(fn.nodes) > 2 else ''})"
                              if len(fn.nodes) > 1 else "")
        g.add_node(Node(id=mid, kind=CALLABLE, name=fn.name, qualname=mid[3:], file=fn.file, start_line=fn.start,
                        end_line=fn.end, parent=parent, fingerprint=fn.fingerprint, signature=sig[:200]))
        g.add_edge(parent, mid, kind=CONTAINS)

    link = Linker(model)
    edges = 0
    routes = 0

    def add_refs(src_id, refs):
        nonlocal edges
        for r in refs:
            if r.target.startswith("ext:"):
                g.external(r.target[4:])
            elif r.target not in g.nodes or r.target == src_id:
                continue
            g.add_edge(src_id, r.target, kind=CALLS, confidence=r.confidence, line=r.line, via=r.via)
            edges += 1

    def map_routes(f, ns, cls, scope_nodes, owner_id):
        """Minimal APIs: a named handler becomes the route; an inline lambda becomes its own node."""
        nonlocal routes
        lambdas = set()
        for verb, path, h, _line in _minimal_apis(model, f, ns, scope_nodes, owner_id):
            detail = f"{verb} {path if path.startswith('/') else '/' + path}"
            if h.type == "member_access_expression":    # MapGet("/n/{id}", NoteEndpoints.Get)
                hit = model.find_class(f, ns, cls, _t(h.child_by_field_name("expression")))
                r = model.fun_in(f, hit[0], hit[1], _t(h.child_by_field_name("name"))) if hit else None
                if r and nid(*r) in g.nodes:
                    g.nodes[nid(*r)].entry = {"kind": "route", "detail": detail}
                    routes += 1
            elif h.type == "identifier":
                tgt = None
                if cls is not None:
                    r = model.fun_in(f, ns, cls, _t(h))
                    tgt = nid(*r) if r else None
                if tgt is None:
                    hit = [k for k, v in model.funs.items() if v.name == _t(h) and (v.static or v.cls is None)]
                    tgt = nid(*hit[0]) if len(hit) == 1 else None
                if tgt and tgt in g.nodes:
                    g.nodes[tgt].entry = {"kind": "route", "detail": detail}
                    routes += 1
            elif h.type in ("lambda_expression", "anonymous_method_expression"):
                lid = f"cs:{f.rel}::{detail}"
                g.add_node(Node(id=lid, kind=CALLABLE, name=detail, qualname=f"{f.rel}::{detail}", file=f.rel,
                                start_line=h.start_point.row + 1, end_line=h.end_point.row + 1, parent=owner_id,
                                fingerprint=hashlib.sha1(h.text, usedforsecurity=False).hexdigest()[:12],
                                signature=re.sub(r"\s+", " ", _t(h).split("=>")[0])[:200] + " =>"))
                g.add_edge(owner_id, lid, kind=CONTAINS)
                g.nodes[lid].entry = {"kind": "route", "detail": detail}
                routes += 1
                env = _params(_kid(h, "parameter_list"))
                add_refs(lid, link.walk_nodes(f, ns, cls, [h], env, lid))
                lambdas.add(h.id)
        return lambdas

    by_rel = {f.rel: f for f, _ in files}
    fn_ns = {}
    for (ns, local), fn in model.funs.items():
        fn_ns[(ns, local)] = ns
        f = by_rel[fn.file]
        cls = model.classes.get((ns, fn.cls)) if fn.cls else None
        src = nid(ns, local)
        skip = map_routes(f, ns, cls, fn.nodes, src) if fn.name in ("Main", "Configure", "MapEndpoints") or any(
            b"Map" in nd.text for nd in fn.nodes) else set()
        env = dict(fn.params)
        refs = []
        for nd in fn.nodes:
            body = nd.child_by_field_name("body") or _kid(nd, "block", "arrow_expression_clause")
            if body is not None:
                refs += link.walk_nodes(f, ns, cls, [body], env, src, skip)
        add_refs(src, refs)
    for f, _ in files:                                   # top-level statements (Program.cs)
        if not f.top_level:
            continue
        mid = f"cs:{f.rel}"
        ns = next(iter(sorted(f.namespaces)), "")
        skip = map_routes(f, ns, None, f.top_level, mid)
        add_refs(mid, link.walk_nodes(f, ns, None, f.top_level, {}, mid, skip))
        if not f.is_test:
            g.nodes[mid].entry = {"kind": "main", "detail": f"program start ({f.rel})"}

    g.meta.setdefault("http_calls", []).extend(link.http)
    for key, n in model.unresolved.items():
        g.unresolved[key[:120]] = g.unresolved.get(key[:120], 0) + n
    for (ns, local), fn in model.funs.items():
        node = g.nodes.get(nid(ns, local))
        if node is None:
            continue
        f = by_rel[fn.file]
        if fn.name == "Main" and fn.static:
            node.entry = {"kind": "main", "detail": f"program start ({fn.file})"}
        elif fn.is_test or (f.is_test and fn.name[:1].isupper() and fn.cls and fn.cls.endswith(("Tests", "Test"))):
            node.entry = {"kind": "test", "detail": fn.file}
        cls = model.classes.get((ns, fn.cls)) if fn.cls else None
        if fn.route and cls is not None and not f.is_test:
            verb, path = fn.route
            short = cls.name.split(".")[-1]
            prefix = (cls.route_prefix or "").replace("[controller]", short[:-10] if short.endswith("Controller")
                                                      else short).replace("[action]", fn.name)
            path = path.replace("[action]", fn.name)
            full = path.lstrip("~") if path.startswith("~/") or path.startswith("/") else \
                "/".join(x for x in (prefix, path) if x)
            node.entry = {"kind": "route", "detail": f"{verb} /{full.lstrip('/')}".rstrip("/") if full else f"{verb} /"}
            routes += 1
    return {"files": len(files), "lines": total, "classes": len(model.classes), "functions": len(model.funs),
            "routes": routes, "http_calls": len(link.http), "unresolved": sum(model.unresolved.values())}
