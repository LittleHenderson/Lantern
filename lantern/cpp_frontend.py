"""C and C++: functions, classes and their calls, plus the HTTP routes of the common C++ web libraries.

Node ids: function `cc:<ns.Class>.<method>` / `cc:<ns>.<fn>` / `cc:<fn>` (namespaces and classes dotted; overloads share
one node; a constructor is `Class.Class`), a C `static` function `cc:<fn>@<file>` (file-local), a route lambda
`cc:<file>::GET /path`, a class `cc:<ns.Class>`, file module `cc:<path>`.

Calls are resolved by:
  * `name`          `f()` → a method of the enclosing class or its bases, else a function in the same namespace (inner
                    first), else a global or same-file `static` function; an unknown plain function is
                    `ext:<name>` (the C library and system calls: `system`, `sprintf`, `sqlite3_exec`)
  * `this`          `this->f()`
  * `assoc`         `Class::f()` on a repo class (static methods), `ns::f()` on a repo namespace; a library
                    `std::system()` is `ext:std.system`
  * `receiver-type` `x.f()` / `p->f()` where `x` is a parameter, local or member whose written type (through `const`,
                    `&`, `*`, `std::unique_ptr<T>`/`shared_ptr<T>`, `auto x = new T`/`T(...)`/`make_unique<T>`) is a
                    repo class; a library type → `ext:<Type>.<f>`
  * `constructor`   `new T(...)`, `T x(...)` → `T.T`
Calls on receivers of unknown type are counted in `graph.unresolved`; chains on library calls are not.

Entries: `main` (`main`), test files and gtest/Catch2 `TEST(...)`/`TEST_CASE(...)` blocks (`test`), and routes:
cpp-httplib `svr.Get("/p", handler)`, Crow `CROW_ROUTE(app, "/p").methods("POST"_method)(handler)`, Drogon
`ADD_METHOD_TO(Ctrl::m, "/p", Get)` / `app().registerHandler("/p", handler, {Post})`, Pistache
`Routes::Get(router, "/p", Routes::bind(&Ctrl::m, this))`. A lambda handler is its own node.
Outgoing calls: libcurl `CURLOPT_URL` and cpp-httplib `httplib::Client` → `meta["http_calls"]`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .graph import CALLABLE, CALLS, CLASS, CONTAINS, MODULE, RESOLVED, Graph, Node
from .python_frontend import SKIP_DIRS, inside_repo, project_bytes

C_EXTS = {".c"}
CPP_EXTS = {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h", ".ipp"}
MAX_BYTES = 1_500_000
SKIP = re.compile(r"(^|/)(third_party|third-party|thirdparty|external|extern|deps|vendor|vendored|_deps|build|"
                  r"cmake-build-[^/]*|out|bazel-[^/]*|\.pio|subprojects)/", re.I)
# Single-file libraries people copy into their repo: their code is not the app's
VENDORED = re.compile(r"(^|/)(httplib\.h|json\.hpp|nlohmann/[^/]+|crow_all\.h|sqlite3\.[ch]|sqlite3ext\.h|"
                      r"catch(_amalgamated)?\.[hc]pp|doctest\.h|stb_\w+\.h|miniz\.[ch]|cJSON\.[ch]|picojson\.h|"
                      r"tinyxml2\.(h|cpp)|imgui\w*\.(h|cpp)|lodepng\.(h|cpp)|nanosvg\w*\.h|uthash\.h|"
                      r"mongoose\.[ch]|civetweb\.[ch]|toml\.hpp|CLI11\.hpp|cxxopts\.hpp|httplib/.*)$", re.I)
TEST_FILE_RE = re.compile(r"(^|/)(tests?|unittests?|spec)/|(_test|_tests|_unittest|Test|Tests)\.(c|cc|cpp|cxx)$")
TEST_MACROS = {"TEST", "TEST_F", "TEST_P", "TYPED_TEST", "TEST_CASE", "SCENARIO", "BOOST_AUTO_TEST_CASE",
               "BOOST_FIXTURE_TEST_CASE"}
VERBS = {"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Options": "OPTIONS"}
DROGON_RE = re.compile(r"\b(ADD_METHOD_TO|METHOD_ADD|PATH_ADD)\s*\(\s*([\w:]+)\s*,\s*\"([^\"]*)\"\s*(?:,([^)]*))?\)")
SMART = re.compile(r"^(?:std::)?(?:unique_ptr|shared_ptr|weak_ptr|optional|reference_wrapper)<\s*(.+?)\s*(?:,.*)?>$")


def _parsers():
    import tree_sitter as ts
    import tree_sitter_c as tc
    import tree_sitter_cpp as tcpp
    return ts.Parser(ts.Language(tc.language())), ts.Parser(ts.Language(tcpp.language()))


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _named(n) -> list:
    return [c for c in n.children if c.is_named] if n is not None else []


def _str(n) -> str | None:
    """A plain string literal's text (also `"POST"_method`, concatenated literals)."""
    if n is None:
        return None
    if n.type == "user_defined_literal":
        return _str(next((c for c in n.children if c.type in ("string_literal", "raw_string_literal")), None))
    if n.type == "string_literal":
        return "".join(_t(c) for c in n.children if c.type in ("string_content", "escape_sequence"))
    if n.type == "concatenated_string":
        parts = [_str(c) for c in _named(n)]
        return None if None in parts else "".join(parts)
    return None


def _decl_name(d):
    """The identifier a declarator names, through pointers, references, arrays, init and function declarators."""
    while d is not None and d.type in ("pointer_declarator", "reference_declarator", "array_declarator",
                                       "init_declarator", "function_declarator", "parenthesized_declarator",
                                       "attributed_declarator"):
        inner = d.child_by_field_name("declarator")
        if inner is None:
            inner = next((c for c in d.children if c.is_named and c.type not in ("type_qualifier",)), None)
        d = inner
    return d


def _func_decl(d):
    while d is not None and d.type != "function_declarator":
        d = d.child_by_field_name("declarator")
    return d


def _clean_type(t: str) -> str:
    t = re.sub(r"\b(const|volatile|struct|class|typename|static|inline|mutable|constexpr|unsigned|signed)\b", " ", t)
    t = t.replace("&", " ").replace("*", " ").strip()
    t = re.sub(r"\s+", "", t)
    m = SMART.match(t)
    if m:
        t = m.group(1)
    return re.sub(r"<.*>$", "", t)


@dataclass
class CFun:
    id: str
    name: str
    cls: str | None
    ns: str
    file: str
    start: int
    end: int
    signature: str
    fingerprint: str
    node: object = None
    params: dict = field(default_factory=dict)


@dataclass
class CClass:
    id: str
    short: str
    file: str
    start: int
    end: int
    kind: str
    bases: list[str] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)
    methods: set[str] = field(default_factory=set)


class Model:
    def __init__(self):
        self.classes: dict[str, CClass] = {}
        self.by_short: dict[str, list[str]] = {}
        self.namespaces: set[str] = set()
        self.funs: dict[str, CFun] = {}
        self.free: dict[str, list[str]] = {}          # short name → function ids (namespaced or global)
        self.statics: dict[tuple[str, str], str] = {}  # (file, name) → id
        self.unresolved: dict[str, int] = {}

    def find(self, name: str, ns: str) -> str | None:
        """A type as written (`Store`, `app::Store`, `::Store`) → a repo class id, from namespace `ns` outwards."""
        d = name.lstrip(":").replace("::", ".")
        if not d:
            return None
        parts = ns.split(".") if ns else []
        for i in range(len(parts), -1, -1):
            cand = ".".join(parts[:i] + [d])
            if cand in self.classes:
                return cand
        hits = self.by_short.get(d.split(".")[-1], [])
        return hits[0] if len(hits) == 1 and "." not in d else None

    def ancestors(self, cid: str) -> list[str]:
        out, todo = [], [cid]
        while todo and len(out) < 20:
            c = self.classes.get(todo.pop(0))
            if c is None or c.id in out:
                continue
            out.append(c.id)
            ns = c.id.rsplit(".", 1)[0] if "." in c.id else ""
            for b in c.bases:
                r = self.find(b, ns)
                if r:
                    todo.append(r)
        return out

    def fun_in(self, cid: str | None, name: str) -> str | None:
        for a in (self.ancestors(cid) if cid else []):
            fid = f"cc:{a}.{name}"
            if fid in self.funs:
                return fid
        return None

    def free_fun(self, name: str, ns: str, file: str) -> str | None:
        s = self.statics.get((file, name))
        if s:
            return s
        parts = ns.split(".") if ns else []
        for i in range(len(parts), -1, -1):
            fid = "cc:" + ".".join(parts[:i] + [name])
            if fid in self.funs and self.funs[fid].cls is None:
                return fid
        return None


def discover(repo: Path) -> list[Path]:
    out = []
    exts = C_EXTS | CPP_EXTS
    for p in repo.rglob("*"):
        if p.suffix.lower() not in exts or not p.is_file():
            continue
        rel = p.relative_to(repo)
        if any(x in SKIP_DIRS for x in rel.parts[:-1]) or SKIP.search(rel.as_posix()) or \
                VENDORED.search(rel.as_posix()) or not inside_repo(p, repo):
            continue
        out.append(p)
    return sorted(out)


def _params(plist) -> dict[str, str]:
    out = {}
    for c in _named(plist):
        if c.type not in ("parameter_declaration", "optional_parameter_declaration"):
            continue
        nm = _decl_name(c.child_by_field_name("declarator"))
        if nm is not None and nm.type == "identifier":
            out[_t(nm)] = _clean_type(_t(c.child_by_field_name("type")))
    return out


class Collector:
    def __init__(self, model: Model, rel: str, is_c: bool):
        self.m, self.rel, self.is_c = model, rel, is_c
        self.lambdas: list = []

    def walk(self, nodes, ns: str, cls: CClass | None):
        for c in nodes:
            t = c.type
            if t == "namespace_definition":
                nm = c.child_by_field_name("name")
                inner = (ns + "." if ns else "") + (_t(nm).replace("::", ".") if nm is not None else "")
                if nm is None:
                    inner = ns                                       # anonymous namespace
                self.m.namespaces.add(inner)
                self.walk(_named(c.child_by_field_name("body")), inner, None)
            elif t in ("class_specifier", "struct_specifier") and c.child_by_field_name("body") is not None:
                self._class(c, ns, cls)
            elif t in ("declaration", "field_declaration", "type_definition", "template_declaration",
                       "linkage_specification", "preproc_ifdef", "preproc_if", "preproc_else", "preproc_elif",
                       "declaration_list"):
                for x in _named(c):
                    if x.type in ("class_specifier", "struct_specifier") and x.child_by_field_name("body") is not None:
                        self._class(x, ns, cls)
                if t == "field_declaration" and cls is not None:
                    self._field(c, cls)
                elif t in ("declaration", "field_declaration") and cls is not None:
                    fd = _func_decl(c.child_by_field_name("declarator"))
                    nm = _decl_name(fd) if fd is not None else None
                    if nm is not None:
                        cls.methods.add(_t(nm).split("::")[-1])
                if t in ("template_declaration", "linkage_specification", "preproc_ifdef", "preproc_if",
                         "preproc_else", "preproc_elif", "declaration_list"):
                    self.walk([x for x in _named(c) if x.type not in ("class_specifier", "struct_specifier")], ns, cls)
            elif t == "function_definition":
                self._fun(c, ns, cls)
            elif t == "field_declaration_list":
                self.walk(_named(c), ns, cls)

    def _class(self, c, ns: str, outer: CClass | None):
        nm = c.child_by_field_name("name")
        if nm is None:
            return
        local = _t(nm).replace("::", ".")
        local = re.sub(r"<.*>$", "", local)
        prefix = outer.id if outer else ns
        cid = (prefix + "." if prefix else "") + local
        k = self.m.classes.get(cid)
        if k is None:
            k = CClass(id=cid, short=local.split(".")[-1], file=self.rel, start=c.start_point.row + 1,
                       end=c.end_point.row + 1, kind=c.type.split("_")[0])
            self.m.classes[cid] = k
            self.m.by_short.setdefault(k.short, []).append(cid)
        for b in c.children:
            if b.type == "base_class_clause":
                k.bases += [re.sub(r"<.*>$", "", _t(x)) for x in _named(b)
                            if x.type in ("type_identifier", "qualified_identifier", "template_type")]
        self.walk(_named(c.child_by_field_name("body")), ns, k)

    def _field(self, c, cls: CClass):
        typ = _clean_type(_t(c.child_by_field_name("type")))
        for d in c.children_by_field_name("declarator"):
            if _func_decl(d) is not None:
                continue
            nm = _decl_name(d)
            if nm is not None and nm.type in ("field_identifier", "identifier"):
                cls.fields[_t(nm)] = typ

    def _fun(self, c, ns: str, cls: CClass | None):
        fd = _func_decl(c.child_by_field_name("declarator"))
        if fd is None:
            return
        nm = _decl_name(fd)
        if nm is None:
            return
        raw = _t(nm)
        body = c.child_by_field_name("body")
        sig_end = body.start_byte if body is not None else c.end_byte
        sig = re.sub(r"\s+", " ", c.text[: sig_end - c.start_byte].decode("utf-8", "replace")).strip()
        params = _params(fd.child_by_field_name("parameters"))
        if raw in TEST_MACROS:                                   # TEST(Suite, Name) { ... }
            args = [p.strip() for p in _t(fd.child_by_field_name("parameters")).strip("()").split(",")]
            fid = f"cc:{self.rel}::{raw} {'.'.join(a for a in args if a)[:60]}"
            self._add(fid, raw, None, ns, c, sig, {}, test=True)
            return
        owner = cls
        name = raw
        if nm.type in ("qualified_identifier", "template_function") and "::" in raw:
            qual, name = raw.rsplit("::", 1)
            qual = re.sub(r"<[^<>]*>", "", qual)
            hit = self.m.find(qual, ns)
            if hit:
                owner = self.m.classes[hit]
            else:
                ns = (ns + "." if ns else "") + qual.replace("::", ".")
        name = name.replace("~", "~")
        if owner is not None:
            fid = f"cc:{owner.id}.{name}"
            owner.methods.add(name)
        elif name == "main" and not ns:                          # every program has its own main
            fid = f"cc:main@{self.rel}"
        elif self.is_c and any(x.type == "storage_class_specifier" and _t(x) == "static" for x in c.children):
            fid = f"cc:{name}@{self.rel}"
            self.m.statics[(self.rel, name)] = fid
        else:
            fid = "cc:" + (ns + "." if ns else "") + name
        self._add(fid, name, owner.id if owner else None, ns, c, sig, params)

    def _add(self, fid, name, cls, ns, c, sig, params, test=False):
        if fid in self.m.funs:
            if self.m.funs[fid].node is not None and self.m.funs[fid].node.child_by_field_name("body") is not None:
                return
        self.m.funs[fid] = CFun(id=fid, name=name, cls=cls, ns=ns, file=self.rel, start=c.start_point.row + 1,
                                end=c.end_point.row + 1, signature=sig[:200],
                                fingerprint=hashlib.sha1(c.text, usedforsecurity=False).hexdigest()[:12], node=c,
                                params=params)
        if cls is None and not fid.startswith(f"cc:{self.rel}::") and "@" not in fid:
            self.m.free.setdefault(name, []).append(fid)


@dataclass
class Ref:
    target: str
    line: int
    via: str


def _walk_all(n):
    stack = [n] if n is not None else []
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.children))


class Linker:
    def __init__(self, model: Model):
        self.m = model
        self.http: list[dict] = []
        self.routes: list[tuple] = []            # (verb, path, handler node, owner fn, line)

    def _type_of_expr(self, e, ns: str) -> str | None:
        """The written type a value expression produces: `new T(...)`, `T(...)`, `std::make_unique<T>(...)`."""
        if e is None:
            return None
        if e.type == "new_expression":
            return _clean_type(_t(e.child_by_field_name("type")))
        if e.type == "call_expression":
            f = e.child_by_field_name("function")
            ft = _t(f)
            m = re.match(r"(?:std::)?make_(?:unique|shared)<\s*([\w:]+)", ft)
            if m:
                return m.group(1)
            if f is not None and f.type in ("identifier", "qualified_identifier", "type_identifier") and \
                    self.m.find(ft, ns):
                return ft
        if e.type in ("compound_literal_expression",):
            return _clean_type(_t(e.child_by_field_name("type")))
        return None

    def _type_of(self, recv, fn: CFun, env: dict) -> tuple[str | None, bool]:
        """(repo class id or library type name, is_repo) for a receiver; (None, False) when unknown."""
        if recv is None:
            return None, False
        if recv.type == "parenthesized_expression":
            return self._type_of(next(iter(_named(recv)), None), fn, env)
        if recv.type == "pointer_expression":                   # (*p).f()
            return self._type_of(recv.child_by_field_name("argument"), fn, env)
        if recv.type == "subscript_expression":
            return None, False
        typ = None
        if recv.type == "identifier":
            name = _t(recv)
            typ = env.get(name)
            if typ is None and fn.cls:
                for a in self.m.ancestors(fn.cls):
                    typ = self.m.classes[a].fields.get(name)
                    if typ:
                        break
        elif recv.type == "field_expression" and _t(recv.child_by_field_name("argument")) == "this" and fn.cls:
            fname = _t(recv.child_by_field_name("field"))
            for a in self.m.ancestors(fn.cls):
                typ = self.m.classes[a].fields.get(fname)
                if typ:
                    break
        if not typ or typ == "auto":
            return None, False
        hit = self.m.find(typ, fn.ns)
        return (hit, True) if hit else (typ, False)

    def target(self, call, fn: CFun, env: dict) -> tuple[str | None, str] | None:
        f = call.child_by_field_name("function")
        if f is None:
            return None
        if f.type == "template_function":
            f = f.child_by_field_name("name") or f
        if f.type == "identifier":
            name = _t(f)
            if fn.cls:
                r = self.m.fun_in(fn.cls, name)
                if r:
                    return r, "name"
            r = self.m.free_fun(name, fn.ns, fn.file)
            if r:
                return r, "name"
            hit = self.m.find(name, fn.ns)                        # T(...) builds a T
            if hit:
                r = self.m.fun_in(hit, hit.split(".")[-1])
                return (r, "constructor") if r else None
            if name in env:                                       # a function pointer or a lambda held in a local
                return None
            return f"ext:{name}", "import"
        if f.type == "qualified_identifier":
            raw = re.sub(r"<[^<>]*>", "", _t(f))
            qual, name = raw.rsplit("::", 1) if "::" in raw else ("", raw)
            hit = self.m.find(qual, fn.ns) if qual else None
            if hit:
                r = self.m.fun_in(hit, name)
                return (r, "assoc") if r else None
            if qual:
                ns = qual.lstrip(":").replace("::", ".")
                for base in ([fn.ns + "." + ns] if fn.ns else []) + [ns]:
                    fid = f"cc:{base}.{name}"
                    if fid in self.m.funs:
                        return fid, "assoc"
                return f"ext:{ns}.{name}", "import"
            r = self.m.free_fun(name, "", fn.file)
            return (r, "name") if r else (f"ext:{name}", "import")
        if f.type == "field_expression":
            recv = f.child_by_field_name("argument")
            name = _t(f.child_by_field_name("field"))
            if recv is not None and recv.type == "this":
                r = self.m.fun_in(fn.cls, name) if fn.cls else None
                return (r, "this") if r else None
            typ, repo = self._type_of(recv, fn, env)
            if typ and repo:
                r = self.m.fun_in(typ, name)
                return (r, "receiver-type") if r else None
            if typ:
                return f"ext:{typ.replace('::', '.')}.{name}", "receiver-type"
            if recv is not None and recv.type == "field_expression":     # req.path_params.at(): a library value's member
                base, brepo = self._type_of(recv.child_by_field_name("argument"), fn, env)
                if base and not brepo:
                    return None
            if recv is not None and recv.type == "call_expression":
                inner = self.target(recv, fn, env)
                if inner is None or (inner[0] or "").startswith("ext:"):
                    return None
            if recv is not None and recv.type in ("identifier", "field_expression", "call_expression"):
                return None, ""
        return None

    def walk(self, body, fn: CFun, env: dict, skip: set) -> list[Ref]:
        refs: list[Ref] = []
        stack = [body] if body is not None else []
        while stack:
            x = stack.pop()
            if x.id in skip:
                continue
            line = x.start_point.row + 1
            if x.type in ("declaration", "field_declaration") and x.parent is not None and x.parent.type != \
                    "field_declaration_list":
                typ = _clean_type(_t(x.child_by_field_name("type")))
                for d in x.children_by_field_name("declarator"):
                    nm = _decl_name(d)
                    if nm is None or nm.type != "identifier":
                        continue
                    t = typ
                    if d.type == "init_declarator" and (typ in ("auto", "") or typ.endswith("auto")):
                        t = self._type_of_expr(d.child_by_field_name("value"), fn.ns) or ""
                    env[_t(nm)] = t
                    hit = self.m.find(t, fn.ns) if t else None
                    if hit and d.type == "init_declarator" and d.child_by_field_name("value") is not None and \
                            d.child_by_field_name("value").type in ("argument_list", "initializer_list"):
                        r = self.m.fun_in(hit, hit.split(".")[-1])          # T x(...);
                        if r:
                            refs.append(Ref(r, line, "constructor"))
            elif x.type == "new_expression":
                hit = self.m.find(_clean_type(_t(x.child_by_field_name("type"))), fn.ns)
                r = self.m.fun_in(hit, hit.split(".")[-1]) if hit else None
                if r:
                    refs.append(Ref(r, line, "constructor"))
            elif x.type == "lambda_expression":
                pass
            elif x.type == "call_expression":
                res = self.target(x, fn, env)
                if res is not None:
                    t, via = res
                    if t:
                        refs.append(Ref(t, line, via))
                    elif via == "":
                        key = f"{fn.id}: {_t(x.child_by_field_name('function'))[:60]}"
                        self.m.unresolved[key] = self.m.unresolved.get(key, 0) + 1
                before = len(self.routes)
                self._route(x, fn)
                for r in self.routes[before:]:
                    if not isinstance(r[2], str):
                        skip.add(r[2].id)                         # a route lambda is its own node
                self._http(x, fn, env)
            stack.extend(reversed(x.children))
        return refs

    # ---- routes and outgoing calls
    def _handler(self, h, fn: CFun):
        """A handler argument → a lambda node, or a repo function id (`&Ctrl::m`, `handle`, `Routes::bind(&C::m, this)`)."""
        if h is None:
            return None
        if h.type == "lambda_expression":
            return h
        if h.type == "call_expression" and re.search(r"bind\s*$", _t(h.child_by_field_name("function"))):
            args = _named(h.child_by_field_name("arguments"))
            return self._handler(args[0] if args else None, fn)
        if h.type == "pointer_expression":
            h = h.child_by_field_name("argument")
        if h is not None and h.type == "qualified_identifier":
            qual, name = _t(h).rsplit("::", 1)
            hit = self.m.find(qual, fn.ns)
            return self.m.fun_in(hit, name) if hit else None
        if h is not None and h.type == "identifier":
            return self.m.free_fun(_t(h), fn.ns, fn.file) or (self.m.fun_in(fn.cls, _t(h)) if fn.cls else None)
        return None

    def _route(self, call, fn: CFun):
        f = call.child_by_field_name("function")
        args = _named(call.child_by_field_name("arguments"))
        line = call.start_point.row + 1
        if f is None:
            return
        ft = _t(f)
        # cpp-httplib: svr.Get("/p", handler) on a Server
        if f.type == "field_expression" and _t(f.child_by_field_name("field")) in VERBS and len(args) >= 2 and \
                _str(args[0]) is not None and not re.search(r"cli|client", _t(f.child_by_field_name("argument")), re.I):
            h = self._handler(args[-1], fn)
            if h is not None:
                self.routes.append((VERBS[_t(f.child_by_field_name("field"))], _str(args[0]), h, fn, line))
            return
        # Crow: CROW_ROUTE(app, "/p")[.methods(...)](handler)
        if f.type == "call_expression" and args:
            inner, methods = f, []
            if inner.child_by_field_name("function") is not None and \
                    inner.child_by_field_name("function").type == "field_expression" and \
                    _t(inner.child_by_field_name("function").child_by_field_name("field")) == "methods":
                methods = [(_str(a) or "").upper() for a in _named(inner.child_by_field_name("arguments"))]
                inner = inner.child_by_field_name("function").child_by_field_name("argument")
            if inner is not None and inner.type == "call_expression" and \
                    _t(inner.child_by_field_name("function")) in ("CROW_ROUTE", "CROW_BP_ROUTE", "CROW_WEBSOCKET_ROUTE"):
                rargs = _named(inner.child_by_field_name("arguments"))
                path = _str(rargs[1]) if len(rargs) > 1 else None
                h = self._handler(args[-1], fn)
                if path is not None and h is not None:
                    self.routes.append(("/".join(m for m in methods if m) or "GET", path, h, fn, line))
            return
        # Drogon: ADD_METHOD_TO(Ctrl::m, "/p", Get, ...), METHOD_ADD(Ctrl::m, "/p", Get); app().registerHandler(...)
        if ft in ("ADD_METHOD_TO", "METHOD_ADD", "PATH_ADD") and len(args) >= 2 and _str(args[1]) is not None:
            h = self._handler(args[0], fn)
            verbs = [VERBS.get(_t(a).split("::")[-1], "") for a in args[2:]]
            if h is not None:
                self.routes.append(("/".join(v for v in verbs if v) or "ANY", _str(args[1]), h, fn, line))
            return
        if ft.endswith("registerHandler") and len(args) >= 2 and _str(args[0]) is not None:
            verbs = [VERBS.get(w, "") for w in re.findall(r"\b(Get|Post|Put|Patch|Delete)\b",
                                                          " ".join(_t(a) for a in args[2:]))]
            h = self._handler(args[1], fn)
            if h is not None:
                self.routes.append(("/".join(v for v in verbs if v) or "ANY", _str(args[0]), h, fn, line))
            return
        # Pistache: Routes::Get(router, "/p", Routes::bind(&C::m, this))
        m = re.match(r"(?:Pistache::Rest::)?Routes::(Get|Post|Put|Patch|Delete|Options)$", ft)
        if m and len(args) >= 3 and _str(args[1]) is not None:
            h = self._handler(args[2], fn)
            if h is not None:
                self.routes.append((VERBS[m.group(1)], _str(args[1]), h, fn, line))

    def _http(self, call, fn: CFun, env: dict):
        f = call.child_by_field_name("function")
        args = _named(call.child_by_field_name("arguments"))
        if f is None or not args:
            return
        raw, method = None, "GET"
        if _t(f) == "curl_easy_setopt" and len(args) >= 3 and _t(args[1]) == "CURLOPT_URL":
            raw = _str(args[2])
        elif f.type == "field_expression" and _t(f.child_by_field_name("field")) in VERBS:
            recv = f.child_by_field_name("argument")
            typ = env.get(_t(recv), "") if recv is not None else ""
            if "Client" in typ or re.search(r"cli|client", _t(recv), re.I):
                raw, method = _str(args[0]), VERBS[_t(f.child_by_field_name("field"))]
        if not raw:
            return
        from .java_frontend import _normalize
        norm = _normalize(raw, False)
        if norm:
            path, host, pu = norm
            self.http.append({"src": fn.id, "method": method, "path": path, "raw": raw, "prefix_unknown": pu,
                              "host": host, "line": call.start_point.row + 1, "ui": None, "file": fn.file})


def add_cpp(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    paths = discover(repo)
    if not paths:
        return {}
    try:
        c_parser, cpp_parser = _parsers()
    except ImportError:
        g.meta.setdefault("skipped_languages", []).append("c/c++ (pip install tree-sitter-c tree-sitter-cpp)")
        return {}
    has_cpp = any(p.suffix.lower() in CPP_EXTS - {".h"} for p in paths)
    model = Model()
    texts: dict[str, str] = {}
    files = []
    total = 0
    for p in paths:
        try:
            src = project_bytes(p, repo)
        except OSError:
            continue
        if len(src) > MAX_BYTES:
            continue
        rel = p.relative_to(repo).as_posix()
        is_c = p.suffix.lower() == ".c" or (p.suffix.lower() == ".h" and not has_cpp)
        root = (c_parser if is_c else cpp_parser).parse(src).root_node
        lines = src.count(b"\n") + 1
        total += lines
        Collector(model, rel, is_c).walk(_named(root), "", None)
        files.append((rel, lines))
        texts[rel] = src.decode("utf-8", "replace")

    for rel, lines in files:
        mid = f"cc:{rel}"
        g.add_node(Node(id=mid, kind=MODULE, name=Path(rel).name, qualname=rel, file=rel, start_line=1, end_line=lines))
        if TEST_FILE_RE.search(rel):
            g.nodes[mid].entry = {"kind": "test", "detail": rel}
    for c in model.classes.values():
        outer = c.id.rsplit(".", 1)[0] if "." in c.id else None
        parent = f"cc:{outer}" if outer in model.classes else f"cc:{c.file}"
        bases = f" : {', '.join(c.bases)}" if c.bases else ""
        g.add_node(Node(id=f"cc:{c.id}", kind=CLASS, name=c.short, qualname=c.id.replace(".", "::"), file=c.file,
                        start_line=c.start, end_line=c.end, parent=parent, signature=f"{c.kind} {c.short}{bases}"[:200]))
        g.add_edge(parent, f"cc:{c.id}", kind=CONTAINS)
    for fid, fn in model.funs.items():
        parent = f"cc:{fn.cls}" if fn.cls and fn.cls in model.classes else f"cc:{fn.file}"
        g.add_node(Node(id=fid, kind=CALLABLE, name=fn.name, qualname=fid[3:].replace(".", "::"), file=fn.file,
                        start_line=fn.start, end_line=fn.end, parent=parent, fingerprint=fn.fingerprint,
                        signature=fn.signature))
        g.add_edge(parent, fid, kind=CONTAINS)
        if "::" in fid and fid.split("::", 1)[1].split(" ", 1)[0] in TEST_MACROS:
            g.nodes[fid].entry = {"kind": "test", "detail": fn.file}
        elif fn.name == "main" and fn.cls is None and not fn.ns:
            g.nodes[fid].entry = {"kind": "main", "detail": f"program start ({fn.file})"}
        elif TEST_FILE_RE.search(fn.file):
            g.nodes[fid].entry = {"kind": "test", "detail": fn.file}

    link = Linker(model)
    edges = 0

    def add_refs(src_id, refs):
        nonlocal edges
        for r in refs:
            if r.target.startswith("ext:"):
                g.external(r.target[4:])
            elif r.target not in g.nodes or r.target == src_id:
                continue
            g.add_edge(src_id, r.target, kind=CALLS, confidence=RESOLVED, line=r.line, via=r.via)
            edges += 1

    for fid, fn in list(model.funs.items()):
        body = fn.node.child_by_field_name("body")
        before = len(link.routes)
        env = dict(fn.params)
        add_refs(fid, link.walk(body, fn, env, set()))
        # route lambdas become their own nodes; their calls move from the enclosing function to them
        for verb, path, h, _owner, _line in link.routes[before:]:
            detail = f"{verb} {path}"
            if isinstance(h, str):
                if h in g.nodes and not (g.nodes[h].entry and g.nodes[h].entry.get("kind") == "route"):
                    g.nodes[h].entry = {"kind": "route", "detail": detail}
                continue
            lid = f"cc:{fn.file}::{detail}"
            plist = h.child_by_field_name("declarator")
            sig = f"[](){'' if plist is None else ' ' + _t(plist)}"
            lfn = CFun(id=lid, name=detail, cls=fn.cls, ns=fn.ns, file=fn.file, start=h.start_point.row + 1,
                       end=h.end_point.row + 1, signature=re.sub(r"\s+", " ", _t(plist) if plist is not None else "()")[:200],
                       fingerprint=hashlib.sha1(h.text, usedforsecurity=False).hexdigest()[:12], node=h,
                       params=_params(plist.child_by_field_name("parameters")) if plist is not None else {})
            g.add_node(Node(id=lid, kind=CALLABLE, name=detail, qualname=f"{fn.file}::{detail}", file=fn.file,
                            start_line=lfn.start, end_line=lfn.end, parent=f"cc:{fn.file}",
                            fingerprint=lfn.fingerprint, signature=lfn.signature or sig))
            g.add_edge(f"cc:{fn.file}", lid, kind=CONTAINS)
            g.nodes[lid].entry = {"kind": "route", "detail": detail}
            lenv = dict(env)
            lenv.update(lfn.params)
            add_refs(lid, link.walk(h.child_by_field_name("body"), lfn, lenv, set()))

    # Drogon controllers declare their routes in the class body: ADD_METHOD_TO(Ctrl::m, "/p", Get, Post)
    for text in texts.values():
        for m in DROGON_RE.finditer(text):
            qual, _, name = m.group(2).rpartition("::")
            hit = model.find(qual, "") if qual else None
            fid = model.fun_in(hit, name) if hit else None
            if fid and fid in g.nodes and not g.nodes[fid].entry:
                verbs = [VERBS.get(w.strip().split("::")[-1], "") for w in (m.group(4) or "").split(",")]
                g.nodes[fid].entry = {"kind": "route", "detail": f"{'/'.join(v for v in verbs if v) or 'ANY'} {m.group(3)}"}
                link.routes.append(None)
    g.meta.setdefault("http_calls", []).extend(link.http)
    for key, n in model.unresolved.items():
        g.unresolved[key[:120]] = g.unresolved.get(key[:120], 0) + n
    return {"files": len(files), "lines": total, "classes": len(model.classes), "functions": len(model.funs),
            "routes": len(link.routes), "http_calls": len(link.http), "unresolved": sum(model.unresolved.values())}
