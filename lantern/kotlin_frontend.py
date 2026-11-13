"""Kotlin: Android apps and Kotlin servers, mapped like the Java reader maps Java.

Node ids: class `kt:<package>.<Class>` (nested `Outer.Inner`, a companion's functions belong to the class), method
`kt:<package>.<Class>.<fun>`, top-level function `kt:<package>.<fun>`, file module `kt:<path>.kt`. Overloads share one
node, like Java.

Calls are resolved by:
  * `name`          `helper()` → a function of the same class (or a class it extends in the repo), else a top-level
                    function of the same package
  * `import`        `doThing()` / `Util.f()` through an explicit import, or a top-level function of an imported package
  * `this`          `this.helper()`
  * `assoc`         `Util.f()`, `Repo.make()`: an `object`, or a class's companion
  * `receiver-type` `repo.load()` where `repo` is a parameter, a constructor property, a property or a local whose type
                    is written (`val r: Repo`) or comes from a constructor call (`val r = Repo()`) or from a repo
                    function's written return type
  * `interface`     the receiver's type is an interface or abstract class in the repo: one `possible` edge to each
                    class that implements it
  * `callback`      a function reference `::helper` / `this::helper`
Calls on library types become `ext:<Type>.<fun>` nodes (`ext:Log.d`); a receiver whose type is unknown is counted in
`graph.unresolved`. Lambdas belong to the function they are written in. Entries: `fun main`, `@Test` functions and test
files, Spring routes (`@RequestMapping` on the class + `@GetMapping`…), Jetpack Compose screens (`@Composable fun
…Screen`, a `page`). Android entry points come from the manifest
(`android.add_entries`), the same way as for Java.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import deep
from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import inside_repo, project_bytes, skipped

MAX_BYTES = 1_500_000
TEST_FILE_RE = re.compile(r"(^|/)src/(test|androidTest|sharedTest|commonTest|jvmTest)\w*/|(^|/)tests?/")
ROUTE_ANN = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "PatchMapping": "PATCH",
             "DeleteMapping": "DELETE", "RequestMapping": "ANY"}
KOTLIN_BUILTINS = {"println", "print", "require", "check", "error", "listOf", "mutableListOf", "mapOf", "mutableMapOf",
                   "setOf", "mutableSetOf", "arrayOf", "emptyList", "emptyMap", "lazy", "run", "let", "apply", "also",
                   "with", "repeat", "requireNotNull", "checkNotNull", "TODO", "maxOf", "minOf", "buildList",
                   "buildString", "launch", "async", "runBlocking", "withContext", "remember", "mutableStateOf"}


def _parser():
    import tree_sitter as ts
    import tree_sitter_kotlin as tk
    return ts.Parser(ts.Language(tk.language()))


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _kid(n, *types):
    return next((c for c in n.children if c.type in types), None)


def _kids(n, *types):
    return [c for c in n.children if c.type in types]


def _type_name(n) -> str | None:
    """`Repo`, `Repo?`, `a.b.Repo<T>` → the last simple name ("Repo")."""
    if n is None:
        return None
    if n.type in ("nullable_type", "parenthesized_type", "type"):
        inner = next((c for c in n.children if c.is_named), None)
        return _type_name(inner)
    if n.type == "user_type":
        ids = _kids(n, "identifier", "type_identifier")
        return _t(ids[-1]) if ids else None
    return None


def _annotations(n) -> list:
    mods = _kid(n, "modifiers")
    return _kids(mods, "annotation") if mods is not None else []


def _ann_name(a) -> str:
    ci = _kid(a, "constructor_invocation")
    ut = _kid(ci, "user_type") if ci is not None else _kid(a, "user_type")
    return _type_name(ut) or ""


def _ann_string(a) -> str | None:
    ci = _kid(a, "constructor_invocation")
    args = _kid(ci, "value_arguments") if ci is not None else None
    for va in _kids(args, "value_argument") if args is not None else []:
        s = _kid(va, "string_literal")
        if s is not None and not _kids(s, "interpolation", "string_template_expression", "line_string_expression"):
            return "".join(_t(c) for c in s.children if c.type == "string_content")
    return None


@dataclass
class KFun:
    name: str
    cls: str | None            # local class name, None = top level
    file: str
    start: int
    end: int
    signature: str
    fingerprint: str
    params: dict[str, str] = field(default_factory=dict)
    returns: str | None = None
    route: tuple[str, str] | None = None
    is_test: bool = False
    composable: bool = False
    nodes: list = field(default_factory=list)      # the function_declaration nodes (overloads)


@dataclass
class KClass:
    name: str                  # "Outer.Inner"
    file: str
    start: int
    end: int
    kind: str                  # class | interface | object | enum | abstract
    supers: list[str] = field(default_factory=list)
    props: dict[str, str] = field(default_factory=dict)
    route_prefix: str = ""
    funs: set[str] = field(default_factory=set)


@dataclass
class KFile:
    rel: str
    pkg: str
    lines: int
    imports: dict[str, str] = field(default_factory=dict)    # simple name -> fq name
    star: list[str] = field(default_factory=list)             # packages imported with .*
    is_test: bool = False


class Model:
    left = None     # (map, reader) once the reader has a map: where a piece that was not read is written down

    def __init__(self):
        self.classes: dict[tuple[str, str], KClass] = {}       # (pkg, local) -> class
        self.funs: dict[tuple[str, str], KFun] = {}            # (pkg, "Class.f" or "f") -> fun
        self.unresolved: dict[str, int] = {}

    def class_by_fq(self, fq: str) -> tuple[str, KClass] | None:
        pkg, _, name = fq.rpartition(".")
        while pkg is not None:
            c = self.classes.get((pkg, name))
            if c:
                return pkg, c
            if "." not in pkg:
                break
            pkg, _, head = pkg.rpartition(".")
            name = f"{head}.{name}"
        return None

    def find_class(self, f: KFile, cls: KClass | None, name: str) -> tuple[str, KClass] | None:
        if not name:
            return None
        if cls is not None:   # nested in the current class, or a sibling nested class
            for cand in (f"{cls.name}.{name}", f"{cls.name.rsplit('.', 1)[0]}.{name}" if "." in cls.name else None):
                if cand and (f.pkg, cand) in self.classes:
                    return f.pkg, self.classes[(f.pkg, cand)]
        if name in f.imports:
            hit = self.class_by_fq(f.imports[name])
            if hit:
                return hit
        if (f.pkg, name) in self.classes:
            return f.pkg, self.classes[(f.pkg, name)]
        for sp in f.star:
            if (sp, name) in self.classes:
                return sp, self.classes[(sp, name)]
        return None

    def fun_in(self, f: KFile, pkg: str, c: KClass, name: str, depth: int = 0) -> tuple[str, str] | None:
        """(pkg, "Class.f") for `name` on class `c` or a repo class it extends."""
        if name in c.funs:
            return pkg, f"{c.name}.{name}"
        if depth > 6:
            return None
        for s in c.supers:
            hit = self.find_class(f, None, s) or ((pkg, self.classes[(pkg, s)]) if (pkg, s) in self.classes else None)
            if hit and hit[1] is not c:
                r = self.fun_in(f, hit[0], hit[1], name, depth + 1)
                if r:
                    return r
        return None

    def implementers(self, pkg: str, c: KClass) -> list[tuple[str, KClass]]:
        return [(p, k) for (p, _), k in self.classes.items() if c.name.split(".")[-1] in k.supers and k is not c
                and k.kind != "interface"]


def nid(pkg: str, local: str) -> str:
    return f"kt:{pkg}.{local}" if pkg else f"kt:{local}"


def discover(repo: Path) -> list[Path]:
    out = []
    for p in repo.rglob("*.kt"):
        rel = p.relative_to(repo)
        if skipped(rel.parts[:-1], repo) or not p.is_file() or not inside_repo(p, repo):
            continue
        out.append(p)
    return sorted(out)


def _collect(model: Model, f: KFile, root) -> None:
    def walk(n, outer: KClass | None):
        for c in n.children:
            try:
                if c.type == "class_declaration" or c.type == "object_declaration":
                    _class(c, outer)
                elif c.type == "companion_object" and outer is not None:
                    body = _kid(c, "class_body")
                    if body is not None:
                        walk(body, outer)                  # a companion's functions belong to the class
                elif c.type == "function_declaration":
                    _fun(c, outer)
                elif c.type in ("ERROR", "class_body", "enum_class_body", "statements"):
                    walk(c, outer)
            except RecursionError:
                # declared inside more declarations than this walk follows: left where it stands and written down
                deep.leave(model.left, f.rel, c)

    def _class(c, outer):
        name_n = _kid(c, "identifier", "type_identifier")
        if name_n is None:
            return
        local = f"{outer.name}.{_t(name_n)}" if outer else _t(name_n)
        kws = {ch.type for ch in c.children}
        mods = _t(_kid(c, "modifiers")) if _kid(c, "modifiers") is not None else ""
        kind = ("interface" if "interface" in kws else "object" if c.type == "object_declaration"
                else "enum" if re.search(r"\benum\b", mods) else "abstract" if re.search(r"\b(abstract|sealed)\b", mods)
                else "class")
        k = KClass(name=local, file=f.rel, start=c.start_point.row + 1, end=c.end_point.row + 1, kind=kind)
        ds = _kid(c, "delegation_specifiers")
        for spec in _kids(ds, "delegation_specifier") if ds is not None else []:
            ci = _kid(spec, "constructor_invocation")
            tn = _type_name(_kid(ci, "user_type") if ci is not None else _kid(spec, "user_type"))
            if tn:
                k.supers.append(tn)
        pc = _kid(c, "primary_constructor")
        cps = _kid(pc, "class_parameters") if pc is not None else None
        for cp in _kids(cps, "class_parameter") if cps is not None else []:
            if _kid(cp, "val", "var") is None and not any(ch.type in ("val", "var") for ch in cp.children):
                continue
            pn, tn = _kid(cp, "identifier"), _type_name(next((ch for ch in cp.children if ch.type in
                                                              ("user_type", "nullable_type")), None))
            if pn is not None and tn:
                k.props[_t(pn)] = tn
        for a in _annotations(c):
            if _ann_name(a) == "RequestMapping":
                k.route_prefix = (_ann_string(a) or "").rstrip("/")
        body = _kid(c, "class_body", "enum_class_body")
        if body is not None:
            for pd in _kids(body, "property_declaration"):
                vd = _kid(pd, "variable_declaration")
                if vd is None:
                    continue
                pn = _kid(vd, "identifier")
                tn = _type_name(next((ch for ch in vd.children if ch.type in ("user_type", "nullable_type")), None))
                if tn is None:
                    call = _kid(pd, "call_expression")
                    callee = call.children[0] if call is not None and call.children else None
                    if callee is not None and callee.type == "identifier" and _t(callee)[:1].isupper():
                        tn = _t(callee)
                if pn is not None and tn:
                    k.props[_t(pn)] = tn
        model.classes[(f.pkg, local)] = k
        if body is not None:
            walk(body, k)

    def _fun(c, cls: KClass | None):
        name_n = _kid(c, "identifier", "simple_identifier")
        if name_n is None:
            return
        name = _t(name_n)
        local = f"{cls.name}.{name}" if cls else name
        params = {}
        fvp = _kid(c, "function_value_parameters")
        for prm in _kids(fvp, "parameter") if fvp is not None else []:
            pn = _kid(prm, "identifier")
            tn = _type_name(next((ch for ch in prm.children if ch.type in ("user_type", "nullable_type")), None))
            if pn is not None:
                params[_t(pn)] = tn or ""
        ret = None
        seen_params = False
        for ch in c.children:
            if ch.type == "function_value_parameters":
                seen_params = True
            elif seen_params and ch.type in ("user_type", "nullable_type"):
                ret = _type_name(ch)
                break
        anns = _annotations(c)
        route = None
        for a in anns:
            an = _ann_name(a)
            if an in ROUTE_ANN:
                route = (ROUTE_ANN[an], _ann_string(a) or "")
        is_test = any(_ann_name(a) == "Test" for a in anns)
        composable = any(_ann_name(a) == "Composable" for a in anns)
        body = _kid(c, "function_body")
        sig_end = body.start_byte if body is not None else c.end_byte
        sig = c.text[: sig_end - c.start_byte].decode("utf-8", "replace")
        sig = re.sub(r"\s+", " ", re.sub(r"^\s*(@\w+(\([^)]*\))?\s*)+", "", sig)).strip()
        fp = hashlib.sha1(c.text, usedforsecurity=False).hexdigest()[:12]
        key = (f.pkg, local)
        if key in model.funs:
            fn = model.funs[key]
            fn.nodes.append(c)
            fn.end = max(fn.end, c.end_point.row + 1)
            fn.params.update(params)
            return
        model.funs[key] = KFun(name=name, cls=cls.name if cls else None, file=f.rel, start=c.start_point.row + 1,
                               end=c.end_point.row + 1, signature=sig[:200], fingerprint=fp, params=params, returns=ret,
                               route=route, is_test=is_test or f.is_test, composable=composable,
                               nodes=[c])
        if cls is not None:
            cls.funs.add(name)

    walk(root, None)


@dataclass
class Ref:
    target: str
    line: int
    confidence: str
    via: str
    kind: str = "call"


class Linker:
    left = None     # (map, "kotlin") once the reader has a map: where a piece that was not read is written down

    def __init__(self, model: Model):
        self.m = model
        self.top: dict[tuple[str, str], KFun] = {k: v for k, v in model.funs.items() if v.cls is None}

    def _top_fun(self, f: KFile, name: str) -> tuple[str, str, str] | None:
        if (f.pkg, name) in self.top:
            return f.pkg, name, "name"
        if name in f.imports:
            fq = f.imports[name]
            pkg = fq.rpartition(".")[0]
            if (pkg, name) in self.top:
                return pkg, name, "import"
        for sp in f.star:
            if (sp, name) in self.top:
                return sp, name, "import"
        return None

    def _type_of(self, f: KFile, cls: KClass | None, env: dict[str, str], e) -> str | None:
        """The simple type name of an expression, when it is known."""
        if e is None:
            return None
        if e.type == "identifier":
            n = _t(e)
            if n in env:
                return env[n] or None
            if cls is not None:
                c = cls
                while c is not None:
                    if n in c.props:
                        return c.props[n]
                    c = self.m.classes.get((f.pkg, c.name.rsplit(".", 1)[0])) if "." in c.name else None
            return None
        if e.type == "this_expression":
            return cls.name.split(".")[-1] if cls else None
        if e.type == "call_expression" and e.children:
            callee = e.children[0]
            if callee.type == "identifier" and _t(callee)[:1].isupper():
                return _t(callee)
            if callee.type == "navigation_expression":
                hit = self._nav_target(f, cls, env, callee)
                if hit and hit[0] and not hit[0].startswith("ext:"):
                    fn = self.m.funs.get(hit[2])
                    return fn.returns if fn else None
            if callee.type == "identifier":
                tf = self._top_fun(f, _t(callee))
                if tf:
                    return self.top[(tf[0], tf[1])].returns
                if cls is not None:
                    r = self.m.fun_in(f, f.pkg, cls, _t(callee))
                    if r:
                        return self.m.funs[r].returns
        if e.type in ("parenthesized_expression",):
            inner = next((c for c in e.children if c.is_named), None)
            return self._type_of(f, cls, env, inner)
        return None

    def _nav_target(self, f: KFile, cls: KClass | None, env, nav):
        """(target id, via, (pkg, local) of the repo function, confidence, extra targets) for `recv.name`."""
        named = [c for c in nav.children if c.is_named]
        if len(named) < 2:
            return None
        recv, name_n = named[0], named[-1]
        name = _t(name_n)
        if recv.type == "super_expression":
            return ("", "super", None, None, [])
        if recv.type == "this_expression" and cls is not None:
            r = self.m.fun_in(f, f.pkg, cls, name)
            return (nid(*r), "this", r, RESOLVED, []) if r else None
        if recv.type == "identifier" and _t(recv) not in env and not (cls and _t(recv) in cls.props):
            hit = self.m.find_class(f, cls, _t(recv))
            if hit:                                            # Util.f(), Repo.make() (object or companion)
                r = self.m.fun_in(f, hit[0], hit[1], name)
                return (nid(*r), "assoc", r, RESOLVED, []) if r else None
            if _t(recv)[:1].isupper():                         # Log.d(), TextUtils.isEmpty()
                return (f"ext:{_t(recv)}.{name}", "import", None, RESOLVED, [])
        tn = self._type_of(f, cls, env, recv)
        if tn:
            hit = self.m.find_class(f, cls, tn)
            if hit:
                pkg, k = hit
                r = self.m.fun_in(f, pkg, k, name)
                if k.kind in ("interface", "abstract"):
                    extra = []
                    for ipkg, impl in self.m.implementers(pkg, k):
                        ir = self.m.fun_in(f, ipkg, impl, name)
                        if ir:
                            extra.append(nid(*ir))
                    if extra:
                        return ("", "interface", None, POSSIBLE, extra)
                return (nid(*r), "receiver-type", r, RESOLVED, []) if r else None
            return (f"ext:{tn}.{name}", "receiver-type", None, RESOLVED, [])
        return (None, None, None, None, [])

    def walk(self, f: KFile, fn: KFun, src: str) -> list[Ref]:
        cls = self.m.classes.get((f.pkg, fn.cls)) if fn.cls else None
        refs: list[Ref] = []
        for node in fn.nodes:
            env = dict(fn.params)
            body = _kid(node, "function_body")
            if body is not None:
                self._walk(f, cls, body, env, refs, src)
        return refs

    def _walk(self, f, cls, n, env, refs, src):
        stack = [n]
        while stack:
            x = stack.pop()
            try:
                if x.type == "property_declaration":
                    vd = _kid(x, "variable_declaration")
                    pn = _kid(vd, "identifier") if vd is not None else None
                    if pn is not None:
                        tn = _type_name(next((ch for ch in vd.children if ch.type in ("user_type", "nullable_type")), None))
                        if tn is None:
                            val = next((ch for ch in x.children if ch.is_named and ch.type not in
                                        ("variable_declaration", "modifiers")), None)
                            tn = self._type_of(f, cls, env, val)
                        env[_t(pn)] = tn or ""
                elif x.type == "call_expression" and x.children:
                    self._call(f, cls, x, env, refs, src)
                elif x.type == "callable_reference":
                    ids = _kids(x, "identifier")
                    if ids and cls is not None and len(ids) == 1:
                        r = self.m.fun_in(f, f.pkg, cls, _t(ids[-1]))
                        if r:
                            refs.append(Ref(nid(*r), x.start_point.row + 1, INFERRED, "callback", "callback"))
                    elif ids and len(ids) == 1:
                        tf = self._top_fun(f, _t(ids[0]))
                        if tf:
                            refs.append(Ref(nid(tf[0], tf[1]), x.start_point.row + 1, INFERRED, "callback", "callback"))
                elif x.type in ("class_declaration", "object_declaration", "function_declaration") and x is not n:
                    continue                                         # a local class or function is its own scope
            except RecursionError:
                # nested deeper than the lookup follows: left with all that is written in it, and written down
                deep.leave(self.left, f.rel, x, env, kinds=("identifier", "simple_identifier"), blank="")
                continue
            stack.extend(reversed(x.children))

    def _call(self, f, cls, x, env, refs, src):
        callee = x.children[0]
        line = x.start_point.row + 1
        if callee.type == "identifier":
            name = _t(callee)
            if cls is not None:
                r = self.m.fun_in(f, f.pkg, cls, name)
                if r:
                    refs.append(Ref(nid(*r), line, RESOLVED, "name"))
                    return
            tf = self._top_fun(f, name)
            if tf:
                refs.append(Ref(nid(tf[0], tf[1]), line, RESOLVED, tf[2]))
                return
            hit = self.m.find_class(f, cls, name)
            if hit:                                              # a constructor: the class's init runs
                init = self.m.fun_in(f, hit[0], hit[1], "init")
                if init:
                    refs.append(Ref(nid(*init), line, RESOLVED, "constructor"))
            return
        if callee.type == "navigation_expression":
            res = self._nav_target(f, cls, env, callee)
            if res is None:
                return
            target, via, _r, conf, extra = res
            if via == "super":
                return
            if target:
                refs.append(Ref(target, line, conf or RESOLVED, via))
            for t in extra:
                refs.append(Ref(t, line, POSSIBLE, via))
            if target is None and not extra:
                named = [c for c in callee.children if c.is_named]
                key = f"{src}: {_t(named[0])[:40]}.{_t(named[-1])}"
                self.m.unresolved[key] = self.m.unresolved.get(key, 0) + 1


def add_kotlin(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    paths = discover(repo)
    if not paths:
        return {}
    try:
        parser = _parser()
    except ImportError:
        g.meta.setdefault("skipped_languages", []).append("kotlin (pip install tree-sitter-kotlin)")
        return {}
    model = Model()
    model.left = (g, "kotlin")
    files: list[tuple[KFile, object]] = []      # trees kept alive for as long as their nodes are used
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
        ph = _kid(root, "package_header")
        pkg = _t(_kid(ph, "qualified_identifier", "identifier")) if ph is not None else ""
        lines = src.count(b"\n") + 1
        total += lines
        f = KFile(rel=rel, pkg=pkg, lines=lines, is_test=bool(TEST_FILE_RE.search(rel)))
        for imp in root.children:
            if imp.type not in ("import", "import_header"):
                continue
            q = _kid(imp, "qualified_identifier", "identifier")
            text = _t(imp)
            if q is None:
                continue
            fq = _t(q)
            if re.search(r"\.\*\s*$", text) or text.rstrip().endswith("*"):
                f.star.append(fq)
            else:
                alias = re.search(r"\bas\s+(\w+)\s*$", text)
                f.imports[alias.group(1) if alias else fq.rsplit(".", 1)[-1]] = fq
        files.append((f, tree))
        deep.whole(model.left, f.rel, _collect, model, f, root)

    by_rel = {f.rel: f for f, _ in files}
    for f, _ in files:
        g.add_node(Node(id=f"kt:{f.rel}", kind=MODULE, name=Path(f.rel).name, qualname=f.rel, file=f.rel,
                        start_line=1, end_line=f.lines))
        if f.is_test:
            g.nodes[f"kt:{f.rel}"].entry = {"kind": "test", "detail": f.rel}
    for (pkg, local), c in model.classes.items():
        cid = nid(pkg, local)
        parent = nid(pkg, local.rsplit(".", 1)[0]) if "." in local else f"kt:{c.file}"
        g.add_node(Node(id=cid, kind=CLASS, name=local.split(".")[-1], qualname=cid[3:], file=c.file, start_line=c.start,
                        end_line=c.end, parent=parent, signature=f"{c.kind} {local}"))
        g.add_edge(parent, cid, kind=CONTAINS)
    for (pkg, local), fn in model.funs.items():
        mid = nid(pkg, local)
        parent = nid(pkg, fn.cls) if fn.cls else f"kt:{fn.file}"
        sig = fn.signature + (f"  (+{len(fn.nodes) - 1} overload{'s' if len(fn.nodes) > 2 else ''})"
                              if len(fn.nodes) > 1 else "")
        g.add_node(Node(id=mid, kind=CALLABLE, name=fn.name, qualname=mid[3:], file=fn.file, start_line=fn.start,
                        end_line=fn.end, parent=parent, fingerprint=fn.fingerprint, signature=sig[:200],
                        decorators=[f"@{fn.route[0]} {fn.route[1]}"] if fn.route else []))
        g.add_edge(parent, mid, kind=CONTAINS)
    link = Linker(model)
    link.left = (g, "kotlin")
    edges = 0
    for (pkg, local), fn in model.funs.items():
        src = nid(pkg, local)
        for r in link.walk(by_rel[fn.file], fn, src):
            if r.target.startswith("ext:"):
                g.external(r.target[4:])
            elif r.target not in g.nodes or r.target == src:
                continue
            g.add_edge(src, r.target, kind=CALLS, confidence=r.confidence, line=r.line, via=r.via)
            edges += 1
    for key, n in model.unresolved.items():
        g.unresolved[key[:120]] = g.unresolved.get(key[:120], 0) + n
    routes = 0
    for (pkg, local), fn in model.funs.items():
        node = g.nodes.get(nid(pkg, local))
        if node is None:
            continue
        if fn.name == "main" and fn.cls is None:
            node.entry = {"kind": "main", "detail": f"program start ({fn.file})"}
        elif fn.is_test and (fn.cls is None or fn.name[:1].islower()):
            if by_rel[fn.file].is_test or fn.is_test:
                node.entry = {"kind": "test", "detail": fn.file}
        elif fn.composable and fn.name.endswith("Screen") and len(fn.name) > 6 and not by_rel[fn.file].is_test:
            # Jetpack Compose draws each screen as a function: `@Composable fun GardenScreen(...)`
            node.entry = {"kind": "page", "detail": f"{fn.name[:-6]} screen (Compose) · {fn.name}"}
        if fn.route:
            verb, path = fn.route
            prefix = model.classes[(pkg, fn.cls)].route_prefix if fn.cls and (pkg, fn.cls) in model.classes else ""
            full = (prefix + path) if path and path != "/" else (prefix or path or "/")
            node.entry = {"kind": "route", "detail": f"{verb} {full if full.startswith('/') else '/' + full}"}
            routes += 1
    return {"files": len(files), "lines": total, "classes": len(model.classes), "functions": len(model.funs),
            "routes": routes, "unresolved": sum(model.unresolved.values())}
