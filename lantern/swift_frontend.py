"""Swift: iOS apps and Swift servers, mapped like the Kotlin reader maps Kotlin.

Swift has no packages inside a target, so a type is named by itself. Node ids: type `sw:<Type>` (nested
`Outer.Inner`), method `sw:<Type>.<func>` (initialisers are `Type.init`, a computed property such as SwiftUI's `body` is a
function of its type), top-level function `sw:<func>`, file module `sw:<path>.swift`. An `extension` adds its functions
to the type it extends; a type from a library that the repo extends gets a node of its own (`extension String`).
Overloads (and functions that differ only by argument labels) share one node.

Calls are resolved by:
  * `name`          `helper()` → a function of the same type (or a repo type it inherits from), else a top-level function
  * `self`          `self.helper()`
  * `assoc`         `Store.make()` / `Store.shared` statics
  * `receiver-type` `store.load()` where `store` is a parameter, a property or a local whose type is written
                    (`let s: Store`) or comes from an initialiser (`Store()`) or a repo function's written return type
  * `interface`     the receiver's type is a protocol in the repo: one `possible` edge to each type that adopts it
  * `constructor`   `Store()` runs `Store.init`
  * `callback`      a method passed by name (`Button("Go", action: refresh)`, `#selector(refresh)`)
  * `swiftui-body`  `EntryView(id: e)` inside a view: SwiftUI runs `EntryView.body` to draw it (`inferred`)
Calls on library types become `ext:<Type>.<func>` nodes (`ext:URLSession.dataTask`); a receiver whose type is unknown is
counted in `graph.unresolved`. Closures belong to the function they are written in.

Entries: `@main` (the app's start), XCTest `test…` methods and test targets, Vapor routes (`app.get("p", use: h)`). iOS
screens and links are added by `ios.add_entries`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import SKIP_DIRS, inside_repo

MAX_BYTES = 1_500_000
SKIP_SWIFT = {"Pods", "Carthage", "DerivedData", ".build", "SourcePackages"}
TEST_FILE_RE = re.compile(r"(^|/)[^/]*(Tests|UITests|Specs)/|(^|/)Tests?/")
VAPOR_VERBS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE"}


def _parser():
    import tree_sitter as ts
    import tree_sitter_swift as sw
    return ts.Parser(ts.Language(sw.language()))


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _kid(n, *types):
    return next((c for c in n.children if c.type in types), None) if n is not None else None


def _kids(n, *types):
    return [c for c in n.children if c.type in types] if n is not None else []


TYPE_NODES = ("user_type", "optional_type", "implicitly_unwrapped_type", "opaque_type", "existential_type")


def _type_name(n) -> str | None:
    """`Store`, `Store?`, `some View`, `any Store`, `Module.Store<T>` → the last simple name."""
    if n is None:
        return None
    if n.type == "user_type":
        ids = _kids(n, "type_identifier")
        return _t(ids[-1]) if ids else None
    if n.type in TYPE_NODES or n.type == "type_annotation":
        inner = next((c for c in n.children if c.type in TYPE_NODES), None)
        return _type_name(inner)
    return None


def _attributes(n) -> list[str]:
    mods = _kid(n, "modifiers")
    return [_type_name(_kid(a, "user_type")) or "" for a in _kids(mods, "attribute")]


@dataclass
class SFun:
    name: str
    cls: str | None
    file: str
    start: int
    end: int
    signature: str
    fingerprint: str
    params: dict[str, str] = field(default_factory=dict)
    returns: str | None = None
    attrs: list[str] = field(default_factory=list)
    is_test: bool = False
    nodes: list = field(default_factory=list)


@dataclass
class SType:
    name: str
    file: str
    start: int
    end: int
    kind: str                       # class | struct | enum | actor | protocol | extension
    supers: list[str] = field(default_factory=list)
    props: dict[str, str] = field(default_factory=dict)
    funs: set[str] = field(default_factory=set)
    attrs: list[str] = field(default_factory=list)


@dataclass
class SFile:
    rel: str
    lines: int
    is_test: bool = False


class Model:
    def __init__(self):
        self.types: dict[str, SType] = {}
        self.funs: dict[str, SFun] = {}           # "Type.f" or "f"
        self.unresolved: dict[str, int] = {}

    def find_type(self, cls: SType | None, name: str) -> SType | None:
        if not name:
            return None
        if cls is not None:
            for cand in (f"{cls.name}.{name}", f"{cls.name.rsplit('.', 1)[0]}.{name}" if "." in cls.name else None):
                if cand and cand in self.types:
                    return self.types[cand]
        return self.types.get(name)

    def fun_in(self, t: SType, name: str, depth: int = 0) -> str | None:
        if name in t.funs:
            return f"{t.name}.{name}"
        if depth > 6:
            return None
        for s in t.supers:
            sup = self.types.get(s)
            if sup is not None and sup is not t:
                r = self.fun_in(sup, name, depth + 1)
                if r:
                    return r
        return None

    def adopters(self, t: SType) -> list[SType]:
        short = t.name.split(".")[-1]
        return [k for k in self.types.values() if short in k.supers and k is not t and k.kind != "protocol"]


def nid(local: str) -> str:
    return f"sw:{local}"


def discover(repo: Path) -> list[Path]:
    out = []
    for p in repo.rglob("*.swift"):
        rel = p.relative_to(repo)
        if any(x in SKIP_DIRS or x in SKIP_SWIFT for x in rel.parts[:-1]) or not p.is_file() or not inside_repo(p, repo):
            continue
        out.append(p)
    return sorted(out)


def _signature(c) -> str:
    body = _kid(c, "function_body", "computed_property")
    end = body.start_byte if body is not None else c.end_byte
    sig = c.text[: end - c.start_byte].decode("utf-8", "replace")
    return re.sub(r"\s+", " ", re.sub(r"^\s*(@\w+(\([^)]*\))?\s*)+", "", sig)).strip()


def _params(c) -> dict[str, str]:
    out = {}
    for prm in _kids(c, "parameter"):
        names = _kids(prm, "simple_identifier")
        if names:
            out[_t(names[-1])] = _type_name(next((ch for ch in prm.children if ch.type in TYPE_NODES), None)) or ""
    return out


def _returns(c) -> str | None:
    seen = False
    for ch in c.children:
        if ch.type == "->":
            seen = True
        elif seen and ch.type in TYPE_NODES:
            return _type_name(ch)
    return None


def _collect(model: Model, f: SFile, root) -> None:
    def walk(n, outer: SType | None):
        for c in n.children:
            if c.type in ("class_declaration", "protocol_declaration"):
                _type(c, outer)
            elif c.type in ("function_declaration", "init_declaration", "protocol_function_declaration"):
                _fun(c, outer)
            elif c.type == "property_declaration" and outer is not None:
                _prop(c, outer)
            elif c.type in ("ERROR", "class_body", "enum_class_body", "protocol_body", "statements"):
                walk(c, outer)

    def _type(c, outer):
        kw = next((ch.type for ch in c.children if ch.type in ("class", "struct", "enum", "actor", "extension",
                                                                 "protocol")), "class")
        if kw == "extension":
            name = _type_name(_kid(c, "user_type"))
        else:
            name_n = _kid(c, "type_identifier")
            name = _t(name_n) if name_n is not None else None
        if not name:
            return
        local = f"{outer.name}.{name}" if outer is not None and kw != "extension" else name
        t = model.types.get(local)
        fresh = SType(name=local, file=f.rel, start=c.start_point.row + 1, end=c.end_point.row + 1, kind=kw,
                      attrs=_attributes(c))
        if t is None:
            t = model.types[local] = fresh
        elif t.kind == "extension" and kw != "extension":     # the real declaration wins over an extension seen first
            t.file, t.start, t.end, t.kind, t.attrs = fresh.file, fresh.start, fresh.end, kw, fresh.attrs
        for spec in _kids(c, "inheritance_specifier"):
            tn = _type_name(_kid(spec, "user_type"))
            if tn and tn not in t.supers:
                t.supers.append(tn)
        body = _kid(c, "class_body", "enum_class_body", "protocol_body")
        if body is not None:
            walk(body, t)

    def _prop(c, t: SType):
        pat = _kid(c, "pattern")
        pn = _kid(pat, "simple_identifier") if pat is not None else None
        if pn is None:
            return
        name = _t(pn)
        if _kid(c, "computed_property") is not None:          # `var body: some View { … }` runs code: a function
            _fun(c, t, name=name)
            return
        tn = _type_name(_kid(c, "type_annotation"))
        if tn is None:
            call = _kid(c, "call_expression")
            callee = call.children[0] if call is not None and call.children else None
            if callee is not None and callee.type == "simple_identifier" and _t(callee)[:1].isupper():
                tn = _t(callee)
        if tn:
            t.props[name] = tn

    def _fun(c, cls: SType | None, name: str | None = None):
        if name is None:
            if c.type == "init_declaration":
                name = "init"
            else:
                name_n = _kid(c, "simple_identifier")
                if name_n is None:
                    return
                name = _t(name_n)
        local = f"{cls.name}.{name}" if cls else name
        attrs = _attributes(c)
        fp = hashlib.sha1(c.text, usedforsecurity=False).hexdigest()[:12]
        if local in model.funs:
            fn = model.funs[local]
            fn.nodes.append(c)
            fn.params.update(_params(c))
            if fn.file == f.rel:
                fn.end = max(fn.end, c.end_point.row + 1)
            return
        model.funs[local] = SFun(name=name, cls=cls.name if cls else None, file=f.rel, start=c.start_point.row + 1,
                                 end=c.end_point.row + 1, signature=_signature(c)[:200], fingerprint=fp,
                                 params=_params(c), returns=_returns(c), attrs=attrs,
                                 is_test=f.is_test or (name.startswith("test") and cls is not None
                                                       and "XCTestCase" in cls.supers), nodes=[c])
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


def _nav_parts(nav):
    """(receiver node, member name) of `a.b`, `a?.b`, `self.b`."""
    suffix = [c for c in nav.children if c.type == "navigation_suffix"]
    recv = next((c for c in nav.children if c.is_named and c.type != "navigation_suffix"), None)
    if not suffix or recv is None:
        return None, None
    name = _kid(suffix[-1], "simple_identifier")
    return recv, (_t(name) if name is not None else None)


class Linker:
    def __init__(self, model: Model):
        self.m = model

    def _type_of(self, cls: SType | None, env: dict[str, str], e) -> str | None:
        if e is None:
            return None
        if e.type == "simple_identifier":
            n = _t(e)
            if n in env:
                return env[n] or None
            c = cls
            while c is not None:
                if n in c.props:
                    return c.props[n]
                c = self.m.types.get(c.name.rsplit(".", 1)[0]) if "." in c.name else None
            if n[:1].isupper() and self.m.find_type(cls, n) is not None:
                return n                                          # `Sync.shared`: the type itself (statics)
            return None
        if e.type == "self_expression":
            return cls.name.split(".")[-1] if cls else None
        if e.type == "navigation_expression":                    # self.store, a.b
            recv, name = _nav_parts(e)
            rt = self._type_of(cls, env, recv)
            t = self.m.find_type(cls, rt) if rt else None
            return t.props.get(name) if t is not None and name else None
        if e.type == "call_expression" and e.children:
            callee = e.children[0]
            if callee.type == "simple_identifier":
                n = _t(callee)
                if n[:1].isupper():
                    return n
                if cls is not None:
                    r = self.m.fun_in(cls, n)
                    if r:
                        return self.m.funs[r].returns
                if n in self.m.funs:
                    return self.m.funs[n].returns
            if callee.type == "navigation_expression":
                res = self._nav_target(cls, env, callee)
                if res and res[2]:
                    return self.m.funs[res[2]].returns
        if e.type in ("tuple_expression", "parenthesized_expression", "try_expression", "await_expression",
                      "force_unwrap_expression", "postfix_expression"):
            inner = next((c for c in e.children if c.is_named), None)
            return self._type_of(cls, env, inner)
        return None

    def _nav_target(self, cls: SType | None, env, nav):
        """(target id, via, repo function key, confidence, extra targets) for `recv.name(...)`."""
        recv, name = _nav_parts(nav)
        if recv is None or not name:
            return None
        if recv.type == "super_expression":
            return ("", "super", None, None, [])
        if recv.type == "self_expression" and cls is not None:
            r = self.m.fun_in(cls, name)
            return (nid(r), "self", r, RESOLVED, []) if r else None
        if recv.type == "simple_identifier" and _t(recv) not in env and not (cls and _t(recv) in cls.props):
            t = self.m.find_type(cls, _t(recv))
            if t is not None:                                     # Store.make(), static functions
                r = self.m.fun_in(t, name)
                return (nid(r), "assoc", r, RESOLVED, []) if r else None
            if _t(recv)[:1].isupper():                            # URLSession.shared, UserDefaults.standard
                return (f"ext:{_t(recv)}.{name}", "import", None, RESOLVED, [])
        tn = self._type_of(cls, env, recv)
        if tn:
            t = self.m.find_type(cls, tn)
            if t is not None:
                if t.kind == "protocol":
                    extra = [nid(r) for a in self.m.adopters(t) for r in [self.m.fun_in(a, name)] if r]
                    if extra:
                        return ("", "interface", None, POSSIBLE, extra)
                r = self.m.fun_in(t, name)
                return (nid(r), "receiver-type", r, RESOLVED, []) if r else None
            return (f"ext:{tn}.{name}", "receiver-type", None, RESOLVED, [])
        return (None, None, None, None, [])

    def walk(self, fn: SFun, src: str) -> list[Ref]:
        cls = self.m.types.get(fn.cls) if fn.cls else None
        refs: list[Ref] = []
        for node in fn.nodes:
            body = _kid(node, "function_body", "computed_property")
            if body is not None:
                self._walk(cls, body, dict(fn.params), refs, src)
        return refs

    def _walk(self, cls, n, env, refs, src):
        stack = [n]
        while stack:
            x = stack.pop()
            if x.type == "property_declaration":
                pat = _kid(x, "pattern")
                pn = _kid(pat, "simple_identifier") if pat is not None else None
                if pn is not None:
                    tn = _type_name(_kid(x, "type_annotation"))
                    if tn is None:
                        val = next((ch for ch in x.children if ch.is_named and ch.type not in
                                    ("value_binding_pattern", "pattern", "modifiers", "type_annotation")), None)
                        tn = self._type_of(cls, env, val)
                    env[_t(pn)] = tn or ""
            elif x.type == "call_expression" and x.children:
                self._call(cls, x, env, refs, src)
            elif x.type == "value_argument":
                val = [c for c in x.children if c.is_named and c.type != "value_argument_label"]
                if len(val) == 1 and val[0].type == "simple_identifier" and cls is not None \
                        and _t(val[0]) not in env:                # Button("Go", action: refresh)
                    r = self.m.fun_in(cls, _t(val[0]))
                    if r:
                        refs.append(Ref(nid(r), x.start_point.row + 1, INFERRED, "callback", "callback"))
            elif x.type == "selector_expression" and cls is not None:   # #selector(refresh)
                name = re.search(r"#selector\(\s*(?:self\.)?(\w+)", _t(x))
                r = self.m.fun_in(cls, name.group(1)) if name else None
                if r:
                    refs.append(Ref(nid(r), x.start_point.row + 1, INFERRED, "callback", "callback"))
            elif x.type in ("class_declaration", "function_declaration", "protocol_declaration") and x is not n:
                continue
            stack.extend(reversed(x.children))

    def _call(self, cls, x, env, refs, src):
        callee = x.children[0]
        line = x.start_point.row + 1
        if callee.type == "simple_identifier":
            name = _t(callee)
            if cls is not None:
                r = self.m.fun_in(cls, name)
                if r:
                    refs.append(Ref(nid(r), line, RESOLVED, "name"))
                    return
            if name in self.m.funs and self.m.funs[name].cls is None:
                refs.append(Ref(nid(name), line, RESOLVED, "name"))
                return
            t = self.m.find_type(cls, name)
            if t is not None:
                init = self.m.fun_in(t, "init")
                if init:
                    refs.append(Ref(nid(init), line, RESOLVED, "constructor"))
                if "View" in t.supers and "body" in t.funs:  # SwiftUI draws a view it is given by running its body
                    refs.append(Ref(nid(f"{t.name}.body"), line, INFERRED, "swiftui-body", "jsx"))
            return
        if callee.type == "navigation_expression":
            res = self._nav_target(cls, env, callee)
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
                recv, name = _nav_parts(callee)
                key = f"{src}: {_t(recv)[:40]}.{name}"
                self.m.unresolved[key] = self.m.unresolved.get(key, 0) + 1


def _vapor_routes(model: Model, fn: SFun) -> list[tuple[str, str, str]]:
    """`app.get("users", ":id", use: show)` inside `fn` → (verb, path, handler function key)."""
    out = []
    cls = model.types.get(fn.cls) if fn.cls else None
    for node in fn.nodes:
        stack = [node]
        while stack:
            x = stack.pop()
            stack.extend(x.children)
            if x.type != "call_expression" or not x.children or x.children[0].type != "navigation_expression":
                continue
            _recv, verb = _nav_parts(x.children[0])
            if verb not in VAPOR_VERBS:
                continue
            args = _kid(_kid(x, "call_suffix"), "value_arguments")
            parts, handler = [], None
            for va in _kids(args, "value_argument"):
                label = _kid(va, "value_argument_label")
                val = [c for c in va.children if c.is_named and c.type != "value_argument_label"]
                if label is not None and _t(label) == "use" and val:
                    h = _t(val[0]).replace("self.", "")
                    if "." in h:                                  # `c.show` with `let c = NoteController()` above
                        var, _, meth = h.rpartition(".")
                        m = re.search(r"\b(?:let|var)\s+" + re.escape(var) + r"\s*(?::\s*(\w+)|=\s*(\w+)\s*\()",
                                      _t(node))
                        t = model.types.get((m.group(1) or m.group(2)) if m else var)
                        handler = model.fun_in(t, meth) if t is not None else None
                    else:
                        handler = (cls and model.fun_in(cls, h)) or (h if h in model.funs else None)
                elif label is None and val and val[0].type == "line_string_literal":
                    parts.append("".join(_t(c) for c in val[0].children if c.type == "line_str_text"))
            if handler:
                path = "/" + "/".join(p.strip("/") for p in parts if p.strip("/"))
                out.append((VAPOR_VERBS[verb], re.sub(r"/:(\w+)", r"/{\1}", path), handler))
    return out


def add_swift(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    paths = discover(repo)
    if not paths:
        return {}
    try:
        parser = _parser()
    except ImportError:
        g.meta.setdefault("skipped_languages", []).append("swift (pip install tree-sitter-swift)")
        return {}
    model = Model()
    files: list[tuple[SFile, object]] = []      # trees kept alive for as long as their nodes are used
    total = 0
    for p in paths:
        try:
            src = p.read_bytes()
        except OSError:
            continue
        if len(src) > MAX_BYTES:
            continue
        rel = p.relative_to(repo).as_posix()
        tree = parser.parse(src)
        lines = src.count(b"\n") + 1
        total += lines
        f = SFile(rel=rel, lines=lines, is_test=bool(TEST_FILE_RE.search(rel)))
        files.append((f, tree))
        _collect(model, f, tree.root_node)

    for f, _ in files:
        g.add_node(Node(id=f"sw:{f.rel}", kind=MODULE, name=Path(f.rel).name, qualname=f.rel, file=f.rel,
                        start_line=1, end_line=f.lines))
        if f.is_test:
            g.nodes[f"sw:{f.rel}"].entry = {"kind": "test", "detail": f.rel}
    for local, t in model.types.items():
        tid = nid(local)
        parent = nid(local.rsplit(".", 1)[0]) if "." in local else f"sw:{t.file}"
        g.add_node(Node(id=tid, kind=CLASS, name=local.split(".")[-1], qualname=local, file=t.file, start_line=t.start,
                        end_line=t.end, parent=parent,
                        signature=f"{t.kind} {local}" + (f": {', '.join(t.supers)}" if t.supers else ""),
                        decorators=[f"@{a}" for a in t.attrs if a]))
        g.add_edge(parent, tid, kind=CONTAINS)
    for local, fn in model.funs.items():
        mid = nid(local)
        parent = nid(fn.cls) if fn.cls else f"sw:{fn.file}"
        sig = fn.signature + (f"  (+{len(fn.nodes) - 1} overload{'s' if len(fn.nodes) > 2 else ''})"
                              if len(fn.nodes) > 1 else "")
        g.add_node(Node(id=mid, kind=CALLABLE, name=fn.name, qualname=local, file=fn.file, start_line=fn.start,
                        end_line=fn.end, parent=parent, fingerprint=fn.fingerprint, signature=sig[:200],
                        decorators=[f"@{a}" for a in fn.attrs if a]))
        g.add_edge(parent, mid, kind=CONTAINS)
    link = Linker(model)
    for local, fn in model.funs.items():
        src = nid(local)
        for r in link.walk(fn, src):
            if r.target.startswith("ext:"):
                g.external(r.target[4:])
            elif r.target not in g.nodes or r.target == src:
                continue
            g.add_edge(src, r.target, kind=CALLS, confidence=r.confidence, line=r.line, via=r.via)
    for key, n in model.unresolved.items():
        g.unresolved[key[:120]] = g.unresolved.get(key[:120], 0) + n
    routes = 0
    for local, fn in model.funs.items():
        node = g.nodes.get(nid(local))
        if node is None:
            continue
        cls = model.types.get(fn.cls) if fn.cls else None
        if fn.is_test and (fn.cls is None or fn.name.startswith("test")):
            node.entry = {"kind": "test", "detail": fn.file}
        elif cls is not None and "main" in cls.attrs and (fn.name == "body" and "App" in cls.supers
                                                         or fn.name in ("main", "application")):
            node.entry = {"kind": "main", "detail": f"app start ({cls.name}) · {fn.name}"}
        elif fn.cls is None and fn.name == "main":
            node.entry = {"kind": "main", "detail": f"program start ({fn.file})"}
        for verb, path, handler in _vapor_routes(model, fn):
            h = g.nodes.get(nid(handler))
            if h is not None:
                h.entry = {"kind": "route", "detail": f"{verb} {path}"}
                routes += 1
    if any(f.rel.endswith("main.swift") for f, _ in files):
        for f, _ in files:
            if f.rel.endswith("main.swift") and not f.is_test:
                g.nodes[f"sw:{f.rel}"].entry = {"kind": "main", "detail": f"program start ({f.rel})"}
    return {"files": len(files), "lines": total, "types": len(model.types), "functions": len(model.funs),
            "routes": routes, "unresolved": sum(model.unresolved.values())}
