"""Dart: Flutter apps (and plain Dart programs), mapped like the Swift reader maps Swift.

Dart names a type by itself across the files that import it, so ids are `dt:<Class>.<method>` and `dt:<function>`;
a private name (leading `_`, visible in its own file only) carries its file: `dt:_HomeState@lib/home.dart`. File module:
`dt:<path>.dart`. A constructor is `Class.new` (named constructors `Class.named`), getters are functions, an `extension
on String` adds its functions to `dt:String`.

Calls are resolved by:
  * `name`          `helper()` → a method of the same class (or a repo class it extends or mixes in), else a top-level
                    function
  * `this`          `this.helper()`
  * `assoc`         `NoteStore.create()`: a static or named constructor
  * `receiver-type` `store.find()` where `store` is a parameter, a field or a local whose type is written, comes from a
                    constructor call (`final s = NoteStore()`), or from a repo function's written return type
  * `interface`     the receiver's type is an abstract class or one others `implements`: one `possible` edge each
  * `constructor`   `NoteStore()` runs `NoteStore.new` when the class writes one
  * `callback`      a method passed by name (`onPressed: _save`)
  * `flutter-build` `NoteScreen(id: id)` inside a build: Flutter draws it by running its `build` (a StatefulWidget's
                    is in its State class) (`inferred`)
Calls on library types become `ext:<Type>.<method>`; a receiver whose type is unknown is counted in `graph.unresolved`.
Closures belong to the function they are written in.

Entries: `main`, test files (`test/`, `integration_test/`, `*_test.dart`). Flutter screens and links are marked by
`flutter.add_entries`.
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
SKIP_DART = {".dart_tool", "build", ".pub-cache", "ios", "android", "macos", "windows", "linux", "web"}
TEST_FILE_RE = re.compile(r"(^|/)(test|integration_test|test_driver)/|_test\.dart$")
GENERATED_RE = re.compile(r"\.(g|freezed|gr|config|mocks|pb|pbenum|pbjson|pbserver)\.dart$")
WIDGET_BASES = {"StatelessWidget", "StatefulWidget", "ConsumerWidget", "ConsumerStatefulWidget", "HookWidget",
                "HookConsumerWidget", "StatefulHookWidget", "StatefulHookConsumerWidget", "GetView", "GetWidget"}
STATE_BASES = {"State", "ConsumerState", "HookState"}


def _parser():
    import tree_sitter as ts
    import tree_sitter_dart as td
    return ts.Parser(ts.Language(td.language()))


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _kid(n, *types):
    return next((c for c in n.children if c.type in types), None) if n is not None else None


def _kids(n, *types):
    return [c for c in n.children if c.type in types] if n is not None else []


@dataclass
class DFun:
    name: str
    cls: str | None
    key: str
    file: str
    start: int
    end: int
    signature: str
    fingerprint: str
    params: dict[str, str] = field(default_factory=dict)
    returns: str | None = None
    is_static: bool = False
    bodies: list = field(default_factory=list)
    is_test: bool = False


@dataclass
class DClass:
    name: str
    key: str                   # name, or name@file for a private class
    file: str
    start: int
    end: int
    kind: str                  # class | abstract | mixin | extension | enum
    supers: list[str] = field(default_factory=list)       # extends, with, implements, on
    implements: list[str] = field(default_factory=list)
    state_of: str | None = None                          # `extends State<HomeScreen>` → "HomeScreen"
    props: dict[str, str] = field(default_factory=dict)
    funs: set[str] = field(default_factory=set)


class Model:
    def __init__(self):
        self.types: dict[str, DClass] = {}
        self.funs: dict[str, DFun] = {}
        self.unresolved: dict[str, int] = {}

    def key(self, name: str, file: str) -> str:
        return f"{name}@{file}" if name.startswith("_") else name

    def find_type(self, name: str | None, file: str) -> DClass | None:
        if not name:
            return None
        return self.types.get(self.key(name, file))

    def fun_in(self, t: DClass, name: str, file: str, depth: int = 0) -> str | None:
        if name in t.funs:
            return f"{t.key}.{name}"
        if depth > 6:
            return None
        for s in t.supers:
            sup = self.find_type(s, t.file) or self.find_type(s, file)
            if sup is not None and sup is not t:
                r = self.fun_in(sup, name, file, depth + 1)
                if r:
                    return r
        return None

    def implementers(self, t: DClass) -> list[DClass]:
        return [k for k in self.types.values() if t.name in k.supers and k is not t and k.kind not in ("abstract",
                                                                                                    "mixin")]


def nid(key: str) -> str:
    return f"dt:{key}"


def discover(repo: Path) -> list[Path]:
    out = []
    for p in repo.rglob("*.dart"):
        rel = p.relative_to(repo)
        parts = rel.parts[:-1]
        if skipped(parts, repo) or not p.is_file() or not inside_repo(p, repo):
            continue
        # a Flutter project's platform folders hold generated code (ios/Runner, android/app/…), not the app's Dart
        if any(x in SKIP_DART for x in parts) and not any(x in ("lib", "test", "bin") for x in parts):
            continue
        if GENERATED_RE.search(p.name):
            continue
        out.append(p)
    return sorted(out)


def _type_of_node(n) -> str | None:
    """The simple name of a written type (`NoteStore`, `NoteStore?`, `List<Note>` → List)."""
    if n is None:
        return None
    if n.type == "type_identifier":
        return _t(n)
    ti = _kid(n, "type_identifier")
    return _t(ti) if ti is not None else None


def _params(sig) -> dict[str, str]:
    out: dict[str, str] = {}
    fpl = _kid(sig, "formal_parameter_list")
    if fpl is None:
        return out
    stack = [fpl]
    while stack:
        x = stack.pop()
        if x.type == "formal_parameter":
            ident = [c for c in x.children if c.type == "identifier"]
            cp = _kid(x, "constructor_param")
            if cp is not None:
                ident = _kids(cp, "identifier")
            if ident:
                out[_t(ident[-1])] = _t(_kid(x, "type_identifier")) if _kid(x, "type_identifier") is not None else ""
            continue
        stack.extend(x.children)
    return out


def _collect(model: Model, rel: str, root, is_test: bool) -> None:
    def add_fun(sig, body, cls: DClass | None):
        inner = sig
        static = any(c.type == "static" for c in sig.children)
        if sig.type == "method_signature":
            inner = next((c for c in sig.children if c.is_named and c.type != "static"), sig)
        if inner.type in ("constructor_signature", "constant_constructor_signature", "factory_constructor_signature",
                          "redirecting_factory_constructor_signature"):
            ids = _kids(inner, "identifier")
            name = _t(ids[1]) if len(ids) > 1 else "new"
            static = True
            ret = cls.name if cls else None
        else:
            idn = _kid(inner, "identifier")
            if idn is None:
                return
            name = _t(idn)
            ret = None
            for c in inner.children:
                if c.type == "identifier":
                    break
                if c.type == "type_identifier":
                    ret = _t(c)
        key = (f"{cls.key}.{name}" if cls else model.key(name, rel))
        fp = hashlib.sha1((sig.text or b"") + (body.text if body is not None else b""),
                          usedforsecurity=False).hexdigest()[:12]
        end = (body or sig).end_point.row + 1
        if key in model.funs:
            fn = model.funs[key]
            if body is not None:
                fn.bodies.append(body)
            fn.end = max(fn.end, end) if fn.file == rel else fn.end
            return
        model.funs[key] = DFun(name=name, cls=cls.key if cls else None, key=key, file=rel,
                               start=sig.start_point.row + 1, end=end,
                               signature=re.sub(r"\s+", " ", _t(sig)).strip()[:200], fingerprint=fp,
                               params=_params(inner), returns=ret, is_static=static,
                               bodies=[body] if body is not None else [], is_test=is_test)
        if cls is not None:
            cls.funs.add(name)

    def members(body, cls: DClass):
        kids = body.children
        for i, c in enumerate(kids):
            nxt = kids[i + 1] if i + 1 < len(kids) else None
            if c.type == "method_signature":
                add_fun(c, nxt if nxt is not None and nxt.type == "function_body" else None, cls)
            elif c.type == "declaration":
                sig = next((x for x in c.children if x.type.endswith("constructor_signature")
                            or x.type in ("function_signature", "getter_signature", "setter_signature")), None)
                if sig is not None:
                    add_fun(sig, None, cls)
                    continue
                tn = _type_of_node(_kid(c, "type_identifier")) if _kid(c, "type_identifier") is not None else None
                for ii in [x for x in (_kid(c, "initialized_identifier_list") or c).children
                           if x.type == "initialized_identifier"]:
                    name = _kid(ii, "identifier")
                    t = tn
                    if t is None:                                     # final store = NoteStore();
                        vals = [x for x in ii.children if x.is_named][1:]
                        if vals and vals[0].type == "identifier" and _t(vals[0])[:1].isupper():
                            t = _t(vals[0])
                        elif vals and vals[0].type in ("const_object_expression", "new_expression"):
                            t = _type_of_node(vals[0])
                    if name is not None and t:
                        cls.props[_t(name)] = t

    def walk(n):
        kids = n.children
        for i, c in enumerate(kids):
            nxt = kids[i + 1] if i + 1 < len(kids) else None
            if c.type in ("class_definition", "mixin_declaration", "extension_declaration", "enum_declaration"):
                idn = _kid(c, "identifier")
                if c.type == "extension_declaration":
                    on = _kid(c, "type_identifier")
                    name = _t(on) if on is not None else None
                else:
                    name = _t(idn) if idn is not None else None
                if not name:
                    continue
                key = model.key(name, rel)
                kind = {"mixin_declaration": "mixin", "extension_declaration": "extension",
                        "enum_declaration": "enum"}.get(c.type, "abstract" if any(x.type == "abstract" for x in c.children)
                                                        else "class")
                t = model.types.get(key)
                if t is None:
                    t = model.types[key] = DClass(name=name, key=key, file=rel, start=c.start_point.row + 1,
                                                  end=c.end_point.row + 1, kind=kind)
                elif t.kind == "extension" and kind != "extension":
                    t.file, t.start, t.end, t.kind = rel, c.start_point.row + 1, c.end_point.row + 1, kind
                for part in c.children:
                    if part.type == "superclass":
                        for x in part.children:
                            if x.type == "type_identifier":
                                t.supers.append(_t(x))
                            elif x.type == "type_arguments" and t.supers and t.supers[-1] in STATE_BASES:
                                arg = _kid(x, "type_identifier")
                                t.state_of = _t(arg) if arg is not None else None
                            elif x.type == "mixins":
                                t.supers += [_t(y) for y in x.children if y.type == "type_identifier"]
                    elif part.type == "interfaces":
                        imp = [_t(y) for y in part.children if y.type == "type_identifier"]
                        t.supers += imp
                        t.implements += imp
                    elif part.type == "type_identifier" and c.type == "mixin_declaration":
                        t.supers.append(_t(part))
                body = _kid(c, "class_body", "extension_body", "enum_body")
                if body is not None:
                    members(body, t)
            elif c.type == "function_signature":
                add_fun(c, nxt if nxt is not None and nxt.type == "function_body" else None, None)
            elif c.type == "getter_signature":
                add_fun(c, nxt if nxt is not None and nxt.type == "function_body" else None, None)
            elif c.type == "ERROR":
                walk(c)

    walk(root)


@dataclass
class Ref:
    target: str
    line: int
    confidence: str
    via: str


PRIMARY = ("identifier", "this", "super", "const_object_expression", "new_expression", "parenthesized_expression")


class Linker:
    def __init__(self, model: Model):
        self.m = model

    def widget_build(self, t: DClass, file: str) -> str | None:
        """The build a widget's construction leads to: its own, or its State class's."""
        if "build" in t.funs:
            return f"{t.key}.build"
        for k in self.m.types.values():
            if k.state_of == t.name and "build" in k.funs:
                return f"{k.key}.build"
        return None

    def _is_widget(self, t: DClass, depth: int = 0) -> bool:
        if any(s in WIDGET_BASES for s in t.supers):
            return True
        if depth > 6:
            return False
        return any(self._is_widget(s, depth + 1) for s in (self.m.find_type(x, t.file) for x in t.supers)
                   if s is not None and s is not t)

    def construct(self, t: DClass, file: str, line: int, refs: list[Ref]) -> None:
        ctor = self.m.fun_in(t, "new", file) if "new" in t.funs else None
        if ctor:
            refs.append(Ref(nid(ctor), line, RESOLVED, "constructor"))
        if self._is_widget(t):
            b = self.widget_build(t, file)
            if b:
                refs.append(Ref(nid(b), line, INFERRED, "flutter-build"))

    def walk(self, fn: DFun) -> list[Ref]:
        cls = self.m.types.get(fn.cls) if fn.cls else None
        refs: list[Ref] = []
        for body in fn.bodies:
            env = dict(fn.params)
            self._walk(fn, cls, body, env, refs)
        return refs

    def _walk(self, fn, cls, n, env, refs):
        stack = [n]
        while stack:
            x = stack.pop()
            if x.type == "initialized_variable_definition":
                ids = _kids(x, "identifier")
                if ids:
                    tn = _t(_kid(x, "type_identifier")) if _kid(x, "type_identifier") is not None else None
                    if tn is None:
                        after = x.children[x.children.index(ids[0]) + 1:]
                        tn = self._chain(fn, cls, [c for c in after if c.is_named], env, None, record=False)
                    env[_t(ids[0])] = tn or ""
            elif x.type == "named_argument":                        # onPressed: _save
                val = [c for c in x.children if c.is_named and c.type != "label"]
                if len(val) == 1 and val[0].type == "identifier" and cls is not None and _t(val[0]) not in env:
                    r = self.m.fun_in(cls, _t(val[0]), fn.file)
                    if r:
                        refs.append(Ref(nid(r), x.start_point.row + 1, INFERRED, "callback"))
            kids = x.children
            i = 0
            while i < len(kids):                                    # a primary followed by selectors is one chain
                c = kids[i]
                if c.type in PRIMARY and i + 1 < len(kids) and kids[i + 1].type == "selector":
                    j = i + 1
                    while j < len(kids) and kids[j].type == "selector":
                        j += 1
                    self._chain(fn, cls, kids[i:j], env, refs)
                    i = j
                    continue
                if c.type in ("const_object_expression", "new_expression"):
                    t = self.m.find_type(_type_of_node(c), fn.file)
                    if t is not None:
                        self.construct(t, fn.file, c.start_point.row + 1, refs)
                i += 1
            stack.extend(reversed(kids))

    def _chain(self, fn, cls, parts, env, refs, record=True) -> str | None:
        """Walk `a.b(…).c(…)`; add edges for repo calls; return the chain's type when known."""
        if not parts:
            return None
        out = refs if refs is not None else []
        head = parts[0]
        line = head.start_point.row + 1
        cur: str | None = None          # the receiver's type name
        kind = "unknown"                # unknown | type (statics) | value | this
        i = 1
        if head.type == "this":
            cur, kind = (cls.name if cls else None), "this"
        elif head.type in ("const_object_expression", "new_expression"):
            tn = _type_of_node(head)
            t = self.m.find_type(tn, fn.file)
            if t is not None and record:
                self.construct(t, fn.file, line, out)
            cur, kind = tn, "value"
        elif head.type == "identifier":
            name = _t(head)
            called = len(parts) > 1 and _kid(parts[1], "argument_part") is not None
            if called:                                              # name(...)
                i = 2
                r = self.m.fun_in(cls, name, fn.file) if cls is not None else None
                if r:
                    if record:
                        out.append(Ref(nid(r), line, RESOLVED, "name"))
                    cur, kind = self.m.funs[r].returns, "value"
                elif self.m.key(name, fn.file) in self.m.funs and self.m.funs[self.m.key(name, fn.file)].cls is None:
                    k = self.m.key(name, fn.file)
                    if record:
                        out.append(Ref(nid(k), line, RESOLVED, "name"))
                    cur, kind = self.m.funs[k].returns, "value"
                else:
                    t = self.m.find_type(name, fn.file)
                    if t is not None and record:
                        self.construct(t, fn.file, line, out)
                    cur, kind = (name if name[:1].isupper() else None), "value"
            elif name in env:
                cur, kind = env[name] or None, "value"
            elif cls is not None and name in cls.props:
                cur, kind = cls.props[name], "value"
            elif name[:1].isupper():
                cur, kind = name, "type"
            else:
                return None
        else:
            return None
        while i < len(parts):
            sel = parts[i]
            member = _kid(sel, "unconditional_assignable_selector", "conditional_assignable_selector")
            idn = _kid(member, "identifier") if member is not None else None
            if idn is None:
                i += 1
                continue
            name = _t(idn)
            called = i + 1 < len(parts) and _kid(parts[i + 1], "argument_part") is not None
            sline = sel.start_point.row + 1
            t = self.m.find_type(cur, fn.file) if cur else None
            if not called:                                          # a field: follow its type
                cur = t.props.get(name) if t is not None else None
                kind = "value"
                i += 1
                continue
            i += 2
            if kind == "unknown" or cur is None:
                if record and refs is not None:
                    key = f"{nid(fn.key)}: {_t(parts[0])[:40]}.{name}"
                    self.m.unresolved[key] = self.m.unresolved.get(key, 0) + 1
                cur = None
                continue
            if t is None:                                           # a library type
                if record:
                    out.append(Ref(f"ext:{cur}.{name}", sline, RESOLVED, "import" if kind == "type" else "receiver-type"))
                cur = None
                continue
            via = {"this": "this", "type": "assoc"}.get(kind, "receiver-type")
            if kind != "type" and (t.kind in ("abstract", "mixin") or any(t.name in k.implements
                                                                        for k in self.m.types.values())):
                extra = [nid(r) for k in self.m.implementers(t) for r in [self.m.fun_in(k, name, fn.file)] if r]
                if extra:
                    if record:
                        out.extend(Ref(e, sline, POSSIBLE, "interface") for e in extra)
                    cur = None
                    continue
            r = self.m.fun_in(t, name, fn.file)
            if r:
                if record:
                    out.append(Ref(nid(r), sline, RESOLVED, via))
                cur = self.m.funs[r].returns
            else:
                cur = None
            kind = "value"
        return cur


def add_dart(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    paths = discover(repo)
    if not paths:
        return {}
    try:
        parser = _parser()
    except ImportError:
        g.meta.setdefault("skipped_languages", []).append("dart (pip install tree-sitter-dart)")
        return {}
    model = Model()
    trees = []
    total = 0
    files = []
    for p in paths:
        try:
            src = project_bytes(p, repo)
        except OSError:
            continue
        if len(src) > MAX_BYTES:
            continue
        rel = p.relative_to(repo).as_posix()
        tree = parser.parse(src)
        trees.append(tree)
        lines = src.count(b"\n") + 1
        total += lines
        is_test = bool(TEST_FILE_RE.search(rel))
        files.append((rel, lines, is_test))
        deep.whole((g, "dart"), rel, _collect, model, rel, tree.root_node, is_test)
    for rel, lines, is_test in files:
        g.add_node(Node(id=f"dt:{rel}", kind=MODULE, name=Path(rel).name, qualname=rel, file=rel, start_line=1,
                        end_line=lines))
        if is_test:
            g.nodes[f"dt:{rel}"].entry = {"kind": "test", "detail": rel}
    for key, t in model.types.items():
        sig = f"{t.kind} {t.name}" + (f": {', '.join(t.supers)}" if t.supers else "")
        if t.state_of:
            sig += f" (state of {t.state_of})"
        g.add_node(Node(id=nid(key), kind=CLASS, name=t.name, qualname=key, file=t.file, start_line=t.start,
                        end_line=t.end, parent=f"dt:{t.file}", signature=sig))
        g.add_edge(f"dt:{t.file}", nid(key), kind=CONTAINS)
    for key, fn in model.funs.items():
        parent = nid(fn.cls) if fn.cls else f"dt:{fn.file}"
        g.add_node(Node(id=nid(key), kind=CALLABLE, name=fn.name, qualname=key, file=fn.file, start_line=fn.start,
                        end_line=fn.end, parent=parent, fingerprint=fn.fingerprint, signature=fn.signature))
        g.add_edge(parent, nid(key), kind=CONTAINS)
    link = Linker(model)
    for key, fn in model.funs.items():
        src = nid(key)
        for r in link.walk(fn):
            if r.target.startswith("ext:"):
                g.external(r.target[4:])
            elif r.target not in g.nodes or r.target == src:
                continue
            g.add_edge(src, r.target, kind=CALLS, confidence=r.confidence, line=r.line, via=r.via)
    for k, n in model.unresolved.items():
        g.unresolved[k[:120]] = g.unresolved.get(k[:120], 0) + n
    for key, fn in model.funs.items():
        node = g.nodes[nid(key)]
        if fn.is_test:
            node.entry = {"kind": "test", "detail": fn.file}
        elif fn.name == "main" and fn.cls is None:
            node.entry = {"kind": "main", "detail": f"app start ({fn.file})"}
    del trees
    return {"files": len(files), "lines": total, "types": len(model.types), "functions": len(model.funs),
            "unresolved": sum(model.unresolved.values())}
