"""TypeScript/JavaScript frontend: parse .ts/.tsx/.js/.jsx files into the same Unified Code Graph.

Shape mirrors python_frontend.py: discover -> parse each file into a `TSModule` (defs, call sites,
HTTP calls, imports, exports) -> `TSResolver` -> `add_to_graph()`. Node ids use the `ts:` prefix.

What it understands:
  * functions, arrow functions and function expressions bound to names, classes and methods,
    nested functions (scoped like Python's `outer.inner`)
  * ES imports and re-exports (`export *`, `export { x } from`), tsconfig `paths`, Vite `@` alias
  * calls, `new`, JSX `<Component />` renders, `this.method()`, `Class.staticMethod()`
  * functions passed by name (callbacks, `onClick={save}`) as "possible" edges
  * HTTP calls (fetch, axios-style `.get/.post`, generated clients with `url:`), linked to backend
    routes later by bridge.py
  * entry points: Next.js pages and route handlers, TanStack/React Router file routes, Express-style
    `app.get("/path", handler)` routes, and app starts (`createRoot`, `.listen()`)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node as TSNode, Parser

from .graph import CALLABLE, CALLS, CLASS, CONTAINS, MAY_CALL, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import SKIP_DIRS

TS_LANGUAGE = Language(tsts.language_typescript())
TSX_LANGUAGE = Language(tsts.language_tsx())
JS_LANGUAGE = Language(tsjs.language())

EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
RESOLVE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
TS_SKIP_DIRS = SKIP_DIRS | {".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel", ".output", "coverage",
                            "out", "storybook-static", ".expo", "bower_components", "vendor"}
TEST_FILE_RE = re.compile(r"(^|/)(__tests__|tests?|e2e|cypress|playwright)/|\.(test|spec|stories)\.[cm]?[jt]sx?$")
CONFIG_FILE_RE = re.compile(r"(^|/)[^/]*\.config\.[cm]?[jt]s$|(^|/)\.eslintrc|(^|/)tailwind\.")

HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
SERVER_OBJECTS = {"app", "router", "server", "fastify", "routes", "api_router", "apiRouter", "r", "route"}
FUNC_TYPES = {"arrow_function", "function_expression", "function", "generator_function"}
# Browser/Node globals: calls on these are platform calls, not repo code, and not worth counting as
# "unresolved" (the Python side skips builtins the same way).
JS_GLOBALS = {
    "console", "JSON", "Math", "Object", "Array", "String", "Number", "Boolean", "Promise", "Date", "Symbol",
    "Error", "TypeError", "Map", "Set", "WeakMap", "RegExp", "Intl", "Reflect", "Proxy", "BigInt",
    "window", "document", "navigator", "location", "history", "localStorage", "sessionStorage",
    "globalThis", "process", "require", "module", "exports", "Buffer", "fetch", "setTimeout",
    "clearTimeout", "setInterval", "clearInterval", "queueMicrotask", "requestAnimationFrame",
    "parseInt", "parseFloat", "isNaN", "encodeURIComponent", "decodeURIComponent", "URL",
    "URLSearchParams", "FormData", "Headers", "Response", "Request", "AbortController", "atob", "btoa",
    "structuredClone", "alert", "confirm", "import", "super",
}
# Wrappers whose first argument is the real component/function body: `memo(() => ...)` etc.
WRAPPERS = {"memo", "forwardRef", "useCallback", "useMemo", "observer", "React.memo", "React.forwardRef",
            "styled", "withRouter", "connect"}


# --------------------------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------------------------

def discover(repo: Path) -> list[Path]:
    repo = repo.resolve()
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d not in TS_SKIP_DIRS and not d.startswith("."))
        for fn in sorted(filenames):
            if not fn.endswith(EXTS) or fn.endswith((".d.ts", ".min.js")):
                continue
            p = Path(dirpath) / fn
            rel = p.relative_to(repo).as_posix()
            if TEST_FILE_RE.search(rel) or CONFIG_FILE_RE.search(rel):
                continue
            out.append(p)
    return out


def _modname(rel: str) -> str:
    stem = rel.rsplit(".", 1)[0]
    return ".".join(re.sub(r"[^\w$\[\]()@-]", "_", part) for part in stem.split("/"))


# --------------------------------------------------------------------------------------------
# Per-file parse results
# --------------------------------------------------------------------------------------------

@dataclass
class TSDef:
    local: str
    kind: str                       # "function" | "class"
    name: str
    start: int
    end: int
    signature: str
    fingerprint: str
    parent_local: str | None = None
    docstring: str | None = None
    entry: dict | None = None


@dataclass
class TSCall:
    scope: str | None
    kind: str                       # call | new | jsx | ref | event
    chain: list[str]
    line: int
    text: str
    detail: str | None = None       # e.g. "onClick" for event refs


@dataclass
class HttpCall:
    scope: str | None
    method: str                     # GET, POST, ... or ANY when unknown
    url: str                        # normalized, params as {}
    raw: str
    line: int
    client: str                     # fetch | axios-style | generated


@dataclass
class TSModule:
    path: Path
    rel: str
    name: str
    lines: int
    defs: dict[str, TSDef] = field(default_factory=dict)
    calls: list[TSCall] = field(default_factory=list)
    http: list[HttpCall] = field(default_factory=list)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)   # local -> (spec, imported|*|default)
    exports: dict[str, str] = field(default_factory=dict)               # exported name -> local name
    reexports: dict[str, tuple[str, str]] = field(default_factory=dict) # exported name -> (spec, name)
    star_exports: list[str] = field(default_factory=list)
    route_handlers: list[tuple[str, str]] = field(default_factory=list) # (handler identifier, detail)
    page_components: list[tuple[str, str]] = field(default_factory=list)
    starts_app: bool = False


def _text(n: TSNode | None) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _first_line(n: TSNode) -> str:
    return _text(n).split("\n", 1)[0][:120]


def _fingerprint(n: TSNode) -> str:
    return hashlib.sha256(re.sub(r"\s+", " ", _text(n)).encode()).hexdigest()[:16]


def _chain(n: TSNode | None) -> list[str] | None:
    """`a.b.c` -> ["a", "b", "c"]; `this.x` -> ["this", "x"]; `a?.b` too. Anything else -> None."""
    if n is None:
        return None
    if n.type in ("identifier", "property_identifier", "type_identifier", "private_property_identifier"):
        return [_text(n)]
    if n.type == "this":
        return ["this"]
    if n.type == "member_expression":
        obj = _chain(n.child_by_field_name("object"))
        prop = n.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        return obj + [_text(prop)]
    if n.type in ("non_null_expression", "parenthesized_expression") and n.named_child_count == 1:
        return _chain(n.named_children[0])
    if n.type == "nested_identifier" or n.type == "jsx_namespace_name":
        return _text(n).split(".")
    if n.type == "member_expression" or n.type == "await_expression":
        return None
    return None


def _string_value(n: TSNode | None) -> str | None:
    """Literal string or template string (with ${...} turned into {})."""
    if n is None:
        return None
    if n.type == "string":
        return "".join(_text(c) for c in n.named_children if c.type in ("string_fragment", "escape_sequence"))
    if n.type == "template_string":
        out = []
        for c in n.children:
            if c.type == "string_fragment":
                out.append(_text(c))
            elif c.type == "template_substitution":
                out.append("{}")
        return "".join(out)
    if n.type == "binary_expression":   # `${API}/items` style: "base + '/items'" -> {}/items
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        lv, rv = _string_value(left), _string_value(right)
        if lv is None and rv is None:
            return None
        return (lv if lv is not None else "{}") + (rv if rv is not None else "{}")
    return None


def _jsdoc(n: TSNode) -> str | None:
    prev = n.prev_named_sibling
    if prev is not None and prev.type == "comment" and _text(prev).startswith("/**"):
        body = re.sub(r"^/\*\*|\*/$", "", _text(prev))
        lines = [re.sub(r"^\s*\* ?", "", ln).strip() for ln in body.splitlines()]
        doc = "\n".join(ln for ln in lines if ln).strip()
        return doc[:1000] or None
    return None


def _signature(n: TSNode, name: str) -> str:
    params = n.child_by_field_name("parameters") or n.child_by_field_name("parameter")
    p = re.sub(r"\s+", " ", _text(params))[:160] if params is not None else "()"
    if not p.startswith("("):
        p = f"({p})"
    asyn = "async " if _text(n).lstrip().startswith("async") else ""
    return f"{asyn}function {name}{p}"


def _object_pairs(n: TSNode | None) -> dict[str, TSNode]:
    out: dict[str, TSNode] = {}
    if n is None or n.type != "object":
        return out
    for c in n.named_children:
        if c.type == "pair":
            k = c.child_by_field_name("key")
            key = _string_value(k) if k is not None and k.type == "string" else _text(k)
            out[key] = c.child_by_field_name("value")
        elif c.type == "shorthand_property_identifier":
            out[_text(c)] = c
    return out


def normalize_url(url: str) -> str:
    """Strip scheme/host/query, turn every path parameter style into {}."""
    url = re.sub(r"^[a-z]+://[^/]*", "", url.strip())
    url = re.sub(r"^\{\}(?=/)", "", url)            # `${BASE}/items` -> /items
    url = url.split("?", 1)[0].split("#", 1)[0]
    url = re.sub(r"\{[^}/]*\}", "{}", url)
    url = re.sub(r"(?<=/):[A-Za-z_]\w*", "{}", url)  # express :id
    url = re.sub(r"\[\.*\w+\]", "{}", url)           # next [id]
    url = re.sub(r"<(?:\w+:)?\w+>", "{}", url)       # flask <int:id>
    if len(url) > 1:
        url = url.rstrip("/")
    return url or "/"


# --------------------------------------------------------------------------------------------
# Walker
# --------------------------------------------------------------------------------------------

class _Walker:
    def __init__(self, mod: TSModule):
        self.m = mod

    def add_def(self, n: TSNode, name: str, scope: str | None, kind: str = "function",
                doc_node: TSNode | None = None) -> str:
        local = f"{scope}.{name}" if scope else name
        if local in self.m.defs:   # overloads / re-declarations: keep the first, still walk the body
            return local
        sig = (f"class {name}" if kind == "class" else _signature(n, name))
        self.m.defs[local] = TSDef(local=local, kind=kind, name=name, start=n.start_point[0] + 1,
                                   end=n.end_point[0] + 1, signature=sig, fingerprint=_fingerprint(n),
                                   parent_local=scope, docstring=_jsdoc(doc_node or n))
        return local

    # scope: qualname of the enclosing def (None = module level); cls: enclosing class local
    def visit(self, n: TSNode, scope: str | None, cls: str | None) -> None:
        t = n.type
        if t in ("function_declaration", "generator_function_declaration"):
            name = _text(n.child_by_field_name("name"))
            local = self.add_def(n, name, scope, doc_node=n.parent if n.parent and n.parent.type == "export_statement" else n)
            self._body(n, local, cls)
            return
        if t in ("class_declaration", "abstract_class_declaration", "class"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                local = self.add_def(n, _text(nm), scope, kind="class")
                body = n.child_by_field_name("body")
                if body is not None:
                    for c in body.named_children:
                        self.visit(c, local, local)
                return
        if t == "method_definition" and cls is not None:
            name = _text(n.child_by_field_name("name"))
            local = self.add_def(n, name, cls)
            self._body(n, local, cls)
            return
        if t in ("public_field_definition", "field_definition") and cls is not None:
            # `handle = () => {...}` class fields act as methods
            val = n.child_by_field_name("value")
            nm = n.child_by_field_name("name") or n.child_by_field_name("property")
            if val is not None and val.type in FUNC_TYPES and nm is not None:
                local = self.add_def(val, _text(nm), cls, doc_node=n)
                self._body(val, local, cls)
                return
        if t == "variable_declarator":
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and nm.type == "identifier" and val is not None:
                fn = val if val.type in FUNC_TYPES else None
                if fn is None and val.type == "call_expression":
                    callee = _text(val.child_by_field_name("function"))
                    args = val.child_by_field_name("arguments")
                    first = args.named_children[0] if args is not None and args.named_child_count else None
                    if callee in WRAPPERS and first is not None and first.type in FUNC_TYPES:
                        self.record_call(val, scope)       # the wrapper call itself
                        fn = first
                if fn is not None:
                    decl = n.parent.parent if n.parent is not None and n.parent.parent is not None else n
                    local = self.add_def(fn, _text(nm), scope, doc_node=decl)
                    self._body(fn, local, cls)
                    return
                if val.type == "class":
                    local = self.add_def(val, _text(nm), scope, kind="class")
                    body = val.child_by_field_name("body")
                    for c in (body.named_children if body is not None else []):
                        self.visit(c, local, local)
                    return
        if t == "pair" and scope is None:
            # module-level object of functions: `export const api = { list: () => ... }`
            pass
        if t == "call_expression":
            if self.route_registration(n, scope, cls):
                return
            self.record_call(n, scope)
        elif t == "new_expression":
            ch = _chain(n.child_by_field_name("constructor"))
            if ch:
                self.m.calls.append(TSCall(scope, "new", ch, n.start_point[0] + 1, _first_line(n)))
        elif t in ("jsx_opening_element", "jsx_self_closing_element"):
            self.record_jsx(n, scope)
        for c in n.named_children:
            self.visit(c, scope, cls)

    def _body(self, fn: TSNode, local: str, cls: str | None) -> None:
        for fld in ("parameters", "body"):
            b = fn.child_by_field_name(fld)
            if b is not None:
                self.visit(b, local, cls)

    # ---- calls ----
    def record_call(self, n: TSNode, scope: str | None) -> None:
        fn = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        line = n.start_point[0] + 1
        ch = _chain(fn)
        if ch is None and fn is not None and fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            if obj is not None and obj.type == "new_expression":   # `new Foo().bar()`
                ctor = _chain(obj.child_by_field_name("constructor"))
                if ctor:
                    self.m.calls.append(TSCall(scope, "call", ctor + ["<new>", _text(fn.child_by_field_name("property"))],
                                               line, _first_line(n)))
        if ch:
            self.m.calls.append(TSCall(scope, "call", ch, line, _first_line(n)))
            if scope is None and ch[-1] in ("createRoot", "render", "hydrateRoot", "listen", "createApp", "mount"):
                self.m.starts_app = True
        self.http_call(n, fn, args, ch, scope, line)
        # functions passed by name: `useMutation({ mutationFn: login })`, `items.map(render)`
        if args is not None:
            for a in args.named_children:
                self._refs_in(a, scope, line, depth=0)

    def _refs_in(self, a: TSNode, scope: str | None, line: int, depth: int) -> None:
        if a.type == "identifier":
            self.m.calls.append(TSCall(scope, "ref", [_text(a)], line, _text(a)))
        elif a.type == "member_expression":
            ch = _chain(a)
            if ch and ch[0] == "this":
                self.m.calls.append(TSCall(scope, "ref", ch, line, _text(a)))
        elif a.type == "object" and depth < 2:
            for k, v in _object_pairs(a).items():
                if v is not None and v.type in ("identifier", "member_expression", "object",
                                                 "shorthand_property_identifier"):
                    if v.type == "shorthand_property_identifier":
                        self.m.calls.append(TSCall(scope, "ref", [_text(v)], line, _text(v)))
                    else:
                        self._refs_in(v, scope, line, depth + 1)

    def record_jsx(self, n: TSNode, scope: str | None) -> None:
        nm = n.child_by_field_name("name")
        line = n.start_point[0] + 1
        ch = _chain(nm) if nm is not None else None
        if ch and ch[-1][:1].isupper():
            self.m.calls.append(TSCall(scope, "jsx", ch, line, f"<{'.'.join(ch)}>"))
        for attr in n.named_children:
            if attr.type != "jsx_attribute" or attr.named_child_count < 2:
                continue
            aname = _text(attr.named_children[0])
            val = attr.named_children[1]
            if val.type != "jsx_expression" or not val.named_child_count:
                continue
            inner = val.named_children[0]
            ich = _chain(inner)
            if ich and aname.startswith("on") and aname[2:3].isupper():
                self.m.calls.append(TSCall(scope, "event", ich, line, f"{aname}={{{'.'.join(ich)}}}", aname))
            elif ich and len(ich) == 1:
                self.m.calls.append(TSCall(scope, "ref", ich, line, f"{aname}={{{ich[0]}}}"))

    # ---- HTTP ----
    def http_call(self, n: TSNode, fn: TSNode | None, args: TSNode | None, ch: list[str] | None,
                  scope: str | None, line: int) -> None:
        argv = list(args.named_children) if args is not None else []
        first = argv[0] if argv else None
        method, url, client = None, None, None
        if ch and ch[-1] in ("fetch", "$fetch", "ofetch", "useFetch") and len(ch) <= 2:
            url = _string_value(first)
            opts = _object_pairs(argv[1]) if len(argv) > 1 else {}
            m = _string_value(opts.get("method"))
            method, client = (m or "GET").upper(), "fetch"
        elif fn is not None and fn.type == "member_expression":
            verb = _text(fn.child_by_field_name("property")).lower()
            if verb in HTTP_VERBS or verb == "request":
                if first is not None and first.type in ("string", "template_string", "binary_expression"):
                    url = _string_value(first)
                    client = "axios-style"
                elif first is not None and first.type == "object":
                    pairs = _object_pairs(first)
                    url = _string_value(pairs.get("url"))
                    client = "generated" if "url" in pairs else None
                    if verb == "request":
                        verb = (_string_value(pairs.get("method")) or "ANY").lower()
                method = verb.upper()
        elif ch and ch[-1] == "axios" and first is not None and first.type == "object":
            pairs = _object_pairs(first)
            url, method, client = _string_value(pairs.get("url")), (_string_value(pairs.get("method")) or "GET").upper(), "axios-style"
        if url is None or method is None:
            return
        if not (url.startswith("/") or url.startswith("{}/") or re.match(r"^https?://", url)):
            return   # `map.get("key")`, `params.get(...)`: not a URL
        self.m.http.append(HttpCall(scope, method, normalize_url(url), url, line, client or "fetch"))

    # ---- Express / Hono / Fastify style servers ----
    def route_registration(self, n: TSNode, scope: str | None, cls: str | None) -> bool:
        fn = n.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return False
        verb = _text(fn.child_by_field_name("property")).lower()
        if verb not in HTTP_VERBS | {"all", "use"} or verb == "use":
            return False
        args = n.child_by_field_name("arguments")
        argv = list(args.named_children) if args is not None else []
        path = _string_value(argv[0]) if argv else None
        if path is None or not path.startswith("/") or len(argv) < 2:
            return False
        obj = _chain(fn.child_by_field_name("object"))
        rest = argv[1:]
        has_fn = any(a.type in FUNC_TYPES for a in rest)
        if not has_fn and not (obj and obj[-1] in SERVER_OBJECTS):
            return False
        detail = f"{'ANY' if verb == 'all' else verb.upper()} {path}"
        self.record_call_only(n, scope)
        handler = rest[-1]
        for a in rest[:-1]:
            self._refs_in(a, scope, n.start_point[0] + 1, 0) if a.type != "arrow_function" else self.visit(a, scope, cls)
        if handler.type in FUNC_TYPES:
            local = self.add_def(handler, detail, scope)
            self.m.defs[local].entry = {"kind": "route", "detail": detail}
            self._body(handler, local, cls)
        elif handler.type == "identifier" or handler.type == "member_expression":
            self.m.route_handlers.append((".".join(_chain(handler) or [_text(handler)]), detail))
            self._refs_in(handler, scope, n.start_point[0] + 1, 0)
        return True

    def record_call_only(self, n: TSNode, scope: str | None) -> None:
        ch = _chain(n.child_by_field_name("function"))
        if ch:
            self.m.calls.append(TSCall(scope, "call", ch, n.start_point[0] + 1, _first_line(n)))


def _imports_exports(m: TSModule, root: TSNode) -> None:
    for st in root.named_children:
        if st.type == "import_statement":
            src = _string_value(st.child_by_field_name("source"))
            if src is None:
                continue
            for clause in st.named_children:
                if clause.type != "import_clause":
                    continue
                for c in clause.named_children:
                    if c.type == "identifier":
                        m.imports[_text(c)] = (src, "default")
                    elif c.type == "namespace_import":
                        m.imports[_text(c.named_children[-1])] = (src, "*")
                    elif c.type == "named_imports":
                        for spec in c.named_children:
                            if spec.type != "import_specifier":
                                continue
                            ids = [x for x in spec.named_children if x.type in ("identifier", "string")]
                            if not ids:
                                continue
                            imported = _text(spec.child_by_field_name("name")) or _text(ids[0])
                            alias = spec.child_by_field_name("alias")
                            m.imports[_text(alias) if alias is not None else _text(ids[-1])] = (src, imported)
        elif st.type == "export_statement":
            src = _string_value(st.child_by_field_name("source"))
            decl = st.child_by_field_name("declaration")
            is_default = any(c.type == "default" for c in st.children)
            clause = next((c for c in st.named_children if c.type == "export_clause"), None)
            if src is not None and clause is None:
                ns = next((c for c in st.named_children if c.type == "namespace_export"), None)
                if ns is not None:
                    m.reexports[_text(ns.named_children[-1])] = (src, "*")
                else:
                    m.star_exports.append(src)
            elif clause is not None:
                for spec in clause.named_children:
                    if spec.type != "export_specifier":
                        continue
                    name = _text(spec.child_by_field_name("name"))
                    alias = spec.child_by_field_name("alias")
                    out = _text(alias) if alias is not None else name
                    if src is not None:
                        m.reexports[out] = (src, name)
                    else:
                        m.exports[out] = name
            elif decl is not None:
                names = []
                if decl.type in ("function_declaration", "generator_function_declaration", "class_declaration",
                                 "abstract_class_declaration"):
                    names = [_text(decl.child_by_field_name("name"))]
                elif decl.type in ("lexical_declaration", "variable_declaration"):
                    names = [_text(d.child_by_field_name("name")) for d in decl.named_children
                             if d.type == "variable_declarator"]
                for nm in names:
                    m.exports[nm] = nm
                if is_default and names:
                    m.exports["default"] = names[0]
            elif is_default:
                val = st.named_children[-1] if st.named_child_count else None
                if val is not None and val.type == "identifier":
                    m.exports["default"] = _text(val)
                elif val is not None and val.type in FUNC_TYPES | {"class"}:
                    m.exports["default"] = "default"
                elif val is not None and val.type == "call_expression":   # export default memo(Foo)
                    args = val.child_by_field_name("arguments")
                    if args is not None and args.named_child_count and args.named_children[0].type == "identifier":
                        m.exports["default"] = _text(args.named_children[0])


def _file_routes(m: TSModule, root: TSNode) -> None:
    """TanStack/React Router `createFileRoute("/path")({ component: X })`."""
    def walk(n: TSNode):
        if n.type == "call_expression":
            inner = n.child_by_field_name("function")
            if inner is not None and inner.type == "call_expression" and \
                    _text(inner.child_by_field_name("function")) in ("createFileRoute", "createRoute", "createLazyFileRoute"):
                iargs = inner.child_by_field_name("arguments")
                path = _string_value(iargs.named_children[0]) if iargs is not None and iargs.named_child_count else None
                args = n.child_by_field_name("arguments")
                opts = _object_pairs(args.named_children[0]) if args is not None and args.named_child_count else {}
                comp = opts.get("component")
                if comp is not None and comp.type in ("identifier", "shorthand_property_identifier"):
                    m.page_components.append((_text(comp), _clean_page_path(path or "/")))
                return
        for c in n.named_children:
            walk(c)
    walk(root)


def _clean_page_path(path: str) -> str:
    segs = [s for s in path.split("/") if s and not s.startswith("_") and not (s.startswith("(") and s.endswith(")"))]
    return "/" + "/".join(segs)


def parse_module(path: Path, repo: Path, parsers: dict[str, Parser]) -> TSModule:
    src = path.read_bytes()
    rel = path.relative_to(repo).as_posix()
    lang = "tsx" if path.suffix in (".tsx", ".jsx") else ("ts" if path.suffix in (".ts", ".mts", ".cts") else "js")
    # many .js files contain JSX; the JS grammar handles JSX natively
    tree = parsers[lang].parse(src)
    m = TSModule(path=path, rel=rel, name=_modname(rel), lines=src.count(b"\n") + 1)
    _imports_exports(m, tree.root_node)
    _Walker(m).visit(tree.root_node, None, None)
    _file_routes(m, tree.root_node)
    if "default" in m.exports and m.exports["default"] == "default" and "default" not in m.defs:
        # anonymous `export default function () {}`: name it after the file
        for st in tree.root_node.named_children:
            if st.type == "export_statement" and any(c.type == "default" for c in st.children):
                val = st.named_children[-1]
                if val.type in FUNC_TYPES:
                    m.defs["default"] = TSDef("default", "function", "default", val.start_point[0] + 1,
                                              val.end_point[0] + 1, _signature(val, "default"), _fingerprint(val))
    return m


# --------------------------------------------------------------------------------------------
# Module resolution
# --------------------------------------------------------------------------------------------

def _load_jsonc(p: Path) -> dict:
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return {}
    text = re.sub(r"(?m)(?<![:\"'])//.*$", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


class _Aliases:
    """tsconfig/jsconfig `paths` and Vite/webpack `@` aliases, per project folder."""

    def __init__(self, repo: Path):
        self.rules: list[tuple[Path, str, list[Path]]] = []   # (project dir, prefix pattern, targets)
        for cfg in sorted(list(repo.rglob("tsconfig*.json")) + list(repo.rglob("jsconfig.json"))):
            if any(part in TS_SKIP_DIRS for part in cfg.relative_to(repo).parts):
                continue
            opts = _load_jsonc(cfg).get("compilerOptions", {})
            base = cfg.parent / opts.get("baseUrl", ".")
            for pat, targets in (opts.get("paths") or {}).items():
                self.rules.append((cfg.parent, pat, [base / t for t in targets]))
        for cfg in sorted(repo.rglob("vite.config.*")) + sorted(repo.rglob("webpack.config.*")):
            if any(part in TS_SKIP_DIRS for part in cfg.relative_to(repo).parts):
                continue
            try:
                text = cfg.read_text(errors="replace")
            except OSError:
                continue
            for a, t in re.findall(r"['\"]?(@[\w/-]*|~)['\"]?\s*:\s*(?:path\.)?resolve\([^,]+,\s*['\"]([^'\"]+)['\"]\)", text):
                self.rules.append((cfg.parent, a + "/*", [cfg.parent / t / "*"]))

    def expand(self, from_file: Path, spec: str) -> list[Path]:
        out = []
        for proj, pat, targets in self.rules:
            if proj not in from_file.parents:
                continue
            if pat.endswith("*"):
                if spec.startswith(pat[:-1]):
                    rest = spec[len(pat) - 1:]
                    out += [Path(str(t).replace("*", rest)) for t in targets]
            elif spec == pat:
                out += targets
        return out


def _try_file(base: Path) -> Path | None:
    cands = [base]
    if base.suffix in (".js", ".jsx", ".mjs", ".cjs"):
        cands.append(base.with_suffix(""))           # TS ESM: import "./x.js" means x.ts
    for b in cands:
        if b.is_file() and b.suffix in RESOLVE_EXTS:
            return b
        for ext in RESOLVE_EXTS:
            p = b.with_name(b.name + ext)
            if p.is_file():
                return p
        if b.is_dir():
            for ext in RESOLVE_EXTS:
                p = b / f"index{ext}"
                if p.is_file():
                    return p
    return None


# --------------------------------------------------------------------------------------------
# Resolver
# --------------------------------------------------------------------------------------------

def tsid(qual: str) -> str:
    return f"ts:{qual}"


class TSResolver:
    def __init__(self, repo: Path, mods: dict[str, TSModule]):
        self.repo = repo
        self.mods = mods
        self.by_path = {m.path.resolve(): m for m in mods.values()}
        self.aliases = _Aliases(repo)
        self._spec_cache: dict[tuple[str, str], TSModule | str | None] = {}

    def module_for(self, m: TSModule, spec: str) -> TSModule | str | None:
        """Repo module, or the npm package name (str) for bare imports, or None."""
        key = (m.rel, spec)
        if key in self._spec_cache:
            return self._spec_cache[key]
        res: TSModule | str | None = None
        if spec.startswith("."):
            p = _try_file((m.path.parent / spec).resolve())
            res = self.by_path.get(p.resolve()) if p else None
        else:
            for cand in self.aliases.expand(m.path, spec):
                p = _try_file(cand.resolve())
                if p and p.resolve() in self.by_path:
                    res = self.by_path[p.resolve()]
                    break
            if res is None and spec.startswith(("@/", "~/")):
                # common convention when no config was found: nearest package's src/
                for parent in m.path.parents:
                    if (parent / "package.json").is_file():
                        p = _try_file((parent / "src" / spec[2:]).resolve()) or _try_file((parent / spec[2:]).resolve())
                        res = self.by_path.get(p.resolve()) if p else None
                        break
                    if parent == self.repo:
                        break
            if res is None:
                parts = spec.split("/")
                res = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
        self._spec_cache[key] = res
        return res

    def export_of(self, m: TSModule, name: str, depth: int = 0) -> tuple[str, str] | None:
        """Follow exports/re-exports to (kind, target): ("def", qualname) | ("mod", module name) | ("ext", name)."""
        if depth > 12:
            return None
        if name == "*":
            return ("mod", m.name)
        local = m.exports.get(name)
        if local is None and name != "default" and name in m.defs and m.defs[name].parent_local is None:
            local = name   # CommonJS or loosely exported; still the right target
        if local is not None:
            if local in m.defs:
                return ("def", f"{m.name}.{local}")
            if local in m.imports:
                return self.import_target(m, local, depth + 1)
        if name in m.reexports:
            spec, inner = m.reexports[name]
            tm = self.module_for(m, spec)
            if isinstance(tm, TSModule):
                return self.export_of(tm, inner, depth + 1)
            if isinstance(tm, str):
                return ("ext", f"{tm}.{inner}")
        for spec in m.star_exports:
            tm = self.module_for(m, spec)
            if isinstance(tm, TSModule):
                r = self.export_of(tm, name, depth + 1)
                if r:
                    return r
        return None

    def import_target(self, m: TSModule, local: str, depth: int = 0) -> tuple[str, str] | None:
        spec, imported = m.imports[local]
        tm = self.module_for(m, spec)
        if isinstance(tm, TSModule):
            return self.export_of(tm, imported, depth)
        if isinstance(tm, str):
            return ("ext", tm if imported in ("*", "default") else f"{tm}.{imported}")
        return None

    def lookup(self, m: TSModule, scope: str | None, name: str) -> tuple[str, str, str] | None:
        """Name visible from `scope`: (kind, target, via)."""
        s = scope
        while True:
            local = f"{s}.{name}" if s else name
            if local in m.defs:
                return ("def", f"{m.name}.{local}", "ts-local")
            if not s:
                break
            s = s.rsplit(".", 1)[0] if "." in s else None
        if name in m.imports:
            r = self.import_target(m, name)
            if r:
                return (r[0], r[1], "ts-import")
        return None

    def class_of(self, m: TSModule, scope: str | None) -> str | None:
        s = scope
        while s:
            if s in m.defs and m.defs[s].kind == "class":
                return f"{m.name}.{s}"
            s = s.rsplit(".", 1)[0] if "." in s else None
        return None

    def method(self, class_qual: str, meth: str) -> str | None:
        mod = self._mod_of(class_qual)
        if mod is None:
            return None
        local = class_qual[len(mod.name) + 1:] + "." + meth
        return f"{mod.name}.{local}" if local in mod.defs else None

    def _mod_of(self, qual: str) -> TSModule | None:
        best = None
        for name, mod in self.mods.items():
            if qual.startswith(name + ".") and (best is None or len(name) > len(best.name)):
                best = mod
        return best

    def def_kind(self, qual: str) -> str | None:
        mod = self._mod_of(qual)
        if mod is None:
            return None
        d = mod.defs.get(qual[len(mod.name) + 1:])
        return d.kind if d else None

    def resolve(self, m: TSModule, cs: TSCall) -> list[tuple[str, str, str]]:
        """-> [(target id, confidence, via)]"""
        ch = cs.chain
        if ch[0] == "this":
            cq = self.class_of(m, cs.scope)
            if cq and len(ch) == 2:
                t = self.method(cq, ch[1])
                if t:
                    return [(tsid(t), RESOLVED, "ts-this")]
            return []
        if "<new>" in ch:
            i = ch.index("<new>")
            cls = self.resolve(m, TSCall(cs.scope, "new", ch[:i], cs.line, cs.text))
            if cls and i == len(ch) - 2:
                cq = cls[0][0][3:]
                if cq.endswith(".constructor"):
                    cq = cq[: -len(".constructor")]
                t = self.method(cq, ch[-1]) if self.def_kind(cq) == "class" else None
                if t:
                    return [(tsid(t), RESOLVED, "ts-new-method")]
            return []
        head = self.lookup(m, cs.scope, ch[0])
        if head is None:
            return []
        kind, target, via = head
        if kind == "ext":
            return [(f"ext:{'.'.join([target] + ch[1:])}", RESOLVED, via)]
        if len(ch) == 1:
            if kind == "def":
                if self.def_kind(target) == "class":
                    ctor = self.method(target, "constructor")
                    return [(tsid(ctor or target), RESOLVED, via + ("-new" if cs.kind == "new" else ""))]
                return [(tsid(target), RESOLVED, via)]
            return []
        if kind == "def" and len(ch) == 2 and self.def_kind(target) == "class":
            t = self.method(target, ch[1])
            if t:
                return [(tsid(t), RESOLVED, "ts-static")]
        if kind == "mod" and len(ch) >= 2:
            tm = self.mods.get(target)
            r = self.export_of(tm, ch[1]) if tm else None
            if r and r[0] == "def":
                if len(ch) == 2:
                    return [(tsid(r[1]), RESOLVED, "ts-namespace")]
                if len(ch) == 3 and self.def_kind(r[1]) == "class":
                    t = self.method(r[1], ch[2])
                    if t:
                        return [(tsid(t), RESOLVED, "ts-namespace-static")]
        return []


# --------------------------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------------------------

def _next_route_path(rel: str, marker: str) -> str | None:
    parts = rel.split("/")
    if marker not in parts:
        return None
    segs = parts[parts.index(marker) + 1:]
    segs[-1] = segs[-1].rsplit(".", 1)[0]
    if segs[-1] in ("page", "route", "index"):
        segs = segs[:-1]
    segs = [s for s in segs if not (s.startswith("(") and s.endswith(")")) and not s.startswith("@")]
    segs = ["{}" if re.fullmatch(r"\[\.*\w+\]", s) else s for s in segs]
    return "/" + "/".join(segs)


def _entries(m: TSModule, r: TSResolver) -> dict[str, dict]:
    """local def name -> entry dict"""
    out: dict[str, dict] = {}
    rel = m.rel
    base = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    parts = rel.split("/")
    # Next.js app router
    if "app" in parts and base == "route":
        path = _next_route_path(rel, "app")
        for verb in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            local = m.exports.get(verb)
            if local in m.defs:
                out[local] = {"kind": "route", "detail": f"{verb} {path}"}
    elif "app" in parts and base in ("page", "layout"):
        local = m.exports.get("default")
        if local in m.defs:
            out[local] = {"kind": "page", "detail": _next_route_path(rel, "app") or "/"}
    # Next.js pages router
    elif "pages" in parts:
        local = m.exports.get("default")
        path = _next_route_path(rel, "pages") or "/"
        if local in m.defs:
            if path.startswith("/api"):
                out[local] = {"kind": "route", "detail": f"ANY {path}"}
            elif not base.startswith("_"):
                out[local] = {"kind": "page", "detail": path}
    # TanStack / React Router file routes
    for comp, path in m.page_components:
        hit = r.lookup(m, None, comp)
        if hit and hit[0] == "def" and hit[1].startswith(m.name + "."):
            out[hit[1][len(m.name) + 1:]] = {"kind": "page", "detail": path}
    # Express-style handlers referenced by name
    for handler, detail in m.route_handlers:
        hit = r.lookup(m, None, handler.split(".")[0])
        if hit and hit[0] == "def" and len(handler.split(".")) == 1:
            out[("@" + hit[1])] = {"kind": "route", "detail": detail}   # may live in another module
    for local, d in m.defs.items():
        if d.entry:
            out[local] = d.entry
    return out


# --------------------------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------------------------

def parse_repo(repo: Path) -> dict[str, TSModule]:
    repo = repo.resolve()
    parsers = {"ts": Parser(TS_LANGUAGE), "tsx": Parser(TSX_LANGUAGE), "js": Parser(JS_LANGUAGE)}
    mods: dict[str, TSModule] = {}
    for path in discover(repo):
        try:
            info = parse_module(path, repo, parsers)
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        if info.lines > 20000:   # bundled or generated blobs
            continue
        if info.name in mods:
            info.name = f"{info.name}__{len(mods)}"
        mods[info.name] = info
    return mods


def add_to_graph(g: Graph, repo: str | Path) -> dict:
    """Parse JS/TS files and add their nodes and edges to `g`. Returns per-language stats and the
    raw HTTP call list for bridge.py."""
    repo = Path(repo).resolve()
    mods = parse_repo(repo)
    r = TSResolver(repo, mods)
    total_lines = 0
    for m in mods.values():
        total_lines += m.lines
        mod_entry = {"kind": "main", "detail": m.rel} if m.starts_app else None
        g.add_node(Node(id=tsid(m.name), kind=MODULE, name=m.name.split(".")[-1], qualname=m.name,
                        file=m.rel, start_line=1, end_line=m.lines, entry=mod_entry))
        for d in m.defs.values():
            q = f"{m.name}.{d.local}"
            parent = tsid(f"{m.name}.{d.parent_local}") if d.parent_local else tsid(m.name)
            g.add_node(Node(id=tsid(q), kind=CLASS if d.kind == "class" else CALLABLE, name=d.name, qualname=q,
                            file=m.rel, start_line=d.start, end_line=d.end, parent=parent,
                            fingerprint=d.fingerprint, signature=d.signature, docstring=d.docstring))
            g.add_edge(parent, tsid(q), kind=CONTAINS, confidence=RESOLVED)
    for m in mods.values():
        for local, entry in _entries(m, r).items():
            nid = tsid(local[1:]) if local.startswith("@") else tsid(f"{m.name}.{local}")
            if nid in g.nodes and not g.nodes[nid].entry:
                g.nodes[nid].entry = entry

    unresolved_before = sum(g.unresolved.values())
    for m in mods.values():
        for cs in m.calls:
            src = tsid(f"{m.name}.{cs.scope}") if cs.scope else tsid(m.name)
            targets = r.resolve(m, cs)
            if cs.kind in ("ref", "event"):
                # functions handed over by name run later (callbacks, event handlers): "possible"
                targets = [(t, POSSIBLE, ("jsx-event " + (cs.detail or "")) if cs.kind == "event" else "ts-callback-ref")
                           for t, _, _ in targets if not t.startswith("ext:")]
            elif cs.kind == "jsx":
                targets = [(t, c, "jsx-render") for t, c, _ in targets]
            if not targets:
                if cs.kind in ("call", "new") and cs.chain[0] not in JS_GLOBALS:
                    g.unresolved[cs.text[:80]] = g.unresolved.get(cs.text[:80], 0) + 1
                continue
            for tgt, conf, via in targets:
                if tgt.startswith("ext:"):
                    g.external(tgt[4:])
                elif tgt not in g.nodes or g.nodes[tgt].kind == MODULE:
                    continue
                if tgt == src:
                    continue
                g.add_edge(src, tgt, kind=MAY_CALL if conf == POSSIBLE else CALLS, confidence=conf,
                           line=cs.line, via=via)

    http = []
    for m in mods.values():
        for h in m.http:
            src = tsid(f"{m.name}.{h.scope}") if h.scope else tsid(m.name)
            http.append({"src": src, "method": h.method, "url": h.url, "raw": h.raw, "file": m.rel,
                         "line": h.line, "client": h.client})
    return {"files": len(mods), "lines": total_lines, "http_calls": http,
            "unresolved_call_sites": sum(g.unresolved.values()) - unresolved_before}
