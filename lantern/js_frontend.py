"""TypeScript / JavaScript frontend: React, Next.js, Vite SPAs, Express/Hono/Fastify servers.

Adds JS/TS modules, functions, components, and classes to the same Unified Code Graph the Python
frontend builds, plus:
  * UI entry points: Next.js pages, file-based routes (TanStack Router), React Router routes,
    SPA mounts (createRoot().render)
  * server entry points: Next.js route handlers and pages/api, Express-style app.get('/x', fn)
  * component rendering (<EditItem/>), callbacks passed as props (onClick={save}), and
  * HTTP calls (fetch, axios, generated API clients), which bridge.py links to backend routes.

Same honesty rules as the Python frontend: every edge records `via` and a confidence level, and
calls that can't be traced are counted, not guessed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_javascript as tsj
import tree_sitter_typescript as tst
from tree_sitter import Language, Node as TSNode, Parser

from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import SKIP_DIRS, inside_repo

LANGS = {
    ".ts": Language(tst.language_typescript()),
    ".mts": Language(tst.language_typescript()),
    ".cts": Language(tst.language_typescript()),
    ".tsx": Language(tst.language_tsx()),
    ".js": Language(tsj.language()),
    ".jsx": Language(tsj.language()),
    ".mjs": Language(tsj.language()),
    ".cjs": Language(tsj.language()),
}
RESOLVE_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
# Globals and browser/runtime APIs: calls to these are noise in a call map.
JS_GLOBALS = {
    "console", "Math", "JSON", "Object", "Array", "String", "Number", "Boolean", "Promise", "Date",
    "Error", "RegExp", "Map", "Set", "WeakMap", "Symbol", "Reflect", "parseInt", "parseFloat",
    "setTimeout", "clearTimeout", "setInterval", "clearInterval", "requestAnimationFrame",
    "document", "window", "globalThis", "navigator", "location", "history", "localStorage",
    "sessionStorage", "encodeURIComponent", "decodeURIComponent", "structuredClone", "queueMicrotask",
    "URL", "URLSearchParams", "FormData", "Headers", "Response", "Request", "Blob", "File",
    "atob", "btoa", "alert", "confirm", "prompt", "require", "process", "Buffer", "isNaN",
    "TextEncoder", "TextDecoder", "AbortController", "crypto", "performance", "fetch",
}
TEST_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^|/)(__tests__|__mocks__|tests?|e2e|cypress|playwright)/")
GENERATED_RE = re.compile(r"\.gen\.[jt]sx?$|(^|/)generated/")


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


def _string_value(n: TSNode | None) -> str | None:
    if n is None:
        return None
    if n.type == "string":
        return "".join(_text(c) for c in n.named_children if c.type in ("string_fragment", "escape_sequence"))
    if n.type == "template_string" and not any(c.type == "template_substitution" for c in n.named_children):
        return "".join(_text(c) for c in n.named_children if c.type == "string_fragment")
    return None


def _chain(n: TSNode | None) -> list[str] | None:
    """Callee expression -> name chain, e.g. ItemsService.updateItem -> ["ItemsService", "updateItem"]."""
    if n is None:
        return None
    t = n.type
    if t in ("identifier", "property_identifier", "type_identifier", "shorthand_property_identifier"):
        return [_text(n)]
    if t == "this":
        return ["this"]
    if t == "member_expression":
        base = _chain(n.child_by_field_name("object"))
        prop = n.child_by_field_name("property")
        if base is None or prop is None:
            return None
        return base + [_text(prop)]
    if t in ("parenthesized_expression", "non_null_expression", "as_expression", "satisfies_expression"):
        inner = n.named_children[0] if n.named_child_count else None
        return _chain(inner)
    if t == "call_expression":
        base = _chain(n.child_by_field_name("function"))
        if base is None:
            return None
        base[-1] += "()"
        return base
    if t in ("jsx_namespace_name", "nested_identifier", "member_expression"):
        return _text(n).split(".")
    return None


def _jsx_name(n: TSNode) -> list[str] | None:
    name = n.child_by_field_name("name")
    if name is None:
        return None
    txt = _text(name)
    if not txt or not (txt[0].isupper() or "." in txt):
        return None  # lowercase = DOM element
    return txt.split(".")


# --------------------------------------------------------------------------------------------
# Per-file results
# --------------------------------------------------------------------------------------------

@dataclass
class JSDef:
    local: str
    name: str
    kind: str                  # function | class | method
    start: int
    end: int
    parent_local: str
    in_class: str | None
    params: str
    fingerprint: str
    jsx: bool = False          # returns JSX: a React component
    entry: dict | None = None


@dataclass
class JSRef:
    scope: str
    parts: list[str]
    line: int
    kind: str                  # call | new | jsx | callback
    ui: str | None = None      # e.g. "onClick" when it happens inside an event handler


@dataclass
class HttpCall:
    scope: str
    method: str
    path: str                  # normalized, e.g. "/api/v1/items/{}"
    raw: str                   # as written, for display
    prefix_unknown: bool
    host: str | None           # external host, if any
    line: int
    ui: str | None = None


@dataclass
class JSModule:
    name: str                  # repo-relative path without extension
    rel: str
    path: Path
    lines: int
    is_test: bool
    defs: dict[str, JSDef] = field(default_factory=dict)
    imports: dict[str, tuple[str | None, str, str]] = field(default_factory=dict)  # local -> (mod, name, spec)
    exports: dict[str, str] = field(default_factory=dict)       # exported -> local
    reexports: list[tuple[str | None, dict | None]] = field(default_factory=list)  # (mod, {exp: imp} | None=*)
    default: str | None = None
    consts: dict[str, str] = field(default_factory=dict)         # module-level string constants
    local_types: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    class_bases: dict[str, list[str]] = field(default_factory=dict)
    refs: list[JSRef] = field(default_factory=list)
    http: list[HttpCall] = field(default_factory=list)
    route_regs: list[dict] = field(default_factory=list)        # express-style, {method, path, handler parts|local}
    page_regs: list[dict] = field(default_factory=list)         # router config, {path, component parts}
    mounts_app: bool = False
    listens: bool = False


# --------------------------------------------------------------------------------------------
# Walker
# --------------------------------------------------------------------------------------------

FUNC_TYPES = {"arrow_function", "function_expression", "function", "generator_function"}
DEF_DECLS = {"function_declaration", "generator_function_declaration"}
CLASS_DECLS = {"class_declaration", "abstract_class_declaration", "class"}
WRAPPERS = {"memo", "forwardRef", "observer", "React.memo", "React.forwardRef", "withRouter", "styled"}


def _contains_jsx(n: TSNode) -> bool:
    stack = [n]
    while stack:
        cur = stack.pop()
        if cur.type in ("jsx_element", "jsx_self_closing_element", "jsx_fragment"):
            return True
        if cur is not n and cur.type in FUNC_TYPES | DEF_DECLS:
            continue  # nested functions don't make the outer one a component
        stack.extend(cur.children)
    return False


def _unwrap_func(value: TSNode | None) -> TSNode | None:
    """`const X = memo((props) => ...)` -> the inner function node."""
    if value is None:
        return None
    if value.type in FUNC_TYPES:
        return value
    if value.type == "call_expression":
        fn = _text(value.child_by_field_name("function"))
        args = value.child_by_field_name("arguments")
        if fn in WRAPPERS and args is not None and args.named_child_count:
            return _unwrap_func(args.named_children[0])
    if value.type in ("parenthesized_expression", "as_expression", "satisfies_expression") and value.named_child_count:
        return _unwrap_func(value.named_children[0])
    return None


class Walker:
    def __init__(self, m: JSModule, resolve_spec):
        self.m = m
        self.resolve_spec = resolve_spec
        self.anon = 0

    # -- defs
    def add_def(self, node: TSNode, name: str, scope: str, kind: str, in_class: str | None,
                outer: TSNode | None = None) -> str:
        local = f"{scope}.{name}" if scope else name
        body = node.child_by_field_name("body")
        params = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
        o = outer or node
        self.m.defs[local] = JSDef(
            local=local, name=name, kind=kind, start=o.start_point[0] + 1, end=o.end_point[0] + 1,
            parent_local=scope, in_class=in_class, params=_text(params)[:200],
            fingerprint=_fingerprint(node), jsx=kind != "class" and body is not None and _contains_jsx(body))
        return local

    def walk(self, n: TSNode, scope: str, cls: str | None = None, ui: str | None = None):
        t = n.type
        if t in ("import_statement",):
            self._import(n)
            return
        if t == "export_statement":
            self._export(n, scope, cls, ui)
            return
        if t in DEF_DECLS:
            name = _text(n.child_by_field_name("name"))
            local = self.add_def(n, name, scope, "function", cls)
            self._walk_body(n, local, None, ui)
            return
        if t in CLASS_DECLS and n.child_by_field_name("name") is not None:
            self._class(n, _text(n.child_by_field_name("name")), scope, ui)
            return
        if t == "variable_declarator":
            self._declarator(n, scope, cls, ui)
            return
        if t == "call_expression":
            self._call(n, scope, cls, ui)
            return
        if t == "new_expression":
            ch = _chain(n.child_by_field_name("constructor"))
            if ch:
                self.m.refs.append(JSRef(scope, ch, n.start_point[0] + 1, "new", ui))
        if t in ("jsx_opening_element", "jsx_self_closing_element"):
            self._jsx(n, scope, cls, ui)
            return
        if t == "pair":
            key = _text(n.child_by_field_name("key")).strip("'\"")
            val = n.child_by_field_name("value")
            sub_ui = key if re.match(r"^on[A-Z]", key) or key in ("mutationFn", "queryFn", "action") else ui
            if val is not None and val.type in ("identifier", "member_expression"):
                ch = _chain(val)
                if ch:
                    self.m.refs.append(JSRef(scope, ch, n.start_point[0] + 1, "callback", sub_ui))
            if val is not None:
                self.walk(val, scope, cls, sub_ui)
            return
        if t == "object" and scope == "" or t == "object":
            self._maybe_router_object(n)
        for c in n.children:
            self.walk(c, scope, cls, ui)

    def _walk_body(self, fn: TSNode, local: str, cls: str | None, ui: str | None):
        for fld in ("parameters", "parameter", "body"):
            c = fn.child_by_field_name(fld)
            if c is not None:
                self.walk(c, local, cls, ui)

    def _class(self, n: TSNode, name: str, scope: str, ui):
        local = self.add_def(n, name, scope, "class", None)
        heritage = next((c for c in n.children if c.type == "class_heritage"), None)
        if heritage is not None:
            ext = next((c for c in heritage.named_children if c.type == "extends_clause"), heritage)
            val = ext.child_by_field_name("value") or (ext.named_children[0] if ext.named_child_count else None)
            ch = _chain(val)
            if ch:
                self.m.class_bases[local] = ch
        body = n.child_by_field_name("body")
        if body is None:
            return
        for c in body.named_children:
            if c.type in ("method_definition", "abstract_method_signature"):
                mname = _text(c.child_by_field_name("name"))
                ml = self.add_def(c, mname, local, "method", local)
                self._walk_body(c, ml, local, ui)
            elif c.type in ("public_field_definition", "field_definition"):
                val = c.child_by_field_name("value")
                fn = _unwrap_func(val)
                if fn is not None:
                    mname = _text(c.child_by_field_name("name") or c.child_by_field_name("property"))
                    ml = self.add_def(fn, mname, local, "method", local, outer=c)
                    self._walk_body(fn, ml, local, ui)
                elif val is not None:
                    self.walk(val, local, local, ui)

    def _declarator(self, n: TSNode, scope: str, cls, ui):
        name_node = n.child_by_field_name("name")
        value = n.child_by_field_name("value")
        if name_node is None:
            return
        name = _text(name_node)
        fn = _unwrap_func(value)
        if fn is not None and name_node.type == "identifier":
            local = self.add_def(fn, name, scope, "function", cls, outer=n)
            self._walk_body(fn, local, None, ui)
            if value is not fn:  # memo(...)/forwardRef(...) wrapper call
                self.walk(value.child_by_field_name("function"), scope, cls, ui)
            return
        if value is not None and value.type in CLASS_DECLS:
            self._class(value, name, scope, ui)
            return
        if value is not None and name_node.type == "identifier":
            sv = self._url_of(value)
            if sv is not None and not scope:
                self.m.consts[name] = sv
            if value.type == "new_expression":
                ch = _chain(value.child_by_field_name("constructor"))
                if ch:
                    self.m.local_types.setdefault(scope, {})[name] = ch
            if value.type == "call_expression":
                fch = _chain(value.child_by_field_name("function"))
                if fch and fch[-1] in ("express", "Router", "Hono", "fastify", "Fastify"):
                    self.m.local_types.setdefault(scope, {})[name] = ["<server>"]
        if value is not None:
            self.walk(value, scope, cls, ui)

    # -- imports / exports
    def _import(self, n: TSNode):
        src = n.child_by_field_name("source")
        spec = _string_value(src) or ""
        target = self.resolve_spec(spec)
        clause = next((c for c in n.named_children if c.type == "import_clause"), None)
        if clause is None:
            return
        for c in clause.named_children:
            if c.type == "identifier":
                self.m.imports[_text(c)] = (target, "default", spec)
            elif c.type == "namespace_import":
                ident = next((x for x in c.named_children if x.type == "identifier"), None)
                if ident is not None:
                    self.m.imports[_text(ident)] = (target, "*", spec)
            elif c.type == "named_imports":
                for s in c.named_children:
                    if s.type != "import_specifier":
                        continue
                    nm = s.child_by_field_name("name")
                    al = s.child_by_field_name("alias")
                    self.m.imports[_text(al or nm)] = (target, _text(nm), spec)

    def _export(self, n: TSNode, scope, cls, ui):
        src = n.child_by_field_name("source")
        decl = n.child_by_field_name("declaration")
        is_default = any(c.type == "default" for c in n.children)
        if src is not None:
            target = self.resolve_spec(_string_value(src) or "")
            clause = next((c for c in n.named_children if c.type == "export_clause"), None)
            if clause is None:
                self.m.reexports.append((target, None))
            else:
                mp = {}
                for s in clause.named_children:
                    if s.type == "export_specifier":
                        nm, al = s.child_by_field_name("name"), s.child_by_field_name("alias")
                        mp[_text(al or nm)] = _text(nm)
                self.m.reexports.append((target, mp))
            return
        if decl is not None:
            before = set(self.m.defs)
            self.walk(decl, scope, cls, ui)
            new = [d for d in self.m.defs if d not in before and "." not in d]
            for d in new:
                self.m.exports[d] = d
            if decl.type in ("lexical_declaration", "variable_declaration"):
                for v in decl.named_children:
                    if v.type == "variable_declarator":
                        nm = _text(v.child_by_field_name("name"))
                        self.m.exports.setdefault(nm, nm)
            if is_default and new:
                self.m.default = new[0]
            return
        clause = next((c for c in n.named_children if c.type == "export_clause"), None)
        if clause is not None:
            for s in clause.named_children:
                if s.type == "export_specifier":
                    nm, al = s.child_by_field_name("name"), s.child_by_field_name("alias")
                    self.m.exports[_text(al or nm)] = _text(nm)
            return
        if is_default:
            val = n.child_by_field_name("value") or next(
                (c for c in n.named_children if c.type not in ("comment", "decorator")), None)
            if val is None:
                return
            if val.type == "identifier":
                self.m.default = _text(val)
                return
            fn = _unwrap_func(val)
            if fn is not None:
                local = self.add_def(fn, "default", scope, "function", None, outer=n)
                self.m.default = local
                self._walk_body(fn, local, None, ui)
                return
            if val.type in CLASS_DECLS:
                nm = _text(val.child_by_field_name("name")) or "default"
                self._class(val, nm, scope, ui)
                self.m.default = nm
                return
            if val.type == "call_expression":
                fch = _chain(val.child_by_field_name("function"))
                args = val.child_by_field_name("arguments")
                first = args.named_children[0] if args is not None and args.named_child_count else None
                if first is not None and first.type == "identifier":   # export default connect(X)
                    self.m.default = _text(first)
            self.walk(val, scope, cls, ui)

    # -- calls
    def _call(self, n: TSNode, scope: str, cls, ui):
        fn = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        line = n.start_point[0] + 1
        ch = _chain(fn)

        # createFileRoute("/path")({ component: X })  (TanStack Router)
        if fn is not None and fn.type == "call_expression":
            inner = _chain(fn.child_by_field_name("function"))
            iargs = fn.child_by_field_name("arguments")
            if inner and inner[-1] in ("createFileRoute", "createLazyFileRoute") and iargs is not None:
                p = _string_value(iargs.named_children[0]) if iargs.named_child_count else None
                obj = argv[0] if argv and argv[0].type == "object" else None
                comp = self._obj_prop(obj, ("component", "Component")) if obj is not None else None
                if p is not None and comp is not None and _chain(comp):
                    self.m.page_regs.append({"path": p, "component": _chain(comp), "line": line})

        # Express / Hono / Fastify route registration: app.get('/x', ..., handler)
        if ch and len(ch) >= 2 and ch[-1] in HTTP_METHODS | {"all"} and argv:
            p = self._url_of(argv[0])
            last = argv[-1]
            if p is not None and p.startswith("/") and len(argv) >= 2 and (
                    last.type in FUNC_TYPES or last.type == "identifier" or last.type == "member_expression"):
                method = ch[-1].upper() if ch[-1] != "all" else "ANY"
                reg = {"method": method, "path": p, "line": line, "scope": scope}
                if last.type in FUNC_TYPES:
                    self.anon += 1
                    local = self.add_def(last, f"{method.lower()}_{_slug(p)}", scope, "function", None)
                    reg["local"] = local
                    for a in argv[:-1]:
                        self.walk(a, scope, cls, ui)
                    self._walk_body(last, local, None, None)
                else:
                    reg["handler"] = _chain(last)
                self.m.route_regs.append(reg)
                return
        if ch and ch[-1] == "listen" and len(ch) >= 2:
            self.m.listens = True
        if ch and ch[-1] in ("render", "hydrate") and (
                (len(ch) >= 2 and ch[-2] in ("createRoot()", "ReactDOM", "hydrateRoot()")) or ch[0] in ("ReactDOM",)):
            self.m.mounts_app = True
        if ch and ch[0] in ("createApp", "createRoot", "hydrateRoot") and len(ch) == 1:
            if ch[0] == "createApp":
                self.m.mounts_app = True

        hch = ch
        if hch is None and fn is not None and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")   # (options.client ?? client).post({...})
            hch = ["<expr>", _text(prop)] if prop is not None else None
        http = self._http(hch, argv, line, scope, ui)
        if http:
            self.m.http.append(http)
        if ch:
            self.m.refs.append(JSRef(scope, ch, line, "call", ui))
        # functions passed as arguments are likely to be called: useEffect(load), map(render)
        for a in argv:
            if a.type == "identifier":
                self.m.refs.append(JSRef(scope, [_text(a)], line, "callback", ui))
        if fn is not None:
            self.walk(fn, scope, cls, ui)
        for a in argv:
            self.walk(a, scope, cls, ui)

    def _obj_prop(self, obj: TSNode | None, keys) -> TSNode | None:
        if obj is None:
            return None
        for p in obj.named_children:
            if p.type == "pair" and _text(p.child_by_field_name("key")).strip("'\"") in keys:
                return p.child_by_field_name("value")
            if p.type == "shorthand_property_identifier" and _text(p) in keys:
                return p
        return None

    def _maybe_router_object(self, obj: TSNode):
        """{ path: "/items", element: <Items/> } or { path, component: Items } (React Router etc.)."""
        pnode = self._obj_prop(obj, ("path",))
        p = _string_value(pnode) if pnode is not None else None
        if p is None:
            return
        comp = self._obj_prop(obj, ("component", "Component", "element"))
        if comp is None:
            return
        parts = None
        if comp.type in ("jsx_self_closing_element", "jsx_element"):
            el = comp if comp.type == "jsx_self_closing_element" else comp.child_by_field_name("open_tag")
            parts = _jsx_name(el) if el is not None else None
        else:
            parts = _chain(comp)
        if parts:
            self.m.page_regs.append({"path": p, "component": parts, "line": obj.start_point[0] + 1})

    def _jsx(self, n: TSNode, scope, cls, ui):
        parts = _jsx_name(n)
        line = n.start_point[0] + 1
        if parts:
            self.m.refs.append(JSRef(scope, parts, line, "jsx", ui))
        attrs = {}
        for a in n.named_children:
            if a.type != "jsx_attribute":
                continue
            kids = a.named_children
            if not kids:
                continue
            aname = _text(kids[0])
            val = kids[1] if len(kids) > 1 else None
            attrs[aname] = val
            sub_ui = aname if re.match(r"^on[A-Z]", aname) or aname == "action" else ui
            if val is not None and val.type == "jsx_expression" and val.named_child_count:
                inner = val.named_children[0]
                if inner.type in ("identifier", "member_expression"):
                    ch = _chain(inner)
                    if ch:
                        self.m.refs.append(JSRef(scope, ch, line, "callback", sub_ui))
                self.walk(inner, scope, cls, sub_ui)
            elif val is not None:
                self.walk(val, scope, cls, sub_ui)
        # <Route path="/x" element={<X/>} /> or component={X}
        if parts and parts[-1] == "Route" and "path" in attrs:
            p = _string_value(attrs["path"]) if attrs["path"] is not None else None
            target = attrs.get("element") or attrs.get("component") or attrs.get("Component")
            comp = None
            if target is not None and target.type == "jsx_expression" and target.named_child_count:
                inner = target.named_children[0]
                if inner.type in ("jsx_self_closing_element", "jsx_element"):
                    el = inner if inner.type == "jsx_self_closing_element" else inner.child_by_field_name("open_tag")
                    comp = _jsx_name(el) if el is not None else None
                else:
                    comp = _chain(inner)
            if p is not None and comp:
                self.m.page_regs.append({"path": p, "component": comp, "line": line})

    # -- HTTP
    def _url_of(self, n: TSNode | None) -> str | None:
        """String-ish expression -> URL pattern with "{}" for dynamic parts; None if not a string."""
        if n is None:
            return None
        t = n.type
        if t == "string":
            return _string_value(n)
        if t == "template_string":
            out = []
            for c in n.named_children:
                if c.type == "string_fragment":
                    out.append(_text(c))
                elif c.type == "template_substitution":
                    inner = c.named_children[0] if c.named_child_count else None
                    if inner is not None and inner.type == "identifier" and _text(inner) in self.m.consts:
                        out.append(self.m.consts[_text(inner)])
                    else:
                        out.append("{}")
            return "".join(out)
        if t == "binary_expression" and _text(n.child_by_field_name("operator")) == "+":
            left, right = self._url_of(n.child_by_field_name("left")), self._url_of(n.child_by_field_name("right"))
            return (left if left is not None else "{}") + (right if right is not None else "{}") \
                if (left is not None or right is not None) else None
        if t == "identifier" and _text(n) in self.m.consts:
            return self.m.consts[_text(n)]
        return None

    def _method_of(self, opts: TSNode | None) -> str:
        """The HTTP verb from a fetch/axios options argument. No options means GET. A verb we can't read (a variable,
        an options object built elsewhere, a spread) is "ANY": the bridge then never claims a confirmed link."""
        if opts is None:
            return "GET"
        if opts.type != "object":
            return "ANY"
        mnode = self._obj_prop(opts, ("method",))
        if mnode is None:
            return "ANY" if any(c.type == "spread_element" for c in opts.named_children) else "GET"
        v = _string_value(mnode)
        return v.upper() if v and v.upper() in {m.upper() for m in HTTP_METHODS} else "ANY"

    def _http(self, ch, argv, line, scope, ui) -> HttpCall | None:
        if not ch:
            return None
        last = ch[-1]
        method, url_node, opts = None, None, None
        if last in ("fetch", "$fetch", "ofetch", "useSWR", "useFetch") and len(ch) <= 2 and argv:
            url_node = argv[0]
            method = self._method_of(argv[1] if len(argv) > 1 else None)
        elif last.lower() in HTTP_METHODS and len(ch) >= 2 and argv:
            method = last.upper()
            if argv[0].type == "object":
                url_node = self._obj_prop(argv[0], ("url",))
            else:
                url_node = argv[0]
        elif (last == "request" and len(ch) >= 2 or ch == ["axios"]) and argv and argv[0].type == "object":
            url_node = self._obj_prop(argv[0], ("url",))
            method = self._method_of(argv[0])
        if method is None or url_node is None:
            return None
        raw = self._url_of(url_node)
        if raw is None:
            return None
        return _normalize_http(raw, method, scope, line, ui)


def _slug(p: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", p).strip("_") or "root"


def _normalize_http(raw: str, method: str, scope: str, line: int, ui) -> HttpCall | None:
    url = raw.strip()
    host = None
    prefix_unknown = False
    m = re.match(r"^(https?:)?//([^/{}]+)(/.*)?$", url)
    if m:
        host = m.group(2)
        url = m.group(3) or "/"
        if host.split(":")[0] in ("localhost", "127.0.0.1", "0.0.0.0"):  # nosec B104: comparing a URL host, not binding
            host = None
    elif url.startswith("{}"):
        prefix_unknown = True       # `${API_URL}/items`
        url = url[2:]
    if not url.startswith("/"):
        return None
    url = url.split("?")[0].split("#")[0]
    segs = [s for s in url.split("/") if s]
    norm = "/" + "/".join("{}" if ("{" in s or s.startswith(":")) else s for s in segs)
    return HttpCall(scope=scope, method=method, path=norm, raw=raw, prefix_unknown=prefix_unknown,
                    host=host, line=line, ui=ui)


# --------------------------------------------------------------------------------------------
# Module resolution (relative paths, tsconfig paths, @/ alias)
# --------------------------------------------------------------------------------------------

def _load_jsonc(p: Path) -> dict:
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    txt = re.sub(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', lambda m: m.group(1) or "", txt, flags=re.S)
    txt = re.sub(r",(\s*[}\]])", r"\1", txt)
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return {}


class SpecResolver:
    def __init__(self, repo: Path, files: dict[str, str]):
        self.repo = repo
        self.files = files            # rel path -> module name
        self._alias_cache: dict[Path, list[tuple[str, list[Path]]]] = {}

    def _aliases(self, d: Path) -> list[tuple[str, list[Path]]]:
        """Path aliases from the nearest tsconfig/jsconfig (and its tsconfig.*.json siblings)."""
        cur = d
        while True:
            if cur in self._alias_cache:
                return self._alias_cache[cur]
            cands = [cur / n for n in ("tsconfig.json", "jsconfig.json")] + sorted(cur.glob("tsconfig.*.json"))
            found: list[tuple[str, list[Path]]] = []
            for c in cands:
                if not c.exists():
                    continue
                co = _load_jsonc(c).get("compilerOptions", {}) or {}
                base = (c.parent / co.get("baseUrl", ".")).resolve()
                for pat, targets in (co.get("paths") or {}).items():
                    found.append((pat, [(base / t).resolve() for t in targets]))
            if found or (cur / "package.json").exists() or cur == self.repo or cur == cur.parent:
                if not found and (cur / "package.json").exists():
                    root = cur / "src" if (cur / "src").is_dir() else cur
                    found = [("@/*", [root.resolve() / "*"]), ("~/*", [root.resolve() / "*"])]
                self._alias_cache[cur] = found
                return found
            cur = cur.parent

    def _try(self, base: Path) -> str | None:
        cands = [base] + [base.with_name(base.name + e) for e in RESOLVE_EXTS] + \
                [base / ("index" + e) for e in RESOLVE_EXTS]
        for c in cands:
            try:
                rel = c.resolve().relative_to(self.repo).as_posix()
            except ValueError:
                continue
            if rel in self.files:
                return self.files[rel]
        return None

    def resolve(self, spec: str, from_file: Path) -> str | None:
        if not spec:
            return None
        if spec.startswith("."):
            return self._try(from_file.parent / spec)
        for pat, targets in self._aliases(from_file.parent):
            if pat.endswith("*") and spec.startswith(pat[:-1]):
                rest = spec[len(pat) - 1:]
                for t in targets:
                    hit = self._try(Path(str(t).replace("*", rest)))
                    if hit:
                        return hit
            elif pat == spec:
                for t in targets:
                    hit = self._try(t)
                    if hit:
                        return hit
        return None   # bare specifier: a package


# --------------------------------------------------------------------------------------------
# Discovery and build
# --------------------------------------------------------------------------------------------

def discover(repo: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if not inside_repo(p, repo):
                continue
            if p.suffix in LANGS and not fn.endswith((".d.ts", ".min.js", ".bundle.js")) \
                    and not fn.startswith(("vite.config", "next.config", "tailwind.config", "postcss.config",
                                           "eslint.config", "jest.config", "vitest.config", "playwright.config",
                                           "webpack.config", "babel.config", "rollup.config")):
                out.append(p)
    return out


def _nearest_package(path: Path, repo: Path, cache: dict) -> dict:
    cur = path.parent
    while True:
        if cur in cache:
            return cache[cur]
        pj = cur / "package.json"
        if pj.exists():
            try:
                data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                data = {}
            deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
            info = {"dir": cur, "deps": set(deps)}
            cache[cur] = info
            return info
        if cur == repo or cur == cur.parent:
            info = {"dir": repo, "deps": set()}
            cache[cur] = info
            return info
        cur = cur.parent


def nid(mod: str, local: str | None = None) -> str:
    return f"js:{mod}" if not local else f"js:{mod}::{local}"


class JSResolver:
    def __init__(self, mods: dict[str, JSModule], g: Graph):
        self.mods, self.g = mods, g

    def lookup_export(self, mod: str | None, name: str, depth: int = 0):
        """Returns ("def", mod, local) | ("ns", mod) | ("ext", name) | None."""
        if mod is None or mod not in self.mods or depth > 8:
            return None
        m = self.mods[mod]
        if name == "*":
            return ("ns", mod)
        local = m.default if name == "default" else m.exports.get(name, name if name in m.defs else None)
        if local is not None:
            if local in m.defs:
                return ("def", mod, local)
            if local in m.imports:
                tmod, tname, spec = m.imports[local]
                return self.lookup_export(tmod, tname, depth + 1) if tmod else ("ext", f"{spec}.{tname}")
        if name == "default":
            return None
        for tmod, mp in m.reexports:
            if mp is None:
                hit = self.lookup_export(tmod, name, depth + 1)
                if hit:
                    return hit
            elif name in mp:
                return self.lookup_export(tmod, mp[name], depth + 1)
        return None

    def bind(self, m: JSModule, scope: str, name: str):
        s = scope
        while s:
            cand = f"{s}.{name}"
            if cand in m.defs and m.defs[s].kind != "class":
                return ("def", m.name, cand)
            s = m.defs[s].parent_local if s in m.defs else ""
        if name in m.defs:
            return ("def", m.name, name)
        if name in m.imports:
            tmod, tname, spec = m.imports[name]
            if tmod is None:
                return ("ext", spec if tname in ("default", "*") else f"{spec}.{tname}")
            return self.lookup_export(tmod, tname)
        return None

    def method(self, mod: str, cls_local: str, name: str, depth: int = 0):
        if depth > 6:
            return None
        m = self.mods[mod]
        if f"{cls_local}.{name}" in m.defs:
            return ("def", mod, f"{cls_local}.{name}")
        base = m.class_bases.get(cls_local)
        if base:
            r = self.resolve_parts(m, m.defs[cls_local].parent_local, base)
            if r and r[0] == "def" and self.mods[r[1]].defs[r[2]].kind == "class":
                return self.method(r[1], r[2], name, depth + 1)
        return None

    def resolve_parts(self, m: JSModule, scope: str, parts: list[str]):
        if any(p.endswith("()") for p in parts):
            return None
        head = parts[0]
        if head == "this":
            enclosing = m.defs.get(scope)
            cls = enclosing.in_class if enclosing else None
            if cls and len(parts) == 2:
                return self.method(m.name, cls, parts[1])
            return None
        r = self.bind(m, scope, head)
        if r is None and len(parts) == 2:
            t = self._local_type(m, scope, head)
            if t:
                tr = self.resolve_parts(m, scope, t)
                if tr and tr[0] == "def" and self.mods[tr[1]].defs[tr[2]].kind == "class":
                    hit = self.method(tr[1], tr[2], parts[1])
                    return (hit[0], hit[1], hit[2], "local-type") if hit else None
        for p in parts[1:]:
            if r is None:
                return None
            if r[0] == "ns":
                r = self.lookup_export(r[1], p)
            elif r[0] == "def":
                d = self.mods[r[1]].defs[r[2]]
                if d.kind != "class":
                    return None
                r = self.method(r[1], r[2], p)
            elif r[0] == "ext":
                r = ("ext", f"{r[1]}.{p}")
        return r

    def _local_type(self, m: JSModule, scope: str, var: str):
        s = scope
        while True:
            t = m.local_types.get(s, {}).get(var)
            if t:
                return t if t != ["<server>"] else None
            if not s:
                return None
            s = m.defs[s].parent_local if s in m.defs else ""


def _route_path_from_file(rel: str, kind: str) -> str | None:
    """Next.js app/pages file -> URL path, e.g. app/(shop)/items/[id]/page.tsx -> /items/[id]."""
    m = re.search(r"(?:^|/)(?:src/)?(app|pages)/(.*)$", rel)
    if not m:
        return None
    segs = m.group(2).split("/")
    last = re.sub(r"\.[cm]?[jt]sx?$", "", segs[-1])
    segs = segs[:-1] + ([] if last in ("page", "route", "index") else [last])
    segs = [s for s in segs if not (s.startswith("(") and s.endswith(")")) and not s.startswith("@")]
    return "/" + "/".join(segs)


def _clean_page_path(p: str) -> str:
    segs = [s for s in p.split("/") if s and not s.startswith("_")]   # TanStack pathless layouts
    return "/" + "/".join(segs)


def add_js(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo).resolve()
    paths = discover(repo)
    if not paths:
        return {"files": 0, "lines": 0}
    files = {}
    for p in paths:
        rel = p.relative_to(repo).as_posix()
        files[rel] = re.sub(r"\.[cm]?[jt]sx?$", "", rel)
    spec = SpecResolver(repo, files)
    parsers = {ext: Parser(lang) for ext, lang in LANGS.items()}
    mods: dict[str, JSModule] = {}
    pkg_cache: dict = {}
    total = 0
    for p in paths:
        rel = p.relative_to(repo).as_posix()
        try:
            src = p.read_bytes()
        except OSError:
            continue
        if len(src) > 1_500_000:
            continue
        total += src.count(b"\n") + 1
        tree = parsers[p.suffix].parse(src)
        m = JSModule(name=files[rel], rel=rel, path=p, lines=src.count(b"\n") + 1, is_test=bool(TEST_RE.search(rel)))
        w = Walker(m, lambda s, _p=p: spec.resolve(s, _p))
        for c in tree.root_node.children:
            w.walk(c, "")
        mods[m.name] = m

    r = JSResolver(mods, g)
    # nodes
    for m in mods.values():
        g.add_node(Node(id=nid(m.name), kind=MODULE, name=Path(m.rel).name, qualname=m.name, file=m.rel,
                        start_line=1, end_line=m.lines))
        for d in m.defs.values():
            parent = nid(m.name, d.parent_local) if d.parent_local else nid(m.name)
            sig = f"class {d.name}" if d.kind == "class" else f"{'component ' if d.jsx else ''}{d.name}{d.params}"
            g.add_node(Node(id=nid(m.name, d.local), kind=CLASS if d.kind == "class" else CALLABLE,
                            name=d.name, qualname=f"{m.name}::{d.local}", file=m.rel, start_line=d.start,
                            end_line=d.end, parent=parent, fingerprint=d.fingerprint, signature=sig[:200]))
            g.add_edge(parent, nid(m.name, d.local), kind=CONTAINS)

    def target_id(res) -> str | None:
        if res is None:
            return None
        if res[0] == "def":
            d = mods[res[1]].defs[res[2]]
            if d.kind == "class":
                ctor = r.method(res[1], res[2], "constructor")
                return nid(ctor[1], ctor[2]) if ctor else nid(res[1], res[2])
            return nid(res[1], res[2])
        return None

    unresolved = 0
    for m in mods.values():
        for ref in m.refs:
            src_id = nid(m.name, ref.scope) if ref.scope and ref.scope in m.defs else nid(m.name)
            if ref.parts[0] in JS_GLOBALS and ref.kind != "jsx":
                continue
            res = r.resolve_parts(m, ref.scope, ref.parts)
            if res is None:
                if ref.kind == "call" and ref.parts[0] not in ("this",) and not m.is_test:
                    unresolved += 1
                    g.unresolved[".".join(ref.parts)[:120]] = g.unresolved.get(".".join(ref.parts)[:120], 0) + 1
                continue
            if res[0] == "ext":
                if ref.kind == "call" and not res[1].startswith(("react.", "react")):
                    name = _ext_js(res[1])
                    g.external(name)
                    g.add_edge(src_id, f"ext:{name}", kind=CALLS, confidence=RESOLVED, line=ref.line,
                               via="import", detail=ref.ui)
                continue
            tid = target_id(res)
            if tid is None or tid == src_id or tid not in g.nodes:
                continue
            if ref.kind == "callback":
                if g.nodes[tid].kind != CALLABLE:
                    continue
                conf, via = INFERRED, ("ui-event" if ref.ui and ref.ui.startswith("on") else "callback")
            elif ref.kind == "jsx":
                conf, via = RESOLVED, "jsx-render"
            else:
                conf = INFERRED if len(res) > 3 else RESOLVED
                via = res[3] if len(res) > 3 else ("constructor" if ref.kind == "new" else "name")
            g.add_edge(src_id, tid, kind=CALLS, confidence=conf, line=ref.line, via=via, detail=ref.ui)

    # entries
    for m in mods.values():
        pkg = _nearest_package(m.path, repo, pkg_cache)
        is_next = "next" in pkg["deps"]
        rel_pkg = m.path.relative_to(pkg["dir"]).as_posix() if pkg["dir"] in m.path.parents else m.rel
        if m.is_test:
            g.nodes[nid(m.name)].entry = {"kind": "test", "detail": m.rel}
            continue
        if is_next:
            fn = Path(m.rel).name
            if re.search(r"(^|/)(src/)?app/", rel_pkg) and re.match(r"page\.[jt]sx?$", fn) and m.default in m.defs:
                g.nodes[nid(m.name, m.default)].entry = {"kind": "page", "detail": _route_path_from_file(rel_pkg, "page")}
            elif re.search(r"(^|/)(src/)?app/", rel_pkg) and re.match(r"route\.[jt]sx?$", fn):
                path = _route_path_from_file(rel_pkg, "route")
                for verb in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    local = m.exports.get(verb)
                    if local and local in m.defs:
                        g.nodes[nid(m.name, local)].entry = {"kind": "route", "detail": f"{verb} {path}"}
            elif re.search(r"(^|/)(src/)?pages/api/", rel_pkg) and m.default in m.defs:
                g.nodes[nid(m.name, m.default)].entry = {"kind": "route", "detail": f"ANY {_route_path_from_file(rel_pkg, 'api')}"}
            elif re.search(r"(^|/)(src/)?pages/", rel_pkg) and m.default in m.defs \
                    and not re.match(r"_(app|document|error)\.", fn):
                g.nodes[nid(m.name, m.default)].entry = {"kind": "page", "detail": _route_path_from_file(rel_pkg, "page")}
        for reg in m.page_regs:
            res = r.resolve_parts(m, "", reg["component"])
            tid = target_id(res)
            if tid and tid in g.nodes and not g.nodes[tid].entry:
                g.nodes[tid].entry = {"kind": "page", "detail": _clean_page_path(reg["path"])}
        for reg in m.route_regs:
            if "local" in reg:
                tid = nid(m.name, reg["local"])
            else:
                tid = target_id(r.resolve_parts(m, reg["scope"], reg["handler"] or []))
            if tid and tid in g.nodes:
                g.nodes[tid].entry = {"kind": "route", "detail": f"{reg['method']} {reg['path']}"}
        if m.mounts_app:
            g.nodes[nid(m.name)].entry = {"kind": "main", "detail": f"app start ({m.rel})"}
        elif m.listens and m.route_regs:
            g.nodes[nid(m.name)].entry = {"kind": "main", "detail": f"server start ({m.rel})"}

    http_calls = []
    for m in mods.values():
        for h in m.http:
            src_id = nid(m.name, h.scope) if h.scope and h.scope in m.defs else nid(m.name)
            http_calls.append({"src": src_id, "method": h.method, "path": h.path, "raw": h.raw,
                               "prefix_unknown": h.prefix_unknown, "host": h.host, "line": h.line,
                               "ui": h.ui, "file": m.rel})
    g.meta.setdefault("http_calls", []).extend(http_calls)
    return {"files": len(mods), "lines": total, "unresolved": unresolved,
            "components": sum(1 for m in mods.values() for d in m.defs.values() if d.jsx),
            "http_calls": len(http_calls)}


def _ext_js(spec: str) -> str:
    parts = spec.split(".")
    if spec.startswith("@") and "/" in parts[0]:
        return ".".join(parts[:2])
    return ".".join(parts[:2])


def jwt_role(token: str) -> str | None:
    """Decode a JWT payload (no verification) and return its `role` claim, if any."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except (IndexError, ValueError, json.JSONDecodeError, AttributeError):
        return None
