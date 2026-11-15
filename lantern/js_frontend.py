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
import bisect
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_javascript as tsj
import tree_sitter_typescript as tst
from tree_sitter import Language, Node as TSNode, Parser

from . import calls, deep, manifest
from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import inside_repo, project_bytes, project_text, skipped_dir

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
HTML_EXTS = {".html", ".htm"}   # script written inside a page (an app's own pages, Jinja/Django templates, index.html)
# <script> blocks that hold JavaScript: no type, a JavaScript type, or a module. JSON, templates, importmaps and
# JSX-in-the-browser (text/babel) are left alone.
_SCRIPT_RE = re.compile(rb"<script\b([^>]*)>(.*?)</script\s*>", re.I | re.S)
_JS_TYPES = {b"", b"module", b"text/javascript", b"application/javascript", b"text/ecmascript", b"application/ecmascript"}

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
# What `x.use(...)` is handed that is no check before a route. A library's router or app under the name the code gives
# it (`authRoutes`, `adminRouter`, `api`): named for what it serves. Passport's `authenticate('session')` reads who is
# signed in from the session and lets a visitor who is not signed in through (`passport.session()` is the same thing).
ROUTER_NAME = re.compile(r"(?:Router|Routers|Routes|Route|Controller|Controllers|Api|App|^router|^routes|^api|^app)$")
SESSION_ONLY = re.compile(r"\bauthenticate\(\s*['\"`]session['\"`]")
# A library's login made with the word that it is not required (`expressjwt({ ..., credentialsRequired: false })`,
# `auth({ authRequired: false })`): it reads who is calling when a token was sent, and turns nobody away.
OPTIONAL_LOGIN = re.compile(r"\b(credentialsRequired|authRequired)['\"]?\s*:\s*false\b")
# `app.all('*', mw)`, `app.all('/api/*', mw)`: every verb of every path, or of every path under one (group `pre`).
ALL_UNDER = re.compile(r"^(?P<pre>(/[\w:.\-]+)*)/?(\*\w*|\(\.\*\)|\{\*\w+\})$")
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
# More built-ins of the language, Node and the browser, for the call-site inventory (calls.py) only. The map keeps
# JS_GLOBALS as it was (calls to those are not counted at all), so its edge-line count stays comparable across versions;
# a call to one of these is still counted unresolved there, and named a built-in in the inventory.
JS_BUILTINS = JS_GLOBALS | {
    "setImmediate", "clearImmediate", "isFinite", "eval", "escape", "unescape", "Intl", "BigInt", "Proxy", "WeakSet",
    "WeakRef", "FinalizationRegistry", "ArrayBuffer", "SharedArrayBuffer", "DataView", "Int8Array", "Uint8Array",
    "Uint8ClampedArray", "Int16Array", "Uint16Array", "Int32Array", "Uint32Array", "Float32Array", "Float64Array",
    "BigInt64Array", "BigUint64Array", "TypeError", "RangeError", "SyntaxError", "ReferenceError", "EvalError",
    "URIError", "AggregateError", "Function", "Atomics", "WebAssembly", "getComputedStyle", "matchMedia",
    "IntersectionObserver", "ResizeObserver", "MutationObserver", "PerformanceObserver", "CustomEvent", "Event",
    "EventTarget", "Image", "Audio", "Option", "XMLHttpRequest", "WebSocket", "EventSource", "Worker", "SharedWorker",
    "BroadcastChannel", "MessageChannel", "caches", "indexedDB", "customElements", "screen", "scrollTo", "scrollBy",
    "open", "close", "print", "postMessage", "addEventListener", "removeEventListener", "dispatchEvent",
    "getSelection", "cancelAnimationFrame", "requestIdleCallback", "cancelIdleCallback", "DOMParser", "XMLSerializer",
    "FileReader", "Notification", "ReadableStream", "WritableStream", "TransformStream", "AbortSignal",
    "DOMException", "self", "global", "__dirname", "__filename",
}
# Supabase (roadmap stage 1): `<client>.from("<table>").<one of these>(…)` is a call into that table. A value is a
# client by where it came from: what one of the libraries' own makers handed back, or a value of the written type
DB_OPS = ("select", "insert", "update", "upsert", "delete")
# What a file says of itself in its first statements, before any code. `"use client"`: the file and what it loads
# run in the browser. `"use server"`: what it exports runs on the server, also when a client file calls it.
DIRECTIVES = ("use client", "use server")
# The frameworks that run Server Actions: with one of them among the nearest package.json's libraries, a function
# marked "use server" gets an address of its own on the server. With none, the words do nothing.
SERVER_ACTIONS = {"next", "waku", "react-server-dom-webpack", "react-server-dom-turbopack", "react-server-dom-parcel"}
# tRPC (roadmap of 2026-11-14, stage 1). A tRPC app has no route files: `createTRPCRouter({ create:
# protectedProcedure.input(…).mutation(fn) })` makes `post.create` an address. Read only where the nearest
# package.json depends on `@trpc/server`; a router is told by its shape here and by what made it in `_trpc_plan`.
TRPC_SERVER = "@trpc/server"
TRPC_ROUTER = re.compile(r"^\w*[Rr]outers?$")     # the last name of what is called: router, createTRPCRouter, mergeRouters
TRPC_MERGE = re.compile(r"^\w*[Mm]erge\w*Routers?$")
TRPC_KINDS = {"query": "GET", "mutation": "POST", "subscription": "GET"}    # how tRPC's client sends each kind
TRPC_STEPS = {"use", "input", "output", "meta", "concat", "unstable_concat"}   # what a procedure is built up with
TRPC_ADAPTERS = {"fetchRequestHandler", "createNextApiHandler", "createExpressMiddleware", "createHTTPServer",
                 "createHTTPHandler", "awsLambdaRequestHandler", "createKoaMiddleware", "nodeHTTPRequestHandler"}
TRPC_AT_ROOT = {"createHTTPServer", "createHTTPHandler"}    # served at the address itself when no path is written
# What a call through tRPC's client ends in. The hooks and option makers are tRPC's own names: a call that ends in
# one, on a path that is a procedure, is a link even where the client is not followed ("likely"). `query` and
# `mutate` are everyday names: a link only on a client that tRPC's own function made.
TRPC_HOOKS = {"useQuery", "useMutation", "useSuspenseQuery", "useInfiniteQuery", "useSuspenseInfiniteQuery",
              "useSubscription", "usePrefetchQuery", "queryOptions", "mutationOptions", "infiniteQueryOptions",
              "subscriptionOptions"}
TRPC_CALLS = {"query", "mutate", "mutateAsync", "subscribe"}
# SvelteKit (roadmap of 2026-11-14, stage 1). The doors of a SvelteKit app are files with fixed names under
# `src/routes`: `+server.ts` (a function per verb), `+page.server.ts` (`load` hands the page its data, each of
# `actions` is what a form posts to), `+layout.server.ts` (`load` for every page below it); `src/hooks.server.ts`
# (`handle`) runs before all of them. Read only where the nearest package.json depends on `@sveltejs/kit`. A
# `.svelte` file is read wherever it is: its `<script>` as code, its markup for the components it draws, the
# functions it hands to events, the expressions it shows and the forms that post.
SVELTE_EXT = ".svelte"
KIT = "@sveltejs/kit"
SVELTE_CONFIGS = ("svelte.config.js", "svelte.config.ts", "svelte.config.mjs")
KIT_VERBS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
KIT_FILE = re.compile(r"^src/routes/(?P<dir>(?:[^/]+/)*)\+(?P<kind>page\.server|layout\.server|server|page|layout)"
                      r"(?:@[^./]*)?\.(?P<ext>[jt]s|svelte)$")
KIT_HOOKS = re.compile(r"^src/hooks\.server(?:/index)?\.[jt]s$")
_SVELTE_TS = re.compile(rb"\blang\s*=\s*[\"']?(?:ts|typescript)\b", re.I)
_SVELTE_MODULE = re.compile(rb"\bmodule\b", re.I)     # <script module>, <script context="module">: the file's own
_STYLE_RE = re.compile(rb"<style\b[^>]*>.*?</style\s*>", re.I | re.S)
_COMMENT_RE = re.compile(rb"<!--.*?-->", re.S)
_SVELTE_BLOCK = re.compile(rb"\s*(#if|:else\s+if|#key|@html|@render|#await|#each)\s+")
_SVELTE_NAMES = re.compile(rb"\s*(?::then|:catch|#snippet)\s+([^}]*)")
_SVELTE_EACH_AS, _SVELTE_AWAIT_THEN = re.compile(rb"\s+as\s"), re.compile(rb"\s+(?:then|catch)\b")
_SVELTE_ATTR = re.compile(rb"([\w:|.$-]+)\s*=\s*[\"']?$")
_SVELTE_TAG = re.compile(rb"<([A-Z][\w$]*(?:\.[\w$]+)*)(?=[\s/>])")
_SVELTE_NOT_PLAIN = re.compile(rb"\{|(?:async\s+)?function\b|class\b")
_SVELTE_OPEN = re.compile(rb"<[A-Za-z][\w:.-]*")     # where a tag opens: an attribute is one only inside a tag
_FORM_OPEN = re.compile(rb"<form(?=[\s>])")          # `<Form …>` with a capital is a component, not the page's form
# Svelte's own words, which its compiler turns into code (`let n = $state(0)`): in a `.svelte` file and in a
# `.svelte.js` / `.svelte.ts` file, nowhere else
SVELTE_RUNES = frozenset(("$state", "$derived", "$effect", "$props", "$bindable", "$inspect", "$host"))
RUNE_FILE = re.compile(r"\.svelte\.[jt]s$")
# `import { a } from "./util.js"` where the file is `util.ts`: how TypeScript itself reads an import in a project
# that ships modules. Only where no file of the written name is there.
TS_FOR = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
_FORMACTION = re.compile(rb"(?<![\w:.$-])formaction\s*=\s*(?:\"([^\"{}]*)\"|'([^'{}]*)')", re.I)
_JS_NAME = re.compile(rb"[A-Za-z_$][\w$]*")
# `onclick={…}` (Svelte 5) is an event only under a name the browser has; `on:click={…}` (Svelte 4) under any
DOM_EVENTS = frozenset("""click dblclick submit change input keydown keyup keypress focus blur mouseenter mouseleave
    mouseover mouseout mousedown mouseup mousemove pointerdown pointerup pointermove touchstart touchend touchmove
    scroll wheel drag drop dragstart dragend dragover load error reset select contextmenu paste copy cut resize
    toggle close""".split())
SUPABASE_CLIENT = re.compile(r"^@supabase/[\w.-]+\.(create\w*Client\(\)|useSupabaseClient\(\)|SupabaseClient)$")
SUPABASE_NAME = re.compile(r"^_?supabase(_?(client|admin))?$", re.I)   # by its name alone: a possible link, no more
TABLE_NAME = re.compile(r"^[A-Za-z_][\w$]{0,62}$")

JS_LANG = "typescript/javascript"   # the name engine.build_graph gives the language in g.meta["languages"]
# An import of one of these is a file (relative, absolute, a path alias or a package.json "imports" entry), never a
# library: when it does not resolve, the file is missing, and a call through it is not a library call.
FILE_SPEC = (".", "/", "@/", "~/", "#")
TEST_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^|/)(__tests__|__mocks__|tests?|e2e|cypress|playwright)/")
GENERATED_RE = re.compile(r"\.gen\.[jt]sx?$|(^|/)generated/")


def _text(n: TSNode | None) -> str:
    return n.text.decode("utf8", "replace") if n is not None else ""


def _head(src: bytes, n: TSNode | None, keep: int = 120) -> str:
    """The start of a node's text with every run of white space as one space, at least as much of it as the call
    inventory keeps of a callee (`calls.record`), without taking the whole text first: the callee of the outermost
    call of a chain is the whole chain, and one chain of a hundred thousand calls, each asked for its callee's text,
    was megabytes for every call of it."""
    if n is None:
        return ""
    start, end = n.start_byte, n.end_byte
    size = 4 * keep + 32
    while True:
        cut = min(end, start + size)
        text = re.sub(r"\s+", " ", src[start:cut].decode("utf8", "replace"))
        if cut >= end or len(text) > keep + 1:
            return text if cut >= end else text[:keep + 1]
        size *= 4


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
        fnn = n.child_by_field_name("function")
        if fnn is not None and fnn.type == "identifier" and _text(fnn) == "require":
            spec = _require_spec(n)
            if spec is not None:   # require('x') reads as one name: `require:x` (bound by JSResolver.bind)
                return [f"require:{spec}"]
        base = _chain(fnn)
        if base is None:
            return None
        base[-1] += "()"
        return base
    if t in ("jsx_namespace_name", "nested_identifier", "member_expression"):
        return _text(n).split(".")
    return None


def _require_spec(call: TSNode) -> str | None:
    """`require('x')` -> "x"; a require of anything but a written string -> None."""
    args = call.child_by_field_name("arguments")
    argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
    return _string_value(argv[0]) if len(argv) == 1 else None


def _pattern_names(n: TSNode | None) -> list[str]:
    """The names a binding pattern introduces: x, {a, b: c}, [d, e], ...rest, f = 1."""
    if n is None:
        return []
    t = n.type
    if t in ("identifier", "shorthand_property_identifier_pattern"):
        return [_text(n)]
    if t in ("assignment_pattern", "object_assignment_pattern"):
        return _pattern_names(n.child_by_field_name("left"))
    if t == "pair_pattern":
        return _pattern_names(n.child_by_field_name("value"))
    if t in ("object_pattern", "array_pattern", "rest_pattern"):
        return [x for c in n.named_children for x in _pattern_names(c)]
    return []


def _type_chain(tn: TSNode | None) -> list[str] | None:
    """A written TypeScript type -> name chain: `Request` -> ["Request"], `express.Response` -> ["express",
    "Response"], `Store<T>` -> ["Store"]. Unions, objects, functions and the like -> None."""
    if tn is not None and tn.type == "type_annotation":
        tn = tn.named_children[0] if tn.named_child_count else None
    if tn is None:
        return None
    if tn.type == "type_identifier":
        return [_text(tn)]
    if tn.type == "nested_type_identifier":
        return _text(tn).split(".")
    if tn.type == "generic_type":
        return _type_chain(tn.child_by_field_name("name"))
    return None


def _params(node: TSNode | None) -> list[tuple[str, list[str] | None]]:
    """A function's own parameters, in order, as (name, written type or None); destructured names have no type."""
    if node is None:
        return []
    if node.type == "identifier":          # x => ...
        return [(_text(node), None)]
    out: list[tuple[str, list[str] | None]] = []
    for c in node.named_children:
        if c.type in ("required_parameter", "optional_parameter"):
            pat = c.child_by_field_name("pattern")
            typ = _type_chain(next((x for x in c.named_children if x.type == "type_annotation"), None))
            names = _pattern_names(pat)
            if pat is not None and pat.type == "identifier":
                out.append((names[0], typ))
            else:
                out.extend((x, None) for x in names)
        else:
            out.extend((x, None) for x in _pattern_names(c))
    return out


def _site_pos(n: TSNode) -> tuple[int, int]:
    """(line, column from 1) that identifies a call site: its "(" (the template of a tagged template), or the
    component name of a JSX element, or where the expression starts."""
    if n.type in ("call_expression", "new_expression"):
        a = n.child_by_field_name("arguments")
        if a is not None:
            return a.start_point[0] + 1, a.start_point[1] + 1
    elif n.type in ("jsx_opening_element", "jsx_self_closing_element"):
        nm = n.child_by_field_name("name")
        if nm is not None:
            return nm.start_point[0] + 1, nm.start_point[1] + 1
    return n.start_point[0] + 1, n.start_point[1] + 1


def _directives(root: TSNode) -> set[str]:
    """The directives a file begins with (`DIRECTIVES`): statements that are one text and nothing else, before the
    first statement that is anything else. A text further down is a text."""
    out: set[str] = set()
    for c in root.named_children:
        if c.type == "comment":
            continue
        inner = c.named_children[0] if c.type == "expression_statement" and c.named_child_count == 1 else None
        if inner is None or inner.type != "string":
            break
        said = _text(inner)[1:-1]
        if said in DIRECTIVES:
            out.add(said)
    return out


def _or_new(value: TSNode | None) -> TSNode | None:
    """`kept ?? new T()`, `kept || new T()` -> the `new T()`: how an app keeps one client across reloads. Whichever
    side is taken, the code uses the value as the class it would make. `&&` and a `new` on the left are not this."""
    v = _unparen(value)
    if v is None or v.type != "binary_expression":
        return None
    op = v.child_by_field_name("operator")
    right = _unparen(v.child_by_field_name("right"))
    if op is None or _text(op) not in ("??", "||") or right is None or right.type != "new_expression":
        return None
    return right


def _unparen(n: TSNode | None) -> TSNode | None:
    while n is not None and n.type == "parenthesized_expression" and n.named_child_count:
        n = n.named_children[0]
    return n


def _bare(n: TSNode | None) -> TSNode | None:
    """The expression inside brackets, `as T`, `satisfies T` and `!`."""
    for _ in range(8):
        n = _unparen(n)
        if n is None or n.type not in ("as_expression", "satisfies_expression", "non_null_expression") or \
                not n.named_child_count:
            break
        n = n.named_children[0]
    return n


def _trpc_spine(call: TSNode | None):
    """`base.input(x).use(mw).mutation(fn)` -> (["base"], [("input", [x]), ("use", [mw]), ("mutation", [fn])]): what a
    chain of calls is built on, and each call hung on it, in the order written."""
    steps: list[tuple[str, list]] = []
    cur = _bare(call)
    for _ in range(24):
        if cur is None or cur.type != "call_expression":
            break
        fnn = _bare(cur.child_by_field_name("function"))
        if fnn is None or fnn.type != "member_expression":
            break
        args = cur.child_by_field_name("arguments")
        steps.append((_text(fnn.child_by_field_name("property")),
                      [a for a in (args.named_children if args is not None else []) if a.type != "comment"]))
        cur = _bare(fnn.child_by_field_name("object"))
    steps.reverse()
    return (_chain(cur) if cur is not None else None), steps


def _call_nodes(root: TSNode):
    """Every call written in a file: calls, `new`, and JSX elements that name a component (a render)."""
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in ("call_expression", "new_expression"):
            yield n
        elif n.type in ("jsx_opening_element", "jsx_self_closing_element") and _jsx_name(n):
            yield n
        stack.extend(n.children)


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
    member: bool = False       # stored as a property (`X.y = function`, `this.x = …`, `X.prototype.y = …`): no name in scope
    lexical: str | None = None  # where the function is written, when that differs from parent_local (names it can see)
    server: bool = False       # its own body begins with "use server": a Server Action written inside another function


@dataclass
class JSRef:
    scope: str
    parts: list[str]
    line: int
    kind: str                  # call | new | jsx | callback | computed | registration | wrapper
    ui: str | None = None      # e.g. "onClick" when it happens inside an event handler
    at: tuple[int, int] | None = None   # (line, column from 1) of the call's "(": the call site's identity
    text: str = ""             # the callee as written
    args: list[list[str]] | None = None   # names handed to the calls inside the callee: getRepository(User).find
    db: dict | None = None     # `<recv>.from("<table>").<op>(…)`: {recv, schema, table | const, op} (Walker._db_shape)


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
    recv: list[str] | None = None   # what the verb was called on (`router` in router.get(...)), when it has a name


@dataclass
class JSModule:
    name: str                  # repo-relative path without extension
    rel: str
    path: Path
    lines: int
    is_test: bool
    html: bool = False         # script taken from inside an HTML page (module name keeps the .html)
    svelte: bool = False       # a Svelte component file (module name keeps the .svelte)
    runes: bool = False        # ... or a `.svelte.ts` file: Svelte's own words (`$state`) are the language's here
    kit_handles: list[tuple] = field(default_factory=list)   # `handle = sequence(a, b)` of hooks.server: (name, at)
    component: str | None = None   # ... and the function that stands for the component: named after the file
    forms: list[dict] = field(default_factory=list)   # the forms of its markup that post: {line, action}
    # `actions` of a SvelteKit `+page.server` file: {key, line, local | handler + at, wrap} (Walker._kit_actions)
    kit_actions: list[dict] = field(default_factory=list)
    defs: dict[str, JSDef] = field(default_factory=dict)
    imports: dict[str, tuple[str | None, str, str]] = field(default_factory=dict)  # local -> (mod, name, spec)
    exports: dict[str, str] = field(default_factory=dict)       # exported -> local
    reexports: list[tuple[str | None, dict | None]] = field(default_factory=list)  # (mod, {exp: imp} | None=*)
    default: str | None = None
    consts: dict[str, str] = field(default_factory=dict)         # module-level string constants
    local_types: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    var_types: dict[str, dict[str, list[str]]] = field(default_factory=dict)   # scope -> name -> written type
    class_bases: dict[str, list[str]] = field(default_factory=dict)
    refs: list[JSRef] = field(default_factory=list)
    http: list[HttpCall] = field(default_factory=list)
    route_regs: list[dict] = field(default_factory=list)        # express-style, {method, path, handler parts|local}
    page_regs: list[dict] = field(default_factory=list)         # router config, {path, component parts}
    params: dict[str, list[str]] = field(default_factory=dict)  # def local -> its own parameter names, in order
    param_types: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # def local -> name -> written type
    anon_params: dict[str, set[str]] = field(default_factory=dict)  # scope -> parameters of inline functions in it
    declared: dict[str, set[str]] = field(default_factory=dict)  # scope -> names declared there (const/let/var/for)
    unread: list[tuple] = field(default_factory=list)   # (at, line, callee text, "inline"|"require"|"other")
    too_deep: list[int] = field(default_factory=list)   # lines where a statement begins that is nested deeper than
    #                                                     the reader follows (`lantern/deep.py`)
    # stage 3 (CommonJS, Express, values): read by JSResolver.resolve_more, never by resolve_parts
    values: dict[str, dict[str, list[str]]] = field(default_factory=dict)   # scope -> name -> chain it was set to
    reassigned: dict[str, set[str]] = field(default_factory=dict)   # scope -> names assigned after they were declared
    dynamic: dict[str, set[str]] = field(default_factory=dict)      # scope -> names set by require(<not a string>)
    export_values: dict[str, list[str]] = field(default_factory=dict)   # export name ("default") -> chain
    export_new: dict[str, list[str]] = field(default_factory=dict)      # export name -> class of `new X()`
    cjs_from: str | None = None       # module.exports = require('./other')
    ctors: set[str] = field(default_factory=set)      # functions given methods: this.x = function, X.prototype.y
    wrapped: set[str] = field(default_factory=set)    # defs read from `const f = wrap(function ...)`
    param_lists: dict[str, list[list[str]]] = field(default_factory=dict)   # scope -> inline functions' parameters
    cb_params: dict[str, dict[str, tuple | None]] = field(default_factory=dict)  # scope -> name -> (callee, arg, i)
    mounts: list[dict] = field(default_factory=list)  # x.use('/prefix', router...): {recv, scope, prefix, targets}
    alls: list[dict] = field(default_factory=list)    # x.all('*', mw...): the same shape, with `whole`
    optional: set[str] = field(default_factory=set)   # names given a library's login made not to be required
    required: dict[str, set[str]] = field(default_factory=dict)  # scope -> names bound there by `x = require('…')`
    returns: dict[str, set[str]] = field(default_factory=dict)   # function -> what its own `return` statements give:
    #                                                              a variable's name, or "" for anything else
    returned: dict[str, list] = field(default_factory=dict)      # function -> each own `return`'s value as a chain
    #                                                              (a name, a member, a call, `await` of one), or None
    # functions the code puts on an object that is not this file's own function or class (JSResolver.own_names).
    # `put`: by assignment, (scope, owner chain, name, right-hand chain or None for a function written there):
    # `schema.statics.x = function`, `res.x = helper`. `given`: in an object or by name, (scope, name, chain or
    # None): `schema.methods = { x () {} }`, `{ methods: { x () {} } }`, `schema.method('x', fn)`,
    # `Object.assign(obj, { x () {} })`. `plain`: scope -> variables set to an object written there (`const api = {}`)
    # or to `this`.
    put: list[tuple[str, list[str], str, list[str] | None]] = field(default_factory=list)
    given: list[tuple[str, str, list[str] | None]] = field(default_factory=list)
    plain: dict[str, set[str]] = field(default_factory=dict)
    value_args: dict[str, dict[str, list[list[str]]]] = field(default_factory=dict)   # scope -> name -> the names
    #                                                         handed to the calls the variable was set from
    mounts_app: bool = False
    listens: bool = False
    # tRPC (roadmap of 2026-11-14, stage 1), read only where the package depends on @trpc/server (Walker._trpc_*):
    # `trpc_routers`: {name, scope, line, callee (None for an object written out), items}, an item being
    # {key, kind "procedure", type, base, uses, line, local | handler + at}, {key, kind "router", chain | inline}
    # or {kind "spread", chain | inline}; `trpc_bases`: (scope, name) -> {base, uses} for `const x = base.use(fn)`;
    # `trpc_mounts`: {scope, line, endpoint, router | inline, adapter}, where the whole is served
    trpc_routers: list[dict] = field(default_factory=list)
    trpc_bases: dict[tuple[str, str], dict] = field(default_factory=dict)
    trpc_mounts: list[dict] = field(default_factory=list)
    directives: set[str] = field(default_factory=set)   # of DIRECTIVES, the ones the file begins with


# --------------------------------------------------------------------------------------------
# Walker
# --------------------------------------------------------------------------------------------

FUNC_TYPES = {"arrow_function", "function_expression", "function", "generator_function"}
# The node types whose children are statements, read one by one (`Walker.each`): a statement nested deeper than the
# reader follows is left alone and the ones after it are still read.
STATEMENT_LISTS = ("program", "statement_block")
DEF_DECLS = {"function_declaration", "generator_function_declaration"}
CLASS_DECLS = {"class_declaration", "abstract_class_declaration", "class"}
WRAPPERS = {"memo", "forwardRef", "observer", "React.memo", "React.forwardRef", "withRouter", "styled"}
# `const f = wrap(async (req, res) => ...)`: a helper that returns a function around the one it is given (catchAsync,
# asyncHandler, debounce). Calls that return something else are left alone: hooks, timers, effects, promises, tests.
NOT_WRAPPERS = {
    "useMemo", "useEffect", "useLayoutEffect", "useInsertionEffect", "useState", "useReducer", "useRef", "useQuery",
    "useMutation", "useSWR", "useInfiniteQuery", "useSyncExternalStore", "useImperativeHandle", "useTransition",
    "setTimeout", "setInterval", "setImmediate", "requestAnimationFrame", "requestIdleCallback", "queueMicrotask",
    "computed", "watch", "watchEffect", "reactive", "ref", "readonly", "shallowRef", "createSelector",
    "createAsyncThunk", "createSlice", "createStore", "create", "defineStore", "describe", "it", "test", "beforeEach",
    "afterEach", "beforeAll", "afterAll", "expect", "Promise", "require", "import", "eval", "Function", "fetch",
    "addEventListener", "then", "catch", "finally", "map", "filter", "reduce", "forEach", "find", "some", "every",
    "flatMap", "sort", "run", "exec", "call", "apply", "bind", "lazy", "createContext", "styled", "css",
}
MEMBER_WRAPPERS = {"debounce", "throttle", "once", "memoize", "wrap", "catchAsync", "asyncHandler"}
# Method names JavaScript's own objects have (arrays, strings, maps, promises, emitters, streams, DOM nodes). A class
# of the repo with a method of such a name says nothing about what `req.session` or `req.user` holds
# (JSResolver.own_names).
EVERYDAY_MEMBERS = frozenset("""
    at concat entries every fill filter find findIndex findLast flat flatMap forEach includes indexOf join keys
    lastIndexOf map pop push reduce reduceRight reverse shift slice some sort splice unshift values charAt charCodeAt
    endsWith localeCompare match matchAll normalize padEnd padStart repeat replace replaceAll search split startsWith
    substring toLowerCase toUpperCase trim trimEnd trimStart toString valueOf toJSON hasOwnProperty call apply bind
    get set has delete add clear then catch finally next return throw test exec on once off emit addListener
    removeListener addEventListener removeEventListener dispatchEvent write end pipe read close open send json text
    abort destroy append remove focus blur click submit reset play pause log error warn info debug constructor
""".split())
ATTACH_KEYS = ("methods", "statics")   # `{ methods: { x () {} } }`: functions a library puts on its own objects
ATTACH_CALLS = ("method", "static")    # `schema.method('x', fn)`, `schema.static({ x () {} })`
MERGE_CALLS = (["Object", "assign"], ["_", "extend"], ["_", "assign"], ["$", "extend"])   # (target, { x () {} })
# Express handler parameters, by position: (req, res, next) and the error form (err, req, res, next)
REQ_NAMES, RES_NAMES = ("req", "request"), ("res", "response")


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


def _spine_args(n: TSNode | None) -> list[list[str]]:
    """`await getRepository(User).findOne(q)` -> [["q"], ["User"]]: the names handed to the calls a value comes from
    (a class handed to a library may come back as an instance of it)."""
    out: list[list[str]] = []
    for _ in range(16):
        n = _unparen(n) if n is not None else None
        if n is None:
            break
        if n.type == "call_expression":
            args = n.child_by_field_name("arguments")
            for a in (args.named_children if args is not None else []):
                a = _unparen(a)
                ch = _chain(a) if a is not None and a.type in ("identifier", "member_expression") else None
                if ch and not any(x.endswith("()") for x in ch):
                    out.append(ch)
            n = n.child_by_field_name("function")
        elif n.type == "member_expression":
            n = n.child_by_field_name("object")
        elif n.type in ("await_expression", "non_null_expression", "as_expression", "satisfies_expression"):
            n = n.named_children[0] if n.named_child_count else None
        else:
            break
    return out


class Walker:
    def __init__(self, m: JSModule, resolve_spec, trpc: bool = False, kit: str | None = None):
        self.m = m
        self.resolve_spec = resolve_spec
        self.trpc = trpc      # the nearest package.json depends on @trpc/server (and this is no test file)
        self.kit = kit        # what a SvelteKit route file is by its name (`page.server`, `server`, …), or None
        self.top = ""         # the scope whose string constants are the file's own: "", or a Svelte component
        self.planned: dict[int, str] = {}   # where an inline function begins -> the name it is a function under
        self.routed: set[int] = set()       # router calls already read (one written inside another, or in a mount)
        self.owner: tuple[int, str] | None = None   # (where a router call begins, the name it is kept under)
        self.under: dict[int, str] = {}     # where a call begins -> the path of the `x.use("/path", …)` around it
        self.anon = 0
        self.inline = 0       # how many inline functions deep the walk is inside the current named function
        self.nested = 0       # and how many methods written in an object (`{ getAll() {…} }`)

    # -- defs
    def add_def(self, node: TSNode, name: str, scope: str, kind: str, in_class: str | None,
                outer: TSNode | None = None) -> str:
        local = f"{scope}.{name}" if scope else name
        body = node.child_by_field_name("body")
        params = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
        ps = _params(params)
        self.m.params[local] = [x for x, _ in ps]
        typed = {x: t for x, t in ps if t}
        if typed:
            self.m.param_types[local] = typed
        o = outer or node
        self.m.defs[local] = JSDef(
            local=local, name=name, kind=kind, start=o.start_point[0] + 1, end=o.end_point[0] + 1,
            parent_local=scope, in_class=in_class, params=_text(params)[:200],
            fingerprint=_fingerprint(node), jsx=kind != "class" and body is not None and _contains_jsx(body),
            server=(kind != "class" and body is not None and body.type == "statement_block"
                    and "use server" in _directives(body)))
        return local

    def walk(self, n: TSNode, scope: str, cls: str | None = None, ui: str | None = None):
        t = n.type
        if t == "method_definition" and self.planned and n.start_byte in self.planned:
            # `actions = { async remove({ request }) {…} }` of a SvelteKit page: a function of its own, named there
            self._walk_body(n, self.add_def(n, self.planned.pop(n.start_byte), scope, "function", None), None, None)
            return
        if t in FUNC_TYPES:   # an inline function, read as part of the function around it
            plan = self.planned.pop(n.start_byte, None) if self.planned else None
            if plan is not None:   # a tRPC procedure's handler or middleware: a function of its own, named there
                self._walk_body(n, self.add_def(n, plan, scope, "function", None), None, None)
                return
            ps = _params(n.child_by_field_name("parameters") or n.child_by_field_name("parameter"))
            if ps:
                self.m.anon_params.setdefault(scope, set()).update(x for x, _ in ps)
                self.m.param_lists.setdefault(scope, []).append([x for x, _ in ps])
        elif t == "assignment_expression" and self._assign(n, scope, cls, ui):
            return
        elif t == "for_in_statement":
            self.m.declared.setdefault(scope, set()).update(_pattern_names(n.child_by_field_name("left")))
        elif t == "catch_clause":
            self.m.declared.setdefault(scope, set()).update(_pattern_names(n.child_by_field_name("parameter")))
        elif t == "return_statement" and scope and not self.inline:   # the function's own return, not a callback's
            v = _unparen(n.named_children[0]) if n.named_child_count else None
            self.m.returns.setdefault(scope, set()).add(_text(v) if v is not None and v.type == "identifier" else "")
            if not self.nested:
                if v is not None and v.type == "await_expression" and v.named_child_count:
                    v = _unparen(v.named_children[0])
                self.m.returned.setdefault(scope, []).append(
                    _chain(v) if v is not None and v.type in ("call_expression", "member_expression", "identifier")
                    else None)
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
            ctor = n.child_by_field_name("constructor")
            ch = _chain(ctor)
            if ch:
                self.m.refs.append(JSRef(scope, ch, n.start_point[0] + 1, "new", ui, _site_pos(n), _text(ctor)))
            elif ctor is not None:   # new (pick())(): chosen at run time
                self.m.refs.append(JSRef(scope, [], n.start_point[0] + 1, "computed", ui, _site_pos(n), _text(ctor)))
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
                    self.m.refs.append(JSRef(scope, ch, n.start_point[0] + 1, "callback", sub_ui, _site_pos(val),
                                             _text(val)))
            if key in ATTACH_KEYS:
                self._given_object(val, scope)
            if val is not None:
                self.walk(val, scope, cls, sub_ui)
            return
        if t == "object" and scope == "" or t == "object":
            self._maybe_router_object(n)
        if t in STATEMENT_LISTS:
            self.each(n.children, scope, cls, ui)
            return
        inline, nested = t in FUNC_TYPES, t == "method_definition"
        self.inline += inline
        self.nested += nested
        for c in n.children:
            self.walk(c, scope, cls, ui)
        self.inline -= inline
        self.nested -= nested

    def each(self, nodes, scope: str, cls: str | None = None, ui: str | None = None):
        """The statements of a block, one by one. One that is nested deeper than Python lets `walk` call itself is
        left where the reading stopped and written down (`lantern/deep.py`). What the scope knew about the names
        written in it is forgotten: the part that was not read may have declared any of them or given it a new value,
        so each counts as a name of this scope that was assigned again."""
        for c in nodes:
            held, held_nested = self.inline, self.nested
            try:
                self.walk(c, scope, cls, ui)
            except RecursionError:
                self.inline, self.nested = held, held_nested
                self.m.too_deep.append(c.start_point[0] + 1)
                written = deep.names(c, ("identifier", "shorthand_property_identifier_pattern"))
                self.m.declared.setdefault(scope, set()).update(written)
                self.m.reassigned.setdefault(scope, set()).update(written)
                for name in written:
                    self.m.local_types.get(scope, {}).pop(name, None)

    def _walk_body(self, fn: TSNode, local: str, cls: str | None, ui: str | None):
        outer, self.inline = self.inline, 0     # a named function: its body is its own, however deep it is written
        outer_nested, self.nested = self.nested, 0
        for fld in ("parameters", "parameter", "body"):
            c = fn.child_by_field_name(fld)
            if c is not None:
                self.walk(c, local, cls, ui)
        self.inline, self.nested = outer, outer_nested

    def _class(self, n: TSNode, name: str, scope: str, ui):
        local = self.add_def(n, name, scope, "class", None)
        heritage = next((c for c in n.children if c.type == "class_heritage"), None)
        if heritage is not None:
            ext = next((c for c in heritage.named_children if c.type == "extends_clause"), heritage)
            val = ext.child_by_field_name("value") or (ext.named_children[0] if ext.named_child_count else None)
            ch = _chain(val)
            if ch:
                self.m.class_bases[local] = ch
            elif val is not None and val.type != "implements_clause":   # extends (a ? B : C): a base, not a name
                self.m.class_bases[local] = ["<expr>"]
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
        self.m.declared.setdefault(scope, set()).update(_pattern_names(name_node))
        name = _text(name_node)
        written = _type_chain(n.child_by_field_name("type")) if name_node.type == "identifier" else None
        if written:   # let prisma: PrismaClient
            self.m.var_types.setdefault(scope, {})[name] = written
        fn = _unwrap_func(value)
        if fn is None and name_node.type == "identifier":
            fn = self._wrapped_func(value) or (self._trpc_middleware(value) if self.trpc else None)
            if fn is not None:   # const create = wrap(async (req, res) => ...): the function is a node of its own
                local = self.add_def(fn, name, scope, "function", cls, outer=n)
                self.m.wrapped.add(local)
                self._walk_body(fn, local, None, ui)
                wfn = value.child_by_field_name("function")
                self.m.refs.append(JSRef(scope, _chain(wfn), value.start_point[0] + 1, "call", ui, _site_pos(value),
                                         _text(wfn)))
                self.walk(wfn, scope, cls, ui)
                args = value.child_by_field_name("arguments")
                for a in (args.named_children[1:] if args is not None else []):
                    self.walk(a, scope, cls, ui)
                return
        if value is not None and self._require_binding(name_node, value, scope):
            self.walk(value, scope, cls, ui)   # the require() call itself is a call site
            return
        if fn is not None and name_node.type == "identifier":
            local = self.add_def(fn, name, scope, "function", cls, outer=n)
            self._walk_body(fn, local, None, ui)
            if value is not fn and value.type == "call_expression":  # memo(...)/forwardRef(...) wrapper call
                wfn = value.child_by_field_name("function")
                wch = _chain(wfn)
                if wch:   # a call site for the inventory only: the edge-line count never had it
                    self.m.refs.append(JSRef(scope, wch, value.start_point[0] + 1, "wrapper", ui, _site_pos(value),
                                             _text(wfn)))
                self.walk(wfn, scope, cls, ui)
            return   # `(fn) as T`, `(fn) satisfies T`: nothing besides the function to walk
        if value is not None and value.type in CLASS_DECLS:
            self._class(value, name, scope, ui)
            return
        if value is not None and name_node.type == "identifier":
            if self.trpc:
                self._trpc_declared(name, value, scope, n)
            if self.kit == "page.server" and not scope and name == "actions":
                self._kit_actions(_bare(value))
            if self.kit == "hooks" and not scope and name == "handle":
                self._kit_handle(_bare(value))
            if value.type == "call_expression" and OPTIONAL_LOGIN.search(_text(value)):
                self.m.optional.add(name)   # const maybe = expressjwt({ ..., credentialsRequired: false })
            sv = self._url_of(value)
            if sv is not None and scope == self.top:
                self.m.consts[name] = sv
            made = value if value.type == "new_expression" else _or_new(value)
            if made is not None:   # new T(), and `kept ?? new T()`: the kept one or a new one
                ch = _chain(made.child_by_field_name("constructor"))
                if ch:
                    self.m.local_types.setdefault(scope, {})[name] = ch
            if value.type == "call_expression":
                fch = _chain(value.child_by_field_name("function"))
                if fch and fch[-1] in ("express", "Router", "Hono", "fastify", "Fastify"):
                    self.m.local_types.setdefault(scope, {})[name] = ["<server>"]
            vch = self._value_chain(value)
            if vch:
                self.m.values.setdefault(scope, {})[name] = vch
                handed = _spine_args(value)
                if handed:
                    self.m.value_args.setdefault(scope, {})[name] = handed
            if value.type in ("object", "this"):   # const api = {} / var self = this: the code's own object
                self.m.plain.setdefault(scope, set()).add(name)
        if value is not None:
            self.walk(value, scope, cls, ui)

    def _kit_actions(self, obj: TSNode | None) -> None:
        """`export const actions = { default: async ({ request }) => …, remove, save: saveNote }` in a SvelteKit
        `+page.server` file: each key is what a form of the page posts to. A function written there is a function
        of its own from here on (`actions.<key>`), also inside a helper that hands back a function around it
        (`save: guarded(async (event) => …)`, the helper kept as `wrap`); one handed by name keeps the node it has."""
        if obj is None or obj.type != "object":
            return
        for c in obj.named_children:
            item: dict = {"line": c.start_point[0] + 1}
            if c.type == "pair":
                item["key"] = _text(c.child_by_field_name("key")).strip("'\"`")
                val = _bare(c.child_by_field_name("value"))
                inner = self._wrapped_func(val)
                if inner is not None:
                    item["wrap"] = _chain(val.child_by_field_name("function"))
                    val = inner
                if val is not None and val.type in FUNC_TYPES:
                    self.planned[val.start_byte] = item["local"] = f"actions.{item['key']}"
                elif val is not None and val.type in ("identifier", "member_expression") and _chain(val):
                    item["handler"], item["at"] = _chain(val), _site_pos(val)
                else:
                    continue
            elif c.type == "method_definition":
                item["key"] = _text(c.child_by_field_name("name")).strip("'\"`")
                self.planned[c.start_byte] = item["local"] = f"actions.{item['key']}"
            elif c.type == "shorthand_property_identifier":
                item["key"] = _text(c)
                item["handler"], item["at"] = [item["key"]], _site_pos(c)
            else:
                continue
            if item["key"]:
                self.m.kit_actions.append(item)

    def _kit_handle(self, call: TSNode | None) -> None:
        """`export const handle = sequence(first, second)` in SvelteKit's `src/hooks.server`: each function named
        there is a hook of its own, run in that order before every route. `sequence` is the kit's own."""
        if call is None or call.type != "call_expression":
            return
        fn = _chain(call.child_by_field_name("function")) or []
        imp = self.m.imports.get(fn[0]) if len(fn) == 1 else None
        if imp is None or (imp[1], imp[2]) != ("sequence", "@sveltejs/kit/hooks"):
            return
        args = call.child_by_field_name("arguments")
        for a in args.named_children if args is not None else ():
            a = _bare(a)
            if a is not None and a.type in ("identifier", "member_expression") and _chain(a):
                self.m.kit_handles.append((_chain(a), _site_pos(a)))

    # -- CommonJS, values, wrappers (stage 3)
    def _require_binding(self, name_node: TSNode, value: TSNode, scope: str) -> bool:
        """const x = require('x') / const { a, b: c } = require('x') / const f = require('x').f -> imports.
        A require of a path built at run time marks the name, so its calls say why they are not followed."""
        v = _unparen(value)
        if v is not None and v.type == "await_expression" and v.named_child_count:
            v = _unparen(v.named_children[0])
        if v is None:
            return False
        if v.type == "call_expression" and _text(v.child_by_field_name("function")) == "require":
            spec = _require_spec(v)
            if spec is None:
                self.m.dynamic.setdefault(scope, set()).update(_pattern_names(name_node))
                return False
            target = self.resolve_spec(spec)
            if name_node.type == "identifier":
                self.m.imports[_text(name_node)] = (target, "cjs", spec)
                self.m.required.setdefault(scope, set()).add(_text(name_node))
                return True
            if name_node.type == "object_pattern":
                for c in name_node.named_children:
                    if c.type == "shorthand_property_identifier_pattern":
                        self.m.imports[_text(c)] = (target, _text(c), spec)
                    elif c.type == "pair_pattern":
                        k, val = c.child_by_field_name("key"), c.child_by_field_name("value")
                        if k is not None and val is not None and val.type == "identifier":
                            self.m.imports[_text(val)] = (target, _text(k).strip("'\""), spec)
                return True
            return False
        ch = _chain(v) if v.type == "member_expression" else None
        if ch and len(ch) == 2 and ch[0].startswith("require:") and name_node.type == "identifier":
            spec = ch[0][len("require:"):]
            self.m.imports[_text(name_node)] = (self.resolve_spec(spec), ch[1], spec)
            return True
        return False

    @staticmethod
    def _value_chain(value: TSNode | None) -> list[str] | None:
        """What a variable is set to, as a chain the resolver can follow later: a call or member chain
        (`express()`, `document.querySelectorAll('a')`), `await` of one, or a literal array or string."""
        v = _unparen(value)
        if v is not None and v.type == "await_expression" and v.named_child_count:
            v = _unparen(v.named_children[0])
        if v is None:
            return None
        if v.type in ("call_expression", "member_expression", "identifier"):
            return _chain(v)
        if v.type == "array":
            return ["<array>"]
        if v.type in ("string", "template_string"):
            return ["<string>"]
        return None

    @staticmethod
    def _wrapped_func(value: TSNode | None) -> TSNode | None:
        """`wrap(async (req, res) => ...)` -> the inner function, for a helper that hands back a function around
        the one it is given; None for calls that return something else (NOT_WRAPPERS) and for member calls other
        than MEMBER_WRAPPERS (`list.map(fn)` returns a list)."""
        v = _unparen(value)
        if v is None or v.type != "call_expression":
            return None
        fnn = v.child_by_field_name("function")
        ch = _chain(fnn)
        if not ch or any(x.endswith("()") or x.startswith("require:") for x in ch):
            return None
        if len(ch) == 1 and (ch[0] in NOT_WRAPPERS or ch[0] in WRAPPERS or ch[0].startswith("use")):
            return None
        if len(ch) > 1 and ch[-1] not in MEMBER_WRAPPERS:
            return None
        args = v.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        first = _unparen(argv[0]) if argv else None
        return first if first is not None and first.type in FUNC_TYPES else None

    def _assign(self, n: TSNode, scope: str, cls, ui) -> bool:
        """Assignments that define things: `module.exports = ...`, `exports.x = ...`, `this.x = function` in a
        constructor function or class method, `X.prototype.y = function` and `X.y = function` for a function or
        class X of this file. True when the whole statement was read here."""
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        if left is None or right is None:
            return False
        if left.type == "identifier":
            self.m.reassigned.setdefault(scope, set()).add(_text(left))
            return False
        if left.type != "member_expression":
            return False
        lch = _chain(left)
        if not lch:
            return False
        fn = _unwrap_func(right)
        if lch[:2] == ["module", "exports"] or lch[0] == "exports":
            whole = lch == ["module", "exports"]
            key = lch[2] if lch[:2] == ["module", "exports"] and len(lch) == 3 else \
                lch[1] if lch[0] == "exports" and len(lch) == 2 else None
            if scope or (not whole and key is None):
                return False
            return self._cjs_export(key, right, fn, n, ui)
        if fn is None:   # obj.x = helper / obj.methods = { x () {} }: a function put on an object, if `helper` is one
            v = _unparen(right)
            vch = _chain(v) if v is not None and v.type in ("identifier", "member_expression") else None
            if vch and not any(x.endswith("()") for x in vch):
                self.m.put.append((scope, lch[:-1], lch[-1], vch))
            self._given_object(v, scope, lch)
            return False
        if lch[0] == "this" and len(lch) == 2 and scope in self.m.defs:
            d = self.m.defs[scope]
            owner = d.in_class or (scope if d.kind == "function" else None)
            if owner:
                if not d.in_class:
                    self.m.ctors.add(owner)
                local = self._member(self.add_def(fn, lch[1], owner, "method", owner, outer=n), scope)
                self._walk_body(fn, local, owner, ui)
                return True
        top = self.m.defs.get(lch[0])
        if top is not None and top.kind in ("function", "class") and "." not in lch[0]:
            if len(lch) == 3 and lch[1] == "prototype":
                if top.kind == "function":
                    self.m.ctors.add(lch[0])
                local = self._member(self.add_def(fn, lch[2], lch[0], "method", lch[0], outer=n), scope)
                self._walk_body(fn, local, lch[0], ui)
                return True
            if len(lch) == 2:   # a function hung on another one: Foo.helper = function () {}
                local = self._member(self.add_def(fn, lch[1], lch[0], "function", None, outer=n), scope)
                self._walk_body(fn, local, None, ui)
                return True
        # a function put on something that is not this file's own function or class: a library's object, a
        # parameter, a built-in type (`schema.statics.find = function`, `res.fail = function`)
        self.m.put.append((scope, lch[:-1], lch[-1], None))
        return False

    def _given_object(self, obj: TSNode | None, scope: str, owner: list[str] | None = None) -> None:
        """`{ x () {}, y: function () {}, z: helper }` whose functions end up on an object: the names it gives them,
        as functions put on `owner` when the code names the object (`schema.methods = {...}`), else as `given`."""
        obj = _unparen(obj) if obj is not None else None
        if obj is None or obj.type != "object":
            return

        def note(name: str, chain: list[str] | None):
            if owner is not None:
                self.m.put.append((scope, owner, name, chain))
            else:
                self.m.given.append((scope, name, chain))

        for c in obj.named_children:
            if c.type == "method_definition":
                note(_text(c.child_by_field_name("name")), None)
            elif c.type == "shorthand_property_identifier":
                note(_text(c), [_text(c)])
            elif c.type == "pair":
                k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                if k is None or v is None:
                    continue
                if _unwrap_func(v) is not None:
                    note(_text(k).strip("'\""), None)
                elif v.type in ("identifier", "member_expression"):
                    vch = _chain(v)
                    if vch and not any(x.endswith("()") for x in vch):
                        note(_text(k).strip("'\""), vch)

    def _member(self, local: str, scope: str) -> str:
        """A function stored as a property is named after its owner (`Foo.helper`) but is not a name in the owner's
        scope, and it sees the names of the place it is written (`scope`), not the owner's locals."""
        d = self.m.defs[local]
        d.member, d.lexical = True, scope
        return local

    def _cjs_export(self, key: str | None, right: TSNode, fn: TSNode | None, stmt: TSNode, ui) -> bool:
        """module.exports = <right> (key None) or module.exports.<key> / exports.<key> = <right>."""
        m = self.m
        name = key or "default"
        if fn is not None:
            own = fn.child_by_field_name("name")
            local = self.add_def(fn, key or (_text(own) if own is not None else "default"), "", "function", None,
                                 outer=stmt)
            self._walk_body(fn, local, None, ui)
            if right is not fn and right.type == "call_expression":   # memo(...) and the like
                self.walk(right.child_by_field_name("function"), "", None, ui)
            m.exports[name] = local
            if not key:
                m.default = local
            return True
        if right.type in CLASS_DECLS:
            own = right.child_by_field_name("name")
            cname = key or (_text(own) if own is not None else "default")
            self._class(right, cname, "", ui)
            m.exports[name] = cname
            if not key:
                m.default = cname
            return True
        if right.type == "identifier":
            ident = _text(right)
            if ident in m.defs or ident in m.imports:
                m.exports[name] = ident
                if not key:
                    m.default = ident
            else:
                m.export_values[name] = [ident]
            return True
        if right.type == "object" and not key:
            for c in right.named_children:
                if c.type == "shorthand_property_identifier":
                    ident = _text(c)
                    if ident in m.defs or ident in m.imports:
                        m.exports[ident] = ident
                    else:
                        m.export_values[ident] = [ident]
                elif c.type == "pair":
                    k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                    if k is None or v is None:
                        continue
                    kname = _text(k).strip("'\"")
                    vf = _unwrap_func(v)
                    if vf is not None:
                        local = self.add_def(vf, kname, "", "function", None, outer=c)
                        self._walk_body(vf, local, None, ui)
                        m.exports[kname] = local
                    elif v.type == "identifier" and (_text(v) in m.defs or _text(v) in m.imports):
                        m.exports[kname] = _text(v)
                    else:
                        vch = self._value_chain(v)
                        if vch:
                            m.export_values[kname] = vch
                        self.walk(v, "", None, ui)
                elif c.type == "method_definition":
                    kname = _text(c.child_by_field_name("name"))
                    local = self.add_def(c, kname, "", "function", None)
                    self._walk_body(c, local, None, ui)
                    m.exports[kname] = local
                else:
                    self.walk(c, "", None, ui)
            return True
        if right.type == "new_expression":
            nch = _chain(right.child_by_field_name("constructor"))
            if nch:
                m.export_new[name] = nch
            self.walk(right, "", None, ui)
            return True
        vch = self._value_chain(right)
        if vch and len(vch) == 1 and vch[0].startswith("require:") and not key:   # module.exports = require('./x')
            m.cjs_from = self.resolve_spec(vch[0][len("require:"):])
            m.reexports.append((m.cjs_from, None))
        elif vch:
            m.export_values[name] = vch
        self.walk(right, "", None, ui)
        return True

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
                args = val.child_by_field_name("arguments")
                first = args.named_children[0] if args is not None and args.named_child_count else None
                if first is not None and first.type == "identifier":   # export default connect(X)
                    self.m.default = _text(first)
                if self.trpc:
                    self.owner = (val.start_byte, "default")
            self.walk(val, scope, cls, ui)

    # -- calls
    def _call(self, n: TSNode, scope: str, cls, ui):
        fn = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        line = n.start_point[0] + 1
        ch = _chain(fn)
        at, text = _site_pos(n), _text(fn)
        if ch is None:   # a callee no name chain reads: an inline function, an index, a computed expression
            inner = _unparen(fn)
            self.m.refs.append(JSRef(scope, ["<inline>"] if inner is not None and inner.type in FUNC_TYPES else [],
                                     line, "computed", ui, at, text))
        elif self.trpc:
            self._trpc_call(n, ch, argv, scope, line)

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

        # functions put on a library's object by name or in an object: schema.method('x', fn),
        # schema.static({ x () {} }), Object.assign(schema.methods, { x () {} })
        if ch and len(ch) >= 2 and ch[-1] in ATTACH_CALLS and argv and not any(x.endswith("()") for x in ch):
            name = _string_value(argv[0])
            if name is not None and len(argv) > 1:
                if _unwrap_func(argv[1]) is not None:
                    self.m.put.append((scope, ch[:-1], name, None))
                elif argv[1].type in ("identifier", "member_expression") and _chain(argv[1]):
                    self.m.put.append((scope, ch[:-1], name, _chain(argv[1])))
            self._given_object(argv[0], scope, ch[:-1])
        elif ch in MERGE_CALLS and len(argv) > 1:
            target = _chain(argv[0]) if argv[0].type in ("identifier", "member_expression") else None
            if target and target[0] != "exports" and target[:2] != ["module", "exports"]:
                for a in argv[1:]:
                    self._given_object(a, scope, target)

        # Express / Hono / Fastify route registration: app.get('/x', ..., handler), and the same verbs hung on
        # router.route('/x'), where the path is written once: router.route('/x').get(handler).post(mw, handler)
        if ch and len(ch) >= 2 and ch[-1] in HTTP_METHODS | {"all"} and argv:
            chained = self._route_call(fn) if len(ch) >= 3 and ch[-2].endswith("()") else None
            p = chained[1] if chained else self._url_of(argv[0])
            handlers = argv if chained else argv[1:]
            last = argv[-1]
            every = None
            if ch[-1] == "all" and not chained and p is not None and len(argv) > 1:
                # x.all('*', mw) / x.all('/api/*', mw) / x.all('/orders/:id', mw): what is handed to it runs before
                # the routes written after it, as with `use`, when every one of them passes the request on. Whether
                # they do is read where the functions are known (`add_js`); here only what was written
                under = ALL_UNDER.match(p)
                if under or p.startswith("/"):
                    targets = [self._mount_target(a) for a in argv[1:]]
                    every = {"recv": ch[:-1], "scope": scope, "prefix": under.group("pre") if under else p,
                             "line": line, "targets": [t for t in targets if t], "whole": all(targets),
                             "star": under is not None,
                             "lead": None, "unread": False}
                    self.m.alls.append(every)
            if p is not None and p.startswith("/") and handlers and (
                    last.type in FUNC_TYPES or last.type == "identifier" or last.type == "member_expression"):
                method = ch[-1].upper() if ch[-1] != "all" else "ANY"
                reg = {"method": method, "path": p, "line": line, "scope": scope,
                       "recv": chained[0] if chained else ch[:-1], "mw": [], "at": _site_pos(last)}
                if every is not None:
                    reg["all"] = every
                # the registration call is a call site (inventory only; the edge-line count never had it). A verb
                # hung on .route() was always counted there as a call, and stays one
                self.m.refs.append(JSRef(scope, ch, line, "call" if chained else "registration", ui, at, text))
                for a in handlers[:-1]:   # middleware handed to this route, before its handler
                    self._middleware(a, reg["mw"])
                for a in argv[:-1]:   # and the calls written there (auth(), validate(schema)) are call sites
                    self.walk(a, scope, cls, ui)
                if last.type in FUNC_TYPES:
                    self.anon += 1
                    local = self.add_def(last, f"{method.lower()}_{_slug(p)}", scope, "function", None)
                    reg["local"] = local
                    self._walk_body(last, local, None, None)
                else:
                    reg["handler"] = _chain(last)
                self.m.route_regs.append(reg)
                if chained:   # the verbs written before this one on the same .route() call, and .route() itself
                    self.walk(fn, scope, cls, ui)
                return
        # x.use('/prefix', router, ...): a router (or a router factory's result) mounted under a prefix
        if ch and len(ch) >= 2 and ch[-1] == "use" and argv:
            prefix = self._url_of(argv[0])
            if prefix is None or prefix.startswith("/"):
                first = _unparen(argv[0])
                self.m.mounts.append({"recv": ch[:-1], "scope": scope, "prefix": prefix or "", "line": line,
                                      "targets": [t for a in (argv[1:] if prefix is not None else argv)
                                                  for t in [self._mount_target(a, True)] if t],
                                      # no path was read. `lead`: the first argument is a name, which may hold the
                                      # path; `unread`: it is a list of paths, a pattern or a built text. Either way
                                      # what follows may be for paths Lantern does not know
                                      "lead": _text(first) if prefix is None and len(argv) > 1 and first is not None
                                      and first.type in ("identifier", "member_expression") else None,
                                      "unread": prefix is None and first is not None and first.type not in (
                                          "identifier", "member_expression", "call_expression", *FUNC_TYPES)})
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
            http.recv = hch[:-1] if hch[0] != "<expr>" else None
            self.m.http.append(http)
        if ch:
            self.m.refs.append(JSRef(scope, ch, line, "call", ui, at, text, _spine_args(fn) or None,
                                     self._db_shape(fn, ch)))
            # parameters of inline functions handed to this call: what the callee passes them can be known
            # (forEach on a DOM list passes elements, addEventListener an event, fetch().then a response)
            cbp = self.m.cb_params.setdefault(scope, {})
            for ai, a in enumerate(argv):
                fa = _unparen(a)
                if fa is not None and fa.type in FUNC_TYPES:
                    for pi, (pname, _) in enumerate(_params(fa.child_by_field_name("parameters") or
                                                            fa.child_by_field_name("parameter"))):
                        key = (tuple(ch), ai, pi)
                        cbp[pname] = key if cbp.get(pname, key) == key else None
        # functions passed as arguments are likely to be called: useEffect(load), map(render)
        for a in argv:
            if a.type == "identifier":
                self.m.refs.append(JSRef(scope, [_text(a)], line, "callback", ui, _site_pos(a), _text(a)))
        if fn is not None:
            self.walk(fn, scope, cls, ui)
        for a in argv:
            self.walk(a, scope, cls, ui)

    # -- tRPC: routers, the procedures in them, what each is built on, where the whole is served. Shapes only: what
    # made a router, and so whether it is one, is read where the files are known (`_trpc_plan`)
    @staticmethod
    def _trpc_middleware(value: TSNode | None) -> TSNode | None:
        """`t.middleware(async ({ ctx, next }) => …)` -> the function tRPC runs before a procedure, to be named by
        the variable it is kept in."""
        if value is None or value.type != "call_expression":
            return None
        ch = _chain(value.child_by_field_name("function"))
        if not ch or len(ch) < 2 or ch[-1] != "middleware" or any(x.endswith("()") for x in ch):
            return None
        args = value.child_by_field_name("arguments")
        first = _unparen(args.named_children[0]) if args is not None and args.named_child_count else None
        return first if first is not None and first.type in FUNC_TYPES else None

    def _trpc_declared(self, name: str, value: TSNode, scope: str, decl: TSNode) -> None:
        """`const postRouter = createTRPCRouter({…})`: the name the router is kept under, for when the walk reaches
        the call. `const protectedProcedure = t.procedure.use(fn)`: what a procedure of that name is built on.
        `const postRouter = { all: publicProcedure.query(…) } satisfies TRPCRouterRecord`: a router written out."""
        v = _bare(value)
        if v is None:
            return
        if v.type == "call_expression":
            ch = _chain(v.child_by_field_name("function"))
            if ch and TRPC_ROUTER.match(ch[-1]):
                self.owner = (v.start_byte, name)
                return
            base, steps = _trpc_spine(v)
            if base and steps and any(x == "use" for x, _ in steps) and all(x in TRPC_STEPS for x, _ in steps):
                # a function written in `.use()` is made a function of its own only on a name that says procedure:
                # `app.use(fn)`, `unified().use(plugin)` and the like are written the same way
                self.m.trpc_bases[(scope, name)] = {
                    "base": base, "uses": self._trpc_uses(steps, scope, name, "procedure" in base[-1].lower())}
        elif v.type == "object":
            said = _text(value)[v.end_byte - value.start_byte:] + _text(decl.child_by_field_name("type"))
            items = self._trpc_items(v, scope, name, strict=True)
            if any(i["kind"] == "procedure" or i.get("inline") is not None for i in items) or \
                    (items and "Router" in said):
                self.routed.add(v.start_byte)
                self.m.trpc_routers.append({"name": name, "scope": scope, "line": v.start_point[0] + 1,
                                            "callee": None, "items": items})

    def _trpc_call(self, n: TSNode, ch: list[str], argv: list, scope: str, line: int) -> None:
        last = ch[-1]
        if TRPC_ROUTER.match(last) and n.start_byte not in self.routed:
            owner, self.owner = self.owner, None
            self._trpc_router(n, ch, argv, scope, owner[1] if owner and owner[0] == n.start_byte
                              else f"router@{line}")
        if last == "use" and len(argv) > 1:     # app.use("/trpc", createExpressMiddleware({ router }))
            prefix = self._url_of(argv[0])
            for a in argv[1:] if prefix is not None else ():
                a = _bare(a)
                if a is not None and a.type == "call_expression":
                    self.under[a.start_byte] = prefix
        if last in TRPC_ADAPTERS and argv:
            self._trpc_mount(n, _bare(argv[0]), None, scope, line, last)
        elif last == "register" and len(argv) > 1 and "trpc" in _text(argv[0]).lower():
            # fastify.register(fastifyTRPCPlugin, { prefix: "/trpc", trpcOptions: { router } })
            outer = _bare(argv[1])
            if outer is not None and outer.type == "object":
                self._trpc_mount(n, _bare(self._obj_prop(outer, ("trpcOptions",))), outer, scope, line, last)

    def _trpc_mount(self, call: TSNode, opts: TSNode | None, around: TSNode | None, scope: str, line: int,
                    adapter: str) -> None:
        if opts is None or opts.type != "object":
            return
        rv = _bare(self._obj_prop(opts, ("router",)))
        if rv is None:
            return
        rec = {"scope": scope, "line": line, "endpoint": None, "router": None, "inline": None, "adapter": adapter}
        if rv.type == "call_expression":
            rch = _chain(rv.child_by_field_name("function"))
            if rch and TRPC_ROUTER.match(rch[-1]) and rv.start_byte not in self.routed:
                rargs = rv.child_by_field_name("arguments")
                rec["inline"] = self._trpc_router(
                    rv, rch, [a for a in (rargs.named_children if rargs is not None else []) if a.type != "comment"],
                    scope, f"router@{rv.start_point[0] + 1}")
        elif rv.type in ("identifier", "member_expression", "shorthand_property_identifier"):
            rec["router"] = _chain(rv)
        if rec["router"] is None and rec["inline"] is None:
            return
        for obj in (opts, around):
            for key in ("endpoint", "basePath", "prefix"):
                v = self._obj_prop(obj, (key,)) if obj is not None else None
                if v is not None and rec["endpoint"] is None:
                    rec["endpoint"] = self._url_of(v)
        if rec["endpoint"] is None:
            rec["endpoint"] = self.under.get(call.start_byte)
        self.m.trpc_mounts.append(rec)

    def _trpc_router(self, call: TSNode, ch: list[str], argv: list, scope: str, owner: str) -> int | None:
        """`createTRPCRouter({ … })` / `mergeRouters(a, b)` -> its place in `trpc_routers`, or None when what it is
        handed holds nothing a router is made of (`express.Router({ mergeParams: true })`)."""
        items: list[dict] = []
        if TRPC_MERGE.match(ch[-1]):
            for a in argv:
                items += self._trpc_part(_bare(a), scope, f"{owner}.{len(items)}", None)
        else:
            obj = _bare(argv[0]) if argv else None
            if obj is None or obj.type != "object":
                return None
            items = self._trpc_items(obj, scope, owner)
        if not items:
            return None
        self.routed.add(call.start_byte)
        self.m.trpc_routers.append({"name": owner, "scope": scope, "line": call.start_point[0] + 1, "callee": ch,
                                    "items": items})
        return len(self.m.trpc_routers) - 1

    def _trpc_part(self, val: TSNode | None, scope: str, name: str, key: str | None, strict: bool = False) -> list:
        """One value in a router: another router (by name, made in place, or an object written out), or with a key
        a procedure. `key` None: a router spread or merged into this one."""
        kind = "router" if key is not None else "spread"
        head = {"key": key} if key is not None else {}
        if val is None:
            return []
        if val.type in ("identifier", "member_expression", "shorthand_property_identifier"):
            ch = _chain(val)
            return [{**head, "kind": kind, "chain": ch}] if ch and not any(x.endswith("()") for x in ch) else []
        if val.type == "object":
            sub = self._trpc_items(val, scope, name, strict)
            if not sub or (strict and not any(i["kind"] == "procedure" or i.get("inline") is not None for i in sub)):
                return []
            self.m.trpc_routers.append({"name": name, "scope": scope, "line": val.start_point[0] + 1,
                                        "callee": None, "items": sub})
            return [{**head, "kind": kind, "inline": len(self.m.trpc_routers) - 1}]
        if val.type != "call_expression":
            return []
        vch = _chain(val.child_by_field_name("function"))
        if vch and TRPC_ROUTER.match(vch[-1]):
            vargs = val.child_by_field_name("arguments")
            idx = self._trpc_router(val, vch, [a for a in (vargs.named_children if vargs is not None else [])
                                               if a.type != "comment"], scope, name)
            return [{**head, "kind": kind, "inline": idx}] if idx is not None else []
        item = self._trpc_procedure(val, scope, name, strict) if key is not None else None
        return [{**head, **item}] if item else []

    def _trpc_items(self, obj: TSNode, scope: str, owner: str, strict: bool = False) -> list[dict]:
        """What an object handed to a router holds. `strict`: the object stands by itself (no router call around
        it), so only a procedure built on a name that says procedure counts."""
        items: list[dict] = []
        for c in obj.named_children:
            if c.type == "pair":
                key = _string_value(c.child_by_field_name("key")) if c.child_by_field_name("key") is not None and \
                    c.child_by_field_name("key").type == "string" else _text(c.child_by_field_name("key"))
                if key and re.fullmatch(r"[\w$-]+", key):
                    items += self._trpc_part(_bare(c.child_by_field_name("value")), scope, f"{owner}.{key}", key,
                                             strict)
            elif c.type == "shorthand_property_identifier":
                items.append({"key": _text(c), "kind": "router", "chain": [_text(c)]})
            elif c.type == "spread_element" and c.named_child_count:
                items += self._trpc_part(_bare(c.named_children[0]), scope, f"{owner}.{len(items)}", None, strict)
        return items

    def _trpc_procedure(self, call: TSNode, scope: str, name: str, strict: bool) -> dict | None:
        """`protectedProcedure.input(schema).mutation(async ({ ctx, input }) => …)`: the kind, what it is built on,
        the functions put before it with `.use()`, and its handler: written there (a function of its own from here
        on, named `<router>.<key>`) or handed by name."""
        base, steps = _trpc_spine(call)
        if not base or not steps or steps[-1][0] not in TRPC_KINDS:
            return None
        if strict and "procedure" not in base[-1].lower():
            return None
        h = _unparen(steps[-1][1][0]) if steps[-1][1] else None
        item = {"kind": "procedure", "type": steps[-1][0], "base": base, "line": call.start_point[0] + 1}
        if h is not None and h.type in FUNC_TYPES:
            self.planned[h.start_byte] = name
            item["local"] = f"{scope}.{name}" if scope else name
        elif h is not None and h.type in ("identifier", "member_expression") and _chain(h):
            item["handler"], item["at"] = _chain(h), _site_pos(h)
        else:
            return None
        item["uses"] = self._trpc_uses(steps[:-1], scope, name, True)
        return item

    def _trpc_uses(self, steps: list, scope: str, name: str, plan: bool) -> list[dict]:
        """The functions `.use()` puts before a procedure, in the order written: one written there (`plan`: made a
        function of its own, `<name>.use`), one by name, or the call that makes one (`.use(limit({ max: 5 }))`)."""
        out: list[dict] = []
        k = 0
        for step, args in steps:
            a = _bare(args[0]) if step == "use" and args else None
            if a is None:
                continue
            if a.type in FUNC_TYPES:
                if plan:
                    k += 1
                    local = f"{name}.use" + (str(k) if k > 1 else "")
                    self.planned[a.start_byte] = local
                    out.append({"local": f"{scope}.{local}" if scope else local})
            elif a.type in ("identifier", "member_expression"):
                ch = _chain(a)
                if ch:
                    out.append({"chain": ch, "at": _site_pos(a)})
            elif a.type == "call_expression":
                ch = _chain(a.child_by_field_name("function"))
                if ch:
                    out.append({"chain": ch, "called": True})
        return out

    @staticmethod
    def _written(call: TSNode | None):
        """The first argument of a call as a name the code wrote: ("text", it) for a plain string, ("const", name)
        for a bare name (which may be a constant of the file; the resolver says), None for anything else."""
        args = call.child_by_field_name("arguments") if call is not None and call.type == "call_expression" else None
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        if not argv:
            return None
        if argv[0].type == "identifier":
            return ("const", _text(argv[0]))
        if argv[0].type == "template_string" and argv[0].named_child_count:
            return None   # a name built at run time
        text = _string_value(argv[0])
        return ("text", text) if text is not None and TABLE_NAME.match(text) else None

    def _db_shape(self, fn: TSNode | None, ch: list[str]) -> dict | None:
        """`<recv>.from("<table>").<select|insert|update|upsert|delete>`, also behind `.schema("<name>")`: what was
        written, for the resolver to say whether `<recv>` is a Supabase client. None for a storage bucket
        (`<recv>.storage.from("avatars")`) and where the table or the schema is not written as a name."""
        if len(ch) < 3 or ch[-1] not in DB_OPS or ch[-2] != "from()" or fn is None or fn.type != "member_expression":
            return None

        def under(n):   # the call a member is used on, through `!`, `as X` and brackets
            n = _unparen(n)
            while n is not None and n.type in ("non_null_expression", "as_expression", "satisfies_expression") \
                    and n.named_child_count:
                n = _unparen(n.named_children[0])
            return n

        frm = under(fn.child_by_field_name("object"))
        table = self._written(frm)
        recv, schema = ch[:-2], None
        if table is None:
            return None
        if recv[-1] == "schema()":
            inner = frm.child_by_field_name("function")
            schema = self._written(under(inner.child_by_field_name("object")) if inner is not None else None)
            if schema is None or schema[0] != "text":
                return None
            recv = recv[:-1]
        if not recv or recv[-1] == "storage":
            return None
        return {"recv": recv, "schema": schema[1] if schema else None, "op": ch[-1],
                "table": table[1] if table[0] == "text" else None, "const": table[1] if table[0] == "const" else None}

    def _route_call(self, fn: TSNode):
        """`router.route('/x').get(...).post(...)`: for a verb hung on a `.route('<path>')` call (straight on it or
        after other verbs), the chain of what `.route` was called on and the path. None for anything else."""
        obj = fn.child_by_field_name("object") if fn is not None and fn.type == "member_expression" else None
        for _ in range(12):
            if obj is None or obj.type != "call_expression":
                return None
            f = obj.child_by_field_name("function")
            if f is None or f.type != "member_expression":
                return None
            prop = _text(f.child_by_field_name("property"))
            if prop == "route":
                args = obj.child_by_field_name("arguments")
                argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
                p = self._url_of(argv[0]) if len(argv) == 1 else None
                recv = _chain(f.child_by_field_name("object"))
                return (recv, p) if recv and p is not None and p.startswith("/") else None
            if prop not in HTTP_METHODS | {"all"}:
                return None
            obj = f.child_by_field_name("object")
        return None

    def _middleware(self, a: TSNode, out: list):
        """A route's middleware argument: a function by name (`guard.signedIn`), a call that makes one
        (`auth()`, `passport.authenticate('jwt')`), or an array of those."""
        a = _unparen(a)
        if a is None:
            return
        if a.type == "array":
            for c in a.named_children:
                self._middleware(c, out)
        elif a.type in ("identifier", "member_expression"):
            ch = _chain(a)
            if ch:
                out.append({"chain": ch, "at": _site_pos(a), "called": False, "text": _text(a)})
        elif a.type == "call_expression":
            ch = _chain(a.child_by_field_name("function"))
            if ch:
                out.append({"chain": ch, "at": _site_pos(a), "called": True, "text": _text(a)})

    @staticmethod
    def _mount_target(a: TSNode, in_place: bool = False) -> dict | None:
        a = _unparen(a)
        if a is None:
            return None
        if in_place and a.type in FUNC_TYPES:
            # app.use((req, res, next) => { ... }): a function written where it is put on. It has no name and no node
            # of its own; the route's entry names it by the line it starts on
            ps = a.child_by_field_name("parameters")
            n = len([c for c in ps.named_children if c.type != "comment"]) if ps is not None else \
                1 if a.child_by_field_name("parameter") is not None else 0
            return {"kind": "inline", "chain": [], "text": "", "line": a.start_point[0] + 1, "params": n}
        if a.type in ("identifier", "member_expression"):
            ch = _chain(a)
            return {"kind": "value", "chain": ch, "text": _text(a)} if ch else None
        if a.type == "call_expression":
            full = _chain(a)
            if full and len(full) == 1 and full[0].startswith("require:") and not full[0].endswith("()"):
                # require('./routes/notes')
                return {"kind": "module", "spec": full[0][len("require:"):], "text": _text(a)}
            ch = _chain(a.child_by_field_name("function"))
            # makeRouter() / require('./admin')(Router())
            return {"kind": "call", "chain": ch, "text": _text(a)} if ch else None
        return None

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
            self.m.refs.append(JSRef(scope, parts, line, "jsx", ui, _site_pos(n), ".".join(parts)))
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
            sub_ui = aname if re.match(r"^on[A-Z]", aname) or aname in ("action", "formAction") else ui
            if val is not None and val.type == "jsx_expression" and val.named_child_count:
                inner = val.named_children[0]
                if inner.type in ("identifier", "member_expression"):
                    ch = _chain(inner)
                    if ch:
                        self.m.refs.append(JSRef(scope, ch, line, "callback", sub_ui, _site_pos(inner), _text(inner)))
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
        method, url_node = None, None
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

def _load_jsonc(p: Path, repo: Path) -> dict:
    """The table a tsconfig/jsconfig of the project holds (comments and trailing commas allowed); an empty one when
    the file is not the project's, cannot be read, is not valid, or holds something else than a table."""
    try:
        txt = project_text(p, repo)
    except OSError:
        return {}
    txt = re.sub(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', lambda m: m.group(1) or "", txt, flags=re.S)
    txt = re.sub(r",(\s*[}\]])", r"\1", txt)
    return manifest.table(manifest.parse_json(txt))


def _reached(p: Path) -> Path | None:
    """Where the path `p` leads once every link on it is followed, or None when it leads nowhere: links that name
    each other (`a.ts -> b.ts -> a.ts`). Python 3.11 and 3.12 raise for such a loop, and until 2026-11-10 an import
    that mentioned one stopped the whole analysis there."""
    try:
        return p.resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _whole(base: Path, rel: str) -> Path | None:
    """`rel` under `base` as a whole path, or None when what the file says there cannot be a path at all."""
    try:
        return (base / rel).resolve()
    except (ValueError, OSError, RuntimeError):
        return None


class SpecResolver:
    def __init__(self, repo: Path, files: dict[str, str]):
        self.repo = repo
        self.files = files            # rel path -> module name
        self._alias_cache: dict[Path, list[tuple[str, list[Path]]]] = {}
        self._pkgs: dict = {}

    def _kit(self, d: Path) -> bool:
        """Is this folder the root of a SvelteKit project: its config stands here, or its package.json names the kit."""
        return any(inside_repo(d / n, self.repo) for n in SVELTE_CONFIGS) or \
            (inside_repo(d / "package.json", self.repo)
             and KIT in _nearest_package(d / "package.json", self.repo, self._pkgs)["deps"])

    def _aliases(self, d: Path) -> list[tuple[str, list[Path]]]:
        """Path aliases from the nearest tsconfig/jsconfig (and its tsconfig.*.json siblings). A written `baseUrl`
        comes last, as the catch-all it is: the compiler looks a bare name up under it (`components/Button` ->
        `<baseUrl>/components/Button`) after the `paths` and before node_modules."""
        cur = d
        while True:
            if cur in self._alias_cache:
                return self._alias_cache[cur]
            cands = [cur / n for n in ("tsconfig.json", "jsconfig.json")] + sorted(cur.glob("tsconfig.*.json"))
            found: list[tuple[str, list[Path]]] = []
            bases: list[tuple[str, list[Path]]] = []
            for c in cands:
                if not inside_repo(c, self.repo):   # also a link that leads out of the project: as if it were not there
                    continue
                # the file comes with the project: what is not the shape a tsconfig has is passed over (manifest.py)
                co = manifest.table(_load_jsonc(c, self.repo).get("compilerOptions"))
                base = _whole(c.parent, manifest.text(co.get("baseUrl"), "."))
                if base is None:
                    continue
                for pat, targets in manifest.table(co.get("paths")).items():
                    found.append((pat, [t for t in (_whole(base, x) for x in manifest.texts(targets)) if t is not None]))
                if isinstance(co.get("baseUrl"), str) and ("*", [base / "*"]) not in bases:
                    bases.append(("*", [base / "*"]))
            if found or (cur / "package.json").exists() or cur == self.repo or cur == cur.parent:
                if not found and (cur / "package.json").exists():
                    root = cur / "src" if (cur / "src").is_dir() else cur
                    found = [("@/*", [root.resolve() / "*"]), ("~/*", [root.resolve() / "*"])]
                if self._kit(cur):   # SvelteKit's own alias, which no tsconfig of the project writes down
                    lib = (cur / "src" / "lib").resolve()
                    found = found + [("$lib", [lib]), ("$lib/*", [lib / "*"])]
                self._alias_cache[cur] = found + bases
                return self._alias_cache[cur]
            cur = cur.parent

    def _try(self, base: Path) -> str | None:
        # an alias may name the root folder (`"@/*": ["/"]`), which has no name to put an ending on
        named = [base.with_name(base.name + e) for e in RESOLVE_EXTS] if base.name else []
        typed = [base.with_suffix(e) for e in TS_FOR.get(base.suffix, ())] if base.name else []
        cands = [base] + typed + named + [base / ("index" + e) for e in RESOLVE_EXTS]
        for c in cands:
            # as the file is reached, then as its path is written: a file that is a link kept inside the project
            # is read under the name it has there (`inside_repo`), and an import of that name means that file
            for whole in (_reached(c), Path(os.path.normpath(c))):
                try:
                    rel = whole.relative_to(self.repo).as_posix()
                except (ValueError, AttributeError):
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

    def lost(self, spec: str, from_file: Path) -> str | None:
        """A specifier that finds no file, but which the tsconfig/jsconfig `paths` says is a path of this project
        (`"contentlayer/generated": ["./.contentlayer/generated"]`: a generated folder that is not committed):
        "exact" when an alias names this very specifier, "pattern" when a `prefix/*` alias covers it, else None.
        A catch-all `*` pattern and a target inside node_modules say nothing of the kind."""
        if not spec or spec.startswith(".") or self.resolve(spec, from_file) is not None:
            return None
        how = None
        for pat, targets in self._aliases(from_file.parent):
            if not targets or any("node_modules" in t.parts for t in targets):
                continue
            if pat == spec:
                return "exact"
            if pat.endswith("*") and len(pat) > 1 and spec.startswith(pat[:-1]):
                how = "pattern"
        return how


# --------------------------------------------------------------------------------------------
# Discovery and build
# --------------------------------------------------------------------------------------------

def discover(repo: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if not skipped_dir(dirpath, d) and not d.startswith("."))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if not inside_repo(p, repo):
                continue
            if p.suffix.lower() in HTML_EXTS and not fn.endswith(".min.html"):
                out.append(p)
            elif p.suffix == SVELTE_EXT:
                out.append(p)
            elif p.suffix in LANGS and not fn.endswith((".d.ts", ".min.js", ".bundle.js")) \
                    and not fn.startswith(("vite.config", "next.config", "tailwind.config", "postcss.config", "svelte.config",
                                           "eslint.config", "jest.config", "vitest.config", "playwright.config",
                                           "webpack.config", "babel.config", "rollup.config")) \
                    and not built_bundle(p, repo):
                out.append(p)
    return out


def built_bundle(p: Path, repo: Path | None = None) -> bool:
    """A file a build tool wrote (a Vite/webpack bundle or minified script, whatever its name): a few very long
    lines. Its functions are the libraries' code squeezed together, so mapping it adds thousands of one-letter
    nodes and copies whole lines of it into the report (one 1.3 MB bundle made a 360 MB report)."""
    try:
        if p.stat().st_size < 50_000:
            return False
        data = project_bytes(p, p.parent if repo is None else repo)
    except OSError:
        return False
    lines = data.count(b"\n") + 1
    return len(data) / lines > 500 or max(map(len, data.split(b"\n"))) > 50_000


def inline_script(src: bytes) -> bytes | None:
    """The JavaScript written inside an HTML page, as one source the JS grammar can parse, with every byte at its
    original offset (markup becomes spaces, newlines stay), so line numbers point into the HTML file itself.
    None when the page holds no such script."""
    out = bytearray(re.sub(rb"[^\n]", b" ", src))
    found = False
    for m in _SCRIPT_RE.finditer(src):
        attrs, body = m.group(1), m.group(2)
        if re.search(rb"\bsrc\s*=", attrs, re.I):
            continue
        t = re.search(rb"\btype\s*=\s*[\"']?\s*([^\"'\s>]*)", attrs, re.I)
        if (t.group(1).strip().lower() if t else b"") not in _JS_TYPES:
            continue
        if not body.strip():
            continue
        out[m.start(2):m.end(2)] = body
        found = True
    return bytes(out) if found else None


def svelte_parts(src: bytes) -> tuple[bytes, bytes, bool, list[tuple[int, int]]]:
    """A `.svelte` file taken apart: its script (every `<script>` body at its own offset, as `inline_script` does
    for a page), its markup (the rest, with scripts, styles and comments blanked), whether the script is TypeScript
    (`<script lang="ts">`), and where the script of the file itself lies (`<script module>`: it runs once, not with
    each component). Newlines stay where they are, so every line number is the file's own."""
    script = bytearray(re.sub(rb"[^\n]", b" ", src))
    markup = bytearray(src)
    ts, own = False, []
    for m in _SCRIPT_RE.finditer(src):
        attrs = m.group(1)
        markup[m.start():m.end()] = script[m.start():m.end()]
        t = re.search(rb"\btype\s*=\s*[\"']?\s*([^\"'\s>]*)", attrs, re.I)
        if re.search(rb"\bsrc\s*=", attrs, re.I) or (t.group(1).strip().lower() if t else b"") not in _JS_TYPES:
            continue
        script[m.start(2):m.end(2)] = m.group(2)
        ts = ts or bool(_SVELTE_TS.search(attrs))
        if _SVELTE_MODULE.search(attrs):
            own.append((m.start(2), m.end(2)))
    for rx in (_STYLE_RE, _COMMENT_RE):
        for m in rx.finditer(bytes(markup)):
            markup[m.start():m.end()] = re.sub(rb"[^\n]", b" ", m.group(0))
    return bytes(script), bytes(markup), ts, own


def _braces(mk: bytes) -> list[tuple[int, int]]:
    """Where each `{…}` of a Svelte file's markup opens and closes, braces inside it and its strings passed over.
    One that does not close within 4,000 bytes is not read."""
    out, i = [], 0
    while True:
        i = mk.find(b"{", i)
        if i < 0:
            return out
        depth, quote, j, end = 0, 0, i, min(len(mk), i + 4000)
        while j < end:
            c = mk[j]
            if quote:
                if c == 0x5C:
                    j += 1
                elif c == quote:
                    quote = 0
            elif c in (0x22, 0x27, 0x60):
                quote = c
            elif c == 0x7B:
                depth += 1
            elif c == 0x7D:
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= end:
            i += 1
            continue
        out.append((i, j))
        i = j + 1


def _tag_end(mk: bytes, i: int) -> int:
    """Where the tag that is open at `i` closes (its `>`), with strings and `{…}` passed over; -1 when it does not
    within 4,000 bytes."""
    quote, depth, j, end = 0, 0, i, min(len(mk), i + 4000)
    while j < end:
        c = mk[j]
        if quote:
            if c == quote:
                quote = 0
        elif c in (0x22, 0x27) or (c == 0x60 and depth):
            quote = c
        elif c == 0x7B:
            depth += 1
        elif c == 0x7D:
            depth = max(0, depth - 1)
        elif c == 0x3E and not depth:
            return j
        j += 1
    return -1


def _attr(tag: bytes, name: bytes) -> tuple[bool, str | None]:
    """An attribute of a tag: (is it written, its text when that is written out). `action={x}` is (True, None)."""
    m = re.search(rb"(?<![\w:.$-])" + name + rb"\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>{}]+))?", tag, re.I)
    if m is None:
        return False, None
    val = next((x for x in m.groups() if x is not None), None)
    return True, val.decode("utf-8", "replace") if val is not None else None


def svelte_markup(markup: bytes) -> dict:
    """What a Svelte file's markup holds for the map.
    `exprs`: the expressions written in `{…}`, each at its own offset as a statement of its own (`{` becomes `;`),
    so the JS grammar reads them with the file's line numbers: a value shown, an attribute's value, and what
    `{#if …}`, `{#each … as x}`, `{#await …}`, `{#key …}`, `{@html …}` and `{@render …}` ask for. An object or a
    function written out there is left alone (it would not stand as a statement).
    `attrs`: where an attribute's expression starts -> the event it is handed to (`onclick={…}`, `on:click={…}`:
    "onClick") or None for any other attribute.
    `tags`: (line, column, name) of each component drawn (`<Card …>`).
    `forms`: each place a form posts from, {line, action}: the text of its `action` ("" when none is written, None
    when it is worked out as the page runs), and a button's `formaction`.
    `names`: what the blocks name (`as note`, `then value`, a snippet and its parameters): no names of the script."""
    ex = bytearray(re.sub(rb"[^\n]", b" ", markup))
    starts = [0] + [m.end() for m in re.finditer(rb"\n", markup)]

    def where(pos: int) -> tuple[int, int]:
        row = bisect.bisect_right(starts, pos) - 1
        return row + 1, pos - starts[row] + 1

    attrs: dict[int, str | None] = {}
    names: set[str] = set()
    inside, intag = bytearray(len(markup)), bytearray(len(markup))
    spans = _braces(markup)
    for i, j in spans:
        inside[i:j + 1] = b"\x01" * (j + 1 - i)
    for m in _SVELTE_OPEN.finditer(markup):      # `<p>onclick={wipe}</p>` is text: no attribute outside a tag
        end = _tag_end(markup, m.end()) if not inside[m.start()] else -1
        if end > 0:
            intag[m.start():end] = b"\x01" * (end - m.start())
    for i, j in spans:
        a, b = i + 1, j
        blk = None
        if markup[a:b].lstrip()[:1] in (b"#", b":", b"/", b"@"):
            blk = _SVELTE_BLOCK.match(markup, a, b)
            if blk is None:
                named = _SVELTE_NAMES.match(markup, a, b)
                if named is not None:
                    names.update(x.decode("utf-8", "replace") for x in _JS_NAME.findall(named.group(1)))
                continue
            a = blk.end()
            tail = _SVELTE_EACH_AS if blk.group(1) == b"#each" else _SVELTE_AWAIT_THEN if blk.group(1) == b"#await" \
                else None
            cut = tail.search(markup, a, b) if tail is not None else None
            if cut is not None:
                names.update(x.decode("utf-8", "replace") for x in _JS_NAME.findall(markup[cut.end():b].split(b"(")[0]))
                b = cut.start()
        while a < b and markup[a:a + 1].isspace():
            a += 1
        if markup.startswith(b"...", a):
            a += 3
        while b > a and markup[b - 1:b].isspace():
            b -= 1
        if a >= b or _SVELTE_NOT_PLAIN.match(markup, a, b):
            continue
        ex[i:i + 1] = b";"
        ex[a:b] = markup[a:b]
        at = _SVELTE_ATTR.search(markup, max(0, i - 80), i) if blk is None and intag[i] else None
        if at is not None:
            name = at.group(1).decode("utf-8", "replace").split("|")[0]
            event = name[3:] if name.startswith("on:") else name[2:] if name.startswith("on") and \
                name[2:] in DOM_EVENTS else ""
            attrs[a] = "on" + event[:1].upper() + event[1:] if event else None
    tags = [(*where(m.start(1)), m.group(1).decode("utf-8", "replace")) for m in _SVELTE_TAG.finditer(markup)
            if not inside[m.start()]]
    forms = []
    for m in _FORM_OPEN.finditer(markup):
        end = _tag_end(markup, m.end())
        if end < 0 or inside[m.start()]:
            continue
        tag = markup[m.start():end]
        if (_attr(tag, b"method")[1] or "").upper() != "POST":
            continue
        written, action = _attr(tag, b"action")
        forms.append({"line": where(m.start())[0], "action": action if written else ""})
    for m in _FORMACTION.finditer(markup):
        if not inside[m.start()]:
            forms.append({"line": where(m.start())[0],
                          "action": (m.group(1) if m.group(1) is not None else m.group(2)).decode("utf-8", "replace")})
    forms.sort(key=lambda f: f["line"])
    return {"exprs": bytes(ex), "attrs": attrs, "tags": tags, "forms": forms, "names": names}


def read_svelte(w: "Walker", tree, script: bytes, markup: bytes, own: list[tuple[int, int]], parser) -> list:
    """One `.svelte` file into its module. The component is a function named after the file (`+page`, `Card`),
    as long as the file: what its `<script>` declares is written inside it (`+page.save`), what its markup draws,
    shows and hands to events are its calls. A `<script module>` is the file's own code, outside the component.
    Returns the statements read from the markup (for the count of calls nobody read)."""
    m = w.m
    comp = re.sub(r"[^\w$+@-]", "_", Path(m.rel).stem) or "component"
    m.defs[comp] = JSDef(local=comp, name=comp, kind="function", start=1, end=m.lines, parent_local="", in_class=None,
                         params="", fingerprint=hashlib.sha256(script + b"\x00" + markup).hexdigest()[:16], jsx=True)
    m.params[comp] = []
    m.component = m.default = comp
    w.top = comp
    kids = tree.root_node.children
    mine = [c for c in kids if any(a <= c.start_byte < b for a, b in own)]
    w.top = ""
    w.each(mine, "")
    w.top = comp
    w.each([c for c in kids if c not in mine], comp)
    m.default = comp
    got = svelte_markup(markup)
    m.forms = got["forms"]
    if got["names"]:
        m.anon_params.setdefault(comp, set()).update(got["names"])
    for line, col, name in got["tags"]:
        m.refs.append(JSRef(comp, name.split("."), line, "jsx", None, (line, col), name))
    read = []
    for st in parser.parse(got["exprs"]).root_node.children:
        if st.type != "expression_statement" or st.has_error or not st.named_child_count:
            continue
        e = st.named_children[0]
        ui = got["attrs"].get(st.start_byte, False)
        if e.type in ("identifier", "member_expression"):   # a value shown, or a function handed to an attribute
            ch = _chain(e)
            if ch and ui is not False:
                m.refs.append(JSRef(comp, ch, e.start_point[0] + 1, "callback", ui, _site_pos(e), _text(e)))
            continue
        w.each([e], comp, None, ui or None)
        read.append(st)
    return read


def kit_path(folder: str) -> str:
    """`(app)/items/[id=integer]/` under `src/routes` -> `/items/[id]`: a folder in round brackets is no part of
    the address, and a part's matcher (`=integer`) is a rule for it, not a name."""
    segs = [re.sub(r"=\w+(?=\])", "", s) for s in folder.split("/") if s and not (s.startswith("(") and s.endswith(")"))]
    return "/" + "/".join(segs)


def kit_same(route: str, written: str) -> bool:
    """Is the address a form writes (`/notes/{note.id}`) the address of this page (`/notes/[id]`)?"""
    a = [s for s in route.split("/") if s]
    b = [s for s in written.split("?")[0].split("#")[0].split("/") if s]
    return len(a) == len(b) and all(x == y or x.startswith("[") or "{" in y for x, y in zip(a, b))


def _nearest_package(path: Path, repo: Path, cache: dict) -> dict:
    cur = path.parent
    while True:
        if cur in cache:
            return cache[cur]
        pj = cur / "package.json"
        if inside_repo(pj, repo):   # a package.json that is a link out of the project is passed by, as if not there
            try:
                data = manifest.table(manifest.parse_json(project_text(pj, repo)))
            except OSError:
                data = {}
            deps = {**manifest.table(data.get("dependencies")), **manifest.table(data.get("devDependencies"))}
            info = {"dir": cur, "deps": set(deps)}
            cache[cur] = info
            return info
        if cur == repo or cur == cur.parent:
            info = {"dir": repo, "deps": set()}
            cache[cur] = info
            return info
        cur = cur.parent


def _package_name(spec: str) -> str:
    """`@scope/name/sub/path` -> `@scope/name`; `name/sub` -> `name`."""
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def nid(mod: str, local: str | None = None) -> str:
    return f"js:{mod}" if not local else f"js:{mod}::{local}"


def _ext_name(parts: list[str]) -> str:
    """A library callee reached through values and calls -> its node name: up to the first call's result and the
    member used on it (`joi.string().min` for Joi.string().min(2).required()), or at most four names when nothing
    is called on the way (`express.Request.session.destroy`)."""
    for i, p in enumerate(parts):
        if p.endswith("()"):
            tail = [t[:-2] if t.endswith("()") else t for t in parts[i + 1:i + 2]]
            return ".".join(parts[:i + 1] + tail)
    return ".".join(parts[:4])


# What a built-in call hands back, when the code goes on to use it: DOM lists and elements, a fetch's response
DOM_RESULTS = {"querySelectorAll": "NodeList", "getElementsByName": "NodeList", "getElementsByClassName":
               "HTMLCollection", "getElementsByTagName": "HTMLCollection", "querySelector": "Element",
               "getElementById": "Element", "createElement": "Element", "closest": "Element", "fetch":
               "Promise<Response>"}
# (value type, method, argument, parameter) -> what that parameter of the inline function handed over receives
CALLBACK_GIVES = {("NodeList", "forEach", 0, 0): "Element", ("HTMLCollection", "forEach", 0, 0): "Element",
                  ("Element", "addEventListener", 1, 0): "Event", ("document", "addEventListener", 1, 0): "Event",
                  ("window", "addEventListener", 1, 0): "Event", ("Promise<Response>", "then", 0, 0): "Response"}
WINDOWS = ("window", "globalThis", "self", "global")   # their members can be the app's own globals: not followed
# what the browser's window, or a worker's `self`, has besides the names in JS_BUILTINS (`window.scroll(0, 0)`,
# `window.parent.postMessage`, a service worker's `self.skipWaiting()` and `self.clients.claim()`)
WINDOW_MEMBERS = {"scroll", "focus", "blur", "stop", "moveTo", "moveBy", "resizeTo", "resizeBy", "parent", "top",
                  "opener", "frames", "visualViewport", "speechSynthesis", "skipWaiting", "clients", "registration",
                  "importScripts"}


class JSResolver:
    def __init__(self, mods: dict[str, JSModule], g: Graph, spec_for=None, express: set[str] | None = None,
                 lost_for=None):
        self.mods, self.g = mods, g
        self.spec_for = spec_for              # (module, spec) -> module name, for require('x') met while resolving
        self.lost_for = lost_for              # (module, spec) -> True: a path alias of the project that finds no file
        self.express = express or set()       # modules whose package depends on express
        self._own: dict[bool, dict] = {}      # own_names(), for app code and for test code
        self.lost: set[str] = set()           # specs that name a project file that is not there (SpecResolver.lost)
        if lost_for is not None:
            for m in mods.values():
                self.lost |= {sp for tmod, _, sp in m.imports.values() if tmod is None and lost_for(m, sp)}

    def unread(self, name: str) -> bool:
        """`name` (an import that found no file: its specifier, or `specifier.member`) names a file of the project,
        not a package: a relative, `@/`, `~/` or `#` path, or a path alias of the tsconfig/jsconfig. What comes
        from it is unknown, never "a library"."""
        return name.startswith(FILE_SPEC) or any(name == sp or name.startswith(sp + ".") for sp in self.lost)

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
                if tname == "cjs":
                    return ("cjs", tmod) if tmod else ("ext", spec)
                return self.lookup_export(tmod, tname, depth + 1) if tmod else ("ext", f"{spec}.{tname}")
        if name == "default":
            return self.lookup_export(m.cjs_from, "default", depth + 1) if m.cjs_from else None
        for tmod, mp in m.reexports:
            if mp is None:
                hit = self.lookup_export(tmod, name, depth + 1)
                if hit:
                    return hit
            elif name in mp:
                return self.lookup_export(tmod, mp[name], depth + 1)
        return None

    @staticmethod
    def _up(m: JSModule, s: str) -> str:
        """The scope around `s` whose names `s` can see: where its function is written."""
        d = m.defs.get(s)
        if d is None:
            return ""
        return d.lexical if d.lexical is not None else d.parent_local

    def bind(self, m: JSModule, scope: str, name: str):
        s = scope
        while s:
            cand = f"{s}.{name}"
            if cand in m.defs and m.defs[s].kind != "class" and not m.defs[cand].member:
                return ("def", m.name, cand)
            s = self._up(m, s)
        if name in m.defs:
            return ("def", m.name, name)
        if name.startswith("require:") and name not in m.imports:   # require('x') used in place
            spec = name[len("require:"):]
            m.imports[name] = (self.spec_for(m, spec) if self.spec_for else None, "cjs", spec)
            if m.imports[name][0] is None and self.lost_for is not None and self.lost_for(m, spec):
                self.lost.add(spec)
        if name in m.imports:
            tmod, tname, spec = m.imports[name]
            if tmod is None:
                return ("ext", spec if tname in ("default", "*", "cjs") else f"{spec}.{tname}")
            if tname == "cjs":
                return ("cjs", tmod)
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

    def open_base(self, mod: str, cls_local: str, depth: int = 0) -> bool:
        """True when the class, or a repo class it extends, extends something that is not a class in the repo: a
        library class, a computed base, a class from a file Lantern cannot find. Its members may come from there."""
        m = self.mods[mod]
        base = m.class_bases.get(cls_local)
        if not base:
            return False
        r = self.resolve_parts(m, m.defs[cls_local].parent_local, base)
        if r and r[0] == "def" and self.mods[r[1]].defs[r[2]].kind == "class" and depth < 6:
            return self.open_base(r[1], r[2], depth + 1)
        return True

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
        if r is not None and r[0] == "cjs":
            r = self.lookup_export(r[1], "default") if len(parts) == 1 else ("ns", r[1])
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
            if r[0] in ("ns", "cjs"):
                r = self.lookup_export(r[1], p)
            elif r[0] == "def":
                d = self.mods[r[1]].defs[r[2]]
                if d.kind != "class":
                    return None
                r = self.method(r[1], r[2], p)
            elif r[0] == "ext":
                r = ("ext", f"{r[1]}.{p}")
        if r is not None and r[0] == "cjs":
            r = self.lookup_export(r[1], "default")
        return r

    # ---- stage 3: values, library results, Express parameters, parameter types, constructor functions, built-ins.
    # Tried only where resolve_parts found nothing, so no link it made before changes.
    def resolve_more(self, m: JSModule, scope: str, parts: list[str], guard: bool = True, args=()):
        """-> ("def", (module, local), via, confidence) | ("ext", name, via, confidence) |
        ("builtin", name, via, confidence) | None. With `guard`, a member of a library's or the language's value is
        not called theirs when it may be the repo's own function (may_be_own; `args`: the names handed to the calls
        written inside the callee): None, and why() says so."""
        if not parts or parts[0] in ("this", "<inline>"):
            return None
        st = {"value": False}
        val, how = self._eval(m, scope, parts, 0, st)
        if val is None:
            return None
        own_calls = any(p.endswith("()") for p in parts)
        if val[0] == "ext":
            via = "library-result" if own_calls else "library-value" if st["value"] else how
            if guard and via != "import" and self.may_be_own(m, scope, parts, val, how, st, args):
                return None
            return ("ext", _ext_name([val[1]] + val[2]), via, RESOLVED if via == "import" else INFERRED)
        if val[0] == "builtin":
            if guard and self.may_be_own(m, scope, parts, val, how, st, args):
                return None
            via = how if how in ("builtin-value", "literal") else "builtin-value" if st["value"] else "global"
            return ("builtin", "builtin:" + val[1], via, RESOLVED)
        if val[0] == "def" and not own_calls:
            if how in ("param-type", "local-type"):
                return ("def", (val[1], val[2]), how, INFERRED)
            if st["value"]:
                return ("def", (val[1], val[2]), "module-value", INFERRED)
            return ("def", (val[1], val[2]), "member", RESOLVED)
        return None

    def own_names(self, test: bool) -> dict:
        """Property names the repo's own code gives a function under, by where it puts the function:
        "on": {kind of library object: names} for `res.fail = function` (the object is known: Express's response);
        "builtin": names put on a built-in type (`String.prototype.shout = ...`);
        "carried": names any value of unknown type may carry: the two above, a function put on a parameter or
        another object Lantern cannot name (`schema.statics.find = function`), and functions handed over in an
        object or by name (`schema.methods = { x () {} }`, `schema.method('x', fn)`);
        "classlike": methods of the repo's classes, constructor functions and plain objects (`const api = {}`,
        `api.load = function`), except names JavaScript's own objects have (EVERYDAY_MEMBERS).
        What test files define counts for calls in test files only."""
        if test not in self._own:
            on: dict[tuple, set[str]] = {}
            builtin: set[str] = set()
            carried: set[str] = set()
            classlike: set[str] = set()
            for m in self.mods.values():
                if m.is_test and not test:
                    continue
                for scope, owner, name, chain in m.put:
                    if chain is not None and not self._is_function(m, scope, chain):
                        continue
                    kind, key = self._owner_kind(m, scope, owner)
                    if kind == "own":
                        classlike.add(name)
                        continue
                    carried.add(name)
                    if kind == "ext":
                        on.setdefault(key, set()).add(name)
                    elif kind == "builtin":
                        builtin.add(name)
                carried |= {name for scope, name, chain in m.given
                            if chain is None or self._is_function(m, scope, chain)}
                classlike |= {d.name for d in m.defs.values() if d.kind != "class" and (d.in_class or d.member)}
            self._own[test] = {"on": on, "builtin": builtin, "carried": carried,
                               "classlike": classlike - EVERYDAY_MEMBERS}
        return self._own[test]

    def _is_function(self, m: JSModule, scope: str, chain: list[str]) -> bool:
        r = self.resolve_parts(m, scope, chain)
        return r is not None and r[0] == "def" and self.mods[r[1]].defs[r[2]].kind != "class"

    def _owner_kind(self, m: JSModule, scope: str, owner: list[str]) -> tuple[str, tuple | None]:
        """What a function was put on (`owner.name = function`): ("ext", kind) a library's object, ("builtin", None)
        a built-in type, ("own", None) the repo's own function, class, module or plain object, or ("outside", None)
        something Lantern cannot name (a parameter, `this` outside a constructor, an unknown value)."""
        root = owner[0]
        if root == "this":   # inside a class or a function with a name: the object it builds; elsewhere: unknown
            d = m.defs.get(scope)
            return ("own" if d is not None and (d.in_class or d.kind == "function") else "outside"), None
        if root in WINDOWS and self.bind(m, scope, root) is None and self.name_kind(m, scope, root) is None:
            return "own", None   # window.App.start = function: the page's own global, not a method put on a value
        val, _ = self._eval(m, scope, owner, 0, {"value": False})
        if val is not None:
            if val[0] == "ext":
                return "ext", self._kind(val[1], val[2])
            return ("builtin" if val[0] == "builtin" else "own"), None
        b = self.bind(m, scope, root)
        if b is not None and b[0] != "ext":   # a function, class or module of the repo, however deep the property
            return "own", None
        s = scope
        while True:   # `const api = {}` / `var self = this`: the repo's own object
            if root in m.plain.get(s, ()):
                return "own", None
            if not s or root in m.declared.get(s, ()) or root in m.params.get(s, ()):
                break
            s = self._up(m, s)
        return "outside", None

    @staticmethod
    def _kind(base: str, members: list[str]) -> tuple:
        """One name for a kind of library object, however the code reached it: `express.response` and `app.response`
        are the response a handler gets as `res`; a type's `prototype` is the type."""
        members = [x for x in members if x != "prototype"]
        if base in ("express", "express()") and members[-1:] in (["response"], ["request"]):
            base, members = "express", [members[-1].capitalize()]
        return (base, *members)

    def may_be_own(self, m: JSModule, scope: str, parts: list[str], val, how: str | None, st: dict,
                   args=()) -> bool:
        """`x.name()` where `x` came from a library or is a built-in value: could `name` be the repo's own function?
        A value of a known kind (Express's `req`, `res`, app and router, a written TypeScript type,
        `new LibraryClass()`, a built-in value), one step deep: only when the repo puts a function of that name on
        that kind of object. Anything else (what a library call returned, a property of `req`): when the repo puts
        such a function on an object Lantern cannot name or hands one over in an object, when a class of the repo
        with that method was handed to the library calls the value came from (`getRepository(User).findOne()`), and,
        for what hangs on `req` and `res`, when any class of the repo has a method of that name."""
        if len(parts) < 2:
            return False
        own, name = self.own_names(m.is_test), parts[-1]
        if val[0] == "builtin":
            return name in own["builtin"]
        express_object = (val[1] == "express()" and len(val[2]) == 1) or \
            (val[1] == "express" and len(val[2]) == 2 and val[2][0] == "Router()")
        if len(parts) == 2 and not parts[0].endswith("()") and \
                (how in ("express-param", "param-type", "local-type") or express_object):
            return name in own["on"].get(self._kind(val[1], val[2][:-1]), ())
        if name in own["carried"] or how == "express-param" and name in own["classlike"]:
            return True
        for mm, s, chain in [*st.get("args", ()), *((m, scope, c) for c in args)]:
            r = self.resolve_parts(mm, s, chain)
            if r is not None and r[0] == "def" and self.method(r[1], r[2], name) is not None and (
                    self.mods[r[1]].defs[r[2]].kind == "class" or r[2] in self.mods[r[1]].ctors):
                return True
        return False

    def _eval(self, m: JSModule, scope: str, chain: list[str], depth: int, st: dict):
        """Follow a chain (`app`, `use`), (`Joi`, `string()`, `min`) to a value: ("ext", base, members),
        ("builtin", type), ("def", module, local), ("inst", module, class local) or ("ns", module)."""
        if depth > 6 or not chain:
            return None, None
        if chain[0] in ("<array>", "<string>"):
            val, how = ("builtin", "Array" if chain[0] == "<array>" else "String"), "literal"
        else:
            head = chain[0]
            called = head.endswith("()")
            val, how = self._head(m, scope, head[:-2] if called else head, depth, st)
            if val is not None and called:
                val = self._call_value(val)
        for p in chain[1:]:
            if val is None:
                return None, None
            called = p.endswith("()")
            val = self._member(val, p[:-2] if called else p, depth, st)
            if val is not None and called:
                val = self._call_value(val)
        return val, how

    def _head(self, m: JSModule, scope: str, name: str, depth: int, st: dict):
        b = self.bind(m, scope, name)
        if b is not None:
            if b[0] == "ext":   # an import of a file that is not in the repo is not a library
                return (None, None) if self.unread(b[1]) else (("ext", b[1], []), "import")
            if b[0] in ("cjs", "ns"):
                return ("ns", b[1]), "import"
            return ("def", b[1], b[2]), "member"
        s = scope
        while True:
            if name in m.params.get(s, ()) or name in m.anon_params.get(s, ()):
                return self._param(m, s, name, depth, st)
            vals = m.values.get(s, {})
            if name in vals and name not in m.reassigned.get(s, ()) and name not in m.dynamic.get(s, ()):
                was = st["value"]
                st["value"] = True
                st.setdefault("args", []).extend((m, s, c) for c in m.value_args.get(s, {}).get(name, ()))
                v, inner = self._eval(m, s, vals[name], depth + 1, st)
                typed = self._written(m, s, name) if v is None else None
                if typed is None:
                    return v, (inner if v is not None and v[0] == "builtin" else "library-value")
                st["value"] = was
                return typed, "local-type"
            lt = m.local_types.get(s, {}).get(name)
            if lt and lt != ["<server>"]:
                return self._type(m, s, lt), "local-type"
            typed = self._written(m, s, name)
            if typed is not None:
                return typed, "local-type"
            if name in m.declared.get(s, ()) or name in m.dynamic.get(s, ()):
                return None, None
            if not s:
                break
            s = self._up(m, s)
        imp = m.imports.get(name)
        if imp is not None and imp[0] in self.mods and imp[1] not in ("cjs", "*"):
            v = self._exported_value(imp[0], imp[1], depth + 1, st)
            if v is not None:   # import { db } from "./db", where db is a value that file exports
                st["value"] = True
                return v, "import"
        if name in JS_BUILTINS:
            return ("builtin", name), "global"
        return None, None

    def _written(self, m: JSModule, s: str, name: str):
        """The value a variable's written TypeScript type names (`let prisma: PrismaClient`): a library's class or
        a class of the repo. None for no type, one of several, or a type that is no class Lantern can look in."""
        t = m.var_types.get(s, {}).get(name)
        return self._type(m, s, t) if t else None

    def _exported_value(self, mod: str, name: str, depth: int, st: dict):
        """What a file of the project exports under `name`, when that is a value and not a function or a class:
        `export const db = new PrismaClient()`, `export default pool`, `export { db } from "./db"`, `exports.db = …`.
        The value as _eval gives it; None when the name is set again with no written type to hold it, or is built in
        a way Lantern does not follow (a condition, an object written out, a call of a function of the project)."""
        if depth > 6:
            return None
        tm = self.mods[mod]
        local = tm.default if name == "default" else tm.exports.get(name)
        if local is not None and local not in tm.defs:
            if local in tm.reassigned.get("", ()) and local not in tm.var_types.get("", {}):
                return None
            v = self._eval(tm, "", [local], depth + 1, st)[0]
            if v is not None:
                return v
        if name in tm.export_values:   # CommonJS: exports.db = mysql.createPool()
            return self._eval(tm, "", tm.export_values[name], depth + 1, st)[0]
        if name in tm.export_new:
            return self._type(tm, "", tm.export_new[name])
        for tmod, mp in tm.reexports:
            if tmod in self.mods and (mp is None or name in mp):
                hit = self._exported_value(tmod, name if mp is None else mp[name], depth + 1, st)
                if hit is not None:
                    return hit
        return None

    def _param(self, m: JSModule, s: str, name: str, depth: int, st: dict):
        """A parameter: its written TypeScript type, its place in an Express handler, or what a built-in passes
        to the inline function it belongs to. Anything else is not followed."""
        t = m.param_types.get(s, {}).get(name)
        if t:
            v = self._type(m, self._up(m, s), t)
            if v is not None:
                return v, "param-type"
        if m.name in self.express:
            lists = ([m.params[s]] if name in m.params.get(s, ()) else []) + \
                [x for x in m.param_lists.get(s, ()) if name in x]
            for ps in lists:
                role = _express_role(ps).get(name)
                if role:
                    return ("ext", "express", [role]), "express-param"
        cb = m.cb_params.get(s, {}).get(name)
        if cb and len(cb[0]) >= 2:
            recv, _ = self._eval(m, s, list(cb[0][:-1]), depth + 1, {"value": False})
            if recv is not None and recv[0] == "builtin":
                gives = CALLBACK_GIVES.get((recv[1], cb[0][-1], cb[1], cb[2]))
                if gives:
                    return ("builtin", gives), "builtin-value"
        return None, None

    def _type(self, m: JSModule, scope: str, chain: list[str]):
        r = self.resolve_parts(m, scope, chain)
        if r is not None and r[0] == "def":
            d = self.mods[r[1]].defs[r[2]]
            if d.kind == "class" or r[2] in self.mods[r[1]].ctors:
                return ("inst", r[1], r[2])
            return None
        if r is not None and r[0] == "ext":
            return None if self.unread(r[1]) else ("ext", r[1], [])
        if r is None and len(chain) == 1 and chain[0] in JS_BUILTINS:
            return ("builtin", chain[0])
        return None

    def _member(self, val, name: str, depth: int, st: dict):
        kind = val[0]
        if kind == "ext":
            return ("ext", val[1], val[2] + [name])
        if kind == "builtin":
            return None if val[1] in WINDOWS else ("builtin", f"{val[1]}.{name}")
        if kind == "def":
            mm = self.mods[val[1]]
            if f"{val[2]}.{name}" in mm.defs:
                return ("def", val[1], f"{val[2]}.{name}")
            if mm.defs[val[2]].kind == "class":
                hit = self.method(val[1], val[2], name)
                return ("def", hit[1], hit[2]) if hit else None
            return None
        if kind == "inst":
            hit = self.method(val[1], val[2], name)
            return ("def", hit[1], hit[2]) if hit else None
        if kind == "ns":
            mm = self.mods.get(val[1])
            if mm is None:
                return None
            r = self.lookup_export(val[1], name)
            if r is not None:
                if r[0] == "def":
                    return ("def", r[1], r[2])
                if r[0] == "ext":
                    return None if self.unread(r[1]) else ("ext", r[1], [])
                return ("ns", r[1])
            if name in mm.export_values:
                st["value"] = True
                return self._eval(mm, "", mm.export_values[name], depth + 1, st)[0]
            if name in mm.export_new:
                st["value"] = True
                return self._type(mm, "", mm.export_new[name])
            v = self._exported_value(val[1], name, depth + 1, st)
            if v is not None:   # import * as lib from "./lib"; lib.db: a value the file exports
                st["value"] = True
                return v
            whole = None   # module.exports = <a value>: its members
            if "default" in mm.export_values:
                st["value"] = True
                whole = self._eval(mm, "", mm.export_values["default"], depth + 1, st)[0]
            elif "default" in mm.export_new:
                st["value"] = True
                whole = self._type(mm, "", mm.export_new["default"])
            return self._member(whole, name, depth + 1, st) if whole is not None and depth < 6 else None
        return None

    # ---- Supabase (roadmap stage 1): is a value a client, and which table does a call go into
    def client(self, m: JSModule, scope: str, chain: list[str], depth: int = 0):
        """Is the value a chain names a Supabase client? -> the library call or type it came from
        (`@supabase/supabase-js.createClient()`), False when it is a known other thing, None when it is not known.
        Followed here and nowhere else: what a function of the project hands back when every `return` of it is a
        client. (A value another file of the project exports, `export const supabase = createClient(…)`, is followed
        for every library since _exported_value.)"""
        if depth > 6 or not chain:
            return None
        val, _ = self._eval(m, scope, chain, depth, {"value": False})
        if val is not None:
            name = ".".join([val[1]] + val[2]) if val[0] == "ext" else ""
            return name if SUPABASE_CLIENT.match(name) else False
        if len(chain) != 1:
            return None
        name = chain[0]
        if name.endswith("()"):
            b = self.bind(m, scope, name[:-2])
            if b is None or b[0] != "def":
                return None
            tm = self.mods[b[1]]
            found = [self.client(tm, b[2], c, depth + 1) if c else None for c in tm.returned.get(b[2], ())]
            return sorted(found)[0] if found and all(isinstance(x, str) for x in found) else None
        s, seen = scope, []
        while True:
            seen.append(s)
            if name in m.params.get(s, ()) or name in m.anon_params.get(s, ()):
                return None
            if name in m.values.get(s, {}):
                if name in m.dynamic.get(s, ()) or any(name in m.reassigned.get(x, ()) for x in seen):
                    return None
                return self.client(m, s, m.values[s][name], depth + 1)
            if name in m.declared.get(s, ()) or name in m.dynamic.get(s, ()):
                return None
            if not s:
                break
            s = self._up(m, s)
        imp = m.imports.get(name)
        if imp is not None and imp[0] in self.mods and imp[1] not in ("cjs", "*"):
            return self._exported_client(imp[0], imp[1], depth + 1)
        return None

    def _exported_client(self, mod: str, name: str, depth: int):
        if depth > 6:
            return None
        tm = self.mods[mod]
        local = tm.default if name == "default" else tm.exports.get(name)
        if local is not None and local not in tm.defs:
            if local in tm.values.get("", {}):
                if local in tm.reassigned.get("", ()) or local in tm.dynamic.get("", ()):
                    return None
                return self.client(tm, "", tm.values[""][local], depth + 1)
            imp = tm.imports.get(local)
            if imp is not None and imp[0] in self.mods and imp[1] not in ("cjs", "*"):
                return self._exported_client(imp[0], imp[1], depth + 1)
        if name in tm.export_values:   # CommonJS: exports.supabase = createClient(…)
            return self.client(tm, "", tm.export_values[name], depth + 1)
        for tmod, mp in tm.reexports:
            if tmod in self.mods and (mp is None or name in mp):
                hit = self._exported_client(tmod, name if mp is None else mp[name], depth + 1)
                if hit is not None:
                    return hit
        return None

    def _const(self, m: JSModule, scope: str, name: str) -> str | None:
        """The text of a constant of the file, when `name` in this scope is that constant and nothing nearer."""
        s = scope
        while s:
            if name in m.params.get(s, ()) or name in m.anon_params.get(s, ()) or name in m.declared.get(s, ()):
                return None
            s = self._up(m, s)
        if name in m.reassigned.get("", ()) or name in m.anon_params.get("", ()):
            return None
        text = m.consts.get(name)
        return text if text is not None and TABLE_NAME.match(text) else None

    def table_call(self, m: JSModule, scope: str, db: dict):
        """A call written `<recv>.from("<table>").<op>(…)` -> (table id, confidence, via), or None when `<recv>` is
        not a Supabase client as far as the code shows, or the table's name is not written. A client by where the
        value came from is a likely link (`supabase-from`); a value Lantern cannot follow that is only named like
        one (`supabase`, `this.supabase`) a possible one (`supabase-name`)."""
        table = db["table"] if db["table"] is not None else self._const(m, scope, db["const"])
        if table is None:
            return None
        schema = None if db["schema"] == "public" else db["schema"]   # `public` is where a table is unless said
        tid = "db:" + (f"{schema}.{table}" if schema else table)
        recv = db["recv"]
        known = self.client(m, scope, recv)
        if known:
            return tid, table, INFERRED, "supabase-from"
        if known is None and SUPABASE_NAME.match(recv[-1]) and (recv[0] == "this" or len(recv) == 1):
            if len(recv) == 1:   # a name that was given another value, or that is a function or an import, is none
                s = scope
                while True:
                    if recv[0] in m.reassigned.get(s, ()) or recv[0] in m.dynamic.get(s, ()):
                        return None
                    if not s:
                        break
                    s = self._up(m, s)
                if self.bind(m, scope, recv[0]) is not None:
                    return None
            return tid, table, POSSIBLE, "supabase-name"
        return None

    def on_client(self, m: JSModule, scope: str, parts: list[str], args=()) -> str | None:
        """A call on a Supabase client that came from another file or from a function of the project
        (`supabase.from`, `supabase.from().select().order`, `supabase.auth.getUser`) -> the library name it is a
        call of, as resolve_more names the same call on a client made in this file."""
        for k in (1, 2):
            if len(parts) > k and not (k == 2 and parts[0] != "this"):
                base = self.client(m, scope, parts[:k])
                if base:
                    if self.may_be_own(m, scope, parts, ("ext", base, parts[k:-1]), "library-value",
                                       {"value": True}, args):
                        return None
                    return _ext_name([base] + parts[k:])
        return None

    @staticmethod
    def _call_value(val):
        if val[0] == "ext":
            if val[2]:
                return ("ext", val[1], val[2][:-1] + [val[2][-1] + "()"])
            return ("ext", val[1] + "()", [])
        if val[0] == "builtin":
            last = val[1].rsplit(".", 1)[-1]
            return ("builtin", DOM_RESULTS.get(last, val[1] + "()"))
        return None   # what a repo function returns is not followed here

    def name_kind(self, m: JSModule, scope: str, name: str) -> str | None:
        """What `name` is where it is used: "param" (of the function or of an inline function in it), "dynamic"
        (set by require() of a path built at run time), "local", "module" (a variable at the top of the file), or
        None (not declared in this file)."""
        s = scope
        while True:
            if name in m.params.get(s, ()) or name in m.anon_params.get(s, ()):
                return "param"
            if name in m.dynamic.get(s, ()):
                return "dynamic"
            if name in m.declared.get(s, ()):
                return "local" if s else "module"
            if not s:
                return None
            s = self._up(m, s)

    def global_doubt(self, m: JSModule, parts: list[str]) -> str | None:
        """A call that starts at a global name (`window`, `Array`, `document`) and is not a built-in for sure: the
        reason code, or None. `window.App.init()`: a property of the global object that is not one of the browser's
        or Node's own names, so any script may have put it there. `Array.from(x).last()`: a method on a built-in
        value, where the repo itself puts a function of that name on a built-in type."""
        if parts[0] in WINDOWS and len(parts) > 1 and \
                parts[1].removesuffix("()") not in JS_BUILTINS | WINDOW_MEMBERS:
            return "global-property"
        if len(parts) > 2 and any(x.endswith("()") for x in parts[:-1]) and \
                parts[-1] in self.own_names(m.is_test)["builtin"]:
            return "library-or-repo"
        return None

    def why(self, m: JSModule, scope: str, parts: list[str]) -> str:
        """The reason code (calls.REASONS) for a call resolve_parts could not follow."""
        if not parts:
            return "computed"
        head = parts[0]
        if self.resolve_more(m, scope, parts, guard=False) is not None:
            return "library-or-repo"   # a library's or built-in value, and a name the repo gives a function too
        if head in JS_BUILTINS and self.bind(m, scope, head) is None and self.name_kind(m, scope, head) is None:
            doubt = self.global_doubt(m, parts)
            if doubt:
                return doubt
        if m.svelte and len(head) > 1 and head.startswith("$") and self.bind(m, scope, head) is None:
            return "local-unknown"     # `$page.url…` in a Svelte file: what the store `page` holds right now
        if head == "this":
            d = m.defs.get(scope)
            if not (d and d.in_class):
                return "this-outside-class"
            if len(parts) != 2:
                return "self-attribute"
            return "unknown-base" if self.open_base(m.name, d.in_class) else "not-in-class"
        if any(p.endswith("()") for p in parts):
            return "call-result"
        b = self.bind(m, scope, head)
        if b is None:
            if head in m.imports and self.name_kind(m, scope, head) is None:
                return "missing-export"
            k = self.name_kind(m, scope, head)
            if k == "dynamic":
                return "dynamic-require"
            if k == "param":
                return "callback-parameter" if len(parts) == 1 else "parameter"
            if k == "local":
                return "local-unknown"
            if k == "module":
                return "repo-variable"
            return "not-defined"
        if b[0] == "def" and self.mods[b[1]].defs[b[2]].kind != "class":
            return "function-member"
        return "missing-member"

    def _local_type(self, m: JSModule, scope: str, var: str):
        s = scope
        while True:
            t = m.local_types.get(s, {}).get(var)
            if t:
                return t if t != ["<server>"] else None
            if not s:
                return None
            s = self._up(m, s)


def _join_path(prefix: str, path: str) -> str:
    """'/api/notes' + '/' -> '/api/notes'; '/admin' + '/reset' -> '/admin/reset'; '' + '/x' -> '/x'."""
    prefix = prefix.rstrip("/")
    if path in ("", "/"):
        return prefix or "/"
    return prefix + (path if path.startswith("/") else "/" + path)


def _express_role(ps: list[str]) -> dict[str, str]:
    """Parameters of an Express handler, by position: (req, res, next) or (err, req, res, next)."""
    if len(ps) >= 2 and ps[0] in REQ_NAMES and ps[1] in RES_NAMES:
        out = {ps[0]: "Request", ps[1]: "Response"}
        if len(ps) >= 3 and ps[2] == "next":
            out["next"] = "next"
        return out
    if len(ps) >= 3 and ps[0] in ("err", "error", "e") and ps[1] in REQ_NAMES and ps[2] in RES_NAMES:
        out = {ps[1]: "Request", ps[2]: "Response"}
        if len(ps) >= 4 and ps[3] == "next":
            out["next"] = "next"
        return out
    return {}


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


def _trpc_served(m: JSModule, mt: dict, repo: Path, pkg_cache: dict) -> str | None:
    """The address a tRPC handler serves under: the `endpoint` it is given, the path of the `use("/path", …)` it is
    written in, the Next.js route file it stands in (`app/api/trpc/[trpc]/route.ts` -> /api/trpc), "/" for a server
    of its own; None where the code does not say."""
    ep = mt["endpoint"]
    if ep is None:
        pkg = _nearest_package(m.path, repo, pkg_cache)
        rel = m.path.relative_to(pkg["dir"]).as_posix() if pkg["dir"] in m.path.parents else m.rel
        at = _route_path_from_file(rel, "route") if "next" in pkg["deps"] else None
        if at and re.search(r"/\[[^/]+\]$", at):
            ep = at.rsplit("/", 1)[0]
        elif mt["adapter"] in TRPC_AT_ROOT:
            ep = "/"
    return None if ep is None else "/" + ep.strip("/")


def _trpc_plan(mods: dict[str, JSModule], r: "JSResolver", repo: Path, pkg_cache: dict, target_id) -> dict | None:
    """Which function answers which tRPC procedure, and at which address (roadmap of 2026-11-14, stage 1).

    The Walker wrote down everything shaped like a router. One counts where what made it is tRPC's own
    (`initTRPC.create().router`, followed through the files: `made_by_trpc`), where a procedure in it is built on
    tRPC's `procedure` (or, where that is not followed, on a name that says procedure), where it is handed to one
    of tRPC's handlers, or where such a router holds it. A router nobody holds is a root; a procedure's path is the
    keys on the way to it, and its address the root's mount, where the code says one, and that path."""
    keys = [(m.name, i) for m in mods.values() for i in range(len(m.trpc_routers))]
    if not keys:
        return None
    by_name: dict[tuple, tuple] = {}
    for k in keys:
        rec = mods[k[0]].trpc_routers[k[1]]
        by_name.setdefault((k[0], rec["scope"], rec["name"]), k)

    def home(m: JSModule, scope: str, name: str, depth: int = 0):
        """Where a name is declared: (module, scope, name), in this file or in the one it is imported from."""
        if depth > 8:
            return None
        s = scope
        while True:
            if name in m.declared.get(s, ()) or (m.name, s, name) in by_name:
                return m, s, name
            if not s:
                break
            s = r._up(m, s)
        imp = m.imports.get(name)
        if imp is None or imp[0] not in mods or imp[1] in ("cjs", "*"):
            return None
        return exported(mods[imp[0]], imp[1], depth + 1)

    def exported(tm: JSModule, name: str, depth: int = 0):
        if depth > 8:
            return None
        if name == "default" and (tm.name, "", "default") in by_name:
            return tm, "", "default"
        local = tm.default if name == "default" else tm.exports.get(name)
        if local is not None:
            if local in tm.imports and local not in tm.declared.get("", ()):
                return home(tm, "", local, depth + 1)
            return tm, "", local
        for tmod, mp in tm.reexports:
            if tmod in mods and (mp is None or name in mp):
                hit = exported(mods[tmod], name if mp is None else mp[name], depth + 1)
                if hit is not None:
                    return hit
        return None

    def router_at(m: JSModule, scope: str, chain: list[str] | None):
        """The router a name written in `scope` stands for (also `routers.post` of `import * as routers`)."""
        at = None
        if chain and len(chain) == 1:
            at = home(m, scope, chain[0])
        elif chain and len(chain) == 2:
            imp = m.imports.get(chain[0])
            if imp is not None and imp[0] in mods and imp[1] == "*":
                at = exported(mods[imp[0]], chain[1])
        return by_name.get((at[0].name, at[1], at[2])) if at else None

    def made_by_trpc(m: JSModule, scope: str, chain: list[str]) -> bool | None:
        """True where the chain is followed to something of @trpc/server, False where to another library or to
        the language's own, None where it is not followed."""
        val = r._eval(m, scope, list(chain), 0, {"value": False})[0] if chain else None
        if val is None or val[0] not in ("ext", "builtin"):
            return None
        return val[0] == "ext" and val[1].startswith(TRPC_SERVER)

    def built_on(m: JSModule, scope: str, chain: list[str], depth: int = 0):
        """What a procedure is built on, through the names it is given: -> (the names on the way, nearest first;
        the `.use()` steps in the order they run, each as (module, scope, step); made by tRPC or not, as above)."""
        if depth > 8 or not chain:
            return [], [], None
        if len(chain) == 1 and not chain[0].endswith("()"):
            at = home(m, scope, chain[0])
            if at is not None:
                tm, ts, local = at
                rec = tm.trpc_bases.get((ts, local))
                if rec is not None:
                    names, uses, ok = built_on(tm, ts, rec["base"], depth + 1)
                    return [local, *names], [*uses, *((tm, ts, u) for u in rec["uses"])], ok
                v = tm.values.get(ts, {}).get(local)
                if v and local not in tm.reassigned.get(ts, ()):
                    names, uses, ok = built_on(tm, ts, v, depth + 1)
                    return [local, *names], uses, ok
                return [local], [], None
        return [], [], made_by_trpc(m, scope, chain)

    info: dict[tuple, tuple] = {}
    for k in keys:
        m = mods[k[0]]
        rec = m.trpc_routers[k[1]]
        items = []
        for it in rec["items"]:
            if it["kind"] == "procedure":
                items.append((it, *built_on(m, rec["scope"], it["base"])))
            else:
                items.append((it, (m.name, it["inline"]) if it.get("inline") is not None
                              else router_at(m, rec["scope"], it.get("chain"))))
        info[k] = (m, rec, items)
    mounts: dict[tuple, str | None] = {}
    loose: list[str | None] = []
    for m in mods.values():
        for mt in m.trpc_mounts:
            k = (m.name, mt["inline"]) if mt["inline"] is not None else router_at(m, mt["scope"], mt["router"])
            if k in info:
                mounts.setdefault(k, _trpc_served(m, mt, repo, pkg_cache))
            else:
                loose.append(_trpc_served(m, mt, repo, pkg_cache))
    good = set(mounts) | {
        k for k, (m, rec, items) in info.items()
        if (rec["callee"] and made_by_trpc(m, rec["scope"], rec["callee"]))
        or any(x[0]["kind"] == "procedure" and (x[3] or (x[3] is None and "procedure" in x[0]["base"][-1].lower()))
               for x in items)}
    todo = list(good)
    while todo:
        for x in info[todo.pop()][2]:
            if x[0]["kind"] != "procedure" and x[1] in info and x[1] not in good:
                good.add(x[1])
                todo.append(x[1])
    held = {x[1] for k in good for x in info[k][2] if x[0]["kind"] != "procedure" and x[1] in good}
    roots = [k for k in keys if k in good and k not in held]
    bare = [k for k in roots if k not in mounts]
    if len(loose) == 1 and len(bare) == 1:      # one handler whose router is not followed, one router nobody mounts
        mounts[bare[0]] = loose[0]
    procs: list[dict] = []
    seen: set[str] = set()

    def walk(k: tuple, prefix: list[str], mount: str | None, trail: tuple) -> None:
        if k in trail or len(trail) > 12:
            return
        m, rec, items = info[k]
        for x in items:
            it = x[0]
            if it["kind"] != "procedure":
                if x[1] in good:
                    walk(x[1], prefix + ([it["key"]] if it["kind"] == "router" else []), mount, (*trail, k))
                continue
            if x[3] is False:       # built on another library's value: `queue.query(fn)` in a router is no procedure
                continue
            if "local" in it:
                tid = nid(m.name, it["local"])
            else:
                res = r.resolve_parts(m, rec["scope"], it["handler"])
                if res is None:
                    more = r.resolve_more(m, rec["scope"], it["handler"])
                    res = ("def", *more[1]) if more is not None and more[0] == "def" else None
                tid = target_id(res) if res is not None and res[0] == "def" else None
            node = r.g.nodes.get(tid) if tid else None
            if node is None or node.kind != CALLABLE or tid in seen:
                continue
            seen.add(tid)
            path = ".".join([*prefix, it["key"]])
            procs.append({"m": m, "scope": rec["scope"], "item": it, "tid": tid, "path": path, "mount": mount,
                          "detail": f"{TRPC_KINDS[it['type']]} {(mount or '').rstrip('/')}/{path}",
                          "names": x[1], "uses": x[2]})

    for k in [*(k for k in keys if k in mounts), *roots]:
        walk(k, [], mounts.get(k), ())
    paths: dict[str, list[dict]] = {}
    for proc in procs:
        paths.setdefault(proc["path"], []).append(proc)
    return {"procs": procs, "paths": paths, "routers": len(good), "calls": 0, "linked": 0}


def add_js(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo).resolve()
    paths = discover(repo)
    if not paths:
        return {"files": 0, "lines": 0}
    files = {}
    for p in paths:
        rel = p.relative_to(repo).as_posix()
        # a page, a Svelte component and a `.svelte.ts` file keep their whole name: `Toast.svelte` and
        # `Toast.svelte.ts` may stand side by side
        files[rel] = rel if p.suffix.lower() in HTML_EXTS or p.suffix == SVELTE_EXT or RUNE_FILE.search(rel) \
            else re.sub(r"\.[cm]?[jt]sx?$", "", rel)
    spec = SpecResolver(repo, files)
    parsers = {ext: Parser(lang) for ext, lang in LANGS.items()}
    mods: dict[str, JSModule] = {}
    pkg_cache: dict = {}
    total = 0
    for p in paths:
        rel = p.relative_to(repo).as_posix()
        try:
            src = project_bytes(p, repo)
        except OSError:
            continue
        if len(src) > 1_500_000:
            continue
        html, svelte = p.suffix.lower() in HTML_EXTS, p.suffix == SVELTE_EXT
        markup = own = None
        ext = ".js" if html else p.suffix
        if html:
            src = inline_script(src)
            if src is None:
                continue
        elif svelte:
            src, markup, ts, own = svelte_parts(src)
            ext = ".ts" if ts else ".js"
        total += src.count(b"\n") + 1
        tree = parsers[ext].parse(src)
        m = JSModule(name=files[rel], rel=rel, path=p, lines=src.count(b"\n") + 1, is_test=bool(TEST_RE.search(rel)),
                     html=html, svelte=svelte, runes=svelte or bool(RUNE_FILE.search(rel)))
        pkg = _nearest_package(p, repo, pkg_cache)
        in_kit = p.relative_to(pkg["dir"]).as_posix() \
            if KIT in pkg["deps"] and not m.is_test and pkg["dir"] in p.parents else None
        km = KIT_FILE.match(in_kit) if in_kit else None
        w = Walker(m, lambda s, _p=p: spec.resolve(s, _p), trpc=not m.is_test and TRPC_SERVER in pkg["deps"],
                   kit=km.group("kind") if km is not None and not svelte else
                   "hooks" if in_kit and KIT_HOOKS.match(in_kit) else None)
        shown = []
        if svelte:
            shown = read_svelte(w, tree, src, markup, own, parsers[ext])
        else:
            w.each(tree.root_node.children, "")
        if not html and not svelte:
            m.directives = _directives(tree.root_node)
        covered = {ref.at for ref in m.refs if ref.at}
        for cn in [x for top in (tree.root_node, *shown) for x in _call_nodes(top)]:
            pos = _site_pos(cn)
            if pos in covered:
                continue
            fnode = cn.child_by_field_name("function") or cn.child_by_field_name("constructor") or \
                cn.child_by_field_name("name")
            inner = _unparen(fnode)
            kind = "inline" if inner is not None and inner.type in FUNC_TYPES else \
                "require" if fnode is not None and fnode.end_byte - fnode.start_byte == 7 and \
                _text(fnode) == "require" else "other"
            m.unread.append((pos, cn.start_point[0] + 1, _head(src, fnode), kind))
        mods[m.name] = m

    express = {m.name for m in mods.values() if "express" in _nearest_package(m.path, repo, pkg_cache)["deps"]}

    def lost_for(mod: JSModule, sp: str) -> bool:
        """An import that found no file names a file of the project, never a package, when the tsconfig maps it to
        a path of the project. Not when what runs is then a package the project depends on: an alias for the
        package's own name (`"joi": ["./shims/joi"]`), or a `prefix/*` alias that also covers a dependency
        (`@acme/*` for the repo's own packages, beside `@acme/published` installed from npm)."""
        how = spec.lost(sp, mod.path)
        if how is None:
            return False
        deps = _nearest_package(mod.path, repo, pkg_cache)["deps"]
        return sp not in deps if how == "exact" else _package_name(sp) not in deps

    r = JSResolver(mods, g, spec_for=lambda mod, sp: spec.resolve(sp, mod.path), express=express, lost_for=lost_for)
    # nodes
    for m in mods.values():
        g.add_node(Node(id=nid(m.name), kind=MODULE, name=Path(m.rel).name, qualname=m.name, file=m.rel,
                        start_line=1, end_line=m.lines))
        for line in m.too_deep:
            deep.note(g, m.rel, line, "javascript")
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

    def site(m: JSModule, ref: JSRef, src_id: str, targets=None, reason: str | None = None, group: str = "written"):
        at = ref.at or (ref.line, 0)
        calls.record(g.sites, file=m.rel, line=at[0], col=at[1], callee=ref.text or ".".join(ref.parts), caller=src_id,
                     lang=JS_LANG, group=group, test=m.is_test, targets=targets, reason=reason)

    # tRPC: which function answers which procedure. Worked out here, before the calls are read, so that a call
    # through tRPC's client can be linked to its procedure; the entries are set below, with the other routes
    trpc = _trpc_plan(mods, r, repo, pkg_cache, target_id)
    trpc_users = {m.name for m in mods.values() if trpc is not None and not m.is_test and any(
        d.startswith("@trpc/") for d in _nearest_package(m.path, repo, pkg_cache)["deps"])}

    def trpc_call(m: JSModule, ref: JSRef):
        """`api.post.create.useMutation()`: a request to the procedure `post.create` -> (the procedures of that
        path, confidence), or None for a call that is none. Confirmed on a client that one of tRPC's own functions
        made (`createTRPCReact()`, `createTRPCClient()`); likely where the client is not followed (it comes out of a
        hook, a parameter), the path is a procedure and the last name is one of tRPC's hooks or option makers. No
        link on an object of the project's own, on another library's value, or for `mutate` and `query` on a name
        Lantern cannot place."""
        parts = ref.parts
        if len(parts) < 3 or parts[-1] not in TRPC_HOOKS | TRPC_CALLS or parts[0] == "this" or \
                any(x.endswith("()") for x in parts):
            return None
        val = r._eval(m, ref.scope, parts[:1], 0, {"value": False})[0]
        hits = trpc["paths"].get(".".join(parts[1:-1])) or []
        if val is not None:
            client = val[0] == "ext" and val[1].startswith("@trpc/") and not val[1].startswith(TRPC_SERVER)
            return (hits, RESOLVED) if client else None
        if not hits or parts[-1] not in TRPC_HOOKS or r.bind(m, ref.scope, parts[0]) is not None:
            return None
        s = ref.scope
        while True:
            if parts[0] in m.plain.get(s, ()):      # const store = { post: { create: { useMutation () {} } } }
                return None
            if not s:
                break
            s = r._up(m, s)
        return hits, INFERRED

    unresolved = 0
    db_calls: list[dict] = []
    for m in mods.values():
        for ref in m.refs:
            src_id = nid(m.name, ref.scope) if ref.scope and ref.scope in m.defs else nid(m.name)
            if ref.kind == "call" and m.name in trpc_users:
                # a request, as `fetch("/api/notes")` is one: the link is added beside whatever the call itself
                # resolves to below (a call into tRPC's library), and the inventory keeps that reading
                link = trpc_call(m, ref)
                if link is not None:
                    trpc["calls"] += 1
                    trpc["linked"] += bool(link[0])
                    for proc in link[0]:
                        g.add_edge(src_id, proc["tid"], kind=CALLS, confidence=link[1] if len(link[0]) == 1
                                   else POSSIBLE, line=ref.line, via="http-trpc", detail=proc["detail"])
            if ref.kind == "computed":   # inventory only, as are "registration" and "wrapper" below
                if ref.parts == ["<inline>"]:   # (function () {...})(): its body is read as part of this function
                    site(m, ref, src_id, [(src_id, RESOLVED, "inline-function")])
                else:
                    site(m, ref, src_id, reason="computed")
                continue
            inv = ref.kind in ("registration", "wrapper")
            if m.runes and ref.parts[0].removesuffix("()") in SVELTE_RUNES and ref.kind != "jsx":
                if ref.kind != "callback":     # `$state(0)`, `$derived.by(…)`: Svelte's compiler reads these
                    site(m, ref, src_id, [("builtin:" + ".".join(ref.parts), RESOLVED, "svelte-rune")])
                continue
            if ref.parts[0] in JS_GLOBALS and ref.kind != "jsx":
                if ref.kind != "callback":   # (the map never counted these; only the inventory says what they are)
                    doubt = r.global_doubt(m, ref.parts)
                    if doubt:
                        site(m, ref, src_id, reason=doubt)
                    else:
                        site(m, ref, src_id, [("builtin:" + ".".join(ref.parts), RESOLVED,
                                               "require" if ref.parts == ["require"] else "global")])
                continue
            hit = r.table_call(m, ref.scope, ref.db) if ref.db is not None and ref.kind == "call" else None
            if hit is not None:   # a call into a table: the link itself is made by the bridge, from meta["db_calls"]
                tid, table, conf, via = hit
                site(m, ref, src_id, [(tid, conf, via)])
                db_calls.append({"src": src_id, "table": table,
                                 "schema": None if ref.db["schema"] == "public" else ref.db["schema"], "op": ref.db["op"],
                                 "id": tid, "confidence": conf, "via": via, "file": m.rel, "line": ref.line,
                                 "ui": ref.ui})
                continue
            res = r.resolve_parts(m, ref.scope, ref.parts)
            more = r.resolve_more(m, ref.scope, ref.parts, args=ref.args or ()) \
                if res is None and ref.kind != "callback" else None
            if res is None and more is None and ref.kind == "call":
                lib = r.on_client(m, ref.scope, ref.parts, ref.args or ())
                if lib is not None:
                    more = ("ext", lib, "library-result" if any(x.endswith("()") for x in ref.parts)
                            else "library-value", INFERRED)
            if more is not None:
                kind, target, via, conf = more
                counted = not inv and ref.kind == "call" and not m.is_test
                if kind == "builtin":
                    site(m, ref, src_id, [(target, RESOLVED, via)])
                    if counted:   # it was counted unresolved before; now a built-in, still one call site
                        g.builtin_calls += 1
                    continue
                if kind == "ext":
                    site(m, ref, src_id, [(f"ext:{target}", conf, via)])
                    if not inv and ref.kind == "call" and not target.startswith("react"):
                        g.external(target)
                        g.add_edge(src_id, f"ext:{target}", kind=CALLS, confidence=conf, line=ref.line, via=via,
                                   detail=ref.ui)
                    continue
                res = ("def", target[0], target[1], via) if conf == INFERRED else ("def", target[0], target[1])
            if res is None:
                if ref.kind != "callback":
                    head = ref.parts[0]
                    if head in JS_BUILTINS and r.bind(m, ref.scope, head) is None and \
                            r.name_kind(m, ref.scope, head) is None and not r.global_doubt(m, ref.parts):
                        site(m, ref, src_id, [("builtin:" + ".".join(ref.parts), RESOLVED, "global")])
                    else:
                        site(m, ref, src_id, reason=r.why(m, ref.scope, ref.parts))
                if not inv and ref.kind == "call" and ref.parts[0] not in ("this",) and not m.is_test:
                    unresolved += 1
                    g.unresolved[".".join(ref.parts)[:120]] = g.unresolved.get(".".join(ref.parts)[:120], 0) + 1
                continue
            if res[0] == "ext":
                if ref.kind == "callback":
                    continue
                name = _ext_js(res[1])
                if r.unread(res[1]):   # an import of a file that is not in the repo
                    site(m, ref, src_id, reason="missing-module")
                else:
                    site(m, ref, src_id, [(f"ext:{name}", RESOLVED, "import")])
                if not inv and ref.kind == "call" and not res[1].startswith(("react.", "react")):
                    g.external(name)
                    g.add_edge(src_id, f"ext:{name}", kind=CALLS, confidence=RESOLVED, line=ref.line,
                               via="import", detail=ref.ui)
                continue
            tid = target_id(res)
            if tid is None or tid not in g.nodes:
                if ref.kind != "callback":
                    site(m, ref, src_id, reason="missing-member")
                continue
            if ref.kind == "callback":
                if g.nodes[tid].kind != CALLABLE:
                    continue
                conf, via = INFERRED, ("ui-event" if ref.ui and ref.ui.startswith("on") else "callback")
                site(m, ref, src_id, [(tid, conf, via)], group="handed")
            else:
                if ref.kind == "jsx":
                    conf, via = RESOLVED, "jsx-render"
                else:
                    conf = INFERRED if len(res) > 3 else RESOLVED
                    via = res[3] if len(res) > 3 else ("constructor" if ref.kind == "new" else
                                                       "require-call" if ref.parts[0].startswith("require:") else
                                                       more[2] if more is not None else "name")
                site(m, ref, src_id, [(tid, conf, via)])
            if inv or tid == src_id:
                continue
            g.add_edge(src_id, tid, kind=CALLS, confidence=conf, line=ref.line, via=via, detail=ref.ui)
        # calls the walker did not read (a gap in the reader): counted, so the inventory's total stays complete
        if m.unread:
            fns = sorted((d for d in m.defs.values() if d.kind != "class"), key=lambda d: d.end - d.start)
        for at, line, text, kind in m.unread:
            d = next((d for d in fns if d.start <= line <= d.end), None)
            src_id = nid(m.name, d.local) if d else nid(m.name)
            ref = JSRef(d.local if d else "", [], line, "unread", None, at, text)
            if kind == "inline":
                site(m, ref, src_id, [(src_id, RESOLVED, "inline-function")])
            elif kind == "require":
                site(m, ref, src_id, [("builtin:require", RESOLVED, "require")])
            else:
                site(m, ref, src_id, reason="not-read")

    # Routers mounted with x.use('/prefix', router): which router object a route is registered on, and the
    # prefix it is mounted under. A router mounted in two places with different prefixes keeps its written paths.
    def router_key(m: JSModule, scope: str, recv: list[str], depth: int = 0):
        if len(recv) != 1 or depth > 4:
            return None
        name, s = recv[0], scope
        while True:
            if name in m.params.get(s, ()):
                return (m.name, s, "param:" + name)
            if name in m.declared.get(s, ()):
                if name in m.required.get(s, ()) and name in m.imports:   # const notes = require('./routes/notes')
                    tmod, tname, _ = m.imports[name]
                    there = exported_router(tmod, depth + 1) if tmod and tname == "cjs" else None
                    if there is not None:
                        return there
                return (m.name, s, name)
            if not s:
                break
            s = JSResolver._up(m, s)
        if name in m.imports:
            tmod, tname, _ = m.imports[name]
            if tmod and tname in ("cjs", "default"):
                return exported_router(tmod, depth + 1)
        return None

    def exported_router(mod: str | None, depth: int = 0):
        mm = mods.get(mod) if mod else None
        if mm is None:
            return None
        v = mm.export_values.get("default")
        if v and len(v) == 1:
            return router_key(mm, "", v, depth)
        if mm.default and mm.default not in mm.defs:
            return router_key(mm, "", [mm.default], depth)
        return None

    def factory_key(m: JSModule, scope: str, chain: list[str]):
        """makeRouter(express.Router()) / require('./admin')(router): routes inside the function registered on its
        first parameter. require('./routes')(): a function whose every own `return` gives the same variable that
        is not a parameter (`return router`) hands back that router."""
        tgt = r.resolve_parts(m, scope, chain)
        if tgt is None or tgt[0] != "def":
            return None
        tm = mods[tgt[1]]
        ps = tm.params.get(tgt[2]) or []
        rets = tm.returns.get(tgt[2]) or set()
        if len(rets) == 1 and "" not in rets and not rets & set(ps):
            return router_key(tm, tgt[2], [next(iter(rets))])
        return (tgt[1], tgt[2], "param:" + ps[0]) if ps else None

    parents: dict[tuple, set] = {}
    for m in mods.values():
        if m.is_test:
            continue
        for mt in m.mounts:
            pk = router_key(m, mt["scope"], mt["recv"])
            if pk is None:
                continue
            for t in mt["targets"]:
                if t["kind"] == "module":
                    ck = exported_router(spec.resolve(t["spec"], m.path))
                elif t["kind"] == "call":
                    ck = factory_key(m, mt["scope"], t["chain"])
                else:
                    ck = router_key(m, mt["scope"], t["chain"])
                if ck is not None and ck != pk:
                    parents.setdefault(ck, set()).add((pk, mt["prefix"]))

    def full_prefix(key, seen=()):
        ps = parents.get(key)
        if not ps:
            return ""
        if len(ps) > 1 or key in seen or len(seen) > 8:
            return None
        (pk, pre), = ps
        up = full_prefix(pk, (*seen, key))
        return None if up is None else _join_path(up, pre)

    def handed(m: JSModule, scope: str, chain: list[str], at, src_id: str, via: str):
        """A function handed to the router (a route handler or middleware by name): its node, a handed record."""
        res, found = r.resolve_parts(m, scope, chain), RESOLVED
        if res is None:
            more = r.resolve_more(m, scope, chain)
            if more is not None and more[0] == "def":   # through a value or a type Lantern worked out: likely
                res, found = ("def", *more[1]), more[3]
            elif more is not None and more[0] == "ext":
                res = ("ext", more[1])
            elif more is None:
                # a library's value whose function may be the repo's own: the route's list of middleware keeps the
                # name the code wrote (the login check reads names), but no record calls it a library function
                loose = r.resolve_more(m, scope, chain, guard=False)
                if loose is not None and loose[0] == "ext":
                    return f"ext:{_ext_js(loose[1]) if '()' not in loose[1] else loose[1]}"
        ref = JSRef(scope, chain, at[0] if at else 0, "handed", None, at, ".".join(chain))
        if res is not None and res[0] == "ext":
            if r.unread(res[1]):
                # from a file of the project that is not there: the route's list keeps the name the code imports
                # (the login check reads names), but nothing calls it a library's function and no node is made
                site(m, ref, src_id, reason="missing-module", group="handed")
                return f"ext:{res[1]}"
            name = _ext_js(res[1]) if "()" not in res[1] else res[1]
            g.external(name)
            site(m, ref, src_id, [(f"ext:{name}", INFERRED, via)], group="handed")
            return f"ext:{name}"
        tid = target_id(res)
        if tid is None or tid not in g.nodes or g.nodes[tid].kind != CALLABLE:
            return None
        local = tid.split("::", 1)[1] if "::" in tid else ""
        wrapped = local in mods[res[1]].wrapped
        conf, v = (INFERRED, "wrapped-function") if wrapped and via == "route-handler" else (found, via)
        site(m, ref, src_id, [(tid, conf, v)], group="handed")
        if tid != src_id:
            g.add_edge(src_id, tid, kind=CALLS, confidence=conf, line=ref.line, via=v)
        return tid

    # Middleware put on with `use`. `app.use(mw)`, `app.use('/admin', mw)`, `router.use(mw)` and what stands before a
    # router in its mount (`app.use('/api', mw, router)`) run before every route written after them on that app or
    # router, and before the routes of a router mounted after them. Only a route's entry says so (`entry["use"]`,
    # outermost first, each with the place it was put on): no call site, no outcome and no edge is added for it.
    # Read only where the code shows the order: the same file and function as the route or the mount, an earlier line.
    route_keys = {k for mm in mods.values() if not mm.is_test
                  for k in ([router_key(mm, reg["scope"], reg.get("recv") or []) for reg in mm.route_regs]
                            + [router_key(mm, mt["scope"], mt["recv"]) for mt in mm.mounts]) if k}

    def makes_router(tm: JSModule, local: str) -> bool:
        """A function that registers routes, mounts something or makes a router: what it gives is a router."""
        def inside(s: str) -> bool:
            for _ in range(12):
                if s == local:
                    return True
                if not s:
                    return False
                s = JSResolver._up(tm, s)
            return False
        return any(inside(x["scope"]) for x in (*tm.route_regs, *tm.mounts)) or any(
            ref.parts and ref.parts[-1] == "Router" and inside(ref.scope) for ref in tm.refs)

    def use_named(m: JSModule, scope: str, t: dict):
        """What a `use` argument names: ("def", module, local) for a function of the repo, ("ext", name) for a
        library's, None when Lantern cannot tell."""
        if t["kind"] == "module":
            mm = mods.get(spec.resolve(t["spec"], m.path) or "")
            return ("def", mm.name, mm.default) if mm is not None and mm.default in mm.defs else None
        res = r.resolve_parts(m, scope, t["chain"])
        if res is None:
            more = r.resolve_more(m, scope, t["chain"], guard=False)
            res = ("def", *more[1]) if more and more[0] == "def" else \
                ("ext", more[1]) if more and more[0] == "ext" else None
        return res

    def passes_on(m: JSModule, scope: str, t: dict, star: bool) -> bool:
        """Whether what an `all` argument names hands the request on to what is written after it: a function of the
        repo with a third parameter that it calls (`next()`), written by name or made by a call (`requireRole('x')`,
        where the function inside is the one read). A library's function is taken to only where `all` is for every
        path (`app.all('*', helmet())`); on one path it may be the route itself (`app.all('/graphql', server)`)."""
        res = use_named(m, scope, t)
        if res is None:
            return False
        if res[0] != "def":
            return res[0] == "ext" and star and t["kind"] == "call"
        tm = mods[res[1]]

        def under(s: str, top: str) -> bool:
            for _ in range(12):
                if s == top:
                    return True
                if not s:
                    return False
                s = JSResolver._up(tm, s)
            return False
        for local in ([res[2]] if t["kind"] != "call" else [x for x in tm.defs if x != res[2] and under(x, res[2])]):
            ps = tm.params.get(local) or []
            if len(ps) == 3 and any(ref.kind == "call" and ref.parts == [ps[2]] and under(ref.scope, local)
                                    for ref in tm.refs):
                return True
        return False

    def use_id(m: JSModule, scope: str, t: dict) -> str | None:
        """The middleware a `use` argument names: a function of the repo, or a library's under the name the code
        calls. None for what is no middleware or cannot be told: a router or a function that makes one, an error
        handler (four parameters), a class, a value Lantern did not work out, a file that is not there, and
        Passport's reading of the session, which turns nobody away. A function written in place has no node: it is
        named `inline:<file>:<line it starts on>` when it takes the three things a middleware takes."""
        if t["kind"] == "inline":
            return f"inline:{m.rel}:{t['line']}" if t["params"] == 3 else None
        if SESSION_ONLY.search(t.get("text") or "") or OPTIONAL_LOGIN.search(t.get("text") or "") or (
                t["kind"] == "value" and len(t["chain"]) == 1 and t["chain"][0] in m.optional):
            return None
        res = use_named(m, scope, t)
        if res is None:
            return None
        if res[0] == "ext":
            name = _ext_js(res[1]) if "()" not in res[1] else res[1]
            own = name.replace("()", "").rsplit(".", 1)[-1].rsplit("/", 1)[-1]
            # a library's router is named for what it serves (`authRoutes`), which is not what it checks
            if r.unread(res[1]) or ROUTER_NAME.search(own) or ROUTER_NAME.search(t["chain"][-1].replace("()", "")):
                return None
            return f"ext:{name}"
        if res[0] != "def":
            return None
        tm, d = mods[res[1]], mods[res[1]].defs[res[2]]
        if d.kind == "class" or len(tm.params.get(res[2]) or ()) == 4 or makes_router(tm, res[2]):
            return None
        tid = target_id(res)
        return tid if tid in g.nodes and g.nodes[tid].kind == CALLABLE else None

    uses: dict[tuple, list[dict]] = {}      # router -> what `use` put on it: {mod, scope, line, prefix, mids}
    mounted: dict[tuple, list[dict]] = {}   # router -> its mounts: {pk, mod, scope, line, prefix, mids before it}
    for m in mods.values():
        if m.is_test:
            continue
        for mt in (*m.mounts, *m.alls):
            pk = router_key(m, mt["scope"], mt["recv"])
            if pk is None or mt.get("unread"):
                continue
            if "whole" in mt:   # x.all('*', mw): counts only when everything it was handed passes the request on
                ids = [use_id(m, mt["scope"], t) for t in mt["targets"]] if mt["whole"] else []
                if ids and all(ids) and all(passes_on(m, mt["scope"], t, mt["star"]) for t in mt["targets"]):
                    mt["took"] = True
                    uses.setdefault(pk, []).append({"mod": m.name, "scope": mt["scope"], "line": mt["line"],
                                                    "prefix": mt["prefix"],
                                                    "mids": [{"id": x, "file": m.rel, "line": mt["line"]}
                                                             for x in ids]})
                continue
            row = []
            for t in mt["targets"]:
                ck = (exported_router(spec.resolve(t["spec"], m.path)) if t["kind"] == "module" else
                      factory_key(m, mt["scope"], t["chain"]) if t["kind"] == "call" else
                      router_key(m, mt["scope"], t["chain"]))
                if ck is not None and ck != pk and ck in route_keys:
                    row.append((t, "router", ck))
                else:
                    row.append((t, "mid", use_id(m, mt["scope"], t)))
            if mt.get("lead") and (not row or row[0][0].get("text") != mt["lead"] or row[0][2] is None):
                continue   # `app.use(config.base, requireLogin)`: the first name may hold a path
            at = {"mod": m.name, "scope": mt["scope"], "line": mt["line"], "prefix": mt["prefix"]}
            mids: list[dict] = []
            for _t, kind, x in row:
                if kind == "router":
                    mounted.setdefault(x, []).append({**at, "pk": pk, "mids": list(mids)})
                elif x:
                    mids.append({"id": x, "file": m.rel, "line": mt["line"]})
            if mids:
                uses.setdefault(pk, []).append({**at, "mids": mids})

    def put_before(key, path: str, mod: str, scope: str, line: int, seen=()) -> list[dict]:
        """What `use` put in front of a route, or of a mount, written at `line` of `mod` on the router `key`, where
        its path is `path`: through the router's mounts first (only what stands before every one of them), then the
        router's own."""
        out: list[dict] = []
        ways = mounted.get(key) or []
        if ways and key not in seen and len(seen) < 8:
            lists = [put_before(w["pk"], _join_path(w["prefix"], path) if w["prefix"] else path, w["mod"],
                                w["scope"], w["line"], (*seen, key)) + w["mids"] for w in ways]
            out += [x for x in lists[0] if all(any(y["id"] == x["id"] for y in other) for other in lists[1:])]
        for u in sorted(uses.get(key, ()), key=lambda u: u["line"]):
            pre = u["prefix"].rstrip("/")
            if u["mod"] == mod and u["scope"] == scope and u["line"] < line and (
                    not pre or path == pre or path.startswith(pre + "/")):
                out += u["mids"]
        seen_ids: set[str] = set()
        return [x for x in out if not (x["id"] in seen_ids or seen_ids.add(x["id"]))]

    routers: set[tuple] = set()   # the receivers routes are registered on

    def is_router(m: JSModule, scope: str, recv: list[str]) -> bool:
        """`recv.get('/x', makeHandler())`: is `recv` an Express app or router (what express() or express.Router()
        returned, or something this file registers routes on)? Then the line is a route, not an outgoing call."""
        if len(recv) == 1 and router_key(m, scope, recv) in routers:
            return True
        val, _ = r._eval(m, scope, list(recv), 0, {"value": False})
        return val is not None and val[0] == "ext" and val[1] == "express"

    # SvelteKit: what each file with a fixed name is, gathered while the entries are set and joined after them
    kit: dict = {"routes": [], "pages": [], "loads": {}, "layouts": {}, "frames": {}, "actions": [], "handle": {},
                 "files": [], "shared": {}}

    def kit_route(tid: str | None, detail: str, role: str, base: Path) -> str | None:
        node = g.nodes.get(tid) if tid else None
        if node is None or node.kind != CALLABLE or node.entry:
            return None
        node.entry = {"kind": "route", "detail": detail, "sveltekit": role}
        kit["routes"].append((node, base))
        return node.id

    def kit_file(m: JSModule, base: Path, km) -> None:
        folder, kind = km.group("dir"), km.group("kind")
        path = kit_path(folder)
        own = lambda name: nid(m.name, m.exports[name]) if m.exports.get(name) in m.defs else None   # noqa: E731
        if m.svelte:
            node = g.nodes.get(nid(m.name, m.component)) if m.component else None
            if kind == "page" and node is not None and not node.entry:
                node.entry = {"kind": "page", "detail": path}
                kit["pages"].append((m, base, folder))
            elif kind == "layout" and node is not None:
                kit["frames"][(base, folder)] = node.id
        elif kind in ("page", "layout"):
            # `+page.ts`, `+layout.ts`: a `load` that runs on the server for the first view and in the browser after
            # it. Nobody can ask for it from outside, so it is no route: a function its page calls
            if own("load") in g.nodes:
                kit["shared"][(base, folder, kind)] = own("load")
        elif kind == "server":
            for verb in (*KIT_VERBS, "fallback"):     # `fallback` answers every verb that has no function of its own
                kit_route(own(verb), f"{'ANY' if verb == 'fallback' else verb} {path}", "endpoint", base)
        elif kind == "layout.server":
            tid = kit_route(own("load"), f"GET {path.rstrip('/')}/*", "layout load", base)
            if tid:
                kit["layouts"][(base, folder)] = tid
        elif kind == "page.server":
            tid = kit_route(own("load"), f"GET {path}", "load", base)
            if tid:
                kit["loads"][(base, folder)] = tid
            for a in m.kit_actions if "actions" in m.exports else ():
                tid = nid(m.name, a["local"]) if "local" in a else \
                    handed(m, "", a["handler"], a["at"], nid(m.name), "route-handler")
                tid = kit_route(tid, f"POST {path}" + ("" if a["key"] == "default" else f"?/{a['key']}"), "action", base)
                if tid is None:
                    continue
                kit["actions"].append({"base": base, "folder": folder, "path": path, "key": a["key"], "tid": tid})
                hit = r.resolve_parts(m, "", a["wrap"]) if a.get("wrap") else None
                mid = target_id(hit) if hit and hit[0] == "def" else \
                    f"ext:{_ext_js(hit[1])}" if hit and hit[0] == "ext" and not r.unread(hit[1]) else None
                if mid:     # save: guarded(async (event) => …): the helper around it runs first
                    if mid.startswith("ext:"):
                        g.external(mid[4:])
                    g.nodes[tid].entry["middleware"] = [mid]

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
        if pkg["deps"] & SERVER_ACTIONS:
            # Server Actions: the framework gives each one an address of its own, which any visitor can send a request
            # to, whatever page shows the form. So each is a route, named by the function (it has no path to show).
            acts = {local: d.name for local, d in m.defs.items() if d.server}
            if "use server" in m.directives:
                for local in [*m.exports.values(), m.default]:
                    d = m.defs.get(local) if isinstance(local, str) else None
                    if d is not None and d.kind == "function" and not d.in_class:
                        acts.setdefault(local, d.name)
            for local, name in acts.items():
                node = g.nodes.get(nid(m.name, local))
                if node is not None and not node.entry:
                    node.entry = {"kind": "route", "detail": f"ACTION {name}"}
        if KIT in pkg["deps"]:
            km = KIT_FILE.match(rel_pkg)
            if km is not None:
                kit_file(m, pkg["dir"], km)
            elif KIT_HOOKS.match(rel_pkg) and "handle" in m.exports:
                # the function every request passes (or the functions, in the order `sequence(a, b)` names them):
                # marked, as tRPC's handler is, so that the rules which ask routes ask the routes behind it
                hooks = [nid(m.name, m.exports["handle"])] if m.exports["handle"] in m.defs else \
                    [handed(m, "", chain, at, nid(m.name), "route-handler") for chain, at in m.kit_handles]
                for tid in hooks:
                    tid = kit_route(tid, "ANY /*", "handle", pkg["dir"])
                    if tid:
                        g.nodes[tid].entry["serves"] = "sveltekit"
                        kit["handle"].setdefault(pkg["dir"], []).append(tid)
            if m.svelte:
                kit["files"].append((m, pkg["dir"], km))
        for reg in m.page_regs:
            res = r.resolve_parts(m, "", reg["component"])
            tid = target_id(res)
            if tid and tid in g.nodes and not g.nodes[tid].entry:
                g.nodes[tid].entry = {"kind": "page", "detail": _clean_page_path(reg["path"])}
        for reg in m.route_regs:
            src_id = nid(m.name, reg["scope"]) if reg["scope"] and reg["scope"] in m.defs else nid(m.name)
            mw = []
            for x in reg.get("mw", ()):
                if x["called"] and OPTIONAL_LOGIN.search(x.get("text") or ""):
                    continue   # expressjwt({ ..., credentialsRequired: false }): it turns nobody away
                if x["called"]:   # auth(), passport.authenticate('jwt'): the call is a call site of its own
                    hit = r.resolve_parts(m, reg["scope"], x["chain"])
                    if hit is None:   # only the name, for the route's list of middleware: no guard
                        more = r.resolve_more(m, reg["scope"], x["chain"], guard=False)
                        hit = ("def", *more[1]) if more and more[0] == "def" else \
                            ("ext", more[1]) if more and more[0] == "ext" else None
                    if hit and hit[0] == "ext" and r.unread(hit[1]):   # a file that is not there: the name only
                        mid = f"ext:{hit[1]}"
                    elif hit and hit[0] == "ext":
                        mid = f"ext:{_ext_js(hit[1]) if '()' not in hit[1] else hit[1]}"
                        g.external(mid[4:])
                    else:
                        mid = target_id(hit)
                    if mid and (mid in g.nodes or mid.startswith("ext:")):
                        mw.append(mid)
                else:
                    mid = handed(m, reg["scope"], x["chain"], x["at"], src_id, "middleware")
                    if mid and not (len(x["chain"]) == 1 and x["chain"][0] in m.optional):
                        mw.append(mid)
            passes = bool((reg.get("all") or {}).get("took"))   # x.all('/admin/*', requireLogin): no route of its own
            if "local" in reg:
                tid = nid(m.name, reg["local"])
            else:
                tid = handed(m, reg["scope"], reg["handler"] or [], reg.get("at"), src_id,
                             "middleware" if passes else "route-handler") if reg["handler"] else None
            if passes:
                tid = None
            key = router_key(m, reg["scope"], reg.get("recv") or [])
            if key:
                routers.add(key)
            pre = full_prefix(key) if key else ""
            path = _join_path(pre, reg["path"]) if pre else reg["path"]
            if tid and tid in g.nodes and not tid.startswith("ext:"):   # a library's function is never the app's entry
                g.nodes[tid].entry = {"kind": "route", "detail": f"{reg['method']} {path}"}
                if mw:
                    g.nodes[tid].entry["middleware"] = mw
                wide = put_before(key, reg["path"], m.name, reg["scope"], reg["line"]) if key else []
                if wide:
                    g.nodes[tid].entry["use"] = wide
        if m.html:   # a page: what the visitor's browser runs, so its script starts in the Browser lane
            g.nodes[nid(m.name)].entry = {"kind": "page", "detail": m.rel}
        elif m.mounts_app:
            g.nodes[nid(m.name)].entry = {"kind": "main", "detail": f"app start ({m.rel})"}
        elif m.listens and m.route_regs:
            g.nodes[nid(m.name)].entry = {"kind": "main", "detail": f"server start ({m.rel})"}

    if trpc is not None:
        # tRPC procedures: each is a route of its own, named by where it is served and its path through the routers
        used: dict = {}

        def use_node(tm: JSModule, ts: str, u: dict) -> str | None:
            """The function a `.use()` step runs before a procedure: its node, or a library's name."""
            key = (tm.name, ts, u.get("local") or tuple(u["chain"]), u.get("at"))
            if key in used:
                return used[key]
            if "local" in u:
                mid = nid(tm.name, u["local"])
            elif u.get("called"):     # .use(limit({ max: 5 })): the call is a call site of its own; the name only
                hit = r.resolve_parts(tm, ts, u["chain"])
                if hit is None:
                    more = r.resolve_more(tm, ts, u["chain"], guard=False)
                    hit = ("def", *more[1]) if more and more[0] == "def" else \
                        ("ext", more[1]) if more and more[0] == "ext" else None
                if hit and hit[0] == "ext":
                    mid = None if r.unread(hit[1]) else f"ext:{_ext_js(hit[1]) if '()' not in hit[1] else hit[1]}"
                    if mid:
                        g.external(mid[4:])
                else:
                    mid = target_id(hit) if hit and hit[0] == "def" else None
            else:
                mid = handed(tm, ts, u["chain"], u.get("at"), nid(tm.name, ts) if ts and ts in tm.defs
                             else nid(tm.name), "middleware")
            used[key] = mid if mid and (mid in g.nodes or mid.startswith("ext:")) else None
            return used[key]

        made = 0
        for proc in trpc["procs"]:
            m, it, node = proc["m"], proc["item"], g.nodes[proc["tid"]]
            if node.entry:      # a function that is already a route of another kind stays that
                continue
            if "handler" in it:
                handed(m, proc["scope"], it["handler"], it.get("at"),
                       nid(m.name, proc["scope"]) if proc["scope"] and proc["scope"] in m.defs else nid(m.name),
                       "route-handler")
            mw: list[str] = []
            for tm, ts, u in [*proc["uses"], *((m, proc["scope"], u) for u in it["uses"])]:
                mid = use_node(tm, ts, u)
                if mid and mid not in mw:
                    mw.append(mid)
            node.entry = {"kind": "route", "detail": proc["detail"],
                          "trpc": {"path": proc["path"], "type": it["type"], "procedures": proc["names"],
                                   "mount": proc["mount"]}}
            if mw:
                node.entry["middleware"] = mw
            made += 1
        for m in mods.values():
            for mt in m.trpc_mounts if made else ():
                # the handler every procedure stands behind (`app/api/trpc/[trpc]/route.ts`) is their door, not a
                # route that changes data by itself: the rules that ask routes ask the procedures (`serves`)
                node = g.nodes.get(nid(m.name, mt["scope"])) if mt["scope"] in m.defs else None
                if node is not None and (node.entry or {}).get("kind") == "route":
                    node.entry["serves"] = "trpc"
        if made or trpc["calls"]:
            g.meta["trpc"] = {"procedures": made, "routers": trpc["routers"], "client_calls": trpc["calls"],
                              "linked": trpc["linked"]}

    if kit["routes"] or kit["pages"]:
        def kit_link(src: str, tid: str, line: int, conf: str = RESOLVED) -> None:
            g.add_edge(src, tid, kind=CALLS, confidence=conf, line=line, via="http-sveltekit",
                       detail=g.nodes[tid].entry["detail"])

        def kit_calls(src: str, tid: str | None, via: str) -> None:
            if tid:
                g.add_edge(src, tid, kind=CALLS, confidence=RESOLVED, line=1, via=via)

        for node, base in kit["routes"]:
            hooks = kit["handle"].get(base)
            if hooks and node.entry.get("sveltekit") != "handle":   # hooks.server runs before every route of the app
                node.entry["middleware"] = [*hooks, *(node.entry.get("middleware") or ())]
        for m, base, folder in kit["pages"]:
            # the framework's own wiring: a page gets its data from the `load` beside it and from the layouts
            # above it, and is drawn inside those layouts
            src = nid(m.name, m.component)
            if (base, folder) in kit["loads"]:
                kit_link(src, kit["loads"][(base, folder)], 1)
            kit_calls(src, kit["shared"].get((base, folder, "page")), "sveltekit-load")
            parts = [x for x in folder.split("/") if x]
            for i in range(len(parts), -1, -1):
                above = "".join(x + "/" for x in parts[:i])
                if (base, above) in kit["layouts"]:
                    kit_link(src, kit["layouts"][(base, above)], 1)
                kit_calls(src, kit["shared"].get((base, above, "layout")), "sveltekit-load")
                kit_calls(src, kit["frames"].get((base, above)), "sveltekit-layout")
        posted = linked = 0
        for m, base, km in kit["files"]:
            # a form with method="POST" posts to an action: of the page it stands on (`?/name`, or `default` when
            # none is named), or of the page whose address it writes (`/login?/register`)
            src = nid(m.name, m.component)
            for form in m.forms:
                posted += 1
                if form["action"] is None:
                    continue
                at, named, key = form["action"].partition("?/")
                at, key = at.split("?")[0].strip(), key.split("&")[0].strip() if named else "default"
                hits = []
                if not at and km is not None and km.group("kind") == "page":
                    hits = [a for a in kit["actions"] if (a["base"], a["folder"], a["key"]) == (base, km.group("dir"), key)]
                elif at.startswith("/"):
                    hits = [a for a in kit["actions"] if a["base"] == base and a["key"] == key and kit_same(a["path"], at)]
                    # the page with that very address, before one with a part that changes (`/inbox/new`, `[id]`)
                    hits = [a for a in hits if a["path"].rstrip("/") == at.rstrip("/")] or hits
                    if not hits and not named:   # no page's action: a `+server.ts`, matched like any request
                        call = _normalize_http(at, "POST", m.component, form["line"], "onSubmit")
                        if call is not None:
                            m.http.append(call)
                for a in hits:
                    kit_link(src, a["tid"], form["line"], RESOLVED if len(hits) == 1 else POSSIBLE)
                linked += bool(hits)
        g.meta["sveltekit"] = {"routes": sum(1 for n, _ in kit["routes"] if n.entry.get("sveltekit") != "handle"),
                               "pages": len(kit["pages"]), "forms": posted, "linked": linked}

    http_calls = []
    for m in mods.values():
        for h in m.http:
            if h.recv and is_router(m, h.scope, h.recv):   # router.post('/login', passport.authenticate(...)): a route
                continue
            src_id = nid(m.name, h.scope) if h.scope and h.scope in m.defs else nid(m.name)
            http_calls.append({"src": src_id, "method": h.method, "path": h.path, "raw": h.raw,
                               "prefix_unknown": h.prefix_unknown, "host": h.host, "line": h.line,
                               "ui": h.ui, "file": m.rel})
    g.meta.setdefault("http_calls", []).extend(http_calls)
    if db_calls:
        g.meta.setdefault("db_calls", []).extend(db_calls)
    said = {m.rel: sorted(m.directives) for m in mods.values() if m.directives}
    if said:
        g.meta.setdefault("js_directives", {}).update(said)
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
