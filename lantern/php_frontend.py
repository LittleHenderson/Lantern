"""PHP: Laravel, Symfony, Slim, WordPress and plain PHP pages, mapped like the C# reader maps C#.

Node ids: class `php:<Namespace.Path>.<Class>` (namespace separators become dots), method
`php:<Namespace.Path>.<Class>.<method>`, function `php:<Namespace.Path>.<fn>` (global: `php:<fn>`), file module
`php:<path>.php`. An inline route closure is its own node `php:<path>.php::GET /notes/{id}`.

Calls are resolved by:
  * `name`          `helper()` → a repo function (the file's namespace first, then the global one)
  * `this`          `$this->find()`, `self::find()`, `static::find()`, `parent::find()` → own class, parents, traits
  * `assoc`         `Note::find()` on a repo class (an unknown class: `ext:Note.find`, so Laravel facades such as
                    `DB::select` are library calls)
  * `receiver-type` `$this->repo->find()` / `$repo->find()` where the type is written (`private NoteRepo $repo`,
                    promoted constructor parameters, typed parameters) or comes from `new NoteRepo()` / a repo
                    method's written return type
  * `interface`     the receiver's type is an interface or abstract class in the repo: one `possible` edge per class
                    that implements or extends it
  * `constructor`   `new NoteRepo()` → `NoteRepo.__construct`
  * `callback`      `[NoteController::class, 'show']`, `'NoteController@show'`, `[$this, 'save']`, `'my_function'`
                    handed to `add_action`/`array_map`/…
  * `include`       `require 'db.php'` → that file's module (its top-level code runs)
Library functions become `ext:<function>` (`ext:mysqli_query`); an unknown receiver is counted in `graph.unresolved`.
Closures belong to the function they are written in.

Entries:
  * Laravel `Route::get('/p', [C::class, 'm'])` (also `'C@m'`, invokable `C::class`, closures), `Route::resource`,
    `prefix(...)->group(...)` / `Route::group(['prefix' => ...])`; `routes/api.php` adds `/api`. A route registered
    inside an `auth` middleware gets a `middleware` edge to `ext:middleware.auth`, so the login check sees it.
  * Slim / Lumen / generic routers: `$app->get('/p', handler)`, `$app->group('/api', function ($g) { … })`.
  * Symfony `#[Route('/p', methods: ['GET'])]` (and `@Route` docblocks), with the class's prefix.
  * WordPress: `add_action('wp_ajax_nopriv_x', …)` (anyone can call it), `wp_ajax_x` (signed-in users),
    `register_rest_route('ns/v1', '/r', ['methods' => 'GET', 'callback' => …])` → `GET /wp-json/ns/v1/r`.
  * Plain PHP: a file a browser opens directly (top-level code outside views, config, routes, vendor) → `route`
    `ANY /login.php`, so what `$_POST` brings in counts as outside input.
  * PHPUnit tests (`tests/`, `test…` methods, `#[Test]`); Laravel console commands' `handle` (`main`).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .graph import CALLABLE, CALLS, CLASS, CONTAINS, INFERRED, MODULE, POSSIBLE, RESOLVED, Graph, Node
from .python_frontend import SKIP_DIRS, inside_repo, project_bytes, project_text

MAX_BYTES = 1_500_000
SKIP = re.compile(r"(^|/)(vendor|storage|cache|node_modules|wp-admin|wp-includes)/|\.blade\.php$|\.min\.php$", re.I)
TEST_FILE_RE = re.compile(r"(^|/)tests?/|Test\.php$", re.I)
NOT_PAGES = re.compile(r"(^|/)(views?|templates?|resources|config|routes|database|migrations|bootstrap|lang|"
                       r"partials|includes?|inc|lib|src|app|classes|tests?)/", re.I)
VERBS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "any": "ANY",
         "options": "OPTIONS", "map": "ANY", "match": "ANY"}
RESOURCE = [("index", "GET", ""), ("create", "GET", "/create"), ("store", "POST", ""), ("show", "GET", "/{}"),
            ("edit", "GET", "/{}/edit"), ("update", "PUT", "/{}"), ("destroy", "DELETE", "/{}")]
AUTH_MW = re.compile(r"\b(auth|sanctum|passport|jwt|can|verified|role|permission|admin)\b", re.I)
HTTP_FN = re.compile(r"^(get|post|put|patch|delete|head)$", re.I)
CALLBACK_FUNS = {"add_action", "add_filter", "add_shortcode", "array_map", "array_filter", "array_walk", "usort",
                 "uasort", "uksort", "call_user_func", "call_user_func_array", "register_shutdown_function",
                 "set_error_handler", "set_exception_handler", "spl_autoload_register", "register_activation_hook"}
PAGE_SKIP_STMTS = {"namespace_definition", "namespace_use_declaration", "class_declaration", "interface_declaration",
                   "trait_declaration", "enum_declaration", "function_definition", "php_tag", "text_interpolation",
                   "declare_statement", "comment", "const_declaration", "empty_statement"}


def _parser():
    import tree_sitter as ts
    import tree_sitter_php as tp
    return ts.Parser(ts.Language(tp.language_php()))


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _kid(n, *types):
    return next((c for c in n.children if c.type in types), None) if n is not None else None


def _kids(n, *types):
    return [c for c in n.children if c.type in types] if n is not None else []


def _dots(name: str) -> str:
    return name.strip("\\").replace("\\", ".")


def _string(n) -> str | None:
    """The text of a plain string literal (no interpolation), else None."""
    if n is None:
        return None
    if n.type == "string":
        return _t(n)[1:-1]
    if n.type == "encapsed_string":
        if any(c.type not in ('"', "string_content", "escape_sequence", "string_value") for c in n.children):
            return None
        return _t(n)[1:-1]
    return None


def _type_name(n) -> str | None:
    if n is None:
        return None
    if n.type in ("named_type", "optional_type"):
        inner = _kid(n, "name", "qualified_name", "named_type")
        return _type_name(inner) if inner is not None else None
    if n.type in ("name", "qualified_name"):
        t = _t(n)
        return None if t.lower() in ("array", "string", "int", "float", "bool", "mixed", "void", "callable",
                                     "iterable", "object", "null", "self", "static") else t
    if n.type == "union_type":
        for c in n.children:
            r = _type_name(c)
            if r:
                return r
    return None


@dataclass
class PFun:
    name: str
    cls: str | None        # dotted class id without the prefix, or None for a function
    file: str
    start: int
    end: int
    signature: str
    fingerprint: str
    params: dict[str, str] = field(default_factory=dict)
    returns: str | None = None
    static: bool = False
    node: object = None
    attrs: str = ""        # attribute / docblock text above it


@dataclass
class PClass:
    id: str                # dotted: App.Models.Note
    short: str
    ns: str
    file: str
    start: int
    end: int
    kind: str              # class | interface | trait | abstract | enum
    supers: list[str] = field(default_factory=list)        # resolved dotted ids or written names
    props: dict[str, str] = field(default_factory=dict)
    funs: set[str] = field(default_factory=set)
    attrs: str = ""
    uses: dict[str, str] = field(default_factory=dict)     # the file's `use` aliases


@dataclass
class PFile:
    rel: str
    lines: int
    ns: str = ""
    uses: dict[str, str] = field(default_factory=dict)      # alias → dotted name
    is_test: bool = False
    top: list = field(default_factory=list)                 # top-level statements that run
    page: bool = False


class Model:
    def __init__(self):
        self.classes: dict[str, PClass] = {}
        self.by_short: dict[str, list[str]] = {}
        self.funs: dict[str, PFun] = {}       # node id → fun
        self.fun_by_name: dict[str, list[str]] = {}
        self.unresolved: dict[str, int] = {}

    def resolve_class(self, name: str, ns: str, uses: dict[str, str]) -> str | None:
        """A class name as written → a repo class id, or None."""
        if not name:
            return None
        if name.startswith("\\"):
            d = _dots(name)
            return d if d in self.classes else self._by_short(d.split(".")[-1])
        head, _, rest = name.partition("\\")
        if head in uses:
            d = uses[head] + ("." + _dots(rest) if rest else "")
            if d in self.classes:
                return d
        d = (ns + "." if ns else "") + _dots(name)
        if d in self.classes:
            return d
        if _dots(name) in self.classes:
            return _dots(name)
        return self._by_short(_dots(name).split(".")[-1])

    def _by_short(self, short: str) -> str | None:
        hits = self.by_short.get(short, [])
        return hits[0] if len(hits) == 1 else None

    def fun_in(self, cid: str, name: str, depth: int = 0) -> str | None:
        """Method `name` on class `cid`, its parents or its traits (PHP method names ignore case)."""
        c = self.classes.get(cid)
        if c is None or depth > 8:
            return None
        low = name.lower()
        for f in c.funs:
            if f.lower() == low:
                return f"php:{cid}.{f}"
        for s in c.supers:
            if s in self.classes:
                r = self.fun_in(s, name, depth + 1)
                if r:
                    return r
        return None

    def implementers(self, cid: str) -> list[str]:
        """Concrete classes under `cid` (through subclasses). The children index is built once per model, after
        resolve_supers: a scan of every class per call cost seconds on repositories with thousands of classes."""
        children = getattr(self, "_children", None)
        if children is None:
            children = {}
            for k in self.classes.values():
                for s in k.supers:
                    children.setdefault(s, []).append(k.id)
            self._children = children
        out, seen, todo = [], {cid}, [cid]
        while todo:
            cur = todo.pop()
            for kid in children.get(cur, ()):
                if kid not in seen:
                    seen.add(kid)
                    todo.append(kid)
                    if self.classes[kid].kind not in ("interface", "trait"):
                        out.append(kid)
        return out


def discover(repo: Path) -> list[Path]:
    out = []
    for p in repo.rglob("*.php"):
        rel = p.relative_to(repo)
        if any(x in SKIP_DIRS for x in rel.parts[:-1]) or SKIP.search(rel.as_posix()) or not p.is_file() \
                or not inside_repo(p, repo):
            continue
        out.append(p)
    return sorted(out)


def _params(plist) -> dict[str, str]:
    out = {}
    for prm in _kids(plist, "simple_parameter", "property_promotion_parameter", "variadic_parameter"):
        name = prm.child_by_field_name("name")
        if name is not None:
            out[_t(name).lstrip("$")] = _type_name(prm.child_by_field_name("type")) or ""
    return out


def _above(src_lines: list[str], line: int) -> str:
    """Attribute and docblock lines right above a declaration (1-based line)."""
    out = []
    i = line - 2
    while i >= 0 and len(out) < 30:
        s = src_lines[i].strip()
        if s.startswith(("#[", "*", "/**", "*/", "//", "@")) or (out and s.endswith(("]", ")", ","))):
            out.append(s)
            i -= 1
            continue
        break
    return "\n".join(reversed(out))


def _attr_text(c) -> str:
    """`#[Route(...)]` attributes written as part of a declaration."""
    return "\n".join(_t(a) for a in c.children if a.type == "attribute_list")


def _collect(model: Model, f: PFile, root, src_lines: list[str]) -> None:
    def ns_of(n) -> str:
        nm = n.child_by_field_name("name")
        return _dots(_t(nm)) if nm is not None else ""

    def walk(nodes, ns: str):
        for c in nodes:
            if c.type == "namespace_definition":
                body = c.child_by_field_name("body")
                if body is not None:
                    f.ns = ns_of(c)
                    walk(body.children, ns_of(c))
                else:                                       # `namespace App\Models;` holds for the rest of the file
                    ns = ns_of(c)
                    f.ns = ns
            elif c.type == "namespace_use_declaration":
                for clause in _kids(c, "namespace_use_clause"):
                    q = _kid(clause, "qualified_name", "name")
                    alias = clause.child_by_field_name("alias") or (
                        _kids(clause, "name")[-1] if len(_kids(clause, "name")) > 1 else None)
                    full = _dots(_t(q)) if q is not None else ""
                    if full:
                        f.uses[_t(alias) if alias is not None and alias is not q else full.split(".")[-1]] = full
                grp = _kid(c, "namespace_use_group")
                prefix = _kid(c, "namespace_name")
                if grp is not None and prefix is not None:
                    for clause in _kids(grp, "namespace_use_group_clause", "namespace_use_clause"):
                        q = _kid(clause, "namespace_name", "qualified_name", "name")
                        if q is not None:
                            full = _dots(_t(prefix)) + "." + _dots(_t(q))
                            f.uses[full.split(".")[-1]] = full
            elif c.type in ("class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"):
                _class(c, ns)
            elif c.type == "function_definition":
                nm = c.child_by_field_name("name")
                if nm is not None:
                    _fun(c, ns, None, (ns + "." if ns else "") + _t(nm))
            elif c.type not in PAGE_SKIP_STMTS:
                f.top.append(c)

    def _class(c, ns):
        nm = c.child_by_field_name("name")
        if nm is None:
            return
        cid = (ns + "." if ns else "") + _t(nm)
        mods = {_t(m) for m in c.children if m.type in ("abstract_modifier", "final_modifier", "readonly_modifier")}
        kind = {"interface_declaration": "interface", "trait_declaration": "trait", "enum_declaration": "enum"}.get(
            c.type, "class")
        if kind == "class" and "abstract" in mods:
            kind = "abstract"
        k = PClass(id=cid, short=_t(nm), ns=ns, file=f.rel, start=c.start_point.row + 1, end=c.end_point.row + 1,
                   kind=kind, attrs=_above(src_lines, c.start_point.row + 1) + "\n" + _attr_text(c), uses=f.uses)
        for clause in _kids(c, "base_clause", "class_interface_clause"):
            k.supers += [_t(x) for x in clause.children if x.type in ("name", "qualified_name")]
        model.classes[cid] = k
        model.by_short.setdefault(k.short, []).append(cid)
        body = c.child_by_field_name("body") or _kid(c, "declaration_list", "enum_declaration_list")
        for d in (body.children if body is not None else []):
            if d.type == "use_declaration":                    # traits
                k.supers += [_t(x) for x in d.children if x.type in ("name", "qualified_name")]
            elif d.type == "property_declaration":
                tn = _type_name(d.child_by_field_name("type") or _kid(d, "named_type", "optional_type", "union_type"))
                for el in _kids(d, "property_element"):
                    v = _kid(el, "variable_name")
                    init = _kid(el, "property_initializer")
                    t = tn
                    if t is None and init is not None:
                        oc = _kid(init, "object_creation_expression")
                        t = _t(_kid(oc, "name", "qualified_name")) if oc is not None else None
                    if v is not None and t:
                        k.props[_t(v).lstrip("$")] = t
            elif d.type == "method_declaration":
                mn = d.child_by_field_name("name")
                if mn is None:
                    continue
                _fun(d, ns, k, f"{cid}.{_t(mn)}")
                k.funs.add(_t(mn))
                if _t(mn) == "__construct":
                    for pn, pt in _params(d.child_by_field_name("parameters")).items():
                        if pt and any(p.type == "property_promotion_parameter"
                                      for p in d.child_by_field_name("parameters").children):
                            k.props.setdefault(pn, pt)
                    body2 = d.child_by_field_name("body")
                    params = _params(d.child_by_field_name("parameters"))
                    for a in _assignments(body2):              # $this->repo = $repo / new Repo()
                        left, right = a.child_by_field_name("left"), a.child_by_field_name("right")
                        if left is None or right is None or left.type != "member_access_expression" \
                                or _t(left.child_by_field_name("object")) != "$this":
                            continue
                        prop = _t(left.child_by_field_name("name"))
                        if right.type == "object_creation_expression":
                            t = _t(_kid(right, "name", "qualified_name"))
                        elif right.type == "variable_name":
                            t = params.get(_t(right).lstrip("$"))
                        else:
                            t = None
                        if t:
                            k.props.setdefault(prop, t)

    def _fun(c, ns, cls: PClass | None, dotted: str):
        name = _t(c.child_by_field_name("name"))
        body = c.child_by_field_name("body")
        sig_end = body.start_byte if body is not None else c.end_byte
        sig = re.sub(r"\s+", " ", c.text[: sig_end - c.start_byte].decode("utf-8", "replace")).strip()
        sig = re.sub(r"^(#\[[^\]]*\]\s*)+", "", sig)
        mid = f"php:{dotted}"
        if mid in model.funs:
            return
        model.funs[mid] = PFun(name=name, cls=cls.id if cls else None, file=f.rel, start=c.start_point.row + 1,
                               end=c.end_point.row + 1, signature=sig[:200],
                               fingerprint=hashlib.sha1(c.text, usedforsecurity=False).hexdigest()[:12],
                               params=_params(c.child_by_field_name("parameters")),
                               returns=_type_name(c.child_by_field_name("return_type")),
                               static=any(m.type == "static_modifier" for m in c.children), node=c,
                               attrs=_above(src_lines, c.start_point.row + 1) + "\n" + _attr_text(c))
        model.fun_by_name.setdefault(name.lower(), []).append(mid)

    walk(root.children, "")


def _assignments(n):
    out, stack = [], [n] if n is not None else []
    while stack:
        x = stack.pop()
        if x.type == "assignment_expression":
            out.append(x)
        if x.type in ("anonymous_function", "arrow_function", "class_declaration"):
            continue
        stack.extend(x.children)
    return out


@dataclass
class Ref:
    target: str
    line: int
    confidence: str
    via: str


class Linker:
    def __init__(self, model: Model, repo: Path):
        self.m = model
        self.repo = repo
        self.http: list[dict] = []
        self._supers_cache: dict[str, list[str]] = {}

    # ---- types ----
    def _cls(self, name: str | None, f: PFile) -> str | None:
        return self.m.resolve_class(name, f.ns, f.uses) if name else None

    def _type_of(self, f, cls: PClass | None, env, e) -> str | None:
        """A repo class id for an expression, when it can be told."""
        if e is None:
            return None
        if e.type == "variable_name":
            v = _t(e).lstrip("$")
            if v == "this" and cls is not None:
                return cls.id
            return self._cls(env.get(v), f)
        if e.type == "object_creation_expression":
            return self._cls(_t(_kid(e, "name", "qualified_name")), f)
        if e.type in ("member_access_expression", "nullsafe_member_access_expression"):
            owner = self._type_of(f, cls, env, e.child_by_field_name("object"))
            c = self.m.classes.get(owner or "")
            prop = _t(e.child_by_field_name("name"))
            seen: set[str] = set()
            while c is not None and c.id not in seen and len(seen) < 16:   # parents in a circle (Laravel has a few) end here
                seen.add(c.id)
                if prop in c.props:
                    return self.m.resolve_class(c.props[prop], c.ns, c.uses)
                c = next((self.m.classes[s] for s in self._supers(c) if s in self.m.classes), None)
            return None
        if e.type == "parenthesized_expression":
            return self._type_of(f, cls, env, next((x for x in e.children if x.is_named), None))
        if e.type in ("member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression",
                      "function_call_expression"):
            t = self._target(f, cls, env, e)
            fn = self.m.funs.get(t[0]) if t and t[0] else None
            if fn and fn.returns:
                owner = self.m.classes.get(fn.cls or "")
                if fn.returns.lower() in ("self", "static") and owner:
                    return owner.id
                return self.m.resolve_class(fn.returns, owner.ns if owner else f.ns, owner.uses if owner else f.uses)
        return None

    def _supers(self, c: PClass) -> list[str]:
        """Resolved parent ids of a class, remembered: the same lookups ran millions of times on the Laravel framework."""
        hit = self._supers_cache.get(c.id)
        if hit is not None:
            return hit
        out = []
        for s in c.supers:
            r = s if s in self.m.classes else self.m.resolve_class(s, c.ns, c.uses)
            if r:
                out.append(r)
        self._supers_cache[c.id] = out
        return out

    def resolve_supers(self):
        for c in self.m.classes.values():
            c.supers = [s if s in self.m.classes else (self.m.resolve_class(s, c.ns, c.uses) or s.split("\\")[-1])
                        for s in c.supers]

    # ---- calls ----
    def _target(self, f, cls: PClass | None, env, x) -> tuple[str | None, str, str, list[str]] | None:
        """(target id, via, confidence, extra possible targets) for a call node."""
        if x.type == "function_call_expression":
            fn = x.child_by_field_name("function")
            if fn is None or fn.type not in ("name", "qualified_name"):
                return None
            name = _t(fn)
            d = _dots(name)
            for cand in ((f.ns + "." + d) if f.ns and not name.startswith("\\") else None, d):
                if cand and f"php:{cand}" in self.m.funs:
                    return (f"php:{cand}", "name", RESOLVED, [])
            hits = self.m.fun_by_name.get(d.split(".")[-1].lower(), [])
            hits = [h for h in hits if self.m.funs[h].cls is None]
            if len(hits) == 1:
                return (hits[0], "name", RESOLVED, [])
            return (f"ext:{d.split('.')[-1]}", "import", RESOLVED, [])
        if x.type == "scoped_call_expression":
            scope = _t(x.child_by_field_name("scope"))
            name = _t(x.child_by_field_name("name"))
            if scope in ("self", "static") and cls is not None:
                r = self.m.fun_in(cls.id, name)
                return (r, "this", RESOLVED, []) if r else None
            if scope == "parent" and cls is not None:
                for s in self._supers(cls):
                    r = self.m.fun_in(s, name)
                    if r:
                        return (r, "this", RESOLVED, [])
                return None
            cid = self._cls(scope, f)
            if cid:
                r = self.m.fun_in(cid, name)
                return (r, "assoc", RESOLVED, []) if r else None
            full = f.uses.get(scope, scope)
            return (f"ext:{_dots(full).split('.')[-1]}.{name}", "import", RESOLVED, [])
        if x.type in ("member_call_expression", "nullsafe_member_call_expression"):
            obj = x.child_by_field_name("object")
            name = _t(x.child_by_field_name("name"))
            if obj is not None and _t(obj) == "$this" and cls is not None:
                r = self.m.fun_in(cls.id, name)
                return (r, "this", RESOLVED, []) if r else None
            tid = self._type_of(f, cls, env, obj)
            if tid:
                k = self.m.classes[tid]
                r = self.m.fun_in(tid, name)
                if k.kind in ("interface", "abstract"):
                    extra = [e for e in (self.m.fun_in(i, name) for i in self.m.implementers(tid)) if e and e != r]
                    if extra:
                        return (None, "interface", POSSIBLE, extra)
                return (r, "receiver-type", RESOLVED, []) if r else None
            # a typed variable of a library class: `$client->get()` where $client is a Guzzle client
            written = None
            if obj is not None and obj.type == "variable_name":
                written = env.get(_t(obj).lstrip("$"))
            elif obj is not None and obj.type == "member_access_expression" and cls is not None \
                    and _t(obj.child_by_field_name("object")) == "$this":
                written = cls.props.get(_t(obj.child_by_field_name("name")))
            if True:
                if written and written[:1].isupper() and not self._cls(written, f):
                    return (f"ext:{_dots(f.uses.get(written, written)).split('.')[-1]}.{name}", "receiver-type",
                            RESOLVED, [])
            base = obj
            while base is not None and base.type in ("member_call_expression", "nullsafe_member_call_expression",
                                                     "member_access_expression", "nullsafe_member_access_expression",
                                                     "parenthesized_expression"):
                base = base.child_by_field_name("object") if base.type != "parenthesized_expression" else next(
                    (c for c in base.children if c.is_named), None)
            if base is not None and base.type in ("scoped_call_expression", "function_call_expression"):
                t = self._target(f, cls, env, base)
                if t is None or (t[0] or "").startswith("ext:"):
                    return None                                 # a chain on a library call (DB::table()->where())
            return (None, "", "", [])
        return None

    def walk(self, f: PFile, cls: PClass | None, nodes, env: dict, src: str, skip: set) -> list[Ref]:
        refs: list[Ref] = []
        stack = list(reversed(nodes))
        while stack:
            x = stack.pop()
            if x.id in skip:
                continue
            if x.type in ("class_declaration", "function_definition", "interface_declaration", "trait_declaration"):
                continue
            line = x.start_point.row + 1
            if x.type == "assignment_expression":
                left, right = x.child_by_field_name("left"), x.child_by_field_name("right")
                if left is not None and left.type == "variable_name" and right is not None:
                    t = self._type_of(f, cls, env, right)
                    if right.type == "object_creation_expression" and not t:
                        t = _t(_kid(right, "name", "qualified_name")) or None
                    env[_t(left).lstrip("$")] = t or ""
            elif x.type in ("simple_parameter",):
                n = x.child_by_field_name("name")
                if n is not None:
                    env[_t(n).lstrip("$")] = _type_name(x.child_by_field_name("type")) or ""
            elif x.type in ("function_call_expression", "scoped_call_expression", "member_call_expression",
                            "nullsafe_member_call_expression"):
                res = self._target(f, cls, env, x)
                if res is not None:
                    target, via, conf, extra = res
                    if target:
                        refs.append(Ref(target, line, conf or RESOLVED, via))
                    for e in extra:
                        refs.append(Ref(e, line, POSSIBLE, via))
                    if not target and not extra and via == "":
                        fn_n = x.child_by_field_name("object")
                        key = f"{src}: {_t(fn_n)[:40]}->{_t(x.child_by_field_name('name'))}"
                        self.m.unresolved[key] = self.m.unresolved.get(key, 0) + 1
                self._http(f, cls, env, x, src)
                if x.type == "function_call_expression" and _t(x.child_by_field_name("function")) in CALLBACK_FUNS:
                    for a in _kids(x.child_by_field_name("arguments"), "argument"):
                        s = _string(next((c for c in a.children if c.is_named), None))
                        if s and re.fullmatch(r"[A-Za-z_]\w*", s):
                            hits = [h for h in self.m.fun_by_name.get(s.lower(), []) if self.m.funs[h].cls is None]
                            if len(hits) == 1:
                                refs.append(Ref(hits[0], line, INFERRED, "callback"))
            elif x.type == "object_creation_expression":
                cid = self._cls(_t(_kid(x, "name", "qualified_name")), f)
                if cid:
                    r = self.m.fun_in(cid, "__construct")
                    if r:
                        refs.append(Ref(r, line, RESOLVED, "constructor"))
            elif x.type == "array_creation_expression":
                r = self._callable_array(f, cls, x)
                if r:
                    refs.append(Ref(r, line, INFERRED, "callback"))
            elif x.type in ("include_expression", "include_once_expression", "require_expression",
                            "require_once_expression"):
                target = self._include_target(f, x)
                if target:
                    refs.append(Ref(target, line, RESOLVED, "include"))
            stack.extend(reversed(x.children))
        return refs

    def _callable_array(self, f, cls, x) -> str | None:
        """`[NoteController::class, 'show']` or `[$this, 'save']` → that method."""
        els = _kids(x, "array_element_initializer")
        if len(els) != 2:
            return None
        a = next((c for c in els[0].children if c.is_named), None)
        b = _string(next((c for c in els[1].children if c.is_named), None))
        if a is None or not b or not re.fullmatch(r"[A-Za-z_]\w*", b):
            return None
        if a.type == "variable_name" and _t(a) == "$this" and cls is not None:
            return self.m.fun_in(cls.id, b)
        if a.type == "class_constant_access_expression" and _t(a).endswith("::class"):
            cid = self._cls(_t(a.children[0]), f)
            return self.m.fun_in(cid, b) if cid else None
        return None

    def _include_target(self, f: PFile, x) -> str | None:
        s = None
        for c in x.children:
            if c.type in ("string", "encapsed_string"):
                s = _string(c)
            elif c.type == "parenthesized_expression":
                s = _string(next((d for d in c.children if d.is_named), None))
            elif c.type == "binary_expression" and _t(c).startswith("__DIR__"):
                s = _string(c.child_by_field_name("right"))
                s = s.lstrip("/") if s else None
        if not s:
            return None
        for base in (Path(f.rel).parent, Path(".")):
            cand = (base / s).as_posix()
            parts = []
            for p in cand.split("/"):
                if p == "..":
                    if parts:
                        parts.pop()
                elif p not in (".", ""):
                    parts.append(p)
            rel = "/".join(parts)
            if (self.repo / rel).is_file():
                return f"php:{rel}"
        return None

    # ---- outgoing HTTP ----
    def _url(self, f, cls, n) -> tuple[str | None, bool]:
        if n is None:
            return None, False
        s = _string(n)
        if s is not None:
            return s, False
        if n.type == "encapsed_string":
            out, pu = "", False
            for c in n.children:
                if c.type in ("string_content", "string_value"):
                    out += _t(c)
                elif c.type in ('"',):
                    continue
                else:
                    if not out:
                        pu = True
                    out += "{}"
            return out, pu
        if n.type == "binary_expression" and _t(n.child_by_field_name("operator")) == ".":
            left, lp = self._url(f, cls, n.child_by_field_name("left"))
            right, _ = self._url(f, cls, n.child_by_field_name("right"))
            if left is None or right is None:
                return None, False
            return left + (right if not (right == "{}" and left.endswith("{}")) else ""), lp
        return "{}", True

    def _http(self, f, cls, env, x, src):
        method, url_n = None, None
        args = [next((c for c in a.children if c.is_named), None)
                for a in _kids(x.child_by_field_name("arguments"), "argument")]
        if x.type == "scoped_call_expression" and _t(x.child_by_field_name("scope")) == "Http" and args:
            name = _t(x.child_by_field_name("name"))
            if HTTP_FN.match(name):
                method, url_n = name.upper(), args[0]
        elif x.type in ("member_call_expression", "nullsafe_member_call_expression") and args:
            name = _t(x.child_by_field_name("name"))
            obj = _t(x.child_by_field_name("object"))
            if re.search(r"client|http|guzzle|api", obj, re.I) or obj.startswith("Http::"):
                if HTTP_FN.match(name):
                    method, url_n = name.upper(), args[0]
                elif name == "request" and len(args) >= 2 and _string(args[0]):
                    method, url_n = _string(args[0]).upper(), args[1]
        elif x.type == "function_call_expression" and args and _t(x.child_by_field_name("function")) in (
                "curl_init", "file_get_contents", "wp_remote_get", "wp_remote_post"):
            fn = _t(x.child_by_field_name("function"))
            raw = _string(args[0]) or ""
            if fn == "file_get_contents" and not re.match(r"https?://", raw):
                return
            method, url_n = ("POST" if fn == "wp_remote_post" else "GET"), args[0]
        if not method or url_n is None:
            return
        from .java_frontend import _normalize
        raw, pu = self._url(f, cls, url_n)
        if raw is None or raw == "{}":
            return
        norm = _normalize(raw, pu)
        if norm:
            path, host, pu = norm
            self.http.append({"src": src, "method": method, "path": path, "raw": raw, "prefix_unknown": pu,
                              "host": host, "line": x.start_point.row + 1, "ui": None, "file": f.rel})


# ------------------------------------------------------------------------------------------------ routes

@dataclass
class Route:
    verb: str
    path: str
    handler: object        # a node: array, string, closure, class constant
    line: int
    auth: bool
    file: PFile


def _join(*parts: str) -> str:
    segs = [s.strip("/") for s in parts if s and s.strip("/")]
    return "/" + "/".join(segs)


def _laravel_path(p: str) -> str:
    return re.sub(r"\{[^}]*\}", lambda m: m.group(0).replace("?", ""), p)


def _routes(model: Model, f: PFile, nodes) -> list[Route]:
    """Laravel `Route::…` and router-object (`$app->get`, `$router->post`) registrations in these statements."""
    out: list[Route] = []
    api = bool(re.search(r"(^|/)routes/api\.php$", f.rel))

    def visit(n, prefix: str, auth: bool):
        if n.type in ("scoped_call_expression", "member_call_expression"):
            chain = _chain(n)                       # outermost call last
            names = [(_t(c.child_by_field_name("name")) or "").lower() for c in chain]
            root = chain[0]
            is_route = (root.type == "scoped_call_expression" and _t(root.child_by_field_name("scope")) in (
                "Route", "\\Route", "Illuminate\\Support\\Facades\\Route")) or (
                root.type == "member_call_expression" and _t(root.child_by_field_name("object")) in (
                    "$app", "$router", "$route", "$group", "$r", "$api", "$routes", "$v1"))
            if is_route:
                pre, a = prefix, auth
                for c, nm in zip(chain, names):
                    args = [next((x for x in g.children if x.is_named), None)
                            for g in _kids(c.child_by_field_name("arguments"), "argument")]
                    if nm in ("prefix",) and args and _string(args[0]) is not None:
                        pre = _join(pre, _string(args[0]))
                    elif nm in ("middleware", "add") and args and AUTH_MW.search(_t(c.child_by_field_name("arguments"))):
                        a = True
                    elif nm == "group":
                        body_fn = next((x for x in reversed(args) if x is not None and x.type in (
                            "anonymous_function", "arrow_function")), None)
                        opts = next((x for x in args if x is not None and x.type == "array_creation_expression"), None)
                        if opts is not None:
                            m = re.search(r"['\"]prefix['\"]\s*=>\s*['\"]([^'\"]*)", _t(opts))
                            if m:
                                pre = _join(pre, m.group(1))
                            if re.search(r"['\"]middleware['\"]\s*=>[^\]]*", _t(opts)) and AUTH_MW.search(_t(opts)):
                                a = True
                        if args and _string(args[0]) is not None and root.type == "member_call_expression":
                            pre = _join(pre, _string(args[0]))   # Slim: $app->group('/api', function ($g) {...})
                        if body_fn is not None:
                            body = body_fn.child_by_field_name("body")
                            for s in (body.children if body is not None else []):
                                visit(s, pre, a)
                        return
                    elif nm in VERBS and len(args) >= 2 and _string(args[0] if nm != "match" else args[1]) is not None:
                        path = _string(args[0] if nm != "match" else args[1])
                        verb = VERBS[nm]
                        if nm == "match" and args[0] is not None:
                            vs = re.findall(r"['\"](\w+)['\"]", _t(args[0]))
                            verb = vs[0].upper() if len(vs) == 1 else "ANY"
                        later = AUTH_MW.search(" ".join(_t(x.child_by_field_name("arguments")) for x, y in
                                                        zip(chain, names) if y == "middleware"))
                        out.append(Route(verb, _laravel_path(_join(pre, path)), args[-1], c.start_point.row + 1,
                                         a or bool(later), f))
                        return
                    elif nm in ("resource", "apiresource") and len(args) >= 2 and _string(args[0]) is not None:
                        base = _join(pre, _string(args[0]))
                        later = AUTH_MW.search(" ".join(_t(x.child_by_field_name("arguments")) for x, y in
                                                        zip(chain, names) if y == "middleware"))
                        for action, verb, suffix in RESOURCE:
                            if nm == "apiresource" and action in ("create", "edit"):
                                continue
                            out.append(Route(verb, base + suffix, (args[1], action), c.start_point.row + 1,
                                             a or bool(later), f))
                        return
                return
        for c in n.children:
            visit(c, prefix, auth)

    for s in nodes:
        visit(s, "/api" if api else "", False)
    return out


def _chain(n) -> list:
    """`Route::prefix('x')->middleware('auth')->group(...)` → [prefix call, middleware call, group call]."""
    out = []
    cur = n
    while cur is not None and cur.type in ("member_call_expression", "scoped_call_expression"):
        out.append(cur)
        cur = cur.child_by_field_name("object") if cur.type == "member_call_expression" else None
    return list(reversed(out))


def _php_attr_routes(fn: PFun, cls: PClass | None) -> list[tuple[str, str]]:
    """Symfony `#[Route('/p', methods: ['GET'])]` / `@Route("/p", methods={"GET"})` on a method, with the class prefix."""
    out = []
    pre = ""
    if cls is not None:
        m = re.search(r"(?:#\[|@)Route\(\s*(?:path:\s*)?['\"]([^'\"]*)['\"]", cls.attrs)
        pre = m.group(1) if m else ""
    for m in re.finditer(r"(?:#\[|@)(?:Route|Get|Post|Put|Patch|Delete)\(\s*(?:path:\s*)?['\"]([^'\"]*)['\"]([^\n]*)",
                         fn.attrs):
        kind = re.search(r"(?:#\[|@)(\w+)\(", m.group(0)).group(1)
        verbs = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", m.group(2), re.I)
        verb = kind.upper() if kind != "Route" else (verbs[0].upper() if len(verbs) == 1 else "ANY")
        out.append((verb, _join(pre, m.group(1))))
    return out


def _wordpress(model: Model, f: PFile, nodes) -> list[tuple[str, object, int]]:
    """(detail, handler node, line) for `add_action('wp_ajax_…')` and `register_rest_route(...)`."""
    out = []
    stack = list(nodes)
    while stack:
        x = stack.pop()
        if x.type == "function_call_expression":
            fn = _t(x.child_by_field_name("function"))
            args = [next((c for c in a.children if c.is_named), None)
                    for a in _kids(x.child_by_field_name("arguments"), "argument")]
            if fn == "add_action" and len(args) >= 2 and (_string(args[0]) or "").startswith("wp_ajax_"):
                hook = _string(args[0])
                anyone = hook.startswith("wp_ajax_nopriv_")
                action = hook[len("wp_ajax_nopriv_"):] if anyone else hook[len("wp_ajax_"):]
                out.append((f"POST /wp-admin/admin-ajax.php?action={action}" +
                            (" (anyone can call it)" if anyone else " (signed-in users)"), args[1],
                            x.start_point.row + 1))
            elif fn == "register_rest_route" and len(args) >= 3:
                ns, route = _string(args[0]) or "", _string(args[1]) or ""
                opts = _t(args[2]) if args[2] is not None else ""
                m = re.search(r"['\"]methods['\"]\s*=>\s*['\"]?([A-Z,\s]+|WP_REST_Server::\w+)", opts)
                verb = (m.group(1).split(",")[0].strip() if m else "GET")
                verb = {"WP_REST_Server::READABLE": "GET", "WP_REST_Server::CREATABLE": "POST",
                        "WP_REST_Server::EDITABLE": "PUT", "WP_REST_Server::DELETABLE": "DELETE"}.get(verb, verb)
                cb = None
                for el in _kids(args[2], "array_element_initializer") if args[2] is not None else []:
                    named = [c for c in el.children if c.is_named]
                    if len(named) == 2 and _string(named[0]) == "callback":
                        cb = named[1]
                route = re.sub(r"\(\?P<(\w+)>[^)]*\)", r"{\1}", route)
                if cb is not None:
                    out.append((f"{verb or 'GET'} {_join('wp-json', ns, route)}", cb, x.start_point.row + 1))
        stack.extend(x.children)
    return out


# ------------------------------------------------------------------------------------------------ build

def add_php(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    paths = discover(repo)
    if not paths:
        return {}
    try:
        parser = _parser()
    except ImportError:
        g.meta.setdefault("skipped_languages", []).append("php (pip install tree-sitter-php)")
        return {}
    model = Model()
    files: list[PFile] = []
    total = 0
    for p in paths:
        try:
            src = project_bytes(p, repo)
        except OSError:
            continue
        if len(src) > MAX_BYTES:
            continue
        rel = p.relative_to(repo).as_posix()
        root = parser.parse(src).root_node
        lines = src.count(b"\n") + 1
        total += lines
        f = PFile(rel=rel, lines=lines, is_test=bool(TEST_FILE_RE.search(rel)))
        _collect(model, f, root, src.decode("utf-8", "replace").splitlines())
        f.page = bool(f.top) and not f.is_test and not NOT_PAGES.search(rel) and not _only_setup(f.top)
        files.append(f)
    link = Linker(model, repo)
    link.resolve_supers()

    for f in files:
        g.add_node(Node(id=f"php:{f.rel}", kind=MODULE, name=Path(f.rel).name, qualname=f.rel, file=f.rel,
                        start_line=1, end_line=f.lines))
        if f.is_test:
            g.nodes[f"php:{f.rel}"].entry = {"kind": "test", "detail": f.rel}
    for c in model.classes.values():
        sup = f" extends {', '.join(s.split('.')[-1] for s in c.supers)}" if c.supers else ""
        g.add_node(Node(id=f"php:{c.id}", kind=CLASS, name=c.short, qualname=c.id, file=c.file, start_line=c.start,
                        end_line=c.end, parent=f"php:{c.file}", signature=f"{c.kind} {c.short}{sup}"[:200]))
        g.add_edge(f"php:{c.file}", f"php:{c.id}", kind=CONTAINS)
    for mid, fn in model.funs.items():
        parent = f"php:{fn.cls}" if fn.cls else f"php:{fn.file}"
        g.add_node(Node(id=mid, kind=CALLABLE, name=fn.name, qualname=mid[4:], file=fn.file, start_line=fn.start,
                        end_line=fn.end, parent=parent, fingerprint=fn.fingerprint, signature=fn.signature))
        g.add_edge(parent, mid, kind=CONTAINS)

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

    by_rel = {f.rel: f for f in files}

    def handler_target(f: PFile, h, cls_hint: str | None = None) -> str | None:
        if isinstance(h, tuple):                              # resource: (controller node, action)
            node, action = h
            cid = link._cls(_t(node.children[0]) if node.type == "class_constant_access_expression" else _string(node),
                            f)
            return model.fun_in(cid, action) if cid else None
        if h is None:
            return None
        if h.type == "array_creation_expression":
            return link._callable_array(f, None, h)
        s = _string(h)
        if s is not None:
            if "@" in s or ":" in s:                          # 'NoteController@show', Slim 'NoteController:show'
                parts = re.split(r"@|::?", s)
                cname, m = parts[0], parts[-1]
                cid = link._cls(cname, f) or link._cls("App\\Http\\Controllers\\" + cname, f) or model._by_short(
                    cname.split("\\")[-1])
                return model.fun_in(cid, m) if cid else None
            hits = [x for x in model.fun_by_name.get(s.lower(), []) if model.funs[x].cls is None]
            return hits[0] if len(hits) == 1 else None
        if h.type == "binary_expression" and _t(h.child_by_field_name("left")).endswith("::class"):
            m = re.fullmatch(r"[:@](\w+)", _string(h.child_by_field_name("right")) or "")   # Slim: Ping::class . ':handle'
            cid = link._cls(_t(h.child_by_field_name("left"))[:-len("::class")], f)
            return model.fun_in(cid, m.group(1)) if cid and m else None
        if h.type == "class_constant_access_expression" and _t(h).endswith("::class"):   # invokable controller
            cid = link._cls(_t(h.children[0]), f)
            return model.fun_in(cid, "__invoke") if cid else None
        return None

    def mark(target: str, detail: str, auth: bool, line: int):
        nonlocal routes
        n = g.nodes.get(target)
        if n is None:
            return
        n.entry = {"kind": "route", "detail": detail}
        routes += 1
        if auth:
            g.external("middleware.auth")
            g.add_edge(target, "ext:middleware.auth", kind=CALLS, confidence=RESOLVED, line=line, via="middleware")

    def closure_node(f: PFile, h, detail: str, owner: str, auth: bool) -> set:
        lid = f"php:{f.rel}::{detail}"
        g.add_node(Node(id=lid, kind=CALLABLE, name=detail, qualname=f"{f.rel}::{detail}", file=f.rel,
                        start_line=h.start_point.row + 1, end_line=h.end_point.row + 1, parent=owner,
                        fingerprint=hashlib.sha1(h.text, usedforsecurity=False).hexdigest()[:12],
                        signature=re.sub(r"\s+", " ", _t(h).split("{")[0])[:200]))
        g.add_edge(owner, lid, kind=CONTAINS)
        mark(lid, detail, auth, h.start_point.row + 1)
        env = _params(h.child_by_field_name("parameters"))
        body = h.child_by_field_name("body")
        add_refs(lid, link.walk(f, None, [body] if body is not None else [], env, lid, set()))
        return {h.id}

    route_skip: dict[str, set] = {}
    for f in files:
        scopes = [(f"php:{f.rel}", f.top)] + [(mid, [fn.node]) for mid, fn in model.funs.items() if fn.file == f.rel]
        for owner, nodes in scopes:
            for r in _routes(model, f, nodes):
                detail = f"{r.verb} {r.path}"
                h = r.handler
                if not isinstance(h, tuple) and h is not None and h.type in ("anonymous_function", "arrow_function"):
                    route_skip.setdefault(owner, set()).update(closure_node(f, h, detail, owner, r.auth))
                    continue
                t = handler_target(f, h)
                if t:
                    mark(t, detail, r.auth, r.line)
            for detail, h, line in _wordpress(model, f, nodes):
                if h is not None and h.type in ("anonymous_function", "arrow_function"):
                    route_skip.setdefault(owner, set()).update(closure_node(f, h, detail, owner, False))
                    continue
                cls = None
                if owner in model.funs and model.funs[owner].cls:
                    cls = model.classes.get(model.funs[owner].cls)
                t = handler_target(f, h) if h is None or h.type != "array_creation_expression" else \
                    link._callable_array(f, cls, h)
                if t:
                    mark(t, detail, "signed-in" in detail, line)

    for mid, fn in model.funs.items():
        f = by_rel[fn.file]
        cls = model.classes.get(fn.cls) if fn.cls else None
        body = fn.node.child_by_field_name("body")
        refs = link.walk(f, cls, [body] if body is not None else [], dict(fn.params), mid, route_skip.get(mid, set()))
        add_refs(mid, refs)
    for f in files:
        if f.top:
            mid = f"php:{f.rel}"
            add_refs(mid, link.walk(f, None, f.top, {}, mid, route_skip.get(mid, set())))
    included = {e.dst for e in g.call_edges() if e.via == "include"}
    for f in files:
        if f.top:
            mid = f"php:{f.rel}"
            if f.page and not g.nodes[mid].entry and mid not in included:   # an included file is not opened directly
                url = re.sub(r"^(?:.*/)?(?:public|public_html|htdocs|www|web)/", "", f.rel)   # the web root
                g.nodes[mid].entry = {"kind": "route", "detail": f"ANY /{url}"}
                routes += 1

    for mid, fn in model.funs.items():
        node = g.nodes[mid]
        cls = model.classes.get(fn.cls) if fn.cls else None
        f = by_rel[fn.file]
        for verb, path in _php_attr_routes(fn, cls):
            node.entry = {"kind": "route", "detail": f"{verb} {path}"}
            routes += 1
        if node.entry:
            continue
        if f.is_test and cls is not None and (fn.name.startswith("test") or re.search(r"#\[Test\]|@test\b", fn.attrs)):
            node.entry = {"kind": "test", "detail": fn.file}
        elif cls is not None and fn.name == "handle" and any(s.split(".")[-1] == "Command" for s in cls.supers):
            try:
                m = re.search(r"\$signature\s*=\s*['\"]([^\s'\"]+)", project_text(repo / fn.file, repo))
            except OSError:   # the file went away since it was read
                m = None
            node.entry = {"kind": "main", "detail": f"command php artisan {m.group(1) if m else cls.short}"}

    g.meta.setdefault("http_calls", []).extend(link.http)
    for key, n in model.unresolved.items():
        g.unresolved[key[:120]] = g.unresolved.get(key[:120], 0) + n
    return {"files": len(files), "lines": total, "classes": len(model.classes), "functions": len(model.funs),
            "routes": routes, "http_calls": len(link.http), "unresolved": sum(model.unresolved.values())}


def _only_setup(top) -> bool:
    """True when a file's top-level code only loads, defines or returns things (config files, bootstraps)."""
    for s in top:
        t = _t(s).strip()
        if s.type == "return_statement" or s.type == "text":
            continue
        if s.type == "expression_statement" and re.match(
                r"(require|include)(_once)?\b|define\s*\(|declare\s*\(|spl_autoload_register|"
                r"(Route|\$router|\$app|\$route)\b|add_(action|filter|shortcode)\s*\(|register_\w+\s*\(", t):
            continue
        return False
    return True
