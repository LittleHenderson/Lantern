"""Ruby: Rails and Sinatra apps, mapped like the PHP reader maps PHP.

Node ids: class or module `rb:<Outer.Inner>` (`Admin::NotesController` → `rb:Admin.NotesController`), method
`rb:<Outer.Inner>.<method>` (instance and `def self.` methods share the namespace), top-level method `rb:<method>`, file
module `rb:<path>.rb`. A Sinatra route block is its own node `rb:<path>.rb::GET /notes/:id`.

Calls are resolved by:
  * `name`          `helper(x)` or a bare `helper` (not a local variable) → a method of the same class, its
                    superclasses or included modules, else a top-level method
  * `this`          `self.helper`
  * `assoc`         `NoteService.run` (a class method on a repo class); `Note.new` → `Note.initialize`
                    (`constructor`); an Active Record model's own query methods (`Note.where`, `note.save`) are
                    `ext:ActiveRecord.<method>`; an unknown constant → `ext:<Constant>.<method>`
  * `receiver-type` `svc.run` / `@svc.run` where `svc = NoteService.new` (in the method, or `@svc = …` anywhere in the
                    class)
Unknown receivers are counted in `graph.unresolved` (Ruby rarely says a type); chains on library calls are not.
Blocks belong to the method they are written in.

Entries:
  * Rails routes (`config/routes.rb`): `resources`/`resource` (with `only:`/`except:`), `get "/p", to: "c#a"`,
    `get "p" => "c#a"`, `root "c#a"`, `namespace :api` (path and controller module), `scope "/x"`. A controller's
    `before_action :authenticate_user!` (any filter with an auth word, inherited, `only:`/`except:`,
    `skip_before_action`) gives the action a `middleware` edge to `ext:middleware.auth`.
  * Sinatra: `get '/p' do … end` (top level or in a `Sinatra::Base` class).
  * Background jobs (`perform` in an `ApplicationJob` or a class including `Sidekiq::Job`/`Worker`) → `main`;
    Rake tasks are not entries.
  * Tests: files under `spec/` and `test/`, `def test_…` methods.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import deep
from .graph import CALLABLE, CALLS, CLASS, CONTAINS, MODULE, RESOLVED, Graph, Node
from .python_frontend import inside_repo, project_bytes, skipped

MAX_BYTES = 1_500_000
SKIP = re.compile(r"(^|/)(vendor|tmp|log|coverage|node_modules|\.bundle)/|(^|/)db/schema\.rb$")
TEST_FILE_RE = re.compile(r"(^|/)(spec|test)/|_(spec|test)\.rb$")
VERBS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "match": "ANY"}
RESOURCES = [("index", "GET", ""), ("new", "GET", "/new"), ("create", "POST", ""), ("show", "GET", "/:id"),
             ("edit", "GET", "/:id/edit"), ("update", "PATCH", "/:id"), ("destroy", "DELETE", "/:id")]
RESOURCE = [("new", "GET", "/new"), ("create", "POST", ""), ("show", "GET", ""), ("edit", "GET", "/edit"),
            ("update", "PATCH", ""), ("destroy", "DELETE", "")]
AUTH_FILTER = re.compile(r"(^|_)(authenticat\w*?|authoriz\w*?|auth|login|logged_in|signed_in|sign_in|admin|administrative|"
                         r"current_user|verify_user|require_user|session|token|api_key)(_|!|\?|$)")
AR_BASES = {"ApplicationRecord", "ActiveRecord::Base", "Base"}
JOB_BASES = {"ApplicationJob", "ActiveJob::Base"}
# Active Record class methods that hand back a record of the same model (`note = Note.find(id)`; `note.destroy`).
FINDERS = {"find", "find_by", "find_by!", "first", "last", "new", "create", "create!", "take", "find_or_create_by",
           "find_or_initialize_by", "build"}
# Kernel methods that reach the shell, a file or `eval`: kept as `ext:Kernel.<name>` so the Data lane shows them.
KERNEL = {"system", "exec", "spawn", "eval", "open", "fork", "syscall", "instance_eval", "class_eval"}


def _parser():
    import tree_sitter as ts
    import tree_sitter_ruby as tr
    return ts.Parser(ts.Language(tr.language()))


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _ends(src: bytes | None, n, keep: int = 200) -> str:
    """A node's text, or, of one longer than twice `keep` bytes, its first and its last `keep` bytes with a space
    between, read without taking the whole of it. The last call of a chain has the whole chain before it as what
    it is made on, so a line of a hundred thousand chained calls, each asked for that text, was megabytes for every
    call of it (measured 2026-11-13: not through after four minutes). Text of ordinary length is read as before."""
    if n is None:
        return ""
    a, b = n.start_byte, n.end_byte
    if src is None or b - a <= 2 * keep:
        return _t(n)
    return src[a:a + keep].decode("utf-8", "replace") + " " + src[b - keep:b].decode("utf-8", "replace")


def _kids(n, *types):
    return [c for c in n.children if c.type in types] if n is not None else []


def _str(n) -> str | None:
    """A plain string or symbol's text."""
    if n is None:
        return None
    if n.type == "string":
        if any(c.type == "interpolation" for c in n.children):
            return None
        return "".join(_t(c) for c in n.children if c.type == "string_content")
    if n.type in ("simple_symbol", "hash_key_symbol"):
        return _t(n).lstrip(":")
    if n.type == "delimited_symbol":
        return "".join(_t(c) for c in n.children if c.type == "string_content")
    return None


def _args(call) -> list:
    al = call.child_by_field_name("arguments")
    return [c for c in al.children if c.is_named] if al is not None else []


def _pairs(args) -> dict:
    out = {}
    for a in args:
        if a.type == "pair":
            k = _str(a.child_by_field_name("key"))
            if k:
                out[k.rstrip(":")] = a.child_by_field_name("value")
    return out


def _symbols(n) -> list[str]:
    if n is None:
        return []
    if n.type == "array":
        return [s for s in (_str(c) for c in n.children if c.is_named) if s]
    s = _str(n)
    return [s] if s else []


@dataclass
class RFun:
    name: str
    cls: str | None
    file: str
    start: int
    end: int
    signature: str
    fingerprint: str
    params: list[str] = field(default_factory=list)
    node: object = None
    singleton: bool = False


@dataclass
class RClass:
    id: str                # dotted
    short: str
    file: str
    start: int
    end: int
    kind: str              # class | module
    superclass: str | None = None
    mixins: list[str] = field(default_factory=list)
    funs: set[str] = field(default_factory=set)
    ivars: dict[str, str] = field(default_factory=dict)     # @svc → NoteService
    filters: list[tuple[str, str, set, set]] = field(default_factory=list)   # (kind, name, only, except)


@dataclass
class RFile:
    rel: str
    lines: int
    is_test: bool = False
    top: list = field(default_factory=list)


class Model:
    left = None     # (map, reader) once the reader has a map: where a piece that was not read is written down

    def __init__(self):
        self.classes: dict[str, RClass] = {}
        self.by_short: dict[str, list[str]] = {}
        self.funs: dict[str, RFun] = {}
        self.top_funs: dict[str, str] = {}
        self.unresolved: dict[str, int] = {}

    def find(self, name: str, ctx: str | None) -> str | None:
        """A constant as written (`Note`, `Admin::Note`, `::Note`) → a repo class id, looked up from the lexical
        scope `ctx` outwards, then by its last part when that is unique."""
        if not name:
            return None
        d = name.lstrip(":").replace("::", ".")
        if not name.startswith("::") and ctx:
            parts = ctx.split(".")
            for i in range(len(parts), 0, -1):
                cand = ".".join(parts[:i]) + "." + d
                if cand in self.classes:
                    return cand
        if d in self.classes:
            return d
        hits = self.by_short.get(d.split(".")[-1], [])
        return hits[0] if len(hits) == 1 else None

    def ancestors(self, cid: str) -> list[str]:
        out, todo = [], [cid]
        while todo and len(out) < 20:
            c = self.classes.get(todo.pop(0))
            if c is None or c.id in out:
                continue
            out.append(c.id)
            ctx = c.id.rsplit(".", 1)[0] if "." in c.id else None
            for m in c.mixins:
                r = self.find(m, ctx)
                if r:
                    todo.append(r)
            if c.superclass:
                r = self.find(c.superclass, ctx)
                if r:
                    todo.append(r)
        return out

    def fun_in(self, cid: str | None, name: str) -> str | None:
        for a in (self.ancestors(cid) if cid else []):
            if name in self.classes[a].funs:
                return f"rb:{a}.{name}"
        return None

    def is_record(self, cid: str) -> bool:
        for a in self.ancestors(cid):
            c = self.classes[a]
            if c.superclass in AR_BASES or c.superclass == "ActiveRecord::Base" or c.id == "ApplicationRecord":
                return True
        return False


def discover(repo: Path) -> list[Path]:
    out = []
    for p in list(repo.rglob("*.rb")) + list(repo.rglob("Rakefile")):
        rel = p.relative_to(repo)
        if skipped(rel.parts[:-1], repo) or SKIP.search(rel.as_posix()) or not p.is_file() \
                or not inside_repo(p, repo):
            continue
        out.append(p)
    return sorted(set(out))


def _params(n) -> list[str]:
    out = []
    for c in (n.children if n is not None else []):
        if c.type == "identifier":
            out.append(_t(c))
        elif c.type in ("optional_parameter", "keyword_parameter", "splat_parameter", "hash_splat_parameter",
                        "block_parameter"):
            nm = c.child_by_field_name("name")
            if nm is not None:
                out.append(_t(nm))
    return out


def _collect(model: Model, f: RFile, root) -> None:
    def walk(nodes, scope: str | None, cls: RClass | None):
        for c in nodes:
            try:
                if c.type in ("class", "module"):
                    nm = c.child_by_field_name("name")
                    if nm is None:
                        continue
                    local = _t(nm).replace("::", ".")
                    cid = (scope + "." if scope else "") + local
                    k = model.classes.get(cid)
                    if k is None:
                        k = RClass(id=cid, short=local.split(".")[-1], file=f.rel, start=c.start_point.row + 1,
                                   end=c.end_point.row + 1, kind=c.type)
                        model.classes[cid] = k
                        model.by_short.setdefault(k.short, []).append(cid)
                    sup = c.child_by_field_name("superclass")
                    if sup is not None:
                        k.superclass = _t(next((x for x in sup.children if x.is_named), None)) or None
                    body = c.child_by_field_name("body") or next((x for x in c.children if x.type == "body_statement"), None)
                    if body is not None:
                        walk(body.children, cid, k)
                elif c.type in ("method", "singleton_method"):
                    _fun(c, cls)
                elif c.type == "call" and cls is not None and c.child_by_field_name("receiver") is None:
                    m = _t(c.child_by_field_name("method"))
                    args = _args(c)
                    if m in ("include", "extend", "prepend"):
                        cls.mixins += [_t(a) for a in args if a.type in ("constant", "scope_resolution")]
                    elif m in ("before_action", "skip_before_action", "prepend_before_action", "before_filter"):
                        kw = _pairs(args)
                        only, exc = set(_symbols(kw.get("only"))), set(_symbols(kw.get("except")))
                        cond = "if" in kw or "unless" in kw        # a filter that runs only sometimes is not a login check
                        for a in args:
                            s = _str(a)
                            if s:
                                kind = "skip" if m.startswith("skip") else "cond" if cond else "add"
                                cls.filters.append((kind, s, only, exc))
                    elif m in ("attr_accessor", "attr_reader"):
                        pass
                    else:
                        f.top.append(c) if cls is None else None
                elif c.type == "body_statement":
                    walk(c.children, scope, cls)
                elif cls is None and c.type not in ("comment",):
                    f.top.append(c)
            except RecursionError:
                # declared inside more declarations than this walk follows: left where it stands and written down
                deep.leave(model.left, f.rel, c)

    def _fun(c, cls: RClass | None):
        nm = c.child_by_field_name("name")
        if nm is None:
            return
        name = _t(nm)
        mid = f"rb:{cls.id}.{name}" if cls else f"rb:{name}"
        body = c.child_by_field_name("body")
        sig_end = body.start_byte if body is not None else c.end_byte
        sig = re.sub(r"\s+", " ", c.text[: sig_end - c.start_byte].decode("utf-8", "replace")).strip()
        if mid in model.funs:
            return
        model.funs[mid] = RFun(name=name, cls=cls.id if cls else None, file=f.rel, start=c.start_point.row + 1,
                               end=c.end_point.row + 1, signature=sig[:200],
                               fingerprint=hashlib.sha1(c.text, usedforsecurity=False).hexdigest()[:12],
                               params=_params(c.child_by_field_name("parameters")), node=c,
                               singleton=c.type == "singleton_method")
        if cls:
            cls.funs.add(name)
            for a in _walk_all(body):                              # @svc = NoteService.new anywhere in the class
                if a.type == "assignment":
                    left, right = a.child_by_field_name("left"), a.child_by_field_name("right")
                    if left is not None and left.type == "instance_variable" and right is not None \
                            and right.type == "call" and _t(right.child_by_field_name("method")) == "new":
                        recv = right.child_by_field_name("receiver")
                        if recv is not None and recv.type in ("constant", "scope_resolution"):
                            cls.ivars.setdefault(_t(left), _t(recv))
        else:
            model.top_funs[name] = mid

    walk(root.children, None, None)


def _walk_all(n):
    stack = [n] if n is not None else []
    while stack:
        x = stack.pop()
        yield x
        stack.extend(x.children)


@dataclass
class Ref:
    target: str
    line: int
    confidence: str
    via: str


def _foot(node):
    """What a chain hangs on: the receiver at its foot (`a` of `a.b.c`), or the first call that has none."""
    while node is not None and node.type == "call" and node.child_by_field_name("receiver") is not None:
        node = node.child_by_field_name("receiver")
    return node


class Linker:
    left = None     # (map, reader) once the reader has a map: where a piece that was not read is written down

    def __init__(self, model: Model):
        self.m = model
        self.http: list[dict] = []
        self.texts: dict[str, bytes] = {}                    # each file's bytes, for `_ends`

    def _const(self, recv, cls: RClass | None) -> str | None:
        return self.m.find(_t(recv), cls.id if cls else None) if recv is not None and recv.type in (
            "constant", "scope_resolution") else None

    def _type_of(self, recv, cls: RClass | None, env: dict) -> str | None:
        if recv is None:
            return None
        if recv.type == "identifier":
            return env.get(_t(recv)) or None
        if recv.type == "instance_variable" and cls is not None:
            for a in self.m.ancestors(cls.id):
                t = self.m.classes[a].ivars.get(_t(recv))
                if t:
                    return self.m.find(t, a)
            return None
        if recv.type == "call" and _t(recv.child_by_field_name("method")) == "new":
            return self._const(recv.child_by_field_name("receiver"), cls)
        if recv.type == "call" and _t(recv.child_by_field_name("method")) in FINDERS:
            cid = self._const(recv.child_by_field_name("receiver"), cls)
            return cid if cid and self.m.is_record(cid) else None
        if recv.type == "parenthesized_statements":
            inner = recv                                     # brackets inside brackets: taken off one by one
            while inner is not None and inner.type == "parenthesized_statements":
                inner = next((c for c in inner.children if c.is_named), None)
            return self._type_of(inner, cls, env)
        return None

    def target(self, call, cls: RClass | None, env: dict, fn: RFun | None, memo: dict | None = None
               ) -> tuple[str | None, str] | None:
        """(target id, via) for a call; (None, "") when the receiver is unknown (counted); None when nothing to add.

        A chain `a.b.c.d` is worked out from its first call outwards, each call once. `memo` keeps the answers (by
        the call's node) and what each call's chain hangs on, for as long as no name changes what it holds: `walk`
        hands the same one to every call of a body and empties it where a name is given a value. Until 2026-11-13
        every call of a chain went down the whole chain again, at each step once more to its foot: twice the links
        took eight times the time (800 links 26 seconds), and beyond about a thousand links Python stopped it."""
        if memo is None:
            memo = {}
        chain, x = [], call
        while x.id not in memo:
            chain.append(x)
            recv = x.child_by_field_name("receiver")
            if recv is None or recv.type != "call":
                break
            x = recv
        for x in reversed(chain):
            recv = x.child_by_field_name("receiver")
            memo["foot", x.id] = x if recv is None else self._foot_of(recv, memo)
            memo[x.id] = self._target(x, cls, env, fn, memo)
        return memo[call.id]

    @staticmethod
    def _foot_of(recv, memo):
        key = ("foot", recv.id)
        return memo[key] if key in memo else _foot(recv)

    def _target(self, call, cls, env, fn, memo):
        name = _t(call.child_by_field_name("method"))
        recv = call.child_by_field_name("receiver")
        if recv is None:
            if cls is not None and (fn is None or not fn.singleton):
                r = self.m.fun_in(cls.id, name)
                if r:
                    return (r, "name")
            if cls is not None and fn is not None and fn.singleton:
                r = self.m.fun_in(cls.id, name)
                if r and self.m.funs[r].singleton:
                    return (r, "name")
            if name in self.m.top_funs:
                return (self.m.top_funs[name], "name")
            if name in KERNEL:
                return (f"ext:Kernel.{name}", "import")
            return None
        if recv.type == "self":
            r = self.m.fun_in(cls.id, name) if cls else None
            return (r, "this") if r else None
        cid = self._const(recv, cls)
        if cid:
            if name == "new":
                r = self.m.fun_in(cid, "initialize")
                return (r, "constructor") if r else None
            r = self.m.fun_in(cid, name)
            if r:
                return (r, "assoc")
            if self.m.is_record(cid):
                return (f"ext:ActiveRecord.{name}", "assoc")
            return None
        if recv.type in ("constant", "scope_resolution"):
            return (f"ext:{_t(recv).replace('::', '.')}.{name}", "import")
        tid = self._type_of(recv, cls, env)
        if tid:
            r = self.m.fun_in(tid, name)
            if r:
                return (r, "receiver-type")
            if self.m.is_record(tid):
                return (f"ext:ActiveRecord.{name}", "receiver-type")
            return None
        if recv.type == "call":                              # a chain on a library call: Note.all.to_a, expect(1).to
            inner = memo[recv.id]                             # worked out before this call: `target`
            if inner is None or (inner[0] or "").startswith("ext:"):
                return None
        base = self._foot_of(recv, memo)
        if base is not None and base.type in ("constant", "scope_resolution") and not self._const(base, cls):
            return None                                       # a chain on a library (Net::HTTP.get(...).body)
        if recv.type in ("identifier", "instance_variable", "call", "element_reference"):
            return (None, "")
        return None

    def walk(self, nodes, cls: RClass | None, env: dict, src: str, fn: RFun | None, skip: set,
             file: str = "") -> list[Ref]:
        refs: list[Ref] = []
        memo: dict = {}                                      # what `target` worked out while `env` was as it is now
        text = self.texts.get(file or (fn.file if fn is not None else ""))
        # Each node goes on the stack with the node it was found in. Asking a node for its parent costs a walk from
        # the top of the file down to it, and every name of a chain of 20,000 calls asking was 40 seconds (2026-11-13).
        stack = [(n, None) for n in reversed(nodes)]
        while stack:
            x, up = stack.pop()
            if x.id in skip or x.type in ("class", "module", "method", "singleton_method"):
                continue
            line = x.start_point.row + 1
            try:
                if x.type == "assignment":
                    left, right = x.child_by_field_name("left"), x.child_by_field_name("right")
                    if left is not None and left.type == "identifier":
                        t = self._type_of(right, cls, env) if right is not None else None
                        env[_t(left)] = t or ""
                        memo.clear()
                elif x.type in ("block_parameters", "lambda_parameters"):
                    for p in _params(x):
                        env[p] = ""
                    memo.clear()
                elif x.type == "identifier" and (up or x.parent) is not None and (up or x.parent).type in (
                        "body_statement", "then", "else", "do_block", "block_body", "begin",
                        "parenthesized_statements") and _t(x) not in env:
                    name = _t(x)                                   # a bare call: `helper`
                    r = (self.m.fun_in(cls.id, name) if cls else None) or self.m.top_funs.get(name)
                    if r:
                        refs.append(Ref(r, line, RESOLVED, "name"))
                elif x.type == "subshell":                           # `cmd #{x}`
                    refs.append(Ref("ext:Kernel.`", line, RESOLVED, "import"))
                elif x.type == "call":
                    res = self.target(x, cls, env, fn, memo)
                    if res is not None:
                        t, via = res
                        if t:
                            refs.append(Ref(t, line, RESOLVED, via))
                        elif via == "":
                            key = (f"{src}: {_ends(text, x.child_by_field_name('receiver'), 160)[:40]}."
                                   f"{_t(x.child_by_field_name('method'))}")
                            self.m.unresolved[key] = self.m.unresolved.get(key, 0) + 1
                    self._http(x, src, text)
            except RecursionError:
                # nested deeper than the lookup follows: left with all that is written in it, and written down
                deep.leave(self.left, file or (fn.file if fn is not None else ""), x, env, blank="")
                memo.clear()
                continue
            stack.extend((c, x) for c in reversed(x.children))
        return refs

    def _http(self, call, src, text: bytes | None = None):
        name = _t(call.child_by_field_name("method"))
        if name.lower() not in ("get", "post", "put", "patch", "delete", "get_response"):
            return
        args = _args(call)
        if not args:
            return
        recv = _ends(text, call.child_by_field_name("receiver"))
        if not re.search(r"^(HTTParty|Faraday|RestClient|Net::HTTP|HTTP|Excon|Typhoeus)$|conn|client|http|api",
                         recv, re.I):
            return
        url = args[0]
        raw, pu = None, False
        if url.type == "string":
            parts = []
            for c in url.children:
                if c.type == "string_content":
                    parts.append(_t(c))
                elif c.type == "interpolation":
                    if not parts:
                        pu = True
                    parts.append("{}")
            raw = "".join(parts)
        elif url.type == "call" and _t(url.child_by_field_name("method")) == "parse" and _args(url):
            inner = _args(url)[0]
            raw = _str(inner)
        if not raw:
            return
        from .java_frontend import _normalize
        norm = _normalize(raw, pu)
        if norm:
            path, host, pu = norm
            self.http.append({"src": src, "method": "GET" if name == "get_response" else name.upper(), "path": path,
                              "raw": raw, "prefix_unknown": pu, "host": host, "line": call.start_point.row + 1,
                              "ui": None, "file": None})


# ------------------------------------------------------------------------------------------------ routes

def _join(*parts: str) -> str:
    segs = [s.strip("/") for s in parts if s and s.strip("/")]
    return "/" + "/".join(segs)


def _rails_routes(nodes) -> list[tuple[str, str, str, str, int]]:
    """(verb, path, controller path like `api/notes`, action, line) from a routes.rb `draw` block."""
    out = []

    def visit(stmts, prefix: str, module: str):
        for c in stmts:
            if c.type != "call" or c.child_by_field_name("receiver") is not None:
                if c.type in ("call",):
                    blk = c.child_by_field_name("block")
                    if blk is not None:
                        visit(_block_body(blk), prefix, module)
                continue
            m = _t(c.child_by_field_name("method"))
            args = _args(c)
            kw = _pairs(args)
            line = c.start_point.row + 1
            blk = c.child_by_field_name("block")
            first = _str(args[0]) if args else None
            if m in ("namespace",) and first:
                visit(_block_body(blk), _join(prefix, first), (module + "/" if module else "") + first)
            elif m == "scope":
                path = first or _str(kw.get("path")) or ""
                mod = _str(kw.get("module"))
                visit(_block_body(blk), _join(prefix, path), (module + "/" + mod).strip("/") if mod else module)
            elif m in ("resources", "resource"):
                names = [s for s in (_str(a) for a in args) if s]
                only, exc = set(_symbols(kw.get("only"))), set(_symbols(kw.get("except")))
                ctrl_name = _str(kw.get("controller"))
                path_name = _str(kw.get("path"))
                for name in names:
                    ctrl = (module + "/" if module else "") + (ctrl_name or (name if m == "resources" else name + "s"))
                    base = _join(prefix, path_name or name)
                    for action, verb, suffix in (RESOURCES if m == "resources" else RESOURCE):
                        if (only and action not in only) or action in exc:
                            continue
                        out.append((verb, base + suffix, ctrl, action, line))
                    inner = _block_body(blk)
                    if inner:
                        visit_member(inner, base, ctrl, m == "resources")
            elif m in VERBS or m == "root":
                to = _str(kw.get("to"))
                path = first if m != "root" else "/"
                if m == "root" and first and "#" in first:
                    to = first
                for a in args:                               # get "p" => "c#a"
                    if a.type == "pair" and _str(a.child_by_field_name("key")) and \
                            a.child_by_field_name("key").type == "string":
                        path, to = _str(a.child_by_field_name("key")), _str(a.child_by_field_name("value"))
                if path is not None and to and "#" in to:
                    ctrl, action = to.split("#", 1)
                    verb = "GET" if m == "root" else VERBS[m]
                    if m == "match":
                        via = _symbols(kw.get("via"))
                        verb = via[0].upper() if len(via) == 1 else "ANY"
                    out.append((verb, _join(prefix, path), (module + "/" if module else "") + ctrl, action, line))
            elif blk is not None:
                visit(_block_body(blk), prefix, module)

    def visit_member(stmts, base, ctrl, plural):
        for c in stmts:
            if c.type != "call":
                continue
            m = _t(c.child_by_field_name("method"))
            if m in ("member", "collection"):
                for s in _block_body(c.child_by_field_name("block")):
                    if s.type == "call" and _t(s.child_by_field_name("method")) in VERBS and _args(s):
                        a = _str(_args(s)[0])
                        if a:
                            p = base + ("/:id" if m == "member" and plural else "") + "/" + a
                            out.append((VERBS[_t(s.child_by_field_name("method"))], p, ctrl, a, s.start_point.row + 1))
            elif m in VERBS and _args(c) and _str(_args(c)[0]) and not _pairs(_args(c)).get("to"):
                a = _str(_args(c)[0])
                out.append((VERBS[m], base + ("/:id" if plural else "") + "/" + a, ctrl, a, c.start_point.row + 1))
            elif m in ("resources", "resource"):
                pass

    visit(nodes, "", "")
    return out


def _block_body(blk) -> list:
    if blk is None:
        return []
    body = blk.child_by_field_name("body") or next((c for c in blk.children if c.type in ("body_statement",
                                                                                          "block_body")), None)
    return [c for c in body.children if c.is_named] if body is not None else []


def _sinatra(nodes) -> list[tuple[str, str, object, int]]:
    out = []
    for c in nodes:
        if c.type == "call" and c.child_by_field_name("receiver") is None and \
                _t(c.child_by_field_name("method")) in ("get", "post", "put", "patch", "delete") and \
                c.child_by_field_name("block") is not None and _args(c) and _str(_args(c)[0]) is not None:
            out.append((_t(c.child_by_field_name("method")).upper(), _str(_args(c)[0]), c.child_by_field_name("block"),
                        c.start_point.row + 1))
    return out


# ------------------------------------------------------------------------------------------------ build

def add_ruby(g: Graph, repo: str | Path) -> dict:
    repo = Path(repo)
    paths = discover(repo)
    if not paths:
        return {}
    try:
        parser = _parser()
    except ImportError:
        g.meta.setdefault("skipped_languages", []).append("ruby (pip install tree-sitter-ruby)")
        return {}
    model = Model()
    model.left = (g, "ruby")
    files: list[tuple[RFile, object]] = []
    texts: dict[str, bytes] = {}
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
        f = RFile(rel=rel, lines=lines, is_test=bool(TEST_FILE_RE.search(rel)))
        deep.whole(model.left, f.rel, _collect, model, f, root)
        files.append((f, root))
        texts[rel] = src
    link = Linker(model)
    link.left = model.left
    link.texts = texts

    for f, _ in files:
        g.add_node(Node(id=f"rb:{f.rel}", kind=MODULE, name=Path(f.rel).name, qualname=f.rel, file=f.rel,
                        start_line=1, end_line=f.lines))
        if f.is_test:
            g.nodes[f"rb:{f.rel}"].entry = {"kind": "test", "detail": f.rel}
    for c in model.classes.values():
        parent = f"rb:{c.id.rsplit('.', 1)[0]}" if "." in c.id and c.id.rsplit(".", 1)[0] in model.classes \
            else f"rb:{c.file}"
        sup = f" < {c.superclass}" if c.superclass else ""
        g.add_node(Node(id=f"rb:{c.id}", kind=CLASS, name=c.short, qualname=c.id.replace(".", "::"), file=c.file,
                        start_line=c.start, end_line=c.end, parent=parent, signature=f"{c.kind} {c.short}{sup}"[:200]))
        g.add_edge(parent, f"rb:{c.id}", kind=CONTAINS)
    for mid, fn in model.funs.items():
        parent = f"rb:{fn.cls}" if fn.cls else f"rb:{fn.file}"
        g.add_node(Node(id=mid, kind=CALLABLE, name=fn.name, qualname=mid[3:], file=fn.file, start_line=fn.start,
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

    skip: dict[str, set] = {}
    for f, root in files:
        owners = [(f"rb:{f.rel}", f.top)] + [(f"rb:{c.id}", None) for c in model.classes.values() if c.file == f.rel]
        for owner, nodes in owners:
            if nodes is None:                                # Sinatra routes inside `class App < Sinatra::Base`
                c = model.classes[owner[3:]]
                if not (c.superclass or "").startswith("Sinatra"):
                    continue
                cnode = _find_class_node(root, c)
                body = cnode.child_by_field_name("body") if cnode is not None else None
                nodes = [x for x in (body.children if body is not None else []) if x.type == "call"]
                cls = c
            else:
                cls = None
            for verb, path, blk, line in _sinatra(nodes):
                detail = f"{verb} {path}"
                lid = f"rb:{f.rel}::{detail}"
                g.add_node(Node(id=lid, kind=CALLABLE, name=detail, qualname=f"{f.rel}::{detail}", file=f.rel,
                                start_line=line, end_line=blk.end_point.row + 1, parent=owner,
                                fingerprint=hashlib.sha1(blk.text, usedforsecurity=False).hexdigest()[:12],
                                signature=f"{verb.lower()} '{path}' do"))
                g.add_edge(owner, lid, kind=CONTAINS)
                g.nodes[lid].entry = {"kind": "route", "detail": detail}
                routes += 1
                env = {p: "" for p in _params(blk.child_by_field_name("parameters"))}
                add_refs(lid, link.walk(_block_body(blk), cls, env, lid, None, set(), f.rel))
                skip.setdefault(owner if owner.startswith(f"rb:{f.rel}") else f"rb:{f.rel}", set()).add(
                    blk.parent.id)

    for mid, fn in model.funs.items():
        cls = model.classes.get(fn.cls) if fn.cls else None
        body = fn.node.child_by_field_name("body")
        env = {p: "" for p in fn.params}
        add_refs(mid, link.walk([body] if body is not None else [], cls, env, mid, fn, set(), fn.file))
    for f, _ in files:
        if f.top:
            mid = f"rb:{f.rel}"
            add_refs(mid, link.walk(f.top, None, {}, mid, None, skip.get(mid, set()), f.rel))

    # Rails routes → controller actions
    route_files = [(f, root) for f, root in files if re.search(r"(^|/)config/routes(\.rb|/[^/]+\.rb)$", f.rel)]
    for f, root in route_files:
        for verb, path, ctrl, action, line in _rails_routes(f.top or [c for c in root.children if c.is_named]):
            cname = "".join(w.capitalize() for w in re.split(r"[_]", ctrl.split("/")[-1])) + "Controller"
            mods = [("".join(w.capitalize() for w in m.split("_"))) for m in ctrl.split("/")[:-1]]
            cid = ".".join(mods + [cname])
            hit = cid if cid in model.classes else model.find(cname, ".".join(mods) or None)
            target = model.fun_in(hit, action) if hit else None
            if not target or target not in g.nodes:
                continue
            path = re.sub(r"\(([^)]*)\)", r"\1", path)       # optional segments `(.:format)`
            g.nodes[target].entry = {"kind": "route", "detail": f"{verb} {path}"}
            routes += 1
            if _auth_filtered(model, hit, action):
                g.external("middleware.auth")
                g.add_edge(target, "ext:middleware.auth", kind=CALLS, confidence=RESOLVED, line=line, via="middleware")

    for mid, fn in model.funs.items():
        node = g.nodes[mid]
        if node.entry:
            continue
        f_is_test = bool(TEST_FILE_RE.search(fn.file))
        if f_is_test and fn.name.startswith("test_"):
            node.entry = {"kind": "test", "detail": fn.file}
        elif fn.name == "perform" and fn.cls:
            c = model.classes[fn.cls]
            anc = [model.classes[a] for a in model.ancestors(c.id)]
            if any(a.superclass in JOB_BASES for a in anc) or any(
                    re.search(r"Sidekiq::(Job|Worker)", m) for a in anc for m in a.mixins):
                node.entry = {"kind": "main", "detail": f"background job ({c.short})"}

    g.meta.setdefault("http_calls", []).extend(dict(h, file=model.funs[h["src"]].file if h["src"] in model.funs
                                                    else h["src"][3:].split("::")[0]) for h in link.http)
    for key, n in model.unresolved.items():
        g.unresolved[key[:120]] = g.unresolved.get(key[:120], 0) + n
    return {"files": len(files), "lines": total, "classes": len(model.classes), "functions": len(model.funs),
            "routes": routes, "http_calls": len(link.http), "unresolved": sum(model.unresolved.values())}


def _find_class_node(root, c: RClass):
    for x in _walk_all(root):
        if x.type == "class" and x.start_point.row + 1 == c.start:
            return x
    return None


def _auth_filtered(model: Model, cid: str, action: str) -> bool:
    """Does a `before_action` with an auth word cover this action (own class first, then ancestors), and no
    `skip_before_action` for it in a class nearer to the controller?"""
    skipped = set()
    for a in model.ancestors(cid):
        for kind, name, only, exc in model.classes[a].filters:
            covers = (not only or action in only) and action not in exc
            if not covers or not AUTH_FILTER.search(name):
                continue
            if kind == "skip":
                skipped.add(name)
            elif kind == "add" and name not in skipped:
                return True
    return False
