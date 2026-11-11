"""Follow the data (directive point 4, 2026-11-11): a value that arrives with a request is followed across functions
and files to the place where it does something sensitive: a database query, a command, a file, an outbound request,
a page, a redirect.

How it works, in the order the code below is written:

* Both readers (`flow_py`, `flow_js`) translate a file into one small language (`N`: names, calls, strings built
  from parts, assignments, branches, loops), so the engine is written once.
* A value (`Val`) carries where it came from (`Taint`: request data, or "parameter i of this function"), and for each
  kind of action whether it has been made safe for it. `html.escape` makes a value safe for a page and for nothing
  else; `int()` makes it safe for everything. Leading literal text is kept, so `"https://api.example.com/" + name`
  is known not to choose the host, and whether the text reads like SQL.
* A check narrows a value only in the branch that passed it, and an early exit makes the rest of the block that
  branch. A check after the action changes nothing. What a check proves comes from its code (`facts`): membership in
  a list the request did not write, a pattern that bounds the whole value, a resolved path that starts with the
  folder. A function is a validator for what its own body proves on every way out, whatever it is called.
* Every function gets a summary (`Summary`): which parameters reach its return value, which reach a sensitive action
  inside it or below it, and what it proves about them. Callers are analysed after callees (twice round a cycle), so
  a flow through five functions is five summaries applied in turn, each adding its steps.
* Who may reach what (`Az`, `Engine.authz`), three heuristics asked per route and only on a route that shows a
  login: a record reached by an id from the request (`record`, `reached`) where no condition on the route compares
  something of the record with who is signed in, or asks about a role; a path with `admin` in it that never asks
  for an admin; everything the request sent written onto a record (`assigned`). Who is signed in is a kind of value
  of its own (`Taint` kind `ident`), so "the owner is compared" is read from where the two meet, not from a name.
  A page that signs a person in looks them up by the name they typed before anybody is signed in
  (`sign_in_route`): that is not reported.

What it does not do is said in CLAUDE.md under Known gaps; the short form: values stored on objects, in globals that
functions write, in a database or a session are not followed; a library call with a followed value in it does not
pass the value on unless `flow_rules.PROPAGATORS` names it (counted in `stats["stopped"]`); who may reach what is
judged per route, and by names where the code of a check cannot be read."""

from __future__ import annotations

import os
import re as _re
import time
from pathlib import Path
from typing import NamedTuple

from . import flow_rules as R

MAX_STEPS = 14       # steps kept per value (the first ones and the sink; a longer way is cut in the middle)
MAX_TAINTS = 6       # origins kept per value
MAX_DEPTH = 3        # inline functions inside inline functions
MAX_PASSES = 4       # rounds over functions that call each other
# characters; a longer file is not read by the flow engine (the readers of the map still read it) and the tool's
# record then says `partial`. Set well above any file a person writes: a page of 630,000 characters (a report kept
# in the project) made every later run "incomplete" when this was 600,000.
MAX_FILE = 2_000_000
DOM_OK = {"xss", "redirect"}
URL_NEEDS = {"nohost", "nolocal"}
FIXED0: frozenset = frozenset()


# ------------------------------------------------------------------------------------------------ the small language
class N:
    """One node: an expression or a statement. `k` says which; the other fields mean what the reader put there."""
    __slots__ = ("k", "line", "col", "name", "a", "b", "c", "items", "kw")

    def __init__(self, k, line=0, col=0, name=None, a=None, b=None, c=None, items=None, kw=None):
        self.k, self.line, self.col, self.name = k, line, col, name
        self.a, self.b, self.c, self.items, self.kw = a, b, c, items, kw

    def __repr__(self):
        return f"N({self.k}@{self.line} {self.name or ''})"


class P:
    """A parameter: its name, its default (a node) and that default's text, its written type, a pattern for a
    destructured one."""
    __slots__ = ("name", "default", "text", "ann", "kind", "pattern")

    def __init__(self, name, default=None, text=None, ann=None, kind="pos", pattern=None):
        self.name, self.default, self.text, self.ann, self.kind, self.pattern = name, default, text, ann, kind, pattern


class Fn:
    __slots__ = ("name", "params", "body", "line", "first", "end", "decorators", "file", "lang", "cls", "mod", "node",
                 "key", "outer", "inline")

    def __init__(self, name, params, body, line, first=None, end=None, decorators=(), cls=None, inline=False,
                 outer=()):
        self.name, self.params, self.body, self.line = name, params, body, line
        self.first, self.end, self.decorators, self.cls = first or line, end or line, list(decorators), cls
        self.inline, self.outer = inline, set(outer)
        self.file = self.lang = self.mod = self.node = self.key = None


class Mod:
    __slots__ = ("file", "lang", "imports", "consts", "gwrites", "fns", "top", "names", "frameworks", "cvals",
                 "dotted", "bases", "fields")

    def __init__(self, file, lang):
        self.file, self.lang = file, lang
        self.imports: dict[str, str] = {}      # local name -> dotted origin (`requests`, `child_process.exec`, `.service`)
        self.consts: dict[str, list] = {}      # names assigned at the top of the file -> the expressions
        self.gwrites: dict[str, list] = {}     # names a function assigns through `global`
        self.fns: list[Fn] = []
        self.top: Fn | None = None             # the file's own top-level code, as one function
        self.names: dict[str, Fn | None] = {}  # functions and classes of the file by name
        self.frameworks: set[str] = set()
        self.cvals: dict[str, Val] = {}
        self.dotted = None
        self.bases: dict[str, list] = {}       # a class of the file -> its bases as written
        self.fields: dict[str, dict] = {}      # a class of the file -> its fields written with a type: name -> type


# ------------------------------------------------------------------------------------------------ values
class Taint(NamedTuple):
    kind: str            # "src" request data | "param" parameter i of the function being summarised | "ident" who is signed in
    key: object          # src: (file, line, words) | param: index | ident: name
    safe: frozenset      # the kinds of action this value has been made safe for (and marks such as "path:resolved")
    steps: tuple         # ((file, line, words), ...)
    origin: str | None   # "server" | "dom"
    drop: frozenset      # kinds whose earlier safety no longer holds (the name of an entry inside an uploaded archive)


class Dto(str):
    """The `data` of a request body that a class of the project describes: the word "dto", and with it where that
    class is written (`home`: the file's Mod and the class's name there), so a field read out of the body can be
    asked what the class says it is. Two bodies of different classes are not the same thing."""
    __slots__ = ("home",)

    def __new__(cls, home):
        self = super().__new__(cls, "dto")
        self.home = home
        return self

    def __eq__(self, other):
        if isinstance(other, Dto) and (self.home[0] is not other.home[0] or self.home[1] != other.home[1]):
            return False
        return str.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = str.__hash__


class Val:
    __slots__ = ("taints", "fixed", "sql", "html", "prefix", "kind", "data")

    def __init__(self, taints=(), fixed=None, sql=False, html=False, prefix=None, kind=None, data=None):
        self.taints = taints      # tuple[Taint]
        self.fixed = fixed        # None: not known to be fixed text | frozenset of parameter indices it is fixed under
        self.sql, self.html = sql, html
        self.prefix = prefix      # leading literal text, "" when the value starts with something else, None unknown
        self.kind, self.data = kind, data

    def but(self, **kw) -> "Val":
        v = Val(self.taints, self.fixed, self.sql, self.html, self.prefix, self.kind, self.data)
        for k, x in kw.items():
            setattr(v, k, x)
        return v

    def __repr__(self):
        return f"Val({[(t.kind, t.key if t.kind != 'src' else t.key[2][:20], sorted(t.safe)) for t in self.taints]}, " \
               f"fixed={self.fixed}, kind={self.kind}, data={str(self.data)[:40]!r}, prefix={self.prefix!r})"


UNKNOWN = Val()


def const(value) -> Val:
    if isinstance(value, str):
        return Val(fixed=FIXED0, sql=bool(R.SQL_WORDS.search(value)), html=bool(R.HTML_WORDS.search(value)),
                   prefix=value, kind="const", data=value)
    return Val(fixed=FIXED0, kind="const", data=value)


def norm(safe: frozenset, lang: str = "py") -> frozenset:
    """Two half-checks make a whole one: no `..` and not a full path (`os.path.join` and Node's `path.resolve` start
    again at a full path; text glued after fixed text and Node's `path.join` cannot, which is marked where the value
    is glued or joined); starts with one slash and not with two."""
    if "path" not in safe and "path:dots" in safe and "path:abs" in safe:
        safe = safe | {"path"}
    if "redirect" not in safe and "redirect:local" in safe and "redirect:noslash2" in safe:
        safe = safe | {"redirect"}
    return safe


def merge(a: tuple, b: tuple) -> tuple:
    if not b or a is b:
        return a
    if not a:
        return b
    out: dict = {}
    for t in a + b:
        k = (t.kind, t.key)
        o = out.get(k)
        if o is None:
            out[k] = t
        else:   # one origin by two ways: safe only for what both ways made it safe for
            keep = o if len(o.safe) <= len(t.safe) else t
            out[k] = keep._replace(safe=o.safe & t.safe, drop=o.drop | t.drop)
    ts = tuple(out.values())
    if len(ts) > MAX_TAINTS:
        ts = tuple(sorted(ts, key=lambda t: ({"src": 0, "param": 1}.get(t.kind, 2), R.ALL <= t.safe)))[:MAX_TAINTS]
    return ts


# ---- who is signed in, and the checks made on them (directive point 4: who may reach what)
def mark(kind: str, i=None) -> Taint:
    """A check a value stands for: "owner" (who is signed in was compared with something of a record) or "role"
    (what the signed-in person may do was asked). With `i`: the check holds if parameter `i` of the function being
    summarised is who is signed in. A mark counts once a condition is decided on the value that carries it."""
    return Taint("ident", ("=", kind, i), FIXED0, (), None, FIXED0)


def is_mark(t: Taint) -> bool:
    return t.kind == "ident" and isinstance(t.key, tuple)


def claim_mark(strong: bool, sense: bool, where: tuple) -> Taint:
    """A value that stands for the visitor's own word on what they may do (`req.cookies.admin === 'true'`), read at
    `where` (file, line, words). `strong`: sent along by the browser (a cookie, a header), counted wherever a
    condition is decided on it; otherwise written in the address or the body, counted only where the request is
    turned away without it. `sense`: the value is true when the visitor says so (false after a `not` or a `!=`)."""
    return Taint("ident", ("=", ("client", strong, sense, *where), None), FIXED0, (), None, FIXED0)


def is_claim(t: Taint) -> bool:
    return is_mark(t) and isinstance(t.key[1], tuple)


def turned(t: Taint) -> Taint:
    """The mark of `not x` for the mark of `x`: a claim changes its sense, any other check asks what it asked."""
    if not is_claim(t):
        return t
    _c, strong, sense, *where = t.key[1]
    return claim_mark(strong, not sense, tuple(where))


def claim_name(name: str) -> str:
    """A cookie's, header's or field's name as the claim tables read it: `X-Is-Admin`, `HTTP_X_IS_ADMIN` -> `Is_Admin`."""
    n = _re.sub(r"[-\s]+", "_", str(name).strip())
    return _re.sub(r"^(HTTP_)?(x_)?", "", n, flags=_re.I)


def says_not(d) -> bool:
    """Whether fixed text a claim is compared with says "not one": `'0'`, `'false'`, nothing."""
    return d is None or d is False or (isinstance(d, (int, float)) and not isinstance(d, bool) and d == 0) or \
        (isinstance(d, str) and d.strip().lower() in R.NOT_CLAIMED)


def refuses(stmts) -> bool:
    """Whether a branch turns the request away: it raises, or what it answers with or calls says so (401, 403,
    `abort`, a redirect, `next(err)`, the words "forbidden" or "denied")."""
    for s in (stmts or ())[:8]:
        if s.k == "raise":
            return True
        if s.k in ("expr", "return") and s.a is not None and _says_no(s.a):
            return True
    return False


def _says_no(e, depth: int = 0) -> bool:
    if not isinstance(e, N) or depth > 8:
        return False
    if e.k == "const":
        return (isinstance(e.a, (int, str)) and not isinstance(e.a, bool) and e.a in R.REFUSAL_CODES) or \
            (isinstance(e.a, str) and bool(R.REFUSAL.search(e.a)))
    if e.k == "call" and e.a is not None and e.a.k in ("name", "attr"):
        last = e.a.name or ""
        if R.REFUSAL_CALL.search(last) or (last == "next" and e.items):
            return True
    for x in (e.a, e.b, e.c, *(e.items or ()), *(e.kw.values() if isinstance(e.kw, dict) else ())):
        if isinstance(x, tuple):
            if any(_says_no(y, depth + 1) for y in x):
                return True
        elif _says_no(x, depth + 1):
            return True
    return False


def who(v: Val) -> tuple[bool, list]:
    """(whether `v` says who is signed in, the parameters of the function being summarised it may have come from)."""
    return (any(t.kind == "ident" and not isinstance(t.key, tuple) for t in v.taints),
            [t.key for t in v.taints if t.kind == "param"])


def marks_for(v: Val, kinds) -> tuple:
    known, params = who(v)
    return tuple(mark(k) for k in kinds if known) + tuple(mark(k, i) for i in params for k in kinds)


def roled(v: Val, name) -> tuple:
    """The marks for reading `name` off `v`: a role asked of who is signed in (`user.is_admin`, `session["role"]`)."""
    if not v.taints or not isinstance(name, str) or not R.ROLE_WORD.search(name):
        return ()
    return marks_for(v, ("role",))


def whole(v: Val | None, depth: int = 0) -> bool:
    """Whether `v` is everything the request's body sent, or an object made of all of it (`{...req.body}`,
    `{"$set": request.json}`)."""
    if v is None or depth > 3:
        return False
    if v.kind == "bag":
        return v.data in R.BODY_BAGS and any(t.kind == "src" for t in v.taints)
    if v.kind == "obj":
        return any(whole(x, depth + 1) for k, x in v.data.items() if k in R.WHOLE_KEYS)
    return False


def named(words: str) -> str:
    """The name a request value goes by, from the words of its origin: `order_id`, the `id` of `req.params.id`."""
    m = _re.match(r"`([^`]+)`", words or "")
    parts = _re.findall(r"[A-Za-z_$][\w$]*", m.group(1)) if m else []
    return parts[-1] if parts else ""


def sign_in_route(detail: str) -> str | None:
    """"end" when a route's path ends in a word that says it signs a person in (`POST /auth/login`), "near" when only
    parameters follow that word (`/password-recovery/{email}`), None for every other route."""
    path = (detail.partition(" ")[2] or detail).split("?")[0].split("#")[0]
    for i, seg in enumerate(reversed([s for s in path.split("/") if s])):
        if R.PATH_PARAM.match(seg):
            continue
        if R.SIGN_IN_WORD.search(seg):
            return "near" if i else "end"
        break
    return None


def with_step(t: Taint, step: tuple) -> Taint:
    if t.kind == "ident" or step in t.steps or len(t.steps) >= MAX_STEPS:
        return t
    return t._replace(steps=t.steps + (step,))


def stepped(v: Val, step: tuple) -> Val:
    return v.but(taints=tuple(with_step(t, step) for t in v.taints)) if v.taints else v


# ---- the address a request was made to (`flow_rules.OWN_MARKS`)
def safe_for(cls: str, safe: frozenset) -> bool:
    """Whether a value with these marks is safe for an action of kind `cls`: made safe for it, or, for a redirect,
    the address the request itself was made to."""
    return cls in safe or (cls == "redirect" and "redirect:own" in safe)


def disowned(taints: tuple) -> tuple:
    """The same origins, no longer taken as the address the request was made to: a part was read out of it, or it
    went through something that may give back another text. A parameter may be handed that address, so the loss is
    written on it for the caller (`drop`)."""
    if not any(t.kind == "param" or t.safe & R.OWN_MARKS for t in taints):
        return taints
    return tuple(t._replace(safe=t.safe - R.OWN_MARKS, drop=t.drop | R.OWN_MARKS)
                 if t.kind == "param" or t.safe & R.OWN_MARKS else t for t in taints)


def disown(v: Val) -> Val:
    ts = disowned(v.taints)
    if ts is v.taints:
        return v
    return v.but(taints=ts, prefix=None if isinstance(v.prefix, str) and v.prefix.startswith(R.OWN) else v.prefix)


def owned(v: Val | None) -> bool:
    """Whether `v` is the address the request was made to: every outside origin of it is."""
    ts = [t for t in v.taints if t.kind != "ident"] if v is not None else []
    return bool(ts) and all("redirect:own" in t.safe for t in ts)


def join(a: Val | None, b: Val | None) -> Val:
    if a is None:
        return b if b is not None else UNKNOWN
    if b is None or a is b:
        return a
    kind = data = None
    if a.kind == b.kind:
        if a.kind == "const" and a.data == b.data and type(a.data) is type(b.data):
            return a
        if a.kind == "obj":
            kind, data = "obj", {k: join(a.data.get(k), b.data.get(k)) for k in set(a.data) | set(b.data)}
        elif a.kind == "seq":
            kind, data = "seq", (a.data + [x for x in b.data if x not in a.data])[:24]
        elif a.kind in ("ext", "req", "bag", "upload", "self", "regex", "ref") and a.data == b.data:
            kind, data = a.kind, a.data
        elif a.kind == "fn":
            kind, data = "fn", a.data
    elif a.kind in ("req", "upload", "bag", "ext") and b.kind in (None, "const") and not b.taints:
        kind, data = a.kind, a.data          # `x = request.files.get("f") or None`
    elif b.kind in ("req", "upload", "bag", "ext") and a.kind in (None, "const") and not a.taints:
        kind, data = b.kind, b.data
    prefix = os.path.commonprefix([a.prefix, b.prefix]) if isinstance(a.prefix, str) and isinstance(b.prefix, str) \
        else None
    return Val(merge(a.taints, b.taints), None if a.fixed is None or b.fixed is None else a.fixed | b.fixed,
               a.sql or b.sql, a.html or b.html, prefix, kind, data)


def join_all(vals) -> Val:
    out = None
    for v in vals:
        if v is not None:
            out = join(out, v)
    return out if out is not None else UNKNOWN


def concat(parts: list, glue: bool = False) -> Val:
    """Text built from parts: the origins of every part, text that is fixed when every part is, the literal start.
    `glue`: the parts stand in the text in this order, so a part that follows text nobody outside chose (written
    text, or a value with no outside origin: a folder) cannot be a full path on its own."""
    if parts and parts[0].kind == "seq":      # a list plus a list
        data = list(parts[0].data)
        for p in parts[1:]:
            data += p.data if p.kind == "seq" else [p]
        return seq(data)
    taints: tuple = ()
    fixed: frozenset | None = FIXED0
    text, prefix, open_, all_const = [], "", True, True
    sql = html = False
    solid = False
    for p in parts:
        mine = p.taints
        if glue and mine and solid:
            mine = tuple(t if t.kind == "ident" else t._replace(safe=norm(t.safe | {"path:abs"})) for t in mine)
        elif not mine and (p.kind != "const" or (isinstance(p.data, str) and p.data)):
            solid = True
        taints = merge(taints, mine)
        fixed = None if fixed is None or p.fixed is None else fixed | p.fixed
        sql, html = sql or p.sql, html or p.html
        if p.kind == "const" and isinstance(p.data, (str, int, float)) and not isinstance(p.data, bool):
            s = str(p.data)
            text.append(s)
            if open_:
                prefix += s
        else:
            all_const = False
            text.append("\x00")
            if open_ and not prefix and p.prefix == R.OWN_EXACT:
                prefix = R.OWN          # this site's own origin and nothing else: the text after it goes on
            elif open_:
                prefix += p.prefix if isinstance(p.prefix, str) and p.prefix != R.OWN_EXACT else ""
                open_ = False
    if all_const:
        return const("".join(text))
    skeleton = "".join(text)[:3000]
    taints = tuple(t if t.kind == "ident" else t._replace(safe=t.safe | {"nosql"}) for t in taints)
    return Val(taints, fixed, sql or bool(R.SQL_WORDS.search(skeleton)), html or bool(R.HTML_WORDS.search(skeleton)),
               prefix)


def seq(items: list) -> Val:
    fixed: frozenset | None = FIXED0
    taints: tuple = ()
    for v in items:
        taints = merge(taints, v.taints)
        fixed = None if fixed is None or v.fixed is None else fixed | v.fixed
    return Val(taints, fixed, any(v.sql for v in items), any(v.html for v in items), kind="seq", data=list(items)[:24])


def narrow(v: Val, classes: frozenset, fixed: bool = False, lang: str = "py") -> Val:
    if not v.taints and not fixed:
        return v
    ts = tuple(t if t.kind == "ident" else t._replace(safe=norm(t.safe | classes, lang)) for t in v.taints)
    return v.but(taints=ts, fixed=FIXED0 if fixed else v.fixed)


def elem(v: Val) -> Val:
    """One item of a collection: what a loop variable or a callback's parameter holds."""
    if v.kind == "seq" and v.data:
        return join_all(v.data)
    if v.kind == "obj" and v.data:
        return join_all(v.data.values())
    if v.kind in ("upload", "req", "bag"):
        return v
    return Val(v.taints, v.fixed, v.sql, v.html) if (v.taints or v.fixed is not None) else UNKNOWN


def stringy(v: Val) -> bool:
    return v.kind not in ("bag", "obj", "seq", "upload", "req", "fn", "self")


def text_of(e: N | None, depth: int = 0) -> str:
    """Code as a person would write it, short: `request.args.q`, `cur.execute`."""
    if e is None or depth > 6:
        return "…"
    k = e.k
    if k == "name":
        return e.name
    if k == "attr":
        return f"{text_of(e.a, depth + 1)}.{e.name}"
    if k == "index":
        key = e.b
        if key is not None and key.k == "const" and isinstance(key.a, (str, int)):
            return f"{text_of(e.a, depth + 1)}[{key.a!r}]"
        return f"{text_of(e.a, depth + 1)}[…]"
    if k == "call":
        return f"{text_of(e.a, depth + 1)}()"
    if k == "const":
        return repr(e.a)[:30]
    return "…"


def path_of(e: N | None, depth: int = 0) -> str | None:
    """The name a check is about: `x`, `request.args.sort` (also written `request.args["sort"]` or `.get("sort")`)."""
    if e is None or depth > 6:
        return None
    k = e.k
    if k == "name":
        return e.name
    if k == "attr":
        base = path_of(e.a, depth + 1)
        return f"{base}.{e.name}" if base else None
    if k == "index":
        base = path_of(e.a, depth + 1)
        if base and e.b is not None and e.b.k == "const" and isinstance(e.b.a, (str, int)):
            return f"{base}.{e.b.a}"
        return None
    if k == "call" and e.a is not None and e.a.k == "attr":
        if e.a.name in ("get", "getlist", "getall", "get_all", "param", "header") and e.items and \
                e.items[0].k == "const" and isinstance(e.items[0].a, str):
            base = path_of(e.a.a, depth + 1)
            return f"{base}.{e.items[0].a}" if base else None
        if e.a.name in R.KEEP_SUBJECT:
            return path_of(e.a.a, depth + 1)
    if k == "call" and e.a is not None and e.a.k == "name" and e.a.name in ("str", "String") and e.items:
        return path_of(e.items[0], depth + 1)
    return None


def said(e: N, key) -> str:
    """Words for one value read out of what the request sent: the field's name first, then where it was read."""
    base = e.a.a if e.k == "call" and e.a is not None and e.a.k == "attr" else e.a if e.k in ("index", "attr") else None
    if isinstance(key, str) and key and base is not None:
        return f"`{key}` in `{text_of(base)[:60]}` is what the request sent"
    return f"`{text_of(e)[:70]}` is what the request sent"


# ------------------------------------------------------------------------------------------------ one function's state
class Env:
    __slots__ = ("vars", "narrow", "derived", "orig", "proved", "flags", "fn")

    def __init__(self, fn: Fn):
        self.fn = fn
        self.vars: dict[str, Val] = {}
        self.narrow: dict[str, frozenset] = {}     # `request.args.sort` -> what a check proved about it
        self.derived: dict[str, tuple] = {}        # host = urlparse(url).hostname  ->  ("host", "url")
        self.orig: dict[str, int] = {}             # names that still hold a parameter's own value
        self.proved: dict[int, frozenset] = {}     # what checks proved about the parameters so far
        self.flags: dict[str, tuple] = {}          # ok = host in HOSTS  ->  what is known when `ok` holds, and when not

    def copy(self, fn: Fn | None = None) -> "Env":
        e = Env(fn or self.fn)
        e.vars, e.narrow, e.derived = dict(self.vars), dict(self.narrow), dict(self.derived)
        e.orig, e.proved, e.flags = dict(self.orig), dict(self.proved), dict(self.flags)
        return e

    def take(self, o: "Env") -> None:
        self.vars, self.narrow, self.derived, self.orig, self.proved = o.vars, o.narrow, o.derived, o.orig, o.proved
        self.flags = o.flags

    def join(self, o: "Env") -> None:
        for k in set(self.vars) | set(o.vars):
            a, b = self.vars.get(k), o.vars.get(k)
            self.vars[k] = join(a if a is not None else UNKNOWN, b if b is not None else UNKNOWN)
        self.narrow = {p: c & o.narrow[p] for p, c in self.narrow.items() if p in o.narrow}
        self.derived = {k: v for k, v in self.derived.items() if o.derived.get(k) == v}
        self.orig = {k: v for k, v in self.orig.items() if o.orig.get(k) == v}
        self.proved = {i: c & o.proved.get(i, FIXED0) for i, c in self.proved.items()}
        self.flags = {k: v for k, v in self.flags.items() if o.flags.get(k) == v}

    def forget(self, name: str) -> None:
        self.orig.pop(name, None)
        self.derived.pop(name, None)
        if self.flags:      # an answer kept in a variable says nothing once the variable, or what it was about, changed
            self.flags.pop(name, None)
            for k in [k for k, (yes, no) in self.flags.items()
                      if any(p == name or p.startswith(name + ".") for p, _c, _f, _r in yes + no)]:
                del self.flags[k]
        # a check of `host = urlparse(url).hostname` says nothing about a `url` that was given another value since
        for k in [k for k, d in self.derived.items() if d[1] == name or d[1].startswith(name + ".")]:
            del self.derived[k]
        if self.narrow:
            for p in [p for p in self.narrow if p == name or p.startswith(name + ".")]:
                del self.narrow[p]


class SinkRec(NamedTuple):
    param: int
    cls: str
    safe: frozenset
    drop: frozenset
    steps: tuple
    file: str
    line: int
    what: str
    conf: str
    needs: frozenset
    node: str | None


class Az:
    """What one route, or one function for its summary, shows about who may reach what."""
    __slots__ = ("ev", "pev", "records")

    def __init__(self):
        self.ev: set = set()           # "owner" / "role": checks that were made on who is signed in
        self.pev: dict = {}            # parameter index -> the checks made on it, should it be who is signed in
        self.records: dict = {}        # (file, line, origin) -> a record reached by a request value


def asked_of(az: Az) -> frozenset:
    """(parameter, check) for every check made so far on a parameter, should it be who is signed in."""
    return frozenset((i, k) for i, ks in az.pev.items() for k in ks if isinstance(k, str))


def had_marks(az: Az) -> frozenset:
    """The same and the checks made on the function's own account, as words a noted action carries (`SinkRec.needs`)."""
    return frozenset(f"had:{k}" for k in az.ev if isinstance(k, str)) | \
        frozenset(f"hadp:{i}:{k}" for i, k in asked_of(az))


class Summary:
    __slots__ = ("ret", "sinks", "guards", "pred_t", "pred_f", "ev", "pev", "records", "fields")

    def __init__(self):
        self.ret: Val | None = None
        self.fields: dict[str, Val] = {}       # a constructor: what it keeps on the object, field by field
        self.sinks: list[SinkRec] = []
        self.guards: dict[int, frozenset] = {}
        self.pred_t: dict[int, frozenset] = {}
        self.pred_f: dict[int, frozenset] = {}
        self.ev: frozenset = FIXED0
        self.pev: dict[int, frozenset] = {}
        self.records: dict = {}

    def sig(self):
        r = self.ret
        rs = None if r is None else (frozenset((t.kind, t.key, t.safe, t.drop) for t in r.taints), r.fixed, r.sql,
                                     r.kind, r.data if r.kind in ("ext", "req", "bag", "upload") else None,
                                     bool(r.prefix))
        return (rs, frozenset((s.param, s.cls, s.file, s.line, s.safe, s.needs) for s in self.sinks),
                tuple(sorted(self.guards.items())), tuple(sorted(self.pred_t.items())),
                tuple(sorted(self.pred_f.items())), self.ev, tuple(sorted(self.pev.items())),
                frozenset((k, r["unless"], r["had"], r["hadp"]) for k, r in self.records.items()),
                tuple(sorted((k, frozenset((t.kind, t.key, t.safe, t.drop) for t in v.taints), v.fixed, v.sql,
                              v.kind == "const") for k, v in self.fields.items())))


class Ctx:
    """What the analysis of one function collects. An inline function shares its outer function's findings."""

    def __init__(self, fn: Fn, parent: "Ctx | None" = None):
        self.fn = fn
        self.top = parent.top if parent else self
        self.depth = parent.depth + 1 if parent else 0
        self.rets: list[Val] = []
        self.exits: list[tuple] = []     # (proved, truth, facts if true, facts if false)
        self.az: Az = parent.az if parent else Az()      # a route written inline gets one of its own (`closure`)
        if parent is None:
            self.flows: dict = {}
            self.sinks: dict = {}
            self.calls: list = []        # (callee key, {param index: Val}, line)
            self.fields: dict = {}       # `self.x = value` / `this.x = value` in the function's own lines
            self.points: dict = {}       # (file, line) -> [(class, Val)] for "only fixed text reaches this line"

    def flow(self, cls, t: Taint, steps, conf, what, file, line, node, unless=FIXED0, change=False, had=None,
             hadp=None) -> None:
        top = self.top
        key = (cls, file, line, t.key)
        f = {"class": cls, "file": file, "line": line, "sink": what, "confidence": conf, "node": node,
             "source": {"file": t.key[0], "line": t.key[1], "what": t.key[2]},
             "steps": [{"file": a, "line": b, "what": c} for a, b, c in steps]}
        if cls == "record":
            # no finding by itself: the route it is reached from decides, with every check it makes (`Engine.authz`).
            # `unless`: parameters that make the record the caller's own if they are who is signed in; `had`: the
            # checks made before this line, which is what counts for a record that is changed or removed (`hadp`:
            # those made on a parameter, should it be who is signed in). A record inside a called function comes
            # with both as they stood there (`Engine.use`).
            f.update(unless=frozenset(unless), change=change,
                     had=frozenset(self.az.ev) if had is None else had,
                     hadp=asked_of(self.az) if hadp is None else hadp)
            old = self.az.records.get(key)
            if old is None or len(f["steps"]) < len(old["steps"]):
                self.az.records[key] = f
            return
        old = top.flows.get(key)
        if old is None or len(f["steps"]) < len(old["steps"]):
            top.flows[key] = f

    def sink(self, rec: SinkRec) -> None:
        top = self.top
        key = (rec.param, rec.cls, rec.file, rec.line)
        old = top.sinks.get(key)
        if old is None:
            top.sinks[key] = rec
        else:
            top.sinks[key] = old._replace(safe=old.safe & rec.safe, needs=old.needs & rec.needs,
                                          drop=old.drop | rec.drop)


class Result:
    def __init__(self, flows, stats, errors, engine, authz=()):
        self.flows, self.stats, self.errors, self.engine = flows, stats, errors, engine
        self.authz = list(authz)       # per route: records reached with no owner compared, an admin route unasked

    def fixed_only(self, file: str, line: int, cls: str):
        return self.engine.fixed_only(file, line, cls)


# ------------------------------------------------------------------------------------------------ the engine
class Engine:
    def __init__(self, g):
        self.g = g
        self.repo = Path(g.repo_root)
        self.sites: dict = {}
        self.doubt: set[str] = set()       # names of calls Lantern could not link to one function
        self.handed: set[str] = set()      # functions given to code that calls them
        for s in getattr(g, "sites", None) or []:
            if s["group"] == "written":
                self.sites[(s["file"], s["line"], s["col"])] = s
                if s["outcome"] in ("unresolved", "name-only", "possible"):
                    self.doubt.add(s["callee"].rsplit(".", 1)[-1].rstrip("()"))
            else:
                self.handed.update(s["to"])
        self.node_at: dict = {}
        self.module_at: dict = {}
        for n in g.nodes.values():
            if n.file and n.kind == "callable" and n.start_line:
                self.node_at.setdefault((n.file, n.start_line), []).append(n.id)
            elif n.file and n.kind == "module":
                self.module_at[n.file] = n.id
        self.mods: dict[str, Mod] = {}
        self.units: list[Fn] = []
        self.by_node: dict[str, Fn] = {}
        self.by_key: dict = {}
        self.summ: dict = {}
        self.flows: dict = {}
        self.calls: dict = {}
        self.points: dict = {}
        self.escaped: set = set()
        self.attrs: dict = {}              # (file, class, attribute) -> what `self.attribute` was given
        self.plain_calls: set = set()      # calls that make an answer whose kind is then set to something not a page
        self._pages: dict | None = None    # template file -> the places in it that print a value without escaping
        self.handed_pages: dict = {}       # (template, line) -> {(file, line, name): "safe" | "open"}: what each
        #                                    place that shows the page hands a raw place of it
        self.routes: dict = {}             # route function key -> (Fn, Az)
        self.before: dict = {}             # route function key -> {dependency name: its function's key or None}
        self.sent: dict = {}               # a request value's key (file, line, words) -> (its name, the part it is in)
        self.wide: dict = {}               # file -> [(name, key)]: what runs before every route of a router there
        self.py_mods: dict[str, Mod] = {}
        self.errors: list[str] = []
        self.stats = {"files": 0, "functions": 0, "skipped_files": 0, "stopped": 0, "passes": 0}
        self._fixed_memo: dict = {}

    # ---- loading
    def load(self) -> None:
        from . import flow_py
        from .python_frontend import TEST_FILE_RE, discover, project_text
        root = self.repo.resolve()
        for p, dotted in discover(self.repo):
            rel = p.relative_to(root).as_posix()
            if TEST_FILE_RE.search(rel):
                continue
            try:
                text = project_text(p, self.repo)
            except (OSError, UnicodeError):
                continue
            mod = flow_py.build(rel, text) if len(text) <= MAX_FILE else None
            if mod is None:
                self.stats["skipped_files"] += 1
                continue
            mod.dotted = dotted
            self.add(mod)
        try:
            from . import flow_js
        except ImportError:      # the JavaScript reader comes in its own step
            flow_js = None
        if flow_js is not None:
            for mod in flow_js.build_all(self.repo, MAX_FILE, self.stats):
                self.add(mod)

    def add(self, mod: Mod) -> None:
        self.mods[mod.file] = mod
        if mod.dotted:
            self.py_mods[mod.dotted] = mod
        self.stats["files"] += 1
        for fn in mod.fns + [mod.top]:
            fn.mod, fn.file, fn.lang = mod, mod.file, mod.lang
            self._inner(fn.body, mod)
            fn.key = (mod.file, fn.first, fn.name)
            fn.node = self.module_at.get(mod.file) if fn is mod.top else self.node_for(mod.file, fn)
            self.units.append(fn)
            self.by_key[fn.key] = fn
            if fn.node and fn is not mod.top:
                self.by_node.setdefault(fn.node, fn)
        self.stats["functions"] += len(mod.fns)

    def node_for(self, file: str, fn: Fn) -> str | None:
        """The map's function that starts where this one does; of several on one line, the one with its name."""
        for line in (fn.first, fn.line):
            ids = self.node_at.get((file, line))
            if ids:
                return next((i for i in ids if _re.split(r"[.:]", i)[-1] == fn.name), ids[0])
        return None

    def shown(self, fn: Fn, top: Fn) -> str:
        """The name a person knows the code a call stands in by."""
        for f in (fn, top):
            n = self.g.nodes.get(f.node) if f.node else None
            if n is not None and n.kind == "callable":
                return n.name
            if not f.name.startswith("<"):
                return f.name
        return "the top of the file"

    def _inner(self, body, mod: Mod, depth: int = 0) -> None:
        """Inline functions take their file from the function they are written in."""
        stack = list(body or [])
        while stack:
            x = stack.pop()
            if isinstance(x, N):
                if x.k in ("fn", "def") and isinstance(x.a, Fn):
                    f = x.a
                    f.mod, f.file, f.lang = mod, mod.file, mod.lang
                    f.key = (mod.file, f.first, f.name)
                    f.node = self.node_for(mod.file, f)
                    for p in f.params:
                        if p.default is not None:
                            stack.append(p.default)
                    stack.extend(f.body or [])
                    continue
                for v in (x.a, x.b, x.c):
                    if isinstance(v, (N, list, tuple)):
                        stack.append(v)
                if x.items:
                    stack.extend(x.items)
                if x.kw:
                    stack.extend(x.kw.values())
            elif isinstance(x, (list, tuple)):
                stack.extend(x)

    # ---- order: callees before callers
    def order(self) -> tuple[list[Fn], dict]:
        adj: dict[str, set] = {}
        for s in self.sites.values():
            for t in s["to"]:
                t2 = t if t in self.by_node else (t + ".__init__" if t + ".__init__" in self.by_node else None)
                if t2:
                    adj.setdefault(s["caller"], set()).add(t2)
        out: list[Fn] = []
        seen: set = set()
        for u in self.units:
            if u.node is None or u.node in seen:
                continue
            stack = [(u.node, iter(sorted(adj.get(u.node, ()))))]
            seen.add(u.node)
            while stack:
                nid, it = stack[-1]
                nxt = next((t for t in it if t not in seen), None)
                if nxt is None:
                    stack.pop()
                    f = self.by_node.get(nid) or next((x for x in self.units if x.node == nid), None)
                    if f is not None:
                        out.append(f)
                else:
                    seen.add(nxt)
                    stack.append((nxt, iter(sorted(adj.get(nxt, ())))))
        done = {id(f) for f in out}
        out += [u for u in self.units if id(u) not in done]
        callers: dict = {}
        for src, dsts in adj.items():
            for d in dsts:
                callers.setdefault(d, set()).add(src)
        return out, callers

    def run(self, budget: float = 300.0) -> None:
        order, callers = self.order()
        pos = {f.key: i for i, f in enumerate(order)}
        by_node_all: dict = {}
        for f in order:
            if f.node:
                by_node_all.setdefault(f.node, []).append(f)
        dirty = {f.key for f in order}
        start = time.monotonic()
        for n in range(MAX_PASSES):
            self.stats["passes"] = n + 1
            nxt: set = set()
            for f in order:
                if f.key not in dirty:
                    continue
                dirty.discard(f.key)
                old = self.summ[f.key].sig() if f.key in self.summ else None
                try:
                    self.unit(f)
                except RecursionError:
                    self.errors.append(f"{f.file}:{f.line} {f.name}: nested too deep")
                    continue
                except Exception as ex:   # noqa: BLE001  one function the engine cannot read must not end the analysis
                    self.errors.append(f"{f.file}:{f.line} {f.name}: {type(ex).__name__}: {ex}")
                    continue
                if self.summ[f.key].sig() != old and f.node:
                    for c in callers.get(f.node, ()):
                        for cf in by_node_all.get(c, ()):
                            (dirty if pos[cf.key] > pos[f.key] else nxt).add(cf.key)
                if time.monotonic() - start > budget:
                    self.stats["stopped_early"] = True
                    return
            dirty = nxt
            if not dirty:
                break

    def result(self) -> Result:
        flows: dict = {}
        for fl in self.flows.values():
            for key, f in fl.items():
                old = flows.get(key)
                if old is None or len(f["steps"]) < len(old["steps"]):
                    flows[key] = f
        out = sorted(flows.values(), key=lambda f: (f["file"], f["line"], f["class"], f["source"]["file"],
                                                    f["source"]["line"]))
        self.stats["flows"] = len(out)
        return Result(out, self.stats, self.errors, self, self.authz())

    # ---- one function
    def unit(self, fn: Fn) -> None:
        ctx = Ctx(fn)
        env = Env(fn)
        for i, p in enumerate(fn.params):
            self.bind_param(env, fn, i, p, None, ctx, True)
        if not self.block(fn.body, env, ctx):
            self.leave(ctx, env, None, None)
        s = Summary()
        s.ret = join_all(ctx.rets) if ctx.rets else None
        s.sinks = list(ctx.sinks.values())
        idx = range(len(fn.params))
        if ctx.exits:
            for i in idx:
                g = None
                t = f = None
                for proved, truth, pt, pf in ctx.exits:
                    have = proved.get(i, FIXED0)
                    g = have if g is None else g & have
                    if truth is not False:
                        x = have | pt.get(i, FIXED0)
                        t = x if t is None else t & x
                    if truth is not True:
                        x = have | pf.get(i, FIXED0)
                        f = x if f is None else f & x
                if g:
                    s.guards[i] = g
                if t:
                    s.pred_t[i] = t
                if f:
                    s.pred_f[i] = f
        s.ev, s.pev = frozenset(ctx.az.ev), {i: frozenset(k) for i, k in ctx.az.pev.items()}
        s.records = dict(ctx.az.records)
        s.fields = dict(ctx.fields)
        self.summ[fn.key] = s
        self.flows[fn.key], self.calls[fn.key], self.points[fn.key] = ctx.flows, ctx.calls, ctx.points
        if self.is_route(fn):
            self.routes[fn.key] = (fn, ctx.az)

    def leave(self, ctx: Ctx, env: Env, node: N | None, val: Val | None) -> None:
        """A way out of the function with a value: what it returns, and what had been proved by then."""
        ctx.rets.append(val if val is not None else const(None))
        truth = None
        pt: dict = {}
        pf: dict = {}
        if node is None or (node.k == "const"):
            truth = bool(node.a) if node is not None else False
        else:
            t, f = self.facts(node, env, ctx)
            pt, pf = self.by_param(t, env), self.by_param(f, env)
        ctx.exits.append((dict(env.proved), truth, pt, pf))

    @staticmethod
    def by_param(facts, env: Env) -> dict:
        out: dict = {}
        for path, classes, _fixed, rel in facts:
            for p, c in chain(path, classes, rel, env):
                i = env.orig.get(p)
                if i is not None:
                    out[i] = out.get(i, FIXED0) | c
        return out

    # ---- parameters: which ones are request data
    def entry(self, fn: Fn):
        n = self.g.nodes.get(fn.node) if fn.node else None
        return n.entry if n is not None else None

    def is_route(self, fn: Fn) -> bool:
        e = self.entry(fn)
        if e and e.get("kind") == "route":
            return True
        return any(R_ROUTE.search(d) for d in fn.decorators)

    def route_path(self, fn: Fn) -> str:
        e = self.entry(fn)
        text = (e or {}).get("detail") or ""
        return text + " " + " ".join(fn.decorators)

    def source(self, fn: Fn, line: int, words: str, safe=FIXED0, origin="server") -> Taint:
        return Taint("src", (fn.file, line, words), frozenset(safe), ((fn.file, line, words),), origin, FIXED0)

    def param_val(self, fn: Fn, i: int, p: P, summary: bool) -> Val:
        base = Val((Taint("param", i, FIXED0, (), None, FIXED0),), frozenset({i})) if summary else UNKNOWN
        name, ann = p.name, p.ann or ""
        py = fn.lang == "py"
        if py and i == 0 and fn.cls and name in ("self", "cls"):
            return Val(kind="self", data=fn.cls)
        # a body described by a class of the project is that, also under the name `req` or `request`
        body = py and bool(ann) and self.body_class(fn.mod, ann)
        if not body and (name in R.REQUEST_NAMES or (ann and R.REQUEST_TYPES.search(ann)) or
                         (not py and name == "ctx" and len(fn.params) <= 2)):
            return Val(kind="req", data=fn.lang)
        if (ann and R.UPLOAD_TYPES.search(ann)) or (p.text and re_match(r"^(File|UploadFile)\(", p.text)):
            t = self.source(fn, fn.line, f"`{name}` is a file the request uploaded", {"nosql"})
            return Val((t,), kind="upload", data=name)
        m = R.PARAM_DECORATOR.match(p.text) if (not py and p.text) else None
        if m:       # NestJS: the decorator on the parameter says which part of the request it is
            part, inside = m.group(1), m.group(2)
            if part in ("Req", "Request"):
                return Val(kind="req", data="js")
            if R.PARSE_PIPE.search(inside):       # a pipe that turns it into a number, or refuses the request
                words = f"`{name}` arrives with the request (`{p.text[:50]}` on `{fn.name}`)"
                return join(base, Val((self.source(fn, fn.line, words, R.ALL),)))
            if part.startswith("Uploaded"):
                t = self.source(fn, fn.line, f"`{name}` is a file the request uploaded", {"nosql"})
                return Val((t,), kind="upload", data=name)
            words = f"`{name}` arrives with the request (`{p.text[:50]}` on `{fn.name}`)"
            t = self.source(fn, fn.line, words, {"nosql"} if part in ("Param", "Headers") else ())
            keyed = bool(re_match(r"""\s*['"`]""", inside))
            # a body with a written class is that class's fields, not "everything that was sent"
            typed = part == "Body" and ann and not re_match(r"^(any|unknown|object|Object|Record<|Partial<|\{)", ann)
            return Val((t,), kind=None if keyed else "bag", data=None if keyed else "dto" if typed else part.lower())
        route = self.is_route(fn)
        inj = p.text if p.text and R.INJECTED.match(p.text) else ann if "Depends(" in ann else None
        if inj:      # FastAPI hands this one in: what the dependency returns
            dep = self.dependency(fn, inj)
            if route:
                return dep if dep is not None else UNKNOWN
            # a dependency of a dependency: called by hand it holds what it is given; handed in, who is signed in
            whose = tuple(t for t in dep.taints if t.kind == "ident" and not is_mark(t)) if dep is not None else ()
            return base.but(taints=merge(base.taints, whose)) if whose else base
        home = self.class_home(fn.mod, self.class_name(ann)) if body else None
        if not route:
            # a helper that says it takes such a body: its fields are read by what the class says they are
            return base.but(kind="bag", data=Dto(home)) if home else base
        if ann and R.ANN_IDENT.match(ann):
            return Val((Taint("ident", ann, R.ALL, (), None, FIXED0),))
        number = bool(ann and R.SAFE_TYPES.match(ann))
        if ann and not number and R.NOT_INPUT_TYPES.search(ann):
            return base
        where = self.route_path(fn)
        fw = fn.mod.frameworks
        if py:
            if p.kind not in ("pos", "kw") or name.startswith("_"):
                return base
            in_path = re_search(r"[{<](?:\w+:)?" + name + r"(?::\w+)?[}>]", where)
            number = number or bool(re_search(r"<(int|float|uuid):" + name + ">", where))
            if "django" in fw and not in_path:
                return base      # how the address pattern hands this one in is not known: not counted as input
            if not ({"fastapi", "flask", "django"} & fw) and not in_path:
                return base
            if body and not in_path:
                # each field is one value the request sent, named where it is read (`pick.order_id`); the class says
                # which fields there are, so this is not "everything that was sent" (as for a NestJS body class)
                words = f"`{name}` is the request's body (a parameter of `{fn.name}`)"
                return Val((self.source(fn, fn.line, words),), kind="bag", data=Dto(home) if home else "dto")
            if number:
                # a number cannot carry text into a query, a command or a page: safe for every such action. It is
                # still the caller's choice of record, so it is followed (the ownership check, `Engine.record`)
                safe = set(R.ALL)
            else:
                safe = {"nosql"} if (not ann or re_search(r"\b(str|bytes)\b", ann)) else set()
                if in_path and not re_search(r"[{<]path:" + name + r"[}>]|[{<]" + name + r":path[}>]", where):
                    safe.add("path")      # one part of the address: it cannot hold a slash
                if re_search(r"<slug:" + name + ">", where):
                    safe |= R.CHARS
            detail = (self.entry(fn) or {}).get("detail")
            m = re_search(r"\b(Cookie|Header)\(", (p.text or "") + " " + ann)
            part = {"Cookie": "cookies", "Header": "headers"}[m.group(1)] if m else "param"
            words = f"`{name}` arrives with the request" + (f" as {R.CLAIM_PLACE[part]}" if m else "") + \
                f" (a parameter of `{fn.name}`" + (f", {detail})" if detail else ")")
            if not in_path:
                self.sent[(fn.file, fn.line, words)] = (name, part)
            return join(base, Val((self.source(fn, fn.line, words, safe),)))
        if name in ("formData", "searchParams", "params") and (is_next_file(fn.file) or name == "formData"):
            words = f"`{name}` arrives with the request (handed to `{fn.name}`)"
            return Val((self.source(fn, fn.line, words),), kind="bag", data=name)
        return base

    def dependency(self, fn: Fn, text: str) -> Val | None:
        m = re_search(r"Depends\(\s*([A-Za-z_][\w.]*)|Security\(\s*([A-Za-z_][\w.]*)", text or "")
        if not m:
            return None
        name = m.group(1) or m.group(2)
        key = self.fn_named(fn.mod, name)
        self.before.setdefault(fn.key, {})[name] = key      # it runs before the handler: its checks count for it
        s = self.summ.get(key) if key is not None else None
        r = s.ret if s is not None else None
        database = bool(R.DB_NAME.search(name.rsplit(".", 1)[-1])) or (
            r is not None and r.kind == "ext" and isinstance(r.data, str) and bool(R.DATA_LIBS.match(r.data)))
        if auth_word(name) and not database:      # `get_db_session` is the database's session, not the person's
            return Val((Taint("ident", name, R.ALL, (), None, FIXED0),))
        if r is None:
            return None
        return r.but(taints=tuple(t for t in r.taints if t.kind != "param" and not (is_mark(t) and
                                                                                    t.key[2] is not None)), fixed=None)

    def fn_named(self, mod: Mod, name: str):
        """The key of the project's function a name in this file stands for (`check`, `deps.check`), or None."""
        f = mod.names.get(name)
        if f is None and mod.lang == "py":
            head, _, rest = name.partition(".")
            d = mod.imports.get(head)
            f = self.imported(mod, d + ("." + rest if rest else "")) if d else None
        return f.key if f is not None else None

    def bind_param(self, env: Env, fn: Fn, i: int, p: P, given: Val | None, ctx: Ctx, summary: bool) -> None:
        val = given if given is not None else self.param_val(fn, i, p, summary)
        if p.pattern is not None:
            if given is None and not summary and fn.lang == "js" and is_next_file(fn.file):
                val = Val(kind="req", data="js")      # `({ params, searchParams })` of a Next.js page or route
            elif given is None and is_next_file(fn.file) and p.pattern.k == "map":
                val = Val(kind="req", data="js")
            self.assign(p.pattern, val, env, ctx, p.pattern)
        else:
            env.vars[p.name] = val
            if summary and given is None and any(t.kind == "param" for t in val.taints):
                env.orig[p.name] = i

    def imported(self, mod: Mod, dotted: str) -> Fn | None:
        """The function of the project an import names, when it is one."""
        if not dotted or mod.lang != "py":
            return None
        return self.by_node.get("py:" + self.absolute(mod, dotted))

    @staticmethod
    def absolute(mod: Mod, dotted: str) -> str:
        """`.models.User` as written in `mod`, from the top of the project: `app.models.User`."""
        if dotted.startswith("."):
            level = len(dotted) - len(dotted.lstrip("."))
            pkg = (mod.dotted or "").split(".")
            is_pkg = mod.file.endswith("__init__.py")
            pkg = pkg[:len(pkg) - (level - 1 if is_pkg else level)] if level <= len(pkg) else []
            dotted = ".".join(pkg + [dotted.lstrip(".")]).strip(".")
        return dotted

    def model_class(self, mod: Mod, name: str, depth: int = 0, base=R.MODEL_BASE) -> bool:
        """Whether a class of the project makes stored records, by its bases as written (`db.Model`, `Base`,
        `Document`), through the project's own base classes. A class that checks what it is given is not one. With
        another `base`: whether it is a class of that family."""
        if depth > 4 or mod.lang != "py":
            return False
        bases = mod.bases.get(name)
        if bases is None:
            head, dot, last = name.rpartition(".")
            d = mod.imports.get(head if dot else name)
            if not d:
                return False
            full = self.absolute(mod, d)
            target, cls = (full, last) if dot else (full.rpartition(".")[0], full.rpartition(".")[2])
            m2 = self.py_mods.get(target) or next((m for k, m in self.py_mods.items() if k.endswith("." + target)),
                                                  None)
            return m2 is not None and m2 is not mod and self.model_class(m2, cls, depth + 1, base)
        return any(base.search(b) or self.model_class(mod, b, depth + 1, base) for b in bases)

    @staticmethod
    def class_name(ann: str) -> str:
        """The class a written type names: `Pick`, `schemas.Pick`, `Optional[Pick]`, `Annotated[Pick, Body()]`."""
        m = re_match(r"^(?:Annotated\[\s*)?(?:Optional\[\s*)?([A-Za-z_][\w.]*)\s*(?:$|[\],|])", ann or "")
        return m.group(1) if m else ""

    def body_class(self, mod: Mod, ann: str) -> bool:
        """Whether a parameter's written type is a class of the project that describes a request's body (a pydantic
        model, also through the project's own base classes and from another file)."""
        name = self.class_name(ann)
        return bool(name) and self.model_class(mod, name, 0, R.BODY_BASE)

    def class_home(self, mod: Mod, name: str, depth: int = 0):
        """Where a class of the project is written, through the imports that bring its name: (the file's Mod, the
        class's name there), or None for a class Lantern did not read."""
        if not name or depth > 4 or mod.lang != "py":
            return None
        if name in mod.bases:
            return mod, name
        head, dot, last = name.rpartition(".")
        d = mod.imports.get(head if dot else name)
        if not d:
            return None
        full = self.absolute(mod, d)
        target, cls = (full, last) if dot else (full.rpartition(".")[0], full.rpartition(".")[2])
        m2 = self.py_mods.get(target) or next((m for k, m in self.py_mods.items() if k.endswith("." + target)), None)
        return self.class_home(m2, cls, depth + 1) if m2 is not None and m2 is not mod else None

    def field_type(self, mod: Mod, cls: str, field: str, depth: int = 0):
        """The type a class writes for a field, its own before a base class's: (the type as written, the Mod of the
        file that writes it), or None when no class on the way writes the field with a type."""
        if depth > 4:
            return None
        ann = (mod.fields.get(cls) or {}).get(field)
        if ann is not None:
            return ann, mod
        for b in mod.bases.get(cls) or ():
            home = self.class_home(mod, b)
            got = self.field_type(home[0], home[1], field, depth + 1) if home else None
            if got:
                return got
        return None

    # ---- statements
    def block(self, stmts, env: Env, ctx: Ctx) -> bool:
        stmts = stmts or ()
        for i, s in enumerate(stmts):
            if s.k == "assign" and env.fn.lang == "py" and not s.name and s.a is not None and s.a.k == "call" and \
                    len(s.items or ()) == 1 and s.items[0].k == "name" and \
                    self.typed_later(stmts, i, s.items[0].name):
                self.plain_calls.add(id(s.a))
            if self.stmt(s, env, ctx):
                return True
        return False

    @staticmethod
    def typed_later(stmts, i: int, name: str) -> bool:
        """`resp = make_response(text)` and then, straight after in the same block, `resp.mimetype = "text/plain"` or
        `resp.headers["Content-Type"] = "application/json"`: what `resp` holds is not sent as a page. Not when the
        kind is set inside a branch, after `resp` was returned, or to a page."""
        said = None
        for s in stmts[i + 1:i + 13]:
            if s.k == "return":
                break
            if s.k != "assign" or s.name or len(s.items or ()) != 1 or s.a is None:
                continue
            t = s.items[0]
            if t.k == "name" and t.name == name:
                break
            on = t.a
            header = t.k == "index" and on is not None and on.k == "attr" and on.name == "headers" and \
                on.a is not None and on.a.k == "name" and on.a.name == name and t.b is not None and \
                t.b.k == "const" and str(t.b.a).lower() == "content-type"
            attr = t.k == "attr" and t.name in ("mimetype", "content_type", "media_type") and on is not None and \
                on.k == "name" and on.name == name
            if (header or attr) and s.a.k == "const":
                said = R.not_a_page(s.a.a)
        return said is True

    def stmt(self, s: N, env: Env, ctx: Ctx) -> bool:
        k = s.k
        if k == "expr":
            self.eval(s.a, env, ctx)
            return s.a is not None and s.a.k == "call" and bool(R.EXITS.search(text_of(s.a.a)))
        if k == "assign":
            self.assign_stmt(s, env, ctx)
            return False
        if k == "return":
            val = self.eval(s.a, env, ctx) if s.a is not None else None
            if val is not None and ctx.top is ctx and env.fn.lang == "py" and self.is_route(env.fn) and \
                    ("flask" in env.fn.mod.frameworks or
                     any("response_class" in d and "HTMLResponse" in d for d in env.fn.decorators or ())):
                self.page(ctx, env, s.a, val)
            self.leave(ctx, env, s.a, val)
            return True
        if k == "raise":
            if s.a is not None:
                self.eval(s.a, env, ctx)
            return True
        if k == "jump":
            return True
        if k == "if":
            asked = self.eval(s.a, env, ctx)
            self.judged(asked, ctx)
            no_t, no_f = refuses(s.b), refuses(s.c)
            self.claimed(asked, ctx, None if no_t == no_f else "then" if no_t else "else")
            t, f = self.facts(s.a, env, ctx)
            et, ef = env.copy(), env.copy()
            self.apply(et, t)
            self.apply(ef, f)
            xt, xf = self.block(s.b, et, ctx), self.block(s.c, ef, ctx)
            if xt and xf:
                return True
            if xt:
                env.take(ef)
            elif xf:
                env.take(et)
            else:
                et.join(ef)
                env.take(et)
            return False
        if k == "loop":
            target, it, test = s.items
            itv = self.eval(it, env, ctx) if it is not None else None
            looked = self.about(it, env) if it is not None else None
            # a name that was looked up has at least one address (or the look-up raised), so what every turn of the
            # loop refuses holds after it; a `break` leaves with the rest not looked at
            sure = looked is not None and looked[0] == "addr" and not has_break(s.b)
            for turn in range(2):
                body = env.copy()
                if test is not None:
                    asked = self.eval(test, body, ctx)
                    self.judged(asked, ctx)
                    self.claimed(asked, ctx)
                    self.apply(body, self.facts(test, body, ctx)[0])
                if target is not None and itv is not None:
                    written = self.written_keys(it, body)
                    if written is None:
                        self.assign(target, elem(itv), body, ctx, s)
                    elif written[0] == "pairs" and target.k == "seq" and len(target.items or ()) == 2:
                        # `for key, value in {"name": x}.items()`: the keys are the code's own words
                        self.assign(target.items[0], UNKNOWN, body, ctx, s)
                        self.assign(target.items[1], elem(written[1]), body, ctx, s)
                    elif written[0] == "keys":
                        self.assign(target, UNKNOWN, body, ctx, s)
                    else:
                        self.assign(target, elem(itv), body, ctx, s)
                    if looked is not None:
                        for name in names_in(target):
                            body.derived[name] = looked
                left = self.block(s.b, body, ctx)
                if sure and turn == 1 and not left:
                    env.take(body)
                else:
                    env.join(body)
            if s.c:
                self.block(s.c, env, ctx)
            return False
        if k == "try":
            pre = env.copy()
            xb = self.block(s.b, env, ctx)
            pre.join(env)
            alive = [] if xb else [env.copy()]
            for name, hbody in s.items or ():
                he = pre.copy()
                if name:
                    he.vars[name] = UNKNOWN
                    he.forget(name)
                if not self.block(hbody, he, ctx):
                    alive.append(he)
            if not alive:
                if s.c:
                    self.block(s.c, pre, ctx)
                return True
            out = alive[0]
            for e2 in alive[1:]:
                out.join(e2)
            env.take(out)
            return self.block(s.c, env, ctx) if s.c else False
        if k == "with":
            for cexpr, target in s.items or ():
                v = self.eval(cexpr, env, ctx)
                if target is not None:
                    self.assign(target, v, env, ctx, s)
            return self.block(s.b, env, ctx)
        if k == "def":
            f = s.a
            env.vars[f.name] = Val(kind="fn", data=(f, None))
            env.forget(f.name)
            self.closure(f, env, ctx, None, s)
            return False
        if k == "import":
            for name, dotted in (s.kw or {}).items():
                env.vars[name] = Val(kind="req", data=env.fn.lang) if dotted in R.REQUEST_GLOBALS else \
                    Val(kind="ext", data=dotted)
            return False
        if k == "match":
            self.eval(s.a, env, ctx)
            alive = []
            for body in s.items or ():
                e2 = env.copy()
                if not self.block(body, e2, ctx):
                    alive.append(e2)
            for e2 in alive:
                env.join(e2)
            return False
        return False

    def assign_stmt(self, s: N, env: Env, ctx: Ctx) -> None:
        val = self.eval(s.a, env, ctx) if s.a is not None else UNKNOWN
        if s.name:      # x += value
            t = s.items[0]
            old = self.eval(t, env, ctx)
            if s.name in ("+", "%"):
                val = concat([old, val], glue=s.name == "+")
            elif s.name in ("||", "??", "or", "&&", "and"):
                val = join(old, val)
            elif s.name == "/":
                val = Val(merge(old.taints, val.taints), kind=old.kind, data=old.data)
            else:
                val = UNKNOWN
        for t in s.items:
            self.assign(t, val, env, ctx, s)
        if len(s.items) == 1 and s.items[0].k == "name" and not s.name and s.a is not None:
            name = s.items[0].name
            if s.a.k == "name" and s.a.name in env.orig:
                env.orig[name] = env.orig[s.a.name]
            sub = self.subject(s.a, env)
            if sub and sub[1] == "host" and sub[0] != name:
                env.derived[name] = ("host", sub[0])
            whole = self.parsed(s.a, env)        # u = new URL(x) / parts = urlparse(x): `u.hostname` is x's host
            if whole and whole[1] is None and whole[0] != name:
                env.derived[name] = ("url", whole[0])
            if s.a.k in ("cmp", "call", "not", "bool"):      # ok = host in HOSTS ... if not ok: refuse
                yes, no = self.facts(s.a, env, ctx)
                if (yes or no) and not any(p == name or p.startswith(name + ".") for p, _c, _f, _r in yes + no):
                    env.flags[name] = (yes, no)
        if not s.name and s.a is not None:
            ab = self.about(s.a, env)            # ip = socket.gethostbyname(host) / { address } = await dns.lookup(h)
            if ab:
                for t in s.items:
                    for name in names_in(t):
                        if name != ab[1]:
                            env.derived[name] = ab

    def assign(self, t: N, val: Val, env: Env, ctx: Ctx, at: N) -> None:
        k = t.k
        if k == "name":
            env.forget(t.name)
            if val.taints and at is not None and at.line:
                # a step a reader can check: the line where the value was given this name (not said again on the
                # line it was read on)
                step = (env.fn.file, at.line, f"`{t.name}` is set from it")
                val = val.but(taints=tuple(x if x.kind == "ident" or (x.steps and x.steps[-1][:2] == step[:2])
                                           or (x.kind == "param" and not x.steps and at.line == env.fn.line)
                                           else with_step(x, step) for x in val.taints))
            env.vars[t.name] = val
        elif k in ("seq", "star"):
            items = t.items if k == "seq" else [t.a]
            for i, x in enumerate(items):
                one = val.data[i] if val.kind == "seq" and len(val.data) == len(items) else elem(val)
                self.assign(x, one, env, ctx, at)
        elif k == "map":      # const { a, b: c } = value
            for key, x in t.items or ():
                if key is None:
                    self.assign(x, val, env, ctx, at)
                    continue
                name = key.a if key.k == "const" else None
                base = at.a if at.k == "assign" and isinstance(at.a, N) and at.a.k in ("name", "attr", "index") \
                    else None
                got = self.member(val, str(name), N("attr", at.line, a=base, name=str(name)), env, ctx, text=None) \
                    if name is not None else Val(val.taints)
                self.assign(x, got, env, ctx, at)
        elif k == "attr":
            base_text = text_of(t)
            if t.name in R.XSS_ASSIGN:
                self.hit(ctx, env, "xss", val, at, f"{base_text} =", "HIGH" if val.html else "MEDIUM")
            elif base_text in R.REDIRECT_ASSIGN:
                self.redirect(ctx, env, val, at, f"{base_text} =", "MEDIUM")
            elif t.name == "body" and t.a.k in ("name", "attr") and text_of(t.a) in ("ctx", "ctx.response") \
                    and stringy(val):
                self.hit(ctx, env, "xss", val, at, "ctx.body =", "HIGH" if val.html else "MEDIUM")
            base = self.eval(t.a, env, ctx)
            if base.kind == "self" and ctx.fn is ctx.top.fn and len(ctx.fields) < 64:
                ctx.fields[t.name] = join(ctx.fields.get(t.name), val)       # what a constructor keeps
            if base.kind == "self" and env.fn.cls:
                key = (env.fn.file, env.fn.cls, t.name)
                keep = Val(tuple(x for x in val.taints if x.kind != "param"), None, val.sql, val.html, None,
                           val.kind if val.kind in ("ext", "req", "upload", "bag") else None,
                           val.data if val.kind in ("ext", "req", "upload", "bag") else None)
                self.attrs[key] = join(self.attrs.get(key), keep)
            elif t.a.k == "name" and val.taints and t.a.name in env.vars:
                old = env.vars[t.a.name]
                parsed = old.kind == "ext" and isinstance(old.data, str) and old.data.endswith("()") and \
                    bool(R.HOST_OF.match(old.data[:-2]))
                add = val.taints
                if parsed or any("redirect:own" in x.safe for x in old.taints):       # an address
                    if t.name in R.URL_HOST_SET:        # its host is set by hand: no longer the request's own
                        old = disown(old)
                    elif t.name in R.URL_REST_ATTRS:    # its path or query cannot change where it goes
                        add = tuple(x if x.kind == "ident" else x._replace(safe=x.safe | R.URLS) for x in add)
                if old.kind == "obj":
                    env.vars[t.a.name] = old.but(taints=merge(old.taints, add), data={**old.data, t.name: val})
                elif old.kind not in ("req", "self", "ext") or parsed:
                    env.vars[t.a.name] = old.but(taints=merge(old.taints, add))
        elif k == "index":
            if t.b is not None:
                self.eval(t.b, env, ctx)
            if t.a.k == "name" and val.taints:
                old = env.vars.get(t.a.name)
                if old is not None and old.kind not in ("req", "self", "ext"):
                    env.vars[t.a.name] = Val(merge(old.taints, val.taints), None, old.sql, old.html)

    # ---- expressions
    def eval(self, e: N | None, env: Env, ctx: Ctx) -> Val:
        if e is None:
            return UNKNOWN
        k = e.k
        if k == "const":
            return const(e.a)
        if k == "name":
            return self.lookup(e.name, env, ctx)
        if k == "str":
            v = concat([self.eval(p, env, ctx) for p in e.items], glue=True)
            return self.built(ctx, env, e, v)
        if k == "attr":
            base = self.eval(e.a, env, ctx)
            return self.narrowed(e, self.member(base, e.name, e, env, ctx), env)
        if k == "index":
            return self.narrowed(e, self.index(e, env, ctx), env)
        if k == "call":
            return self.call(e, env, ctx)
        if k == "bin":
            a, b = self.eval(e.a, env, ctx), self.eval(e.b, env, ctx)
            if e.name == "+":
                return self.built(ctx, env, e, concat([a, b], glue=True))
            if e.name in ("||", "??", "or", "&&", "and"):
                return join(a, b)
            if e.name == "%" and ((a.kind == "const" and isinstance(a.data, str)) or a.sql or a.html):
                return self.built(ctx, env, e, concat([a] + (list(b.data) if b.kind == "seq" else [b])))
            if e.name == "/" and (a.kind == "ext" or b.kind == "ext" or a.taints or b.taints) and env.fn.lang == "py":
                keep = a if a.kind == "ext" else b
                return Val(merge(a.taints, b.taints), kind=keep.kind if keep.kind == "ext" else None,
                           data=keep.data if keep.kind == "ext" else None)
            return UNKNOWN          # arithmetic: a number
        if k == "cmp":
            return self.compared(e, self.eval(e.a, env, ctx), self.eval(e.b, env, ctx))
        if k == "bool":
            return join_all([self.eval(x, env, ctx) for x in e.items])
        if k == "not":
            v = self.eval(e.a, env, ctx)
            # `not user.is_admin` asks what `user.is_admin` asks; `!req.cookies.admin` asks whether the visitor says so
            asked = tuple(turned(t) for t in v.taints if is_mark(t)) + self.claims(v, None, False)
            return Val(asked) if asked else UNKNOWN
        if k == "cond":
            asked = self.eval(e.a, env, ctx)
            self.judged(asked, ctx)
            self.claimed(asked, ctx)
            t, f = self.facts(e.a, env, ctx)
            et, ef = env.copy(), env.copy()
            self.apply(et, t)
            self.apply(ef, f)
            return join(self.eval(e.b, et, ctx), self.eval(e.c, ef, ctx))
        if k == "seq":
            return seq([self.eval(x, env, ctx) for x in e.items])
        if k == "map":
            data: dict = {}
            rest: tuple = ()
            fixed: frozenset | None = FIXED0
            for key, x in e.items or ():
                v = self.eval(x, env, ctx)
                fixed = None if fixed is None or v.fixed is None else fixed | v.fixed
                if key is not None and key.k == "const":
                    data[str(key.a)] = v
                else:
                    if key is not None:
                        rest = merge(rest, self.eval(key, env, ctx).taints)
                    rest = merge(rest, v.taints)
                    if v.kind == "obj":
                        data.update(v.data)
                    elif v.kind == "bag" and key is None:      # `{...req.body}`: all of it is in here
                        data["..."] = v
            taints = rest
            for v in data.values():
                taints = merge(taints, v.taints)
            return Val(taints, fixed, kind="obj", data=data)
        if k == "fn":
            self.closure(e.a, env, ctx, None, e)
            return Val(kind="fn", data=(e.a, None))
        if k == "comp":
            e2 = env.copy()
            for target, it, conds in e.items or ():
                self.assign(target, elem(self.eval(it, e2, ctx)), e2, ctx, e)
                for c in conds or ():
                    self.eval(c, e2, ctx)
                    self.apply(e2, self.facts(c, e2, ctx)[0])
            v = self.eval(e.a, e2, ctx)
            return Val(v.taints, v.fixed, v.sql, v.html, kind="seq", data=[v])
        if k == "star":
            return self.eval(e.a, env, ctx)
        if k == "walrus":
            v = self.eval(e.a, env, ctx)
            env.forget(e.name)
            env.vars[e.name] = v
            return v
        if k == "yield":
            v = self.eval(e.a, env, ctx) if e.a is not None else const(None)
            ctx.rets.append(v)
            return UNKNOWN
        if k == "regex":
            return Val(fixed=FIXED0, kind="regex", data=e.a)
        if k == "arith":
            for x in e.items or ():
                self.eval(x, env, ctx)
            return UNKNOWN
        if k == "unk":
            return Val(join_all([self.eval(x, env, ctx) for x in e.items or ()]).taints)
        if k in ("assign", "expr", "if", "return"):   # a statement where an expression may stand (JS `a = b` as a value)
            self.stmt(e, env, ctx)
            return self.eval(e.items[0], env, ctx) if k == "assign" and e.items else UNKNOWN
        return UNKNOWN

    def built(self, ctx: Ctx, env: Env, e: N, v: Val) -> Val:
        """Text that reads like SQL and has a value in it: remembered, so a finding on this line can be told whether
        only fixed text ever reaches it. The step is for the person who reads the flow."""
        if v.sql and v.kind != "const":
            ctx.top.points.setdefault((env.fn.file, e.line), []).append(("sql", v))
            if v.taints:
                v = stepped(v, (env.fn.file, e.line, "put into the text of a database query"))
        return v

    def lookup(self, name: str, env: Env, ctx: Ctx, value: bool = True) -> Val:
        v = env.vars.get(name)
        if v is not None:
            return v
        mod = env.fn.mod
        if name in mod.cvals:
            return mod.cvals[name]
        if name in mod.consts or name in mod.gwrites:
            return self.modval(mod, name)
        if name in mod.names:
            f = mod.names[name]
            if value and f is not None:
                self.escaped.add(f.key)
            return Val(kind="ref", data=name)
        d = mod.imports.get(name)
        if d is not None:
            if d in R.REQUEST_GLOBALS:
                return Val(kind="req", data=mod.lang)
            if d in R.IDENT_GLOBALS:        # flask-login's `current_user`, Flask's `session`: who is signed in
                return Val((Taint("ident", name, R.ALL, (), None, FIXED0),), kind="ext", data=d)
            if value:
                f = self.imported(mod, d)
                if f is not None:
                    self.escaped.add(f.key)
            return Val(kind="ext", data=d)
        if name in ("this", "self") and mod.lang == "js":
            return Val(kind="self", data=env.fn.cls)
        if name in R.DOM_SOURCE_HEADS and mod.lang == "js":
            words = f"`{name}` is part of the page's address, which whoever made the link chose"
            return Val((self.source(env.fn, env.fn.line, words, origin="dom"),), kind="ext", data=name)
        return Val(kind="ext", data=name)        # a name of the language or the environment: `open`, `parseInt`

    def modval(self, mod: Mod, name: str) -> Val:
        if name in mod.cvals:
            return mod.cvals[name]
        mod.cvals[name] = UNKNOWN
        env, ctx = Env(mod.top), Ctx(mod.top)
        v = None
        for ex in mod.consts.get(name, []) + mod.gwrites.get(name, []):
            v = join(v, self.eval(ex, env, ctx))
        mod.cvals[name] = v if v is not None else UNKNOWN
        return mod.cvals[name]

    def narrowed(self, e: N, v: Val, env: Env) -> Val:
        if env.narrow and v.taints:
            p = path_of(e)
            c = env.narrow.get(p) if p else None
            if c:
                return narrow(v, c, False, env.fn.lang)
        return v

    def leaf(self, bag: Val, key, e: N, env: Env, attr: bool = False) -> Val:
        """One value out of what the request sent: `request.args["q"]`. Of the address the request was made to, the
        origin and the host are still that address (`req.nextUrl.origin`); any other part is the caller's text."""
        if bag.data == "files" or bag.data == "FILES" or bag.data == "file":
            return Val(bag.taints, kind="upload", data=bag.data)
        words = said(e, key)
        out = []
        keep = attr and isinstance(key, str) and key in R.OWN_ATTRS
        # a body a class of the project describes: the class says what each field is. A field written as a number,
        # a date or a UUID is one (the request is turned away otherwise), so it carries no text anywhere; a field
        # that is itself such a class is read the same way, one level further in
        written = self.field_type(*bag.data.home, key) if isinstance(bag.data, Dto) and attr and \
            isinstance(key, str) else None
        number = bool(written and R.SAFE_TYPES.match(written[0]))
        inner = None
        if written and not number and self.body_class(written[1], written[0]):
            inner = self.class_home(written[1], self.class_name(written[0]))
        for t in bag.taints if keep else disowned(bag.taints):
            safe = t.safe | R.ALL if number else t.safe
            out.append(Taint("src", (env.fn.file, e.line, words), safe, ((env.fn.file, e.line, words),), t.origin,
                             t.drop) if t.kind == "src" and len(t.steps) <= 1 else t._replace(safe=safe))
        if isinstance(key, str) and key and isinstance(bag.data, str):
            self.sent[(env.fn.file, e.line, words)] = (key, str(bag.data))
        if inner:
            return Val(tuple(out), kind="bag", data=Dto(inner))
        got = Val(tuple(out), kind="bag" if bag.data in ("json", "body", "get_json", "data", "payload") and key is None
                  else None, data=bag.data)
        return got.but(prefix=R.OWN_EXACT) if keep and key == "origin" and owned(got) else got

    def member(self, base: Val, name: str, e: N, env: Env, ctx: Ctx, text: str | None = "") -> Val:
        plain = base.kind not in ("req", "bag", "upload")
        if plain and base.taints and name not in R.OWN_ATTRS:
            base = disown(base)         # `url.searchParams`: a part of the address, no longer the address
        v = self.member1(base, name, e, env, ctx, text)
        if plain and name == "origin" and owned(v):
            v = v.but(prefix=R.OWN_EXACT)
        asked = roled(base, name) if base.kind not in ("req", "bag", "upload") else ()
        return v.but(taints=merge(v.taints, asked)) if asked else v

    def member1(self, base: Val, name: str, e: N, env: Env, ctx: Ctx, text: str | None = "") -> Val:
        k = base.kind
        fn = env.fn
        if k == "req":
            inputs = R.PY_INPUT if base.data == "py" else R.JS_INPUT
            if name in inputs:
                shown = text_of(e)[:70] if text is not None else name
                words = f"`{shown}` is what the request sent"
                safe = {"nosql"} if name in R.STRING_ONLY and not (base.data == "js" and name == "query") else ()
                prefix = None
                if base.data == "js" and name in ("nextUrl", "url"):
                    # the address this request was made to: all of it (Next.js), or all of it once a page address
                    # is read against it (`new URL('/login', req.url)`; Express's `req.url` is the path only)
                    safe = set(safe) | {"redirect:own" if name == "nextUrl" else "redirect:base"}
                elif base.data == "py" and name in R.PY_OWN:
                    safe, prefix = set(safe) | {"redirect:own"}, R.OWN + "/"     # scheme, host, then a slash
                t = self.source(fn, e.line, words, safe)
                return Val((t,), kind="upload" if name in ("files", "file", "FILES") else "bag", data=name,
                           prefix=prefix)
            if name in R.IDENT_ATTRS:
                return Val((Taint("ident", name, R.ALL, (), None, FIXED0),))
            if name in ("request", "req", "raw"):
                return base
            return UNKNOWN
        if k == "bag":
            if name in R.NUMERIC_ATTRS and base.data != "dto":      # `size` of such a body is a field like any other
                return UNKNOWN
            return self.leaf(base, name, e, env, attr=True)
        if k == "upload":
            if name in R.UPLOAD_NAME_ATTRS:
                words = f"`{text_of(e)[:70]}` is the name the upload came with"
                return Val(tuple(Taint("src", (fn.file, e.line, words), FIXED0, ((fn.file, e.line, words),), t.origin,
                                       FIXED0) for t in base.taints if t.kind == "src") or base.taints)
            if name in R.NUMERIC_ATTRS:
                return UNKNOWN
            return Val(tuple(t._replace(safe=t.safe | CONTENT) for t in base.taints))
        if k == "ext":
            data = f"{base.data}.{name}"
            if data in R.REQUEST_GLOBALS:
                return Val(kind="req", data=fn.lang)
            if data in R.IDENT_GLOBALS:
                return Val((Taint("ident", name, R.ALL, (), None, FIXED0),), kind="ext", data=data)
            if not base.taints:
                if fn.lang == "js" and data in R.DOM_SOURCE_HEADS:
                    words = f"`{data}` is part of the page's address, which whoever made the link chose"
                    return Val((self.source(fn, e.line, words, origin="dom"),), kind="ext", data=data)
                return Val(kind="ext", data=data)
            head = base.data[:-2] if isinstance(base.data, str) and base.data.endswith("()") else None
            if head and R.HOST_OF.match(head):
                if name in R.URL_REST_ATTRS:
                    return Val(tuple(t._replace(safe=t.safe | R.URLS) for t in base.taints))
                return Val(base.taints)
            if isinstance(base.data, str) and base.data.startswith("pathlib.") and name in ("name", "stem", "suffix"):
                return Val(tuple(t._replace(safe=t.safe | {"path"}) for t in base.taints))
            if name in R.NUMERIC_ATTRS:
                return UNKNOWN
            return Val(base.taints, kind="ext", data=data)
        if k == "obj":
            v = base.data.get(name)
            return v if v is not None else Val(base.taints)
        if k == "self":
            if name in ("request", "req"):
                return Val(kind="req", data=fn.lang)
            if name in ("kwargs", "args") and fn.cls and fn.lang == "py" and "django" in fn.mod.frameworks:
                return UNKNOWN
            return self.attrs.get((fn.file, fn.cls, name), UNKNOWN)
        if not base.taints or name in R.NUMERIC_ATTRS:
            return UNKNOWN
        if name in R.ARCHIVE_ENTRY_ATTRS and any("content" in t.safe for t in base.taints):
            return self.entry_names(base, e, env)
        return Val(base.taints)

    def entry_names(self, v: Val, e: N, env: Env) -> Val:
        """The names of the entries inside an uploaded archive: new text the uploader chose, whatever was done to the
        archive's own name."""
        step = (env.fn.file, e.line, "the names of the entries inside the uploaded archive come with it")
        out = tuple(with_step(t._replace(safe=t.safe - CONTENT, drop=t.drop | CONTENT), step)
                    if t.kind != "ident" else t for t in v.taints)
        return Val(out)

    def index(self, e: N, env: Env, ctx: Ctx) -> Val:
        base = self.eval(e.a, env, ctx)
        key = self.eval(e.b, env, ctx) if e.b is not None else UNKNOWN
        if base.taints and base.kind not in ("req", "bag", "upload") and \
                not (key.kind == "const" and isinstance(key.data, str) and key.data in R.OWN_ATTRS):
            base = disown(base)
        v = self.index1(e, env, ctx, base, key)
        asked = roled(base, key.data) if key.kind == "const" and base.kind not in ("req", "bag", "upload") else ()
        return v.but(taints=merge(v.taints, asked)) if asked else v

    def index1(self, e: N, env: Env, ctx: Ctx, base: Val, key: Val) -> Val:
        k = base.kind
        if k == "req" and key.kind == "const" and isinstance(key.data, str):
            return self.member(base, key.data, e, env, ctx)
        if k == "bag":
            return self.leaf(base, key.data if key.kind == "const" else None, e, env)
        if k == "upload":
            return base
        if k == "obj":
            if key.kind == "const" and str(key.data) in base.data:
                return base.data[str(key.data)]
            return join_all(base.data.values()) if base.data and not base.taints else Val(base.taints, base.fixed)
        if k == "seq":
            if key.kind == "const" and isinstance(key.data, int) and not isinstance(key.data, bool) \
                    and -len(base.data) <= key.data < len(base.data):
                return base.data[key.data]
            return join_all(base.data) if base.data else Val(base.taints, base.fixed)
        if k == "self" or k == "ext" and not base.taints:
            return UNKNOWN
        return Val(base.taints, base.fixed if not base.taints else None)

    # ---- calls
    def call(self, e: N, env: Env, ctx: Ctx) -> Val:
        v, asked = self.call1(e, env, ctx)
        return v.but(taints=merge(v.taints, asked)) if asked else v

    def call1(self, e: N, env: Env, ctx: Ctx) -> tuple[Val, tuple]:
        """What the call gives back, and the checks on who is signed in it stands for (`asked`)."""
        f = e.a
        fn = env.fn
        if e.kw and "dependencies" in e.kw:
            self.router_wide(e, env)
        recv = member = recv_expr = None
        if f.k == "attr":
            recv_expr, member = f.a, f.name
            recv = self.eval(f.a, env, ctx)
            callee = self.member(recv, member, f, env, ctx)
        elif f.k == "name":
            callee = self.lookup(f.name, env, ctx, value=False)
        else:
            callee = self.eval(f, env, ctx)
        args: list = []
        closures: list = []
        for i, a in enumerate(e.items or ()):
            if a.k == "fn":
                args.append(None)
                closures.append((i, a))
            else:
                args.append(self.eval(a, env, ctx))
        kw = {k: self.eval(v, env, ctx) for k, v in (e.kw or {}).items()}
        cb_ret = None
        for i, a in closures:      # a function written in the call: analysed here, with what the receiver holds
            given = [elem(recv)] if recv is not None and recv.taints and member in R.CALLBACK_METHODS else None
            if given and member in ("then", "on", "once", "subscribe", "pipe"):
                given = [Val(recv.taints)]
            r = self.closure(a.a, env, ctx, given, a)
            cb_ret = join(cb_ret, r) if r is not None else cb_ret
            args[i] = Val(kind="fn", data=(a.a, None))
        if callee.kind == "fn" and isinstance(callee.data, tuple):
            r = self.closure(callee.data[0], env, ctx, [a if a is not None else UNKNOWN for a in args], e)
            return (r if r is not None else UNKNOWN), ()
        # a stored record made of everything the request sent: `User(**request.json)`, `new User(req.body)`
        sent = kw.get("**") if "**" in kw else args[0] if e.name == "new" and args else None
        if whole(sent) and self.is_model(f, callee, env):
            self.hit(ctx, env, "assign", Val(tuple(t for t in sent.taints if t.kind == "src")), e,
                     text_of(f)[:60] + "()", "LOW")
        site = self.sites.get((fn.file, e.line, e.col))
        targets, guess = self.targets(site)
        if not targets and f.k == "name" and f.name == "super" and fn.cls and fn.lang == "js":
            # `super(term)`: the constructor of the class this one extends, when it is in this file
            targets = [x for b in fn.mod.bases.get(fn.cls, ()) for x in fn.mod.fns
                       if x.cls == b and x.name in R.CONSTRUCTORS][:1]
        asked = roled(recv, member) if recv is not None and member else ()      # `user.has_role("admin")`
        if targets:
            return self.use(targets, guess, e, env, ctx, args, kw, member is not None or e.name == "new"), asked
        if site and site["outcome"] in ("resolved", "likely") and site["to"] and \
                all(getattr(self.g.nodes.get(x), "kind", None) == "class" for x in site["to"]):
            # a class of the project with no constructor of its own (a dataclass, a form or a model of a library):
            # the object holds what it was given
            carried = join_all([a for a in args if a is not None] + list(kw.values()))
            if carried.taints:
                step = (fn.file, e.line, f"is put into a `{text_of(f)[:40]}` object")
                return Val(tuple(with_step(x, step) for x in carried.taints)), asked
            return UNKNOWN, asked
        canon = None
        if callee.kind == "ext" and isinstance(callee.data, str) and not callee.data.startswith("."):
            canon = callee.data
        elif site and site["to"] and all(t.startswith(("ext:", "builtin:")) for t in site["to"]):
            canon = site["to"][0].split(":", 1)[1]
        if e.name == "new" and canon:
            canon = canon if canon.startswith("new ") or canon != "URL" else "new URL"
        v = self.lib(e, env, ctx, canon, member, recv, recv_expr, callee, args, kw, cb_ret)
        return v, asked + self.asked(e, ctx, canon, member, recv, args, kw)

    def is_model(self, f: N, callee: Val, env: Env) -> bool:
        """Whether the class called here makes a stored record: by its bases as written (Python), by the library or
        the models file it comes from (JavaScript)."""
        name = text_of(f)
        last = name.rsplit(".", 1)[-1]
        if not last[:1].isupper() or R.NOT_RECORD_CLASS.match(name):
            return False
        mod = env.fn.mod
        if mod.lang == "py":
            return f.k == "name" and self.model_class(mod, last)
        d = callee.data if callee.kind == "ext" and isinstance(callee.data, str) else ""
        return bool(d) and bool(R.DATA_LIBS.match(d) or (d.startswith((".", "@/", "~/")) and R.MODEL_PATH.search(d)))

    def asked(self, e: N, ctx: Ctx, canon, member, recv, args: list, kw: dict) -> tuple:
        """Checks made by a call whose code Lantern does not read, as marks on what it gives back: a fixed list asked
        whether it holds who is signed in (`ADMINS.includes(user.email)`), and a function named for a permission
        check that is handed who is signed in (`authorize(user, order)`, which refuses by itself)."""
        out: tuple = ()
        vals = [a for a in args if a is not None] + list(kw.values())
        if member in ("includes", "has", "contains", "__contains__", "indexOf", "index", "count") and \
                recv is not None and not recv.taints and recv.fixed is not None and not recv.fixed:
            listed = [i.data for i in recv.data if i.kind == "const" and isinstance(i.data, str)] \
                if recv.kind == "seq" else []
            for v in vals:
                out += marks_for(v, ("role",))
                if listed:      # `["admin", "staff"].includes(req.cookies.role)`: the visitor's own word
                    out += self.claims(v, listed, True)
        named_ = (member or text_of(e.a)).rsplit(".", 1)[-1]
        if named_ in R.SAME_SECRET and any(x.k != "const" and R.ADMIN_SECRET.search(text_of(x))
                                           for x in e.items or ()):
            out += (mark("role"),)          # `hmac.compare_digest(sent, ADMIN_KEY)`
        if member in R.EQUAL_MEMBERS and recv is not None and vals:     # `order.user.equals(req.user._id)`
            for x, y in ((recv, vals[0]), (vals[0], recv)):
                if y.kind != "const" and not who(y)[0]:
                    out += marks_for(x, ("owner",))
        last = member or (canon or text_of(e.a)).rsplit(".", 1)[-1].rstrip("()")
        if last and R.AUTHZ_CALL.search(last):
            got: tuple = ()
            for v in vals + ([recv] if recv is not None else []):
                got += marks_for(v, ("owner", "role"))
            if got and R.AUTHZ_RAISES.match(last):
                self.judged(Val(got), ctx)
            out += got
        return out

    def judged(self, v: Val, ctx: Ctx) -> None:
        """A condition was decided on `v`: the checks it stands for were made."""
        if not v.taints:
            return
        az = ctx.az
        for t in v.taints:
            if is_mark(t) and not is_claim(t):
                _eq, kind, i = t.key
                if i is None:
                    az.ev.add(kind)
                else:
                    az.pev.setdefault(i, set()).add(kind)

    def claims(self, v: Val, texts, sense: bool) -> tuple:
        """The marks for the visitor's own word on what they may do, read off the request values in `v`: asked
        whether it is there (`texts` None) or compared with the fixed text in `texts`. Only by name, and only for the
        parts of a request its sender writes freely (`flow_rules.CLAIM_HEAD`, `CLAIM_BODY`)."""
        out: tuple = ()
        for t in v.taints:
            if t.kind != "src" or R.COMPARED in t.safe:
                continue
            got = self.sent.get(t.key)
            if got is None:
                continue
            name, part = got
            head = part in R.CLAIM_HEAD
            if not head and part not in R.CLAIM_BODY:
                continue
            n = claim_name(name)
            said_so = bool(R.CLIENT_FLAG.match(n))
            if not said_so and head and texts:
                said_so = bool((R.CLIENT_ROLE.match(n) and any(R.ROLE_VALUE.search(s) for s in texts)) or
                               (R.CLIENT_PERSON.match(n) and any(R.CLIENT_WORD.match(s) for s in texts)))
            if said_so:
                out += (claim_mark(head, sense, t.key),)
        return out

    def claimed(self, v: Val, ctx: Ctx, refused: str | None = None) -> None:
        """A condition was decided on `v`: where `v` is the visitor's own word on what they may do, the route decides
        on it. A value from the address or the body counts only where the branch taken without it (`refused`: "then"
        or "else") turns the request away."""
        for t in (*v.taints, *self.claims(v, None, True)):
            if not is_claim(t):
                continue
            _c, strong, sense, *where = t.key[1]
            if strong or (refused == "then" and not sense) or (refused == "else" and sense):
                ctx.az.ev.add(("client", *where))

    def compared(self, e: N, a: Val, b: Val) -> Val:
        """What a comparison carries on: the values in it, as a number is carried (safe for every action), and the
        check it makes when one side says who is signed in. Against fixed text it asks a role (`user.role ==
        "admin"`, `user.email in ADMINS`); against anything else, whose record this is."""
        if not a.taints and not b.taints:
            return UNKNOWN
        asked: tuple = ()
        equal = e.name in ("==", "===", "!=", "!==", "is", "is not", "in", "not in")
        for x, y in ((a, b), (b, a)):
            known, params = who(x)
            if not equal or (not known and not params):
                continue
            side = text_of(e.a if x is a else e.b)
            if y.kind == "const":
                d = y.data
                if d is None or isinstance(d, bool) or d in ("", 0):
                    kinds = ()
                elif isinstance(d, str) and not (R.ROLE_VALUE.search(d) or R.PERSON_ATTR.search(side)):
                    kinds = ()          # `user.status == "active"` asks nothing about what they may do
                else:
                    kinds = ("role",)
            elif y.fixed is not None and not y.fixed and not y.taints:
                listed = [str(i.data) for i in y.data if i.kind == "const"] if y.kind == "seq" else None
                kinds = ("role",) if listed is None or R.PERSON_ATTR.search(side) or \
                    any(R.ROLE_VALUE.search(s) for s in listed) else ()
            elif who(y)[0] or R.NOT_OWNER.search(text_of(e.a) + " " + text_of(e.b)):
                kinds = ()
            else:
                kinds = ("owner",)
            asked += tuple(mark(k) for k in kinds if known) + tuple(mark(k, i) for i in params for k in kinds)
        if equal and any(x.k != "const" and R.ADMIN_SECRET.search(text_of(x)) for x in (e.a, e.b) if x is not None):
            asked += (mark("role"),)        # what was sent is compared with the admin's own secret
        for x, y in ((a, b), (b, a)):       # what was sent is compared with fixed text: is it the visitor's own claim?
            if not equal or y.taints:
                continue
            if y.kind == "const":
                texts = [y.data]
            elif y.kind == "seq" and y.fixed is not None and not y.fixed:
                texts = [i.data for i in y.data if i.kind == "const"]
            else:
                continue
            same = e.name in ("==", "===", "is", "in")
            sense = same != (y.kind == "const" and says_not(y.data))
            asked += self.claims(x, [s for s in texts if isinstance(s, str)] or [""], sense)
        carried = tuple(t if t.kind == "ident" else t._replace(safe=t.safe | R.ALL | {R.COMPARED})
                        for t in merge(a.taints, b.taints))
        return Val(merge(carried, asked))

    def targets(self, site) -> tuple[list, bool]:
        if not site or site["outcome"] not in ("resolved", "likely", "possible", "name-only"):
            return [], False
        out = []
        for t in site["to"]:
            f = self.by_node.get(t) or self.by_node.get(t + ".__init__") or self.by_node.get(t + ".constructor")
            if f is not None and f not in out:
                out.append(f)
        if site["outcome"] == "name-only":
            return (out if len(out) == 1 else []), True
        return out[:3], False

    def closure(self, f: Fn, env: Env, ctx: Ctx, given, at: N) -> Val | None:
        """A function written inside another one, read where it stands with the names around it."""
        if ctx.depth >= MAX_DEPTH or f.body is None:
            if f.body is not None:
                self.stats["unread"] = self.stats.get("unread", 0) + 1      # what it calls was not seen
            return None
        sub = Ctx(f, ctx)
        route = f.node is not None and (self.entry(f) or {}).get("kind") == "route"
        if route:
            sub.az = Az()       # a route written inline: its own account of who may reach what
            self.routes[f.key] = (f, sub.az)
        e2 = env.copy(f)
        e2.orig = {}
        for i, p in enumerate(f.params):
            g = given[i] if given is not None and i < len(given) else None
            self.bind_param(e2, f, i, p, g, sub, False)
        self.block(f.body, e2, sub)
        for name in f.outer:        # what it assigns outside itself counts from here on, as "may have been set"
            if name in e2.vars:
                env.vars[name] = join(env.vars.get(name, UNKNOWN), e2.vars[name])
                env.forget(name)
        return join_all(sub.rets) if sub.rets else None

    def bound(self, t: Fn, e: N, args: list, kw: dict, method: bool) -> dict:
        """Which value each parameter of `t` gets from this call: {index: (value, the argument's code or None)}."""
        out: dict = {}
        params = t.params
        # `Search(q)` hands `q` to the constructor's second parameter; `Base.__init__(self, q)` names `self` itself
        named_self = t.name == "__init__" and e.a.k == "attr" and e.a.name == "__init__" and \
            not (e.a.a is not None and e.a.a.k == "call" and text_of(e.a.a.a) == "super")
        shift = 1 if (t.lang == "py" and params and params[0].name in ("self", "cls") and t.cls
                      and (method or t.name == "__init__") and not named_self) else 0
        items = e.items or ()
        pos = [(i, p) for i, p in enumerate(params) if p.kind == "pos"][shift:]
        star = next((i for i, p in enumerate(params) if p.kind == "star"), None)
        for j, a in enumerate(args):
            if j < len(pos):
                out[pos[j][0]] = (a if a is not None else UNKNOWN, items[j] if j < len(items) else None)
            elif star is not None:
                old = out.get(star)
                out[star] = (join(old[0] if old else None, a if a is not None else UNKNOWN), None)
        names = {p.name: i for i, p in enumerate(params)}
        kwstar = next((i for i, p in enumerate(params) if p.kind == "kwstar"), None)
        for k, v in kw.items():
            i = names.get(k)
            if i is not None:
                out[i] = (v, (e.kw or {}).get(k))
            elif kwstar is not None:
                old = out.get(kwstar)
                out[kwstar] = (join(old[0] if old else None, v), None)
        for i, p in enumerate(params):
            if i not in out and p.default is not None and p.default.k == "const":
                out[i] = (const(p.default.a), None)
        return out

    def use(self, targets: list, guess: bool, e: N, env: Env, ctx: Ctx, args: list, kw: dict, method: bool) -> Val:
        fn = env.fn
        res = None
        for t in targets:
            s = self.summ.get(t.key)
            b = self.bound(t, e, args, kw, method)
            ctx.top.calls.append((t.key, {i: v for i, (v, _x) in b.items()}, e.line, ctx.top.fn.key,
                                  self.shown(fn, ctx.top.fn)))
            if s is None:
                continue
            shown = t.name if not t.cls or t.name != "__init__" else t.cls
            az = ctx.az
            before, before_p = frozenset(az.ev), asked_of(az)

            def carried(had, hadp, b=b, before=before, before_p=before_p) -> tuple[frozenset, frozenset]:
                """What was asked before a record the called function reaches, in this function's terms: what was
                asked here before the call, what the called function asked on its own account before the record,
                and what it asked before it of a parameter this call hands who is signed in."""
                h, hp = set(before) | set(had), set(before_p)
                for i, kind in hadp:
                    got = b.get(i)
                    if got is not None:
                        known, mine = who(got[0])
                        if known:
                            h.add(kind)
                        hp.update((j, kind) for j in mine)
                return frozenset(h), frozenset(hp)
            if s.ev:                      # checks the function makes on its own account
                az.ev |= s.ev
            for i, kinds in s.pev.items():      # checks it makes on a parameter, when that is who is signed in
                got = b.get(i)
                if got is not None:
                    known, mine = who(got[0])
                    if known:
                        az.ev |= kinds
                    for j in mine:
                        az.pev.setdefault(j, set()).update(kinds)
            for rkey, r in s.records.items():   # records it reaches by request values it reads itself
                scoped, unless = self.told(frozenset(f"who:{i}" for i in r["unless"]), b)
                if not scoped and rkey not in az.records:
                    h, hp = carried(r["had"], r["hadp"])
                    az.records[rkey] = dict(r, unless=unless, had=h, hadp=hp)
            for rec in s.sinks:
                got = b.get(rec.param)
                if got is None:
                    continue
                av = got[0]
                if ("nohost" in rec.needs and R.host_fixed(av.prefix)) or \
                        ("nolocal" in rec.needs and R.stays(av.prefix)):
                    continue
                unless: frozenset = FIXED0
                change = "change" in rec.needs
                qkeep = None
                h = hp = None
                if rec.cls == "record":
                    h, hp = carried(frozenset(n[4:] for n in rec.needs if n.startswith("had:")),
                                    frozenset((int(n.split(":")[1]), n.split(":")[2]) for n in rec.needs
                                              if n.startswith("hadp:")))
                if rec.cls == "record":         # told who is signed in, the function reaches that person's own
                    scoped, unless = self.told(rec.needs, b)
                    if scoped or who(av)[0]:    # ... or the values that pick the record name them
                        continue
                    qn = next((n for n in rec.needs if n.startswith("q:")), None)
                    if qn is not None:          # the database text is this call's to say
                        qv = b.get(int(qn[2:]))
                        said_ = self.record_text(qv[0]) if qv is not None else None
                        if said_ is None:
                            continue
                        if isinstance(said_, tuple):
                            change = said_[1]
                        else:
                            qkeep = f"q:{said_}"
                elif rec.cls == "assign":
                    sent = any(x.kind == "src" for x in av.taints)
                    passing = av.kind is None and bool(av.taints) and not sent
                    # an object written in the code has the code's own field names, whatever its values are
                    ok = whole(av) if ("bag" in rec.needs or av.kind in ("obj", "bag")) else sent
                    if not passing and not ok:
                        continue                # not everything the request sent, and not a parameter that may be
                need_sql = "sql" in rec.needs and not av.sql
                hand = (fn.file, e.line, f"handed to `{shown}()` as `{t.params[rec.param].name}`")
                for ta in av.taints:
                    safe = norm((ta.safe - rec.drop) | rec.safe, fn.lang)
                    if ta.kind == "ident" or safe_for(rec.cls, safe) or \
                            (ta.origin == "dom" and rec.cls not in DOM_OK):
                        continue
                    steps = cut(ta.steps + (hand,) + rec.steps)
                    conf = "LOW" if guess else rec.conf
                    if ta.kind == "src":
                        if not need_sql and qkeep is None:
                            ctx.flow(rec.cls, ta, steps, conf, rec.what, rec.file, rec.line, rec.node, unless, change,
                                     h, hp)
                    else:
                        keep = frozenset(n for n in rec.needs if (n == "sql" and need_sql) or
                                         (n in URL_NEEDS and not av.prefix) or n in ("bag", "name")) | \
                            frozenset(f"who:{j}" for j in unless if j != ta.key) | \
                            (frozenset({"change"}) if change else FIXED0) | (frozenset({qkeep}) if qkeep else FIXED0)
                        if h is not None:
                            keep |= frozenset(f"had:{k}" for k in h if isinstance(k, str)) | \
                                frozenset(f"hadp:{j}:{k}" for j, k in hp)
                        ctx.sink(SinkRec(ta.key, rec.cls, safe, ta.drop | rec.drop, steps, rec.file, rec.line,
                                         rec.what, conf, keep, rec.node))
            for i, classes in s.guards.items():
                got = b.get(i)
                if got is not None and got[1] is not None:
                    sub = self.subject(got[1], env)
                    if sub:
                        self.apply(env, [(sub[0], classes, False, sub[1])])
            built = t.name in R.CONSTRUCTORS or e.name == "new"
            if built and e.a.k in ("attr", "name") and (e.a.name in R.CONSTRUCTORS or e.a.name == "super"):
                # `super().__init__(term)` / `super(term)`: what the parent keeps is kept on this object too
                if ctx.fn is ctx.top.fn:
                    for k, v in s.fields.items():
                        if k not in ctx.fields and len(ctx.fields) < 64:
                            ctx.fields[k] = self.handed_back(v, b, t, shown, fn, e, kept=True)
                continue
            if built and s.fields:
                # the object a constructor makes: each field is what the constructor put there
                data = {k: self.handed_back(v, b, t, shown, fn, e, kept=True) for k, v in s.fields.items()}
                res = join(res, Val(join_all(data.values()).taints, kind="obj", data=data))
                continue
            r = s.ret
            if r is None:
                continue
            res = join(res, self.handed_back(r, b, t, shown, fn, e))
        if res is None:
            # the function's own code was not read (a class with no constructor of its own): the object holds what
            # it was given
            carried = join_all([a for a in args if a is not None] + list(kw.values()))
            return Val(carried.taints) if method and e.name == "new" else UNKNOWN
        if R.IDENT_FN.match(targets[0].name) and not who(res)[0]:
            # named for giving back who is signed in (found from a token Lantern does not follow): taken by its name
            res = res.but(taints=merge(res.taints, (Taint("ident", targets[0].name, R.ALL, (), None, FIXED0),)))
        return res

    @staticmethod
    def handed_back(r: Val, b: dict, t: Fn, shown: str, fn: Fn, e: N, kept: bool = False) -> Val:
        """A value of a called function's summary (what it returns; with `kept`, what its constructor keeps in a
        field) as the caller sees it: the parameters in it are what this call handed in."""
        back = f"is kept by `{shown}()`" if kept else f"comes back from `{shown}()`"
        taints: tuple = ()
        sql, html = r.sql, r.html
        for rt in r.taints:
            if is_mark(rt) and rt.key[2] is not None:      # a check on a parameter: made, if that is who is signed in
                got = b.get(rt.key[2])
                if got is not None:
                    taints = merge(taints, marks_for(got[0], (rt.key[1],)))
                continue
            if rt.kind != "param":
                taints = merge(taints, (with_step(rt, (fn.file, e.line, back)),))
                continue
            got = b.get(rt.key)
            if got is None:
                continue
            av = got[0]
            sql, html = sql or av.sql, html or av.html
            pname = t.params[rt.key].name
            if rt.steps:
                mid = ((fn.file, e.line, f"handed to `{shown}()` as `{pname}`"),) + rt.steps + ((fn.file, e.line, back),)
            elif kept:
                mid = ((fn.file, e.line, f"handed to `{shown}()` as `{pname}`, which keeps it"),)
            else:
                mid = ((fn.file, e.line, f"passes through `{shown}()` and comes back"),)
            for ta in av.taints:
                if ta.kind == "ident":
                    taints = merge(taints, (ta,))
                    continue
                taints = merge(taints, (Taint(ta.kind, ta.key, norm((ta.safe - rt.drop) | rt.safe, fn.lang),
                                              cut(ta.steps + mid), ta.origin, ta.drop | rt.drop),))
        fixed: frozenset | None = None
        if r.fixed is not None:
            fixed = FIXED0
            for i in r.fixed:
                got = b.get(i)
                fixed = None if fixed is None or got is None or got[0].fixed is None else fixed | got[0].fixed
        if r.kind == "const" and not taints:
            return r
        keep_kind = r.kind in ("req", "upload", "bag", "ext", "obj", "seq", "regex")
        return Val(taints, fixed, sql, html, r.prefix if r.prefix else None, r.kind if keep_kind else None,
                   r.data if keep_kind else None)

    @staticmethod
    def told(needs, b: dict) -> tuple[bool, frozenset]:
        """For a record reached inside a called function: whether this call hands it who is signed in (then the
        record is that person's own), and which of the caller's own parameters would do so."""
        mine: set = set()
        for n in needs:
            if not n.startswith("who:"):
                continue
            got = b.get(int(n[4:]))
            if got is None:
                continue
            known, params = who(got[0])
            if known:
                return True, FIXED0
            mine.update(params)
        return False, frozenset(mine)

    # ---- who may reach what: records chosen by the request, everything the request sent written onto one
    @staticmethod
    def record_text(q: Val):
        """What database text says about records: (True, whether it changes them) when it reads, changes or removes
        rows that exist (written text needs a WHERE: without one it is every row, nobody's in particular); the index
        of a parameter when the text is that parameter as it was handed in; None otherwise."""
        text = q.data if q.kind == "const" and isinstance(q.data, str) else \
            q.prefix if q.sql and isinstance(q.prefix, str) and q.prefix else None
        if text is not None:
            if not R.RECORD_SQL.match(text) or (q.kind == "const" and not R.SQL_WHERE.search(text)):
                return None
            return True, not _re.match(r"\W*(select|with)\b", text, _re.I)
        ps = [t.key for t in q.taints if t.kind == "param"]
        if len(ps) == 1 and q.kind is None and q.fixed == frozenset({ps[0]}):
            return ps[0]
        return None

    def reached(self, e: N, env: Env, ctx: Ctx, name: str, member, recv, recv_expr, args: list, kw: dict, a0,
                what: str) -> Val | None:
        """A call on stored data. None when this is none (or says nothing new); else what it gives back: a record,
        which says who is signed in when the call asked for theirs."""
        vals = [a for a in args if a is not None] + list(kw.values())
        rtext = text_of(recv_expr) if recv_expr is not None else ""
        d = recv.data if recv is not None and recv.kind == "ext" and isinstance(recv.data, str) else ""
        lib_data = bool(d) and bool(R.DATA_LIBS.match(d) or d.startswith("record("))
        # Supabase asks the database's own row rules who may see a row (LW-SUPABASE-RLS reads those): which record a
        # query picks is not judged here. What is written onto the row still is: the rules guard rows, not columns
        rls = d.startswith(("@supabase", "record(rls)")) or bool(_re.match(r"(?i)supabase", rtext))
        # a value Lantern knows to be something else: a dict or a list of the code's own, a library that is no database
        other = recv is not None and (recv.kind in ("obj", "seq", "const", "req", "bag", "upload", "fn", "regex") or
                                      (bool(d) and not lib_data and not d.startswith((".", "@/", "~/", "#"))
                                       and d not in R.IDENT_GLOBALS))
        data_recv = lib_data or (bool(rtext) and not other and bool(R.DATA_RECEIVER.search(rtext))
                                 and not R.NOT_DATA.match(rtext))
        full = name or text_of(e.a)
        last = full.rsplit(".", 1)[-1]
        # --- everything the request sent, written onto a stored record
        if member in R.WRITE_MEMBERS and data_recv:
            for v in vals:
                self.assigned(ctx, env, v, e, what)
        elif full == "setattr" and len(args) > 2 and args[1] is not None:
            self.assigned(ctx, env, args[1], e, what, True)
        elif name and R.OVERLAY_CALL.match(name) and a0 is not None and a0.kind == "ext" and \
                isinstance(a0.data, str) and a0.data.startswith("record("):
            for v in vals[1:]:
                self.assigned(ctx, env, v, e, what)
        # --- a record read, changed or removed
        told = None
        if (bool(name) and bool(R.SQL_CALL.match(name))) or (member in R.SQL_MEMBERS and
                                                              not (name and R.NOT_SQL.match(name))):
            q = next((kw[k] for k in ("sql", "query", "statement", "operation") if k in kw), a0)
            qe = e.items[0] if e.items else None
            if q is not None and q.kind != "const" and qe is not None and qe.k == "call" and qe.items and \
                    qe.items[0].k == "const" and isinstance(qe.items[0].a, str):
                q = const(qe.items[0].a)        # `text("SELECT ...")`, `sql.SQL("...")`: the text inside
            told = self.record_text(q) if q is not None else None
            if isinstance(told, tuple):
                got = self.record(ctx, env, e, what, vals, None, told[1], rls=rls)
                if got.taints and recv_expr is not None and recv_expr.k == "name":
                    # `cur.execute(...)` then `cur.fetchone()`: the cursor holds the signed-in person's rows
                    old = env.vars.get(recv_expr.name, UNKNOWN)
                    env.vars[recv_expr.name] = old.but(taints=merge(tuple(t for t in old.taints if t.kind != "ident"),
                                                                    got.taints))
                return got if got.taints else None
        if (member in R.RECORD_SURE and recv_expr is not None and not other and not R.NOT_DATA.match(rtext)) or \
                (member in R.RECORD_MAYBE and data_recv) or last in ("get_object_or_404", "get_list_or_404"):
            return self.record(ctx, env, e, what, vals, recv, bool(member and R.CHANGE_MEMBERS.search(member)),
                               rls=rls)
        if told is not None:        # the text is a parameter: the callers say what it reads (`query_db(sql, args)`)
            self.record(ctx, env, e, what, [v for v in vals if v is not q], None, False, (f"q:{told}",))
        return None

    def record(self, ctx: Ctx, env: Env, e: N, what: str, vals: list, recv, change: bool = False, more=(),
               rls: bool = False) -> Val:
        """A stored record is read, changed or removed here, chosen by `vals`. With who is signed in among them (or as
        what the call is made on) it is that person's own, and nothing is noted. Otherwise every request value among
        them is noted for the route to answer for (`authz`), and every parameter for the callers."""
        fn = env.fn
        taints: tuple = ()
        for v in vals:
            taints = merge(taints, v.taints)
        every = merge(taints, recv.taints) if recv is not None else taints
        whose = tuple(t for t in every if t.kind == "ident" and not is_mark(t))
        if rls:
            return Val(whose, kind="ext", data="record(rls)")
        params = frozenset(t.key for t in every if t.kind == "param")
        lines = set()
        x, depth = e, 0
        while x is not None and depth < 16:     # the calls this one hangs on: `query.filter(a).filter(b)`
            if x.k == "call":
                lines.add(x.line)
            elif x.k not in ("attr", "await", "index"):
                break
            x, depth = x.a, depth + 1
        self.amend(ctx, fn.file, lines, bool(whose), params)
        if not whose:
            step = (fn.file, e.line, f"`{what}`: here it {R.ACTION['record']}")
            for t in taints:
                if t.kind == "src" and t.origin != "dom":
                    if not more:
                        ctx.flow("record", t, cut(t.steps + (step,)), "LOW", what, fn.file, e.line, fn.node, params,
                                 change)
                elif t.kind == "param":
                    needs = frozenset(f"who:{i}" for i in params if i != t.key) | frozenset(more) | \
                        (frozenset({"change"}) if change else FIXED0) | had_marks(ctx.az)
                    ctx.sink(SinkRec(t.key, "record", t.safe, t.drop, cut(t.steps + (step,)), fn.file, e.line, what,
                                     "LOW", needs, fn.node))
        return Val(whose, kind="ext", data="record()")

    @staticmethod
    def amend(ctx: Ctx, file: str, lines: set, scoped: bool, params: frozenset) -> None:
        """A later call of one chain says more about the record the chain reaches: `.filter(id=x)` followed by
        `.filter(owner=<who is signed in>)` is the caller's own record."""
        az = ctx.az
        for key in [k for k in az.records if k[1] == file and k[2] in lines]:
            if scoped:
                del az.records[key]
            elif params:
                az.records[key]["unless"] = az.records[key]["unless"] | params
        sinks = ctx.top.sinks
        for key in [k for k in sinks if k[1] == "record" and k[2] == file and k[3] in lines]:
            if scoped:
                del sinks[key]
            elif params:
                rec = sinks[key]
                sinks[key] = rec._replace(needs=rec.needs | frozenset(f"who:{i}" for i in params if i != rec.param))

    def assigned(self, ctx: Ctx, env: Env, v: Val | None, e: N, what: str, named: bool = False) -> None:
        """`v` is written onto a stored record. A flow when it is everything the request sent (`named`: when the
        request chose which field is set); a note for the callers when it is a parameter as it was handed in."""
        if v is None:
            return
        fn = env.fn
        sent = tuple(t for t in v.taints if t.kind == "src" and t.origin != "dom")
        if whole(v) or (named and sent):
            if sent:
                self.hit(ctx, env, "assign", Val(sent), e, what, "LOW")
            return
        if v.kind is None and v.taints and not sent:
            step = (fn.file, e.line, f"`{what}`: here it {R.ACTION['assign']}")
            for t in v.taints:
                if t.kind == "param":
                    ctx.sink(SinkRec(t.key, "assign", t.safe, t.drop, cut(t.steps + (step,)), fn.file, e.line, what,
                                     "LOW", frozenset({"name" if named else "bag"}), fn.node))

    def router_wide(self, e: N, env: Env) -> None:
        """FastAPI: `APIRouter(dependencies=[Depends(f)])` and `include_router(r, dependencies=[Depends(f)])` run `f`
        before every route of that router. Noted for the router's own file, or the file an included router is from."""
        dep = e.kw["dependencies"]
        names = []
        for it in (dep.items or ()) if dep.k == "seq" else ():
            if it.k == "call" and it.items and text_of(it.a).rsplit(".", 1)[-1] in ("Depends", "Security"):
                names.append(text_of(it.items[0]))
        mod = env.fn.mod
        if not names or mod.lang != "py":
            return
        target = mod
        if text_of(e.a).endswith("include_router") and e.items:
            d = mod.imports.get(text_of(e.items[0]).split(".")[0])
            if d:
                full = self.absolute(mod, d)
                target = self.py_mods.get(full) or self.py_mods.get(full.rpartition(".")[0]) or mod
        have = self.wide.setdefault(target.file, [])
        for n in names:
            pair = (n, self.fn_named(mod, n))
            if pair not in have:
                have.append(pair)

    @staticmethod
    def written_keys(it: N | None, env: Env):
        """For a loop over an object whose keys are written in the code (`{"name": x}`, nothing spread into it):
        ("pairs" | "keys", the object). None for anything else, where a key may be the request's own choice."""
        if it is None:
            return None
        form, of = "keys", it
        if it.k == "call" and it.a is not None:
            if it.a.k == "attr" and it.a.name in ("items", "keys") and not it.items:
                form, of = ("pairs" if it.a.name == "items" else "keys"), it.a.a
            elif text_of(it.a) in ("Object.entries", "Object.keys") and it.items:
                form, of = ("pairs" if it.a.name == "entries" else "keys"), it.items[0]
            else:
                return None
        if of is None or of.k != "name":
            return None
        v = env.vars.get(of.name)
        if v is None or v.kind != "obj" or any(k in R.WHOLE_KEYS and whole(x) for k, x in v.data.items()) \
                or "..." in v.data:
            return None
        return form, v

    def before_of(self, fn: Fn) -> set:
        """The checks made by what runs before a route's own code: its dependencies, its decorators, its middleware,
        a hook that runs before every request of its file. From the function's own summary where the project holds
        it (a `require_admin` that asks nothing counts for nothing); by its name where it is a library's."""
        ev: set = set()

        def take(name: str, key) -> None:
            s = self.summ.get(key) if key is not None else None
            if s is not None:
                ev.update(s.ev)
            elif key is None:
                last = name.rsplit(".", 1)[-1]
                if R.ROLE_NAME.search(last):
                    ev.add("owner" if _re.search(r"owner|owns", last, _re.I) else "role")
        for name, key in (self.before.get(fn.key) or {}).items():
            take(name, key)
        for name, key in self.wide.get(fn.file, ()):
            take(name, key)
        for dec in fn.decorators:
            if R_ROUTE.search(dec):
                for m in _re.finditer(r"(?:Depends|Security)\(\s*([A-Za-z_][\w.]*)", dec):
                    take(m.group(1), self.fn_named(fn.mod, m.group(1)))
                continue
            m = _re.match(r"@?\s*([A-Za-z_$][\w.$]*)", dec)
            if m:
                take(m.group(1), self.fn_named(fn.mod, m.group(1)))
        entry = self.entry(fn) or {}
        for mid in [*(entry.get("middleware") or ()), *(u.get("id") for u in entry.get("use") or ())]:
            f2 = self.by_node.get(mid) if isinstance(mid, str) else None
            if f2 is not None:
                take(f2.name, f2.key)
            elif isinstance(mid, str):
                take(_re.split(r"[:/]", mid)[-1], None)
        for f2 in fn.mod.fns:       # Flask: `@app.before_request` runs before every route of the app
            if f2 is not fn and any("before_request" in x or "before_app_request" in x for x in f2.decorators):
                take(f2.name, f2.key)
        return ev

    def authz(self) -> list:
        """Per route: the records it reaches by an id from the request with nothing that compares the record's owner
        with who is signed in, and whether it is an admin route that asks for no admin. Whether anyone is signed in
        at all is asked where the findings are made (`flowscan`), with the login check every other rule uses."""
        out = []
        for _key, (fn, az) in sorted(self.routes.items(), key=lambda kv: (kv[0][0], kv[0][1], str(kv[0][2]))):
            if fn.node is None:
                continue
            pre = self.before_of(fn)
            ev = set(az.ev) | pre
            detail = (self.entry(fn) or {}).get("detail") or fn.name
            signs_in = sign_in_route(detail)
            records = []
            for r in az.records.values():
                picked_by = named(r["source"]["what"])
                if not R.ID_NAME.search(picked_by):
                    continue        # a search word, a page number: it picks no one's record
                if signs_in and R.LOGIN_NAME.match(picked_by):
                    continue        # signing in, signing up, a new password: a person is looked up by the name typed
                # a record that is changed or removed: only what was asked before it counts
                have = (set(r["had"]) | pre) if r["change"] else ev
                if not ({"owner", "role"} & have):
                    records.append(r)
            # what the route decides on the visitor's own word, where no role of the signed-in person is asked
            client = [] if "role" in ev else sorted({x[1:] for x in ev if isinstance(x, tuple) and x[0] == "client"})
            # the admins' own sign-in page cannot ask for an admin; a route that asks the visitor is the finding above
            role = bool(R.ADMIN_PATH.search(detail)) and "role" not in ev and signs_in != "end" and not client
            if records or role or client:
                records.sort(key=lambda r: (r["file"], r["line"], r["source"]["file"], r["source"]["line"]))
                out.append({"node": fn.node, "file": fn.file, "line": fn.line, "detail": detail,
                            "records": records, "role": role,
                            "client": [{"file": f, "line": ln, "what": w, "name": (self.sent.get((f, ln, w)) or ("",))[0],
                                        "part": (self.sent.get((f, ln, w)) or ("", ""))[1]} for f, ln, w in client]})
        return out

    # ---- library calls: sanitizers, sensitive actions, what passes a value on
    def lib(self, e: N, env: Env, ctx: Ctx, canon, member, recv, recv_expr, callee: Val, args: list, kw: dict,
            cb_ret) -> Val:
        fn = env.fn
        name = canon or ""
        vals = [a for a in args if a is not None]
        a0 = args[0] if args and args[0] is not None else None
        what = text_of(e.a)[:60] + "()"
        tainted_args = any(v.taints for v in vals) or any(v.taints for v in kw.values())
        if fn.lang == "js" and member in R.TYPE_SETTERS:
            # `res.type("text/plain")` / `res.set("Content-Type", "application/json")`: from here on, on this way
            # through the function, what `res` sends is no page (or is one again)
            root = self.answer_of(recv_expr)
            kind = self.kind_said(member, args) if root else None
            if kind is True:
                env.narrow[root + ".#type"] = frozenset({"xss"})
            elif kind is False:
                env.narrow.pop(root + ".#type", None)
        # request data read through a call: request.args.get("q"), req.get("host"), request.get_json()
        if recv is not None and recv.kind == "bag" and member not in R.MUTATORS:
            key = (e.items[0].a if e.items and e.items[0].k == "const" else None)
            if member in R.KEEP_SUBJECT or (self.same_address(member, tainted_args) and
                                            any(t.safe & R.OWN_MARKS for t in recv.taints)):
                return Val(recv.taints)     # `req.nextUrl.clone()`, `request.url.replace("http://", "https://")`
            return self.leaf(recv, key, e, env)
        if callee.kind in ("bag", "upload") and recv is not None and recv.kind == "req":
            if fn.lang == "js" and member in ("get", "header") and e.items and e.items[0].k == "const" and \
                    isinstance(e.items[0].a, str):      # Express: `req.get("X-Role")` reads a header by its name
                for t in callee.taints:
                    if t.kind == "src":
                        self.sent[t.key] = (e.items[0].a, "headers")
            return callee
        if recv is not None and recv.kind == "upload":
            if member in R.UPLOAD_SAVE and a0 is not None:
                self.hit(ctx, env, "path", a0, e, what, "MEDIUM")
                if e.items and e.items[0].k == "name":       # from here on that file holds what was uploaded
                    nm = e.items[0].name
                    content = tuple(t._replace(safe=t.safe | CONTENT) for t in recv.taints)
                    env.vars[nm] = env.vars.get(nm, UNKNOWN).but(taints=merge(env.vars.get(nm, UNKNOWN).taints,
                                                                               content))
                return UNKNOWN
            return callee if callee.taints else Val(tuple(t._replace(safe=t.safe | CONTENT) for t in recv.taints))
        if fn.lang == "js":
            if name == "require" and a0 is not None and a0.kind == "const" and isinstance(a0.data, str):
                spec = a0.data
                return Val(kind="ext", data=spec[5:] if spec.startswith("node:") else spec)
            if name and name.rsplit(".", 1)[-1] in R.URL_HOOKS:
                words = f"`{what}` reads the page's address, which whoever made the link chose"
                return Val((self.source(fn, e.line, words, origin="dom"),), kind="bag", data="params")
        # 0. who is signed in, handed back by a call whose code Lantern does not read: taken by its name
        last = (name or text_of(e.a)).rsplit(".", 1)[-1]
        if (name and R.IDENT_CALLS.match(name)) or R.IDENT_FN.match(last):
            return Val((Taint("ident", last, R.ALL, (), None, FIXED0),), kind="ext", data=(name or last) + "()")
        # 1. what makes a value safe, and for what
        got = self.sanitizer(name, member, recv_expr)
        if got is not False:
            src = a0 if a0 is not None and (a0.taints or recv is None or not recv.taints) else recv
            if src is None or not src.taints:
                return Val(kind="ext", data=name + "()") if name else UNKNOWN
            if got is None:     # a number or a digest: no text of the caller's is left in it, but it is still
                # the caller's choice (of a record), so its origin is kept
                return Val(tuple(t if t.kind == "ident" else t._replace(safe=t.safe | R.ALL) for t in src.taints))
            words = f"goes through `{what}`: that protects {' and '.join(R.PROTECTS[c] for c in sorted(got))}, " \
                    "not other uses"
            step = (fn.file, e.line, words)
            return Val(tuple(with_step(t._replace(safe=norm(t.safe | got, fn.lang)), step) if t.kind != "ident" else t
                             for t in src.taints), None, src.sql, src.html)
        # 2. sensitive actions
        self.sinks(e, env, ctx, name, member, recv, recv_expr, args, kw, a0, what)
        got = self.reached(e, env, ctx, name, member, recv, recv_expr, args, kw, a0, what)
        if got is not None:
            return got
        if name and R.OVERLAY_CALL.match(name) and vals:
            # `Object.assign({}, a, b)`: one object holding what each of them holds
            data: dict = {}
            for v in vals:
                if v.kind == "obj":
                    data.update(v.data)
                elif v.kind == "bag":
                    data["..."] = v
            made = Val(join_all(vals).taints, kind="obj", data=data)
            first = e.items[0] if e.items else None
            if first is not None and first.k == "name" and a0 is not None and a0.kind in ("obj", None):
                env.vars[first.name] = made         # the first object is the one that is filled
                env.forget(first.name)
            return made
        # 3. what the call gives back
        if name == "lxml.etree.XMLParser":
            r = kw.get("resolve_entities")
            return Val(kind="ext", data="lxml.etree.XMLParser(safe)" if r is not None and r.kind == "const"
                       and r.data is False else "lxml.etree.XMLParser()")
        if name == "re.compile" and a0 is not None and a0.kind == "const":
            return Val(fixed=FIXED0, kind="regex", data=a0.data)
        subbed = None           # re.sub(r"[<>]", "", text) / PATTERN.sub("&lt;", text): every `<` replaced by hand
        if name == "re.sub" and len(args) > 2 and args[2] is not None and args[2].taints:
            subbed = (Val(kind="regex", data=a0.data) if a0 is not None and a0.kind == "const" else a0, args[1], args[2])
        elif member == "sub" and recv is not None and recv.kind == "regex" and len(args) > 1 and \
                args[1] is not None and args[1].taints:
            subbed = (recv, a0, args[1])
        if subbed and subbed[0] is not None and self.replaces_lt(fn, "sub", subbed[0], subbed[1], None, env, ctx):
            step = (fn.file, e.line, f"`{what}` replaces every `<`: that protects {R.PROTECTS['xss']}, not other uses")
            return Val(tuple(t if t.kind == "ident" else with_step(t._replace(safe=norm(t.safe | {"xss"}, fn.lang)), step)
                             for t in subbed[2].taints), None, subbed[2].sql, subbed[2].html)
        every = join_all(vals + list(kw.values()))
        if name and R.RESOLVERS.match(name):
            if name.endswith(".join") and fn.lang == "js" and len(vals) > 1:
                # Node's path.join glues: a part after the first cannot start again at a full path (resolve can)
                rest = join_all(vals[1:])
                later = tuple(t if t.kind == "ident" else t._replace(safe=norm(t.safe | {"path:abs"}))
                              for t in rest.taints)
                every = every.but(taints=merge(vals[0].taints, later))
            return Val(tuple(t._replace(safe=t.safe | {"path:resolved"}) for t in every.taints))
        if member in R.RESOLVER_MEMBERS and recv is not None and recv.taints:
            return Val(tuple(t._replace(safe=t.safe | {"path:resolved"}) for t in recv.taints), kind=recv.kind,
                       data=recv.data)
        if name and R.HOST_OF.match(name):
            return self.address(fn, name, args, every)
        if name and R.PROPAGATORS.match(name):
            taints = disowned(every.taints)
            if name in ("json.loads", "json.load", "JSON.parse", "yaml.safe_load", "ast.literal_eval"):
                taints = tuple(t._replace(safe=t.safe - {"nosql"}) for t in taints)
            return Val(taints, every.fixed if not taints else None, every.sql, every.html, kind="ext",
                       data=name + "()")
        if member in R.ARCHIVE_NAMES and recv is not None and recv.taints:
            return self.entry_names(recv, e, env)
        if member is not None and recv is not None:
            if member in R.MUTATORS and tainted_args and recv_expr is not None and recv_expr.k == "name" \
                    and recv.kind not in ("req", "ext", "self", "upload"):
                old = env.vars.get(recv_expr.name, recv)
                if old.kind == "seq" and member in ("append", "push", "add", "unshift"):
                    env.vars[recv_expr.name] = seq(old.data + vals)
                else:
                    env.vars[recv_expr.name] = Val(merge(old.taints, every.taints), None, old.sql or every.sql,
                                                   old.html or every.html)
                return UNKNOWN
            if member in R.LOOKUP_METHODS and recv.kind not in ("req", "bag", "upload"):
                # a look-up gives back what the collection holds, or the default: never the key it was asked for
                default = args[1] if len(args) > 1 and args[1] is not None else kw.get("default")
                if recv.kind == "obj" and a0 is not None and a0.kind == "const" and str(a0.data) in recv.data:
                    return recv.data[str(a0.data)]
                if recv.kind in ("obj", "seq") and recv.data:
                    inner = join_all(list(recv.data.values()) if recv.kind == "obj" else recv.data)
                else:
                    inner = Val(recv.taints, recv.fixed if recv.kind in ("obj", "seq") else None, recv.sql, recv.html)
                return join(inner, default) if default is not None else inner
            if member in R.ARG_ONLY_METHODS or (member in R.ARG_METHODS and not recv.taints):
                if not tainted_args and not recv.taints and recv.fixed is None:
                    return UNKNOWN
                parts = [recv] + vals + list(kw.values())
                v = concat(parts) if len(parts) > 1 else recv
                return self.built(ctx, env, e, Val(v.taints, v.fixed, v.sql, v.html))
            if recv.taints and recv.kind not in ("req",):
                if member in ("replace", "replaceAll") and len(args) > 1 and \
                        self.replaces_lt(fn, member, args[0], args[1], e.items[1], env, ctx):
                    step = (fn.file, e.line, f"`{what}` replaces every `<`: that protects {R.PROTECTS['xss']}, "
                                             "not other uses")
                    return Val(tuple(t if t.kind == "ident" else
                                     with_step(t._replace(safe=norm(t.safe | {"xss"}, fn.lang)), step)
                                     for t in recv.taints), None, recv.sql, recv.html)
                taints = merge(recv.taints, every.taints) if member in R.ARG_METHODS else recv.taints
                if not self.same_address(member, tainted_args):
                    taints = disowned(taints)       # `url.href.split("next=")[1]`: a part, not the address
                if cb_ret is not None and member in ("map", "flatMap", "then", "reduce"):
                    taints = merge(taints, cb_ret.taints)
                if member in ("toString", "valueOf") or member in R.SANITIZER_MEMBERS:
                    pass
                return Val(taints, None, recv.sql, recv.html, kind=recv.kind if recv.kind == "ext" else None,
                           data=f"{recv.data}.{member}()" if recv.kind == "ext" else None)
        if cb_ret is not None and member in ("map", "flatMap", "then", "reduce"):
            return Val(cb_ret.taints)
        if any(t.kind != "ident" and not R.ALL <= t.safe for v in vals + list(kw.values()) for t in v.taints):
            self.stats["stopped"] += 1
        if name and R.OPEN_CALL.match(name) and e.items:
            mode = args[1] if len(args) > 1 and args[1] is not None else kw.get("mode")
            if mode is not None and mode.kind == "const" and isinstance(mode.data, str) and \
                    set(mode.data) & set("wax+") and self.template_file(e.items[0], env):
                return Val(kind="ext", data="open(template)")       # what is written to it becomes a template
        if callee.kind == "ext" and name:
            return Val(kind="ext", data=name + "()")
        return UNKNOWN

    def template_file(self, e: N, env: Env) -> bool:
        """Whether the path written here names a file in the folder the template engine reads: by the text of the
        path (`.../templates/...`, Express's `views`), through the names set at the top of the file and in this
        function, or by a name that says so (`TEMPLATE_DIR`). A file whose name ends like data (`.json`) is none."""
        fn = env.fn
        lits: list = []
        names: list = []
        todo, seen = [e], set()
        local = None
        while todo and len(seen) < 24:
            for x in every_node(todo.pop()):
                if x.k == "const" and isinstance(x.a, str):
                    lits.append(x.a)
                elif x.k == "attr":
                    names.append(x.name)
                elif x.k == "name" and x.name not in seen:
                    seen.add(x.name)
                    names.append(x.name)
                    todo.extend(fn.mod.consts.get(x.name, ()))
                    if local is None:
                        local = {}
                        for s in every_node(fn.body or ()):
                            if s.k == "assign" and isinstance(s.a, N):
                                for t in s.items or ():
                                    for n in names_in(t):
                                        local.setdefault(n, []).append(s.a)
                    todo.extend(local.get(x.name, ()))
        ext = next((m.group(1).lower() for m in (R.FILE_EXT.search(s) for s in reversed(lits)) if m), None)
        if ext is not None and ext not in R.TEMPLATE_EXT:
            return False
        return any(R.TEMPLATE_DIR[fn.lang].search(s) for s in lits) or \
            any(R.TEMPLATE_DIR_NAME[fn.lang].search(n) for n in names)

    def saved_template(self, ctx: Ctx, env: Env, v: Val | None, e: N, what: str) -> None:
        """Text written into a template file: the template engine runs it when the page is rendered. Read from the
        path's names, so a heuristic."""
        if v is None or not v.taints:
            return
        step = (env.fn.file, e.line, "is written into a file of the templates folder, and the template engine runs "
                                     "what that file says when the page is rendered")
        self.hit(ctx, env, "eval", stepped(v, step), e, what, "LOW")

    @staticmethod
    def same_address(member: str | None, tainted_args: bool) -> bool:
        """Whether a call on an address gives the same address back (a copy, its text, its text with fixed text
        swapped for fixed text) and not a part of it."""
        return member in R.OWN_KEEP or (member in ("replace", "replaceAll") and not tainted_args)

    @staticmethod
    def address(fn: Fn, name: str, args: list, every: Val) -> Val:
        """A parsed address. `new URL(page, base)` goes to the site of `base` unless `page` is a whole address or
        starts with two slashes: a page that begins with written text of one slash and more cannot be, so what
        follows in it does not say where the address goes; a base that is the address the request was made to names
        this site. `new URL(req.url)` is that address again."""
        if fn.lang != "js" or name not in ("URL", "new URL"):
            return Val(every.taints, kind="ext", data=name + "()")
        page = args[0] if args else None
        base = args[1] if len(args) > 1 else None
        mine = page.taints if page is not None else ()
        if base is None:
            mine = tuple(t._replace(safe=(t.safe - {"redirect:base"}) | {"redirect:own"})
                         if "redirect:base" in t.safe else t for t in mine)
            return Val(mine, kind="ext", data=name + "()")
        if R.local_path(page.prefix if page is not None else None):
            mine = tuple(t if t.kind == "ident" else t._replace(safe=t.safe | R.URLS) for t in mine)
        else:       # a whole address of its own, for all the code shows: `req.url` in Express may start with `//`
            mine = tuple(t._replace(safe=t.safe - {"redirect:base"}) if "redirect:base" in t.safe else t for t in mine)
        site = tuple(t._replace(safe=(t.safe - {"redirect:base"}) | {"redirect:own"})
                     if "redirect:base" in t.safe else t for t in base.taints)
        return Val(merge(mine, site), kind="ext", data=name + "()")

    def replaces_lt(self, fn: Fn, member: str, pat: Val | None, rep: Val | None, rep_e: N | None, env: Env,
                    ctx: Ctx) -> bool:
        """An escape written by hand: every `<` of the value is replaced, and by text that holds none. In JavaScript
        `replace` with a text, or with a pattern without `g`, replaces the first one only."""
        if pat is None:
            return False
        if pat.kind == "regex":
            if fn.lang == "js" and member == "replace" and "g" not in getattr(pat.data, "flags", ""):
                return False
            if not isinstance(pat.data, str) or not R.covers_lt(pat.data):
                return False
        elif pat.kind == "const" and pat.data == "<":
            if fn.lang == "js" and member != "replaceAll":
                return False
        else:
            return False
        if rep is not None and rep.kind == "const" and isinstance(rep.data, str):
            return "<" not in rep.data
        # (c) => TABLE[c]: a table written in the code, which gives text without `<` for `<`
        f = rep_e.a if rep_e is not None and rep_e.k == "fn" else None
        body = f.body if isinstance(f, Fn) and f.body and len(f.body) == 1 and f.params else None
        ret = body[0].a if body and body[0].k == "return" else None
        if ret is not None and ret.k == "index" and ret.a is not None and ret.a.k == "name" and \
                ret.b is not None and ret.b.k == "name" and ret.b.name == f.params[0].name:
            table = self.lookup(ret.a.name, env, ctx)
            to = table.data.get("<") if table.kind == "obj" and isinstance(table.data, dict) else None
            return to is not None and to.kind == "const" and isinstance(to.data, str) and "<" not in to.data
        return False

    @staticmethod
    def answer_of(recv_expr: N | None) -> str | None:
        """`res` for `res`, `res.status(200)`, `res.status(200).type("txt")`: the answer a chain of calls is made on."""
        x = recv_expr
        for _ in range(8):
            if x is None:
                return None
            if x.k == "name":
                return x.name if x.name in R.RESPONSE_NAMES else None
            if x.k == "call" and x.a is not None and x.a.k == "attr":
                x = x.a.a
                continue
            return None
        return None

    @staticmethod
    def kind_said(member: str, args: list) -> bool | None:
        """What a call on an answer says about its kind: True, no page; False, a page; None, nothing."""
        vals = [a for a in args]
        a0 = vals[0] if vals else None
        if a0 is None:
            return None
        if member in ("type", "contentType"):
            return R.not_a_page(a0.data) if a0.kind == "const" else None
        boxes = [a for a in vals if a is not None and a.kind == "obj" and isinstance(a.data, dict)]
        if a0.kind == "const" and isinstance(a0.data, str) and member != "writeHead":
            if a0.data.lower() != "content-type" or len(vals) < 2 or vals[1] is None:
                return None
            return R.not_a_page(vals[1].data) if vals[1].kind == "const" else None
        for box in boxes:       # res.set({ "Content-Type": ... }) / res.writeHead(200, { "Content-Type": ... })
            for key, v in box.data.items():
                if str(key).lower() == "content-type":
                    return R.not_a_page(v.data) if v.kind == "const" else None
        return None

    def no_page(self, e: N, env: Env, args_of) -> bool:
        """Whether the answer `e` sends was said to be something else than a page: in the chain of calls the send is
        made on (`res.type("txt").send(x)`, the nearest one counts), or earlier on every way here."""
        x = e.a.a if e.a is not None and e.a.k == "attr" else None
        for _ in range(8):
            if x is None or x.k != "call" or x.a is None or x.a.k != "attr":
                break
            if x.a.name in R.TYPE_SETTERS:
                kind = self.kind_said(x.a.name, args_of(x))
                if kind is not None:
                    return kind
            x = x.a.a
        root = self.answer_of(e.a.a if e.a is not None and e.a.k == "attr" else None)
        return bool(root) and "xss" in env.narrow.get(root + ".#type", FIXED0)

    def sanitizer(self, name: str, member, recv_expr):
        """The kinds of action the call makes a value safe for; None for every kind; False when it is no sanitizer."""
        if name:
            for pat, classes in SANITIZERS:
                if pat.search(name):
                    return None if classes is None else frozenset(classes)
            return False
        if member in R.SANITIZER_MEMBERS:
            c = R.SANITIZER_MEMBERS[member]
            return None if c is None else frozenset(c)
        if member == "escape" and recv_expr is not None:
            return frozenset({"sql"}) if R.SQL_RECEIVERS.search(text_of(recv_expr)) else frozenset({"xss"})
        return False

    def sinks(self, e: N, env: Env, ctx: Ctx, name: str, member, recv, recv_expr, args: list, kw: dict, a0,
              what: str) -> None:
        fn = env.fn
        py = fn.lang == "py"

        def arg(i, *names):
            for n in names:
                if n in kw:
                    return kw[n]
            return args[i] if i < len(args) and args[i] is not None else None

        def flag(v, key):
            x = kw.get(key) if py else (v.data.get(key) if v is not None and v.kind == "obj" else None)
            return x is not None and x.kind == "const" and x.data is True
        last = next((a for a in reversed(args) if a is not None and a.kind == "obj"), None)
        # --- database queries
        q = arg(0, "sql", "query", "statement", "operation")
        if name and R.SQL_CALL.match(name):
            if q is not None:
                free = name.rsplit(".", 1)[-1] in ("execute", "executemany", "executescript", "exec_driver_sql",
                                                    "$queryRawUnsafe", "$executeRawUnsafe", "execute_sql")
                self.hit(ctx, env, "sql", q, e, what, "HIGH", FIXED0 if free else frozenset({"sql"}))
        elif member in R.SQL_MEMBERS and q is not None and (not name or not R.NOT_SQL.match(name)):
            self.hit(ctx, env, "sql", q, e, what, "MEDIUM", frozenset({"sql"}))
        # --- commands
        if name and R.SHELL_ALWAYS.match(name):
            self.hit(ctx, env, "shell", arg(0, "cmd", "command", "args"), e, what)
        elif name and R.SHELL_PROGRAM.match(name):
            c = arg(0, "args", "cmd", "command", "file")
            if c is not None:
                if flag(last, "shell"):
                    self.hit(ctx, env, "shell", c, e, what)
                elif c.kind == "seq":
                    if c.data:
                        self.hit(ctx, env, "shell", c.data[0], e, what)
                else:
                    self.hit(ctx, env, "shell", c, e, what)
        # --- code and templates
        if name and R.EVAL_CALL.match(name) and a0 is not None:
            code = a0
            if name in ("Function", "new Function"):       # every argument is code: the names, then the body
                code = join_all([a for a in args if a is not None])
            if name not in ("require", "compile", "__import__") or (a0.taints and a0.kind != "const"):
                self.hit(ctx, env, "eval", code, e, what, "HIGH" if name != "require" else "MEDIUM")
        elif member == "from_string" and a0 is not None and not name:
            self.hit(ctx, env, "eval", a0, e, what, "MEDIUM")
        # --- stored objects
        if name and R.DESERIALIZE_CALL.match(name) and a0 is not None:
            ok = True
            if name.startswith("yaml.") and name.rsplit(".", 1)[-1] in ("load", "load_all"):
                loader = arg(1, "Loader")
                ok = not (loader is not None and isinstance(loader.data, str) and R.YAML_SAFE.search(loader.data))
            elif name == "numpy.load":
                ok = flag(None, "allow_pickle")
            elif name == "torch.load":
                ok = not flag(None, "weights_only")
            if ok:
                self.hit(ctx, env, "deserialize", a0, e, what)
        # --- XML
        if name and R.XXE_CALL.match(name) and a0 is not None:
            parser = arg(1, "parser")
            safe = parser is not None and isinstance(parser.data, str) and parser.data.endswith("(safe)")
            if R.XXE_NEEDS_OPTION.match(name):
                safe = not flag(last, "noent")
            if not safe:
                self.hit(ctx, env, "xxe", a0, e, what, "HIGH" if name.startswith(("lxml", "libxml")) else "MEDIUM")
        # --- text saved as a template
        if member in ("write", "writelines") and recv is not None and recv.kind == "ext" and \
                recv.data == "open(template)":
            self.saved_template(ctx, env, a0, e, what)
        elif member == "write_text" and recv_expr is not None and py and self.template_file(recv_expr, env):
            self.saved_template(ctx, env, a0, e, what)
        elif name and R.FILE_WRITE.match(name) and len(args) > 1 and e.items and \
                self.template_file(e.items[0], env):
            self.saved_template(ctx, env, args[1], e, what)
        # --- files
        if name and R.TAR_EXTRACT.match(name):
            src = recv if name.startswith("tarfile") else a0
            if src is not None and src.taints and "filter" not in kw:
                self.hit(ctx, env, "path", self.entry_names(src, e, env), e, what)
        elif name and R.PATH_CALL.match(name):
            p = arg(0, "file", "path", "filename", "name")
            if p is not None and not (last is not None and "root" in last.data):
                self.hit(ctx, env, "path", p, e, what)
            if R.PATH_BOTH_ARGS.search(name) and len(args) > 1 and args[1] is not None:
                self.hit(ctx, env, "path", args[1], e, what)
        elif not name and member in R.PATH_MEMBERS:
            if a0 is not None and member not in ("read_text", "read_bytes", "unlink", "rmdir", "iterdir") \
                    and not (last is not None and "root" in last.data):
                self.hit(ctx, env, "path", a0, e, what, "MEDIUM")
            elif recv is not None and recv.taints and member in ("read_text", "read_bytes", "write_text",
                                                                 "write_bytes", "unlink", "rmdir", "iterdir"):
                self.hit(ctx, env, "path", recv, e, what, "MEDIUM")
        elif recv is not None and recv.kind == "ext" and isinstance(recv.data, str) and recv.data.startswith("pathlib.") \
                and member in (R.PATH_MEMBERS | R.PATHLIB_MEMBERS) and recv.taints:
            self.hit(ctx, env, "path", recv, e, what)
        # --- outbound requests
        if name and R.SSRF_CALL.match(name):
            u = arg(0, "url")
            if "url" not in kw and len(args) > 1 and args[1] is not None and (
                    R.SSRF_URL_SECOND.search(name) or (a0 is not None and a0.kind == "const"
                                                       and str(a0.data).lower() in R.HTTP_VERBS)):
                u = args[1]
            if u is not None and u.kind == "obj":
                u = next((u.data[k] for k in ("url", "uri", "href", "baseURL", "hostname", "host") if k in u.data),
                         None)
            if u is not None and not R.host_fixed(u.prefix):
                self.hit(ctx, env, "ssrf", u, e, what, "HIGH", frozenset({"nohost"}))
        # --- pages
        if (name and R.RENDER_CALL.match(name)) or (not name and member == "render" and self.answer_of(recv_expr)):
            self.rendered(ctx, env, e, args, kw, what)
        if name and R.XSS_CALL.match(name):
            v = arg(0, "content", "text", "body", "response")
            if name.endswith("insertAdjacentHTML") and len(args) > 1:
                v = args[1]
            ctype = next((kw[k] for k in ("content_type", "mimetype", "media_type") if k in kw), None)
            not_html = ctype is not None and (ctype.kind != "const" or R.XSS_NOT_HTML.search(str(ctype.data)))
            if name.startswith("aiohttp") or name.startswith("werkzeug"):
                not_html = not (ctype is not None and ctype.kind == "const" and "html" in str(ctype.data))
            if py and id(e) in self.plain_calls:
                not_html = True
            if not py and not not_html and member in R.RESPONSE_SEND:
                not_html = self.no_page(e, env, lambda c: [self.eval(i, env, ctx) for i in c.items or ()])
            if v is not None and stringy(v) and not not_html:
                self.hit(ctx, env, "xss", v, e, what, "HIGH" if v.html else "MEDIUM")
        elif not name and member in R.RESPONSE_SEND and self.answer_of(recv_expr) and a0 is not None \
                and stringy(a0) and not self.no_page(e, env, lambda c: [self.eval(i, env, ctx) for i in c.items or ()]):
            self.hit(ctx, env, "xss", a0, e, what, "MEDIUM")
        # --- redirects
        if name and R.REDIRECT_CALL.match(name):
            v = next((a for a in reversed(args) if a is not None and not (a.kind == "const" and
                                                                           isinstance(a.data, (int, float)))), None)
            v = kw.get("url", kw.get("location", v)) if kw else v
            self.redirect(ctx, env, v, e, what, "HIGH")
        elif not name and member == "redirect" and recv_expr is not None and recv_expr.k == "name" \
                and recv_expr.name in (R.RESPONSE_NAMES | {"ctx", "self"}):
            v = next((a for a in reversed(args) if a is not None and not (a.kind == "const" and
                                                                           isinstance(a.data, (int, float)))), None)
            self.redirect(ctx, env, v, e, what, "MEDIUM")
        # --- database filters that are objects
        if member in R.NOSQL_MEMBERS and a0 is not None and (not name or R.NOSQL_LIBS.match(name)):
            conf = "MEDIUM" if name else "LOW"
            if a0.kind == "obj":
                for key, fv in a0.data.items():
                    if key in R.NOSQL_CODE_KEYS:        # the database runs this text as code: text is no protection
                        fv = fv.but(taints=tuple(t if t.kind == "ident" else t._replace(safe=t.safe - {"nosql"})
                                                 for t in fv.taints))
                        self.hit(ctx, env, "nosql", fv, e, what, conf)
                    elif fv.kind not in ("obj", "seq"):
                        self.hit(ctx, env, "nosql", fv, e, what, conf)
            elif a0.kind == "bag":
                self.hit(ctx, env, "nosql", a0, e, what, conf)
        # --- objects merged into the app's own
        if name and R.POLLUTION_CALL.match(name) and (not R.POLLUTION_PLAIN.match(name) or "." in name):
            for v in args[1:]:
                if v is not None and v.kind in ("bag", None, "obj"):
                    self.hit(ctx, env, "pollution", v, e, what, "LOW")

    def redirect(self, ctx: Ctx, env: Env, v: Val | None, e: N, what: str, conf: str) -> None:
        if v is None or not stringy(v) or R.stays(v.prefix):
            return
        self.hit(ctx, env, "redirect", v, e, what, conf, frozenset({"nolocal"}))

    def page(self, ctx: Ctx, env: Env, node: N, val: Val) -> None:
        """What a Flask route returns is sent as a page: text with request data in it is the page's own HTML."""
        if node.k == "seq" and val.kind == "seq" and val.data:
            for h in val.data[1:]:          # return text, 200, {"Content-Type": "text/plain"}
                if h.kind == "obj" and self.kind_said("set", [h]) is True:
                    return
            val = val.data[0]
        if node.k in ("map", "call") or not stringy(val) or val.kind == "ext":
            return
        self.hit(ctx, env, "xss", val, node, "return", "HIGH" if val.html else "MEDIUM")

    def pages(self) -> dict:
        if self._pages is None:
            from . import templates
            try:
                self._pages = templates.index(self.repo)
            except OSError:
                self._pages = {}
        return self._pages

    def rendered(self, ctx: Ctx, env: Env, e: N, args: list, kw: dict, what: str) -> None:
        """A page rendered from a template file: a value the route hands in under a name the file prints without
        escaping is sent to the browser as it is. The finding is at the place in the template, where the fix goes."""
        pages = self.pages()
        if not pages:
            return
        from . import templates
        at = next((i for i, a in enumerate(args) if a is not None and a.kind == "const" and isinstance(a.data, str)),
                  None)
        if at is None:
            return
        files = templates.named(pages, args[at].data)
        given = [a for a in args[at + 1:] if a is not None] + [v for k, v in kw.items() if k in ("context", "**")]
        named_ = {k: v for k, v in kw.items() if k not in ("context", "**", "request", "status", "content_type")}
        for rel in files:
            for raw in pages[rel]:
                for root in raw.roots:
                    v = named_.get(root)
                    for g in given:
                        if g.kind == "obj":
                            x = g.data.get(root)
                            if x is None and "..." in g.data:       # { ...req.query, title: 'x' }
                                x = g.data["..."]
                        else:
                            x = g if g.kind not in ("req", "const", "fn", "self") else None
                        v = x if v is None else v if x is None else join(v, x)
                    # for the template's own finding: is what this call hands over text written in the code, or
                    # made safe for a page? Anything else (a database row, nothing under that name) is open
                    known = v is not None and (bool(v.taints) or v.fixed == FIXED0) and not any(
                        t.kind == "ident" or not safe_for("xss", t.safe) for t in v.taints)
                    self.handed_pages.setdefault((rel, raw.line), {})[(env.fn.file, e.line, root)] = \
                        "safe" if known else "open"
                    if v is None or not v.taints:
                        continue
                    step = (env.fn.file, e.line, f"is handed to the page `{rel}` as `{root}`")
                    self.hit(ctx, env, "xss", stepped(Val(v.taints), step), e,
                             f"{raw.shown} ({raw.way} prints without escaping)", "MEDIUM", at=(rel, raw.line))

    def hit(self, ctx: Ctx, env: Env, cls: str, val: Val | None, node: N, what: str, conf: str = "HIGH",
            needs: frozenset = FIXED0, at: tuple | None = None) -> None:
        """`val` reaches a sensitive action of kind `cls` here (or, with `at`, at that file and line: a place in a
        template the code hands the value to)."""
        if val is None:
            return
        fn = env.fn
        if cls in ("sql", "shell"):
            ctx.top.points.setdefault((fn.file, node.line), []).append((cls, val))
        if not val.taints:
            return
        file, line = at or (fn.file, node.line)
        step = (file, line, f"`{what}`: here it {R.ACTION[cls]}")
        need_sql = "sql" in needs and not val.sql
        for t in val.taints:
            if t.kind == "ident" or safe_for(cls, t.safe) or (t.origin == "dom" and cls not in DOM_OK):
                continue
            if cls == "nosql" and t.kind == "src" and "nosql" in t.safe:
                continue
            if t.kind == "src":
                if not need_sql:
                    ctx.flow(cls, t, cut(t.steps + (step,)), conf, what, file, line, fn.node)
            else:
                keep = frozenset(n for n in needs if (n == "sql" and need_sql) or (n in URL_NEEDS and not val.prefix))
                ctx.sink(SinkRec(t.key, cls, t.safe, t.drop, cut(t.steps + (step,)), file, line, what, conf,
                                 keep, fn.node))

    # ---- what a condition proves
    def subject(self, e: N | None, env: Env, depth: int = 0):
        """(name the condition is about, relation) : relation "host" when it is about the host of an address."""
        if e is None or depth > 5:
            return None
        if e.k == "attr" and e.name in R.HOST_ATTRS and e.a is not None:
            inner = self.parsed(e.a, env, depth + 1)
            if inner:
                return (inner[0], "host")
            if e.a.k == "name" and env.derived.get(e.a.name, ("", ""))[0] == "url":
                return (e.a.name, "host")
        if e.k == "call" and e.a is not None and e.a.k == "attr" and e.a.name in R.KEEP_SUBJECT:
            return self.subject(e.a.a, env, depth + 1)
        if e.k == "call" and e.a is not None and e.a.k == "name" and e.a.name in ("str", "String") and \
                len(e.items or ()) == 1 and e.a.name not in env.vars:
            return self.subject(e.items[0], env, depth + 1)
        if e.k == "bool" and e.name in ("or", "||", "??"):      # `x or ""`: x, or fixed text when there is none
            rest = [x for x in e.items or () if x.k != "const"]
            if len(rest) == 1 and len(e.items) > 1:
                return self.subject(rest[0], env, depth + 1)
        p = path_of(e)
        return (p, None) if p else None

    def parsed(self, e: N | None, env: Env, depth: int = 0):
        """For `urlparse(x)` / `new URL(x)`: what `x` is, as `subject` says it."""
        if e is None or e.k != "call" or not e.items or e.a is None:
            return None
        head = text_of(e.a)
        canon = self.canon_of(e, env)
        if R.HOST_OF.match(canon or head) or head.rsplit(".", 1)[-1] in ("urlparse", "urlsplit", "URL"):
            return self.subject(e.items[0], env, depth + 1)
        return None

    def about(self, e: N | None, env: Env, depth: int = 0):
        """(kind, name) when the value of `e` tells where `name` leads: "addr", an address that `name` (an address or
        a host name) was looked up as; "host", its host; "is", the same value read as an IP address."""
        if e is None or depth > 6:
            return None
        k = e.k
        if k == "name":
            d = env.derived.get(e.name)
            return d if d and d[0] == "addr" else None
        if k in ("attr", "index"):
            root = e
            while root is not None and root.k in ("attr", "index"):
                root = root.a
            return self.about(root, env, depth + 1) if root is not None and root.k in ("name", "call") else None
        if k != "call" or not e.items or e.a is None:
            return None
        canon = self.canon_of(e, env) or text_of(e.a)
        a0 = e.items[0]
        if R.LOOKUP.search(canon):
            sub = self.subject(a0, env)
            return ("addr", sub[0]) if sub else None
        if R.IP_PARSE.match(canon):
            inner = self.about(a0, env, depth + 1)
            if inner:
                return inner
            sub = self.subject(a0, env)
            return ("host" if sub[1] == "host" else "is", sub[0]) if sub else None
        return None

    def ip_subject(self, e: N | None, env: Env):
        """The name a question to an IP address (`.is_private`) is about, or None when `e` is no such address."""
        if e is None:
            return None
        if e.k == "name":
            return e.name if env.derived.get(e.name, ("", ""))[0] in ("addr", "is") else None
        ab = self.about(e, env)
        return ab[1] if ab else None

    def canon_of(self, call: N, env: Env) -> str | None:
        f = call.a
        parts = []
        while f is not None and f.k == "attr":
            parts.append(f.name)
            f = f.a
        if f is None or f.k != "name" or f.name in env.vars:
            return None
        d = env.fn.mod.imports.get(f.name, f.name)
        return ".".join([d] + list(reversed(parts)))

    def facts(self, e: N | None, env: Env, ctx: Ctx):
        """What is known when the condition holds, and when it does not: two lists of (name, kinds, fixed, relation)."""
        if e is None:
            return (), ()
        k = e.k
        if k == "not":
            t, f = self.facts(e.a, env, ctx)
            return f, t
        if k == "bool":
            parts = [self.facts(x, env, ctx) for x in e.items]
            ts, fs = [p[0] for p in parts], [p[1] for p in parts]
            if e.name in ("and", "&&"):
                return union(ts), both(fs)
            return both(ts), union(fs)
        if k == "cmp":
            return self.cmp_facts(e, env, ctx)
        if k == "call":
            return self.call_facts(e, env, ctx)
        asked = e.a if k == "call" and e.a is not None and e.a.k == "attr" and not e.items else e if k == "attr" \
            else None                               # `addr.is_private`, and netaddr's `addr.is_private()`
        if asked is not None and (asked.name in R.IP_BLOCK_ATTRS or asked.name in R.IP_ALLOW_ATTRS):
            # asked of an IP address only: `repo.is_private` is another question
            sub = self.ip_subject(asked.a, env)
            if not sub:
                return (), ()
            fact = ((sub, SSRF, False, None),)
            return ((), fact) if asked.name in R.IP_BLOCK_ATTRS else (fact, ())
        if k == "name" and e.name in env.flags:
            return env.flags[e.name]
        if k in ("name", "attr", "index"):
            sub = self.subject(e, env)
            if sub and sub[1] == "host":       # `if urlparse(x).netloc:` : no host means an address on this site
                return (), ((sub[0], frozenset({"redirect"}), False, None),)
            if k == "name" and env.derived.get(e.name, ("", ""))[0] == "host":
                return (), ((env.derived[e.name][1], frozenset({"redirect"}), False, None),)
        return (), ()

    def cmp_facts(self, e: N, env: Env, ctx: Ctx):
        op = e.name
        a, b = e.a, e.b
        if op in ("in", "not in"):
            out: tuple = ()
            if a.k == "const" and a.a == "..":
                sub = self.subject(b, env)
                if sub and sub[1] is None:
                    out = ((sub[0], frozenset({"path:dots"}), False, None),)
                return ((), out) if op == "in" else (out, ())
            sub = self.subject(a, env)
            box = self.eval(b, env, ctx)
            if sub and not box.taints and box.kind not in ("req", "bag"):
                out = ((sub[0], R.ALL, box.fixed is not None and not box.fixed, sub[1]),)
            return (out, ()) if op == "in" else ((), out)
        if op in ("==", "===", "is", "!=", "!==", "is not"):
            out = ()
            for x, y in ((a, b), (b, a)):
                if x.k == "name" and x.name in env.flags and y.k == "const" and y.a in (None, False):
                    yes, no = env.flags[x.name]      # `found is None`: the answer was no
                    return (no, yes) if op in ("==", "===", "is") else (yes, no)
                if x.k == "typeof":
                    if y.k == "const" and y.a in ("number", "boolean", "bigint", "string"):
                        sub = self.subject(x.a, env)
                        if sub and sub[1] is None:
                            out = ((sub[0], R.ALL if y.a != "string" else frozenset({"nosql"}), False, None),)
                    break
                if x.k == "call" and x.a.k == "attr" and x.a.name == "indexOf" and x.items and \
                        x.items[0].k == "const" and x.items[0].a == ".." and y.k in ("const", "arith"):
                    sub = self.subject(x.a.a, env)
                    if sub and sub[1] is None:
                        out = ((sub[0], frozenset({"path:dots"}), False, None),)
                    break
                if x.k == "call" and x.a.k == "attr" and x.a.name == "range" and not x.items and \
                        y.k == "const" and y.a == "unicast":      # ipaddr.parse(address).range() === 'unicast'
                    ab = self.about(x.a.a, env)
                    if ab:
                        out = ((ab[1], SSRF, False, None),)
                    break
                if x.k == "call" and text_of(x.a).endswith(("commonpath", "commonprefix")) and x.items:
                    inner = x.items[0]
                    for it in (inner.items or ()) if inner.k == "seq" else ():
                        sub = self.subject(it, env)
                        v = self.eval(it, env, ctx) if sub else None
                        if sub and v is not None and v.taints and all("path:resolved" in t.safe for t in v.taints):
                            out = ((sub[0], frozenset({"path"}), False, None),)
                    break
                sub = self.subject(x, env)
                if sub is None:
                    continue
                other = self.eval(y, env, ctx)
                mine = self.eval(x, env, ctx)
                if mine.taints and not other.taints and other.kind not in ("req", "bag"):
                    empty = other.kind == "const" and other.data in ("", None, 0, False)
                    if sub[1] == "host" and empty:      # no host at all: an address on this site
                        out = ((sub[0], frozenset({"redirect"}), False, None),)
                    elif not empty:
                        out = ((sub[0], R.ALL, other.kind == "const", sub[1]),)
                    break
            return (out, ()) if op in ("==", "===", "is") else ((), out)
        return (), ()

    def call_facts(self, e: N, env: Env, ctx: Ctx):
        f = e.a
        items = e.items or ()
        fn = env.fn
        site = self.sites.get((fn.file, e.line, e.col))
        targets, _guess = self.targets(site)
        if targets:
            t = targets[0]
            s = self.summ.get(t.key)
            if s is None or not (s.pred_t or s.pred_f):
                return (), ()
            b = self.bound(t, e, [UNKNOWN] * len(items), {k: UNKNOWN for k in (e.kw or {})}, f.k == "attr")
            yes, no = [], []
            for i, (_v, expr) in b.items():
                sub = self.subject(expr, env) if expr is not None else None
                if not sub:
                    continue
                if s.pred_t.get(i):
                    yes.append((sub[0], s.pred_t[i], False, sub[1]))
                if s.pred_f.get(i):
                    no.append((sub[0], s.pred_f[i], False, sub[1]))
            return tuple(yes), tuple(no)
        canon = self.canon_of(e, env) or ""
        if f.k == "attr":
            m = f.name
            sub = self.subject(f.a, env)
            a0 = items[0] if items else None
            if sub and m in ("endswith", "endsWith") and a0 is not None and a0.k == "const" and \
                    isinstance(a0.a, str) and R.OWN_SUFFIX.match(a0.a) and \
                    (sub[1] == "host" or env.derived.get(sub[0], ("", ""))[0] == "host"):
                # the host of an address ends with `.example.com`: a name under the site's own. Without the dot
                # (`evilexample.com`), about the whole address, or with one label (`.com`) it restricts nothing
                return ((sub[0], R.URLS, False, sub[1]),), ()
            if sub and sub[1] is None:
                name = sub[0]
                if m in R.DIGIT_METHODS:
                    return ((name, R.ALL, False, None),), ()
                if m in R.CHAR_METHODS:
                    return ((name, R.CHARS, False, None),), ()
                if m in ("startswith", "startsWith") and a0 is not None:
                    pre = self.eval(a0, env, ctx)
                    mine = self.eval(f.a, env, ctx)
                    if pre.kind == "const" and isinstance(pre.data, str):
                        if R.host_fixed(pre.data):
                            return ((name, R.URLS, False, None),), ()
                        if pre.data in ("/", "\\"):
                            return ((name, frozenset({"redirect:local"}), False, None),), \
                                   ((name, frozenset({"path:abs"}), False, None),)
                        if pre.data in ("//", "/\\"):
                            return (), ((name, frozenset({"redirect:noslash2"}), False, None),)
                        if pre.data.startswith(".."):
                            return (), ((name, frozenset({"path:dots"}), False, None),)
                    if not pre.taints and mine.taints and all("path:resolved" in t.safe for t in mine.taints) and \
                            (pre.kind != "const" or len(str(pre.data)) > 1):
                        return ((name, frozenset({"path"}), False, None),), ()
                    return (), ()
                if m in ("is_relative_to",) and a0 is not None:
                    mine = self.eval(f.a, env, ctx)
                    if mine.taints and all("path:resolved" in t.safe for t in mine.taints):
                        return ((name, frozenset({"path"}), False, None),), ()
                    return (), ()
                if m in ("includes", "has", "hasOwnProperty") and a0 is not None and a0.k == "const" and a0.a == "..":
                    return (), ((name, frozenset({"path:dots"}), False, None),)
                if m in ("match", "fullmatch", "search") and a0 is not None and fn.lang == "js":
                    pat = self.eval(a0, env, ctx)
                    if pat.kind == "regex":
                        return ((name, R.pattern_classes(pat.data, False), False, None),), ()
            if m == "check" and a0 is not None:          # Node's net.BlockList: true when the address is on it
                box = self.eval(f.a, env, ctx)
                if box.kind == "ext" and isinstance(box.data, str) and R.BLOCK_LIST.search(box.data):
                    # asked about a host name it answers "not on the list": only a looked-up address counts
                    ab = self.about(a0, env)
                    return ((), ((ab[1], SSRF, False, None),)) if ab and ab[0] == "addr" else ((), ())
            # collection.includes(x) / set.has(x) / pattern.test(x) / PATTERN.fullmatch(x)
            if a0 is not None and m in ("includes", "has", "hasOwnProperty", "contains", "__contains__"):
                sub0 = self.subject(a0, env)
                box = self.eval(f.a, env, ctx)
                if sub0 and not box.taints and box.kind not in ("req", "bag", "const"):
                    return ((sub0[0], R.ALL, box.fixed is not None and not box.fixed, sub0[1]),), ()
            if a0 is not None and m in ("test", "match", "fullmatch", "search", "exec"):
                pat = self.eval(f.a, env, ctx)
                sub0 = self.subject(a0, env)
                if pat.kind == "regex" and sub0 and sub0[1] is None:
                    c = R.pattern_classes(pat.data, m == "fullmatch")
                    return (((sub0[0], c, False, None),) if c else ()), ()
            if m == "startswith" or m == "startsWith":      # path.relative(base, x).startsWith("..")
                inner = f.a
                if inner.k == "call" and text_of(inner.a).endswith("relative") and len(inner.items or ()) > 1 and \
                        items and items[0].k == "const" and str(items[0].a).startswith(".."):
                    sub1 = self.subject(inner.items[1], env)
                    if sub1:
                        return (), ((sub1[0], frozenset({"path"}), False, None),)
        tail = canon or text_of(f)
        a0 = items[0] if items else None
        if a0 is None:
            return (), ()
        if tail in ("re.fullmatch", "re.match", "re.search") and len(items) > 1:
            pat = self.eval(a0, env, ctx)
            sub = self.subject(items[1], env)
            data = pat.data if pat.kind in ("const", "regex") else None
            if sub and sub[1] is None and isinstance(data, str):
                c = R.pattern_classes(data, tail == "re.fullmatch")
                return (((sub[0], c, False, None),) if c else ()), ()
            return (), ()
        sub = self.subject(a0, env)
        if not sub:
            return (), ()
        if tail == "isinstance" and len(items) > 1:
            types = [text_of(x) for x in (items[1].items if items[1].k == "seq" else [items[1]])]
            if types and all(t in ("int", "float", "bool", "Decimal", "UUID", "uuid.UUID") for t in types):
                return ((sub[0], R.ALL, False, None),), ()
            if types == ["str"]:
                return ((sub[0], frozenset({"nosql"}), False, None),), ()
            return (), ()
        if R.NAN_CHECK.match(tail):
            return (), ((sub[0], R.ALL, False, None),)
        if R.VALIDATOR_ALL.search(tail):
            return ((sub[0], R.ALL, False, None),), ()
        if R.VALIDATOR_CHARS.search(tail):
            return ((sub[0], R.CHARS, False, None),), ()
        if R.URL_CHECK.search(tail):
            return ((sub[0], R.URLS, False, None),), ()
        if canon and (R.IP_INSIDE_CALL.match(canon) or R.IP_OUTSIDE_CALL.match(canon)):
            # these answer "not private" for a host name too: only an address that was looked up counts
            ab = self.about(a0, env)
            if not ab or ab[0] != "addr":
                return (), ()
            fact = ((ab[1], SSRF, False, None),)
            return ((), fact) if R.IP_INSIDE_CALL.match(canon) else (fact, ())
        if tail in ("os.path.isabs", "path.isAbsolute", "posixpath.isabs"):
            return (), ((sub[0], frozenset({"path:abs"}), False, None),)
        return (), ()

    def apply(self, env: Env, facts) -> None:
        lang = env.fn.lang
        for path, classes, fixed, rel in facts:
            first = True
            for p, c in chain(path, classes, rel, env):
                if p in env.vars:
                    env.vars[p] = narrow(env.vars[p], c, fixed and first and rel is None, lang)
                    i = env.orig.get(p)
                    if i is not None:
                        env.proved[i] = norm(env.proved.get(i, FIXED0) | c, lang)
                else:
                    env.narrow[p] = norm(env.narrow.get(p, FIXED0) | c, lang)
                first = False

    # ---- "only fixed text ever reaches this line"
    def callers_of(self, key) -> list:
        if not hasattr(self, "_callers"):
            idx: dict = {}
            for calls in self.calls.values():
                for callee, vals, line, caller, shown in calls:
                    idx.setdefault(callee, []).append((vals, line, caller, shown))
            self._callers = idx
        return self._callers.get(key, [])

    def called_at(self, fn: Fn) -> set:
        """(file, line) of every call the map links to `fn`, outside test files."""
        if not hasattr(self, "_called_at"):
            idx: dict = {}
            for s in self.sites.values():
                if s.get("test"):
                    continue
                for t in s["to"]:
                    f = self.by_node.get(t) or self.by_node.get(t + ".__init__") or self.by_node.get(t + ".constructor")
                    if f is not None:
                        idx.setdefault(f.key, set()).add((s["file"], s["line"]))
            self._called_at = idx
        return self._called_at.get(fn.key, set())

    def always_fixed(self, key, i: int, seen: frozenset = FIXED0):
        """Every call Lantern found hands parameter `i` fixed text, and nothing else can call the function: the calls
        as [(caller name, file, line)], or None when that cannot be said."""
        memo = (key, i)
        if memo in self._fixed_memo:
            return self._fixed_memo[memo]
        fn = self.by_key.get(key)
        if fn is None or memo in seen or fn.node is None or fn.inline:
            return None
        if key in self.escaped or fn.node in self.handed or self.entry(fn) or fn.decorators or \
                fn.name in self.doubt or fn.name.startswith("__"):
            return None
        calls = self.callers_of(key)
        if not calls:
            return None
        # the map's own list of calls is asked too: a call written where the engine did not read (a class body, a
        # default value, code after a `return`) is a caller whose argument nobody looked at
        seen_at = {(self.by_key[c].file, line) for _v, line, c, _s in calls if c in self.by_key}
        if not self.called_at(fn) <= seen_at:
            return None
        out: list = []
        for vals, line, caller, shown in calls:
            v = vals.get(i)
            if v is None or v.fixed is None or any(t.kind == "src" for t in v.taints):
                return None
            cf = self.by_key.get(caller)
            if cf is None:
                return None
            for j in v.fixed:
                deeper = self.always_fixed(caller, j, seen | {memo})
                if deeper is None:
                    return None
            out.append((shown, cf.file, line))
        self._fixed_memo[memo] = out
        return out

    def fixed_only(self, file: str, line: int, cls: str):
        """For a finding on this line: {"calls": [...]} when only fixed text can reach the action there."""
        best = None
        for key, points in self.points.items():
            if key[0] != file:
                continue
            for (f, ln), recs in points.items():
                if f == file and abs(ln - line) <= 2 and (best is None or abs(ln - line) < best[0]):
                    best = (abs(ln - line), key, [v for c, v in recs if c == cls])
        if best is None or not best[2]:
            return None
        calls: list = []
        for v in best[2]:
            if v.fixed is None or any(t.kind == "src" for t in v.taints):
                return None
            for i in v.fixed:
                got = self.always_fixed(best[1], i)
                if got is None:
                    return None
                calls += [c for c in got if c not in calls]
        fn = self.by_key.get(best[1])
        return {"function": fn.name if fn else None, "calls": [{"from": a, "file": b, "line": c} for a, b, c in
                                                                calls[:5]], "count": len(calls)}


# ------------------------------------------------------------------------------------------------ small helpers
R_ROUTE = _re.compile(r"\.(route|get|post|put|delete|patch|head|options|websocket|api_route)\(|"
                      r"^(api_view|require_http_methods|require_GET|require_POST|action)\b")
SANITIZERS = [(_re.compile(p), c) for p, c in R.SANITIZERS]
SSRF = frozenset({"ssrf"})
CONTENT = frozenset({"path", "ssrf", "redirect", "content"})     # what a file's content cannot be: a name or an address
_AUTH = _re.compile(r"(?:^|[._])(?:get_)?(?:current_)?(user|auth|token|login|session|principal|identity|jwt|"
                    r"api_key|permission|admin|account)", _re.I)
_NEXT = _re.compile(r"(^|/)(app|pages)/.*\.(tsx?|jsx?)$")


def re_search(pat: str, text: str):
    return _re.search(pat, text)


def re_match(pat: str, text: str):
    return _re.match(pat, text)


def auth_word(name: str) -> bool:
    return bool(_AUTH.search(name))


def is_next_file(file: str) -> bool:
    return bool(_NEXT.search(file))


def cut(steps: tuple) -> tuple:
    """A way longer than MAX_STEPS keeps its start and its end, with one line that says steps were left out."""
    if len(steps) <= MAX_STEPS:
        return steps
    head, tail = steps[:5], steps[-(MAX_STEPS - 6):]
    return head + ((tail[0][0], tail[0][1], f"… {len(steps) - len(head) - len(tail)} more steps …"),) + tail


def chain(path: str, classes: frozenset, rel, env: Env):
    """A fact about `path`, then what it says about each name `path` was made from: (name, kinds), nearest first.
    The host of an address says where the address leads and nothing else; the address a name was looked up as says
    whether a request to it stays outside the network, and nothing else."""
    if rel == "host":
        classes = classes & R.URLS
    for _ in range(6):
        if not classes:
            return
        yield path, classes
        d = env.derived.get(path)
        if not d:
            return
        kind, path = d
        classes = classes & (R.URLS if kind in ("host", "url") else SSRF if kind == "addr" else classes)


def every_node(x, depth: int = 0):
    """Every node under `x`, the functions written inside it left out."""
    if depth > 60:
        return
    if isinstance(x, N):
        yield x
        for y in (x.a, x.b, x.c, x.items, x.kw):
            if y is not None:
                yield from every_node(y, depth + 1)
    elif isinstance(x, (list, tuple)):
        for y in x:
            yield from every_node(y, depth + 1)
    elif isinstance(x, dict):
        for y in x.values():
            yield from every_node(y, depth + 1)


def names_in(t: N | None) -> list:
    """The plain names a target sets: `a`, `(a, b)`, `{ a, b: c }`."""
    if t is None:
        return []
    if t.k == "name":
        return [t.name]
    if t.k == "star":
        return names_in(t.a)
    if t.k == "seq":
        return [n for x in t.items or () for n in names_in(x)]
    if t.k == "map":
        return [n for _key, x in t.items or () for n in names_in(x)]
    return []


def has_break(stmts) -> bool:
    """Whether a `break` in these statements leaves the loop they are the body of."""
    for s in stmts or ():
        k = s.k
        if k == "jump" and s.name == "break":
            return True
        if k == "if" and (has_break(s.b) or has_break(s.c)):
            return True
        if k == "with" and has_break(s.b):
            return True
        if k == "try" and (has_break(s.b) or has_break(s.c) or any(has_break(h) for _n, h in s.items or ())):
            return True
        if k == "match" and any(has_break(b) for b in s.items or ()):
            return True
    return False


def union(lists) -> tuple:
    out: dict = {}
    for facts in lists:
        for path, classes, fixed, rel in facts:
            old = out.get((path, rel))
            out[(path, rel)] = (classes | old[0], fixed or old[1]) if old else (classes, fixed)
    return tuple((p, c, f, r) for (p, r), (c, f) in out.items())


def both(lists) -> tuple:
    lists = list(lists)
    if not lists:
        return ()
    out: dict = {(p, r): (c, f) for p, c, f, r in lists[0]}
    for facts in lists[1:]:
        cur = {(p, r): (c, f) for p, c, f, r in facts}
        out = {k: (c & cur[k][0], f and cur[k][1]) for k, (c, f) in out.items() if k in cur and c & cur[k][0]}
    return tuple((p, c, f, r) for (p, r), (c, f) in out.items())


def analyze(g, budget: float = 300.0) -> Result:
    """Every flow from request data to a sensitive action Lantern can follow in the project behind the map `g`."""
    eng = Engine(g)
    eng.load()
    eng.run(budget)
    return eng.result()
