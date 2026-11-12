"""Is a request limit on this route? (directive point 4, 2026-11-11.)

A library that is installed protects nothing. Until this date `slowapi` in the dependencies, or the word in an
import, made the "Rate limiting" protection read "in place" and kept LA-WALLET-DRAIN quiet. This reads where a
limiter is put to work, route by route (`View.of(node)` -> (state, words)):

"yes"    the code shows a limit that covers the route:
         * on the route itself: a decorator (`@limiter.limit("5/minute")`), a dependency
           (`Depends(RateLimiter(...))`), a middleware handed to the route (`app.post('/login', loginLimiter, h)`),
           or a call on a limiter in the handler's own lines (`await ratelimit.limit(ip)`);
         * Express style, for the app or a part of it (`app.use('/api/', rateLimit({...}))`), when the route is
           registered after it in the same file and under that path. Express runs middleware in the order written,
           so one put on the app after the route never runs for it.
"own"    the limiter on the route is a function of the project, named for it, in which nothing visibly counts
         (no clock, no counter, no store, no 429, no rate-limiting library): a name is not a limit.
"maybe"  a limit exists for the whole app and the code does not show that it covers this route: a default limit
         (`Limiter(..., default_limits=[...])`), Django REST framework's default throttles, a request hook or a
         Next.js middleware file named for limiting, `app.use(limiter)` in another file.
"no"     nothing: no limiter, or one that is only installed, only imported, only made, put on another part of the
         app, or put on the app after the route.

Everything here reads names and shapes, like the other protections: a heuristic. A limit kept outside the code (a
proxy, the hosting service) is not seen; the reader of a "no" has to know that."""

from __future__ import annotations

import re

from .graph import Graph
from .websec import IDENT, ROUTE_DOC_KWARGS, _func_name, _strip_strings, code_only, segments

LIBS = re.compile(r"slowapi|fastapi[-_]limiter|flask[-_]limiter|django[-_]ratelimit|express-rate-limit|"
                  r"rate-limiter-flexible|@upstash/ratelimit|@nestjs/throttler|hono-rate-limiter|@fastify/rate-limit|"
                  r"koa-ratelimit|express-slow-down|express-brute|\bratelimit\b|\brate_limit\b|RateLimit", re.I)
# A name's whole lower-case words (`websec.segments`): `loginLimiter`, `RateLimiter`, `ratelimit`, `throttle_classes`.
# The bare word `limit` is not one: `query.limit(20)` takes twenty rows, `express.json({limit: '1mb'})` is a size.
LIMITER = re.compile(r"\b(rate ?limit(?:s|er|ers|ed|ing)?|limiter|throttl(?:e|es|ed|er|ing)|slow ?down|"
                     r"brute(?: ?force)?)\b")
# What a function that limits requests has in it, as code: a clock, a counter, a store, the answer "too many"
COUNTS = re.compile(r"\btime\b|\bdatetime\b|Date\.now|performance\.now|\bmonotonic\b|\bredis\b|\bcache\b|"
                    r"\bincr\w*|\bcount\w*|\bwindow\w*|\b429\b|\+=\s*1\b|\+\+|\bbucket\w*|\bhits?\b|\bttl\b|"
                    r"\bexpir\w*|\blen\(|\.length\b|\.size\b", re.I)
JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
USE = re.compile(r"\.(?:use|register)\s*\(")
DEFAULTS = re.compile(r"\b(?:default_limits|application_limits)\s*=\s*\[")
DRF = re.compile(r"[\"']DEFAULT_THROTTLE_(?:CLASSES|RATES)[\"']\s*:\s*[\[({]\s*[^\])}\s]")
DJANGO_MW = re.compile(r"[\"'][\w.]*RatelimitMiddleware[\"']")
NEST = re.compile(r"\bThrottlerGuard\b|\bThrottlerModule\s*\.\s*forRoot")
HOOK = re.compile(r"before_request|before_app_request|\.middleware\(")
NEXT_MW = re.compile(r"(^|/)middleware\.(?:ts|js|mjs)$")
PREFIX = re.compile(r"\s*(['\"`])([^'\"`]*)\1\s*,")


def _limiter_name(code: str) -> str | None:
    """The first name in `code` (strings blanked) that is built from a limiter word."""
    for m in IDENT.finditer(code):
        if LIMITER.search(segments(m.group(0))):
            return m.group(0)
    return None


def _args(code: str, start: int, most: int = 600) -> int:
    """Where the parenthesis opened just before `start` closes (or `start + most`)."""
    depth = 1
    for i in range(start, min(len(code), start + most)):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i
    return min(len(code), start + most)


class View:
    """What the code shows about request limits, asked route by route."""

    def __init__(self, g: Graph, repo, deps: str = ""):
        self.g = g
        self.repo = repo
        m = LIBS.search(deps)
        self.installed: str | None = m.group(0) if m else None     # the library the dependency files name
        self.by_name: dict[str, list] = {}
        for n in g.nodes.values():
            if n.kind != "module" and n.file and not n.id.startswith("ext:"):
                self.by_name.setdefault(_func_name(g, n.id), []).append(n)
        self._wide: list[dict] | None = None

    # ---- the project's own function, named for limiting: does anything in it count?
    def _lines(self, n) -> str:
        lines = self.repo.text(n.file).splitlines()
        first = n.start_line or 1
        return "\n".join(lines[first - 1:(n.end_line or first)])

    def _own(self, name: str, near: str | None):
        """The function or class of the project that `name` names (`rate_limit`, the `limiter` of `limiter.limit`),
        the one in the file `near` first; None for a library's or a variable."""
        nodes = self.by_name.get(name.split(".")[0], [])
        return next((n for n in nodes if n.file == near), nodes[0] if nodes else None)

    def _counts(self, n) -> bool:
        raw = self._lines(n)
        code = code_only(raw, js=n.file.endswith(JS_EXT))
        body = code.split("\n", 1)[1] if "\n" in code else ""       # not its own name on the first line
        return bool(COUNTS.search(body) or LIBS.search(body) or LIBS.search(raw.split("\n", 1)[-1]))

    def _judge(self, name: str, near: str | None, how: str) -> tuple[str, str]:
        own = self._own(name, near)
        if own is not None and not self._counts(own):
            return "own", (f"`{name}` {how} is the project's own function ({own.file}:{own.start_line}), and nothing "
                           "in it visibly counts requests")
        return "yes", f"`{name}` {how}"

    # ---- on the route itself
    def _on_route(self, n) -> tuple[str, str] | None:
        where = f"({n.file}:{n.start_line})"
        for d in n.decorators or ():
            name = _limiter_name(ROUTE_DOC_KWARGS.sub("", _strip_strings(d)))
            if name:
                state, words = self._judge(name, n.file, "on the route")
                return state, f"{words} {where}"
        for m in re.finditer(r"\b(?:Depends|Security)\(\s*([A-Za-z_][\w.]*)", _strip_strings(n.signature or "")):
            if LIMITER.search(segments(m.group(1))):
                state, words = self._judge(m.group(1), n.file, "handed to the route")
                return state, f"{words} {where}"
        for mid in (n.entry or {}).get("middleware") or ():
            name = _func_name(self.g, mid).split("(")[0].rsplit("/", 1)[-1]
            node = None if mid.startswith("ext:") else self.g.nodes.get(mid)
            if node is not None and node.file:
                if LIMITER.search(segments(name)):
                    if self._counts(node):
                        return "yes", f"`{name}` handed to the route {where}"
                    return "own", (f"`{name}` handed to the route is the project's own function "
                                   f"({node.file}:{node.start_line}), and nothing in it visibly counts requests")
            elif LIBS.search(mid) or LIMITER.search(segments(name)):
                return "yes", f"`{name}` handed to the route {where}"
        if not n.file:
            return None
        code = code_only(self._lines(n), js=n.file.endswith(JS_EXT))
        for m in IDENT.finditer(code):
            if code[m.end():].lstrip(" ").startswith("(") and LIMITER.search(segments(m.group(0))):
                line = (n.start_line or 1) + code.count("\n", 0, m.start())
                state, words = self._judge(m.group(0), n.file, "asked in the handler")
                return state, f"{words} ({n.file}:{line})"
        return None

    # ---- for the whole app, or a part of it
    def wide(self) -> list[dict]:
        if self._wide is not None:
            return self._wide
        out: list[dict] = []
        for f, t in self.repo.code():
            js = f.endswith(JS_EXT)
            code = None
            if js and ".use" in t or js and ".register" in t:
                code = code_only(t, js=True)
                for m in USE.finditer(code):
                    end = _args(code, m.end())
                    inner, raw = code[m.end():end], t[m.end():end]
                    name = _limiter_name(inner) or (LIBS.search(raw).group(0) if LIBS.search(raw) else None)
                    if not name:
                        continue
                    pm = PREFIX.match(raw)
                    prefix = pm.group(2).rstrip("*") if pm else None
                    own = self._own(name, f)
                    out.append({"kind": "use", "file": f, "line": code.count("\n", 0, m.start()) + 1, "name": name,
                                "prefix": prefix if prefix and prefix != "/" else None,
                                "counts": own is None or self._counts(own)})
            if js:
                if NEXT_MW.search(f) and _limiter_name(code if code is not None else code_only(t, js=True)):
                    out.append({"kind": "all", "file": f, "line": 1, "words": "a middleware file that names a limiter"})
                m = NEST.search(t)
                if m:
                    out.append({"kind": "all", "file": f, "line": t.count("\n", 0, m.start()) + 1,
                                "words": "a throttler set up for the app"})
                continue
            if not f.endswith(".py"):
                continue
            for m in DEFAULTS.finditer(code_only(t)):
                if t[m.end():t.find("]", m.end()) if "]" in t[m.end():] else len(t)].strip():
                    out.append({"kind": "all", "file": f, "line": t.count("\n", 0, m.start()) + 1,
                                "words": "a default limit for every route"})
            for rx, words in ((DRF, "default throttles for the framework's views"),
                              (DJANGO_MW, "a rate-limit middleware in the settings")):
                m = rx.search(t)
                if m:
                    out.append({"kind": "all", "file": f, "line": t.count("\n", 0, m.start()) + 1, "words": words})
        for n in self.g.nodes.values():     # a hook that runs before every request, named for limiting
            if n.kind == "module" or not n.file or self.repo.is_test(n.file):
                continue
            if any(HOOK.search(d) for d in n.decorators or ()) and LIMITER.search(segments(_func_name(self.g, n.id))):
                out.append({"kind": "all", "file": n.file, "line": n.start_line or 1,
                            "words": "a hook that runs before every request"
                                     + ("" if self._counts(n) else ", in which nothing visibly counts requests")})
        self._wide = out
        return out

    def of(self, n) -> tuple[str, str]:
        """("yes" | "own" | "maybe" | "no", what was found, in words)."""
        got = self._on_route(n)
        if got:
            return got
        detail = (n.entry or {}).get("detail") or ""
        path = (detail.partition(" ")[2] or detail).split("?")[0]
        maybe, notes = None, []
        for w in self.wide():
            where = f"({w['file']}:{w['line']})"
            if w["kind"] != "use":
                maybe = maybe or f"{w['words']} {where}"
                continue
            prefix = (w["prefix"] or "").rstrip("/")
            if prefix and not (path == prefix or path.startswith(prefix + "/")):
                notes.append(f"`{w['name']}` {where} is for {w['prefix']} only")
                continue
            if w["file"] != n.file:
                maybe = maybe or f"`{w['name']}` put on the app in another file {where}"
            elif w["line"] < (n.start_line or 0):
                if w["counts"]:
                    return "yes", f"`{w['name']}` put on the app before this route {where}"
                return "own", (f"`{w['name']}` put on the app {where} is the project's own function, and nothing in "
                               "it visibly counts requests")
            else:
                notes.append(f"`{w['name']}` {where} is put on the app after this route, so it does not run for it")
        if maybe:
            return "maybe", maybe
        return "no", "; ".join(dict.fromkeys(notes))


def view(g: Graph, repo, deps: str = "") -> View:
    return View(g, repo, deps)
