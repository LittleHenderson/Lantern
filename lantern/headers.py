"""Are security headers set for every response? (2026-11-12.)

Until this date the "Security headers" protection read "in place" when one of a few words stood anywhere in the
code. On a real static site it did so for two reasons, neither of which sends a header: one exported document
carried its own `<meta http-equiv="Content-Security-Policy">`, and the word "helmet" stood in a search pattern as the
name of an HTML tag. The site was served with no security header at all.

This reads where a header is set (`read(g, repo)` -> (status, words, places, notes)):

"in place"  the code or a hosting file shows a header set for every response:
            * a hosting rule for every path (`_headers` `/*`, `netlify.toml` `for = "/*"`, `vercel.json` and
              `next.config.*` `source: "/(.*)"`, nginx `add_header` and Caddy `header` outside a block for one place);
            * a library put on the app: `app.use(helmet())` where `helmet` is the package's own name in that file,
              `Talisman(app)`, Django's own middleware in the settings' `MIDDLEWARE` list, `secure` applied;
            * the project's own function that sets a header and runs for every request: a FastAPI or Flask function
              under `@app.middleware` / `@app.after_request`, a middleware class (`call_next`, `get_response`), an
              Express function handed to `app.use(...)` with no path, a Next.js `middleware` file with no `matcher`.
"check"     a header is set, and the code does not show that every response gets it: a `<meta>` tag in one page (a
            meta tag protects that page only and cannot carry Strict-Transport-Security or X-Frame-Options), a
            header one route puts on its own answer, a hosting rule or a library for one path, a table of headers the
            code does not show being sent, a header named in a language whose ways Lantern does not follow.
"add"       nothing sets one. A word is no header: a comment, a search pattern, a library that is loaded and never
            put on the app, a function that happens to be called `helmet`, a header read from somebody else's answer.

Which headers are sent, and what they say, is not judged here. Names and shapes are read, like the other
protections: a heuristic. Headers a proxy or the hosting service adds outside the code are not seen; the reader of
an "add" has to know that."""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from . import manifest
from .graph import Graph
from .python_frontend import project_text
from .websec import code_only

NAMES = re.compile(r"Content-Security-Policy(?:-Report-Only)?|Strict-Transport-Security|X-Frame-Options|"
                   r"frame-ancestors", re.I)
JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
PAGE_EXT = (".html", ".htm")
PAGE_HEAD = 262_144          # characters of a page that are read: its own policy is a tag in its <head>
HOSTING = ("vercel.json", "netlify.toml", "_headers", "nginx.conf", "Caddyfile")
# The file Next.js itself reads, by its whole name: `next.config.js.tmpl` is a template somebody keeps, not the
# settings in force (Lantern's own card read "in place" for the sample of a starter app).
NEXT_CONFIG = re.compile(r"next\.config\.(?:js|mjs|cjs|ts)")
# What says where an app of the project begins: the settings for every response of one app say nothing about the
# app in the folder beside it (helmet on the API sends nothing with the pages of the site).
APP_FILES = frozenset(("package.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile",
                       "manage.py", "go.mod", "Cargo.toml", "composer.json", "Gemfile", "pom.xml", "build.gradle",
                       "build.gradle.kts", "pubspec.yaml"))
AT_ITS_APP = ("vercel.json", "netlify.toml")      # these sit at the top of what they are for
PUBLISHED = frozenset(("public", "static", "www", "htdocs", "_site"))    # `_headers` lies in the published folder
ASKED = ("route", "page")
# A rule's path that takes in every page: `/*`, `/**`, `*`, `/(.*)`, `/(.*)?`, `/:path*`, `/.*`, `/`
ALL_PATHS = re.compile(r"^(?:/?\*{1,2}|/?\(\.\*\)\??|/:\w+\*|/\.\*|/)$")
META = re.compile(r"<meta\b[^>]{0,200}?http-equiv\s*=\s*\\?[\"']?\s*$", re.I)
META_PAGE = re.compile(r"<meta\b[^>]{0,200}?http-equiv\s*=\s*[\"']?\s*Content-Security-Policy", re.I)
# The package's own name in a file: `const helmet = require('helmet')`, `import guard from 'helmet'`
HELMET = re.compile(r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"](?:@fastify/|koa-|fastify-)?helmet['\"]\s*\)|"
                    r"\bimport\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s+['\"](?:@fastify/|koa-|fastify-)?helmet['\"]")
PUT_ON = re.compile(r"\.(?:use|register)\s*\(")
TALISMAN = re.compile(r"^\s*(?:from\s+(?:flask_)?talisman\s+import\b|import\s+(?:flask_)?talisman\b)", re.M)
TALISMAN_ON = re.compile(r"\bTalisman\s*\(")
DJANGO = re.compile(r"\bMIDDLEWARE(?:_CLASSES)?\s*\+?=\s*[\[(][^\])]*?[\"']((?:django\.middleware\.security\.SecurityMiddleware|"
                    r"django\.middleware\.clickjacking\.XFrameOptionsMiddleware|csp\.middleware\.CSPMiddleware))[\"']")
SECURE = re.compile(r"^\s*(?:import\s+secure\b|from\s+secure\s+import\b)", re.M)
SECURE_MADE = re.compile(r"\bSecure\s*(?:\.\s*\w+\s*)?\(")
SECURE_ON = re.compile(r"\.set_headers(?:_async)?\s*\(|\.framework\.\w+\s*\(")
NEXT_MW = re.compile(r"(^|/)middleware\.(?:ts|js|mjs)$")
# What a function that runs for every request looks like, as code
PY_SHAPE = re.compile(r"\bcall_next\s*\(|\bget_response\s*\(|\bdef\s+process_response\b|"
                      r"\bdef\s+__call__\s*\(\s*self\s*,\s*scope\b")
PY_DECORATED = re.compile(r"\b(?:middleware|after_request|after_app_request)\b")
JS_SHAPE = re.compile(r"\bnext\s*\(")
ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "route", "all"})
# A call that reads a header, or asks whether one is there: nothing is set
READS = frozenset({"get", "has", "includes", "indexOf", "startsWith", "getHeader", "getResponseHeader", "match",
                   "test", "search", "delete", "removeHeader", "pop", "compile", "RegExp", "getlist"})
ASSIGNED_PY = re.compile(r"([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)")
ASSIGNED_JS = re.compile(r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=(?!=)")
BACK = 20_000           # how far back from a place the calls around it are looked for
MOST = 40               # places looked at in one file

SAYS = {
    "meta": "a policy written into a page as a `<meta>` tag protects that one page, and a meta tag cannot carry "
            "Strict-Transport-Security or X-Frame-Options",
    "route": "a header one route puts on its own answer",
    "function": "a function that sets a header, which the code does not show to run for every request",
    "path": "a header set for one path only",
    "table": "header names in a value that the code does not show being sent",
    "language": "a header named in code that Lantern cannot follow to every response",
    "made": "`secure.Secure()` is made, and the code does not show it put on an answer",
    "matcher": "a Next.js middleware that runs only for the paths its `matcher` names",
    "rule": "a hosting rule for one path only",
    "helmet": "helmet is put on the app",
    "talisman": "Flask-Talisman is put on the app",
    "django": "Django's own middleware is in the settings' MIDDLEWARE list",
    "secure": "the `secure` library is put on the answers",
    "every-rule": "a hosting rule for every path",
    "every-request": "a function that runs for every request sets it",
    "next": "the Next.js middleware sets it",
}


@dataclass(frozen=True)
class Sign:
    file: str
    line: int
    whole: bool          # the code shows it covers every response
    kind: str            # a key of SAYS


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# One pass over the text, each place read once: a text or a comment that nothing closes ends where its line or the
# file does, so no line can keep the reading busy (a quote followed by backslashes and no closing quote, which the
# pattern in `websec.code_only` tries every pairing of).
_Q = r"'(?:\\.|[^'\\\n])*(?:'|\\?(?=\n)|\\?\Z)|\"(?:\\.|[^\"\\\n])*(?:\"|\\?(?=\n)|\\?\Z)"
_JS_NOT_CODE = re.compile(r"`(?:\\[\s\S]|[^`\\])*(?:`|\\?\Z)|" + _Q + r"|(/\*[\s\S]*?(?:\*/|\Z)|//[^\n]*)")
_T3 = r"(?:\"\"\"[\s\S]*?(?:\"\"\"|\Z)|'''[\s\S]*?(?:'''|\Z))"
_PY_NOT_CODE = re.compile(r"(^[ \t]*[rRuUbBfF]{0,2}" + _T3 + r")|[rRuUbBfF]{0,2}" + _T3 + "|" + _Q + r"|(#[^\n]*)",
                          re.M)


def _not_code(text: str, js: bool) -> list[tuple[int, int]]:
    """Where comments stand (and, in Python, a text that is a statement by itself: a docstring), in the order of the
    text and none inside another. A header named there is written about, not set."""
    if js:
        return [m.span(1) for m in _JS_NOT_CODE.finditer(text) if m.group(1) is not None]
    return [m.span(m.lastindex) for m in _PY_NOT_CODE.finditer(text) if m.lastindex]


def _within(off: list[tuple[int, int]], pos: int) -> bool:
    """Whether `pos` stands in one of the places `_not_code` gave."""
    i = bisect.bisect_right(off, (pos, float("inf"))) - 1          # the last place that starts at or before `pos`
    return i >= 0 and off[i][0] <= pos < off[i][1]


def _around(code: str, pos: int) -> tuple[list[tuple[str, int]], int | None]:
    """The calls around `pos`, innermost first, as (what is called, where its parenthesis opens), and where the
    outermost bracket that is still open at `pos` stands. `code` has strings and comments blanked."""
    calls, depth, outer = [], 0, None
    for i in range(pos - 1, max(-1, pos - BACK), -1):
        c = code[i]
        if c in ")]}":
            depth += 1
        elif c in "([{":
            if depth:
                depth -= 1
                continue
            outer = i
            if c == "(":
                m = re.search(r"([\w$.]+)\s*$", code[max(0, i - 80):i])
                calls.append((m.group(1) if m else "", i))
    return calls, outer


def _first_arg(text: str, code: str, at: int) -> str | None:
    """The text of the first argument when it is written text (a path), else None."""
    m = re.match(r"\s*(~+)", code[at + 1:at + 400])
    if not m:
        return None
    raw = text[at + 1 + m.start(1):at + 1 + m.end(1)]
    return raw[1:-1] if len(raw) >= 2 else raw


class _Reader:
    def __init__(self, g: Graph, repo):
        self.g, self.repo = g, repo
        self.nodes: dict[str, list] = {}
        for n in g.nodes.values():
            if n.kind == "callable" and n.file and n.start_line and n.end_line:
                self.nodes.setdefault(n.file, []).append(n)
        self._js_code: list[tuple[str, str, str]] | None = None

    # ---- the project's own code

    def node_at(self, f: str, line: int):
        """The innermost function of the map around a line."""
        best = None
        for n in self.nodes.get(f, ()):
            if n.start_line <= line <= n.end_line and (best is None or n.start_line >= best.start_line):
                best = n
        return best

    def js_files(self):
        if self._js_code is None:
            self._js_code = [(f, t, code_only(t, js=True)) for f, t in self.repo.code() if f.endswith(JS_EXT)]
        return self._js_code

    def put_on_app(self, name: str) -> str | None:
        """How a named function is handed to `.use(...)` anywhere in the project: "whole", "path" or None."""
        seen = None
        rx = re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")
        for _f, text, code in self.js_files():
            if name not in code:
                continue
            for m in PUT_ON.finditer(code):
                at = m.end() - 1
                if not rx.search(_args(code, at)):
                    continue
                path = _first_arg(text, code, at)
                if path is None or ALL_PATHS.match(path):
                    return "whole"
                seen = "path"
        return seen

    def place(self, f: str, text: str, code: str, pos: int, js: bool) -> tuple[bool, str] | None:
        """What the code around a place shows: (covers every response, kind), or None where a header is only read."""
        calls, _outer = _around(code, pos)
        if calls and calls[0][0].rsplit(".", 1)[-1] in READS:
            return None
        line = _line(text, pos)
        if js:
            if NEXT_MW.search(f):
                return (False, "matcher") if re.search(r"\bmatcher\b", code) else (True, "next")
            for called, at in calls:
                last = called.rsplit(".", 1)[-1]
                if "." not in called:
                    continue
                if last in ("use", "addHook"):
                    path = _first_arg(text, code, at) if last == "use" else None
                    return (True, "every-request") if path is None or ALL_PATHS.match(path) else (False, "path")
                if last in ROUTE_VERBS:
                    return False, "route"
            n = self.node_at(f, line)
            if n is not None:
                body = "\n".join(code.split("\n")[n.start_line - 1:n.end_line])
                if JS_SHAPE.search(body):
                    how = self.put_on_app(n.name)
                    return (True, "every-request") if how == "whole" else (False, "path" if how else "function")
                return False, "function"
            return False, ""
        if f.endswith(".py"):
            n = self.node_at(f, line)
            if n is not None:
                body = "\n".join(code.split("\n")[n.start_line - 1:n.end_line])
                if PY_SHAPE.search(body) or PY_DECORATED.search(" ".join(n.decorators or ())):
                    return True, "every-request"
                return False, "function"
            return False, ""
        return False, "language"

    def named(self, text: str, code: str, pos: int, js: bool) -> str | None:
        """The name a value written at the top of a file is kept under (`WANTED = {...}`)."""
        _calls, outer = _around(code, pos)
        start = text.rfind("\n", 0, outer if outer is not None else pos) + 1
        m = (ASSIGNED_JS if js else ASSIGNED_PY).match(code, start)
        return m.group(1) if m else None

    def in_code(self, f: str, text: str) -> list[Sign]:
        js = not f.endswith(".py")
        code = code_only(text, js=js)
        off = _not_code(text, js)
        out: list[Sign] = []
        for m in NAMES.finditer(text):
            pos = m.start()
            if len(out) >= MOST:
                break
            if code[pos] != "~" or _within(off, pos):
                continue                                    # not written text: a pattern, a name, a comment
            line = _line(text, pos)
            if META.search(text[max(0, pos - 240):pos]):
                out.append(Sign(f, line, False, "meta"))
                continue
            got = self.place(f, text, code, pos, js and f.endswith(JS_EXT))
            if got is None:
                continue
            whole, kind = got
            if not kind:                                    # at the top of the file: a value kept under a name?
                kind, name = "table", self.named(text, code, pos, js)
                if name:
                    rx = re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")
                    for use in rx.finditer(code):
                        if _line(text, use.start()) == line or not (f.endswith(".py") or f.endswith(JS_EXT)):
                            continue
                        there = self.place(f, text, code, use.start(), f.endswith(JS_EXT))
                        if there and there[0]:
                            whole, kind = True, "every-request"
                            break
            out.append(Sign(f, line, whole, kind))
        return out

    def libraries(self, f: str, text: str) -> tuple[list[Sign], list[str]]:
        """A library that sets the headers, where it is put to work; and a note where one is only loaded."""
        out: list[Sign] = []
        notes: list[str] = []
        if f.endswith(JS_EXT):
            m = HELMET.search(text)
            if m:
                name, code, used = m.group(1) or m.group(2), code_only(text, js=True), False
                rx = re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")
                for u in PUT_ON.finditer(code):
                    at = u.end() - 1
                    if not rx.search(_args(code, at)):
                        continue
                    path = _first_arg(text, code, at)
                    whole = path is None or bool(ALL_PATHS.match(path))
                    out.append(Sign(f, _line(text, u.start()), whole, "helmet" if whole else "path"))
                    used = True
                if not used:
                    notes.append(f"helmet is loaded in {f}, but nothing there puts it on the app")
        elif f.endswith(".py"):
            code = None
            if TALISMAN.search(text):
                code = code_only(text)
                on = TALISMAN_ON.search(code)
                if on:
                    out.append(Sign(f, _line(text, on.start()), True, "talisman"))
                else:
                    notes.append(f"Flask-Talisman is loaded in {f}, but nothing there puts it on the app")
            if SECURE.search(text):
                code = code or code_only(text)
                made, on = SECURE_MADE.search(code), SECURE_ON.search(code)
                if made and on:
                    out.append(Sign(f, _line(text, on.start()), True, "secure"))
                elif made:
                    out.append(Sign(f, _line(text, made.start()), False, "made"))
            for m in DJANGO.finditer(text):
                out.append(Sign(f, _line(text, m.start(1)), True, "django"))
                break
        return out, notes

    # ---- hosting files

    def hosting(self, f: str, text: str) -> list[Sign]:
        name = f.rsplit("/", 1)[-1]
        if name == "_headers":
            return _headers_file(f, text)
        if name == "netlify.toml":
            rules = [(manifest.text(r.get("for")), list(manifest.table(r.get("values"))))
                     for r in manifest.rows(manifest.parse_toml(text).get("headers"))]
            return _rules(f, text, rules)
        if name == "vercel.json":
            rules = [(manifest.text(r.get("source")), [manifest.text(h.get("key")) for h in manifest.rows(r.get("headers"))])
                     for r in manifest.rows(manifest.table(manifest.parse_json(text)).get("headers"))]
            return _rules(f, text, rules)
        if NEXT_CONFIG.fullmatch(name):
            return _next_config(f, text)
        return _server_file(f, text)

    def all(self) -> tuple[list[Sign], list[str]]:
        signs: list[Sign] = []
        notes: list[str] = []
        repo = self.repo
        for f in repo.project_files:
            name = f.rsplit("/", 1)[-1]
            if name in HOSTING or NEXT_CONFIG.fullmatch(name):
                signs += self.hosting(f, repo.text(f))
            elif f.endswith(PAGE_EXT) and not f.endswith(".min.html"):
                try:
                    t = project_text(repo.root / f, repo.root, PAGE_HEAD)    # not kept: a site may hold thousands
                except OSError:
                    continue
                m = META_PAGE.search(t) if "http-equiv" in t.lower() else None
                if m:
                    signs.append(Sign(f, _line(t, m.start()), False, "meta"))
        for f, t in repo.code():
            if NEXT_CONFIG.fullmatch(f.rsplit("/", 1)[-1]):
                continue                                    # read as a hosting file above
            got, said = self.libraries(f, t)
            signs += got
            notes += said
            if NAMES.search(t):
                signs += self.in_code(f, t)
        return signs, notes


def _args(code: str, at: int) -> str:
    """The text between the parenthesis at `at` and its match (at most 600 characters)."""
    depth = 0
    for i in range(at, min(len(code), at + 600)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return code[at + 1:i]
    return code[at + 1:at + 600]


def _headers_file(f: str, text: str) -> list[Sign]:
    """Netlify's and Cloudflare Pages' `_headers`: a path on a line of its own, its headers indented beneath it."""
    out, path = [], None
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] not in " \t":
            path = line.strip()
        elif path and re.match(NAMES.pattern + r"\s*:", line.strip(), re.I):
            whole = bool(ALL_PATHS.match(path))
            out.append(Sign(f, i, whole, "every-rule" if whole else "rule"))
    return out


def _rules(f: str, text: str, rules: list[tuple[str, list[str]]]) -> list[Sign]:
    """Rules read out of a settings file as (path, header names). The line is where that header's name stands."""
    out = []
    for path, names in rules:
        for n in names:
            if not NAMES.fullmatch(n or ""):
                continue
            at = text.find(n)
            whole = bool(ALL_PATHS.match(path or ""))
            out.append(Sign(f, _line(text, at) if at >= 0 else 1, whole, "every-rule" if whole else "rule"))
    return out


def _open_at(code: str, pos: int) -> list[int]:
    """Where the brackets still open at `pos` stand, the innermost first."""
    out, depth = [], 0
    for i in range(pos - 1, max(-1, pos - BACK), -1):
        c = code[i]
        if c in ")]}":
            depth += 1
        elif c in "([{":
            if depth:
                depth -= 1
            else:
                out.append(i)
    return out


def _closes(code: str, at: int) -> int:
    depth = 0
    for i in range(at, min(len(code), at + BACK)):
        if code[i] in "([{":
            depth += 1
        elif code[i] in ")]}":
            depth -= 1
            if depth == 0:
                return i
    return min(len(code), at + BACK)


SOURCE = re.compile(r"\bsource\s*:\s*(['\"`])(.*?)\1")


def _source_around(text: str, code: str, pos: int) -> str | None:
    """The `source` of the rule a place belongs to: the one written in the nearest `{...}` around it that has one."""
    for at in _open_at(code, pos):
        if code[at] != "{":
            continue
        m = SOURCE.search(text, at, _closes(code, at))
        if m:
            return m.group(2)
    return None


def _next_config(f: str, text: str) -> list[Sign]:
    """`next.config.*` is code and is not run: a header's name in written text, and the `source` of the rule it
    stands in. A list of headers kept under a name is followed to the rule that names it."""
    code = code_only(text, js=True)
    off = _not_code(text, True)
    out = []
    for m in NAMES.finditer(text):
        pos = m.start()
        if code[pos] != "~" or _within(off, pos):
            continue
        source = _source_around(text, code, pos)
        if source is None:
            opened = _open_at(code, pos)
            named = ASSIGNED_JS.match(code, text.rfind("\n", 0, opened[-1] if opened else pos) + 1)
            if named:
                rx = re.compile(r"(?<![\w$.])" + re.escape(named.group(1)) + r"(?![\w$])")
                for use in rx.finditer(code, named.end()):
                    source = _source_around(text, code, use.start())
                    if source is not None and ALL_PATHS.match(source):
                        break
        whole = source is not None and bool(ALL_PATHS.match(source))
        out.append(Sign(f, _line(text, pos), whole, "every-rule" if whole else "rule"))
    return out


NARROW = re.compile(r"(?:location|handle|handle_path|route|if|map)\b|@\w+|header\s+[/@]")


def _server_file(f: str, text: str) -> list[Sign]:
    """nginx.conf and a Caddyfile: a header written outside every block that is for one place only."""
    out: list[Sign] = []
    open_: list[str] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if NAMES.search(line) and re.match(r"(?:add_header|more_set_headers|header)\b|[+?>]?[A-Za-z]", line):
            narrow = any(NARROW.match(h) for h in open_) or bool(re.match(r"header\s+[/@]", line))
            out.append(Sign(f, i, not narrow, "rule" if narrow else "every-rule"))
        for c in re.finditer(r"[{}]", line):
            if c.group() == "{":
                open_.append(line[:c.start()].strip())
            elif open_:
                open_.pop()
    return out


def _folder(f: str) -> str:
    return f.rsplit("/", 1)[0] if "/" in f else ""


def _app(f: str, roots: set[str]) -> str:
    """The folder of the app a file belongs to: the nearest folder above it that holds one of `APP_FILES`, else the
    project's top folder (`""`)."""
    at = _folder(f)
    while at and at not in roots:
        at = _folder(at)
    return at


def _reach(s: Sign, roots: set[str]) -> str:
    """The folder a setting for every response is for."""
    name, at = s.file.rsplit("/", 1)[-1], _folder(s.file)
    if name in AT_ITS_APP or NEXT_CONFIG.fullmatch(name):
        return at
    if name == "_headers":
        return _folder(at) if at.rsplit("/", 1)[-1] in PUBLISHED else at
    return _app(s.file, roots)


def _left_out(g: Graph, repo, whole: list[Sign]) -> list[str]:
    """The apps of the project with pages or routes of their own that no setting for every response is for."""
    roots = {_folder(f) for f in repo.project_files if f.rsplit("/", 1)[-1] in APP_FILES}
    asked = {_app(n.file, roots) for n in g.entry_points()
             if (n.entry or {}).get("kind") in ASKED and n.file and not repo.is_test(n.file)}
    reach = {_reach(s, roots) for s in whole}
    return sorted(a for a in asked if not any(r == "" or a == r or a.startswith(r + "/") for r in reach))


def read(g: Graph, repo) -> tuple[str, str, list[str], list[str]]:
    """(status, words to add to the card's reason, the places as file:line, notes for an "add")."""
    signs, notes = _Reader(g, repo).all()
    whole = [s for s in signs if s.whole]
    if whole:
        s = whole[0]
        left = _left_out(g, repo, whole)
        if left:
            where = ", ".join("the top folder" if a == "" else f"`{a}/`" for a in left[:3])
            return ("check", f"The code sets one for every response of one part of the project: {SAYS[s.kind]} "
                    f"({s.file}:{s.line}). Nothing shows that the pages and routes in {where} get one. Check what "
                    "the site really sends.", _places(whole), [])
        return ("in place", f"The code sets one for every response: {SAYS[s.kind]} ({s.file}:{s.line}). Which headers "
                "are sent, and what they say, is not judged here.", _places(whole), [])
    if signs:
        kinds = list(dict.fromkeys(s.kind for s in signs))[:2]
        return ("check", "Lantern found header settings, and none that the code shows to cover every response: "
                + "; ".join(SAYS[k] for k in kinds) + ". Check what the site really sends.", _places(signs), [])
    return "add", "", [], list(dict.fromkeys(notes))[:2]


def _places(signs: list[Sign], n: int = 4) -> list[str]:
    out: list[str] = []
    for s in signs:
        w = f"{s.file}:{s.line}"
        if w not in out:
            out.append(w)
    return out[:n]
