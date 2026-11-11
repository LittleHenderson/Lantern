"""Page templates: where a value is printed into the page without escaping (directive point 4, 2026-11-11).

A template engine escapes what it prints unless the template says not to: EJS `<%- x %>`, Handlebars and Mustache
`{{{x}}}` / `{{& x}}`, Pug `!{x}` / `p!= x`, Jinja, Django, Nunjucks and Twig `{{ x|safe }}` (`|raw`) and everything
inside `{% autoescape off %}`. `read(text, kind)` lists those places with the names of the page's values each one
prints: a loop's own name is traced back to what it loops over (`item` of `{% for item in items %}` is `items`), so
the route that renders the page can be asked what it handed in under that name (`lantern/flow.py`), and a line rule
can point at the place (`websec.template_rules`, LW-XSS-RAW).

Not counted as printing a value: an include or a layout slot (`<%- include('head') %>`, `<%- body %>`,
`{{{body}}}`), a value that goes through something named for escaping or cleaning first (`<%- escapeHtml(x) %>`,
`{{ x|escape|safe }}`, `{{ data|tojson|safe }}`), fixed text.

Everything here reads the template's text with patterns: a heuristic. A template language set up with other
delimiters, a helper that prints raw under a neutral name, and a partial handed its values by name are not seen."""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from .python_frontend import SKIP_DIRS, inside_repo, project_text

KINDS = {".ejs": "ejs", ".hbs": "hbs", ".handlebars": "hbs", ".mustache": "hbs", ".pug": "pug", ".jade": "pug",
         ".html": "jinja", ".htm": "jinja", ".jinja": "jinja", ".jinja2": "jinja", ".j2": "jinja", ".njk": "jinja",
         ".twig": "jinja"}
MAX_TEMPLATE = 400_000
NOT_APP = re.compile(r"(^|/)(tests?|spec|__tests__|e2e|vendor|node_modules|bower_components|dist|build|out|coverage|"
                     r"site-packages|\.next|\.nuxt|static|public|assets)/", re.I)


NOT_A_PAGE = (".min.html", ".component.html")     # a built page; an Angular component (`{{ x | safe }}` is its pipe)


class Raw(NamedTuple):
    line: int
    shown: str        # the place as written, short
    roots: tuple      # names of the page's values printed there
    way: str          # how the template says "do not escape": `<%- %>`, `|safe`


IDENT = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")
WORDS = {"true", "false", "null", "undefined", "none", "None", "True", "False", "this", "typeof", "new", "await",
         "in", "of", "if", "else", "not", "and", "or", "is", "JSON", "Object", "Array", "String", "Number", "Math",
         "Date", "locals", "loop", "self", "super", "range", "var", "let", "const", "function", "return"}
ESCAPER = re.compile(r"escape|sanitiz|purif|encode|clean|strip_?tags|\bxss\b|dompurify|bleach", re.I)
STRINGS = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`")

EJS_RAW = re.compile(r"<%-(.*?)[-_]?%>", re.S)
EJS_SLOT = re.compile(r"^\s*(?:await\s+)?(include|partial|layout|block|contentFor|defineContent)\b|"
                      r"^\s*(body|script|style|scripts|stylesheets|styles|meta|yield)\s*$")
EJS_LOOP = (re.compile(r"([A-Za-z_$][\w$.\[\]]*)\s*\.\s*(?:forEach|map|filter)\s*\(\s*(?:async\s+)?(?:function\s*)?\(?"
                       r"\s*([A-Za-z_$][\w$]*)"),
            re.compile(r"for\s*\(\s*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s+(?:of|in)\s+([A-Za-z_$][\w$.\[\]]*)"))
HBS_RAW = re.compile(r"\{\{\{\s*([^{}]*?)\s*\}\}\}|\{\{&\s*([^{}]*?)\s*\}\}")
HBS_SLOT = re.compile(r"^(body|yield|content|block\b.*|>.*|_sections\b.*|@partial-block)$")
HBS_BLOCK = re.compile(r"\{\{\s*([#/])\s*(each|with)\b\s*([^}\s]*)")
PUG_RAW = (re.compile(r"!\{([^}]*)\}"), re.compile(r"^\s*(?:[\w#.\-]+(?:\([^)]*\))?)?!=\s*(.+)$"))
PUG_LOOP = re.compile(r"^\s*(?:each|for)\s+([A-Za-z_$][\w$]*)(?:\s*,\s*[A-Za-z_$][\w$]*)?\s+in\s+(.+)$")
JINJA_OUT = re.compile(r"\{\{(.*?)\}\}", re.S)
JINJA_TAG = re.compile(r"\{%-?\s*(.*?)\s*-?%\}", re.S)
JINJA_FOR = re.compile(r"^for\s+([A-Za-z_][\w]*)(?:\s*,\s*([A-Za-z_][\w]*))?\s+in\s+(.+?)(?:\s+if\b.*)?$", re.S)
JINJA_SET = re.compile(r"^(?:with|set)\s+([A-Za-z_]\w*)\s*=\s*(.+)$", re.S)
JINJA_OFF = re.compile(r"^autoescape\s+(off|false)\b", re.I)
JINJA_ON = re.compile(r"^endautoescape\b", re.I)
SAFE_FILTERS = {"safe", "raw"}
ESCAPING_FILTERS = {"escape", "e", "forceescape", "force_escape", "tojson", "json_script", "urlencode", "linebreaks",
                    "linebreaksbr", "int", "float", "length", "count", "date", "time", "floatformat", "intcomma",
                    "filesizeformat", "striptags", "bleach", "sanitize", "clean", "urlize", "escapejs", "json_encode",
                    "url_encode", "abs", "round", "pluralize", "yesno", "timesince", "timeuntil", "naturaltime"}


def kind_of(rel: str) -> str | None:
    return KINDS.get(Path(rel).suffix.lower())


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _short(s: str) -> str:
    s = " ".join(s.split())
    return s if len(s) <= 70 else s[:67] + "..."


def _roots(expr: str, alias: dict) -> tuple:
    """The page values an expression reads: its names that are not members, calls, words of the language or text
    in quotes, each traced back through the loops it stands in."""
    bare = STRINGS.sub(" ", expr)
    out: list = []
    for m in IDENT.finditer(bare):
        name = m.group(0)
        if name in WORDS or bare[m.end():].lstrip()[:1] == "(":
            continue
        seen = set()
        while name in alias and name not in seen:
            seen.add(name)
            name = alias[name]
        if name and name not in WORDS and name not in out:
            out.append(name)
    return tuple(out)


def _root(path: str) -> str:
    m = IDENT.search(STRINGS.sub(" ", path))
    return m.group(0) if m else ""


def _escaped(expr: str) -> bool:
    """`escapeHtml(x)`, `sanitize(marked(x))`: the outermost thing the value goes through is named for escaping."""
    m = re.match(r"\s*(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(", expr)
    return bool(m and ESCAPER.search(m.group(1)))


def _ejs(text: str) -> list[Raw]:
    alias: dict = {}
    for rx in EJS_LOOP:
        for m in rx.finditer(text):
            a, b = (m.group(2), m.group(1)) if rx is EJS_LOOP[0] else (m.group(1), m.group(2))
            if a != _root(b):
                alias.setdefault(a, _root(b))
    out = []
    for m in EJS_RAW.finditer(text):
        expr = m.group(1).strip()
        if not expr or EJS_SLOT.search(expr) or _escaped(expr):
            continue
        roots = _roots(expr, alias)
        if roots:
            out.append(Raw(_line(text, m.start()), _short(m.group(0)), roots, "`<%- %>`"))
    return out


def _hbs(text: str) -> list[Raw]:
    blocks = sorted((m.start(), m.group(1), m.group(3)) for m in HBS_BLOCK.finditer(text))
    out = []
    for m in HBS_RAW.finditer(text):
        expr = (m.group(1) if m.group(1) is not None else m.group(2) or "").strip()
        if not expr or HBS_SLOT.match(expr):
            continue
        stack: list = []
        for pos, mark, what in blocks:
            if pos > m.start():
                break
            if mark == "#":
                stack.append(what)
            elif stack:
                stack.pop()
        first = expr.split()[0]
        if first in ("this", ".") or first.startswith(("this.", "./", "@")):
            roots = tuple(dict.fromkeys(_root(x) for x in stack if _root(x)))
        else:
            roots = _roots(first.replace("../", ""), {})
        if roots:
            out.append(Raw(_line(text, m.start()), _short(m.group(0)), roots, "`{{{ }}}`"))
    return out


def _pug(text: str) -> list[Raw]:
    alias: dict = {}
    lines = text.splitlines()
    for ln in lines:
        m = PUG_LOOP.match(ln)
        if m and m.group(1) != _root(m.group(2)):
            alias.setdefault(m.group(1), _root(m.group(2)))
    out = []
    for i, ln in enumerate(lines, 1):
        found = [(m.group(1), "`!{ }`") for m in PUG_RAW[0].finditer(ln)]
        m = PUG_RAW[1].match(ln)
        if m:
            found.append((m.group(1), "`!=`"))
        for expr, way in found:
            if not expr.strip() or _escaped(expr):
                continue
            roots = _roots(expr, alias)
            if roots:
                out.append(Raw(i, _short(ln.strip()), roots, way))
    return out


def _jinja(text: str) -> list[Raw]:
    if "{{" not in text:
        return []
    alias: dict = {}
    off: list = []          # (start, end) of `{% autoescape off %}` ... `{% endautoescape %}`
    start = None
    for m in JINJA_TAG.finditer(text):
        tag = m.group(1)
        f = JINJA_FOR.match(tag)
        if f:
            src = _root(f.group(3))
            for name in (f.group(1), f.group(2)):
                if name and name != src:
                    alias.setdefault(name, src)
            continue
        s = JINJA_SET.match(tag)
        if s and s.group(1) != _root(s.group(2)) and _root(s.group(2)):
            alias.setdefault(s.group(1), _root(s.group(2)))
            continue
        if JINJA_OFF.match(tag):
            start = m.end() if start is None else start
        elif JINJA_ON.match(tag) and start is not None:
            off.append((start, m.start()))
            start = None
    if start is not None:
        off.append((start, len(text)))
    out = []
    for m in JINJA_OUT.finditer(text):
        parts = [p.strip() for p in STRINGS.sub("''", m.group(1)).split("|")]
        filters = [re.match(r"[A-Za-z_]\w*", p).group(0) if re.match(r"[A-Za-z_]\w*", p) else "" for p in parts[1:]]
        marked = next((i for i, f in enumerate(filters) if f in SAFE_FILTERS), None)
        inside = any(a <= m.start() < b for a, b in off)
        if marked is None and not inside:
            continue
        before = filters[:marked] if marked is not None else filters
        if any(f in ESCAPING_FILTERS for f in before):
            continue
        head = m.group(1).split("|")[0]
        if _escaped(head):
            continue
        roots = _roots(head, alias)
        if roots:
            out.append(Raw(_line(text, m.start()), _short(m.group(0)), roots,
                           f"`|{filters[marked]}`" if marked is not None else "`{% autoescape off %}`"))
    return out


READERS = {"ejs": _ejs, "hbs": _hbs, "pug": _pug, "jinja": _jinja}


def read(text: str, kind: str) -> list[Raw]:
    """Every place in a template that prints a value without escaping it."""
    try:
        return READERS[kind](text)
    except (re.error, RecursionError):
        return []


def files(repo: Path):
    """(path from the project's root, text) of every page template of the project itself."""
    root = repo.resolve()
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in KINDS or not p.is_file() or not inside_repo(p, repo):
            continue
        parts = p.relative_to(root).parts
        if any(x in SKIP_DIRS for x in parts[:-1]) or p.name.endswith(NOT_A_PAGE):
            continue
        rel = p.relative_to(root).as_posix()
        if NOT_APP.search(rel):
            continue
        try:
            text = project_text(p, repo)
        except (OSError, UnicodeError):
            continue
        if len(text) <= MAX_TEMPLATE:
            yield rel, text


def index(repo: Path) -> dict[str, list[Raw]]:
    """The templates of the project that print a value without escaping it: {path: the places}."""
    out = {}
    for rel, text in files(repo):
        raws = read(text, kind_of(rel))
        if raws:
            out[rel] = raws
    return out


def named(paths, name: str) -> list[str]:
    """The template files a render call's name may stand for: `profile` is `views/profile.ejs`, `blog/post.html`
    is `blog/templates/blog/post.html`."""
    name = name.strip().lstrip("./")
    if not name:
        return []
    out = []
    for rel in paths:
        stem = rel[:-len(Path(rel).suffix)] if Path(rel).suffix else rel
        for cand in (rel, stem):
            if cand == name or cand.endswith("/" + name):
                out.append(rel)
                break
    return out
