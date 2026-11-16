"""What a browser keeps for a site, read from the code (review stage, 2026-11-15). Two heuristics, both
`tool_confidence: LOW` and ranked medium; they read lines and run nothing.

`LW-LOOPBACK-COOKIE` (`loopback_cookies`): a server that is started on this computer's own address (a tool a person
runs for themselves) and puts a login in a cookie. A browser keeps cookies by host name and not by port, so that
cookie goes with every request to any other program that serves pages on the same computer. The start and the cookie
are looked for in one file, or in two files of one folder.

`LW-SW-KEEPS-PAGES` (`keeps_pages`): a service worker whose `fetch` handler puts aside whatever it fetched under the
request's own address, with nothing in the handler that keeps it to a fixed list or to static files, on a site where
Lantern sees a login. A copy of a signed-in person's page then stays in the browser after they signed out or the
server stopped.

Neither knows what a cookie opens or what a page shows: both say "check"."""
from __future__ import annotations

import re
from pathlib import Path

from . import headers
from .websec import JS_EXTS, _files, _finding, _read, code_only

# Files that are not the app itself: tests, samples, documents.
NOT_THE_APP = re.compile(r"(^|/)(tests?|__tests__|e2e|cypress|playwright|fixtures|__mocks__|mocks?|stories|docs?|"
                         r"examples?|samples?|demos?|bench|benchmarks?)/|(^|/)(test_[^/]*|[^/]*_test)\.py$|"
                         r"\.(test|spec)\.[cm]?[jt]sx?$|\.d\.ts$|\.stories\.[jt]sx?$", re.I)
MOST_ARGS = 400              # characters of a call's arguments that are read
MOST_HANDLER = 20_000        # characters of a fetch handler that are read

LOOP = r"""["'`](?:127\.0\.0\.1|localhost|::1|\[::1\])["'`]"""
LOOP_RE = re.compile(LOOP)
NAME_RE = re.compile(r"[A-Za-z_$][\w$.]{0,80}")
EVERY_ADDRESS = re.compile(r"0\.0\.0\.0|[\"'`]::[\"'`]|[\"'`][\"'`]")

PY_SERVER = re.compile(r"(?<![\w.])(?:[A-Za-z_]\w{0,40}\.){0,3}(?P<what>(?:Threading|Threaded|Forking)?(?:HTTP|TCP|WSGI)Server|"
                       r"make_server|run_simple|TCPSite)\s*\(")
PY_RUN = re.compile(r"(?<![\w.])(?P<what>(?:[A-Za-z_]\w{0,40}\s*\.\s*){1,3}(?:run|run_app|serve))\s*\(")
PY_MAIN = re.compile(r"^if\s+__name__\s*==\s*[\"']__main__[\"']\s*:", re.M)
TRIAL_RUN = re.compile(r"(?<![\w.])(?:debug|reload|use_reloader)\s*=\s*True")
HOST_KEYWORD = re.compile(r"(?<![\w.])host\s*=\s*")
JS_LISTEN = re.compile(r"\.\s*listen\s*\(")
JS_HOST_KEY = re.compile(r"(?<![\w$])host(?:name)?\s*:\s*")

PY_SET = re.compile(r"\.\s*set_cookie\s*\(")
JS_SET = re.compile(r"(?<![\w$])(?:res|response|reply|ctx|c|h)\s*\.\s*(?:cookie|setCookie)\s*\(|"
                    r"(?<![\w$])cookies\s*(?:\(\s*\))?\s*\.\s*set\s*\(")
SET_HEADER = re.compile(r"""["'`]Set-Cookie["'`]\s*[,:]\s*""", re.I)
COOKIE_TEXT = re.compile(r"""\s*[fFrRbB]{0,2}["'`]\s*(?P<name>[\w.$-]{1,60})\s*=(?P<value>[^;"'`\n]{0,120})""")
KEYWORD = re.compile(r"^\s*(?:key|name|value)\s*=\s*")
# The framework's own session, which it keeps in a cookie: something is put into it (read on the blanked text)
SESSION_KEPT_PY = re.compile(r"(?<![\w$.])(?:(?:self\s*\.\s*)?request\s*\.\s*)?session\s*\[\s*~{3,62}\s*\]\s*=(?!=)")
SESSION_KEPT_JS = re.compile(r"(?<![\w$.])(?:req|request|ctx)\s*\.\s*session\s*\.\s*(?P<key>[A-Za-z_$][\w$]{0,40})\s*=(?!=)")
SESSION_KEY = re.compile(r"\[\s*[\"'](?P<key>[^\"'\n]{1,60})[\"']")
# ... and what is kept there says who is signed in (not the messages for the next page, a basket, a form's state)
SAYS_WHO = re.compile(r"user|logged|login|account|admin|member|email|identity|auth|token|(?<![a-z])uid(?![a-z])|"
                      r"(?<![a-z])who(?![a-z])", re.I)
NAME_KEY = re.compile(r"(?<![\w$])name\s*:\s*[\"'`](?P<name>[\w.$-]{1,60})[\"'`]")
VALUE_KEY = re.compile(r"(?<![\w$])value\s*:\s*(?P<value>[^,}\n]{1,80})")
# A cookie that says who is signed in, by its name or by the name of what is put in it
LOGIN_WORD = re.compile(r"token|sess|(?<![a-z])sid(?![a-z])|auth|jwt|secret|api[_-]?key|passw|credential|bearer|login|"
                        r"access[_-]?key|user[_-]?(?:name|id)|(?<![a-z])uid(?![a-z])", re.I)
# ... and the ones that are named alike and are none
NO_LOGIN = re.compile(r"csrf|xsrf|theme|lang|locale|consent|nonce|state|verifier|challenge|redirect|return|flash", re.I)


def _lines(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _close(code: str, open_at: int, most: int) -> int:
    """Where the bracket opened at `open_at` closes in `code` (strings and comments blanked), or the end of what is
    read when it does not close within `most` characters."""
    depth, end = 0, min(len(code), open_at + most)
    for i in range(open_at, end):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i
    return end


def _parts(text: str, code: str, open_at: int, most: int = MOST_ARGS) -> list[str]:
    """The arguments of the call whose parenthesis opens at `open_at`, as they are written."""
    end = _close(code, open_at, most)
    out, depth, start = [], 0, open_at + 1
    for i in range(open_at + 1, end):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(text[start:i])
            start = i + 1
    out.append(text[start:end])
    return [p.strip() for p in out if p.strip()]


def _default_is_this_computer(name: str, text: str) -> bool:
    """Is `name` given this computer's own address in this file: as a value, as a parameter's default, as the
    fallback of a setting, or as a command-line option's default?"""
    leaf = re.escape(name.split(".")[-1])
    given = (r"(?<![\w$.])" + leaf + r"\s*(?::\s*[\w\[\].]{1,40}(?:\s*\|\s*[\w\[\].]{1,40}){0,2})?\s*=\s*"
             r"(?:[\w.]{1,60}\(\s*[\"'][^\"'\n]{0,60}[\"']\s*,\s*|[\w$.]{1,60}\s*(?:\|\||\?\?)\s*)?" + LOOP)
    option = r"[\"']--?" + leaf + r"[\"'][^)\n]{0,200}?default\s*=\s*" + LOOP
    return bool(re.search(given, text) or re.search(option, text))


def _this_computer(expr: str, text: str) -> bool:
    """Does the host written as `expr` name this computer's own address (and no other)?"""
    expr = expr.strip()
    if not expr or EVERY_ADDRESS.search(expr):
        return False
    if LOOP_RE.search(expr):
        return True
    return bool(NAME_RE.fullmatch(expr)) and _default_is_this_computer(expr, text)


def _under_main(text: str, pos: int) -> bool:
    """Is `pos` in the block of an `if __name__ == "__main__":` at the top of a Python file?"""
    last = None
    for m in PY_MAIN.finditer(text, 0, pos):
        last = m
    if last is None:
        return False
    line = text.rfind("\n", 0, pos) + 1
    if line >= last.end() and text[line:line + 1] not in (" ", "\t"):
        return False                  # a line of the file's own after the block
    between = text[last.end():line]
    return all(not ln or ln[0] in " \t#" for ln in between.split("\n")[1:])


def _starts(text: str, code: str, js: bool) -> list[int]:
    """The places in a file where a server is started on this computer's own address."""
    found = []
    if js:
        for m in JS_LISTEN.finditer(code):
            for part in _parts(text, code, m.end() - 1):
                key = JS_HOST_KEY.search(part)
                host = part[key.end():].split(",")[0].split("}")[0] if key else part
                if _this_computer(host, text):
                    found.append(m.start())
                    break
        return found
    for m in PY_SERVER.finditer(code):
        parts = _parts(text, code, m.end() - 1)[:2]
        hosts = []
        for part in parts:
            if part.startswith("("):
                inner = _parts(part, code_only(part), 0)
                part = inner[0] if inner else ""
            hosts.append(part)
        hosts += [p[k.end():] for p in _parts(text, code, m.end() - 1) for k in [HOST_KEYWORD.match(p)] if k]
        if any(_this_computer(h, text) for h in hosts):
            found.append(m.start())
    for m in PY_RUN.finditer(code):
        parts = _parts(text, code, m.end() - 1)
        if any(TRIAL_RUN.search(p) for p in parts) or _under_main(text, m.start()):
            continue                  # a website's own trial run on the developer's computer
        if any(_this_computer(p[k.end():], text) for p in parts for k in [HOST_KEYWORD.match(p)] if k):
            found.append(m.start())
    return found


def _word(text: str) -> str:
    return text.strip().strip("\"'`")


def _says_login(name: str, value: str) -> bool:
    if NO_LOGIN.search(name):
        return False
    if LOGIN_WORD.search(name):
        return True
    value = value.strip()
    return bool(value) and value[0] not in "\"'`0123456789" and bool(LOGIN_WORD.search(value)) \
        and not NO_LOGIN.search(value)


def _cookies(text: str, code: str, off: list, js: bool) -> list[tuple[int, str]]:
    """The places in a file where a cookie that says who is signed in is set, each with the cookie's name."""
    found = []
    for m in (JS_SET if js else PY_SET).finditer(code):
        parts = [KEYWORD.sub("", p) for p in _parts(text, code, m.end() - 1)]
        if parts and parts[0].startswith("{"):        # `cookies.set({ name: 'session', value: ... })`
            name, value = NAME_KEY.search(parts[0]), VALUE_KEY.search(parts[0])
            parts = [name.group("name"), value.group("value") if value else ""] if name else []
        if parts and _says_login(_word(parts[0]), parts[1] if len(parts) > 1 else ""):
            found.append((m.start(), _word(parts[0])))
    for m in SET_HEADER.finditer(text):
        if headers._within(off, m.start()):
            continue
        said = COOKIE_TEXT.match(text, m.end())
        if not said:
            continue
        value = said.group("value")
        inserted = value if re.search(r"[{$%]", value) else ""
        if _says_login(said.group("name"), re.sub(r"[{}$%]", " ", inserted).strip()):
            found.append((m.start(), said.group("name")))
    for m in (SESSION_KEPT_JS if js else SESSION_KEPT_PY).finditer(code):
        key = m.group("key") if js else (SESSION_KEY.search(text, m.start(), m.end()) or [None, ""])[1]
        if SAYS_WHO.search(key) and not NO_LOGIN.search(key):
            found.append((m.start(), "session"))      # once a file: the first place it says who is signed in
            break
    return sorted(found)


def _read_as_code(p: Path, repo: Path):
    rel = p.relative_to(repo).as_posix()
    if NOT_THE_APP.search(rel):
        return None
    js = p.suffix != ".py"
    text = _read(p, repo)
    return rel, text, js


def loopback_cookies(repo: Path) -> list[dict]:
    """LW-LOOPBACK-COOKIE: one finding per line that sets such a cookie."""
    starts: dict[str, list[tuple[str, int, str]]] = {}        # folder -> [(file, line, the line's text)]
    cookies: list[tuple[str, int, str, str]] = []             # (file, line, the cookie's name, the line's text)
    for p in _files(repo, JS_EXTS | {".py"}):
        got = _read_as_code(p, repo)
        if got is None:
            continue
        rel, text, js = got
        binds = bool(re.search(r"listen\s*\(", text)) if js else bool(re.search(r"Server\s*\(|make_server|run_simple|"
                                                                               r"TCPSite|\.\s*(?:run|run_app|serve)\s*\(",
                                                                               text))
        sets = "cookie" in text.lower() or "session" in text
        if not (binds or sets):
            continue
        code = code_only(text, js=js)
        off = headers._not_code(text, js)
        lines = text.splitlines()
        folder = rel.rpartition("/")[0]
        if binds:
            for pos in _starts(text, code, js):
                ln = _lines(text, pos)
                starts.setdefault(folder, []).append((rel, ln, lines[ln - 1].strip() if ln <= len(lines) else ""))
        if sets:
            for pos, name in _cookies(text, code, off, js):
                ln = _lines(text, pos)
                cookies.append((rel, ln, name, lines[ln - 1].strip() if ln <= len(lines) else ""))
    out, seen = [], set()
    for rel, ln, name, line in sorted(cookies):
        here = starts.get(rel.rpartition("/")[0])
        if not here or (rel, ln) in seen:
            continue
        seen.add((rel, ln))
        at = next((s for s in here if s[0] == rel), here[0])
        out.append(_finding(
            "LW-LOOPBACK-COOKIE",
            f"A server for this computer only puts a login in a cookie (`{name[:60]}`), which the browser also sends "
            "to other programs on this computer",
            "MEDIUM", rel, ln, category="code", conf="LOW", cwe=287, fixed_rank="medium",
            more=("Heuristic: read from the lines of this folder's files. A server is started on this computer's own "
                  f"address in {at[0]}, line {at[1]}, and this line puts `{name[:60]}` in a cookie. A browser keeps "
                  "cookies by host name and not by port: it sends this one with every request to any other program "
                  "that serves pages on this computer, on whatever port, and that program can then ask this server "
                  "for whatever the cookie opens. HttpOnly and SameSite do not change that. That is as intended "
                  "when the cookie opens nothing by itself, or when this start is only a trial run of a site that "
                  "is served under a name of its own. Check what the cookie opens. For a server that stays on this "
                  "computer, hand the key to the page (in the part of the link after #), keep it in the page's own "
                  "storage, which the browser does keep apart for each port, and send it in a header with each "
                  "request."),
            snippet=line))
    return out


# ------------------------------------------------------------------ a service worker that keeps every page

FETCH_LISTENER = re.compile(r"""addEventListener\s*\(\s*["'`]fetch["'`]\s*,\s*""")
HANDLER_BY_NAME = re.compile(r"[A-Za-z_$][\w$.]{0,80}\s*\)")
NOT_READ = re.compile(r"workbox|precacheAndRoute|serwist|__WB_MANIFEST", re.I)          # a library keeps: not read
REQUEST_OF = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]{0,40}\s*\.\s*request(?![\w$])")
REQUEST_PICKED = re.compile(r"(?:const|let|var)\s+\{\s*request\s*(?::\s*(?P<a>[A-Za-z_$][\w$]{0,40}))?\s*\}\s*=")
REQUEST_NAMED = re.compile(r"(?:const|let|var)\s+(?P<b>[A-Za-z_$][\w$]{0,40})\s*=\s*[A-Za-z_$][\w$]{0,40}\s*\.\s*request"
                           r"\s*(?:[;\n]|$)")
HANDED_ON = re.compile(r"(?<![\w$.])(?P<to>[A-Za-z_$][\w$]{0,40})\s*\(\s*"
                       r"(?P<what>[A-Za-z_$][\w$]{0,40}(?:\s*\.\s*request)?)\s*[,)]")
NOT_A_HELPER = frozenset({"fetch", "Request", "URL", "String", "if", "while", "for", "switch", "return", "typeof",
                          "await", "catch", "function"})
REQUEST_HANDED = re.compile(r"\(\s*\{\s*request\s*(?:,[^}\n]{0,60})?\}\s*\)")       # `({ request }) =>`
STORED = re.compile(r"(?<![\w$])(?P<into>[A-Za-z_$][\w$]{0,40})\s*\.\s*(?:put|add)\s*\(\s*"
                    r"(?P<what>[A-Za-z_$][\w$]{0,40}(?:\s*\.\s*request)?)(?:\s*\.\s*url|\s*\.\s*clone\s*\(\s*\))?\s*[,)]")
NOT_A_STORE = frozenset({"classList", "headers", "formData", "params", "searchParams", "set", "seen", "list"})
# What keeps a handler to files that are the same for everybody
BY_KIND = re.compile(r"\.\s*destination(?![\w$])")
_ENDINGS = r"(?:css|m?js|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|wasm)"
BY_ENDING = re.compile(r"\\\.\(?(?:\?:)?" + _ENDINGS + r"(?![a-z])|endsWith\s*\(\s*[\"'`]\." + _ENDINGS + r"(?![a-z])",
                       re.I)
BY_FOLDER = re.compile(r"startsWith\s*\(\s*[\"'`]/?(?:static|assets|_next/static|_app/immutable|build|dist|img|images|"
                       r"fonts|css|js|icons|media|public)(?![a-z])", re.I)
# ... asked of a list, on the blanked text: not a text looked for in the address, and not the site's own origin
BY_LIST = re.compile(r"\.\s*(?:includes|has|indexOf)\s*\(\s*(?![~\s)])(?![\w$.]{0,60}origin)")
# A sign, anywhere in the project's own code, that somebody signs in
LOGIN_SIGN = re.compile(r"Set-Cookie|set_cookie\s*\(|\.\s*cookie\s*\(|Authorization|"
                        r"(?<![A-Za-z])(?:log|sign)[ _-]?(?:in|out)(?![a-z])|(?<![A-Za-z])(?:password|passwd|session)|"
                        r"(?<![A-Za-z])(?:access|auth|id|refresh|api)[_-]?token", re.I)
CODE_ENDINGS = JS_EXTS | {".py", ".html", ".htm", ".vue", ".svelte", ".php", ".rb", ".go", ".java", ".kt", ".cs"}
MOST_LOOKED_AT = 4000        # files looked through for a sign of a login


def _handlers(text: str, code: str, off: list) -> list[tuple[int, int]]:
    """The fetch handlers of a service worker, as (start, end) in the file."""
    out = []
    for m in FETCH_LISTENER.finditer(text):
        if headers._within(off, m.start()):
            continue
        if HANDLER_BY_NAME.match(code, m.end()):
            return [(0, len(text))]                 # the handler is a function written elsewhere in the file
        out.append((m.start(), _close(code, text.index("(", m.start()), MOST_HANDLER)))
    return out


def _narrowed(raw: str, body: str) -> bool:
    return bool(BY_KIND.search(body) or BY_ENDING.search(raw) or BY_FOLDER.search(raw) or BY_LIST.search(body))


def _keeps(text: str, code: str, start: int, end: int) -> int | None:
    """Where a fetch handler puts aside what it fetched for the request, when nothing keeps that to chosen files."""
    raw, body = text[start:end], code[start:end]
    if _narrowed(raw, body):
        return None
    names = {m.group("a") or "request" for m in REQUEST_PICKED.finditer(body)}
    if REQUEST_HANDED.search(body[:300]):
        names.add("request")
    names |= {m.group("b") for m in REQUEST_NAMED.finditer(body)}
    for m in STORED.finditer(body):
        what = re.sub(r"\s+", "", m.group("what"))
        if m.group("into") in NOT_A_STORE:
            continue
        if what in names or (what.endswith(".request") and REQUEST_OF.fullmatch(what)):
            return start + m.start()
    # nothing put aside in the handler itself: a function of the file that the handler hands the request to
    asked = names | {re.sub(r"\s+", "", r.group(0)) for r in REQUEST_OF.finditer(body)}
    handed = any(m.group("to") not in NOT_A_HELPER and re.sub(r"\s+", "", m.group("what")) in asked
                 for m in HANDED_ON.finditer(body))
    if not handed or (start, end) == (0, len(text)) or _narrowed(text, code):
        return None
    for m in STORED.finditer(code):
        if m.group("into") not in NOT_A_STORE and re.sub(r"\s+", "", m.group("what")) in names | {"request", "req"}:
            return m.start()
    return None


def _login_seen(repo: Path, not_these: set[str]) -> str | None:
    """A file of the project's own code that shows somebody signs in, or None."""
    from .js_frontend import built_bundle
    looked = 0
    for p in _files(repo, CODE_ENDINGS):
        rel = p.relative_to(repo).as_posix()
        if rel in not_these or NOT_THE_APP.search(rel) or built_bundle(p, repo):
            continue
        looked += 1
        if looked > MOST_LOOKED_AT:
            return None
        if LOGIN_SIGN.search(_read(p, repo)):
            return rel
    return None


def keeps_pages(repo: Path) -> list[dict]:
    """LW-SW-KEEPS-PAGES: one finding per service worker, on the line that puts the answer aside."""
    from .js_frontend import built_bundle
    kept: list[tuple[str, int, str]] = []
    workers: set[str] = set()
    for p in _files(repo, JS_EXTS):
        rel = p.relative_to(repo).as_posix()
        if NOT_THE_APP.search(rel) or built_bundle(p, repo):
            continue
        text = _read(p, repo)
        if "fetch" not in text or "addEventListener" not in text or not FETCH_LISTENER.search(text):
            continue
        workers.add(rel)
        if NOT_READ.search(text):
            continue
        code = code_only(text, js=True)
        off = headers._not_code(text, True)
        lines = text.splitlines()
        for start, end in _handlers(text, code, off):
            pos = _keeps(text, code, start, end)
            if pos is not None:
                ln = _lines(text, pos)
                kept.append((rel, ln, lines[ln - 1].strip() if ln <= len(lines) else ""))
                break
    if not kept:
        return []
    login = _login_seen(repo, workers)
    if login is None:
        return []                         # as far as Lantern sees, the pages are the same for everybody
    return [_finding(
        "LW-SW-KEEPS-PAGES",
        "This service worker keeps a copy of every page and answer it fetches, on a site people sign in to",
        "MEDIUM", rel, ln, category="code", conf="LOW", cwe=525, fixed_rank="medium",
        more=("Heuristic: read from this file's lines. Its `fetch` handler puts aside what it fetched under the "
              "request's own address, and Lantern found nothing in the handler that keeps this to a fixed list of "
              f"files or to static files. Lantern saw a sign that people sign in to this site in {login}, so some of "
              "those pages and answers are likely one person's own. A copy stays in the browser after that person "
              "has signed out, or after the server has stopped, and the service worker shows it again without "
              "asking the server: on a computer several people use, or at an address another program can serve "
              "later (a port of this computer), somebody else can read it. That is as intended on a site whose "
              "pages are the same for everybody. Keep a fixed list of files that hold nothing of one person's (the "
              "icon, the styles, a page that says the site is offline), or keep by kind of file, and delete what "
              "was kept when the person signs out."),
        snippet=line) for rel, ln, line in sorted(kept)]
