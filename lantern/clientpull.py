"""`LW-SERVER-IMPORT-IN-CLIENT`: a file that reads a secret setting, pulled into the browser's side (roadmap of
2026-11-14, stage 5).

A file that begins with `"use client"` is handed to every visitor's browser, and so is every file it imports, and
every file those import. Where one of them was written for the server and reads a secret setting by its name
(`process.env.STRIPE_SECRET_KEY`), the server's code is in what visitors download. The setting itself arrives there
empty unless the build hands it over; `env` in `next.config.*` does, and then the secret's value is in the page.

Read from the map (`Graph.js_pulls`: which files of the project are loaded with each file, written down by the JS/TS
reader; an import of types only loads nothing) and from each reached file's own code. Nothing is built and nothing
is run. The way stops at a file that begins with `"use server"` (its functions are called over the network, the file
is not handed over) and at a file that imports `server-only` (a page that pulls it in does not build).

A settings file of t3's env libraries (`@t3-oss/env-nextjs`, `-core`, `-nuxt`) is made to be imported by pages: a page
reads its public settings, the server's settings it lists come from `process.env`, which the build hands to a page
only where it is told to, and the library refuses a server setting read in the browser. A read inside the library's
call is no server code in the page (`checker_calls`); a read outside it still is, and where `env` in `next.config.*`
hands the setting over, its value is in the page wherever the file reads it, inside the call too.

A heuristic. What import lines do not show: a bundler leaves out code that nothing calls, a project with no
`"use client"` file is not read at all, `import()` and `require` are not followed, and a file that only loads a
server library and reads no secret setting is not named (a page that pulls a database driver in does not build).
"""
from __future__ import annotations

import re
from pathlib import Path

from tree_sitter import Parser

from .aiapp import read_as_code
from .js_frontend import LANGS
from .localweb import NOT_THE_APP
from .python_frontend import inside_repo, project_text
from .websec import PUBLIC_PREFIX, SAFE_NAMES, SECRET_WORD, _finding

RULE = "LW-SERVER-IMPORT-IN-CLIENT"
MOST_FILE = 2_000_000       # characters of a file that are read
MOST_LOOKED = 400           # places of one file that are asked about (is this code, or a text that names a setting?)
MOST_APART = 4_000          # characters of `const { A, B } = process.env` that are read back from its end
MOST_REACHED = 20_000       # files that are followed from the client files
MOST_FOUND = 200            # findings of one project
MOST_STEPS = 3_000_000      # import lines looked at while counting the client files that reach a file
MOST_SHOWN = 12             # files of a way that are listed, and settings of a file that are named
MOST_CONFIG = 200_000       # characters of a next.config file that are read
MOST_BLOCK = 20_000         # characters of its `env` block

# A setting's name says it is a secret: the words every rule about settings reads, and a database's address, which
# carries the database's password.
SECRET_NAME = re.compile(rf"{SECRET_WORD}|[A-Z0-9_]*(?:POSTGRES|POSTGRESQL|MONGODB|MONGO|MYSQL|REDIS)_(?:URL|URI)"
                         r"[A-Z0-9_]*")
PUBLIC_NAME = re.compile(PUBLIC_PREFIX)
_N = rb"([A-Z][A-Z0-9_]*)"
_BAG = rb"(?:process\.env|import\.meta\.env|Bun\.env)"
# process.env.NAME, process.env["NAME"], import.meta.env.NAME, Bun.env.NAME, Deno.env.get("NAME"); not `env.NAME`,
# which is an object of the project's own (one that checks its settings refuses a server's setting in a page)
READ = re.compile(rb"(?<![\w$])(?:" + _BAG + rb"\s*(?:\.\s*" + _N + rb"(?![\w$])|\[\s*[\"'`]" + _N + rb"[\"'`]\s*\])"
                  rb"|Deno\.env\.get\(\s*[\"'`]" + _N + rb"[\"'`]\s*\))")
# const { NAME, OTHER: local } = process.env
APART = re.compile(rb"\}\s*=\s*(" + _BAG + rb")(?![\w$])(?!\s*[.\[?])")
A_NAME = re.compile(rb"[A-Z][A-Z0-9_]*")
CODE = ("identifier", "meta_property")      # what tree-sitter says stands where code names the settings' object
# t3's env libraries, which keep a server's settings out of a page (see the note above): their import line, and a
# call of their function by the name it was given there
SHARED_CHECKER = re.compile(rb"""import\s*\{([^}]{0,400})\}\s*from\s*["']@t3-oss/env-(?:nextjs|core|nuxt)["']""")
MOST_CALLS = 20             # calls of that function in one file that are looked at

NEXT_CONFIGS = ("next.config.js", "next.config.mjs", "next.config.cjs", "next.config.ts")
ENV_BLOCK = re.compile(r"(?<![\w$.])env\s*:\s*\{")
ENV_KEY = re.compile(r"""(?:^|[{,])\s*["']?([A-Z][A-Z0-9_]*)["']?\s*(?=[:,}])""")


def secret_name(name: str) -> bool:
    """Does a setting's name say it is a secret that only the server may hold?"""
    return bool(SECRET_NAME.fullmatch(name)) and not PUBLIC_NAME.match(name) and not SAFE_NAMES.search(name)


def checker_calls(text: str, rel: str) -> list[tuple[int, int]]:
    """Where a file calls the function of t3's env libraries (`createEnv`, or the name the import line gives it): the
    byte range of each call, or [] when the file does not import it. At most `MOST_CALLS` calls are looked at."""
    data = text.encode("utf-8", "replace")
    names: set[bytes] = set()
    for m in SHARED_CHECKER.finditer(data):
        for part in m.group(1).split(b","):
            words = part.split()
            if words and words[0] == b"createEnv":
                names.add(words[2] if len(words) == 3 and words[1] == b"as" else b"createEnv")
    if not names:
        return []
    end = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    root = Parser(LANGS.get(end, LANGS[".tsx"])).parse(data).root_node
    spans: list[tuple[int, int]] = []
    called = re.compile(rb"(?<![\w$.])(" + b"|".join(re.escape(n) for n in sorted(names)) + rb")\s*\(")
    for m in called.finditer(data):
        if len(spans) >= MOST_CALLS:
            break
        node = root.named_descendant_for_byte_range(m.start(1), m.end(1))
        if node is None or node.type != "identifier" or node.parent is None:
            continue
        call = node.parent
        if call.type == "call_expression" and call.child_by_field_name("function") == node:
            spans.append((call.start_byte, call.end_byte))
    return spans


def secret_reads(text: str, rel: str, skip: list[tuple[int, int]] | None = None) -> list[tuple[int, str]]:
    """The secret settings a JS/TS file's code reads by name: `(line, name)`, each setting once, at its first read.
    A name in a remark, in a text, in a pattern or in the words of a page is no read: tree-sitter is asked what
    stands at the place (a name inside `${…}` of a template is code). At most `MOST_LOOKED` places are asked
    about. A read inside one of the byte ranges of `skip` is not counted."""
    data = text.encode("utf-8", "replace")
    if b"env" not in data:
        return []
    known: dict[bytes, bool] = {}
    hits: list[tuple[int, bytes, int]] = []         # where the name stands, the name, where the settings' object
    for m in READ.finditer(data):
        name = m.group(1) or m.group(2) or m.group(3)
        if name not in known:
            known[name] = secret_name(name.decode("ascii"))
        if known[name]:
            hits.append((m.start(), name, m.start()))
    for m in APART.finditer(data):
        close = m.start()
        opened = data.rfind(b"{", max(0, close - MOST_APART), close)
        if opened < 0:
            continue
        at = opened + 1
        for part in data[at:close].split(b","):
            got = A_NAME.match(part.lstrip())
            name = got.group(0) if got else b""
            rest = part.lstrip()[len(name):].lstrip()[:1]
            if name and rest in (b"", b":", b"=") and secret_name(name.decode("ascii")):
                hits.append((at + len(part) - len(part.lstrip()), name, m.start(1)))
            at += len(part) + 1
    if skip:
        hits = [h for h in hits if not any(a <= h[0] < b for a, b in skip)]
    if not hits:
        return []
    out: list[tuple[int, str]] = []
    seen: set[bytes] = set()
    root, looked, line, last = None, 0, 1, 0
    for at, name, head in sorted(hits):
        if name in seen:
            continue
        if looked >= MOST_LOOKED:
            break
        if root is None:
            end = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
            root = Parser(LANGS.get(end, LANGS[".tsx"])).parse(data).root_node
        looked += 1
        node = root.named_descendant_for_byte_range(head, head + 1)
        if node is None or node.type not in CODE:
            continue
        line += data.count(b"\n", last, at)
        last = at
        seen.add(name)
        out.append((line, name.decode("ascii")))
    return out


def handed_by(text: str, rel: str) -> dict[str, int]:
    """The settings a `next.config.*` file hands to the page's code: the names written in its `env: {…}` block, each
    with its line. Next.js writes the value of each into the page's code wherever the code reads the setting. A
    remark is not read."""
    code = "\n".join(read_as_code(text.split("\n"), rel)[0])
    out: dict[str, int] = {}
    for m in ENV_BLOCK.finditer(code):
        depth, end = 1, m.end()
        while end < len(code) and end - m.end() < MOST_BLOCK and depth:
            depth += {"{": 1, "}": -1}.get(code[end], 0)
            end += 1
        block = code[m.end() - 1:end]
        for key in ENV_KEY.finditer(block):
            out.setdefault(key.group(1), code.count("\n", 0, m.end() - 1 + key.start(1)) + 1)
    return out


class _Configs:
    """Which `next.config.*` file a client file is built with (the nearest above it), and what that file hands on."""

    def __init__(self, repo: Path):
        self.repo = repo
        self.of: dict[str, tuple[str, dict[str, int]] | None] = {}

    def at(self, folder: str) -> tuple[str, dict[str, int]] | None:
        if folder not in self.of:
            self.of[folder] = None
            for name in NEXT_CONFIGS:
                rel = f"{folder}/{name}" if folder else name
                p = self.repo / rel
                if not inside_repo(p, self.repo):
                    continue
                try:
                    text = project_text(p, self.repo, MOST_CONFIG + 1)
                except OSError:
                    continue
                self.of[folder] = (rel, handed_by(text, rel) if len(text) <= MOST_CONFIG else {})
                break
        return self.of[folder]

    def hands(self, client: str, names: list[str]) -> tuple[str, dict | None]:
        """The first of `names` that the client file's build hands to the page, and where it says so."""
        folder = client.rsplit("/", 1)[0] if "/" in client else ""
        while True:
            got = self.at(folder)
            if got is not None:
                for name in names:
                    if name in got[1]:
                        return name, {"file": got[0], "line": got[1][name]}
                return "", None
            if not folder:
                return "", None
            folder = folder.rsplit("/", 1)[0] if "/" in folder else ""


def _way(path: list[str]) -> tuple[list[str], int]:
    """A way as it is listed: whole, or its two ends with the number of files between that are not listed."""
    if len(path) <= MOST_SHOWN:
        return path, 0
    half = MOST_SHOWN // 2
    return path[:half] + path[-half:], len(path) - 2 * half


def _words(rel: str, names: list[str], lines: dict[str, int], path: list[str], not_shown: int, first_line: int | None,
           clients: int | None, handed: dict | None) -> tuple[str, str]:
    """A finding's title and what stands under it."""
    name, client = names[0], path[0]
    more = f" (and {len(names) - 1} more)" if len(names) > 1 else ""
    alone = len(path) == 1
    title = (f'{rel} begins with "use client" and reads the secret setting {name}{more}' if alone else
             f"{rel} reads the secret setting {name}{more} and is pulled into the browser's side by {client}")
    if handed:
        title += f", and {handed['file']} hands that setting to the page's code"
    if alone:
        how = (f'{rel} begins with "use client", so its code is part of what every visitor\'s browser downloads.')
    else:
        half = len(path) // 2
        chain = (" → ".join(path) if not not_shown else
                 " → ".join(path[:half]) + f" → … ({not_shown} more files) … → " + " → ".join(path[half:]))
        how = (f'{client} begins with "use client", so it is handed to every visitor\'s browser with every file it '
               f"imports and every file those import. This file is reached that way: {chain}"
               + (f" (the first step is the import on line {first_line} of {client})." if first_line else "."))
    others = (clients or 1) - 1
    if others:
        how += (f' {others} other file that begins with "use client" reaches it too.' if others == 1 else
                f' {others} other files that begin with "use client" reach it too.')
    listed = names[:MOST_SHOWN]
    read = (f"Its code reads the secret setting {name} on line {lines[name]}." if len(names) == 1 else
            "Its code reads the secret settings " + ", ".join(f"{n} (line {lines[n]})" for n in listed)
            + (f" and {len(names) - len(listed)} more." if len(names) > len(listed) else "."))
    if handed:
        value = (f"{handed['file']} line {handed['line']} names {name} under `env`, and Next.js writes the value of "
                 "every setting named there into the page's code wherever the code reads it: the secret itself is "
                 "then in what every visitor downloads. Replace the secret with a new one once this is fixed.")
    else:
        value = ("So the server's code is in the page's files for anyone to read: which service it calls, how, and "
                 "under which setting's name. The setting itself arrives there empty unless the build hands it over "
                 "(Lantern found no `env` entry of a next.config file that names it), and code that needs it then "
                 "fails in the browser.")
    do = ('Keep the read in a file that only the server loads: put the work behind a route or a Server Action (a '
          'file that begins with "use server") and let the page call that, and write `import "server-only"` at the '
          "top of this file, so that a page which pulls it in does not build.")
    return title, (f"Heuristic: read from import lines and settings' names; nothing was built and nothing run. {how} "
                   f"{read} {value} {do} This is no problem only where the file's code does not reach a page after "
                   "all (a bundler leaves out code that nothing calls) or the setting is no secret; neither can be "
                   "read from import lines.")


def reached(g) -> tuple[list[str], dict[str, str | None], set[str]]:
    """What is handed to the browser by what the import lines say: the files that begin with `"use client"`, every
    file loaded with one of them (each with the file it was reached from, in the order reached; a client file with
    None), and the files the way stops at (`"use server"`, `server-only`)."""
    said = g.meta.get("js_directives") or {}
    pulls = getattr(g, "js_pulls", None) or {}
    closed = {rel for rel, d in said.items() if "use server" in d} | set(getattr(g, "js_server_only", None) or ())
    clients = sorted(rel for rel, d in said.items()
                     if "use client" in d and rel not in closed and not NOT_THE_APP.search(rel))
    # breadth first from every client file at once: a file is reached from the nearest one, the first by name
    came: dict[str, str | None] = {c: None for c in clients}
    order = list(clients)
    for rel in order:                               # grows while it is gone through
        if len(order) >= MOST_REACHED:
            break
        for nxt in sorted(pulls.get(rel, ())):
            if nxt not in came and nxt not in closed:
                came[nxt] = rel
                order.append(nxt)
    return clients, came, closed


def pulled(g) -> list[dict]:
    """LW-SERVER-IMPORT-IN-CLIENT: one finding for each file whose code reads a secret setting and that is loaded
    with a file that begins with `"use client"` (that file itself, or one reached through value imports and
    re-exports), on the line of its first such read."""
    repo = Path(g.repo_root)
    pulls = getattr(g, "js_pulls", None) or {}
    clients, came, closed = reached(g)
    if not clients:
        return []
    targets: list[tuple[str, list[tuple[int, str]]]] = []
    for rel in came:
        if NOT_THE_APP.search(rel):
            continue
        try:
            text = project_text(repo / rel, repo, MOST_FILE + 1)
        except OSError:
            continue
        if len(text) > MOST_FILE or "env" not in text:
            continue
        reads = secret_reads(text, rel)
        if reads:
            spans = checker_calls(text, rel)
            targets.append((rel, reads, secret_reads(text, rel, skip=spans) if spans else reads))
            if len(targets) >= MOST_FOUND:
                break
    if not targets:
        return []
    back: dict[str, list[str]] = {}                 # which files load a file
    for src, got in pulls.items():
        if src not in closed:
            for dst in got:
                back.setdefault(dst, []).append(src)
    start, steps = set(clients), 0
    configs, out = _Configs(repo), []
    for rel, every, reads in sorted(targets):
        path = [rel]
        while came[path[-1]] is not None:
            path.append(came[path[-1]])
        path.reverse()
        first, handed = configs.hands(path[0], [name for _line, name in every])
        if handed:
            reads = every                           # the build writes the value wherever the file reads it
        elif not reads:
            continue                                # every read stands inside the call of t3's env library
        count: int | None = 0                       # the client files that reach it, counted against the imports
        seen, todo = {rel}, [rel]
        while todo and count is not None:
            cur = todo.pop()
            count += cur in start
            for src in back.get(cur, ()):
                steps += 1
                if src not in seen:
                    seen.add(src)
                    todo.append(src)
            if steps > MOST_STEPS:
                count = None                        # not counted: said as not known, never as a number
        lines = {name: line for line, name in reads}
        names = [name for _line, name in reads]
        if handed:
            names.remove(first)
            names.insert(0, first)
        shown, not_shown = _way(path)
        first_line = pulls.get(path[0], {}).get(path[1]) if len(path) > 1 else None
        title, more = _words(rel, names, lines, shown, not_shown, first_line, count, handed)
        out.append({**_finding(RULE, title, "HIGH" if handed else "MEDIUM", rel, lines[names[0]],
                               category="exposure", conf="LOW", cwe=200, more=more, snippet=names[0],
                               fixed_rank="high" if handed else "medium"),
                    "pulled": {"settings": names[:MOST_SHOWN], "path": shown, "not_shown": not_shown,
                               "clients": count, "handed": handed}})
    return out
