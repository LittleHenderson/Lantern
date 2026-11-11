"""Security features to add (spec 9.4): protections a senior engineer would put in, each shown only when the code
gives a reason, with the evidence that triggered it.

Findings say what is wrong in code that exists; this says what is missing. Every item is a heuristic built from the
graph and file patterns (so it is labeled as such), and none of them changes a finding or the readiness score.

Each item: {id, title, status: "add" | "check" | "in place", why, evidence: [file:line ...], how, found: [...]}
"check" means the code shows an app-wide mechanism (middleware, a router dependency, an auth library) but not
that it covers the routes in question; the reader has to confirm it.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import ratelimit
from .context import code_mentions, handles_passwords, password_hash_uses
from .graph import Graph
from .websec import call_adjacency, code_only, is_public_route, login_check, mentions_auth, mutating_route

SENSITIVE_PATH = re.compile(r"(^|/)(login|log-in|signin|sign-in|signup|sign-up|register|auth|token|session|password|"
                            r"reset|forgot|otp|verify|magic-link|2fa|mfa|invite)(/|$|\b)", re.I)
RATE_LIMIT_LIBS = ratelimit.LIBS      # what a rate-limiting library is called; where one is put to work: ratelimit.py
HEADER_SIGNS = re.compile(r"helmet|Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|"
                          r"SecurityMiddleware|secure\.Secure|talisman|frame-ancestors", re.I)
FAST_HASH = re.compile(r"hashlib\.(md5|sha1|sha224|sha256|sha512)\s*\(|createHash\(\s*['\"](md5|sha1|sha256|sha512)['\"]")
# Whole words: `\bcrypto` in a regex string reads as "bcrypt" without them. Searched in dependency files and in code
# with strings and comments blanked (a word in a list of phrases is not a hashing library).
SLOW_HASH = re.compile(r"(?<![\w-])(?:bcrypt(?:js)?|argon2(?:-cffi|id)?|scrypt|passlib|pbkdf2(?:_hmac)?|"
                       r"generate_password_hash|make_password|pwdlib)(?![\w-])", re.I)
MANAGED_AUTH = re.compile(r"@supabase/|supabase\.auth|next-auth|@auth/|@clerk/|firebase/auth|firebase-admin|"
                          r"auth0|lucia|better-auth|django\.contrib\.auth|fastapi[-_]users|flask[-_]login", re.I)
SERVER_FETCH = re.compile(
    r"\b(requests|httpx)\.(get|post|put|patch|delete|request|head|stream)\(\s*"
    r"(?![\"']|f[\"']|url=[\"'])([A-Za-z_][\w.\[\]'\"]*)|\burlopen\(\s*(?![\"'])([A-Za-z_][\w.]*)|"
    r"\bfetch\(\s*(?![\"'`])([A-Za-z_][\w.]*)\s*[,)]")
ALLOW_LIST = re.compile(r"allow_?list|allowed_?hosts|ALLOWED_HOSTS|allowedHosts|ALLOWED_DOMAINS|is_private|"
                        r"isPrivate|ssrf", re.I)
UPLOAD = re.compile(r"\bUploadFile\b|request\.files|multer\(|formData\(\)|\.formData\(|FileField|busboy|formidable")
UPLOAD_LIMIT = re.compile(r"MAX_CONTENT_LENGTH|max_size|maxFileSize|fileSize|content_type|contentType|mimetype|"
                          r"fileFilter|DATA_UPLOAD_MAX|sizeLimit|bodyParser", re.I)
# Framework settings written as a string key (`app.config["MAX_CONTENT_LENGTH"] = ...`), matched in the raw text
UPLOAD_LIMIT_KEY = re.compile(r"[\"'](?:MAX_CONTENT_LENGTH|DATA_UPLOAD_MAX_MEMORY_SIZE|FILE_UPLOAD_MAX_MEMORY_SIZE)[\"']\s*\]?\s*[=:]")
# App-wide mechanisms: middleware, router-level dependencies, auth libraries wired in once
GLOBAL_AUTH = re.compile(
    r"add_middleware\(\s*\w*(?:auth|login|session|jwt)\w*|AuthenticationMiddleware|LoginRequiredMiddleware|"
    r"DEFAULT_PERMISSION_CLASSES|dependencies\s*=\s*\[\s*Depends\(|before_request|@app\.middleware|"
    r"\b(?:app|router|server)\.use\(\s*[^)\n]*(?:auth|passport|jwt|session|requireUser|protect|guard|clerk)|"
    r"clerkMiddleware|withAuth\(|authMiddleware|export\s+(?:default\s+)?(?:async\s+)?function\s+middleware\b|"
    r"export\s+const\s+middleware\b|withMiddlewareAuth", re.I)


def _where(hits, n=4) -> list[str]:
    out: list[str] = []
    for f, ln, _ in hits:          # one place per line: a pattern that matches twice on a line is still one place
        w = f"{f}:{ln}"
        if w not in out:
            out.append(w)
    return out[:n]


def _code_grep(repo, rx: re.Pattern, limit: int = 20) -> list[tuple[str, int, str]]:
    """Matches in code with strings and comments blanked. A word inside advice text, a message or a pattern list
    (Lantern's own `UPLOAD = re.compile(r"...UploadFile...")`) is not upload handling or a rate limiter."""
    out = []
    for f, t in repo.code():
        if not rx.search(t):
            continue
        code = code_only(t, js=not f.endswith(".py"))
        for m in rx.finditer(code):
            line = code.count("\n", 0, m.start()) + 1
            out.append((f, line, t.splitlines()[line - 1].strip()[:160]))
            if len(out) >= limit:
                return out
    return out


def _deps_text(repo) -> str:
    return " ".join(repo.text(f) for f in repo.project_files
                    if f.rsplit("/", 1)[-1] in ("pyproject.toml", "package.json", "Pipfile")
                    or re.search(r"(^|/)requirements[^/]*\.txt$", f))


def _config_hits(repo, rx: re.Pattern) -> list[tuple[str, int, str]]:
    """Matches in code plus hosting config files (vercel.json, netlify.toml, _headers, next.config.*)."""
    hits = repo.grep(rx, limit=5)
    for f in repo.project_files:
        name = f.rsplit("/", 1)[-1]
        if name in ("vercel.json", "netlify.toml", "_headers", "nginx.conf", "Caddyfile") or name.startswith("next.config"):
            t = repo.text(f)
            m = rx.search(t)
            if m:
                hits.append((f, t.count("\n", 0, m.start()) + 1, ""))
    return hits


def _rate_limit(view, trig: list, what: str) -> tuple[str, str, list[str], list[str]]:
    """(status, why, evidence, found) for the rate-limit item: "in place" only when every route in question shows a
    limit that covers it; "check" when a limit exists and the code does not show that for each of them; "add" when
    nothing puts a limit to work, whatever is installed."""
    states = [(n, d, *view.of(n)) for n, d in trig]
    yes = [s for s in states if s[2] == "yes"]
    own = [s for s in states if s[2] == "own"]
    maybe = [s for s in states if s[2] == "maybe"]
    rest = [s for s in states if s[2] != "yes"]
    shown = [f"{d} ({n.file}:{n.start_line})" for n, d, _s, _w in (rest + yes)[:4]]     # the ones without first
    if len(yes) == len(states):
        return ("in place", f"{what} could be called as fast as an attacker likes; the code puts a request limit on "
                + ("each of them." if len(states) > 1 else "it."), shown, [f"{d}: {w}" for _n, d, _s, w in yes[:4]])
    open_ = ("can be called as fast as an attacker likes: password guessing, sign-up spam, or running up your bill.")
    if yes or own or maybe:
        parts = []
        if yes:
            parts.append(f"{len(yes)} of {len(states)} show a limit that covers the route; the others do not.")
        if own:
            parts.append(f"{own[0][3]}: a name is not a limit, so check what it does.")
        if maybe:
            parts.append("A limit is set up for the whole app, but the code does not show that it covers "
                         + ("these routes" if len(states) > 1 else "this route")
                         + " or that it is tight enough for signing in; check the ones listed.")
        found = list(dict.fromkeys([f"{d}: {w}" for _n, d, _s, w in yes[:2]] + [w for _n, _d, _s, w in maybe[:2]]
                                   + [w for _n, _d, _s, w in own[:2]]))
        return "check", f"{what} {open_} " + " ".join(parts), shown, found[:4]
    notes = list(dict.fromkeys(w for _n, _d, _s, w in states if w))
    more = ""
    if view.installed:
        more = (f" `{view.installed}` is installed, but nothing in the code puts a limit on "
                + ("these routes." if len(states) > 1 else "this route."))
    if notes:
        more += " " + notes[0][0].upper() + notes[0][1:] + "."
    return "add", f"{what} {open_}{more}", shown, []


def advise(g: Graph, sec: dict | None, repo, shape: str) -> list[dict]:
    web = shape in ("full-stack web app", "web API", "frontend web app")
    # Routes in test code (a test's own server, the sample apps under tests/fixtures) are not the app's routes
    routes = [(n, (n.entry or {}).get("detail") or "") for n in g.entry_points()
              if (n.entry or {}).get("kind") == "route" and not (n.file and repo.is_test(n.file))]
    deps = _deps_text(repo)
    # In code, or on an import line (a JS import names its package in a string); not a word in a pattern list
    managed = MANAGED_AUTH.search(deps) or _code_grep(repo, MANAGED_AUTH, limit=1) or [
        h for h in repo.grep(MANAGED_AUTH, limit=50) if re.match(r"\s*(import|from|export)\b|.*\brequire\(", h[2])][:1]
    out: list[dict] = []

    def item(id_, title, status, why, evidence, how, found=None):
        out.append({"id": id_, "title": title, "status": status, "why": why, "evidence": evidence, "how": how,
                    "found": found or [], "heuristic": True})

    # 1. Rate limiting on sign-in and other abuse-prone routes
    sensitive = [(n, d) for n, d in routes if SENSITIVE_PATH.search(d.partition(" ")[2] or d)]
    writes = [(n, d) for n, d in routes if d.split(" ")[0].upper() in ("POST", "PUT", "PATCH", "DELETE")]
    if sensitive or writes:
        # A library that is installed protects nothing (until 2026-11-11 its name in the dependencies read "in
        # place"): the limit has to be on the route, or on the app where the code shows it covers the route.
        trig = sensitive or writes
        what = f"{len(sensitive)} sign-in or account route(s)" if sensitive else f"{len(writes)} route(s) that change data"
        status, why, shown, found = _rate_limit(ratelimit.view(g, repo, deps), trig, what)
        item("rate-limit", "Rate limiting", status, why, shown,
             "Limit requests per user and per IP on these routes: slowapi (FastAPI), Flask-Limiter, express-rate-limit, "
             "or @upstash/ratelimit (Next.js / serverless).", found)

    # 2. Security headers
    if web:
        hh = _config_hits(repo, HEADER_SIGNS)
        item("security-headers", "Security headers", "in place" if hh else "add",
             "Browsers protect your users from clickjacking, mixed content, and injected scripts only when the app "
             "sends headers such as Content-Security-Policy, Strict-Transport-Security, and X-Frame-Options.",
             [f"{shape}; no header setup found in code or hosting config"] if not hh else [],
             "Set them once for every response: helmet (Express), the headers() block in next.config.js, "
             "a vercel.json/netlify.toml headers rule, or a small middleware in FastAPI/Flask.",
             _where(hh))

    # 3. SSRF: the server fetches a URL that isn't a fixed string
    if routes:
        hits = [h for h in repo.grep(SERVER_FETCH, limit=40) if not _client_side(h[0])]
        if hits:
            # Only an allow-list in a file that makes these requests: `ALLOWED_HOSTS` for the Host header a server
            # answers to (Django, lantern-cloud's settings) says nothing about where it sends requests
            fetching = {f for f, _, _ in hits}
            allow = [h for h in _code_grep(repo, ALLOW_LIST, limit=200) if h[0] in fetching][:1]
            item("ssrf-allowlist", "Allow-list for outgoing requests", "in place" if allow else "add",
                 "The server makes HTTP requests to an address held in a variable. "
                 + ("An allow-list was found in the code; confirm it is checked before these requests." if allow else
                    "If any part of it comes from a user, they can make your server call internal services or cloud "
                    "metadata endpoints (SSRF)."),
                 _where(hits),
                 "Only call hosts from a fixed allow-list, reject private and link-local IP addresses, and never pass a "
                 "user-supplied URL straight to requests/httpx/fetch.",
                 _where(allow))

    # 4. Slow password hashing. "Passwords are handled" means code names a password value (a word in a string, a
    # comment or a regex list does not count); "a fast hash on a password" means the hashed value, where the result
    # goes, or the function around it is password-named (context.py, names only). A fast hash used for an id, a seed
    # or a checksum is not evidence about passwords.
    pw = handles_passwords(repo.code())
    if pw and not managed:
        fast = password_hash_uses(g, repo.grep(FAST_HASH, limit=200), lambda f: repo.text(f).splitlines(), {})
        slow = SLOW_HASH.search(deps) or code_mentions(repo.code(), SLOW_HASH)
        if fast:
            item("password-hashing", "Slow password hashing", "add",
                 "A fast hash (MD5/SHA) is applied to a password-named value: a leaked database could be cracked in hours.",
                 _where(fast),
                 "Store only argon2 or bcrypt hashes (passlib/pwdlib/bcrypt in Python, bcrypt or argon2 in Node), or "
                 "use a managed auth service so you never store passwords.")
        elif slow:
            item("password-hashing", "Slow password hashing", "in place",
                 "Passwords are handled in the code, and a slow hashing library is present.", [],
                 "Keep using it for every stored password.", ["bcrypt / argon2 / scrypt found"])
        else:
            item("password-hashing", "Slow password hashing", "check",
                 "Code names a password value, but Lantern saw no code that hashes one, fast or slow, and no "
                 "password-hashing library. If the app stores passwords anywhere, confirm they are hashed with "
                 "argon2 or bcrypt; if it only passes them on (a database login, an outside service), nothing is needed.",
                 _where(pw),
                 "Store only argon2 or bcrypt hashes (passlib/pwdlib/bcrypt in Python, bcrypt or argon2 in Node), or "
                 "use a managed auth service so you never store passwords.")

    # 5. Login check on every route that changes data. Each route is checked on its own (decorator, signature,
    # what it calls, what its body says with strings and comments blanked out); the LW-AUTH-MISSING findings
    # (routes the frontend calls) count too. A user lookup by a request value is a weak sign: at most "check".
    no_auth = [f for f in (sec or {}).get("findings", []) if f.get("rule") == "LW-AUTH-MISSING" and f.get("status") != "accepted"
               and not f.get("in_tests")]
    need = [(n, d) for n, d in writes if not is_public_route(d) and mutating_route(d)]
    if need or no_auth:
        adj = call_adjacency(g)
        signed, weak, bare = [], [], []
        for n, d in need:
            sign = login_check(g, n, adj, repo.text(n.file) if n.file else None)
            if sign is None:
                bare.append((n, d, None))
            elif sign[0] == "weak":
                weak.append((n, d, sign[1]))
            else:
                signed.append((n, d, sign[1]))
        where = [f"{d} ({n.file}:{n.start_line})" for n, d, _ in bare]
        weak_where = [f"{d} ({n.file}:{n.start_line}): {sign}" for n, d, sign in weak]
        for f in no_auth:   # routes the app calls that the list above does not already name
            loc = f"{f['file']}:{f['line']}"
            if not any(loc in w for w in where + weak_where):
                where.append(f"{f.get('snippet') or 'route'} ({loc})")
        app_wide = _global_auth_signs(repo)
        if not app_wide and managed:
            app_wide = [("an auth library is installed", 0, "")]
        how = ("Check the signed-in user at the top of each handler (or in shared middleware), and check they may "
               "act on this record, not just that they are signed in.")
        # The sentences describe what was found, so the finding and this item tell the same story.
        none_found = (f"{len(where)} route(s) change data with no sign of a login check in the handler, in what it "
                      "calls, or in app-wide middleware, so anyone on the internet can call them.") if where else ""
        only_lookup = (f"{len(weak)} route(s) that change data only look up a user by a value from the request and "
                       "test the result. That finds the record's owner, not who is calling (the shape behind most "
                       "\"anyone can edit anyone's data\" bugs), so the signed-in user must be checked too.") if weak else ""
        found_ok = [f"{d}: {sign}" for _, d, sign in signed[:4]]
        if no_auth or (bare and not app_wide):
            item("route-auth", "Login check on routes that change data", "add",
                 " ".join(x for x in (none_found, only_lookup) if x), (where + weak_where)[:6], how, found_ok)
        elif bare:
            item("route-auth", "Login check on routes that change data", "check",
                 f"{len(bare)} route(s) that change data have no login check of their own. An app-wide check was "
                 f"found, so confirm it actually runs for these routes. {only_lookup}".rstrip(), (where + weak_where)[:6],
                 "Make sure the middleware or router dependency covers these routes (path matchers, router "
                 "prefixes, excluded paths), or add the check at the top of each handler. " + how,
                 [f"{f}:{ln}" if ln else f for f, ln, _ in app_wide[:4]])
        elif weak:
            item("route-auth", "Login check on routes that change data", "check",
                 only_lookup.replace("must be checked too", "needs confirming"), weak_where[:6], how, found_ok)
        else:
            item("route-auth", "Login check on routes that change data", "in place",
                 f"All {len(need)} route(s) that change data show a login check in the handler or in what it calls "
                 "(the check looks for common login patterns, not your permission rules).", [],
                 how, [f"{d}: {sign}" for _, d, sign in signed[:6]])

    # 6. File uploads
    up = _code_grep(repo, UPLOAD, limit=10)
    if up:
        lim = _code_grep(repo, UPLOAD_LIMIT, limit=1) or repo.grep(UPLOAD_LIMIT_KEY, limit=1)
        item("upload-checks", "Upload size and type checks", "in place" if lim else "add",
             "The app accepts file uploads" + (", and the code sets a size or type limit; confirm it applies to every "
                                               "upload." if lim else
                                               ". Without limits, one request can fill your disk or memory, and a file "
                                               "named photo.jpg can be anything."), _where(up),
             "Cap the size, check the real file type (not only the name), store uploads outside the web root or in "
             "object storage, and never run or serve them as code.", _where(lim))
    return out


def _global_auth_signs(repo) -> list[tuple[str, int, str]]:
    """Middleware, router-level dependencies, or auth libraries wired in once for the whole app."""
    out = []
    for f, ln, text in _code_grep(repo, GLOBAL_AUTH, limit=40):
        if re.search(r"before_request|@app\.middleware|function\s+middleware|const\s+middleware", text):
            # generic hooks count only when what follows looks at who is calling
            window = _body(repo.text(f).splitlines(), ln - 1)
            if not mentions_auth(code_only(window, js=not f.endswith(".py")), js=not f.endswith(".py")):
                continue
        out.append((f, ln, text))
    for f in repo.project_files:   # Next.js middleware file
        if re.fullmatch(r"(?:src/)?middleware\.[tj]sx?", f) and mentions_auth(code_only(repo.text(f), js=True), js=True):
            out.append((f, 1, "middleware file"))
    return out


def _body(lines: list[str], i: int, cap: int = 20) -> str:
    """The hook at line `i` (0-based) up to where it ends: the next line back at its indent or less, after its own
    `def`/`function` line, at most `cap` lines. A hook that only counts requests is not a login check because the
    function after it checks a session."""
    if i >= len(lines):
        return ""
    indent = len(lines[i]) - len(lines[i].lstrip())
    out, started = [lines[i]], False
    for line in lines[i + 1:i + 1 + cap]:
        if line.strip():
            ind = len(line) - len(line.lstrip())
            if started and ind <= indent and not line.lstrip().startswith((")", "}", "]")):
                break
            if ind > indent or re.match(r"\s*(async\s+)?(def|function)\b", line):
                started = True
        out.append(line)
    return "\n".join(out)


def _client_side(f: str) -> bool:
    """Browser code: its fetches are the user's own, not the server's."""
    if not f.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte")):
        return False
    p = Path(f).as_posix()
    return not re.search(r"(^|/)(api|server|routes|pages/api|app/api|functions|backend|lambda)/|route\.(t|j)sx?$|"
                         r"server\.(t|j)s$|middleware\.(t|j)s$", p)
