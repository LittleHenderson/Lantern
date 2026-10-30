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

from .graph import Graph
from .websec import BODY_AUTH, call_adjacency, code_only, is_public_route, login_check, mutating_route

SENSITIVE_PATH = re.compile(r"(^|/)(login|log-in|signin|sign-in|signup|sign-up|register|auth|token|session|password|"
                            r"reset|forgot|otp|verify|magic-link|2fa|mfa|invite)(/|$|\b)", re.I)
RATE_LIMIT_LIBS = re.compile(r"slowapi|fastapi[-_]limiter|flask[-_]limiter|django[-_]ratelimit|express-rate-limit|"
                             r"rate-limiter-flexible|@upstash/ratelimit|@nestjs/throttler|hono-rate-limiter|"
                             r"\bratelimit\b|\brate_limit\b|RateLimit", re.I)
HEADER_SIGNS = re.compile(r"helmet|Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|"
                          r"SecurityMiddleware|secure\.Secure|talisman|frame-ancestors", re.I)
FAST_HASH = re.compile(r"hashlib\.(md5|sha1|sha224|sha256|sha512)\s*\(|createHash\(\s*['\"](md5|sha1|sha256|sha512)['\"]")
SLOW_HASH = re.compile(r"bcrypt|argon2|scrypt|passlib|pbkdf2|generate_password_hash|make_password|pwdlib", re.I)
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
# App-wide mechanisms: middleware, router-level dependencies, auth libraries wired in once
GLOBAL_AUTH = re.compile(
    r"add_middleware\(\s*\w*(?:auth|login|session|jwt)\w*|AuthenticationMiddleware|LoginRequiredMiddleware|"
    r"DEFAULT_PERMISSION_CLASSES|dependencies\s*=\s*\[\s*Depends\(|before_request|@app\.middleware|"
    r"\b(?:app|router|server)\.use\(\s*[^)\n]*(?:auth|passport|jwt|session|requireUser|protect|guard|clerk)|"
    r"clerkMiddleware|withAuth\(|authMiddleware|export\s+(?:default\s+)?(?:async\s+)?function\s+middleware\b|"
    r"export\s+const\s+middleware\b|withMiddlewareAuth", re.I)


def _where(hits, n=4) -> list[str]:
    return [f"{f}:{ln}" for f, ln, _ in hits[:n]]


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


def advise(g: Graph, sec: dict | None, repo, shape: str) -> list[dict]:
    web = shape in ("full-stack web app", "web API", "frontend web app")
    routes = [(n, (n.entry or {}).get("detail") or "") for n in g.entry_points() if (n.entry or {}).get("kind") == "route"]
    deps = _deps_text(repo)
    managed = MANAGED_AUTH.search(deps) or repo.grep(MANAGED_AUTH, limit=1)
    out: list[dict] = []

    def item(id_, title, status, why, evidence, how, found=None):
        out.append({"id": id_, "title": title, "status": status, "why": why, "evidence": evidence, "how": how,
                    "found": found or [], "heuristic": True})

    # 1. Rate limiting on sign-in and other abuse-prone routes
    sensitive = [(n, d) for n, d in routes if SENSITIVE_PATH.search(d.partition(" ")[2] or d)]
    writes = [(n, d) for n, d in routes if d.split(" ")[0].upper() in ("POST", "PUT", "PATCH", "DELETE")]
    if sensitive or writes:
        rl = RATE_LIMIT_LIBS.search(deps) or repo.grep(RATE_LIMIT_LIBS, limit=1)
        trig = sensitive or writes
        item("rate-limit", "Rate limiting", "in place" if rl else "add",
             (f"{len(sensitive)} sign-in or account route(s)" if sensitive else f"{len(writes)} route(s) that change data")
             + " can be called as fast as an attacker likes: password guessing, sign-up spam, or running up your bill.",
             [f"{d} ({n.file}:{n.start_line})" for n, d in trig[:4]],
             "Limit requests per user and per IP on these routes: slowapi (FastAPI), Flask-Limiter, express-rate-limit, "
             "or @upstash/ratelimit (Next.js / serverless).",
             [] if not rl else ["a rate-limiting library or setting was found"])

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
            allow = repo.grep(ALLOW_LIST, limit=1)
            item("ssrf-allowlist", "Allow-list for outgoing requests", "in place" if allow else "add",
                 "The server makes HTTP requests to an address held in a variable. If any part of it comes from a user, "
                 "they can make your server call internal services or cloud metadata endpoints (SSRF).",
                 _where(hits),
                 "Only call hosts from a fixed allow-list, reject private and link-local IP addresses, and never pass a "
                 "user-supplied URL straight to requests/httpx/fetch.",
                 _where(allow))

    # 4. Slow password hashing
    pw = repo.grep(re.compile(r"password", re.I), limit=60)
    pw_files = {f for f, _, _ in pw}
    if pw_files and not managed:
        fast = [h for h in repo.grep(FAST_HASH, limit=40) if h[0] in pw_files]
        slow = SLOW_HASH.search(deps) or repo.grep(SLOW_HASH, limit=1)
        if fast or not slow:
            item("password-hashing", "Slow password hashing", "add",
                 "Passwords are handled in the code, and " + (
                     "a fast hash (MD5/SHA) is used in the same files: a leaked database could be cracked in hours."
                     if fast else "no password-hashing library (bcrypt, argon2, scrypt) was found."),
                 _where(fast or pw),
                 "Store only argon2 or bcrypt hashes (passlib/pwdlib/bcrypt in Python, bcrypt or argon2 in Node), or "
                 "use a managed auth service so you never store passwords.")
        else:
            item("password-hashing", "Slow password hashing", "in place",
                 "Passwords are handled in the code, and a slow hashing library is present.", [],
                 "Keep using it for every stored password.", ["bcrypt / argon2 / scrypt found"])

    # 5. Login check on every route that changes data. Each route is checked on its own (decorator, signature,
    # what it calls, what its body says with strings and comments blanked out); the LW-AUTH-MISSING findings
    # (routes the frontend calls) count too. A user lookup by a request value is a weak sign: at most "check".
    no_auth = [f for f in (sec or {}).get("findings", []) if f.get("rule") == "LW-AUTH-MISSING" and f.get("status") != "accepted"]
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
        for f in no_auth:
            loc = f"{f['file']}:{f['line']}"
            if not any(loc in w for w in where):
                where.append(f"{f.get('snippet') or 'route'} ({loc})")
        app_wide = _global_auth_signs(repo)
        if not app_wide and managed:
            app_wide = [("an auth library is installed", 0, "")]
        how = ("Check the signed-in user at the top of each handler (or in shared middleware), and check they may "
               "act on this record, not just that they are signed in.")
        if no_auth or (bare and not app_wide):
            item("route-auth", "Login check on routes that change data", "add",
                 f"{len(where)} route(s) change data with no sign of a login check in the handler, in what it "
                 "calls, or in app-wide middleware, so anyone on the internet can call them.",
                 where[:6], how, [f"{d}: {sign}" for _, d, sign in signed[:4]])
        elif bare:
            item("route-auth", "Login check on routes that change data", "check",
                 f"{len(bare)} route(s) that change data have no login check of their own. An app-wide check was "
                 "found, so confirm it actually runs for these routes.", where[:6],
                 "Make sure the middleware or router dependency covers these routes (path matchers, router "
                 "prefixes, excluded paths), or add the check at the top of each handler. " + how,
                 [f"{f}:{ln}" if ln else f for f, ln, _ in app_wide[:4]])
        elif weak:
            item("route-auth", "Login check on routes that change data", "check",
                 f"{len(weak)} route(s) that change data only look up a user by a value from the request and test "
                 "the result. That finds the record's owner, not who is calling (the shape behind most "
                 "\"anyone can edit anyone's data\" bugs), so confirm the signed-in user is checked too.",
                 [f"{d} ({n.file}:{n.start_line}): {sign}" for n, d, sign in weak[:6]], how,
                 [f"{d}: {sign}" for _, d, sign in signed[:4]])
        else:
            item("route-auth", "Login check on routes that change data", "in place",
                 f"All {len(need)} route(s) that change data show a login check in the handler or in what it calls "
                 "(the check looks for common login patterns, not your permission rules).", [],
                 how, [f"{d}: {sign}" for _, d, sign in signed[:6]])

    # 6. File uploads
    up = [h for h in repo.grep(UPLOAD, limit=10)]
    if up:
        lim = repo.grep(UPLOAD_LIMIT, limit=1)
        item("upload-checks", "Upload size and type checks", "in place" if lim else "add",
             "The app accepts file uploads. Without limits, one request can fill your disk or memory, and a file "
             "named photo.jpg can be anything.", _where(up),
             "Cap the size, check the real file type (not only the name), store uploads outside the web root or in "
             "object storage, and never run or serve them as code.", _where(lim))
    return out


def _global_auth_signs(repo) -> list[tuple[str, int, str]]:
    """Middleware, router-level dependencies, or auth libraries wired in once for the whole app."""
    out = []
    for f, ln, text in repo.grep(GLOBAL_AUTH, limit=40):
        if re.search(r"before_request|@app\.middleware|function\s+middleware|const\s+middleware", text):
            # generic hooks count only when what follows looks at who is calling
            window = "\n".join(repo.text(f).splitlines()[ln - 1:ln + 20])
            if not BODY_AUTH.search(code_only(window, js=not f.endswith(".py"))):
                continue
        out.append((f, ln, text))
    for f in repo.project_files:   # Next.js middleware file
        if re.fullmatch(r"(?:src/)?middleware\.[tj]sx?", f) and BODY_AUTH.search(code_only(repo.text(f), js=True)):
            out.append((f, 1, "middleware file"))
    return out


def _client_side(f: str) -> bool:
    """Browser code: its fetches are the user's own, not the server's."""
    if not f.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte")):
        return False
    p = Path(f).as_posix()
    return not re.search(r"(^|/)(api|server|routes|pages/api|app/api|functions|backend|lambda)/|route\.(t|j)sx?$|"
                         r"server\.(t|j)s$|middleware\.(t|j)s$", p)
