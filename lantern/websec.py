"""Full-stack security checks: the holes AI-built web apps are known for.

All checks are deterministic (patterns, file conventions, and graph queries). Each finding says
which rule fired and why. Heuristic checks are marked tool_confidence LOW so the report can say so.

  LW-PUBLIC-SECRET   secret-looking env var with a browser-exposed prefix (NEXT_PUBLIC_, VITE_, ...)
  LW-SERVICE-ROLE    Supabase service-role JWT committed to the repo
  LW-JWT             other hard-coded JWT
  LW-CORS-ANY        CORS allows every origin (worse with credentials)
  LW-DB-OPEN         Firebase/Firestore rules that let anyone read or write
  LW-NO-RLS          Supabase table created without row-level security
  LW-AUTH-MISSING    route that changes data, called by the UI, with no login check found
  LJ-*               JavaScript/TypeScript code patterns (eval, XSS sinks, shell, SQL, TLS)
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .graph import Graph
from .js_frontend import jwt_role
from .python_frontend import SKIP_DIRS, inside_repo

PUBLIC_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_|VUE_APP_)"
SECRET_WORD = r"[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|DB_URL|DATABASE_URL|STRIPE_SK|API_KEY)[A-Z0-9_]*"
_NAME = rf"({PUBLIC_PREFIX}{SECRET_WORD})\b"
# Only where a value is actually read or set as an environment variable, never a mere identifier:
PUBLIC_SECRET_CODE_RE = re.compile(
    rf"(?:process\.env|import\.meta\.env|\benv)\s*(?:\.\s*|\[\s*['\"`]){_NAME}|['\"`]{_NAME}['\"`]")
PUBLIC_SECRET_CONF_RE = re.compile(rf"^\s*(?:export\s+)?-?\s*{_NAME}\s*[:=]", re.M)
SVELTE_PUBLIC_RE = re.compile(r"import\s*\{([^}]*)\}\s*from\s*['\"]\$env/(?:static|dynamic)/public['\"]")
# Keys that are meant for the browser (restricted by referrer or project rules, not secrets): not flagged
SAFE_NAMES = re.compile(r"PUBLISHABLE|ANON|PUBLIC_KEY$|SITE_KEY|FIREBASE|MAPS_API|MAPBOX|RECAPTCHA|TURNSTILE|ALGOLIA|"
                        r"SENTRY|POSTHOG|ANALYTICS|_GA_|GTM|EMAILJS|CLERK_|TINYMCE|FONTAWESOME|GIPHY|YOUTUBE")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
WEB_EXTS = JS_EXTS | {".py", ".html"}

JS_RULES = [
    # id, regex, severity, title, cwe
    ("LJ-EVAL", re.compile(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\("), "HIGH",   # not Playwright's $eval
     "Runs text as code (eval / new Function)", 95),
    ("LJ-XSS-HTML", re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=(?!\s*['\"]{2})|\bv-html\s*=|\{@html\s"), "MEDIUM",
     "Inserts raw HTML into the page (cross-site scripting risk)", 79),
    ("LJ-EXEC", re.compile(r"\b(?:exec|execSync|spawn)\s*\(\s*(?:`[^`]*\$\{|[^)\n]*\+)"), "HIGH",
     "Builds a shell command from variables (command injection risk)", 78),
    ("LJ-SQL-CONCAT", re.compile(r"\.(?:query|execute|raw|unsafe)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{",
                                 re.I), "HIGH", "Builds SQL from variables in a template string (SQL injection risk)", 89),
    ("LJ-TLS-OFF", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"), "MEDIUM",
     "Turns off HTTPS certificate checks", 295),
    ("LJ-TOKEN-STORAGE", re.compile(r"localStorage\.setItem\(\s*['\"][^'\"]*(?:token|jwt|auth|session)[^'\"]*['\"]", re.I),
     "LOW", "Stores a login token in localStorage, where any injected script can read it", 922),
]

# Names of things that check who is calling: decorators, dependencies, callees, body words. `getUser`/`get_user`
# are deliberately absent: fetching a user record is a check only when the argument identifies the caller (below).
AUTH_NAME_RE = re.compile(r"current_?user|auth|login_required|require_?user|verify|token|permission|jwt|"
                          r"session|is_?admin|superuser|guard|protect|clerk|getServerSession", re.I)
# The same idea read from a handler's body (attributes, awaits, helpers the graph did not link)
BODY_AUTH = re.compile(r"current_?user|request\.user|req\.user|\bauth(?!or)|authenticat|authoriz|login_required|"
                       r"require_?(?:user|auth|login)|permission|jwt|is_?admin|superuser|getServerSession|"
                       r"verify_?token|check_?token|clerk|\bguard|protect|locals\.user|session\.user|"
                       r"session\[.{0,20}user", re.I)
# A helper that fetches a user record. `get_user(token)` identifies the caller; `get_user(payload["owner"])` finds
# the record's owner (the IDOR shape), which proves nothing about who is calling.
USER_LOOKUP = re.compile(r"\b(?:get|fetch|find|load|lookup|read|select)_?user(?:_?by_?\w+|s)?\s*\(", re.I)
CALLER_ARG = re.compile(r"token|session|request|\breq\b|\bctx\b|context|headers?|cookies?|authorization|jwt|"
                        r"claims|locals|auth|credential|bearer|principal|identity", re.I)
# ...but the request's content (body, query, path) is what the caller sent, not who the caller is
REQUEST_VALUE = re.compile(r"\b(?:request|req)\.(?:args|form|json|body|query|params|values|files|data|get_json|"
                           r"path_params|query_params|matchdict|POST|GET|FILES)\b|\b(?:params|payload|body|"
                           r"searchParams|formData|form|args|input)\b", re.I)
CONDITION = re.compile(r"\b(?:if|elif|while|assert|unless)\b|[=!]==?|\bis\b|\bnot\b|!|&&|\|\||\?")
PUBLIC_ROUTE_RE = re.compile(r"login|signin|sign-in|signup|sign-up|register|password|reset|recover|health|"
                             r"webhook|callback|logout|verify|token|public|contact|subscribe|oauth|"
                             r"(?<![a-z])auth(?![a-z])", re.I)   # /auth/refresh, not /authors
MUTATING = {"POST", "PUT", "PATCH", "DELETE", "ANY"}


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).hexdigest()[:12]


def _files(repo: Path, exts=None, names=None):
    for p in repo.rglob("*"):
        if not p.is_file() or not inside_repo(p, repo):
            continue
        parts = p.relative_to(repo).parts
        if any(x in SKIP_DIRS for x in parts[:-1]):   # a file named .env is not the .env/ venv folder
            continue
        if p.name.endswith((".min.js", ".map", ".d.ts")) or p.name in ("package-lock.json", "bun.lock"):
            continue
        if (exts and p.suffix in exts) or (names and (p.name in names or any(p.name.startswith(n) for n in names))):
            yield p


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _finding(rule, title, sev, file, line, category="code", conf="HIGH", cwe=None, more=None,
             snippet="", fixed_rank=None):
    f = {"id": _fid("lw", rule, file, line), "tool": "lantern-web", "rule": rule, "title": title,
         "tool_severity": sev, "tool_confidence": conf, "file": file, "line": line, "cwe": cwe,
         "more_info": more, "snippet": snippet[:300], "category": category}
    if fixed_rank:
        f["fixed_rank"] = fixed_rank
    return f


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def js_rules(repo: Path) -> list[dict]:
    out = []
    for p in _files(repo, JS_EXTS):
        text = _read(p)
        rel = p.relative_to(repo).as_posix()
        for rule, rx, sev, title, cwe in JS_RULES:
            for m in rx.finditer(text):
                ln = _line_of(text, m.start())
                src_line = text.splitlines()[ln - 1] if text else ""
                if src_line.lstrip().startswith(("//", "*")):
                    continue
                out.append(_finding(rule, title, sev, rel, ln, cwe=cwe, snippet=src_line.strip()))
    return out


def exposed_secrets(repo: Path) -> list[dict]:
    out, seen = [], set()
    for p in _files(repo, WEB_EXTS | {".json", ".yml", ".yaml", ".toml"}, names=(".env",)):
        text = _read(p)
        rel = p.relative_to(repo).as_posix()
        is_conf = p.name.startswith(".env") or p.suffix in (".yml", ".yaml", ".toml")
        hits = [(m.start(), m.group(1)) for m in PUBLIC_SECRET_CONF_RE.finditer(text)] if is_conf else \
            [(m.start(), m.group(1) or m.group(2)) for m in PUBLIC_SECRET_CODE_RE.finditer(text)]
        for sm in SVELTE_PUBLIC_RE.finditer(text):
            for nm in re.findall(rf"\b{PUBLIC_PREFIX}{SECRET_WORD}\b", sm.group(1)):
                hits.append((sm.start(), nm))
        for start, name in hits:
            if SAFE_NAMES.search(name) or (rel, name) in seen:
                continue
            seen.add((rel, name))
            ln = _line_of(text, start)
            out.append(_finding(
                "LW-PUBLIC-SECRET", f"Secret-looking setting {name} is sent to every visitor's browser",
                "HIGH", rel, ln, category="exposure", cwe=200, fixed_rank="high",
                more=("Variables starting with NEXT_PUBLIC_, VITE_, REACT_APP_ and similar are copied into the "
                      "JavaScript that browsers download. Keep secrets in server-only variables and call them "
                      "from server code."),
                snippet=name))
        for m in JWT_RE.finditer(text):
            role = jwt_role(m.group(0))
            ln = _line_of(text, m.start())
            if role == "service_role":
                out.append(_finding(
                    "LW-SERVICE-ROLE", "Supabase service-role key is in the code (it bypasses all database rules)",
                    "HIGH", rel, ln, category="secret", cwe=798, fixed_rank="critical",
                    more="Rotate this key in the Supabase dashboard, then load it only on the server from an environment variable.",
                    snippet="[redacted]"))
            elif role not in ("anon", "authenticated"):
                out.append(_finding(
                    "LW-JWT", "Hard-coded login token (JWT) in the code", "MEDIUM", rel, ln, category="secret",
                    conf="MEDIUM", cwe=798, fixed_rank="medium", snippet="[redacted]"))
    return out


def cors(repo: Path) -> list[dict]:
    out = []
    for p in _files(repo, {".py"} | JS_EXTS):
        text = _read(p)
        rel = p.relative_to(repo).as_posix()
        if p.suffix == ".py":
            for m in re.finditer(r"add_middleware\(\s*CORSMiddleware|\bCORS\(", text):
                window = text[m.start(): m.start() + 600]
                if re.search(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", window):
                    creds = re.search(r"allow_credentials\s*=\s*True", window)
                    out.append(_cors_finding(rel, _line_of(text, m.start()), bool(creds)))
        else:
            for m in re.finditer(r"\bcors\s*\(\s*\)", text):
                out.append(_cors_finding(rel, _line_of(text, m.start()), False))
            for m in re.finditer(r"origin\s*:\s*(?:['\"]\*['\"]|true)", text):
                window = text[max(0, m.start() - 300): m.start() + 300]
                out.append(_cors_finding(rel, _line_of(text, m.start()), "credentials: true" in window))
            for m in re.finditer(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]", text):
                out.append(_cors_finding(rel, _line_of(text, m.start()), False))
    return out


def _cors_finding(rel, line, creds):
    if creds:
        return _finding("LW-CORS-ANY", "CORS lets any website call this API with users' logged-in cookies",
                        "HIGH", rel, line, category="config", cwe=942, fixed_rank="high",
                        more="List your own frontend's address instead of '*'.")
    return _finding("LW-CORS-ANY", "CORS lets any website call this API", "MEDIUM", rel, line,
                    category="config", cwe=942, fixed_rank="medium",
                    more="Fine for a truly public API; otherwise list your own frontend's address instead of '*'.")


def database_rules(repo: Path) -> list[dict]:
    out = []
    for p in _files(repo, names=("firestore.rules", "storage.rules", "database.rules.json")):
        text = _read(p)
        rel = p.relative_to(repo).as_posix()
        for m in re.finditer(r"allow\s+[\w,\s]*:\s*if\s+true\s*;?", text):
            out.append(_finding("LW-DB-OPEN", "Database rules let anyone on the internet read or write", "HIGH",
                                rel, _line_of(text, m.start()), category="config", cwe=284, fixed_rank="critical",
                                snippet=m.group(0)))
        for m in re.finditer(r"request\.time\s*<\s*timestamp\.date\(", text):
            out.append(_finding("LW-DB-OPEN", "Database is in 'test mode': open to everyone until a date",
                                "HIGH", rel, _line_of(text, m.start()), category="config", cwe=284, fixed_rank="high"))
        for m in re.finditer(r"['\"]\.(read|write)['\"]\s*:\s*true", text):
            out.append(_finding("LW-DB-OPEN", "Realtime Database rules let anyone read or write", "HIGH", rel,
                                _line_of(text, m.start()), category="config", cwe=284, fixed_rank="critical"))
    sql_files = list(_files(repo, {".sql"}))
    uses_supabase = (repo / "supabase").is_dir() or any(
        "@supabase" in _read(pj) for pj in _files(repo, names=("package.json",)))
    if sql_files and uses_supabase:
        rls, created = set(), []
        for p in sql_files:
            text = _read(p)
            for m in re.finditer(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\"?public\"?\.)?\"?(\w+)\"?\s+"
                                 r"enable\s+row\s+level\s+security", text, re.I):
                rls.add(m.group(1).lower())
            for m in re.finditer(r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?public\"?\.)?\"?(\w+)\"?", text, re.I):
                created.append((m.group(1).lower(), p.relative_to(repo).as_posix(), _line_of(text, m.start())))
            for m in re.finditer(r"create\s+policy[^;]*using\s*\(\s*true\s*\)", text, re.I | re.S):
                out.append(_finding("LW-NO-RLS", "Row-level security policy allows everyone (using (true))",
                                    "MEDIUM", p.relative_to(repo).as_posix(), _line_of(text, m.start()),
                                    category="config", cwe=284, fixed_rank="medium"))
        for name, rel, line in created:
            if name not in rls:
                out.append(_finding(
                    "LW-NO-RLS", f"Table '{name}' has no row-level security: anyone with the public key can read it",
                    "HIGH", rel, line, category="config", cwe=284, fixed_rank="high",
                    more=f"alter table {name} enable row level security; then add policies for who may read and write."))
    return out


def _func_name(g: Graph, nid: str) -> str:
    """Just the function's own name (never its module path, which may contain words like 'auth')."""
    if nid.startswith("ext:"):
        return nid[4:]
    n = g.nodes.get(nid)
    if n is None:
        return ""
    return n.qualname.split("::")[-1].split(".")[-1] if n.kind != "module" else ""


def _blank(m: re.Match) -> str:
    return re.sub(r"[^\n]", "~", m.group(0))


def code_only(text: str, js: bool = False) -> str:
    """The text with string literals and comments blanked out, same length, so offsets and line numbers still
    hold. A route path '/auth/refresh', a message, a docstring, or `# TODO: add auth here` is not a login check."""
    if js:
        text = re.sub(r"`(?:\\.|[^`\\])*`", _blank, text)
    else:
        text = re.sub(r"(\"\"\"|''')[\s\S]*?\1", _blank, text)
    text = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", _blank, text)
    if js:
        text = re.sub(r"/\*[\s\S]*?\*/", _blank, text)
        text = re.sub(r"//[^\n]*", _blank, text)
    else:
        text = re.sub(r"#[^\n]*", _blank, text)
    return text


def _strip_strings(s: str) -> str:
    return code_only(s, js=True) if "`" in s else code_only(s)


def _call_args(code: str, start: int) -> str:
    """The text between the parenthesis at `start` and its match (at most 300 characters)."""
    depth = 0
    for i in range(start, min(len(code), start + 300)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return code[start + 1:i]
    return code[start + 1:start + 300]


def body_auth_sign(text: str, start_line: int, end_line: int, js: bool) -> tuple[str, str] | None:
    """What a handler's own lines say about checking the caller, read with strings and comments blanked out.
    ("strong", evidence) for words that only make sense when checking who is calling, or a user lookup given the
    caller's token/request/session (or nothing); ("weak", evidence) for a user lookup by some other value whose
    result is then tested, which finds a record, not the caller; None otherwise. Weak never counts as in place."""
    lines = text.splitlines()
    if not start_line or start_line > len(lines):
        return None
    raw = "\n".join(lines[start_line - 1:(end_line or start_line)])
    code = code_only(raw, js)
    m = BODY_AUTH.search(code)
    if m:
        return "strong", f"handler mentions `{m.group(0)}`"
    weak = None
    for m in USER_LOOKUP.finditer(code):
        args = _call_args(code, m.end() - 1)
        call = raw[m.start():m.end() + len(args) + 1].replace("\n", " ")
        call = re.sub(r"\s+", " ", call)[:60]
        if not args.strip() or (CALLER_ARG.search(args) and not REQUEST_VALUE.search(args)):
            return "strong", f"handler calls `{call}`"
        line_start = code.rfind("\n", 0, m.start()) + 1
        line_end = code.find("\n", m.end())
        line = code[line_start:line_end if line_end >= 0 else len(code)]
        lhs = re.match(r"\s*(?:(?:const|let|var)\s+)?(?:\{\s*)?([A-Za-z_$][\w$]*)[^=]*=[^=]", line)
        checked = bool(CONDITION.search(line[:m.start() - line_start]))   # `if not get_user(x):`
        if lhs and not checked:
            name = re.escape(lhs.group(1))
            for later in code[line_end:].splitlines() if line_end >= 0 else []:
                if re.search(rf"(?<![\w$.]){name}(?![\w$])", later) and CONDITION.search(later):
                    checked = True
                    break
        if checked and weak is None:
            by = re.sub(r"\s+", " ", raw[m.end():m.end() + len(args)].strip())[:40]
            weak = ("weak", f"`{call}` looks up a user by `{by}`, not by who is calling")
    return weak


def call_adjacency(g: Graph) -> dict[str, list[str]]:
    adj: dict[str, list[str]] = {}
    for e in g.call_edges():
        adj.setdefault(e.src, []).append(e.dst)
    return adj


def route_auth_sign(g: Graph, n, adj: dict[str, list[str]], depth: int = 3) -> str | None:
    """The first visible sign that this route checks who is calling: a decorator, a parameter or dependency in
    its signature, or a function named like an auth check within `depth` calls. None when nothing was found."""
    for d in n.decorators:
        m = AUTH_NAME_RE.search(_strip_strings(d))
        if m:
            return f"decorator @{d.split('(')[0]}"
    m = AUTH_NAME_RE.search(_strip_strings(n.signature or ""))
    if m:
        return f"`{m.group(0)}` in its parameters"
    seen, frontier = {n.id}, [n.id]
    for _ in range(depth):
        nxt = []
        for u in frontier:
            for v in adj.get(u, []):
                if v in seen:
                    continue
                seen.add(v)
                if AUTH_NAME_RE.search(_func_name(g, v)):
                    return f"calls `{_func_name(g, v)}`"
                nxt.append(v)
        frontier = nxt
    return None


def login_check(g: Graph, n, adj: dict[str, list[str]], text: str | None) -> tuple[str, str] | None:
    """Everything Lantern can see about a route checking its caller: ("strong", why) from the decorator, signature,
    callees or body; ("weak", why) when the body only looks up a user by a request value and tests the result;
    None when nothing was found. Shared by the LW-AUTH-MISSING rule and the protections advisor so both tell the
    same story: a weak sign is never "in place", and a route with no sign gets the finding."""
    sign = route_auth_sign(g, n, adj)
    if sign:
        return "strong", sign
    if text is None or not n.file:
        return None
    return body_auth_sign(text, n.start_line or 0, n.end_line or n.start_line or 0, js=not n.file.endswith(".py"))


def is_public_route(detail: str) -> bool:
    """Sign-in, sign-up, webhooks and the like: expected to be reachable without a login."""
    return bool(PUBLIC_ROUTE_RE.search(detail.partition(" ")[2] or detail))


def mutating_route(detail: str) -> bool:
    verb = detail.partition(" ")[0]
    return bool({v.upper() for v in verb.split("/")} & MUTATING)


def missing_auth(g: Graph) -> list[dict]:
    """Routes the frontend calls that change data, where no login check is visible within 3 calls."""
    out = []
    bridged = {}
    for e in g.call_edges():
        if (e.via or "").startswith("http-") and not e.dst.startswith("ext:"):
            bridged.setdefault(e.dst, e.detail)
    adj = call_adjacency(g)
    texts: dict[str, str] = {}
    for rid, detail in bridged.items():
        n = g.nodes.get(rid)
        if n is None or not n.entry:
            continue
        route = n.entry.get("detail", "")
        if not mutating_route(route) or is_public_route(route):
            continue
        if n.file and n.file not in texts:
            try:
                texts[n.file] = (Path(g.repo_root) / n.file).read_text(encoding="utf-8", errors="replace")
            except OSError:
                texts[n.file] = ""
        sign = login_check(g, n, adj, texts.get(n.file or ""))
        if sign and sign[0] == "strong":
            continue
        more = ("Heuristic: Lantern looked three calls deep for anything named like an auth check (current_user, "
                "auth, verify, session, permission...) and read the handler's own lines for the same words. ")
        if sign:
            more += (f"The handler only has {sign[1]}: that finds the record's owner, not who is calling. "
                     "Check the signed-in user as well. ")
        out.append(_finding(
            "LW-AUTH-MISSING", f"{n.entry['detail']} changes data, is called by the app, and no login check was found",
            "MEDIUM", n.file, n.start_line, category="code", conf="LOW", cwe=306, fixed_rank="medium",
            more=more + "If this route is meant to be public, ignore it.", snippet=detail or ""))
    return out


def scan_web(g: Graph) -> tuple[list[dict], list[dict]]:
    repo = Path(g.repo_root)
    findings = js_rules(repo) + exposed_secrets(repo) + cors(repo) + database_rules(repo) + missing_auth(g)
    has_js = "typescript/javascript" in g.meta.get("languages", {})
    tools = [{"tool": "lantern-web", "status": "ok" + ("" if has_js else " (no JS/TS files; Python-side checks only)"),
              "version": "0.1"}]
    return findings, tools
