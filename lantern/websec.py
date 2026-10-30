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
from .python_frontend import SKIP_DIRS

PUBLIC_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_|VUE_APP_)"
SECRET_WORD = r"[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|DB_URL|DATABASE_URL|STRIPE_SK)[A-Z0-9_]*"
_NAME = rf"({PUBLIC_PREFIX}{SECRET_WORD})\b"
# Only where a value is actually read or set as an environment variable, never a mere identifier:
PUBLIC_SECRET_CODE_RE = re.compile(
    rf"(?:process\.env|import\.meta\.env|\benv)\s*(?:\.\s*|\[\s*['\"`]){_NAME}|['\"`]{_NAME}['\"`]")
PUBLIC_SECRET_CONF_RE = re.compile(rf"^\s*(?:export\s+)?-?\s*{_NAME}\s*[:=]", re.M)
SVELTE_PUBLIC_RE = re.compile(r"import\s*\{([^}]*)\}\s*from\s*['\"]\$env/(?:static|dynamic)/public['\"]")
SAFE_NAMES = re.compile(r"PUBLISHABLE|ANON|PUBLIC_KEY$|SITE_KEY")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
WEB_EXTS = JS_EXTS | {".py", ".html"}

JS_RULES = [
    # id, regex, severity, title, cwe
    ("LJ-EVAL", re.compile(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\("), "HIGH",
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

AUTH_NAME_RE = re.compile(r"current_?user|auth|login_required|require_?user|verify|token|permission|jwt|"
                          r"session|is_?admin|superuser|guard|protect|clerk|getServerSession|getUser", re.I)
PUBLIC_ROUTE_RE = re.compile(r"login|signin|sign-in|signup|sign-up|register|password|reset|recover|health|"
                             r"webhook|callback|logout|verify|token|public|contact|subscribe|oauth|auth", re.I)
MUTATING = {"POST", "PUT", "PATCH", "DELETE", "ANY"}


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).hexdigest()[:12]


def _files(repo: Path, exts=None, names=None):
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        parts = p.relative_to(repo).parts
        if any(x in SKIP_DIRS for x in parts):
            continue
        if p.name.endswith((".min.js", ".map", ".d.ts")) or p.name in ("package-lock.json", "bun.lock"):
            continue
        if (exts and p.suffix in exts) or (names and (p.name in names or any(p.name.startswith(n) for n in names))):
            yield p


def _read(p: Path) -> str:
    try:
        return p.read_text(errors="replace")
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
        rel = str(p.relative_to(repo))
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
        rel = str(p.relative_to(repo))
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
        rel = str(p.relative_to(repo))
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
        rel = str(p.relative_to(repo))
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
                created.append((m.group(1).lower(), str(p.relative_to(repo)), _line_of(text, m.start())))
            for m in re.finditer(r"create\s+policy[^;]*using\s*\(\s*true\s*\)", text, re.I | re.S):
                out.append(_finding("LW-NO-RLS", "Row-level security policy allows everyone (using (true))",
                                    "MEDIUM", str(p.relative_to(repo)), _line_of(text, m.start()),
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


def missing_auth(g: Graph) -> list[dict]:
    """Routes the frontend calls that change data, where no login check is visible within 3 calls."""
    out = []
    bridged = {}
    for e in g.call_edges():
        if (e.via or "").startswith("http-") and not e.dst.startswith("ext:"):
            bridged.setdefault(e.dst, e.detail)
    adj: dict[str, list[str]] = {}
    for e in g.call_edges():
        adj.setdefault(e.src, []).append(e.dst)
    for rid, detail in bridged.items():
        n = g.nodes.get(rid)
        if n is None or not n.entry:
            continue
        verb, _, path = n.entry.get("detail", "").partition(" ")
        verbs = {v.upper() for v in verb.split("/")}
        if not verbs & MUTATING or PUBLIC_ROUTE_RE.search(path):
            continue
        if any(AUTH_NAME_RE.search(d) for d in n.decorators) or AUTH_NAME_RE.search(n.signature or ""):
            continue
        seen, frontier, found = {rid}, [rid], False
        for _ in range(3):
            nxt = []
            for u in frontier:
                for v in adj.get(u, []):
                    if v in seen:
                        continue
                    seen.add(v)
                    if AUTH_NAME_RE.search(_func_name(g, v)):
                        found = True
                    nxt.append(v)
            frontier = nxt
        if found:
            continue
        out.append(_finding(
            "LW-AUTH-MISSING", f"{n.entry['detail']} changes data, is called by the app, and no login check was found",
            "MEDIUM", n.file, n.start_line, category="code", conf="LOW", cwe=306, fixed_rank="medium",
            more=("Heuristic: Lantern looked three calls deep for anything named like an auth check "
                  "(current_user, auth, verify, session, permission...). If this route is meant to be public, ignore it."),
            snippet=detail or ""))
    return out


def scan_web(g: Graph) -> tuple[list[dict], list[dict]]:
    repo = Path(g.repo_root)
    findings = js_rules(repo) + exposed_secrets(repo) + cors(repo) + database_rules(repo) + missing_auth(g)
    has_js = "typescript/javascript" in g.meta.get("languages", {})
    tools = [{"tool": "lantern-web", "status": "ok" + ("" if has_js else " (no JS/TS files; Python-side checks only)"),
              "version": "0.1"}]
    return findings, tools
