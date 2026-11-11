"""Full-stack security checks: the holes AI-built web apps are known for.

All checks are deterministic (patterns, file conventions, and graph queries). Each finding says
which rule fired and why. Heuristic checks are marked tool_confidence LOW so the report can say so.

  LW-PUBLIC-SECRET   secret-looking env var with a browser-exposed prefix (NEXT_PUBLIC_, VITE_, ...)
  LW-SERVICE-ROLE    Supabase service-role JWT committed to the repo
  LW-JWT             other hard-coded JWT
  LW-CORS-ANY        CORS allows every origin (worse with credentials)
  LW-DB-OPEN         Firebase/Firestore rules that let anyone read or write
  LW-NO-RLS          Supabase table created without row-level security
  LW-AUTH-MISSING    route that changes data, called by the UI, with no login check found (flowscan.py makes the
                     same finding for a route nothing calls that changes or removes a record picked by an id)
  LW-XSS-RAW         a place in a page template that prints a value without escaping it (templates.py; ranked by
                     what the flow step knows of the value)
  LW-SECRET-INLINE   a signing secret, its fallback for a missing setting, an account's password or a database
                     address with its password, written in JS/TS, Python or a JSON settings file
  LJ-*               JavaScript/TypeScript code patterns (eval, XSS sinks, shell, SQL, TLS)
  LG-*               Go code patterns (SQL and shell built from variables, TLS off, weak hashes, unsafe)
  LR-*               Rust code patterns (format! into SQL or a shell command, TLS off, weak hashes, unsafe blocks)
  LH-*               PHP code patterns (SQL/shell/eval from variables, include from input, unserialize, echo of
                     request data, Blade {!! !!}, MD5 passwords, TLS off, extract($_GET), CORS *, display_errors)
  LC-*               C# code patterns (dotnet.py: SQL/shell from variables, TLS off, weak hashes, BinaryFormatter, CORS *)
  LV-*               Java code patterns (SQL/shell from variables, TLS off, weak hashes, ObjectInputStream, CORS *)
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .flow_rules import READS_TOKEN, VERIFIES
from .graph import Graph
from .js_frontend import jwt_role
from .python_frontend import inside_repo, project_text, skipped

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

JAVA_RULES = [
    ("LV-SQL-CONCAT", re.compile(r"(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|prepareStatement|query|queryForObject|queryForList|update)\s*\(\s*(?:\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\"\s*\+|String\.format\(\s*\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b"
                               r"|\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\$\{?[A-Za-z_])", re.I), "HIGH",
     "Builds SQL from variables (SQL injection risk)", 89),     # the last form is a Kotlin string template
    ("LV-EXEC-CONCAT", re.compile(r"(?:Runtime\.getRuntime\(\)\.exec|(?:new\s+)?ProcessBuilder)\s*\((?:[^)\n]*(?:\+|String\.format)|\s*\"[^\"\n]*\$\{?[A-Za-z_])"), "HIGH",
     "Builds a shell command from variables (command injection risk)", 78),
    ("LV-TLS-OFF", re.compile(r"setHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"), "MEDIUM",
     "Turns off HTTPS certificate checks", 295),
    ("LV-WEAK-HASH", re.compile(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"", re.I), "MEDIUM", "Uses a weak hash (MD5/SHA-1)", 328),
    ("LV-DESERIALIZE", re.compile(r"new\s+ObjectInputStream\s*\("), "MEDIUM", "Deserializes Java objects from a stream (untrusted data can run code)", 502),
    ("LV-CORS-ALL", re.compile(r"@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?\"\*\""), "MEDIUM", "Allows any website to call this API (CORS *)", 942),
]

RUST_RULES = [
    ("LR-SQL-FORMAT", re.compile(r"format!\(\s*r?#*\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\{", re.I), "HIGH",
     "Builds SQL from variables with format! (SQL injection risk)", 89),
    ("LR-EXEC-FORMAT", re.compile(r"Command::new\([^)\n]*format!|\.args?\(\s*&?(?:format!|\[?\s*format!)"), "HIGH",
     "Builds a shell command from variables (command injection risk)", 78),
    ("LR-TLS-OFF", re.compile(r"danger_accept_invalid_(?:certs|hostnames)\(\s*true\s*\)"), "MEDIUM",
     "Turns off HTTPS certificate checks", 295),
    ("LR-WEAK-HASH", re.compile(r"\b(?:md5::compute|Md5::new|Sha1::new)\b"), "MEDIUM", "Uses a weak hash (MD5/SHA-1)", 328),
    ("LR-UNSAFE", re.compile(r"\bunsafe\s*\{"), "LOW", "Uses an unsafe block", 242),
]

GO_RULES = [
    ("LG-SQL-CONCAT", re.compile(r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw)\s*\(\s*(?:\w+\s*,\s*)?"
                                 r"(?:\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\"\s*\+|fmt\.Sprintf\(\s*\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b)",
                                 re.I), "HIGH", "Builds SQL from variables (SQL injection risk)", 89),
    ("LG-EXEC", re.compile(r"exec\.Command(?:Context)?\s*\([^)\n]*(?:\+|fmt\.Sprintf)"), "HIGH",
     "Builds a shell command from variables (command injection risk)", 78),
    ("LG-TLS-OFF", re.compile(r"InsecureSkipVerify\s*:\s*true"), "MEDIUM", "Turns off HTTPS certificate checks", 295),
    ("LG-WEAK-HASH", re.compile(r"\b(?:md5|sha1)\.(?:New|Sum)\s*\("), "MEDIUM", "Uses a weak hash (MD5/SHA-1)", 328),
    ("LG-UNSAFE", re.compile(r"\bunsafe\.Pointer\s*\("), "LOW", "Uses unsafe pointers", 242),
]

# An auth word counts only as a whole segment of a name: `getToken`, `has_permission`, `OAuth2PasswordBearer` and
# `protectedProcedure` are checks; `tokenize`, `load_permissions`, `protect_zone` and `author` are not. `verify` counts
# only with the caller as its object (`verify_token`, `verify_session`, `verify_password`): a route that verifies a
# payment, a signature or an age has not checked who is calling. Names are split
# on `_`, `.`, `$` and camelCase by `segments()` ("load permissions") and matched with word boundaries. `getUser`/
# `get_user` are deliberately absent (fetching a user record is a check only when the argument identifies the caller,
# below), and so is a bare `session`: `Depends(get_session)` and `db.session` are database sessions.
AUTH_WORDS = re.compile(
    r"\b(?:current (?:user|identity)|o?auth[nz]?|authenticat\w*|authoriz\w*|"
    r"(?:login|permission|admin|staff|staff member|jwt|fresh jwt|token|auth|user|role|roles|scope|scopes|api key) required|"
    r"require[sd]? (?:user|auth|login|session|admin|role|roles|permission|permissions|scope|scopes|api key)|"
    r"has (?:role|roles|permission|permissions|scope|scopes)|check (?:permission|permissions|role|roles|scope|scopes)|"
    r"is (?:admin|superuser|staff|logged in|signed in)|logged in|signed in|"
    r"verify (?:session|user|password|otp|2 ?fa|mfa|credentials?|identity|caller|login)|"
    r"(?:verify|check|validate|require[sd]?) api key|(?<!csrf )token|permission|jwt|"
    r"superuser|(?:^|\w+ )guard$|protected|clerk|bearer|principal)\b|^(?:protect|requires)$")
# In JavaScript, `getSession`/`useSession`/`getServerSession` read the login (next-auth, Supabase); a Python
# `get_session` is a database session and never counts.
JS_AUTH_WORDS = re.compile(r"\b(?:get server session|get session|use session)\b")
IDENT = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
# Read from a handler's body. Shapes that are a check wherever they appear: the framework's view of the caller.
BODY_AUTH_SHAPED = re.compile(r"request\.user|req\.user|locals\.user|session\.user|session\[.{0,20}user|"
                              r"\bin\s+session\s*[:)]|request\.state\.user|ctx\.state\.user|req\.session|"
                              r"request\.session", re.I)
# A parameter whose bare name means the caller (anything else named like an auth word is data: `permissions`)
CALLER_PARAM = re.compile(r"(?:current|auth|authenticated|logged_?in|signed_?in|session)_?user|current_?identity|"
                          r"principal|caller|viewer", re.I)
# Parameters that carry the request itself, or are injected by the framework rather than sent in the request
INJECTED = re.compile(r"\b(?:Header|Cookie|Depends|Security)\s*\(")
CARRIER = re.compile(r"req|request|res|response|ctx|context|event|locals|self|cls|next|env|platform|c|h|e", re.I)
# A helper that fetches a user record. `get_user(token)` identifies the caller; `get_user(payload["owner"])` finds
# the record's owner (the IDOR shape), which proves nothing about who is calling.
USER_LOOKUP = re.compile(r"\b(?:get|fetch|find|load|lookup|read|select)_?user(?:_?by_?\w+|s)?\s*\(", re.I)
CALLER_ARG = re.compile(r"token|session|request|\breq\b|\bctx\b|context|headers?|cookies?|authorization|jwt|"
                        r"claims|locals|auth|credential|bearer|principal|identity", re.I)
# ...but the request's content (body, query, path) is what the caller sent, not who the caller is
REQUEST_VALUE = re.compile(r"\b(?:request|req)\.(?:args|form|json|body|query|params|values|files|data|get_json|"
                           r"path_params|query_params|matchdict|POST|GET|FILES)\b|\b(?:params|payload|body|"
                           r"searchParams|formData|form|args|input)\b", re.I)
# ...and so is everything reached from it: `payload.get("permissions")`, `req.body.auth`, `params["protected"]`
DATA_CHAIN = re.compile(REQUEST_VALUE.pattern + r"(?:\s*(?:\.\s*[\w$]+|\[[^\]\n]*\]|\((?:[^()\n]|\([^()\n]*\))*\)))*", re.I)
ASSIGNMENT = re.compile(r"^\s*(?:(?:const|let|var)\s+)?(?P<lhs>[\w$]+(?:\s*,\s*[\w$]+)*|\{[^}=\n]*\}|\[[^\]=\n]*\])"
                        r"\s*(?::[^=\n]+?)?\s*(?:[-+*/%&|^]|\*\*|//|\?\?|\|\||&&)?=(?![=>])\s*(?P<rhs>.+)$")
CONDITION = re.compile(r"\b(?:if|elif|while|assert|unless)\b|[=!]==?|\bis\b|\bnot\b|!|&&|\|\||\?")
PUBLIC_ROUTE_RE = re.compile(r"login|signin|sign-in|signup|sign-up|register|password|reset|recover|health|"
                             r"webhook|callback|logout|log-out|signout|sign-out|verify|token|public|contact|subscribe|oauth|"
                             r"(?<![a-z])auth(?![a-z])", re.I)   # /auth/refresh, not /authors
MUTATING = {"POST", "PUT", "PATCH", "DELETE", "ANY"}


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).hexdigest()[:12]


def _files(repo: Path, exts=None, names=None):
    for p in repo.rglob("*"):
        if not p.is_file() or not inside_repo(p, repo):
            continue
        parts = p.relative_to(repo).parts
        if skipped(parts[:-1], repo):   # a file named .env is not the .env/ venv folder
            continue
        if p.name.endswith((".min.js", ".map", ".d.ts")) or p.name in ("package-lock.json", "bun.lock"):
            continue
        if (exts and p.suffix in exts) or (names and (p.name in names or any(p.name.startswith(n) for n in names))):
            yield p


def _read(p: Path, repo) -> str:
    """The text of a file of the project `repo`; nothing when it is none or cannot be read."""
    try:
        return project_text(p, repo)
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
        text = _read(p, repo)
        rel = p.relative_to(repo).as_posix()
        for rule, rx, sev, title, cwe in JS_RULES:
            for m in rx.finditer(text):
                ln = _line_of(text, m.start())
                src_line = text.splitlines()[ln - 1] if text else ""
                if src_line.lstrip().startswith(("//", "*")):
                    continue
                if rule == "LJ-EXEC" and JS_DEV_PATH.search(rel):
                    # end-to-end tooling (Detox, Maestro, Cypress) or a build script: run by a developer with their
                    # own values, never by a user of the app, so it is a heuristic note
                    out.append(_finding(rule, title, "LOW", rel, ln, conf="LOW", cwe=cwe, snippet=src_line.strip(), fixed_rank="low"))
                    continue
                out.append(_finding(rule, title, sev, rel, ln, cwe=cwe, snippet=src_line.strip()))
    return out


JS_DEV_PATH = re.compile(r"(^|/)(detox|maestro|e2e|cypress|__tests__|tests?|scripts?|tools|ci)/|\.(test|spec)\.[jt]sx?$", re.I)


def go_rules(repo: Path) -> list[dict]:
    return _pattern_rules(repo, {".go"}, GO_RULES, skip=lambda rel: rel.endswith("_test.go"))


def rust_rules(repo: Path) -> list[dict]:
    return _pattern_rules(repo, {".rs"}, RUST_RULES, skip=lambda rel: rel.startswith("tests/") or "/tests/" in rel)


_KT_TEMPLATE = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")
_UPPER = re.compile(r"^[A-Z][A-Z0-9_]+$")


def _sql_from_constants(line: str) -> bool:
    """`@Query("SELECT * FROM events WHERE type = $TYPE_TASK")`, `query("DELETE FROM " + TABLE + " WHERE id = ?")`:
    every name glued into the SQL is an UPPER_CASE constant, so there is nothing a user could inject."""
    names = _KT_TEMPLATE.findall(line)
    plain = re.sub(r"\"(?:[^\"\\\n]|\\.)*\"", "", line)
    start = plain.find("(")
    if start < 0:
        return False
    depth, end = 0, len(plain)
    for i in range(start, len(plain)):                 # the first call's argument list, to its matching paren
        depth += plain[i] == "("
        depth -= plain[i] == ")"
        if depth == 0:
            end = i
            break
    first = plain[start + 1:end].split(",")[0]
    names += [x.strip() for x in first.split("+") if x.strip()]
    return bool(names) and all(_UPPER.match(n.rsplit(".", 1)[-1]) for n in names)


def java_rules(repo: Path) -> list[dict]:
    # Kotlin servers (Spring, Ktor) call the same Java APIs, so the same patterns apply to .kt files
    out = _pattern_rules(repo, {".java", ".kt"}, JAVA_RULES,
                         skip=lambda rel: "/src/test/" in rel or rel.startswith("src/test/"))
    return [f for f in out if not (f["rule"] == "LV-SQL-CONCAT" and _sql_from_constants(f.get("snippet") or ""))]


_PHP_VAR = r"(?:\$\w|\{\$)"
_PHP_SQL_WORD = r"(?i:\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|WHERE|FROM|ORDER\s+BY|VALUES)\b)"
_PHP_SQL_CALL = (r"(?:\b(?:mysqli_query|mysqli_multi_query|mysqli_real_query|mysql_query|pg_query|sqlite_query)|"
                 r"->(?:query|exec|prepare|multi_query|real_query|get_results|get_row|get_var|get_col)|"
                 r"\bDB::(?:select|insert|update|delete|statement|unprepared|affectingStatement))\s*\(")
_PHP_STR = r"(?:\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*')"
_PHP_ARGS = r"(?:[^\"';\n]|" + _PHP_STR + r")*?"     # whole strings only, so a closing quote never starts one
_PHP_BUILT = (r"(?:\"(?:[^\"\\\n]|\\.)*?" + _PHP_VAR + r"|" + _PHP_STR + r"\s*\.\s*\$|\$\w+\s*\.\s*['\"])")
PHP_RULES = [   # (id, pattern, severity, title, cwe, tool confidence, rank)
    ("LH-SQL-CONCAT", re.compile(_PHP_SQL_CALL + r"(?=[^;\n]*" + _PHP_SQL_WORD + r")" + _PHP_ARGS + _PHP_BUILT),
     "HIGH", "Builds a database query from variables (SQL injection risk); use prepared statements with placeholders",
     89, "HIGH", None),
    ("LH-SQL-CONCAT", re.compile(r"^\s*\$\w+\s*\.?=\s*(?:\"(?=[^\"\n]*" + _PHP_SQL_WORD + r")[^\"\n]*" + _PHP_VAR +
                                 r"|['\"](?=[^'\"\n]*" + _PHP_SQL_WORD + r")[^'\"\n]*['\"]\s*\.\s*\$)", re.M),
     "HIGH", "Builds a database query from variables (SQL injection risk); use prepared statements with placeholders",
     89, "HIGH", None),
    ("LH-SQL-RAW", re.compile(r"(?:(?:->|::)(?:whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw|fromRaw)|\bDB::raw)\s*\("
                              r"(?:\s*\$\w+\s*[,)]|" + _PHP_ARGS + _PHP_BUILT + r")"),
     "HIGH", "Puts variables into a raw SQL fragment (SQL injection risk); pass them as bindings", 89, "HIGH", None),
    ("LH-EXEC", re.compile(r"\b(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\((?=[^;\n]*\$)|"
                           r"`[^`\n]*\$\w[^`\n]*`"),
     "HIGH", "Runs a shell command built from variables (command injection risk)", 78, "HIGH", None),
    ("LH-EVAL", re.compile(r"\beval\s*\(\s*\$|\bassert\s*\(\s*\$|\bcreate_function\s*\(|"
                           r"\bpreg_replace\s*\(\s*['\"]([^\w\s\\])[^'\"]*\1[a-zA-Z]*e[a-zA-Z]*['\"]"),
     "HIGH", "Runs text as PHP code (code injection risk)", 94, "HIGH", None),
    ("LH-INCLUDE-INPUT", re.compile(r"\b(?:include|require)(?:_once)?\b[\s(]*[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)"),
     "HIGH", "Loads a PHP file named by the visitor (they can run or read other files)", 98, "HIGH", None),
    ("LH-INCLUDE-VAR", re.compile(r"^\s*(?:include|require)(?:_once)?\b[\s(]*\$\w+", re.M),
     "MEDIUM", "Loads a PHP file whose name is in a variable; make sure it can never come from a visitor", 98, "LOW",
     None),
    ("LH-UNSERIALIZE", re.compile(r"\bunserialize\s*\(\s*\$(?![^;\n]*allowed_classes)"), "MEDIUM",
     "Unserializes data into PHP objects (untrusted data can run code); use json_decode", 502, "HIGH", None),
    ("LH-XSS-ECHO", re.compile(r"(?:\b(?:echo|print)\b|<\?=)(?![^;\n]*(?:htmlspecialchars|htmlentities|esc_html|esc_attr|"
                               r"intval|\(int\)|e\())[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)"),
     "MEDIUM", "Writes what the visitor sent straight into the page (cross-site scripting); wrap it in htmlspecialchars",
     79, "HIGH", None),
    ("LH-XSS-BLADE", re.compile(r"\{!!\s*(?!\s*(?:csrf_field|method_field|json_encode)\b)[^!]*!!\}"), "MEDIUM",
     "Prints a value into the page without escaping it ({!! !!}); use {{ }} unless it is HTML you made yourself",
     79, "LOW", None),
    ("LH-WEAK-PASSWORD-HASH", re.compile(r"\b(?:md5|sha1|crc32)\s*\(\s*\$\w*(?i:pass|pwd)"), "HIGH",
     "Stores passwords with a fast hash (MD5/SHA-1); use password_hash() and password_verify()", 916, "HIGH", "high"),
    ("LH-WEAK-HASH", re.compile(r"\b(?:md5|sha1)\s*\((?!\s*\$\w*(?i:pass|pwd))(?=[^;\n]*(?i:token|secret|key|reset|"
                                r"session|nonce))"), "MEDIUM",
     "Makes a token or key with MD5/SHA-1; use random_bytes() or hash('sha256', …)", 328, "LOW", None),
    ("LH-TLS-OFF", re.compile(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:=>|,)\s*(?:false|0)\b|['\"]verify['\"]\s*=>\s*false|"
                              r"->withoutVerifying\s*\(|['\"]sslverify['\"]\s*=>\s*false", re.I),
     "HIGH", "Turns off HTTPS certificate checks (anyone on the network can read and change the traffic)", 295, "HIGH",
     "high"),
    ("LH-EXTRACT", re.compile(r"\b(?:extract|parse_str)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"), "MEDIUM",
     "Turns request fields into variables (a visitor can overwrite any variable, like $is_admin)", 621, "HIGH", None),
    ("LH-CORS-ALL", re.compile(r"header\s*\(\s*['\"]Access-Control-Allow-Origin:\s*\*|['\"]allowed_origins['\"]\s*=>\s*"
                               r"\[\s*['\"]\*['\"]"), "MEDIUM", "Allows any website to call this API (CORS *)", 942,
     "HIGH", None),
    ("LH-DEBUG", re.compile(r"ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(?:1|on|true)|"
                            r"define\s*\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*true", re.I), "MEDIUM",
     "Shows PHP errors to visitors (they reveal file paths, queries and sometimes passwords)", 209, "HIGH", None),
    ("LH-UPLOAD-NAME", re.compile(r"move_uploaded_file\s*\([^;\n]*\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name"), "MEDIUM",
     "Saves an upload under the name the visitor chose (they can upload a .php file and run it)", 434, "LOW", None),
    ("LH-CLEARTEXT-URL", re.compile(r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|schemas\.)"
                                    r"[^'\"\s]+['\"]"), "LOW", "Talks to a server over plain http", 319, "HIGH", "low"),
]


_RB_INTERP = r"(?:\"[^\"\n]*#\{|%Q?[{(\[][^\n]*#\{|<<[~-]?['\"]?[A-Z]+['\"]?)"     # "…#{x}…", %Q(…#{x}…), heredocs
_RB_BUILT = r"(?:" + _RB_INTERP + r"|['\"][^'\"\n]*['\"]\s*\+\s*[@\w])"
_RB_SQL_CALL = (r"(?:\.|\b)(?:where|not|or|find_by_sql|count_by_sql|select|order|reorder|group|having|joins|pluck|"
                r"exists\?|execute|exec_query|exec_update|exec_delete|exec_insert|select_all|select_one|select_value|"
                r"select_values|select_rows|find_by|delete_all|destroy_all|update_all|from|lock|query|prepare)"
                r"\s*\(?\s*")
RUBY_RULES = [   # (id, pattern, severity, title, cwe, tool confidence, rank); ERB templates get only LB-XSS-RAW
    ("LB-SQL-INTERP", re.compile(_RB_SQL_CALL + _RB_BUILT), "HIGH",
     "Builds a database query from variables (SQL injection risk); use placeholders: where(\"title LIKE ?\", q)", 89,
     "HIGH", None),
    ("LB-SQL-PARAMS", re.compile(r"\.(?:order|reorder|group|pluck|select|from|joins|having)\s*\(?\s*params\s*\["),
     "HIGH", "Puts a request value straight into a raw SQL part (ORDER BY, SELECT…); pick from a fixed list instead",
     89, "HIGH", None),
    ("LB-EXEC", re.compile(r"(?:\b(?:system|exec|spawn|IO\.popen|Open3\.\w+|Process\.spawn)\s*\(?[^\n]*#\{|`[^`\n]*#\{|"
                           r"%x[{(\[][^\n]*#\{|\b(?:system|exec|spawn|IO\.popen|Open3\.\w+)\s*\(?\s*(?:params\b|[\"'][^\"'\n]*"
                           r"[\"']\s*\+))"),
     "HIGH", "Runs a shell command built from variables (command injection risk); pass the words as separate arguments",
     78, "HIGH", None),
    ("LB-EVAL", re.compile(r"\b(?:eval|instance_eval|class_eval|module_eval)\s*\(?\s*(?:params\b|\"[^\"\n]*#\{|[a-z_]\w*\s*"
                           r"(?:\)|$))|\brender\s*\(?\s*inline:\s*(?:params\b|\"[^\"\n]*#\{)|"
                           r"params\s*\[[^\]]+\](?:\s*\.\s*\w+)*?\s*\.\s*(?:safe_)?constantize\b|\.(?:public_)?send\s*\(\s*params\s*\[",
                           re.M),
     "HIGH", "Runs text, a class name or a method name the code was given (code injection risk)", 94, "HIGH", None),
    ("LB-DESERIALIZE", re.compile(r"\bMarshal\.load\s*\(|\bYAML\.unsafe_load\s*\("), "HIGH",
     "Turns data into Ruby objects (untrusted data can run code); use JSON.parse", 502, "HIGH", None),
    ("LB-DESERIALIZE", re.compile(r"\bYAML\.load\s*\((?![^\n]*"
                                  r"permitted_classes)(?=[^\n]*(?:params|request|body|read|cookies))"), "MEDIUM",
     "Turns data into Ruby objects (untrusted data can run code); use JSON.parse or YAML.safe_load", 502, "LOW", None),
    ("LB-XSS-RAW", re.compile(r"\.html_safe\b|<%==|\braw\s*\(?\s*(?:params|@?\w+)"), "MEDIUM",
     "Prints a value into the page without escaping it (html_safe/raw/<%==); let Rails escape it unless you made the HTML",
     79, "LOW", None),
    ("LB-MASS-ASSIGN", re.compile(r"\.permit!|\bparams\.to_unsafe_h\b|\.(?:new|create|create!|update|update!|"
                                  r"update_attributes|assign_attributes|insert_all|upsert)\s*\(\s*params\s*(?:\[[^\]]+\]\s*)?\)"),
     "MEDIUM", "Saves every field the visitor sends (they can set fields like admin: true); list the allowed ones with "
               "params.require(...).permit(...)", 915, "HIGH", None),
    ("LB-REDIRECT", re.compile(r"\bredirect_to\s*\(?\s*(?:params\s*\[|request\.referr?er\b)(?![^\n]*allow_other_host:\s*"
                               r"false)"), "MEDIUM",
     "Sends the visitor to an address taken from the request (an attacker's link can bounce people to their own site)",
     601, "HIGH", None),
    ("LB-FILE-INPUT", re.compile(r"\b(?:send_file|send_data\s*\(?\s*File\.read|File\.(?:read|open|write|delete|"
                                 r"binread|readlines|unlink)|IO\.(?:read|readlines)|FileUtils\.\w+|Pathname\.new|"
                                 r"(?<![.\w])open)\s*\(?[^\n]*params\s*\["), "HIGH",
     "Opens a file named by the request (a visitor can read or change other files; `open` can even run commands)", 22,
     "HIGH", None),
    ("LB-TLS-OFF", re.compile(r"VERIFY_NONE|\bverify(?:_ssl)?:\s*false|ssl_verify_mode\s*(?:=|:)\s*:?none|"
                              r"ssl:\s*\{[^}\n]*verify:\s*false"), "HIGH",
     "Turns off HTTPS certificate checks (anyone on the network can read and change the traffic)", 295, "HIGH", "high"),
    ("LB-WEAK-PASSWORD-HASH", re.compile(r"Digest::(?:MD5|SHA1)\.(?:hex|base64)?digest\s*\(?\s*@?\w*(?i:pass|pwd)"),
     "HIGH", "Stores passwords with a fast hash (MD5/SHA-1); use has_secure_password (bcrypt)", 916, "HIGH", "high"),
    ("LB-WEAK-HASH", re.compile(r"^(?=[^\n]*(?i:token|secret|key|reset|session|nonce))[^\n]*?Digest::(?:MD5|SHA1)\."
                                r"(?:hex|base64)?digest\b(?!\s*\(?\s*@?\w*(?i:pass|pwd))", re.M), "MEDIUM",
     "Makes a token or key with MD5/SHA-1; use SecureRandom or OpenSSL::HMAC with SHA-256", 328, "LOW", None),
    ("LB-CSRF-OFF", re.compile(r"\bskip_(?:before_action|forgery_protection)\b[^\n]*(?:verify_authenticity_token|$)|"
                               r"protect_from_forgery\s+with:\s*:null_session", re.M), "MEDIUM",
     "Turns off Rails' protection against forged form posts (another site can make a signed-in visitor's browser "
     "submit forms)", 352, "LOW", None),
    ("LB-CORS-ALL", re.compile(r"\borigins\s*\(?\s*['\"]\*['\"]|['\"]Access-Control-Allow-Origin['\"]\]?\s*(?:=|,)\s*"
                               r"['\"]\*['\"]"), "MEDIUM", "Allows any website to call this API (CORS *)", 942, "HIGH",
     None),
    ("LB-DEBUG", re.compile(r"config\.consider_all_requests_local\s*=\s*true|\bset\s+:show_exceptions\s*,\s*true"),
     "MEDIUM", "Shows full error pages to visitors in production (they reveal code, queries and settings)", 209, "HIGH",
     None),
    ("LB-SECRET-BASE", re.compile(r"\bsecret_key_base\s*=\s*['\"][0-9a-f]{30,}['\"]"), "HIGH",
     "Writes the secret that signs every session cookie into the code (anyone with the code can sign in as anyone)",
     798, "HIGH", None),
    ("LB-CLEARTEXT-URL", re.compile(r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|schemas\.)"
                                    r"[^'\"\s#]+['\"]"), "LOW", "Talks to a server over plain http", 319, "HIGH", "low"),
]


DEV_SCRIPT = re.compile(r"(^|/)(scripts?|fastlane|tools|bin|ci)/|(^|/)(Fastfile|Rakefile|Dangerfile|Podfile)$|\.rake$", re.I)


def ruby_rules(repo: Path) -> list[dict]:
    out = []
    for p in _files(repo, {".rb", ".erb", ".rake"}):
        rel = p.relative_to(repo).as_posix()
        if re.search(r"(^|/)(spec|tests?|vendor|tmp|log|db/migrate)/", rel):
            continue
        text = _read(p, repo)
        lines = text.splitlines()
        erb = rel.endswith(".erb")
        seen = set()
        for rule, rx, sev, title, cwe, conf, rank in RUBY_RULES:
            if erb and rule != "LB-XSS-RAW":
                continue
            if rule == "LB-DEBUG" and not re.search(r"(^|/)config/environments/production\.rb$|(^|/)(app|server|config)"
                                                    r"\.(rb|ru)$", rel):
                continue
            if rule == "LB-CSRF-OFF" and "verify_authenticity_token" not in text and "null_session" not in text:
                continue
            for m in rx.finditer(text):
                ln = _line_of(text, m.start() + (len(m.group(0)) - len(m.group(0).lstrip())))
                src = lines[ln - 1] if ln <= len(lines) else ""
                if src.lstrip().startswith("#") or (rule, ln) in seen:
                    continue
                if rule == "LB-CSRF-OFF" and "verify_authenticity_token" not in src and "null_session" not in src:
                    continue
                seen.add((rule, ln))
                if rule == "LB-EXEC" and DEV_SCRIPT.search(rel):
                    # a build or release script run by a developer (fastlane, Scripts/, Rakefile): the command is built
                    # from the developer's own values, not from anything a user sends, so it is a heuristic note
                    out.append(_finding(rule, title, "LOW", rel, ln, conf="LOW", cwe=cwe, snippet=src.strip(), fixed_rank="low"))
                    continue
                out.append(_finding(rule, title, sev, rel, ln, conf=conf, cwe=cwe, snippet=src.strip(), fixed_rank=rank))
    return out


_CX_SQL_WORD = (r"(?i:\bSELECT\b[^\"\n]*\bFROM\b|\bINSERT\s+(?:OR\s+\w+\s+)?INTO\b|\bUPDATE\s+\w+\s+SET\b|\bDELETE\s+FROM\b|"
                r"\bWHERE\s+\w+\s*(?:=|<|>|LIKE\b|IN\b))")
_CX_VAR = r"[A-Za-z_][\w.\->\[\]()]*"
CPP_RULES = [   # (id, pattern, severity, title, cwe, tool confidence, rank)
    ("LX-SQL-BUILT", re.compile(r"\b(?:sn?printf|asprintf|std::format|fmt::format|absl::StrFormat)\s*\([^;\n]*\"(?=[^\"\n]*"
                                + _CX_SQL_WORD + r")[^\"\n]*%(?:s|d|ld|u)[^\"\n]*\"|\"(?=[^\"\n]*" + _CX_SQL_WORD +
                                r")[^\"\n]*\"\s*\+\s*" + _CX_VAR + r"|\b(?:sqlite3_exec|sqlite3_prepare(?:_v[23])?|mysql_query|"
                                r"mysql_real_query|PQexec)\s*\(\s*\w+\s*,\s*(?!\")[^,;\n]*\+"),
     "HIGH", "Builds a database query from variables (SQL injection risk); use sqlite3_bind_* / prepared statements",
     89, "HIGH", None),
    ("LX-EXEC", re.compile(r"\b(?:std::)?(?:system|popen|_popen|wsystem|execl|execlp|execle|WinExec|ShellExecuteA?W?)\s*\(\s*"
                           r"(?!\")(?!NULL\b)(?!nullptr\b)(?!0\s*\))[^;\n]"), "HIGH",
     "Runs a shell command that is not a fixed string (command injection risk); use execv with an argument list", 78,
     "HIGH", None),
    ("LX-GETS", re.compile(r"\bgets\s*\(\s*\w"), "HIGH",
     "Reads a line with gets(), which cannot stop at the end of the buffer (buffer overflow); use fgets", 242, "HIGH",
     None),
    ("LX-BUFFER", re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|stpcpy|lstrcpy\w?|StrCpy\w?)\s*\("),
     "MEDIUM", "Copies into a fixed-size buffer without a length (a long value overflows it); use snprintf, strlcpy or "
               "std::string", 120, "LOW", None),
    ("LX-SCANF", re.compile(r"\b(?:f|s)?scanf\s*\([^;\n]*\"[^\"\n]*%s"), "MEDIUM",
     "Reads text with scanf(\"%s\"), which has no length limit (buffer overflow); give a width like %63s", 120, "HIGH",
     None),
    ("LX-FORMAT", re.compile(r"\b(?:printf|vprintf)\s*\(\s*(?!\")" + _CX_VAR + r"\s*\)|\b(?:fprintf|syslog|dprintf)\s*\(\s*"
                             r"\w+\s*,\s*(?!\")" + _CX_VAR + r"\s*\)|\bsn?printf\s*\(\s*\w+\s*,\s*(?:\w+\s*,\s*)?(?!\")"
                             r"(?!sizeof)" + _CX_VAR + r"\s*\)"), "HIGH",
     "Uses a variable as the format string (a value containing %n or %s can read or write memory); write printf(\"%s\", x)",
     134, "HIGH", None),
    ("LX-TLS-OFF", re.compile(r"(?:SSL_CTX_set_verify|SSL_set_verify|mbedtls_ssl_conf_authmode|wolfSSL_CTX_set_verify)\s*\("
                              r"[^;\n?]*VERIFY_NONE|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*0L?\b|"
                              r"enable_server_certificate_verification\s*\(\s*false|verify_mode\s*\(\s*(?:boost::)?asio::ssl::"
                              r"verify_none|set_verify_mode\s*\([^)]*verify_none"), "HIGH",
     "Turns off HTTPS certificate checks (anyone on the network can read and change the traffic)", 295, "HIGH", "high"),
    ("LX-WEAK-RANDOM", re.compile(r"^(?=[^\n]*(?i:token|secret|session|nonce|salt|password|otp|key))[^\n]*?\b(?:rand|random|"
                                  r"srand)\s*\(", re.M), "MEDIUM",
     "Makes a secret value with rand(), which is predictable; use getrandom/RAND_bytes or std::random_device", 338,
     "LOW", None),
    ("LX-WEAK-PASSWORD-HASH", re.compile(r"\b(?:MD5|SHA1|EVP_md5|EVP_sha1)\s*\([^;\n]*(?i:pass|pwd)"), "HIGH",
     "Stores passwords with a fast hash (MD5/SHA-1); use a password hash such as Argon2 or bcrypt", 916, "HIGH", "high"),
    ("LX-TEMP-FILE", re.compile(r"\b(?:tmpnam|tempnam|mktemp|_mktemp)\s*\("), "MEDIUM",
     "Picks a temporary file name another program can guess and take first; use mkstemp", 377, "HIGH", None),
    ("LX-PATH-INPUT", re.compile(r"(?:(?<![\w.>:])(?:fopen|open|ifstream|ofstream|remove|unlink)|std::(?:ifstream|ofstream|"
                                 r"fstream|filesystem::remove\w*))\s*[({]"
                                 r"[^;\n]*(?:argv\s*\[|req(?:uest)?(?:\.|->)(?:get_param_value|body|matches|getParameter|"
                                 r"path_params|url_params))"), "HIGH",
     "Opens a file named by the request or the command line (a caller can read or change other files)", 22, "HIGH",
     None),
    ("LX-CLEARTEXT-URL", re.compile(r"\"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|schemas\.)[^\"\s]+\""),
     "LOW", "Talks to a server over plain http", 319, "HIGH", "low"),
]


def cpp_rules(repo: Path) -> list[dict]:
    out = []
    from .cpp_frontend import C_EXTS, CPP_EXTS, SKIP, VENDORED
    for p in _files(repo, C_EXTS | CPP_EXTS | {".C", ".CPP"}):
        rel = p.relative_to(repo).as_posix()
        if SKIP.search(rel) or VENDORED.search(rel) or re.search(r"(^|/)(tests?|unittests?|spec|examples?|samples?|benchmarks?)/|_test\.|_unittest\.",
                                         rel):
            continue
        text = _read(p, repo)
        lines = text.splitlines()
        seen = set()
        for rule, rx, sev, title, cwe, conf, rank in CPP_RULES:
            for m in rx.finditer(text):
                ln = _line_of(text, m.start() + (len(m.group(0)) - len(m.group(0).lstrip())))
                src = lines[ln - 1] if ln <= len(lines) else ""
                if src.lstrip().startswith(("//", "*", "/*", "#")) or (rule, ln) in seen:
                    continue
                if rule == "LX-BUFFER" and ("LX-SQL-BUILT", ln) in seen:
                    continue
                seen.add((rule, ln))
                if rule == "LB-EXEC" and DEV_SCRIPT.search(rel):
                    # a build or release script run by a developer (fastlane, Scripts/, Rakefile): the command is built
                    # from the developer's own values, not from anything a user sends, so it is a heuristic note
                    out.append(_finding(rule, title, "LOW", rel, ln, conf="LOW", cwe=cwe, snippet=src.strip(), fixed_rank="low"))
                    continue
                out.append(_finding(rule, title, sev, rel, ln, conf=conf, cwe=cwe, snippet=src.strip(), fixed_rank=rank))
    return out


def php_rules(repo: Path) -> list[dict]:
    out = []
    for p in _files(repo, {".php"}):
        rel = p.relative_to(repo).as_posix()
        if re.search(r"(^|/)tests?/|Test\.php$|(^|/)(storage|cache)/", rel):
            continue
        text = _read(p, repo)
        lines = text.splitlines()
        blade = rel.endswith(".blade.php")
        seen = set()
        for rule, rx, sev, title, cwe, conf, rank in PHP_RULES:
            if (rule == "LH-XSS-BLADE") != blade:
                continue
            for m in rx.finditer(text):
                ln = _line_of(text, m.start() + (len(m.group(0)) - len(m.group(0).lstrip())))
                src = lines[ln - 1] if ln <= len(lines) else ""
                if src.lstrip().startswith(("//", "#", "*", "/*")) or (rule, ln) in seen:
                    continue
                seen.add((rule, ln))
                if rule == "LB-EXEC" and DEV_SCRIPT.search(rel):
                    # a build or release script run by a developer (fastlane, Scripts/, Rakefile): the command is built
                    # from the developer's own values, not from anything a user sends, so it is a heuristic note
                    out.append(_finding(rule, title, "LOW", rel, ln, conf="LOW", cwe=cwe, snippet=src.strip(), fixed_rank="low"))
                    continue
                out.append(_finding(rule, title, sev, rel, ln, conf=conf, cwe=cwe, snippet=src.strip(), fixed_rank=rank))
    return out


def _pattern_rules(repo: Path, exts: set[str], rules, skip) -> list[dict]:
    """Line patterns over one language's files; `skip` takes the repo-relative path."""
    out = []
    for p in _files(repo, exts):
        rel = p.relative_to(repo).as_posix()
        if skip(rel):
            continue
        text = _read(p, repo)
        for rule, rx, sev, title, cwe in rules:
            for m in rx.finditer(text):
                ln = _line_of(text, m.start())
                src_line = text.splitlines()[ln - 1] if text else ""
                if src_line.lstrip().startswith("//"):
                    continue
                out.append(_finding(rule, title, sev, rel, ln, cwe=cwe, snippet=src_line.strip()))
    return out


def exposed_secrets(repo: Path) -> list[dict]:
    out, seen = [], set()
    for p in _files(repo, WEB_EXTS | {".json", ".yml", ".yaml", ".toml"}, names=(".env",)):
        text = _read(p, repo)
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
        text = _read(p, repo)
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
        text = _read(p, repo)
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
        "@supabase" in _read(pj, repo) for pj in _files(repo, names=("package.json",)))
    if sql_files and uses_supabase:
        rls, created = set(), []
        for p in sql_files:
            text = _read(p, repo)
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


def segments(ident: str) -> str:
    """A name as whole lower-case words: `getServerSession` -> "get server session", `load_permissions` ->
    "load permissions", `OAuth2PasswordBearer` -> "o auth 2 password bearer", `tokenize` -> "tokenize"."""
    parts = []
    for chunk in re.split(r"[^A-Za-z0-9]+", ident):
        parts += re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", chunk)
    return " ".join(p.lower() for p in parts)


# Python's `secrets.token_urlsafe`, `token_hex` and `token_bytes` make random text: a nonce, a share link, a new
# key. The word `token` in them says nothing about who is calling (until 2026-11-11 a route that made a nonce read as
# one with a login check, and Lantern's own share page was asked whose record it shows). With the module's name in
# front, a call on what they give is on random text too (`secrets.token_bytes(8).hex()`).
MAKES_TEXT = re.compile(r"(?:(?:ext )?secrets token (?:urlsafe|hex|bytes)\b|token (?:urlsafe|hex|bytes)$)")


def auth_word(ident: str, js: bool = False) -> str | None:
    """The auth words `ident` is built from, matched as whole segments, or None: `get_token` -> "token", `tokenize`
    -> None, `load_permissions` -> None (plural: a list of permissions, not a check), `has_permission` -> a match."""
    words = segments(ident)
    if MAKES_TEXT.match(words):
        return None
    m = AUTH_WORDS.search(words) or (JS_AUTH_WORDS.search(words) if js else None)
    return m.group(0) if m else None


def auth_ident(text: str, js: bool = False) -> str | None:
    """The first name in `text` (strings removed) built from an auth word: `Depends(get_current_user)` ->
    `get_current_user`, `Annotated[User, Depends(get_session)]` -> None."""
    for m in IDENT.finditer(_strip_strings(text)):
        if auth_word(m.group(0), js):
            return m.group(0)
    return None


def mentions_auth(code: str, js: bool = False) -> bool:
    """Middleware windows: the framework's view of the caller, or any name built from an auth word."""
    return bool(BODY_AUTH_SHAPED.search(code) or auth_ident(code, js))


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


def _blank_data(m: re.Match) -> str:
    return re.sub(r"[^\n]", "^", m.group(0))


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


def _split_top(s: str, ch: str) -> tuple[str, str]:
    """Split at the first `ch` outside brackets (and not part of `==`, `=>`, `!=`)."""
    depth = 0
    for i, c in enumerate(s):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ch and depth == 0 and not (ch == "=" and (s[i + 1:i + 2] in ("=", ">") or s[i - 1:i] in ("=", "!", "<", ">"))):
            return s[:i], s[i + 1:]
    return s, ""


def _params(signature: str) -> list[tuple[str, str, str]]:
    """(name, annotation, default) for each parameter of `def f(a: int = 1, *, user=Depends(x))` or `(req, res)`."""
    start = signature.find("(")
    if start < 0:
        return []
    inner, out, depth, buf, parts = _call_args(signature, start), [], 0, [], []
    for c in inner:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
    parts.append("".join(buf))
    for part in parts:
        part = part.strip().lstrip("*").strip()
        if not part or part in ("/",):
            continue
        head, default = _split_top(part, "=")
        name, annotation = _split_top(head, ":")
        out.append((name.strip(), annotation.strip(), default.strip()))
    return out


PAYLOAD_TYPE = re.compile(r"\b[A-Za-z_]\w*?(?:Request|RequestForm|Body|Payload|Input|In|Create|Update|Schema|Form|"
                          r"Response|DTO|Dto|Params|Data)\b")


def signature_sign(signature: str, doubted: frozenset = frozenset()) -> str | None:
    """A parameter that brings the caller in: a dependency or type named like an auth check (`Depends(current_user)`,
    `user: CurrentUser`, `Security(...)`), or a name that can only mean the caller (`current_user`). A parameter
    merely named like an auth word (`permissions: list[str]`, `is_admin: bool`) is data the caller sent. A parameter
    filled by a function named in `doubted` is no sign (`_doubted_names`)."""
    for name, annotation, default in _params(signature):
        if doubted and _names_one(default + " " + annotation, doubted):
            continue
        if default and (auth_ident(default) or re.search(r"\bSecurity\s*\(", default)):
            return f"`{name}={default}`"[:70] + " in its parameters"
        # a request body's type (`body: TokenRequest`, `form: OAuth2PasswordRequestForm`) is what the caller sent,
        # not a check of who they are
        if annotation and auth_ident(PAYLOAD_TYPE.sub("", annotation)):
            return f"`{name}: {annotation}`"[:70] + " in its parameters"
        if CALLER_PARAM.fullmatch(name):
            return f"`{name}` in its parameters"
    return None


def _data_params(signature: str) -> set[str]:
    """Plain parameters: what the caller sent. Not the request itself, an injected dependency, header or cookie, an
    auth-typed parameter, or a name that means the caller or a credential (`token`, `authorization`)."""
    out = set()
    for name, annotation, default in _params(signature):
        if CARRIER.fullmatch(name) or CALLER_PARAM.fullmatch(name) or CALLER_ARG.search(name):
            continue
        if auth_ident(default + " " + annotation) or INJECTED.search(default):
            continue
        for part in re.findall(r"[A-Za-z_$][\w$]*", name):   # `{ a, b }` destructuring too
            out.add(part)
    return out


def _blank_names(code: str, signature: str) -> str:
    """Blank the names that hold what the caller sent: plain parameters, and every local name assigned from request
    data (already blanked to `^`; strings and comments are `~`) or from such a name, followed in order.
    `permissions = payload.get("permissions")` then reads as no check, and so does every later use of `permissions`."""
    names = _data_params(signature)
    for line in code.splitlines():
        m = ASSIGNMENT.match(line)
        if not m:
            continue
        rhs = m.group("rhs")
        if "^" in rhs or names & set(re.findall(r"(?<![\w$.])[A-Za-z_$][\w$]*", rhs)):
            names.update(re.findall(r"[A-Za-z_$][\w$]*", re.sub(r":\s*[\w$]+", "", m.group("lhs"))))
    names -= {"const", "let", "var"}
    if not names:
        return code
    held = re.compile(r"(?<![\w$.])(?:" + "|".join(re.escape(t) for t in sorted(names, key=len, reverse=True)) + r")(?![\w$])")
    return held.sub(lambda mm: "^" * len(mm.group(0)), code)


def _use_shape(code: str, s: int, e: int) -> tuple[str, str] | None:
    """How the auth word at code[s:e] is used: ("call", ident), ("attribute", ident), ("decorator", ident), or
    None for a bare name or an assignment target (`permissions = ...`, `user.is_admin = True`)."""
    i = s
    while i > 0 and (code[i - 1].isalnum() or code[i - 1] in "_$."):
        i -= 1
    j = e
    while j < len(code) and (code[j].isalnum() or code[j] in "_$" or (code[j] == "." and j + 1 < len(code) and (code[j + 1].isalnum() or code[j + 1] in "_$"))):
        j += 1
    ident = code[i:j].strip(".")
    k = j
    while k < len(code) and code[k] in " \t":
        k += 1
    rest = code[k:k + 3]
    if re.match(r"(?:[-+*/%&|^]|\*\*|//|\?\?|&&|\|\|)?=(?![=>])", rest):
        return None
    if rest.startswith("("):
        return "call", ident
    if rest.startswith("[") or "." in ident:
        return "attribute", ident
    q = i - 1
    while q >= 0 and code[q] in " \t":
        q -= 1
    if q >= 0 and code[q] == "@":
        return "decorator", ident
    return None


def body_auth_sign(text: str, start_line: int, end_line: int, js: bool, signature: str = "") -> tuple[str, str] | None:
    """What a handler's own lines say about checking the caller, read with strings, comments and request data
    blanked out. ("strong", evidence) for the framework's view of the caller (`request.user`), an auth word used
    as a call or attribute (`authorize(...)`, `user.is_admin`), or a user lookup given the caller's token/request/
    session (or nothing); ("weak", evidence) for a user lookup by some other value whose result is then tested,
    which finds a record, not the caller; None otherwise. A bare local name or parameter is never a sign, however
    it is called: `permissions = payload.get("permissions")` is what the caller claims. Weak never counts as in place."""
    lines = text.splitlines()
    if not start_line or start_line > len(lines):
        return None
    raw = "\n".join(lines[start_line - 1:(end_line or start_line)])
    chains = DATA_CHAIN.sub(_blank_data, code_only(raw, js))   # strings, comments (~), request data and what hangs off it (^)
    code = _blank_names(chains, signature)                 # ...and the names that hold it (all the same length)
    m = BODY_AUTH_SHAPED.search(code)
    if m:
        return "strong", f"handler mentions `{m.group(0).rstrip(':) ')}`"
    for m in IDENT.finditer(code):   # a name built from an auth word, used as a call, attribute or decorator
        if not auth_word(m.group(0), js):
            continue
        shape = _use_shape(code, m.start(), m.end())
        if shape:
            kind, ident = shape
            return "strong", f"handler calls `{ident}(...)`" if kind == "call" else f"handler mentions `{ident}`"
    weak = None
    for m in USER_LOOKUP.finditer(chains):   # the lookup's result variable is tested, so read it with names intact
        args = _call_args(chains, m.end() - 1)
        call = raw[m.start():m.end() + len(args) + 1].replace("\n", " ")
        call = re.sub(r"\s+", " ", call)[:60]
        held = code[m.end():m.end() + len(args)]   # same span with the names that hold request data blanked
        if not args.strip() or CALLER_ARG.search(m.group(0)) or (CALLER_ARG.search(args) and "^" not in held):
            return "strong", f"handler calls `{call}`"   # get_user(), get_user_by_token(x), get_user(token)
        line_start = chains.rfind("\n", 0, m.start()) + 1
        line_end = chains.find("\n", m.end())
        line = chains[line_start:line_end if line_end >= 0 else len(chains)]
        lhs = re.match(r"\s*(?:(?:const|let|var)\s+)?(?:\{\s*)?([A-Za-z_$][\w$]*)[^=]*=[^=]", line)
        checked = bool(CONDITION.search(line[:m.start() - line_start]))   # `if not get_user(x):`
        if lhs and not checked:
            name = re.escape(lhs.group(1))
            for later in chains[line_end:].splitlines() if line_end >= 0 else []:
                if re.search(rf"(?<![\w$.]){name}(?![\w$])", later) and CONDITION.search(later):
                    checked = True
                    break
        if checked and weak is None:
            by = re.sub(r"\s+", " ", raw[m.end():m.end() + len(args)].strip())[:40]
            weak = ("weak", f"`{call}` looks up a user by `{by}`, not by who is calling")
    return weak


ROUTE_DOC_KWARGS = re.compile(r"\b(?:response_model|response_class|responses|tags|summary|description|name|status_code|"
                              r"operation_id|deprecated|include_in_schema|response_description|"
                              r"response_model_exclude\w*)\s*=\s*(?:\[[^\]]*\]|\{[^}]*\}|[^,)]+)")


def call_adjacency(g: Graph) -> dict[str, list[str]]:
    adj: dict[str, list[str]] = {}
    for e in g.call_edges():
        adj.setdefault(e.src, []).append(e.dst)
    return adj


# npm packages that are a login check and nothing else: whatever they hand a route turns away a request that does
# not carry what they ask for, under whatever name the package gives it (`expressjwt`). Read only for a library's
# function (`ext:<package>.<member>`); a package that merely reads a token (`jwt-decode`) is not one.
LOGIN_PACKAGE = re.compile(r"^(express-jwt|koa-jwt|express-basic-auth|basic-auth-connect|http-auth-connect|"
                           r"express-oauth2-jwt-bearer|connect-ensure-login)(\.|\(|$)")


def _in_doubt(nid, doubt) -> bool:
    """With `doubt` (what the flow step read is no login, `flow.Soft`): whether this function's name is not to be
    taken as a sign of one. A function of the project on whose way a token library is called and whose code turns
    nobody away for it, the token library's own function, and what is called on that function's answer
    (`jwt.decode().get`): on such a route a request whose token does not hold went on, so "it calls `jwt.decode`"
    says nothing."""
    if doubt is None or not isinstance(nid, str):
        return False
    if nid in doubt.nodes:
        return True
    if not nid.startswith("ext:"):
        return False
    lib = nid[4:].split("()", 1)[0]
    return bool(VERIFIES.match(lib) or READS_TOKEN.match(lib))


# A library's login made with the word that it is not required turns nobody away (Python; JS/TS has
# `js_frontend.OPTIONAL_LOGIN`): Flask-JWT-Extended's `@jwt_required(optional=True)` and
# `verify_jwt_in_request(optional=True)`, Flask-HTTPAuth's `@auth.login_required(optional=True)`: a call named
# like a login check (`auth_word`) that is handed `optional=True`. On such a route the library's own names for who is calling
# (`OPTIONAL_NAMES`) say nothing either: nobody may be. And FastAPI's security schemes (`SCHEME_ONLY`) carry the
# credential in, and refuse a request that has none unless made with `auto_error=False`: they check nothing about
# it, so a parameter filled by one, which the handler never looks at, is no login. Until 2026-11-11 both read as one.
NOT_REQUIRED = re.compile(r"([A-Za-z_][\w.]*)\s*\([^()\n]*\boptional\s*=\s*True\b")
OPTIONAL_NAMES = frozenset({"jwt_required", "verify_jwt_in_request", "get_jwt_identity", "get_jwt", "current_user",
                            "get_current_user"})
SCHEME_ONLY = re.compile(r"^[ \t]*([A-Za-z_]\w*)[ \t]*(?::[^=\n]+)?=[ \t]*(?:[\w.]+\.)?(OAuth2PasswordBearer|"
                         r"OAuth2AuthorizationCodeBearer|OAuth2|HTTPBearer|HTTPBasic|HTTPDigest|APIKeyHeader|"
                         r"APIKeyCookie|APIKeyQuery|OpenIdConnect)\(", re.M)


def passed_over(n, text: str | None) -> dict[str, str]:
    """What stands on a Python route and looks like a login check without being one, as name -> the reason in
    words: a library's login made optional on this route (`NOT_REQUIRED`, on a decorator or in the handler's lines),
    with the library's names for who is calling, and a FastAPI security scheme made in the route's own file whose
    value the handler takes in and never looks at (the parameter's name stands nowhere but among the parameters)."""
    out: dict[str, str] = {}
    if not text or not n.file or not n.file.endswith(".py"):
        return out
    lines = text.splitlines()
    start = n.start_line or 0
    if not start or start > len(lines):
        return out
    body = code_only("\n".join(lines[start - 1:(n.end_line or start)]))
    for where in (*(n.decorators or ()), body):
        for m in NOT_REQUIRED.finditer(where):
            parts = m.group(1).split(".")
            name = parts[-1]
            if not auth_word(name):
                continue        # some other call that takes a parameter named `optional`: it says nothing of a login
            why = (f"`{name}` is made optional here (`optional=True`), so a request that carries no token goes on, "
                   "and what the library says about who is calling may be nobody")
            for part in parts:  # `auth.login_required(optional=True)`: the object it hangs on is no sign either
                out[part] = why
            for other in OPTIONAL_NAMES:
                out.setdefault(other, why)
    schemes = dict(SCHEME_ONLY.findall(text))
    if schemes:
        for name, annotation, default in _params(n.signature or ""):
            got = [s for s in re.findall(r"[A-Za-z_]\w*", default + " " + annotation) if s in schemes]
            if got and len(re.findall(rf"(?<![\w.]){re.escape(name)}\b", body)) <= 1:
                why = (f"`{got[0]}` only carries the token in (FastAPI's `{schemes[got[0]]}` checks nothing about "
                       f"it), and nothing in the handler looks at `{name}`")
                out[got[0]] = why
                out.setdefault(schemes[got[0]], why)
    return out


def passed_over_words(n, text: str | None) -> str:
    """A sentence for each thing `passed_over` names, for a finding's explanation; nothing when there is none."""
    said: list[str] = []
    for why in passed_over(n, text).values():
        if why not in said:
            said.append(why)
    return "".join(f"Not taken for a login check: {why}. " for why in said)


def _doubted_names(g: Graph, doubt) -> frozenset:
    """The own names of the project's functions in `doubt`: where a decorator or a parameter names one of them, the
    name is no sign either. By name alone, so another function of the same name is passed over with it."""
    if doubt is None:
        return frozenset()
    return frozenset(name for name in (_func_name(g, nid) for nid in doubt.nodes if not nid.startswith("ext:"))
                     if name)


def _names_one(code: str, doubted: frozenset) -> bool:
    return any(part in doubted for part in re.findall(r"[A-Za-z_$][\w$]*", code))


def route_auth_sign(g: Graph, n, adj: dict[str, list[str]], depth: int = 3, doubt=None,
                    skip: frozenset = frozenset()) -> str | None:
    """The first visible sign that this route checks who is calling: a decorator, a parameter or dependency in
    its signature, or a function named like an auth check within `depth` calls. None when nothing was found.
    `doubt`: what the flow step read is no login on this route (`_in_doubt`); its names are passed over, and so
    are the names in `skip` (`passed_over`)."""
    js = n.id.startswith(("js:", "go:", "jv:", "kt:", "sw:", "dt:", "cs:", "php:"))   # JS, Go, Java, Kotlin, Swift, Dart, C#: camelCase; Python and Rust snake_case
    doubted = _doubted_names(g, doubt) | skip
    for d in n.decorators:
        # a route decorator's description of its answer (`response_model=TokenResponse`, `tags=["auth"]`) says what
        # the route returns, not that it checks the caller
        d_check = ROUTE_DOC_KWARGS.sub("", d)
        if doubted:     # `@token_optional`, `dependencies=[Depends(read_token)]`: the doubted name says nothing
            d_check = re.sub(r"[A-Za-z_$][\w$]*", lambda m: "x" if m.group(0) in doubted else m.group(0), d_check)
        if auth_ident(d_check, js):
            return f"decorator @{d.split('(')[0]}"
    sig = signature_sign(n.signature or "", doubted)
    if sig:
        return sig
    for mid in (n.entry or {}).get("middleware") or ():   # Express: router.delete('/x', requireLogin, handler)
        if _in_doubt(mid, doubt):
            continue
        # the function's own name: not the package or file it comes from, and never the folders on the way
        name = _func_name(g, mid).split("(")[0].rsplit(".", 1)[-1].rsplit("/", 1)[-1]
        if auth_word(name, True) or LOGIN_PACKAGE.match(_func_name(g, mid)):
            return f"middleware `{name}`"
    for u in (n.entry or {}).get("use") or ():   # Express: app.use(requireLogin) written before the route
        if _in_doubt(u["id"], doubt):
            continue
        name = _func_name(g, u["id"]).split("(")[0].rsplit(".", 1)[-1].rsplit("/", 1)[-1]
        if auth_word(name, True) or LOGIN_PACKAGE.match(_func_name(g, u["id"])):
            return f"middleware `{name}` put on before this route ({u['file']}:{u['line']})"
    seen, frontier = {n.id}, [n.id]
    for _ in range(depth):
        nxt = []
        for u in frontier:
            for v in adj.get(u, []):
                if v in seen:
                    continue
                seen.add(v)
                if not _in_doubt(v, doubt) and _func_name(g, v).split("(")[0].rsplit(".", 1)[-1] not in skip and \
                        auth_word(_func_name(g, v),
                                  v.startswith(("js:", "go:", "jv:", "kt:", "sw:", "dt:", "cs:", "php:"))):
                    return f"calls `{_func_name(g, v)}`"
                nxt.append(v)
        frontier = nxt
    return None


def auth_callees(g: Graph, n, adj: dict[str, list[str]], depth: int = 3) -> list[str]:
    """The name of every function within `depth` calls of a route that is named like an auth check: the walk of
    `route_auth_sign`, which stops at the first one."""
    out, seen, frontier = [], {n.id}, [n.id]
    for _ in range(depth):
        nxt = []
        for u in frontier:
            for v in adj.get(u, []):
                if v in seen:
                    continue
                seen.add(v)
                name = _func_name(g, v)
                if auth_word(name, v.startswith(("js:", "go:", "jv:", "kt:", "sw:", "dt:", "cs:", "php:"))):
                    out.append(name)
                nxt.append(v)
        frontier = nxt
    return out


def login_check(g: Graph, n, adj: dict[str, list[str]], text: str | None, doubt=None) -> tuple[str, str] | None:
    """Everything Lantern can see about a route checking its caller: ("strong", why) from the decorator, signature,
    callees or body; ("weak", why) when the body only looks up a user by a request value and tests the result;
    None when nothing was found. Shared by the LW-AUTH-MISSING rule and the protections advisor so both tell the
    same story: a weak sign is never "in place", and a route with no sign gets the finding. `doubt` (from the flow
    step, for a route on whose way a token library is called and nothing turns anybody away): the names it holds
    are no sign (`_in_doubt`), and neither are the handler's lines on which the token library is called. What
    `passed_over` names on the route (a login made optional, a token only carried in) is no sign either."""
    skip = frozenset(passed_over(n, text))
    sign = route_auth_sign(g, n, adj, doubt=doubt, skip=skip)
    if sign:
        return "strong", sign
    if text is None or not n.file:
        return None
    if doubt is not None:
        rows = text.splitlines()
        for file, line in doubt.lines:
            if file == n.file and 0 < line <= len(rows):
                rows[line - 1] = ""
        text = "\n".join(rows)
    doubted = _doubted_names(g, doubt) | skip   # `@login_required` above the handler, where that function is one
    if doubted:
        text = re.sub(r"[A-Za-z_$][\w$]*", lambda m: "_" * len(m.group(0)) if m.group(0) in doubted else m.group(0),
                      text)
    return body_auth_sign(text, n.start_line or 0, n.end_line or n.start_line or 0, js=not n.file.endswith((".py", ".rb")),
                          signature=n.signature or "")


def is_public_route(detail: str) -> bool:
    """Sign-in, sign-up, webhooks and the like: expected to be reachable without a login."""
    return bool(PUBLIC_ROUTE_RE.search(detail.partition(" ")[2] or detail))


def mutating_route(detail: str) -> bool:
    verb = detail.partition(" ")[0]
    return bool({v.upper() for v in verb.split("/")} & MUTATING)


# Said on a finding the flow step asks for: the route calls a library that reads a login token, and that is not
# taken as a login check there. What Lantern found, and the three ways it comes about; never "the token is not
# checked", which Lantern has not shown.
TOKEN_LETS_ON = ("The code on the way to this route calls a library that reads a login token, and Lantern found "
                 "nothing it can follow that turns away a request whose token does not hold, or that carries none: "
                 "the failure is caught and the request goes on, the token is read without being checked, or the "
                 "answer is not waited for. So that call was not taken as a login check for this route. ")


def missing_auth(g: Graph, only=None, doubt=None) -> list[dict]:
    """Routes the frontend calls that change data, where no login check is visible within 3 calls. With `only`
    (the map's nodes of routes, from the flow step: `flow.Result.caught`) those routes are asked instead, called by
    the frontend or not, and read with `doubt` (`login_check`): a token library on the way to them is no sign."""
    out = []
    bridged = {}
    for e in g.call_edges():
        if (e.via or "").startswith("http-") and not e.dst.startswith("ext:"):
            bridged.setdefault(e.dst, e.detail)
    if only is not None:
        bridged = {rid: bridged.get(rid) or "" for rid in sorted(only)}
    adj = call_adjacency(g)
    texts: dict[str, str] = {}
    for rid, detail in bridged.items():
        n = g.nodes.get(rid)
        if n is None or not n.entry:
            continue
        route = n.entry.get("detail") or ""
        if not mutating_route(route) or is_public_route(route):
            continue
        if n.file and n.file not in texts:
            try:
                texts[n.file] = project_text(Path(g.repo_root) / n.file, g.repo_root)
            except OSError:
                texts[n.file] = ""
        sign = login_check(g, n, adj, texts.get(n.file or ""), doubt=doubt)
        if sign and sign[0] == "strong":
            continue
        more = ("Heuristic: Lantern looked three calls deep for anything named like an auth check (current_user, "
                "auth, login_required, token, permission...) and read the handler's own lines for the same words. ")
        if sign:
            more += (f"The only sign in the handler is that {sign[1]}: that finds a record, not the caller. "
                     "Check the signed-in user as well. ")
        more += passed_over_words(n, texts.get(n.file or ""))
        title = f"{n.entry['detail']} changes data, is called by the app, and no login check was found"
        if only is not None:
            title = (f"{n.entry['detail']} changes data, and Lantern found nothing that turns away a request whose "
                     "login token does not hold")
            more = TOKEN_LETS_ON + more
        out.append(_finding(
            "LW-AUTH-MISSING", title, "MEDIUM", n.file, n.start_line, category="code", conf="LOW", cwe=306,
            fixed_rank="medium", more=more + "If this route is meant to be public, ignore it.", snippet=detail or ""))
    return out


# ------------------------------------------------------------- a secret written in the code (LW-SECRET-INLINE)
# The text that signs sessions and login tokens, the password of an account the app connects with, a database address
# that carries its password: written out in JS/TS, Python or a JSON settings file. Read from the text with patterns
# (the name a value is given, the call it is handed to), so a heuristic; keys of a known format are the key patterns'
# business (`security.SECRET_PATTERNS`, gitleaks), and a line they list is not listed again here.
SECRET_JSON = re.compile(r"(^|/)config/[^/]+\.json$|(^|/)(config|default|production|development|settings|secrets?)"
                         r"\.json$")
SECRET_NOT_CODE = re.compile(r"(^|/)(locales?|i18n|lang|langs|languages|translations?|messages|fixtures|__mocks__|"
                             r"mocks?|stories|docs?|examples?)/|\.d\.ts$|\.stories\.[jt]sx?$", re.I)
JS_STR = r"""(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\$\n]|\\.)*)`)"""
PY_STR = r"""(?:[bBrRuU]{0,2}(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"))"""
JS_SETTING = (r"(?:process\.env(?:\.\w+|\[\s*[\"']\w+[\"']\s*\])|import\.meta\.env\.\w+|Deno\.env\.get\([^()]*\)|"
              r"[\w$.]*[cC]onfig[\w$.]*\.get\([^()]*\))")
JS_DEFAULT = re.compile(JS_SETTING + r"\s*(?:\|\||\?\?)\s*" + JS_STR + r"\s*[,;)}\]]?\s*$")
JS_DEFAULT_HEAD = re.compile(JS_SETTING + r"\s*(?:\|\||\?\?)\s*" + JS_STR)
JS_ENV_DEFAULT = re.compile(r"process\.env(?:\.(\w+)|\[\s*[\"'](\w+)[\"']\s*\])\s*(?:\|\||\?\?)\s*" + JS_STR)
PY_DEFAULT = re.compile(r"(?:os\.environ\.get|os\.getenv|environ\.get|getenv)\(\s*" + PY_STR + r"\s*,\s*" + PY_STR
                        + r"\s*\)")
SECRET_CAND = re.compile(r"""(?<![\w$])(?:\[\s*)?(?P<q>["']?)(?P<name>[A-Za-z_$][\w$\-]*)(?P=q)(?:\s*\])?\s*\??"""
                         r"""(?:\s*:\s*string\s*(?==))?\s*[:=](?![=>])\s*""")
PY_SECRET_NAME = re.compile(r"(?<![\w.])(?P<name>[A-Za-z_][\w.]*(?:\[\s*[\"'][\w\-]+[\"']\s*\])?)\s*=(?!=)\s*")
SECRET_WORTH_A_LOOK = re.compile(r"secret|key|pass|pwd", re.I)
SECRET_FILE_WORTH_A_LOOK = re.compile(r"secret|key|pass|pwd|jwt|cookieParser|hmac|Serializer|Signer|://", re.I)
KEY_WORDS = {"private", "signing", "sign", "encryption", "hmac", "jwt", "session", "cookie", "token", "master"}
JS_KEY_CALLS = [(re.compile(r"(?<![\w$.])(?:jwt|jsonwebtoken|JWT|jsonWebToken)\s*\.\s*(?:sign|verify)\s*\("), 1),
                (re.compile(r"(?<![\w$.])cookieParser\s*\("), 0),
                (re.compile(r"(?<![\w$])createHmac\s*\("), 1)]
PY_KEY_CALLS = [(re.compile(r"(?<![\w.])jwt\.(?:encode|decode)\s*\("), 1),
                (re.compile(r"(?<![\w.])hmac\.new\s*\("), 0),
                (re.compile(r"(?<![\w.])(?:URLSafeTimedSerializer|URLSafeSerializer|TimestampSigner|Signer|"
                            r"TimedSerializer)\s*\("), 0)]
# the names Flask and Django themselves give the text that signs: a phrase under them is the secret, as in the call
PY_OWN_NAMES = {"secret_key", "jwt_secret_key"}
PY_LIT_END = re.compile(r"\s*(?:$|[,)}\]#])")
# a secret under a plain name, followed from the call that signs with it (`_followed`)
JS_REF = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,2}"
PY_REF = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){0,2}"
JS_REF_END = re.compile(r"(" + JS_REF + r")\s*(?:$|[,})\]])")
PY_SIGNED_WITH = re.compile(r"(?:\.secret_key|\[\s*[\"'](?:JWT_)?SECRET_KEY[\"']\s*\]|(?<![\w.])(?:JWT_)?SECRET_KEY)"
                            r"\s*=(?!=)\s*(" + PY_REF + r")\s*(?:$|[,)#])", re.M)
NOT_A_SETTING = {"process", "import", "req", "request", "res", "this", "self", "cls", "env", "ctx", "os",
                 "window", "undefined", "null", "true", "false", "None", "True", "False", "app", "current_app"}
JS_FILE_ENDS = ("", ".js", ".ts", ".cjs", ".mjs", ".json", ".jsx", ".tsx", "/index.js", "/index.ts")
FOLLOW_MOST = 4         # lines listed for one name: a text for each place the app runs, not a file of labels
# the call a secret is handed to, a few lines up: there a phrase of several words is a secret too, not a message
SIGNING_CALL = re.compile(r"(?:[sS]ession\w*|[jJ]wt\w*|JWT|\w*Strategy|NextAuth|[cC]ookie\w*)\s*\(")
CONNECTION = re.compile(r"(?<![\w$])(?:host|hostname|server|database|dialect|service|connectionString)\s*:|"
                        r"createConnection|createPool|createTransport|\bnew\s+(?:Pool|Client|Sequelize)\b|"
                        r"(?<![\w$])auth\s*:\s*\{")
DB_ADDRESS = re.compile(r"""["'`](?:mongodb(?:\+srv)?|postgres(?:ql)?(?:\+\w+)?|mysql(?:\+\w+)?|mariadb|rediss?|"""
                        r"""amqps?|mssql)://([^:'"`@/\s${}]+):([^@'"`\s]+)@([^/'"`\s:?]+)""")
NOT_A_PASSWORD = re.compile(r"[${}<>%]|^(password|passwd|pass|pwd|secret|x{3,}|\*+)$", re.I)
SECRET_TITLES = {
    "signing": "A signing secret is written in the code: anyone who can read the code can forge a session or a login "
               "token; read it from a setting kept outside the code",
    "default": "A signing secret falls back to text written in the code when the setting is missing, and the app then "
               "runs with a secret anyone can read; stop with an error instead",
    "password": "The password of an account the app connects with is written in the code; read it from a setting "
                "kept outside the code",
    "address": "A database address that carries its password is written in the code; read it from a setting kept "
               "outside the code",
}


def _name_words(name: str) -> list[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return [w.lower() for w in re.split(r"[\s_\-$.]+", s) if w]


def secret_name(name: str) -> str | None:
    """`signing` for a name whose last words say it is a secret or a key that signs (`cookieSecret`, `JWT_SECRET_KEY`,
    `secretOrKey`, `privateKey`), `password` for one that ends in a word for a password, None for any other
    (`secretName`, `SECRET_HEADER`, `passwordField`, `apiKey`: the name or place of a secret, or a public key)."""
    w = _name_words(name)
    if not w:
        return None
    if w[-1] == "secret" or w[-2:] == ["secret", "key"] or w[-3:] in (["secret", "or", "key"],
                                                                      ["secret", "access", "key"]):
        return "signing"
    if len(w) >= 2 and w[-1] == "key" and w[-2] in KEY_WORDS:
        return "signing"
    return "password" if w[-1] in ("password", "passwd", "pwd", "pass") else None


def _no_secret(name: str, value: str, in_call: bool) -> bool:
    """A value that is not the secret itself: nothing, the name of a setting, a placeholder, a place (a path, an
    address), a label that repeats the name, words for a person (`in_call`: the value stands in the call that
    takes the secret, where a phrase is the secret)."""
    v = value.strip()
    if not v or re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", v) or v.startswith(("./", "../", "/", "~/", "-----BEGIN")):
        return True
    if re.search(r"^<.*>$|^\{\{.*\}\}$|\$\{|%s|^\*+$|^x{3,}$|^\.{3}$|://", v, re.I) or \
            re.search(r"\.(pem|key|crt|cer|p12|pfx|json|txt|env)$", v):
        return True
    if v[:1].isupper() and v.lower().replace("-", " ").split() == _name_words(name):
        return True
    # words for a person: begins with a capital and goes on, or ends like a sentence
    return not in_call and ((v[:1].isupper() and len(v.split()) >= 2) or v.endswith((".", "!", "?", ":")))


def _str_value(m, first: int = 1) -> str:
    return next((g for g in m.groups()[first - 1:] if g is not None), "")


def _args_at(text: str, start: int, limit: int = 4000) -> list[tuple[int, str]]:
    """(offset, text) of each argument of the call whose opening parenthesis is just before `start`; nothing when the
    call does not close within `limit` characters."""
    out, depth, i, begin, n = [], 0, start, start, min(len(text), start + limit)
    while i < n:
        c = text[i]
        if c in "'\"`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                out.append((begin, text[begin:i]))
                return out
            depth -= 1
        elif c == "," and depth == 0:
            out.append((begin, text[begin:i]))
            begin = i + 1
        i += 1
    return []


def _secrets_in(text: str, js: bool, py: bool) -> dict[int, tuple[str, str, str]]:
    """{line: (kind, the text itself, confidence)} for one file."""
    from .security import SECRET_PATTERNS
    lines = text.splitlines()
    found: dict[int, tuple[str, str, str]] = {}
    comment = "#" if py else ("//", "*", "/*")

    def add(ln: int, kind: str, value: str, conf: str) -> None:
        src = lines[ln - 1] if 0 < ln <= len(lines) else ""
        if src.lstrip().startswith(comment) or ln in found:
            return
        if any(rx.search(src) for _n, rx in SECRET_PATTERNS) or JWT_RE.search(src):
            return                                          # a key of a known format: listed by its own rule
        found[ln] = (kind, value, conf)

    string = re.compile(PY_STR if py else JS_STR)
    whole = re.compile(r"\s*" + string.pattern + r"\s*$")
    # 1. the call a secret is handed to, with the text written in its place
    for rx, at in (PY_KEY_CALLS if py else JS_KEY_CALLS if js else ()):
        for m in rx.finditer(text):
            args = _args_at(text, m.end())
            if len(args) <= at:
                continue
            off, arg = args[at]
            ln = _line_of(text, off + len(arg) - len(arg.lstrip()))
            lit = whole.match(arg)
            dflt = (PY_DEFAULT.fullmatch(arg.strip()) if py else JS_DEFAULT.fullmatch(arg.strip()))
            if lit and not _no_secret("secret", _str_value(lit), True):
                add(ln, "signing", _str_value(lit), "MEDIUM")
            elif dflt and not _no_secret("secret", _str_value(dflt, 3 if py else 1), True):
                add(ln, "default", _str_value(dflt, 3 if py else 1), "LOW")
    # 2. a value given a name that says it is a secret
    for i, src in enumerate(lines, 1):
        if not SECRET_WORTH_A_LOOK.search(src):
            continue
        if py:      # a name that says it signs (a password is left to Bandit's B105 and B106)
            for m in PY_SECRET_NAME.finditer(src):
                last = re.findall(r"[A-Za-z_]\w*", m.group("name"))
                if not last or secret_name(last[-1]) != "signing":
                    continue
                d = PY_DEFAULT.match(src, m.end())
                lit = string.match(src, m.end())
                own = last[-1].lower() in PY_OWN_NAMES
                if d and not _no_secret(last[-1], _str_value(d, 3), True):
                    add(i, "default", _str_value(d, 3), "LOW")
                elif lit and PY_LIT_END.match(src, lit.end()) and not _no_secret(last[-1], _str_value(lit), own):
                    add(i, "signing", _str_value(lit), "MEDIUM" if own else "LOW")
            continue
        for m in SECRET_CAND.finditer(src):
            kind = secret_name(m.group("name"))
            if kind is None:
                continue
            around = "\n".join(lines[max(0, i - 7):i - 1]) + "\n" + src[:m.start()]
            in_call = bool(SIGNING_CALL.search(around))
            lit = string.match(src, m.end())
            if lit:
                value = _str_value(lit)
                if src[lit.end():].lstrip()[:1] == "+" or _no_secret(m.group("name"), value, in_call):
                    continue
                if kind == "password":
                    if CONNECTION.search("\n".join(lines[max(0, i - 7):i + 6])):
                        add(i, "password", value, "LOW")
                else:
                    add(i, "signing", value, "MEDIUM" if in_call else "LOW")
            elif kind == "signing":
                d = JS_DEFAULT_HEAD.match(src, m.end())
                if d and not _no_secret(m.group("name"), _str_value(d), True):
                    add(i, "default", _str_value(d), "LOW")
    # 3. a setting whose own name says it is a secret, read with text for when it is missing
    for m in (PY_DEFAULT if py else JS_ENV_DEFAULT).finditer(text) if (py or js) else ():
        setting = (m.group(1) or m.group(2) or "")
        value = _str_value(m, 3)
        if secret_name(setting) == "signing" and not _no_secret(setting, value, True):
            add(_line_of(text, m.start()), "default", value, "LOW")
    # 4. a database address with the password in it (not one on this computer: a host with a dot)
    for m in DB_ADDRESS.finditer(text):
        if "." in m.group(3) and not m.group(3).startswith("127.") and not NOT_A_PASSWORD.search(m.group(2)):
            add(_line_of(text, m.start()), "address", m.group(2), "MEDIUM")
    return found


def _redacted(src: str, value: str) -> str:
    """The line with the secret's text taken out: where it stands as a whole string, or between `:` and `@` in an
    address; the whole line is withheld when neither is found."""
    out = re.sub(r"(['\"`])" + re.escape(value) + r"\1", r"\1[redacted]\1", src)
    if out == src:
        out = src.replace(":" + value + "@", ":[redacted]@")
    return out.strip() if out != src else "[redacted]"


def _texts_named(rel: str, text: str, key: str, py: bool, span: tuple | None = None) -> list[tuple]:
    """(file, line, kind, the text) for each line of `text` that gives the name `key` a text of its own (or a text
    for when a setting is missing): `key: '…'`, `exports.key = '…'`, `export const key = '…'`, Python's `KEY = '…'`
    at the top or in a class. Inside `span` only, when one is given (the object a name of the file stands for)."""
    k = re.escape(key)
    if py:
        rx = re.compile(r"(?m)^[ \t]*" + k + r"\s*(?::\s*str\s*)?=(?!=)\s*")
    else:
        rx = re.compile(r"(?<![\w$.])(?:(?:module\.)?exports\.|(?:export\s+)?(?:const|let|var)\s+)?"
                        r"(?P<q>[\"']?)" + k + r"(?P=q)\s*(?::\s*string\s*(?==))?\s*[:=](?![=>])\s*")
    string = re.compile(PY_STR if py else JS_STR)
    out = []
    for m in rx.finditer(text, *(span or ())):
        start = text.rfind("\n", 0, m.start()) + 1
        if text[start:m.start()].lstrip().startswith("#" if py else ("//", "*", "/*")):
            continue
        end = text.find("\n", m.end())
        rest = text[m.end():end if end >= 0 else len(text)]
        lit = string.match(rest)
        dflt = PY_DEFAULT.match(rest) if py else JS_DEFAULT_HEAD.match(rest)
        if lit and (PY_LIT_END.match(rest, lit.end()) if py else rest[lit.end():].lstrip()[:1] != "+") and \
                not _no_secret(key, _str_value(lit), True):
            out.append((rel, _line_of(text, m.start()), "signing", _str_value(lit)))
        elif dflt and not _no_secret(key, _str_value(dflt, 3 if py else 1), True):
            out.append((rel, _line_of(text, m.start()), "default", _str_value(dflt, 3 if py else 1)))
    return out if len(out) <= FOLLOW_MOST else []


def _project_file(repo: Path, candidates) -> tuple[str, str] | None:
    """The first of `candidates` that is a file of the project Lantern reads: (path from the root, text)."""
    root = repo.resolve()
    for c in candidates:
        try:
            p = Path(os.path.normpath(c))
            parts = p.relative_to(root).parts
        except ValueError:
            continue
        if skipped(parts[:-1], root) or not p.is_file() or not inside_repo(p, repo):
            continue
        return p.relative_to(root).as_posix(), _read(p, repo)
    return None


def _js_where(repo: Path, rel: str, text: str, ref: str) -> list[tuple]:
    """Where a name handed to a signing call gets its text: `PHRASE` and `settings.phrase` of this file, or the file
    of the project the name was loaded from (`const config = require('./config')`, `import { phrase } from …`)."""
    head, *rest = ref.split(".")
    h = re.escape(head)
    if not rest:
        got = _texts_named(rel, text, head, False)
        got = [g for g in got if re.match(r"\s*(?:export\s+)?(?:const|let|var)\s", text.splitlines()[g[1] - 1])]
        if got:
            return got
    else:
        m = re.search(r"(?m)^\s*(?:export\s+)?(?:const|let|var)\s+" + h + r"\s*(?::[^=\n]+)?=\s*\{", text)
        if m:
            inside = _args_at(text, m.end())
            return _texts_named(rel, text, rest[-1], False, (m.end(), inside[-1][0] + len(inside[-1][1]))) \
                if inside else []
    key = rest[-1] if rest else None
    spec = None
    m = re.search(r"(?:const|let|var)\s+" + h + r"\s*=\s*require\(\s*[\"']([^\"']+)[\"']\s*\)", text) or \
        re.search(r"import\s+(?:\*\s+as\s+)?" + h + r"\s+from\s*[\"']([^\"']+)[\"']", text)
    if m:
        spec = m.group(1)
    else:
        for m in re.finditer(r"(?:(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*[\"']([^\"']+)[\"']\s*\)|"
                             r"import\s*(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*[\"']([^\"']+)[\"'])", text):
            names, where = (m.group(1), m.group(2)) if m.group(1) is not None else (m.group(3), m.group(4))
            for part in names.split(","):
                bits = [b.strip() for b in re.split(r"\s+as\s+|\s*:\s*", part.strip())]
                was, now = bits[0], bits[-1]
                if now == head:
                    spec, key = where, key or was
    if spec is None or key is None or not spec.startswith("."):
        return []
    base = str((repo.resolve() / rel).parent / spec)
    ends = [base + e for e in JS_FILE_ENDS] + ([base[:-3] + ".ts"] if base.endswith(".js") else [])
    other = _project_file(repo, ends)
    return _texts_named(other[0], other[1], key, False) if other else []


def _py_where(repo: Path, rel: str, text: str, ref: str) -> list[tuple]:
    """The same for Python: `PHRASE` of this file, `config.PHRASE` of a module or `Live.PHRASE` of a class the file
    imports from the project."""
    head, *rest = ref.split(".")
    key = rest[-1] if rest else head
    if not rest:
        got = [g for g in _texts_named(rel, text, head, True) if not text.splitlines()[g[1] - 1][:1].isspace()]
        if got:
            return got
    elif re.search(r"(?m)^class\s+" + re.escape(head) + r"\b", text):
        return _texts_named(rel, text, key, True)
    here = (repo.resolve() / rel).parent
    modules: list[tuple[int, str]] = []         # (dots, dotted name) of the files the name may stand for
    for m in re.finditer(r"(?m)^[ \t]*import\s+([^\n#]+)", text):
        for part in m.group(1).split(","):
            bits = part.split()
            if bits and (bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0]) == head and rest:
                modules.append((0, bits[0]))
    for m in re.finditer(r"(?m)^[ \t]*from\s+(\.*)([\w.]*)\s+import\s+(\([^)]*\)|[^\n#]+)", text):
        for part in m.group(3).strip("()").split(","):
            bits = part.split()
            if not bits or (bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0]) != head:
                continue
            base = m.group(2)
            if rest:        # `from . import config` (a module) or `from .settings import Live` (a class in one)
                modules.append((len(m.group(1)), (base + "." if base else "") + bits[0]))
            if base or not rest:
                modules.append((len(m.group(1)), base))
            key = key if rest else bits[0]
    for dots, name in modules:
        path = name.replace(".", "/")
        if dots:
            starts = [here.parents[dots - 2] if dots > 1 else here]
        else:
            starts = [repo.resolve(), here, *[p for p in here.parents if repo.resolve() in (p, *p.parents)]]
        tails = (path + ".py", path + "/__init__.py") if path else ("__init__.py",)
        other = _project_file(repo, [str(s / t) for s in starts for t in tails])
        if other:
            got = _texts_named(other[0], other[1], key, True)
            if got:
                return got
    return []


def _followed(repo: Path, rel: str, text: str, js: bool) -> list[tuple]:
    """A secret under a plain name: the names handed to the calls that sign (`session({ secret: config.phrase })`,
    `jwt.sign(data, PHRASE)`, `app.secret_key = config.PHRASE`), each followed to the line that gives it its text."""
    refs: list[str] = []
    for rx, at in (JS_KEY_CALLS if js else PY_KEY_CALLS):
        for m in rx.finditer(text):
            args = _args_at(text, m.end())
            if len(args) > at and re.fullmatch(JS_REF if js else PY_REF, args[at][1].strip()):
                refs.append(args[at][1].strip())
    if js:
        lines = text.splitlines()
        for i, src in enumerate(lines, 1):
            if not SECRET_WORTH_A_LOOK.search(src):
                continue
            for m in SECRET_CAND.finditer(src):
                ref = JS_REF_END.match(src, m.end())
                if ref and secret_name(m.group("name")) == "signing" and \
                        SIGNING_CALL.search("\n".join(lines[max(0, i - 7):i - 1]) + "\n" + src[:m.start()]):
                    refs.append(ref.group(1))
    else:
        refs += [m.group(1) for m in PY_SIGNED_WITH.finditer(text)]
    out: list[tuple] = []
    for ref in dict.fromkeys(refs):
        if ref.split(".")[0] not in NOT_A_SETTING:
            out += (_js_where if js else _py_where)(repo, rel, text, ref)
    return out


def inline_secrets(repo: Path) -> list[dict]:
    """LW-SECRET-INLINE: one finding per line, ranked medium, the text itself never repeated in the finding."""
    found: dict[tuple, tuple] = {}          # (file, line) -> (kind, the text, confidence)
    texts: dict[str, str] = {}
    for p in _files(repo, JS_EXTS | {".py", ".json"}):
        rel = p.relative_to(repo).as_posix()
        if (p.suffix == ".json" and not SECRET_JSON.search(rel)) or SECRET_NOT_CODE.search(rel):
            continue
        text = _read(p, repo)
        if not SECRET_FILE_WORTH_A_LOOK.search(text):
            continue
        texts[rel] = text
        js, py = p.suffix in JS_EXTS, p.suffix == ".py"
        for ln, got in _secrets_in(text, js, py).items():
            found[(rel, ln)] = got
        if js or py:
            for rel2, ln, kind, value in _followed(repo, rel, text, js):
                if not SECRET_NOT_CODE.search(rel2):
                    found.setdefault((rel2, ln), (kind, value, "LOW"))
    out = []
    for (rel, ln), (kind, value, conf) in sorted(found.items()):
        if rel not in texts:
            texts[rel] = _read(repo / rel, repo)
        lines = texts[rel].splitlines()
        f = _finding("LW-SECRET-INLINE", SECRET_TITLES[kind], "HIGH" if kind == "signing" else "MEDIUM", rel, ln,
                     conf=conf, cwe=798, snippet=_redacted(lines[ln - 1] if ln <= len(lines) else "", value),
                     fixed_rank="medium")
        f["secret_kind"] = kind
        out.append(f)
    return out


def template_rules(repo: Path) -> list[dict]:
    """A page template that prints a value without escaping it (LW-XSS-RAW): EJS `<%- x %>`, Handlebars `{{{x}}}`,
    Pug `!{x}` / `!=`, Jinja, Django, Nunjucks and Twig `{{ x|safe }}` (`lantern/templates.py`). A pattern match on
    the template's text, so `tool_confidence` LOW and ranked medium whatever reaches it; `flowscan.run` then ranks
    each place by what the code that shows the page hands it (request data followed there, fixed text, not known)."""
    from . import templates
    out = []
    for rel, raws in templates.index(repo).items():
        seen = set()
        for r in raws:
            if r.line in seen:
                continue
            seen.add(r.line)
            way = r.way.strip("`")
            out.append(_finding("LW-XSS-RAW", f"Prints a value into the page without escaping it ({way}); let the "
                                "template escape it unless the app made that HTML itself", "MEDIUM", rel, r.line,
                                conf="LOW", cwe=79, snippet=r.shown, fixed_rank="medium"))
    return out


def scan_web(g: Graph) -> tuple[list[dict], list[dict]]:
    repo = Path(g.repo_root)
    findings = js_rules(repo) + go_rules(repo) + rust_rules(repo) + java_rules(repo) + php_rules(repo) + ruby_rules(repo) + cpp_rules(repo) + template_rules(repo) + inline_secrets(repo) + exposed_secrets(repo) + cors(repo) + database_rules(repo) + missing_auth(g)
    has_js = "typescript/javascript" in g.meta.get("languages", {})
    tools = [{"tool": "lantern-web", "status": "ok" + ("" if has_js else " (no JS/TS files; Python-side checks only)"),
              "version": "0.1"}]
    from . import android
    af, mobile = android.scan(g)
    seen = {(f["file"], f["line"]) for f in findings if f["rule"] in ("LV-SQL-CONCAT", "LJ-SQL-CONCAT")}
    findings += [f for f in af if not (f["rule"] == "LM-SQL-CONCAT" and (f["file"], f["line"]) in seen)]
    if mobile:
        g.meta["mobile"] = mobile
        n = len(mobile["modules"])
        tools.append({"tool": "lantern-android", "status": f"ok ({n} app module{'s' if n != 1 else ''})", "version": "0.1"})
    from . import flutter, ios
    findings += flutter.scan(g)
    if g.meta.get("flutter"):
        tools.append({"tool": "lantern-flutter", "status": "ok", "version": "0.1"})
    from . import dotnet
    findings += dotnet.scan(g)
    if "c#" in g.meta.get("languages", {}):
        tools.append({"tool": "lantern-dotnet", "status": "ok" + (" (MAUI app)" if g.meta.get("maui") else ""),
                      "version": "0.1"})
    from . import rn
    rnf, rmobile = rn.scan(g)
    findings += rnf
    if rmobile:
        tools.append({"tool": "lantern-react-native", "status": "ok", "version": "0.1"})
    inf, imobile = ios.scan(g)
    findings += inf
    if imobile:
        n = len(imobile["modules"])
        tools.append({"tool": "lantern-ios", "status": f"ok ({n} app{'s' if n != 1 else ''})", "version": "0.1"})
        if mobile:   # Android and iOS apps in one repository: one card per app, Android's platform name kept
            mobile["modules"] += [dict(m, platform="ios") for m in imobile["modules"]]
        else:
            g.meta["mobile"] = imobile
    if rmobile:
        if g.meta.get("mobile"):
            g.meta["mobile"]["modules"] += [dict(m, platform="react-native") for m in rmobile["modules"]]
        else:
            g.meta["mobile"] = rmobile
    return findings, tools
