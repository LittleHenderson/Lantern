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
  LG-*               Go code patterns (SQL and shell built from variables, TLS off, weak hashes, unsafe)
  LR-*               Rust code patterns (format! into SQL or a shell command, TLS off, weak hashes, unsafe blocks)
  LH-*               PHP code patterns (SQL/shell/eval from variables, include from input, unserialize, echo of
                     request data, Blade {!! !!}, MD5 passwords, TLS off, extract($_GET), CORS *, display_errors)
  LC-*               C# code patterns (dotnet.py: SQL/shell from variables, TLS off, weak hashes, BinaryFormatter, CORS *)
  LV-*               Java code patterns (SQL/shell from variables, TLS off, weak hashes, ObjectInputStream, CORS *)
"""

from __future__ import annotations

import hashlib
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
        text = _read(p)
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
        text = _read(p)
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
        text = _read(p)
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
        text = _read(p)
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


def segments(ident: str) -> str:
    """A name as whole lower-case words: `getServerSession` -> "get server session", `load_permissions` ->
    "load permissions", `OAuth2PasswordBearer` -> "o auth 2 password bearer", `tokenize` -> "tokenize"."""
    parts = []
    for chunk in re.split(r"[^A-Za-z0-9]+", ident):
        parts += re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", chunk)
    return " ".join(p.lower() for p in parts)


def auth_word(ident: str, js: bool = False) -> str | None:
    """The auth words `ident` is built from, matched as whole segments, or None: `get_token` -> "token", `tokenize`
    -> None, `load_permissions` -> None (plural: a list of permissions, not a check), `has_permission` -> a match."""
    words = segments(ident)
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


def signature_sign(signature: str) -> str | None:
    """A parameter that brings the caller in: a dependency or type named like an auth check (`Depends(current_user)`,
    `user: CurrentUser`, `Security(...)`), or a name that can only mean the caller (`current_user`). A parameter
    merely named like an auth word (`permissions: list[str]`, `is_admin: bool`) is data the caller sent."""
    for name, annotation, default in _params(signature):
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


def route_auth_sign(g: Graph, n, adj: dict[str, list[str]], depth: int = 3) -> str | None:
    """The first visible sign that this route checks who is calling: a decorator, a parameter or dependency in
    its signature, or a function named like an auth check within `depth` calls. None when nothing was found."""
    js = n.id.startswith(("js:", "go:", "jv:", "kt:", "sw:", "dt:", "cs:", "php:"))   # JS, Go, Java, Kotlin, Swift, Dart, C#: camelCase; Python and Rust snake_case
    for d in n.decorators:
        # a route decorator's description of its answer (`response_model=TokenResponse`, `tags=["auth"]`) says what
        # the route returns, not that it checks the caller
        d_check = ROUTE_DOC_KWARGS.sub("", d)
        if auth_ident(d_check, js):
            return f"decorator @{d.split('(')[0]}"
    sig = signature_sign(n.signature or "")
    if sig:
        return sig
    seen, frontier = {n.id}, [n.id]
    for _ in range(depth):
        nxt = []
        for u in frontier:
            for v in adj.get(u, []):
                if v in seen:
                    continue
                seen.add(v)
                if auth_word(_func_name(g, v), v.startswith(("js:", "go:", "jv:", "kt:", "sw:", "dt:", "cs:", "php:"))):
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
    return body_auth_sign(text, n.start_line or 0, n.end_line or n.start_line or 0, js=not n.file.endswith((".py", ".rb")),
                          signature=n.signature or "")


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
                "auth, login_required, token, permission...) and read the handler's own lines for the same words. ")
        if sign:
            more += (f"The only sign in the handler is that {sign[1]}: that finds a record, not the caller. "
                     "Check the signed-in user as well. ")
        out.append(_finding(
            "LW-AUTH-MISSING", f"{n.entry['detail']} changes data, is called by the app, and no login check was found",
            "MEDIUM", n.file, n.start_line, category="code", conf="LOW", cwe=306, fixed_rank="medium",
            more=more + "If this route is meant to be public, ignore it.", snippet=detail or ""))
    return out


def scan_web(g: Graph) -> tuple[list[dict], list[dict]]:
    repo = Path(g.repo_root)
    findings = js_rules(repo) + go_rules(repo) + rust_rules(repo) + java_rules(repo) + php_rules(repo) + ruby_rules(repo) + cpp_rules(repo) + exposed_secrets(repo) + cors(repo) + database_rules(repo) + missing_auth(g)
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
