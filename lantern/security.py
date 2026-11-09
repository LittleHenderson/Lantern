"""Security stage: deterministic scanners find issues; the call graph ranks them by reachability.

Models never create or close findings. They only explain them later (see explain.py).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import deque
from pathlib import Path

from . import context, lanes
from .graph import Graph
from .python_frontend import SKIP_DIRS, inside_repo

UNTRUSTED_ENTRY_KINDS = {"route", "cli", "main", "script"}

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b")),
]
SECRET_EXTS = {".py", ".env", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".txt", ".sh",
               ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html",
               ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".php", ".tf", ".properties", ".xml"}
SECRET_SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock", "uv.lock"}


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).hexdigest()[:12]


# ---------------------------------------------------------------------------- scanners

def run_bandit(repo: Path) -> tuple[list[dict], dict]:
    import importlib.util
    if importlib.util.find_spec("bandit") is None:
        return [], {"tool": "bandit", "status": 'skipped: not installed (pip install "lantern[scan]")', "version": "-"}
    excl = ",".join(str(repo / d) for d in SKIP_DIRS if (repo / d).exists())
    cmd = [sys.executable, "-m", "bandit", "-r", str(repo), "-f", "json", "-q", "--exit-zero"]
    if excl:
        cmd += ["-x", excl]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return [], {"tool": "bandit", "status": f"error: {exc}"}
    out = []
    for r in data.get("results", []):
        rel = Path(r["filename"]).resolve().relative_to(repo).as_posix()
        out.append({
            "id": _fid("bandit", r["test_id"], rel, r["line_number"]),
            "tool": "bandit", "rule": r["test_id"], "title": r["issue_text"],
            "tool_severity": r["issue_severity"], "tool_confidence": r["issue_confidence"],
            "file": rel, "line": r["line_number"],
            "cwe": (r.get("issue_cwe") or {}).get("id"), "more_info": r.get("more_info"),
            "snippet": (r.get("code") or "").strip()[:400], "category": "code",
        })
    version = _tool_version([sys.executable, "-m", "bandit", "--version"])
    return out, {"tool": "bandit", "status": "ok", "version": version}


def run_secrets(repo: Path) -> tuple[list[dict], dict]:
    """gitleaks when installed; otherwise a small built-in pattern scan."""
    if shutil.which("gitleaks"):
        try:
            proc = subprocess.run(
                ["gitleaks", "detect", "--no-git", "-s", str(repo), "-f", "json", "-r", "/dev/stdout",
                 "--exit-code", "0"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
            rows = json.loads(proc.stdout or "[]")
            out = [{
                "id": _fid("gitleaks", r["RuleID"], r["File"], r["StartLine"]),
                "tool": "gitleaks", "rule": r["RuleID"], "title": f"Possible secret: {r['Description']}",
                "tool_severity": "HIGH", "tool_confidence": "MEDIUM",
                "file": Path(r["File"]).resolve().relative_to(repo).as_posix(), "line": r["StartLine"],
                "snippet": "[redacted]", "category": "secret",
            } for r in rows]
            return out, {"tool": "gitleaks", "status": "ok"}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, ValueError):
            pass  # fall through to the built-in patterns below
    out = []
    for p in repo.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(repo).parts[:-1]) \
                or not inside_repo(p, repo):
            continue
        if p.suffix not in SECRET_EXTS and not p.name.startswith(".env"):
            continue
        if p.name in SECRET_SKIP_FILES or p.name.endswith((".min.js", ".map")):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for rule, rx in SECRET_PATTERNS:
                if rx.search(line):
                    rel = p.relative_to(repo).as_posix()
                    out.append({
                        "id": _fid("secrets", rule, rel, i), "tool": "lantern-secrets", "rule": rule,
                        "title": f"Possible secret ({rule})", "tool_severity": "HIGH",
                        "tool_confidence": "MEDIUM", "file": rel, "line": i,
                        "snippet": "[redacted]", "category": "secret",
                    })
    return out, {"tool": "lantern-secrets", "status": "ok (built-in patterns; install gitleaks for full coverage)"}


def _tool_version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30).stdout
        m = re.search(r"\d+\.\d+(\.\d+)?", out)
        return m.group(0) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------------------- graph link

REQUEST_DATA = re.compile(r"\b(request|req)\.(args|form|json|body|query|params|values|files|data|cookies|headers|"
                          r"get_json|path_params|query_params|POST|GET|FILES|META)\b|\bsearchParams\b|\bformData\b|"
                          r"\bsys\.argv\b|\binput\(|\bevent\[|\bctx\.(query|params|request)\b|"
                          # Go: net/http, gin, echo, fiber, chi
                          r"\b[rc]\.(PathValue|FormValue|PostFormValue|Body|Header|Cookie|Param|Params|Query|QueryParam|"
                          r"PostForm|BindJSON|ShouldBind\w*|Bind|GetHeader|FormFile|URL\.Query)\b|\bchi\.URLParam\(|"
                          # Java: servlet / Spring
                          r"\.(getParameter|getParameterMap|getHeader|getInputStream|getReader|getCookies|getQueryString|"
                          r"getPathInfo|getRequestURI)\(|"
                          # Android: data another app or a link put into an Intent
                          r"\bget(?:String|Int|Long|Boolean|Bundle|Parcelable|Serializable|CharSequence)(?:Array)?(?:List)?Extra\(|"
                          r"\bgetQueryParameter\(|\bgetIntent\(\)\.(?:getData|getExtras|getDataString)\(|\bintent\.(?:data|extras|dataString)\b"
                          # iOS: what a link carries (ios.py)
                          r"|\.queryItems\b|\bURLComponents\s*\(\s*(?:url|string):|\buserActivity\.webpageURL\b|"
                          r"\burl\.(?:query|path|host|absoluteString|pathComponents|fragment)\b"
                          # Vapor (Swift servers)
                          r"|\breq\.(?:parameters|query|content|headers|body)\b"
                          # Flutter: what a link or a route carries
                          r"|\.(?:queryParameters|pathParameters|queryParametersAll)\b|\bgetInitial(?:Link|Uri|AppLink)\s*\("
                          # React Native / Expo: what a link or a navigation carries
                          r"|\broute\.params\b|\buse(?:Local|Global)SearchParams\s*\(|\bLinking\.parse\s*\("
                          # C#: ASP.NET request data, what a link (`Uri`) or an Android intent carries (MAUI, Xamarin)
                          r"|\bRequest\.(?:Query|Form|Headers|Cookies|RouteValues|Body|QueryString)\b"
                          r"|\b(?:uri|url|link|appLink)\.(?:Query|AbsolutePath|AbsoluteUri|Segments|Fragment|Host|OriginalString)\b"
                          r"|\bHttpUtility\.ParseQueryString\s*\(|\bIntent\.(?:Data|DataString|Extras)\b|\bIntent\.Get\w*Extra\s*\("
                          # PHP: superglobals, Laravel's request, PSR-7 (Slim) requests ($ and -> may be read as . )
                          r"|\b_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\brequest(?:->|\.)(?:input|get|query|post|all|only|"
                          r"file|cookie|header|json|route|string|integer|boolean)\s*\(|\brequest\(\s*['\"]|"
                          r"(?:->|\.)(?:getParsedBody|getQueryParams|getUploadedFiles|getCookieParams)\s*\("
                          r"|\bfile_get_contents\(\s*['\"]php://input")
# Ruby (Rails, Sinatra): `params[:q]`, `params.require(...)`, the raw request, cookies. Only for `.rb` files: a bare
# `params` in JS is usually a router's own value.
RUBY_REQUEST_DATA = re.compile(REQUEST_DATA.pattern + r"|\bparams\b(?:\[[^\]\n]*\])?(?!\s*=[^=])|\brequest\.(?:body|raw_post|headers|"
                               r"query_string|query_parameters|request_parameters|params|env|fullpath|url)\b|"
                               r"\bcookies\s*\[|\bARGV\b|\bgets\b")
# C/C++: program arguments, the environment, what arrives on a socket or stdin, and the request objects of cpp-httplib,
# Crow, Drogon and Pistache.
C_EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp")
C_REQUEST_DATA = re.compile(REQUEST_DATA.pattern + r"|\bargv\s*\[\s*\w*\s*\]|\bgetenv\s*\(|\b(?:recv|recvfrom|fgets|gets)\s*\(|"
                            r"\bgetline\s*\(\s*(?:std::)?cin\b|\bstd::cin\b|\bscanf\s*\(|\breq(?:uest)?(?:\.|->)(?:get_param_value|get_header_value|"
                            r"get_file_value|body|params|path_params|url_params|matches|getParameter|getBody|getJsonObject|"
                            r"getHeader|query|param|resource)\b|\breq->getParameter\b")
# `x = ...`, `const {a, b} = ...`, `x: T = ...`, `x += ...`, `self.x = ...`, `a, b = ...`
ASSIGN = re.compile(r"^\s*(?:(?:const|let|var|val)\s+)?(?P<lhs>[A-Za-z_$][\w$.]*(?:\s*,\s*[A-Za-z_$][\w$.]*)*|"
                    r"\[[^\]=]*\]|\{[^}=]*\})\s*(?::\s*[^=]+?)?\s*(?P<op>[-+*/%&|^]|\*\*|//|\?\?|&&|\|\|)?=(?!=)\s*(?P<rhs>.+)$",
                    re.S)
BINDS = [   # loops and context managers that bind a name to a value
    re.compile(r"^\s*(?:async\s+)?for\s+(?P<lhs>[\w., ]+?)\s+in\s+(?P<rhs>.+?):", re.S),
    re.compile(r"^\s*(?:async\s+)?with\s+(?P<rhs>.+?)\s+as\s+(?P<lhs>\w+)\s*:", re.S),
    re.compile(r"^\s*for\s*\(\s*(?:const|let|var)\s+(?P<lhs>[\w{}\[\], $]+?)\s+(?:of|in)\s+(?P<rhs>[^)]+)\)", re.S),
]
_STRINGS = re.compile(r"(['\"`])(?:\\.|(?!\1).)*\1")
_TEMPLATE_REF = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*)|\$([A-Za-z_]\w*)|\\\(\s*([A-Za-z_]\w*)|#\{\s*@?([A-Za-z_]\w*)")


def _blank_string(m: re.Match) -> str:
    """A string literal becomes `''`, keeping the names a template puts into it (`"id = $id"` in Kotlin, `\\(id)` in Swift,
    `${id}` in a JS template literal, `$"…{id}"` in C#) so a value spliced into SQL or a command is still seen as used."""
    refs = [a or b or c or d for a, b, c, d in _TEMPLATE_REF.findall(m.group(0))]
    head = m.string[max(0, m.start() - 2):m.start()]
    if "$" in head:   # C# `$"… {id}"`
        refs += re.findall(r"(?<!\{)\{\s*([A-Za-z_]\w*)", m.group(0))
    return "''" + "".join(f" + {r}" for r in refs)


def _php_line(raw: str) -> str:
    """A PHP line in the shape the input check reads: strings blanked (keeping `$x` and `{$x}` put into double-quoted
    ones), `.` concatenation read as `+`, `->` as `.`, and `$` dropped from variable names."""
    def blank(m: re.Match) -> str:
        if m.group(1) == "'":
            return "''"
        return "''" + "".join(f" + {r}" for r in re.findall(r"\{?\$([A-Za-z_]\w*)", m.group(0)))
    t = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", blank, raw)
    t = t.replace(".=", "+=")
    t = re.sub(r"(?<=[\w'\")\]])\s*\.(?!\.)\s*(?=[$\w'\"(])", " + ", t)
    t = t.replace("->", ".").replace("?.", ".")
    return re.sub(r"\$(?=[A-Za-z_])", "", t)


def _rb_line(raw: str) -> str:
    """A Ruby line for the input check: `@x` read as `x` (instance variables carry values between lines of a controller
    action), `%x(...)`/`%Q(...)` read as strings."""
    t = re.sub(r"%[xQqw]?\((.*?)\)", lambda m: '"' + m.group(1).replace('"', "'") + '"', raw)
    return re.sub(r"(?<![\w@])@(?=[A-Za-z_])", "", t)


_C_DECL = re.compile(r"^(\s*)(?:(?:const|static|unsigned|signed|auto|struct|volatile|register)\s+)*[A-Za-z_][\w:]*"
                     r"(?:<[^;=()]*>)?(?:\s+const)?[\s*&]+(?=[A-Za-z_]\w*\s*(?:\[[^\]]*\]\s*)?=)")
_C_FILL = re.compile(r"^(\s*)(?:std::)?(sn?printf|strn?cpy|strn?cat|memcpy|asprintf)\s*\(\s*&?([A-Za-z_]\w*)\s*,(.*)\)\s*;")


def _c_line(raw: str) -> str:
    """A C/C++ line for the input check: a declaration `std::string q = …` read as `q = …`, and a buffer filled by
    `sprintf(buf, …, x)` / `strcpy(buf, x)` read as `buf = … x` (`strcat` as `buf += x`)."""
    t = _C_DECL.sub(r"\1", raw)
    m = _C_FILL.match(t)
    if m:
        op = "+=" if "cat" in m.group(2) else "="
        t = f"{m.group(1)}{m.group(3)} {op} {m.group(4)};"
    return t


def _statements(lines: list[str], first: int, last: int, js: bool) -> list[tuple[int, int, str]]:
    """Lines first..last (1-based, inclusive) grouped into statements: a line with open brackets takes the
    following lines until they balance (at most 12). Comments and string contents are dropped. In JS a line that
    ends by opening a block (`app.post('/x', (req, res) => {`) ends its statement there, so a callback's body is
    read line by line rather than as one giant call."""
    out, buf, start, depth = [], [], 0, 0
    for ln in range(first, min(last, len(lines)) + 1):
        raw = lines[ln - 1]
        code = _STRINGS.sub(_blank_string, raw)
        code = re.sub(r"//.*$" if js else r"#.*$", "", code)
        if not buf:
            start = ln
        buf.append(code)
        depth += code.count("(") + code.count("[") + code.count("{") - code.count(")") - code.count("]") - code.count("}")
        if depth <= 0 or len(buf) >= 12 or (js and code.rstrip().endswith("{")):
            out.append((start, ln, " ".join(x.strip() for x in buf)))
            buf, depth = [], 0
    if buf:
        out.append((start, min(last, len(lines)), " ".join(x.strip() for x in buf)))
    return out


def _names(lhs: str) -> list[str]:
    """Names bound by an assignment target: `a`, `a, b`, `[a, b]`, `{a, b: c}`, `self.x`."""
    out = []
    for part in re.split(r"[,\s]+", lhs.strip("[]{} ")):
        part = part.strip().lstrip(".")
        if ":" in part:
            part = part.split(":", 1)[1].strip()   # {key: alias}
        if re.fullmatch(r"[A-Za-z_$][\w$.]*", part):
            out.append(part)
    return out


def _uses(name: str, text: str) -> bool:
    return re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", text) is not None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _input_on_line(g: Graph, f: dict, cache: dict[str, list[str]]) -> dict | False:
    """Does the flagged line use something a caller controls: a parameter, request data, or a local variable
    that was set from either earlier in the same function? Assignments are followed in order inside the function
    only (not across functions, branches, or loops), so it can say yes for a parameter that is in fact always a
    constant, and it says no for input that arrives through another function's return value. A plain `name = ...`
    with nothing tainted on its right clears the name again, but only at the same block level as the line that
    tainted it (or the function body for a parameter): `if not cmd: cmd = "ls"` is a default, not a reset."""
    n = g.nodes.get(f.get("node") or "")
    if not n or not f.get("line") or not n.start_line:
        return False
    if f["file"] not in cache:
        try:
            cache[f["file"]] = (Path(g.repo_root) / f["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[f["file"]] = []
    src = cache[f["file"]]
    show = (lambda x: x)
    if f["file"].endswith(".php"):
        src = [_php_line(x) for x in src]
        show = (lambda x: re.sub(r"^(request|_[A-Z]+)\b", r"$\1", x).replace(".", "->"))   # back to PHP spelling
    req_re = C_REQUEST_DATA if f["file"].endswith(C_EXTS) else REQUEST_DATA
    if f["file"].endswith(C_EXTS):
        src = [_c_line(x) for x in src]
    if f["file"].endswith(".rb"):
        src = [_rb_line(x) for x in src]
        req_re = RUBY_REQUEST_DATA
    line = f["line"]
    if not 0 < line <= len(src):
        return False
    js = not f["file"].endswith((".py", ".rb"))
    sig = n.signature or ""
    if f["file"].endswith(".go"):
        sig = re.sub(r"^func\s*\([^)]*\)\s*", "func ", sig)      # the receiver is not input
    plist = sig[sig.find("("):] if "(" in sig else ""
    if f["file"].endswith(".rs"):
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        params = []
        for piece in re.split(r",(?![^<(]*[>)])", inner):
            pat = piece.split(":", 1)[0].strip().replace("&", "").replace("mut ", "").strip()
            m = re.fullmatch(r"\w+\((\w+)\)", pat)             # State(state), Path(id), Json(body)
            params.append(m.group(1) if m else pat)
        params = [x for x in params if re.fullmatch(r"[A-Za-z_]\w*", x)]
    elif f["file"].endswith(".php"):
        params = re.findall(r"\$(\w+)", plist)                # `Request $request, $id` → request, id
    elif f["file"].endswith(".dart"):
        # Dart writes `Type name` (and `{required String id}`, `this.id`): the last identifier of each parameter
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", re.sub(r"@\w+(\([^)]*\))?|\brequired\b|[{}\[\]]", " ", inner))
        params = [m.group(1) for piece in inner.split(",")
                  for m in [re.search(r"([A-Za-z_$][\w$]*)\s*(?:=[^,]*)?$", piece.strip())] if m]
    elif f["file"].endswith((".kt", ".swift")):
        # Kotlin and Swift write `name: Type` (after `vararg`/`val`, an argument label, annotations): the name before
        # each top-level colon
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", re.sub(r"@\w+(\([^)]*\))?", "", inner))
        params = [m.group(1) for piece in re.split(r",(?![^(]*\))", inner)
                  for m in [re.search(r"([A-Za-z_]\w*)\s*:", piece)] if m]
    elif f["file"].endswith(C_EXTS):
        # C/C++ write `const std::string& name`, `char **argv`, `int n = 3`: the identifier before any default
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", inner)
        params = [m.group(1) for piece in inner.split(",")
                  for m in [re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:=[^,]*)?$", piece.strip())] if m]
    elif f["file"].endswith((".java", ".cs")):
        # `Type name` order: the last identifier of each parameter (annotations and generics stripped)
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", re.sub(r"@\w+(\([^)]*\))?", "", inner))
        params = [m.group(1) for piece in inner.split(",") for m in [re.search(r"([A-Za-z_$][\w$]*)\s*$", piece.strip())] if m]
    else:
        params = re.findall(r"[(,{]\s*\*{0,2}(?:\.\.\.)?([A-Za-z_$][\w$]*)", plist)
    tainted = {name: f"parameter `{name}`" for name in params if name not in ("self", "cls", "this")}
    stmts = _statements(src, n.start_line, max(n.end_line or n.start_line, line + 3), js)
    flagged = next((st for st in stmts if st[0] <= line <= st[1]), None)
    if flagged is None:
        return False
    head = _indent(src[n.start_line - 1])
    body = next((_indent(src[st[0] - 1]) for st in stmts if _indent(src[st[0] - 1]) > head), head + 1)
    level = {name: body for name in tainted}   # the block level at which each name was tainted
    for start, _end, text in stmts:
        if start >= flagged[0]:
            break
        m = ASSIGN.match(text) or next((b.match(text) for b in BINDS if b.match(text)), None)
        if not m:
            continue
        lhs, rhs = m.group("lhs"), m.group("rhs")
        req = req_re.search(rhs)
        src_name = next((t for t in tainted if _uses(t, rhs)), None)
        if req:
            origin = f"request data `{show(req.group(0))}`"
        elif src_name:
            origin = tainted[src_name]
        else:
            if "op" in m.groupdict() and not m.group("op"):
                for name in _names(lhs):   # a plain reassignment at the same level replaces the tainted value
                    if name in tainted and _indent(src[start - 1]) <= level[name]:
                        del tainted[name], level[name]
            continue
        for name in _names(lhs):
            tainted[name] = f"`{name}`, which line {start} sets from {origin}"
            level[name] = _indent(src[start - 1])
    text = flagged[2]
    m = req_re.search(text)
    if m:
        return {"via": f"request data `{show(m.group(0))}`"}
    for name, origin in tainted.items():
        if _uses(name, text):
            return {"via": origin}
    return False


def _node_at(g: Graph, file: str | None, line: int | None) -> str | None:
    if not file:
        return None
    best, best_span = None, None
    for n in g.nodes_in(file):
        if n.file != file or n.start_line is None:
            continue
        if line is None:
            if n.kind == "module":
                return n.id
            continue
        if n.start_line <= line <= (n.end_line or n.start_line):
            span = (n.end_line or n.start_line) - n.start_line
            if best_span is None or span < best_span:
                best, best_span = n.id, span
    return best


def reachability(g: Graph, include_tests: bool = False, kinds: set[str] | None = None) -> dict[str, dict]:
    """Multi-source BFS from entry points. Returns node id -> {entry, kind, path}."""
    adj: dict[str, list[str]] = {}
    for e in g.call_edges():
        adj.setdefault(e.src, []).append(e.dst)
    seen: dict[str, dict] = {}
    q: deque[str] = deque()
    entries = [n for n in g.entry_points() if (include_tests or n.entry["kind"] != "test")
               and (kinds is None or n.entry["kind"] in kinds)]
    # untrusted-input entries first so their paths win ties
    entries.sort(key=lambda n: 0 if n.entry["kind"] in UNTRUSTED_ENTRY_KINDS else 1)
    for n in entries:
        if n.id not in seen:
            seen[n.id] = {"entry": n.id, "kind": n.entry["kind"], "prev": None}
            q.append(n.id)
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen[nxt] = {"entry": seen[cur]["entry"], "kind": seen[cur]["kind"], "prev": cur}
                q.append(nxt)
    out = {}
    for nid, info in seen.items():
        path, cur = [], nid
        while cur is not None:
            path.append(cur)
            cur = seen[cur]["prev"]
        out[nid] = {"entry": info["entry"], "kind": info["kind"], "path": list(reversed(path))}
    return out


def rank(f: dict) -> str:
    """The rank from the tool's severity, reachability and input, then capped by what the code around the line shows
    (context.py: a weak hash used as an identifier, SQL that splices only fixed text). A cap is written on the finding
    as `rank_note`, with the rank it would have had as `rank_before_context`, so nothing changes silently."""
    r = _rank(f)
    cap, why = None, None
    ctx = f.get("context") or {}
    h, sql = ctx.get("hash"), ctx.get("sql")
    if h and h["purpose"] == "non-security":
        cap, why = "low", (f"The hash looks like an identifier, seed or checksum ({h['why']}), not protection for a "
                           "password, token or signature. MD5/SHA-1 are fine for that. Lantern read names, not meaning.")
    elif h and h["purpose"] == "unknown":
        cap, why = "medium", ("Lantern could not tell what this hash is for (" + h["why"] + "). It is not ranked "
                              "critical or high without evidence that it protects a password, token or signature.")
    elif sql and sql["fixed_only"]:
        cap, why = "low", ("Only fixed text is put into the SQL string (" + "; ".join(
            f"{s['expr']}: {s['why']}" for s in sql["spliced"]) + ")" + (
            ", and the values are passed to the database driver separately." if sql["driver_params"] else "."))
    if cap and RANK_ORDER[r] < RANK_ORDER[cap]:
        f["rank_before_context"] = r
        f["rank_note"] = why
        return cap
    f.pop("rank_before_context", None)
    f.pop("rank_note", None)
    return r


def _rank(f: dict) -> str:
    if f.get("fixed_rank"):
        return f["fixed_rank"]
    sev = f["tool_severity"]
    reach = f.get("reachable")
    untrusted = reach and reach["kind"] in UNTRUSTED_ENTRY_KINDS
    if f["category"] == "secret":
        return "critical"
    if f["category"] == "dependency":   # npm says how bad; pip-audit doesn't, so those stay high
        return {"moderate": "medium", "low": "low", "info": "low"}.get(str(f.get("dep_severity")), "high")
    if sev == "HIGH" and untrusted and f.get("input") is not False:
        return "critical"   # spec 9.3: high severity and touched by untrusted input (False: the line uses none)
    if (sev == "HIGH" and reach) or (sev == "MEDIUM" and untrusted):
        return "high"
    if (sev == "MEDIUM" and reach) or sev == "HIGH":
        return "medium"
    return "low"


RANK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ACCEPTED_FILE = "lantern-accepted.json"


def load_accepted(repo: Path) -> dict[str, dict]:
    """Accepted risks live in the repo (committed), each with the builder's written reason."""
    p = repo / ACCEPTED_FILE
    try:
        rows = json.loads(p.read_text(encoding="utf-8")).get("accepted", []) if p.exists() else []
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}
    return {r["id"]: r for r in rows if isinstance(r, dict) and r.get("id") and reason_ok(r.get("reason"))}


def reason_ok(reason) -> bool:
    """A real written reason: at least 10 letters/digits across two or more words, not one repeated character.
    Applies to hand-edited `lantern-accepted.json` too, so "x" can't silence --fail-on."""
    if not isinstance(reason, str):
        return False
    words = re.findall(r"[^\W_]{2,}", reason)
    chars = "".join(words)
    return len(words) >= 2 and len(chars) >= 10 and len(set(chars.lower())) >= 5


def save_accepted(repo: Path, accepted: dict[str, dict]) -> Path:
    p = repo / ACCEPTED_FILE
    rows = sorted(accepted.values(), key=lambda r: r["id"])
    p.write_text(json.dumps({"about": "Security findings the builder reviewed and accepted, with reasons. "
                                      "Managed by `lantern accept`.", "accepted": rows}, indent=1) + "\n", encoding="utf-8")
    return p


ID_VERSION = 2


def stable_ids(repo: Path, findings: list[dict]) -> None:
    """Give each finding an id that survives moving its code: tool, rule, file, and the flagged line's text with
    spaces removed, plus a counter for identical lines in one file. Lines added above a finding don't change it,
    so "fixed" means the flagged code is really gone (or changed). Findings without a line keep the scanner's id."""
    lines: dict[str, list[str]] = {}
    seen: dict[str, int] = {}
    for f in sorted(findings, key=lambda f: (f.get("file") or "", f.get("line") or 0, f.get("rule") or "")):
        if not f.get("file") or not f.get("line"):
            continue
        if f["file"] not in lines:
            try:
                lines[f["file"]] = (repo / f["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines[f["file"]] = []
        src = lines[f["file"]]
        text = re.sub(r"\s+", "", src[f["line"] - 1]) if 0 < f["line"] <= len(src) else f"line{f['line']}"
        key = "|".join(map(str, (f.get("tool"), f.get("rule"), f["file"], text)))
        seen[key] = seen.get(key, 0) + 1
        f["id"] = _fid(key, seen[key])


def scan(g: Graph, offline: bool | None = None) -> dict:
    """All scanners. `offline` skips the dependency audits, the only steps that use the network
    (None: follow LANTERN_OFFLINE)."""
    repo = Path(g.repo_root)
    findings, tools = [], []
    from .depaudit import run_composer_audit, run_gem_audit, run_maven_audit, run_npm_audit, run_pip_audit
    for fn in (run_bandit, lambda r: run_pip_audit(r, offline), lambda r: run_npm_audit(r, offline),
               lambda r: run_maven_audit(r, offline), lambda r: run_composer_audit(r, offline),
               lambda r: run_gem_audit(r, offline), run_secrets):
        f, info = fn(repo)
        findings += f
        tools.append(info)
    from .websec import scan_web
    wf, wt = scan_web(g)
    findings += wf
    tools += wt
    from .aiapp import scan_ai
    af, ai = scan_ai(g)
    findings += af
    tools.append({"tool": "lantern-ai", "status": "ok" + ("" if ai["calls"] else " (no model, vector or paid API calls found)"),
                  "version": "0.1"})
    from .packs import load_all, scan_packs, split_enabled
    loaded, skipped = load_all(repo, keep_disabled=True)
    loaded, off = split_enabled(loaded)
    if loaded:
        pf, pt = scan_packs(repo, loaded)
        findings += pf
        tools += pt
    # a pack turned off in Settings is named with its status, so the Evidence Report says it was not used
    tools += [{"tool": f"lantern-pack:{pk['pack']}", "status": "off (turned off in Settings)",
               "version": str(pk.get("version", "-"))} for pk in off]
    tools += [{"tool": where, "status": "skipped: " + why, "version": "-"} for where, why in skipped]
    stable_ids(repo, findings)
    accepted = load_accepted(repo)
    reach = reachability(g)
    ui_reach = reachability(g, kinds={"page", "main"})
    test_reach = reachability(g, include_tests=True)
    from .js_frontend import TEST_RE as JS_TEST_RE
    from .python_frontend import TEST_FILE_RE
    lines_cache: dict[str, list[str]] = {}
    py_cache: dict = {}

    def lines_for(file: str) -> list[str]:
        if file not in lines_cache:
            try:
                lines_cache[file] = (repo / file).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines_cache[file] = []
        return lines_cache[file]
    for f in findings:
        f["in_tests"] = bool(f["file"] and (TEST_FILE_RE.search(f["file"]) or JS_TEST_RE.search(f["file"])))
        pin = f.pop("pin", None)          # a manifest finding names the class it is about (android.py)
        f["node"] = (pin if pin in g.nodes else None) or _node_at(g, f["file"], f["line"])
        r = reach.get(f["node"]) if f["node"] else None
        f["reachable"] = r
        f["reachable_from_tests_only"] = bool(not r and f["node"] in test_reach)
        u = ui_reach.get(f["node"]) if f["node"] else None
        f["ui_path"] = u["path"] if u else None
        # Stack strip: the lane the problem lives on, and every lane its path crosses (lanes.py).
        node = g.nodes.get(f["node"]) if f["node"] else None
        f["hot_lane"] = (node.lane if node else None) or lanes.lane_for_file(f["file"], lanes.phone_roots(g.meta))
        data_hops = ["data"] if node and any((g.nodes.get(e.dst) and g.nodes[e.dst].lane == "data")
                                             for e in g.callees(node.id)) else []
        f["lanes"] = lanes.lanes_for_path(g, (u["path"] if u else None) or (r["path"] if r else None),
                                          f["hot_lane"], data_hops)
        f["input"] = _input_on_line(g, f, lines_cache) if f["category"] == "code" and r and \
            r["kind"] in UNTRUSTED_ENTRY_KINDS else None
        if f["category"] == "code":
            # what the flagged code is for (context.py); it can lower the rank, never remove the finding
            ctx = {}
            hp = context.hash_purpose(g, f, lines_for, py_cache)
            if hp:
                ctx["hash"] = hp
            sq = context.sql_splice(g, f, py_cache)
            if sq:
                ctx["sql"] = sq
                if sq["fixed_only"] and f["input"]:
                    # the input check reads the whole statement; for SQL only what is spliced into the text counts
                    f["input"] = False
            if ctx:
                f["context"] = ctx
        f["rank"] = "low" if f["in_tests"] and f["category"] == "code" else rank(f)
        acc = accepted.get(f["id"])
        f["status"] = "accepted" if acc else "open"
        if acc:
            f["accepted"] = {k: acc.get(k) for k in ("reason", "by", "date")}
    # Scenarios (scenarios.py): a short story of one person meeting each finding, built from the facts above only.
    from .scenarios import attach as attach_scenarios
    attach_scenarios(findings, g)
    findings.sort(key=lambda f: (f["in_tests"], RANK_ORDER[f["rank"]], f["file"] or "", f["line"] or 0))
    live =[f for f in findings if not f["in_tests"] and f["status"] == "open"]
    counts = {k: sum(1 for f in live if f["rank"] == k) for k in RANK_ORDER}
    counts["in_tests"] = sum(1 for f in findings if f["in_tests"])
    counts["accepted"] = sum(1 for f in findings if f["status"] == "accepted")
    return {"findings": findings, "tools": tools, "counts": counts, "id_version": ID_VERSION,
            "reachable_nodes": len(reach), "total_callables": sum(1 for n in g.nodes.values() if n.kind == "callable"),
            "ai": ai, "mobile": g.meta.get("mobile")}
