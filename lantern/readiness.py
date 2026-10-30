"""Deployment Readiness Score (spec section 10): ten weighted categories of deterministic checks.

Every point has a visible reason. A check is `pass`, `fail`, `partial`, or `skip` (not applicable or
not measurable here); skipped checks leave the score's denominator, so a CLI isn't docked for having no
health endpoint. Checks that rely on text patterns say so in `how`.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .depaudit import NOTHING_TO_CHECK
from .graph import Graph
from .protections import advise as advise_protections
from .python_frontend import SKIP_DIRS, TEST_FILE_RE, inside_repo

READINESS_VERSION = 1

CATEGORIES = [
    ("security", "Security findings", 20),
    ("secrets", "Secrets and config", 12),
    ("input", "Input and error handling", 10),
    ("deps", "Dependencies", 10),
    ("tests", "Tests", 10),
    ("observability", "Observability", 8),
    ("packaging", "Packaging", 8),
    ("ci", "CI/CD", 8),
    ("resilience", "Resilience", 8),
    ("docs", "Documentation", 6),
]

CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
JS_TEST_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^|/)(__tests__|tests?|e2e|cypress|playwright)/")
PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock")
JS_LOCKS = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
CI_FILES = (".gitlab-ci.yml", ".circleci/config.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml",
            ".travis.yml", "Jenkinsfile")
DEPLOY_FILES = {"vercel.json": "Vercel", "netlify.toml": "Netlify", "fly.toml": "Fly.io",
                "render.yaml": "Render", "railway.json": "Railway", "Procfile": "Heroku-style Procfile",
                "app.yaml": "Google App Engine", "docker-compose.yml": "Docker Compose",
                "docker-compose.yaml": "Docker Compose", "compose.yml": "Docker Compose",
                "compose.yaml": "Docker Compose", "serverless.yml": "Serverless Framework"}

ENV_PY = re.compile(r"""os\.(?:environ\.get|getenv)\(\s*["']([A-Z][A-Z0-9_]+)["']|os\.environ\[\s*["']([A-Z][A-Z0-9_]+)["']\]""")
ENV_JS = re.compile(r"""(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]+)|process\.env\[\s*["']([A-Z][A-Z0-9_]+)["']\]""")
BARE_EXCEPT = re.compile(r"^\s*except\s*:", re.M)
PY_HTTP = re.compile(r"\b(requests|httpx)\.(get|post|put|patch|delete|head|request)\(")
PY_HTTP_CLIENT = re.compile(r"\bhttpx\.(Async)?Client\(")
DEBUG_ON = re.compile(r"""\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True\b""")
LOGGING = re.compile(r"\bimport logging\b|\bfrom logging\b|\bstructlog\b|\bloguru\b|from ['\"](pino|winston|bunyan|@sentry/[a-z]+)['\"]|require\(['\"](pino|winston|bunyan)['\"]\)")
VALIDATION = re.compile(r"\bpydantic\b|\bfrom fastapi\b|\bmarshmallow\b|\bwtforms\b|\bvoluptuous\b|from ['\"](zod|yup|joi|valibot|class-validator|@sinclair/typebox|ajv)['\"]")
RETRY = re.compile(r"\btenacity\b|\bbackoff\b|urllib3\.util\.retry|\bRetry\(|['\"](p-retry|axios-retry|async-retry|ky)['\"]|\bretries\s*[:=]")
SHUTDOWN = re.compile(r"signal\.signal\(\s*signal\.SIGTERM|SIGTERM|lifespan|@app\.on_event\(\s*['\"]shutdown|atexit\.register")
HEALTH_PATH = re.compile(r"/(health|healthz|healthcheck|ready|readyz|livez|ping|status)\b", re.I)
TEST_CMD = re.compile(r"\b(pytest|unittest|tox|nox|npm (run )?test|pnpm (run )?test|yarn test|vitest|jest|playwright test|go test|cargo test|make test)\b")
SCAN_CMD = re.compile(r"\b(lantern|bandit|pip-audit|npm audit|pnpm audit|yarn audit|semgrep|opengrep|codeql|trivy|snyk|gitleaks|safety|osv-scanner|dependabot)\b", re.I)


# ---------------------------------------------------------------------------- repo facts

class Repo:
    """Cached, read-only view of the files that readiness checks look at."""

    def __init__(self, root: Path):
        self.root = root
        self.files: list[str] = []
        for p in root.rglob("*"):
            rel = p.relative_to(root)
            if any(x in SKIP_DIRS for x in rel.parts[:-1]) or not p.is_file() or not inside_repo(p, root):
                continue
            self.files.append(rel.as_posix())
        self.files.sort()
        # Manifests and config inside test folders (fixtures, sample apps) don't describe this project.
        self.project_files = [f for f in self.files if not self.is_test(f)]
        self._text: dict[str, str] = {}

    def has(self, *names: str) -> str | None:
        """First file whose path or basename matches one of `names` (case-insensitive)."""
        low = {f.lower(): f for f in self.project_files}
        for n in names:
            if n.lower() in low:
                return low[n.lower()]
        for n in names:
            for f in self.project_files:
                if f.lower().rsplit("/", 1)[-1] == n.lower() and f.count("/") <= 2:
                    return f
        return None

    def text(self, rel: str) -> str:
        if rel not in self._text:
            try:
                self._text[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._text[rel] = ""
        return self._text[rel]

    def code(self, tests: bool = False):
        for f in self.files:
            if Path(f).suffix not in CODE_EXTS or f.endswith((".min.js", ".d.ts")):
                continue
            if self.is_test(f) != tests:
                continue
            yield f, self.text(f)

    @staticmethod
    def is_test(f: str) -> bool:
        return bool(TEST_FILE_RE.search(f) or JS_TEST_RE.search(f) or f.rsplit("/", 1)[-1].startswith("conftest"))

    def grep(self, rx: re.Pattern, tests: bool = False, limit: int = 20) -> list[tuple[str, int, str]]:
        out = []
        for f, t in self.code(tests):
            for m in rx.finditer(t):
                line = t.count("\n", 0, m.start()) + 1
                out.append((f, line, t.splitlines()[line - 1].strip()[:160] if t else ""))
                if len(out) >= limit:
                    return out
        return out

    def env_vars(self) -> dict[str, str]:
        """Environment variable names the code reads -> first place it reads them."""
        out: dict[str, str] = {}
        for f, t in self.code():
            rx = ENV_PY if f.endswith(".py") else ENV_JS
            for m in rx.finditer(t):
                name = m.group(1) or m.group(2)
                out.setdefault(name, f"{f}:{t.count(chr(10), 0, m.start()) + 1}")
        return out


def detect_stack(repo: Repo, g: Graph) -> dict:
    deps_text = " ".join(repo.text(f) for f in repo.project_files
                         if f.rsplit("/", 1)[-1] in ("pyproject.toml", "package.json", "Pipfile")
                         or re.search(r"(^|/)requirements[^/]*\.txt$", f)).lower()
    fw = []
    for key, label in (("fastapi", "FastAPI"), ("flask", "Flask"), ("django", "Django"), ("starlette", "Starlette"),
                       ('"next"', "Next.js"), ('"react"', "React"), ('"vite"', "Vite"), ('"express"', "Express"),
                       ('"hono"', "Hono"), ('"fastify"', "Fastify"), ("@supabase/", "Supabase"),
                       ("firebase", "Firebase"), ("click", "Click"), ("typer", "Typer")):
        if key in deps_text:
            fw.append(label)
    entries = Counter((n.entry or {}).get("kind") for n in g.entry_points())
    langs = list((g.meta.get("languages") or {}).keys())
    deploy = sorted({v for k, v in DEPLOY_FILES.items() if repo.has(k)})
    return {"frameworks": fw, "entries": dict(entries), "languages": langs, "deploy_targets": deploy}


def classify_shape(stack: dict) -> str:
    e = stack["entries"]
    pages, routes = e.get("page", 0), e.get("route", 0)
    if pages and routes:
        return "full-stack web app"
    if routes:
        return "web API"
    if pages or "React" in stack["frameworks"] or "Next.js" in stack["frameworks"]:
        return "frontend web app"
    if e.get("cli") or e.get("script"):
        return "command-line tool"
    if e.get("main"):
        return "script or worker"
    return "library"


SERVICE_SHAPES = {"full-stack web app", "web API"}


# ---------------------------------------------------------------------------- checks

def _check(cid, title, points, status, evidence="", fix="", how="file check", earned=None):
    if earned is None:
        earned = {"pass": points, "partial": points / 2}.get(status, 0)
    return {"id": cid, "title": title, "points": points, "earned": round(earned, 2) if status != "skip" else 0,
            "status": status, "evidence": evidence, "fix": fix, "how": how}


def _where(hits, n=3) -> str:
    s = ", ".join(f"{f}:{ln}" for f, ln, _ in hits[:n])
    return s + (f" and {len(hits) - n} more" if len(hits) > n else "")


def check_security(sec: dict | None) -> list[dict]:
    if not sec:
        return [_check("sec-scan", "Security scan ran", 20, "fail", "No scan results (ran with --no-scan).",
                       "Run `lantern analyze` without --no-scan.")]
    open_ = [f for f in sec["findings"] if not f.get("in_tests") and f.get("status") != "accepted"]
    acc = [f for f in sec["findings"] if f.get("status") == "accepted"]
    by = Counter(f["rank"] for f in open_)
    out = []
    for rank, pts in (("critical", 10), ("high", 6), ("medium", 4)):
        n = by.get(rank, 0)
        out.append(_check(f"sec-{rank}", f"No open {rank} findings", pts, "pass" if not n else "fail",
                          (f"{n} open {rank} finding{'s' if n != 1 else ''}" if n else
                           f"no open {rank} findings from the scanners that ran (they recognize known patterns, "
                           "not every flaw)") + (
                              f"; {sum(1 for f in acc if f['rank'] == rank)} accepted with a written reason"
                              if any(f['rank'] == rank for f in acc) else ""),
                          "" if not n else "Fix them (see the Findings tab), or record why the risk is acceptable "
                          "with `lantern accept ID --reason \"...\"`.", how="scanners + reachability"))
    return out


def check_secrets(repo: Repo, sec: dict | None, env: dict[str, str]) -> list[dict]:
    out = []
    secret_rules = {"LW-PUBLIC-SECRET", "LW-SERVICE-ROLE"}
    secrets = [f for f in (sec or {}).get("findings", []) if not f.get("in_tests") and
               f.get("status") != "accepted" and (f["category"] == "secret" or f["rule"] in secret_rules)]
    out.append(_check("secrets-none", "No secrets in code", 5, "pass" if not secrets else "fail",
                      f"{len(secrets)} possible secret{'s' if len(secrets) != 1 else ''}"
                      + (": " + ", ".join(f"{f['file']}:{f['line']}" for f in secrets[:3]) if secrets else ""),
                      "" if not secrets else "Move each value to an environment variable and rotate it; "
                      "anything committed should be treated as leaked.", how="secret scanner"))
    out.append(_check("secrets-env", "Config read from the environment", 3,
                      "pass" if env else "skip",
                      f"reads {len(env)} variable{'s' if len(env) != 1 else ''}: {', '.join(sorted(env)[:6])}"
                      if env else "no environment variables read; nothing to configure",
                      how="pattern: os.environ / os.getenv / process.env / import.meta.env"))
    example = repo.has(".env.example", ".env.sample", ".env.template", "example.env")
    if env:
        missing = sorted(v for v in env if example and v not in repo.text(example))
        st = "pass" if example and not missing else "partial" if example else "fail"
        ev = (f"{example} lists every variable" if st == "pass" else
              f"{example} is missing {', '.join(missing[:5])}" if example else "no .env.example")
        out.append(_check("secrets-example", ".env.example documents every variable", 2, st, ev,
                          "" if st == "pass" else "Lantern can generate one: see Starter files below.",
                          how="file check + pattern"))
    else:
        out.append(_check("secrets-example", ".env.example documents every variable", 2, "skip",
                          "no environment variables read"))
    envs = [f for f in repo.project_files if f.rsplit("/", 1)[-1] in (".env", ".env.local", ".env.production")]
    gi = repo.text(".gitignore") if repo.has(".gitignore") else ""
    if envs:
        ignored = re.search(r"^\s*/?\.env(\*|\.\*|\.local)?\s*$|^\s*\*\.env\s*$|^\s*\.env\*", gi, re.M)
        out.append(_check("secrets-gitignore", ".env files are git-ignored", 2, "pass" if ignored else "fail",
                          f"found {', '.join(envs[:3])}; .gitignore {'covers' if ignored else 'does not cover'} them",
                          "" if ignored else "Add `.env*` (and `!.env.example`) to .gitignore."))
    else:
        out.append(_check("secrets-gitignore", ".env files are git-ignored", 2, "skip", "no .env files present"))
    return out


def check_input(repo: Repo, shape: str) -> list[dict]:
    out = []
    bare = repo.grep(BARE_EXCEPT)
    py = any(f.endswith(".py") for f in repo.files)
    out.append(_check("input-bare-except", "No bare `except:`", 4,
                      "skip" if not py else "pass" if not bare else "partial" if len(bare) <= 2 else "fail",
                      "no Python code" if not py else f"{len(bare)} bare except: {_where(bare)}" if bare
                      else "none found",
                      "" if not bare else "Catch the specific exceptions you expect; a bare except also swallows "
                      "Ctrl-C and hides bugs.", how="pattern"))
    if shape in SERVICE_SHAPES:
        hits = repo.grep(VALIDATION, limit=1)
        out.append(_check("input-validation", "Request input is validated by a schema", 3,
                          "pass" if hits else "fail",
                          f"schema library in use ({hits[0][0]})" if hits else "no schema validation library found",
                          "" if hits else "Validate request bodies with pydantic (Python) or zod (TypeScript).",
                          how="pattern: pydantic / FastAPI / marshmallow / zod / yup / joi / valibot"))
        dbg = repo.grep(DEBUG_ON)
        out.append(_check("input-debug", "Debug mode is off (no stack traces to users)", 3,
                          "pass" if not dbg else "fail", _where(dbg) if dbg else "no debug=True found",
                          "" if not dbg else "Read debug from an environment variable that defaults to off.",
                          how="pattern"))
    else:
        out.append(_check("input-validation", "Request input is validated by a schema", 3, "skip",
                          f"not a service ({shape})"))
        out.append(_check("input-debug", "Debug mode is off", 3, "skip", f"not a service ({shape})"))
    return out


def check_deps(repo: Repo, sec: dict | None, shape: str) -> list[dict]:
    out = []
    # Published libraries and CLI tools declare version ranges and let installers resolve them.
    has_py = repo.has("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")
    py_manifest = shape not in ("library", "command-line tool") and has_py
    js_manifests = [f for f in repo.project_files if f.rsplit("/", 1)[-1] == "package.json"]
    want, have = [], []
    if py_manifest:
        want.append("Python")
        req = [f for f in repo.project_files if re.search(r"(^|/)requirements[^/]*\.txt$", f)]
        pinned_req = req and all(re.search(r"==|@ |--hash", repo.text(r)) or not repo.text(r).strip() for r in req)
        if repo.has(*PY_LOCKS) or pinned_req:
            have.append("Python")
    for pj in js_manifests:
        d = pj.rsplit("/", 1)[0] + "/" if "/" in pj else ""
        want.append(pj)
        if any((d + lk) in repo.files for lk in JS_LOCKS) or any(lk in repo.files for lk in JS_LOCKS):
            have.append(pj)
    if want:
        miss = [w for w in want if w not in have]
        out.append(_check("deps-lock", "Lockfile committed", 4,
                          "pass" if not miss else "partial" if have else "fail",
                          "lockfile for every manifest" if not miss else f"no lockfile for {', '.join(miss[:3])}",
                          "" if not miss else "Commit the lockfile your package manager writes (package-lock.json, "
                          "pnpm-lock.yaml, uv.lock, poetry.lock) so every install gets the same versions."))
    else:
        out.append(_check("deps-lock", "Lockfile committed", 4, "skip",
                          f"not expected: a {shape} usually leaves exact versions to whoever installs it"
                          if has_py else "no dependency manifest"))
    tools = {t.get("tool"): t for t in (sec or {}).get("tools", [])}
    audited = [n for n in ("pip-audit", "npm-audit") if (tools.get(n) or {}).get("status") == "ok"]
    unchecked = [f"{n} ({str(tools[n].get('status', ''))[:90]})" for n in ("pip-audit", "npm-audit")
                 if n in tools and n not in audited and tools[n].get("status") not in NOTHING_TO_CHECK]
    vuln = [f for f in (sec or {}).get("findings", []) if f["category"] == "dependency" and f.get("status") != "accepted"]
    if vuln:
        out.append(_check("deps-vuln", "No known-vulnerable versions", 4, "fail",
                          f"{len(vuln)} known vulnerabilit{'ies' if len(vuln) != 1 else 'y'} in "
                          f"{len({f.get('package') for f in vuln})} package(s)",
                          "Upgrade to the fixed versions listed in Findings.", how="pip-audit, npm audit"))
    elif audited:
        out.append(_check("deps-vuln", "No known-vulnerable versions", 4, "partial" if unchecked else "pass",
                          f"{' and '.join(audited)} found none" + (f"; not checked: {'; '.join(unchecked)}"
                                                                   if unchecked else ""),
                          "" if not unchecked else "Commit a lock file so exact versions can be checked.",
                          how="pip-audit, npm audit"))
    else:
        out.append(_check("deps-vuln", "No known-vulnerable versions", 4, "skip",
                          "not checked: " + ("; ".join(unchecked) if unchecked else "no dependency files"),
                          how="pip-audit, npm audit"))
    loose = []
    for pj in js_manifests:
        try:
            d = json.loads(repo.text(pj) or "{}")
        except json.JSONDecodeError:
            d = None
        if not isinstance(d, dict):
            loose.append(f"{pj} could not be read (not valid JSON), so its versions were not checked")
            continue
        for sect in ("dependencies", "devDependencies"):
            for k, v in (d.get(sect) or {}).items():
                if isinstance(v, str) and v.strip() in ("*", "latest", "") :
                    loose.append(f"{pj}: {k}@{v or '(empty)'}")
    for r in (f for f in repo.project_files if re.search(r"(^|/)requirements[^/]*\.txt$", f)):
        for ln in repo.text(r).splitlines():
            s = ln.split("#")[0].strip()
            if s and not s.startswith("-") and not re.search(r"[=<>~!@]", s):
                loose.append(f"{r}: {s}")
    if want:
        out.append(_check("deps-pinned", "Versions are bounded (no `*`, `latest`, or bare names)", 2,
                          "pass" if not loose else "fail",
                          "every dependency has a version constraint" if not loose else ", ".join(loose[:4]),
                          "" if not loose else "Give each dependency a version range."))
    else:
        out.append(_check("deps-pinned", "Versions are bounded", 2, "skip", "no dependency manifest"))
    return out


def check_tests(repo: Repo, g: Graph, run_meta: dict) -> list[dict]:
    out = []
    tests = [f for f in repo.files if Path(f).suffix in CODE_EXTS and repo.is_test(f)]
    out.append(_check("tests-exist", "Tests exist", 4, "pass" if tests else "fail",
                      f"{len(tests)} test file{'s' if len(tests) != 1 else ''}" if tests else "no test files found",
                      "" if tests else "Add tests for your most important flows first (sign-in, payments, data changes)."))
    # Which non-test entry points do tests reach, directly or through the code they call?
    reach: set[str] = set()
    stack = [n.id for n in g.entry_points() if (n.entry or {}).get("kind") == "test"]
    while stack:
        u = stack.pop()
        if u in reach:
            continue
        reach.add(u)
        stack += [e.dst for e in g.callees(u)]
    entries = [n for n in g.entry_points() if (n.entry or {}).get("kind") in ("route", "cli", "script", "page")]
    if entries:
        hit = [n for n in entries if n.id in reach or any(e.src in reach for e in g.callers(n.id))]
        frac = len(hit) / len(entries)
        miss = [n.entry.get("detail") or n.qualname for n in entries if n not in hit]
        out.append(_check("tests-entries", "Tests touch every entry point", 4,
                          "pass" if frac >= 0.999 else "partial" if frac >= 0.5 else "fail",
                          f"{len(hit)} of {len(entries)} reached from tests" + (f"; not reached: {', '.join(miss[:4])}" if miss else ""),
                          "" if not miss else "Add a test that calls each untested route or command.",
                          how="call graph from test functions (static; frameworks' test clients are not followed)",
                          earned=4 * frac))
    else:
        out.append(_check("tests-entries", "Tests touch every entry point", 4, "skip", "no routes, pages, or commands"))
    tr = run_meta.get("trace") or {}
    if "returncode" in tr:
        out.append(_check("tests-pass", "Tests pass", 2, "pass" if tr["returncode"] == 0 else "fail",
                          f"traced test run exited {tr['returncode']}", how="lantern analyze --trace"))
    else:
        out.append(_check("tests-pass", "Tests pass", 2, "skip",
                          "not run (Lantern never runs your code unless you pass --trace)"))
    return out


def check_observability(repo: Repo, g: Graph, shape: str) -> list[dict]:
    out = []
    log = repo.grep(LOGGING, limit=1)
    if shape in ("library", "command-line tool"):
        out.append(_check("obs-logging", "Uses a logging library", 3, "skip",
                          f"{shape}: output to the terminal is the interface"))
    else:
        out.append(_check("obs-logging", "Uses a logging library", 3, "pass" if log else "fail",
                          f"{log[0][0]}" if log else "no logging library found",
                          "" if log else "Use the `logging` module (Python) or pino (Node) so logs have levels "
                          "and context.", how="pattern"))
    if shape in SERVICE_SHAPES:
        routes = [n for n in g.entry_points() if (n.entry or {}).get("kind") == "route"]
        health = [n for n in routes if HEALTH_PATH.search((n.entry or {}).get("detail") or "")]
        out.append(_check("obs-health", "Health-check endpoint", 3, "pass" if health else "fail",
                          health[0].entry["detail"] if health else f"none among {len(routes)} routes",
                          "" if health else "Add GET /health returning 200, so your host can tell when the app is up. "
                          "See Starter files.", how="route table"))
    else:
        out.append(_check("obs-health", "Health-check endpoint", 3, "skip", f"not a service ({shape})"))
    prints = [h for h in repo.grep(re.compile(r"^\s*print\(", re.M), limit=200)
              if not re.search(r"(^|/)(cli|__main__|scripts?|bench|examples?|tools)(/|\.py$)", h[0])]
    if shape in SERVICE_SHAPES and any(f.endswith(".py") for f in repo.files):
        out.append(_check("obs-print", "No print debugging in server code", 2,
                          "pass" if not prints else "partial" if len(prints) <= 3 else "fail",
                          f"{len(prints)} print() call{'s' if len(prints) != 1 else ''}: {_where(prints)}" if prints else "none",
                          "" if not prints else "Replace print() with logger.info()/debug().", how="pattern"))
    else:
        out.append(_check("obs-print", "No print debugging in server code", 2, "skip", f"not a Python service ({shape})"))
    return out


def check_packaging(repo: Repo, shape: str, stack: dict) -> list[dict]:
    out = []
    if shape not in SERVICE_SHAPES and shape != "frontend web app":
        manifest = repo.has("pyproject.toml", "setup.py", "package.json")
        out.append(_check("pkg-manifest", "Installable package definition", 8, "pass" if manifest else "fail",
                          manifest or "no pyproject.toml, setup.py, or package.json",
                          "" if manifest else "Add a pyproject.toml so others can `pip install` it."))
        return out
    serverless = {"Vercel", "Netlify"} & set(stack["deploy_targets"]) or (
        "Next.js" in stack["frameworks"] and not repo.has("Dockerfile"))
    docker = repo.has("Dockerfile")
    if serverless and not docker:
        out.append(_check("pkg-platform", "Deploys through a managed platform", 8, "pass",
                          ", ".join(stack["deploy_targets"]) or "Next.js (deployable on Vercel, Netlify, and others)",
                          how="file check"))
        return out
    out.append(_check("pkg-docker", "Container definition (Dockerfile)", 3, "pass" if docker else "fail",
                      docker or "no Dockerfile", "" if docker else "See Starter files for a Dockerfile."))
    if docker:
        t = repo.text(docker)
        froms = re.findall(r"^\s*FROM\s+(\S+)", t, re.M | re.I)
        user = re.findall(r"^\s*USER\s+(\S+)", t, re.M | re.I)
        nonroot = bool(user) and user[-1] not in ("root", "0")
        out.append(_check("pkg-user", "Container runs as a non-root user", 2, "pass" if nonroot else "fail",
                          f"USER {user[-1]}" if user else "no USER line, so it runs as root",
                          "" if nonroot else "Add a user and `USER app` before CMD."))
        final = froms[-1] if froms else ""
        slim = bool(re.search(r"slim|alpine|distroless|chainguard|wolfi|scratch", final))
        out.append(_check("pkg-slim", "Slim base image", 1, "pass" if slim else "fail", f"FROM {final}" if final else "no FROM",
                          "" if slim else "Use a -slim or -alpine base image."))
        pinned = bool(final) and ":" in final and not final.endswith(":latest")
        out.append(_check("pkg-tag", "Base image tag pinned (not `latest`)", 1, "pass" if pinned else "fail",
                          f"FROM {final}" if final else "no FROM"))
        di = repo.has(".dockerignore")
        out.append(_check("pkg-dockerignore", ".dockerignore present", 1, "pass" if di else "fail", di or "missing",
                          "" if di else "Keeps .env, .git, and node_modules out of the image. See Starter files."))
    else:
        for cid, title, pts in (("pkg-user", "Container runs as a non-root user", 2), ("pkg-slim", "Slim base image", 1),
                                ("pkg-tag", "Base image tag pinned", 1), ("pkg-dockerignore", ".dockerignore present", 1)):
            out.append(_check(cid, title, pts, "fail", "no Dockerfile"))
    return out


def check_ci(repo: Repo) -> list[dict]:
    wf = [f for f in repo.files if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))]
    wf += [f for f in CI_FILES if f in repo.files]
    text = "\n".join(repo.text(f) for f in wf)
    tests = TEST_CMD.search(text)
    scans = SCAN_CMD.search(text) or repo.has(".github/dependabot.yml")
    return [
        _check("ci-exists", "CI workflow exists", 3, "pass" if wf else "fail", ", ".join(wf[:3]) or "none",
               "" if wf else "See Starter files for a GitHub Actions workflow."),
        _check("ci-tests", "CI runs the tests", 3, "pass" if tests else "fail",
               f"runs `{tests.group(0)}`" if tests else "no test command found in CI", how="pattern"),
        _check("ci-scan", "CI runs a security scanner", 2, "pass" if scans else "fail",
               f"runs {scans.group(0) if hasattr(scans, 'group') else 'dependabot'}" if scans else "no scanner in CI",
               "" if scans else "Add `lantern analyze` (or bandit / npm audit) to CI.", how="pattern"),
    ]


def check_resilience(repo: Repo, shape: str, stack: dict) -> list[dict]:
    out = []
    no_timeout = []
    for f, t in repo.code():
        if not f.endswith(".py"):
            continue
        for m in PY_HTTP.finditer(t):
            depth, i = 0, m.end() - 1
            while i < len(t):
                depth += {"(": 1, ")": -1}.get(t[i], 0)
                if depth == 0:
                    break
                i += 1
            if "timeout" not in t[m.end():i]:
                no_timeout.append((f, t.count("\n", 0, m.start()) + 1, ""))
    js_fetch = repo.grep(re.compile(r"\b(fetch|axios\.(get|post|put|patch|delete))\("), limit=500)
    js_timeout = repo.grep(re.compile(r"AbortSignal\.timeout|AbortController|timeout\s*:"), limit=1)
    py_calls = sum(1 for _ in repo.grep(PY_HTTP, limit=500))
    total = py_calls + len(js_fetch)
    if total:
        js_bad = len(js_fetch) if js_fetch and not js_timeout else 0
        bad = len(no_timeout) + js_bad
        out.append(_check("res-timeout", "Outbound HTTP calls have timeouts", 4,
                          "pass" if not bad else "partial" if bad < total else "fail",
                          f"{bad} of {total} calls without a timeout" + (f": {_where(no_timeout)}" if no_timeout else
                                                                          " (no AbortSignal/timeout in frontend code)" if js_bad else ""),
                          "" if not bad else "Pass timeout= to requests/httpx; use AbortSignal.timeout(ms) with fetch.",
                          how="pattern", earned=4 * (1 - bad / total)))
    else:
        out.append(_check("res-timeout", "Outbound HTTP calls have timeouts", 4, "skip", "no outbound HTTP calls found"))
    if total:
        r = repo.grep(RETRY, limit=1)
        out.append(_check("res-retry", "Retries with backoff on outbound calls", 2, "pass" if r else "fail",
                          r[0][0] if r else "no retry helper found",
                          "" if r else "Retry idempotent calls with backoff (tenacity, p-retry).", how="pattern"))
    else:
        out.append(_check("res-retry", "Retries with backoff", 2, "skip", "no outbound HTTP calls found"))
    managed = "Next.js" in stack["frameworks"] or {"Vercel", "Netlify"} & set(stack["deploy_targets"])
    if shape in SERVICE_SHAPES and not managed:
        s = repo.grep(SHUTDOWN, limit=1)
        uvicorn = "FastAPI" in stack["frameworks"]
        out.append(_check("res-shutdown", "Graceful shutdown", 2, "pass" if s or uvicorn else "fail",
                          s[0][0] if s else "uvicorn handles SIGTERM for FastAPI apps" if uvicorn else "no SIGTERM handling",
                          "" if s or uvicorn else "Handle SIGTERM so in-flight requests finish on deploy.", how="pattern"))
    else:
        out.append(_check("res-shutdown", "Graceful shutdown", 2, "skip",
                          "the platform manages process lifecycle" if managed else f"not a service ({shape})"))
    return out


def check_docs(repo: Repo) -> list[dict]:
    readme = repo.has("README.md", "README.rst", "README.txt", "README")
    t = repo.text(readme) if readme else ""
    runs = bool(re.search(r"(pip install|npm (install|i|run)|pnpm|yarn|uv |poetry|docker|make |python -m|npx )", t))
    lic = repo.has("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")
    sec = repo.has("SECURITY.md", ".github/SECURITY.md")
    return [
        _check("docs-readme", "README with run instructions", 3,
               "pass" if readme and runs else "partial" if readme else "fail",
               f"{readme}" + ("" if runs else " has no install or run commands") if readme else "no README",
               "" if readme and runs else "Explain how to install and run the project in a code block."),
        _check("docs-license", "License", 2, "pass" if lic else "fail", lic or "no LICENSE file",
               "" if lic else "Pick a license (choosealicense.com) so others know how they may use the code."),
        _check("docs-security", "SECURITY.md", 1, "pass" if sec else "fail", sec or "missing",
               "" if sec else "See Starter files."),
    ]


# ---------------------------------------------------------------------------- advisor

def hotspots(g: Graph, top: int = 5) -> list[dict]:
    fan = Counter()
    for e in g.call_edges():
        if e.src != e.dst and e.dst in g.nodes and g.nodes[e.dst].kind == "callable":
            fan[e.dst] += 1
    out = []
    for nid, n in fan.most_common(top):
        if n < 5:
            break
        node = g.nodes[nid]
        out.append({"node": nid, "name": node.qualname, "file": node.file, "line": node.start_line, "callers": n,
                    "why": f"{n} functions call this; a bug or slowdown here spreads to all of them. "
                           "Make sure it has tests."})
    return out


def advice(shape: str, stack: dict) -> list[str]:
    fw = set(stack["frameworks"])
    tips = {
        "full-stack web app": [
            "Deploy the frontend and the API as two pieces: the frontend as static files or on a platform such as "
            "Vercel or Netlify, the API as a container (Fly.io, Render, Railway, Cloud Run).",
            "Keep all configuration in environment variables, with an .env.example listing every name.",
            "Use a managed database with automatic backups, and connect through a pooled connection string.",
            "Put the API behind HTTPS only, and allow your frontend's origin in CORS (not `*`).",
        ],
        "web API": [
            "Package the API as a container and run it on a platform that restarts it and checks /health.",
            "Keep configuration in environment variables (twelve-factor), never in code.",
            "Use a managed database; run two or more instances behind the platform's load balancer.",
            "Move slow work (emails, reports, imports) off the request onto a background queue.",
        ],
        "frontend web app": [
            "Deploy on a static or edge platform (Vercel, Netlify, Cloudflare Pages); no server to manage.",
            "Only variables meant to be public belong in NEXT_PUBLIC_/VITE_ names; everything else stays on a server.",
        ],
        "command-line tool": [
            "Publish it as a package (PyPI or npm) with a console entry point, and tag releases.",
            "Build and test on Linux, macOS, and Windows in CI before each release.",
        ],
        "script or worker": [
            "Run it on a schedule or a queue with a platform that retries failures and keeps logs.",
            "Make each run safe to repeat (idempotent) so a retry can't double-apply work.",
        ],
        "library": [
            "Publish with a version number and a changelog; keep the public API small and tested.",
        ],
    }[shape][:]
    if "Supabase" in fw:
        tips.append("Turn on row-level security for every Supabase table the browser can reach, and keep the "
                    "service-role key on the server only.")
    if "Next.js" in fw:
        tips.append("Next.js deploys cleanly on Vercel; route handlers become serverless functions, so keep them "
                    "short and put long jobs on a queue.")
    return tips


# ---------------------------------------------------------------------------- starter files

def starter_files(repo: Repo, shape: str, stack: dict, env: dict[str, str]) -> dict[str, dict]:
    """Files Lantern can write for you. Only ones that don't exist yet; nothing is written here."""
    out: dict[str, dict] = {}
    fw = set(stack["frameworks"])
    py = "python" in stack["languages"]
    pkgs = sorted((f for f in repo.project_files if f.rsplit("/", 1)[-1] == "package.json"), key=lambda f: f.count("/"))
    pkg_root = pkgs[0].rsplit("/", 1)[0] + "/" if pkgs and "/" in pkgs[0] else ""
    if env and not repo.has(".env.example"):
        lines = ["# Copy to .env and fill in. Never commit .env.", ""]
        for k in sorted(env):
            pub = k.startswith(("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_"))
            lines.append(f"# used at {env[k]}{' (sent to the browser: must not be secret)' if pub else ''}")
            lines.append(f"{k}=")
        out[".env.example"] = {"why": "Lists every environment variable the code reads, so a new machine or "
                                      "host can be configured without reading the source.",
                               "content": "\n".join(lines) + "\n"}
    if shape in SERVICE_SHAPES and not repo.has("Dockerfile") and not ("Next.js" in fw and not py):
        if py:
            app = _guess_asgi(repo)
            cmd = (f'["uvicorn", "{app}", "--host", "0.0.0.0", "--port", "8000"]' if "FastAPI" in fw or "Starlette" in fw
                   else f'["gunicorn", "-b", "0.0.0.0:8000", "{app}"]')
            install = ("COPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt"
                       if repo.has("requirements.txt") else "COPY . .\nRUN pip install --no-cache-dir .")
            content = f"""FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
{install}
COPY . .
RUN useradd --create-home app
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)"
CMD {cmd}
"""
        else:
            content = """FROM node:20-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
USER node
EXPOSE 3000
CMD ["npm", "start"]
"""
        out["Dockerfile"] = {"why": "A slim image that runs as a non-root user, with a health check.",
                             "content": content}
    if (shape in SERVICE_SHAPES or "Dockerfile" in out or repo.has("Dockerfile")) and not repo.has(".dockerignore"):
        out[".dockerignore"] = {"why": "Keeps secrets and bulky folders out of the image.",
                                "content": ".git\n.env\n.env.*\n!.env.example\nnode_modules\n__pycache__\n*.pyc\n"
                                           ".venv\nvenv\n.lantern\ndist\nbuild\n.next\ncoverage\n"}
    has_ci = any(f.startswith(".github/workflows/") for f in repo.files) or any(f in repo.files for f in CI_FILES)
    if not has_ci:
        steps = []
        if py:
            steps += ["      - uses: actions/setup-python@v5", "        with:", "          python-version: \"3.12\"",
                      "      - run: pip install -e . pytest" if repo.has("pyproject.toml") else
                      "      - run: pip install -r requirements.txt pytest" if repo.has("requirements.txt") else
                      "      - run: pip install pytest",
                      "      - run: python -m pytest -q"]
        if any(f.endswith("package.json") for f in repo.project_files):
            wd = f"\n        working-directory: {pkg_root.rstrip('/')}" if pkg_root else ""
            lock = any((pkg_root + lk) in repo.files for lk in JS_LOCKS)
            steps += ["      - uses: actions/setup-node@v4", "        with:", "          node-version: 20",
                      f"      - run: npm {'ci' if lock else 'install'}{wd}",
                      "      - run: npm test --if-present" + wd]
        steps += ["      - name: Lantern security and readiness audit",
                  "        run: |",
                  "          pip install \"lantern[scan] @ git+https://github.com/LittleHenderson/Lantern\"",
                  "          lantern analyze . --out /tmp/lantern --fail-on high"]
        out[".github/workflows/ci.yml"] = {
            "why": "Runs your tests and Lantern's scanners on every push, so problems are caught before deploy.",
            "content": "name: ci\non: [push, pull_request]\npermissions:\n  contents: read\njobs:\n  test:\n"
                       "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
                       + "\n".join(steps) + "\n"}
    if not repo.has("SECURITY.md", ".github/SECURITY.md"):
        out["SECURITY.md"] = {"why": "Tells people how to report a vulnerability privately.",
                              "content": "# Security policy\n\nPlease report security problems privately to "
                                         "<your email> rather than in a public issue. We aim to reply within 3 "
                                         "working days.\n\nSupported versions: the latest release.\n"}
    if shape in SERVICE_SHAPES:
        routes = [r for r in stack.get("routes", []) if HEALTH_PATH.search(r)]
        if not routes:
            if "FastAPI" in fw:
                out["health (add to your FastAPI app)"] = {
                    "why": "Lets your host check the app is alive.", "snippet": True,
                    "content": "@app.get(\"/health\")\ndef health():\n    return {\"ok\": True}\n"}
            elif "Flask" in fw:
                out["health (add to your Flask app)"] = {
                    "why": "Lets your host check the app is alive.", "snippet": True,
                    "content": "@app.get(\"/health\")\ndef health():\n    return {\"ok\": True}\n"}
            elif "Next.js" in fw:
                out["app/api/health/route.ts"] = {
                    "why": "Lets your host check the app is alive.",
                    "content": "export function GET() {\n  return Response.json({ ok: true });\n}\n"}
            elif fw & {"Express", "Hono", "Fastify"}:
                out["health (add to your server)"] = {
                    "why": "Lets your host check the app is alive.", "snippet": True,
                    "content": "app.get('/health', (req, res) => res.json({ ok: true }));\n"}
    return out


def _guess_asgi(repo: Repo) -> str:
    for f, t in repo.code():
        if f.endswith(".py"):
            m = re.search(r"^(\w+)\s*=\s*(FastAPI|Flask|Starlette)\(", t, re.M)
            if m:
                return f[:-3].replace("/", ".") + ":" + m.group(1)
    return "app:app"


# ---------------------------------------------------------------------------- score

def grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def assess(g: Graph, sec: dict | None, run_meta: dict | None = None) -> dict:
    root = Path(g.repo_root)
    repo = Repo(root)
    stack = detect_stack(repo, g)
    stack["routes"] = [(n.entry or {}).get("detail") or "" for n in g.entry_points()
                       if (n.entry or {}).get("kind") == "route"]
    shape = classify_shape(stack)
    env = repo.env_vars()
    checks = {
        "security": check_security(sec),
        "secrets": check_secrets(repo, sec, env),
        "input": check_input(repo, shape),
        "deps": check_deps(repo, sec, shape),
        "tests": check_tests(repo, g, run_meta or {}),
        "observability": check_observability(repo, g, shape),
        "packaging": check_packaging(repo, shape, stack),
        "ci": check_ci(repo),
        "resilience": check_resilience(repo, shape, stack),
        "docs": check_docs(repo),
    }
    cats, total_w, total_e = [], 0.0, 0.0
    for key, title, weight in CATEGORIES:
        cs = checks[key]
        avail = sum(c["points"] for c in cs if c["status"] != "skip")
        got = sum(c["earned"] for c in cs if c["status"] != "skip")
        frac = got / avail if avail else None
        if frac is not None:
            total_w += weight
            total_e += weight * frac
        cats.append({"key": key, "title": title, "weight": weight,
                     "score": None if frac is None else round(frac * weight, 1),
                     "percent": None if frac is None else round(frac * 100), "checks": cs})
    score = round(100 * total_e / total_w) if total_w else 0
    todo = sorted((c | {"category": cat["title"], "gain": round(cat["weight"] * (c["points"] - c["earned"]) /
                                                                 max(1, sum(x["points"] for x in cat["checks"] if x["status"] != "skip")), 1)}
                   for cat in cats for c in cat["checks"] if c["status"] in ("fail", "partial")),
                  key=lambda c: -c["gain"])
    return {
        "version": READINESS_VERSION, "score": score, "grade": grade(score), "categories": cats,
        "shape": shape, "stack": {k: v for k, v in stack.items() if k != "routes"},
        "advice": advice(shape, stack), "hotspots": hotspots(g),
        "protections": advise_protections(g, sec, repo, shape),
        "env_vars": sorted(env), "next_steps": todo[:8],
        "starter": starter_files(repo, shape, stack, env),
    }
