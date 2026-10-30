"""Known-vulnerable dependency versions, for Python and JavaScript.

Both checks ask a public vulnerability database (PyPI/OSV through pip-audit, the npm registry through `npm audit`),
so they are the only network calls `lantern analyze` makes. `--offline` (or LANTERN_OFFLINE=1) skips them, and the
report then says the dependencies were not checked.

Nothing from the analyzed repo is executed or trusted as configuration:
  * Python: exact versions are read from lock files (uv.lock, poetry.lock, pdm.lock, Pipfile.lock), `==` lines in
    requirements*.txt, and `==` pins in pyproject.toml. Only `name==version` pairs reach pip-audit, in a temporary
    file, so index URLs or options in the repo's files are ignored. Ranges (`>=1.2`) can't be checked, because the
    installed version isn't known; they are counted and reported as not checked.
  * JavaScript: `npm audit --package-lock-only` reads package-lock.json (no install, no scripts). The registry is
    passed explicitly so a repo's .npmrc can't redirect the query.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

from .python_frontend import SKIP_DIRS, inside_repo

NPM_REGISTRY = "https://registry.npmjs.org/"
TEST_DIR_RE = re.compile(r"(^|/)(tests?|__tests__|fixtures|examples?)/")
PIN_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_\-]*)\s*(;.*)?$")
NOTHING_TO_CHECK = ("skipped: no Python dependency files", "skipped: no package.json")
NPM_SEVERITY = {"critical": "HIGH", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW", "info": "LOW"}


def _pkg_version(name: str) -> str | None:
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:  # noqa: BLE001 - not installed
        return None


def offline() -> bool:
    return os.environ.get("LANTERN_OFFLINE", "").strip() not in ("", "0", "false", "no")


def _project_files(repo: Path, names: tuple[str, ...] | None = None, pattern: re.Pattern | None = None) -> list[Path]:
    """Files in the project itself: not vendored, not in tests or sample apps, not symlinked out of the repo."""
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != "node_modules"]
        for fn in filenames:
            if (names and fn in names) or (pattern and pattern.search(fn)):
                p = Path(dirpath) / fn
                rel = p.relative_to(repo).as_posix()
                if not TEST_DIR_RE.search(rel) and inside_repo(p, repo):
                    out.append(p)
    return sorted(out)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------- Python

def python_pins(repo: Path) -> tuple[dict[str, tuple[str, str]], list[str], list[str]]:
    """{normalized name: (version, file it came from)}, the unpinned requirement texts, and the files read."""
    pins: dict[str, tuple[str, str]] = {}
    loose: list[str] = []
    files: list[str] = []

    def add(name, version, rel):
        if name and version:
            pins.setdefault(_norm(name), (str(version), rel))

    for p in _project_files(repo, names=("uv.lock", "poetry.lock", "pdm.lock")):
        rel = p.relative_to(repo).as_posix()
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        files.append(rel)
        for pkg in data.get("package") or []:
            src = pkg.get("source") or {}
            if isinstance(src, dict) and (src.get("editable") or src.get("virtual") or src.get("directory")):
                continue   # the project itself, not a published package
            add(pkg.get("name"), pkg.get("version"), rel)
    for p in _project_files(repo, names=("Pipfile.lock",)):
        rel = p.relative_to(repo).as_posix()
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        files.append(rel)
        for name, spec in (data.get("default") or {}).items():
            v = (spec or {}).get("version", "") if isinstance(spec, dict) else ""
            add(name, v.lstrip("="), rel)
    for p in _project_files(repo, pattern=re.compile(r"^requirements[^/]*\.txt$")):
        rel = p.relative_to(repo).as_posix()
        files.append(rel)
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.split(" #")[0].strip()
            if not s or s.startswith(("#", "-")):
                continue
            m = PIN_RE.match(s.split("--hash")[0].strip().rstrip("\\").strip())
            if m:
                add(m.group(1), m.group(3), rel)
            else:
                loose.append(f"{rel}: {s[:60]}")
    for p in _project_files(repo, names=("pyproject.toml",)):
        rel = p.relative_to(repo).as_posix()
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        deps = list((data.get("project") or {}).get("dependencies") or [])
        poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
        deps += [k + ("==" + v if isinstance(v, str) and re.match(r"^\d", v) else "")
                 for k, v in poetry.items() if k.lower() != "python"]
        if deps:
            files.append(rel)
        for d in deps:
            m = PIN_RE.match(str(d))
            if m:
                add(m.group(1), m.group(3), rel)
            elif _norm(re.split(r"[\s<>=!~\[;(@]", str(d), maxsplit=1)[0]) not in pins:
                loose.append(f"{rel}: {str(d)[:60]}")
    # a range in pyproject is fine when a lock file pins the same package
    loose = [x for x in loose if _norm(re.split(r"[\s<>=!~\[;(@]", x.split(": ", 1)[1], maxsplit=1)[0]) not in pins]
    return pins, loose, sorted(set(files))


def run_pip_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    from .security import _fid
    info = {"tool": "pip-audit", "role": "known-vulnerable Python packages", "version": _pkg_version("pip-audit")}
    pins, loose, files = python_pins(repo)
    if not files:
        return [], info | {"status": "skipped: no Python dependency files"}
    if not pins:
        return [], info | {"status": "skipped: no exact versions to check (commit a lock file such as uv.lock or "
                                     "poetry.lock, or pin with ==)", "files": files, "unpinned": len(loose)}
    if offline() if no_network is None else no_network:
        return [], info | {"status": "skipped: offline", "files": files}
    if not shutil.which("pip-audit"):
        return [], info | {"status": "skipped: not installed (pip install pip-audit)", "files": files}
    with tempfile.TemporaryDirectory() as td:
        req = Path(td) / "requirements.txt"
        req.write_text("".join(f"{n}=={v}\n" for n, (v, _) in sorted(pins.items())), encoding="utf-8")
        cmd = ["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off", "--no-deps", "--disable-pip"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
            data = json.loads(proc.stdout or "{}")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError) as exc:
            return [], info | {"status": f"error: {type(exc).__name__} (network needed?)", "files": files}
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            name = dep.get("name", "")
            out.append({
                "id": _fid("pip-audit", _norm(name), v["id"]),
                "tool": "pip-audit", "rule": v["id"],
                "title": f"{name} {dep.get('version', '')} has known vulnerability {v['id']}",
                "tool_severity": "HIGH", "tool_confidence": "HIGH",
                "file": pins.get(_norm(name), ("", files[0]))[1], "line": None,
                "more_info": f"Fixed in: {', '.join(v.get('fix_versions', [])) or 'no fix yet'}",
                "snippet": (v.get("description") or "")[:400], "category": "dependency", "package": name,
            })
    return out, info | {"status": "ok", "files": files, "checked": len(pins), "unpinned": len(loose),
                        "unpinned_examples": loose[:5]}


# ---------------------------------------------------------------------------- JavaScript

def run_npm_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    from .security import _fid
    info = {"tool": "npm-audit", "role": "known-vulnerable npm packages (production dependencies)"}
    manifests = _project_files(repo, names=("package.json",))
    if not manifests:
        return [], info | {"status": "skipped: no package.json"}
    locks = [m.parent / "package-lock.json" for m in manifests if (m.parent / "package-lock.json").is_file()]
    other = [m.parent.relative_to(repo).as_posix() or "." for m in manifests
             if not (m.parent / "package-lock.json").is_file()]
    if not locks:
        why = ("pnpm-lock.yaml / yarn.lock / bun.lock aren't read yet; run `pnpm audit` or `yarn npm audit`"
               if any((m.parent / x).is_file() for m in manifests for x in ("pnpm-lock.yaml", "yarn.lock", "bun.lock"))
               else "no package-lock.json, so exact versions are unknown (commit your lock file)")
        return [], info | {"status": f"skipped: {why}"}
    if offline() if no_network is None else no_network:
        return [], info | {"status": "skipped: offline"}
    npm = shutil.which("npm")
    if not npm:
        return [], info | {"status": "skipped: npm not installed"}
    out, files, errors = [], [], []
    try:
        info["version"] = subprocess.run([npm, "--version"], capture_output=True, text=True, encoding="utf-8",
                                         errors="replace", timeout=30).stdout.strip()[:20] or None
    except (OSError, subprocess.TimeoutExpired):
        pass
    for lock in locks:
        rel = lock.relative_to(repo).as_posix()
        cmd = [npm, "audit", "--json", "--package-lock-only", "--omit=dev", f"--registry={NPM_REGISTRY}"]
        try:
            proc = subprocess.run(cmd, cwd=lock.parent, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=180, env={**os.environ, "npm_config_audit_level": "info"})
            data = json.loads(proc.stdout or "{}")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{rel}: {type(exc).__name__}")
            continue
        if "error" in data and "vulnerabilities" not in data:
            errors.append(f"{rel}: {str((data.get('error') or {}).get('summary', 'failed'))[:80]}")
            continue
        files.append(rel)
        for name, v in (data.get("vulnerabilities") or {}).items():
            advisories = [x for x in v.get("via") or [] if isinstance(x, dict)]
            if not advisories:
                continue   # only vulnerable through another package; that package gets its own finding
            for adv in advisories:
                rule = (adv.get("url") or "").rsplit("/", 1)[-1] or str(adv.get("source") or name)
                fix = v.get("fixAvailable")
                fix_txt = (f"upgrade {fix.get('name')} to {fix.get('version')}" if isinstance(fix, dict)
                           else "a fix is available (npm audit fix)" if fix else "no fix yet")
                out.append({
                    "id": _fid("npm-audit", rel, name, rule),
                    "tool": "npm-audit", "rule": rule,
                    "title": f"{name} ({adv.get('range') or v.get('range') or 'installed version'}): "
                             f"{adv.get('title') or 'known vulnerability'}",
                    "tool_severity": NPM_SEVERITY.get(str(adv.get("severity") or v.get("severity")), "MEDIUM"),
                    "dep_severity": adv.get("severity") or v.get("severity"),
                    "tool_confidence": "HIGH", "file": rel, "line": None,
                    "more_info": adv.get("url") or fix_txt, "snippet": fix_txt, "category": "dependency",
                    "package": name,
                })
    status = "ok" if files and not errors else ("partial: " if files else "error: ") + "; ".join(errors)[:200]
    res = info | {"status": status, "files": files}
    if other:
        res["not_checked"] = other[:10]
    return out, res
