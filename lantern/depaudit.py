"""Known-vulnerable dependency versions, for Python, JavaScript, Java/Kotlin/Android (Gradle and Maven) and PHP.

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
  * Gradle and Maven (Android apps, Java/Kotlin servers): `group:name:version` read from build.gradle(.kts), the
    version catalog gradle/libs.versions.toml and pom.xml (with its own <properties>), shipped dependencies only (no
    test configurations), asked of the OSV database (api.osv.dev, ecosystem Maven) as plain name/version pairs.
    Nothing runs Gradle or Maven. Versions with `+`, ranges or variables Lantern cannot resolve are counted as not
    checked. Only the libraries written in the build files are checked, not the ones they pull in.
  * PHP: every library in composer.lock's shipped `packages` (not `packages-dev`), name and exact version, asked of
    OSV (ecosystem Packagist). Nothing runs Composer. The finding points at the line in composer.json that asks for
    the library, or at its entry in composer.lock when another library pulled it in.
  * Ruby: every gem in Gemfile.lock's `specs` with its exact version, asked of OSV (ecosystem RubyGems), except gems the
    Gemfile lists only in `group :development`/`:test` blocks. Nothing runs Bundler. The finding points at the
    Gemfile's `gem "name"` line, or at the gem's line in Gemfile.lock when another gem pulled it in.
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
NOTHING_TO_CHECK = ("skipped: no Python dependency files", "skipped: no package.json", "skipped: no Gradle or Maven files",
                    "skipped: no composer.lock", "skipped: no Gemfile.lock")
AUDIT_TOOLS = ("pip-audit", "npm-audit", "maven-audit", "composer-audit", "gem-audit")
OSV_API = "https://api.osv.dev/v1"
NPM_SEVERITY = {"critical": "HIGH", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW", "info": "LOW"}


def _pkg_version(name: str) -> str | None:
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:  # noqa: BLE001 - not installed
        return None


def precomputed(tool: str) -> tuple[list[dict], dict] | None:
    """Results of an audit that already ran elsewhere: Lantern's cloud service runs the audits (network, lock files
    only) in one step and the analysis (no network at all) in another, and hands the first step's file to the
    second through LANTERN_AUDITS_FROM. None when there is no such file or it has nothing for `tool`."""
    path = os.environ.get("LANTERN_AUDITS_FROM", "")
    if not path:
        return None
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8")).get(tool)
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("findings"), list) or not isinstance(d.get("info"), dict):
        return None
    return [f for f in d["findings"] if isinstance(f, dict)], d["info"]


def run_all(repo: Path) -> dict:
    """All audits with the network on, as {tool: {findings, info}} (what LANTERN_AUDITS_FROM reads)."""
    out = {}
    for tool, fn in (("pip-audit", run_pip_audit), ("npm-audit", run_npm_audit), ("maven-audit", run_maven_audit),
                     ("composer-audit", run_composer_audit), ("gem-audit", run_gem_audit)):
        try:
            f, info = fn(repo, False)
        except Exception as exc:  # noqa: BLE001 - one audit's surprise (a registry down, odd output) must not drop the others
            f, info = [], {"tool": tool, "status": f"error: {type(exc).__name__} (network needed?)"}
        out[tool] = {"findings": f, "info": info}
    return out


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
    pre = precomputed("pip-audit")
    if pre is not None:
        return pre
    info = {"tool": "pip-audit", "role": "known-vulnerable Python packages", "version": _pkg_version("pip-audit")}
    pins, loose, files = python_pins(repo)
    if not files:
        return [], info | {"status": "skipped: no Python dependency files"}
    if not pins:
        return [], info | {"status": "skipped: no exact versions to check (commit a lock file such as uv.lock or "
                                     "poetry.lock, or pin with ==)", "files": files, "unpinned": len(loose)}
    if not shutil.which("pip-audit"):
        return [], info | {"status": 'skipped: not installed (pip install "lantern[scan]")', "files": files}
    if offline() if no_network is None else no_network:
        return [], info | {"status": "skipped: offline", "files": files}
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
        name = dep.get("name", "")
        for v, aliases in _advisories(dep.get("vulns", [])):
            out.append({
                "id": _fid("pip-audit", _norm(name), v["id"]),
                "tool": "pip-audit", "rule": v["id"],
                "title": f"{name} {dep.get('version', '')} has known vulnerability {v['id']}",
                "tool_severity": "HIGH", "tool_confidence": "HIGH",
                "file": pins.get(_norm(name), ("", files[0]))[1], "line": None,
                "more_info": f"Fixed in: {', '.join(v.get('fix_versions', [])) or 'no fix yet'}"
                             + (f". Also listed as {', '.join(aliases)}" if aliases else ""),
                "snippet": (v.get("description") or "")[:400], "category": "dependency", "package": name,
            })
    return out, info | {"status": "ok", "files": files, "checked": len(pins), "unpinned": len(loose),
                        "unpinned_examples": loose[:5]}


def _advisories(vulns: list[dict]) -> list[tuple[dict, list[str]]]:
    """One entry per advisory. pip-audit can list the same id twice and the same CVE under two ids (a PYSEC and a
    GHSA entry that alias each other); those are merged, lowest id first so results are stable between runs."""
    groups: list[tuple[set[str], dict]] = []
    for v in sorted((v for v in vulns if isinstance(v, dict) and v.get("id")), key=lambda v: str(v["id"])):
        keys = {str(v["id"])} | {str(a) for a in (v.get("aliases") or [])}
        for known, _ in groups:
            if known & keys:
                known |= keys
                break
        else:
            groups.append((keys, v))
    return [(v, sorted(keys - {str(v["id"])})) for keys, v in groups]


# ---------------------------------------------------------------------------- JavaScript

def run_npm_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    from .security import _fid
    pre = precomputed("npm-audit")
    if pre is not None:
        return pre
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



# ---------------------------------------------------------------------------- Gradle / Maven (OSV)

GRADLE_FILES = ("build.gradle", "build.gradle.kts")
# Configurations that ship with the app (test and lint configurations are left out, like npm's --omit=dev)
GRADLE_DEP = re.compile(r"^\s*(implementation|api|compile|runtimeOnly|compileOnly|releaseImplementation|kapt|ksp|"
                        r"annotationProcessor|coreLibraryDesugaring|\w+Implementation)(?<!testImplementation)"
                        r"(?<!androidTestImplementation)(?<!debugImplementation)\s*\(?\s*(?:platform\()?"
                        r"[\"']([\w.\-]+):([\w.\-]+):([^\"'@\s]+)[\"']", re.M)
GRADLE_VAR = re.compile(r"^\s*(?:ext\.)?(?:val\s+|def\s+)?(\w+)\s*=\s*[\"']([\w.\-]+)[\"']", re.M)
EXACT = re.compile(r"^[0-9][\w.\-]*$")
OSV_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "moderate", "MEDIUM": "moderate", "LOW": "low"}


def maven_coords(repo: Path) -> tuple[dict[str, tuple[str, str, int]], list[str], list[str]]:
    """{"group:name": (version, file, line)}, versions not checked ("group:name:1.+"), files read."""
    pins: dict[str, tuple[str, str, int]] = {}
    loose: list[str] = []
    files: list[str] = []

    def add(coord: str, ver: str, rel: str, line: int):
        if EXACT.match(ver) and "+" not in ver:
            pins.setdefault(coord, (ver, rel, line))
        else:
            loose.append(f"{coord}:{ver}")

    for p in _project_files(repo, names=GRADLE_FILES):
        rel = p.relative_to(repo).as_posix()
        try:
            text = p.read_text(encoding="utf-8", errors="replace")[:2_000_000]
        except OSError:
            continue
        found = False
        vars_ = dict(GRADLE_VAR.findall(text))
        for m in GRADLE_DEP.finditer(text):
            found = True
            ver = m.group(4)
            vm = re.fullmatch(r"\$\{?(\w+)\}?", ver)
            if vm:
                ver = vars_.get(vm.group(1), ver)
            add(f"{m.group(2)}:{m.group(3)}", ver, rel, text.count("\n", 0, m.start()) + 1)
        if found:
            files.append(rel)
    for p in _project_files(repo, names=("libs.versions.toml",)):
        rel = p.relative_to(repo).as_posix()
        try:
            cat = tomllib.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        versions = {k: v for k, v in (cat.get("versions") or {}).items() if isinstance(v, str)}
        text = p.read_text(encoding="utf-8", errors="replace")
        for key, lib in (cat.get("libraries") or {}).items():
            if isinstance(lib, str):
                parts = lib.split(":")
                if len(parts) == 3:
                    coord, ver = f"{parts[0]}:{parts[1]}", parts[2]
                else:
                    continue
            elif isinstance(lib, dict):
                coord = lib.get("module") or (f"{lib.get('group')}:{lib.get('name')}" if lib.get("group") else None)
                v = lib.get("version")
                ver = versions.get(v.get("ref")) if isinstance(v, dict) else v
                if not coord or not isinstance(ver, str):
                    continue
            else:
                continue
            if "test" in key.lower() or "junit" in coord or "espresso" in coord:
                continue
            pos = text.find(key)
            add(coord, ver, rel, text.count("\n", 0, pos) + 1 if pos >= 0 else 1)
        files.append(rel)
    for p in _project_files(repo, names=("pom.xml",)):
        rel = p.relative_to(repo).as_posix()
        try:
            text = p.read_text(encoding="utf-8", errors="replace")[:2_000_000]
        except OSError:
            continue
        pm_ = re.search(r"<properties>(.*?)</properties>", text, re.S)
        props = dict(re.findall(r"<([\w.\-]+)>\s*([\w.\-]+)\s*</\1>", pm_.group(1))) if pm_ else {}
        found = False
        for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
            body = m.group(1)
            g = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", body)
            a = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", body)
            v = re.search(r"<version>\s*([^<\s]+)\s*</version>", body)
            sc = re.search(r"<scope>\s*(test|provided)\s*</scope>", body)
            if not (g and a and v) or sc:
                continue
            found = True
            ver = v.group(1)
            pm = re.fullmatch(r"\$\{([\w.\-]+)\}", ver)
            if pm:
                ver = props.get(pm.group(1), ver)
            add(f"{g.group(1)}:{a.group(1)}", ver, rel, text.count("\n", 0, m.start()) + 1)
        if found:
            files.append(rel)
    return pins, loose, files


def _osv_post(path: str, body: dict, timeout: float = 60) -> dict:
    import urllib.request
    req = urllib.request.Request(f"{OSV_API}/{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "lantern"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310: fixed https://api.osv.dev URL
        return json.loads(r.read(20_000_000).decode("utf-8", "replace"))


def _osv_get(path: str, timeout: float = 30) -> dict:
    import urllib.request
    req = urllib.request.Request(f"{OSV_API}/{path}", headers={"User-Agent": "lantern"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310: fixed https://api.osv.dev URL
        return json.loads(r.read(5_000_000).decode("utf-8", "replace"))


def _osv_fixed(vuln: dict, coord: str) -> list[str]:
    out = []
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict) or (aff.get("package") or {}).get("name") != coord:
            continue
        for rng in aff.get("ranges") or []:
            for ev in (rng.get("events") or []) if isinstance(rng, dict) else []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    out.append(str(ev["fixed"])[:40])
    return sorted(set(out))


def run_maven_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    pre = precomputed("maven-audit")
    if pre is not None:
        return pre
    info = {"tool": "maven-audit", "role": "known-vulnerable Gradle/Maven libraries (OSV database)", "version": "osv-v1"}
    pins, loose, files = maven_coords(repo)
    if not files:
        return [], info | {"status": "skipped: no Gradle or Maven files"}
    if not pins:
        return [], info | {"status": "skipped: no exact versions to check", "files": files, "unpinned": len(loose)}
    if offline() if no_network is None else no_network:
        return [], info | {"status": "skipped: offline", "files": files}
    try:
        out = _osv_findings("maven-audit", "Maven", pins)
    except (OSError, ValueError) as exc:
        return [], info | {"status": f"error: {type(exc).__name__} (network needed?)", "files": files}
    return out, info | {"status": "ok", "files": files, "checked": len(pins), "unpinned": len(loose),
                        "unpinned_examples": loose[:5]}


def _osv_findings(tool: str, ecosystem: str, pins: dict[str, tuple[str, str, int]]) -> list[dict]:
    """Ask OSV about exact `name → (version, file, line)` pins of one ecosystem; one finding per known vulnerability."""
    from .security import _fid
    coords = sorted(pins)
    res = []
    for i in range(0, len(coords), 500):
        chunk = coords[i:i + 500]
        data = _osv_post("querybatch", {"queries": [{"package": {"name": c, "ecosystem": ecosystem},
                                                     "version": pins[c][0]} for c in chunk]})
        res += list(zip(chunk, data.get("results") or []))
    details: dict[str, dict] = {}
    out = []
    for coord, r in res:
        for v in (r or {}).get("vulns") or []:
            vid = str((v or {}).get("id") or "")[:60]
            if not vid:
                continue
            if vid not in details and len(details) < 300:
                details[vid] = _osv_get(f"vulns/{vid}")
            d = details.get(vid) or {}
            sev = OSV_SEVERITY.get(str((d.get("database_specific") or {}).get("severity") or "").upper(), "moderate")
            fixed = _osv_fixed(d, coord)
            aliases = [str(a)[:40] for a in (d.get("aliases") or [])][:5]
            ver, rel, line = pins[coord]
            out.append({
                "id": _fid(tool, coord, vid),
                "tool": tool, "rule": vid,
                "title": f"{coord} {ver}: {str(d.get('summary') or 'known vulnerability')[:160]}",
                "tool_severity": NPM_SEVERITY.get(sev, "MEDIUM"), "dep_severity": sev,
                "tool_confidence": "HIGH", "file": rel, "line": line,
                "more_info": f"Fixed in: {', '.join(fixed) or 'no fix listed'}"
                             + (f". Also listed as {', '.join(aliases)}" if aliases else "")
                             + f". https://osv.dev/vulnerability/{vid}",
                "snippet": str(d.get("details") or d.get("summary") or "")[:400], "category": "dependency",
                "package": coord,
            })
    return out


# ---------------------------------------------------------------------------- PHP (Composer, OSV)

def composer_pins(repo: Path) -> tuple[dict[str, tuple[str, str, int]], list[str]]:
    """Exact versions from every composer.lock (shipped `packages`, not `packages-dev`): name → (version, file, line).
    The line is where composer.json asks for the library when it does (a direct library), else its place in the lock."""
    pins: dict[str, tuple[str, str, int]] = {}
    files = []
    for lock in _project_files(repo, names=("composer.lock",)):
        rel = lock.relative_to(repo).as_posix()
        try:
            text = lock.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, ValueError):
            continue
        files.append(rel)
        cj = lock.with_name("composer.json")
        cj_rel = cj.relative_to(repo).as_posix()
        try:
            cj_text = cj.read_text(encoding="utf-8", errors="replace")
        except OSError:
            cj_text = ""
        for pkg in data.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            name, ver = str(pkg.get("name") or ""), str(pkg.get("version") or "")
            if not re.fullmatch(r"[\w.-]+/[\w.-]+", name) or not re.fullmatch(r"v?\d+(\.\d+)*([-.+][\w.]+)?", ver):
                continue
            m = re.search(r'"' + re.escape(name) + r'"\s*:', cj_text)
            if m:
                where = (cj_rel, cj_text.count("\n", 0, m.start()) + 1)
            else:
                lm = re.search(r'"name"\s*:\s*"' + re.escape(name) + '"', text)
                where = (rel, text.count("\n", 0, lm.start()) + 1 if lm else 1)
            pins.setdefault(name, (ver.lstrip("v"), *where))
    return pins, files


def run_composer_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    pre = precomputed("composer-audit")
    if pre is not None:
        return pre
    info = {"tool": "composer-audit", "role": "known-vulnerable PHP libraries (composer.lock, OSV database)",
            "version": "osv-v1"}
    pins, files = composer_pins(repo)
    if not files:
        return [], info | {"status": "skipped: no composer.lock"}
    if offline() if no_network is None else no_network:
        return [], info | {"status": "skipped: offline", "files": files}
    try:
        out = _osv_findings("composer-audit", "Packagist", pins)
    except (OSError, ValueError) as exc:
        return [], info | {"status": f"error: {type(exc).__name__} (network needed?)", "files": files}
    return out, info | {"status": "ok", "files": files, "checked": len(pins)}


# ---------------------------------------------------------------------------- Ruby (Bundler, OSV)

def _gemfile_dev_only(text: str) -> tuple[dict[str, int], set[str]]:
    """Gemfile: gem name → line where it is written, and the gems written only inside development/test groups."""
    lines: dict[str, int] = {}
    shipped, dev = set(), set()
    stack: list[bool] = []                       # one entry per open `do` block: is it a dev/test group?
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        g = re.match(r"group\s+(.+?)\s+do\b", line)
        if g:
            names = set(re.findall(r":(\w+)", g.group(1)))
            stack.append(bool(names) and names <= {"development", "test"})
            continue
        if re.search(r"\bdo\s*(\|[^|]*\|)?\s*$", line):
            stack.append(any(stack))
            continue
        if line == "end" and stack:
            stack.pop()
            continue
        m = re.match(r"gem\s+['\"]([\w.-]+)['\"](.*)$", line)
        if m:
            lines.setdefault(m.group(1), i)
            grp = re.search(r"group:\s*\[?([^\]]*)", m.group(2))
            in_dev = any(stack) or bool(grp and set(re.findall(r":(\w+)", grp.group(1))) <= {"development", "test"}
                                        and re.findall(r":(\w+)", grp.group(1)))
            (dev if in_dev else shipped).add(m.group(1))
    return lines, dev - shipped


def gem_pins(repo: Path) -> tuple[dict[str, tuple[str, str, int]], list[str]]:
    """Exact versions from every Gemfile.lock: name → (version, file, line)."""
    pins: dict[str, tuple[str, str, int]] = {}
    files = []
    for lock in _project_files(repo, names=("Gemfile.lock",)):
        rel = lock.relative_to(repo).as_posix()
        try:
            text = lock.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append(rel)
        gf = lock.with_name("Gemfile")
        try:
            gtext = gf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            gtext = ""
        glines, dev_only = _gemfile_dev_only(gtext)
        in_specs = False
        for i, raw in enumerate(text.splitlines(), 1):
            if re.match(r"^\S", raw):
                in_specs = False
                continue
            if raw.strip() == "specs:":
                in_specs = True
                continue
            m = re.match(r"^    ([A-Za-z0-9][\w.-]*) \((\d[\w.]*)(?:-[a-z][\w-]*)?\)\s*$", raw) if in_specs else None
            if not m or m.group(1) in dev_only:
                continue
            where = (gf.relative_to(repo).as_posix(), glines[m.group(1)]) if m.group(1) in glines else (rel, i)
            pins.setdefault(m.group(1), (m.group(2), *where))
    return pins, files


def run_gem_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    pre = precomputed("gem-audit")
    if pre is not None:
        return pre
    info = {"tool": "gem-audit", "role": "known-vulnerable Ruby gems (Gemfile.lock, OSV database)", "version": "osv-v1"}
    pins, files = gem_pins(repo)
    if not files:
        return [], info | {"status": "skipped: no Gemfile.lock"}
    if offline() if no_network is None else no_network:
        return [], info | {"status": "skipped: offline", "files": files}
    try:
        out = _osv_findings("gem-audit", "RubyGems", pins)
    except (OSError, ValueError) as exc:
        return [], info | {"status": f"error: {type(exc).__name__} (network needed?)", "files": files}
    return out, info | {"status": "ok", "files": files, "checked": len(pins)}


if __name__ == "__main__":   # python -m lantern.depaudit REPO OUT.json  (the cloud service's audit step)
    import sys
    Path(sys.argv[2]).write_text(json.dumps(run_all(Path(sys.argv[1]))), encoding="utf-8")
