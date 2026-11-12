"""Known-vulnerable dependency versions, for Python, JavaScript, Java/Kotlin/Android (Gradle and Maven) and PHP.

Both checks ask a public vulnerability database (PyPI/OSV through pip-audit, the npm registry through `npm audit`),
so they are the only network calls `lantern analyze` makes. `--offline` (or LANTERN_OFFLINE=1) skips them, and the
report then says the dependencies were not checked.

Nothing from the analyzed repo is executed or trusted as configuration:
  * Python: exact versions are read from lock files (uv.lock, poetry.lock, pdm.lock, Pipfile.lock), `==` lines in
    requirements*.txt, and `==` pins in pyproject.toml. Only `name==version` pairs reach pip-audit, in a temporary
    file, so index URLs or options in the repo's files are ignored. Ranges (`>=1.2`) can't be checked, because the
    installed version isn't known; they are counted and reported as not checked.
  * JavaScript: `npm audit --package-lock-only` reads package-lock.json (no install, no scripts). npm is started in
    a folder of Lantern's own, on copies laid out as the files lie in the project: package.json, the lock file,
    npm-shrinkwrap.json when it is there (npm up to 11 takes it before the lock file) and the package.json of each folder
    of the project a lock file names (a workspace package, a `file:` library), each handed over as what Lantern
    read in it, written out anew (`_npm_json`). So npm reads no `.npmrc` of the project and no folder outside it
    (`_npm_stage`). Until 2026-11-10 npm ran in the project's folder. The
    registry was passed explicitly, but a `.npmrc` there could still switch the audit off (`offline=true`: nothing
    found, nobody asked, and the record said `ok`), send the question through a proxy of the project's choosing,
    switch the check of the registry's certificate off, make npm write its cache where the project said, and make
    the audit fail; and a lock file or a workspace pattern that named a folder beside the project had npm read
    that folder's package.json. npm is not started where Lantern cannot read one of the files as JSON, on a lock
    file that names a folder by its full path, in words a path and an address read differently, or more than
    `NPM_CLIMB` levels up, nor where package.json, or the lock file's own first entry, asks for workspace folders
    outside its own folder: the record names the file and says why (`partial` when another lock file was
    audited, `failed` when none was).
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

A dependency file comes with the project, so what it says is checked before it is used (2026-11-10, `Odd`):
  * Only a package name and a version of the form the ecosystem defines leave Lantern: for pip-audit's input file
    `PY_NAME` and `PY_VERSION` (PEP 508 names, PEP 440 versions, plain ASCII), for OSV `MAVEN_NAME`, `COMPOSER_NAME`
    and the gem pattern. Until that date a lock file's "version" could add lines of its own to pip-audit's input,
    and one entry pip-audit cannot read (`1.0-SNAPSHOT.final`) made it give up on every package.
  * An entry that is anything else, a file that is not valid TOML or JSON, and a file whose shape is not a lock
    file's (a list where a table belongs) are named in the audit's record: `not_read` (how many), `errors` (the
    first `Odd.KEEP`, each one line of printable ASCII), state `partial`. The rest is still checked. Until that
    date such a file ended the whole analysis with a Python error, or was passed over without a word.
  * What has no released version to look up (a Composer library installed from a branch, a Pipfile.lock entry from
    a link or a folder, a Gradle library whose name holds a variable) is counted in `unpinned`, as ranges are.
  * `guarded` is the wall behind all of it: an audit that raises anything nobody foresaw becomes that audit's
    `failed` record, in the cloud's audit step (`run_all`) and in `security.scan` alike.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import tomllib
from pathlib import Path

from . import listing, manifest, programs, scanresult
from .python_frontend import inside_repo, project_text, skipped_dir

NPM_REGISTRY = "https://registry.npmjs.org/"
TEST_DIR_RE = re.compile(r"(^|/)(tests?|__tests__|fixtures|examples?)/")
PIN_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_\-]*)\s*(;.*)?$")
NOTHING_TO_CHECK = ("skipped: no Python dependency files", "skipped: no package.json", "skipped: no Gradle or Maven files",
                    "skipped: no composer.lock", "skipped: no Gemfile.lock",
                    "skipped: no package.json names a library that ships")
# A project that names libraries in a file with no lock file beside it has no version to ask about, so none of them
# is looked up. That is not "nothing to check": the record counts them (`unlocked`, the first few in
# `unlocked_examples`), its status says a lock file is missing, and a release decision counts them as not checked.
NO_LOCK = "so exact versions are unknown (commit your lock file)"
UNLOCKED_KEEP = 5
OTHER_LOCKS = ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")      # npm's lock files Lantern does not read yet
PLATFORM_PACKAGE = re.compile(r"^(php(-64bit|-ipv6|-zts|-debug)?|hhvm|composer(-plugin-api|-runtime-api)?|"
                              r"(ext|lib)-[\w.-]+)$", re.I)       # composer.json `require`: PHP itself, no library
AUDIT_TOOLS = ("pip-audit", "npm-audit", "maven-audit", "composer-audit", "gem-audit")
OSV_API = "https://api.osv.dev/v1"
# Every host the audits ask: pip-audit's vulnerability service (it runs with --no-deps --disable-pip, so it downloads
# no package), the npm registry, OSV. `lantern analyze` reaches nothing else, so a run that may reach only these
# (python tools/netguard/lantern_netguard.py --allow <these> -- lantern analyze ...) loses nothing.
AUDIT_HOSTS = ("pypi.org", "registry.npmjs.org", "api.osv.dev")
NPM_SEVERITY = {"critical": "HIGH", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW", "info": "LOW"}

# What may leave Lantern as a package name and a version. Plain ASCII, nothing a line of a requirements file or a
# query could be extended with, and no longer than any real one.
PY_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,98}[A-Za-z0-9])?")                       # PEP 508
PY_VERSION = re.compile(r"(?=.{1,100}\Z)v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"                     # PEP 440, appendix B
                        r"(?:[-_.]?(?:alpha|beta|preview|pre|rc|a|b|c)[-_.]?[0-9]*)?"
                        r"(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?(?:[-_.]?dev[-_.]?[0-9]*)?"
                        r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?", re.I | re.A)
MAVEN_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,200}:[A-Za-z0-9_.\-]{1,200}")                      # group:artifact
COMPOSER_NAME = re.compile(r"(?=.{3,200}\Z)[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+")                # vendor/package
COMPOSER_VERSION = re.compile(r"(?=.{1,100}\Z)v?[0-9]+(?:\.[0-9]+)*(?:[-.+][A-Za-z0-9_.+\-]+)?")
COMPOSER_BRANCH = re.compile(r"[\x21-\x7e]{1,100}")                                            # dev-main, 2.x-dev
GEM_LINE = re.compile(r"    ([A-Za-z0-9][A-Za-z0-9_.\-]{0,199}) \(([0-9][A-Za-z0-9_.]{0,99})(?:-[a-z][A-Za-z0-9_.\-]*)?\)\s*")
NOT_THE_PROJECTS = "a link that does not lead to a file of the project, so it was not read"
MAX_FILE = 32 * 1024 * 1024             # a dependency file larger than this is not read (the largest real ones: a few MB)


def _shown(value, limit: int = 60) -> str:
    """What a project's file says, as it may be kept in a record and shown on a console and in the report: for text,
    one line of printable ASCII in quotes (anything else as an escape), cut short; for anything else, what it is."""
    if isinstance(value, str):
        text = value[:limit + 1].encode("unicode_escape").decode("ascii")
        return '"' + (text if len(value) <= limit and len(text) <= limit else text[:limit] + "...") + '"'
    return {dict: "a table", list: "a list", bool: "true or false", int: "a number", float: "a number",
            type(None): "nothing"}.get(type(value), "not text")


def _plain(text, limit: int = 200) -> str:
    """`text` as one line of printable ASCII, cut short: a file's name or a line of it, for a record. Every other
    character becomes an escape; what is printable ASCII already stays as it is."""
    return re.sub(r"[^\x20-\x7e]", lambda m: m.group().encode("unicode_escape").decode("ascii"), str(text)[:limit])[:limit]


def _short(rel: str) -> str:
    """A file's name for a line of the record: of a long path the end is kept (the file's own name), so what is said
    of the file still fits on the line."""
    return rel if len(rel) <= 100 else "..." + rel[-97:]


def _unlocked(found: list[tuple[str, str]]) -> dict:
    """What an audit's record says of the libraries (file, name) a project names where no lock file says which
    version is installed: how many, and the first few. Nothing at all when there are none."""
    found = sorted(set(found))
    if not found:
        return {}
    return {"unlocked": len(found),
            "unlocked_examples": [_plain(f"{_short(rel)}: {name}") for rel, name in found[:UNLOCKED_KEEP]]}


class Odd:
    """What in a project's dependency files is not a package name and a version, or not a dependency file at all:
    counted, and the first `KEEP` named in plain words, for the audit's record. A file named here counts as one of
    the project's dependency files even when nothing in it could be read."""
    KEEP = 20

    def __init__(self) -> None:
        self.count = 0
        self.lines: list[str] = []
        self.files: set[str] = set()

    def add(self, rel: str, what: str) -> None:
        self.count += 1
        self.files.add(rel)
        if len(self.lines) < self.KEEP:
            self.lines.append(_plain(f"{_short(rel)}: {what}"))

    def fields(self) -> dict:
        """What the record says of them: nothing at all when there are none."""
        return {"not_read": self.count, "errors": list(self.lines)} if self.count else {}

    def why(self, also: str = "") -> str:
        """The record's reason: these, and `also` (what the audit itself could not finish) when there is any."""
        n = self.count
        said = (f"{n} part{'s' if n != 1 else ''} of the dependency files could not be read as a package name and "
                "version") if n else ""
        return "; ".join(x for x in (said, also) if x)


def _read(p: Path, rel: str, odd: Odd, repo: Path) -> str | None:
    """The text of a dependency file of the project, or None with the reason kept in `odd`: only a plain file of a
    size a real one has is read (a pipe or a device under such a name would hold the analysis up for good), and only
    one that lies in the project (a link that leads out of it names somebody else's libraries, and Lantern would ask
    the audit services about them)."""
    try:
        if not inside_repo(p, repo):   # said in the same words whatever the link leads to, a file or nothing at all
            odd.add(rel, NOT_THE_PROJECTS if os.path.islink(p) else "not a plain file, so it was not read")
            return None
        if os.stat(p).st_size > MAX_FILE:
            odd.add(rel, f"larger than {MAX_FILE // (1024 * 1024)} MB, so it was not read")
            return None
        return project_text(p, repo).removeprefix("\ufeff")   # the mark some editors put first
    except OSError as exc:
        odd.add(rel, f"could not be read ({type(exc).__name__})")
        return None


def _quiet(p: Path, repo: Path) -> str:
    """The text of a file that only says where a library is written (composer.json, Gemfile): "" when it is not
    there or cannot be read, which costs a line number and nothing else."""
    return _read(p, p.name, Odd(), repo) or ""


def _toml(text: str | None, rel: str, odd: Odd) -> dict | None:
    """The table a TOML file holds, or None with the reason kept in `odd` (`text` None: `_read` has said why)."""
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        at = re.search(r"at line (\d+)", str(exc))
        odd.add(rel, "not valid TOML" + (f" (line {at.group(1)})" if at else "") + ", so it was not read")
        return None


def _json(text: str | None, rel: str, odd: Odd):
    """(True, the value a JSON file holds) or (False, None) with the reason kept in `odd`."""
    if text is None:
        return False, None
    try:
        return True, json.loads(text)
    except (ValueError, RecursionError) as exc:
        odd.add(rel, "not valid JSON" + (f" (line {exc.lineno})" if isinstance(exc, json.JSONDecodeError) else "")
                + ", so it was not read")
        return False, None


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


def audits() -> tuple:
    """Every audit as (tool, function), looked up when asked, so a test's stand-in for one of them is the one run."""
    return (("pip-audit", run_pip_audit), ("npm-audit", run_npm_audit), ("maven-audit", run_maven_audit),
            ("composer-audit", run_composer_audit), ("gem-audit", run_gem_audit))


def guarded(tool: str, fn, repo: Path, no_network: bool | None) -> tuple[list[dict], dict]:
    """One audit with a wall behind it: whatever it raises that nobody foresaw (a registry down, odd output, a
    dependency file of a shape no reader expected) becomes that audit's `failed` record, and the others still run.
    The error's own words are left out: they can hold text of the project's files."""
    try:
        return fn(repo, no_network)
    except Exception as exc:  # noqa: BLE001 - one audit's surprise must not drop the others, or the whole analysis
        asked = not (offline() if no_network is None else no_network)
        return [], scanresult.record(tool, "failed", f"{type(exc).__name__} "
                                     + ("(network needed?)" if asked else "(while reading the project's dependency files)"))


def run_all(repo: Path) -> dict:
    """All audits with the network on, as {tool: {findings, info}} (what LANTERN_AUDITS_FROM reads)."""
    out = {}
    with listing.one_run(repo):     # the audits ask twelve times which files there are: one walk
        for tool, fn in audits():
            f, info = guarded(tool, fn, repo, False)
            out[tool] = {"findings": f, "info": info}
    return out


def offline() -> bool:
    return os.environ.get("LANTERN_OFFLINE", "").strip() not in ("", "0", "false", "no")


def _project_files(repo: Path, names: tuple[str, ...] | None = None, pattern: re.Pattern | None = None) -> list[Path]:
    """The names in the project itself that are dependency files: not vendored, not in tests or sample apps. A name
    is listed whatever answers to it (a link that leads out of the project, a pipe), so that the audit's record can
    say it was not read: `_read` is the one way such a file is opened, and it opens a file of the project only."""
    out = []
    for dirpath, fn in listing.once(repo, "dependency-files", lambda: _names(repo)):
        if (names and fn in names) or (pattern and pattern.search(fn)):
            p = Path(dirpath) / fn
            rel = p.relative_to(repo).as_posix()
            if not TEST_DIR_RE.search(rel):
                out.append(p)
    return sorted(out)


def _names(repo: Path) -> list[tuple[str, str]]:
    """Every name in the project's folders, with the folder it is in: not under a folder Lantern leaves out, not
    under `node_modules`, and a folder that is a link is not walked into. One walk for all the audits of a run
    (`listing.once`): until 2026-11-12 each of the twelve questions the audits ask walked the whole project, beside
    the reading of the code."""
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if not skipped_dir(dirpath, d) and d != "node_modules"]
        out.extend((dirpath, fn) for fn in filenames)
    return out


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------- Python

def python_pins(repo: Path, odd: Odd | None = None) -> tuple[dict[str, tuple[str, str]], list[str], list[str]]:
    """{normalized name: (version, file it came from)}, the unpinned requirement texts, and the files read. What is
    no package name and version, and what could not be read, goes to `odd`."""
    odd = odd if odd is not None else Odd()
    pins: dict[str, tuple[str, str]] = {}
    loose: list[str] = []
    files: list[str] = []

    def add(name, version, rel: str, where: str) -> None:
        if not isinstance(name, str) or not PY_NAME.fullmatch(name):
            odd.add(rel, f"{where}: {_shown(name)} is not a package name")
        elif not isinstance(version, str) or not PY_VERSION.fullmatch(version):
            odd.add(rel, f"{name}: {_shown(version)} is not a version")
        else:
            pins.setdefault(_norm(name), (version, rel))

    for p in _project_files(repo, names=("uv.lock", "poetry.lock", "pdm.lock")):
        rel = p.relative_to(repo).as_posix()
        files.append(rel)
        data = _toml(_read(p, rel, odd, repo), rel, odd)
        packages = data.get("package") if data is not None else None
        if packages is None:
            continue
        if not isinstance(packages, list):
            odd.add(rel, f"its packages are {_shown(packages)}, not a list")
            continue
        for i, pkg in enumerate(packages, 1):
            if not isinstance(pkg, dict):
                odd.add(rel, f"entry {i} is {_shown(pkg)}, not a package")
                continue
            src = pkg.get("source") or {}
            if isinstance(src, dict) and (src.get("editable") or src.get("virtual") or src.get("directory")):
                continue   # the project itself, not a published package
            name = pkg.get("name")
            if "version" not in pkg and isinstance(name, str) and PY_NAME.fullmatch(name):
                loose.append(f"{rel}: {name} (no version written)")
                continue
            add(name, pkg.get("version"), rel, f"entry {i}")
    for p in _project_files(repo, names=("Pipfile.lock",)):
        rel = p.relative_to(repo).as_posix()
        files.append(rel)
        ok, data = _json(_read(p, rel, odd, repo), rel, odd)
        if not ok:
            continue
        default = data.get("default") if isinstance(data, dict) else None
        if not isinstance(data, dict) or not isinstance(default, (dict, type(None))):
            odd.add(rel, f"its {'default packages are' if isinstance(data, dict) else 'content is'} "
                         f"{_shown(default if isinstance(data, dict) else data)}, not a table")
            continue
        for name, spec in (default or {}).items():
            if not isinstance(spec, dict):
                odd.add(rel, f"{_shown(name)} is {_shown(spec)}, not a package")
            elif spec.get("version") is None and PY_NAME.fullmatch(name):
                loose.append(f"{rel}: {name} (from a link or a folder: no released version)")
            else:
                v = spec.get("version")
                add(name, v[2:] if isinstance(v, str) and v.startswith("==") else v, rel, "default")
    for p in _project_files(repo, pattern=re.compile(r"^requirements[^/]*\.txt$")):
        rel = p.relative_to(repo).as_posix()
        files.append(rel)
        for ln in (_read(p, rel, odd, repo) or "").splitlines():
            s = ln.split(" #")[0].strip()
            if not s or s.startswith(("#", "-")):
                continue
            m = PIN_RE.match(s.split("--hash")[0].strip().rstrip("\\").strip())
            if m:
                add(m.group(1), m.group(3), rel, "a line")
            else:
                loose.append(f"{rel}: {_plain(s, 60)}")
    for p in _project_files(repo, names=("pyproject.toml",)):
        rel = p.relative_to(repo).as_posix()
        data = _toml(_read(p, rel, odd, repo), rel, odd)
        if data is None:
            continue
        deps: list = []
        project, tool = data.get("project"), data.get("tool")
        if not isinstance(project, (dict, type(None))):
            odd.add(rel, f"its [project] is {_shown(project)}, not a table")
        elif not isinstance((project or {}).get("dependencies"), (list, type(None))):
            odd.add(rel, f"its dependencies are {_shown(project['dependencies'])}, not a list")
        else:
            deps += (project or {}).get("dependencies") or []
        poetry = tool.get("poetry") if isinstance(tool, dict) else None
        named = poetry.get("dependencies") if isinstance(poetry, dict) else None
        if not isinstance(tool, (dict, type(None))) or not isinstance(poetry, (dict, type(None))) \
                or not isinstance(named, (dict, type(None))):
            odd.add(rel, "its [tool.poetry] dependencies are not a table")
        else:
            deps += [k + ("==" + v if isinstance(v, str) and re.match(r"^\d", v) else "")
                     for k, v in (named or {}).items() if k.lower() != "python"]
        if deps:
            files.append(rel)
        for d in deps:
            if not isinstance(d, str):
                odd.add(rel, f"a dependency is {_shown(d)}, not text")
                continue
            m = PIN_RE.match(d)
            if m:
                add(m.group(1), m.group(3), rel, "a dependency")
            elif _norm(re.split(r"[\s<>=!~\[;(@]", d, maxsplit=1)[0]) not in pins:
                loose.append(f"{rel}: {_plain(d, 60)}")
    # a range in pyproject is fine when a lock file pins the same package
    loose = [x for x in loose if _norm(re.split(r"[\s<>=!~\[;(@]", x.split(": ", 1)[1], maxsplit=1)[0]) not in pins]
    return pins, loose, sorted(set(files) | odd.files)


PIP_AUDIT_TIMEOUT = 300


def run_pip_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    """pip-audit over the exact versions found in the repo. Exit 0 = ran, nothing known; exit 1 = ran, found
    vulnerabilities; anything else is a failure. A package pip-audit could not look up (`skip_reason`), and an entry
    of the project's files that is no package name and version (`Odd`), make the run `partial` and are listed; the
    findings for the others are kept."""
    from .security import _fid
    pre = precomputed("pip-audit")
    if pre is not None:
        return pre
    info: dict = {"role": "known-vulnerable Python packages", "version": _pkg_version("pip-audit")}
    odd = Odd()
    pins, loose, files = python_pins(repo, odd)
    if not files:
        return [], scanresult.record("pip-audit", "skipped", "no Python dependency files", **info)
    if not pins and odd.count:      # nothing in these files can be asked about, so nobody is asked, and that is said
        return [], scanresult.record("pip-audit", "partial", odd.why(), files=files, unpinned=len(loose),
                                     **odd.fields(), **info)
    if not pins:
        return [], scanresult.record("pip-audit", "skipped", "no exact versions to check (commit a lock file such as "
                                     "uv.lock or poetry.lock, or pin with ==)", applicable=False, files=files,
                                     unpinned=len(loose), **info)
    pip_audit = programs.find("pip-audit")
    if not pip_audit:
        return [], scanresult.record("pip-audit", "unavailable", 'pip install "lantern[scan]"', files=files, **info)
    if offline() if no_network is None else no_network:
        return [], scanresult.record("pip-audit", "skipped", "offline", applicable=True, files=files, **info)
    info |= {"files": files, "scope": {"files": files, "packages": len(pins)}, "checked": len(pins),
             "unpinned": len(loose), "unpinned_examples": loose[:5]}
    with tempfile.TemporaryDirectory() as td:
        req = Path(td) / "requirements.txt"
        req.write_text("".join(f"{n}=={v}\n" for n, (v, _) in sorted(pins.items())), encoding="utf-8")
        cmd = [pip_audit, "-r", str(req), "-f", "json", "--progress-spinner", "off", "--no-deps", "--disable-pip"]
        run = scanresult.run_tool(cmd, timeout=PIP_AUDIT_TIMEOUT)
    info |= {"exit_code": run.returncode, "duration_ms": run.duration_ms}
    if run.timed_out:
        return [], scanresult.record("pip-audit", "timeout", f"after {PIP_AUDIT_TIMEOUT} s", **info)
    if run.error:
        return [], scanresult.record("pip-audit", "failed", f"{run.error} (network needed?)", **info)
    err = scanresult.tail(run.stderr)
    if run.returncode not in (0, 1):
        return [], scanresult.record("pip-audit", "failed", f"exit code {run.returncode}: {err or 'no message'} "
                                     "(network needed?)", **info)
    data, why = scanresult.parse_json(run.stdout, dict)
    if data is None:
        return [], scanresult.record("pip-audit", "failed", why + (f"; stderr: {err}" if err else ""), **info)
    if not isinstance(data.get("dependencies"), list):
        return [], scanresult.record("pip-audit", "failed", "no dependencies list in the output", **info)
    out, errors = [], []
    for dep in data["dependencies"]:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name") or "")
        if dep.get("skip_reason"):
            errors.append(f"{name or '?'}: {str(dep['skip_reason'])[:160]}")
            continue
        for v, aliases in _advisories(dep.get("vulns") or []):
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
    info["findings"] = len(out)
    if errors or odd.count:
        also = f"{len(errors)} package{'s' if len(errors) != 1 else ''} could not be checked" if errors else ""
        return out, scanresult.record("pip-audit", "partial", odd.why(also), **(info | odd.fields()
                                                                               | {"errors": odd.lines + errors}))
    return out, scanresult.record("pip-audit", "ok", **info)


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

NPM_AUDIT_TIMEOUT = 180
NPM_READS = ("package.json", "package-lock.json", "npm-shrinkwrap.json")   # npm up to 11 takes the last before the lock file
NPM_CLIMB = 16                          # how many `..` one entry of a lock file may hold
NPM_LOCAL_MAX = 5000                    # how many folders of its own a lock file may name (workspace packages, `file:` libraries)
NPM_LOCAL_BYTES = 64 * 1024 * 1024      # and what their package.json files may hold together
NPM_LINE = 300                          # a line of the record about npm: longer than any of them gets
NOT_STARTED = "so npm was not started on it"
NPM_FULL = re.compile(r"/|[A-Za-z][:|]")                        # how a full path starts, as a path and as an address
NPM_TWICE = re.compile(r"[%\x00-\x1f\x7f]")                     # read one way in a path and another in an address
NPM_ELSEWHERE = re.compile(r"(?!file:)[a-z][a-z0-9+.\-]+:", re.I)   # https:, git+ssh:, github:, npm: are no folders
NPM_BRACES = re.compile(r"\.[{},]|[{},]\.|[{,]/|[{,][,}]")      # braces that can put `..` or a leading `/` together


def _npm_version(npm: str) -> str | None:
    run = scanresult.run_tool([npm, "--version"], timeout=30)
    return (run.stdout or "").strip()[:20] or None


def _npm_json(p: Path, rel: str, odd: Odd, repo: Path) -> tuple | None:
    """A JSON file npm is to read, as (what it holds, the same written out anew), or None with the reason kept in
    `odd`. npm is handed what Lantern read, never a file's own text: two readers of one text can disagree (a name
    that stands twice, JSON nested deeper than Python follows and Node reads), and npm would then follow what
    Lantern never saw."""
    ok, value = _json(_read(p, rel, odd, repo), rel, odd)
    if not ok:
        return None
    try:
        return value, json.dumps(value, allow_nan=False)
    except (ValueError, RecursionError):        # NaN, a number too large: JSON for Python, not for npm
        odd.add(rel, "not valid JSON, so it was not read")
        return None


def _npm_places(lock: dict) -> list[str]:
    """What in a lock file may name a folder on this computer: every key of `packages` and what an entry marked as
    a link points at (a workspace package, a `file:` library; npm takes anything but false, 0, "" and nothing for
    the mark, and joins what the entry points at to its folder as a path, whatever it looks like), and from the
    older `dependencies` list each `version`, `from` and `resolved` that is not an address somewhere else (npm
    reads `file:…` and a bare path there as a folder)."""
    out: list[str] = []
    for key, entry in manifest.table(lock.get("packages")).items():
        entry = manifest.table(entry)
        out.append(key)
        if entry.get("link") not in (None, False) and isinstance(entry.get("resolved"), str):
            out.append(entry["resolved"])
    todo = [manifest.table(lock.get("dependencies"))]
    while todo:
        for entry in todo.pop().values():
            entry = manifest.table(entry)
            out += [entry[k] for k in ("version", "from", "resolved")
                    if isinstance(entry.get(k), str) and not NPM_ELSEWHERE.match(entry[k])]
            if entry.get("dependencies"):
                todo.append(manifest.table(entry["dependencies"]))
    return list(dict.fromkeys(re.sub(r"^file:", "", p, flags=re.I) for p in out if p))


def _npm_wanders(package) -> str | None:
    """The first workspace pattern of what a `package.json` holds that may lead npm out of the folder the file lies
    in (npm reads the `package.json` of every folder such a pattern finds): one with `..`, a full path, a backslash,
    or braces that can put either together. None when there is none."""
    asked = manifest.table(package).get("workspaces")
    if isinstance(asked, dict):
        asked = asked.get("packages")
    for pattern in [asked] if isinstance(asked, str) else manifest.texts(asked):
        p = pattern.lstrip("!")
        if ".." in p or "\\" in p or ":" in p or p.startswith("/") or NPM_BRACES.search(p):
            return pattern
    return None


def _npm_stage(lock: Path, repo: Path, own: Path) -> tuple[Path | None, list[str]]:
    """What npm is to read, as copies in `own`, a folder of Lantern's own: (the folder to start npm in, what was
    left out and why), or (None, [why]) and npm is then not started on this lock file. Each line names its file.

    npm takes settings from the folder it is started in (`.npmrc`), so it is never started in the project. The copy
    keeps the project's layout: `package.json`, `package-lock.json` and `npm-shrinkwrap.json` (npm up to 11 prefers it) at the
    lock file's place, and the `package.json` of each folder the lock file names inside the project (npm reads it for
    every workspace package and `file:` library; without it a workspace package and all it needs are left out of the
    audit without a word). Every file is read the way any dependency file is (`_read`: a plain file of the project,
    of a size a real one has) and handed over as what Lantern read in it, written out anew (`_npm_json`); one that
    Lantern cannot read is not handed over.

    npm reads nothing outside `own`. A folder the lock file names outside the project is not copied, and the copy
    lies as many folders deep in `own` as any entry of the lock file holds `..`, so nothing is where such an entry
    points. What cannot be kept in that way is refused: a folder named by its full path, by words a path and an
    address read differently (`%`, a control character, `~`), more than `NPM_CLIMB` levels up, and a workspace
    pattern that leaves its folder (`_npm_wanders`), in `package.json` or in a lock file's own first entry, which
    npm takes in its place when it cannot use that file."""
    here = lock.parent
    base = list(here.relative_to(repo).parts)
    rel = "/".join([*base, lock.name])

    def refused(why: str) -> tuple[None, list[str]]:
        return None, [_plain(f"{_short(rel)}: {why}, {NOT_STARTED}", NPM_LINE)]

    odd = Odd()
    read = {name: _npm_json(here / name, name, odd, repo) for name in NPM_READS
            if name != "npm-shrinkwrap.json" or os.path.lexists(here / name)}
    if odd.count:
        return None, [_plain(f"{_short(rel)}: npm was not started on it ({odd.lines[0]})", NPM_LINE)]
    spots: dict[tuple[str, ...], None] = {}     # the folders inside the project npm reads a package.json in
    climb = 0
    for name, (value, _) in read.items():
        first = value if name == "package.json" else manifest.table(manifest.table(value).get("packages")).get("")
        wanders = _npm_wanders(first)
        if wanders is not None:
            who = "" if name == lock.name else f"its {name} "
            return refused(f"{who}asks for workspace folders outside its own folder ({_shown(wanders)})")
        for place in [] if name == "package.json" else _npm_places(manifest.table(value)):
            way = place.replace("\\", "/")
            steps = way.split("/")
            if NPM_FULL.match(way):
                return refused(f"names a folder by its full path ({_shown(place)})")
            if NPM_TWICE.search(way) or "~" in steps:
                return refused(f"names a folder in words that programs read in different ways ({_shown(place)})")
            climb = max(climb, way.count(".."))
            parts, out = list(base), False
            for step in steps:
                if step == "..":
                    out = out or not parts
                    parts = parts[:-1]
                elif step not in ("", "."):
                    parts.append(step)
            if not out and parts != base and "node_modules" not in parts:
                spots[tuple(parts)] = None
    if climb > NPM_CLIMB:
        return refused(f"names a folder {climb} levels up")
    top = own.joinpath(*["above"] * climb, "project")
    where = top.joinpath(*base)
    where.mkdir(parents=True)
    for name, (_, text) in read.items():
        (where / name).write_text(text, encoding="utf-8")
    left: list[str] = []
    copied, room = 0, NPM_LOCAL_BYTES
    for parts in spots:
        try:
            source, to = repo.joinpath(*parts, "package.json"), top.joinpath(*parts, "package.json")
            if repo not in source.parents or top not in to.parents or not os.path.lexists(source):
                continue                    # a name that is no folder of the project here; npm finds none there either
            one, name = Odd(), "/".join([*parts, "package.json"])
            got = _npm_json(source, name, one, repo)
            if got is None:                 # a link that leads out of the project, a pipe, no JSON: said, and not copied
                left.append(one.lines[0])
                continue
            wanders = _npm_wanders(got[0])
            if wanders is not None:
                left.append(_plain(f"{_short(name)}: asks for workspace folders outside its own folder "
                                   f"({_shown(wanders)}), so npm was not given it", NPM_LINE))
                continue
            copied, room = copied + 1, room - len(got[1])
            if copied > NPM_LOCAL_MAX:
                return refused(f"names more than {NPM_LOCAL_MAX} folders of its own")
            if room < 0:
                return refused("the package.json files of the folders it names hold more than "
                               f"{NPM_LOCAL_BYTES // (1024 * 1024)} MB together")
            to.parent.mkdir(parents=True, exist_ok=True)
            to.write_text(got[1], encoding="utf-8")
        except ValueError:                  # a name no file can have (a NUL in it): there is none
            continue
    return where, left


def _npm_unlocked(manifests: list[Path], repo: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Of the package.json files with no package-lock.json beside them: the libraries each names for the shipped app
    (`dependencies`, `optionalDependencies`) where no lock file of any kind says which versions are installed, as
    (file, name); and the folders whose versions are in a lock file Lantern does not read yet (pnpm, yarn, bun,
    beside the file or in a folder above it). A folder that a package-lock.json further up lists among its packages
    (an npm workspace) is neither: that lock file is checked, and it holds this folder's libraries."""
    named: list[tuple[str, str]] = []
    elsewhere: list[str] = []
    locks: dict[Path, dict | None] = {}

    def lock_of(folder: Path) -> dict | None:
        if folder not in locks:
            p = folder / "package-lock.json"
            text = _read(p, p.name, Odd(), repo) if inside_repo(p, repo) else None
            locks[folder] = manifest.table(manifest.parse_json(text)) if text is not None else None
        return locks[folder]

    for m in manifests:
        folder = m.parent
        if inside_repo(folder / "package-lock.json", repo):
            continue
        rel = m.relative_to(repo).as_posix()
        covered = other = False
        at = folder
        while True:
            if any((at / x).is_file() for x in OTHER_LOCKS):
                other = True
                break
            if at != folder:
                lock = lock_of(at)
                if lock is not None:
                    inner = folder.relative_to(at).as_posix()
                    packages = manifest.table(lock.get("packages"))
                    if inner in packages or (not packages and "workspaces" in manifest.table(
                            manifest.parse_json(_quiet(at / "package.json", repo) or "{}"))):
                        covered = True
                        break
            if at == repo or repo not in at.parents:
                break
            at = at.parent
        if covered:
            continue
        if other:
            elsewhere.append(folder.relative_to(repo).as_posix() or ".")
            continue
        text = _read(m, rel, Odd(), repo)
        data = manifest.parse_json(text) if text is not None else None
        if not isinstance(data, dict):
            named.append((rel, "(what it names could not be read)"))
            continue
        for part in ("dependencies", "optionalDependencies"):
            named += [(rel, _plain(k, 80)) for k in manifest.table(data.get(part)) if isinstance(k, str)]
    return named, elsewhere


def run_npm_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    """`npm audit --package-lock-only` per lock file. Exit 0 = nothing known, exit 1 = vulnerabilities (or an error
    npm reports as JSON `{"error": …}`, which is read as a failure). One lock file failing while another was checked
    makes the run `partial`; all failing is `failed` (or `timeout` when every one timed out)."""
    from .security import _fid
    pre = precomputed("npm-audit")
    if pre is not None:
        return pre
    info: dict = {"role": "known-vulnerable npm packages (production dependencies)"}
    manifests = [m for m in _project_files(repo, names=("package.json",)) if inside_repo(m, repo)]   # npm reads it itself
    if not manifests:
        return [], scanresult.record("npm-audit", "skipped", "no package.json", **info)
    # npm reads the lock file itself: one that is a link out of the project counts as none (npm would send the
    # names in somebody else's file to the registry)
    locks = [m.parent / "package-lock.json" for m in manifests if inside_repo(m.parent / "package-lock.json", repo)]
    other = [m.parent.relative_to(repo).as_posix() or "." for m in manifests
             if not inside_repo(m.parent / "package-lock.json", repo)]
    named, elsewhere = _npm_unlocked(manifests, repo)
    info |= _unlocked(named)
    if elsewhere and locks:     # beside folders that are checked: said on the record, which may end as `ok`
        info["other_locks"] = elsewhere[:10]
    if not locks:
        if any((m.parent / x).is_file() for m in manifests for x in ("pnpm-lock.yaml", "yarn.lock", "bun.lock")):
            # the project's exact versions exist but Lantern cannot read them yet: a gap on Lantern's side
            return [], scanresult.record("npm-audit", "skipped", "pnpm-lock.yaml / yarn.lock / bun.lock aren't read "
                                         "yet; run `pnpm audit` or `yarn npm audit`", applicable=True, **info)
        if not named and not elsewhere:
            return [], scanresult.record("npm-audit", "skipped", "no package.json names a library that ships", **info)
        return [], scanresult.record("npm-audit", "skipped", f"no package-lock.json, {NO_LOCK}", applicable=False,
                                     **info)
    if offline() if no_network is None else no_network:
        return [], scanresult.record("npm-audit", "skipped", "offline", applicable=True, **info)
    npm = programs.find("npm")
    if not npm:
        return [], scanresult.record("npm-audit", "unavailable", "npm is not on this computer", **info)
    info["version"] = _npm_version(npm)
    out, files, errors, timeouts = [], [], [], 0
    codes: dict[str, int | None] = {}
    duration = 0
    for lock in locks:
        rel = lock.relative_to(repo).as_posix()
        cmd = [npm, "audit", "--json", "--package-lock-only", "--omit=dev", f"--registry={NPM_REGISTRY}"]
        run = None
        try:
            with programs.folder() as own:      # never in the project: npm would take its `.npmrc` for settings
                where, left = _npm_stage(lock, repo, own)
                if where is not None:
                    run = scanresult.run_tool(cmd, timeout=NPM_AUDIT_TIMEOUT, cwd=where,
                                              env={**os.environ, "npm_config_audit_level": "info"})
        except OSError as exc:
            left = [f"{rel}: a folder of Lantern's own for npm could not be made ({type(exc).__name__}), {NOT_STARTED}"]
        errors += left
        if run is None:
            continue
        codes[rel] = run.returncode
        duration += run.duration_ms
        if run.timed_out:
            errors.append(f"{rel}: timed out")
            timeouts += 1
            continue
        if run.error:
            errors.append(f"{rel}: {run.error}")
            continue
        data, why = scanresult.parse_json(run.stdout, dict)
        if data is None:
            err = scanresult.tail(run.stderr)
            errors.append(f"{rel}: {why}" + (f" (exit code {run.returncode}; {err})" if err else f" (exit code {run.returncode})"))
            continue
        if isinstance(data.get("error"), dict) and "vulnerabilities" not in data:
            e = data["error"]
            errors.append(f"{rel}: {str(e.get('code') or 'error')[:40]}: {str(e.get('summary') or 'failed')[:120]}")
            continue
        if run.returncode not in (0, 1):
            errors.append(f"{rel}: exit code {run.returncode}: {scanresult.tail(run.stderr) or 'no message'}")
            continue
        if not isinstance(data.get("vulnerabilities"), dict):
            errors.append(f"{rel}: no vulnerabilities list in the output")
            continue
        files.append(rel)
        for name, v in data["vulnerabilities"].items():
            if not isinstance(v, dict):
                continue
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
    info |= {"files": files, "scope": {"files": files}, "findings": len(out), "duration_ms": duration,
             "exit_code": next(iter(codes.values())) if len(codes) == 1 else None, "exit_codes": codes}
    if other:
        info["not_checked"] = other[:10]
    if files and not errors:
        return out, scanresult.record("npm-audit", "ok", **info)
    if files:
        return out, scanresult.record("npm-audit", "partial", "; ".join(errors)[:300], errors=errors, **info)
    if timeouts == len(locks):
        return out, scanresult.record("npm-audit", "timeout", f"after {NPM_AUDIT_TIMEOUT} s per lock file", errors=errors, **info)
    return out, scanresult.record("npm-audit", "failed", "; ".join(errors)[:300], errors=errors, **info)



# ---------------------------------------------------------------------------- Gradle / Maven (OSV)

GRADLE_FILES = ("build.gradle", "build.gradle.kts")
# Configurations that ship with the app (test and lint configurations are left out, like npm's --omit=dev)
GRADLE_DEP = re.compile(r"^\s*(implementation|api|compile|runtimeOnly|compileOnly|releaseImplementation|kapt|ksp|"
                        r"annotationProcessor|coreLibraryDesugaring|\w+Implementation)(?<!testImplementation)"
                        r"(?<!androidTestImplementation)(?<!debugImplementation)\s*\(?\s*(?:platform\()?"
                        r"[\"']([\w.\-]+):([\w.\-]+):([^\"'@\s]+)[\"']", re.M)
GRADLE_VAR = re.compile(r"^\s*(?:ext\.)?(?:val\s+|def\s+)?(\w+)\s*=\s*[\"']([\w.\-]+)[\"']", re.M)
MAVEN_VERSION = re.compile(r"[0-9][A-Za-z0-9_.\-]{0,99}")     # one version: no `+`, no range, no variable
OSV_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "moderate", "MEDIUM": "moderate", "LOW": "low"}


def maven_coords(repo: Path, odd: Odd | None = None) -> tuple[dict[str, tuple[str, str, int]], list[str], list[str]]:
    """{"group:name": (version, file, line)}, the libraries with no exact name and version to look up
    ("group:name:1.+", a name that holds a variable), files read. What is no library at all, and what could not be
    read, goes to `odd`."""
    odd = odd if odd is not None else Odd()
    pins: dict[str, tuple[str, str, int]] = {}
    loose: list[str] = []
    files: list[str] = []

    def add(coord: str, ver: str, rel: str, line: int):
        if MAVEN_NAME.fullmatch(coord) and MAVEN_VERSION.fullmatch(ver):
            pins.setdefault(coord, (ver, rel, line))
        else:
            loose.append(_plain(f"{coord}:{ver}", 120))

    for p in _project_files(repo, names=GRADLE_FILES):
        rel = p.relative_to(repo).as_posix()
        text = _read(p, rel, odd, repo)
        if text is None:
            continue
        text = text[:2_000_000]
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
        text = _read(p, rel, odd, repo)
        cat = _toml(text, rel, odd)
        if cat is None:
            continue
        files.append(rel)
        versions, libraries = cat.get("versions"), cat.get("libraries")
        if not isinstance(versions, (dict, type(None))):
            odd.add(rel, f"its versions are {_shown(versions)}, not a table")
            versions = None
        if not isinstance(libraries, (dict, type(None))):
            odd.add(rel, f"its libraries are {_shown(libraries)}, not a table")
            continue
        for key, lib in (libraries or {}).items():
            where = f"library {_shown(key, 40)}"
            if isinstance(lib, str):                        # "group:name:version"
                parts = lib.split(":")
                if len(parts) not in (2, 3):
                    odd.add(rel, f"{where} is {_shown(lib)}, not group:name:version")
                    continue
                coord, ver = ":".join(parts[:2]), (parts[2] if len(parts) == 3 else None)
            elif isinstance(lib, dict):
                coord = lib.get("module")
                if coord is None:
                    group, name = lib.get("group"), lib.get("name")
                    coord = f"{group}:{name}" if isinstance(group, str) and isinstance(name, str) else \
                        (name if isinstance(group, str) else group)
                if not isinstance(coord, str):
                    odd.add(rel, f"{where} has {_shown(coord)} where its group and name belong")
                    continue
                ver = lib.get("version")
                if isinstance(ver, dict) and "ref" in ver:  # the name of an entry of [versions]
                    ref = ver["ref"]
                    if not isinstance(ref, str):
                        odd.add(rel, f"{where} names its version with {_shown(ref)}, not with a name")
                        continue
                    ver = (versions or {}).get(ref)
                if not isinstance(ver, (str, dict, type(None))):    # a table here is strictly / require / prefer
                    odd.add(rel, f"{where} has {_shown(ver)} where its version belongs")
                    continue
            else:
                odd.add(rel, f"{where} is {_shown(lib)}, not a library")
                continue
            if "test" in key.lower() or "junit" in coord or "espresso" in coord:
                continue
            if ver is None or isinstance(ver, dict):        # no one version: it comes from a place Lantern does not read
                loose.append(_plain(f"{coord} ({'a range of versions' if isinstance(ver, dict) else 'no version written'})", 120))
                continue
            pos = text.find(key)
            add(coord, ver, rel, text.count("\n", 0, pos) + 1 if pos >= 0 else 1)
    for p in _project_files(repo, names=("pom.xml",)):
        rel = p.relative_to(repo).as_posix()
        text = _read(p, rel, odd, repo)
        if text is None:
            continue
        text = text[:2_000_000]
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
    return pins, loose, files + sorted(odd.files - set(files))


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


class OSVAnswer(ValueError):
    """OSV answered in a shape Lantern does not understand (no results list, or not one answer per query)."""


OSV_DETAIL_LIMIT = 300


def _osv_failure(exc: Exception) -> tuple[str, str]:
    """The state and reason for an OSV audit that could not finish."""
    if isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
        return "timeout", f"OSV did not answer in time ({type(exc).__name__})"
    if isinstance(exc, OSVAnswer):
        return "failed", str(exc)
    if isinstance(exc, json.JSONDecodeError):
        return "failed", f"JSONDecodeError: broken JSON from OSV ({str(exc)[:80]})"
    return "failed", f"{type(exc).__name__}: {str(exc)[:120]} (network needed?)"


def _osv_audit(tool: str, ecosystem: str, pins: dict[str, tuple[str, str, int]], info: dict,
               odd: Odd | None = None) -> tuple[list[dict], dict]:
    """Run one OSV-backed audit and write its record: `ok`, `partial` (a vulnerability's details could not be fetched,
    and the finding is kept with a generic title; or an entry of the project's files was no name and version, `odd`),
    `failed` or `timeout`. Nobody is asked when there is nothing to ask about."""
    odd = odd if odd is not None else Odd()
    try:
        out, errors = _osv_findings(tool, ecosystem, pins) if pins else ([], [])
    except (OSError, ValueError) as exc:
        state, why = _osv_failure(exc)
        return [], scanresult.record(tool, state, why, **info)
    info["findings"] = len(out)
    if errors or odd.count:
        also = f"{len(errors)} vulnerability detail{'s' if len(errors) != 1 else ''} could not be fetched" if errors else ""
        return out, scanresult.record(tool, "partial", odd.why(also), **(info | odd.fields()
                                                                        | {"errors": odd.lines + errors}))
    return out, scanresult.record(tool, "ok", **info)


def run_maven_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    pre = precomputed("maven-audit")
    if pre is not None:
        return pre
    info: dict = {"role": "known-vulnerable Gradle/Maven libraries (OSV database)", "version": "osv-v1"}
    odd = Odd()
    pins, loose, files = maven_coords(repo, odd)
    if not files:
        return [], scanresult.record("maven-audit", "skipped", "no Gradle or Maven files", **info)
    if not pins and odd.count:
        return [], scanresult.record("maven-audit", "partial", odd.why(), files=files, unpinned=len(loose),
                                     **odd.fields(), **info)
    if not pins:
        return [], scanresult.record("maven-audit", "skipped", "no exact versions to check", applicable=False, files=files,
                                     unpinned=len(loose), **info)
    if offline() if no_network is None else no_network:
        return [], scanresult.record("maven-audit", "skipped", "offline", applicable=True, files=files, **info)
    return _osv_audit("maven-audit", "Maven", pins, info | {"files": files, "scope": {"files": files, "packages": len(pins)},
                                                           "checked": len(pins), "unpinned": len(loose),
                                                           "unpinned_examples": loose[:5]}, odd)


def _osv_findings(tool: str, ecosystem: str, pins: dict[str, tuple[str, str, int]]) -> tuple[list[dict], list[str]]:
    """Ask OSV about exact `name → (version, file, line)` pins of one ecosystem; one finding per known vulnerability.
    Returns the findings and the details that could not be fetched (one line each). Raises `OSVAnswer` when the
    batch answer has the wrong shape, and lets network errors through for the caller's record."""
    from .security import _fid
    coords = sorted(pins)
    res = []
    for i in range(0, len(coords), 500):
        chunk = coords[i:i + 500]
        data = _osv_post("querybatch", {"queries": [{"package": {"name": c, "ecosystem": ecosystem},
                                                     "version": pins[c][0]} for c in chunk]})
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            raise OSVAnswer("wrong shape: OSV's answer has no results list")
        if len(results) != len(chunk):
            raise OSVAnswer(f"wrong shape: expected {len(chunk)} answer{'s' if len(chunk) != 1 else ''} from OSV, "
                            f"got {len(results)}")
        res += list(zip(chunk, results))
    details: dict[str, dict] = {}
    errors: list[str] = []
    not_fetched = 0
    out = []
    for coord, r in res:
        for v in (r.get("vulns") or []) if isinstance(r, dict) else []:
            vid = str((v or {}).get("id") or "")[:60] if isinstance(v, dict) else ""
            if not vid:
                continue
            if vid not in details:
                if len(details) >= OSV_DETAIL_LIMIT:
                    details[vid] = {}
                    not_fetched += 1
                else:
                    try:
                        d = _osv_get(f"vulns/{vid}")
                        details[vid] = d if isinstance(d, dict) else {}
                    except (OSError, ValueError) as exc:
                        details[vid] = {}
                        errors.append(f"{vid}: {type(exc).__name__} {str(exc)[:120]}".rstrip())
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
    if not_fetched:
        errors.append(f"details of {not_fetched} vulnerabilit{'ies' if not_fetched != 1 else 'y'} not fetched "
                      f"(limit {OSV_DETAIL_LIMIT} per run); their findings carry a generic title")
    return out, errors


# ---------------------------------------------------------------------------- PHP (Composer, OSV)

def composer_pins(repo: Path, odd: Odd | None = None,
                  loose: list[str] | None = None) -> tuple[dict[str, tuple[str, str, int]], list[str]]:
    """Exact versions from every composer.lock (shipped `packages`, not `packages-dev`): name → (version, file, line).
    The line is where composer.json asks for the library when it does (a direct library), else its place in the lock.
    A library installed from a branch (`dev-main`, `2.x-dev`) has no released version to look up and goes to `loose`
    as "name version"; what is no name and version, and what could not be read, goes to `odd`."""
    odd = odd if odd is not None else Odd()
    loose = loose if loose is not None else []
    pins: dict[str, tuple[str, str, int]] = {}
    files = []
    for lock in _project_files(repo, names=("composer.lock",)):
        rel = lock.relative_to(repo).as_posix()
        files.append(rel)
        text = _read(lock, rel, odd, repo)
        ok, data = _json(text, rel, odd)
        if not ok:
            continue
        packages = data.get("packages") if isinstance(data, dict) else None
        if not isinstance(data, dict):
            odd.add(rel, f"its content is {_shown(data)}, not a table")
            continue
        if not isinstance(packages, (list, type(None))):
            odd.add(rel, f"its packages are {_shown(packages)}, not a list")
            continue
        cj = lock.with_name("composer.json")
        cj_rel = cj.relative_to(repo).as_posix()
        cj_text = _quiet(cj, repo)
        for i, pkg in enumerate(packages or [], 1):
            if not isinstance(pkg, dict):
                odd.add(rel, f"entry {i} is {_shown(pkg)}, not a package")
                continue
            name, ver = pkg.get("name"), pkg.get("version")
            if not isinstance(name, str) or not COMPOSER_NAME.fullmatch(name):
                odd.add(rel, f"entry {i}: {_shown(name)} is not a package name")
                continue
            if isinstance(ver, str) and (ver.startswith("dev-") or ver.endswith("-dev")) and COMPOSER_BRANCH.fullmatch(ver):
                loose.append(f"{name} {ver}")
                continue
            if not isinstance(ver, str) or not COMPOSER_VERSION.fullmatch(ver):
                odd.add(rel, f"{name}: {_shown(ver)} is not a version")
                continue
            m = re.search(r'"' + re.escape(name) + r'"\s*:', cj_text)
            if m:
                where = (cj_rel, cj_text.count("\n", 0, m.start()) + 1)
            else:
                lm = re.search(r'"name"\s*:\s*"' + re.escape(name) + '"', text)
                where = (rel, text.count("\n", 0, lm.start()) + 1 if lm else 1)
            pins.setdefault(name, (ver.lstrip("v"), *where))
    return pins, files


def _composer_unlocked(repo: Path) -> list[tuple[str, str]]:
    """(file, name) of every library a composer.json with no composer.lock beside it asks for in `require` (what
    ships; `require-dev` does not, and PHP itself and its extensions are no libraries)."""
    named: list[tuple[str, str]] = []
    for cj in _project_files(repo, names=("composer.json",)):
        if not inside_repo(cj, repo) or inside_repo(cj.with_name("composer.lock"), repo):
            continue
        rel = cj.relative_to(repo).as_posix()
        text = _read(cj, rel, Odd(), repo)
        data = manifest.parse_json(text) if text is not None else None
        if not isinstance(data, dict):
            named.append((rel, "(what it names could not be read)"))
            continue
        named += [(rel, _plain(k, 80)) for k in manifest.table(data.get("require"))
                  if isinstance(k, str) and not PLATFORM_PACKAGE.match(k)]
    return named


def run_composer_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    pre = precomputed("composer-audit")
    if pre is not None:
        return pre
    info: dict = {"role": "known-vulnerable PHP libraries (composer.lock, OSV database)", "version": "osv-v1"}
    odd, loose = Odd(), []
    pins, files = composer_pins(repo, odd, loose)
    info |= _unlocked(_composer_unlocked(repo))
    if not files and "unlocked" in info:
        return [], scanresult.record("composer-audit", "skipped", f"no composer.lock, {NO_LOCK}", applicable=False,
                                     **info)
    if not files:
        return [], scanresult.record("composer-audit", "skipped", "no composer.lock", **info)
    if loose:                           # said only when there are any, so a record without them is as it always was
        info |= {"unpinned": len(loose), "unpinned_examples": loose[:5]}
    if not pins and odd.count:
        return [], scanresult.record("composer-audit", "partial", odd.why(), files=files, **odd.fields(), **info)
    if offline() if no_network is None else no_network:
        return [], scanresult.record("composer-audit", "skipped", "offline", applicable=True, files=files, **info)
    return _osv_audit("composer-audit", "Packagist", pins, info | {"files": files, "scope": {"files": files, "packages": len(pins)},
                                                                  "checked": len(pins)}, odd)


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


def gem_pins(repo: Path, odd: Odd | None = None) -> tuple[dict[str, tuple[str, str, int]], list[str]]:
    """Exact versions from every Gemfile.lock: name → (version, file, line). A gem's own line under `specs:` (four
    spaces, then its name) that is no name and version goes to `odd`, and so does a lock file that cannot be read."""
    odd = odd if odd is not None else Odd()
    pins: dict[str, tuple[str, str, int]] = {}
    files = []
    for lock in _project_files(repo, names=("Gemfile.lock",)):
        rel = lock.relative_to(repo).as_posix()
        files.append(rel)
        text = _read(lock, rel, odd, repo)
        if text is None:
            continue
        gf = lock.with_name("Gemfile")
        glines, dev_only = _gemfile_dev_only(_quiet(gf, repo))
        in_specs = False
        for i, raw in enumerate(text.splitlines(), 1):
            if re.match(r"^\S", raw):
                in_specs = False
                continue
            if raw.strip() == "specs:":
                in_specs = True
                continue
            if not in_specs or not re.match(r" {4}\S", raw):
                continue                    # deeper lines say what a gem needs, not what is installed
            m = GEM_LINE.fullmatch(raw)
            if not m:
                odd.add(rel, f"line {i}: {_shown(raw.strip())} is not a gem name and version")
                continue
            if m.group(1) in dev_only:
                continue
            where = (gf.relative_to(repo).as_posix(), glines[m.group(1)]) if m.group(1) in glines else (rel, i)
            pins.setdefault(m.group(1), (m.group(2), *where))
    return pins, files


def _gem_unlocked(repo: Path) -> list[tuple[str, str]]:
    """(file, name) of every gem a Gemfile with no Gemfile.lock beside it names outside its development and test
    groups."""
    named: list[tuple[str, str]] = []
    for gf in _project_files(repo, names=("Gemfile",)):
        if not inside_repo(gf, repo) or inside_repo(gf.with_name("Gemfile.lock"), repo):
            continue
        rel = gf.relative_to(repo).as_posix()
        text = _read(gf, rel, Odd(), repo)
        if text is None:
            named.append((rel, "(what it names could not be read)"))
            continue
        lines, dev_only = _gemfile_dev_only(text)
        named += [(rel, _plain(name, 80)) for name in lines if name not in dev_only]
    return named


def run_gem_audit(repo: Path, no_network: bool | None = None) -> tuple[list[dict], dict]:
    pre = precomputed("gem-audit")
    if pre is not None:
        return pre
    info: dict = {"role": "known-vulnerable Ruby gems (Gemfile.lock, OSV database)", "version": "osv-v1"}
    odd = Odd()
    pins, files = gem_pins(repo, odd)
    info |= _unlocked(_gem_unlocked(repo))
    if not files and "unlocked" in info:
        return [], scanresult.record("gem-audit", "skipped", f"no Gemfile.lock, {NO_LOCK}", applicable=False, **info)
    if not files:
        return [], scanresult.record("gem-audit", "skipped", "no Gemfile.lock", **info)
    if not pins and odd.count:
        return [], scanresult.record("gem-audit", "partial", odd.why(), files=files, **odd.fields(), **info)
    if offline() if no_network is None else no_network:
        return [], scanresult.record("gem-audit", "skipped", "offline", applicable=True, files=files, **info)
    return _osv_audit("gem-audit", "RubyGems", pins, info | {"files": files, "scope": {"files": files, "packages": len(pins)},
                                                            "checked": len(pins)}, odd)


if __name__ == "__main__":   # python -m lantern.depaudit REPO OUT.json  (the cloud service's audit step)
    import sys
    Path(sys.argv[2]).write_text(json.dumps(run_all(Path(sys.argv[1]))), encoding="utf-8")
