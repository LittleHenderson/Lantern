"""A project's libraries, fetched for one run of its tests (a firm pass or fail, stage 2, 2026-11-13).

Until then the sandbox ran a project's tests on whatever the Python that runs Lantern had installed (and, for
JavaScript, on a `node_modules` folder the project happened to bring). A project whose libraries are not on the
computer failed at its first import and the release decision read "Blocked: the tests failed", about code nobody
had run. Now, before the tests:

* **What the project asks for is read, never run.** Python: `requirements*.txt` at the top of the project (lines
  of the form a store defines: a name, versions, a marker, fingerprints; `-r` and `-c` files of the project are
  followed) and `pyproject.toml` (`dependencies`, the extras and groups named for tests, Poetry's tables), with
  the exact versions of a lock file beside them (`uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`) as the
  versions to take. JavaScript: `package.json` and npm's lock file. `setup.py` is code and is not run.
* **Where libraries come from is the person's setting, never the project's.** The official store (pypi.org,
  registry.npmjs.org), or the store the person names (LANTERN_STORE_PYTHON, LANTERN_STORE_NPM: `https://…`, or
  `http://` on this computer). A line of the project that names another store, a link or a folder is not
  followed, and the tests are then not run (`Unavailable`), because they would run on other libraries than the
  project's.
* **The fetch is a step of its own, in the sandbox** (`fetch`): pip or npm, started by Lantern in a folder of
  Lantern's own, never in the project, with settings Lantern wrote. Its one way out is the doorkeeper
  (`lantern._stores`), which reaches the store and nothing else; on Linux the step runs in a network of its own
  whose only listener is that doorkeeper. Only ready-built packages are taken (pip: wheels; npm: with install
  scripts off), so no code of any library runs while a network can be reached.
* **The tests then run with the network off on exactly those libraries**: for Python the libraries installed
  beside Lantern are taken off the path (`LANTERN_SANDBOX_LIBRARIES=fetched`, the guard file's `_only_fetched`),
  so a project that forgot to name a library hears of it here. Where the tests run in a container, the libraries
  are fetched for the container's system (`Plan.platforms`) and handed to it to read.
* **The record names every library** with its version, the file that was fetched and its fingerprint
  (`sandbox.run(...)["libraries"]`, `run.json` `trace.libraries`), and whether every version was the project's
  own choice (`exact`).

Offline (`--offline`, LANTERN_OFFLINE) nothing is fetched: the tests run on what is installed when every library
the project names is there (`state: "installed"`), and are otherwise not run, with the missing ones named.
Nothing is kept between runs: the folder the libraries are fetched into is the run's temp folder."""
from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import _stores, depaudit, manifest, programs, results

FETCH_SECONDS = 600                     # the time a fetch gets
DOOR_PORT = 8118                        # where the doorkeeper listens in a network of the fetch's own
VARIABLES = {"python": "LANTERN_STORE_PYTHON", "node": "LANTERN_STORE_NPM"}
OFFICIAL = {"python": ("https://pypi.org/simple/", [["pypi.org", 443], ["files.pythonhosted.org", 443]]),
            "node": ("https://registry.npmjs.org/", [["registry.npmjs.org", 443]])}
REQ_FILES = ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "requirements-test.txt",
             "requirements_test.txt", "requirements-tests.txt", "dev-requirements.txt", "test-requirements.txt",
             "requirements/dev.txt", "requirements/test.txt", "requirements/tests.txt")
TEST_GROUPS = ("test", "tests", "testing", "dev", "develop", "development")
PY_LOCKS = ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock")
OTHER_JS_LOCKS = {"pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn", "bun.lockb": "bun", "bun.lock": "bun"}
MOST_LINES = 2000                       # requirement lines one project may have
DEPTH = 4                               # how many `-r` files deep
SHOWN = 40                              # libraries named one by one in the log

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,98}[A-Za-z0-9])?"
_VERSION = r"[A-Za-z0-9][A-Za-z0-9.*+!_\-]{0,99}"
_CLAUSE = rf"(?:~=|===?|!=|<=|>=|<|>)\s*{_VERSION}"
REQUIREMENT = re.compile(
    rf"(?P<name>{_NAME})\s*(?P<extras>\[\s*{_NAME}(?:\s*,\s*{_NAME})*\s*\])?\s*"
    rf"(?P<spec>\(?\s*{_CLAUSE}(?:\s*,\s*{_CLAUSE})*\s*\)?)?\s*"
    r"(?P<marker>;\s*[A-Za-z0-9_.\"' <>=!~(),\-]{1,300})?\s*"
    r"(?P<hashes>(?:--hash[= ]sha(?:256|384|512):[0-9a-f]{64,128}\s*)*)")
PINNED = re.compile(rf"==\s*({_VERSION})")
ELSEWHERE = "names another store, a link or a folder to take libraries from"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _plain(text, limit: int = 80) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


_FILE_NAME = re.compile(r"[A-Za-z0-9._\-]{1,60}(?:/[A-Za-z0-9._\-]{1,60}){0,5}")


def _file_words(rel: str) -> str:
    """A requirements file's name for a reason shown to a person: as written when it is an everyday path."""
    return rel if _FILE_NAME.fullmatch(rel) else "a file the project names"


def _library_words(name: str) -> str:
    """A library's name for a reason shown to a person: as written when it has the form a store defines."""
    return name if re.fullmatch(_NAME, name) and len(name) <= 60 else "a library"


class Store:
    """Where libraries are fetched from: `url`, the words for it (`host`), and what the doorkeeper lets through."""

    def __init__(self, language: str):
        from .sandbox import NoLibraries as Unavailable
        official, allowed = OFFICIAL[language]
        said = os.environ.get(VARIABLES[language], "").strip()
        self.url, self.allowed, self.official = official, [list(a) for a in allowed], True
        if said:
            try:
                parts = urlsplit(said)
                host, port = parts.hostname, parts.port
            except ValueError:
                parts = host = port = None
            here = host in _stores.LOCAL
            if not host or parts.username or parts.query or parts.fragment or parts.scheme not in ("https", "http") \
                    or (parts.scheme == "http" and not here) or not said.isprintable() or len(said) > 300:
                raise Unavailable(f"the store named in {VARIABLES[language]} is not an address Lantern fetches from "
                                  "(https://…, or http:// on this computer), so no library was fetched")
            self.url = said if said.endswith("/") else said + "/"
            self.allowed, self.official = [[host.lower(), port or (443 if parts.scheme == "https" else 80)]], False
        first = urlsplit(self.url)
        self.host = first.netloc
        self.plain = first.scheme == "http"
        # the person's own proxy and certificates, for a store that is not on this computer
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
        self.through = _stores.upstream(proxy) if proxy and not self.plain else None
        self.cert = next((v for v in (os.environ.get(k) for k in ("PIP_CERT", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE",
                                                                  "NODE_EXTRA_CA_CERTS")) if v and os.path.isfile(v)), None)


class Plan:
    """What `plan` found: `state` (`none`, `installed`, `fetch`) and the record so far."""

    def __init__(self, language: str):
        self.language = language
        self.state = "none"
        self.asked: list[dict] = []         # {"text", "file"}: what the project asks for, in its own words
        self.lines: list[str] = []          # Python: the lines pip is given
        self.constraints: list[str] = []    # Python: versions it must keep to
        self.pinned: set[str] = set()       # names whose version is the project's own choice
        self.notes: list[str] = []          # said in the log and the record, and nothing more
        self.added: list[str] = []          # what Lantern asks for itself (the test runner)
        self.lock: Path | None = None       # JavaScript: npm's lock file
        self.manifest: Path | None = None
        self.left: list[str] = []           # what the fetch started and Lantern could not end, in its own words
        self.locked: dict[str, dict[str, set[str]]] = {}   # Python: name -> version -> the fingerprints a lock names
        self.listed: dict[str, dict[str, list[str]]] = {}  # Python: name -> version -> the files a lock lists by name
        self.lock_name = ""                 # the lock file that was read
        self.hashed = False                 # Python: the project writes fingerprints beside its requirements
        self.platforms: list[str] = []      # Python: the systems ready-built libraries must run on, when that is
                                            # not this one (the tests' container: `sandbox.image_platforms`)
        self.record: dict = {"state": "none", "language": language}

    @property
    def fetch(self) -> bool:
        return self.state == "fetch"


# ---------------------------------------------------------------------------- what a Python project asks for
def _text(p: Path, repo: Path) -> str | None:
    from .python_frontend import project_text
    try:
        return project_text(p, repo, 4_000_000)
    except (OSError, ValueError):
        return None


def _requirement(text: str) -> tuple[str, str, str] | None:
    """(the name, the line pip is given, the same without fingerprints) for a line of the form a store defines."""
    m = REQUIREMENT.fullmatch(text.strip()) if len(text) <= 4000 else None
    if not m:
        return None
    spec = re.sub(r"\s+", "", m.group("spec") or "")
    marker = re.sub(r"\s+", " ", (m.group("marker") or "").strip())
    shown = m.group("name") + re.sub(r"\s+", "", m.group("extras") or "") + spec + (" " + marker if marker else "")
    hashes = " ".join("--hash=" + h for h in re.findall(r"sha(?:256|384|512):[0-9a-f]+", m.group("hashes") or ""))
    return m.group("name"), shown + (" " + hashes if hashes else ""), shown


class _Reader:
    def __init__(self, repo: Path, plan: Plan, offline: bool = False):
        from .sandbox import NoLibraries
        self.repo, self.plan, self.refuse, self.offline = repo, plan, NoLibraries, offline
        self.seen: set[str] = set()
        self.own = ""                           # the project's own name
        self.folders: set[str] = set()          # libraries that are folders of the project (workspace members)
        self.passed: set[str] = set()

    def stop(self, rel: str, why: str):
        raise self.refuse(f"the project's libraries could not be fetched: {_file_words(rel)} {why}, so the tests "
                          "were not run on other libraries than the project's")

    def elsewhere(self, rel: str) -> None:
        """A line that takes a library from another store, a link or a folder. Where libraries are fetched it is
        not followed and nothing is fetched. Offline nothing is fetched anyway: the tests run on what is installed,
        as they always did, and the record says that the line was passed over."""
        if not self.offline:
            self.stop(rel, ELSEWHERE)
        if rel not in self.passed:
            self.passed.add(rel)
            self.plan.notes.append(f"{_file_words(rel)} {ELSEWHERE}: passed over, because offline nothing is fetched")

    def add(self, text: str, rel: str, constraint: bool = False, line: int = 0) -> None:
        if "://" in text or " @ " in text or text.startswith((".", "/", "file:")) or text.endswith((".whl", ".zip", ".tar.gz")):
            return self.elsewhere(rel)
        got = _requirement(text)
        if got is None:
            self.stop(rel, "names a library in a form Lantern does not read" + (f" (line {line})" if line else ""))
        name, line, shown = got
        if _norm(name) == self.own or _norm(name) in self.folders:
            return          # the project itself (with some of its own extras), or a folder of it: nothing to fetch
        spec = re.split(r"[ ;]", shown[len(name):].split("]")[-1], maxsplit=1)[0]
        exact = bool(PINNED.fullmatch(spec or "")) and "*" not in spec      # `==1.0.*` is a pattern, not a version
        if "--hash=" in line:
            self.plan.hashed = True
        if constraint:
            self.plan.constraints.append(line)
            if exact:
                self.plan.pinned.add(_norm(name))
            return
        if len(self.plan.lines) >= MOST_LINES:
            self.stop(rel, f"names more than {MOST_LINES} libraries")
        if shown not in self.seen:
            self.seen.add(shown)
            self.plan.lines.append(line)
            self.plan.asked.append({"text": shown, "file": rel})
            if exact:
                self.plan.pinned.add(_norm(name))

    def file(self, rel: str, depth: int = 0, constraint: bool = False) -> None:
        text = _text(self.repo / rel, self.repo)
        if text is None:
            if depth:
                self.stop(rel, "is named by another file and cannot be read")
            return
        number, whole = 0, ""
        for at, raw in enumerate(text.splitlines(), 1):
            number = number or at               # a line that goes on over several is the line it starts on
            if raw.endswith("\\"):
                whole += raw[:-1] + " "
                continue
            line, number, whole, n = re.sub(r"(^|\s)#.*$", "", whole + raw).strip(), 0, "", number
            if not line:
                continue
            option, _, value = line.partition(" ") if not line.startswith("--") or "=" not in line.split(" ")[0] \
                else line.partition("=")
            value = value.strip()
            if option in ("-r", "--requirement", "-c", "--constraint"):
                inner = (Path(rel).parent / value).as_posix()
                if depth >= DEPTH or not value or ".." in Path(inner).parts or Path(value).is_absolute():
                    self.stop(rel, "names a file outside the project, or files inside files too deep")
                self.file(inner, depth + 1, constraint or option in ("-c", "--constraint"))
            elif option in ("-e", "--editable") or line in (".", "./"):
                if value.split("[")[0] in (".", "./") or line in (".", "./"):
                    self.plan.notes.append(f"{_file_words(rel)}: the project itself is on the tests' path as it "
                                           "is (not installed)")
                else:
                    self.elsewhere(rel)
            elif option in ("-i", "--index-url"):
                if not _same_store(value, _store_hosts()):
                    self.elsewhere(rel)
            elif option in ("--extra-index-url", "-f", "--find-links", "--trusted-host", "--no-index"):
                self.elsewhere(rel)
            elif line.startswith("-"):
                said = option if re.fullmatch(r"--?[a-z][a-z\-]{0,30}", option) else "one"
                self.plan.notes.append(f"{_file_words(rel)}, line {n}: an option of pip's that Lantern does not "
                                       f"follow ({said})")
            else:
                self.add(line, rel, constraint, n)


def _caret(name: str, text: str) -> str:
    """One of Poetry's own version words as a store's: `^1.2` is `>=1.2,<2`, `~1.2.3` is `>=1.2.3,<1.3`."""
    text = text.strip()
    if text in ("", "*"):
        return name
    if re.fullmatch(r"\d[\w.]*", text):
        return f"{name}=={text}"
    m = re.fullmatch(r"([\^~])\s*(\d+(?:\.\d+)*)", text)
    if not m:
        return name + text
    nums = [int(n) for n in m.group(2).split(".")]
    if m.group(1) == "~":
        top = nums[:2] if len(nums) > 1 else nums[:1]
    else:
        top = nums[:next((i + 1 for i, n in enumerate(nums) if n), len(nums))]
    top = [*top[:-1], top[-1] + 1]
    return f"{name}>={m.group(2)},<{'.'.join(map(str, top))}"


def _pyproject(reader: _Reader) -> None:
    rel = "pyproject.toml"
    text = _text(reader.repo / rel, reader.repo)
    if text is None:
        return
    data = manifest.parse_toml(text)
    project = manifest.table(data.get("project"))
    reader.own = _norm(manifest.text(project.get("name")))
    tool = manifest.table(data.get("tool"))
    poetry, uv = manifest.table(tool.get("poetry")), manifest.table(tool.get("uv"))
    # the stores a tool's own table names (uv, Poetry, PDM), and uv's table of where single libraries come from
    stores = [manifest.text(s.get("url")) for s in manifest.tables(uv.get("index")) + manifest.tables(poetry.get("source"))
              + manifest.tables(manifest.table(tool.get("pdm")).get("source"))]
    for key in ("index-url", "extra-index-url", "find-links"):
        stores += [manifest.text(uv.get(key))] + manifest.texts(uv.get(key))
    if any(url and not _same_store(url, _store_hosts()) for url in stores):
        reader.elsewhere(rel)
    for name, source in manifest.table(uv.get("sources")).items():
        ways = manifest.tables(source) or [manifest.table(source)]
        if all(way.get("workspace") is True for way in ways):
            reader.folders.add(_norm(name))
            reader.plan.notes.append(f"{rel}: {_library_words(name)} is a folder of the project itself (a workspace "
                                     "member): it is on the tests' path only where the project puts it there")
        elif not all(set(way) <= {"index", "marker"} for way in ways):   # an index is among the stores above
            reader.elsewhere(rel)
    for dep in manifest.texts(project.get("dependencies")):
        reader.add(dep, rel)
    left: set[str] = set()                  # groups of libraries the project names and Lantern does not take
    for table in (manifest.table(project.get("optional-dependencies")), manifest.table(data.get("dependency-groups"))):
        taken = set(TEST_GROUPS)
        for group in TEST_GROUPS:
            for dep in manifest.rows(table.get(group)):
                if isinstance(dep, str):
                    reader.add(dep, rel)
                elif isinstance(dep, dict) and isinstance(dep.get("include-group"), str):
                    taken.add(dep["include-group"])
                    for inner in manifest.texts(table.get(dep["include-group"])):
                        reader.add(inner, rel)
        left.update(str(group) for group, deps in table.items() if group not in taken and manifest.rows(deps))
    reader.own = reader.own or _norm(manifest.text(poetry.get("name")))
    tables = [manifest.table(poetry.get("dependencies")), manifest.table(poetry.get("dev-dependencies"))]
    tables += [manifest.table(manifest.table(g).get("dependencies"))
               for name, g in manifest.table(poetry.get("group")).items() if name in TEST_GROUPS]
    left.update(str(name) for name, g in manifest.table(poetry.get("group")).items()
                if name not in TEST_GROUPS and manifest.table(manifest.table(g).get("dependencies")))
    left.update(str(name) for name, deps in manifest.table(poetry.get("extras")).items()
                if name not in TEST_GROUPS and manifest.rows(deps))
    if left:
        # A test of a part that needs an optional library fails for that alone, and the run says which were left
        # (2026-11-13, a public project: two of its tests need a library it names under `minify`).
        named = sorted(g for g in left if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,39}", g))
        shown, more = [f'"{g}"' for g in named[:6]], len(left) - min(len(named), 6)
        words = ", ".join(shown[:-1]) + (" and " if len(shown) > 1 else "") + shown[-1] if shown and not more else \
            ", ".join(shown) + (" and " if shown else "") + f"{more} more"
        reader.plan.notes.append(
            f"{rel}: the libraries the project names as optional (under {words}) were not fetched. Lantern takes "
            "what the project always needs and what it names for its tests, so a test of a part that needs an "
            "optional library fails here for that alone")
    for table in tables:
        for name, value in table.items():
            if _norm(name) == "python":
                continue
            if isinstance(value, dict):
                if any(k in value for k in ("git", "path", "url", "file")):
                    reader.elsewhere(rel)
                    continue
                extras = manifest.texts(value.get("extras"))    # (`source` names one of the stores read above)
                name, value = name + (f"[{','.join(extras)}]" if extras else ""), manifest.text(value.get("version"))
            if isinstance(value, str):
                reader.add(_caret(name, value), rel)


def _place_of(url: str) -> tuple[str, int] | None:
    """(host, port) an address names, the port its kind of address has when none is written; None for no address."""
    try:
        parts = urlsplit(url.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host or parts.scheme not in ("https", "http"):
        return None
    return host.lower(), port or (443 if parts.scheme == "https" else 80)


def _store_hosts() -> set[tuple[str, int]]:
    """The stores a project's own files may name: the official one, and the one the person set."""
    mine = _place_of(os.environ.get(VARIABLES["python"], ""))
    return {("pypi.org", 443), ("files.pythonhosted.org", 443)} | ({mine} if mine else set())


def _same_store(url: str, hosts: set[tuple[str, int]]) -> bool:
    return _place_of(url) in hosts


def _pipfile(reader: _Reader) -> None:
    """Pipenv's own list: `[packages]` and `[dev-packages]`, a version word or a table each."""
    rel = "Pipfile"
    text = _text(reader.repo / rel, reader.repo)
    if text is None:
        return
    data, hosts = manifest.parse_toml(text), _store_hosts()
    for source in manifest.rows(data.get("source")):
        url = manifest.text(manifest.table(source).get("url"))
        if url and not _same_store(url, hosts):
            reader.elsewhere(rel)
    for section in ("packages", "dev-packages"):
        for name, value in manifest.table(data.get(section)).items():
            if isinstance(value, dict):
                if value.get("editable") and manifest.text(value.get("path")) in (".", "./"):
                    continue                    # the project itself
                if any(k in value for k in ("git", "hg", "svn", "bzr", "path", "file")):
                    reader.elsewhere(rel)
                    continue
                extras = manifest.texts(value.get("extras"))
                name, value = name + (f"[{','.join(extras)}]" if extras else ""), manifest.text(value.get("version"))
            if isinstance(value, str):
                reader.add(name if value.strip() in ("", "*") else name + value.strip(), rel)


_SHA256 = re.compile(r"sha256:([0-9a-f]{64})")


def _file_of(said: str) -> str:
    """The file a lock file lists, by its name alone: `x-1.0-py3-none-any.whl` of a link or of a name."""
    return said.split("#", 1)[0].split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1][:300]


def _lock(repo: Path, found: Plan, reader: _Reader) -> None:
    """The lock file at the top of the project (the first of `PY_LOCKS` that is there). The versions it fixes are
    the versions taken, and the fingerprints it names are compared with the files the store hands out
    (`_fetch_python`): a file that is another one means no test is run. An entry that sends a library to another
    store than the person's, to a link or to a folder stops the plan: asked of the person's store by its name,
    that library may be somebody else's."""
    for rel in PY_LOCKS:
        text = _text(repo / rel, repo)
        if text is None:
            continue
        hosts, entries = _store_hosts(), []
        if rel == "Pipfile.lock":
            data = manifest.table(manifest.parse_json(text))
            for source in manifest.rows(manifest.table(data.get("_meta")).get("sources")):
                url = manifest.text(manifest.table(source).get("url"))
                if url and not _same_store(url, hosts):
                    reader.stop(rel, ELSEWHERE)
            for section in ("default", "develop"):
                for name, spec in manifest.table(data.get(section)).items():
                    spec = manifest.table(spec)
                    if spec.get("editable") and manifest.text(spec.get("path")) in (".", "./"):
                        continue                # the project itself
                    if any(k in spec for k in ("git", "hg", "svn", "bzr", "path", "file")):
                        reader.stop(rel, ELSEWHERE)
                    version = manifest.text(spec.get("version"))
                    entries.append((name, version[2:] if version.startswith("==") else "", manifest.texts(spec.get("hashes"))))
        else:
            data = manifest.parse_toml(text)
            older = manifest.table(manifest.table(data.get("metadata")).get("files"))    # Poetry before 1.5
            for pkg in manifest.tables(data.get("package")):
                name, source = manifest.text(pkg.get("name")), manifest.table(pkg.get("source"))
                if rel == "uv.lock":
                    if any(k in source for k in ("editable", "virtual", "directory")):
                        continue                # the project itself, or a folder of it
                    registry = manifest.text(source.get("registry"))
                    other = any(k in source for k in ("git", "url", "path")) \
                        or bool(registry and not _same_store(registry, hosts))
                elif rel == "poetry.lock":
                    other = bool(source) and (manifest.text(source.get("type")) != "legacy"
                                              or not _same_store(manifest.text(source.get("url")), hosts))
                else:
                    other = any(k in pkg for k in ("git", "url", "path", "ref", "revision"))
                if other:
                    reader.stop(rel, ELSEWHERE)
                files = manifest.tables(pkg.get("wheels")) + manifest.tables(pkg.get("files")) \
                    + manifest.tables(older.get(name)) + [manifest.table(pkg.get("sdist"))]
                entries.append((name, manifest.text(pkg.get("version")), [manifest.text(f.get("hash")) for f in files],
                                [_file_of(manifest.text(f.get("file")) or manifest.text(f.get("url"))) for f in files]))
        unread = 0
        for name, version, hashes, *names in entries:
            if not isinstance(name, str) or not re.fullmatch(_NAME, name) or not re.fullmatch(_VERSION, version) \
                    or "*" in version:
                unread += 1
                continue
            named = found.locked.setdefault(_norm(name), {}).setdefault(version, set())
            named.update(m.group(1) for m in map(_SHA256.fullmatch, hashes) if m)
            if names:
                found.listed.setdefault(_norm(name), {}).setdefault(version, []).extend(n for n in names[0] if n)
        for name, versions in sorted(found.locked.items()):
            if name != reader.own and len(versions) == 1:       # two versions of one library: pip's choice among them
                found.constraints.append(f"{name}=={next(iter(versions))}")
                found.pinned.add(name)
        found.lock_name = rel
        if unread:
            found.notes.append(f"{rel}: {unread} entr{'y' if unread == 1 else 'ies'} with no name and exact version "
                               "of the form a store defines, passed over")
        return


def _python(repo: Path, plan: Plan, words: list[str], offline: bool = False) -> _Reader:
    reader = _Reader(repo, plan, offline)
    _pyproject(reader)
    _pipfile(reader)
    for rel in REQ_FILES:
        reader.file(rel)
    if not plan.asked:
        return reader
    head = Path(words[0]).name.lower()
    runner = "pytest" if head in ("pytest", "py.test") or words[1:3] == ["-m", "pytest"] else ""
    if runner and not any(_norm(re.split(r"[\[<>=!~; ]", a["text"], maxsplit=1)[0]) == runner for a in plan.asked):
        plan.added.append(runner)               # the command needs it and the project does not name it
        plan.lines.append(runner)
    return reader


def _names(plan: Plan) -> list[str]:
    """The libraries the plan names for this Python on this system: a line whose marker says it is for another
    (`tomli; python_version < "3.11"`) names none here."""
    return [re.split(r"[\[<>=!~; ]", a["text"], maxsplit=1)[0] for a in plan.asked
            if applies(a["text"].partition(";")[2]) is not False] + plan.added


# ---------------------------------------------------------------------------- a marker: is a line for this Python
_MARK_TOKEN = re.compile(r"""\s*(\(|\)|"[^"]*"|'[^']*'|==|!=|<=|>=|~=|<|>|[A-Za-z_][A-Za-z0-9_.]*)""")
_VERSIONS = ("python_version", "python_full_version", "implementation_version", "platform_release")


def _marker_values() -> dict:
    import platform
    return {"python_version": "%d.%d" % sys.version_info[:2], "python_full_version": platform.python_version(),
            "os_name": os.name, "sys_platform": sys.platform, "platform_system": platform.system(),
            "platform_machine": platform.machine(), "platform_release": platform.release(),
            "platform_python_implementation": platform.python_implementation(),
            "implementation_name": sys.implementation.name,
            "implementation_version": "%d.%d.%d" % sys.implementation.version[:3], "extra": ""}


def applies(marker: str):
    """Whether a requirement's marker (the part after `;`) holds for this Python on this system: True, False, or
    None where Lantern cannot tell (a form it does not read), which callers take as "it may". No marker: True."""
    marker = marker.strip()
    if not marker:
        return True
    tokens, at = [], 0
    while at < len(marker):
        m = _MARK_TOKEN.match(marker, at)
        if not m:
            if marker[at:].strip():
                return None
            break
        tokens.append(m.group(1))
        at = m.end()
    return _marker(tokens)


def _marker(tokens: list[str]):
    values = _marker_values()
    place = [0]

    def value(tok):
        if tok[:1] in "\"'":
            return tok[1:-1], None
        return (values[tok], tok) if tok in values else (None, tok)

    def number(text):
        parts = re.findall(r"\d+", text)
        return tuple(int(p) for p in parts[:4]) if parts and re.match(r"\d", text) else None

    def one():
        if place[0] < len(tokens) and tokens[place[0]] == "(":
            place[0] += 1
            got = either()
            if place[0] >= len(tokens) or tokens[place[0]] != ")":
                raise ValueError
            place[0] += 1
            return got
        left, op, right = tokens[place[0]:place[0] + 3] if tokens[place[0] + 1:place[0] + 2] != ["not"] else \
            (tokens[place[0]], "not in", tokens[place[0] + 3] if tokens[place[0] + 2:place[0] + 3] == ["in"] else None)
        place[0] += 4 if op == "not in" else 3
        (a, var_a), (b, var_b) = value(left), value(right)
        if a is None or b is None:
            raise ValueError
        if op in ("in", "not in"):
            return (a in b) is (op == "in")
        if (var_a or var_b) in _VERSIONS and op != "~=":
            a, b = number(a), number(b)
            if a is None or b is None:
                raise ValueError
            width = max(len(a), len(b))
            a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
        elif op not in ("==", "!="):
            raise ValueError
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]

    def both():
        got = one()
        while place[0] < len(tokens) and tokens[place[0]] == "and":
            place[0] += 1
            got = one() and got
        return got

    def either():
        got = both()
        while place[0] < len(tokens) and tokens[place[0]] == "or":
            place[0] += 1
            got = both() or got
        return got

    try:
        got = either()
        return bool(got) if place[0] == len(tokens) else None
    except (ValueError, KeyError, IndexError, TypeError):
        return None


# ---------------------------------------------------------------------------- what a JavaScript project asks for
def _node(repo: Path, plan: Plan, cwd_rel: str) -> None:
    here = repo / cwd_rel if cwd_rel else repo
    data = manifest.table(manifest.parse_json(_text(here / "package.json", repo) or ""))
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, wanted in manifest.table(data.get(key)).items():
            plan.asked.append({"text": f"{_plain(name, 100)}@{_plain(wanted, 60)}", "file": "package.json"})
    plan.manifest = here / "package.json"
    for name in ("npm-shrinkwrap.json", "package-lock.json"):
        if os.path.lexists(here / name):
            plan.lock = here / name
            break


def _elsewhere(lock: dict, store: Store) -> int:
    """How many packages a lock file says to take from a place that is not the store."""
    count = 0
    for key, entry in manifest.table(lock.get("packages")).items():
        where = manifest.text(manifest.table(entry).get("resolved"))
        if key and where and not where.startswith(("https://registry.npmjs.org/", store.url, "file:")):
            count += 1
    return count


# ---------------------------------------------------------------------------- the plan
def plan(repo: Path, language: str, words: list[str], cwd_rel: str = "", offline: bool | None = None) -> Plan:
    """What to do about a project's libraries before its tests run. Raises `sandbox.NoLibraries` (an `Unavailable`)
    when the tests must not be started: the project names another place to take libraries from, or the check is
    offline and what the project names is not on this computer."""
    from .sandbox import NoLibraries as Unavailable
    found = Plan(language)
    reader = None
    offline = depaudit.offline() if offline is None else offline
    if language == "python":
        reader = _python(repo, found, words, offline)
    elif language == "node":
        _node(repo, found, cwd_rel)
    else:
        return found                            # other languages: as before, on what the computer has
    if not found.asked:
        return found
    found.record.update(asked=found.asked, notes=found.notes)
    if language == "node":
        here = found.manifest.parent
        other = next((pm for name, pm in OTHER_JS_LOCKS.items() if os.path.lexists(here / name)), None)
        brought = (here / "node_modules").is_dir()
        if offline or (other and not found.lock):
            if not brought:
                raise Unavailable(
                    "the project's packages are not on this computer and "
                    + ("the check is offline, so they were not fetched" if offline else
                       f"Lantern does not fetch from a {other} lock file yet (it reads npm's)")
                    + ": run the project's own install first, or check it online with an npm lock file")
            found.state = "installed"
            found.record.update(state="installed", exact=False,
                                on="the node_modules folder the project brought, as it is")
            return found
    elif offline:
        missing, here = [], []
        for name in _names(found):
            try:
                here.append({"name": name, "version": importlib.metadata.version(name)})
            except importlib.metadata.PackageNotFoundError:
                missing.append(name)
        if missing:
            raise Unavailable("the check is offline, so no library was fetched, and these libraries the project "
                              f"names are not on this computer: {', '.join(_library_words(m) for m in missing[:12])}"
                              + (f" and {len(missing) - 12} more" if len(missing) > 12 else ""))
        found.state = "installed"
        found.record.update(state="installed", exact=False, packages=here,
                            on="the libraries installed beside Lantern (the check is offline)")
        return found
    if reader is not None:
        _lock(repo, found, reader)
        if found.hashed and found.added:
            # pip takes no file without a fingerprint once the project names one for any: the runner Lantern would
            # add has none of the project's, and adding it would stop the whole fetch with pip's words for it.
            raise Unavailable(f"the project writes fingerprints beside its libraries and does not name "
                              f"{found.added[0]}, which its test command needs: no file is taken without a "
                              f"fingerprint then, so name {found.added[0]} and what it needs, each with its exact "
                              "version and fingerprint, where the project names its libraries")
    found.state = "fetch"
    return found


def described(repo: Path, language: str) -> str:
    """The sheet's line about libraries for this project, or "" when it names none (or cannot be read here)."""
    try:
        found = plan(Path(repo), language, ["python", "-m", "unittest"] if language == "python" else ["npm", "test"])
        if not found.fetch:
            return ""
        store = Store(language)
    except Exception:  # noqa: BLE001 - the sheet says what it can; the run itself says why it cannot start
        return ""
    return (f"the libraries your project names are fetched first, from {store.host} and nowhere else, "
            f"{WALL_WORDS[walls()]}, into a folder that is deleted after; only ready-built packages, so no code "
            "of a library runs while a network can be reached; the tests then run with the network off on "
            "exactly those libraries")


def _own_network_here() -> bool:
    from . import sandbox
    return os.name == "posix" and not sandbox.own_network()


# What holds the fetching program to the doorkeeper on this system, and the words for it.
WALL_WORDS = {
    "own-network": "in a network of its own whose only way out is Lantern's doorkeeper",
    "port-rule": "through Lantern's doorkeeper, the one address the system lets the fetching program connect to",
    "told": "through Lantern's doorkeeper, which the fetching program is told to use (this system has no rule "
            "that holds it to that)",
}


def walls() -> str:
    """`own-network`: the fetch runs in a network that holds the doorkeeper's listener and nothing else (Linux,
    where the system gives a run one). `port-rule`: the kernel lets the fetching program connect to the
    doorkeeper's port and to no other (Landlock, Linux 6.7 on). `told`: pip or npm is given the doorkeeper as its
    proxy and nothing in the system holds it to that (macOS, Windows, an older Linux)."""
    from . import sandbox
    if _own_network_here():
        return "own-network"
    return "port-rule" if sys.platform.startswith("linux") and sandbox.landlock_abi() >= 4 else "told"


# ---------------------------------------------------------------------------- the fetch
class _Fetch:
    """One fetch: the folders, the way out, and the launcher around the fetching program."""

    def __init__(self, found: Plan, root: Path, log, cancel, memory: int):
        from . import sandbox
        self.sandbox, self.plan, self.root, self.log, self.cancel, self.memory = sandbox, found, root, log, cancel, memory
        self.store = Store(found.language)
        self.dir = root / "fetch"
        self.tmp = self.dir / "tmp"
        self.as_nobody = hasattr(os, "geteuid") and os.geteuid() == 0
        self.own = _own_network_here()
        self.door = None
        self.said: list[str] = []
        try:
            self.tmp.mkdir(parents=True)
            self.cert = None
            if self.store.cert and os.path.getsize(self.store.cert) <= 8_000_000:
                self.cert = self.dir / "certificates.pem"       # the person's own, where the fetch's user may read it
                shutil.copyfile(self.store.cert, self.cert)
        except OSError as e:
            raise sandbox.NoLibraries("the folder the project's libraries are fetched into could not be made "
                                      f"({e.strerror or type(e).__name__})") from e
        if self.own:
            self.port = DOOR_PORT
        else:           # no network of the fetch's own on this system: the doorkeeper listens on this computer
            listener = _stores.listen(0)
            self.port = listener.getsockname()[1]
            self.door = _stores.Door(listener, self.store.allowed, self.store.through, self.said.append).start()
        self.proxy = f"http://127.0.0.1:{self.port}"

    def hand_over(self, *folders: Path) -> None:
        if self.as_nobody:
            os.chown(self.root, 65534, 65534)
            for folder in (self.dir, *folders):
                self.sandbox._hand_over(folder, 65534, 65534)

    def run(self, cmd: list[str], cwd: Path, writable: list[Path], readable: list[str], extra_env: dict | None = None):
        """(result, output, stopped at the time limit) of the fetching program, in the sandbox's launcher."""
        sandbox = self.sandbox
        env = sandbox._env_base(self.tmp)
        env.update(extra_env or {})
        job = None
        if os.name == "posix":
            from . import _jail
            policy = {"writable": [str(w) for w in writable], "nobody": self.as_nobody, "python": False, "net": True,
                      "own_net": self.own, "net_told": False, "must": True, "parent": os.getpid(),
                      "cpu": FETCH_SECONDS * sandbox._processors(), "memory": self.memory << 20,
                      "readable": readable, "runs": cmd[0] if os.path.isabs(cmd[0]) else ""}
            if self.own:
                policy["door"] = {"port": self.port, "allowed": self.store.allowed, "through": self.store.through}
            else:
                policy["tcp_ports"] = [self.port]
            pkg_root = str(Path(__file__).resolve().parent.parent)
            cmd = [sys.executable, "-I", "-c",
                   f"import sys; sys.path.insert(0, {pkg_root!r}); from lantern._jail import main; main(sys.argv[1:])",
                   json.dumps(policy), "--", *cmd]
            ask = _jail.ASK if sys.platform.startswith("linux") else 0.0
        else:
            ask, job = 0.0, (lambda: sandbox._windows_job(self.memory))

        def said(line: str) -> None:
            if line.startswith((_stores.REFUSED, _stores.OPENED)):
                self.said.append(line)
            elif line.strip():
                self.log(line if line.startswith("sandbox:") else "sandbox: fetch: " + line[:300])
        left: list[str] = []
        output = ""
        try:
            rc, output, timed_out = sandbox._stream(cmd, cwd, env, FETCH_SECONDS, said, job=job, cancel=self.cancel,
                                                    ask=ask, left=left)
        finally:
            if self.door is not None:
                self.door.close()
            self.plan.left = left + (sandbox._left_by_launcher(output) if os.name == "posix" else [])
        why = sandbox._unavailable(rc, output)
        if why:
            raise sandbox.Unavailable(why)
        return rc, output, timed_out

    def refused(self) -> int:
        return sum(1 for line in self.said if line.startswith(_stores.REFUSED))

    def stop(self, why: str, then: str = ""):
        raise self.sandbox.NoLibraries(f"the project's libraries could not be fetched: {why}, so its tests were not "
                                       f"run{then}")


_BUILT = re.compile(r"[^/\\]+-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)\.whl")     # …-python-abi-system.whl
_SYSTEMS = (("linux", "Linux"), ("macosx", "macOS"), ("win", "Windows"), ("android", "Android"), ("ios", "iOS"))
_MARKERS = {"Linux": "linux", "macOS": "darwin", "Windows": "win32"}        # what `sys_platform` says there


def _built_for(files: list[str]) -> tuple[set[str], bool]:
    """(the systems the ready-built files among `files` are for, whether a source package is among them), read
    from the names a store gives its files: `any` for a file that runs on every system."""
    systems, source = set(), False
    for name in files:
        m = _BUILT.fullmatch(name)
        if not m:
            source = source or name.endswith((".tar.gz", ".zip", ".tar.bz2", ".tgz"))
            continue
        for tag in m.group(3).lower().split("."):
            systems.add("any" if tag == "any" else next(
                (word for part, word in _SYSTEMS if (part in tag if part == "linux" else tag.startswith(part))),
                _plain(tag, 40)))
    return systems, source


def _not_built_for_here(output: str, found: Plan) -> tuple[str, str]:
    """(the reason, what the person can do) where pip could not take a library whose one version the project's
    lock file fixes, and the lock file's own list of that version's files says why: none of them is ready-built for
    the system the tests run on. pip's own word for it is "conflicting dependencies" (what the project asks for
    against the version the lock file fixes), which names no cause. ("", "") when the lock file does not say."""
    here = "Linux" if found.platforms or sys.platform.startswith("linux") else \
        "macOS" if sys.platform == "darwin" else "Windows" if os.name == "nt" else ""
    named = re.findall(r"No matching distribution found for ([^\s(<>=!~;\[]+)", output)
    m = re.search(r"Cannot install (.{1,2000}?) because these package versions have conflicting dependencies", output)
    if m:
        named += [re.split(r"[\s(<>=!~;\[]", part.strip(), maxsplit=1)[0] for part in re.split(r",\s*|\s+and\s+", m.group(1))]
    for name in named:
        versions = found.listed.get(_norm(name), {})
        if not here or len(versions) != 1:
            continue
        version, files = next(iter(versions.items()))
        systems, source = _built_for(files)
        if "any" in systems or here in systems or not (systems or source):
            continue
        what = f"{_library_words(name)} {version}, the version the project's lock file fixes, has no ready-built package"
        if not systems:
            return (what + " (the lock file lists it as source only: it has to be built by running code it brings, "
                    "and Lantern does not build a library)"), ""
        others = sorted(systems)
        listed = ", ".join(others[:-1]) + (" and " if len(others) > 1 else "") + others[-1]
        mark = _MARKERS.get(others[0]) if len(others) == 1 else None
        return (f"{what} for {here} (the lock file lists it ready-built for {listed} only"
                + (", and as source, which Lantern does not build" if source else "") + ")",
                f". Where the tests do not need it on {here}, the project can say which systems it is for where it "
                "names it" + (f' (`{_library_words(name)}; sys_platform == "{mark}"`)' if mark else "")
                + f": it is then not asked for on {here}, and the tests run on the rest")
    return "", ""


def _pip_failure(output: str, store: Store, refused: int) -> str:
    missing = re.findall(r"No matching distribution found for ([^\s(<>=!~;\[]+)", output)
    if missing:
        return (f"{_library_words(missing[0])} was not found in the store ({store.host}) as a ready-built package "
                "for this Python")
    if "DO NOT MATCH THE HASHES" in output:
        return "a file the store handed out is not the one the project's fingerprint names"
    if "--require-hashes mode" in output or "Hashes are required" in output:
        return ("the project writes fingerprints for some of its libraries and not for all, and pip then takes no "
                "file without one: every library, and each one those need, has to be named with its exact version "
                "and its fingerprint")
    if "ResolutionImpossible" in output or "conflicting dependencies" in output:
        m = re.search(r"Cannot install (.{1,300}?) because these package versions have conflicting dependencies", output)
        about = [w for w in (re.split(r"[\s(<>=!~;\[]", part.strip(), maxsplit=1)[0]
                             for part in re.split(r",\s*|\s+and\s+", m.group(1) if m else ""))
                 if re.fullmatch(_NAME, w)][:3]
        return "the versions the project names cannot be had together" \
            + (f" (pip could not take {' or '.join(_library_words(w) for w in about)} beside the rest)" if about else "")
    if "no such option: --report" in output:
        return "the pip of the Python that runs Lantern is too old to say what it fetched (pip 23 or newer does)"
    if refused:
        return f"the fetch asked for {refused} place(s) that are not the store, which the doorkeeper refused"
    if "Connection refused" in output or "ProxyError" in output or "Max retries exceeded" in output:
        return f"the store ({store.host}) could not be reached"
    return "pip ended with an error (its last lines are in the log)"


def _fetch_python(job: _Fetch, repo: Path, app: Path) -> Path:
    found, store = job.plan, job.store
    if getattr(importlib.util.find_spec("pip"), "origin", None) is None:
        job.stop("the Python that runs Lantern has no pip to fetch them with")
    libs = job.root / "libs"
    libs.mkdir()
    wanted, report = job.dir / "wanted.txt", job.dir / "fetched.json"
    wanted.write_text("\n".join(found.lines) + "\n", encoding="utf-8")
    cmd = programs.python("pip", "install", "--isolated", "--no-input", "--disable-pip-version-check", "--no-cache-dir",
                          "--only-binary=:all:", "--no-compile", "--no-warn-script-location", "--no-warn-conflicts",
                          "--progress-bar", "off",
                          "--quiet", "--retries", "1", "--timeout", "30", "--target", str(libs),
                          "--index-url", store.url, "--proxy", job.proxy, "--report", str(report), "-r", str(wanted))
    if found.constraints:
        keep = job.dir / "versions.txt"
        keep.write_text("\n".join(found.constraints) + "\n", encoding="utf-8")
        cmd += ["-c", str(keep)]
    if job.cert:
        cmd += ["--cert", str(job.cert)]
    for system in found.platforms:
        cmd += ["--platform", system]
    # `--no-warn-conflicts`: pip otherwise compares what it fetched with the libraries installed in the Python it
    # runs in (those beside Lantern, which the tests never run on) and writes each one that wants another version
    # as an "ERROR" of the project's fetch.
    job.hand_over(libs)
    pip = importlib.util.find_spec("pip")
    readable = [os.path.dirname(pip.origin), os.path.dirname(os.__file__)]
    rc, output, timed_out = job.run(cmd, job.dir, [job.dir, libs], readable)
    if rc is None and not timed_out:
        return None
    if timed_out:
        job.stop(f"the fetch was not through after {FETCH_SECONDS // 60} minutes")
    if rc != 0:
        why, then = _not_built_for_here(output, found)
        job.stop(why or _pip_failure(output, store, job.refused()), then)
    text, why = results.plain(report)
    try:
        installed = manifest.rows(manifest.table(json.loads(text or "")).get("install"))
    except ValueError:
        installed = None
    if installed is None or why:
        job.stop("pip did not say what it fetched")
    packages = []
    for item in installed:
        item = manifest.table(item)
        meta, info = manifest.table(item.get("metadata")), manifest.table(item.get("download_info"))
        archive = manifest.table(info.get("archive_info"))
        digest = manifest.text(manifest.table(archive.get("hashes")).get("sha256")) \
            or manifest.text(archive.get("hash")).removeprefix("sha256=")
        name, version = _plain(manifest.text(meta.get("name")), 100), _plain(manifest.text(meta.get("version")), 100)
        if not name or not re.fullmatch(r"[0-9a-f]{64}", digest):
            job.stop("pip did not say what it fetched")
        named = found.locked.get(_norm(name), {}).get(version)
        if named and digest not in named:
            job.stop(f"the file the store handed out for {_library_words(name)} {version} is not one the project's "
                     "lock file names (its fingerprint differs)")
        packages.append({"name": name, "version": version, "fingerprint": "sha256:" + digest,
                         "file": _plain(urlsplit(manifest.text(info.get("url"))).path.rsplit("/", 1)[-1], 200),
                         "asked": bool(item.get("requested")), "exact": _norm(name) in found.pinned,
                         # the fingerprint is one the project names: in its lock file, or beside its requirements
                         # (pip then takes no file whose fingerprint is not written there)
                         "checked": bool(named) or found.hashed})
    packages.sort(key=lambda p: _norm(p["name"]))
    found.record.update(state="fetched", store=store.host, packages=packages, added=found.added)
    return libs


_ONE_VERSION = re.compile(r"=?v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")     # npm: one version, no range


def _npm_failure(output: str, store: Store, refused: int) -> str:
    if "EINTEGRITY" in output:
        return "a package the store handed out is not the one the lock file names (its fingerprint differs)"
    if refused:
        return f"the fetch asked for {refused} place(s) that are not the store, which the doorkeeper refused"
    if "E404" in output:
        return f"a package the project names is not in the store ({store.host})"
    if "ECONNREFUSED" in output or "ETIMEDOUT" in output or "ENOTFOUND" in output:
        return f"the store ({store.host}) could not be reached"
    return "npm ended with an error (its last lines are in the log)"


def _fetch_node(job: _Fetch, repo: Path, app: Path, cwd_rel: str):
    found, store, sandbox = job.plan, job.store, job.sandbox
    npm = programs.find("npm")
    if not npm:
        job.stop("npm is not installed on this computer")
    stage = job.dir / "npm"
    stage.mkdir()
    lock = {}
    if found.lock is not None:
        lock = manifest.table(manifest.parse_json(_text(found.lock, repo) or ""))
        if _elsewhere(lock, store):
            raise sandbox.NoLibraries(f"the project's libraries could not be fetched: {found.lock.name} {ELSEWHERE} "
                                      f"({_elsewhere(lock, store)} of its packages), so the tests were not run on "
                                      "other libraries than the project's")
        where, left = depaudit._npm_stage(found.lock, repo, stage)
        if where is None:
            job.stop(_plain(left[0] if left else "npm's lock file cannot be used", 300))
        verb = "ci"
    else:
        where = stage / "project"
        where.mkdir()
        data = manifest.parse_json(_text(found.manifest, repo) or "")
        if not isinstance(data, dict):
            job.stop("package.json cannot be read")
        (where / "package.json").write_text(json.dumps(data), encoding="utf-8")
        verb = "install"
        found.notes.append("package.json: no lock file, so the newest versions that fit were taken")
    nothing = job.dir / "no-settings"       # two names that are no files: npm reads no settings of anyone's
    cmd = [npm, verb, "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error", "--fetch-retries=1",
           f"--registry={store.url}", f"--proxy={job.proxy}", f"--https-proxy={job.proxy}", "--noproxy=",
           f"--userconfig={nothing / 'user'}", f"--globalconfig={nothing / 'global'}", f"--cache={job.tmp / 'npm'}"]
    if job.cert:
        cmd.append(f"--cafile={job.cert}")
    job.hand_over()
    rc, output, timed_out = job.run(cmd, where, [job.dir], [])
    if rc is None and not timed_out:
        return None
    if timed_out:
        job.stop(f"the fetch was not through after {FETCH_SECONDS // 60} minutes")
    if rc != 0:
        job.stop(_npm_failure(output, store, job.refused()))
    text, why = results.plain(where / "package-lock.json")
    final = manifest.table(manifest.parse_json(text or ""))
    packages, seen, theirs = [], set(), manifest.table(lock.get("packages"))
    wanted = dict(a["text"].rsplit("@", 1) for a in found.asked if "@" in a["text"][1:])
    for key, entry in manifest.table(final.get("packages")).items():
        entry = manifest.table(entry)
        if "node_modules/" not in key or entry.get("link"):
            continue
        name = _plain(manifest.text(entry.get("name")) or key.rsplit("node_modules/", 1)[1], 200)
        version = _plain(manifest.text(entry.get("version")), 100)
        if (name, version) not in seen:
            seen.add((name, version))
            integrity = manifest.text(entry.get("integrity"))
            packages.append({"name": name, "version": version, "fingerprint": _plain(integrity, 200),
                             "file": _plain(manifest.text(entry.get("resolved")).rsplit("/", 1)[-1], 200),
                             "asked": key.count("node_modules/") == 1 and any(
                                 a["text"].rsplit("@", 1)[0] == name for a in found.asked),
                             # npm ci takes the lock file's version and refuses a file with another fingerprint;
                             # with no lock file only a library package.json itself names by one version is fixed
                             "exact": found.lock is not None or (key.count("node_modules/") == 1 and bool(
                                 _ONE_VERSION.fullmatch(wanted.get(name, ""))) and wanted[name].lstrip("=v") == version),
                             "checked": bool(integrity) and manifest.table(theirs.get(key)).get("integrity") == integrity})
    packages.sort(key=lambda p: p["name"])
    target = (app / cwd_rel if cwd_rel else app) / "node_modules"
    try:
        if os.path.lexists(target) and not sandbox._rm(target):
            job.stop("the copy's own node_modules folder could not be replaced")
        if (where / "node_modules").is_dir():
            os.rename(where / "node_modules", target)
    except OSError as e:
        job.stop(f"the fetched packages could not be put beside the copy ({e.strerror or type(e).__name__})")
    scripts = sum(1 for e in manifest.table(final.get("packages")).values() if manifest.table(e).get("hasInstallScript"))
    if scripts:
        found.notes.append(f"{scripts} package(s) bring an install script, which was not run")
    # Node looks for a package in `node_modules` of every folder above the one it runs in, up to the top. Above
    # the copy that is this run's own folder and then the person's: one that lies there (a stray `npm install` in
    # the home folder, with the temp folder beneath it) is in reach of the tests, and it cannot be taken out of
    # Node's way. It is said, as a count and never as a place.
    above = sum(1 for folder in app.parents if os.path.isdir(folder / "node_modules"))
    if above:
        found.notes.append(f"{above} folder(s) of packages lie above the folder the tests run in, on this computer: "
                           "Node looks there too, so the tests may load a package the project does not name")
        found.record["above"] = above
    found.lock_name = found.lock.name if found.lock is not None else ""
    found.record.update(state="fetched", store=store.host, packages=packages, added=[], notes=found.notes)
    return target


def fetch(found: Plan, repo: Path, app: Path, root: Path, cwd_rel: str, log, cancel=None, memory: int = 2048):
    """Fetch what `found` names for the run whose temp folder is `root` and whose copy of the project is `app`.
    Returns the folder the libraries are in (Python: to be put on the tests' path; JavaScript: `node_modules`,
    already beside the copy's `package.json`), or None when the fetch was stopped because it was asked to.
    Raises `sandbox.NoLibraries`, with the reason, when the libraries could not be fetched, and `Unavailable` when
    the sandbox the fetch runs in could not be set up: the tests are then not started."""
    job = _Fetch(found, root, log, cancel, memory)
    held = walls()
    log(f"sandbox: fetching the libraries the project names from {job.store.host}, {WALL_WORDS[held]}")
    try:
        where = _fetch_python(job, repo, app) if found.language == "python" else _fetch_node(job, repo, app, cwd_rel)
    finally:
        job.sandbox._rm(job.dir)        # what the fetching program left beside the libraries; the run's folder goes later
    if where is None:
        return None
    packages = found.record.get("packages", [])
    log(f"sandbox: fetched {len(packages)} librar{'y' if len(packages) == 1 else 'ies'} from {job.store.host}, each "
        "with its fingerprint:")
    for p in packages[:SHOWN]:
        log(f"sandbox:   {p['name']} {p['version']}  {p['fingerprint'][:19]}…")
    if len(packages) > SHOWN:
        log(f"sandbox:   and {len(packages) - SHOWN} more (all of them are in the record)")
    for note in found.notes:
        log("sandbox: " + note)
    count, loose = len(packages), sum(1 for p in packages if not p.get("exact"))
    checked = sum(1 for p in packages if p.get("checked"))
    if count and not loose:
        log("sandbox: every version is the project's own choice" + (f" ({found.lock_name})" if found.lock_name else ""))
    elif count:
        log(f"sandbox: {loose} of {count} librar{'y' if count == 1 else 'ies'} {'is' if loose == 1 else 'are'} at a "
            "version the project does not fix: the newest that fits was taken, and a run on another day may take another")
    if count:
        log("sandbox: " + ("every fingerprint is one the project names itself" if checked == count else
                           f"{checked} of {count} fingerprints are ones the project names itself; the others are "
                           "what the store handed out" if checked else
                           "the project names no fingerprint: each one above is what the store handed out, written "
                           "down so that a later run can be compared with this one"))
    reached = sorted({line.split(" ", 1)[1] for line in job.said if line.startswith(_stores.OPENED)})
    found.record.update(exact=not loose, checked=checked, reached=reached, refused=job.refused(), walls=held)
    if found.lock_name:
        found.record["locked"] = found.lock_name
    return where
