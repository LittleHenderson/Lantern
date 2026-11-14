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
* **What the project names as optional is fetched too, and left out when it cannot be had** (2026-11-14; Python).
  The libraries of every other extra or group of `pyproject.toml` (`Plan.optional`) are asked for beside the
  rest, so that a test of any part of the project can run. Where that fetch does not go through, it starts again
  without them (`fetch`), the tests run on what the project always needs and names for its tests, and the run
  and the record say which groups were left out and why (`record["optional"]`: `groups`, `more`, `fetched`,
  `why`). They are not asked for at all where one of them names another store, a link or a folder, or where the
  project writes fingerprints beside its libraries; a project whose only libraries are optional ones runs on
  them. What the project always needs is never left out.
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
* **The tests then run on exactly those libraries, with the network off wherever the run's own walls hold**
  (`sandbox.tests_off_the_network`, `described`: JavaScript tests on macOS and Windows are not kept from the
  network by anything of Lantern's, and the line about the libraries says so there): for Python the libraries
  installed beside Lantern are taken off the path (`LANTERN_SANDBOX_LIBRARIES=fetched`, the guard file's
  `_only_fetched`), so a project that forgot to name a library hears of it here. Where the tests run in a container, the libraries
  are fetched for the container's system (`Plan.platforms`) and handed to it to read.
* **The record names every library** with its version, the file that was fetched and its fingerprint
  (`sandbox.run(...)["libraries"]`, `run.json` `trace.libraries`), and whether every version was the project's
  own choice (`exact`).

Offline (`--offline`, LANTERN_OFFLINE) nothing is fetched: the tests run on what is installed when every library
the project names is there (`state: "installed"`), and are otherwise not run, with the missing ones named.
Nothing is kept between runs: the folder the libraries are fetched into is the run's temp folder."""
from __future__ import annotations

import collections
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

from . import _builder, _stores, depaudit, manifest, programs, results

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
BUILD_SECONDS = 600                     # the time each step of a build gets (`_build`)
MOST_BUILT = 5                          # the libraries one run builds from their source
MOST_SOURCE = 200 << 20                 # the bytes of a source package that are taken
MOST_PACKAGE = 1 << 30                  # the bytes of the package a build may hand back
BUILD_LINES = 40                        # the lines of a build step's own output the log takes from its start,
BUILD_TAIL = 40                         # and from its end (where an error is said); the rest is counted

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
        # Python: the libraries the project names as optional (`[project.optional-dependencies]`, a group that is
        # not one for its tests): {"line", "text", "file", "name", "exact"}; `groups`: the names of those groups;
        # `optional_why`: why they are not asked for at all, when they are not
        self.optional: list[dict] = []
        self.groups: list[str] = []
        self.optional_why = ""
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

    def optional(self, text: str, rel: str) -> None:
        """A library of a group the project names as optional. It is kept apart (`plan.optional`): the fetch asks
        for these beside the rest, and goes on without them when they cannot be had (`fetch`). A line that takes
        a library from another store, a link or a folder, or one in a form Lantern does not read, is not followed
        here either; no optional library is asked for then, and the run says why (`plan.optional_why`)."""
        if self.plan.optional_why:
            return
        if "://" in text or " @ " in text or text.startswith((".", "/", "file:")) or text.endswith((".whl", ".zip", ".tar.gz")):
            self.plan.optional_why = "one of them " + ELSEWHERE.replace("names", "is named with", 1).replace(
                " to take libraries from", "")
            return
        got = _requirement(text)
        if got is None:
            self.plan.optional_why = "one of them is named in a form Lantern does not read"
            return
        name, line, shown = got
        if _norm(name) == self.own or _norm(name) in self.folders or any(o["text"] == shown for o in self.plan.optional):
            return
        if len(self.plan.optional) >= MOST_LINES:
            self.plan.optional_why = f"they are more than {MOST_LINES}"
            return
        spec = re.split(r"[ ;]", shown[len(name):].split("]")[-1], maxsplit=1)[0]
        self.plan.optional.append({"line": line, "text": shown, "file": rel, "name": _norm(name),
                                   "exact": bool(PINNED.fullmatch(spec or "")) and "*" not in spec})

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
    # The groups of libraries the project names as optional: every group that is not one for its tests. Their
    # libraries are asked for beside the rest, so that a test of any part of the project can run (2026-11-14:
    # Lantern's own tests need the libraries it names under `scan`, and a public project's the ones under
    # `minify`; until then such tests failed for that alone, and the decision read "the tests failed").
    left: set[str] = set()
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
        for group, deps in table.items():
            if group in taken or not manifest.rows(deps):
                continue
            left.add(str(group))
            for dep in manifest.rows(deps):
                if isinstance(dep, str):
                    reader.optional(dep, rel)
                elif isinstance(dep, dict) and isinstance(dep.get("include-group"), str):
                    for inner in manifest.texts(table.get(dep["include-group"])):
                        reader.optional(inner, rel)
    reader.own = reader.own or _norm(manifest.text(poetry.get("name")))
    # Poetry: its own table of libraries (one it marks `optional` is in there, and is taken with the rest, as
    # before), its groups for tests, and after them every other group, as optional
    tables = [(manifest.table(poetry.get("dependencies")), False), (manifest.table(poetry.get("dev-dependencies")), False)]
    for name, g in manifest.table(poetry.get("group")).items():
        deps = manifest.table(manifest.table(g).get("dependencies"))
        if name in TEST_GROUPS:
            tables.append((deps, False))
        elif deps:
            left.add(str(name))
            tables.append((deps, True))
    reader.plan.groups = sorted(set(reader.plan.groups) | left)
    for table, optional in tables:
        for name, value in table.items():
            if _norm(name) == "python":
                continue
            if isinstance(value, dict):
                if any(k in value for k in ("git", "path", "url", "file")):
                    if optional:
                        reader.optional("./" + _plain(str(name), 60), rel)      # counted as taken from elsewhere
                    else:
                        reader.elsewhere(rel)
                    continue
                extras = manifest.texts(value.get("extras"))    # (`source` names one of the stores read above)
                name, value = name + (f"[{','.join(extras)}]" if extras else ""), manifest.text(value.get("version"))
            if isinstance(value, str):
                (reader.optional if optional else reader.add)(_caret(name, value), rel)


def _group_words(groups: list[str]) -> str:
    """The names of a project's groups for Lantern's own sentences: up to six, each one a name a tool would write;
    the rest are counted. (They are the project's text: one that is not such a name is not repeated.)"""
    named = sorted(g for g in groups if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,39}", g))
    shown, more = [f'"{g}"' for g in named[:6]], len(groups) - min(len(named), 6)
    if shown and not more:
        return ", ".join(shown[:-1]) + (" and " if len(shown) > 1 else "") + shown[-1]
    return ", ".join(shown) + (" and " if shown else "") + f"{more} more"


LEFT_OUT = ("Lantern takes what the project always needs and what it names for its tests, so a test of a part that "
            "needs an optional library fails here for that alone")


def _optional_record(plan: Plan, fetched: bool, why: str = "") -> dict:
    named = sorted(g for g in plan.groups if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,39}", g))
    return {"groups": named[:40], "more": len(plan.groups) - len(named[:40]), "fetched": fetched,
            **({"why": why} if why else {})}


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
    # what the project names as optional and also names for good is no optional library
    plan.optional = [o for o in plan.optional if o["text"] not in reader.seen]
    if offline or not plan.groups:
        plan.optional = []                      # offline nothing is fetched: the tests run on what is installed
    elif plan.hashed and plan.optional and not plan.optional_why:
        plan.optional_why = ("the project writes fingerprints beside its libraries and none beside these, and no "
                             "file is taken without a fingerprint then")
    if plan.groups and not offline and (plan.optional_why or not plan.optional):
        why = plan.optional_why or "every one of them is the project itself or one it names for good already"
        if plan.optional_why:
            plan.notes.append(f"pyproject.toml: the libraries the project names as optional (under "
                              f"{_group_words(plan.groups)}) were not fetched: {why}. {LEFT_OUT}")
            plan.record["optional"] = _optional_record(plan, False, why)
        plan.optional = []
    if not plan.asked and plan.optional:
        # the only libraries the project names: they are what its tests run on, and there is no "rest" to go on with
        for o in plan.optional:
            reader.add(o["line"], o["file"])
        plan.record["optional"] = _optional_record(plan, True)
        plan.optional = []
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
    from . import sandbox
    line = (f"the libraries your project names are fetched first, from {store.host} and nowhere else, "
            f"{wall_words(walls())}, into a folder that is deleted after; only ready-built packages, so no code "
            "of a library runs while it is fetched; the tests then run ")
    if sandbox.tests_off_the_network(language):
        return line + "with the network off on exactly those libraries"
    # tests that are not Python, where nothing below Python holds a program (`sandbox.held_below_python`)
    return line + ("on exactly those libraries, and are not kept from the network by this run (the line about the "
                   "network says why)")


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


# Inside a sandbox whose doorman makes every connection for what runs in it (Lantern's own tests, run by Lantern),
# the kernel's rule for a program's own connections decides nothing: the doorman, which is not under that rule,
# makes them. What holds the fetching program there is the sandbox around this one.
TOLD_INSIDE = ("through Lantern's doorkeeper, which the fetching program is told to use (a sandbox around this one "
               "makes every connection for what runs inside it, so no rule of this run's own holds the program to "
               "that; the walls of that sandbox stand)")


def _doorman_above() -> bool:
    from . import sandbox
    return sys.platform.startswith("linux") and sandbox.own_sockets() == sandbox.DOORMAN_ABOVE


def walls() -> str:
    """`own-network`: the fetch runs in a network that holds the doorkeeper's listener and nothing else (Linux,
    where the system gives a run one). `port-rule`: the kernel lets the fetching program connect to the
    doorkeeper's port and to no other (Landlock, Linux 6.7 on). `told`: pip or npm is given the doorkeeper as its
    proxy and nothing in the system holds it to that (macOS, Windows, an older Linux, and a run inside a sandbox
    whose doorman makes its connections: `_doorman_above`)."""
    from . import sandbox
    if _own_network_here():
        return "own-network"
    if _doorman_above():
        return "told"
    return "port-rule" if sys.platform.startswith("linux") and sandbox.landlock_abi() >= 4 else "told"


def wall_words(held: str) -> str:
    """The words for what holds the fetching program, for the log and the sheet."""
    return TOLD_INSIDE if held == "told" and _doorman_above() else WALL_WORDS[held]


# ---------------------------------------------------------------------------- where a library is built
def cannot_build(platforms=()) -> str:
    """Why no library is built from its source in this run, in words that end a sentence; "" where one is.

    Building a library runs code it brings, and a build starts what it likes (a compiler), so Python's guard holds
    nothing of it. A library is built only where the kernel holds any program of the run to the run's walls: the
    network (`sandbox.held_below_python`) and the folders (Landlock). That is Linux, outside another sandbox.
    `platforms`: the systems the libraries are fetched for when that is not this one (the tests' container); a
    library would have to be built there too, which is not done."""
    from . import sandbox
    if platforms:
        return ("the tests run in a container here, and a library is built only where the tests run on this "
                "computer itself (LANTERN_SANDBOX=subprocess)")
    if not sandbox.held_below_python():
        return "a build is a program that Python's guard does not hold, and " + sandbox.not_held_how()
    if sandbox.landlock_abi() < 1:
        return ("a build is a program that Python's guard does not hold, and this system's kernel has no rule for "
                "folders that Lantern can set (Landlock), so a build could read and write what you can")
    if not sys.platform.startswith("linux"):
        return "the kernel's rules a build is held by are Linux's"
    return ""


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
        self.port, self.proxy = DOOR_PORT, f"http://127.0.0.1:{DOOR_PORT}"
        self.way_out()

    def way_out(self) -> None:
        """The way out for the next fetching program: `proxy`. In a network of the fetch's own the launcher makes
        the doorkeeper there, for each program anew. Where the system gives a run none, the doorkeeper listens on
        this computer, and each `run` closes its own when its program ends: a fetch that builds a library fetches
        more than once, and no doorkeeper listens while a build runs. A command line that names `proxy` is
        written after this."""
        if self.own or self.door is not None:
            return
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
            elif not _doorman_above():      # there the rule would be written down and decide nothing (`walls`)
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
            self.close()
            self.plan.left = left + (sandbox._left_by_launcher(output) if os.name == "posix" else [])
        why = sandbox._unavailable(rc, output)
        if why:
            raise sandbox.Unavailable(why)
        return rc, output, timed_out

    def behind_walls(self, cmd: list[str], cwd: Path, tmp: Path, writable: list[Path], readable: list[str],
                     wall: dict | None, first: tuple[str, ...] = (), more_env: dict | None = None):
        """(result, output, stopped at the time limit) of one step of a build (`_build`), started under the rules
        a project's tests are started under (`sandbox._run_subprocess`) and with no way out: no doorkeeper and no
        port it may connect to, a network of its own where the system gives a run one, the doorman, the run's
        memory, the person's own folders closed to its reads (`wall`), writes in `writable` only, and everything
        it started ended with it. Not Python's guard: a build starts what it likes, so only what holds any program
        counts (`cannot_build`, which is asked before any of this). `first`: folders that stand first on PATH."""
        from . import _jail
        sandbox = self.sandbox
        linux = sys.platform.startswith("linux")
        env = sandbox._env_base(tmp)
        env.pop("VIRTUAL_ENV", None)
        env.update(more_env or {})
        if self.as_nobody and env.get("PATH"):
            env["PATH"] = sandbox._path_for(env["PATH"], 65534, 65534)[0]
        env["PATH"] = os.pathsep.join([*first, *([env["PATH"]] if env.get("PATH") else [])])
        policy = {"writable": [str(w) for w in writable], "nobody": self.as_nobody, "python": False, "net": True,
                  "own_net": not sandbox.own_network(), "net_told": False, "must": True, "parent": os.getpid(),
                  "cpu": max(sandbox.WALL_CLOCK, BUILD_SECONDS) * sandbox._processors(), "memory": self.memory << 20,
                  "readable": readable, "runs": cmd[0] if os.path.isabs(cmd[0]) else "",
                  "shm": (self.memory << 20) // 4 if linux and not sandbox.own_memory() else 0,
                  "sockets": linux and not sandbox.own_sockets()}
        if wall is not None:
            policy["read"] = wall
        pkg_root = str(Path(__file__).resolve().parent.parent)
        cmd = [sys.executable, "-I", "-c",
               f"import sys; sys.path.insert(0, {pkg_root!r}); from lantern._jail import main; main(sys.argv[1:])",
               json.dumps(policy), "--", *cmd]

        lock, last, counts = threading.Lock(), collections.deque(maxlen=BUILD_TAIL), [0, 0, False]

        def said(line: str) -> None:
            # Every line is taken as the build's own, whatever it begins with. The launcher's lines about its
            # walls begin with "sandbox:" and are left out: Lantern said once which walls a build runs behind,
            # and a build that writes such a line itself gains nothing by it. The log takes the first lines of a
            # step and its last ones; a build may write thousands.
            if not line.strip() or line.startswith("sandbox:"):
                return
            with lock:
                if counts[2]:
                    return
                if counts[0] < BUILD_LINES:
                    counts[0] += 1
                    self.log("sandbox: build: " + line[:300])
                else:
                    counts[1] += 1
                    last.append(line[:300])
        left: list[str] = []
        output = ""
        try:
            rc, output, timed_out = sandbox._stream(cmd, cwd, env, BUILD_SECONDS, said, cancel=self.cancel,
                                                    ask=_jail.ASK if linux else 0.0, left=left)
        finally:
            self.plan.left = left + sandbox._left_by_launcher(output)
            with lock:
                counts[2] = True            # whatever still holds the step's output open writes nothing more here
                if counts[1] > len(last):
                    self.log(f"sandbox: build: ({counts[1] - len(last)} more lines of this step are left out here)")
                for line in last:
                    self.log("sandbox: build: " + line)
        why = sandbox._unavailable(rc, output)
        if why:
            raise sandbox.Unavailable(why)
        return rc, output, timed_out

    def refused(self) -> int:
        return sum(1 for line in self.said if line.startswith(_stores.REFUSED))

    def held_by(self) -> str:
        """What holds this fetch's program to its doorkeeper, in words."""
        return wall_words("own-network" if self.own else walls())

    def close(self) -> None:
        """The doorkeeper of this fetch stops listening (a fetch that stopped before its program ran left it open)."""
        if self.door is not None:
            self.door.close()
            self.door = None

    def stop(self, why: str, then: str = "", final: bool = False):
        stopped = self.sandbox.NoLibraries(f"the project's libraries could not be fetched: {why}, so its tests were "
                                           f"not run{then}")
        stopped.why = why               # the reason alone, for a fetch that goes on without the optional libraries
        stopped.final = final           # no fetch goes on after this one, with fewer libraries or otherwise (`fetch`)
        raise stopped


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
        why = cannot_build(found.platforms)
        unbuilt = f"Lantern does not build a library here: {why}" if why else "it was not built"
        if not systems:
            return (what + " (the lock file lists it as source only: it has to be built by running code it brings, "
                    f"and {unbuilt})"), ""
        others = sorted(systems)
        listed = ", ".join(others[:-1]) + (" and " if len(others) > 1 else "") + others[-1]
        mark = _MARKERS.get(others[0]) if len(others) == 1 else None
        return (f"{what} for {here} (the lock file lists it ready-built for {listed} only"
                + (f", and as source, and {unbuilt}" if source else "") + ")",
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


def _pip(job: _Fetch, target: Path, wanted: Path, report: Path, *more: str) -> list[str]:
    """pip's command line for one fetch into `target`: ready-built packages only, from the person's store, through
    this fetch's doorkeeper (`job.way_out()` comes first)."""
    cmd = programs.python("pip", "install", "--isolated", "--no-input", "--disable-pip-version-check", "--no-cache-dir",
                          "--only-binary=:all:", "--no-compile", "--no-warn-script-location", "--no-warn-conflicts",
                          "--progress-bar", "off",
                          "--quiet", "--retries", "1", "--timeout", "30", "--target", str(target),
                          "--index-url", job.store.url, "--proxy", job.proxy, "--report", str(report), "-r", str(wanted),
                          *more)
    if job.cert:
        cmd += ["--cert", str(job.cert)]
    return cmd


def _reported(report: Path) -> list[dict] | None:
    """What pip's report says it installed, one row a package: `name`, `version`, `digest` (the SHA-256 of the
    file), `url` (where the file came from), `asked`. None when the report does not say."""
    text, why = results.plain(report)
    try:
        installed = manifest.rows(manifest.table(json.loads(text or "")).get("install"))
    except (ValueError, RecursionError):
        installed = None
    if installed is None or why:
        return None
    rows = []
    for item in installed:
        item = manifest.table(item)
        meta, info = manifest.table(item.get("metadata")), manifest.table(item.get("download_info"))
        archive = manifest.table(info.get("archive_info"))
        digest = manifest.text(manifest.table(archive.get("hashes")).get("sha256")) \
            or manifest.text(archive.get("hash")).removeprefix("sha256=")
        name, version = _plain(manifest.text(meta.get("name")), 100), _plain(manifest.text(meta.get("version")), 100)
        if not name or not re.fullmatch(r"[0-9a-f]{64}", digest):
            return None
        rows.append({"name": name, "version": version, "digest": digest, "url": manifest.text(info.get("url")),
                     "asked": bool(item.get("requested"))})
    return rows


# ---------------------------------------------------------------------------- a library that has to be built
# (2026-11-14.) Until this step only ready-built files were taken, and a library whose one version the project
# fixes, and that the store has for this system as source only, meant "no test was run". Such a library is built
# now, one step at a time, by Lantern's own small program (`lantern/_builder.py`, a copy of it in the build's
# folder) and never by pip or a `setup.py`:
#
#   source   the source package of exactly that version, from the store, through the doorkeeper. Nothing of it
#            is read. Lantern then takes the file's fingerprint itself: it has to be one the project names (its
#            lock file, or `--hash` beside the requirement), or, where the project names none, the one the
#            store's page names for the file.
#   unpack   behind the walls of the tests' run (`_Fetch.behind_walls`), like every step after it that looks
#            into the package: files and folders beneath one top folder, or nothing; and how it says it is built.
#   tools    what the build names as its tools: names with versions, asked of the store as the project's
#            libraries are (ready-built only, through the doorkeeper), into a folder of the build's own. A tool
#            is never built.
#   needs    the build is asked what else it needs (the first step that runs code the library brings).
#   build    it builds. No doorkeeper listens while any of the last two run.
#
# What comes back is believed only as far as Lantern can look at it: one plain file in the build's `out` folder,
# named as a package of that library at that version, copied out by Lantern with its fingerprint taken on the way;
# what the file says of itself inside is pip's to check when it is asked to take it (inside the fetch's walls).
# The tests' copy, their libraries, their temp folder and their Python are no folder of a build's.
_STEP_WHY = {
    "link": "holds a link, and a source package with a link in it is not unpacked",
    "outside": "holds a name that leaves its folder",
    "top": "does not have one folder at its top with everything in it",
    "kind": "holds something that is neither a file nor a folder",
    "count": f"holds more than {_builder.MOST_FILES} files",
    "size": "is larger than Lantern unpacks",
    "broken": "cannot be read (it is cut short, or is no source package)",
    "follow": "says how it is built in a form Lantern cannot follow",
    "outside-code": "names code for its build that lies outside its source",
}
BUILDING = ("sandbox: {words} is not in the store ({host}) ready-built for this system: building it from its source, "
            "behind the walls the tests run behind and with the network off")
_PACKAGE = re.compile(r"([A-Za-z0-9_.]+)-([A-Za-z0-9_.!+]+)(?:-\d[A-Za-z0-9_.]*)?-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)


def _time_words(seconds: int) -> str:
    return f"{seconds // 60} minutes" if seconds >= 120 else f"{seconds} seconds"


def _own_look(path: Path, most: int, into: Path | None = None) -> str | None:
    """The SHA-256 of the file at `path`, taken by Lantern itself: a plain file with one name, opened as itself
    and never through a link, of at most `most` bytes. With `into`, the bytes are written to that new file as
    they are read, so what is kept is what was looked at. None for anything else, and nothing is kept then."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _NOFOLLOW)
    except OSError:
        return None
    out, done = None, False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > most:
            return None
        if into is not None:
            out = os.open(into, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o644)
        digest, left = hashlib.sha256(), info.st_size
        while left:
            chunk = os.read(fd, min(1 << 20, left))
            if not chunk:
                return None                 # shorter than it was
            digest.update(chunk)
            left -= len(chunk)
            at = 0
            while out is not None and at < len(chunk):
                at += os.write(out, chunk[at:])
        if os.read(fd, 1):
            return None                     # longer than it was
        done = True
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)
        if out is not None:
            os.close(out)
            if not done:
                try:
                    os.unlink(into)
                except OSError:
                    pass


def _step_said(path: Path) -> dict:
    """What a step of a build wrote as its result (`_builder._say`): a small plain file that holds a table, or {}."""
    try:
        if os.lstat(path).st_size > 1_000_000:
            return {}
    except OSError:
        return {}
    text, why = results.plain(path)
    data = manifest.parse_json(text or "") if not why else None
    return data if isinstance(data, dict) else {}


def _fixed(found: Plan, name: str) -> str:
    """The one version of `name` the project fixes: the only one its lock file names, or the one it writes with
    `==` beside the library. "" where it fixes none, or more than one: which source to build is the project's
    word, never Lantern's choice."""
    key = _norm(name)
    versions = set(found.locked.get(key, {}))
    if versions:
        return next(iter(versions)) if len(versions) == 1 else ""
    for line in [*found.lines, *found.constraints]:
        got = _requirement(line)
        if got and _norm(got[0]) == key:
            spec = re.split(r"[ ;]", got[2][len(got[0]):].split("]")[-1], maxsplit=1)[0]
            m = PINNED.fullmatch(spec or "")
            if m and "*" not in spec:
                versions.add(m.group(1))
    return next(iter(versions)) if len(versions) == 1 else ""


def _named_prints(found: Plan, name: str, version: str) -> set[str]:
    """The SHA-256 fingerprints the project names for `name` at `version`: its lock file's, and the ones written
    beside the library's own requirement (`--hash=sha256:…`)."""
    key = _norm(name)
    named = set(found.locked.get(key, {}).get(version, ()))
    for line in [*found.lines, *found.constraints]:
        got = _requirement(line)
        if got and _norm(got[0]) == key:
            named.update(re.findall(r"--hash=sha256:([0-9a-f]{64})\b", got[1]))
    return named


def _here() -> str:
    """The system the tests run on, as `_built_for` names systems."""
    return "Linux" if sys.platform.startswith("linux") else "macOS" if sys.platform == "darwin" else \
        "Windows" if os.name == "nt" else ""


def _to_build(output: str, found: Plan) -> list[tuple[str, str, bool]]:
    """(name, version, sure) of each library pip could not take that may be built from its source. Sure: pip
    found no ready-built file of it, at the one version the project fixes; or pip's word is "conflicting
    dependencies" (what the project asks for against the version its lock file fixes, which names no cause) and
    the lock file lists that version as source, and ready-built for other systems only. Not sure: that word,
    about a library whose one version the project fixes in a lock file that lists no files (Pipenv's). Then the
    store's own page says whether the version is there ready-built for this system, and it is built only when
    not (`_build`)."""
    here = "Linux" if found.platforms else _here()
    wanted: list[tuple[str, str, bool]] = []

    def add(name: str, version: str, sure: bool) -> None:
        if version and re.fullmatch(_NAME, name) and len(name) <= 60 \
                and not any(_norm(w[0]) == _norm(name) for w in wanted):
            wanted.append((name, version, sure))
    for name in re.findall(r"No matching distribution found for ([^\s(<>=!~;\[]+)", output):
        add(name, _fixed(found, name), True)
    m = re.search(r"Cannot install (.{1,2000}?) because these package versions have conflicting dependencies", output)
    for part in re.split(r",\s*|\s+and\s+", m.group(1)) if m else []:
        name = re.split(r"[\s(<>=!~;\[]", part.strip(), maxsplit=1)[0]
        versions = found.listed.get(_norm(name), {})
        if len(versions) == 1:
            version, files = next(iter(versions.items()))
            systems, source = _built_for(files)
            if source and "any" not in systems and here not in systems and _fixed(found, name) == version:
                add(name, version, True)
        elif not versions and len(found.locked.get(_norm(name), {})) == 1:
            add(name, _fixed(found, name), False)
    return wanted


def _tool_lines(said) -> list[str] | None:
    """The lines pip is given for the tools a source package names (in its `pyproject.toml`, or when its build is
    asked): each a library's name with versions, in the form a store defines. None when one is anything else (a
    link, another store, a folder, an option, a fingerprint) or when they are too many: a stranger's text names no
    place to fetch from. A tool whose marker says it is for another Python or system is left out."""
    if not isinstance(said, list) or len(said) > _builder.MOST_TOOLS:
        return None
    lines = []
    for text in said:
        if not isinstance(text, str) or len(text) > 500:
            return None
        text = text.strip()
        if "://" in text or " @ " in text or text.startswith((".", "/", "file:", "-")) \
                or text.lower().endswith((".whl", ".zip", ".tar.gz")):
            return None
        got = _requirement(text)
        if got is None or got[1] != got[2]:
            return None
        fits = applies(got[2].partition(";")[2])
        if fits is None:
            return None
        if fits and got[1] not in lines:
            lines.append(got[1])
    return lines


def _fetch_tools(job: _Fetch, here: Path, tools: Path, lines: list[str], words: str, held: list[str], number: int):
    """Fetch the tools a build names into its `tools` folder: (the "name version" of each, the lines that hold a
    later fetch for the same build to these versions), or None when the fetch was stopped because it was asked
    to. They are asked of the store the way the project's libraries are, and a tool is never built."""
    wanted, report = here / "run" / f"tools-{number}.txt", here / "run" / f"tools-{number}.json"
    wanted.write_text("\n".join(lines) + "\n", encoding="utf-8")
    job.log(f"sandbox: build: fetching the tools the build of {words} names from the store ({job.store.host}), "
            f"ready-built only: {', '.join(_plain(line, 80) for line in lines[:8])}"
            + (f" and {len(lines) - 8} more" if len(lines) > 8 else ""))
    more = []
    if held:
        keep = here / "run" / f"held-{number}.txt"
        keep.write_text("\n".join(held) + "\n", encoding="utf-8")
        more = ["-c", str(keep)]
    job.way_out()
    cmd = _pip(job, tools, wanted, report, *more)
    pip = importlib.util.find_spec("pip")
    rc, output, timed_out = job.run(cmd, job.dir, [job.dir], [os.path.dirname(pip.origin), os.path.dirname(os.__file__)])
    if rc is None and not timed_out:
        return None
    if timed_out:
        job.stop(f"the tools the build of {words} names were not fetched after {FETCH_SECONDS // 60} minutes")
    if rc != 0:
        job.stop(f"the build of {words} could not get its tools: {_pip_failure(output, job.store, job.refused())}")
    rows = _reported(report)
    if rows is None:
        job.stop(f"the build of {words} could not get its tools: pip did not say what it fetched")
    if any(urlsplit(row["url"]).scheme == "file" for row in rows):
        job.stop(f"the build of {words} could not get its tools: one was taken from this computer and not from the store")
    names = [f"{row['name']} {row['version']}" for row in rows]
    hold = [f"{row['name']}=={row['version']}" for row in rows
            if re.fullmatch(_NAME, row["name"]) and re.fullmatch(_VERSION, row["version"]) and "*" not in row["version"]]
    return names, hold


def _build(job: _Fetch, repo: Path, name: str, version: str, number: int, sure: bool = True):
    """Build `name` at `version` from its source, in a folder of its own under the fetch's (the steps are named
    above `_STEP_WHY`). Returns what was built: `file` (the package, copied into the fetch's `built` folder),
    `sha256` (its fingerprint), `from` and `source_sha256` (the source package and its fingerprint), `with` (the
    tools), `checked` (the source's fingerprint is one the project names); "" when the store has no source
    package of that version; None when the run was stopped because it was asked to; False where it is not `sure`
    that the library has to be built (`_to_build`) and the store's page does not show it: the page names a
    ready-built file of that version for this system, or no source of it. Anything else stops the fetch, with the
    reason in Lantern's words (`job.stop`)."""
    found, store, sandbox = job.plan, job.store, job.sandbox
    words = f"{_library_words(name)} {version}"
    here = job.dir / "build" / str(number)
    kept = job.dir / "built"
    script = here / "run" / "_lantern_builder.py"
    try:
        for folder in ("in", "src", "tools", "out", "tmp", "run", "res"):
            (here / folder).mkdir(parents=True)
        shutil.copyfile(Path(__file__).resolve().parent / "_builder.py", script)
        kept.mkdir(exist_ok=True)
        job.hand_over()
        if job.as_nobody:               # the packages Lantern copies out of a build are Lantern's own to write
            os.chown(kept, 0, 0)
    except OSError as e:
        job.stop(f"the folder {words} would be built in could not be made ({e.strerror or type(e).__name__})")
    stdlib = os.path.dirname(os.__file__)
    archive = here / "in" / "source.tar.gz"

    # -- the source package, from the store
    job.way_out()
    given = {"index": store.url, "name": name, "version": version, "into": str(archive), "most": MOST_SOURCE,
             "result": str(here / "res" / "source.json"), "proxy": job.proxy, "cert": str(job.cert) if job.cert else ""}
    rc, output, timed_out = job.run([sys.executable, "-I", "-S", str(script), "source", json.dumps(given)], here,
                                    [here / "in", here / "res"], [str(script), stdlib])
    if rc is None and not timed_out:
        return None
    if timed_out:
        job.stop(f"the source package of {words} was not fetched after {FETCH_SECONDS // 60} minutes")
    said = _step_said(here / "res" / "source.json")
    state = said.get("state")
    if not sure and state in ("fetched", "no-library", "no-source"):
        there = said.get("ready")
        systems = _built_for([f for f in there[:_builder.MOST_READY] if isinstance(f, str)])[0] \
            if isinstance(there, list) else {"any"}
        if state != "fetched" or "any" in systems or _here() in systems:
            sandbox._rm(here)           # pip's word was about something else: nothing is built
            return False
    if state in ("no-library", "no-source"):
        return ""
    if state == "too-large":
        job.stop(f"the source package of {words} is larger than Lantern takes ({MOST_SOURCE >> 20} MB)")
    if state == "refused":
        job.stop(f"the source package of {words} lies at a place that is not the store, which the doorkeeper refused")
    if state == "unreachable":
        job.stop(f"the store ({store.host}) could not be reached for the source package of {words}")
    file = said.get("file")
    if rc != 0 or state != "fetched" or not isinstance(file, str) or not _builder.pick(
            f'<a href="{file}">', name, version) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!\-]{0,199}", file):
        job.stop(f"the source package of {words} could not be fetched (the last lines are in the log)")
    digest = _own_look(archive, MOST_SOURCE)
    if digest is None:
        job.stop(f"the source package of {words} could not be fetched (the last lines are in the log)")
    named = _named_prints(found, name, version)
    if named and digest not in named:
        job.stop(f"the source package the store handed out for {words} is not the one the project names (its "
                 "fingerprint differs) and was not built")
    if not named and said.get("page_sha256") != digest:
        job.stop(f"the source package the store handed out for {words} is not the file the store's own page names "
                 "(its fingerprint differs, or the page names none) and was not built")

    # -- behind the walls from here on
    wall = sandbox.read_wall(repo, here, "python", True, sys.executable)

    def step(which: str, cmd: list[str], writable: list[str], readable: list[str], first=(), more_env=None):
        result = here / "res" / f"{which}.json"
        try:
            if os.path.lexists(result):
                os.unlink(result)
        except OSError:
            job.stop(f"the build of {words} ended with an error (its last lines are in the log)")
        rc, output, timed_out = job.behind_walls(
            [*cmd, str(script), which, json.dumps({**given, "result": str(result)})], here, here / "tmp",
            [here / w for w in writable], readable, wall, first, more_env)
        if rc is None and not timed_out:
            return None
        if job.plan.left:
            # A build is a stranger's code, and something it started is still going. Whatever the step itself
            # ended with, nothing more of this run is started beside it: no further step, no second fetch without
            # the optional libraries, no test.
            job.stop(f"something the build of {words} started could not be ended", final=True)
        if timed_out:
            job.stop(f"the build of {words} was not through after {_time_words(BUILD_SECONDS)}")
        if sandbox._over_memory(rc, output):
            had = sandbox.memory_words(job.memory)
            job.stop(f"the build of {words} used more memory than the run has" + (f" ({had})" if had else ""))
        if rc != 0:
            job.stop(f"the build of {words} ended with an error (its last lines are in the log)")
        return _step_said(result)

    given = {"archive": str(archive), "into": str(here / "src")}
    if not sure:
        job.log(BUILDING.format(words=words, host=store.host))
    job.log(f"sandbox: build: unpacking {file}")
    said = step("unpack", [sys.executable, "-I", "-S"], ["src", "tmp", "res"], [str(script), stdlib])
    if said is None:
        return None
    if said.get("state") == "refused":
        job.stop(f"the source package of {words} {_STEP_WHY.get(said.get('why'), _STEP_WHY['broken'])}, so it was "
                 "not built")
    top, backend, path = said.get("top"), said.get("backend"), said.get("path")
    lines = _tool_lines(said.get("tools"))
    source = here / "src" / top if isinstance(top, str) and top not in ("", ".", "..") and len(top) <= 200 \
        and top.isprintable() and not any(c in top for c in "/\\") else None
    if said.get("state") != "unpacked" or source is None or not stat.S_ISDIR(os.lstat(source).st_mode if
                                                                             os.path.lexists(source) else 0):
        job.stop(f"the source package of {words} {_STEP_WHY['broken']}, so it was not built")
    if not isinstance(backend, str) or len(backend) > 300 or not _builder.BACKEND.fullmatch(backend) \
            or not isinstance(path, list) or len(path) > 20 or not all(
                isinstance(p, str) and p and len(p) <= 300 and not os.path.isabs(p) and ".." not in Path(p).parts for p in path):
        job.stop(f"the source package of {words} {_STEP_WHY['follow']}, so it was not built")
    tool_words = (f"the source package of {words} names a tool for its build that is not a library's name with "
                  "versions (a link, another store, a folder, an option), and Lantern fetches a tool by its name, "
                  "from the store")
    if lines is None:
        job.stop(tool_words)

    # -- its tools, and a Python of the build's own that finds them
    tools, held = here / "tools", []
    used: list[str] = []
    if lines:
        got = _fetch_tools(job, here, tools, lines, words, [], 1)
        if got is None:
            return None
        used, held = got
    own = sandbox._own_python(here, tools, tools, lambda line: None)
    if own is None:
        job.stop(f"a Python for the build of {words} could not be made")
    python, home, site = own
    readable = [str(script), stdlib, str(home / "pyvenv.cfg"), str(site / "lantern.pth"), str(tools)]

    def first() -> list[str]:
        return [os.path.dirname(python), *[str(tools / d) for d in ("bin", "Scripts") if (tools / d).is_dir()]]
    given = {"source": str(source), "backend": backend, "path": path, "out": str(here / "out")}

    # -- what else the build needs, asked of the build itself
    said = step("needs", [python, "-P"], ["src", "tmp", "res"], readable, first(), {"VIRTUAL_ENV": str(home)})
    if said is None:
        return None
    more = _tool_lines(said.get("tools")) if said.get("state") == "said" else None
    if more is None:
        job.stop(tool_words)
    if more:
        got = _fetch_tools(job, here, tools, more, words, held, 2)
        if got is None:
            return None
        used = sorted(set(used) | set(got[0]))
        sandbox._programs_run_by(tools, python)

    # -- the build
    if step("build", [python, "-P"], ["src", "tmp", "res", "out"], readable, first(), {"VIRTUAL_ENV": str(home)}) is None:
        return None
    left = []
    try:
        with os.scandir(here / "out") as entries:
            for entry in entries:
                left.append((entry.name, entry.is_file(follow_symlinks=False)))
                if len(left) > 1:
                    break
    except OSError:
        left = []
    if len(left) != 1 or not left[0][1]:
        job.stop(f"the build of {words} did not leave exactly one package (one plain file) where a build leaves it")
    package = left[0][0]
    m = _PACKAGE.fullmatch(package) if len(package) <= 200 else None
    if not m or _norm(m.group(1)) != _norm(name) or m.group(2).lower() != version.lower().replace("-", "_"):
        job.stop(f"the build of {words} left a package of another name or version than the one asked for")
    if os.path.lexists(kept / package):
        job.stop(f"the build of {words} left a package of another name or version than the one asked for")
    built = _own_look(here / "out" / package, MOST_PACKAGE, kept / package)
    if built is None:
        job.stop(f"the build of {words} did not leave exactly one package (one plain file) where a build leaves it")
    sandbox._rm(here)           # the source, the tools and the build's own Python: nothing of them is used again
    return {"file": package, "sha256": built, "from": file, "source_sha256": digest, "with": sorted(used),
            "checked": bool(named)}


def _build_what_pip_left(job: _Fetch, repo: Path, output: str, built: dict):
    """After a fetch pip did not get through: build the libraries it could not take that may be built (`_to_build`),
    into `built` (by name). True when at least one was built, so that pip is asked again with those beside the
    store's; False when there is nothing to build here (the caller then says why the fetch failed, as it always
    did); None when the run was stopped because it was asked to."""
    found = job.plan
    wanted = _to_build(output, found)
    again = [w for w in wanted if _norm(w[0]) in built]
    if again:
        name, version = again[0][:2]
        words = f"{_library_words(name)} {version}"
        missing = re.findall(r"No matching distribution found for ([^\s(<>=!~;\[]+)", output)
        if any(_norm(m) == _norm(name) for m in missing) or "inconsistent" in output or "has an invalid wheel" in output:
            job.stop(f"the package built for {words} was not taken as that by pip (it says another name or version "
                     "inside, or is not for this Python)")
        job.stop(_pip_failure(output, job.store, job.refused()) + f" ({words} was built from its source for this "
                 "run, and pip could still not take it beside the rest)")
    if not wanted or cannot_build(found.platforms):
        return False
    made = 0
    for name, version, sure in wanted:
        if len(built) >= MOST_BUILT:
            job.stop(f"more than {MOST_BUILT} of the project's libraries would have to be built from their source, "
                     "and Lantern builds no more than that for one run")
        words = f"{_library_words(name)} {version}"
        if sure:
            job.log(BUILDING.format(words=words, host=job.store.host))
        got = _build(job, repo, name, version, len(built) + 1, sure)
        if got is None:
            return None
        if got is False:
            continue
        if got == "":
            job.stop(f"{_library_words(name)} was not found in the store ({job.store.host}) as a ready-built package "
                     f"for this Python, and the store has no source package of version {version} to build it from")
        built[_norm(name)] = {**got, "name": name, "version": version}
        made += 1
        job.log(f"sandbox: built {words} from {got['from']} (sha256:{got['source_sha256'][:12]}…)"
                + (", with " + ", ".join(got["with"][:8]) if got["with"] else ""))
    return made > 0


def _for_pip(lines: list[str], built: dict) -> list[str]:
    """The lines pip is given once libraries were built: a fingerprint written beside a library that was built
    names its source, which Lantern compared itself (`_build`); pip is handed the built package's in its place."""
    out = []
    for line in lines:
        got = _requirement(line) if "--hash=" in line else None
        made = built.get(_norm(got[0])) if got else None
        out.append(f"{got[2]} --hash=sha256:{made['sha256']}" if made else line)
    return out


def _fetch_python(job: _Fetch, repo: Path, app: Path) -> Path:
    found, store = job.plan, job.store
    pip = importlib.util.find_spec("pip")
    if getattr(pip, "origin", None) is None:
        job.stop("the Python that runs Lantern has no pip to fetch them with")
    libs = job.root / "libs"
    libs.mkdir()
    wanted, report, keep = job.dir / "wanted.txt", job.dir / "fetched.json", job.dir / "versions.txt"
    readable = [os.path.dirname(pip.origin), os.path.dirname(os.__file__)]
    built: dict[str, dict] = {}         # the libraries built from their source in this fetch, by name (`_build`)
    while True:
        wanted.write_text("\n".join(_for_pip(found.lines, built)) + "\n", encoding="utf-8")
        more = []
        if found.constraints:
            keep.write_text("\n".join(_for_pip(found.constraints, built)) + "\n", encoding="utf-8")
            more += ["-c", str(keep)]
        if built:                       # the packages Lantern built, beside the store's
            more += ["--find-links", str(job.dir / "built")]
        for system in found.platforms:
            more += ["--platform", system]
        # `--no-warn-conflicts`: pip otherwise compares what it fetched with the libraries installed in the Python
        # it runs in (those beside Lantern, which the tests never run on) and writes each one that wants another
        # version as an "ERROR" of the project's fetch.
        job.hand_over(libs)
        job.way_out()
        rc, output, timed_out = job.run(_pip(job, libs, wanted, report, *more), job.dir, [job.dir, libs], readable)
        if rc is None and not timed_out:
            return None
        if timed_out:
            job.stop(f"the fetch was not through after {FETCH_SECONDS // 60} minutes")
        if rc == 0:
            break
        # a library pip found no ready-built file of may be one to build: then pip is asked again
        again = _build_what_pip_left(job, repo, output, built)
        if again is None:
            return None
        if not again:
            why, then = _not_built_for_here(output, found)
            job.stop(why or _pip_failure(output, store, job.refused()), then)
    rows = _reported(report)
    if rows is None:
        job.stop("pip did not say what it fetched")
    packages = []
    for row in rows:
        name, version, digest = row["name"], row["version"], row["digest"]
        made = built.get(_norm(name))
        if urlsplit(row["url"]).scheme == "file":
            if not made or digest != made["sha256"]:      # only what Lantern built lies on this computer
                job.stop("pip took a file from this computer that is not a package Lantern built")
            packages.append({"name": name, "version": version, "fingerprint": "sha256:" + digest, "file": made["file"],
                             "asked": row["asked"], "exact": True, "checked": made["checked"],
                             "built": {"from": made["from"], "source_fingerprint": "sha256:" + made["source_sha256"],
                                       "with": made["with"]}})
            continue
        named = found.locked.get(_norm(name), {}).get(version)
        if named and digest not in named:
            job.stop(f"the file the store handed out for {_library_words(name)} {version} is not one the project's "
                     "lock file names (its fingerprint differs)")
        packages.append({"name": name, "version": version, "fingerprint": "sha256:" + digest,
                         "file": _plain(urlsplit(row["url"]).path.rsplit("/", 1)[-1], 200),
                         "asked": row["asked"], "exact": _norm(name) in found.pinned,
                         # the fingerprint is one the project names: in its lock file, or beside its requirements
                         # (pip then takes no file whose fingerprint is not written there)
                         "checked": bool(named) or found.hashed})
    packages.sort(key=lambda p: _norm(p["name"]))
    found.record.update(state="fetched", store=store.host, packages=packages, added=found.added)
    made = [p for p in packages if "built" in p]
    found.record.pop("built", None)
    if made:
        found.record["built"] = len(made)
    for p in made:
        found.notes.append(f"{_library_words(p['name'])} {p['version']} is not in the store ready-built for this "
                           f"system and was built from its source ({p['built']['from']}) in the sandbox, with the "
                           "network off" + (f", with {', '.join(p['built']['with'][:8])}" if p["built"]["with"] else ""))
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
    from . import sandbox
    held = walls()
    job, where, refused = None, None, 0
    if found.language == "python" and found.optional:
        # First with the libraries the project names as optional, so that a test of any part of it can run. Where
        # they cannot be had beside the rest (one is nowhere, or is not ready-built for this system, or wants
        # another version of a library than the rest does), the fetch starts again without them, and the run says
        # which groups were left out and why: they are optional by the project's own word. What the project
        # always needs is never left out.
        lines, asked, pinned, words = list(found.lines), list(found.asked), set(found.pinned), _group_words(found.groups)
        found.lines = lines + [o["line"] for o in found.optional]
        found.asked = asked + [{"text": o["text"], "file": o["file"]} for o in found.optional]
        found.pinned = pinned | {o["name"] for o in found.optional if o["exact"]}
        job = _Fetch(found, root, log, cancel, memory)
        log(f"sandbox: fetching the libraries the project names from {job.store.host}, {wall_words(held)}; the ones "
            f"it names as optional (under {words}) too")
        try:
            where = _fetch_python(job, repo, app)
        except sandbox.NoLibraries as e:
            if getattr(e, "final", False):
                raise                       # something of that fetch is still going: nothing is started beside it
            why = getattr(e, "why", "") or "the fetch did not go through"
            log(f"sandbox: with the optional libraries the fetch did not go through ({why}); fetching again without them")
            found.lines, found.asked, found.pinned = lines, asked, pinned
            found.record["optional"] = _optional_record(found, False, why)
            found.notes.append(f"pyproject.toml: the libraries the project names as optional (under {words}) could "
                               f"not be had beside the rest ({why}) and were left out. {LEFT_OUT}")
            refused = job.refused()         # what the doorkeeper refused then is counted with the rest
            job.close()
            job.sandbox._rm(job.dir)        # the second fetch starts in folders of its own, as empty as the first
            job.sandbox._rm(root / "libs")
            job = None
        else:
            if where is not None:
                found.record["optional"] = _optional_record(found, True)
                found.notes.append(f"pyproject.toml: the libraries the project names as optional (under {words}) "
                                   "were fetched too, so that a test of any part of it can run")
        finally:
            found.record["asked"] = found.asked
            if job is not None:
                job.close()
                job.sandbox._rm(job.dir)
    if job is None:
        job = _Fetch(found, root, log, cancel, memory)
        log(f"sandbox: fetching the libraries the project names from {job.store.host}, {wall_words(held)}")
        try:
            where = _fetch_python(job, repo, app) if found.language == "python" else _fetch_node(job, repo, app, cwd_rel)
        finally:
            job.close()
            job.sandbox._rm(job.dir)    # what the fetching program left beside the libraries; the run's folder goes later
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
    found.record.update(exact=not loose, checked=checked, reached=reached, refused=refused + job.refused(), walls=held)
    if found.lock_name:
        found.record["locked"] = found.lock_name
    return where
