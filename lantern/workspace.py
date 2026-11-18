"""Several projects read as one map (roadmap of 2026-11-14, stage 6, part 1: `lantern workspace`).

A web app, a phone app and the API they call often live in repositories of their own, and the map of one of them
ends where a request leaves it: the page's `fetch("/api/notes")` is a call to somewhere the map does not know. A
**workspace** puts the projects side by side, each in a folder under its own name, and checks that folder like any
other project. The bridge then links a page of one project to the route of another by exactly the rule it uses inside
one repository (method and path, `bridge.py`), every link keeps the `via` that says how it was made, and what a
finding is reached from crosses the line between the projects as it crosses the line between a project's own page and
server.

Where it lives: `LANTERN_HOME/workspaces/<name>/` holds a copy of each member (`<name>/<member>/…`), and the record
beside it, `LANTERN_HOME/workspaces/<name>.json`, says what each member is, where it came from and which commit it was
at. The record is never inside the folder that is checked, and only the person's own command (`lantern workspace`)
writes one: a list of members a project brings is never read (`record_for` reads a record by where it is, the way
`remote.is_clone` knows a clone of Lantern's own).

What a copy brings in (`_copy`): the member's plain files and folders, byte for byte; a link only where it stays inside
the member (`programs.link_inside`); never the folders of git and of other version control, Lantern's own results
(`.lantern`, which may have come with the project), installed libraries and the caches of tools (`NOT_COPIED`); never a
pipe, a device or anything else that is no file. What was left out is counted per member (`left_out`). A repository
link is cloned first, by `remote.clone` and its rules.

What the map does not make up (`guard`, after the bridge):

* **A name two projects share** (two projects made from one template write the same Java package and class; two Rails
  apps each have a `UsersController`) is read by Lantern as one name, so the map holds one node for code of two
  projects and their calls mix. Which names are shared is found when the workspace is made, by reading each member
  alone under its own folder name (`_shared`); every link that touches such a name is only `possible`, and the names
  are listed with the members that write them.
* **Code of one project that names code of another** (`from textutil import clean`, where only another member has a
  `textutil.py`) is linked by the readers as inside one repository. Whether the project installs that member is not
  read, so such a link is only `possible`, and it is listed (`across.code`).
* **A request answered across projects** keeps the bridge's own confidence and `via`, and is listed (`across.rows`).

A workspace reads as one repository that holds the projects in folders, and Lantern reads it the way it reads such a
repository: what is checked of a member is what would be checked of that folder there. A member's name is the folder
name of its copy, so it is part of every path on the map (`api/main.py`). It is made of lowercase letters, digits and
dashes, and it is never a name Lantern's own folder rules give a meaning (`RESERVED`, `RESERVED_STARTS`: a folder of
tests or examples, one every reader leaves out, a web root, a folder of templates; `_made_name` puts `-project` after
such a name), which would change how the member's files are read. Where a reader's rule is about where a project
begins (the address of a PHP page below its web root), the reader asks `below` and reckons from the member's folder.

Not in this change: contracts the projects share (OpenAPI files, `.proto` files, a tRPC router imported as a package)
are not read as links; a member's accepted risks (`lantern-accepted.json`) are not read in the workspace, so its
accepted findings show open there.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import stat
from pathlib import Path

from . import programs, removal, results
from .graph import CONFIDENCE_RANK, POSSIBLE, outside

KIND = "lantern-workspace"
SCHEMA = 1
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
MOST_MEMBERS = 12
MOST_ROWS = 200          # links across members a map keeps; the rest are counted (`more`)
MOST_SHARED = 500        # shared names a record keeps
MOST_EXAMPLES = 20
MOST_FILES = 200_000
MOST_FILE = 256 << 20
# Folder names a reader or a rule of Lantern's own gives a meaning: a member under such a name would be read
# differently (all of its files as test code or as an example, left out by every reader, its pages under another
# address, its headers published for every project). A member is never given one. The list is what Lantern's own folder
# rules and lists of folder names say, found from them by `tests/test_workspace.py` (a new rule fails that test until
# its names are here or it is said why they need not be), and the samples' trial agrees (27 of 66 names change what is
# read, all here). Names whose rules decide only where a file is drawn, a route's address or a protection card are not.
RESERVED = frozenset({
    "app", "assets", "bench", "benchmark", "benchmarks", "bin", "bootstrap", "build", "cache", "ci", "classes",
    "cli", "config", "coverage", "cypress", "database", "db", "demo", "demos", "deps", "detox", "dist", "doc",
    "docs", "e2e", "env", "example", "examples", "extern", "external", "fastlane", "fixture", "fixtures",
    "generated", "htdocs", "httplib", "i18n", "inc", "include", "includes", "jinja2", "lang", "langs",
    "languages", "lib", "locale", "locales", "log", "maestro", "messages", "migrations", "mock", "mocks",
    "nlohmann", "obj", "out", "packages", "pages", "partials", "playwright", "public", "resources", "routes",
    "sample", "samples", "script", "scripts", "site-packages", "spec", "src", "static", "storage", "stories",
    "subprojects", "target", "template", "templates", "test", "tests", "third-party", "thirdparty", "tmp",
    "tools", "translation", "translations", "unittest", "unittests", "vendor", "vendored", "venv", "view",
    "views", "wp-admin", "wp-includes", "www",
})
# Beginnings of folder names a reader leaves out (a C/C++ build's own folders: `cmake-build-debug`, `bazel-out`)
RESERVED_STARTS = ("bazel-", "cmake-build-")
# Folders that are never copied: version control, Lantern's results (they may have come with the project), installed
# libraries, tools' caches. Every reader leaves them out as well (`python_frontend.SKIP_DIRS`).
NOT_COPIED = frozenset({
    ".git", ".hg", ".svn", ".lantern", "node_modules", "bower_components", "__pycache__", ".venv", "venv", ".tox",
    ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".eggs", ".next", ".nuxt", ".svelte-kit",
    ".turbo", ".vercel", ".expo", ".parcel-cache", ".angular",
})
# The file at the top of every folder Lantern made for a workspace: a folder without it is never replaced or removed
MARK = ".lantern-workspace"
# The Evidence Report's line for a workspace (its folder holds no commit of its own): checked again where it is kept
VERIFY_LINE = "lantern verify ~/.lantern/workspaces/{name} --report evidence.html"
LEFT_OUT = {"folder": "a folder of version control, results, installed libraries or a tool's cache",
            "link-out": "a link that leads out of the project", "kind": "neither a file, a folder nor a link",
            "large": "larger than 256 MB", "name": "a name this computer cannot write",
            "unreadable": "a file or folder this user may not read"}


class Refused(ValueError):
    """A workspace that is not made or checked. The text is a sentence for the person."""


def home() -> Path:
    return removal.home() / "workspaces"


def folder_of(name: str) -> Path:
    return home() / name


def _record_path(name: str) -> Path:
    return home() / f"{name}.json"


# ------------------------------------------------------------------------------------------------------- names


def _usable(name: str) -> bool:
    return bool(NAME.fullmatch(name or "")) and name not in RESERVED and not name.startswith(RESERVED_STARTS)


def _made_name(text: str) -> str:
    """A member's name made from a folder's or a repository's name: lowercase, every other run of characters a dash;
    a name a reader gives a meaning of its own gets `-project` after it (`docs-project`), and one that begins as such
    a name does gets `project-` in front as well (`project-cmake-build-debug-project`)."""
    name = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:40].strip("-") or "project"
    if not _usable(name):
        name = (name[:31].strip("-") or "project") + "-project"
    if not _usable(name):
        name = "project-" + name[:32].strip("-")
    return name


def _own_name(given: str | None, source: str) -> str:
    """A member's name: the one the person gave, else one made from the repository's or the folder's own name
    (`ValueError` for a link that is none)."""
    from . import remote
    if given is not None:
        return given
    if remote.looks_like_url(source):
        return _made_name(remote.parse(source)["name"])
    return _made_name(Path(source).expanduser().resolve().name)


def _distinct(names: list[str]) -> list[str]:
    """The names in order, a second `api` as `api-2`, a third as `api-3`."""
    out, taken = [], set()
    for first in names:
        name, n = first, 2
        while name in taken:
            name = f"{first[:37]}-{n}"
            n += 1
        taken.add(name)
        out.append(name)
    return out


def _spec(text: str) -> tuple[str | None, str]:
    """`NAME=FOLDER` or `NAME=LINK` names the member; a path or a link alone does not. The part before the first `=`
    is a name only where it holds no path separator, no drive and no address."""
    left, eq, right = (text or "").partition("=")
    if eq and left and not any(c in left for c in "/\\:") and right:
        return left, right
    return None, text


# --------------------------------------------------------------------------------------------------- the record


def _well_formed(rec, name: str) -> bool:
    if not isinstance(rec, dict) or rec.get("kind") != KIND or rec.get("schema") != SCHEMA or rec.get("name") != name:
        return False
    members = rec.get("members")
    if not isinstance(members, list) or not 2 <= len(members) <= MOST_MEMBERS:
        return False
    names = [m.get("name") for m in members if isinstance(m, dict)]
    if len(names) != len(members) or len(set(names)) != len(names) or not all(_usable(n) for n in names):
        return False
    shared = rec.get("shared_in", {})
    return isinstance(rec.get("shared", []), list) and isinstance(shared, dict)


def record_for(repo) -> dict | None:
    """The record of the workspace whose folder `repo` is, or None: only a folder directly under `home()` with the
    record Lantern wrote beside it, as a plain file (never a link) that reads back whole. Nothing inside a project,
    and no folder anywhere else, is ever taken for a workspace."""
    try:
        folder = Path(repo).resolve()
        base = home().resolve()
    except (OSError, RuntimeError):
        return None
    if folder.parent != base or not NAME.fullmatch(folder.name):
        return None
    text, _why = results.plain(base / f"{folder.name}.json")
    if text is None:
        return None
    try:
        rec = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return rec if _well_formed(rec, folder.name) else None


def listed() -> list[dict]:
    out = []
    try:
        names = sorted(p.name[:-5] for p in home().iterdir() if p.name.endswith(".json"))
    except OSError:
        return []
    for name in names:
        if NAME.fullmatch(name):
            rec = record_for(home() / name)
            if rec is not None:
                out.append(rec)
    return out


def _ours(folder: Path) -> bool:
    """Whether `folder` is one Lantern made for a workspace: a folder, not a link, with Lantern's mark at its top."""
    try:
        return stat.S_ISDIR(os.lstat(folder).st_mode) and stat.S_ISREG(os.lstat(folder / MARK).st_mode)
    except OSError:
        return False


def _may_replace(name: str) -> None:
    """`Refused` unless what is kept under the workspace's name is Lantern's own or nothing: a folder the person keeps
    there, or a file of the record's name Lantern did not write, is never replaced."""
    folder, rec = folder_of(name), _record_path(name)
    if os.path.lexists(folder) and not _ours(folder):
        raise Refused(f"{folder} is not a workspace Lantern made, so it is left as it is: give the workspace another "
                      "name (--name), or move that folder away.")
    if os.path.lexists(rec) and record_for(folder) is None:
        raise Refused(f"{rec} is not a workspace's record Lantern wrote, so it is left as it is: give the workspace "
                      "another name (--name).")


def remove(name: str) -> None:
    """Remove a workspace: its copies and its record. `Refused` when there is none of that name, or when the folder
    of that name is not one Lantern made (it is then left as it is)."""
    if not NAME.fullmatch(name or "") or record_for(folder_of(name)) is None:
        raise Refused(f"There is no workspace called {name!r}: `lantern workspace --list` names them.")
    if os.path.lexists(folder_of(name)) and not _ours(folder_of(name)):
        raise Refused(f"{folder_of(name)} is not a workspace Lantern made, so it is left as it is (and its record "
                      "with it).")
    for place in (folder_of(name), _record_path(name)):
        why = removal.remove(place)
        if why:
            raise Refused(f"{place} could not be removed: {why}.")


# ------------------------------------------------------------------------------------------------------ copying


def _read(path: str) -> bytes | None:
    """A regular file's bytes, opened without following a link and taken only when it is still a plain file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        try:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            data = f.read(MOST_FILE + 1)
        except OSError:
            return None
    return data if len(data) <= MOST_FILE else None


def _linkish(st: os.stat_result) -> bool:
    """A link, or on Windows a junction or another reparse point, which leads elsewhere like a link."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


class _Budget:
    def __init__(self):
        from . import remote
        self.mb, self.bytes, self.files = remote.max_mb(), 0, 0

    def take(self, size: int, member: str) -> None:
        self.bytes += size
        self.files += 1
        if self.mb and self.bytes > self.mb * 1_000_000:
            raise Refused(f"The projects of this workspace hold more than Lantern's {self.mb} MB limit "
                          f"(LANTERN_CLONE_MAX_MB) by the time {member} is copied.")
        if self.files > MOST_FILES:
            raise Refused(f"The projects of this workspace hold more than {MOST_FILES:,} files.")


def _copy(src: Path, dst: Path, member: str, budget: _Budget) -> dict:
    """The member's files written into `dst`, folder by folder in name order: plain files byte for byte, a link only
    where it stays inside the member, nothing else. Returns `{files, links, bytes, left_out: {why: count}}`."""
    files = links = size = 0
    left: dict[str, int] = {}

    def skip(why: str) -> None:
        left[why] = left.get(why, 0) + 1

    todo: list[tuple[str, ...]] = [()]
    while todo:
        parts = todo.pop()
        try:
            with os.scandir(src.joinpath(*parts)) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            skip("unreadable")
            continue
        for e in entries:
            p = [*parts, e.name]
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                skip("unreadable")
                continue
            if _linkish(st):
                try:
                    target = os.readlink(e.path)
                except (OSError, ValueError):
                    skip("link-out")
                    continue
                if not programs.link_inside(p, target):
                    skip("link-out")
                    continue
                try:
                    programs.put_link(dst, p, target)
                    links += 1
                except (ValueError, OSError):
                    skip("link-out")
            elif stat.S_ISDIR(st.st_mode):
                if e.name in NOT_COPIED or (e.name == "env" and _environment(Path(e.path))):
                    skip("folder")
                else:
                    todo.append(tuple(p))
            elif stat.S_ISREG(st.st_mode):
                if st.st_size > MOST_FILE:
                    skip("large")
                    continue
                budget.take(st.st_size, member)
                data = _read(e.path)
                if data is None:
                    skip("unreadable")
                    continue
                try:
                    programs.put_copy(dst, p, data)
                except ValueError:
                    skip("name")
                    continue
                files, size = files + 1, size + len(data)
            else:
                skip("kind")
    return {"files": files, "links": links, "bytes": size, "left_out": dict(sorted(left.items()))}


def _environment(folder: Path) -> bool:
    from .python_frontend import is_environment
    return is_environment(folder)


# ------------------------------------------------------------------------------------------------ making one


def plan(members, name=None) -> str:
    """The name a workspace of `members` gets, and `Refused` for what `make` refuses before it copies or fetches
    anything: not a list of two to `MOST_MEMBERS` texts, a member's name that cannot be one, a link that is none, a
    folder that is not there, a workspace's name that cannot be one, or a folder or record under that name that Lantern
    did not make (`_may_replace`). The app asks it before it lists the workspace."""
    from . import remote
    if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
        raise Refused("A workspace is a list of folders or repository links.")
    if len(members) < 2:
        raise Refused("A workspace is two projects or more: name each folder or repository link after "
                      "`lantern workspace`.")
    if len(members) > MOST_MEMBERS:
        raise Refused(f"A workspace holds at most {MOST_MEMBERS} projects.")
    if name is not None and not (isinstance(name, str) and NAME.fullmatch(name)):
        raise Refused(f"{name!r} cannot be a workspace's name: use up to 40 lowercase letters, digits and dashes.")
    names = []
    for text in members:
        given, source = _spec(text)
        if given is not None and not _usable(given):
            raise Refused(f"{given!r} cannot be a project's name in a workspace: use lowercase letters, digits and "
                          "dashes, not a name Lantern gives a meaning of its own (tests, build, vendor, src, …).")
        if not remote.looks_like_url(source) and not Path(source).expanduser().is_dir():
            raise Refused(f"{source} is not a folder.")
        try:
            names.append(_own_name(given, source))
        except ValueError as e:
            raise Refused(f"{source} could not be fetched: {e}") from None
    name = name or _made_name("-".join(_distinct(names)))
    _may_replace(name)
    return name


def _sources(members: list[str], log) -> list[dict]:
    """Each member as `{name, from, source, folder}`; a link cloned first. `Refused` for anything that is not two
    to `MOST_MEMBERS` distinct folders or links, none inside another or holding the workspaces (`plan` has checked
    the rest)."""
    from . import gitfacts, remote
    base = home().resolve()
    out = []
    for text in members:
        given, source = _spec(text)
        if remote.looks_like_url(source):
            try:
                folder = Path(remote.clone(source, log=log)).resolve()
                made = _made_name(remote.parse(source)["name"])
            except (ValueError, RuntimeError) as e:
                raise Refused(f"{source} could not be fetched: {e}") from None
            kind = "link"
        else:
            folder = Path(source).expanduser()
            if not folder.is_dir():
                raise Refused(f"{source} is not a folder.")
            folder, made, kind = folder.resolve(), _made_name(folder.resolve().name), "folder"
            source = str(folder)
        if folder.is_relative_to(base):
            raise Refused(f"{source} is a workspace's own folder; name the projects it was made of instead.")
        if base.is_relative_to(folder):
            raise Refused(f"{source} holds the folder where Lantern keeps its workspaces ({base}), so it would be "
                          "copied into itself.")
        for m in out:
            if m["folder"] == folder:
                raise Refused(f"{source} is named twice.")
            if folder.is_relative_to(m["folder"]) or m["folder"].is_relative_to(folder):
                raise Refused(f"{source} and {m['source']} lie one inside the other; name each project once.")
        info = gitfacts.info(folder)
        known = bool(info.get("commit"))
        out.append({"name": given or made, "from": kind, "source": source, "folder": folder,
                    "commit": info.get("commit"), "dirty": bool(info.get("dirty")) if known else None,
                    "branch": info.get("branch") if known else None, "remote": info.get("remote") if known else None,
                    # its own accepted risks are not read in the workspace: the Limits say so where there are some
                    "accepted": os.path.isfile(folder / "lantern-accepted.json")
                    and not os.path.islink(folder / "lantern-accepted.json")})
    for m, distinct in zip(out, _distinct([m["name"] for m in out])):
        m["name"] = distinct
    return out


def _shared(new: Path, names: list[str]) -> dict[str, list[str]]:
    """The names on the map that more than one member writes: each member read alone, in a folder that holds only
    its copy under the same name (moved there and back), so every name is the name it has on the workspace's map."""
    from .engine import build_graph
    solo = new.with_name(new.name + ".solo")
    solo.mkdir()
    seen: dict[str, list[str]] = {}
    try:
        for name in names:
            os.rename(new / name, solo / name)
            try:
                g = build_graph(solo)
            finally:
                os.rename(solo / name, new / name)
            for nid in g.nodes:
                if not outside(nid):
                    seen.setdefault(nid, []).append(name)
    finally:
        removal.remove(solo)
    return {nid: ms for nid, ms in sorted(seen.items()) if len(ms) > 1}


def make(members: list[str], name: str | None = None, log=None) -> dict:
    """Make the workspace `name` of `members` (folders, repository links, `NAME=FOLDER`, `NAME=LINK`), or make it
    again: every member is copied anew, the names they share are found, and the record is written. Returns it."""
    log = log or (lambda line: None)
    name = plan(list(members), name)
    srcs = _sources(list(members), log)
    base = home()
    base.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(6)
    new = base / f".{name}.{token}.new"
    new.mkdir()
    budget = _Budget()
    try:
        for m in srcs:
            log(f"copying {m['name']} from {m['source']}")
            m.update(_copy(m["folder"], new / m["name"], m["name"], budget))
            (new / m["name"]).mkdir(exist_ok=True)     # a member with no file still has its folder
        shared = _shared(new, [m["name"] for m in srcs])
        (new / MARK).write_text(f"Lantern made this folder for the workspace {name}: `lantern workspace --remove "
                                f"{name}` removes it.\n", encoding="utf-8")
        _may_replace(name)                             # as before the copies were made
    except BaseException:
        removal.remove(new)
        raise
    dest = folder_of(name)
    old = None
    if os.path.lexists(dest):
        old = base / f".{name}.{token}.old"
        os.rename(dest, old)
    os.rename(new, dest)
    if old is not None:
        # the results of the checks made before (`.lantern`: the first check's record, what was fixed since) stay
        # with the workspace; the copies they were made of go
        was = old / ".lantern"
        if was.is_dir() and not was.is_symlink():
            try:
                os.rename(was, dest / ".lantern")
            except OSError:
                pass
        removal.remove(old)
    from . import __version__
    rec = {"kind": KIND, "schema": SCHEMA, "name": name, "lantern": __version__,
           "made": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "members": [{k: (str(v) if isinstance(v, Path) else v) for k, v in m.items() if k != "folder"}
                       for m in srcs],
           "shared": list(shared)[:MOST_SHARED], "shared_count": len(shared),
           "shared_in": {k: shared[k] for k in list(shared)[:MOST_SHARED]}}
    results.write(_record_path(name), json.dumps(rec, indent=1))
    return rec


def again(name: str, log=None) -> dict:
    """Make the workspace `name` again from where its record says its members came from."""
    rec = record_for(folder_of(name)) if NAME.fullmatch(name or "") else None
    if rec is None:
        raise Refused(f"There is no workspace called {name!r}: `lantern workspace --list` names them.")
    return make([f"{m['name']}={m['source']}" for m in rec["members"]], name=name, log=log)


# -------------------------------------------------------------------------------------------- on the map itself


def _shown_source(m: dict) -> str:
    """Where a member came from, as the map and the Evidence Report say it: a repository link as it was given, a
    folder by its own name only. Its whole place on this computer stays in the record, for `again`."""
    src = str(m.get("source") or "")
    return src if m.get("from") == "link" else Path(src).name


def describe(rec: dict) -> dict:
    """What the map says of its workspace (`g.meta["workspace"]`, before the guard adds what crosses)."""
    keep = ("name", "from", "commit", "dirty", "branch", "remote", "files", "links", "left_out", "accepted")
    return {"name": rec["name"], "made": rec.get("made"),
            "members": [{k: m.get(k) for k in keep} | {"source": _shown_source(m)} for m in rec["members"]]}


def below(meta, rel: str) -> tuple[str, str]:
    """`(member, path below it)` for a file of a workspace's map, `("", rel)` for a project of its own or a file of
    no member. For a reader whose rule is about the project's own top: where a page of a project answers is reckoned
    from the project's folder, as it is when the project is read alone."""
    top, sep, rest = (rel or "").partition("/")
    if sep and top in {m.get("name") for m in _members(meta)}:
        return top, rest
    return "", rel


def _members(meta) -> list[dict]:
    ws = meta.get("workspace") if isinstance(meta, dict) else None
    members = ws.get("members") if isinstance(ws, dict) else None
    return [m for m in members if isinstance(m, dict)] if isinstance(members, list) else []


def payload(meta) -> dict:
    """The workspace's share of the Evidence Report's digest: each member with the commit it was copied at (and
    `+changes` where its files differed from that commit), and how many names two members write. Nothing for a
    project of its own, so its digest is what it was."""
    ws = meta.get("workspace") if isinstance(meta, dict) else None
    if not isinstance(ws, dict):
        return {}
    shared = ws.get("shared") if isinstance(ws.get("shared"), dict) else {}
    return {"workspace": {
        "members": [f"{m.get('name')}:{m.get('commit') or ''}{'+changes' if m.get('dirty') else ''}"
                    for m in _members(meta)],
        "shared": int(shared.get("names") or 0)}}


def shown(meta) -> dict | None:
    """What the Evidence Report's provenance says of a workspace: its name and each member, where it came from and
    the commit it was copied at. None for a project of its own."""
    ws = meta.get("workspace") if isinstance(meta, dict) else None
    if not isinstance(ws, dict):
        return None
    keep = ("name", "from", "source", "commit", "dirty", "branch", "remote")
    return {"name": ws.get("name"), "made": ws.get("made"),
            "members": [{k: m.get(k) for k in keep} for m in _members(meta)]}


def limits(meta) -> list[str]:
    """The Evidence Report's Limits lines for a workspace; none for a project of its own."""
    ws = meta.get("workspace") if isinstance(meta, dict) else None
    if not isinstance(ws, dict):
        return []
    members = _members(meta)
    names = lambda ms: ", ".join(str(m.get("name")) for m in ms)     # noqa: E731
    out = [f"This map is a workspace of {len(members)} projects ({names(members)}), copied side by side by Lantern"
           + (f" at {ws['made']}" if isinstance(ws.get("made"), str) else "") + ". Each was read from its copy; links "
           "that lead out of a project, version control, installed libraries and tools' caches were not copied. "
           "Contracts the projects share (OpenAPI files, .proto files, a tRPC router used as a package) are not read "
           "as links yet: only requests one project makes and another answers are."]
    none = [m for m in members if not m.get("commit")]
    if none:
        out.append(f"{names(none)}: in no git repository Lantern reads, so no commit is named for "
                   f"{'it' if len(none) == 1 else 'them'}.")
    dirty = [m for m in members if m.get("dirty")]
    if dirty:
        out.append(f"{names(dirty)}: files differed from the commit named when the copy was made, so the commit is "
                   "not the whole of what was read.")
    across = ws.get("across") if isinstance(ws.get("across"), dict) else {}
    if across.get("code"):
        out.append(f"{across['code']} link(s) of code from one project into another are marked possible: whether a "
                   "project installs the other one is not read.")
    shared = ws.get("shared") if isinstance(ws.get("shared"), dict) else {}
    if shared.get("names"):
        out.append(f"{shared['names']} name(s) are written in more than one project (two projects made from one "
                   "template, for example). Lantern reads such a name as one, so every link that touches it is "
                   "marked possible.")
    accepted = [m for m in members if m.get("accepted")]
    if accepted:
        out.append(f"{names(accepted)}: the risks accepted in the project's own lantern-accepted.json are not read "
                   "in a workspace, so those findings show as open here.")
    return out


def _member(g, nid: str, names: set[str]) -> str | None:
    n = g.nodes.get(nid)
    top = (n.file or "").split("/", 1)[0] if n is not None and n.file else None
    return top if top in names else None


def guard(g, rec: dict) -> None:
    """After the bridge: what crosses from one member to another is listed, a link of code across members and every
    link that touches a name two members write is only `possible`, and the call-site inventory says the same."""
    names = {m["name"] for m in rec["members"]}
    shared = set(rec.get("shared") or [])
    weak = CONFIDENCE_RANK[POSSIBLE]
    rows, requests, code, lowered = [], 0, 0, set()
    for e in g.edges:
        if outside(e.dst):
            continue
        a, b = _member(g, e.src, names), _member(g, e.dst, names)
        request = (e.via or "").startswith("http-")
        if (e.src in shared or e.dst in shared or (a and b and a != b and not request)) \
                and CONFIDENCE_RANK.get(e.confidence, weak) < weak:
            e.confidence = POSSIBLE
            lowered.add((e.src, e.dst))
        if not (a and b and a != b):
            continue
        row = {"from": a, "to": b, "kind": "request" if request else "code", "via": e.via,
               "confidence": e.confidence, "src": e.src, "dst": e.dst}
        if request:
            requests += 1
            entry = g.nodes[e.dst].entry or {}
            row |= {"call": e.detail, "route": entry.get("detail")}
        else:
            code += 1
        rows.append(row)
    rows.sort(key=lambda r: (r["kind"] != "request", r["from"], r["to"], r["src"], r["dst"]))
    for s in g.sites:
        if s.get("outcome") not in ("resolved", "likely"):
            continue
        caller = _member(g, s.get("caller") or "", names)
        for t in s.get("to") or []:
            if outside(t):
                continue
            if (s.get("caller"), t) in lowered or t in shared or (caller and _member(g, t, names) not in (None, caller)):
                s["outcome"], s["confidence"] = "possible", POSSIBLE
                break
    shared_in = rec.get("shared_in") or {}
    examples = [f"{nid.split(':', 1)[1]} ({', '.join(shared_in.get(nid) or [])})"
                for nid in sorted(shared)[:MOST_EXAMPLES]]
    g.meta.setdefault("workspace", describe(rec))
    g.meta["workspace"]["across"] = {"requests": requests, "code": code, "rows": rows[:MOST_ROWS],
                                     "more": max(0, len(rows) - MOST_ROWS)}
    g.meta["workspace"]["shared"] = {"names": int(rec.get("shared_count") or len(shared)), "examples": examples}


def summary(ws: dict) -> str:
    """One line for the log: what crosses between the projects of a workspace."""
    across, shared = ws.get("across") or {}, ws.get("shared") or {}
    r, c, s = across.get("requests", 0), across.get("code", 0), shared.get("names", 0)
    return (f"{r} request{'s' if r != 1 else ''} from one project answered by another; "
            f"{c} link{'s' if c != 1 else ''} of code across projects (possible); "
            f"{s} name{'s' if s != 1 else ''} written in more than one project (links to them possible)")
