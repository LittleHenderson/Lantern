"""The test machine's program (a firm pass or fail, stage 3, step 4; the design "Website test runs").

The website runs a project's tests on a machine of their own: one machine for one check, made for it and thrown away
after it, holding no key and no secret and nothing of anybody else's. On that machine this program is the first and
only program. It takes the project and the libraries the website fetched for it as one archive, runs the tests in
Lantern's sandbox as an ordinary user, and holds the result until the website takes it.

    python -I -m lantern.runner serve [--host H] [--port P] [--ready FILE] [--work DIR]   # the machine's program
    python -m lantern.runner run ARCHIVE --out FILE                                       # one check, no door
    python -m lantern.runner pack PROJECT OUT [--minutes N] [--memory MB] [--cwd DIR]
                                  [--libraries DIR --record FILE [--fetched-with PYTHON]] -- COMMAND...

**The door** (`Door`): one address, and nothing answers there but to the key made for this one check. The machine
is handed the key's SHA-256 fingerprint, never the key, in `LANTERN_RUNNER_KEY_SHA256` (`KEY_VARIABLE`), which the
program takes out of its own surroundings when it starts. A request is let in only with the header
`Authorization: Bearer <key>` written exactly so (`Runner.allowed`: the key's characters only, compared by its
fingerprint in constant time); without it every address answers 401 and nothing else, so a stranger learns nothing
of what is there. With it: `PUT /v1/check` takes the archive once (its length said, or sent in chunks; at most
`most` bytes, and only what the disk has room for; a sender that stops is cut off and may send again),
`GET /v1/check?from=N` says how it is going (state, steps with their times, the log's lines from N, the result),
`POST /v1/stop` stops the tests with everything they started, `POST /v1/end` ends the program. No answer is kept by
anyone in between (`Cache-Control: no-store`), and every answer closes its connection.

**The archive** (`take`): `check.json` (the check's settings, taken by shape: `settings`), `project/` and, when the
website fetched the project's libraries, `libraries/` as the fetch laid them out, and nothing else. It is unpacked
with the website's own rules (`lantern.archive`: no name that leaves its folder, sizes counted while written), and
three of its own: nothing is unwrapped, a file's run bit is kept and no other, and a link is made only where npm
makes one (`links_npm_makes`). What does not fit on the machine's disk is refused before it is unpacked.

**The walls** (`walls`): the tests run only where every wall the design counts on stands on this machine: a network
of the tests' own (which holds nothing but its own address, so the tests cannot even reach the door), the doorman
that makes every connection of their programs, the watch on the memory they use together, and an ordinary user for
them (the program is root for that switch alone). Where one does not stand, no test is run and the result says
which and why (`state: "unable"`).

**The check** (`check`): the tests run with `sandbox.run(..., given=...)`, on exactly the libraries the website
fetched (`libraries.given`) and on no others; nothing is fetched on the machine. The result says what ran where
(`runner`: Lantern's version and commit, Python, the system, the walls and what the run keeps the tests from), what
was taken (`taken`), the check's settings (`check`) and how the tests went (`tests`: the sandbox's result, the files
of the calls they made named from the project's top). `state`: `done` (the tests ran; whether they passed is in
`tests`), `refused` (the archive is not a check this machine takes), `unable` (a wall does not stand, or the sandbox
could not be set up) or `stopped` (the website asked for it), with `why_not` in Lantern's own words.

**The clock** (`Runner`): the program leaves by itself when no archive came in `wait_for_archive` seconds
("no archive came"), when the result waited `wait_for_taker` seconds for the website ("nobody took the result"),
when the website took it and did not end the machine in as long again, and when it ran longer than any check may
(`longest`). Nothing of the check is written outside the program's own folder, and that folder is removed at the
end; the machine itself is removed by the website.

Standard library and Lantern only: the machine's image holds nothing else (cloud/runner/Dockerfile)."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import socketserver
import stat
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path, PurePosixPath

from . import __version__, archive, libraries, removal, results, sandbox

KEY_VARIABLE = "LANTERN_RUNNER_KEY_SHA256"   # the key's fingerprint, the one thing the machine is handed
MOST_KEY = 512                     # characters of a key
_KEY = re.compile(r"[A-Za-z0-9_-]+")
_DIGEST = re.compile(r"[0-9a-f]{64}")

MOST_SETTINGS = 4 << 20            # bytes of check.json
MOST_WORDS = 64                    # words of the test command
MOST_WORD = 1000                   # characters of one word
MOST_CWD = 200                     # characters of the folder the tests run in
MOST_PYTHON = 120                  # characters of the Python that fetched the libraries
MOST_PACKAGES = 100_000
LANGUAGES = ("python", "node")     # what the machine's image holds: Python, and Node with its npm
MOST_ARCHIVE = 8 << 30             # bytes an archive may have (the machine's disk is the true limit: `room`)
MOST_UNPACKED = 32 << 30           # bytes of the files once unpacked
MOST_ENTRIES = 400_000             # entries of an archive: a project's libraries for JavaScript are many small files
ROOM = 64 << 20                    # bytes of the disk kept free for the program and the sandbox's own files
MIN_RATE = 1 << 20                 # bytes a second an archive must come at least, taken over its whole length
MIN_SECONDS = 120                  # the least time a sender gets for a whole archive
READ_TIMEOUT = 60.0                # seconds a read may wait for the next bytes
MOST_AT_ONCE = 16                  # connections served at the same time
MOST_LINE = 2000                   # characters of one line of the log
KEEP_LINES = 20_000                # lines of the log kept for the website (the older are dropped and counted)
MOST_PER_ASK = 5000                # lines handed over in one answer
MOST_CHUNK_LINE = 64               # bytes of a chunk's size line
MOST_TRAILERS = 32
CHUNK = 1 << 16
WAIT_FOR_ARCHIVE = 600.0           # seconds the program waits for the archive
WAIT_FOR_TAKER = 600.0             # seconds a result waits for the website, and the website then has to end it
LONGEST = (sandbox.MINUTES[1] + 30) * 60.0   # seconds the program lives at most: the longest tests, and room

WEBSITE_ENDED = "the website ended it"
END_STATES = ("done", "refused", "unable", "stopped")
STOPPED = "the website asked for the tests to be stopped"
DATE = (1980, 1, 1, 0, 0, 0)       # every entry of an archive this program packs (the same files, the same archive)


class Refused(archive.Refused):
    """A plain sentence: why the check was not taken. Nothing of it was run."""


# ---------------------------------------------------------------------------- the check's settings, by shape
_KEYS = {"version", "command", "minutes", "memory", "libraries", "cwd", "fetched_with"}
_NEEDED = ("version", "command", "minutes", "memory", "libraries")
_PYTHON_PATH = re.compile(r"/[A-Za-z0-9._+/-]+")


def _pairs(pairs: list) -> dict:
    """A JSON object whose names are each written once (a reader that takes the first and one that takes the last
    of two would read two different checks)."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("a name written twice")
        out[k] = v
    return out


def _no_constant(word: str):
    raise ValueError(f"not JSON: {word}")


def _whole(x, low: int, high: int) -> bool:
    return type(x) is int and low <= x <= high


def _word(w) -> bool:
    return isinstance(w, str) and 0 < len(w) <= MOST_WORD and not any(ord(c) < 32 or ord(c) == 127 for c in w)


def _folder(cwd) -> str:
    """The folder of the project the tests run in, as parts below the project's top, or Refused."""
    bad = Refused("The folder the tests run in is not a folder inside the project, so nothing was run.")
    if not isinstance(cwd, str) or len(cwd) > MOST_CWD:
        raise bad
    if cwd == "":
        return ""
    if any(c in cwd for c in "\\:") or any(ord(c) < 32 or ord(c) == 127 for c in cwd) or cwd.startswith("/"):
        raise bad
    parts = cwd.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise bad
    return cwd


def _record(said, language: str) -> dict:
    """The record of the libraries: `none`, or `fetched` with its packages, each named with a version; kept as it
    is (the sandbox hands it back as the result's `libraries`)."""
    bad = Refused("The record of the libraries the website fetched is not of the shape the test machine takes, so "
                  "nothing was run.")
    if not isinstance(said, dict) or said.get("state") not in ("none", "fetched") or said.get("language") != language:
        raise bad
    if said["state"] == "fetched":
        rows = said.get("packages")
        if not isinstance(rows, list) or len(rows) > MOST_PACKAGES:
            raise bad
        for row in rows:
            if not (isinstance(row, dict) and isinstance(row.get("name"), str) and row["name"]
                    and isinstance(row.get("version"), str)):
                raise bad
    return said


def settings(raw: bytes) -> dict:
    """check.json, taken by shape: {version, command, language, minutes, memory, cwd, libraries, fetched_with}.
    Refused for anything else, without a word of what was written (a setting this version does not know is
    counted, not named)."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MOST_SETTINGS:
        raise Refused("The check's settings are larger than the test machine reads, so nothing was run.")
    try:
        said = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused("The check's settings are not JSON the test machine can read, so nothing was run.") from None
    if not isinstance(said, dict):
        raise Refused("The check's settings are not a table of settings, so nothing was run.")
    unknown = set(said) - _KEYS
    if unknown:
        raise Refused(f"The check's settings hold {len(unknown)} setting{'s' if len(unknown) != 1 else ''} this test "
                      "machine does not know, so nothing was run.")
    missing = [k for k in _NEEDED if k not in said]
    if missing:
        raise Refused(f"The check's settings leave out {', '.join(missing)}, so nothing was run.")
    if not _whole(said["version"], 1, 1):
        raise Refused("The check's settings are of a version this test machine does not know (it knows version 1), "
                      "so nothing was run.")
    words = said["command"]
    if not (isinstance(words, list) and 0 < len(words) <= MOST_WORDS and all(_word(w) for w in words)):
        raise Refused("The test command is not a list of words the test machine takes, so nothing was run.")
    try:
        language = sandbox.check_command(list(words))
    except ValueError as e:
        raise Refused(f"The test command is not one the test machine runs ({e}), so nothing was run.") from None
    if language not in LANGUAGES:
        raise Refused("The test machine runs the tests of Python and JavaScript projects for now, so nothing was run.")
    if Path(words[0]).name.lower() in ("pnpm", "yarn"):
        raise Refused("The test machine has npm, which comes with its Node, and not pnpm or yarn: the tests are run "
                      "with npm (npm test), so nothing was run.")
    low, high = sandbox.MINUTES
    if not _whole(said["minutes"], low, high):
        raise Refused(f"The tests' time limit is a whole number of minutes from {low} to {high}, so nothing was run.")
    low, high = sandbox.MEGABYTES
    if not _whole(said["memory"], low, high):
        raise Refused(f"The tests' memory is a whole number of megabytes from {low} to {high:,}, so nothing was run.")
    cwd = _folder(said.get("cwd", ""))
    record = _record(said["libraries"], language)
    fetched_with = said.get("fetched_with", "")
    if not (isinstance(fetched_with, str) and len(fetched_with) <= MOST_PYTHON
            and (fetched_with == "" or _PYTHON_PATH.fullmatch(fetched_with))):
        raise Refused("The Python that fetched the libraries is not named by a full path the test machine takes, so "
                      "nothing was run.")
    return {"version": 1, "command": list(words), "language": language, "minutes": said["minutes"],
            "memory": said["memory"], "cwd": cwd, "libraries": record, "fetched_with": fetched_with}


# ---------------------------------------------------------------------------- the archive
def links_npm_makes(name: str, target: str) -> bool:
    """A link that npm makes when it installs, and nothing else: a program's link in a `.bin` folder of the
    libraries (`libraries/.bin/jest`, `libraries/a/node_modules/.bin/b`), leading up one level and down into a
    package beside it (`../jest/bin/jest.js`), never out of that folder, never into another folder of links, never to
    a place of the machine."""
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts) or parts[0] != "libraries" or len(parts) < 3 or parts[-2] != ".bin":
        return False
    if len(parts) != 3 and parts[-3] != "node_modules":
        return False
    if not isinstance(target, str) or not 0 < len(target) <= archive.MOST_LINK or "\\" in target:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in target) or not target.startswith("../"):
        return False
    rest = target[3:].split("/")
    return bool(rest) and not any(p in ("", ".", "..", ".bin") for p in rest)


def _free_at(path: Path) -> int:
    """Bytes free on the disk of `path` (or of the nearest folder above it that is there); 0 when it cannot be said,
    so nothing that may not fit is taken."""
    p = Path(path)
    while not p.exists() and p.parent != p:
        p = p.parent
    try:
        return shutil.disk_usage(p).free
    except OSError:
        return 0


def take(archive_path: Path, work: Path, free=None) -> dict:
    """Unpack a check's archive into `work` (made here; it must not be there): {settings, project, libraries (the
    folder, or None), files, bytes, links}. Refused, with nothing left in `work`, for an archive that is not a check
    this machine takes. `free`: a function that says the bytes free on the disk (the machine's disk by default)."""
    work = Path(work)
    free = free or (lambda: _free_at(work))
    try:
        zf = zipfile.ZipFile(archive_path)
    except (zipfile.BadZipFile, OSError, ValueError):
        raise Refused("The check's archive is not a .zip the test machine can read, so nothing was run.") from None
    with zf:
        try:
            info = zf.getinfo("check.json")
        except KeyError:
            raise Refused("The check's archive holds no settings (check.json), so nothing was run.") from None
        if info.is_dir() or info.flag_bits & 0x1 or info.file_size > MOST_SETTINGS \
                or stat.S_IFMT((info.external_attr >> 16) & 0xFFFF) not in (0, stat.S_IFREG):
            raise Refused("The check's settings are not a plain file the test machine reads, so nothing was run.")
        try:
            with zf.open(info) as r:
                raw = r.read(MOST_SETTINGS + 1)
        except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, NotImplementedError, ValueError):
            raise Refused("The check's archive is damaged, so nothing was run.") from None
        said = settings(raw)
        declared = sum(i.file_size for i in zf.infolist() if not i.is_dir())
    fetched = said["libraries"]["state"] == "fetched"
    have = free()
    # the files once unpacked, and the sandbox's copy of them beside (the libraries are moved, or copied where
    # the run's folder is on another disk), and room for the program and the sandbox's own files
    if 2 * declared + ROOM > have:
        raise Refused(f"The project and its libraries take {declared:,} bytes once unpacked, and the test machine's "
                      "disk has no room for them and the copy the tests run on, so nothing was run.")
    unpacked: dict = {}
    try:
        archive.unpack(Path(archive_path), work, min(MOST_UNPACKED, max(0, (have - ROOM) // 2)), strip=False,
                       said=unpacked, entries=MOST_ENTRIES, modes=True, links=links_npm_makes)
    except archive.Refused as e:
        raise Refused(str(e)) from None
    try:
        tops = {}
        with os.scandir(work) as it:
            for e in it:
                tops[e.name] = "dir" if e.is_dir(follow_symlinks=False) else "file" if e.is_file(follow_symlinks=False) \
                    else "other"
        want = {"check.json": "file", "project": "dir"}
        if fetched:
            want["libraries"] = "dir"
        if "libraries" in tops and not fetched:
            raise Refused("The check's archive holds libraries its settings do not name, so nothing was run.")
        if fetched and "libraries" not in tops:
            raise Refused("The check's settings say the website fetched the project's libraries, and the archive holds "
                          "none, so nothing was run.")
        if any(tops.get(k) != v for k, v in want.items()) or set(tops) - set(want):
            raise Refused("The check's archive holds something besides its settings, the project and its libraries, "
                          "so nothing was run.")
        project = work / "project"
        if said["cwd"]:
            here = project
            for part in said["cwd"].split("/"):
                here = here / part
                if here.is_symlink() or not here.is_dir():
                    raise Refused("The folder the tests run in is not in the project, so nothing was run.")
    except BaseException:
        removal.remove(work)
        raise
    return {"settings": said, "project": project, "libraries": work / "libraries" if fetched else None,
            "files": unpacked.get("files", 0), "bytes": unpacked.get("bytes", 0), "links": unpacked.get("links", 0)}


def pack(project: Path, out: Path, command: list[str], cwd: str = "", minutes: int = 10, memory: int = 2048,
         libraries: Path | None = None, record: dict | None = None, fetched_with: str = "") -> dict:
    """Write a check's archive: the settings, the project and, where they were fetched, its libraries as the fetch
    laid them out (`record` is that fetch's record). Every entry has the same date, a file the mode 0755 when it may
    be run and 0644 otherwise, and nothing is followed through a link: a link of the project is left out (the
    machine makes none there) and a link of the libraries goes in only where npm makes one (else ValueError).
    Folders the sandbox's copy leaves out (`sandbox.SKIP`) are left out of the project. Returns {files, bytes,
    links, skipped, left_out}: what went in, and what of the project did not, with why. ValueError (a `Refused`
    among them) for settings the machine would refuse."""
    if libraries is not None and record is None:
        raise ValueError("libraries come with the record of the fetch that made them")
    if record is None:
        try:
            language = sandbox.check_command(list(command))
        except ValueError:
            language = "python"     # `settings` says what is wrong with the command
        record = {"state": "none", "language": language}
    said = {"version": 1, "command": list(command), "minutes": minutes, "memory": memory, "libraries": record}
    if cwd:
        said["cwd"] = cwd
    if fetched_with:
        said["fetched_with"] = fetched_with
    raw = json.dumps(said, ensure_ascii=False, indent=1).encode("utf-8")
    settings(raw)
    if (record.get("state") == "fetched") != (libraries is not None):
        raise ValueError("libraries are packed exactly when the record says they were fetched")
    counted = {"files": 0, "bytes": 0, "links": 0, "skipped": 0, "left_out": [], "entries": 1}
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        info = zipfile.ZipInfo("check.json", DATE)
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, raw)
        counted["files"] += 1
        counted["bytes"] += len(raw)
        _tree(z, Path(project), "project", counted)
        if libraries is not None:
            _tree(z, Path(libraries), "libraries", counted)
    counted.pop("entries")
    return counted


def _dir_entry(z: zipfile.ZipFile, name: str, counted: dict) -> None:
    info = zipfile.ZipInfo(name.rstrip("/") + "/", DATE)
    info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
    z.writestr(info, b"")
    counted["entries"] += 1


def _left(counted: dict, rel: str, why: str) -> None:
    counted["left_out"].append({"path": rel, "why": why})


def _tree(z: zipfile.ZipFile, top: Path, name: str, counted: dict) -> None:
    """One folder of the archive (`project` or `libraries`), walked without following a link."""
    if not top.is_dir() or top.is_symlink():
        raise ValueError(f"the {name} folder to pack is not a folder")
    _dir_entry(z, name, counted)
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(top).as_posix()
        prefix = name if rel_dir == "." else f"{name}/{rel_dir}"
        keep = []
        for d in sorted(dirnames):
            if os.path.islink(here / d):
                filenames.append(d)                     # a link to a folder is a link like any other
            elif name == "project" and d in sandbox.SKIP:
                counted["skipped"] += 1                 # the sandbox's copy leaves it out too
            else:
                keep.append(d)
        dirnames[:] = keep
        if rel_dir != "." and not keep and not filenames:
            _dir_entry(z, prefix, counted)              # an empty folder is there on the machine too
        for f in sorted(set(filenames)):
            p = here / f
            arc = f"{prefix}/{f}"
            if len(arc) > archive.MAX_NAME or any(c in arc for c in "\\\x00") or \
                    any(part in (".", "..") for part in arc.split("/")):
                _left(counted, arc[len(name) + 1:][:300], "a name the test machine's unpacker does not take")
                continue
            try:
                st = os.lstat(p)
            except OSError as e:
                _left(counted, arc[len(name) + 1:], f"it could not be read ({e.strerror or type(e).__name__})")
                continue
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(p)
                if name == "libraries" and links_npm_makes(arc, target):
                    info = zipfile.ZipInfo(arc, DATE)
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    z.writestr(info, target.encode("utf-8"))
                    counted["links"] += 1
                    counted["entries"] += 1
                elif name == "libraries":
                    raise ValueError(f"the libraries hold a link npm does not make: {arc}")
                else:
                    _left(counted, arc[len(name) + 1:], "a link (the test machine makes none in the project)")
                continue
            if not stat.S_ISREG(st.st_mode):
                _left(counted, arc[len(name) + 1:], "not a plain file")
                continue
            _file(z, p, arc, counted)
            if counted["entries"] > MOST_ENTRIES:
                raise ValueError(f"the archive would hold more than {MOST_ENTRIES:,} files")


def _file(z: zipfile.ZipFile, p: Path, arc: str, counted: dict) -> None:
    """One plain file copied into the archive byte for byte: opened as itself (never through a link at its name, never
    waiting on a pipe put there meanwhile) and taken only while it is a plain file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_BINARY", 0)
    fd = os.open(p, flags)
    with os.fdopen(fd, "rb") as src:
        st = os.fstat(src.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{arc} changed while it was packed")
        info = zipfile.ZipInfo(arc, DATE)
        info.external_attr = (stat.S_IFREG | (0o755 if st.st_mode & 0o111 else 0o644)) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with z.open(info, "w", force_zip64=st.st_size > (1 << 30)) as dst:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
                counted["bytes"] += len(chunk)
    counted["files"] += 1
    counted["entries"] += 1


# ---------------------------------------------------------------------------- the walls the design counts on
def _memory_watch() -> str:
    if not sys.platform.startswith("linux"):
        return "the watch on the memory the tests use together is made on Linux only"
    from . import _jail
    try:
        with open("/proc/self/status", "rb") as f:
            seen = _jail._kb(f.read(), (b"VmRSS:",))
    except OSError as e:
        return f"this system does not say how much memory a program uses ({e.strerror or type(e).__name__})"
    return "" if seen is not None else "this system does not say how much memory a program uses"


def _ordinary_user() -> str:
    if not sys.platform.startswith("linux"):
        return "the switch to an ordinary user for the tests is made on Linux only"
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return "this program does not run as root, so it cannot switch the tests to an ordinary user of their own"
    return ""


def walls() -> list[dict]:
    """The walls the design counts on, asked of this system: [{wall, stands, why}] (`why` is "" where it stands)."""
    rows = []
    for wall, ask in (("the tests' own network", sandbox.own_network),
                      ("a doorman for every connection", sandbox.own_sockets),
                      ("the memory watch", _memory_watch),
                      ("an ordinary user for the tests", _ordinary_user)):
        try:
            why = ask()
        except Exception as e:  # noqa: BLE001 - a wall that cannot be asked about does not stand
            why = f"it could not be asked about ({type(e).__name__})"
        rows.append({"wall": wall, "stands": not why, "why": why or ""})
    return rows


def _commit() -> str:
    from . import _build
    return _build.COMMIT if isinstance(_build.COMMIT, str) and re.fullmatch(r"[0-9a-f]{40}", _build.COMMIT) else ""


def about() -> dict:
    """What runs the check: Lantern (version and commit), Python, the system, and the walls."""
    return {"lantern": __version__, "commit": _commit(), "python": platform.python_version(),
            "system": f"{platform.system()} {platform.release()}".strip(), "walls": walls()}


def _and(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _wall_words(missing: list[dict]) -> str:
    names = [w["wall"] for w in missing]
    text = (f"{_and(names)} {'does' if len(names) == 1 else 'do'} not stand on this machine "
            f"({'; '.join(w['why'] for w in missing)}), so no test was run.")
    return text[0].upper() + text[1:]


def _relative(tests: dict, top: Path) -> None:
    """The files of the calls the tests made, named from the project's top (the machine's folders mean nothing to
    the website); a file outside the project keeps its full name."""
    real = str(Path(top).resolve())
    for row in tests.get("pairs") or []:
        for side in ("caller", "callee"):
            try:
                f = row[side][0]
            except (KeyError, IndexError, TypeError):
                continue
            if isinstance(f, str) and f.startswith(real + os.sep):
                row[side][0] = PurePosixPath(*Path(f[len(real) + 1:]).parts).as_posix()


def check(archive_path: Path, work: Path, log=print, cancel=None, free=None) -> dict:
    """One check: the walls asked, the archive taken into `work` (made here, removed at the end), the tests run.
    `log` gets every line (and, where it has one, `log.step(name, said)` each step); `cancel` (a threading.Event)
    stops the tests with everything they started. Never raises for the archive or the tests: the result says."""
    cancel = cancel if cancel is not None else threading.Event()
    step = getattr(log, "step", None) or (lambda name, said="": None)
    result: dict = {"version": 1, "state": "", "why_not": "", "runner": about()}
    work = Path(work)
    try:
        missing = [w for w in result["runner"]["walls"] if not w["stands"]]
        if missing:
            result.update(state="unable", why_not=_wall_words(missing))
            return result
        step("unpacking", "the archive is unpacked with the website's own rules")
        try:
            taken = take(archive_path, work, free=free)
        except archive.Refused as e:
            result.update(state="refused", why_not=str(e))
            return result
        s = taken["settings"]
        result["taken"] = {"files": taken["files"], "bytes": taken["bytes"], "links": taken["links"]}
        result["check"] = {k: s[k] for k in ("command", "cwd", "minutes", "memory", "language")}
        fetched = s["libraries"]["state"] == "fetched"
        result["runner"]["reach"] = sandbox.reach(s["language"], fetched)
        if cancel.is_set():
            result.update(state="stopped", why_not=STOPPED)
            return result
        plan = libraries.given(taken["libraries"], s["libraries"], s["language"], s["fetched_with"])
        step("running", f"{taken['files']:,} files taken; the tests run in the sandbox as an ordinary user")
        try:
            tests = sandbox.run(taken["project"], s["command"], log=log, timeout=sandbox.time_limit(s["minutes"]),
                                backend="subprocess", cwd_rel=s["cwd"], cancel=cancel, memory=s["memory"],
                                offline=True, given=plan)
        except sandbox.Unavailable as e:
            result.update(state="unable", why_not=f"The sandbox could not be set up on this machine ({e}), so no test "
                          "was run.")
            return result
        tests = json.loads(json.dumps(dict(tests), default=str))
        _relative(tests, taken["project"])
        result["tests"] = tests
        if tests.get("cancelled"):
            result.update(state="stopped", why_not=STOPPED)
        else:
            result.update(state="done", why_not="")
        return result
    except Exception as e:  # noqa: BLE001 - the website gets a result, whatever went wrong
        result.update(state="unable", why_not=f"The test machine's program failed ({type(e).__name__}), so the check "
                      "has no result.")
        result.pop("tests", None)
        return result
    finally:
        if os.path.lexists(work):
            removal.remove(work)


# ---------------------------------------------------------------------------- the program: its state and clock
def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Lines:
    """What `check` is handed as its `log`: each line, and each step."""

    def __init__(self, runner: Runner):
        self._runner = runner

    def __call__(self, line) -> None:
        self._runner._line(str(line))

    def step(self, name: str, said: str = "") -> None:
        self._runner._step(name, said)


class Runner:
    """The machine's one check, from the archive to the result, and the clock that ends the program.

    `digest`: the key's SHA-256 fingerprint (64 lowercase hexadecimal characters; ValueError otherwise). `work`: the
    program's own folder (made, owner only). `check`: what runs a check (`check(archive, work, log, cancel)`),
    `lantern.runner.check` unless a test hands another. `most`: bytes an archive may have; `free`: a function that
    says the bytes free on the disk. `read_timeout`: seconds a read may wait. The three `wait_for_archive`,
    `wait_for_taker` and `longest` are the clock's (this module's opening text). `say`: where the program's own
    few lines go (none by default)."""

    def __init__(self, digest: str, work: Path, check=None, most: int = MOST_ARCHIVE, free=None,
                 read_timeout: float = READ_TIMEOUT, wait_for_archive: float = WAIT_FOR_ARCHIVE,
                 wait_for_taker: float = WAIT_FOR_TAKER, longest: float = LONGEST, say=None):
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError("the key's fingerprint is 64 lowercase hexadecimal characters")
        self._digest = digest
        self.work = Path(work)
        self.work.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.work, 0o700)
        self.most = most
        self.free = free or (lambda: _free_at(self.work))
        self.read_timeout = read_timeout
        self.wait_for_archive, self.wait_for_taker, self.longest = wait_for_archive, wait_for_taker, longest
        self._check = check or (lambda a, w, lg, c: globals()["check"](a, w, lg, c, free=self.free))
        self._say = say or (lambda text: None)
        self.lock = threading.Lock()
        self.state = "waiting"
        self.steps: list[dict] = []
        self.lines: list[str] = []
        self.first = 0                     # the number of the first line kept
        self.result: dict | None = None
        self.cancel = threading.Event()
        self.ended = threading.Event()
        self.why_ended = ""
        self._changed = threading.Event()
        self._born = time.monotonic()
        self._result_at: float | None = None
        self._taken_at: float | None = None
        self._thread: threading.Thread | None = None
        threading.Thread(target=self._clock, daemon=True, name="lantern-runner-clock").start()

    # the key
    def allowed(self, said) -> bool:
        """The request's `Authorization` header is exactly `Bearer <the check's key>`."""
        if not isinstance(said, str) or not said.startswith("Bearer "):
            return False
        key = said[len("Bearer "):]
        if not 0 < len(key) <= MOST_KEY or not _KEY.fullmatch(key):
            return False
        return hmac.compare_digest(hashlib.sha256(key.encode("ascii")).hexdigest(), self._digest)

    def room(self) -> int:
        """Bytes an archive may still take on the disk."""
        return self.free() - ROOM

    # the log and the steps
    def _line(self, line: str) -> None:
        with self.lock:
            self.lines.append(line[:MOST_LINE])
            if len(self.lines) > KEEP_LINES + 1000:
                drop = len(self.lines) - KEEP_LINES
                del self.lines[:drop]
                self.first += drop

    def _step_locked(self, name: str, said: str) -> None:
        self.steps.append({"at": _now(), "step": name, "said": said})
        if name in ("unpacking", "running") and self.state not in END_STATES:
            self.state = name

    def _step(self, name: str, said: str = "") -> None:
        with self.lock:
            self._step_locked(name, said)

    def view(self, start: int = 0) -> dict:
        """How it is going: {state, steps, lines (from line `start`), next, result, missed?}. Handing over a result
        counts as its being taken."""
        with self.lock:
            last = self.first + len(self.lines)
            begin = min(max(start, self.first), last)
            lines = self.lines[begin - self.first:begin - self.first + MOST_PER_ASK]
            out = {"state": self.state, "steps": list(self.steps), "lines": lines, "next": begin + len(lines),
                   "result": self.result}
            if begin > start:
                out["missed"] = begin - start
            if self.result is not None and self._taken_at is None:
                self._taken_at = time.monotonic()
                self._changed.set()
        return out

    # the archive
    def begin_taking(self) -> bool:
        with self.lock:
            if self.state != "waiting" or self.ended.is_set():
                return False
            self.state = "taking"
            self._step_locked("taking", "the archive is coming")
        return True

    def not_taken(self, why: str) -> None:
        with self.lock:
            if self.state == "taking":
                self.state = "waiting"
            self._step_locked("not taken", why)
        self._changed.set()

    def taken(self, path: Path, size: int) -> None:
        with self.lock:
            self.state = "unpacking"
            self._step_locked("taken", f"{size:,} bytes")
            self._thread = threading.Thread(target=self._run, args=(Path(path),), daemon=True,
                                            name="lantern-runner-check")
            self._thread.start()
        self._changed.set()
        self._say(f"an archive of {size:,} bytes was taken")

    def _run(self, path: Path) -> None:
        try:
            result = self._check(path, self.work / f"check-{secrets.token_hex(6)}", _Lines(self), self.cancel)
            if not isinstance(result, dict) or result.get("state") not in END_STATES:
                raise TypeError("a check gave no result")
        except Exception as e:  # noqa: BLE001 - the website gets a result, whatever went wrong
            result = {"version": 1, "state": "unable",
                      "why_not": f"The test machine's program failed ({type(e).__name__}), so the check has no result."}
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        with self.lock:
            self.result = result
            self.state = result["state"]
            self._step_locked(result["state"], str(result.get("why_not") or ""))
            self._result_at = time.monotonic()
        self._changed.set()
        self._say(f"the check ended: {result['state']}")

    def stop(self) -> None:
        self.cancel.set()

    # the end
    def end(self, why: str) -> None:
        with self.lock:
            if self.ended.is_set():
                return
            self.why_ended = why
        self.cancel.set()
        self.ended.set()
        self._changed.set()

    def finish(self, seconds: float = 60.0) -> bool:
        """After the end: wait for the check (its tests are being ended) and remove what it left in the program's
        folder. True when nothing of it is left going."""
        t = self._thread
        if t is not None:
            t.join(seconds)
        return t is None or not t.is_alive()

    def _next(self) -> tuple[float, str]:
        best = (self._born + self.longest, "it ran longer than any check may")
        if self.state == "waiting":
            best = min(best, (self._born + self.wait_for_archive, "no archive came"))
        elif self.result is not None and self._result_at is not None:
            if self._taken_at is None:
                best = min(best, (self._result_at + self.wait_for_taker, "nobody took the result"))
            else:
                best = min(best, (self._taken_at + self.wait_for_taker,
                                  "the result was taken, and the website did not end the machine"))
        return best

    def _clock(self) -> None:
        """Ends the program at the first deadline that passes; waits on a change of state, never in a loop of its
        own."""
        while not self.ended.is_set():
            with self.lock:
                at, why = self._next()
            wait = at - time.monotonic()
            if wait <= 0:
                self.end(why)
                return
            if self._changed.wait(min(wait, 3600.0)):
                self._changed.clear()


# ---------------------------------------------------------------------------- the door
class _Cut(Exception):
    def __init__(self, code: int, why: str):
        super().__init__(why)
        self.code, self.why = code, why


_SHORT = {400: "the request could not be read", 404: "nothing here", 405: "not this way", 408: "too slow",
          411: "say the archive's length", 413: "too large", 414: "the address is too long",
          431: "the request's headers are too large", 505: "speak HTTP/1.1"}


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lantern-runner"
    sys_version = ""

    def version_string(self) -> str:
        return "lantern-runner"

    def log_message(self, format, *args) -> None:       # noqa: A002 - the standard library's own name
        pass                                            # nothing of a request is written anywhere

    def setup(self) -> None:
        self.timeout = self.server.runner.read_timeout
        self._unread = False
        super().setup()

    # every answer
    def _answer(self, code: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=True).encode("ascii")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True
        if self._unread:
            self._linger()

    def _linger(self) -> None:
        """A body that was not read is let come before the connection is closed, for a moment: closed with bytes
        unread, the connection is reset, and the asker may lose the answer."""
        self._unread = False
        try:
            self.connection.shutdown(socket.SHUT_WR)
            self.connection.settimeout(0.5)
            end, got = time.monotonic() + 2.0, 0
            while time.monotonic() < end and got < (8 << 20):
                chunk = self.connection.recv(CHUNK)
                if not chunk:
                    break
                got += len(chunk)
        except OSError:
            pass

    def send_error(self, code, message=None, explain=None) -> None:
        if code == 501:          # a method nobody answers: as any other request
            headers = getattr(self, "headers", None)
            said = headers.get_all("Authorization") if headers is not None else None
            if not said or len(said) != 1 or not self.server.runner.allowed(said[0]):
                return self._answer(401, {"error": "not allowed"})
            return self._answer(405, {"error": _SHORT[405]})
        self._answer(int(code), {"error": _SHORT.get(int(code), _SHORT[400])})

    def handle_expect_100(self) -> bool:
        said = self.headers.get_all("Authorization") or []
        if len(said) != 1 or not self.server.runner.allowed(said[0]):
            self._answer(401, {"error": "not allowed"})
            return False
        return super().handle_expect_100()

    def do_GET(self) -> None:
        self._route()

    do_PUT = do_POST = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_GET

    def _route(self) -> None:
        runner: Runner = self.server.runner
        length = self.headers.get("Content-Length", "")
        self._unread = bool(self.headers.get("Transfer-Encoding")) or (length.strip() not in ("", "0"))
        said = self.headers.get_all("Authorization") or []
        if len(said) != 1 or not runner.allowed(said[0]):
            return self._answer(401, {"error": "not allowed"})
        path, _, query = self.path.partition("?")
        if (self.command, path) == ("GET", "/v1/check"):
            return self._view(runner, query)
        if (self.command, path) == ("PUT", "/v1/check"):
            return self._take(runner)
        if (self.command, path) == ("POST", "/v1/stop"):
            runner.stop()
            return self._answer(202, {"state": runner.state})
        if (self.command, path) == ("POST", "/v1/end"):
            self._answer(202, {"state": "ended"})
            runner.end(WEBSITE_ENDED)
            return None
        if path in ("/v1/check", "/v1/stop", "/v1/end"):
            return self._answer(405, {"error": _SHORT[405]})
        return self._answer(404, {"error": _SHORT[404]})

    def _view(self, runner: Runner, query: str) -> None:
        start = 0
        if query:
            name, eq, value = query.partition("=")
            if name != "from" or not eq or not value.isascii() or not value.isdigit() or len(value) > 12:
                return self._answer(400, {"error": "ask with ?from=<the number of a line>"})
            start = int(value)
        return self._answer(200, runner.view(start))

    def _take(self, runner: Runner) -> None:
        te = self.headers.get_all("Transfer-Encoding") or []
        cl = self.headers.get_all("Content-Length") or []
        if (te and cl) or len(te) > 1 or len(cl) > 1:
            return self._answer(400, {"error": "a body says its length one way"})
        length: int | None = None
        if te:
            if te[0].strip().lower() != "chunked":
                return self._answer(400, {"error": "an archive is sent whole or in chunks"})
        elif cl:
            v = cl[0].strip()
            if not v.isascii() or not v.isdigit() or len(v) > 18:
                return self._answer(400, {"error": _SHORT[400]})
            length = int(v)
        else:
            return self._answer(411, {"error": _SHORT[411]})
        if length is not None:
            if length > runner.most:
                return self._answer(413, {"error": f"an archive may have at most {runner.most:,} bytes"})
            if length > runner.room():
                return self._answer(507, {"error": "the test machine's disk has no room for an archive of that size"})
            if length == 0:
                return self._answer(400, {"error": "the archive is empty"})
        if not runner.begin_taking():
            return self._answer(409, {"error": "this machine has taken its check's archive already"})
        path = runner.work / f"archive-{secrets.token_hex(8)}.zip"
        try:
            size = self._receive(runner, path, length)
        except _Cut as cut:
            _gone(path)
            runner.not_taken(cut.why)
            return self._answer(cut.code, {"error": cut.why})
        except BaseException:
            _gone(path)
            runner.not_taken("the archive could not be taken")
            raise
        self._unread = False
        runner.taken(path, size)
        return self._answer(202, {"state": "unpacking"})

    def _read(self, n: int, deadline: float) -> bytes:
        if time.monotonic() > deadline:
            raise _Cut(408, "the archive came too slowly")
        try:
            return self.rfile.read1(n)
        except TimeoutError:
            raise _Cut(408, "the archive stopped coming") from None
        except OSError:
            raise _Cut(400, "the connection ended before the archive did") from None

    def _readline(self, deadline: float, limit: int) -> bytes:
        if time.monotonic() > deadline:
            raise _Cut(408, "the archive came too slowly")
        try:
            return self.rfile.readline(limit)
        except TimeoutError:
            raise _Cut(408, "the archive stopped coming") from None
        except OSError:
            raise _Cut(400, "the connection ended before the archive did") from None

    def _receive(self, runner: Runner, path: Path, length: int | None) -> int:
        """The body, written to a file of the program's own as it comes (never through a link at its place),
        counted against what may come. Returns its size; `_Cut` with the answer's code otherwise."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) \
            | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        got, room = 0, runner.room()
        deadline = time.monotonic() + max(MIN_SECONDS, (length if length is not None else runner.most) / MIN_RATE)
        with os.fdopen(fd, "wb") as out:
            if length is not None:
                while got < length:
                    chunk = self._read(min(CHUNK, length - got), deadline)
                    if not chunk:
                        raise _Cut(400, "the connection ended before the archive did")
                    out.write(chunk)
                    got += len(chunk)
                return got
            while True:
                line = self._readline(deadline, MOST_CHUNK_LINE + 2)
                if not line.endswith(b"\r\n"):
                    raise _Cut(400, "a chunk of the archive does not say its size")
                text = line[:-2]
                if not text or len(text) > 16 or any(c not in b"0123456789abcdefABCDEF" for c in text):
                    raise _Cut(400, "a chunk of the archive does not say its size")
                size = int(text, 16)
                if size == 0:
                    break
                if got + size > runner.most:
                    raise _Cut(413, f"an archive may have at most {runner.most:,} bytes")
                if got + size > room:
                    raise _Cut(507, "the test machine's disk has no room for an archive of that size")
                left = size
                while left:
                    chunk = self._read(min(CHUNK, left), deadline)
                    if not chunk:
                        raise _Cut(400, "the connection ended before the archive did")
                    out.write(chunk)
                    got += len(chunk)
                    left -= len(chunk)
                if self._readline(deadline, 3) != b"\r\n":
                    raise _Cut(400, "a chunk of the archive does not end as a chunk ends")
            for _ in range(MOST_TRAILERS + 1):
                line = self._readline(deadline, 1026)
                if line == b"\r\n":
                    break
                if not line.endswith(b"\r\n"):
                    raise _Cut(400, "the archive's last lines could not be read")
            else:
                raise _Cut(400, "the archive's last lines could not be read")
        if got == 0:
            raise _Cut(400, "the archive is empty")
        return got


def _gone(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


class Door(http.server.ThreadingHTTPServer):
    """The machine's one door: `Runner`'s routes, behind the check's key (this module's opening text). At most
    `MOST_AT_ONCE` connections are served at once; one more is closed at once. Closing the door ends the program."""

    daemon_threads = True
    request_queue_size = MOST_AT_ONCE

    def __init__(self, address, runner: Runner):
        if ":" in str(address[0]):
            self.address_family = socket.AF_INET6
        self.runner = runner
        self._slots = threading.BoundedSemaphore(MOST_AT_ONCE)
        super().__init__(address, _Handler)

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)        # not HTTPServer's: it asks the network for this computer's name
        self.server_name, self.server_port = "lantern-runner", self.server_address[1]

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address) -> None:
        pass                       # a connection that broke is no news, and nothing of it is written anywhere

    def server_close(self) -> None:
        super().server_close()
        self.runner.end("the door was closed")


# ---------------------------------------------------------------------------- the command line
def _say(text: str) -> None:
    print(f"lantern-runner: {text}", flush=True)


def _serve(a) -> int:
    digest = os.environ.pop(KEY_VARIABLE, "")
    if not _DIGEST.fullmatch(digest):
        _say(f"no key for the check: {KEY_VARIABLE} holds no fingerprint of one, so the door stays shut")
        return 2
    made = not a.work
    work = Path(a.work) if a.work else Path(tempfile.mkdtemp(prefix="lantern-runner-"))
    runner = Runner(digest, work, wait_for_archive=a.wait_for_archive, wait_for_taker=a.wait_for_taker,
                    longest=a.longest, say=_say)
    try:
        door = Door((a.host, a.port), runner)
    except OSError as e:
        _say(f"the door could not be opened at {a.host}:{a.port} ({e.strerror or type(e).__name__})")
        return 2
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: runner.end("the machine was told to stop"))
    threading.Thread(target=door.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True,
                     name="lantern-runner-door").start()
    port = door.server_address[1]
    if a.ready:
        results.write(Path(a.ready), json.dumps({"port": port}) + "\n")
    _say(f"the door is open on port {port}")
    try:
        runner.ended.wait()
        _say(f"the machine ends: {runner.why_ended}")
        door.shutdown()
        runner.finish()
        sandbox.stop_all()
        door.server_close()
    finally:
        if made:
            removal.remove(work)
    return 0 if runner.why_ended == WEBSITE_ENDED else 1


def _run(a) -> int:
    work = Path(tempfile.mkdtemp(prefix="lantern-runner-"))
    try:
        result = check(Path(a.archive), work / "check", log=print)
    finally:
        removal.remove(work)
    results.write(Path(a.out), json.dumps(result, indent=1) + "\n")
    print(f"the check ended: {result['state']}{': ' + result['why_not'] if result['why_not'] else ''}")
    return 0 if result["state"] == "done" else 3


def _pack(a) -> int:
    words = list(a.command)
    if words[:1] == ["--"]:
        words = words[1:]
    record = None
    if a.record:
        text, why = results.plain(Path(a.record))
        try:
            record = json.loads(text) if text is not None else None
        except ValueError:
            why = "it is not JSON"
        if record is None:
            print(f"not packed: the record of the fetch was not read ({why or 'there is no such file'})", file=sys.stderr)
            return 2
    try:
        said = pack(Path(a.project), Path(a.out), words, cwd=a.cwd, minutes=a.minutes, memory=a.memory,
                    libraries=Path(a.libraries) if a.libraries else None, record=record, fetched_with=a.fetched_with)
    except ValueError as e:
        print(f"not packed: {e}", file=sys.stderr)
        return 2
    print(f"packed {said['files']:,} files, {said['bytes']:,} bytes, {said['links']} links; "
          f"{len(said['left_out'])} left out")
    for row in said["left_out"][:20]:
        print(f"  left out: {row['path']} ({row['why']})")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m lantern.runner", description="The test machine's program.")
    sub = ap.add_subparsers(dest="what", required=True)
    s = sub.add_parser("serve", help="open the door and run the one check that comes through it")
    s.add_argument("--host", default="0.0.0.0")  # nosec B104: reached from outside the machine, and only with the check's key
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--ready", help="a file the port is written to once the door is open")
    s.add_argument("--work", help="the program's own folder (a new temp folder by default, removed at the end)")
    s.add_argument("--wait-for-archive", type=float, default=WAIT_FOR_ARCHIVE)
    s.add_argument("--wait-for-taker", type=float, default=WAIT_FOR_TAKER)
    s.add_argument("--longest", type=float, default=LONGEST)
    r = sub.add_parser("run", help="run one check's archive here, with no door")
    r.add_argument("archive")
    r.add_argument("--out", required=True)
    p = sub.add_parser("pack", help="write a check's archive")
    p.add_argument("project")
    p.add_argument("out")
    p.add_argument("--minutes", type=int, default=10)
    p.add_argument("--memory", type=int, default=2048)
    p.add_argument("--cwd", default="")
    p.add_argument("--libraries")
    p.add_argument("--record")
    p.add_argument("--fetched-with", default="")
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    return {"serve": _serve, "run": _run, "pack": _pack}[a.what](a)


if __name__ == "__main__":
    sys.exit(main())
