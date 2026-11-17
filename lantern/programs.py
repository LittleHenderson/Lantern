"""The programs Lantern starts are the person's own: never the current folder's, never a project's (stage 7 of the
2026-11-09 directive).

Lantern is often started inside the folder of the project it was asked to read, and reading a project must not run
it. Until 2026-11-10 the current folder could choose what ran, three ways:

  * A tool started as `python -m <tool>` (Bandit) looked in the current folder first for every module it loads. That
    is Python's own rule. A project file named `bandit.py`, `logging.py` or `yaml.py` ran as a program.
  * A program started by its bare name (`git`, `npm`, `gitleaks`, `pip-audit`, `docker`, `tesseract`, `taskkill`):
    Windows looks in the current folder before PATH, and so does `shutil.which` there.
  * On any system a PATH entry that is empty, `.` or another relative path means the current folder.

`find(name)` gives a program's full path from the folders PATH names in full, or None. `python(module, ...)` is the
command line of a Python tool that is not given the current folder (`-P`, Python 3.11 and later). `env(base)` is the
environment a helper is started with (`remote.run_bounded` uses it for every one): PATH and PYTHONPATH without their
relative entries, and on Windows the system's own switch against looking in the current folder, which its shell
obeys when a `.cmd` (npm) starts `node` by its bare name. Nothing else of the person's environment is changed.
`settings(name, text)` is a settings file of Lantern's own for a tool that would otherwise look for one in the
folder it scans (Bandit and a project's `.bandit`). `folder()` is a folder of Lantern's own for a tool that takes
settings from the folder it is started in (npm and a project's `.npmrc`): the tool is started there, on copies
of the files it is to read. `put(folder, name, text)` writes a file of Lantern's own into such a folder (gitleaks'
settings, its empty list, the sample it is asked about first), the same bytes on every system.

Not covered: a folder PATH names in full is the person's own setting and is used as written, also when it lies inside
a project (a project's own virtual environment that the person switched on); and Lantern itself is started by Python
the way the person's own settings say (`python -m lantern.cli` inside a project, or PYTHONPATH with a relative
entry, hand Lantern's own Python the current folder before any line of Lantern runs).
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path

WINDOWS = os.name == "nt"
STARTABLE = (".com", ".exe", ".bat", ".cmd")   # what Windows starts by its path; PATHEXT may name more (.js, .vbs)
SEARCHED = ("PATH", "PYTHONPATH")
SWITCH = "NoDefaultCurrentDirectoryInExePath"


def _full(folder: str) -> str | None:
    """A PATH entry that names a folder in full, without the quotes Windows allows round it; else None."""
    if WINDOWS:
        folder = folder.strip('"')
    return folder if folder and os.path.isabs(folder) else None


def find(name: str, path: str | None = None) -> str | None:
    """The full path of the program `name` (a bare name) in the first folder of `path` (PATH when None) that holds
    it. Only folders named in full are looked in: never the current folder."""
    if not isinstance(name, str) or not name or name in (".", "..") or "\0" in name \
            or any(sep and sep in name for sep in (os.sep, os.altsep, "/", "\\")):
        return None
    if path is None:
        path = os.environ.get("PATH", os.defpath)
    names = [name]
    if WINDOWS:
        if os.path.splitext(name)[1].lower() not in STARTABLE:
            asked = [e.strip().lower() for e in os.environ.get("PATHEXT", "").split(os.pathsep)]
            names = [name + e for e in ([e for e in asked if e in STARTABLE] or STARTABLE)]
    for folder in path.split(os.pathsep):
        folder = _full(folder)
        if folder is None:
            continue
        for n in names:
            full = os.path.join(folder, n)
            if os.path.isfile(full) and (WINDOWS or os.access(full, os.X_OK)):
                return full
    return None


def python(module: str, *args: str) -> list[str]:
    """The command line that runs a Python module as a program, in this Python, without the current folder on its
    path."""
    return [sys.executable, "-P", "-m", module, *args]


def env(base: dict | None = None) -> dict:
    """The environment for a helper Lantern starts: `base` (the person's own when None) with the relative entries
    of PATH and PYTHONPATH left out. A new dictionary; `base` is not changed."""
    out = dict(os.environ if base is None else base)
    for key in list(out):
        if (key.upper() if WINDOWS else key) not in SEARCHED:
            continue
        kept = [f for f in (_full(x) for x in str(out[key]).split(os.pathsep)) if f]
        if kept:
            out[key] = os.pathsep.join(kept)
        elif key.upper() == "PATH" and not WINDOWS:
            out[key] = "/usr/bin:/bin"    # an empty PATH is read as the current folder
        elif key.upper() == "PATH":
            out[key] = ""
        else:
            del out[key]
    if WINDOWS:
        out[SWITCH] = "1"
    return out


@contextlib.contextmanager
def settings(name: str, text: str):
    """A settings file of Lantern's own, for the time a tool runs: `text` under `name` in a new temp folder (only
    this user can read it), handed over as its path and gone afterwards. A tool that is told where its settings are
    looks for none in the folder it scans. OSError when the file cannot be written: the caller then does not start
    the tool. A folder that cannot be cleared away afterwards is left where it is, without a word (Windows may hold
    a file a moment longer than its writer)."""
    with tempfile.TemporaryDirectory(prefix="lantern-settings-", ignore_cleanup_errors=True) as own:
        path = Path(own) / name
        path.write_text(text, encoding="utf-8")
        yield path


@contextlib.contextmanager
def folder():
    """A folder of Lantern's own, for the time a tool runs: new and empty, in the temp folder, for this user only,
    and gone afterwards with what was put in it. A tool that takes settings from the folder it is started in is
    started here, on copies of the files it is to read, so it finds no settings file of a project. OSError when the
    folder cannot be made: the caller then does not start the tool. A folder that cannot be cleared away
    afterwards is left where it is, without a word."""
    with tempfile.TemporaryDirectory(prefix="lantern-own-", ignore_cleanup_errors=True) as own:
        yield Path(own)


def put(folder: Path, name: str, text: str) -> Path:
    """A file of Lantern's own in a folder of Lantern's own (`folder()`): `text` under the bare name `name`, handed
    back as its path. For what a tool is told to read in place of a project's file: its settings, a list, a sample
    it is asked about. Every line ends the same way on every system, so the tool is handed the same bytes.
    ValueError for a name that is not a bare name (nothing is written outside the folder); OSError when the file
    cannot be written: the caller then does not start the tool."""
    if not isinstance(name, str) or not name or name in (".", "..") or "\0" in name \
            or any(sep and sep in name for sep in (os.sep, os.altsep, "/", "\\")):
        raise ValueError("not a bare name")
    path = Path(folder) / name
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _one_name(part) -> bool:
    """Is `part` the name of one file or folder on this system: nothing that leads up, down or to another drive?"""
    return isinstance(part, str) and bool(part) and part not in (".", "..") and "\0" not in part \
        and not any(sep and sep in part for sep in (os.sep, os.altsep, "/")) and not (WINDOWS and ":" in part)


def put_copy(folder: Path, parts: list[str], data: bytes) -> Path:
    """A copy of a project's file in a folder of Lantern's own (`folder()`): `data`, byte for byte, under the names
    `parts`, one folder below the other as they are in the project, handed back as its path. For a tool that is
    started on copies of a project's files and not on the project itself. ValueError when `parts` is no list of
    names of one file or folder each (nothing is written outside the folder); OSError when the copy cannot be
    written: the caller then does not start the tool."""
    if not isinstance(parts, (list, tuple)) or not parts or not all(_one_name(part) for part in parts):
        raise ValueError("not a bare name")
    path = Path(folder).joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def link_inside(parts: list[str], target) -> bool:
    """Does a link written at `parts` (its names, one folder below the other, from the top of a folder) with the text
    `target` stay inside that folder, whatever else lies in it? Only a target that first climbs (`../`), no further
    than the folder's top, and then goes down by plain names. A climb after a name is refused: the name may itself
    be a link, and climbing out of the place that leads to is not climbing out of the place it stands in
    (`a/b/up -> ../..` is the top; `a/b/x -> up/../y` then reads the folder above the top). An address from the top
    of the disk, a drive, a backslash and an empty text are refused."""
    if not isinstance(parts, (list, tuple)) or not parts or not all(_one_name(part) for part in parts):
        return False
    if not isinstance(target, str) or not target or "\0" in target or "\\" in target or target.startswith("/"):
        return False
    steps = [step for step in target.split("/") if step not in ("", ".")]
    up = 0
    while up < len(steps) and steps[up] == "..":
        up += 1
    return up <= len(parts) - 1 and all(_one_name(step) for step in steps[up:])


def put_link(folder: Path, parts: list[str], target: str) -> Path:
    """A link of a project, made again in a folder of Lantern's own (`folder()`) beside the copies of its files:
    at `parts`, leading to `target` as the project wrote it. Only a link that stays inside the folder
    (`link_inside`); ValueError for any other, and nothing is made. Where this system lets this user make no link
    (Windows without the right), the target's text is written as a small file, which is what git itself checks
    out there. OSError when neither can be written."""
    if not link_inside(parts, target):
        raise ValueError("not a link that stays inside")
    path = Path(folder).joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, path, target_is_directory=(path.parent / target).is_dir())
    except (NotImplementedError, OSError):
        if os.path.lexists(path):
            raise
        path.write_bytes(target.encode("utf-8", "surrogateescape"))
    return path
