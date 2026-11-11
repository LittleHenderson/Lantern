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
folder it scans (Bandit and a project's `.bandit`).

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
