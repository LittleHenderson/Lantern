"""The project's files, looked up once for a whole run (directive point 10, 2026-11-12).

Until then every reader that wanted "the project's files of this kind" walked the whole folder again: the web rules
once per language, the packs once per rule and per manifest name, the dependency audits once per lock-file name, the
secret patterns once more. On a large project that was dozens of walks of the same tree in one `lantern analyze`,
each asking for every file whether it is a plain file, whether it lies inside the project and whether a folder on
its way is left out.

`files(repo)` gives that answer: every file under `repo` that is a file of the project (`inside_repo`) and not under
a folder Lantern leaves out (`skipped`), as `(path, parts)` with `parts` counted from the project's root, in the
order `repo.rglob("*")` gives them, which is the order the readers had before. Inside `one_run(repo)` the folder is
walked once and the list is kept until the run ends; outside a run nothing is kept and every call walks, as before,
so a caller that changes the project between two calls (a test, the app between two checks) sees the change.

What is kept is which files there are, never what they hold: every reader still opens a file through
`python_frontend.project_text`, which asks `inside_repo` again at that moment. `fresh(repo)` drops what a run kept,
for the one step of a run after which the folder may hold other files: the project's own tests, run in its folder.

`once(repo, what, make)` is the same promise for a reader that lists the folder its own way (the dependency audits:
every name that answers, read or not, `depaudit._names`): inside a run `make()` is called once for `what`, outside
one every time. Two threads that ask the same thing at once get one walk; a thread that asks something else is not
held up by it (the audits run beside the reading of the code).
"""
from __future__ import annotations

import contextlib
import os
import threading
from pathlib import Path

_LOCK = threading.Lock()
_RUNS: dict[str, "_Run"] = {}    # the folder of a run under way -> what was listed for it


class _Run:
    def __init__(self):
        self.going = 0                      # how many runs of this folder are under way
        self.kept: dict = {}
        self.lock = threading.Lock()        # held only to look something up, never while a folder is walked
        self.making: dict = {}              # what is being listed now -> the lock its askers wait on
        self.round = 0                      # counted up by `fresh`: a walk begun before it is not kept after it

    def once(self, key, make):
        while True:
            with self.lock:
                if key in self.kept:
                    return self.kept[key]
                mine = key not in self.making
                gate = self.making.setdefault(key, threading.Lock())
                began = self.round
                if mine:
                    gate.acquire()
            if not mine:
                with gate:                  # somebody is walking for this very question: wait, then look again
                    continue
            try:
                value = make()
            finally:
                with self.lock:
                    self.making.pop(key, None)
                gate.release()
            with self.lock:
                if self.round == began:     # else the folder may have changed while it was walked: handed on, not kept
                    self.kept.setdefault(key, value)
                    return self.kept[key]
            return value


def _where(repo) -> str:
    return os.path.abspath(os.fspath(repo))


@contextlib.contextmanager
def one_run(repo):
    """For the time of one analysis of `repo`: its folder is walked once. Runs of the same folder that overlap (the
    app's threads) share the list and it is dropped when the last of them ends."""
    keys = {_where(repo), os.path.realpath(os.fspath(repo))}    # as it was written, and where that leads
    with _LOCK:
        run = next((_RUNS[k] for k in keys if k in _RUNS), None) or _Run()
        for k in keys:
            _RUNS.setdefault(k, run)
        run.going += 1
    try:
        yield
    finally:
        with _LOCK:
            run.going -= 1
            if run.going <= 0:
                for k in [k for k, r in _RUNS.items() if r is run]:
                    del _RUNS[k]


def fresh(repo) -> None:
    """Forget what the run under way listed for `repo`: its files may have changed."""
    with _LOCK:
        run = _RUNS.get(_where(repo))
    if run:
        with run.lock:
            run.kept.clear()
            run.round += 1


def going(repo) -> bool:
    """Whether a run of `repo` is under way (what is listed for it is kept)."""
    with _LOCK:
        return _where(repo) in _RUNS


def _walk(repo: Path) -> list[tuple[Path, tuple[str, ...]]]:
    from .python_frontend import inside_repo, skipped
    out = []
    for p in repo.rglob("*"):
        parts = p.relative_to(repo).parts
        # the same three questions as before, the one that needs no look at the disk first
        if skipped(parts[:-1], repo) or not p.is_file() or not inside_repo(p, repo):
            continue
        out.append((p, parts))
    return out


def files(repo: Path) -> list[tuple[Path, tuple[str, ...]]]:
    """Every file of the project `repo` that is not under a folder Lantern leaves out, as `(path, parts)`, in the
    order `repo.rglob("*")` gives them. Walked once per run inside `one_run(repo)`; the list is the caller's to read,
    not to change."""
    repo = Path(repo)
    with _LOCK:
        run = _RUNS.get(_where(repo))
    if run is None:
        return _walk(repo)
    return run.once(("files", os.fspath(repo)), lambda: _walk(repo))    # by the spelling asked with: the paths begin with it


def once(repo, what: str, make):
    """`make()`, called once for `what` in a run of `repo` and every time outside one. What it gives is the
    caller's to read, not to change."""
    with _LOCK:
        run = _RUNS.get(_where(repo))
    if run is None:
        return make()
    return run.once((what, os.fspath(repo)), make)
