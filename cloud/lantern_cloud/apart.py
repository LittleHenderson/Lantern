"""Each check of a project runs as a user of its own (website stage, step 2, 2026-11-18).

A check is done in restricted steps (`lantern/_jail.py`) that read the project and never run it: unpacking an
upload, the dependency audit, the analysis, the explanations. The walls of a step keep it from writing outside its
own folder and from the network; what it may read is what its user may read. Until this change every step ran as one
user (root's `nobody`, or, where the service is not root, the service's own user), so a step that was taken over
could read what other checks held while they ran, and, as the service's own user, the service's files.

Here, where the service is root:
* `StepUsers` gives each check a user of its own, a number of `_jail.STEP_USERS` that nobody else on the machine
  has, and not one that another check has while the service runs; the launcher runs each step of the check as that
  user (policy key `user`), and when the check is over whatever still runs as that user is ended (`_jail.end_user`).
* `hand_over`, before each step: the check's temp folder, what the service made in it for the step and the check's
  copy of the code become the check's user's, and no other user may enter them. Only what is the service's is
  handed over, and nothing a link names: a step that was taken over may leave links for the next one.
* `close_up`, when the service starts: its database and journal files, its results, its uploads and Lantern's own
  folder are closed to others, and what the service's former user made in them (the website's image ran the service
  as an ordinary user until this change) becomes the service's own, so its clean-up may remove it.
* `PROOF`, before the first step of each check (and when the service starts, where checks must be kept apart): a
  step of the check's user tries to read the service's database, results, uploads and Lantern's own folder, list
  the work folder, and read the service's environment and open files. The check goes on only where every one of
  them was refused or is not there. With `LANTERN_CLOUD_STEPS_APART=required` (the website's image) a service that
  cannot keep checks apart starts none, and says so to the person (`NOT_APART`) before anything of the check is
  copied. A proof that does not answer (it was not started, was stopped, or ended before it was done) proves nothing
  either way: that check is not started either (`UNPROVEN`), and nothing is said of the service.

Where the service is not root (a person's own computer), steps run as the service's own user, as before; the health
page says "shared".
"""

from __future__ import annotations

import os
import secrets
import stat
import threading
from pathlib import Path

from lantern import _jail

NOT_APART = ("Lantern's server cannot keep checks apart from each other right now, so it starts none. Nothing of "
             "your project was copied or read. Please try again later.")
UNPROVEN = ("Lantern's server could not finish making sure that this check is kept apart from the others, so it did "
            "not start it. Nothing of your project was copied or read. Please try again.")
APART = "· This check runs as a user of its own, who cannot read Lantern's own files or anyone else's check"
OPEN = ("· This check's user could read what is Lantern's own ({}), so the check was stopped before "
        "anything of it was copied")
UNANSWERED = ("· The step that makes sure this check is kept apart from the others did not finish, so the check was "
              "stopped before anything of it was copied")
WORDS = ("apart", "unchecked", "shared", "open")    # the health page's `steps`
MADE_FOR_A_STEP = ("home", "out", "src", "upload.zip")   # what the service makes in a check's temp folder for a step


def as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


class StepUsers:
    """The users each check's steps run as: one per check (`key`: the check's folder). `on` is False where the
    service is not root; `take` then gives None and the steps run as the service's own user. Numbers are taken in
    turn from a place chosen at random when the service starts, so a number comes round again only after 500,000
    checks, and never while a program of that user still runs."""

    def __init__(self, on: bool | None = None, first: int | None = None):
        self.on = as_root() if on is None else bool(on)
        count = len(_jail.STEP_USERS)
        self._at = (secrets.randbelow(count) if first is None else first) % count
        self._lock = threading.Lock()
        self._given: dict[str, int] = {}

    def take(self, key) -> int | None:
        if not self.on:
            return None
        k = os.fspath(key)
        with self._lock:
            busy = set(self._given.values())
            for _ in range(len(_jail.STEP_USERS)):
                uid = _jail.STEP_USERS[self._at]
                self._at = (self._at + 1) % len(_jail.STEP_USERS)
                if uid not in busy and not _jail.processes_of(uid):
                    self._given[k] = uid
                    return uid
        raise RuntimeError("no user is free for this check")

    def of(self, key) -> int | None:
        with self._lock:
            return self._given.get(os.fspath(key))

    def give_back(self, key) -> int:
        """The check is over: end whatever still runs as its user. Returns how many could not be ended."""
        k = os.fspath(key)
        with self._lock:
            uid = self._given.get(k)
        if uid is None:
            return 0
        left = _jail.end_user(uid)
        with self._lock:
            self._given.pop(k, None)
        return left


# ---------------------------------------------------------------------------- a check's folders
def hand_over(root: Path, uid: int) -> None:
    """Before a step of a check: the check's folder `root` stays the service's, and others may only pass through it;
    its temp folder (owner only), what the service made in it for the step (`MADE_FOR_A_STEP`) and the check's copy
    of the code (`root/src`, owner only) become `uid`'s. No step runs while this is done, and what is the service's
    can be changed by the service alone, so nothing here is moved under it."""
    os.chmod(root, 0o711)   # nosec B103 - a folder: the check's user passes through it to its own, and lists nothing
    _give(root / "tmp", uid, tree=False, mode=0o700)
    for name in MADE_FOR_A_STEP:
        _give(root / "tmp" / name, uid)
    _give(root / "src", uid, mode=0o700)


def _give(path: Path, uid: int, tree: bool = True, mode: int | None = None) -> None:
    """`path`, and with `tree` everything beneath it that is the service's, becomes `uid`'s. A link is never
    followed (its own owner changes), a folder that is not the service's is not looked into (a step made it, or
    somebody else), and a file with a second name keeps its owner (it may be a name of another file of the
    service's: a step can give one where the system allows it)."""
    me = os.geteuid()
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if st.st_uid != me or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
        return
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        return
    if stat.S_ISDIR(st.st_mode) and tree:
        todo = [os.fspath(path)]
        while todo:
            with os.scandir(todo.pop()) as entries:
                for e in entries:
                    try:
                        s = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if s.st_uid != me:
                        continue
                    if stat.S_ISDIR(s.st_mode):
                        todo.append(e.path)
                    elif not (stat.S_ISLNK(s.st_mode) or (stat.S_ISREG(s.st_mode) and s.st_nlink == 1)):
                        continue
                    os.chown(e.path, uid, uid, follow_symlinks=False)
    os.chown(path, uid, uid, follow_symlinks=False)
    if mode is not None:
        os.chmod(path, mode)    # a folder of the service's, looked at above without following a link


# ---------------------------------------------------------------------------- the service's own files
def close_up(db: str, results: str, uploads: str, work: str, home: str | None) -> None:
    """When the service starts. As root: what the user who owns the database made (the service's former user) in
    the service's own places becomes root's (the place, and each entry at its top: the clean-up asks only there),
    and the uploads and Lantern's own folder are made where they are missing. Then, whoever the service is: the
    database and its journal files are owner only, and so are the results, the uploads and Lantern's own folder.
    The work folder is the worker's (`Worker.__init__`: others may pass through it, not list it)."""
    files = [db + x for x in ("", "-wal", "-shm", "-journal")]
    folders = [f for f in (results, uploads, home) if f]
    me = os.geteuid()
    if as_root():
        former = _former(db)
        if former is not None:
            for f in files:
                _take_over(f, former)
            for d in [*folders, work]:
                _take_over(d, former)
                for e in _entries(d):
                    _take_over(e, former)
        for d in folders:
            if not os.path.lexists(d):
                os.makedirs(d, mode=0o700, exist_ok=True)
    for f in files:
        _close(f, 0o600, me, stat.S_ISREG)
    for d in folders:
        _close(d, 0o700, me, stat.S_ISDIR)


def _former(db: str) -> int | None:
    try:
        st = os.lstat(db)
    except OSError:
        return None
    return st.st_uid if stat.S_ISREG(st.st_mode) and st.st_uid != os.geteuid() else None


def _take_over(path: str, former: int) -> None:
    try:
        if os.lstat(path).st_uid == former:
            os.chown(path, 0, 0, follow_symlinks=False)
    except OSError:
        pass


def _entries(folder: str) -> list[str]:
    try:
        if not stat.S_ISDIR(os.lstat(folder).st_mode):
            return []
        with os.scandir(folder) as it:
            return [e.path for e in it]
    except OSError:
        return []


def _close(path: str, mode: int, me: int, kind) -> None:
    try:
        st = os.lstat(path)
        if kind(st.st_mode) and st.st_uid == me and st.st_mode & 0o777 != mode:
            os.chmod(path, mode)
    except OSError:
        pass


# ---------------------------------------------------------------------------- the proof
# What the proof step runs. Its lines on stdout are its answer, read by `what_was_read`: whom it runs as, and for each
# place it is asked about whether it could do what it was asked to there.
PROOF = r"""
import os, sys
print("LANTERN-STEP-USER", os.getuid(), os.geteuid(), file=sys.stdout, flush=True)
a = sys.argv[1:]
for i in range(0, len(a) - 2, 3):
    kind, path, how = a[i:i + 3]
    try:
        if how == "file":
            with open(path, "rb") as f:
                f.read(1)
        elif how == "list":
            os.listdir(path)
        else:
            os.stat(path)
            try:
                os.stat(os.path.join(path, ".lantern-nothing-of-that-name"))
            except FileNotFoundError:
                pass
        said = "read"
    except FileNotFoundError:
        said = "absent"
    except OSError:
        said = "refused"
    print("LANTERN-STEP-CHECK", kind, how, said, file=sys.stdout, flush=True)
"""


def probes(db: str, results: str, uploads: str, work: str, home: str | None, pid: int) -> list[str]:
    """What a step of a check tries to read, three words each: what it is, the place, and how (`file`: read it,
    `list`: list it, `enter`: pass through it to a name inside)."""
    out = []
    for x in ("", "-wal", "-shm", "-journal"):
        out += ["database", db + x, "file"]
    for kind, place in (("results", results), ("uploads", uploads), *((("lantern-folder", home),) if home else ())):
        out += [kind, place, "list", kind, place, "enter"]
    out += ["work-folder", work, "list", "service", f"/proc/{pid}/environ", "file", "service", f"/proc/{pid}/fd", "list"]
    return out


def what_was_read(output: str, uid: int, asked: int) -> list[str] | None:
    """From the proof's output: what the step could read (empty: nothing), with `user` when it said it ran as
    another user than `uid` and `no-answer` beside either when it did not answer for every place it was asked about.
    None when it proved nothing either way: it read nothing it said, said it ran as `uid` or did not say whom it ran
    as, and did not answer for every place (it was not started, was stopped, or ended before it was done)."""
    user, read, answered = None, set(), 0
    for line in output.splitlines():
        words = line.split()
        if words[:1] == ["LANTERN-STEP-USER"] and len(words) == 3:
            user = words[1:]
        elif words[:1] == ["LANTERN-STEP-CHECK"] and len(words) == 4:
            answered += 1
            if words[3] not in ("refused", "absent"):
                read.add(words[1])
    if user is not None and user != [str(uid), str(uid)]:
        read.add("user")
    if read:
        return sorted(read | ({"no-answer"} if answered != asked else set()))
    if user is None or answered != asked:
        return None
    return []
