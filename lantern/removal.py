"""Deleting what Lantern itself made, and only that (2026-11-10, stage 7 of the 2026-11-09 directive).

Three things in one place, because each caller used to do them its own way and each way had a hole.

`remove(path)` deletes a file, a link or a folder with everything in it, and answers None when nothing is left or
one sentence saying why not. It never raises for something the system refused, and never looks away from it.
  * A link is removed as a link. Nothing it points at is opened, changed or deleted, at the top or inside.
  * No mode is changed outside `path`. A folder inside it that its owner may not enter or write is given its owner's
    rights back through the folder itself, never through a name another program could swap for a link.
  * Depth does not matter. The walk holds one folder open at a time and finds its way back up through `..`,
    checking each time that it arrived where it came from. (The standard library's `shutil.rmtree` calls itself
    once per level before Python 3.13 and stops with RecursionError at about a thousand levels; from 3.13 on it
    holds one open file per level.) A folder moved elsewhere in the middle ends the removal, and the place it was
    moved to is not touched.
  * Another disk attached inside the folder is not entered.
  * The sentence is Lantern's own: a count and the system's reason, never a name from inside the folder, which may
    be a stranger's repository.

`ours(holder, name, shape, kind)` is asked before a sweep deletes something it did not make in this very call: a
name of the shape Lantern gives, directly in the folder Lantern keeps such things in, a real folder (or plain file)
and not a link, belonging to the user Lantern runs as. Anything else is left alone.

`note` / `retry_noted`: a temp folder of the test sandbox that could not be deleted (on Windows, a file a virus
scanner still holds open is enough) is written down in LANTERN_HOME/leftovers.json and deleted the next time tests
are run, but only while the thing at that place is still the very folder Lantern made there.

Standard library only. Tests: tests/test_removal.py; the cloud service's use of it: tests/test_cloud_cleanup.py.
"""

from __future__ import annotations

import datetime as dt
import errno
import json
import os
import re
import shutil
import stat
import sys
import threading
from pathlib import Path

MAX_FAILED = 1000     # after this many things that could not be removed, the walk stops trying
_LINUX = sys.platform.startswith("linux")
# Every step is taken from a folder held open, by a name inside it: nothing is reached through a path that another
# program could change under us. Windows has no such calls and takes the standard library's way.
_BY_FOLDER = (os.name == "posix" and {os.open, os.unlink, os.rmdir, os.stat} <= os.supports_dir_fd
              and os.scandir in os.supports_fd)
_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_stat_fd = os.fstat   # under a name of its own, so a test can stand in for a disk attached inside a folder
_LINK_TAGS = (0xA000000C, 0xA0000003)   # Windows: a symbolic link, a junction

PLAIN = {errno.EACCES: "no permission", errno.EPERM: "not permitted", errno.EBUSY: "in use",
         errno.EROFS: "the disk is read-only", errno.ENOTEMPTY: "not empty",
         errno.EXDEV: "another disk is attached inside it", errno.EIO: "the disk reported an error",
         errno.EMFILE: "too many open files", errno.ENFILE: "too many open files",
         errno.ENAMETOOLONG: "a name is too long", errno.EINVAL: "not a name Lantern removes"}
WHY = {"name": "its name is not one Lantern gives", "link": "it is a link, not something Lantern made",
       "kind": "it is not the kind of thing Lantern keeps there", "owner": "it belongs to another user",
       "look": "Lantern could not look at it"}


class _Tally:
    """What could not be removed: how many things, and the system's first reason."""

    def __init__(self):
        self.n = 0
        self.first: tuple[str, int | None] | None = None
        self.at_top = False      # the thing itself, not something in it
        self.moved = False

    def add(self, err: BaseException) -> None:
        self.n += 1
        if self.first is None:
            self.first = (type(err).__name__, getattr(err, "errno", None))

    def reason(self) -> str:
        kind, code = self.first or ("OSError", None)
        plain = PLAIN.get(code) or ("its folders are nested too deep" if kind == "RecursionError" else "")
        tech = kind + (f" {code}" if code is not None else "")
        return f"{plain} ({tech})" if plain else tech


def remove(path) -> str | None:
    """Delete the file, link or folder at `path`, with everything in it. None when nothing is left there; otherwise
    why not, in one sentence that names nothing from inside it. Never raises for what the system refused."""
    path = os.fspath(path)
    tally = _Tally()
    try:
        (_by_folder if _BY_FOLDER else _by_path)(path, tally)
    except (OSError, RecursionError) as e:
        tally.add(e)
    if tally.moved:
        return "it was moved while Lantern was removing it; the place it was moved to was not touched"
    if not tally.n:
        return None if not os.path.lexists(path) else "it is still there, and the system gave no reason"
    if tally.at_top and tally.n == 1:
        return f"it could not be removed; the reason: {tally.reason()}"
    return (f"{tally.n:,} thing{'s' if tally.n != 1 else ''} in it could not be removed"
            + ("; Lantern stopped trying there" if tally.n >= MAX_FAILED else "")
            + f"; the first reason: {tally.reason()}")


# ---------------------------------------------------------------------------- POSIX: from folders held open
def _by_folder(path: str, tally: _Tally) -> None:
    head, name = os.path.split(path.rstrip(os.sep) if len(path) > 1 else path)
    if name in ("", ".", ".."):
        tally.add(OSError(errno.EINVAL, "not a name"))
        tally.at_top = True
        return
    try:
        parent = os.open(head or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    except (FileNotFoundError, NotADirectoryError):
        return                                   # no such place: nothing is there
    try:
        try:
            st = os.lstat(name, dir_fd=parent)
        except FileNotFoundError:
            return
        fd = None
        if stat.S_ISDIR(st.st_mode):
            fd, counted = _open_dir(parent, name, tally)
            if fd is None and counted:
                tally.at_top = True
                return
        if fd is None:                           # a file or a link (or no folder any more): removed as what it is
            err = _drop(parent, name)
            if err is not None:
                tally.add(err)
                tally.at_top = True
            return
        _empty(fd, tally)
        if tally.n or tally.moved:
            return
        try:
            os.rmdir(name, dir_fd=parent)
        except FileNotFoundError:
            pass
        except OSError as e:
            tally.add(e)
            tally.at_top = True
    finally:
        os.close(parent)


def _empty(cur: int, tally: _Tally) -> None:
    """Remove everything in the open folder `cur`, which this closes. One folder is held open at a time: going down
    closes the one above, and going back up opens `..` and checks that it is the folder we came down from."""
    st = _stat_fd(cur)
    dev, here = st.st_dev, (st.st_dev, st.st_ino)
    above: list[tuple[tuple[int, int], str, set[str]]] = []   # who each folder above is, the name entered, what stays in it
    stays: set[str] = set()                                   # names in the open folder that could not be removed
    try:
        while True:
            child = _sweep(cur, stays, tally)
            if tally.n >= MAX_FAILED:
                return
            if child is not None:
                fd, counted = _open_dir(cur, child, tally, dev)
                if fd is None:
                    if not counted:              # no folder any more (swapped for a link or a file): removed as what it is
                        err = _drop(cur, child)
                        if err is not None:
                            tally.add(err)
                            counted = True
                    if counted:
                        stays.add(child)
                    continue
                above.append((here, child, stays))
                os.close(cur)
                cur = fd
                st = _stat_fd(cur)
                here, stays = (st.st_dev, st.st_ino), set()
                continue
            if not above:
                return
            up = os.open("..", _DIR, dir_fd=cur)
            st = _stat_fd(up)
            if (st.st_dev, st.st_ino) != above[-1][0]:
                os.close(up)
                tally.moved = True
                return
            left = bool(stays)
            os.close(cur)
            cur = up
            here, name, stays = above.pop()
            if left:                             # it holds something that could not be removed: no failure of its own
                stays.add(name)
                continue
            try:
                os.rmdir(name, dir_fd=cur)
            except FileNotFoundError:
                pass
            except OSError as e:
                tally.add(e)
                stays.add(name)
    except OSError as e:                         # the way back up could not be opened, or a folder could not be read
        tally.add(e)
    finally:
        os.close(cur)


def _sweep(fd: int, stays: set[str], tally: _Tally) -> str | None:
    """Unlink everything in the open folder that is not a folder. Answers the name of a folder in it that is still
    to be emptied, or None when nothing more can be done here. The folder is listed again after anything was
    removed: some file systems leave names out of a listing that is read while its entries are deleted."""
    while True:
        acted = False
        try:
            with os.scandir(fd) as entries:
                for e in entries:
                    name = e.name
                    if name in stays:
                        continue
                    try:
                        folder = e.is_dir(follow_symlinks=False)
                    except OSError:
                        folder = False
                    if folder:
                        return name
                    err = _drop(fd, name)
                    if err is None:
                        acted = True
                        continue
                    if _is_dir(fd, name):        # the listing called it a file, the system says it is a folder
                        return name
                    tally.add(err)
                    stays.add(name)
                    if tally.n >= MAX_FAILED:
                        return None
        except OSError as e:                     # it could not be listed (to the end): what is in it is not known
            tally.add(e)
            stays.add(".")
            return None
        if not acted:
            return None


def _drop(fd: int, name: str) -> OSError | None:
    """Unlink `name` in the open folder. The error when the system refused; None when it is gone (also before)."""
    try:
        os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        return e
    return None


def _is_dir(fd: int, name: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(name, dir_fd=fd).st_mode)
    except OSError:
        return False


def _open_dir(parent: int, name: str, tally: _Tally, dev: int | None = None) -> tuple[int | None, bool]:
    """The folder `name` of the open folder `parent`, opened without following a link, its owner's rights given back
    when they were taken off. (None, False): it is no folder (any more), or gone. (None, True): it could not be
    entered, which is counted."""
    fd = None
    for second in (False, True):
        try:
            fd = os.open(name, _DIR, dir_fd=parent)
            break
        except FileNotFoundError:
            return None, False
        except PermissionError as e:
            if second or not _give_rights(parent, name):
                tally.add(e)
                return None, True
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):    # a link or a file now (FreeBSD says EMLINK)
                return None, False
            tally.add(e)
            return None, True
    try:
        st = _stat_fd(fd)
        if dev is not None and st.st_dev != dev:
            raise OSError(errno.EXDEV, "another file system")
        mode, me = stat.S_IMODE(st.st_mode), os.geteuid()
        if me != 0 and st.st_uid == me and mode & stat.S_IRWXU != stat.S_IRWXU:
            os.fchmod(fd, mode | stat.S_IRWXU)   # the folder itself, held open: nothing else can be meant
    except OSError as e:
        os.close(fd)
        tally.add(e)
        return None, True
    return fd, False


def _give_rights(parent: int, name: str) -> bool:
    """Give the folder `name`, which its owner may not open, its owner's rights back. On Linux through the folder
    itself (opened as a bare reference, looked at, then changed by that reference); elsewhere by its name without
    following a link. Never a link, never a file, never another user's folder."""
    me = os.geteuid()
    try:
        if _LINUX and hasattr(os, "O_PATH"):
            ref = os.open(name, os.O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
            try:
                st = _stat_fd(ref)
                if not stat.S_ISDIR(st.st_mode) or me not in (0, st.st_uid):
                    return False
                os.chmod(f"/proc/self/fd/{ref}", stat.S_IMODE(st.st_mode) | stat.S_IRWXU)
            finally:
                os.close(ref)
            return True
        st = os.lstat(name, dir_fd=parent)
        if not stat.S_ISDIR(st.st_mode) or me not in (0, st.st_uid):
            return False
        os.chmod(name, stat.S_IMODE(st.st_mode) | stat.S_IRWXU, dir_fd=parent, follow_symlinks=False)
        return True
    except (OSError, NotImplementedError):
        return False


# ---------------------------------------------------------------------------- Windows: the standard library's way
def _linkish(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) in _LINK_TAGS


def _is_link(path) -> bool:
    try:
        return _linkish(os.lstat(path))
    except OSError:
        return False


def _by_path(path: str, tally: _Tally) -> None:
    if not os.path.lexists(path):
        return
    if _is_link(path) or not os.path.isdir(path):
        try:
            os.unlink(path)                      # a link or a junction goes as itself; what it points at stays
        except FileNotFoundError:
            pass
        except OSError as e:
            tally.add(e)
            tally.at_top = True
        return

    def again(fn, p, exc):
        err = exc[1] if isinstance(exc, tuple) else exc
        if isinstance(err, FileNotFoundError):
            return
        if fn in (os.unlink, os.remove, os.rmdir) and not _is_link(p):
            if fn is os.rmdir and tally.n:       # it holds something that could not be removed: no failure of its own
                return
            try:                                 # Windows refuses to delete a read-only file: clear that, try once more
                os.chmod(p, stat.S_IMODE(os.lstat(p).st_mode) | stat.S_IWRITE | stat.S_IREAD)
                fn(p)
                return
            except OSError as e:
                err = e
        tally.add(err)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=again)
    else:
        shutil.rmtree(path, onerror=again)


# ---------------------------------------------------------------------------- is it Lantern's to delete?
def ours(holder, name, shape: re.Pattern, kind: str = "folder") -> str | None:
    """Whether the thing called `name` in the folder `holder` is one Lantern may delete. None: yes. Otherwise one
    word (the sentence for each is in WHY): "gone" (nothing is there), "name" (not a single name of the shape
    Lantern gives), "link", "kind" (a file where Lantern keeps folders, or the other way round), "owner" (another
    user's), "look" (the system would not let Lantern look)."""
    if (not isinstance(name, str) or not name or name in (".", "..") or "\x00" in name or os.sep in name
            or (os.altsep and os.altsep in name) or not shape.fullmatch(name)):
        return "name"
    try:
        st = os.lstat(os.path.join(os.fspath(holder), name))
    except (FileNotFoundError, NotADirectoryError):
        return "gone"
    except (OSError, ValueError):
        return "look"
    if _linkish(st):
        return "link"
    if not (stat.S_ISDIR(st.st_mode) if kind == "folder" else stat.S_ISREG(st.st_mode)):
        return "kind"
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        return "owner"
    return None


# ---------------------------------------------------------------------------- the sandbox's temp folder, tried again
NOTES = "leftovers.json"
SANDBOX = re.compile(r"lantern-sandbox-[a-z0-9_]{8}")     # what `tempfile.mkdtemp(prefix="lantern-sandbox-")` names
MAX_NOTES = 200
_notes_lock = threading.Lock()


def home() -> Path:
    return Path(os.environ.get("LANTERN_HOME") or Path.home() / ".lantern")


def _read() -> list[dict]:
    try:
        d = json.loads((home() / NOTES).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = d.get("folders") if isinstance(d, dict) else None
    return [r for r in rows if isinstance(r, dict)][:MAX_NOTES] if isinstance(rows, list) else []


def _write(rows: list[dict]) -> None:
    f = home() / NOTES
    try:
        if not rows:
            f.unlink(missing_ok=True)
            return
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_name(f".{NOTES}.{os.getpid()}.{threading.get_ident()}.tmp")
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as out:
            json.dump({"folders": rows}, out, indent=1)
        os.replace(tmp, f)
    except OSError:
        pass          # the note is a convenience; the folder was already named in the run's log


def noted() -> list[dict]:
    """The temp folders written down as still to be deleted: [{path, dev, ino, noted, why, tried}]."""
    return _read()


def note(path, why: str | None = None) -> None:
    """Write down a temp folder of the sandbox that could not be deleted, with which folder it is (the disk's own
    number for it), so that the next run deletes that folder and no other."""
    p = os.path.abspath(os.fspath(path))
    try:
        st = os.lstat(p)
    except OSError:
        return
    if not SANDBOX.fullmatch(os.path.basename(p)) or not stat.S_ISDIR(st.st_mode) or _linkish(st):
        return
    with _notes_lock:
        rows = [r for r in _read() if r.get("path") != p]
        rows.append({"path": p, "dev": st.st_dev, "ino": st.st_ino, "noted": dt.datetime.now(dt.UTC).isoformat(),
                     "why": (why or "")[:300], "tried": 0})
        _write(rows[-MAX_NOTES:])


def _still_the_folder(r: dict) -> bool | None:
    """Whether the thing at the noted place is the folder Lantern made there. None: nothing is there any more."""
    p = r.get("path")
    if (not isinstance(p, str) or not os.path.isabs(p) or os.path.normpath(p) != p
            or not SANDBOX.fullmatch(os.path.basename(p))):
        return False
    try:
        st = os.lstat(p)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (OSError, ValueError):
        return False
    if not stat.S_ISDIR(st.st_mode) or _linkish(st) or (st.st_dev, st.st_ino) != (r.get("dev"), r.get("ino")):
        return False
    if hasattr(os, "geteuid"):      # as root the sandbox hands its folder to `nobody`, who runs the tests
        me = os.geteuid()
        if st.st_uid != me and not (me == 0 and st.st_uid == 65534):
            return False
    return True


def retry_noted() -> dict:
    """Try again to delete every noted folder. {"removed": how many are gone now, "waiting": the paths still there,
    "dropped": notes thrown away because the thing at that place is not the folder that was noted}."""
    out: dict = {"removed": 0, "waiting": [], "dropped": 0}
    if not os.path.lexists(home() / NOTES):
        return out
    with _notes_lock:
        keep = []
        for r in _read():
            same = _still_the_folder(r)
            if same is None:
                continue
            if not same:
                out["dropped"] += 1
                continue
            why = remove(r["path"])
            if why is None:
                out["removed"] += 1
                continue
            tried = r.get("tried")
            keep.append({**r, "tried": (tried if isinstance(tried, int) else 0) + 1, "why": why[:300]})
            out["waiting"].append(r["path"])
        _write(keep)
    return out
