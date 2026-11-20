"""The switcher: the one part of the website's service that stays root (website stage, step 3, 2026-11-20).

The owner's answer of 2026-11-20: the website's image may start as root, so that each check's steps run as a user of
that check's own (`apart.py`), "then narrow root to a small part". From 2026-11-18 until this change the whole
service ran as root: its web pages, its database, the clones it makes and the results it reads back from the steps.
A hole in any of that was a hole as root. Now the image starts this program as root; it starts the service as an
ordinary user of its own (`app`, `LANTERN_CLOUD_SERVICE_USER`), stays beside it, and does four things as root, each
only when the service asks for it over the socket that the service alone holds (`Client`):

* `take`: a user of its own for a check, a number of `_jail.STEP_USERS` that no other check has and under which
  nothing runs;
* `step`: one step of that check, as its user. The check's temporary folder and its copy of the code, with all that
  is in them, are handed to that user first (`hand_over`), so a step finds what the steps before it wrote (the
  dependency audit's file, the unpacked upload) as where the service is root (`apart.hand_over`, which hands over
  less because a step's files stay its user's there). The step is started by a small program of Lantern's own
  (`HELPER`), as root, with an empty environment: it makes the step's network of its own where the step reads no
  network, becomes the check's user for good (no other group, no way back, no new privileges), and only then starts
  the launcher (`lantern/_jail.py`) with the step's command and environment, so nothing the service hands over is
  read or run as root. When the service asks, or when it goes, the step is stopped with everything it started
  (`lantern.sandbox._Run.stop`, what the service did itself where it was root), whatever still runs as the check's
  user is ended (`_jail.end_user`), and the folders are handed back (`hand_back`), so the service reads what the
  step wrote;
* `give_back`: the check is over: whatever still runs as its user is ended, its folders are the service's again,
  and the user is free for another check;
* when it starts: what is on the service's own disk (`LANTERN_CLOUD_DATA`) and belongs to root, to `nobody` or to a
  check's user becomes the service's user's (`take_over`): what the service made while it ran as root, and what a
  step left when the machine stopped.

Whatever it changes, it first holds by a descriptor of its own and sees owned by the user it expects (`_hand`): a
check's folder of the service's before a step, one of the check's user's after it. It never follows a link (a link's
own owner changes, never what it names), never changes a file with a second name (it may be a name of a file of
somebody else's), never goes onto another disk, and never takes a name twice. So a service or a step that was taken
over can make it change nothing of root's and nothing of any other user's, however it moves names about meanwhile.

The launcher of a step now runs as the check's user from its first instruction (where the service was root it ran
as root and handed only the command to that user). Where nothing of the kernel's keeps a step from signalling its
own launcher, which is its user's, the step could end it: what the step started is then ended all the same, by the
session and by the user (`_Run.stop`, `_jail.end_user`), after every step.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
from pathlib import Path

from lantern import _jail

FD_VARIABLE = "LANTERN_CLOUD_SWITCHER_FD"     # the service's end of the socket (set by the switcher alone)
USER_VARIABLE = "LANTERN_CLOUD_SERVICE_USER"  # the user the service runs as: a name of this system, or a number
DATA_VARIABLE = "LANTERN_CLOUD_DATA"          # the one folder the service keeps everything in (its disk)
CHECK = re.compile(r"(?:run|explain)-[a-z0-9_]{8}")   # a check's folder: `Cleanup.fresh` (tempfile's names)
MOST_MESSAGE = 1 << 20      # bytes of one request or answer
MOST_TEXT = 256 << 10       # bytes of a step's command, and of its environment
MOST_DEPTH = 1000           # folders inside folders that a hand-over or hand-back follows (deeper ones are counted)
MOST_ASK = 30.0             # seconds a step's launcher may be given to end what it started
OPS = ("hello", "take", "step", "give_back")
LOST = "lost+found"         # at the top of a disk: the file system's own, never handed over

_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_PIN = getattr(os, "O_PATH", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_AT_EMPTY_PATH, _AT_SYMLINK_NOFOLLOW = 0x1000, 0x100
_SET_ID = stat.S_ISUID | stat.S_ISGID
_PR_SET_PDEATHSIG = 1

# The launcher, started by the helper once it is the check's user (as `Worker._jailed` starts it where the service
# is root); `{pkg}` is the folder Lantern's own package is in.
LAUNCHER = "import sys; sys.path.insert(0, {pkg!r}); from lantern._jail import main; main(sys.argv[1:])"

# The helper: started by the switcher as root with an empty environment and no argument but the number of a file
# the switcher wrote (`_start`), whose contents it trusts: the check's user, the folder, whether to make a network
# of the step's own, and the command and environment of the step. Makes the network as root, becomes the user, then
# starts the command. Says what it could not do the way the launcher says it (`_jail.MARK`, `_jail.UNAVAILABLE`).
HELPER = r"""
import json, os, sys
fd = int(sys.argv[1])
parts = []
while True:
    b = os.read(fd, 1 << 16)
    if not b:
        break
    parts.append(b)
os.close(fd)
spec = json.loads(b"".join(parts))
def say(text):
    os.write(1, (text + "\n").encode("utf-8", "replace"))
def refuse(word):
    say(%(mark)r + " " + word)
    os._exit(%(unavailable)d)
if spec["own_net"]:
    sys.path.insert(0, spec["pkg"])
    from lantern import _jail
    if _jail._own_network(False) == 0:
        say("sandbox: a network of its own, which nothing outside can be reached from")
    else:
        say("sandbox: a network of its own could not be made")
uid = spec["uid"]
try:
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
except OSError:
    refuse("user")
if os.getresuid() != (uid, uid, uid) or os.getresgid() != (uid, uid, uid) or os.getgroups():
    refuse("user")
say("sandbox: a user of its own for this check, who may read only this check's files")
import ctypes
if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
    refuse("no-new-privileges")
try:
    os.chdir(spec["cwd"])
    os.execve(spec["argv"][0], spec["argv"], spec["env"])
except OSError as e:
    say("sandbox: the step could not be started (%%s)" %% (e.strerror or e.errno))
    os._exit(127)
""" % {"mark": _jail.MARK, "unavailable": _jail.UNAVAILABLE}


class Refused(RuntimeError):
    """The switcher will not do what it was asked: `str()` says why, in Lantern's own words."""


class SwitcherGone(RuntimeError):
    """The switcher did not answer: nothing more can be started or stopped as a check's user."""


# ---------------------------------------------------------------------------- holding a thing before changing it
_libc = None


def _fchownat(fd: int, uid: int, gid: int) -> None:
    """Change the owner of what `fd` holds (opened with O_PATH: also a link itself, never what it names)."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.fchownat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
    if _libc.fchownat(fd, b"", uid, gid, _AT_EMPTY_PATH | _AT_SYMLINK_NOFOLLOW) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


class Users:
    """Which owners a hand-over takes, or looks into: some numbers, and some ranges of numbers."""

    def __init__(self, *ids: int, ranges: tuple = ()):
        self.ids, self.ranges = frozenset(ids), tuple(ranges)

    def __contains__(self, uid) -> bool:
        return uid in self.ids or any(uid in r for r in self.ranges)

    def plus(self, *ids: int) -> Users:
        return Users(*self.ids, *ids, ranges=self.ranges)


FORMER = Users(0, _jail.NOBODY, ranges=(_jail.STEP_USERS,))   # what `take_over` gives the service


def _pin(dir_fd: int, name: str):
    """Hold `name` in the folder `dir_fd` without following a link: (descriptor, is a folder), or None when nothing
    is there. A folder is opened to be read; anything else is only held (O_PATH), never opened, so a pipe or a
    device is not woken. Raises OSError for anything else."""
    try:
        return os.open(name, _DIR, dir_fd=dir_fd), True
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno not in (errno.ENOTDIR, errno.ELOOP):
            raise
    try:
        return os.open(name, _PIN, dir_fd=dir_fd), False
    except FileNotFoundError:
        return None


def _change(fd: int, st: os.stat_result, is_dir: bool, to: int, gid: int, mode: int | None, fix: bool) -> bool:
    """Give what `fd` holds (`st`: what it was seen as) to `to`. A folder and a plain file of one name change owner
    (`mode`: the mode it gets; `fix`: its new owner may read, write, and pass through it); a set-user-ID or
    set-group-ID bit never stays; a link's own owner changes; anything else (a file with a second name, a pipe, a
    socket, a device) is left as it is. True when it was changed."""
    try:
        if is_dir:
            os.fchown(fd, to, gid)
            was = stat.S_IMODE(st.st_mode)
            want = mode if mode is not None else (was | 0o700 if fix else was)
            if want != was:
                os.fchmod(fd, want)
            return True
        if stat.S_ISREG(st.st_mode):
            if st.st_nlink != 1:
                return False
            _fchownat(fd, to, gid)
            was = stat.S_IMODE(st.st_mode)
            want = (mode if mode is not None else was) & ~_SET_ID
            if fix:
                want |= 0o600
            if want != was or was & _SET_ID:
                os.chmod(f"/proc/self/fd/{fd}", want)   # the very file held, not a name: O_PATH has no fchmod
            return True
        if stat.S_ISLNK(st.st_mode):
            _fchownat(fd, to, gid)
            return True
    except OSError:
        return False
    return False


def _names(fd: int) -> list[str] | None:
    try:
        return os.listdir(fd)
    except OSError:
        return None


def _hand(dir_fd: int, name: str, frm: Users, enter: Users, to: int, gid: int, mode: int | None = None,
          fix: bool = False, tree: bool = True, dev: int | None = None) -> int:
    """`name` in the folder `dir_fd`, and with `tree` everything beneath it: what is owned by one of `frm` becomes
    `to`'s (`_change`; `mode` only for `name` itself), and folders owned by one of `frm` or `enter` are looked into.
    Nothing on another disk than `dev` (the disk of `name` when None). Returns how many things could not be handed
    (deeper than `MOST_DEPTH`, or refused by the system)."""
    try:
        got = _pin(dir_fd, name)
    except OSError:
        return 1
    if got is None:
        return 0
    fd, is_dir = got
    try:
        st = os.fstat(fd)
        if dev is not None and st.st_dev != dev:
            return 0
        kept = 0
        if st.st_uid in frm and not _change(fd, st, is_dir, to, gid, mode, fix) and (is_dir or stat.S_ISREG(st.st_mode)):
            kept += 1
        if is_dir and tree and (st.st_uid in frm or st.st_uid in enter):
            kept += _beneath(fd, st.st_dev, frm, enter, to, gid, fix)
        return kept
    finally:
        os.close(fd)


def _beneath(top: int, dev: int, frm: Users, enter: Users, to: int, gid: int, fix: bool) -> int:
    """Everything beneath the folder `top` (held, not changed here), one folder held at a time for each level."""
    first = _names(top)
    if first is None:
        return 1
    kept, stack = 0, [(top, first, False)]
    try:
        while stack:
            dfd, names, own = stack[-1]
            if not names:
                stack.pop()
                if own:
                    os.close(dfd)
                continue
            name = names.pop()
            try:
                got = _pin(dfd, name)
            except OSError:
                kept += 1
                continue
            if got is None:
                continue
            fd, is_dir = got
            keep = False
            try:
                st = os.fstat(fd)
                if st.st_dev != dev:
                    continue
                if st.st_uid in frm and not _change(fd, st, is_dir, to, gid, None, fix) \
                        and (is_dir or stat.S_ISREG(st.st_mode)):
                    kept += 1
                if is_dir and (st.st_uid in frm or st.st_uid in enter):
                    below = _names(fd) if len(stack) < MOST_DEPTH else None
                    if below is None:
                        kept += 1
                        continue
                    stack.append((fd, below, True))
                    keep = True
            except OSError:
                kept += 1
            finally:
                if not keep:
                    os.close(fd)
    finally:
        for dfd, _names_left, own in stack:
            if own:
                os.close(dfd)
    return kept


def hand_over(check: int, uid: int, app: int) -> int:
    """Before a step of a check (`check`: its folder, held): the folder stays the service's and others may only pass
    through it; its temp folder and the check's copy of the code (`src`), each owner only, and everything in them
    that is the service's become `uid`'s: what the service made for the step, and what the steps before it wrote,
    which `hand_back` gave the service after each of them. Returns how many things could not be handed over."""
    os.fchmod(check, 0o711)    # nosec B103 - a folder: the check's user passes through it to its own, and lists nothing
    service, inside = Users(app), Users(app, uid)
    return (_hand(check, "tmp", service, inside, uid, uid, mode=0o700)
            + _hand(check, "src", service, inside, uid, uid, mode=0o700))


def hand_back(check: int, uid: int, app: int, gid: int) -> int:
    """After a step (`check`: its folder, held): everything in it that is `uid`'s becomes the service's again, which
    may then read it, write it and remove it. Returns how many things could not be handed back."""
    names = _names(check)
    if names is None:
        return 1
    return sum(_hand(check, name, Users(uid), Users(app), app, gid, fix=True) for name in names)


# ---------------------------------------------------------------------------- the service's own disk
def service_user(word: str) -> tuple[int, int, str, str | None]:
    """(user number, group number, name, home folder) of the user the service runs as: a name of this system, or a
    number (its group the same number). Never root, `nobody`, a check's user or root's group."""
    if word.isdigit():
        uid, gid, name, home = int(word), int(word), word, None
    else:
        import pwd
        try:
            pw = pwd.getpwnam(word)
        except KeyError:
            raise Refused(f"there is no user {word!r} on this system to run the service as") from None
        uid, gid, name, home = pw.pw_uid, pw.pw_gid, pw.pw_name, pw.pw_dir
    if uid in (0, _jail.NOBODY) or uid in _jail.STEP_USERS or gid == 0:
        raise Refused("the service must run as an ordinary user of its own: not root, not nobody, not a check's user")
    return uid, gid, name, home


def open_data(path: str, app: int) -> tuple[int, bool]:
    """The service's own folder, held: (descriptor, it is a disk of its own). It must be named by its full path, be
    a folder (not a link to one), and be the service's user's own, or root's where a disk is mounted there (the top
    folder of a disk mounted for an image that starts as root may be root's). Anything else is refused: the switcher
    gives what it finds in there to the service's user."""
    if not path or not os.path.isabs(path):
        raise Refused(f"{DATA_VARIABLE} must name the service's own folder by its full path")
    path = os.path.normpath(path)
    if path == os.path.sep:
        raise Refused(f"{DATA_VARIABLE} must name a folder of the service's own, not the top of the system")
    try:
        fd = os.open(path, _DIR)
    except OSError:
        raise Refused(f"{DATA_VARIABLE} is not a folder (a link is not followed)") from None
    try:
        st = os.fstat(fd)
        mounted = st.st_dev != os.stat("..", dir_fd=fd, follow_symlinks=False).st_dev
        if st.st_uid == app or (st.st_uid == 0 and mounted):
            return fd, mounted
    except OSError:
        pass
    os.close(fd)
    raise Refused(f"{DATA_VARIABLE} is neither the service user's own folder nor a disk mounted there for it")


def places(data: str) -> str:
    """Where the service keeps its database, results, uploads, work and Lantern's own folder, each inside `data`
    (they are what the switcher gives the service's user, and where each check's folder is). Returns the work
    folder."""
    from .settings import Settings
    s = Settings()
    named = {"LANTERN_CLOUD_DB": s.db_path, "LANTERN_CLOUD_RESULTS": s.results_dir, "LANTERN_CLOUD_WORK": s.work_dir,
             "LANTERN_CLOUD_UPLOADS": s.uploads(), "LANTERN_HOME": os.environ.get("LANTERN_HOME", "")}
    data = os.path.normpath(data)
    for name, place in named.items():
        if not place:
            raise Refused(f"{name} must be set, to a place in {DATA_VARIABLE}")
        full = os.path.normpath(os.path.abspath(place))
        if full == data or os.path.commonpath([data, full]) != data:
            raise Refused(f"{name} must be a place in {DATA_VARIABLE}")
    return os.path.normpath(os.path.abspath(s.work_dir))


def take_over(data: int, app: int, gid: int, mounted: bool) -> int:
    """When the switcher starts, before the service: what is on the service's disk (`data`, held) and is root's,
    `nobody`'s or a check's user's becomes the service's user's (and it may read, write and remove it): the files
    the service made while it ran as root (2026-11-18 to 2026-11-20), and what a step left when the machine stopped.
    Nothing on another disk, nothing a link names, no file with a second name. Returns how many things could not
    be taken over."""
    st = os.fstat(data)
    try:
        if st.st_uid in FORMER:
            kept = 0 if _change(data, st, True, app, gid, 0o711, False) else 1
        else:
            kept = 0
            if stat.S_IMODE(st.st_mode) != 0o711:
                os.fchmod(data, 0o711)    # nosec B103 - a folder: each check's user passes through it, lists nothing
    except OSError:
        kept = 1
    names = _names(data)
    if names is None:
        return kept + 1
    for name in names:
        if mounted and name == LOST:
            continue
        kept += _hand(data, name, FORMER, Users(app), app, gid, fix=True, dev=st.st_dev)
    return kept


def _may_change(st: os.stat_result, app: int, gid: int, above: bool = False) -> bool:
    """Whether the service's user may change what `st` describes (not a link: see `_above`), or what is in it: it is
    that user's, or its group's with the group's write bit, or anyone may write it. `above`: a folder on the way to
    what is looked at, where the sticky bit (as on /tmp) lets nobody rename or remove another's entry."""
    if st.st_uid == app:
        return True
    writable = (st.st_mode & stat.S_IWGRP and st.st_gid == gid) or st.st_mode & stat.S_IWOTH
    if writable and above and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
        return False
    return bool(writable)


MOST_LINKS = 40             # links followed one after the other before a place is taken as one that could change


def _nearest(path: Path) -> Path:
    """`path`, or the nearest folder above it that is there: whoever may write that folder could make what is missing
    (a sticky folder too, which keeps others from removing an entry, not from making one)."""
    while not os.path.lexists(path) and path.parent != path:
        path = path.parent
    return path


def _above(path: Path, app: int, gid: int, links: int = 0) -> str | None:
    """`path` and every folder above it: the first the service's user may change, or None. A link's own mode means
    nothing (it is replaced by whoever may write its folder, the next one looked at), so where a link is on the way,
    where it leads is looked at too, and the folders above that."""
    for p in [path, *path.parents]:
        try:
            st = os.lstat(p)
        except OSError:
            return str(p)
        if stat.S_ISLNK(st.st_mode):
            if links >= MOST_LINKS:
                return str(p)
            bad = _above(_nearest(Path(os.path.realpath(p))), app, gid, links + 1)
            if bad:
                return bad
            continue
        if _may_change(st, app, gid, above=p != path):
            return str(p)
    return None


def _within(top: Path, app: int, gid: int, more: list) -> str | None:
    """Every folder and file beneath `top`: the first the service's user may change, or None. A link is not walked
    through: where it leads is looked at like a place of its own (`_above`), and a folder it leads to is added to
    `more`, to be walked once."""
    for here, folders, files in os.walk(top, followlinks=False):
        for name in [*folders, *files]:
            full = os.path.join(here, name)
            try:
                st = os.lstat(full)
            except OSError:
                return full
            if stat.S_ISLNK(st.st_mode):
                target = Path(os.path.realpath(full))
                bad = _above(_nearest(target), app, gid)
                if bad:
                    return bad
                if target.is_dir():
                    more.append(target)
            elif _may_change(st, app, gid):
                return full
    return None


def _code_places() -> list[Path]:
    """Every folder Python looks for code in (`sys.path`: its own library, the libraries installed beside it, whose
    `.pth` files it reads and runs when it starts, and wherever Lantern's two packages are), each named once and
    none inside another."""
    found = []
    for entry in [*sys.path, os.path.dirname(os.path.dirname(_jail.__file__)), os.path.dirname(os.path.dirname(__file__))]:
        try:
            p = Path(entry or os.curdir).resolve()
            if p.exists():
                found.append(p)
        except (OSError, RuntimeError, ValueError):
            continue
    kept: list[Path] = []
    for p in sorted(set(found), key=lambda p: len(p.parts)):
        if not any(p == k or k in p.parents for k in kept):
            kept.append(p)
    return kept


def _venv_settings() -> list[str]:
    """Where Python looks for a virtual environment's settings before anything else (`pyvenv.cfg` beside the program
    it was started as, or one folder up): that file names the library Python then loads, so whoever may change one,
    or make one where there is none, chooses what root runs at the switcher's next start."""
    program = Path(os.path.abspath(sys.executable))
    return [str(program.parent / "pyvenv.cfg"), str(program.parent.parent / "pyvenv.cfg")]


def unchangeable(app: int, gid: int, places: list[Path] | None = None) -> str | None:
    """None when the service's user can change nothing the switcher runs as root: every folder Python looks for code
    in (`_code_places`; `places` in their stead, for a test), each folder and file in them, every folder above each of
    them, where each link in them leads (and, for a folder, all that is in it), the file of every module the switcher
    loaded so far, the program it runs as (the name it was started by and where that leads) and the two places of a
    virtual environment's settings file (`_venv_settings`; where there is none, the folder it would be in). Else the
    first place that user could change: the switcher then does not start, as root would run what the service may
    write."""
    todo, walked = (_code_places() if places is None else [Path(os.path.abspath(x)) for x in places]), set()
    while todo:
        top = todo.pop()
        if top in walked or any(w in top.parents for w in walked):
            continue
        walked.add(top)
        bad = _above(top, app, gid) or (_within(top, app, gid, todo) if top.is_dir() else None)
        if bad:
            return bad
    if places is not None:
        return None
    files = [getattr(m, "__file__", None) for m in list(sys.modules.values())]
    for f in dict.fromkeys([*files, sys.executable]):
        if isinstance(f, str) and f and os.path.lexists(f):   # a module of a zip file: the file is one of the places
            bad = _above(Path(os.path.abspath(f)), app, gid)
            if bad:
                return bad
    for f in _venv_settings():      # there or not: whoever may make one there chooses the library as well
        bad = _above(_nearest(Path(f)), app, gid)
        if bad:
            return bad
    return None


def _open_files() -> None:
    """As many open files as the system lets this program have: a hand-over holds one folder for each level."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard == resource.RLIM_INFINITY or soft < hard:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard if hard != resource.RLIM_INFINITY else 1 << 20, hard))
    except (ImportError, ValueError, OSError):
        pass


# ---------------------------------------------------------------------------- what the service asks for
def read_request(data: bytes) -> dict:
    """A request, taken by its shape alone: one of `OPS`, a check's folder name, and for a step its command (words),
    its environment (names and words) and whether it reads the network. Anything else is refused."""
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("the request is not JSON") from None
    if not isinstance(msg, dict) or msg.get("op") not in OPS:
        raise Refused("the switcher does not know that request")
    op = msg["op"]
    if op == "hello":
        return {"op": op}
    check = msg.get("check")
    if not isinstance(check, str) or not CHECK.fullmatch(check):
        raise Refused("that is not the name of a check's folder")
    if op != "step":
        return {"op": op, "check": check}
    argv, env, net = msg.get("argv"), msg.get("env"), msg.get("net")
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) and "\0" not in a for a in argv)):
        raise Refused("a step's command must be a list of words")
    if not (isinstance(env, dict) and all(isinstance(k, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k)
                                          and isinstance(v, str) and "\0" not in v for k, v in env.items())):
        raise Refused("a step's environment must be names and words")
    if sum(len(a) for a in argv) > MOST_TEXT or sum(len(k) + len(v) for k, v in env.items()) > MOST_TEXT:
        raise Refused("a step's command or environment is too long")
    if type(net) is not bool:
        raise Refused("a step must say whether it reads the network")
    return {"op": op, "check": check, "argv": argv, "env": env, "net": net}


def _send(conn: socket.socket, msg: dict) -> None:
    conn.send(json.dumps(msg).encode("utf-8"))


def _is_socket(fd: int) -> bool:
    try:
        st = os.fstat(fd)
        if not stat.S_ISSOCK(st.st_mode):
            return False
        with socket.socket(fileno=os.dup(fd)) as s:
            return s.family == socket.AF_UNIX and s.type == socket.SOCK_SEQPACKET
    except OSError:
        return False


def _is_pipe_to_write(fd: int) -> bool:
    try:
        import fcntl
        return stat.S_ISFIFO(os.fstat(fd).st_mode) and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY
    except OSError:
        return False


class Switcher:
    """What the switcher keeps while the service runs: the users it gave, the steps under way, what it started."""

    def __init__(self, sock: socket.socket, data: int, data_path: str, work: str, app: int, gid: int):
        self.sock, self.data, self.app, self.gid = sock, data, app, gid
        self.work = work
        self.work_parts = Path(work).relative_to(os.path.normpath(data_path)).parts
        self.pkg = str(Path(_jail.__file__).resolve().parent.parent)
        self.lock = threading.Lock()
        self.spawn = threading.Lock()          # held while a process is made and written down (`reap`)
        self.users: dict[str, int] = {}        # check -> its user
        self.busy: set[str] = set()            # checks with a step, or a hand-back, under way
        self.known: set[int] = set()           # processes this program started that are not collected yet
        self.closing = threading.Event()
        self.threads: set[threading.Thread] = set()
        self._at = secrets.randbelow(len(_jail.STEP_USERS))

    # ------------------------------------------------------------ requests
    def listen(self) -> None:
        """Each request in a thread of its own, until the service closes its end."""
        while not self.closing.is_set():
            try:
                data, fds, flags, _ = socket.recv_fds(self.sock, MOST_MESSAGE, 4)
            except OSError:
                return
            if not data and not fds:
                return
            if flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)):
                for fd in fds:
                    os.close(fd)
                continue
            t = threading.Thread(target=self._serve, args=(data, fds), name="lantern-switcher", daemon=True)
            with self.lock:
                self.threads.add(t)
            t.start()

    def _serve(self, data: bytes, fds: list[int]) -> None:
        reply = None
        try:
            if not fds or not _is_socket(fds[0]):
                return
            reply = socket.socket(fileno=fds[0])
            fds = fds[1:]
            try:
                msg = read_request(data)
                op = msg["op"]
                if op == "hello":
                    _send(reply, {"switcher": os.getpid(), "user": self.app})
                elif op == "take":
                    _send(reply, {"uid": self.take(msg["check"])})
                elif op == "give_back":
                    _send(reply, self.give_back(msg["check"]))
                else:
                    if len(fds) != 1 or not _is_pipe_to_write(fds[0]):
                        raise Refused("a step's output must be a pipe the step writes to")
                    self.step(msg, reply, fds.pop())
            except Refused as e:
                _send(reply, {"error": str(e)})
            except Exception as e:  # noqa: BLE001 - said to the service, which ends the check
                print(f"lantern-cloud switcher: a request failed ({type(e).__name__})", file=sys.stderr, flush=True)
                _send(reply, {"error": f"the switcher could not do this ({type(e).__name__})"})
        except OSError:
            pass
        finally:
            for fd in fds:
                os.close(fd)
            if reply is not None:
                reply.close()
            with self.lock:
                self.threads.discard(threading.current_thread())

    def _open_check(self, name: str) -> int:
        """The check's folder in the work folder, held, each folder on the way the service's own."""
        fd = os.dup(self.data)
        try:
            for part in (*self.work_parts, name):
                try:
                    nxt = os.open(part, _DIR, dir_fd=fd)
                except OSError:
                    raise Refused("there is no such check folder") from None
                os.close(fd)
                fd = nxt
                if os.fstat(fd).st_uid != self.app:
                    raise Refused("that check's folder is not the service's")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def take(self, name: str) -> int:
        os.close(self._open_check(name))
        with self.lock:
            if name in self.users:
                return self.users[name]
            busy = set(self.users.values())
            for _ in range(len(_jail.STEP_USERS)):
                uid = _jail.STEP_USERS[self._at]
                self._at = (self._at + 1) % len(_jail.STEP_USERS)
                if uid not in busy and not _jail.processes_of(uid):
                    self.users[name] = uid
                    return uid
        raise Refused("no user is free for this check")

    def _claim(self, name: str) -> int:
        with self.lock:
            uid = self.users.get(name)
            if uid is None:
                raise Refused("that check was given no user")
            if name in self.busy:
                raise Refused("a step of that check is under way")
            self.busy.add(name)
            return uid

    def give_back(self, name: str) -> dict:
        with self.lock:
            if name not in self.users:
                return {"left": 0, "kept": 0}
        uid = self._claim(name)
        try:
            left = _jail.end_user(uid)
            kept = self._hand_back(name, uid)
        finally:
            with self.lock:
                self.busy.discard(name)
                self.users.pop(name, None)
        return {"left": left, "kept": kept}

    def _hand_back(self, name: str, uid: int) -> int:
        try:
            check = self._open_check(name)
        except Refused:
            return 0                            # the service removed it
        try:
            return hand_back(check, uid, self.app, self.gid)
        finally:
            os.close(check)

    # ------------------------------------------------------------ one step
    def step(self, msg: dict, reply: socket.socket, out: int) -> None:
        """One step of a check, from the hand-over to the hand-back. `out`, the pipe the step writes to, is this
        call's to close: as soon as the step holds its own, so the service's reader sees the end of the output with
        the end of the step."""
        name = msg["check"]
        try:
            uid = self._claim(name)
        except BaseException:
            os.close(out)
            raise
        p = None
        try:
            try:
                check = self._open_check(name)
                try:
                    kept = hand_over(check, uid, self.app)
                finally:
                    os.close(check)
                p = self._start(uid, name, msg["argv"], msg["env"], msg["net"], out)
            finally:
                os.close(out)
            try:
                _send(reply, {"pid": p.pid, "kept": kept})
            except OSError:
                pass                           # the service went: `_watch` sees it, and stops the step
            self._watch(p, reply, uid, name)
        finally:
            if p is None:                      # nothing started: what was handed over goes back now
                self._hand_back(name, uid)
            with self.lock:
                self.busy.discard(name)

    def _start(self, uid: int, name: str, argv: list[str], env: dict, net: bool, out: int) -> subprocess.Popen:
        tmp = os.path.join(self.work, name, "tmp")
        policy = {"writable": [tmp], "python": True, "net": not net, "parent": os.getpid()}
        launcher = [sys.executable, "-I", "-c", LAUNCHER.format(pkg=self.pkg), json.dumps(policy), "--", *argv]
        spec = json.dumps({"uid": uid, "own_net": not net, "pkg": self.pkg, "cwd": tmp, "argv": launcher, "env": env})
        held = os.memfd_create("lantern-step", getattr(os, "MFD_CLOEXEC", 1))
        try:
            view = memoryview(spec.encode("utf-8"))
            while view:
                view = view[os.write(held, view):]
            os.lseek(held, 0, os.SEEK_SET)
            with self.spawn:
                p = subprocess.Popen([sys.executable, "-I", "-S", "-c", HELPER, str(held)], stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=subprocess.STDOUT, pass_fds=(held,), close_fds=True,
                                     start_new_session=True, env={}, cwd="/")
                self.known.add(p.pid)
        finally:
            os.close(held)
        return p

    def _watch(self, p: subprocess.Popen, reply: socket.socket, uid: int, name: str) -> None:
        """Until the service asks for the step to stop (or goes): say when it ended by itself. Then stop it with
        everything it started, end what still runs as the check's user, hand the folders back, and say how it went."""
        from lantern import sandbox
        run = sandbox._Run(p, None, _jail.ASK, None)
        ended, ask = False, _jail.ASK
        try:
            held = os.pidfd_open(p.pid)
        except (AttributeError, OSError):
            held = None
        try:
            while not self.closing.is_set():
                if not ended and run.ended():
                    ended = True
                    try:
                        _send(reply, {"ended": True})
                    except OSError:
                        break
                watch = [reply] + ([held] if held is not None and not ended else [])
                ready, _, _ = select.select(watch, [], [], 1.0 if held is not None or ended else 0.05)
                if reply in ready:
                    try:
                        data = reply.recv(MOST_MESSAGE)
                    except OSError:
                        data = b""
                    if not data:
                        break                   # the service is gone: the step goes too
                    try:
                        m = json.loads(data.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError):
                        break
                    if isinstance(m, dict) and m.get("do") == "stop":
                        a = m.get("ask")
                        ask = min(float(a), MOST_ASK) if type(a) in (int, float) and a >= 0 else _jail.ASK
                        break
        finally:
            if held is not None:
                os.close(held)
        run.ask = ask
        said = list(run.stop())
        left = list(run.left)
        n = _jail.end_user(uid)
        if n:
            words = f"{n} process(es) of this check's user could not be ended"
            said.append(words)
            left.append(words)
        with self.spawn:
            self.known.discard(p.pid)
        kept = self._hand_back(name, uid)
        try:
            _send(reply, {"over": True, "rc": p.returncode, "said": said, "left": left, "kept": kept})
        except OSError:
            pass

    # ------------------------------------------------------------ the end
    def reap(self) -> None:
        """As the first process of its machine (a container started without an init of its own): collect the
        programs whose parents went before them and were handed to it, never one this program waits for itself."""
        me = os.getpid()
        with self.spawn:
            try:
                table = _jail._all()
            except OSError:
                return
            for pid, (state, parent, _session) in table.items():
                if state == b"Z" and parent == me and pid not in self.known:
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass

    def close(self, wait: float = 60.0) -> None:
        """The service has gone: every step is stopped (each in its own thread, as above), and whatever still runs
        as a check's user is ended."""
        import time
        self.closing.set()
        end = time.monotonic() + wait
        with self.lock:
            threads = list(self.threads)
        for t in threads:
            t.join(max(0.0, end - time.monotonic()))
        with self.lock:
            uids = list(self.users.values())
        for uid in uids:
            _jail.end_user(uid)


def _say(text: str) -> None:
    print(f"lantern-cloud switcher: {text}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    """`python -I -m lantern_cloud.switcher -- <the service's command>`, as root. Returns the service's own result
    (128 + the signal's number when a signal ended it)."""
    argv = sys.argv[1:] if argv is None else list(argv)
    cmd = argv[argv.index("--") + 1:] if "--" in argv else []
    if not cmd:
        _say("usage: python -I -m lantern_cloud.switcher -- <the command that starts the service>")
        return 2
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        _say("it starts the service as a user of its own and each check's steps as theirs, which only root can do "
             "on Linux; to run the service as yourself, start its command directly")
        return 2
    try:
        uid, gid, name, _home = service_user(os.environ.get(USER_VARIABLE, "app"))
        bad = unchangeable(uid, gid)
        if bad:
            raise Refused(f"the service's user could change {bad}, which the switcher runs as root")
        data_path = os.environ.get(DATA_VARIABLE, "")
        data, mounted = open_data(data_path, uid)
        work = places(data_path)
    except Refused as e:
        _say(f"not started: {e}")
        return 2
    _open_files()
    kept = take_over(data, uid, gid, mounted)
    if kept:
        _say(f"{kept} thing(s) on the service's disk could not be given to its user")
    mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    env = dict(os.environ)
    # The service's home is its own folder: the image's /home/app stays root's, and others pass through it only.
    env.update({FD_VARIABLE: str(theirs.fileno()), "USER": name, "LOGNAME": name, "HOME": os.path.normpath(data_path)})
    holder: dict = {}
    early: list[int] = []

    def forward(signum, _frame):
        p = holder.get("service")
        if p is None:
            early.append(signum)
            return
        try:
            os.kill(p.pid, signum)
        except ProcessLookupError:
            pass
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, forward)
    service = subprocess.Popen(cmd, env=env, pass_fds=(theirs.fileno(),), user=uid, group=gid, extra_groups=[],
                               close_fds=True)
    holder["service"] = service
    theirs.close()
    sw = Switcher(mine, data, data_path, work, uid, gid)
    sw.known.add(service.pid)
    for sig in early:
        forward(sig, None)
    threading.Thread(target=sw.listen, name="lantern-switcher-listen", daemon=True).start()
    _say(f"the service runs as user {uid}; each check's steps run as a user of that check's own")
    while True:
        try:
            rc = service.wait(timeout=1.0)
            break
        except subprocess.TimeoutExpired:
            if os.getpid() == 1:
                sw.reap()
    sw.close()
    return 128 - rc if rc < 0 else rc


# ---------------------------------------------------------------------------- the service's side
class Remote:
    """One step the switcher runs, as `lantern.sandbox._stream` sees a process (`_Run` asks `remote`): its lines,
    whether it ended, and the one way to stop it (`stop`), which the switcher does, where the step's user can be
    signalled. `returncode` is known once it was stopped."""

    remote = True

    def __init__(self, conn: socket.socket, out: int, pid: int):
        self.conn, self.pid, self.returncode = conn, pid, None
        self.stdout = open(out, "r", encoding="utf-8", errors="replace")   # noqa: SIM115 - closed by its reader
        self._ended = False

    def ended(self) -> bool:
        if not self._ended:
            try:
                data = self.conn.recv(MOST_MESSAGE, socket.MSG_DONTWAIT)
            except (BlockingIOError, InterruptedError):
                return False
            except OSError:
                data = b""
            if not data or _answer(data).get("ended"):
                self._ended = True          # ended, or the switcher went (and `stop` says so)
        return self._ended

    def stop(self, ask: float) -> tuple[list[str], list[str]]:
        """Ask the switcher to stop the step with everything it started; (what there is to say, of it what could not
        be ended). Where the switcher does not answer, that is said, as something that could not be ended."""
        m = None
        try:
            _send(self.conn, {"do": "stop", "ask": ask})
            self.conn.settimeout(ask + 120)
            while m is None:
                data = self.conn.recv(MOST_MESSAGE)
                if not data:
                    break
                got = _answer(data)
                if got.get("over"):
                    m = got
        except OSError:
            pass
        finally:
            self.conn.close()
        if m is None:
            words = "the switcher did not answer when this step was to be stopped, so what it started may still run"
            return [words], [words]
        rc = m.get("rc")
        self.returncode = rc if type(rc) is int else None
        said = [str(x)[:300] for x in (m.get("said") or []) if isinstance(x, str)]
        left = [str(x)[:300] for x in (m.get("left") or []) if isinstance(x, str)]
        kept = m.get("kept")
        if type(kept) is int and kept > 0:
            said.append(f"{kept} thing(s) the step left could not be handed back to the service")
        return said, left

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


def _answer(data: bytes) -> dict:
    try:
        m = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return m if isinstance(m, dict) else {}


class Client:
    """The service's end: the socket the switcher gave it (`FD_VARIABLE`). Each request goes with a socket of its own
    for the answer (and, for a step, for the step's life), so requests from several threads never mix."""

    def __init__(self, fd: int):
        try:
            sock = socket.socket(fileno=fd)
        except OSError:
            raise SwitcherGone("the switcher's socket is not there") from None
        if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_SEQPACKET:
            sock.detach()
            raise SwitcherGone("what the service was given is not the switcher's socket")
        sock.set_inheritable(False)
        self.sock = sock
        _ended_with_the_switcher()
        hello = self._ask({"op": "hello"}, timeout=30.0)
        self.pid = int(hello.get("switcher") or 0)

    def _ask(self, msg: dict, fds: tuple = (), timeout: float = 60.0, keep: bool = False):
        mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            try:
                socket.send_fds(self.sock, [json.dumps(msg).encode("utf-8")], [theirs.fileno(), *fds])
            finally:
                theirs.close()
            mine.settimeout(timeout)
            data = mine.recv(MOST_MESSAGE)
        except OSError:
            mine.close()
            raise SwitcherGone("the switcher did not answer") from None
        if not data:
            mine.close()
            raise SwitcherGone("the switcher went")
        reply = _answer(data)
        if "error" in reply:
            mine.close()
            raise Refused(str(reply["error"])[:300])
        if keep:
            return reply, mine
        mine.close()
        return reply

    def take(self, check: str) -> int:
        uid = self._ask({"op": "take", "check": check}).get("uid")
        if type(uid) is not int or uid not in _jail.STEP_USERS:
            raise Refused("the switcher gave no user of the ones kept for checks")
        return uid

    def give_back(self, check: str) -> int:
        left = self._ask({"op": "give_back", "check": check}, timeout=300.0).get("left")
        return left if type(left) is int else 0

    def step(self, check: str, argv: list[str], env: dict, net: bool) -> Remote:
        r, w = os.pipe()
        try:
            reply, conn = self._ask({"op": "step", "check": check, "argv": argv, "env": env, "net": bool(net)},
                                    fds=(w,), timeout=600.0, keep=True)
        except BaseException:
            os.close(r)
            raise
        finally:
            os.close(w)
        return Remote(conn, r, int(reply.get("pid") or 0))


def _ended_with_the_switcher() -> None:
    """The service ends when the switcher does (Linux): asked by the kernel, as the launcher of a step is."""
    if sys.platform.startswith("linux"):
        try:
            ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_PDEATHSIG, int(signal.SIGTERM), 0, 0, 0)
        except (OSError, AttributeError):
            pass


_client: Client | None = None
_client_lock = threading.Lock()


def connect() -> Client | None:
    """The switcher this service was started by (one for the life of the program), or None when it was not."""
    global _client
    with _client_lock:
        if _client is None:
            word = os.environ.pop(FD_VARIABLE, None)
            if word is None:
                return None
            try:
                fd = int(word)
            except ValueError:
                raise SwitcherGone("the switcher's socket is not named by a number") from None
            _client = Client(fd)
        return _client


def connected() -> bool:
    """A switcher started this service (it may not have been asked anything yet)."""
    return _client is not None or FD_VARIABLE in os.environ


if __name__ == "__main__":
    sys.exit(main())
