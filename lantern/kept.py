"""Work kept between runs (directive point 10, 2026-11-12).

Reading one file of a project (parsing it, walking its tree, writing down its functions, calls and imports) gives the
same answer every time the file holds the same bytes, and until 2026-11-12 every run did it again for every file: a
second run of an unchanged project took as long as the first. The same holds for a scanner started on a set of files
that has not changed. `kept` keeps such answers on this computer, in `LANTERN_HOME/cache`, and hands one back when
the question is exactly the same.

What makes that safe:

* **The key is the whole question.** An answer is stored under one SHA-256 of everything it was worked out from: the
  bytes of the file, the name it was read under, the kind of work, and a stamp of the code that did the work
  (`Shelf.stamp`: every Python file of this Lantern, the Python that runs it and the parser libraries the reader
  names, by their content). A changed file, a renamed file, another Lantern, another parser: another key, and the
  work is done anew. Nothing is looked up by a file's name, date or size.
* **Never in the project.** The project's folder, its `.lantern/` included, may have come with the project. Nothing
  kept is read from there or written there.
* **Data, never code.** An answer is written as JSON and read back as JSON, into plain values and the few record
  classes its reader named; nothing is run when it is read. An entry that does not read back whole (cut short, of
  another shape, not this user's, a link) is no entry, and the work is done anew.
* **The person's own.** Entries are files of the current user that nobody else may read (they hold names and lines
  of the code).
* **Off with one switch**, `LANTERN_CACHE=off`, and off by itself where the work has to be done again or the place is
  shared: `lantern verify` (`without()`: it exists to do the work again) and the runs of the cloud service
  (`LANTERN_CLOUD_RUN`: one service, many people's code).

What is kept is how a file reads, never what was found in the project as a whole: links between files, findings,
ranks, the score and the release decision are worked out in every run from the files as they are.

`tidy()` keeps the folder bounded (entries not used for `KEEP_DAYS`, then the least recently used over
`LANTERN_CACHE_MB`), `clear()` empties it (`lantern cache --clear`), `size()` says how much is there.
"""
from __future__ import annotations

import contextlib
import contextvars
import hashlib
import importlib
import json
import os
import re
import stat
import sys
import threading
import time
from dataclasses import fields, is_dataclass
from pathlib import Path

OFF_WORDS = frozenset(("off", "0", "no", "false"))
MAX_ENTRY = 64 * 1024 * 1024        # bytes: a larger answer is not kept
KEEP_DAYS = 30                      # an entry nobody asked for in this many days is removed
DEFAULT_MB = 1024                   # what the folder may hold before the least recently used entries go
TIDY_EVERY = 24 * 3600              # seconds between two looks at the whole folder
NOTHING = object()                  # what `Shelf.get` hands back when nothing usable is kept

_KIND = re.compile(r"^[a-z][a-z0-9-]{0,40}$")
_PART = re.compile(r"^[0-9a-f]{2}$")
_ENTRY = re.compile(r"^[0-9a-f]{62}\.json$")
_LEFT = re.compile(r"^\.[0-9a-f]{62}\.[0-9]+\.[0-9]+\.tmp$")
_TAG = "\x01"
_PLAIN = frozenset((str, int, float, bool, type(None)))     # the values that are kept as they are

_WITHOUT: contextvars.ContextVar[bool] = contextvars.ContextVar("lantern_kept_without", default=False)
_TALLY: contextvars.ContextVar["Tally | None"] = contextvars.ContextVar("lantern_kept_tally", default=None)
_LOCK = threading.Lock()
_DIGESTS: dict[str, bytes | None] = {}


def home() -> Path:
    return Path(os.environ.get("LANTERN_HOME") or Path.home() / ".lantern") / "cache"


def on() -> bool:
    """Whether kept work may be used and added to, here and now."""
    if _WITHOUT.get():
        return False
    if (os.environ.get("LANTERN_CACHE") or "").strip().lower() in OFF_WORDS:
        return False
    return not os.environ.get("LANTERN_CLOUD_RUN")


@contextlib.contextmanager
def without():
    """For the time of this block nothing kept is used and nothing is added: the work is done."""
    token = _WITHOUT.set(True)
    try:
        yield
    finally:
        _WITHOUT.reset(token)


# ------------------------------------------------------------------------------------------- how much was reused
class Tally:
    """What one run took from kept work and what it worked out anew, by kind of work."""

    def __init__(self):
        self.reused: dict[str, int] = {}
        self.anew: dict[str, int] = {}
        self._lock = threading.Lock()

    def count(self, kind: str, reused: bool) -> None:
        with self._lock:
            side = self.reused if reused else self.anew
            side[kind] = side.get(kind, 0) + 1

    def table(self) -> dict:
        with self._lock:
            return {kind: {"reused": self.reused.get(kind, 0), "anew": self.anew.get(kind, 0)}
                    for kind in sorted(set(self.reused) | set(self.anew))}

    def said(self) -> str:
        """One line for a run's log, or nothing when no kept work was asked for."""
        rows = self.table()
        if not rows:
            return ""
        return "; ".join(f"{kind}: {n['reused']} from kept work, {n['anew']} anew" for kind, n in rows.items())


def current() -> Tally | None:
    """The count of the run under way in this thread, if one is kept."""
    return _TALLY.get()


@contextlib.contextmanager
def tally():
    """Counts, for the time of this block and the threads handed its context, what was reused and what was not."""
    t = Tally()
    token = _TALLY.set(t)
    try:
        yield t
    finally:
        _TALLY.reset(token)


# ------------------------------------------------------------------------------------------- the stamp of the code
def _digest_of(files: list[Path], root: Path) -> bytes:
    h = hashlib.sha256()
    for p in files:
        h.update(p.relative_to(root).as_posix().encode("utf-8", "surrogatepass"))
        h.update(b"\0")
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.digest()


def _own_code() -> bytes | None:
    """One digest of every Python file of this Lantern and of the Python that runs it; None when they cannot be read
    (then nothing is kept: an answer could not say which code gave it)."""
    with _LOCK:
        if "" not in _DIGESTS:
            try:
                root = Path(__file__).resolve().parent
                files = sorted(p for p in root.rglob("*.py") if p.is_file())
                h = hashlib.sha256(_digest_of(files, root))
                h.update(repr((sys.version, sys.platform, sys.byteorder)).encode("utf-8"))
                _DIGESTS[""] = h.digest()
            except (OSError, ValueError):
                _DIGESTS[""] = None
        return _DIGESTS[""]


def _library(name: str) -> bytes | None:
    """One digest of the files of an installed library: its code and its compiled part, whatever folder of its own
    they lie in."""
    with _LOCK:
        if name not in _DIGESTS:
            try:
                mod = importlib.import_module(name)
                where = Path(mod.__file__).resolve()
                root = where.parent
                files = (sorted(p for p in root.rglob("*") if p.is_file() and p.suffix != ".pyc")
                         if where.name == "__init__.py" else [where])
                _DIGESTS[name] = _digest_of(files, root)
            except (ImportError, OSError, ValueError, AttributeError, TypeError):
                _DIGESTS[name] = None
        return _DIGESTS[name]


# ------------------------------------------------------------------------------------------- one kind of work
class Shelf:
    """One kind of kept work: `Shelf("python-file", classes=(ModuleInfo, ...), libraries=("tree_sitter", ...))`.

    `key(*parts)` → the name of the question (None when nothing may be kept now), `get(key)` → the answer or
    `NOTHING`, `put(key, value)` → whether it was kept. A value is made of None, yes/no, numbers, text, lists,
    tuples, sets, tables and the record classes named here, whose fields are taken one by one in their written
    order. Anything else (a path, a parser's node, a class not named) is not kept: `put` says no and the reader goes
    on as if there were no kept work."""

    def __init__(self, kind: str, classes: tuple[type, ...] = (), libraries: tuple[str, ...] = ()):
        if not _KIND.match(kind):
            raise ValueError("a kind of kept work is named in small letters, digits and dashes")
        for c in classes:
            if not (isinstance(c, type) and is_dataclass(c)):
                raise TypeError("only record classes (dataclasses) can be named for kept work")
        self.kind = kind
        self.libraries = tuple(libraries)
        self._names = {c.__name__: c for c in classes}
        self._fields = {c: tuple(f.name for f in fields(c)) for c in classes}
        if len(self._names) != len(classes):
            raise ValueError("two record classes of one name cannot be told apart in kept work")
        self._stamp: bytes | None | bool = False

    # ---- the question
    def stamp(self) -> bytes | None:
        """The code that does this kind of work, as one digest: this Lantern, the Python that runs it, and the
        libraries the reader named. None when any of them cannot be read."""
        if self._stamp is False:
            parts = [_own_code()] + [_library(name) for name in self.libraries]
            if any(p is None for p in parts):
                self._stamp = None
            else:
                h = hashlib.sha256(self.kind.encode("ascii"))
                for name in sorted(self._names):        # the records' own shape is part of the question
                    h.update(repr((name, self._fields[self._names[name]])).encode("utf-8"))
                for p in parts:
                    h.update(p)
                self._stamp = h.digest()
        return self._stamp

    def key(self, *parts: str | bytes) -> str | None:
        if not on():
            return None
        stamp = self.stamp()
        if stamp is None:
            return None
        h = hashlib.sha256(stamp)
        for part in parts:
            b = part if isinstance(part, (bytes, bytearray)) else str(part).encode("utf-8", "surrogatepass")
            h.update(len(b).to_bytes(8, "big"))     # each part with its length: two lists of parts never read alike
            h.update(b)
        return h.hexdigest()

    def _path(self, key: str) -> Path:
        return home() / self.kind / key[:2] / (key[2:] + ".json")

    # ---- reading
    def get(self, key: str | None):
        if key is None:
            return NOTHING
        value = self._read(key)
        t = _TALLY.get()
        if t is not None:
            t.count(self.kind, value is not NOTHING)
        return value

    def _read(self, key: str):
        try:
            fd = os.open(self._path(key), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_BINARY", 0))
        except (OSError, ValueError):
            return NOTHING
        try:
            with os.fdopen(fd, "rb") as fh:
                st = os.fstat(fh.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_ENTRY or not _mine(st):
                    return NOTHING
                data = fh.read(MAX_ENTRY + 1)
                if time.time() - st.st_mtime > TIDY_EVERY:      # asked for today: `tidy` leaves it
                    with contextlib.suppress(OSError, NotImplementedError, TypeError):
                        os.utime(fh.fileno() if os.utime in os.supports_fd else self._path(key))
            box = json.loads(data)
            if type(box) is not dict or box.get("k") != key or "v" not in box:
                return NOTHING
            return self._dec(box["v"])
        except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
            return NOTHING

    def _dec(self, x):
        # most values are plain (a name, a line number): they are taken as they are without a call for each
        t = type(x)
        if t in _PLAIN:
            return x
        dec = self._dec
        if t is dict:
            return {k: v if type(v) in _PLAIN else dec(v) for k, v in x.items()}
        if t is not list:
            raise ValueError("not a kept value")
        if not x or type(x[0]) is not str or x[0][:1] != _TAG:
            return [i if type(i) in _PLAIN else dec(i) for i in x]
        tag = x[0]
        if tag == "\x01c":
            cls = self._names.get(x[1]) if len(x) > 1 and type(x[1]) is str else None
            names = self._fields.get(cls)
            if names is None or len(x) - 2 != len(names):
                raise ValueError("a record of another shape")
            obj = object.__new__(cls)
            put = object.__setattr__
            for i, name in enumerate(names, 2):
                v = x[i]
                put(obj, name, v if type(v) in _PLAIN else dec(v))
            return obj
        rest = [i if type(i) in _PLAIN else dec(i) for i in x[1:]]
        if tag == "\x01t":
            return tuple(rest)
        if tag == "\x01l":
            return rest
        if tag == "\x01s":
            return set(rest)
        if tag == "\x01f":
            return frozenset(rest)
        if tag == "\x01d":
            return {k: v for k, v in rest}
        raise ValueError("not a kept value")

    # ---- writing
    def _enc(self, x):
        t = type(x)
        if t in _PLAIN:
            return x
        enc = self._enc
        if t is list:
            out = [i if type(i) in _PLAIN else enc(i) for i in x]
            if out and type(out[0]) is str and out[0][:1] == _TAG:
                out.insert(0, "\x01l")
            return out
        if t is dict:
            if all(type(k) is str for k in x):
                return {k: v if type(v) in _PLAIN else enc(v) for k, v in x.items()}
            return ["\x01d", *([enc(k), enc(v)] for k, v in x.items())]
        if t is tuple:
            return ["\x01t", *[i if type(i) in _PLAIN else enc(i) for i in x]]
        if t is set or t is frozenset:
            items = [enc(i) for i in x]
            with contextlib.suppress(TypeError):    # the same set is written the same way every time, where it can be
                items.sort()
            return ["\x01s" if t is set else "\x01f", *items]
        names = self._fields.get(t)
        if names is None:
            raise TypeError(f"{t.__name__} is not kept")
        out = ["\x01c", t.__name__]
        for name in names:
            v = getattr(x, name)
            out.append(v if type(v) in _PLAIN else enc(v))
        return out

    def put(self, key: str | None, value) -> bool:
        if key is None:
            return False
        try:
            data = json.dumps({"k": key, "v": self._enc(value)}, check_circular=False,
                              separators=(",", ":")).encode("ascii")
        except (TypeError, ValueError, RecursionError, AttributeError):
            return False                    # it holds something that is not plain data: not kept
        if len(data) > MAX_ENTRY:
            return False
        path = self._path(key)
        tmp = path.with_name(f".{key[2:]}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            _folders(path.parent)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            # Windows refuses the next line while another writer is putting the same entry there (PermissionError):
            # this answer is then not kept, and the other writer's, which is the same answer, is.
            os.replace(tmp, path)           # whole or not there: a reader never sees half an answer
            return True
        except (OSError, ValueError):
            with contextlib.suppress(OSError, ValueError):
                os.unlink(tmp)
            return False


def _mine(st) -> bool:
    return not hasattr(os, "geteuid") or st.st_uid == os.geteuid()


def _folders(last: Path) -> None:
    """The folders down to `last`, each one closed to other users when it is made here."""
    root = home()
    root.parent.mkdir(parents=True, exist_ok=True)
    for d in (root, last.parent, last):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass


# ------------------------------------------------------------------------------------------- the folder as a whole
def _entries(root: Path | None = None, left: bool = False):
    """(path, stat) of every entry in the folder: `<kind>/<two hex>/<62 hex>.json`, plain files only, no link
    followed, nothing else looked at. With `left`, the unfinished files a stopped write left beside them instead."""
    root = home() if root is None else root
    want = _LEFT if left else _ENTRY
    try:
        kinds = [d for d in os.scandir(root) if _KIND.match(d.name) and d.is_dir(follow_symlinks=False)]
    except OSError:
        return
    for kind in kinds:
        try:
            parts = [d for d in os.scandir(kind.path) if _PART.match(d.name) and d.is_dir(follow_symlinks=False)]
        except OSError:
            continue
        for part in parts:
            try:
                files = list(os.scandir(part.path))
            except OSError:
                continue
            for f in files:
                try:
                    if want.match(f.name) and f.is_file(follow_symlinks=False):
                        yield Path(f.path), f.stat(follow_symlinks=False)
                except OSError:
                    continue


def size() -> tuple[int, int]:
    """(how many entries, how many bytes) are kept now."""
    n = total = 0
    for _, st in _entries():
        n += 1
        total += st.st_size
    return n, total


def _drop(path: Path) -> bool:
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


def clear() -> tuple[int, int]:
    """Removes every entry: (how many were removed, how many could not be)."""
    gone = stayed = 0
    for path, _ in list(_entries()) + list(_entries(left=True)):
        if _drop(path):
            gone += 1
        else:
            stayed += 1
    return gone, stayed


def cap_bytes() -> int:
    said = (os.environ.get("LANTERN_CACHE_MB") or "").strip()
    mb = int(said) if said.isdigit() else DEFAULT_MB
    return max(16, mb) * 1024 * 1024


def tidy(now: float | None = None, force: bool = False) -> int:
    """Keeps the folder bounded; at most once in `TIDY_EVERY` unless `force`. Removes the entries nobody asked for in
    `KEEP_DAYS` days, then the least recently used ones until the folder is under its cap, and the unfinished files
    of writes that were cut off a day ago or more. Returns how many files it removed; never raises."""
    try:
        now = time.time() if now is None else now
        root = home()
        mark = root / ".tidied"
        if not root.is_dir():
            return 0
        if not force:
            try:
                if now - os.lstat(mark).st_mtime < TIDY_EVERY:
                    return 0
            except OSError:
                pass
        with contextlib.suppress(OSError):
            fd = os.open(mark, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
            os.utime(mark, (now, now))
        removed = 0
        kept: list[tuple[float, int, Path]] = []
        for path, st in _entries(root):
            if now - st.st_mtime > KEEP_DAYS * 86400 and _mine(st):
                removed += _drop(path)
            else:
                kept.append((st.st_mtime, st.st_size, path))
        total, cap = sum(s for _, s, _ in kept), cap_bytes()
        if total > cap:
            for _, s, path in sorted(kept):             # the least recently used first, down to four fifths
                if total <= cap * 4 // 5:
                    break
                if _drop(path):
                    removed += 1
                    total -= s
        for path, st in _entries(root, left=True):
            if now - st.st_mtime > TIDY_EVERY:
                removed += _drop(path)
        return removed
    except Exception:   # noqa: BLE001  (tidying up is never a reason for a run to fail)
        return 0
