"""The results folder (`PATH/.lantern`, or `--out`): reading back what an earlier run left there (2026-11-10,
directive stage 7).

`lantern analyze` reads three files an earlier run of the same folder wrote: `security.json` (which findings were
there before), `baseline.json` (the first analysis, for "fixed since") and `explanations.json` (a model's words, for
the report). A run can do without each of them, so none of them may stop it. Until this date one that was cut off
(the computer was switched off while it was written), empty, not text, or of another shape ended every later
`lantern analyze` of that folder with a Python error, until someone deleted the file by hand.

`earlier(out, name)` gives the file's table, or nothing and the reason in one sentence made of fixed words (never
text from the file). Only a plain file is read: not a link (the folder lies inside the analysed project by default,
so what is in it may have come with the project), not a folder, a pipe or a device (a pipe would hold the run up for
good), and not one larger than `MAX_BYTES`. `SHAPES` says, per file, what the parts this run uses must look like. A
file with one odd part is passed over whole: a result file is Lantern's own, so an odd part means it is not what
Lantern wrote, and the rest of it is no better known.

Reading changes and removes nothing. The results a command is about (`lantern evidence`, `explain`, `verify` on a
finished run) are still read strictly (`pipeline.load`): passing those over would turn a damaged scan result into
"no findings".

Writing (the same date). The results folder lies inside the analysed project by default, and a project comes from
anywhere: a link somebody sent, a zip, a clone. Until this date every result file was written with a plain
`write_text`, which follows a link and waits on a pipe: a project that brought `.lantern/security.json` as a link to
a file of the person's own had that file overwritten with Lantern's results, one that brought `.lantern` itself as a
link had Lantern's files made wherever it pointed, and a pipe under a result file's name held the run up for good.

`write(path, text)` is the one way a result file is written: the text goes into a new file beside its place and is
moved there in one step. A link at that place is replaced by Lantern's own file and what it pointed at is left
alone; a pipe or a device there is replaced the same way; a folder there is refused (`Refused`). The file is whole
or as it was: a write that stops half-way leaves the file of the run before. What was met is kept for the run to
say (`said`). `folder(repo, out)` gives the results folder and makes it when it is missing; one that is a link
inside the project, or is reached through one, is refused in words for the person, before anything is analysed. A
link outside the project is the person's own (results kept on another disk) and is followed. `ready` refuses a
folder under the name of a file a run is about to write, before the run starts. `inner` is for a folder Lantern
keeps inside the results folder (the cache of explanations).

Limits. A link put in place between the look and the write is not seen by `folder` (that takes another program of
this computer writing in the project at that very moment); `write` itself never opens the name it replaces.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import threading
import time
from pathlib import Path

from . import removal

MAX_BYTES = 256 * 1024 * 1024       # the largest real result file seen is a few MB
NOT_OURS = "it does not hold what Lantern writes there"
CUT_OFF = "it is not complete JSON (a run that was cut off while it wrote the file leaves it so)"


def plain(p: Path) -> tuple[str | None, str | None]:
    """(text, None) for the plain file at `p`, (None, None) when nothing is there, else (None, why). Never follows
    a link and never waits on a pipe."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as exc:
        return None, f"it could not be looked at ({type(exc).__name__})"
    if stat.S_ISLNK(st.st_mode):
        return None, "it is a link, and Lantern does not read its results through a link"
    if not stat.S_ISREG(st.st_mode):
        return None, "it is not a plain file"
    if st.st_size > MAX_BYTES:
        return None, f"it is larger than {MAX_BYTES // (1024 * 1024)} MB"
    # The name is opened once and the open file is asked again what it is, so a link or a pipe put there since the
    # look above is not read either (O_NONBLOCK: opening a pipe nobody writes to would otherwise never come back).
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None, "it is not a plain file"
            data = fh.read(MAX_BYTES + 1)
    except (OSError, ValueError) as exc:
        return None, f"it could not be read ({type(exc).__name__})"
    if len(data) > MAX_BYTES:
        return None, f"it is larger than {MAX_BYTES // (1024 * 1024)} MB"
    try:
        return data.decode("utf-8").removeprefix("\ufeff"), None
    except UnicodeDecodeError:
        return None, "it is not text"


def _number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _text_or_nothing(x) -> bool:
    return x is None or isinstance(x, str)


def scan_shape(d: dict) -> str | None:
    """`security.json` of the run before: this run takes the ids of its findings and nothing else."""
    fs = d.get("findings")
    if fs is not None and not (isinstance(fs, list)
                               and all(isinstance(f, dict) and _text_or_nothing(f.get("id")) for f in fs)):
        return "its findings are not a list of findings with an id each"
    return None


def baseline_shape(d: dict) -> str | None:
    """`baseline.json` as `evidence.baseline_from` writes it, in every release so far (`tests/fixtures/old_results`):
    a field added there has to be let through here."""
    if isinstance(d.get("id_version"), bool) or not isinstance(d.get("id_version"), (int, str, type(None))):
        return "its id_version is not a number"
    for k in ("date", "commit"):
        if not _text_or_nothing(d.get(k)):
            return f"its {k} is not text"
    counts = d.get("counts")
    if counts is not None and not (isinstance(counts, dict) and all(_number(v) for v in counts.values())):
        return "its counts are not numbers"
    rd = d.get("readiness")
    if rd is not None:
        if not isinstance(rd, dict) or not (rd.get("score") is None or _number(rd["score"])) \
                or not _text_or_nothing(rd.get("grade")):
            return "its readiness is not a score and a grade"
        cats = rd.get("categories")
        if cats is not None and not (isinstance(cats, dict) and all(v is None or _number(v) for v in cats.values())):
            return "its readiness categories are not numbers"
    fs = d.get("findings")
    if fs is None:
        return None
    if not isinstance(fs, dict):
        return "its findings are not a table"
    for v in fs.values():
        if not isinstance(v, dict) or not all(isinstance(v.get(k), str) for k in ("rule", "rank", "title")) \
                or not _text_or_nothing(v.get("file")) or not (v.get("line") is None or _number(v["line"])):
            return "one of its findings is not a rule, a rank, a title, a file and a line"
    return None


def explanations_shape(d: dict) -> str | None:
    """`explanations.json` as `explain.run` and `pipeline.explain` write it: the record of each function is a table.
    What is inside a record is the viewer's to escape and is not looked at here."""
    e = d.get("explanations")
    if e is not None and not (isinstance(e, dict) and all(isinstance(r, dict) for r in e.values())):
        return "its explanations are not a table of records"
    for k in ("stats", "metaphor"):
        if d.get(k) is not None and not isinstance(d[k], dict):
            return f"its {k} is not a table"
    return None


SHAPES = {"security.json": scan_shape, "baseline.json": baseline_shape, "explanations.json": explanations_shape}


def earlier(out: Path, name: str) -> tuple[dict | None, str | None]:
    """What an earlier run left in `out` under `name`: (table, None); (None, None) when there is no such file; or
    (None, why) when what is there cannot be taken for what Lantern writes. Never raises for what the file holds."""
    text, why = plain(Path(out) / name)
    if text is None:
        return None, why
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None, CUT_OFF
    if not isinstance(data, dict):
        return None, NOT_OURS
    odd = SHAPES[name](data) if name in SHAPES else None
    return (None, f"{NOT_OURS}: {odd}") if odd else (data, None)


# ---------------------------------------------------------------------------- writing

class Refused(RuntimeError):
    """Lantern will not write where it was asked to. The message is for the person: the command line prints it after
    `error:` and ends with 2, the app shows it as the reason the job did not run."""


KEEP_SAID = 200                     # lines kept until a run asks for them; more than that are not kept
_said: list[tuple[str, str]] = []   # (the folder, what `write` met there)
_said_lock = threading.Lock()


def _say(folder, line: str) -> None:
    with _said_lock:
        if len(_said) < KEEP_SAID and (str(folder), line) not in _said:
            _said.append((str(folder), line))


def said(out=None) -> list[str]:
    """What `write` met in the folder `out` (in every folder when None) since this was last asked: one sentence per
    link, pipe or device it replaced, in Lantern's own words. Asking takes the sentences away, so each is said once."""
    with _said_lock:
        mine = [x for x in _said if out is None or x[0] == str(out)]
        _said[:] = [x for x in _said if x not in mine]
    return [line for _folder, line in mine]


def _look(path) -> tuple[str | None, os.stat_result | None]:
    """What is at `path` itself: None (nothing), "file", "folder", "link" (a symbolic link, on Windows also a
    junction) or "other" (a pipe, a device, a socket), with what the system said about it."""
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None, None
    if removal._linkish(st):
        return "link", st
    if stat.S_ISDIR(st.st_mode):
        return "folder", st
    return ("file" if stat.S_ISREG(st.st_mode) else "other"), st


def _a_folder(path: Path, where: str) -> str:
    return (f"{path.name} in {where} ({path.parent}) is a folder, and Lantern keeps a file of that name there. "
            "Move or rename the folder, then run again.")


def _kept(path: Path, where: str) -> str:
    return (f"{path.name} in {where} ({path.parent}) may not be changed by this user (it is marked read-only, or it "
            "is somebody else's), and Lantern does not replace a file it may not change. Make the file writable or "
            "move it away, then run again.")


def _in_the_way(path: Path, kind: str | None, where: str) -> str | None:
    """Why Lantern will not put a file at `path` (None when it will): a folder is there, or a file that this user
    may not change. Writing the older way stopped at such a file too; replacing it would not, so it is asked."""
    if kind == "folder":
        return _a_folder(path, where)
    if kind == "file" and not os.access(path, os.W_OK):
        return _kept(path, where)
    return None


TRIES = 50 if os.name == "nt" else 1   # Windows refuses to replace a file another program is reading at that moment


def _replace(tmp, path, tries: int = TRIES) -> None:
    """Move `tmp` into the place of `path`; where the system refuses, try again `tries` times in all, 20 ms apart
    (a second on Windows), and then let the refusal through."""
    for left in range(tries - 1, -1, -1):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if not left:
                raise
            time.sleep(0.02)


def write(path, text: str, newline: str | None = None, where: str = "the results folder") -> Path:
    """Write `text` as the file `path`, in one step: into a new file beside it (a name of this call's own, never an
    existing one), then moved into place. So the name itself is never opened: a link there is replaced and what it
    pointed at is left alone, a pipe there cannot hold the write up, and the file is whole or as it was. A folder
    there is `Refused`, and so is a file this user may not change (marked read-only, or somebody else's). `newline`
    as for `open` (None writes this system's line ends, as `write_text` did)."""
    path = Path(path)
    kind, st = _look(path)
    why = _in_the_way(path, kind, where)
    if why:
        raise Refused(why)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.part")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(tmp, flags, 0o666)          # the mode of any new file of the person (their umask applies)
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as fh:
            if kind == "file" and hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), st.st_mode & 0o777)   # as open or as closed as the file it takes the place of
            fh.write(text)
        if kind in ("link", "other") and os.name == "nt":
            os.unlink(path)                      # Windows does not replace a link to a folder; it goes as itself
        try:
            _replace(tmp, path)
        except IsADirectoryError:                # a folder was put there since the look above
            raise Refused(_a_folder(path, where)) from None
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if kind == "link":
        _say(path.parent, f"{path.name} in {where} was a link; Lantern put its own file in its place and left what "
                          "the link pointed at alone")
    elif kind == "other":
        _say(path.parent, f"{path.name} in {where} was not a plain file (a pipe or a device); Lantern put its own "
                          "file in its place")
    return path


def _within(path: str, top: str) -> bool:
    path, top = os.path.normcase(path), os.path.normcase(top)
    return path == top or path.startswith(top.rstrip("\\/") + os.sep)


def folder(repo, out=None) -> Path:
    """The results folder of the project `repo`: `out` when the person named one (`--out`), else `repo/.lantern`,
    given back as it was named and made when it is not there. `Refused` when the folder is a link that lies inside
    the project, or is reached through one (those came with the project, and Lantern's files would be made wherever
    such a link points), and when something that is not a folder is in its place. A link outside the project is the
    person's own and is followed."""
    d = Path(out) if out else Path(repo) / ".lantern"
    whole = d if d.is_absolute() else Path.cwd() / d
    project = os.path.realpath(repo)
    at = Path(whole.anchor)
    for part in whole.parts[1:]:
        above, at = at, at / part
        try:
            kind, _st = _look(at)
        except OSError:                          # it cannot be looked at: making the folder below says why
            break
        if kind is None:
            break
        if kind == "link" and _within(os.path.realpath(above), project):
            raise Refused(f"{at} is a link, and Lantern does not write its results through a link that came with "
                          "the project. Remove the link, or name a results folder of your own with --out.")
    try:
        os.makedirs(whole, exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        raise Refused(f"{whole} is not a folder, so Lantern cannot keep its results there. Move or rename what is "
                      "there, or name a results folder of your own with --out.") from None
    return d


def link_in_project(repo, path) -> bool:
    """Whether `path` itself is a link that lies inside the project `repo` (through whatever folders it is named)."""
    try:
        return _look(path)[0] == "link" and _within(os.path.realpath(os.path.dirname(os.path.abspath(path))),
                                                    os.path.realpath(repo))
    except OSError:
        return False


def ready(out, names) -> None:
    """Before a run starts: `Refused` when one of the files it is about to write (`names`) is a folder in `out`, or
    a file this user may not change. Found at the end, that would cost the whole run and leave the results of two
    runs mixed."""
    for name in names:
        why = _in_the_way(Path(out) / name, _look(Path(out) / name)[0], "the results folder")
        if why:
            raise Refused(why)


def inner(root, what: str) -> Path:
    """A folder Lantern keeps inside the results folder (`what` says what for), made when it is not there. One that
    is a link is `Refused` wherever it lies: nobody but Lantern has a reason to put anything there."""
    kind, _st = _look(root)
    if kind == "link":
        raise Refused(f"{root} is a link, and Lantern does not keep {what} through a link. Remove the link; Lantern "
                      "makes the folder anew.")
    try:
        os.makedirs(root, exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        raise Refused(f"{root} is not a folder, so Lantern cannot keep {what} there. Move or rename what is "
                      "there.") from None
    return Path(root)
