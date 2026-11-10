"""What git knows about a folder, read without letting the folder's own git settings decide or start anything.

Why (found 2026-11-10, stage 7 of the 2026-11-09 directive). A git folder's settings file (`.git/config`) can name
commands, and git runs them by itself: `core.fsmonitor` is run by `git status` and by everything else that reads the
index, a clean filter when a file's content has to be compared, and `git status` starts itself inside every
submodule, under that submodule's settings. `git clone` never copies such settings from the other side, but a folder
that arrives another way brings its `.git` as it is: an unpacked archive, a download, a shared drive, an upload to
the cloud service. Until that day `lantern analyze` asked git for the commit and for uncommitted changes inside the
analyzed folder, and a line planted there was run with the rights of the person, although Lantern says it only
reads code.

So the folder's `.git` is read like any other file of the project, here and not by git:

* where the repository is: `.git` in the folder or in a folder above it (`find`); a `.git` file (a linked worktree,
  a submodule) only when the place it names points back at this folder; never through a link;
* the commit and the branch (`HEAD`, a loose ref, `packed-refs`) and the address of `origin` (`settings`);
* a short list of settings that say how files were written to this disk (`INERT`: true/false and fixed words).

git itself is started only on a git folder Lantern makes for the occasion (`_shadow`): its settings file is written
here from that short list, its `HEAD` is the commit found above, and git's own variables point it at the project's
files, index and objects. There git reads the project's index, objects and files, and none of the project's
settings; nothing in them can name a program. Submodules are looked into one by one in the same way (`_changed`),
never by git. The person's own git settings (in their home folder, or the computer's) are theirs and still apply.

Known limits. Not read (no commit, with a note): a `.git` that is a link; a `.git` file whose target does not point
back, which is what `git init --separate-git-dir` makes; a repository that keeps its refs in the newer "reftable"
form; a bare repository (it has no files to analyze). Counted as changed, with a note, when git cannot compare:
an index or an objects folder that is a link, a submodule whose own git folder is not read or whose name in the
index points out of the folder, submodules nested more than five deep. A filter that only the repository's own
settings define (`git lfs install --local`) is not run, so a file it would have cleaned can count as changed once
its time stamp differs from the index. A submodule the repository's settings tell git to ignore is looked into all
the same. Whose git folder it is, is not looked at: git refuses a repository that another user of the computer owns
(unless the person listed it, `safe.directory`), because it would obey that user's settings; Lantern obeys none of
them and reads it, also when it sits in a folder above the one asked about. The index (a split or sparse one too),
the objects (and the other object folders the repository names) and `.gitattributes` are still read by git, as
they are for any repository a person clones. Standard library only.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import remote

HEX = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_BOOL = {"true": "true", "yes": "true", "on": "true", "1": "true", "": "false",
         "false": "false", "no": "false", "off": "false", "0": "false"}
# The only settings of a project's git folder that reach git, each with the values it may have. They say how the
# files were written to this disk, so that an unchanged checkout does not look changed. None can name a program, a
# path or an address.
INERT: dict[str, dict[str, str]] = {
    "core.filemode": _BOOL, "core.symlinks": _BOOL, "core.ignorecase": _BOOL, "core.precomposeunicode": _BOOL,
    "core.trustctime": _BOOL, "core.longpaths": _BOOL, "core.sparsecheckout": _BOOL,
    "core.sparsecheckoutcone": _BOOL,
    "core.autocrlf": {**_BOOL, "input": "input"},
    "core.eol": {"lf": "lf", "crlf": "crlf", "native": "native"},
    "core.checkstat": {"default": "default", "minimal": "minimal"},
}
# git's own variables that say where a repository is: taken out of the caller's environment before ours go in
_PLACES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES", "GIT_SHALLOW_FILE",
           "GIT_GRAFT_FILE", "GIT_INTERNAL_SUPER_PREFIX")
SMALL, SETTINGS_CAP, PACKED_CAP = 4096, 1 << 20, 64 << 20
SUBMODULE_DEPTH = 5
NOT_ONE = "not a git repository"
UNREAD = ("its git folder is a link, or is kept in another place that does not name this folder back, "
          "so it was not read")
REFTABLE = "its git folder keeps the branches in the newer reftable form, which Lantern does not read"
UNKNOWN = "git could not compare the files with the commit, so they are counted as changed"


@dataclass(frozen=True)
class Repo:
    top: Path       # the folder the files are in
    gitdir: Path    # where HEAD and the index are
    common: Path    # where the refs, the objects and the settings file are (the same, but for a linked worktree)


def _is(path: Path | str, real: Path) -> bool:
    """Whether `path`, links followed, is the place `real` (which is written without links)."""
    try:
        return os.path.normcase(os.path.realpath(path, strict=True)) == os.path.normcase(str(real))
    except (OSError, ValueError):
        return False


def _own_file(p: Path) -> bool:
    """A plain file that is there under its own name: no link and no Windows junction anywhere on the way to it."""
    try:
        return stat.S_ISREG(os.lstat(p).st_mode) and _is(p, p)
    except (OSError, ValueError):
        return False


def _real_dir(p: Path) -> bool:
    """A folder that is there under its own name: not a link, not a Windows junction."""
    try:
        return stat.S_ISDIR(os.lstat(p).st_mode) and _is(p, p)
    except (OSError, ValueError):
        return False


def _text(base: Path, name: str, cap: int) -> str | None:
    """The text of the plain file `name` under the folder `base` (written without links), of at most `cap` bytes.
    None for anything else: nothing there, a folder, a pipe (never opened in a way that could wait), a larger file,
    and a link or a Windows junction anywhere on the way from `base` to the file, so that what is read is the git
    folder's own."""
    p = base / name
    if not _own_file(p):
        return None
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_BINARY", 0))
    except (OSError, ValueError):
        return None
    with os.fdopen(fd, "rb") as f:
        try:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
                return None
            return f.read(cap).decode("utf-8", "replace")
        except OSError:
            return None


_SECTION = re.compile(r'\[([A-Za-z0-9.-]+)(?:[ \t]+"((?:[^"\\\n]|\\[^\n])*)")?\]')
_NAME = re.compile(r"([A-Za-z][A-Za-z0-9-]*)[ \t]*")


def _value(text: str, pos: int) -> tuple[str | None, int]:
    """(the value that starts at `pos`, where the next line starts), read the way git's own `parse_value` reads
    it: quotes keep spaces, a `#` or `;` outside quotes ends it, a backslash at the end of a line carries on in the
    next. Blanks before and after the value are dropped; blanks inside it are kept as written, a tab as a tab,
    which is git's reading since 2.45 (older git made each of them a space). None for a value git refuses (a quote
    left open, an escape it does not know)."""
    out: list[str] = []                         # one character each
    quote, comment, n = False, False, len(text)
    cut: int | None = None      # where a run of blanks began: the value ends there unless something follows them
    while True:
        c = text[pos] if pos < n else "\n"
        pos += 1
        if c == "\n":
            return (None if quote else "".join(out[:cut])), pos
        if comment:
            continue
        if c in " \t\r" and not quote:
            if out:                             # blanks before the value are dropped
                cut = len(out) if cut is None else cut
                out.append(c)
            continue
        if c in "#;" and not quote:
            comment = True
            continue
        cut = None
        if c == "\\":
            c = text[pos] if pos < n else "\n"
            pos += 1
            if c == "\n":
                continue
            if c not in 'tbn\\"':
                end = text.find("\n", pos)
                return None, n if end < 0 else end + 1
            c = {"t": "\t", "b": "\b", "n": "\n"}.get(c, c)
        elif c == '"':
            quote = not quote
            continue
        out.append(c)


def settings(common: Path) -> dict[str, str]:
    """A git folder's settings file, read as text and obeyed by nobody: `{"section.subsection.name": last value}`,
    section and name in lower case, the way `git config --list` writes them. Includes are not followed. A line
    git would refuse is passed over (git itself stops at the first one and reads nothing of such a file)."""
    text = _text(common, "config", SETTINGS_CAP)
    out: dict[str, str] = {}
    if text is None:
        return out
    text = text.removeprefix("\ufeff").replace("\r\n", "\n")
    pos, n, section = 0, len(text), None

    def next_line(i: int) -> int:
        end = text.find("\n", i)
        return n if end < 0 else end + 1

    while pos < n:
        c = text[pos]
        if c in " \t\n\r":
            pos += 1
        elif c == "[":
            m = _SECTION.match(text, pos)
            section = None if not m else m.group(1).lower() + (
                "" if m.group(2) is None else "." + re.sub(r"\\(.)", r"\1", m.group(2)))
            pos = m.end() if m else next_line(pos)
        elif c.isascii() and c.isalpha():
            m = _NAME.match(text, pos)
            pos = m.end()
            if pos >= n or text[pos] == "\n":
                value = "true"                  # a name alone means true
            elif text[pos] != "=":
                value, pos = None, next_line(pos)
            else:
                value, pos = _value(text, pos + 1)
            if section and value is not None:
                out[f"{section}.{m.group(1).lower()}"] = value
        else:                                   # a comment, or a line that is not a setting
            pos = next_line(pos)
    return out


def _resolved(base: Path, said: str) -> Path | None:
    try:
        return (base / said).resolve()
    except (OSError, ValueError, RuntimeError):
        return None


def _named(top: Path, dot: Path) -> Path | None:
    """The git folder a `.git` FILE names, only when that folder points back at this place: a linked worktree's
    folder keeps the way back in its `gitdir` file, a submodule's in its `core.worktree` setting. Without the way
    back a planted file would have Lantern read, and report, another repository of this computer."""
    m = re.fullmatch(r"gitdir: (.+)", (_text(top, ".git", SMALL) or "").strip())
    target = _resolved(top, m.group(1)) if m else None
    if target is None or not _real_dir(target):
        return None
    back = _text(target, "gitdir", SMALL)
    if back is not None and _is(target / back.strip(), dot):
        return target
    worktree = settings(target).get("core.worktree")
    return target if worktree and _is(target / worktree, top) else None


def _common(gitdir: Path, linked: bool) -> Path | None:
    """Where a git folder keeps what its worktrees share: itself, or, for a linked worktree, the folder its
    `commondir` file names. git keeps a worktree's own folder at `<shared>/worktrees/<name>` and nowhere else; a
    `commondir` that says anything else would have another repository's commit and address reported as this
    one's, and is not read."""
    if not os.path.lexists(gitdir / "commondir"):
        return gitdir
    said = _text(gitdir, "commondir", SMALL)
    common = _resolved(gitdir, said.strip()) if linked and said is not None else None
    if common is None or not _real_dir(common) or not _is(common / "worktrees" / gitdir.name, gitdir):
        return None
    return common


def _ceilings() -> set[str]:
    """The folders `GIT_CEILING_DIRECTORIES` names: the person's own word on where git must not look further up."""
    out = set()
    for said in os.environ.get("GIT_CEILING_DIRECTORIES", "").split(os.pathsep):
        if said and os.path.isabs(said):
            out.add(os.path.normcase(os.path.realpath(said)))
    return out


def _locate(folder: Path | str, up: bool = True) -> tuple[Repo | None, str | None]:
    """(the repository `folder` is in, None), or (None, why it is not read; None when there is none at all)."""
    try:
        here = Path(folder).resolve(strict=True)
        disk = os.stat(here).st_dev
    except (OSError, ValueError, RuntimeError):
        return None, None
    stop = _ceilings() if up else set()
    for top in ((here, *here.parents) if up else (here,)):
        dot = top / ".git"
        try:
            if os.stat(top).st_dev != disk or (top != here and os.path.normcase(str(top)) in stop):
                break                               # git does not cross onto another disk, or past a ceiling, either
            st = os.lstat(dot)
        except OSError:
            continue
        linked = stat.S_ISREG(st.st_mode)
        gitdir = _named(top, dot) if linked else dot if _real_dir(dot) else None
        if gitdir is None:
            return None, UNREAD
        if _text(gitdir, "HEAD", SMALL) is None:
            return None, None                       # no git folder at all: it has no HEAD that is a plain file
        common = _common(gitdir, linked)
        return (Repo(top, gitdir, common), None) if common is not None else (None, UNREAD)
    return None, None


def find(folder: Path | str) -> Repo | None:
    """The repository `folder` is in: its own `.git`, or the nearest one above it on the same disk, as git looks.
    Found by looking, never by asking git. None when there is none Lantern reads (see the module's known limits)."""
    return _locate(folder)[0]


def _ref_ok(ref: str) -> bool:
    return bool(re.fullmatch(r"refs/[^\x00-\x20\x7f~^:?*\[\\]+", ref)) and ".." not in ref and "//" not in ref \
        and not ref.endswith(("/", ".", ".lock")) and "/." not in ref and "@{" not in ref


def _ref(repo: Repo, ref: str, depth: int = 0) -> str | None:
    if depth > 5 or not _ref_ok(ref):
        return None
    loose = _text(repo.common, ref, SMALL)
    if loose is not None:
        loose = loose.strip()
        if HEX.fullmatch(loose):
            return loose
        return _ref(repo, loose[5:], depth + 1) if loose.startswith("ref: ") else None
    packed = _text(repo.common, "packed-refs", PACKED_CAP)
    for line in (packed or "").split("\n"):
        line = line.rstrip("\r")
        if line.endswith(" " + ref) and HEX.fullmatch(line[:-len(ref) - 1]):
            return line[:-len(ref) - 1]
    return None


def head(repo: Repo) -> tuple[str | None, str | None]:
    """(commit, branch) as the folder's `HEAD` says. The branch is "HEAD" when no branch is checked out; the commit
    is None when the branch has no commit yet or the refs are kept in a form Lantern does not read."""
    said = (_text(repo.gitdir, "HEAD", SMALL) or "").strip()
    if HEX.fullmatch(said):
        return said, "HEAD"
    if not said.startswith("ref: ") or not _ref_ok(said[5:]):
        return None, None
    ref = said[5:]
    return _ref(repo, ref), ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref[len("refs/"):]


def head_commit(folder: Path | str) -> str | None:
    """The commit a folder's files were checked out from, read by hand. No program is started."""
    repo = find(folder)
    return head(repo)[0] if repo else None


@contextlib.contextmanager
def _shadow(repo: Repo, commit: str | None):
    """A git folder of Lantern's own for questions about `repo`: yields a function that starts git with the given
    arguments and returns what it printed (None when git is not installed, did not end well or took too long).
    git reads the project's files, index and objects there, with settings written here. The index and the objects
    folder must be the git folder's own (no link on the way), or nothing is asked. Removed afterwards; it holds two
    small text files written here and nothing of the project."""
    cfg = settings(repo.common)
    git = shutil.which("git")
    index, objects = repo.gitdir / "index", repo.common / "objects"
    made = None
    if git and _real_dir(repo.top) and _real_dir(objects) and (_own_file(index) or not os.path.lexists(index)):
        try:
            made = Path(tempfile.mkdtemp(prefix="lantern-git-"))
            sha256 = bool(commit and len(commit) == 64) or cfg.get("extensions.objectformat", "").lower() == "sha256"
            lines = ["[core]", f"\trepositoryformatversion = {1 if sha256 else 0}", "\tbare = false"]
            for key, allowed in INERT.items():
                value = allowed.get(cfg.get(key, "\0").strip().lower())
                if value is not None:
                    lines.append(f"\t{key.split('.', 1)[1]} = {value}")
            if sha256:
                lines += ["[extensions]", "\tobjectformat = sha256"]
            (made / "config").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            (made / "HEAD").write_text((commit or "ref: refs/heads/none") + "\n", encoding="utf-8", newline="\n")
            for d in ("objects", "refs", "no-hooks"):
                (made / d).mkdir()
        except OSError:                             # no place to make it: every question is left unanswered
            if made is not None:
                shutil.rmtree(made, ignore_errors=True)
            made = None
    env = {k: v for k, v in os.environ.items() if k not in _PLACES}
    env.update({"GIT_DIR": str(made), "GIT_WORK_TREE": str(repo.top), "GIT_OBJECT_DIRECTORY": str(objects),
                "GIT_INDEX_FILE": str(index), "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"})

    def ask(args: list[str], timeout: float = 60) -> str | None:
        if made is None:
            return None
        try:        # run_bounded ends the whole tree of programs at the time limit
            p = remote.run_bounded([git, "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={made / 'no-hooks'}",
                                    *args], cwd=repo.top, env=env, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return p.stdout if p.returncode == 0 else None

    try:
        yield ask
    finally:
        if made is not None:
            shutil.rmtree(made, ignore_errors=True)


def _changed(repo: Repo, ask, depth: int = 0) -> bool | None:
    """Whether files git keeps track of differ from the commit, here or inside a submodule that is checked out.
    None when that cannot be told."""
    staged = ask(["ls-files", "--stage", "-z"])         # reads the index only
    if staged is None:
        return None
    inside = []
    for entry in staged.split("\0"):
        if not entry.startswith("160000 ") or "\t" not in entry:
            continue
        # A submodule. Its name comes from the index, which the folder brought with it, and git compares its commit
        # by reading the git folder its `.git` names. So before git is asked anything about the files, every
        # submodule that is checked out must be one Lantern itself would read: a real folder inside this one
        # (`_real_dir` refuses `..`, a link, and an absolute name elsewhere) whose git folder is its own.
        sub = repo.top / entry.split("\t", 1)[1]
        if repo.top not in sub.parents:
            return None
        if not os.path.lexists(sub / ".git"):
            continue                                    # not checked out: none of its files are in the folder
        inner, _ = _locate(sub, up=False) if depth < SUBMODULE_DEPTH and _real_dir(sub) else (None, None)
        at = head(inner)[0] if inner is not None else None
        if not at:
            return None
        inside.append((inner, at))
    # `--ignore-submodules=dirty`: git reports a submodule that is at another commit and does not start itself
    # inside it, where the submodule's own settings would be obeyed. The submodules are looked into below.
    status = ask(["status", "--porcelain", "--untracked-files=no", "--ignore-submodules=dirty"])
    if status is None:
        return None
    if status.strip():
        return True
    for inner, at in inside:
        with _shadow(inner, at) as ask_inner:
            changed = _changed(inner, ask_inner, depth + 1)
        if changed is not False:
            return changed
    return False


def _committed_at(ask, commit: str) -> str | None:
    """When the commit was made, as `2026-11-10T04:11:37-08:00` (what git prints for `%cI`)."""
    body = ask(["cat-file", "commit", commit], timeout=20)
    m = re.search(r"^committer .*> (\d{1,12}) ([+-])(\d\d)(\d\d)$", (body or "").split("\n\n", 1)[0], re.M)
    if not m:
        return None
    off = dt.timedelta(hours=int(m.group(3)), minutes=int(m.group(4))) * (-1 if m.group(2) == "-" else 1)
    try:
        return dt.datetime.fromtimestamp(int(m.group(1)), dt.timezone(off)).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def info(folder: Path | str) -> dict:
    """The commit a folder is at, its branch, whether files differ from the commit, the address of `origin`, and when
    the commit was made. `{"commit": None, "note": …}` when the folder is in no repository Lantern reads, or git is
    not installed. `dirty` is True, with a `note`, when git could not tell."""
    if not shutil.which("git"):
        return {"commit": None, "note": "git not installed"}
    repo, why = _locate(folder)
    if repo is None:
        return {"commit": None, "note": why or NOT_ONE}
    cfg = settings(repo.common)
    commit, branch = head(repo)
    if not commit:
        reftable = cfg.get("extensions.refstorage", "files").strip().lower() != "files"
        return {"commit": None, "note": REFTABLE if reftable else NOT_ONE}
    with _shadow(repo, commit) as ask:
        changed = _changed(repo, ask)
        when = _committed_at(ask, commit)
    url = re.sub(r"[\x00-\x1f\x7f]", "", cfg.get("remote.origin.url") or "")[:2000]
    out = {"commit": commit, "branch": branch, "dirty": changed is not False,
           "remote": re.sub(r"//[^@/]+@", "//", url) or None,       # never a name or password kept in the address
           "committed_at": when}
    if changed is None:
        out["note"] = UNKNOWN
    return out


def deleted(folder: Path | str, timeout: float = 120) -> list[str] | None:
    """The files of the index of the repository whose `.git` is in `folder` that are not in the folder
    (`git ls-files --deleted`). None when that cannot be told."""
    repo, _ = _locate(folder, up=False)
    if repo is None:
        return None
    with _shadow(repo, head(repo)[0]) as ask:
        out = ask(["ls-files", "--deleted", "-z"], timeout=timeout)
    return None if out is None else [p for p in out.split("\0") if p]
