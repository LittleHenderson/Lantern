"""A check before each push (roadmap of 2026-11-14, stage 6, part 2): `lantern hook install`.

Opt-in. `install` writes git's `pre-push` hook into the repository, and from then on, before git sends anything, the
hook hands Lantern what git says is being pushed (one line per branch or tag: the local name and commit, the remote
name and the commit the other side has). For each, `run` compares the commit being pushed with what the other side
already has, by the same two checks as `lantern diff` (`pipeline.change`, offline, so no library is looked up), and
ends with 1, which makes git stop the whole push, when the change itself brings what blocks a release
(`diff.blockers`: a critical or high finding that is new, reached only now, ranked higher or open again, a secret
written into a file, a request of the page that a route answered before and none answers now). What blocked the
project before the push and still does is the project's, not the push's, and does not stop it. The receipt of each
check is written to `.lantern/push/<branch>/`; `git push --no-verify` pushes once without the check.

What the other side has (the base): the commit git names for it, where this repository holds that commit. For a new
branch, or a commit this repository does not hold, the commit where the pushed one parted from the remote's main
branch (`<remote>/HEAD`, else `<remote>/main`, else `<remote>/master`, as this repository last saw them). Where
there is none of these (the first push to an empty remote), everything pushed is new: the pushed commit is compared
with nothing, and every critical or high finding in it stops the push.

The hook is the person's. `install` writes one only where none is, or where the one there is Lantern's own (`MARK`
in its first lines, a plain file), and `remove` takes away only Lantern's own: a hook of the person's, or a link, is
never replaced, changed or removed, and the person is told the one line to add to their own. Where git would not run
a hook from `.git/hooks` (a `core.hooksPath` set in the repository's or the person's settings), nothing is written
and the person is told why. Reading the repository goes through `gitfacts` (never git started on the project's own
settings). The hook runs the Lantern that wrote it, with the Python that wrote it, never a copy in the project (`-P`:
the project's folder is not on Python's path).

Speed (measured, `bench/push_check.py`, `bench/push_check_results.md`): on the 15 sample projects a push took 1.00
to 1.42 seconds in two runs, a planted fault included; on Lantern's own repository (793 files) about 100 seconds, since each push
is two whole checks. What each file reads as is kept between runs (`lantern/kept.py`), so a file that did not change is
not read again; the scanners and the data-flow step look at the whole project on each side.
"""
from __future__ import annotations

import os
import re
import stat
import sys
import time
from pathlib import Path

MARK = "# lantern-pre-push 1: written by `lantern hook install`; `lantern hook remove` takes it away."
MOST_HOOK = 64 * 1024       # bytes: a larger file under the hook's name is not Lantern's
MOST_SAID = 12              # lines of what blocks, per push, printed (all are in the receipt)
MOST_LIMITS = 3             # limits of one push's check printed beyond those every check has (`diff.standing`)
ZERO = re.compile(r"0{40}(?:0{24})?")
HEX = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
MAIN = ("HEAD", "main", "master")       # the remote's branches a new branch is compared with, in this order
NO_VERIFY = "To push once without this check: git push --no-verify"
NOT_A_REPO = ("This folder is in no git repository Lantern reads, so there is no push to check here. The check "
              "before each push is written into a repository's own hooks folder.")


class Refused(ValueError):
    """Lantern will not write or remove the hook here. The text is a sentence for the person."""


def _shown(text, most: int = 300) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(text))[:most]


def _quoted(text: str) -> str:
    """`text` as one word for the shell: in single quotes, a quote inside written as '"'"'."""
    return "'" + text.replace("'", "'\"'\"'") + "'"


STARTER = ("import os, sys; p = sys.argv.pop(1); "
           "all(os.path.normcase(os.path.abspath(x)) != os.path.normcase(p) for x in sys.path if x) "
           "and sys.path.insert(0, p); "
           "from lantern.cli import main; raise SystemExit(main([\"hook\", \"run\", *sys.argv[1:]]))")


def _this_lantern() -> str:
    """What follows the Python in both lines: without the project's folder on its path (`-P`), this Lantern loaded
    (its folder, the starter's first word, is put on the path only where this Python would not find it), with what git
    handed the hook."""
    here = Path(__file__).resolve().parent.parent
    return f'-P -c {_quoted(STARTER)} {_quoted(here.as_posix())} "$@"'


def command_line() -> str:
    """The line the hook runs: this Python (named in the hook as `$python`) and this Lantern."""
    return f'"$python" {_this_lantern()}'


def hook_text() -> str:
    python = Path(sys.executable).as_posix()
    return "\n".join([
        "#!/bin/sh",
        MARK,
        "# Before each push Lantern compares what the push sends with what the other side has, and stops the push",
        "# when the change brings what blocks a release (docs/diff.md, \"Before each push\").",
        f"# {NO_VERIFY}",
        f"python={_quoted(python)}",
        'if [ -f "$python" ]; then',
        f"  exec {command_line()}",
        "fi",
        'echo "lantern: the Python this check was written for is not there any more: $python" >&2',
        "echo \"lantern: run 'lantern hook install' again, or 'lantern hook remove'. "
        f"{NO_VERIFY}\" >&2",
        "exit 2",
        ""])


def _ours(path: Path) -> bool | None:
    """True for Lantern's own hook at `path`, False for anything else there, None when nothing is there. The file is
    opened as itself: never through a link at its name, and never waiting on a pipe put there after it was looked at."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_size > MOST_HOOK:
        return False
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError):
        return False
    with os.fdopen(fd, "rb") as f:
        try:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return False
            head = f.read(1024)
        except OSError:
            return False
    return MARK in head.decode("utf-8", errors="replace").split("\n")[:3]


def _place(folder) -> tuple[object, Path]:
    """(the repository, the place of its pre-push hook). `Refused` where there is no repository Lantern reads, or
    where git runs hooks from another folder (`core.hooksPath`), so a hook in `.git/hooks` would never run."""
    from . import gitfacts
    repo = gitfacts.find(folder)
    if repo is None:
        raise Refused(NOT_A_REPO)
    other = gitfacts.settings(repo.common).get("core.hookspath") or gitfacts.person_setting("core.hooksPath")
    if other:
        raise Refused(f"git runs this repository's hooks from another folder ({_shown(other, 200)}, the setting "
                      "core.hooksPath), so a hook in .git/hooks would never run, and Lantern writes nothing there. "
                      "To check each push, add this line to the pre-push hook in that folder: "
                      f"{own_line()}")
    return repo, repo.common / "hooks" / "pre-push"


def own_line() -> str:
    """The one line a hook of the person's can run to have Lantern check the push (what git hands a hook passed on):
    the same Python and Lantern as Lantern's own hook (until 2026-11-17 `python -P -m lantern.cli`, which runs
    whichever Lantern that Python finds by itself)."""
    return f"{_quoted(Path(sys.executable).as_posix())} {_this_lantern()} || exit $?"


def install(folder) -> dict:
    """Write Lantern's pre-push hook into the repository `folder` is in. `{path, state: written | updated}`."""
    from . import results
    _repo, path = _place(folder)
    ours = _ours(path)
    if ours is False:
        raise Refused(f"A pre-push hook is already there ({_shown(path)}), and Lantern did not write it, so Lantern "
                      "leaves it as it is. To check each push from it, add this line to it: " + own_line())
    path.parent.mkdir(parents=True, exist_ok=True)
    results.write(path, hook_text(), newline="\n", where="the repository's hooks folder")
    # git starts a hook as the person who pushes: run by its owner only, changed by nobody else
    os.chmod(path, 0o700)
    return {"path": str(path), "state": "updated" if ours else "written"}


def remove(folder) -> dict:
    """Take Lantern's pre-push hook away. `{path, removed}`; `Refused` for a hook Lantern did not write."""
    _repo, path = _place(folder)
    ours = _ours(path)
    if ours is None:
        return {"path": str(path), "removed": False}
    if ours is False:
        raise Refused(f"The pre-push hook there ({_shown(path)}) is not Lantern's, so Lantern does not remove it.")
    path.unlink()
    return {"path": str(path), "removed": True}


def status(folder) -> dict:
    """`{path, on, words}`: whether the check before each push is on in the repository `folder` is in."""
    try:
        _repo, path = _place(folder)
    except Refused as e:
        return {"path": None, "on": False, "words": f"The check before each push is not on: {e}"}
    ours = _ours(path)
    words = {True: f"The check before each push is on ({path}).",
             None: "The check before each push is not on in this repository. `lantern hook install` turns it on.",
             False: f"The check before each push is not on: the pre-push hook there ({path}) is one of your own. "
                    "To check each push from it, add this line to it: " + own_line()}[ours]
    return {"path": str(path), "on": bool(ours), "words": words}


# ------------------------------------------------------------------------------------------------- the check itself
def _base(top: Path, remote: str | None, theirs: str, head: str) -> tuple[str | None, str]:
    """(the commit the push is compared with, what it is, in words). None: nothing to compare with."""
    from . import gitfacts
    if not ZERO.fullmatch(theirs):
        try:
            return gitfacts.resolve(top, theirs), f"what {remote or 'the other side'} has"
        except gitfacts.NoCommit:
            pass        # a commit this repository does not hold (the other side moved on): where it parted from main
    if remote and gitfacts.named(remote):
        for branch in MAIN:
            try:
                there = gitfacts.resolve(top, f"{remote}/{branch}")
                return gitfacts.merge_base(top, there, head), f"where it parted from {remote}/{branch}"
            except gitfacts.NoCommit:
                continue
    return None, "nothing: the first push of this code"


IGNORED = ("# Written by Lantern (`lantern hook install`): the receipts of the check before each push are not part of\n"
           "# the project, so git leaves this folder out.\n*\n")


def _receipts(top: Path) -> Path:
    """`.lantern/push` of the project, with a `.gitignore` of its own that leaves it all out of git: a receipt is
    written at every push, and `git add -A` would otherwise put the last one into the next commit. Made the way
    every results folder is (`results.folder`): `Refused` where it, or `.lantern`, is a link that came with the
    project (until 2026-11-17 the `.gitignore` was written through such a link, wherever it pointed)."""
    from . import results
    where = results.folder(top, results.folder(top, None) / "push")
    if results.plain(where / ".gitignore")[0] != IGNORED:
        results.write(where / ".gitignore", IGNORED, newline="\n")
    return where


def _slug(ref: str) -> str:
    short = re.sub(r"^refs/(heads/)?", "", ref)
    return (re.sub(r"[^A-Za-z0-9._-]+", "-", short).strip(".-") or "push")[:60]


def run(folder, remote: str | None, lines: list[str], say=None) -> int:
    """Check what git says is being pushed (`lines`, as git hands them to a pre-push hook). 0: nothing in it blocks
    a release (or nothing is pushed); 1: a change brings what blocks a release, and git stops the push; 2: Lantern
    could not check it, and git stops the push too (with the way to push without the check)."""
    from . import diff, gitfacts, pipeline, programs
    say = say or (lambda line: print(line, file=sys.stderr, flush=True))
    began = time.perf_counter()
    pushes = []
    for line in lines:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 4 or not HEX.fullmatch(parts[1]) or not HEX.fullmatch(parts[3]):
            say("lantern  could not read what git said is being pushed, so the push was not checked. " + NO_VERIFY)
            return 2
        pushes.append(parts)
    repo = gitfacts.find(folder)
    if repo is None:
        say(f"lantern  {NOT_A_REPO} {NO_VERIFY}")
        return 2
    worst = 0
    for local_ref, local, remote_ref, theirs in pushes:
        name = _shown(re.sub(r"^refs/(heads/|tags/)?", "", local_ref), 80)
        if ZERO.fullmatch(local):
            say(f"lantern  {_shown(remote_ref, 80)} is taken away on {_shown(remote or 'the other side', 80)}: "
                "no code is sent, nothing to check")
            continue
        try:
            head = gitfacts.resolve(repo.top, local)
            base, what = _base(repo.top, remote, theirs, head)
            say(f"lantern  checking the push of {name}: {head[:12]} after {base[:12] if base else 'nothing'} ({what})")
            out = _receipts(repo.top) / _slug(local_ref)
            quiet = lambda _line: None      # noqa: E731
            if base is None:                # compared with nothing: the check of an empty folder
                with programs.folder() as own:
                    (own / "nothing").mkdir()
                    pipeline.analyze(own / "nothing", own / "out", offline=True, log=quiet)
                    got = pipeline.change(repo.top, f"{head}..{head}", out=out, offline=True, log=quiet,
                                          base_results=own / "out", base_label="nothing",
                                          head_label=f"the push of {name}")
            else:
                got = pipeline.change(repo.top, f"{base}..{head}", out=out, offline=True, log=quiet,
                                      base_label=what, head_label=f"the push of {name}")
        except (gitfacts.NoCommit, diff.NotResults, RuntimeError, OSError) as e:
            say(f"lantern  could not check the push of {name}: {_shown(e, 400)}")
            say(f"lantern  {NO_VERIFY}")
            worst = max(worst, 2)
            continue
        receipt = got["receipt"]
        rows = diff.blockers(receipt)
        where = Path(got["paths"]["html"])
        with_time = f"({time.perf_counter() - began:.1f} s)"
        if rows:
            say(f"lantern  stopped: this push brings what blocks a release {with_time}")
            for row in rows[:MOST_SAID]:
                say(f"lantern    - {_shown(row['words'])}")
            if len(rows) > MOST_SAID:
                say(f"lantern    and {len(rows) - MOST_SAID} more")
            worst = max(worst, 1)
        else:
            after = ((receipt.get("release") or {}).get("after") or {}).get("decision")
            say(f"lantern  checked {with_time}: nothing in it blocks a release"
                + (" (the release decision was Blocked before this push, for what was there already)"
                   if after == "Blocked" else ""))
        for limit in [x for x in receipt.get("limits") or [] if not diff.standing(x)][:MOST_LIMITS]:
            say(f"lantern  not checked: {_shown(limit, 400)}")
        say(f"lantern  read from the code (the tests are not run); the receipt, with what such a check cannot see: "
            f"{where}")
    if worst:
        say(f"lantern  {NO_VERIFY}")
    return worst
