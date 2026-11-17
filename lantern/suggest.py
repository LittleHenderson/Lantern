"""A fix that stands in another folder, put onto Lantern's own copy of the project so that it can be held to the fix
contract, and written out as a suggested change only when it passed (roadmap of 2026-11-14, stage 3).

The candidate is a folder: the project with a fix in it (a second checkout, the folder a coding assistant worked in).
It is never analyzed where it stands and nothing in it is run. `change(repo, candidate)` lists the files that differ
between the project and the candidate, by the one walk Lantern copies a project with (`agents._files`: plain files
only, the folders every reader leaves out not entered). `lay(repo, candidate, copy, got)` makes `copy` the project
with exactly that change in it, and `patch(repo, candidate, got)` writes that change as text. So what is analyzed,
what the tests run on and what is written out are one and the same change, by how they are made: a change the
candidate makes anywhere else (inside `node_modules` or `build`, to a link) is in none of the three.

Lantern applies nothing to the project and sends nothing anywhere: the text is for a person to read and apply
(`git apply`, `patch -p1`).
"""
from __future__ import annotations

import difflib
import os
import shutil
from pathlib import Path

from .python_frontend import project_bytes

MOST_FILE = 2 << 20         # characters of one side of one file in a suggested change
MOST_PATCH = 8 << 20        # characters of a whole suggested change
CONTEXT = 3
NOT_TEXT = "is not text a patch can carry (it is not UTF-8 text, or holds a NUL)"


def _real(p) -> str:
    return os.path.realpath(p)


def change(repo: Path, candidate: Path) -> dict:
    """The files that differ between the project and the candidate: `{"before": {path: sha256}, "after": {…},
    "files": [path, …]}`. ValueError (a sentence for the person) when the candidate is no folder, is the project's
    own folder, lies inside it or around it, is too big to copy, or holds the same files."""
    from .agents import _files
    repo, candidate = Path(repo), Path(candidate)
    if not candidate.is_dir():
        raise ValueError("The candidate is not a folder. Give the folder that holds the project with the fix in it.")
    a, b = _real(repo), _real(candidate)
    if a == b:
        raise ValueError("The candidate is the project's own folder. To check a fix made in the project itself, "
                         "leave --candidate out.")
    if (b + os.sep).startswith(a + os.sep) or (a + os.sep).startswith(b + os.sep):
        raise ValueError("The candidate lies inside the project's folder, or the project inside the candidate, so "
                         "each would be read as a part of the other. Put the copy with the fix beside the project.")
    before, after = _files(repo), _files(candidate)
    files = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    if not files:
        raise ValueError("The candidate holds the same files as the project: there is no change to check.")
    return {"before": before, "after": after, "files": files}


def _place(copy: Path, rel: str) -> Path:
    """Where `rel` goes in Lantern's copy, its folders made one by one. Nothing is ever written through a link: a
    link that stands where a folder is needed stops the check (ValueError)."""
    at = copy
    parts = Path(rel).parts
    for part in parts[:-1]:
        at = at / part
        if at.is_symlink() or (at.exists() and not at.is_dir()):
            raise ValueError("The candidate has a folder where the project has a link or a file, which Lantern does "
                             "not copy over: this change cannot be checked as a suggested change.")
        if not at.exists():
            at.mkdir(mode=0o700)
    dst = at / parts[-1]
    if dst.is_symlink():
        os.unlink(dst)
    elif dst.is_dir():
        raise ValueError("The candidate has a file where the project has a folder, which Lantern does not copy "
                         "over: this change cannot be checked as a suggested change.")
    return dst


def _runs(root: Path, rel: str) -> bool:
    """Whether the file is marked as a program. Windows has no such mark."""
    if os.name == "nt":
        return False
    try:
        return bool(os.stat(root / rel, follow_symlinks=False).st_mode & 0o111)
    except OSError:
        return False


def _put(copy: Path, rel: str, root: Path) -> None:
    data = project_bytes(root / rel, root)
    dst = _place(copy, rel)
    with open(dst, "wb") as f:
        f.write(data)
    if os.name != "nt":
        os.chmod(dst, 0o755 if _runs(root, rel) else 0o644)


def lay(repo: Path, candidate: Path, copy: Path, got: dict, whole: bool = False) -> None:
    """Make `copy` (a folder of Lantern's own that is not there yet) the project with the candidate's change in it.
    `whole`: everything a run of the project's tests gets (`sandbox._copy`), for when tests will run on it;
    otherwise the files Lantern reads and copies, which is all an analysis needs. Then each changed file is put
    there as the candidate has it, and each file the candidate no longer has is taken away. ValueError (a
    sentence) when the project cannot be copied or a changed file went away meanwhile."""
    repo, candidate, copy = Path(repo), Path(candidate), Path(copy)
    try:
        if whole:
            from .sandbox import _copy
            _copy(repo, copy)
        else:
            copy.mkdir(parents=True, mode=0o700)
            for rel in got["before"]:
                _put(copy, rel, repo)
        for rel in got["files"]:
            if rel in got["after"]:
                _put(copy, rel, candidate)
            else:
                dst = copy / rel
                if dst.is_symlink() or dst.is_file():
                    os.unlink(dst)
    except FileNotFoundError:
        raise ValueError("A file of the project or of the candidate went away while it was copied. Nothing was "
                         "checked; try again when nothing else is changing the two folders.") from None
    except (shutil.Error, OSError):
        raise ValueError("The project could not be copied for the check (a file that cannot be read, or no room "
                         "left). Nothing was checked.") from None


def _plain(rel: str) -> bool:
    """A name a patch carries as it is written: printable ASCII with no quote and no backslash, and no part of it
    begins or ends with a space."""
    return (all(" " <= c <= "~" and c not in '"\\' for c in rel)
            and all(part == part.strip() and part for part in rel.split("/")))


def _text(root: Path, rel: str) -> str | None:
    try:
        text = project_bytes(root / rel, root).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if "\x00" in text or len(text) > MOST_FILE else text


def _lines(text: str) -> list[str]:
    """Lines as a patch counts them: ended by a line feed and by nothing else (Python's own `splitlines` also ends a
    line at a form feed and at a dozen other characters, which `git apply` and `patch` do not)."""
    parts = text.split("\n")
    return [x + "\n" for x in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def _hunks(a: list[str], b: list[str]) -> list[str]:
    out = []
    for i, line in enumerate(difflib.unified_diff(a, b, "a", "b", n=CONTEXT)):
        if i < 2:           # difflib's own two name lines; the names are written by `patch`
            continue
        out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return out


def patch(repo: Path, candidate: Path, got: dict, said=()) -> tuple[str | None, str | None]:
    """The change as text that `git apply` and `patch -p1` take in the project's folder: `(text, None)`, or
    `(None, why)` when it cannot be written as text. `said`: lines put at the top, each behind `# `."""
    repo, candidate = Path(repo), Path(candidate)
    out = ["# " + "".join(c if " " <= c <= "~" else "?" for c in str(line)) + "\n" for line in said]
    size = sum(len(x) for x in out)
    for rel in got["files"]:
        if not _plain(rel):
            return None, ("a changed file has a name a patch cannot carry as it is written (a character outside "
                          "plain ASCII, a quote, a backslash, or a space at an end)")
        had, has = rel in got["before"], rel in got["after"]
        old = _text(repo, rel) if had else ""
        new = _text(candidate, rel) if has else ""
        if old is None or new is None:
            return None, f"{rel} {NOT_TEXT}, or is over {MOST_FILE >> 20} MB"
        tab = "\t" if " " in rel else ""
        piece = [f"diff --git a/{rel} b/{rel}\n"]
        was = "100755" if had and _runs(repo, rel) else "100644"
        now = "100755" if has and _runs(candidate, rel) else "100644"
        if not had:
            piece.append(f"new file mode {now}\n")
        elif not has:
            piece.append(f"deleted file mode {was}\n")
        elif was != now:
            piece += [f"old mode {was}\n", f"new mode {now}\n"]
        hunks = _hunks(_lines(old), _lines(new))
        if hunks:
            piece += [f"--- a/{rel}{tab}\n" if had else "--- /dev/null\n",
                      f"+++ b/{rel}{tab}\n" if has else "+++ /dev/null\n"] + hunks
        size += sum(len(x) for x in piece)
        if size > MOST_PATCH:
            return None, f"the change is over {MOST_PATCH >> 20} MB of text"
        out += piece
    return "".join(out), None
