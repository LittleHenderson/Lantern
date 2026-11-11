"""Lantern deletes only what it made, never through a link, and says when it could not (lantern/removal.py).

Stage 7 of the 2026-11-09 directive, part 2 ("Fix silent report-retention cleanup failures. Record and safely retry
failed cleanup without deleting user-owned source folders. Test path, link and ownership boundaries."). Each
dangerous case has a safe twin: the same call on a folder Lantern did make removes it.

* `removal.remove`: a whole folder goes (read-only files, folders with every right taken off, links); a link is
  removed as a link; a folder nested deeper than Python can recurse, and deeper than a path can be long, goes with a
  handful of open files; a folder swapped for a link or moved away in the middle is not followed; another disk
  attached inside is not entered; and a failure is said in Lantern's own words, with nothing outside changed.
* `removal.ours`: the name, link, kind and owner boundaries of what a sweep may delete.
* The test sandbox's temp folder: written down when it could not be deleted, deleted the next time, and left alone
  when the thing at that place is no longer the folder Lantern made.
* `remote`: a failed clone removes what it made and nothing else.

The cloud service's side (results, work folders, uploads, the record of what is owed): tests/test_cloud_cleanup.py.
"""
import json
import os
import re
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest
from test_sandbox_safety import PYTEST, QUIET, _project

from lantern import removal, remote, sandbox

ROOT = Path(sandbox.__file__).resolve().parent.parent
only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (links, modes, folders held open)")
RUN = re.compile(r"run-[a-z0-9_]{8}")


def _tree(root: Path) -> Path:
    (root / "app" / "sub").mkdir(parents=True)
    (root / "app" / "sub" / "f.txt").write_text("x", encoding="utf-8")
    (root / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    return root


def _mode(p) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


def _deep(root: Path, levels: int) -> None:
    """`levels` folders inside each other, made one at a time (the whole path may be longer than a path can be)."""
    root.mkdir()
    fd = os.open(root, os.O_RDONLY)
    try:
        for _ in range(levels):
            os.mkdir("d", dir_fd=fd)
            nxt = os.open("d", os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = nxt
        with open(os.open("leaf.txt", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w", encoding="utf-8") as f:
            f.write("x")
    finally:
        os.close(fd)


def _rm_rf(path) -> None:
    """A test's own clean-up of a tree pytest could not remove itself (too deep, or with rights taken off)."""
    if os.path.lexists(path):
        subprocess.run(["chmod", "-R", "u+rwx", "--", str(path)], capture_output=True)
        subprocess.run(["rm", "-rf", "--", str(path)], capture_output=True)


# ---------------------------------------------------------------------------- removal.remove
def test_a_folder_goes_whole_read_only_files_included(tmp_path):
    root = _tree(tmp_path / "made")
    os.chmod(root / "app" / "sub" / "f.txt", stat.S_IREAD)
    assert removal.remove(root) is None and not root.exists()
    assert removal.remove(root) is None                      # nothing there: nothing is left, which is the answer
    one = tmp_path / "one.txt"
    one.write_text("x", encoding="utf-8")
    assert removal.remove(one) is None and not one.exists()  # a single file goes too


@only_posix
def test_folders_with_every_right_taken_off_and_links_go_and_nothing_a_link_points_at_is_touched(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("kept", encoding="utf-8")
    os.chmod(outside / "kept.txt", 0o444)
    os.chmod(outside, 0o555)
    root = _tree(tmp_path / "made")
    os.symlink(outside, root / "app" / "link-to-a-folder")
    os.symlink(outside / "kept.txt", root / "app" / "link-to-a-file")
    os.symlink(tmp_path / "nothing-here", root / "app" / "link-to-nothing")
    closed = root / "app" / "closed"
    (closed / "inner").mkdir(parents=True)
    (closed / "inner" / "x.txt").write_text("x", encoding="utf-8")
    os.chmod(closed / "inner", 0o000)
    os.chmod(closed, 0o000)
    os.chmod(root / "app" / "sub", 0o555)
    try:
        assert removal.remove(root) is None and not root.exists()
        assert _mode(outside) == 0o555 and _mode(outside / "kept.txt") == 0o444, "a mode outside the folder was changed"
        assert (outside / "kept.txt").read_text(encoding="utf-8") == "kept"
    finally:
        os.chmod(outside, 0o755)
        _rm_rf(root)


@only_posix
def test_a_link_is_removed_as_a_link(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("kept", encoding="utf-8")
    os.chmod(outside, 0o555)
    holder = tmp_path / "holder"
    holder.mkdir()
    os.chmod(holder, 0o1777)
    link = holder / "made"
    os.symlink(outside, link)
    try:
        assert removal.remove(link) is None and not os.path.lexists(link)
        assert _mode(outside) == 0o555 and (outside / "kept.txt").read_text(encoding="utf-8") == "kept"
        assert _mode(holder) == 0o1777, "the mode of the folder that held the link was changed"
    finally:
        os.chmod(outside, 0o755)


def test_what_could_not_be_removed_is_said_without_a_name_from_inside(tmp_path, monkeypatch):
    holder = tmp_path / "holder"
    holder.mkdir()
    before = _mode(holder)
    root = _tree(holder / "made")
    (root / "app" / "secret-name.txt").write_text("x", encoding="utf-8")
    real = os.unlink

    def unlink(path, *a, **kw):
        if os.path.basename(os.fspath(path)) == "secret-name.txt":
            raise PermissionError(13, "in use", os.fspath(path))
        return real(path, *a, **kw)
    monkeypatch.setattr(os, "unlink", unlink)
    why = removal.remove(root)
    assert isinstance(why, str) and "could not be removed" in why and "PermissionError" in why, why
    assert "secret-name" not in why and str(tmp_path) not in why, "a name from inside the folder is in the sentence"
    assert (root / "app" / "secret-name.txt").exists()
    assert not (root / "app" / "main.py").exists() and not (root / "app" / "sub").exists()   # what could go, went
    assert _mode(holder) == before, "the mode of the folder that holds it was changed"
    monkeypatch.setattr(os, "unlink", real)
    assert removal.remove(root) is None and not root.exists()   # and once it can be removed, it is


@only_posix
@pytest.mark.parametrize("levels", [1500, 2500])     # deeper than Python recurses; deeper than a path can be long
def test_a_folder_nested_very_deep_is_removed_with_a_handful_of_open_files(tmp_path, levels):
    """Until 2026-11-10 the standard library did this, by calling itself once per level: RecursionError at about a
    thousand levels on Python 3.11 and 3.12 (which left a cloud run "running" for good and the service unable to
    start), and from 3.13 on one open file per level, which the system's limit ends."""
    root = tmp_path / "lantern-sandbox-deep"
    _deep(root, levels)
    script = ("import os, resource, sys\n"
              "sys.path.insert(0, sys.argv[1])\n"
              "from lantern import sandbox\n"
              "soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)\n"
              "resource.setrlimit(resource.RLIMIT_NOFILE, (min(64, soft), hard))\n"
              "print('GONE' if sandbox._rm(sys.argv[2]) else 'LEFT', flush=True)\n")
    try:
        r = subprocess.run([sys.executable, "-c", script, str(ROOT), str(root)], capture_output=True, text=True,
                           encoding="utf-8", timeout=300)
        assert r.stdout.strip() == "GONE" and not root.exists(), (r.stdout + r.stderr)[-600:]
    finally:
        _rm_rf(root)


@only_posix
def test_a_folder_swapped_for_a_link_in_the_middle_is_not_followed(tmp_path, monkeypatch):
    """What the standard library also gets right; kept so that it stays right."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("kept", encoding="utf-8")
    root = _tree(tmp_path / "made")
    victim = root / "app" / "victim"
    victim.mkdir()
    real, swapped = os.open, []

    def swap_then_open(path, flags, *a, **kw):
        if os.fspath(path) == "victim" and not swapped:
            swapped.append(1)
            os.rmdir(victim)
            os.symlink(outside, victim)
        return real(path, flags, *a, **kw)
    monkeypatch.setattr(os, "open", swap_then_open)
    assert removal.remove(root) is None and not root.exists()
    monkeypatch.setattr(os, "open", real)
    assert swapped and (outside / "kept.txt").read_text(encoding="utf-8") == "kept"


@only_posix
def test_a_folder_moved_away_in_the_middle_ends_the_removal_and_its_new_place_is_not_touched(tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "kept.txt").write_text("kept", encoding="utf-8")
    root = tmp_path / "made"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "c.txt").write_text("x", encoding="utf-8")
    real, moved = os.open, []

    def move_then_open(path, flags, *a, **kw):
        if os.fspath(path) == ".." and not moved:
            moved.append(1)
            os.rename(root / "a" / "b", elsewhere / "b")
        return real(path, flags, *a, **kw)
    monkeypatch.setattr(os, "open", move_then_open)
    why = removal.remove(root)
    monkeypatch.setattr(os, "open", real)
    assert moved and why and "moved" in why, why
    assert (elsewhere / "kept.txt").read_text(encoding="utf-8") == "kept" and (elsewhere / "b").is_dir()
    assert removal.remove(root) is None                      # the next try, with nothing moving, removes what is left


@only_posix
def test_another_disk_attached_inside_is_not_entered(tmp_path, monkeypatch):
    root = _tree(tmp_path / "made")
    mounted = root / "app" / "mounted"
    mounted.mkdir()
    (mounted / "theirs.txt").write_text("theirs", encoding="utf-8")
    ino, real = os.lstat(mounted).st_ino, removal._stat_fd

    def stat_fd(fd):
        st = real(fd)
        if st.st_ino != ino:
            return st
        return types.SimpleNamespace(st_dev=st.st_dev + 1, st_ino=st.st_ino, st_mode=st.st_mode, st_uid=st.st_uid)
    monkeypatch.setattr(removal, "_stat_fd", stat_fd)
    why = removal.remove(root)
    assert why and "another disk" in why, why
    assert (mounted / "theirs.txt").read_text(encoding="utf-8") == "theirs"
    assert not (root / "app" / "main.py").exists()           # the rest of the folder went
    monkeypatch.setattr(removal, "_stat_fd", real)
    assert removal.remove(root) is None


def test_the_sandbox_and_a_clone_are_removed_the_same_way(tmp_path):
    a, b = _tree(tmp_path / "lantern-sandbox-a"), _tree(tmp_path / "clone")
    assert sandbox._rm(a) is True and not a.exists()
    assert remote.remove_tree(b) is None and not b.exists()


# ---------------------------------------------------------------------------- removal.ours
@pytest.mark.parametrize("name", ["", ".", "..", "run-abc", "a/run-abcd1234", "../run-abcd1234", "run-abcd1234/",
                                  "/etc", "RUN-ABCD1234", "run-abcd1234\x00", "my-project", None, 7])
def test_a_name_lantern_would_not_give_is_never_lanterns(tmp_path, name):
    (tmp_path / "run-abcd1234").mkdir()
    (tmp_path / "my-project").mkdir()
    assert removal.ours(tmp_path, name, RUN) == "name"


def test_only_a_real_folder_or_file_of_the_right_kind_is_lanterns(tmp_path):
    (tmp_path / "run-abcd1234").mkdir()
    (tmp_path / "run-file0000").write_text("x", encoding="utf-8")
    assert removal.ours(tmp_path, "run-abcd1234", RUN) is None                 # the safe twin: Lantern's own folder
    assert removal.ours(tmp_path, "run-file0000", RUN, "file") is None
    assert removal.ours(tmp_path, "run-file0000", RUN) == "kind"               # a file where a folder is kept
    assert removal.ours(tmp_path, "run-abcd1234", RUN, "file") == "kind"
    assert removal.ours(tmp_path, "run-gone0000", RUN) == "gone"
    assert removal.ours(tmp_path / "no-such-folder", "run-abcd1234", RUN) == "gone"
    assert set(removal.WHY) >= {"name", "link", "kind", "owner"}


@only_posix
def test_a_link_with_the_right_name_is_not_lanterns(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f.txt").write_text("x", encoding="utf-8")
    os.symlink(outside, tmp_path / "run-link0000")
    os.symlink(outside / "f.txt", tmp_path / "run-link1111")
    os.symlink(tmp_path / "nothing", tmp_path / "run-link2222")
    assert removal.ours(tmp_path, "run-link0000", RUN) == "link"
    assert removal.ours(tmp_path, "run-link1111", RUN, "file") == "link"
    assert removal.ours(tmp_path, "run-link2222", RUN) == "link"


@only_posix
def test_what_belongs_to_another_user_is_not_lanterns(tmp_path, monkeypatch):
    d = tmp_path / "run-abcd1234"
    d.mkdir()
    assert removal.ours(tmp_path, "run-abcd1234", RUN) is None
    me = os.geteuid()
    if me == 0:
        os.chown(d, 65534, 65534)                       # really another user's
    else:
        monkeypatch.setattr(os, "geteuid", lambda: me + 1)   # Lantern runs as someone else than the folder's owner
    assert removal.ours(tmp_path, "run-abcd1234", RUN) == "owner"


# ---------------------------------------------------------------------------- the sandbox's temp folder, tried again
def _left(tmp_path, name="lantern-sandbox-abcd1234") -> Path:
    root = tmp_path / name
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    return root


def test_a_noted_folder_is_deleted_at_the_next_try(tmp_path):
    root = _left(tmp_path)
    removal.note(root, "1 thing in it could not be removed")
    removal.note(root)                                                   # a second note of the same folder adds nothing
    assert [n["path"] for n in removal.noted()] == [str(root)]
    r = removal.retry_noted()
    assert r["removed"] == 1 and r["waiting"] == [] and not root.exists() and removal.noted() == []
    assert removal.retry_noted() == {"removed": 0, "waiting": [], "dropped": 0}


def test_a_noted_folder_that_still_cannot_be_deleted_stays_noted(tmp_path, monkeypatch):
    root = _left(tmp_path)
    removal.note(root)
    real = os.rmdir

    def rmdir(path, *a, **kw):
        if os.path.basename(os.fspath(path)) == root.name:
            raise PermissionError(13, "in use", os.fspath(path))
        return real(path, *a, **kw)
    monkeypatch.setattr(os, "rmdir", rmdir)
    r = removal.retry_noted()
    assert r["removed"] == 0 and r["waiting"] == [str(root)] and root.exists()
    assert [(n["path"], n["tried"]) for n in removal.noted()] == [(str(root), 1)]
    monkeypatch.setattr(os, "rmdir", real)
    assert removal.retry_noted()["removed"] == 1 and not root.exists() and removal.noted() == []


def test_a_noted_place_that_now_holds_another_folder_is_left_alone(tmp_path):
    root = _left(tmp_path)
    removal.note(root)
    root.rename(tmp_path / "moved-away")
    other = _left(tmp_path)                                              # another folder, same place, same name
    (other / "mine.txt").write_text("mine", encoding="utf-8")
    r = removal.retry_noted()
    assert r == {"removed": 0, "waiting": [], "dropped": 1}
    assert (other / "mine.txt").read_text(encoding="utf-8") == "mine" and (tmp_path / "moved-away" / "app").is_dir()
    assert removal.noted() == []                                         # the note was about a folder that is gone from there


@only_posix
def test_a_noted_place_that_now_holds_a_link_is_left_alone(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("kept", encoding="utf-8")
    root = _left(tmp_path)
    removal.note(root)
    root.rename(tmp_path / "moved-away")
    os.symlink(outside, root)
    assert removal.retry_noted()["removed"] == 0
    assert os.path.islink(root) and (outside / "kept.txt").read_text(encoding="utf-8") == "kept"


def test_planted_notes_delete_nothing(tmp_path):
    mine = tmp_path / "my-project"
    (mine / "src").mkdir(parents=True)
    (mine / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    st = os.lstat(mine)
    shaped = _left(tmp_path, "lantern-sandbox-zzzz9999")
    home = removal.home()
    home.mkdir(parents=True, exist_ok=True)
    (home / removal.NOTES).write_text(json.dumps({"folders": [
        {"path": str(mine), "dev": st.st_dev, "ino": st.st_ino},                 # the person's folder, exactly: not a name Lantern gives
        {"path": str(shaped), "dev": st.st_dev, "ino": st.st_ino},               # the right name, but not the folder that was noted
        {"path": "lantern-sandbox-abcd1234", "dev": 1, "ino": 1},                # not a whole path
        {"path": str(tmp_path / "x" / ".." / "lantern-sandbox-zzzz9999"), "dev": 1, "ino": 1},
        {"path": str(shaped)}, "nonsense", 7, None, ["a"]]}), encoding="utf-8")
    r = removal.retry_noted()
    assert r["removed"] == 0 and r["waiting"] == []
    assert (mine / "src" / "a.py").is_file() and (shaped / "app" / "main.py").is_file()
    assert removal.noted() == []
    (home / removal.NOTES).write_text("{not json", encoding="utf-8")
    assert removal.retry_noted() == {"removed": 0, "waiting": [], "dropped": 0} and removal.noted() == []


def test_a_sandbox_folder_that_could_not_be_deleted_is_deleted_by_the_next_run(tmp_path, monkeypatch):
    repo = _project(tmp_path, QUIET)
    real = sandbox._rm
    monkeypatch.setattr(sandbox, "_rm", lambda path: False)
    lines = []
    assert sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)["returncode"] == 0
    left = [Path(x.split("still there: ", 1)[1]) for x in lines if "still there: " in x]
    assert len(left) == 1 and left[0].is_dir()
    try:
        assert [n["path"] for n in removal.noted()] == [str(left[0])]
        monkeypatch.setattr(sandbox, "_rm", real)
        again = []
        assert sandbox.run(repo, PYTEST, log=again.append, backend="subprocess", timeout=120)["returncode"] == 0
        assert not left[0].exists() and removal.noted() == []
        assert any("an earlier run could not delete" in x for x in again), again
    finally:
        _rm_rf(left[0])


def test_a_project_that_cannot_be_copied_is_not_run_and_the_reason_is_said(tmp_path, monkeypatch):
    """Folders nested deeper than Python recurses stop the copy with RecursionError, which is no OSError."""
    repo = _project(tmp_path, QUIET)

    def too_deep(src, dst):
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(sandbox, "_copy", too_deep)
    lines = []
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    assert "could not be copied" in str(e.value) and "nested too deep" in str(e.value)
    assert not any("PLANTED-RAN" in x for x in lines)


# ---------------------------------------------------------------------------- a failed clone removes only what it made
def test_a_copy_into_a_folder_that_holds_files_is_refused_and_the_files_stay(tmp_path):
    mine = tmp_path / "my-app"
    (mine / "src").mkdir(parents=True)
    (mine / "src" / "main.py").write_text("print('mine')\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as e:
        remote.fetch((tmp_path / "no-such-repository").as_uri(), mine)
    assert "is not empty" in str(e.value)
    assert (mine / "src" / "main.py").read_text(encoding="utf-8") == "print('mine')\n"


def test_a_failed_copy_into_a_new_or_empty_folder_leaves_nothing(tmp_path):
    new, empty = tmp_path / "new", tmp_path / "empty"
    empty.mkdir()
    for dest in (new, empty):                                            # the safe twin: what the copy made is removed
        with pytest.raises(RuntimeError):
            remote.fetch((tmp_path / "no-such-repository").as_uri(), dest)
        assert not dest.exists()


@only_posix
def test_removing_a_clone_that_is_a_link_changes_nothing_it_points_at(tmp_path):
    shared = tmp_path / "shared"
    kept = shared / "kept"
    kept.mkdir(parents=True)
    (kept / "keep.txt").write_text("keep", encoding="utf-8")
    os.chmod(kept, 0o755)
    os.chmod(shared, 0o1777)
    link = shared / "clone"
    os.symlink(kept, link)
    assert remote.remove_tree(link) is None and not os.path.lexists(link)
    assert _mode(kept) == 0o755 and _mode(shared) == 0o1777, "a mode outside the clone was changed"
    assert (kept / "keep.txt").read_text(encoding="utf-8") == "keep"


def _too_big(tmp_path) -> Path:
    """A repository whose one file is over a 1 MB limit, and a folder that holds only its `.git` (no files yet)."""
    def git(*args, cwd):
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, encoding="utf-8")
    src = tmp_path / "origin"
    src.mkdir()
    (src / "big.py").write_text("x = 1\n" * 300_000, encoding="utf-8")
    git("init", "-q", "-b", "main", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x", cwd=src)
    dest = tmp_path / "theirs"
    git("clone", "-q", "--no-checkout", src.as_uri(), str(dest), cwd=tmp_path)
    return dest


def test_a_checkout_that_fails_removes_a_lantern_clone_but_not_a_folder_of_the_persons(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_CLONE_MAX_MB", "1")
    theirs = _too_big(tmp_path)                     # the person's own repository folder, with no files checked out
    with pytest.raises(RuntimeError) as e:
        remote.clone("https://github.com/octo/shop", dest=theirs)
    assert "above Lantern's 1 MB limit" in str(e.value)
    assert (theirs / ".git").is_dir(), "a folder Lantern did not clone was deleted"
    remote._mark(theirs)                            # the safe twin: the same folder, cloned by Lantern
    with pytest.raises(RuntimeError):
        remote.clone("https://github.com/octo/shop", dest=theirs)
    assert not theirs.exists()
