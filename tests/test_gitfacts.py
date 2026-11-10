"""What git knows about a folder is read without obeying that folder's own git settings (`lantern/gitfacts.py`).

Found 2026-11-10 (stage 7 of the 2026-11-09 directive). `lantern analyze` asked git about the folder it was given
(`git status` for uncommitted changes, `git ls-files --deleted` for a clone's missing files), and git ran a command
named in that folder's `.git/config`. A folder that brings its own `.git` (an unpacked download, an upload) could
so have a command run with the rights of the person, by a tool that says it only reads code.

Three kinds of test, kept apart on purpose:
* planted: a setting, a pointer or a variable that must not be obeyed (each failed on the code before);
* honest: repositories as people have them, which must get the answers git itself gives (they passed before, too);
* limits: what the new reading deliberately does not read, and says so.
The planted commands only write a marker file.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from lantern import case, evidence, gitfacts, remote
from lantern.cli import main

only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (symbolic links)")
WHEN = {"GIT_AUTHOR_DATE": "2026-11-01T10:00:00+0100", "GIT_COMMITTER_DATE": "2026-11-01T10:00:00+0100"}


def git(*args, cwd, ok=True, env=None) -> str:
    """git as the test itself uses it, on repositories the test made before anything was planted in them."""
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                       env={**os.environ, **WHEN, **(env or {})}, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0 or not ok, (args, r.stderr)
    return r.stdout.strip()


def write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode("utf-8"))
    return p


def make(tmp_path: Path, name: str = "app", *init, line: str = "print('hello')") -> Path:
    d = tmp_path / name
    d.mkdir(parents=True)
    git("init", "-q", "-b", "main", *init, cwd=d)
    write(d / "app.py", line + "\n")
    write(d / "sub" / "b.py", "x = 1\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "one", cwd=d)
    return d


def git_says(d: Path) -> dict:
    """What git answers for an honest repository: the questions Lantern asked before 2026-11-10, word for word."""
    return {"commit": git("rev-parse", "HEAD", cwd=d), "branch": git("rev-parse", "--abbrev-ref", "HEAD", cwd=d),
            "dirty": bool(git("status", "--porcelain", "--untracked-files=no", cwd=d)),
            "remote": git("config", "--get", "remote.origin.url", cwd=d, ok=False) or None,
            "committed_at": git("log", "-1", "--format=%cI", cwd=d)}


def command(mark: Path) -> str:
    """A shell command for a git setting; all it does is write the marker."""
    return f"echo ran >> '{mark.as_posix()}'"


def plant(config: Path, text: str) -> None:
    with open(config, "a", encoding="utf-8", newline="\n") as f:
        f.write(text)


def fsmonitor(mark: Path) -> str:
    return f'[core]\n\tfsmonitor = "{command(mark)}; false"\n'


def touched(p: Path) -> None:
    os.utime(p, (1, 1))     # the file looks changed to git, which then has to read it again to compare


# ---------------------------------------------------------------------------- planted: nothing is run

@pytest.mark.parametrize("ask", ["the commit facts", "lantern analyze", "a folder that carries Lantern's clone mark"])
def test_a_command_planted_in_the_folders_git_settings_is_not_run(ask, tmp_path, capsys):
    d = make(tmp_path)
    write(d / ".gitignore", ".lantern/\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "two", cwd=d)
    commit, mark = git("rev-parse", "HEAD", cwd=d), tmp_path / "MARK"
    plant(d / ".git" / "config", fsmonitor(mark))
    touched(d / "app.py")
    if ask == "the commit facts":
        got = evidence.git_info(d)
        assert (got["commit"], got["branch"], got["dirty"]) == (commit, "main", False)
    elif ask == "lantern analyze":
        assert main(["analyze", str(d), "--no-scan"]) == 0
        head = json.loads((d / ".lantern" / "evidence.json").read_text(encoding="utf-8"))["header"]
        assert (head["commit"], head["dirty"]) == (commit, False)
    else:
        write(d / ".git" / remote.MARK, "cloned by Lantern\n")       # anyone can write this mark into a folder
        assert remote.is_clone(d)
        remote.check_complete(d)                                     # nothing is missing: no error
        assert remote.missing_files(d) == []
    assert not mark.exists(), "git ran the command planted in the folder's settings"


def test_a_planted_filter_is_not_run_and_the_unchanged_file_stays_unchanged(tmp_path):
    d = make(tmp_path)
    write(d / ".gitattributes", "*.py filter=planted\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "attributes", cwd=d)
    mark = tmp_path / "MARK"
    plant(d / ".git" / "config", f'[filter "planted"]\n\tclean = "{command(mark)}; cat"\n\tsmudge = cat\n')
    touched(d / "app.py")
    got = evidence.git_info(d)
    assert not mark.exists(), "git ran the filter planted in the folder's settings"
    assert got["dirty"] is False and "note" not in got


def with_submodule(tmp_path: Path) -> tuple[Path, Path]:
    lib = make(tmp_path, "lib", line="print('a library')")
    sup = make(tmp_path, "super")
    git("-c", "protocol.file.allow=always", "submodule", "add", "-q", lib.as_uri(), "vendor/lib", cwd=sup)
    git("commit", "-q", "-m", "with a submodule", cwd=sup)
    return sup, lib


def test_a_submodules_settings_are_not_obeyed_either(tmp_path):
    sup, _lib = with_submodule(tmp_path)
    mark = tmp_path / "MARK"
    plant(sup / ".git" / "modules" / "vendor" / "lib" / "config", fsmonitor(mark))
    touched(sup / "vendor" / "lib" / "app.py")
    got = evidence.git_info(sup)
    assert not mark.exists(), "git was started inside the submodule, under the submodule's own settings"
    assert got["dirty"] is False and "note" not in got


def test_nothing_of_a_whole_set_of_planted_settings_is_run(tmp_path):
    """Every setting of a git folder that can name a program or another file, at once."""
    d = make(tmp_path)
    write(d / ".gitattributes", "*.py filter=planted diff=planted\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "attributes", cwd=d)
    commit, mark, run = git("rev-parse", "HEAD", cwd=d), tmp_path / "MARK", command(tmp_path / "MARK")
    hooks = tmp_path / "hooks"
    for name in ("post-index-change", "pre-commit", "post-checkout", "reference-transaction", "fsmonitor-watchman"):
        write(hooks / name, f"#!/bin/sh\n{run}\n").chmod(0o755)
    write(tmp_path / "gpg.sh", f"#!/bin/sh\n{run}\n").chmod(0o755)
    write(tmp_path / "included.cfg", f'[core]\n\tfsmonitor = "{run}; false"\n')
    plant(d / ".git" / "config",
          f'[core]\n\tfsmonitor = "{run}; false"\n\thooksPath = {hooks.as_posix()}\n\tpager = "{run}"\n'
          f'\tsshCommand = "{run}"\n\teditor = "{run}"\n\tattributesFile = {(tmp_path / "attrs").as_posix()}\n'
          f'[filter "planted"]\n\tclean = "{run}; cat"\n\tsmudge = "{run}; cat"\n\tprocess = "{run}"\n'
          f'[diff "planted"]\n\ttextconv = "{run}; cat"\n\tcommand = "{run}"\n'
          f'[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {(tmp_path / "gpg.sh").as_posix()}\n'
          f'[extensions]\n\tpartialClone = origin\n'
          f'[remote "origin"]\n\turl = "ext::sh -c \\"{run}\\""\n\tpromisor = true\n\tuploadpack = "{run}"\n'
          f'[protocol "ext"]\n\tallow = always\n[alias]\n\tstatus = "!{run}"\n'
          f'[include]\n\tpath = {(tmp_path / "included.cfg").as_posix()}\n')
    touched(d / "app.py")
    got = evidence.git_info(d)
    assert gitfacts.deleted(d) == [] and gitfacts.head_commit(d) == commit
    assert not mark.exists(), "something planted in the folder's git settings was run"
    assert (got["commit"], got["branch"], got["dirty"], got["committed_at"]) == \
        (commit, "main", False, "2026-11-01T10:00:00+01:00") and "note" not in got


def test_only_settings_that_cannot_name_anything_reach_git(tmp_path, monkeypatch):
    d = make(tmp_path)
    plant(d / ".git" / "config",
          '[core]\n\tautocrlf = input\n\tignorecase = true\n\teol = "lf; echo x"\n\tcheckStat = "minimal\\necho"\n'
          '\tfsmonitor = x\n\tsshCommand = x\n\tworktree = /\n\thooksPath = /x\n\tattributesFile = /x\n'
          '\texcludesFile = /x\n[filter "x"]\n\tclean = x\n[alias]\n\tstatus = !x\n[include]\n\tpath = /x\n'
          '[includeIf "gitdir:/"]\n\tpath = /x\n[extensions]\n\tworktreeConfig = true\n[url "x"]\n\tinsteadOf = y\n')
    seen, real = [], remote.run_bounded

    def look(cmd, cwd=None, env=None, timeout=900):
        seen.append((list(cmd), Path(env["GIT_DIR"], "config").read_text(encoding="utf-8"), dict(env), cwd))
        return real(cmd, cwd=cwd, env=env, timeout=timeout)
    monkeypatch.setattr(remote, "run_bounded", look)
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(tmp_path / "elsewhere"))
    assert gitfacts.info(d)["dirty"] is False and gitfacts.deleted(d) == []
    assert len(seen) >= 3                                   # status, the submodule list, the commit; then ls-files
    harmless = {"repositoryformatversion", *(k.split(".", 1)[1] for k in gitfacts.INERT), "bare"}
    for cmd, cfg, env, cwd in seen:
        lines = [ln.strip() for ln in cfg.splitlines()]
        assert lines[0] == "[core]" and all(ln.split(" = ")[0] in harmless for ln in lines[1:]), cfg
        assert "autocrlf = input" in lines and "ignorecase = true" in lines
        assert not any(ln.startswith(("eol", "checkstat")) for ln in lines)       # a value outside the fixed words
        shadow = Path(env["GIT_DIR"])
        assert d not in shadow.parents and shadow != d / ".git"                   # git's folder is Lantern's own
        assert env["GIT_WORK_TREE"] == str(d) and Path(env["GIT_INDEX_FILE"]) == d / ".git" / "index"
        assert Path(env["GIT_OBJECT_DIRECTORY"]) == d / ".git" / "objects"
        assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in env and env["GIT_OPTIONAL_LOCKS"] == "0"
        assert cmd[1:5] == ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={shadow / 'no-hooks'}"]
        assert Path(cwd) == d


def test_asking_writes_nothing_into_the_folder_and_leaves_nothing_behind(tmp_path, monkeypatch):
    d = make(tmp_path)
    touched(d / "app.py")

    def state():
        return {p.relative_to(d).as_posix(): (p.stat().st_mtime_ns, p.stat().st_size)
                for p in sorted(d.rglob("*")) if p.is_file()}
    before = state()
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    assert evidence.git_info(d)["dirty"] is False and gitfacts.deleted(d) == []
    assert state() == before, "asking about the folder changed a file in it"
    assert list(temp.iterdir()) == [], "a git folder Lantern made was left behind"
    git("update-index", "--split-index", cwd=d)                    # the index in two files, one of them shared
    assert list((d / ".git").glob("sharedindex.*"))
    want = git_says(d)                                             # the test's own question: plain git may write
    touched(d / "app.py")
    before = state()
    assert want["dirty"] is False and evidence.git_info(d) == want and gitfacts.deleted(d) == []
    assert state() == before and list(temp.iterdir()) == []


def test_git_variables_of_the_shell_do_not_point_lantern_at_another_repository(tmp_path, monkeypatch):
    """As when Lantern is started from a git hook, where git has set these for its own repository."""
    d = make(tmp_path)
    other = make(tmp_path, "other", line="print('another repository')")
    write(other / "app.py", "print('changed there')\n")
    want = git_says(d)
    assert want["dirty"] is False and git("rev-parse", "HEAD", cwd=other) != want["commit"]
    for name, value in (("GIT_DIR", other / ".git"), ("GIT_WORK_TREE", other), ("GIT_INDEX_FILE", other / ".git" / "index"),
                        ("GIT_OBJECT_DIRECTORY", other / ".git" / "objects"), ("GIT_COMMON_DIR", other / ".git")):
        monkeypatch.setenv(name, str(value))
    assert evidence.git_info(d) == want
    assert gitfacts.deleted(d) == [] and gitfacts.head_commit(d) == want["commit"]


# ---------------------------------------------------------------------------- planted: pointers out of the folder

@pytest.fixture
def other(tmp_path):
    """Another repository of this computer, which a planted pointer wants read and reported."""
    o = make(tmp_path, "other", line="print('somebody else')")
    git("remote", "add", "origin", "https://example.invalid/private/other.git", cwd=o)
    return o


def nothing_of(o: Path, got: dict) -> bool:
    return git("rev-parse", "HEAD", cwd=o) not in json.dumps(got) and "private/other" not in json.dumps(got)


def test_a_git_file_that_names_another_repository_is_not_followed(tmp_path, other):
    d = tmp_path / "app"
    write(d / "app.py", "x = 1\n")
    write(d / ".git", f"gitdir: {(other / '.git').as_posix()}\n")
    got = evidence.git_info(d)
    assert got == {"commit": None, "note": gitfacts.UNREAD} and nothing_of(other, got)
    assert gitfacts.head_commit(d) is None and gitfacts.deleted(d) is None


@pytest.mark.parametrize("where", ["in the .git folder", "in a worktree folder that points back"])
def test_a_planted_commondir_does_not_have_another_repository_read(where, tmp_path, other):
    if where == "in the .git folder":
        d = make(tmp_path)
        write(d / ".git" / "commondir", (other / ".git").as_posix() + "\n")
    else:
        d = tmp_path / "app"
        write(d / "app.py", "x = 1\n")
        write(d / ".git", "gitdir: x\n")
        write(d / "x" / "gitdir", (d / ".git").as_posix() + "\n")
        write(d / "x" / "HEAD", "ref: refs/heads/main\n")
        write(d / "x" / "commondir", (other / ".git").as_posix() + "\n")
    got = evidence.git_info(d)
    assert got == {"commit": None, "note": gitfacts.UNREAD} and nothing_of(other, got)
    assert gitfacts.head_commit(d) is None


@only_posix
@pytest.mark.parametrize("what", [".git", "refs", "HEAD", "config", "packed-refs", "index", "objects"])
def test_a_link_in_place_of_git_data_is_not_followed(what, tmp_path, other, monkeypatch):
    d = make(tmp_path)
    own = git("rev-parse", "HEAD", cwd=d)
    at = d / ".git" if what == ".git" else d / ".git" / what
    if what == "packed-refs":
        git("pack-refs", "--all", cwd=other)
        shutil.rmtree(d / ".git" / "refs" / "heads")        # the branch could now only come from the linked file
        (d / ".git" / "refs" / "heads").mkdir()
    elif at.is_dir():
        shutil.rmtree(at)
    else:
        at.unlink()
    os.symlink(other / ".git" if what == ".git" else other / ".git" / what, at)
    got = evidence.git_info(d)
    assert nothing_of(other, got), got
    if what == "config":        # the folder's own commit is still read; its settings, which are the link, are not
        assert got["commit"] == own and got["remote"] is None
    elif what in ("index", "objects"):      # the commit is the folder's own; git is not started on linked data
        monkeypatch.setattr(remote, "run_bounded", lambda *a, **k: pytest.fail("git was started"))
        got = evidence.git_info(d)
        assert (got["commit"], got["dirty"], got["note"], got["committed_at"]) == (own, True, gitfacts.UNKNOWN, None)
        assert gitfacts.deleted(d) is None
    else:
        assert got == {"commit": None, "note": gitfacts.UNREAD if what == ".git" else gitfacts.NOT_ONE}
        assert gitfacts.head_commit(d) is None


@pytest.mark.skipif(os.name != "nt", reason="needs Windows (a junction)")
@pytest.mark.parametrize("what", [".git", "refs"])
def test_a_junction_in_place_of_git_data_is_not_followed(what, tmp_path, other):
    import _winapi
    d = make(tmp_path)
    at = d / ".git" if what == ".git" else d / ".git" / what
    for folder, _dirs, files in os.walk(at):    # git's object files are read-only on Windows
        for f in files:
            os.chmod(os.path.join(folder, f), 0o600)
    shutil.rmtree(at)
    _winapi.CreateJunction(str(other / ".git" if what == ".git" else other / ".git" / what), str(at))
    got = evidence.git_info(d)
    assert got["commit"] is None and nothing_of(other, got), got
    assert gitfacts.head_commit(d) is None


def test_a_submodule_whose_git_file_names_another_repository_counts_as_changed(tmp_path, other):
    sup, _lib = with_submodule(tmp_path)
    assert evidence.git_info(sup)["dirty"] is False
    (sup / "vendor" / "lib" / ".git").unlink()
    write(sup / "vendor" / "lib" / ".git", f"gitdir: {(other / '.git').as_posix()}\n")
    got = evidence.git_info(sup)
    assert (got["dirty"], got.get("note")) == (True, gitfacts.UNKNOWN) and nothing_of(other, got)


@pytest.mark.parametrize("name", ["an absolute name", "a name with .."])
def test_a_submodule_entry_that_points_out_of_the_folder_is_not_looked_into(name, tmp_path, other, monkeypatch):
    """The index comes with the folder. git does not let such a name be added, so it is written in by hand."""
    d = tmp_path / "app"
    d.mkdir()
    git("init", "-q", "-b", "main", cwd=d)
    write(d / "zz.py", "x = 1\n")
    git("add", "-A", cwd=d)
    # both written with "/", as git writes names: git prints a name that holds a "\" in quotes (a Windows path)
    target = other.as_posix() if name == "an absolute name" else os.path.relpath(other, d).replace(os.sep, "/")
    stand_in = "m" * len(target.encode())                           # a name of the same length, which git accepts
    git("update-index", "--add", "--cacheinfo", f"160000,{git('rev-parse', 'HEAD', cwd=other)},{stand_in}", cwd=d)
    git("commit", "-q", "-m", "a submodule entry", cwd=d)
    raw = (d / ".git" / "index").read_bytes()
    assert raw.count(stand_in.encode()) == 1
    body = raw[:-20].replace(stand_in.encode(), target.encode())
    (d / ".git" / "index").write_bytes(body + hashlib.sha1(body).digest())      # the index ends with its own checksum
    assert target in git("ls-files", "--stage", cwd=d)                          # git reads the entry as written
    asked, real = [], remote.run_bounded

    def look(cmd, cwd=None, env=None, timeout=900):
        asked.append((env["GIT_WORK_TREE"], cmd[5]))
        return real(cmd, cwd=cwd, env=env, timeout=timeout)
    monkeypatch.setattr(remote, "run_bounded", look)
    got = evidence.git_info(d)
    assert (got["dirty"], got.get("note")) == (True, gitfacts.UNKNOWN) and nothing_of(other, got)
    assert asked and all(where == str(d) for where, _ in asked)     # git was never pointed at the other repository
    assert "status" not in [what for _, what in asked]              # nor asked to compare, which reads through the entry


# ---------------------------------------------------------------------------- what cannot be told is said

def test_when_git_cannot_compare_the_files_count_as_changed_and_the_report_says_why(tmp_path, capsys):
    d = make(tmp_path)
    write(d / ".gitignore", ".lantern/\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "two", cwd=d)
    commit = git("rev-parse", "HEAD", cwd=d)
    (d / ".git" / "index").write_bytes(b"not an index at all")
    got = evidence.git_info(d)
    assert got["commit"] == commit and got["dirty"] is True, f"said unchanged although git could not tell: {got}"
    assert got["note"] == gitfacts.UNKNOWN
    assert main(["analyze", str(d), "--no-scan"]) == 0
    page = (d / ".lantern" / "evidence.html").read_text(encoding="utf-8")
    assert "with uncommitted changes" in page and "git could not compare the files with the commit" in page


def test_a_git_folder_that_is_not_read_is_named_on_the_evidence_page(tmp_path, other, capsys):
    d = tmp_path / "app"
    write(d / "app.py", "x = 1\n")
    write(d / ".git", f"gitdir: {(other / '.git').as_posix()}\n")
    assert main(["analyze", str(d), "--no-scan"]) == 0
    page = (d / ".lantern" / "evidence.html").read_text(encoding="utf-8")
    assert "not pinned: no git commit" in page and "does not name this folder back" in page


def test_a_finding_says_when_the_comparison_with_the_commit_could_not_be_made():
    sec = {"findings": [{"id": "a", "case": {"where": {}}}, {"id": "b", "case": {"where": {}}}]}
    case.stamp(sec, {"commit": "c" * 40, "dirty": True, "note": gitfacts.UNKNOWN}, set())
    assert sec["findings"][0]["case"]["where"] == {"revision": "c" * 40, "revision_note": gitfacts.UNKNOWN}
    case.stamp(sec, {"commit": "c" * 40, "dirty": True}, set())
    assert sec["findings"][1]["case"]["where"]["revision_note"] == "the folder has changes that are not committed"
    clean = {"findings": [{"id": "c", "case": {"where": {}}}]}
    case.stamp(clean, {"commit": "c" * 40, "dirty": False}, set())
    assert clean["findings"][0]["case"]["where"] == {"revision": "c" * 40}


# ---------------------------------------------------------------------------- honest: the answers git gives

def test_a_plain_repository_gets_the_answers_git_gives(tmp_path):
    d = make(tmp_path)
    assert evidence.git_info(d) == git_says(d)
    assert evidence.git_info(d / "sub") == git_says(d)                      # from a folder inside it, too
    git("remote", "add", "origin", "https://user:tok123@example.invalid/a/b.git", cwd=d)
    assert evidence.git_info(d)["remote"] == "https://example.invalid/a/b.git"      # never a name or password
    assert evidence.git_info(tmp_path) == {"commit": None, "note": "not a git repository"}
    assert evidence.git_info(tmp_path / "nothing-here") == {"commit": None, "note": "not a git repository"}


def test_changes_count_as_git_counts_them(tmp_path):
    d = make(tmp_path)
    write(d / "untracked.txt", "u\n")
    assert evidence.git_info(d)["dirty"] is False                           # a file git does not keep track of
    write(d / "app.py", "print('changed')\n")
    assert evidence.git_info(d)["dirty"] is True and git_says(d)["dirty"] is True
    git("checkout", "-q", "--", "app.py", cwd=d)
    write(d / "new.py", "y = 2\n")
    git("add", "new.py", cwd=d)
    assert evidence.git_info(d)["dirty"] is True                            # added, not committed
    git("reset", "-q", "--hard", cwd=d)
    (d / "sub" / "b.py").unlink()
    assert evidence.git_info(d)["dirty"] is True and gitfacts.deleted(d) == ["sub/b.py"]
    git("checkout", "-q", "--", "sub/b.py", cwd=d)
    touched(d / "app.py")
    assert evidence.git_info(d) == git_says(d) and gitfacts.deleted(d) == []


def test_other_shapes_of_repository_get_the_answers_git_gives(tmp_path):
    d = make(tmp_path)
    git("pack-refs", "--all", cwd=d)                                        # the branch is in packed-refs only
    assert not (d / ".git" / "refs" / "heads" / "main").exists()
    assert evidence.git_info(d) == git_says(d)
    git("checkout", "-q", "--detach", cwd=d)                                # no branch
    assert evidence.git_info(d) == git_says(d) and evidence.git_info(d)["branch"] == "HEAD"
    git("checkout", "-q", "main", cwd=d)
    git("worktree", "add", "-q", str(tmp_path / "linked"), "-b", "side", cwd=d)
    assert evidence.git_info(tmp_path / "linked") == git_says(tmp_path / "linked")
    assert evidence.git_info(tmp_path / "linked")["branch"] == "side"
    write(tmp_path / "linked" / "app.py", "print('changed in the other worktree')\n")
    assert (evidence.git_info(tmp_path / "linked")["dirty"], evidence.git_info(d)["dirty"]) == (True, False)
    shallow = tmp_path / "shallow"
    git("clone", "-q", "--depth", "1", d.as_uri(), str(shallow), cwd=tmp_path)
    assert evidence.git_info(shallow) == git_says(shallow) and gitfacts.deleted(shallow) == []
    unborn = tmp_path / "unborn"
    unborn.mkdir()
    git("init", "-q", "-b", "main", cwd=unborn)
    assert evidence.git_info(unborn) == {"commit": None, "note": "not a git repository"}     # as before: no commit yet


def test_a_sha256_repository_is_read(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    if subprocess.run(["git", "init", "-q", "-b", "main", "--object-format=sha256"], cwd=d, capture_output=True).returncode:
        pytest.skip("this git cannot make a sha256 repository")
    write(d / "app.py", "x = 1\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "one", cwd=d)
    got = evidence.git_info(d)
    assert len(got["commit"]) == 64 and got == git_says(d)


def test_a_commit_time_is_written_the_way_git_wrote_it(tmp_path):
    d = make(tmp_path)
    assert evidence.git_info(d)["committed_at"] == "2026-11-01T10:00:00+01:00"
    write(d / "app.py", "x = 2\n")
    git("commit", "-q", "-a", "-m", "two", cwd=d, env={"GIT_COMMITTER_DATE": "2026-11-02T08:30:00+0000"})
    assert evidence.git_info(d)["committed_at"] == "2026-11-02T08:30:00+00:00"
    git("commit", "-q", "--allow-empty", "-m", "three", cwd=d, env={"GIT_COMMITTER_DATE": "2026-11-03T23:59:59-0930"})
    assert evidence.git_info(d)["committed_at"] == "2026-11-03T23:59:59-09:30"


def test_line_endings_are_compared_the_way_the_repository_was_set_up(tmp_path):
    d = make(tmp_path)
    git("config", "core.autocrlf", "true", cwd=d)
    (d / "app.py").unlink()
    git("checkout", "-q", "--", "app.py", cwd=d)                # written with CRLF now
    assert (d / "app.py").read_bytes().endswith(b"\r\n")
    touched(d / "app.py")
    assert evidence.git_info(d)["dirty"] is False and git_says(d)["dirty"] is False
    git("config", "core.autocrlf", "false", cwd=d)
    os.utime(d / "app.py", (2, 2))
    assert evidence.git_info(d)["dirty"] is True and git_says(d)["dirty"] is True


def test_a_change_inside_a_submodule_still_counts(tmp_path):
    sup, lib = with_submodule(tmp_path)
    inner = sup / "vendor" / "lib"
    assert evidence.git_info(sup)["dirty"] is False and git_says(sup)["dirty"] is False
    assert evidence.git_info(inner)["commit"] == git("rev-parse", "HEAD", cwd=lib)       # asked about by itself
    write(inner / "app.py", "print('changed inside')\n")
    assert evidence.git_info(sup)["dirty"] is True and git_says(sup)["dirty"] is True
    git("checkout", "-q", "--", "app.py", cwd=inner)
    assert evidence.git_info(sup)["dirty"] is False
    write(inner / "app.py", "print('a new commit inside')\n")
    git("commit", "-q", "-a", "-m", "inside", cwd=inner)                                 # at another commit now
    assert evidence.git_info(sup)["dirty"] is True and git_says(sup)["dirty"] is True


def test_a_submodule_that_is_not_checked_out_changes_nothing(tmp_path):
    sup, _lib = with_submodule(tmp_path)
    fresh = tmp_path / "fresh"
    git("clone", "-q", sup.as_uri(), str(fresh), cwd=tmp_path)             # vendor/lib is an empty folder here
    assert not (fresh / "vendor" / "lib" / ".git").exists()
    assert evidence.git_info(fresh) == git_says(fresh) and evidence.git_info(fresh)["dirty"] is False


def test_files_left_out_on_purpose_are_not_missing(tmp_path):
    """A sparse checkout, which is how Lantern leaves out bulk files of a clone over its size limit."""
    d = make(tmp_path)
    write(d / ".git" / "info" / "sparse-checkout", "/*\n!/sub/\n")
    git("config", "core.sparseCheckout", "true", cwd=d)
    git("reset", "-q", "--hard", cwd=d)
    assert not (d / "sub" / "b.py").exists()
    assert gitfacts.deleted(d) == [] and evidence.git_info(d) == git_says(d)
    (d / "app.py").unlink()
    assert gitfacts.deleted(d) == ["app.py"]


def test_gits_own_sparse_checkout_gets_the_answers_git_gives(tmp_path):
    """`git sparse-checkout` keeps its settings in a second file (`config.worktree`), which Lantern does not read:
    the index itself says which files were left out."""
    d = make(tmp_path)
    write(d / "deep" / "er" / "c.py", "y = 2\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "two", cwd=d)
    if subprocess.run(["git", "sparse-checkout", "init", "--cone", "--sparse-index"], cwd=d,
                      capture_output=True).returncode:
        pytest.skip("this git has no sparse-checkout command with a sparse index")
    git("sparse-checkout", "set", "sub", cwd=d)
    assert "sparse" in (d / ".git" / "config.worktree").read_text(encoding="utf-8") and not (d / "deep").exists()
    assert evidence.git_info(d) == git_says(d) and gitfacts.deleted(d) == []
    touched(d / "sub" / "b.py")
    assert evidence.git_info(d) == git_says(d) and evidence.git_info(d)["dirty"] is False
    (d / "sub" / "b.py").unlink()
    assert evidence.git_info(d)["dirty"] is True and gitfacts.deleted(d) == ["sub/b.py"]


def test_a_clone_with_no_files_checked_out_counts_as_git_counts_it(tmp_path):
    d = make(tmp_path)
    bare = tmp_path / "no-files"
    git("clone", "-q", "--no-checkout", d.as_uri(), str(bare), cwd=tmp_path)
    assert not (bare / ".git" / "index").exists()
    assert evidence.git_info(bare) == git_says(bare) and evidence.git_info(bare)["dirty"] is True


def test_the_persons_own_word_on_where_git_stops_looking_is_kept(tmp_path, monkeypatch):
    """GIT_CEILING_DIRECTORIES: git does not look for a repository in the named folders or above them."""
    d = make(tmp_path)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.pathsep.join(["relative/is/ignored", str(d)]))
    assert subprocess.run(["git", "rev-parse", "HEAD"], cwd=d / "sub", capture_output=True).returncode != 0
    assert evidence.git_info(d / "sub") == {"commit": None, "note": "not a git repository"}
    assert gitfacts.head_commit(d / "sub") is None
    assert evidence.git_info(d) == git_says(d)                      # the folder asked about is always looked at


def test_reading_the_commit_starts_no_program(tmp_path, monkeypatch):
    d = make(tmp_path)
    commit = git("rev-parse", "HEAD", cwd=d)

    def none(*a, **k):
        raise AssertionError("a program was started")
    monkeypatch.setattr(subprocess, "Popen", none)
    assert gitfacts.head_commit(d) == commit and gitfacts.head_commit(d / "sub") == commit
    assert gitfacts.head_commit(tmp_path) is None


# ---------------------------------------------------------------------------- the settings file, read as text

def test_the_settings_file_is_read_as_text_the_way_git_reads_it(tmp_path):
    cfg = write(tmp_path / "config",
                '\ufeff# a comment\n[core]\n\tbare = false\n\tAutoCRLF = Input ; said in passing\n'
                '\tquoted = " a b " # c\n\thalf = a" b "c   \n\tescaped = a\\tb\\\\c\\"d\n\tlong = one \\\n  two\n'
                '\tspaced =   a \t b   \n\tempty =\n\thash = "a#b;c" ; d\n'
                '[remote "Origin"]\n\turl = first\n[remote "origin"]\n\turl = https://example.invalid/a.git\n'
                '\turl = last\n[Branch.Main]\n\tremote = origin\n[section "with \\"quote\\""] name = on the same line\n'
                '; another comment\r\n[windows]\r\n\tline = endings\r\n'
                '[include]\n\tpath = ' + (tmp_path / "more").as_posix() + '\n')
    write(tmp_path / "more", "[core]\n\tfsmonitor = from-the-included-file\n")
    got = gitfacts.settings(tmp_path)
    listed = git("config", "-f", str(cfg), "--null", "--list", cwd=tmp_path)    # git's own reading of the same text
    want = dict(item.split("\n", 1) for item in listed.split("\0") if item)     # the last value of a name wins
    assert len(want) == 15 and got == want
    assert got["core.quoted"] == " a b " and got["core.half"] == "a b c" and got["core.long"] == "one   two"
    assert got["core.escaped"] == 'a\tb\\c"d' and got["core.spaced"] == "a   b" and got["core.hash"] == "a#b;c"
    assert got["remote.origin.url"] == "last" and got["remote.Origin.url"] == "first"   # a subsection keeps its case
    assert got["branch.main.remote"] == "origin" and got['section.with "quote".name'] == "on the same line"
    assert "core.fsmonitor" not in got                                           # includes are not followed
    write(tmp_path / "alone" / "config", "[core]\n\talone\n\tlast")
    assert gitfacts.settings(tmp_path / "alone") == {"core.alone": "true", "core.last": "true"}
    assert git("config", "-f", str(tmp_path / "alone" / "config"), "--type=bool", "--get", "core.alone",
               cwd=tmp_path) == "true"
    # what git refuses is passed over, and never lands under the section before it
    write(tmp_path / "bad" / "config", '[core]\n\ta = 1\nnot a setting\n\tb = "open\n[broken\n\tname = lost\n'
                                       '[core]\n\tc = \\x\n\td = 4\n[spaces in name]\n\te = 5\n= 6\n')
    assert gitfacts.settings(tmp_path / "bad") == {"core.a": "1", "core.d": "4"}
    assert gitfacts.settings(tmp_path / "nothing") == {}


# ---------------------------------------------------------------------------- limits: not read, and said

def test_a_git_folder_kept_elsewhere_with_no_way_back_is_not_read(tmp_path):
    """`git init --separate-git-dir`: the .git file names a folder that does not name this one back (git 2.43),
    which is also what a planted pointer at somebody else's repository looks like. Not read, and said."""
    d = tmp_path / "app"
    d.mkdir()
    git("init", "-q", "-b", "main", "--separate-git-dir", str(tmp_path / "kept-elsewhere.git"), cwd=d)
    write(d / "a.txt", "a\n")
    git("add", "-A", cwd=d)
    git("commit", "-q", "-m", "one", cwd=d)
    if "worktree" in (tmp_path / "kept-elsewhere.git" / "config").read_text(encoding="utf-8"):
        assert evidence.git_info(d) == git_says(d)              # a git that writes the way back: read
    else:
        assert evidence.git_info(d) == {"commit": None, "note": gitfacts.UNREAD}


def test_refs_kept_in_the_reftable_form_are_not_read(tmp_path):
    d = make(tmp_path)
    write(d / ".git" / "HEAD", "ref: refs/heads/.invalid\n")                # what such a repository's HEAD holds
    plant(d / ".git" / "config", "[extensions]\n\trefStorage = reftable\n")
    assert evidence.git_info(d) == {"commit": None, "note": gitfacts.REFTABLE}


def test_without_git_nothing_is_claimed(tmp_path, monkeypatch):
    d = make(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
    assert evidence.git_info(d) == {"commit": None, "note": "git not installed"}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
