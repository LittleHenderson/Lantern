"""Another commit of a project, named and copied out without obeying the project (`gitfacts.resolve`, `merge_base`,
`copy`; `programs.put_link`; roadmap of 2026-11-14, stage 2).

`lantern diff` checks two commits of a project. A commit comes from whoever wrote the pull request, so the copy
that is checked must be the commit and nothing less: git's own way of writing a commit out (`git archive`) obeys
the commit's `.gitattributes`, where one line leaves a file out or rewrites it. Each planted thing below stands
beside a twin: the same repository without the plant, which must be copied alike.
"""
import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from lantern import gitfacts, programs

only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (symbolic links)")
WHEN = {"GIT_AUTHOR_DATE": "2026-11-01T10:00:00+0100", "GIT_COMMITTER_DATE": "2026-11-01T10:00:00+0100"}


def git(*args, cwd) -> str:
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "maintenance.auto=false",
                        "-c", "gc.auto=0", "-c", "core.autocrlf=false", "-c", "init.defaultBranch=main", *args], cwd=cwd,
                       env={**os.environ, **WHEN}, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, (args, r.stderr)
    return r.stdout.strip()


def put(root: Path, files: dict) -> None:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))


def commit(root: Path, files: dict, message: str = "a commit") -> str:
    if not (root / ".git").exists():
        root.mkdir(parents=True, exist_ok=True)
        git("init", "-q", ".", cwd=root)
    put(root, files)
    git("add", "-A", cwd=root)
    git("commit", "-q", "--allow-empty", "-m", message, cwd=root)
    return git("rev-parse", "HEAD", cwd=root)


def held(root: Path) -> dict:
    """Every file under `root` with its bytes; a link as ("link", its text)."""
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            out[rel] = ("link", os.readlink(p).replace(os.sep, "/"))
        elif p.is_file():
            out[rel] = p.read_bytes()
    return out


def in_git(root: Path, sha: str) -> dict:
    """What the commit holds, asked of git one object at a time: the bytes a copy has to have."""
    out = {}
    for rel in git("ls-tree", "-r", "--name-only", sha, cwd=root).splitlines():
        r = subprocess.run(["git", "cat-file", "blob", f"{sha}:{rel}"], cwd=root, capture_output=True)
        assert r.returncode == 0, rel
        out[rel] = r.stdout
    return out


FILES = {"app/keys.py": "KEY = 'k'\n", "app/main.py": "import keys\r\nprint(keys.KEY)\n", "notes.txt": "one\ntwo\n",
         "stamp.txt": "$Id$ $Format:%H$\n", "docs/readme.md": "# read me\n"}
PLANTED = ("app/keys.py export-ignore\ndocs/ export-ignore\n*.txt text eol=crlf\n*.py text eol=lf\n"
           "stamp.txt ident export-subst\n")


# --------------------------------------------------------------------------------------------- the copy is the commit
def test_a_commit_is_copied_byte_for_byte(tmp_path):
    sha = commit(tmp_path / "repo", FILES)
    got = gitfacts.copy(tmp_path / "repo", sha, tmp_path / "copy")
    assert held(tmp_path / "copy") == {k: v.encode("utf-8") for k, v in FILES.items()} == in_git(tmp_path / "repo", sha)
    assert got["root"] == tmp_path / "copy" and got["files"] == len(FILES) and got["left_out"] == {} and got["links"] == 0


def test_the_commits_own_attributes_file_leaves_nothing_out_and_rewrites_nothing(tmp_path):
    """The plant: with these lines git's own archive of the commit holds neither `app/keys.py` nor `docs/`, ends
    every line of the text files another way and fills two stamps in (seen with git 2.43.0 before this was written)."""
    files = {**FILES, ".gitattributes": PLANTED}
    sha = commit(tmp_path / "repo", files)
    got = gitfacts.copy(tmp_path / "repo", sha, tmp_path / "copy")
    made = held(tmp_path / "copy")
    assert made == in_git(tmp_path / "repo", sha) and sorted(made) == sorted(files)
    assert made["app/keys.py"] == b"KEY = 'k'\n" and made["docs/readme.md"] == b"# read me\n"       # not left out
    assert made["notes.txt"] == b"one\ntwo\n" and made["stamp.txt"] == b"$Id$ $Format:%H$\n"        # not rewritten
    assert got["files"] == len(files) and got["left_out"] == {}
    # and git's plain archive of the same commit does leave them out, so the test is about something
    plain = subprocess.run(["git", "archive", "--format=tar", sha], cwd=tmp_path / "repo", capture_output=True, env={**os.environ, **WHEN})
    names = tarfile.open(fileobj=io.BytesIO(plain.stdout)).getnames()
    assert plain.returncode == 0 and "app/main.py" in names and "app/keys.py" not in names and "docs/readme.md" not in names, names


def test_an_earlier_commit_is_copied_as_it_was_and_the_folder_is_not_touched(tmp_path):
    repo = tmp_path / "repo"
    first = commit(repo, FILES)
    second = commit(repo, {"app/main.py": "print('changed')\n", "new.py": "x = 1\n"})
    (repo / "scratch.txt").write_text("not committed", encoding="utf-8")
    before = held(repo)
    gitfacts.copy(repo, first, tmp_path / "one")
    gitfacts.copy(repo, second, tmp_path / "two")
    assert held(tmp_path / "one") == {k: v.encode("utf-8") for k, v in FILES.items()}
    assert held(tmp_path / "two")["app/main.py"] == b"print('changed')\n" and "new.py" in held(tmp_path / "two")
    assert "scratch.txt" not in held(tmp_path / "two")
    assert held(repo) == before and git("status", "--porcelain", cwd=repo) == "?? scratch.txt"


def test_a_command_named_in_the_projects_git_settings_is_not_run_by_the_copy(tmp_path):
    repo, mark = tmp_path / "repo", tmp_path / "ran.txt"
    sha = commit(repo, {**FILES, ".gitattributes": "*.py filter=plant\n"})
    with open(repo / ".git" / "config", "a", encoding="utf-8", newline="\n") as f:
        f.write(f"[filter \"plant\"]\n\tsmudge = echo ran >> '{mark.as_posix()}'; cat\n\tclean = cat\n"
                f"[core]\n\tfsmonitor = echo ran >> '{mark.as_posix()}'\n"
                f"[tar \"tar\"]\n\tcommand = echo ran >> '{mark.as_posix()}'; cat\n")
    gitfacts.copy(repo, sha, tmp_path / "copy")
    assert gitfacts.resolve(repo, "HEAD") == sha
    assert not mark.exists()
    assert held(tmp_path / "copy")["app/keys.py"] == b"KEY = 'k'\n"


def test_only_the_asked_folder_of_a_larger_repository_is_copied(tmp_path):
    repo = tmp_path / "repo"
    sha = commit(repo, {"services/api/app.py": "a = 1\n", "services/web/index.js": "let b\n", "top.py": "t = 0\n"})
    got = gitfacts.copy(repo / "services" / "api", sha, tmp_path / "copy")
    assert got["root"] == tmp_path / "copy" / "services" / "api" and got["files"] == 1
    assert held(tmp_path / "copy") == {"services/api/app.py": b"a = 1\n"}


# ---------------------------------------------------------------------------------------------------------- links
@only_posix
def test_a_link_that_stays_inside_is_made_again_and_one_that_leads_out_is_not(tmp_path):
    repo = tmp_path / "repo"
    put(repo, {"app/main.py": "m = 1\n", "shared/util.py": "u = 1\n"})
    (tmp_path / "outside.txt").write_text("the person's own", encoding="utf-8")
    os.symlink("../shared", repo / "app" / "shared")                    # stays inside
    os.symlink("main.py", repo / "app" / "start.py")                    # stays inside
    os.symlink("../../outside.txt", repo / "app" / "out.txt")           # climbs out of the top
    os.symlink("/etc/hostname", repo / "abs.txt")                       # an address from the top of the disk
    os.symlink("..", repo / "shared" / "up")                            # the top itself: inside
    os.symlink("up/../outside.txt", repo / "shared" / "trick.txt")      # a climb after a name that is a link
    sha = commit(repo, {})
    got = gitfacts.copy(repo, sha, tmp_path / "copy")
    made = held(tmp_path / "copy")
    assert made["app/shared"] == ("link", "../shared") and made["app/start.py"] == ("link", "main.py")
    assert made["shared/up"] == ("link", "..")
    for gone in ("app/out.txt", "abs.txt", "shared/trick.txt"):
        assert gone not in made and not os.path.lexists(tmp_path / "copy" / gone)
    assert got["links"] == 3 and got["left_out"] == {"link-out": 3} and got["files"] == 2
    assert (tmp_path / "outside.txt").read_text(encoding="utf-8") == "the person's own"


@pytest.mark.parametrize("parts, target, inside", [
    (["a", "b", "x"], "y", True), (["a", "b", "x"], "../c/y", True), (["a", "b", "x"], "../../y", True),
    (["x"], ".", True), (["a", "x"], "..", True), (["a", "x"], "./y/", True),
    (["a", "b", "x"], "../../../y", False), (["x"], "..", False), (["x"], "../y", False),
    (["a", "x"], "up/../y", False), (["a", "x"], "y/..", False), (["a", "x"], "/etc/passwd", False),
    (["a", "x"], "", False), (["a", "x"], "y\\..\\..\\z", False), (["a", "x"], "y\0z", False),
    (["a", "..", "x"], "y", False), ([], "y", False), (["a", "x"], None, False),
])
def test_which_link_stays_inside_whatever_else_lies_in_the_folder(parts, target, inside):
    assert programs.link_inside(parts, target) is inside


@only_posix
def test_no_link_that_leads_out_is_ever_made(tmp_path):
    with pytest.raises(ValueError):
        programs.put_link(tmp_path, ["a", "x"], "../../etc/passwd")
    with pytest.raises(ValueError):
        programs.put_link(tmp_path, ["a", "x"], "up/../../y")
    assert not (tmp_path / "a").exists()
    made = programs.put_link(tmp_path, ["a", "x"], "../b")
    assert os.readlink(made) == "../b"


# ------------------------------------------------------------------------------------------------ naming a commit
def test_a_commit_is_named_the_ways_people_name_one(tmp_path):
    repo = tmp_path / "repo"
    first = commit(repo, {"a.py": "a = 1\n"})
    second = commit(repo, {"a.py": "a = 2\n"})
    git("branch", "feature/login", first, cwd=repo)
    git("tag", "v1", first, cwd=repo)
    git("tag", "-a", "v2", "-m", "a tag with a note", second, cwd=repo)
    git("update-ref", "refs/remotes/origin/main", first, cwd=repo)
    for name, want in (("HEAD", second), ("main", second), ("HEAD~1", first), ("HEAD^", first), ("main~1", first),
                       ("feature/login", first), ("v1", first), ("v2", second), ("v2~1", first), ("origin/main", first),
                       (first, first), (first[:10], first), ("refs/heads/main", second)):
        assert gitfacts.resolve(repo, name) == want, name
    assert gitfacts.merge_base(repo, first, second) == first


@pytest.mark.parametrize("name", ["", "-x", "--upload-pack=touch x", "main..HEAD", "HEAD@{1}", "a b", "main:secret.py",
                                  "$(id)", "main;id", "x" * 300, "refs/heads/../../config", "main.lock", None, "~1"])
def test_a_name_that_is_no_commits_name_is_refused_with_a_sentence(tmp_path, name):
    repo = tmp_path / "repo"
    commit(repo, {"a.py": "a = 1\n"})
    with pytest.raises(gitfacts.NoCommit, match="is not a name Lantern takes for a commit"):
        gitfacts.resolve(repo, name)


def test_a_commit_that_is_not_there_is_said_so(tmp_path):
    repo = tmp_path / "repo"
    commit(repo, {"a.py": "a = 1\n"})
    with pytest.raises(gitfacts.NoCommit, match="has no branch, tag or commit named 'nothing'"):
        gitfacts.resolve(repo, "nothing")
    with pytest.raises(gitfacts.NoCommit, match="git did not find the commit"):
        gitfacts.resolve(repo, "HEAD~5")
    with pytest.raises(gitfacts.NoCommit, match="git did not find the commit"):
        gitfacts.resolve(repo, "0" * 40)
    with pytest.raises(gitfacts.NoCommit, match="could not list the files"):
        gitfacts.copy(repo, "0" * 40, tmp_path / "copy")
    assert not (tmp_path / "copy").exists() or not any((tmp_path / "copy").iterdir())


def test_a_folder_that_is_in_no_repository_is_said_so(tmp_path):
    (tmp_path / "plain").mkdir()
    with pytest.raises(gitfacts.NoCommit, match="is in no git repository Lantern reads"):
        gitfacts.resolve(tmp_path / "plain", "HEAD")
    with pytest.raises(gitfacts.NoCommit, match="is in no git repository Lantern reads"):
        gitfacts.copy(tmp_path / "plain", "0" * 40, tmp_path / "copy")


def test_a_copy_that_holds_less_than_the_commit_is_not_handed_back(tmp_path, monkeypatch):
    """Should a git ever leave a file out all the same, the count against git's own list says so."""
    sha = commit(tmp_path / "repo", {**FILES, ".gitattributes": PLANTED})
    monkeypatch.setattr(gitfacts, "OWN_ATTRIBUTES", "# nothing switched off\n")
    with pytest.raises(gitfacts.NoCommit, match=r"git wrote out 4 of the 6 files of commit"):
        gitfacts.copy(tmp_path / "repo", sha, tmp_path / "copy")
