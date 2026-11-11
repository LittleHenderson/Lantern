"""A link in a project that leads out of the project is not read, and not shown (2026-11-10).

A project comes from anywhere, and a git repository can hold symbolic links to any path of the computer it is cloned
on. Lantern's readers of source files refused a file that was itself such a link (`inside_repo`). But:

* the notes file (`lantern-narratives.md`) was read without asking, and it is shown in the Evidence Report as it is:
  a repository that brought that name as a link to a file outside it had the first 20,000 characters of that file
  in its report;
* `inside_repo` looked only at the last name of a path, so a file reached through a folder that is a link out of the
  project (`lantern-packs -> /somewhere`) counted as the project's;
* Bandit finds its files itself, opened a `.py` link wherever it led, and its findings quote the lines.

Now `inside_repo` answers for the whole path (a plain file, or a link to one, that lies inside the project by
whatever folders it is reached), the notes file asks it, Bandit is told which files to leave out and nothing is taken
from them, and a repository Lantern clones is written without links at all (`core.symlinks=false`).

Each refusal has a safe twin beside it: the project's own file, a link that stays inside the project, the person's
own shortcut to the project.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from lantern import gitfacts, pipeline, remote, scanresult, security
from lantern.python_frontend import inside_repo

needs_links = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (symbolic links, pipes)")
PRIVATE = "the private line 7341 of a file that is not in the project"
APP = {"app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"}
SHELL = "import subprocess\n\n\ndef go(cmd):\n    subprocess.call(cmd, shell=True)\n"


def _write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _analyze(repo: Path, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    pipeline.analyze(repo, out, log=lambda line: None, offline=True)
    return out


def _everything(out: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted(out.iterdir()) if p.is_file())


def _notes(out: Path):
    return json.loads((out / "evidence.json").read_text(encoding="utf-8"))["understanding"]


def _without_bandit(monkeypatch) -> None:
    """Bandit is another program and takes a second and a half of each analysis; it has tests of its own below."""
    monkeypatch.setattr(security, "run_bandit", lambda repo, applicable=True: ([], scanresult.record(
        "bandit", "unavailable", "left out of this test", applicable=False, version=None,
        role="Python code patterns", exclusions=[])))


# ---------------------------------------------------------------------------- the notes file

@needs_links
def test_a_notes_file_that_is_a_link_out_of_the_project_is_not_shown(tmp_path, monkeypatch):
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", APP)
    private = tmp_path / "private.txt"
    private.write_text(PRIVATE + "\n", encoding="utf-8")
    os.symlink(private, repo / "lantern-narratives.md")
    out = _analyze(repo, tmp_path / "out")
    assert PRIVATE not in _everything(out)                      # before: in evidence.html and evidence.json
    assert _notes(out) is None


@needs_links
def test_a_notes_file_reached_through_a_folder_link_out_of_the_project_is_not_shown(tmp_path, monkeypatch):
    """A link that looks as if it stayed inside (`notes/private.md`), where `notes` is the folder that leads out."""
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", APP)
    _write(tmp_path / "outside", {"private.md": PRIVATE + "\n"})
    os.symlink(tmp_path / "outside", repo / "notes")
    os.symlink("notes/private.md", repo / "lantern-narratives.md")
    out = _analyze(repo, tmp_path / "out")
    assert PRIVATE not in _everything(out) and _notes(out) is None


@needs_links
def test_a_notes_file_of_the_project_is_shown_as_before(tmp_path, monkeypatch):
    """The safe twins: no file, a link to a file that lies inside the project, and the file itself."""
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", APP | {"docs/flows.md": "How a command reaches the shell, in our words.\n"})
    assert _notes(_analyze(repo, tmp_path / "out0")) is None
    os.symlink("docs/flows.md", repo / "lantern-narratives.md")
    assert "How a command reaches the shell" in _notes(_analyze(repo, tmp_path / "out"))
    (repo / "lantern-narratives.md").unlink()
    (repo / "lantern-narratives.md").write_text("Written here.\n", encoding="utf-8")
    assert _notes(_analyze(repo, tmp_path / "out2")) == "Written here.\n"


@needs_links
def test_a_pipe_under_the_notes_files_name_does_not_hold_the_run_up(tmp_path, monkeypatch):
    """Before, the report waited for good for somebody to write into the pipe (the run is ended here after 20 s)."""
    import signal
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", APP)
    os.mkfifo(repo / "lantern-narratives.md")

    def late(*_):
        raise TimeoutError("the analysis was still waiting on the pipe after 20 s")
    before = signal.signal(signal.SIGALRM, late)
    signal.alarm(20)
    try:
        out = _analyze(repo, tmp_path / "out")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, before)
    assert _notes(out) is None


# ---------------------------------------------------------------------------- a folder that is a link

@needs_links
def test_a_folder_that_is_a_link_out_of_the_project_is_not_read_through(tmp_path, monkeypatch):
    """A file can be reached through a folder that is a link: `lantern-packs/` with a pack of rules in it. The
    folder is no more the project's than the file would be."""
    _without_bandit(monkeypatch)
    pack = {"pack": "mine", "version": "1", "about": "Our own rule.", "rules": [{
        "id": "LP-MINE-SHELL", "title": "A shell is started", "pattern": r"os\.system", "severity": "MEDIUM",
        "files": ["*.py"], "fix": "Do not start one."}]}
    says = {}
    for how in ("gone", "link", "real"):
        here = tmp_path / how
        repo = _write(here / "project", APP)
        if how == "real":
            _write(repo, {"lantern-packs/mine.json": json.dumps(pack)})
        elif how == "link":
            _write(here / "outside", {"mine.json": json.dumps(pack)})
            os.symlink(here / "outside", repo / "lantern-packs")
        out = _analyze(repo, here / "out")
        says[how] = sorted(f["rule"] for f in json.loads((out / "security.json").read_text(encoding="utf-8"))["findings"])
    assert "LP-MINE-SHELL" in says["real"]                          # the twin: the project's own pack still counts
    assert says["link"] == says["gone"] and "LP-MINE-SHELL" not in says["link"]


# ---------------------------------------------------------------------------- the one question every reader asks

@needs_links
def test_what_counts_as_a_file_of_the_project(tmp_path):
    repo = _write(tmp_path / "project", {"app.py": "x = 1\n", "pkg/mod.py": "y = 2\n", "pkg/sub/deep.py": "v = 5\n"})
    outside = _write(tmp_path / "outside", {"private.py": "z = 3\n", "dir/inner.py": "w = 4\n"})
    for name in ("app.py", "pkg/mod.py", "pkg/sub/deep.py"):
        assert inside_repo(repo / name, repo), name
    os.symlink("app.py", repo / "same.py")                      # a link to a file of the project: read, as before
    os.symlink(repo / "pkg", repo / "alias")                    # and through a folder link that stays inside
    os.symlink("../app.py", repo / "pkg" / "up.py")
    for name in ("same.py", "alias/mod.py", "alias/sub/deep.py", "pkg/up.py", "pkg/../app.py"):
        assert inside_repo(repo / name, repo), name
    os.symlink(outside / "private.py", repo / "out.py")         # a link out
    os.symlink("out.py", repo / "chain.py")                     # a link to a link out
    os.symlink(outside / "dir", repo / "vendor")                # a folder that is a link out: before, read through
    os.symlink(outside / "nowhere.py", repo / "broken.py")
    os.symlink("loop.py", repo / "loop.py")                     # a link to itself
    for name in ("out.py", "chain.py", "vendor/inner.py", "broken.py", "loop.py", "missing.py", "pkg", "alias",
                 "pkg/../../outside/private.py", "app.py/x"):
        assert not inside_repo(repo / name, repo), name
    assert not inside_repo(outside / "private.py", repo)        # a path that was never under the project
    assert not inside_repo(repo, repo)                          # the project is a folder, not a file of itself
    os.mkfifo(repo / "pipe.py")                                 # no file at all: reading one waits for good
    os.symlink("pipe.py", repo / "to-pipe.py")
    assert not inside_repo(repo / "pipe.py", repo) and not inside_repo(repo / "to-pipe.py", repo)
    os.symlink(repo, tmp_path / "shortcut")                     # the person's own shortcut to the project changes nothing
    short = tmp_path / "shortcut"
    assert inside_repo(short / "app.py", short) and inside_repo(short / "alias" / "mod.py", short)
    assert not inside_repo(short / "out.py", short) and not inside_repo(short / "vendor" / "inner.py", short)
    assert inside_repo(short / "app.py", repo) and inside_repo(repo / "app.py", short)   # one named each way


@needs_links
def test_the_quick_look_and_the_slow_look_agree(tmp_path, monkeypatch):
    """`inside_repo` decides the usual case without following anything. Whatever it says must be what following
    every link says."""
    from lantern import python_frontend
    repo = _write(tmp_path / "project", {"app.py": "x = 1\n", "pkg/mod.py": "y = 2\n", "pkg/sub/deep.py": "v = 5\n"})
    outside = _write(tmp_path / "outside", {"private.py": "z = 3\n", "dir/inner.py": "w = 4\n"})
    os.symlink(repo / "pkg", repo / "alias")
    os.symlink(outside / "dir", repo / "vendor")
    os.symlink(outside / "private.py", repo / "out.py")
    os.mkfifo(repo / "pipe.py")
    _write(tmp_path / "project2", {"app.py": "x = 1\n"})       # a folder whose path begins with the project's
    names = ["app.py", "pkg/mod.py", "pkg/sub/deep.py", "alias/mod.py", "vendor/inner.py", "out.py", "pipe.py",
             "pkg", "missing.py", "pkg/missing.py", "pkg//mod.py", "pkg/./mod.py", "./app.py", "pkg/../app.py",
             "pkg/sub/../../../outside/private.py", "../project2/app.py", "vendor/../app.py", "alias/../app.py",
             "app.py/", "pkg/"]
    said = []

    def ask() -> dict:
        got = {name: inside_repo(os.path.join(repo, name), repo) for name in names}
        got |= {name + " (the project written with a slash at its end)": inside_repo(f"{repo}/{name}", f"{repo}/")
                for name in names}
        got["a neighbour"] = inside_repo(tmp_path / "project2" / "app.py", repo)
        got["a neighbour, by the text of its path"] = inside_repo(f"{repo}2/app.py", repo)
        return got
    quick = ask()
    plain = python_frontend._plain_way
    monkeypatch.setattr(python_frontend, "_plain_way", lambda p, repo: said.append(plain(p, repo)) and False)
    slow = ask()
    assert quick == slow
    assert [n for n in names if quick[n]] == ["app.py", "pkg/mod.py", "pkg/sub/deep.py", "alias/mod.py", "pkg//mod.py",
                                              "pkg/./mod.py", "./app.py", "pkg/../app.py", "alias/../app.py"]
    assert not quick["a neighbour"] and not quick["a neighbour, by the text of its path"]
    assert True in said and False in said                       # and both looks were in use


def test_a_plain_file_a_folder_and_a_name_nothing_answers_to(tmp_path):
    """The same question on every system, links or not."""
    repo = _write(tmp_path / "project", {"app.py": "x = 1\n", "pkg/mod.py": "y = 2\n"})
    (tmp_path / "elsewhere.py").write_text("z = 3\n", encoding="utf-8")
    assert inside_repo(repo / "app.py", repo) and inside_repo(repo / "pkg" / "mod.py", repo)
    assert inside_repo(repo / "pkg" / ".." / "app.py", repo)
    assert not inside_repo(repo / "pkg", repo) and not inside_repo(repo / "missing.py", repo)
    assert not inside_repo(tmp_path / "elsewhere.py", repo) and not inside_repo(repo / ".." / "elsewhere.py", repo)


@pytest.mark.skipif(os.name != "nt", reason="needs Windows (a junction, the folder link every Windows user can make)")
def test_on_windows_a_folder_that_is_a_junction_out_of_the_project_is_not_read_through(tmp_path):
    import _winapi

    from lantern import packs
    pack = {"pack": "mine", "version": "1", "about": "Our own rule.", "rules": [{
        "id": "LP-MINE-SHELL", "title": "A shell is started", "pattern": r"os\.system", "severity": "MEDIUM",
        "files": ["*.py"], "fix": "Do not start one."}]}
    repo = _write(tmp_path / "project", APP | {"pkg/mod.py": "y = 2\n"})
    outside = _write(tmp_path / "outside", {"inner.py": "w = 4\n", "packs/mine.json": json.dumps(pack)})
    _winapi.CreateJunction(str(outside), str(repo / "vendor"))
    _winapi.CreateJunction(str(repo / "pkg"), str(repo / "alias"))
    assert not inside_repo(repo / "vendor" / "inner.py", repo)   # before: counted as the project's
    assert inside_repo(repo / "alias" / "mod.py", repo)          # the twin: a junction that stays inside
    _winapi.CreateJunction(str(outside / "packs"), str(repo / "lantern-packs"))
    assert "mine" not in [p["pack"] for p in packs.load_all(repo)[0]]
    twin = _write(tmp_path / "twin", APP | {"lantern-packs/mine.json": json.dumps(pack)})
    assert "mine" in [p["pack"] for p in packs.load_all(twin)[0]]
    _winapi.CreateJunction(str(repo), str(tmp_path / "shortcut"))   # the person's own shortcut to the project
    short = tmp_path / "shortcut"
    assert inside_repo(short / "app.py", short) and not inside_repo(short / "vendor" / "inner.py", short)


# ---------------------------------------------------------------------------- Bandit, which finds its files itself

@needs_links
def test_bandit_is_not_sent_through_a_link_out_of_the_project(tmp_path):
    repo = _write(tmp_path / "project", APP)
    outside = tmp_path / "outside.py"
    outside.write_text(SHELL.rstrip("\n") + "  # " + PRIVATE + "\n", encoding="utf-8")
    os.symlink(outside, repo / "tool.py")
    os.symlink("app.py", repo / "same.py")                      # the twin: a link that stays inside is still checked
    findings, record = security.run_bandit(repo)
    assert record["state"] == "ok"
    assert sorted({f["file"] for f in findings}) == ["app.py"]  # before: tool.py too, with the outside file's line
    assert len(findings) == 2                                   # app.py, and once more as same.py (named by where it leads)
    assert PRIVATE not in json.dumps(findings)
    assert "tool.py" in record["exclusions"] and "same.py" not in record["exclusions"]
    assert record["scope"] == {"files": 2}                      # and tool.py is not counted as a file that was checked


@needs_links
def test_only_the_link_is_left_out_of_bandit(tmp_path):
    """Bandit leaves a file out when an exclusion is found anywhere in its path, so the path of `tool.py` alone
    would take the project's own `tool.pyw` and `tool.py.old.py` with it, and a comma in a name would cut the
    exclusion in two (that one is not handed to Bandit; nothing is taken from the file all the same). Each file
    here starts a shell; only the three links must go unreported."""
    repo = _write(tmp_path / "project", {"tool.pyw": SHELL, "tool.py.old.py": SHELL, "a,b/keep.py": SHELL,
                                         "a[1]/keep.py": SHELL, "a/keep.py": SHELL, "a_b/tool.py": SHELL})
    outside = tmp_path / "outside.py"
    outside.write_text(SHELL, encoding="utf-8")
    os.symlink(outside, repo / "tool.py")
    os.symlink(outside, repo / "a,b" / "tool.py")
    os.symlink(outside, repo / "a[1]" / "tool.py")
    findings, record = security.run_bandit(repo)
    assert record["state"] == "ok"
    kept = ["a,b/keep.py", "a/keep.py", "a[1]/keep.py", "a_b/tool.py", "tool.py.old.py", "tool.pyw"]
    assert sorted({f["file"] for f in findings if f["rule"] == "B602"}) == kept
    assert record["scope"] == {"files": 6}                      # none of the three links counts as a file checked
    assert [x for x in record["exclusions"] if x.endswith(".py")] == ["a,b/tool.py", "a[1]/tool.py", "tool.py"]


@needs_links
def test_a_pipe_under_a_python_name_does_not_hold_bandit_up(tmp_path, monkeypatch):
    """Before, Bandit waited on it until Lantern's time limit for Bandit ended the whole check: a project could
    switch the Python checker off by bringing a pipe (the limit is 15 s here so the older code fails soon)."""
    monkeypatch.setattr(security, "BANDIT_TIMEOUT", 15)
    repo = _write(tmp_path / "project", APP)
    os.mkfifo(repo / "wait.py")
    findings, record = security.run_bandit(repo)
    assert record["state"] == "ok" and [f["file"] for f in findings] == ["app.py"]
    assert "wait.py" in record["exclusions"]


@needs_links
def test_more_links_than_fit_a_command_line_are_still_not_reported(tmp_path, monkeypatch):
    """The exclusions that do not fit the command line are not handed to Bandit; nothing is taken from those files
    all the same."""
    monkeypatch.setattr(security, "EXCLUSIONS_FIT", 3 * len(str(tmp_path)), raising=False)
    repo = _write(tmp_path / "project", APP)
    outside = tmp_path / "outside.py"
    outside.write_text(SHELL.rstrip("\n") + "  # " + PRIVATE + "\n", encoding="utf-8")
    for n in range(12):
        os.symlink(outside, repo / f"tool{n:02}.py")
    findings, record = security.run_bandit(repo)
    assert record["state"] == "ok"
    assert sorted({f["file"] for f in findings}) == ["app.py"] and PRIVATE not in json.dumps(findings)
    assert record["scope"] == {"files": 1}
    assert [x for x in record["exclusions"] if x.endswith(".py")] == [f"tool{n:02}.py" for n in range(12)]


@needs_links
def test_a_folder_named_like_one_bandit_skips_is_still_looked_into(tmp_path):
    """`build/`, `vendor/` and their like are left out of Bandit at the top of the project only. A link in a folder
    of that name further down is opened by Bandit like any other, so it has to be found and left out too."""
    repo = _write(tmp_path / "project", APP | {"pkg/build/keep.py": SHELL, "build/made.py": SHELL})
    outside = tmp_path / "outside.py"
    outside.write_text(SHELL.rstrip("\n") + "  # " + PRIVATE + "\n", encoding="utf-8")
    os.symlink(outside, repo / "pkg" / "build" / "tool.py")
    os.symlink(outside, repo / "build" / "tool.py")
    findings, record = security.run_bandit(repo)
    assert record["state"] == "ok"
    assert sorted({f["file"] for f in findings}) == ["app.py", "pkg/build/keep.py"]
    assert PRIVATE not in json.dumps(findings)
    assert record["exclusions"] == ["build", "pkg/build/tool.py"]   # the whole top folder, and the one link below
    assert record["scope"] == {"files": 2}


@needs_links
def test_a_file_bandit_cannot_read_counts_only_when_it_is_the_projects(tmp_path):
    """A project file Bandit cannot read makes the check partial, and is named: that stays. A file that is not the
    project's makes no such gap (here one Bandit does open: its path has a comma, so it cannot be excluded)."""
    cut_short = "def f(:\n"
    repo = _write(tmp_path / "project", APP | {"bad.py": cut_short, "a,b/keep.py": SHELL})
    outside = tmp_path / "outside.py"
    outside.write_text(cut_short, encoding="utf-8")
    os.symlink(outside, repo / "a,b" / "tool.py")
    findings, record = security.run_bandit(repo)
    assert record["state"] == "partial"
    assert len(record["errors"]) == 1 and record["errors"][0].startswith("bad.py: ")
    assert sorted({f["file"] for f in findings}) == ["a,b/keep.py", "app.py"]
    (repo / "bad.py").unlink()
    findings, record = security.run_bandit(repo)
    assert record["state"] == "ok" and not record.get("errors")
    assert sorted({f["file"] for f in findings}) == ["a,b/keep.py", "app.py"]


def test_as_many_exclusions_as_fit_and_no_more(monkeypatch):
    paths = ["/p/a.py", "/p/b.py", "/p/c,d.py", "/p/e.py"]
    one = len("/p/a.p[y]") + 1                                  # each exclusion and the comma after it
    monkeypatch.setattr(security, "EXCLUSIONS_FIT", 3 * one, raising=False)
    assert security._only(paths) == ["/p/a.p[y]", "/p/b.p[y]", "/p/e.p[y]"]   # the one with a comma cannot be written
    monkeypatch.setattr(security, "EXCLUSIONS_FIT", 3 * one - 1, raising=False)
    assert security._only(paths) == ["/p/a.p[y]", "/p/b.p[y]"]
    monkeypatch.setattr(security, "EXCLUSIONS_FIT", one, raising=False)
    assert security._only(paths) == ["/p/a.p[y]"]
    monkeypatch.setattr(security, "EXCLUSIONS_FIT", 1000, raising=False)
    assert security._only(["/p/x[1]/a?.pyw"]) == ["/p/x[[]1]/a[?].py[w]"]   # a name's own brackets and marks, as text


# ---------------------------------------------------------------------------- a repository Lantern clones

QUIET = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main", "-c", "gc.auto=0",
         "-c", "maintenance.auto=false"]


def _commit(path: Path, message: str = "one") -> None:
    if not (path / ".git").exists():
        subprocess.run(["git", *QUIET, "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", *QUIET, "add", "."], cwd=path, check=True)
    subprocess.run(["git", *QUIET, "commit", "-q", "-m", message], cwd=path, check=True)


@needs_links
def test_a_clone_is_written_without_links(tmp_path):
    """For every program that reads a clone after Lantern's own readers: a link in a repository Lantern clones is
    written as a small file that holds the link's own text, as git does on a Windows without links."""
    private = tmp_path / "private.txt"
    private.write_text(PRIVATE + "\n", encoding="utf-8")
    src = _write(tmp_path / "src", APP | {"pkg/mod.py": "y = 2\n"})
    os.symlink(private, src / "lantern-narratives.md")
    os.symlink("app.py", src / "same.py")
    os.symlink("pkg", src / "alias")
    _commit(src)
    dest = tmp_path / "clone"
    remote.fetch(src.as_uri(), dest)
    for name in ("lantern-narratives.md", "same.py", "alias"):
        assert (dest / name).is_file() and not (dest / name).is_symlink(), name
    assert (dest / "lantern-narratives.md").read_text(encoding="utf-8") == str(private)
    assert (dest / "app.py").read_text(encoding="utf-8") == APP["app.py"]
    assert remote.missing_files(dest) == []                     # and the clone still counts as complete
    remote.check_complete(dest, "could not check")
    assert gitfacts.info(dest)["dirty"] is False                # and as unchanged since its commit


@needs_links
def test_a_clone_an_earlier_lantern_made_gets_no_new_link_when_it_is_updated(tmp_path):
    src = _write(tmp_path / "src", APP)
    _commit(src)
    dest, log = tmp_path / "clone", []
    subprocess.run(["git", *QUIET, "clone", "-q", "--depth", "1", "--", src.as_uri(), str(dest)], check=True)
    private = tmp_path / "private.txt"
    private.write_text(PRIVATE + "\n", encoding="utf-8")
    os.symlink(private, src / "lantern-narratives.md")
    _commit(src, "two")
    assert remote.clone("https://github.com/o/r", log=log.append, dest=dest) == dest
    assert log == [f"updating {dest}"]
    assert (dest / "lantern-narratives.md").is_file() and not (dest / "lantern-narratives.md").is_symlink()
    assert (dest / "lantern-narratives.md").read_text(encoding="utf-8") == str(private)


@needs_links
def test_a_cloned_repository_with_a_notes_link_shows_nothing_of_the_file(tmp_path, monkeypatch):
    """End to end: clone, then analyze."""
    _without_bandit(monkeypatch)
    private = tmp_path / "private.txt"
    private.write_text(PRIVATE + "\n", encoding="utf-8")
    src = _write(tmp_path / "src", APP)
    os.symlink(private, src / "lantern-narratives.md")
    _commit(src)
    dest = tmp_path / "clone"
    remote.fetch(src.as_uri(), dest)
    out = _analyze(dest, tmp_path / "out")
    assert PRIVATE not in _everything(out)
    assert _notes(out) == str(private)                          # the link's own text, which the repository held anyway
