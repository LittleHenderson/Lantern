"""What the first public projects showed (2026-11-13, a firm pass or fail, the finish check of stage 2).

Three public projects were run from their links, on a computer with none of their libraries. The JavaScript one's
tests ended with 1,426 passed and 4 failed, and the release decision said "Blocked: the tests failed". None of
the four was the project's doing:

* **A repository's links.** A copy of a repository that Lantern makes itself holds no links (`remote.NO_LINKS`,
  since 2026-11-10: a link is written as a small file that holds the link's own text, so that no program which
  reads the copy is led out of it). Tests that go through a link of their own project, a fixture that is a link
  to a program, a folder shared by a link, then found a small text file where the link was. Now the copy the
  tests run on gets those links back, each one that stays in the project; a link that leads out of the project
  stays the small file it was, and the run says how many.
* **A program that is nowhere.** Where Lantern runs as root the tests run as another user, with the PATH Lantern
  was started with, and a folder on it that this user may not enter (root's own `~/.local/bin`) made the system
  answer "permission denied" where a program is simply not there. Tests that expect "not found" for a missing
  program failed. Now such a folder is not on the tests' PATH, and the run says so.

The project with both languages then showed a third, in a copy of it changed as Lantern's own reason advised:

* **pytest's cache.** Lantern started pytest with its cache switched off, and a project whose own pytest settings
  use the cache (`--failed-first`) had no test run at all: pytest ended with "unrecognized arguments". Now the
  cache is left on; what it writes is in the tests' copy and goes with it.

Each case stands beside its twin."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lantern import gitfacts, remote, sandbox

UNITTEST = ["python", "-m", "unittest", "-v"]
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"]
only_posix = pytest.mark.skipif(os.name != "posix", reason="making a link needs a right of its own on Windows")
needs_root = pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0,
                                reason="needs root (the tests then run as another user)")


def QUIET(line):
    """A log nobody reads."""


THROUGH_LINKS = '''
import os, subprocess, sys, unittest
from pathlib import Path

TOP = Path(__file__).resolve().parent.parent

class Links(unittest.TestCase):
    def test_a_link_to_a_file_is_a_link_and_reads_as_the_file(self):
        self.assertTrue(os.path.islink(TOP / "fixtures" / "same.txt"))
        self.assertEqual((TOP / "fixtures" / "same.txt").read_text(encoding="utf-8"), "as written")

    def test_a_link_to_a_folder_lists_the_folder(self):
        self.assertTrue(os.path.islink(TOP / "shared"))
        self.assertEqual(sorted(os.listdir(TOP / "shared")), ["a.txt", "tool.py"])

    def test_a_program_started_through_a_link_runs(self):
        r = subprocess.run([sys.executable, str(TOP / "fixtures" / "tool-link")], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "the tool ran"), r.stderr)

    def test_a_link_to_a_link_and_one_up_and_down_again(self):
        self.assertEqual((TOP / "fixtures" / "twice.txt").read_text(encoding="utf-8"), "as written")
        self.assertEqual((TOP / "fixtures" / "round.txt").read_text(encoding="utf-8"), "as written")

    def test_a_link_to_nothing_is_still_a_link(self):
        self.assertTrue(os.path.islink(TOP / "fixtures" / "nowhere"))
        self.assertFalse(os.path.exists(TOP / "fixtures" / "nowhere"))
'''

LINKS = {"fixtures/same.txt": "../data/a.txt", "shared": "data", "fixtures/tool-link": "../data/tool.py",
         "fixtures/twice.txt": "same.txt", "fixtures/round.txt": "../shared/../data/a.txt",
         "fixtures/nowhere": "not-there"}


def _repository(folder: Path, source: str, links: dict[str, str]) -> Path:
    """A small git repository with one test file, a data folder and the given links, committed."""
    (folder / "tests").mkdir(parents=True)
    (folder / "data").mkdir()
    (folder / "fixtures").mkdir()
    (folder / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (folder / "tests" / "test_tiny.py").write_text(source, encoding="utf-8")
    (folder / "data" / "a.txt").write_text("as written", encoding="utf-8")
    (folder / "data" / "tool.py").write_text("print('the tool ran')\n", encoding="utf-8")
    (folder / "fixtures" / "kept.txt").write_text("kept", encoding="utf-8")
    for name, target in links.items():
        os.symlink(target, folder / name)
    for args in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "one"]):
        subprocess.run([*GIT, *args], cwd=folder, check=True)
    return folder


def _clone(tmp_path: Path, source: str, links: dict[str, str]) -> Path:
    """Lantern's own copy of such a repository, made the way `lantern analyze <link>` makes it."""
    src = _repository(tmp_path / "src", source, links)
    dest = tmp_path / "clone"
    remote.fetch(src.as_uri(), dest)
    return dest


@only_posix
def test_what_the_cases_below_stand_on(tmp_path):
    """Lantern's own copy of a repository holds each link as a small file with the link's text, and git's record
    of the repository still says which files are links."""
    clone = _clone(tmp_path, THROUGH_LINKS, LINKS)
    for name, target in LINKS.items():
        assert not os.path.islink(clone / name) and (clone / name).read_text(encoding="utf-8") == target, name
    assert sorted(gitfacts.links(clone)) == sorted(LINKS)
    assert gitfacts.links(tmp_path / "src") == sorted(LINKS)          # asked of any repository, the same answer
    (tmp_path / "plain").mkdir()
    assert gitfacts.links(tmp_path / "plain") is None                 # no repository: not known


@only_posix
def test_tests_that_go_through_a_link_of_their_project_pass_in_lanterns_own_copy_too(tmp_path):
    """Until then every one of these failed in a project run from its link, and the decision read Blocked."""
    clone = _clone(tmp_path, THROUGH_LINKS, LINKS)
    lines: list[str] = []
    res = sandbox.run(clone, UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert "Ran 5 tests" in res["output_tail"] and res["blocked"] == [], res
    said = [line for line in lines if "links of the repository" in line or "link of the repository" in line]
    assert said == ["sandbox: 6 links of the repository are links again in the tests' copy (Lantern's own copy "
                    "of a repository keeps each as a small file)"], lines
    # Lantern's copy itself is as it was: still no link in it
    assert [name for name in LINKS if os.path.islink(clone / name)] == []


@only_posix
def test_the_twin_in_a_folder_of_the_persons_own_runs_as_before(tmp_path):
    """A folder the person made keeps its links as it always did, and nothing is said about links."""
    repo = _repository(tmp_path / "mine", THROUGH_LINKS, LINKS)
    lines: list[str] = []
    res = sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert [line for line in lines if "of the repository" in line] == []


OUT_OF_IT = '''
import os, unittest
from pathlib import Path

TOP = Path(__file__).resolve().parent.parent
LEFT = {left!r}

class Links(unittest.TestCase):
    def test_a_link_that_leads_out_is_no_link_here(self):
        for name in LEFT:
            self.assertFalse(os.path.islink(TOP / name), name)
            self.assertTrue(os.path.isfile(TOP / name), name)

    def test_the_link_that_stays_is_one(self):
        self.assertTrue(os.path.islink(TOP / "fixtures" / "same.txt"))

    def test_nothing_outside_is_read_through_them(self):
        for name in LEFT:
            self.assertNotIn("SECRET", (TOP / name).read_text(encoding="utf-8"), name)
'''


@only_posix
def test_a_link_that_leads_out_of_the_project_stays_the_small_file_it_was(tmp_path):
    """The dangerous twin. A repository's links can name any path: one that goes up out of the project, a full
    path, one that only looks as if it stayed (through a link to the project's own top, whose `..` is the folder
    above the project), a link to such a link. None of them is made a link; the one beside them that stays in
    the project is."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("SECRET-of-the-person", encoding="utf-8")
    out = {"up.txt": "../outside/secret.txt", "full.txt": str(outside / "secret.txt"),
           "top": ".", "fixtures/looks-inside.txt": "../top/../outside/secret.txt",
           "fixtures/deep.txt": "../data/../../outside/secret.txt", "to-a-link-out.txt": "up.txt"}
    stays = {"fixtures/same.txt": "../data/a.txt"}
    left = ["up.txt", "full.txt", "fixtures/looks-inside.txt", "fixtures/deep.txt"]
    clone = _clone(tmp_path, OUT_OF_IT.format(left=left), {**out, **stays})
    lines: list[str] = []
    res = sandbox.run(clone, UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert "SECRET" not in res["output_tail"]
    said = [line for line in lines if "of the repository" in line]
    # `top` (the project's own top) and the link to a link that stays a file are links: they lead nowhere outside
    assert said == ["sandbox: 3 links of the repository are links again in the tests' copy (Lantern's own copy "
                    "of a repository keeps each as a small file)",
                    "sandbox: 4 links of the repository lead out of the project and stay small files in the copy: "
                    "tests that go through them do not find what they name"], lines


@only_posix
def test_a_file_the_record_calls_a_link_and_that_is_no_link_text_is_left_alone(tmp_path):
    """What stands at a link's place in Lantern's copy is taken as a link's text only when it can be one: a file
    somebody changed since (longer than a path, more than one line, empty) stays as it is."""
    clone = _clone(tmp_path, THROUGH_LINKS, LINKS)
    (clone / "fixtures" / "same.txt").write_text("../data/a.txt\nand a second line\n", encoding="utf-8")
    (clone / "fixtures" / "twice.txt").write_text("x" * 5000, encoding="utf-8")
    (clone / "fixtures" / "nowhere").write_text("", encoding="utf-8")
    app = tmp_path / "copy"
    lines: list[str] = []
    sandbox._copy_in(clone, app, lines.append)
    assert [n for n in LINKS if os.path.islink(app / n)] == ["shared", "fixtures/tool-link", "fixtures/round.txt"]
    assert (app / "fixtures" / "same.txt").read_text(encoding="utf-8") == "../data/a.txt\nand a second line\n"
    assert any("3 links of the repository are links again" in line for line in lines), lines
    assert any("3 links of the repository lead out of the project" in line for line in lines) is False, lines
    assert any("3 files that the repository holds as links are not a link's text" in line for line in lines), lines


# ---------------------------------------------------------------------------- a program that is nowhere
def _folders(table: dict[str, tuple[int, int, int]]):
    """A stand-in for the system's answer about a path: its mode, owner and group, from a table."""
    import stat
    import types

    def look(path):
        if path not in table:
            raise FileNotFoundError(path)
        mode, uid, gid = table[path]
        return types.SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=gid)
    return look


@only_posix
def test_which_folders_the_tests_user_may_enter():
    """Read from the modes of the folder and of every folder above it, for the user the tests run as (who is in
    no other group): the owner's bits where the folder is that user's, the group's where it is the group's, and
    everybody's otherwise."""
    look = _folders({"/": (0o755, 0, 0), "/usr": (0o755, 0, 0), "/usr/bin": (0o755, 0, 0),
                     "/root": (0o700, 0, 0), "/root/bin": (0o755, 0, 0),
                     "/theirs": (0o700, 65534, 0), "/theirs/bin": (0o070, 0, 65534), "/theirs/other": (0o007, 65534, 65534),
                     "/group": (0o750, 0, 65534), "/listed": (0o744, 0, 0)})

    def may(path):
        return sandbox._may_enter(path, 65534, 65534, look)

    assert may("/usr/bin") and may("/") and may("/usr/bin/")
    assert not may("/root") and not may("/root/bin")             # open itself, under a folder that is closed
    assert may("/theirs") and may("/theirs/bin") and may("/group")
    assert not may("/theirs/other")                              # the owner's bits count for the owner, not everybody's
    assert not may("/listed")                                    # may be listed, not entered
    assert not may("/not/there") and not may("relative/bin") and not may("")
    kept, left = sandbox._path_for(os.pathsep.join(["/root/bin", "/usr/bin", "", "relative", "/listed", "/", "/gone"]),
                                   65534, 65534, look)
    # what is there and closed to that user is left out; what is not there, or no full path, is not this rule's
    assert kept == os.pathsep.join(["/usr/bin", "", "relative", "/", "/gone"]) and left == ["/root/bin", "/listed"]


NOWHERE = '''
import os, shutil, subprocess, unittest

class Programs(unittest.TestCase):
    def test_a_program_that_is_nowhere_is_not_found(self):
        with self.assertRaises(FileNotFoundError):
            subprocess.run(["lantern-no-such-program"])
        with self.assertRaises(FileNotFoundError):
            os.execvp("lantern-no-such-program", ["lantern-no-such-program"])

    def test_a_program_that_is_there_is_found_and_runs(self):
        self.assertTrue(shutil.which("sh"))
        self.assertEqual(subprocess.run(["sh", "-c", "exit 7"]).returncode, 7)
'''


def _plain_project(folder: Path, source: str) -> Path:
    (folder / "tests").mkdir(parents=True)
    (folder / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (folder / "tests" / "test_tiny.py").write_text(source, encoding="utf-8")
    return folder


@only_posix
def test_a_program_that_is_nowhere_is_not_found_in_the_sandbox_either(tmp_path):
    """The honest twin, for every user: with nothing closed on PATH the answer is the one tests get at home."""
    res = sandbox.run(_plain_project(tmp_path / "tiny", NOWHERE), UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]


@needs_root
def test_a_folder_of_path_the_tests_user_may_not_enter_does_not_turn_not_found_into_refused(tmp_path, monkeypatch):
    """As root, with a folder of root's alone first on PATH, as on a computer where root has programs of its
    own: until then the first test failed with PermissionError, as two tests of a public project did."""
    import tempfile
    mine = Path(tempfile.mkdtemp(prefix="lantern-roots-own-"))
    try:
        os.chmod(mine, 0o700)
        (mine / "bin").mkdir()
        monkeypatch.setenv("PATH", os.pathsep.join([str(mine / "bin"), os.environ.get("PATH", "")]))
        lines: list[str] = []
        res = sandbox.run(_plain_project(tmp_path / "tiny", NOWHERE), UNITTEST, log=lines.append, backend="subprocess")
        assert res["returncode"] == 0, res["output_tail"]
        said = [line for line in lines if "PATH" in line and "closed to the user the tests run as" in line]
        assert len(said) == 1 and str(mine / "bin") in said[0], lines
    finally:
        os.chmod(mine, 0o700)
        import shutil
        shutil.rmtree(mine, ignore_errors=True)
    # the twin: with no such folder on PATH nothing is said
    monkeypatch.setenv("PATH", os.pathsep.join(p for p in os.environ["PATH"].split(os.pathsep)
                                               if p and sandbox._may_enter(p, 65534, 65534)))
    lines = []
    res = sandbox.run(_plain_project(tmp_path / "twin", NOWHERE), UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0 and [line for line in lines if "closed to the user the tests run as" in line] == []


# ---------------------------------------------------------------------------- pytest's own settings
def _pytest_project(folder: Path, settings: str) -> Path:
    folder.mkdir(parents=True)
    (folder / "pyproject.toml").write_text(settings, encoding="utf-8")
    (folder / "test_it.py").write_text("def test_it():\n    assert 1 + 1 == 2\n", encoding="utf-8")
    return folder


@pytest.mark.parametrize("option", ["--failed-first", "--last-failed", "--cache-clear", "--new-first"])
def test_a_project_whose_pytest_settings_use_pytests_cache_has_its_tests_run(tmp_path, option):
    """A project may write `--failed-first` in its own pytest settings. Lantern switched pytest's cache off for
    every run (the cache is written beside the tests, which the sandbox refused until the tests got a copy of
    their own, 2026-11-13), and pytest then does not know the option: "unrecognized arguments", not one test
    run, and the release decision read "the tests failed". Found on a public project (2026-11-13). The cache is
    written in the copy, and is gone with it."""
    repo = _pytest_project(tmp_path / "proj", f'[tool.pytest.ini_options]\naddopts = "{option}"\n')
    res = sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=QUIET, backend="subprocess")
    assert res["returncode"] == 0 and "1 passed" in res["output_tail"], res["output_tail"]
    assert sorted(p.name for p in repo.iterdir()) == ["pyproject.toml", "test_it.py"]


def test_the_twin_with_no_such_setting_runs_as_before_and_one_that_asks_for_no_cache_gets_none(tmp_path):
    repo = _pytest_project(tmp_path / "proj", '[tool.pytest.ini_options]\naddopts = "-q"\n')
    res = sandbox.run(repo, ["python", "-m", "pytest"], log=QUIET, backend="subprocess")
    assert res["returncode"] == 0 and "1 passed" in res["output_tail"], res["output_tail"]
    res = sandbox.run(repo, ["python", "-m", "pytest", "-p", "no:cacheprovider"], log=QUIET, backend="subprocess")
    assert res["returncode"] == 0 and "1 passed" in res["output_tail"], res["output_tail"]
    assert sorted(p.name for p in repo.iterdir()) == ["pyproject.toml", "test_it.py"]


def test_the_python_that_runs_this_is_named():
    """The names this file's cases use, so that a renamed helper fails here and not in the middle of a run."""
    assert callable(sandbox._copy_in) and callable(gitfacts.links) and sys.executable
