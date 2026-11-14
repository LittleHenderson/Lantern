"""What the two checks of stage 2's first change showed (2026-11-14, a firm pass or fail).

The change was pushed with every sandbox and library test passing on the computer it was written on. Two checks
then ran on it, and both failed: GitHub's own run of the tests (21 failed there), and Lantern's own tests run by
Lantern in the sandbox (decision "Incomplete": 334 failed, where stage 1's code had "Passed" with none). Sorted by
cause, these were faults of the new code, each of which a project of somebody else's would have met too:

* **Moving a file from one folder to another.** The doorman's side of a run was put one Landlock domain below
  the doorman (`_jail._below`), with one rule, "no signal to a process outside". Linux refuses a move or a second
  name from one folder to another to every process under any such domain that does not allow it by name, also
  where the domain is about something else, and says "Invalid cross-device link". So tests that moved a file
  between two folders of their own temp folder, or gave it a second name there, failed in the sandbox and passed
  at home. Now that domain allows it everywhere, and the rules for writes above it decide as they did.
* **Lantern's own install record.** Where Lantern is installed for editing in place inside the home folder (a
  developer's clone, GitHub's machines), the folder around its package was open to the tests by name only, and
  the record of the install that lies there (`lantern.egg-info`) was closed with the rest of the home folder.
  Python reads the record of every installed library when it starts pytest, so every run in such a place ended
  with "read of …/lantern.egg-info/entry_points.txt (your own folders are closed to the tests)" in its results,
  and tests that failed were then not counted as failed. Now that record is open like the package it belongs to.
* **A run inside a run.** Tests that start a run themselves (Lantern's own) run on libraries Lantern fetched for
  the outer run, which lie in the outer run's folder: a temp folder, closed to the inner run's tests. They
  could not read the libraries they run on ("No module named pytest"). Now every folder of installed libraries
  this Python has on its path stays open, wherever it lies; a project of the person's own that is on the path
  stays closed, as before.

Each case stands beside its twin: what must stay refused is still refused."""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from lantern import sandbox

LINUX = sys.platform.startswith("linux")
UNITTEST = ["python", "-m", "unittest", "-v"]
only_posix = pytest.mark.skipif(os.name != "posix", reason="a second name for a file needs a right of its own on Windows")


@pytest.fixture
def open_place():
    """A folder every user of this computer may enter, deleted afterwards. Where Lantern runs as root the tests
    of a project run as another user, who may not enter pytest's own temp folder: what a run is made of (a Python,
    a copy of Lantern) has to lie where that user can come to it, as it does on a person's computer."""
    top = Path(tempfile.mkdtemp(prefix="lantern-test-second-"))
    os.chmod(top, 0o755)
    try:
        yield top
    finally:
        shutil.rmtree(top, ignore_errors=True)


def _project(folder: Path, source: str, **more: str) -> Path:
    folder.mkdir(parents=True)
    (folder / "pyproject.toml").write_text("[project]\nname = 'tiny'\n", encoding="utf-8")
    (folder / "test_tiny.py").write_text(textwrap.dedent(source), encoding="utf-8")
    for name, text in more.items():
        (folder / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return folder


# ---------------------------------------------------------------------------- moving a file between folders
MOVES = '''
import os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

class Moves(unittest.TestCase):
    def setUp(self):
        self.top = Path(tempfile.mkdtemp())
        self.a, self.b = self.top / "a", self.top / "b"
        self.a.mkdir()
        self.b.mkdir()
        (self.a / "one.txt").write_text("1", encoding="utf-8")

    def test_a_file_is_moved_to_another_folder(self):
        os.rename(self.a / "one.txt", self.b / "moved.txt")
        self.assertEqual(sorted(os.listdir(self.a)), [])
        self.assertEqual((self.b / "moved.txt").read_text(encoding="utf-8"), "1")

    def test_a_file_takes_the_place_of_one_in_another_folder(self):
        (self.b / "old.txt").write_text("old", encoding="utf-8")
        os.replace(self.a / "one.txt", self.b / "old.txt")
        self.assertEqual((self.b / "old.txt").read_text(encoding="utf-8"), "1")

    def test_a_file_gets_a_second_name_in_another_folder(self):
        os.link(self.a / "one.txt", self.b / "also.txt")
        self.assertTrue(os.path.samefile(self.a / "one.txt", self.b / "also.txt"))

    def test_a_folder_with_what_is_in_it_is_moved_into_another(self):
        (self.a / "inner").mkdir()
        (self.a / "inner" / "f.txt").write_text("f", encoding="utf-8")
        os.rename(self.a / "inner", self.b / "inner")
        self.assertEqual((self.b / "inner" / "f.txt").read_text(encoding="utf-8"), "f")

    def test_from_the_projects_copy_to_the_temp_folder_and_back(self):
        Path("made.txt").write_text("made", encoding="utf-8")
        os.rename("made.txt", self.a / "made.txt")
        os.rename(self.a / "made.txt", "back.txt")
        self.assertEqual(Path("back.txt").read_text(encoding="utf-8"), "made")

    def test_a_program_that_is_not_python_under_the_guard_does_the_same(self):
        code = ("import os, sys\\n"
                "a, b = sys.argv[1:3]\\n"
                "os.link(a + '/one.txt', b + '/also.txt')\\n"
                "os.rename(a + '/one.txt', b + '/moved.txt')\\n")
        r = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(self.a), str(self.b)],
                           capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(sorted(os.listdir(self.b)), ["also.txt", "moved.txt"])
'''


@only_posix
def test_tests_that_move_a_file_from_one_of_their_folders_to_another_run_as_they_do_at_home(tmp_path):
    """Six of six failed in the sandbox on the code before ("Invalid cross-device link"), where the kernel has
    the rule the doorman's side is put under (Linux 6.12 on), and passed at home and on stage 1's code."""
    repo = _project(tmp_path / "tiny", MOVES)
    lines: list[str] = []
    res = sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0 and "Ran 6 tests" in res["output_tail"], res["output_tail"]
    assert res["blocked"] == [], res["blocked"]


OUT = '''
import os, subprocess, sys, tempfile, unittest
from pathlib import Path

OUTSIDE = Path({outside!r})

class Out(unittest.TestCase):
    def setUp(self):
        self.mine = Path(tempfile.mkdtemp()) / "mine.txt"
        self.mine.write_text("mine", encoding="utf-8")

    def test_a_file_is_not_moved_out_of_the_tests_folders(self):
        with self.assertRaises(OSError):
            os.rename(self.mine, OUTSIDE / "moved.txt")
        self.assertTrue(self.mine.exists())

    def test_nor_given_a_second_name_out_there(self):
        with self.assertRaises(OSError):
            os.link(self.mine, OUTSIDE / "also.txt")

    def test_nor_by_a_program_that_is_not_python_under_the_guard(self):
        code = ("import os, sys\\n"
                "for do in (os.rename, os.link):\\n"
                "    try:\\n"
                "        do(sys.argv[1], sys.argv[2] + '/' + do.__name__ + '.txt')\\n"
                "        print('DONE', do.__name__)\\n"
                "    except OSError as e:\\n"
                "        print('refused', do.__name__)\\n")
        r = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(self.mine), str(OUTSIDE)],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.split(), ["refused", "rename", "refused", "link"], r.stderr)
'''


@only_posix
def test_the_twin_that_moves_a_file_out_of_its_folders_is_still_refused(tmp_path):
    """What the rule is for stays: nothing of the tests' appears in a folder that is not theirs, by Python or by
    a program below it, and Python's tries are written down."""
    outside = tmp_path / "outside"
    outside.mkdir()
    os.chmod(outside, 0o777)                    # the system's own rights would let any user write there
    repo = _project(tmp_path / "tiny", OUT.format(outside=str(outside)))
    res = sandbox.run(repo, UNITTEST, log=lambda line: None, backend="subprocess")
    assert sorted(os.listdir(outside)) == [], os.listdir(outside)
    if LINUX and sandbox.landlock_abi() >= 1:
        # where the kernel holds the tests to their folders, each of the three is refused and the tests pass
        assert res["returncode"] == 0 and "Ran 3 tests" in res["output_tail"], res["output_tail"]
    assert {b["kind"] for b in res["blocked"]} <= {"write", "read"}, res["blocked"]
    assert any(b["kind"] == "write" and "outside" in b["what"] for b in res["blocked"]), res["blocked"]


@pytest.mark.skipif(not LINUX, reason="the rule is Linux's")
def test_the_rule_that_keeps_signals_from_the_doorman_leaves_moves_to_the_rules_above_it(tmp_path):
    """The rule itself, with no run around it: a process under the rules for writes and then under the doorman's
    extra rule moves and links between two folders it may write in, and not into one it may not."""
    if sandbox.landlock_abi() < 6:
        pytest.skip("this kernel's Landlock has no rule about signals (Linux 6.12 on), so no such domain is made")
    mine, other = tmp_path / "mine", tmp_path / "other"
    for folder in (mine / "a", mine / "b", other):
        folder.mkdir(parents=True)
    (mine / "a" / "one.txt").write_text("1", encoding="utf-8")
    code = textwrap.dedent('''
        import ctypes, os, sys
        from lantern import _jail
        mine, other = sys.argv[1:3]
        state, failed, _ = _jail._landlock([mine], False)
        assert failed is None and state.startswith("on"), state
        assert _jail._below(ctypes.CDLL(None, use_errno=True)) == 0
        os.link(mine + "/a/one.txt", mine + "/b/also.txt")
        os.rename(mine + "/a/one.txt", mine + "/b/moved.txt")
        for do in (os.rename, os.link):
            try:
                do(mine + "/b/moved.txt", other + "/" + do.__name__ + ".txt")
                print("DONE", do.__name__)
            except OSError:
                print("refused", do.__name__)
    ''')
    r = subprocess.run([sys.executable, "-c", code, str(mine), str(other)], capture_output=True, text=True,
                       encoding="utf-8", env={**os.environ, "PYTHONPATH": str(Path(sandbox.__file__).parent.parent)})
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["refused", "rename", "refused", "link"], r.stdout
    assert sorted(os.listdir(mine / "b")) == ["also.txt", "moved.txt"] and os.listdir(other) == []


# ---------------------------------------------------------------------------- what a run is made of, in a closed folder
RUN = '''
import json, sys
from pathlib import Path
from lantern import sandbox
lines = []
res = sandbox.run(Path(sys.argv[1]), sys.argv[2:], log=lines.append, backend="subprocess")
print("RESULT " + json.dumps({"rc": res["returncode"], "blocked": res["blocked"], "tail": res["output_tail"][-4000:],
                              "lines": lines, "where": sandbox.__file__,
                              "wall": sandbox.read_wall(Path(sys.argv[1]), Path(sys.argv[1]), "python", False)}))
'''


def _run_as(python: str, env: dict, repo: Path, words: list[str]) -> dict:
    """A run of `repo`'s tests started by another Python, or by this one with another environment: its result."""
    import json
    r = subprocess.run([python, "-c", RUN, str(repo), *words], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, timeout=600, cwd=str(repo.parent))
    told = [line for line in r.stdout.splitlines() if line.startswith("RESULT ")]
    assert r.returncode == 0 and told, (r.stdout[-3000:], r.stderr[-3000:])
    return json.loads(told[-1][7:])


def _lantern_installed_for_editing_in(home: Path) -> Path:
    """A copy of Lantern as a developer has it: the package in a folder of the home folder, the record of its
    install beside it, and files of the person's own beside both."""
    top = home / "code" / "Lantern"
    shutil.copytree(Path(sandbox.__file__).resolve().parent, top / "lantern",
                    ignore=shutil.ignore_patterns("__pycache__"))
    record = top / "lantern.egg-info"
    record.mkdir()
    (record / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: lantern\nVersion: 0.0.1\n", encoding="utf-8")
    (record / "entry_points.txt").write_text("[console_scripts]\nlantern = lantern.cli:main\n", encoding="utf-8")
    (record / "top_level.txt").write_text("lantern\n", encoding="utf-8")
    (top / "notes.txt").write_text("the person's own notes: SECRET-NOTES\n", encoding="utf-8")
    (top / "private").mkdir()
    (top / "private" / "keys.txt").write_text("SECRET-KEYS\n", encoding="utf-8")
    return top


READS_BESIDE = '''
import importlib.metadata, unittest
from pathlib import Path

TOP = Path({top!r})

class Reads(unittest.TestCase):
    def test_python_reads_the_record_of_lanterns_install_as_a_test_runner_does(self):
        found = [d for d in importlib.metadata.distributions()
                 if d.metadata["Name"] == "lantern" and d.version == "0.0.1"]
        self.assertEqual(len(found), 1)
        self.assertEqual([e.name for e in found[0].entry_points], ["lantern"])

    def test_the_persons_own_files_beside_it_are_not_read(self):
        for name in ("notes.txt", "private/keys.txt"):
            try:
                text = (TOP / name).read_text(encoding="utf-8")
            except OSError:
                text = ""
            self.assertNotIn("SECRET", text, name)
'''


@only_posix
def test_lanterns_own_install_record_in_the_home_folder_is_not_a_read_the_tests_were_refused(tmp_path, open_place):
    """On GitHub's machines 19 tests failed for this alone: every run there named a refused read of
    `lantern.egg-info/entry_points.txt`, which Python itself reads, and a run that was refused something is not
    counted as tests that failed."""
    home = open_place / "home"
    top = _lantern_installed_for_editing_in(home)
    repo = _project(tmp_path / "tiny", READS_BESIDE.format(top=str(top)))
    env = {**os.environ, "HOME": str(home), "PYTHONPATH": str(top)}
    got = _run_as(sys.executable, env, repo, UNITTEST)
    assert Path(got["where"]).parent.parent == top, got["where"]         # the run was this copy's
    assert "Ran 2 tests" in got["tail"], got["tail"]
    walled = got["wall"] is not None
    if not walled:          # no rule for reads on this system: nothing is closed, nothing is said
        assert got["blocked"] == [], got["blocked"]
        return
    record = os.path.realpath(top / "lantern.egg-info")
    assert record in got["wall"]["open"] and os.path.realpath(top) in got["wall"]["list"], got["wall"]
    # ... and nothing else of that folder: not the folder itself, not a folder of the person's own in it
    assert not any(os.path.realpath(p) in (os.path.realpath(top), os.path.realpath(top / "private"))
                   for p in got["wall"]["open"]), got["wall"]["open"]
    assert got["rc"] == 0, got["tail"]
    assert [b for b in got["blocked"] if "egg-info" in b["what"]] == [], got["blocked"]
    # what the tests themselves reached for is still said, and nothing that Python read on its own account
    assert [b["kind"] for b in got["blocked"]] == ["read", "read"], got["blocked"]
    assert ["notes.txt" in got["blocked"][0]["what"], "private" in got["blocked"][1]["what"]] == [True, True], got["blocked"]


USES_A_LIBRARY = '''
import unittest

class Uses(unittest.TestCase):
    def test_a_library_this_python_has_through_a_path_file_is_found(self):
        import tinylib
        self.assertEqual(tinylib.VALUE, 7)

    def test_a_project_of_the_persons_own_on_the_path_is_not_read(self):
        try:
            import minepkg
            text = minepkg.SECRET
        except (ImportError, OSError):
            text = ""
        self.assertNotIn("SECRET-MINE", text)
'''


@only_posix
def test_tests_find_the_libraries_this_python_has_through_a_path_file_wherever_the_folder_lies(tmp_path, open_place):
    """A run inside a run: Lantern's own tests, run by Lantern, start runs of their own with a Python whose
    libraries are the ones fetched for the outer run, in the outer run's folder (a temp folder: closed). On the
    code before, the inner tests could not read them ("No module named pytest", 34 tests for that alone)."""
    import sysconfig
    import venv
    base = open_place / "py"
    venv.EnvBuilder(system_site_packages=False, symlinks=True, with_pip=False).create(base)
    site = Path(sysconfig.get_path("purelib", "venv", {"base": str(base), "platbase": str(base)}))
    libs = open_place / "fetched" / "libs"
    (libs / "tinylib").mkdir(parents=True)
    (libs / "tinylib" / "__init__.py").write_text("VALUE = 7\n", encoding="utf-8")
    (libs / "tinylib-1.0.dist-info").mkdir()
    (libs / "tinylib-1.0.dist-info" / "METADATA").write_text("Metadata-Version: 2.1\nName: tinylib\nVersion: 1.0\n",
                                                              encoding="utf-8")
    mine = open_place / "mine"
    (mine / "minepkg").mkdir(parents=True)
    (mine / "minepkg" / "__init__.py").write_text("SECRET = 'SECRET-MINE'\n", encoding="utf-8")
    # the libraries Lantern itself runs on here (inside a run of Lantern's own they are that run's fetched ones,
    # which its Python finds through a path file), the folder of fetched libraries, and a project of the person's own
    named = [*sandbox._site_dirs(), *sandbox._library_dirs(), str(libs), str(mine)]
    (site / "named.pth").write_text("".join(p + "\n" for p in named), encoding="utf-8")
    repo = _project(tmp_path / "tiny", USES_A_LIBRARY)
    python = str(base / "bin" / "python")
    env = {**os.environ, "PYTHONPATH": str(Path(sandbox.__file__).resolve().parent.parent)}
    got = _run_as(python, env, repo, UNITTEST)
    assert got["rc"] == 0 and "Ran 2 tests" in got["tail"], got["tail"]
    if got["wall"] is None:
        return
    assert os.path.realpath(libs) in got["wall"]["open"], got["wall"]["open"]
    assert not any(os.path.realpath(p) == os.path.realpath(mine) for p in got["wall"]["open"]), got["wall"]["open"]
    said = [line for line in got["lines"] if "folder(s) of your own that are closed now" in line]
    assert len(said) == 1 and os.path.realpath(mine) in said[0], got["lines"]
    # the closed folder is off the tests' path, so Python's own search of its path is no read they were refused
    # (on the code before, every module not found earlier on the path left "read of …/mine" in the results)
    assert got["blocked"] == [], got["blocked"]


# ------------------------------------------------- what holds a program that is not Python, said as it is
# The second run of Lantern's own tests in the sandbox, on the fixed code, ended with five failures that are one
# thing. A run started inside a run cannot put a doorman of its own before its programs (the kernel takes one
# per chain), so the doorman of the sandbox around it makes every connection of the inner run's programs too,
# and makes it by the outer sandbox's rules: the kernel's rules of the inner run (no TCP, no socket name of a
# program outside) are asked of the one that connects, and that is the outer doorman. Nothing leaves the outer
# sandbox. But the inner run's sheet and log said "network connections refused" and "nothing on this computer is
# let through", which is true there of Python code only. The same words stood, since stage 1, on the sheet of
# JavaScript tests on macOS and Windows, where no rule of the kernel's holds a program that is not Python at all
# (GitHub's Windows machine showed it: such a test reached a listener of the computer).
ABOVE = sandbox.DOORMAN_ABOVE
WHY = "this system refused the rights it takes (error 1)"
NO_DOORMAN = "this system does not let Lantern put a doorman between the tests' programs and the kernel"
CLOSED_WORDS = ("network connections refused", "nothing on this computer is let through")


def _system(monkeypatch, linux=True, network="", doorman="", landlock=7):
    monkeypatch.delenv("LANTERN_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "docker_ok", lambda: False)
    monkeypatch.setattr(sandbox, "_LINUX", linux)
    monkeypatch.setattr(sandbox, "_OWN_NETWORK", [network if linux else "a network of their own for the tests is made on Linux only"])
    monkeypatch.setattr(sandbox, "_OWN_SOCKETS", [doorman if linux else "the doorman is made on Linux only"])
    monkeypatch.setattr(sandbox, "_OWN_MEMORY", [""])
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: landlock if linux else 0)


@pytest.mark.parametrize("held, system", [
    (True, {}),                                                     # a network of the run's own
    (True, {"network": WHY}),                                       # none, and a doorman of the run's own
    (True, {"network": WHY, "doorman": NO_DOORMAN}),                # neither, and the kernel's rule for TCP
    (False, {"network": WHY, "doorman": NO_DOORMAN, "landlock": 3}),  # a kernel before that rule
    (False, {"network": WHY, "doorman": ABOVE}),                    # a run inside a run
    (False, {"linux": False}),                                      # macOS, Windows
])
def test_whether_a_program_that_is_not_python_is_held_is_read_from_what_the_run_was_given(monkeypatch, held, system):
    _system(monkeypatch, **system)
    assert sandbox.held_below_python() is held


@pytest.mark.parametrize("system, says", [
    ({"network": WHY, "doorman": ABOVE}, "sandbox around this one"),
    ({"network": WHY, "doorman": NO_DOORMAN, "landlock": 3}, "kernel"),
    ({"linux": False}, "Linux"),
])
def test_the_sheet_does_not_say_the_network_is_closed_to_tests_that_nothing_keeps_from_it(tmp_path, monkeypatch,
                                                                                          system, says):
    """Tests that are not Python, where nothing below Python holds them: the sheet says so, with the reason."""
    _system(monkeypatch, **system)
    details = sandbox.describe(tmp_path, "node")["details"]
    said = " ".join(details)
    assert not any(words in said for words in CLOSED_WORDS), details
    assert "not kept from the network" in said and says in said, details
    # Python's own tests there: the guard refuses what Python code tries, and the sheet adds what it does not hold
    details = sandbox.describe(tmp_path, "python")["details"]
    said = " ".join(details)
    assert "opening network connections are refused" in said, details
    assert "a program the tests start that is not Python is not kept from the network" in said and says in said, details


@pytest.mark.parametrize("system", [{}, {"network": WHY}, {"network": WHY, "doorman": NO_DOORMAN}])
def test_the_twins_that_are_held_read_as_before(tmp_path, monkeypatch, system):
    _system(monkeypatch, **system)
    for language in ("node", "python"):
        said = " ".join(sandbox.describe(tmp_path, language)["details"])
        assert "not kept from the network" not in said, said
        if system:
            assert CLOSED_WORDS[1] in said, said
        else:
            assert "a network of its own:" in said, said


def test_inside_another_sandbox_the_line_about_the_doorman_says_whose_walls_decide(tmp_path, monkeypatch):
    """Until now it read "can still connect to a socket file of another program of this computer", which is what
    a run with no doorman at all has to say; inside another sandbox the reach ends at that sandbox."""
    _system(monkeypatch, network=WHY, doorman=ABOVE)
    line = next(d for d in sandbox.describe(tmp_path, "python")["details"] if "sandbox around this one" in d
                and "doorman" not in d.split("sandbox around this one")[0][-40:])
    assert "another program of this computer" not in line and "nothing outside" in line, line
    # the twin: no doorman because the system has none
    _system(monkeypatch, network=WHY, doorman=NO_DOORMAN)
    details = sandbox.describe(tmp_path, "python")["details"]
    assert any(NO_DOORMAN in d and "another program of this computer" in d for d in details), details


@pytest.mark.parametrize("language, off, system", [
    ("node", True, {}), ("node", True, {"network": WHY}), ("node", False, {"network": WHY, "doorman": ABOVE}),
    ("node", False, {"linux": False}), ("python", True, {"linux": False}), ("python", True, {"network": WHY, "doorman": ABOVE}),
])
def test_the_line_about_fetched_libraries_says_network_off_only_where_it_is(tmp_path, monkeypatch, language, off, system):
    """`the tests then run with the network off` stood on every sheet; for JavaScript tests where nothing keeps
    a program that is not Python from the network it was not true."""
    import json

    from lantern import libraries
    _system(monkeypatch, **system)
    monkeypatch.delenv("LANTERN_OFFLINE", raising=False)
    monkeypatch.setenv("LANTERN_STORE_PYTHON", "http://127.0.0.1:9/simple/")
    monkeypatch.setenv("LANTERN_STORE_NPM", "http://127.0.0.1:9/")
    if language == "python":
        (tmp_path / "requirements.txt").write_text("tinylib==1.0\n", encoding="utf-8")
    else:
        manifest = {"name": "proj", "version": "1.0.0", "scripts": {"test": "node test.js"},
                    "dependencies": {"tiny-lib": "1.0.0"}}
        lock = {"name": "proj", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
                "packages": {"": manifest, "node_modules/tiny-lib": {
                    "version": "1.0.0", "resolved": "http://127.0.0.1:9/tiny-lib/-/tiny-lib-1.0.0.tgz",
                    "integrity": "sha512-" + "A" * 86 + "=="}}}
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    line = libraries.described(tmp_path, language)
    assert "fetched first" in line, line
    assert ("with the network off" in line) is off, line
    assert ("not kept from the network" in line) is not off, line


@pytest.mark.parametrize("windows", [False, True])
def test_the_line_about_a_python_of_the_runs_own_says_what_windows_does_with_the_bare_name(windows):
    """Windows looks for a program named without its folder in the folder of the program that asks first, and the
    Python of the run's own is, on Windows, a small program that starts the computer's Python: so `python` by its
    bare name, in an environment a test made itself, is the computer's own Python there, with the computer's
    libraries (GitHub's Windows machine: `False False` where every other system says `True True`)."""
    line = sandbox._own_python_words(windows)
    assert "a Python of the run's own" in line
    assert ("by the bare name" in line and "the computer's own Python" in line) is windows, line
    assert ("whatever it is handed" in line) is not windows, line


@pytest.mark.parametrize("off, backend, language, own, system", [
    (True, "docker", "node", False, {"linux": False}),              # a container has a network of its own
    (True, "subprocess", "node", True, {}),                         # so has this run
    (True, "subprocess", "python", False, {"linux": False}),        # Python's tests: the guard
    (True, "subprocess", "node", False, {"network": WHY}),          # another program, held by the run's doorman
    (False, "subprocess", "node", False, {"network": WHY, "doorman": ABOVE}),
    (False, "subprocess", "node", False, {"linux": False}),
])
def test_whether_the_tests_were_off_the_network_is_worked_out_for_the_run_that_was_made(monkeypatch, off, backend,
                                                                                         language, own, system):
    _system(monkeypatch, **system)
    assert sandbox._was_off_network(backend, language, own) is off


def test_a_run_says_whether_its_tests_were_off_the_network_and_the_app_repeats_only_that(tmp_path, monkeypatch):
    """The app's message after a run on fetched libraries ended "with the network off" whatever the run was.
    Now the run says it (`off_network`, in `run.json` under `trace` too) and the page says it only for `true`."""
    import json
    import re

    from lantern import pipeline
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")     # this run's backend, not whatever the computer has
    repo = _project(tmp_path / "tiny", "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n")
    res = sandbox.run(repo, UNITTEST, log=lambda line: None, backend="subprocess")
    assert res["returncode"] == 0 and res["off_network"] is True, res["output_tail"]
    out = repo / ".lantern"
    out.mkdir()
    pipeline.analyze(repo, out, trace_cmd=UNITTEST, sandbox=True, offline=True, log=lambda line: None)
    trace = json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]
    assert trace["ran"] is True and trace["off_network"] is True, trace
    page = (Path(sandbox.__file__).parent / "viewer" / "app.html").read_text(encoding="utf-8")
    said = re.findall(r"[^\n]*with the network off[^\n]*", page)
    assert said and all("r.off_network === true" in line for line in said), said
