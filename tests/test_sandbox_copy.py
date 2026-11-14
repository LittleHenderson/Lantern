"""The tests may change their own copy of the project, and nothing else (2026-11-13).

The sandbox runs a project's tests on a copy of the project, which is thrown away afterwards. Until then the copy
was marked "cannot be changed" as well (every write bit taken off, and the kernel's rules let the tests write in
their temp folder only), so a test that does what tests do at home failed in the sandbox: one that writes a file
beside the code (a coverage record, a snapshot, a small database), and one that copies a sample folder somewhere
and writes into the copy, because a copy made the usual way keeps the marks of what it was copied from. Lantern's
own tests were among them: 94 of the first 300 failed that way and no other.

Now the copy is the tests' to change. What is kept out of reach is what always was: the project itself, and
everything else on the computer. Each case here stands beside the twin that reaches outside the copy, which must
still be refused and written down. Lantern's own driver for behaviour checks (`run_inside`) still gets a copy it
cannot change: there a write outside the app's data folder is what the check is looking for
(`tests/test_behave.py::test_the_shop_samples_planted_command_is_seen_as_a_file_the_request_chose`)."""
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest
from test_sandbox import BACKENDS

from lantern import sandbox

PYTEST = ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"]


def QUIET(line):
    """A log nobody reads."""


def _failed(out: str) -> set[str]:
    """The names of the tests pytest's summary says failed."""
    return {line.split("::", 1)[1].split(" ", 1)[0] for line in out.splitlines()
            if line.startswith("FAILED ") and "::" in line}


def _project(folder: Path, source: str) -> Path:
    """A small project: one test file, a sample folder, and a file only its owner may read."""
    (folder / "tests").mkdir(parents=True)
    (folder / "data" / "sub").mkdir(parents=True)
    (folder / "keys").mkdir()
    (folder / "pyproject.toml").write_text("[project]\nname = 'tiny'\n", encoding="utf-8")
    (folder / "tests" / "test_tiny.py").write_text(source, encoding="utf-8")
    (folder / "data" / "a.txt").write_text("as written", encoding="utf-8")
    (folder / "data" / "sub" / "b.txt").write_text("b", encoding="utf-8")
    (folder / "keys" / "id").write_text("private", encoding="utf-8")
    os.chmod(folder / "keys" / "id", 0o600)
    os.chmod(folder / "keys", 0o700)
    return folder


def _listing(folder: Path) -> list[tuple[str, int, str]]:
    """Every file of a folder: its name, its mode and what it holds."""
    out = []
    for p in sorted(folder.rglob("*")):
        if p.is_file() and not p.is_symlink():
            out.append((p.relative_to(folder).as_posix(), stat.S_IMODE(p.stat().st_mode), p.read_text(encoding="utf-8")))
    return out


AT_HOME = '''
import os, shutil, sqlite3, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOP = HERE.parent

def test_a_file_written_beside_the_tests_is_there():
    (HERE / "made.txt").write_text("made by a test", encoding="utf-8")
    assert (HERE / "made.txt").read_text(encoding="utf-8") == "made by a test"

def test_a_file_of_the_project_is_changed_in_the_copy():
    (TOP / "data" / "a.txt").write_text("changed", encoding="utf-8")
    assert (TOP / "data" / "a.txt").read_text(encoding="utf-8") == "changed"
    os.remove(TOP / "data" / "sub" / "b.txt")
    (TOP / "build" / "out").mkdir(parents=True)

def test_a_copy_of_a_sample_folder_can_be_written_into(tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(TOP / "data", copy)
    (copy / "new.txt").write_text("x", encoding="utf-8")
    (copy / "sub" / "deeper").mkdir()
    (copy / "a.txt").write_text("the copy's own", encoding="utf-8")

def test_a_program_that_is_not_python_writes_in_the_copy():
    if os.name != "posix":
        return
    r = subprocess.run(["sh", "-c", 'echo x > "$1"', "sh", str(HERE / "made-by-sh.txt")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (HERE / "made-by-sh.txt").read_text(encoding="utf-8") == "x\\n"

def test_a_database_beside_the_code():
    db = sqlite3.connect(str(TOP / "app.db"))
    db.execute("create table t (x)")
    db.execute("insert into t values (1)")
    db.commit()
    assert db.execute("select count(*) from t").fetchone() == (1,)
    db.close()

def test_a_file_only_its_owner_may_read_is_read():
    assert (TOP / "keys" / "id").read_text(encoding="utf-8") == "private"
'''


@pytest.mark.parametrize("backend", BACKENDS)
def test_tests_that_write_beside_their_code_run_as_they_do_at_home(backend, tmp_path):
    repo = _project(tmp_path / "tiny", AT_HOME)
    before = _listing(repo)
    r = sandbox.run(repo, PYTEST, log=QUIET, backend=backend)
    assert r["returncode"] == 0, r["output_tail"]
    assert r["blocked"] == []
    assert _listing(repo) == before, "the project itself was changed"       # nothing the tests did is in the project
    assert not (repo / "build").exists() and not (repo / "app.db").exists()


OUTSIDE = '''
import os, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = Path((HERE / "where.txt").read_text(encoding="utf-8").strip())

def test_write_outside_the_copy():
    (OUT / "planted.txt").write_text("x", encoding="utf-8")

def test_make_a_folder_outside_the_copy():
    os.mkdir(OUT / "planted-folder")

def test_write_outside_below_python():
    if os.name != "posix":
        return
    # not Python's own file functions: only the kernel's rules (Landlock, a container's read-only files) stop this
    r = subprocess.run(["sh", "-c", 'echo x > "$1"', "sh", str(OUT / "planted-sh.txt")], capture_output=True, text=True)
    print("SH", r.returncode, r.stderr.strip())
    assert r.returncode == 0, r.stderr

def test_the_copy_is_still_the_tests_own():
    (HERE / "made.txt").write_text("x", encoding="utf-8")
'''


@pytest.fixture()
def outside():
    """A folder that is not the tests' copy and that every user of this computer may come to and write in (a
    test's tmp_path is its owner's alone, and the sandbox's tests run as `nobody` when Lantern is root): nothing
    but the sandbox keeps the tests out of it."""
    folder = Path(tempfile.mkdtemp(prefix="outside-"))
    folder.chmod(0o777)
    try:
        yield folder
    finally:
        shutil.rmtree(folder, ignore_errors=True)


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_twin_that_writes_outside_its_copy_is_still_refused_and_written_down(backend, tmp_path, outside):
    repo = _project(tmp_path / "tiny", OUTSIDE)
    # a container has its own files: there the place outside is a folder of the container, which cannot be changed
    (repo / "tests" / "where.txt").write_text("/usr" if backend == "docker" else str(outside), encoding="utf-8")
    before = _listing(repo)
    r = sandbox.run(repo, PYTEST, log=QUIET, backend=backend)
    out = r["output_tail"]
    assert r["returncode"] == 1, out
    failed = _failed(out)
    assert {"test_write_outside_the_copy", "test_make_a_folder_outside_the_copy"} <= failed, out
    assert "test_the_copy_is_still_the_tests_own" not in failed, out
    assert {b["kind"] for b in r["blocked"]} == {"write"}, r["blocked"]
    assert any("planted.txt" in b["what"] for b in r["blocked"]), r["blocked"]
    if sys.platform.startswith("linux") and (backend == "docker" or sandbox.landlock_abi() >= 1):
        assert "test_write_outside_below_python" in failed, out
        assert list(outside.iterdir()) == []
    assert not (outside / "planted.txt").exists() and not (outside / "planted-folder").exists()
    assert _listing(repo) == before, "the project itself was changed"


REAL = '''
from pathlib import Path

HERE = Path(__file__).resolve().parent
REAL = Path((HERE / "where.txt").read_text(encoding="utf-8").strip())

def test_change_a_file_of_the_project_itself():
    (REAL / "data" / "a.txt").write_text("changed", encoding="utf-8")

def test_add_a_file_to_the_project_itself():
    (REAL / "tests" / "planted.py").write_text("x = 1", encoding="utf-8")
'''


def test_the_project_itself_stays_out_of_reach(tmp_path):
    """The copy is what the tests may change; the folder it was copied from is like any other place outside."""
    repo = _project(tmp_path / "tiny", REAL)
    os.chmod(repo, 0o777)
    os.chmod(repo / "tests", 0o777)
    os.chmod(repo / "data" / "a.txt", 0o666)
    (repo / "tests" / "where.txt").write_text(str(repo), encoding="utf-8")
    before = _listing(repo)
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess")
    assert r["returncode"] == 1, r["output_tail"]
    assert _failed(r["output_tail"]) == {"test_change_a_file_of_the_project_itself", "test_add_a_file_to_the_project_itself"}
    assert {b["kind"] for b in r["blocked"]} == {"write"}, r["blocked"]
    assert _listing(repo) == before


LINKED = '''
from pathlib import Path

HERE = Path(__file__).resolve().parent

def test_the_link_is_a_link_in_the_copy_too():
    assert (HERE / "link").is_symlink()
'''


@pytest.mark.skipif(os.name != "posix", reason="making a link needs a right of its own on Windows")
def test_a_link_out_of_the_project_is_not_followed_when_the_copy_is_handed_over(tmp_path):
    """The copy is handed to the user the tests run as (when Lantern is root) and never marked: neither goes
    through a link the project brought to a file or a folder outside it."""
    repo = _project(tmp_path / "tiny", LINKED)
    others = Path(tempfile.mkdtemp(prefix="others-"))
    others.chmod(0o755)              # where the sandbox's own user can come, unlike a test's tmp_path
    try:
        target, folder = others / "somebody-elses.txt", others / "somebody-elses"
        target.write_text("not the project's", encoding="utf-8")
        folder.mkdir()
        (folder / "inside.txt").write_text("not the project's either", encoding="utf-8")
        os.chmod(target, 0o644)
        os.chmod(folder, 0o755)
        os.symlink(target, repo / "tests" / "link")
        os.symlink(folder, repo / "data" / "linked-folder")
        seen = [(p, os.stat(p).st_uid, os.stat(p).st_gid, stat.S_IMODE(os.stat(p).st_mode))
                for p in (target, folder, folder / "inside.txt")]
        r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess")
        assert r["returncode"] == 0, r["output_tail"]
        for p, uid, gid, mode in seen:
            st = os.stat(p)
            assert (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (uid, gid, mode), p
        assert target.read_text(encoding="utf-8") == "not the project's"
    finally:
        shutil.rmtree(others, ignore_errors=True)


def test_the_copy_is_made_anew_for_every_run(tmp_path):
    """What one run's tests left in their copy is not there for the next run."""
    source = '''
from pathlib import Path

HERE = Path(__file__).resolve().parent

def test_nothing_is_left_from_an_earlier_run():
    assert not (HERE / "left.txt").exists()
    (HERE / "left.txt").write_text("x", encoding="utf-8")
'''
    repo = _project(tmp_path / "tiny", source)
    for _ in range(2):
        r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess")
        assert r["returncode"] == 0, r["output_tail"]
    assert not (repo / "tests" / "left.txt").exists()


def test_the_sheet_says_what_the_tests_may_change(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    words = " ".join(sandbox.describe(tmp_path, "python")["details"])
    assert "a fresh copy of your project in a temp folder" in words
    assert "the tests can change the copy and nothing else" in words
    assert "read-only copy" not in words

