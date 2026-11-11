"""Lantern starts only the person's own programs, and a project's own settings do not steer the Python scanner
(2026-11-10, directive stage 7).

Lantern is often started inside the folder of the project it was asked to read, and reading a project must not run
it. Until this date the current folder, and with it the project, could choose what ran:

1. Bandit was started as `python -m bandit`. Python then looks in the current folder first for every module the
   program loads, so a project file named `bandit.py`, `json.py` or `logging.py` ran as a program with the person's
   rights.
2. A program started by its bare name (`git`, `npm`, `pip-audit`, `gitleaks`, `docker`, `tesseract`) was looked for
   the way the system looks: on Windows in the current folder before PATH (`shutil.which` does the same there), and
   on any system in the current folder for a PATH entry that is empty, `.` or another relative path.
3. Bandit takes settings from a `.bandit` file anywhere in the folder it scans. A project could switch its checks
   off or leave its own files out, and Lantern's record then said the scan was complete, with nothing found. Two
   such files, or one that names a file for the report, made the scan fail (Bandit 1.9.4 cannot write to a file
   named that way, so the person's file stayed as it was).

Each case stands beside one that must keep working: the person's own program in an absolute PATH folder is found and
used, and a project's findings are still found.
"""
import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from lantern import ask, depaudit, evidence, mcp_server, remote, sandbox, scanresult, security

ROOT = Path(__file__).resolve().parents[1]
only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (programs written as shell scripts)")
only_windows = pytest.mark.skipif(os.name != "nt", reason="needs Windows (how it looks for a program to start)")
MD5 = {"app.py": "import hashlib\n\n\ndef digest(x):\n    return hashlib.md5(x).hexdigest()\n"}


def _programs():
    from lantern import programs
    return programs


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _marks(tmp_path: Path) -> Path:
    d = tmp_path / "marks"
    d.mkdir(exist_ok=True)
    return d


def _ran(marks: Path, who: str) -> list[str]:
    return sorted(p.name for p in marks.iterdir() if p.name.startswith(who + "-"))


def _module(marks: Path, who: str) -> str:
    """A Python file that only leaves a mark when it is loaded."""
    return f"import os\nopen(os.path.join({str(marks)!r}, {who!r} + '-' + str(os.getpid())), 'w').close()\n"


def _program(folder: Path, name: str, marks: Path, who: str, answer: str = "") -> Path:
    """A program (a shell script) that leaves a mark when it is started and then answers with `answer`."""
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_text(f"#!/bin/sh\n: > '{marks}/{who}-'$$\n{answer}\n", encoding="utf-8")
    p.chmod(0o755)
    return p


def _md5(found: list[dict]) -> list[str]:
    return [f["file"] for f in found if f["rule"] == "B324"]


# ---------------------------------------------------------------- 1. the scanner is not given the current folder


@pytest.mark.parametrize("planted", ["bandit.py", "bandit/__main__.py", "tokenize.py", "logging.py", "argparse.py", "yaml.py"])
def test_the_scanner_started_inside_a_project_loads_no_file_of_the_project(tmp_path, monkeypatch, planted):
    pytest.importorskip("bandit")
    marks, repo = _marks(tmp_path), _write(tmp_path / "p", MD5)
    _write(repo, {planted: _module(marks, "planted")})
    if "/" in planted:
        _write(repo, {"bandit/__init__.py": ""})
    monkeypatch.chdir(repo)                                    # `cd project`, then `lantern analyze .`
    found, record = security.run_bandit(repo)
    assert _ran(marks, "planted") == []
    assert record["state"] == "ok" and record["version"], record
    assert _md5(found) == ["app.py"]


def test_a_relative_folder_in_the_persons_python_path_is_not_handed_to_the_scanner(tmp_path, monkeypatch):
    pytest.importorskip("bandit")
    marks, repo = _marks(tmp_path), _write(tmp_path / "p", MD5)
    _write(repo, {"json.py": _module(marks, "planted")})
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([".", "", os.environ.get("PYTHONPATH", "")]))
    found, record = security.run_bandit(repo)
    assert _ran(marks, "planted") == []
    assert record["state"] == "ok" and _md5(found) == ["app.py"], record


def test_the_twin_a_project_with_such_a_file_is_scanned_from_elsewhere_as_before(tmp_path, monkeypatch):
    pytest.importorskip("bandit")
    marks, repo = _marks(tmp_path), _write(tmp_path / "p", MD5)
    _write(repo, {"json.py": _module(marks, "planted")})
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "elsewhere")
    found, record = security.run_bandit(repo)
    assert _ran(marks, "planted") == [] and record["state"] == "ok" and _md5(found) == ["app.py"]


# ---------------------------------------------------------------- 3. the project's own settings for the scanner


def _settings(tmp_path: Path) -> dict[str, dict[str, str]]:
    other = tmp_path / "another-folder"
    other.mkdir(exist_ok=True)
    return {
        "its checks switched off": {".bandit": "[bandit]\nskips = B324\n"},
        "every file left out": {".bandit": "[bandit]\nexclude = *.py\n"},
        "only another check asked for": {".bandit": "[bandit]\ntests = B101\n"},
        "pointed at another folder": {".bandit": f"[bandit]\ntargets = {other}\n"},
        "a settings file of the project's own": {".bandit": "[bandit]\nconfigfile = {repo}/quiet.yaml\n",
                                                 "quiet.yaml": "skips: ['B324']\n"},
        "in a folder further down": {"pkg/.bandit": "[bandit]\nskips = B324\n", "pkg/x.py": "X = 1\n"},
        "two of them": {"a/.bandit": "[bandit]\n", "b/.bandit": "[bandit]\n", "a/x.py": "X = 1\n", "b/x.py": "X = 1\n"},
    }


@pytest.mark.parametrize("case", ["its checks switched off", "every file left out", "only another check asked for",
                                  "pointed at another folder", "a settings file of the project's own",
                                  "in a folder further down", "two of them"])
def test_a_settings_file_inside_the_project_does_not_steer_the_scanner(tmp_path, case):
    pytest.importorskip("bandit")
    repo = _write(tmp_path / "p", MD5)
    _write(repo, {rel: text.replace("{repo}", str(repo)) for rel, text in _settings(tmp_path)[case].items()})
    found, record = security.run_bandit(repo)
    assert record["state"] == "ok", record
    assert _md5(found) == ["app.py"]


def test_the_scanner_writes_its_report_to_no_file_a_project_names(tmp_path):
    """On the code before, Bandit 1.9.4 failed on this setting and wrote nothing, and so did the scan. A Bandit that
    can write there would write over the file; with settings of Lantern's own it is not asked to."""
    pytest.importorskip("bandit")
    mine = tmp_path / "the-persons-own-file.txt"
    mine.write_text("mine\n", encoding="utf-8")
    repo = _write(tmp_path / "p", {**MD5, ".bandit": f"[bandit]\noutput = {mine}\n"})
    found, record = security.run_bandit(repo)
    assert mine.read_text(encoding="utf-8") == "mine\n"
    assert record["state"] == "ok" and _md5(found) == ["app.py"], record


def test_without_its_own_settings_file_the_scanner_is_not_started(tmp_path, monkeypatch):
    """Started without one, Bandit would look for the project's. No room in the temp folder is the usual reason."""
    pytest.importorskip("bandit")
    repo = _write(tmp_path / "p", {**MD5, ".bandit": "[bandit]\nskips = B324\n"})
    started = []
    monkeypatch.setattr(scanresult, "run_tool", lambda cmd, **kw: started.append(cmd))

    def no_room(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(_programs().tempfile, "TemporaryDirectory", no_room)
    found, record = security.run_bandit(repo)
    assert found == [] and started == []
    assert record["state"] == "failed" and "No space left on device" in record["why"], record


def test_a_settings_folder_that_cannot_be_removed_does_not_cost_the_scan(tmp_path, monkeypatch):
    """Windows may hold a file a moment longer than its writer (a virus scanner reading it). What the scanner found
    stands, and the record does not say that the settings file could not be written."""
    pytest.importorskip("bandit")
    repo = _write(tmp_path / "p", MD5)
    (tmp_path / "temp").mkdir()
    monkeypatch.setattr(_programs().tempfile, "tempdir", str(tmp_path / "temp"))   # what is left stays in the test's folder
    real, held = os.unlink, []

    def busy(path, *a, **k):
        if os.path.basename(os.fspath(path)) == "bandit.ini":
            held.append(path)
            raise OSError(16, "Device or resource busy")
        return real(path, *a, **k)
    monkeypatch.setattr(os, "unlink", busy)
    found, record = security.run_bandit(repo)
    monkeypatch.undo()
    assert held, "the settings file was never cleared away: the test shows nothing"
    assert record["state"] == "ok" and _md5(found) == ["app.py"], record


def test_the_twin_a_project_without_settings_is_scanned_as_before(tmp_path):
    pytest.importorskip("bandit")
    found, record = security.run_bandit(_write(tmp_path / "p", MD5))
    assert record["state"] == "ok" and record["exit_code"] == 1 and _md5(found) == ["app.py"]


# ---------------------------------------------------------------- 2. a program is the person's own


class _Picture:
    """What `ask.ocr_image` needs of a picture."""

    def convert(self, mode):
        return self

    def save(self, buf, format):
        buf.write(b"a picture")


def _git_repo(folder: Path) -> Path:
    git = shutil.which("git")                    # asked before the test changes PATH
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "app.py").write_text("X = 1\n", encoding="utf-8")
    for words in (["init", "-q"], ["add", "app.py"],
                  ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "one"]):
        subprocess.run([git, "-c", "gc.auto=0", "-c", "maintenance.auto=false", *words], cwd=folder, check=True,
                       capture_output=True, timeout=60)
    return folder


def _via_git(tmp_path):
    r = remote._git(["--version"], cwd=None)
    assert r.returncode == 0 and r.stdout.startswith("git version"), (r.stdout, r.stderr)


def _via_commit(tmp_path):
    got = evidence.git_info(Path.cwd())
    assert re.fullmatch(r"[0-9a-f]{40}", got.get("commit") or ""), got


def _via_engine(tmp_path):
    assert evidence.engine_ref()


def _via_npm(tmp_path):
    _write(Path.cwd(), {"package.json": '{"name": "p", "version": "1.0.0"}',
                        "package-lock.json": '{"name": "p", "version": "1.0.0", "lockfileVersion": 3, "packages": {}}'})
    found, record = depaudit.run_npm_audit(Path.cwd(), no_network=False)
    assert record["state"] == "ok" and found == [], record


def _via_pip_audit(tmp_path):
    _write(Path.cwd(), {"requirements.txt": "requests==2.31.0\n"})
    found, record = depaudit.run_pip_audit(Path.cwd(), no_network=False)
    assert record["state"] == "ok" and found == [], record


def _via_gitleaks(tmp_path):
    _write(Path.cwd(), {"app.py": "X = 1\n"})
    found, records = security.run_secrets(Path.cwd())
    assert records[0]["tool"] == "gitleaks" and records[0]["state"] == "ok" and found == [], records


def _via_tesseract(tmp_path):
    assert "READ 4821" in ask.ocr_image(_Picture())


def _via_docker(tmp_path):
    assert sandbox.docker_ok() is True


def _via_setup(tmp_path):
    text = mcp_server.setup_text()
    assert str(tmp_path / "own" / "lantern") in text and '"./lantern"' not in text and " ./lantern " not in text, text


WAYS = {
    # the program, what the person's own one answers, how Lantern is asked to start it
    "git": ("git", None, _via_git),
    "git, for a project's commit": ("git", None, _via_commit),
    "git, for Lantern's own commit": ("git", None, _via_engine),
    "npm": ("npm", 'if [ "$1" = "--version" ]; then echo 10.0.0; else echo \'{"vulnerabilities": {}}\'; fi', _via_npm),
    "pip-audit": ("pip-audit", 'echo \'{"dependencies": [], "fixes": []}\'', _via_pip_audit),
    "gitleaks": ("gitleaks", 'if [ "$1" = "version" ]; then echo 8.18.0; exit 0; fi\n'
                             'while [ $# -gt 0 ]; do if [ "$1" = "-r" ]; then printf "[]" > "$2"; fi; shift; done', _via_gitleaks),
    "tesseract": ("tesseract", "echo READ 4821", _via_tesseract),
    "docker": ("docker", "echo 27.0.0", _via_docker),
    "lantern, in the words for an assistant's settings": ("lantern", "echo lantern", _via_setup),
}


@only_posix
@pytest.mark.parametrize("entry", ["", ".", "bin"], ids=["an empty PATH entry", "a dot", "a relative folder"])
@pytest.mark.parametrize("way", sorted(WAYS))
def test_a_program_in_the_current_folder_is_not_started_whatever_path_says(tmp_path, monkeypatch, way, entry):
    """PATH is the person's, and an entry of it that is no full path means "the folder I am in". Inside a project
    that is the project. The person's own program, in a folder PATH names in full, is the one that runs."""
    if way == "docker" and not sys.platform.startswith("linux"):
        pytest.skip("Lantern asks for Docker on Linux only")
    name, answer, ask_lantern = WAYS[way]
    marks = _marks(tmp_path)
    here = _git_repo(tmp_path / "p") if "commit" in way and "project" in way else tmp_path / "p"
    here.mkdir(exist_ok=True)
    _program(here / entry if entry not in ("", ".") else here, name, marks, "planted")
    path = [entry]
    if answer is not None:                                     # the person's own one; for git it is the system's
        _program(tmp_path / "own", name, marks, "own", answer)
        path.append(str(tmp_path / "own"))
    monkeypatch.setenv("PATH", os.pathsep.join(path + [os.environ.get("PATH", "")]))
    monkeypatch.delenv("LANTERN_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "_DOCKER", {})
    monkeypatch.chdir(here)
    ask_lantern(tmp_path)
    assert _ran(marks, "planted") == []
    assert answer is None or way.startswith("lantern") or _ran(marks, "own")


DOCKER = """#!/bin/sh
# a stand-in for the docker program: it writes down what it was asked and the PATH it was given
here=$(dirname "$0")
echo "$1 PATH=$PATH" >> "$here/asked.log"
case "$1" in
  run) echo CONTAINER-RUNNING; exec sleep 300 ;;
  rm) echo "$3" ;;
esac
exit 0
"""


@only_posix
def test_the_docker_that_runs_and_removes_a_container_is_the_persons_own(tmp_path, monkeypatch):
    """A test run in Docker, started inside the project with a `docker` of the project's beside it. Docker starts
    helpers of its own by their names, so it is handed no PATH entry that means the current folder either."""
    marks = _marks(tmp_path)
    repo = _write(tmp_path / "p", {"pyproject.toml": "[project]\nname = 'p'\n",
                                   "tests/test_it.py": "def test_ran():\n    assert True\n"})
    _program(repo, "docker", marks, "planted")
    own = _write(tmp_path / "own", {"docker": DOCKER})
    (own / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", str(own), os.environ.get("PATH", "")]))
    monkeypatch.chdir(repo)
    r = sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=lambda line: None, backend="docker", timeout=2)
    assert r["timed_out"] and "CONTAINER-RUNNING" in r["output_tail"], r
    assert _ran(marks, "planted") == []
    asked = [line.split(" PATH=", 1) for line in (own / "asked.log").read_text(encoding="utf-8").splitlines()]
    assert [what for what, _ in asked] == ["run", "rm"], asked
    for what, path in asked:
        entries = path.split(os.pathsep)
        assert entries[0] == str(own) and all(os.path.isabs(e) for e in entries), (what, path)


@only_posix
def test_docker_asked_for_and_not_installed_means_the_tests_were_not_run(tmp_path, monkeypatch):
    """Said in Lantern's words, as for any sandbox that cannot be set up (until 2026-11-10 a Python error)."""
    repo = _write(tmp_path / "p", {"pyproject.toml": "[project]\nname = 'p'\n",
                                   "tests/test_it.py": "def test_ran():\n    assert True\n"})
    (tmp_path / "empty").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=lambda line: None, backend="docker", timeout=30)
    assert "Docker is not installed" in str(e.value)


@only_posix
def test_in_the_sandbox_the_runner_of_the_tests_is_the_persons_own_program(tmp_path, monkeypatch):
    """`npm test`: the first word is looked for in the folders PATH names in full, so a file of the project named
    `npm` is not what runs the project's tests. (The tests themselves are the project's code, inside the sandbox.)"""
    own = Path(tempfile.mkdtemp(prefix="own-"))                # where the sandbox's own user can read, unlike tmp_path
    try:
        own.chmod(0o755)
        (own / "npm").write_text('#!/bin/sh\necho THE-PERSONS-NPM "$@"\n', encoding="utf-8")
        (own / "npm").chmod(0o755)
        repo = _write(tmp_path / "p", {"package.json": '{"name": "p", "scripts": {"test": "true"}}',
                                       "npm": "#!/bin/sh\necho THE-PROJECTS-NPM\n"})
        (repo / "npm").chmod(0o755)
        monkeypatch.setenv("PATH", os.pathsep.join([".", "", str(own), os.environ.get("PATH", "")]))
        monkeypatch.chdir(repo)
        r = sandbox.run(repo, ["npm", "test"], log=lambda line: None, backend="subprocess", timeout=60)
    finally:
        shutil.rmtree(own, ignore_errors=True)
    assert "THE-PERSONS-NPM test" in r["output_tail"] and "THE-PROJECTS-NPM" not in r["output_tail"], r


@only_posix
def test_in_the_sandbox_a_runner_written_with_a_dot_is_the_projects_own_wrapper(tmp_path):
    """`./gradlew test` names a file of the project, at its top, whichever folder the tests are started in."""
    repo = _write(tmp_path / "p", {"gradlew": '#!/bin/sh\necho THE-PROJECTS-WRAPPER "$@"\n', "build.gradle": "",
                                   "app/build.gradle": ""})
    (repo / "gradlew").chmod(0o755)
    r = sandbox.run(repo, ["./gradlew", "test"], log=lambda line: None, backend="subprocess", timeout=60, cwd_rel="app")
    assert "THE-PROJECTS-WRAPPER test" in r["output_tail"], r


@only_posix
def test_in_the_sandbox_a_runner_that_is_not_installed_is_said_by_its_name(tmp_path, monkeypatch):
    """Nothing else is started in its place: `test`, the next word, is a program of every POSIX system."""
    repo = _write(tmp_path / "p", {"package.json": '{"name": "p", "scripts": {"test": "true"}}'})
    monkeypatch.setenv("PATH", os.pathsep.join(["/usr/bin", "/bin"]))
    assert _programs().find("yarn") is None and _programs().find("test")
    r = sandbox.run(repo, ["yarn", "test"], log=lambda line: None, backend="subprocess", timeout=60)
    assert r["returncode"] == 127 and "could not start yarn" in r["output_tail"], r


# ---------------------------------------------------------------- the lookup itself


@only_posix
def test_find_gives_the_full_path_from_the_folders_path_names_in_full(tmp_path, monkeypatch):
    marks = _marks(tmp_path)
    own = _program(tmp_path / "own", "tool-7341", marks, "own")
    _program(tmp_path / "here", "tool-7341", marks, "planted")
    monkeypatch.chdir(tmp_path / "here")
    find = _programs().find
    assert shutil.which("tool-7341", path=os.pathsep.join(["", str(tmp_path / "own")])) == "tool-7341"   # the older way
    for path in ("", ".", os.pathsep, "." + os.pathsep + "bin", "../here"):
        assert find("tool-7341", path) is None, path
    for path in (str(tmp_path / "own"), os.pathsep.join(["", ".", str(tmp_path / "own")]),
                 os.pathsep.join([str(tmp_path / "nothing-here"), str(tmp_path / "own")])):
        assert find("tool-7341", path) == str(own), path
    monkeypatch.setenv("PATH", os.pathsep.join([".", str(tmp_path / "own")]))
    assert find("tool-7341") == str(own)                       # PATH is asked when none is handed over
    assert find("tool-7342") is None


@only_posix
def test_find_takes_a_bare_name_of_a_file_that_may_be_started_and_nothing_else(tmp_path):
    marks = _marks(tmp_path)
    own = tmp_path / "own"
    _program(own, "tool-7341", marks, "own")
    (own / "a-folder").mkdir()
    (own / "not-a-program").write_text("text\n", encoding="utf-8")
    find = _programs().find
    for name in ("", ".", "..", "a-folder", "not-a-program", "./tool-7341", "own/tool-7341", str(own / "tool-7341"),
                 "tool-7341\0", None, 7):
        assert find(name, str(own)) is None, name
    assert find("tool-7341", str(own)) == str(own / "tool-7341")


def test_on_windows_find_adds_the_endings_windows_can_start_and_no_other(tmp_path, monkeypatch):
    """The Windows rules, tried on any system with folders written this system's way."""
    programs = _programs()
    monkeypatch.setattr(programs, "WINDOWS", True)
    own = tmp_path / "own"
    own.mkdir()
    for name in ("git.exe", "npm.cmd", "npm.js", "tool.bat", "old.com", "script.py", "plain"):
        (own / name).write_text("", encoding="utf-8")
    monkeypatch.setenv("PATHEXT", os.pathsep.join([".COM", ".EXE", ".BAT", ".CMD", ".JS", ".PY"]))
    path = os.pathsep.join(["", ".", '"' + str(own) + '"'])               # Windows lets a PATH entry stand in quotes
    assert programs.find("git", path) == str(own / "git.exe")
    assert programs.find("git.exe", path) == str(own / "git.exe")
    assert programs.find("npm", path) == str(own / "npm.cmd")              # never npm.js, which Windows cannot start
    assert programs.find("tool", path) == str(own / "tool.bat") and programs.find("old", path) == str(own / "old.com")
    assert programs.find("script", path) is None and programs.find("script.py", path) is None
    assert programs.find("plain", path) is None                           # no ending: not a program there
    monkeypatch.delenv("PATHEXT")
    assert programs.find("npm", path) == str(own / "npm.cmd")              # the endings Windows starts, when PATHEXT is not set
    monkeypatch.setenv("PATHEXT", ".JS")
    assert programs.find("npm", path) == str(own / "npm.cmd")              # a PATHEXT that names none of them


def test_python_gives_a_tool_no_current_folder(tmp_path, monkeypatch):
    """`-P` is Python's own switch (3.11 and later) for "do not put the current folder first"."""
    cmd = _programs().python("json.tool", "--help")
    assert cmd[:4] == [sys.executable, "-P", "-m", "json.tool"] and cmd[4:] == ["--help"]
    _write(tmp_path, {"probe7341.py": "print('loaded from the current folder')\n"})
    monkeypatch.chdir(tmp_path)
    older = subprocess.run([sys.executable, "-m", "probe7341"], capture_output=True, text=True, timeout=60)
    assert "loaded from the current folder" in older.stdout              # the reason for the switch
    now = subprocess.run(_programs().python("probe7341"), capture_output=True, text=True, timeout=60)
    assert now.returncode != 0 and "loaded" not in now.stdout and "No module named" in now.stderr


def test_env_keeps_the_folders_named_in_full_and_changes_nothing_else(tmp_path, monkeypatch):
    programs = _programs()
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    base = {"PATH": os.pathsep.join(["", ".", a, "bin", b, "../x"]), "PYTHONPATH": os.pathsep.join([".", a, "src"]),
            "HOME": "/home/x", "OTHER": "."}
    before = dict(base)
    got = programs.env(base)
    assert got["PATH"] == os.pathsep.join([a, b]) and got["PYTHONPATH"] == a
    assert got["HOME"] == "/home/x" and got["OTHER"] == "." and base == before
    assert "NoDefaultCurrentDirectoryInExePath" not in got or os.name == "nt"
    only_relative = programs.env({"PATH": os.pathsep.join(["", "."]), "PYTHONPATH": "."})
    assert all(os.path.isabs(x) for x in only_relative["PATH"].split(os.pathsep) if x)
    assert only_relative["PATH"] or os.name == "nt"                       # Windows looks in its own folders without PATH
    assert "PYTHONPATH" not in only_relative                              # an empty one would be read as the current folder
    monkeypatch.setenv("PATH", os.pathsep.join([".", a]))
    assert programs.env()["PATH"] == a and os.environ["PATH"] != a          # the person's environment, when none is handed over
    monkeypatch.setattr(programs, "WINDOWS", True)
    windows = programs.env({"Path": os.pathsep.join([".", a]), "X": "1"})
    assert windows == {"Path": a, "X": "1", "NoDefaultCurrentDirectoryInExePath": "1"}


def test_every_helper_is_started_with_that_environment(tmp_path, monkeypatch):
    a = str(tmp_path / "a")
    monkeypatch.setenv("PATH", os.pathsep.join([".", a, os.environ.get("PATH", "")]))
    show = "import os; print(os.environ['PATH']); print(os.environ.get('NoDefaultCurrentDirectoryInExePath'))"
    for env in (None, {**os.environ, "EXTRA": "1"}):
        r = remote.run_bounded([sys.executable, "-c", show], env=env, timeout=60)
        path, switch = r.stdout.splitlines()[:2]
        assert path.split(os.pathsep)[0] == a and "." not in path.split(os.pathsep), path
        assert switch == ("1" if os.name == "nt" else str(os.environ.get("NoDefaultCurrentDirectoryInExePath")))
    assert security._tool_version([sys.executable, "-c", "import os; print('1.2.3' if '.' not in "
                                   "os.environ['PATH'].split(os.pathsep) else 'the current folder is on PATH')"]) == "1.2.3"


def test_on_windows_the_program_that_ends_a_tree_is_found_the_same_way(tmp_path, monkeypatch):
    """The Windows branch of `remote._kill_tree`, tried on any system with a stand-in for the start: the person's own
    `taskkill` from a folder PATH names in full, else the system's own by its full path, never the bare name; and
    what it prints is taken, not shown among Lantern's own words."""
    import types
    programs, started = _programs(), []

    class Proc:
        pid = 4821

        def kill(self):
            pass
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setattr(remote, "sys", types.SimpleNamespace(platform="win32"))
    monkeypatch.setattr(remote, "subprocess", types.SimpleNamespace(
        run=lambda cmd, **kw: started.append((cmd, kw)), TimeoutExpired=subprocess.TimeoutExpired))
    monkeypatch.setattr(programs, "find", lambda name, path=None: None)
    remote._kill_tree(Proc())
    monkeypatch.setattr(programs, "find", lambda name, path=None: str(tmp_path / "own" / (name + ".exe")))
    remote._kill_tree(Proc())
    monkeypatch.undo()
    assert [cmd[0] for cmd, _ in started] == [os.path.join(str(tmp_path), "System32", "taskkill.exe"),
                                              str(tmp_path / "own" / "taskkill.exe")]
    assert all(cmd[1:] == ["/F", "/T", "/PID", "4821"] and kw.get("capture_output") is True and kw.get("timeout")
               for cmd, kw in started), started


# ---------------------------------------------------------------- no other way to start a program

STARTERS = {"run", "Popen", "call", "check_call", "check_output", "run_bounded", "run_tool", "_tool_version", "_stream",
            "system", "popen", "startfile", "execv", "execve", "execvp", "execvpe", "spawnv", "spawnvp"}
# A Python program started with the current folder first, on purpose: the project's own tests, in the project's
# folder, inside the sandbox ("Watch my tests run") or at the person's own command (`lantern trace`).
ON_PURPOSE = {("lantern/sandbox.py", "lantern.tracehook"), ("lantern/trace.py", "lantern.tracehook")}


def _bare(e) -> bool:
    return isinstance(e, ast.Constant) and isinstance(e.value, str) and bool(e.value) and not re.search(r"[/\\]", e.value)


def _unsafe_starts(source: str, rel: str = "x.py") -> list[str]:
    """What in this source starts, or looks for, a program another way than `lantern.programs`. A command kept in a
    name is followed inside the function that starts it."""
    tree, out = ast.parse(source), set()

    def scopes(node, inside):
        """Each node with the function it is written in (the module for a line outside any)."""
        for child in ast.iter_child_nodes(node):
            mine = child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) else inside
            yield child, inside
            yield from scopes(child, mine)

    nodes = list(scopes(tree, tree))
    lists: dict[tuple[int, str], list[ast.List]] = {}
    for n, where in nodes:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.List):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    lists.setdefault((id(where), t.id), []).append(n.value)
    for n, where in nodes:
        if isinstance(n, ast.List) and len(n.elts) > 2 and isinstance(n.elts[0], ast.Attribute) \
                and ast.unparse(n.elts[0]) == "sys.executable" and isinstance(n.elts[1], ast.Constant) and n.elts[1].value == "-m":
            module = n.elts[2].value if isinstance(n.elts[2], ast.Constant) else "?"
            if (rel, module) not in ON_PURPOSE:
                out.add(f"{rel}:{n.lineno}: python -m {module} is given the current folder (programs.python)")
        if not isinstance(n, ast.Call):
            continue
        callee = n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id if isinstance(n.func, ast.Name) else ""
        if callee == "which" and rel != "lantern/programs.py":
            out.add(f"{rel}:{n.lineno}: shutil.which looks in the current folder on Windows (programs.find)")
        if callee in STARTERS and n.args:
            first = n.args[0]
            kept = lists.get((id(where), first.id), []) if isinstance(first, ast.Name) else []
            for words in ([first] if isinstance(first, ast.List) else kept):
                if words.elts and _bare(words.elts[0]):
                    out.add(f"{rel}:{n.lineno}: {words.elts[0].value} is started by its bare name (programs.find)")
    return sorted(out)


def test_no_program_is_started_any_other_way():
    """Every module of Lantern, the cloud service and the gateway: a later line that starts a program by its bare
    name, asks `shutil.which`, or starts a Python tool with the current folder first fails here."""
    found = []
    for base in ("lantern", "cloud/lantern_cloud", "gateway"):
        for p in sorted((ROOT / base).rglob("*.py")):
            if "starters" not in p.parts:
                found += _unsafe_starts(p.read_text(encoding="utf-8"), p.relative_to(ROOT).as_posix())
    assert found == []


@pytest.mark.parametrize("source,word", [
    ('import subprocess\nsubprocess.run(["git", "status"])\n', "git is started by its bare name"),
    ('cmd = ["npm", "audit"]\nrun_tool(cmd, timeout=3)\n', "npm is started by its bare name"),
    ('def f():\n    args = ["docker", "run"]\n    return _stream(args, None, {}, 3, print)\n', "docker is started"),
    ('import shutil\nx = shutil.which("git")\n', "shutil.which"),
    ('import sys\ncmd = [sys.executable, "-m", "bandit", "-r", "."]\n', "python -m bandit"),
])
def test_the_look_for_other_ways_sees_them(source, word):
    assert word in " ".join(_unsafe_starts(source))


@pytest.mark.parametrize("source", [
    'from lantern import programs\nimport subprocess\nsubprocess.run([programs.find("git"), "status"])\n',
    'from lantern import programs\ncmd = programs.python("bandit", "-r", ".")\nrun_tool(cmd, timeout=3)\n',
    'import sys\ncmd = [sys.executable, "-I", "-m", "lantern._jail", "x"]\n',
    'TOOLS = ["pip-audit", "npm-audit"]\nwords = ["npm", "test"]\n',            # words, never started
    'import subprocess\nsubprocess.run(["/usr/bin/git", "status"])\n',
])
def test_the_look_for_other_ways_passes_the_right_ones(source):
    assert _unsafe_starts(source) == []


# ---------------------------------------------------------------- Windows itself


def _system32(name: str) -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


@only_windows
def test_windows_itself_starts_a_bare_name_from_the_current_folder(tmp_path, monkeypatch):
    """The reason for the rule, asked of Windows: a copy of its own shell under a name no other program has."""
    shutil.copyfile(_system32("cmd.exe"), tmp_path / "lantern-probe-7341.exe")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    found = shutil.which("lantern-probe-7341")
    assert found and Path(found).resolve().parent == tmp_path.resolve(), found
    r = subprocess.run(["lantern-probe-7341", "/c", "echo", "ran-7341"], capture_output=True, text=True, timeout=60,
                       stdin=subprocess.DEVNULL)
    assert r.returncode == 0 and "ran-7341" in r.stdout, (r.stdout, r.stderr)
    assert _programs().find("lantern-probe-7341") is None


@only_windows
def test_on_windows_git_is_the_persons_own_with_a_program_of_that_name_in_the_current_folder(tmp_path, monkeypatch):
    shutil.copyfile(_system32("cmd.exe"), tmp_path / "git.exe")
    monkeypatch.chdir(tmp_path)
    git = _programs().find("git")
    assert git and Path(git).resolve().parent != tmp_path.resolve(), git
    r = remote._git(["--version"], cwd=None)
    assert r.returncode == 0 and r.stdout.startswith("git version"), (r.stdout, r.stderr)


@only_windows
def test_on_windows_a_helpers_own_shell_does_not_look_in_the_current_folder(tmp_path):
    """`npm` is a `.cmd` there, run by Windows' shell, which starts `node` by its bare name where none stands beside
    it. The shell looks in the current folder first unless the environment tells it not to."""
    (tmp_path / "lantern-probe-7342.bat").write_text("@echo ran-7342\r\n", encoding="ascii")
    cmd = _system32("cmd.exe")
    plain = {k: v for k, v in os.environ.items() if k.lower() != "nodefaultcurrentdirectoryinexepath"}
    older = subprocess.run([cmd, "/c", "lantern-probe-7342"], cwd=tmp_path, env=plain, capture_output=True, text=True,
                           timeout=60, stdin=subprocess.DEVNULL)
    assert "ran-7342" in older.stdout, (older.stdout, older.stderr)
    now = remote.run_bounded([cmd, "/c", "lantern-probe-7342"], cwd=tmp_path, timeout=60)
    assert "ran-7342" not in now.stdout and now.returncode != 0, (now.stdout, now.stderr)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
