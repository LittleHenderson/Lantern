"""What a project's dependency files say is checked before it is used (2026-11-10, directive stage 7, part 3).

A lock file comes with the project, so it is as untrusted as the code. Until this date:

* a lock file with an unexpected shape (a list where a table belongs, a number where a name belongs) stopped the whole
  analysis with a Python error, `--offline` or not;
* names and versions from uv.lock, poetry.lock, pdm.lock and Pipfile.lock went unchecked into the file handed to
  pip-audit, so a "version" could add lines of its own to that file, and one entry pip-audit cannot read (a version
  such as `1.0-SNAPSHOT.final`) made it give up on every package, the vulnerable ones included;
* entries Lantern could not use (composer.lock, Gemfile.lock, a lock file that is not valid TOML or JSON) were left
  out without a word, and the record still said `ok`.

Now only a package name and a version of the form the ecosystem defines leave Lantern; whatever else an entry holds
is named in the audit's record (`errors`, state `partial`) and the rest is still checked.

Nothing here reaches the network. Where the real pip-audit takes part, it is its dry run: it reads the input file
exactly as an audit would and asks nobody.
"""
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from lantern import depaudit, evidence, scanresult
from lantern.cli import main
from lantern.engine import build_graph
from lantern.scanresult import ToolRun
from lantern.security import scan


def _write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _plain(text: str) -> bool:
    """One line of printable ASCII: what may be shown on a console and kept in a record."""
    return bool(re.fullmatch(r"[\x20-\x7e]*", text))


RUN = {"pip-audit": depaudit.run_pip_audit, "maven-audit": depaudit.run_maven_audit,
       "composer-audit": depaudit.run_composer_audit, "gem-audit": depaudit.run_gem_audit}

# ---------------------------------------------------------------------------- a file with an unexpected shape

ODD_SHAPES = {    # what is wrong: (the audit, the file, its text, what the record then says of the file)
    "uv.lock: package is a word": ("pip-audit", "uv.lock", 'package = "requests"\n', 'its packages are "requests", not a list'),
    "uv.lock: a package is a word": ("pip-audit", "uv.lock", 'package = ["requests"]\n', 'entry 1 is "requests", not a package'),
    "poetry.lock: package is one table": ("pip-audit", "poetry.lock", '[package]\nname = "requests"\nversion = "2.19.0"\n',
                                          "its packages are a table, not a list"),
    "poetry.lock: not TOML": ("pip-audit", "poetry.lock", '<<<<<<< HEAD\n[[package]]\nname = "requests"\n',
                              "not valid TOML (line 1), so it was not read"),
    "pdm.lock: a name is a table": ("pip-audit", "pdm.lock", '[[package]]\nversion = "1.0"\n[package.name]\nx = 1\n',
                                    "entry 1: a table is not a package name"),
    "Pipfile.lock: a list": ("pip-audit", "Pipfile.lock", "[]", "its content is a list, not a table"),
    "Pipfile.lock: default is a list": ("pip-audit", "Pipfile.lock", '{"default": ["requests"]}',
                                        "its default packages are a list, not a table"),
    "Pipfile.lock: a version is a number": ("pip-audit", "Pipfile.lock", '{"default": {"requests": {"version": 2}}}',
                                            "requests: a number is not a version"),
    "Pipfile.lock: not JSON": ("pip-audit", "Pipfile.lock", '{"default": {\n', "not valid JSON (line 2), so it was not read"),
    "pyproject.toml: project is a word": ("pip-audit", "pyproject.toml", 'project = "x"\n', 'its [project] is "x", not a table'),
    "pyproject.toml: dependencies is a table": ("pip-audit", "pyproject.toml", "[project.dependencies]\nflask = 1\n",
                                                "its dependencies are a table, not a list"),
    "pyproject.toml: poetry's are a list": ("pip-audit", "pyproject.toml", '[tool.poetry]\ndependencies = ["requests"]\n',
                                            "its [tool.poetry] dependencies are not a table"),
    "libs.versions.toml: libraries is a list": ("maven-audit", "gradle/libs.versions.toml", 'libraries = ["a:b:1"]\n',
                                                "its libraries are a list, not a table"),
    "libs.versions.toml: a module is a number": ("maven-audit", "gradle/libs.versions.toml",
                                                 '[libraries]\nx = { module = 5, version = "1" }\n',
                                                 'library "x" has a number where its group and name belong'),
    "libs.versions.toml: a name is a number": ("maven-audit", "gradle/libs.versions.toml",
                                               '[libraries]\nx = { group = "com.example", name = 5, version = "1" }\n',
                                               'library "x" has a number where its group and name belong'),
    "libs.versions.toml: a group is a number": ("maven-audit", "gradle/libs.versions.toml",
                                                '[libraries]\nx = { group = 5, name = "lib", version = "1" }\n',
                                                'library "x" has a number where its group and name belong'),
    "libs.versions.toml: a ref is a list": ("maven-audit", "gradle/libs.versions.toml",
                                            '[libraries]\nx = { module = "a:b", version = { ref = ["v"] } }\n',
                                            'library "x" names its version with a list, not with a name'),
    "libs.versions.toml: versions is a list": ("maven-audit", "gradle/libs.versions.toml",
                                               'versions = ["1"]\n[libraries]\nx = { module = "a:b", version.ref = "v" }\n',
                                               "its versions are a list, not a table"),
    "libs.versions.toml: not TOML": ("maven-audit", "gradle/libs.versions.toml", "[libraries\n",
                                     "not valid TOML (line 1), so it was not read"),
    "composer.lock: a list": ("composer-audit", "composer.lock", "[]", "its content is a list, not a table"),
    "composer.lock: packages is a number": ("composer-audit", "composer.lock", '{"packages": 5}',
                                            "its packages are a number, not a list"),
    "composer.lock: not JSON": ("composer-audit", "composer.lock", "{", "not valid JSON (line 1), so it was not read"),
}


@pytest.mark.parametrize("what", sorted(ODD_SHAPES))
def test_a_dependency_file_with_an_unexpected_shape_is_named_in_the_record(what, tmp_path):
    tool, name, text, said = ODD_SHAPES[what]
    _write(tmp_path, {name: text})
    for no_network in (True, False):            # nothing in such a file can be asked about, so nobody is asked
        findings, info = RUN[tool](tmp_path, no_network)
        assert findings == [] and info["state"] == "partial" and info["applicable"] is True, info
        assert info["errors"] == [f"{name}: {said}"] and _plain(info["errors"][0])        # said once, and what it is
        assert info["not_read"] == 1 and info["files"] == [name]
        assert info["status"] == "partial: 1 part of the dependency files could not be read as a package name and version"
    assert scanresult.incomplete([info]) == [info]                       # so the report and readiness say so
    line = evidence.incomplete_lines([info])[0]
    assert "covered only part of the project" in line and name in line


def test_the_analysis_finishes_on_dependency_files_it_cannot_read(tmp_path, capsys):
    """The whole command, as a person runs it: before, each of these files ended it with a Python error."""
    _write(tmp_path, {"app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"}
           | {name: text for _tool, name, text, _said in (ODD_SHAPES[k] for k in (
               "Pipfile.lock: a list", "composer.lock: a list", "libs.versions.toml: a module is a number"))})
    assert main(["analyze", str(tmp_path), "--offline"]) == 0
    sec = json.loads((tmp_path / ".lantern" / "security.json").read_text(encoding="utf-8"))
    states = {t["tool"]: t.get("state") for t in sec["tools"]}
    assert (states["pip-audit"], states["composer-audit"], states["maven-audit"]) == ("partial",) * 3
    assert any(f["tool"] == "bandit" for f in sec["findings"]), "the code's own findings are still there"
    page = (tmp_path / ".lantern" / "evidence.html").read_text(encoding="utf-8")
    assert "Pipfile.lock" in page and "composer.lock" in page and "libs.versions.toml" in page


def test_one_audit_that_raises_is_a_line_in_the_scan_and_not_the_end_of_it(tmp_path, monkeypatch):
    """The second wall: whatever an audit trips over that nobody foresaw, the scan goes on and says which one."""
    _write(tmp_path, {"app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n", "Gemfile.lock": "GEM\n  specs:\n"})

    def surprise(repo, no_network=None):
        raise RuntimeError("nobody foresaw this")
    monkeypatch.setattr(depaudit, "run_gem_audit", surprise)
    sec = scan(build_graph(tmp_path), offline=True)
    gem = next(t for t in sec["tools"] if t["tool"] == "gem-audit")
    assert gem["state"] == "failed" and "RuntimeError" in gem["status"] and "nobody foresaw" not in gem["status"]
    assert gem["status"].endswith("(while reading the project's dependency files)")      # offline: nobody was being asked
    assert any(f["tool"] == "bandit" for f in sec["findings"])
    assert {t["tool"] for t in sec["tools"]} >= {"pip-audit", "npm-audit", "maven-audit", "composer-audit", "gem-audit"}
    findings, info = depaudit.guarded("gem-audit", surprise, tmp_path, False)             # the same with the network on
    assert findings == [] and info["state"] == "failed" and info["status"].endswith("RuntimeError (network needed?)"), info


# ---------------------------------------------------------------------------- what is read at all

only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (a pipe)")
PIPES = {"uv.lock": "pip-audit", "Pipfile.lock": "pip-audit", "requirements.txt": "pip-audit", "pyproject.toml": "pip-audit",
         "composer.lock": "composer-audit", "Gemfile.lock": "gem-audit", "gradle/libs.versions.toml": "maven-audit",
         "build.gradle": "maven-audit", "pom.xml": "maven-audit"}


def _audit_into(done: list, tool: str, repo: Path, no_network: bool) -> None:
    done.append(RUN[tool](repo, no_network))


def _within(seconds: int, tool: str, repo: Path, pipe: Path, no_network: bool = True) -> dict:
    """The audit's record, from a thread: an audit that opens the pipe waits there for good, and the test must not."""
    done: list = []
    run = threading.Thread(target=_audit_into, args=(done, tool, repo, no_network), daemon=True)
    run.start()
    run.join(seconds)
    if not done:                                    # let the waiting read go, then say what happened
        try:
            os.close(os.open(pipe, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass
        pytest.fail(f"{tool} is still waiting for {pipe.name}, which is a pipe nobody writes to")
    return done[0][1]


@only_posix
@pytest.mark.parametrize("name", sorted(PIPES))
def test_a_pipe_under_a_dependency_files_name_is_not_read(name, tmp_path):
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(tmp_path / name)
    info = _within(20, PIPES[name], tmp_path, tmp_path / name)
    assert info["state"] == "partial" and info["errors"] == [f"{name}: not a plain file, so it was not read"], info


@only_posix
def test_a_pipe_beside_a_lock_file_costs_a_line_number_and_nothing_else(tmp_path, monkeypatch):
    """composer.json and Gemfile only say where a library is written: as pipes they held the audit up as well."""
    asked = _osv(monkeypatch)
    _write(tmp_path, {"composer.lock": json.dumps({"packages": [{"name": "acme/rc", "version": "2.0.0"}]}),
                      "Gemfile.lock": "GEM\n  specs:\n    rails (7.0.4)\n"})
    os.mkfifo(tmp_path / "composer.json")
    os.mkfifo(tmp_path / "Gemfile")
    for tool, name, lock in (("composer-audit", "composer.json", "composer.lock"), ("gem-audit", "Gemfile", "Gemfile.lock")):
        info = _within(20, tool, tmp_path, tmp_path / name, no_network=False)
        assert info["state"] == "ok" and info["checked"] == 1 and info["files"] == [lock], info
    assert sorted(asked) == [("acme/rc", "2.0.0"), ("rails", "7.0.4")]


def test_a_dependency_file_larger_than_the_limit_is_not_read(tmp_path, monkeypatch):
    lock = _write(tmp_path, {"uv.lock": _toml_lock([("flask", "2.0.1")])}) / "uv.lock"
    monkeypatch.setattr(depaudit, "MAX_FILE", lock.stat().st_size - 1)
    _f, info = depaudit.run_pip_audit(tmp_path, True)
    assert info["state"] == "partial" and info["errors"] == ["uv.lock: larger than 0 MB, so it was not read"], info
    monkeypatch.setattr(depaudit, "MAX_FILE", lock.stat().st_size)             # the twin: just small enough
    assert depaudit.python_pins(tmp_path)[0] == {"flask": ("2.0.1", "uv.lock")}


def test_a_dependency_file_that_starts_with_a_byte_order_mark_is_read(tmp_path):
    """Some editors on Windows put the mark first, and neither the JSON nor the TOML reader takes a text that starts
    with it: such a lock file was passed over, or stopped the analysis."""
    bom = "\ufeff"
    _write(tmp_path, {"a/uv.lock": bom + _toml_lock([("flask", "2.0.1")]),
                      "b/Pipfile.lock": bom + json.dumps({"default": {"requests": {"version": "==2.31.0"}}}),
                      "c/requirements.txt": bom + "idna==3.4\n",
                      "composer.lock": bom + json.dumps({"packages": [{"name": "acme/rc", "version": "2.0.0"}]}),
                      "Gemfile.lock": bom + "GEM\n  specs:\n    rails (7.0.4)\n",
                      "gradle/libs.versions.toml": bom + '[libraries]\nplain = "com.example:plain:1.2.3"\n'})
    assert (tmp_path / "a" / "uv.lock").read_bytes().startswith(b"\xef\xbb\xbf")
    odd = depaudit.Odd()
    pins, loose, _files = depaudit.python_pins(tmp_path, odd)
    assert {n: v for n, (v, _file) in pins.items()} == {"flask": "2.0.1", "requests": "2.31.0", "idna": "3.4"} and not loose
    assert set(depaudit.composer_pins(tmp_path, odd)[0]) == {"acme/rc"}
    assert set(depaudit.gem_pins(tmp_path, odd)[0]) == {"rails"}
    assert set(depaudit.maven_coords(tmp_path, odd)[0]) == {"com.example:plain"}
    assert odd.count == 0, odd.lines


def test_a_lock_entry_with_no_version_is_counted_as_not_checked(tmp_path):
    """Nothing is wrong with such an entry and nothing can be looked up for it: it is counted, as a range is."""
    _write(tmp_path, {"uv.lock": '[[package]]\nname = "flask"\nversion = "2.0.1"\n\n[[package]]\nname = "ours"\n'
                                 '[package.source]\ngit = "https://example.invalid/ours.git"\n'})
    odd = depaudit.Odd()
    pins, loose, _files = depaudit.python_pins(tmp_path, odd)
    assert set(pins) == {"flask"} and loose == ["uv.lock: ours (no version written)"] and odd.count == 0
    # the twin: the project's own entry (uv writes it without a version when the version is worked out at build time)
    _write(tmp_path / "twin", {"uv.lock": '[[package]]\nname = "flask"\nversion = "2.0.1"\n\n[[package]]\nname = "myapp"\n'
                                          '[package.source]\neditable = "."\n'})
    pins, loose, _files = depaudit.python_pins(tmp_path / "twin", odd)
    assert set(pins) == {"flask"} and loose == [] and odd.count == 0


def test_an_odd_entry_of_a_lock_file_is_named_by_its_place_in_the_file(tmp_path):
    """An entry with no usable name can only be pointed at: the first entry of the file is entry 1."""
    _write(tmp_path, {"uv.lock": 'package = [{ name = "flask", version = "2.0.1" }, 5, { name = 7, version = "1.0" }]\n'})
    odd = depaudit.Odd()
    pins, loose, files = depaudit.python_pins(tmp_path, odd)
    assert pins == {"flask": ("2.0.1", "uv.lock")} and loose == [] and files == ["uv.lock"]
    assert odd.lines == ["uv.lock: entry 2 is a number, not a package", "uv.lock: entry 3: a number is not a package name"]


def test_a_poetry_project_without_a_lock_file_has_its_exact_versions_checked(tmp_path):
    """Kept as it was: an exact version is checked, a range is counted, and `python` itself is not a package."""
    _write(tmp_path, {"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\nflask = "2.0.1"\n'
                                        'requests = "^2.31"\nours = { git = "https://example.invalid/ours.git" }\n'})
    odd = depaudit.Odd()
    pins, loose, files = depaudit.python_pins(tmp_path, odd)
    assert pins == {"flask": ("2.0.1", "pyproject.toml")} and files == ["pyproject.toml"] and odd.count == 0
    assert loose == ["pyproject.toml: requests", "pyproject.toml: ours"]


def test_many_odd_entries_are_all_counted_and_the_first_twenty_are_named(tmp_path):
    _write(tmp_path, {"uv.lock": _toml_lock([(f"pkg{i}", "latest") for i in range(50)])})
    _f, info = depaudit.run_pip_audit(tmp_path, True)
    assert info["state"] == "partial" and info["not_read"] == 50 and len(info["errors"]) == depaudit.Odd.KEEP == 20, info
    assert info["errors"][0] == 'uv.lock: pkg0: "latest" is not a version' and info["errors"][-1].startswith("uv.lock: pkg19:")
    assert "50 parts of the dependency files" in info["status"]
    line = evidence.incomplete_lines([info])[0]
    assert "covered only part of the project" in line and "50" in line


# ---------------------------------------------------------------------------- Python: what reaches pip-audit

GOOD = {    # names and versions that look unusual and are right: each must reach pip-audit as written
    "Flask": "2.0.1", "ruamel.yaml": "0.17.21", "typing_extensions": "4.9.0", "backports-zoneinfo": "0.2.1",
    "zope.interface": "6.1", "torch": "2.1.0+cpu", "pytz": "2024.1", "setuptools-scm": "8.0.0.post1",
    "black": "24.1a1", "numpy": "2.0.0rc1", "attrs": "23.2.0.dev0", "epoch-lib": "1!2.0", "a": "1", "pkg7": "v1.2",
}
PLANTED = [  # (name, version): one of the two is no package name or no version
    ("requests==2.31.0\n--extra-index-url https://packages.example.invalid/simple\nurllib3", "1.26.0"),
    ("urllib3", "1.26.0\n-r /etc/hostname"),
    ("idna", "3.4\n-e /srv/somewhere"),
    ("certifi", "2024.2.2 --hash=sha256:00"),
    ("chardet", "5.2.0; python_version < '3'"),
    ("six @ https://packages.example.invalid/six.whl", "1.16.0"),
    ("-e", "1.0"),
    ("click", "1.0-SNAPSHOT.final"),
    ("jinja2", "latest"),
    ("markupsafe", ""),
    ("", "2.1.5"),
    ("werkzeug", "3.0.1\x1b[2J"),
    ("it" + "s" * 300, "1.0"),
    ("nåme", "1.0"),
]


def _toml_lock(entries) -> str:
    return "".join(f"[[package]]\nname = {json.dumps(n)}\nversion = {json.dumps(v)}\n\n" for n, v in entries)


def _reads_its_input(seen: dict, known=()):
    """Stands in for the run of pip-audit: keeps the file it was handed. With `known`, the real pip-audit reads that
    file first (its dry run: the same reading, and nobody is asked) and its verdict is the result when it refuses the
    file; else the answer is made up here: every package named in `known` has one known vulnerability."""
    def run(cmd, **kw):
        req = cmd[cmd.index("-r") + 1]
        seen["req"] = Path(req).read_text(encoding="utf-8")
        if known:
            p = subprocess.run([sys.executable, "-m", "pip_audit", "-r", req, "-f", "json", "--progress-spinner", "off",
                                "--no-deps", "--disable-pip", "--dry-run"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
            seen["its own reading"] = p.returncode
            if p.returncode != 0:
                return ToolRun(p.returncode, p.stdout, p.stderr)
        deps = [{"name": n, "version": v, "vulns": [{"id": "PYSEC-0000-1", "fix_versions": ["9.9"], "description": "made up"}]
                 if n in known else []} for n, v in re.findall(r"(?m)^([^\s=-][^\s=]*)==(\S+)$", seen["req"])]
        return ToolRun(1 if any(d["vulns"] for d in deps) else 0, json.dumps({"dependencies": deps}), "")
    return run


@pytest.mark.parametrize("lock", ["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"])
def test_only_a_package_name_and_a_version_reach_pip_audit(lock, tmp_path, monkeypatch):
    entries = list(GOOD.items()) + PLANTED
    if lock == "Pipfile.lock":
        text = json.dumps({"default": {n: {"version": "==" + v} for n, v in entries}})
    elif lock == "requirements.txt":        # one line each is all such a file can say; a line that is no pin is a range
        entries = list(GOOD.items()) + [("click", "1.0-SNAPSHOT.final"), ("jinja2", "latest")]
        text = "".join(f"{n}=={v}\n" for n, v in entries)
    else:
        text = _toml_lock(entries)
    _write(tmp_path, {lock: text})
    seen: dict = {}
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
    monkeypatch.setattr(scanresult, "run_tool", _reads_its_input(seen))
    _findings, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    want = sorted(f"{depaudit._norm(n)}=={v}" for n, v in GOOD.items())
    assert sorted(seen["req"].splitlines()) == want, "something other than the known-good names and versions was handed over"
    odd = len(entries) - len(GOOD)
    assert info["state"] == "partial" and info["checked"] == len(GOOD) and info["not_read"] == odd, info
    assert len(info["errors"]) == odd and all(e.startswith(lock + ":") and _plain(e) and len(e) <= 200
                                                for e in info["errors"]), info["errors"]
    assert "not_read" not in depaudit.run_pip_audit(_write(tmp_path / "twin", {lock: text.split("click")[0]
                                                           if lock == "requirements.txt" else _toml_lock(GOOD.items())
                                                           if lock != "Pipfile.lock" else json.dumps(
                                                               {"default": {n: {"version": "==" + v} for n, v in GOOD.items()}})}),
                                                    no_network=False)[1], "the safe twin: nothing odd, nothing said"


def test_one_entry_pip_audit_cannot_read_no_longer_hides_every_other_package(tmp_path, monkeypatch):
    """Read by pip-audit itself. Before: its reading of the file failed on the one entry, the audit's state was
    `failed`, and the package with a known vulnerability was not reported."""
    pytest.importorskip("pip_audit")
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
    for lock, odd in (("uv.lock", ("inhouse", "1.0-SNAPSHOT.final")), ("poetry.lock", ("urllib3", "1.26.0\n-e /srv/x")),
                      ("requirements.txt", ("inhouse", "1.0-SNAPSHOT.final"))):
        entries = [("flask", "2.0.1"), odd, ("requests", "2.31.0")]
        d = _write(tmp_path / lock, {lock: "".join(f"{n}=={v}\n" for n, v in entries) if lock.endswith(".txt")
                                     else _toml_lock(entries)})
        seen: dict = {}
        monkeypatch.setattr(scanresult, "run_tool", _reads_its_input(seen, known=("flask",)))
        findings, info = depaudit.run_pip_audit(d, no_network=False)
        assert seen["its own reading"] == 0, "pip-audit itself could not read what Lantern handed it"
        assert [f["package"] for f in findings] == ["flask"] and info["state"] == "partial", (lock, info)
        assert info["checked"] == 2 and info["not_read"] == 1 and odd[0] in info["errors"][0]
    # the safe twin: every unusual and right name and version is one pip-audit reads, and the state is `ok`
    d = _write(tmp_path / "twin", {"uv.lock": _toml_lock(GOOD.items())})
    seen = {}
    monkeypatch.setattr(scanresult, "run_tool", _reads_its_input(seen, known=("flask",)))
    findings, info = depaudit.run_pip_audit(d, no_network=False)
    assert seen["its own reading"] == 0 and info["state"] == "ok" and [f["package"] for f in findings] == ["flask"]
    assert info["checked"] == len(GOOD) and "errors" not in info


def test_what_a_pipfile_lock_installs_from_a_link_or_a_folder_is_counted_as_not_checked(tmp_path):
    _write(tmp_path, {"Pipfile.lock": json.dumps({"default": {
        "flask": {"version": "==2.0.1"},
        "ours": {"git": "https://example.invalid/ours.git", "ref": "abc"},
        "local": {"path": ".", "editable": True}}})})
    pins, loose, _files = depaudit.python_pins(tmp_path)
    assert set(pins) == {"flask"} and len(loose) == 2 and all(x.startswith("Pipfile.lock: ") for x in loose)
    _f, info = depaudit.run_pip_audit(tmp_path, no_network=True)
    assert info["status"] == "skipped: offline" and "not_read" not in info


# ---------------------------------------------------------------------------- PHP, Ruby, Gradle and Maven: OSV is asked

def _osv(monkeypatch) -> list:
    asked: list = []

    def post(path, body, timeout=60):
        asked.extend((q["package"]["name"], q["version"]) for q in body["queries"])
        return {"results": [{} for _ in body["queries"]]}
    monkeypatch.setattr(depaudit, "_osv_post", post)
    return asked


def test_composer_entries_that_are_no_name_and_version_are_named_not_dropped(tmp_path, monkeypatch):
    asked = _osv(monkeypatch)
    _write(tmp_path, {"composer.lock": json.dumps({"packages": [
        {"name": "laravel/framework", "version": "v10.0.0"}, {"name": "acme/rc", "version": "2.0.0-RC1"},
        {"name": "acme/fork", "version": "dev-main"}, {"name": "acme/next", "version": "2.x-dev"},      # branches
        {"name": "acme/odd name", "version": "1.0.0"}, {"name": "weird", "version": "1.0.0"},
        {"name": "acme/nåme", "version": "1.0.0"}, {"name": "acme/ok2", "version": "1.0\n2.0"},
        {"name": ["acme/list"], "version": "1.0.0"}, {"name": "acme/number", "version": 3},
        "not an entry", {"version": "1.0.0"}]})})
    findings, info = depaudit.run_composer_audit(tmp_path, no_network=False)
    assert sorted(asked) == [("acme/rc", "2.0.0-RC1"), ("laravel/framework", "10.0.0")]
    assert findings == [] and info["state"] == "partial" and info["checked"] == 2, info
    assert info["not_read"] == 8 and len(info["errors"]) == 8
    assert all(e.startswith("composer.lock:") and _plain(e) for e in info["errors"]), info["errors"]
    assert 'composer.lock: entry 11 is "not an entry", not a package' in info["errors"]   # counted from 1, as a person would
    assert info["unpinned"] == 2 and sorted(info["unpinned_examples"]) == ["acme/fork dev-main", "acme/next 2.x-dev"]
    # the safe twin: branches alone are counted, and the state stays `ok`
    _write(tmp_path / "twin", {"composer.lock": json.dumps({"packages": [
        {"name": "laravel/framework", "version": "v10.0.0"}, {"name": "acme/fork", "version": "dev-main"}]})})
    _f, info = depaudit.run_composer_audit(tmp_path / "twin", no_network=False)
    assert info["state"] == "ok" and info["unpinned"] == 1 and "errors" not in info and "not_read" not in info
    lines = evidence.limits(build_graph(tmp_path / "twin"), {"tools": [info], "findings": []}, None, {}, "full", None)
    assert any("installed from a branch" in ln and "1 PHP" in ln for ln in lines), lines


def test_gem_lines_that_are_no_name_and_version_are_named_not_dropped(tmp_path, monkeypatch):
    asked = _osv(monkeypatch)
    _write(tmp_path, {"Gemfile": 'gem "rails"\n', "Gemfile.lock":
                      "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n"
                      "    odd gem (1.0)\n    nokogiri (1.15.4-x86_64-linux)\n    broken (not-a-version)\n"
                      "    nåme (1.0)\n    tail (1.0) extra\n    pre (2.0.0.rc1)\n\nPLATFORMS\n  ruby\n"})
    findings, info = depaudit.run_gem_audit(tmp_path, no_network=False)
    assert sorted(asked) == [("nokogiri", "1.15.4"), ("pre", "2.0.0.rc1"), ("rails", "7.0.4")]
    assert findings == [] and info["state"] == "partial" and info["checked"] == 3 and info["not_read"] == 4, info
    assert all(re.match(r"Gemfile\.lock: line \d+: ", e) and _plain(e) for e in info["errors"]), info["errors"]
    assert [int(re.search(r"line (\d+)", e).group(1)) for e in info["errors"]] == [6, 8, 9, 10]
    _write(tmp_path / "twin", {"Gemfile.lock": "GEM\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n"})
    _f, info = depaudit.run_gem_audit(tmp_path / "twin", no_network=False)
    assert info["state"] == "ok" and "errors" not in info and "not_read" not in info


def test_a_library_name_osv_is_asked_about_is_a_library_name(tmp_path, monkeypatch):
    """Gradle and Maven: a name with a variable in it, or with anything a coordinate cannot hold, was sent to OSV as
    written and counted as checked."""
    asked = _osv(monkeypatch)
    _write(tmp_path, {
        "pom.xml": "<project><dependencies>"
                   "<dependency><groupId>com.example</groupId><artifactId>ok</artifactId><version>1.0</version></dependency>"
                   "<dependency><groupId>${project.groupId}</groupId><artifactId>core</artifactId><version>1.0</version></dependency>"
                   '<dependency><groupId>com.example"}],"x":[{"</groupId><artifactId>a&amp;b</artifactId>'
                   "<version>1.0</version></dependency></dependencies></project>",
        "gradle/libs.versions.toml": '[versions]\ngson = "2.8.5"\n[libraries]\n'
                                     'gson = { module = "com.google.code.gson:gson", version.ref = "gson" }\n'
                                     'spaced = "com.example:has space:1.0"\n'
                                     'plain = "com.example:plain:1.2.3"\n'
                                     'odd = { module = 5, version = "1" }\n'})
    findings, info = depaudit.run_maven_audit(tmp_path, no_network=False)
    assert sorted(asked) == [("com.example:ok", "1.0"), ("com.example:plain", "1.2.3"), ("com.google.code.gson:gson", "2.8.5")]
    assert findings == [] and info["state"] == "partial" and info["checked"] == 3, info
    assert info["unpinned"] == 3 and all(_plain(x) for x in info["unpinned_examples"])      # counted as not checked
    assert info["not_read"] == 1 and info["errors"][0].startswith("gradle/libs.versions.toml:")


def test_a_catalog_library_with_no_single_version_is_counted_as_not_checked(tmp_path, monkeypatch):
    """A Gradle catalog may leave a version to a platform, or give a range: nothing to look up, and nothing wrong."""
    asked = _osv(monkeypatch)
    _write(tmp_path, {"gradle/libs.versions.toml":
                      '[versions]\nrich = { strictly = "[1.0, 2.0[", prefer = "1.5" }\n[libraries]\n'
                      'plain = "com.example:plain:1.2.3"\n'
                      'managed = { module = "com.example:managed" }\n'
                      'short = "com.example:short"\n'
                      'ranged = { module = "com.example:ranged", version = { strictly = "[1.0, 2.0[" } }\n'
                      'by-ref = { module = "com.example:byref", version.ref = "rich" }\n'
                      'plus = "com.example:plus:1.+"\n'})
    findings, info = depaudit.run_maven_audit(tmp_path, no_network=False)
    assert asked == [("com.example:plain", "1.2.3")] and findings == []
    assert info["state"] == "ok" and info["checked"] == 1 and info["unpinned"] == 5 and "errors" not in info, info
    assert info["unpinned_examples"] == ["com.example:managed (no version written)", "com.example:short (no version written)",
                                         "com.example:ranged (a range of versions)", "com.example:byref (a range of versions)",
                                         "com.example:plus:1.+"]
    lines = evidence.limits(build_graph(tmp_path), {"tools": [info], "findings": []}, None, {}, "full", None)
    assert any(ln.startswith("5 Gradle/Maven libraries are written without an exact name and version") for ln in lines), lines
    assert any("the libraries they pull in were not." in ln for ln in lines)
    # an audit that could ask about nothing still says how many it could not check
    _write(tmp_path / "none", {"gradle/libs.versions.toml": '[libraries]\nmanaged = { module = "com.example:managed" }\n'})
    _f, info = depaudit.run_maven_audit(tmp_path / "none", no_network=False)
    lines = evidence.limits(build_graph(tmp_path / "none"), {"tools": [info], "findings": []}, None, {}, "full", None)
    assert info["state"] == "skipped" and any(ln.startswith("1 Gradle/Maven library is written without") for ln in lines), lines
    assert not any("the libraries they pull in" in ln for ln in lines)       # nothing was checked, so that is not said


def test_the_reason_of_a_partial_audit_counts_each_kind_in_plain_words(tmp_path, monkeypatch):
    """One, or several; entries that are no name and version, what the service could not answer for, or both."""
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)

    def pip_audit(*skipped):
        deps = [{"name": "flask", "version": "1.0", "vulns": []}] + [{"name": n, "skip_reason": f"not found: {n}"} for n in skipped]
        monkeypatch.setattr(scanresult, "run_tool", lambda cmd, **kw: ToolRun(0, json.dumps({"dependencies": deps}), ""))
        return depaudit.run_pip_audit(tmp_path, False)[1]
    lock = [("flask", "1.0"), ("one", "1.0"), ("two", "1.0")]
    _write(tmp_path, {"uv.lock": _toml_lock(lock)})
    assert pip_audit("one")["status"] == "partial: 1 package could not be checked"
    info = pip_audit("one", "two")
    assert info["status"] == "partial: 2 packages could not be checked" and "not_read" not in info
    assert info["errors"] == ["one: not found: one", "two: not found: two"]
    _write(tmp_path, {"uv.lock": _toml_lock(lock + [("odd", "latest"), ("odder", "newest")])})
    info = pip_audit("one")
    assert info["status"] == ("partial: 2 parts of the dependency files could not be read as a package name and version; "
                              "1 package could not be checked")
    assert info["not_read"] == 2 and info["checked"] == 3
    assert info["errors"] == ['uv.lock: odd: "latest" is not a version', 'uv.lock: odder: "newest" is not a version',
                              "one: not found: one"]

    # the audits that ask OSV: what is known of a vulnerability could not be fetched
    monkeypatch.setattr(depaudit, "_osv_post", lambda path, body, timeout=60: {
        "results": [{"vulns": [{"id": "GHSA-" + q["package"]["name"][-4:]}]} for q in body["queries"]]})

    def down(path, timeout=30):
        raise OSError("no route")
    monkeypatch.setattr(depaudit, "_osv_get", down)
    for n, said in ((1, "1 vulnerability detail could not be fetched"), (2, "2 vulnerability details could not be fetched")):
        php = _write(tmp_path / f"php{n}", {"composer.lock": json.dumps({"packages": [
            {"name": f"acme/aaa{i}", "version": "1.0.0"} for i in range(n)]})})
        findings, info = depaudit.run_composer_audit(php, False)
        assert info["status"] == "partial: " + said and len(findings) == n and len(info["errors"]) == n, info


def test_the_first_five_of_what_has_no_exact_version_are_kept_as_examples(tmp_path, monkeypatch):
    asked = _osv(monkeypatch)
    names = [f"com.example:lib{i}" for i in range(7)]
    _write(tmp_path, {"gradle/libs.versions.toml": "[libraries]\nplain = \"com.example:plain:1.2.3\"\n" + "".join(
        f'l{i} = "{n}:1.+"\n' for i, n in enumerate(names))})
    info = depaudit.run_maven_audit(tmp_path, False)[1]
    assert asked == [("com.example:plain", "1.2.3")] and info["unpinned"] == 7
    assert info["unpinned_examples"] == [n + ":1.+" for n in names[:5]]
    php = _write(tmp_path / "php", {"composer.lock": json.dumps({"packages": [{"name": "acme/rc", "version": "2.0.0"}] + [
        {"name": f"acme/fork{i}", "version": "dev-main"} for i in range(7)]})})
    info = depaudit.run_composer_audit(php, False)[1]
    assert info["unpinned"] == 7 and info["unpinned_examples"] == [f"acme/fork{i} dev-main" for i in range(5)]
    py = _write(tmp_path / "py", {"requirements.txt": "flask==2.0.1\n" + "".join(f"pkg{i}>=1.0\n" for i in range(7))})
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
    monkeypatch.setattr(scanresult, "run_tool", lambda cmd, **kw: ToolRun(0, json.dumps({"dependencies": []}), ""))
    info = depaudit.run_pip_audit(py, False)[1]
    assert info["unpinned"] == 7 and info["unpinned_examples"] == [f"requirements.txt: pkg{i}>=1.0" for i in range(5)]


def test_what_is_shown_of_an_odd_entry_cannot_draw_on_a_console(tmp_path):
    _write(tmp_path, {"uv.lock": _toml_lock([("flask", "2.0.1"), ("x\x1b]0;owned\x07\x1b[2J", "1"), ("y" * 5000, "1"),
                                             ("z\u202e", "1")])})
    _f, info = depaudit.run_pip_audit(tmp_path, no_network=True)
    assert info["status"] == "skipped: offline"         # asked offline: the names that can be checked wait for a run
    _write(tmp_path / "only-odd", {"uv.lock": _toml_lock([("x\x1b]0;owned\x07\x1b[2J", "1"), ("y" * 5000, "1")])})
    _f, info = depaudit.run_pip_audit(tmp_path / "only-odd", no_network=True)
    assert info["state"] == "partial" and len(info["errors"]) == 2
    assert all(_plain(e) and len(e) <= 200 for e in info["errors"]) and _plain(info["status"])


def test_how_much_of_an_odd_value_is_shown(tmp_path):
    """Sixty characters of a text, in quotes, with three dots when there was more; of anything else, only what it is."""
    shown = depaudit._shown
    assert shown("a" * 60) == '"' + "a" * 60 + '"' and shown("a" * 61) == '"' + "a" * 60 + '..."'
    assert shown("\x1b" * 20) == '"' + "\\x1b" * 15 + '..."'               # counted as it is shown, not as it is stored
    assert shown("") == '""' and shown("dev-main", 3) == '"dev..."'
    assert [shown(v) for v in ({}, [], True, 5, 1.5, None, b"x")] == [
        "a table", "a list", "true or false", "a number", "a number", "nothing", "not text"]
    # of a long path the end is kept, which says which file it is, and the whole line is 200 characters at most
    rel = f"{'d' * 60}/{'e' * 60}/uv.lock"
    _write(tmp_path / "deep", {rel: _toml_lock([("n" * 100, "latest")])})
    _f, info = depaudit.run_pip_audit(tmp_path / "deep", True)
    assert info["files"] == [rel] and info["errors"] == [("..." + rel[-97:] + ": " + "n" * 100)[:200]]
    _write(tmp_path / "near", {rel[-100:]: "package = 5\n"})                 # the twin: a path that fits is shown whole
    assert depaudit.run_pip_audit(tmp_path / "near", True)[1]["errors"] == [rel[-100:] + ": its packages are a number, not a list"]
    # a requirement that is no exact version is kept as an example, 60 characters of it
    long = "requests>=2.31 ; python_version >= '3.8' and platform_system != 'Windows' and extra == 'all'"
    _write(tmp_path / "loose", {"requirements.txt": long + "\n", "pyproject.toml": f"[project]\ndependencies = [{json.dumps(long)}]\n"})
    assert depaudit.python_pins(tmp_path / "loose")[1] == ["requirements.txt: " + long[:60], "pyproject.toml: " + long[:60]]
    # a library that cannot be looked up is kept as an example, 120 characters of it; of a catalog's key, 40
    _write(tmp_path, {"gradle/libs.versions.toml": f'[libraries]\nlong = "com.example:{"n" * 300}:1.+"\n'
                                                   f'bare = {{ module = "com.example:{"m" * 200}" }}\n{"k" * 50} = {{ module = 5 }}\n'})
    odd = depaudit.Odd()
    assert depaudit.maven_coords(tmp_path, odd)[1] == [("com.example:" + "n" * 300)[:120], ("com.example:" + "m" * 200)[:120]]
    assert odd.lines == [f'gradle/libs.versions.toml: library "{"k" * 40}..." has a number where its group and name belong']
