"""The project's own versions, to the letter, and a fingerprint for every library (a firm pass or fail, stage 2).

A test run says something about a project only when it ran on the libraries the project means. So: the versions a
project fixes are the versions taken (an exact `==`, or a lock file: uv, Poetry, PDM, Pipenv, npm); a fingerprint
the project names for a file is checked against the file the store handed out, and a file that is another one
means no test is run; a lock file that sends a library to another store than the person's is not followed; and the
record names every library with its version and fingerprint and says, for each, whether the version was the
project's own choice (`exact`) and whether the fingerprint is one the project names (`checked`).

No test here reaches the internet: the stores are stand-ins on this computer (`tests/stores.py`)."""
import json
import sys
from pathlib import Path

import pytest
from stores import NpmStore, PyStore
from test_libraries import UNITTEST, _check, _js_project, _named, _online, _py_project, needs_npm

from lantern import sandbox

QUIET = lambda line: None       # noqa: E731
WHEEL = "stage2sample-1.0.0-py3-none-any.whl"
LOCKS = ["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"]
PYPI = "https://pypi.org/simple"


@pytest.fixture()
def pystore():
    """Two versions of one library: 1.0.0 answers 42 and the newer 1.1.0 answers 43."""
    with PyStore() as store:
        store.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 42\n"})
        store.add("stage2sample", "1.1.0", {"stage2sample/__init__.py": "def answer():\n    return 43\n"})
        yield store


@pytest.fixture()
def npmstore():
    with NpmStore() as store:
        yield store


def _lock_text(kind: str, entries, source: str = PYPI) -> str:
    """A lock file of `kind` as its tool writes it, for `entries` = (name, version, fingerprint): one file, built
    for every system. Where the third is a list of (file name, fingerprint), those are the files the lock file
    lists for that version: ready-built for one system or another, and `.tar.gz` for the source."""
    entries = [(name, version, [(f"{name}-{version}-py3-none-any.whl", files)] if isinstance(files, str) else files)
               for name, version, files in entries]
    if kind == "Pipfile.lock":
        return json.dumps({
            "_meta": {"hash": {"sha256": "0" * 64}, "pipfile-spec": 6,
                      "sources": [{"name": "pypi", "url": source, "verify_ssl": True}]},
            "default": {}, "develop": {name: {"hashes": ["sha256:" + digest for _, digest in files], "index": "pypi",
                                              "version": "==" + version} for name, version, files in entries}})
    out = []
    if kind == "uv.lock":
        out.append('version = 1\nrequires-python = ">=3.8"\n\n[[package]]\nname = "proj"\nversion = "0.1.0"\n'
                   'source = { virtual = "." }\n')
    for name, version, files in entries:
        out.append(f'[[package]]\nname = "{name}"\nversion = "{version}"\n')
        if kind == "uv.lock":
            at = "https://files.pythonhosted.org/packages/aa/bb/"
            out.append(f'source = {{ registry = "{source}" }}\n'
                       + "".join(f'sdist = {{ url = "{at}{file}", hash = "sha256:{digest}", size = 900 }}\n'
                                 for file, digest in files if not file.endswith(".whl")))
            built = [f'    {{ url = "{at}{file}", hash = "sha256:{digest}", size = 900 }},\n'
                     for file, digest in files if file.endswith(".whl")]
            if built:
                out.append("wheels = [\n" + "".join(built) + "]\n")
        else:
            out.append("files = [\n" + "".join(f'    {{file = "{file}", hash = "sha256:{digest}"}},\n'
                                               for file, digest in files) + "]\n")
            if kind == "poetry.lock" and source != PYPI:
                out.append(f'\n[package.source]\ntype = "legacy"\nurl = "{source}"\nreference = "other"\n')
    if kind == "poetry.lock":
        out.append('[metadata]\nlock-version = "2.0"\npython-versions = "^3.8"\ncontent-hash = "' + "0" * 64 + '"\n')
    if kind == "pdm.lock":
        out.insert(0, '[metadata]\ngroups = ["default"]\nlock_version = "4.4"\n')
    return "\n".join(out)


def _locked_project(folder: Path, kind: str, entries=None, source: str = PYPI, check: str = "42") -> Path:
    """A project that names `stage2sample` with no version, as each tool's own file does, with a lock file of
    `kind` beside it (none when `entries` is None)."""
    repo = _py_project(folder, check=f"self.assertEqual(stage2sample.answer(), {check})")
    (repo / "requirements.txt").unlink()
    if kind == "Pipfile.lock":
        (repo / "Pipfile").write_text('[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\nverify_ssl = true\n\n'
                                      '[packages]\n\n[dev-packages]\nstage2sample = "*"\n', encoding="utf-8")
    elif kind == "poetry.lock":
        (repo / "pyproject.toml").write_text('[tool.poetry]\nname = "proj"\nversion = "0.1.0"\n\n'
                                             '[tool.poetry.dependencies]\npython = "^3.8"\nstage2sample = "*"\n',
                                             encoding="utf-8")
    else:
        (repo / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "0.1.0"\n'
                                             'dependencies = ["stage2sample"]\n', encoding="utf-8")
    if entries is not None:
        (repo / kind).write_text(_lock_text(kind, entries, source), encoding="utf-8")
    if kind == "pdm.lock" and source != PYPI:       # PDM's lock file names no store: the project's own table does
        with open(repo / "pyproject.toml", "a", encoding="utf-8") as f:
            f.write(f'\n[[tool.pdm.source]]\nname = "private"\nurl = "{source}"\n')
    return repo


# ---------------------------------------------------------------------------- a lock file's versions
@pytest.mark.parametrize("kind", LOCKS)
def test_the_versions_and_fingerprints_of_a_lock_file_are_followed(tmp_path, monkeypatch, pystore, kind):
    """The store has a newer version; the lock file says 1.0.0 and names its file's fingerprint. That file is
    taken, the record says the version was the project's choice and the fingerprint the project's own."""
    _online(monkeypatch, python=pystore)
    repo = _locked_project(tmp_path / "proj", kind, [("stage2sample", "1.0.0", pystore.sha256[WHEEL])])
    lines = []
    res = sandbox.run(repo, UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    libs, got = res["libraries"], _named(res)["stage2sample"]
    assert got["version"] == "1.0.0" and got["exact"] is True and got["checked"] is True
    assert libs["exact"] is True and libs["checked"] == 1 and libs["locked"] == kind
    assert any("every version is the project's own choice" in line for line in lines), lines


@pytest.mark.parametrize("kind", LOCKS)
def test_the_twin_with_no_lock_file_gets_the_newest_and_the_record_says_so(tmp_path, monkeypatch, pystore, kind):
    _online(monkeypatch, python=pystore)
    lines = []
    res = sandbox.run(_locked_project(tmp_path / "proj", kind, None, check="43"), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    libs, got = res["libraries"], _named(res)["stage2sample"]
    assert got["version"] == "1.1.0" and got["exact"] is False and got["checked"] is False
    assert libs["exact"] is False and libs["checked"] == 0 and "locked" not in libs
    assert any("1 of 1" in line and "does not fix" in line for line in lines), lines


@pytest.mark.parametrize("kind", LOCKS)
def test_a_file_that_is_not_the_one_the_lock_file_names_means_no_test_is_run(tmp_path, monkeypatch, pystore, kind):
    """The store hands out a file under the right name and version whose content is not what the project locked."""
    _online(monkeypatch, python=pystore)
    repo = _locked_project(tmp_path / "proj", kind, [("stage2sample", "1.0.0", "ab" * 32)])
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines = []
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=lines.append)
    assert "fingerprint" in str(e.value) and "stage2sample" in str(e.value) and "lock file" in str(e.value)
    assert "PLANTED-RAN" not in " ".join(lines)


@pytest.mark.parametrize("kind", LOCKS)
def test_a_lock_file_that_sends_a_library_to_another_store_is_not_followed(tmp_path, monkeypatch, pystore, kind):
    """A library the project takes from a store of its own, asked of the person's store by its name, may be
    somebody else's library there. Nothing is fetched, and the tests are not run."""
    _online(monkeypatch, python=pystore)
    repo = _locked_project(tmp_path / "proj", kind, [("stage2sample", "1.0.0", pystore.sha256[WHEEL])],
                           source="https://packages.example.invalid/simple")
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=QUIET)
    assert "another store" in str(e.value) and "example.invalid" not in str(e.value) and pystore.seen == []


@pytest.mark.parametrize("entry", [
    '[[package]]\nname = "stage2sample"\nversion = "1.0.0"\nsource = { git = "https://example.invalid/x.git" }\n',
    '[[package]]\nname = "stage2sample"\nversion = "1.0.0"\nsource = { url = "https://example.invalid/x.whl" }\n',
    '[[package]]\nname = "stage2sample"\nversion = "1.0.0"\nsource = { path = "../x.whl" }\n',
])
def test_a_library_locked_to_a_link_or_a_folder_is_not_followed(tmp_path, monkeypatch, pystore, entry):
    _online(monkeypatch, python=pystore)
    repo = _locked_project(tmp_path / "proj", "uv.lock", [])
    (repo / "uv.lock").write_text("version = 1\n\n" + entry, encoding="utf-8")
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=QUIET)
    assert "another store, a link or a folder" in str(e.value) and pystore.seen == []


OTHER = "https://packages.example.invalid/simple"


@pytest.mark.parametrize("table", [
    f'[[tool.uv.index]]\nname = "private"\nurl = "{OTHER}"\n',
    f'[tool.uv]\nextra-index-url = ["{OTHER}"]\n',
    f'[tool.uv]\nindex-url = "{OTHER}"\n',
    f'[[tool.poetry.source]]\nname = "private"\nurl = "{OTHER}"\n',
    f'[[tool.pdm.source]]\nname = "private"\nurl = "{OTHER}"\n',
    '[tool.uv.sources]\nstage2sample = { git = "https://example.invalid/x.git" }\n',
    '[tool.uv.sources]\nstage2sample = { path = "../elsewhere" }\n',
])
def test_a_store_or_a_link_named_in_a_tools_own_table_is_not_followed(tmp_path, monkeypatch, pystore, table):
    _online(monkeypatch, python=pystore)
    repo = _locked_project(tmp_path / "proj", "uv.lock", None)
    with open(repo / "pyproject.toml", "a", encoding="utf-8") as f:
        f.write("\n" + table)
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=QUIET)
    assert "another store, a link or a folder" in str(e.value) and "example.invalid" not in str(e.value)
    assert pystore.seen == []


def test_a_library_that_is_a_folder_of_the_project_is_not_asked_of_the_store(tmp_path, monkeypatch, pystore):
    """A workspace member has the name of a library and is a folder of the project. Asked of the store by that
    name it would be somebody else's library, so it is not asked for at all, and the record says so."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2member", "9.9.9", {"stage2member.py": "raise SystemExit('PLANTED-RAN: the store\'s library')\n"})
    repo = _locked_project(tmp_path / "proj", "uv.lock", None, check="43")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "proj"\nversion = "0.1.0"\ndependencies = ["stage2sample", "stage2member"]\n\n'
        '[tool.uv.sources]\nstage2member = { workspace = true }\n', encoding="utf-8")
    (repo / "stage2member.py").write_text("OWN = True\n", encoding="utf-8")
    (repo / "test_it.py").write_text(
        "import unittest\n\nimport stage2member\nimport stage2sample\n\n\nclass T(unittest.TestCase):\n"
        "    def test_it(self):\n        self.assertTrue(stage2member.OWN)\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert list(_named(res)) == ["stage2sample"] and "/simple/stage2member/" not in pystore.seen
    assert any("stage2member" in note and "folder of the project" in note for note in res["libraries"]["notes"])


def test_offline_a_line_that_names_another_store_is_passed_over_and_said(tmp_path, monkeypatch, pystore):
    """Offline nothing is fetched from anywhere, so a line that names another store asks for nothing: the tests run
    on what is installed, as they did before libraries were fetched, and the record says the line was passed over."""
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    repo = _py_project(tmp_path / "proj", needs=f"--extra-index-url {OTHER}\npytest\n")
    (repo / "test_it.py").write_text("import pytest\n\n\ndef test_it():\n    assert pytest.__version__\n", encoding="utf-8")
    res = sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=QUIET)
    assert res["returncode"] == 0 and res["libraries"]["state"] == "installed" and pystore.seen == []
    assert any("passed over" in note and "example.invalid" not in note for note in res["libraries"]["notes"])


def test_a_lock_file_made_with_the_persons_own_store_is_followed(tmp_path, monkeypatch, pystore):
    """The twin: the store the lock file names is the one the person set."""
    _online(monkeypatch, python=pystore)
    repo = _locked_project(tmp_path / "proj", "uv.lock", [("stage2sample", "1.0.0", pystore.sha256[WHEEL])],
                           source=pystore.url.rstrip("/"))
    res = sandbox.run(repo, UNITTEST, log=QUIET)
    assert res["returncode"] == 0 and res["libraries"]["exact"] is True


def test_a_library_the_lock_file_does_not_name_is_said(tmp_path, monkeypatch, pystore):
    """A lock file that is behind the project's own list: the library it does not name is taken at the newest
    version that fits, and the record does not call the run exact."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2other", "2.0.0", {"stage2other.py": "X = 1\n"})
    repo = _locked_project(tmp_path / "proj", "uv.lock", [("stage2sample", "1.0.0", pystore.sha256[WHEEL])])
    (repo / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "0.1.0"\n'
                                         'dependencies = ["stage2sample", "stage2other"]\n', encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    got = _named(res)
    assert got["stage2sample"]["exact"] is True and got["stage2other"]["exact"] is False
    assert res["libraries"]["exact"] is False and res["libraries"]["checked"] == 1


# ---------------------------------------------------------------------------- a version that is not there for this system
ELSEWHERE = ("win_amd64", "Windows", "win32") if sys.platform == "darwin" else ("macosx_11_0_arm64", "macOS", "darwin")
FILES_NAMED = ["uv.lock", "poetry.lock", "pdm.lock"]        # these list each file by its name; Pipenv's names none


def _for_another_system(folder: Path, store: PyStore, kind: str, older: bool = True, built: bool = True,
                        names: str = "stage2mac") -> Path:
    """A project that names `stage2sample` and `stage2mac`, with a lock file that fixes `stage2mac` 3.0.0. The
    store has that version ready-built for another system than this one (`built`) and as source, and (`older`) a
    2.0.0 for every system, which the lock file does not name."""
    files = []
    if built:
        tag = "py3-none-" + ELSEWHERE[0]
        files.append((f"stage2mac-3.0.0-{tag}.whl", store.add("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, tag=tag)))
    files.append(("stage2mac-3.0.0.tar.gz", store.add("stage2mac", "3.0.0", source=True, files={
        "setup.py": "raise SystemExit('PLANTED-BUILT: the source of a library was run')\n", "stage2mac.py": "N = 3\n"})))
    if older:
        store.add("stage2mac", "2.0.0", {"stage2mac.py": "N = 2\n"})
    repo = _locked_project(folder, kind, [("stage2sample", "1.0.0", store.sha256[WHEEL]), ("stage2mac", "3.0.0", files)])
    manifest = repo / ("Pipfile" if kind == "Pipfile.lock" else "pyproject.toml")
    text = manifest.read_text(encoding="utf-8")
    if kind in ("Pipfile.lock", "poetry.lock"):
        assert names == "stage2mac"
        text = text.replace('stage2sample = "*"\n', 'stage2sample = "*"\nstage2mac = "*"\n')
    else:
        text = text.replace('["stage2sample"]', "['stage2sample', '" + names + "']")
    assert "stage2mac" in text
    manifest.write_text(text, encoding="utf-8")
    return repo


@pytest.mark.parametrize("older", [True, False], ids=["an older one fits", "no version fits"])
@pytest.mark.parametrize("kind", FILES_NAMED)
def test_a_version_that_is_ready_built_for_another_system_only_is_said_as_that(tmp_path, monkeypatch, pystore, kind, older):
    """The lock file fixes a version that the store has ready-built for another system only, and as source. Found
    on a public project (2026-11-13): pip's word for it is "conflicting dependencies", and Lantern said "the
    versions the project names cannot be had together", which sends the reader after a conflict that is not there.
    The source is not asked for and nothing of it runs, no test is run, and the reason names the library, its
    version and the system the lock file lists it for."""
    _online(monkeypatch, python=pystore)
    repo = _for_another_system(tmp_path / "proj", pystore, kind, older=older)
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines = []
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=lines.append)
    said = str(e.value)
    assert "stage2mac 3.0.0" in said and "lock file" in said and "no ready-built package for" in said, said
    assert f"for {ELSEWHERE[1]} only" in said and "does not build" in said and "tests were not run" in said, said
    assert "cannot be had together" not in said and "PLANTED" not in " ".join(lines), (said, lines)
    assert not any(path.endswith(".tar.gz") for path in pystore.seen), pystore.seen


@pytest.mark.parametrize("kind", FILES_NAMED)
def test_a_version_that_is_there_as_source_only_is_said_as_that(tmp_path, monkeypatch, pystore, kind):
    """The same with no ready-built file of that version at all: the lock file lists the source and nothing else."""
    _online(monkeypatch, python=pystore)
    repo = _for_another_system(tmp_path / "proj", pystore, kind, built=False)
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines = []
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=lines.append)
    said = str(e.value)
    assert "stage2mac 3.0.0" in said and "as source only" in said and "does not build" in said, said
    assert "cannot be had together" not in said and ELSEWHERE[1] not in said and "PLANTED" not in " ".join(lines), said
    assert not any(path.endswith(".tar.gz") for path in pystore.seen), pystore.seen


def test_a_lock_file_that_names_no_files_gets_no_reason_it_cannot_know(tmp_path, monkeypatch, pystore):
    """Pipenv's lock file names fingerprints and no file: which systems a version is built for is not in it. The
    reason then says what pip said and names the library, and claims nothing about systems."""
    _online(monkeypatch, python=pystore)
    repo = _for_another_system(tmp_path / "proj", pystore, "Pipfile.lock")
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines = []
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=lines.append)
    said = str(e.value)
    assert "stage2mac" in said and "cannot be had together" in said, said
    assert ELSEWHERE[1] not in said and "does not build" not in said and "PLANTED" not in " ".join(lines), said


def test_versions_that_do_not_go_together_are_still_said_as_that(tmp_path, monkeypatch, pystore):
    """The twin with a conflict that is one: the project asks for 1.1 or newer and its lock file, which is behind,
    fixes 1.0.0. Every file the lock file lists fits this system, so nothing is said about systems."""
    _online(monkeypatch, python=pystore)
    repo = _locked_project(tmp_path / "proj", "uv.lock", [("stage2sample", "1.0.0", pystore.sha256[WHEEL])])
    (repo / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "0.1.0"\n'
                                         'dependencies = ["stage2sample>=1.1"]\n', encoding="utf-8")
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=QUIET)
    said = str(e.value)
    assert "cannot be had together" in said and "stage2sample" in said, said
    assert "ready-built" not in said and "does not build" not in said, said


def test_a_library_the_project_names_for_another_system_is_not_asked_for_here(tmp_path, monkeypatch, pystore):
    """What the reason above tells the person to do, done: the project says which system the library is for. It is
    then not asked for on this one, and the tests run on the rest, every version the project's own."""
    _online(monkeypatch, python=pystore)
    repo = _for_another_system(tmp_path / "proj", pystore, "uv.lock",
                               names=f'stage2mac; sys_platform == "{ELSEWHERE[2]}"')
    res = sandbox.run(repo, UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert set(_named(res)) == {"stage2sample"} and res["libraries"]["exact"] is True
    assert not any("stage2mac-" in path for path in pystore.seen), pystore.seen


# ---------------------------------------------------------------------------- versions and fingerprints in requirements
def test_an_exact_version_is_exact_and_a_pattern_is_not(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    res = sandbox.run(_py_project(tmp_path / "a", needs="stage2sample==1.0.0\n"), UNITTEST, log=QUIET)
    assert res["libraries"]["exact"] is True and _named(res)["stage2sample"]["exact"] is True
    res = sandbox.run(_py_project(tmp_path / "b", needs="stage2sample==1.0.*\n"), UNITTEST, log=QUIET)
    assert _named(res)["stage2sample"]["version"] == "1.0.0"
    assert res["libraries"]["exact"] is False and _named(res)["stage2sample"]["exact"] is False


def test_a_library_that_comes_with_another_is_named_and_exact_only_when_the_project_fixes_it(tmp_path, monkeypatch, pystore):
    """`stage2sample 2.0.0` needs `stage2dep`. The project fixes the first and says nothing of the second: both
    are in the record, and the second is not the project's choice. With a versions file that fixes it, it is."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2sample", "2.0.0", {"stage2sample/__init__.py": "import stage2dep\n\n\ndef answer():\n"
                                          "    return stage2dep.N\n"}, requires=("stage2dep>=1",))
    pystore.add("stage2dep", "1.0.0", {"stage2dep.py": "N = 42\n"})
    pystore.add("stage2dep", "1.5.0", {"stage2dep.py": "N = 43\n"})
    lines = []
    res = sandbox.run(_py_project(tmp_path / "a", check="self.assertEqual(stage2sample.answer(), 43)",
                                  needs="stage2sample==2.0.0\n"), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    got = _named(res)
    assert (got["stage2sample"]["asked"], got["stage2sample"]["exact"]) == (True, True)
    assert (got["stage2dep"]["version"], got["stage2dep"]["asked"], got["stage2dep"]["exact"]) == ("1.5.0", False, False)
    assert res["libraries"]["exact"] is False
    assert any("1 of 2" in line and "does not fix" in line for line in lines), lines
    repo = _py_project(tmp_path / "b", needs="stage2sample==2.0.0\n-c versions.txt\n")
    (repo / "versions.txt").write_text("stage2dep==1.0.0\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert _named(res)["stage2dep"]["version"] == "1.0.0" and _named(res)["stage2dep"]["exact"] is True
    assert res["libraries"]["exact"] is True


def test_a_fingerprint_written_beside_a_requirement_is_checked(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    right = pystore.sha256[WHEEL]
    res = sandbox.run(_py_project(tmp_path / "a", needs=f"stage2sample==1.0.0 --hash=sha256:{right}\n"), UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert _named(res)["stage2sample"]["checked"] is True and res["libraries"]["checked"] == 1
    repo = _py_project(tmp_path / "b", needs=f"stage2sample==1.0.0 \\\n    --hash=sha256:{'cd' * 32}\n")
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines = []
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=lines.append)
    assert "fingerprint" in str(e.value) and "PLANTED-RAN" not in " ".join(lines)


def test_fingerprints_for_some_libraries_and_not_for_all_are_said_as_such(tmp_path, monkeypatch, pystore):
    """pip takes no file without a fingerprint once the project names one for any. That is the project's own rule,
    so it is kept, and the reason says what is missing: not "the tests failed"."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2other", "2.0.0", {"stage2other.py": "X = 1\n"})
    needs = f"stage2sample==1.0.0 --hash=sha256:{pystore.sha256[WHEEL]}\nstage2other==2.0.0\n"
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(_py_project(tmp_path / "proj", needs=needs), UNITTEST, log=QUIET)
    assert "fingerprints for some" in str(e.value)


def test_a_test_runner_the_project_does_not_name_is_not_added_beside_fingerprints(tmp_path, monkeypatch, pystore):
    """Where the project names no fingerprints, Lantern adds the runner its test command needs. Beside
    fingerprints it cannot (no file is taken without one), and says what to name."""
    _online(monkeypatch, python=pystore)
    needs = f"stage2sample==1.0.0 --hash=sha256:{pystore.sha256[WHEEL]}\n"
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(_py_project(tmp_path / "proj", needs=needs), ["python", "-m", "pytest", "-q"], log=QUIET)
    assert "pytest" in str(e.value) and "fingerprint" in str(e.value) and pystore.seen == []


# ---------------------------------------------------------------------------- JavaScript
@needs_npm
def test_npms_lock_file_is_followed_to_the_letter_and_the_record_says_so(tmp_path, monkeypatch, npmstore):
    _online(monkeypatch, npm=npmstore)
    res = sandbox.run(_js_project(tmp_path / "proj", npmstore), ["npm", "test"], log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    got = _named(res)["stage2-sample"]
    assert got["exact"] is True and got["checked"] is True and got["fingerprint"].startswith("sha512-")
    assert res["libraries"]["exact"] is True and res["libraries"]["checked"] == 1
    assert res["libraries"]["locked"] == "package-lock.json"


@needs_npm
def test_javascript_with_no_lock_file_takes_the_newest_and_says_so(tmp_path, monkeypatch, npmstore):
    _online(monkeypatch, npm=npmstore)
    repo = _js_project(tmp_path / "proj", npmstore)
    (repo / "package-lock.json").unlink()
    manifest = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    manifest["dependencies"]["stage2-sample"] = "^1.0.0"
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    lines = []
    res = sandbox.run(repo, ["npm", "test"], log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    got = _named(res)["stage2-sample"]
    assert got["exact"] is False and got["checked"] is False
    assert res["libraries"]["exact"] is False and "locked" not in res["libraries"]
    assert any("1 of 1" in line and "does not fix" in line for line in lines), lines
    # the twin: package.json itself names one version, so that library is the project's own choice (what it
    # brings with it would not be)
    manifest["dependencies"]["stage2-sample"] = "1.0.0"
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    res = sandbox.run(repo, ["npm", "test"], log=QUIET)
    assert res["returncode"] == 0 and _named(res)["stage2-sample"]["exact"] is True
    assert _named(res)["stage2-sample"]["checked"] is False


# ---------------------------------------------------------------------------- the record of a whole check
def _evidence(repo: Path) -> dict:
    return json.loads((repo / ".lantern" / "evidence.json").read_text(encoding="utf-8"))


def test_the_evidence_names_every_library_with_its_fingerprint(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", needs="stage2sample==1.0.0\n")
    run, _, _ = _check(repo, UNITTEST)
    assert run["libraries"]["packages"][0]["exact"] is True
    ev = _evidence(repo)
    libs = ev["provenance"]["libraries"]
    assert libs["state"] == "fetched" and libs["store"] == pystore.host and libs["exact"] is True
    assert libs["packages"] == [{"name": "stage2sample", "version": "1.0.0", "exact": True, "checked": False,
                                 "fingerprint": "sha256:" + pystore.sha256[WHEEL]}]
    page = (repo / ".lantern" / "evidence.html").read_text(encoding="utf-8")
    assert "stage2sample" in page and pystore.sha256[WHEEL] in page
    assert not [line for line in ev["limits"] if "does not fix" in line]


def test_versions_the_project_does_not_fix_are_a_limit_of_the_report(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", check="self.assertEqual(stage2sample.answer(), 43)", needs="stage2sample\n")
    run, _, _ = _check(repo, UNITTEST)
    assert run["returncode"] == 0 and run["libraries"]["exact"] is False
    limit = [line for line in _evidence(repo)["limits"] if "does not fix" in line]
    assert len(limit) == 1 and "1 of the 1" in limit[0] and "another day" in limit[0]


@pytest.mark.parametrize("planted", [
    "<b>x</b>", ["a"], {"state": "fetched", "packages": "all of them"},
    {"state": "fetched", "store": "<script>alert(1)</script>" * 40, "exact": "yes",
     "packages": [{"name": "<img src=x>", "version": ["1"], "fingerprint": "sha256:" + "z" * 64}, "x", None]},
    {"state": "made up", "packages": []},
])
def test_a_record_of_libraries_read_back_from_disk_is_taken_by_its_shape(planted):
    """`run.json` lies in the project's own results folder and may have come with the project."""
    from lantern import evidence
    got = evidence.libraries_shown({"ran": True, "command": ["x"], "returncode": 0, "libraries": planted})
    if got is not None:
        assert got["state"] in ("fetched", "installed") and isinstance(got["exact"], bool)
        assert all(isinstance(p[k], str) and len(p[k]) <= 220 for p in got["packages"]
                   for k in ("name", "version", "fingerprint"))
        assert "<" not in json.dumps(got) and len(json.dumps(got)) < 2000      # names of a fixed shape, and bounded


def test_a_record_as_lantern_writes_it_is_shown_whole():
    """The twin: nothing of an honest record is lost on the way to the report."""
    from lantern import evidence
    packages = [{"name": "stage2sample", "version": "1.0.0", "fingerprint": "sha256:" + "ab" * 32, "file": WHEEL,
                 "asked": True, "exact": True, "checked": True},
                {"name": "@scope/pkg", "version": "2.0.0-rc.1", "fingerprint": "sha512-" + "Ab+/" * 21 + "ab==",
                 "file": "pkg-2.0.0-rc.1.tgz", "asked": False, "exact": False, "checked": True}]
    got = evidence.libraries_shown({"ran": True, "command": ["x"], "returncode": 0, "libraries": {
        "state": "fetched", "language": "python", "store": "pypi.org", "exact": False, "checked": 2, "packages": packages}})
    assert got == {"state": "fetched", "store": "pypi.org", "exact": False, "checked": 2, "left_out": 0, "above": 0,
                   "packages": [{k: p[k] for k in ("name", "version", "exact", "checked", "fingerprint")} for p in packages]}
