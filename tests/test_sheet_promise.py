"""What the sheet of "Watch my tests run" promises before a run, and what the person has to have said where this
run's walls do not hold every program of the tests (review stage, 2026-11-15).

Until then the sheet's last line read "Nothing leaves this computer: the tests have no way out to the internet or
to your network." on every system and for every kind of test, under a list whose own lines said what is held and
what is not, and the app's answer about tests said the same. The line now comes from `sandbox.reach`, which reads
the answers `sandbox.describe` reads; where a program of the tests is not held, the run starts only after the
person agreed to exactly that sentence. Every system here is a pretend one (`_system`), so the same cases are
asked on Linux, macOS and Windows; nothing of a project is run (`pipeline.analyze` is a stand-in).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from test_libraries import _online, _py_project, pystore  # noqa: F401  (pystore is a fixture)
from test_sandbox_second_look import ABOVE, NO_DOORMAN, WHY, _system
from test_server import call, srv, wait  # noqa: F401  (srv is a fixture)

import lantern
from lantern import pipeline, sandbox, server

LANGUAGES = ("python", "node", "go", "rust", "java")
NOTHING_LEAVES = "Nothing leaves this computer: the tests have no way out to the internet or to your network."
HELD, PYTHON_ONLY, NOT_HELD = "all", "python", "none"
# a system, then what it holds of (the network, the files) for Python's tests and for tests that are not Python
SYSTEMS = {
    "a network of the run's own": ({}, (HELD, HELD), (HELD, HELD)),
    "no network of its own, a doorman": ({"network": WHY}, (HELD, HELD), (HELD, HELD)),
    "neither, the kernel's rule for connections": ({"network": WHY, "doorman": NO_DOORMAN}, (HELD, HELD), (HELD, HELD)),
    "a kernel before that rule": ({"network": WHY, "doorman": NO_DOORMAN, "landlock": 3},
                                  (PYTHON_ONLY, HELD), (NOT_HELD, HELD)),
    "a run inside a run": ({"network": WHY, "doorman": ABOVE}, (PYTHON_ONLY, HELD), (NOT_HELD, HELD)),
    "a network of its own and no rule for files": ({"landlock": 0}, (HELD, PYTHON_ONLY), (HELD, NOT_HELD)),
    "a Linux with none of it": ({"network": WHY, "doorman": NO_DOORMAN, "landlock": 0},
                                (PYTHON_ONLY, PYTHON_ONLY), (NOT_HELD, NOT_HELD)),
    "macOS, Windows": ({"linux": False}, (PYTHON_ONLY, PYTHON_ONLY), (NOT_HELD, NOT_HELD)),
}
OTHER = SYSTEMS["macOS, Windows"][0]
OWN = SYSTEMS["a network of the run's own"][0]
OLDER = SYSTEMS["a kernel before that rule"][0]
# Windows where it makes a wall of its own around a project's Python tests on the libraries fetched for them
# (a firm pass or fail, stage 4, step 5: `sandbox.wall_here`, `sandbox.WALL_LINE`)
WALLED = {"linux": False, "windows": True, "wall": True}


@pytest.mark.parametrize("language", LANGUAGES)
@pytest.mark.parametrize("name", list(SYSTEMS))
def test_the_sheets_last_line_promises_only_what_this_run_keeps(tmp_path, monkeypatch, name, language):
    system, python, other = SYSTEMS[name]
    _system(monkeypatch, **system)
    network, files = python if language == "python" else other
    r = sandbox.reach(language)
    assert (r["network"], r["files"]) == (network, files), r
    words, ask = r["words"], r["ask"]
    if (network, files) == (HELD, HELD):
        assert words == NOTHING_LEAVES and ask == "", r
        return
    assert "Nothing leaves" not in words and ask and words.endswith(ask), r
    assert ("no way out" in words) == (network != NOT_HELD), words          # said of what is held, and only of that
    assert ("Python code in the tests has no way out" in words) == (network == PYTHON_ONLY), words
    assert ("reach the internet and your network" in ask) == (network != HELD), ask
    assert ("read and change the files" in ask) == (files != HELD), ask
    assert ("a program the tests start that is not Python" in ask) == (language == "python"), ask
    assert ("these tests, which are not Python" in ask) == (language != "python"), ask
    # the sheet's list above that line says the same of the network (`sandbox.describe` reads the same answers)
    listed = " ".join(sandbox.describe(tmp_path, language)["details"])
    assert ("not kept from the network" in listed) == (network != HELD), listed


def test_in_a_container_every_program_is_held_on_any_system(monkeypatch):
    for system in (OTHER, OLDER):
        _system(monkeypatch, **system)
        monkeypatch.setattr(sandbox, "docker_ok", lambda: True)
        held = [language for language in LANGUAGES if sandbox.image_for(language)]
        assert "node" in held
        for language in held:
            r = sandbox.reach(language)
            assert (r["network"], r["files"], r["words"], r["ask"]) == (HELD, HELD, NOTHING_LEAVES, ""), (language, r)


def test_with_libraries_to_fetch_the_line_does_not_say_that_nothing_leaves(monkeypatch):
    """The fetch asks a store for the libraries by name and version before the tests start: something leaves."""
    _system(monkeypatch, **OWN)
    words = sandbox.reach("python", fetched=True)["words"]
    assert "Nothing leaves" not in words and "Your code does not leave this computer" in words, words
    assert "fetched by name" in words and "no way out to the internet or to your network" in words, words
    _system(monkeypatch, **OTHER)
    for language in ("python", "node"):
        r = sandbox.reach(language, fetched=True)
        assert r == sandbox.reach(language) and "does not leave" not in r["words"], r


def _projects(tmp_path) -> tuple[Path, Path]:
    js, py = tmp_path / "js", tmp_path / "py"
    js.mkdir()
    py.mkdir()
    (js / "package.json").write_text('{"scripts": {"test": "vitest"}}', encoding="utf-8")
    (py / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    return js, py


def test_the_sheet_is_handed_that_line_and_what_to_ask(tmp_path, monkeypatch):
    js, py = _projects(tmp_path)
    _system(monkeypatch, **OTHER)
    d = server.detect_test_command(js)
    said = sandbox.reach("node")
    assert d["language"] == "node" and d["leaves"] == said["words"] and "no way out" not in d["leaves"], d["leaves"]
    assert d["reach"] == {"network": NOT_HELD, "files": NOT_HELD, "ask": said["ask"]} and said["ask"], d["reach"]
    d = server.detect_test_command(py)
    assert d["reach"]["network"] == PYTHON_ONLY and "that is not Python" in d["leaves"], d
    assert "Nothing leaves" not in d["leaves"], d["leaves"]
    _system(monkeypatch, **OWN)                               # the twin: every program held, the line as it was
    for repo in (js, py):
        d = server.detect_test_command(repo)
        assert d["leaves"] == NOTHING_LEAVES and d["reach"] == {"network": HELD, "files": HELD, "ask": ""}, d


def _added(base, repo: Path) -> str:
    code, pj = call(base, "/api/projects", "POST", {"path": str(repo)})
    assert code in (200, 201), pj
    return (pj.get("project") or pj)["id"]


@pytest.fixture()
def started(monkeypatch):
    """The commands the app would have run, in place of running them."""
    ran: list = []
    monkeypatch.setattr(pipeline, "analyze", lambda *a, **k: (ran.append(k["trace_cmd"]) if k.get("trace_cmd") else None) or {})
    return ran


def test_tests_this_run_does_not_hold_start_only_after_the_person_agreed_to_that_sentence(srv, tmp_path,  # noqa: F811
                                                                                          monkeypatch, started):
    base, store = srv
    js, _ = _projects(tmp_path)
    pid = _added(base, js)
    _system(monkeypatch, **OTHER)
    code, d = call(base, f"/api/projects/{pid}/testcmd")
    ask, command, trace = d["reach"]["ask"], d["command"], f"/api/projects/{pid}/trace"
    assert code == 200 and ask and d["reach"]["accepted"] is False and "no way out" not in d["leaves"], d
    code, e = call(base, trace, "POST", {"command": command, "confirm": True})
    assert code == 409 and ask in e["error"] and not started, e
    # a confirmation of the command, given while the sheet still ended "Nothing leaves this computer", is no such word
    store.confirm_test(pid, command)
    code, e = call(base, trace, "POST", {"command": command})
    assert code == 409 and ask in e["error"] and not started, e
    # nor is a plain yes, or another sentence
    for said in (True, "accepted", "yes", ask + " ", ask[:-1], sandbox.reach("python")["ask"], [ask], {"ask": ask}):
        code, e = call(base, trace, "POST", {"command": command, "confirm": True, "reach": said})
        assert code == 409 and ask in e["error"] and not started, (said, e)
    code, j = call(base, trace, "POST", {"command": command, "confirm": True, "reach": ask})
    assert code == 202, j
    assert wait(base, j["id"])["status"] == "done" and started == [sandbox.split(command)], started
    # said once for this project, this command and these words: the sheet does not ask again
    code, d = call(base, f"/api/projects/{pid}/testcmd")
    assert d["reach"]["ask"] == ask and d["reach"]["accepted"] is True, d["reach"]
    code, j = call(base, trace, "POST", {"command": command})
    assert code == 202 and wait(base, j["id"])["status"] == "done" and len(started) == 2, j
    # another command of the same project is asked about
    code, e = call(base, trace, "POST", {"command": "npx vitest run", "confirm": True})
    assert code == 409 and ask in e["error"] and len(started) == 2, e
    # and so is the same command once the sentence is another one (here: the files are held, the network is not)
    _system(monkeypatch, **OLDER)
    other = sandbox.reach("node")["ask"]
    assert other and other != ask
    code, e = call(base, trace, "POST", {"command": command, "reach": ask})
    assert code == 409 and other in e["error"] and len(started) == 2, e
    # a second project has not been spoken for
    _system(monkeypatch, **OTHER)
    second = tmp_path / "second"
    second.mkdir()
    (second / "package.json").write_text('{"scripts": {"test": "vitest"}}', encoding="utf-8")
    code, e = call(base, f"/api/projects/{_added(base, second)}/trace", "POST", {"command": command, "confirm": True})
    assert code == 409 and ask in e["error"] and len(started) == 2, e


def test_where_every_program_is_held_nothing_more_is_asked(srv, tmp_path, monkeypatch, started):  # noqa: F811
    base, _ = srv
    js, py = _projects(tmp_path)
    for repo in (js, py):
        pid = _added(base, repo)
        _system(monkeypatch, **OWN)
        code, d = call(base, f"/api/projects/{pid}/testcmd")
        assert d["leaves"] == NOTHING_LEAVES and d["reach"] == {"network": HELD, "files": HELD, "ask": "",
                                                                "accepted": True}, d
        code, e = call(base, f"/api/projects/{pid}/trace", "POST", {"command": d["command"]})
        assert code == 409 and "confirm this command first" in e["error"], e          # as before
        code, j = call(base, f"/api/projects/{pid}/trace", "POST", {"command": d["command"], "confirm": True})
        assert code == 202 and wait(base, j["id"])["status"] == "done", j
    assert len(started) == 2


def test_in_the_terminal_such_tests_start_only_after_the_word_for_it(srv, tmp_path, monkeypatch, started):  # noqa: F811
    from lantern.server import Handler, TerminalRefused, run_terminal_command
    base, store = srv
    js, _ = _projects(tmp_path)
    pid = _added(base, js)
    p, app = store.project(pid), Handler.app
    _system(monkeypatch, **OTHER)
    ask = sandbox.reach("node")["ask"]
    with pytest.raises(TerminalRefused) as e:
        run_terminal_command(app, p, js, js / ".lantern", ["trace", "--", "npm", "test"])
    assert ask in str(e.value) and "trace --anyway" in str(e.value) and not started, str(e.value)
    job = run_terminal_command(app, p, js, js / ".lantern", ["trace", "--anyway", "--", "npm", "test"])["job"]
    assert job["kind"] == "trace" and wait(base, job["id"])["status"] == "done" and started == [["npm", "test"]]
    # said once: the same command needs no second word, in the terminal and on the sheet
    job = run_terminal_command(app, p, js, js / ".lantern", ["trace", "npm", "test"])["job"]
    assert wait(base, job["id"])["status"] == "done" and len(started) == 2
    assert call(base, f"/api/projects/{pid}/testcmd")[1]["reach"]["accepted"] is True
    # `--anyway` lets nothing else through: still a test command only
    for argv in (["trace", "--anyway", "--", "bash", "-c", "npm test"], ["trace", "--anyway"], ["analyze", "--anyway"]):
        with pytest.raises(TerminalRefused):
            run_terminal_command(app, p, js, js / ".lantern", argv)
    # the twin: where every program is held the word is not asked for
    _system(monkeypatch, **OWN)
    job = run_terminal_command(app, p, js, js / ".lantern", ["trace", "--", "npx", "vitest", "run"])["job"]
    assert wait(base, job["id"])["status"] == "done" and len(started) == 3


def test_no_page_and_no_help_text_promises_it_for_every_system():
    """The words stand in one place, `sandbox.reach`, which says them where they are true. The page drew
    "Nothing leaves this computer." even where the server said nothing; the answer among the app's questions and
    the help of `--sandbox` said "no way out" of every run."""
    root = Path(lantern.__file__).parent
    for phrase in ("no way out to the internet", "Nothing leaves this computer"):
        holds = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.suffix in (".py", ".html", ".js")
                       and phrase in p.read_text(encoding="utf-8", errors="replace"))
        assert holds == ["sandbox.py"], (phrase, holds)
    page = (root / "viewer" / "app.html").read_text(encoding="utf-8")
    sheet = page[page.index("async function watchTestsSheet(p)"):]
    sheet = sheet[:sheet.index("\n}\n")]
    assert "d.reach" in sheet and 'id="shreach"' in sheet and "reach:" in sheet, "the sheet asks, and sends what was agreed to"
    assert "esc(d.leaves)" in sheet and "d.leaves ||" not in sheet                 # no words of the page's own
    answer = next(line for line in page.splitlines() if "'Does Lantern run my app or my tests?'" in line)
    assert "the sheet" in answer and "read-only" not in answer and "no way out" not in answer, answer


def test_the_command_line_says_what_its_sandbox_keeps_only_where_it_does(capsys):
    from lantern import cli
    with pytest.raises(SystemExit):
        cli.main(["analyze", "--help"])
    said = " ".join(capsys.readouterr().out.split())
    assert "--sandbox" in said and "no way out to the internet" not in said
    assert "where this system's sandbox holds them" in said, said


# ---------------------------------------------------------------------------- Windows, where it makes a wall of its own
def test_where_windows_makes_a_wall_the_sheet_asks_only_for_what_the_wall_does_not_hold(monkeypatch):
    """A project's own Python tests on the libraries fetched for them run inside a wall of Windows' own made for
    the run: every program they start is kept from the person's files and from the internet by Windows itself, so
    only what the wall does not close is asked about, in the wall's own words (`WALL_ASK`). Tests on this
    computer's Python and tests that are not Python are not put inside it, and are asked about as before."""
    _system(monkeypatch, **WALLED)
    r = sandbox.reach("python", fetched=True)
    assert (r["network"], r["files"]) == (PYTHON_ONLY, HELD), r
    assert r["ask"] == sandbox.WALL_ASK and r["words"].endswith(r["ask"]), r
    assert "Python code in the tests has no way out" in r["words"] and "Nothing leaves" not in r["words"], r
    assert "read and change the files" not in r["ask"] and "not every way" in r["ask"], r
    for language, fetched in (("python", False), ("node", True), ("go", True)):
        other = sandbox.reach(language, fetched=fetched)
        assert "wall" not in other["ask"] and "read and change the files" in other["ask"], (language, other)
    _system(monkeypatch, **{**WALLED, "wall": False})       # the twin: the same Windows where no wall is made
    r = sandbox.reach("python", fetched=True)
    assert (r["network"], r["files"]) == (PYTHON_ONLY, PYTHON_ONLY) and "read and change the files" in r["ask"], r


def test_where_windows_makes_a_wall_the_list_says_so_for_those_tests_alone(tmp_path, monkeypatch,
                                                                          pystore):  # noqa: F811
    _online(monkeypatch, python=pystore)
    py = _py_project(tmp_path / "fetching")
    js, _ = _projects(tmp_path)
    _system(monkeypatch, **WALLED)
    listed = sandbox.describe(py, "python")["details"]
    assert sandbox.WALL_LINE in listed and sandbox.WALL_BESIDE in listed, listed
    assert not any("is not kept from the network by this run" in line for line in listed), listed
    for repo, language in ((js, "node"), (_projects_plain(tmp_path), "python")):
        listed = sandbox.describe(repo, language)["details"]
        assert sandbox.WALL_LINE not in listed and sandbox.WALL_BESIDE not in listed, (language, listed)


def _projects_plain(tmp_path) -> Path:
    """A Python project that names no library: its tests run on this computer's Python, outside the wall."""
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "test_it.py").write_text("def test_it():\n    pass\n", encoding="utf-8")
    return plain


def test_where_windows_makes_a_wall_the_app_asks_for_the_walls_sentence_before_such_tests(srv, tmp_path,  # noqa: F811
                                                                                         monkeypatch, started,
                                                                                         pystore):  # noqa: F811
    """The sheet, the route and the terminal decide alike whether the libraries are fetched (`server.fetches`),
    so the sentence the person agrees to is the one the run keeps."""
    base, store = srv
    _online(monkeypatch, python=pystore)
    py = _py_project(tmp_path / "fetching")
    pid = _added(base, py)
    _system(monkeypatch, **WALLED)
    code, d = call(base, f"/api/projects/{pid}/testcmd")
    walled = sandbox.reach("python", fetched=True)
    assert code == 200 and d["reach"]["ask"] == sandbox.WALL_ASK and d["leaves"] == walled["words"], d
    trace = f"/api/projects/{pid}/trace"
    for said in (sandbox.reach("python")["ask"], True):           # the sentence of a run outside the wall is none
        code, e = call(base, trace, "POST", {"command": d["command"], "confirm": True, "reach": said})
        assert code == 409 and sandbox.WALL_ASK in e["error"] and not started, e
    code, j = call(base, trace, "POST", {"command": d["command"], "confirm": True, "reach": sandbox.WALL_ASK})
    assert code == 202 and wait(base, j["id"])["status"] == "done" and len(started) == 1, j
