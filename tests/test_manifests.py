"""A file that parses and has the wrong shape costs a fact, never the analysis (2026-11-10, directive stage 7, part 3).

A project's own files come with the project: `"dependencies": "x"` in package.json, `paths = 5` in tsconfig.json, a
list where pyproject.toml's `[project]` belongs. Each is valid JSON or TOML. Until this date such a file ended
`lantern analyze` with a Python error: `bench/manifests.py` counts how many on the code before (the numbers are in
its first lines). A result file that an earlier run left cut off (the computer was switched off while it was written)
did the same to every later run of that folder.

The sweep itself is too slow for every CI run (11,652 whole analyses). Here are:
  * FOUND: for each line of code the sweep stopped at, values that stopped it. With the fix none of them does;
  * the top level of every file in four other shapes, so a new reader that trips at once is caught here;
  * the safe twins: the same files as they should be still give their facts, and an odd value beside good ones
    costs only its own fact;
  * earlier result files that are cut off, empty, not text, a link, a pipe or a folder, and the twin that is whole;
  * the sweep's own answer: 0 when nothing stops, 1 when a reader is made to stop again.

Nothing here reaches the network (the sweep runs offline; Bandit, another program that reads none of these files, is
left out of it).
"""
import json
import os
import sys
import threading
from pathlib import Path

import pytest

from lantern import evidence, pipeline, results, security

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))
import manifests as sweep  # noqa: E402  (bench/manifests.py)

OLD_RESULTS = Path(__file__).parent / "fixtures" / "old_results"
Y = {"x": ["y"]}
NUL = "a\x00b"
# key of sweep.KINDS -> (the place in the file, the value put there). Each stopped the analysis on the code before.
FOUND = {
    "js:package.json": [((), []), ((), [{"x": 1}]), (("dependencies",), "x"), (("dependencies",), ["x"]),
                        (("devDependencies",), [{"x": 1}]), (("dependencies",), 5)],
    "js:tsconfig.json": [((), []), ((), [{"x": 1}]), (("compilerOptions",), "x"), (("compilerOptions",), [{"x": 1}]),
                         (("compilerOptions", "paths"), "x"), (("compilerOptions", "paths"), [{"x": 1}]),
                         (("compilerOptions", "baseUrl"), []), (("compilerOptions", "baseUrl"), Y),
                         (("compilerOptions", "baseUrl"), 5), (("compilerOptions", "paths"), {"x": 1}),
                         (("compilerOptions", "paths", "~lib", 0), Y), (("compilerOptions", "paths", "@/*"), "x"),
                         (("compilerOptions",), None),
                         # texts where a text belongs: a NUL in a path, and the root folder, which has no name
                         (("compilerOptions", "baseUrl"), NUL), (("compilerOptions", "paths", "@/*", 0), NUL),
                         (("compilerOptions", "paths", "~lib", 0), NUL), (("compilerOptions", "paths", "@/*", 0), "/"),
                         (("compilerOptions", "paths", "@/*"), "../../../outside")],
    "js:app.json": [(("expo",), []), (("expo",), [{"x": 1}]), (("expo", "android", "permissions"), 5),
                    (("expo", "android", "permissions"), True), (("expo", "android"), "x"), (("expo", "ios"), [5]),
                    (("expo", "scheme"), {"x": 1})],
    "py:pyproject.toml": [(("project",), "x"), (("project",), [{"x": 1}]), (("tool",), "x"), (("tool", "poetry"), [{"x": 1}]),
                          (("tool", "poetry", "dependencies"), "x"), (("tool", "poetry", "dependencies"), [{"x": 1}]),
                          (("project", "scripts"), {"x": 1}), (("tool", "poetry", "scripts", "app"), Y),
                          (("project", "optional-dependencies"), "x"), (("project", "optional-dependencies"), [{"x": 1}]),
                          (("dependency-groups",), "x"), (("dependency-groups",), [{"x": 1}]),
                          (("tool", "poetry", "dependencies"), []), (("tool", "poetry", "dependencies"), 0),
                          (("project", "dependencies"), 5), (("project", "dependencies"), True)],
    "py:Pipfile": [(("packages",), "x"), (("dev-packages",), [{"x": 1}]), (("packages",), 5)],
    "py:notebook.ipynb": [(("cells", 0, "outputs", 1, "data"), "x"), (("cells", 0, "outputs", 1, "data"), [{"x": 1}]),
                          (("cells", 0, "source"), [5]), (("cells", 1, "source"), [{"x": 1}]), (("cells", 0, "outputs"), 5),
                          (("cells", 0, "outputs"), True), (("cells", 0, "outputs", 0, "text"), [5]),
                          (("cells", 0, "outputs", 1, "data", "text/plain", 0), Y)],
    "any:lantern-accepted.json": [(("accepted",), 5), (("accepted", 0, "id"), Y), (("accepted",), "x"), ((), [5])],
    "any:lantern-packs": [(("entries", 0, "detail"), ""), (("requires", "files"), [5]), (("requires", "files", 0), Y),
                          (("rules", 0, "id"), []), (("rules", 0, "id"), Y), (("requires", "text"), [5]),
                          (("requires", "text", 0), Y), (("rules", 0, "fix"), 5), (("rules", 0, "more"), Y),
                          (("rules", 0, "category"), [5]), (("about",), 5), (("rules", 0, "severity"), [])],
    "py:uv.lock": [(("package",), "x"), (("package", 1), [{"x": 1}]), (("package", 0, "name"), 5), (("package", 0, "name"), Y),
                   (("package",), 5), (("package",), True)],
    "py:Pipfile.lock": [((), []), (("default",), [{"x": 1}]), (("default", "flask", "version"), []),
                        (("default", "flask", "version"), Y)],
    "php:composer.lock": [((), []), ((), [{"x": 1}]), (("packages",), 5), (("packages",), True)],
    "jv:libs.versions.toml": [(("versions",), "x"), (("versions",), [{"x": 1}]), (("libraries",), "x"),
                              (("libraries",), [{"x": 1}]), (("libraries", "gson", "module"), ["x"]),
                              (("libraries", "gson", "module"), Y), (("libraries", "gson", "version", "ref"), []),
                              (("libraries", "gson", "version", "ref"), Y), (("libraries", "gson", "module"), 5),
                              (("libraries", "gson", "module"), True)],
    "out:security.json": [((), "x"), ((), [{"x": 1}]), (("findings",), "x"), (("findings", 0), [{"x": 1}]), (("findings",), 5),
                          (("findings", 0, "id"), Y)],
    "out:baseline.json": [(("findings",), "x"), (("findings",), [5]), (("findings",), {"x": 1}),
                          (("findings", "0000000000aa"), [{"x": 1}]), (("counts",), "x"), (("counts",), [{"x": 1}]),
                          ((), "x"), ((), [{"x": 1}]), ((), []), ((), 0), (("findings",), {"x": {"y": 1}}),
                          (("findings", "0000000000aa"), Y), (("findings", "0000000000aa", "rule"), []),
                          (("findings", "0000000000aa", "file"), Y), (("findings",), 5), (("findings",), [{"x": 1}]),
                          (("readiness",), "x"), (("readiness", "categories"), [5]), (("counts", "high"), "x"),
                          (("date",), 5), (("commit",), Y)],
    "out:explanations.json": [((), "x"), ((), [{"x": 1}]), (("stats",), "x"), (("stats",), [{"x": 1}]),
                              (("explanations",), {"x": 1}), (("explanations", "py:app.run"), [{"x": 1}]),
                              (("explanations",), []), (("explanations",), [{"x": 1}]), (("metaphor",), 5),
                              (("explanations",), None)],
}


def _odd(project, at, value) -> str:
    return sweep.text_of(sweep.swapped(project.tree, at, value), project.kind.fmt)


def _read(project, name: str):
    return json.loads((project.out / name).read_text(encoding="utf-8"))


def _entries(project) -> dict:
    return {n["id"]: n["entry"] for n in _read(project, "graph.json")["nodes"] if n.get("entry")}


def _calls_from(project, start: str) -> set:
    return {e["dst"] for e in _read(project, "graph.json")["edges"] if e["src"] == start}


def _check(project, check_id: str) -> dict:
    return next(ch for c in _read(project, "readiness.json")["categories"] for ch in c["checks"] if ch["id"] == check_id)


# ------------------------------------------------------------------------------- what the sweep found

@pytest.mark.parametrize("key", sorted(FOUND))
def test_the_values_the_sweep_found_no_longer_stop_the_analysis(key, tmp_path):
    project = sweep.Project(key, tmp_path)
    assert project.stops(None) is None, "the file as it should be"
    stopped = {}
    for at, value in FOUND[key]:
        text = _odd(project, at, value)
        assert text is not None, (at, value)
        where = project.stops(text)
        if where:
            stopped[f"{sweep.name_of(at)} = {json.dumps(value)}"] = where
    assert stopped == {}


TOP = ["x", 5, [5], {"x": 1}]
STRUCTURED = sorted(k for k, kind in sweep.KINDS.items() if kind.group != "text")


@pytest.mark.parametrize("key", STRUCTURED)
def test_the_top_level_of_every_file_in_four_other_shapes(key, tmp_path):
    """The file's top, and each value one key down, as a word, a number, a list and a table."""
    result = sweep.sweep(key, tmp_path, replacements=TOP, depth=1)
    assert result["runs"] >= 3 and result["finds"] == {}, result["finds"]


# ------------------------------------------------------------------------------- the safe twins

def test_a_web_project_as_it_should_be_gives_every_fact_its_files_hold(tmp_path):
    project = sweep.Project("js:package.json", tmp_path)
    project.run()
    entries = _entries(project)
    assert entries["js:pages/index::Home"]["kind"] == "page"                  # package.json: depends on next
    assert entries["js:pages/api/items::handler"]["kind"] == "route"
    assert entries["js:server::get_api_items"]["detail"] == "GET /api/items"  # package.json: depends on express
    assert entries["js:app/index::Start"]["detail"].startswith("LINK ")       # app.json: a scheme other apps can open
    meta = _read(project, "graph.json")["meta"]
    assert meta["platform"] == "react-native" and meta["rn"]["apps"][0]["config"] == "app.json"
    called = _calls_from(project, "js:src/App::App")
    assert "js:src/lib/helper::helper" in called     # `@/lib/helper`
    assert "js:src/lib/other::other" in called       # `~lib`, which only tsconfig.json's paths know
    rules = sorted(f["rule"] for f in _read(project, "security.json")["findings"] if f["file"] == "app.json")
    assert rules == ["LN-ATS-OFF", "LN-BACKUP", "LN-UNUSED-PERMISSION", "LN-UNUSED-PERMISSION", "LN-URL-SCHEME"]
    assert _check(project, "deps-pinned")["status"] == "pass"


def test_a_python_project_as_it_should_be_gives_every_fact_its_files_hold(tmp_path):
    project = sweep.Project("py:pyproject.toml", tmp_path)
    project.run()
    assert _entries(project)["py:app.run"] == {"kind": "script", "detail": "app"}     # [project.scripts]
    said = _check(project, "deps-pinned")["evidence"]
    assert "pyproject.toml: bandit" in said and "not a table" not in said

    project = sweep.Project("py:notebook.ipynb", tmp_path / "notebook")
    project.run()
    sec = _read(project, "security.json")
    assert sec["ai"]["notebooks"] == [{"file": "notes/try.ipynb", "code_cells": 1, "ai": ["model"], "secrets": 0}]
    assert _entries(project)["py:app.run"]["detail"] == "ANY /run"                    # the project's own pack
    assert [(f["rule"], f["status"]) for f in sec["findings"]] == [("LP-MINE-SYSTEM", "open")]

    project = sweep.Project("any:lantern-accepted.json", tmp_path / "accepted")
    project.run()
    finding, = _read(project, "security.json")["findings"]
    assert finding["status"] == "accepted"
    assert finding["accepted"] == {"reason": "known and reviewed by the team", "by": "me", "date": "2026-11-01"}


# ------------------------------------------------------------------------------- an odd value costs its own fact

def test_an_odd_part_of_package_json_costs_that_part_only(tmp_path):
    project = sweep.Project("js:package.json", tmp_path)
    project.write(_odd(project, ("devDependencies",), "x"))
    project.run()
    assert _entries(project)["js:pages/index::Home"]["kind"] == "page"        # `dependencies` is still read
    check = _check(project, "deps-pinned")
    assert check["status"] == "fail"
    assert check["evidence"] == "package.json: its devDependencies are not a table, so the versions there were not checked"

    project.write(_odd(project, ("dependencies",), ["next"]))                 # now nothing says the project uses Next.js
    project.run()
    assert "js:pages/index::Home" not in _entries(project)
    assert "its dependencies are not a table" in _check(project, "deps-pinned")["evidence"]


def test_an_odd_alias_in_tsconfig_costs_that_alias_only(tmp_path):
    project = sweep.Project("js:tsconfig.json", tmp_path)
    project.write(_odd(project, ("compilerOptions", "paths", "@/*"), 5))
    project.run()
    called = _calls_from(project, "js:src/App::App")
    assert "js:src/lib/other::other" in called and "js:src/lib/helper::helper" not in called

    for target in (NUL, "/", "x" * 5000, "../../../outside"):                 # a text that is no place in the project
        project.write(_odd(project, ("compilerOptions", "paths", "@/*", 0), target))
        project.run()
        called = _calls_from(project, "js:src/App::App")
        assert "js:src/lib/other::other" in called and "js:src/lib/helper::helper" not in called, target[:20]

    project.write(_odd(project, ("compilerOptions", "baseUrl"), NUL))         # the whole file is passed over, and the
    project.run()                                                             # `@/` every project has still works
    called = _calls_from(project, "js:src/App::App")
    assert "js:src/lib/helper::helper" in called and "js:src/lib/other::other" not in called


def test_an_odd_part_of_app_json_costs_that_part_only(tmp_path):
    project = sweep.Project("js:app.json", tmp_path)
    project.write(_odd(project, ("expo", "android", "permissions"), 5))
    project.run()
    rules = sorted(f["rule"] for f in _read(project, "security.json")["findings"] if f["file"] == "app.json")
    assert rules == ["LN-ATS-OFF", "LN-BACKUP", "LN-URL-SCHEME"]

    project.write(_odd(project, ("expo", "android", "permissions"), ["CAMERA", 5, Y]))   # the one text among them counts
    project.run()
    rules = sorted(f["rule"] for f in _read(project, "security.json")["findings"] if f["file"] == "app.json")
    assert rules == ["LN-ATS-OFF", "LN-BACKUP", "LN-UNUSED-PERMISSION", "LN-URL-SCHEME"]


def test_an_odd_part_of_pyproject_costs_that_part_only(tmp_path):
    project = sweep.Project("py:pyproject.toml", tmp_path)
    project.write(_odd(project, ("project", "scripts"), {"app": "app:run", "bad": 5, "worse": ["x"], "none": "nothing:here"}))
    project.run()
    assert _entries(project)["py:app.run"] == {"kind": "script", "detail": "app"}

    project.write(_odd(project, ("project",), "x"))                           # [tool.poetry] still says what it says
    project.run()
    assert _entries(project)["py:app.run"] == {"kind": "script", "detail": "app"}        # [tool.poetry.scripts]
    said = _check(project, "deps-pinned")["evidence"]
    assert said.startswith("pyproject.toml: its [project] is not a table, so the versions there were not checked")
    assert "pyproject.toml: pytest" in said                                   # [dependency-groups] was still read


def test_an_odd_cell_of_a_notebook_costs_that_cell_only(tmp_path):
    project = sweep.Project("py:notebook.ipynb", tmp_path)
    cells = [{"cell_type": "code", "source": [5], "outputs": 5}, 5, "x",
             {"cell_type": "code", "source": "client.chat.completions.create(model='m', messages=[])\n", "outputs": [Y]}]
    project.write(_odd(project, ("cells",), cells))
    project.run()
    assert _read(project, "security.json")["ai"]["notebooks"] == [
        {"file": "notes/try.ipynb", "code_cells": 2, "ai": ["model"], "secrets": 0}]


def test_an_odd_row_of_the_accepted_risks_accepts_nothing_and_the_good_row_still_counts(tmp_path):
    project = sweep.Project("any:lantern-accepted.json", tmp_path)
    good = project.tree["accepted"][0]
    project.write(_odd(project, ("accepted",), [5, "x", {"id": 5, "reason": good["reason"]}, {"id": Y}, good]))
    project.run()
    finding, = _read(project, "security.json")["findings"]
    assert finding["status"] == "accepted" and finding["accepted"]["reason"] == good["reason"]

    project.write(_odd(project, ("accepted",), [dict(good, reason=5), dict(good, reason=["because"])]))
    project.run()
    finding, = _read(project, "security.json")["findings"]
    assert finding["status"] == "open" and not finding.get("accepted")        # no written reason, nothing accepted

    project.write(_odd(project, ("accepted", 0, "by"), Y))                    # an odd name beside a real reason
    project.run()
    finding, = _read(project, "security.json")["findings"]
    assert finding["status"] == "accepted" and finding["accepted"]["by"] is None


def test_a_pack_with_an_odd_part_is_refused_by_name_and_the_analysis_goes_on(tmp_path):
    project = sweep.Project("any:lantern-packs", tmp_path)
    project.run()
    assert [f["rule"] for f in _read(project, "security.json")["findings"]] == ["LP-MINE-SYSTEM"]

    for at, value, why in ((("rules", 0, "fix"), 5, "`fix` is a string"), (("about",), 5, "`about` must be a string"),
                           (("requires", "files"), [5], "`requires` must be an object"),
                           (("rules", 0, "id"), [], "`id` must look like LP-NAME")):
        project.write(_odd(project, at, value))
        project.run()
        sec = _read(project, "security.json")
        assert sec["findings"] == [], at                                      # none of its rules ran
        row, = [t for t in sec["tools"] if t["tool"] == "project pack mine.json"]
        assert row["status"].startswith("skipped: ") and why in row["status"], row


def test_a_pack_entry_that_leaves_the_optional_detail_out_is_a_route_with_words(tmp_path):
    """Before, such an entry gave a route with no words at all, and the step that links pages to routes stopped."""
    project = sweep.Project("any:lantern-packs", tmp_path)
    entry = {k: v for k, v in project.tree["entries"][0].items() if k != "detail"}
    assert security is not None and project.stops(_odd(project, ("entries", 0), entry)) is None
    route = _entries(project)["py:app.run"]
    assert route["kind"] == "route" and route["via"] == "pack:mine"
    assert isinstance(route["detail"], str) and route["detail"]


# ------------------------------------------------------------------------------- what an earlier run left

def _analyze(project) -> list[str]:
    """`lantern analyze` on the tiny project (no Bandit, offline); the lines it logged."""
    said: list[str] = []
    real = security.run_bandit
    security.run_bandit = project._bandit
    try:
        pipeline.analyze(project.repo, project.out, offline=True, log=said.append)
    finally:
        security.run_bandit = real
    return said


def _earlier(said: list[str]) -> list[str]:
    return [line for line in said if line.startswith("earlier ")]


DAMAGE = {
    "cut off": lambda good: good[: len(good) // 2],
    "empty": lambda good: b"",
    "not text": lambda good: b"\xff\xfe\x00{" + good,
    "nothing": lambda good: b"null",
    "a list": lambda good: b"[" + good + b"]",
    "another shape": lambda good: json.dumps({k: [5] for k in json.loads(good)}).encode(),
}
SAID = {"cut off": results.CUT_OFF, "empty": results.CUT_OFF, "not text": "it is not text", "nothing": results.NOT_OURS,
        "a list": results.NOT_OURS, "another shape": results.NOT_OURS + ": its "}


@pytest.fixture(scope="module")
def whole(tmp_path_factory):
    """A results folder after a run, with the three files an earlier run leaves, each as it should be."""
    project = sweep.Project("out:explanations.json", tmp_path_factory.mktemp("whole"))
    _analyze(project)
    project.kind, project.tree = sweep.KINDS["out:baseline.json"], None
    tree = json.loads(json.dumps(sweep.BASELINE).replace("FINDING", _read(project, "security.json")["findings"][0]["id"])
                      .replace('"IDS"', json.dumps(security.ID_VERSION)))
    (project.out / "baseline.json").write_text(json.dumps(tree), encoding="utf-8")
    return project


def _copy(whole, tmp_path):
    """A fresh copy of the whole project and its results, so that one test's damage is not the next one's."""
    import shutil
    shutil.copytree(whole.repo, tmp_path / "repo")
    shutil.copytree(whole.out, tmp_path / "out")
    project = sweep.Project.__new__(sweep.Project)
    project.__dict__.update(whole.__dict__)
    project.repo, project.out = tmp_path / "repo", tmp_path / "out"
    return project


def test_whole_earlier_results_are_used(whole, tmp_path):
    project = _copy(whole, tmp_path)
    said = _analyze(project)
    assert _earlier(said) == []
    finding, = _read(project, "security.json")["findings"]
    reproduced, = [row for row in finding["case"]["status"] if row["word"] == "reproduced"]
    assert reproduced["done"] is True                                         # security.json and baseline.json
    record = _read(project, "evidence.json")
    assert [f["title"] for f in record["security"]["fixed"]] == ["gone since"]            # baseline.json
    assert record["scorecard"]["baseline_date"] == "2026-11-01"
    assert [m["model"] for m in record["provenance"]["models"]] == ["stand-in/model"]     # explanations.json
    assert not any("baseline.json" in line for line in record["limits"])


def _seen_again(project):
    finding, = _read(project, "security.json")["findings"]
    row, = [row for row in finding["case"]["status"] if row["word"] == "reproduced"]
    return row["done"]


def test_the_run_before_alone_says_that_a_finding_was_seen_again(whole, tmp_path):
    """A finding the first analysis had not met yet is known from the run before (`security.json`) and from nothing
    else, and only while both runs name their findings the same way. Every other test here has the finding in the
    baseline as well, which hid a mistake in either of these two lines."""
    project = _copy(whole, tmp_path)
    base = _read(project, "baseline.json")
    base["findings"] = {k: v for k, v in base["findings"].items() if v["title"] == "gone since"}
    (project.out / "baseline.json").write_text(json.dumps(base), encoding="utf-8")
    assert _earlier(_analyze(project)) == [] and _seen_again(project) is True
    sec = _read(project, "security.json")                                     # the twin: a run that named findings another way
    sec["id_version"] = "another way"
    (project.out / "security.json").write_text(json.dumps(sec), encoding="utf-8")
    assert _earlier(_analyze(project)) == [] and _seen_again(project) is False
    (project.out / "security.json").unlink()                                  # and no run before at all: the baseline only
    (project.out / "baseline.json").unlink()
    _analyze(project)
    assert _seen_again(project) is None                                       # a first run has nothing to compare with


@pytest.mark.parametrize("name", sorted(results.SHAPES))
@pytest.mark.parametrize("how", sorted(DAMAGE))
def test_an_earlier_result_file_that_cannot_be_used_is_passed_over_and_said(whole, tmp_path, name, how):
    project = _copy(whole, tmp_path)
    damaged = DAMAGE[how]((project.out / name).read_bytes())
    (project.out / name).write_bytes(damaged)
    assert results.earlier(project.out, name)[0] is None
    assert results.earlier(project.out, name)[1].startswith(SAID[how])

    said = _analyze(project)                                                  # the run finishes
    line, = _earlier(said)
    assert line.startswith(f"earlier {name}") and SAID[how] in line
    record = _read(project, "evidence.json")
    finding, = _read(project, "security.json")["findings"]                    # written anew, whatever was there
    assert finding["rule"] == "LP-MINE-SYSTEM"
    if name == "security.json":
        assert [f["title"] for f in record["security"]["fixed"]] == ["gone since"]        # the baseline still counts
    elif name == "baseline.json":
        assert (project.out / name).read_bytes() == damaged                   # left as it is: not compared, not replaced
        assert record["security"]["fixed"] == [] and record["scorecard"]["before"] is None
        limit, = [x for x in record["limits"] if "baseline.json" in x]
        assert SAID[how] in limit and "--reset-baseline" in limit
        assert "baseline.json" in (project.out / "evidence.html").read_text(encoding="utf-8")
    else:
        assert (project.out / name).read_bytes() == damaged
        assert record["provenance"]["models"] == []
        assert (project.out / "report.html").is_file()


def test_a_baseline_that_cannot_be_used_stays_until_the_person_starts_a_new_one(whole, tmp_path, capsys):
    from lantern import cli
    project = _copy(whole, tmp_path)
    (project.out / "baseline.json").write_text("<<<<<<< ours\n{}\n=======\n{}\n>>>>>>> theirs\n", encoding="utf-8")
    _analyze(project)
    _analyze(project)                                                         # as often as it is run
    assert (project.out / "baseline.json").read_text(encoding="utf-8").startswith("<<<<<<< ours")
    assert cli.main(["evidence", str(project.repo), "--out", str(project.out), "--reset-baseline"]) == 0
    base = _read(project, "baseline.json")
    assert results.baseline_shape(base) is None and list(base["findings"].values())[0]["rule"] == "LP-MINE-SYSTEM"
    assert not any("baseline.json" in x for x in _read(project, "evidence.json")["limits"])
    assert _earlier(_analyze(project)) == []


only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (symbolic links, pipes)")
KEPT_NAMES = ("baseline.json", "explanations.json")     # the two earlier files `analyze` reads and does not write anew


@only_posix
@pytest.mark.parametrize("name", KEPT_NAMES)
def test_a_link_under_a_result_files_name_is_not_read(whole, tmp_path, name):
    """The results folder lies inside the analysed project by default, so a link in it may have come with the project:
    what it points at is not read, although it is a whole result file here."""
    project = _copy(whole, tmp_path)
    kept = tmp_path / "elsewhere.json"
    (project.out / name).replace(kept)
    os.symlink(kept, project.out / name)
    assert results.earlier(project.out, name) == (None, "it is a link, and Lantern does not read its results through a link")
    line, = [x for x in _earlier(_analyze(project)) if x.startswith(f"earlier {name}")]
    assert "it is a link" in line
    assert (project.out / name).is_symlink() and json.loads(kept.read_text(encoding="utf-8"))   # both left as they were


@pytest.mark.parametrize("name", KEPT_NAMES)
def test_a_folder_under_a_result_files_name_is_not_read(whole, tmp_path, name):
    project = _copy(whole, tmp_path)
    (project.out / name).unlink()
    (project.out / name).mkdir()
    assert results.earlier(project.out, name) == (None, "it is not a plain file")
    line, = [x for x in _earlier(_analyze(project)) if x.startswith(f"earlier {name}")]
    assert "it is not a plain file" in line and (project.out / name).is_dir()


def _into(done: list, project) -> None:
    done.append(_earlier(_analyze(project)))


@only_posix
@pytest.mark.parametrize("name", KEPT_NAMES)
def test_a_pipe_under_a_result_files_name_does_not_hold_the_run_up(whole, tmp_path, name):
    """Opening a pipe nobody writes to never comes back: a run that tried would wait for good."""
    project = _copy(whole, tmp_path)
    (project.out / name).unlink()
    os.mkfifo(project.out / name)
    done: list = []
    run = threading.Thread(target=_into, args=(done, project), daemon=True)
    run.start()
    run.join(60)
    try:
        assert done, "the run is still waiting for the pipe"
        assert any(x.startswith(f"earlier {name}") and "it is not a plain file" in x for x in done[0])
    finally:
        if not done:                                                          # let the waiting read go, whatever the result
            os.close(os.open(project.out / name, os.O_WRONLY | os.O_NONBLOCK))


def test_a_result_file_larger_than_the_limit_is_not_read(whole, tmp_path, monkeypatch):
    project = _copy(whole, tmp_path)
    monkeypatch.setattr(results, "MAX_BYTES", (project.out / "baseline.json").stat().st_size - 1)
    assert results.earlier(project.out, "baseline.json") == (None, "it is larger than 0 MB")
    monkeypatch.setattr(results, "MAX_BYTES", (project.out / "baseline.json").stat().st_size)
    assert results.earlier(project.out, "baseline.json")[1] is None           # the twin: just small enough


def test_every_baseline_lantern_has_written_is_let_through(tmp_path):
    """The shape check must not turn a real baseline away: the ones older releases wrote, and today's."""
    olds = sorted(OLD_RESULTS.glob("*/baseline.json"))
    assert len(olds) >= 2
    for p in olds:
        assert results.earlier(p.parent, "baseline.json")[1] is None, p
        assert results.earlier(p.parent, "security.json")[1] is None, p
    sec = json.loads((olds[-1].parent / "security.json").read_text(encoding="utf-8"))
    rd = json.loads((olds[-1].parent / "readiness.json").read_text(encoding="utf-8"))
    assert results.baseline_shape(evidence.baseline_from(sec, "0123abc", rd)) is None
    assert results.baseline_shape(evidence.baseline_from(sec, None, None)) is None
    assert results.baseline_shape(evidence.baseline_from(None, None, None)) is None
    assert results.earlier(tmp_path, "baseline.json") == (None, None)         # no file at all is not a problem


GOOD = {
    "baseline.json": {"id_version": 3, "date": "2026-11-01", "commit": "0123abc", "counts": {"critical": 1, "high": 0},
                      "readiness": {"score": 71, "grade": "C", "categories": {"security": 0.5, "tests": None}},
                      "findings": {"F1": {"rule": "LP-X", "rank": "critical", "title": "t", "file": "app.py", "line": 3}}},
    "security.json": {"id_version": 3, "findings": [{"id": "F1", "rule": "LP-X"}], "tools": []},
    "explanations.json": {"explanations": {"py:app.run": {"lens2": "words"}}, "stats": {"asked": 1},
                          "metaphor": {"world": "kitchen"}},
}
A_FINDING = "one of its findings is not a rule, a rank, a title, a file and a line"
SCORE = "its readiness is not a score and a grade"
ONE_CHANGE = [  # (file, where, the value put there, what the check then says: None when the file is still taken)
    ("baseline.json", ("id_version",), [3], "its id_version is not a number"),
    ("baseline.json", ("id_version",), True, "its id_version is not a number"),
    ("baseline.json", ("id_version",), "3", None),
    ("baseline.json", ("id_version",), None, None),
    ("baseline.json", ("date",), 20261101, "its date is not text"),
    ("baseline.json", ("date",), None, None),
    ("baseline.json", ("commit",), ["0123abc"], "its commit is not text"),
    ("baseline.json", ("commit",), None, None),
    ("baseline.json", ("counts",), [1, 0], "its counts are not numbers"),
    ("baseline.json", ("counts", "critical"), "1", "its counts are not numbers"),
    ("baseline.json", ("counts", "critical"), True, "its counts are not numbers"),
    ("baseline.json", ("counts", "critical"), 1.0, None),
    ("baseline.json", ("counts",), None, None),
    ("baseline.json", ("readiness",), "71", SCORE),
    ("baseline.json", ("readiness", "score"), "71", SCORE),
    ("baseline.json", ("readiness", "score"), False, SCORE),
    ("baseline.json", ("readiness", "grade"), 3, SCORE),
    ("baseline.json", ("readiness", "score"), None, None),
    ("baseline.json", ("readiness", "grade"), None, None),
    ("baseline.json", ("readiness",), None, None),
    ("baseline.json", ("readiness", "categories"), [0.5], "its readiness categories are not numbers"),
    ("baseline.json", ("readiness", "categories", "security"), "half", "its readiness categories are not numbers"),
    ("baseline.json", ("readiness", "categories"), None, None),
    ("baseline.json", ("findings",), ["F1"], "its findings are not a table"),
    ("baseline.json", ("findings",), None, None),
    ("baseline.json", ("findings",), {}, None),
    ("baseline.json", ("findings", "F1"), "LP-X", A_FINDING),
    ("baseline.json", ("findings", "F1", "rule"), None, A_FINDING),
    ("baseline.json", ("findings", "F1", "rank"), 1, A_FINDING),
    ("baseline.json", ("findings", "F1", "title"), ["t"], A_FINDING),
    ("baseline.json", ("findings", "F1", "file"), 5, A_FINDING),
    ("baseline.json", ("findings", "F1", "file"), None, None),
    ("baseline.json", ("findings", "F1", "line"), "3", A_FINDING),
    ("baseline.json", ("findings", "F1", "line"), True, A_FINDING),
    ("baseline.json", ("findings", "F1", "line"), None, None),
    ("security.json", ("findings",), {"F1": {}}, "its findings are not a list of findings with an id each"),
    ("security.json", ("findings", 0), "F1", "its findings are not a list of findings with an id each"),
    ("security.json", ("findings", 0, "id"), 7, "its findings are not a list of findings with an id each"),
    ("security.json", ("findings", 0, "id"), None, None),
    ("security.json", ("findings",), None, None),
    ("explanations.json", ("explanations",), ["words"], "its explanations are not a table of records"),
    ("explanations.json", ("explanations", "py:app.run"), "words", "its explanations are not a table of records"),
    ("explanations.json", ("explanations",), None, None),
    ("explanations.json", ("stats",), [1], "its stats is not a table"),
    ("explanations.json", ("stats",), None, None),
    ("explanations.json", ("metaphor",), "kitchen", "its metaphor is not a table"),
    ("explanations.json", ("metaphor",), None, None),
]


@pytest.mark.parametrize("name, where, value, said", ONE_CHANGE,
                         ids=[f"{n.split('.')[0]}:{'.'.join(map(str, w))}={json.dumps(v)}" for n, w, v, _s in ONE_CHANGE])
def test_one_value_of_the_wrong_kind_in_an_earlier_result_file(name, where, value, said, tmp_path):
    """Each thing the shape checks look at, one at a time, and next to it what a real file may hold there (a value
    left out, a number written with a point): the first is said, the second is taken."""
    assert results.SHAPES[name](GOOD[name]) is None
    tree = json.loads(json.dumps(GOOD[name]))
    at = tree
    for step in where[:-1]:
        at = at[step]
    at[where[-1]] = value
    assert results.SHAPES[name](tree) == said
    (tmp_path / name).write_text(json.dumps(tree), encoding="utf-8")            # and as `analyze` meets it: in a file
    assert results.earlier(tmp_path, name) == ((tree, None) if said is None else (None, f"{results.NOT_OURS}: {said}"))


# ------------------------------------------------------------------------------- the sweep's own answer

def test_the_sweep_answers_0_when_nothing_stops_and_1_when_a_reader_stops_again(tmp_path, monkeypatch, capsys):
    quick = ["--only", "any:lantern-accepted.json", "--depth", "1"]
    assert sweep.main([*quick, "--work", str(tmp_path / "a")]) == 0
    assert "0 stopped the analysis, at 0 line(s)" in capsys.readouterr().out

    def as_before(repo):                                                      # the reader as it was until 2026-11-10
        p = repo / security.ACCEPTED_FILE
        return {r["id"]: r for r in json.loads(p.read_text(encoding="utf-8")).get("accepted", [])} if p.exists() else {}

    monkeypatch.setattr(security, "load_accepted", as_before)
    assert sweep.main([*quick, "--work", str(tmp_path / "b"), "--json", str(tmp_path / "found.json")]) == 1
    said = capsys.readouterr().out
    # the place it names is the last line of Lantern's own code on the way: where the reader was called from
    assert "AttributeError at security.py:" in said and "stopped the analysis, at 1 line(s)" in said
    found = json.loads((tmp_path / "found.json").read_text(encoding="utf-8"))
    assert found["stopped"] >= 3 and found["runs"] == 63
    assert sweep.main(["--only", "no:such-file"]) == 2
