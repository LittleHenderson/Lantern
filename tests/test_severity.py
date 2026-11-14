"""Directive point 6, first half: an unknown path is not evidence of safety.

A finding keeps four facts apart (the tool's own severity, the tool's confidence, what the map says about who reaches
the line, the evidence) and one rank worked out from them. The rank goes UP when an entry point from outside reaches
the line and request data is not ruled out. It goes DOWN only on evidence that is written on the finding. That Lantern
found no path to a line is neither: the rank then stays at the tool's own severity, and the finding says the path is
not known. Each lowering here stands beside a deceptive near-miss that must not be lowered.
"""
from pathlib import Path

import pytest

import lantern_files
from lantern.engine import build_graph
from lantern.security import RANK_ORDER, rank, rank_reason, scan

FIXTURES = Path(__file__).parent / "fixtures"
FLOOR = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _scan(root: Path, files: dict[str, str]) -> list[dict]:
    return scan(build_graph(_write(root, files)), offline=True)["findings"]


# ------------------------------------------------------------------------------- no path found: nothing is lowered
# A helper nothing in the project calls. Lantern cannot say who runs it: a scheduler, another program, a framework
# that calls by name. Before this stage the rank was one step under the tool's severity "because nothing reaches it".

NO_PATH = {
    "a shell command built from a parameter (Bandit: high)":
        ("import subprocess\n\n\ndef clean(name):\n    subprocess.run('rm -rf ' + name, shell=True)\n", "B602", "high"),
    "text handed to eval (Bandit: medium)":
        ("def work_out(text):\n    return eval(text)\n", "B307", "medium"),
}


@pytest.mark.parametrize("case", sorted(NO_PATH))
def test_a_finding_no_path_was_found_to_keeps_the_tools_severity(tmp_path, case):
    code, rule, want = NO_PATH[case]
    f = next(f for f in _scan(tmp_path, {"jobs.py": code}) if f["rule"] == rule)
    assert f["reachable"] is None
    assert f["rank"] == want, (f["rank"], rank_reason(f))
    assert "rank_note" not in f                              # nothing lowered it, so nothing says it was lowered
    assert f["reachability"]["state"] == "unknown", f["reachability"]
    assert "not proof" in f["reachability"]["why"]
    why = rank_reason(f)
    assert "found no path" in why and "nothing in the map reaches it" not in why, why


def test_the_same_line_reached_from_a_route_with_request_data_is_raised_and_says_what_raised_it(tmp_path):
    fs = _scan(tmp_path, {"app.py": "import subprocess\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n\n"
                                    "@app.post('/clean')\ndef clean(name: str):\n"
                                    "    subprocess.run('rm -rf ' + name, shell=True)\n"})
    f = next(f for f in fs if f["rule"] == "B602")
    assert f["rank"] == "critical" and f["tool_severity"] == "HIGH"
    assert f["reachability"]["state"] == "reached" and f["reachability"]["kind"] == "route"
    assert f["rank_basis"][0] == {"step": "severity", "rank": "high", "why": f["rank_basis"][0]["why"]}
    assert [s["step"] for s in f["rank_basis"]] == ["severity", "raised"] and f["rank_basis"][-1]["rank"] == "critical"


def test_the_rank_rules_in_one_place():
    base = {"category": "code", "reachable": None}
    # the tool's severity is the floor: no path, a path from tests only, a path from a page
    assert rank({**base, "tool_severity": "HIGH"}) == "high"
    assert rank({**base, "tool_severity": "MEDIUM"}) == "medium"
    assert rank({**base, "tool_severity": "LOW"}) == "low"
    assert rank({**base, "tool_severity": "HIGH", "reachable": {"kind": "test"}}) == "high"
    assert rank({**base, "tool_severity": "MEDIUM", "reachable": {"kind": "page"}}) == "medium"
    # raised by who reaches it, as before
    assert rank({**base, "tool_severity": "HIGH", "reachable": {"kind": "route"}}) == "critical"
    assert rank({**base, "tool_severity": "MEDIUM", "reachable": {"kind": "route"}}) == "high"
    # a route reaches it and the line was seen to use no request data: not raised, and not lowered either
    assert rank({**base, "tool_severity": "HIGH", "reachable": {"kind": "route"}, "input": False}) == "high"
    assert rank({"category": "secret", "tool_severity": "HIGH", "reachable": None}) == "critical"


# ---------------------------------------------------------------------------- reached by the test suite only
def test_code_only_the_test_suite_reaches_is_not_lowered_for_that(tmp_path):
    fs = _scan(tmp_path, {"jobs.py": NO_PATH["a shell command built from a parameter (Bandit: high)"][0],
                          "tests/test_jobs.py": "from jobs import clean\n\n\ndef test_clean():\n    clean('x')\n"})
    f = next(f for f in fs if f["rule"] == "B602")
    assert f["reachable"] is None and f["reachable_from_tests_only"] is True
    assert f["rank"] == "high" and "rank_note" not in f
    assert f["reachability"]["state"] == "tests-only"
    assert "not proof" in f["reachability"]["why"]


# ------------------------------------------------------------------- "test code", by its name or by who runs it
# A finding in a test file is ranked low and counted apart: users do not run the test suite. The file's NAME is the
# only evidence for that, and a name can deceive: a file called like a test that the app itself imports and runs.

APP_HEAD = "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n"
RUNS_IT = "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
NAMED_LIKE_A_TEST = {
    "lowered: a test file that only the tests run":
        ({"app.py": APP_HEAD + "@app.get('/ok')\ndef ok():\n    return 'ok'\n",
          "tests/test_tools.py": RUNS_IT + "\n\ndef test_run():\n    run('ls')\n"}, "tests/test_tools.py", True, "low"),
    "kept: a file named like a test that a route of the app runs with request data":
        ({"app.py": "from test_tools import run\n" + APP_HEAD + "@app.post('/run')\ndef go(cmd: str):\n    run(cmd)\n",
          "test_tools.py": RUNS_IT}, "test_tools.py", False, "critical"),
    "kept: a folder named tests that holds the app's own code":
        ({"app.py": "from tests.tools import run\n" + APP_HEAD + "@app.post('/run')\ndef go(cmd: str):\n    run(cmd)\n",
          "tests/__init__.py": "", "tests/tools.py": RUNS_IT}, "tests/tools.py", False, "critical"),
    "lowered: a test file with a small app of its own, which is still only test code":
        ({"app.py": APP_HEAD + "@app.get('/ok')\ndef ok():\n    return 'ok'\n",
          "tests/test_app.py": "import subprocess\nfrom fastapi import FastAPI\n\nfake = FastAPI()\n\n\n"
                               "@fake.post('/run')\ndef go(cmd: str):\n    subprocess.run(cmd, shell=True)\n"},
         "tests/test_app.py", True, "low"),
}


@pytest.mark.parametrize("case", sorted(NAMED_LIKE_A_TEST))
def test_a_finding_counts_as_test_code_by_who_runs_it_not_only_by_the_files_name(tmp_path, case):
    files, where, in_tests, want = NAMED_LIKE_A_TEST[case]
    res = scan(build_graph(_write(tmp_path, files)), offline=True)
    f = next(f for f in res["findings"] if f["rule"] == "B602" and f["file"] == where)
    assert f["in_tests"] is in_tests and f["rank"] == want, (f["in_tests"], f["rank"], f.get("reachable"))
    if not in_tests:
        assert res["counts"]["critical"] == 1 and res["counts"]["in_tests"] == 0
        assert "named like a test" in rank_reason(f)
    else:
        assert res["counts"]["critical"] == 0 and "Test code" in rank_reason(f)


# A guess by method name is no evidence of who runs a file. The app calls `.launch()` on something whose type
# Lantern cannot tell, and a class in a test file has a method `launch`: Lantern links the call to it by the name
# alone (the inventory's "name-only"). Counted as "the app runs this file", each test double of a project became
# the app's own code (on Lantern's own code: 12 findings in six of its test files, one of them high, 2026-11-11).
GUESSED = {
    "app.py": APP_HEAD + "@app.post('/run')\ndef go(worker, cmd: str):\n    return worker.launch(cmd)\n",
    "tests/test_tools.py": "import subprocess\n\n\nclass FakeWorker:\n    def launch(self, cmd):\n"
                           "        subprocess.run(cmd, shell=True)\n\n\ndef test_launch():\n    FakeWorker().launch('ls')\n",
}
# The near-miss: the same class, and the app makes one itself. That link is worked out, not guessed.
WORKED_OUT = {
    "app.py": "from tests.test_tools import FakeWorker\n" + APP_HEAD
              + "@app.post('/run')\ndef go(cmd: str):\n    return FakeWorker().launch(cmd)\n",
    "tests/__init__.py": "", "tests/test_tools.py": GUESSED["tests/test_tools.py"],
}


def test_a_guess_by_method_name_does_not_make_a_test_file_the_apps_own_code(tmp_path):
    res = scan(build_graph(_write(tmp_path / "guessed", GUESSED)), offline=True)
    f = next(f for f in res["findings"] if f["rule"] == "B602")
    assert f["in_tests"] is True and f["rank"] == "low" and "test_file_in_use" not in f, (f["rank"], f.get("reachable"))
    assert res["counts"]["critical"] == 0 and res["counts"]["high"] == 0
    # ... and the guess is not hidden: the reason says a call by name alone might lead here
    assert f["test_file_guessed"] is True
    assert "by its name alone" in rank_reason(f) and "guess" in rank_reason(f), rank_reason(f)

    res = scan(build_graph(_write(tmp_path / "worked", WORKED_OUT)), offline=True)
    f = next(f for f in res["findings"] if f["rule"] == "B602")
    assert f["in_tests"] is False and f["test_file_in_use"] is True and f["rank"] == "critical", (f["rank"], f.get("reachable"))
    assert "test_file_guessed" not in f


# What a project's own test run shows is no evidence of who runs a test file either (2026-11-13). While the tests
# run, the app's code calls what a test handed it: a stand-in put in the place of one of the app's functions, a
# callback, a double for one of its objects. The recording of the run has those calls, from the app's code into
# the test file, and until then each of them made the whole test file "the app's own code": after "Watch my tests
# run" on Lantern itself, 41 of its test files with 3,095 findings were counted as the app's code, 7 of them
# high, and the release decision read Blocked for them. The same findings with no test run: test code, all low.
SEEN_RUNNING = {
    "app.py": "import sys\n\nimport helpers\nfrom tests.test_kept import really_used\n\n\n"
              "def go(cmd):\n    return helpers.launch(cmd)\n\n\n"
              "def run(cmd, launch=None):\n    return (launch or helpers.launch)(cmd)\n\n\n"
              "def work(worker, cmd):\n    return worker.launch(cmd)\n\n\n"
              "def keep(cmd):\n    return really_used(cmd)\n\n\n"
              "if __name__ == '__main__':\n    go(sys.argv[1])\n    run(sys.argv[1])\n    work(None, sys.argv[1])\n"
              "    keep(sys.argv[1])\n",
    "helpers.py": "def launch(cmd):\n    return cmd\n",
    "tests/__init__.py": "",
    # a stand-in a test puts in the place of the app's own function
    "tests/test_stand_in.py": "import subprocess\n\nimport app\nimport helpers\n\n\n"
                              "def stand_in(cmd):\n    subprocess.run(cmd, shell=True)\n\n\n"
                              "def test_go(monkeypatch):\n    monkeypatch.setattr(helpers, 'launch', stand_in)\n"
                              "    app.go('echo ok')\n",
    # a callback a test hands the app
    "tests/test_callback.py": "import subprocess\n\nimport app\n\n\n"
                              "def test_run():\n    def launch(cmd):\n        subprocess.run(cmd, shell=True)\n\n"
                              "    app.run('echo ok', launch=launch)\n",
    # a double for one of the app's objects: the link is a guess by method name, and the run then saw it
    "tests/test_double.py": "import subprocess\n\nimport app\n\n\n"
                            "class FakeWorker:\n    def launch(self, cmd):\n        subprocess.run(cmd, shell=True)\n\n\n"
                            "def test_work():\n    app.work(FakeWorker(), 'echo ok')\n",
    # the twin that must stay the app's own code: the app itself loads this file, as its code says
    "tests/test_kept.py": "import subprocess\n\n\n"
                          "def really_used(cmd):\n    subprocess.run(cmd, shell=True)\n\n\n"
                          "def test_keep():\n    import app\n    app.keep('echo ok')\n",
}
HANDED_OVER = ("tests/test_stand_in.py", "tests/test_callback.py", "tests/test_double.py")


def test_what_the_tests_hand_the_app_while_they_run_does_not_make_a_test_file_the_apps_own_code(tmp_path):
    from lantern.trace import merge_trace, run_trace
    repo = _write(tmp_path, SEEN_RUNNING)
    by_file = lambda res: {f["file"]: f for f in res["findings"] if f["rule"] == "B602"}        # noqa: E731

    # with no test run: three test files, and the one the app loads
    res = scan(build_graph(repo), offline=True)
    before = by_file(res)
    assert sorted(before) == sorted([*HANDED_OVER, "tests/test_kept.py"]), sorted(before)
    assert all(before[name]["in_tests"] is True and before[name]["rank"] == "low" for name in HANDED_OVER)
    assert before["tests/test_kept.py"]["test_file_in_use"] is True and before["tests/test_kept.py"]["rank"] == "critical"
    assert res["counts"]["critical"] == 1 and res["counts"]["high"] == 0, res["counts"]

    # the same project after its tests ran and their calls were recorded
    g = build_graph(repo)
    data = run_trace(repo, ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    assert data["returncode"] == 0, data["stderr_tail"]
    merge_trace(g, data)
    links = {(e.src, e.dst): (e.confidence, e.via) for e in g.call_edges()}
    # the recording does hold the calls from the app into each test file
    assert links[("py:app.go", "py:tests.test_stand_in.stand_in")] == ("observed", "runtime-only")
    assert links[("py:app.run", "py:tests.test_callback.test_run.launch")] == ("observed", "runtime-only")
    assert links[("py:app.work", "py:tests.test_double.FakeWorker.launch")] == ("observed", "unique-method-name+observed")
    res = scan(g, offline=True)
    after = by_file(res)
    for name in HANDED_OVER:
        f = after[name]
        assert f["in_tests"] is True and f["rank"] == "low" and "test_file_in_use" not in f, (name, f["rank"], f.get("reachable"))
        # ... and what the run showed is not hidden: the reason says the tests handed it over
        assert f["test_file_stood_in"] is True and "test_file_guessed" not in f, name
        assert "while the tests ran" in rank_reason(f) and "handed" in rank_reason(f), rank_reason(f)
        assert f["rank_basis"][-1]["step"] == "test-code" and "handed" in f["rank_basis"][-1]["why"], f["rank_basis"]
    # the file the app's own code loads is the app's code, with the run as without it
    kept = after["tests/test_kept.py"]
    assert links[("py:app.keep", "py:tests.test_kept.really_used")][0] == "observed"
    assert kept["in_tests"] is False and kept["test_file_in_use"] is True and kept["rank"] == "critical", kept["rank"]
    assert "test_file_stood_in" not in kept and "named like a test" in rank_reason(kept)
    assert res["counts"]["critical"] == 1 and res["counts"]["high"] == 0, res["counts"]


# ------------------------------------------------------- every lowering is written down, on every sample app
SAMPLES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "old_results")


@pytest.mark.parametrize("sample", SAMPLES)
def test_no_finding_is_ranked_under_its_severity_without_a_reason_written_on_it(sample):
    """What may put a rank under the tool's severity: test code, evidence from the code around the line (`rank_note`
    with `rank_before_context`), a rank a rule fixes itself, an advisory's own severity. Nothing else, on any sample."""
    fs = scan(build_graph(FIXTURES / sample), offline=True)["findings"]
    odd = []
    for f in fs:
        floor = FLOOR.get(f.get("tool_severity"))
        if not floor or RANK_ORDER[f["rank"]] <= RANK_ORDER[floor]:
            continue
        if f["in_tests"] or f.get("fixed_rank") or f["category"] == "dependency":
            continue
        if f.get("rank_note") and f.get("rank_before_context"):
            continue
        odd.append((f["rule"], f["file"], f["line"], f["tool_severity"], f["rank"]))
    assert not odd, odd


@pytest.mark.parametrize("sample", SAMPLES)
def test_every_finding_says_what_is_known_about_who_reaches_it_and_how_its_rank_came_about(sample):
    fs = scan(build_graph(FIXTURES / sample), offline=True)["findings"]
    assert fs
    for f in fs:
        r = f["reachability"]
        assert r["state"] in ("reached", "tests-only", "unknown", "not-code"), r
        assert (r["state"] == "reached") is bool(f["reachable"]), (f["rule"], r, f["reachable"])
        assert isinstance(r["why"], str) and r["why"]
        basis = f["rank_basis"]
        assert basis and basis[-1]["rank"] == f["rank"], (f["rule"], basis, f["rank"])
        assert all(s["step"] in ("severity", "raised", "lowered", "fixed", "test-code") and s["why"] for s in basis)
        # the four facts stay their own fields beside the rank
        assert "tool_severity" in f and "tool_confidence" in f and "reachable" in f
        if not f["in_tests"]:
            assert f["case"]["evidence"], f["rule"]


def test_the_case_says_an_unknown_path_is_unknown_not_safe(tmp_path):
    f = next(f for f in _scan(tmp_path, {"jobs.py": NO_PATH["text handed to eval (Bandit: medium)"][0]})
             if f["rule"] == "B307")
    case = f["case"]
    assert any("found no path" in e["fact"] for e in case["evidence"]), case["evidence"]
    assert any("no path" in u and "not proof" in u for u in case["unknown"]), case["unknown"]
    assert case["severity"]["rank"] == "medium" and case["severity"]["tool_severity"] == "MEDIUM"


def test_the_report_does_not_call_a_finding_unreachable_when_no_path_was_found():
    html = lantern_files.page("report.html")
    assert "Not reachable from any" not in html
    assert "No path found" in html
