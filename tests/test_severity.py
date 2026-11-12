"""Directive point 6, first half: an unknown path is not evidence of safety.

A finding keeps four facts apart (the tool's own severity, the tool's confidence, what the map says about who reaches
the line, the evidence) and one rank worked out from them. The rank goes UP when an entry point from outside reaches
the line and request data is not ruled out. It goes DOWN only on evidence that is written on the finding. That Lantern
found no path to a line is neither: the rank then stays at the tool's own severity, and the finding says the path is
not known. Each lowering here stands beside a deceptive near-miss that must not be lowered.
"""
from pathlib import Path

import pytest

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
    html = (Path(__file__).parents[1] / "lantern" / "viewer" / "report.html").read_text(encoding="utf-8")
    assert "Not reachable from any" not in html
    assert "No path found" in html
