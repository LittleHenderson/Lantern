"""Directive point 6, second half: a release decision that does not depend on the average score.

    Blocked      a required criterion failed (an open critical or high finding, failed tests, a broken behaviour case)
    Incomplete   nothing failed and required evidence is missing (a scanner, the library check, the tests, the plan)
    Passed       every required criterion that applies has passed

A critical issue is not averaged away by unrelated points, tests that were not run are not a pass, 100 needs a
passed release, and the record is tied to the exact code, libraries, settings and tools. Each refusal stands beside
the twin that must pass, and each pass beside a deceptive near-miss that must not.
"""
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

import lantern_files
from lantern import behave, release, seal
from lantern.engine import build_graph
from lantern.readiness import assess, grade
from lantern.security import scan

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "old_results")
RAN_OK = {"trace": {"command": ["pytest", "-q"], "returncode": 0, "ran": True}}
GIT = {"commit": None}


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


# A small service with nothing to find: no library list, a test, a route that returns fixed text.
CLEAN = {
    "app.py": "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n"
              "    return {'ok': True}\n",
    "tests/test_app.py": "from app import health\n\n\ndef test_health():\n    assert health() == {'ok': True}\n",
    "README.md": "# Clean\n\nA sample.\n",
}
# The same service with one line added: a shell command built from what the request sent.
BROKEN = {**CLEAN, "app.py": "import subprocess\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n\n"
                             "@app.get('/health')\ndef health():\n    return {'ok': True}\n\n\n"
                             "@app.post('/run')\ndef run(cmd: str):\n"
                             "    return subprocess.run(cmd, shell=True).returncode\n"}


def _assess(root: Path, files: dict[str, str], run_meta: dict | None = None, *, seen: bool = True, **kw) -> dict:
    """The readiness of the project in `root` with `files` written into it. `seen`: hand in the record of a browser
    run of this code in which every check held (`_seen`), so that a test of another criterion is about that one
    alone; the tests of the browser's own criterion are below ("the browser")."""
    g = build_graph(_write(root, files))
    if seen and "browser" not in kw:
        kw["browser"] = _seen(root)
    return assess(g, scan(g, offline=True), run_meta if run_meta is not None else dict(RAN_OK), git=GIT, **kw)


def _seen(root: Path, outcomes: dict | None = None, drop: tuple = (), **over) -> dict:
    """A record as `lantern browse` writes it for the project in `root`, sealed by this computer: every check held
    but those `outcomes` names (`{check: outcome}`, or `{check: (outcome, [codes], why)}`), and none of `drop`."""
    from lantern import browse
    checks = []
    for c in browse.CHECKS:
        got = (outcomes or {}).get(c.id, "held")
        outcome, codes, why = got if isinstance(got, tuple) else (got, [c.codes[0]] if got == "broken" else [], None)
        if c.id not in drop:
            checks.append({"id": c.id, "outcome": outcome, "codes": list(codes),
                           "saw": [{"code": k, "page": "/"} for k in codes], "why": why})
    rec = {"of": {"commit": None, "dirty": None, "lantern": "test", "code_sha256": release.code_digest(root)["sha256"]},
           "ran": True, "why_not": None,
           "browser": {"name": "Chrome", "version": "153", "own_sandbox": True, "how": "test", "keyboard_end": "leaves"},
           "site": {"how": "app", "address": "http://localhost:20001", "pages": 1},
           "opened": [{"path": "/health", "status": 200, "seconds": 0.1}], "checks": checks, "asked_outside": [],
           "browser_own": [], "seconds": 0.5}
    rec.update(over)
    rec["seal"] = seal.sign(rec)
    return rec


def _state(rd: dict, cid: str) -> str:
    return next(c["state"] for c in rd["release"]["criteria"] if c["id"] == cid)


# ------------------------------------------------------------------------------------------------ the three words
def test_a_clean_project_whose_tests_ran_and_passed_reads_passed(tmp_path):
    rd = _assess(tmp_path, CLEAN)
    rel = rd["release"]
    assert rel["decision"] == "Passed", rel["words"]
    assert rel["blocking"] == [] and rel["missing"] == []
    # an app Lantern can start is a site: what a browser saw of it on this code is part of the proof (`_seen`)
    assert rel["profile"]["required"] == ["findings", "scanners", "tests", "browser"]
    # what the profile did not ask for is said, with the reason: "Passed" is not more than it is
    assert {x["id"] for x in rel["profile"]["not_required"]} == {"dependencies", "behaviour"}
    assert "no app was started" in next(x["why"] for x in rel["profile"]["not_required"] if x["id"] == "behaviour")


# What a well-kept project has beside its code: the points a critical finding used to be averaged against.
KEPT = {
    ".github/workflows/ci.yml": "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
                                "      - uses: actions/checkout@v4\n      - run: pip install pytest bandit\n"
                                "      - run: pytest -q\n      - run: bandit -r .\n",
    "LICENSE": "MIT License\n\nPermission is hereby granted, free of charge, to any person.\n",
    "SECURITY.md": "# Security\n\nReport a problem to security@example.com.\n",
}


def test_a_critical_finding_blocks_the_release_and_is_not_averaged_away(tmp_path):
    rd = _assess(tmp_path, {**BROKEN, **KEPT})
    rel = rd["release"]
    assert rel["decision"] == "Blocked" and rel["blocking"] == ["findings"], rel["words"]
    assert "1 critical" in rel["words"] and "B602" in rel["words"]
    # the checklist's points are kept as they are; the score cannot be above an F while the release is blocked
    assert rd["checklist"] > release.BLOCKED_CAP, rd["checklist"]      # the other categories earned their points
    assert rd["score"] == release.BLOCKED_CAP and rd["grade"] == "F"
    # the twin without that line
    clean = _assess(tmp_path / "twin", {**CLEAN, **KEPT})
    assert clean["release"]["decision"] == "Passed" and clean["score"] == clean["checklist"] > rd["checklist"]


def test_a_high_finding_no_path_was_found_to_blocks_too(tmp_path):
    """Before this stage it was ranked medium "because nothing reaches it" and the badge stayed green."""
    files = {**CLEAN, "jobs.py": "import subprocess\n\n\ndef clean(name):\n    subprocess.run('rm -rf ' + name, shell=True)\n"}
    rel = _assess(tmp_path, files)["release"]
    assert rel["decision"] == "Blocked" and "1 high" in rel["words"], rel["words"]


def test_a_finding_with_no_line_is_named_by_its_file_alone():
    """A known problem in a library is found in a lock file, at no line. Until 2026-11-13 the decision's words
    said "at uv.lock:None" for it (seen on the first public project a link was run from)."""
    def words(**where):
        return release._findings({"findings": [{"id": "x", "rule": "PYSEC-0000-1", "rank": "high", **where}]})["why"]

    assert "PYSEC-0000-1 in uv.lock" in words(file="uv.lock", line=None)
    assert "PYSEC-0000-1 in uv.lock" in words(file="uv.lock")
    assert "None" not in words(file="uv.lock", line=None) + words(file="uv.lock") + words(file=None, line=None)
    assert words(file=None, line=None).endswith("PYSEC-0000-1")
    assert "PYSEC-0000-1 at app.py:7" in words(file="app.py", line=7)          # the twin with a line, as before


def test_a_finding_the_project_accepted_with_a_reason_does_not_block_and_is_named(tmp_path):
    g = build_graph(_write(tmp_path, BROKEN))
    fid = next(f["id"] for f in scan(g, offline=True)["findings"] if f["rule"] == "B602")
    (tmp_path / "lantern-accepted.json").write_text(json.dumps({"accepted": [
        {"id": fid, "reason": "only reachable on the build machine, behind the VPN", "by": "dev", "date": "2026-11-11"}]}),
        encoding="utf-8")
    rd = assess(build_graph(tmp_path), scan(build_graph(tmp_path), offline=True), dict(RAN_OK), git=GIT)
    c = next(c for c in rd["release"]["criteria"] if c["id"] == "findings")
    assert c["state"] == "passed" and "accepted by the project with a written reason" in c["why"], c
    # the near-miss: a row without a written reason accepts nothing
    (tmp_path / "lantern-accepted.json").write_text(json.dumps({"accepted": [{"id": fid, "reason": ""}]}),
                                                    encoding="utf-8")
    rd = assess(build_graph(tmp_path), scan(build_graph(tmp_path), offline=True), dict(RAN_OK), git=GIT)
    assert rd["release"]["decision"] == "Blocked"


# ------------------------------------------------------------------------------------------------ tests
TESTS = {
    "not run at all": ({}, "missing", "Incomplete"),
    "asked for, and the sandbox could not be set up": (
        {"trace": {"command": ["pytest"], "returncode": None, "ran": False, "unavailable": "no landlock"}},
        "missing", "Incomplete"),
    "stopped at the time limit": (
        {"trace": {"command": ["pytest"], "returncode": None, "ran": True, "timed_out": True}}, "missing", "Incomplete"),
    "failed where the sandbox refused something": (
        {"trace": {"command": ["pytest"], "returncode": 1, "ran": True, "blocked": ["network"]}}, "missing", "Incomplete"),
    "failed": ({"trace": {"command": ["pytest"], "returncode": 1, "ran": True}}, "failed", "Blocked"),
    "ran and passed": (RAN_OK, "passed", "Passed"),
}


@pytest.mark.parametrize("case", sorted(TESTS))
def test_tests_count_only_when_they_ran_and_passed(tmp_path, case):
    run_meta, state, decision = TESTS[case]
    rd = _assess(tmp_path, CLEAN, dict(run_meta))
    assert _state(rd, "tests") == state and rd["release"]["decision"] == decision, rd["release"]["words"]


def test_tests_that_were_not_run_do_not_become_points(tmp_path):
    ran = _assess(tmp_path / "a", CLEAN)
    skipped = _assess(tmp_path / "b", CLEAN, {})
    check = lambda rd: next(c for cat in rd["categories"] for c in cat["checks"] if c["id"] == "tests-pass")
    assert check(ran)["status"] == "pass" and check(skipped)["status"] == "skip" and check(skipped)["required"] is True
    # before: a skipped check left the sum, so the same project scored the same with and without its tests run
    assert skipped["checklist"] < ran["checklist"], (skipped["checklist"], ran["checklist"])
    assert skipped["score"] < 100
    assert any(s["id"] == "tests-pass" for s in skipped["next_steps"])


def test_a_project_with_no_tests_is_incomplete_not_passed(tmp_path):
    rd = _assess(tmp_path, {k: v for k, v in CLEAN.items() if not k.startswith("tests/")}, {})
    assert rd["release"]["decision"] == "Incomplete" and "has no tests" in rd["release"]["words"]


# ------------------------------------------------------------------------------------------------ scanners, libraries
def test_a_scanner_that_did_not_finish_makes_the_release_incomplete(tmp_path):
    g = build_graph(_write(tmp_path, CLEAN))
    sec = scan(g, offline=True)
    ok = assess(g, sec, dict(RAN_OK), git=GIT, browser=_seen(tmp_path))
    assert ok["release"]["decision"] == "Passed"
    hurt = copy.deepcopy(sec)
    b = next(t for t in hurt["tools"] if t["tool"] == "bandit")
    b.update(state="failed", status="error: exit 2", why="exit 2")
    rd = assess(g, hurt, dict(RAN_OK), git=GIT, browser=_seen(tmp_path))
    assert rd["release"]["decision"] == "Incomplete" and rd["release"]["missing"] == ["scanners"]
    assert "bandit" in rd["release"]["words"]


LIBRARIES = {
    "offline: the libraries were not looked up": ({"requirements.txt": "requests==2.31.0\n"}, "missing"),
    "no exact version written down": ({"requirements.txt": "requests>=2\n"}, "missing"),
    "a kind of library list Lantern has no check for": ({"go.mod": "module x\n\ngo 1.22\n"}, "missing"),
    "no library list at all": ({}, "not-applicable"),
    # Named and never looked up: with no lock file there is no version to ask about. Before, each of these read
    # "The project lists no libraries", and the release could read Passed with not one library checked.
    "a package.json that names a library, with no lock file":
        ({"package.json": '{"name": "x", "dependencies": {"left-pad": "^1.3.0"}}\n'}, "missing"),
    "a composer.json that names a library, with no lock file":
        ({"composer.json": '{"require": {"php": ">=8.1", "monolog/monolog": "^3.0"}}\n'}, "missing"),
    "a Gemfile that names a gem, with no lock file":
        ({"Gemfile": "source 'https://rubygems.org'\n\ngem 'rails', '~> 7.1'\n"}, "missing"),
    # ... each beside the same file with nothing in it that ships
    "safe twin: a package.json that names no library":
        ({"package.json": '{"name": "x", "scripts": {"test": "node test.js"}, "devDependencies": {"vite": "^6.0.0"}}\n'},
         "not-applicable"),
    "safe twin: a composer.json that asks for PHP itself only":
        ({"composer.json": '{"require": {"php": ">=8.1", "ext-json": "*"}, "require-dev": {"phpunit/phpunit": "^11"}}\n'},
         "not-applicable"),
    "safe twin: a Gemfile whose only gem is for tests":
        ({"Gemfile": "source 'https://rubygems.org'\n\ngroup :test do\n  gem 'rspec'\nend\n"}, "not-applicable"),
    # A sample app kept among the tests is not what the project ships: the audits leave such folders out
    # (`depaudit.TEST_DIR_RE`), and so does the question "is there a kind of library list nobody checks".
    # Before, Lantern's own decision said its Go, Rust, Dart and .NET libraries were unchecked: its sample apps'.
    "safe twin: a Go sample app kept among the tests":
        ({"tests/fixtures/goapp/go.mod": "module x\n\ngo 1.22\n", "examples/demo/Cargo.toml": "[package]\n"},
         "not-applicable"),
    "a Go service in a folder whose name only begins like a test folder's":
        ({"testing-tools/go.mod": "module x\n\ngo 1.22\n"}, "missing"),
    "a Rust service beside a sample app":
        ({"tests/fixtures/goapp/go.mod": "module x\n\ngo 1.22\n", "worker/Cargo.toml": "[package]\n"}, "missing"),
}


@pytest.mark.parametrize("case", sorted(LIBRARIES))
def test_libraries_that_were_not_checked_are_missing_evidence(tmp_path, case):
    extra, state = LIBRARIES[case]
    rd = _assess(tmp_path, {**CLEAN, **extra})
    assert _state(rd, "dependencies") == state, rd["release"]["words"]
    assert rd["release"]["decision"] == ("Passed" if state == "not-applicable" else "Incomplete")
    if case == "a Rust service beside a sample app":            # the service's list is named, the sample's is not
        assert "Rust" in rd["release"]["words"] and "Go (" not in rd["release"]["words"]


def test_the_record_counts_the_libraries_named_with_no_lock_file(tmp_path):
    """The count is on the audit's own record (`unlocked`), also when another folder of the project has a lock file
    and was checked: one folder looked up does not speak for the one beside it."""
    from lantern import depaudit
    _write(tmp_path, {"web/package.json": '{"dependencies": {"react": "^19.0.0", "axios": "^1.7.0"},'
                                          ' "optionalDependencies": {"fsevents": "*"}, "devDependencies": {"vite": "^6"}}',
                      "api/package.json": '{"dependencies": {"express": "^4.19.0"}}',
                      "api/package-lock.json": '{"name": "api", "lockfileVersion": 3, "packages": {}}'})
    rec = depaudit.run_npm_audit(tmp_path, True)[1]
    assert rec["unlocked"] == 3, rec                        # web's three; api's one has a lock file
    assert rec["unlocked_examples"] == ["web/package.json: axios", "web/package.json: fsevents",
                                        "web/package.json: react"]
    only = _write(tmp_path / "only", {"package.json": '{"dependencies": {"left-pad": "^1.3.0"}}'})
    rec = depaudit.run_npm_audit(only, True)[1]
    assert rec["unlocked"] == 1 and rec["why"].startswith("no package-lock.json") and rec["state"] == "skipped"
    none = _write(tmp_path / "none", {"package.json": '{"name": "x", "devDependencies": {"vite": "^6"}}'})
    rec = depaudit.run_npm_audit(none, True)[1]
    assert rec["status"] in depaudit.NOTHING_TO_CHECK and "unlocked" not in rec, rec
    php = _write(tmp_path / "php", {"composer.json": '{"require": {"php": ">=8.1", "monolog/monolog": "^3.0"}}'})
    rec = depaudit.run_composer_audit(php, True)[1]
    assert rec["unlocked"] == 1 and rec["status"] not in depaudit.NOTHING_TO_CHECK, rec
    ruby = _write(tmp_path / "ruby", {"Gemfile": "gem 'rails', '~> 7.1'\ngem 'pg'\ngroup :development do\n  gem 'pry'\nend\n"})
    rec = depaudit.run_gem_audit(ruby, True)[1]
    assert rec["unlocked"] == 2 and rec["status"] not in depaudit.NOTHING_TO_CHECK, rec


def test_one_folder_that_was_looked_up_does_not_speak_for_the_folder_beside_it(tmp_path):
    g = build_graph(_write(tmp_path, {**CLEAN, "package.json": '{"dependencies": {"left-pad": "^1.3.0"}}'}))
    sec = scan(g, offline=True)
    npm = next(t for t in sec["tools"] if t["tool"] == "npm-audit")
    npm.update(state="ok", status="ok", why="", applicable=True, unlocked=2,
               unlocked_examples=["web/package.json: axios", "web/package.json: react"])
    rd = assess(g, sec, dict(RAN_OK), git=GIT)
    c = next(c for c in rd["release"]["criteria"] if c["id"] == "dependencies")
    assert c["state"] == "missing" and "2 libraries are named in a file with no lock file" in c["why"], c
    assert rd["release"]["decision"] == "Incomplete"
    # the Evidence page's limits say it too, whatever state the audit ended in
    from lantern import evidence
    said = evidence.limits(g, sec, rd, dict(RAN_OK), "full", None)
    assert any("2 npm libraries are named in a package.json with no lock file" in line for line in said), said


def test_libraries_that_were_all_looked_up_pass(tmp_path):
    g = build_graph(_write(tmp_path, {**CLEAN, "requirements.txt": "requests==2.31.0\n"}))
    sec = scan(g, offline=True)
    pa = next(t for t in sec["tools"] if t["tool"] == "pip-audit")
    pa.update(state="ok", status="ok", why="", applicable=True, checked=1, unpinned=0)
    sec["incomplete"] = []
    rd = assess(g, sec, dict(RAN_OK), git=GIT, browser=_seen(tmp_path))
    assert _state(rd, "dependencies") == "passed" and rd["release"]["decision"] == "Passed", rd["release"]["words"]
    assert "dependencies" in rd["release"]["profile"]["required"]


# ------------------------------------------------------------------------------------------------ 100
def test_the_score_rules():
    assert release.score(100, "Passed") == 100
    assert release.score(100, "Incomplete") == 99          # 100 is for a passed release with complete evidence
    assert release.score(100, "Blocked") == release.BLOCKED_CAP == 59 and grade(59) == "F"
    assert release.score(40, "Blocked") == 40 and release.score(73, "Incomplete") == 73


@pytest.mark.parametrize("sample", SAMPLES)
def test_no_sample_reads_100_or_passed_with_a_blocking_finding_or_missing_evidence(sample):
    g = build_graph(FIXTURES / sample)
    sec = scan(g, offline=True)
    rd = assess(g, sec, {"offline": True}, git=GIT)
    rel = rd["release"]
    assert rel["decision"] in release.DECISIONS
    blocking = [f for f in sec["findings"] if not f["in_tests"] and f["status"] == "open"
                and f["rank"] in ("critical", "high")]
    assert (rel["decision"] == "Blocked") is bool(blocking), (rel["decision"], len(blocking))
    assert rel["decision"] != "Passed"                      # no sample's tests were run in this check
    assert rd["score"] < 100 and (not blocking or rd["score"] <= release.BLOCKED_CAP)
    assert rd["grade"] == grade(rd["score"])
    for c in rel["criteria"]:
        assert c["state"] in release.STATES and c["why"] and c["title"]
        assert c["state"] == "passed" or c["state"] == "not-applicable" or c["fix"], c


# ------------------------------------------------------------------------------------------------ behaviour
PLAN = {"app": {"asgi": "app:app"}, "checks": [{"id": "health", "kind": "hide", "request": {"path": "/health"},
                                                "never": ["password"]}]}
WITH_PLAN = {**CLEAN, behave.PLAN_NAME: json.dumps(PLAN)}


def _record(root: Path, outcomes=None, **over) -> dict:
    """A record as `lantern behave` writes it for the project in `root`, sealed by this computer."""
    plan = behave.load(root)
    outcomes = outcomes if outcomes is not None else [{"check": "health", "case": "as written", "kind": "hide",
                                                       "outcome": "held"}]
    rec = {"version": 1, "of": {"plan_sha256": behave.plan_sha256(plan), "commit": None, "dirty": None,
                                "code_sha256": release.code_digest(root)["sha256"]},
           "ran": True, "why_not": None, "summary": behave.summary(outcomes), "outcomes": outcomes}
    rec.update(over)
    rec["seal"] = seal.sign(rec)
    return rec


def _with_record(root: Path, rec) -> dict:
    g = build_graph(root)
    return assess(g, scan(g, offline=True), dict(RAN_OK), git=GIT, behaviour=rec, browser=_seen(root))


def test_a_project_with_a_plan_needs_the_plan_run_on_this_code(tmp_path):
    _write(tmp_path, WITH_PLAN)
    rd = _with_record(tmp_path, None)
    assert _state(rd, "behaviour") == "missing" and rd["release"]["decision"] == "Incomplete"
    assert "behaviour" in rd["release"]["profile"]["required"]
    rd = _with_record(tmp_path, _record(tmp_path))
    assert _state(rd, "behaviour") == "passed" and rd["release"]["decision"] == "Passed", rd["release"]["words"]


def test_a_broken_behaviour_case_blocks_the_release(tmp_path):
    _write(tmp_path, WITH_PLAN)
    out = [{"check": "health", "case": "as written", "kind": "hide", "outcome": "broken", "codes": ["leaked"]}]
    rd = _with_record(tmp_path, _record(tmp_path, out))
    assert rd["release"]["decision"] == "Blocked" and rd["release"]["blocking"] == ["behaviour"]
    assert "health / as written" in rd["release"]["words"]


def _planted(root):          # what a project can bring in its own results folder: "every check held", no seal
    rec = _record(root)
    rec.pop("seal")
    return rec


def _edited(root):           # a real record of a broken run, its outcome changed afterwards, the seal left on
    rec = _record(root, [{"check": "health", "case": "as written", "kind": "hide", "outcome": "broken"}])
    rec["outcomes"][0]["outcome"] = "held"
    rec["summary"] = behave.summary(rec["outcomes"])
    return rec


def _of_other_code(root):    # a real record, and then a file of the project changed
    rec = _record(root)
    (root / "app.py").write_text(CLEAN["app.py"] + "\n\n@app.get('/debug')\ndef debug():\n    return {'password': 'x'}\n",
                                 encoding="utf-8")
    return rec


def _of_another_plan(root):  # a real record, and then the plan got a check
    rec = _record(root)
    plan = json.loads(json.dumps(PLAN))
    plan["checks"].append({"id": "more", "kind": "hide", "request": {"path": "/health"}, "never": ["token"]})
    (root / behave.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")
    return rec


def _not_started(root):
    return _record(root, [], ran=False, why_not="the sandbox the app runs in could not be set up")


def _undecided(root):
    return _record(root, [{"check": "health", "case": "as written", "kind": "hide", "outcome": "inconclusive"}])


NEAR_MISSES = {"planted without a seal": _planted, "edited after it was sealed": _edited,
               "made on other code": _of_other_code, "made with another plan": _of_another_plan,
               "the app was not started": _not_started, "a case could not be decided": _undecided}


@pytest.mark.parametrize("case", sorted(NEAR_MISSES))
def test_a_behaviour_record_that_is_not_of_this_code_and_plan_and_computer_does_not_count(tmp_path, case):
    _write(tmp_path, WITH_PLAN)
    rd = _with_record(tmp_path, NEAR_MISSES[case](tmp_path))
    assert _state(rd, "behaviour") == "missing", next(c for c in rd["release"]["criteria"] if c["id"] == "behaviour")
    assert rd["release"]["decision"] == "Incomplete"


def test_a_seal_made_with_another_computers_key_does_not_hold(tmp_path, monkeypatch):
    rec = {"ran": True, "summary": {"held": 3}}
    rec["seal"] = seal.sign(rec)
    assert seal.holds(rec) and not seal.holds({**rec, "ran": False}) and not seal.holds({"ran": True})
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "elsewhere"))
    assert not seal.holds(rec)               # no key there yet, and holds() makes none
    assert not (tmp_path / "elsewhere").exists()
    assert seal.sign(rec) != rec["seal"]     # that computer's own seal is another one


def test_a_plan_that_cannot_be_used_is_missing_evidence_not_no_plan(tmp_path):
    _write(tmp_path, {**CLEAN, behave.PLAN_NAME: json.dumps({"app": {"asgi": "app:app"}, "checks": []})})
    rd = _with_record(tmp_path, None)
    assert _state(rd, "behaviour") == "missing" and "cannot be used" in rd["release"]["words"]


# ------------------------------------------------------------------------------------------------ the browser
# A site is what `lantern browse` opens (an app Lantern can start, or a folder of plain pages). Page errors, failed
# forms, a visitor let in and protections not sent block a release; dead links, loads from another computer and
# keyboard issues are shown and block nothing. The record counts only with this computer's seal, for this code.
PAGES = {"index.html": "<!doctype html><title>Home</title><h1>Home</h1>\n",
         "tests/test_pages.py": "def test_pages():\n    assert True\n"}


def _crit(rd: dict, cid: str) -> dict:
    return next(c for c in rd["release"]["criteria"] if c["id"] == cid)


def test_a_site_counts_only_once_a_browser_opened_it_on_this_code(tmp_path):
    rd = _assess(tmp_path, CLEAN, seen=False)
    rel = rd["release"]
    assert "browser" in rel["profile"]["required"] and rel["missing"] == ["browser"], rel["words"]
    assert rel["decision"] == "Incomplete" and rd["score"] <= release.NOT_PASSED_CAP
    c = _crit(rd, "browser")
    assert c["state"] == "missing" and "browser.json" in c["why"] and "lantern browse" in c["fix"], c
    rd = _assess(tmp_path, {}, browser=_seen(tmp_path), seen=False)
    assert _crit(rd, "browser")["state"] == "passed" and rd["release"]["decision"] == "Passed", rd["release"]["words"]


def test_a_project_with_nothing_to_open_is_not_asked_for_a_browser_run(tmp_path):
    rd = _assess(tmp_path, SUMS, seen=False)
    rel = rd["release"]
    assert "browser" not in rel["profile"]["required"] and _crit(rd, "browser")["state"] == "not-applicable"
    assert rel["decision"] == "Passed", rel["words"]
    why = next(x["why"] for x in rel["profile"]["not_required"] if x["id"] == "browser")
    assert "nothing to open" in why and "not opened yet" in why, why     # other kinds of site: said, not passed over
    # and the Evidence page's limits say it, so a "Passed" there does not read as a site a browser saw
    from lantern import evidence
    g = build_graph(tmp_path)
    said = evidence.limits(g, scan(g, offline=True), rd, dict(RAN_OK), "full", None)
    assert [line for line in said if line.startswith("What a browser shows of the project.")] == [
        "What a browser shows of the project. " + why], said
    rd = _assess(tmp_path, CLEAN, seen=True)        # a site a browser opened: the limits say nothing of the kind
    g = build_graph(tmp_path)
    said = evidence.limits(g, scan(g, offline=True), rd, dict(RAN_OK), "full", None)
    assert _crit(rd, "browser")["state"] == "passed" and not [x for x in said if "What a browser shows" in x], said


def test_plain_pages_count_too_and_what_their_host_sends_is_named_as_not_checked(tmp_path):
    rd = _assess(tmp_path, PAGES, seen=False)
    assert _crit(rd, "browser")["state"] == "missing" and "browser" in rd["release"]["profile"]["required"]
    rec = _seen(tmp_path, {"protections": ("not-run", [], "hosting-unknown"),
                           "visitor": ("nothing-to-check", [], "no page asks for a sign-in")},
                site={"how": "pages", "address": "http://localhost:20001", "pages": 1})
    rd = _assess(tmp_path, {}, browser=rec, seen=False)
    c = _crit(rd, "browser")
    assert c["state"] == "passed" and rd["release"]["decision"] == "Passed", c
    assert "hosting" in c["why"] and "not checked" in c["why"], c


BLOCKS = {"opens": "server-error", "script": "raised", "forms": "form-error", "visitor": "let-in",
          "protections": "said-not-sent"}


@pytest.mark.parametrize("check", sorted(BLOCKS))
def test_a_real_fault_the_browser_saw_blocks_the_release(tmp_path, check):
    _write(tmp_path, CLEAN)
    rd = _assess(tmp_path, {}, browser=_seen(tmp_path, {check: ("broken", [BLOCKS[check]], None)}), seen=False)
    rel = rd["release"]
    assert rel["decision"] == "Blocked" and rel["blocking"] == ["browser"], rel["words"]
    assert BLOCKS[check] in _crit(rd, "browser")["why"] and rd["score"] <= release.BLOCKED_CAP


SHOWN = {"leads": "dead-link", "outside": "outside-script", "keyboard": "no-label"}


@pytest.mark.parametrize("outcome", ["broken", "inconclusive", "not-run"])
@pytest.mark.parametrize("check", sorted(SHOWN))
def test_dead_links_outside_loads_and_keyboard_issues_are_shown_and_block_nothing(tmp_path, check, outcome):
    _write(tmp_path, CLEAN)
    got = (outcome, [SHOWN[check]] if outcome == "broken" else [], "browser-failed" if outcome == "not-run" else None)
    rd = _assess(tmp_path, {}, browser=_seen(tmp_path, {check: got}), seen=False)
    c = _crit(rd, "browser")
    assert c["state"] == "passed" and rd["release"]["decision"] == "Passed", rd["release"]["words"]
    assert ("shown" in c["why"] and check in c["why"]), c
    if outcome == "broken":
        assert SHOWN[check] in c["why"], c


def _b_planted(root):         # what a project can bring in its own results folder: "every check held", no seal
    rec = _seen(root)
    rec.pop("seal")
    return rec


def _b_edited(root):          # a sealed record of a run where a page did not open, made to say held afterwards
    rec = _seen(root, {"opens": ("broken", ["server-error"], None)})
    rec["checks"][0].update(outcome="held", codes=[], saw=[])
    return rec


def _b_other_code(root):      # a sealed record, and then a file of the project changed
    rec = _seen(root)
    (root / "app.py").write_text(CLEAN["app.py"] + "\n\n@app.get('/debug')\ndef debug():\n    return {'x': 1}\n",
                                 encoding="utf-8")
    return rec


def _b_not_run(root):
    from lantern import browse
    return _seen(root, {c.id: ("not-run", [], "no-browser") for c in browse.CHECKS}, ran=False, why_not="no-browser")


B_NEAR_MISSES = {
    "planted without a seal": _b_planted, "edited after it was sealed": _b_edited, "made on other code": _b_other_code,
    "the browser checks were not run": _b_not_run,
    "the page's script could not be decided": lambda root: _seen(root, {"script": ("inconclusive", [], "undecided")}),
    "the forms were not looked at": lambda root: _seen(root, {"forms": ("not-run", [], "browser-failed")}),
    "the record has no visitor check": lambda root: _seen(root, drop=("visitor",)),
    "no page was opened": lambda root: _seen(root, opened=[]),
    "protections not run for a reason other than the host": lambda root: _seen(
        root, {"protections": ("not-run", [], "browser-failed")}),
}


@pytest.mark.parametrize("case", sorted(B_NEAR_MISSES))
def test_a_browser_record_that_is_not_of_this_code_and_computer_or_not_whole_does_not_count(tmp_path, case):
    _write(tmp_path, CLEAN)
    rd = _assess(tmp_path, {}, browser=B_NEAR_MISSES[case](tmp_path), seen=False)
    c = _crit(rd, "browser")
    assert c["state"] == "missing" and rd["release"]["decision"] == "Incomplete", c
    assert c["fix"], c


def test_a_browser_record_that_could_not_be_read_is_said(tmp_path):
    rd = _assess(tmp_path, CLEAN, seen=False, browser_unread="it is not a plain file")
    c = _crit(rd, "browser")
    assert c["state"] == "missing" and "it is not a plain file" in c["why"], c


def test_analyze_counts_the_browser_record_beside_its_results_only_with_this_computers_seal(tmp_path):
    from lantern import browse, pipeline
    repo = _write(tmp_path / "proj", CLEAN)
    out = repo / ".lantern"
    out.mkdir()

    def analyzed(rec) -> dict:
        (out / browse.RESULT_NAME).write_text(json.dumps(rec), encoding="utf-8")
        pipeline.analyze(repo, out, log=lambda m: None, offline=True)
        return json.loads((out / "readiness.json").read_text(encoding="utf-8"))

    assert _crit(analyzed(_seen(repo)), "browser")["state"] == "passed"
    assert _crit(analyzed(_b_planted(repo)), "browser")["state"] == "missing"
    (out / browse.RESULT_NAME).unlink()
    (out / browse.RESULT_NAME).mkdir()                    # a folder under the record's name: said, never guessed at
    pipeline.analyze(repo, out, log=lambda m: None, offline=True)
    c = _crit(json.loads((out / "readiness.json").read_text(encoding="utf-8")), "browser")
    assert c["state"] == "missing" and "could not be used" in c["why"], c


# ------------------------------------------------------------------------------------------ which tests to write
# A project with no tests stays Incomplete whatever a browser saw (the owner's answer of 2026-11-21: what a browser
# saw never counts in place of tests). The decision names, read from the code, the tests to write first, and a first
# test file is offered where Lantern can import the app (a FastAPI app made in the code). That file is run below:
# on the app it was written from, where it passes, and on the same app after a change that lets a visitor delete,
# where it fails.
NOTES_MAIN = (
    "import os\nimport sqlite3\n\n"
    "from fastapi import Depends, FastAPI, Header, HTTPException\n\n"
    "from notes import ai\n\n"
    "DB = os.environ.get('NOTES_DB', 'notes.db')\n"
    "SECRET_KEY = os.environ.get('SECRET_KEY', '')\n"
    "with sqlite3.connect(DB) as _db:\n"
    "    _db.execute('CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, text TEXT)')\n"
    "app = FastAPI()\n\n\n"
    "def require_login(authorization: str = Header('')):\n"
    "    if not SECRET_KEY or authorization != 'Bearer ' + SECRET_KEY:\n"
    "        raise HTTPException(401, 'sign in first')\n"
    "    return 'alice'\n\n\n"
    "@app.get('/')\ndef home():\n    return {'page': 'home'}\n\n\n"
    "@app.get('/health')\ndef health():\n    return {'ok': True}\n\n\n"
    "@app.post('/login')\ndef login(name: str, password: str):\n    return {'token': 'made later'}\n\n\n"
    "@app.post('/notes')\ndef add(text: str, user: str = Depends(require_login)):\n"
    "    with sqlite3.connect(DB) as db:\n        db.execute('INSERT INTO notes (text) VALUES (?)', (text,))\n"
    "    return {'added': True}\n\n\n"
    "@app.delete('/notes/{note_id}')\ndef remove(note_id: int, user: str = Depends(require_login)):\n"
    "    with sqlite3.connect(DB) as db:\n        db.execute('DELETE FROM notes WHERE id = ?', (note_id,))\n"
    "    return {'removed': note_id}\n\n\n"
    "@app.post('/contact')\ndef contact(text: str):\n    return {'thanks': True}\n\n\n"
    "@app.post('/ask')\ndef ask(text: str, user: str = Depends(require_login)):\n"
    "    return {'answer': ai.ask_model(text)}\n")
NOTES = {"notes/__init__.py": "",
         "notes/main.py": NOTES_MAIN,
         # the library is asked for only when the route runs, so the tests need nothing but FastAPI
         "notes/ai.py": "def ask_model(text):\n    from openai import OpenAI\n"
                        "    return OpenAI().chat.completions.create(model='m', messages=[{'role': 'user', "
                        "'content': text}])\n",
         "README.md": "# Notes\n\nA sample.\n"}
FIRST = "tests/test_first.py"


def test_a_project_with_no_tests_is_told_which_to_write_first_from_its_code(tmp_path):
    rd = _assess(tmp_path, NOTES)
    c = _crit(rd, "tests")
    assert c["state"] == "missing" and c["why"].startswith("The project has no tests."), c
    assert [(w["kind"], w["where"]) for w in c["write"]] == [
        ("sign-in", "POST /login"),
        ("signed-in-change", "POST /notes"), ("signed-in-change", "DELETE /notes/{note_id}"),
        ("signed-in-change", "POST /ask"),
        ("open-change", "POST /contact"),
        ("paid", "POST /ask"),
        ("read", "GET /"), ("read", "GET /health")], c["write"]
    assert all(w["file"] == "notes/main.py" and isinstance(w["line"], int) for w in c["write"]), c["write"]
    for words in ("the sign-in (POST /login)", "(POST /notes, DELETE /notes/{note_id} and POST /ask)",
                  "(POST /contact)", "a paid service", "(GET / and GET /health)", FIRST):
        assert words in c["fix"], c["fix"]
    assert rd["release"]["decision"] == "Incomplete" and "tests" in rd["release"]["missing"]
    assert FIRST in rd["starter"] and not rd["starter"][FIRST].get("snippet")


def test_a_project_with_tests_or_with_nothing_to_name_is_not_given_a_list(tmp_path):
    rd = _assess(tmp_path / "a", {**NOTES, "tests/test_notes.py": "def test_x():\n    assert True\n"}, run_meta={})
    c = _crit(rd, "tests")
    assert c["state"] == "missing" and "were not run" in c["why"] and "write" not in c, c
    assert FIRST not in rd["starter"]
    rd = _assess(tmp_path / "b", {"sums.py": SUMS["sums.py"]}, seen=False)
    c = _crit(rd, "tests")
    assert c["state"] == "missing" and c["write"] == [] and "most important flows" in c["fix"], c
    assert FIRST not in rd["starter"] and FIRST not in c["fix"]


def test_many_routes_of_a_kind_are_counted_and_not_all_named(tmp_path):
    more = "".join(f"\n\n@app.delete('/n{i}')\ndef d{i}(user: str = Depends(require_login)):\n    return {{}}\n"
                   for i in range(7))
    rd = _assess(tmp_path, {**NOTES, "notes/main.py": NOTES_MAIN + more})
    c = _crit(rd, "tests")
    assert "(POST /notes, DELETE /notes/{note_id}, POST /ask and 7 more)" in c["fix"], c["fix"]
    assert len([w for w in c["write"] if w["kind"] == "signed-in-change"]) == 10


def test_what_a_browser_saw_shows_beside_missing_tests_and_does_not_stand_in_for_them(tmp_path):
    rd = _assess(tmp_path, NOTES)
    c = _crit(rd, "tests")
    assert _crit(rd, "browser")["state"] == "passed" and rd["release"]["decision"] == "Incomplete"
    assert "A browser opened the site on this code" in c["why"] and "not count in place of tests" in c["why"], c
    rd = _assess(tmp_path, {}, seen=False)           # no browser run: nothing is said of one
    c = _crit(rd, "tests")
    assert _crit(rd, "browser")["state"] == "missing" and "browser" not in c["why"], c


def _first_run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", FIRST], cwd=root,
                          capture_output=True, text=True, encoding="utf-8", timeout=300)


def test_the_first_test_file_passes_on_its_app_and_catches_a_visitor_let_in_after_a_change(tmp_path):
    root = _write(tmp_path / "notes", NOTES)
    first = _assess(root, {})["starter"][FIRST]
    text = first["content"]
    compile(text, FIRST, "exec")
    assert "answers without a server error" in first["why"] and "visitor" in first["why"], first["why"]
    for words in ("from notes.main import app", "('DELETE', '/notes/1')", "('POST', '/notes')", "'/health'",
                  "NOTES_DB", "SECRET_KEY"):
        assert words in text, text
    for words in ("POST /login", "POST /contact", "POST /ask"):     # what only the person can write: named, not run
        assert any(words in line for line in text.splitlines() if line.startswith("#")), text
    _write(root, {FIRST: text})
    ran = _first_run(root)
    assert ran.returncode == 0 and "5 passed" in ran.stdout, ran.stdout + ran.stderr
    # the same tests, after a change to the code that drops the sign-in from one route
    twin = _write(tmp_path / "twin", {**NOTES, FIRST: text, "notes/main.py": NOTES_MAIN.replace(
        "def remove(note_id: int, user: str = Depends(require_login)):", "def remove(note_id: int):")})
    ran = _first_run(twin)
    assert ran.returncode == 1 and "1 failed, 4 passed" in ran.stdout, ran.stdout + ran.stderr
    assert "DELETE /notes/1 let a visitor in" in ran.stdout, ran.stdout


def test_the_first_test_file_makes_the_apps_secret_each_time_it_runs_and_writes_none_down(tmp_path):
    # The secret the app signs with is made by the test file when it runs, never a text written down: one text in
    # Lantern's code would be the same in every project the file is written for, a secret anyone can read. Lantern's
    # own file is read by the rule that finds a secret written in the code (Lantern must pass its own audit), and so
    # is the project with the file in it.
    from lantern import firsttests, websec
    root = _write(tmp_path / "notes", NOTES)
    text = _assess(root, {})["starter"][FIRST]["content"]
    assert "import secrets\n" in text and "os.environ.setdefault('SECRET_KEY', secrets.token_hex(32))" in text, text
    assert "'SECRET_KEY', '" not in text, text
    own = _write(tmp_path / "own", {"lantern/firsttests.py": Path(firsttests.__file__).read_text(encoding="utf-8")})
    assert websec.inline_secrets(own) == [], websec.inline_secrets(own)
    _write(root, {FIRST: text})
    found = [f for f in scan(build_graph(root), offline=True)["findings"] if f.get("file") == FIRST]
    assert not [f for f in found if f["tool"] in ("gitleaks", "lantern-secrets") or f.get("cwe") == 798], found
    # a project whose app reads no secret gets no `secrets` line
    text = _assess(tmp_path / "plain", MADE_LATER, seen=False)["starter"][FIRST]["content"]
    assert "secrets" not in text and "import os\n" in text, text


HOME_ROUTE ="\n\n@router.get('/')\ndef home():\n    return {'page': 'home'}\n"
MADE_LATER = {  # the app made by a function, its routes on a router of their own
    "notes/__init__.py": "",
    "notes/main.py": "from fastapi import FastAPI\n\nfrom notes.routes import router\n\n\ndef create_app():\n"
                     "    app = FastAPI()\n    app.include_router(router)\n    return app\n",
    "notes/routes.py": "from fastapi import APIRouter\n\nrouter = APIRouter()\n" + HOME_ROUTE}
IN_A_FOLDER = {  # the app in a folder that is no package, loaded the way Python loads it there
    "backend/main.py": "from fastapi import APIRouter, FastAPI\n\nfrom pages import router\n\napp = FastAPI()\n"
                       "app.include_router(router)\n",
    "backend/pages.py": "from fastapi import APIRouter\n\nrouter = APIRouter()\n" + HOME_ROUTE}


@pytest.mark.parametrize("files, says", [(MADE_LATER, ("from notes.main import create_app", "app = create_app()")),
                                         (IN_A_FOLDER, ("'backend'", "from main import app"))],
                         ids=["made-by-a-function", "in-a-folder"])
def test_the_first_test_file_makes_the_app_the_way_the_code_does(tmp_path, files, says):
    root = _write(tmp_path / "p", files)
    text = _assess(root, {}, seen=False)["starter"][FIRST]["content"]
    for words in says:
        assert words in text, text
    _write(root, {FIRST: text})
    ran = _first_run(root)
    assert ran.returncode == 0 and "1 passed" in ran.stdout, ran.stdout + ran.stderr


def test_the_first_test_file_is_written_only_where_lantern_can_import_the_app(tmp_path):
    # a path written in the code that is no plain path: never put into the file as code or as a comment
    odd = NOTES_MAIN.replace("@app.post('/contact')", "@app.post('/contact\\nimport os; os.remove(\"x\")')")
    text = _assess(tmp_path / "o", {**NOTES, "notes/main.py": odd})["starter"][FIRST]["content"]
    assert "os.remove" not in text and "\nimport os;" not in text, text
    compile(text, FIRST, "exec")
    # Express, or a FastAPI app in a folder whose name Python cannot import: the list, and no file
    rd = _assess(tmp_path / "e", {"server.js": "const express = require('express');\nconst app = express();\n"
                                               "app.delete('/notes/:id', (req, res) => res.json({}));\n"
                                               "app.listen(3000);\n"}, seen=False)
    assert FIRST not in rd["starter"] and _crit(rd, "tests")["write"], _crit(rd, "tests")
    rd = _assess(tmp_path / "d", {"my-app/__init__.py": "", "my-app/main.py": NOTES_MAIN.replace(
        "from notes import ai\n", "")}, seen=False)
    assert FIRST not in rd["starter"], rd["starter"].get(FIRST)


# ------------------------------------------------------------------------------------------------ what it is tied to
def test_the_record_is_tied_to_the_code_the_libraries_the_settings_and_the_tools(tmp_path):
    files = {**CLEAN, "requirements.txt": "requests==2.31.0\n"}
    rd = _assess(tmp_path, files, {"offline": True, **RAN_OK})
    b = rd["release"]["bound_to"]
    assert b["code"]["files"] == len(files) and len(b["code"]["sha256"]) == 64 and b["code"]["not_read"] == 0
    assert list(b["dependencies"]["files"]) == ["requirements.txt"] and b["dependencies"]["count"] == 1
    assert b["settings"]["offline"] is True and b["settings"]["trace"] == ["pytest", "-q"]
    assert b["settings"]["plan_sha256"] is None and b["settings"]["accepted_sha256"] is None
    tools = {t["tool"]: t for t in b["tools"]}
    assert tools["lantern"]["version"] and tools["bandit"]["state"] == "ok" and "python" in tools
    assert b["commit"] is None and b["uncommitted_changes"] is None

    def again(change):
        change()
        return _assess(tmp_path, {}, {"offline": True, **RAN_OK})["release"]["bound_to"]

    same = again(lambda: None)
    assert same["code"] == b["code"] and same["dependencies"] == b["dependencies"]
    one = again(lambda: (tmp_path / "README.md").write_text("# Clean\n\nA sample!\n", encoding="utf-8"))
    assert one["code"]["sha256"] != b["code"]["sha256"] and one["dependencies"] == b["dependencies"]
    two = again(lambda: (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8"))
    assert two["dependencies"]["sha256"] != b["dependencies"]["sha256"]
    moved = again(lambda: (tmp_path / "README.md").rename(tmp_path / "READ.md"))
    assert moved["code"]["sha256"] != one["code"]["sha256"] and moved["code"]["files"] == one["code"]["files"]


def test_the_results_folder_is_not_part_of_the_code(tmp_path):
    _write(tmp_path, CLEAN)
    before = release.code_digest(tmp_path)
    _write(tmp_path, {".lantern/security.json": "{}", ".git/HEAD": "ref: refs/heads/main\n"})
    assert release.code_digest(tmp_path) == before


# ------------------------------------------------------------------------------------- end to end, and what shows it
# No library at all, so the sandbox needs nothing from this computer but Python and pytest.
SUMS = {"sums.py": "def add(a, b):\n    return a + b\n",
        "tests/test_sums.py": "from sums import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        "README.md": "# Sums\n\nA sample.\n"}


def test_a_project_reaches_passed_only_by_having_its_tests_run_and_pass(tmp_path, monkeypatch):
    """The whole way, as a person would go it: no record is handed in, the tests are run in the sandbox."""
    from lantern import pipeline
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    cmd = ["python", "-m", "pytest", "-q"]

    def decision(name, files, trace):
        repo = _write(tmp_path / name, files)
        res = pipeline.analyze(repo, tmp_path / (name + "-out"), trace_cmd=cmd if trace else None, sandbox=True,
                               offline=True, log=lambda m: None)
        rd = json.loads((tmp_path / (name + "-out") / "readiness.json").read_text(encoding="utf-8"))
        assert res["release"] == rd["release"]["decision"]
        return rd

    not_run = decision("a", SUMS, False)
    assert not_run["release"]["decision"] == "Incomplete" and not_run["release"]["missing"] == ["tests"]
    ran = decision("b", SUMS, True)
    assert ran["release"]["decision"] == "Passed", ran["release"]["words"]
    assert ran["score"] == ran["checklist"] > not_run["checklist"]
    fails = decision("c", {**SUMS, "sums.py": "def add(a, b):\n    return a - b\n"}, True)
    assert fails["release"]["decision"] == "Blocked" and fails["release"]["blocking"] == ["tests"], fails["release"]["words"]
    assert fails["score"] <= release.BLOCKED_CAP


def test_the_command_line_says_the_decision_and_can_demand_one(tmp_path, capsys):
    from lantern.cli import main
    broken, clean = _write(tmp_path / "broken", {**BROKEN, **KEPT}), _write(tmp_path / "clean", CLEAN)
    run = lambda repo, n, *more: main(["analyze", str(repo), "--out", str(tmp_path / f"o{n}"), "--offline", *more])
    # said in every run, demanded only when asked
    assert run(broken, 1) == 0
    assert "release Blocked" in capsys.readouterr().out
    assert run(broken, 2, "--require", "not-blocked") == 1
    assert "release decision is Blocked" in capsys.readouterr().err
    # Incomplete (the tests were not run): nothing blocks, and it is not a pass
    assert run(clean, 3, "--require", "not-blocked") == 0
    assert run(clean, 4, "--require", "passed") == 1
    err = capsys.readouterr().err
    assert "release decision is Incomplete" in err and "tests" in err


def test_the_report_page_draws_the_decision_from_fixed_words_and_ci_poisons_the_rest():
    root = Path(__file__).parents[1]
    html = lantern_files.page("report.html")
    assert "const DECISION_TONE = {Blocked: 'critical', Incomplete: 'warning', Passed: 'good'};" in html
    assert "function releaseBox(" in html and "lantern readiness . --json" not in html     # no such command exists
    audit = (root / "tools" / "audit.sh").read_text(encoding="utf-8")
    assert "--only criteria,profile,bound_to,blocking,missing" in audit


# ----------------------------------------------------------------- read back from a file: the connector, Ask, cards
def test_a_decision_read_back_from_a_file_is_taken_by_its_shape():
    """readiness.json lies in the results folder, which may come with the project: only one of the three words is
    a decision, and what stands beside it is cut to plain text of a bounded length."""
    for odd in (None, {}, {"release": "Passed"}, {"release": {"decision": "Passed<script>"}}, {"release": ["Passed"]},
                {"release": {"decision": ["Passed"]}}):
        assert release.shown(odd) is None, odd
    v = release.shown({"release": {"decision": "Blocked", "words": 5, "criteria": [
        {"id": "findings", "state": "failed", "title": "t", "why": "w" * 5000, "required": True},
        "x", {"id": "tests", "state": "odd"}, {"id": "behaviour", "state": "missing", "required": False}]}})
    assert v["decision"] == "Blocked" and v["words"] == ""
    assert [c["id"] for c in v["criteria"]] == ["findings", "behaviour"] and len(v["criteria"][0]["why"]) == 1000
    assert v["blocking"] == ["findings"] and v["missing"] == []          # what is not required is not missing


def _analyzed(tmp_path, files):
    from lantern import pipeline
    repo = _write(tmp_path / "proj", files)
    pipeline.analyze(repo, pipeline.out_dir(repo), log=lambda m: None, offline=True)
    return repo


def test_the_connector_and_ask_lantern_say_the_decision(tmp_path):
    from lantern import ask
    from lantern.mcp_server import Projects, Server
    repo = _analyzed(tmp_path, BROKEN)
    s = Server(Projects([str(repo)]))
    call = lambda name, **args: s.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                          "params": {"name": name, "arguments": args}})["result"]
    r = call("lantern_readiness", project="proj")
    assert "Release decision: Blocked" in r["content"][0]["text"], r["content"][0]["text"]
    rel = r["structuredContent"]["release"]
    assert rel["decision"] == "Blocked" and rel["blocking"] == ["findings"] and "tests" in rel["missing"]
    assert next(c for c in rel["criteria"] if c["id"] == "findings")["state"] == "failed"
    p = call("lantern_projects")
    assert p["structuredContent"]["projects"][0]["release"] == "Blocked" and "release Blocked" in p["content"][0]["text"]
    facts = ask.facts(repo)
    assert "Release decision: Blocked" in facts and "B602" in facts
    # results an older Lantern wrote have no decision: nothing is made up for them
    out = repo / ".lantern"
    old = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    del old["release"]
    (out / "readiness.json").write_text(json.dumps(old), encoding="utf-8")
    r = call("lantern_readiness", project="proj")
    assert r["structuredContent"]["release"] is None and "Release decision" not in r["content"][0]["text"]
    assert "Release decision" not in ask.facts(repo)


def test_the_apps_card_carries_the_decision_and_only_one_of_the_three_words(tmp_path, monkeypatch):
    from lantern.server import App, Store
    repo = _analyzed(tmp_path, BROKEN)
    app = App(Store(tmp_path / "home"), "tok", 0)
    p = app.store.add_project(repo)
    assert app.summary(p)["release"] == "Blocked"
    out = repo / ".lantern"
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    rd["release"]["decision"] = "<img src=x onerror=alert(1)>"
    (out / "readiness.json").write_text(json.dumps(rd), encoding="utf-8")
    assert app.summary(p)["release"] is None
    page = lantern_files.page("app.html")
    assert "const RELEASE_TONE = {Blocked: 'critical', Incomplete: 'warning', Passed: 'good'};" in page


# --- Lantern's own check of itself (tools/self_readiness.py, a step of CI) ---------------------------------------

def _own(decision, missing=(), failed=(), skips=(), score=95, grade="A"):
    crit = [{"id": i, "title": i.title(), "required": True, "why": f"why {i}", "fix": "",
             "state": "failed" if i in failed else "missing" if i in missing else "passed"}
            for i in ("findings", "scanners", "dependencies", "tests", "browser")]
    checks = [{"id": "tests-exist", "status": "pass", "evidence": "12 test files"}]
    checks += [{"id": i, "status": "skip", "evidence": "not run", **({"required": True} if req else {})}
               for i, req in skips]
    rd = {"version": 2, "score": score, "grade": grade, "checklist": score, "shape": "library",
          "categories": [{"key": "tests", "checks": checks}]}
    if decision:
        rd["release"] = {"decision": decision, "words": f"{decision}: words", "criteria": crit,
                         "blocking": list(failed), "missing": list(missing)}
    return rd


OWN_CHECK = {
    "passed": (_own("Passed"), 0),
    "incomplete only because this check does not run the tests":
        (_own("Incomplete", missing=("tests",), skips=(("tests-pass", True),)), 0),
    "incomplete only because this check runs neither the tests nor a browser":
        (_own("Incomplete", missing=("tests", "browser"), skips=(("tests-pass", True),)), 0),
    "a skipped check nothing depends on": (_own("Passed", skips=(("secrets-gitignore", False),)), 0),
    # ... and what must stop CI
    "blocked": (_own("Blocked", failed=("findings",), score=59, grade="F"), 1),
    "blocked, with a grade somebody wrote back to A": (_own("Blocked", failed=("findings",)), 1),
    "incomplete because libraries were not checked": (_own("Incomplete", missing=("dependencies",)), 1),
    "incomplete for the tests and for something else":
        (_own("Incomplete", missing=("tests", "scanners"), skips=(("tests-pass", True),)), 1),
    "a required check skipped that nobody allowed": (_own("Passed", skips=(("deps-vuln", True),)), 1),
    "the word Passed over a criterion that is missing": ({**_own("Incomplete", missing=("dependencies",)),
                                                         "release": {**_own("Incomplete", missing=("dependencies",))["release"],
                                                                     "decision": "Passed"}}, 1),
    "no release decision in the file": (_own(None), 1),
}


@pytest.mark.parametrize("case", sorted(OWN_CHECK))
def test_lanterns_own_check_reads_the_decision_and_names_every_skip(tmp_path, capsys, case):
    """Until this stage the self-check passed over every skipped check without a word, so "tests not run" counted
    as nothing wrong. Now it fails on Blocked, on a decision that is missing anything but the one thing this check
    cannot have (it reads the code and never runs the tests: CI's test jobs do), and on a required check that was
    skipped and is not on its short list; what it lets through it prints, with the reason."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("self_readiness", Path(__file__).parents[1] / "tools" / "self_readiness.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rd, want = OWN_CHECK[case]
    p = tmp_path / "readiness.json"
    p.write_text(json.dumps(rd), encoding="utf-8")
    code = mod.main(["self_readiness.py", str(p)])
    out = capsys.readouterr().out
    assert code == want, out
    assert ("PASS" in out.splitlines()[-1]) == (want == 0), out
    if case.startswith("incomplete only"):
        assert "release Incomplete" in out and "allowed missing tests" in out and "allowed skip" in out, out
        assert "tests-pass" in out and "CI" in out, out            # the reason says who does run them
    if case == "incomplete only because this check runs neither the tests nor a browser":
        assert "allowed missing browser" in out and "lantern browse" in out, out   # and why its pages are not opened
    if case == "a skipped check nothing depends on":
        assert "skip" in out and "secrets-gitignore" in out, out   # said, even though it stops nothing
    if case == "no release decision in the file":
        assert "no release decision" in out, out


# --- the one check of Lantern's own that may fail: its website's image starts as root ----------------------------

def _self_readiness():
    import importlib.util
    spec = importlib.util.spec_from_file_location("self_readiness", Path(__file__).parents[1] / "tools" / "self_readiness.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SWITCHER_CMD = ('CMD ["python", "-I", "-m", "lantern_cloud.switcher", "--", \\\n'
                '     "uvicorn", "lantern_cloud.app:create_app", "--factory"]\n')
WEBSITE_IMAGE = ('FROM golang:1.26 AS tools\nRUN go install example.com/tool@v1\n'
                 'FROM python:3.12-slim\nRUN pip install .\n# the image starts as root for its switcher (a comment)\n'
                 'RUN useradd --uid 1000 app\n'
                 'ENV LANTERN_CLOUD_DB=/home/app/data/db \\\n    LANTERN_CLOUD_DATA=/home/app/data \\\n'
                 '    LANTERN_CLOUD_SERVICE_USER=app \\\n    LANTERN_CLOUD_STEPS_APART=required \\\n'
                 '    PYTHONUNBUFFERED=1\n' + SWITCHER_CMD)
GATEWAY_IMAGE = 'FROM python:3.12-slim\nRUN useradd app\nUSER app\nCMD ["uvicorn", "gateway.app:create_app"]\n'
PLAIN_IMAGE = 'FROM python:3.12-slim\nCMD ["python", "-m", "http.server"]\n'


def _website(cmd: str = SWITCHER_CMD, **env: str) -> dict:
    """The website's image with another command, or with settings changed (None: the line taken out)."""
    text = WEBSITE_IMAGE.replace(SWITCHER_CMD, cmd)
    for name, value in env.items():
        line = next(x for x in text.splitlines(keepends=True) if f"LANTERN_CLOUD_{name}=" in x)
        text = text.replace(line, "" if value is None else line.replace(line.split("=", 1)[1].split()[0], value))
    return {"cloud/Dockerfile": text, "gateway/Dockerfile": GATEWAY_IMAGE}


ROOT_IMAGE = {
    "as the repository has it": ({"cloud/Dockerfile": WEBSITE_IMAGE, "gateway/Dockerfile": GATEWAY_IMAGE}, 0),
    "the setting in the older form": (_website(SWITCHER_CMD.replace("CMD", "ENV LANTERN_CLOUD_STEPS_APART required\nCMD"),
                                               STEPS_APART=None), 0),
    "an image in the tests' own folders": ({"cloud/Dockerfile": WEBSITE_IMAGE, "gateway/Dockerfile": GATEWAY_IMAGE,
                                            "tests/fixtures/app/Dockerfile": PLAIN_IMAGE}, 0),
    "Python named by its full path": (_website(SWITCHER_CMD.replace('"python"', '"/usr/local/bin/python3"')), 0),
    # ... and where the reason no longer holds, the failure stops CI as any other does
    "the service started directly, not by its switcher": (_website('CMD ["uvicorn", "lantern_cloud.app:create_app"]\n'),
                                                          1),
    "the switcher only in a comment": (_website("# " + SWITCHER_CMD.replace(" \\\n    ", " ")
                                                + 'CMD ["uvicorn", "lantern_cloud.app:create_app"]\n'), 1),
    "the switcher started by a shell": (_website("CMD python -I -m lantern_cloud.switcher -- uvicorn x:app\n"), 1),
    "the switcher behind an entry point": (_website('ENTRYPOINT ["/bin/sh", "-c"]\n' + SWITCHER_CMD), 1),
    "a program of the image's own run before it": (_website(
        'CMD ["python", "-I", "start.py", "-m", "lantern_cloud.switcher", "--", "uvicorn", "x:app"]\n'), 1),
    "the switcher with no command for the service": (_website(
        'CMD ["python", "-I", "-m", "lantern_cloud.switcher", "--"]\n'), 1),
    "the service's user is root": (_website(SERVICE_USER="root"), 1),
    "the service's user is root by number": (_website(SERVICE_USER="0"), 1),
    "the service's user is nobody": (_website(SERVICE_USER="nobody"), 1),
    "no user named for the service": (_website(SERVICE_USER=None), 1),
    "no folder of the service's own": (_website(DATA=None), 1),
    "a folder of the service's own named by a relative path": (_website(DATA="data"), 1),
    "the image no longer keeps each check's steps apart": ({"cloud/Dockerfile": WEBSITE_IMAGE.replace(
        "STEPS_APART=required", "STEPS_APART=off"), "gateway/Dockerfile": GATEWAY_IMAGE}, 1),
    "the setting only in a comment": ({"cloud/Dockerfile": PLAIN_IMAGE.replace(
        "CMD", "# ENV LANTERN_CLOUD_STEPS_APART=required\nCMD"), "gateway/Dockerfile": GATEWAY_IMAGE}, 1),
    "the setting in a stage before the image's own": ({"cloud/Dockerfile": "FROM golang:1.26 AS tools\n"
        "ENV LANTERN_CLOUD_STEPS_APART=required\n" + PLAIN_IMAGE, "gateway/Dockerfile": GATEWAY_IMAGE}, 1),
    "the setting taken back further down": ({"cloud/Dockerfile": WEBSITE_IMAGE.replace(
        "CMD", "ENV LANTERN_CLOUD_STEPS_APART=\"\"\nCMD"), "gateway/Dockerfile": GATEWAY_IMAGE}, 1),
    "another image that runs as root": ({"cloud/Dockerfile": WEBSITE_IMAGE,
                                         "gateway/Dockerfile": GATEWAY_IMAGE.replace("USER app", "USER 0:0")}, 1),
    "another image with no user of its own": ({"cloud/Dockerfile": WEBSITE_IMAGE, "gateway/Dockerfile": GATEWAY_IMAGE,
                                               "Dockerfile": PLAIN_IMAGE}, 1),
    "another image whose user is only in an earlier stage": ({"cloud/Dockerfile": WEBSITE_IMAGE,
        "gateway/Dockerfile": "FROM python:3.12-slim AS build\nUSER app\n" + PLAIN_IMAGE}, 1),
    "no website image at all": ({"gateway/Dockerfile": GATEWAY_IMAGE}, 1),
}


# Why each case where the switcher is not first, or the service's user or folder is not named, is refused
NOT_FIRST, NO_USER, NO_FOLDER = "does not start its switcher first", "names no ordinary user", "names no folder"
ROOT_IMAGE_WHY = {
    "the service started directly, not by its switcher": NOT_FIRST, "the switcher only in a comment": NOT_FIRST,
    "the switcher started by a shell": NOT_FIRST, "the switcher behind an entry point": NOT_FIRST,
    "a program of the image's own run before it": NOT_FIRST, "the switcher with no command for the service": NOT_FIRST,
    "the service's user is root": NO_USER, "the service's user is root by number": NO_USER,
    "the service's user is nobody": NO_USER, "no user named for the service": NO_USER,
    "no folder of the service's own": NO_FOLDER, "a folder of the service's own named by a relative path": NO_FOLDER,
    "the image no longer keeps each check's steps apart": "LANTERN_CLOUD_STEPS_APART=required",
}


def _image_run(tmp_path, files, checks):
    repo = tmp_path / "repo"
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    rd = _own("Incomplete", missing=("tests",), skips=(("tests-pass", True),))
    rd["categories"].append({"key": "packaging", "checks": checks})
    p = tmp_path / "readiness.json"
    p.write_text(json.dumps(rd), encoding="utf-8")
    return _self_readiness().main(["self_readiness.py", str(p)], root=repo)


ROOT_FAILS = [{"id": "pkg-user", "status": "fail", "evidence": "no USER line, so it runs as root"}]


@pytest.mark.parametrize("case", sorted(ROOT_IMAGE))
def test_the_website_image_may_start_as_root_only_while_it_keeps_each_checks_steps_apart(tmp_path, capsys, case):
    """The owner's answer of 2026-11-20: the website's image starts as root, so that it can run each check's steps
    as a user of that check's own (only root can switch to another user), and root is narrowed to the small part
    that starts the steps (its switcher, the image's first program, which starts the service as an ordinary user it
    names). Lantern's readiness check of a container (`pkg-user`) fails for such an image, and the self-check fails
    on any failed check: this one may fail, said every time with its reason, and only while the repository still
    shows that reason (the image starts its switcher first, with an ordinary user and a folder of the service's own
    named, requires the steps apart, and every other image of the project names a user that is not root)."""
    files, want = ROOT_IMAGE[case]
    code = _image_run(tmp_path, files, ROOT_FAILS)
    out = capsys.readouterr().out
    assert code == want, out
    assert "pkg-user" in out, out
    if want == 0:
        assert "allowed fail" in out and "2026-11-20" in out and out.splitlines()[-1] == "PASS", out
    else:
        assert "allowed only while" in out and out.splitlines()[-1].startswith("FAIL"), out
        assert ROOT_IMAGE_WHY.get(case, "") in out, out


def test_beside_it_any_other_failed_check_stops_ci_as_before(tmp_path, capsys):
    files = ROOT_IMAGE["as the repository has it"][0]
    code = _image_run(tmp_path, files, ROOT_FAILS + [{"id": "pkg-slim", "status": "fail", "evidence": "FROM python:3.12"}])
    out = capsys.readouterr().out
    assert code == 1 and "pkg-slim" in out and "allowed fail" in out, out


def test_an_allowance_no_longer_used_is_said(tmp_path, capsys):
    """When the website's image names a user again (or the check reads another image), the list says it can go."""
    files = ROOT_IMAGE["as the repository has it"][0]
    code = _image_run(tmp_path, files, [{"id": "pkg-user", "status": "pass", "evidence": "USER app"}])
    out = capsys.readouterr().out
    assert code == 0 and "pkg-user passed here" in out, out


def test_lanterns_own_repository_shows_why_its_website_image_starts_as_root():
    """The repository as it is: what CI's step will find. When the image stops keeping the steps apart, or another
    image loses its user, this fails here first and names the reason."""
    mod = _self_readiness()
    assert set(mod.ALLOWED_FAIL) == {"pkg-user"}
    for cid, (_why, holds) in mod.ALLOWED_FAIL.items():
        assert holds(Path(__file__).parents[1]) is None, (cid, holds(Path(__file__).parents[1]))


# --- the held-out benchmark reads the decision (bench/heldout/run_heldout.py) ------------------------------------

def _heldout():
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_heldout_for_test",
                                                  Path(__file__).parents[1] / "bench" / "heldout" / "run_heldout.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _app(name, kind, decision, missing=(), blocking=()):
    why = {i: f"why {i}" for i in (*missing, *blocking)}
    return {"name": name, "kind": kind, "stack": "python", "complete": True, "expectations": [], "call_sites": {},
            "loud_findings": [], "scanners": [], "findings": {"by_rank": {}},
            "readiness": {"score": 80, "grade": "B", "shape": "x"},
            "release": {"decision": decision, "basis": "readiness.json release gate", "missing": list(missing),
                        "blocking": list(blocking), "why": why}}


def test_the_held_out_benchmark_counts_only_blocked_as_refused_and_lists_incomplete_apart():
    """The owner's decision of 2026-11-11: a clean app counts as refused a green release only when it reads Blocked.
    The benchmark never runs an app's tests, so every app reads Incomplete at best: those are listed apart, each
    with what is missing, and the older count (anything but Passed) stays in the table beside the new one."""
    h = _heldout()
    apps = [_app("clean-a", "clean", "Incomplete", missing=("tests",)),
            _app("clean-b", "clean", "Blocked", blocking=("findings",)),
            _app("clean-c", "clean", "Passed"),
            _app("clean-d", "clean", "Incomplete", missing=("tests", "dependencies")),
            _app("vuln-a", "vulnerable", "Blocked", blocking=("findings",)),
            _app("vuln-b", "vulnerable", "Incomplete", missing=("tests",)),
            _app("vuln-c", "vulnerable", "Passed")]
    s = h.summarize(apps)
    assert s["clean_apps"] == 4 and s["clean_apps_refused"] == ["clean-b"]
    assert s["clean_apps_incomplete"] == [{"name": "clean-a", "missing": ["tests"]},
                                          {"name": "clean-d", "missing": ["tests", "dependencies"]}]
    assert s["clean_apps_not_passed"] == ["clean-a", "clean-b", "clean-d"]          # the count before this stage
    assert s["vulnerable_apps_given_green"] == ["vuln-c"]
    assert s["vulnerable_apps_blocked"] == ["vuln-a"] and s["vulnerable_apps_incomplete"] == ["vuln-b"]
    page = h.markdown({"label": "t", "engine": "e", "definition_sha256": "0" * 64, "ran_at": "now", "offline": True,
                       "apps": apps, "summary": s})
    assert "| Clean apps Blocked (refused a green release) | 1 / 4 (clean-b) |" in page
    assert "| Clean apps Incomplete (not refused: evidence is missing) | 2 / 4 (clean-a, clean-d) |" in page
    assert "| Clean apps not Passed (the count before the release decision) | 3 / 4 (clean-a, clean-b, clean-d) |" in page
    assert "| Vulnerable apps given a green release (Passed) | 1 / 3 (vuln-c) |" in page
    assert "| Vulnerable apps Blocked | 1 / 3 (vuln-a) |" in page
    assert "| Vulnerable apps Incomplete, not Blocked | 1 / 3 (vuln-b) |" in page
    assert "- release Incomplete · missing: tests (why tests); dependencies (why dependencies)" in page
    assert "- release Blocked · failed: findings (why findings)" in page


def test_the_held_out_benchmark_takes_the_decision_from_the_result_file(tmp_path):
    h = _heldout()
    rd = _assess(tmp_path, {**CLEAN, "go.mod": "module x\n\ngo 1.22\n"}, {})      # tests not run, Go libraries unchecked
    rel = h.release_of(rd, [])
    assert rel["decision"] == "Incomplete" and rel["missing"] == ["dependencies", "tests"] and rel["blocking"] == []
    assert "Go" in rel["why"]["dependencies"] and "not run" in rel["why"]["tests"]
    # a result file written before the decision existed is read by the older rule, and says so
    old = h.release_of({"score": 90}, [{"rank": "high"}])
    assert old["decision"] == "Blocked" and old["basis"].startswith("badge rule") and old["missing"] == []
