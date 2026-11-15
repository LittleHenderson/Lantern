"""What Lantern leaves on the repository it checked (lantern/onrepo.py, action.yml): the comment, the saved report and
the badge, and the one command that puts them on a repository.

The words are built from result files that may come with the project, so every planted value is shown beside the
ordinary report that must read well: a title that tries to mention a person, link out, show an image or break the
table stays text, and a file of the wrong shape gives a report with no decision, never an error."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys

import pytest
import yaml

import lantern_files
from lantern import onrepo, results
from lantern.cli import main as cli_main
from lantern.pipeline import analyze

FIXTURES = lantern_files.ROOT / "tests" / "fixtures"
GIT = shutil.which("git")
COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64


def _ev(decision="Blocked", *, title="Use of weak MD5 hash", file="shop/auth.py", words=None, **extra):
    crit = [{"id": "findings", "title": "No critical or high finding is open", "required": True,
             "state": "failed" if decision == "Blocked" else "passed", "why": "1 critical finding is open",
             "fix": "Fix it"},
            {"id": "tests", "title": "The project's tests were run and passed", "required": True,
             "state": "passed" if decision == "Passed" else "missing", "why": "", "fix": "Run them"}]
    ev = {"header": {"commit": COMMIT, "generated_at": "2026-11-15 10:00 UTC", "engine": "c" * 40, "dirty": False},
          "scorecard": {"now": {"critical": 1, "high": 0, "medium": 2, "low": 3},
                        "readiness": {"score": 59, "grade": "F"}},
          "security": {"open": [{"id": "x1", "rank": "critical", "rule": "B324", "title": title, "file": file,
                                 "line": 18}], "accepted": [], "incomplete": []},
          "release": {"decision": decision, "words": words if words is not None else f"{decision}: reason",
                      "criteria": crit},
          "digest": DIGEST}
    ev.update(extra)
    return ev


# --------------------------------------------------------------------------- the words

@pytest.mark.parametrize("decision,mark", [("Passed", "🟢"), ("Blocked", "🔴"), ("Incomplete", "🟡")])
def test_each_decision_is_said_with_its_word_and_its_meaning(decision, mark):
    text = onrepo.summary(_ev(decision))
    assert text.startswith(onrepo.MARKER + "\n")
    assert f"## {mark} Lantern: {decision}" in text
    assert onrepo.LOOK[decision][2] in text
    assert "| 1 | 0 | 2 | 3 |" in text
    assert COMMIT in text and DIGEST in text
    assert "lantern verify . --report ../lantern-evidence.json" in text
    assert onrepo.decision_of(_ev(decision)) == decision


def test_a_report_with_no_decision_or_of_another_shape_says_so_and_does_not_fail():
    for ev in ({}, None, {"release": {"decision": "Shipped!"}}, {"header": [], "scorecard": "x", "security": 5,
                                                                "release": [], "digest": 7}):
        text = onrepo.summary(ev)
        assert "Lantern: No decision" in text
        assert onrepo.decision_of(ev) == "none"


POISON = ("@octocat look #12 ![x](https://evil.example/p.png) <img src=x onerror=alert(1)> [click](http://evil) "
          "www.evil.example | a | b `code` $math$ \n## heading\n")


def test_a_planted_title_file_and_words_stay_text():
    text = onrepo.summary(_ev(title=POISON, file="a`b@c/<x>.py\n# h", words=POISON), short=True)
    body = text.split("<details>")[0]
    assert "@octocat" not in body and "@​octocat" in body           # no mention of a person
    assert "#12" not in body                                             # no reference to an issue
    assert "](http" not in body and "![" not in body                     # no link, no image
    assert "<img" not in body and "&lt;img" in body                       # no HTML
    assert "https://evil" not in body and "http://evil" not in body       # no bare link GitHub would make
    assert "www.evil" not in body
    assert "\n## heading" not in body                                    # no line of its own
    assert "`a'b@c/<x>.py # h:18`" in body                                # a file is a code span, its backtick taken out
    finding = [ln for ln in body.splitlines() if ln.startswith("- **critical**")]
    assert len(finding) == 1


def test_links_are_only_githubs_own():
    good = "https://github.com/o/r/actions/runs/1"
    text = onrepo.summary(_ev(), run_url=good, report_url="https://evil.example/report.zip")
    assert f"({good})" in text and "evil.example" not in text
    assert "javascript:" not in onrepo.summary(_ev(), run_url="javascript:alert(1)")


def test_a_long_report_is_cut_to_what_github_takes():
    many = [{"id": f"x{i}", "rank": "low", "title": "t" * 300, "file": "f.py", "line": i} for i in range(5000)]
    ev = _ev()
    ev["security"]["open"] = many
    assert len(onrepo.summary(ev)) <= onrepo.MOST_COMMENT
    assert onrepo.summary(ev, short=True).count("\n- **low**") == onrepo.TOP_COMMENT


def test_findings_are_listed_most_serious_first_and_heuristics_say_so():
    ev = _ev()
    ev["security"]["open"] = [{"rank": "low", "title": "L", "file": "a", "line": 1},
                              {"rank": "high", "title": "H", "file": "b", "line": 2, "tool_confidence": "LOW"}]
    text = onrepo.summary(ev)
    assert text.index("**high** · H") < text.index("**low** · L")
    assert "heuristic" in text.split("**high** · H")[1].splitlines()[0]


# --------------------------------------------------------------------------- the saved report

def _git(cwd, *args):
    return subprocess.run([GIT, *args], cwd=cwd, check=True, capture_output=True, text=True, encoding="utf-8").stdout


@pytest.fixture
def checked(tmp_path):
    """The shop sample as a git repository, checked once (offline), with its results apart."""
    if not GIT:
        pytest.skip("git is not installed")
    repo = tmp_path / "shop"
    shutil.copytree(FIXTURES / "shop", repo)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x")
    out = tmp_path / "results"
    analyze(repo, out, offline=True)
    return repo, out


def test_the_saved_report_is_the_check_itself_and_verifies(checked, tmp_path):
    repo, out = checked
    written = onrepo.save(repo, out, run_url="https://github.com/o/r/actions/runs/1")
    names = sorted(p.name for p in written)
    assert names == ["README.md", "badge.svg", "evidence.html", "evidence.json"]
    folder = repo / ".lantern" / "report"
    assert (folder / "evidence.json").read_text(encoding="utf-8") == (out / "evidence.json").read_text(encoding="utf-8")
    readme = (folder / "README.md").read_text(encoding="utf-8")
    assert "Lantern: Blocked" in readme and "evidence.html` in this folder" in readme
    commit = _git(repo, "rev-parse", "HEAD").strip()
    assert commit in readme and commit[:7] in (folder / "badge.svg").read_text(encoding="utf-8")
    # the report folder is no code of the project: the next check of the same commit finds the same results
    shutil.copy(folder / "evidence.json", tmp_path / "kept.json")
    r = subprocess.run([sys.executable, "-m", "lantern.cli", "verify", str(repo), "--report", str(tmp_path / "kept.json")],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0 and "MATCH" in r.stdout, r.stdout + r.stderr


def test_the_report_is_not_saved_through_a_link_that_came_with_the_project(checked, tmp_path):
    repo, out = checked
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    try:
        (repo / ".lantern").symlink_to(elsewhere, target_is_directory=True)
    except OSError:
        pytest.skip("this system does not let this user make a link")
    with pytest.raises(results.Refused):
        onrepo.save(repo, out)
    assert list(elsewhere.iterdir()) == []


def test_save_needs_a_finished_check(tmp_path):
    with pytest.raises(results.Refused):
        onrepo.save(tmp_path, tmp_path / "nothing")


# --------------------------------------------------------------------------- setup

def test_setup_puts_lantern_on_a_repository_and_a_second_run_changes_nothing(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "README.md").write_text("# My app\n\nIt does things.\n", encoding="utf-8")
    (repo / ".gitignore").write_text("node_modules/\n.lantern/\n", encoding="utf-8")
    done = onrepo.setup(repo, ref="v0.12.0")
    wf = yaml.safe_load((repo / onrepo.WORKFLOW).read_text(encoding="utf-8"))
    on = wf.get("on", wf.get(True))
    assert on["push"]["paths-ignore"] == [".lantern/report/**"]        # merging the report starts no new report
    assert "pull_request" in on
    assert wf["permissions"] == {"contents": "write", "pull-requests": "write"}
    steps = wf["jobs"]["lantern"]["steps"]
    assert steps[1]["uses"] == "LittleHenderson/Lantern@v0.12.0" and steps[1]["with"]["require"] == "not-blocked"
    readme = (repo / "README.md").read_text(encoding="utf-8").splitlines()
    assert readme[:3] == ["# My app", "", onrepo.BADGE_LINE]
    assert (repo / ".lantern/report/README.md").read_text(encoding="utf-8").startswith(onrepo.MARKER)
    assert "no analysis yet" in (repo / ".lantern/report/badge.svg").read_text(encoding="utf-8")
    assert ".lantern/*\n!.lantern/report/" in (repo / ".gitignore").read_text(encoding="utf-8")
    assert len(done) == 4
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    again = onrepo.setup(repo, ref="v0.12.0")
    assert {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()} == before
    assert any("already" in d for d in again)


@pytest.mark.skipif(not GIT, reason="git is not installed")
def test_after_setup_git_keeps_the_report_folder_and_still_ignores_the_rest(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / ".gitignore").write_text(".lantern/\n", encoding="utf-8")
    onrepo.setup(repo, ref="main", readme=False)
    (repo / ".lantern" / "graph.json").write_text("{}", encoding="utf-8")
    listed = _git(repo, "status", "--porcelain", "--untracked-files=all")
    assert ".lantern/report/README.md" in listed and ".lantern/report/badge.svg" in listed
    assert "graph.json" not in listed


def test_setup_leaves_a_workflow_that_is_not_lanterns_unless_told(tmp_path):
    wf = tmp_path / onrepo.WORKFLOW
    wf.parent.mkdir(parents=True)
    wf.write_text("name: mine\n", encoding="utf-8")
    with pytest.raises(results.Refused):
        onrepo.setup(tmp_path, ref="main")
    assert wf.read_text(encoding="utf-8") == "name: mine\n"
    onrepo.setup(tmp_path, ref="main", force=True)
    assert "LittleHenderson/Lantern@main" in wf.read_text(encoding="utf-8")


def test_setup_with_no_readme_says_which_line_to_add(tmp_path):
    done = onrepo.setup(tmp_path, ref="main")
    assert any(onrepo.BADGE_LINE in d for d in done)
    assert not (tmp_path / "README.md").exists()


def test_which_version_of_the_action_a_new_workflow_names():
    assert onrepo.action_ref("d" * 40) == "d" * 40
    assert onrepo.action_ref("v0.12.0") == "v0.12.0"
    assert onrepo.action_ref("v1.0.0") == "v1.0.0"
    assert onrepo.action_ref("v0.11.0") == "main"          # that release holds no Action
    assert onrepo.action_ref("") == "main"
    for bad in ("main; rm -rf /", "x\ny", "a b", ""):
        with pytest.raises(ValueError):
            onrepo.workflow(bad)


def test_the_command(checked, capsys):
    repo, out = checked
    assert cli_main(["github", "summary", str(repo), "--out", str(out), "--decision-only"]) == 0
    assert capsys.readouterr().out == "Blocked\n"
    assert cli_main(["github", "summary", str(repo), "--out", str(out), "--short"]) == 0
    assert capsys.readouterr().out.startswith(onrepo.MARKER)
    assert cli_main(["github", "save", str(repo), "--out", str(out), "--to", "docs/lantern"]) == 0
    assert (repo / "docs/lantern/README.md").is_file()
    assert cli_main(["github", "setup", str(repo), "--ref", "main"]) == 0
    assert "Allow GitHub Actions to create and approve pull requests" in capsys.readouterr().out


# --------------------------------------------------------------------------- the Action

ACTION = lantern_files.ROOT / "action.yml"


def _steps():
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]


def test_every_script_of_the_action_is_valid_shell_and_takes_outside_values_only_from_its_environment():
    bash = shutil.which("bash")
    runs = [s for s in _steps() if "run" in s]
    assert len(runs) == 6
    for s in runs:
        # a value written into a script by ${{ }} is run as part of it: a branch name could become a command
        assert "${{" not in s["run"], s["name"]
        assert s["shell"] == "bash"
        if bash:
            r = subprocess.run([bash, "-n"], input=s["run"], capture_output=True, text=True, encoding="utf-8")
            assert r.returncode == 0, (s["name"], r.stderr)


def test_the_action_uses_versioned_steps_and_writes_only_where_github_allows():
    steps = _steps()
    for s in steps:
        if "uses" in s:
            assert re.fullmatch(r"actions/[a-z-]+@v\d+", s["uses"]), s["uses"]
    names = {s["name"] if "name" in s else s["uses"]: s for s in steps}
    assert names["Comment on the pull request"]["if"].startswith("github.event_name == 'pull_request'")
    save = names["Save the report through a pull request"]
    assert "github.event_name != 'pull_request'" in save["if"]
    assert "default_branch" in save["if"]
    assert "lantern/report" in save["run"] and "git add -f" in save["run"]
    inputs = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["inputs"]
    assert inputs["require"]["default"] == "not-blocked" and inputs["save-report"]["default"] == "pull-request"
    docs = (lantern_files.ROOT / "docs" / "github.md").read_text(encoding="utf-8")
    for name in inputs:
        assert f"`{name}`" in docs, name


@pytest.mark.skipif(not shutil.which("bash"), reason="bash is not installed")
@pytest.mark.parametrize("require,decision,fails", [
    ("not-blocked", "Blocked", True), ("not-blocked", "Incomplete", False), ("not-blocked", "Passed", False),
    ("passed", "Incomplete", True), ("passed", "none", True), ("passed", "Passed", False),
    ("none", "Blocked", False), ("sometimes", "Passed", True)])
def test_the_last_step_passes_or_fails_on_the_decision(require, decision, fails):
    step = next(s for s in _steps() if s.get("name") == "Pass or fail this check")
    r = subprocess.run([shutil.which("bash"), "-c", step["run"]], capture_output=True, text=True, encoding="utf-8",
                       env={"REQUIRE": require, "DECISION": decision, "PATH": "/usr/bin:/bin"})
    assert (r.returncode != 0) == fails, r.stdout
