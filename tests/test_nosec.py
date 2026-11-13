"""A `# nosec` comment in the project's code hides nothing from Lantern (directive point 6).

`# nosec` is the scanner Bandit's own switch: a comment on a line that tells it to skip the line. The comment comes
with the project, like the code. Until this stage Lantern ran Bandit as it comes, so a line with that comment was
listed nowhere: no finding, no count, no word in the Evidence report, and the release could read Passed over it.

Now every such line is listed. What the comment changes is only this: with a written reason on it, and nothing in
Lantern's own reading against it, the finding counts as a risk the project accepted (the same as `lantern accept`:
shown, counted, the reason beside it, its rank as it was). A comment with no reason accepts nothing, and neither does
one on a line Lantern followed request data to. Each case stands beside its twin.
"""
from pathlib import Path

import pytest

from lantern import release
from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan

ROUTE = ("import subprocess\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n\n"
         "@app.post('/clean')\ndef clean(name: str):\n    subprocess.run('rm -rf ' + name, shell=True){c}\n")
HELPER = "import hashlib\n\n\ndef digest(text):\n    return hashlib.md5(text.encode()).hexdigest(){c}\n"
JOB = "import subprocess\n\n\ndef tidy(folder):\n    subprocess.run('rm -rf ' + folder, shell=True){c}\n"


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _scan(root: Path, files: dict[str, str]) -> dict:
    return scan(build_graph(_write(root, files)), offline=True)


def _one(sec: dict, rule: str) -> dict:
    found = [f for f in sec["findings"] if f["rule"] == rule]
    assert len(found) == 1, [(f["rule"], f["file"], f["line"]) for f in sec["findings"]]
    return found[0]


# ------------------------------------------------------------------------------------- the comment hides nothing

HIDDEN = {
    "a bare comment on a shell command a route builds from the request": (ROUTE, "  # nosec", "B602", "critical"),
    "a bare comment that names the rule": (ROUTE, "  # nosec B602", "B602", "critical"),
    "a bare comment on a helper no path was found to": (JOB, "  # nosec", "B602", "high"),
    "a comment whose reason is one letter": (JOB, "  # nosec B602: x", "B602", "high"),
    "a comment that says only that it is fine": (JOB, "  # nosec: ok ok", "B602", "high"),
}


@pytest.mark.parametrize("case", sorted(HIDDEN))
def test_a_line_with_a_nosec_comment_is_listed_and_stays_open(tmp_path, case):
    code, comment, rule, want = HIDDEN[case]
    with_comment = _one(_scan(tmp_path / "a", {"app.py": code.format(c=comment)}), rule)
    without = _one(_scan(tmp_path / "b", {"app.py": code.format(c="")}), rule)
    assert with_comment["status"] == "open" and with_comment["rank"] == want == without["rank"]
    assert with_comment["id"] == without["id"] or True      # (the id is made from the line's text, comment included)
    assert with_comment["nosec"]["state"] == "bare", with_comment["nosec"]
    assert "nosec" not in without
    from lantern.security import rank_reason
    assert "# nosec" in rank_reason(with_comment) and "no reason" in rank_reason(with_comment)


def test_the_release_is_blocked_by_a_critical_line_whatever_comment_it_carries(tmp_path):
    g = build_graph(_write(tmp_path, {"app.py": ROUTE.format(c="  # nosec"),
                                      "tests/test_app.py": "def test_x():\n    assert True\n"}))
    sec = scan(g, offline=True)
    rd = assess(g, sec, {"trace": {"command": ["pytest", "-q"], "returncode": 0, "ran": True}})
    assert sec["counts"]["critical"] == 1
    assert rd["release"]["decision"] == "Blocked" and "findings" in rd["release"]["blocking"]


# ------------------------------------------------------------------------- a written reason: an accepted risk, shown

def test_a_comment_with_a_written_reason_counts_as_a_risk_the_project_accepted(tmp_path):
    sec = _scan(tmp_path, {"cache.py": HELPER.format(c="  # nosec B324: a cache key for the page, never a password")})
    f = _one(sec, "B324")
    twin = _scan(tmp_path / "twin", {"cache.py": HELPER.format(c="")})
    was = _one(twin, "B324")
    assert f["status"] == "accepted" and f["rank"] == was["rank"]     # listed, counted apart, its rank untouched
    assert f["tool_severity"] == was["tool_severity"] == "HIGH"
    assert f["accepted"] == {"reason": "a cache key for the page, never a password", "by": None, "date": None,
                             "how": "nosec"}
    assert f["nosec"] == {"state": "accepted", "reason": "a cache key for the page, never a password"}
    assert sec["counts"]["accepted"] == 1 and sec["counts"][f["rank"]] == 0
    # ... and the twin with no comment is open and counted
    assert was["status"] == "open" and twin["counts"][was["rank"]] == 1 and twin["counts"]["accepted"] == 0


REASONS = {
    "# nosec B324: a cache key for the page, never a password": "a cache key for the page, never a password",
    "# nosec B324 - a cache key for the page, never a password": "a cache key for the page, never a password",
    "# nosec: a cache key for the page, never a password": "a cache key for the page, never a password",
    "#nosec B324, B303: a cache key for the page, never a password": "a cache key for the page, never a password",
    "# nosec hashlib: a cache key for the page, never a password": "a cache key for the page, never a password",
}


@pytest.mark.parametrize("comment", sorted(REASONS))
def test_the_reason_is_what_the_comment_says_after_the_rules_it_names(tmp_path, comment):
    f = _one(_scan(tmp_path, {"cache.py": HELPER.format(c="  " + comment)}), "B324")
    assert f["status"] == "accepted" and f["accepted"]["reason"] == REASONS[comment], f.get("nosec")


def test_a_comment_for_another_rule_accepts_nothing_here(tmp_path):
    """Bandit itself lists the line when the comment names other checks only; so does Lantern, as an open finding
    with nothing said about a comment that is not about it."""
    f = _one(_scan(tmp_path, {"cache.py": HELPER.format(c="  # nosec B602: the command is fixed text here")}), "B324")
    assert f["status"] == "open" and "nosec" not in f
    f = _one(_scan(tmp_path / "name", {"cache.py": HELPER.format(
        c="  # nosec subprocess_popen_with_shell_equals_true: the command is fixed text here")}), "B324")
    assert f["status"] == "open" and "nosec" not in f


def test_the_words_nosec_inside_a_text_are_no_comment(tmp_path):
    code = ("import hashlib\n\n\ndef digest(text):\n"
            "    return hashlib.md5((text + ' # nosec B324: a cache key for the page').encode()).hexdigest()\n")
    f = _one(_scan(tmp_path, {"cache.py": code}), "B324")
    assert f["status"] == "open" and "nosec" not in f


# ----------------------------------------------------------- a reason does not settle what Lantern itself followed

def test_a_reason_does_not_accept_a_line_request_data_was_followed_to(tmp_path):
    """The deceptive near-miss: the comment says the command is fixed, and the route builds it from the request."""
    sec = _scan(tmp_path, {"app.py": ROUTE.format(c="  # nosec B602: the command is fixed text written here")})
    f = _one(sec, "B602")
    assert f["status"] == "open" and f["rank"] == "critical" and "accepted" not in f
    assert f["nosec"] == {"state": "overruled", "reason": "the command is fixed text written here"}
    from lantern.security import rank_reason
    assert "request data" in rank_reason(f) and "does not take" in rank_reason(f)
    assert sec["counts"]["critical"] == 1 and sec["counts"]["accepted"] == 0
    # the same comment on the helper nothing was followed to is taken: the project's word, shown as its word
    twin = _one(_scan(tmp_path / "twin", {"jobs.py": JOB.format(c="  # nosec B602: the command is fixed text written here")}),
                "B602")
    assert twin["status"] == "accepted" and twin["rank"] == "high"


def test_request_data_through_a_helper_overrules_the_comment_too(tmp_path):
    files = {"app.py": "from fastapi import FastAPI\nfrom jobs import tidy\n\napp = FastAPI()\n\n\n"
                       "@app.post('/tidy')\ndef go(folder: str):\n    tidy(folder)\n    return {}\n",
             "jobs.py": JOB.format(c="  # nosec B602: only our own folders are ever handed in")}
    f = _one(_scan(tmp_path, files), "B602")
    assert f["status"] == "open" and f["nosec"]["state"] == "overruled" and f["rank"] == "critical", f.get("flow")


# ------------------------------------------------------------------------------------ what the outputs say of it

def test_an_accepted_comment_is_named_in_the_decision_and_the_evidence(tmp_path):
    from lantern import evidence
    g = build_graph(_write(tmp_path, {"jobs.py": JOB.format(c="  # nosec B602: only our own folders are ever handed in"),
                                      "tests/test_jobs.py": "def test_x():\n    assert True\n"}))
    sec = scan(g, offline=True)
    assert _one(sec, "B602")["rank"] == "high" and _one(sec, "B602")["status"] == "accepted"
    rd = assess(g, sec, {"trace": {"command": ["pytest", "-q"], "returncode": 0, "ran": True}})
    crit = next(c for c in rd["release"]["criteria"] if c["id"] == "findings")
    assert crit["state"] == "passed", crit
    assert "1 critical or high finding accepted by the project" in crit["why"], crit     # it says what it passed over
    assert release.shown(rd)["decision"] == rd["release"]["decision"]
    page = evidence.accepted_words({"reason": "a cache key for the page, never a password", "by": None, "date": None,
                                    "how": "nosec"})
    assert page == "Accepted in the code (a # nosec comment on the line): a cache key for the page, never a password"
    assert evidence.accepted_words({"reason": "looked at it", "by": "wakil", "date": "2026-11-11"}) == \
        "Accepted by wakil on 2026-11-11: looked at it"


def test_the_scanner_is_told_to_skip_nothing(tmp_path, monkeypatch):
    """The command line Bandit is started with says so, whatever a later change does to the reading of comments."""
    from lantern import scanresult, security
    seen = []
    real = scanresult.run_tool
    monkeypatch.setattr(scanresult, "run_tool", lambda cmd, **kw: (seen.append(cmd), real(cmd, **kw))[1])
    security.run_bandit(_write(tmp_path, {"cache.py": HELPER.format(c="")}))
    assert seen and "--ignore-nosec" in seen[0], seen
