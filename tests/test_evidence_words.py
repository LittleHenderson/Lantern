"""What the Evidence Report says about what it read (2026-11-19, from a comparison with another review tool on one
project): the project's own story is labelled as its own, low findings of one kind are folded into one row and none
is lost, the findings in test code can be opened one by one, and the scanners' line says no more than they did."""
import json
import re

from lantern import evidence, release
from lantern.cli import main

from test_evidence import _repo, _write


def _ev(repo):
    return json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))


def test_the_projects_own_story_is_said_to_be_its_own(tmp_path):
    repo = _repo(tmp_path)
    (repo / evidence.NARRATIVES_FILE).write_text("# Payments\n\nEvery payment is checked twice.\n", encoding="utf-8")
    assert main(["analyze", str(repo), "--no-scan"]) == 0
    html = (repo / ".lantern/evidence.html").read_text(encoding="utf-8")
    at = html.index("<h2>6 · Understanding")
    part = html[at:html.index("</section>", at)]
    assert "the project's own" in part and "did not check them" in part and "checked twice" in part


def test_low_findings_of_one_kind_are_folded_and_none_is_lost(tmp_path):
    repo = _repo(tmp_path)
    _write(repo, {f"m{i}.py": "import subprocess\n" for i in range(5)})
    assert main(["analyze", str(repo), "--offline"]) == 0
    ev = _ev(repo)
    b404 = [f for f in ev["security"]["open"] if f["rule"] == "B404"]
    assert len(b404) == 5
    html = evidence.render_html(ev)
    assert "5 places in 5 files" in html
    for f in b404:      # each place is still a row
        assert f"{f['file']}:{f['line']}" in html


def test_findings_in_test_code_can_be_opened_one_by_one(tmp_path):
    repo = _repo(tmp_path)
    _write(repo, {"tests/test_a.py": "import hashlib\n\ndef test_a():\n    assert hashlib.md5(b'x')\n"})
    assert main(["analyze", str(repo), "--offline"]) == 0
    ev = _ev(repo)
    assert ev["security"]["in_tests"] >= 1 and ev["security"]["in_tests_open"]
    html = evidence.render_html(ev)
    assert re.search(r"<details><summary class='muted'>\d+ more finding\(s\) are in test code only", html)
    assert "tests/test_a.py:" in html


def test_an_older_report_without_the_list_still_shows_the_count(tmp_path):
    repo = _repo(tmp_path)
    _write(repo, {"tests/test_a.py": "import hashlib\n\ndef test_a():\n    assert hashlib.md5(b'x')\n"})
    assert main(["analyze", str(repo), "--offline"]) == 0
    ev = _ev(repo)
    ev["security"].pop("in_tests_open")
    assert "more finding(s) are in test code only.</p>" in evidence.render_html(ev)


def test_the_scanners_line_promises_no_more_than_they_did():
    assert "covered everything" not in release.TITLES["scanners"]
    assert "left out nothing it reads" in release.TITLES["scanners"]


def test_the_score_says_its_points_are_not_runs(tmp_path):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo), "--no-scan"]) == 0
    html = (repo / ".lantern/evidence.html").read_text(encoding="utf-8")
    assert "not from running anything" in html
