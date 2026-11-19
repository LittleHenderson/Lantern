"""The badge a check is shared with, and the page it links to (roadmap of 2026-11-14, stage 6, part 3).

The badge the app and the website serve is drawn from a results folder, which a project can bring along, so it is
drawn from the parts of the record the badge shows, each in its own shape (`evidence.badge_record`). The page a
shared badge links to (`evidence.check_html`, `/s/<slug>/check.html` on the website, tests in test_cloud_share.py)
names the commit, a fingerprint of the code, the release decision, how many of the scanners that apply finished,
and one line that repeats the check: what it says the check found is read from the part of the record the results
fingerprint is made of, so the line, which makes that fingerprint again, checks it.
"""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from lantern import evidence, server
from lantern.cli import main

COMMIT = "a" * 40
APP = {"app.py": "import hashlib\n\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n\n"
                 "if __name__ == '__main__':\n    h(b'x')\n"}
LINK = "https://github.com/octo/notes"


def _said(svg: str) -> str:
    """The words a badge shows."""
    return " ".join(re.findall(r"<text[^>]*>([^<]*)</text>", svg))


def _colour(svg: str) -> str:
    return re.search(r'<rect x="58"[^>]*fill="(#[0-9A-Fa-f]{6})"', svg).group(1)


def _record(out: Path, decision: str | None, unfinished=(), critical: int = 0, high: int = 0) -> dict:
    ev = {"header": {"commit": COMMIT, "generated_at": "2026-11-17 18:00 UTC"},
          "scorecard": {"now": {"critical": critical, "high": high, "medium": 0, "low": 0}},
          "release": {"decision": decision, "criteria": []} if decision else None,
          "security": {"incomplete": [{"tool": t, "state": "failed"} for t in unfinished]}}
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
    (out / "readiness.json").write_text(json.dumps({"score": 90, "grade": "A"}), encoding="utf-8")
    return ev


@pytest.mark.parametrize("decision, unfinished, words, colour", [
    ("Incomplete", ("bandit",), "scan incomplete", "#64748B"),
    ("Incomplete", (), "incomplete", "#64748B"),
    ("Blocked", (), "blocked", "#B54708"),      # blocked by its tests or a behaviour check: no finding is open
])
def test_the_badge_the_app_serves_says_what_the_release_decision_says(tmp_path, decision, unfinished, words, colour):
    ev = _record(tmp_path / "out", decision, unfinished)
    code, body, ctype, _ = server.result_page(tmp_path / "out", "badge.svg")
    assert code == 200 and ctype == "image/svg+xml"
    assert body == evidence.badge_svg(90, "A", ev)        # the badge drawn from the whole record
    assert words in _said(body) and _colour(body) == colour


def test_a_passed_release_and_a_report_with_no_decision_keep_their_green_badge(tmp_path):
    for decision in ("Passed", None):         # None: a report an older Lantern made, read by the older rule
        ev = _record(tmp_path / str(decision), decision)
        body = server.result_page(tmp_path / str(decision), "badge.svg")[1]
        assert body == evidence.badge_svg(90, "A", ev) and _colour(body) == "#0D9488"
        assert "incomplete" not in _said(body) and "blocked" not in _said(body)
    _record(tmp_path / "high", "Blocked", high=1)
    assert _colour(server.result_page(tmp_path / "high", "badge.svg")[1]) == "#B54708"


def test_a_planted_record_puts_none_of_its_own_words_on_the_badge(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    ev = {"header": {"commit": "<b>x</b>", "generated_at": ["2026-11-17"]},
          "scorecard": {"now": {"critical": "9", "high": True}},
          "release": {"decision": "Passed<script>"}, "security": {"incomplete": "bandit"}}
    (out / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
    (out / "readiness.json").write_text(json.dumps({"score": "100", "grade": "A<"}), encoding="utf-8")
    body = server.result_page(out, "badge.svg")[1]
    assert "<script" not in body and "Passed" not in body and "<b>" not in body
    assert evidence.badge_record(ev) == {"header": {"commit": "bb", "generated_at": None},
                                         "scorecard": {"now": {"critical": 0, "high": 0}}}
    assert evidence.badge_record("not a record") == {"header": {"commit": None, "generated_at": None},
                                                     "scorecard": {"now": {}}}


# ------------------------------------------------------------------------------------------- the check page
def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "HOME": str(root),
                        "GIT_CONFIG_NOSYSTEM": "1"})


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    """A small project of one commit, checked offline the way the website checks one (results outside it)."""
    repo = tmp_path_factory.mktemp("project") / "notes"
    repo.mkdir()
    for rel, text in APP.items():
        (repo / rel).write_text(text, encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    out = repo.parent / "out"
    assert main(["analyze", str(repo), "--out", str(out), "--offline"]) == 0
    return repo, out, json.loads((out / "evidence.json").read_text(encoding="utf-8"))


def _line(page: str) -> str:
    import html
    return html.unescape(re.search(r"<pre class='line'><code>(.*?)</code></pre>", page, re.S).group(1))


def test_the_check_page_names_the_commit_the_code_the_decision_the_scanners_and_the_line(checked):
    repo, out, ev = checked
    commit = ev["payload"]["commit"]
    code = ev["release"]["bound_to"]["code"]["sha256"]
    page = evidence.check_html(ev, LINK)
    assert "<script" not in page and f"<code>{commit}</code>" in page and code[:12] in page
    assert ev["release"]["decision"] in ("Passed", "Incomplete", "Blocked") and ev["release"]["decision"] in page
    f = evidence.check_facts(ev, LINK)
    unfinished = {t["tool"] for t in ev["security"]["incomplete"]}
    ran = {r["tool"] for r in ev["provenance"]["tools"] if r.get("role") == "scanner" and r.get("state") == "ok"}
    assert f["whole"] and set(f["finished"]) == ran and {n for n, _ in f["left"]} == unfinished
    assert f["percent"] == 100 * len(ran) // (len(ran) + len(unfinished))
    assert f"{len(ran)} of {len(ran) + len(unfinished)} that apply finished and left out nothing they read" in page
    engine = ev["header"]["engine"]
    assert _line(page) == (f"git clone {LINK} lantern-check && cd lantern-check && git checkout {commit} && "
                           f"pip install \"lantern[scan] @ git+https://github.com/LittleHenderson/Lantern@{engine}\" && "
                           f"lantern verify . --digest {ev['digest']} --offline")
    assert f["criteria"] and len(f["criteria"]) == len(ev["payload"]["readiness"]["release"]["criteria"])
    for cid, state in f["criteria"]:
        # the page escapes every value, the titles too (an apostrophe is written as `&#x27;`)
        assert f"{evidence.E(evidence.release.TITLES[cid])}: <b>{evidence.CRITERION_SAYS[state]}</b>" in page


def test_the_logo_on_the_page_leads_to_lantern_and_the_guide_is_one_click_away(checked):
    """As on every page of Lantern: the logo does something (here it opens the website, which says what Lantern is),
    and "How to use Lantern" is there."""
    page = evidence.check_html(checked[2], LINK)
    top = re.search(r"<div class='topbar'>(.*?)</div>", page, re.S).group(1)
    brand = re.search(r"<a class='brand' href='/'[^>]*>(.*?)</a>", top, re.S)
    assert brand and "<svg class='mark'" in brand.group(1) and "<b>Lantern</b>" in brand.group(1)
    assert re.search(r"<a class='btn' id='guidelink' href='/guide'[^>]*>How to use Lantern</a>", top)


def test_the_line_on_the_page_makes_the_same_fingerprint_on_that_commit(checked, tmp_path, capsys):
    """What the page promises: the line run on another computer ends with MATCH. Here the copy of the project is
    made from its folder in place of its link, and the Lantern that runs it is this one."""
    repo, out, ev = checked
    line = _line(evidence.check_html(ev, LINK))
    commit = re.search(r"git checkout ([0-9a-f]{40})", line).group(1)
    digest = re.search(r"--digest (sha256:[0-9a-f]{64})", line).group(1)
    copy = tmp_path / "lantern-check"
    subprocess.run(["git", "clone", "-q", str(repo), str(copy)], check=True, capture_output=True)
    _git(copy, "checkout", "-q", commit)
    assert main(["verify", str(copy), "--digest", digest, "--offline"]) == 0
    assert "MATCH" in capsys.readouterr().out
    (copy / "app.py").write_text(APP["app.py"].replace("md5", "sha256"), encoding="utf-8")
    _git(copy, "commit", "-qam", "another")         # another commit: the line no longer matches
    assert main(["verify", str(copy), "--digest", digest, "--offline"]) == 1


def test_a_record_that_does_not_hold_together_gets_no_line(checked):
    repo, out, ev = checked
    for change in ({"commit": "b" * 40}, {"readiness": {**ev["payload"]["readiness"], "release": {
            **ev["payload"]["readiness"]["release"], "decision": "Passed"}}} if ev["release"]["decision"] != "Passed"
            else {"lantern": "0.0.1"}):
        planted = {**ev, "payload": {**ev["payload"], **change}}    # the facts changed, the fingerprint not
        f = evidence.check_facts(planted, LINK)
        page = evidence.check_html(planted, LINK)
        assert not f["whole"] and evidence.check_line(f) == (None, evidence.NOT_WHOLE)
        assert "b" * 40 not in page and "<pre" not in page and "does not hold together" in page
        assert f["decision"] is None and f["commit"] is None
    assert evidence.check_facts({**ev, "digest": "sha256:" + "0" * 64}, LINK)["whole"] is False
    assert evidence.check_facts({**ev, "payload": "x"}, LINK)["whole"] is False


@pytest.mark.parametrize("link", [
    "https://github.com/octo/notes$(touch x)", "https://github.com/octo/no`te`s", "https://github.com/octo/nötes",
    "https://[::1]/octo/notes", "lantern:upload/notes", "lantern:sample/notes", "https://x@github.com/octo/notes",
    "file:///etc", "", None, 7])
def test_a_link_that_is_not_plainly_one_is_no_part_of_the_line(checked, link):
    repo, out, ev = checked
    f = evidence.check_facts(ev, link)
    line, beside = evidence.check_line(f)
    assert f["link"] is None and f["name"] is None
    assert line.startswith(f"git checkout {ev['payload']['commit']} && ") and "Run it in a copy" in beside
    page = evidence.check_html(ev, link)
    assert "touch" not in page and "`" not in page and "::1" not in page and "lantern-check" not in page


def test_the_link_is_the_one_its_parts_make(checked):
    repo, out, ev = checked
    for typed in ("https://github.com/octo/notes.git", "https://GitHub.com/octo/notes/", "git@github.com:octo/notes.git",
                  "https://github.com/octo/notes/tree/main"):
        assert evidence.check_facts(ev, typed)["link"] == LINK, typed


def test_checks_a_page_line_cannot_repeat_say_why(checked):
    repo, out, ev = checked
    f = evidence.check_facts(ev, LINK)
    for change, word in (({"trace": True}, "tests"), ({"typecheck": True}, "type checkers"),
                         ({"workspace": True}, "several projects"), ({"commit": None}, "no commit"),
                         ({"uncommitted": True}, "no commit")):
        line, why = evidence.check_line({**f, **change})
        assert line is None and word in why
    assert evidence.check_line({**f, "offline": False})[0].endswith(f"--digest {ev['digest']}")
    assert evidence.check_line({**f, "scan": False})[0].endswith("--offline --no-scan")
    assert ' && pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern" && ' in evidence.check_line(
        {**f, "engine": None})[0]


def test_odd_values_in_the_record_are_left_out_of_the_page(checked):
    repo, out, ev = checked
    planted = json.loads(json.dumps(ev))
    planted["header"]["engine"] = "main; curl x"
    planted["header"]["generated_at"] = "<i>today</i>"
    planted["security"]["incomplete"] = [{"tool": "<b>bandit</b>", "state": "failed"}, {"tool": ["x"]}, "bandit", 7]
    planted["scorecard"]["now"] = {"critical": "<b>", "high": -3}
    page = evidence.check_html(planted, LINK)
    f = evidence.check_facts(planted, LINK)
    assert f["whole"] and f["engine"] is None and f["when"] is None and f["left"] == []
    assert "curl" not in page and "<i>" not in page and "<b>bandit" not in page and "&lt;b&gt;" not in page
    assert "git+https://github.com/LittleHenderson/Lantern\"" in _line(page)      # the newest Lantern, said plainly


def test_what_the_page_says_the_check_found_is_what_the_line_checks(checked):
    """The parts of a record outside its fingerprint decide nothing the page says the check found: counts kept beside
    it are not shown (the decision's own part says whether a critical or high finding is open), and a scanner the
    fingerprinted part names as having covered only part of the project, or as not having finished, counts as one
    that did not finish whether or not the record's list of such scanners names it."""
    repo, out, ev = checked
    before = evidence.check_facts(ev, LINK)
    planted = json.loads(json.dumps(ev))
    planted["scorecard"]["now"] = {"critical": 7, "high": 5, "medium": 0, "low": 0}
    planted["payload"]["scanners"] = sorted(planted["payload"]["scanners"] + ["probe-a:1.0:er", "probe-b:2.1:pa"])
    planted["digest"] = evidence.digest(planted["payload"])
    f = evidence.check_facts(planted, LINK)
    page = evidence.check_html(planted, LINK)
    assert f["whole"] and "7 critical" not in page and "5 high" not in page and "Open findings" not in page
    assert dict(f["left"])["probe-a"] == "failed" and dict(f["left"])["probe-b"] == "partial"
    assert "probe-a did not finish" in page and "probe-b covered only part of the project" in page
    assert len(f["left"]) == len(before["left"]) + 2 and f["applies"] == len(f["finished"]) + len(f["left"])
    # the record's list says which way a scanner did not finish only where that agrees with the fingerprinted part
    planted["security"]["incomplete"] += [{"tool": "probe-a", "state": "timeout"}, {"tool": "probe-b", "state": "ok"}]
    left = dict(evidence.check_facts(planted, LINK)["left"])
    assert left["probe-a"] == "timeout" and left["probe-b"] == "partial"
    # twin: a scanner that was skipped had work to do only where the record's own list says so
    skipped = json.loads(json.dumps(ev))
    skipped["payload"]["scanners"] = sorted(skipped["payload"]["scanners"] + ["probe-c:1.0:sk"])
    skipped["digest"] = evidence.digest(skipped["payload"])
    assert "probe-c" not in dict(evidence.check_facts(skipped, LINK)["left"])
    skipped["security"]["incomplete"].append({"tool": "probe-c", "state": "unavailable"})
    assert dict(evidence.check_facts(skipped, LINK)["left"])["probe-c"] == "unavailable"
    assert evidence.check_facts(skipped, LINK)["applies"] == before["applies"] + 1


def test_the_app_builds_the_page_from_the_results_and_never_sends_a_file_of_them(checked, tmp_path):
    repo, out, ev = checked
    code, body, ctype, headers = server.check_page(out, LINK)
    assert code == 200 and ctype.startswith("text/html") and body == evidence.check_html(ev, LINK)
    assert headers["Content-Security-Policy"] == evidence.CHECK_POLICY and "script" not in evidence.CHECK_POLICY
    (tmp_path / "check.html").write_text("<script>planted</script>", encoding="utf-8")
    assert server.check_page(tmp_path, LINK)[0] == 404             # no evidence.json: nothing to show
    (tmp_path / "evidence.json").write_text("[1, 2]", encoding="utf-8")
    assert server.check_page(tmp_path, LINK)[0] == 404
    (tmp_path / "evidence.json").write_text(json.dumps({"payload": {"commit": 1}, "digest": 5}), encoding="utf-8")
    code, body, _ctype, _h = server.check_page(tmp_path, LINK)
    assert code == 200 and "does not hold together" in body and "planted" not in body
