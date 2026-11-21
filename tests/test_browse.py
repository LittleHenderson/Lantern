"""The browser checks (docs/browser.md; a firm pass or fail, stage 5), held to the contract written before they were
built. Two small sites (`tests/browse_sites.py`): each written safe must break no check, and each planted problem must
break its own check with its own code and change no other.

What runs everywhere: the list on the page is the list in `lantern/browse.py`; every planted version is the safe site
but for its own pieces, and every code is planted at least once; Lantern's reading of the code says the same of the
app and of the twins only a browser can tell apart; with no browser every check says why it was not run. The tests
with a real browser run where LANTERN_TESTS_BROWSER names one by its full path (CI: its browser job)."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

import browse_sites
from browse_sites import PLANTED, SAFE
from lantern import browse

DOC = Path(__file__).resolve().parents[1] / "docs" / "browser.md"
BROWSER = os.environ.get("LANTERN_TESTS_BROWSER", "").strip() and os.path.normpath(os.environ["LANTERN_TESTS_BROWSER"].strip())
needs_browser = pytest.mark.skipif(not BROWSER, reason="no browser named for these tests (LANTERN_TESTS_BROWSER)")
SHORT = 3       # seconds a page has to answer in these tests: the site that never answers is seen sooner


def _doc_checks() -> list[tuple[str, str, list[str]]]:
    """(id, title, codes) of each check as docs/browser.md writes it."""
    text, out = DOC.read_text(encoding="utf-8"), []
    parts = re.split(r"^### `([a-z-]+)`: (.+)$", text, flags=re.M)
    for at in range(1, len(parts), 3):
        codes = re.search(r"^Codes: (.+)$", parts[at + 2], flags=re.M)
        out.append((parts[at], parts[at + 1].strip(), re.findall(r"`([a-z-]+)`", codes.group(1)) if codes else []))
    return out


def test_the_checks_are_written_down_once():
    assert _doc_checks() == [(c.id, c.title, list(c.codes)) for c in browse.CHECKS]
    codes = [code for c in browse.CHECKS for code in c.codes]
    assert len(codes) == len(set(codes)) == 24, codes          # a code says which check gave it
    assert list(browse.BY_ID) == [c.id for c in browse.CHECKS]


def test_the_outcomes_and_the_reasons_are_the_pages_own():
    text = DOC.read_text(encoding="utf-8")
    section = text.split("## Outcomes", 1)[1].split("\n## ", 1)[0]
    bullets = re.findall(r"^\* `([a-z-]+)`", section, flags=re.M)
    assert bullets == list(browse.OUTCOMES)
    reasons = re.search(r"^\* `not-run`, with the reason: (.+?)(?=^\S|\Z)", section, flags=re.M | re.S).group(1)
    assert set(re.findall(r"`([a-z-]+)`", reasons)) - set(browse.BY_ID) == set(browse.WHY_NOT)
    limits = {n for n in re.findall(r"`([A-Z]+_[A-Z_]+)`", text) if not n.startswith("LANTERN_")}
    assert limits == {"MOST_PAGES", "MOST_CLICKS", "PAGE_SECONDS"}, limits
    assert all(type(getattr(browse, n)) is int and getattr(browse, n) > 0 for n in limits)   # the code's own


@pytest.mark.parametrize("name", sorted(PLANTED))
def test_every_planted_version_is_the_safe_site_but_for_its_own_pieces(name):
    p = PLANTED[name]
    assert p.site in SAFE and p.check in browse.BY_ID and p.code in browse.BY_ID[p.check].codes, p
    safe, planted = browse_sites.files(p.site), browse_sites.files(p.site, name)
    changed = {f for f in set(safe) | set(planted) if safe.get(f) != planted.get(f)}
    assert changed == {f for f, _, _ in p.edits}, changed
    for f, old, new in p.edits:
        if old is None:
            assert f not in safe and planted[f] == new
        else:
            assert old != new and safe[f].count(old) == 1


def test_every_code_is_planted_and_every_site_says_each_check():
    planted = {(p.check, p.code) for p in PLANTED.values()}
    assert planted == {(c.id, code) for c in browse.CHECKS for code in c.codes}
    for site, want in SAFE.items():
        assert list(want) == [c.id for c in browse.CHECKS] and set(want.values()) <= set(browse.OUTCOMES), site
    for name, p in PLANTED.items():                            # a planted problem breaks a check the safe site holds
        assert SAFE[p.site][p.check] == "held", name
        assert (p.check == "outside") == bool(p.asks), name


def _reading(repo: Path):
    """What Lantern's reading of the code says of the app: each route's login, and the headers' status."""
    from lantern import engine, headers, readiness, websec
    g = engine.build_graph(repo)
    logins = {r["detail"]: r["login"] for r in websec.route_logins(
        g, lambda f: (repo / f).read_text(encoding="utf-8").splitlines())}
    return logins, headers.read(g, readiness.Repo(repo))[0]


def test_the_code_reading_cannot_tell_the_app_from_the_twins_only_a_browser_can(tmp_path):
    safe = _reading(browse_sites.write(tmp_path / "safe", "app"))
    assert safe[0].get("GET /account") in ("shown", "lookup"), safe       # the page asks who is calling
    assert safe[1] == "in place", safe                                   # a header set for every response
    for name in ("visitor-let-in", "headers-said-not-sent"):
        assert _reading(browse_sites.write(tmp_path / name, "app", name)) == safe, name


def test_with_no_browser_every_check_is_not_run_and_says_why(tmp_path):
    repo = browse_sites.write(tmp_path / "s", "pages")
    record = browse.run(repo, browser=str(tmp_path / "no-browser-here"))
    assert record["ran"] is False and record["why_not"] == "no-browser" and record["why"] == browse.WHY_NOT["no-browser"]
    assert [(c["id"], c["outcome"], c["why"]) for c in record["checks"]] == \
        [(c.id, "not-run", "no-browser") for c in browse.CHECKS]


def _box(tmp_path: Path):
    box = browse._Box(tmp_path, {}, 1, lambda line: None)
    box._where(tmp_path)
    return box, tmp_path / "browse" / "in", tmp_path / "browse" / "out"


def _answer(place: Path, text: str, owner) -> None:
    place.write_text(text, encoding="utf-8")
    if owner is not None and hasattr(os, "chown") and owner != os.getuid():
        os.chown(place, owner, owner)                  # written by the box's own user


def _link_folder(target: Path, place: Path) -> None:
    """`place` made a link to the folder `target` (on Windows a junction, which needs no right of its own)."""
    if sys.platform == "win32":
        import _winapi
        _winapi.CreateJunction(str(target), str(place))
    else:
        os.symlink(target, place)


def test_the_boxs_folder_takes_a_request_whole_and_reads_an_answer_once(tmp_path):
    box, inbox, out = _box(tmp_path)
    try:
        box._put("00000001.json", {"method": "GET", "path": "/"})
        assert os.listdir(inbox) == ["00000001.json"]                     # put in place whole, nothing beside it
        assert json.loads((inbox / "00000001.json").read_text(encoding="utf-8")) == {"method": "GET", "path": "/"}
        assert box._take("00000001.json") is None                         # no answer yet
        _answer(out / "00000001.json", '{"status": 200}', box.owner)
        assert box._take("00000001.json") == {"status": 200}
        assert os.listdir(out) == [] and box._take("00000001.json") is None
    finally:
        box.stop()


def test_the_boxs_answer_is_read_only_as_a_plain_file_of_its_own(tmp_path):
    box, inbox, out = _box(tmp_path)
    kept = tmp_path / "kept.json"
    _answer(kept, '{"status": 200, "body": "not the box\'s"}', box.owner)
    try:
        os.link(kept, out / "00000001.json")                              # a second name of a file elsewhere
        assert box._take("00000001.json") is None and kept.exists()
        if os.name == "posix":
            os.symlink(kept, out / "00000002.json")                       # a link to it
            assert box._take("00000002.json") is None and kept.exists()
        os.mkdir(out / "00000003.json")
        assert box._take("00000003.json") is None
        _answer(out / "00000004.json", '{"status": 204}', box.owner)      # the twin: a plain file of its own
        assert box._take("00000004.json") == {"status": 204}
    finally:
        box.stop()


def test_a_folder_of_the_box_put_elsewhere_by_a_link_is_not_followed(tmp_path):
    box, inbox, out = _box(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _answer(elsewhere / "00000001.json", '{"status": 200}', box.owner)
    try:
        for part in (inbox, out):
            os.rename(part, part.with_name(part.name + "-moved"))
            _link_folder(elsewhere, part)
        assert box._take("00000001.json") is None
        try:
            box._put("00000002.json", {"method": "GET", "path": "/"})
        except OSError:
            pass                                                          # refused, or written where it was made
        assert sorted(os.listdir(elsewhere)) == ["00000001.json"]         # nothing written there, nothing taken
    finally:
        box.stop()


def _program(path: Path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_where_a_browser_is_looked_for(tmp_path):
    there = _program(tmp_path / "chrome")
    assert browse.find_browser({"LANTERN_BROWSER": there}) == os.path.normpath(there)
    assert browse.find_browser({"LANTERN_BROWSER": str(tmp_path / "nothing"), "PATH": str(tmp_path)}) is None
    assert browse.find_browser({"LANTERN_BROWSER": "chrome", "PATH": str(tmp_path)}) is None    # a full path only
    if sys.platform != "win32":
        folder = tmp_path / "bin"
        folder.mkdir()
        named = _program(folder / "chromium")
        assert browse.find_browser({"PATH": str(folder)}, system="linux") == named
        assert browse.find_browser({"PATH": str(tmp_path / "empty")}, system="linux") is None
    top = tmp_path / "Programs"
    exe = top / "Google" / "Chrome" / "Application" / "chrome.exe"
    exe.parent.mkdir(parents=True)
    _program(exe)
    if sys.platform == "win32":
        assert browse.find_browser({"ProgramFiles": str(top)}, system="win32") == str(exe)
    assert browse.find_browser({"ProgramFiles": "Programs"}, system="win32") is None           # a full path only


# The command (`lantern browse`), on every system. What it prints and how it ends come from the record alone, so a
# record written by hand stands in for a run here; a run itself is tested below, with a real browser.

def _record(outcomes: dict[str, str], saw: list[dict] | None = None) -> dict:
    checks = []
    for c in browse.CHECKS:
        outcome = outcomes.get(c.id, "held")
        codes = [c.codes[0]] if outcome == "broken" else []
        checks.append({"id": c.id, "outcome": outcome, "codes": codes,
                       "saw": (saw or [{"code": c.codes[0], "page": "/"}]) if codes else [],
                       "why": "test" if outcome == "not-run" else None})
    return {"of": {"commit": None, "dirty": None, "lantern": "test"}, "ran": True, "why_not": None,
            "browser": {"name": "Chromium", "version": "1", "own_sandbox": True, "how": "test"},
            "site": {"how": "pages", "address": "http://localhost:20001", "pages": 1},
            "opened": [{"path": "/", "status": 200, "seconds": 0.1}], "checks": checks, "asked_outside": [],
            "browser_own": [], "seconds": 0.5}


def _browse(monkeypatch, tmp_path, record) -> tuple[int, Path]:
    from lantern import cli
    monkeypatch.setattr(browse, "run", lambda repo, **kw: record)
    repo = tmp_path / "site"
    repo.mkdir(exist_ok=True)
    out = tmp_path / "out"
    return cli.main(["browse", str(repo), "--out", str(out)]), out / browse.RESULT_NAME


def test_the_command_ends_with_0_only_when_a_check_held_and_none_failed(tmp_path, monkeypatch, capsys):
    held = _record({"forms": "nothing-to-check", "visitor": "nothing-to-check"})
    code, written = _browse(monkeypatch, tmp_path, held)
    said = capsys.readouterr().out
    assert code == 0, said
    assert "browse        6 held, 0 broken, 0 undecided, 2 with nothing to check, 0 not run (0.5 s; 1 pages opened)" \
        in said, said
    assert json.loads(written.read_text(encoding="utf-8")) == held
    for outcome in ("broken", "inconclusive", "not-run"):
        code, written = _browse(monkeypatch, tmp_path, _record({"script": outcome}))
        said = capsys.readouterr().out
        assert code == 1, (outcome, said)
        assert f"{outcome:13} script: " in said, said
        assert json.loads(written.read_text(encoding="utf-8"))["checks"][1]["outcome"] == outcome
    code, _ = _browse(monkeypatch, tmp_path, _record({c.id: "nothing-to-check" for c in browse.CHECKS}))
    assert code == 1, capsys.readouterr().out             # a run that held nothing is no pass


def test_what_the_browser_saw_reaches_the_terminal_printable_only(tmp_path, monkeypatch, capsys):
    planted = {"code": "error", "page": "/‮", "line": "\x1b]0;a title\x07\x1b[2J" + " " + "x\x85y"}
    code, written = _browse(monkeypatch, tmp_path, _record({"script": "broken"}, saw=[planted]))
    said = capsys.readouterr().out
    assert code == 1, said
    assert "broken        script: " in said, said
    assert not any(not ch.isprintable() for line in said.splitlines() for ch in line), repr(said)
    plain = {"code": "error", "page": "/index.html", "line": "Uncaught TypeError: x is not a function"}
    code, written = _browse(monkeypatch, tmp_path, _record({"script": "broken"}, saw=[plain]))
    said = capsys.readouterr().out
    assert "Uncaught TypeError: x is not a function" in said and "/index.html" in said, said   # the twin is said as it is


def test_the_command_says_why_nothing_was_opened_and_still_writes_the_record(tmp_path, capsys):
    from lantern import cli
    assert cli.main(["browse", str(tmp_path / "nothing-here")]) == 2
    assert "is not a folder" in capsys.readouterr().err
    repo = browse_sites.write(tmp_path / "s", "pages")
    out = tmp_path / "o1"
    assert cli.main(["browse", str(repo), "--out", str(out), "--browser", str(tmp_path / "no-browser-here")]) == 3
    said = capsys.readouterr().out
    assert f"not run       {browse.WHY_NOT['no-browser']}" in said, said
    record = json.loads((out / browse.RESULT_NAME).read_text(encoding="utf-8"))
    assert (record["ran"], record["why_not"]) == (False, "no-browser")
    assert {c["outcome"] for c in record["checks"]} == {"not-run"}
    bare = tmp_path / "bare"
    bare.mkdir()
    stand_in = _program(tmp_path / ("chrome.exe" if sys.platform == "win32" else "chrome"))   # never started here
    out = tmp_path / "o2"
    code = cli.main(["browse", str(bare), "--out", str(out), "--browser", stand_in])
    why = json.loads((out / browse.RESULT_NAME).read_text(encoding="utf-8"))["why_not"]
    if sys.platform.startswith(browse.BUILT_FOR):
        assert (code, why) == (2, "no-site"), capsys.readouterr()
    else:
        assert (code, why) == (3, "not-built"), capsys.readouterr()


# With a real browser (LANTERN_TESTS_BROWSER).

@pytest.fixture
def the_browser(request):
    """The browser this run was told of. A run told of one that is not there fails; one that ran is named."""
    assert os.path.isabs(BROWSER) and os.path.isfile(BROWSER), f"LANTERN_TESTS_BROWSER names no program: {BROWSER!r}"

    def said(record):
        ran = getattr(request.config, "_lantern_ran_against", None)
        if ran is None:
            ran = request.config._lantern_ran_against = {}
        b = record.get("browser") or {}
        ran["browser"] = f"{b.get('name') or 'of a name it did not tell'} {b.get('version') or ''}".strip()
    return said


def _outcomes(record) -> dict[str, str]:
    return {c["id"]: c["outcome"] for c in record["checks"]}


def _codes(record, check: str) -> list[str]:
    return sorted({s["code"] for c in record["checks"] if c["id"] == check for s in c.get("saw") or []})


@needs_browser
@pytest.mark.parametrize("site", sorted(SAFE))
def test_each_site_written_safe_breaks_no_check(tmp_path, site, the_browser):
    record = browse.run(browse_sites.write(tmp_path / site, site), browser=BROWSER)
    the_browser(record)
    assert record["ran"] is True, (record.get("why_not"), record.get("why"))
    assert record["browser"]["own_sandbox"] is True, record["browser"]
    assert _outcomes(record) == SAFE[site], record["checks"]
    assert not any(c["codes"] for c in record["checks"]), record["checks"]
    assert record["asked_outside"] == [], record["asked_outside"]        # the safe sites ask nothing of another computer


@needs_browser
@pytest.mark.parametrize("name", sorted(PLANTED))
def test_each_planted_problem_breaks_its_own_check_and_no_other(tmp_path, name, the_browser):
    p = PLANTED[name]
    record = browse.run(browse_sites.write(tmp_path / name, p.site, name), browser=BROWSER,
                        page_seconds=SHORT if name == "hangs" else browse.PAGE_SECONDS)
    the_browser(record)
    assert record["ran"] is True, (record.get("why_not"), record.get("why"))
    assert _outcomes(record) == dict(SAFE[p.site], **{p.check: "broken"}), record["checks"]
    assert _codes(record, p.check) == [p.code], record["checks"]
    asked = {a["host"] for a in record["asked_outside"]}
    assert asked == ({p.asks} if p.asks else set()), record["asked_outside"]
    assert all(a["refused"] is True for a in record["asked_outside"]), record["asked_outside"]
