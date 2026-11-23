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
from browse_sites import LOOKALIKES, PLANTED, SAFE
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
    from lantern import pictures
    limits = {n for n in re.findall(r"`([A-Z]+_[A-Z_]+)`", text) if not n.startswith("LANTERN_")}
    held = {**{n: getattr(browse, n) for n in ("MOST_PAGES", "MOST_CLICKS", "PAGE_SECONDS")},
            **{n: getattr(pictures, n) for n in ("MOST_PICTURES", "KEEP_RUNS")}}
    assert limits == set(held), limits
    assert all(type(v) is int and v > 0 for v in held.values())     # the code's own
    assert "each a PNG of at most 8 MB" in text and pictures.MOST_BYTES == 8 << 20


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


@pytest.mark.parametrize("name", sorted(LOOKALIKES))
def test_every_lookalike_is_the_safe_site_but_for_its_own_pieces_and_says_what_it_gives(name):
    look = LOOKALIKES[name]
    assert name not in PLANTED and look.site in SAFE, name
    safe, version = browse_sites.files(look.site), browse_sites.files(look.site, name)
    changed = {f for f in set(safe) | set(version) if safe.get(f) != version.get(f)}
    assert changed == {f for f, _, _ in look.edits}, changed
    for f, old, new in look.edits:
        if old is None:
            assert f not in safe and version[f] == new
        else:
            assert old != new and safe[f].count(old) == 1
    gives = {check: (outcome, codes) for check, outcome, codes in look.gives}
    assert len(gives) == len(look.gives) and set(gives) <= set(browse.BY_ID), look.gives
    for check, (outcome, codes) in gives.items():
        assert outcome in browse.OUTCOMES and outcome != SAFE[look.site][check], (check, outcome)
        assert set(codes) <= set(browse.BY_ID[check].codes) and (outcome == "broken") == bool(codes), (check, codes)
    assert (gives.get("outside", ("",))[0] == "broken") == bool(look.asks), name
    says = dict(look.says)
    assert len(says) == len(look.says) and set(says) <= set(browse.BY_ID) and all(says.values()), look.says


def test_a_control_or_form_not_found_again_is_left_and_said_and_a_check_that_did_nothing_is_not_held(tmp_path):
    """A click is for the control first seen on the page: on the page opened anew it is found again by its kind, its
    words and, for a link, its address; a form by its address, its method and its fields (2026-11-22). Where none
    there has them, or more than one has, nothing is clicked or sent: the log names the page, the check's reason says
    how many were left, and a check that did none of what it was to do (and had no link to look at) is not held."""
    lines: list[str] = []
    walk = browse._Walk(None, browse.Site("pages", tmp_path, ["/"]), None, 1.0, "http://localhost:1", lines.append)
    try:
        def leads() -> dict:
            walk.saw = {c.id: [] for c in browse.CHECKS}
            return next(c for c in walk.judge() if c["id"] == "leads")

        button = {"i": 0, "link": False, "shown": True, "tag": "button", "text": "Seen 1 time", "href": None}
        walk.click = lambda path, c, link: False         # not found again on the page opened anew
        walk.leads("/", [button])
        assert (walk.looked["leads"], walk.not_clicked) == (0, 1)
        assert any("/" in line and "not found again" in line for line in lines), lines
        assert (leads()["outcome"], leads()["why"]) == ("inconclusive", browse.not_clicked(1))
        walk.click = lambda path, c, link: True          # found again and clicked
        walk.leads("/", [button, dict(button, i=1, text="Seen 2 times")])
        assert (walk.looked["leads"], walk.not_clicked) == (2, 1)
        assert (leads()["outcome"], leads()["why"]) == ("held", browse.not_clicked(1))
        walk.click = lambda path, c, link: False
        walk.leads("/", [button, button])
        assert (walk.looked["leads"], walk.not_clicked) == (2, 3)
        assert leads()["why"] == browse.not_clicked(3) and browse.not_clicked(3).startswith("3 controls not clicked")
        assert browse.not_clicked(1).startswith("1 control not clicked")
        walk.looked["leads"], walk.not_clicked = 0, 0
        assert (leads()["outcome"], leads()["why"]) == ("nothing-to-check", "the pages have no link or button")

        # a form the same way: found again by its address, its method and its fields, else not sent
        def forms() -> dict:
            walk.saw = {c.id: [] for c in browse.CHECKS}
            return next(c for c in walk.judge() if c["id"] == "forms")

        form = {"i": 0, "action": "http://localhost:1/notes?visit=1", "method": "post", "shown": True}
        walk.send = lambda path, f: False
        walk.forms("/", [form])
        assert (walk.looked["forms"], walk.not_sent) == (0, 1)
        assert any("/" in line and "form" in line and "not found again" in line for line in lines), lines
        assert (forms()["outcome"], forms()["why"]) == ("inconclusive", browse.not_sent(1))
        walk.send = lambda path, f: True
        walk.forms("/", [form, dict(form, i=1)])
        assert (walk.looked["forms"], walk.not_sent) == (2, 1)
        assert (forms()["outcome"], forms()["why"]) == ("held", browse.not_sent(1))
        assert browse.not_sent(1).startswith("1 form not sent") and browse.not_sent(2).startswith("2 forms not sent")
        walk.looked["forms"], walk.not_sent = 0, 0
        assert (forms()["outcome"], forms()["why"]) == ("nothing-to-check", "the pages have no form sent to the site")
    finally:
        walk.pool.shutdown(wait=False)


def test_a_request_the_pages_own_policy_stopped_is_not_counted_as_asked(tmp_path):
    """The browser tells of a request it stopped itself before sending it, because the page's own policy (its
    Content-Security-Policy) refused it: such a request never reached Lantern's door and was not asked of another
    computer, so the outside check does not count it, its reason says how many it left out, and it makes nothing on
    the page undecided (a script the page's own policy refuses is missing on the live site too). A request the browser
    tells of that ended any other way, or that it told no end of, stays counted (2026-11-22, the browser benchmark's
    first whole run: until then every such request was counted as asked)."""
    lines: list[str] = []
    walk = browse._Walk(None, browse.Site("pages", tmp_path, ["/"]), None, 1.0, "http://localhost:1", lines.append)
    try:
        tab = browse._Tab("s1", "t1", phase=("load", "/", 1))
        walk.tabs["s1"] = tab

        def asked(rid: str, url: str, kind: str = "Script") -> None:
            walk.event("Network.requestWillBeSent", {"requestId": rid, "request": {"url": url}, "type": kind}, "s1")

        def check(name: str) -> dict:
            return next(c for c in walk.judge() if c["id"] == name)

        asked("1", "https://chat.example.net/widget.js")
        walk.event("Network.loadingFailed", {"requestId": "1", "blockedReason": "csp", "errorText": ""}, "s1")
        tab.phase = ("reload", "/", 2)                   # the same page opened anew for a click: the same request
        asked("2", "https://chat.example.net/widget.js")
        walk.event("Network.loadingFailed", {"requestId": "2", "blockedReason": "csp", "errorText": ""}, "s1")
        walk.saw["keyboard"].append({"code": "no-name", "page": "/", "control": "<button>", "what": "no name"})
        assert walk.asked_outside() == []
        assert (check("outside")["outcome"], check("outside")["why"]) == ("held", browse.kept_in(1))
        assert browse.kept_in(1).startswith("1 request for another computer not counted")
        assert browse.kept_in(2).startswith("2 requests for another computer not counted")
        assert check("keyboard")["outcome"] == "broken"   # decided: no script of another computer was refused there
        assert any("chat.example.net" in line and "/" in line for line in lines), lines

        # its twins: stopped for another reason, failed at Lantern's door, or with no end told: counted as asked
        walk.saw = {c.id: [] for c in browse.CHECKS}
        tab.phase = ("load", "/", 3)
        asked("3", "https://stats.example.org/count.js")
        walk.event("Network.loadingFailed", {"requestId": "3", "blockedReason": "other", "errorText": ""}, "s1")
        asked("4", "https://api.example.org/collect", "Fetch")
        walk.event("Network.loadingFailed", {"requestId": "4", "errorText": "net::ERR_BLOCKED_BY_CLIENT"}, "s1")
        asked("5", "https://pixel.example.net/p.gif", "Image")
        assert [a["host"] for a in walk.asked_outside()] == ["stats.example.org", "api.example.org",
                                                             "pixel.example.net"]
        outside = check("outside")
        assert (outside["outcome"], outside["codes"]) == ("broken", ["outside-file", "outside-script"]), outside
    finally:
        walk.pool.shutdown(wait=False)


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


def test_the_record_says_which_code_it_is_of_and_carries_this_computers_seal(tmp_path):
    """The release decision counts a record only of this code and with this computer's seal (`release._browser`),
    as it does the behaviour record; so every record says which code it was made on, whatever came out of the run,
    and the results folder is not part of that code."""
    from lantern import release, seal
    repo = browse_sites.write(tmp_path / "s", "pages")
    out = repo / "results"
    out.mkdir()
    (out / "earlier.txt").write_text("a result of an earlier run, not the project's code\n", encoding="utf-8")
    record = browse.run(repo, browser=str(tmp_path / "no-browser-here"), out=out)
    assert record["of"]["code_sha256"] == release.code_digest(repo, leave_out=out)["sha256"], record["of"]
    assert record["of"]["code_sha256"] != release.code_digest(repo)["sha256"]
    assert seal.holds(record), record
    assert not seal.holds({**record, "ran": True}) and not seal.holds({**record, "checks": []})   # changed after


def test_the_command_writes_the_record_sealed_and_of_this_code(tmp_path, capsys):
    from lantern import cli, release, seal
    repo = browse_sites.write(tmp_path / "s", "pages")
    out = repo / "results"
    assert cli.main(["browse", str(repo), "--out", str(out), "--browser", str(tmp_path / "no-browser-here")]) == 3
    record = json.loads((out / browse.RESULT_NAME).read_text(encoding="utf-8"))
    assert seal.holds(record), capsys.readouterr()
    assert record["of"]["code_sha256"] == release.code_digest(repo, leave_out=out)["sha256"], record["of"]


SAMPLES = sorted(p.name for p in (Path(__file__).resolve().parent / "fixtures").iterdir()
                 if p.is_dir() and p.name != "old_results")


@pytest.mark.parametrize("where", ["app", "pages", "nothing", *SAMPLES])
def test_what_a_run_would_open_is_told_without_opening_it(tmp_path, where):
    """`site_kind`, which the release decision asks whether the project has a site a browser run must open, says
    what a run itself finds (`_site`), for the two test sites, a project with nothing to open and every sample."""
    from lantern import engine
    if where in ("app", "pages"):
        repo = browse_sites.write(tmp_path / where, where)
    elif where == "nothing":
        repo = tmp_path / "sums"
        repo.mkdir()
        (repo / "sums.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    else:
        repo = Path(__file__).resolve().parent / "fixtures" / where
    g = engine.build_graph(repo)
    site = browse._site(repo, g)
    assert browse.site_kind(repo, g) == (site.how if site is not None else None), where
    if where in ("app", "pages"):
        assert browse.site_kind(repo, g) == where
    elif where == "nothing":
        assert browse.site_kind(repo, g) is None


def _sealed(repo: Path, **over) -> dict:
    """A record as `lantern browse` writes it for `repo` (below: `_record`), every check broken with one row that
    holds a long value, a table and a number, of this code and sealed by this computer; `over` changes it first."""
    from lantern import release, seal
    rec = _record({c.id: "broken" for c in browse.CHECKS},
                  saw=[{"code": "x", "page": "/", "what": "w" * 1000, "nested": {"a": 1}, "n": 3}])
    rec["of"]["code_sha256"] = release.code_digest(repo)["sha256"]
    rec.update(over)
    rec["seal"] = seal.sign(rec)
    return rec


def test_the_report_shows_a_record_only_of_this_computer_and_this_code(tmp_path):
    from lantern import release
    repo = browse_sites.write(tmp_path / "s", "pages")
    code = release.code_digest(repo)["sha256"]
    rec = _sealed(repo)
    v = browse.view(rec, code)
    assert (v["ran"], v["pages"], v["browser"]) == (True, 1, "Chromium 1"), v
    assert [c["id"] for c in v["checks"]] == [c.id for c in browse.CHECKS]
    first = v["checks"][0]
    assert first["outcome"] == "broken" and first["codes"] == [browse.CHECKS[0].codes[0]], first
    assert first["saw"] == [{"code": "x", "page": "/", "what": "w" * browse.VIEW_TEXT, "n": 3}], first  # cut; no table
    assert {c["id"]: c["blocks"] for c in v["checks"]} == {c.id: c.id in release.BROWSER_BLOCKS for c in browse.CHECKS}
    assert all("saw" not in c for c in browse.view(rec, code, "structure")["checks"])   # the site's own text left out
    unsealed = {k: x for k, x in rec.items() if k != "seal"}
    for near in (None, "not a record", unsealed, {**rec, "ran": False}):
        assert browse.view(near, code) is None, near
    assert browse.view(rec, "0" * 64) is None and browse.view(rec, None) is None     # other code; nothing to compare
    odd = _sealed(repo, checks=[{"id": "opens", "outcome": "fine", "codes": [], "saw": []},
                                {"id": "script", "outcome": "broken", "codes": ["raised", "made-up"], "saw": "x"},
                                {"id": "elsewhere", "outcome": "held"}])
    assert [(c["id"], c["codes"], c.get("saw")) for c in browse.view(odd, code)["checks"]] == [("script", ["raised"], [])]
    not_run = _sealed(repo, ran=False, why_not="no-browser")
    assert browse.view(not_run, code) == {"ran": False, "why": browse.WHY_NOT["no-browser"], "browser": "Chromium 1"}


def test_the_report_carries_what_the_browser_saw_only_with_this_computers_seal(tmp_path):
    from lantern import pipeline, report
    repo = browse_sites.write(tmp_path / "s", "pages")
    out = repo / ".lantern"
    out.mkdir()
    rec = _sealed(repo)
    for record, shown in ((rec, True), ({k: x for k, x in rec.items() if k != "seal"}, False)):
        (out / browse.RESULT_NAME).write_text(json.dumps(record), encoding="utf-8")
        pipeline.analyze(repo, out, log=lambda m: None, offline=True)
        seen = report.read_bundle(out / "report.html").get("browser")
        assert (seen is not None) is shown and (not shown or seen["ran"] is True), seen


# The pictures of the pages: kept on this computer only (lantern/pictures.py).

def _png(seed: int = 0) -> bytes:
    """A small picture in PNG's own form (signature, header, data, end), a different one for each seed."""
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    rows = b"".join(b"\x00" + bytes((seed % 256, seed // 256 % 256, 7)) * 2 for _ in range(2))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def _named(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest() + ".png"


def test_the_pictures_of_a_run_are_kept_on_this_computer_named_by_what_they_hold(tmp_path):
    from lantern import pictures
    one, two = _png(1), _png(2)
    kept = pictures.keep([("/", one), ("/about", two), ("/broken", b"<html>not a picture</html>"), ("/again", one),
                          ("/big", one + b"\0" * pictures.MOST_BYTES)])
    assert pictures.SET.fullmatch(kept["set"] or ""), kept
    assert kept["shots"] == [{"page": "/", "name": _named(one), "bytes": len(one)},
                             {"page": "/about", "name": _named(two), "bytes": len(two)},
                             {"page": "/again", "name": _named(one), "bytes": len(one)}], kept
    assert kept["not_kept"] == 2, kept                              # not a picture; too large
    home = Path(os.environ["LANTERN_HOME"]).resolve()
    folder = pictures.place() / kept["set"]
    assert folder.resolve().is_relative_to(home), folder          # Lantern's own folder of this computer
    assert sorted(p.name for p in folder.iterdir()) == sorted({_named(one), _named(two)})   # one file for one picture
    assert pictures.read(kept["set"], _named(one)) == one and pictures.read(kept["set"], _named(two)) == two
    if os.name == "posix":                                         # closed to other users
        assert stat.S_IMODE(pictures.place().stat().st_mode) == 0o700 and stat.S_IMODE(folder.stat().st_mode) == 0o700
        assert {stat.S_IMODE(p.stat().st_mode) for p in folder.iterdir()} == {0o600}
    many = pictures.keep([(f"/p{i}", _png(10 + i)) for i in range(pictures.MOST_PICTURES + 3)])
    assert (len(many["shots"]), many["not_kept"]) == (pictures.MOST_PICTURES, 3), many
    assert pictures.keep([]) == {"set": None, "shots": [], "not_kept": 0}       # nothing taken: no folder made
    assert sorted(p.name for p in pictures.place().iterdir()) == sorted((kept["set"], many["set"]))


def test_a_picture_is_read_back_only_as_a_plain_file_of_lanterns_own_that_holds_what_its_name_says(tmp_path):
    from lantern import pictures
    kept = pictures.keep([("/", _png(1)), ("/b", _png(2))])
    s, n = kept["set"], kept["shots"][0]["name"]
    assert pictures.read(s, n) == _png(1)                                       # the honest twin
    for bad_set, bad_name in ((s, "../" + n), (s, n.upper()), (s, n[:-4]), (s, "x.png"), (s, n + "/"),
                              ("../" + s, n), (s.upper(), n), (s + "/..", n), (None, n), (s, None), (1, n),
                              ("0" * len(s), n)):
        assert pictures.read(bad_set, bad_name) is None, (bad_set, bad_name)
    changed = pictures.place() / s / kept["shots"][1]["name"]
    changed.write_bytes(_png(3))                     # changed after it was kept: not the picture its name says
    assert pictures.read(s, kept["shots"][1]["name"]) is None
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / _named(_png(4))).write_bytes(_png(4))
    try:                                             # a link named like a picture, to a file that holds exactly it
        os.symlink(elsewhere / _named(_png(4)), pictures.place() / s / _named(_png(4)))
    except (OSError, NotImplementedError):
        pass                                         # this user may make no link here (Windows without the right)
    else:
        assert pictures.read(s, _named(_png(4))) is None
    other = "f" * len(s)                             # a run's folder that is a link to a folder elsewhere
    _link_folder(elsewhere, pictures.place() / other)
    assert pictures.read(other, _named(_png(4))) is None
    assert (elsewhere / _named(_png(4))).read_bytes() == _png(4)


def test_only_the_newest_runs_pictures_are_kept_and_nothing_else_there_is_touched(tmp_path, monkeypatch):
    from lantern import pictures
    monkeypatch.setattr(pictures, "KEEP_RUNS", 3)
    root = pictures.place()
    root.mkdir(parents=True)
    (root / "notes.txt").write_text("mine", encoding="utf-8")
    (root / "mine").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("x", encoding="utf-8")
    _link_folder(outside, root / ("e" * 32))         # a link named like a run's folder
    made = []
    for i in range(5):
        k = pictures.keep([("/", _png(i))])
        made.append(k["set"])
        os.utime(root / k["set"], (1_000_000 + i, 1_000_000 + i))          # the earlier, the older
    left = {p.name for p in root.iterdir()}
    assert {s for s in made if s in left} == set(made[-3:]), (made, left)
    assert {"notes.txt", "mine", "e" * 32} <= left, left
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "x"


def test_a_record_names_its_pictures_and_the_report_only_counts_them(tmp_path):
    import base64

    from lantern import pictures, pipeline, release, report
    repo = browse_sites.write(tmp_path / "s", "pages")
    out = repo / ".lantern"
    out.mkdir()
    kept = pictures.keep([("/", _png(1)), ("/about", _png(2))])
    rec = _sealed(repo, pictures=kept)
    code = release.code_digest(repo)["sha256"]
    assert browse.view(rec, code)["pictures"] == 2 and browse.view(rec, code, "structure")["pictures"] == 2
    assert browse.view(_sealed(repo), code)["pictures"] == 0                    # a record from before them
    odd = _sealed(repo, pictures={"set": "x", "shots": [{"page": "/", "name": "../a.png", "bytes": 1}, "no"]})
    assert browse.view(odd, code)["pictures"] == 0
    (out / browse.RESULT_NAME).write_text(json.dumps(rec), encoding="utf-8")
    pipeline.analyze(repo, out, log=lambda m: None, offline=True)
    assert report.read_bundle(out / "report.html")["browser"]["pictures"] == 2
    named = [kept["set"], *(s["name"][:-4] for s in kept["shots"]), base64.b64encode(_png(1)).decode()[8:40]]
    for f in out.rglob("*"):
        if f.is_file() and f.name != browse.RESULT_NAME:
            data = f.read_bytes()
            assert not any(x.encode() in data for x in named), f        # not in the report or any other result
    assert not [p for p in repo.rglob("*") if p.is_file() and p.read_bytes()[:8] == pictures.PNG]   # no picture there


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


def test_the_command_says_how_many_pictures_it_kept_and_where(tmp_path, monkeypatch, capsys):
    from lantern import pictures
    kept = pictures.keep([("/", _png(1)), ("/about", _png(2))])
    with_them = dict(_record({"forms": "nothing-to-check", "visitor": "nothing-to-check"}), pictures=kept)
    assert _browse(monkeypatch, tmp_path, with_them)[0] == 0
    said = capsys.readouterr().out
    assert f"pictures      2 of the pages, kept on this computer only: {pictures.place() / kept['set']}" in said, said
    assert _browse(monkeypatch, tmp_path, _record({"forms": "nothing-to-check", "visitor": "nothing-to-check"}))[0] == 0
    assert "pictures" not in capsys.readouterr().out                            # none taken, none said


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
    """The codes the check gives: those of what it saw and counted, never of what it left undecided."""
    return next(c["codes"] for c in record["checks"] if c["id"] == check)


def _told(record, want: dict | None = None) -> str:
    """What a failure says: the browser, and each check that is not as wanted (with no `want`, each that saw
    something), with the first rows it saw, so a run on another machine says what it was."""
    lines = [f"browser: {json.dumps(record.get('browser'), sort_keys=True)}"]
    for c in record.get("checks") or []:
        if (want is not None and want.get(c["id"]) == c["outcome"] and not c.get("codes")) or \
                (want is None and not c.get("saw")):
            continue
        lines.append(f"{c['id']}: {c['outcome']} {c.get('codes')} why={c.get('why')!r} saw={json.dumps(c.get('saw')[:6])}")
    return "\n".join(lines)


@needs_browser
@pytest.mark.parametrize("site", sorted(SAFE))
def test_each_site_written_safe_breaks_no_check(tmp_path, site, the_browser):
    record = browse.run(browse_sites.write(tmp_path / site, site), browser=BROWSER)
    the_browser(record)
    assert record["ran"] is True, (record.get("why_not"), record.get("why"))
    assert record["browser"]["own_sandbox"] is True, record["browser"]
    assert _outcomes(record) == SAFE[site], _told(record, SAFE[site])
    assert not any(c["codes"] or c["saw"] for c in record["checks"]), _told(record)
    assert record["asked_outside"] == [], record["asked_outside"]        # the safe sites ask nothing of another computer
    assert record["browser"]["keyboard_end"] in browse.KEYBOARD_ENDS, _told(record)    # what this browser does
    from lantern import pictures                     # a picture of each page that shows something, kept here only
    kept = record.get("pictures") or {}
    assert kept.get("shots") and kept.get("not_kept") == 0, kept
    assert {s["page"] for s in kept["shots"]} <= {p["path"] for p in record["opened"]}, kept
    for s in kept["shots"]:
        data = pictures.read(kept["set"], s["name"])
        assert data is not None and data[:8] == pictures.PNG and len(data) == s["bytes"], s
    assert not [p for p in tmp_path.rglob("*") if p.is_file() and p.read_bytes()[:8] == pictures.PNG]


@needs_browser
def test_a_site_with_no_control_gives_the_keyboard_nothing_to_check(tmp_path, the_browser):
    """A site whose pages have no link, button or field, and nothing that answers a click, gives the keyboard nothing
    to look at: nothing-to-check with the reason, not a held that nothing was looked at for (2026-11-22, the browser
    benchmark's first whole run: until then each page opened counted, and a task list that draws nothing read held)."""
    site = tmp_path / "closed"
    site.mkdir()
    (site / "index.html").write_text(
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Closed</title>\n</head>\n<body>\n'
        "<main>\n<h1>Closed for the holidays</h1>\n<p>We open again on Monday.</p>\n</main>\n</body>\n</html>\n",
        encoding="utf-8", newline="\n")
    record = browse.run(site, browser=BROWSER)
    the_browser(record)
    assert record["ran"] is True, (record.get("why_not"), record.get("why"))
    keyboard = next(c for c in record["checks"] if c["id"] == "keyboard")
    assert (keyboard["outcome"], keyboard["why"]) == ("nothing-to-check", "the pages have no link, button or field"), \
        _told(record)
    assert _outcomes(record) == {"opens": "held", "script": "nothing-to-check", "leads": "nothing-to-check",
                                 "forms": "nothing-to-check", "visitor": "nothing-to-check", "protections": "not-run",
                                 "outside": "held", "keyboard": "nothing-to-check"}, _told(record)


@needs_browser
@pytest.mark.parametrize("name", sorted(PLANTED))
def test_each_planted_problem_breaks_its_own_check_and_no_other(tmp_path, name, the_browser):
    p = PLANTED[name]
    record = browse.run(browse_sites.write(tmp_path / name, p.site, name), browser=BROWSER,
                        page_seconds=SHORT if name == "hangs" else browse.PAGE_SECONDS)
    the_browser(record)
    assert record["ran"] is True, (record.get("why_not"), record.get("why"))
    want = dict(SAFE[p.site], **{p.check: "broken"})
    assert _outcomes(record) == want, _told(record, want)
    assert _codes(record, p.check) == [p.code], _told(record, want)
    assert not any(s.get("undecided") for c in record["checks"] for s in c["saw"]), _told(record)
    asked = {a["host"] for a in record["asked_outside"]}
    assert asked == ({p.asks} if p.asks else set()), record["asked_outside"]
    assert all(a["refused"] is True for a in record["asked_outside"]), record["asked_outside"]


@needs_browser
@pytest.mark.parametrize("name", sorted(LOOKALIKES))
def test_each_lookalike_gives_what_it_should(tmp_path, name, the_browser):
    """A look-alike breaks no check the safe site holds unless it says so: Tab moving on inside a frame, a date field
    or a part with a tree of its own is no trap, a page that listens for keys does not hold the keyboard, a hidden
    element is not asked to be reached, a cover that fades away as the page opens is gone before the page is looked
    at and clicked, and what a refused script from another computer could have done is undecided, with each row it
    saw marked so and no code given for it."""
    look = LOOKALIKES[name]
    record = browse.run(browse_sites.write(tmp_path / name, look.site, name), browser=BROWSER)
    the_browser(record)
    assert record["ran"] is True, (record.get("why_not"), record.get("why"))
    want = dict(SAFE[look.site], **{check: outcome for check, outcome, _ in look.gives})
    assert _outcomes(record) == want, _told(record, want)
    codes = {check: list(codes) for check, _, codes in look.gives}
    says = dict(look.says)
    for c in record["checks"]:
        assert c["codes"] == codes.get(c["id"], []), _told(record, want)
        if c["id"] in says:
            assert says[c["id"]] in (c["why"] or ""), _told(record, want)
        elif c["outcome"] == "held":
            assert c["why"] is None, _told(record, want)
        if c["outcome"] == "inconclusive":
            assert c["saw"] and all(s.get("undecided") is True for s in c["saw"]) and c["why"], _told(record, want)
        else:
            assert not any(s.get("undecided") for s in c["saw"]), _told(record, want)
    asked = {a["host"] for a in record["asked_outside"]}
    assert asked == ({look.asks} if look.asks else set()), record["asked_outside"]
