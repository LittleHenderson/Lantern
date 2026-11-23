"""The browser benchmark's definitions (bench/browser/README.md; a firm pass or fail, stage 5, step 5), held together
with no browser: its list of checks and codes is the one in `lantern/browse.py`, each part's definitions hold
together, every version builds from its family's safe site, every one of the 24 codes is planted in each part, a run
is compared with what was written down the way the README says, the fingerprint follows every file of a part, and
the held-back part is opened only when it is named."""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lantern import browse

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench" / "browser"
PARTS = ("open", "held-back")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(BENCH))
import define  # noqa: E402  (bench/browser/define.py, the module each part's cases.py takes its names from)

runner = _load("browser_bench_runner", BENCH / "run_browser.py")


def _part(part: str):
    return runner.part_of(part)


def test_the_codes_are_the_checks_own():
    assert define.CODES == {c.id: c.codes for c in browse.CHECKS}
    assert define.CHECKS == tuple(c.id for c in browse.CHECKS)
    assert define.OUTCOMES == browse.OUTCOMES


@pytest.mark.parametrize("part", PARTS)
def test_each_part_holds_together(part):
    families, versions = _part(part)
    assert define.faults(families, versions) == []
    assert {v.kind for v in versions.values()} == set(define.KINDS)
    for name in families:
        assert (BENCH / part / "sites" / name).is_dir(), name
        assert versions[name].kind == define.SAFE


@pytest.mark.parametrize("part", PARTS)
def test_every_version_builds_from_its_family_and_differs_from_it(part):
    families, versions = _part(part)
    safe = {name: define.files(BENCH / part / "sites", name, versions[name]) for name in families}
    for name, v in versions.items():
        built = define.files(BENCH / part / "sites", v.family, v)
        for file in built:
            p = Path(file)
            assert not p.is_absolute() and ".." not in p.parts and "\\" not in file and not file.endswith(".tmpl"), file
        if v.kind == define.SAFE:
            assert built == safe[v.family]
            continue
        assert v.edits and built != safe[v.family], name
        for edit in v.edits:
            if edit[0] == "replace" and edit[3]:
                assert edit[3] in built[edit[1]], (name, edit[1])
            elif edit[0] == "add":
                assert built[edit[1]] == edit[2], name
            elif edit[0] == "remove":
                assert edit[1] not in built, name
            elif edit[0] == "rename":
                assert edit[1] not in built and edit[2] in built, name


def test_an_edit_that_does_not_stand_exactly_once_is_refused(tmp_path):
    site = tmp_path / "sites" / "s"
    site.mkdir(parents=True)
    (site / "index.html.tmpl").write_text("<p>a</p><p>a</p>", encoding="utf-8")
    (site / "dot.env.tmpl").write_text("X=1\n", encoding="utf-8")
    plain = define.Version("s", "safe", "the site")
    assert define.files(tmp_path / "sites", "s", plain) == {"index.html": "<p>a</p><p>a</p>", ".env": "X=1\n"}
    for edits in ((("replace", "index.html", "<p>a</p>", "<p>b</p>"),),       # twice
                  (("replace", "index.html", "<p>c</p>", "<p>b</p>"),),       # not at all
                  (("add", "index.html", "x"),), (("rename", "index.html", ".env"),), (("bend", "index.html"),)):
        with pytest.raises(ValueError):
            define.files(tmp_path / "sites", "s", define.Version("s", "planted", "x", edits))
    (site / "README.md").write_text("not a template", encoding="utf-8")
    with pytest.raises(ValueError):
        define.files(tmp_path / "sites", "s", plain)


@pytest.mark.parametrize("part", PARTS)
def test_every_code_is_planted_in_each_part(part):
    _families, versions = _part(part)
    planted = {code for v in versions.values() for _check, code in v.planted}
    assert planted == {code for codes in define.CODES.values() for code in codes}


def test_no_python_file_of_the_benchmark_reads_as_lanterns_own_debug_switch():
    """Lantern's readiness check reads each code file of Lantern as Lantern's own (`readiness.DEBUG_ON`, and
    `BARE_EXCEPT` beside it): a planted line written whole in a part's `cases.py` read as Lantern's debug switch left on
    and failed Lantern's check of itself (2026-11-22). The line still stands in the version it plants (the next test)."""
    from lantern import readiness
    found = []
    for p in sorted(BENCH.rglob("*.py")):
        text = p.read_text(encoding="utf-8")
        for rx in (readiness.DEBUG_ON, readiness.BARE_EXCEPT):
            found += [f"{p.relative_to(ROOT).as_posix()}:{text.count(chr(10), 0, m.start()) + 1}"
                      for m in rx.finditer(text)]
    assert found == []


def test_the_shortcut_left_on_is_still_planted_in_its_version():
    from lantern import readiness
    _families, versions = _part("open")
    sites = BENCH / "open" / "sites"
    planted = define.files(sites, "library", versions["l-let-in"])["app/data.py"]
    safe = define.files(sites, "library", versions["library"])["app/data.py"]
    assert readiness.DEBUG_ON.search(planted)
    assert not readiness.DEBUG_ON.search(safe)


@pytest.mark.parametrize("part", PARTS)
def test_the_readme_counts_each_part_as_its_cases_do(part):
    families, versions = _part(part)
    row = next(line for line in (BENCH / "README.md").read_text(encoding="utf-8").splitlines()
               if line.startswith(f"| `{part}` |"))
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert re.findall(r"`([a-z-]+)`", cells[1]) == list(families)
    kinds = [sum(1 for v in versions.values() if v.kind == k) for k in ("planted", "look-alike", "safe")]
    assert [int(c) for c in cells[2:6]] == [len(versions), *kinds]


@pytest.mark.parametrize("part", PARTS)
def test_every_reading_beyond_the_contract_is_listed_in_the_readme(part):
    _families, versions = _part(part)
    readme = (BENCH / "README.md").read_text(encoding="utf-8").split("## Readings beyond", 1)[1]
    for name, v in versions.items():
        if v.beyond:
            assert f"`{name}`" in readme, name


def _record(want: dict, rows: list[tuple[str, str]], undecided: bool = False) -> dict:
    """A record of `lantern browse` that gives `want` (check -> (outcome, codes)) with `rows` (code, page) seen."""
    checks = []
    for check, (outcome, codes) in want.items():
        saw = [{"code": code, "page": page, **({"undecided": True} if undecided else {})}
               for code, page in rows if code in define.CODES[check]]
        checks.append({"id": check, "outcome": outcome, "codes": list(codes), "saw": saw})
    return {"ran": True, "checks": checks}


def test_a_run_is_compared_with_what_was_written_down():
    families, versions = _part("open")
    planted = next(v for v in versions.values() if v.kind == "planted")
    family = families[planted.family]
    want = define.expected(family, planted)
    same = define.compare(family, planted, _record(want, list(planted.seen)))
    assert same["as_written"] and same["found"] and same["differences"] == []
    (check, code), = planted.planted[:1]
    # the planted problem not given: missed, not found
    lost = dict(want)
    lost[check] = (family.safe[check], ())
    got = define.compare(family, planted, _record(lost, [s for s in planted.seen if s[0] != code]))
    assert not got["as_written"] and got["found"] is False and (check, code) in got["missed"]
    # a code more than was written down: a false alarm
    other = next(c for c in define.CHECKS if want[c][0] != "broken" and family.safe[c] == "held")
    more = dict(want)
    more[other] = ("broken", (define.CODES[other][0],))
    got = define.compare(family, planted, _record(more, list(planted.seen) + [(define.CODES[other][0], "/")]))
    assert got["false_alarms"] == [(other, define.CODES[other][0])] and got["found"] is True and not got["as_written"]
    # the same codes, another outcome
    held = dict(want)
    held[other] = ("inconclusive", ())
    got = define.compare(family, planted, _record(held, list(planted.seen)))
    assert got["outcomes"] == [(other, want[other][0], "inconclusive")] and not got["as_written"]
    # the row written down only as undecided: not seen, so not found
    got = define.compare(family, planted, _record(want, list(planted.seen), undecided=True))
    assert got["absent"] and got["found"] is False
    # a run that could not be made says so on every check
    got = define.compare(family, planted, {"ran": False, "why_not": "no-browser", "checks": [
        {"id": c, "outcome": "not-run", "codes": [], "saw": []} for c in define.CHECKS]})
    assert not got["as_written"] and got["found"] is False and (check, code) in got["missed"]
    # a safe version gives no `found`
    safe = versions[planted.family]
    assert define.compare(family, safe, _record(define.expected(family, safe), []))["found"] is None


def test_the_counts_are_the_readmes():
    families, versions = _part("open")

    def row(name, record):
        v = versions[name]
        x = define.compare(families[v.family], v, record)
        x.update(given={c: list(g) for c, g in define.got(record).items()}, ran=True, why_not=None, browser_own=0,
                 asked_outside=0, seconds=1.0, browser={})
        return {"name": name, "family": v.family, "kind": v.kind, "what": v.what, "planted": [list(p) for p in v.planted],
                "beyond": v.beyond, "runs": [x], "as_written": x["as_written"], "same_each_run": True,
                "found": None if v.kind != "planted" else x["found"], "seconds": 1.0}

    planted = [n for n, v in versions.items() if v.kind == "planted"][:2]
    clean = [n for n, v in versions.items() if v.kind != "planted"][:2]
    rows = []
    for n in planted + clean:
        v = versions[n]
        rows.append(row(n, _record(define.expected(families[v.family], v), list(v.seen))))
    first = versions[planted[0]]
    rows[0] = row(planted[0], _record({c: (families[first.family].safe[c], ()) for c in define.CHECKS}, []))
    t = runner.tally(rows)
    assert (t["versions"], t["as_written"], t["planted"], t["found"], t["clean"], t["clean_as_written"]) == \
        (4, 3, 2, 1, 2, 2)
    assert t["missed"] and all(m[0] == planted[0] for m in t["missed"]) and t["false_alarms"] == []
    words = runner.summary(t, 1)
    assert "Planted problems found: 1 of 2." in words and "Safe sites and look-alikes as written down: 2 of 2." in words
    table = runner.table(rows, t, families)
    assert f"| `{planted[0]}` |" in table and "NO: " in table and "| Code | Planted in | Found in |" in table


def test_git_leaves_out_no_file_of_the_benchmark():
    """Every file a part is made of is one the repository keeps. The repository's `.gitignore` leaves out every folder
    named `dist`, and until 2026-11-22 the task list's built folder (`open/sites/tasks/dist/`) was in no commit: the
    benchmark was built whole on the computer it was written on and not from GitHub's checkout (README, a dated note)."""
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout: what git leaves out cannot be asked of it")
    files = [p.relative_to(ROOT).as_posix() for p in sorted(BENCH.rglob("*"))
             if p.is_file() and "__pycache__" not in p.parts]
    asked = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"], cwd=ROOT, input="\n".join(files) + "\n",
                           capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert asked.returncode in (0, 1), asked.stderr           # 1: git leaves out none of them
    assert asked.stdout.split() == []


def test_the_fingerprint_follows_every_file_of_a_part(tmp_path):
    copy = tmp_path / "browser"
    copy.mkdir()
    shutil.copy2(BENCH / "define.py", copy / "define.py")
    shutil.copytree(BENCH / "open", copy / "open", ignore=shutil.ignore_patterns("__pycache__"))
    first = runner.definition_sha256("open", copy)
    assert first == runner.definition_sha256("open")
    page = copy / "open" / "sites" / "garden" / "index.html.tmpl"
    text = page.read_text(encoding="utf-8")
    page.write_text(text + " ", encoding="utf-8")
    assert runner.definition_sha256("open", copy) != first
    page.write_text(text, encoding="utf-8")
    assert runner.definition_sha256("open", copy) == first
    page.rename(page.with_name("start.html.tmpl"))
    assert runner.definition_sha256("open", copy) != first
    assert runner.definition_sha256("held-back") != first


def test_the_runner_opens_the_open_part_unless_the_held_back_part_is_named(capsys):
    assert runner.PARTS[0] == "open"
    assert runner.main(["/nowhere", "--only", "not-a-version"]) == 2
    assert runner.main(["/nowhere", "--part", "held-back", "--only", "garden"]) == 2      # a version of the open part
    assert runner.main(["/nowhere", "--runs", "0"]) == 2
    assert "unknown: garden" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        runner.main(["/nowhere", "--part", "hidden"])
    workflows = "\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / ".github" / "workflows").glob("*.yml")))
    assert "held-back" not in workflows                 # opened once at the end of stage 5, never by a job of CI
