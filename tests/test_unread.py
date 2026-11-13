"""What a project holds that Lantern takes for code or software and did not read (2026-11-12).

A real site kept 17 Python files, 12,518 lines, as `<name>.py.txt` and ran them in the browser, beside a copy of the
runtime that runs them in `vendor/`. No reader and no scanner opened one of them, and the report said nothing: the
Python scanner read "ok" on 0 files, the release decision's scanners criterion said every scanner had covered
everything, and the libraries criterion said the project lists no libraries.

Each case stands beside a twin that must read as before. None of the examples is copied from that site."""

import json

import pytest

from lantern import depaudit, evidence, unread
from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _run(root, offline=True):
    g = build_graph(root)
    sec = scan(g, offline=offline)
    rd = assess(g, sec, {})
    return g, sec, rd


def _tool(sec, name):
    return next(t for t in sec["tools"] if t["tool"] == name)


def _criterion(rd, cid):
    return next(c for c in rd["release"]["criteria"] if c["id"] == cid)


def _limits(g, sec, rd):
    return evidence.limits(g, sec, rd, {}, "full", None)


PAGE = ("<!doctype html><html><head><title>Sums</title></head><body><main id=\"out\"></main>"
        "<script type=\"module\" src=\"worker.js\"></script></body></html>\n")
WORKER = ("export async function start() {\n  const text = await fetch('./engine.py.txt').then(r => r.text());\n"
          "  return text.length;\n}\n")
UNSAFE_PY = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n"
SAFE_PY = "def add(a, b):\n    return a + b\n"
SITE = {"index.html": PAGE, "worker.js": WORKER}


# ---------------------------------------------------------------- Python kept as text is read by the Python scanner

def test_python_kept_as_text_is_read_by_the_python_scanner(tmp_path):
    _write(tmp_path, {**SITE, "engine.py.txt": UNSAFE_PY})
    g, sec, rd = _run(tmp_path)
    found = [f for f in sec["findings"] if f["tool"] == "bandit"]
    assert [(f["rule"], f["file"], f["line"]) for f in found if f["rule"] == "B602"] == [("B602", "engine.py.txt", 5)], found
    bandit = _tool(sec, "bandit")
    assert bandit["state"] == "ok" and bandit["applicable"] is True, bandit
    assert bandit["scope"] == {"files": 1, "under_another_name": 1}, bandit
    kept = sec["not_read"]["renamed"]
    assert (kept["files"], kept["lines"], kept["scanned"], kept["endings"]) == (1, 5, 1, {".py.txt": 1}), kept
    # the scanners did their part; what stays unread is said where the report says what it cannot vouch for
    assert _criterion(rd, "scanners")["state"] == "passed"
    said = [line for line in _limits(g, sec, rd) if "under another name" in line]
    assert len(said) == 1 and "engine.py.txt" in said[0] and "Bandit read" in said[0] and "map" in said[0], said


def test_the_twin_with_nothing_wrong_in_it_gets_no_finding(tmp_path):
    _write(tmp_path, {**SITE, "engine.py.txt": SAFE_PY})
    g, sec, rd = _run(tmp_path)
    assert [f for f in sec["findings"] if f["tool"] == "bandit"] == []
    assert _tool(sec, "bandit")["scope"] == {"files": 1, "under_another_name": 1}


def test_a_project_with_no_such_file_reads_as_before(tmp_path):
    _write(tmp_path, {**SITE, "notes.txt": "import this is not code\n", "engine.py": SAFE_PY})
    g, sec, rd = _run(tmp_path)
    assert _tool(sec, "bandit")["scope"] == {"files": 1}
    assert sec["not_read"] == {}
    assert not [line for line in _limits(g, sec, rd) if "under another name" in line or "copied into" in line]
    assert _criterion(rd, "scanners")["state"] == "passed"


def test_text_that_is_no_python_under_a_python_name_is_said_not_passed_over(tmp_path):
    _write(tmp_path, {**SITE, "engine.py.txt": "Dear reader,\n\nthis file was meant (to hold code.\n"})
    g, sec, rd = _run(tmp_path)
    bandit = _tool(sec, "bandit")
    assert bandit["state"] == "partial" and any("engine.py.txt" in e for e in bandit["errors"]), bandit
    assert _criterion(rd, "scanners")["state"] == "missing"


def test_python_kept_as_text_that_did_not_fit_the_scanners_command_line_is_said_not_read(tmp_path, monkeypatch):
    from lantern import security
    _write(tmp_path, {**SITE, "a.py.txt": SAFE_PY, "b.py.txt": UNSAFE_PY})
    monkeypatch.setattr(security, "HANDED_FIT", len(str(tmp_path / "a.py.txt")) + 1)       # room for one path
    g, sec, rd = _run(tmp_path)
    kept = sec["not_read"]["renamed"]
    assert (kept["files"], kept["scanned"], kept["as_text_unscanned"], kept["as_text_unscanned_examples"]) == \
        (2, 1, 1, ["b.py.txt"]), kept
    c = _criterion(rd, "scanners")
    assert c["state"] == "missing" and "b.py.txt" in c["why"], c


# ---------------------------------------------------------------- a command of fixed text in Python kept as text

def _tools(arg):
    return ("import os\n\nWINDOWS = os.name == \"nt\"\n\n\ndef choose():\n    return input()\n\n\n"
            f"def today(fmt):\n    os.system({arg})\n")


@pytest.mark.parametrize("arg", ['"date /t" if WINDOWS else "date"', '"date" + " /t"',
                                 '("date /t" if WINDOWS else "date") + " "'])
def test_a_command_of_fixed_text_in_python_kept_as_text_is_ranked_low_and_says_why(tmp_path, arg):
    _write(tmp_path, {**SITE, "engine.py.txt": _tools(arg)})
    g, sec, rd = _run(tmp_path)
    found = [f for f in sec["findings"] if f["rule"] == "B605"]
    assert [(f["file"], f["line"]) for f in found] == [("engine.py.txt", 11)], found      # it stays listed
    f = found[0]
    assert f["tool_severity"] == "HIGH", f                    # the scanner cannot tell a choice of literals from input
    assert f["rank"] == "low" and f["rank_before_context"] == "high", (f["rank"], f.get("rank_before_context"))
    assert "written in the code itself" in f["rank_note"], f["rank_note"]
    assert f["context"]["fixed"]["calls"] == [] and f["context"]["fixed"]["reads"] == "the call on this line", f["context"]
    said = [e for e in f["case"]["evidence"] if "written in the code itself" in e["fact"]]
    assert [e["from"] for e in said] == ["context (code)"], f["case"]["evidence"]         # no data flow was followed
    assert "B605" not in json.dumps(rd["release"]["criteria"][0]), rd["release"]["criteria"][0]


@pytest.mark.parametrize("arg", ['"date " + fmt', "fmt", '"date %s" % fmt', 'f"date {fmt}"', "choose()",
                                 '"date /t" if WINDOWS else choose()', "*fmt"])
def test_its_twin_that_takes_a_value_stays_high(tmp_path, arg):
    _write(tmp_path, {**SITE, "engine.py.txt": _tools(arg)})
    g, sec, rd = _run(tmp_path)
    found = [f for f in sec["findings"] if f["rule"] == "B605"]
    assert [(f["file"], f["line"], f["rank"]) for f in found] == [("engine.py.txt", 11, "high")], found
    assert "rank_note" not in found[0] and "fixed" not in (found[0].get("context") or {}), found[0]


def test_a_wildcard_the_shell_fills_in_is_not_fixed_text(tmp_path):
    _write(tmp_path, {**SITE, "engine.py.txt": _tools('"tar cf /tmp/out.tar *"')})
    g, sec, rd = _run(tmp_path)
    found = [f for f in sec["findings"] if f["rule"] == "B609"]
    assert [(f["file"], f["line"], f["rank"]) for f in found] == [("engine.py.txt", 11, "high")], found
    assert "rank_note" not in found[0], found[0]


# ---------------------------------------------------------------- code no scanner reads

def test_code_kept_as_text_that_no_scanner_reads_leaves_the_scanners_criterion_missing(tmp_path):
    _write(tmp_path, {**SITE, "helper.js.txt": "export function run(code) {\n  return eval(code);\n}\n"})
    g, sec, rd = _run(tmp_path)
    kept = sec["not_read"]["renamed"]
    assert (kept["files"], kept["scanned"], kept["as_text_unscanned"]) == (1, 0, 1), kept
    c = _criterion(rd, "scanners")
    assert c["state"] == "missing" and "helper.js.txt" in c["why"] and c["fix"], c
    assert rd["release"]["decision"] != "Passed"
    said = [line for line in _limits(g, sec, rd) if "under another name" in line]
    assert len(said) == 1 and "No scanner" in said[0], said


def test_a_template_is_named_in_the_limits_and_is_no_gap_of_the_scanners(tmp_path):
    _write(tmp_path, {**SITE, "starter/main.py.tmpl": UNSAFE_PY, "starter/app.js.tmpl": "export const x = 1;\n"})
    g, sec, rd = _run(tmp_path)
    kept = sec["not_read"]["renamed"]
    assert (kept["files"], kept["scanned"], kept["as_text_unscanned"]) == (2, 0, 0), kept
    assert kept["endings"] == {".js.tmpl": 1, ".py.tmpl": 1}
    assert [f for f in sec["findings"] if f["tool"] == "bandit"] == []          # a template is not handed to Bandit
    assert _criterion(rd, "scanners")["state"] == "passed"
    said = [line for line in _limits(g, sec, rd) if "under another name" in line]
    assert len(said) == 1 and "2 files" in said[0], said


@pytest.mark.parametrize("name", ["readme.txt", "notes.py.md", "data.json.txt", "archive.py.txt.zip", "a.txt.py"])
def test_other_names_are_not_code_under_another_name(tmp_path, name):
    _write(tmp_path, {**SITE, name: SAFE_PY})
    assert unread.survey(tmp_path).get("renamed") is None


# ---------------------------------------------------------------- software copied into the project

COPIED = {"vendor/widget/package.json": '{\n  "name": "widget-lib",\n  "version": "1.2.3"\n}\n',
          "vendor/widget/widget.mjs": "export const widget = 1;\n"}


def test_software_copied_into_the_project_is_named_and_offline_it_is_a_gap(tmp_path):
    _write(tmp_path, {**SITE, **COPIED})
    g, sec, rd = _run(tmp_path, offline=True)
    info = _tool(sec, "copied-audit")
    assert info["state"] == "skipped" and info["applicable"] is True and "offline" in info["status"], info
    assert info["copied"] == 1 and info["copied_examples"] == ["widget-lib 1.2.3 (vendor/widget)"], info
    c = _criterion(rd, "dependencies")
    assert c["state"] == "missing" and c["required"] is True, c                  # before: "lists no libraries"
    said = [line for line in _limits(g, sec, rd) if line.startswith("Software copied into")]
    assert len(said) == 1 and "widget-lib 1.2.3" in said[0] and "vendor/widget" in said[0], said
    assert "was not looked up for known problems in this check" in said[0], said


def test_a_copy_with_a_known_problem_is_a_finding_and_its_twin_is_clean(tmp_path, monkeypatch):
    asked = []

    def post(path, body, timeout=60):
        asked.append(body)
        return {"results": [{"vulns": [{"id": "GHSA-test-copy"}]} if q["version"] == "1.2.3" else {}
                            for q in body["queries"]]}

    monkeypatch.setattr(depaudit, "_osv_post", post)
    monkeypatch.setattr(depaudit, "_osv_get", lambda path, timeout=30: {
        "summary": "Script injection", "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "widget-lib"}, "ranges": [{"events": [{"fixed": "1.2.9"}]}]}]})
    _write(tmp_path, {**SITE, **COPIED})
    out, info = depaudit.run_copied_audit(tmp_path, no_network=False)
    assert asked[0]["queries"] == [{"package": {"name": "widget-lib", "ecosystem": "npm"}, "version": "1.2.3"}]
    assert info["state"] == "ok" and info["checked"] == 1, info
    assert [(f["tool"], f["file"], f["line"]) for f in out] == [("copied-audit", "vendor/widget/package.json", 3)], out
    assert "1.2.9" in out[0]["more_info"]

    twin = tmp_path / "twin"
    _write(twin, {**SITE, **COPIED, "vendor/widget/package.json": COPIED["vendor/widget/package.json"].replace("1.2.3", "1.2.9")})
    out, info = depaudit.run_copied_audit(twin, no_network=False)
    assert out == [] and info["state"] == "ok" and info["checked"] == 1, (out, info)
    g = build_graph(twin)
    sec = scan(g, offline=False)
    rd = assess(g, sec, {})
    c = _criterion(rd, "dependencies")
    assert c["state"] == "passed" and "copied-audit" in c["why"], c
    said = [line for line in _limits(g, sec, rd) if line.startswith("Software copied into")]
    assert len(said) == 1 and "was looked up for known problems" in said[0] and "says it is" in said[0], said


def test_copied_files_with_no_name_and_version_cannot_be_looked_up(tmp_path):
    _write(tmp_path, {**SITE, "vendor/charts.min.js": "window.charts = 1;\n", "vendor/old/tool.mjs": "export default 1;\n"})
    g, sec, rd = _run(tmp_path, offline=False)
    info = _tool(sec, "copied-audit")
    assert info["state"] == "partial" and info["unnamed"] == 2, info
    assert _criterion(rd, "dependencies")["state"] == "missing"
    said = [line for line in _limits(g, sec, rd) if line.startswith("Software copied into")]
    assert len(said) == 1 and "2 files" in said[0] and "no name and version" in said[0], said


@pytest.mark.parametrize("marker", ["vendor/autoload.php", "vendor/composer/installed.json", "vendor/modules.txt",
                                    "vendor/bundle/ruby/gem.rb"])
def test_a_package_managers_own_folder_is_not_copied_in_software(tmp_path, marker):
    _write(tmp_path, {**SITE, **COPIED, marker: "x\n"})
    assert unread.survey(tmp_path).get("copied") is None
    out, info = depaudit.run_copied_audit(tmp_path, no_network=True)
    assert info["state"] == "skipped" and info["applicable"] is False, info


@pytest.mark.parametrize("where", ["tests/fixtures/site", "examples/demo", "test/data"])
def test_a_copy_kept_for_the_tests_or_a_sample_is_not_the_projects_copied_in_software(tmp_path, where):
    # the other audits leave the dependency files of tests and sample apps out the same way (`depaudit.TEST_DIR_RE`)
    _write(tmp_path, {**SITE, **{f"{where}/{k}": v for k, v in COPIED.items()}})
    assert unread.survey(tmp_path).get("copied") is None
    out, info = depaudit.run_copied_audit(tmp_path, no_network=True)
    assert info["state"] == "skipped" and info["applicable"] is False, info


def test_a_python_environment_named_env_is_not_looked_through_for_copies(tmp_path):
    # a folder named `env` is left out only where it is a Python environment (`python_frontend.skipped_dir`): what
    # is installed there with a `vendor` folder of its own (the pages of a notebook server, under `share/`) is not
    # software copied into the project
    inside = "env/share/jupyter/lab/static"
    _write(tmp_path, {**SITE, "env/pyvenv.cfg": "home = /usr/bin\n",
                      **{f"{inside}/{k}": v for k, v in COPIED.items()}})
    assert unread.survey(tmp_path).get("copied") is None
    out, info = depaudit.run_copied_audit(tmp_path, no_network=True)
    assert info["state"] == "skipped" and info["applicable"] is False, info

    # its twin: the project's own folder of that name, which every reader reads
    twin = tmp_path / "twin"
    _write(twin, {**SITE, **{f"config/env/{k}": v for k, v in COPIED.items()}})
    got = unread.survey(twin)["copied"]
    assert got["named"] == ["widget-lib 1.2.3 (config/env/vendor/widget)"], got


def test_copied_software_deeper_than_lantern_looks_is_said_not_looked_at(tmp_path, monkeypatch):
    monkeypatch.setattr(unread, "MAX_DEPTH", 2)
    _write(tmp_path, {**SITE, "vendor/top.js": "window.a = 1;\n", "vendor/a/b/c/deep.js": "window.b = 1;\n"})
    got = unread.survey(tmp_path)["copied"]
    assert (got["unnamed"], got["cut_short"]) == (1, True), got
    g, sec, rd = _run(tmp_path, offline=False)
    info = _tool(sec, "copied-audit")
    assert info["state"] == "partial" and "not looked at" in info["status"], info
    said = [line for line in _limits(g, sec, rd) if line.startswith("Software copied into")]
    assert len(said) == 1 and "was not looked at" in said[0], said

    twin = tmp_path / "twin"
    _write(twin, {**SITE, "vendor/top.js": "window.a = 1;\n", "vendor/a/b/near.js": "window.b = 1;\n"})
    got = unread.survey(twin)["copied"]
    assert (got["unnamed"], got["cut_short"]) == (2, False), got
    g, sec, rd = _run(twin, offline=False)
    said = [line for line in _limits(g, sec, rd) if line.startswith("Software copied into")]
    assert len(said) == 1 and "was not looked at" not in said[0], said


def test_a_project_with_no_copied_software_reads_as_before(tmp_path):
    _write(tmp_path, SITE)
    g, sec, rd = _run(tmp_path)
    info = _tool(sec, "copied-audit")
    assert info["state"] == "skipped" and info["applicable"] is False, info
    c = _criterion(rd, "dependencies")
    assert c["state"] == "not-applicable" and c["required"] is False, c


def test_a_copy_that_is_a_link_out_of_the_project_is_not_read(tmp_path):
    outside = tmp_path / "outside"
    _write(outside, {"package.json": '{"name": "secret-lib", "version": "9.9.9"}\n'})
    repo = tmp_path / "repo"
    _write(repo, SITE)
    (repo / "vendor" / "widget").mkdir(parents=True)
    try:
        (repo / "vendor" / "widget" / "package.json").symlink_to(outside / "package.json")
    except OSError:
        pytest.skip("this system makes no links")
    got = unread.survey(repo)
    assert "secret-lib" not in json.dumps(got), got


# ---------------------------------------------------------------- the report's own words

def test_a_project_with_no_python_is_not_told_about_python_built_in_calls(tmp_path):
    _write(tmp_path, SITE)
    g, sec, rd = _run(tmp_path)
    said = [line for line in _limits(g, sec, rd) if "call sites read" in line]
    assert len(said) == 1 and "built-in calls" in said[0] and "Python" not in said[0], said
