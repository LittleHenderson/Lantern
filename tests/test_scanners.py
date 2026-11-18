"""Scanner adapters must never report a failure as success (directive stage 2).

Every adapter (Bandit, Gitleaks and the built-in secret patterns, pip-audit, npm audit, the OSV audits) returns a
common record (`lantern.scanresult.record`): `state` is one of ok / partial / failed / timeout / unavailable /
skipped, with the tool's version, exit code, scope, exclusions and errors. Findings a scanner did produce are kept
even when the rest of its run failed. The tests feed each adapter empty output, broken and wrong-shaped JSON, a
missing tool, a timeout, an unreadable file and a partial failure, and then prove the states reach the command
line, the app's project summary, the stored results and the readiness score.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import re
import secrets
import socket
import string
import sys
from pathlib import Path

import pytest

from lantern import depaudit, evidence, pipeline, programs, readiness, scanresult, security
from lantern.cli import main as cli_main
from lantern.engine import build_graph
from lantern.scanresult import ToolRun

# ---------------------------------------------------------------- helpers


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _run(returncode=0, stdout="", stderr="", timed_out=False, error=None) -> ToolRun:
    return ToolRun(returncode=returncode, stdout=stdout, stderr=stderr, timed_out=timed_out, duration_ms=12, error=error)


def _fake_tool(monkeypatch, result: ToolRun):
    """Every external scanner process answers with `result`."""
    calls = []

    def run_tool(cmd, *, timeout, cwd=None, env=None):
        calls.append(list(cmd))
        return result
    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    return calls


PY_APP = {"app.py": "import subprocess\n\ndef go(x):\n    subprocess.run(x, shell=True)\n"}
BANDIT_HIT = {"errors": [], "generated_at": "2026-11-09", "metrics": {"_totals": {"loc": 4}, "./app.py": {"loc": 4}},
              "results": [{"filename": "app.py", "test_id": "B602", "issue_text": "shell", "issue_severity": "HIGH",
                           "issue_confidence": "HIGH", "line_number": 4, "issue_cwe": {"id": 78}, "more_info": "", "code": "x"}]}


# ---------------------------------------------------------------- the record


def test_record_states_and_status_sentences_for_old_readers():
    ok = scanresult.record("bandit", "ok", version="1.9.4", exit_code=1, scope={"files": 3})
    assert ok["state"] == "ok" and ok["status"] == "ok" and ok["applicable"] is True and ok["exit_code"] == 1
    assert scanresult.record("pip-audit", "skipped", "no Python dependency files")["status"] == "skipped: no Python dependency files"
    assert scanresult.record("pip-audit", "skipped", "no Python dependency files")["applicable"] is False
    off = scanresult.record("pip-audit", "skipped", "offline", applicable=True)
    assert off["applicable"] is True and off["status"] == "skipped: offline"
    assert scanresult.record("bandit", "failed", "empty output")["status"].startswith("error: empty output")
    t = scanresult.record("bandit", "timeout", "after 600 s")
    assert t["status"].startswith("error: timed out") and t["state"] == "timeout"
    u = scanresult.record("bandit", "unavailable", 'pip install "lantern[scan]"')
    assert u["status"].startswith("skipped: not installed") and u["state"] == "unavailable"
    p = scanresult.record("bandit", "partial", "2 files could not be read", errors=["a.py: bad syntax"])
    assert p["status"].startswith("partial: 2 files") and p["errors"] == ["a.py: bad syntax"]
    with pytest.raises(ValueError):
        scanresult.record("x", "done")


def test_state_of_reads_records_written_before_states_existed():
    assert scanresult.state_of({"tool": "bandit", "status": "ok"}) == "ok"
    assert scanresult.state_of({"tool": "lantern-secrets", "status": "ok (built-in patterns; install gitleaks for full coverage)"}) == "ok"
    assert scanresult.state_of({"tool": "pip-audit", "status": "skipped: no Python dependency files"}) == "skipped"
    assert scanresult.state_of({"tool": "bandit", "status": 'skipped: not installed (pip install "lantern[scan]")'}) == "unavailable"
    assert scanresult.state_of({"tool": "npm-audit", "status": "partial: web/package-lock.json: JSONDecodeError"}) == "partial"
    assert scanresult.state_of({"tool": "bandit", "status": "error: TimeoutExpired"}) == "timeout"
    assert scanresult.state_of({"tool": "maven-audit", "status": "error: URLError (network needed?)"}) == "failed"
    # nothing to check is not incomplete; a deliberate offline skip and an uninstalled tool are
    old = [{"tool": "pip-audit", "status": "skipped: no Python dependency files"},
           {"tool": "npm-audit", "status": "skipped: offline"},
           {"tool": "bandit", "status": 'skipped: not installed (pip install "lantern[scan]")'},
           {"tool": "lantern-web", "status": "ok"}]
    assert [x["tool"] for x in scanresult.incomplete(old)] == ["npm-audit", "bandit"]


def test_parse_json_names_each_bad_shape():
    assert scanresult.parse_json("", dict) == (None, "empty output")
    assert scanresult.parse_json("   \n", dict) == (None, "empty output")
    data, why = scanresult.parse_json("{not json", dict)
    assert data is None and why.startswith("broken JSON")
    data, why = scanresult.parse_json("[1, 2]", dict)
    assert data is None and "expected an object" in why
    assert scanresult.parse_json('{"a": 1}', dict) == ({"a": 1}, None)


def test_run_tool_reports_a_missing_program_and_a_timeout(tmp_path):
    r = scanresult.run_tool(["/nonexistent/program-xyz", "--version"], timeout=5)
    assert r.returncode is None and r.error and not r.timed_out
    import sys
    r = scanresult.run_tool([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert r.timed_out and r.returncode is None and r.duration_ms >= 400


# ---------------------------------------------------------------- Bandit


def test_bandit_findings_with_exit_code_one_are_ok(tmp_path, monkeypatch):
    _write(tmp_path, PY_APP)
    _fake_tool(monkeypatch, _run(1, json.dumps(BANDIT_HIT)))
    monkeypatch.setattr(security, "_tool_version", lambda cmd: "1.9.4")
    f, info = security.run_bandit(tmp_path)
    assert len(f) == 1 and f[0]["rule"] == "B602" and f[0]["file"] == "app.py"
    assert info["state"] == "ok" and info["status"] == "ok" and info["exit_code"] == 1 and info["version"] == "1.9.4"
    assert info["scope"]["files"] == 1 and info["findings"] == 1


@pytest.mark.parametrize("stdout,code,words", [
    ("", 0, "empty output"), ("", 1, "empty output"), ("{\"results\": [", 0, "broken JSON"),
    ("[]", 0, "expected an object"), ("{\"metrics\": {}}", 0, "no results list"),
])
def test_bandit_empty_broken_or_wrong_shaped_output_is_a_failure_not_a_clean_bill(tmp_path, monkeypatch, stdout, code, words):
    _write(tmp_path, PY_APP)
    _fake_tool(monkeypatch, _run(code, stdout, "boom"))
    f, info = security.run_bandit(tmp_path)
    assert f == [] and info["state"] == "failed" and words in info["why"], info
    assert info["status"].startswith("error:") and info["exit_code"] == code


def test_bandit_crash_exit_code_is_a_failure_with_its_message(tmp_path, monkeypatch):
    _write(tmp_path, PY_APP)
    _fake_tool(monkeypatch, _run(2, "", "bandit: error: unrecognized arguments: --what\n"))
    f, info = security.run_bandit(tmp_path)
    assert f == [] and info["state"] == "failed" and info["exit_code"] == 2
    assert "unrecognized arguments" in info["why"]


def test_bandit_timeout_is_its_own_state(tmp_path, monkeypatch):
    _write(tmp_path, PY_APP)
    _fake_tool(monkeypatch, _run(None, "", "", timed_out=True))
    f, info = security.run_bandit(tmp_path)
    assert f == [] and info["state"] == "timeout" and "timed out" in info["status"]


def test_bandit_file_errors_keep_the_findings_and_mark_the_run_partial(tmp_path, monkeypatch):
    _write(tmp_path, PY_APP | {"broken.py": "def (:\n"})
    data = json.loads(json.dumps(BANDIT_HIT))
    data["errors"] = [{"filename": "broken.py", "reason": "syntax error while parsing AST from file"}]
    data["metrics"]["./broken.py"] = {"loc": 1}
    _fake_tool(monkeypatch, _run(1, json.dumps(data)))
    f, info = security.run_bandit(tmp_path)
    assert len(f) == 1 and info["state"] == "partial"
    assert info["errors"] == ["broken.py: syntax error while parsing AST from file"] and "1 file" in info["why"]


def test_bandit_not_installed_is_unavailable_and_records_the_exclusions(tmp_path, monkeypatch):
    _write(tmp_path, PY_APP | {"node_modules/x/index.js": "", ".venv/lib/a.py": ""})
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a: None if name == "bandit" else real(name, *a))
    f, info = security.run_bandit(tmp_path)
    assert f == [] and info["state"] == "unavailable" and info["applicable"] is True
    assert info["status"].startswith("skipped: not installed")
    # and when it runs, the folders it was told to skip are written down
    monkeypatch.setattr(importlib.util, "find_spec", real)
    _fake_tool(monkeypatch, _run(0, json.dumps({**BANDIT_HIT, "results": []})))
    f, info = security.run_bandit(tmp_path)
    assert sorted(info["exclusions"]) == [".venv", "node_modules"]


def test_bandit_really_runs_and_fills_the_record(tmp_path):
    """No fakes: Bandit 1.x exits 1 when it finds something; the record must say ok, not error."""
    pytest.importorskip("bandit")
    _write(tmp_path, PY_APP)
    f, info = security.run_bandit(tmp_path)
    assert any(x["rule"] == "B602" for x in f)
    assert info["state"] == "ok" and info["exit_code"] == 1 and info["version"] and info["duration_ms"] >= 0


# ---------------------------------------------------------------- secrets: gitleaks and the built-in patterns


# gitleaks is asked about a file of Lantern's own before the project (the section after this one), so the stand-in
# of these tests answers that first question as the real program does and `project` stands for the run that follows.


def test_gitleaks_crash_falls_back_to_patterns_but_is_recorded_as_a_failure(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": 'KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n'})
    calls = _stand_in(monkeypatch, tmp_path, project=lambda cmd: _run(2, "", "panic: something broke\n"))
    f, infos = security.run_secrets(tmp_path)
    assert [c["project"] for c in calls] == [False, True]
    by = {i["tool"]: i for i in infos}
    assert by["gitleaks"]["state"] == "failed" and "something broke" in by["gitleaks"]["why"]
    assert by["lantern-secrets"]["state"] == "ok" and by["lantern-secrets"]["fallback_for"] == "gitleaks"
    assert len(f) == 1 and f[0]["tool"] == "lantern-secrets"


def test_gitleaks_report_file_is_read_and_exit_code_one_means_findings(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})

    def project(cmd):
        report = Path(cmd[cmd.index("-r") + 1])
        assert report.suffix == ".json" and not str(report).startswith("/dev")
        report.write_text(json.dumps([{"RuleID": "aws-access-token", "Description": "AWS key", "StartLine": 1,
                                       "File": os.path.join(_after(cmd, "-s"), "config.py")}]), encoding="utf-8")
        return _run(1, "", "")
    _stand_in(monkeypatch, tmp_path, project=project)
    f, infos = security.run_secrets(tmp_path)
    assert len(f) == 1 and f[0]["tool"] == "gitleaks" and f[0]["snippet"] == "[redacted]"
    assert infos == [infos[0]] and infos[0]["state"] == "ok" and infos[0]["exit_code"] == 1


def test_gitleaks_clean_run_leaves_an_empty_report(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})
    _stand_in(monkeypatch, tmp_path, project=lambda cmd: _run(0, "", ""))     # exit 0, report file never written
    f, infos = security.run_secrets(tmp_path)
    assert f == [] and infos[0]["tool"] == "gitleaks" and infos[0]["state"] == "ok" and infos[0]["findings"] == 0


def test_gitleaks_timeout_and_broken_report_are_failures(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})
    _stand_in(monkeypatch, tmp_path, project=lambda cmd: _run(None, "", "", timed_out=True))
    _, infos = security.run_secrets(tmp_path)
    assert infos[0]["tool"] == "gitleaks" and infos[0]["state"] == "timeout" and infos[1]["tool"] == "lantern-secrets"

    def project(cmd):
        Path(cmd[cmd.index("-r") + 1]).write_text("<html>", encoding="utf-8")
        return _run(1, "", "")
    _stand_in(monkeypatch, tmp_path, project=project)
    _, infos = security.run_secrets(tmp_path)
    assert infos[0]["state"] == "failed" and "broken JSON" in infos[0]["why"]


def test_gitleaks_absent_is_written_down_beside_the_built_in_scan(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})
    monkeypatch.setattr(programs, "find", lambda name: None)
    f, infos = security.run_secrets(tmp_path)
    by = {i["tool"]: i for i in infos}
    assert by["gitleaks"]["state"] == "unavailable" and by["gitleaks"]["applicable"] is False
    assert by["lantern-secrets"]["state"] == "ok" and by["lantern-secrets"]["scope"]["files"] == 1


def test_built_in_secret_scan_counts_files_it_could_not_read(tmp_path, monkeypatch):
    _write(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n", ".env": "TOKEN=abc\n"})
    monkeypatch.setattr(programs, "find", lambda name: None)
    real = security._read_text

    def read(p: Path, repo: Path) -> str:
        if p.name == "b.py":
            raise OSError(13, "Permission denied")
        return real(p, repo)
    monkeypatch.setattr(security, "_read_text", read)
    f, infos = security.run_secrets(tmp_path)
    s = next(i for i in infos if i["tool"] == "lantern-secrets")
    assert s["state"] == "partial" and s["errors"] == ["b.py: Permission denied"] and s["scope"]["files"] == 2


def test_a_keys_place_kept_by_filler_is_no_secret_and_a_key_beside_it_still_is(tmp_path):
    """An example file keeps a key's place with filler (`sk_live_` and 24 times `x`): the right start for the
    pattern, and nothing but one filler character after it. Until 2026-11-16 the built-in patterns called that a
    possible secret, which ranks critical. Filler is only what cannot be a key: every letter and digit after the
    fixed start is `x`, or every one is `0`, or the text is the one example key a provider prints in its own
    guide. Anything else that fits a pattern is still a finding, the safe side: one other character among the
    filler, a body of another repeated letter, a key that looks made up but is no filler. The record counts what
    was passed over."""
    x24, real = "x" * 24, "a1B2c3D4" * 3
    _write(tmp_path, {
        ".env.example": "\n".join([
            "STRIPE_SECRET_KEY=" + "sk_live_" + x24,
            "GITHUB_TOKEN=" + "ghp_" + "X" * 36,
            "AWS_ACCESS_KEY_ID=" + "AKIA" + "X" * 16,
            "AWS_OTHER_KEY_ID=" + "AKIA" + "0" * 16,
            "SLACK_BOT_TOKEN=" + "xoxb-" + "xxxxxxxxxxxx-xxxxxxxxxxxx",
            "ANTHROPIC_API_KEY=" + "sk-ant-" + "xxxx-xxxx_" * 3,
            "OPENAI_API_KEY=" + "sk-" + "x" * 40,
            "AWS_GUIDE_KEY_ID=" + "AKIA" + "IOSFODNN7" + "EXAMPLE",
            ""]),
        ".env": "\n".join([
            "STRIPE_SECRET_KEY=" + "sk_live_" + real,                       # line 1: a key
            "OLD_KEY=" + "sk_live_" + "x" * 23 + "7",                       # line 2: one other character among the filler
            "TEST_KEY=" + "sk_live_" + "a" * 24,                            # line 3: another repeated letter stays a finding
            "COUNT_KEY=" + "sk_live_" + "1234567890" * 3,                   # line 4: looks made up, is no filler
            "BOTH=" + "sk_live_" + x24 + " " + "sk_live_" + real,           # line 5: filler and a key on one line
            "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7" + "EXAMPLF",        # line 6: not the guide's key
            ""]),
        "config.py": "KEY = '" + "sk_live_" + x24 + "'\n"})                 # filler is filler in a code file too
    found, record = security._builtin_secrets(tmp_path)
    assert sorted((f["file"], f["line"], f["rule"]) for f in found) == [
        (".env", 1, "stripe-live-key"), (".env", 2, "stripe-live-key"), (".env", 3, "stripe-live-key"),
        (".env", 4, "stripe-live-key"), (".env", 5, "stripe-live-key"), (".env", 6, "aws-access-key")]
    assert record["state"] == "ok" and record["scope"] == {"files": 3, "placeholders": 10}, record
    assert record["version"] == security.SECRETS_VERSION == "3"
    assert not any("xxx" in json.dumps(f) for f in found)


def test_with_no_filler_the_built_in_scans_record_is_as_it_was(tmp_path):
    _write(tmp_path, {"config.py": "KEY = '" + "sk_live_" + "a1B2c3D4" * 3 + "'\n"})
    found, record = security._builtin_secrets(tmp_path)
    assert len(found) == 1 and record["scope"] == {"files": 1}


# ---------------------------------------------------------------- gitleaks: settings of Lantern's own, a folder of its own
#
# gitleaks takes what it is to look for, and what it is to leave out, from more places than its command line. So
# Lantern starts it with a settings file of its own (gitleaks' own rules and nothing else), in an empty folder of
# its own, with an empty list of findings to leave out, told to pass over a comment that switches a line off, with
# no GITLEAKS_ variable of the shell, and hands it the project under a name of Lantern's own. Before the project it
# is handed one file of Lantern's own that holds a key made for this run: a scanner that does not find that key is
# not believed about the project, and the built-in patterns run. The stand-in tests run everywhere; the tests with
# the real program run where LANTERN_TESTS_GITLEAKS names one (CI: one pinned version, built from its source).

OWN_SETTINGS = "[extend]\nuseDefault = true\n"
GITLEAKS = os.environ.get("LANTERN_TESTS_GITLEAKS", "").strip() and os.path.normpath(os.environ["LANTERN_TESTS_GITLEAKS"].strip())


def _a_key() -> str:
    """Text of the shape of a GitHub token, made for this run: never a real one and never in the repository."""
    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


def _after(cmd, flag):
    return cmd[cmd.index(flag) + 1] if flag in cmd else None


def _text_of(cmd, flag):
    name = _after(cmd, flag)
    return Path(name).read_text(encoding="utf-8") if name and os.path.isfile(name) else None


def _in_project(name, repo) -> bool:
    return Path(os.path.abspath(name)).is_relative_to(os.path.abspath(repo))


def _finds_keys(cmd, where=None, also=()):
    """What an honest gitleaks does with the folder it is handed: every line that holds a key of that shape, each
    file named by the path the folder was handed under (`where`: a program that names the files another way)."""
    source, rows = _after(cmd, "-s"), []
    for folder, _, names in os.walk(source):
        for name in sorted(names):
            full = os.path.join(folder, name)
            try:
                lines = Path(full).read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for n, line in enumerate(lines, 1):
                if re.search(r"ghp_[0-9A-Za-z]{36}", line):
                    rows.append({"RuleID": "github-pat", "Description": "GitHub token", "StartLine": n,
                                 "File": full if where is None else where(full)})
    rows += [{"RuleID": "github-pat", "Description": "GitHub token", "StartLine": 1, "File": os.path.join(source, x)}
             for x in also]
    Path(_after(cmd, "-r")).write_text(json.dumps(rows), encoding="utf-8")
    return _run(0, "", "")


def _stand_in(monkeypatch, repo, project=_finds_keys, first=_finds_keys):
    """A gitleaks for these tests: `first` answers what Lantern asks it before the project, `project` the run on
    the project. Gives the list of its calls: what each was started with, and what was there at that moment."""
    calls, home = [], os.path.realpath(repo)

    def run_tool(cmd, *, timeout, cwd=None, env=None):
        source = _after(cmd, "-s")
        on_project = os.path.realpath(source) == home
        calls.append({"cmd": list(cmd), "cwd": cwd, "env": env, "source": source, "project": on_project,
                      "settings": _text_of(cmd, "--config"), "leave_out": _text_of(cmd, "--gitleaks-ignore-path"),
                      "in_cwd": sorted(os.listdir(cwd)) if cwd else None})
        return (project if on_project else first)(cmd)
    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    monkeypatch.setattr(programs, "find", lambda name, path=None: "/usr/bin/gitleaks" if name == "gitleaks" else None)
    return calls


def _kept(repo) -> dict:
    """Every file of a folder with its text: what a run must leave exactly as it was."""
    return {p.relative_to(repo).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted(Path(repo).rglob("*")) if p.is_file() and not p.is_symlink()}


def _its_own(repo, key):
    """A project that brings what gitleaks would take from a project: settings, a list of findings to leave out,
    a comment on the line."""
    here = repo / "config.py"
    lines = [f"{name}:{rule}:1" for rule in ("github-pat", "generic-api-key")
             for name in ("config.py", "./config.py", str(here), os.path.realpath(here))]
    return _write(repo, {"config.py": f'TOKEN = "{key}"  # gitleaks:allow\n', ".gitleaks.toml": 'title = "the project\'s own"\n',
                         ".gitleaksignore": "\n".join(lines) + "\n"})


def test_gitleaks_is_started_with_settings_of_lanterns_own_in_a_folder_of_its_own(tmp_path, monkeypatch):
    """Whatever the project and the person's shell bring, the program is started the same way, twice: on a file of
    Lantern's own first, then on the project. Afterwards nothing of Lantern's is left and nothing of the project
    is touched."""
    repo = _its_own(tmp_path / "p", _a_key())
    before = _kept(repo)
    for name in ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "GITLEAKS_ANYTHING"):
        monkeypatch.setenv(name, str(repo / ".gitleaks.toml"))
    calls = _stand_in(monkeypatch, repo)
    found, records = security.run_secrets(repo)
    assert [(f["tool"], f["file"], f["line"]) for f in found] == [("gitleaks", "config.py", 1)], (found, records)
    assert records == [records[0]] and records[0]["state"] == "ok" and records[0]["way"] == "linked", records
    assert [c["project"] for c in calls] == [False, True]
    for c in calls:
        cmd = c["cmd"]
        assert c["settings"] == OWN_SETTINGS and c["leave_out"] == "" and "--ignore-gitleaks-allow" in cmd, cmd
        assert not any(_in_project(_after(cmd, flag), repo) for flag in ("--config", "--gitleaks-ignore-path", "-r", "-s")), cmd
        assert c["cwd"] and not _in_project(c["cwd"], repo) and c["in_cwd"] == [], c
        assert not [k for k in c["env"] if k.upper().startswith("GITLEAKS_")] and c["env"].get("PATH"), sorted(c["env"])
    way = calls[1]["source"]                       # the project, under a name of Lantern's own, as a folder
    assert way.endswith(os.sep) and len(Path(way).name) >= 32 and Path(way).name != Path(calls[0]["source"]).name
    for c in calls:                                # nothing of Lantern's is left, nothing of the project is touched
        assert not os.path.lexists(c["source"].rstrip(os.sep)) and not os.path.exists(_after(c["cmd"], "--config"))
        assert not os.path.exists(c["cwd"])
    assert _kept(repo) == before
    again = _stand_in(monkeypatch, repo)
    security.run_secrets(repo)
    assert Path(again[1]["source"]).name != Path(way).name          # a new name every run


def test_what_gitleaks_found_keeps_the_projects_own_paths_and_its_id(tmp_path, monkeypatch):
    """The twin of every refusal below: an honest run. A finding is named by the file's path in the project and
    keeps the id it always had, so what a person accepted or fixed is still the same finding."""
    key = _a_key()
    repo = _write(tmp_path / "p", {"config.py": f'x = 1\nTOKEN = "{key}"\n', "pkg/deep/settings.py": f'TOKEN = "{key}"\n',
                                   "clean.py": "y = 2\n"})
    _stand_in(monkeypatch, repo)
    found, records = security.run_secrets(repo)
    assert sorted((f["file"], f["line"]) for f in found) == [("config.py", 2), ("pkg/deep/settings.py", 1)], found
    assert {f["id"] for f in found} == {security._fid("gitleaks", "github-pat", "config.py", 2),
                                        security._fid("gitleaks", "github-pat", "pkg/deep/settings.py", 1)}
    assert all(f["snippet"] == "[redacted]" and key not in json.dumps(f) for f in found)
    assert records == [records[0]] and records[0]["state"] == "ok" and records[0]["findings"] == 2, records


def _finds_nothing(cmd):
    Path(_after(cmd, "-r")).write_text("[]", encoding="utf-8")
    return _run(0, "", "")


@pytest.mark.parametrize("first, words", [
    (_finds_nothing, "did not find"),
    (lambda cmd: _run(0, "", ""), "did not find"),
    (lambda cmd: _run(126, "", "Error: unknown flag: --ignore-gitleaks-allow\n"), "unknown flag"),
    (lambda cmd: _run(1, "", "FTL could not load the settings\n"), "could not load the settings"),
    (lambda cmd: _run(None, "", "", timed_out=True), "did not answer"),
    (lambda cmd: _run(None, error="OSError: [Errno 8] Exec format error"), "Exec format error"),
], ids=["it finds nothing", "it writes no report", "it does not know an option", "it ends with an error",
        "it does not answer", "it cannot be started"])
def test_a_gitleaks_that_does_not_find_lanterns_own_key_is_not_believed_about_the_project(tmp_path, monkeypatch, first, words):
    """Old enough not to know an option, started with rules that find nothing, or not started at all: what such a
    program would say about the project is not asked for. The record says why, and the built-in patterns run."""
    repo = _write(tmp_path / "p", {"config.py": 'KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n'})
    calls = _stand_in(monkeypatch, repo, first=first)
    found, records = security.run_secrets(repo)
    by = {r["tool"]: r for r in records}
    assert by["gitleaks"]["state"] == "failed" and words in by["gitleaks"]["why"], by["gitleaks"]
    assert "Lantern" in by["gitleaks"]["why"] and calls and not any(c["project"] for c in calls), by["gitleaks"]
    assert by["lantern-secrets"]["state"] == "ok" and by["lantern-secrets"]["fallback_for"] == "gitleaks"
    assert [(f["tool"], f["file"]) for f in found] == [("lantern-secrets", "config.py")]


def test_a_file_gitleaks_names_outside_what_it_was_handed_fails_the_run(tmp_path, monkeypatch):
    """The program found Lantern's own key under the name it was handed, and then names the project's files
    another way: its list cannot be told to be whole. Failed, in the record's words, and the patterns run."""
    repo = _write(tmp_path / "p", {"config.py": f'TOKEN = "{_a_key()}"\n', "aws.py": 'KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n'})
    calls = _stand_in(monkeypatch, repo, project=lambda cmd: _finds_keys(cmd, where=os.path.realpath))
    found, records = security.run_secrets(repo)
    by = {r["tool"]: r for r in records}
    assert [c["project"] for c in calls] == [False, True] and by["gitleaks"]["state"] == "failed", records
    assert "outside" in by["gitleaks"]["why"] and by["lantern-secrets"]["fallback_for"] == "gitleaks", by["gitleaks"]
    assert {f["tool"] for f in found} == {"lantern-secrets"}


@pytest.mark.skipif(sys.platform == "win32", reason="a link made by the test: POSIX")
def test_a_file_gitleaks_names_through_a_link_out_of_the_project_or_that_is_not_there_is_no_finding(tmp_path, monkeypatch):
    """A scanner's row is a finding only for a file of the project. The twin, a plain file two folders down, is in
    the test above."""
    outside = _write(tmp_path / "elsewhere", {"secret.py": f'TOKEN = "{_a_key()}"\n'})
    repo = _write(tmp_path / "p", {"config.py": f'TOKEN = "{_a_key()}"\n'})
    (repo / "out").symlink_to(outside, target_is_directory=True)
    _stand_in(monkeypatch, repo, project=lambda cmd: _finds_keys(cmd, also=("out/secret.py", "gone.py")))
    found, records = security.run_secrets(repo)
    assert [f["file"] for f in found] == ["config.py"] and records[0]["state"] == "ok" and records[0]["findings"] == 1, (found, records)


def test_without_a_folder_of_lanterns_own_gitleaks_is_not_started(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", {"config.py": 'KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n'})
    calls = _stand_in(monkeypatch, repo)

    @contextlib.contextmanager
    def no_folder():
        raise OSError(28, "No space left on device")
        yield
    monkeypatch.setattr(programs, "folder", no_folder)
    found, records = security.run_secrets(repo)
    by = {r["tool"]: r for r in records}
    assert calls == [] and by["gitleaks"]["state"] == "failed" and "No space left on device" in by["gitleaks"]["why"], records
    assert "folder" in by["gitleaks"]["why"] and by["lantern-secrets"]["fallback_for"] == "gitleaks"
    assert [f["tool"] for f in found] == ["lantern-secrets"]


def _no_link(monkeypatch):
    def refuse(target, link):
        raise OSError(1, "Operation not permitted")
    monkeypatch.setattr(security, "_gitleaks_link", refuse)


def test_where_no_name_of_lanterns_own_can_be_made_gitleaks_gets_the_project_by_its_path(tmp_path, monkeypatch):
    """A system that lets Lantern make no link: the project is handed over as it always was, with the settings,
    the folder and the first question as everywhere. That is as good where the project brings no list of findings
    to leave out."""
    repo = _write(tmp_path / "p", {"config.py": f'TOKEN = "{_a_key()}"  # gitleaks:allow\n', ".gitleaks.toml": 'title = "own"\n'})
    _no_link(monkeypatch)
    calls = _stand_in(monkeypatch, repo)
    found, records = security.run_secrets(repo)
    assert [f["file"] for f in found] == ["config.py"] and records == [records[0]], (found, records)
    assert records[0]["state"] == "ok" and records[0]["way"] == "plain", records
    assert [c["project"] for c in calls] == [False, True] and calls[1]["source"] == str(repo)
    for c in calls:
        assert c["settings"] == OWN_SETTINGS and c["leave_out"] == "" and "--ignore-gitleaks-allow" in c["cmd"]
        assert not _in_project(c["cwd"], repo) and c["in_cwd"] == []


@pytest.mark.parametrize("as_a", ["file", "link"])
def test_where_no_name_of_lanterns_own_can_be_made_a_project_with_its_own_list_is_not_scanned_by_gitleaks(tmp_path, monkeypatch, as_a):
    """The same system, and the project brings a list of findings for gitleaks to leave out: handed over by its
    own path the program would read it. It is not started on the project; the record says why; the patterns run."""
    if as_a == "link" and sys.platform == "win32":
        pytest.skip("a link made by the test: POSIX")
    repo = _write(tmp_path / "p", {"config.py": 'KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n'})
    if as_a == "file":
        (repo / ".gitleaksignore").write_text("config.py:aws-access-token:1\n", encoding="utf-8")
    else:
        (repo / ".gitleaksignore").symlink_to(tmp_path / "nowhere")
    _no_link(monkeypatch)
    calls = _stand_in(monkeypatch, repo)
    found, records = security.run_secrets(repo)
    by = {r["tool"]: r for r in records}
    assert by["gitleaks"]["state"] == "failed" and ".gitleaksignore" in by["gitleaks"]["why"], by["gitleaks"]
    assert not any(c["project"] for c in calls) and by["lantern-secrets"]["fallback_for"] == "gitleaks"
    assert [(f["tool"], f["file"]) for f in found] == [("lantern-secrets", "config.py")]


def test_a_gitleaks_that_names_files_by_where_a_link_leads_gets_the_project_by_its_path(tmp_path, monkeypatch):
    """A program that looks through the name it was handed and names files by where it leads: the name of
    Lantern's own protects nothing there, so the first question fails that way and is asked the plain way."""
    key = _a_key()
    repo = _write(tmp_path / "p", {"config.py": f'TOKEN = "{key}"\n'})
    through = lambda cmd: _finds_keys(cmd, where=os.path.realpath)      # noqa: E731
    calls = _stand_in(monkeypatch, repo, project=through, first=through)
    found, records = security.run_secrets(repo)
    assert [f["file"] for f in found] == ["config.py"] and records[0]["state"] == "ok" and records[0]["way"] == "plain", records
    assert [c["project"] for c in calls] == [False, False, True] and calls[2]["source"] == str(repo)
    (repo / ".gitleaksignore").write_text("config.py:github-pat:1\n", encoding="utf-8")
    calls = _stand_in(monkeypatch, repo, project=through, first=through)
    found, records = security.run_secrets(repo)
    assert records[0]["state"] == "failed" and not any(c["project"] for c in calls), records


SH_GITLEAKS = """#!/bin/sh
# a stand-in for the gitleaks program: it writes down how it was started, and names every file with a key in it
here=$(dirname "$0")
echo "$1 cwd=$(pwd) variables=$(env | grep -c '^GITLEAKS_')" >> "$here/asked.log"
if [ "$1" = "version" ]; then echo 8.30.1; exit 0; fi
while [ $# -gt 0 ]; do
  case "$1" in -s) src="$2" ;; -r) out="$2" ;; esac
  shift
done
rows=""
for f in $(grep -rl 'ghp_' "$src" 2>/dev/null); do
  n=$(grep -n 'ghp_' "$f" | head -1 | cut -d: -f1)
  rows="$rows${rows:+,}{\\"RuleID\\": \\"github-pat\\", \\"File\\": \\"$f\\", \\"StartLine\\": $n}"
done
printf '[%s]' "$rows" > "$out"
"""


@pytest.mark.skipif(sys.platform == "win32", reason="a shell script stands in for the program: POSIX")
def test_every_start_of_gitleaks_is_in_a_folder_of_lanterns_own_without_its_variables(tmp_path, monkeypatch):
    """A real process this time, started inside the project with the shell's variables set: also the question
    which version it is goes to a program that stands in a folder of Lantern's own and sees none of them."""
    repo = _its_own(tmp_path / "p", _a_key())
    program = tmp_path / "bin" / "gitleaks"
    _write(tmp_path, {"bin/gitleaks": SH_GITLEAKS})
    program.chmod(0o755)
    monkeypatch.setenv("PATH", str(program.parent) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("GITLEAKS_CONFIG", str(repo / ".gitleaks.toml"))
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", 'title = "the shell\'s"')
    monkeypatch.chdir(repo)
    found, records = security.run_secrets(repo)
    assert [(f["tool"], f["file"], f["line"]) for f in found] == [("gitleaks", "config.py", 1)], (found, records)
    assert records[0]["state"] == "ok" and records[0]["version"] == "8.30.1", records
    asked = (program.parent / "asked.log").read_text(encoding="utf-8").splitlines()
    assert sorted(line.split()[0] for line in asked) == ["detect", "detect", "version"], asked
    for line in asked:
        cwd = line.split(" cwd=", 1)[1].rsplit(" variables=", 1)[0]
        assert line.endswith(" variables=0") and not _in_project(cwd, repo) and not os.path.exists(cwd), line


# The real program. Each dangerous project beside its twin: the same key alone, and a project with no key.

needs_gitleaks = pytest.mark.skipif(not GITLEAKS, reason="no gitleaks named for these tests (LANTERN_TESTS_GITLEAKS)")


@pytest.fixture
def the_real_one(monkeypatch, request):
    """The gitleaks this run was told of, as the program Lantern finds. A run told of one that is not there fails."""
    assert os.path.isabs(GITLEAKS) and os.path.isfile(GITLEAKS), f"LANTERN_TESTS_GITLEAKS names no program: {GITLEAKS!r}"
    real = programs.find
    monkeypatch.setattr(programs, "find", lambda name, path=None: GITLEAKS if name == "gitleaks" else real(name, path))
    for name in [k for k in os.environ if k.upper().startswith("GITLEAKS_")]:
        monkeypatch.delenv(name)

    def said(records):
        ran = getattr(request.config, "_lantern_ran_against", None)
        if ran is None:
            ran = request.config._lantern_ran_against = {}
        ran["gitleaks"] = f"{records[0].get('version') or 'of a version it did not tell'} ({records[0].get('way')})"
    return said


@needs_gitleaks
def test_the_real_gitleaks_finds_a_key_and_finds_none_where_there_is_none(tmp_path, the_real_one):
    key = _a_key()
    repo = _write(tmp_path / "p", {"config.py": f'TOKEN = "{key}"\n', "app.py": "def go():\n    return 1\n"})
    found, records = security.run_secrets(repo)
    the_real_one(records)
    assert [(f["tool"], f["rule"], f["file"], f["line"]) for f in found] == [("gitleaks", "github-pat", "config.py", 1)], (found, records)
    assert records == [records[0]] and records[0]["state"] == "ok" and records[0]["findings"] == 1, records
    assert key not in json.dumps(found) + json.dumps(records)
    clean = _write(tmp_path / "q", {"config.py": 'TOKEN = os.environ["TOKEN"]\n', "app.py": "def go():\n    return 1\n"})
    found, records = security.run_secrets(clean)
    assert found == [] and records == [records[0]] and records[0]["state"] == "ok" and records[0]["findings"] == 0, records


@needs_gitleaks
def test_the_real_gitleaks_finds_the_same_key_beside_everything_a_project_and_a_shell_can_bring(tmp_path, monkeypatch, the_real_one):
    """The same key and the same finding, with the project's own settings file, its list of findings to leave
    out, a comment on the line, and the shell's variables for settings."""
    key = _a_key()
    alone = _write(tmp_path / "alone" / "p", {"config.py": f'TOKEN = "{key}"\n'})
    want, _ = security.run_secrets(alone)
    repo = _its_own(tmp_path / "beside" / "p", key)
    _write(repo, {"pkg/.gitleaksignore": "x:github-pat:1\n", "pkg/.gitleaks.toml": 'title = "deeper"\n',
                  "pkg/inner.py": f'TOKEN = "{key}"  # gitleaks:allow\n'})
    before = _kept(repo)
    nothing = _write(tmp_path / "shell", {"none.toml": 'title = "the shell\'s"\n'}) / "none.toml"
    monkeypatch.setenv("GITLEAKS_CONFIG", str(nothing))
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", 'title = "the shell\'s"\n')
    monkeypatch.chdir(repo)
    found, records = security.run_secrets(repo)
    the_real_one(records)
    assert sorted((f["rule"], f["file"], f["line"]) for f in found) == [("github-pat", "config.py", 1), ("github-pat", "pkg/inner.py", 1)], (found, records)
    assert records == [records[0]] and records[0]["state"] == "ok", records
    assert [f["id"] for f in found if f["file"] == "config.py"] == [f["id"] for f in want] and len(want) == 1
    assert _kept(repo) == before and key not in json.dumps(found) + json.dumps(records)


# ---------------------------------------------------------------- pip-audit


PIP_OK = {"dependencies": [{"name": "flask", "version": "2.0.1", "vulns": [{"id": "PYSEC-1", "fix_versions": ["2.2.5"], "description": "bad"}]}]}


def _pip_repo(tmp_path, monkeypatch):
    _write(tmp_path, {"requirements.txt": "flask==2.0.1\n"})
    monkeypatch.setattr(programs, "find", lambda n: "/bin/" + n)
    monkeypatch.setattr(depaudit, "_pkg_version", lambda n: "2.10.1")


def test_pip_audit_exit_code_one_with_vulnerabilities_is_ok(tmp_path, monkeypatch):
    _pip_repo(tmp_path, monkeypatch)
    _fake_tool(monkeypatch, _run(1, json.dumps(PIP_OK)))
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert len(f) == 1 and info["state"] == "ok" and info["exit_code"] == 1 and info["checked"] == 1
    assert info["version"] == "2.10.1" and info["scope"]["files"] == ["requirements.txt"]


@pytest.mark.parametrize("stdout,code,words", [
    ("", 0, "empty output"), ("<html>registry is down</html>", 0, "broken JSON"), ("[]", 0, "expected an object"),
    ('{"dependencies": "nope"}', 0, "no dependencies list"),
])
def test_pip_audit_bad_output_is_a_failure(tmp_path, monkeypatch, stdout, code, words):
    _pip_repo(tmp_path, monkeypatch)
    _fake_tool(monkeypatch, _run(code, stdout))
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert f == [] and info["state"] == "failed" and words in info["why"], info


def test_pip_audit_crash_timeout_missing_and_offline_states(tmp_path, monkeypatch):
    _pip_repo(tmp_path, monkeypatch)
    _fake_tool(monkeypatch, _run(2, "", "ERROR: could not resolve host pypi.org\n"))
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert info["state"] == "failed" and "could not resolve host" in info["why"] and info["exit_code"] == 2
    _fake_tool(monkeypatch, _run(None, "", "", timed_out=True))
    assert depaudit.run_pip_audit(tmp_path, no_network=False)[1]["state"] == "timeout"
    monkeypatch.setattr(programs, "find", lambda n: None)
    info = depaudit.run_pip_audit(tmp_path, no_network=False)[1]
    assert info["state"] == "unavailable" and info["applicable"] is True
    monkeypatch.setattr(programs, "find", lambda n: "/bin/" + n)
    info = depaudit.run_pip_audit(tmp_path, no_network=True)[1]
    assert info["state"] == "skipped" and info["why"] == "offline" and info["applicable"] is True


def test_pip_audit_skipped_packages_make_the_run_partial_and_keep_findings(tmp_path, monkeypatch):
    _write(tmp_path, {"requirements.txt": "flask==2.0.1\nleftpad==1.0\n"})
    monkeypatch.setattr(programs, "find", lambda n: "/bin/" + n)
    data = {"dependencies": PIP_OK["dependencies"] + [{"name": "leftpad", "skip_reason": "Dependency not found on PyPI and could not be audited: leftpad (1.0)"}]}
    _fake_tool(monkeypatch, _run(1, json.dumps(data)))
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert len(f) == 1 and info["state"] == "partial" and info["errors"] == ["leftpad: Dependency not found on PyPI and could not be audited: leftpad (1.0)"]


# What pip-audit writes when the service it asks fails it. pip-audit 2.10.1 catches neither a read timeout nor a cut
# connection, so its traceback ends with the name `requests` gives the error; a connection it could not make it says
# in a sentence of its own, after its logger's prefix (pip_audit/_service/pypi.py, pip_audit/_cli.py).
PYPI_SLOW = ("Traceback (most recent call last):\n"
             "  File \"/usr/lib/python3/site-packages/requests/adapters.py\", line 713, in send\n"
             "    raise ReadTimeout(e, request=request)\n"
             "requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='pypi.org', port=443): Read timed out. "
             "(read timeout=15)\n")
PYPI_CUT = ("Traceback (most recent call last):\n"
            "requests.exceptions.ConnectionError: ('Connection aborted.', ConnectionResetError(104, "
            "'Connection reset by peer'))\n")
PYPI_BUSY = ("Traceback (most recent call last):\n"
             "requests.exceptions.HTTPError: 503 Server Error: Service Unavailable for url: "
             "https://pypi.org/pypi/flask/2.0.1/json\n\n"
             "The above exception was the direct cause of the following exception:\n\n"
             "Traceback (most recent call last):\n"
             "pip_audit._service.interface.ServiceError\n")
PYPI_UNREACHED = ("ERROR:pip_audit._cli:Could not connect to PyPI's vulnerability feed\n"
                  "ERROR:pip_audit._cli:Tip: your network may be blocking this service. Try another service with "
                  "`-s SERVICE`\n")


def _tries(monkeypatch, *runs, step=1.0):
    """pip-audit answers with each of `runs` in turn (the last one again after that); the clock moves `step`
    seconds a try, and a pause before another try is written down and not waited for. Returns the time limit each
    try was given, and the pauses."""
    limits, pauses, now = [], [], [0.0]

    def run_tool(cmd, *, timeout, cwd=None, env=None):
        limits.append(timeout)
        now[0] += step
        return runs[min(len(limits), len(runs)) - 1]

    def pause(seconds):
        pauses.append(seconds)
        now[0] += seconds
    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    monkeypatch.setattr(depaudit, "_clock", lambda: now[0], raising=False)
    monkeypatch.setattr(depaudit, "_pause", pause, raising=False)
    return limits, pauses


@pytest.mark.parametrize("stderr,words", [
    (PYPI_SLOW, "pypi.org did not answer in time"), (PYPI_CUT, "the connection to pypi.org failed"),
    (PYPI_BUSY, "pypi.org answered with an error"), (PYPI_UNREACHED, "the connection to pypi.org failed"),
])
def test_pip_audit_asks_again_when_the_service_it_asks_failed_it(tmp_path, monkeypatch, stderr, words):
    """One slow answer of pypi.org ended pip-audit, which does not ask again itself, and Lantern's check of itself
    read as not done (CI, 2026-11-18: "Read timed out. (read timeout=15)"). When the service pip-audit asks failed
    it, pip-audit is started again, at most PIP_AUDIT_TRIES times in all and within the audit's time limit, and the
    record says how often and why; what the last try found is the audit's."""
    _pip_repo(tmp_path, monkeypatch)
    limits, pauses = _tries(monkeypatch, _run(1, "", stderr), _run(1, json.dumps(PIP_OK)))
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert len(limits) == 2 and len(f) == 1 and info["state"] == "ok", (limits, info)
    assert pauses == [depaudit.PIP_AUDIT_PAUSES[0]] and info["tries"] == 2 and info["asked_again"] == [words], info
    assert words in info["status"] and info["exit_code"] == 1 and info["duration_ms"] == 24, info
    # it failed every time: the audit is not done, as before, and says how often it asked
    limits, pauses = _tries(monkeypatch, _run(1, "", stderr))
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert f == [] and info["state"] == "failed" and len(limits) == depaudit.PIP_AUDIT_TRIES == info["tries"], info
    assert info["asked_again"] == [words] * (depaudit.PIP_AUDIT_TRIES - 1), info
    assert pauses == list(depaudit.PIP_AUDIT_PAUSES) and scanresult.tail(stderr) in info["why"], info
    assert words in info["status"], info


@pytest.mark.parametrize("run", [
    _run(1, "", "ERROR:pip_audit._cli:invalid requirements input: flask==2.0.1\n"),       # a file it refuses
    _run(1, "", "ERROR:pip_audit._cli:invalid requirements input: requests.exceptions.ReadTimeout==1\n"),   # a name
    _run(1, "", "requests.exceptions.SSLError: HTTPSConnectionPool(host='pypi.org', port=443): certificate verify "
                "failed\n"),
    _run(1, "", "requests.exceptions.ProxyError: HTTPSConnectionPool(host='pypi.org', port=443): Unable to connect "
                "to proxy\n"),
    _run(1, "", "requests.exceptions.HTTPError: 403 Client Error: Forbidden for url: "
                "https://pypi.org/pypi/flask/2.0.1/json\n"),
    _run(2, "", PYPI_SLOW),                                     # not the way pip-audit ends
    _run(1, json.dumps(PIP_OK), PYPI_SLOW),                     # it answered: what it found is the audit's
    _run(None, "", "", timed_out=True),                         # the audit's own time limit
    _run(None, error="OSError: the run was stopped; no helper program is started for it any more"),
])
def test_pip_audit_is_not_asked_again_for_anything_else(tmp_path, monkeypatch, run):
    """The twins: a failure another try would not change (a file pip-audit refuses, also one whose package is
    named like such an error, a certificate, a proxy that refuses, a refusal of the service), an end that is not
    pip-audit's, an answer, the audit's own time limit and a run that was stopped are each the audit's one try,
    with the record as before."""
    _pip_repo(tmp_path, monkeypatch)
    limits, pauses = _tries(monkeypatch, run)
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert len(limits) == 1 and pauses == [] and "tries" not in info and "asked_again" not in info, info


def test_pip_audit_asks_again_only_while_the_audit_has_time_left(tmp_path, monkeypatch):
    """Each try gets what is left of PIP_AUDIT_TIMEOUT, and none starts with less than PIP_AUDIT_AT_LEAST seconds of
    it: a service that is slow every time does not make the audit take longer than its limit."""
    _pip_repo(tmp_path, monkeypatch)
    limits, pauses = _tries(monkeypatch, _run(1, "", PYPI_SLOW),
                            step=depaudit.PIP_AUDIT_TIMEOUT - depaudit.PIP_AUDIT_AT_LEAST)
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert len(limits) == 1 and pauses == [] and info["state"] == "failed" and "tries" not in info, (limits, info)
    limits, pauses = _tries(monkeypatch, _run(1, "", PYPI_SLOW), _run(1, json.dumps(PIP_OK)), step=100.0)
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert info["state"] == "ok" and limits == [depaudit.PIP_AUDIT_TIMEOUT, depaudit.PIP_AUDIT_TIMEOUT - 100.0
                                                  - depaudit.PIP_AUDIT_PAUSES[0]], (limits, info)


# ---------------------------------------------------------------- npm audit


NPM_OK = {"auditReportVersion": 2, "vulnerabilities": {"lodash": {"severity": "high", "range": "<4.17.21", "fixAvailable": True,
          "via": [{"source": 1, "title": "Command Injection", "url": "https://github.com/advisories/GHSA-x", "severity": "high"}]}}}


def _npm_repo(tmp_path, monkeypatch):
    _write(tmp_path, {"package.json": "{}", "package-lock.json": "{}"})
    monkeypatch.setattr(programs, "find", lambda n: "/bin/" + n)
    monkeypatch.setattr(depaudit, "_npm_version", lambda npm: "10.9.9")


def test_npm_audit_exit_code_one_with_vulnerabilities_is_ok(tmp_path, monkeypatch):
    _npm_repo(tmp_path, monkeypatch)
    _fake_tool(monkeypatch, _run(1, json.dumps(NPM_OK)))
    f, info = depaudit.run_npm_audit(tmp_path, no_network=False)
    assert len(f) == 1 and info["state"] == "ok" and info["exit_code"] == 1 and info["version"] == "10.9.9"
    assert info["scope"]["files"] == ["package-lock.json"]


@pytest.mark.parametrize("stdout,words", [
    ("", "empty output"), ("<html>", "broken JSON"), ("[]", "expected an object"),
    ('{"auditReportVersion": 2}', "no vulnerabilities"), ('{"vulnerabilities": []}', "no vulnerabilities"),
    ('{"error": {"code": "ENOLOCK", "summary": "This command requires an existing lockfile."}}', "ENOLOCK"),
])
def test_npm_audit_bad_output_is_a_failure(tmp_path, monkeypatch, stdout, words):
    _npm_repo(tmp_path, monkeypatch)
    _fake_tool(monkeypatch, _run(0, stdout, "something on stderr"))
    f, info = depaudit.run_npm_audit(tmp_path, no_network=False)
    assert f == [] and info["state"] == "failed" and words in info["why"], info


def test_npm_audit_one_of_two_lock_files_failing_is_partial_with_the_good_ones_findings(tmp_path, monkeypatch):
    _write(tmp_path, {"web/package.json": "{}", "web/package-lock.json": "{}", "api/package.json": "{}", "api/package-lock.json": "{}"})
    monkeypatch.setattr(programs, "find", lambda n: "/bin/" + n)
    monkeypatch.setattr(depaudit, "_npm_version", lambda npm: "10.9.9")

    def run_tool(cmd, *, timeout, cwd=None, env=None):
        return _run(1, json.dumps(NPM_OK)) if Path(cwd).name == "api" else _run(None, "", "", timed_out=True)
    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    f, info = depaudit.run_npm_audit(tmp_path, no_network=False)
    assert len(f) == 1 and f[0]["file"] == "api/package-lock.json"
    assert info["state"] == "partial" and info["errors"] == ["web/package-lock.json: timed out"] and info["scope"]["files"] == ["api/package-lock.json"]


def test_npm_audit_timeout_alone_is_a_timeout(tmp_path, monkeypatch):
    _npm_repo(tmp_path, monkeypatch)
    _fake_tool(monkeypatch, _run(None, "", "", timed_out=True))
    f, info = depaudit.run_npm_audit(tmp_path, no_network=False)
    assert f == [] and info["state"] == "timeout"


# ---------------------------------------------------------------- OSV (Gradle/Maven, Composer, RubyGems)


def _java_repo(tmp_path):
    (tmp_path / "build.gradle").write_text("dependencies {\n    implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'\n}\n", encoding="utf-8")
    return tmp_path


def test_osv_wrong_shaped_answer_is_a_failure(tmp_path, monkeypatch):
    _java_repo(tmp_path)
    monkeypatch.setattr(depaudit, "_osv_post", lambda *a, **k: {"results": "nope"})
    f, info = depaudit.run_maven_audit(tmp_path, False)
    assert f == [] and info["state"] == "failed" and "wrong shape" in info["why"]
    monkeypatch.setattr(depaudit, "_osv_post", lambda *a, **k: {"results": []})    # one query, zero answers
    f, info = depaudit.run_maven_audit(tmp_path, False)
    assert f == [] and info["state"] == "failed" and "1 answer" in info["why"]


def test_osv_one_detail_lookup_failing_keeps_the_finding_and_marks_partial(tmp_path, monkeypatch):
    _java_repo(tmp_path)
    monkeypatch.setattr(depaudit, "_osv_post", lambda *a, **k: {"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}]})

    def get(path, timeout=30):
        if path.endswith("GHSA-2"):
            raise OSError("connection reset")
        return {"id": "GHSA-1", "summary": "bad thing", "database_specific": {"severity": "HIGH"}}
    monkeypatch.setattr(depaudit, "_osv_get", get)
    f, info = depaudit.run_maven_audit(tmp_path, False)
    assert [x["rule"] for x in f] == ["GHSA-1", "GHSA-2"] and "known vulnerability" in f[1]["title"]
    assert info["state"] == "partial" and info["errors"] == ["GHSA-2: OSError connection reset"]


def test_osv_timeout_is_a_timeout(tmp_path, monkeypatch):
    _java_repo(tmp_path)

    def slow(*a, **k):
        raise socket.timeout("timed out")
    monkeypatch.setattr(depaudit, "_osv_post", slow)
    f, info = depaudit.run_maven_audit(tmp_path, False)
    assert f == [] and info["state"] == "timeout"


# ---------------------------------------------------------------- the states reach every surface


def _broken_bandit(monkeypatch):
    monkeypatch.setattr(security, "run_bandit", lambda repo, applicable=True: ([], scanresult.record(
        "bandit", "timeout", "after 600 s", role="Python code patterns", version="1.9.4")))


def _scan(tmp_path, monkeypatch):
    _write(tmp_path, PY_APP | {"requirements.txt": "flask==2.0.1\n"})
    _broken_bandit(monkeypatch)
    g = build_graph(tmp_path)
    return g, security.scan(g, offline=True)


def test_scan_lists_incomplete_scanners_and_readiness_does_not_pass_them(tmp_path, monkeypatch):
    g, sec = _scan(tmp_path, monkeypatch)
    inc = scanresult.incomplete(sec["tools"])
    assert {x["tool"] for x in inc} == {"bandit", "pip-audit"}     # timed out; skipped because offline
    assert sec["incomplete"] == inc
    checks = {c["id"]: c for c in readiness.check_security(sec)}
    assert checks["sec-scanners"]["status"] == "fail" and "bandit" in checks["sec-scanners"]["evidence"]
    assert "timed out" in checks["sec-scanners"]["evidence"] and "pip-audit" in checks["sec-scanners"]["evidence"]
    rd = readiness.assess(g, sec, {"offline": True})
    assert [x["tool"] for x in rd["incomplete"]] == ["bandit", "pip-audit"]
    assert rd["score"] < readiness.assess(g, {**sec, "tools": [t for t in sec["tools"] if t["tool"] not in ("bandit", "pip-audit")]
                                             + [scanresult.record("bandit", "ok"), scanresult.record("pip-audit", "skipped", "no Python dependency files")],
                                             "incomplete": []}, {"offline": True})["score"]


def test_readiness_a_deliberate_offline_skip_is_partial_a_broken_scanner_is_a_failure():
    base = {"findings": [], "counts": {}}
    off = base | {"tools": [scanresult.record("bandit", "ok"), scanresult.record("pip-audit", "skipped", "offline", applicable=True)]}
    assert {c["id"]: c for c in readiness.check_security(off)}["sec-scanners"]["status"] == "partial"
    bad = base | {"tools": [scanresult.record("bandit", "failed", "empty output"), scanresult.record("pip-audit", "ok")]}
    assert {c["id"]: c for c in readiness.check_security(bad)}["sec-scanners"]["status"] == "fail"
    good = base | {"tools": [scanresult.record("bandit", "ok"), scanresult.record("pip-audit", "skipped", "no Python dependency files"),
                             scanresult.record("gitleaks", "unavailable", "not installed; built-in patterns ran", applicable=False)]}
    assert {c["id"]: c for c in readiness.check_security(good)}["sec-scanners"]["status"] == "pass"


def test_evidence_limits_badge_and_provenance_say_the_scan_was_incomplete(tmp_path, monkeypatch):
    g, sec = _scan(tmp_path, monkeypatch)
    rd = readiness.assess(g, sec, {"offline": True})
    lim = evidence.limits(g, sec, rd, {"offline": True}, "full", None)
    assert any("bandit" in x and "timed out" in x and "Python code" in x for x in lim), lim
    ev = evidence.build(g, sec, rd, None, {"offline": True}, None, "full")
    assert ev["security"]["incomplete"] and ev["security"]["incomplete"][0]["tool"] == "bandit"
    assert "scan incomplete" in evidence.badge_text(ev)
    row = next(r for r in ev["provenance"]["tools"] if r["tool"] == "bandit")
    assert row["state"] == "timeout"
    html = evidence.render_html(ev)
    assert "did not finish" in html and "timeout" in html


def test_pipeline_logs_incomplete_scanners_and_stores_them(tmp_path, monkeypatch):
    _write(tmp_path, PY_APP)
    _broken_bandit(monkeypatch)
    lines = []
    out = tmp_path / ".lantern"
    res = pipeline.analyze(tmp_path, pipeline.out_dir(tmp_path, out), log=lines.append, offline=True)
    assert any(ln.startswith("incomplete") and "bandit" in ln and "timed out" in ln for ln in lines), lines
    run = json.loads((out / "run.json").read_text(encoding="utf-8"))
    assert [x["tool"] for x in run["incomplete"]] == ["bandit"]
    assert [x["tool"] for x in res["incomplete"]] == ["bandit"]
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    assert rd["incomplete"][0]["state"] == "timeout"
    report = (out / "report.html").read_text(encoding="utf-8")
    assert '"state": "timeout"' in report or '"state":"timeout"' in report


def test_cli_fail_on_refuses_a_green_exit_when_a_scanner_did_not_finish(tmp_path, monkeypatch, capsys):
    _write(tmp_path, {"clean.py": "def ok():\n    return 1\n"})
    _broken_bandit(monkeypatch)
    out = tmp_path / "out"
    assert cli_main(["analyze", str(tmp_path), "--out", str(out), "--offline", "--fail-on", "medium"]) == 1
    err = capsys.readouterr().err
    assert "incomplete" in err and "bandit" in err
    # without --fail-on the run still succeeds and says so on the console
    assert cli_main(["analyze", str(tmp_path), "--out", str(out), "--offline"]) == 0


def test_cli_fail_on_accepts_a_deliberate_offline_run(tmp_path, monkeypatch):
    """--offline is the user's choice: the skipped audits are listed, but they do not fail the run by themselves."""
    pytest.importorskip("bandit")
    _write(tmp_path, {"clean.py": "def ok():\n    return 1\n", "requirements.txt": "flask==2.0.1\n"})
    out = tmp_path / "out"
    assert cli_main(["analyze", str(tmp_path), "--out", str(out), "--offline", "--fail-on", "medium"]) == 0


def test_server_summary_names_incomplete_scanners(tmp_path, monkeypatch):
    from lantern.server import App, Store
    _write(tmp_path / "proj", PY_APP)
    _broken_bandit(monkeypatch)
    store = Store(tmp_path / "home")
    store.root.mkdir()
    app = App(store, "tok", 0)
    p = app.store.add_project(tmp_path / "proj")
    pipeline.analyze(tmp_path / "proj", app.out(p), log=lambda s: None, offline=True)
    s = app.summary(p)
    assert s["incomplete"] == ["bandit"]


def test_old_result_files_without_states_still_work(tmp_path):
    old = {"findings": [], "tools": [{"tool": "bandit", "status": "ok", "version": "1.7"},
                                     {"tool": "pip-audit", "status": "skipped: offline"}], "counts": {}}
    checks = {c["id"]: c for c in readiness.check_security(old)}
    assert checks["sec-scanners"]["status"] == "partial"
    assert evidence.tool_versions(old)[-1]["state"] == "skipped"
