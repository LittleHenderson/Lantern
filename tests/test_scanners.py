"""Scanner adapters must never report a failure as success (directive stage 2).

Every adapter (Bandit, Gitleaks and the built-in secret patterns, pip-audit, npm audit, the OSV audits) returns a
common record (`lantern.scanresult.record`): `state` is one of ok / partial / failed / timeout / unavailable /
skipped, with the tool's version, exit code, scope, exclusions and errors. Findings a scanner did produce are kept
even when the rest of its run failed. The tests feed each adapter empty output, broken and wrong-shaped JSON, a
missing tool, a timeout, an unreadable file and a partial failure, and then prove the states reach the command
line, the app's project summary, the stored results and the readiness score.
"""
from __future__ import annotations

import importlib.util
import json
import socket
from pathlib import Path

import pytest

from lantern import depaudit, evidence, pipeline, readiness, scanresult, security
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


def _gitleaks_present(monkeypatch):
    monkeypatch.setattr(security.shutil, "which", lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else None)


def test_gitleaks_crash_falls_back_to_patterns_but_is_recorded_as_a_failure(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": 'KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n'})
    _gitleaks_present(monkeypatch)
    _fake_tool(monkeypatch, _run(2, "", "panic: something broke\n"))
    f, infos = security.run_secrets(tmp_path)
    by = {i["tool"]: i for i in infos}
    assert by["gitleaks"]["state"] == "failed" and "something broke" in by["gitleaks"]["why"]
    assert by["lantern-secrets"]["state"] == "ok" and by["lantern-secrets"]["fallback_for"] == "gitleaks"
    assert len(f) == 1 and f[0]["tool"] == "lantern-secrets"


def test_gitleaks_report_file_is_read_and_exit_code_one_means_findings(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})
    _gitleaks_present(monkeypatch)

    def run_tool(cmd, *, timeout, cwd=None, env=None):
        report = Path(cmd[cmd.index("-r") + 1])
        assert report.suffix == ".json" and not str(report).startswith("/dev")
        report.write_text(json.dumps([{"RuleID": "aws-access-token", "Description": "AWS key", "File": str(tmp_path / "config.py"),
                                       "StartLine": 1}]), encoding="utf-8")
        return _run(1, "", "")
    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    f, infos = security.run_secrets(tmp_path)
    assert len(f) == 1 and f[0]["tool"] == "gitleaks" and f[0]["snippet"] == "[redacted]"
    assert infos == [infos[0]] and infos[0]["state"] == "ok" and infos[0]["exit_code"] == 1


def test_gitleaks_clean_run_leaves_an_empty_report(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})
    _gitleaks_present(monkeypatch)
    _fake_tool(monkeypatch, _run(0, "", ""))     # exit 0, report file never written
    f, infos = security.run_secrets(tmp_path)
    assert f == [] and infos[0]["tool"] == "gitleaks" and infos[0]["state"] == "ok" and infos[0]["findings"] == 0


def test_gitleaks_timeout_and_broken_report_are_failures(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})
    _gitleaks_present(monkeypatch)
    _fake_tool(monkeypatch, _run(None, "", "", timed_out=True))
    _, infos = security.run_secrets(tmp_path)
    assert infos[0]["tool"] == "gitleaks" and infos[0]["state"] == "timeout" and infos[1]["tool"] == "lantern-secrets"

    def run_tool(cmd, *, timeout, cwd=None, env=None):
        Path(cmd[cmd.index("-r") + 1]).write_text("<html>", encoding="utf-8")
        return _run(1, "", "")
    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    _, infos = security.run_secrets(tmp_path)
    assert infos[0]["state"] == "failed" and "broken JSON" in infos[0]["why"]


def test_gitleaks_absent_is_written_down_beside_the_built_in_scan(tmp_path, monkeypatch):
    _write(tmp_path, {"config.py": "x = 1\n"})
    monkeypatch.setattr(security.shutil, "which", lambda name: None)
    f, infos = security.run_secrets(tmp_path)
    by = {i["tool"]: i for i in infos}
    assert by["gitleaks"]["state"] == "unavailable" and by["gitleaks"]["applicable"] is False
    assert by["lantern-secrets"]["state"] == "ok" and by["lantern-secrets"]["scope"]["files"] == 1


def test_built_in_secret_scan_counts_files_it_could_not_read(tmp_path, monkeypatch):
    _write(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n", ".env": "TOKEN=abc\n"})
    monkeypatch.setattr(security.shutil, "which", lambda name: None)
    real = security._read_text

    def read(p: Path, repo: Path) -> str:
        if p.name == "b.py":
            raise OSError(13, "Permission denied")
        return real(p, repo)
    monkeypatch.setattr(security, "_read_text", read)
    f, infos = security.run_secrets(tmp_path)
    s = next(i for i in infos if i["tool"] == "lantern-secrets")
    assert s["state"] == "partial" and s["errors"] == ["b.py: Permission denied"] and s["scope"]["files"] == 2


# ---------------------------------------------------------------- pip-audit


PIP_OK = {"dependencies": [{"name": "flask", "version": "2.0.1", "vulns": [{"id": "PYSEC-1", "fix_versions": ["2.2.5"], "description": "bad"}]}]}


def _pip_repo(tmp_path, monkeypatch):
    _write(tmp_path, {"requirements.txt": "flask==2.0.1\n"})
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
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
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: None)
    info = depaudit.run_pip_audit(tmp_path, no_network=False)[1]
    assert info["state"] == "unavailable" and info["applicable"] is True
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
    info = depaudit.run_pip_audit(tmp_path, no_network=True)[1]
    assert info["state"] == "skipped" and info["why"] == "offline" and info["applicable"] is True


def test_pip_audit_skipped_packages_make_the_run_partial_and_keep_findings(tmp_path, monkeypatch):
    _write(tmp_path, {"requirements.txt": "flask==2.0.1\nleftpad==1.0\n"})
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
    data = {"dependencies": PIP_OK["dependencies"] + [{"name": "leftpad", "skip_reason": "Dependency not found on PyPI and could not be audited: leftpad (1.0)"}]}
    _fake_tool(monkeypatch, _run(1, json.dumps(data)))
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert len(f) == 1 and info["state"] == "partial" and info["errors"] == ["leftpad: Dependency not found on PyPI and could not be audited: leftpad (1.0)"]


# ---------------------------------------------------------------- npm audit


NPM_OK = {"auditReportVersion": 2, "vulnerabilities": {"lodash": {"severity": "high", "range": "<4.17.21", "fixAvailable": True,
          "via": [{"source": 1, "title": "Command Injection", "url": "https://github.com/advisories/GHSA-x", "severity": "high"}]}}}


def _npm_repo(tmp_path, monkeypatch):
    _write(tmp_path, {"package.json": "{}", "package-lock.json": "{}"})
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
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
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
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
