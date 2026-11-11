"""Outside services failing never stop an analysis (test checklist 3.5, "what this checklist does not cover").

Lantern talks to four kinds of outside service: the OSV vulnerability database (Gradle/Maven, Composer, RubyGems audits),
pip-audit and npm (Python and JavaScript audits), the model gateway, and the cloud service's own audit step. Each is
made to fail here the way it fails in life (connection refused, garbage output, a crash), and the result must be a run
that finishes with a plain status line saying what was not checked, never a traceback or a missing report.
"""
import json
import socket
import urllib.error

import pytest

from tests.test_server import srv  # noqa: F401 - fixture

from lantern import depaudit, programs, scanresult
from lantern.engine import build_graph
from lantern.scanresult import ToolRun
from lantern.security import scan


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _java_repo(tmp_path):
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n    implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'\n}\n", encoding="utf-8")
    (tmp_path / "composer.lock").write_text(json.dumps({"packages": [{"name": "laravel/framework", "version": "v8.0.0"}]}),
                                            encoding="utf-8")
    (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n    rails (6.0.0)\n", encoding="utf-8")
    (tmp_path / "Gemfile").write_text("gem 'rails'\n", encoding="utf-8")
    return tmp_path


def _down(*_a, **_k):
    raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))


def test_osv_down_is_a_status_line_not_a_crash(tmp_path, monkeypatch):
    repo = _java_repo(tmp_path)
    monkeypatch.setattr(depaudit, "_osv_post", _down)
    for fn in (depaudit.run_maven_audit, depaudit.run_composer_audit, depaudit.run_gem_audit):
        findings, info = fn(repo, False)
        assert findings == [] and info["status"].startswith("error: URLError"), info
        assert "network" in info["status"]


def test_osv_garbage_answer_is_a_status_line(tmp_path, monkeypatch):
    repo = _java_repo(tmp_path)
    monkeypatch.setattr(depaudit, "_osv_post", lambda *a, **k: json.loads("not json"))
    findings, info = depaudit.run_maven_audit(repo, False)
    assert findings == [] and info["status"].startswith("error: JSONDecodeError"), info


def test_pip_audit_and_npm_failing_are_status_lines(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {"lodash": "4.17.0"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"name": "x", "lockfileVersion": 3, "packages": {}}', encoding="utf-8")
    monkeypatch.setattr(programs, "find", lambda name: f"/usr/bin/{name}")
    # the tool could not even start (scanresult.run_tool reports it instead of raising)
    monkeypatch.setattr(scanresult, "run_tool", lambda cmd, **k: ToolRun(None, error="OSError: the tool crashed"))
    findings, info = depaudit.run_pip_audit(tmp_path, False)
    assert findings == [] and info["state"] == "failed" and info["status"].startswith("error: OSError"), info
    findings, info = depaudit.run_npm_audit(tmp_path, False)
    assert findings == [] and info["state"] == "failed" and info["status"].startswith("error"), info
    # it ran, but what came back was not JSON
    monkeypatch.setattr(scanresult, "run_tool", lambda cmd, **k: ToolRun(0, stdout="<html>registry is down</html>"))
    findings, info = depaudit.run_pip_audit(tmp_path, False)
    assert findings == [] and info["state"] == "failed" and "broken JSON" in info["status"], info
    # it hung until the time limit killed it
    monkeypatch.setattr(scanresult, "run_tool", lambda cmd, **k: ToolRun(None, timed_out=True))
    findings, info = depaudit.run_pip_audit(tmp_path, False)
    assert info["state"] == "timeout" and info["status"].startswith("error: timed out"), info


def test_one_audit_tool_crashing_does_not_drop_the_others(tmp_path, monkeypatch):
    """`python -m lantern.depaudit` (the cloud audit step) writes every tool's result even when one raises."""
    repo = _java_repo(tmp_path)
    monkeypatch.setattr(depaudit, "_osv_post", lambda path, body, **k: {"results": [{} for _ in body["queries"]]})

    def boom(repo, no_network=None):
        raise RuntimeError("surprise")
    monkeypatch.setattr(depaudit, "run_pip_audit", boom)
    out = depaudit.run_all(repo)
    assert set(out) == {"pip-audit", "npm-audit", "maven-audit", "composer-audit", "gem-audit"}
    assert out["pip-audit"]["info"]["status"] == "error: RuntimeError (network needed?)"
    assert out["maven-audit"]["info"]["status"] == "ok"


def test_the_whole_scan_finishes_with_the_network_down(tmp_path, monkeypatch):
    """security.scan with every outside service refusing: findings from the code still arrive, tools say what failed."""
    repo = _java_repo(tmp_path)
    (repo / "src").mkdir()
    (repo / "src" / "App.java").write_text(
        'package a;\npublic class App {\n  public void run(String q) throws Exception {\n'
        '    Runtime.getRuntime().exec("ls " + q);\n  }\n}\n', encoding="utf-8")
    monkeypatch.setattr(depaudit, "_osv_post", _down)
    monkeypatch.setattr(programs, "find", lambda name: None)
    g = build_graph(repo)
    sec = scan(g, offline=False)
    assert any(f["rule"] == "LV-EXEC-CONCAT" for f in sec["findings"]), [f["rule"] for f in sec["findings"]]
    statuses = {t["tool"]: t.get("status", "") for t in sec["tools"]}
    assert statuses["maven-audit"].startswith("error: URLError")
    assert statuses["pip-audit"].startswith("skipped")


def test_a_model_gateway_that_is_down_says_so(monkeypatch):
    from lantern import providers
    monkeypatch.setattr(providers.time, "sleep", lambda s: None)   # the retry back-off, not waited for here
    port = _closed_port()
    p = providers.LanternHostedProvider("lt_test", f"http://127.0.0.1:{port}/v1")
    with pytest.raises(providers.ProviderError, match="cannot reach"):
        p._send({"model": "x", "messages": []})
    with pytest.raises(providers.ProviderError, match="cannot reach gateway"):
        providers.allowance_status("lt_test", f"http://127.0.0.1:{port}/v1")
    assert providers.sign_in_providers(f"http://127.0.0.1:{port}/v1") == []


def test_the_app_reports_a_gateway_outage_as_a_sentence(srv, tmp_path, monkeypatch):  # noqa: F811 - fixture
    """/api/allowance answers {available: false, error: "cannot reach gateway…"}, so Settings can show it."""
    from tests.test_server import call
    port = _closed_port()
    monkeypatch.setenv("LANTERN_TOKEN", "lt_test")
    monkeypatch.setenv("LANTERN_GATEWAY_URL", f"http://127.0.0.1:{port}/v1")
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    base, _store = srv
    code, d = call(base, "/api/allowance")
    assert code == 200 and d["available"] is False and "cannot reach gateway" in d["error"]
