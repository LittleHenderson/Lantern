import json
from pathlib import Path

import pytest

from lantern.engine import build_graph
from lantern.security import rank, reachability, scan

FIX = Path(__file__).parent / "fixtures" / "shop"


@pytest.fixture(scope="module")
def result():
    g = build_graph(FIX)
    return g, scan(g)


def by_rule(findings, rule):
    return [f for f in findings if f["rule"] == rule]


def test_sql_injection_reachable_from_route(result):
    g, s = result
    (f,) = by_rule(s["findings"], "B608")
    assert f["node"] == "py:shop.repo.UserRepo.get"
    assert f["reachable"]["path"] == [
        "py:shop.app.read_user", "py:shop.auth.Session.login", "py:shop.repo.UserRepo.get"]
    assert f["rank"] == "high"


def test_shell_injection_is_critical(result):
    _, s = result
    (f,) = by_rule(s["findings"], "B602")
    assert f["rank"] == "critical"


def test_test_only_code_is_not_reachable(result):
    g, _ = result
    r = reachability(g)
    assert "py:tests.test_auth.test_check_password" not in r
    assert "py:tests.test_auth.test_check_password" in reachability(g, include_tests=True)


def test_rank_rules():
    base = {"category": "code", "reachable": None}
    assert rank({**base, "tool_severity": "HIGH"}) == "medium"
    assert rank({**base, "tool_severity": "LOW"}) == "low"
    assert rank({**base, "tool_severity": "HIGH", "reachable": {"kind": "route"}}) == "critical"
    assert rank({**base, "tool_severity": "HIGH", "reachable": {"kind": "test"}}) == "high"
    assert rank({"category": "secret", "tool_severity": "HIGH", "reachable": None}) == "critical"


def test_builtin_secret_scan(tmp_path):
    (tmp_path / "config.py").write_text('KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n', encoding="utf-8")
    g = build_graph(tmp_path)
    s = scan(g)
    secrets = [f for f in s["findings"] if f["category"] == "secret"]
    assert secrets and secrets[0]["rank"] == "critical"
    assert secrets[0]["snippet"] == "[redacted]"


def test_secret_scan_covers_frontend_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "api.ts").write_text('const key = "sk_live_' + "a" * 24 + '"\n', encoding="utf-8")
    (tmp_path / "src" / "Pay.tsx").write_text('export const t = "ghp_' + "b" * 36 + '"\n', encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text('k = "sk_live_' + "c" * 24 + '"\n', encoding="utf-8")
    g = build_graph(tmp_path)
    files = sorted(f["file"] for f in scan(g)["findings"] if f["category"] == "secret")
    assert files == ["src/Pay.tsx", "src/api.ts"]


def test_secret_scans_read_dotenv_files(tmp_path):
    # `.env` is in SKIP_DIRS (as a virtualenv folder name); a *file* named .env must still be scanned
    (tmp_path / ".env").write_text("STRIPE_KEY=sk_live_" + "d" * 24 + "\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJx\n", encoding="utf-8")
    g = build_graph(tmp_path)
    rules = {f["rule"] for f in scan(g)["findings"] if f["file"] == ".env"}
    assert "stripe-live-key" in rules        # security.run_secrets
    assert "LW-PUBLIC-SECRET" in rules       # websec.exposed_secrets


def test_symlinks_out_of_the_repo_are_not_read(tmp_path):
    import os
    outside = tmp_path / "home"
    outside.mkdir()
    (outside / "credentials").write_text("aws_key = 'AKIA" + "ABCDEFGHIJKLMNOP'\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    try:
        os.symlink(outside / "credentials", repo / "creds.py")
        os.symlink(outside / "credentials", repo / ".env")
    except OSError:
        import pytest
        pytest.skip("symlinks not supported")
    from lantern.engine import build_graph
    from lantern.report import collect_sources
    from lantern.security import scan
    g = build_graph(repo)
    assert not any(n.file == "creds.py" for n in g.nodes.values())
    assert not [f for f in scan(g)["findings"] if f["category"] == "secret"]
    assert "AKIA" not in "".join(collect_sources(g).values())


def test_accepted_risks_need_a_real_reason(tmp_path):
    from lantern.security import load_accepted, reason_ok
    assert not reason_ok("x") and not reason_ok("aaaaaaaaaaaa") and not reason_ok("          ") and not reason_ok(None)
    assert reason_ok("Only admins reach this; input is a fixed list")
    (tmp_path / "lantern-accepted.json").write_text(json.dumps({"accepted": [
        {"id": "a", "reason": "x"}, {"id": "b", "reason": "Test fixture only, never deployed"}]}))
    assert set(load_accepted(tmp_path)) == {"b"}


def test_critical_needs_input_on_the_flagged_line(tmp_path):
    from lantern.engine import build_graph
    from lantern.security import scan
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom fastapi import FastAPI\n\napp = FastAPI()\nCMD = 'backup --all'\n"
        "@app.post('/run')\ndef run(name: str):\n    subprocess.run('backup ' + name, shell=True)\n\n"
        "@app.post('/nightly')\ndef nightly():\n    subprocess.run(CMD, shell=True)\n", encoding="utf-8")
    g = build_graph(tmp_path)
    f = {x["line"]: x for x in scan(g)["findings"] if x["rule"] == "B602"}
    assert f[8]["rank"] == "critical" and f[8]["input"] == {"via": "parameter `name`"}
    assert f[12]["rank"] == "high" and f[12]["input"] is False


def test_input_through_a_local_variable_is_still_critical(tmp_path):
    """The classic shape: read the request into a variable, use it on the next line. Lantern follows assignments
    inside the function, in order, and names the line that set the variable. A constant stays high."""
    from lantern.engine import build_graph
    from lantern.security import scan
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
        "@app.route('/run', methods=['POST'])\ndef run():\n    cmd = request.args.get('cmd')\n"
        "    subprocess.run(cmd, shell=True)\n\n"
        "@app.route('/run2', methods=['POST'])\ndef run2():\n    raw = request.form['cmd']\n    cleaned = raw.strip()\n"
        "    subprocess.run(\n        'backup ' + cleaned,\n        shell=True,\n    )\n\n"
        "@app.route('/nightly', methods=['POST'])\ndef nightly():\n    cmd = 'backup --all'\n"
        "    subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    g = build_graph(tmp_path)
    f = {x["node"].rsplit(".", 1)[-1]: x for x in scan(g)["findings"] if x["rule"] == "B602"}
    assert f["run"]["rank"] == "critical"
    assert f["run"]["input"] == {"via": "`cmd`, which line 8 sets from request data `request.args`"}
    assert f["run2"]["rank"] == "critical"   # bandit points at the `shell=True` line inside the multi-line call
    assert f["run2"]["input"]["via"] == ("`cleaned`, which line 14 sets from `raw`, which line 13 sets from request "
                                         "data `request.form`")
    assert f["nightly"]["rank"] == "high" and f["nightly"]["input"] is False


def test_input_follows_assignments_in_js_handlers(tmp_path):
    from lantern.engine import build_graph
    from lantern.security import scan
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {"express": "^4"}}', encoding="utf-8")
    (tmp_path / "server.js").write_text(
        "const express = require('express');\nconst { exec } = require('child_process');\nconst app = express();\n\n"
        "app.post('/run', (req, res) => {\n  const { cmd } = req.body;\n  const full = 'backup ' + cmd;\n"
        "  exec('nice ' + full);\n  res.send('ok');\n});\n\n"
        "app.post('/nightly', (req, res) => {\n  const job = 'all';\n  exec('backup ' + job);\n  res.send('ok');\n});\n",
        encoding="utf-8")
    f = {x["line"]: x for x in scan(build_graph(tmp_path))["findings"] if x["rule"] == "LJ-EXEC"}
    assert f[8]["rank"] == "critical"
    assert f[8]["input"] == {"via": "`full`, which line 7 sets from `cmd`, which line 6 sets from request data `req.body`"}
    assert f[14]["rank"] == "high" and f[14]["input"] is False
