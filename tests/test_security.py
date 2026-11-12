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
    # Bandit rates the pattern medium, which alone made this high. Since the data-flow stage Lantern follows the
    # route's parameter through `Session.login` into the query text, and a query built from request data is critical.
    assert f["flow"]["class"] == "sql" and f["flow"]["source"]["file"] == "shop/app.py", f["flow"]
    assert f["rank"] == "critical" and f["tool_severity"] == "MEDIUM"


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
    assert f[8]["rank"] == "critical"
    assert f[8]["input"] == {"via": "`name` arrives with the request (a parameter of `run`, POST /run)", "flow": True}
    # the command that is fixed text: no input, as before; since the data-flow stage that is said as evidence
    # (nothing from outside is put into the text), and the rank is low where it was high
    assert f[12]["input"] is False
    assert f[12]["rank"] == "low" and f[12]["rank_before_context"] == "high"
    assert "Only fixed text reaches this line" in f[12]["rank_note"]


def test_input_through_a_local_variable_is_still_critical(tmp_path):
    """The classic shape: read the request into a variable, use it on the next line. Lantern follows the value
    from the line that read it, and the steps name each line that gave it a new name. A constant is not request
    data: `input` is False, and since the data-flow stage the rank is low, with the reason written on the finding."""
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
    assert f["run"]["input"] == {"via": "`cmd` in `request.args` is what the request sent", "flow": True}
    assert [s["line"] for s in f["run"]["flow"]["steps"]] == [8, 9]
    assert f["run2"]["rank"] == "critical"   # bandit points at the `shell=True` line inside the multi-line call
    assert f["run2"]["input"]["via"] == "`cmd` in `request.form` is what the request sent"
    assert [(s["line"], s["what"]) for s in f["run2"]["flow"]["steps"]][:2] == [
        (13, "`cmd` in `request.form` is what the request sent"), (14, "`cleaned` is set from it")]
    assert f["run2"]["flow"]["steps"][-1]["line"] == 15
    assert f["nightly"]["input"] is False
    assert f["nightly"]["rank"] == "low" and f["nightly"]["rank_before_context"] == "high"


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
    assert f[8]["input"] == {"via": "`cmd` in `req.body` is what the request sent", "flow": True}
    assert [(s["line"], s["what"]) for s in f[8]["flow"]["steps"]][:2] == [
        (6, "`cmd` in `req.body` is what the request sent"), (7, "`full` is set from it")]
    assert f[8]["flow"]["steps"][-1]["line"] == 8
    # 'backup ' + 'all': fixed text, so no input as before, and now low with the reason on the finding
    assert f[14]["input"] is False
    assert f[14]["rank"] == "low" and f[14]["rank_before_context"] == "high" and "fixed text" in f[14]["rank_note"]


def test_reassigning_a_safe_value_clears_the_input(tmp_path):
    """`cmd = request.args.get(...)` then `cmd = "ls -la"` at the same level: the request value is gone, so the
    line is not critical (it was high; since the data-flow stage it is low, because only fixed text reaches it).
    A default inside an `if` block (`if not cmd: cmd = "ls"`) does not clear it, nor does `cmd += "x"`, nor a
    reassignment that still uses the tainted name."""
    from lantern.engine import build_graph
    from lantern.security import scan
    (tmp_path / "app.py").write_text(
        "import subprocess\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
        "@app.route('/reset', methods=['POST'])\ndef reset():\n    cmd = request.args.get('cmd')\n"
        "    cmd = 'ls -la'\n    subprocess.run(cmd, shell=True)\n\n"
        "@app.route('/default', methods=['POST'])\ndef default():\n    cmd = request.args.get('cmd')\n"
        "    if not cmd:\n        cmd = 'ls'\n    subprocess.run(cmd, shell=True)\n\n"
        "@app.route('/append', methods=['POST'])\ndef append():\n    cmd = request.args.get('cmd')\n"
        "    cmd += ' --all'\n    subprocess.run(cmd, shell=True)\n\n"
        "@app.route('/wrap', methods=['POST'])\ndef wrap():\n    cmd = request.args.get('cmd')\n"
        "    cmd = 'nice ' + cmd\n    subprocess.run(cmd, shell=True)\n\n"
        "@app.route('/param', methods=['POST'])\ndef param(cmd):\n    cmd = 'ls'\n    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8")
    f = {x["node"].rsplit(".", 1)[-1]: x for x in scan(build_graph(tmp_path))["findings"] if x["rule"] == "B602"}
    for name in ("reset", "param"):
        assert f[name]["input"] is False
        assert f[name]["rank"] == "low" and f[name]["rank_before_context"] == "high", name
        assert "Only fixed text reaches this line" in f[name]["rank_note"]
    assert f["default"]["rank"] == "critical"
    assert f["default"]["input"] == {"via": "`cmd` in `request.args` is what the request sent", "flow": True}
    assert f["append"]["rank"] == "critical" and f["wrap"]["rank"] == "critical"
    assert [s["line"] for s in f["wrap"]["flow"]["steps"]] == [27, 28, 29]
    assert "rank_note" not in f["default"] and "rank_note" not in f["append"] and "rank_note" not in f["wrap"]
