"""Lantern as a connector (MCP over stdio): read, analyze, re-check, verify; never accept or close."""

import io
import json
import shutil
from pathlib import Path

import pytest

from lantern import mcp_server
from lantern.mcp_server import Projects, Server

FIX = Path(__file__).parent / "fixtures" / "shop"


@pytest.fixture
def shop(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    repo = tmp_path / "shop"
    shutil.copytree(FIX, repo)
    from lantern import pipeline
    pipeline.analyze(repo, pipeline.out_dir(repo), log=lambda m: None, offline=True)
    return repo


def rpc(server, method, params=None, mid=1):
    return server.handle({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})


def call(server, name, **args):
    r = rpc(server, "tools/call", {"name": name, "arguments": args})
    assert "result" in r, r
    res = r["result"]
    return res["isError"], res["content"][0]["text"], res.get("structuredContent")


def test_handshake_lists_tools_and_records_the_client(shop):
    s = Server(Projects([str(shop)]))
    r = rpc(s, "initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "Claude Code", "version": "2.1"}})
    assert r["result"]["serverInfo"]["name"] == "lantern" and "cannot accept" in r["result"]["instructions"]
    assert rpc(s, "notifications/initialized") is None
    names = [t["name"] for t in rpc(s, "tools/list")["result"]["tools"]]
    assert names == ["lantern_projects", "lantern_findings", "lantern_paths", "lantern_explain", "lantern_readiness",
                     "lantern_analyze", "lantern_recheck", "lantern_verify"]
    assert not any(w in n for n in names for w in ("accept", "close", "dismiss"))
    err, text, data = call(s, "lantern_projects")
    assert not err and data["projects"][0]["name"] == "shop" and data["projects"][0]["open_findings"]["critical"] == 2
    conns = mcp_server.connections(s.P.store)
    assert conns[0]["name"] == "Claude Code" and conns[0]["version"] == "2.1" and conns[0]["calls"] == 1
    assert conns[0]["last_tool"] == "lantern_projects"


def test_findings_paths_readiness_explain(shop):
    s = Server(Projects([str(shop)]))
    err, text, data = call(s, "lantern_findings", project="shop", rank="critical")
    assert not err and data["total"] == 2 and data["cannot_close"] is True
    b602 = next(f for f in data["findings"] if f["rule"] == "B602")
    assert b602["file"] == "shop/app.py" and b602["from_the_app"].startswith("/admin page")
    assert "-HTTP POST /backup->" in b602["from_the_app"] and b602["uses_outside_input"] == "parameter `name`"
    assert "lantern accept" in text
    # one finding by id, as the "Send to…" reference names it
    err, text, one = call(s, "lantern_findings", project="shop", id=b602["id"][:6])
    assert not err and [f["id"] for f in one["findings"]] == [b602["id"]]
    err, text, paths = call(s, "lantern_paths", project="shop", target="backup")
    assert not err
    fn = paths["functions"][0]
    assert fn["name"] == "shop.app.backup" and fn["entry"]["detail"] == "POST /backup"
    assert any(c["from"].endswith("runBackup") and c["confidence"] == "resolved" for c in fn["callers"])
    assert b602["id"] + " B602" in fn["findings_here"]
    err, text, _ = call(s, "lantern_paths", project="shop", target="shop/app.py:16")
    assert not err and "shop.app.backup" in text
    err, text, rd = call(s, "lantern_readiness", project="shop")
    assert not err and rd["grade"] in "ABCDF" and rd["next_steps"]
    err, text, ex = call(s, "lantern_explain", project="shop", target="backup")
    assert not err and ex["explanation"] is None and "no Lantern explanation yet" in text and "subprocess" in ex["source"]


def test_unknown_project_and_closed_doors(shop):
    s = Server(Projects([str(shop)]))
    err, text, _ = call(s, "lantern_findings", project="nothing-here")
    assert err and "No project called" in text
    r = rpc(s, "tools/call", {"name": "lantern_accept", "arguments": {"finding": "x", "reason": "because"}})
    assert r["error"]["code"] == -32602 and "cannot accept or close" in r["error"]["message"]
    r = rpc(s, "tools/call", {"name": "lantern_close_finding", "arguments": {}})
    assert "cannot accept or close" in r["error"]["message"]
    assert rpc(s, "nope/method")["error"]["code"] == -32601


def test_fix_then_recheck(shop):
    s = Server(Projects([str(shop)]))
    _, _, data = call(s, "lantern_findings", project="shop", rank="critical")
    md5 = next(f for f in data["findings"] if f["rule"] == "B324")
    # the vibe coder (or their assistant) fixes the weak hash
    auth = shop / "shop" / "auth.py"
    src = auth.read_text(encoding="utf-8")
    assert "md5" in src
    auth.write_text(src.replace("hashlib.md5(", "hashlib.sha256("), encoding="utf-8")
    err, text, rc = call(s, "lantern_recheck", project="shop", finding=md5["id"])
    assert not err and rc["status"] == "fixed" and "gone" in text
    assert any(f["id"] == md5["id"] for f in rc["fixed"])
    # asking again: the id no longer exists, and the answer says why
    err, text, rc = call(s, "lantern_recheck", project="shop", finding=md5["id"])
    assert err and "not an open finding" in text
    # a finding that is still there stays open
    b602 = next(f for f in data["findings"] if f["rule"] == "B602")
    err, text, rc = call(s, "lantern_recheck", project="shop", finding=b602["id"])
    assert not err and rc["status"] == "open"


def test_verify_matches_and_refuses_traces(shop):
    s = Server(Projects([str(shop)]))
    err, text, v = call(s, "lantern_verify", project="shop")
    assert not err and v["match"] is True and text.startswith("MATCH")
    err, text, v = call(s, "lantern_verify", project="shop", digest="sha256:" + "0" * 64)
    assert not err and v["match"] is False and text.startswith("DIFFERENT")
    # a report made with a trace is never replayed from here: a trace runs the project's code
    ev = json.loads((shop / ".lantern" / "evidence.json").read_text(encoding="utf-8"))
    ev["payload"]["run"] = {"scan": True, "trace": ["python", "-m", "pytest"]}
    (shop / "traced.json").write_text(json.dumps(ev), encoding="utf-8")
    err, text, v = call(s, "lantern_verify", project="shop", report="traced.json")
    assert not err and v.get("refused") and "lantern verify" in text and "python -m pytest" in text


def test_stdio_framing(shop):
    s = Server(Projects([str(shop)]))
    lines = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}), "not json",
             json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
             json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})]
    out = io.BytesIO()
    s.serve_stdio(io.BytesIO("\n".join(lines).encode() + b"\n"), out)
    got = [json.loads(x) for x in out.getvalue().decode().splitlines()]
    assert [g.get("id") for g in got] == [1, None, 2] and got[1]["error"]["code"] == -32700
    assert len(got[2]["result"]["tools"]) == 8


def test_setup_text_and_cli():
    from lantern.cli import main
    text = mcp_server.setup_text()
    assert "claude mcp add lantern" in text and '"mcpServers"' in text and "cannot accept or close" in text
    assert main(["mcp", "--setup"]) == 0
