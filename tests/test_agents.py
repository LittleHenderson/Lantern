"""Fix this for me: a coding agent the person picked fixes one finding in a copy, and Lantern checks the copy.

The agent here is a small Python script standing in for Claude Code, Codex or Aider, so the whole path runs for real:
copy, agent, analysis of the copy, verdict, apply or throw away."""

import json
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

from lantern import agents, pipeline

FIX = Path(__file__).parent / "fixtures" / "shop"
AGENT = textwrap.dedent("""
    import pathlib, sys
    mode = pathlib.Path(sys.argv[1]).read_text().strip()
    auth = pathlib.Path("shop/auth.py")
    src = auth.read_text()
    if mode == "fix":
        auth.write_text(src.replace("hashlib.md5(", "hashlib.sha256("))
    elif mode == "worse":   # fixes the hash but adds a route that hands a visitor's text to a shell
        auth.write_text(src.replace("hashlib.md5(", "hashlib.sha256("))
        app = pathlib.Path("shop/app.py")
        app.write_text(app.read_text() + '\\n\\n@app.get("/ping")\\ndef ping(host: str):\\n'
                       '    subprocess.call("ping -c1 " + host, shell=True)\\n    return {"ok": True}\\n')
    elif mode == "computed":   # the finding stops showing; the weak hash is still what runs
        auth.write_text(src.replace("hashlib.md5(", 'getattr(hashlib, "m" + "d5")('))
    elif mode == "comment":    # a comment answers for the finding
        auth.write_text(src.replace(" == user", " == user  # nosec B324: only compared, never stored"))
    elif mode == "no_tests":   # a true fix that also takes the project's test away
        auth.write_text(src.replace("hashlib.md5(", "hashlib.sha256("))
        pathlib.Path("tests/test_auth.py").unlink()
    elif mode == "pack":       # the rule that found it is changed; the code is as it was
        pack = pathlib.Path("lantern-packs/house.json")
        pack.write_text(pack.read_text().replace("md5", "md6"))
    elif mode == "nothing":
        pass
    print("prompt was:", sys.argv[2][:60])
""")


@pytest.fixture
def shop(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    repo = tmp_path / "shop"
    shutil.copytree(FIX, repo)
    pipeline.analyze(repo, pipeline.out_dir(repo), log=lambda m: None, offline=True)
    script, mode = tmp_path / "fake_agent.py", tmp_path / "mode.txt"
    script.write_text(AGENT, encoding="utf-8")
    monkeypatch.setitem(agents.AGENTS, "claude",
                        ("Claude Code", "fake-claude", lambda prompt: [sys.executable, str(script), str(mode), prompt]))
    find = agents.find
    monkeypatch.setattr(agents, "find", lambda prog: sys.executable if prog == "fake-claude" else find(prog))
    return repo, mode, tmp_path / "work"


def md5_id(repo):
    sec = json.loads((repo / ".lantern" / "security.json").read_text(encoding="utf-8"))
    return next(f["id"] for f in sec["findings"] if f["rule"] == "B324")


def test_a_checked_fix_reaches_the_project_only_on_apply(shop):
    repo, mode, work = shop
    mode.write_text("fix")
    before = (repo / "shop" / "auth.py").read_text(encoding="utf-8")
    res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
    assert res["status"] == "fixed" and res["verdict"].startswith("Fixed")
    assert [f["path"] for f in res["files"]] == ["shop/auth.py"] and "+" in res["files"][0]["diff"]
    assert "sha256" in res["files"][0]["diff"]
    assert (repo / "shop" / "auth.py").read_text(encoding="utf-8") == before      # nothing touched yet
    out = agents.apply_fix(repo, res["fix"], work_root=work)
    assert out["applied"] == ["shop/auth.py"]
    assert "hashlib.sha256(" in (repo / "shop" / "auth.py").read_text(encoding="utf-8")
    assert not (work / agents.FIXES_DIR / res["fix"]).exists()                    # the copy is gone after apply
    with pytest.raises(ValueError, match="gone"):
        agents.apply_fix(repo, res["fix"], work_root=work)


def test_lantern_says_so_when_the_agent_makes_things_worse_or_does_nothing(shop):
    repo, mode, work = shop
    mode.write_text("worse")
    res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
    assert res["status"] == "fixed_with_new" and "new serious" in res["verdict"]
    assert any(n["rank"] in ("critical", "high") for n in res["new"])
    agents.discard_fix(res["fix"], work_root=work)
    assert not (work / agents.FIXES_DIR / res["fix"]).exists()
    mode.write_text("nothing")
    res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
    assert res["status"] == "no_change" and res["fix"] is None


def test_apply_refuses_when_the_person_changed_the_file_meanwhile(shop):
    repo, mode, work = shop
    mode.write_text("fix")
    res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
    auth = repo / "shop" / "auth.py"
    auth.write_text(auth.read_text(encoding="utf-8") + "\n# my own edit\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed since"):
        agents.apply_fix(repo, res["fix"], work_root=work)
    assert auth.read_text(encoding="utf-8").endswith("# my own edit\n")


def test_only_the_listed_agents_run_and_fix_ids_cannot_leave_the_folder(shop):
    repo, mode, work = shop
    with pytest.raises(ValueError, match="Settings"):
        agents.run_fix(repo, repo / ".lantern", md5_id(repo), "rm -rf /", "full", lambda m: None, work_root=work)
    with pytest.raises(ValueError, match="not open"):
        agents.run_fix(repo, repo / ".lantern", "nope", "claude", "full", lambda m: None, work_root=work)
    for bad in ("../x", "..", ".hidden", "a/b", "", None):
        with pytest.raises(ValueError):
            agents.apply_fix(repo, bad, work_root=work)
    assert {a["id"] for a in agents.available()} == {"claude", "codex", "aider"}


def test_a_fix_belongs_to_its_project(shop, tmp_path):
    repo, mode, work = shop
    mode.write_text("fix")
    res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ValueError, match="another project"):
        agents.apply_fix(other, res["fix"], work_root=work)


def test_the_agent_gets_no_lantern_secrets(shop, monkeypatch):
    repo, mode, work = shop
    mode.write_text("nothing")
    monkeypatch.setenv("LANTERN_GATEWAY_TOKEN", "secret")
    seen = {}

    def runner(argv, **kw):
        seen.update(kw)
        import subprocess
        return subprocess.run(argv, **kw)
    agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, runner=runner, work_root=work)
    assert not any(k.startswith("LANTERN") for k in seen["env"]) and seen["stdin"] is not None
    assert seen["cwd"] != str(repo) and Path(seen["cwd"]).name == repo.name


def live_of(page):
    start = page.index("window.LANTERN_LIVE = ") + len("window.LANTERN_LIVE = ")
    return json.JSONDecoder().raw_decode(page[start:])[0]


def test_the_app_offers_the_agent_only_once_it_is_picked(shop, tmp_path):
    import threading
    from http.server import ThreadingHTTPServer

    from lantern.server import App, Handler, Store
    from test_server import call, wait
    repo, mode, _ = shop
    store = Store(tmp_path / "home")
    store.root.mkdir(exist_ok=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.app = App(store, "tok-123", httpd.server_address[1])
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        _, p = call(base, "/api/projects", "POST", {"path": str(repo)})
        pid = p["id"]
        code, a = call(base, "/api/agents")
        assert code == 200 and a["chosen"] == "" and {x["id"] for x in a["agents"]} == {"claude", "codex", "aider"}
        # off by default: the report offers nothing and the action refuses
        assert live_of(call(base, f"/p/{pid}/report.html")[1])["agent"] is None
        fid = md5_id(repo)
        code, e = call(base, f"/api/projects/{pid}/agentfix", "POST", {"finding": fid})
        assert code == 400 and "Settings" in e["error"]
        assert call(base, "/api/settings", "POST", {"agent": "bash -c x"})[0] == 400
        assert call(base, "/api/settings", "POST", {"agent": "claude"})[0] == 200
        assert live_of(call(base, f"/p/{pid}/report.html")[1])["agent"] == {"id": "claude", "name": "Claude Code"}
        code, e = call(base, f"/api/projects/{pid}/agentfix", "POST", {"finding": "nope"})
        assert code == 400
        mode.write_text("fix")
        code, job = call(base, f"/api/projects/{pid}/agentfix", "POST", {"finding": fid})
        assert code == 202
        j = wait(base, job["id"])
        assert j["status"] == "done" and j["result"]["status"] == "fixed", j
        assert "md5" in (repo / "shop" / "auth.py").read_text(encoding="utf-8")
        code, job = call(base, f"/api/projects/{pid}/agentapply", "POST", {"fix": j["result"]["fix"]})
        assert code == 202 and wait(base, job["id"])["status"] == "done"
        assert "hashlib.sha256(" in (repo / "shop" / "auth.py").read_text(encoding="utf-8")
        sec = json.loads((repo / ".lantern" / "security.json").read_text(encoding="utf-8"))
        assert fid not in {f["id"] for f in sec["findings"]}
        # throwing a fix away
        mode.write_text("worse")
        sec_open = next(f["id"] for f in sec["findings"] if f["status"] == "open" and not f.get("in_tests"))
        code, job = call(base, f"/api/projects/{pid}/agentfix", "POST", {"finding": sec_open})
        j = wait(base, job["id"])
        assert j["status"] == "done"
        if j["result"]["fix"]:
            assert call(base, f"/api/projects/{pid}/agentdiscard", "POST", {"fix": j["result"]["fix"]})[0] == 200
            assert not (store.root / "fixes" / agents.FIXES_DIR / j["result"]["fix"]).exists()
        assert call(base, f"/api/projects/{pid}/agentdiscard", "POST", {"fix": "../../etc"})[0] == 400
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_change_that_only_hides_the_finding_is_not_called_fixed(shop):
    """The verdict is the fix contract's (`lantern/fixcheck.py`). Until 2026-11-16 only the finding's id was looked
    for, and the call put together at run time read "Fixed"."""
    repo, mode, work = shop
    for how, part, words in (("computed", "calls", "it was hidden and not fixed"),
                             ("comment", "gone", "Lantern still finds the problem")):
        mode.write_text(how)
        res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
        assert res["status"] == "not_fixed" and words in res["verdict"], (how, res["verdict"])
        assert "Don't apply this one." in res["verdict"]
        assert res["contract"]["verdict"] == "refused" and part in res["contract"]["broken"], (how, res["contract"])
        agents.discard_fix(res["fix"], work_root=work)
    mode.write_text("no_tests")
    res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
    assert res["status"] == "fixed_with_new" and "makes something else worse" in res["verdict"], res["verdict"]
    assert "tests/test_auth.py is gone" in res["verdict"] and res["contract"]["broken"] == ["tests"]
    assert "Look before you apply it." in res["verdict"]


def test_a_true_fix_says_that_the_tests_were_not_run(shop):
    repo, mode, work = shop
    mode.write_text("fix")
    res = agents.run_fix(repo, repo / ".lantern", md5_id(repo), "claude", "full", lambda m: None, work_root=work)
    assert res["status"] == "fixed" and "Your tests were not run on the change" in res["verdict"]
    assert res["contract"]["verdict"] == "incomplete" and res["contract"]["not_shown"] == ["tests"]
    assert [i["id"] for i in res["contract"]["items"]] == ["gone", "no-suppression", "still-read", "links", "calls", "nothing-new", "tests"]


def test_a_rule_changed_so_that_the_finding_stops_showing_is_not_called_fixed(shop):
    """A pack that comes with the project found it, and the agent changes the pack and not the code. The pack still
    runs; only what it said at each check tells the two apart, and "no longer found" is then no proof of a fix."""
    repo, mode, work = shop
    (repo / "lantern-packs").mkdir()
    (repo / "lantern-packs" / "house.json").write_text(json.dumps({"pack": "house", "version": "1", "rules": [
        {"id": "LP-HOUSE-HASH", "title": "A weak hash for a password", "severity": "MEDIUM", "files": ["shop/*.py"],
         "pattern": "md5\\("}]}), encoding="utf-8")
    pipeline.analyze(repo, pipeline.out_dir(repo), log=lambda m: None, offline=True)
    sec = json.loads((repo / ".lantern" / "security.json").read_text(encoding="utf-8"))
    fid = next(f["id"] for f in sec["findings"] if f["rule"] == "LP-HOUSE-HASH")
    mode.write_text("pack")
    res = agents.run_fix(repo, repo / ".lantern", fid, "claude", "full", lambda m: None, work_root=work)
    assert res["status"] == "not_fixed" and "does not show that it is fixed" in res["verdict"], res["verdict"]
    assert "the rules of lantern-pack:house" in res["verdict"] and "Don't apply this one." in res["verdict"]
    assert res["contract"]["verdict"] == "incomplete" and "gone" in res["contract"]["not_shown"]
    agents.discard_fix(res["fix"], work_root=work)
    mode.write_text("fix")              # the safe twin: the line itself is changed
    res = agents.run_fix(repo, repo / ".lantern", fid, "claude", "full", lambda m: None, work_root=work)
    assert res["status"] == "fixed", res["verdict"]
