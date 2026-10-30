import json
import os
import shutil
import stat
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from lantern.server import App, Handler, Store

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture()
def srv(tmp_path):
    store = Store(tmp_path / "home")
    store.root.mkdir()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    Handler.app = App(store, "tok-123", port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", store
    httpd.shutdown()
    httpd.server_close()


def call(base, path, method="GET", body=None, token="tok-123", cookie=True, host=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    if cookie:
        req.add_header("Cookie", "lantern_token=tok-123")
    if token:
        req.add_header("X-Lantern-Token", token)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req) as r:
            data = r.read()
            return r.status, (json.loads(data) if r.headers.get_content_type() == "application/json" else data.decode())
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            return e.code, json.loads(data)
        except json.JSONDecodeError:
            return e.code, data.decode()


def wait(base, job_id, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        _, j = call(base, f"/api/jobs/{job_id}")
        if j["status"] != "running":
            return j
        time.sleep(0.2)
    raise AssertionError("job did not finish")


def test_access_control(srv):
    base, _ = srv
    assert call(base, "/", cookie=False, token=None)[0] == 403              # no token: locked page
    assert call(base, "/api/state", cookie=False, token=None)[0] == 403
    assert call(base, "/api/state", host="evil.example:80")[0] == 403        # DNS rebinding
    assert call(base, "/api/settings", "POST", {}, token=None)[0] == 403     # cookie alone can't write
    assert call(base, "/api/settings", "POST", {}, token="wrong")[0] == 403
    code, page = call(base, "/")
    assert code == 200 and "tok-123" in page and "<title>Lantern</title>" in page
    # the tokenized link sets an HttpOnly, SameSite=Strict cookie and redirects
    req = urllib.request.Request(base + "/?token=tok-123")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        urllib.request.build_opener(NoRedirect).open(req)
    except urllib.error.HTTPError as e:
        assert e.code == 303
        c = e.headers["Set-Cookie"]
        assert "HttpOnly" in c and "SameSite=Strict" in c


def test_project_lifecycle(srv, tmp_path):
    base, store = srv
    repo = tmp_path / "shop"
    shutil.copytree(FIX / "shop", repo)
    assert call(base, "/api/projects", "POST", {"path": str(tmp_path / "nope")})[0] == 400
    code, p = call(base, "/api/projects", "POST", {"path": str(repo)})
    assert code == 200 and not p["has_report"]
    code, job = call(base, f"/api/projects/{p['id']}/analyze", "POST", {})
    assert code == 202
    # a second run while the first is going is refused
    assert call(base, f"/api/projects/{p['id']}/analyze", "POST", {})[0] in (202, 409)
    j = wait(base, job["id"])
    assert j["status"] == "done", j
    assert any(line.startswith("ready") for line in j["log"])
    _, st = call(base, "/api/state")
    pr = st["projects"][0]
    assert pr["has_report"] and pr["grade"] == "F" and pr["counts"]["critical"] >= 1
    assert pr["shape"] == "full-stack web app"
    code, html = call(base, f"/p/{p['id']}/report.html")
    assert code == 200 and "window.LANTERN_LIVE" in html
    assert call(base, f"/p/{p['id']}/evidence.html")[0] == 200
    # plan for explanations
    code, plan = call(base, f"/api/projects/{p['id']}/plan")
    assert code == 200 and plan["nodes"] > 0 and plan["input_tokens"] > 0
    # explain needs a model
    assert call(base, f"/api/projects/{p['id']}/explain", "POST", {})[0] == 400
    # starter files: write one, never overwrite, never escape the project
    assert call(base, f"/api/projects/{p['id']}/starter", "POST", {"name": "SECURITY.md"})[0] == 200
    assert (repo / "SECURITY.md").exists()
    assert call(base, f"/api/projects/{p['id']}/starter", "POST", {"name": "SECURITY.md"})[0] == 400
    assert call(base, f"/api/projects/{p['id']}/starter", "POST", {"name": "../x"})[0] == 400
    # accept a risk with a reason, which re-runs the analysis
    sec = json.loads((repo / ".lantern/security.json").read_text(encoding="utf-8"))
    fid = next(f["id"] for f in sec["findings"] if f["rank"] == "critical" and f["category"] == "code")
    assert call(base, f"/api/projects/{p['id']}/accept", "POST", {"finding": fid, "reason": "no"})[0] == 400
    code, job = call(base, f"/api/projects/{p['id']}/accept", "POST",
                     {"finding": fid, "reason": "Admin-only endpoint behind the VPN"})
    assert code == 202 and wait(base, job["id"])["status"] == "done"
    sec = json.loads((repo / ".lantern/security.json").read_text(encoding="utf-8"))
    assert next(f for f in sec["findings"] if f["id"] == fid)["status"] == "accepted"
    # removing from the list keeps files
    assert call(base, f"/api/projects/{p['id']}", "DELETE")[0] == 200
    assert (repo / ".lantern/report.html").exists() and not store.projects()


def test_keys_stay_private(srv):
    base, store = srv
    code, r = call(base, "/api/settings", "POST", {"provider": "anthropic", "model": "m", "key": "sk-session"})
    assert code == 200
    anth = next(x for x in r["providers"] if x["name"] == "anthropic")
    assert anth["key"] == "this session" and "sk-session" not in json.dumps(r)
    assert "sk-session" not in (store.root / "keys.json").read_text(encoding="utf-8")
    call(base, "/api/settings", "POST", {"provider": "anthropic", "key": "sk-remember", "remember": True})
    kf = store.root / "keys.json"
    assert json.loads(kf.read_text(encoding="utf-8"))["anthropic"] == "sk-remember"
    if os.name == "posix":
        assert stat.S_IMODE(kf.stat().st_mode) == 0o600
    _, st = call(base, "/api/state")
    assert "sk-remember" not in json.dumps(st)
    call(base, "/api/settings", "POST", {"forget_key": True})
    assert "anthropic" not in json.loads(kf.read_text(encoding="utf-8"))
    assert call(base, "/api/settings", "POST", {"provider": "nope"})[0] == 400


def test_explain_end_to_end_with_a_local_fake_model(srv, tmp_path):
    import subprocess
    import sys
    base, _ = srv
    repo = tmp_path / "shop"
    shutil.copytree(FIX / "shop", repo)
    tool = Path(__file__).parent.parent / "tools" / "fake_model.py"
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    fake = subprocess.Popen([sys.executable, str(tool), str(port)])
    try:
        time.sleep(0.5)
        _, p = call(base, "/api/projects", "POST", {"path": str(repo)})
        assert wait(base, call(base, f"/api/projects/{p['id']}/analyze", "POST", {})[1]["id"])["status"] == "done"
        call(base, "/api/settings", "POST", {"provider": "openai-compatible", "model": "demo",
                                             "base_url": f"http://127.0.0.1:{port}/v1"})
        node = "js:web/src/pages/Admin::BackupButton"
        code, job = call(base, f"/api/projects/{p['id']}/explain", "POST", {"nodes": [node]})
        assert code == 202
        j = wait(base, job["id"])
        assert j["status"] == "done", j
        _, r = call(base, f"/api/projects/{p['id']}/explanation?node=" + urllib.request.quote(node))
        assert r["record"]["validated"] and r["record"]["lens1"]["summary"]
        assert node in (repo / ".lantern/report.html").read_text(encoding="utf-8")
    finally:
        fake.terminate()


def _planted_repo(tmp_path):
    """A cloned repo that ships its own .lantern/ results, with script in every field it can reach."""
    repo = tmp_path / "planted"
    out = repo / ".lantern"
    out.mkdir(parents=True)
    x = '<img src=x onerror="alert(1)">'
    (repo / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (out / "report.html").write_text(f"<!doctype html><script>alert('planted')</script>{x}", encoding="utf-8")
    (out / "evidence.html").write_text(f"<script>alert('planted')</script>", encoding="utf-8")
    (out / "badge.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', encoding="utf-8")
    (out / "security.json").write_text(json.dumps({"counts": {"critical": x, "high": 1, "medium": 0}, "findings": []}), encoding="utf-8")
    (out / "readiness.json").write_text(json.dumps({"score": x, "grade": x, "shape": x}), encoding="utf-8")
    (out / "run.json").write_text(json.dumps({"finished_at": x}), encoding="utf-8")
    return repo


def test_planted_results_cannot_run_script(srv, tmp_path):
    base, store = srv
    repo = _planted_repo(tmp_path)
    p = store.add_project(repo)
    _, st = call(base, "/api/state")
    s = next(x for x in st["projects"] if x["id"] == p["id"])
    assert s["counts"]["critical"] == 0 and s["counts"]["high"] == 1   # non-numbers dropped
    assert s["score"] is None and s["grade"] is None and s["shape"] is None   # only Lantern's own shape names
    # Repo-supplied HTML is never served as a page: no planted script, no live token in a planted report.
    code, body = call(base, f"/p/{p['id']}/report.html")
    assert code == 409 and "planted" not in body and "tok-123" not in body
    for name in ("evidence.html", "badge.svg"):
        code, body = call(base, f"/p/{p['id']}/{name}")
        assert "alert" not in str(body), name


def test_pages_carry_a_nonce_csp(srv, tmp_path):
    base, store = srv
    repo = tmp_path / "app"
    shutil.copytree(FIX / "shop", repo)
    p = store.add_project(repo)
    wait(base, call(base, f"/api/projects/{p['id']}/analyze", "POST", {})[1]["id"])
    for path in ("/", f"/p/{p['id']}/report.html", f"/p/{p['id']}/evidence.html"):
        req = urllib.request.Request(base + path, headers={"Cookie": "lantern_token=tok-123"})
        with urllib.request.urlopen(req) as r:
            csp, body = r.headers["Content-Security-Policy"], r.read().decode()
        assert "script-src" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0], path
        if "nonce-" in csp:
            nonce = csp.split("nonce-")[1].split("'")[0]
            assert body.count("<script") == body.count(f'nonce="{nonce}"') + body.count('type="application/json"'), path
    # the live report is rebuilt from the template, with the token only in our own script
    _, body = call(base, f"/p/{p['id']}/report.html")
    assert "window.LANTERN_LIVE" in body


def test_non_ascii_token_is_refused_not_crashed(srv):
    base, _ = srv
    code, _ = call(base, "/?token=%C3%A9", cookie=False, token=None)
    assert code == 403


def test_another_machine_needs_its_address_allowed(srv, monkeypatch):
    """`lantern serve --host 0.0.0.0` listens on every interface, but the Host check still admits only this machine's
    own names until LANTERN_ALLOWED_HOST names the address the other machine uses, so DNS rebinding stays blocked."""
    base, _ = srv
    port = base.rsplit(":", 1)[1]
    monkeypatch.delenv("LANTERN_ALLOWED_HOST", raising=False)
    assert call(base, "/api/state", host=f"192.168.1.5:{port}")[0] == 403
    monkeypatch.setenv("LANTERN_ALLOWED_HOST", f"192.168.1.5:{port}")
    assert call(base, "/api/state", host=f"192.168.1.5:{port}")[0] == 200
    assert call(base, "/api/state", host=f"192.168.1.6:{port}")[0] == 403
