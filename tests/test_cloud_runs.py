"""Cloud service, milestone 2: start a run from a link, the worker clones, analyses in the sandbox, keeps only the
results, and deletes the clone whatever happens. Limits, ownership, log streaming, restarts.

The clone step is replaced by a local `git clone` of a fixture repository (the real one is https only and is
covered by tests/test_remote.py); everything after it is the real worker: the jailed analysis, the result files,
the clean-up.
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
if os.name != "posix":
    pytest.skip("the cloud worker runs on Linux (its restricted process is POSIX)", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
from fastapi.testclient import TestClient  # noqa: E402

from lantern import remote  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_cloud.store import Store  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

LINK = "https://github.com/octo/shop"
SOURCE_LINE = 'subprocess.call("tar czf " + name'     # a line of the fixture's code


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, encoding="utf-8")


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    src = tmp_path_factory.mktemp("origin") / "shop"
    shutil.copytree(ROOT / "tests" / "fixtures" / "shop", src)
    git("init", "-q", "-b", "main", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x", cwd=src)
    return src


@pytest.fixture
def clone_from(monkeypatch, origin):
    seen = {}

    def fake_clone(link, dest, log):
        seen["link"], seen["dest"] = link, dest
        log(f"cloning {link}")
        git("clone", "-q", "--depth", "1", origin.as_uri(), str(dest), cwd=dest.parent)
        remote._mark(dest)
        return dest
    monkeypatch.setattr(worker_mod, "clone_repo", fake_clone)
    return seen


def workdir(tmp_path) -> str:
    """Under /tmp itself: when the tests run as root the analysis drops to `nobody`, who cannot pass through
    pytest's private tmp_path folders."""
    import tempfile
    w = Path(tempfile.mkdtemp(prefix="lantern-cloud-test-"))
    (tmp_path / "workdir").write_text(str(w), encoding="utf-8")
    return str(w)


def make(tmp_path, **kw):
    gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")))
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "cloud.db"),
                 results_dir=str(tmp_path / "results"), work_dir=workdir(tmp_path), audits=False, **kw)
    cloud = TestClient(create_app(s, transport=httpx.ASGITransport(app=gw_app)))
    store = gw_app.state.store
    return cloud, store, s


def bearer(t):
    return {"authorization": f"Bearer {t}"}


def wait(cloud, tok, rid, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        r = cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).json()
        if r["status"] not in ("queued", "running"):
            return r
        time.sleep(0.3)
    raise AssertionError("run did not finish")


def test_a_run_keeps_results_and_deletes_the_clone(tmp_path, clone_from):
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    r = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))
    assert r.status_code == 202, r.text
    d = r.json()
    assert d["status"] in ("queued", "running") and d["privacy"] == "structure" and d["host"] == "github.com" and d["shared"] is False
    assert "account" not in d
    done = wait(cloud, tok, d["id"])
    assert done["status"] == "done", done
    assert done["summary"]["score"] is not None and done["summary"]["counts"]["critical"] >= 1
    assert len(done["commit"]) == 40
    assert "commit " in done["log_tail"] and "Mapping the code" in done["log_tail"]
    assert str(tmp_path) not in done["log_tail"]                # temp paths are scrubbed from the log
    # Results kept, at the chosen privacy level: structure keeps no source.
    res = Path(s.results_dir) / d["id"]
    assert (res / "report.html").is_file() and (res / "evidence.json").is_file() and (res / "security.json").is_file()
    assert SOURCE_LINE not in (res / "report.html").read_text(encoding="utf-8")
    assert json.loads((res / "run.json").read_text(encoding="utf-8"))["privacy"] == "structure"
    # The clone and every temp file are gone.
    assert list(Path(s.work_dir).iterdir()) == []
    assert not clone_from["dest"].exists()
    # Listed for the owner, newest first; counted for today.
    runs = cloud.get("/v1/runs", headers=bearer(tok)).json()["runs"]
    assert [x["id"] for x in runs] == [d["id"]]
    assert cloud.get("/v1/me", headers=bearer(tok)).json()["runs_today"] == 1


def test_full_privacy_needs_the_snippet_agreement_and_keeps_snippets(tmp_path, clone_from):
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    r = cloud.post("/v1/repos", json={"link": LINK, "privacy": "full"}, headers=bearer(tok))
    assert r.status_code == 400 and "snippets of your code will be stored" in r.json()["error"]["message"]
    r = cloud.post("/v1/repos", json={"link": LINK, "privacy": "full", "stored_snippets_ok": True}, headers=bearer(tok))
    done = wait(cloud, tok, r.json()["id"])
    assert done["status"] == "done" and done["privacy"] == "full"
    html = (Path(s.results_dir) / done["id"] / "report.html").read_text(encoding="utf-8")
    assert "tar czf" in html


@pytest.mark.parametrize("link,why", [
    ("http://github.com/octo/shop", "https"),
    ("file:///etc", "https"),
    ("https://user:pw@github.com/octo/shop", ""),
    ("https://evil.example/octo/shop", ""),
    ("", "Paste the https link"),
    (None, "Paste the https link"),
])
def test_bad_links_are_refused_before_anything_runs(tmp_path, clone_from, link, why):
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    r = cloud.post("/v1/repos", json={"link": link}, headers=bearer(tok))
    assert r.status_code == 400, r.text
    assert why in r.json()["error"]["message"]
    assert cloud.get("/v1/runs", headers=bearer(tok)).json()["runs"] == []
    assert "link" not in clone_from


def test_bad_privacy_and_host_allow_list(tmp_path, clone_from):
    cloud, gw, s = make(tmp_path, allowed_hosts="gitlab.com")
    tok = gw.sign_in("github:1", "github:octo")
    assert cloud.post("/v1/repos", json={"link": LINK, "privacy": "everything"}, headers=bearer(tok)).status_code == 400
    r = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))
    assert r.status_code == 400 and "gitlab.com" in r.json()["error"]["message"]


def test_runs_belong_to_their_owner(tmp_path, clone_from):
    cloud, gw, s = make(tmp_path)
    a, b = gw.sign_in("github:1", "github:a"), gw.sign_in("github:2", "github:b")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(a)).json()["id"]
    wait(cloud, a, rid)
    for path in (f"/v1/runs/{rid}", f"/v1/runs/{rid}/stream"):
        r = cloud.get(path, headers=bearer(b))
        assert r.status_code == 404 and r.json()["error"]["type"] == "not_found"
    assert cloud.get("/v1/runs", headers=bearer(b)).json()["runs"] == []
    assert cloud.get(f"/v1/runs/{rid}").status_code == 401
    assert cloud.get("/v1/runs/" + "x" * 200, headers=bearer(a)).status_code == 404


def test_limits_answer_429_with_a_sentence(tmp_path, monkeypatch, origin):
    gate = threading.Event()

    def slow_clone(link, dest, log):
        gate.wait(30)
        git("clone", "-q", "--depth", "1", origin.as_uri(), str(dest), cwd=dest.parent)
        remote._mark(dest)
        return dest
    monkeypatch.setattr(worker_mod, "clone_repo", slow_clone)
    cloud, gw, s = make(tmp_path, runs_per_day=2)
    tok = gw.sign_in("github:1", "github:octo")
    first = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    r = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))
    assert r.status_code == 429 and "already have a run going" in r.json()["error"]["message"]
    gate.set()
    wait(cloud, tok, first)
    second = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))
    assert second.status_code == 202
    wait(cloud, tok, second.json()["id"])
    r = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))
    assert r.status_code == 429 and "today's 2 runs" in r.json()["error"]["message"]
    other = gw.sign_in("github:2", "github:other")    # someone else is not affected
    assert cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(other)).status_code == 202


def test_global_daily_limit(tmp_path, clone_from):
    cloud, gw, s = make(tmp_path, global_runs_per_day=1)
    a, b = gw.sign_in("github:1", "github:a"), gw.sign_in("github:2", "github:b")
    wait(cloud, a, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(a)).json()["id"])
    r = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(b))
    assert r.status_code == 429 and "everyone" in r.json()["error"]["message"]


def test_a_failed_clone_leaves_nothing_behind(tmp_path, monkeypatch):
    seen = {}

    def too_big(link, dest, log):
        dest.mkdir()
        (dest / "partial").write_text("x", encoding="utf-8")
        seen["dest"] = dest
        raise RuntimeError(f"{dest} is 950 MB, above the 200 MB limit (LANTERN_CLONE_MAX_MB)")
    monkeypatch.setattr(worker_mod, "clone_repo", too_big)
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    done = wait(cloud, tok, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"])
    assert done["status"] == "error" and "above the 200 MB limit" in done["error"]
    assert str(tmp_path) not in done["error"]
    assert list(Path(s.work_dir).iterdir()) == [] and not seen["dest"].exists()
    assert not (Path(s.results_dir) / done["id"]).exists()


def test_the_analysis_cannot_reach_the_network_or_write_outside(tmp_path, clone_from, monkeypatch):
    """A tricked analyser is stopped by the sandbox: no network, no writes outside its temp folder."""
    outside = tmp_path / "planted.txt"
    script = ("import socket, sys\n"
              f"try:\n    open({str(outside)!r}, 'w').write('x')\nexcept Exception as e:\n    print('write refused', e)\n"
              "try:\n    socket.create_connection(('203.0.113.9', 443), timeout=2)\nexcept Exception as e:\n"
              "    print('net refused', e)\nsys.exit(3)\n")
    monkeypatch.setattr(worker_mod.Worker, "analyze_cmd", staticmethod(lambda repo, out, privacy, offline=True: [sys.executable, "-c", script]))
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    done = wait(cloud, tok, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"])
    assert done["status"] == "blocked", done
    assert "sandbox does not allow" in done["error"]
    assert not outside.exists()
    assert list(Path(s.work_dir).iterdir()) == [] and not (Path(s.results_dir) / done["id"]).exists()


def test_the_wall_clock_stops_a_run(tmp_path, clone_from, monkeypatch):
    monkeypatch.setattr(worker_mod.Worker, "analyze_cmd",
                        staticmethod(lambda repo, out, privacy, offline=True: [sys.executable, "-c", "import time; time.sleep(60)"]))
    cloud, gw, s = make(tmp_path, job_timeout=8)
    tok = gw.sign_in("github:1", "github:octo")
    t = time.time()
    done = wait(cloud, tok, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"])
    assert done["status"] == "error" and "was stopped" in done["error"]
    assert time.time() - t < 40
    assert list(Path(s.work_dir).iterdir()) == []


def test_stream_sends_log_lines_then_the_end(tmp_path, clone_from):
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    with cloud.stream("GET", f"/v1/runs/{rid}/stream", headers=bearer(tok)) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        body = "".join(r.iter_text())
    events = [e for e in body.split("\n\n") if e.strip()]
    assert events[-1].startswith("event: end")
    end = json.loads(events[-1].split("data: ", 1)[1])
    assert end["status"] == "done"
    logs = [json.loads(e.split("data: ", 1)[1]) for e in events if e.startswith("event: log")]
    assert any("Mapping the code" in ln for ln in logs)
    # A finished run answers at once with its saved tail.
    with cloud.stream("GET", f"/v1/runs/{rid}/stream", headers=bearer(tok)) as r:
        again = "".join(r.iter_text())
    assert "event: end" in again and "Mapping the code" in again


def test_restart_requeues_waiting_runs_and_reports_cut_off_ones(tmp_path, clone_from):
    s = Settings(db_path=str(tmp_path / "c.db"), results_dir=str(tmp_path / "r"), work_dir=workdir(tmp_path),
                 audits=False)
    st = Store(s.db_path)
    a = st.create_run("github:1", LINK, "github.com", "structure", per_day=9, global_per_day=9, per_user_active=9)
    b = st.create_run("github:1", LINK, "github.com", "structure", per_day=9, global_per_day=9, per_user_active=9)
    st.update_run(a, status="running")
    leftover = Path(s.work_dir) / "run-crashed"
    leftover.mkdir(parents=True)
    (leftover / "file").write_text("x", encoding="utf-8")
    w = worker_mod.Worker(s, st)
    assert not leftover.exists()                       # a crashed run's temp folder is removed at start-up
    assert st.run(a)["status"] == "error" and "restarted" in st.run(a)["error"]
    end = time.time() + 120
    while st.run(b)["status"] in ("queued", "running") and time.time() < end:
        time.sleep(0.3)
    assert st.run(b)["status"] == "done"
    w.shutdown()


@pytest.mark.skipif(not shutil.which("npm"), reason="npm not installed")
def test_precomputed_audits_reach_the_report(tmp_path, monkeypatch):
    """The audit step's file is what the offline analysis reports (LANTERN_AUDITS_FROM)."""
    from lantern import depaudit
    f = tmp_path / "a.json"
    f.write_text(json.dumps({"npm-audit": {"findings": [], "info": {"tool": "npm-audit", "status": "ok", "files": ["x"]}}}),
                 encoding="utf-8")
    monkeypatch.setenv("LANTERN_AUDITS_FROM", str(f))
    assert depaudit.run_npm_audit(tmp_path, True) == ([], {"tool": "npm-audit", "status": "ok", "files": ["x"]})
    assert depaudit.run_pip_audit(tmp_path, True)[1]["status"] != "ok"     # no entry for pip-audit: runs as usual
    f.write_text("not json", encoding="utf-8")
    assert depaudit.precomputed("npm-audit") is None


def test_sample_apps_are_listed_and_checked_without_a_clone(tmp_path, monkeypatch):
    def no_clone(link, dest, log):
        raise AssertionError("a sample app must not be cloned")
    monkeypatch.setattr(worker_mod, "clone_repo", no_clone)
    cloud, gw, s = make(tmp_path)
    listed = cloud.get("/v1/samples").json()["samples"]            # public: shown before sign-in
    ids = [x["id"] for x in listed]
    assert "notes-api" in ids and all(x["title"] and x["summary"] for x in listed)
    tok = gw.sign_in("github:1", "github:octo")
    for bad in ("../notes-api", "nope", 7, ""):
        r = cloud.post("/v1/repos", json={"sample": bad}, headers=bearer(tok))
        assert r.status_code == 400 and "sample apps" in r.json()["error"]["message"], (bad, r.text)
    r = cloud.post("/v1/repos", json={"sample": "notes-api"}, headers=bearer(tok))
    assert r.status_code == 202, r.text
    d = r.json()
    assert d["link"] == "lantern:sample/notes-api" and d["host"] == "sample"
    done = wait(cloud, tok, d["id"])
    assert done["status"] == "done", done
    assert done["summary"]["counts"]["critical"] + done["summary"]["counts"]["high"] >= 1   # the planted problems
    assert "built-in starter apps" in done["log_tail"]
    assert (Path(s.results_dir) / d["id"] / "report.html").is_file()
