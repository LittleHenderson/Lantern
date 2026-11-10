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
from lantern_cloud.cleanup import MARK  # noqa: E402
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
                 results_dir=str(tmp_path / "results"), work_dir=workdir(tmp_path), **{"audits": False, **kw})
    cloud = TestClient(create_app(s, transport=httpx.ASGITransport(app=gw_app)))
    store = gw_app.state.store
    return cloud, store, s


def bearer(t):
    return {"authorization": f"Bearer {t}"}


def left_by_a_step(monkeypatch, word: str, where: str, target: Path, how: str = "link"):
    """What a step that was taken over could leave for the service to pick up. After the restricted step whose
    command holds `word` has ended (the step itself runs as it always does), `where` in its temp folder
    ("out/graph.json", "out/cache", "out") is a link to `target`, or, with how="second name", a second name of the
    file `target` (a hard link). Returns the real `_jailed`, for a safe twin."""
    real = worker_mod.Worker._jailed

    def and_then(self, rid, root, cmd, **kw):
        got = real(self, rid, root, cmd, **kw)
        if word in cmd:
            at = root / "tmp" / where
            if at.is_dir() and not at.is_symlink():
                shutil.rmtree(at)
            elif os.path.lexists(at):
                os.unlink(at)
            at.parent.mkdir(parents=True, exist_ok=True)
            (os.link if how == "second name" else os.symlink)(target, at)
        return got
    monkeypatch.setattr(worker_mod.Worker, "_jailed", and_then)
    return real


def holds(folder: Path, text: str) -> list[str]:
    """The files under `folder` that hold `text`, and every link under it (a link has no place in a results
    folder), each as a path from `folder`."""
    found = []
    for dirpath, dirs, files in os.walk(folder):
        for f in dirs + files:
            q = Path(dirpath) / f
            if q.is_symlink() or (q.is_file() and text.encode() in q.read_bytes()):
                found.append(q.relative_to(folder).as_posix())
    return sorted(found)


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


def test_a_private_repository_says_so_and_offers_upload(tmp_path, monkeypatch):
    """git asks for a password (a private repository, or no such one): the person reads plain words and the website
    offers Upload instead; git's own words stay in the log."""
    def private(link, dest, log):
        raise RuntimeError("could not clone it: fatal: could not read Username for 'https://github.com': terminal "
                           "prompts disabled. If the repository is private, clone it yourself and add the folder.")
    monkeypatch.setattr(worker_mod, "clone_repo", private)
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    done = wait(cloud, tok, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"])
    assert done["status"] == "error" and done["error"] == worker_mod.NOT_PUBLIC and done["hint"] == "upload"
    assert "could not read Username" in done["log_tail"] and "clone it yourself" not in done["error"]


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
    leftover = Path(s.work_dir) / "run-crashed0"       # as the worker makes it: its mark is inside
    leftover.mkdir(parents=True)
    (leftover / "file").write_text("x", encoding="utf-8")
    (leftover / MARK).write_text("made by lantern-cloud for one run\n", encoding="utf-8")
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


def _zip_of(folder: Path, top: str = "shop", extra: dict | None = None) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file() and ".lantern" not in p.parts and "__pycache__" not in p.parts:
                z.write(p, f"{top}/{p.relative_to(folder).as_posix()}")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


SHOP = Path(__file__).parent / "fixtures" / "shop"


def test_an_uploaded_zip_is_checked_and_then_deleted(tmp_path, monkeypatch):
    def no_clone(link, dest, log):
        raise AssertionError("an upload must not be cloned")
    monkeypatch.setattr(worker_mod, "clone_repo", no_clone)
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    body = _zip_of(SHOP)
    assert cloud.post("/v1/uploads?name=shop", content=body).status_code == 401           # signed in only
    r = cloud.post("/v1/uploads?name=my%20shop/../x", content=body, headers=bearer(tok))
    assert r.status_code == 202, r.text
    d = r.json()
    assert d["link"] == "lantern:upload/myshop..x" and d["host"] == "upload"                # a label, never a path
    done = wait(cloud, tok, d["id"])
    assert done["status"] == "done", done
    assert done["summary"]["counts"]["critical"] >= 1 and "Unpacking your upload" in done["log_tail"]
    assert not list(Path(s.uploads()).iterdir())                     # the upload is gone once the run has it
    res = Path(s.results_dir) / d["id"]
    assert (res / "report.html").is_file() and SOURCE_LINE not in (res / "report.html").read_text(encoding="utf-8")
    # explanations would need the code again, which is deleted
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(tok))
    r = cloud.post(f"/v1/runs/{d['id']}/explain", headers=bearer(tok))
    assert r.status_code == 409 and "uploaded app" in r.json()["error"]["message"]


def test_bad_uploads_are_refused(tmp_path):
    cloud, gw, s = make(tmp_path, clone_max_mb=1)
    tok = gw.sign_in("github:1", "github:octo")
    r = cloud.post("/v1/uploads", content=b"hello, not a zip", headers=bearer(tok))
    assert r.status_code == 400 and ".zip" in r.json()["error"]["message"]
    r = cloud.post("/v1/uploads", content=b"PK" + os.urandom(2 << 20), headers=bearer(tok))
    assert r.status_code == 413 and "larger than 1 MB" in r.json()["error"]["message"]
    r = cloud.post("/v1/uploads?privacy=full", content=_zip_of(SHOP), headers=bearer(tok))
    assert r.status_code == 400                                      # snippets need the agreement, as for links
    assert not [p for p in Path(s.uploads()).iterdir()]              # nothing half-written is left behind
    # an archive that tries to write outside its folder: the run stops with the unpacker's sentence
    r = cloud.post("/v1/uploads", content=_zip_of(SHOP, extra={"../../evil.py": "x"}), headers=bearer(tok))
    assert r.status_code == 202
    done = wait(cloud, tok, r.json()["id"])
    assert done["status"] == "error" and "outside its folder" in done["error"], done
    assert not (Path(s.work_dir).parent / "evil.py").exists()


def test_a_restart_keeps_only_the_uploads_of_waiting_runs(tmp_path):
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "cloud.db"),
                 results_dir=str(tmp_path / "results"), work_dir=workdir(tmp_path), audits=False)
    store = Store(s.db_path)
    rid = store.create_run("github:1", "lantern:upload/shop", "upload", "structure", per_day=10, global_per_day=10,
                           per_user_active=2)
    over = store.create_run("github:1", "lantern:upload/shop", "upload", "structure", per_day=10, global_per_day=10,
                            per_user_active=2)
    store.update_run(over, status="error")
    up = Path(s.uploads())
    up.mkdir(parents=True, exist_ok=True)
    (up / f"{rid}.zip").write_bytes(b"PK")             # its run is still queued: kept for it
    (up / f"{over}.zip").write_bytes(b"PK")            # its run is over
    (up / ".part-0123456789abcdef").write_bytes(b"PK")   # cut off while it was being received
    w = worker_mod.Worker(s, store)
    w.pool.shutdown(wait=False, cancel_futures=True)   # only the start-up sweep is tested here
    assert {p.name for p in up.iterdir()} <= {f"{rid}.zip"}      # (the waiting run may have taken its upload by now)
    # (what is in that folder and is not Lantern's own is left alone: tests/test_cloud_cleanup.py)


def test_the_audit_step_failing_still_gives_a_finished_run(tmp_path, clone_from, monkeypatch):
    """Outside services down (OSV, npm, pip-audit, or the audit process itself crashing): the run finishes, the log says
    the dependency audit did not finish, and the report records that dependencies were not checked (offline)."""
    real = worker_mod.Worker._jailed

    def jailed(self, rid, root, cmd, **kw):
        if "lantern.depaudit" in cmd:
            kw["log"]("audit: Traceback (most recent call last): ConnectionRefusedError")
            return 1, "ConnectionRefusedError", False      # exit 1, nothing written
        return real(self, rid, root, cmd, **kw)
    monkeypatch.setattr(worker_mod.Worker, "_jailed", jailed)
    cloud, gw, s = make(tmp_path, audits=True)
    tok = gw.sign_in("github:1", "github:octo")
    d = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()
    done = wait(cloud, tok, d["id"])
    assert done["status"] == "done", done
    assert "the dependency audit did not finish" in done["log_tail"]
    res = Path(s.results_dir) / d["id"]
    ev = json.loads((res / "evidence.json").read_text(encoding="utf-8"))
    assert ev["payload"]["run"]["offline"] is True, ev["payload"]["run"]     # `lantern verify` will skip the audits too
    sec = json.loads((res / "security.json").read_text(encoding="utf-8"))
    audits = {t["tool"]: t.get("status", "") for t in sec["tools"] if t["tool"].endswith("-audit")}
    assert audits and all(st.startswith("skipped") for st in audits.values()), audits
    assert done["summary"]["counts"]["critical"] >= 1      # the code's own findings are unaffected
    assert list(Path(s.work_dir).iterdir()) == []


def test_the_code_is_read_from_a_folder_named_after_the_repository():
    # The Evidence Report is titled after the folder it read; a fixed `repo` folder titled every report "repo"
    s = worker_mod.source_name
    assert s("https://github.com/LittleHenderson/Lantern") == "Lantern"
    assert s("https://github.com/octo/shop.git") == "shop"
    assert s("https://gitlab.com/octo/shop/tree/main") == "shop"
    assert s("lantern:sample/shop") == "shop"
    assert s("lantern:upload/my app.zip") == "my-app"
    for bad in ("lantern:upload/..", "lantern:upload/", "not a link", None):
        assert s(bad) == "app"


# ---------------------------------------------------------------------------- stage 7: stopping, and the guard
def _lines(cloud, rid) -> list[str]:
    return cloud.app.state.worker.logs.since(rid, 0)[0]


def test_shutting_the_service_down_ends_the_step_a_run_is_in_with_everything_it_started(tmp_path, clone_from, monkeypatch):
    """Before, `shutdown` only kept waiting runs from starting: the step that was running went on to its end, and
    the processes it had started (here a child, one in a session of its own, a daemon) stayed after it."""
    from test_sandbox_safety import LEAVES, _started, _still_there
    monkeypatch.setattr(worker_mod.Worker, "analyze_cmd",
                        staticmethod(lambda repo, out, privacy, offline=True: [sys.executable, "-c", LEAVES]))
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    end, pids = time.time() + 120, []
    while not pids and time.time() < end:
        pids = _started(_lines(cloud, rid))
        time.sleep(0.1)
    try:
        assert len(pids) == 3, _lines(cloud, rid)
        t = time.time()
        cloud.app.state.worker.shutdown()
        done = wait(cloud, tok, rid, timeout=60)
        assert done["status"] == "error" and done["error"] == worker_mod.SHUT_DOWN, done
        assert time.time() - t < 30
        assert _still_there(pids) == [], "a process the step started outlived the service's shutdown"
        assert list(Path(s.work_dir).iterdir()) == [] and not (Path(s.results_dir) / rid).exists()
    finally:
        for pid in pids:
            try:
                os.kill(pid, 9)
            except OSError:
                pass


def test_a_step_is_not_started_once_the_service_is_stopping(tmp_path, clone_from):
    cloud, gw, s = make(tmp_path)
    worker = cloud.app.state.worker
    worker.stopping.set()                      # as `shutdown` does, with the pool left open so the run is taken up
    tok = gw.sign_in("github:1", "github:octo")
    done = wait(cloud, tok, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"])
    assert done["status"] == "error" and done["error"] == worker_mod.SHUT_DOWN
    assert not any("sandbox: Landlock" in x for x in _lines(cloud, done["id"])), "a step was started"
    assert list(Path(s.work_dir).iterdir()) == []


def test_the_service_stops_its_worker_when_it_is_shut_down(tmp_path):
    cloud, _gw, _s = make(tmp_path)
    worker = cloud.app.state.worker
    with cloud:                                # start-up and shutdown, as the server that runs the service does them
        assert cloud.get("/v1/health").status_code == 200 and not worker.stopping.is_set()
    assert worker.stopping.is_set()


@pytest.mark.parametrize("guard", ["missing", "there"])
def test_a_reading_step_whose_guard_did_not_load_says_so_and_goes_on(guard, tmp_path, clone_from, monkeypatch):
    """The cloud's steps read a project and run none of it, so they carry on without the guard. Before, nothing
    said that it was not there."""
    from lantern import _jail, sandbox
    if guard == "missing":
        monkeypatch.setattr(sandbox, "SITECUSTOMIZE", "# a guard that did not load\n")
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    done = wait(cloud, tok, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"])
    assert done["status"] == "done", done
    said = [x for x in _lines(cloud, done["id"]) if x == _jail.GUARD_MISSING]
    assert len(said) == (1 if guard == "missing" else 0), _lines(cloud, done["id"])


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root (the steps then run as another user)")
def test_as_root_with_files_made_owner_only_a_step_still_has_its_guard(tmp_path, clone_from, monkeypatch):
    """Where root's files are made owner-only (umask 077), the user the steps run as could not read the guard's
    folder; Python left it out of its path without a word and the step ran with no guard."""
    script = ("import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
              "s.sendto(b'x', ('127.0.0.1', 9))\nprint('PACKET-SENT', flush=True)\n")
    monkeypatch.setattr(worker_mod.Worker, "analyze_cmd", staticmethod(lambda repo, out, privacy, offline=True: [sys.executable, "-c", script]))
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    old = os.umask(0o077)
    try:
        done = wait(cloud, tok, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"])
    finally:
        os.umask(old)
    lines = _lines(cloud, done["id"])
    assert done["status"] == "blocked" and "network sendto" in done["error"], (done, lines)
    assert not any("PACKET-SENT" in x for x in lines) and _jail_guard_missing() not in lines


def _jail_guard_missing() -> str:
    from lantern import _jail
    return _jail.GUARD_MISSING
