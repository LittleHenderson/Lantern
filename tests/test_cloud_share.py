"""Cloud service, milestone 5: share links (off until the owner turns them on, revocable), deleting a run, deleting
everything about a person, and the retention sweep (off by default: results are kept until the person deletes them)."""

import re
import sqlite3
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from test_cloud_runs import LINK, SOURCE_LINE, bearer, clone_from, make, origin, wait  # noqa: E402,F401
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def done_run(tmp_path, clone_from):  # noqa: F811
    cloud, gw, s = make(tmp_path, public_url="http://testserver")
    tok = gw.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    assert wait(cloud, tok, rid)["status"] == "done"
    return cloud, gw, s, tok, rid


def path(url):
    return url.replace("http://testserver", "")


def stranger(cloud):
    return TestClient(cloud.app)       # no cookies, no token


def test_share_is_off_until_the_owner_turns_it_on(done_run):
    cloud, gw, s, tok, rid = done_run
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).json()["shared"] is False
    assert cloud.get(f"/v1/runs/{rid}/share", headers=bearer(tok)).json() == {"shared": False, "url": None}
    assert stranger(cloud).get(f"/s/{rid}/report.html").status_code == 404        # the run id is not a share link
    r = stranger(cloud).get("/s/" + "x" * 24 + "/report.html")
    assert r.status_code == 404 and "This link is off" in r.text and "<script" not in r.text


def test_shared_report_opens_for_anyone_read_only(done_run):
    cloud, gw, s, tok, rid = done_run
    v = cloud.post(f"/v1/runs/{rid}/share", headers=bearer(tok)).json()
    assert v["shared"] is True and re.fullmatch(r"http://testserver/s/[A-Za-z0-9_-]{24}/report\.html", v["url"])
    assert rid not in v["url"]
    assert cloud.post(f"/v1/runs/{rid}/share", headers=bearer(tok)).json() == v      # the same link again
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).json()["shared"] is True
    anyone = stranger(cloud)
    page = anyone.get(path(v["url"]))
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    nonce = re.search(r"'nonce-([^']+)'", page.headers["content-security-policy"]).group(1)
    assert all(f'nonce="{nonce}"' in t for t in re.findall(r"<script[^>]*>", page.text) if 'type="application/json"' not in t)
    assert page.headers["x-robots-tag"] == "noindex" and page.headers["referrer-policy"] == "no-referrer"
    assert "window.LANTERN_LIVE = " not in page.text           # read-only
    assert SOURCE_LINE not in page.text                         # privacy as chosen before the run, never widened
    base = path(v["url"]).rsplit("/", 1)[0]
    assert anyone.get(base + "/evidence.html").status_code == 200
    assert anyone.get(base + "/badge.svg").headers["content-type"].startswith("image/svg+xml")
    for name in ("findings.json", "graph.json", "readiness.json", "secrets.txt", "..%2Fcloud.db"):
        assert anyone.get(f"{base}/{name}").status_code == 404     # pages only, not the raw data files


def test_only_the_owner_shares_and_only_finished_runs(done_run, monkeypatch):
    cloud, gw, s, tok, rid = done_run
    other = gw.sign_in("github:2", "github:b")
    assert cloud.post(f"/v1/runs/{rid}/share", headers=bearer(other)).status_code == 404
    assert cloud.delete(f"/v1/runs/{rid}/share", headers=bearer(other)).status_code == 404
    assert cloud.post(f"/v1/runs/{rid}/share").status_code == 401
    from lantern_cloud import worker as worker_mod

    def boom(link, dest, log):
        raise RuntimeError("could not clone it: not found")
    monkeypatch.setattr(worker_mod, "clone_repo", boom)
    bad = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(other)).json()["id"]
    wait(cloud, other, bad)
    assert cloud.post(f"/v1/runs/{bad}/share", headers=bearer(other)).status_code == 409


def test_stop_sharing_turns_the_link_off_for_good(done_run):
    cloud, gw, s, tok, rid = done_run
    old = cloud.post(f"/v1/runs/{rid}/share", headers=bearer(tok)).json()["url"]
    assert cloud.delete(f"/v1/runs/{rid}/share", headers=bearer(tok)).json() == {"shared": False, "url": None}
    r = stranger(cloud).get(path(old))
    assert r.status_code == 404 and "This link is off" in r.text
    new = cloud.post(f"/v1/runs/{rid}/share", headers=bearer(tok)).json()["url"]
    assert new != old and stranger(cloud).get(path(old)).status_code == 404     # sharing again never revives the old link
    assert stranger(cloud).get(path(new)).status_code == 200


def test_delete_a_run_removes_its_results_and_its_link(done_run):
    cloud, gw, s, tok, rid = done_run
    url = cloud.post(f"/v1/runs/{rid}/share", headers=bearer(tok)).json()["url"]
    folder = Path(s.results_dir) / rid
    assert folder.is_dir()
    other = gw.sign_in("github:2", "github:b")
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(other)).status_code == 404     # not theirs
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok)).json() == {"deleted": rid}
    assert not folder.exists()
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).status_code == 404
    assert stranger(cloud).get(path(url)).status_code == 404
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok)).status_code == 404


def test_a_run_still_going_is_not_deleted(tmp_path, monkeypatch, clone_from):  # noqa: F811
    from lantern_cloud import worker as worker_mod
    gate = {"go": False}

    def slow(link, dest, log):
        while not gate["go"]:
            time.sleep(0.05)
        raise RuntimeError("stopped")
    monkeypatch.setattr(worker_mod, "clone_repo", slow)
    cloud, gw, s = make(tmp_path)
    tok = gw.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    try:
        r = cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok))
        assert r.status_code == 409 and "still going" in r.json()["error"]["message"]
        assert cloud.delete("/v1/me", headers=bearer(tok)).status_code == 409
    finally:
        gate["go"] = True
    wait(cloud, tok, rid)
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok)).status_code == 200


def test_delete_me_forgets_everything(done_run):
    cloud, gw, s, tok, rid = done_run
    url = cloud.post(f"/v1/runs/{rid}/share", headers=bearer(tok)).json()["url"]
    other = gw.sign_in("github:2", "github:b")
    cloud.get("/v1/me", headers=bearer(other))
    r = cloud.delete("/v1/me", headers=bearer(tok))
    assert r.json() == {"deleted": True, "runs": 1}
    assert not (Path(s.results_dir) / rid).exists() and stranger(cloud).get(path(url)).status_code == 404
    db = sqlite3.connect(s.db_path)
    assert db.execute("select count(*) from runs where account = 'github:1'").fetchone()[0] == 0
    assert db.execute("select count(*) from daily where account = 'github:1'").fetchone()[0] == 0
    assert [a for (a,) in db.execute("select account from users")] == ["github:2"]      # nobody else touched
    # signing in again later starts a fresh, empty account
    assert cloud.get("/v1/runs", headers=bearer(tok)).json() == {"runs": []}


def test_cookie_deletes_need_the_sites_header(done_run):
    cloud, gw, s, tok, rid = done_run
    c = TestClient(cloud.app)
    c.cookies.set("lt", tok)
    assert c.delete(f"/v1/runs/{rid}").status_code == 403
    assert c.delete("/v1/me").status_code == 403
    assert c.post(f"/v1/runs/{rid}/share").status_code == 403
    assert c.post(f"/v1/runs/{rid}/share", headers={"x-lantern-site": "1"}).status_code == 200
    r = c.delete("/v1/me", headers={"x-lantern-site": "1"})
    gone = r.headers["set-cookie"]
    assert r.status_code == 200 and gone.startswith("lt=") and ("max-age=0" in gone.lower() or "expires=" in gone.lower())


def test_retention_sweep_is_off_by_default_and_deletes_old_runs_when_set(done_run):
    from lantern_cloud.app import sweep
    cloud, gw, s, tok, rid = done_run
    store = cloud.app.state.store
    assert s.retention_days == 0 and sweep(store, s.results_dir, 0) == []
    assert sweep(store, s.results_dir, 30) == []                  # finished just now: kept
    with store.lock:
        store.db.execute("update runs set finished = '2020-01-01T00:00:00+00:00' where id = ?", (rid,))
        store.db.commit()
    assert sweep(store, s.results_dir, 30) == [rid]
    assert store.run(rid) is None and not (Path(s.results_dir) / rid).exists()
