"""Probes for tests/test_isolation.py: background work a test asked the cloud service for ends with that test.

Not collected by a normal run (the file name does not start with test_). The two probes run in this order: the first
walks away from two runs, the second is the test that would be blamed.
"""
import os
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

from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

LINK = "https://github.com/octo/shop"
DOWNLOADS: list = []      # one entry for each run whose download step reached the first probe's stand-in
KEPT: dict = {}           # the service and its two runs, for the second probe to look at


def test_probe_a_test_that_walks_away_from_its_runs(tmp_path, monkeypatch):
    """Two people start a run on a service that works on one run at a time, and the test returns. The first run's
    download is held until one second after that, so the second run reaches its own download later still: at a time
    when, unless work ends with its test, this test's stand-in is gone and the real download asks github.com."""
    reached, go = threading.Event(), threading.Event()

    def stand_in(link, dest, log):
        DOWNLOADS.append(link)
        reached.set()
        go.wait(30)
        raise RuntimeError("the probe's stand-in downloads nothing")
    monkeypatch.setattr(worker_mod, "clone_repo", stand_in)
    gateway = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")))
    settings = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "cloud.db"),
                        results_dir=str(tmp_path / "results"), work_dir=str(tmp_path / "work"), audits=False,
                        concurrent_jobs=1)
    app = create_app(settings, transport=httpx.ASGITransport(app=gateway))
    cloud = TestClient(app)
    runs = []
    for who in ("github:1", "github:2"):
        token = gateway.state.store.sign_in(who, who)
        r = cloud.post("/v1/repos", json={"link": LINK}, headers={"authorization": f"Bearer {token}"})
        assert r.status_code == 202, r.text
        runs.append(r.json()["id"])
    KEPT.update(store=app.state.store, runs=runs)
    assert reached.wait(20)
    threading.Timer(1.0, go.set).start()


def test_probe_the_test_after_it():
    """Waits until both runs have ended. Each one's download went to the first probe's stand-in; and the conftest
    fails this probe when anything asks for another computer while it runs."""
    store, runs = KEPT["store"], KEPT["runs"]
    end = time.time() + 60
    while time.time() < end and any(store.run(r)["status"] in ("queued", "running") for r in runs):
        time.sleep(0.1)
    assert [store.run(r)["status"] for r in runs] == ["error", "error"]
    assert DOWNLOADS == [LINK, LINK]
