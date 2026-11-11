"""Opt-in usage counts and the owner's dashboard: off by default, counts only, nothing else accepted."""

import json
import sys
from pathlib import Path

import pytest

from lantern import usage

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from lantern_gateway.app import Settings, create_app  # noqa: E402

ADMIN = "admin-" + "z" * 20


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("LANTERN_GATEWAY_URL", raising=False)
    return tmp_path / "home"


@pytest.fixture
def gw(tmp_path):
    app = create_app(Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k", admin_secret=ADMIN,
                              db_path=str(tmp_path / "gw.db"), free_requests=5))
    return TestClient(app)


def test_off_by_default_records_nothing(home):
    assert usage.enabled() is False
    usage.record("analyze")
    assert not (home / "usage.json").exists() and not (home / "install_id").exists()
    assert usage.pending() == [] and usage.describe().startswith("OFF")


def test_on_counts_known_features_only(home):
    usage.set_enabled(True)
    assert len(usage.install_id()) == 32 and usage.install_id() == usage.install_id()
    for f in ("analyze", "analyze", "explain", "not_a_feature", "accept"):
        usage.record(f)
    p = usage.pending()
    assert len(p) == 1 and p[0]["features"] == {"analyze": 2, "explain": 1, "accept": 1}
    assert set(p[0]) == {"install", "version", "os", "day", "features"}   # and nothing else
    assert usage.describe().startswith("ON") and "Next ping" in usage.describe()
    usage.set_enabled(False)
    usage.record("analyze")
    assert usage.pending() == [] and usage.describe().startswith("OFF")


def test_gateway_accepts_counts_and_rejects_everything_else(gw):
    good = {"install": "ab" * 16, "version": "0.1.0", "os": "Linux", "features": {"analyze": 3, "explain": 1}}
    r = gw.post("/v1/usage", json=good)
    assert r.status_code == 200 and r.json()["recorded"] == ["analyze", "explain"]
    # unknown feature names, file names, paths and non-counts are dropped on the floor
    r = gw.post("/v1/usage", json={**good, "features": {"analyze": 1, "project": "my-secret-app", "file": "a.py", "x": True}})
    assert r.json()["recorded"] == ["analyze"]
    assert gw.post("/v1/usage", json={**good, "install": "short"}).status_code == 400
    assert gw.post("/v1/usage", json={**good, "day": "2001-01-01"}).status_code == 400
    assert gw.post("/v1/usage", content=b"{" * 5000).status_code == 413
    # the same day sent twice keeps the larger count, never doubles
    gw.post("/v1/usage", json={**good, "features": {"analyze": 5}})
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()
    assert stats["app"]["installs_total"] == 1
    feats = {f["feature"]: f["count"] for f in stats["app"]["features_30d"]}
    assert feats == {"analyze": 5, "explain": 1}
    assert stats["app"]["os"] == [{"os": "Linux", "installs": 1}]


def test_admin_stats_and_dashboard_need_the_secret(gw):
    assert gw.get("/v1/admin/stats").status_code == 403
    assert gw.get("/v1/admin/stats", headers={"authorization": "Bearer wrong"}).status_code == 403
    tok = gw.post("/v1/tokens", json={"label": "wakil"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    s = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()
    assert s["allowance"]["tokens_issued"] == 1 and s["allowance"]["users_ever_used"] == 0
    assert s["limits"]["requests"] == 5 and s["global_daily_usd"] == 10.0
    assert s["allowance"]["top_users"][0]["label"] == "wakil"
    page = gw.get("/v1/admin")
    assert page.status_code == 200 and "owner dashboard" in page.text and "Content-Security-Policy" in page.headers
    assert tok.startswith("lt_")


@pytest.fixture
def gw_address(gw):
    """The gateway of `gw` behind a real address on this computer: each request is handed to it as it came, path
    included, and its answer goes back. (Until 2026-11-10 this test replaced `urlopen` and handed over the body
    alone, so it could not see that the path Lantern posted to was not one the gateway has.)"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length") or 0))
            r = gw.post(self.path, content=body, headers={"content-type": "application/json"})
            if r.status_code == 200:
                seen.append(json.loads(body))
            self.send_response(r.status_code)
            self.send_header("content-length", str(len(r.content)))
            self.end_headers()
            self.wfile.write(r.content)

        def log_message(self, *a):
            pass
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", seen
    httpd.shutdown()
    httpd.server_close()


def test_app_sends_pending_pings_to_the_gateway(home, gw_address):
    address, sent = gw_address
    usage.set_enabled(True)
    usage.record("analyze")
    assert usage.send(address) == 1
    assert sent[0]["features"] == {"analyze": 1}
    assert usage.send(address) == 0                        # already sent; nothing new
    usage.record("explain")
    assert usage.send(address) == 1                        # the day's counts changed: sent again, gateway keeps the max
    assert usage.send(address + "/v1") == 0                # the address as Lantern is set up with it: the same place
    usage.record("accept")
    assert usage.send(address + "/v1") == 1 and sent[-1]["features"] == {"analyze": 1, "explain": 1, "accept": 1}
    assert usage.send("") == 0                             # no gateway configured: nothing leaves


def test_server_setting_toggle(home, tmp_path):
    from lantern.server import Store
    st = Store(home)
    assert st.settings()["share_usage"] is False
    st.save_settings({**st.settings(), "share_usage": True})
    assert usage.enabled() is True and (home / "install_id").exists()
    st.save_settings({**st.settings(), "share_usage": False})
    assert usage.enabled() is False
