"""Cloud service, milestone 1: settings, store, sign-in through the gateway, health, admin stats.

The gateway here is the real gateway app (in process, through httpx's ASGI transport), so the test proves the
two services agree on the token scheme: a token minted or signed in at the gateway works on the cloud service.
"""

import sqlite3
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
from fastapi.testclient import TestClient  # noqa: E402

from lantern_cloud import __version__ as CLOUD_VERSION  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

ADMIN = "admin-" + "y" * 20


class CountingASGI(httpx.ASGITransport):
    def __init__(self, app):
        super().__init__(app=app)
        self.calls = 0

    async def handle_async_request(self, request):
        self.calls += 1
        return await super().handle_async_request(request)


@pytest.fixture
def env(tmp_path):
    gw_app = create_gateway(GwSettings(admin_secret=ADMIN, db_path=str(tmp_path / "gw.db")))
    gw = TestClient(gw_app)
    transport = CountingASGI(gw_app)
    s = Settings(gateway_url="http://gateway.test/v1", admin_secret=ADMIN, db_path=str(tmp_path / "cloud.db"),
                 results_dir=str(tmp_path / "results"), work_dir=str(tmp_path / "work"), audits=False)
    cloud = TestClient(create_app(s, transport=transport))
    return gw, gw_app, cloud, transport, s, tmp_path


def bearer(t):
    return {"authorization": f"Bearer {t}"}


def test_health_is_public_and_shows_no_counters(env):
    _, _, cloud, transport, _, _ = env
    r = cloud.get("/v1/health")
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] is True and d["service"] == "lantern-cloud" and d["version"] == CLOUD_VERSION
    import lantern
    assert d["engine"] == lantern.__version__
    # Owner decisions: every known host, results kept until deleted, structure-only by default.
    assert d["hosts"] == "all"
    assert d["limits"]["retention_days"] is None and d["limits"]["default_privacy"] == "structure"
    assert d["limits"]["clone_max_mb"] == 500
    assert "users" not in d and "runs" not in d
    assert transport.calls == 0          # health never asks the gateway


def test_signed_out_and_unknown_tokens_are_refused(env):
    _, _, cloud, _, _, _ = env
    r = cloud.get("/v1/me")
    assert r.status_code == 401 and r.json()["error"]["type"] == "signed_out"
    r = cloud.get("/v1/me", headers=bearer("lt_not-a-real-token"))
    assert r.status_code == 401 and "Sign in again" in r.json()["error"]["message"]


def test_gateway_token_signs_in_and_only_the_account_is_stored(env):
    gw, _, cloud, transport, s, _ = env
    tok = gw.post("/v1/tokens", json={"label": "tester"}, headers=bearer(ADMIN)).json()["token"]
    r = cloud.get("/v1/me", headers=bearer(tok))
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["label"] == "tester" and d["runs_today"] == 0 and d["runs_active"] == 0
    assert d["limits"]["runs_per_day"] == s.runs_per_day
    # Asked once, then the answer is reused (keyed by the token's hash, in memory only).
    cloud.get("/v1/me", headers=bearer(tok))
    assert transport.calls == 1
    # The database holds the account id and label, never the token or its hash.
    db = sqlite3.connect(s.db_path)
    rows = db.execute("select account, label from users").fetchall()
    assert len(rows) == 1 and rows[0][0].startswith("token:") and rows[0][1] == "tester"
    raw = Path(s.db_path).read_bytes()
    assert tok.encode() not in raw
    import hashlib
    assert hashlib.sha256(tok.encode()).hexdigest().encode() not in raw


def test_signing_in_somewhere_else_keeps_the_website_signed_in(env):
    _, gw_app, cloud, _, s, _ = env
    store = gw_app.state.store
    t1 = store.sign_in("github:4242", "github:octo")
    assert cloud.get("/v1/me", headers=bearer(t1)).json()["label"] == "github:octo"
    t2 = store.sign_in("github:4242", "github:octo")      # the same person signs in on the app or the gateway page
    assert cloud.get("/v1/me", headers=bearer(t2)).status_code == 200
    accounts = [r[0] for r in sqlite3.connect(s.db_path).execute("select account from users")]
    assert accounts == ["github:4242"]
    # The website's earlier sign-in still works once the cached answer is gone: nobody signs in twice.
    cloud.app.state.identity.cache.clear()
    assert cloud.get("/v1/me", headers=bearer(t1)).json()["label"] == "github:octo"
    # Switching the account off at the gateway still signs out every place.
    store.db.execute("update users set disabled = 1 where token_hash = ?", (store.user(t1)["hash"],))
    store.db.commit()
    cloud.app.state.identity.cache.clear()
    assert cloud.get("/v1/me", headers=bearer(t1)).status_code == 401 and cloud.get("/v1/me", headers=bearer(t2)).status_code == 401


def test_gateway_down_is_unavailable_not_signed_out(tmp_path):
    def down(request):
        raise httpx.ConnectError("no route")
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "c.db"), results_dir=str(tmp_path / "r"), work_dir=str(tmp_path / "w"))
    cloud = TestClient(create_app(s, transport=httpx.MockTransport(down)))
    r = cloud.get("/v1/me", headers=bearer("lt_whatever"))
    assert r.status_code == 503 and r.json()["error"]["type"] == "unavailable"

    def odd(request):
        return httpx.Response(200, json={"account": ""})
    cloud = TestClient(create_app(s, transport=httpx.MockTransport(odd)))
    assert cloud.get("/v1/me", headers=bearer("lt_whatever")).status_code == 503


def test_admin_stats_needs_the_admin_secret(env):
    gw, _, cloud, _, _, _ = env
    assert cloud.get("/v1/admin/stats").status_code == 403
    assert cloud.get("/v1/admin/stats", headers=bearer("wrong")).status_code == 403
    tok = gw.post("/v1/tokens", json={"label": "a"}, headers=bearer(ADMIN)).json()["token"]
    cloud.get("/v1/me", headers=bearer(tok))
    d = cloud.get("/v1/admin/stats", headers=bearer(ADMIN)).json()
    assert d["users"] == 1 and d["runs"] == 0 and d["shared"] == 0


def test_admin_stats_closed_when_no_secret_is_set(tmp_path):
    s = Settings(admin_secret="", db_path=str(tmp_path / "c.db"), results_dir=str(tmp_path / "r"), work_dir=str(tmp_path / "w"))
    assert TestClient(create_app(s)).get("/v1/admin/stats", headers=bearer("")).status_code == 403


def test_store_delete_user_forgets_everything(tmp_path):
    from lantern_cloud.store import Store, now
    st = Store(str(tmp_path / "c.db"))
    st.touch_user("github:1", "github:a")
    st.db.execute("insert into runs (id, account, link, privacy, status, created) values ('r1', 'github:1', "
                  "'https://github.com/a/b', 'structure', 'done', ?)", (now(),))
    st.db.execute("insert into daily (day, account, runs) values ('2026-11-03', 'github:1', 3)")
    st.db.commit()
    assert st.delete_user("github:1") == ["r1"]
    assert st.user("github:1") is None and st.active_runs() == 0
    assert st.db.execute("select count(*) from daily").fetchone()[0] == 0


def test_settings_from_environment(monkeypatch):
    monkeypatch.setenv("LANTERN_CLOUD_HOSTS", "github.com, GitLab.com ,")
    monkeypatch.setenv("LANTERN_CLOUD_RUNS_PER_DAY", "not-a-number")
    s = Settings()
    assert s.hosts() == ["github.com", "gitlab.com"] and s.runs_per_day == 10


def test_versions_match_their_pyproject():
    import re
    txt = (ROOT / "cloud" / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "([^"]+)"', txt, re.M).group(1) == CLOUD_VERSION
    from lantern_gateway import __version__ as gwv
    txt = (ROOT / "gateway" / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "([^"]+)"', txt, re.M).group(1) == gwv


def test_idle_exit_waits_for_runs_and_requests(env):
    from lantern_cloud.idle import IdleExit
    stops = []
    busy = {"v": True}
    ie = IdleExit(0.0005, busy=lambda: busy["v"], stop=lambda: stops.append(1))   # 0.03 s
    import time
    time.sleep(0.05)
    assert ie.check() is False and stops == []          # a run is going: never stops
    busy["v"] = False
    assert ie.check() is False                          # the run just ended: the idle clock starts again
    time.sleep(0.05)
    assert ie.check() is True and stops == [1]
    assert ie.check() is False and stops == [1]         # once
    assert IdleExit(0, busy=lambda: False, stop=lambda: stops.append(2)).check() is False
    # Requests reset the clock.
    _, _, cloud, _, _, _ = env
    before = cloud.app.state.idle.last
    time.sleep(0.01)
    cloud.get("/v1/health")
    assert cloud.app.state.idle.last > before


OLD_SCHEMA_V0_10 = """
create table if not exists users (
  account text primary key, label text, created text, last_seen text, ai_consent text);
create table if not exists runs (
  id text primary key, account text not null, link text not null, host text, privacy text not null,
  status text not null, stage text, error text, created text not null, started text, finished text,
  commit_sha text, summary text, log_tail text, share_slug text unique,
  explain_status text, explain_error text, explain_summary text);
create index if not exists runs_by_account on runs (account, created);
create table if not exists daily (day text, account text, runs integer default 0, primary key (day, account));
create table if not exists global_daily (day text primary key, runs integer default 0);
"""

OLDER_SCHEMA = """
create table if not exists users (account text primary key, label text, created text, last_seen text);
create table if not exists runs (
  id text primary key, account text not null, link text not null, host text, privacy text not null,
  status text not null, stage text, error text, created text not null, started text, finished text,
  commit_sha text, summary text, share_slug text unique);
create table if not exists daily (day text, account text, runs integer default 0, primary key (day, account));
create table if not exists global_daily (day text primary key, runs integer default 0);
"""


@pytest.mark.parametrize("schema", [OLD_SCHEMA_V0_10, OLDER_SCHEMA])
def test_an_older_database_opens_and_keeps_its_rows(tmp_path, schema):
    """Upgrades: the cloud database written by v0.10.0 (and the first cloud release) opens in this version, missing
    columns are added, and the old rows are still listed and counted."""
    from lantern_cloud.store import Store
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript(schema)
    con.execute("insert into users (account, label, created, last_seen) values ('github:1', 'octo', '2026-11-03T10:00:00', '2026-11-03T10:00:00')")
    con.execute("insert into runs (id, account, link, host, privacy, status, created, finished, commit_sha, summary) values "
                "('r1', 'github:1', 'https://github.com/o/shop', 'github.com', 'structure', 'done', '2026-11-03T10:00:00', "
                "'2026-11-03T10:01:00', 'abc', '{\"score\": 71, \"counts\": {\"critical\": 1}}')")
    con.execute("insert into daily (day, account, runs) values ('2026-11-03', 'github:1', 1)")
    con.commit()
    con.close()
    s = Store(str(db))
    cols = {r[1] for r in s.db.execute("pragma table_info(runs)")}
    assert {"log_tail", "explain_status", "explain_error", "explain_summary"} <= cols
    assert "ai_consent" in {r[1] for r in s.db.execute("pragma table_info(users)")}
    runs = s.runs("github:1")
    assert len(runs) == 1
    r = s.run("r1")
    assert r["status"] == "done" and r["link"].endswith("/shop")
    assert s.runs_today("github:1", "2026-11-03") == 1
    s2 = Store(str(db))                                # opening again is harmless (idempotent migration)
    assert s2.run("r1")["id"] == "r1"


def test_limit_messages_say_how_long_until_the_reset():
    import datetime as dt
    from lantern_cloud.store import until_midnight_utc
    at = dt.datetime(2026, 11, 5, 18, 40, tzinfo=dt.UTC)
    assert until_midnight_utc(at) == "in 5 h 20 min (00:00 UTC)"
    assert until_midnight_utc(dt.datetime(2026, 11, 5, 23, 59, 30, tzinfo=dt.UTC)) == "in 1 min (00:00 UTC)"
    assert until_midnight_utc(dt.datetime(2026, 11, 5, 0, 0, 0, tzinfo=dt.UTC)) == "in 24 h 0 min (00:00 UTC)"


def test_sign_out_everywhere_from_the_website(env):
    _, gw_app, cloud, _, _, _ = env
    store = gw_app.state.store
    web, app_tok = store.sign_in("github:77", "github:seven"), store.sign_in("github:77", "github:seven")
    cloud.cookies.set("lt", web)
    site = {"x-lantern-site": "1"}
    assert cloud.get("/v1/me").status_code == 200 and cloud.get("/v1/me", headers=bearer(app_tok)).status_code == 200
    assert cloud.post("/v1/signout", json={"everywhere": True}).status_code == 403          # only from Lantern's page
    r = cloud.post("/v1/signout", json={"everywhere": True}, headers=site)
    assert r.status_code == 200 and r.json()["ended"] == 2
    cloud.cookies.clear()
    assert cloud.get("/v1/me", headers=bearer(app_tok)).status_code == 401                # the app is signed out too
    # A plain sign-out ends only this browser's sign-in.
    web, app_tok = store.sign_in("github:77", "github:seven"), store.sign_in("github:77", "github:seven")
    cloud.cookies.set("lt", web)
    assert cloud.post("/v1/signout", headers=site).json()["ended"] == 1
    assert store.user(web) is None and cloud.get("/v1/me", headers=bearer(app_tok)).status_code == 200
