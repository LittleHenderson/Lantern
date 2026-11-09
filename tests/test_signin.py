"""Sign in with GitHub / Google: signed state, server-side exchange, one token per account, parked tokens."""

import sys
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from lantern_gateway import auth  # noqa: E402
from lantern_gateway.app import Settings, create_app  # noqa: E402

ADMIN = "admin-" + "z" * 20
CLI = "c" * 40


def providers_transport(calls: list):
    """Fake GitHub and Google: the code 'good' signs in user 42 / sub 9876543210; anything else is refused."""
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if request.url.host in ("github.com", "oauth2.googleapis.com"):
            body = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            if body.get("code") != "good" or not body.get("client_secret"):
                return httpx.Response(400, json={"error": "bad_verification_code"})
            return httpx.Response(200, json={"access_token": "at_" + body["code"], "token_type": "bearer"})
        if request.url.host == "api.github.com":
            assert request.headers["authorization"] == "Bearer at_good"
            return httpx.Response(200, json={"id": 42, "login": "octocat", "email": "secret@example.com"})
        if request.url.host == "openidconnect.googleapis.com":
            return httpx.Response(200, json={"sub": "9876543210", "email": "someone@gmail.com"})
        return httpx.Response(500)
    return httpx.MockTransport(handler)


@pytest.fixture
def gw(tmp_path):
    calls: list = []
    s = Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k", admin_secret=ADMIN,
                 db_path=str(tmp_path / "gw.db"), public_url="https://gw.test", github_client_id="gh-id",
                 github_client_secret="gh-secret", google_client_id="go-id", google_client_secret="go-secret")
    client = TestClient(create_app(s, transport=providers_transport(calls)), follow_redirects=False)
    client.calls = calls
    client.s = s
    return client


def _signin(gw, provider, cli=CLI, code="good"):
    r = gw.get(f"/v1/auth/{provider}/start", params={"cli": cli})
    assert r.status_code == 302
    loc = r.headers["location"]
    state = dict(x.split("=", 1) for x in loc.split("?", 1)[1].split("&"))["state"]
    assert "client_secret" not in loc
    return gw.get(f"/v1/auth/{provider}/callback", params={"code": code, "state": state})


def test_providers_and_login_page(gw):
    assert gw.get("/v1/auth/providers").json() == {"providers": ["github", "google"], "login_url": "https://gw.test/v1/login"}
    page = gw.get("/v1/login", params={"cli": CLI})
    assert page.status_code == 200 and "Sign in with GitHub" in page.text and "Sign in with Google" in page.text
    assert f"cli={CLI}" in page.text and "Content-Security-Policy" in page.headers
    assert "cli=" not in gw.get("/v1/login", params={"cli": "short!"}).text        # a malformed cli code is dropped


def test_github_sign_in_issues_one_token_and_parks_it_for_the_cli(gw):
    r = _signin(gw, "github")
    assert r.status_code == 200 and "octocat" in r.text and "secret@example.com" not in r.text
    tok = gw.get("/v1/auth/claim", params={"cli": CLI}).json()["token"]
    assert tok.startswith("lt_") and tok not in r.text      # the app collects it; the page never shows it
    assert gw.get("/v1/auth/claim", params={"cli": CLI}).status_code == 404      # one claim only
    a = gw.get("/v1/allowance", headers={"authorization": f"Bearer {tok}"}).json()
    assert a["used_requests"] == 0 and a["remaining_requests"] == 300
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert stats["accounts"] == 1 and stats["accounts_github"] == 1
    assert stats["top_users"][0]["label"] == "github:octocat"


def test_signing_in_again_keeps_the_other_sign_ins_and_shares_one_allowance(gw):
    """Signing in on a second place (the website after the app, a phone after a laptop) must not sign the first
    one out, and must not give a second allowance: both tokens count against one row."""
    _signin(gw, "github")
    tok1 = gw.get("/v1/auth/claim", params={"cli": CLI}).json()["token"]
    store = gw.app.state.store
    store.record(store.user(tok1)["hash"], "2026-11-02", 1000, 0.01, "m")
    cli2 = "d" * 40
    _signin(gw, "github", cli=cli2)
    tok2 = gw.get("/v1/auth/claim", params={"cli": cli2}).json()["token"]
    assert tok2 != tok1
    h = lambda t: {"authorization": f"Bearer {t}"}   # noqa: E731
    a1, a2 = gw.get("/v1/allowance", headers=h(tok1)).json(), gw.get("/v1/allowance", headers=h(tok2)).json()
    assert a1["used_requests"] == a2["used_requests"] == 1 and a2["used_tokens"] == 1000     # one shared count
    store.record(store.user(tok2)["hash"], "2026-11-02", 5, 0.01, "m")
    assert gw.get("/v1/allowance", headers=h(tok1)).json()["used_requests"] == 2
    assert gw.get("/v1/whoami", headers=h(tok1)).json() == gw.get("/v1/whoami", headers=h(tok2)).json()
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert stats["accounts"] == 1                                                                       # still one account


def test_sign_ins_are_capped_and_the_least_recently_used_goes_first(tmp_path):
    from lantern_gateway.app import Store
    st = Store(str(tmp_path / "cap.db"))
    toks = [st.sign_in("github:7", "seven") for _ in range(st.MAX_SESSIONS)]
    st.db.execute("update sessions set last_used = '2026-01-01T00:00:00+00:00'")
    st.db.execute("update sessions set last_used = '2026-02-01T00:00:00+00:00' where token_hash != ?",
                  (__import__("lantern_gateway.app", fromlist=["_hash"])._hash(toks[3]),))
    st.db.commit()
    newest = st.sign_in("github:7", "seven")
    assert st.user(toks[3]) is None                               # the one not used for longest is signed out
    assert all(st.user(t) for i, t in enumerate(toks) if i != 3) and st.user(newest)
    assert st.sign_out(newest) and st.user(newest) is None and st.user(toks[0])


def test_an_account_from_before_sessions_keeps_its_old_token(tmp_path):
    """Accounts signed in before this change have one token that is itself the counter row. Their next sign-in
    moves them over without signing that token out or resetting the count."""
    from lantern_gateway.app import Store, _hash
    st = Store(str(tmp_path / "old.db"))
    old = "lt_" + "o" * 43
    st.db.execute("insert into users (token_hash, label, created, used_requests, used_tokens, last_used) "
                  "values (?, 'octo', '2026-11-01', 12, 3400, '2026-11-01')", (_hash(old),))
    st.db.execute("insert into accounts (account, token_hash, label, created, last_signin, signins) "
                  "values ('github:1', ?, 'octo', '2026-11-01', '2026-11-01', 1)", (_hash(old),))
    st.db.commit()
    new = st.sign_in("github:1", "octo")
    assert st.user(old) and st.user(new) and st.user(old)["hash"] == st.user(new)["hash"] != _hash(old)
    assert st.user(new)["used_requests"] == 12 and st.user(new)["used_tokens"] == 3400
    assert st.identity(st.user(old)["hash"])["account"] == "github:1"
    third = st.sign_in("github:1", "octo")                       # a later sign-in reuses the same counter row
    assert st.user(third)["hash"] == st.user(old)["hash"]


def test_switching_off_an_account_signs_out_every_place(tmp_path):
    from lantern_gateway.app import Store
    st = Store(str(tmp_path / "off.db"))
    a, b = st.sign_in("github:9", "nine"), st.sign_in("github:9", "nine")
    st.db.execute("update users set disabled = 1 where token_hash = ?", (st.user(a)["hash"],))
    st.db.commit()
    assert st.user(a)["disabled"] and st.user(b)["disabled"]


def test_google_sign_in_never_stores_the_email(gw):
    r = _signin(gw, "google")
    assert r.status_code == 200 and "gmail" not in r.text
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert stats["accounts_google"] == 1 and stats["top_users"][0]["label"] == "google:…543210"
    row = gw.app.state.store.db.execute("select account, label from accounts").fetchone()
    assert row == ("google:9876543210", "google:…543210")


def test_bad_state_bad_code_and_unconfigured_provider(gw, tmp_path):
    r = gw.get("/v1/auth/github/callback", params={"code": "good", "state": "forged"})
    assert r.status_code == 400 and "expired" in r.text
    r = _signin(gw, "github", code="wrong")
    assert r.status_code == 502 and "did not confirm" in r.text
    assert gw.get("/v1/auth/claim", params={"cli": CLI}).status_code == 404
    assert gw.get("/v1/auth/claim", params={"cli": "x"}).status_code == 400
    bare = TestClient(create_app(Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k",
                                          db_path=str(tmp_path / "bare.db"))))
    assert bare.get("/v1/auth/github/start").status_code == 404
    assert bare.get("/v1/auth/providers").json()["providers"] == []
    assert "No sign-in method" in bare.get("/v1/login").text


def test_state_round_trip_and_expiry():
    st = auth.sign_state("s3cret", "github", CLI)
    assert auth.read_state("s3cret", st) == {"t": auth.read_state("s3cret", st)["t"], "p": "github", "c": CLI}
    assert auth.read_state("other", st) is None
    # Tamper with a byte in the middle of the signature (the last base64 character carries only a few bits, so
    # replacing it can decode to the same bytes once in a while).
    i = len(st) - 8
    assert auth.read_state("s3cret", st[:i] + ("A" if st[i] != "A" else "B") + st[i + 1:]) is None


def test_cli_login_polls_and_saves(gw, monkeypatch, tmp_path):
    """`lantern login --github` with the gateway's claim endpoint answered by this test app."""
    from lantern import providers
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", "https://gw.test/v1")
    seen = {"n": 0}

    def fake_claim(cli, url=None):
        seen["n"] += 1
        if seen["n"] < 2:
            return None
        return "lt_from_browser"
    monkeypatch.setattr(providers, "sign_in_claim", fake_claim)
    monkeypatch.setattr("time.sleep", lambda s: None)
    from lantern.cli import main
    assert main(["login", "--github", "--no-browser"]) == 0
    assert providers.load_token() == "lt_from_browser" and seen["n"] == 2


def test_many_new_accounts_in_a_day_are_paused_but_existing_ones_sign_in(tmp_path):
    """Abuse: one person making account after account to multiply the free allowance. New accounts past the day's cap
    get a 429 page with a sentence; an account that already exists signs in again as usual."""
    calls: list = []
    s = Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k", admin_secret=ADMIN,
                 db_path=str(tmp_path / "gw.db"), public_url="https://gw.test", github_client_id="gh-id",
                 github_client_secret="gh-secret", google_client_id="go-id", google_client_secret="go-secret",
                 signups_per_day=2)
    gw = TestClient(create_app(s, transport=providers_transport(calls)), follow_redirects=False)
    store = gw.app.state.store
    store.sign_in("github:1", "github:one", 2)
    store.sign_in("github:2", "github:two", 2)
    assert store.signups_today() == 2
    r = _signin(gw, "github")                       # a third, new account today (GitHub user 42)
    assert r.status_code == 429 and "try again tomorrow" in r.text and r.headers["retry-after"] == "86400"
    assert store.is_new_account("github:42") and store.signups_today() == 2
    tok = store.sign_in("github:1", "github:one", 2)   # existing account: never counted, keeps working
    assert tok.startswith("lt_")
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert stats["accounts_new_today"] == 2 and stats["accounts"] == 2
    s.signups_per_day = 0                           # 0 = no cap
    r = _signin(gw, "github")
    assert r.status_code == 200 and store.signups_today() == 3


def test_the_mark_and_word_lantern_link_home(monkeypatch):
    # Wakil clicked the logo on the "You're in" page and nothing happened: every gateway page's top bar is a link home.
    monkeypatch.delenv("LANTERN_HOME_URL", raising=False)
    for page in (auth.done_page("lt_x", "google:…abc", True), auth.login_page([], "", None), auth.error_page("x")):
        assert '<header><a class="home" href="https://lantern-cloud.fly.dev/"' in page
        assert "<span>Lantern</span></a></header>" in page
    monkeypatch.setenv("LANTERN_HOME_URL", "https://example.org/lantern/")
    assert 'href="https://example.org/lantern/"' in auth.error_page("x")
    for bad in ("javascript:alert(1)", "http://example.org/", 'https://x.org/"><script>'):
        monkeypatch.setenv("LANTERN_HOME_URL", bad)
        assert 'href="https://lantern-cloud.fly.dev/"' in auth.error_page("x")


def test_the_token_stays_off_screen_when_lantern_picks_it_up():
    # A token shown on the page ends up in screenshots; the app/terminal that opened the tab collects it by itself.
    parked = auth.done_page("lt_secretvalue123", "google:…abc", True)
    assert "lt_secretvalue123" not in parked and "lt_se" not in parked and "<details" not in parked
    assert "lt_secretvalue123" in auth.done_page("lt_secretvalue123", "google:…abc", False)
