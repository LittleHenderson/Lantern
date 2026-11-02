"""Sign in with GitHub / Google: signed state, server-side exchange, one token per account, parked tokens."""

import json
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
    assert r.status_code == 200 and "lt_" in r.text and "octocat" in r.text and "secret@example.com" not in r.text
    tok = gw.get("/v1/auth/claim", params={"cli": CLI}).json()["token"]
    assert tok.startswith("lt_") and tok in r.text
    assert gw.get("/v1/auth/claim", params={"cli": CLI}).status_code == 404      # one claim only
    a = gw.get("/v1/allowance", headers={"authorization": f"Bearer {tok}"}).json()
    assert a["used_requests"] == 0 and a["remaining_requests"] == 300
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert stats["accounts"] == 1 and stats["accounts_github"] == 1
    assert stats["top_users"][0]["label"] == "github:octocat"


def test_signing_in_again_rotates_the_token_and_keeps_the_counters(gw):
    _signin(gw, "github")
    tok1 = gw.get("/v1/auth/claim", params={"cli": CLI}).json()["token"]
    store = gw.app.state.store
    store.record(store.user(tok1)["hash"], "2026-11-02", 1000, 0.01, "m")
    cli2 = "d" * 40
    _signin(gw, "github", cli=cli2)
    tok2 = gw.get("/v1/auth/claim", params={"cli": cli2}).json()["token"]
    assert tok2 != tok1
    assert gw.get("/v1/allowance", headers={"authorization": f"Bearer {tok1}"}).status_code == 401    # old one stops
    a = gw.get("/v1/allowance", headers={"authorization": f"Bearer {tok2}"}).json()
    assert a["used_requests"] == 1 and a["used_tokens"] == 1000                                         # carried over
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert stats["accounts"] == 1                                                                       # still one account


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
    assert auth.read_state("s3cret", st[:-2] + "zz") is None


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
