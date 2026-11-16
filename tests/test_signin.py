"""Sign in with GitHub / Google: signed state, server-side exchange, one token per account, parked tokens."""

import base64
import hashlib
import html
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
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
    # https, as the gateway is reached: a browser keeps the cookie of a started sign-in only for an https address
    client = TestClient(create_app(s, transport=providers_transport(calls)), follow_redirects=False,
                        base_url="https://gw.test")
    client.calls = calls
    client.s = s
    return client


def _signin(gw, provider, cli=CLI, code="good"):
    """A sign-in no app collects (and what an app from before 0.2.7 starts): it ends on the page with the Copy button."""
    r = gw.get(f"/v1/auth/{provider}/start", params={"cli": cli})
    assert r.status_code == 302
    loc = r.headers["location"]
    state = dict(x.split("=", 1) for x in loc.split("?", 1)[1].split("&"))["state"]
    assert "client_secret" not in loc
    return gw.get(f"/v1/auth/{provider}/callback", params={"code": code, "state": state})


RETURN = "http://127.0.0.1:8765/api/login/return"
NONCE = "n" * 24


def _pair():
    """What an app makes before it starts a sign-in: a secret it keeps to itself, and the fingerprint of that
    secret, which is all it shows (the test works both out by itself, so it also says what the gateway must do)."""
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def _browser(gw):
    """One more browser on the same gateway: its own cookies, and nothing of anyone else's."""
    return TestClient(gw.app, follow_redirects=False, base_url=str(gw.base_url))


def _state(location: str) -> str:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))["state"]


def _handed(location: str) -> dict:
    """What the gateway sends the finishing browser back with."""
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))


def _sign_in(gw, provider="github", code="good"):
    """One whole sign-in the way an app does it: (its token or None, the answer that decided it)."""
    verifier, challenge = _pair()
    r = gw.get(f"/v1/auth/{provider}/start", params={"challenge": challenge, "return": RETURN, "nonce": NONCE})
    assert r.status_code == 302 and "client_secret" not in r.headers["location"]
    r = gw.get(f"/v1/auth/{provider}/callback", params={"code": code, "state": _state(r.headers["location"])})
    if r.status_code != 303:
        return None, r
    got = gw.post("/v1/auth/redeem", json={"code": _handed(r.headers["location"])["code"], "verifier": verifier})
    return (got.json()["token"], r) if got.status_code == 200 else (None, got)


def test_providers_and_login_page(gw):
    assert gw.get("/v1/auth/providers").json() == {"providers": ["github", "google"], "login_url": "https://gw.test/v1/login"}
    page = gw.get("/v1/login", params={"cli": CLI})
    assert page.status_code == 200 and "Sign in with GitHub" in page.text and "Sign in with Google" in page.text
    assert f"cli={CLI}" in page.text and "Content-Security-Policy" in page.headers
    assert "cli=" not in gw.get("/v1/login", params={"cli": "short!"}).text        # a malformed cli code is dropped
    # what an app says today rides along to the start, written so that the page cannot be broken out of
    _, challenge = _pair()
    page = gw.get("/v1/login", params={"challenge": challenge, "return": RETURN, "nonce": NONCE, "cli": CLI})
    assert (f"/v1/auth/github/start?x=1&amp;challenge={challenge}&amp;return=http%3A%2F%2F127.0.0.1%3A8765%2Fapi%2Flogin"
            f"%2Freturn&amp;nonce={NONCE}\"") in page.text and "cli=" not in page.text


def test_github_sign_in_issues_one_token_to_the_app_that_started_it(gw):
    tok, r = _sign_in(gw, "github")
    # the app collects it; the gateway shows no page of its own and the token is in nothing the browser was sent
    assert tok.startswith("lt_") and r.status_code == 303 and tok not in r.text and tok not in r.headers["location"]
    assert "octocat" not in r.headers["location"] and "secret@example.com" not in r.text
    a = gw.get("/v1/allowance", headers={"authorization": f"Bearer {tok}"}).json()
    assert a["used_requests"] == 0 and a["remaining_requests"] == 300
    stats = gw.get("/v1/admin/stats", headers={"authorization": f"Bearer {ADMIN}"}).json()["allowance"]
    assert stats["accounts"] == 1 and stats["accounts_github"] == 1
    assert stats["top_users"][0]["label"] == "github:octocat"


def test_signing_in_again_keeps_the_other_sign_ins_and_shares_one_allowance(gw):
    """Signing in on a second place (the website after the app, a phone after a laptop) must not sign the first
    one out, and must not give a second allowance: both tokens count against one row."""
    tok1, _ = _sign_in(gw, "github")
    store = gw.app.state.store
    store.record(store.user(tok1)["hash"], "2026-11-02", 1000, 0.01, "m")
    tok2, _ = _sign_in(gw, "github")
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
    tok, r = _sign_in(gw, "github", code="wrong")
    assert tok is None and r.status_code == 502 and "location" not in r.headers
    assert gw.app.state.store.db.execute("select count(*) from handover").fetchone()[0] == 0
    bare = TestClient(create_app(Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k",
                                          db_path=str(tmp_path / "bare.db"))))
    assert bare.get("/v1/auth/github/start").status_code == 404
    assert bare.get("/v1/auth/providers").json()["providers"] == []
    assert "No sign-in method" in bare.get("/v1/login").text


def test_state_round_trip_and_expiry():
    hand = {"challenge": "h" * 43, "return": RETURN, "nonce": NONCE}
    st = auth.sign_state("s3cret", "github", browser="b" * 32, hand=hand)
    read = auth.read_state("s3cret", st)
    assert read == {"t": read["t"], "p": "github", "n": read["n"], "b": "b" * 32, "h": "h" * 43, "r": RETURN, "s": NONCE}
    assert len(read["n"]) >= 12 and auth.sign_state("s3cret", "github", hand=hand) != st     # no two links are the same text
    # an app from before 0.2.7 is only marked as one: the code it chose is in no link
    assert auth.read_state("s3cret", auth.sign_state("s3cret", "github", old=True)).get("o") == 1
    state, name, mine = auth.begin("s3cret", "github")
    read = auth.read_state("s3cret", state)
    assert set(read) == {"t", "p", "n", "b"} and name == auth.COOKIE + read["n"] and len(mine) >= 43
    assert auth.same_browser(read, {name: mine}) and not auth.same_browser(read, {name: mine + "x"})
    assert not auth.same_browser(read, {}) and not auth.same_browser({**read, "b": ""}, {name: ""})
    assert auth.read_state("other", st) is None
    # Tamper with a byte in the middle of the signature (the last base64 character carries only a few bits, so
    # replacing it can decode to the same bytes once in a while).
    i = len(st) - 8
    assert auth.read_state("s3cret", st[:i] + ("A" if st[i] != "A" else "B") + st[i + 1:]) is None


def test_many_new_accounts_in_a_day_are_paused_but_existing_ones_sign_in(tmp_path):
    """Abuse: one person making account after account to multiply the free allowance. New accounts past the day's cap
    get a 429 page with a sentence; an account that already exists signs in again as usual."""
    calls: list = []
    s = Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k", admin_secret=ADMIN,
                 db_path=str(tmp_path / "gw.db"), public_url="https://gw.test", github_client_id="gh-id",
                 github_client_secret="gh-secret", google_client_id="go-id", google_client_secret="go-secret",
                 signups_per_day=2)
    gw = TestClient(create_app(s, transport=providers_transport(calls)), follow_redirects=False, base_url="https://gw.test")
    store = gw.app.state.store
    store.sign_in("github:1", "github:one", 2)
    store.sign_in("github:2", "github:two", 2)
    assert store.signups_today() == 2
    r = _signin(gw, "github")                       # a third, new account today (GitHub user 42)
    assert r.status_code == 429 and "try again tomorrow" in r.text and r.headers["retry-after"] == "86400"
    assert store.is_new_account("github:42") and store.signups_today() == 2
    # the same when an app collects the sign-in: the person reads it on the gateway's page, and nothing waits for the app
    tok, r = _sign_in(gw, "github")
    assert tok is None and r.status_code == 429 and "try again tomorrow" in r.text and "location" not in r.headers
    assert store.db.execute("select count(*) from handover").fetchone()[0] == 0 and store.signups_today() == 2
    # the cap fell between the sign-in and the collecting: the app is told, and still no account is made
    s.signups_per_day = 0
    verifier, challenge = _pair()
    r = gw.get("/v1/auth/github/start", params={"challenge": challenge, "return": RETURN, "nonce": NONCE})
    r = gw.get("/v1/auth/github/callback", params={"code": "good", "state": _state(r.headers["location"])})
    s.signups_per_day = 2
    r = gw.post("/v1/auth/redeem", json={"code": _handed(r.headers["location"])["code"], "verifier": verifier})
    assert r.status_code == 429 and "try again tomorrow" in r.json()["detail"] and r.headers["retry-after"] == "86400"
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
    for page in (auth.done_page("lt_x", "google:…abc", True), auth.login_page([]), auth.error_page("x")):
        assert '<header><a class="home" href="https://lantern-cloud.fly.dev/"' in page
        assert '<span>Lantern</span></a><a class="guide" href="https://lantern-cloud.fly.dev/guide"' in page
    monkeypatch.setenv("LANTERN_HOME_URL", "https://example.org/lantern/")
    assert 'href="https://example.org/lantern/"' in auth.error_page("x")
    assert 'href="https://example.org/lantern/guide"' in auth.error_page("x")   # How to use Lantern goes there too
    for bad in ("javascript:alert(1)", "http://example.org/", 'https://x.org/"><script>'):
        monkeypatch.setenv("LANTERN_HOME_URL", bad)
        assert 'href="https://lantern-cloud.fly.dev/"' in auth.error_page("x")


def test_the_token_is_in_no_page_when_lantern_picks_it_up(gw):
    # A token shown on a page ends up in screenshots. The app, terminal or website that started the sign-in collects it
    # by itself: the gateway shows no page then, and what it sends the browser holds no token and no account name.
    tok, r = _sign_in(gw, "github")
    for text in (r.text, r.headers["location"], r.headers.get("set-cookie", "")):
        assert tok not in text and "lt_" not in text and "octocat" not in text
    # the page of a sign-in nobody collects says one thing more to a person whose older app is still waiting
    assert "older than this sign-in page" in auth.done_page("lt_secretvalue123", "google:…abc", old=True)
    assert "older than" not in auth.done_page("lt_secretvalue123", "google:…abc")


def test_sign_out_one_place_or_everywhere(gw):
    store = gw.app.state.store
    a, b, c = (store.sign_in("github:11", "eleven") for _ in range(3))
    store.record(store.user(a)["hash"], "2026-11-02", 7, 0.01, "m")
    h = lambda t: {"authorization": f"Bearer {t}"}   # noqa: E731
    assert gw.post("/v1/auth/signout", headers=h(a)).json() == {"signed_out": 1}          # just this place
    assert store.user(a) is None and store.user(b) and store.user(c)
    assert gw.post("/v1/auth/signout", headers=h(a), json={"everywhere": True}).status_code == 401   # needs a live token
    assert gw.post("/v1/auth/signout", headers=h(b), json={"everywhere": True}).json() == {"signed_out": 2}
    assert store.user(b) is None and store.user(c) is None
    d = store.sign_in("github:11", "eleven")                       # signing in again carries on from the counts
    assert store.user(d)["used_requests"] == 1 and not store.user(d)["disabled"]
    assert store.db.execute("select count(*) from sessions").fetchone()[0] == 1   # no leftover rows


def test_sign_out_everywhere_for_an_account_from_before_sessions(tmp_path):
    from lantern_gateway.app import Store, _hash
    st = Store(str(tmp_path / "o.db"))
    old = "lt_" + "p" * 43
    st.db.execute("insert into users (token_hash, label, created, used_requests, last_used) values (?, 'x', '2026-11-01', 4, '2026-11-01')", (_hash(old),))
    st.db.execute("insert into accounts (account, token_hash, label, created, last_signin, signins) values ('github:3', ?, 'x', '2026-11-01', '2026-11-01', 1)", (_hash(old),))
    st.db.commit()
    assert st.sign_out(old, everywhere=True) == 1 and st.user(old)["disabled"]
    new = st.sign_in("github:3", "x")
    assert st.user(new)["used_requests"] == 4 and st.user(old)["disabled"]


def test_a_token_nobody_collects_sits_behind_a_copy_button():
    # Wakil (2026-11-09): the page printed the whole token; show only a Lantern button that says to press it.
    page = auth.done_page("lt_secretvalue123", "github:wakil", False)
    assert 'id="copy"' in page and "Copy my Lantern token" in page and auth.MARK in page
    assert '<input type="hidden" id="tok" value="lt_secretvalue123">' in page
    # printed only inside the copy-failed box (hidden until then) and for browsers with scripts off
    assert page.count('<pre class="tok">') == 2
    assert '<div id="fb" hidden><pre class="tok">' in page and '<noscript><pre class="tok">' in page
    assert "shown once" not in page
    assert f"<script>{auth.COPY_JS}</script>" in page
    # a planted token value cannot break out of the attribute
    assert '"><script>' not in auth.done_page('lt_"><script>x', "github:a", False)


def test_the_copy_script_is_allowed_by_hash_only(gw):
    import base64
    import hashlib
    want = base64.b64encode(hashlib.sha256(auth.COPY_JS.encode()).digest()).decode()
    assert auth.COPY_JS_HASH == f"'sha256-{want}'"
    csp = gw.get("/v1/login").headers["content-security-policy"]
    assert f"script-src {auth.COPY_JS_HASH};" in csp and "unsafe-inline' https://fonts" in csp
    assert "script-src 'unsafe-inline'" not in csp


# ---- A sign-in is handed only to the one who started it, through the browser that finished it ----


def _asks(client, verifier: str, codes=(CLI, "", "x" * 43)) -> list:
    """Everything a person can ask the gateway for with what they chose themselves: the pick-up by a code of their
    own, and the hand-over without the one-time code that only the finishing browser was given."""
    return [client.get("/v1/auth/claim", params={"cli": CLI})] + [
        client.post("/v1/auth/redeem", json={"code": c, "verifier": verifier}) for c in codes]


def _sessions(gw) -> int:
    return gw.app.state.store.db.execute("select count(*) from sessions").fetchone()[0]


def test_a_sign_in_another_person_finishes_is_never_handed_to_the_one_who_started_it(gw):
    """Two people. The first starts a sign-in with a code and a secret of their own choosing and gets the second to
    finish it (a link in a message is enough). Whatever the first one holds afterwards must fetch nothing."""
    first, second = _browser(gw), _browser(gw)
    verifier, challenge = _pair()
    start = {"cli": CLI, "challenge": challenge, "return": RETURN, "nonce": NONCE}
    r = first.get("/v1/auth/github/start", params=start)
    assert r.status_code == 302
    link = r.headers["location"]                       # the provider's page, as the first person would pass it on

    # 1. The second person opens the provider's link. Their browser never started a sign-in here.
    r = second.get("/v1/auth/github/callback", params={"code": "good", "state": _state(link)})
    got = [a for a in _asks(first, verifier) if a.status_code == 200 or "lt_" in a.text]
    assert not got, "the one who started the sign-in collected the other person's token"
    assert r.status_code == 400 and "lt_" not in r.text and "not started in this browser" in r.text
    assert _sessions(gw) == 0                          # nobody was signed in, and the provider was not even asked
    assert not [c for c in gw.calls if "github.com" in c[1]]

    # 2. The second person opens the first one's start link itself, so their own browser did start it. They are
    #    sent back to an address on their own computer with a one-time code: it never passes the first person.
    r = second.get("/v1/auth/github/start", params=start)
    r = second.get("/v1/auth/github/callback", params={"code": "good", "state": _state(r.headers["location"])})
    got = [a for a in _asks(first, verifier) if a.status_code == 200 or "lt_" in a.text]
    assert not got, "the one who started the sign-in collected the other person's token"
    assert r.status_code == 303 and r.headers["location"].startswith(RETURN + "?")
    assert "lt_" not in r.text and "lt_" not in r.headers["location"]
    # no token exists for a sign-in nobody has proved to be theirs
    assert _sessions(gw) == 0


def test_the_app_that_started_a_sign_in_collects_it_once(gw):
    """The twin: the same steps by one person in one browser end with that person's token, exactly once."""
    verifier, challenge = _pair()
    r = gw.get("/v1/auth/github/start", params={"challenge": challenge, "return": RETURN, "nonce": NONCE})
    assert r.status_code == 302
    r = gw.get("/v1/auth/github/callback", params={"code": "good", "state": _state(r.headers["location"])})
    assert r.status_code == 303 and r.headers["location"].split("?")[0] == RETURN
    assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"
    handed = _handed(r.headers["location"])
    assert set(handed) == {"code", "state"} and handed["state"] == NONCE and len(handed["code"]) >= 43
    assert _sessions(gw) == 0
    r = gw.post("/v1/auth/redeem", json={"code": handed["code"], "verifier": verifier})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    token = r.json()["token"]
    assert token.startswith("lt_") and r.json()["limits"]["requests"] == gw.s.free_requests
    assert gw.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"}).json()["account"] == "github:42"
    assert _sessions(gw) == 1
    # once: the same code and secret a second time get nothing, and no second token is made
    r = gw.post("/v1/auth/redeem", json={"code": handed["code"], "verifier": verifier})
    assert r.status_code == 400 and "lt_" not in r.text and _sessions(gw) == 1
    # the gateway keeps neither the code nor a token while a sign-in waits: hashes and the account's name only
    kept = b"".join(f.read_bytes() for f in Path(gw.s.db_path).parent.glob("gw.db*"))
    assert handed["code"].encode() not in kept and token.encode() not in kept and b"github:42" in kept


def test_a_wrong_secret_ends_the_sign_in_and_a_late_one_gets_nothing(gw, monkeypatch):
    def finished():
        verifier, challenge = _pair()
        r = gw.get("/v1/auth/github/start", params={"challenge": challenge, "return": RETURN, "nonce": NONCE})
        r = gw.get("/v1/auth/github/callback", params={"code": "good", "state": _state(r.headers["location"])})
        return verifier, _handed(r.headers["location"])["code"]

    verifier, code = finished()
    other, _ = _pair()
    assert gw.post("/v1/auth/redeem", json={"code": code, "verifier": other}).status_code == 400
    # the code was used up by the wrong try: the right secret comes too late
    assert gw.post("/v1/auth/redeem", json={"code": code, "verifier": verifier}).status_code == 400
    assert _sessions(gw) == 0
    # a code waits two minutes, not ten: it sits in an address bar meanwhile
    verifier, code = finished()
    real = time.time()
    monkeypatch.setattr(time, "time", lambda: real + auth.REDEEM_TTL + 1)
    assert gw.post("/v1/auth/redeem", json={"code": code, "verifier": verifier}).status_code == 400
    monkeypatch.setattr(time, "time", lambda: real)
    assert auth.REDEEM_TTL <= 120 and _sessions(gw) == 0
    for body in ({}, {"code": code}, {"verifier": verifier}, {"code": 5, "verifier": []}, {"code": "a" * 200, "verifier": "b"}):
        assert gw.post("/v1/auth/redeem", json=body).status_code == 400
    assert gw.post("/v1/auth/redeem", json={"code": "a" * 5000, "verifier": verifier}).status_code == 413
    assert gw.post("/v1/auth/redeem", content=b"[1]", headers={"content-type": "application/json"}).status_code == 400


def test_the_pick_up_by_a_code_of_the_callers_choosing_is_gone(gw):
    """An app from before still asks; it is told to wait as it always was when nothing was there, and the answer
    says in words that nothing will come. No token is ever kept for a code a caller chose."""
    r = _signin(gw, "github")                         # an app from before: only its own `cli` code
    assert r.status_code == 200 and "Copy my Lantern token" in r.text      # the person carries it over by hand
    assert "older" in r.text and "update" in r.text.lower()
    r = gw.get("/v1/auth/claim", params={"cli": CLI})
    assert r.status_code == 404 and r.json()["pending"] is True and r.json()["ended"] is True
    assert "Copy" in r.json()["detail"] and "lt_" not in r.text
    db = gw.app.state.store.db
    assert db.execute("select count(*) from handover").fetchone()[0] == 0
    assert not db.execute("select 1 from sqlite_master where name = 'pending'").fetchone()


RETURNS = [
    ("http://127.0.0.1:8765/api/login/return", True),
    ("http://127.0.0.1:49152/", True),
    ("http://[::1]:8765/signin", True),
    ("https://lantern-cloud.fly.dev/v1/signin/return", True),          # the website this gateway serves
    ("https://www.example.test/v1/signin/return", True),               # one more, named in the gateway's settings
    ("http://localhost:8765/api/login/return", False),                 # a name: a hosts file can point it elsewhere
    ("http://127.0.0.1/api/login/return", False),                      # no port
    ("http://127.0.0.1:80/api/login/return", False),                   # a port only the system's own services open
    ("http://127.0.0.1:99999/x", False),
    ("http://127.0.0.1:8765/a?b=c", False),
    ("http://127.0.0.1:8765/a#b", False),
    ("http://127.0.0.1:8765/a b", False),
    ("http://127.0.0.1:8765/../a", False),
    ("http://someone@127.0.0.1:8765/a", False),
    ("http://127.0.0.1.elsewhere.test:8765/a", False),
    ("http://127.0.0.2:8765/a", False),
    ("http://192.168.1.5:8765/a", False),
    ("http://0.0.0.0:8765/a", False),
    ("https://127.0.0.1:8765/a", False),
    ("https://elsewhere.test/v1/signin/return", False),
    ("https://lantern-cloud.fly.dev.elsewhere.test/v1/signin/return", False),
    ("https://lantern-cloud.fly.dev:8443/v1/signin/return", False),
    ("https://lantern-cloud.fly.dev@elsewhere.test/x", False),
    ("http://lantern-cloud.fly.dev/v1/signin/return", False),          # the website, but not over https
    ("https://LANTERN-cloud.fly.dev/v1/signin/return", False),
    ("//elsewhere.test/x", False),
    ("/v1/login", False),
    ("javascript:void(0)", False),
    ("file:///etc/hosts", False),
    ("", False),
    ("http://127.0.0.1:8765/" + "a" * 300, False),
]


@pytest.mark.parametrize("address, allowed", RETURNS)
def test_a_sign_in_is_sent_back_only_to_this_computer_or_to_a_website_the_gateway_names(gw, monkeypatch, address, allowed):
    monkeypatch.delenv("LANTERN_HOME_URL", raising=False)
    gw.s.return_origins = "https://www.example.test"
    _, challenge = _pair()
    assert auth.valid_return(address, auth.return_origins(gw.s.return_origins)) == (address if allowed else "")
    r = gw.get("/v1/auth/github/start", params={"challenge": challenge, "return": address, "nonce": NONCE})
    assert r.status_code == (302 if allowed else 400)
    if not allowed:
        assert "state=" not in r.headers.get("location", "") and "set-cookie" not in r.headers
    # the page with the buttons hands on only what the start would take, and nothing of it as page text
    page = gw.get("/v1/login", params={"challenge": challenge, "return": address, "nonce": NONCE})
    assert page.status_code == (200 if allowed else 400) and "<script" not in page.text
    assert ("pick the sign-in up by itself" in page.text) == allowed and ("return=" in page.text) == allowed


@pytest.mark.parametrize("params", [
    {"challenge": "short", "return": RETURN, "nonce": NONCE},
    {"challenge": "a" * 43 + "=", "return": RETURN, "nonce": NONCE},
    {"challenge": "a" * 44, "return": RETURN, "nonce": NONCE},
    {"challenge": "a" * 43, "return": RETURN},                          # no nonce
    {"challenge": "a" * 43, "return": RETURN, "nonce": "short"},
    {"challenge": "a" * 43, "return": RETURN, "nonce": "n" * 23 + "&"},
    {"challenge": "a" * 43, "nonce": NONCE},                            # a fingerprint with nowhere to send the code
    {"return": RETURN, "nonce": NONCE},                                 # somewhere to send it and no fingerprint
])
def test_a_start_that_is_half_a_hand_over_is_refused_not_guessed(gw, params):
    r = gw.get("/v1/auth/github/start", params=params)
    assert r.status_code == 400 and "location" not in r.headers


def test_a_sign_in_is_finished_only_in_the_browser_that_started_it(gw):
    """Start and finish are tied by a cookie only that browser holds; the link alone is not enough, also for the
    sign-in that ends on the page with the Copy button."""
    r = gw.get("/v1/auth/github/start")
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Secure" in cookie and "Max-Age=600" in cookie
    assert "Path=/v1/auth" in cookie
    state = _state(r.headers["location"])
    other = _browser(gw)
    r = other.get("/v1/auth/github/callback", params={"code": "good", "state": state})
    assert r.status_code == 400 and "not started in this browser" in r.text and "lt_" not in r.text
    assert _sessions(gw) == 0 and not [c for c in gw.calls if "github.com" in c[1]]
    # a cookie of the right name with another value is not it either
    name = cookie.split("=", 1)[0]
    other.cookies.set(name, "v" * 43)
    r = other.get("/v1/auth/github/callback", params={"code": "good", "state": state})
    assert r.status_code == 400 and _sessions(gw) == 0
    # the wrong browser's tries did not use the link up: the right one still finishes, and its cookie is taken away
    r = gw.get("/v1/auth/github/callback", params={"code": "good", "state": state})
    assert r.status_code == 200 and "Copy my Lantern token" in r.text and _sessions(gw) == 1
    assert name + '=""' in r.headers["set-cookie"] or name + "=;" in r.headers["set-cookie"]
    # two sign-ins started in one browser do not undo each other
    a = gw.get("/v1/auth/github/start").headers["location"]
    b = gw.get("/v1/auth/google/start").headers["location"]
    assert gw.get("/v1/auth/github/callback", params={"code": "good", "state": _state(a)}).status_code == 200
    assert gw.get("/v1/auth/google/callback", params={"code": "good", "state": _state(b)}).status_code == 200


# ---- The terminal and the app on a person's computer: a real gateway on this computer, a stand-in for the browser ----

@pytest.fixture
def live(tmp_path):
    """A gateway that listens on this computer (GitHub and Google are stand-ins inside it): its `/v1` address."""
    uvicorn = pytest.importorskip("uvicorn")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    s = Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k", admin_secret=ADMIN,
                 db_path=str(tmp_path / "live.db"), public_url=f"http://127.0.0.1:{port}", github_client_id="gh-id",
                 github_client_secret="gh-secret", google_client_id="go-id", google_client_secret="go-secret")
    server = uvicorn.Server(uvicorn.Config(create_app(s, transport=providers_transport([])), host="127.0.0.1", port=port,
                                           log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/v1"
    server.should_exit = True
    th.join(timeout=5)


def _a_person_signs_in(browser, link: str, provider: str = "github"):
    """What a person's browser does with the link of a sign-in page: the page, its button, the provider (a stand-in:
    the browser is handed straight back), and the gateway's answer, which says where the browser goes next."""
    page = browser.get(link)
    assert page.status_code == 200, page.text[-300:]
    href = html.unescape(re.search(rf'href="(/v1/auth/{provider}/start[^"]*)"', page.text).group(1))
    r = browser.get(urllib.parse.urljoin(link, href))
    assert r.status_code == 302
    return browser.get(urllib.parse.urljoin(link, f"/v1/auth/{provider}/callback"),
                       params={"code": "good", "state": _state(r.headers["location"])})


def test_the_terminal_signs_in_through_the_browser_that_comes_back_to_it(live, monkeypatch, tmp_path, capsys):
    """`lantern login --github`, the whole way: the command listens on this computer, the browser is sent back to it
    with a one-time code, and the command collects the token with the secret it kept."""
    from lantern import providers
    from lantern.cli import main
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", live)
    seen: dict = {}

    def opened(link):                                  # in place of the person's browser
        def go():
            try:
                with httpx.Client() as browser:
                    back = _a_person_signs_in(browser, link).headers["location"]
                    # first somebody else on this computer asks the listener, with a code and a mark of their own
                    seen["other"] = httpx.get(back.split("?")[0], params={"code": "x" * 43, "state": "y" * 32})
                    seen["named"] = httpx.get(back, headers={"Host": "localhost:1"})       # under another name
                    seen["page"] = browser.get(back)
            except Exception as e:  # noqa: BLE001
                seen["error"] = repr(e)
        threading.Thread(target=go, daemon=True).start()
        return True
    monkeypatch.setattr("webbrowser.open", opened)
    assert main(["login", "--github"]) == 0, seen
    tok = providers.load_token()
    assert tok.startswith("lt_") and "error" not in seen, seen
    assert seen["page"].status_code == 200 and "You're signed in" in seen["page"].text
    assert seen["page"].headers["content-security-policy"] == "default-src 'none'; style-src 'unsafe-inline'"
    for wrong in (seen["other"], seen["named"]):
        assert wrong.status_code == 400 and "not started from this Lantern" in wrong.text
    out = capsys.readouterr().out
    assert tok not in out and "challenge=" in out and "/login?provider=github\n" in out and "verifier" not in out
    assert httpx.get(live + "/whoami", headers={"Authorization": f"Bearer {tok}"}).json()["account"] == "github:42"


def test_the_terminal_says_so_when_nobody_finishes_the_sign_in(live, monkeypatch, tmp_path, capsys):
    from lantern import providers
    from lantern.cli import main
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", live)
    real = providers.sign_in_here
    monkeypatch.setattr(providers, "sign_in_here", lambda provider, show: real(provider, show, seconds=0))
    assert main(["login", "--github", "--no-browser"]) == 2
    said = capsys.readouterr()
    assert "timed out" in said.err and "lantern login --token" in said.err and providers.load_token() is None
    # the gateway's own words reach the person when it has nothing to give
    with pytest.raises(providers.ProviderError, match="already collected, took too long, or was not started by this app"):
        providers.sign_in_redeem("c" * 43, "v" * 64, live)


@pytest.fixture
def app_here(tmp_path, monkeypatch, live):
    """The app of `lantern serve` on this computer, with the gateway above: (its address, its port)."""
    from http.server import ThreadingHTTPServer

    from lantern.server import App, Handler, Store
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", live)
    store = Store(tmp_path / "home")
    store.root.mkdir()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    before = getattr(Handler, "app", None)
    Handler.app = App(store, "tok-123", port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", port
    httpd.shutdown()
    httpd.server_close()
    Handler.app = before


def _app_asks(app: str, path: str, **body):
    if body:
        return httpx.post(app + path, json=body, headers={"X-Lantern-Token": "tok-123"})
    return httpx.get(app + path, cookies={"lantern_token": "tok-123"})


def test_the_app_signs_in_when_the_browser_comes_back_to_it(app_here, live):
    from lantern import providers
    app, port = app_here
    st = _app_asks(app, "/api/login/start", provider="github").json()
    assert set(st) == {"url", "id", "provider"} and len(st["id"]) >= 24      # the secret stays in the app, not the page
    assert f"return=http%3A%2F%2F127.0.0.1%3A{port}%2Fapi%2Flogin%2Freturn&nonce={st['id']}" in st["url"]
    assert _app_asks(app, f"/api/login/poll?id={st['id']}").json() == {"done": False}
    with httpx.Client() as browser:
        back = _a_person_signs_in(browser, st["url"]).headers["location"]
        assert back.startswith(f"http://127.0.0.1:{port}/api/login/return?code=")
        page = browser.get(back)                   # the tab came from the gateway: it holds no session of the app
    assert page.status_code == 200 and "You're signed in" in page.text and "tok-123" not in page.text
    assert page.headers["content-security-policy"] == "default-src 'none'; style-src 'unsafe-inline'"
    assert _app_asks(app, f"/api/login/poll?id={st['id']}").json() == {"done": True}
    tok = providers.load_token()
    assert tok.startswith("lt_") and tok not in page.text
    assert httpx.get(live + "/whoami", headers={"Authorization": f"Bearer {tok}"}).json()["account"] == "github:42"
    # the same address a second time, and an address with no code, sign nobody in
    assert httpx.get(back).status_code == 400 and httpx.get(back.split("?")[0]).status_code == 400
    assert _app_asks(app, "/api/login/poll?id=" + "z" * 32).json()["done"] is False


def test_a_sign_in_somebody_else_started_and_pointed_at_this_app_signs_nobody_in(app_here, live):
    """Two people again, at the app. The first makes a sign-in of their own, with a secret of their own, and points
    its way back at the address of the second person's Lantern. The second person signs in through that link. Their
    app takes nothing it did not start, and uses the code up, so that it is worth nothing to the first person even
    if they are read the address bar."""
    from lantern import providers
    app, port = app_here
    verifier, challenge = _pair()
    link = f"{live}/login?" + urllib.parse.urlencode({
        "provider": "github", "challenge": challenge, "return": f"http://127.0.0.1:{port}/api/login/return", "nonce": "m" * 24})
    with httpx.Client() as browser:
        back = _a_person_signs_in(browser, link).headers["location"]
        page = browser.get(back)
    assert page.status_code == 400 and "not started from this Lantern" in page.text
    assert providers.load_token() is None
    got = httpx.post(live + "/auth/redeem", json={"code": _handed(back)["code"], "verifier": verifier})
    assert got.status_code == 400 and "lt_" not in got.text
    # the app's own sign-in, started meanwhile, is not disturbed by it
    st = _app_asks(app, "/api/login/start", provider="github").json()
    assert httpx.get(f"{app}/api/login/return", params={"code": "c" * 43, "state": "m" * 24}).status_code == 400
    with httpx.Client() as browser:
        assert browser.get(_a_person_signs_in(browser, st["url"]).headers["location"]).status_code == 200
    assert providers.load_token().startswith("lt_")


def test_an_app_that_does_not_listen_on_this_computers_own_address_asks_for_a_paste(tmp_path, monkeypatch):
    from lantern.server import App, Store
    monkeypatch.setenv("LANTERN_GATEWAY_URL", "http://127.0.0.1:9/v1")
    store = Store(tmp_path / "home")
    st = App(store, "t", 8765, own_address="").sign_in_begin("google")
    assert st == {"url": "http://127.0.0.1:9/v1/login?provider=google", "id": "", "provider": "google"}
    st = App(store, "t", 8765, own_address="[::1]").sign_in_begin("google")
    assert "return=http%3A%2F%2F%5B%3A%3A1%5D%3A8765%2Fapi%2Flogin%2Freturn" in st["url"] and st["id"]
    # a browser that reached the app under another name is on another computer: the gateway cannot send it back here
    assert App(store, "t", 8765).sign_in_begin("google", here=False)["id"] == ""


def test_this_computers_own_address_is_worked_out_from_where_the_app_listens():
    from lantern.server import own_address
    every = ".".join(["0"] * 4)                               # every address of this computer, IPv4
    assert [own_address(x) for x in ("127.0.0.1", every, "::1", "::")] == ["127.0.0.1", "127.0.0.1", "[::1]", "[::1]"]
    assert [own_address(x) for x in ("192.168.1.5", "127.0.0.2", "fe80::1", "my-laptop", "")] == [""] * 5


def test_the_app_offers_the_hand_over_only_to_a_browser_on_this_computer(app_here, monkeypatch):
    app, port = app_here
    monkeypatch.setenv("LANTERN_ALLOWED_HOST", f"laptop.lan:{port}")
    far = httpx.post(app + "/api/login/start", json={"provider": "github"},
                     headers={"X-Lantern-Token": "tok-123", "Host": f"laptop.lan:{port}"}).json()
    assert far["id"] == "" and "challenge=" not in far["url"] and far["url"].endswith("/login?provider=github")
    near = _app_asks(app, "/api/login/start", provider="github").json()
    assert near["id"] and "challenge=" in near["url"]


def test_the_address_a_sign_in_is_sent_to_is_written_out_from_its_checked_parts():
    own = auth.return_origins("https://lantern.example")
    assert auth.valid_return("http://127.0.0.1:08765/api/login/return", own) == "http://127.0.0.1:8765/api/login/return"
    assert auth.valid_return("http://[::1]:8765/signin", own) == "http://[::1]:8765/signin"
    assert auth.valid_return("https://lantern.example/v1/signin/return", own) == "https://lantern.example/v1/signin/return"
    assert auth.valid_return("https://lantern.example.evil.test/v1/signin/return", own) == ""
    assert [auth.mark_of(x) for x in ("n" * 24, "n" * 15, "n" * 24 + "&x=1", None, 5)] == ["n" * 24, "", "", "", ""]
