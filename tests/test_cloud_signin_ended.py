"""A sign-in that was ended is refused from then on (review stage, 2026-11-15).

The website asks the gateway whose sign-in a request carries. Until this date it kept a "yes" for five minutes, so
a sign-in that was ended somewhere else (the app's "sign out everywhere", an account switched off) went on working
on the website for that long; and a sign-out from the website while the gateway could not be reached removed the
browser's cookie, answered as a sign-out that worked, and left the sign-in itself alive. Each case stands beside
twins that must keep working. The gateway is the real gateway app, in process, behind a door the test can shut."""

import asyncio
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
from fastapi.testclient import TestClient  # noqa: E402

import lantern_cloud  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.identity import Identity  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

ADMIN = "admin-" + "y" * 20
SITE = {"x-lantern-site": "1"}


class Door(httpx.ASGITransport):
    """The way to the gateway: every request is written down, and the test can shut it."""

    def __init__(self, app):
        super().__init__(app=app)
        self.asked: list[str] = []
        self.shut = False

    async def handle_async_request(self, request):
        self.asked.append(f"{request.method} {request.url.path}")
        if self.shut:
            raise httpx.ConnectError("no route")
        return await super().handle_async_request(request)


def _services(tmp_path, **more):
    gw_app = create_gateway(GwSettings(admin_secret=ADMIN, db_path=str(tmp_path / "gw.db")))
    door = Door(gw_app)
    s = Settings(gateway_url="http://gateway.test/v1", admin_secret=ADMIN, db_path=str(tmp_path / "cloud.db"),
                 results_dir=str(tmp_path / "results"), work_dir=str(tmp_path / "work"), audits=False, **more)
    cloud = TestClient(create_app(s, transport=door))
    cloud.app.state.identity.again = ()          # a test that wants the later tries asks for them itself
    return TestClient(gw_app), gw_app.state.store, cloud, door


def bearer(t):
    return {"authorization": f"Bearer {t}"}


def _whoami(door) -> int:
    return door.asked.count("GET /v1/whoami")


# ------------------------------------------------------------------ ended somewhere else, the website had asked
def test_a_sign_in_ended_somewhere_else_is_refused_at_the_next_request(tmp_path):
    gw, store, cloud, _ = _services(tmp_path)
    web, phone = store.sign_in("github:77", "github:seven"), store.sign_in("github:77", "github:seven")
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 200          # in use: the website has asked
    # the person signs out everywhere, in the app on their phone
    assert gw.post("/v1/auth/signout", json={"everywhere": True}, headers=bearer(phone)).json()["signed_out"] == 2
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 401          # a read
    assert cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(web)).status_code == 401   # a change
    assert cloud.post("/v1/runs/none/view", headers=bearer(web)).status_code == 401     # a link to results
    cloud.cookies.set("lt", web)                                                # the same sign-in, as the page sends it
    assert cloud.get("/v1/me").status_code == 401
    assert cloud.post("/v1/ai/consent", json={"agree": True}, headers=SITE).status_code == 401


def test_an_account_switched_off_at_the_gateway_is_refused_at_the_next_request(tmp_path):
    _, store, cloud, _ = _services(tmp_path)
    web = store.sign_in("github:78", "github:eight")
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 200
    store.db.execute("update users set disabled = 1 where token_hash = ?", (store.user(web)["hash"],))
    store.db.commit()
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 401


def test_a_sign_in_in_use_is_asked_about_each_time_and_keeps_working(tmp_path):
    _, store, cloud, door = _services(tmp_path)
    web = store.sign_in("github:79", "github:nine")
    for n in (1, 2, 3):
        assert cloud.get("/v1/me", headers=bearer(web)).json()["label"] == "github:nine"
        assert _whoami(door) == n
    assert cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(web)).json()["consent"] is True
    assert cloud.get("/v1/health").status_code == 200 and _whoami(door) == 4    # a public page asks nothing


def test_where_answers_are_remembered_a_change_asks_the_gateway_all_the_same(tmp_path):
    """`LANTERN_CLOUD_IDENTITY_TTL` above 0: a read may be answered from what the gateway said that long ago; a
    request that changes something, or makes a link, never is."""
    gw, store, cloud, door = _services(tmp_path, identity_ttl=300)
    web = store.sign_in("github:80", "github:ten")
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 200
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 200 and _whoami(door) == 1   # the twin: remembered
    assert cloud.post("/v1/ai/consent", json={"agree": False}, headers=bearer(web)).status_code == 200
    assert _whoami(door) == 2                                                   # a change asked
    assert gw.post("/v1/auth/signout", headers=bearer(web)).json()["signed_out"] == 1
    assert cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(web)).status_code == 401
    assert not cloud.app.state.store.consent("github:80")                       # and nothing was changed
    assert cloud.post("/v1/runs/none/view", headers=bearer(web)).status_code == 401
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 401          # the refusal is what is remembered now


# ------------------------------------------------------------------ signing out while the gateway is away
def _signs_out_unheard(tmp_path, again=()):
    gw, store, cloud, door = _services(tmp_path)
    ident = cloud.app.state.identity
    ident.again = again
    web, other = store.sign_in("github:81", "github:eleven"), store.sign_in("github:82", "github:twelve")
    cloud.cookies.set("lt", web)
    assert cloud.get("/v1/me").status_code == 200
    door.shut = True
    r = cloud.post("/v1/signout", headers=SITE)
    return r, store, cloud, door, ident, web, other


def test_a_sign_out_the_gateway_did_not_hear_of_is_not_called_done(tmp_path):
    r, store, cloud, door, ident, web, other = _signs_out_unheard(tmp_path)
    said = r.json()
    assert r.status_code == 200 and said["signed_in"] is False and said["ended"] == 0
    assert said["confirmed"] is False
    assert "could not reach" in said["message"] and "Sign out everywhere" in said["message"]
    gone = r.headers["set-cookie"]
    assert gone.startswith("lt=") and "Max-Age=0" in gone                       # the browser's cookie is removed
    door.shut = False
    assert store.user(web) is not None           # the gateway still knows the sign-in: that is what the answer said
    # The website takes it no more: not from this browser, not from a copy of its cookie.
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 401
    assert cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(web)).status_code == 401
    cloud.cookies.set("lt", web)
    assert cloud.get("/v1/me").status_code == 401
    cloud.cookies.clear()
    assert cloud.get("/v1/me", headers=bearer(other)).status_code == 200        # somebody else is not touched
    assert cloud.app.state.idle.busy()           # the service does not go to sleep on a sign-in it still has to end
    # The next try reaches the gateway, the sign-in ends there, and the website lets go of the token.
    assert asyncio.run(ident.finish()) == 0
    assert store.user(web) is None and not ident.unfinished and not cloud.app.state.idle.busy()
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 401


def test_the_website_tries_again_by_itself_until_the_gateway_has_heard(tmp_path):
    r, store, cloud, door, ident, web, _ = _signs_out_unheard(tmp_path, again=(0.01,) * 400)
    assert r.json()["confirmed"] is False and store.user(web) is not None
    door.shut = False
    until = time.monotonic() + 20
    while store.user(web) is not None and time.monotonic() < until:
        time.sleep(0.02)
    assert store.user(web) is None                                              # ended at the gateway, nobody asked
    ident.trying.join(20)
    assert not ident.trying.is_alive() and not ident.unfinished


def test_after_its_last_try_the_website_holds_the_token_no_longer_and_still_refuses_it(tmp_path):
    r, store, cloud, door, ident, web, _ = _signs_out_unheard(tmp_path, again=(0.01, 0.01, 0.01))
    assert r.json()["confirmed"] is False
    ident.trying.join(20)
    assert not ident.trying.is_alive()
    assert door.asked.count("POST /v1/auth/signout") == 4                       # the sign-out and three more tries
    assert not ident.unfinished                                                 # the token is in no list any more
    door.shut = False
    assert store.user(web) is not None                                          # the gateway never heard
    assert cloud.get("/v1/me", headers=bearer(web)).status_code == 401          # the website refuses it all the same


def test_the_list_of_sign_ins_ended_here_does_not_grow_without_end():
    ident = Identity("http://gateway.test/v1", transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    ident.again = ()
    ident.MOST_ENDED = 8
    for n in range(30):
        ident.end_here(f"lt_{n:04d}")
    assert len(ident.ended) <= 8 and len(ident.unfinished) <= 8
    assert ident.ended_here("lt_0029") and not ident.ended_here("lt_0000")      # the newest are the ones kept


def test_made_up_text_does_not_push_a_real_sign_in_off_that_list():
    def answer(request):
        if request.url.path.endswith("/whoami"):
            return httpx.Response(200, json={"account": "github:9", "label": "github:nine"})
        return httpx.Response(503)

    ident = Identity("http://gateway.test/v1", transport=httpx.MockTransport(answer))
    ident.again = ()
    ident.MOST_ENDED = 8
    assert asyncio.run(ident.whoami("lt_real"))["account"] == "github:9"       # a sign-in the gateway said yes to here
    ident.end_here("lt_real")
    for n in range(30):
        ident.end_here(f"made-up-{n:04d}")                                      # text the website never saw as one
    assert len(ident.ended) <= 8 and ident.ended_here("lt_real")                # the real one is still refused
    assert list(ident.unfinished.values()) == ["lt_real"]                       # and the only one tried again
    assert asyncio.run(ident.whoami("lt_real")) is None


# ------------------------------------------------------------------ the twins: a sign-out that worked
def test_a_sign_out_the_gateway_heard_says_so(tmp_path):
    _, store, cloud, _ = _services(tmp_path)
    ident = cloud.app.state.identity
    web, phone = store.sign_in("github:83", "github:thirteen"), store.sign_in("github:83", "github:thirteen")
    cloud.cookies.set("lt", web)
    assert cloud.get("/v1/me").status_code == 200
    r = cloud.post("/v1/signout", headers=SITE)
    assert r.json() == {"signed_in": False, "ended": 1, "confirmed": True}
    assert store.user(web) is None and not ident.unfinished and not ident.ended and ident.trying is None
    assert cloud.get("/v1/me", headers=bearer(phone)).status_code == 200        # the phone stays signed in
    cloud.cookies.clear()
    assert cloud.post("/v1/signout", headers=SITE).json() == {"signed_in": False, "ended": 0, "confirmed": True}


def test_sign_out_everywhere_with_the_gateway_away_signs_nothing_out_and_says_that(tmp_path):
    _, store, cloud, door = _services(tmp_path)
    ident = cloud.app.state.identity
    web = store.sign_in("github:84", "github:fourteen")
    cloud.cookies.set("lt", web)
    door.shut = True
    r = cloud.post("/v1/signout", json={"everywhere": True}, headers=SITE)
    assert r.status_code == 503 and "nothing was signed out" in r.json()["error"]["message"]
    assert "set-cookie" not in r.headers and not ident.ended and not ident.unfinished
    door.shut = False
    assert cloud.get("/v1/me").status_code == 200                               # still signed in here, as it said
    assert cloud.post("/v1/signout", json={"everywhere": True}, headers=SITE).json() == {
        "signed_in": False, "ended": 1, "confirmed": True}


def test_the_page_shows_what_the_website_answered():
    page = (Path(lantern_cloud.__file__).parent / "site" / "index.html").read_text(encoding="utf-8")
    start = page.index("async function signOut()")
    body = page[start:page.index("function signOutAllSheet()", start)]
    assert "catch (e) {}" not in body            # until 2026-11-15 any answer, and no answer, read as signed out
    assert "confirmed === false" in body and ".message" in body
