"""A link to a run's results opens what its person may read now (review stage, 2026-11-15).

`POST /v1/runs/{id}/view` hands out links that open a report for an hour, and the report leaves a cookie for the
pages beside it. Until this date a link said which run, until when and which layers, and nothing about whom it was
made for: somebody taken out of a workspace, or given fewer layers, kept the run and the layers of the moment the
link was made, for the rest of the hour. So did a stream of a run's progress that was open. Each change that takes
something away is tried with the link in the address and with the cookie, beside the people it must not touch."""

import asyncio
import threading

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from test_cloud_runs import LINK, bearer, clone_from, make, origin, wait  # noqa: E402,F401,I001  (it finds the services)
from test_cloud_teams import code_of, invite  # noqa: E402

import lantern_cloud.app as cloud_app  # noqa: E402

SITE = {"x-lantern-site": "1"}
SERVER_CODE = "shop.app.backup"                 # a function of the sample's server, in a report that shows it


@pytest.fixture
def club(tmp_path, clone_from):  # noqa: F811
    """ana owns a finished run and a workspace it is in; ben and cat are members who may see every layer."""
    cloud, gw, s = make(tmp_path, public_url="http://testserver")
    ana, ben, cat = gw.sign_in("github:1", "github:ana"), gw.sign_in("github:2", "github:ben"), gw.sign_in("github:3", "github:cat")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(ana)).json()["id"]
    assert wait(cloud, ana, rid)["status"] == "done"
    wid = cloud.post("/v1/workspaces", json={"name": "Shop team"}, headers=bearer(ana)).json()["id"]
    for tok in (ben, cat):
        joined = cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ana, wid)["url"])}, headers=bearer(tok))
        assert joined.status_code == 200, joined.text
    assert cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": wid}, headers=bearer(ana)).status_code == 200
    people = {p["name"]: p["id"] for p in cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ana)).json()["people"]}
    return {"cloud": cloud, "gw": gw, "ana": ana, "ben": ben, "cat": cat, "rid": rid, "wid": wid, "people": people}


def key(c, who: str) -> str:
    links = c["cloud"].post(f"/v1/runs/{c['rid']}/view", headers=bearer(c[who]))
    assert links.status_code == 200, links.text
    return links.json()["report"].split("?k=", 1)[1]


def opened(c, k: str, name: str = "report.html", cookie: bool = False):
    """The page a link gives: with the link in the address, or with the cookie the report left in the browser."""
    cloud = c["cloud"]
    cloud.cookies.clear()
    if cookie:
        r = cloud.get(f"/r/{c['rid']}/{name}", headers={"cookie": f"lv={k}"})
    else:
        r = cloud.get(f"/r/{c['rid']}/{name}?k={k}")
    cloud.cookies.clear()
    return r


def opens(c, k: str) -> list[int]:
    return [opened(c, k).status_code, opened(c, k, "evidence.html", cookie=True).status_code,
            opened(c, k, "findings.json", cookie=True).status_code]


def layers(c, who: str, lanes) -> None:
    r = c["cloud"].put(f"/v1/workspaces/{c['wid']}/people/{c['people'][who]}", json={"lanes": lanes}, headers=bearer(c["ana"]))
    assert r.status_code == 200, r.text


def _taken_out(c):
    return c["cloud"].delete(f"/v1/workspaces/{c['wid']}/people/{c['people']['ben']}", headers=bearer(c["ana"]))


def _left(c):
    return c["cloud"].delete(f"/v1/workspaces/{c['wid']}/people/{c['people']['ben']}", headers=bearer(c["ben"]))


def _run_taken_out(c):
    return c["cloud"].put(f"/v1/runs/{c['rid']}/workspace", json={"workspace": None}, headers=bearer(c["ana"]))


def _closed(c):
    return c["cloud"].delete(f"/v1/workspaces/{c['wid']}", headers=bearer(c["ana"]))


def _run_moved(c):
    other = c["cloud"].post("/v1/workspaces", json={"name": "Ana alone"}, headers=bearer(c["ana"])).json()["id"]
    return c["cloud"].put(f"/v1/runs/{c['rid']}/workspace", json={"workspace": other}, headers=bearer(c["ana"]))


# what takes the run away from ben -> does cat, who was not touched, still read it?
CHANGES = {"ben is taken out of the workspace": (_taken_out, True), "ben leaves the workspace": (_left, True),
           "the run is taken out of the workspace": (_run_taken_out, False), "the workspace is closed": (_closed, False),
           "the run is moved to a workspace ben is not in": (_run_moved, False)}


@pytest.mark.parametrize("change", list(CHANGES))
def test_a_link_made_for_somebody_who_may_no_longer_read_the_run_opens_nothing(club, change):
    c = club
    bens, anas, cats = key(c, "ben"), key(c, "ana"), key(c, "cat")
    for k in (bens, anas, cats):
        assert opens(c, k) == [200, 200, 200]
    does, cat_stays = CHANGES[change]
    assert does(c).status_code == 200
    assert opens(c, bens) == [401, 401, 401]             # in the address, and as the cookie the report left
    assert opens(c, anas) == [200, 200, 200]             # the run's owner reads it as before
    assert opens(c, cats) == ([200, 200, 200] if cat_stays else [401, 401, 401])
    assert c["cloud"].post(f"/v1/runs/{c['rid']}/view", headers=bearer(c["ben"])).status_code == 404   # and gets no new one


def test_a_link_never_opens_more_layers_than_its_person_may_see_now(club):
    c = club
    whole = key(c, "ben")
    assert SERVER_CODE in opened(c, whole).text
    layers(c, "ben", ["frontend", "browser"])
    assert opens(c, whole) == [401, 401, 401]            # made when ben saw every layer: it would show the server's code
    two = key(c, "ben")
    page = opened(c, two)
    assert page.status_code == 200 and SERVER_CODE not in page.text
    layers(c, "ben", ["frontend"])
    assert opened(c, two).status_code == 401 and opened(c, two, cookie=True).status_code == 401
    one = key(c, "ben")
    assert opened(c, one).status_code == 200
    # The twin: more layers later take nothing away. The link opens what it was made for, and no more than that.
    layers(c, "ben", ["frontend", "browser", "server"])
    page = opened(c, one)
    assert page.status_code == 200 and SERVER_CODE not in page.text
    layers(c, "ben", None)
    assert opened(c, one).status_code == 200 and SERVER_CODE not in opened(c, one).text
    assert SERVER_CODE in opened(c, key(c, "ben")).text  # a link made now opens every layer
    assert opens(c, key(c, "cat")) == [200, 200, 200]    # cat was never narrowed


def test_a_link_is_for_the_one_it_was_made_for(club):
    """ben's link is not cat's: taking ben out ends it, although cat, who still reads the run, could have one like it."""
    c = club
    bens = key(c, "ben")
    exp, lanes, who, sig = bens.split(".")
    cats = key(c, "cat")
    assert cats.split(".")[2] != who and "github" not in bens and "ben" not in bens     # says nobody's name
    assert _taken_out(c).status_code == 200
    for forged in (f"{exp}.{lanes}.{cats.split('.')[2]}.{sig}", f"{exp}.{lanes}.{sig}", f"{exp}.{sig}",
                   f"{exp}.{lanes}..{sig}", f"{exp}.{lanes}.{who}.{cats.split('.')[3]}"):
        assert opened(c, forged).status_code == 401 and opened(c, forged, cookie=True).status_code == 401


def test_signing_out_on_the_website_ends_the_links_made_for_that_account(club):
    c = club
    cloud = c["cloud"]
    anas, bens = key(c, "ana"), key(c, "ben")
    cloud.cookies.set("lt", c["ana"])
    assert cloud.post("/v1/signout", headers=SITE).json()["confirmed"] is True
    assert opens(c, anas) == [401, 401, 401]
    assert opens(c, bens) == [200, 200, 200]             # somebody else's link is not touched
    c["ana"] = c["gw"].sign_in("github:1", "github:ana")
    assert opens(c, key(c, "ana")) == [200, 200, 200]    # signed in again: a new link opens


class _Sleeps:
    """`asyncio`, as the website's module sees it, with a `sleep` that says when a stream has got to its first wait."""

    def __init__(self):
        self.waiting = threading.Event()

    def __getattr__(self, name):
        return getattr(asyncio, name)

    async def sleep(self, seconds):
        self.waiting.set()
        await asyncio.sleep(min(seconds, 0.05))


def _a_stream_open_on_a_run_under_way(c, who: str, monkeypatch):
    sleeps = _Sleeps()
    monkeypatch.setattr(cloud_app, "asyncio", sleeps)
    store = c["cloud"].app.state.store
    with store.lock:
        store.db.execute("update runs set status = 'running' where id = ?", (c["rid"],))
        store.db.commit()
    got: dict = {}

    def read():
        with c["cloud"].stream("GET", f"/v1/runs/{c['rid']}/stream", headers=bearer(c[who])) as r:
            got["status"], got["body"] = r.status_code, "".join(r.iter_text())

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    assert sleeps.waiting.wait(30)                       # the stream is open and waits for the run's next lines

    def ended(wait: float = 20) -> bool:
        reader.join(wait)
        over = not reader.is_alive()
        with store.lock:                                 # whatever came of it, nothing is left waiting on this run
            store.db.execute("update runs set status = 'done' where id = ?", (c["rid"],))
            store.db.commit()
        reader.join(30)
        return over
    return got, ended


def test_an_open_stream_ends_when_its_reader_may_no_longer_read_the_run(club, monkeypatch):
    c = club
    got, ended = _a_stream_open_on_a_run_under_way(c, "ben", monkeypatch)
    assert _taken_out(c).status_code == 200
    assert ended() and got["status"] == 200 and "event: end" not in got["body"]


def test_an_open_stream_ends_when_its_readers_sign_in_has_ended(club, monkeypatch):
    c = club
    monkeypatch.setattr(cloud_app, "STREAM_ASKS_AGAIN", 0.0)
    got, ended = _a_stream_open_on_a_run_under_way(c, "ben", monkeypatch)
    assert c["gw"].sign_out(c["ben"], False) == 1
    assert ended() and "event: end" not in got["body"]


def test_an_open_stream_goes_on_for_a_reader_nothing_was_taken_from(club, monkeypatch):
    c = club
    monkeypatch.setattr(cloud_app, "STREAM_ASKS_AGAIN", 0.0)
    got, ended = _a_stream_open_on_a_run_under_way(c, "cat", monkeypatch)
    assert _taken_out(c).status_code == 200              # ben goes; cat's stream is cat's
    assert not ended(3)                                  # still open three seconds on, until the run was finished
    assert got["status"] == 200 and "event: end" in got["body"]
