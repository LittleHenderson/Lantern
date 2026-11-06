"""Cloud service: team workspaces (directive: user first, step 3). A workspace is a few people who can open each
other's runs. One-time invite links (7 days, only a hash kept, no email), owner and member roles, runs that join a
workspace only when their own owner puts them there, and members who can read but never change someone else's run."""

import datetime as dt
import hashlib
import sqlite3

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from test_cloud_runs import LINK, bearer, clone_from, make, origin, wait  # noqa: E402,F401


@pytest.fixture
def team(tmp_path, clone_from):  # noqa: F811
    cloud, gw, s = make(tmp_path, public_url="http://testserver")
    ana, ben, cat = gw.sign_in("github:1", "github:ana"), gw.sign_in("github:2", "github:ben"), gw.sign_in("github:3", "github:cat")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(ana)).json()["id"]
    assert wait(cloud, ana, rid)["status"] == "done"
    w = cloud.post("/v1/workspaces", json={"name": "  Shop   team "}, headers=bearer(ana))
    assert w.status_code == 201
    return cloud, s, ana, ben, cat, rid, w.json()


def code_of(url):
    return url.split("#/join/", 1)[1]


def invite(cloud, tok, wid):
    r = cloud.post(f"/v1/workspaces/{wid}/invites", headers=bearer(tok))
    assert r.status_code == 201, r.text
    return r.json()


def test_a_new_workspace_has_its_owner_only(team):
    cloud, s, ana, ben, cat, rid, w = team
    assert w["name"] == "Shop team" and w["role"] == "owner" and w["runs"] == []
    assert [(p["name"], p["role"], p["you"]) for p in w["people"]] == [("ana", "owner", True)]
    assert "account" not in str(w["people"]) and "github:1" not in str(w)
    assert cloud.get("/v1/workspaces", headers=bearer(ana)).json()["workspaces"][0]["people"] == 1
    assert cloud.get("/v1/workspaces", headers=bearer(ben)).json()["workspaces"] == []
    assert cloud.get(f"/v1/workspaces/{w['id']}", headers=bearer(ben)).status_code == 404
    for bad in ("", "   ", "x" * 61, "a\x07b", None, 5):
        assert cloud.post("/v1/workspaces", json={"name": bad}, headers=bearer(ana)).status_code == 400


def test_an_invite_is_one_time_and_keeps_only_a_hash(team):
    cloud, s, ana, ben, cat, rid, w = team
    inv = invite(cloud, ana, w["id"])
    code = code_of(inv["url"])
    assert inv["url"].startswith("http://testserver/#/join/") and inv["one_time"] is True and len(code) >= 30
    exp = dt.datetime.fromisoformat(inv["expires"])
    assert dt.timedelta(days=6, hours=23) < exp - dt.datetime.now(dt.UTC) <= dt.timedelta(days=7)
    db = sqlite3.connect(s.db_path)
    dump = "\n".join(db.iterdump())
    assert code not in dump and hashlib.sha256(code.encode()).hexdigest() in dump
    assert "@" not in dump                                             # no email is asked for or kept
    # anyone holding the link sees the workspace's name, and nothing else, before signing in
    peek = cloud.post("/v1/invites/peek", json={"code": code})
    assert peek.status_code == 200 and peek.json()["name"] == "Shop team" and set(peek.json()) == {"name", "expires"}
    j = cloud.post("/v1/invites/accept", json={"code": code}, headers=bearer(ben))
    assert j.status_code == 200 and j.json()["role"] == "member"
    assert sorted(p["name"] for p in j.json()["people"]) == ["ana", "ben"]
    # used: it stops working, for everyone
    assert cloud.post("/v1/invites/accept", json={"code": code}, headers=bearer(cat)).status_code == 404
    assert cloud.post("/v1/invites/peek", json={"code": code}).status_code == 404
    assert cloud.get(f"/v1/workspaces/{w['id']}", headers=bearer(cat)).status_code == 404
    assert cloud.post("/v1/invites/accept", json={"code": code}).status_code == 401
    for bad in ("", "x" * 30, None, ["x"], "y" * 500):
        assert cloud.post("/v1/invites/accept", json={"code": bad}, headers=bearer(cat)).status_code == 404


def test_an_invite_expires_after_seven_days_and_can_be_cancelled(team):
    cloud, s, ana, ben, cat, rid, w = team
    code = code_of(invite(cloud, ana, w["id"])["url"])
    db = sqlite3.connect(s.db_path)
    db.execute("update invites set expires = ?", ((dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)).isoformat(),))
    db.commit()
    assert cloud.post("/v1/invites/accept", json={"code": code}, headers=bearer(ben)).status_code == 404
    code2 = code_of(invite(cloud, ana, w["id"])["url"])
    assert cloud.delete(f"/v1/workspaces/{w['id']}/invites", headers=bearer(ana)).json() == {"cancelled": 1}
    assert cloud.post("/v1/invites/accept", json={"code": code2}, headers=bearer(ben)).status_code == 404


def test_only_the_owner_invites_renames_and_closes(team):
    cloud, s, ana, ben, cat, rid, w = team
    cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ana, w["id"])["url"])}, headers=bearer(ben))
    wid = w["id"]
    assert cloud.post(f"/v1/workspaces/{wid}/invites", headers=bearer(ben)).status_code == 403
    assert cloud.patch(f"/v1/workspaces/{wid}", json={"name": "Mine now"}, headers=bearer(ben)).status_code == 403
    assert cloud.delete(f"/v1/workspaces/{wid}", headers=bearer(ben)).status_code == 403
    assert cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ben)).json()["invites_open"] is None
    assert cloud.patch(f"/v1/workspaces/{wid}", json={"name": "Shop"}, headers=bearer(ana)).json()["name"] == "Shop"


def test_a_run_joins_only_when_its_owner_puts_it_there(team):
    cloud, s, ana, ben, cat, rid, w = team
    wid = w["id"]
    cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ana, wid)["url"])}, headers=bearer(ben))
    # not yet in the workspace: ben cannot open it
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(ben)).status_code == 404
    # ben cannot put ana's run in; ana cannot put it in a workspace she is not in
    assert cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": wid}, headers=bearer(ben)).status_code == 404
    other = cloud.post("/v1/workspaces", json={"name": "Cat's"}, headers=bearer(cat)).json()["id"]
    assert cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": other}, headers=bearer(ana)).status_code == 404
    v = cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": wid}, headers=bearer(ana))
    assert v.status_code == 200 and v.json()["workspace"] == wid
    # now ben reads it: the run, its log, its report links, its place in the workspace
    got = cloud.get(f"/v1/runs/{rid}", headers=bearer(ben)).json()
    assert got["status"] == "done" and got["mine"] is False and "account" not in got
    assert cloud.get(f"/v1/runs/{rid}/stream", headers=bearer(ben)).status_code == 200
    links = cloud.post(f"/v1/runs/{rid}/view", headers=bearer(ben)).json()
    assert cloud.get(links["report"].replace("http://testserver", "")).status_code == 200
    runs = cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ben)).json()["runs"]
    assert [(r["id"], r["by"], r["mine"]) for r in runs] == [(rid, "ana", False)]
    # it stays out of ben's own list
    assert cloud.get("/v1/runs", headers=bearer(ben)).json()["runs"] == []
    # ben reads, never changes: no share, no explain, no delete, no moving it
    assert cloud.post(f"/v1/runs/{rid}/share", headers=bearer(ben)).status_code == 404
    assert cloud.post(f"/v1/runs/{rid}/explain", headers=bearer(ben)).status_code == 404
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(ben)).status_code == 404
    assert cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": None}, headers=bearer(ben)).status_code == 404
    # cat, outside the workspace, still sees nothing
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(cat)).status_code == 404
    assert cloud.post(f"/v1/runs/{rid}/view", headers=bearer(cat)).status_code == 404
    # ana takes it out again
    assert cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": None}, headers=bearer(ana)).json()["workspace"] is None
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(ben)).status_code == 404


def test_leaving_removing_and_closing_give_runs_back(team):
    cloud, s, ana, ben, cat, rid, w = team
    wid = w["id"]
    for tok in (ben, cat):
        cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ana, wid)["url"])}, headers=bearer(tok))
    cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": wid}, headers=bearer(ana))
    people = {p["name"]: p["id"] for p in cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ana)).json()["people"]}
    # a member cannot take someone else out, and nobody can take the owner out
    assert cloud.delete(f"/v1/workspaces/{wid}/people/{people['cat']}", headers=bearer(ben)).status_code == 403
    assert cloud.delete(f"/v1/workspaces/{wid}/people/{people['ana']}", headers=bearer(ana)).status_code == 409
    # ben leaves; the owner takes cat out
    assert cloud.delete(f"/v1/workspaces/{wid}/people/{people['ben']}", headers=bearer(ben)).json()["left"] is True
    assert cloud.delete(f"/v1/workspaces/{wid}/people/{people['cat']}", headers=bearer(ana)).json()["left"] is False
    for tok in (ben, cat):
        assert cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).status_code == 404
    # closing: the run goes back to being ana's alone, and nothing is deleted
    assert cloud.delete(f"/v1/workspaces/{wid}", headers=bearer(ana)).json() == {"closed": wid}
    r = cloud.get(f"/v1/runs/{rid}", headers=bearer(ana)).json()
    assert r["status"] == "done" and r["workspace"] is None
    assert cloud.get("/v1/workspaces", headers=bearer(ana)).json()["workspaces"] == []


def test_deleting_an_account_closes_its_workspaces_and_leaves_others(team):
    cloud, s, ana, ben, cat, rid, w = team
    wid = w["id"]
    cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ana, wid)["url"])}, headers=bearer(ben))
    bens = cloud.post("/v1/workspaces", json={"name": "Ben's"}, headers=bearer(ben)).json()["id"]
    cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ben, bens)["url"])}, headers=bearer(ana))
    assert cloud.delete("/v1/me", headers=bearer(ana)).status_code == 200
    assert cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ben)).status_code == 404      # ana's: closed
    left = cloud.get(f"/v1/workspaces/{bens}", headers=bearer(ben)).json()                  # ben's: ana is gone
    assert [p["name"] for p in left["people"]] == ["ben"]


def test_workspace_limits_answer_429_with_a_sentence(tmp_path, clone_from):  # noqa: F811
    cloud, gw, s = make(tmp_path, public_url="http://testserver", workspaces_per_owner=1, workspace_people=2, open_invites=1)
    a, b, c = (gw.sign_in(f"github:{i}", f"github:{n}") for i, n in enumerate("abc"))
    wid = cloud.post("/v1/workspaces", json={"name": "One"}, headers=bearer(a)).json()["id"]
    r = cloud.post("/v1/workspaces", json={"name": "Two"}, headers=bearer(a))
    assert r.status_code == 429 and "up to 1 workspace" in r.json()["error"]["message"]
    code = code_of(invite(cloud, a, wid)["url"])
    r = cloud.post(f"/v1/workspaces/{wid}/invites", headers=bearer(a))
    assert r.status_code == 429 and "invite link" in r.json()["error"]["message"]
    cloud.post("/v1/invites/accept", json={"code": code}, headers=bearer(b))
    code = code_of(invite(cloud, a, wid)["url"])
    r = cloud.post("/v1/invites/accept", json={"code": code}, headers=bearer(c))
    assert r.status_code == 429 and "2 people" in r.json()["error"]["message"]


def test_a_cookie_cannot_change_a_workspace_from_another_site(team):
    cloud, s, ana, ben, cat, rid, w = team
    cloud.cookies.set("lt", ana)
    r = cloud.post(f"/v1/workspaces/{w['id']}/invites")                 # no X-Lantern-Site header
    assert r.status_code == 403
    assert cloud.post(f"/v1/workspaces/{w['id']}/invites", headers={"x-lantern-site": "1"}).status_code == 201
    cloud.cookies.clear()


def test_a_member_can_be_shown_only_some_layers(team):
    """Per-layer permissions (directive step 4): the owner picks which layers a member sees. That member's report
    is built without the rest, the link they get says which layers it opens (and can't be edited to open more),
    and what describes the whole app (score, log, evidence, raw files, Ask Lantern) stays with full members."""
    cloud, s, ana, ben, cat, rid, w = team
    wid = w["id"]
    for tok in (ben, cat):
        cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ana, wid)["url"])}, headers=bearer(tok))
    cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": wid}, headers=bearer(ana))
    people = {p["name"]: p["id"] for p in cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ana)).json()["people"]}
    ben_id, cat_id, ana_id = people["ben"], people["cat"], people["ana"]
    # only the owner chooses, never for the owner, and only real layers
    assert cloud.put(f"/v1/workspaces/{wid}/people/{cat_id}", json={"lanes": ["frontend"]}, headers=bearer(ben)).status_code == 403
    assert cloud.put(f"/v1/workspaces/{wid}/people/{ana_id}", json={"lanes": ["frontend"]}, headers=bearer(ana)).status_code == 409
    for bad in ([], ["api"], "frontend", [3]):
        assert cloud.put(f"/v1/workspaces/{wid}/people/{ben_id}", json={"lanes": bad}, headers=bearer(ana)).status_code == 400
    v = cloud.put(f"/v1/workspaces/{wid}/people/{ben_id}", json={"lanes": ["frontend", "browser"]}, headers=bearer(ana))
    assert v.status_code == 200
    assert {p["name"]: p["lanes"] for p in v.json()["people"]} == {"ana": None, "ben": ["browser", "frontend"], "cat": None}
    # ben: the run without the whole-app parts, and a workspace page that says what he sees
    got = cloud.get(f"/v1/runs/{rid}", headers=bearer(ben)).json()
    assert got["lanes"] == ["browser", "frontend"] and got["summary"] is None and got["log_tail"] == ""
    tw = cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ben)).json()
    assert tw["lanes"] == ["browser", "frontend"] and tw["runs"][0]["summary"] is None
    assert "event: log" not in cloud.get(f"/v1/runs/{rid}/stream", headers=bearer(ben)).text
    # ana and cat still see everything
    full = cloud.get(f"/v1/runs/{rid}", headers=bearer(cat)).json()
    assert "lanes" not in full and full["summary"] and full["log_tail"]
    assert "event: log" in cloud.get(f"/v1/runs/{rid}/stream", headers=bearer(cat)).text
    # the report: ben's is built without the server's code; ana's has it
    links = cloud.post(f"/v1/runs/{rid}/view", headers=bearer(ben)).json()
    k = links["report"].split("?k=", 1)[1]
    assert k.split(".")[1] == "bf"
    page = cloud.get(links["report"].replace("http://testserver", ""))
    assert page.status_code == 200 and "shop.app.backup" not in page.text and "shop/app.py" not in page.text
    mine = cloud.post(f"/v1/runs/{rid}/view", headers=bearer(ana)).json()
    assert "shop.app.backup" in cloud.get(mine["report"].replace("http://testserver", "")).text
    assert cloud.get(links["evidence"].replace("http://testserver", "")).status_code == 403
    # the link can't be edited to open more layers
    exp, _, sig = k.split(".")
    cloud.cookies.clear()          # ana's link above left her browser's cookie in this shared test client
    for forged in (f"{exp}.{sig}", f"{exp}.bfsd.{sig}", f"{exp}.bfs.{sig}", f"{exp}.all.{sig}"):
        assert cloud.get(f"/r/{rid}/report.html?k={forged}").status_code == 401
    # Ask Lantern reads the whole app: refused for ben, with a sentence
    cloud.post("/v1/ai/consent", json={"agree": True}, headers=bearer(ben))
    a = cloud.post("/v1/ask", json={"run": rid, "question": "What should I fix first?"}, headers=bearer(ben))
    assert a.status_code == 403 and "layers" in a.text
    # back to every layer
    cloud.put(f"/v1/workspaces/{wid}/people/{ben_id}", json={"lanes": None}, headers=bearer(ana))
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(ben)).json()["summary"]
    cloud.put(f"/v1/workspaces/{wid}/people/{ben_id}", json={"lanes": list(("browser", "frontend", "server", "data"))}, headers=bearer(ana))
    assert {p["name"]: p["lanes"] for p in cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ana)).json()["people"]}["ben"] is None
