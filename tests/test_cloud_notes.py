"""Cloud service: notes on the map (directive: user first, step 5). People who can open a run leave short notes on
a function for each other. Words only: a note never changes the analysis and never reaches a model. A member who
sees only some layers neither sees nor leaves notes on the rest."""

import sqlite3

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from test_cloud_runs import bearer, clone_from, origin  # noqa: E402,F401
from test_cloud_teams import code_of, invite, team  # noqa: E402,F401

SERVER_FN = "py:shop.app.backup"
FRONT_FN = "js:web/src/api::runBackup"


@pytest.fixture
def notes(team):  # noqa: F811
    cloud, s, ana, ben, cat, rid, w = team
    wid = w["id"]
    cloud.post("/v1/invites/accept", json={"code": code_of(invite(cloud, ana, wid)["url"])}, headers=bearer(ben))
    cloud.put(f"/v1/runs/{rid}/workspace", json={"workspace": wid}, headers=bearer(ana))
    return cloud, s, ana, ben, cat, rid, wid


def test_people_who_can_open_a_run_leave_notes_for_each_other(notes):
    cloud, s, ana, ben, cat, rid, wid = notes
    a = cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": "  Is this <b>backup</b> still used?\nAsk Dev. "},
                   headers=bearer(ana))
    assert a.status_code == 201
    b = cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": "Yes, nightly."}, headers=bearer(ben))
    assert b.status_code == 201
    got = cloud.get(f"/v1/runs/{rid}/notes", headers=bearer(ben)).json()["notes"]
    assert [(n["by"], n["body"], n["mine"], n["can_delete"]) for n in got] == [
        ("ana", "Is this <b>backup</b> still used?\nAsk Dev.", False, False), ("ben", "Yes, nightly.", True, True)]
    assert "account" not in str(got) and "github:" not in str(got)
    # the owner may delete any note on their run; a member only their own
    first = got[0]["id"]
    assert cloud.delete(f"/v1/notes/{first}", headers=bearer(ben)).status_code == 403
    assert cloud.get(f"/v1/runs/{rid}/notes", headers=bearer(ana)).json()["notes"][1]["can_delete"] is True
    assert cloud.delete(f"/v1/notes/{got[1]['id']}", headers=bearer(ana)).json() == {"deleted": got[1]["id"]}
    # someone who can't open the run can't read, add or delete
    assert cloud.get(f"/v1/runs/{rid}/notes", headers=bearer(cat)).status_code == 404
    assert cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": "hi"}, headers=bearer(cat)).status_code == 404
    assert cloud.delete(f"/v1/notes/{first}", headers=bearer(cat)).status_code == 404


def test_a_note_is_short_words_on_a_function_that_is_on_the_map(notes):
    cloud, s, ana, ben, cat, rid, wid = notes
    url = f"/v1/runs/{rid}/notes"
    for bad in ("", "   ", "x" * 1001, "bell\x07", None, 5):
        assert cloud.post(url, json={"node": SERVER_FN, "body": bad}, headers=bearer(ana)).status_code == 400
    for node in ("py:nope", None, 3, ""):
        assert cloud.post(url, json={"node": node, "body": "hi"}, headers=bearer(ana)).status_code == 404
    assert cloud.post(url, json={"node": SERVER_FN, "body": "x" * 1000}, headers=bearer(ana)).status_code == 201


def test_a_member_limited_to_some_layers_sees_notes_only_there(notes):
    cloud, s, ana, ben, cat, rid, wid = notes
    for node in (SERVER_FN, FRONT_FN):
        assert cloud.post(f"/v1/runs/{rid}/notes", json={"node": node, "body": f"note on {node}"}, headers=bearer(ana)).status_code == 201
    ben_id = next(p["id"] for p in cloud.get(f"/v1/workspaces/{wid}", headers=bearer(ana)).json()["people"] if p["name"] == "ben")
    cloud.put(f"/v1/workspaces/{wid}/people/{ben_id}", json={"lanes": ["frontend", "browser"]}, headers=bearer(ana))
    seen = cloud.get(f"/v1/runs/{rid}/notes", headers=bearer(ben)).json()["notes"]
    assert [n["node"] for n in seen] == [FRONT_FN]
    assert cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": "hi"}, headers=bearer(ben)).status_code == 404
    hidden = next(n["id"] for n in cloud.get(f"/v1/runs/{rid}/notes", headers=bearer(ana)).json()["notes"] if n["node"] == SERVER_FN)
    assert cloud.delete(f"/v1/notes/{hidden}", headers=bearer(ben)).status_code == 404


def test_notes_go_with_their_run_and_their_author(notes):
    cloud, s, ana, ben, cat, rid, wid = notes
    cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": "from ben"}, headers=bearer(ben))
    assert cloud.delete("/v1/me", headers=bearer(ben)).status_code == 200
    assert cloud.get(f"/v1/runs/{rid}/notes", headers=bearer(ana)).json()["notes"] == []
    cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": "from ana"}, headers=bearer(ana))
    assert cloud.delete(f"/v1/runs/{rid}", headers=bearer(ana)).status_code in (200, 204)
    assert sqlite3.connect(s.db_path).execute("select count(*) from notes").fetchone()[0] == 0


def test_a_report_holds_a_limited_number_of_notes(tmp_path, clone_from):  # noqa: F811
    from test_cloud_runs import LINK, make, wait
    cloud, gw, s = make(tmp_path, public_url="http://testserver", notes_per_run=2)
    tok = gw.sign_in("github:1", "github:ana")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    assert wait(cloud, tok, rid)["status"] == "done"
    for i in range(2):
        assert cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": str(i)}, headers=bearer(tok)).status_code == 201
    r = cloud.post(f"/v1/runs/{rid}/notes", json={"node": SERVER_FN, "body": "one more"}, headers=bearer(tok))
    assert r.status_code == 429 and "2 notes" in r.json()["error"]["message"]
