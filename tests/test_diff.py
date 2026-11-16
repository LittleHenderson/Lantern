"""What a change does to an app (`lantern/diff.py`, `lantern diff`; roadmap of 2026-11-14, stage 2).

One small app (a FastAPI server, a React page that asks it) is checked twice with the whole analysis, before a
change and after it, and the receipt has to name exactly what was planted: a new route that asks nobody who is
calling, a login check taken off a route, a request of the page that no route answers any more, a finding that
a route reaches now. Each planted change stands beside a twin that looks alike and is none (the new route asks
for a login; page and server were renamed together; the risky helper is called by something no door reaches;
only a comment and the spacing changed), and the twin's receipt has to be quiet about it.
"""
import json
import re
from pathlib import Path

import pytest
from test_commit_copy import commit, git, held

from lantern import diff, onrepo, pipeline

APP = '''\
from fastapi import Depends, FastAPI, Header, HTTPException

from . import store

app = FastAPI()


def current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401)
    return store.user_for(authorization)


@app.get("/api/notes")
def list_notes(user=Depends(current_user)):
    return store.all_notes(user)


@app.delete("/api/notes/{note_id}")
def delete_note(note_id: int, user=Depends(current_user)):
    store.remove(note_id, user)
    return {"deleted": note_id}
'''

STORE = '''\
import sqlite3

DB = "notes.db"


def user_for(token):
    return token.split(":")[0]


def all_notes(user):
    with sqlite3.connect(DB) as con:
        return con.execute("select id, text from notes where owner = ?", (user,)).fetchall()


def remove(note_id, user):
    with sqlite3.connect(DB) as con:
        con.execute("delete from notes where id = ? and owner = ?", (note_id, user))
'''

API_JS = '''\
export async function loadNotes() {
  const res = await fetch("/api/notes");
  return res.json();
}

export async function removeNote(id) {
  await fetch(`/api/notes/${id}`, { method: "DELETE" });
}
'''

APP_JSX = '''\
import { useEffect, useState } from "react";
import { loadNotes, removeNote } from "./api";

export default function App() {
  const [notes, setNotes] = useState([]);
  useEffect(() => {
    loadNotes().then(setNotes);
  }, []);
  return (
    <ul>
      {notes.map((n) => (
        <li key={n[0]}>
          {n[1]} <button onClick={() => removeNote(n[0])}>Delete</button>
        </li>
      ))}
    </ul>
  );
}
'''

MAIN_JSX = '''\
import { createRoot } from "react-dom/client";
import App from "./App";

createRoot(document.getElementById("root")).render(<App />);
'''

BASE = {
    "pyproject.toml": '[project]\nname = "notes"\nversion = "0.1.0"\ndependencies = ["fastapi==0.115.0"]\n',
    "api/__init__.py": "",
    "api/app.py": APP,
    "api/store.py": STORE,
    "web/package.json": '{"name": "web", "private": true, "dependencies": {"react": "18.3.1", "react-dom": "18.3.1"}}\n',
    "web/src/api.js": API_JS,
    "web/src/App.jsx": APP_JSX,
    "web/src/main.jsx": MAIN_JSX,
}

# ---- the planted changes and their twins: each is the base with a few lines more or other
EXPORT_OPEN = '''

@app.post("/api/admin/export")
def export_everything(target: str):
    return store.all_notes(target)
'''
EXPORT_ASKS = '''

@app.post("/api/admin/export")
def export_everything(target: str, user=Depends(current_user)):
    return store.all_notes(user)
'''
DELETE_ASKS = '''def delete_note(note_id: int, user=Depends(current_user)):
    store.remove(note_id, user)
'''
DELETE_OPEN = '''def delete_note(note_id: int):
    store.remove(note_id, "anyone")
'''
BACKUP = '''

def backup(name):
    import subprocess
    subprocess.run("tar czf " + name + " notes.db", shell=True)
'''
BACKUP_ROUTE = '''

@app.post("/api/backup")
def make_backup(name: str, user=Depends(current_user)):
    store.backup(name)
    return {"made": name}
'''
BACKUP_NIGHTLY = '''

def nightly():
    backup("nightly")
'''


def changed(files: dict, **swaps) -> dict:
    """`files` with, for each `path=(old, new)`, that one text swapped (it must stand there once), or with
    `path=text` added at the file's end."""
    out = dict(files)
    for key, how in swaps.items():
        path = {"app": "api/app.py", "store": "api/store.py", "api": "web/src/api.js", "page": "web/src/App.jsx"}[key]
        if isinstance(how, tuple):
            old, new = how
            assert out[path].count(old) == 1, (path, old)
            out[path] = out[path].replace(old, new)
        else:
            out[path] = out[path] + how
    return out


def write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


class Checks:
    """The whole analysis of a version of the app, once per version however many tests ask for it."""

    def __init__(self, folder):
        self.folder, self.done = folder, {}

    def of(self, files: dict, label: str) -> dict:
        key = json.dumps(files, sort_keys=True)
        if key not in self.done:
            repo = self.folder / f"v{len(self.done)}" / "notes"
            write(repo, files)
            out = self.folder / f"v{len(self.done)}" / "out"
            pipeline.analyze(repo, out, offline=True, log=lambda *_: None)
            self.done[key] = out
        return diff.load(self.done[key], label=label)

    def receipt(self, base: dict, head: dict) -> dict:
        return diff.compare(self.of(base, "before"), self.of(head, "after"))


@pytest.fixture(scope="module")
def checks(tmp_path_factory):
    return Checks(tmp_path_factory.mktemp("diff"))


def words(rows) -> list[str]:
    return [r["words"] for r in rows]


# ------------------------------------------------------------------------------------------------ nothing changed
def test_the_same_code_twice_is_no_change(checks):
    r = checks.receipt(BASE, BASE)
    assert r["same"] is True and not any(r["counts"].values()), r["counts"]
    assert r["release"]["changed"] is False
    text = diff.markdown(r)
    assert text.startswith(diff.MARK) and "No door was added or removed" in text


def test_a_comment_and_other_spacing_are_no_change(checks):
    """The twin of every test below: the files differ, the app does not."""
    head = changed(BASE,
                   app=("def list_notes(user=Depends(current_user)):\n    return store.all_notes(user)\n",
                        "def list_notes(user = Depends(current_user)):\n    # everything this user wrote\n\n"
                        "    return store.all_notes( user )\n"),
                   api=("export async function loadNotes() {\n  const res = await fetch(\"/api/notes\");\n",
                        "// the list\nexport async function loadNotes() {\n\n      const res = await fetch(\"/api/notes\");  // all of them\n"))
    assert head != BASE
    r = checks.receipt(BASE, head)
    assert r["same"] is True, (r["counts"], r["touches"]["changed"])
    assert r["touches"]["changed"] == [] and r["doors"]["login_changed"] == [] and r["links"]["broken"] == []


# ------------------------------------------------------------------------------------------------------ new doors
def test_a_new_route_that_asks_nobody_who_is_calling_is_named(checks):
    r = checks.receipt(BASE, changed(BASE, app=EXPORT_OPEN))
    assert words(r["doors"]["added"]) == ["POST /api/admin/export"]
    door = r["doors"]["added"][0]
    assert door["login"]["state"] == "none" and door["login"]["changes"] is True and door["file"] == "api/app.py"
    assert r["counts"]["doors_added"] == 1 and r["counts"]["doors_added_open"] == 1 and r["same"] is False
    assert r["doors"]["removed"] == [] and r["doors"]["login_changed"] == [] and r["links"]["broken"] == []
    text = diff.markdown(r)
    assert "**Added** `POST /api/admin/export` (api/app.py:" in text and "**no login check found**, and it changes data." in text


def test_a_new_route_that_asks_is_added_and_not_called_open(checks):
    r = checks.receipt(BASE, changed(BASE, app=EXPORT_ASKS))
    assert words(r["doors"]["added"]) == ["POST /api/admin/export"]
    door = r["doors"]["added"][0]
    assert door["login"]["state"] == "shown" and "current_user" in door["login"]["why"]
    assert r["counts"]["doors_added"] == 1 and r["counts"]["doors_added_open"] == 0
    text = diff.markdown(r)
    assert "no login check found" not in text and "a login check is shown" in text


def test_a_removed_route_is_named(checks):
    r = checks.receipt(changed(BASE, app=EXPORT_ASKS), BASE)
    assert words(r["doors"]["removed"]) == ["POST /api/admin/export"] and r["doors"]["added"] == []


# ------------------------------------------------------------------------------------------------- a login check
def test_a_login_check_taken_off_a_route_is_named(checks):
    r = checks.receipt(BASE, changed(BASE, app=(DELETE_ASKS, DELETE_OPEN)))
    assert [(d["words"], d["before"]["state"], d["after"]["state"], d["weaker"]) for d in r["doors"]["login_changed"]] == [
        ("DELETE /api/notes/{note_id}", "shown", "none", True)]
    assert r["counts"]["logins_weaker"] == 1 and r["doors"]["added"] == [] and r["doors"]["removed"] == []
    assert "**Login check weaker** on `DELETE /api/notes/{note_id}`" in diff.markdown(r)
    assert [f["name"] for f in r["touches"]["changed"]] == ["delete_note"]


def test_a_login_check_put_on_a_route_is_stronger_not_weaker(checks):
    r = checks.receipt(changed(BASE, app=(DELETE_ASKS, DELETE_OPEN)), BASE)
    assert [(d["words"], d["weaker"]) for d in r["doors"]["login_changed"]] == [("DELETE /api/notes/{note_id}", False)]
    assert r["counts"]["logins_weaker"] == 0 and "Login check stronger" in diff.markdown(r)


# ------------------------------------------------------------------------------ the link between page and server
def test_a_route_renamed_under_a_page_that_still_asks_the_old_one_is_a_broken_link(checks):
    head = changed(BASE, app=('@app.delete("/api/notes/{note_id}")', '@app.delete("/api/note/{note_id}")'))
    r = checks.receipt(BASE, head)
    assert [(x["words"], x["file"]) for x in r["links"]["broken"]] == [("DELETE /api/notes/{}", "web/src/api.js")]
    became = r["links"]["broken"][0]["became"]
    assert [(b["what"], b["now"]) for b in became] == [("path", "DELETE /api/note/{note_id}")]
    assert r["counts"]["links_broken"] == 1
    assert [(m["before"], m["after"]) for m in r["doors"]["moved"]] == [
        ("DELETE /api/notes/{note_id}", "DELETE /api/note/{note_id}")]
    assert r["doors"]["added"] == [] and r["doors"]["removed"] == []
    text = diff.markdown(r)
    assert "**Broken**: web/src/api.js:" in text and "has another path now: `DELETE /api/note/{note_id}`" in text


def test_a_route_that_answers_another_verb_now_is_a_broken_link(checks):
    head = changed(BASE, app=('@app.delete("/api/notes/{note_id}")', '@app.post("/api/notes/{note_id}")'))
    r = checks.receipt(BASE, head)
    assert [x["words"] for x in r["links"]["broken"]] == ["DELETE /api/notes/{}"]
    assert [(b["what"], b["now"]) for b in r["links"]["broken"][0]["became"]] == [("verb", "POST /api/notes/{note_id}")]


def test_page_and_server_renamed_together_break_no_link(checks):
    head = changed(BASE, app=('@app.delete("/api/notes/{note_id}")', '@app.delete("/api/note/{note_id}")'),
                   api=("fetch(`/api/notes/${id}`", "fetch(`/api/note/${id}`"))
    r = checks.receipt(BASE, head)
    assert r["links"]["broken"] == [] and r["links"]["unanswered"] == [] and r["counts"]["links_broken"] == 0
    assert [(m["before"], m["after"]) for m in r["doors"]["moved"]] == [
        ("DELETE /api/notes/{note_id}", "DELETE /api/note/{note_id}")]


def test_a_new_request_of_the_page_that_no_route_answers_is_named(checks):
    more = '\nexport async function pinNote(id) {\n  await fetch(`/api/notes/${id}/pin`, { method: "POST" });\n}\n'
    r = checks.receipt(BASE, changed(BASE, api=more))
    assert [x["words"] for x in r["links"]["unanswered"]] == ["POST /api/notes/{}/pin"] and r["links"]["broken"] == []


# ------------------------------------------------------------------------------------------------------- findings
def test_a_finding_a_route_reaches_now_is_named(checks):
    pytest.importorskip("bandit")
    base = changed(BASE, store=BACKUP)
    r = checks.receipt(base, changed(base, app=BACKUP_ROUTE))
    reached = r["findings"]["now_reached"]
    assert reached and {(f["file"], f["reached"], f["door"]["words"]) for f in reached} == {("api/store.py", True, "POST /api/backup")}
    shell = [f for f in reached if f["rule"] == "B602"]          # the command built from a name and run by the shell
    assert [(f["rank_before"], f["rank"]) for f in shell] == [("high", "critical")]
    assert all(f["file"] != "api/store.py" for f in r["findings"]["new"])      # it was there before: not new
    assert r["counts"]["findings_now_reached"] == len(reached)
    assert "1 critical or high finding a door reaches now" in r["release"]["words"]
    assert "**Reached now** (it was in the code before, and no door reached it)" in diff.markdown(r)


def test_the_same_helper_called_by_something_no_door_reaches_is_not_reached(checks):
    pytest.importorskip("bandit")
    base = changed(BASE, store=BACKUP)
    r = checks.receipt(base, changed(base, store=BACKUP_NIGHTLY))
    assert r["findings"]["now_reached"] == [] and r["counts"]["findings_now_reached"] == 0
    assert [f["name"] for f in r["touches"]["added"]] == ["nightly"]


def test_a_new_serious_finding_moves_the_release_decision(checks):
    pytest.importorskip("bandit")
    head = changed(changed(BASE, store=BACKUP), app=BACKUP_ROUTE)
    r = checks.receipt(BASE, head)
    assert r["release"]["before"]["decision"] != "Blocked" and r["release"]["after"]["decision"] == "Blocked"
    assert r["release"]["changed"] is True and "→ Blocked (" in r["release"]["words"]
    new = [f for f in r["findings"]["new"] if f["file"] == "api/store.py"]
    assert new and new[0]["rank"] in ("critical", "high") and new[0]["reached"] is True
    assert "new critical or high finding" in r["release"]["words"]
    back = checks.receipt(head, BASE)
    assert [f["file"] for f in back["findings"]["fixed"] if f["rank"] in ("critical", "high")] == ["api/store.py"]
    assert back["release"]["after"]["decision"] != "Blocked" and back["release"]["changed"] is True


# -------------------------------------------------- a finding somebody answered for, and one that weighs more now
SHELL_LINE = '    subprocess.run("tar czf " + name + " notes.db", shell=True)\n'
REASON = "only the nightly job calls it, with a fixed name"
SHELL_LINE_SAID = SHELL_LINE.rstrip("\n") + f"  # nosec B602: {REASON}\n"


def test_a_finding_answered_for_by_a_comment_in_the_code_is_accepted_and_not_fixed(checks):
    """The comment changes the line's text, and with it the finding's id: the old id is gone, and the line is as
    risky as it was. A receipt that called it fixed would say what no tool found."""
    pytest.importorskip("bandit")
    risky = changed(changed(BASE, store=BACKUP), store=BACKUP_NIGHTLY)
    said = changed(risky, store=(SHELL_LINE, SHELL_LINE_SAID))
    r = checks.receipt(risky, said)
    assert r["findings"]["fixed"] == [] and r["counts"]["findings_fixed"] == 0
    assert [(f["rule"], f["file"], f["how"], f["reason"], f.get("came")) for f in r["findings"]["accepted"]] == [
        ("B602", "api/store.py", "nosec", REASON, None)]
    assert r["counts"]["findings_accepted"] == 1 and r["same"] is False
    assert r["findings"]["new"] == [] and r["findings"]["still_open"] == []
    text = diff.markdown(r)
    assert f"**Accepted in this change** (a `# nosec` comment: “{REASON}”)" in text and "Fixed ·" not in text
    assert "1 finding accepted" in diff.summary_line(r) and "fixed" not in diff.summary_line(r)
    assert "accepted here" in diff.page(r)


def test_the_comment_taken_off_again_opens_the_finding_again(checks):
    pytest.importorskip("bandit")
    risky = changed(changed(BASE, store=BACKUP), store=BACKUP_NIGHTLY)
    r = checks.receipt(changed(risky, store=(SHELL_LINE, SHELL_LINE_SAID)), risky)
    assert [(f["rule"], f["file"]) for f in r["findings"]["reopened"]] == [("B602", "api/store.py")]
    assert r["findings"]["new"] == [] and r["counts"]["findings_new"] == 0 and r["counts"]["findings_reopened"] == 1
    assert "Open again (it was accepted before)" in diff.markdown(r) and "1 finding open again" in diff.summary_line(r)


def test_a_finding_that_comes_with_its_own_comment_is_listed_as_accepted_and_as_new_here(checks):
    """A change that adds a risky line and its excuse at once is not a change with nothing to say about findings."""
    pytest.importorskip("bandit")
    said = changed(changed(changed(BASE, store=BACKUP), store=BACKUP_NIGHTLY), store=(SHELL_LINE, SHELL_LINE_SAID))
    r = checks.receipt(BASE, said)
    shell = [f for f in r["findings"]["accepted"] if f["rule"] == "B602"]
    assert [(f["file"], f["how"], f["reason"], f["came"]) for f in shell] == [("api/store.py", "nosec", REASON, True)]
    assert all(f["rule"] != "B602" for f in r["findings"]["new"])
    assert "(new here; a `# nosec` comment" in diff.markdown(r) and "new here" in diff.page(r)
    back = checks.receipt(said, BASE)           # twin: the line and its comment removed together: nothing was fixed,
    assert all(f["rule"] != "B602" for f in back["findings"]["fixed"])      # because nothing was open
    assert back["findings"]["reopened"] == []


def test_a_finding_accepted_in_the_accepted_file_keeps_its_id_and_is_accepted(checks):
    pytest.importorskip("bandit")
    risky = changed(changed(BASE, store=BACKUP), store=BACKUP_NIGHTLY)
    [was] = [f for f in checks.of(risky, "before")["security"]["findings"] if f["rule"] == "B602"]
    listed = dict(risky) | {"lantern-accepted.json": json.dumps({"accepted": [
        {"id": was["id"], "reason": "the name is fixed text in every caller", "by": "a reviewer", "date": "2026-11-16"}]})}
    r = checks.receipt(risky, listed)
    assert [(f["id"], f["how"], f["reason"]) for f in r["findings"]["accepted"]] == [
        (was["id"], "accepted", "the name is fixed text in every caller")]
    assert r["findings"]["fixed"] == [] and r["counts"]["findings_accepted"] == 1
    assert "**Accepted in this change** (lantern accept: “the name is fixed text in every caller”)" in diff.markdown(r)
    back = checks.receipt(listed, risky)
    assert [f["id"] for f in back["findings"]["reopened"]] == [was["id"]] and back["counts"]["findings_reopened"] == 1


def test_a_finding_that_weighs_more_after_the_change_is_named_and_counted(checks):
    """The line was there and a route reached it; what changed is that the route hands it the request's own text."""
    pytest.importorskip("bandit")
    risky = changed(changed(BASE, store=BACKUP), app=BACKUP_ROUTE)
    tame = changed(risky, app=("    store.backup(name)\n", '    store.backup("nightly")\n'))
    r = checks.receipt(tame, risky)
    assert [(f["rule"], f["rank_before"], f["rank"], f["raised"], f["door"]["words"]) for f in r["findings"]["rank_changed"]] == [
        ("B602", "low", "critical", True, "POST /api/backup")]
    assert r["counts"]["findings_raised"] == 1 and r["findings"]["new"] == [] and r["findings"]["now_reached"] == []
    assert r["release"]["after"]["decision"] == "Blocked" and "1 finding now ranked critical or high" in r["release"]["words"]
    assert "**Ranked higher** (was low)" in diff.markdown(r) and "1 finding ranked higher" in diff.summary_line(r)
    back = checks.receipt(risky, tame)          # twin: the other way it weighs less, and nothing is called fixed
    assert [(f["rank_before"], f["rank"], f["raised"]) for f in back["findings"]["rank_changed"]] == [("critical", "low", False)]
    assert back["counts"]["findings_raised"] == 0 and back["findings"]["fixed"] == [] and back["same"] is False
    assert "Ranked lower (was critical)" in diff.markdown(back) and "ranked higher" not in diff.summary_line(back)


def test_what_moved_the_decision_is_said_in_words_that_count_more_than_one_rightly(checks):
    side = checks.of(BASE, "before")
    two = lambda **more: [{"rank": "high", **more}, {"rank": "critical", **more}]  # noqa: E731
    none = {k: [] for k in ("new", "fixed", "still_open", "now_reached", "rank_changed", "accepted", "reopened")}
    why = diff._compare_release(side, side, none | {
        "new": two(), "now_reached": two(), "rank_changed": two(raised=True, rank_before="low"), "reopened": two(),
        "fixed": two(), "accepted": two()})["why"]
    assert why == ["2 new critical or high findings", "2 critical or high findings a door reaches now",
                   "2 findings now ranked critical or high", "2 critical or high findings open again",
                   "2 critical or high findings fixed", "2 critical or high findings accepted in this change"]
    one = diff._compare_release(side, side, none | {"fixed": two()[:1], "accepted": two(came=True)})["why"]
    assert one == ["1 critical or high finding fixed"]      # one that came with its acceptance moved nothing
    lower = diff._compare_release(side, side, none | {"rank_changed": two(raised=False, rank_before="low")})["why"]
    assert lower == [] and diff._compare_release(side, side, none)["why"] == []


# ----------------------------------------------------------------------------------------- calls that cost money
SUMMARISE = '''

@app.post("/api/summarise")
def summarise(text: str, user=Depends(current_user)):
    from openai import OpenAI
    return OpenAI().chat.completions.create(model="m", messages=[{"role": "user", "content": text}])
'''
SUMMARY_HELPER = '''

def summary_of(text):
    from openai import OpenAI
    return OpenAI().chat.completions.create(model="m", messages=[{"role": "user", "content": text}])
'''
SUMMARY_ROUTE = '''

@app.post("/api/summarise")
def summarise(text: str, user=Depends(current_user)):
    return store.summary_of(text)
'''


def test_a_paid_call_a_new_route_reaches_is_named(checks):
    r = checks.receipt(BASE, changed(BASE, app=SUMMARISE))
    [p] = r["paid"]
    assert (p["kind"], p["detail"], (p["login"] or {}).get("state")) == ("route", "POST /api/summarise", "shown")
    assert [(c["kind"], c["provider"], c["file"]) for c in p["calls"]] == [("model", "OpenAI", "api/app.py")]
    assert p["in"]["node"] == "py:api.app.summarise" and r["counts"]["paid_new"] == 1
    assert r["touches"]["paid"] == ["model (OpenAI)"]
    assert "### Calls that cost money" in diff.markdown(r) and "now reaches a paid call (model · OpenAI" in diff.markdown(r)
    assert "1 new way to a paid call" in diff.summary_line(r) and "now reaches a call that costs money" in diff.page(r)


def test_a_paid_call_no_door_reaches_is_no_way_to_it_until_a_route_calls_it(checks):
    helper = changed(BASE, store=SUMMARY_HELPER)
    r = checks.receipt(BASE, helper)
    assert r["paid"] == [] and r["counts"]["paid_new"] == 0 and [f["name"] for f in r["touches"]["added"]] == ["summary_of"]
    assert "### Calls that cost money" not in diff.markdown(r)
    wired = checks.receipt(helper, changed(helper, app=SUMMARY_ROUTE))     # the call was there; the way to it is new
    [p] = wired["paid"]
    assert (p["detail"], p["in"]["node"], p["in"]["file"]) == ("POST /api/summarise", "py:api.store.summary_of", "api/store.py")
    assert wired["counts"]["paid_new"] == 1
    same = checks.receipt(changed(BASE, app=SUMMARISE), changed(BASE, app=SUMMARISE))      # reached before and after
    assert same["paid"] == [] and same["same"] is True


# -------------------------------------------------------------------- links that were mended, routes nobody asks
def test_a_route_put_back_where_the_page_asks_mends_the_link(checks):
    lost = changed(BASE, app=('@app.delete("/api/notes/{note_id}")', '@app.delete("/api/note/{note_id}")'))
    r = checks.receipt(lost, BASE)
    assert [(m["words"], m["file"], words(m["answered_by"])) for m in r["links"]["mended"]] == [
        ("DELETE /api/notes/{}", "web/src/api.js", ["DELETE /api/notes/{note_id}"])]
    assert r["links"]["broken"] == [] and r["links"]["unanswered"] == [] and r["same"] is False
    assert [(d["before"], d["after"]) for d in r["doors"]["moved"]] == [("DELETE /api/note/{note_id}", "DELETE /api/notes/{note_id}")]
    assert "answers now." in diff.markdown(r) and "1 door moved" in diff.summary_line(r)


def test_a_route_the_page_stops_asking_is_named_and_is_no_broken_link(checks):
    quiet = changed(BASE, api=('  await fetch(`/api/notes/${id}`, { method: "DELETE" });\n', "  return id;\n"))
    r = checks.receipt(BASE, quiet)
    assert words(r["links"]["unasked"]) == ["DELETE /api/notes/{note_id}"]
    assert r["links"]["broken"] == [] and r["doors"]["removed"] == [] and r["same"] is False
    assert "any more; the route is still there." in diff.markdown(r)
    back = checks.receipt(quiet, BASE)          # twin: the page asks again, and a route answers: nothing to mend
    assert back["links"]["unasked"] == [] and back["links"]["mended"] == [] and back["links"]["broken"] == []


# -------------------------------------------------------------------------------------------- what a change touches
def test_what_a_changed_function_touches_is_followed_up_to_the_doors_and_down_to_the_data(checks):
    head = changed(BASE, store=('"delete from notes where id = ? and owner = ?"', '"delete from notes where owner = ? and id = ?"'))
    r = checks.receipt(BASE, head)
    t = r["touches"]
    assert [f["name"] for f in t["changed"]] == ["remove"] and t["added"] == [] and t["removed"] == []
    assert "DELETE /api/notes/{note_id}" in words(t["doors"])
    assert ("main", "app start (web/src/main.jsx)") in [(d["kind"], d["words"]) for d in t["doors"]]   # the page that asks the route
    assert "GET /api/notes" not in words(t["doors"])
    assert any("sqlite3" in x for x in t["reaches"]["outside"]), t["reaches"]
    assert r["doors"]["added"] == [] and r["links"]["broken"] == [] and r["same"] is False


# ------------------------------------------------------------------------------------- results Lantern can use
def test_a_folder_that_holds_no_results_is_refused_with_a_sentence(tmp_path):
    with pytest.raises(diff.NotResults, match="does not hold the results of a check: graph.json is missing"):
        diff.load(tmp_path)


def test_results_that_are_damaged_or_no_plain_file_are_refused_with_a_sentence_too(checks, tmp_path):
    good = Path(checks.of(BASE, "before")["out"])
    for n, (name, make) in enumerate([
            ("security.json", lambda f: f.write_text("{", encoding="utf-8")),                  # cut off
            ("readiness.json", lambda f: f.write_text("[" * 200_000, encoding="utf-8")),       # nested too deep
            ("graph.json", lambda f: f.write_text("[1, 2]", encoding="utf-8")),                # another shape
            ("graph.json", lambda f: f.symlink_to(good / "graph.json"))]):                     # a link, also to a good file
        folder = tmp_path / f"r{n}"
        folder.mkdir()
        for other in diff.FILES:
            (folder / other).write_bytes((good / other).read_bytes())
        (folder / name).unlink()
        try:
            make(folder / name)
        except OSError:                 # a system that lets this user make no link
            continue
        with pytest.raises(diff.NotResults, match="does not hold the results of a check") as e:
            diff.load(folder)
        assert name in str(e.value), (n, str(e.value))
    assert diff.load(good)["graph"]["nodes"]                 # the twin: the good folder is taken


def test_results_of_an_older_lantern_are_compared_without_the_login_record_and_the_receipt_says_so(checks, tmp_path):
    base, head = checks.of(BASE, "before"), checks.of(changed(BASE, app=EXPORT_OPEN), "after")
    old = dict(base, security={k: v for k, v in base["security"].items() if k != "route_logins"})
    r = diff.compare(old, head)
    assert words(r["doors"]["added"]) == ["POST /api/admin/export"]
    assert any("does not write down what each route shows about a login" in x for x in r["limits"])
    newer = diff.compare(base, head)
    assert not any("does not write down" in x for x in newer["limits"])


def another(folder, out, **parts) -> Path:
    """A copy of one check's results in which, for each `name=change`, that file's table went through `change`."""
    folder.mkdir(parents=True)
    for p in Path(out).iterdir():
        if p.is_file():
            (folder / p.name).write_bytes(p.read_bytes())
    for name, change in parts.items():
        table = json.loads((folder / f"{name}.json").read_text(encoding="utf-8"))
        change(table)
        (folder / f"{name}.json").write_text(json.dumps(table), encoding="utf-8")
    return folder


def test_two_checks_made_by_two_lanterns_are_compared_and_the_receipt_says_what_that_may_mean(checks, tmp_path):
    """What an older Lantern found in the same code may differ for the Lantern alone: a rule added since, a rank
    worked out another way. A receipt that lists such a difference as the change's own has to say so."""
    import lantern
    base, head = checks.of(BASE, "before"), checks.of(changed(BASE, app=EXPORT_OPEN), "after")
    said = "different versions of Lantern"
    r = diff.compare(base, head)
    assert (r["base"]["lantern"], r["head"]["lantern"]) == (lantern.__version__, lantern.__version__)
    assert not any(said in x or "which version of Lantern" in x for x in r["limits"])
    older = diff.load(another(tmp_path / "older", base["out"], run=lambda t: t.update(lantern="0.10.0")), label="before")
    r = diff.compare(older, head)
    assert r["base"]["lantern"] == "0.10.0" and words(r["doors"]["added"]) == ["POST /api/admin/export"]
    assert any(f"{said} (0.10.0 before the change, {lantern.__version__} after)" in x for x in r["limits"]), r["limits"]
    assert said in diff.markdown(r) and said in diff.page(r)
    unsaid = diff.load(another(tmp_path / "unsaid", base["out"], run=lambda t: t.pop("lantern")), label="before")
    r = diff.compare(unsaid, head)
    assert r["base"]["lantern"] is None
    assert any("before the change does not say which version of Lantern made it" in x for x in r["limits"])
    (tmp_path / "unsaid" / "run.json").unlink()             # results with no record of the run at all: the same
    assert diff.compare(diff.load(tmp_path / "unsaid"), head)["base"]["lantern"] is None
    for odd in (HOSTILE, "9" * 300, ["0.11.0"], 11):          # what stands there is repeated only when it is a version
        made = diff.load(another(tmp_path / f"odd{len(str(odd))}", base["out"], run=lambda t, odd=odd: t.update(lantern=odd)))
        r = diff.compare(made, head)
        assert r["base"]["lantern"] is None and "onerror" not in diff.page(r) and "9" * 40 not in diff.markdown(r)


def test_findings_that_two_checks_name_in_two_ways_are_not_compared(checks, tmp_path):
    """A finding is the same on both sides by its id. Where the two checks make ids in different ways, every finding
    would read as fixed and as new: nothing about findings is said then, and the receipt says why."""
    pytest.importorskip("bandit")
    base, head = checks.of(BASE, "before"), checks.of(changed(changed(BASE, store=BACKUP), app=BACKUP_ROUTE), "after")
    assert diff.compare(base, head)["findings"]["new"]          # twin: named the same way, the new finding is listed
    other = diff.load(another(tmp_path / "other", base["out"], security=lambda t: t.update(id_version=1)), label="before")
    r = diff.compare(other, head)
    assert all(rows == [] for rows in r["findings"].values())
    assert not any(n for k, n in r["counts"].items() if k.startswith("findings_"))
    assert any("findings are not compared" in x for x in r["limits"]), r["limits"]
    assert "finding" not in " ".join(r["release"]["why"])       # and no finding is given as what moved the decision
    assert words(r["doors"]["added"]) == ["POST /api/backup"] and r["same"] is False     # the rest is compared
    assert "### Findings" not in diff.markdown(r) and "findings are not compared" in diff.markdown(r)


# ------------------------------------------------------------------------------------------- the receipt's forms
HOSTILE = '`</code><img src=x onerror=alert(1)>\n## a heading | [a link](https://example.invalid) <script>alert(2)</script>'


def poisoned(checks) -> dict:
    """A receipt in which every text that comes from a project is hostile."""
    r = json.loads(json.dumps(checks.receipt(BASE, changed(changed(BASE, app=EXPORT_OPEN), app=(DELETE_ASKS, DELETE_OPEN)))))

    def soil(x):
        if isinstance(x, dict):
            return {k: (HOSTILE if isinstance(v, str) and k in ("words", "detail", "file", "name", "title", "why", "label",
                                                                 "before_words", "after_words", "now_words", "rule")
                        else soil(v)) for k, v in x.items()}
        return [soil(v) for v in x] if isinstance(x, list) else x
    return soil(r)


def outside_code(text: str) -> str:
    """The text as GitHub reads it outside its code spans: a character with a backslash in front is no mark."""
    return re.sub(r"`[^`\n]*`", "", re.sub(r"\\.", "", text))


def test_text_of_a_project_cannot_write_markdown_of_its_own(checks):
    text = diff.markdown(poisoned(checks))
    for line in text.splitlines():
        assert not line.startswith("## a heading"), line
        assert len(re.findall(r"(?<!\\)`", line)) % 2 == 0, line      # no code span is left open or closed early
    # inside a code span GitHub shows every character as itself; outside one nothing of the project is HTML or a link
    outside = outside_code(text)
    assert "<img" not in outside and "<script" not in outside and "onerror=alert(1)>" not in outside
    assert "](https://" not in outside and "[a link](" not in outside


NAMES_SOMEBODY = "@octocat fixes #12, see https://example.invalid/x and www.example.invalid"


def test_text_of_a_project_names_nobody_and_links_nowhere(checks):
    """On GitHub a plain `@name` sends that person a notice, `#12` becomes a link to an issue and an address a link.
    Outside a code span the receipt's text breaks each of them, as the report's comment does (`onrepo.md`)."""
    r = json.loads(json.dumps(poisoned(checks)).replace(json.dumps(HOSTILE)[1:-1], NAMES_SOMEBODY))
    for text in (diff.markdown(r), diff.markdown(r, short=True)):
        outside = outside_code(text)
        assert "octocat" in outside                        # the text is shown, as text
        assert "@octocat" not in outside and "https://" not in outside and "www.example" not in outside
        assert not re.search(r"(?<![\\&\w])#12", outside)


def test_a_long_sentence_among_the_limits_is_text_too(checks):
    """A scanner's name comes out of a results file, which may be anybody's: however long it is, it is written as
    text (until this test a line of more than 300 characters among the limits was written as it came)."""
    base, head = checks.of(BASE, "x"), dict(checks.of(BASE, "x"))
    head["security"] = dict(head["security"], incomplete=[{"tool": "<img src=x> [a](https://example.invalid) " * 12}])
    text = diff.markdown(diff.compare(base, head))
    assert "<img" not in text and "](https://" not in text


def test_a_part_of_the_decision_that_one_side_alone_was_checked_for_is_said(checks):
    """The Action checks the code before a pull request without running its tests. Where the workflow ran them on the
    pull request itself, "Incomplete → Passed" is no doing of the pull request, and the receipt has to say so."""
    def with_tests(side, state):
        side = json.loads(json.dumps({k: v for k, v in side.items()}))
        for c in side["readiness"]["release"]["criteria"]:
            if c["id"] == "tests":
                c["state"] = state
        return side
    base = checks.of(BASE, "x")
    said = diff.compare(base, with_tests(base, "passed"))
    line = [x for x in said["limits"] if x.startswith("Not everything was checked on both sides")]
    assert line and "the project's tests (only after the change)" in line[0], said["limits"]
    assert "tests: missing → passed" in said["release"]["words"]
    assert "run on neither side" not in " ".join(said["limits"])
    back = diff.compare(with_tests(base, "passed"), base)
    assert "the project's tests (only before the change)" in " ".join(back["limits"])
    for same in ("passed", "missing"):                 # checked on both sides, or on neither: nothing to say
        both = diff.compare(with_tests(base, same), with_tests(base, same))
        assert "Not everything was checked on both sides" not in " ".join(both["limits"])


def test_the_comment_on_a_pull_request_holds_the_receipt_and_stays_within_what_github_takes(checks, monkeypatch):
    after = changed(BASE, app=EXPORT_OPEN)
    r = checks.receipt(BASE, after)
    ev = onrepo.read(Path(checks.of(after, "x")["out"]))
    plain = onrepo.summary(ev, short=True)
    text = onrepo.summary(ev, short=True, change=r)
    assert text.startswith(onrepo.MARKER) and len(text) <= onrepo.MOST_COMMENT
    assert "## Lantern: what this change does" in text and "**Added** `POST /api/admin/export`" in text
    # what the change does comes first, then the project as a whole, under a heading of its own
    assert text.index("what this change does") < text.index("## The project as a whole") < text.index("| Critical | High |")
    assert "what this change does" not in plain and "The project as a whole" not in plain
    assert "The functions" not in text and "The functions" in onrepo.summary(ev, change=r)     # short: without the list
    # a receipt longer than its share is cut at a line, says so, and leaves nothing folded open
    monkeypatch.setattr(onrepo, "MOST_CHANGE", 900)
    cut = onrepo.summary(ev, change=r)
    part = cut[cut.index("what this change does"):cut.index("## The project as a whole")]
    assert len(part) < 1100 and "cut short" in part and part.count("<details>") == part.count("</details>")
    assert "| Critical | High |" in cut
    # a file of another shape under the receipt's name is said, and the report is still made
    for odd in ({}, {"schema": 1}, {"schema": 1, "doors": []}, [1], "x", dict(r, release=7), dict(r, doors={"added": [5]})):
        said = onrepo.summary(ev, short=True, change=odd)
        assert "could not be read" in said and "| Critical | High |" in said, odd


def test_the_page_runs_no_script_and_escapes_every_value(checks):
    page = diff.page(poisoned(checks))
    assert "<script" not in page and "<img" not in page and "onerror=alert(1)&gt;" in page
    assert "Content-Security-Policy" in page and "default-src 'none'" in page and "script-src" not in page
    import base64
    import hashlib
    import re
    style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(style.encode("utf-8")).digest()).decode("ascii")
    assert f"style-src 'sha256-{digest}'" in page
    assert " on" not in " ".join(re.findall(r"<[a-z][^>]*>", page)).replace(" one", "")  # no event attribute in any tag
    assert "style=" not in page


def test_the_three_files_are_written_as_result_files(checks, tmp_path):
    r = checks.receipt(BASE, changed(BASE, app=EXPORT_OPEN))
    paths = diff.write(tmp_path / "change", r)
    assert sorted(p.name for p in paths.values()) == ["change.html", "change.json", "change.md"]
    assert json.loads(paths["json"].read_text(encoding="utf-8")) == json.loads(json.dumps(r))
    assert paths["md"].read_text(encoding="utf-8").startswith(diff.MARK)
    assert paths["html"].read_text(encoding="utf-8").startswith("<!doctype html>")
    link = tmp_path / "elsewhere.txt"
    link.write_text("the person's own file", encoding="utf-8")
    (tmp_path / "change" / "change.md").unlink()
    try:
        (tmp_path / "change" / "change.md").symlink_to(link)
    except (OSError, NotImplementedError):
        return
    diff.write(tmp_path / "change", r)
    assert link.read_text(encoding="utf-8") == "the person's own file"      # a link under that name is replaced, not followed


def test_one_line_for_a_log(checks):
    r = checks.receipt(BASE, changed(BASE, app=EXPORT_OPEN))
    line = diff.summary_line(r)
    assert line.startswith("release decision ") and "1 new door" in line
    assert diff.summary_line(checks.receipt(BASE, BASE)) == "no change in doors, links, findings or the release decision"


# ------------------------------------------------------------ what "changed" means for each language's reader
ONE_FUNCTION = {     # the map's prefix: (the files, the comment that is put where {c} stands)
    "py": ({"a.py": "def f(x):\n{c}    return x\n"}, "    # a note\n"),
    "js": ({"a.js": "export function f(x) {\n{c}  return x;\n}\n"}, "  // a note\n"),
    "go": ({"go.mod": "module example.com/a\n\ngo 1.22\n", "a.go": "package main\n\nfunc f(x int) int {\n{c}\treturn x\n}\n"},
           "\t// a note\n"),
    "rs": ({"Cargo.toml": '[package]\nname = "a"\nversion = "0.1.0"\n', "src/lib.rs": "pub fn f(x: i32) -> i32 {\n{c}    x\n}\n"},
           "    // a note\n"),
    "jv": ({"A.java": "class A {\n    int f(int x) {\n{c}        return x;\n    }\n}\n"}, "        // a note\n"),
    "kt": ({"A.kt": "fun f(x: Int): Int {\n{c}    return x\n}\n"}, "    // a note\n"),
    "sw": ({"A.swift": "func f(x: Int) -> Int {\n{c}    return x\n}\n"}, "    // a note\n"),
    "dt": ({"a.dart": "int f(int x) {\n{c}  return x;\n}\n"}, "  // a note\n"),
    "cs": ({"A.cs": "class A {\n    int f(int x) {\n{c}        return x;\n    }\n}\n"}, "        // a note\n"),
    "php": ({"a.php": "<?php\nfunction f($x) {\n{c}    return $x;\n}\n"}, "    // a note\n"),
    "rb": ({"a.rb": "def f(x)\n{c}  x\nend\n"}, "  # a note\n"),
    "cc": ({"a.cpp": "int f(int x) {\n{c}  return x;\n}\n"}, "  // a note\n"),
}


@pytest.mark.parametrize("prefix", sorted(ONE_FUNCTION))
def test_whether_a_comment_inside_a_function_reads_as_a_change_is_what_the_receipt_says(prefix, tmp_path):
    """The receipt says "a comment or a reformatting changes none", and names the languages where that is not so
    (`diff.BY_TEXT`). Every reader is asked here, so the sentence cannot go stale when a reader changes."""
    from lantern import engine
    files, comment = ONE_FUNCTION[prefix]
    prints = []
    for name, c in (("plain", ""), ("noted", comment)):
        write(tmp_path / name, {rel: text.replace("{c}", c) for rel, text in files.items()})
        g = engine.build_graph(tmp_path / name)
        fn = [n for n in g.nodes.values() if n.kind == "callable" and n.name == "f" and n.id.startswith(prefix + ":")]
        assert len(fn) == 1 and fn[0].fingerprint, (prefix, [n.id for n in g.nodes.values()])
        prints.append(fn[0].fingerprint)
    assert (prints[0] != prints[1]) == (prefix in diff.BY_TEXT), (prefix, prints)


# ------------------------------------------------------------------------- the command: two commits of a project
def run(args, capsys):
    from lantern.cli import main
    code = main(args)
    said = capsys.readouterr()
    return code, said.out, said.err


def test_the_command_checks_two_commits_and_names_the_planted_change(tmp_path, capsys):
    repo = tmp_path / "notes"
    first = commit(repo, BASE)
    second = commit(repo, changed(BASE, app=EXPORT_OPEN))
    before = held(repo)
    code, out, err = run(["diff", str(repo), "HEAD~1..HEAD", "--offline"], capsys)
    assert code == 0, err
    where = repo / ".lantern" / "change"
    assert [line.split()[-1] for line in out.splitlines() if line.startswith("wrote ")] == [
        str(where / "change.html"), str(where / "change.md"), str(where / "change.json")]
    assert "change  release decision Incomplete → Incomplete: 1 new door" in out
    r = json.loads((where / "change.json").read_text(encoding="utf-8"))
    assert words(r["doors"]["added"]) == ["POST /api/admin/export"] and r["counts"]["doors_added_open"] == 1
    assert (r["base"]["commit"], r["head"]["commit"]) == (first, second)
    assert (r["base"]["label"], r["head"]["label"]) == ("HEAD~1", "HEAD")
    md = (where / "change.md").read_text(encoding="utf-8")
    assert f"Compared `HEAD~1 ({first[:10]})` (before) with `HEAD ({second[:10]})` (after)." in md
    # each side's own results are beside the receipt; the project's files and its results folder are as they were
    assert (where / "before" / "graph.json").is_file() and (where / "after" / "security.json").is_file()
    assert {k: v for k, v in held(repo).items() if not k.startswith(".lantern/")} == before
    assert sorted(p.name for p in (repo / ".lantern").iterdir()) == ["change"]
    assert git("status", "--porcelain", "--untracked-files=no", cwd=repo) == ""


def test_with_no_words_the_last_commit_is_compared_with_the_files_as_they_are(tmp_path, capsys, monkeypatch):
    repo = tmp_path / "notes"
    first = commit(repo, BASE)
    write(repo, changed(BASE, app=(DELETE_ASKS, DELETE_OPEN)))          # changed and not committed
    monkeypatch.chdir(repo)
    code, out, err = run(["diff", "--offline", "--format", "md", "--short"], capsys)
    assert code == 0, err
    assert out.startswith(diff.MARK) and "**Login check weaker** on `DELETE /api/notes/{note_id}`" in out
    assert f"Compared `HEAD ({first[:10]})` (before) with `the files as they are now ({first[:10]} with changes that are not committed)`" in out
    assert "<details><summary>The functions</summary>" not in out
    assert "checking commit " + first[:12] in err and "checking the files as they are now" in err     # the log went beside it


def test_one_word_that_is_no_folder_is_the_two_versions(tmp_path, capsys, monkeypatch):
    repo = tmp_path / "notes"
    first = commit(repo, BASE)
    git("branch", "before-export", first, cwd=repo)
    commit(repo, changed(BASE, app=EXPORT_ASKS))
    monkeypatch.chdir(repo)
    code, out, err = run(["diff", "before-export..main", "--offline", "--format", "json"], capsys)
    assert code == 0, err
    r = json.loads(out)
    assert words(r["doors"]["added"]) == ["POST /api/admin/export"] and r["counts"]["doors_added_open"] == 0
    assert (r["base"]["label"], r["head"]["label"]) == ("before-export", "main")


def test_three_dots_compare_from_where_the_two_parted(tmp_path, capsys):
    repo = tmp_path / "notes"
    commit(repo, BASE)
    git("checkout", "-q", "-b", "feature", cwd=repo)
    commit(repo, changed(BASE, app=EXPORT_OPEN))
    git("checkout", "-q", "main", cwd=repo)
    commit(repo, changed(BASE, app=(DELETE_ASKS, DELETE_OPEN)))          # main went on: not the feature's doing
    code, out, err = run(["diff", str(repo), "main...feature", "--offline", "--format", "json"], capsys)
    assert code == 0, err
    r = json.loads(out)
    assert words(r["doors"]["added"]) == ["POST /api/admin/export"] and r["doors"]["login_changed"] == []
    assert r["base"]["label"] == "where main and feature parted"
    two = run(["diff", str(repo), "main..feature", "--offline", "--format", "json"], capsys)
    assert [d["weaker"] for d in json.loads(two[1])["doors"]["login_changed"]] == [False]      # two dots: main as it is now


def test_checks_already_made_are_used_and_not_made_again(checks, tmp_path, capsys):
    base, head = checks.of(BASE, "x")["out"], checks.of(changed(BASE, app=EXPORT_OPEN), "x")["out"]
    plain = tmp_path / "plain"          # no repository at all: nothing is copied or checked
    plain.mkdir()
    code, out, err = run(["diff", str(plain), "--base-results", base, "--head-results", head, "--out", str(tmp_path / "c"),
                          "--format", "json"], capsys)
    assert code == 0, err
    assert words(json.loads(out)["doors"]["added"]) == ["POST /api/admin/export"]
    assert sorted(p.name for p in (tmp_path / "c").iterdir()) == ["change.html", "change.json", "change.md"]
    assert "checking" not in err


def test_two_checks_a_service_already_holds_give_the_receipt_the_command_gives(checks, tmp_path, capsys):
    """The website's GitHub App will hold a check of each side of a pull request already. From the two results
    folders alone (no repository, no command, no git) the same receipt comes out as the command writes, the page
    the app's server builds from the stored data is the same page, and the text fits a comment."""
    from lantern.server import result_page
    base, head = checks.of(BASE, "x")["out"], checks.of(changed(BASE, app=EXPORT_OPEN), "x")["out"]
    plain, kept = tmp_path / "plain", tmp_path / "results"
    plain.mkdir()
    code, out, err = run(["diff", str(plain), "--base-results", base, "--head-results", head, "--out", str(kept / "change"),
                          "--base-label", "main", "--head-label", "this pull request", "--format", "json"], capsys)
    assert code == 0, err
    made = diff.compare(diff.load(base, label="main"), diff.load(head, label="this pull request"))
    as_stored = json.loads(json.dumps(made))
    assert json.loads(out) == as_stored and diff.read(kept / "change" / "change.json") == as_stored
    assert (kept / "change" / "change.md").read_text(encoding="utf-8") == diff.markdown(made)
    status, page, kind, headers = result_page(kept, "change.html")
    assert status == 200 and page == diff.page(made) and kind.startswith("text/html")
    assert "script-src" not in headers["Content-Security-Policy"] and "default-src 'none'" in headers["Content-Security-Policy"]
    text = diff.markdown(made, short=True)
    assert text.startswith(diff.MARK) and len(text.encode("utf-8")) <= onrepo.MOST_CHANGE and "POST /api/admin/export" in text


def test_a_check_already_made_of_the_files_is_compared_with_a_commit_under_the_names_given(tmp_path, capsys):
    """What Lantern's GitHub Action does on a pull request: the files as they are were checked a moment ago, so only
    the commit before is checked, and the two sides are called what the person calls them."""
    repo = tmp_path / "notes"
    first = commit(repo, BASE)
    second = commit(repo, changed(BASE, app=EXPORT_OPEN))
    made = tmp_path / "made"
    pipeline.analyze(repo, made, offline=True, log=lambda *_: None)
    code, out, err = run(["diff", str(repo), first, "--head-results", str(made), "--out", str(tmp_path / "c"), "--offline",
                          "--base-label", "main", "--head-label", "this pull request", "--format", "md", "--short"], capsys)
    assert code == 0, err
    assert f"Compared `main ({first[:10]})` (before) with `this pull request ({second[:10]})` (after)." in out
    assert "**Added** `POST /api/admin/export`" in out
    assert err.count("checking") == 1 and "before  checking commit" in err         # the files: not a second time
    assert sorted(p.name for p in (tmp_path / "c").iterdir()) == ["before", "change.html", "change.json", "change.md"]
    # the comment's text with the receipt in it, as the Action asks for it
    code, text, err = run(["github", "summary", str(repo), "--out", str(made), "--short",
                           "--change", str(tmp_path / "c" / "change.json")], capsys)
    assert code == 0, err
    assert text.startswith(onrepo.MARKER) and "**Added** `POST /api/admin/export`" in text
    assert "this pull request" in text and "## The project as a whole" in text
    # a receipt that is not there, or is no receipt, is said in the text and the command still gives the report
    (tmp_path / "odd.json").write_text('{"schema": 99}', encoding="utf-8")
    for name in ("nothing.json", "odd.json"):
        code, text, err = run(["github", "summary", str(repo), "--out", str(made), "--short",
                               "--change", str(tmp_path / name)], capsys)
        assert code == 0 and "could not be read" in text and "| Critical | High |" in text, (name, err)


@pytest.mark.parametrize("args, sentence", [
    (["nowhere..HEAD"], "has no branch, tag or commit named 'nowhere'"),
    (["HEAD~7"], "git did not find the commit 'HEAD~7' stands for"),
    (["HEAD@{1}"], "is not a name Lantern takes for a commit"),
    (["--base-results", "{empty}"], "does not hold the results of a check"),
])
def test_what_cannot_be_compared_ends_with_a_sentence_and_writes_nothing(tmp_path, capsys, args, sentence):
    repo = tmp_path / "notes"
    commit(repo, BASE)
    (tmp_path / "empty").mkdir()
    code, out, err = run(["diff", str(repo), *[a.replace("{empty}", str(tmp_path / "empty")) for a in args], "--offline"], capsys)
    assert code == 2 and sentence in err and err.count("\n") <= 3, err
    assert not (repo / ".lantern" / "change" / "change.json").exists() and "Traceback" not in err


def test_a_folder_in_no_repository_is_said_so(tmp_path, capsys):
    write(tmp_path / "plain", BASE)
    code, out, err = run(["diff", str(tmp_path / "plain"), "--offline"], capsys)
    assert code == 2 and "is in no git repository Lantern reads" in err
