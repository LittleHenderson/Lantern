"""What a change does to an app (`lantern/diff.py`, `lantern diff`; roadmap of 2026-11-14, stage 2).

One small app (a FastAPI server, a React page that asks it) is checked twice with the whole analysis, before a
change and after it, and the receipt has to name exactly what was planted: a new route that asks nobody who is
calling, a login check taken off a route, a request of the page that no route answers any more, a finding that
a route reaches now. Each planted change stands beside a twin that looks alike and is none (the new route asks
for a login; page and server were renamed together; the risky helper is called by something no door reaches;
only a comment and the spacing changed), and the twin's receipt has to be quiet about it.
"""
import json

import pytest

from lantern import diff, pipeline

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


def test_results_of_an_older_lantern_are_compared_without_the_login_record_and_the_receipt_says_so(checks, tmp_path):
    base, head = checks.of(BASE, "before"), checks.of(changed(BASE, app=EXPORT_OPEN), "after")
    old = dict(base, security={k: v for k, v in base["security"].items() if k != "route_logins"})
    r = diff.compare(old, head)
    assert words(r["doors"]["added"]) == ["POST /api/admin/export"]
    assert any("does not write down what each route shows about a login" in x for x in r["limits"])
    newer = diff.compare(base, head)
    assert not any("does not write down" in x for x in newer["limits"])


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


def test_text_of_a_project_cannot_write_markdown_of_its_own(checks):
    text = diff.markdown(poisoned(checks))
    assert "<img" not in text and "<script" not in text and "onerror=alert(1)>" not in text
    for line in text.splitlines():
        assert not line.startswith("## a heading"), line
        assert line.count("`") % 2 == 0, line        # no code span is left open or closed early


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
