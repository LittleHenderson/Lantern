"""The fix contract (`lantern/fixcheck.py`; roadmap of 2026-11-14, stage 3: the guarded fix loop).

One small app (a FastAPI server, a React page that asks it, two tests) has two planted problems: a route hands a
visitor's text to a shell, and a file is fingerprinted with MD5. Each is "fixed" in many ways. One way is a true fix.
The others only make the finding stop showing: a comment that excuses it, an entry in the list of accepted risks, the
code moved to a place Lantern reads differently or not at all, the call put together at run time, the file broken
so that no scanner reads it, the route taken away, a test deleted. The contract has to refuse each of those, name
the part that broke, and hold on the true fix. Until this stage the recheck called several of them "fixed".
"""
import json

import pytest

from lantern import fixcheck, pipeline

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


@app.get("/api/fingerprint")
def fingerprint(user=Depends(current_user)):
    return {"is": store.fingerprint()}


@app.post("/api/backup")
def make_backup(name: str, user=Depends(current_user)):
    store.backup(name)
    return {"made": name}
'''

STORE = '''\
import hashlib
import sqlite3
import subprocess

DB = "notes.db"


def user_for(token):
    return token.split(":")[0]


def all_notes(user):
    with sqlite3.connect(DB) as con:
        return con.execute("select id, text from notes where owner = ?", (user,)).fetchall()


def fingerprint():
    with open(DB, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def backup(name):
    subprocess.run("tar czf " + name + " notes.db", shell=True)
'''

API_JS = '''\
export async function loadNotes() {
  const res = await fetch("/api/notes");
  return res.json();
}

export async function makeBackup(name) {
  await fetch("/api/backup?name=" + encodeURIComponent(name), { method: "POST" });
}
'''

APP_JSX = '''\
import { useEffect, useState } from "react";
import { loadNotes, makeBackup } from "./api";

export default function App() {
  const [notes, setNotes] = useState([]);
  useEffect(() => {
    loadNotes().then(setNotes);
  }, []);
  return (
    <div>
      <ul>
        {notes.map((n) => (
          <li key={n[0]}>{n[1]}</li>
        ))}
      </ul>
      <button onClick={() => makeBackup("today")}>Back up</button>
    </div>
  );
}
'''

MAIN_JSX = '''\
import { createRoot } from "react-dom/client";
import App from "./App";

createRoot(document.getElementById("root")).render(<App />);
'''

TEST_STORE = '''\
from api import store


def test_the_user_is_the_part_before_the_colon():
    assert store.user_for("ada:secret") == "ada"


def test_a_backup_is_made(monkeypatch):
    ran = []
    monkeypatch.setattr(store.subprocess, "run", lambda *a, **k: ran.append(a))
    store.backup("today")
    assert ran
'''

BASE = {
    "pyproject.toml": '[project]\nname = "notes"\nversion = "0.1.0"\ndependencies = ["fastapi==0.115.0"]\n',
    "api/__init__.py": "",
    "api/app.py": APP,
    "api/store.py": STORE,
    "tests/test_store.py": TEST_STORE,
    "web/package.json": '{"name": "web", "private": true, "dependencies": {"react": "18.3.1", "react-dom": "18.3.1"}}\n',
    "web/src/api.js": API_JS,
    "web/src/App.jsx": APP_JSX,
    "web/src/main.jsx": MAIN_JSX,
}

SHELL_LINE = '    subprocess.run("tar czf " + name + " notes.db", shell=True)\n'
BACKUP_FN = "def backup(name):\n" + SHELL_LINE
MD5_LINE = "        return hashlib.md5(f.read()).hexdigest()\n"
HELPER = "import subprocess\n\n\ndef backup(name):\n" + SHELL_LINE
BACKUP_ROUTE = '''\


@app.post("/api/backup")
def make_backup(name: str, user=Depends(current_user)):
    store.backup(name)
    return {"made": name}
'''
SECOND_TEST = '''\


def test_a_backup_is_made(monkeypatch):
    ran = []
    monkeypatch.setattr(store.subprocess, "run", lambda *a, **k: ran.append(a))
    store.backup("today")
    assert ran
'''


def swap(files: dict, path: str, old: str, new: str) -> dict:
    assert files[path].count(old) == 1, (path, old)
    return {**files, path: files[path].replace(old, new)}


# ---- true fixes: the shell is gone and the name is checked; the fingerprint is made with SHA-256
SAFE_BACKUP = '''\
def backup(name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name):
        raise ValueError("not a name for a backup")
    subprocess.run(["tar", "czf", name + ".tgz", "notes.db"], check=True)
'''
TRUE_FIX = swap(swap(BASE, "api/store.py", BACKUP_FN, SAFE_BACKUP), "api/store.py", "import hashlib\n", "import hashlib\nimport re\n")
# the same fix with the safe code in a file of its own that Lantern reads, and one more test
TRUE_FIX_NEW_FILE = {
    **swap(swap(BASE, "api/store.py", BACKUP_FN, "def backup(name):\n    safe.backup(name)\n"),
           "api/store.py", "import subprocess\n", "import subprocess\n\nfrom . import safe\n"),
    "api/safe.py": "import re\nimport subprocess\n\n\n" + SAFE_BACKUP,
    "tests/test_safe.py": 'import pytest\n\nfrom api import safe\n\n\ndef test_a_name_with_a_space_is_refused():\n'
                          '    with pytest.raises(ValueError):\n        safe.backup("a b")\n',
}
MD5_TRUE_FIX = swap(BASE, "api/store.py", MD5_LINE, MD5_LINE.replace("md5", "sha256"))

# ---- "fixes" of the shell line that only hide it
SAID_SO = swap(BASE, "api/store.py", SHELL_LINE, SHELL_LINE.rstrip("\n") + "  # nosec B602: the name comes from our own page\n")
IN_TESTS = {**swap(swap(BASE, "api/store.py", BACKUP_FN, "def backup(name):\n    helpers.backup(name)\n"),
                   "api/store.py", "import subprocess\n", "import subprocess\n\nfrom tests import helpers\n"),
            "tests/__init__.py": "", "tests/helpers.py": HELPER}
MOVED_FILE = {**swap(swap(BASE, "api/store.py", BACKUP_FN, "def backup(name):\n    tools.backup(name)\n"),
                     "api/store.py", "import subprocess\n", "import subprocess\n\nfrom . import tools\n"),
              "api/tools.py": HELPER}
AS_TEXT = {**swap(BASE, "api/store.py", BACKUP_FN, '''\
def backup(name):
    scope = {}
    exec(open("api/backup.py.txt").read(), scope)
    scope["backup"](name)
'''), "api/backup.py.txt": HELPER}
COMPUTED = swap(BASE, "api/store.py", SHELL_LINE,
                '    getattr(subprocess, "r" + "un")("tar czf " + name + " notes.db", **{"sh" + "ell": True})\n')
BROKEN_FILE = swap(BASE, "api/store.py", 'DB = "notes.db"\n', 'DB = "notes.db"\nif 1:\n')     # no Python any more
ROUTE_GONE = swap(BASE, "api/app.py", BACKUP_ROUTE, "")
SKIPPED_FOLDER = {**swap(swap(BASE, "api/store.py", BACKUP_FN, "def backup(name):\n    helpers.backup(name)\n"),
                         "api/store.py", "import subprocess\n", "import subprocess\n\nfrom build import helpers\n"),
                  "build/__init__.py": "", "build/helpers.py": HELPER}

# ---- the true fix of the shell line, with something else made worse on the way
LOGIN_OFF = swap(TRUE_FIX, "api/app.py", "def list_notes(user=Depends(current_user)):\n    return store.all_notes(user)\n",
                 'def list_notes(user: str = "ada"):\n    return store.all_notes(user)\n')
TEST_GONE = {k: v for k, v in TRUE_FIX.items() if k != "tests/test_store.py"}
TEST_CUT = swap(TRUE_FIX, "tests/test_store.py", SECOND_TEST, "")
EVAL_ADDED = swap(TRUE_FIX, "api/store.py", 'def user_for(token):\n    return token.split(":")[0]\n',
                  "def user_for(token):\n    return eval(token)\n")

# ---- the fingerprint: a comment that answers for it (no request data reaches that line, so the comment is taken)
REASON = "a fingerprint of the file and nothing secret"
MD5_SAID_SO = swap(BASE, "api/store.py", MD5_LINE, MD5_LINE.rstrip("\n") + f"  # nosec B324: {REASON}\n")

# name -> (files, the parts of the contract that must be broken, whether no other part may be)
TRICKS = {
    "a comment on a line request data reaches": (SAID_SO, {"gone", "no-suppression"}, True),
    "moved into the tests folder": (IN_TESTS, {"gone"}, False),
    "moved into another file": (MOVED_FILE, {"gone"}, False),
    "kept as text and run with exec": (AS_TEXT, {"gone", "still-read", "calls", "nothing-new"}, True),
    "the call put together at run time": (COMPUTED, {"calls"}, True),
    "the file broken so no scanner reads it": (BROKEN_FILE, {"still-read"}, True),
    "the route taken away": (ROUTE_GONE, {"gone", "links"}, True),
    "moved into a folder Lantern does not read": (SKIPPED_FOLDER, {"calls"}, True),
    "a login check taken off another route": (LOGIN_OFF, {"nothing-new"}, True),
    "the tests deleted": (TEST_GONE, {"tests"}, True),
    "one test deleted": (TEST_CUT, {"tests"}, True),
    "a worse line added elsewhere": (EVAL_ADDED, {"nothing-new"}, True),
}
RAN_AND_PASSED = {"ran": True, "returncode": 0}


def write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


class Checks:
    """The whole analysis of a version of the app, once per version however many tests ask for it."""

    def __init__(self, folder):
        self.folder, self.done = folder, {}

    def of(self, files: dict):
        key = json.dumps(files, sort_keys=True)
        if key not in self.done:
            repo = self.folder / f"v{len(self.done)}" / "notes"
            write(repo, files)
            out = self.folder / f"v{len(self.done)}" / "out"
            pipeline.analyze(repo, out, offline=True, log=lambda *_: None)
            self.done[key] = (out, repo)
        out, repo = self.done[key]
        return fixcheck.load(out), repo

    def finding(self, rule: str, files: dict | None = None) -> str:
        side, _ = self.of(BASE if files is None else files)
        ids = [f["id"] for f in side["security"]["findings"] if f["rule"] == rule and not f.get("in_tests")]
        assert len(ids) == 1, (rule, ids)
        return ids[0]

    def judge(self, head: dict, rule: str = "B602", base: dict | None = None, tests=RAN_AND_PASSED) -> dict:
        base = BASE if base is None else base
        before, _ = self.of(base)
        after, repo = self.of(head)
        return fixcheck.judge(before, after, self.finding(rule, base), repo=repo, tests=tests)


@pytest.fixture(scope="module")
def checks(tmp_path_factory):
    return Checks(tmp_path_factory.mktemp("fixcheck"))


def states(result: dict) -> dict:
    return {i["id"]: i["state"] for i in result["items"]}


def broken(result: dict) -> set:
    return {i["id"] for i in result["items"] if i["state"] == "broken"}


def said(result: dict, part: str) -> str:
    return " ".join(next(i for i in result["items"] if i["id"] == part)["facts"])


# --------------------------------------------------------------------------------------------- the contract itself
def test_the_contract_is_seven_parts_in_plain_sentences():
    parts = fixcheck.contract()
    assert [p["id"] for p in parts] == ["gone", "no-suppression", "still-read", "links", "calls", "nothing-new", "tests"]
    assert [p["id"] for p in parts] == list(fixcheck.ITEMS)
    for p in parts:
        assert p["need"].endswith(".") and len(p["need"]) > 30, p


def test_the_planted_problems_are_found_before_any_fix(checks):
    side, _ = checks.of(BASE)
    open_now = {(f["rule"], f["file"]) for f in side["security"]["findings"] if not f.get("in_tests")}
    assert {("B602", "api/store.py"), ("B324", "api/store.py")} <= open_now


# ------------------------------------------------------------------------------------------------- the true fixes
def test_a_true_fix_holds_every_part(checks):
    r = checks.judge(TRUE_FIX)
    assert r["verdict"] == "passed", r
    assert set(states(r).values()) == {"held"}, states(r)
    assert r["finding"]["rule"] == "B602" and r["finding"]["file"] == "api/store.py"
    # what came with the fix is said and breaks nothing: two notes of Bandit's lowest rank on the new line
    assert "B603" in said(r, "nothing-new") and "low" in said(r, "nothing-new")
    assert "passed" in r["words"]


def test_a_true_fix_in_a_new_file_lantern_reads_with_one_more_test_holds_too(checks):
    """The twin of every "moved" trick below: the safe code is in a file of its own, the file is on the map."""
    r = checks.judge(TRUE_FIX_NEW_FILE)
    assert r["verdict"] == "passed", (broken(r), r["items"])


def test_a_true_fix_whose_tests_were_not_run_is_not_passed_and_not_refused(checks):
    r = checks.judge(TRUE_FIX, tests=None)
    assert r["verdict"] == "incomplete" and broken(r) == set()
    assert states(r)["tests"] == "not-shown" and "not run" in said(r, "tests")
    assert {k: v for k, v in states(r).items() if k != "tests"} == dict.fromkeys(fixcheck.ITEMS[:-1], "held")
    # a sandbox that could not be set up, or a run stopped at its limit, shows nothing either
    for nothing in ({"ran": False}, {"ran": True, "returncode": None, "timed_out": True}):
        assert checks.judge(TRUE_FIX, tests=nothing)["verdict"] == "incomplete", nothing


def test_a_true_fix_under_which_the_tests_fail_is_refused(checks):
    r = checks.judge(TRUE_FIX, tests={"ran": True, "returncode": 1})
    assert r["verdict"] == "refused" and broken(r) == {"tests"}
    assert "ended with 1" in said(r, "tests")


def test_the_other_planted_problem_fixed_truly(checks):
    r = checks.judge(MD5_TRUE_FIX, rule="B324")
    assert r["verdict"] == "passed", (broken(r), r["items"])


# ------------------------------------------------------------------------------------- what only hides the finding
@pytest.mark.parametrize("trick", sorted(TRICKS))
def test_a_fix_that_only_hides_the_finding_is_refused(checks, trick):
    files, must, only = TRICKS[trick]
    r = checks.judge(files)
    assert r["verdict"] == "refused", (trick, states(r))
    assert must <= broken(r), (trick, broken(r))
    if only:
        assert broken(r) == must, (trick, broken(r), r["items"])
    for part in must:
        assert said(r, part), part            # each broken part says what broke it


def test_what_each_refusal_says(checks):
    """The sentence a person or an agent reads: the fact that broke the part, with the place."""
    r = checks.judge(SAID_SO)
    assert "# nosec" in said(r, "no-suppression")
    assert "api/store.py" in said(r, "gone") and "B602" in said(r, "gone")
    r = checks.judge(MOVED_FILE)
    assert "api/tools.py" in said(r, "gone")
    r = checks.judge(IN_TESTS)
    assert "tests/helpers.py" in said(r, "gone")
    r = checks.judge(COMPUTED)
    assert "api/store.py" in said(r, "calls") and "run time" in said(r, "calls")
    r = checks.judge(SKIPPED_FOLDER)
    assert "build.helpers.backup" in said(r, "calls") and "does not read" in said(r, "calls")
    r = checks.judge(BROKEN_FILE)
    assert "bandit" in said(r, "still-read") and "api/store.py" in said(r, "still-read")
    r = checks.judge(AS_TEXT)
    assert "api/backup.py.txt" in said(r, "gone") + said(r, "still-read")
    r = checks.judge(ROUTE_GONE)
    assert "POST /api/backup" in said(r, "links")
    r = checks.judge(LOGIN_OFF)
    assert "GET /api/notes" in said(r, "nothing-new") and "login" in said(r, "nothing-new")
    r = checks.judge(EVAL_ADDED)
    assert "B307" in said(r, "nothing-new")
    r = checks.judge(TEST_GONE)
    assert "tests/test_store.py" in said(r, "tests")
    r = checks.judge(TEST_CUT)
    assert "tests/test_store.py" in said(r, "tests") and "test_a_backup_is_made" in said(r, "tests")
    assert "refused" in r["words"]


def test_a_comment_that_answers_for_the_finding_is_a_suppression_and_no_fix(checks):
    side, _ = checks.of(MD5_SAID_SO)
    md5 = [f for f in side["security"]["findings"] if f["rule"] == "B324"]
    assert [f["status"] for f in md5] == ["accepted"]            # Lantern takes the comment: no request data reaches the line
    r = checks.judge(MD5_SAID_SO, rule="B324")
    assert r["verdict"] == "refused" and broken(r) == {"gone", "no-suppression"}
    assert REASON in said(r, "no-suppression")


def test_an_entry_in_the_list_of_accepted_risks_is_a_suppression_and_no_fix(checks):
    """What `lantern accept` writes for a person, written by the fix itself."""
    fid = checks.finding("B324")
    accepted = {**BASE, "lantern-accepted.json": json.dumps({"accepted": [{"id": fid, "reason": REASON}]})}
    side, _ = checks.of(accepted)
    assert [f["status"] for f in side["security"]["findings"] if f["id"] == fid] == ["accepted"]
    r = checks.judge(accepted, rule="B324")
    assert r["verdict"] == "refused" and broken(r) == {"gone", "no-suppression"}
    assert "accepted" in said(r, "no-suppression")


def test_a_comment_that_was_there_before_the_fix_is_not_held_against_it(checks):
    """The twin: the project had accepted the fingerprint before; the shell line is then fixed truly."""
    base = MD5_SAID_SO
    head = swap(swap(base, "api/store.py", BACKUP_FN, SAFE_BACKUP), "api/store.py", "import hashlib\n", "import hashlib\nimport re\n")
    r = checks.judge(head, base=base)
    assert r["verdict"] == "passed", (broken(r), r["items"])
    assert states(r)["no-suppression"] == "held"


def test_a_finding_that_is_not_open_before_cannot_be_judged(checks):
    before, _ = checks.of(BASE)
    after, repo = checks.of(TRUE_FIX)
    with pytest.raises(ValueError, match="not an open finding"):
        fixcheck.judge(before, after, "no-such-id", repo=repo)
    side, _ = checks.of(MD5_SAID_SO)
    accepted = next(f["id"] for f in side["security"]["findings"] if f["rule"] == "B324")
    with pytest.raises(ValueError, match="not an open finding"):
        fixcheck.judge(side, after, accepted, repo=repo)


def test_the_same_code_again_is_refused_as_not_gone(checks):
    r = checks.judge(BASE)
    assert r["verdict"] == "refused" and broken(r) == {"gone"}
    assert "still" in said(r, "gone")


def test_results_without_the_list_of_calls_leave_that_part_not_shown(checks, tmp_path):
    """Results an older Lantern wrote have no `calls.json`: the part about calls is then not shown, never held."""
    import shutil
    before, _ = checks.of(BASE)
    after, repo = checks.of(TRUE_FIX)
    old = tmp_path / "older"
    shutil.copytree(after["out"], old)
    (old / "calls.json").unlink()
    r = fixcheck.judge(before, fixcheck.load(old), checks.finding("B602"), repo=repo, tests=RAN_AND_PASSED)
    assert states(r)["calls"] == "not-shown" and r["verdict"] == "incomplete"


def test_the_result_as_text_names_every_part_and_the_verdict(checks):
    text = fixcheck.text(checks.judge(COMPUTED))
    assert text.splitlines()[0].startswith("Refused")
    for part in fixcheck.ITEMS:
        assert part in text
    assert "broken" in text and "held" in text
    assert fixcheck.text(checks.judge(TRUE_FIX)).splitlines()[0].startswith("Passed")
    assert fixcheck.text(checks.judge(TRUE_FIX, tests=None)).splitlines()[0].startswith("Incomplete")
