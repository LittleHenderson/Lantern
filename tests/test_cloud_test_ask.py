"""Before a check of the website runs a person's tests (a firm pass or fail, stage 3, step 6).

The website asks first. `GET /v1/tests` gives the words the test machine's program writes (`lantern.runner.ask`); a
person's yes is kept for those very words (`POST /v1/tests/consent`, with their fingerprint), so words that change are
asked again; and a check that asks for its tests (`tests` of `POST /v1/repos` and of `POST /v1/uploads`) starts only
after that yes and only where the website runs test machines. The words are tied to the walls the machine's program
puts up (`runner.walls`): a wall taken away, or a new one, fails a test here until the words are read again. The page
prints the server's words and writes none of its own about what the machine can reach.

Each refusal stands beside the request that goes through. No check runs here: the worker's hand-over is stood in for
(`tests/test_cloud_test_runs.py` runs the worker)."""
from __future__ import annotations

import io
import json
import os
import re
import sys
import threading
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
if os.name != "posix":
    pytest.skip("the cloud service runs on Linux (its restricted process is POSIX)", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
from fastapi.testclient import TestClient  # noqa: E402

from lantern import libraries, runner, sandbox  # noqa: E402
from lantern_cloud import app as app_mod  # noqa: E402
from lantern_cloud import machines as machines_mod  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

PAGE = (ROOT / "cloud" / "lantern_cloud" / "site" / "index.html").read_text(encoding="utf-8")
LINK = "https://github.com/octo/adder"
# The parts of the words a person agrees to that a wall of the machine's program makes true, by that wall's name.
SAID_BY = {"as an ordinary user": {"an ordinary user for the tests"},
           "in a network of their own with no other computer on it": {"the tests' own network",
                                                                       "a doorman for every connection"},
           "within the minutes and memory you choose": {"the memory watch"}}
# A wall the words need not name: it keeps a check's tests from flooding their own machine, which they share with
# nothing of the person's.
UNSAID = {"a limit on the tests' programs"}


class Machines:
    """The test machines, stood in for: switched on, of this size; nothing is ever run on them here."""

    def __init__(self, most_memory: int = 8192, archive_mb: int = 64):
        self.most_memory, self.archive_mb = most_memory, archive_mb

    def run(self, *a, **kw):                     # pragma: no cover - no check runs in these tests
        raise AssertionError("no check runs here")

    def sweep_forever(self, over: threading.Event) -> None:
        over.wait()


@pytest.fixture
def site(tmp_path, monkeypatch):
    """`site(machines)`: the website, signed in through its gateway, whose checks are written down and not run."""
    handed: list[str] = []
    monkeypatch.setattr(worker_mod.Worker, "submit", lambda self, rid: handed.append(rid))
    made = []

    def make(machines=None):
        n = len(made)
        gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / f"gw{n}.db")))
        s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / f"cloud{n}.db"),
                     results_dir=str(tmp_path / f"results{n}"), work_dir=str(tmp_path / f"work{n}"), audits=False,
                     per_user_active=10)          # the checks are written down and never end here: a few may wait at once
        client = TestClient(app_mod.create_app(s, transport=httpx.ASGITransport(app=gw_app), test_machines=machines))
        client.__enter__()
        made.append(client)
        token = gw_app.state.store.sign_in("github:1", "github:octo")
        client.headers.update({"authorization": f"Bearer {token}"})
        return client, client.app.state.store, handed
    yield make
    for client in made:
        client.__exit__(None, None, None)


def _agree(client) -> dict:
    words = client.get("/v1/tests").json()
    r = client.post("/v1/tests/consent", json={"agree": True, "digest": words["digest"]})
    assert r.status_code == 200 and r.json()["agreed"] is True, r.text
    return words


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app/app.py", "def add(a, b):\n    return a + b\n")
    return buf.getvalue()


def _parts(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


# ---------------------------------------------------------------------------- the words, and the walls they speak of
def test_the_words_are_the_machines_programs_and_their_fingerprint_is_of_both():
    said = runner.ask()
    assert said["ask"] == runner.MACHINE_ASK and said["libraries"] == runner.libraries_ask()
    assert said["digest"] == __import__("hashlib").sha256(f"{said['ask']}\n{said['libraries']}".encode()).hexdigest()


def test_each_part_of_the_words_has_a_wall_that_makes_it_true():
    walls = {w["wall"] for w in runner.walls()}
    named = set().union(*SAID_BY.values())
    # a wall taken away, or a new one, comes here first: the words a person agreed to are read again with it
    assert walls == named | UNSAID, sorted(walls ^ (named | UNSAID))
    for part in SAID_BY:
        assert part in runner.MACHINE_ASK, part


ASKED_BY = {"the tests' own network": (sandbox, "own_network"), "a doorman for every connection": (sandbox, "own_sockets"),
            "the memory watch": (runner, "_memory_watch"), "a limit on the tests' programs": (runner, "_programs_limit"),
            "an ordinary user for the tests": (runner, "_ordinary_user")}


@pytest.mark.parametrize("missing", [None, *sorted(set().union(*SAID_BY.values()))])
def test_the_machine_runs_no_test_where_a_wall_the_words_speak_of_does_not_stand(monkeypatch, tmp_path, missing):
    """What makes the words true on every machine: its program asks for every wall before it takes a check, and runs
    nothing where one does not stand (the real program on a machine: tests/test_runner.py, tools/runner_image.py)."""
    assert set(ASKED_BY) == {w["wall"] for w in runner.walls()}
    for wall, (module, name) in ASKED_BY.items():
        monkeypatch.setattr(module, name, lambda wall=wall: "not on this machine" if wall == missing else "")
    result = runner.check(tmp_path / "no-such-check.zip", tmp_path / "work", log=lambda *a, **k: None)
    if missing is None:          # the twin: every wall stands, and the program goes on to the check it was handed
        assert result["state"] == "refused" and "taken" not in result, result
    else:
        assert result["state"] == "unable" and missing in result["why_not"].lower() and "taken" not in result, result
    assert not (tmp_path / "work").exists()


def test_the_libraries_words_name_the_stores_by_their_host_alone(monkeypatch):
    for v in libraries.VARIABLES.values():
        monkeypatch.delenv(v, raising=False)
    official = runner.libraries_ask()
    assert "pypi.org (Python)" in official and "registry.npmjs.org (JavaScript)" in official
    assert "is not built" in official
    monkeypatch.setenv("LANTERN_STORE_PYTHON", "https://mirror.example.org/pypi/simple")
    mirror = runner.libraries_ask()
    assert "mirror.example.org (Python)" in mirror and "/pypi/" not in mirror and "https://" not in mirror
    assert runner.ask()["digest"] != __import__("hashlib").sha256(
        f"{runner.MACHINE_ASK}\n{official}".encode()).hexdigest()           # another store: the words changed


@pytest.mark.parametrize("setting", ["https://user:not-for-the-page@mirror.example.org/simple",
                                     "https://user@mirror.example.org/simple",
                                     "https://:not-for-the-page@mirror.example.org/simple",
                                     "https://mirror.example.org/simple?token=not-for-the-page",
                                     "http://mirror.example.org/simple"])
def test_a_store_setting_with_a_user_part_or_of_another_kind_is_never_shown(monkeypatch, setting):
    monkeypatch.setenv("LANTERN_STORE_PYTHON", setting)
    with pytest.raises(sandbox.NoLibraries):
        libraries.Store("python")
    said = runner.libraries_ask()
    assert "the store the website names (Python)" in said
    assert "not-for-the-page" not in said and "user" not in said and "mirror" not in said, said


def test_a_store_setting_with_a_port_is_shown_with_it(monkeypatch):
    monkeypatch.setenv("LANTERN_STORE_PYTHON", "https://mirror.example.org:8443/simple")
    assert libraries.Store("python").host == "mirror.example.org:8443"
    assert "mirror.example.org:8443 (Python)" in runner.libraries_ask()


# ---------------------------------------------------------------------------- /v1/tests and the person's yes
def test_the_website_says_whether_it_runs_tests_and_in_which_words(site):
    client, _store, _handed = site(Machines(most_memory=8192))
    t = client.get("/v1/tests").json()
    assert t["on"] is True and t["why_off"] == "" and t["agreed"] is False
    assert (t["ask"], t["libraries"], t["digest"]) == (runner.MACHINE_ASK, runner.libraries_ask(), runner.ask()["digest"])
    assert t["minutes"] == {"default": sandbox.WALL_CLOCK // 60, "least": 1, "most": 240}
    assert t["memory"] == {"default": 2048, "least": 128, "most": 8192 - machines_mod.ROOM_MB}
    me = client.get("/v1/me").json()
    assert me["tests"] == {"on": True, "agreed": False}


def test_with_its_machines_off_the_website_says_so(site):
    client, _store, _handed = site(None)
    t = client.get("/v1/tests").json()
    assert t["on"] is False and t["why_off"] == worker_mod.MACHINES_OFF
    assert client.get("/v1/me").json()["tests"] == {"on": False, "agreed": False}


def test_signed_out_nothing_is_said_or_kept(site):
    client, _store, _handed = site(Machines())
    del client.headers["authorization"]
    assert client.get("/v1/tests").status_code == 401
    assert client.post("/v1/tests/consent", json={"agree": True, "digest": runner.ask()["digest"]}).status_code == 401


def test_a_yes_is_kept_for_the_words_shown_and_can_be_taken_back(site):
    client, store, _handed = site(Machines())
    words = client.get("/v1/tests").json()
    # a yes to other words is no yes: the page that showed them is told to show the new ones
    r = client.post("/v1/tests/consent", json={"agree": True, "digest": "0" * 64})
    assert r.status_code == 409 and r.json()["error"]["message"] == app_mod.TESTS_WORDS_CHANGED
    assert client.post("/v1/tests/consent", json={"agree": True}).status_code == 409
    assert client.get("/v1/tests").json()["agreed"] is False and store.tests_consent("github:1") is None
    # the twin: the words it showed
    r = client.post("/v1/tests/consent", json={"agree": True, "digest": words["digest"]})
    assert r.status_code == 200 and r.json()["agreed"] is True
    assert client.get("/v1/tests").json()["agreed"] is True and client.get("/v1/me").json()["tests"]["agreed"] is True
    assert store.tests_consent("github:1") == words["digest"]        # the fingerprint, never the words
    r = client.post("/v1/tests/consent", json={"agree": False})
    assert r.status_code == 200 and r.json()["agreed"] is False
    assert client.get("/v1/tests").json()["agreed"] is False and store.tests_consent("github:1") is None
    for odd in ({"agree": "yes"}, {"agree": 1}, {}, {"agree": None}):
        assert client.post("/v1/tests/consent", json=odd).status_code == 400, odd


def test_words_that_changed_after_the_yes_are_asked_again(site, monkeypatch):
    client, _store, _handed = site(Machines())
    _agree(client)
    monkeypatch.setenv("LANTERN_STORE_NPM", "https://npm-mirror.example.org/")    # the website's store changed
    assert client.get("/v1/tests").json()["agreed"] is False
    r = client.post("/v1/repos", json={"link": LINK, "tests": True})
    assert r.status_code == 412 and r.json()["error"]["message"] == app_mod.TESTS_CONSENT_NEEDED


# ---------------------------------------------------------------------------- a check that asks for its tests
def test_a_check_with_tests_starts_only_after_the_yes(site):
    client, store, handed = site(Machines())
    r = client.post("/v1/repos", json={"link": LINK, "tests": True})
    assert r.status_code == 412 and r.json()["error"]["type"] == "consent_needed"
    assert handed == [] and store.runs("github:1") == []           # no check was made
    _agree(client)
    r = client.post("/v1/repos", json={"link": LINK, "tests": True})
    assert r.status_code == 202, r.text
    run = r.json()
    assert run["tests"] == {"command": None, "cwd": None, "minutes": 10, "memory": 2048}   # Lantern finds the command
    assert run["steps"] == [] and handed == [run["id"]]
    assert store.run(run["id"])["tests"] == run["tests"]


@pytest.mark.parametrize("none", [None, False])
def test_a_check_without_tests_asks_nothing_first(site, none):
    client, store, handed = site(Machines())
    r = client.post("/v1/repos", json={"link": LINK, **({} if none is None else {"tests": none})})
    assert r.status_code == 202, r.text
    assert r.json()["tests"] is None and store.run(r.json()["id"])["tests"] is None and len(handed) == 1


def test_with_the_machines_off_a_check_with_tests_is_refused_and_one_without_starts(site):
    client, store, handed = site(None)
    r = client.post("/v1/repos", json={"link": LINK, "tests": True})
    assert r.status_code == 409 and r.json()["error"]["message"] == worker_mod.MACHINES_OFF
    assert handed == [] and store.runs("github:1") == []
    assert client.post("/v1/repos", json={"link": LINK}).status_code == 202 and len(handed) == 1


@pytest.mark.parametrize(("tests", "asked"), [
    ({"command": "python -m pytest -q"}, {"command": ["python", "-m", "pytest", "-q"], "cwd": "", "minutes": 10,
                                          "memory": 2048}),
    ({"command": ["npm", "test"], "cwd": "web", "minutes": 30, "memory": 4096},
     {"command": ["npm", "test"], "cwd": "web", "minutes": 30, "memory": 4096}),
    ({"command": "", "cwd": "", "minutes": 5}, {"command": None, "cwd": None, "minutes": 5, "memory": 2048}),
    ({"memory": 7168}, {"command": None, "cwd": None, "minutes": 10, "memory": 7168}),
    ({}, {"command": None, "cwd": None, "minutes": 10, "memory": 2048})])
def test_what_a_check_asks_of_its_tests_is_kept_in_the_machines_shape(site, tests, asked):
    client, store, _handed = site(Machines(most_memory=8192))
    _agree(client)
    r = client.post("/v1/repos", json={"link": LINK, "tests": tests})
    assert r.status_code == 202, r.text
    assert r.json()["tests"] == asked and store.run(r.json()["id"])["tests"] == asked


@pytest.mark.parametrize("tests", [
    "yes", 1, ["python", "-m", "pytest"], {"command": "python -m pytest", "more": 1},
    {"minutes": 0}, {"minutes": 241}, {"minutes": "10"}, {"minutes": True}, {"minutes": None},
    {"memory": 64}, {"memory": 7169}, {"memory": 2048.5},
    {"command": "rm -rf /"}, {"command": "python app.py"}, {"command": "pnpm test"}, {"command": "yarn test"},
    {"command": ["npm", 1]}, {"command": 7},
    {"cwd": "web"}, {"command": None, "cwd": "web"},                 # a folder goes with a command
    {"command": "npm test", "cwd": "../up"}, {"command": "npm test", "cwd": "/etc"}, {"command": "npm test", "cwd": 1},
    {"command": "python -m pytest 'tests"}])                          # a quote not closed
def test_tests_asked_in_a_shape_the_machine_does_not_take_start_nothing(site, tests):
    client, store, handed = site(Machines(most_memory=8192))
    _agree(client)
    r = client.post("/v1/repos", json={"link": LINK, "tests": tests})
    assert r.status_code == 400, (tests, r.text)
    assert r.json()["error"]["message"].endswith(".")
    assert handed == [] and store.runs("github:1") == []


# ---------------------------------------------------------------------------- an upload that asks for its tests
def test_an_upload_with_tests_is_refused_before_its_body_is_read(site):
    client, store, handed = site(Machines())
    up = Path(client.app.state.settings.uploads())
    r = client.post("/v1/uploads", params={"name": "adder", "tests": "true"}, content=_zip())
    assert r.status_code == 412 and handed == [] and store.runs("github:1") == []
    assert [p for p in _parts(up) if p.startswith(".part-")] == []   # not a byte of the body was kept
    for odd in ("{", "[1, 2", "nope", '"' * 3):
        r = client.post("/v1/uploads", params={"name": "adder", "tests": odd}, content=_zip())
        assert r.status_code == 400 and r.json()["error"]["message"] == app_mod.TESTS_SHAPE, odd
    _agree(client)
    r = client.post("/v1/uploads", params={"name": "adder", "tests": json.dumps({"minutes": 4})}, content=_zip())
    assert r.status_code == 202, r.text
    assert r.json()["tests"] == {"command": None, "cwd": None, "minutes": 4, "memory": 2048} and len(handed) == 1
    r = client.post("/v1/uploads", params={"name": "adder"}, content=_zip())       # the twin: no tests asked
    assert r.status_code == 202 and r.json()["tests"] is None and len(handed) == 2


def test_an_upload_with_tests_is_refused_where_the_machines_are_off(site):
    client, store, handed = site(None)
    r = client.post("/v1/uploads", params={"name": "adder", "tests": "true"}, content=_zip())
    assert r.status_code == 409 and handed == [] and store.runs("github:1") == []


# ---------------------------------------------------------------------------- what a check shows of its steps
def test_a_checks_steps_and_tests_are_shown_only_in_their_shape(site):
    client, store, _handed = site(Machines())
    rid = client.post("/v1/repos", json={"link": LINK}).json()["id"]
    steps = [{"key": "clone", "at": "2026-11-21T10:00:00+00:00"}, {"key": "analyze", "at": "2026-11-21T10:00:05+00:00"}]
    store.update_run(rid, steps=steps)
    assert client.get(f"/v1/runs/{rid}").json()["steps"] == steps
    with store.lock:
        store.db.execute("update runs set steps = ? where id = ?", ('{"clone": "x"}', rid))
        store.db.commit()
    assert client.get(f"/v1/runs/{rid}").json()["steps"] == []


# ---------------------------------------------------------------------------- the page
def _function(name: str) -> str:
    at = PAGE.index(f"function {name}(")
    return PAGE[at:PAGE.index("\n}\n", at)]


def test_the_page_offers_the_tick_line_only_where_the_machines_are_on():
    tick = next(line for line in PAGE.splitlines() if line.startswith("const testsTick = "))
    assert tick.startswith("const testsTick = () => testsOn() ?") and tick.rstrip().endswith(": '';")
    assert "Also run my tests, on a test machine made for this check" in tick
    assert "S.me.tests.on === true" in next(line for line in PAGE.splitlines() if line.startswith("const testsOn = "))


def test_the_sheet_prints_the_servers_words_and_none_of_its_own_about_the_machine():
    sheet = _function("testsSheet")
    assert "${esc(t.ask)}" in sheet and "${esc(t.libraries)}" in sheet and "digest: t.digest" in sheet
    for own in ("network", "internet", "computer", "reach", "ordinary user", "Nothing leaves"):
        assert own not in sheet, own
    for phrase in [*SAID_BY, "no way out to the internet", "Nothing leaves this computer"]:
        assert phrase not in PAGE, phrase


def test_the_pages_steps_are_the_workers_steps():
    keys = re.findall(r"\['(\w+)', '", PAGE[PAGE.index("const TEST_STEPS = "):PAGE.index("const TESTS_SEALED")])
    assert keys == ["libraries", "tests"]
    order = list(worker_mod.STAGES)
    assert order.index("audit") < order.index("libraries") < order.index("tests") < order.index("analyze")
    plain = PAGE[PAGE.index("const PLAIN_STEPS = "):PAGE.index("const TEST_STEPS = ")]
    assert set(re.findall(r"(\w+): \['", plain)) == set(worker_mod.STAGES)


def test_the_cards_words_are_the_workers_states():
    said = PAGE[PAGE.index("const TESTS_SAID = "):PAGE.index("const testsState = ")]
    assert re.findall(r"'([a-z ]+)': \['", said) == list(worker_mod.TESTS_SAID)
