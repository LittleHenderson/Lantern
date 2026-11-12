"""The throw-away apps of the behaviour tests (directive point 5, 2026-11-11: "Create disposable test applications
and test actual outcomes and side effects").

`bench/behaviour/apps.py` writes Corkboard, a small notes app for teams, as the safe app or with one problem
planted. Here: every version is a Python program, a planted version differs from the safe app in the pieces its
problem names and in nothing else, and the safe app does its ordinary work, so that a behaviour test which finds
the safe app refusing something is not looking at an app that refuses everything. What happens when the wrong
person asks is tests/test_behave.py's business."""
import ast
import difflib
import importlib
import importlib.util
import io
import sqlite3
import sys
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jwt")
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location("behaviour_apps", ROOT / "bench" / "behaviour" / "apps.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corkboard = _generator()
KINDS = {"no-login", "other-user", "other-tenant", "privilege", "refused-but-changed", "credential", "invalid-input",
         "oversize", "upload", "archive", "redirect", "internal-address", "login-limit", "concurrency", "db-error",
         "interrupted", "retry", "recovery"}


def test_the_safe_app_and_every_planted_version_are_python():
    for planted in [None, *corkboard.PLANTED]:
        for name, text in corkboard.source(planted).items():
            if name.endswith(".py"):
                ast.parse(text, filename=f"{planted or 'safe'}/{name}")
            assert "@@" not in text, (planted, name)


@pytest.mark.parametrize("planted", sorted(corkboard.PLANTED))
def test_a_planted_version_differs_from_the_safe_app_in_its_own_pieces_only(planted):
    kind, sentence, pieces = corkboard.PLANTED[planted]
    assert kind in KINDS and sentence and sentence[0].isupper() and not sentence.endswith(".")
    assert pieces and all(which != "safe" and which in corkboard.PIECES[slot] for slot, which in pieces.items())
    safe, mine = corkboard.source(), corkboard.source(planted)
    assert safe != mine and sorted(safe) == sorted(mine)
    gone, came = [], []
    for name in safe:
        for line in difflib.ndiff(safe[name].splitlines(), mine[name].splitlines()):
            if line[:2] in ("- ", "+ ") and line[2:].strip():
                (gone if line[0] == "-" else came).append(line[2:])
    # every line that went is a line of the safe pieces the problem names, every line that came one of its own
    assert [line for line in gone if not _of(line, [corkboard.PIECES[slot]["safe"] for slot in pieces])] == []
    assert [line for line in came if not _of(line, [corkboard.PIECES[slot][which] for slot, which in pieces.items()])] == []


def _of(line: str, texts: list) -> bool:
    """Is `line` a line of one of the pieces, or the line a one-line piece is written into?"""
    return any(line in text.splitlines() or (text and "\n" not in text and text in line) for text in texts)


def test_every_piece_is_used_and_every_kind_of_problem_is_planted():
    used = {(slot, which) for _, _, pieces in corkboard.PLANTED.values() for slot, which in pieces.items()}
    there = {(slot, which) for slot, named in corkboard.PIECES.items() for which in named if which != "safe"}
    assert there == used
    assert all("safe" in named for named in corkboard.PIECES.values())
    assert {kind for kind, _, _ in corkboard.PLANTED.values()} == KINDS


def test_the_app_is_written_as_plain_files_and_holds_no_secret(tmp_path):
    folder = corkboard.build(tmp_path / "app")
    assert sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()) == sorted(corkboard.FILES)
    text = "".join(p.read_text(encoding="utf-8") for p in folder.rglob("*.py"))
    assert 'os.environ["CORKBOARD_SECRET"]' in text and "SECRET = \"" not in text and "SECRET = '" not in text


@pytest.fixture
def safe_app(tmp_path, monkeypatch):
    """The safe app, loaded into this process the way a test of any FastAPI app loads it."""
    folder = corkboard.build(tmp_path / "app")
    monkeypatch.setenv("CORKBOARD_DB", str(tmp_path / "data" / "corkboard.db"))
    monkeypatch.setenv("CORKBOARD_SECRET", "s" * 40)
    monkeypatch.setenv("CORKBOARD_HASH_ROUNDS", "1000")
    monkeypatch.syspath_prepend(str(folder))
    for name in [m for m in sys.modules if m == "corkboard" or m.startswith("corkboard.")]:
        del sys.modules[name]
    main = importlib.import_module("corkboard.main")
    try:
        with TestClient(main.app, follow_redirects=False) as client:
            yield client, tmp_path / "data"
    finally:
        for name in [m for m in sys.modules if m == "corkboard" or m.startswith("corkboard.")]:
            del sys.modules[name]


def _as(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_the_safe_app_does_its_ordinary_work(safe_app):
    client, data = safe_app
    made = client.post("/teams", json={"name": "Kiln", "email": "tara@kiln.test", "password": "tara-password"})
    assert made.status_code == 201
    joined = client.post("/signup", json={"invite": made.json()["invite"], "email": "alice@kiln.test",
                                          "password": "alice-password"})
    assert joined.status_code == 201
    tara = client.post("/login", json={"email": "tara@kiln.test", "password": "tara-password"}).json()["token"]
    alice = client.post("/login", json={"email": "alice@kiln.test", "password": "alice-password"}).json()["token"]
    assert client.get("/me", headers=_as(alice)).json()["role"] == "member"
    assert client.get("/me", headers=_as(tara)).json()["role"] == "admin"

    note = client.post("/notes", json={"text": "buy clay", "private": True}, headers=_as(alice))
    assert note.status_code == 201
    note_id = note.json()["id"]
    assert [n["text"] for n in client.get("/notes", headers=_as(alice)).json()] == ["buy clay"]
    assert client.get(f"/notes/{note_id}", headers=_as(tara)).status_code == 200        # the team's admin may
    assert client.put(f"/notes/{note_id}", json={"text": "buy more clay"}, headers=_as(alice)).status_code == 200
    assert "buy more clay" in client.get("/export", headers=_as(alice)).text
    assert client.get(f"/teams/{made.json()['team_id']}/notes", headers=_as(alice)).status_code == 200
    assert client.delete(f"/notes/{note_id}", headers=_as(alice)).status_code == 204
    assert client.get("/notes", headers=_as(alice)).json() == []

    up = client.post("/files", params={"name": "list.txt"}, content=b"clay, glaze", headers=_as(alice))
    assert up.status_code == 201
    down = client.get(f"/files/{up.json()['id']}", headers=_as(alice))
    assert down.content == b"clay, glaze" and down.headers["content-disposition"] == "attachment"
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w") as z:
        z.writestr("notes/one.txt", "one")
        z.writestr("two.txt", "two")
    assert client.post("/import", content=packed.getvalue(), headers=_as(alice)).json() == {"files": 2}

    back = client.get("/go", params={"next": "/notes"})
    assert back.status_code == 303 and back.headers["location"] == "/notes"
    read_only = client.post("/tokens", json={"scope": "read"}, headers=_as(alice)).json()["token"]
    assert client.get("/notes", headers=_as(read_only)).status_code == 200

    db = sqlite3.connect(data / "corkboard.db")
    db.execute("INSERT INTO coupons (code, amount) VALUES ('WELCOME', 50)")
    db.commit()
    assert client.post("/coupons/redeem", json={"code": "WELCOME"}, headers=_as(alice)).json() == {"credits_added": 50}
    tara_id = client.get("/me", headers=_as(tara)).json()["id"]
    sent = client.post("/transfer", json={"to": tara_id, "amount": 20}, headers={**_as(alice), "Idempotency-Key": "k1"})
    assert sent.status_code == 200
    assert client.get("/me", headers=_as(alice)).json()["credits"] == 30
    assert client.get("/me", headers=_as(tara)).json()["credits"] == 20
    alice_id = client.get("/me", headers=_as(alice)).json()["id"]
    assert client.delete(f"/admin/users/{alice_id}", headers=_as(tara)).status_code == 204
    assert client.get("/me", headers=_as(alice)).status_code == 401
    db.close()


def test_the_safe_app_says_no_in_the_ordinary_ways(safe_app):
    """A handful of refusals, each with the answer a person would get. The behaviour runner asks far more, and
    looks at what changed; this is only that the app under it is a real one."""
    client, _ = safe_app
    made = client.post("/teams", json={"name": "Kiln", "email": "tara@kiln.test", "password": "tara-password"})
    tara = client.post("/login", json={"email": "tara@kiln.test", "password": "tara-password"}).json()["token"]
    assert client.get("/notes").status_code == 401
    assert client.get("/notes", headers=_as(tara[:-2] + "xx")).status_code == 401
    assert client.post("/teams", json={"name": "Kiln", "email": "other@kiln.test", "password": "x" * 8}).status_code == 409
    assert client.post("/signup", json={"invite": "nope", "email": "a@b.test", "password": "x" * 8}).status_code == 404
    assert client.post("/notes", json={"text": ""}, headers=_as(tara)).status_code == 422
    assert client.post("/files", params={"name": "page.html"}, content=b"<p>", headers=_as(tara)).status_code == 415
    assert client.post("/import", content=b"not a zip", headers=_as(tara)).status_code == 400
    assert client.get("/go", params={"next": "//elsewhere.test/"}).headers["location"] == "/"
    assert client.post("/transfer", json={"to": 999, "amount": 5}, headers=_as(tara)).status_code == 404
    assert client.post("/coupons/redeem", json={"code": "NOPE"}, headers=_as(tara)).status_code == 409
    assert client.delete(f"/admin/users/{made.json()['user_id']}", headers=_as(tara)).status_code == 409
