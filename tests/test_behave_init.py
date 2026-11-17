"""A first behaviour plan written from the code (roadmap stage 4: `lantern behave --init`, `lantern/behave_init.py`).

Two halves. The first reads small FastAPI projects written here and looks at the plan Lantern drafts for each:
nothing of a project is run, so these tests are the same on every system. The second starts an app in the test
sandbox with the plan exactly as Lantern wrote it: a small notes app that is right, where every case must hold,
beside versions of it with one piece changed, where the case for that piece must break and no other."""
import importlib.util
import json
import os
from pathlib import Path

import pytest
from test_server import call, srv, wait  # noqa: F401  (srv: the app on 127.0.0.1 with its token)

import lantern
from lantern import behave, behave_init, cli, learn, sandbox

ROOT = Path(__file__).resolve().parents[1]
starts_an_app = pytest.mark.skipif(bool(sandbox.NO_APPS), reason=f"no app is started here: {sandbox.NO_APPS}")


def _project(folder: Path, files: dict) -> Path:
    for rel, text in files.items():
        path = folder / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return folder


def _drafted(tmp_path: Path, files) -> dict:
    made = behave_init.draft(_project(tmp_path / "project", files if isinstance(files, dict) else {"main.py": files}))
    if made["plan"] is not None:
        behave.check(json.loads(json.dumps(made["plan"])))          # what is drafted is a plan the runner takes
    return made


def _check(made: dict, name: str) -> dict:
    found = [c for c in made["plan"]["checks"] if c["id"] == name]
    assert len(found) == 1, [c["id"] for c in made["plan"]["checks"]]
    return found[0]


def _left(made: dict) -> dict:
    return {row["route"]: row["why"] for row in made["left_out"]}


def _review(made: dict, name: str) -> str:
    return " ".join(row["why"] for row in made["review"] if row["check"] == name)


# ------------------------------------------------------------------------------------------- apps that are only read
# The start of every app below: where the data is, who is calling, a sign-up and a sign-in. None of it has to work:
# these are read, never started.
HEAD = '''
import os
import sqlite3
from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, Form, Header, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, HttpUrl

DB = os.environ.get("BOARD_DB", "board.db")
app = FastAPI()


class Account(BaseModel):
    email: str
    password: str


def current_user(authorization: str = Header(default="")) -> int:
    row = sqlite3.connect(DB).execute("SELECT user_id FROM sessions WHERE token = ?", (authorization[7:],)).fetchone()
    if row is None:
        raise HTTPException(401, "Sign in first")
    return row[0]


@app.post("/signup")
def signup(account: Account):
    return {"id": 1}


@app.post("/login")
def login(account: Account):
    return {"token": "t"}
'''
ME = '''

@app.get("/me")
def me(user: int = Depends(current_user)):
    return {"id": user}
'''
BEFORE_THE_DOORS = HEAD.split('@app.post("/signup")')[0]
SEED = [
    {"request": {"method": "POST", "path": "/signup", "json": {"email": "alice@example.test", "password": "Alice-pass-phrase-1"}}},
    {"request": {"method": "POST", "path": "/signup", "json": {"email": "bob@example.test", "password": "Bob-pass-phrase-1"}}},
    {"request": {"method": "POST", "path": "/login", "json": {"email": "alice@example.test", "password": "Alice-pass-phrase-1"}},
     "save": {"alice_token": "json:token"}},
    {"request": {"method": "POST", "path": "/login", "json": {"email": "bob@example.test", "password": "Bob-pass-phrase-1"}},
     "save": {"bob_token": "json:token"}},
]
FACTORY = (HEAD + ME).replace("app = FastAPI()", "app = APIRouter()\n\n\ndef create_app():\n    made = FastAPI()\n"
                                                 "    made.include_router(app)\n    return made")


@pytest.mark.parametrize("files, app", [
    ({"main.py": HEAD + ME}, {"asgi": "main:app"}),
    ({"shop/__init__.py": "", "shop/api.py": HEAD + ME}, {"asgi": "shop.api:app"}),
    # a folder that is no package is the folder the app is started in
    ({"backend/main.py": HEAD + ME}, {"asgi": "main:app", "cwd": "backend"}),
    # ... unless the file reaches for the file beside it with a dot, which only works from the folder above
    ({"pkg/main.py": "from . import store\n" + HEAD + ME, "pkg/store.py": "X = 1\n"}, {"asgi": "pkg.main:app"}),
    ({"main.py": FACTORY}, {"asgi": "main:create_app", "factory": True}),
])
def test_the_app_is_found_where_it_is_made_and_named_the_way_it_is_loaded(tmp_path, files, app):
    made = _drafted(tmp_path, files)
    plan = made["plan"]
    assert plan["app"] == {**app, "env": {"BOARD_DB": "{data}/app.db"}}
    assert plan["state"] == {"sqlite": ["{data}/app.db"]}
    assert plan["people"] == {"alice": {"token": "{alice_token}"}, "bob": {"token": "{bob_token}"}}
    assert plan["seed"] == SEED
    assert [c["id"] for c in plan["checks"]] == ["get-me", "limit-post-login"]
    assert _check(made, "get-me") == {
        "id": "get-me", "kind": "refuse", "request": {"method": "GET", "path": "/me"}, "who": ["nobody"], "allowed": ["alice"],
        "about": "GET /me is for people who are signed in: a visitor who is not must be turned away."}
    assert made["cases"] == 5 and made["left_out"] == [] and made["why_not"] is None


def test_the_same_code_gives_the_same_plan_and_nothing_of_the_project_is_run(tmp_path):
    ran = 'open("ran.txt", "w").write("the app was loaded")\n'
    repo = _project(tmp_path / "project", {"main.py": ran + HEAD + ROUTES + LIMITS})
    first = behave_init.draft(repo)
    second = behave_init.draft(repo)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True) and first["plan"]["checks"]
    assert sorted(p.name for p in repo.iterdir()) == ["main.py"]


@pytest.mark.parametrize("files, said", [
    ({"tool.py": "print('hello')\n"}, "found none made in this project's code"),
    ({"app.py": "from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.post('/login')\ndef login():\n    return {}\n"},
     "found none made in this project's code"),
    # an app with no way to make an account, and one whose sign-in hands out nothing to sign requests with
    ({"main.py": BEFORE_THE_DOORS + ME}, "not a request that makes an account"),
    ({"main.py": (HEAD + ME).replace('return {"token": "t"}', 'return {"ok": True}')},
     "not a sign-in that answers with a token"),
])
def test_where_no_plan_can_be_written_none_is_and_the_reason_is_said(tmp_path, files, said):
    made = _drafted(tmp_path, files)
    assert made["plan"] is None and said in made["why_not"] and "docs/behaviour.md" in made["why_not"]
    written = behave_init.write(tmp_path / "project")
    assert written["written"] is None and not (tmp_path / "project" / behave.PLAN_NAME).exists()


def test_an_app_whose_sign_up_hands_out_the_token_needs_no_sign_in(tmp_path):
    only_signup = HEAD.split('@app.post("/login")')[0].replace('return {"id": 1}', 'return {"id": 1, "token": "t"}')
    made = _drafted(tmp_path, only_signup + ME)
    assert made["plan"]["seed"] == [dict(step, save={f"{who}_token": "json:token"}) for step, who in zip(SEED, ("alice", "bob"))]
    assert [c["id"] for c in made["plan"]["checks"]] == ["get-me"]       # no sign-in to try wrong passwords at


FORMS = BEFORE_THE_DOORS + '''
@app.post("/register")
def register(email: str = Form(...), password: str = Form(...)):
    return {"id": 1}


@app.post("/token")
def token(form: OAuth2PasswordRequestForm = Depends()):
    return {"access_token": "t", "token_type": "bearer"}
''' + ME


def test_forms_are_sent_as_forms_and_the_sign_in_form_gets_the_account_under_its_own_names(tmp_path):
    made = _drafted(tmp_path, FORMS)
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    assert made["plan"]["seed"] == [
        {"request": {"method": "POST", "path": "/register", "headers": form,
                     "text": "email=alice%40example.test&password=Alice-pass-phrase-1"}},
        {"request": {"method": "POST", "path": "/register", "headers": form,
                     "text": "email=bob%40example.test&password=Bob-pass-phrase-1"}},
        {"request": {"method": "POST", "path": "/token", "headers": form,
                     "text": "username=alice%40example.test&password=Alice-pass-phrase-1"},
         "save": {"alice_token": "json:access_token"}},
        {"request": {"method": "POST", "path": "/token", "headers": form,
                     "text": "username=bob%40example.test&password=Bob-pass-phrase-1"},
         "save": {"bob_token": "json:access_token"}}]
    wrong = _check(made, "limit-post-token")
    assert wrong["request"]["text"] == "username=alice%40example.test&password=not-the-pass-phrase-0" and wrong["times"] == 10


# ------------------------------------------------------------------------------------------- the app's settings
SETTINGS = (HEAD + ME).replace('DB = os.environ.get("BOARD_DB", "board.db")', '''DB = os.environ.get("DATABASE_URL", "postgresql://localhost/board")
SECRET = os.environ["SESSION_SECRET"]
UPLOADS = os.getenv("UPLOAD_DIR", "uploads")
MOST = int(os.environ.get("MAX_UPLOAD_SIZE", "1000"))
SENDER = os.environ["MAIL_FROM"]''')
SETTINGS_CLASS = (HEAD + ME).replace('DB = os.environ.get("BOARD_DB", "board.db")', '''from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./board.db"
    secret_key: str
    page_size: int = 20


settings = Settings()
DB = settings.database_url''')


def test_the_settings_the_code_reads_are_handed_over_by_what_their_names_say(tmp_path):
    made = _drafted(tmp_path, SETTINGS)
    assert made["plan"]["app"]["env"] == {"DATABASE_URL": "sqlite:///{data}/app.db", "SESSION_SECRET": "{secret}",
                                          "UPLOAD_DIR": "{data}/upload-dir"}
    assert made["plan"]["state"] == {"sqlite": ["{data}/app.db"], "folders": ["{data}/upload-dir"]}
    notes = " ".join(made["notes"])
    # a database of another kind is said, and so is a setting with no value that Lantern cannot make one for
    assert "DATABASE_URL names a database of another kind by default (postgresql)" in notes
    assert "The app reads the setting MAIL_FROM (main.py:16) and has no value for it" in notes
    assert "MAX_UPLOAD_SIZE" not in notes and "SESSION_SECRET" not in notes


def test_a_settings_class_is_read_field_by_field(tmp_path):
    made = _drafted(tmp_path, SETTINGS_CLASS)
    assert made["plan"]["app"]["env"] == {"DATABASE_URL": "sqlite:///{data}/app.db", "SECRET_KEY": "{secret}"}
    assert made["plan"]["state"] == {"sqlite": ["{data}/app.db"]}


def test_a_database_place_written_in_the_code_is_said_first_and_a_setting_beside_it_is_not(tmp_path):
    fixed = (HEAD + ME).replace('DB = os.environ.get("BOARD_DB", "board.db")\n', "").replace("sqlite3.connect(DB)",
                                                                                           'sqlite3.connect("board.db")')
    made = _drafted(tmp_path, fixed)
    assert "state" not in made["plan"] and "env" not in made["plan"]["app"]
    assert made["notes"][0].startswith("The app opens its database at a place written in the code (main.py:21).")
    assert "Let the app read the place from a setting" in made["notes"][0]
    # the twin: the place comes from a setting, and nothing is said
    assert not _drafted(tmp_path / "twin", HEAD + ME)["notes"]


def test_tables_named_for_a_record_of_what_was_tried_may_change_at_a_refusal(tmp_path):
    tables = '''
sqlite3.connect(DB).executescript("""
    CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, text TEXT);
    CREATE TABLE IF NOT EXISTS login_attempts (email TEXT PRIMARY KEY, wrong INTEGER);
    create table audit_log (id INTEGER PRIMARY KEY, what TEXT);
    CREATE TABLE catalogue (id INTEGER PRIMARY KEY);
""")
'''
    made = _drafted(tmp_path, HEAD + tables + ME)
    assert made["plan"]["quiet_tables"] == ["audit_log", "login_attempts"]
    assert "audit_log, login_attempts" in " ".join(made["notes"])
    assert "quiet_tables" not in _drafted(tmp_path / "twin", HEAD + ME)["plan"]


# ------------------------------------------------------------------------------------------- what a request carries
VALUES = '''

class Colour(str, Enum):
    red = "red"
    blue = "blue"


class Size(BaseModel):
    width: int = Field(gt=3)
    unit: Literal["cm", "in"]


class Thing(BaseModel):
    title: str
    email: EmailStr
    colour: Colour
    size: Size
    tags: list[str] = []
    website: HttpUrl
    code: str = Field(min_length=12)
    when: datetime
    count: int = Field(ge=2, le=5)
    note: Optional[str] = None


@app.post("/things")
def add_thing(thing: Thing, user: int = Depends(current_user)):
    return {"id": 1}


class Odd(BaseModel):
    shape: complex


@app.post("/odd")
def add_odd(odd: Odd, user: int = Depends(current_user)):
    return {"id": 1}


@app.post("/photos")
def add_photo(picture: bytes, user: int = Depends(current_user)):
    return {"id": 1}


@app.post("/hooks")
def add_hook(x_signature: str = Header(...), user: int = Depends(current_user)):
    return {"id": 1}
'''


def test_a_body_is_filled_in_by_the_type_and_the_name_of_each_field_it_cannot_do_without(tmp_path):
    made = _drafted(tmp_path, HEAD + VALUES)
    assert _check(made, "post-things")["request"] == {"method": "POST", "path": "/things", "json": {
        "title": "written by a check of Lantern", "email": "somebody@example.test", "colour": "red",
        "size": {"width": 4, "unit": "cm"}, "website": "https://example.test/", "code": "textxxxxxxxx",
        "when": "2026-01-01T12:00:00", "count": 2}}
    # a text under a name Lantern does not know is made up and said; a value it cannot make leaves the route out
    assert "Lantern made up a value for `code`" in _review(made, "post-things")
    # an address is made up too, and an app that fetches it or keeps a list of its own will refuse it: said
    assert "Lantern made up an address for `website` (https://example.test/)" in _review(made, "post-things")
    assert _left(made) == {
        "POST /odd": "`shape` is of a kind Lantern cannot make a value for (`complex`)",
        "POST /photos": "it takes an uploaded file",
        "POST /hooks": "it needs the header x-signature, which Lantern cannot fill in"}
    assert made["left_out"][0]["where"] == "main.py:70"


NOTHING_HAS_TO_BE_SENT = '''

class Profile(BaseModel):
    website: Optional[HttpUrl] = None
    colour: Optional[str] = None
    nickname: Optional[str] = None
    description: str | None = Field(default=None, max_length=200)
    public: bool = False


class Look(BaseModel):
    colour: Optional[str] = None
    website: Optional[HttpUrl] = None
    public: bool = False


@app.patch("/me")
def change_me(profile: Profile, user: int = Depends(current_user)):
    return {}


@app.patch("/look")
def change_look(look: Look, user: int = Depends(current_user)):
    return {}
'''


def test_a_body_in_which_nothing_has_to_be_sent_is_not_sent_empty_where_lantern_is_sure_of_one_field(tmp_path):
    made = _drafted(tmp_path, HEAD + NOTHING_HAS_TO_BE_SENT)
    # sent empty the request changes nothing, and a refusal beside a request that changed nothing proves nothing:
    # one field Lantern is sure of, a free text before a name; never a made-up value, an address or a switch
    assert _check(made, "patch-me")["request"] == {"method": "PATCH", "path": "/me",
                                                   "json": {"description": "written by a check of Lantern"}}
    assert "empty body" not in _review(made, "patch-me")
    # sure of none: the body stays empty, and the plan says what that means for the case
    assert _check(made, "patch-look")["request"] == {"method": "PATCH", "path": "/look", "json": {}}
    assert "Lantern sends PATCH /look an empty body" in _review(made, "patch-look")


# ------------------------------------------------------------------------------------------- which routes get a case
ROUTES = '''

class NoteIn(BaseModel):
    text: str


class PetOut(BaseModel):
    id: int
    name: str


class PetIn(BaseModel):
    name: str


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/about")
def about():
    return {"name": "Board"}


@app.get("/stats")
def stats():
    n = sqlite3.connect(DB).execute("SELECT count(*) FROM notes").fetchone()[0]
    return {"notes": n}


@app.get("/me")
def me(user: int = Depends(current_user)):
    return {"id": user}


@app.delete("/widgets/{widget_id}")
def remove_widget(widget_id: int, user: int = Depends(current_user)):
    return {}


@app.post("/notes")
def add_note(note: NoteIn, user: int = Depends(current_user)):
    return {"id": 1}


@app.get("/notes/{note_id}")
def read_note(note_id: int, user: int = Depends(current_user)):
    return {"id": note_id, "text": "x"}


@app.post("/orders")
def add_order(note: NoteIn, user: int = Depends(current_user)):
    return {"order_id": 1}


@app.delete("/orders/{order_id}")
def remove_order(order_id: int, user: int = Depends(current_user)):
    return {}


@app.post("/pets", response_model=PetOut)
def add_pet(pet: PetIn, user: int = Depends(current_user)):
    return make_pet(pet)


@app.put("/pets/{pet_id}")
def change_pet(pet_id: int, pet: PetIn, user: int = Depends(current_user)):
    return {}


@app.post("/boxes")
def add_box(note: NoteIn, user: int = Depends(current_user)):
    return {"ok": True}


@app.delete("/boxes/{box_id}")
def remove_box(box_id: int, user: int = Depends(current_user)):
    return {}


@app.post("/cards")
def add_card(note: NoteIn):
    return {"id": 1}


@app.delete("/cards/{card_id}")
def remove_card(card_id: int, user: int = Depends(current_user)):
    return {}


@app.get("/teams/{team_id}/notes/{note_id}")
def team_note(team_id: int, note_id: int, user: int = Depends(current_user)):
    return {}


@app.post("//double")
def double(note: NoteIn, user: int = Depends(current_user)):
    return {}
'''


def test_every_route_that_changes_something_or_asks_who_is_calling_gets_a_case_without_a_login(tmp_path):
    made = _drafted(tmp_path, HEAD + ROUTES)
    assert [c["id"] for c in made["plan"]["checks"]] == [
        "get-stats", "get-me", "post-notes", "get-notes-note-id", "post-orders", "delete-orders-order-id", "post-pets",
        "put-pets-pet-id", "post-boxes", "post-cards", "limit-post-login"]
    for name in ("get-stats", "get-me", "post-notes", "post-orders", "post-pets", "post-boxes", "post-cards"):
        case = _check(made, name)
        # nobody is turned away, beside alice who is let in: a refusal that turns everybody away proves nothing
        assert (case["kind"], case["who"], case["allowed"]) == ("refuse", ["nobody"], ["alice"]) and "arrange" not in case
    assert _check(made, "post-notes")["about"].startswith("POST /notes changes what the app keeps")
    assert made["cases"] == 26


def test_a_page_for_everyone_gets_no_case_and_a_page_that_reads_what_the_app_keeps_gets_one_to_look_at(tmp_path):
    made = _drafted(tmp_path, HEAD + ROUTES)
    left = _left(made)
    assert left["GET /health"] == "its address is one made to be open (a sign-in, a webhook, a health page)"
    assert left["GET /about"].endswith("it looks like a page for everyone")
    # the look-alike: no login in its code either, but it reads the notes table
    assert "shows no check of who is calling, and it reads what the app keeps" in _review(made, "get-stats")
    assert 'this case will read "let in"' in _review(made, "get-stats")
    # a route that changes something with no login in its code: the case stands, and says what it will read
    assert "The code of POST /cards shows no check of who is calling." in _review(made, "post-cards")
    assert _review(made, "get-me") == "" and _review(made, "post-notes") == ""


def test_a_row_picked_by_a_number_is_asked_for_by_somebody_else_who_is_signed_in(tmp_path):
    made = _drafted(tmp_path, HEAD + ROUTES)
    read = _check(made, "get-notes-note-id")
    assert read == {
        "id": "get-notes-note-id", "kind": "refuse", "request": {"method": "GET", "path": "/notes/{alice_note}"},
        "who": ["bob", "nobody"], "allowed": ["alice"], "must_not_say": ["kept by alice"],
        "arrange": [{"request": {"method": "POST", "path": "/notes", "json": {"text": "kept by alice"}}, "as": "alice",
                     "save": {"alice_note": "json:id"}}],
        "about": "GET /notes/{note_id} is asked for a row that alice made: bob, who is signed in as somebody else, and a "
                 "visitor who is not signed in must both be turned away."}
    assert 'take "bob" out of this case\'s "who"' in _review(made, "get-notes-note-id")
    # the new row's number is read from the answer under the name the code gives it: `order_id`, or a field of the
    # model the route says it answers with
    assert _check(made, "delete-orders-order-id")["arrange"][0]["save"] == {"alice_order": "json:order_id"}
    assert _check(made, "delete-orders-order-id")["request"] == {"method": "DELETE", "path": "/orders/{alice_order}"}
    assert "must_not_say" not in _check(made, "delete-orders-order-id")
    changed = _check(made, "put-pets-pet-id")
    assert changed["arrange"][0]["save"] == {"alice_pet": "json:id"}
    # what alice changes it to is not what the row was made with, or her own request would change nothing
    assert changed["arrange"][0]["request"]["json"] != changed["request"]["json"]


def test_a_row_lantern_cannot_make_leaves_its_route_out_with_the_reason(tmp_path):
    left = _left(_drafted(tmp_path, HEAD + ROUTES))
    assert left["DELETE /widgets/{widget_id}"] == "Lantern found no request that makes a row for it (a POST to /widgets)"
    assert left["DELETE /boxes/{box_id}"] == ("the answer of POST /boxes does not show the new row's number in a way "
                                              "Lantern can read")
    assert left["DELETE /cards/{card_id}"] == ("the request that makes a row for it (POST /cards) does not ask who is "
                                               "calling, so the row would be nobody's")
    assert left["GET /teams/{team_id}/notes/{note_id}"] == "its address names more than one row, and Lantern makes one"
    # an address a plan cannot hold costs that route, not the plan
    assert left["POST //double"] == "its address is not one a plan can hold"
    assert len(left) == 7


# ------------------------------------------------------------------------------------------- limits and repeats
LIMITS = '''
import openai
from slowapi import Limiter

limiter = Limiter(key_func=lambda request: "x")


class Question(BaseModel):
    question: str


class Payment(BaseModel):
    amount: int


@app.post("/ask")
def ask(q: Question, user: int = Depends(current_user)):
    client = openai.OpenAI()
    return client.chat.completions.create(model="m", messages=[{"role": "user", "content": q.question}])


@app.post("/payments")
def pay(payment: Payment, idempotency_key: Optional[str] = Header(default=None), user: int = Depends(current_user)):
    return {"id": 1}


@app.post("/echo")
def echo(q: Question, user: int = Depends(current_user)):
    return {"said": q.question}
'''
LIMITED_LOGIN = HEAD.replace('@app.post("/login")', '@app.post("/login")\n@limiter.limit("5/minute")')


def test_wrong_passwords_are_tried_as_often_as_the_limit_written_on_the_sign_in_says(tmp_path):
    written = _drafted(tmp_path, LIMITED_LOGIN + LIMITS)
    wrong = _check(written, "limit-post-login")
    assert wrong["kind"] == "limit" and wrong["times"] == 5 and "who" not in wrong
    assert wrong["request"]["json"] == {"email": "alice@example.test", "password": "not-the-pass-phrase-0"}
    assert _review(written, "limit-post-login") == ""
    # the twin with no limit written on the route: ten, and a line that says to raise it for an app that allows more
    plain = _drafted(tmp_path / "twin", HEAD + LIMITS)
    assert _check(plain, "limit-post-login")["times"] == 10
    assert 'raise "times"' in _review(plain, "limit-post-login")


def test_a_route_that_reaches_a_paid_service_gets_a_limit_case_and_a_payment_a_case_for_twice(tmp_path):
    made = _drafted(tmp_path, HEAD + LIMITS)
    assert [c["id"] for c in made["plan"]["checks"]] == [
        "post-ask", "post-payments", "post-echo", "limit-post-login", "limit-post-ask", "once-post-payments",
        "retry-post-payments"]
    paid = _check(made, "limit-post-ask")
    assert (paid["kind"], paid["who"], paid["times"], paid["may_reach"]) == ("limit", "alice", 10, ["api.openai.com"])
    assert "The sandbox has no network" in _review(made, "limit-post-ask")
    # the case without a login for that route may not reach the service for a visitor: no `may_reach` on it
    assert "may_reach" not in _check(made, "post-ask")
    assert "reads undecided where the visitor is turned away" in _review(made, "post-ask")
    once = _check(made, "once-post-payments")
    assert (once["kind"], once["who"], once["request"]["json"]) == ("once", "alice", {"amount": 1})
    again = _check(made, "retry-post-payments")
    assert again["kind"] == "retry" and again["request"]["headers"] == {"Idempotency-Key": "lantern-check-1"}
    # the look-alike: a route that pays for nothing and repeats nothing gets its case without a login and no more
    assert not [c["id"] for c in made["plan"]["checks"] if c["id"].endswith("post-echo") and c["id"] != "post-echo"]


# ------------------------------------------------------------------------------------------- files built to hold it up
def test_a_file_python_cannot_read_and_a_file_nested_very_deep_cost_only_themselves(tmp_path):
    made = _drafted(tmp_path, {"main.py": HEAD + ME, "broken.py": "def f(:\n   ((((\n",
                               "deep.py": "x = " + "(" * 3000 + "1" + ")" * 3000 + "\n",
                               "wide.py": "x = [" + "1, " * 150_000 + "]\n"})
    assert [c["id"] for c in made["plan"]["checks"]] == ["get-me", "limit-post-login"] and made["plan"]["seed"] == SEED


# ------------------------------------------------------------------------------------------- the file and the command
def test_the_plan_is_written_once_and_a_plan_that_is_there_is_left_alone(tmp_path):
    repo = _project(tmp_path / "project", {"main.py": HEAD + ROUTES})
    made = behave_init.write(repo)
    target = repo / behave.PLAN_NAME
    assert made["written"] == str(target) and made["exists"] is False
    plan = json.loads(target.read_text(encoding="utf-8"))
    behave.check(json.loads(json.dumps(plan)))
    assert behave.load(repo) is not None
    # what Lantern was not sure of and what it left out is in the file itself, for whoever reads it later
    assert set(plan["notes"]) == {"made_by", "read_first", "review", "left_out"} and len(plan["notes"]["left_out"]) == 7
    assert plan["notes"]["made_by"].startswith("lantern behave --init (Lantern ")
    target.write_text('{"mine": true}\n', encoding="utf-8")
    again = behave_init.write(repo)
    assert again["written"] is None and again["exists"] is True and "left as it is" in again["why_not"]
    assert target.read_text(encoding="utf-8") == '{"mine": true}\n'
    forced = behave_init.write(repo, force=True)
    assert forced["written"] == str(target) and json.loads(target.read_text(encoding="utf-8")) == plan


def test_a_link_at_the_plans_place_is_replaced_and_what_it_pointed_at_is_left_alone(tmp_path):
    repo = _project(tmp_path / "project", {"main.py": HEAD + ME})
    outside = tmp_path / "somebody-elses.json"
    outside.write_text("not the project's\n", encoding="utf-8")
    try:
        os.symlink(outside, repo / behave.PLAN_NAME)
    except (OSError, NotImplementedError):
        pytest.skip("no link can be made here")
    assert behave_init.write(repo)["written"] is None                 # something is there: left as it is
    assert behave_init.write(repo, force=True)["written"]
    assert not (repo / behave.PLAN_NAME).is_symlink() and "checks" in json.loads((repo / behave.PLAN_NAME).read_text(encoding="utf-8"))
    assert outside.read_text(encoding="utf-8") == "not the project's\n"


def test_the_command_writes_the_plan_says_what_to_look_at_and_ends_with_0(tmp_path, capsys):
    repo = _project(tmp_path / "project", {"main.py": HEAD + ROUTES})
    assert cli.main(["behave", str(repo), "--init"]) == 0
    said = capsys.readouterr().out
    lines = said.splitlines()
    assert lines[0] == "app           main:app" and "setting       BOARD_DB={data}/app.db" in lines
    assert "plan          11 checks, 26 requests" in lines
    assert sum(line.startswith("look at ") for line in lines) == 6 and sum(line.startswith("left out ") for line in lines) == 7
    assert lines[-2] == f"wrote         {repo / behave.PLAN_NAME}"
    assert lines[-1] == f"next          read {behave.PLAN_NAME}, change what does not fit the app, then: lantern behave {repo}"
    # a second time nothing is written, and the command says so with 2; --force writes it again
    before = (repo / behave.PLAN_NAME).read_text(encoding="utf-8")
    assert cli.main(["behave", str(repo), "--init"]) == 2
    assert capsys.readouterr().out == ("not written   the project has a lantern-behaviour.json already, and it was left as "
                                       "it is (--force writes a new one over it)\n")
    assert cli.main(["behave", str(repo), "--init", "--force"]) == 0
    assert (repo / behave.PLAN_NAME).read_text(encoding="utf-8") == before


def test_the_command_says_why_it_wrote_nothing_and_force_alone_is_refused(tmp_path, capsys):
    bare = _project(tmp_path / "bare", {"tool.py": "print('hello')\n"})
    assert cli.main(["behave", str(bare), "--init"]) == 2
    assert "not written   Lantern writes a first plan for a FastAPI app" in capsys.readouterr().out
    assert not (bare / behave.PLAN_NAME).exists()
    assert cli.main(["behave", str(bare), "--force"]) == 2
    assert "--force goes with --init" in capsys.readouterr().err
    assert cli.main(["behave", str(tmp_path / "nothing-here"), "--init"]) == 2


def test_a_long_list_is_cut_short_on_the_terminal_and_whole_in_the_file(tmp_path, capsys):
    many = "".join(f'\n\n@app.get("/page{n}")\ndef page{n}():\n    return {{"n": {n}}}\n' for n in range(20))
    repo = _project(tmp_path / "project", {"main.py": HEAD + ME + many})
    assert cli.main(["behave", str(repo), "--init"]) == 0
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("left out ")]
    assert len(lines) == 13 and lines[-1] == ('left out      and 8 more routes with no check (all of them are in the file, '
                                              'under "notes")')
    assert len(json.loads((repo / behave.PLAN_NAME).read_text(encoding="utf-8"))["notes"]["left_out"]) == 20


def test_text_from_the_code_reaches_the_terminal_printable(tmp_path, capsys):
    odd = '\n\n@app.get("/a\x1b[31mb")\ndef coloured():\n    return {"n": 1}\n'
    repo = _project(tmp_path / "project", {"main.py": HEAD + ME + odd})
    assert cli.main(["behave", str(repo), "--init"]) == 0
    said = capsys.readouterr().out
    assert "\x1b" not in said and "left out      GET /a?[31mb: " in said


# ------------------------------------------------------------------------------------------- the same from the app
def _in_the_app(base, repo) -> str:
    code, p = call(base, "/api/projects", "POST", {"path": str(repo)})
    assert code == 200, p
    return (p.get("project") or p)["id"]


def _pressed(base, pid, body=None) -> dict:
    code, job = call(base, f"/api/projects/{pid}/behaviourplan", "POST", body or {})
    assert code == 202 and job["kind"] == "plan", job
    done = wait(base, job["id"])
    assert done["status"] == "done", done
    return done["result"]


def test_the_apps_button_writes_the_plan_the_command_writes_and_leaves_one_that_is_there_alone(srv, tmp_path):  # noqa: F811
    base, _ = srv
    repo = _project(tmp_path / "project", {"main.py": HEAD + ROUTES})
    twin = _project(tmp_path / "twin", {"main.py": HEAD + ROUTES})
    assert behave_init.write(twin)["written"]
    as_the_command_wrote_it = (twin / behave.PLAN_NAME).read_text(encoding="utf-8")
    pid = _in_the_app(base, repo)
    r = _pressed(base, pid)
    assert r["written"] is True and r["file"] == behave.PLAN_NAME and r["exists"] is False
    assert (r["checks"], r["requests"]) == (11, 26) and r["counts"] == {"read_first": 0, "look_at": 6, "left_out": 7}
    assert r["line"] == ("lantern-behaviour.json holds 11 checks (26 requests) for main:app. 6 of them are marked to look at "
                         "first, and 7 routes were left out, each with the reason.")
    assert "lantern behave" in r["next"] and len(r["look_at"]) == 6 and r["left_out"][0].startswith("GET /health: ")
    assert (repo / behave.PLAN_NAME).read_text(encoding="utf-8") == as_the_command_wrote_it
    # the plan is the one thing written: the results folder the app made when the project was added stays empty
    assert sorted(p.name for p in repo.iterdir()) == [".lantern", behave.PLAN_NAME, "main.py"]
    assert not list((repo / ".lantern").iterdir())
    # pressed again, nothing is written and the answer says a plan is there; with the person's word it is written over
    (repo / behave.PLAN_NAME).write_text('{"mine": true}\n', encoding="utf-8")
    assert _pressed(base, pid) == {"written": False, "exists": True,
                                   "why": "the project has a lantern-behaviour.json already, and it was left as it is"}
    assert (repo / behave.PLAN_NAME).read_text(encoding="utf-8") == '{"mine": true}\n'
    for odd in ("yes", 1, 0, ["true"]):
        assert call(base, f"/api/projects/{pid}/behaviourplan", "POST", {"force": odd})[0] == 400, odd
    assert (repo / behave.PLAN_NAME).read_text(encoding="utf-8") == '{"mine": true}\n'
    assert _pressed(base, pid, {"force": True})["written"] is True
    assert (repo / behave.PLAN_NAME).read_text(encoding="utf-8") == as_the_command_wrote_it


def test_the_app_says_in_lanterns_sentence_why_no_plan_was_written(srv, tmp_path):  # noqa: F811
    base, _ = srv
    bare = _project(tmp_path / "bare", {"tool.py": "print('hello')\n"})
    r = _pressed(base, _in_the_app(base, bare))
    assert r["written"] is False and r["exists"] is False and "Lantern writes a first plan for a FastAPI app" in r["why"]
    assert sorted(p.name for p in bare.iterdir()) == [".lantern", "tool.py"] and not list((bare / ".lantern").iterdir())


def test_the_page_has_one_button_for_it_and_the_sentences_about_the_plan_are_the_servers():
    page = (Path(lantern.__file__).parent / "viewer" / "app.html").read_text(encoding="utf-8")
    assert page.count('id="behaviourplan"') == 1                    # one button on a project's screen, in both views
    assert "/behaviourplan`, {method: 'POST', body: force ? {force: true} : {}}" in page
    assert "esc(r.line || '')" in page and "esc(r.next || '')" in page and "String(r.why" in page
    assert page.count("data-planover") == 2                         # the button in the message, and the place that hears it
    assert "r.exists === true" in page                              # offered only where a plan is there already
    assert page.count(".sub #behaviourplan span") == 2              # an icon where the screen is narrow, as its neighbours


# ------------------------------------------------------------------------------------------- the plan, run as written
# Pinboard: one person's notes, with a sign-up, a sign-in that counts wrong passwords in the database, and notes
# that only their owner reads, changes and removes. Each part below has its right form and, beside it, forms with
# one thing wrong.
PIN_HEAD = '''"""Pinboard: one person's notes."""
import hashlib
import os
import secrets
import sqlite3

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

DB = os.environ.get("PINBOARD_DB", "pinboard.db")
MOST_WRONG = 5
WRONG = {}
app = FastAPI()


def get_db():
    return sqlite3.connect(DB)


def make_tables():
    con = get_db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT);
        CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER);
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner INTEGER, text TEXT);
        CREATE TABLE IF NOT EXISTS login_attempts (email TEXT PRIMARY KEY, wrong INTEGER);
    """)
    con.commit()
    con.close()


make_tables()


class Account(BaseModel):
    email: str
    password: str


class NoteIn(BaseModel):
    text: str


def hashed(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"pinboard", 1000).hex()


def current_user(authorization: str = Header(default="")) -> int:
    con = get_db()
    row = con.execute("SELECT user_id FROM sessions WHERE token = ?", (authorization.removeprefix("Bearer "),)).fetchone()
    con.close()
    if row is None:
        raise HTTPException(401, "Sign in first")
    return row[0]


@app.post("/signup")
def signup(account: Account):
    con = get_db()
    try:
        made = con.execute("INSERT INTO users (email, password) VALUES (?, ?)", (account.email, hashed(account.password)))
        con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That e-mail has an account")
    finally:
        con.close()
    return {"id": made.lastrowid}


@app.post("/notes")
def add_note(note: NoteIn, user: int = Depends(current_user)):
    con = get_db()
    made = con.execute("INSERT INTO notes (owner, text) VALUES (?, ?)", (user, note.text))
    con.commit()
    con.close()
    return {"id": made.lastrowid}
'''
LOGIN = '''

@app.post("/login")
def login(account: Account):
    con = get_db()
    wrong = con.execute("SELECT wrong FROM login_attempts WHERE email = ?", (account.email,)).fetchone()
    if wrong and wrong[0] >= MOST_WRONG:
        con.close()
        raise HTTPException(429, "Too many wrong passwords")
    row = con.execute("SELECT id, password FROM users WHERE email = ?", (account.email,)).fetchone()
    if row is None or row[1] != hashed(account.password):
        con.execute("INSERT INTO login_attempts (email, wrong) VALUES (?, 1) "
                    "ON CONFLICT(email) DO UPDATE SET wrong = wrong + 1", (account.email,))
        con.commit()
        con.close()
        raise HTTPException(401, "Wrong e-mail or password")
    token = secrets.token_urlsafe(24)
    con.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, row[0]))
    con.commit()
    con.close()
    return {"token": token}
'''
LOGIN_NO_LIMIT = '''

@app.post("/login")
def login(account: Account):
    con = get_db()
    row = con.execute("SELECT id, password FROM users WHERE email = ?", (account.email,)).fetchone()
    if row is None or row[1] != hashed(account.password):
        con.close()
        raise HTTPException(401, "Wrong e-mail or password")
    token = secrets.token_urlsafe(24)
    con.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, row[0]))
    con.commit()
    con.close()
    return {"token": token}
'''
LOGIN_COUNTS_IN_MEMORY = '''

@app.post("/login")
def login(account: Account):
    if WRONG.get(account.email, 0) >= MOST_WRONG:
        raise HTTPException(429, "Too many wrong passwords")
    con = get_db()
    row = con.execute("SELECT id, password FROM users WHERE email = ?", (account.email,)).fetchone()
    if row is None or row[1] != hashed(account.password):
        con.close()
        WRONG[account.email] = WRONG.get(account.email, 0) + 1
        raise HTTPException(401, "Wrong e-mail or password")
    token = secrets.token_urlsafe(24)
    con.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, row[0]))
    con.commit()
    con.close()
    return {"token": token}
'''
LISTING = '''

@app.get("/notes")
def list_notes(user: int = Depends(current_user)):
    con = get_db()
    rows = con.execute("SELECT id, text FROM notes WHERE owner = ?", (user,)).fetchall()
    con.close()
    return [{"id": r[0], "text": r[1]} for r in rows]
'''
LISTING_FOR_ANYBODY = '''

@app.get("/notes")
def list_notes():
    con = get_db()
    rows = con.execute("SELECT id, text FROM notes").fetchall()
    con.close()
    return [{"id": r[0], "text": r[1]} for r in rows]
'''
READ = '''

@app.get("/notes/{note_id}")
def read_note(note_id: int, user: int = Depends(current_user)):
    con = get_db()
    row = con.execute("SELECT owner, text FROM notes WHERE id = ?", (note_id,)).fetchone()
    con.close()
    if row is None or row[0] != user:
        raise HTTPException(404, "No such note")
    return {"id": note_id, "text": row[1]}
'''
READ_ANYBODYS = READ.replace("if row is None or row[0] != user:", "if row is None:")
CHANGE = '''

@app.put("/notes/{note_id}")
def change_note(note_id: int, note: NoteIn, user: int = Depends(current_user)):
    con = get_db()
    row = con.execute("SELECT owner FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None or row[0] != user:
        con.close()
        raise HTTPException(404, "No such note")
    con.execute("UPDATE notes SET text = ? WHERE id = ?", (note.text, note_id))
    con.commit()
    con.close()
    return {"id": note_id}
'''
CHANGE_ANYBODYS = CHANGE.replace("if row is None or row[0] != user:", "if row is None:")
REMOVE = '''

@app.delete("/notes/{note_id}")
def remove_note(note_id: int, user: int = Depends(current_user)):
    con = get_db()
    row = con.execute("SELECT owner FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None or row[0] != user:
        con.close()
        raise HTTPException(404, "No such note")
    con.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    con.commit()
    con.close()
    return {"removed": note_id}
'''
REMOVE_WITH_NO_LOGIN = '''

@app.delete("/notes/{note_id}")
def remove_note(note_id: int):
    con = get_db()
    con.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    con.commit()
    con.close()
    return {"removed": note_id}
'''
REMOVE_THEN_ASK = '''

@app.delete("/notes/{note_id}")
def remove_note(note_id: int, user: int = Depends(current_user)):
    con = get_db()
    row = con.execute("SELECT owner FROM notes WHERE id = ?", (note_id,)).fetchone()
    con.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    con.commit()
    con.close()
    if row is None or row[0] != user:
        raise HTTPException(404, "No such note")
    return {"removed": note_id}
'''
assert READ_ANYBODYS != READ and CHANGE_ANYBODYS != CHANGE
ACROSS = ("straight after", "after a restart", "on another worker")
CASES = ["get-notes/nobody", "post-notes/nobody", "get-notes-note-id/bob", "get-notes-note-id/nobody",
         "put-notes-note-id/bob", "put-notes-note-id/nobody", "delete-notes-note-id/bob", "delete-notes-note-id/nobody",
         *(f"limit-post-login/{when}" for when in ACROSS)]
# one changed part -> the cases that must break, each with what the runner must say; every other case holds
WRONG_IN_ONE_PART = {
    "a note is removed for anybody, signed in or not": (
        {"remove": REMOVE_WITH_NO_LOGIN}, {"delete-notes-note-id/bob": ["let-in"], "delete-notes-note-id/nobody": ["let-in"]}),
    "a note is read by anybody who is signed in": (
        {"read": READ_ANYBODYS}, {"get-notes-note-id/bob": ["leaked", "let-in"]}),
    "a note is changed by anybody who is signed in": (
        {"change": CHANGE_ANYBODYS}, {"put-notes-note-id/bob": ["let-in"]}),
    "a note is removed first and its owner asked for afterwards": (
        {"remove": REMOVE_THEN_ASK}, {"delete-notes-note-id/bob": ["refused-but-changed"]}),
    "the notes are listed for a visitor who is not signed in": (
        {"listing": LISTING_FOR_ANYBODY}, {"get-notes/nobody": ["let-in"]}),
    "wrong passwords are not counted": (
        {"login": LOGIN_NO_LIMIT}, {f"limit-post-login/{when}": ["unlimited"] for when in ACROSS}),
    "wrong passwords are counted in the memory of one copy of the app": (
        {"login": LOGIN_COUNTS_IN_MEMORY},
        {"limit-post-login/after a restart": ["forgotten"], "limit-post-login/on another worker": ["forgotten"]}),
}


def _pinboard(**other) -> str:
    parts = {"login": LOGIN, "listing": LISTING, "read": READ, "change": CHANGE, "remove": REMOVE}
    assert set(other) <= set(parts)
    return PIN_HEAD + "".join({**parts, **other}.values())


def _run_as_written(folder: Path, app: str) -> dict:
    """The plan Lantern writes for `app`, run exactly as written: {check/case: (outcome, codes)}."""
    repo = _project(folder, {"pinboard.py": app})
    made = behave_init.write(repo)
    assert made["written"], made["why_not"]
    record = behave.run(repo, log=lambda line: None)
    assert record["ran"], record["why_not"]
    return {f"{o['check']}/{o['case']}": (o["outcome"], sorted(o.get("codes") or [])) for o in record["outcomes"]}


def test_the_plan_for_the_notes_app_holds_one_case_for_each_thing_that_can_go_wrong(tmp_path):
    made = _drafted(tmp_path, {"pinboard.py": _pinboard()})
    plan = made["plan"]
    assert plan["app"] == {"asgi": "pinboard:app", "env": {"PINBOARD_DB": "{data}/app.db"}}
    assert plan["quiet_tables"] == ["login_attempts"]
    assert [c["id"] for c in plan["checks"]] == ["post-notes", "get-notes", "get-notes-note-id", "put-notes-note-id",
                                                 "delete-notes-note-id", "limit-post-login"]
    assert made["cases"] == 16 and made["left_out"] == []
    # every version below gets a case for the part that is wrong in it, although its code shows less
    for said, (other, _breaks) in WRONG_IN_ONE_PART.items():
        twin = _drafted(tmp_path / said.replace(" ", "-"), {"pinboard.py": _pinboard(**other)})
        assert sorted(c["id"] for c in twin["plan"]["checks"]) == sorted(c["id"] for c in plan["checks"]), said


@starts_an_app
def test_the_plan_lantern_wrote_runs_as_it_is_and_every_case_holds_on_the_right_app(tmp_path):
    pytest.importorskip("fastapi")
    assert _run_as_written(tmp_path / "right", _pinboard()) == {case: ("held", []) for case in CASES}


@starts_an_app
@pytest.mark.parametrize("said", list(WRONG_IN_ONE_PART))
def test_with_one_part_wrong_the_case_for_that_part_breaks_and_no_other(tmp_path, said):
    pytest.importorskip("fastapi")
    other, breaks = WRONG_IN_ONE_PART[said]
    got = _run_as_written(tmp_path / "wrong", _pinboard(**other))
    assert got == {case: ("broken", breaks[case]) if case in breaks else ("held", []) for case in CASES}, said


# ------------------------------------------------------------------------------------------- the sample apps
@starts_an_app
@pytest.mark.parametrize("solved", [False, True])
def test_the_starter_notes_app_gets_a_plan_that_runs_as_it_is(tmp_path, solved):
    pytest.importorskip("fastapi")
    pytest.importorskip("python_multipart")     # the starter takes its sign-in as a form, which FastAPI reads with it
    repo = tmp_path / "notes-api"
    learn.scaffold("notes-api", repo, solved=solved)
    made = behave_init.write(repo)
    assert made["written"], made["why_not"]
    assert [c["id"] for c in made["plan"]["checks"]] == ["get-notes", "post-notes", "get-notes-search", "limit-post-login"]
    record = behave.run(repo, log=lambda line: None)
    assert record["ran"], record["why_not"]
    got = {f"{o['check']}/{o['case']}": (o["outcome"], sorted(o.get("codes") or [])) for o in record["outcomes"]}
    # neither the starter nor its solution counts wrong passwords: a true thing about the app, said by the plan
    assert got == {"get-notes/nobody": ("held", []), "post-notes/nobody": ("held", []), "get-notes-search/nobody": ("held", []),
                   **{f"limit-post-login/{when}": ("broken", ["unlimited"]) for when in ACROSS}}


# ------------------------------------------------------------------------------------------- the benchmark app
def _bench():
    spec = importlib.util.spec_from_file_location("behaviour_run", ROOT / "bench" / "behaviour" / "run_behaviour.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_what_is_written_down_for_the_benchmark_app_names_its_planted_problems_and_cases_the_plan_holds(tmp_path):
    bench = _bench()
    assert set(bench.first.CAUGHT) <= set(bench.apps.PLANTED)
    made = bench.write_first(tmp_path, bench.SAFE)
    assert made["written"] and len(made["plan"]["checks"]) == 16 and made["cases"] == 40
    cases = {f"{c['check']}/{c['case']}" for c in behave.scene(behave.load(tmp_path / bench.SAFE))[1] if c["role"] != "control"}
    for planted, breaks in bench.first.CAUGHT.items():
        assert set(breaks) <= cases, planted
    # the plan is written from each version's own code, and a planted problem does not take its case away
    for planted in bench.first.CAUGHT:
        assert [c["id"] for c in bench.write_first(tmp_path, planted)["plan"]["checks"]] == \
            [c["id"] for c in made["plan"]["checks"]], planted
    # what a first plan leaves out of this app, each with the reason, and what it says to look at first
    assert sorted(r["route"] for r in made["left_out"]) == [
        "DELETE /admin/users/{user_id}", "GET /files/{file_id}", "GET /go", "POST /files", "POST /import", "POST /signup",
        "POST /tokens"]
    assert {r["check"] for r in made["review"]} >= {"post-preview", "post-coupons-redeem", "post-transfer",
                                                    "once-post-coupons-redeem", "once-post-transfer", "retry-post-transfer"}


def test_a_run_that_differs_from_what_is_written_down_is_said_case_by_case():
    first = _bench().first
    plan = {"notes": {"review": [{"check": "post-transfer", "why": "a made-up value"}]}}

    def record(**outcomes):
        return {"ran": True, "outcomes": [{"check": k.split("/")[0], "case": k.split("/")[1], "outcome": v[0], "codes": v[1]}
                                          for k, v in outcomes.items()]}
    held = {"get-notes/nobody": ("held", []), "post-transfer/nobody": ("inconclusive", [])}
    assert first.differences(None, record(**held), plan) == []
    assert first.differences("no-login-list", record(**{**held, "get-notes/nobody": ("broken", ["let-in"])}), plan) == []
    # the planted problem is not caught; a case breaks that nobody wrote down; a case is undecided and was not named
    assert first.differences("no-login-list", record(**held), plan) == [
        "get-notes/nobody: written down as broken (let-in), came out held"]
    assert first.differences(None, record(**{**held, "get-notes/nobody": ("broken", ["let-in"])}), plan) == [
        "get-notes/nobody: broken (let-in), which is not written down"]
    assert first.differences(None, record(**{**held, "get-me/nobody": ("inconclusive", [])}), plan) == [
        "get-me/nobody: inconclusive, and the plan did not name its check to look at first"]
    assert first.differences(None, {"ran": False, "why_not": "the app could not be started"}, plan) == [
        "the plan was not run: the app could not be started"]


@starts_an_app
@pytest.mark.parametrize("version", ["safe", "no-login-list", "refused-but-deleted", "limit-in-memory", "double-spend"])
def test_the_plan_lantern_writes_for_the_benchmark_app_shows_what_was_written_down_before_its_first_run(tmp_path, version):
    """Five of the 33 versions (`python bench/behaviour/run_behaviour.py WORKDIR --first-plan` runs them all): the
    safe app, three planted problems a first plan is to catch, and one it is not (two coupons at the same moment)."""
    pytest.importorskip("fastapi")
    pytest.importorskip("jwt")
    bench = _bench()
    row = bench.run_first(tmp_path, version, bench.write_first(tmp_path, version))
    assert row["differences"] == []
    assert bool(row["broken"]) == (version in bench.first.CAUGHT)
    assert row["checks"] == 16 and row["summary"]["held"] >= 14
