"""Throw-away apps for the behaviour tests (directive point 5).

`build(folder, planted)` writes Corkboard, a small notes app for teams (FastAPI + SQLite + sign-in tokens), into
`folder`. With nothing planted it is the safe app. `PLANTED` lists the problems that can be planted, one at a time:
each swaps one or more pieces of the safe source (`PIECES`) for a dangerous piece and changes nothing else, so an
app with one planted problem differs from the safe app in exactly that problem. The apps are written at test time
into a temp folder and thrown away; nothing here is ever served outside the behaviour runner.

    python bench/behaviour/run_behaviour.py FOLDER --only PLANTED-ID      # writes that app into FOLDER, and runs it
"""
from __future__ import annotations

from pathlib import Path

DB_PY = '''"""Corkboard's store: one SQLite file."""
import os
import sqlite3

DB_PATH = os.environ.get("CORKBOARD_DB", os.path.join("data", "corkboard.db"))
DB_WAIT = float(os.environ.get("CORKBOARD_DB_WAIT", "5"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS teams (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, invite TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
                                  role TEXT NOT NULL DEFAULT 'member', team_id INTEGER NOT NULL,
                                  credits INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, team_id INTEGER NOT NULL, owner_id INTEGER NOT NULL,
                                  text TEXT NOT NULL, private INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, team_id INTEGER NOT NULL, owner_id INTEGER NOT NULL,
                                  name TEXT NOT NULL, stored TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS coupons (code TEXT PRIMARY KEY, amount INTEGER NOT NULL, used_by INTEGER);
CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY, from_id INTEGER NOT NULL, to_id INTEGER NOT NULL,
                                      amount INTEGER NOT NULL, key TEXT, UNIQUE (from_id, key));
CREATE TABLE IF NOT EXISTS login_attempts (email TEXT PRIMARY KEY, wrong INTEGER NOT NULL,
                                           locked_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, who TEXT, what TEXT NOT NULL);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=DB_WAIT, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = connect()
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


@@get_db@@
'''

AUTH_PY = '''"""Who is asking: passwords, sign-in tokens, and the checks the routes ask for."""
import hashlib
import hmac
import os
import secrets
import time

import jwt
from fastapi import Depends, Header, HTTPException

from .db import get_db

SECRET = os.environ["CORKBOARD_SECRET"]            # given by whoever runs the app, never written here
TOKEN_MINUTES = int(os.environ.get("CORKBOARD_TOKEN_MINUTES", "30"))
HASH_ROUNDS = int(os.environ.get("CORKBOARD_HASH_ROUNDS", "200000"))
NO_SUCH_USER = "0" * 16 + "$" + "0" * 64            # compared against when the e-mail is unknown


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), HASH_ROUNDS)
    return salt + "$" + digest.hex()


def password_matches(password: str, stored: str) -> bool:
    salt = stored.split("$", 1)[0]
    return hmac.compare_digest(hash_password(password, salt), stored)


def make_token(user_id: int, scope: str = "full") -> str:
    claims = {"sub": str(user_id), "scope": scope, "exp": int(time.time()) + TOKEN_MINUTES * 60}
    return jwt.encode(claims, SECRET, algorithm="HS256")


def read_token(token: str) -> dict:
@@read_token@@


def current_user(authorization: str = Header(default=""), conn=Depends(get_db)) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in first")
    try:
        claims = read_token(authorization[len("Bearer "):])
        user_id = int(claims["sub"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise HTTPException(401, "Sign in again")
    row = conn.execute("SELECT id, email, role, team_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(401, "Sign in again")
    return {"id": row["id"], "email": row["email"], "role": row["role"], "team_id": row["team_id"],
            "scope": claims.get("scope", "full")}


def can_write(user: dict = Depends(current_user)) -> dict:
@@can_write@@
    return user


def team_admin(user: dict = Depends(can_write)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Only a team admin may do this")
    return user
'''

MAIN_PY = '''"""Corkboard: notes for small teams."""
import csv
import io
import mimetypes
import os
import secrets
import shutil
import sqlite3
import time
import urllib.parse
import urllib.request
import zipfile
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from . import db
from .auth import NO_SUCH_USER, can_write, current_user, hash_password, make_token, password_matches, team_admin
from .db import get_db

UPLOADS = os.path.join(os.path.dirname(os.path.abspath(db.DB_PATH)), "uploads")
MAX_BODY = 256 * 1024             # a JSON request
MAX_UPLOAD = 2 * 1024 * 1024      # /files and /import
MAX_UNPACKED = 5 * 1024 * 1024    # what a zip may hold once unpacked
MAX_ENTRIES = 50
MAX_WRONG = 5
LOCK_SECONDS = 15 * 60
SAFE_TYPES = {".txt", ".md", ".csv", ".png", ".jpg", ".pdf"}
PREVIEW_HOSTS = {h.strip() for h in os.environ.get("CORKBOARD_PREVIEW_HOSTS", "example.org").split(",") if h.strip()}


@asynccontextmanager
async def lifespan(_app):
    db.init()
    yield


app = FastAPI(title="Corkboard", lifespan=lifespan)

@@body_limit@@

class NewTeam(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=8, max_length=200)


class SignUp(BaseModel):
    invite: str = Field(max_length=100)
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=8, max_length=200)


class Login(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)


class NoteIn(BaseModel):
    text: @@note_text@@
    private: bool = False


@@profile_model@@


class TokenIn(BaseModel):
    scope: str


class TransferIn(BaseModel):
    to: int
    amount: @@amount@@


class RedeemIn(BaseModel):
    code: str = Field(max_length=40)


class PreviewIn(BaseModel):
    url: str = Field(max_length=2000)


def _note(conn, note_id: int):
    row = conn.execute("SELECT id, team_id, owner_id, text, private FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such note")
    return row


def _may_see(note, user) -> bool:
    if note["team_id"] != user["team_id"]:
        return False
    return not note["private"] or note["owner_id"] == user["id"] or user["role"] == "admin"


def _may_edit(note, user) -> bool:
    return note["team_id"] == user["team_id"] and (note["owner_id"] == user["id"] or user["role"] == "admin")


def _refused(conn, user, what: str) -> None:
    conn.execute("INSERT INTO audit (who, what) VALUES (?, ?)", (user["email"], "refused: " + what))
    conn.commit()


# ------------------------------------------------------------------------------------------------ accounts
@app.post("/teams", status_code=201)
def create_team(body: NewTeam, conn=Depends(get_db)):
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (body.email,)).fetchone():
        raise HTTPException(409, "That e-mail is taken")
    if conn.execute("SELECT 1 FROM teams WHERE name = ?", (body.name,)).fetchone():
        raise HTTPException(409, "That team name is taken")
    invite = secrets.token_urlsafe(12)
    team_id = conn.execute("INSERT INTO teams (name, invite) VALUES (?, ?)", (body.name, invite)).lastrowid
    user_id = conn.execute("INSERT INTO users (email, password, role, team_id) VALUES (?, ?, 'admin', ?)",
                           (body.email, hash_password(body.password), team_id)).lastrowid
    conn.commit()
    return {"team_id": team_id, "user_id": user_id, "invite": invite}


@app.post("/signup", status_code=201)
def sign_up(body: SignUp, conn=Depends(get_db)):
    team = conn.execute("SELECT id FROM teams WHERE invite = ?", (body.invite,)).fetchone()
    if team is None:
        raise HTTPException(404, "No team has that invite")
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (body.email,)).fetchone():
        raise HTTPException(409, "That e-mail is taken")
    user_id = conn.execute("INSERT INTO users (email, password, role, team_id) VALUES (?, ?, 'member', ?)",
                           (body.email, hash_password(body.password), team["id"])).lastrowid
    conn.commit()
    return {"user_id": user_id, "team_id": team["id"]}


@@login@@


@app.post("/tokens")
def new_token(body: TokenIn, user=Depends(can_write)):
    if body.scope not in ("read", "full"):
        raise HTTPException(422, "A token is for 'read' or 'full'")
    return {"token": make_token(user["id"], body.scope)}


@app.get("/me")
def me(user=Depends(current_user), conn=Depends(get_db)):
    credits = conn.execute("SELECT credits FROM users WHERE id = ?", (user["id"],)).fetchone()["credits"]
    return {"id": user["id"], "email": user["email"], "role": user["role"], "team_id": user["team_id"],
            "credits": credits}


@@update_me@@


@@remove_user@@


# ------------------------------------------------------------------------------------------------ notes
@@list_notes@@


@app.post("/notes", status_code=201)
def create_note(body: NoteIn, user=Depends(can_write), conn=Depends(get_db)):
    note_id = conn.execute("INSERT INTO notes (team_id, owner_id, text, private) VALUES (?, ?, ?, ?)",
                           (user["team_id"], user["id"], body.text, int(body.private))).lastrowid
    conn.commit()
    return {"id": note_id}


@@read_note@@


@@change_note@@


@@delete_note@@


@@team_notes@@


@@export@@


# ------------------------------------------------------------------------------------------------ files
@@upload@@


@@download@@


@@import_zip@@


# ------------------------------------------------------------------------------------------------ links
@@go@@


@@preview@@


# ------------------------------------------------------------------------------------------------ credits
@@redeem@@


@@transfer@@
'''

PIECES: dict[str, dict[str, str]] = {}


def piece(slot: str, name: str, text: str) -> None:
    PIECES.setdefault(slot, {})[name] = text.strip("\n")


# ---------------------------------------------------------------------------------------------------- db.py
piece("get_db", "safe", '''
def get_db():
    """One connection for one request; what was not committed is undone when it closes."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
''')
piece("get_db", "shared", '''
_conn = None


def get_db():
    """The app's connection."""
    global _conn
    if _conn is None:
        _conn = connect()
    yield _conn
''')

# ---------------------------------------------------------------------------------------------------- auth.py
piece("read_token", "safe", '''
    return jwt.decode(token, SECRET, algorithms=["HS256"], options={"require": ["exp", "sub"]})
''')
piece("read_token", "no-expiry", '''
    return jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})
''')
piece("read_token", "no-signature", '''
    return jwt.decode(token, options={"verify_signature": False})
''')
piece("can_write", "safe", '''
    if user["scope"] != "full":
        raise HTTPException(403, "This token may only read")
''')
piece("can_write", "no-scope", "")

# ---------------------------------------------------------------------------------------------------- main.py
piece("body_limit", "safe", '''

class BodyLimit:
    """Refuses a request body that is too large, before the app reads it."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = MAX_UPLOAD if scope["path"] in ("/files", "/import") else MAX_BODY
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            await JSONResponse({"detail": "That is too large"}, status_code=413)(scope, receive, send)
            return
        seen = 0

        async def counted():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise HTTPException(413, "That is too large")
            return message
        await self.app(scope, counted, send)


app.add_middleware(BodyLimit)

''')
piece("body_limit", "none", "")
piece("note_text", "safe", "str = Field(min_length=1, max_length=10000)")
piece("note_text", "any-length", "str")
piece("amount", "safe", "int = Field(gt=0, le=1000000)")
piece("amount", "any-number", "int")
piece("profile_model", "safe", '''
class ProfileIn(BaseModel):
    email: str = Field(min_length=3, max_length=200)
''')
piece("profile_model", "with-role", '''
class ProfileIn(BaseModel):
    email: str | None = Field(default=None, min_length=3, max_length=200)
    role: str | None = None
''')

piece("login", "safe", '''
@app.post("/login")
def login(body: Login, conn=Depends(get_db)):
    now = time.time()
    seen = conn.execute("SELECT wrong, locked_until FROM login_attempts WHERE email = ?", (body.email,)).fetchone()
    if seen is not None and seen["locked_until"] > now:
        raise HTTPException(429, "Too many wrong passwords. Try again later")
    user = conn.execute("SELECT id, password FROM users WHERE email = ?", (body.email,)).fetchone()
    if not password_matches(body.password, user["password"] if user else NO_SUCH_USER) or user is None:
        wrong = (seen["wrong"] if seen is not None else 0) + 1
        conn.execute("INSERT INTO login_attempts (email, wrong, locked_until) VALUES (?, ?, ?) "
                     "ON CONFLICT (email) DO UPDATE SET wrong = excluded.wrong, locked_until = excluded.locked_until",
                     (body.email, wrong, now + LOCK_SECONDS if wrong >= MAX_WRONG else 0))
        conn.commit()
        raise HTTPException(401, "Wrong e-mail or password")
    conn.execute("DELETE FROM login_attempts WHERE email = ?", (body.email,))
    conn.commit()
    return {"token": make_token(user["id"])}
''')
piece("login", "no-limit", '''
@app.post("/login")
def login(body: Login, conn=Depends(get_db)):
    user = conn.execute("SELECT id, password FROM users WHERE email = ?", (body.email,)).fetchone()
    if not password_matches(body.password, user["password"] if user else NO_SUCH_USER) or user is None:
        raise HTTPException(401, "Wrong e-mail or password")
    return {"token": make_token(user["id"])}
''')
piece("login", "in-memory", '''
_wrong_passwords: dict[str, tuple[int, float]] = {}


@app.post("/login")
def login(body: Login, conn=Depends(get_db)):
    now = time.time()
    wrong, locked_until = _wrong_passwords.get(body.email, (0, 0.0))
    if locked_until > now:
        raise HTTPException(429, "Too many wrong passwords. Try again later")
    user = conn.execute("SELECT id, password FROM users WHERE email = ?", (body.email,)).fetchone()
    if not password_matches(body.password, user["password"] if user else NO_SUCH_USER) or user is None:
        wrong += 1
        _wrong_passwords[body.email] = (wrong, now + LOCK_SECONDS if wrong >= MAX_WRONG else 0.0)
        raise HTTPException(401, "Wrong e-mail or password")
    _wrong_passwords.pop(body.email, None)
    return {"token": make_token(user["id"])}
''')

piece("update_me", "safe", '''
@app.patch("/me")
def update_me(body: ProfileIn, user=Depends(can_write), conn=Depends(get_db)):
    taken = conn.execute("SELECT 1 FROM users WHERE email = ? AND id != ?", (body.email, user["id"])).fetchone()
    if taken:
        raise HTTPException(409, "That e-mail is taken")
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (body.email, user["id"]))
    conn.commit()
    return {"email": body.email}
''')
piece("update_me", "with-role", '''
@app.patch("/me")
def update_me(body: ProfileIn, user=Depends(can_write), conn=Depends(get_db)):
    if body.email is not None:
        taken = conn.execute("SELECT 1 FROM users WHERE email = ? AND id != ?", (body.email, user["id"])).fetchone()
        if taken:
            raise HTTPException(409, "That e-mail is taken")
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (body.email, user["id"]))
    if body.role is not None:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, user["id"]))
    conn.commit()
    return {"email": body.email, "role": body.role}
''')

piece("remove_user", "safe", '''
@app.delete("/admin/users/{user_id}", status_code=204)
def remove_user(user_id: int, admin=Depends(team_admin), conn=Depends(get_db)):
    target = conn.execute("SELECT id, team_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None or target["team_id"] != admin["team_id"]:
        raise HTTPException(404, "No such user")
    if target["id"] == admin["id"]:
        raise HTTPException(409, "An admin cannot remove themself")
    conn.execute("DELETE FROM notes WHERE owner_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return Response(status_code=204)
''')
piece("remove_user", "any-member", '''
@app.delete("/admin/users/{user_id}", status_code=204)
def remove_user(user_id: int, admin=Depends(can_write), conn=Depends(get_db)):
    target = conn.execute("SELECT id, team_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None or target["team_id"] != admin["team_id"]:
        raise HTTPException(404, "No such user")
    if target["id"] == admin["id"]:
        raise HTTPException(409, "An admin cannot remove themself")
    conn.execute("DELETE FROM notes WHERE owner_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return Response(status_code=204)
''')
piece("remove_user", "any-team", '''
@app.delete("/admin/users/{user_id}", status_code=204)
def remove_user(user_id: int, admin=Depends(team_admin), conn=Depends(get_db)):
    target = conn.execute("SELECT id, team_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        raise HTTPException(404, "No such user")
    if target["id"] == admin["id"]:
        raise HTTPException(409, "An admin cannot remove themself")
    conn.execute("DELETE FROM notes WHERE owner_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return Response(status_code=204)
''')

piece("list_notes", "safe", '''
@app.get("/notes")
def list_notes(user=Depends(current_user), conn=Depends(get_db)):
    rows = conn.execute("SELECT id, team_id, owner_id, text, private FROM notes WHERE team_id = ? ORDER BY id",
                        (user["team_id"],)).fetchall()
    return [dict(r) for r in rows if _may_see(r, user)]
''')
piece("list_notes", "no-login", '''
@app.get("/notes")
def list_notes(conn=Depends(get_db)):
    rows = conn.execute("SELECT id, team_id, owner_id, text, private FROM notes ORDER BY id").fetchall()
    return [dict(r) for r in rows]
''')

piece("read_note", "safe", '''
@app.get("/notes/{note_id}")
def read_note(note_id: int, user=Depends(current_user), conn=Depends(get_db)):
    note = _note(conn, note_id)
    if not _may_see(note, user):
        raise HTTPException(404, "No such note")
    return dict(note)
''')
piece("read_note", "private-unchecked", '''
@app.get("/notes/{note_id}")
def read_note(note_id: int, user=Depends(current_user), conn=Depends(get_db)):
    note = _note(conn, note_id)
    if note["team_id"] != user["team_id"]:
        raise HTTPException(404, "No such note")
    return dict(note)
''')
piece("read_note", "team-unchecked", '''
@app.get("/notes/{note_id}")
def read_note(note_id: int, user=Depends(current_user), conn=Depends(get_db)):
    note = _note(conn, note_id)
    if note["private"] and note["owner_id"] != user["id"]:
        raise HTTPException(404, "No such note")
    return dict(note)
''')

piece("change_note", "safe", '''
@app.put("/notes/{note_id}")
def change_note(note_id: int, body: NoteIn, user=Depends(can_write), conn=Depends(get_db)):
    note = _note(conn, note_id)
    if note["team_id"] != user["team_id"]:
        raise HTTPException(404, "No such note")
    if not _may_edit(note, user):
        _refused(conn, user, f"change note {note_id}")
        raise HTTPException(403, "Only the note's owner or a team admin may change it")
    conn.execute("UPDATE notes SET text = ?, private = ? WHERE id = ?", (body.text, int(body.private), note_id))
    conn.commit()
    return {"id": note_id}
''')
piece("change_note", "unchecked", '''
@app.put("/notes/{note_id}")
def change_note(note_id: int, body: NoteIn, user=Depends(can_write), conn=Depends(get_db)):
    _note(conn, note_id)
    conn.execute("UPDATE notes SET text = ?, private = ? WHERE id = ?", (body.text, int(body.private), note_id))
    conn.commit()
    return {"id": note_id}
''')

piece("delete_note", "safe", '''
@app.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: int, user=Depends(can_write), conn=Depends(get_db)):
    note = _note(conn, note_id)
    if note["team_id"] != user["team_id"]:
        raise HTTPException(404, "No such note")
    if not _may_edit(note, user):
        _refused(conn, user, f"delete note {note_id}")
        raise HTTPException(403, "Only the note's owner or a team admin may delete it")
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    return Response(status_code=204)
''')
piece("delete_note", "unchecked", '''
@app.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: int, user=Depends(can_write), conn=Depends(get_db)):
    _note(conn, note_id)
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    return Response(status_code=204)
''')
piece("delete_note", "checked-too-late", '''
@app.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: int, user=Depends(can_write), conn=Depends(get_db)):
    note = _note(conn, note_id)
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    if note["team_id"] != user["team_id"]:
        raise HTTPException(404, "No such note")
    if not _may_edit(note, user):
        raise HTTPException(403, "Only the note's owner or a team admin may delete it")
    return Response(status_code=204)
''')

piece("team_notes", "safe", '''
@app.get("/teams/{team_id}/notes")
def team_notes(team_id: int, user=Depends(current_user), conn=Depends(get_db)):
    if team_id != user["team_id"]:
        raise HTTPException(404, "No such team")
    rows = conn.execute("SELECT id, team_id, owner_id, text, private FROM notes WHERE team_id = ? ORDER BY id",
                        (team_id,)).fetchall()
    return [dict(r) for r in rows if _may_see(r, user)]
''')
piece("team_notes", "any-team", '''
@app.get("/teams/{team_id}/notes")
def team_notes(team_id: int, user=Depends(current_user), conn=Depends(get_db)):
    rows = conn.execute("SELECT id, team_id, owner_id, text, private FROM notes WHERE team_id = ? AND private = 0 "
                        "ORDER BY id", (team_id,)).fetchall()
    return [dict(r) for r in rows]
''')

piece("export", "safe", '''
def _cell(text: str) -> str:
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text     # a spreadsheet must not run it


@app.get("/export")
def export(user=Depends(current_user), conn=Depends(get_db)):
    rows = conn.execute("SELECT id, team_id, owner_id, text, private FROM notes WHERE team_id = ? ORDER BY id",
                        (user["team_id"],)).fetchall()
    out = io.StringIO()
    sheet = csv.writer(out)
    sheet.writerow(["id", "owner", "text"])
    for r in rows:
        if _may_see(r, user):
            sheet.writerow([r["id"], r["owner_id"], _cell(r["text"])])
    return PlainTextResponse(out.getvalue(), media_type="text/csv")
''')
piece("export", "every-team", '''
def _cell(text: str) -> str:
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text     # a spreadsheet must not run it


@app.get("/export")
def export(user=Depends(current_user), conn=Depends(get_db)):
    rows = conn.execute("SELECT id, team_id, owner_id, text, private FROM notes WHERE private = 0 ORDER BY id").fetchall()
    out = io.StringIO()
    sheet = csv.writer(out)
    sheet.writerow(["id", "owner", "text"])
    for r in rows:
        sheet.writerow([r["id"], r["owner_id"], _cell(r["text"])])
    return PlainTextResponse(out.getvalue(), media_type="text/csv")
''')

piece("upload", "safe", '''
@app.post("/files", status_code=201)
async def upload(request: Request, name: str, user=Depends(can_write), conn=Depends(get_db)):
    kind = os.path.splitext(name)[1].lower()
    if kind not in SAFE_TYPES:
        raise HTTPException(415, "That kind of file is not accepted")
    data = await request.body()
    stored = secrets.token_hex(12) + kind
    os.makedirs(UPLOADS, exist_ok=True)
    with open(os.path.join(UPLOADS, stored), "wb") as f:
        f.write(data)
    file_id = conn.execute("INSERT INTO files (team_id, owner_id, name, stored) VALUES (?, ?, ?, ?)",
                           (user["team_id"], user["id"], name[:200], stored)).lastrowid
    conn.commit()
    return {"id": file_id}
''')
piece("upload", "own-name", '''
@app.post("/files", status_code=201)
async def upload(request: Request, name: str, user=Depends(can_write), conn=Depends(get_db)):
    kind = os.path.splitext(name)[1].lower()
    if kind not in SAFE_TYPES:
        raise HTTPException(415, "That kind of file is not accepted")
    data = await request.body()
    os.makedirs(UPLOADS, exist_ok=True)
    with open(os.path.join(UPLOADS, name), "wb") as f:
        f.write(data)
    file_id = conn.execute("INSERT INTO files (team_id, owner_id, name, stored) VALUES (?, ?, ?, ?)",
                           (user["team_id"], user["id"], name[:200], name)).lastrowid
    conn.commit()
    return {"id": file_id}
''')
piece("upload", "any-kind", '''
@app.post("/files", status_code=201)
async def upload(request: Request, name: str, user=Depends(can_write), conn=Depends(get_db)):
    kind = os.path.splitext(name)[1].lower()
    data = await request.body()
    stored = secrets.token_hex(12) + kind
    os.makedirs(UPLOADS, exist_ok=True)
    with open(os.path.join(UPLOADS, stored), "wb") as f:
        f.write(data)
    file_id = conn.execute("INSERT INTO files (team_id, owner_id, name, stored) VALUES (?, ?, ?, ?)",
                           (user["team_id"], user["id"], name[:200], stored)).lastrowid
    conn.commit()
    return {"id": file_id}
''')

piece("download", "safe", '''
@app.get("/files/{file_id}")
def download(file_id: int, user=Depends(current_user), conn=Depends(get_db)):
    row = conn.execute("SELECT team_id, name, stored FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None or row["team_id"] != user["team_id"]:
        raise HTTPException(404, "No such file")
    with open(os.path.join(UPLOADS, row["stored"]), "rb") as f:
        data = f.read()
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": "attachment", "X-Content-Type-Options": "nosniff"})
''')
piece("download", "as-its-kind", '''
@app.get("/files/{file_id}")
def download(file_id: int, user=Depends(current_user), conn=Depends(get_db)):
    row = conn.execute("SELECT team_id, name, stored FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None or row["team_id"] != user["team_id"]:
        raise HTTPException(404, "No such file")
    with open(os.path.join(UPLOADS, row["stored"]), "rb") as f:
        data = f.read()
    return Response(data, media_type=mimetypes.guess_type(row["name"])[0] or "application/octet-stream")
''')

_IMPORT_HEAD = '''
@app.post("/import", status_code=201)
async def import_zip(request: Request, user=Depends(can_write)):
    data = await request.body()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(400, "That is not a zip file")
    entries = [e for e in archive.infolist() if not e.is_dir()]
'''
piece("import_zip", "safe", _IMPORT_HEAD + '''
    if len(entries) > MAX_ENTRIES or sum(e.file_size for e in entries) > MAX_UNPACKED:
        raise HTTPException(413, "The zip holds too much")
    folder = os.path.join(UPLOADS, "import-" + secrets.token_hex(6))
    inside = os.path.realpath(folder) + os.sep
    targets = [os.path.realpath(os.path.join(folder, e.filename)) for e in entries]
    if any(not t.startswith(inside) for t in targets):
        raise HTTPException(400, "The zip holds a name that leaves its folder")
    unpacked = 0
    for entry, target in zip(entries, targets):
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with archive.open(entry) as src, open(target, "wb") as dst:
            while chunk := src.read(65536):
                unpacked += len(chunk)
                if unpacked > MAX_UNPACKED:          # the sizes the zip declared were not true
                    dst.close()
                    shutil.rmtree(folder)
                    raise HTTPException(413, "The zip holds too much")
                dst.write(chunk)
    return {"files": len(entries)}
''')
piece("import_zip", "names-unchecked", _IMPORT_HEAD + '''
    if len(entries) > MAX_ENTRIES or sum(e.file_size for e in entries) > MAX_UNPACKED:
        raise HTTPException(413, "The zip holds too much")
    folder = os.path.join(UPLOADS, "import-" + secrets.token_hex(6))
    unpacked = 0
    for entry in entries:
        target = os.path.join(folder, entry.filename)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with archive.open(entry) as src, open(target, "wb") as dst:
            while chunk := src.read(65536):
                unpacked += len(chunk)
                if unpacked > MAX_UNPACKED:          # the sizes the zip declared were not true
                    dst.close()
                    shutil.rmtree(folder)
                    raise HTTPException(413, "The zip holds too much")
                dst.write(chunk)
    return {"files": len(entries)}
''')
piece("import_zip", "sizes-unchecked", _IMPORT_HEAD + '''
    folder = os.path.join(UPLOADS, "import-" + secrets.token_hex(6))
    inside = os.path.realpath(folder) + os.sep
    targets = [os.path.realpath(os.path.join(folder, e.filename)) for e in entries]
    if any(not t.startswith(inside) for t in targets):
        raise HTTPException(400, "The zip holds a name that leaves its folder")
    for entry, target in zip(entries, targets):
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with archive.open(entry) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return {"files": len(entries)}
''')

piece("go", "safe", '''
@app.get("/go")
def go(next: str = "/"):
    """After signing in, back to the page the person came from: a page of this site only."""
    if not next.startswith("/") or next.startswith("//") or "\\\\" in next or any(ord(c) < 32 for c in next):
        next = "/"
    return RedirectResponse(next, status_code=303)
''')
piece("go", "anywhere", '''
@app.get("/go")
def go(next: str = "/"):
    """After signing in, back to the page the person came from."""
    return RedirectResponse(next, status_code=303)
''')
piece("go", "slash-only", '''
@app.get("/go")
def go(next: str = "/"):
    """After signing in, back to the page the person came from: a page of this site only."""
    if not next.startswith("/"):
        next = "/"
    return RedirectResponse(next, status_code=303)
''')

_PREVIEW_TAIL = '''
    try:
        with _no_redirects.open(body.url, timeout=3) as page:
            text = page.read(20000).decode("utf-8", "replace")
    except (OSError, ValueError):
        raise HTTPException(502, "The page could not be read")
    start, end = text.find("<title>"), text.find("</title>")
    return {"title": text[start + 7:end].strip()[:200] if 0 <= start < end else ""}
'''
_PREVIEW_HEAD = '''
class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_no_redirects = urllib.request.build_opener(_NoRedirects)


@app.post("/preview")
def preview(body: PreviewIn, user=Depends(current_user)):
    """The title of a linked page, shown beside the link."""
'''
piece("preview", "safe", _PREVIEW_HEAD + '''
    link = urllib.parse.urlsplit(body.url)
    try:
        known = link.scheme == "https" and link.hostname in PREVIEW_HOSTS and link.port in (None, 443)
    except ValueError:
        known = False
    if not known or link.username is not None:
        raise HTTPException(400, "Only pages of known sites can be previewed")
''' + _PREVIEW_TAIL)
piece("preview", "any-address", _PREVIEW_HEAD + _PREVIEW_TAIL)
piece("preview", "by-words", _PREVIEW_HEAD + '''
    if "localhost" in body.url or "127.0.0.1" in body.url:
        raise HTTPException(400, "That address cannot be previewed")
''' + _PREVIEW_TAIL)

piece("redeem", "safe", '''
@app.post("/coupons/redeem")
def redeem(body: RedeemIn, user=Depends(can_write), conn=Depends(get_db)):
    took = conn.execute("UPDATE coupons SET used_by = ? WHERE code = ? AND used_by IS NULL", (user["id"], body.code))
    if took.rowcount != 1:
        conn.rollback()
        raise HTTPException(409, "That coupon is not valid, or was used already")
    amount = conn.execute("SELECT amount FROM coupons WHERE code = ?", (body.code,)).fetchone()["amount"]
    conn.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (amount, user["id"]))
    conn.commit()
    return {"credits_added": amount}
''')
piece("redeem", "look-then-take", '''
@app.post("/coupons/redeem")
def redeem(body: RedeemIn, user=Depends(can_write), conn=Depends(get_db)):
    coupon = conn.execute("SELECT amount, used_by FROM coupons WHERE code = ?", (body.code,)).fetchone()
    if coupon is None or coupon["used_by"] is not None:
        raise HTTPException(409, "That coupon is not valid, or was used already")
    conn.execute("UPDATE coupons SET used_by = ? WHERE code = ?", (user["id"], body.code))
    conn.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (coupon["amount"], user["id"]))
    conn.commit()
    return {"credits_added": coupon["amount"]}
''')

_TRANSFER_HEAD = '''
@app.post("/transfer")
def transfer(body: TransferIn, idempotency_key: str = Header(default="", max_length=100), user=Depends(can_write),
             conn=Depends(get_db)):
    """Give credits to a teammate. A request sent again with the same Idempotency-Key is answered, not repeated."""
'''
_TRANSFER_KEY = '''
    if idempotency_key:
        earlier = conn.execute("SELECT id FROM transfers WHERE from_id = ? AND key = ?",
                               (user["id"], idempotency_key)).fetchone()
        if earlier is not None:
            return {"transfer_id": earlier["id"], "repeated": True}
'''
_TRANSFER_TARGET = '''
    target = conn.execute("SELECT id, team_id FROM users WHERE id = ?", (body.to,)).fetchone()
    if target is None or target["team_id"] != user["team_id"] or target["id"] == user["id"]:
        raise HTTPException(404, "No such teammate")
'''
_DEBIT = ('"UPDATE users SET credits = credits - ? WHERE id = ? AND credits >= ?",\n'
          '                        (body.amount, user["id"], body.amount)')
_CREDIT = '"UPDATE users SET credits = credits + ? WHERE id = ?", (body.amount, body.to)'
_RECORD = ('"INSERT INTO transfers (from_id, to_id, amount, key) VALUES (?, ?, ?, ?)",\n'
           '                                   (user["id"], body.to, body.amount, idempotency_key or None)')
piece("transfer", "safe", _TRANSFER_HEAD + _TRANSFER_KEY + _TRANSFER_TARGET + f'''
    took = conn.execute({_DEBIT})
    if took.rowcount != 1:
        conn.rollback()
        raise HTTPException(409, "Not enough credits")
    conn.execute({_CREDIT})
    try:
        transfer_id = conn.execute({_RECORD}).lastrowid
    except sqlite3.IntegrityError:                 # the same key, at the same moment: the other one counts
        conn.rollback()
        raise HTTPException(409, "That transfer is already being made")
    conn.commit()
    return {{"transfer_id": transfer_id}}
''')
piece("transfer", "saved-step-by-step", _TRANSFER_HEAD + _TRANSFER_KEY + _TRANSFER_TARGET + f'''
    took = conn.execute({_DEBIT})
    conn.commit()
    if took.rowcount != 1:
        raise HTTPException(409, "Not enough credits")
    conn.execute({_CREDIT})
    conn.commit()
    transfer_id = conn.execute({_RECORD}).lastrowid
    conn.commit()
    return {{"transfer_id": transfer_id}}
''')
piece("transfer", "given-back-by-hand", _TRANSFER_HEAD + _TRANSFER_KEY + _TRANSFER_TARGET + f'''
    took = conn.execute({_DEBIT})
    conn.commit()
    if took.rowcount != 1:
        raise HTTPException(409, "Not enough credits")
    try:
        conn.execute({_CREDIT})
        transfer_id = conn.execute({_RECORD}).lastrowid
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        conn.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (body.amount, user["id"]))
        conn.commit()
        raise HTTPException(503, "The transfer could not be made. Nothing was taken")
    return {{"transfer_id": transfer_id}}
''')
piece("transfer", "key-ignored", _TRANSFER_HEAD + _TRANSFER_TARGET + f'''
    took = conn.execute({_DEBIT})
    if took.rowcount != 1:
        conn.rollback()
        raise HTTPException(409, "Not enough credits")
    conn.execute({_CREDIT})
    transfer_id = conn.execute("INSERT INTO transfers (from_id, to_id, amount) VALUES (?, ?, ?)",
                               (user["id"], body.to, body.amount)).lastrowid
    conn.commit()
    return {{"transfer_id": transfer_id}}
''')

# ---------------------------------------------------------------------------------------------------- planted
# id -> (kind, what is wrong in plain words, {slot: piece})
PLANTED: dict[str, tuple[str, str, dict[str, str]]] = {
    "no-login-list": ("no-login", "Anyone can list every note without signing in", {"list_notes": "no-login"}),
    "private-note-read": ("other-user", "A teammate can read another person's private note",
                          {"read_note": "private-unchecked"}),
    "other-team-read": ("other-tenant", "A member of another team can read a team's note", {"read_note": "team-unchecked"}),
    "other-user-change": ("other-user", "Any signed-in person can change another person's note",
                          {"change_note": "unchecked"}),
    "other-user-delete": ("other-user", "Any signed-in person can delete another person's note",
                          {"delete_note": "unchecked"}),
    "refused-but-deleted": ("refused-but-changed", "The delete is refused, but the note is already gone",
                            {"delete_note": "checked-too-late"}),
    "other-team-list": ("other-tenant", "The notes of any team can be listed by the team's number",
                        {"team_notes": "any-team"}),
    "export-every-team": ("other-tenant", "The export holds every team's notes", {"export": "every-team"}),
    "member-removes-user": ("privilege", "A regular member can remove a user", {"remove_user": "any-member"}),
    "other-team-admin": ("other-tenant", "An admin of another team can remove a user", {"remove_user": "any-team"}),
    "expired-token": ("credential", "A sign-in that has run out still works", {"read_token": "no-expiry"}),
    "unsigned-token": ("credential", "A sign-in token that was altered or made up still works",
                       {"read_token": "no-signature"}),
    "scope-unchecked": ("credential", "A token meant for reading only can change things", {"can_write": "no-scope"}),
    "role-in-profile": ("invalid-input", "A member can make themself admin through the profile form",
                        {"profile_model": "with-role", "update_me": "with-role"}),
    "negative-transfer": ("invalid-input", "A negative amount moves credits the wrong way", {"amount": "any-number"}),
    "no-size-limit": ("oversize", "A request of several megabytes is accepted and stored",
                      {"body_limit": "none", "note_text": "any-length"}),
    "upload-name-escapes": ("upload", "An upload's name can leave the uploads folder", {"upload": "own-name"}),
    "upload-served-as-page": ("upload", "An uploaded web page is accepted and served back as a page",
                              {"upload": "any-kind", "download": "as-its-kind"}),
    "zip-entry-escapes": ("archive", "A name inside a zip can leave the folder it is unpacked into",
                          {"import_zip": "names-unchecked"}),
    "zip-bomb": ("archive", "A small zip that unpacks to many megabytes is unpacked in full",
                 {"import_zip": "sizes-unchecked"}),
    "open-redirect": ("redirect", "The redirect goes to any address it is given", {"go": "anywhere"}),
    "redirect-half-checked": ("redirect", "The redirect's check lets //another-site through", {"go": "slash-only"}),
    "fetch-any-address": ("internal-address", "The link preview fetches any address, internal ones too",
                          {"preview": "any-address"}),
    "fetch-half-checked": ("internal-address", "The preview's check misses other spellings of internal addresses",
                           {"preview": "by-words"}),
    "no-login-limit": ("login-limit", "Wrong passwords can be tried without end", {"login": "no-limit"}),
    "limit-in-memory": ("login-limit", "The count of wrong passwords is forgotten at a restart and not shared "
                        "between workers", {"login": "in-memory"}),
    "double-spend": ("concurrency", "A coupon can be redeemed twice at the same moment", {"redeem": "look-then-take"}),
    "no-undo": ("db-error", "A transfer that fails half-way keeps the half that was done",
                {"transfer": "saved-step-by-step"}),
    "undo-by-hand": ("interrupted", "A transfer that is cut off half-way keeps the half that was done",
                     {"transfer": "given-back-by-hand"}),
    "retry-repeats": ("retry", "The same transfer sent again moves the credits again", {"transfer": "key-ignored"}),
    "shared-connection": ("recovery", "The half of a failed transfer is saved by the next person's request",
                          {"get_db": "shared"}),
}

FILES = {"corkboard/__init__.py": "", "corkboard/db.py": DB_PY, "corkboard/auth.py": AUTH_PY, "corkboard/main.py": MAIN_PY,
         "requirements.txt": "fastapi\nPyJWT\n"}


def source(planted: str | None = None) -> dict[str, str]:
    """The app's files as text: the safe app, or the one with `planted` in it."""
    chosen = {slot: "safe" for slot in PIECES}
    if planted is not None:
        chosen.update(PLANTED[planted][2])
    out = {}
    for name, text in FILES.items():
        for slot, which in chosen.items():
            text = text.replace(f"@@{slot}@@", PIECES[slot][which])
        if "@@" in text:
            raise ValueError(f"{name}: a piece is missing")
        out[name] = text
    return out


def build(folder, planted: str | None = None) -> Path:
    """Write the app into `folder` (made if needed) and return it."""
    folder = Path(folder)
    for name, text in source(planted).items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return folder
