"""Who may reach what (directive point 4, 2026-11-11): a signed-in person reading or changing a record by its id with
nothing that compares the record's owner with who is asking; an admin route that only asks whether someone is signed
in; everything the request sent written onto a record.

These read what the code does with the value that says who is signed in, never a name: a function called
`check_owner` that compares nothing is no check, and one called `load` that compares the owner is. Every finding here is
a heuristic (`tool_confidence: LOW`). None of these files is copied from an app of the held-out benchmark; they were
written before the rules were."""

import pytest

from lantern.engine import build_graph

PROJECT = {"pyproject.toml": '[project]\nname="a"\nversion="0"\ndependencies=["fastapi"]\n', "app/__init__.py": ""}
FASTAPI = ("import logging\nimport sqlite3\n\nfrom fastapi import Depends, FastAPI, Header, HTTPException\n\n"
           "app = FastAPI()\nlog = logging.getLogger(__name__)\n\n\n"
           "def get_db():\n    conn = sqlite3.connect('app.db')\n    conn.row_factory = sqlite3.Row\n    try:\n"
           "        yield conn\n    finally:\n        conn.close()\n\n\n"
           "def get_current_user(authorization: str = Header(...), db=Depends(get_db)):\n"
           "    row = db.execute('SELECT id, is_admin FROM users WHERE token = ?', (authorization,)).fetchone()\n"
           "    if row is None:\n        raise HTTPException(401)\n    return row\n\n\n")
ONE = "SELECT * FROM orders WHERE id = ?"
MINE = "SELECT * FROM orders WHERE id = ? AND user_id = ?"


def _scan(root, files, project=None):
    from lantern.security import scan
    for rel, text in {**(PROJECT if project is None else project), **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    sec = scan(build_graph(root), offline=True)
    flow = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert flow["state"] == "ok", flow
    return [f for f in sec["findings"] if not f["in_tests"]]


def _authz(fs):
    return sorted(f["rule"] for f in fs if f["rule"].startswith("LT-AUTHZ"))


def _route(body, sig="order_id: int, user=Depends(get_current_user), db=Depends(get_db)", verb="get",
           path="/orders/{order_id}"):
    return f"@app.{verb}('{path}')\ndef handle({sig}):\n{body}"


# ------------------------------------------------------------- another person's record, Python

OWNER = {
    "caught: the order is read by its id, and who is asking is never looked at":
        (_route(f"    return db.execute('{ONE}', (order_id,)).fetchone()\n"), ["LT-AUTHZ-OWNER"]),
    "caught: the same for a delete":
        (_route("    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {'ok': True}\n",
                verb="delete"), ["LT-AUTHZ-OWNER"]),
    "clean: the query asks for the caller's own order":
        (_route(f"    return db.execute('{MINE}', (order_id, user['id'])).fetchone()\n"), []),
    "clean: the owner is compared after the order is read":
        (_route(f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n"
                "    if row is None or row['user_id'] != user['id']:\n        raise HTTPException(404)\n"
                "    return row\n"), []),
    "caught: a helper named check_owner that compares nothing":
        ("def check_owner(user, order_id):\n    return True\n\n\n" +
         _route(f"    check_owner(user, order_id)\n    return db.execute('{ONE}', (order_id,)).fetchone()\n"),
         ["LT-AUTHZ-OWNER"]),
    "clean: a helper with a plain name that compares the owner":
        ("def load(db, user, order_id):\n"
         f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n"
         "    if row is None or row['user_id'] != user['id']:\n        raise HTTPException(404)\n    return row\n\n\n" +
         _route("    return load(db, user, order_id)\n"), []),
    "caught: who is asking is only written to the log":
        (_route("    log.info('order %s read by %s', order_id, user['id'])\n"
                f"    return db.execute('{ONE}', (order_id,)).fetchone()\n"), ["LT-AUTHZ-OWNER"]),
    "caught: the caller only has to exist":
        (_route(f"    if not user:\n        raise HTTPException(401)\n"
                f"    return db.execute('{ONE}', (order_id,)).fetchone()\n"), ["LT-AUTHZ-OWNER"]),
    "clean: nobody is signed in at all, which is another finding's business":
        (_route(f"    return db.execute('{ONE}', (order_id,)).fetchone()\n", sig="order_id: int, db=Depends(get_db)"),
         []),
    "clean: the route is for admins and asks for one":
        (_route("    if not user['is_admin']:\n        raise HTTPException(403)\n"
                f"    return db.execute('{ONE}', (order_id,)).fetchone()\n"), []),
    "caught: the query is in a service function that is not told who is asking":
        (f"def load_order(db, oid):\n    return db.execute('{ONE}', (oid,)).fetchone()\n\n\n" +
         _route("    return load_order(db, order_id)\n"), ["LT-AUTHZ-OWNER"]),
    "clean: the service function is told who is asking and puts it in the query":
        (f"def load_order(db, oid, uid):\n    return db.execute('{MINE}', (oid, uid)).fetchone()\n\n\n" +
         _route("    return load_order(db, order_id, user['id'])\n"), []),
    "clean: a search word chooses no one's record":
        (_route("    return db.execute('SELECT * FROM products WHERE name LIKE ?', (q,)).fetchall()\n",
                sig="q: str, user=Depends(get_current_user), db=Depends(get_db)", path="/products"), []),
    "clean: the caller's own orders, chosen by who is signed in":
        (_route("    return db.execute('SELECT * FROM orders WHERE user_id = ?', (user['id'],)).fetchall()\n",
                sig="user=Depends(get_current_user), db=Depends(get_db)", path="/orders"), []),
    "clean: a new order is nobody else's record":
        (_route("    db.execute('INSERT INTO orders (item_id, user_id) VALUES (?, ?)', (item_id, user['id']))\n"
                "    return {'ok': True}\n", sig="item_id: int, user=Depends(get_current_user), db=Depends(get_db)",
                verb="post", path="/orders"), []),
}


@pytest.mark.parametrize("case", sorted(OWNER))
def test_a_record_reached_by_its_id_needs_its_owner_compared(tmp_path, case):
    body, want = OWNER[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_the_finding_says_where_the_record_is_reached_and_that_it_is_a_heuristic(tmp_path):
    body, _ = OWNER["caught: the query is in a service function that is not told who is asking"]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    f = next(x for x in fs if x["rule"] == "LT-AUTHZ-OWNER")
    assert f["tool"] == "lantern-flow" and f["tool_confidence"] == "LOW" and f["rank"] == "medium", f
    assert f["file"] == "app/main.py" and "GET /orders/{order_id}" in f["title"], f
    steps = f["flow"]["steps"]
    assert steps[0]["what"].startswith("`order_id` arrives with the request") and "load_order" in steps[1]["what"]
    assert f["flow"]["sink"]["line"] == 27 and f["flow"]["class"] == "record", f["flow"]      # the query's own line


ORM = ("from sqlalchemy.orm import Session\n\nfrom .models import Order\n\n\n")
ORM_CASES = {
    "caught: an ORM query by the id alone":
        (ORM + _route("    return db.query(Order).filter(Order.id == order_id).first()\n",
                      sig="order_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)"),
         ["LT-AUTHZ-OWNER"]),
    "clean: the ORM query also asks for the caller's own":
        (ORM + _route("    return db.query(Order).filter(Order.id == order_id, Order.user_id == user['id']).first()\n",
                      sig="order_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)"), []),
    "caught: session.get by the id alone":
        (ORM + _route("    return db.get(Order, order_id)\n",
                      sig="order_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)"),
         ["LT-AUTHZ-OWNER"]),
    "clean: session.get, then the owner is compared":
        (ORM + _route("    order = db.get(Order, order_id)\n    if order is None or order.user_id != user['id']:\n"
                      "        raise HTTPException(404)\n    return order\n",
                      sig="order_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)"), []),
}
MODELS = ("from sqlalchemy import Column, Integer\nfrom sqlalchemy.orm import declarative_base\n\n"
          "Base = declarative_base()\n\n\nclass Order(Base):\n    __tablename__ = 'orders'\n"
          "    id = Column(Integer, primary_key=True)\n    user_id = Column(Integer)\n")


@pytest.mark.parametrize("case", sorted(ORM_CASES))
def test_the_same_through_an_orm(tmp_path, case):
    body, want = ORM_CASES[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body, "app/models.py": MODELS})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- an admin route, Python

ADMIN_SIG = "user=Depends(get_current_user), db=Depends(get_db)"
USERS = "    return db.execute('SELECT id, email FROM users').fetchall()\n"
ROLE = {
    "caught: an admin page that only asks whether someone is signed in":
        (_route(USERS, sig=ADMIN_SIG, path="/admin/users"), ["LT-AUTHZ-ROLE"]),
    "clean: it asks whether the caller is an admin":
        (_route("    if not user['is_admin']:\n        raise HTTPException(403)\n" + USERS, sig=ADMIN_SIG,
                path="/admin/users"), []),
    "clean: a dependency asks whether the caller is an admin":
        ("def require_admin(user=Depends(get_current_user)):\n    if not user['is_admin']:\n"
         "        raise HTTPException(403)\n    return user\n\n\n" +
         _route(USERS, sig="admin=Depends(require_admin), db=Depends(get_db)", path="/admin/users"), []),
    "caught: a dependency named require_admin that asks nothing about the role":
        ("def require_admin(user=Depends(get_current_user)):\n    return user\n\n\n" +
         _route(USERS, sig="admin=Depends(require_admin), db=Depends(get_db)", path="/admin/users"),
         ["LT-AUTHZ-ROLE"]),
    "clean: a page that is not for admins":
        (_route(USERS, sig=ADMIN_SIG, path="/team/users"), []),
}


@pytest.mark.parametrize("case", sorted(ROLE))
def test_an_admin_route_has_to_ask_for_an_admin(tmp_path, case):
    body, want = ROLE[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- everything the request sent, onto a record (Python)

FLASK = ("from flask import Flask, abort, jsonify, request\nfrom flask_login import current_user, login_required\n\n"
         "from .models import User, db\n\napp = Flask(__name__)\n\n\n")
FLASK_PROJECT = {"pyproject.toml": '[project]\nname="a"\nversion="0"\ndependencies=["flask", "flask-login"]\n',
                 "app/__init__.py": "",
                 "app/models.py": "from flask_sqlalchemy import SQLAlchemy\n\ndb = SQLAlchemy()\n\n\n"
                                  "class User(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
                                  "    name = db.Column(db.String)\n    is_admin = db.Column(db.Boolean)\n"}
ME = "@app.post('/me')\n@login_required\ndef update_me():\n"
ASSIGN = {
    "caught: every field the request sent is written onto the user":
        (ME + "    User.query.filter_by(id=current_user.id).update(request.json)\n    db.session.commit()\n"
              "    return jsonify(ok=True)\n", ["LT-AUTHZ-MASS-ASSIGN"]),
    "caught: a loop that sets whatever was sent":
        (ME + "    for key, value in request.json.items():\n        setattr(current_user, key, value)\n"
              "    db.session.commit()\n    return jsonify(ok=True)\n", ["LT-AUTHZ-MASS-ASSIGN"]),
    "clean: one named field":
        (ME + "    current_user.name = request.json['name']\n    db.session.commit()\n    return jsonify(ok=True)\n",
         []),
    "clean: named fields are picked out first":
        (ME + "    data = {'name': request.json['name']}\n"
              "    User.query.filter_by(id=current_user.id).update(data)\n    db.session.commit()\n"
              "    return jsonify(ok=True)\n", []),
    "caught: a new user made of everything that was sent":
        ("@app.post('/users')\ndef sign_up():\n    user = User(**request.json)\n    db.session.add(user)\n"
         "    db.session.commit()\n    return jsonify(id=user.id)\n", ["LT-AUTHZ-MASS-ASSIGN"]),
}


@pytest.mark.parametrize("case", sorted(ASSIGN))
def test_everything_the_request_sent_written_onto_a_record(tmp_path, case):
    body, want = ASSIGN[case]
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=FLASK_PROJECT)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


FLASK_OWNER = {
    "caught: flask-login says who is signed in, and the note is read by its id alone":
        ("from .models import Note\n\n\n@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n"
         "    note = Note.query.get_or_404(note_id)\n    return jsonify(text=note.text)\n", ["LT-AUTHZ-OWNER"]),
    "clean: the note's owner is compared with who is signed in":
        ("from .models import Note\n\n\n@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n"
         "    note = Note.query.get_or_404(note_id)\n    if note.user_id != current_user.id:\n        abort(403)\n"
         "    return jsonify(text=note.text)\n", []),
    "clean: the query is for the caller's own note":
        ("from .models import Note\n\n\n@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n"
         "    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()\n"
         "    return jsonify(text=note.text)\n", []),
}


@pytest.mark.parametrize("case", sorted(FLASK_OWNER))
def test_flask_login_and_a_record_by_its_id(tmp_path, case):
    body, want = FLASK_OWNER[case]
    project = dict(FLASK_PROJECT)
    project["app/models.py"] += ("\n\nclass Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
                                 "    user_id = db.Column(db.Integer)\n    text = db.Column(db.String)\n")
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=project)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# How an app loads its record classes must not matter (found 2026-11-11 while writing the stage report: every Flask
# example above says `from .models import ...`, and with `from app.models import Note`, the commonest way, nothing was
# reported). The same four routes in six layouts; a class that comes from a library stays a library's.
NOTE_MODELS = ("from flask_sqlalchemy import SQLAlchemy\n\ndb = SQLAlchemy()\n\n\n"
               "class Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
               "    user_id = db.Column(db.Integer)\n    text = db.Column(db.String)\n")
FLASK_DEPS = '[project]\nname="a"\nversion="0"\ndependencies=["flask", "flask-login"]\n'
# layout: (the file with the routes, how it loads the class, the class as written, the other files)
LOADED = {
    "a relative import": ("app/main.py", "from .models import Note, db", "Note",
                          {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "app/models.py": NOTE_MODELS}),
    "the package by its name": ("app/main.py", "from app.models import Note, db", "Note",
                                {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "app/models.py": NOTE_MODELS}),
    "the models file as a module of the package": ("app/main.py", "from app import models\nfrom app.models import db",
                                                   "models.Note", {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "",
                                                                   "app/models.py": NOTE_MODELS}),
    "a flat project": ("app.py", "from models import Note, db", "Note",
                       {"pyproject.toml": FLASK_DEPS, "models.py": NOTE_MODELS}),
    "a flat project, the file as a module": ("app.py", "import models\nfrom models import db", "models.Note",
                                             {"pyproject.toml": FLASK_DEPS, "models.py": NOTE_MODELS}),
    "the app in a folder below the repository's": ("backend/app/main.py", "from app.models import Note, db", "Note",
                                                   {"backend/pyproject.toml": FLASK_DEPS, "backend/app/__init__.py": "",
                                                    "backend/app/models.py": NOTE_MODELS}),
    # started from inside its folder (`cd app && flask run`), an app finds the file beside it by its bare name, also
    # when the folder holds an `__init__.py`
    "the file beside, by its bare name, in a folder that is a package": (
        "app/main.py", "from models import Note, db", "Note",
        {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "app/models.py": NOTE_MODELS}),
    # `from .models import *` brings what Python would bring
    "everything the models file holds, with a star": (
        "app/main.py", "from .models import *", "Note",
        {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "app/models.py": NOTE_MODELS}),
    "everything the models file holds, with a star, the package by its name": (
        "app/main.py", "from app.models import *", "Note",
        {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "app/models.py": NOTE_MODELS}),
    "a flat project, with a star": ("app.py", "from models import *", "Note",
                                    {"pyproject.toml": FLASK_DEPS, "models.py": NOTE_MODELS}),
    "with a star, through a second file that brings it with a star": (
        "app/main.py", "from .store import *", "Note",
        {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "app/models.py": NOTE_MODELS,
         "app/store.py": "from .models import *\n"}),
}
NOTE_HEAD = ("from flask import Flask, abort, jsonify, request\nfrom flask_login import current_user, login_required\n\n"
             "{load}\n\napp = Flask(__name__)\n\n\n")
NOTE_ROUTES = {
    "caught: the note is read by its id alone":
        ("@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n"
         "    note = {N}.query.get_or_404(note_id)\n    return jsonify(text=note.text)\n", ["LT-AUTHZ-OWNER"]),
    "caught: the note is removed by its id alone":
        ("@app.delete('/notes/<int:note_id>')\n@login_required\ndef remove_note(note_id):\n"
         "    note = {N}.query.get_or_404(note_id)\n    db.session.delete(note)\n    db.session.commit()\n"
         "    return jsonify(ok=True)\n", ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared before the note is removed":
        ("@app.delete('/notes/<int:note_id>')\n@login_required\ndef remove_note(note_id):\n"
         "    note = {N}.query.get_or_404(note_id)\n    if note.user_id != current_user.id:\n        abort(403)\n"
         "    db.session.delete(note)\n    db.session.commit()\n    return jsonify(ok=True)\n", []),
    "caught: everything the request sent is written onto the caller's own note":
        ("@app.post('/notes/<int:note_id>')\n@login_required\ndef change_note(note_id):\n"
         "    {N}.query.filter_by(id=note_id, user_id=current_user.id).update(request.json)\n"
         "    db.session.commit()\n    return jsonify(ok=True)\n", ["LT-AUTHZ-MASS-ASSIGN"]),
}


@pytest.mark.parametrize("layout", sorted(LOADED))
@pytest.mark.parametrize("case", sorted(NOTE_ROUTES))
def test_how_the_record_class_is_loaded_does_not_matter(tmp_path, layout, case):
    main, load, cls, others = LOADED[layout]
    body, want = NOTE_ROUTES[case]
    fs = _scan(tmp_path, {main: NOTE_HEAD.replace("{load}", load) + body.replace("{N}", cls)}, project=others)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


LIBRARY_CLASS = {
    "clean: a class a library hands over, read the same way":
        ("from flask import Flask, jsonify\nfrom flask_login import login_required\n\nfrom shoplib.models import Note\n\n"
         "app = Flask(__name__)\n\n\n@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n"
         "    note = Note.query.get_or_404(note_id)\n    return jsonify(text=note.text)\n", []),
    "clean: a library named like a file of the project that lies somewhere else":
        ("from flask import Flask, jsonify\nfrom flask_login import login_required\n\nfrom inventory import Note\n\n"
         "app = Flask(__name__)\n\n\n@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n"
         "    note = Note.query.get_or_404(note_id)\n    return jsonify(text=note.text)\n", []),
    # `app/shoplib.py` is the project's settings for that library (as `proj/celery.py` is for Celery): it holds no `Note`
    "clean: a library named like the file beside, which holds no such class":
        ("from flask import Flask, jsonify\nfrom flask_login import login_required\n\nfrom shoplib import Note\n\n"
         "app = Flask(__name__)\n\n\n@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n"
         "    note = Note.query.get_or_404(note_id)\n    return jsonify(text=note.text)\n", []),
}


@pytest.mark.parametrize("case", sorted(LIBRARY_CLASS))
def test_a_class_from_a_library_is_not_the_projects_record(tmp_path, case):
    body, want = LIBRARY_CLASS[case]
    others = {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "tools/__init__.py": "",
              "tools/inventory.py": NOTE_MODELS,
              "app/shoplib.py": "from shoplib import Shop\n\nshop = Shop('notes')\n"}
    fs = _scan(tmp_path, {"app/main.py": body}, project=others)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# A star import brings the names Python would bring, and no others; an import written inside the function that uses
# the class is read like one at the top of the file.
STAR_READ = ("@app.get('/notes/<int:note_id>')\n@login_required\ndef read_note(note_id):\n{inside}"
             "    note = Note.query.get_or_404(note_id)\n{check}    return jsonify(text=note.text)\n")
STAR_CHECK = "    if note.user_id != current_user.id:\n        abort(403)\n"
STAR_FILES = {"pyproject.toml": FLASK_DEPS, "app/__init__.py": "", "app/models.py": NOTE_MODELS}
# case: (the import at the top, the import inside the function, the owner check, files that differ, what is reported)
STAR_AND_INSIDE = {
    "caught: the file says what a star brings, and the class is on that list":
        ("from .models import *", "", "", {"app/models.py": '__all__ = ["db", "Note"]\n\n' + NOTE_MODELS},
         ["LT-AUTHZ-OWNER"]),
    "clean: the file says what a star brings, the class is not on that list, and the name is a library's":
        ("from shoplib.models import Note\nfrom .models import *", "", "",
         {"app/models.py": '__all__ = ["db"]\n\n' + NOTE_MODELS}, []),
    "clean: a name written by hand after the star is the one that counts":
        ("from .models import *\nfrom shoplib.models import Note", "", "", {}, []),
    "clean: a star import of a library, and the class is the library's":
        ("from shoplib.models import *", "", "", {}, []),
    "clean: with a star, and the owner is compared":
        ("from .models import *", "", STAR_CHECK, {}, []),
    "clean: a later star import of a library may bring that name too, so Lantern does not say whose it is":
        ("from .models import *\nfrom shoplib.models import *", "", "", {}, []),
    "caught: the import is inside the function, the package by its name":
        ("", "    from app.models import Note\n", "", {}, ["LT-AUTHZ-OWNER"]),
    "caught: the import is inside the function, with a dot":
        ("", "    from .models import Note\n", "", {}, ["LT-AUTHZ-OWNER"]),
    "clean: the import is inside the function, and the owner is compared":
        ("", "    from app.models import Note\n", STAR_CHECK, {}, []),
    "clean: the import is inside the function, and the class is a library's":
        ("", "    from shoplib.models import Note\n", "", {}, []),
}


@pytest.mark.parametrize("case", sorted(STAR_AND_INSIDE))
def test_a_star_import_and_an_import_inside_the_function(tmp_path, case):
    top, inside, check, files, want = STAR_AND_INSIDE[case]
    body = NOTE_HEAD.replace("{load}", top) + STAR_READ.replace("{inside}", inside).replace("{check}", check)
    fs = _scan(tmp_path, {"app/main.py": body}, project={**STAR_FILES, **files})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_an_import_inside_the_function_in_a_flat_project(tmp_path):
    body = NOTE_HEAD.replace("{load}", "") + STAR_READ.replace("{inside}", "    from models import Note\n")
    fs = _scan(tmp_path, {"app.py": body.replace("{check}", "")},
               project={"pyproject.toml": FLASK_DEPS, "models.py": NOTE_MODELS})
    assert _authz(fs) == ["LT-AUTHZ-OWNER"], [(f["rule"], f["file"], f["line"]) for f in fs]


# Which file of the project an import written from the top names. `known`: every Python file's dotted name, True for
# a package's `__init__`.
APP = {"app": True, "app.main": False, "app.models": False}
OWN_MODULE = {
    "the package by its name": (("app", "models"), ["app"], APP, ("app", "models")),
    "a flat project": (("models",), [], {"app": False, "models": False}, ("models",)),
    "the folder below the repository's is where imports start": (
        ("app", "models"), ["backend", "app"],
        {"backend.app": True, "backend.app.main": False, "backend.app.models": False}, ("backend", "app", "models")),
    "the nearest folder first": (("utils",), ["scripts"],
                                 {"scripts.tool": False, "scripts.utils": False, "utils": False}, ("scripts", "utils")),
    "a package's own file is not reached by its bare name: that name is the library's": (
        ("celery",), ["proj"], {"proj": True, "proj.celery": False, "proj.tasks": False}, None),
    "a single name the standard library has": (("logging",), [], {"logging": False, "app": False}, None),
    "a longer path that starts with a name of the standard library is never found by its ending": (
        ("email", "utils"), ["app"], {**APP, "app.email": True, "app.email.utils": False}, None),
    "a project's own package named like a module of the standard library, written in full": (
        ("calendar", "models"), ["calendar"], {"calendar": True, "calendar.models": False, "calendar.views": False},
        ("calendar", "models")),
    "from a test file: the one file of the project whose name ends with the path": (
        ("notes", "models"), ["tests"], {"tests.test_notes": False, "src.notes": True, "src.notes.models": False},
        ("src", "notes", "models")),
    "two files end with the path: neither": (
        ("core", "models"), ["tests"], {"tests.test_x": False, "a.core.models": False, "b.core.models": False}, None),
}


@pytest.mark.parametrize("case", sorted(OWN_MODULE))
def test_which_file_of_the_project_an_import_from_the_top_names(case):
    import sys

    from lantern import flow
    parts, pkg, known, want = OWN_MODULE[case]
    assert flow.own_module(parts, pkg, known, frozenset(sys.stdlib_module_names)) == want


# ------------------------------------------------------------- JavaScript: Express

PACKAGE = '{"dependencies": {"express": "4.19.2", "mysql2": "3.9.7", "mongoose": "8.4.0", "lodash": "4.17.21"}}'
JS = ("const express = require('express')\n"
      "const mysql = require('mysql2/promise')\n"
      "const _ = require('lodash')\n"
      "const { Order, User } = require('./models')\n"
      "const app = express()\n"
      "app.use(express.json())\n"
      "const pool = mysql.createPool({ host: 'localhost' })\n"
      "function requireLogin (req, res, next) {\n"
      "  if (!req.session.userId) return res.status(401).end()\n"
      "  next()\n"
      "}\n")
JS_MODELS = ("const mongoose = require('mongoose')\n"
             "const Order = mongoose.model('Order', new mongoose.Schema({ user: String, item: String }))\n"
             "const User = mongoose.model('User', new mongoose.Schema({ name: String, role: String }))\n"
             "module.exports = { Order, User }\n")


def _js(body, mw="requireLogin, ", verb="get", path="/orders/:id"):
    return f"app.{verb}('{path}', {mw}async (req, res) => {{\n{body}}})\n"


JS_OWNER = {
    "caught: the order is read by its id alone":
        (_js("  const [rows] = await pool.query('SELECT * FROM orders WHERE id = ?', [req.params.id])\n"
             "  res.json(rows[0])\n"), ["LT-AUTHZ-OWNER"]),
    "clean: the query asks for the caller's own order":
        (_js("  const [rows] = await pool.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', "
             "[req.params.id, req.session.userId])\n  res.json(rows[0])\n"), []),
    "clean: the owner is compared after the order is read":
        (_js("  const [rows] = await pool.query('SELECT * FROM orders WHERE id = ?', [req.params.id])\n"
             "  if (!rows[0] || rows[0].user_id !== req.session.userId) return res.status(404).end()\n"
             "  res.json(rows[0])\n"), []),
    "caught: a model looked up by the id alone":
        (_js("  res.json(await Order.findById(req.params.id))\n"), ["LT-AUTHZ-OWNER"]),
    "clean: the model is asked for the caller's own":
        (_js("  res.json(await Order.findOne({ _id: req.params.id, user: req.session.userId }))\n"), []),
    "clean: a middleware compares the owner before the handler runs":
        ("async function ownsOrder (req, res, next) {\n"
         "  const order = await Order.findById(req.params.id)\n"
         "  if (!order || order.user !== req.session.userId) return res.status(404).end()\n"
         "  next()\n}\n" +
         _js("  res.json(await Order.findById(req.params.id))\n", mw="requireLogin, ownsOrder, "), []),
    "caught: a middleware named ownsOrder that compares nothing":
        ("function ownsOrder (req, res, next) {\n  next()\n}\n" +
         _js("  res.json(await Order.findById(req.params.id))\n", mw="requireLogin, ownsOrder, "), ["LT-AUTHZ-OWNER"]),
    "clean: nobody is signed in at all, which is another finding's business":
        (_js("  res.json(await Order.findById(req.params.id))\n", mw=""), []),
    "caught: an order deleted by its id alone":
        (_js("  await Order.deleteOne({ _id: req.params.id })\n  res.status(204).end()\n", verb="delete"),
         ["LT-AUTHZ-OWNER"]),
}


@pytest.mark.parametrize("case", sorted(JS_OWNER))
def test_express_a_record_reached_by_its_id(tmp_path, case):
    body, want = JS_OWNER[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# A login put on with `use`: on the app, on a path, on a router or on its mount. It counts for the routes written
# after it, and for nothing else.
READ = "  res.json(await Order.findById(req.params.id))\n"
OWNS = ("async function ownsOrder (req, res, next) {\n"
        "  const order = await Order.findById(req.params.id)\n"
        "  if (!order || order.user !== req.session.userId) return res.status(404).end()\n"
        "  next()\n}\n")
JS_GUARD = ("exports.requireLogin = function (req, res, next) {\n"
            "  if (!req.session.userId) return res.status(401).end()\n  next()\n}\n")
JS_ROUTER = ("const router = require('express').Router()\nconst { Order } = require('../models')\n"
             "const { requireLogin } = require('../lib/guard')\n")
ROUTER_READ = "router.get('/orders/:id', async (req, res) => {\n" + READ + "})\nmodule.exports = router\n"
JS_USE = {
    "caught: the login is put on the app before the route":
        ({"server.js": JS + "app.use(requireLogin)\n" + _js(READ, mw="")}, ["LT-AUTHZ-OWNER"]),
    "clean: it is put on the app after the route, so nobody is signed in there (another finding's business)":
        ({"server.js": JS + _js(READ, mw="") + "app.use(requireLogin)\n"}, []),
    "caught: it is put on the path the route is under":
        ({"server.js": JS + "app.use('/orders', requireLogin)\n" + _js(READ, mw="")}, ["LT-AUTHZ-OWNER"]),
    "clean: it is put on another path":
        ({"server.js": JS + "app.use('/orderly', requireLogin)\n" + _js(READ, mw="")}, []),
    "caught: it is put on the router the route is on":
        ({"server.js": JS + "app.use('/api', require('./routes/orders'))\n", "lib/guard.js": JS_GUARD,
          "routes/orders.js": JS_ROUTER + "router.use(requireLogin)\n" + ROUTER_READ}, ["LT-AUTHZ-OWNER"]),
    "caught: it stands before the router in its mount":
        ({"server.js": JS + "app.use('/api', requireLogin, require('./routes/orders'))\n", "lib/guard.js": JS_GUARD,
          "routes/orders.js": JS_ROUTER + ROUTER_READ}, ["LT-AUTHZ-OWNER"]),
    "caught: it is put on the app before a router loaded into a name is mounted":
        ({"server.js": JS + "const orders = require('./routes/orders')\napp.use(requireLogin)\n"
                            "app.use('/api', orders)\n", "lib/guard.js": JS_GUARD,
          "routes/orders.js": JS_ROUTER + ROUTER_READ}, ["LT-AUTHZ-OWNER"]),
    "clean: it is put on the app after the router is mounted":
        ({"server.js": JS + "const orders = require('./routes/orders')\napp.use('/api', orders)\n"
                            "app.use(requireLogin)\n", "lib/guard.js": JS_GUARD,
          "routes/orders.js": JS_ROUTER + ROUTER_READ}, []),
    "clean: a middleware put on the path compares the owner":
        ({"server.js": JS + OWNS + "app.use(requireLogin)\napp.use('/orders/:id', ownsOrder)\n" + _js(READ, mw="")},
         []),
    "caught: a middleware named ownsOrder put on the path compares nothing":
        ({"server.js": JS + "function ownsOrder (req, res, next) {\n  next()\n}\n"
                            "app.use(requireLogin)\napp.use('/orders/:id', ownsOrder)\n" + _js(READ, mw="")},
         ["LT-AUTHZ-OWNER"]),
    "clean: only a session library is put on the app, which signs nobody in":
        ({"server.js": JS + "const session = require('express-session')\n"
                            "app.use(session({ secret: process.env.SESSION_SECRET }))\n" + _js(READ, mw="")}, []),
    "caught: an admin path under a login put on the app asks for no admin":
        ({"server.js": JS + "app.use(requireLogin)\n"
                            + _js("  res.json(await User.find())\n", mw="", path="/admin/users")}, ["LT-AUTHZ-ROLE"]),
    "clean: the admin check is put on the admin path":
        ({"server.js": JS + "function requireAdmin (req, res, next) {\n"
                            "  if (req.session.role !== 'admin') return res.status(403).end()\n  next()\n}\n"
                            "app.use(requireLogin)\napp.use('/admin', requireAdmin)\n"
                            + _js("  res.json(await User.find())\n", mw="", path="/admin/users")}, []),
}


@pytest.mark.parametrize("case", sorted(JS_USE))
def test_express_a_login_put_on_with_use(tmp_path, case):
    files, want = JS_USE[case]
    fs = _scan(tmp_path, {"models.js": JS_MODELS, **files}, project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


JS_ROLE = {
    "caught: an admin route that only asks whether someone is signed in":
        (_js("  res.json(await User.find())\n", path="/admin/users"), ["LT-AUTHZ-ROLE"]),
    "clean: a middleware asks for an admin":
        ("function requireAdmin (req, res, next) {\n"
         "  if (req.session.role !== 'admin') return res.status(403).end()\n  next()\n}\n" +
         _js("  res.json(await User.find())\n", mw="requireLogin, requireAdmin, ", path="/admin/users"), []),
    "caught: a middleware named requireAdmin that asks nothing":
        ("function requireAdmin (req, res, next) {\n  next()\n}\n" +
         _js("  res.json(await User.find())\n", mw="requireLogin, requireAdmin, ", path="/admin/users"),
         ["LT-AUTHZ-ROLE"]),
    "clean: the handler asks for an admin itself":
        (_js("  if (req.session.role !== 'admin') return res.status(403).end()\n  res.json(await User.find())\n",
             path="/admin/users"), []),
}


@pytest.mark.parametrize("case", sorted(JS_ROLE))
def test_express_an_admin_route_has_to_ask_for_an_admin(tmp_path, case):
    body, want = JS_ROLE[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


JS_ASSIGN = {
    "caught: every field the request sent is written onto the user":
        (_js("  await User.findByIdAndUpdate(req.session.userId, req.body)\n  res.status(204).end()\n",
             verb="put", path="/me"), ["LT-AUTHZ-MASS-ASSIGN"]),
    "caught: a copy of everything that was sent":
        (_js("  const data = { ...req.body }\n  await User.findByIdAndUpdate(req.session.userId, data)\n"
             "  res.status(204).end()\n", verb="put", path="/me"), ["LT-AUTHZ-MASS-ASSIGN"]),
    "caught: everything that was sent is laid over the record":
        (_js("  const user = await User.findById(req.session.userId)\n  Object.assign(user, req.body)\n"
             "  await user.save()\n  res.status(204).end()\n", verb="put", path="/me"), ["LT-AUTHZ-MASS-ASSIGN"]),
    "clean: one named field":
        (_js("  await User.findByIdAndUpdate(req.session.userId, { name: req.body.name })\n"
             "  res.status(204).end()\n", verb="put", path="/me"), []),
    "clean: named fields are picked out first":
        (_js("  const data = _.pick(req.body, ['name', 'bio'])\n"
             "  await User.findByIdAndUpdate(req.session.userId, data)\n  res.status(204).end()\n",
             verb="put", path="/me"), []),
    "clean: the fields are taken out by name":
        (_js("  const { name, bio } = req.body\n  await User.findByIdAndUpdate(req.session.userId, { name, bio })\n"
             "  res.status(204).end()\n", verb="put", path="/me"), []),
    "caught: a new user made of everything that was sent":
        (_js("  const user = await User.create(req.body)\n  res.json({ id: user.id })\n", mw="", verb="post",
             path="/users"), ["LT-AUTHZ-MASS-ASSIGN"]),
}


@pytest.mark.parametrize("case", sorted(JS_ASSIGN))
def test_express_everything_the_request_sent_written_onto_a_record(tmp_path, case):
    body, want = JS_ASSIGN[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- look-alikes: the order of things, helpers, app-wide checks

MORE = {
    "caught: the owner is compared only after the order is deleted":
        (_route("    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n"
                f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n"
                "    if row is not None and row['user_id'] != user['id']:\n        raise HTTPException(403)\n"
                "    return {'ok': True}\n", verb="delete"), ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then the order is deleted":
        (_route(f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n"
                "    if row is None or row['user_id'] != user['id']:\n        raise HTTPException(404)\n"
                "    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n"
                "    return {'ok': True}\n", verb="delete"), []),
    "caught: the query text is handed to a helper that runs it":
        ("def query_db(db, sql, args=()):\n    return db.execute(sql, args).fetchall()\n\n\n" +
         _route(f"    return query_db(db, '{ONE}', (order_id,))\n"), ["LT-AUTHZ-OWNER"]),
    "clean: the helper is handed a query for the caller's own order":
        ("def query_db(db, sql, args=()):\n    return db.execute(sql, args).fetchall()\n\n\n" +
         _route(f"    return query_db(db, '{MINE}', (order_id, user['id']))\n"), []),
    "clean: the helper is handed a query that picks no record":
        ("def query_db(db, sql, args=()):\n    return db.execute(sql, args).fetchall()\n\n\n" +
         _route("    return query_db(db, 'INSERT INTO views (order_id) VALUES (?)', (order_id,))\n"), []),
    "caught: an account that is active is not an account that owns the order":
        (_route("    if user['status'] != 'active':\n        raise HTTPException(403)\n"
                f"    return db.execute('{ONE}', (order_id,)).fetchone()\n"), ["LT-AUTHZ-OWNER"]),
    "caught: a number made of what the request sent still picks the record":
        (_route(f"    return db.execute('{ONE}', (int(order_id),)).fetchone()\n",
                sig="order_id: str, user=Depends(get_current_user), db=Depends(get_db)"), ["LT-AUTHZ-OWNER"]),
    "clean: a check the project does not hold, named for what it does, is taken at its word":
        ("from authlib_checks import authorize\n\n\n" +
         _route(f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n    authorize(user, row)\n    return row\n"),
         []),
    "caught: a call the project does not hold, named for something else":
        ("from metrics_lib import audit\n\n\n" +
         _route(f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n    audit(user, row)\n    return row\n"),
         ["LT-AUTHZ-OWNER"]),
    "clean: every route of the router asks for an admin first":
        ("from fastapi import APIRouter\n\n\n"
         "def require_admin(user=Depends(get_current_user)):\n    if not user['is_admin']:\n"
         "        raise HTTPException(403)\n    return user\n\n\n"
         "router = APIRouter(prefix='/admin', dependencies=[Depends(require_admin)])\n\n\n"
         "@router.get('/users')\ndef handle(user=Depends(get_current_user), db=Depends(get_db)):\n" + USERS +
         "\n\napp.include_router(router)\n", []),
    "caught: every route of the router runs a function that asks nothing":
        ("from fastapi import APIRouter\n\n\n"
         "def require_admin(user=Depends(get_current_user)):\n    return user\n\n\n"
         "router = APIRouter(prefix='/admin', dependencies=[Depends(require_admin)])\n\n\n"
         "@router.get('/users')\ndef handle(user=Depends(get_current_user), db=Depends(get_db)):\n" + USERS +
         "\n\napp.include_router(router)\n", ["LT-AUTHZ-ROLE"]),
    "clean: SQLAlchemy 2: the statement asks for the caller's own":
        ("from sqlalchemy import select\n\nfrom .models import Order\n\n\n" +
         _route("    stmt = select(Order).where(Order.id == order_id, Order.user_id == user['id'])\n"
                "    return db.execute(stmt).scalar_one_or_none()\n"), []),
    "caught: SQLAlchemy 2: the statement asks by the id alone":
        ("from sqlalchemy import select\n\nfrom .models import Order\n\n\n" +
         _route("    stmt = select(Order).where(Order.id == order_id)\n"
                "    return db.execute(stmt).scalar_one_or_none()\n"), ["LT-AUTHZ-OWNER"]),
    "clean: a second filter on the same query asks for the caller's own":
        ("from .models import Order\n\n\n" +
         _route("    q = db.query(Order).filter(Order.id == order_id).filter(Order.user_id == user['id'])\n"
                "    return q.first()\n"), []),
}


@pytest.mark.parametrize("case", sorted(MORE))
def test_look_alikes_of_an_ownership_check(tmp_path, case):
    body, want = MORE[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body, "app/models.py": MODELS})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


FLASK_MORE = {
    "clean: a hook before every request asks for an admin":
        ("@app.before_request\ndef only_admins():\n    if not current_user.is_admin:\n        abort(403)\n\n\n"
         "@app.get('/admin/users')\n@login_required\ndef users():\n    return jsonify(n=User.query.count())\n", []),
    "caught: a hook before every request that asks nothing about the role":
        ("@app.before_request\ndef only_admins():\n    if not current_user.is_authenticated:\n        abort(401)\n\n\n"
         "@app.get('/admin/users')\n@login_required\ndef users():\n    return jsonify(n=User.query.count())\n",
         ["LT-AUTHZ-ROLE"]),
    "clean: the project's own decorator asks for an admin":
        ("from functools import wraps\n\n\ndef admin_only(view):\n    @wraps(view)\n    def inner(*args, **kwargs):\n"
         "        if not current_user.is_admin:\n            abort(403)\n        return view(*args, **kwargs)\n"
         "    return inner\n\n\n"
         "@app.get('/admin/users')\n@login_required\n@admin_only\ndef users():\n"
         "    return jsonify(n=User.query.count())\n", []),
    "caught: the project's own decorator is named admin_only and asks nothing":
        ("from functools import wraps\n\n\ndef admin_only(view):\n    @wraps(view)\n    def inner(*args, **kwargs):\n"
         "        return view(*args, **kwargs)\n    return inner\n\n\n"
         "@app.get('/admin/users')\n@login_required\n@admin_only\ndef users():\n"
         "    return jsonify(n=User.query.count())\n", ["LT-AUTHZ-ROLE"]),
    "clean: a library's decorator named for a role is taken at its word":
        ("from flask_principal import roles_required\n\n\n"
         "@app.get('/admin/users')\n@login_required\n@roles_required('admin')\ndef users():\n"
         "    return jsonify(n=User.query.count())\n", []),
    "caught: a helper sets whatever fields it is handed, and is handed everything":
        ("def apply(user, data):\n    for key, value in data.items():\n        setattr(user, key, value)\n\n\n" +
         ME + "    apply(current_user, request.json)\n    db.session.commit()\n    return jsonify(ok=True)\n",
         ["LT-AUTHZ-MASS-ASSIGN"]),
    "clean: the helper is handed two named fields":
        ("def apply(user, data):\n    for key, value in data.items():\n        setattr(user, key, value)\n\n\n" +
         ME + "    apply(current_user, {'name': request.json['name'], 'bio': request.json['bio']})\n"
              "    db.session.commit()\n    return jsonify(ok=True)\n", []),
    "caught: a number read from the address picks the note":
        ("from .models import Note\n\n\n@app.get('/note')\n@login_required\ndef read_note():\n"
         "    note_id = int(request.args['id'])\n    note = Note.query.get(note_id)\n"
         "    return jsonify(text=note.text)\n", ["LT-AUTHZ-OWNER"]),
    "clean: the same, and the query is for the caller's own note":
        ("from .models import Note\n\n\n@app.get('/note')\n@login_required\ndef read_note():\n"
         "    note_id = int(request.args['id'])\n"
         "    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()\n"
         "    return jsonify(text=note.text)\n", []),
}


@pytest.mark.parametrize("case", sorted(FLASK_MORE))
def test_flask_look_alikes(tmp_path, case):
    body, want = FLASK_MORE[case]
    project = dict(FLASK_PROJECT)
    project["app/models.py"] += ("\n\nclass Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
                                 "    user_id = db.Column(db.Integer)\n    text = db.Column(db.String)\n")
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=project)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


JS_MORE = {
    "caught: the owner is compared only after the order is deleted":
        (_js("  await Order.deleteOne({ _id: req.params.id })\n"
             "  const order = await Order.findById(req.params.id)\n"
             "  if (order && order.user !== req.session.userId) return res.status(403).end()\n"
             "  res.status(204).end()\n", verb="delete"), ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then the order is deleted":
        (_js("  const order = await Order.findById(req.params.id)\n"
             "  if (!order || order.user !== req.session.userId) return res.status(404).end()\n"
             "  await Order.deleteOne({ _id: req.params.id })\n  res.status(204).end()\n", verb="delete"), []),
    "clean: the owner is compared with a method":
        (_js("  const order = await Order.findById(req.params.id)\n"
             "  if (!order || !order.user.equals(req.session.userId)) return res.status(404).end()\n"
             "  res.json(order)\n"), []),
    "clean: the id in the address has to be the caller's own":
        (_js("  if (req.params.id !== req.session.userId) return res.status(403).end()\n"
             "  res.json(await User.findById(req.params.id))\n", path="/users/:id"), []),
    "caught: a list of fixed names is asked about the order, not about the caller":
        (_js("  if (!['open', 'paid'].includes(req.query.state)) return res.status(400).end()\n"
             "  res.json(await Order.findById(req.params.id))\n"), ["LT-AUTHZ-OWNER"]),
    "clean: the caller has to be on a fixed list of admins":
        ("const ADMINS = ['ana@example.com', 'bo@example.com']\n" +
         _js("  if (!ADMINS.includes(req.session.email)) return res.status(403).end()\n"
             "  res.json(await User.find())\n", path="/admin/users"), []),
    "caught: a helper lays everything it is handed over the record, and is handed everything":
        ("async function change (id, fields) {\n  const user = await User.findById(id)\n"
         "  Object.assign(user, fields)\n  return user.save()\n}\n" +
         _js("  await change(req.session.userId, req.body)\n  res.status(204).end()\n", verb="put", path="/me"),
         ["LT-AUTHZ-MASS-ASSIGN"]),
    "clean: the helper is handed one named field":
        ("async function change (id, fields) {\n  const user = await User.findById(id)\n"
         "  Object.assign(user, fields)\n  return user.save()\n}\n" +
         _js("  await change(req.session.userId, { name: req.body.name })\n  res.status(204).end()\n",
             verb="put", path="/me"), []),
}


@pytest.mark.parametrize("case", sorted(JS_MORE))
def test_express_look_alikes(tmp_path, case):
    body, want = JS_MORE[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_a_loop_over_fields_the_code_names_sets_only_those(tmp_path):
    body = (ME + "    data = {'name': request.json['name'], 'bio': request.json['bio']}\n"
                 "    for key, value in data.items():\n        setattr(current_user, key, value)\n"
                 "    db.session.commit()\n    return jsonify(ok=True)\n")
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=FLASK_PROJECT)
    assert _authz(fs) == [], [(f["rule"], f["file"], f["line"]) for f in fs]
    body = (ME + "    data = {'name': request.json['name'], **request.json}\n"
                 "    for key, value in data.items():\n        setattr(current_user, key, value)\n"
                 "    db.session.commit()\n    return jsonify(ok=True)\n")
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=FLASK_PROJECT)
    assert _authz(fs) == ["LT-AUTHZ-MASS-ASSIGN"], [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- other ways of saying who is signed in, other databases

def test_an_admin_route_that_asks_for_the_admin_secret_is_asking(tmp_path):
    secret = ("import hmac\nimport os\n\n\n" +
              _route("    if not hmac.compare_digest(x_admin_key, os.environ['ADMIN_KEY']):\n"
                     "        raise HTTPException(403)\n" + USERS,
                     sig="x_admin_key: str = Header(...), user=Depends(get_current_user), db=Depends(get_db)",
                     path="/admin/users"))
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + secret})
    assert _authz(fs) == [], [(f["rule"], f["file"], f["line"]) for f in fs]
    plain = _route("    if x_request_id != os.environ['REGION']:\n        raise HTTPException(400)\n" + USERS,
                   sig="x_request_id: str = Header(...), user=Depends(get_current_user), db=Depends(get_db)",
                   path="/admin/users")
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + "import os\n\n\n" + plain})
    assert _authz(fs) == ["LT-AUTHZ-ROLE"], [(f["rule"], f["file"], f["line"]) for f in fs]


JWT = ("from flask import Flask, jsonify, request\nfrom flask_jwt_extended import get_jwt_identity, jwt_required\n\n"
       "from .models import Note, db\n\napp = Flask(__name__)\n\n\n")
JWT_CASES = {
    "caught: the token says who is asking, and the note is read by its id alone":
        ("@app.get('/notes/<int:note_id>')\n@jwt_required()\ndef read_note(note_id):\n"
         "    uid = get_jwt_identity()\n    app.logger.info('read by %s', uid)\n"
         "    note = Note.query.get_or_404(note_id)\n    return jsonify(text=note.text)\n", ["LT-AUTHZ-OWNER"]),
    "clean: the query asks for a note of the person the token names":
        ("@app.get('/notes/<int:note_id>')\n@jwt_required()\ndef read_note(note_id):\n"
         "    uid = get_jwt_identity()\n"
         "    note = Note.query.filter_by(id=note_id, user_id=uid).first_or_404()\n"
         "    return jsonify(text=note.text)\n", []),
    "clean: the note's owner is compared with the person the token names":
        ("@app.get('/notes/<int:note_id>')\n@jwt_required()\ndef read_note(note_id):\n"
         "    note = Note.query.get_or_404(note_id)\n    if note.user_id != get_jwt_identity():\n"
         "        return jsonify(error='not found'), 404\n    return jsonify(text=note.text)\n", []),
}


@pytest.mark.parametrize("case", sorted(JWT_CASES))
def test_a_token_that_names_the_caller(tmp_path, case):
    body, want = JWT_CASES[case]
    project = dict(FLASK_PROJECT)
    project["pyproject.toml"] = '[project]\nname="a"\nversion="0"\ndependencies=["flask", "flask-jwt-extended"]\n'
    project["app/models.py"] += ("\n\nclass Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
                                 "    user_id = db.Column(db.Integer)\n    text = db.Column(db.String)\n")
    fs = _scan(tmp_path, {"app/main.py": JWT + body}, project=project)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


PRISMA_PACKAGE = '{"dependencies": {"express": "4.19.2", "@prisma/client": "5.14.0", "jsonwebtoken": "9.0.2"}}'
PRISMA = ("const express = require('express')\n"
          "const jwt = require('jsonwebtoken')\n"
          "const { PrismaClient } = require('@prisma/client')\n"
          "const prisma = new PrismaClient()\n"
          "const app = express()\n"
          "app.use(express.json())\n"
          "function auth (req, res, next) {\n"
          "  try {\n    req.user = jwt.verify(req.headers.authorization, process.env.JWT_KEY)\n    next()\n"
          "  } catch (e) {\n    res.status(401).end()\n  }\n"
          "}\n")
PRISMA_CASES = {
    "caught: an invoice looked up by the id alone":
        ("app.get('/invoices/:id', auth, async (req, res) => {\n"
         "  res.json(await prisma.invoice.findUnique({ where: { id: req.params.id } }))\n})\n", ["LT-AUTHZ-OWNER"]),
    "clean: the look-up asks for the caller's own invoice":
        ("app.get('/invoices/:id', auth, async (req, res) => {\n"
         "  res.json(await prisma.invoice.findFirst({ where: { id: req.params.id, userId: req.user.id } }))\n})\n",
         []),
    "caught: an invoice changed by the id alone, with fields the code names":
        ("app.patch('/invoices/:id', auth, async (req, res) => {\n"
         "  res.json(await prisma.invoice.update({ where: { id: req.params.id }, data: { note: req.body.note } }))\n"
         "})\n", ["LT-AUTHZ-OWNER"]),
    "caught: the caller's own profile, changed with everything that was sent":
        ("app.patch('/me', auth, async (req, res) => {\n"
         "  res.json(await prisma.user.update({ where: { id: req.user.id }, data: req.body }))\n})\n",
         ["LT-AUTHZ-MASS-ASSIGN"]),
    "clean: an admin route whose handler asks for the role":
        ("app.get('/admin/invoices', auth, async (req, res) => {\n"
         "  if (req.user.role !== 'admin') return res.status(403).end()\n"
         "  res.json(await prisma.invoice.findMany())\n})\n", []),
}


@pytest.mark.parametrize("case", sorted(PRISMA_CASES))
def test_express_with_prisma(tmp_path, case):
    body, want = PRISMA_CASES[case]
    fs = _scan(tmp_path, {"server.js": PRISMA + body}, project={"package.json": PRISMA_PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


NEXT_PACKAGE = ('{"dependencies": {"next": "14.2.3", "next-auth": "4.24.7", "@prisma/client": "5.14.0", '
                '"@supabase/supabase-js": "2.43.0"}}')
NEXT_LIB = ("import { PrismaClient } from '@prisma/client'\nexport const prisma = new PrismaClient()\n")
NEXT_HEAD = ("import { getServerSession } from 'next-auth'\n"
             "import { createClient } from '@supabase/supabase-js'\n"
             "import { prisma } from '../../../../lib/prisma'\n"
             "import { authOptions } from '../../../../lib/auth'\n\n"
             "const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY)\n\n")
NEXT_CASES = {
    "caught: a signed-in person reads any invoice by its id":
        ("export async function GET (req, { params }) {\n"
         "  const session = await getServerSession(authOptions)\n"
         "  if (!session) return new Response('sign in', { status: 401 })\n"
         "  return Response.json(await prisma.invoice.findUnique({ where: { id: params.id } }))\n}\n",
         ["LT-AUTHZ-OWNER"]),
    "clean: the look-up asks for an invoice of the signed-in person":
        ("export async function GET (req, { params }) {\n"
         "  const session = await getServerSession(authOptions)\n"
         "  if (!session) return new Response('sign in', { status: 401 })\n"
         "  return Response.json(await prisma.invoice.findFirst({ where: { id: params.id, "
         "userId: session.user.id } }))\n}\n", []),
    "clean: the invoice's owner is compared with the signed-in person":
        ("export async function GET (req, { params }) {\n"
         "  const session = await getServerSession(authOptions)\n"
         "  if (!session) return new Response('sign in', { status: 401 })\n"
         "  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } })\n"
         "  if (!invoice || invoice.userId !== session.user.id) return new Response('not found', { status: 404 })\n"
         "  return Response.json(invoice)\n}\n", []),
    "clean: Supabase is asked, and its own row rules say who may see the row":
        ("export async function GET (req, { params }) {\n"
         "  const session = await getServerSession(authOptions)\n"
         "  if (!session) return new Response('sign in', { status: 401 })\n"
         "  const { data } = await supabase.from('invoices').select('*').eq('id', params.id).single()\n"
         "  return Response.json(data)\n}\n", []),
    "caught: Supabase's row rules do not choose the columns: everything that was sent is written":
        ("export async function PATCH (req, { params }) {\n"
         "  const session = await getServerSession(authOptions)\n"
         "  if (!session) return new Response('sign in', { status: 401 })\n"
         "  const body = await req.json()\n"
         "  await supabase.from('profiles').update(body).eq('id', session.user.id)\n"
         "  return new Response(null, { status: 204 })\n}\n", ["LT-AUTHZ-MASS-ASSIGN"]),
}


@pytest.mark.parametrize("case", sorted(NEXT_CASES))
def test_next_route_handlers(tmp_path, case):
    body, want = NEXT_CASES[case]
    fs = _scan(tmp_path, {"app/api/invoices/[id]/route.js": NEXT_HEAD + body, "lib/prisma.js": NEXT_LIB,
                          "lib/auth.js": "export const authOptions = { providers: [] }\n"},
               project={"package.json": NEXT_PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


DJANGO_PROJECT = {"requirements.txt": "django==5.0.6\n", "shop/__init__.py": "",
                  "shop/models.py": "from django.conf import settings\nfrom django.db import models\n\n\n"
                                    "class Invoice(models.Model):\n"
                                    "    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)\n"
                                    "    total = models.IntegerField()\n",
                  "shop/urls.py": "from django.urls import path\n\nfrom . import views\n\n"
                                  "urlpatterns = [path('invoices/<int:pk>/', views.invoice)]\n"}
DJANGO = ("from django.contrib.auth.decorators import login_required\nfrom django.http import Http404, JsonResponse\n"
          "from django.shortcuts import get_object_or_404\n\nfrom .models import Invoice\n\n\n")
DJANGO_CASES = {
    "caught: any signed-in person reads any invoice":
        ("@login_required\ndef invoice(request, pk):\n    inv = get_object_or_404(Invoice, pk=pk)\n"
         "    return JsonResponse({'total': inv.total})\n", ["LT-AUTHZ-OWNER"]),
    "clean: the look-up asks for the signed-in person's invoice":
        ("@login_required\ndef invoice(request, pk):\n    inv = get_object_or_404(Invoice, pk=pk, user=request.user)\n"
         "    return JsonResponse({'total': inv.total})\n", []),
    "clean: the invoice's owner is compared with the signed-in person":
        ("@login_required\ndef invoice(request, pk):\n    inv = Invoice.objects.get(pk=pk)\n"
         "    if inv.user_id != request.user.id:\n        raise Http404\n"
         "    return JsonResponse({'total': inv.total})\n", []),
    "clean: staff may read every invoice":
        ("@login_required\ndef invoice(request, pk):\n    if not request.user.is_staff:\n        raise Http404\n"
         "    inv = Invoice.objects.get(pk=pk)\n    return JsonResponse({'total': inv.total})\n", []),
}


@pytest.mark.parametrize("case", sorted(DJANGO_CASES))
def test_django_views(tmp_path, case):
    body, want = DJANGO_CASES[case]
    fs = _scan(tmp_path, {"shop/views.py": DJANGO + body}, project=DJANGO_PROJECT)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- what the finding says to a person

def test_the_story_and_the_case_of_an_ownership_finding(tmp_path):
    body, _ = OWNER["caught: the order is read by its id, and who is asking is never looked at"]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    f = next(x for x in fs if x["rule"] == "LT-AUTHZ-OWNER")
    sc = f["scenario"]
    assert sc["kind"] == "owner" and "no ready-made story" not in sc["harm"], sc
    assert any("signed in with their own account" in s for s in sc["steps"]), sc["steps"]
    assert "heuristic" in sc["harm"], sc["harm"]
    assert f["headline"] == "A signed-in person may be able to reach other people's records", f["headline"]
    case = f["case"]
    needs = {c["need"]: c["met"] for c in case["conditions"]}
    assert needs["The request chooses which record is reached"] is True, needs
    assert needs["Nothing compares the record's owner with who is signed in"] is True, needs
    assert needs["The record is one person's, not something every signed-in person may see"] is None, needs
    assert any("followed to the look-up at app/main.py:" in e["fact"] for e in case["evidence"]), case["evidence"]
    assert case["confidence"]["level"] == "low", case["confidence"]


def test_the_story_of_an_admin_route_and_of_everything_that_was_sent(tmp_path):
    body, _ = ROLE["caught: an admin page that only asks whether someone is signed in"]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    f = next(x for x in fs if x["rule"] == "LT-AUTHZ-ROLE")
    assert f["scenario"]["kind"] == "role" and f["rank"] == "medium" and f["tool_confidence"] == "LOW", f
    assert any("ordinary account" in s for s in f["scenario"]["steps"]), f["scenario"]
    assert {c["need"]: c["met"] for c in f["case"]["conditions"]}["The route is meant for admins only"] is None
    body, _ = ASSIGN["caught: every field the request sent is written onto the user"]
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=FLASK_PROJECT)
    f = next(x for x in fs if x["rule"] == "LT-AUTHZ-MASS-ASSIGN")
    assert f["scenario"]["kind"] == "mass-assign" and f["rank"] == "medium" and f["tool_confidence"] == "LOW", f
    assert any('"is_admin": true' in s for s in f["scenario"]["steps"]), f["scenario"]["steps"]
    assert f["flow"]["class"] == "assign" and f["flow"]["steps"], f["flow"]


def test_everything_that_was_sent_copied_into_an_object_first(tmp_path):
    caught = _js("  const data = {}\n  Object.assign(data, req.body)\n"
                 "  await User.findByIdAndUpdate(req.session.userId, data)\n  res.status(204).end()\n",
                 verb="put", path="/me")
    fs = _scan(tmp_path, {"server.js": JS + caught, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == ["LT-AUTHZ-MASS-ASSIGN"], [(f["rule"], f["file"], f["line"]) for f in fs]
    clean = _js("  const data = {}\n  Object.assign(data, { name: req.body.name })\n"
                "  await User.findByIdAndUpdate(req.session.userId, data)\n  res.status(204).end()\n",
                verb="put", path="/me")
    fs = _scan(tmp_path, {"server.js": JS + clean, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == [], [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- the page that signs a person in

# Signing in, signing up and asking for a new password look a person up by the name they typed, and nobody is signed
# in yet: that is the route's job, not another person's record. Found on Lantern's own teaching app (notes), whose
# fixed version was reported for its sign-in route. Each clean one stands beside a route that must still be caught.
TOKENS = ("import hashlib\nimport hmac\n\nfrom fastapi import Form, Request\n\n\n"
          "def check_password(password, password_hash):\n"
          "    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), password_hash)\n\n\n"
          "def make_token(user_id):\n    return hmac.new(b'k', str(user_id).encode(), 'sha256').hexdigest()\n\n\n"
          "def verify_token(value):\n    if not hmac.compare_digest(make_token(value.partition('.')[0]), value):\n"
          "        raise HTTPException(401)\n\n\n")
BY_NAME = "    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()\n"
SIGN_IN_BODY = (BY_NAME + "    if user is None or not check_password(password, user['password_hash']):\n"
                "        raise HTTPException(401)\n    return {'token': make_token(user['id'])}\n")
FORM_SIG = "username: str = Form(...), password: str = Form(...), db=Depends(get_db)"
SIGN_IN = {
    "clean: signing in looks a person up by the name they typed":
        (_route(SIGN_IN_BODY, sig=FORM_SIG, verb="post", path="/login"), []),
    "clean: the framework's own sign-in form":
        ("from fastapi.security import OAuth2PasswordRequestForm\n\n\n" +
         _route("    user = db.execute('SELECT * FROM users WHERE username = ?', (form.username,)).fetchone()\n"
                "    if user is None or not check_password(form.password, user['password_hash']):\n"
                "        raise HTTPException(400)\n    return {'access_token': make_token(user['id'])}\n",
                sig="form: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)", verb="post",
                path="/login/access-token"), []),
    "clean: asking for a new password by e-mail address":
        (_route("    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()\n"
                "    if user is not None:\n        log.info('reset link %s', make_token(user['id']))\n"
                "    return {'ok': True}\n", sig="email: str, db=Depends(get_db)", verb="post",
                path="/password-recovery/{email}"), []),
    "clean: signing up asks whether the name is taken":
        (_route(BY_NAME + "    if user is not None:\n        raise HTTPException(409)\n"
                "    db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password))\n"
                "    return {'token': make_token(username)}\n", sig=FORM_SIG, verb="post", path="/signup"), []),
    "caught: another person's orders, picked by their user name, behind a login":
        (_route("    return db.execute('SELECT * FROM orders WHERE username = ?', (username,)).fetchall()\n",
                sig="username: str, user=Depends(get_current_user), db=Depends(get_db)",
                path="/users/{username}/orders"), ["LT-AUTHZ-OWNER"]),
    "caught: another person's password, changed by their id, behind a login":
        (_route("    db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password, user_id))\n"
                "    return {'ok': True}\n",
                sig="user_id: int, password: str = Form(...), user=Depends(get_current_user), db=Depends(get_db)",
                verb="put", path="/users/{user_id}/password"), ["LT-AUTHZ-OWNER"]),
    "clean: an address confirmed by a code: the only sign of a login is a function that makes a token":
        (_route("    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()\n"
                "    if user is None or not hmac.compare_digest(user['code'], code):\n"
                "        raise HTTPException(400)\n    return {'token': make_token(user['id'])}\n",
                sig="user_id: int, code: str, db=Depends(get_db)", verb="post", path="/confirm"), []),
    "caught: the only sign of a login is a function that checks a token":
        (_route("    verify_token(request.headers.get('authorization', ''))\n"
                f"    return db.execute('{ONE}', (order_id,)).fetchone()\n",
                sig="order_id: int, request: Request, db=Depends(get_db)"), ["LT-AUTHZ-OWNER"]),
    "clean: the admins' own sign-in page asks for no admin":
        (_route(SIGN_IN_BODY, sig=FORM_SIG, verb="post", path="/admin/login"), []),
    "caught: an admin page that resets a person's password and asks for no admin":
        (_route("    db.execute('UPDATE users SET password_hash = ? WHERE id = ?', ('', user_id))\n"
                "    return {'ok': True}\n", sig="user_id: int, user=Depends(get_current_user), db=Depends(get_db)",
                verb="post", path="/admin/reset/{user_id}"), ["LT-AUTHZ-ROLE"]),
}


@pytest.mark.parametrize("case", sorted(SIGN_IN))
def test_a_sign_in_page_looks_a_person_up_by_the_name_they_typed(tmp_path, case):
    body, want = SIGN_IN[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + TOKENS + body})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


JS_TOKENS = ("const bcrypt = require('bcryptjs')\nconst jwt = require('jsonwebtoken')\n"
             "function signToken (user) {\n  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET)\n}\n"
             "function verifyToken (req) {\n  return jwt.verify(req.headers.authorization, process.env.JWT_SECRET)\n}\n")
JS_CHECK = ("  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) "
            "return res.status(401).end()\n")
JS_SIGN_IN = {
    "clean: signing in, the session is told who it is":
        (_js("  const user = await User.findOne({ email: req.body.email })\n" + JS_CHECK +
             "  req.session.userId = user.id\n  res.json({ ok: true })\n", mw="", verb="post", path="/login"), []),
    "clean: signing in, the app signs a token":
        (_js("  const user = await User.findOne({ name: req.body.username })\n" + JS_CHECK +
             "  res.json({ token: signToken(user) })\n", mw="", verb="post", path="/api/auth/signin"), []),
    "clean: an address confirmed by a code: the only sign of a login is a function that makes a token":
        (_js("  const user = await User.findById(req.body.id)\n"
             "  if (!user || user.code !== req.body.code) return res.status(400).end()\n"
             "  res.json({ token: signToken(user) })\n", mw="", verb="post", path="/confirm"), []),
    "caught: the only sign of a login is a function that checks the token":
        (_js("  verifyToken(req)\n  res.json(await Order.findById(req.params.id))\n", mw=""), ["LT-AUTHZ-OWNER"]),
    "caught: another person's orders, picked by their user name, behind a login":
        (_js("  res.json(await Order.findOne({ user: req.params.username }))\n", path="/users/:username/order"),
         ["LT-AUTHZ-OWNER"]),
    "clean: the admins' own sign-in page asks for no admin":
        (_js("  const user = await User.findOne({ email: req.body.email })\n" + JS_CHECK +
             "  req.session.userId = user.id\n  res.json({ ok: true })\n", mw="", verb="post", path="/admin/login"),
         []),
}


@pytest.mark.parametrize("case", sorted(JS_SIGN_IN))
def test_express_a_sign_in_page(tmp_path, case):
    body, want = JS_SIGN_IN[case]
    fs = _scan(tmp_path, {"server.js": JS + JS_TOKENS + body, "models.js": JS_MODELS},
               project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_flask_signing_in_with_a_session(tmp_path):
    body = ("from flask import session\nfrom werkzeug.security import check_password_hash\n\n\n"
            "@app.post('/login')\ndef login():\n"
            "    user = User.query.filter_by(name=request.form['username']).first()\n"
            "    if user is None or not check_password_hash(user.password_hash, request.form['password']):\n"
            "        abort(401)\n    session['user_id'] = user.id\n    return jsonify(ok=True)\n")
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=FLASK_PROJECT)
    assert _authz(fs) == [], [(f["rule"], f["file"], f["line"]) for f in fs]
    # the same look-up behind a login, on a page that is not about signing in, is somebody else's record
    body = ("@app.get('/people/<username>')\n@login_required\ndef person(username):\n"
            "    user = User.query.filter_by(name=username).first_or_404()\n    return jsonify(id=user.id)\n")
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=FLASK_PROJECT)
    assert _authz(fs) == ["LT-AUTHZ-OWNER"], [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- nobody has to be signed in, and a record is changed
# A route with no login at all was LW-AUTH-MISSING's only when a frontend in the project calls it. A record changed or
# removed there by an id from the request is anybody's to change whoever calls the route, so it is the same finding.
def _open(fs):
    return sorted((f["rule"], f["line"]) for f in fs if f["rule"] == "LW-AUTH-MISSING" or f["rule"].startswith("LT-AUTHZ"))


JS_AT = JS.count("\n") + 1          # the line of a route written right after the head
JS_ANON = {
    "caught: an order removed by its id, and nobody has to be signed in":
        (_js("  await Order.deleteOne({ _id: req.params.id })\n  res.status(204).end()\n", mw="", verb="delete"),
         [("LW-AUTH-MISSING", JS_AT)]),
    "caught: the same for a change":
        (_js("  await Order.updateOne({ _id: req.params.id }, { item: req.body.item })\n  res.end()\n", mw="",
             verb="put"), [("LW-AUTH-MISSING", JS_AT)]),
    "caught: a link that removes (GET), which no verb gives away":
        (_js("  await Order.deleteOne({ _id: req.params.id })\n  res.redirect('/orders')\n", mw="",
             path="/orders/:id/remove"), [("LW-AUTH-MISSING", JS_AT)]),
    "caught: through SQL":
        (_js("  await pool.query('DELETE FROM orders WHERE id = ?', [req.params.id])\n  res.end()\n", mw="",
             verb="delete"), [("LW-AUTH-MISSING", JS_AT)]),
    "clean: an order read by its id with nobody signed in may be a public page":
        (_js(READ, mw=""), []),
    "clean: a new record is nobody's yet (a contact form)":
        (_js("  await Order.create({ item: req.body.item })\n  res.status(201).end()\n", mw="", verb="post",
             path="/orders"), []),
    "clean: picked by a secret link, not by an id":
        (_js("  await Order.deleteOne({ shareToken: req.params.token })\n  res.end()\n", mw="", verb="delete",
             path="/shares/:token"), []),
    "clean: a path made to be called without a login":
        (_js("  await Order.updateOne({ _id: req.body.id }, { paid: true })\n  res.end()\n", mw="", verb="post",
             path="/webhook/orders"), []),
    "clean of this finding: somebody is signed in, so it is the owner that is missing":
        (_js("  await Order.deleteOne({ _id: req.params.id })\n  res.status(204).end()\n", verb="delete"),
         [("LT-AUTHZ-OWNER", JS_AT + 1)]),      # on the line the order is removed (until round 3: on the route's)
}


@pytest.mark.parametrize("case", sorted(JS_ANON))
def test_express_a_record_changed_with_nobody_signed_in(tmp_path, case):
    body, want = JS_ANON[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _open(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


PY_AT = FASTAPI.count("\n") + 2     # the `def` line of a route written right after the head
ANON_SIG = "order_id: int, db=Depends(get_db)"
PY_ANON = {     # the finding is where the route begins (its decorator), as for a route the frontend calls
    "caught: an order removed by its id, and nobody has to be signed in":
        (_route("    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {'ok': True}\n",
                sig=ANON_SIG, verb="delete"), [("LW-AUTH-MISSING", PY_AT - 1)]),
    "caught: the same for a change":
        (_route("    db.execute('UPDATE orders SET paid = 1 WHERE id = ?', (order_id,))\n    return {'ok': True}\n",
                sig=ANON_SIG, verb="post"), [("LW-AUTH-MISSING", PY_AT - 1)]),
    "clean: read by its id with nobody signed in":
        (_route(f"    return db.execute('{ONE}', (order_id,)).fetchone()\n", sig=ANON_SIG), []),
    "clean: a new row":
        (_route("    db.execute('INSERT INTO orders (item) VALUES (?)', (item,))\n    return {'ok': True}\n",
                sig="item: str, db=Depends(get_db)", verb="post", path="/orders"), []),
    "clean of this finding: somebody is signed in":
        (_route("    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {'ok': True}\n",
                verb="delete"), [("LT-AUTHZ-OWNER", PY_AT + 1)]),     # on the line of the DELETE, as above
}


@pytest.mark.parametrize("case", sorted(PY_ANON))
def test_a_record_changed_with_nobody_signed_in(tmp_path, case):
    body, want = PY_ANON[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    assert _open(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_a_route_the_frontend_calls_and_that_changes_a_record_gets_one_finding(tmp_path):
    fs = _scan(tmp_path, {
        "server.js": JS + _js("  await Order.deleteOne({ _id: req.params.id })\n  res.status(204).end()\n", mw="",
                              verb="delete") + "app.listen(3000)\n",
        "models.js": JS_MODELS,
        "web/app.js": "export async function remove(id) { await fetch('/orders/' + id, {method: 'DELETE'}) }\n"},
        project={"package.json": PACKAGE})
    got = [f for f in fs if f["rule"] == "LW-AUTH-MISSING"]
    assert [(f["file"], f["line"]) for f in got] == [("server.js", JS_AT)]
    assert got[0]["title"] == "DELETE /orders/:id changes data, is called by the app, and no login check was found"


def test_the_finding_for_an_open_route_says_which_record_and_ranks_medium(tmp_path):
    fs = _scan(tmp_path, {"server.js": JS + _js("  await Order.deleteOne({ _id: req.params.id })\n"
                                                "  res.status(204).end()\n", mw="", verb="delete"),
                          "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    (f,) = [f for f in fs if f["rule"] == "LW-AUTH-MISSING"]
    assert f["title"] == ("DELETE /orders/:id changes or removes a record picked by an id from the request, and no "
                          "login check was found")
    assert (f["tool_confidence"], f["rank"], f["cwe"]) == ("LOW", "medium", 306)
    assert f["flow"]["sink"] == {"file": "server.js", "line": JS_AT + 1,
                                 "what": "Order.deleteOne()"}, f["flow"]["sink"]
    assert f["flow"]["source"]["what"] == "`id` in `req.params` is what the request sent"
    assert "If this route is meant to be open to everyone" in f["more_info"]


# ------------------------------------------------------------- what a visitor may do, decided on what the visitor sends
# `admin=true` in a cookie, `X-Role: admin` in a header, `?admin=1`: the visitor writes those. A route that decides on
# one, with no role of the signed-in person asked anywhere, lets anybody say they are an admin.
LIST = "  res.json(await User.find())\n"
NO = "return res.status(403).end()\n"
JS_CLIENT = {
    "caught: a cookie that says admin":
        (_js(f"  if (req.cookies.admin !== 'true') {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: a cookie that names the role":
        (_js(f"  if (req.cookies.role !== 'admin') {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: a header":
        (_js(f"  if (req.headers['x-admin'] !== '1') {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: kept under a name first":
        (_js(f"  const isAdmin = req.cookies.isAdmin === 'true'\n  if (!isAdmin) {NO}" + LIST, path="/reports"),
         ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: only asked whether it is there":
        (_js(f"  if (!req.cookies.isAdmin) {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: written in the address":
        (_js(f"  if (req.query.admin !== '1') {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: a cookie that names the person, compared with the word admin":
        (_js(f"  if (req.cookies.user !== 'admin') {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: asked by a helper":
        ("function isAdmin (req) {\n  return req.cookies.admin === 'true'\n}\n" +
         _js(f"  if (!isAdmin(req)) {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: asked by a middleware handed to the route":
        (f"function adminOnly (req, res, next) {{\n  if (req.cookies.admin !== 'true') {NO}  next()\n}}\n" +
         _js(LIST, mw="requireLogin, adminOnly, ", path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught once: on an admin path it is this finding, not the one for a path where nothing is asked":
        (_js(f"  if (req.cookies.admin !== 'true') {NO}" + LIST, path="/admin/users"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: also where nobody has to be signed in":
        (_js(f"  if (req.cookies.admin !== 'true') {NO}" + LIST, mw="", path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "clean: the role is the session's":
        (_js(f"  if (req.session.role !== 'admin') {NO}" + LIST, path="/reports"), []),
    "clean: a cookie the server signed":
        (_js(f"  if (req.signedCookies.role !== 'admin') {NO}" + LIST, path="/reports"), []),
    "clean: a token the server checks first":
        ("const jwt = require('jsonwebtoken')\n" +
         _js("  const claims = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n"
             f"  if (claims.role !== 'admin') {NO}" + LIST, path="/reports"), []),
    "clean: a role in the address picks which list is shown":
        (_js("  res.json(await User.find({ role: req.query.role }))\n", path="/people"), []),
    "clean: a role in the address, in a condition, is still a filter":
        (_js("  const list = req.query.role === 'admin' ? await User.find({ role: 'admin' }) : await User.find()\n"
             "  res.json(list)\n", path="/people"), []),
    "clean: the signed-in person's role is asked as well":
        (_js(f"  if (req.session.role !== 'admin') {NO}  if (req.cookies.admin === 'compact') return res.json([])\n"
             + LIST, path="/reports"), []),
    "clean: a secret the caller must know is not a claim":
        (_js(f"  if (req.headers['x-api-key'] !== process.env.REPORTS_KEY) {NO}" + LIST, path="/reports"), []),
    "clean: a cookie that keeps a choice of the screen":
        (_js("  if (req.cookies.theme === 'dark') res.set('X-Theme', 'dark')\n"
             "  if (req.cookies.tab === 'admin') res.set('X-Tab', 'admin')\n" + LIST, path="/people"), []),
    "caught: looked up in a list of roles":
        (_js(f"  if (!['admin', 'staff'].includes(req.cookies.role)) {NO}" + LIST, path="/reports"),
         ["LT-AUTHZ-CLIENT-ROLE"]),
    "clean: looked up in a list of screens":
        (_js("  if (!['grid', 'list'].includes(req.cookies.view)) return res.status(400).end()\n" + LIST,
             path="/people"), []),
    "caught: a header read with req.get":
        (_js(f"  if (req.get('X-Admin') !== 'yes') {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: taken out of the cookies by name":
        (_js(f"  const {{ admin }} = req.cookies\n  if (admin !== 'true') {NO}" + LIST, path="/reports"),
         ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: the role cookie under another spelling":
        (_js(f"  if (req.cookies.userRole !== 'ADMIN') {NO}" + LIST, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: decided in one expression":
        (_js("  const list = req.cookies.isAdmin === 'true' ? await User.find() : []\n  res.json(list)\n",
             path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: written in the body, and the request is turned away without it":
        (_js(f"  if (!req.body.admin) {NO}" + LIST, path="/reports", verb="post"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: written in the address, and the other branch turns the request away":
        (_js("  if (req.query.admin === '1') {\n  " + LIST + "  } else {\n    res.status(403).end()\n  }\n",
             path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "clean: the address says admin and the request is turned away for it":
        (_js(f"  if (req.query.admin) {NO}" + LIST, path="/reports"), []),
    "clean: a word in the address picks a filter":
        (_js("  let q = {}\n  if (req.query.admin === '1') q = { admin: true }\n  res.json(await User.find(q))\n",
             path="/people"), []),
    "clean: a cookie named admin compared with a secret of the server's":
        (_js(f"  if (req.cookies.admin !== process.env.ADMIN_COOKIE) {NO}" + LIST, path="/reports"), []),
    "clean: whether any cookie came at all":
        (_js("  if (!req.cookies) return res.status(400).end()\n" + LIST, path="/people"), []),
    "clean: a role in the body that the sign-up page refuses":
        (_js("  if (req.body.role === 'admin') return res.status(403).end()\n"
             "  res.json(await User.create({ name: req.body.name }))\n", path="/people", verb="post", mw=""), []),
}


@pytest.mark.parametrize("case", sorted(JS_CLIENT))
def test_express_a_visitor_who_says_they_are_an_admin(tmp_path, case):
    body, want = JS_CLIENT[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


NAMES = "    return jsonify([u.name for u in User.query.all()])\n"
FLASK_CLIENT = {
    "caught: a cookie that says admin":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if request.cookies.get('admin') != '1':\n        abort(403)\n" + NAMES, ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: a header that names the role":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if request.headers.get('X-Role') != 'admin':\n        abort(403)\n" + NAMES, ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: written in the address, and only asked whether it is there":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if not request.args.get('admin'):\n        abort(403)\n" + NAMES, ["LT-AUTHZ-CLIENT-ROLE"]),
    "clean: the session says it":
        ("from flask import session\n\n\n@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if session.get('role') != 'admin':\n        abort(403)\n" + NAMES, []),
    "clean: the signed-in person is asked":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if not current_user.is_admin:\n        abort(403)\n" + NAMES, []),
    "clean: a page number in the address":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if not request.args.get('page'):\n        abort(400)\n" + NAMES, []),
    "caught: not among the roles in a tuple":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if request.cookies.get('role') not in ('admin', 'staff'):\n        abort(403)\n" + NAMES,
         ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: asked by a decorator of the project's own":
        ("from functools import wraps\n\n\ndef admin_cookie(view):\n    @wraps(view)\n    def inner(*a, **kw):\n"
         "        if request.cookies.get('admin') != '1':\n            abort(403)\n        return view(*a, **kw)\n"
         "    return inner\n\n\n@app.get('/reports')\n@login_required\n@admin_cookie\ndef reports():\n" + NAMES,
         ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: asked in a hook that runs before every route":
        ("@app.before_request\ndef gate():\n    if request.path.startswith('/reports') and "
         "request.headers.get('X-Admin') != '1':\n        abort(403)\n\n\n"
         "@app.get('/reports')\n@login_required\ndef reports():\n" + NAMES, ["LT-AUTHZ-CLIENT-ROLE"]),
    "clean: a cookie compared with a setting of the app":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    if request.cookies.get('admin') != app.config['ADMIN_COOKIE']:\n        abort(403)\n" + NAMES, []),
    "clean: a word in the address picks a filter":
        ("@app.get('/reports')\n@login_required\ndef reports():\n"
         "    q = User.query\n    if request.args.get('admin'):\n        q = q.filter_by(admin=True)\n"
         "    return jsonify([u.name for u in q.all()])\n", []),
}


@pytest.mark.parametrize("case", sorted(FLASK_CLIENT))
def test_flask_a_visitor_who_says_they_are_an_admin(tmp_path, case):
    body, want = FLASK_CLIENT[case]
    fs = _scan(tmp_path, {"app/main.py": FLASK + body}, project=FLASK_PROJECT)
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


EVERYONE = "    return db.execute('SELECT id, email FROM users').fetchall()\n"
SIGNED = "user=Depends(get_current_user), db=Depends(get_db)"
FASTAPI_CLIENT = {
    "caught: a cookie handed in as a parameter":
        ("from fastapi import Cookie\n\n\n" + _route(
            "    if is_admin != '1':\n        raise HTTPException(403)\n" + EVERYONE,
            sig="is_admin: str = Cookie('0'), " + SIGNED, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: a header handed in as a parameter":
        (_route("    if x_role != 'admin':\n        raise HTTPException(403)\n" + EVERYONE,
                sig="x_role: str = Header(None), " + SIGNED, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "caught: a yes or no in the address":
        (_route("    if not admin:\n        raise HTTPException(403)\n" + EVERYONE,
                sig="admin: bool = False, " + SIGNED, path="/reports"), ["LT-AUTHZ-CLIENT-ROLE"]),
    "clean: the signed-in person is asked":
        (_route("    if not user['is_admin']:\n        raise HTTPException(403)\n" + EVERYONE, sig=SIGNED,
                path="/reports"), []),
    "clean: a yes or no in the address that picks what is listed":
        (_route("    if active:\n        return db.execute('SELECT id FROM users WHERE active = 1').fetchall()\n"
                + EVERYONE, sig="active: bool = False, " + SIGNED, path="/people"), []),
}


@pytest.mark.parametrize("case", sorted(FASTAPI_CLIENT))
def test_fastapi_a_visitor_who_says_they_are_an_admin(tmp_path, case):
    body, want = FASTAPI_CLIENT[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_the_finding_names_the_value_the_visitor_sends_and_where_it_is_read(tmp_path):
    body = (f"function adminOnly (req, res, next) {{\n  if (req.cookies.admin !== 'true') {NO}  next()\n}}\n" +
            _js(LIST, mw="requireLogin, adminOnly, ", path="/reports") +
            _js(LIST, mw="requireLogin, adminOnly, ", path="/exports"))
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    (f,) = [f for f in fs if f["rule"] == "LT-AUTHZ-CLIENT-ROLE"]          # one place, two routes: one finding
    assert (f["file"], f["line"]) == ("server.js", JS_AT + 1)               # where the cookie is read
    assert f["title"] == ("GET /exports and 1 more route decide what the caller may do from a cookie the caller "
                          "sends (`admin`)"), f["title"]
    assert (f["tool_confidence"], f["rank"], f["cwe"], f["tool"]) == ("LOW", "medium", 807, "lantern-flow")
    assert f["headline"] == "A visitor can say they are an admin"
    assert "GET /reports" in f["more_info"] and "GET /exports" in f["more_info"]


# ------------------------------------------------------------- the id of a record inside a body described by a class
PICK = "from pydantic import BaseModel\n\n\nclass Pick(BaseModel):\n    order_id: int\n    note: str = ''\n\n\n"
SHOW = dict(sig="pick: Pick, user=Depends(get_current_user), db=Depends(get_db)", verb="post", path="/orders/show")
BODY_CLASS = {
    "caught: the order's id is a field of the body":
        (PICK + _route(f"    return db.execute('{ONE}', (pick.order_id,)).fetchone()\n", **SHOW), ["LT-AUTHZ-OWNER"]),
    "clean: the query asks for the caller's own order":
        (PICK + _route(f"    return db.execute('{MINE}', (pick.order_id, user['id'])).fetchone()\n", **SHOW), []),
    "clean: a note in the body picks no one's record":
        (PICK + _route("    return db.execute('SELECT * FROM orders WHERE note = ?', (pick.note,)).fetchall()\n",
                       **SHOW), []),
    "caught: the parameter is named req":
        (PICK + _route(f"    return db.execute('{ONE}', (req.order_id,)).fetchone()\n",
                       **dict(SHOW, sig="req: Pick, user=Depends(get_current_user), db=Depends(get_db)")),
         ["LT-AUTHZ-OWNER"]),
    "caught: a base class of the project's own in between":
        ("from pydantic import BaseModel\n\n\nclass Strict(BaseModel):\n    pass\n\n\nclass Pick(Strict):\n"
         "    order_id: int\n\n\n" + _route(f"    return db.execute('{ONE}', (pick.order_id,)).fetchone()\n", **SHOW),
         ["LT-AUTHZ-OWNER"]),
    "caught: the order is removed by the id in the body":
        (PICK + _route("    db.execute('DELETE FROM orders WHERE id = ?', (pick.order_id,))\n    return {'ok': True}\n",
                       **SHOW), ["LT-AUTHZ-OWNER"]),
}


@pytest.mark.parametrize("case", sorted(BODY_CLASS))
def test_a_record_picked_by_an_id_in_a_body_class(tmp_path, case):
    body, want = BODY_CLASS[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_a_body_class_kept_in_another_file(tmp_path):
    fs = _scan(tmp_path, {"app/schemas.py": PICK,
                          "app/main.py": FASTAPI + "from . import schemas\nfrom .schemas import Pick\n\n\n" + _route(
                              f"    return db.execute('{ONE}', (pick.order_id,)).fetchone()\n", **SHOW) + "\n\n" + _route(
                              f"    return db.execute('{ONE}', (pick.order_id,)).fetchone()\n",
                              **dict(SHOW, sig="pick: schemas.Pick, user=Depends(get_current_user), db=Depends(get_db)",
                                     path="/orders/peek")).replace("def handle", "def peek")})
    assert _authz(fs) == ["LT-AUTHZ-OWNER", "LT-AUTHZ-OWNER"], [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- a helper that changes a record and only then checks
# What a route asked before a record is changed or removed is what counts; that holds inside a function the route
# calls as it does in the route's own lines.
GONE = "    db.execute('DELETE FROM orders WHERE id = ?', (oid,))\n    db.commit()\n"
READ_ROW = f"    row = db.execute('{ONE}', (oid,)).fetchone()\n"
NOT_MINE = "    if row is None or row['user_id'] != user['id']:\n        raise HTTPException(403)\n"
CALLS = _route("    remove(db, order_id, user)\n    return {'ok': True}\n", verb="delete")
LATE = {
    "caught: the helper removes the order and only then compares its owner":
        ("def remove(db, oid, user):\n" + READ_ROW + GONE + NOT_MINE + "\n\n" + CALLS, ["LT-AUTHZ-OWNER"]),
    "clean: the helper compares the owner, then removes the order":
        ("def remove(db, oid, user):\n" + READ_ROW + NOT_MINE + GONE + "\n\n" + CALLS, []),
    "caught: two helpers deep, the inner one removes and the outer one compares afterwards":
        ("def drop(db, oid):\n" + GONE + "\n\ndef remove(db, oid, user):\n" + READ_ROW + "    drop(db, oid)\n" +
         NOT_MINE + "\n\n" + CALLS, ["LT-AUTHZ-OWNER"]),
    "clean: two helpers deep, the outer one compares first":
        ("def drop(db, oid):\n" + GONE + "\n\ndef remove(db, oid, user):\n" + READ_ROW + NOT_MINE +
         "    drop(db, oid)\n\n\n" + CALLS, []),
    "caught: the route compares only after the helper has removed the order":
        ("def drop(db, oid):\n" + GONE + "\n\n" + _route(
            f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n    drop(db, order_id)\n"
            "    if row is None or row['user_id'] != user['id']:\n        raise HTTPException(403)\n"
            "    return {'ok': True}\n", verb="delete"), ["LT-AUTHZ-OWNER"]),
    "clean: the route compares, then the helper removes":
        ("def drop(db, oid):\n" + GONE + "\n\n" + _route(
            f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n"
            "    if row is None or row['user_id'] != user['id']:\n        raise HTTPException(403)\n"
            "    drop(db, order_id)\n    return {'ok': True}\n", verb="delete"), []),
    "caught: one helper checks, but it is called after the one that removes":
        ("def drop(db, oid):\n" + GONE + "\n\ndef mine(db, oid, user):\n" + READ_ROW + NOT_MINE + "\n\n" + _route(
            "    drop(db, order_id)\n    mine(db, order_id, user)\n    return {'ok': True}\n", verb="delete"),
         ["LT-AUTHZ-OWNER"]),
    "clean: the helper that checks is called first":
        ("def drop(db, oid):\n" + GONE + "\n\ndef mine(db, oid, user):\n" + READ_ROW + NOT_MINE + "\n\n" + _route(
            "    mine(db, order_id, user)\n    drop(db, order_id)\n    return {'ok': True}\n", verb="delete"), []),
}


@pytest.mark.parametrize("case", sorted(LATE))
def test_what_was_asked_before_a_helper_changed_the_record(tmp_path, case):
    body, want = LATE[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


JS_GONE = "  await Order.deleteOne({ _id: id })\n"
JS_NOT_MINE = "  if (!order || String(order.user) !== String(user.id)) throw new Error('not yours')\n"
JS_CALLS = _js("  await remove(req.params.id, req.user)\n  res.status(204).end()\n", verb="delete")
JS_LATE = {
    "caught: the helper removes the order and only then compares its owner":
        ("async function remove (id, user) {\n  const order = await Order.findById(id)\n" + JS_GONE + JS_NOT_MINE +
         "}\n" + JS_CALLS, ["LT-AUTHZ-OWNER"]),
    "clean: the helper compares the owner, then removes the order":
        ("async function remove (id, user) {\n  const order = await Order.findById(id)\n" + JS_NOT_MINE + JS_GONE +
         "}\n" + JS_CALLS, []),
    "caught: the helper reads the request itself, removes, then compares":
        ("async function remove (req) {\n  const order = await Order.findById(req.params.id)\n"
         "  await Order.deleteOne({ _id: req.params.id })\n"
         "  if (!order || order.user !== req.session.userId) throw new Error('not yours')\n}\n" +
         _js("  await remove(req)\n  res.status(204).end()\n", verb="delete"), ["LT-AUTHZ-OWNER"]),
    "clean: the helper reads the request itself, compares, then removes":
        ("async function remove (req) {\n  const order = await Order.findById(req.params.id)\n"
         "  if (!order || order.user !== req.session.userId) throw new Error('not yours')\n"
         "  await Order.deleteOne({ _id: req.params.id })\n}\n" +
         _js("  await remove(req)\n  res.status(204).end()\n", verb="delete"), []),
}


@pytest.mark.parametrize("case", sorted(JS_LATE))
def test_express_what_was_asked_before_a_helper_changed_the_record(tmp_path, case):
    body, want = JS_LATE[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- a database helper of the project's own
# route -> service -> `db.query(text, values)`: the helper runs whatever text it is handed, so the function that
# writes the text says which record is reached, and who is signed in among the values it hands over makes the
# record that person's own, exactly as it does on `conn.execute(text, values)` itself. (Added 2026-11-11 with the
# fix: until then every query that went through such a helper was reported, the caller's own order too.)
DB_HELPER = ("import sqlite3\n\n\n"
             "def query(sql, params=()):\n    conn = sqlite3.connect('app.db')\n    conn.row_factory = sqlite3.Row\n"
             "    rows = conn.execute(sql, params).fetchall()\n    conn.close()\n    return [dict(r) for r in rows]\n\n\n"
             "def one(sql, params=()):\n    rows = query(sql, params)\n    return rows[0] if rows else None\n\n\n"
             "def run(sql, params=()):\n    conn = sqlite3.connect('app.db')\n    conn.execute(sql, params)\n"
             "    conn.commit()\n    conn.close()\n\n\n"
             "def first(sql, *params):\n    conn = sqlite3.connect('app.db')\n"
             "    return conn.execute(sql, params).fetchone()\n")
SVC = "from . import db\n\n\n"
VIA_SIG = "order_id: int, user=Depends(get_current_user)"
PLAIN = _route("    return service.get_order(order_id)\n", sig=VIA_SIG)
WITH_ID = _route("    return service.get_order(order_id, user['id'])\n", sig=VIA_SIG)
VIA_HELPER = {
    "caught: the service asks the helper for the order by its id alone":
        (PLAIN, SVC + f"def get_order(order_id):\n    return db.one('{ONE}', (order_id,))\n", ["LT-AUTHZ-OWNER"]),
    "clean: the service hands the helper who is asking among the values":
        (WITH_ID, SVC + f"def get_order(order_id, user_id):\n    return db.one('{MINE}', (order_id, user_id))\n", []),
    "clean: the same through the helper the other helper calls":
        (WITH_ID, SVC + f"def get_order(order_id, user_id):\n    rows = db.query('{MINE}', (order_id, user_id))\n"
                        "    return rows[0] if rows else None\n", []),
    "clean: the values as a list":
        (WITH_ID, SVC + f"def get_order(order_id, user_id):\n    return db.one('{MINE}', [order_id, user_id])\n", []),
    "clean: the values by name":
        (WITH_ID, SVC + "def get_order(order_id, user_id):\n"
                        "    return db.one('SELECT * FROM orders WHERE id = :id AND user_id = :uid',\n"
                        "                  {'id': order_id, 'uid': user_id})\n", []),
    "clean: the values one by one":
        (WITH_ID, SVC + f"def get_order(order_id, user_id):\n    return db.first('{MINE}', order_id, user_id)\n", []),
    "caught: one by one, and who is asking is not among them":
        (PLAIN, SVC + f"def get_order(order_id):\n    return db.first('{ONE}', order_id)\n", ["LT-AUTHZ-OWNER"]),
    "clean: the helper's name is imported on its own":
        (WITH_ID, f"from .db import one\n\n\ndef get_order(order_id, user_id):\n"
                  f"    return one('{MINE}', (order_id, user_id))\n", []),
    "clean: the query's text is a constant of the file":
        (WITH_ID, SVC + f"MINE = '{MINE}'\n\n\ndef get_order(order_id, user_id):\n"
                        "    return db.one(MINE, (order_id, user_id))\n", []),
    "clean: the route hands the service the signed-in person, the service takes the id out":
        (_route("    return service.get_order(order_id, user)\n", sig=VIA_SIG),
         SVC + f"def get_order(order_id, user):\n    return db.one('{MINE}', (order_id, user['id']))\n", []),
    "caught: the service is told who is asking and leaves it out of the values":
        (WITH_ID, SVC + f"def get_order(order_id, user_id):\n    return db.one('{ONE}', (order_id,))\n",
         ["LT-AUTHZ-OWNER"]),
    "caught: who is asking goes into the log's row, the order is read without it":
        (WITH_ID, SVC + "def get_order(order_id, user_id):\n"
                        "    db.run('INSERT INTO views (order_id, user_id) VALUES (?, ?)', (order_id, user_id))\n"
                        f"    return db.one('{ONE}', (order_id,))\n", ["LT-AUTHZ-OWNER"]),
    "clean: the service compares the owner of what the helper gave back":
        (WITH_ID, SVC + f"def get_order(order_id, user_id):\n    order = db.one('{ONE}', (order_id,))\n"
                        "    if order is None or order['user_id'] != user_id:\n        return None\n"
                        "    return order\n", []),
    "clean: the route compares the owner of what the service gave back":
        (_route("    order = service.get_order(order_id)\n"
                "    if order is None or order['user_id'] != user['id']:\n        raise HTTPException(404)\n"
                "    return order\n", sig=VIA_SIG),
         SVC + f"def get_order(order_id):\n    return db.one('{ONE}', (order_id,))\n", []),
    "caught: removed through the helper by anyone who is signed in":
        (_route("    service.delete_order(order_id)\n    return {'ok': True}\n", sig=VIA_SIG, verb="delete"),
         SVC + "def delete_order(order_id):\n    db.run('DELETE FROM orders WHERE id = ?', (order_id,))\n",
         ["LT-AUTHZ-OWNER"]),
    "clean: removed through the helper, the caller's own only":
        (_route("    service.delete_order(order_id, user['id'])\n    return {'ok': True}\n", sig=VIA_SIG,
                verb="delete"),
         SVC + "def delete_order(order_id, user_id):\n"
               "    db.run('DELETE FROM orders WHERE id = ? AND user_id = ?', (order_id, user_id))\n", []),
}


@pytest.mark.parametrize("case", sorted(VIA_HELPER))
def test_a_query_that_goes_through_a_database_helper_of_the_project(tmp_path, case):
    route, service, want = VIA_HELPER[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + "from . import service\n\n\n" + route, "app/service.py": service,
                          "app/db.py": DB_HELPER})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- Express: where the login is put, and what makes it
# A login for every path put on with `all`, a login made by a library call, a check with a plain name that turns away
# whoever is not signed in, and a caller that has to send a secret only the server holds. Each beside what looks the
# same and is not: `all` on another path or after the route, a library that signs nobody in, a token that is asked
# for only when one was sent, a secret compared with nothing refused.
def _gates(fs):
    return sorted(f["rule"] for f in fs if f["rule"] == "LW-AUTH-MISSING" or f["rule"].startswith("LT-AUTHZ"))


def _refuse(name, cond, code=401):
    return f"function {name} (req, res, next) {{\n  if ({cond}) return res.status({code}).end()\n  next()\n}}\n"


def _mine(by):
    return f"  await Order.deleteOne({{ _id: req.params.id, user: {by} }})\n  res.status(204).end()\n"


EX_DELETE = "  await Order.deleteOne({ _id: req.params.id })\n  res.status(204).end()\n"
EX_ROUTE = _js(EX_DELETE, mw="", verb="delete")
EX_JWT = ("const { expressjwt } = require('express-jwt')\n"
          "const checkJwt = expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] })\n")
EX_MAYBE = ("const { expressjwt } = require('express-jwt')\nconst maybe = expressjwt({ secret: process.env.JWT_SECRET, "
            "algorithms: ['HS256'], credentialsRequired: false })\n")
EX_PLACED = {
    "all: a login for every path, the owner is what is missing":
        ("app.all('*', requireLogin)\n" + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "all: written after the route, nobody is signed in there":
        (EX_ROUTE + "app.all('*', requireLogin)\n", ["LW-AUTH-MISSING"]),
    "all: on everything under the path the route is under":
        ("app.all('/orders/*', requireLogin)\n" + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "all: on another path, and the login is not itself a route that should ask for an admin":
        ("app.all('/admin/*', requireLogin)\n" + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "all: what is put on only writes a line in the log":
        ("function logIt (req, res, next) {\n  console.log(req.path)\n  next()\n}\napp.all('*', logIt)\n" + EX_ROUTE,
         ["LW-AUTH-MISSING"]),
    "all: a login for every path and the delete names the owner":
        ("app.all('*', requireLogin)\n" + _js(_mine("req.session.userId"), mw="", verb="delete"), []),
    "all: a handler for every verb of a path stays a route, and it removes a record for anybody":
        ("app.all('/orders/:id', async (req, res) => {\n" + EX_DELETE + "})\n", ["LW-AUTH-MISSING"]),
    "all: an admin page under a login put on with all asks for no admin":
        ("app.all('*', requireLogin)\n" + _js("  res.json(await User.find())\n", mw="", path="/admin/users"),
         ["LT-AUTHZ-ROLE"]),
    "all: the admin check is put on the admin pages with all":
        (_refuse("requireAdmin", "req.session.role !== 'admin'", 403) + "app.all('*', requireLogin)\n"
         "app.all('/admin/*', requireAdmin)\n" + _js("  res.json(await User.find())\n", mw="", path="/admin/users"),
         []),
    "library: express-jwt put on the app, the owner is what is missing":
        (EX_JWT + "app.use(checkJwt)\n" + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "library: express-jwt made in the use line itself":
        ("const { expressjwt } = require('express-jwt')\n"
         "app.use(expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] }))\n" + EX_ROUTE,
         ["LT-AUTHZ-OWNER"]),
    "library: express-jwt on the route":
        (EX_JWT + _js(EX_DELETE, mw="checkJwt, ", verb="delete"), ["LT-AUTHZ-OWNER"]),
    "library: express-jwt made in the route's own line":
        ("const { expressjwt } = require('express-jwt')\n"
         + _js(EX_DELETE, mw="expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] }), ",
               verb="delete"), ["LT-AUTHZ-OWNER"]),
    "library: express-jwt and the delete names who the token says is calling":
        (EX_JWT + "app.use(checkJwt)\n" + _js(_mine("req.auth.sub"), mw="", verb="delete"), []),
    "library: express-jwt that lets a request with no token through signs nobody in":
        ("const { expressjwt } = require('express-jwt')\n"
         "app.use(expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'], credentialsRequired: false }))\n"
         + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "library: the same kept in a name and put on the route":
        (EX_MAYBE + _js(EX_DELETE, mw="maybe, ", verb="delete"), ["LW-AUTH-MISSING"]),
    "library: the same kept in a name and put on the app":
        (EX_MAYBE + "app.use(maybe)\n" + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "library: the same made in the line of a route whose handler has a name":
        ("const { expressjwt } = require('express-jwt')\nasync function removeOrder (req, res) {\n" + EX_DELETE
         + "}\napp.delete('/orders/:id', expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'], "
           "credentialsRequired: false }), removeOrder)\n", ["LW-AUTH-MISSING"]),
    "library: a sign-in service asked not to require a login":
        ("const { auth } = require('express-openid-connect')\n"
         "app.use(auth({ authRequired: false, secret: process.env.OIDC_SECRET }))\n" + EX_ROUTE,
         ["LW-AUTH-MISSING"]),
    "library: the same service left to require one":
        ("const { auth } = require('express-openid-connect')\n"
         "app.use(auth({ secret: process.env.OIDC_SECRET }))\n" + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "library: cors, helmet, a rate limit and a cookie parser sign nobody in":
        ("const cors = require('cors')\nconst helmet = require('helmet')\n"
         "const rateLimit = require('express-rate-limit')\nconst cookieParser = require('cookie-parser')\n"
         "app.use(cors())\napp.use(helmet())\napp.use(rateLimit({ windowMs: 60000, max: 30 }))\n"
         "app.use(cookieParser())\n" + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "library: a package named for tokens that only reads one, with a function named decode":
        ("const { decode } = require('jwt-decode-middleware')\napp.use(decode())\n" + EX_ROUTE,
         ["LW-AUTH-MISSING"]),
    "library: basic auth with one password, the admin's, kept by the server":
        ("const basicAuth = require('express-basic-auth')\n"
         "app.use(basicAuth({ users: { admin: process.env.ADMIN_PASSWORD } }))\n" + EX_ROUTE, []),
    "library: basic auth with a list of people, any of whom removes any order":
        ("const basicAuth = require('express-basic-auth')\nconst people = require('./people.json')\n"
         "app.use(basicAuth({ users: people }))\n" + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "plain name: a check called restrict that turns away whoever has no session":
        (_refuse("restrict", "!req.session.userId") + _js(EX_DELETE, mw="restrict, ", verb="delete"),
         ["LT-AUTHZ-OWNER"]),
    "plain name: the same check, and an order read by its id":
        (_refuse("restrict", "!req.session.userId") + _js(READ, mw="restrict, "), ["LT-AUTHZ-OWNER"]),
    "plain name: the same check, and the order is the caller's own":
        (_refuse("restrict", "!req.session.userId")
         + _js("  res.json(await Order.findOne({ _id: req.params.id, user: req.session.userId }))\n",
               mw="restrict, "), []),
    "plain name: let through when signed in, sent to the sign-in page otherwise":
        ("function restrict (req, res, next) {\n  if (req.session.userId) return next()\n"
         "  res.redirect('/login')\n}\n" + _js(READ, mw="restrict, "), ["LT-AUTHZ-OWNER"]),
    "plain name: with an else":
        ("function restrict (req, res, next) {\n  if (req.session.userId) {\n    next()\n  } else {\n"
         "    res.status(401).json({ error: 'sign in first' })\n  }\n}\n" + _js(READ, mw="restrict, "),
         ["LT-AUTHZ-OWNER"]),
    "plain name: the handler itself turns away whoever has no session":
        (_js("  if (!req.session.userId) return res.status(401).end()\n" + READ, mw=""), ["LT-AUTHZ-OWNER"]),
    "plain name: a check called restrict that looks at the session and refuses nobody":
        ("function restrict (req, res, next) {\n  if (!req.session.userId) console.log('a visitor')\n  next()\n}\n"
         + _js(EX_DELETE, mw="restrict, ", verb="delete"), ["LW-AUTH-MISSING"]),
    "plain name: it refuses a request with no cart, which is nobody's name":
        (_refuse("restrict", "!req.session.cart", 400) + _js(EX_DELETE, mw="restrict, ", verb="delete"),
         ["LW-AUTH-MISSING"]),
    "plain name: it refuses a request whose body names no user, which the visitor writes":
        (_refuse("restrict", "!req.body.userId", 400) + _js(EX_DELETE, mw="restrict, ", verb="delete"),
         ["LW-AUTH-MISSING"]),
    "plain name: an order read by its id with no check at all may be a public page":
        (_js(READ, mw=""), []),
}


@pytest.mark.parametrize("case", sorted(EX_PLACED))
def test_express_where_the_login_is_put_and_what_makes_it(tmp_path, case):
    text, want = EX_PLACED[case]
    fs = _scan(tmp_path, {"server.js": JS + text, "models.js": JS_MODELS, "people.json": "{}\n"},
               project={"package.json": PACKAGE})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_express_a_login_put_on_a_router_with_all(tmp_path):
    files = {"server.js": JS + "app.use('/api', require('./routes/orders'))\n", "lib/guard.js": JS_GUARD,
             "models.js": JS_MODELS,
             "routes/orders.js": JS_ROUTER + "router.all('*', requireLogin)\n" + ROUTER_READ}
    fs = _scan(tmp_path, files, project={"package.json": PACKAGE})
    assert _gates(fs) == ["LT-AUTHZ-OWNER"], [(f["rule"], f["file"], f["line"]) for f in fs]
    g = build_graph(tmp_path)
    routes = sorted(n.entry["detail"] for n in g.nodes.values() if n.entry and n.entry.get("kind") == "route")
    assert routes == ["GET /api/orders/:id"], routes         # the login is no route of its own


EX_KEY = _refuse("gate", "req.get('x-api-key') !== process.env.API_KEY")
EX_SECRET = {
    "clean: the admin's token after the word Bearer":
        (_refuse("gate", "(req.get('authorization') || '') !== 'Bearer ' + process.env.ADMIN_TOKEN")
         + _js(EX_DELETE, mw="gate, ", verb="delete"), []),
    "clean: the same, both sides kept in names first":
        ("function gate (req, res, next) {\n  const sent = req.get('authorization') || ''\n"
         "  const want = 'Bearer ' + process.env.ADMIN_TOKEN\n"
         "  if (sent !== want) return res.status(401).end()\n  next()\n}\n"
         + _js(EX_DELETE, mw="gate, ", verb="delete"), []),
    "clean: compared in constant time, as buffers kept in names":
        ("const crypto = require('crypto')\nfunction gate (req, res, next) {\n"
         "  const given = Buffer.from(req.get('x-admin-token') || '')\n"
         "  const want = Buffer.from(process.env.ADMIN_TOKEN || '')\n"
         "  if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return res.status(401).end()\n"
         "  next()\n}\n" + _js(EX_DELETE, mw="gate, ", verb="delete"), []),
    "caught: only the lengths of the two are compared":
        ("function gate (req, res, next) {\n  const given = Buffer.from(req.get('x-admin-token') || '')\n"
         "  const want = Buffer.from(process.env.ADMIN_TOKEN || '')\n"
         "  if (given.length !== want.length) return res.status(401).end()\n  next()\n}\n"
         + _js(EX_DELETE, mw="gate, ", verb="delete"), ["LW-AUTH-MISSING"]),
    "clean: a key of the server's own that every caller has to send":
        (EX_KEY + _js(EX_DELETE, mw="gate, ", verb="delete"), []),
    "clean: the same asked in the handler":
        (_js("  if (req.get('x-api-key') !== process.env.API_KEY) return res.status(401).end()\n" + EX_DELETE,
             mw="", verb="delete"), []),
    "clean: the key is kept in a settings file of the project":
        ("const config = require('./config')\n" + _refuse("gate", "req.get('x-api-key') !== config.apiKey")
         + _js(EX_DELETE, mw="gate, ", verb="delete"), []),
    "clean: a secret the payment service and the server share":
        (_js("  if (req.get('x-hook-secret') !== process.env.HOOK_SECRET) return res.status(401).end()\n"
             "  await Order.updateOne({ _id: req.body.id }, { paid: true })\n  res.end()\n", mw="", verb="post",
             path="/orders/paid"), []),
    "clean: an admin page behind the server's key":
        (EX_KEY + _js("  res.json(await User.find())\n", mw="requireLogin, gate, ", path="/admin/users"), []),
    "caught: a header compared with the server's region, which is no secret":
        (_refuse("gate", "req.get('x-region') !== process.env.REGION", 400)
         + _js(EX_DELETE, mw="gate, ", verb="delete"), ["LW-AUTH-MISSING"]),
    "caught: a page size from the settings file compared":
        ("const config = require('./config')\n" + _refuse("gate", "req.query.size !== config.pageSize", 400)
         + _js(EX_DELETE, mw="gate, ", verb="delete"), ["LW-AUTH-MISSING"]),
    "caught: the key is compared and nothing is refused":
        ("function gate (req, res, next) {\n"
         "  if (req.get('x-api-key') === process.env.API_KEY) res.set('x-trusted', '1')\n  next()\n}\n"
         + _js(EX_DELETE, mw="gate, ", verb="delete"), ["LW-AUTH-MISSING"]),
    "caught: the key is compared with what the request itself sent":
        (_refuse("gate", "req.get('x-api-key') !== req.query.key")
         + _js(EX_DELETE, mw="gate, ", verb="delete"), ["LW-AUTH-MISSING"]),
    "caught: the key is compared with a key the request names in its own body":
        (_refuse("gate", "req.get('x-api-key') !== req.body.config.apiKey")
         + _js(EX_DELETE, mw="gate, ", verb="delete"), ["LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(EX_SECRET))
def test_express_a_caller_that_has_to_send_the_servers_own_secret(tmp_path, case):
    text, want = EX_SECRET[case]
    fs = _scan(tmp_path, {"server.js": JS + text, "models.js": JS_MODELS,
                          "config.js": "module.exports = { apiKey: process.env.API_KEY, pageSize: '20' }\n"},
               project={"package.json": PACKAGE})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


KEY_SIG = "order_id: int, x_api_key: str = Header(...), db=Depends(get_db)"
PY_SECRET = {
    "clean: a key from the environment, read with a subscript":
        ("    if x_api_key != os.environ['API_KEY']:\n        raise HTTPException(401)\n", []),
    "clean: read with getenv":
        ("    if x_api_key != os.getenv('SERVICE_TOKEN'):\n        raise HTTPException(401)\n", []),
    "clean: kept in a name at the top of the file":
        ("    if x_api_key != API_KEY:\n        raise HTTPException(401)\n", []),
    "clean: compared in constant time":
        ("    if not hmac.compare_digest(x_api_key, os.environ['API_KEY']):\n        raise HTTPException(401)\n", []),
    "caught: compared with the region, which is no secret":
        ("    if x_api_key != os.environ['REGION']:\n        raise HTTPException(400)\n", ["LW-AUTH-MISSING"]),
    "caught: compared with the key and nothing is refused":
        ("    if x_api_key != os.environ['API_KEY']:\n        log.info('no key')\n", ["LW-AUTH-MISSING"]),
    "caught: only asked whether a key was sent":
        ("    if not x_api_key:\n        raise HTTPException(401)\n", ["LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(PY_SECRET))
def test_a_caller_that_has_to_send_the_servers_own_secret(tmp_path, case):
    check, want = PY_SECRET[case]
    body = check + "    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    db.commit()\n"
    head = "import hmac\nimport os\n\nAPI_KEY = os.environ.get('API_KEY', '')\n\n\n"
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + head + _route(body, sig=KEY_SIG, verb="delete")})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- Flask: a login asked in plain code
# No decorator of a library and no name that says "login": the code itself turns away whoever has no user in the
# session, in a helper, in a decorator of the project's own, or before every request.
SESSION_FLASK = ("import functools\nimport sqlite3\n\n"
                 "from flask import Flask, abort, g, jsonify, redirect, request, session, url_for\n\n"
                 "app = Flask(__name__)\n\n\n"
                 "def db():\n    conn = sqlite3.connect('app.db')\n    conn.row_factory = sqlite3.Row\n"
                 "    return conn\n\n\n")
SESSION_READ = ("    row = db().execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone()\n"
                "    return jsonify(dict(row))\n")
SESSION_GONE = ("    conn = db()\n    conn.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n"
                "    conn.commit()\n    return jsonify(ok=True)\n")
MEMBERS = ("def members(view):\n    @functools.wraps(view)\n    def inner(*args, **kwargs):\n"
           "        if 'user_id' not in session:\n            return redirect(url_for('login'))\n"
           "        return view(*args, **kwargs)\n    return inner\n\n\n")
EVERY_REQUEST = "@app.before_request\ndef every_time():\n"


def _order(check, body=SESSION_READ, verb="get", above="", dec=""):
    return SESSION_FLASK + above + f"@app.{verb}('/orders/<int:order_id>')\n{dec}def order(order_id):\n{check}{body}"


SESSION_LOGIN = {
    "caught: a helper with a plain name turns away whoever has no user in the session":
        (_order("    need_someone()\n",
                above="def need_someone():\n    if 'user_id' not in session:\n        abort(401)\n\n\n"),
         ["LT-AUTHZ-OWNER"]),
    "clean: the same helper, and the order is the caller's own":
        (_order("    need_someone()\n",
                body="    row = db().execute('SELECT * FROM orders WHERE id = ? AND user_id = ?',\n"
                     "                       (order_id, session['user_id'])).fetchone()\n"
                     "    return jsonify(dict(row))\n",
                above="def need_someone():\n    if 'user_id' not in session:\n        abort(401)\n\n\n"), []),
    "clean: a helper with the same name that looks at the session and refuses nobody":
        (_order("    need_someone()\n",
                above="def need_someone():\n    if 'user_id' not in session:\n        app.logger.info('a visitor')\n"
                      "\n\n"), []),
    "caught: the same helper that refuses nobody, in front of a delete: nobody has to be signed in":
        (_order("    need_someone()\n", SESSION_GONE, verb="delete",
                above="def need_someone():\n    if 'user_id' not in session:\n        app.logger.info('a visitor')\n"
                      "\n\n"), ["LW-AUTH-MISSING"]),
    "caught: a decorator of the project's own with a plain name":
        (_order("", above=MEMBERS, dec="@members\n"), ["LT-AUTHZ-OWNER"]),
    "caught: before every request, the sign-in page left open":
        (_order("", above=EVERY_REQUEST + "    if request.endpoint != 'login' and 'user_id' not in session:\n"
                                          "        return redirect(url_for('login'))\n\n\n"), ["LT-AUTHZ-OWNER"]),
    "caught: before every request, written the other way round":
        (_order("", above=EVERY_REQUEST + "    if request.endpoint in ('login', 'static') or session.get('user_id'):\n"
                                          "        return None\n    return redirect(url_for('login'))\n\n\n"),
         ["LT-AUTHZ-OWNER"]),
    "clean: before every request, but only the admin pages ask for a user":
        (_order("", above=EVERY_REQUEST + "    if request.path.startswith('/admin') and 'user_id' not in session:\n"
                                          "        return redirect(url_for('login'))\n\n\n"), []),
    "caught: the same in front of a delete: an order is not an admin page, so nobody has to be signed in":
        (_order("", SESSION_GONE, verb="delete",
                above=EVERY_REQUEST + "    if request.path.startswith('/admin') and 'user_id' not in session:\n"
                                      "        return redirect(url_for('login'))\n\n\n"), ["LW-AUTH-MISSING"]),
    "caught: a visitor who writes ?guest=1 is let through, so nobody has to be signed in":
        (_order("    need_someone()\n", SESSION_GONE, verb="delete",
                above="def need_someone():\n    if 'user_id' not in session and not request.args.get('guest'):\n"
                      "        abort(401)\n\n\n"), ["LW-AUTH-MISSING"]),
    "caught: the helper asks for a user id in the body, which the visitor writes":
        (_order("    need_someone()\n", SESSION_GONE, verb="delete",
                above="def need_someone():\n    if not request.json.get('user_id'):\n        abort(400)\n\n\n"),
         ["LW-AUTH-MISSING"]),
    "caught: the helper asks whether there is a session and a user in it":
        (_order("    need_someone()\n", SESSION_GONE, verb="delete",
                above="def need_someone():\n    if not session or session.get('user_id') is None:\n"
                      "        abort(401)\n\n\n"), ["LT-AUTHZ-OWNER"]),
}


@pytest.mark.parametrize("case", sorted(SESSION_LOGIN))
def test_flask_a_login_asked_in_plain_code(tmp_path, case):
    text, want = SESSION_LOGIN[case]
    fs = _scan(tmp_path, {"app/main.py": text},
               project={"pyproject.toml": '[project]\nname="a"\nversion="0"\ndependencies=["flask"]\n',
                        "app/__init__.py": ""})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- where an ownership finding stands
# Round 3 (2026-11-11). Until then the finding stood on the route's first line, one per route. It stands on the line
# the record is reached, where the owner has to be compared (every other flow finding stands on its action), with the
# routes that reach it listed: one service function used by five routes is one place to fix. For a database helper
# that runs whatever text it is handed, that line is where the text is written. `LT-AUTHZ-ROLE` and `LW-AUTH-MISSING`
# are about the route and stay on it.
def _line(text, needle):
    return next(i for i, ln in enumerate(text.splitlines(), 1) if needle in ln)


def _where(fs):
    return sorted((f["rule"], f["file"], f["line"]) for f in fs
                  if f["rule"].startswith("LT-AUTHZ") or f["rule"] == "LW-AUTH-MISSING")


TOTAL = _route("    return {'total': service.get_order(db, order_id)['total']}\n",
               path="/orders/{order_id}/total").replace("def handle", "def total")
BY_SERVICE = "from . import service\n\n\n" + _route("    return service.get_order(db, order_id)\n")
ORDER_SVC = f"def get_order(db, order_id):\n    return db.execute('{ONE}', (order_id,)).fetchone()\n"


def test_an_ownership_finding_stands_on_the_line_the_record_is_reached(tmp_path):
    main = FASTAPI + _route(f"    log.info('order %s', order_id)\n    return db.execute('{ONE}', (order_id,)).fetchone()\n")
    fs = _scan(tmp_path, {"app/main.py": main})
    assert _where(fs) == [("LT-AUTHZ-OWNER", "app/main.py", _line(main, f"db.execute('{ONE}'"))], _where(fs)
    f = next(x for x in fs if x["rule"] == "LT-AUTHZ-OWNER")
    assert f["title"].startswith("GET /orders/{order_id} reaches a record by an id from the request"), f["title"]
    assert f["routes"] == ["GET /orders/{order_id}"] and f["flow"]["sink"]["line"] == f["line"], f


def test_a_record_reached_in_a_service_file_is_found_there_once_for_every_route(tmp_path):
    main = FASTAPI + BY_SERVICE + "\n\n" + TOTAL
    fs = _scan(tmp_path, {"app/main.py": main, "app/service.py": ORDER_SVC})
    assert _where(fs) == [("LT-AUTHZ-OWNER", "app/service.py", 2)], _where(fs)
    f = next(x for x in fs if x["rule"] == "LT-AUTHZ-OWNER")
    assert f["routes"] == ["GET /orders/{order_id}", "GET /orders/{order_id}/total"], f["routes"]
    assert f["title"].startswith("GET /orders/{order_id} and 1 more route reach a record by an id"), f["title"]
    assert f["tool_confidence"] == "LOW" and f["rank"] == "medium", f


def test_a_route_that_compares_the_owner_is_not_among_the_routes_of_the_finding(tmp_path):
    mine = _route("    order = service.get_order(db, order_id)\n"
                  "    if order is None or order['user_id'] != user['id']:\n        raise HTTPException(404)\n"
                  "    return order\n")
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + "from . import service\n\n\n" + mine + "\n\n" + TOTAL,
                          "app/service.py": ORDER_SVC})
    assert _where(fs) == [("LT-AUTHZ-OWNER", "app/service.py", 2)], _where(fs)
    assert next(x for x in fs if x["rule"] == "LT-AUTHZ-OWNER")["routes"] == ["GET /orders/{order_id}/total"]
    # and with the other route comparing too, nothing is left
    both = TOTAL.replace("    return {'total': service.get_order(db, order_id)['total']}\n",
                         "    order = service.get_order(db, order_id)\n    if order['user_id'] != user['id']:\n"
                         "        raise HTTPException(404)\n    return {'total': order['total']}\n")
    fs = _scan(tmp_path / "both", {"app/main.py": FASTAPI + "from . import service\n\n\n" + mine + "\n\n" + both,
                                   "app/service.py": ORDER_SVC})
    assert _where(fs) == [], _where(fs)


def test_one_route_that_reaches_two_records_has_two_places_to_fix(tmp_path):
    main = FASTAPI + _route(
        f"    order = db.execute('{ONE}', (order_id,)).fetchone()\n"
        "    notes = db.execute('SELECT * FROM notes WHERE order_id = ?', (order_id,)).fetchall()\n"
        "    return {'order': order, 'notes': notes}\n")
    fs = _scan(tmp_path, {"app/main.py": main})
    assert _where(fs) == [("LT-AUTHZ-OWNER", "app/main.py", _line(main, f"db.execute('{ONE}'")),
                          ("LT-AUTHZ-OWNER", "app/main.py", _line(main, "FROM notes"))], _where(fs)


def test_through_a_database_helper_the_finding_stands_where_the_query_is_written(tmp_path):
    svc = (SVC + f"def get_order(order_id):\n    return db.one('{ONE}', (order_id,))\n\n\n"
           "def get_invoice(invoice_id):\n    return db.one('SELECT * FROM invoices WHERE id = ?', (invoice_id,))\n")
    invoice = _route("    return service.get_invoice(invoice_id)\n", sig="invoice_id: int, user=Depends(get_current_user)",
                     path="/invoices/{invoice_id}").replace("def handle", "def invoice")
    main = FASTAPI + "from . import service\n\n\n" + PLAIN + "\n\n" + invoice
    fs = _scan(tmp_path, {"app/main.py": main, "app/service.py": svc, "app/db.py": DB_HELPER})
    # two queries through one helper are two findings, each where its text is written, not one on the helper's line
    assert _where(fs) == [("LT-AUTHZ-OWNER", "app/service.py", _line(svc, "FROM orders")),
                          ("LT-AUTHZ-OWNER", "app/service.py", _line(svc, "FROM invoices"))], _where(fs)
    by_line = {f["line"]: f for f in fs if f["rule"] == "LT-AUTHZ-OWNER"}
    assert by_line[_line(svc, "FROM orders")]["routes"] == ["GET /orders/{order_id}"]
    assert by_line[_line(svc, "FROM invoices")]["routes"] == ["GET /invoices/{invoice_id}"]
    last = by_line[_line(svc, "FROM orders")]["flow"]["steps"][-1]
    assert last["file"] == "app/db.py" and "conn.execute" in last["what"], last     # the way still ends at the helper


def test_express_handlers_in_a_file_of_their_own(tmp_path):
    handlers = ("const { Order } = require('../models')\nasync function load (id) {\n  return Order.findById(id)\n}\n"
                "exports.show = async function (req, res) {\n  res.json(await load(req.params.id))\n}\n"
                "exports.print = async function (req, res) {\n  res.json({ lines: (await load(req.params.id)).lines })\n}\n"
                "exports.mine = async function (req, res) {\n  const order = await load(req.params.id)\n"
                "  if (!order || order.user !== req.session.userId) return res.status(404).end()\n  res.json(order)\n}\n")
    files = {"server.js": "const express = require('express')\nconst handlers = require('./core/handlers')\n"
                          "const { requireLogin } = require('./lib/guard')\nconst app = express()\n"
                          "app.get('/orders/:id', requireLogin, handlers.show)\n"
                          "app.get('/orders/:id/print', requireLogin, handlers.print)\n"
                          "app.get('/my/orders/:id', requireLogin, handlers.mine)\n",
             "lib/guard.js": JS_GUARD, "models.js": JS_MODELS, "core/handlers.js": handlers}
    fs = _scan(tmp_path, files, project={"package.json": PACKAGE})
    assert _where(fs) == [("LT-AUTHZ-OWNER", "core/handlers.js", 3)], _where(fs)
    assert next(x for x in fs if x["rule"] == "LT-AUTHZ-OWNER")["routes"] == ["GET /orders/:id", "GET /orders/:id/print"]


def test_an_admin_route_and_a_route_with_no_login_keep_their_finding_on_the_route(tmp_path):
    main = FASTAPI + _route(f"    return db.execute('{ONE}', (order_id,)).fetchone()\n", path="/admin/orders/{order_id}")
    fs = _scan(tmp_path, {"app/main.py": main})
    assert _where(fs) == [("LT-AUTHZ-ROLE", "app/main.py", _line(main, "def handle("))], _where(fs)
    main = FASTAPI + _route("    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {'ok': True}\n",
                            sig=ANON_SIG, verb="delete")
    fs = _scan(tmp_path / "open", {"app/main.py": main})
    assert _where(fs) == [("LW-AUTH-MISSING", "app/main.py", _line(main, "@app.delete("))], _where(fs)


# ------------------------------------------------------------- something that cannot be taken back, done before the check
# A command run, a file removed or another service told to change something for a record the request picks, and only
# then the question whose record it is: the refusal comes after the harm. Reported where the route does ask (for the
# owner or a role), but only after the action; where it never asks, the record's own finding above says so, and a
# command with an id and no record to own is nobody's business here. The finding stands on the action.
ACT_HEAD = FASTAPI + "import os\nimport subprocess\n\nimport requests\n\nBILLING = 'https://billing.internal'\n\n\n"
ACT_SIG = "report_id: int, user=Depends(get_current_user), db=Depends(get_db)"
REPORT = "    report = db.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()\n"
NOT_OWNER = "    if report is None or report['owner_id'] != user['id']:\n        raise HTTPException(403)\n"
BUILD = "    subprocess.run(['make', 'report', str(report_id)], check=False)\n"
OWN_REPORT = ("def own_report(" + ACT_SIG + "):\n" + REPORT + NOT_OWNER + "    return report\n\n\n")


def _act(body, sig=ACT_SIG):
    return _route(body + "    return {'ok': True}\n", sig=sig, verb="post", path="/reports/{report_id}/build")


ACTS = {    # what the finding stands on (a piece of that line), or None
    "caught: a command is run for the report, and only then is its owner compared":
        (_act(REPORT + BUILD + NOT_OWNER), "subprocess.run("),
    "clean: the owner is compared first":
        (_act(REPORT + NOT_OWNER + BUILD), None),
    "caught: the command is in a helper that is called before the check":
        ("def build(rid):\n    subprocess.run(['make', 'report', str(rid)], check=False)\n\n\n" +
         _act(REPORT + "    build(report_id)\n" + NOT_OWNER), "subprocess.run("),
    "clean: the helper is called after the check":
        ("def build(rid):\n    subprocess.run(['make', 'report', str(rid)], check=False)\n\n\n" +
         _act(REPORT + NOT_OWNER + "    build(report_id)\n"), None),
    "caught: a file of the report is removed first":
        (_act(REPORT + "    os.remove(os.path.join('exports', str(report_id) + '.pdf'))\n" + NOT_OWNER), "os.remove("),
    "caught: another service is told to change something first":
        (_act(REPORT + "    requests.post(BILLING + '/refunds/' + str(report_id))\n" + NOT_OWNER), "requests.post("),
    "clean: another service is only asked first":
        (_act(REPORT + "    requests.get(BILLING + '/status/' + str(report_id))\n" + NOT_OWNER), None),
    "clean: the command carries nothing of the request":
        (_act(REPORT + "    subprocess.run(['make', 'all'], check=False)\n" + NOT_OWNER), None),
    "clean: the command is run for who is signed in":
        (_act(REPORT + "    subprocess.run(['quota', str(user['id'])], check=False)\n" + NOT_OWNER), None),
    "clean: the owner is compared by a dependency, before any line of the route":
        (OWN_REPORT + _act(BUILD, sig="report_id: int, report=Depends(own_report)"), None),
    "caught: a role is asked only after the command":
        (_act(REPORT + BUILD + "    if not user['is_admin']:\n        raise HTTPException(403)\n"), "subprocess.run("),
    "not this finding: nothing on the route asks whose the report is, so the record's own finding says it":
        (_act(REPORT + BUILD), "FROM reports"),
    "clean: a command with an id and no record to own":
        (_act(BUILD), None),
    "clean: a command with a search word, which picks nobody's record":
        (_act("    subprocess.run(['grep', '-c', word, 'notes.txt'], check=False)\n" + REPORT + NOT_OWNER,
              sig="word: str, " + ACT_SIG), None),
}


@pytest.mark.parametrize("case", sorted(ACTS))
def test_a_check_that_comes_after_something_that_cannot_be_taken_back(tmp_path, case):
    body, on = ACTS[case]
    main = ACT_HEAD + body
    fs = _scan(tmp_path, {"app/main.py": main})
    want = [("LT-AUTHZ-OWNER", "app/main.py", _line(main, on))] if on else []
    assert _where(fs) == want, [(f["rule"], f["file"], f["line"], f["title"]) for f in fs]


def test_a_late_check_is_said_as_one(tmp_path):
    main = ACT_HEAD + _act(REPORT + BUILD + NOT_OWNER)
    f = next(x for x in _scan(tmp_path, {"app/main.py": main}) if x["rule"] == "LT-AUTHZ-OWNER")
    assert f["title"] == ("POST /reports/{report_id}/build runs a command for a record picked by an id from the request "
                          "before it asks whose the record is"), f["title"]
    assert f["tool_confidence"] == "LOW" and f["rank"] == "medium" and f["flow"]["sink"]["line"] == f["line"], f
    assert "here a command is run for it" in f["flow"]["steps"][-1]["what"], f["flow"]["steps"]
    # the story and the case say that the check is there and comes too late, not that there is none
    assert f["late"] == "shell" and f["scenario"]["kind"] == "owner-late", (f.get("late"), f["scenario"]["kind"])
    assert "asks whose the record is only afterwards" in f["scenario"]["harm"], f["scenario"]["harm"]
    assert f["headline"] == "Something is done for a record before the app asks whose it is", f["headline"]
    needs = {c["need"]: c["met"] for c in f["case"]["conditions"]}
    assert needs["Whose the record is gets asked only after this line"] is True, needs
    assert "Nothing compares the record's owner with who is signed in" not in needs, needs
    # a record changed before the check says the same of the change
    main = FASTAPI + _route(f"    row = db.execute('{ONE}', (order_id,)).fetchone()\n"
                            "    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n"
                            "    if row is None or row['user_id'] != user['id']:\n        raise HTTPException(403)\n"
                            "    return {'ok': True}\n", verb="delete")
    f = next(x for x in _scan(tmp_path / "gone", {"app/main.py": main}) if x["rule"] == "LT-AUTHZ-OWNER")
    assert f["title"] == ("DELETE /orders/{order_id} changes or removes a record picked by an id from the request "
                          "before it asks whose the record is"), f["title"]
    assert f["line"] == _line(main, "DELETE FROM orders"), f


JS_ACT_HEAD = JS + ("const { execFile } = require('child_process')\nconst fs = require('fs')\n"
                    "const axios = require('axios')\n")
JS_REPORT = "  const order = await Order.findById(req.params.id)\n"
JS_NOT_OWNER = "  if (!order || order.user !== req.session.userId) return res.status(403).end()\n"
JS_BUILD = "  execFile('make', ['report', req.params.id])\n"
JS_ACTS = {
    "caught: a command is run for the order, and only then is its owner compared":
        (JS_REPORT + JS_BUILD + JS_NOT_OWNER, "execFile('make'"),
    "clean: the owner is compared first":
        (JS_REPORT + JS_NOT_OWNER + JS_BUILD, None),
    "caught: a file of the order is removed first":
        (JS_REPORT + "  fs.unlinkSync('exports/' + req.params.id + '.pdf')\n" + JS_NOT_OWNER, "fs.unlinkSync("),
    "caught: another service is told to change something first":
        (JS_REPORT + "  await axios.post('https://billing.internal/refunds/' + req.params.id)\n" + JS_NOT_OWNER,
         "axios.post("),
    "clean: another service is only asked first":
        (JS_REPORT + "  await axios.get('https://billing.internal/status/' + req.params.id)\n" + JS_NOT_OWNER, None),
    "clean: the command carries nothing of the request":
        (JS_REPORT + "  execFile('make', ['all'])\n" + JS_NOT_OWNER, None),
}


@pytest.mark.parametrize("case", sorted(JS_ACTS))
def test_express_a_check_that_comes_after_something_that_cannot_be_taken_back(tmp_path, case):
    body, on = JS_ACTS[case]
    server = JS_ACT_HEAD + _js(body + "  res.json({ ok: true })\n", verb="post", path="/orders/:id/build")
    fs = _scan(tmp_path, {"server.js": server, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    want = [("LT-AUTHZ-OWNER", "server.js", _line(server, on))] if on else []
    assert _where(fs) == want, [(f["rule"], f["file"], f["line"], f["title"]) for f in fs]


# ------------------------------------------------------------- Express: a check written in place in `use`
# `app.use((req, res, next) => { if (!req.session.userId) return res.status(401).end(); next() })`: the check has no
# name, so it is read for what its lines do, as a check with a plain name is. Added 2026-11-11: until then such a
# function was not among what runs before a route, the route read as open to everybody ("no login check was found"),
# and that any signed-in person could remove another's order was not said.
def _in_place(cond, code=401, path="", params="req, res, next"):
    at = f"'{path}', " if path else ""
    return f"app.use({at}({params}) => {{\n  if ({cond}) return res.status({code}).end()\n  next()\n}})\n"


EX_ADMIN_PAGE = _js("  res.json(await User.find())\n", mw="", path="/admin/users")
EX_API = "api.delete('/orders/:id', async (req, res) => {\n" + EX_DELETE + "})\n"
EX_API_GATE = "api.use((req, res, next) => {\n  if (!req.session.userId) return res.status(401).end()\n  next()\n})\n"
EX_IN_PLACE = {
    "caught: it turns away whoever has no session, and any of them removes any order":
        (_in_place("!req.session.userId") + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "caught: the same written with the word function":
        ("app.use(function (req, res, next) {\n  if (!req.session.userId) { res.status(401).end(); return }\n"
         "  next()\n})\n" + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "caught: let through when signed in, sent to the sign-in page otherwise":
        ("app.use((req, res, next) => {\n  if (req.session.userId) return next()\n  res.redirect('/login')\n})\n"
         + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "caught: for the path the route is under":
        (_in_place("!req.session.userId", path="/orders") + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "caught: the second of two functions handed to one use":
        ("app.use((req, res, next) => {\n  console.log(req.path)\n  next()\n}, (req, res, next) => {\n"
         "  if (!req.session.userId) return res.status(401).end()\n  next()\n})\n" + EX_ROUTE, ["LT-AUTHZ-OWNER"]),
    "caught: on a router of its own, before the route":
        ("const api = express.Router()\n" + EX_API_GATE + EX_API + "app.use('/api', api)\n", ["LT-AUTHZ-OWNER"]),
    "clean: and the delete names the owner":
        (_in_place("!req.session.userId") + _js(_mine("req.session.userId"), mw="", verb="delete"), []),
    "open: it only writes a line in the log":
        ("app.use((req, res, next) => {\n  console.log(req.path)\n  next()\n})\n" + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "open: written after the route":
        (EX_ROUTE + _in_place("!req.session.userId"), ["LW-AUTH-MISSING"]),
    "open: for another path":
        (_in_place("!req.session.userId", path="/account") + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "open: on a router of its own, after the route":
        ("const api = express.Router()\n" + EX_API + EX_API_GATE + "app.use('/api', api)\n", ["LW-AUTH-MISSING"]),
    "open: it looks at the session and refuses nobody":
        ("app.use((req, res, next) => {\n  if (!req.session.userId) console.log('a visitor')\n  next()\n})\n"
         + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "open: it refuses a request with no cart, which is nobody's name":
        (_in_place("!req.session.cart", 400) + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "open: four parameters, which is what handles an error and not what lets a request in":
        (_in_place("!req.session.userId", params="err, req, res, next") + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "open: whoever has no session is turned away only when the request is a GET":
        ("app.use((req, res, next) => {\n  if (req.method !== 'GET') return next()\n"
         "  if (!req.session.userId) return res.status(401).end()\n  next()\n})\n" + EX_ROUTE, ["LW-AUTH-MISSING"]),
    "caught: an admin page behind a login written in place asks for no admin":
        (_in_place("!req.session.userId") + EX_ADMIN_PAGE, ["LT-AUTHZ-ROLE"]),
    "clean: the admin check is written in place for the admin pages":
        (_in_place("!req.session.userId") + _in_place("req.session.role !== 'admin'", 403, "/admin") + EX_ADMIN_PAGE,
         []),
    "caught: the admin check written in place is for other pages":
        (_in_place("!req.session.userId") + _in_place("req.session.role !== 'admin'", 403, "/reports")
         + EX_ADMIN_PAGE, ["LT-AUTHZ-ROLE"]),
    "caught: what is written in place for the admin pages only sets a header":
        (_in_place("!req.session.userId") + "app.use('/admin', (req, res, next) => {\n"
         "  res.set('Cache-Control', 'no-store')\n  next()\n})\n" + EX_ADMIN_PAGE, ["LT-AUTHZ-ROLE"]),
}


@pytest.mark.parametrize("case", sorted(EX_IN_PLACE))
def test_express_a_check_written_in_place_in_use(tmp_path, case):
    text, want = EX_IN_PLACE[case]
    fs = _scan(tmp_path, {"server.js": JS + text, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- a route the page calls, behind a login the code shows
# "No login check was found" is said of a route the page calls by the names around it (`websec.missing_auth`). Where
# the code itself turns away whoever is not signed in (a check with a plain name, one written in place, a Flask hook
# that runs before every request), that sentence is wrong, and since 2026-11-11 it is not said: until then such a
# route got it beside the finding that says a login is there and the owner is not asked.
WEB_PAGE = ("export async function remove (id) { await fetch('/orders/' + id, { method: 'DELETE' }) }\n"
            "export async function add (item) {\n"
            "  await fetch('/orders', { method: 'POST', body: JSON.stringify({ item }) })\n}\n")
EX_ADD = _js("  await Order.create({ item: req.body.item })\n  res.status(201).end()\n", mw="", verb="post",
             path="/orders")
EX_BOTH = EX_ROUTE + EX_ADD
EX_CALLED = {
    "open: nothing before the two routes":
        (EX_BOTH, ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "caught: a login with a name that says so, put on with use":
        ("app.use(requireLogin)\n" + EX_BOTH, ["LT-AUTHZ-OWNER"]),
    "caught: the same check under a plain name, put on with use":
        (_refuse("restrict", "!req.session.userId") + "app.use(restrict)\n" + EX_BOTH, ["LT-AUTHZ-OWNER"]),
    "caught: the same check under a plain name, handed to each route":
        (_refuse("restrict", "!req.session.userId") + _js(EX_DELETE, mw="restrict, ", verb="delete")
         + _js("  await Order.create({ item: req.body.item })\n  res.status(201).end()\n", mw="restrict, ",
               verb="post", path="/orders"), ["LT-AUTHZ-OWNER"]),
    "caught: the same check written in place":
        (_in_place("!req.session.userId") + EX_BOTH, ["LT-AUTHZ-OWNER"]),
    "clean: the check written in place, and the delete names the owner":
        (_in_place("!req.session.userId") + _js(_mine("req.session.userId"), mw="", verb="delete") + EX_ADD, []),
    "open: a plain name that only writes a line in the log":
        ("function restrict (req, res, next) {\n  console.log(req.path)\n  next()\n}\napp.use(restrict)\n" + EX_BOTH,
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "open: written in place, and it only writes a line in the log":
        ("app.use((req, res, next) => {\n  console.log(req.path)\n  next()\n})\n" + EX_BOTH,
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "open: the check under a plain name is put on after the routes":
        (_refuse("restrict", "!req.session.userId") + EX_BOTH + "app.use(restrict)\n",
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "open: the check under a plain name is for another path":
        (_refuse("restrict", "!req.session.userId") + "app.use('/account', restrict)\n" + EX_BOTH,
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(EX_CALLED))
def test_express_a_route_the_page_calls_behind_a_login_the_code_shows(tmp_path, case):
    text, want = EX_CALLED[case]
    fs = _scan(tmp_path, {"server.js": JS + text + "app.listen(3000)\n", "models.js": JS_MODELS, "web/app.js": WEB_PAGE},
               project={"package.json": PACKAGE})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


HOOK_PROJECT = {"requirements.txt": "flask==3.0.3\n", "app/__init__.py": "", "web/app.js": WEB_PAGE}
HOOK_HEAD = ("import sqlite3\n\nfrom flask import Flask, abort, request, session\n\napp = Flask(__name__)\n\n\n"
             "def db():\n    return sqlite3.connect('app.db')\n\n\n")
HOOK_ROUTES = ("@app.delete('/orders/<int:order_id>')\ndef remove(order_id):\n"
               "    db().execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return '', 204\n\n\n"
               "@app.post('/orders')\ndef add():\n"
               "    db().execute('INSERT INTO orders (item) VALUES (?)', (request.json['item'],))\n    return '', 201\n")
HOOK_GATE = "    if 'user_id' not in session:\n        abort(401)\n\n\n"
HOOKS = {
    "open: nothing runs before the two routes":
        ("", ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "caught: a hook with a plain name turns away whoever has no session":
        ("@app.before_request\ndef gate():\n" + HOOK_GATE, ["LT-AUTHZ-OWNER"]),
    "caught: the same hook under a name that says so":
        ("@app.before_request\ndef require_login():\n" + HOOK_GATE, ["LT-AUTHZ-OWNER"]),
    "open: a hook that only writes a line in the log":
        ("@app.before_request\ndef gate():\n    app.logger.info(request.path)\n\n\n",
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "open: the same lines in a function that is no hook":
        ("def gate():\n" + HOOK_GATE, ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "open: a hook that looks at the session and refuses nobody":
        ("@app.before_request\ndef gate():\n    if 'user_id' not in session:\n        app.logger.info('a visitor')\n\n\n",
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(HOOKS))
def test_flask_a_route_the_page_calls_behind_a_hook_that_turns_visitors_away(tmp_path, case):
    before, want = HOOKS[case]
    fs = _scan(tmp_path, {"app/main.py": HOOK_HEAD + before + HOOK_ROUTES}, project=HOOK_PROJECT)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


DEP_PROJECT = dict(PROJECT, **{"web/app.js": WEB_PAGE})
DEP_HEAD = ("import sqlite3\n\nfrom fastapi import Depends, FastAPI, HTTPException, Request\n\napp = FastAPI()\n\n\n"
            "def get_db():\n    return sqlite3.connect('app.db')\n\n\n")
DEP_GATE = ("(request: Request):\n    uid = request.session.get('user_id')\n    if not uid:\n"
            "        raise HTTPException(401)\n    return uid\n\n\n")
DEPS = {
    "open: no dependency but the database":
        ("", "", ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "caught: a dependency with a plain name turns away whoever has no session":
        ("def caller" + DEP_GATE, "uid=Depends(caller), ", ["LT-AUTHZ-OWNER"]),
    "caught: the same dependency under a name that says so":
        ("def current_user" + DEP_GATE, "uid=Depends(current_user), ", ["LT-AUTHZ-OWNER"]),
    "open: a dependency with a plain name that reads a header and refuses nobody":
        ("def caller(request: Request):\n    return request.headers.get('x-trace')\n\n\n", "trace=Depends(caller), ",
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(DEPS))
def test_fastapi_a_route_the_page_calls_behind_a_dependency_that_turns_visitors_away(tmp_path, case):
    dep, sig, want = DEPS[case]
    routes = (f"@app.delete('/orders/{{order_id}}')\ndef remove(order_id: int, {sig}db=Depends(get_db)):\n"
              "    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {}\n\n\n"
              f"@app.post('/orders')\ndef add(body: dict, {sig}db=Depends(get_db)):\n"
              "    db.execute('INSERT INTO orders (item) VALUES (?)', (body['item'],))\n    return {}\n")
    fs = _scan(tmp_path, {"app/main.py": DEP_HEAD + dep + routes}, project=DEP_PROJECT)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_the_record_says_how_many_routes_were_not_called_open_because_the_code_shows_a_login(tmp_path):
    from lantern.security import scan
    files = {"package.json": PACKAGE, "models.js": JS_MODELS, "web/app.js": WEB_PAGE,
             "server.js": JS + _in_place("!req.session.userId") + EX_BOTH + "app.listen(3000)\n"}
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    sec = scan(build_graph(tmp_path), offline=True)
    record = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert record["scope"]["login_read_from_code"] == 2, record


# ------------------------------------------------------------- a login asked of some verbs only
# `if (req.method === 'GET') return next()` in front of a login check: reading is open to everybody and only a change
# asks who is signed in. A login is then a login for the routes of the verbs that are asked, and for no other. Added
# 2026-11-11, found on examples of Lantern's own: until then which verb a request is was read like "which page" (the
# sign-in page left open), so a check that lets every GET through still counted as a login for the pages that read.
def _by_verb(fs):
    out = []
    for f in fs:
        if f["rule"] == "LW-AUTH-MISSING":
            out.append((f["rule"], f["title"].split()[0]))
        elif f["rule"].startswith("LT-AUTHZ"):
            out.extend((f["rule"], r.split()[0]) for r in f.get("routes") or [f["title"]])
    return sorted(out)


def _gate(body, head="app.use((req, res, next) => {\n"):
    return head + body + "})\n"


VERB_PAGE = ("export async function show (id) { return (await fetch('/orders/' + id)).json() }\n"
             "export async function remove (id) { await fetch('/orders/' + id, { method: 'DELETE' }) }\n")
EX_SHOW = _js("  res.json(await Order.findById(req.params.id))\n", mw="")
EX_ASK = "  if (!req.session.userId) return res.status(401).end()\n  next()\n"
BOTH_ASKED = [("LT-AUTHZ-OWNER", "DELETE"), ("LT-AUTHZ-OWNER", "GET")]
ONLY_REMOVE_ASKED = [("LT-AUTHZ-OWNER", "DELETE")]
ONLY_SHOW_ASKED = [("LT-AUTHZ-OWNER", "GET"), ("LW-AUTH-MISSING", "DELETE")]
NEITHER_ASKED = [("LW-AUTH-MISSING", "DELETE")]
EX_VERBS = {
    "both asked: every request is asked who is signed in":
        (_gate(EX_ASK), BOTH_ASKED),
    "both asked: a preflight request is let through and every other is asked":
        (_gate("  if (req.method === 'OPTIONS') return next()\n" + EX_ASK), BOTH_ASKED),
    "both asked: OPTIONS and HEAD from a list are let through":
        (_gate("  if (['OPTIONS', 'HEAD'].includes(req.method)) return next()\n" + EX_ASK), BOTH_ASKED),
    "both asked: everything but a preflight request is asked, in one condition":
        (_gate("  if (req.method !== 'OPTIONS' && !req.session.userId) return res.status(401).end()\n  next()\n"),
         BOTH_ASKED),
    "both asked: a verb the app does not answer is refused, and then everybody is asked":
        (_gate("  if (req.method === 'TRACE') return res.status(405).end()\n" + EX_ASK), BOTH_ASKED),
    "only the removal asked: every GET is let through first":
        (_gate("  if (req.method === 'GET') return next()\n" + EX_ASK), ONLY_REMOVE_ASKED),
    "only the removal asked: GET and HEAD from a list are let through first":
        (_gate("  if (['GET', 'HEAD'].includes(req.method)) return next()\n" + EX_ASK), ONLY_REMOVE_ASKED),
    "only the removal asked: the verb is compared in small letters":
        (_gate("  if (req.method.toLowerCase() === 'get') return next()\n" + EX_ASK), ONLY_REMOVE_ASKED),
    "only the removal asked: everything but a GET is asked, in one condition":
        (_gate("  if (req.method !== 'GET' && !req.session.userId) return res.status(401).end()\n  next()\n"),
         ONLY_REMOVE_ASKED),
    "only the removal asked: let through when it is a GET or somebody is signed in":
        (_gate("  if (req.method === 'GET' || req.session.userId) return next()\n  res.status(401).end()\n"),
         ONLY_REMOVE_ASKED),
    "only the removal asked: the check is in a branch for DELETE":
        (_gate("  if (req.method === 'DELETE') {\n    if (!req.session.userId) return res.status(401).end()\n  }\n"
               "  next()\n"), ONLY_REMOVE_ASKED),
    "only the removal asked: the same check under a plain name":
        (_gate("  if (req.method === 'GET') return next()\n" + EX_ASK, "function restrict (req, res, next) {\n")[:-2]
         + "\napp.use(restrict)\n", ONLY_REMOVE_ASKED),
    "only the reading asked: every DELETE is let through first":
        (_gate("  if (req.method === 'DELETE') return next()\n" + EX_ASK), ONLY_SHOW_ASKED),
    "only the reading asked: whoever has no session is turned away only when the request is a GET":
        (_gate("  if (req.method !== 'GET') return next()\n" + EX_ASK), ONLY_SHOW_ASKED),
    "neither asked: the check is in a branch for POST":
        (_gate("  if (req.method === 'POST') {\n    if (!req.session.userId) return res.status(401).end()\n  }\n"
               "  next()\n"), NEITHER_ASKED),
    "neither asked: only a POST with no session is turned away, in one condition":
        (_gate("  if (req.method === 'POST' && !req.session.userId) return res.status(401).end()\n  next()\n"),
         NEITHER_ASKED),
    "neither asked: nothing before the routes":
        ("", NEITHER_ASKED),
}


@pytest.mark.parametrize("case", sorted(EX_VERBS))
def test_express_a_login_asked_of_some_verbs_only(tmp_path, case):
    gate, want = EX_VERBS[case]
    fs = _scan(tmp_path, {"server.js": JS + gate + EX_SHOW + EX_ROUTE + "app.listen(3000)\n", "models.js": JS_MODELS,
                          "web/app.js": VERB_PAGE}, project={"package.json": PACKAGE})
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


VERB_PROJECT = {"requirements.txt": "flask==3.0.3\n", "app/__init__.py": "", "web/app.js": VERB_PAGE}
VERB_ROUTES = ("@app.get('/orders/<int:order_id>')\ndef show(order_id):\n"
               "    return db().execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone()\n\n\n"
               "@app.delete('/orders/<int:order_id>')\ndef remove(order_id):\n"
               "    db().execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return '', 204\n")
VERB_BOTH = ("@app.route('/orders/<int:order_id>', methods=['GET', 'DELETE'])\ndef order(order_id):\n"
             "    if request.method == 'DELETE':\n"
             "        db().execute('DELETE FROM orders WHERE id = ?', (order_id,))\n        return '', 204\n"
             "    return db().execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone()\n")


def _hook(body):
    return "@app.before_request\ndef gate():\n" + body + "\n\n"


PY_VERBS = {
    "both asked: every request is asked who is signed in":
        (_hook("    if 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES, BOTH_ASKED),
    "both asked: a preflight request is let through and every other is asked":
        (_hook("    if request.method == 'OPTIONS':\n        return None\n"
               "    if 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES, BOTH_ASKED),
    "both asked: OPTIONS and HEAD from a tuple are let through":
        (_hook("    if request.method in ('OPTIONS', 'HEAD'):\n        return None\n"
               "    if 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES, BOTH_ASKED),
    "both asked: everything but a preflight request is asked, in one condition":
        (_hook("    if request.method != 'OPTIONS' and 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES,
         BOTH_ASKED),
    "only the removal asked: every GET is let through first":
        (_hook("    if request.method == 'GET':\n        return None\n"
               "    if 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES, ONLY_REMOVE_ASKED),
    "only the removal asked: the verbs that only read are let through first":
        (_hook("    if request.method in ('GET', 'HEAD', 'OPTIONS'):\n        return None\n"
               "    if 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES, ONLY_REMOVE_ASKED),
    "only the removal asked: everything but the verbs that only read is asked, in one condition":
        (_hook("    if request.method not in ('GET', 'HEAD', 'OPTIONS') and 'user_id' not in session:\n"
               "        abort(401)\n"), VERB_ROUTES, ONLY_REMOVE_ASKED),
    "only the reading asked: every DELETE is let through first":
        (_hook("    if request.method == 'DELETE':\n        return None\n"
               "    if 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES, ONLY_SHOW_ASKED),
    "neither asked: only a POST with no session is turned away":
        (_hook("    if request.method == 'POST' and 'user_id' not in session:\n        abort(401)\n"), VERB_ROUTES,
         NEITHER_ASKED),
    "neither asked: one route answers GET and DELETE, and every GET is let through first":
        (_hook("    if request.method == 'GET':\n        return None\n"
               "    if 'user_id' not in session:\n        abort(401)\n"), VERB_BOTH, [("LW-AUTH-MISSING", "GET/DELETE")]),
    "both asked: one route answers GET and DELETE, and every request is asked":
        (_hook("    if 'user_id' not in session:\n        abort(401)\n"), VERB_BOTH,
         [("LT-AUTHZ-OWNER", "GET/DELETE"), ("LT-AUTHZ-OWNER", "GET/DELETE")]),
}


@pytest.mark.parametrize("case", sorted(PY_VERBS))
def test_flask_a_login_asked_of_some_verbs_only(tmp_path, case):
    before, routes, want = PY_VERBS[case]
    fs = _scan(tmp_path, {"app/main.py": HOOK_HEAD + before + routes}, project=VERB_PROJECT)
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


# ------------------------------------------------------------- a login with no telling name: what the code does
# The three ways a hand-written check knows who is calling, read from the code and not from what the function is
# called: a library checks the token and fails when it does not hold; the token is looked up among the people; and
# in a function every request passes through, a request that is not handed on never reaches the route, whatever it
# is answered with. Added 2026-11-11 from examples of Lantern's own: until then each of these, under a plain name or
# written in place, read "no login check was found".
TOKEN_PACKAGE = ('{"dependencies": {"express": "4.19.2", "mysql2": "3.9.7", "mongoose": "8.4.0", "lodash": "4.17.21", '
                 '"jsonwebtoken": "9.0.2", "jose": "5.2.0", "firebase-admin": "12.1.0", "google-auth-library": "9.10.0"}}')
EX_JWT_LIB = "const jwt = require('jsonwebtoken')\n"
EX_JOSE_LIB = "const { jwtVerify } = require('jose')\nconst JOSE_KEY = new TextEncoder().encode(process.env.JWT_SECRET)\n"
ASYNC_GATE = "app.use(async (req, res, next) => {\n"
EX_CHECKED = "    req.user = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n"
EX_SEEN = "  let seen = null\n  try {\n    seen = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n  } catch (e) {\n"
EX_HOLDER = "async function holder (word) {\n  return User.findOne({ token: word })\n}\n"
EX_TOKENS = {
    "both asked: a token the library checks, and a failure answered with 401":
        (EX_JWT_LIB + _gate("  try {\n" + EX_CHECKED + "  } catch (e) {\n    return res.status(401).end()\n  }\n"
                            "  next()\n"), BOTH_ASKED),
    "both asked: the same with nothing that catches the failure":
        (EX_JWT_LIB + _gate(EX_CHECKED + "  next()\n"), BOTH_ASKED),
    "both asked: the failure handed on as an error":
        (EX_JWT_LIB + _gate("  try {\n" + EX_CHECKED + "  } catch (e) {\n    return next(e)\n  }\n  next()\n"),
         BOTH_ASKED),
    "both asked: the failure answered with a 500, and the way on is inside the try":
        (EX_JWT_LIB + _gate("  try {\n" + EX_CHECKED + "    next()\n  } catch (e) {\n"
                            "    res.status(500).json({ error: 'try again' })\n  }\n"), BOTH_ASKED),
    "both asked: the library's callback says whether the token held":
        (EX_JWT_LIB + _gate("  jwt.verify(req.cookies.token, process.env.JWT_SECRET, (err, user) => {\n"
                            "    if (err) return res.sendStatus(403)\n    req.user = user\n    next()\n  })\n"),
         BOTH_ASKED),
    "both asked: the project's own helper hands back who it is or nothing":
        (EX_JWT_LIB + "function whoIs (token) {\n  try {\n    return jwt.verify(token, process.env.JWT_SECRET)\n"
         "  } catch (e) {\n    return null\n  }\n}\n"
         + _gate("  const user = whoIs(req.cookies.token)\n  if (!user) return res.status(401).end()\n"
                 "  req.user = user\n  next()\n"), BOTH_ASKED),
    "both asked: a token looked up among the people":
        (_gate("  const found = await User.findOne({ token: req.headers.authorization })\n"
               "  if (!found) return res.status(401).end()\n  req.user = found\n  next()\n", ASYNC_GATE), BOTH_ASKED),
    "both asked: an API key looked up with SQL":
        (_gate("  const [rows] = await pool.query('SELECT id FROM users WHERE api_key = ?', [req.headers['x-api-key']])\n"
               "  if (!rows.length) return res.status(401).end()\n  next()\n", ASYNC_GATE), BOTH_ASKED),
    "both asked: whoever is not signed in gets the sign-in page":
        (_gate("  if (!req.session.userId) return res.render('login')\n  next()\n"), BOTH_ASKED),
    "both asked: whoever is not signed in is answered with words and no status":
        (_gate("  if (!req.session.userId) return res.json({ ok: false })\n  next()\n"), BOTH_ASKED),
    "both asked: signed in goes on, and the function ends on a page for everybody else":
        (_gate("  if (req.session.userId) return next()\n  res.render('welcome')\n"), BOTH_ASKED),
    "only the removal asked: the way on under another name, and every GET takes it first":
        ("app.use((req, res, done) => {\n  if (req.method === 'GET') return done()\n"
         "  if (!req.session.userId) return res.status(401).end()\n  done()\n})\n", ONLY_REMOVE_ASKED),
    "neither asked: the failure is caught and the request goes on":
        (EX_JWT_LIB + _gate("  try {\n" + EX_CHECKED + "  } catch (e) {\n    req.user = null\n  }\n  next()\n"),
         NEITHER_ASKED),
    "neither asked: the helper's failure is caught where it is called, and the request goes on":
        (EX_JWT_LIB + "function mustBe (token) {\n  return jwt.verify(token, process.env.JWT_SECRET)\n}\n"
         + _gate("  try {\n    req.user = mustBe(req.cookies.token)\n  } catch (e) {\n    req.user = null\n  }\n"
                 "  next()\n"), NEITHER_ASKED),
    "neither asked: the token is read without being checked":
        (EX_JWT_LIB + _gate("  const seen = jwt.decode(req.cookies.token)\n  if (!seen) return res.status(401).end()\n"
                            "  next()\n"), NEITHER_ASKED),
    "neither asked: a person looked up by an id the caller writes in a header":
        (_gate("  const found = await User.findById(req.headers['x-user-id'])\n"
               "  if (!found) return res.status(401).end()\n  next()\n", ASYNC_GATE), NEITHER_ASKED),
    "neither asked: only that some header was sent":
        (_gate("  if (!req.headers.authorization) return res.status(401).end()\n  next()\n"), NEITHER_ASKED),
    "neither asked: the callback goes on whatever the library said":
        (EX_JWT_LIB + _gate("  jwt.verify(req.cookies.token, process.env.JWT_SECRET, (err, user) => {\n"
                            "    req.user = user\n    next()\n  })\n"), NEITHER_ASKED),
    "neither asked: whoever is not signed in gets a note and goes on":
        (_gate("  if (!req.session.userId) res.locals.note = 'Sign in to see more'\n  next()\n"), NEITHER_ASKED),
    "neither asked: whoever is not signed in is handed on first and answered afterwards":
        (_gate("  if (!req.session.userId) {\n    next()\n    return res.end()\n  }\n  next()\n"), NEITHER_ASKED),
    "neither asked: asked inside the try, and the failure that is caught lets the request on":
        (EX_JWT_LIB + _gate("  try {\n    const seen = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n"
                            "    if (!seen.sub) return res.status(401).end()\n    req.user = seen\n"
                            "  } catch (e) {\n    req.user = null\n  }\n  next()\n"), NEITHER_ASKED),
    "both asked: a failure gives nothing, and whoever has nothing is turned away after the try":
        (EX_JWT_LIB + _gate(EX_SEEN + "    seen = null\n  }\n  if (!seen) return res.status(401).end()\n  next()\n"),
         BOTH_ASKED),
    "neither asked: a failure gives a guest, so nobody is turned away after the try":
        (EX_JWT_LIB + _gate(EX_SEEN + "    seen = { sub: 'guest' }\n  }\n  if (!seen) return res.status(401).end()\n"
                            "  next()\n"), NEITHER_ASKED),
    "both asked: the token is looked up by a helper that is handed it":
        (EX_HOLDER + _gate("  const found = await holder(req.headers.authorization)\n"
                           "  if (!found) return res.status(401).end()\n  next()\n", ASYNC_GATE), BOTH_ASKED),
    "neither asked: the same helper is handed an id the caller writes in a header":
        (EX_HOLDER + _gate("  const found = await holder(req.headers['x-user-id'])\n"
                           "  if (!found) return res.status(401).end()\n  next()\n", ASYNC_GATE), NEITHER_ASKED),
    "both asked: another library checks the token and nothing catches a failure":
        (EX_JOSE_LIB + _gate("  req.seen = await jwtVerify(req.cookies.token, JOSE_KEY)\n  next()\n", ASYNC_GATE),
         BOTH_ASKED),
    "both asked: a failure is turned into nothing in place, and whoever has nothing is turned away":
        (EX_JOSE_LIB + _gate("  const seen = await jwtVerify(req.cookies.token, JOSE_KEY).catch(() => null)\n"
                             "  if (!seen) return res.status(401).end()\n  next()\n", ASYNC_GATE), BOTH_ASKED),
    "neither asked: a failure is turned into nothing in place, and the request goes on":
        (EX_JOSE_LIB + _gate("  req.seen = await jwtVerify(req.cookies.token, JOSE_KEY).catch(() => null)\n  next()\n",
                             ASYNC_GATE), NEITHER_ASKED),
    "both asked: signed in goes on and everybody else gets a page, written as one choice":
        (_gate("  return req.session.userId ? next() : res.render('login')\n"), BOTH_ASKED),
    "neither asked: the name of the page is chosen by who is signed in, and everybody goes on":
        (_gate("  res.locals.page = req.session.userId ? 'home' : 'welcome'\n  next()\n"), NEITHER_ASKED),
    "both asked: the library's promise hands the request on only when the token held":
        (EX_JOSE_LIB + _gate("  jwtVerify(req.cookies.token, JOSE_KEY).then((seen) => {\n    req.seen = seen\n"
                             "    next()\n  }).catch(() => res.status(401).end())\n"), BOTH_ASKED),
    "neither asked: the library's promise is not waited for, and the request goes on beside it":
        (EX_JOSE_LIB + _gate("  jwtVerify(req.cookies.token, JOSE_KEY).then((seen) => {\n    req.seen = seen\n  })\n"
                             "  next()\n"), NEITHER_ASKED),
    "neither asked: what the library hands back is not waited for, and a promise is always something":
        (EX_JOSE_LIB + _gate("  const seen = jwtVerify(req.cookies.token, JOSE_KEY)\n"
                             "  if (!seen) return res.status(401).end()\n  next()\n"), NEITHER_ASKED),
    "both asked: a sign-in service checks the token (firebase-admin)":
        ("const admin = require('firebase-admin')\n"
         + _gate("  req.seen = await admin.auth().verifyIdToken(req.headers.authorization)\n  next()\n", ASYNC_GATE),
         BOTH_ASKED),
    "both asked: a sign-in service checks the token (google-auth-library)":
        ("const { OAuth2Client } = require('google-auth-library')\nconst google = new OAuth2Client()\n"
         + _gate("  req.seen = await google.verifyIdToken({ idToken: req.headers.authorization })\n  next()\n",
                 ASYNC_GATE), BOTH_ASKED),
    "neither asked: the project's own function is called verify and checks nothing":
        ("function verify (word) {\n  return { sub: word }\n}\n"
         + _gate("  req.seen = verify(req.cookies.token)\n  next()\n"), NEITHER_ASKED),
}


@pytest.mark.parametrize("case", sorted(EX_TOKENS))
def test_express_a_login_with_no_telling_name(tmp_path, case):
    gate, want = EX_TOKENS[case]
    fs = _scan(tmp_path, {"server.js": JS + gate + EX_SHOW + EX_ROUTE + "app.listen(3000)\n", "models.js": JS_MODELS,
                          "web/app.js": VERB_PAGE}, project={"package.json": TOKEN_PACKAGE})
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


PY_TOKEN_PROJECT = {"requirements.txt": "flask==3.0.3\nPyJWT==2.8.0\n", "app/__init__.py": "", "web/app.js": VERB_PAGE}
PY_TOKEN_HEAD = ("import os\nimport sqlite3\n\nimport jwt\nfrom flask import Flask, abort, g, render_template, request, "
                 "session\n\napp = Flask(__name__)\nKEY = os.environ['JWT_KEY']\n\n\n"
                 "def db():\n    return sqlite3.connect('app.db')\n\n\n")
PY_CHECKED = "        g.caller = jwt.decode(request.headers.get('Authorization', ''), KEY, algorithms=['HS256'])\n"
PY_TOKENS = {
    "both asked: a token the library checks, and a failure turned away":
        (_hook("    try:\n" + PY_CHECKED + "    except jwt.PyJWTError:\n        abort(401)\n"), BOTH_ASKED),
    "both asked: the same with nothing that catches the failure":
        (_hook(PY_CHECKED[4:]), BOTH_ASKED),
    "both asked: a token looked up among the people":
        (_hook("    row = db().execute('SELECT id FROM users WHERE token = ?', "
               "(request.headers.get('Authorization'),)).fetchone()\n"
               "    if row is None:\n        abort(401)\n    g.caller_id = row[0]\n"), BOTH_ASKED),
    "both asked: whoever is not signed in gets the sign-in page":
        (_hook("    if 'user_id' not in session:\n        return render_template('login.html')\n"), BOTH_ASKED),
    "neither asked: the failure is caught and the request goes on":
        (_hook("    try:\n" + PY_CHECKED + "    except jwt.PyJWTError:\n        g.caller = None\n"), NEITHER_ASKED),
    "neither asked: the token is read with the check switched off":
        (_hook("    seen = jwt.decode(request.headers.get('Authorization', ''), options={'verify_signature': False})\n"
               "    if not seen:\n        abort(401)\n"), NEITHER_ASKED),
    "neither asked: a person looked up by an id the caller writes in a header":
        (_hook("    row = db().execute('SELECT id FROM users WHERE id = ?', "
               "(request.headers.get('X-User-Id'),)).fetchone()\n    if row is None:\n        abort(401)\n"),
         NEITHER_ASKED),
    "neither asked: whoever is not signed in is noted and goes on":
        (_hook("    if 'user_id' not in session:\n        g.guest = True\n"), NEITHER_ASKED),
    "neither asked: whoever is not signed in leaves the hook with nothing, which lets the request on":
        (_hook("    if 'user_id' not in session:\n        return None\n    g.guest = False\n"), NEITHER_ASKED),
    "neither asked: the failure is suppressed and the request goes on":
        (_hook("    from contextlib import suppress\n    with suppress(jwt.PyJWTError):\n" + PY_CHECKED), NEITHER_ASKED),
    "both asked: a failure gives nothing, and whoever has nothing is turned away after the try":
        (_hook("    seen = None\n    try:\n        seen = jwt.decode(request.headers.get('Authorization', ''), KEY, "
               "algorithms=['HS256'])\n    except jwt.PyJWTError:\n        seen = None\n"
               "    if seen is None:\n        abort(401)\n"), BOTH_ASKED),
    "neither asked: asked inside the try, and the failure that is caught lets the request on":
        (_hook("    try:\n        seen = jwt.decode(request.headers.get('Authorization', ''), KEY, algorithms=['HS256'])\n"
               "        if seen.get('sub') is None:\n            abort(401)\n"
               "    except Exception:\n        g.guest = True\n"), NEITHER_ASKED),
    "both asked: another library checks the token (python-jose), and nothing catches a failure":
        (_hook(PY_CHECKED[4:]), BOTH_ASKED),
    "both asked: a sign-in service checks the token (firebase_admin)":
        (_hook("    g.caller = auth.verify_id_token(request.headers.get('Authorization', ''))\n"), BOTH_ASKED),
    "both asked: a sign-in service checks the token (google-auth)":
        (_hook("    g.caller = id_token.verify_oauth2_token(request.headers.get('Authorization', ''), None, KEY)\n"),
         BOTH_ASKED),
    "neither asked: the project's own function is called decode and checks nothing":
        ("def decode(word):\n    return {'sub': word}\n\n\n"
         + _hook("    g.caller = decode(request.headers.get('Authorization', ''))\n"), NEITHER_ASKED),
}
PY_TOKEN_LIBS = {"python-jose": "from jose import jwt\n", "firebase_admin": "import jwt\nfrom firebase_admin import auth\n",
                 "google-auth": "import jwt\nfrom google.oauth2 import id_token\n"}


@pytest.mark.parametrize("case", sorted(PY_TOKENS))
def test_flask_a_login_with_no_telling_name(tmp_path, case):
    before, want = PY_TOKENS[case]
    head = PY_TOKEN_HEAD.replace("import jwt\n", next((v for k, v in PY_TOKEN_LIBS.items() if k in case), "import jwt\n"))
    fs = _scan(tmp_path, {"app/main.py": head + before + VERB_ROUTES}, project=PY_TOKEN_PROJECT)
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


TOKEN_DEP_HEAD = ("import os\nimport sqlite3\n\nimport jwt\nfrom fastapi import Depends, FastAPI, Header, HTTPException\n\n"
                  "app = FastAPI()\nKEY = os.environ['JWT_KEY']\n\n\n"
                  "def get_db():\n    return sqlite3.connect('app.db')\n\n\n")
TOKEN_DEPS = {
    "caught: a dependency with a plain name looks the token up among the people":
        ("def caller(authorization: str = Header(...), db=Depends(get_db)):\n"
         "    row = db.execute('SELECT id FROM users WHERE token = ?', (authorization,)).fetchone()\n"
         "    if row is None:\n        raise HTTPException(401)\n    return row\n\n\n", ["LT-AUTHZ-OWNER"]),
    "caught: a dependency with a plain name has the library check the token":
        ("def caller(authorization: str = Header(...)):\n    try:\n"
         "        return jwt.decode(authorization, KEY, algorithms=['HS256'])\n"
         "    except jwt.PyJWTError:\n        raise HTTPException(401)\n\n\n", ["LT-AUTHZ-OWNER"]),
    "open: the same dependency hands back nothing when the token does not hold":
        ("def caller(authorization: str = Header(...)):\n    try:\n"
         "        return jwt.decode(authorization, KEY, algorithms=['HS256'])\n"
         "    except jwt.PyJWTError:\n        return None\n\n\n", ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
    "open: a dependency with a plain name looks a person up by an id from a header":
        ("def caller(x_user_id: str = Header(...), db=Depends(get_db)):\n"
         "    row = db.execute('SELECT id FROM users WHERE id = ?', (x_user_id,)).fetchone()\n"
         "    if row is None:\n        raise HTTPException(404)\n    return row\n\n\n",
         ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(TOKEN_DEPS))
def test_fastapi_a_login_with_no_telling_name(tmp_path, case):
    dep, want = TOKEN_DEPS[case]
    routes = ("@app.delete('/orders/{order_id}')\ndef remove(order_id: int, who=Depends(caller), db=Depends(get_db)):\n"
              "    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {}\n\n\n"
              "@app.post('/orders')\ndef add(body: dict, who=Depends(caller), db=Depends(get_db)):\n"
              "    db.execute('INSERT INTO orders (item) VALUES (?)', (body['item'],))\n    return {}\n")
    fs = _scan(tmp_path, {"app/main.py": TOKEN_DEP_HEAD + dep + routes}, project=DEP_PROJECT)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- named for a login, and a failed token goes on
# The other side of "what the code does, not what it is called": a function named for a login (`requireAuth`,
# `login_required`, `get_current_user`), or a token library's own call, on the way to a route, where the code lets a
# request go on whose token does not hold or that carries none. Until 2026-11-11 the names check took each of these
# for a login check ("it calls `jwt.decode`"), so such a route read as signed in. Each beside the same name with the
# failure turned away, and beside a soft reader that is followed by a check that does turn away.
NAMED_SOFT = ("  try {\n    req.user = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n  } catch (e) {\n"
              "    req.user = null\n  }\n  next()\n}\n")
NAMED_HARD = NAMED_SOFT.replace("    req.user = null\n", "    return res.status(401).end()\n")
OWN_SOFT = ("  let who = null\n  try {\n    who = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n"
            "  } catch (e) {\n    who = null\n  }\n")
OWN_HARD = OWN_SOFT.replace("    who = null\n  }\n", "    return res.status(401).end()\n  }\n")
EX_SHOWN = "  res.json(await Order.findById(req.params.id))\n"


def _both(mw="", own=""):
    return _js(own + EX_SHOWN, mw=mw) + _js(own + EX_DELETE, mw=mw, verb="delete")


EX_NAMED = {
    "open: a middleware named for a login catches the failure and lets the request on":
        (EX_JWT_LIB + "function requireAuth (req, res, next) {\n" + NAMED_SOFT + _both("requireAuth, "), NEITHER_ASKED),
    "asked: the same name, and the failure is answered with 401":
        (EX_JWT_LIB + "function requireAuth (req, res, next) {\n" + NAMED_HARD + _both("requireAuth, "), BOTH_ASKED),
    "open: the same soft middleware put before every route":
        (EX_JWT_LIB + "function authenticate (req, res, next) {\n" + NAMED_SOFT + "app.use(authenticate)\n" + _both(),
         NEITHER_ASKED),
    "asked: a soft token reader before every route, then the project's own check on the route":
        (EX_JWT_LIB + "function readToken (req, res, next) {\n" + NAMED_SOFT + "app.use(readToken)\n"
         + _both("requireLogin, "), BOTH_ASKED),
    "asked: a soft reader named authenticate, then a plain check of what it left":
        (EX_JWT_LIB + "function authenticate (req, res, next) {\n" + NAMED_SOFT + "app.use(authenticate)\n"
         + "function mustBe (req, res, next) {\n  if (!req.user) return res.status(401).end()\n  next()\n}\n"
         + _both("mustBe, "), BOTH_ASKED),
    "asked: a soft token reader, then a library's login middleware on the route":
        (EX_JWT_LIB + "const { ensureLoggedIn } = require('connect-ensure-login')\n"
         + "function readToken (req, res, next) {\n" + NAMED_SOFT + "app.use(readToken)\n"
         + _both("ensureLoggedIn(), "), BOTH_ASKED),
    "open: the handler itself reads the token and goes on when it does not hold":
        (EX_JWT_LIB + _js(EX_SHOWN, mw="") + _js(OWN_SOFT + EX_DELETE, mw="", verb="delete"), NEITHER_ASKED),
    "asked: the handler itself has the library check the token and answers 401":
        (EX_JWT_LIB + _both(own=OWN_HARD), BOTH_ASKED),
    "open: a middleware named authenticate only reads what the token says, and nothing checks it":
        (EX_JWT_LIB + "function authenticate (req, res, next) {\n  req.user = jwt.decode(req.cookies.token)\n"
         "  next()\n}\n" + _both("authenticate, "), NEITHER_ASKED),
    "open: the same with a library that only reads tokens (jwt-decode)":
        ("const { jwtDecode } = require('jwt-decode')\nfunction authenticate (req, res, next) {\n"
         "  req.user = jwtDecode(req.cookies.token)\n  next()\n}\n" + _both("authenticate, "), NEITHER_ASKED),
    "clean: a soft token reader before every route, and the removal takes only the caller's own order":
        (EX_JWT_LIB + "function readToken (req, res, next) {\n" + NAMED_SOFT + "app.use(readToken)\n"
         + _js(_mine("req.user.sub"), mw="", verb="delete"), []),
    "one finding: a soft token reader, and the handler reads a field of what it left before it removes any order":
        (EX_JWT_LIB + "function readToken (req, res, next) {\n" + NAMED_SOFT + "app.use(readToken)\n"
         + _js("  console.log(req.user.sub)\n" + EX_DELETE, mw="", verb="delete"), ONLY_REMOVE_ASKED),
    "asked: the header is read unchecked to pick the key, and then the library checks the token":
        (EX_JWT_LIB + "function authenticate (req, res, next) {\n  const head = jwt.decode(req.cookies.token)\n"
         "  if (!head) return res.status(401).end()\n" + NAMED_HARD.replace("process.env.JWT_SECRET", "keys[head.kid]")
         + "const keys = { a: process.env.JWT_SECRET }\n" + _both("authenticate, "), BOTH_ASKED),
}


@pytest.mark.parametrize("case", sorted(EX_NAMED))
def test_express_a_check_named_for_a_login_that_lets_a_failed_token_on(tmp_path, case):
    gate, want = EX_NAMED[case]
    fs = _scan(tmp_path, {"server.js": JS + gate + "app.listen(3000)\n", "models.js": JS_MODELS,
                          "web/app.js": VERB_PAGE}, project={"package.json": TOKEN_PACKAGE})
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


PY_WRAP = ("import functools\n\n\ndef login_required(view):\n    @functools.wraps(view)\n    def inner(*a, **kw):\n"
           "        try:\n    " + PY_CHECKED + "        except jwt.PyJWTError:\n            {end}\n"
           "        return view(*a, **kw)\n    return inner\n\n\n")
PY_WRAPPED = VERB_ROUTES.replace("def show", "@login_required\ndef show").replace("def remove",
                                                                                 "@login_required\ndef remove")
PY_NAMED = {
    "open: a decorator named login_required catches the failure and calls the view":
        (PY_WRAP.format(end="g.caller = None"), NEITHER_ASKED),
    "asked: the same decorator turns the failure away":
        (PY_WRAP.format(end="abort(401)"), BOTH_ASKED),
}


@pytest.mark.parametrize("case", sorted(PY_NAMED))
def test_flask_a_check_named_for_a_login_that_lets_a_failed_token_on(tmp_path, case):
    before, want = PY_NAMED[case]
    fs = _scan(tmp_path, {"app/main.py": PY_TOKEN_HEAD + before + PY_WRAPPED}, project=PY_TOKEN_PROJECT)
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


def _token_dep(name, end):
    return (f"def {name}(authorization: str = Header(...)):\n    try:\n"
            "        return jwt.decode(authorization, KEY, algorithms=['HS256'])\n"
            f"    except jwt.PyJWTError:\n        {end}\n\n\n")


def _dep_routes(dep, name, check="", where="", args="(order_id,)", first=""):
    """`check`: lines at the top of both routes. `first`: lines at the top of the removal only."""
    return (f"@app.delete('/orders/{{order_id}}')\ndef remove(order_id: int, {name}=Depends({dep}), "
            f"db=Depends(get_db)):\n{check}{first}    db.execute('DELETE FROM orders WHERE id = ?{where}', {args})\n"
            "    return {}\n\n\n"
            f"@app.post('/orders')\ndef add(body: dict, {name}=Depends({dep}), db=Depends(get_db)):\n{check}"
            "    db.execute('INSERT INTO orders (item) VALUES (?)', (body['item'],))\n    return {}\n")


BOTH_OPEN = ["LW-AUTH-MISSING", "LW-AUTH-MISSING"]
FA_NAMED = {
    "open: a dependency named get_current_user hands back nothing when the token does not hold":
        (_token_dep("get_current_user", "return None") + _dep_routes("get_current_user", "current_user"), BOTH_OPEN),
    "caught: the same name, and the failure is refused":
        (_token_dep("get_current_user", "raise HTTPException(401)") + _dep_routes("get_current_user", "current_user"),
         ["LT-AUTHZ-OWNER"]),
    "caught: nothing comes back for a failed token, and the route turns away whoever has nothing":
        (_token_dep("caller", "return None")
         + _dep_routes("caller", "who", "    if who is None:\n        raise HTTPException(401)\n"), ["LT-AUTHZ-OWNER"]),
    "caught: a second dependency turns away whoever the first one gave nothing for":
        (_token_dep("maybe", "return None") + "def need(who=Depends(maybe)):\n    if who is None:\n"
         "        raise HTTPException(401)\n    return who\n\n\n" + _dep_routes("need", "who"), ["LT-AUTHZ-OWNER"]),
    "open: the second dependency only passes on what the first gave":
        (_token_dep("maybe", "return None") + "def need(who=Depends(maybe)):\n    return who\n\n\n"
         + _dep_routes("need", "who"), BOTH_OPEN),
    "caught: the second dependency passes on what a first one that refuses gave":
        (_token_dep("strict", "raise HTTPException(401)") + "def need(who=Depends(strict)):\n    return who\n\n\n"
         + _dep_routes("need", "who"), ["LT-AUTHZ-OWNER"]),
    # a visitor with no token reaches these two routes and touches nobody's order: the removal asks whose it is. The
    # route that adds an order asks nothing, and is listed
    "one open: nothing comes back for a failed token, and the removal takes only the caller's own order":
        (_token_dep("maybe", "return None")
         + _dep_routes("maybe", "who", where=" AND user_id = ?", args="(order_id, who['sub'])"), ["LW-AUTH-MISSING"]),
    "one open: nothing comes back for a failed token, and the removal compares the order's owner first":
        (_token_dep("maybe", "return None")
         + _dep_routes("maybe", "who", first="    row = db.execute('SELECT user_id FROM orders WHERE id = ?', "
                       "(order_id,)).fetchone()\n    if row is None or row[0] != who['sub']:\n"
                       "        raise HTTPException(404)\n"), ["LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(FA_NAMED))
def test_fastapi_a_check_named_for_a_login_that_lets_a_failed_token_on(tmp_path, case):
    code, want = FA_NAMED[case]
    fs = _scan(tmp_path, {"app/main.py": TOKEN_DEP_HEAD + code}, project=DEP_PROJECT)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_a_route_a_failed_token_reaches_is_said_in_those_words_and_counted(tmp_path):
    """What the finding says is what Lantern found, not more: a token library is called, and nothing it can follow
    turns a request away. With the way from the request to the record where there is one, and counted in the record."""
    from lantern.security import scan
    code = _token_dep("get_current_user", "return None") + _dep_routes("get_current_user", "current_user")
    for rel, text in {**DEP_PROJECT, "app/main.py": TOKEN_DEP_HEAD + code}.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    sec = scan(build_graph(tmp_path), offline=True)
    record = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert record["scope"]["token_check_lets_on"] == 2, record
    open_ = sorted((f for f in sec["findings"] if f["rule"] == "LW-AUTH-MISSING"), key=lambda f: f["line"])
    assert [f["title"].split(",")[0] for f in open_] == [
        "DELETE /orders/{order_id} changes or removes a record picked by an id from the request",
        "POST /orders changes data"], [f["title"] for f in open_]
    for f in open_:
        assert f["title"].endswith("Lantern found nothing that turns away a request whose login token does not hold")
        assert "calls a library that reads a login token" in f["more_info"], f
        assert f["tool"] == "lantern-flow" and f["tool_confidence"] == "LOW" and f["rank"] == "medium", f
    assert open_[0]["flow"]["sink"]["line"] == open_[0]["line"] + 2, open_[0]["flow"]


# ------------------------------------------------------------- the everyday shapes of a token check
# The ways apps write a token check when they follow the usual tutorials and templates (added 2026-11-11, written the
# way those are commonly written, none copied from the held-out apps): each has to read as what it is. Trying them
# showed three defects of the reading itself. One: what a token library hands back was taken for a secret the server
# keeps, because the key stands among the call's arguments, so `if username is None: raise` on the token's subject
# read as "asks for an admin's secret" and no ownership finding was made behind the standard FastAPI dependency.
# Two: a failure that is caught and left with `return None`, followed by a look-up that refuses, read as a login for
# every request, though the request with a bad token had already gone on with nothing. Three: a record reached
# through who is signed in was noted for the whole route also where only some of the requests get to it.
EVERYDAY_HEAD = (TOKEN_DEP_HEAD.replace("import jwt\n", "import jwt\nfrom fastapi.security import OAuth2PasswordBearer\n")
                 + "oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')\n\n\n")
LOOKED_UP = ("    user = db.execute('SELECT id FROM users WHERE name = ?', (username,)).fetchone()\n"
             "    if user is None:\n        raise credentials_exception\n    return user\n\n\n")
UNCHECKED = ("    payload = jwt.decode(authorization, KEY, algorithms=['HS256'], "
             "options={'verify_signature': False})\n")
OWNER_FIRST = ("    row = db.execute('SELECT user_id FROM orders WHERE id = ?', (order_id,)).fetchone()\n"
               "    if row is None or row[0] != who['sub']:\n        raise HTTPException(404)\n")


def _everyday(end):
    return ("def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):\n"
            "    credentials_exception = HTTPException(status_code=401)\n    try:\n"
            "        payload = jwt.decode(token, KEY, algorithms=['HS256'])\n        username = payload.get('sub')\n"
            "        if username is None:\n            raise credentials_exception\n"
            f"    except jwt.PyJWTError:\n        {end}\n" + LOOKED_UP + _dep_routes("get_current_user", "current_user"))


def _by_header(default, body):
    return (f"def get_current_user(authorization: str = Header({default}), db=Depends(get_db)):\n{body}\n\n"
            + _dep_routes("get_current_user", "current_user"))


FA_EVERYDAY = {
    "caught: the token checked in a try, its subject looked up, one 401 raised for every failure":
        (_everyday("raise credentials_exception"), ["LT-AUTHZ-OWNER"]),
    "open: the same dependency hands back nothing for a token that does not hold":
        (_everyday("return None"), BOTH_OPEN),
    "caught: the token's subject is asked for, and a token with none is refused":
        (_by_header("...", "    try:\n        payload = jwt.decode(authorization, KEY, algorithms=['HS256'])\n"
                    "    except jwt.PyJWTError:\n        raise HTTPException(401)\n    sub = payload.get('sub')\n"
                    "    if sub is None:\n        raise HTTPException(401)\n    return sub\n"), ["LT-AUTHZ-OWNER"]),
    "open: nothing comes back when no token was sent":
        (_by_header("None", "    if not authorization:\n        return None\n"
                    "    return jwt.decode(authorization, KEY, algorithms=['HS256'])\n"), BOTH_OPEN),
    "caught: a request with no token is refused":
        (_by_header("None", "    if not authorization:\n        raise HTTPException(401)\n"
                    "    return jwt.decode(authorization, KEY, algorithms=['HS256'])\n"), ["LT-AUTHZ-OWNER"]),
    "open: nothing comes back when no token was sent, and the others are looked up among the people":
        (_by_header("None", "    if not authorization:\n        return None\n"
                    "    payload = jwt.decode(authorization, KEY, algorithms=['HS256'])\n"
                    "    user = db.execute('SELECT id FROM users WHERE name = ?', (payload['sub'],)).fetchone()\n"
                    "    if user is None:\n        raise HTTPException(401)\n    return user\n"), BOTH_OPEN),
    "open: the token is read with the check switched off, and the role it names is compared":
        (_by_header("...", UNCHECKED + "    if payload.get('role') != 'admin':\n        raise HTTPException(403)\n"
                    "    return payload\n"), BOTH_OPEN),
    "open: the token is read with the check switched off, and the removal compares the name in it with the owner":
        ("def maybe(authorization: str = Header(...)):\n" + UNCHECKED.replace("payload = ", "return ") + "\n\n"
         + _dep_routes("maybe", "who", first=OWNER_FIRST), BOTH_OPEN),
}


@pytest.mark.parametrize("case", sorted(FA_EVERYDAY))
def test_fastapi_the_everyday_shapes_of_a_token_check(tmp_path, case):
    code, want = FA_EVERYDAY[case]
    fs = _scan(tmp_path, {"app/main.py": EVERYDAY_HEAD + code}, project=DEP_PROJECT)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


EX_CALLBACK = ("function auth (req, res, next) {\n  const token = req.headers.authorization\n{first}"
               "  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {\n{then}    next()\n  })\n}\n")
EX_GUEST = ("async function auth (req, res, next) {\n  let payload\n  try {\n"
            "    payload = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n  } catch (e) {\n    {end}\n  }\n"
            "  const user = await User.findById(payload.sub)\n  if (!user) return res.status(401).end()\n"
            "  req.user = user\n  next()\n}\n")
EX_EVERYDAY = {
    "asked: no token is answered 401 and a bad one 403, in the library's callback":
        (EX_CALLBACK.replace("{first}", "  if (!token) return res.status(401).end()\n")
         .replace("{then}", "    if (err) return res.sendStatus(403)\n    req.user = user\n"), BOTH_ASKED),
    "open: the library's callback hands every request on, with a person or without":
        (EX_CALLBACK.replace("{first}", "").replace("{then}", "    if (!err) req.user = user\n"), NEITHER_ASKED),
    "asked: the token after the word Bearer, checked in a try, the person looked up, 401 in the catch":
        ("async function auth (req, res, next) {\n  let token\n"
         "  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {\n    try {\n"
         "      token = req.headers.authorization.split(' ')[1]\n"
         "      const decoded = jwt.verify(token, process.env.JWT_SECRET)\n"
         "      req.user = await User.findById(decoded.id)\n      next()\n    } catch (error) {\n"
         "      res.status(401).json({ message: 'Not authorized' })\n    }\n  }\n"
         "  if (!token) {\n    res.status(401).json({ message: 'No token' })\n  }\n}\n", BOTH_ASKED),
    "asked: a failed token is answered 401, and the person is looked up for the others":
        (EX_GUEST.replace("{end}", "return res.status(401).end()"), BOTH_ASKED),
    "open: a failed token goes on as a guest, and the person is looked up for the others":
        (EX_GUEST.replace("{end}", "return next()"), NEITHER_ASKED),
    "asked: the token's subject is asked for after the check":
        ("function auth (req, res, next) {\n  let payload\n  try {\n"
         "    payload = jwt.verify(req.cookies.token, process.env.JWT_SECRET)\n  } catch (e) {\n"
         "    return res.status(401).end()\n  }\n  if (payload.sub == null) return res.status(401).end()\n"
         "  req.user = payload\n  next()\n}\n", BOTH_ASKED),
    "open: 'none' is taken as a way of signing, and the role in the token is compared":
        ("function auth (req, res, next) {\n"
         "  const payload = jwt.verify(req.cookies.token, process.env.JWT_SECRET, { algorithms: ['HS256', 'none'] })\n"
         "  if (payload.role !== 'admin') return res.status(403).end()\n  req.user = payload\n  next()\n}\n",
         NEITHER_ASKED),
}


@pytest.mark.parametrize("case", sorted(EX_EVERYDAY))
def test_express_the_everyday_shapes_of_a_token_check(tmp_path, case):
    gate, want = EX_EVERYDAY[case]
    fs = _scan(tmp_path, {"server.js": JS + EX_JWT_LIB + gate + _both("auth, ") + "app.listen(3000)\n",
                          "models.js": JS_MODELS, "web/app.js": VERB_PAGE}, project={"package.json": TOKEN_PACKAGE})
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


PY_REQUIRED = ("from functools import wraps\n\n\ndef token_required(f):\n    @wraps(f)\n"
               "    def decorated(*args, **kwargs):\n        token = request.headers.get('x-access-token')\n"
               "        if not token:\n            return {'message': 'Token is missing!'}, 401\n        try:\n"
               "            data = jwt.decode(token, KEY, algorithms=['HS256'])\n        except Exception:\n"
               "            {end}\n{then}        return f(*args, **kwargs)\n    return decorated\n\n\n")
PY_PERSON = ("        user = db().execute('SELECT id FROM users WHERE id = ?', (data['sub'],)).fetchone()\n"
             "        if user is None:\n            return {'message': 'Nobody by that name'}, 401\n")
PY_REQUIRING = VERB_ROUTES.replace("def show", "@token_required\ndef show").replace("def remove",
                                                                                   "@token_required\ndef remove")
PY_EVERYDAY = {
    "asked: a decorator named token_required answers 401 for no token and for one that does not hold":
        (PY_REQUIRED.replace("{end}", "return {'message': 'Token is invalid!'}, 401").replace("{then}", ""),
         BOTH_ASKED),
    "open: the same decorator only notes a token that does not hold":
        (PY_REQUIRED.replace("{end}", "data = None").replace("{then}", ""), NEITHER_ASKED),
    "asked: 401 for a token that does not hold, and the person is looked up for the others":
        (PY_REQUIRED.replace("{end}", "return {'message': 'Token is invalid!'}, 401").replace("{then}", PY_PERSON),
         BOTH_ASKED),
    "open: the view is called for a token that does not hold, and the person is looked up for the others":
        (PY_REQUIRED.replace("{end}", "return f(*args, **kwargs)").replace("{then}", PY_PERSON), NEITHER_ASKED),
}


@pytest.mark.parametrize("case", sorted(PY_EVERYDAY))
def test_flask_the_everyday_shapes_of_a_token_check(tmp_path, case):
    before, want = PY_EVERYDAY[case]
    fs = _scan(tmp_path, {"app/main.py": PY_TOKEN_HEAD + before + PY_REQUIRING}, project=PY_TOKEN_PROJECT)
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


# A secret the server keeps asks something of a request only where what the request sent is compared with it. The
# secret asked whether it is set, compared with words of the code, or handed to a call whose answer is then asked
# whether it is there, asks nobody anything: until 2026-11-11 each of these read as "the caller had to send the
# admin's secret", and an admin page behind it was not reported.
SECRET_SIG = "x_admin_key: str = Header(...), user=Depends(get_current_user), db=Depends(get_db)"
SECRET_NEAR = {
    "caught: the admin's secret is only asked whether it is set":
        ("    if os.environ.get('ADMIN_KEY') is None:\n        raise HTTPException(503)\n", ["LT-AUTHZ-ROLE"]),
    "caught: the admin's secret is compared with words of the code":
        ("    if os.environ['ADMIN_KEY'] == 'changeme':\n        raise HTTPException(503)\n", ["LT-AUTHZ-ROLE"]),
    "caught: what a call made with the admin's secret is asked whether it is there":
        ("    client = billing.Client(os.environ['ADMIN_TOKEN'])\n    if client is None:\n"
         "        raise HTTPException(503)\n", ["LT-AUTHZ-ROLE"]),
    "clean: what was sent is compared with the admin's secret kept under a name":
        ("    want = os.environ['ADMIN_KEY']\n    if x_admin_key != want:\n        raise HTTPException(403)\n", []),
    "clean: what was sent is compared with words built from the admin's secret":
        ("    if x_admin_key != 'Key ' + os.environ['ADMIN_KEY']:\n        raise HTTPException(403)\n", []),
}


@pytest.mark.parametrize("case", sorted(SECRET_NEAR))
def test_a_kept_secret_asks_something_only_where_what_was_sent_is_compared_with_it(tmp_path, case):
    check, want = SECRET_NEAR[case]
    code = "import os\n\nimport billing\n\n\n" + _route(check + USERS, sig=SECRET_SIG, path="/admin/users")
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + code})
    assert _authz(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# The tutorial middleware above ("the token after the word Bearer") hands the request on in one place only, deep in
# the branch for a request that carries a token. The same shape with a second way on is open. Written after the fix
# that reads the first (2026-11-11); each of these read right when it was written.
EX_PROTECT = ("async function auth (req, res, next) {\n  let token\n"
              "  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {\n    try {\n"
              "      token = req.headers.authorization.split(' ')[1]\n"
              "      const decoded = jwt.verify(token, process.env.JWT_SECRET)\n"
              "      req.user = await User.findById(decoded.id)\n      next()\n    } catch (error) {\n"
              "      {catch}\n    }\n  }{else}\n  if (!token) {\n    {after}\n  }\n}\n")
EX_IN_BRANCH = ("async function auth (req, res, next) {\n  if (req.headers.authorization) {\n    try {\n"
                "      req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET)\n"
                "    } catch (error) {\n      {catch}\n    }\n    {then}\n  }\n  res.status(401).end()\n}\n")
EX_BY_CALLBACK = ("function auth (req, res, next) {\n  if (req.headers.authorization) {\n"
                  "    jwt.verify(req.headers.authorization, process.env.JWT_SECRET, (err, user) => {\n{first}"
                  "      req.user = user\n      next()\n    })\n  }\n}\n")


def _protect(caught="res.status(401).json({ message: 'Not authorized' })", other="",
             after="res.status(401).json({ message: 'No token' })"):
    return EX_PROTECT.replace("{catch}", caught).replace("{else}", other).replace("{after}", after)


EX_WAYS = {
    "open: the catch hands the request on":
        (_protect(caught="next()"), NEITHER_ASKED),
    "open: a request with no token is handed on after the branch":
        (_protect(after="next()"), NEITHER_ASKED),
    "open: an else hands the request on":
        (_protect(other=" else {\n    return next()\n  }"), NEITHER_ASKED),
    "open: the catch only writes the failure down, and the request is handed on after the try":
        (EX_IN_BRANCH.replace("{catch}", "console.log(error)").replace("{then}", "next()"), NEITHER_ASKED),
    "asked: the same with 401 in the catch":
        (EX_IN_BRANCH.replace("{catch}", "return res.status(401).end()").replace("{then}", "return next()"),
         BOTH_ASKED),
    "open: the library's callback, in the branch for a request with a token, hands every such request on":
        (EX_BY_CALLBACK.replace("{first}", ""), NEITHER_ASKED),
    "asked: the same callback hands on only a request whose token held":
        (EX_BY_CALLBACK.replace("{first}", "      if (err) return res.sendStatus(403)\n"), BOTH_ASKED),
}


@pytest.mark.parametrize("case", sorted(EX_WAYS))
def test_express_a_check_in_a_branch_counts_only_where_no_other_way_hands_the_request_on(tmp_path, case):
    gate, want = EX_WAYS[case]
    fs = _scan(tmp_path, {"server.js": JS + EX_JWT_LIB + gate + _both("auth, ") + "app.listen(3000)\n",
                          "models.js": JS_MODELS, "web/app.js": VERB_PAGE}, project={"package.json": TOKEN_PACKAGE})
    assert _by_verb(fs) == want, [(f["rule"], f["file"], f["line"], f.get("routes")) for f in fs]


# ------------------------------------------------------------- a library's login made optional, a token only carried
# A library's login check made with the word that it is not required turns nobody away, and neither does a FastAPI
# security scheme whose token the handler never looks at: the scheme only carries the token in. Until 2026-11-11 the
# names check took `@jwt_required(optional=True)` and `token: str = Depends(oauth2_scheme)` for a login, whatever
# came of them. Each beside the same library call that does ask, and beside the optional one followed by a refusal.
JWT_HEAD = JWT.replace("get_jwt_identity, jwt_required", "get_jwt_identity, jwt_required, verify_jwt_in_request") \
    .replace("jsonify, request", "abort, jsonify, request")
JWT_DROP = ("@app.delete('/notes/<int:note_id>')\n{above}def drop_note(note_id):\n{first}"
            "    note = Note.query.get_or_404(note_id)\n    db.session.delete(note)\n    db.session.commit()\n"
            "    return jsonify(ok=True)\n")
JWT_OPTIONAL = {
    "asked: the library's decorator as it comes":
        (JWT_DROP.replace("{above}", "@jwt_required()\n").replace("{first}", ""), ["LT-AUTHZ-OWNER"]),
    "open: the decorator is made optional":
        (JWT_DROP.replace("{above}", "@jwt_required(optional=True)\n").replace("{first}", ""), ["LW-AUTH-MISSING"]),
    "open: optional, and the handler only writes down who is calling":
        (JWT_DROP.replace("{above}", "@jwt_required(optional=True)\n")
         .replace("{first}", "    app.logger.info('dropped by %s', get_jwt_identity())\n"), ["LW-AUTH-MISSING"]),
    "asked: optional, and whoever has no token is turned away in the handler":
        (JWT_DROP.replace("{above}", "@jwt_required(optional=True)\n")
         .replace("{first}", "    if get_jwt_identity() is None:\n        abort(401)\n"), ["LT-AUTHZ-OWNER"]),
    "asked: optional, and whoever the library names nobody for is turned away, through a name":
        (JWT_DROP.replace("{above}", "@jwt_required(optional=True)\n")
         .replace("{first}", "    uid = get_jwt_identity()\n    if not uid:\n        abort(401)\n"), ["LT-AUTHZ-OWNER"]),
    "open: optional, and a request with no token is only written down":
        (JWT_DROP.replace("{above}", "@jwt_required(optional=True)\n")
         .replace("{first}", "    if get_jwt_identity() is None:\n        app.logger.info('a guest')\n"),
         ["LW-AUTH-MISSING"]),
    "asked: the library's decorator as it comes, and another call in the handler is made with optional=True":
        (JWT_DROP.replace("{above}", "@jwt_required()\n")
         .replace("{first}", "    extras = dict(optional=True)\n    app.logger.info('dropped', extra=extras)\n"),
         ["LT-AUTHZ-OWNER"]),
    "open: another library's login decorator made optional":
        ("from flask_httpauth import HTTPBasicAuth\n\nauth = HTTPBasicAuth()\n\n\n" +
         JWT_DROP.replace("{above}", "@auth.login_required(optional=True)\n").replace("{first}", ""),
         ["LW-AUTH-MISSING"]),
    "asked: that library's login decorator as it comes":
        ("from flask_httpauth import HTTPBasicAuth\n\nauth = HTTPBasicAuth()\n\n\n" +
         JWT_DROP.replace("{above}", "@auth.login_required\n").replace("{first}", ""), ["LT-AUTHZ-OWNER"]),
    "asked: the library's check is called in the handler":
        (JWT_DROP.replace("{above}", "").replace("{first}", "    verify_jwt_in_request()\n"), ["LT-AUTHZ-OWNER"]),
    "open: the check called in the handler is made optional":
        (JWT_DROP.replace("{above}", "").replace("{first}", "    verify_jwt_in_request(optional=True)\n"),
         ["LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(JWT_OPTIONAL))
def test_flask_a_library_login_made_optional_turns_nobody_away(tmp_path, case):
    body, want = JWT_OPTIONAL[case]
    project = dict(FLASK_PROJECT)
    project["pyproject.toml"] = '[project]\nname="a"\nversion="0"\ndependencies=["flask", "flask-jwt-extended"]\n'
    project["app/models.py"] += ("\n\nclass Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
                                 "    user_id = db.Column(db.Integer)\n    text = db.Column(db.String)\n")
    fs = _scan(tmp_path, {"app/main.py": JWT_HEAD + body}, project=project)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


CARRIED_HEAD = (EVERYDAY_HEAD.replace("import OAuth2PasswordBearer\n", "import HTTPBearer, OAuth2PasswordBearer\n")
                + "bearer = HTTPBearer(auto_error=False)\n\n\n")


def _carried(param, first=""):
    return (f"@app.delete('/orders/{{order_id}}')\ndef remove(order_id: int, {param}, db=Depends(get_db)):\n{first}"
            "    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {}\n")


FA_CARRIED = {
    "open: the bearer token is taken in and never looked at":
        (_carried("token: str = Depends(oauth2_scheme)"), ["LW-AUTH-MISSING"]),
    "open: the same, written with Annotated":
        ("from typing import Annotated\n\n\n" + _carried("token: Annotated[str, Depends(oauth2_scheme)]"),
         ["LW-AUTH-MISSING"]),
    "open: a bearer scheme that does not even ask for a token, never looked at":
        (_carried("cred=Depends(bearer)"), ["LW-AUTH-MISSING"]),
    "asked: the token the scheme carried in is checked in the route":
        (_carried("cred=Depends(bearer)",
                  "    who = jwt.decode(cred.credentials, KEY, algorithms=['HS256'])\n    log_who(who)\n"),
         ["LT-AUTHZ-OWNER"]),
    "kept: the token is handed to code Lantern does not read, and the older reading by names stands":
        (_carried("token: str = Depends(oauth2_scheme)", "    accounts.require(token)\n"), ["LT-AUTHZ-OWNER"]),
}


@pytest.mark.parametrize("case", sorted(FA_CARRIED))
def test_fastapi_a_token_that_is_only_carried_in_is_no_login(tmp_path, case):
    code, want = FA_CARRIED[case]
    fs = _scan(tmp_path, {"app/main.py": CARRIED_HEAD + code}, project=DEP_PROJECT)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


def test_a_login_that_was_passed_over_is_named_in_the_finding(tmp_path):
    """The finding says which thing that looks like a login was not taken for one, and why."""
    fs = _scan(tmp_path, {"app/main.py": CARRIED_HEAD + _carried("token: str = Depends(oauth2_scheme)")},
               project=DEP_PROJECT)
    f = next(f for f in fs if f["rule"] == "LW-AUTH-MISSING")
    assert "`oauth2_scheme` only carries the token in" in f["more_info"], f["more_info"]
    project = dict(FLASK_PROJECT)
    project["pyproject.toml"] = '[project]\nname="a"\nversion="0"\ndependencies=["flask", "flask-jwt-extended"]\n'
    project["app/models.py"] += ("\n\nclass Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
                                 "    user_id = db.Column(db.Integer)\n    text = db.Column(db.String)\n")
    body = JWT_DROP.replace("{above}", "@jwt_required(optional=True)\n").replace("{first}", "")
    fs = _scan(tmp_path / "b", {"app/main.py": JWT_HEAD + body}, project=project)
    f = next(f for f in fs if f["rule"] == "LW-AUTH-MISSING")
    assert "`jwt_required` is made optional here" in f["more_info"], f["more_info"]


# ------------------------------------------------------------- a record changed or removed through its own object
# The everyday way with an object mapper: the record is read by its id into an object, and the object is then
# removed or saved (`db.session.delete(note)`, `note.delete()`, `order.deleteOne()`, `row.destroy()`, a field set and
# `save()` or the session's `commit()`). That is a change of the record that was read. Until 2026-11-11 only the
# read was noted: an owner asked for after the removal was not too late, and a route with no login that removes a
# record this way was not listed. Each beside the same lines in the right order, and beside an object that is only
# read or only changed for the answer (a field blanked before it is shown, nothing saved).
HELD_HEAD = FLASK.replace("import User, db", "import Draft, Note, User, db")
HELD_MODELS = ("\n\nclass Note(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
               "    user_id = db.Column(db.Integer)\n    text = db.Column(db.String)\n"
               "\n\nclass Draft(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n"
               "    user_id = db.Column(db.Integer)\n")
HELD_NOTE = "    note = Note.query.get_or_404(note_id)\n"
HELD_MINE = "    if note.user_id != current_user.id:\n        abort(403)\n"
HELD_DROP = "    db.session.delete(note)\n    db.session.commit()\n"
HELD_FIND = "def find_note(note_id):\n    return Note.query.get_or_404(note_id)\n\n\n"
HELD_DROPPER = ("def drop_note(note_id):\n    note = Note.query.get_or_404(note_id)\n    db.session.delete(note)\n"
                "    db.session.commit()\n{end}\n\n")


def _held(body, verb="delete", login=True, before=""):
    return (before + f"@app.{verb}('/notes/<int:note_id>')\n" + ("@login_required\n" if login else "") +
            "def handle(note_id):\n" + body + "    return jsonify(ok=True)\n")


PY_HELD = {
    "caught: the note is removed through the session, and its owner is compared only afterwards":
        (_held(HELD_NOTE + HELD_DROP + HELD_MINE), ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then the note is removed through the session":
        (_held(HELD_NOTE + HELD_MINE + HELD_DROP), []),
    "caught: nobody is signed in, and the note is removed through the session":
        (_held(HELD_NOTE + HELD_DROP, login=False), ["LW-AUTH-MISSING"]),
    "clean: nobody is signed in, and the note is only read":
        (_held(HELD_NOTE + "    app.logger.info('read %s', note.id)\n", verb="get", login=False), []),
    "caught: the note's own delete, and its owner is compared only afterwards":
        (_held(HELD_NOTE + "    note.delete()\n" + HELD_MINE), ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then the note's own delete":
        (_held(HELD_NOTE + HELD_MINE + "    note.delete()\n"), []),
    "caught: nobody is signed in, and the note's own delete":
        (_held(HELD_NOTE + "    note.delete()\n", login=False), ["LW-AUTH-MISSING"]),
    "caught: a field of the note is set and saved, and its owner is compared only afterwards":
        (_held(HELD_NOTE + "    note.text = request.json['text']\n    note.save()\n" + HELD_MINE, verb="put"),
         ["LT-AUTHZ-OWNER"]),
    "caught: nobody is signed in, a field of the note is set and the session committed":
        (_held(HELD_NOTE + "    note.text = request.json['text']\n    db.session.commit()\n", verb="put", login=False),
         ["LW-AUTH-MISSING"]),
    "clean: nobody is signed in, a field is blanked before the note is shown and nothing is saved":
        (_held(HELD_NOTE + "    note.user_id = None\n    app.logger.info('shown %s', note.text)\n", verb="get",
               login=False), []),
    "clean: nobody is signed in, and the session is committed for a new row, the note itself untouched":
        (_held(HELD_NOTE + "    db.session.add(Draft(user_id=note.user_id))\n    db.session.commit()\n", verb="post",
               login=False), []),
    "caught: nobody is signed in, a helper hands the note back and the route removes it":
        (_held("    note = find_note(note_id)\n" + HELD_DROP, login=False, before=HELD_FIND), ["LW-AUTH-MISSING"]),
    "caught: a helper hands the note back, the route removes it and compares its owner only afterwards":
        (_held("    note = find_note(note_id)\n" + HELD_DROP + HELD_MINE, before=HELD_FIND), ["LT-AUTHZ-OWNER"]),
    "clean: what is removed before the check is the caller's own draft, the note is only read":
        (_held(HELD_NOTE + "    draft = Draft.query.filter_by(user_id=current_user.id).first()\n"
               "    db.session.delete(draft)\n    db.session.commit()\n" + HELD_MINE), []),
    "clean: the note is taken out of a list of the code's own, and its owner is compared afterwards":
        (_held(HELD_NOTE + "    shown = [note]\n    shown.remove(note)\n" + HELD_MINE, verb="get"), []),
    # more shapes, written after the fix (each read right at once)
    "caught: nobody is signed in, the note is read with first() and removed through the session":
        (_held("    note = Note.query.filter_by(id=note_id).first()\n" + HELD_DROP, login=False), ["LW-AUTH-MISSING"]),
    "caught: nobody is signed in, the read is a chain written over three lines":
        (_held("    note = (Note.query\n            .filter_by(id=note_id)\n            .first_or_404())\n" + HELD_DROP,
               login=False), ["LW-AUTH-MISSING"]),
    "not counted: `update` on what was read may be a dict's own in Python (a document read with pymongo)":
        (_held(HELD_NOTE + "    note.update(seen=True)\n", verb="post", login=False), []),
    "caught: nobody is signed in, a helper reads the note by the id it is handed and removes it":
        (_held("    drop_note(note_id)\n", login=False, before=HELD_DROPPER.replace("{end}", "")),
         ["LW-AUTH-MISSING"]),
    "caught: the helper removes the note, and the route compares its owner only afterwards":
        (_held("    note = drop_note(note_id)\n" + HELD_MINE, before=HELD_DROPPER.replace("{end}", "    return note\n")),
         ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then the helper removes the note":
        (_held(HELD_NOTE + HELD_MINE + "    drop_note(note_id)\n", before=HELD_DROPPER.replace("{end}", "")), []),
    "clean: nobody is signed in, and the session is committed with nothing set on the note":
        (_held(HELD_NOTE + "    db.session.commit()\n", verb="post", login=False), []),
    "caught: a field of the note is set and the session committed, and its owner is compared only afterwards":
        (_held(HELD_NOTE + "    note.text = request.json['text']\n    db.session.commit()\n" + HELD_MINE, verb="put"),
         ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then a field is set and the session committed":
        (_held(HELD_NOTE + HELD_MINE + "    note.text = request.json['text']\n    db.session.commit()\n", verb="put"),
         []),
}


@pytest.mark.parametrize("case", sorted(PY_HELD))
def test_flask_a_record_changed_or_removed_through_its_own_object(tmp_path, case):
    body, want = PY_HELD[case]
    project = dict(FLASK_PROJECT)
    project["app/models.py"] += HELD_MODELS
    fs = _scan(tmp_path, {"app/main.py": HELD_HEAD + body}, project=project)
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


JS_HELD_ORDER = "  const order = await Order.findById(req.params.id)\n"
JS_HELD_MINE = "  if (!order || order.user !== req.session.userId) return res.status(403).end()\n"
JS_HELD = {
    "caught: the order is removed with its own method, and its owner is compared only afterwards":
        (_js(JS_HELD_ORDER + "  await order.deleteOne()\n" + JS_HELD_MINE + "  res.status(204).end()\n",
             verb="delete"), ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then the order is removed with its own method":
        (_js(JS_HELD_ORDER + JS_HELD_MINE + "  await order.deleteOne()\n  res.status(204).end()\n", verb="delete"),
         []),
    "caught: nobody is signed in, and the order is removed with its own method":
        (_js(JS_HELD_ORDER + "  await order.remove()\n  res.status(204).end()\n", mw="", verb="delete"),
         ["LW-AUTH-MISSING"]),
    "caught: nobody is signed in, and the row is destroyed":
        (_js("  const row = await Order.findByPk(req.params.id)\n  await row.destroy()\n  res.status(204).end()\n",
             mw="", verb="delete"), ["LW-AUTH-MISSING"]),
    "caught: nobody is signed in, a field of the order is set and saved":
        (_js(JS_HELD_ORDER + "  order.item = String(req.body.item)\n  await order.save()\n  res.json({ ok: true })\n",
             mw="", verb="put"), ["LW-AUTH-MISSING"]),
    "clean: nobody is signed in, a field is blanked before the order is sent and nothing is saved":
        (_js(JS_HELD_ORDER + "  order.user = undefined\n  res.json(order)\n", mw=""), []),
    "clean: nobody is signed in, and the order is only read":
        (_js(JS_HELD_ORDER + "  res.json(order)\n", mw=""), []),
    # more shapes, written after the fix (each read right at once)
    "caught: nobody is signed in, and the row's own update writes a field":
        (_js("  const row = await Order.findByPk(req.params.id)\n  await row.update({ item: String(req.body.item) })\n"
             "  res.json({ ok: true })\n", mw="", verb="put"), ["LW-AUTH-MISSING"]),
    "caught: nobody is signed in, the order is read with exec() and removed with its own method":
        (_js("  const order = await Order.findOne({ _id: req.params.id }).exec()\n  await order.deleteOne()\n"
             "  res.status(204).end()\n", mw="", verb="delete"), ["LW-AUTH-MISSING"]),
    "caught: nobody is signed in, and the order is handed to its repository to remove":
        ("const orderRepository = require('./repo')\n" +
         _js(JS_HELD_ORDER + "  await orderRepository.remove(order)\n  res.status(204).end()\n", mw="", verb="delete"),
         ["LW-AUTH-MISSING"]),
    "clean: nobody is signed in, and the order is taken out of an array of the code's own":
        (_js(JS_HELD_ORDER + "  const list = [order]\n  list.splice(0, 1)\n  res.json(list)\n", mw=""), []),
    "clean: nobody is signed in, and a field is taken off a plain copy of the order":
        (_js("  const order = await Order.findById(req.params.id).lean()\n  delete order.user\n  res.json(order)\n",
             mw=""), []),
    "caught: a field of the order is set and saved, and its owner is compared only afterwards":
        (_js(JS_HELD_ORDER + "  order.item = String(req.body.item)\n  await order.save()\n" + JS_HELD_MINE +
             "  res.json({ ok: true })\n", verb="put"), ["LT-AUTHZ-OWNER"]),
    "clean: the owner is compared, then a field of the order is set and saved":
        (_js(JS_HELD_ORDER + JS_HELD_MINE + "  order.item = String(req.body.item)\n  await order.save()\n"
             "  res.json({ ok: true })\n", verb="put"), []),
}


@pytest.mark.parametrize("case", sorted(JS_HELD))
def test_express_a_record_changed_or_removed_through_its_own_object(tmp_path, case):
    body, want = JS_HELD[case]
    fs = _scan(tmp_path, {"server.js": JS + body, "models.js": JS_MODELS}, project={"package.json": PACKAGE})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


# ------------------------------------------------------------- a function that makes random text is no login check
# 2026-11-11: Lantern's audit of itself asked whose record its own share page shows. The page is read by a random
# link and nobody signs in there; the route's helper calls `secrets.token_urlsafe` for a nonce, and the word `token`
# in that name was taken for a sign of a login (`websec.auth_word`).

NONCE = "import secrets\n\n\ndef nonce():\n    return secrets.token_urlsafe(16)\n\n\n"
BY_LINK = "    row = db.execute('SELECT * FROM orders WHERE share_slug = ?', (slug,)).fetchone()\n"
RANDOM_TEXT = {
    "clean: a page read by its link, and a helper that makes a nonce":
        (NONCE + _route(BY_LINK + "    return {'row': row, 'nonce': nonce()}\n", sig="slug: str, db=Depends(get_db)",
                        path="/s/{slug}"), []),
    "clean: the same, the random text made in the handler":
        ("import secrets\n\n\n" + _route(BY_LINK + "    return {'row': row, 'nonce': secrets.token_hex(8)}\n",
                                         sig="slug: str, db=Depends(get_db)", path="/s/{slug}"), []),
    "caught: the same page behind a login, and nothing asks whose the order is":
        (NONCE + _route(BY_LINK + "    return {'row': row, 'nonce': nonce()}\n",
                        sig="slug: str, user=Depends(get_current_user), db=Depends(get_db)", path="/s/{slug}"),
         ["LT-AUTHZ-OWNER"]),
    "caught: no login, a nonce is made, and the order is removed by its id":
        (NONCE + _route("    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n    return {'ok': nonce()}\n",
                        sig="order_id: int, db=Depends(get_db)", verb="delete"), ["LW-AUTH-MISSING"]),
    "caught: no login, random bytes are made, and the order is removed by its id":
        ("import secrets\n\n\n" +
         _route("    db.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n"
                "    return {'ok': secrets.token_bytes(8).hex()}\n",
                sig="order_id: int, db=Depends(get_db)", verb="delete"), ["LW-AUTH-MISSING"]),
}


@pytest.mark.parametrize("case", sorted(RANDOM_TEXT))
def test_a_function_that_makes_random_text_is_no_sign_of_a_login(tmp_path, case):
    body, want = RANDOM_TEXT[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + body})
    assert _gates(fs) == want, [(f["rule"], f["file"], f["line"]) for f in fs]


@pytest.mark.parametrize("name,word", [("secrets.token_urlsafe", None), ("secrets.token_hex", None),
                                       ("token_bytes", None), ("secrets.token_bytes().hex", None),
                                       ("token_hex_valid", "token"), ("verify_token", "verify token"),
                                       ("get_token", "token"), ("token_required", "token"),
                                       ("check_token_hex", "token")])
def test_the_names_check_reads_a_maker_of_random_text_as_no_auth_word(name, word):
    from lantern import websec
    got = websec.auth_word(name)
    assert (got is None) == (word is None), got
