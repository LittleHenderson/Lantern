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
         [("LT-AUTHZ-OWNER", JS_AT)]),
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
                verb="delete"), [("LT-AUTHZ-OWNER", PY_AT)]),
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
