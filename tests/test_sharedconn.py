"""`LW-SHARED-CONNECTION`: one database connection for every thread, used with no lock held.

A program that opens one SQLite connection with the library's own guard switched off (`check_same_thread=False`),
keeps it for the whole program and uses it on more than one thread without a lock answers two requests of the same
moment on the one connection together: one of them gets an error out of the library, or an answer that is empty
or the other request's. A heuristic (it reads one file's own text and does not know how the program is run), so
each dangerous example stands beside twins that must stay quiet.
"""
import time

from lantern import sharedconn
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-SHARED-CONNECTION"

# One connection on `self`, a lock that some functions take: `user` and `numbers` do not.
STORE_PY = '''import sqlite3
import threading


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("create table if not exists users (hash text primary key, name text)")
        self.lock = threading.Lock()

    def save(self, h, name):
        with self.lock:
            self.db.execute("insert into users values (?, ?)", (h, name))
            self.db.commit()

    def user(self, h):
        return self.db.execute("select name from users where hash = ?", (h,)).fetchone()

    def numbers(self):
        q = self.db.execute
        return q("select count(*) from users").fetchone()[0]

    def close(self):
        self.db.close()
'''

# The same store with every use under the lock: a helper only locked code calls, a decorator, an `acquire()`.
SAFE_STORE_PY = '''import sqlite3
import threading


def with_lock(fn):
    def inner(self, *a):
        with self.lock:
            return fn(self, *a)
    return inner


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("create table if not exists users (hash text primary key, name text)")
        self.lock = threading.RLock()
        self._tidy()

    def _tidy(self):
        self.db.execute("delete from users where name is null")

    def save(self, h, name):
        with self.lock:
            self.db.execute("insert into users values (?, ?)", (h, name))
            self.db.commit()

    def user(self, h):
        with self.lock:
            return self._row(h)

    def _row(self, h):
        return self.db.execute("select name from users where hash = ?", (h,)).fetchone()

    @with_lock
    def numbers(self):
        q = self.db.execute
        return q("select count(*) from users").fetchone()[0]

    def names(self):
        self.lock.acquire()
        try:
            return self.db.execute("select name from users").fetchall()
        finally:
            self.lock.release()

    def close(self):
        self.db.close()
'''

# One connection at the top of the file, no lock anywhere, handlers that are plain functions.
NOTES_PY = '''import sqlite3

from flask import Flask, jsonify

app = Flask(__name__)
conn = sqlite3.connect("notes.db", check_same_thread=False)
conn.execute("create table if not exists notes (id integer primary key, text text)")


@app.route("/notes")
def notes():
    return jsonify(conn.execute("select id, text from notes").fetchall())


@app.route("/notes/count")
def count():
    return jsonify(conn.execute("select count(*) from notes").fetchone()[0])
'''

# The connection comes from a function of the file, and a thread is handed the function that uses it.
JOBS_PY = '''import sqlite3
import threading

PATH = "jobs.db"


def connect():
    c = sqlite3.connect(PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


db = connect()


def worker():
    while True:
        row = db.execute("select id from jobs where done = 0").fetchone()
        if row is None:
            return
        db.execute("update jobs set done = 1 where id = ?", (row["id"],))


def start():
    for _ in range(4):
        threading.Thread(target=worker).start()
'''

# Opened when first asked for, under a name of the file, with `connect` under a name of its own.
LAZY_PY = '''from sqlite3 import connect as open_db

_conn = None


def db():
    global _conn
    if _conn is None:
        _conn = open_db("lazy.db", check_same_thread=False)
    return _conn


def count():
    return _conn.execute("select count(*) from things").fetchone()[0]
'''

# A handler on the event loop and a plain one: the loop's thread and a worker thread are two.
MIXED_PY = '''import sqlite3

from fastapi import FastAPI

app = FastAPI()
conn = sqlite3.connect("mixed.db", check_same_thread=False)


@app.get("/a")
async def a():
    return conn.execute("select 1").fetchone()


@app.get("/b")
def b():
    return conn.execute("select 2").fetchone()
'''

# Twins of the last one and of the notes app: every handler on the event loop, with a helper only they call.
LOOP_PY = '''import sqlite3

from fastapi import FastAPI

app = FastAPI()
conn = sqlite3.connect("loop.db", check_same_thread=False)


def first(sql):
    return conn.execute(sql).fetchone()


@app.get("/a")
async def a():
    return first("select 1")


@app.get("/b")
async def b():
    return conn.execute("select 2").fetchone()
'''

# Not shared, or not said to be: a connection for each call, one for each thread, the library's guard left on, a
# parameter that happens to bear the connection's name, another library's connection, a pool's own setting.
APART_PY = '''import sqlite3
import threading

import aiosqlite
from sqlalchemy import create_engine

local = threading.local()
guarded = sqlite3.connect("guarded.db")
conn = sqlite3.connect("shared.db", check_same_thread=False)
lock = threading.Lock()
engine = create_engine("sqlite:///pool.db", connect_args={"check_same_thread": False})


def each_call(note):
    c = sqlite3.connect("each.db", check_same_thread=False)
    try:
        c.execute("insert into notes (text) values (?)", (note,))
        c.commit()
    finally:
        c.close()


def each_thread():
    if not hasattr(local, "conn"):
        local.conn = sqlite3.connect("thread.db", check_same_thread=False)
    return local.conn.execute("select 1").fetchone()


def guard_on():
    return guarded.execute("select 1").fetchone()


def export(conn, to):
    return conn.execute("select * from notes").fetchall(), to


def under_the_lock():
    with lock:
        return conn.execute("select 1").fetchone()


async def another_library(path):
    other = await aiosqlite.connect(path, check_same_thread=False)
    return await other.execute("select 1")


def set_up():
    conn.execute("create table if not exists notes (text text)")


set_up()
'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


APP = {"server/__init__.py": "", "server/store.py": STORE_PY, "server/safe_store.py": SAFE_STORE_PY,
       "server/notes.py": NOTES_PY, "server/jobs.py": JOBS_PY, "server/lazy.py": LAZY_PY,
       "server/mixed.py": MIXED_PY, "server/loop.py": LOOP_PY, "server/apart.py": APART_PY}


def test_a_shared_connection_used_with_no_lock_is_named_and_its_safe_twins_are_not(tmp_path):
    """Dangerous: a store whose lock two functions do not take (one of them takes the connection's `execute` under
    another name), a connection at the top of a file with plain handlers and no lock, one made by a function of
    the file and used by a thread's target, one opened when first asked for, and a plain handler beside one on
    the event loop. Safe twins: every use under the lock (a helper only locked code calls, a decorator, an
    `acquire()`), every handler on the event loop, a connection for each call or each thread, the library's own
    guard left on, a parameter with the connection's name, another library, a pool's setting, set-up at the top
    of the file. One finding for each connection, on the first such line, naming the other functions."""
    _write(tmp_path, APP)
    all_of = scan(build_graph(tmp_path))["findings"]
    found = sorted((f["file"], f["line"], f["snippet"]) for f in all_of if f["rule"] == RULE)
    assert found == [
        ("server/jobs.py", 18, 'row = db.execute("select id from jobs where done = 0").fetchone()'),
        ("server/lazy.py", 14, 'return _conn.execute("select count(*) from things").fetchone()[0]'),
        ("server/mixed.py", 11, 'return conn.execute("select 1").fetchone()'),
        ("server/notes.py", 12, 'return jsonify(conn.execute("select id, text from notes").fetchall())'),
        ("server/store.py", 17, 'return self.db.execute("select name from users where hash = ?", (h,)).fetchone()'),
    ], found
    by_file = {f["file"]: f for f in all_of if f["rule"] == RULE}
    one = by_file["server/store.py"]
    assert one["tool_confidence"] == "LOW" and one["rank"] == "medium" and one["cwe"] == 567
    assert "`self.db`" in one["title"] and "`user`" in one["title"] and "Heuristic" in one["more_info"]
    assert "Line 7 opens" in one["more_info"] and "`numbers` (line 20)" in one["more_info"], one["more_info"]
    assert "2 other uses of it in this file stand under a lock; these do not." in one["more_info"]
    assert "`close`" not in one["more_info"]
    assert "found no lock around any use" in by_file["server/notes.py"]["more_info"]
    assert "`count` (line 17)" in by_file["server/notes.py"]["more_info"]
    assert "`b` (line 16)" in by_file["server/mixed.py"]["more_info"]
    story = one["scenario"]
    assert "at the same moment" in " ".join(story["steps"]) and "one database connection" in story["harm"]


def test_what_the_reading_of_one_file_gives_back():
    """The reading by itself, on the texts above: where each connection is opened, how the code writes it, how
    many uses stand under a lock and which functions use it with none held."""
    assert sharedconn.read(STORE_PY) == [
        {"opened": 7, "shown": "self.db", "held": 2, "places": [("user", 17), ("numbers", 20)]}]
    assert sharedconn.read(NOTES_PY) == [
        {"opened": 6, "shown": "conn", "held": 0, "places": [("notes", 12), ("count", 17)]}]
    assert sharedconn.read(JOBS_PY) == [{"opened": 13, "shown": "db", "held": 0, "places": [("worker", 18)]}]
    assert sharedconn.read(LAZY_PY) == [{"opened": 9, "shown": "_conn", "held": 0, "places": [("count", 14)]}]
    assert sharedconn.read(MIXED_PY) == [{"opened": 6, "shown": "conn", "held": 0, "places": [("a", 11), ("b", 16)]}]
    for safe in (SAFE_STORE_PY, LOOP_PY, APART_PY):
        assert sharedconn.read(safe) == []


def test_one_changed_line_makes_a_safe_twin_dangerous():
    """Each twin is quiet for the one reason it shows: take that away and it is named."""
    no_lock = SAFE_STORE_PY.replace("        with self.lock:\n            return self._row(h)\n",
                                    "        return self._row(h)\n")
    assert [c["places"] for c in sharedconn.read(no_lock)] == [[("_row", 31)]]
    plain = LOOP_PY.replace("async def b():", "def b():")
    assert [c["places"] for c in sharedconn.read(plain)] == [[("first", 10), ("b", 20)]]
    late = SAFE_STORE_PY.replace("            self.db.commit()\n", "        self.db.commit()\n")
    assert [c["places"] for c in sharedconn.read(late)] == [[("save", 25)]]
    handed = LOOP_PY + "\n\ndef start(pool):\n    pool.submit(first, 'select 3')\n"
    assert [c["places"] for c in sharedconn.read(handed)] == [[("first", 10), ("b", 20)]]


def test_nothing_is_said_of_test_code_and_of_examples(tmp_path):
    """Test files and the examples of a project's documents are not the app."""
    _write(tmp_path, {"tests/__init__.py": "", "tests/test_store.py": STORE_PY, "docs/example.py": NOTES_PY,
                      "examples/jobs.py": JOBS_PY})
    assert [f for f in scan(build_graph(tmp_path))["findings"] if f["rule"] == RULE] == []


def test_files_built_to_hold_the_check_up_are_read_in_bounded_time_or_passed_by(tmp_path):
    """A file of five thousand functions that each use the connection is read in bounded time; one that is nested
    too deep to read, one that is no Python, and one over the size that is read are passed by without a word, and
    the files beside them are still read."""
    many = ("import sqlite3\nconn = sqlite3.connect('m.db', check_same_thread=False)\n"
            + "".join(f"def f{i}():\n    return conn.execute('select {i}')\n" for i in range(5_000)))
    deep = ("import sqlite3\nconn = sqlite3.connect('d.db', check_same_thread=False)\n"
            "def f():\n    return " + "(" * 5000 + "conn" + ")" * 5000 + "\n")
    broken = "import sqlite3\nconn = sqlite3.connect('b.db', check_same_thread=False\ndef f(:\n"
    large = NOTES_PY + "# " + "x" * sharedconn.MOST_FILE + "\n"
    _write(tmp_path, {"app/__init__.py": "", "app/many.py": many, "app/deep.py": deep, "app/broken.py": broken,
                      "app/large.py": large, "app/notes.py": NOTES_PY})
    g = build_graph(tmp_path)
    began = time.monotonic()
    found = sharedconn.shared_connections(g)
    assert time.monotonic() - began < 10
    assert sorted((f["file"], f["line"]) for f in found) == [("app/many.py", 4), ("app/notes.py", 12)]
    assert "and 4993 more" in next(f for f in found if f["file"] == "app/many.py")["more_info"]
