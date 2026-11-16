"""One database connection, many requests at the same moment.

The gateway keeps one SQLite connection for every request, and its web server answers requests on several threads.
Whatever is done on that connection has to be done by one thread at a time (`Store.lock`). Until 2026-11-16 three
of the store's functions read from it outside the lock (`user`, `today_requests`, `spend_today`). Two requests at
the same moment could then be answered with a server error, and a sign-in that holds could be read as one nobody
knows.

It was found by the website's own browser check, after the website began to ask the gateway about a sign-in on
every request: a page that makes several requests when it opens then asks the gateway several things at once.

Each case has its twin: a sign-in that was ended, and one nobody issued, is known to none of the requests that ask
together. The website's store, which always read under its lock, is asked the same way.
"""
import ast
import asyncio
import sys
import threading
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))

from lantern_cloud.store import Store as SiteStore  # noqa: E402
from lantern_gateway.app import Settings, Store, create_app  # noqa: E402

ADMIN = "admin-" + "x" * 20
ASKERS, TIMES, COUNTS, DAY = 8, 400, 120, "2026-11-16"


def _at_once(*jobs, seconds: int = 120) -> list:
    """Each job on a thread of its own, all let go together. Gives back what they raised."""
    go, raised = threading.Barrier(len(jobs)), []

    def run(job):
        try:
            go.wait(20)
            job()
        except BaseException as e:      # noqa: BLE001  (the test reads whatever a thread ended with)
            raised.append(e)

    threads = [threading.Thread(target=run, args=(job,), daemon=True) for job in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(seconds)
    assert not any(t.is_alive() for t in threads), "a thread never came back"
    return raised


# ------------------------------------------------------------------------------------------- the gateway's store
def test_a_sign_in_that_holds_is_known_to_every_request_that_asks_at_the_same_moment(tmp_path):
    store = Store(str(tmp_path / "g.db"))
    token = store.sign_in("github:1", "someone")
    row, answers = store.user(token), []
    assert row and not row["disabled"]

    def ask():
        for _ in range(TIMES):
            answers.append(store.user(token))

    raised = _at_once(*[ask] * ASKERS)
    assert raised == [], f"{len(raised)} of {ASKERS} threads ended with an error, the first: {raised[0]!r}"
    unknown = sum(a is None for a in answers)
    assert unknown == 0, f"{unknown} of {len(answers)} questions about a sign-in that holds were answered 'nobody'"
    assert len(answers) == ASKERS * TIMES and all(a == row for a in answers)


def test_a_sign_in_that_was_ended_and_one_nobody_issued_are_known_to_none_of_them(tmp_path):
    """The twin: asking together never makes somebody known."""
    store = Store(str(tmp_path / "g.db"))
    ended, kept = store.sign_in("github:1", "someone"), store.sign_in("github:2", "somebody else")
    assert store.sign_out(ended) == 1
    answers = {"ended": [], "made up": [], "kept": []}

    def ask():
        for _ in range(TIMES // 2):
            answers["ended"].append(store.user(ended))
            answers["made up"].append(store.user("lt_" + "0" * 40))
            answers["kept"].append(store.user(kept))

    assert _at_once(*[ask] * ASKERS) == []
    assert all(a is None for a in answers["ended"] + answers["made up"])
    assert len(answers["kept"]) == ASKERS * (TIMES // 2) and all(a is not None for a in answers["kept"])


def test_a_sign_in_ended_while_others_ask_is_not_known_again_afterwards(tmp_path):
    store = Store(str(tmp_path / "g.db"))
    token = store.sign_in("github:1", "someone")
    back = []

    def ask():
        gone = False
        for _ in range(TIMES):
            known = store.user(token) is not None
            if gone and known:
                back.append(True)
            gone = gone or not known

    def end():
        for _ in range(50):
            store.user(token)
        store.sign_out(token)

    assert _at_once(end, *[ask] * (ASKERS - 1)) == []
    assert back == [] and store.user(token) is None


def test_what_is_counted_while_others_ask_is_counted_once_and_read_whole(tmp_path):
    store = Store(str(tmp_path / "g.db"))
    token = store.sign_in("github:1", "someone")
    h, odd = store.user(token)["hash"], []
    issued = store.stats(DAY, 7)["allowance"]["tokens_issued"]

    def numbers():                      # the owner's dashboard: some thirty reads, one after the other
        for _ in range(COUNTS):
            seen = store.stats(DAY, 7)["allowance"]["tokens_issued"]
            if seen != issued:
                odd.append(("the dashboard", issued, seen))

    def count():
        for _ in range(COUNTS):
            store.record(h, DAY, 10, 0.001, "a-model")

    def ask():
        last = 0
        for _ in range(TIMES):
            now, spent, who = store.today_requests(h, DAY), store.spend_today(DAY), store.user(token)
            if not (last <= now <= 2 * COUNTS and 0 <= spent <= 2 * COUNTS * 0.001 + 1e-9 and who is not None):
                odd.append((last, now, spent, who))
            last = now

    raised = _at_once(count, count, numbers, *[ask] * (ASKERS - 3))
    assert raised == [], f"{len(raised)} threads ended with an error, the first: {raised[0]!r}"
    assert odd == []
    assert store.today_requests(h, DAY) == 2 * COUNTS == store.user(token)["used_requests"]
    assert store.spend_today(DAY) == pytest.approx(2 * COUNTS * 0.001)


def test_a_step_under_the_lock_may_ask_what_another_function_reads_under_it(tmp_path):
    """`hold` looks at the limits and counts in one step, and asks `today_requests` and `spend_today` on the way:
    the lock is one a thread may take again."""
    store = Store(str(tmp_path / "g.db"))
    token = store.sign_in("github:1", "someone")
    h = store.user(token)["hash"]
    with store.lock:
        assert store.today_requests(h, DAY) == 0 and store.spend_today(DAY) == 0.0 and store.user(token)


# ------------------------------------------------------------------------------------------- the gateway itself
def _gateway(tmp_path):
    return create_app(Settings(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="sk-" + "o" * 12,
                               deepseek_model="deepseek-flash", admin_secret=ADMIN, db_path=str(tmp_path / "g.db")),
                      transport=httpx.MockTransport(lambda request: httpx.Response(500)))


def test_the_gateway_answers_many_questions_about_one_sign_in_at_the_same_moment(tmp_path):
    async def main():
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=_gateway(tmp_path)), base_url="http://testserver")
        async with client:
            r = await client.post("/v1/tokens", json={"label": "tester"}, headers={"authorization": f"Bearer {ADMIN}"})
            who, nobody = {"authorization": "Bearer " + r.json()["token"]}, {"authorization": "Bearer lt_" + "0" * 40}
            first = (await client.get("/v1/whoami", headers=who)).json()
            assert first["account"].startswith("token:")
            for _ in range(5):
                asked = [client.get(path, headers=who) for path in ("/v1/whoami", "/v1/allowance") * 20]
                answers = await asyncio.gather(*asked, *[client.get("/v1/whoami", headers=nobody) for _ in range(20)])
                mine, theirs = answers[:40], answers[40:]
                assert [a.status_code for a in mine] == [200] * 40, sorted({a.status_code for a in mine})
                assert all(a.json() == first for a in mine[::2])
                assert [a.status_code for a in theirs] == [401] * 20          # the twin: nobody is let in by the crowd
    asyncio.run(main())


# ------------------------------------------------------------------------------------------- the website's store
def test_the_websites_store_answers_many_at_the_same_moment(tmp_path):
    store = SiteStore(str(tmp_path / "c.db"))
    store.touch_user("github:1", "someone")
    odd = []

    def seen():
        for n in range(COUNTS):
            store.touch_user("github:1", f"someone {n}")

    def ask():
        for _ in range(TIMES):
            who = store.user("github:1")
            if who is None or store.user("github:2") is not None or store.runs_today("github:1") != 0:
                odd.append(who)

    assert _at_once(seen, *[ask] * (ASKERS - 1)) == []
    assert odd == []


# ------------------------------------------------------------------------------------------- how they are written
STORES = [("gateway/lantern_gateway/app.py", "Store"), ("cloud/lantern_cloud/store.py", "Store")]


def _takes_the_lock(node) -> bool:
    return isinstance(node, ast.With) and any(
        isinstance(i.context_expr, ast.Attribute) and i.context_expr.attr == "lock"
        and isinstance(i.context_expr.value, ast.Name) and i.context_expr.value.id == "self" for i in node.items)


def _the_connection(node) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == "db" and isinstance(node.value, ast.Name)
            and node.value.id == "self")


def _outside_the_lock(text: str, name: str) -> list[tuple[str, int, str]]:
    """The uses of a store's one connection, and of the helpers that count on their caller's lock, that stand
    outside `with self.lock:`. A use is a call written on it and also the connection or one of its functions taken
    under another name (`q = self.db.execute`, called three lines further down: the first version of this reading
    looked for calls only and passed such a function by). A helper that counts on its caller is named with an
    underscore, takes no lock itself and uses the connection, or a helper that does; `__init__` is left out,
    because nobody else has the store yet."""
    store = next(n for n in ast.parse(text).body if isinstance(n, ast.ClassDef) and n.name == name)
    methods = [n for n in store.body if isinstance(n, ast.FunctionDef) and n.name != "__init__"]
    bare = [m for m in methods if m.name.startswith("_") and not any(_takes_the_lock(n) for n in ast.walk(m))]
    inner: set[str] = set()
    while True:                 # a helper that only shapes what it is handed touches nothing and is none
        more = {m.name for m in bare if m.name not in inner and any(
            isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self"
            and (n.attr == "db" or n.attr in inner) for n in ast.walk(m))}
        if not more:
            break
        inner |= more
    out = []

    def walk(node, fn, locked):
        locked = locked or _takes_the_lock(node)
        if not locked and isinstance(node, ast.Attribute):
            if _the_connection(node.value):
                out.append((fn, node.lineno, f"self.db.{node.attr}"))
                return
            if _the_connection(node):
                out.append((fn, node.lineno, "self.db"))
            elif isinstance(node.value, ast.Name) and node.value.id == "self" and node.attr in inner:
                out.append((fn, node.lineno, f"self.{node.attr}"))
        for child in ast.iter_child_nodes(node):
            walk(child, fn, locked)

    for m in methods:
        walk(m, m.name, m.name in inner)
    return out


@pytest.mark.parametrize("path, name", STORES, ids=["gateway", "website"])
def test_no_call_on_a_stores_one_connection_stands_outside_its_lock(path, name):
    found = _outside_the_lock((ROOT / path).read_text(encoding="utf-8"), name)
    assert found == [], "; ".join(f"{fn} line {line}: {what}" for fn, line, what in found)


def test_the_reading_of_a_stores_code_tells_a_call_outside_the_lock_from_one_under_it():
    """The check above, on two stores written for it."""
    safe = ("class Store:\n"
            "    def __init__(self):\n        self.db.execute('create')\n"
            "    def user(self, h):\n        with self.lock:\n            return self._row(h)\n"
            "    def _row(self, h):\n        return self.db.execute('select', (h,)).fetchone()\n"
            "    def _all(self, sql):\n        with self.lock:\n            return self.db.execute(sql).fetchall()\n"
            "    def names(self):\n        return [self._shape(row) for row in self._all('select')]\n"
            "    def _shape(self, row):\n        return dict(row)\n")
    assert _outside_the_lock(safe, "Store") == []
    unsafe = safe.replace("        with self.lock:\n            return self._row(h)\n", "        return self._row(h)\n")
    assert _outside_the_lock(unsafe, "Store") == [("user", 5, "self._row")]
    late = safe + ("    def count(self, h):\n        with self.lock:\n            self.db.execute('update')\n"
                   "        self.db.commit()\n")
    assert _outside_the_lock(late, "Store") == [("count", 19, "self.db.commit")]
    by_name = safe + ("    def numbers(self):\n        q = self.db.execute\n"
                      "        return q('select').fetchall()\n")
    assert _outside_the_lock(by_name, "Store") == [("numbers", 17, "self.db.execute")]
    handed = safe + "    def copy(self, to):\n        return backup(self.db, to)\n"
    assert _outside_the_lock(handed, "Store") == [("copy", 17, "self.db")]
