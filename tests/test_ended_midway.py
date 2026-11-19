"""A sign-in checked under a lock that is let go before the change it allows (lantern/staleauth.py). Examples of
Lantern's own, written after another review tool named the shape in a project Lantern was measured on (none copied
from it). Each dangerous example stands beside safe twins and look-alikes."""
import textwrap

from lantern import staleauth
from lantern.engine import build_graph
from lantern.security import scan


def d(text: str) -> str:
    return textwrap.dedent(text).lstrip()


def got(text):
    return [(c["check"], [(u["check_line"], u["change"]) for u in c["uses"]], c["ended_by"])
            for c in staleauth.read(text)]


SERVER = d('''
    import hmac
    import secrets
    import threading


    class Server:
        def __init__(self, store):
            self._lock = threading.Lock()
            self._token = secrets.token_hex(16)
            self.store = store

        def token_ok(self, token):
            with self._lock:
                return hmac.compare_digest(token, self._token)

        def sign_out(self):
            with self._lock:
                self._token = secrets.token_hex(16)

        def delete_note(self, token, note_id):
            if not self.token_ok(token):
                raise PermissionError("signed out")
            self.store.delete_note(note_id)
''')

EPOCH = d('''
    import threading


    class Sessions:
        def __init__(self):
            self._guard = threading.RLock()
            self._epoch = 1

        def current(self, epoch):
            with self._guard:
                if self._epoch != epoch:
                    return False
                return True

        def revoke_all(self):
            with self._guard:
                self._epoch += 1


    def handle(sessions, bank, epoch, amount):
        if sessions.current(epoch):
            bank.transfer(amount)
''')

LOOP = d('''
    import threading


    class Hub:
        def __init__(self):
            self.auth_lock = threading.Lock()
            self.secret = "x"

        def allowed(self, sent):
            with self.auth_lock:
                return sent == self.secret

        def rotate_secret(self, new):
            with self.auth_lock:
                self.secret = new

        def serve(self, sent, jobs):
            for job in jobs:
                if not self.allowed(sent):
                    break
                job.execute()
''')

NESTED = d('''
    import threading


    class App:
        def __init__(self):
            self._auth_lock = threading.Lock()
            self._session_epoch = "a"

        def _check(self, epoch):
            with self._auth_lock:
                return epoch == self._session_epoch

        def reset_session(self):
            with self._auth_lock:
                self._session_epoch = "b"

        def make_handler(self):
            outer = self

            class Handler:
                def do_POST(self, epoch, body):
                    if not outer._check(epoch):
                        self.reply_unauthorized()
                        return
                    outer.config.set_limit(body["limit"])

            return Handler
''')

ASYNC = d('''
    import asyncio


    class Gate:
        def __init__(self):
            self.lock = asyncio.Lock()
            self.api_key = "k"

        def valid(self, key):
            with self.lock:
                return key == self.api_key

        def revoke_key(self):
            with self.lock:
                self.api_key = None

    async def pay(gate, key, orders, oid):
        if not gate.valid(key):
            return {"error": "no"}
        await orders.place_order(oid)
''')


def test_a_check_let_go_before_the_change_is_found():
    assert got(SERVER) == [("token_ok", [(21, "delete_note")], ["sign_out"])]
    assert got(EPOCH) == [("current", [(21, "transfer")], ["revoke_all"])]
    assert got(LOOP) == [("allowed", [(19, "execute")], ["rotate_secret"])]
    assert got(NESTED) == [("_check", [(22, "set_limit")], ["reset_session"])]
    assert got(ASYNC) == [("valid", [(18, "place_order")], ["revoke_key"])]


def test_its_twins_are_not():
    held = SERVER.replace("        if not self.token_ok(token):\n            raise PermissionError(\"signed out\")\n"
                          "        self.store.delete_note(note_id)\n",
                          "        with self._lock:\n            if not hmac.compare_digest(token, self._token):\n"
                          "                raise PermissionError(\"signed out\")\n            self.store.delete_note(note_id)\n")
    assert held != SERVER and got(held) == []                    # the change is made under the same lock
    held_outside = SERVER.replace("        if not self.token_ok(token):\n            raise PermissionError(\"signed out\")\n"
                                  "        self.store.delete_note(note_id)\n",
                                  "        with self._lock:\n            if not self.token_ok(token):\n"
                                  "                raise PermissionError(\"signed out\")\n"
                                  "            self.store.delete_note(note_id)\n")
    assert held_outside != SERVER and got(held_outside) == []    # the lock held across both
    never_ended = SERVER.replace("        with self._lock:\n            self._token = secrets.token_hex(16)\n",
                                 "        pass\n")
    assert never_ended != SERVER and got(never_ended) == []      # nothing ends the sign-in
    no_lock = SERVER.replace("        with self._lock:\n            return hmac", "        return hmac")
    assert no_lock != SERVER and got(no_lock) == []              # no lock in the check: not this shape
    only_reads = SERVER.replace("self.store.delete_note(note_id)", "return self.store.read_note(note_id)")
    assert got(only_reads) == []                                 # nothing changes after the check
    not_sign_in = SERVER.replace("self._token", "self._colour").replace("compare_digest(token, self._colour)",
                                                                       "compare_digest(token, self._colour)")
    assert got(not_sign_in) == []                                # the field says nothing of a sign-in
    ended_in_init = SERVER.replace("def sign_out(self)", "def __init__(self)")
    assert got(ended_in_init) == []                              # only the object's start sets it


def test_it_runs_in_a_check_and_skips_test_code(tmp_path):
    for rel, text in {"app/server.py": SERVER, "tests/test_server.py": EPOCH}.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    found = [f for f in scan(build_graph(tmp_path), offline=True)["findings"] if f["rule"] == staleauth.RULE]
    assert [(f["file"], f["line"]) for f in found] == [("app/server.py", 21)]
    f = found[0]
    assert f["tool_confidence"] == "LOW" and f["rank"] == "medium" and f["scenario"]["kind"] != "generic"
    assert f["ended_midway"]["ended_by"] == ["sign_out"] and f["ended_midway"]["uses"][0]["change"] == "delete_note"
