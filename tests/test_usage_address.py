"""Where the opt-in usage counts go (stage 7 of the 2026-11-09 directive: "the address used for optional usage
reporting"). They are sent to the gateway's own route, the address is looked at before anything leaves, a redirect is
not an acceptance, and a send the gateway did not take is said in Lantern's own words. Every refusal sits beside an
address that must still work. Nothing here leaves this computer: the gateway is the real one, started on 127.0.0.1."""

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from lantern import providers, usage

pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from lantern_gateway.app import Settings, create_app  # noqa: E402

ADMIN = "admin-" + "u" * 20


def _settings(tmp_path) -> Settings:
    return Settings(primary="deepseek", deepseek_url="https://x.test", deepseek_key="k", admin_secret=ADMIN,
                    db_path=str(tmp_path / "gw.db"), free_requests=5)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("LANTERN_GATEWAY_URL", raising=False)
    return tmp_path / "home"


@pytest.fixture
def gateway(tmp_path):
    """The gateway itself on this computer. `url` is written the way every address of the gateway is (it ends in
    /v1); `counts()` is what its owner's page shows of the app: installs and uses per feature."""
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(_settings(tmp_path)), host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    url = f"http://127.0.0.1:{port}/v1"

    def counts() -> tuple[int, dict]:
        req = urllib.request.Request(f"{url}/admin/stats", headers={"authorization": f"Bearer {ADMIN}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            app = json.loads(r.read())["app"]
        return app["installs_total"], {f["feature"]: f["count"] for f in app["features_30d"]}
    yield SimpleNamespace(url=url, counts=counts)
    server.should_exit = True
    th.join(timeout=5)


@pytest.fixture
def stranger():
    """Servers on this computer that are not the gateway. `stranger(answer)` starts one; `answer(method, path)` gives
    `(status, headers, text)`, and `asked` keeps every request it got as `(method, path, body)`."""
    made = []

    def start(answer):
        me = SimpleNamespace(asked=[])

        class H(BaseHTTPRequestHandler):
            def _any(self):
                n = int(self.headers.get("content-length") or 0)
                me.asked.append((self.command, self.path, self.rfile.read(n) if n else b""))
                status, headers, text = answer(self.command, self.path)
                data = text.encode("utf-8")
                self.send_response(status, "Words Of The Server")
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            do_GET = do_POST = _any

            def log_message(self, *a):
                pass
        me.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        me.url = f"http://127.0.0.1:{me.httpd.server_address[1]}"
        threading.Thread(target=me.httpd.serve_forever, daemon=True).start()
        made.append(me)
        return me
    yield start
    for me in made:
        me.httpd.shutdown()
        me.httpd.server_close()


@pytest.fixture
def no_web_answer():
    """Something listens at the address and answers, but not as a web server does."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                continue
            with c:
                try:
                    c.settimeout(2)
                    c.recv(65536)
                    c.sendall(b"this is no web answer\r\n\r\n")
                except OSError:
                    pass
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.getsockname()[1]}/v1"
    stop.set()
    th.join(timeout=5)
    srv.close()


def _counted(feature: str = "analyze") -> None:
    usage.set_enabled(True)
    usage.record(feature)


def _send() -> int:
    """What the command line does when it ends, and the app every six hours."""
    return usage.send(providers.gateway_url())


# ------------------------------------------------------------------------------------------------
# The counts arrive
# ------------------------------------------------------------------------------------------------

def test_the_counts_arrive_at_the_gateway_lantern_is_set_up_with(home, gateway, monkeypatch):
    monkeypatch.setenv("LANTERN_GATEWAY_URL", gateway.url)
    _counted()
    assert _send() == 1
    assert gateway.counts() == (1, {"analyze": 1})
    assert _send() == 0                                           # sent already: nothing new
    usage.record("explain")
    assert _send() == 1                                           # the day's counts changed
    assert gateway.counts() == (1, {"analyze": 1, "explain": 1})


def test_the_address_lantern_ships_with_ends_at_a_route_the_gateway_has(tmp_path):
    to, why = usage.destination(providers.DEFAULT_GATEWAY_URL)
    assert why is None
    there, shipped = urllib.parse.urlsplit(to), urllib.parse.urlsplit(providers.DEFAULT_GATEWAY_URL)
    assert (there.scheme, there.netloc) == (shipped.scheme, shipped.netloc) == ("https", shipped.netloc)
    takes_posts = {r.path for r in create_app(_settings(tmp_path)).routes if "POST" in (getattr(r, "methods", None) or ())}
    assert there.path in takes_posts


def test_an_address_written_without_v1_arrives_as_it_did_before(home, gateway, monkeypatch):
    monkeypatch.setenv("LANTERN_GATEWAY_URL", gateway.url.removesuffix("/v1"))
    _counted()
    assert _send() == 1
    assert gateway.counts() == (1, {"analyze": 1})


def test_a_day_the_gateway_took_is_not_sent_again_whatever_order_its_counts_were_made_in(home, gateway, monkeypatch):
    """What was sent is kept as one text per day and compared with what waits: the two have to be written alike."""
    monkeypatch.setenv("LANTERN_GATEWAY_URL", gateway.url)
    _counted("serve")
    usage.record("analyze")                                       # counted after "serve", and before it in the alphabet
    assert _send() == 1
    assert usage.pending() == [] and _send() == 0
    assert gateway.counts() == (1, {"serve": 1, "analyze": 1})


@pytest.mark.parametrize("nothing", ["", None, 7, ["https://gateway.example/v1"]])
def test_no_gateway_address_is_said_and_nothing_is_tried(home, nothing):
    assert usage.destination(nothing) == (None, usage.WHY_NOT["none"])
    _counted()
    assert usage.send("") == 0
    assert "Not sent: the gateway address is not set. The counts stay on this computer." in usage.describe("")
    assert len(usage.pending()) == 1


def test_the_command_line_sends_what_was_counted_when_it_ends(home, gateway, monkeypatch):
    monkeypatch.setenv("LANTERN_GATEWAY_URL", gateway.url)
    _counted()
    r = subprocess.run([sys.executable, "-m", "lantern.cli", "usage", "--show"], capture_output=True, text=True,
                       encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    assert gateway.counts() == (1, {"analyze": 1})
    assert f"Sent to: {gateway.url}/usage" in r.stdout            # and the person is shown where


def test_no_counts_and_nothing_tried_while_sharing_is_off(home, stranger, monkeypatch):
    s = stranger(lambda method, path: (200, {}, "{}"))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", s.url + "/v1")
    usage.record("analyze")
    assert _send() == 0 and s.asked == []
    assert usage.describe() == "OFF. Nothing is sent anywhere.\nNothing waiting to be sent."


# ------------------------------------------------------------------------------------------------
# The address is looked at before anything leaves
# ------------------------------------------------------------------------------------------------

NOT_HTTPS = "does not begin with https://"
A_SECRET = "holds a name or a password"
NO_COMPUTER = "names no computer"
NO_PORT = "has a port that is not a number"
MORE = "has a question mark or a # part"
NOT_PLAIN = "is not a plain web address"

REFUSED = [
    ("http://gateway.example/v1", NOT_HTTPS),                     # the install id would cross the network in clear
    ("ftp://gateway.example/v1", NOT_HTTPS),
    ("file:///tmp/gateway/v1", NOT_HTTPS),
    ("gateway.example/v1", NOT_HTTPS),
    ("//gateway.example/v1", NOT_HTTPS),
    ("https://name:word@gateway.example/v1", A_SECRET),
    ("https://name@gateway.example/v1", A_SECRET),
    ("https:///v1", NO_COMPUTER),
    ("https://gate_way!.example/v1", NO_COMPUTER),
    ("https://gateway.example:https/v1", NO_PORT),
    ("https://gateway.example:99999/v1", NO_PORT),
    ("https://gateway.example:0/v1", NO_PORT),
    ("https://gateway.example/v1?to=elsewhere", MORE),
    ("https://gateway.example/v1#part", MORE),
    ("https://gateway.example/v1\r\nX-More: 1", NOT_PLAIN),
    ("https://gateway.example/ v1", NOT_PLAIN),
    (" https://gateway.example/v1", NOT_PLAIN),
    ("https://gateway.exämple/v1", NOT_PLAIN),
    ("https://gateway.example\\@other.example/v1", NOT_PLAIN),
    ("https://[::1/v1", NOT_PLAIN),
    ("https://gateway.example/v1\x7f", NOT_PLAIN),
    ("https://" + "a" * 2000 + ".example/v1", NOT_PLAIN),
    ("https://gateway.example/" + "a" * (2001 - len("https://gateway.example//v1")) + "/v1", NOT_PLAIN),   # 2,001 characters
]


@pytest.mark.parametrize("address, why", REFUSED, ids=[f"refused{i}" for i in range(len(REFUSED))])
def test_an_address_no_gateway_has_is_sent_nothing(home, monkeypatch, address, why):
    """The session's guard fails this test when anything is tried for another computer, whatever `send` returns."""
    monkeypatch.setenv("LANTERN_GATEWAY_URL", address)
    _counted()
    assert _send() == 0
    said = usage.describe()
    assert "Not sent: the gateway address " + why in said
    assert address not in said and "word@" not in said            # the address may hold a password: it is not repeated
    assert len(usage.pending()) == 1                              # the counts stay on this computer
    assert usage.destination(address) == (None, next(v for v in usage.WHY_NOT.values() if why in v))


ACCEPTED = [
    ("https://gateway.example/v1", "https://gateway.example/v1/usage"),
    ("https://gateway.example/v1/", "https://gateway.example/v1/usage"),
    ("https://gateway.example", "https://gateway.example/v1/usage"),
    ("HTTPS://Gateway.Example:8443/lantern/v1", "HTTPS://Gateway.Example:8443/lantern/v1/usage"),
    ("https://203.0.113.7/v1", "https://203.0.113.7/v1/usage"),
    ("https://[2001:db8::7]:8443/v1", "https://[2001:db8::7]:8443/v1/usage"),
    ("http://127.0.0.1:8080/v1", "http://127.0.0.1:8080/v1/usage"),
    ("http://localhost:8080/v1", "http://localhost:8080/v1/usage"),
    ("http://[::1]:8080/v1", "http://[::1]:8080/v1/usage"),
    ("https://gateway.example/~team!/v1", "https://gateway.example/~team!/v1/usage"),
    ("https://gateway.example/v10", "https://gateway.example/v10/v1/usage"),
    ("https://gateway.example/" + "a" * (2000 - len("https://gateway.example//v1")) + "/v1",                  # 2,000 characters
     "https://gateway.example/" + "a" * (2000 - len("https://gateway.example//v1")) + "/v1/usage"),
]


@pytest.mark.parametrize("address, to", ACCEPTED)
def test_an_address_a_gateway_may_have_is_taken(address, to):
    assert usage.destination(address) == (to, None)


def test_nothing_leaves_for_another_computer_while_real_providers_are_switched_off(home, monkeypatch):
    """`LANTERN_NO_REAL_PROVIDERS` is the person's switch for "nothing leaves this computer"; the tests run with it.
    Its twin is every test above that reaches the gateway on this computer with the switch on."""
    assert providers.real_providers_off()
    monkeypatch.setenv("LANTERN_GATEWAY_URL", "https://gateway.example/v1")
    _counted()
    assert _send() == 0                                           # and the session's guard saw no try
    said = usage.describe()
    assert "Not sent in this run: real providers are switched off (LANTERN_NO_REAL_PROVIDERS is set)" in said
    assert len(usage.pending()) == 1
    # the twin: without the switch that address is where the counts would go (asked, not tried)
    monkeypatch.delenv("LANTERN_NO_REAL_PROVIDERS")
    assert usage.where() == ("https://gateway.example/v1/usage", None)
    assert "Sent to: https://gateway.example/v1/usage" in usage.describe()


# ------------------------------------------------------------------------------------------------
# What is not an acceptance, and what the person is told
# ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("code", [300, 301, 302, 303, 307, 308])
def test_a_redirect_is_not_an_acceptance(home, stranger, monkeypatch, code):
    other = stranger(lambda method, path: (200, {}, "{}"))
    first = stranger(lambda method, path: (code, {"Location": other.url + "/v1/usage"}, ""))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", first.url + "/v1")
    _counted()
    assert _send() == 0
    assert other.asked == []                                      # nothing was asked of the place it pointed to
    assert [a[:2] for a in first.asked] == [("POST", "/v1/usage")]
    assert len(usage.pending()) == 1                              # and the counts are not marked as sent
    assert "not taken (the gateway answered with a redirect, which Lantern does not follow)" in usage.describe()


@pytest.mark.parametrize("status", [204, 400, 404, 429, 500])
def test_a_send_the_gateway_did_not_take_is_said_and_the_counts_stay(home, stranger, monkeypatch, status):
    s = stranger(lambda method, path: (status, {}, "<b>words of the server</b>"))
    monkeypatch.setenv("LANTERN_GATEWAY_URL", s.url + "/v1")
    _counted()
    assert _send() == 0
    said = usage.describe()
    assert f"Last try {usage.today()}: not taken (the gateway answered {status}). The counts stay on this computer" in said
    assert "words of the server" not in said.lower()              # never text a server sent
    assert len(usage.pending()) == 1


def test_a_gateway_that_cannot_be_reached_is_said(home, monkeypatch):
    monkeypatch.setenv("LANTERN_GATEWAY_URL", f"http://127.0.0.1:{_free_port()}/v1")     # nothing listens there
    _counted()
    assert _send() == 0
    assert "not taken (the gateway could not be reached)" in usage.describe()
    assert len(usage.pending()) == 1


def test_an_answer_that_is_no_web_answer_does_not_stop_lantern(home, no_web_answer, monkeypatch):
    """`send` runs when the command line ends and in the app's background thread: it must come back."""
    monkeypatch.setenv("LANTERN_GATEWAY_URL", no_web_answer)
    _counted()
    assert _send() == 0
    assert "not taken (the gateway gave no answer Lantern could read)" in usage.describe()
    assert len(usage.pending()) == 1


def test_a_day_the_gateway_took_is_said_and_the_rest_stays(home, stranger, monkeypatch):
    """Two days wait; the gateway takes the first and fails on the second."""
    import datetime as dt
    n = []

    def answer(method, path):
        n.append(1)
        return (200, {}, "{}") if len(n) == 1 else (500, {}, "")
    s = stranger(answer)
    monkeypatch.setenv("LANTERN_GATEWAY_URL", s.url + "/v1")
    _counted()
    yesterday = (dt.datetime.now(dt.UTC).date() - dt.timedelta(days=1)).isoformat()
    kept = json.loads((home / "usage.json").read_text(encoding="utf-8"))
    (home / "usage.json").write_text(json.dumps({yesterday: {"explain": 2}, **kept}), encoding="utf-8")
    assert _send() == 1
    assert ("the gateway took the counts of 1 day, then stopped (the gateway answered 500). The rest stay on this "
            "computer") in usage.describe()
    assert [p["day"] for p in usage.pending()] == [usage.today()]


def test_the_last_try_is_said_and_is_forgotten_when_sharing_is_turned_off(home, gateway, monkeypatch):
    monkeypatch.setenv("LANTERN_GATEWAY_URL", gateway.url)
    _counted()
    assert "Last try" not in usage.describe()                     # nothing was tried yet
    assert _send() == 1
    said = usage.describe()
    assert said.startswith("ON.") and f"Sent to: {gateway.url}/usage" in said
    assert f"Last try {usage.today()}: the gateway took the counts of 1 day." in said
    assert _send() == 0 and usage.describe() == said              # nothing waited: that was no try
    usage.set_enabled(False)
    assert not (home / "usage_last.json").exists()
    assert usage.describe() == "OFF. Nothing is sent anywhere.\nNothing waiting to be sent."


def test_a_note_of_the_last_try_that_lantern_did_not_write_says_nothing(home, monkeypatch):
    """The note is a file in Lantern's own folder; what it holds is still never shown as it is."""
    monkeypatch.setenv("LANTERN_GATEWAY_URL", "http://127.0.0.1:9/v1")
    _counted()
    day = usage.today()
    for planted in ({"day": "<script>", "taken": 1}, {"day": day, "taken": "many"}, ["x"], "words",
                    {"day": day.replace("-", ""), "taken": 1}, {"day": 20261110, "taken": 1},
                    {"day": day, "taken": -1}, {"day": day, "taken": 367}, {"day": day, "taken": True},
                    {"day": day, "taken": 0}, {"day": day, "taken": 0, "why": "<b>words</b>"},
                    {"day": day, "taken": 0, "why": "answered"}, {"day": day, "taken": 0, "why": "answered", "status": True},
                    {"day": day, "taken": 0, "why": "answered", "status": 99},
                    {"day": day, "taken": 0, "why": "answered", "status": 600},
                    {"day": day, "taken": 0, "why": "answered", "status": "<b>words</b>"}):
        (home / "usage_last.json").write_text(json.dumps(planted), encoding="utf-8")
        said = usage.describe()
        assert "Last try" not in said and "script" not in said and "words" not in said, planted
    # the twins: notes of the shape Lantern writes, at the edges of what it takes
    for written, sentence in (
            ({"day": day, "taken": 366}, f"Last try {day}: the gateway took the counts of 366 days."),
            ({"day": day, "taken": 2, "why": "unreachable"},
             f"Last try {day}: the gateway took the counts of 2 days, then stopped (the gateway could not be reached)."),
            ({"day": day, "taken": 0, "why": "answered", "status": 100}, f"Last try {day}: not taken (the gateway answered 100)."),
            ({"day": day, "taken": 0, "why": "answered", "status": 599}, f"Last try {day}: not taken (the gateway answered 599).")):
        (home / "usage_last.json").write_text(json.dumps(written), encoding="utf-8")
        assert sentence in usage.describe()


# ------------------------------------------------------------------------------------------------
# The app's Settings
# ------------------------------------------------------------------------------------------------

@pytest.fixture
def ask_app(home, tmp_path, monkeypatch):
    """`lantern serve` on this computer; `ask(path)` reads a route the way its page does."""
    from lantern.server import App, Handler, Store
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(Handler, "app", App(Store(home), "tok-123", httpd.server_address[1]), raising=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def ask(path: str) -> dict:
        req = urllib.request.Request(f"http://127.0.0.1:{httpd.server_address[1]}{path}",
                                     headers={"Cookie": "lantern_token=tok-123", "X-Lantern-Token": "tok-123"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    yield ask
    httpd.shutdown()
    httpd.server_close()


def test_the_app_is_told_whether_the_counts_can_be_sent_and_where(ask_app, monkeypatch):
    usage.set_enabled(True)
    monkeypatch.setenv("LANTERN_GATEWAY_URL", "http://127.0.0.1:9/v1")
    got = ask_app("/api/usage")
    assert (got["enabled"], got["gateway"], got["where"], got["why"]) == (True, True, "http://127.0.0.1:9/v1/usage", None)
    monkeypatch.setenv("LANTERN_GATEWAY_URL", "http://gateway.example/v1")
    got = ask_app("/api/usage")
    assert (got["gateway"], got["where"]) == (False, None) and NOT_HTTPS in got["why"]
    assert "Not sent: " + got["why"] in got["text"]
