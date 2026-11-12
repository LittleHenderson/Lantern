"""What the gateway does with requests nobody signed in for (stage 7 of the 2026-11-09 directive: "verify abuse
controls on sign-in and telemetry without breaking endpoints that are intentionally anonymous").

Each refusal sits beside the ordinary use that must keep working: a usage report from an app, a person signing in,
the owner opening their page. Nothing here leaves this computer: the gateway is the real one, the model and GitHub
are stand-ins, and a sender's address is a header the test writes (`Fly-Client-IP`, the one Fly's proxy sets)."""

import asyncio
import contextlib
import datetime as dt
import json
import socket
import sqlite3
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from lantern_gateway import app as gateway_app  # noqa: E402
from lantern_gateway.app import Settings, Store, create_app  # noqa: E402

ADMIN = "admin-" + "k" * 24
CLI = "c" * 40
# where the clock of the limits stands in these tests: 40 s into its minute, 2,800 s into its hour, 6,400 s into its day
START = 1_000_000_000.0
PIECE = 65536


def today() -> str:
    return dt.datetime.now(dt.UTC).date().isoformat()


def stand_ins(calls: list, github: str = "ok"):
    """The model and GitHub. `github`: "ok" (the code `good` signs in user 42), "down" (cannot be reached) or
    "odd" (answers with a list)."""
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.host, request.url.path))
        if request.url.host in ("github.com", "api.github.com"):
            if github == "down":
                raise httpx.ConnectError("no route to host", request=request)
            if github == "odd":
                return httpx.Response(200, json=["not", "a", "table"])
            if request.url.host == "github.com":
                body = dict(x.split("=", 1) for x in request.content.decode().split("&"))
                if body.get("code") != "good":
                    return httpx.Response(400, json={"error": "bad_verification_code"})
                return httpx.Response(200, json={"access_token": "at_good"})
            return httpx.Response(200, json={"id": 42, "login": "octocat"})
        return httpx.Response(200, json={
            "id": "c1", "model": "m", "usage": {"prompt_tokens": 7, "completion_tokens": 11},
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "{}"}}]})
    return httpx.MockTransport(handler)


class Gateway:
    def __init__(self, tmp_path, github: str = "ok", **over):
        self.calls: list = []
        self.s = Settings(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="k", admin_secret=ADMIN,
                          db_path=str(tmp_path / "gw.db"), public_url="https://gw.test", github_client_id="gh-id",
                          github_client_secret="gh-secret", **over)
        self.app = create_app(self.s, transport=stand_ins(self.calls, github))
        self.app.state.limiter.clock = lambda: START        # stands still until `later` moves it
        self.client = TestClient(self.app, follow_redirects=False, raise_server_exceptions=False)

    def ping(self, install: str = "a" * 32, sender: str = "203.0.113.5", **over):
        body = {"install": install, "day": today(), "version": "0.10.0", "os": "Linux", "features": {"analyze": 2}, **over}
        return self.client.post("/v1/usage", json=body, headers={"Fly-Client-IP": sender})

    def stats(self, sender: str = "198.51.100.1", secret: str = ADMIN):
        return self.client.get("/v1/admin/stats", headers={"authorization": f"Bearer {secret}", "Fly-Client-IP": sender})

    def shown(self) -> dict:
        """What the owner's page shows of the app."""
        return self.stats().json()["app"]

    def link(self, cli: str = CLI) -> str:
        """A sign-in link's `state`, as GitHub would hand it back."""
        r = self.client.get("/v1/auth/github/start", params={"cli": cli})
        assert r.status_code == 302
        return dict(x.split("=", 1) for x in r.headers["location"].split("?", 1)[1].split("&"))["state"]

    def back(self, state: str, code: str = "good", sender: str = "203.0.113.5"):
        return self.client.get("/v1/auth/github/callback", params={"code": code, "state": state},
                               headers={"Fly-Client-IP": sender})

    def asked_github(self) -> int:
        return sum(1 for c in self.calls if c[1] in ("github.com", "api.github.com"))

    def asked_model(self) -> int:
        return sum(1 for c in self.calls if c[1] == "upstream.test")

    def token(self) -> str:
        return self.client.post("/v1/tokens", json={"label": "t"}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]

    def later(self, seconds: float) -> None:
        """Move the clock the limits count by."""
        now = self.app.state.limiter.clock() + seconds
        self.app.state.limiter.clock = lambda: now


@pytest.fixture
def gw(tmp_path):
    return Gateway(tmp_path)


def test_the_clock_the_limits_count_by_stands_still_until_a_test_moves_it(gw):
    """The limits count in windows of the clock (this minute, this hour, this day). With the real clock a test that
    counts "30 in a minute" loses its count when a full minute passes in the middle of it: on CI (2026-11-11) the
    31st wrong secret was answered 403 where 429 was expected, because the 30 before it had been counted in the
    minute that had just ended. So every gateway of these tests starts at one fixed moment, and only `later` moves
    it."""
    assert gw.app.state.limiter.clock() == START
    time.sleep(0.01)
    assert gw.app.state.limiter.clock() == START
    gw.later(60)
    assert gw.app.state.limiter.clock() == START + 60


def stream(app, path: str, total: int, headers=(), method: str = "POST") -> dict:
    """Send `total` bytes to `path` in 64 KB pieces; how many the gateway took, and its answer."""
    got = {"taken": 0, "status": None, "body": b""}

    async def receive():
        if got["taken"] >= total:
            return {"type": "http.request", "body": b"", "more_body": False}
        got["taken"] += PIECE
        return {"type": "http.request", "body": b"x" * PIECE, "more_body": True}

    async def send(message):
        if message["type"] == "http.response.start":
            got["status"] = message["status"]
        elif message["type"] == "http.response.body":
            got["body"] += message.get("body", b"")

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "path": path,
             "raw_path": path.encode(), "query_string": b"", "root_path": "", "scheme": "http",
             "headers": [(b"host", b"gw.test"), (b"content-type", b"application/json"), *headers],
             "client": ("203.0.113.9", 4000), "server": ("gw.test", 80)}
    asyncio.run(app(scope, receive, send))
    return got


# ------------------------------------------------------------------ how much of a request is read

EIGHT_MB = 8 * 1024 * 1024


@pytest.mark.parametrize("path", ["/v1/usage", "/v1/tokens", "/v1/auth/signout"])
def test_a_large_body_from_nobody_is_not_read_past_the_limit(gw, path):
    got = stream(gw.app, path, EIGHT_MB)
    assert got["status"] == 413
    assert got["taken"] <= 4000 + PIECE                       # the piece that crossed the limit, and no more
    assert json.loads(got["body"])["error"] == {
        "type": "too_large", "message": "usage ping too large" if path == "/v1/usage" else "Request body too large."}


@pytest.mark.parametrize("path", ["/v1/usage", "/v1/tokens", "/v1/auth/signout", "/v1/chat/completions"])
def test_a_body_that_says_it_is_too_large_is_refused_before_any_of_it_is_read(gw, path):
    got = stream(gw.app, path, EIGHT_MB, headers=[(b"content-length", str(EIGHT_MB).encode())])
    assert (got["status"], got["taken"]) == (413, 0)


def test_a_size_that_is_no_number_is_refused_before_any_of_the_body_is_read(gw):
    got = stream(gw.app, "/v1/usage", EIGHT_MB, headers=[(b"content-length", b"many")])
    assert (got["status"], got["taken"]) == (413, 0)


def test_an_answer_that_has_begun_is_not_begun_a_second_time():
    """The cap around an app that answers first and reads afterwards (none of the gateway's own does): past the
    limit the app is told the caller has gone, and the caller is not sent the start of a second answer."""
    from lantern_gateway.limits import BodyCap
    sent, seen = [], []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        while True:
            message = await receive()
            seen.append(message["type"])
            if message["type"] == "http.disconnect" or not message.get("more_body"):
                break
        await send({"type": "http.response.body", "body": b"late"})

    async def receive():
        return {"type": "http.request", "body": b"x" * 600, "more_body": True}

    async def send(message):
        sent.append((message["type"], message.get("status")))

    asyncio.run(BodyCap(app, lambda path: (1000, "too large"))({"type": "http", "path": "/x", "headers": []}, receive, send))
    assert sent == [("http.response.start", 200)]               # one beginning, and nothing after the limit
    assert seen == ["http.request", "http.disconnect"]


def test_a_large_body_from_a_token_holder_is_not_read_past_the_limit(gw):
    tok = gw.token()
    got = stream(gw.app, "/v1/chat/completions", EIGHT_MB, headers=[(b"authorization", f"Bearer {tok}".encode())])
    assert got["status"] == 413
    assert got["taken"] <= gw.s.max_body_bytes + PIECE
    assert gw.asked_model() == 0


def test_the_twin_a_body_at_the_limit_is_read_and_one_byte_more_is_not(tmp_path):
    g = Gateway(tmp_path, max_body_bytes=2000)
    tok = g.token()
    h = {"authorization": f"Bearer {tok}", "content-type": "application/json"}

    def chat(size: int):
        head = '{"messages": [{"role": "user", "content": "'
        return g.client.post("/v1/chat/completions", content=head + "a" * (size - len(head) - 4) + '"}]}', headers=h)
    assert chat(2000).status_code == 200
    assert chat(2001).status_code == 413
    assert g.asked_model() == 1

    def ping(size: int):
        body = json.dumps({"install": "a" * 32, "day": today(), "features": {"analyze": 1}, "pad": ""})
        return g.client.post("/v1/usage", content=body[:-2] + "p" * (size - len(body)) + '"}',
                             headers={"content-type": "application/json"})
    assert ping(4000).status_code == 200
    assert ping(4001).status_code == 413


def test_the_twin_a_path_the_gateway_does_not_have_reads_nothing(gw):
    got = stream(gw.app, "/v1/nothing-here", EIGHT_MB)
    assert (got["status"], got["taken"]) == (404, 0)


def test_the_twin_a_question_without_a_body_is_answered_as_before(gw):
    got = stream(gw.app, "/v1/health", 0, method="GET")
    assert got["status"] == 200 and json.loads(got["body"])["ok"] is True


@contextlib.contextmanager
def served(app):
    """The gateway behind a real server on this computer; gives its port."""
    uvicorn = pytest.importorskip("uvicorn")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    try:
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.05)
        yield port
    finally:
        server.should_exit = True
        th.join(timeout=5)


@pytest.mark.parametrize("how", ["in pieces, without saying how much", "saying how much first"])
@pytest.mark.parametrize("path", ["/v1/usage", "/v1/tokens"])
def test_on_the_wire_a_large_upload_from_nobody_is_cut_off(gw, path, how):
    """The same through a real server and a real connection: 64 MB are offered, and the gateway hangs up long before
    they are through. (The code before took all 64 MB into memory, on a machine that has 256 MB.)"""
    total, sent, answer = 64 * 1024 * 1024, 0, b""
    with served(gw.app) as port:
        s = socket.create_connection(("127.0.0.1", port), timeout=30)
        head = f"POST {path} HTTP/1.1\r\nHost: gw.test\r\nContent-Type: application/json\r\n"
        chunked = how.startswith("in pieces")
        head += "Transfer-Encoding: chunked\r\n\r\n" if chunked else f"Content-Length: {total}\r\n\r\n"
        piece = b"x" * PIECE
        try:
            s.sendall(head.encode())
            while sent < total:
                s.sendall(b"10000\r\n" + piece + b"\r\n" if chunked else piece)
                sent += PIECE
        except OSError:
            pass                                        # the gateway hung up: what this test is about
        with contextlib.suppress(OSError):
            s.settimeout(5)
            while part := s.recv(65536):
                answer += part
        s.close()
    assert sent < total, "the whole upload was taken"
    assert not answer or answer.startswith(b"HTTP/1.1 413"), answer[:80]


# ------------------------------------------------------------------ a usage report of another shape

ODD_BODIES = {"a list": "[1, 2]", "a number": "5", "a text": '"x"', "null": "null", "true": "true",
              "nested 1,500 deep": "[" * 1500 + "]" * 1500, "a table nested 600 deep": '{"a":' * 600 + "1" + "}" * 600}


@pytest.mark.parametrize("name", sorted(ODD_BODIES))
def test_a_usage_report_of_another_shape_is_refused_in_plain_words(gw, name):
    r = gw.client.post("/v1/usage", content=ODD_BODIES[name], headers={"content-type": "application/json"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["type"] == "bad_request"
    assert gw.shown()["installs_total"] == 0


def test_the_twin_an_ordinary_usage_report_is_kept(gw):
    r = gw.ping()
    assert r.status_code == 200 and r.json() == {"ok": True, "recorded": ["analyze"]}
    shown = gw.shown()
    assert shown["installs_total"] == 1
    assert shown["features_30d"] == [{"feature": "analyze", "count": 2, "installs": 1}]
    assert shown["versions"] == [{"version": "0.10.0", "installs": 1}]
    assert shown["os"] == [{"os": "Linux", "installs": 1}]
    assert gw.stats().json()["days"] == 30                      # the owner's numbers cover 30 days unless asked otherwise


@pytest.mark.parametrize("name", ["a" * 31, "a" * 33, "g" * 32, "A" * 32, "a" * 31 + " ", ""])
def test_an_install_id_of_another_shape_is_refused(gw, name):
    assert gw.ping(name).status_code == 400
    assert gw.shown()["installs_total"] == 0


def test_a_limit_of_one_is_one(tmp_path):
    g = Gateway(tmp_path, sender_pings_per_hour=1)
    assert [g.ping().status_code for _ in range(2)] == [200, 429]
    (tmp_path / "b").mkdir()
    g = Gateway(tmp_path / "b", sender_installs_per_day=1)
    assert [g.ping(install(n)).status_code for n in range(2)] == [200, 429]


def test_the_twin_a_limit_set_to_nothing_limits_nothing(tmp_path):
    """0 switches a limit off, as the documents say: for the owner who wants none."""
    g = Gateway(tmp_path, sender_pings_per_hour=0, sender_installs_per_day=0, installs_per_day=0)
    assert [g.ping(install(n)).status_code for n in range(400)] == [200] * 400
    assert g.shown()["installs_total"] == 400


@pytest.mark.parametrize("version", ["<b>hello</b> you", "see evil.example", "1.0 call 555-0100", "v1", "",
                                     "1." * 9, ["0.10.0"], {"a": 1}, 7])
def test_a_version_that_is_no_version_is_not_kept(gw, version):
    assert gw.ping(version=version).status_code == 200            # the counts are still taken
    assert gw.shown()["versions"] == [{"version": "", "installs": 1}]


@pytest.mark.parametrize("version", ["0.10.0", "1.2", "0.11.0rc1", "0.10.1.dev3", "2.0.0b2", "0.10.0.post1", "12.34.56"])
def test_the_twin_a_version_is_kept(gw, version):
    assert gw.ping(version=version).status_code == 200
    assert gw.shown()["versions"] == [{"version": version, "installs": 1}]


@pytest.mark.parametrize("os_name", ["see evil.example", "<script>", "linux; rm -rf", "", ["Linux"], 5])
def test_a_system_name_the_gateway_does_not_know_is_kept_as_other(gw, os_name):
    assert gw.ping(os=os_name).status_code == 200
    assert gw.shown()["os"] == [{"os": "other", "installs": 1}]


@pytest.mark.parametrize("os_name", ["Linux", "Darwin", "Windows"])
def test_the_twin_a_system_name_it_knows_is_kept(gw, os_name):
    assert gw.ping(os=os_name).status_code == 200
    assert gw.shown()["os"] == [{"os": os_name, "installs": 1}]


# ------------------------------------------------------------------ how many usage reports are taken

def install(n: int) -> str:
    return f"{n:032x}"


def test_new_installs_in_a_day_are_capped_for_everyone_together(gw):
    """With the limits as they come: 1,000 new installs a day. Each from another sender, so no sender's own limit
    is what stops them."""
    answers = [gw.ping(install(n), sender=f"10.{n // 65536}.{n // 256 % 256}.{n % 256}").status_code for n in range(1001)]
    assert answers[:1000] == [200] * 1000
    assert answers[1000] == 429
    assert gw.shown()["installs_total"] == 1000


def test_past_the_cap_a_new_install_is_told_to_come_back_and_a_known_one_is_still_counted(tmp_path):
    g = Gateway(tmp_path, installs_per_day=3)
    for n in range(3):
        assert g.ping(install(n), sender=f"203.0.113.{n}").status_code == 200
    r = g.ping(install(99), sender="203.0.113.99")
    assert r.status_code == 429
    assert r.json()["error"]["type"] == "rate_limited"
    assert 0 < int(r.headers["retry-after"]) <= 86400
    assert g.ping(install(1), sender="203.0.113.1", features={"explain": 4}).status_code == 200      # the twin
    shown = g.shown()
    assert shown["installs_total"] == 3
    assert {f["feature"]: f["count"] for f in shown["features_30d"]} == {"analyze": 6, "explain": 4}


def test_one_sender_may_bring_only_so_many_new_installs_a_day(gw):
    answers = [gw.ping(install(n), sender="203.0.113.7").status_code for n in range(51)]
    assert answers == [200] * 50 + [429]
    assert gw.ping(install(500), sender="203.0.113.8").status_code == 200           # the twin: another sender
    assert gw.ping(install(3), sender="203.0.113.7").status_code == 200             # the twin: an install it brought
    assert gw.shown()["installs_total"] == 51
    gw.later(86400)
    assert gw.ping(install(51), sender="203.0.113.7").status_code == 200            # the next day


def test_one_sender_may_send_only_so_many_reports_an_hour(gw):
    answers = [gw.ping(sender="203.0.113.7").status_code for _ in range(301)]
    assert answers == [200] * 300 + [429]
    r = gw.ping(sender="203.0.113.7")
    assert r.status_code == 429 and 0 < int(r.headers["retry-after"]) <= 3600
    assert gw.ping(sender="203.0.113.8").status_code == 200                         # the twin: another sender
    gw.later(3600)
    assert gw.ping(sender="203.0.113.7").status_code == 200                         # the next hour


def test_a_refused_report_is_not_parsed_and_changes_nothing(tmp_path):
    g = Gateway(tmp_path, sender_pings_per_hour=2)
    assert [g.ping().status_code for _ in range(2)] == [200, 200]
    r = g.client.post("/v1/usage", content="[1]", headers={"Fly-Client-IP": "203.0.113.5", "content-type": "application/json"})
    assert r.status_code == 429
    assert g.ping(features={"explain": 9}).status_code == 429
    assert {f["feature"] for f in g.shown()["features_30d"]} == {"analyze"}


def test_senders_in_one_ipv6_network_count_as_one(tmp_path):
    g = Gateway(tmp_path, sender_pings_per_hour=3)
    answers = [g.ping(sender=f"2001:db8:1:2::{n:x}").status_code for n in range(1, 5)]
    assert answers == [200, 200, 200, 429]
    assert g.ping(sender="2001:db8:1:3::1").status_code == 200                      # the twin: the network beside it


def test_an_address_header_is_used_only_where_the_owner_says_a_proxy_sets_it(tmp_path):
    g = Gateway(tmp_path, sender_pings_per_hour=2, address_header="")
    answers = [g.ping(sender=f"203.0.113.{n}").status_code for n in range(4)]
    assert answers == [200, 200, 429, 429]              # a sender cannot name itself: all four came from one place


def test_a_header_that_is_no_address_names_nobody(tmp_path):
    g = Gateway(tmp_path, sender_pings_per_hour=2)
    answers = [g.ping(sender=text).status_code for text in ("one", "two", "three", "unknown, 203.0.113.9")]
    assert answers == [200, 200, 429, 429]


def test_an_address_is_read_as_the_network_the_counts_go_by():
    from lantern_gateway.limits import _address, sender
    assert _address("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64"
    assert _address("fe80::1:2:3:4") == "fe80::/64"
    assert _address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == "ffff:ffff:ffff:ffff::/64"
    assert _address("::ffff:203.0.113.7") == "203.0.113.7"      # an IPv4 caller written the IPv6 way: itself
    assert _address("::ffff:203.0.113.8") != _address("::ffff:203.0.113.7")
    assert _address(" 203.0.113.7 ") == "203.0.113.7"
    assert _address("nonsense") is None and _address("") is None and _address("203.0.113.7, 198.51.100.1") is None
    there = {"headers": [(b"Fly-Client-IP", b"198.51.100.4")], "client": ("203.0.113.9", 4000)}
    assert sender(there, "fly-client-ip") == "198.51.100.4"
    assert sender(there, "") == "203.0.113.9" == sender(there, "x-other")       # the connection's own address
    assert sender({"headers": [(b"fly-client-ip", b"me")], "client": ("203.0.113.9", 1)}, "fly-client-ip") == "203.0.113.9"
    assert sender({"headers": []}, "") == "connection:" == sender({"client": None}, "fly-client-ip")
    assert sender({"client": ("testclient", 50000)}, "") == "connection:testclient"


def test_no_address_is_kept(gw):
    for n in range(3):
        gw.ping(install(n), sender="203.0.113.77")
    gw.stats(sender="203.0.113.78", secret="wrong")
    gw.back(gw.link(), sender="203.0.113.79")
    held = repr(vars(gw.app.state.limiter))
    for address in ("203.0.113.77", "203.0.113.78", "203.0.113.79"):
        assert address not in held
        assert address.encode() not in Path(gw.s.db_path).read_bytes()


def test_the_table_of_senders_cannot_grow_without_end():
    from lantern_gateway.limits import Limiter
    lim = Limiter(max_keys=100)
    for n in range(5000):
        lim.take("ping", f"sender-{n}", 2, 3600)
    assert lim.size() <= 100
    # past the table's size, the senders it has no room for share one count: still a limit, never none
    answers = [lim.take("ping", f"late-{n}", 2, 3600) for n in range(50)]
    assert answers.count(True) <= 2


def test_the_twin_a_limiter_counts_per_sender_and_starts_again_with_the_window():
    from lantern_gateway.limits import Limiter
    now = [1000.0]
    lim = Limiter(clock=lambda: now[0])
    assert [lim.take("ping", "a", 2, 60) for _ in range(3)] == [True, True, False]
    assert lim.full("ping", "a", 2, 60) and not lim.full("ping", "b", 2, 60)
    assert lim.take("ping", "b", 2, 60) and lim.take("other", "a", 2, 60)
    assert lim.wait(60) == 20                                   # 1000 s is 40 s into its minute
    now[0] += 19.6
    assert lim.wait(60) == 1                                    # never "come back in 0 seconds"
    now[0] += 40.4
    assert lim.take("ping", "a", 2, 60)
    assert Limiter().size() == 0 and lim.size() == 3
    assert not lim.full("new", "a", 1, 60)                      # a limit of one: nobody is past it before a first try
    assert lim.take("new", "a", 1, 60) and lim.full("new", "a", 1, 60)


def test_a_full_table_keeps_the_counts_it_has_and_puts_only_newcomers_together():
    """Exactly `max_keys` counts: the senders that came first keep their own, whatever comes after shares the last."""
    from lantern_gateway.limits import Limiter
    lim = Limiter(max_keys=5, clock=lambda: 1000.0)
    assert [lim.take("k", f"early-{n}", 3, 60) for n in range(4)] == [True] * 4
    assert lim.take("k", "late-1", 1, 60)                       # the fifth count: the one the newcomers share
    assert not lim.take("k", "late-2", 1, 60)                   # ... and this is its second
    assert lim.size() == 5
    assert [lim.take("k", "early-0", 3, 60) for _ in range(3)] == [True, True, False]      # its own count: 2, 3, 4
    assert lim.take("k", "early-1", 3, 60) and not lim.full("k", "early-1", 3, 60)
    assert lim.size() == 5


def test_counts_of_a_minute_that_has_ended_make_room_for_new_senders():
    from lantern_gateway.limits import Limiter
    now = [1000.0]
    lim = Limiter(max_keys=5, clock=lambda: now[0])
    assert lim.take("k", "old", 1, 60)
    now[0] += 60
    assert [lim.take("k", f"early-{n}", 1, 60) for n in range(3)] == [True] * 3
    assert lim.take("k", "new", 1, 60)                          # the table was full; the ended minute went
    assert (lim.name("new"), int(now[0] // 60)) in lim.counts["k"] and lim.size() == 4
    assert not lim.take("k", "new", 1, 60) and lim.take("k", "newer", 1, 60)     # "new" has its own count


def test_the_app_keeps_its_counts_when_the_gateway_says_come_back_later(tmp_path, monkeypatch):
    """The real sender of the app against a gateway that is past its cap: nothing is lost on the person's computer,
    and the same counts arrive once the gateway takes new installs again."""
    from lantern import usage
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    g = Gateway(tmp_path, installs_per_day=1)
    assert g.ping(install(1)).status_code == 200
    with served(g.app) as port:
        usage.set_enabled(True)
        usage.record("analyze")
        waiting = usage.pending()
        assert len(waiting) == 1
        assert usage.send(f"http://127.0.0.1:{port}/v1") == 0
        assert usage.pending() == waiting
        assert "429" in (usage.last() or "")
        g.s.installs_per_day = 2                                       # the twin: the next day, as it were
        assert usage.send(f"http://127.0.0.1:{port}/v1") == 1
        assert g.shown()["installs_total"] == 2


# ------------------------------------------------------------------ the owner's secret

def test_wrong_admin_secrets_from_one_sender_are_stopped_after_five_in_a_minute(gw):
    answers = [gw.stats(sender="203.0.113.7", secret=f"guess-{n}").status_code for n in range(7)]
    assert answers == [403] * 5 + [429, 429]
    r = gw.stats(sender="203.0.113.7")                           # the right secret, in the same minute: not looked at
    assert r.status_code == 429 and 0 < int(r.headers["retry-after"]) <= 60
    assert gw.stats(sender="203.0.113.8").status_code == 200     # the twin: the owner, from their own address
    gw.later(60)
    assert gw.stats(sender="203.0.113.7").status_code == 200


def test_both_admin_addresses_share_the_count(gw):
    h = {"Fly-Client-IP": "203.0.113.7", "authorization": "Bearer nope"}
    answers = [gw.client.post("/v1/tokens", json={}, headers=h).status_code for _ in range(3)]
    answers += [gw.client.get("/v1/admin/stats", headers=h).status_code for _ in range(3)]
    answers += [gw.client.post("/v1/tokens", json={}, headers=h).status_code]
    assert answers == [403] * 5 + [429, 429]
    assert gw.client.post("/v1/tokens", json={}, headers={"Fly-Client-IP": "203.0.113.7"}).status_code == 429   # no secret at all


def test_wrong_admin_secrets_from_many_senders_stop_every_try_for_the_rest_of_the_minute(gw):
    answers = [gw.stats(sender=f"203.0.113.{n}", secret="nope").status_code for n in range(31)]
    assert answers == [403] * 30 + [429]
    assert gw.stats(sender="198.51.100.200").status_code == 429            # said in the documents: the owner waits too
    gw.later(60)
    assert gw.stats(sender="198.51.100.200").status_code == 200


def test_a_secret_in_letters_outside_ascii_is_a_wrong_secret_not_an_error(gw):
    for word in ("Bearer caf\xe9", "caf\xe9", "Bearer \xff\xfe"):
        r = gw.client.get("/v1/admin/stats", headers={"authorization": word.encode("latin-1")})
        assert r.status_code == 403, word


def test_the_twin_the_right_secret_is_never_counted(gw):
    assert [gw.stats(sender="203.0.113.7").status_code for _ in range(100)] == [200] * 100


def test_the_twin_the_owners_page_itself_is_open(gw):
    for _ in range(8):
        gw.stats(sender="203.0.113.7", secret="nope")
    r = gw.client.get("/v1/admin", headers={"Fly-Client-IP": "203.0.113.7"})
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]


def test_the_owners_page_has_words_for_too_many_wrong_secrets(gw):
    """Read from the page's text only (no browser here): the answer 429 gets a sentence, as 403 does."""
    page = gw.client.get("/v1/admin").text
    assert "r.status === 429 ? WAIT" in page
    assert "const WAIT = 'Too many wrong secrets in the last minute. Wait a minute, then try again.';" in page


# ------------------------------------------------------------------ signing in

def test_a_sign_in_token_waiting_for_the_app_is_not_in_the_database_in_clear(gw):
    r = gw.back(gw.link())
    assert r.status_code == 200
    row = sqlite3.connect(gw.s.db_path).execute("select token from pending").fetchone()
    assert row is not None and not row[0].startswith("lt_")
    assert b"lt_" not in Path(gw.s.db_path).read_bytes()
    tok = gw.client.get("/v1/auth/claim", params={"cli": CLI}).json()["token"]          # the twin: the app collects it
    assert tok.startswith("lt_") and tok not in row[0]
    assert gw.client.get("/v1/allowance", headers={"authorization": f"Bearer {tok}"}).status_code == 200
    assert gw.client.get("/v1/auth/claim", params={"cli": CLI}).status_code == 404       # once
    assert sqlite3.connect(gw.s.db_path).execute("select count(*) from pending").fetchone()[0] == 0


def test_the_waiting_token_can_be_opened_only_with_the_apps_own_code(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    store.park(CLI, "lt_" + "t" * 43)
    store.park("d" * 40, "lt_" + "t" * 43)
    rows = [r[0] for r in store.db.execute("select token from pending order by cli_hash")]
    assert len(set(rows)) == 2                                    # the same token under two codes: two different texts
    assert store.claim("e" * 40) is None
    assert store.claim("d" * 40) == "lt_" + "t" * 43
    assert store.claim(CLI) == "lt_" + "t" * 43


def test_a_token_left_in_clear_by_the_version_before_is_not_handed_out_and_does_not_stay(tmp_path):
    g = Gateway(tmp_path)
    db = sqlite3.connect(g.s.db_path)
    clear = "lt_" + "o" * 43
    db.execute("insert into pending (cli_hash, token, created) values (?, ?, strftime('%s','now'))",
               (gateway_app._hash(CLI), clear))
    db.commit()
    db.close()
    again = Gateway(tmp_path)                                     # the gateway starts again, as after a deploy
    assert sqlite3.connect(g.s.db_path).execute("select count(*) from pending").fetchone()[0] == 0
    assert again.client.get("/v1/auth/claim", params={"cli": CLI}).status_code == 404


def test_a_token_nobody_collected_is_gone_after_ten_minutes(gw, monkeypatch):
    now = [gateway_app.time.time()]
    monkeypatch.setattr(gateway_app.time, "time", lambda: now[0])
    gw.back(gw.link())
    waiting = lambda: sqlite3.connect(gw.s.db_path).execute("select count(*) from pending").fetchone()[0]  # noqa: E731
    assert waiting() == 1
    now[0] += 600                                               # ten minutes to the second: still there
    assert gw.client.get("/v1/auth/claim", params={"cli": "z" * 40}).status_code == 404    # somebody else's question
    assert waiting() == 1
    now[0] += 0.5
    assert gw.client.get("/v1/auth/claim", params={"cli": "z" * 40}).status_code == 404
    assert waiting() == 0
    assert gw.client.get("/v1/auth/claim", params={"cli": CLI}).status_code == 404


def test_the_twin_a_token_is_collected_within_the_ten_minutes(gw, monkeypatch):
    now = [gateway_app.time.time()]
    monkeypatch.setattr(gateway_app.time, "time", lambda: now[0])
    gw.back(gw.link())
    now[0] += 599
    r = gw.client.get("/v1/auth/claim", params={"cli": CLI})
    assert r.status_code == 200 and r.json()["token"].startswith("lt_")


def test_a_sign_in_link_works_once_and_github_is_not_asked_again(gw):
    state = gw.link()
    assert gw.back(state).status_code == 200
    asked = gw.asked_github()
    for code in ("good", "bad", "good"):
        r = gw.back(state, code)
        assert r.status_code == 400 and "already used" in r.text
    assert gw.asked_github() == asked
    assert gw.back(gw.link("d" * 40)).status_code == 200          # the twin: a new link signs the same person in again
    assert gw.client.get("/v1/auth/claim", params={"cli": "d" * 40}).json()["token"].startswith("lt_")


def test_a_link_with_a_wrong_code_is_used_up_too(gw):
    state = gw.link()
    assert gw.back(state, "bad").status_code == 502
    asked = gw.asked_github()
    assert [gw.back(state, "bad").status_code for _ in range(20)] == [400] * 20
    assert gw.asked_github() == asked


def test_one_sender_may_make_the_gateway_ask_the_provider_only_so_often(gw):
    answers = [gw.back(gw.link(), "bad", sender="203.0.113.7").status_code for _ in range(12)]
    assert answers == [502] * 10 + [429, 429]
    asked = gw.asked_github()
    assert asked == 10
    r = gw.back(gw.link(), sender="203.0.113.7")
    assert r.status_code == 429 and 0 < int(r.headers["retry-after"]) <= 60 and "text/html" in r.headers["content-type"]
    assert gw.asked_github() == asked
    assert gw.back(gw.link(), sender="203.0.113.8").status_code == 200       # the twin: another person signs in
    gw.later(60)
    assert gw.back(gw.link("d" * 40), sender="203.0.113.7").status_code == 200


def test_sign_ins_for_everyone_together_are_bounded_too(tmp_path):
    g = Gateway(tmp_path, signins_per_minute_all=3)
    answers = [g.back(g.link(), "bad", sender=f"203.0.113.{n}").status_code for n in range(5)]
    assert answers == [502, 502, 502, 429, 429]
    assert g.asked_github() == 3
    g.later(60)
    assert g.back(g.link(), sender="203.0.113.9").status_code == 200


def test_two_people_who_start_in_the_same_second_do_not_share_a_link(gw):
    one, two = gw.link(""), gw.link("")                    # no app's code: a person in a browser
    assert one != two
    assert gw.back(one, sender="203.0.113.1").status_code == 200
    assert gw.back(two, sender="203.0.113.2").status_code == 200


@pytest.mark.parametrize("github", ["down", "odd"])
def test_a_provider_that_cannot_be_reached_or_answers_oddly_is_said_on_a_page(tmp_path, github):
    g = Gateway(tmp_path, github=github)
    r = g.back(g.link())
    assert r.status_code == 502 and "text/html" in r.headers["content-type"]
    assert "did not confirm" in r.text
    assert sqlite3.connect(g.s.db_path).execute("select count(*) from accounts").fetchone()[0] == 0


def test_the_twin_starting_a_sign_in_and_asking_for_its_token_are_never_limited(gw):
    h = {"Fly-Client-IP": "203.0.113.7"}
    assert {gw.client.get("/v1/auth/github/start", params={"cli": CLI}, headers=h).status_code for _ in range(200)} == {302}
    assert {gw.client.get("/v1/auth/claim", params={"cli": CLI}, headers=h).status_code for _ in range(400)} == {404}
    assert gw.asked_github() == 0


# ------------------------------------------------------------------ a request for the model of another shape

def chat(g, tok, content: str):
    return g.client.post("/v1/chat/completions", content=content,
                         headers={"authorization": f"Bearer {tok}", "content-type": "application/json"})


@pytest.mark.parametrize("name", ["a list", "a number", "null", "nested 1,500 deep", "nested 100,000 deep"])
def test_a_request_for_the_model_of_another_shape_is_refused_in_plain_words(gw, name):
    r = chat(gw, gw.token(), ODD_BODIES.get(name) or "[" * 100_000 + "]" * 100_000)
    assert r.status_code == 400 and r.json()["error"]["type"] == "bad_request"
    assert gw.asked_model() == 0


@pytest.mark.parametrize("max_tokens", ['"many"', "[1]", "1e400", "-1e400", '{"a": 1}', "true", "null"])
def test_a_size_that_is_no_number_is_answered_with_the_gateways_own(gw, max_tokens):
    r = chat(gw, gw.token(), '{"messages": [{"role": "user", "content": "hi"}], "max_tokens": ' + max_tokens + "}")
    assert r.status_code == 200, r.text
    assert gw.asked_model() == 1


@pytest.mark.parametrize("max_tokens, kept", [("50", 50), ("50.9", 50), ("0", 3000), ("-5", 1), ("99999", 3000)])
def test_the_twin_a_size_that_is_a_number_is_used_up_to_the_cap(tmp_path, max_tokens, kept):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["max_tokens"])
        return httpx.Response(200, json={"id": "c", "model": "m", "choices": [], "usage": {}})
    s = Settings(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="k", admin_secret=ADMIN,
                 db_path=str(tmp_path / "g.db"))
    client = TestClient(create_app(s, transport=httpx.MockTransport(handler)))
    tok = client.post("/v1/tokens", json={}, headers={"authorization": f"Bearer {ADMIN}"}).json()["token"]
    r = client.post("/v1/chat/completions", content='{"messages": [{"role": "user", "content": "hi"}], "max_tokens": '
                    + max_tokens + "}", headers={"authorization": f"Bearer {tok}", "content-type": "application/json"})
    assert r.status_code == 200 and seen == [kept]


# ------------------------------------------------------------------ what is open to anybody stays open

def test_the_twin_what_is_open_to_anybody_still_answers_without_a_token(gw):
    c = gw.client
    assert c.get("/v1/health").json()["ok"] is True
    assert c.get("/v1/auth/providers").json()["providers"] == ["github"]
    assert c.get("/v1/login").status_code == 200
    assert c.get("/v1/admin").status_code == 200
    assert c.get("/v1/auth/github/start").status_code == 302
    assert c.get("/v1/auth/claim", params={"cli": CLI}).status_code == 404
    assert c.post("/v1/usage", json={"install": "b" * 32, "features": {"serve": 1}}).status_code == 200
    assert c.get("/v1/allowance").status_code == 401
    assert c.get("/v1/admin/stats").status_code == 403


def test_the_twin_a_health_check_every_few_seconds_is_never_refused(gw):
    assert {gw.client.get("/v1/health").status_code for _ in range(500)} == {200}


def test_the_limits_are_the_numbers_the_documents_give(monkeypatch):
    for name in ("LANTERN_INSTALLS_PER_DAY", "LANTERN_SENDER_INSTALLS_PER_DAY", "LANTERN_SENDER_PINGS_PER_HOUR",
                 "LANTERN_ADDRESS_HEADER", "LANTERN_MAX_BODY"):
        monkeypatch.delenv(name, raising=False)
    s = Settings()
    assert (s.installs_per_day, s.sender_installs_per_day, s.sender_pings_per_hour) == (1000, 50, 300)
    assert (s.admin_wrong_per_minute, s.admin_wrong_per_minute_all) == (5, 30)
    assert (s.sender_signins_per_minute, s.signins_per_minute_all) == (10, 120)
    assert (s.address_header, s.max_body_bytes, gateway_app.limits.SMALL_BODY, gateway_app.PARKED) == ("fly-client-ip", 250_000, 4000, 600)
    readme = (Path(__file__).resolve().parents[1] / "gateway" / "README.md").read_text(encoding="utf-8")
    for words in ("| `LANTERN_INSTALLS_PER_DAY` | 1000 |", "| `LANTERN_SENDER_INSTALLS_PER_DAY` | 50 |",
                  "| `LANTERN_SENDER_PINGS_PER_HOUR` | 300 |", "| `LANTERN_ADDRESS_HEADER` | fly-client-ip |",
                  "five wrong secrets in a minute from one sender, or 30 from everyone together",
                  "at most 10 times a minute for one sender and 120 times a minute for everyone together",
                  "4,000 bytes everywhere else", "waits up to ten minutes"):
        assert words in readme, words


def test_each_refusal_says_the_seconds_left_of_its_minute_hour_or_day(tmp_path):
    """The limiter's clock stands at 1,000,000,000 s: 40 s into its minute, 2,800 s into its hour, 6,400 s into
    its day."""
    g = Gateway(tmp_path, sender_pings_per_hour=3, sender_installs_per_day=1)
    assert g.app.state.limiter.clock() == 1_000_000_000.0
    for n in range(5):
        g.stats(sender="203.0.113.7", secret=f"guess-{n}")
    assert g.stats(sender="203.0.113.7").headers["retry-after"] == "20"
    for _ in range(10):
        g.back(g.link(), "bad", sender="203.0.113.7")
    assert g.back(g.link(), sender="203.0.113.7").headers["retry-after"] == "20"
    assert g.ping(install(1), sender="203.0.113.7").status_code == 200
    assert g.ping(install(2), sender="203.0.113.7").headers["retry-after"] == "80000"      # a second new install today
    assert g.ping(install(1), sender="203.0.113.7").status_code == 200
    assert g.ping(install(1), sender="203.0.113.7").headers["retry-after"] == "800"        # a fourth report this hour


def test_come_back_tomorrow_is_counted_to_midnight_utc():
    at = dt.datetime(2026, 11, 10, 22, 58, 57, 1, tzinfo=dt.UTC)
    assert gateway_app.seconds_to_midnight_utc(at) == 3662
    assert gateway_app.seconds_to_midnight_utc(dt.datetime(2026, 11, 10, 23, 59, 59, 999_999, tzinfo=dt.UTC)) == 1


def test_every_limit_the_code_reads_from_the_environment_is_named_for_the_owner():
    root = Path(__file__).resolve().parents[1]
    names = ("LANTERN_INSTALLS_PER_DAY", "LANTERN_SENDER_INSTALLS_PER_DAY", "LANTERN_SENDER_PINGS_PER_HOUR",
             "LANTERN_ADDRESS_HEADER")
    code = (root / "gateway" / "lantern_gateway" / "app.py").read_text(encoding="utf-8")
    for doc in ("gateway/README.md", ".env.example", "docs/deploy.md"):
        text = (root / doc).read_text(encoding="utf-8")
        for name in names:
            assert name in code and name in text, (name, doc)
