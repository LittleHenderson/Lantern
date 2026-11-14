"""The doorkeeper of the fetching step (`lantern._stores`): it hands on what is asked of a store it was told
about, and nothing else. Every place here is on this computer; a name that is nowhere (`.invalid`) is only ever
written into a request, never looked up."""
from __future__ import annotations

import socket
import threading

import pytest
from stores import _Store

from lantern import _stores


class _Echo:
    """A server on 127.0.0.1 that says back what it is told, for what goes through a tunnel."""

    def __init__(self, greeting: bytes = b""):
        self.listener = _stores.listen(0)
        self.port = self.listener.getsockname()[1]
        self.greeting = greeting
        self.got: list[bytes] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        with conn:
            if self.greeting:
                conn.sendall(self.greeting)
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                self.got.append(data)
                conn.sendall(data.upper())

    def close(self):
        self.listener.close()


class _Upstream(_Echo):
    """A stand-in for a person's own proxy: answers `CONNECT` with 200 and then says back what it is told."""

    def _one(self, conn):
        with conn:
            head = b""
            while b"\r\n\r\n" not in head:
                data = conn.recv(4096)
                if not data:
                    return
                head += data
            self.got.append(head)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data.upper())


@pytest.fixture
def store():
    with _Store() as s:
        s.pages["/simple/thing/"] = ("text/html", b"<html>the index of thing</html>")
        yield s


@pytest.fixture
def door(store):
    said: list[str] = []
    d = _stores.Door(_stores.listen(0), [["127.0.0.1", store.port]], said=said.append).start()
    d.port = d.listener.getsockname()[1]
    d.said_lines = said
    yield d
    d.close()


def _ask(port: int, text: bytes, more: bytes = b"", wait: float = 10.0) -> bytes:
    """What the doorkeeper at `port` answers to `text` (and, once it has answered, to `more`)."""
    with socket.create_connection(("127.0.0.1", port), timeout=wait) as s:
        s.sendall(text)
        got = b""
        try:
            if more:
                while b"\r\n\r\n" not in got:
                    data = s.recv(4096)
                    if not data:
                        return got
                    got += data
                s.sendall(more)
                got += s.recv(4096)
                return got
            while True:
                data = s.recv(65536)
                if not data:
                    return got
                got += data
        except (TimeoutError, ConnectionError):
            return got


def test_what_is_asked_of_the_store_is_handed_on_and_the_answer_comes_back(door, store):
    got = _ask(door.port, f"GET http://127.0.0.1:{store.port}/simple/thing/ HTTP/1.1\r\nHost: 127.0.0.1:{store.port}\r\n"
                          "Proxy-Authorization: Basic c2VjcmV0\r\nAccept: */*\r\n\r\n".encode())
    assert got.startswith(b"HTTP/1.0 200") or got.startswith(b"HTTP/1.1 200"), got[:200]
    assert got.endswith(b"<html>the index of thing</html>")
    assert store.seen == ["/simple/thing/"]                       # as a request for the store itself, by its path
    assert door.said_lines == [f"{_stores.OPENED} 127.0.0.1:{store.port}"]
    assert door.refused == []


def test_a_store_is_named_once_however_often_it_is_reached(door, store):
    for _ in range(3):
        _ask(door.port, f"GET http://127.0.0.1:{store.port}/simple/thing/ HTTP/1.1\r\n\r\n".encode())
    assert len(store.seen) == 3 and len(door.said_lines) == 1


@pytest.mark.parametrize("how", ["plain", "tunnel"])
def test_any_other_place_is_refused_and_never_reached(door, store, how):
    with _Store() as other:
        other.pages["/x"] = ("text/plain", b"not for you")
        if how == "plain":
            got = _ask(door.port, f"GET http://127.0.0.1:{other.port}/x HTTP/1.1\r\n\r\n".encode())
        else:
            got = _ask(door.port, f"CONNECT 127.0.0.1:{other.port} HTTP/1.1\r\n\r\n".encode())
        assert got.startswith(b"HTTP/1.1 403 "), got[:200]
        assert b"not for you" not in got and other.seen == [] and store.seen == []
        assert door.refused == [f"127.0.0.1:{other.port}"]
        assert door.said_lines == [f"{_stores.REFUSED} 127.0.0.1:{other.port}"]


@pytest.mark.parametrize("target", [
    "http://example.invalid/simple/thing/",             # another computer, by name: refused before any name is looked up
    "http://127.0.0.1/simple/thing/",                   # the store's computer at another port (80)
    "http://localhost:{port}/simple/thing/",            # the store by another name than the one that was allowed
    "http://[::1]:{port}/simple/thing/",
])
def test_the_store_under_another_name_or_port_is_another_place(door, store, target):
    got = _ask(door.port, f"GET {target.format(port=store.port)} HTTP/1.1\r\n\r\n".encode())
    assert got.startswith(b"HTTP/1.1 403 "), got[:200]
    assert store.seen == [] and len(door.refused) == 1


@pytest.mark.parametrize("line", [
    "GET /simple/thing/ HTTP/1.1",                      # no place named at all
    "GET https://127.0.0.1:{port}/simple/thing/ HTTP/1.1",   # an encrypted address goes through a tunnel, never like this
    "GET http://someone:secret@127.0.0.1:{port}/simple/thing/ HTTP/1.1",    # a name and a password in the address
    "GET http://127.0.0.1:{port}/a b HTTP/1.1",         # four words
    "GET http://127.0.0.1:notaport/x HTTP/1.1",
    "CONNECT 127.0.0.1:{port}/x HTTP/1.1",              # a tunnel is to a place, not to a path
    "CONNECT someone@127.0.0.1:{port} HTTP/1.1",
    "nonsense",
])
def test_a_request_the_doorkeeper_cannot_read_is_not_handed_on(door, store, line):
    got = _ask(door.port, (line.format(port=store.port) + "\r\n\r\n").encode())
    assert got.startswith(b"HTTP/1.1 400 "), got[:200]
    assert store.seen == [] and door.said_lines == []


def test_first_lines_without_an_end_are_given_up(door, store):
    got = _ask(door.port, b"GET http://127.0.0.1:%d/" % store.port + b"a" * (_stores.HEAD_MOST + 5000))
    assert got == b"" and store.seen == []


def test_a_tunnel_to_a_store_carries_both_ways():
    echo = _Echo()
    said: list[str] = []
    d = _stores.Door(_stores.listen(0), [["127.0.0.1", echo.port]], said=said.append).start()
    try:
        got = _ask(d.listener.getsockname()[1], f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\n\r\n".encode(), b"hello")
        assert got.startswith(b"HTTP/1.1 200 ") and got.endswith(b"HELLO"), got
        assert echo.got == [b"hello"]                   # none of the request's own lines went into the tunnel
        assert said == [f"{_stores.OPENED} 127.0.0.1:{echo.port}"]
    finally:
        d.close()
        echo.close()


def test_a_store_that_does_not_answer_is_said_as_such(store):
    nobody = _stores.listen(0)
    port = nobody.getsockname()[1]
    nobody.close()                                      # a port where nothing listens
    d = _stores.Door(_stores.listen(0), [["127.0.0.1", port]]).start()
    try:
        got = _ask(d.listener.getsockname()[1], f"GET http://127.0.0.1:{port}/x HTTP/1.1\r\n\r\n".encode())
        assert got.startswith(b"HTTP/1.1 502 "), got[:200]
        assert d.reached == set() and d.refused == []
    finally:
        d.close()


def test_a_store_on_another_computer_is_reached_through_the_persons_own_proxy():
    """The doorkeeper asks the proxy this computer is set up with for the store, by name, and for nothing else."""
    up = _Upstream()
    through = _stores.upstream(f"http://someone:pass@127.0.0.1:{up.port}")
    assert through == {"host": "127.0.0.1", "port": up.port, "auth": "c29tZW9uZTpwYXNz"}
    d = _stores.Door(_stores.listen(0), [["store.example.invalid", 443]], through=through).start()
    port = d.listener.getsockname()[1]
    try:
        got = _ask(port, b"CONNECT store.example.invalid:443 HTTP/1.1\r\n\r\n", b"hello")
        assert got.startswith(b"HTTP/1.1 200 ") and got.endswith(b"HELLO"), got
        asked = up.got[0].decode()
        assert asked.startswith("CONNECT store.example.invalid:443 HTTP/1.1\r\n")
        assert "Proxy-Authorization: Basic c29tZW9uZTpwYXNz\r\n" in asked
        up.got.clear()
        got = _ask(port, b"CONNECT elsewhere.example.invalid:443 HTTP/1.1\r\n\r\n")
        assert got.startswith(b"HTTP/1.1 403 ") and up.got == []    # the person's proxy never hears of it
    finally:
        d.close()
        up.close()


@pytest.mark.parametrize("address, want", [
    ("http://127.0.0.1:3128", {"host": "127.0.0.1", "port": 3128, "auth": None}),
    ("proxy.example.invalid:8080", {"host": "proxy.example.invalid", "port": 8080, "auth": None}),
    ("http://proxy.example.invalid", {"host": "proxy.example.invalid", "port": 80, "auth": None}),
    ("https://proxy.example.invalid:8443", None),       # a proxy that is itself spoken to in TLS: not one it can use
    ("socks5://127.0.0.1:1080", None),
    ("http://", None),
    ("http://127.0.0.1:notaport", None),
])
def test_which_proxy_address_the_doorkeeper_takes(address, want):
    assert _stores.upstream(address) == want


def test_closing_the_doorkeeper_ends_its_listener(store):
    d = _stores.Door(_stores.listen(0), [["127.0.0.1", store.port]]).start()
    port = d.listener.getsockname()[1]
    d.close()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
