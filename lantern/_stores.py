"""The doorkeeper of the fetching step (a firm pass or fail, stage 2, 2026-11-13; standard library only).

Before a project's tests run, the libraries it names are fetched (`lantern.libraries`). The program that fetches
them (pip, npm) is given one way out: this doorkeeper, a small forwarding proxy that connects to the stores it was
told about (a host and a port each) and to nothing else, and says so for every other place it is asked for
(`REFUSED`). Where the fetch runs in a network of its own (`lantern._jail`), the doorkeeper is the only thing that
listens there and its other side is with the launcher, outside: there is then no second way out for any program
of the fetch, in any language. Elsewhere it listens on this computer's own address and the fetching program is
told to use it.

What it does not do: it does not read what is said inside an encrypted connection to a store (the fetching
program checks the store's certificate itself), and it keeps no copy of anything."""
from __future__ import annotations

import base64
import select
import socket
import threading
from urllib.parse import urlsplit

REFUSED = "LANTERN-STORE-REFUSED:"   # a line of the fetch's log: a place that is no store was asked for
OPENED = "LANTERN-STORE-OPENED:"     # ... and: a store was reached
HEAD_MOST = 16384                    # the most bytes a request's first lines may have
WAIT = 30.0                          # seconds to reach a store, and for a request's first lines
IDLE = 120.0                         # seconds a connection may say nothing in either direction


def _head(conn: socket.socket) -> tuple[bytes, bytes] | None:
    """A request's (or an answer's) first lines and whatever came after them, or None."""
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > HEAD_MOST:
            return None
        try:
            chunk = conn.recv(4096)
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head, rest


def _place(text: str, port: int) -> tuple[str, int] | None:
    """`host`, `host:port` or `[v6]:port` as (host in small letters, port), or None."""
    try:
        parts = urlsplit("//" + text)
        host, number = parts.hostname, parts.port
    except ValueError:
        return None
    if not host or parts.username or parts.path or parts.query:
        return None
    return host.lower(), number or port


def upstream(address: str) -> dict | None:
    """The person's own proxy (`https://` requests of this computer go through it: HTTPS_PROXY), as the doorkeeper
    takes it: `{"host", "port", "auth"}`, or None for no address or one that is not `http://host:port`."""
    try:
        parts = urlsplit(address if "://" in address else "http://" + address)
        if parts.scheme != "http" or not parts.hostname:
            return None
        auth = None
        if parts.username:
            auth = base64.b64encode(f"{parts.username}:{parts.password or ''}".encode()).decode()
        return {"host": parts.hostname, "port": parts.port or 80, "auth": auth}
    except ValueError:
        return None


LOCAL = ("127.0.0.1", "localhost", "::1")


class Door:
    """`listener`: a listening socket (wherever it was made). `allowed`: the stores, `[host, port]` each.
    `through`: the person's own proxy for places that are not this computer (`upstream`), or None.
    `said`: called with one line for each store reached and each place refused."""

    def __init__(self, listener: socket.socket, allowed, through: dict | None = None, said=None):
        self.listener = listener
        self.allowed = {(str(h).lower(), int(p)) for h, p in allowed}
        self.through = through if isinstance(through, dict) and through.get("host") else None
        self.said = said or (lambda line: None)
        self.refused: list[str] = []
        self.reached: set[str] = set()
        self._closed = False

    def start(self) -> "Door":
        threading.Thread(target=self._serve, name="lantern-doorkeeper", daemon=True).start()
        return self

    def close(self) -> None:
        """No connection is taken from here on. A listener that a thread is waiting on stays open in the system
        until that wait ends, so the wait is ended first (`shutdown`), and a connection that slipped in between
        is closed unanswered (`_serve`)."""
        self._closed = True
        for end in (lambda: self.listener.shutdown(socket.SHUT_RDWR), self.listener.close):
            try:
                end()
            except OSError:
                pass

    def _serve(self) -> None:
        while not self._closed:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            if self._closed:
                conn.close()
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _reach(self, host: str, port: int) -> tuple[socket.socket, bytes]:
        """A connection to a store, straight or through the person's own proxy, and what that proxy sent after
        its answer."""
        if self.through and host not in LOCAL:
            s = socket.create_connection((self.through["host"], int(self.through["port"])), timeout=WAIT)
            ask = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            if self.through.get("auth"):
                ask += f"Proxy-Authorization: Basic {self.through['auth']}\r\n"
            s.sendall((ask + "\r\n").encode("ascii"))
            got = _head(s)
            if not got or b" 200" not in got[0].split(b"\r\n", 1)[0]:
                s.close()
                raise OSError("the proxy of this computer did not open the way to the store")
            return s, got[1]
        return socket.create_connection((host, port), timeout=WAIT), b""

    def _one(self, conn: socket.socket) -> None:
        out = None
        try:
            conn.settimeout(WAIT)
            got = _head(conn)
            if not got:
                return
            head, rest = got
            lines = head.decode("latin-1").split("\r\n")
            words = lines[0].split(" ")
            if len(words) != 3:
                return self._answer(conn, 400)
            method, target, version = words
            tunnel = method.upper() == "CONNECT"
            if tunnel:
                place, path = _place(target, 443), ""
            else:
                parts = urlsplit(target)
                place = _place(parts.netloc, 80) if parts.scheme == "http" else None
                path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
            if place is None:
                return self._answer(conn, 400)
            name = f"{place[0]}:{place[1]}"
            if place not in self.allowed:
                self.refused.append(name)
                self.said(f"{REFUSED} {name}")
                return self._answer(conn, 403)
            try:
                out, first = self._reach(*place)
            except OSError:
                return self._answer(conn, 502)
            if name not in self.reached:
                self.reached.add(name)
                self.said(f"{OPENED} {name}")
            if tunnel:
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self._pipe(conn, out, to_out=rest, to_conn=first)
            else:       # one request for one store, handed on as a request for that store itself
                kept = [ln for ln in lines[1:] if not ln.lower().startswith(("proxy-", "connection:"))]
                ask = "\r\n".join([f"{method} {path} {version}", *kept, "Connection: close"]) + "\r\n\r\n"
                self._pipe(conn, out, to_out=ask.encode("latin-1") + rest, to_conn=first)
        except OSError:
            pass
        finally:
            for s in (conn, out):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    @staticmethod
    def _answer(conn: socket.socket, status: int) -> None:
        words = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}[status]
        try:
            conn.sendall(f"HTTP/1.1 {status} {words}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
        except OSError:
            pass

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket, to_out: bytes = b"", to_conn: bytes = b"") -> None:
        """Everything `a` says goes to `b` and the other way round, until both have ended or neither has said
        anything for `IDLE` seconds."""
        a.settimeout(None)
        b.settimeout(None)
        if to_out:
            b.sendall(to_out)
        if to_conn:
            a.sendall(to_conn)
        other, going = {a: b, b: a}, {a, b}
        while going:
            ready, _, _ = select.select(list(going), [], [], IDLE)
            if not ready:
                return
            for s in ready:
                try:
                    data = s.recv(65536)
                except OSError:
                    return
                if data:
                    other[s].sendall(data)
                    continue
                going.discard(s)
                try:
                    other[s].shutdown(socket.SHUT_WR)
                except OSError:
                    pass


def listen(port: int = 0) -> socket.socket:
    """A listener on this computer's own address (in whichever network the caller is in)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)
    return s
