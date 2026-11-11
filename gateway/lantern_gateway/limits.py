"""Limits on what anybody can send the gateway without signing in (stage 7 of the 2026-11-09 directive).

Three pieces, standard library only:

  * `BodyCap` wraps the whole app. No request's body is read past the limit of its path: a body that says it is
    larger is refused before any of it is read, and one that does not say is refused at the piece that crosses the
    limit. Without it the framework read a body whole before any handler could look at its size.
  * `Limiter` counts in memory, per kind and per sender, in windows of a fixed length (a minute, an hour, a day).
    Nothing of it is written to disk, and it starts empty when the gateway starts.
  * `sender` names who a request came from for those counts: the address the owner's proxy wrote in a header
    (Fly's `Fly-Client-IP`), else the address of the connection. IPv6 addresses count by their /64 network (one
    subscriber has all of it). The name the Limiter keeps is a keyed hash of that, made with a key that exists only
    in this process: no address is kept, in memory or on disk.

What the counts cannot do: a sender with many addresses is many senders. That is why each per-sender limit sits
beside a limit for everyone together where one matters (new installs a day, wrong admin secrets a minute).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import time

SMALL_BODY = 4000          # bytes: a usage report, a sign-out, a token's label


class Limiter:
    """Counts per (kind, sender, window). `take` counts one and says whether it was still within the limit; `full`
    only looks. Each kind holds at most `max_keys` counts; the senders there is no room for share one of them, so
    a flood of senders is limited more, never less."""

    def __init__(self, max_keys: int = 20_000, clock=time.time):
        self.max_keys = max_keys
        self.clock = clock
        self.key = secrets.token_bytes(32)
        self.counts: dict[str, dict[tuple[bytes, int], int]] = {}

    def name(self, who: str) -> bytes:
        """What is kept of a sender: a keyed hash, never the address."""
        return hmac.new(self.key, who.encode("utf-8", "replace"), hashlib.sha256).digest()[:16]

    def _slot(self, kind: str, who: str, window: int) -> tuple[dict, tuple[bytes, int]]:
        table = self.counts.setdefault(kind, {})
        now = int(self.clock() // window)
        slot = (self.name(who), now)
        if slot not in table and len(table) >= self.max_keys - 1:
            for old in [k for k in table if k[1] != now]:       # windows that have ended
                del table[old]
            if len(table) >= self.max_keys - 1:
                slot = (b"", now)                               # no room: everybody else, together
        return table, slot

    def take(self, kind: str, who: str, limit: int, window: int) -> bool:
        table, slot = self._slot(kind, who, window)
        table[slot] = table.get(slot, 0) + 1
        return table[slot] <= limit

    def full(self, kind: str, who: str, limit: int, window: int) -> bool:
        table, slot = self._slot(kind, who, window)
        return table.get(slot, 0) >= limit

    def wait(self, window: int) -> int:
        """Seconds until the window that is running now ends (at least 1)."""
        return max(1, int(window - self.clock() % window))

    def size(self) -> int:
        return max((len(t) for t in self.counts.values()), default=0)


def _address(text: str) -> str | None:
    """`text` as the address the counts go by, or None when it is no address."""
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 6:
        return str(ipaddress.IPv6Address(int(ip) >> 64 << 64)) + "/64"
    return str(ip)


def sender(scope: dict, header: str = "") -> str:
    """Who sent this request, for the counts. `header` is the header the owner's proxy writes the caller's address
    in ("" when there is no such proxy: a header a caller writes itself must not name it). A header that holds no
    address is passed over."""
    if header:
        want = header.lower().encode("latin-1", "replace")
        for key, value in scope.get("headers") or ():
            if key.lower() == want:
                found = _address(value.decode("latin-1"))
                if found:
                    return found
    host = (scope.get("client") or ("", 0))[0] or ""
    return _address(host) or f"connection:{host}"


class BodyCap:
    """ASGI wrapper: at most `limit_for(path)` bytes of a request's body are read. Past it the caller gets 413
    in the gateway's own JSON, the app is told the caller has gone, and whatever the app then says or raises is
    dropped."""

    def __init__(self, app, limit_for):
        self.app = app
        self.limit_for = limit_for

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit, words = self.limit_for(scope.get("path") or "")
        state = {"taken": 0, "refused": False, "started": False}

        async def refuse():
            state["refused"] = True
            if state["started"]:
                return
            body = json.dumps({"error": {"type": "too_large", "message": words}}).encode()
            await send({"type": "http.response.start", "status": 413,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                    (b"connection", b"close")]})
            await send({"type": "http.response.body", "body": body})

        declared = next((v for k, v in scope.get("headers") or () if k.lower() == b"content-length"), None)
        if declared is not None:
            try:
                too_large = int(declared) > limit
            except ValueError:
                too_large = True                                # a length that is no number
            if too_large:
                await refuse()
                return

        async def capped_receive():
            if state["refused"]:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                state["taken"] += len(message.get("body") or b"")
                if state["taken"] > limit:
                    await refuse()
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            if state["refused"]:
                return
            if message["type"] == "http.response.start":
                state["started"] = True
            await send(message)

        try:
            await self.app(scope, capped_receive, guarded_send)
        except Exception:
            if not state["refused"]:
                raise
