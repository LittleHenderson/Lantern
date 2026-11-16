"""Who is calling: the gateway's sign-in, reused.

The website signs a person in through the gateway (GitHub or Google, `/v1/login` + `/v1/auth/claim`, the same flow
the app and CLI use) and sends that token here as `Authorization: Bearer lt_...`. This service never sees an OAuth
secret or a password; it asks the gateway `GET /v1/whoami` which account the token belongs to, each time (the
token itself is never stored or logged).

Each sign-in gets its own token at the gateway and earlier ones keep working; runs are keyed by the account id, so
they follow the person.

A sign-in that was ended is refused from then on (review stage, 2026-11-15). Until then a "yes" was kept for five
minutes, so a sign-in ended somewhere else (the app's "sign out everywhere", an account switched off) went on
working here that long. The owner can still let answers be remembered (`ttl` above 0): a "yes" is then used again
for a read, never for a request that changes something or makes a link (`fresh`). And a sign-out from the website
that the gateway did not hear of is no sign-out that worked: the website itself takes that sign-in no more
(`end_here`, `ended`), says so, and tries again for a few minutes to end it at the gateway (`again`, `finish`).
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time

import httpx


class GatewayUnavailable(Exception):
    """The gateway did not answer; the caller says "sign-in check unavailable", never "signed out"."""


def _key(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


class Identity:
    MAX_CACHE = 5000
    MOST_ENDED = 5000                       # sign-ins signed out here that the gateway has not said are ended
    TRY_AGAIN = (5, 15, 45, 120, 300)       # seconds from one further try to end such a sign-in to the next

    def __init__(self, gateway_url: str, ttl: int = 0, transport: httpx.AsyncBaseTransport | None = None):
        self.base = gateway_url.rstrip("/")
        self.url = self.base + "/whoami"
        self.ttl = ttl
        self.transport = transport
        self.cache: dict[str, tuple[float, dict | None]] = {}
        # Tokens by their SHA-256, in memory only. `seen`: the gateway said yes to it here, with the account it
        # named (it grants nothing: it tells a real sign-in from made-up text when a sign-out goes unheard, and
        # says whose links to results end with a sign-out). `ended`: signed out here, unheard
        # by the gateway, refused here from then on (True: one the website had seen). `unfinished`: the tokens of
        # those it had seen, held only while the further tries last.
        self.seen: dict[str, str] = {}
        self.ended: dict[str, bool] = {}
        self.unfinished: dict[str, str] = {}
        self.again: tuple = self.TRY_AGAIN
        self.trying: threading.Thread | None = None
        self.over = threading.Event()       # the service is stopping
        self._lock = threading.Lock()
        self._going = self._newer = False

    async def whoami(self, token: str, fresh: bool = False) -> dict | None:
        """{"account", "label"} for a valid token, None for an unknown or disabled one and for one signed out here.
        `fresh`: the request changes something or makes a link, so a remembered "yes" is not enough for it."""
        if not token or len(token) > 512:
            return None
        key = _key(token)
        if key in self.ended:
            return None
        hit = self.cache.get(key)
        if hit and hit[0] > time.monotonic() and not (fresh and hit[1]):
            return hit[1]
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=10) as client:
                r = await client.get(self.url, headers={"authorization": f"Bearer {token}",
                                                        "user-agent": "lantern-cloud"})
        except httpx.HTTPError as e:
            raise GatewayUnavailable(type(e).__name__) from None
        if r.status_code == 401:
            who = None
        elif r.status_code == 200:
            try:
                d = r.json()
            except ValueError:
                raise GatewayUnavailable("bad answer") from None
            acc = d.get("account") if isinstance(d, dict) else None
            if not isinstance(acc, str) or not acc or len(acc) > 100:
                raise GatewayUnavailable("bad answer")
            who = {"account": acc, "label": str(d.get("label") or "")[:100]}
        else:
            raise GatewayUnavailable(f"HTTP {r.status_code}")
        if who:
            self.seen.pop(key, None)
            self.seen[key] = who["account"]
            while len(self.seen) > self.MAX_CACHE:
                del self.seen[next(iter(self.seen))]
        if self.ttl > 0:
            if len(self.cache) >= self.MAX_CACHE:
                self.cache.clear()
            # A refusal is remembered for a short while only, so a fresh sign-in works at once.
            self.cache[key] = (time.monotonic() + (self.ttl if who else min(self.ttl, 30)), who)
        else:
            self.cache.pop(key, None)
        return who

    def forget(self, token: str) -> None:
        """Drop the remembered answer for a token the gateway has since refused (signed in somewhere else)."""
        self.cache.pop(_key(token), None)

    def account_of(self, token: str) -> str | None:
        """The account the gateway named for this token here, if it was used here since the service started."""
        return self.seen.get(_key(token))

    def ended_here(self, token: str) -> bool:
        return _key(token) in self.ended

    def end_here(self, token: str) -> bool:
        """This sign-in was signed out on the website and the gateway did not hear of it. The website takes it no
        more from now on. True when it is a sign-in the gateway had said yes to here: then the website tries again
        for a while to end it at the gateway (`again`). Text it never saw as a sign-in is refused and not tried
        again, and never pushes a real one off the list (`MOST_ENDED`: the oldest of its own kind goes first)."""
        key = _key(token)
        start = False
        with self._lock:
            sure = key in self.seen or self.ended.get(key, False)
            self.ended.pop(key, None)
            self.ended[key] = sure
            self.cache.pop(key, None)
            while len(self.ended) > self.MOST_ENDED:
                old = next((k for k, real in self.ended.items() if not real), None) or next(iter(self.ended))
                del self.ended[old]
                self.unfinished.pop(old, None)
            real = sure and key in self.ended
            if real:
                self.unfinished[key] = token
            later = real and bool(self.again)       # with no `again`, whoever made this object calls `finish`
            if later:
                self._newer = True
                start, self._going = not self._going, True
                if start:
                    self.trying = threading.Thread(target=self._keep_trying, name="lantern-signout", daemon=True)
        if start:
            self.trying.start()
        return later

    async def finish(self) -> int:
        """One more try to end, at the gateway, each sign-in that was signed out here unheard. How many are left."""
        for key, token in list(self.unfinished.items()):
            try:
                await self.sign_out(token)
            except GatewayUnavailable:
                continue
            with self._lock:                # the gateway has heard (or knows no such sign-in): it refuses it now
                self.unfinished.pop(key, None)
                self.ended.pop(key, None)
        return len(self.unfinished)

    def _keep_trying(self) -> None:
        """The further tries, `again` seconds apart, counted anew when another sign-out goes unheard meanwhile.
        After the last one the tokens are let go of; the website goes on refusing them."""
        tries = 0
        while True:
            with self._lock:
                if self._newer:
                    tries, self._newer = 0, False
                if not self.unfinished or tries >= len(self.again):
                    self.unfinished.clear()
                    self._going = False
                    return
                wait = self.again[tries]
            if self.over.wait(wait):
                with self._lock:
                    self.unfinished.clear()
                    self._going = False
                return
            tries += 1
            try:
                asyncio.run(self.finish())
            except Exception:  # noqa: BLE001  (a try that failed in any way is a try that did not reach the gateway)
                pass

    async def _get(self, path: str) -> httpx.Response:
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=10) as client:
                return await client.get(self.base + path, headers={"user-agent": "lantern-cloud"})
        except httpx.HTTPError as e:
            raise GatewayUnavailable(type(e).__name__) from None

    async def providers(self) -> list[str]:
        """The sign-in providers the gateway has switched on (GitHub, Google)."""
        r = await self._get("/auth/providers")
        if r.status_code != 200:
            raise GatewayUnavailable(f"HTTP {r.status_code}")
        try:
            ps = r.json().get("providers") or []
        except (ValueError, AttributeError):
            raise GatewayUnavailable("bad answer") from None
        return [p for p in ps if p in ("github", "google")]

    async def allowance(self, token: str) -> dict | None:
        """What is left of the person's free allowance (`GET /v1/allowance`), numbers only; None if not known."""
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=10) as client:
                r = await client.get(self.base + "/allowance", headers={"authorization": f"Bearer {token}",
                                                                         "user-agent": "lantern-cloud"})
        except httpx.HTTPError as e:
            raise GatewayUnavailable(type(e).__name__) from None
        if r.status_code != 200:
            return None
        try:
            d = r.json()
        except ValueError:
            return None
        keys = ("remaining_requests", "limit_requests", "remaining_today")
        return {k: d.get(k) if isinstance(d.get(k), int) and not isinstance(d.get(k), bool) else None for k in keys}

    def login_url(self, provider: str, challenge: str, back: str, nonce: str) -> str:
        """The gateway page that sends the person straight to GitHub or Google. `challenge`: the SHA-256 of a secret
        the website keeps for this browser; `back`: where the gateway sends the browser afterwards (the website's
        `/v1/signin/return`); `nonce`: the website's mark of this sign-in."""
        from urllib.parse import quote, urlencode
        return f"{self.base}/auth/{quote(provider)}/start?" + urlencode({"challenge": challenge, "return": back, "nonce": nonce})

    async def sign_out(self, token: str, everywhere: bool = False) -> int:
        """End this sign-in at the gateway (or every sign-in of the account) and forget cached answers."""
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=10) as client:
                r = await client.post(self.base + "/auth/signout", json={"everywhere": everywhere},
                                      headers={"authorization": f"Bearer {token}", "user-agent": "lantern-cloud"})
        except httpx.HTTPError as e:
            raise GatewayUnavailable(type(e).__name__) from None
        # Every cached answer goes: the account's other tokens are not known here by hash.
        self.cache.clear()
        if r.status_code == 401:
            return 0
        if r.status_code != 200:
            raise GatewayUnavailable(f"HTTP {r.status_code}")
        try:
            return int(r.json().get("signed_out") or 0)
        except (ValueError, AttributeError, TypeError):
            return 0

    async def redeem(self, code: str, verifier: str) -> str | None:
        """The token of a sign-in the website started: the one-time code the browser came back with and the secret
        kept for that browser (`POST /v1/auth/redeem`). One try per code. None when the gateway has nothing to give
        for the two (used, too late, not started with this secret)."""
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=10) as client:
                r = await client.post(self.base + "/auth/redeem", json={"code": code, "verifier": verifier},
                                      headers={"user-agent": "lantern-cloud"})
        except httpx.HTTPError as e:
            raise GatewayUnavailable(type(e).__name__) from None
        if r.status_code in (400, 429):
            return None
        if r.status_code != 200:
            raise GatewayUnavailable(f"HTTP {r.status_code}")
        try:
            tok = r.json().get("token")
        except (ValueError, AttributeError):
            raise GatewayUnavailable("bad answer") from None
        return tok if isinstance(tok, str) and 0 < len(tok) <= 512 else None
