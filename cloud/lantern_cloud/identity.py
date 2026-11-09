"""Who is calling: the gateway's sign-in, reused.

The website signs a person in through the gateway (GitHub or Google, `/v1/login` + `/v1/auth/claim`, the same flow
the app and CLI use) and sends that token here as `Authorization: Bearer lt_...`. This service never sees an OAuth
secret or a password; it asks the gateway `GET /v1/whoami` which account the token belongs to, and keeps the answer
in memory for a few minutes keyed by the token's SHA-256 (the token itself is never stored or logged).

Each sign-in gets its own token at the gateway and earlier ones keep working; runs are keyed by the account id, so
they follow the person.
"""

from __future__ import annotations

import hashlib
import time

import httpx


class GatewayUnavailable(Exception):
    """The gateway did not answer; the caller says "sign-in check unavailable", never "signed out"."""


class Identity:
    MAX_CACHE = 5000

    def __init__(self, gateway_url: str, ttl: int = 300, transport: httpx.AsyncBaseTransport | None = None):
        self.base = gateway_url.rstrip("/")
        self.url = self.base + "/whoami"
        self.ttl = ttl
        self.transport = transport
        self.cache: dict[str, tuple[float, dict | None]] = {}

    async def whoami(self, token: str) -> dict | None:
        """{"account", "label"} for a valid token, None for an unknown or disabled one."""
        if not token or len(token) > 512:
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        hit = self.cache.get(key)
        if hit and hit[0] > time.monotonic():
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
        if len(self.cache) >= self.MAX_CACHE:
            self.cache.clear()
        # A refusal is remembered for a short while only, so a fresh sign-in works at once.
        self.cache[key] = (time.monotonic() + (self.ttl if who else min(self.ttl, 30)), who)
        return who

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

    def login_url(self, provider: str, cli: str) -> str:
        """The gateway page that sends the person straight to GitHub or Google; the token is parked under `cli`."""
        from urllib.parse import quote
        return f"{self.base}/auth/{quote(provider)}/start?cli={quote(cli)}"

    async def claim(self, cli: str) -> str | None:
        """The token parked for `cli` once the person has signed in (once, within ten minutes), else None."""
        from urllib.parse import quote
        r = await self._get(f"/auth/claim?cli={quote(cli)}")
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise GatewayUnavailable(f"HTTP {r.status_code}")
        try:
            tok = r.json().get("token")
        except (ValueError, AttributeError):
            raise GatewayUnavailable("bad answer") from None
        return tok if isinstance(tok, str) and 0 < len(tok) <= 512 else None
