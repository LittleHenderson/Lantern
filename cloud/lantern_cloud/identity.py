"""Who is calling: the gateway's sign-in, reused.

The website signs a person in through the gateway (GitHub or Google, `/v1/login` + `/v1/auth/claim`, the same flow
the app and CLI use) and sends that token here as `Authorization: Bearer lt_...`. This service never sees an OAuth
secret or a password; it asks the gateway `GET /v1/whoami` which account the token belongs to, and keeps the answer
in memory for a few minutes keyed by the token's SHA-256 (the token itself is never stored or logged).

Signing in again rotates the token at the gateway; runs are keyed by the account id, so they follow the person.
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
        self.url = gateway_url.rstrip("/") + "/whoami"
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
