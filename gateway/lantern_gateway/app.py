"""Lantern gateway: the free allowance.

Holds the project's DeepSeek key on the server (never in the client), and gives each user a metered
allowance through an OpenAI-compatible endpoint. When a user's allowance runs out they get HTTP 402
and the Lantern CLI tells them how to add their own key.

Guarantees, in order of importance:
  1. The upstream key never leaves this process; clients only ever see their own Lantern token.
  2. Spend is bounded: per-user lifetime and daily limits, plus a global daily dollar cap that pauses
     the free allowance for everyone before the owner's bill can run away.
  3. Requests are narrowed to what Lantern needs: one allowed model, capped max_tokens, capped body
     size, chat messages only. The gateway can't be used as a general-purpose free LLM.
  4. No code is stored: only token hashes, counts, and costs. Request and response bodies are never
     logged or written to disk.

Run:  DEEPSEEK_API_KEY=... LANTERN_ADMIN_SECRET=... uvicorn lantern_gateway.app:create_app --factory
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    upstream_url: str = field(default_factory=lambda: os.environ.get("UPSTREAM_URL", "https://api.deepseek.com").rstrip("/"))
    upstream_key: str = field(default_factory=lambda: os.environ.get("DEEPSEEK_API_KEY", ""))
    model: str = field(default_factory=lambda: os.environ.get("LANTERN_MODEL_ID", "deepseek-flash"))
    admin_secret: str = field(default_factory=lambda: os.environ.get("LANTERN_ADMIN_SECRET", ""))
    db_path: str = field(default_factory=lambda: os.environ.get("LANTERN_DB", "lantern_gateway.db"))
    # Per user. ~300 explanations is a few full runs on a typical app.
    free_requests: int = field(default_factory=lambda: _env_int("LANTERN_FREE_REQUESTS", 300))
    free_tokens: int = field(default_factory=lambda: _env_int("LANTERN_FREE_TOKENS", 1_500_000))
    daily_requests: int = field(default_factory=lambda: _env_int("LANTERN_DAILY_REQUESTS", 120))
    # Everyone, per UTC day. When reached, the allowance pauses until tomorrow (HTTP 503).
    global_daily_usd: float = field(default_factory=lambda: _env_float("LANTERN_GLOBAL_DAILY_USD", 10.0))
    max_tokens_cap: int = field(default_factory=lambda: _env_int("LANTERN_MAX_TOKENS", 3000))
    max_body_bytes: int = field(default_factory=lambda: _env_int("LANTERN_MAX_BODY", 250_000))
    # Price per 1M tokens used for the spend cap. Defaults: deepseek-flash *peak* rates (conservative).
    usd_per_m_input: float = field(default_factory=lambda: _env_float("LANTERN_USD_PER_M_INPUT", 0.30))
    usd_per_m_output: float = field(default_factory=lambda: _env_float("LANTERN_USD_PER_M_OUTPUT", 1.20))


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    """SQLite: token hashes and counters only."""

    def __init__(self, path: str):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript("""
            create table if not exists users (
              token_hash text primary key, label text, created text,
              used_requests integer default 0, used_tokens integer default 0, disabled integer default 0);
            create table if not exists daily (
              day text, token_hash text, requests integer default 0, primary key (day, token_hash));
            create table if not exists spend (day text primary key, usd real default 0, requests integer default 0);
        """)
        self.db.commit()

    def mint(self, label: str) -> str:
        token = "lt_" + secrets.token_urlsafe(32)
        with self.lock:
            self.db.execute("insert into users (token_hash, label, created) values (?, ?, ?)",
                            (_hash(token), label[:100], dt.datetime.now(dt.UTC).isoformat()))
            self.db.commit()
        return token

    def user(self, token: str) -> dict | None:
        row = self.db.execute("select token_hash, used_requests, used_tokens, disabled from users where token_hash = ?",
                              (_hash(token),)).fetchone()
        if not row:
            return None
        return {"hash": row[0], "used_requests": row[1], "used_tokens": row[2], "disabled": bool(row[3])}

    def today_requests(self, h: str, day: str) -> int:
        row = self.db.execute("select requests from daily where day = ? and token_hash = ?", (day, h)).fetchone()
        return row[0] if row else 0

    def spend_today(self, day: str) -> float:
        row = self.db.execute("select usd from spend where day = ?", (day,)).fetchone()
        return row[0] if row else 0.0

    def record(self, h: str, day: str, tokens: int, usd: float) -> None:
        with self.lock:
            self.db.execute("update users set used_requests = used_requests + 1, used_tokens = used_tokens + ? "
                            "where token_hash = ?", (tokens, h))
            self.db.execute("insert into daily (day, token_hash, requests) values (?, ?, 1) "
                            "on conflict(day, token_hash) do update set requests = requests + 1", (day, h))
            self.db.execute("insert into spend (day, usd, requests) values (?, ?, 1) "
                            "on conflict(day) do update set usd = usd + excluded.usd, requests = requests + 1",
                            (day, usd))
            self.db.commit()


def _err(status: int, kind: str, message: str, **extra) -> JSONResponse:
    return JSONResponse({"error": {"type": kind, "message": message, **extra}}, status_code=status)


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    s = settings or Settings()
    store = Store(s.db_path)
    app = FastAPI(title="Lantern gateway", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings = store, s

    def today() -> str:
        return dt.datetime.now(dt.UTC).date().isoformat()

    def auth(authorization: str | None) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing token")
        u = store.user(authorization[7:].strip())
        if u is None or u["disabled"]:
            raise HTTPException(401, "unknown or disabled token")
        return u

    def remaining(u: dict, day: str) -> dict:
        return {
            "requests": max(0, s.free_requests - u["used_requests"]),
            "tokens": max(0, s.free_tokens - u["used_tokens"]),
            "today": max(0, s.daily_requests - store.today_requests(u["hash"], day)),
        }

    @app.get("/v1/health")
    def health():
        return {"ok": True, "model": s.model, "configured": bool(s.upstream_key)}

    @app.post("/v1/tokens")
    def mint(payload: dict, authorization: str | None = Header(default=None)):
        """Admin only: create a user token. Returned once; only its hash is stored."""
        if not s.admin_secret or not authorization or not hmac.compare_digest(
                authorization.removeprefix("Bearer ").strip(), s.admin_secret):
            raise HTTPException(403, "admin only")
        return {"token": store.mint(str(payload.get("label", ""))), "limits": {
            "requests": s.free_requests, "tokens": s.free_tokens, "per_day": s.daily_requests}}

    @app.get("/v1/allowance")
    def allowance(authorization: str | None = Header(default=None)):
        u = auth(authorization)
        r = remaining(u, today())
        return {"used_requests": u["used_requests"], "limit_requests": s.free_requests,
                "used_tokens": u["used_tokens"], "limit_tokens": s.free_tokens,
                "remaining_requests": r["requests"], "remaining_tokens": r["tokens"],
                "remaining_today": r["today"], "model": s.model}

    @app.post("/v1/chat/completions")
    async def chat(request: Request, authorization: str | None = Header(default=None)):
        u = auth(authorization)
        day = today()
        raw = await request.body()
        if len(raw) > s.max_body_bytes:
            return _err(413, "too_large", "Request is larger than the free allowance accepts.")
        try:
            body = json.loads(raw)
        except ValueError:
            return _err(400, "bad_request", "Body must be JSON.")
        r = remaining(u, day)
        if r["requests"] <= 0 or r["tokens"] <= 0:
            return _err(402, "quota_exceeded",
                        f"You've used your free Lantern allowance ({s.free_requests} explanations).",
                        remaining=0)
        if r["today"] <= 0:
            return _err(402, "daily_limit",
                        f"You've reached today's free limit ({s.daily_requests}). It resets at 00:00 UTC.",
                        remaining=r["requests"])
        if store.spend_today(day) >= s.global_daily_usd:
            return _err(503, "allowance_paused",
                        "The free allowance is paused for today because it reached its daily budget.")
        if not s.upstream_key:
            return _err(503, "not_configured", "The gateway has no upstream key configured.")
        msgs = body.get("messages")
        if not isinstance(msgs, list) or not msgs or len(msgs) > 4 or not all(
                isinstance(m, dict) and m.get("role") in ("system", "user", "assistant")
                and isinstance(m.get("content"), str) for m in msgs):
            return _err(400, "bad_request", "Only plain chat messages are accepted.")
        # Narrow the request to what Lantern needs; ignore everything else the client sent.
        out = {"model": s.model, "messages": [{"role": m["role"], "content": m["content"]} for m in msgs],
               "max_tokens": max(1, min(int(body.get("max_tokens") or s.max_tokens_cap), s.max_tokens_cap)),
               "thinking": {"type": "disabled"}}
        if isinstance(body.get("response_format"), dict) and body["response_format"].get("type") == "json_object":
            out["response_format"] = {"type": "json_object"}
        try:
            async with httpx.AsyncClient(transport=transport, timeout=120) as client:
                resp = await client.post(f"{s.upstream_url}/chat/completions", json=out,
                                         headers={"authorization": f"Bearer {s.upstream_key}"})
        except httpx.HTTPError:
            return _err(502, "upstream_unreachable", "Could not reach the model provider. Try again shortly.")
        if resp.status_code != 200:
            # Never echo upstream bodies: they can include account details.
            return _err(502 if resp.status_code >= 500 or resp.status_code in (401, 402, 403) else resp.status_code,
                        "upstream_error", f"The model provider returned HTTP {resp.status_code}.")
        data = resp.json()
        usage = data.get("usage") or {}
        tin, tout = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        usd = tin / 1e6 * s.usd_per_m_input + tout / 1e6 * s.usd_per_m_output
        store.record(u["hash"], day, tin + tout, usd)
        after = remaining(store.user(authorization[7:].strip()), day)
        clean = {"id": data.get("id"), "object": "chat.completion", "model": data.get("model", s.model),
                 "choices": [{"index": c.get("index", 0), "finish_reason": c.get("finish_reason"),
                              "message": {"role": "assistant", "content": (c.get("message") or {}).get("content")}}
                             for c in data.get("choices", [])],
                 "usage": {"prompt_tokens": tin, "completion_tokens": tout, "total_tokens": tin + tout}}
        return JSONResponse(clean, headers={
            "x-lantern-remaining-requests": str(after["requests"]),
            "x-lantern-remaining-tokens": str(after["tokens"]),
            "x-lantern-remaining-today": str(after["today"])})

    return app

