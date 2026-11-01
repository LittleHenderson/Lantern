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
    # Fallback: Anthropic, used only when DeepSeek fails (no balance, rate limited, down, unreachable). Off until
    # ANTHROPIC_API_KEY is set. Prices default to Claude Haiku 5.5 standard rates (prompts under 100k tokens).
    fallback_url: str = field(default_factory=lambda: os.environ.get("FALLBACK_URL", "https://api.anthropic.com").rstrip("/"))
    fallback_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    fallback_model: str = field(default_factory=lambda: os.environ.get("LANTERN_FALLBACK_MODEL", "claude-haiku-5-5"))
    fallback_usd_per_m_input: float = field(default_factory=lambda: _env_float("LANTERN_FALLBACK_USD_PER_M_INPUT", 0.10))
    fallback_usd_per_m_output: float = field(default_factory=lambda: _env_float("LANTERN_FALLBACK_USD_PER_M_OUTPUT", 0.50))


# The only feature names a usage ping may carry. Counts per name per day; never file names, paths or code.
USAGE_FEATURES = frozenset({
    "analyze", "analyze_link", "explain", "explain_one", "accept", "starter", "verify", "export_sarif", "packs",
    "serve", "learn", "trace", "mcp_call", "mcp_connect", "evidence", "report_open", "settings_save"})


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    """SQLite: token hashes and counters only."""

    def __init__(self, path: str, free_requests: int = 300):
        self.lock = threading.Lock()
        self.free_requests = free_requests
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript("""
            create table if not exists users (
              token_hash text primary key, label text, created text,
              used_requests integer default 0, used_tokens integer default 0, disabled integer default 0);
            create table if not exists daily (
              day text, token_hash text, requests integer default 0, primary key (day, token_hash));
            create table if not exists spend (day text primary key, usd real default 0, requests integer default 0);
            create table if not exists models (
              day text, model text, requests integer default 0, usd real default 0, primary key (day, model));
            create table if not exists installs (
              install text primary key, first_seen text, last_seen text, version text, os text);
            create table if not exists usage (
              day text, install text, feature text, count integer default 0, primary key (day, install, feature));
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

    def record(self, h: str, day: str, tokens: int, usd: float, model: str = "") -> None:
        with self.lock:
            if model:
                self.db.execute("insert into models (day, model, requests, usd) values (?, ?, 1, ?) "
                                "on conflict(day, model) do update set usd = usd + excluded.usd, requests = requests + 1",
                                (day, model, usd))
            self.db.execute("update users set used_requests = used_requests + 1, used_tokens = used_tokens + ? "
                            "where token_hash = ?", (tokens, h))
            self.db.execute("insert into daily (day, token_hash, requests) values (?, ?, 1) "
                            "on conflict(day, token_hash) do update set requests = requests + 1", (day, h))
            self.db.execute("insert into spend (day, usd, requests) values (?, ?, 1) "
                            "on conflict(day) do update set usd = usd + excluded.usd, requests = requests + 1",
                            (day, usd))
            self.db.commit()


    # ---- opt-in usage pings from the app (counts per feature per day; no code, no paths, no names) ----
    def record_usage(self, install: str, day: str, version: str, os_name: str, features: dict[str, int]) -> None:
        now = dt.datetime.now(dt.UTC).isoformat()
        with self.lock:
            self.db.execute("insert into installs (install, first_seen, last_seen, version, os) values (?, ?, ?, ?, ?) "
                            "on conflict(install) do update set last_seen = excluded.last_seen, "
                            "version = excluded.version, os = excluded.os", (install, now, now, version, os_name))
            for feature, count in features.items():
                self.db.execute("insert into usage (day, install, feature, count) values (?, ?, ?, ?) "
                                "on conflict(day, install, feature) do update set count = max(count, excluded.count)",
                                (day, install, feature, count))
            self.db.commit()

    def stats(self, today: str, days: int = 30) -> dict:
        """Everything the owner's dashboard shows. Aggregates only."""
        since = (dt.date.fromisoformat(today) - dt.timedelta(days=days - 1)).isoformat()
        week = (dt.date.fromisoformat(today) - dt.timedelta(days=6)).isoformat()
        q = self.db.execute
        one = lambda sql, *a: (q(sql, a).fetchone() or [0])[0] or 0  # noqa: E731
        rows = lambda sql, *a: q(sql, a).fetchall()  # noqa: E731
        return {
            "today": today, "days": days,
            "allowance": {
                "tokens_issued": one("select count(*) from users"),
                "users_ever_used": one("select count(*) from users where used_requests > 0"),
                "users_active_today": one("select count(distinct token_hash) from daily where day = ?", today),
                "users_active_7d": one("select count(distinct token_hash) from daily where day >= ?", week),
                "users_active_30d": one("select count(distinct token_hash) from daily where day >= ?", since),
                "requests_today": one("select requests from spend where day = ?", today),
                "requests_30d": one("select sum(requests) from spend where day >= ?", since),
                "usd_today": round(one("select usd from spend where day = ?", today), 4),
                "usd_30d": round(one("select sum(usd) from spend where day >= ?", since), 4),
                "users_exhausted": one("select count(*) from users where used_requests >= ?", self.free_requests),
                "disabled": one("select count(*) from users where disabled = 1"),
                "daily": [{"day": d, "requests": r, "usd": round(u, 4)} for d, r, u in
                          rows("select day, requests, usd from spend where day >= ? order by day", since)],
                "by_model": [{"model": m, "requests": r, "usd": round(u, 4)} for m, r, u in
                             rows("select model, sum(requests), sum(usd) from models where day >= ? group by model "
                                  "order by sum(requests) desc", since)],
                "top_users": [{"label": lb or "(no label)", "requests": r, "tokens": t} for lb, r, t in
                              rows("select label, used_requests, used_tokens from users order by used_requests desc limit 10")],
            },
            "app": {
                "installs_total": one("select count(*) from installs"),
                "installs_active_7d": one("select count(distinct install) from usage where day >= ?", week),
                "installs_active_30d": one("select count(distinct install) from usage where day >= ?", since),
                "features_30d": [{"feature": f, "count": c, "installs": n} for f, c, n in
                                 rows("select feature, sum(count), count(distinct install) from usage where day >= ? "
                                      "group by feature order by sum(count) desc", since)],
                "daily_installs": [{"day": d, "installs": n} for d, n in
                                   rows("select day, count(distinct install) from usage where day >= ? group by day order by day", since)],
                "versions": [{"version": v, "installs": n} for v, n in
                             rows("select version, count(*) from installs group by version order by count(*) desc limit 8")],
                "os": [{"os": o, "installs": n} for o, n in rows("select os, count(*) from installs group by os order by count(*) desc")],
            },
        }


async def _anthropic(transport, s: "Settings", out: dict) -> dict | None:
    """The same narrowed request against Anthropic's Messages API, answered in OpenAI shape. None on any failure."""
    system = "\n\n".join(m["content"] for m in out["messages"] if m["role"] == "system")
    msgs = [{"role": m["role"], "content": m["content"]} for m in out["messages"] if m["role"] != "system"]
    if not msgs or msgs[0]["role"] != "user":
        msgs.insert(0, {"role": "user", "content": "(see system prompt)"})
    body = {"model": s.fallback_model, "max_tokens": out["max_tokens"], "messages": msgs}
    if system:
        body["system"] = system
    try:
        async with httpx.AsyncClient(transport=transport, timeout=120) as client:
            r = await client.post(f"{s.fallback_url}/v1/messages", json=body,
                                  headers={"x-api-key": s.fallback_key, "anthropic-version": "2023-06-01"})
        if r.status_code != 200:
            return None
        d = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
    if out.get("response_format", {}).get("type") == "json_object":
        i, j = text.find("{"), text.rfind("}")   # Anthropic has no JSON mode; trim any prose around the object
        if i >= 0 and j > i:
            text = text[i:j + 1]
    u = d.get("usage") or {}
    return {"id": d.get("id"), "model": d.get("model", s.fallback_model),
            "choices": [{"index": 0, "finish_reason": d.get("stop_reason"), "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": int(u.get("input_tokens") or 0), "completion_tokens": int(u.get("output_tokens") or 0)}}


def _err(status: int, kind: str, message: str, **extra) -> JSONResponse:
    return JSONResponse({"error": {"type": kind, "message": message, **extra}}, status_code=status)


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    s = settings or Settings()
    store = Store(s.db_path, s.free_requests)
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
        return {"ok": True, "model": s.model, "configured": bool(s.upstream_key),
                "fallback": s.fallback_model if s.fallback_key else None}

    def admin(authorization: str | None) -> None:
        if not s.admin_secret or not authorization or not hmac.compare_digest(
                authorization.removeprefix("Bearer ").strip(), s.admin_secret):
            raise HTTPException(403, "admin only")

    @app.post("/v1/tokens")
    def mint(payload: dict, authorization: str | None = Header(default=None)):
        """Admin only: create a user token. Returned once; only its hash is stored."""
        admin(authorization)
        return {"token": store.mint(str(payload.get("label", ""))), "limits": {
            "requests": s.free_requests, "tokens": s.free_tokens, "per_day": s.daily_requests}}

    @app.get("/v1/admin/stats")
    def admin_stats(authorization: str | None = Header(default=None), days: int = 30):
        """Admin only: the numbers behind the dashboard. Aggregates, never bodies or code."""
        admin(authorization)
        return {**store.stats(today(), max(1, min(int(days), 365))), "global_daily_usd": s.global_daily_usd,
                "limits": {"requests": s.free_requests, "tokens": s.free_tokens, "per_day": s.daily_requests}}

    @app.get("/v1/admin")
    def admin_page():
        """The owner's dashboard: one page that asks for the admin secret (kept in this tab only) and draws the
        numbers from /v1/admin/stats. No framework, no outside requests."""
        from fastapi.responses import HTMLResponse
        from .dashboard import PAGE
        return HTMLResponse(PAGE, headers={"Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; "
                                                                       "style-src 'unsafe-inline'; connect-src 'self'"})

    @app.post("/v1/usage")
    async def usage(request: Request):
        """Opt-in usage ping from the Lantern app: a random install id, the app version and OS, and how many
        times each feature was used that day. Nothing else is accepted; unknown fields are dropped."""
        raw = await request.body()
        if len(raw) > 4000:
            return _err(413, "too_large", "usage ping too large")
        try:
            body = json.loads(raw)
        except ValueError:
            return _err(400, "bad_request", "Body must be JSON.")
        install = str(body.get("install") or "")
        if not isinstance(body, dict) or len(install) != 32 or any(c not in "0123456789abcdef" for c in install):
            return _err(400, "bad_request", "install must be 32 hex characters")
        day = str(body.get("day") or today())
        try:
            d = dt.date.fromisoformat(day)
        except ValueError:
            return _err(400, "bad_request", "bad day")
        if abs((dt.date.fromisoformat(today()) - d).days) > 3:
            return _err(400, "bad_request", "day too far from today")
        feats = body.get("features")
        if not isinstance(feats, dict):
            return _err(400, "bad_request", "features must be an object")
        clean = {}
        for k, v in list(feats.items())[:40]:
            if isinstance(k, str) and k in USAGE_FEATURES and isinstance(v, int) and not isinstance(v, bool) and v > 0:
                clean[k] = min(v, 100_000)
        store.record_usage(install, d.isoformat(), str(body.get("version") or "")[:20], str(body.get("os") or "")[:20], clean)
        return {"ok": True, "recorded": sorted(clean)}

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
        used_model, data, err = s.model, None, None
        try:
            async with httpx.AsyncClient(transport=transport, timeout=120) as client:
                resp = await client.post(f"{s.upstream_url}/chat/completions", json=out,
                                         headers={"authorization": f"Bearer {s.upstream_key}"})
            if resp.status_code == 200:
                data = resp.json()
            else:
                err = resp.status_code
        except httpx.HTTPError:
            err = "unreachable"
        # DeepSeek failed. Its own account problems (no balance, rate limit, outage) must not take the free
        # allowance down, so hand the same request to the fallback when one is configured.
        if data is None and s.fallback_key and (err == "unreachable" or err in (401, 402, 403, 429) or int(err) >= 500):
            fb = await _anthropic(transport, s, out)
            if fb is not None:
                data, used_model, err = fb, s.fallback_model, None
        if data is None:
            if err == "unreachable":
                return _err(502, "upstream_unreachable", "Could not reach the model provider. Try again shortly.")
            # Never echo upstream bodies: they can include account details.
            return _err(502 if err >= 500 or err in (401, 402, 403) else err,
                        "upstream_error", f"The model provider returned HTTP {err}.")
        usage = data.get("usage") or {}
        tin, tout = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        pin, pout = ((s.fallback_usd_per_m_input, s.fallback_usd_per_m_output) if used_model == s.fallback_model
                     else (s.usd_per_m_input, s.usd_per_m_output))
        usd = tin / 1e6 * pin + tout / 1e6 * pout
        store.record(u["hash"], day, tin + tout, usd, used_model)
        after = remaining(store.user(authorization[7:].strip()), day)
        clean = {"id": data.get("id"), "object": "chat.completion", "model": data.get("model", used_model),
                 "choices": [{"index": c.get("index", 0), "finish_reason": c.get("finish_reason"),
                              "message": {"role": "assistant", "content": (c.get("message") or {}).get("content")}}
                             for c in data.get("choices", [])],
                 "usage": {"prompt_tokens": tin, "completion_tokens": tout, "total_tokens": tin + tout}}
        return JSONResponse(clean, headers={
            "x-lantern-remaining-requests": str(after["requests"]),
            "x-lantern-remaining-tokens": str(after["tokens"]),
            "x-lantern-remaining-today": str(after["today"]),
            "x-lantern-model": used_model})

    return app

