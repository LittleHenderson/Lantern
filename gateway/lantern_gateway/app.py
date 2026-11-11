"""Lantern gateway: the free allowance.

Holds the project's model keys on the server (never in the client), and gives each user a metered
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
  5. What anybody can send without signing in is bounded (limits.py): no body is read past the limit of its path,
     the opt-in usage reports are counted per sender and for everyone together, wrong admin secrets and sign-ins
     a sender has the gateway ask a provider about are counted per minute. A sender's address is never kept.

Run:  ANTHROPIC_API_KEY=... DEEPSEEK_API_KEY=... LANTERN_ADMIN_SECRET=... uvicorn lantern_gateway.app:create_app --factory
Claude Haiku 5.5 (Anthropic) answers first; DeepSeek answers when Anthropic fails. LANTERN_PRIMARY=deepseek swaps them.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import __version__, limits

log = logging.getLogger("lantern.gateway")


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
    # Two providers. `primary` answers first; the other one answers when the primary fails (no balance, rate
    # limited, down, unreachable). Either may be left without a key; then it is simply not used.
    primary: str = field(default_factory=lambda: os.environ.get("LANTERN_PRIMARY", "anthropic"))
    anthropic_url: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_URL", "https://api.anthropic.com").rstrip("/"))
    anthropic_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    anthropic_model: str = field(default_factory=lambda: os.environ.get("LANTERN_ANTHROPIC_MODEL", "claude-haiku-5-5"))
    # Claude Haiku 5.5 standard rates (prompts under 100k tokens), per 1M tokens
    anthropic_usd_in: float = field(default_factory=lambda: _env_float("LANTERN_ANTHROPIC_USD_PER_M_INPUT", 0.10))
    anthropic_usd_out: float = field(default_factory=lambda: _env_float("LANTERN_ANTHROPIC_USD_PER_M_OUTPUT", 0.50))
    deepseek_url: str = field(default_factory=lambda: os.environ.get("UPSTREAM_URL", "https://api.deepseek.com").rstrip("/"))
    deepseek_key: str = field(default_factory=lambda: os.environ.get("DEEPSEEK_API_KEY", ""))
    deepseek_model: str = field(default_factory=lambda: os.environ.get("LANTERN_MODEL_ID", "deepseek-flash"))
    # deepseek-flash *peak* rates (conservative)
    deepseek_usd_in: float = field(default_factory=lambda: _env_float("LANTERN_USD_PER_M_INPUT", 0.30))
    deepseek_usd_out: float = field(default_factory=lambda: _env_float("LANTERN_USD_PER_M_OUTPUT", 1.20))
    admin_secret: str = field(default_factory=lambda: os.environ.get("LANTERN_ADMIN_SECRET", ""))
    # Sign in with GitHub / Google: OAuth apps whose callback is <public_url>/v1/auth/<provider>/callback
    public_url: str = field(default_factory=lambda: os.environ.get("LANTERN_PUBLIC_URL", "https://lantern-gateway.fly.dev").rstrip("/"))
    github_client_id: str = field(default_factory=lambda: os.environ.get("GITHUB_CLIENT_ID", ""))
    github_client_secret: str = field(default_factory=lambda: os.environ.get("GITHUB_CLIENT_SECRET", ""))
    google_client_id: str = field(default_factory=lambda: os.environ.get("GOOGLE_CLIENT_ID", ""))
    google_client_secret: str = field(default_factory=lambda: os.environ.get("GOOGLE_CLIENT_SECRET", ""))
    auth_secret: str = field(default_factory=lambda: os.environ.get("LANTERN_AUTH_SECRET", ""))
    db_path: str = field(default_factory=lambda: os.environ.get("LANTERN_DB", "lantern_gateway.db"))
    # Per user. ~300 explanations is a few full runs on a typical app.
    free_requests: int = field(default_factory=lambda: _env_int("LANTERN_FREE_REQUESTS", 300))
    free_tokens: int = field(default_factory=lambda: _env_int("LANTERN_FREE_TOKENS", 1_500_000))
    daily_requests: int = field(default_factory=lambda: _env_int("LANTERN_DAILY_REQUESTS", 120))
    # Everyone, per UTC day. When reached, the allowance pauses until tomorrow (HTTP 503).
    global_daily_usd: float = field(default_factory=lambda: _env_float("LANTERN_GLOBAL_DAILY_USD", 10.0))
    # New accounts per UTC day, everyone together: one person making many GitHub/Google accounts to multiply the free
    # allowance is slowed to this many a day (an existing account signing in again is never counted). 0 = no cap.
    signups_per_day: int = field(default_factory=lambda: _env_int("LANTERN_SIGNUPS_PER_DAY", 200))
    # What anybody can send without signing in (limits.py). The opt-in usage reports: new installs per UTC day for
    # everyone together, new installs per sender per day, reports per sender per hour. 0 = no limit.
    installs_per_day: int = field(default_factory=lambda: _env_int("LANTERN_INSTALLS_PER_DAY", 1000))
    sender_installs_per_day: int = field(default_factory=lambda: _env_int("LANTERN_SENDER_INSTALLS_PER_DAY", 50))
    sender_pings_per_hour: int = field(default_factory=lambda: _env_int("LANTERN_SENDER_PINGS_PER_HOUR", 300))
    # Wrong admin secrets a minute, and sign-ins a minute the gateway asks a provider about: from one sender, and
    # from everyone together.
    admin_wrong_per_minute: int = 5
    admin_wrong_per_minute_all: int = 30
    sender_signins_per_minute: int = 10
    signins_per_minute_all: int = 120
    # The header the proxy in front of the gateway writes the caller's address in (Fly: Fly-Client-IP). "" where
    # there is no such proxy: a header the caller writes itself must not name it.
    address_header: str = field(default_factory=lambda: os.environ.get("LANTERN_ADDRESS_HEADER", "fly-client-ip"))
    max_tokens_cap: int = field(default_factory=lambda: _env_int("LANTERN_MAX_TOKENS", 3000))
    max_body_bytes: int = field(default_factory=lambda: _env_int("LANTERN_MAX_BODY", 250_000))
    # Token hashes not used (or signed in with) for this many days, and per-day counters older than this, are
    # deleted once a day. 0 or less keeps everything.
    retention_days: int = field(default_factory=lambda: _env_int("LANTERN_RETENTION_DAYS", 90))

    def oauth(self, provider: str) -> tuple[str, str] | None:
        """(client id, client secret) when that sign-in is configured."""
        cid, sec = {"github": (self.github_client_id, self.github_client_secret),
                    "google": (self.google_client_id, self.google_client_secret)}.get(provider, ("", ""))
        return (cid, sec) if cid and sec else None

    def sign_in_providers(self) -> list[str]:
        return [p for p in ("github", "google") if self.oauth(p)]

    @property
    def state_secret(self) -> str:
        return self.auth_secret or (hashlib.sha256(("state:" + self.admin_secret).encode()).hexdigest() if self.admin_secret else "")

    def provider(self, name: str) -> dict:
        if name == "anthropic":
            return {"name": name, "kind": "anthropic", "url": self.anthropic_url, "key": self.anthropic_key,
                    "model": self.anthropic_model, "usd_in": self.anthropic_usd_in, "usd_out": self.anthropic_usd_out}
        return {"name": "deepseek", "kind": "openai", "url": self.deepseek_url, "key": self.deepseek_key,
                "model": self.deepseek_model, "usd_in": self.deepseek_usd_in, "usd_out": self.deepseek_usd_out}

    def order(self) -> list[dict]:
        """Providers to try, in order, keys present only."""
        first = "anthropic" if self.primary == "anthropic" else "deepseek"
        second = "deepseek" if first == "anthropic" else "anthropic"
        return [p for p in (self.provider(first), self.provider(second)) if p["key"]]

    @property
    def model(self) -> str:
        return self.order()[0]["model"] if self.order() else self.provider(self.primary)["model"]


# The only feature names a usage ping may carry. Counts per name per day; never file names, paths or code.
USAGE_FEATURES = frozenset({
    "analyze", "analyze_link", "explain", "explain_one", "accept", "starter", "verify", "export_sarif", "packs",
    "serve", "learn", "trace", "mcp_call", "mcp_connect", "evidence", "report_open", "settings_save"})


# What a usage report may say of the app besides its counts: a version that reads as one, a system the app runs on.
# Anything else is not kept as written: the owner's page shows these, and anybody can send a report.
USAGE_VERSION = re.compile(r"[0-9]{1,4}(\.[0-9]{1,4}){1,3}((a|b|rc|\.dev|\.post)[0-9]{1,4})?")
USAGE_SYSTEMS = frozenset({"Linux", "Darwin", "Windows"})
PARKED = 600             # seconds a token waits for the app that started the sign-in
SEALED = "s1:"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _pad(cli: str, n: int) -> bytes:
    return hashlib.shake_256(b"lantern parked token\0" + cli.encode()).digest(n)


def _seal(cli: str, token: str) -> str:
    """A token as it waits in the database for the app that started the sign-in: readable only with that app's own
    code (`cli`), of which the gateway keeps a hash and nothing else. The promise is hashes only, and a token nobody
    collected would otherwise sit in the database file, and in every copy of it, in clear."""
    raw = token.encode()
    return SEALED + bytes(a ^ b for a, b in zip(raw, _pad(cli, len(raw)), strict=True)).hex()


def _open(cli: str, sealed: str) -> str | None:
    if not sealed.startswith(SEALED):
        return None                       # a row the version before left in clear: never handed out
    try:
        raw = bytes.fromhex(sealed[len(SEALED):])
        return bytes(a ^ b for a, b in zip(raw, _pad(cli, len(raw)), strict=True)).decode()
    except ValueError:
        return None


def seconds_to_midnight_utc(now: dt.datetime | None = None) -> int:
    now = now or dt.datetime.now(dt.UTC)
    nxt = (now + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((nxt - now).total_seconds()))


def until_midnight_utc(now: dt.datetime | None = None) -> str:
    """"in 5 h 20 min (00:00 UTC)": the daily limits reset at midnight UTC, which is not midnight for most people, so
    every message that says when also says how long from now."""
    now = now or dt.datetime.now(dt.UTC)
    nxt = (now + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    mins = max(1, int((nxt - now).total_seconds() // 60))
    h, m = divmod(mins, 60)
    when = f"{h} h {m} min" if h else f"{m} min"
    return f"in {when} (00:00 UTC)"


class SignupsPaused(Exception):
    """Today's cap on new accounts is reached; existing accounts keep working."""

    def __init__(self, today: int):
        super().__init__(f"{today} new accounts today")
        self.today = today


class InstallsPaused(Exception):
    """Today's cap on new installs in the usage reports is reached; installs seen before keep being counted."""


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
            create table if not exists accounts (
              account text primary key, token_hash text, label text, created text, last_signin text, signins integer default 0);
            create table if not exists pending (
              cli_hash text primary key, token text, created real);
            create table if not exists sessions (
              token_hash text primary key, anchor_hash text, created text, last_used text);
            create index if not exists sessions_anchor on sessions (anchor_hash);
        """)
        # last_used: the last request, sign-in, or rotation (for a disabled hash). Retention counts from it.
        cols = {r[1] for r in self.db.execute("pragma table_info(users)")}
        if "last_used" not in cols:
            self.db.execute("alter table users add column last_used text")
        # anchor = 1: a counter row made by `sign_in` that no token is (its sessions point at it).
        if "anchor" not in cols:
            self.db.execute("alter table users add column anchor integer default 0")
        # A parked token the version before left in clear, and any that waited too long, do not stay.
        self.db.execute("delete from pending where token not like ? or created < ?", (SEALED + "%", time.time() - PARKED))
        self.db.commit()
        self.pruned_day = ""

    def mint(self, label: str) -> str:
        token = "lt_" + secrets.token_urlsafe(32)
        with self.lock:
            now = dt.datetime.now(dt.UTC).isoformat()
            self.db.execute("insert into users (token_hash, label, created, last_used) values (?, ?, ?, ?)",
                            (_hash(token), label[:100], now, now))
            self.db.commit()
        return token

    def is_new_account(self, account: str) -> bool:
        with self.lock:
            return self.db.execute("select 1 from accounts where account = ?", (account,)).fetchone() is None

    def signups_today(self, today: str | None = None) -> int:
        """Accounts first seen today (UTC)."""
        today = today or dt.datetime.now(dt.UTC).date().isoformat()
        with self.lock:
            return (self.db.execute("select count(*) from accounts where substr(created, 1, 10) = ?", (today,)).fetchone() or [0])[0]

    # How many places one account can stay signed in at once (the app, the CLI, the website on a laptop and a
    # phone, ...). A sign-in past this many signs out the place used least recently.
    MAX_SESSIONS = 8

    def sign_in(self, account: str, label: str, max_new_per_day: int = 0) -> str:
        """A new token for this sign-in; the account's other sign-ins keep working. Every token of an account
        points at one counter row (the account's "anchor": a `users` row whose hash belongs to no token anyone
        holds), so the allowance and today's count are shared, never multiplied by signing in again. At most
        MAX_SESSIONS tokens live per account; the least recently used goes first. An account from before this
        (its one token was itself the counter row) is moved over on its next sign-in, its old token kept as one
        of the sessions. With `max_new_per_day`, a first sign-in past that many new accounts today raises
        SignupsPaused (abuse: many accounts, one person)."""
        token = "lt_" + secrets.token_urlsafe(32)
        th = _hash(token)
        now = dt.datetime.now(dt.UTC)
        today, stamp = now.date().isoformat(), now.isoformat()
        with self.lock:
            q = self.db.execute
            row = q("select token_hash from accounts where account = ?", (account,)).fetchone()
            if row is None and max_new_per_day > 0:
                n = (q("select count(*) from accounts where substr(created, 1, 10) = ?", (today,)).fetchone() or [0])[0]
                if n >= max_new_per_day:
                    raise SignupsPaused(n)
            old = row[0] if row else None
            u = q("select used_requests, used_tokens, disabled from users where token_hash = ?", (old,)).fetchone() if old else None
            # A switched-off row (or one from before sessions) gets a fresh counter row that carries its counts.
            anchor = old if (u and not u[2] and self._is_anchor(old)) else None
            if anchor is None:
                anchor = _hash("anchor:" + secrets.token_urlsafe(32))
                used_req, used_tok = (u[0], u[1]) if u else (0, 0)
                q("insert into users (token_hash, label, created, used_requests, used_tokens, last_used, anchor) "
                  "values (?, ?, ?, ?, ?, ?, 1)", (anchor, label[:100], stamp, used_req, used_tok, stamp))
                if old:
                    d = q("select requests from daily where day = ? and token_hash = ?", (today, old)).fetchone()
                    if d and d[0]:
                        q("insert into daily (day, token_hash, requests) values (?, ?, ?)", (today, anchor, d[0]))
                    if u and not u[2]:
                        # The account's one token from before: it stays signed in, now as one of its sessions.
                        q("insert or replace into sessions (token_hash, anchor_hash, created, last_used) values (?, ?, ?, ?)",
                          (old, anchor, stamp, stamp))
                    q("update users set disabled = 1, last_used = ? where token_hash = ?", (stamp, old))
                    q("update sessions set anchor_hash = ? where anchor_hash = ?", (anchor, old))
            q("insert into sessions (token_hash, anchor_hash, created, last_used) values (?, ?, ?, ?)", (th, anchor, stamp, stamp))
            extra = q("select token_hash from sessions where anchor_hash = ? order by last_used desc, created desc "
                      "limit -1 offset ?", (anchor, self.MAX_SESSIONS)).fetchall()
            for (h,) in extra:
                q("delete from sessions where token_hash = ?", (h,))
            q("update users set last_used = ?, label = ? where token_hash = ?", (stamp, label[:100], anchor))
            q("insert into accounts (account, token_hash, label, created, last_signin, signins) values (?, ?, ?, ?, ?, 1) "
              "on conflict(account) do update set token_hash = excluded.token_hash, label = excluded.label, "
              "last_signin = excluded.last_signin, signins = signins + 1",
              (account, anchor, label[:100], stamp, stamp))
            self.db.commit()
        return token

    def _is_anchor(self, h: str) -> bool:
        """A counter row made by `sign_in` (not a token anyone holds). Rows made before the `anchor` column are
        recognised by having sessions (each anchor got its first one in the same transaction)."""
        row = self.db.execute("select anchor from users where token_hash = ?", (h,)).fetchone()
        if row and row[0]:
            return True
        return self.db.execute("select 1 from sessions where anchor_hash = ? limit 1", (h,)).fetchone() is not None

    def sign_out(self, token: str, everywhere: bool = False) -> int:
        """End this sign-in, or with `everywhere` every sign-in of its account (a lost laptop, a token shown in a
        screenshot). The counts stay: the next sign-in carries on from them. Returns how many sign-ins ended.
        A token minted by hand, or an account's one token from before sessions, is switched off instead."""
        h = _hash(token)
        with self.lock:
            q = self.db.execute
            sess = q("select anchor_hash from sessions where token_hash = ?", (h,)).fetchone()
            if sess:
                n = (q("delete from sessions where anchor_hash = ?", (sess[0],)) if everywhere
                     else q("delete from sessions where token_hash = ?", (h,))).rowcount
            else:
                n = q("update users set disabled = 1 where token_hash = ? and disabled = 0 and coalesce(anchor, 0) = 0",
                      (h,)).rowcount
            self.db.commit()
        return n

    def park(self, cli: str, token: str) -> None:
        """Keep a new sign-in's token for the app that started it, sealed with the app's own code (`_seal`)."""
        with self.lock:
            self.db.execute("delete from pending where created < ?", (time.time() - PARKED,))
            self.db.execute("insert or replace into pending (cli_hash, token, created) values (?, ?, ?)",
                            (_hash(cli), _seal(cli, token), time.time()))
            self.db.commit()

    def claim(self, cli: str) -> str | None:
        """The token parked for this code: once, within ten minutes. Every question, whoever asks, also clears
        away the tokens nobody collected in time."""
        with self.lock:
            self.db.execute("delete from pending where created < ?", (time.time() - PARKED,))
            row = self.db.execute("select token from pending where cli_hash = ?", (_hash(cli),)).fetchone()
            self.db.execute("delete from pending where cli_hash = ?", (_hash(cli),))
            self.db.commit()
        return _open(cli, row[0]) if row else None

    def user(self, token: str) -> dict | None:
        """The counter row behind a token: a sign-in's session leads to its account's anchor; a token minted by
        hand is its own row. `hash` is the counter row's, which every count and lookup after this uses."""
        h = _hash(token)
        sess = self.db.execute("select anchor_hash, last_used from sessions where token_hash = ?", (h,)).fetchone()
        if sess:
            h = sess[0]
            now = dt.datetime.now(dt.UTC).isoformat()
            if (sess[1] or "")[:13] != now[:13]:          # the session's last use, kept to the hour
                with self.lock:
                    self.db.execute("update sessions set last_used = ? where token_hash = ?", (now, _hash(token)))
                    self.db.commit()
        row = self.db.execute("select token_hash, used_requests, used_tokens, disabled from users where token_hash = ?",
                              (h,)).fetchone()
        if not row:
            return None
        return {"hash": row[0], "used_requests": row[1], "used_tokens": row[2], "disabled": bool(row[3])}

    def identity(self, h: str) -> dict:
        """Who a token belongs to, for Lantern's cloud service: the signed-in account (`github:<id>`, `google:<sub>`)
        and its label. A token minted by hand has no account; it is named by a prefix of its hash. Counts as a use,
        so a person who only uses cloud mode keeps their token past the retention window."""
        with self.lock:
            row = self.db.execute("select account, label from accounts where token_hash = ?", (h,)).fetchone()
            if not row:
                lab = self.db.execute("select label from users where token_hash = ?", (h,)).fetchone()
                row = ("token:" + h[:16], (lab[0] if lab else "") or "token")
            self.db.execute("update users set last_used = ? where token_hash = ?", (dt.datetime.now(dt.UTC).isoformat(), h))
            self.db.commit()
        return {"account": row[0], "label": row[1] or ""}

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
            self.db.execute("update users set used_requests = used_requests + 1, used_tokens = used_tokens + ?, last_used = ? "
                            "where token_hash = ?", (tokens, dt.datetime.now(dt.UTC).isoformat(), h))
            self.db.execute("insert into daily (day, token_hash, requests) values (?, ?, 1) "
                            "on conflict(day, token_hash) do update set requests = requests + 1", (day, h))
            self.db.execute("insert into spend (day, usd, requests) values (?, ?, 1) "
                            "on conflict(day) do update set usd = usd + excluded.usd, requests = requests + 1",
                            (day, usd))
            self.db.commit()

    def prune(self, today: str, days: int = 90) -> dict:
        """Retention: delete token hashes with no request, sign-in or rotation for `days` days (with the account
        mapping that points at them), per-day counters older than `days`, and app installs not seen since.
        An account idle that long starts again with a fresh allowance on its next sign-in."""
        if days <= 0:
            return {}
        cut = (dt.date.fromisoformat(today) - dt.timedelta(days=days)).isoformat()   # rows dated before this go
        out = {}
        with self.lock:
            q = self.db.execute
            out["token_hashes"] = q("select count(*) from users where coalesce(last_used, created) < ?", (cut,)).fetchone()[0]
            q("delete from accounts where token_hash in "
              "(select token_hash from users where coalesce(last_used, created) < ?)", (cut,))
            q("delete from daily where token_hash in "
              "(select token_hash from users where coalesce(last_used, created) < ?)", (cut,))
            q("delete from sessions where anchor_hash in "
              "(select token_hash from users where coalesce(last_used, created) < ?)", (cut,))
            q("delete from users where coalesce(last_used, created) < ?", (cut,))
            out["sessions"] = q("delete from sessions where coalesce(last_used, created) < ?", (cut,)).rowcount
            out["daily"] = q("delete from daily where day < ?", (cut,)).rowcount
            out["spend"] = q("delete from spend where day < ?", (cut,)).rowcount
            out["models"] = q("delete from models where day < ?", (cut,)).rowcount
            out["usage"] = q("delete from usage where day < ?", (cut,)).rowcount
            out["installs"] = q("delete from installs where last_seen < ?", (cut,)).rowcount
            q("delete from pending where created < ?", (time.time() - PARKED,))
            self.db.commit()
            self.pruned_day = today
        return out

    def prune_daily(self, today: str, days: int) -> None:
        """Run `prune` at most once per UTC day (called on requests, so an idle gateway prunes on its next one)."""
        if self.pruned_day != today:
            self.prune(today, days)

    # ---- opt-in usage pings from the app (counts per feature per day; no code, no paths, no names) ----
    def knows_install(self, install: str) -> bool:
        with self.lock:
            return self.db.execute("select 1 from installs where install = ?", (install,)).fetchone() is not None

    def record_usage(self, install: str, day: str, version: str, os_name: str, features: dict[str, int],
                     max_new_per_day: int = 0) -> None:
        """With `max_new_per_day`, an install not seen before, past that many new ones today (UTC, everyone
        together), raises InstallsPaused and nothing is kept: anybody can send a report, and each new id is a row."""
        now = dt.datetime.now(dt.UTC).isoformat()
        with self.lock:
            if max_new_per_day > 0 and self.db.execute("select 1 from installs where install = ?", (install,)).fetchone() is None:
                n = self.db.execute("select count(*) from installs where substr(first_seen, 1, 10) = ?", (now[:10],)).fetchone()[0]
                if n >= max_new_per_day:
                    raise InstallsPaused()
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
                "accounts": one("select count(*) from accounts"),
                "accounts_github": one("select count(*) from accounts where account like 'github:%'"),
                "accounts_google": one("select count(*) from accounts where account like 'google:%'"),
                "accounts_new_today": one("select count(*) from accounts where substr(created, 1, 10) = ?", today),
                "accounts_new_7d": one("select count(*) from accounts where substr(created, 1, 10) >= ?", week),
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


async def _call(transport, prov: dict, out: dict) -> tuple[dict | None, object]:
    """One provider, one narrowed request. Returns (answer in OpenAI shape, None) or (None, reason)."""
    try:
        async with httpx.AsyncClient(transport=transport, timeout=120) as client:
            if prov["kind"] == "anthropic":
                system = "\n\n".join(m["content"] for m in out["messages"] if m["role"] == "system")
                msgs = [{"role": m["role"], "content": m["content"]} for m in out["messages"] if m["role"] != "system"]
                if not msgs or msgs[0]["role"] != "user":
                    msgs.insert(0, {"role": "user", "content": "(see system prompt)"})
                # Thinking off: the answer is a fixed JSON shape, and thinking tokens would eat the max_tokens budget
                # and cut the JSON short (seen with Haiku 5.5: 2,500 output tokens billed, 700 visible).
                body = {"model": prov["model"], "max_tokens": out["max_tokens"], "messages": msgs,
                        "thinking": {"type": "disabled"}}
                if system:
                    body["system"] = system
                if out.get("response_format", {}).get("type") == "json_object":
                    # Anthropic has no JSON mode. A forced tool call is the equivalent: the API itself guarantees the
                    # answer is a well-formed JSON object (free text can carry an unescaped quote and fail to parse).
                    body["tools"] = [{"name": "json", "description": "The JSON object the prompt asks for, with its keys "
                                      "(lens1, lens2, ...) at the top level of the input, not wrapped in another key.",
                                      "input_schema": {"type": "object", "additionalProperties": True}}]
                    body["tool_choice"] = {"type": "tool", "name": "json"}
                r = await client.post(f"{prov['url']}/v1/messages", json=body,
                                      headers={"x-api-key": prov["key"], "anthropic-version": "2023-06-01"})
            else:
                body = {**out, "model": prov["model"], "thinking": {"type": "disabled"}}
                r = await client.post(f"{prov['url']}/chat/completions", json=body,
                                      headers={"authorization": f"Bearer {prov['key']}"})
    except httpx.HTTPError:
        return None, "unreachable"
    if r.status_code != 200:
        # Server log only (never the client): enough to diagnose a rejected request, never the prompt.
        log.warning("upstream %s HTTP %s: %r", prov["name"], r.status_code, r.text[:300])
        if r.status_code == 400 and "credit balance" in r.text.lower():
            return None, 402   # Anthropic reports an empty account as 400; treat it as "no balance" so the fallback answers
        return None, r.status_code
    try:
        d = r.json()
    except ValueError:
        return None, 502
    if prov["kind"] != "anthropic":
        return d, None
    tool = next((b for b in d.get("content", []) if b.get("type") == "tool_use" and isinstance(b.get("input"), dict)), None)
    if tool is not None:
        obj = _unwrap(tool["input"])
        text = json.dumps(obj, ensure_ascii=False)
    else:
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        if out.get("response_format", {}).get("type") == "json_object":
            i, j = text.find("{"), text.rfind("}")   # trim any prose around the object
            if i >= 0 and j > i:
                text = text[i:j + 1]
    u = d.get("usage") or {}
    return {"id": d.get("id"), "model": d.get("model", prov["model"]),
            "choices": [{"index": 0, "finish_reason": d.get("stop_reason"), "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": int(u.get("input_tokens") or 0), "completion_tokens": int(u.get("output_tokens") or 0)}}, None


def _unwrap(obj: dict) -> dict:
    """Normalize what a forced tool call hands back. Seen from Haiku 5.5: the answer wrapped in one extra key
    ({"answer": {...}}), and nested objects sent as JSON strings ("lens3": "{\"text\": ...}"), sometimes both."""
    for _ in range(3):
        for k, v in list(obj.items()):
            if isinstance(v, str) and v.lstrip()[:1] in ("{", "["):
                try:   # raw_decode: the first complete value, ignoring a stray trailing brace (seen: "...}}")
                    obj[k] = json.JSONDecoder(strict=False).raw_decode(v.lstrip())[0]
                except ValueError:
                    pass
        if len(obj) == 1 and isinstance(next(iter(obj.values())), dict):
            obj = next(iter(obj.values()))
            continue
        break
    return obj


def _retryable(err) -> bool:
    return err == "unreachable" or err in (401, 402, 403, 429) or (isinstance(err, int) and err >= 500)


def _err(status: int, kind: str, message: str, headers: dict | None = None, **extra) -> JSONResponse:
    return JSONResponse({"error": {"type": kind, "message": message, **extra}}, status_code=status, headers=headers)


def _table(raw: bytes) -> dict | None:
    """A request's body as a JSON object, or None: not JSON, nested deeper than Python follows, or JSON of another
    shape (a list, a number, a text). Each of those was an internal error (HTTP 500) before."""
    try:
        body = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return body if isinstance(body, dict) else None


def _size(asked, cap: int) -> int:
    """`max_tokens` as the client asked, from 1 to the cap; the cap when it asked for nothing or for no number."""
    if isinstance(asked, bool) or not isinstance(asked, (int, float)) or not math.isfinite(asked) or not asked:
        return cap
    return max(1, min(int(asked), cap))


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    s = settings or Settings()
    store = Store(s.db_path, s.free_requests)
    app = FastAPI(title="Lantern gateway", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings = store, s
    limiter = app.state.limiter = limits.Limiter()

    def body_limit(path: str) -> tuple[int, str]:
        if path == "/v1/chat/completions":
            return s.max_body_bytes, "Request is larger than the free allowance accepts."
        return limits.SMALL_BODY, "usage ping too large" if path == "/v1/usage" else "Request body too large."

    app.add_middleware(limits.BodyCap, limit_for=body_limit)

    def who(request: Request) -> str:
        return limits.sender(request.scope, s.address_header)

    def slow_down(seconds: int) -> dict:
        return {"Retry-After": str(seconds), "Cache-Control": "no-store"}

    def today() -> str:
        return dt.datetime.now(dt.UTC).date().isoformat()

    store.prune_daily(today(), s.retention_days)

    def auth(authorization: str | None) -> dict:
        store.prune_daily(today(), s.retention_days)
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
        order = s.order()
        # Public and cached by monitors: the version and which model answers, never counters or spend.
        return {"ok": True, "version": __version__, "model": s.model, "configured": bool(order),
                "primary": order[0]["name"] if order else None,
                "fallback": order[1]["model"] if len(order) > 1 else None}

    def admin(authorization: str | None, request: Request) -> None:
        """The owner's secret. Wrong ones are counted per minute, for the sender and for everyone together; past
        either count no secret is looked at until the minute ends, the right one included, so guessing is slowed to
        those counts. (Senders from many addresses can keep the owner waiting that way; they cannot get in.)"""
        sender = who(request)
        if limiter.full("admin", sender, s.admin_wrong_per_minute, 60) or \
                limiter.full("admin-all", "", s.admin_wrong_per_minute_all, 60):
            raise HTTPException(429, "too many wrong admin secrets; try again in a minute", headers=slow_down(limiter.wait(60)))
        if not s.admin_secret or not authorization or not hmac.compare_digest(
                authorization.removeprefix("Bearer ").strip().encode(), s.admin_secret.encode()):
            limiter.take("admin", sender, s.admin_wrong_per_minute, 60)
            limiter.take("admin-all", "", s.admin_wrong_per_minute_all, 60)
            raise HTTPException(403, "admin only")

    @app.post("/v1/tokens")
    def mint(payload: dict, request: Request, authorization: str | None = Header(default=None)):
        """Admin only: create a user token. Returned once; only its hash is stored."""
        admin(authorization, request)
        return {"token": store.mint(str(payload.get("label", ""))), "limits": {
            "requests": s.free_requests, "tokens": s.free_tokens, "per_day": s.daily_requests}}

    # ---- Sign in with GitHub / Google ----
    from . import auth as oauth
    from fastapi.responses import HTMLResponse, RedirectResponse
    page_headers = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
                    f"script-src {oauth.COPY_JS_HASH}; font-src https://fonts.gstatic.com", "Referrer-Policy": "no-referrer",
                    "Cache-Control": "no-store"}

    @app.get("/v1/auth/providers")
    def auth_providers():
        return {"providers": s.sign_in_providers(), "login_url": f"{s.public_url}/v1/login"}

    @app.get("/v1/login")
    def login(cli: str | None = None, provider: str | None = None):
        return HTMLResponse(oauth.login_page(s.sign_in_providers(), oauth.valid_cli(cli), provider), headers=page_headers)

    @app.get("/v1/auth/{provider}/start")
    def auth_start(provider: str, cli: str | None = None):
        if not s.oauth(provider) or not s.state_secret:
            raise HTTPException(404, "that sign-in is not configured")
        cid, _ = s.oauth(provider)
        state = oauth.sign_state(s.state_secret, provider, oauth.valid_cli(cli))
        return RedirectResponse(oauth.authorize_url(provider, cid, f"{s.public_url}/v1/auth/{provider}/callback", state),
                                status_code=302, headers={"Cache-Control": "no-store"})

    used: dict[str, float] = {}       # sign-in links already used: a hash of each, until the link would have run out

    def first_use(state: str) -> bool:
        """A sign-in link is good once. Without this, one link could be sent back any number of times for ten
        minutes, and each time the gateway asked the provider with its own secret."""
        now, key = time.time(), _hash(state)
        if len(used) >= 50_000:
            for k in [k for k, until in used.items() if until < now]:
                del used[k]
            if len(used) >= 50_000:
                used.clear()
        if used.get(key, 0) > now:
            return False
        used[key] = now + oauth.STATE_TTL
        return True

    @app.get("/v1/auth/{provider}/callback")
    async def auth_callback(request: Request, provider: str, code: str | None = None, state: str | None = None,
                            error: str | None = None):
        if not s.oauth(provider) or not s.state_secret:
            raise HTTPException(404, "that sign-in is not configured")
        st = oauth.read_state(s.state_secret, state or "")
        if st is None or st.get("p") != provider:
            return HTMLResponse(oauth.error_page("This sign-in link has expired or was not started here. Go back and try again."),
                                status_code=400, headers=page_headers)
        if error or not code:
            return HTMLResponse(oauth.error_page("Sign-in was cancelled or refused by the provider."), status_code=400, headers=page_headers)
        sender = who(request)
        if limiter.full("signin", sender, s.sender_signins_per_minute, 60) or \
                limiter.full("signin-all", "", s.signins_per_minute_all, 60):
            # Not counted against the link: the person can load this page again when the minute has ended.
            return HTMLResponse(oauth.error_page("Too many sign-ins in the last minute. Wait a minute, then load this page again."),
                                status_code=429, headers={**page_headers, **slow_down(limiter.wait(60))})
        if not first_use(state or ""):
            return HTMLResponse(oauth.error_page("This sign-in link was already used. Go back and start again."),
                                status_code=400, headers=page_headers)
        limiter.take("signin", sender, s.sender_signins_per_minute, 60)
        limiter.take("signin-all", "", s.signins_per_minute_all, 60)
        cid, sec = s.oauth(provider)
        signed = await oauth.exchange(provider, cid, sec, code, f"{s.public_url}/v1/auth/{provider}/callback", transport)
        if signed is None:
            return HTMLResponse(oauth.error_page("The provider did not confirm the sign-in. Try again."), status_code=502, headers=page_headers)
        account, label = signed
        try:
            token = store.sign_in(account, label, s.signups_per_day)
        except SignupsPaused:
            log.warning("sign-ups paused: %s new accounts today (cap %s)", store.signups_today(), s.signups_per_day)
            return HTMLResponse(oauth.error_page("Lantern's free allowance has had as many new sign-ups today as it can take. "
                                                 "Existing accounts keep working; please try again tomorrow."),
                                status_code=429, headers={**page_headers, "Retry-After": "86400"})
        cli = st.get("c") or ""
        if cli:
            store.park(cli, token)
        return HTMLResponse(oauth.done_page(token, label, bool(cli)), headers=page_headers)

    @app.get("/v1/auth/claim")
    def auth_claim(cli: str | None = None):
        """The client collects the token parked for its cli code: once, within ten minutes of the sign-in."""
        if not oauth.valid_cli(cli):
            raise HTTPException(400, "bad cli code")
        tok = store.claim(cli)
        if tok is None:
            return JSONResponse({"pending": True}, status_code=404, headers={"Cache-Control": "no-store"})
        return JSONResponse({"token": tok, "limits": {"requests": s.free_requests, "tokens": s.free_tokens, "per_day": s.daily_requests}},
                            headers={"Cache-Control": "no-store"})

    @app.get("/v1/admin/stats")
    def admin_stats(request: Request, authorization: str | None = Header(default=None), days: int = 30):
        """Admin only: the numbers behind the dashboard. Aggregates, never bodies or code."""
        admin(authorization, request)
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
        sender = who(request)
        if s.sender_pings_per_hour > 0 and not limiter.take("ping", sender, s.sender_pings_per_hour, 3600):
            return _err(429, "rate_limited", "Too many usage reports from this network in the last hour.",
                        headers=slow_down(limiter.wait(3600)))
        body = _table(await request.body())          # limits.BodyCap has stopped anything over 4,000 bytes
        if body is None:
            return _err(400, "bad_request", "Body must be a JSON object.")
        install = str(body.get("install") or "")
        if len(install) != 32 or any(c not in "0123456789abcdef" for c in install):
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
        version, system = body.get("version"), body.get("os")
        version = version if isinstance(version, str) and USAGE_VERSION.fullmatch(version) else ""
        system = system if isinstance(system, str) and system in USAGE_SYSTEMS else "other"
        store.prune_daily(today(), s.retention_days)
        new = not store.knows_install(install)
        if new and s.sender_installs_per_day > 0 and limiter.full("install", sender, s.sender_installs_per_day, 86400):
            return _err(429, "rate_limited", "Too many new installs from this network today.",
                        headers=slow_down(limiter.wait(86400)))
        try:
            store.record_usage(install, d.isoformat(), version, system, clean, s.installs_per_day)
        except InstallsPaused:
            return _err(429, "rate_limited", "The gateway has taken as many new installs today as it accepts. "
                        f"It starts again {until_midnight_utc()}.", headers=slow_down(seconds_to_midnight_utc()))
        if new:
            limiter.take("install", sender, s.sender_installs_per_day, 86400)
        return {"ok": True, "recorded": sorted(clean)}

    @app.get("/v1/allowance")
    def allowance(authorization: str | None = Header(default=None)):
        u = auth(authorization)
        r = remaining(u, today())
        return {"used_requests": u["used_requests"], "limit_requests": s.free_requests,
                "used_tokens": u["used_tokens"], "limit_tokens": s.free_tokens,
                "remaining_requests": r["requests"], "remaining_tokens": r["tokens"],
                "remaining_today": r["today"], "model": s.model}

    @app.post("/v1/auth/signout")
    def auth_signout(payload: dict | None = None, authorization: str | None = Header(default=None)):
        """Sign out with the token itself: this place, or `{"everywhere": true}` every place the account is signed
        in (the website, the app, the CLI). Needs a working token, so nobody can sign someone else out."""
        auth(authorization)
        n = store.sign_out(authorization[7:].strip(), bool((payload or {}).get("everywhere")))
        return JSONResponse({"signed_out": n}, headers={"Cache-Control": "no-store"})

    @app.get("/v1/whoami")
    def whoami(authorization: str | None = Header(default=None)):
        """The account behind a token, for Lantern's cloud service (one sign-in for both). Never the email."""
        u = auth(authorization)
        return store.identity(u["hash"])

    @app.post("/v1/chat/completions")
    async def chat(request: Request, authorization: str | None = Header(default=None)):
        u = auth(authorization)
        day = today()
        body = _table(await request.body())          # limits.BodyCap has stopped anything over max_body_bytes
        if body is None:
            return _err(400, "bad_request", "Body must be a JSON object.")
        r = remaining(u, day)
        if r["requests"] <= 0 or r["tokens"] <= 0:
            return _err(402, "quota_exceeded",
                        f"You've used your free Lantern allowance ({s.free_requests} explanations).",
                        remaining=0)
        if r["today"] <= 0:
            return _err(402, "daily_limit",
                        f"You've reached today's free limit ({s.daily_requests}). It resets {until_midnight_utc()}.",
                        remaining=r["requests"])
        if store.spend_today(day) >= s.global_daily_usd:
            return _err(503, "allowance_paused",
                        "The free allowance is paused for today because it reached its daily budget.")
        if not s.order():
            return _err(503, "not_configured", "The gateway has no model key configured.")
        msgs = body.get("messages")
        if not isinstance(msgs, list) or not msgs or len(msgs) > 4 or not all(
                isinstance(m, dict) and m.get("role") in ("system", "user", "assistant")
                and isinstance(m.get("content"), str) for m in msgs):
            return _err(400, "bad_request", "Only plain chat messages are accepted.")
        # Narrow the request to what Lantern needs; ignore everything else the client sent.
        out = {"messages": [{"role": m["role"], "content": m["content"]} for m in msgs],
               "max_tokens": _size(body.get("max_tokens"), s.max_tokens_cap)}
        if isinstance(body.get("response_format"), dict) and body["response_format"].get("type") == "json_object":
            out["response_format"] = {"type": "json_object"}
        data, err, used = None, None, None
        for prov in s.order():
            data, err = await _call(transport, prov, out)
            if data is not None:
                used = prov
                break
            if not _retryable(err):   # a bad request is bad for every provider
                break
        if data is None:
            if err == "unreachable":
                return _err(502, "upstream_unreachable", "Could not reach the model provider. Try again shortly.")
            # Never echo upstream bodies: they can include account details.
            return _err(502 if err >= 500 or err in (401, 402, 403) else err,
                        "upstream_error", f"The model provider returned HTTP {err}.")
        used_model = used["model"]
        usage = data.get("usage") or {}
        tin, tout = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        usd = tin / 1e6 * used["usd_in"] + tout / 1e6 * used["usd_out"]
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

