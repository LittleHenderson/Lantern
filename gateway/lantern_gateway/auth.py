"""Sign in with GitHub or Google to get a free-allowance token: one token per account, issued by the gateway.

Flow (the CLI and the app use the same one):
  1. The client makes a random `cli` code (32+ URL-safe characters) and opens
     `/v1/login?provider=github&cli=<code>` in a browser (or `/v1/auth/github/start?cli=…` directly).
  2. The gateway redirects to the provider with a signed `state` (HMAC over the time and the cli code).
  3. The provider calls back with a `code`; the gateway exchanges it server-side (the client secret never leaves
     this server), reads the account id, and issues or rotates that account's token.
  4. The callback page shows the token once and, when a cli code was given, parks it so the client can collect it
     with `/v1/auth/claim?cli=<code>` (one time, within 10 minutes).

Stored per account: the provider's stable id (`github:<id>`, `google:<sub>`), a label (the GitHub login, or
`google:` plus the last 6 characters of the subject id — never the email), the token hash and counters. Signing
in again rotates the token (the old one stops working) and carries the counters over, so a new sign-in is never
a fresh allowance.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import time
import urllib.parse

import httpx

PROVIDERS = {
    "github": {
        "name": "GitHub",
        "authorize": "https://github.com/login/oauth/authorize",
        "token": "https://github.com/login/oauth/access_token",
        "user": "https://api.github.com/user",
        "scope": "read:user",
    },
    "google": {
        "name": "Google",
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "user": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid",
    },
}
STATE_TTL = 600          # seconds a sign-in may take
CLAIM_TTL = 600          # seconds a parked token waits for its client
CLI_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


def sign_state(secret: str, provider: str, cli: str) -> str:
    payload = json.dumps({"t": int(time.time()), "p": provider, "c": cli}, separators=(",", ":")).encode()
    mac = hmac.new(secret.encode(), payload, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(payload + mac).decode().rstrip("=")


def read_state(secret: str, state: str) -> dict | None:
    try:
        raw = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4))
        payload, mac = raw[:-16], raw[-16:]
        if not hmac.compare_digest(hmac.new(secret.encode(), payload, hashlib.sha256).digest()[:16], mac):
            return None
        d = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(d, dict) or time.time() - int(d.get("t", 0)) > STATE_TTL or d.get("p") not in PROVIDERS:
        return None
    return d


def authorize_url(provider: str, client_id: str, redirect_uri: str, state: str) -> str:
    p = PROVIDERS[provider]
    q = {"client_id": client_id, "redirect_uri": redirect_uri, "state": state, "scope": p["scope"],
         "response_type": "code"}
    if provider == "google":
        q["prompt"] = "select_account"
    return p["authorize"] + "?" + urllib.parse.urlencode(q)


async def exchange(provider: str, client_id: str, client_secret: str, code: str, redirect_uri: str,
                   transport: httpx.AsyncBaseTransport | None = None) -> tuple[str, str] | None:
    """(account id, label) for the signed-in user, or None when the provider refused."""
    p = PROVIDERS[provider]
    async with httpx.AsyncClient(transport=transport, timeout=20) as client:
        r = await client.post(p["token"], data={"client_id": client_id, "client_secret": client_secret, "code": code,
                                               "redirect_uri": redirect_uri, "grant_type": "authorization_code"},
                              headers={"accept": "application/json"})
        if r.status_code != 200:
            return None
        try:
            tok = r.json().get("access_token")
        except ValueError:
            return None
        if not tok:
            return None
        r = await client.get(p["user"], headers={"authorization": f"Bearer {tok}", "accept": "application/json",
                                                 "user-agent": "lantern-gateway"})
        if r.status_code != 200:
            return None
        try:
            u = r.json()
        except ValueError:
            return None
    if provider == "github":
        uid, login = u.get("id"), str(u.get("login") or "")
        if not uid:
            return None
        return f"github:{uid}", f"github:{login[:40]}"
    sub = str(u.get("sub") or "")
    if not sub:
        return None
    return f"google:{sub}", f"google:…{sub[-6:]}"


def login_page(configured: list[str], cli: str, provider: str | None) -> str:
    """The page a person lands on: one button per configured provider. The cli code rides along."""
    cli_q = f"&cli={urllib.parse.quote(cli)}" if cli else ""
    buttons = "".join(
        f'<a class="btn" href="/v1/auth/{k}/start?x=1{cli_q}">Sign in with {PROVIDERS[k]["name"]}</a>'
        for k in configured)
    body = buttons or "<p>No sign-in method is configured on this gateway yet.</p>"
    return _page("Sign in to Lantern", f"""<h1>Get a free allowance</h1>
<p>Sign in once. Lantern gives each account one token for about 300 explanations with Claude Haiku. The gateway keeps a
hash of the token and usage counts; no code, prompts or email addresses are stored.</p>
<div class="row">{body}</div>
<p class="small">{'Your terminal or app will pick the token up by itself after you sign in.' if cli else 'The token is shown once on the next page; paste it into <code>lantern login --token …</code>.'}</p>""")


def done_page(token: str, label: str, parked: bool) -> str:
    return _page("Signed in", f"""<h1>You're in{html.escape(' as ' + label.split(':', 1)[1]) if label.startswith('github:') and ':' in label else ''}</h1>
{'<p>Your terminal or app has picked up the token. You can close this tab.</p>' if parked else ''}
<p>Your Lantern token, shown once:</p>
<pre class="tok">{html.escape(token)}</pre>
<p class="small">Keep it like a password. To use it on a computer: <code>lantern login --token {html.escape(token[:5])}…</code>.
Signing in again later gives a new token and keeps your usage count.</p>""")


def error_page(msg: str) -> str:
    return _page("Sign-in problem", f"<h1>Sign-in problem</h1><p>{html.escape(msg)}</p><p class=\"small\"><a href=\"/v1/login\">Back</a></p>")


def _page(title: str, inner: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · Lantern</title>
<style>
:root{{--bg:#F5F5F2;--surface:#fff;--ink:#161618;--muted:#6E6E74;--line:rgba(22,22,24,.09);--accent:#0F7B74}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0E0E10;--surface:#161618;--ink:#F3F3F1;--muted:#8C8C92;--line:rgba(255,255,255,.08);--accent:#4FC3BA}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:560px;margin:8vh auto;padding:28px 24px;background:var(--surface);border:1px solid var(--line);border-radius:14px}}
h1{{font-size:22px;margin:0 0 10px}}p{{margin:10px 0}}.small{{font-size:13px;color:var(--muted)}}
.row{{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}}
.btn{{display:inline-block;padding:11px 16px;border-radius:10px;background:var(--ink);color:var(--bg);text-decoration:none;font-weight:600}}
.tok{{font:14px ui-monospace,Menlo,Consolas,monospace;padding:12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;user-select:all;overflow-wrap:anywhere;white-space:pre-wrap}}
code{{font-family:ui-monospace,Menlo,Consolas,monospace}}
</style></head><body><main>{inner}</main></body></html>"""


def valid_cli(cli: str | None) -> str:
    return cli if cli and CLI_RE.match(cli) else ""
