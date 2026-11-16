"""Sign in with GitHub or Google to get a free-allowance token: one token per sign-in, issued by the gateway.

Flow (the terminal, the app and the website use the same one):
  1. The app makes a secret it keeps to itself (the "verifier", 43+ URL-safe characters) and opens
     `/v1/login?challenge=<SHA-256 of the secret, base64url>&return=<where to send the browser back>&nonce=<its own
     mark>` in a browser (or `/v1/auth/github/start?…` directly). The return address is on the person's own computer
     (`http://127.0.0.1:<port>/…`) or a website this gateway names (`return_origins`).
  2. The gateway redirects to the provider with a signed `state` (HMAC over the time and what the app said) and
     gives the browser a cookie. Only the browser that holds the cookie can finish this sign-in.
  3. The provider calls back with a `code`; the gateway exchanges it server-side (the client secret never leaves
     this server) and reads the account id.
  4. The gateway sends that same browser back to the return address with a one-time code. The app, which the browser
     has now reached, collects its token with `POST /v1/auth/redeem {code, verifier}`: once, within two minutes.
     The token is made at that moment. Nobody who merely started a sign-in, or chose a value in it, can collect
     what another person finished: the code goes only where the finishing browser goes, and it is worth nothing
     without the secret.
  Without a challenge the sign-in ends on a page whose button copies the token (it is not drawn on screen), for the
  person to paste into Lantern. Until 0.2.6 an app collected its token with a code of its own choosing
  (`/v1/auth/claim?cli=`); nothing is kept for such a code any more.

Stored per account: the provider's stable id (`github:<id>`, `google:<sub>`), a label (the GitHub login, or
`google:` plus the last 6 characters of the subject id — never the email), the token hashes and counters. Each
sign-in gets its own token and the account's other sign-ins keep working (`Store.sign_in`, up to `MAX_SESSIONS`);
every token counts against the account's one counter row, so a new sign-in is never a fresh allowance.
"""


from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
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
REDEEM_TTL = 120         # seconds a finished sign-in waits for the app that started it (its code is in an address bar)
CLI_RE = re.compile(r"[A-Za-z0-9_-]{32,128}")            # what an app from before 0.2.7 sends: recognised, never used
CHALLENGE_RE = re.compile(r"[A-Za-z0-9_-]{43}")          # SHA-256 of the app's secret, base64url without padding
VERIFIER_RE = re.compile(r"[A-Za-z0-9._~-]{43,128}")     # the secret itself, shown only when the app collects
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")           # the app's own mark, handed back with the code
CODE_RE = re.compile(r"[A-Za-z0-9_-]{43,128}")           # the one-time code the finishing browser carries back
# Where a finished sign-in may be sent back to. On the person's own computer: the address written as a number (a name
# such as localhost is whatever a hosts file says) with a port an ordinary program may open. Or a website by https.
LOOPBACK_RE = re.compile(r"http://(?:127\.0\.0\.1|\[::1\]):([0-9]{4,5})(/[A-Za-z0-9._~/-]*)")
WEBSITE_RE = re.compile(r"(https://[a-z0-9.-]+(?::[0-9]{1,5})?)(/[A-Za-z0-9._~/-]*)")
COOKIE = "ls_"           # + the state's random part: the cookie of the browser that started that sign-in


def challenge_of(verifier: str) -> str:
    """The fingerprint an app shows of its secret when it starts a sign-in (RFC 7636, S256)."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def return_origins(named: str = "") -> frozenset[str]:
    """The websites a finished sign-in may be sent back to: Lantern's own (`home_url`) and those the gateway's
    setting names (`LANTERN_RETURN_ORIGINS`, separated by commas), each as `https://host[:port]`."""
    origin = r"https://[a-z0-9.-]+(?::[0-9]{1,5})?"
    own = re.match(origin, home_url().lower())            # Lantern's own website, whichever page of it the logo opens
    out = {own.group(0)} if own else set()
    out.update(u.strip().rstrip("/") for u in named.split(",") if re.fullmatch(origin, u.strip().rstrip("/")))
    return frozenset(out)


def valid_return(address: str | None, origins: frozenset[str]) -> str:
    """The address as given when a finished sign-in may be sent there, else "". No query, no fragment, no name and
    password, no `.` or `..` or empty step in the path: the gateway adds `?code=…&state=…` and nothing else."""
    a = address or ""
    if len(a) > 200:
        return ""
    m = LOOPBACK_RE.fullmatch(a)
    if m:
        ok = 1024 <= int(m.group(1)) <= 65535
    else:
        m = WEBSITE_RE.fullmatch(a)
        ok = bool(m) and m.group(1) in origins
    steps = m.group(2).split("/")[1:] if ok else []
    if not ok or any(x in (".", "..") for x in steps) or "" in steps[:-1]:
        return ""
    return a


def asked(challenge: str | None, back: str | None, nonce: str | None, origins: frozenset[str]) -> dict | None:
    """What an app that collects its sign-in itself says at the start, all three or none: `{}` when none was given
    (the sign-in ends on the page with the Copy button), None when what was given is not all three in the forms
    allowed (the start is refused: half a hand-over is not guessed at)."""
    if challenge is None and back is None and nonce is None:
        return {}
    back = valid_return(back, origins)
    if not (CHALLENGE_RE.fullmatch(challenge or "") and NONCE_RE.fullmatch(nonce or "") and back):
        return None
    return {"challenge": challenge, "return": back, "nonce": nonce}


def sign_state(secret: str, provider: str, tid: str = "", browser: str = "", hand: dict | None = None,
               old: bool = False) -> str:
    """A sign-in link's `state`: when it was made, for which provider, a random part (so that no two links are the
    same text: a link is good once, and two people starting in the same second must not share one), the fingerprint
    of what the starting browser holds in its cookie, and, for an app that collects its sign-in itself, what it said
    at the start (`asked`). `old`: an app from before 0.2.7 started this; the last page tells the person so."""
    d = {"t": int(time.time()), "p": provider, "n": tid or secrets.token_urlsafe(9), "b": browser}
    if hand:
        d.update(h=hand["challenge"], r=hand["return"], s=hand["nonce"])
    elif old:
        d["o"] = 1
    payload = json.dumps(d, separators=(",", ":")).encode()
    mac = hmac.new(secret.encode(), payload, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(payload + mac).decode().rstrip("=")


def begin(secret: str, provider: str, hand: dict | None = None, old: bool = False) -> tuple[str, str, str]:
    """A sign-in this browser starts now: (state, the cookie's name, the cookie's value). The value is a secret of
    this one sign-in; the state carries its fingerprint, so the link alone does not finish it (`same_browser`)."""
    tid, mine = secrets.token_urlsafe(9), secrets.token_urlsafe(32)
    return sign_state(secret, provider, tid, fingerprint(mine), hand, old), COOKIE + tid, mine


def same_browser(st: dict, cookies) -> bool:
    """Is this the browser that started the sign-in this state belongs to? A link that was passed on to somebody
    else arrives without the cookie."""
    mine = cookies.get(COOKIE + str(st.get("n") or "")) or ""
    return bool(mine) and hmac.compare_digest(fingerprint(mine), str(st.get("b") or "-"))


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
    """(account id, label) for the signed-in user, or None when the provider refused, could not be reached, or
    answered with something that is not the table it promises."""
    try:
        return await _exchange(provider, client_id, client_secret, code, redirect_uri, transport)
    except (httpx.HTTPError, AttributeError, TypeError):
        return None


async def _exchange(provider: str, client_id: str, client_secret: str, code: str, redirect_uri: str,
                    transport: httpx.AsyncBaseTransport | None = None) -> tuple[str, str] | None:
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


def login_page(configured: list[str], hand: dict | None = None, cli: str = "") -> str:
    """The page a person lands on: one button per configured provider. What the app said at the start (`asked`)
    rides along; an app from before 0.2.7 is recognised by its `cli` code, which is passed on and never used."""
    more = {k: hand[k] for k in ("challenge", "return", "nonce")} if hand else {"cli": cli} if cli else {}
    q = html.escape("&" + urllib.parse.urlencode(more), quote=True) if more else ""
    buttons = "".join(
        f'<a class="btn" href="/v1/auth/{k}/start?x=1{q}">Sign in with {PROVIDERS[k]["name"]}</a>'
        for k in configured)
    body = buttons or "<p>No sign-in method is configured on this gateway yet.</p>"
    return _page("Sign in to Lantern", f"""<h1>Get a free allowance</h1>
<p>Sign in once. Lantern gives each account one token for about 300 explanations with Claude Haiku. The gateway keeps a
hash of the token and usage counts; no code, prompts or email addresses are stored.</p>
<div class="row">{body}</div>
<p class="small">{'Lantern will pick the sign-in up by itself after you sign in.' if hand else 'The next page has a button that copies your token; paste it into <code>lantern login --token …</code>.'}</p>""")


# The one script a gateway page runs: the Copy button on the "You're in" page. The page's Content-Security-Policy allows
# exactly this text by its hash (COPY_JS_HASH), so nothing else planted in a page could run.
COPY_JS = ("var b=document.getElementById('copy'),t=document.getElementById('tok'),f=document.getElementById('fb');"
           "b.hidden=false;"
           "b.addEventListener('click',function(){"
           "function no(){f.hidden=false;b.textContent='Copy did not work: the token is below';}"
           "if(!navigator.clipboard){no();return;}"
           "navigator.clipboard.writeText(t.value).then(function(){"
           "b.textContent='Copied. Now paste it into Lantern';b.classList.add('ok');},no);});")
COPY_JS_HASH = "'sha256-" + base64.b64encode(hashlib.sha256(COPY_JS.encode()).digest()).decode() + "'"


def done_page(token: str, label: str, old: bool = False) -> str:
    """The last page of a sign-in no app collects by itself: the person carries the token over by hand. It is never
    drawn on screen (a token on screen ends up in screenshots): one Lantern button copies it. Only when copying fails,
    or scripts are off, does the page print it. `old`: an app from before 0.2.7 started this and is still waiting."""
    who = html.escape(' as ' + label.split(':', 1)[1]) if label.startswith('github:') and ':' in label else ''
    older = ('<p class="small">Is Lantern still waiting for you? This copy of Lantern is older than this sign-in page: '
             'paste the token into its Settings, and update Lantern when you can.</p>') if old else ""
    t = html.escape(token, quote=True)
    pre = f'<pre class="tok">{t}</pre>'
    return _page("Signed in", f"""<h1>You're in{who}</h1>
<p>Press the button to copy your Lantern token, then paste it into Lantern (Settings, or
<code>lantern login --token</code> in a terminal).</p>
<input type="hidden" id="tok" value="{t}">
<div class="row"><button type="button" class="btn" id="copy" hidden>{MARK}<span>Copy my Lantern token</span></button></div>
<div id="fb" hidden>{pre}</div>
<noscript>{pre}</noscript>
{older}<p class="small">Keep it like a password: never paste it into a chat or a screenshot. Signing in again later gives a new
token and keeps your usage count.</p>
<script>{COPY_JS}</script>""")


def error_page(msg: str) -> str:
    return _page("Sign-in problem", f"<h1>Sign-in problem</h1><p>{html.escape(msg)}</p><p class=\"small\"><a href=\"/v1/login\">Back</a></p>")


# The page style is the Lantern app's (tokens, typeface, the lantern mark), so signing in looks like the rest of Lantern.
MARK = ('<span class="mark" aria-hidden="true"><svg viewBox="0 0 64 64"><path d="M26 13h12M25 51h14" stroke="#F3F3F1" '
        'stroke-width="3" stroke-linecap="round"/><path d="M22 19h20l-2.5 27h-15z" fill="none" stroke="#F3F3F1" stroke-width="3" '
        'stroke-linejoin="round"/><path d="M32 25.5c3.2 3.6 4.8 6.3 4.8 8.8a4.8 4.8 0 0 1-9.6 0c0-2.5 1.6-5.2 4.8-8.8z" '
        'fill="#FFB547"/></svg></span>')
FONTS = ('<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700'
         '&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">')


# Where the mark and the word "Lantern" in the top bar go: the Lantern website. LANTERN_HOME_URL points them elsewhere
# (an https address only; anything else falls back to the website).
HOME_URL = "https://lantern-cloud.fly.dev/"


def home_url() -> str:
    u = os.environ.get("LANTERN_HOME_URL", "").strip()
    return u if re.fullmatch(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?", u) else HOME_URL


def _page(title: str, inner: str) -> str:
    home = html.escape(home_url(), quote=True)
    guide = html.escape(urllib.parse.urljoin(home_url(), "guide"), quote=True)   # the website's How to use Lantern
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · Lantern</title>
{FONTS}
<style>
:root{{color-scheme:light;--bg:#F5F5F2;--glow:rgba(255,181,71,.2);--surface:#fff;--ink:#161618;--ink-2:#46464C;--muted:#62626A;--line:rgba(22,22,24,.09);--line-2:rgba(22,22,24,.16);--accent:#0B5F5A;--sunken:#EEEEEA;--primary:#161618;--on-primary:#fff}}
@media(prefers-color-scheme:dark){{:root{{color-scheme:dark;--bg:#0E0E10;--glow:rgba(255,170,60,.09);--surface:#161618;--ink:#F3F3F1;--ink-2:#BEBEC3;--muted:#9A9AA0;--line:rgba(255,255,255,.08);--line-2:rgba(255,255,255,.15);--accent:#7FDBD3;--sunken:#0A0A0B;--primary:#F3F3F1;--on-primary:#0E0E10}}}}
*{{box-sizing:border-box}}[hidden]{{display:none!important}}
body{{margin:0;min-height:100vh;background:var(--bg);color:var(--ink-2);font:15px/1.6 "DM Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}}
header{{display:flex;align-items:center;height:56px;padding:0 20px;border-bottom:1px solid var(--line)}}
.home{{display:inline-flex;align-items:center;gap:10px;margin-left:-8px;padding:6px 8px;border-radius:12px;font:600 16px "DM Sans",-apple-system,sans-serif;color:var(--ink);letter-spacing:-.02em;text-decoration:none}}
.guide{{margin-left:auto;display:inline-flex;align-items:center;min-height:44px;padding:0 10px;border-radius:10px;font-weight:600;font-size:14px;text-decoration:none}}.guide:hover{{background:var(--sunken)}}.guide:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
.home:hover{{background:var(--sunken)}}.home:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
.mark{{width:28px;height:28px;border-radius:9px;background:#141416;display:inline-block;box-shadow:0 0 0 1px var(--line),0 4px 14px -4px rgba(255,170,60,.5)}}.mark svg{{width:100%;height:100%;display:block}}
main{{position:relative;max-width:520px;margin:9vh auto;padding:28px 28px 24px;background:var(--surface);border:1px solid var(--line);border-radius:18px;box-shadow:0 1px 2px rgba(16,16,20,.04),0 6px 20px -6px rgba(16,16,20,.10)}}
main::before{{content:"";position:absolute;z-index:-1;left:-120px;top:-120px;width:420px;height:300px;background:radial-gradient(closest-side,var(--glow),transparent)}}
h1{{font:700 26px/1.2 "DM Sans",-apple-system,sans-serif;letter-spacing:-.028em;color:var(--ink);margin:0 0 10px}}p{{margin:10px 0}}
.small{{font-size:13px;color:var(--muted)}}a{{color:var(--accent)}}
.row{{display:flex;flex-direction:column;gap:10px;margin:20px 0}}
.btn{{display:flex;align-items:center;justify-content:center;height:46px;padding:0 16px;border-radius:13px;background:var(--primary);color:var(--on-primary);text-decoration:none;font-weight:600}}
button.btn{{width:100%;border:0;gap:10px;font:600 15px "DM Sans",-apple-system,sans-serif;cursor:pointer}}button.btn:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
button.btn.ok{{background:var(--accent);color:var(--on-primary)}}.btn .mark{{width:24px;height:24px;border-radius:7px}}
.btn+.btn{{background:var(--surface);color:var(--ink);border:1px solid var(--line-2)}}
.tok{{font:13px/1.5 "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;padding:12px 14px;background:var(--sunken);color:var(--ink);border:1px solid var(--line);border-radius:12px;user-select:all;overflow-wrap:anywhere;white-space:pre-wrap}}
details{{margin-top:16px;font-size:14px}}
summary{{display:inline-flex;align-items:center;gap:6px;cursor:pointer;color:var(--muted);list-style:none;padding:4px 8px;margin-left:-8px;border-radius:8px}}
summary::-webkit-details-marker{{display:none}}summary::before{{content:"";width:6px;height:6px;border:solid currentColor;border-width:0 1.5px 1.5px 0;transform:rotate(-45deg);transition:transform .15s}}
details[open] summary::before{{transform:rotate(45deg)}}summary:hover{{color:var(--ink);background:var(--sunken)}}
summary:focus{{outline:none}}summary:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
code{{font:12.5px "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;background:var(--sunken);padding:1px 6px;border-radius:6px;color:var(--ink)}}
@media(max-width:560px){{main{{margin:16px;padding:22px 18px}}}}
</style></head><body><header><a class="home" href="{home}" title="Go to Lantern">{MARK}<span>Lantern</span></a><a class="guide" href="{guide}" title="How to use Lantern: short animated demos">How to use Lantern</a></header><main>{inner}</main></body></html>"""


def valid_cli(cli: str | None) -> str:
    return cli if cli and CLI_RE.fullmatch(cli) else ""
