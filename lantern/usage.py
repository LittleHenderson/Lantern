"""Opt-in usage counts. Off by default; nothing leaves the machine until the person turns it on.

What is sent, once a day at most, to the Lantern gateway (`POST /v1/usage`), and nothing else:
  * a random install id (32 hex characters, made the first time sharing is turned on, kept in LANTERN_HOME/install_id)
  * the Lantern version and the operating system name (`Windows`, `Darwin`, `Linux`)
  * how many times each feature was used that day (`analyze: 3, explain: 1`), from the fixed list in FEATURES

Never sent: project names, folders, file names, code, findings, model names, keys, or anything typed.
`lantern usage --show` prints exactly what the next ping would contain. The gateway only accepts the
feature names below, so even a modified client cannot smuggle more through this channel.

Where it is sent (stage 7 of the 2026-11-09 directive; until 2026-11-10 the counts were posted to `<gateway>/v1/usage`
with a gateway address that already ends in `/v1`, a route the gateway does not have, so with the address Lantern
ships with no count ever arrived, and nothing said so). `destination(base)` gives the one address the counts go to for
a gateway address, or the reason none is sent, in fixed words that never repeat the address (it may hold a password):
https, or http for this computer only; a host; no name or password; no `?` or `#` part; plain printable characters.
`where(base)` adds the person's switch (`LANTERN_NO_REAL_PROVIDERS`: nothing leaves for another computer). `send` asks
`where`, follows no redirect (a redirect is not an acceptance), never raises, and writes down how the last try ended
(`usage_last.json`: a day, a number and a word of `TRIED`, never text a server sent); `describe` says where the counts
go, or why they do not, and how the last try ended.
"""

from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import json
import os
import platform
import re
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import __version__

FEATURES = frozenset({
    "analyze", "analyze_link", "explain", "explain_one", "accept", "starter", "verify", "export_sarif", "packs",
    "serve", "learn", "trace", "mcp_call", "mcp_connect", "evidence", "report_open", "settings_save"})
SETTING = "share_usage"


def home() -> Path:
    return Path(os.environ.get("LANTERN_HOME") or Path.home() / ".lantern")


def _read(name: str, default):
    p = home() / name
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
    except (OSError, json.JSONDecodeError):
        return default


def _write(name: str, data) -> None:
    home().mkdir(parents=True, exist_ok=True)
    (home() / name).write_text(json.dumps(data), encoding="utf-8")


def enabled() -> bool:
    return bool(_read("settings.json", {}).get(SETTING))


def set_enabled(on: bool) -> None:
    s = _read("settings.json", {})
    s[SETTING] = bool(on)
    _write("settings.json", s)
    if on:
        install_id()
    else:   # turning it off also throws away whatever was counted but not yet sent
        for name in ("usage.json", "usage_sent.json", "usage_last.json"):
            try:
                (home() / name).unlink()
            except OSError:
                pass


def install_id() -> str:
    p = home() / "install_id"
    try:
        v = p.read_text(encoding="utf-8").strip()
        if len(v) == 32 and all(c in "0123456789abcdef" for c in v):
            return v
    except OSError:
        pass
    v = secrets.token_hex(16)
    home().mkdir(parents=True, exist_ok=True)
    p.write_text(v, encoding="utf-8")
    return v


def today() -> str:
    return dt.datetime.now(dt.UTC).date().isoformat()


def record(feature: str) -> None:
    """Count one use of a feature. Cheap and silent; does nothing unless sharing is on."""
    if feature not in FEATURES or not enabled():
        return
    try:
        counts = _read("usage.json", {})
        day = counts.setdefault(today(), {})
        day[feature] = int(day.get(feature, 0)) + 1
        for k in [k for k in counts if k != today() and k < (dt.date.today() - dt.timedelta(days=7)).isoformat()]:
            counts.pop(k, None)   # anything older than a week was either sent or is stale
        _write("usage.json", counts)
    except (OSError, ValueError, TypeError):
        pass


def pending() -> list[dict]:
    """The pings that would be sent now: one per day with counts, oldest first. Empty when sharing is off."""
    if not enabled():
        return []
    counts = _read("usage.json", {})
    sent = _read("usage_sent.json", {})
    out = []
    for day in sorted(k for k in counts if isinstance(counts[k], dict)):
        feats = {k: int(v) for k, v in counts[day].items() if k in FEATURES and isinstance(v, int) and v > 0}
        if feats and sent.get(day) != json.dumps(feats, sort_keys=True):
            out.append({"install": install_id(), "version": __version__, "os": platform.system(), "day": day,
                        "features": feats})
    return out


# Why no count is sent to a gateway address, in fixed words. The address itself is never repeated: it may hold a password.
WHY_NOT = {
    "none": "the gateway address is not set",
    "plain": "the gateway address is not a plain web address (printable characters without blanks or a backslash, "
             "at most 2,000 of them)",
    "https": "the gateway address does not begin with https:// (http:// is taken for this computer only)",
    "secret": "the gateway address holds a name or a password",
    "host": "the gateway address names no computer",
    "port": "the gateway address has a port that is not a number",
    "more": "the gateway address has a question mark or a # part",
}
SWITCHED_OFF = "real providers are switched off (LANTERN_NO_REAL_PROVIDERS is set)"
MAX_ADDRESS = 2000
HOST_NAME = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", re.I)
# How a try that the gateway did not take ended. "answered" carries the status, a number.
TRIED = {
    "redirect": "the gateway answered with a redirect, which Lantern does not follow",
    "unreachable": "the gateway could not be reached",
    "unreadable": "the gateway gave no answer Lantern could read",
}


def destination(base: str) -> tuple[str | None, str | None]:
    """The address the counts are posted to for the gateway address `base`, written as every address of the gateway is
    (`providers.gateway_url()`: it ends in `/v1`, the folder all the gateway's routes are in; one written without it is
    given it). `(address, None)`, or `(None, why)` with a sentence of `WHY_NOT`. Looks at the text only."""
    from .providers import on_this_computer
    if not isinstance(base, str) or not base:
        return None, WHY_NOT["none"]
    if len(base) > MAX_ADDRESS or "\\" in base or any(not 33 <= ord(c) < 127 for c in base):
        return None, WHY_NOT["plain"]
    try:
        u = urllib.parse.urlsplit(base)
    except ValueError:
        return None, WHY_NOT["plain"]
    scheme = u.scheme.lower()
    if scheme not in ("http", "https"):
        return None, WHY_NOT["https"]
    if "@" in u.netloc:
        return None, WHY_NOT["secret"]
    if "?" in base or "#" in base:
        return None, WHY_NOT["more"]
    host = u.hostname or ""
    if not host or not (_is_address(host) or HOST_NAME.fullmatch(host)):
        return None, WHY_NOT["host"]
    try:
        if u.port == 0:
            return None, WHY_NOT["port"]
    except ValueError:
        return None, WHY_NOT["port"]
    if scheme == "http" and not on_this_computer(base):
        return None, WHY_NOT["https"]
    base = base.rstrip("/")
    return base + ("/usage" if base.endswith("/v1") else "/v1/usage"), None


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def where(base: str | None = None) -> tuple[str | None, str | None]:
    """Where the counts go now: `destination` of the gateway address (None: the one Lantern is set up with), and
    nothing for another computer while the person has real providers switched off."""
    from . import providers
    to, why = destination(providers.gateway_url() if base is None else base)
    if to and providers.real_providers_off() and not providers.on_this_computer(to):
        return None, SWITCHED_OFF
    return to, why


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is not followed: the counts were not taken, and what a redirect points at was never the address the
    person agreed to. urllib then raises the redirect itself as an HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _post(to: str, ping: dict, timeout: float) -> dict | None:
    """None when the gateway took the ping, else how the try ended: `{"why": <a word of TRIED or "answered">, ...}`."""
    req = urllib.request.Request(to, data=json.dumps(ping).encode("utf-8"), method="POST",
                                 headers={"content-type": "application/json", "user-agent": f"lantern/{__version__}"})
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as r:   # `to` is http(s): destination()
            return None if r.status == 200 else {"why": "answered", "status": int(r.status)}
    except urllib.error.HTTPError as e:
        e.close()
        return {"why": "redirect"} if 300 <= e.code < 400 else {"why": "answered", "status": int(e.code)}
    except (urllib.error.URLError, OSError):
        return {"why": "unreachable"}
    except (http.client.HTTPException, ValueError):
        return {"why": "unreadable"}


def send(url: str, timeout: float = 4.0) -> int:
    """Send the pending pings to the gateway whose address is `url` (as `providers.gateway_url()` gives it). Returns how
    many the gateway took. Never raises."""
    if not enabled() or not url:
        return 0
    to, _ = where(url)
    if not to:
        return 0
    n, ended = 0, None
    sent = _read("usage_sent.json", {})
    pings = pending()
    for ping in pings:
        ended = _post(to, ping, timeout)
        if ended:
            break
        sent[ping["day"]] = json.dumps(ping["features"], sort_keys=True)
        n += 1
    try:
        _write("usage_sent.json", {k: v for k, v in sent.items() if k >= (dt.date.today() - dt.timedelta(days=14)).isoformat()})
        if pings:
            _write("usage_last.json", {"day": today(), "taken": n, **(ended or {})})
    except OSError:
        pass
    return n


def last() -> str | None:
    """One sentence about the latest try to send, built from Lantern's own words: the note holds a day, a number and
    a word of `TRIED`, and a note of any other shape says nothing."""
    t = _read("usage_last.json", None)
    if not isinstance(t, dict):
        return None
    day, taken, why, status = t.get("day"), t.get("taken"), t.get("why"), t.get("status")
    try:
        if not isinstance(day, str) or dt.date.fromisoformat(day).isoformat() != day:
            return None
    except ValueError:
        return None
    if not isinstance(taken, int) or isinstance(taken, bool) or not 0 <= taken <= 366:
        return None
    if why is None:
        reason = None
    elif why == "answered" and isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
        reason = f"the gateway answered {status}"
    elif isinstance(why, str) and why in TRIED:
        reason = TRIED[why]
    else:
        return None
    took = f"the gateway took the counts of {taken} day{'' if taken == 1 else 's'}"
    if reason is None:
        return f"Last try {day}: {took}." if taken else None
    if taken:
        return f"Last try {day}: {took}, then stopped ({reason}). The rest stay on this computer and are tried again."
    return f"Last try {day}: not taken ({reason}). The counts stay on this computer and are tried again."


def send_in_background(url: str) -> None:
    """For the app and the CLI: never block anything on the network."""
    if enabled() and url and pending():
        threading.Thread(target=send, args=(url,), daemon=True).start()


def describe(url: str | None = None) -> str:
    """Plain words for Settings and `lantern usage --show`: on or off, where the counts go (or why they do not, for
    the gateway address `url`; None: the one Lantern is set up with), how the last try ended, and what waits."""
    p = pending()
    if not enabled():
        head = "OFF. Nothing is sent anywhere."
    else:
        head = ("ON. Lantern sends, at most once a day: a random install id, its version, your operating system name, and "
                "how many times each feature was used. Never project names, files, code, findings or keys.")
        to, why = where(url)
        if to:
            head += f"\nSent to: {to}"
            head += f"\n{last()}" if last() else ""
        elif why == SWITCHED_OFF:
            head += f"\nNot sent in this run: {why}. The counts stay on this computer."
        else:
            head += f"\nNot sent: {why}. The counts stay on this computer."
    if not p:
        return head + "\nNothing waiting to be sent."
    return head + "\nNext ping(s):\n" + "\n".join(json.dumps(x) for x in p)
