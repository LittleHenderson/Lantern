"""Opt-in usage counts. Off by default; nothing leaves the machine until the person turns it on.

What is sent, once a day at most, to the Lantern gateway (`POST /v1/usage`), and nothing else:
  * a random install id (32 hex characters, made the first time sharing is turned on, kept in LANTERN_HOME/install_id)
  * the Lantern version and the operating system name (`Windows`, `Darwin`, `Linux`)
  * how many times each feature was used that day (`analyze: 3, explain: 1`), from the fixed list in FEATURES

Never sent: project names, folders, file names, code, findings, model names, keys, or anything typed.
`lantern usage --show` prints exactly what the next ping would contain. The gateway only accepts the
feature names below, so even a modified client cannot smuggle more through this channel.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import secrets
import threading
import urllib.error
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
        for name in ("usage.json", "usage_sent.json"):
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


def send(url: str, timeout: float = 4.0) -> int:
    """Send the pending pings to `url` (the gateway). Returns how many were accepted. Never raises."""
    if not enabled() or not url:
        return 0
    n = 0
    sent = _read("usage_sent.json", {})
    for ping in pending():
        try:
            req = urllib.request.Request(url.rstrip("/") + "/v1/usage", data=json.dumps(ping).encode("utf-8"),
                                         headers={"content-type": "application/json", "user-agent": f"lantern/{__version__}"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310: https gateway URL from config
                if r.status == 200:
                    sent[ping["day"]] = json.dumps(ping["features"], sort_keys=True)
                    n += 1
        except (urllib.error.URLError, OSError, ValueError):
            break
    try:
        _write("usage_sent.json", {k: v for k, v in sent.items() if k >= (dt.date.today() - dt.timedelta(days=14)).isoformat()})
    except OSError:
        pass
    return n


def send_in_background(url: str) -> None:
    """For the app and the CLI: never block anything on the network."""
    if enabled() and url and pending():
        threading.Thread(target=send, args=(url,), daemon=True).start()


def describe() -> str:
    """Plain words for Settings and `lantern usage --show`."""
    p = pending()
    head = ("ON. Lantern sends, at most once a day: a random install id, its version, your operating system name, and "
            "how many times each feature was used. Never project names, files, code, findings or keys."
            if enabled() else "OFF. Nothing is sent anywhere.")
    if not p:
        return head + "\nNothing waiting to be sent."
    return head + "\nNext ping(s):\n" + "\n".join(json.dumps(x) for x in p)
