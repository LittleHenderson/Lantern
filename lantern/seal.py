"""This computer's seal on a record Lantern made by running a project's code (2026-11, directive point 6).

`behaviour.json` lies in the results folder, and the results folder usually lies in the project: a project can bring
one of its own that says every check held. So the release decision (`release.py`) counts such a record only when it
carries the seal of the Lantern that made it: an HMAC-SHA256 of the record under a key made on first use and kept in
LANTERN_HOME (`seal.key`, readable by its owner only). A record made on another computer, or changed since it was
made, does not hold.

The seal says which Lantern made the record. It does not say the record is right, and whoever can read LANTERN_HOME
can make one. Standard library only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets

from .removal import home

NAME = "seal.key"
BYTES = 32


def _key(make: bool) -> bytes | None:
    """The key, made when `make` and there is none. None when it cannot be read or made, or is not a key of ours."""
    p = home() / NAME
    try:
        if p.is_symlink() or not p.is_file():
            raise FileNotFoundError(p)
        with open(p, encoding="ascii", errors="replace") as f:
            key = bytes.fromhex(f.read(4 * BYTES).strip())
        return key if len(key) == BYTES else None
    except FileNotFoundError:
        if not make or p.is_symlink() or p.exists():
            return None
    except (OSError, ValueError):
        return None
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:     # another Lantern made it in the same moment
        return _key(False)
    except OSError:
        return None
    key = secrets.token_bytes(BYTES)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(key.hex() + "\n")
    except OSError:
        return None
    return key


def _body(record: dict) -> bytes:
    return json.dumps({k: v for k, v in record.items() if k != "seal"}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("ascii")


def sign(record: dict) -> str | None:
    """The seal for `record` (everything in it but `seal`), or None when this computer has no key and none can be
    made (LANTERN_HOME cannot be written)."""
    key = _key(True)
    if key is None:
        return None
    return hmac.new(key, _body(record), hashlib.sha256).hexdigest()


def holds(record) -> bool:
    """Whether `record` carries the seal this computer's Lantern gives exactly this record."""
    if not isinstance(record, dict) or not isinstance(record.get("seal"), str):
        return False
    key = _key(False)
    if key is None:
        return False
    try:
        want = hmac.new(key, _body(record), hashlib.sha256).hexdigest()
    except (TypeError, ValueError, RecursionError):   # a record nested deeper than Python follows is none of ours
        return False
    return hmac.compare_digest(want, record["seal"])
