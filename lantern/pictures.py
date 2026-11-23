"""Pictures of the pages a browser check opened (`lantern browse`; a firm pass or fail, stage 5, step 3).

A picture shows the person what the browser saw, and it can show what the project's pages hold, so it stays on this
computer: in LANTERN_HOME/pictures/, a folder of each run's own (`SET`, a random name) closed to other users, each
picture a file named by its own SHA-256 (`NAME`) and written as a new file, never through a link. Nothing of them goes
into the results folder (which usually lies in the project, and is shared with the report), the report, Ask
Lantern, an explanation or the connector: the record (browser.json `pictures`) names them by their fingerprint
only, and the report says how many there are. The app (`lantern serve`) shows them behind its session key, and only
those a record sealed by this computer names (`server`, `/api/projects/<id>/browser/pictures`).

The folders of the `KEEP_RUNS` newest runs are kept; an older run's folder is removed by its exact name, and only
when it is a plain folder of this user's that Lantern named (`removal.ours`): nothing else in the folder is touched,
and no link is followed. A picture is read back only from such a folder, only as a plain file of this user's, and
only when what it holds is what its name says (`read`)."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from pathlib import Path

from . import removal

PNG = b"\x89PNG\r\n\x1a\n"      # how every PNG picture begins, before its header chunk (IHDR)
MOST_PICTURES = 10              # pictures kept of one run: the first pages that showed something
MOST_BYTES = 8 << 20            # bytes of one picture; a larger one is not kept
KEEP_RUNS = 20                  # the runs whose pictures are kept on this computer; an older run's are removed
SET = re.compile(r"[0-9a-f]{32}")           # the folder of one run's pictures
NAME = re.compile(r"[0-9a-f]{64}\.png")     # one picture: the SHA-256 of what it holds
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)     # 0 where the system has no way to open a name without going through a link
BINARY = getattr(os, "O_BINARY", 0)
CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def place() -> Path:
    """Where the pictures of every run are kept: LANTERN_HOME/pictures."""
    return removal.home() / "pictures"


def is_picture(data) -> bool:
    """A PNG picture of at most MOST_BYTES: its signature, then its header chunk."""
    return (isinstance(data, (bytes, bytearray)) and 24 <= len(data) <= MOST_BYTES and bytes(data[:8]) == PNG
            and bytes(data[12:16]) == b"IHDR")


def _closed_folder(path: Path) -> bool:
    """`path` is a plain folder of this user's, closed to other users: made so when it is not there, closed when it
    is this user's and open to others; never a link, never another user's."""
    try:
        os.mkdir(path, 0o700)
        return True
    except FileExistsError:
        pass
    except OSError:
        return False
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode) or removal._linkish(st):
        return False
    if hasattr(os, "geteuid"):
        if st.st_uid != os.geteuid():
            return False
        if stat.S_IMODE(st.st_mode) & 0o077:
            try:
                os.chmod(path, 0o700)
            except OSError:
                return False
    return True


def keep(shots) -> dict:
    """Keep the pictures of one run: `shots` is [(page, picture)] in the order the pages were opened. What is not a
    PNG picture of at most MOST_BYTES is not kept, nor anything after the first MOST_PICTURES; a picture taken of
    two pages is one file. {"set": the run's folder or None, "shots": [{"page", "name", "bytes"}], "not_kept": n},
    with "why" in Lantern's own words when the folder could not be made. Never raises for what the system refused;
    the older runs beyond KEEP_RUNS are removed afterwards (`tidy`)."""
    shots = list(shots or [])
    if not shots:
        return {"set": None, "shots": [], "not_kept": 0}
    root = place()
    try:
        root.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    run = secrets.token_hex(16)
    folder = root / run
    if not (_closed_folder(root) and _closed_folder(folder)):
        return {"set": None, "shots": [], "not_kept": len(shots),
                "why": "LANTERN_HOME/pictures could not be made a folder of this user's own"}
    rows, written, not_kept = [], set(), 0
    for page, data in shots:
        if len(rows) >= MOST_PICTURES or not is_picture(data) or not isinstance(page, str):
            not_kept += 1
            continue
        name = hashlib.sha256(data).hexdigest() + ".png"
        if name not in written:
            try:
                fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | BINARY | CLOEXEC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            except OSError:
                not_kept += 1
                continue
            written.add(name)
        rows.append({"page": page[:300], "name": name, "bytes": len(data)})
    tidy(spare=run)
    return {"set": run, "shots": rows, "not_kept": not_kept}


def listed(record) -> tuple[str | None, list[dict]]:
    """(the run's folder, [{"page", "name", "bytes"}]) of what a browser record says it kept, taken by shape only:
    a folder and names of the forms Lantern gives, a page that is text. (None, []) for anything else."""
    kept = record.get("pictures") if isinstance(record, dict) else None
    if not isinstance(kept, dict) or not isinstance(kept.get("set"), str) or not SET.fullmatch(kept["set"]):
        return None, []
    rows = []
    for s in kept.get("shots") if isinstance(kept.get("shots"), list) else []:
        if (isinstance(s, dict) and isinstance(s.get("name"), str) and NAME.fullmatch(s["name"])
                and isinstance(s.get("page"), str)):
            n = s.get("bytes")
            rows.append({"page": s["page"][:300], "name": s["name"],
                         "bytes": n if isinstance(n, int) and not isinstance(n, bool) else None})
    return kept["set"], rows[:MOST_PICTURES]


def read(run, name) -> bytes | None:
    """The picture called `name` of the run `run`, or None: only from a plain folder of this user's that Lantern
    named, only as a plain file of this user's with that name, and only when what it holds is a picture whose
    SHA-256 is its name."""
    if not (isinstance(run, str) and SET.fullmatch(run) and isinstance(name, str) and NAME.fullmatch(name)):
        return None
    root = place()
    if removal.ours(root, run, SET) is not None or removal.ours(root / run, name, NAME, kind="file") is not None:
        return None
    try:
        fd = os.open(root / run / name, os.O_RDONLY | NOFOLLOW | BINARY | CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MOST_BYTES:
            return None
        parts, left = [], MOST_BYTES + 1
        while left > 0:
            piece = os.read(fd, min(left, 1 << 20))
            if not piece:
                break
            parts.append(piece)
            left -= len(piece)
    except OSError:
        return None
    finally:
        os.close(fd)
    data = b"".join(parts)
    if not is_picture(data) or hashlib.sha256(data).hexdigest() + ".png" != name:
        return None
    return data


def tidy(spare: str | None = None) -> int:
    """Remove the folders of the runs older than the KEEP_RUNS newest (by when each was last changed), keeping
    `spare`; only plain folders of this user's that Lantern named, each by its exact name (`removal.remove`).
    How many were removed."""
    root = place()
    try:
        entries = list(os.scandir(root))
    except OSError:
        return 0
    runs = []
    for e in entries:
        if SET.fullmatch(e.name) and removal.ours(root, e.name, SET) is None:
            try:
                runs.append((e.stat(follow_symlinks=False).st_mtime, e.name))
            except OSError:
                continue
    runs.sort(reverse=True)
    gone = 0
    for _, name in runs[KEEP_RUNS:]:
        if name != spare and removal.remove(root / name) is None:
            gone += 1
    return gone
