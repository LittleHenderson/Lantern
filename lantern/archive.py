"""Unpack an uploaded .zip of an app into a folder, refusing anything that could write outside it or fill the disk.

Used by cloud mode for "Upload from this computer" (`python -m lantern.archive SRC DEST --max-mb N`), inside the
restricted process with no network. The archive comes from a stranger, so every entry is checked before a byte is
written:

* names: relative, no `..`, no drive letters or backslashes, no NUL, at most 400 characters; repeated names refused;
* kinds: plain files and folders only (a symbolic link, device or other special file in the archive is refused);
* sizes: the declared total and the bytes actually written both stay under the cap (a "zip bomb" that lies about
  its sizes is stopped while writing), at most 100,000 entries, no encrypted entries;
* one top folder that holds everything (the usual "zip of a folder") is unwrapped, so the app's files sit at the root.

Errors are one plain sentence on stderr and exit code 2; nothing is left behind in DEST.

The test machine's program (`lantern.runner`) unpacks the archive of a check with the same rules and three more of
its own asking (`unpack(strip=False, modes=True, links=...)`): nothing is unwrapped, a file's run bit is kept and no
other (a file with any run bit is written 0755, any other 0644: never setuid, setgid or writable by others), and a
symbolic link is made only where the caller's rule says it is one npm makes (`links(name, target)`), last, after every
file, with no file or folder under its name, so nothing is ever written through it.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

MAX_ENTRIES = 100_000
MAX_NAME = 400
CHUNK = 1 << 16


class Refused(ValueError):
    """A plain sentence for the person: why the archive was not unpacked."""


def _safe_name(name: str) -> PurePosixPath | None:
    """The entry's path inside DEST, or None for the archive's own folder entries that add nothing ('./')."""
    if not name or len(name) > MAX_NAME or "\x00" in name or "\\" in name:
        raise Refused("The .zip has a file name Lantern cannot use safely.")
    p = PurePosixPath(name)
    if p.is_absolute() or (p.parts and ":" in p.parts[0]) or any(part == ".." for part in p.parts):
        raise Refused("The .zip has a file that would land outside its folder, so it was not unpacked.")
    parts = [x for x in p.parts if x not in ("", ".")]
    return PurePosixPath(*parts) if parts else None


def _kind(info: zipfile.ZipInfo) -> str:
    mode = (info.external_attr >> 16) & 0xFFFF
    if info.is_dir():
        return "dir"
    if stat.S_IFMT(mode) == stat.S_IFLNK:
        return "link"             # made only where the caller's rule takes it (`unpack(links=...)`)
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG):   # no type bits (most tools) or a plain file are fine
        return "special"          # a device, pipe…: never written
    return "file"


MOST_LINK = 1024                  # characters of a link's target


def _link_target(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    """What a link entry says it leads to: its data, plain text of at most `MOST_LINK` characters."""
    if info.file_size > MOST_LINK * 4 or info.flag_bits & 0x1:
        raise Refused("The .zip holds a link Lantern does not make, so it was not unpacked.")
    with zf.open(info) as r:
        data = r.read(MOST_LINK * 4 + 1)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("The .zip holds a link Lantern does not make, so it was not unpacked.") from None
    if len(text) > MOST_LINK:
        raise Refused("The .zip holds a link Lantern does not make, so it was not unpacked.")
    return text


def _write(zf: zipfile.ZipFile, info: zipfile.ZipInfo, out: Path, mode: int | None, written: int, max_bytes: int) -> int:
    """One file, created new (never through a link at its place) and counted while it is written. `mode`: the
    permissions it gets whatever the umask, or None for the system's own for a new file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_BINARY", 0)
    fd = os.open(out, flags, 0o666 if mode is None else 0o600)
    with zf.open(info) as r, os.fdopen(fd, "wb") as w:
        if mode is not None and hasattr(os, "fchmod"):
            os.fchmod(w.fileno(), mode)
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:   # sizes in the archive can lie; the bytes cannot
                raise Refused(f"The app is larger than {max_bytes // (1 << 20)} MB once unpacked.")
            w.write(chunk)
    return written


def unpack(src: Path, dest: Path, max_bytes: int, strip: bool = True, said: dict | None = None,
           entries: int = MAX_ENTRIES, modes: bool = False, links=None) -> int:
    """Unpack `src` into `dest` (created; must not exist). Returns the number of files written.

    `strip`: one top folder around everything is unwrapped (an upload of a zipped folder); False keeps every name as
    it is. `said`: filled with what was written (`files`, `bytes`, `links`). `entries`: the most entries the archive
    may hold. `modes`: a file with a run bit in the archive is written 0755 and any other 0644, whatever the umask
    (without it every file is written as the system writes a new one). `links`: None, and a link in the archive is
    refused as before; else a function `links(name, target) -> bool` of the link's place in `dest` (a posix path)
    and the text it leads to, which must say yes for each link, and a link is then made after every file and
    folder, where no other entry lies under its name."""
    dest = Path(dest)
    if dest.exists():
        raise Refused("Lantern's work folder was not empty.")
    try:
        zf = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError):
        raise Refused("That file is not a .zip Lantern can read. Zip the app's folder and upload it again.") from None
    with zf:
        infos = zf.infolist()
        if len(infos) > entries:
            raise Refused(f"The .zip holds more than {entries:,} files.")
        plan, seen, declared = [], set(), 0
        for info in infos:
            rel = _safe_name(info.filename)
            if rel is None:
                continue
            kind = _kind(info)
            if kind == "special" or (kind == "link" and links is None):
                raise Refused("The .zip contains a link or special file, which Lantern does not unpack. "
                              "Zip the app's folder without links and upload it again.")
            if info.flag_bits & 0x1:
                raise Refused("The .zip is password-protected. Upload one without a password.")
            key = rel.as_posix()
            if kind in ("file", "link"):
                if key in seen:
                    raise Refused("The .zip names the same file twice.")
                seen.add(key)
            if kind == "file":
                declared += info.file_size
                if declared > max_bytes:
                    raise Refused(f"The app is larger than {max_bytes // (1 << 20)} MB once unpacked.")
            plan.append((info, rel, kind))
        if not any(k == "file" for _i, _r, k in plan):
            raise Refused("The .zip is empty.")
        # One top folder around everything ("myapp/…", as zipping a folder makes): unwrap it, where asked.
        tops = {rel.parts[0] for _i, rel, _k in plan}
        strip = strip and len(tops) == 1 and all(len(rel.parts) > 1 or k == "dir" for _i, rel, k in plan)
        final = [(info, PurePosixPath(*(rel.parts[1:] if strip else rel.parts)) if (rel.parts[1:] if strip else rel.parts)
                  else None, kind) for info, rel, kind in plan]
        final = [(info, rel, kind) for info, rel, kind in final if rel is not None]
        made = []                                    # (info, rel, target) of each link, made last
        if any(kind == "link" for _i, _r, kind in final):
            names = {rel.as_posix() for _i, rel, k in final if k != "link"}
            for info, rel, kind in final:
                if kind != "link":
                    continue
                target = _link_target(zf, info)
                name = rel.as_posix()
                if name in names or not links(name, target):
                    raise Refused("The .zip holds a link Lantern does not make, so it was not unpacked.")
                made.append((info, rel, target))
            under = {rel.as_posix() for _i, rel, _t in made}
            for _info, rel, _k in final:         # nothing of the archive lies under a link's name, in any order
                if any(PurePosixPath(*rel.parts[:n]).as_posix() in under for n in range(1, len(rel.parts))):
                    raise Refused("The .zip has a file under the name of one of its links, so it was not unpacked.")
        written, count = 0, 0
        try:
            dest.mkdir(parents=True)
            root = dest.resolve()
            for info, rel, kind in final:
                if kind == "link":
                    continue
                out = dest.joinpath(*rel.parts)
                if root not in out.resolve().parents and out.resolve() != root:
                    raise Refused("The .zip has a file that would land outside its folder, so it was not unpacked.")
                if kind == "dir":
                    out.mkdir(parents=True, exist_ok=True)
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                mode = None
                if modes:
                    mode = 0o755 if (info.external_attr >> 16) & 0o111 else 0o644
                written = _write(zf, info, out, mode, written, max_bytes)
                count += 1
            for _info, rel, target in made:   # last: no file is written after a link is there
                out = dest.joinpath(*rel.parts)
                out.parent.mkdir(parents=True, exist_ok=True)
                if out.parent.resolve() != root and root not in out.parent.resolve().parents:
                    raise Refused("The .zip has a file that would land outside its folder, so it was not unpacked.")
                os.symlink(target, out)
        except Refused:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, NotImplementedError):
            shutil.rmtree(dest, ignore_errors=True)
            raise Refused("The .zip is damaged or uses a format Lantern cannot read. Zip the folder again.") from None
    if said is not None:
        said.update(files=count, bytes=written, links=len(made))
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m lantern.archive", description="Unpack an uploaded .zip safely.")
    ap.add_argument("src")
    ap.add_argument("dest")
    ap.add_argument("--max-mb", type=int, default=200)
    a = ap.parse_args(argv)
    from ._jail import say_if_guard_missing
    say_if_guard_missing()
    try:
        n = unpack(Path(a.src), Path(a.dest), a.max_mb << 20)
    except Refused as e:
        print(str(e), file=sys.stderr)
        return 2
    print(f"unpacked {n} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
