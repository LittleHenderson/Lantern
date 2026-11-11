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
"""

from __future__ import annotations

import argparse
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
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG):   # no type bits (most tools) or a plain file are fine
        return "special"          # a symbolic link, device, pipe…: never written
    return "file"


def unpack(src: Path, dest: Path, max_bytes: int) -> int:
    """Unpack `src` into `dest` (created; must not exist). Returns the number of files written."""
    dest = Path(dest)
    if dest.exists():
        raise Refused("Lantern's work folder was not empty.")
    try:
        zf = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError):
        raise Refused("That file is not a .zip Lantern can read. Zip the app's folder and upload it again.") from None
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise Refused(f"The .zip holds more than {MAX_ENTRIES:,} files.")
        plan, seen, declared = [], set(), 0
        for info in infos:
            rel = _safe_name(info.filename)
            if rel is None:
                continue
            kind = _kind(info)
            if kind == "special":
                raise Refused("The .zip contains a link or special file, which Lantern does not unpack. "
                              "Zip the app's folder without links and upload it again.")
            if info.flag_bits & 0x1:
                raise Refused("The .zip is password-protected. Upload one without a password.")
            key = rel.as_posix()
            if kind == "file":
                if key in seen:
                    raise Refused("The .zip names the same file twice.")
                seen.add(key)
                declared += info.file_size
                if declared > max_bytes:
                    raise Refused(f"The app is larger than {max_bytes // (1 << 20)} MB once unpacked.")
            plan.append((info, rel, kind))
        if not seen:
            raise Refused("The .zip is empty.")
        # One top folder around everything ("myapp/…", as zipping a folder makes): unwrap it.
        tops = {rel.parts[0] for _i, rel, _k in plan}
        strip = len(tops) == 1 and all(len(rel.parts) > 1 or k == "dir" for _i, rel, k in plan)
        written, count = 0, 0
        try:
            dest.mkdir(parents=True)
            root = dest.resolve()
            for info, rel, kind in plan:
                parts = rel.parts[1:] if strip else rel.parts
                if not parts:
                    continue
                out = dest.joinpath(*parts)
                if root not in out.resolve().parents and out.resolve() != root:
                    raise Refused("The .zip has a file that would land outside its folder, so it was not unpacked.")
                if kind == "dir":
                    out.mkdir(parents=True, exist_ok=True)
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as r, open(out, "xb") as w:
                    while True:
                        chunk = r.read(CHUNK)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_bytes:   # sizes in the archive can lie; the bytes cannot
                            raise Refused(f"The app is larger than {max_bytes // (1 << 20)} MB once unpacked.")
                        w.write(chunk)
                count += 1
        except Refused:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, NotImplementedError):
            shutil.rmtree(dest, ignore_errors=True)
            raise Refused("The .zip is damaged or uses a format Lantern cannot read. Zip the folder again.") from None
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
