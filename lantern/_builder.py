"""Lantern's own part of building a library from its source (a firm pass or fail, stage 2; `lantern/libraries.py`).

A copy of this file is put into each build's own folder and started there by the sandbox's launcher, one step at a
time: `python <flags> _lantern_builder.py <step> '<what the step is given, as JSON>'`. It uses Python's own library
and nothing of Lantern's, because the Python of a build has the build's tools on its path and nothing else. Each
step writes one small JSON file that says how it went. `libraries` takes that file by its shape, and believes
nothing in it that it can look at itself: the fingerprint of the source, and the package the build left.

* `source`, the one step with a way out (through the doorkeeper, to the store): ask the store's page of the
  library for the source package of exactly the version the project fixes (`pick`) and save that file. Nothing in
  the file is read.
* `unpack`, behind the walls of the tests' run like the two after it: unpack that file (`unpack`: plain files and
  folders beneath the one folder at its top, or nothing at all) and read in its `pyproject.toml` how it is built
  (`how`). No line of the library runs.
* `needs`: ask the build what else it needs now that it can see its source (`get_requires_for_build_wheel`).
* `build`: have it build (`build_wheel`), in the source's own folder.

The last two run code the library brings, which is what building is. They are called the way every tool calls
them (PEP 517): in the source's folder, with the folders the source names for its own build code first on the
path, and never through pip or `setup.py`. What such a step writes as its result may be the library's words and
not this file's; nothing is built on it that the walls do not hold anyway."""
from __future__ import annotations

import html
import json
import os
import re
import sys

MOST_FILES = 20_000                 # the entries one source package may hold
MOST_UNPACKED = 1 << 30             # the bytes it may hold once unpacked
MOST_PAGE = 64 << 20                # the bytes of a store's page that are read
MOST_TOOLS = 50                     # the tools a build may name
MOST_TOML = 4_000_000
LEGACY = "setuptools.build_meta:__legacy__"         # the build of a source that names none (PEP 517)
LEGACY_TOOLS = ["setuptools>=40.8.0"]
_PART = r"[A-Za-z_][A-Za-z0-9_]*"
BACKEND = re.compile(rf"{_PART}(?:\.{_PART})*(?::{_PART}(?:\.{_PART})*)?")
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)


class Refused(Exception):
    """A source package that is not taken. `why` is one word: `link`, `outside`, `top`, `kind`, `count`, `size`,
    `broken` (`unpack`), `follow`, `outside-code` (`how`)."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------- which file of a store's page
# A link of the page: `<a … href="…">`. Read with a pattern whose every part is bounded; a page is a stranger's
# text, and a parser that follows its nesting can be held up by it.
_LINK = re.compile(r"""<a\s[^<>]{0,4000}?(?<![\w\-])href\s*=\s*(?:"([^"<>]{1,4000})"|'([^'<>]{1,4000})')""", re.I)


def pick(page: str, name: str, version: str) -> tuple[str, str] | None:
    """The source package of exactly `version` of `name` on a store's page of that library (PyPI's simple index):
    (its address as the page writes it, without what follows a `#`; the SHA-256 the page names for it, or "").
    The file is told by the name a store gives it, `<name>-<version>.tar.gz`, with the library's name written any
    way a store may write it (`Stage2_Mac`, `stage2-mac`). None when the page names no such file: not a
    ready-built file, not another version, not a library whose name begins the same, not a `.zip`."""
    want, tail = _norm(name), "-" + version.lower()
    for m in _LINK.finditer(page[:MOST_PAGE]):
        place, _, mark = html.unescape(m.group(1) or m.group(2)).strip().partition("#")
        file = place.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        if not file.lower().endswith(".tar.gz"):
            continue
        stem = file[:-len(".tar.gz")]
        head = stem[:-len(tail)]
        if not stem.lower().endswith(tail) or not head or _norm(head) != want:
            continue
        said = re.fullmatch(r"sha256=([0-9a-f]{64})", mark.strip().lower())
        return place, said.group(1) if said else ""
    return None


# ---------------------------------------------------------------------------- unpacking
def _entries(t):
    """Each entry of an open archive as (the entry, the parts of its name, "dir" or "file"), in the archive's
    order; `Refused` at the first that is not a plain file or a folder beneath the one folder at the top."""
    import tarfile
    kinds: dict[str, str] = {}
    top, total = None, 0
    for count, m in enumerate(t, 1):
        if count > MOST_FILES:
            raise Refused("count")
        name = m.name
        if not isinstance(name, str) or "\x00" in name:
            raise Refused("broken")
        if os.name == "nt" and ("\\" in name or ":" in name):
            raise Refused("outside")
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if name.startswith("/") or ".." in parts:
            raise Refused("outside")
        if m.issym() or m.islnk():
            raise Refused("link")
        if m.isdir():
            kind = "dir"
        elif m.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not m.issparse():
            kind = "file"
        else:
            raise Refused("kind")
        if not parts:
            if kind == "dir":
                continue                    # `./`, the archive's own folder
            raise Refused("broken")
        top = top or parts[0]
        if parts[0] != top or (kind == "file" and len(parts) == 1):
            raise Refused("top")
        for at in range(1, len(parts)):
            if kinds.setdefault("/".join(parts[:at]), "dir") != "dir":
                raise Refused("broken")     # a file where a folder has to be
        path = "/".join(parts)
        if kind == "dir":
            if kinds.setdefault(path, "dir") != "dir":
                raise Refused("broken")
        else:
            if path in kinds or not isinstance(m.size, int) or m.size < 0:
                raise Refused("broken")     # a name twice
            kinds[path] = "file"
            total += m.size
            if total > MOST_UNPACKED:
                raise Refused("size")
        yield m, parts, kind
    if top is None:
        raise Refused("top")                # nothing in it


def unpack(archive, into) -> str:
    """Unpack the source package `archive` (a `.tar.gz`) into the empty folder `into`; returns the name of the one
    folder at its top. Plain files and folders only, every one beneath that folder, at most `MOST_FILES` entries
    and `MOST_UNPACKED` bytes: `Refused` otherwise, with the reason as one word. The whole package is read
    before anything is written, so nothing is written for one that holds anything refused or is cut short; and
    what is written is written anew, never through a link and never over a file that is there."""
    import tarfile
    import zlib
    odd = (tarfile.TarError, EOFError, OSError, zlib.error, ValueError, OverflowError)
    top = ""
    for write in (False, True):
        try:
            with tarfile.open(archive, "r:gz") as t:
                for m, parts, kind in _entries(t):
                    top = parts[0]
                    where = os.path.join(into, *parts)
                    if kind == "dir":
                        if write:
                            os.makedirs(where, mode=0o755, exist_ok=True)
                        continue
                    data, left, out = t.extractfile(m), m.size, None
                    if write:
                        os.makedirs(os.path.dirname(where), mode=0o755, exist_ok=True)
                        out = os.fdopen(os.open(where, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                                                0o755 if m.mode & 0o100 else 0o644), "wb")
                    try:
                        while left:
                            chunk = data.read(min(1 << 16, left)) if data is not None else b""
                            if not chunk:
                                raise Refused("broken")     # shorter than it says
                            left -= len(chunk)
                            if out is not None:
                                out.write(chunk)
                    finally:
                        if out is not None:
                            out.close()
        except Refused:
            raise
        except odd:
            raise Refused("broken") from None
    return top


def how(source: str) -> dict:
    """How the source in the folder `source` says it is built: `{"backend", "path", "tools"}`, read from its
    `pyproject.toml` the way every tool reads it (PEP 517 and 518). With no such file, or none that names a build,
    it is setuptools' older way. `Refused("follow")` for a table that is not of that shape, and
    `Refused("outside-code")` where it names code for its build that does not lie in the source."""
    import tomllib
    legacy = {"backend": LEGACY, "path": [], "tools": list(LEGACY_TOOLS)}
    try:
        fd = os.open(os.path.join(source, "pyproject.toml"), os.O_RDONLY | NOFOLLOW)
    except FileNotFoundError:
        return legacy
    except OSError:
        raise Refused("follow") from None
    with os.fdopen(fd, "rb") as f:
        data = f.read(MOST_TOML + 1)
    try:
        if len(data) > MOST_TOML:
            raise ValueError("too large")
        table = tomllib.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        raise Refused("follow") from None
    system = table.get("build-system")
    if system is None:
        return legacy
    tools = system.get("requires") if isinstance(system, dict) else None
    if not isinstance(tools, list) or len(tools) > MOST_TOOLS or not all(isinstance(t, str) for t in tools):
        raise Refused("follow")
    backend, path = system.get("build-backend", LEGACY), system.get("backend-path", [])
    if not isinstance(backend, str) or len(backend) > 300 or not BACKEND.fullmatch(backend):
        raise Refused("follow")
    if not isinstance(path, list) or len(path) > 20 or not all(isinstance(p, str) and p for p in path):
        raise Refused("follow")
    real = os.path.realpath(source)
    for p in path:
        there = os.path.realpath(os.path.join(real, p))
        if os.path.isabs(p) or not (there == real or there.startswith(real + os.sep)):
            raise Refused("outside-code")
    return {"backend": backend, "path": path, "tools": tools}


# ---------------------------------------------------------------------------- the steps
def _say(result: str, data: dict) -> None:
    with os.fdopen(os.open(result, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o644), "w", encoding="utf-8") as f:
        f.write(json.dumps(data))


def _get(url: str, proxy: str, cert: str, most: int, sink=None):
    """(the store's answer as a number, or a word when there was none; the bytes it sent, or how many were handed
    to `sink`): one page or file of the store, asked through the doorkeeper `proxy`. A few of the store's own
    redirects are followed; the doorkeeper decides where any of it may lead."""
    import http.client
    import ssl
    from urllib.parse import urljoin, urlsplit
    door = urlsplit(proxy)
    for _ in range(4):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
            return "odd", b""
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(door.hostname, door.port, timeout=30,
                                               context=ssl.create_default_context(cafile=cert or None))
            conn.set_tunnel(parts.hostname, parts.port or 443)
            target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        else:
            conn = http.client.HTTPConnection(door.hostname, door.port, timeout=30)
            target = url.split("#", 1)[0]
        try:
            conn.request("GET", target, headers={"Host": parts.netloc, "Accept": "text/html, */*;q=0.1",
                                                 "Accept-Encoding": "identity", "User-Agent": "lantern",
                                                 "Connection": "close"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                url = urljoin(url, r.getheader("Location"))
                continue
            if r.status != 200:
                return r.status, b""
            got, held = 0, []
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                got += len(chunk)
                if got > most:
                    return "large", b""
                (sink or held.append)(chunk)
            return 200, got if sink else b"".join(held)
        finally:
            conn.close()
    return "odd", b""


def _source(given: dict) -> dict:
    """Save the source package of `name` `version` from the store at `index` into the file `into` (made anew)."""
    import hashlib
    from urllib.parse import urljoin
    page_at = given["index"].rstrip("/") + "/" + _norm(given["name"]) + "/"
    try:
        status, page = _get(page_at, given["proxy"], given.get("cert", ""), MOST_PAGE)
        if status != 200:
            return {"state": "no-library" if status == 404 else "refused" if status == 403 else "unreachable"}
        found = pick(page.decode("utf-8", "replace"), given["name"], given["version"])
        if found is None:
            return {"state": "no-source"}
        digest = hashlib.sha256()
        with os.fdopen(os.open(given["into"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o644), "wb") as out:
            def sink(chunk: bytes) -> None:
                digest.update(chunk)
                out.write(chunk)
            status, size = _get(urljoin(page_at, found[0]), given["proxy"], given.get("cert", ""), given["most"], sink)
        if status != 200:
            return {"state": "too-large" if status == "large" else "refused" if status == 403 else "unreachable"}
        return {"state": "fetched", "file": found[0].split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1][:300],
                "sha256": digest.hexdigest(), "bytes": size, "page_sha256": found[1]}
    except (OSError, ValueError) as e:      # no way to the store, or an answer that is none (`http.client`'s are OSError)
        refused = "403" in str(e) and "Tunnel" in str(e)
        return {"state": "refused" if refused else "unreachable"}


def _unpack(given: dict) -> dict:
    try:
        top = unpack(given["archive"], given["into"])
        return {"state": "unpacked", "top": top, **how(os.path.join(given["into"], top))}
    except Refused as e:
        return {"state": "refused", "why": e.why}


def _backend(given: dict):
    """The build of the source in `source`, loaded the way every tool loads it: from that folder, with the
    folders the source names for its own build code first on the path."""
    import importlib
    os.chdir(given["source"])
    sys.path[:0] = [os.path.join(given["source"], p) for p in given["path"]]
    module, _, inner = given["backend"].partition(":")
    found = importlib.import_module(module)
    for part in inner.split(".") if inner else []:
        found = getattr(found, part)
    return found


def _needs(given: dict) -> dict:
    ask = getattr(_backend(given), "get_requires_for_build_wheel", None)
    said = ask(None) if ask is not None else []
    return {"state": "said", "tools": [str(s) for s in list(said)[:MOST_TOOLS + 1]]}


def _build(given: dict) -> dict:
    return {"state": "built", "file": str(_backend(given).build_wheel(given["out"], None, None))[:300]}


STEPS = {"source": _source, "unpack": _unpack, "needs": _needs, "build": _build}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in STEPS:
        print("lantern builder: a step and what it is given")
        return 2
    given = json.loads(argv[1])
    _say(given["result"], STEPS[argv[0]](given))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
