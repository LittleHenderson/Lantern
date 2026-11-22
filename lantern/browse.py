"""Browser checks (a firm pass or fail, stage 5, 2026-11-21): the project's own site opened in a real browser, and
what happened there said. The contract is `docs/browser.md`, written before the checks were built; this module holds
its list, and `tests/test_browse.py` holds the two to each other.

`run(repo)` gives the record (docs/browser.md, "What comes out"). How a run goes:

* The site (`_site`): a FastAPI app Lantern reads in the code (`behave_init.app_of`, the app `lantern behave`
  starts) is started in the sealed box (`_Box`: `sandbox.run_inside` with Lantern's own driver
  `lantern._browse_inside`, on a copy of the project, with no network, answering through a folder of the box's own);
  otherwise a folder of plain pages is served by Lantern's own code (`_Pages`: the project's own files only, a link
  that leads out of the project is no file). The site's address is `http://localhost:<port>`, at which no program
  listens.
* The browser (`lantern._cdp`): started with its own sandbox (on Linux the browser's own page about it must say so)
  and an empty profile of the run's own, driven through a pipe. Every request of a page is stopped inside the browser
  before it leaves (`Fetch`): one for the site's address is answered from the site, any other is refused there and
  written down. The browser's one way out is a door of Lantern's own (`_Door`) that forwards nothing: what reaches
  it (what the browser asks for itself) is refused and written down too.
* The walk (`_Walk`): every page the site says it has is opened, and looked at once it has settled (no request
  under way, nothing changed for a moment, nothing on it still moving); then its links and buttons are clicked one
  at a time, its forms filled with made-up values and sent once, and it is walked with the Tab key, each from a
  fresh load of the page. A visitor with no sign-in opens the pages the code reading says ask who is
  calling, in a browser context of its own. What each check saw is read from what was recorded (`_judge`).

A browser check only says what the browser saw: nothing here creates, closes or re-ranks a finding."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import socket
import stat
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import pictures, programs


@dataclass(frozen=True)
class Check:
    """One check: its id, what it holds in plain words, and the codes a broken outcome gives."""
    id: str
    title: str
    codes: tuple[str, ...]


CHECKS: tuple[Check, ...] = (
    Check("opens", "every page opens", ("server-error", "not-found", "no-answer", "empty")),
    Check("script", "the page's own script runs without an error", ("raised", "console-error", "not-loaded")),
    Check("leads", "links and buttons lead somewhere", ("dead-link", "empty-link", "dead-button", "button-raises")),
    Check("forms", "forms can be sent", ("form-error", "form-nowhere", "form-raises")),
    Check("visitor", "a visitor who is not signed in is kept out where the code asks for a sign-in", ("let-in",)),
    Check("protections", "the protections the code sets are sent", ("said-not-sent", "cookie-open")),
    Check("outside", "nothing is asked of another computer", ("outside-script", "outside-file")),
    Check("keyboard", "it can be used without a mouse",
          ("no-name", "no-label", "not-reached", "no-focus-ring", "trapped")),
)
BY_ID = {c.id: c for c in CHECKS}

# Only `held` counts as held. `inconclusive`: every row the check saw is undecided (below), so it may come from
# something the run itself refused.
OUTCOMES = ("held", "broken", "inconclusive", "nothing-to-check", "not-run")

# What a page's script could have changed, where a script from another computer was refused on that page (every such
# request is refused in a run): the rows of these codes there are undecided (`"undecided": true` on the row), may come
# from that script being missing, and give no code. A server's answer, a missing file of the site's own, a link in the
# page as it was sent and a trap (a listener of a script that ran) are decided whatever the refused script would have
# done.
UNDECIDED = {"opens": ("empty",), "script": ("raised", "console-error"),
             "leads": ("empty-link", "dead-button", "button-raises"), "forms": ("form-raises",),
             "keyboard": ("no-name", "no-label", "not-reached", "no-focus-ring")}
UNDECIDED_WHY = "what was seen came on pages where a script from another computer was refused, and may come from " \
                "that script being missing"


def not_sent(n: int) -> str:
    """The `forms` check's reason where forms were not sent (2026-11-22): on the page opened anew no form, or more than
    one, had the address, the method and the fields of the one first seen. With none sent, the check is
    `inconclusive`."""
    return (f"{n} form{'' if n == 1 else 's'} not sent: on the page opened anew Lantern could not tell which form was "
            "the one first seen (none had its address, its method and its fields, or more than one had)")


def not_clicked(n: int) -> str:
    """The `leads` check's reason where controls were not clicked (2026-11-22): on the page opened anew for a click no
    control, or more than one, had the kind, the words and, for a link, the address of the one first seen, so Lantern
    could not tell which it was and clicked none. With nothing else looked at, the check is `inconclusive`."""
    return (f"{n} control{'' if n == 1 else 's'} not clicked: on the page opened anew Lantern could not tell which "
            "control was the one first seen (none had its kind, its words and, for a link, its address, or more than "
            "one had)")

# Why a check, or a whole run, was not run: Lantern's own words, never text of a page, a browser or an app.
WHY_NOT = {
    "not-built": "The browser checks are not built for this system yet.",
    "no-browser": "No browser Lantern can drive was found (Chrome, Chromium, Edge or Brave); LANTERN_BROWSER can name "
                  "one by its full path.",
    "no-browser-sandbox": "The browser cannot keep its own sandbox on this computer, and Lantern does not open a "
                          "project's pages without it.",
    "browser-failed": "The browser stopped, or did not answer, before the pages were looked at.",
    "no-site": "There is nothing to open: no folder of plain pages and no app Lantern can start.",
    "not-started": "The app could not be started in the sealed box.",
    "no-sandbox": "The sealed box cannot be set up on this computer, so the app is not started.",
    "hosting-unknown": "Plain pages: what a hosting service would send with them is not in the project's folder.",
}

BUILT_FOR = ("linux", "darwin", "win32")   # the systems the checks are built for (sys.platform starts with one)
MOST_PAGES = 50          # pages opened in one run
MOST_CLICKS = 40         # links and buttons clicked on one page
PAGE_SECONDS = 20        # how long a page has to answer and settle
RESULT_NAME = "browser.json"   # the record, in the results folder (`lantern browse`)
NOT_COMPARED = ("Strict-Transport-Security",)   # sent over HTTPS only; the site is served over plain HTTP in a run

# Where each system installs the browsers Lantern drives (all of the Chromium family, driven alike).
ON_PATH = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge",
           "microsoft-edge-stable", "brave-browser")
MAC_APPS = ("Google Chrome.app/Contents/MacOS/Google Chrome", "Chromium.app/Contents/MacOS/Chromium",
            "Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "Brave Browser.app/Contents/MacOS/Brave Browser")
WINDOWS_PLACES = (("ProgramFiles", r"Google\Chrome\Application\chrome.exe"),
                  ("ProgramFiles(x86)", r"Google\Chrome\Application\chrome.exe"),
                  ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
                  ("ProgramFiles", r"Microsoft\Edge\Application\msedge.exe"),
                  ("ProgramFiles(x86)", r"Microsoft\Edge\Application\msedge.exe"),
                  ("ProgramFiles", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                  ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                  ("LOCALAPPDATA", r"Chromium\Application\chrome.exe"))


def _program(path: str) -> bool:
    return os.path.isabs(path) and os.path.isfile(path) and (sys.platform == "win32" or os.access(path, os.X_OK))


def find_browser(env=None, system: str | None = None) -> str | None:
    """The full path of the browser a run uses, or None: the one `LANTERN_BROWSER` names (a full path; one that names
    no program gives None, and no other is looked for), else the first of the places each system installs them."""
    env = os.environ if env is None else env
    system = system or sys.platform
    named = (env.get("LANTERN_BROWSER") or "").strip()
    if named:
        return os.path.normpath(named) if _program(named) else None
    if system == "win32":
        for var, rest in WINDOWS_PLACES:
            top = (env.get(var) or "").strip()
            if top and os.path.isabs(top) and _program(os.path.join(top, rest)):
                return os.path.join(top, rest)
        return None
    if system == "darwin":
        home = (env.get("HOME") or "").strip()
        for top in ["/Applications"] + ([os.path.join(home, "Applications")] if os.path.isabs(home) else []):
            for app in MAC_APPS:
                if _program(os.path.join(top, app)):
                    return os.path.join(top, app)
        return None
    for name in ON_PATH:
        found = programs.find(name, env.get("PATH", os.defpath))
        if found:
            return found
    return None


# ================================================================================================== the site
PAGE_EXT = (".html", ".htm")
BUILT = ("public", "dist", "build", "out", "_site", "site", "www")     # where a built folder of plain pages lies
MOST_FILE = 16 << 20            # bytes of one file of plain pages that are handed to the browser
TYPES = {".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
         ".json": "application/json", ".map": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
         ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
         ".avif": "image/avif", ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff",
         ".ttf": "font/ttf", ".otf": "font/otf", ".txt": "text/plain; charset=utf-8", ".xml": "application/xml",
         ".pdf": "application/pdf", ".wasm": "application/wasm", ".mp4": "video/mp4", ".webm": "video/webm",
         ".mp3": "audio/mpeg", ".wav": "audio/wav", ".webmanifest": "application/manifest+json"}


def _route_pattern(path: str) -> re.Pattern:
    """A route's path as the router matches it: `{name}` is one part of the address, `{name:path}` the rest."""
    out = ""
    for piece in re.split(r"(\{[^{}]*\})", path):
        if piece.startswith("{") and piece.endswith("}"):
            out += ".+" if piece[1:-1].partition(":")[2] == "path" else "[^/]+"
        else:
            out += re.escape(piece)
    return re.compile(out + "/?")


@dataclass
class Site:
    """What a run opens: `how` is `pages` or `app`; `pages` the addresses the site says it has (the start page
    first); `logins` those of them the code reading says ask who is calling; `headers` the security headers the code
    sets for every response (lower case), compared with what was sent; `routes` (an app) what its code answers."""
    how: str
    root: Path
    pages: list[str]
    logins: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    routes: list[tuple[str, re.Pattern]] = field(default_factory=list)
    app: dict | None = None
    notes: list[str] = field(default_factory=list)

    def has(self, path: str) -> bool:
        """Does the site have this address: a route of the app's code, a file of the folder."""
        if self.how == "app":
            return any(p.fullmatch(path) for _, p in self.routes)
        return _Pages.place(self.root, path) is not None


def _pages_folder(repo: Path) -> Path | None:
    """The folder of plain pages: the project's own top when a page is there, else the first built folder with a
    start page."""
    try:
        if any(f.suffix.lower() in PAGE_EXT and f.is_file() for f in repo.iterdir()):
            return repo
    except OSError:
        return None
    for name in BUILT:
        if (repo / name / "index.html").is_file():
            return repo / name
    return None


def _page_files(root: Path, repo: Path) -> list[str]:
    from .python_frontend import inside_repo, skipped
    found: list[str] = []
    for folder, dirs, files in os.walk(root):
        rel = Path(folder).relative_to(root)
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and not skipped([*rel.parts, d], root))
        for name in sorted(files):
            if Path(name).suffix.lower() in PAGE_EXT and inside_repo(Path(folder) / name, repo):
                found.append("/" + (rel / name).as_posix() if rel.parts else "/" + name)
        if len(found) > MOST_PAGES * 4:
            break
    found.sort(key=lambda p: (p != "/index.html", p.count("/"), p))
    return found[:MOST_PAGES]


def _site(repo: Path, g) -> Site | None:
    """What a run of the project at `repo` (its map `g`) opens, or None when there is nothing to open."""
    from . import behave_init, headers, readiness, websec
    found = behave_init.app_of(g)
    if found is not None:
        routes, gets = [], []
        for n in g.entry_points():
            detail = str((n.entry or {}).get("detail") or "")
            if (n.entry or {}).get("kind") != "route" or not n.id.startswith("py:") or " /" not in detail:
                continue
            verb, _, path = detail.partition(" ")
            routes.append((verb.upper(), _route_pattern(path)))
            if verb.upper() in ("GET", "ANY") and "{" not in path and path not in gets:
                gets.append(path)
        gets.sort(key=lambda p: (p != "/", p))
        texts: dict[str, list[str]] = {}

        def lines_for(file: str) -> list[str]:
            if file not in texts:
                from .python_frontend import project_text
                try:
                    texts[file] = project_text(repo / file, repo).splitlines()
                except OSError:
                    texts[file] = []
            return texts[file]

        logins = [r["detail"].partition(" ")[2] for r in websec.route_logins(g, lines_for)
                  if r.get("login") in ("shown", "lookup") and str(r.get("detail", "")).startswith("GET /")
                  and "{" not in r["detail"]]
        status, _, places, _ = headers.read(g, readiness.Repo(repo))
        named: list[str] = []
        if status == "in place":
            for place in places:
                file, _, line = place.rpartition(":")
                text = lines_for(file)
                if line.isdigit() and 0 < int(line) <= len(text):
                    for m in headers.NAMES.finditer(text[int(line) - 1]):
                        name = m.group(0).lower()
                        if name != "frame-ancestors" and name not in named \
                                and name not in (h.lower() for h in NOT_COMPARED):
                            named.append(name)
        return Site("app", repo, gets[:MOST_PAGES], logins=[p for p in logins if p in gets], headers=named,
                    routes=routes, app=found["app"], notes=list(found.get("notes") or []))
    folder = _pages_folder(repo)
    if folder is None:
        return None
    pages = _page_files(folder, repo)
    return Site("pages", folder, pages) if pages else None


def site_kind(repo: Path, g) -> str | None:
    """What a run of the project at `repo` (its map `g`) would open, as `_site` finds it, without opening anything
    or reading more of the code than that takes: `app`, `pages`, or None when there is nothing to open. The release
    decision asks it whether the project has a site that a browser must have opened (`release._browser`)."""
    from . import behave_init
    repo = Path(repo)
    if behave_init.app_of(g) is not None:
        return "app"
    folder = _pages_folder(repo)
    return "pages" if folder is not None and _page_files(folder, repo) else None


class _Pages:
    """A folder of plain pages, served by Lantern's own code: the project's own files only."""

    def __init__(self, root: Path, repo: Path):
        self.root, self.repo = root, repo

    @staticmethod
    def place(root: Path, path: str) -> Path | None:
        from .python_frontend import inside_repo
        parts = [p for p in urllib.parse.unquote(path).split("/") if p not in ("", ".")]
        if any(p == ".." or "\\" in p or "\0" in p or ":" in p for p in parts):
            return None
        place = root.joinpath(*parts)
        try:
            if place.is_dir() and not place.is_symlink():
                place = place / "index.html"
        except OSError:
            return None
        return place if inside_repo(place, root) else None

    def answer(self, method: str, target: str, headers, body: bytes, seconds: float):
        from .python_frontend import project_bytes
        if method not in ("GET", "HEAD"):
            return 405, [("Content-Type", "text/plain; charset=utf-8"), ("Allow", "GET, HEAD")], b"Method not allowed"
        path = urllib.parse.urlsplit(target).path
        place = self.place(self.root, path)
        if place is None:
            return 404, [("Content-Type", "text/html; charset=utf-8")], b"<!doctype html><title>Not found</title>"
        try:
            data = project_bytes(place, self.repo, MOST_FILE)
        except OSError:
            return 404, [("Content-Type", "text/html; charset=utf-8")], b"<!doctype html><title>Not found</title>"
        kind = TYPES.get(place.suffix.lower(), "application/octet-stream")
        return 200, [("Content-Type", kind), ("Cache-Control", "no-store")], b"" if method == "HEAD" else data


REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)   # Windows: a link or a junction


def _plain_folder(place: Path):
    """(device, number) of `place` when it is a folder and no link or junction, else None."""
    try:
        st = os.lstat(place)
    except OSError:
        return None
    if not stat.S_ISDIR(st.st_mode) or getattr(st, "st_file_attributes", 0) & REPARSE:
        return None
    return st.st_dev, st.st_ino


class _Box:
    """The project's app, started in the sealed box (`sandbox.run_inside` with `lantern._browse_inside`) and asked
    through a folder of the box's own: a request is a file Lantern puts in `in/`, its answer a file the box puts in
    `out/`. Lantern's side opens those two folders before the box starts and reads an answer only when it is a plain
    file of the box's own user, through no link. On Windows, where a folder is not held open by Lantern, each of the
    two is known by its number when it is made and looked at again before each use (`_folder`), and a request is
    written under a name of its own before it is put in place."""

    READY_SECONDS = 120         # the box is set up and the app imported and started in this time
    POLL = 0.005

    def __init__(self, repo: Path, spec: dict, port: int, log):
        self.repo, self.spec, self.port, self.log = repo, spec, port, log
        self.cancel = threading.Event()
        self.made = threading.Event()
        self.thread: threading.Thread | None = None
        self.result: dict | None = None
        self.failed: tuple[str, str] | None = None
        self.chan: Path | None = None
        self.fds: dict[str, int] = {}
        self.ids: dict[str, tuple | None] = {}
        self.n = 0
        self.lock = threading.Lock()
        self.owner = 65534 if hasattr(os, "geteuid") and os.geteuid() == 0 else (os.getuid() if hasattr(os, "getuid") else None)

    def _where(self, tmp: Path) -> None:
        chan = tmp / "browse"
        for part in ("in", "out"):
            (chan / part).mkdir(parents=True)
        if os.name == "posix":
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            self.fds = {part: os.open(chan / part, flags) for part in ("in", "out")}
        else:
            self.ids = {part: _plain_folder(chan / part) for part in ("in", "out")}
        self.chan = chan
        self.made.set()

    def _folder(self, part: str) -> Path:
        """`in` or `out` of the box's folder, still the folder Lantern made (Windows); OSError when it is not."""
        place = self.chan / part
        if self.ids.get(part) is None or _plain_folder(place) != self.ids[part]:
            raise OSError(f"the box's folder {part!r} is not the one Lantern made")
        return place

    def _run(self) -> None:
        from . import sandbox
        scene = {"app": self.spec, "site": {"host": "localhost", "port": self.port}}
        try:
            self.result = sandbox.run_inside(self.repo, "lantern._browse_inside", scene, log=self.log,
                                             timeout=max(sandbox.WALL_CLOCK, 1800), cancel=self.cancel,
                                             where=self._where)
        except sandbox.Unavailable as e:
            self.failed = ("no-sandbox", str(e)[:300])
        except Exception as e:  # noqa: BLE001 - whatever stopped the box, the app was not started
            self.failed = ("not-started", f"{type(e).__name__}: {e}"[:300])
        finally:
            self.made.set()

    def start(self) -> str | None:
        """Start the box and wait until the app says it started: None, or the reason it was not (`WHY_NOT`)."""
        self.thread = threading.Thread(target=self._run, daemon=True, name="lantern-browse-box")
        self.thread.start()
        end = time.monotonic() + self.READY_SECONDS
        while time.monotonic() < end:
            if self.failed:
                return self.failed[0]
            said = self._take("ready.json") if self.made.is_set() and self.chan is not None else None
            if said is not None:
                if said.get("ready") is True:
                    return None
                self.failed = ("not-started", str(said.get("error") or "")[:300])
                return "not-started"
            if not self.thread.is_alive():
                return (self.failed or ("not-started", ""))[0]
            time.sleep(0.05)
        self.failed = ("not-started", "the app did not start in time")
        return "not-started"

    def _put(self, name: str, data: dict) -> None:
        text = json.dumps(data).encode("utf-8")
        if "in" in self.fds:
            fd = os.open(name + ".part", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644,
                         dir_fd=self.fds["in"])
            try:
                os.write(fd, text)
            finally:
                os.close(fd)
            os.rename(name + ".part", name, src_dir_fd=self.fds["in"], dst_dir_fd=self.fds["in"])
        else:
            part = self._folder("in") / f"{name}.{secrets.token_hex(8)}.part"
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
            try:
                view = memoryview(text)
                while view:
                    view = view[os.write(fd, view):]
            finally:
                os.close(fd)
            os.replace(part, self._folder("in") / name)

    def _take(self, name: str) -> dict | None:
        """The answer under `name` in `out/`, read and removed, or None while there is none."""
        try:
            if "out" in self.fds:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fds["out"])
            else:
                where = self._folder("out") / name
                st = os.lstat(where)
                if not stat.S_ISREG(st.st_mode) or getattr(st, "st_file_attributes", 0) & REPARSE:
                    return None
                fd = os.open(where, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 64 << 20 \
                    or (self.owner is not None and os.name == "posix" and st.st_uid != self.owner):
                return None
            chunks, left = [], st.st_size + 1
            while left > 0:
                piece = os.read(fd, min(left, 1 << 20))
                if not piece:
                    break
                chunks.append(piece)
                left -= len(piece)
        finally:
            os.close(fd)
        try:
            if "out" in self.fds:
                os.unlink(name, dir_fd=self.fds["out"])
            else:
                os.unlink(self._folder("out") / name)
        except OSError:
            pass
        try:
            said = json.loads(b"".join(chunks))
        except ValueError:
            return {}
        return said if isinstance(said, dict) else {}

    def answer(self, method: str, target: str, headers, body: bytes, seconds: float):
        with self.lock:
            self.n += 1
            name = f"{self.n:08d}.json"
        self._put(name, {"method": method, "path": target, "headers": [[k, v] for k, v in headers],
                         "body": base64.b64encode(body).decode("ascii")})
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            said = self._take(name)
            if said is not None:
                try:
                    data = base64.b64decode(str(said.get("body") or ""))
                    status = int(said.get("status"))
                except (TypeError, ValueError):
                    return 500, [], b""
                heads = [(str(k), str(v)) for k, v in said.get("headers") or [] if isinstance(k, str)]
                return status, heads, data
            if self.thread is not None and not self.thread.is_alive():
                return None
            time.sleep(self.POLL)
        return None

    def stop(self) -> None:
        if self.chan is not None:
            try:
                self._put("stop.json", {})
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=10)
            if self.thread.is_alive():
                self.cancel.set()
                self.thread.join(timeout=60)
        for fd in self.fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds = {}


class _Door:
    """The browser's one way out: a door of Lantern's own on 127.0.0.1 that forwards nothing. Whatever reaches it
    (what the browser asks for itself, a request the browser did not show its pages) is refused and written down:
    the method and the computer it was for, never more."""

    MOST = 200

    def __init__(self):
        self.seen: list[dict] = []
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True, name="lantern-browse-door")
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 16384:
                piece = conn.recv(4096)
                if not piece:
                    break
                data += piece
            first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace").split(" ")
            if len(first) >= 2:
                method, target = first[0][:16], first[1]
                if method.upper() == "CONNECT":
                    host = target.rsplit(":", 1)[0]
                else:
                    host = urllib.parse.urlsplit(target).hostname or ""
                with self.lock:
                    if len(self.seen) < self.MOST:
                        self.seen.append({"method": method, "host": host[:200], "refused": True})
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ================================================================================================== the walk
OBSERVER = """(() => {
  const s = {changes: 0, last: performance.now()};
  Object.defineProperty(window, '__lantern', {value: s});
  new MutationObserver((list) => { s.changes += list.length; s.last = performance.now(); })
    .observe(document, {subtree: true, childList: true, attributes: true, characterData: true});
})();"""

MEASURE = """(() => {
  const b = document.body;
  let seen = !!(b && (b.innerText || '').trim());
  if (!seen) for (const e of document.querySelectorAll('img,svg,canvas,video,picture,iframe,object,embed,input,button,select,textarea')) {
    const r = e.getBoundingClientRect(); if (r.width > 1 && r.height > 1) { seen = true; break; } }
  return {seen, scripts: document.scripts.length};
})()"""

CONTROL_SEL = "a[href], area[href], button, input[type=button], input[type=submit], input[type=reset], input[type=image]"
# What a control is, asked the same way wherever it is asked: its kind, its words and, for a link, where it points
ABOUT_CONTROL = """(e) => ({tag: e.tagName.toLowerCase(),
  text: (e.innerText || e.value || e.getAttribute('aria-label') || '').trim().slice(0, 60),
  href: e.matches('a[href], area[href]') ? e.getAttribute('href') : null})"""
CONTROLS = """(() => { const about = %s;
  return Array.from(document.querySelectorAll(%s)).map((e, i) => {
  const d = about(e), link = d.href !== null;
  const r = e.getBoundingClientRect();
  const frag = link && e.hash ? decodeURIComponent(e.hash.slice(1)) : '';
  return {i, link, href: d.href, url: link ? e.href : null,
          inForm: !link && !!(e.form || e.closest('form')),
          shown: r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden',
          named: !!(frag && (document.getElementById(frag) || document.getElementsByName(frag).length)),
          tag: d.tag, text: d.text};
}); })()""" % (ABOUT_CONTROL, json.dumps(CONTROL_SEL))

# The control a click is for, on the page opened anew for the click: the one at its place when it is the same control
# (the same kind, words and address), else the one control of the page that is, else none. A page may differ from
# the one its controls were listed on: what a site keeps on its own server is not emptied between the steps
# (2026-11-22: until then the control at the same place was clicked whatever it was, and after a click that changed
# what the site keeps, the next click landed on another control).
POINT = """((i, want) => { const about = %s, all = Array.from(document.querySelectorAll(%s));
  const same = (e) => { const d = about(e); return d.tag === want.tag && d.text === want.text && d.href === want.href; };
  let e = all[i];
  if (!e || !same(e)) { const found = all.filter(same); e = found.length === 1 ? found[0] : null; }
  if (!e) return null;
  e.scrollIntoView({block: 'center', inline: 'center'}); const r = e.getBoundingClientRect();
  return {x: r.left + r.width / 2, y: r.top + r.height / 2, tag: e.tagName.toLowerCase()}; })""" % (
    ABOUT_CONTROL, json.dumps(CONTROL_SEL))

# What a form is, asked the same way wherever it is asked: where it is sent, how, and the names of its fields. Not
# what its fields hold: a hidden field often holds a token the site makes anew for each visit, and each step is one
ABOUT_FORM = """(f) => ({action: f.action, method: (f.getAttribute('method') || 'get').toLowerCase(),
  names: Array.from(f.elements).map(e => e.name || '').join('&')})"""

FORMS = """(() => { const about = %s;
  return Array.from(document.forms).map((f, i) => {
  const r = f.getBoundingClientRect(), d = about(f);
  return {i, action: d.action, method: d.method, names: d.names,
          shown: r.width > 0 && r.height > 0, id: f.id || '', fields: f.elements.length};
}); })()""" % ABOUT_FORM

# The form a sending is for, on the page opened anew (2026-11-22: until then the form at the same place among the
# page's forms was sent, whatever it was): the one at the same place when it is the same form (`ABOUT_FORM`), else the
# one form of the page that is, else none (null): Lantern cannot tell which it is, and sends nothing. Filled with
# made-up values by the kind of each field; gives the place of its submit button, or none, and the form's place.
FILL = """((i, want) => {
  const about = %s, all = Array.from(document.forms);
  const same = (g) => { const d = about(g); return d.action === want.action && d.method === want.method && d.names === want.names; };
  let f = all[i];
  if (!f || !same(f)) { const found = all.filter(same); f = found.length === 1 ? found[0] : null; }
  if (!f) return null;
  const at = all.indexOf(f);
  const kind = (el) => ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.labels && el.labels[0] ? el.labels[0].innerText : '')).toLowerCase();
  for (const el of Array.from(f.elements)) {
    if (el.disabled || el.readOnly) continue;
    const t = (el.type || '').toLowerCase(), n = kind(el);
    if (el.tagName === 'SELECT') { const o = Array.from(el.options).find(o => o.value !== '' && !o.disabled); if (o) el.value = o.value; }
    else if (['hidden', 'submit', 'button', 'reset', 'image', 'file'].includes(t)) continue;
    else if (t === 'checkbox') { if (el.required) el.checked = true; }
    else if (t === 'radio') { if (!Array.from(f.elements).some(o => o.type === 'radio' && o.name === el.name && o.checked)) el.checked = true; }
    else if (t === 'email' || /mail/.test(n)) el.value = 'ada@example.com';
    else if (t === 'number' || t === 'range') el.value = el.min || '1';
    else if (t === 'date') el.value = '2026-01-02';
    else if (t === 'time') el.value = '10:30';
    else if (t === 'datetime-local') el.value = '2026-01-02T10:30';
    else if (t === 'month') el.value = '2026-01';
    else if (t === 'week') el.value = '2026-W01';
    else if (t === 'color') el.value = '#336699';
    else if (t === 'tel' || /phone|tel/.test(n)) el.value = '555 0100';
    else if (t === 'url') el.value = location.origin + '/';
    else if (t === 'password') el.value = 'Made-up-password-1';
    else if (el.tagName === 'TEXTAREA') el.value = 'A short message from Lantern.';
    else if (/name/.test(n)) el.value = 'Ada Example';
    else el.value = 'Lantern';
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
  }
  const s = f.querySelector('button:not([type]), button[type=submit], input[type=submit], input[type=image]')
    || Array.from(document.querySelectorAll('button[form], input[form]')).find(b => b.form === f && ['submit', 'image'].includes(b.type));
  if (!s) return {submitter: false, at};
  s.scrollIntoView({block: 'center', inline: 'center'}); const r = s.getBoundingClientRect();
  return {submitter: true, at, x: r.left + r.width / 2, y: r.top + r.height / 2};
})""" % ABOUT_FORM

STYLE = """(e) => { const c = getComputedStyle(e); return [c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset,
  c.boxShadow, c.borderTopColor, c.borderTopWidth, c.borderBottomColor, c.borderBottomWidth, c.backgroundColor, c.color,
  c.textDecorationLine].join('|'); }"""

FOCUSABLES = """(() => {
  const style = %s;
  const sel = 'a[href], area[href], button, input:not([type=hidden]), select, textarea, iframe, summary, [tabindex], [contenteditable=""], [contenteditable=true]';
  if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur();
  const list = Array.from(document.querySelectorAll(sel)).filter(e => !e.disabled && e.tabIndex >= 0
    && e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden');
  Object.defineProperty(window, '__lanternFocus', {value: {list, reached: new Set(), last: null}, configurable: true});
  return list.map(e => ({style: style(e), tag: e.tagName.toLowerCase(),
    text: (e.innerText || e.value || e.getAttribute('aria-label') || e.getAttribute('name') || '').trim().slice(0, 60)}));
})()""" % STYLE

# Where the keyboard is after a press: the page's own place for it (`document.activeElement`), and inside a part with a
# tree of its own (an open shadow root) the control inside it. Tab moves on inside a frame, a player's controls and the
# parts of a date or time field while the page's place stays the same (`inside`).
AFTER_TAB = """(() => {
  const style = %s, F = window.__lanternFocus; const top = document.activeElement;
  let a = top;
  while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement;
  const body = !a || a === document.body || a === document.documentElement;
  const same = !body && a === F.last; F.last = body ? null : a;
  if (!body) { F.reached.add(a); F.reached.add(top); }
  const i = F.list.indexOf(top), tag = a ? a.tagName.toLowerCase() : '', type = a ? String(a.type || '').toLowerCase() : '';
  const inside = !body && (['iframe', 'frame', 'object', 'embed', 'portal'].includes(tag)
    || ((tag === 'video' || tag === 'audio') && a.controls)
    || (tag === 'input' && ['date', 'time', 'datetime-local', 'month', 'week'].includes(type)));
  return {i, body, same, inside, deep: a !== top, style: body ? null : style(a), tag};
})()""" % STYLE

# The place of the keyboard and every element above it, up through the hosts of trees of their own: whose listeners
# say whether the page's script can hold the keyboard there.
HOLDERS = """(() => { const out = []; let e = document.activeElement;
  while (e && e.shadowRoot && e.shadowRoot.activeElement) e = e.shadowRoot.activeElement;
  while (e && e.nodeType === 1) { out.push(e); const up = e.parentNode;
    e = up && up.nodeType === 11 ? up.host : up; }
  return out; })()"""
KEYISH = ("keydown", "keyup", "keypress", "focus", "blur", "focusin", "focusout")

# What this browser does when Tab is pressed on the last control of a page, seen once a run on a page of Lantern's own
# with two buttons and no script: the keyboard leaves the page, goes back to the first control, or stays.
PROBE = "data:text/html;charset=utf-8," + urllib.parse.quote(
    '<!doctype html><title>Lantern</title><button id="a">a</button> <button id="b">b</button>', safe="")
KEYBOARD_ENDS = ("leaves", "wraps", "stays")
MOST_PRESSES = 80               # Tab presses on one page

REACHED = """function () { const F = window.__lanternFocus; if (!F) return false;
  for (const r of F.reached) { if (r === this || this.contains(r) || r.contains(this)) return true; } return false; }"""

SHOWN = """function () { const r = this.getBoundingClientRect();
  return r.width > 0 && r.height > 0 && getComputedStyle(this).visibility !== 'hidden'; }"""

DESCRIBE = """function () { return {tag: this.tagName.toLowerCase(), id: this.id || '',
  text: (this.innerText || this.getAttribute('aria-label') || '').trim().slice(0, 60)}; }"""

CLICKISH = ("click", "mousedown", "mouseup", "pointerdown", "pointerup", "touchstart", "touchend", "auxclick", "dblclick")
LINKISH = ("link", "button", "menuitem", "tab")
FIELDISH = ("textbox", "searchbox", "combobox", "spinbutton", "checkbox", "radio", "slider", "switch", "listbox")
MOST_ELEMENTS = 3000            # elements of one page whose listeners are looked at
CLICK_SECONDS = 3.0             # what a click does shows in this time (a new page gets PAGE_SECONDS)
QUIET = 0.25                    # seconds with no request and no change to the page: the page has settled
# ... and nothing on it is still moving, by the browser's own list of its animations: a transition or an animation
# that ends (one that goes on for ever, a spinner, does not hold the page up). Until 2026-11-21 a page whose cover
# fades away as it opens was looked at, and clicked, while the cover was still there or after it had gone, which
# gave two runs on the same code two answers (Lantern's own landing page: its cover fades for 0.9 s).
SETTLED = """(() => { const s = window.__lantern; let moving = 0;
  for (const a of document.getAnimations()) {
    const t = a.playState === 'running' && a.effect ? a.effect.getComputedTiming() : null;
    if (t && isFinite(t.endTime)) moving += 1; }
  return {since: s ? performance.now() - s.last : null, moving}; })()"""
SCRIPT_KINDS = ("Script",)
SIGN_IN_COOKIE = re.compile(r"(?i)(?:^|[^a-z])(?:session|sess|sessid|sessionid|sid|auth|jwt|token|login|remember)"
                            r"(?:[^a-z]|$)|sessid$|sessionid$|^jsessionid$|^phpsessid$")


@dataclass
class _Tab:
    session: str
    target: str
    context: str | None = None          # the browser context made for this tab alone (`_Walk.fresh`)
    phase: tuple = ("idle",)
    frame: str | None = None
    url: str = ""
    world: int | None = None            # Lantern's own world in the page (its script cannot see the page's)
    main: int | None = None             # the page's own world, asked only through the browser's own calls
    worlds: set = field(default_factory=set)
    inflight: set = field(default_factory=set)
    last_net: float = 0.0
    loads: int = 0
    navigations: int = 0
    in_document: int = 0
    dialogs: int = 0
    windows: int = 0


class _Walk:
    def __init__(self, b, site: Site, server, page_seconds: float, origin: str, log):
        self.b, self.site, self.server, self.page_seconds = b, site, server, page_seconds
        self.origin = origin
        self.log = log
        self.lock = threading.Lock()
        self.tabs: dict[str, _Tab] = {}
        self.children: dict[str, _Tab] = {}
        self.targets: set[str] = set()
        self.answers: list[dict] = []
        self.errors: list[dict] = []
        self.outside: list[dict] = []
        self.asked: list[tuple] = []        # (phase, kind) of each request for the site, when it was stopped
        self.fetched: set[str] = set()
        self.pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="lantern-browse-answer")
        self.k = 0
        self.pages: list[dict] = []
        self.saw: dict[str, list[dict]] = {c.id: [] for c in CHECKS}
        self.looked: dict[str, int] = {c.id: 0 for c in CHECKS}
        self.not_clicked = 0                # controls not found again on the page opened anew for their click
        self.not_sent = 0                   # forms not found again on the page opened anew to be sent
        self.scripts = 0
        self.visitor_judged = 0
        self.keyboard_end = "unknown"
        self.shots: list[tuple[str, bytes]] = []    # (page, picture) of the first pages that showed something

    # ------------------------------------------------------------------------------------------- events
    def tab_of(self, session: str | None) -> _Tab | None:
        if session is None:
            return None
        return self.tabs.get(session) or self.children.get(session)

    def event(self, method: str, params: dict, session: str | None) -> None:
        tab = self.tab_of(session)
        now = time.monotonic()
        if method == "Fetch.requestPaused" and tab is not None:
            self._paused(tab, session, params)
        elif method == "Network.requestWillBeSent" and tab is not None:
            with self.lock:
                tab.inflight.add(params.get("requestId"))
                tab.last_net = now
            url = str((params.get("request") or {}).get("url") or "")
            if not self._ours(url) and urllib.parse.urlsplit(url).scheme in ("http", "https", "ws", "wss") \
                    and params.get("requestId") not in self.fetched:
                self._out(tab, url, str(params.get("type") or "Other"))
        elif method in ("Network.loadingFinished", "Network.loadingFailed") and tab is not None:
            with self.lock:
                tab.inflight.discard(params.get("requestId"))
                tab.last_net = now
        elif method == "Network.webSocketCreated" and tab is not None:
            url = str(params.get("url") or "")
            if not self._ours(url.replace("ws://", "http://", 1)):
                self._out(tab, url, "WebSocket")
        elif method == "Runtime.exceptionThrown" and tab is not None:
            d = params.get("exceptionDetails") or {}
            if d.get("executionContextId") in tab.worlds:
                return
            text = str((d.get("exception") or {}).get("description") or d.get("text") or "an error")
            self._error(tab, "raised", text.split("\n", 1)[0][:200])
        elif method == "Runtime.consoleAPICalled" and tab is not None:
            if params.get("type") != "error" or params.get("executionContextId") in tab.worlds:
                return
            args = params.get("args") or []
            text = " ".join(str(a.get("value", a.get("description", ""))) for a in args[:3])
            self._error(tab, "console", text[:200])
        elif method == "Runtime.executionContextCreated" and tab is not None and session in self.tabs:
            ctx = params.get("context") or {}
            aux = ctx.get("auxData") or {}
            if ctx.get("name") == "lantern":
                with self.lock:
                    tab.worlds.add(ctx.get("id"))
                    if aux.get("frameId") == tab.frame or tab.frame is None:
                        tab.world = ctx.get("id")
            elif aux.get("isDefault") and (aux.get("frameId") == tab.frame or tab.frame is None):
                with self.lock:
                    tab.main = ctx.get("id")
        elif method == "Page.frameNavigated" and tab is not None and session in self.tabs:
            frame = params.get("frame") or {}
            if not frame.get("parentId"):
                with self.lock:
                    tab.frame = frame.get("id")
                    tab.url = str(frame.get("url") or "")
                    tab.navigations += 1
                    tab.world = tab.main = None
        elif method == "Page.navigatedWithinDocument" and tab is not None:
            with self.lock:
                tab.in_document += 1
        elif method == "Page.loadEventFired" and tab is not None and session in self.tabs:
            with self.lock:
                tab.loads += 1
        elif method == "Page.javascriptDialogOpening" and tab is not None:
            with self.lock:
                tab.dialogs += 1
            self.b.send("Page.handleJavaScriptDialog", {"accept": False}, session)
        elif method == "Target.attachedToTarget" and tab is not None:
            child = params.get("sessionId")
            with self.lock:
                self.children[child] = tab
            self.b.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]}, child)
            self.b.send("Network.enable", {}, child)
            self.b.send("Runtime.runIfWaitingForDebugger", {}, child)
        elif method == "Target.targetCreated" and session is None:
            info = params.get("targetInfo") or {}
            if info.get("type") == "page" and info.get("openerId") and info.get("targetId") not in self.targets:
                self.b.send("Target.closeTarget", {"targetId": info.get("targetId")})
                for t in list(self.tabs.values()):
                    if t.target == info.get("openerId"):
                        with self.lock:
                            t.windows += 1

    def _ours(self, url: str) -> bool:
        return url == self.origin or url.startswith(self.origin + "/") or url.startswith(self.origin + "?")

    def _out(self, tab: _Tab, url: str, kind: str) -> None:
        parts = urllib.parse.urlsplit(url)
        address = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))[:300]
        with self.lock:
            self.outside.append({"tab": tab.session, "phase": tab.phase, "address": address,
                                 "host": (parts.hostname or "")[:200], "kind": kind})

    def _error(self, tab: _Tab, how: str, text: str) -> None:
        with self.lock:
            self.errors.append({"tab": tab.session, "phase": tab.phase, "how": how, "text": text})

    def _paused(self, tab: _Tab, session: str, params: dict) -> None:
        req = params.get("request") or {}
        url = str(req.get("url") or "")
        rid = params.get("requestId")
        kind = str(params.get("resourceType") or "Other")
        with self.lock:
            if params.get("networkId"):
                self.fetched.add(params.get("networkId"))
            phase = tab.phase
        if self._ours(url):
            with self.lock:
                self.asked.append((phase, kind))
            self.pool.submit(self._answer, tab, session, rid, req, kind, phase)
        elif urllib.parse.urlsplit(url).scheme in ("data", "blob", "about"):
            self.b.send("Fetch.continueRequest", {"requestId": rid}, session)
        else:
            self._out(tab, url, kind)
            self.b.send("Fetch.failRequest", {"requestId": rid, "errorReason": "BlockedByClient"}, session)

    def _answer(self, tab: _Tab, session: str, rid, req: dict, kind: str, phase: tuple) -> None:
        url = str(req.get("url") or "")
        parts = urllib.parse.urlsplit(url)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        entries = req.get("postDataEntries") or []
        if entries:
            body = b"".join(base64.b64decode(str(e.get("bytes") or "")) for e in entries)
        else:
            body = str(req.get("postData") or "").encode("utf-8")
        heads = [(str(k), str(v)) for k, v in (req.get("headers") or {}).items()]
        method = str(req.get("method") or "GET").upper()
        t0 = time.monotonic()
        try:
            got = self.server.answer(method, target, heads, body, self.page_seconds)
        except Exception as e:  # noqa: BLE001 - the site's side failed: no answer, said as such
            self.log(f"browse: a request could not be answered ({type(e).__name__})")
            got = None
        record = {"tab": tab.session, "phase": phase, "path": parts.path or "/", "kind": kind, "method": method,
                  "status": None, "headers": [], "seconds": round(time.monotonic() - t0, 3)}
        if got is not None:
            status, out_heads, data = got
            record["status"] = status if 100 <= int(status) <= 599 else 500
            record["headers"] = [(k, v) for k, v in out_heads]
        with self.lock:                     # written down before the page can see the answer
            self.answers.append(record)
        try:
            if got is None:
                self.b.send("Fetch.failRequest", {"requestId": rid, "errorReason": "TimedOut"}, session)
            else:
                self.b.send("Fetch.fulfillRequest", {"requestId": rid, "responseCode": record["status"],
                                                      "responseHeaders": [{"name": k, "value": v} for k, v in out_heads],
                                                      "body": base64.b64encode(data).decode("ascii")}, session)
        except Exception:  # noqa: BLE001 - the browser ended; the walk sees it
            pass

    # ------------------------------------------------------------------------------------------- tabs
    def open_tab(self, context: str | None) -> _Tab:
        params = {"url": "about:blank"}
        if context:
            params["browserContextId"] = context
        target = self.b.call("Target.createTarget", params)["targetId"]
        self.targets.add(target)
        session = self.b.call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        tab = _Tab(session, target)
        with self.lock:
            self.tabs[session] = tab
        for method, args in (("Page.enable", {}), ("Runtime.enable", {}), ("Network.enable", {}),
                             ("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]}),
                             ("Page.addScriptToEvaluateOnNewDocument", {"source": OBSERVER, "worldName": "lantern"}),
                             ("Emulation.setFocusEmulationEnabled", {"enabled": True}),
                             ("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True,
                                                       "flatten": True}),
                             ("Accessibility.enable", {})):
            self.b.call(method, args, session)
        return tab

    def close_tab(self, tab: _Tab) -> None:
        try:
            self.b.call("Target.closeTarget", {"targetId": tab.target})
        except Exception:  # noqa: BLE001 - a tab that is gone already
            pass

    def fresh(self) -> _Tab:
        """A tab in a browser context made for it alone, for one step of the walk (a page, a click, a form, the
        visitor), thrown away after it (`drop`): so each step is a first visit, and nothing an earlier step left in
        the browser is there (cookies, storage, the session's storage, databases, caches, the window's name). Until
        2026-11-22 every step of a run was made in one tab, and what a click had kept in the browser changed the pages
        of every step after it (the browser benchmark's first run: a task list that keeps its tasks in the browser,
        whose next click then landed on another button)."""
        from . import _cdp
        try:
            context = self.b.call("Target.createBrowserContext", {})["browserContextId"]
        except _cdp.CallError as e:
            raise _cdp.BrowserError("browser-failed", f"no browser context for a step ({e.message[:100]})") from e
        try:
            tab = self.open_tab(context)
        except _cdp.CallError as e:
            self._dispose(context)
            raise _cdp.BrowserError("browser-failed", f"no tab for a step ({e.message[:100]})") from e
        tab.context = context
        return tab

    def drop(self, tab: _Tab) -> None:
        """Throw the tab of one step away with its browser context, and everything the site kept in it."""
        with self.lock:
            self.tabs.pop(tab.session, None)
            for child in [s for s, t in self.children.items() if t is tab]:
                self.children.pop(child, None)
        if tab.context:
            self._dispose(tab.context)
        else:
            self.close_tab(tab)

    def _dispose(self, context: str) -> None:
        try:
            self.b.call("Target.disposeBrowserContext", {"browserContextId": context})
        except Exception:  # noqa: BLE001 - a browser that ended: the walk sees it at its next step
            pass

    def eval(self, tab: _Tab, expression: str, by_value: bool = True):
        if tab.world is None:
            return None
        try:
            r = self.b.call("Runtime.evaluate", {"expression": expression, "contextId": tab.world,
                                                 "returnByValue": by_value, "timeout": 5000, "objectGroup": "lantern"},
                            tab.session)
        except Exception:  # noqa: BLE001 - the page went away under the question
            return None
        if r.get("exceptionDetails"):
            return None
        res = r.get("result") or {}
        return res.get("value") if by_value else res

    def load(self, tab: _Tab, path: str, kind: str = "load") -> dict:
        """Open the page at `path` in `tab` and let it settle: {path, status, seconds, opened}."""
        with self.lock:
            self.k += 1
            phase = (kind, path, self.k)
            tab.phase = phase
            loads = tab.loads
            tab.world = tab.main = None
        t0 = time.monotonic()
        deadline = t0 + self.page_seconds
        error = None
        try:
            r = self.b.call("Page.navigate", {"url": self.origin + path}, tab.session, timeout=self.page_seconds + 15)
            error = r.get("errorText")
        except Exception as e:  # noqa: BLE001 - an answer that never came is the page's
            error = str(e)[:100]
        while time.monotonic() < deadline and not error:
            with self.lock:
                if tab.loads > loads and tab.world is not None:
                    break
            time.sleep(0.02)
        self.settle(tab, deadline)
        first = self.first_document(phase, path)
        status = first["status"] if first else None
        return {"path": path, "status": status, "seconds": round(time.monotonic() - t0, 3), "phase": phase,
                "error": error}

    def first_document(self, phase: tuple, path: str | None = None) -> dict | None:
        end = time.monotonic() + 1.0
        while True:
            with self.lock:
                found = [a for a in self.answers if a["phase"] == phase and a["kind"] == "Document"
                         and (path is None or a["path"] == path)]
            if found or time.monotonic() > end:
                return found[0] if found else None
            time.sleep(0.02)

    def settle(self, tab: _Tab, deadline: float) -> bool:
        while time.monotonic() < deadline:
            with self.lock:
                busy, last = bool(tab.inflight), tab.last_net
            net = not busy and time.monotonic() - last >= QUIET
            dom = True
            if net and tab.world is not None:
                now = self.eval(tab, SETTLED) or {}
                since = now.get("since")
                dom = (since is None or since >= QUIET * 1000) and not now.get("moving")
            if net and dom:
                return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------------------------------------------------- one page
    def page(self, path: str) -> None:
        """One page: opened, looked at and walked with the keyboard in a tab of its own; then each of its links and
        buttons clicked and each of its forms sent, each on the page opened anew in a tab of its own (`fresh`)."""
        tab = self.fresh()
        try:
            got = self.load(tab, path)
            self.pages.append({"path": path, "status": got["status"], "seconds": got["seconds"]})
            status = got["status"]
            self.looked["opens"] += 1
            if status is None:
                self.saw["opens"].append({"code": "no-answer", "page": path,
                                          "what": f"no answer came within {self.page_seconds:g} seconds"})
                return
            if status >= 500:
                self.saw["opens"].append({"code": "server-error", "page": path, "status": status,
                                          "what": f"the site answered {status}"})
                return
            if status == 404:
                self.saw["opens"].append({"code": "not-found", "page": path, "status": 404,
                                          "what": "the site answered \"not found\" for a page it says it has"})
                return
            if not 200 <= status < 300:
                return                  # a sign-in asked for (401, 403) or a move to another page: not broken
            measured = self.eval(tab, MEASURE) or {}
            self.scripts += int(measured.get("scripts") or 0)
            if measured and not measured.get("seen"):
                self.saw["opens"].append({"code": "empty", "page": path, "status": status,
                                          "what": "the page shows nothing that can be seen"})
            elif measured.get("seen") and len(self.shots) < pictures.MOST_PICTURES:
                self.picture(tab, path)
            controls = self.eval(tab, CONTROLS) or []
            forms = self.eval(tab, FORMS) or []
            self.keyboard(tab, path)
        finally:
            self.drop(tab)
        self.leads(path, controls)
        self.forms(path, forms)

    def picture(self, tab: _Tab, path: str) -> None:
        """A picture of the page as it settled, taken by the browser itself (`Page.captureScreenshot`), kept for the
        record with the others of this run (`pictures.keep`, on this computer only). A page that went away, an
        answer that is not a PNG picture or is too large: no picture, and nothing else changes."""
        try:
            r = self.b.call("Page.captureScreenshot", {"format": "png"}, tab.session, timeout=20)
            text = r.get("data") if isinstance(r, dict) else None
            if not isinstance(text, str) or len(text) > (pictures.MOST_BYTES // 3 + 1) * 4:
                return
            data = base64.b64decode(text, validate=True)
        except Exception:  # noqa: BLE001 - the page or the browser would not: no picture
            return
        if pictures.is_picture(data):
            self.shots.append((path, data))

    # ------------------------------------------------------------------------------------------- leads
    def leads(self, path: str, controls: list) -> None:
        clicks = missed = 0
        for c in controls:
            if not isinstance(c, dict) or not c.get("shown"):
                continue
            if c.get("link"):
                url = str(c.get("url") or "")
                parts = urllib.parse.urlsplit(url)
                if parts.scheme in ("mailto", "tel", "sms"):
                    continue
                self.looked["leads"] += 1
                if parts.scheme == "javascript" or (self._ours(url) and parts.path == path and not c.get("named")
                                                    and (url.split("#", 1)[0] == (self.origin + path) or "#" in url)):
                    if "#" not in url and parts.scheme != "javascript":
                        continue        # a link to this same page, which opens it again
                    if clicks < MOST_CLICKS:
                        clicks += 1
                        missed += not self.click(path, c, link=True)
                    continue
                if not self._ours(url):
                    continue            # another computer: not followed, not counted
                if not self.site.has(parts.path or "/"):
                    self.saw["leads"].append({"code": "dead-link", "page": path, "link": str(c.get("href"))[:200],
                                              "address": (parts.path or "/")[:200],
                                              "what": "a link to an address the site does not have"})
                continue
            if c.get("inForm"):
                continue                # a form's own buttons are the forms check's
            self.looked["leads"] += 1
            if clicks < MOST_CLICKS:
                clicks += 1
                missed += not self.click(path, c, link=False)
        if missed:
            self.looked["leads"] -= missed          # what was not clicked was not looked at
            self.not_clicked += missed
            self.log(f"browse: {missed} control(s) of {path[:200]} not found again on the page opened anew, "
                     "so not clicked")

    def _effect(self, tab: _Tab, before: dict, phase: tuple) -> dict:
        with self.lock:
            asked = sum(1 for a in self.answers if a["phase"] == phase) + \
                sum(1 for o in self.outside if o["phase"] == phase)
            raised = [e for e in self.errors if e["phase"] == phase and e["how"] == "raised"]
            moved = tab.navigations > before["navigations"]
            within = tab.in_document > before["in_document"]
            dialogs = tab.dialogs > before["dialogs"]
            windows = tab.windows > before["windows"]
        changes = None if moved else self.eval(tab, "window.__lantern.changes")
        changed = isinstance(changes, (int, float)) and changes > before.get("changes", 0)
        return {"asked": asked, "raised": raised, "moved": moved, "within": within, "dialogs": dialogs,
                "windows": windows, "changed": changed}

    def _before(self, tab: _Tab) -> dict:
        with self.lock:
            out = {"navigations": tab.navigations, "in_document": tab.in_document, "dialogs": tab.dialogs,
                   "windows": tab.windows}
        out["changes"] = self.eval(tab, "window.__lantern.changes") or 0
        return out

    def _press(self, tab: _Tab, x: float, y: float) -> None:
        for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
            args = {"type": kind, "x": x, "y": y}
            if kind != "mouseMoved":
                args.update(button="left", clickCount=1)
            self.b.call("Input.dispatchMouseEvent", args, tab.session, timeout=self.page_seconds + 10)

    def click(self, path: str, c: dict, link: bool) -> bool:
        """Click the control `c` on the page opened anew in a tab of its own and say what the click did. False when
        the control was not found again there (`POINT`): then nothing is clicked and nothing is said of it."""
        tab = self.fresh()
        try:
            return self._click(tab, path, c, link)
        finally:
            self.drop(tab)

    def _click(self, tab: _Tab, path: str, c: dict, link: bool) -> bool:
        got = self.load(tab, path, "reload")
        if got["status"] is None or not 200 <= got["status"] < 300:
            return True
        want = {"tag": c.get("tag"), "text": c.get("text"), "href": c.get("href")}
        point = self.eval(tab, f"({POINT})({int(c['i'])}, {json.dumps(want)})")
        if not isinstance(point, dict) or point.get("tag") != c.get("tag"):
            return False
        before = self._before(tab)
        with self.lock:
            self.k += 1
            phase = ("click", path, self.k)
            tab.phase = phase
        try:
            self._press(tab, float(point["x"]), float(point["y"]))
        except Exception:  # noqa: BLE001 - the page went away under the click
            return True
        time.sleep(0.15)
        self.settle(tab, time.monotonic() + CLICK_SECONDS)
        effect = self._effect(tab, before, phase)
        what = {"page": path, "control": f"<{c.get('tag')}> {c.get('text') or ''}".strip()[:100]}
        if effect["raised"]:
            self.saw["leads"].append({"code": "button-raises", **what,
                                      "what": "a click raised an error in the site's script: "
                                              + effect["raised"][0]["text"][:120]})
        elif not (effect["asked"] or effect["moved"] or effect["dialogs"] or effect["windows"] or effect["changed"]):
            if link:
                self.saw["leads"].append({"code": "empty-link", **what, "link": str(c.get("href"))[:200],
                                          "what": "a link that leads nowhere: the click changed nothing"
                                                  + (" but the part of the address after #" if effect["within"] else "")})
            else:
                self.saw["leads"].append({"code": "dead-button", **what,
                                          "what": "a button that does nothing when it is clicked"})
        return True

    # ------------------------------------------------------------------------------------------- forms
    def forms(self, path: str, forms: list) -> None:
        """Send each form of the page that is sent to the site, once, on the page opened anew in a tab of its own."""
        missed = 0
        for f in forms:
            if not isinstance(f, dict):
                continue
            if not self._ours(str(f.get("action") or "")):
                continue                # sent to another computer: not sent
            self.looked["forms"] += 1
            missed += not self.send(path, f)
        if missed:
            self.looked["forms"] -= missed          # what was not sent was not looked at
            self.not_sent += missed
            self.log(f"browse: {missed} form(s) of {path[:200]} not found again on the page opened anew, so not sent")

    def send(self, path: str, f: dict) -> bool:
        """Send the form `f` on the page opened anew in a tab of its own and say what came of it. False when the form
        was not found again there (`FILL`): then nothing is sent and nothing is said of it."""
        tab = self.fresh()
        try:
            return self._form(tab, path, f)
        finally:
            self.drop(tab)

    def _form(self, tab: _Tab, path: str, f: dict) -> bool:
        got = self.load(tab, path, "reload")
        if got["status"] is None or not 200 <= got["status"] < 300:
            return True
        with self.lock:
            self.k += 1
            phase = ("form", path, self.k)
            tab.phase = phase           # what filling the form sets off is the form's too
        want = {"action": f.get("action"), "method": f.get("method"), "names": f.get("names")}
        filled = self.eval(tab, f"({FILL})({int(f['i'])}, {json.dumps(want)})")
        if not isinstance(filled, dict) or not isinstance(filled.get("at"), int):
            return False
        try:
            if filled.get("submitter"):
                self._press(tab, float(filled["x"]), float(filled["y"]))
            else:
                self.eval(tab, f"document.forms[{int(filled['at'])}].requestSubmit()")
        except Exception:  # noqa: BLE001 - the page went away while the form was sent
            pass
        # the page the form was sent to: asked for within CLICK_SECONDS, then answered within a page's time
        sent_page = None
        deadline = time.monotonic() + CLICK_SECONDS
        while True:
            with self.lock:
                docs = [a for a in self.answers if a["phase"] == phase and a["kind"] == "Document"]
                asked = any(q == (phase, "Document") for q in self.asked)
            now = time.monotonic()
            if docs or (now >= deadline and not asked) or now >= deadline + self.page_seconds + 1:
                sent_page = docs[0] if docs else None
                break
            time.sleep(0.05)
        self.settle(tab, time.monotonic() + CLICK_SECONDS)
        with self.lock:
            raised = [e for e in self.errors if e["phase"] == phase and e["how"] == "raised"]
            fetched = [a for a in self.answers if a["phase"] == phase and a["kind"] in ("XHR", "Fetch")]
        what = {"page": path, "form": f"form {int(f['i']) + 1}" + (f" ({f.get('id')})" if f.get("id") else "")}
        statuses = ([sent_page["status"]] if sent_page and sent_page.get("status") is not None else []) + \
            [a["status"] for a in fetched if a.get("status") is not None]
        to = (sent_page or {}).get("path") or urllib.parse.urlsplit(str(f.get("action") or "")).path
        if any(s >= 500 for s in statuses):
            self.saw["forms"].append({"code": "form-error", **what, "address": to[:200],
                                      "status": next(s for s in statuses if s >= 500),
                                      "what": "the site answered the form with a server error"})
        elif any(s in (404, 405) for s in statuses):
            self.saw["forms"].append({"code": "form-nowhere", **what, "address": to[:200],
                                      "status": next(s for s in statuses if s in (404, 405)),
                                      "what": "the form is sent to an address the site does not have"})
        elif raised:
            self.saw["forms"].append({"code": "form-raises", **what,
                                      "what": "sending the form raised an error in the site's script: "
                                              + raised[0]["text"][:120]})
        return True

    # ------------------------------------------------------------------------------------------- keyboard
    def keyboard(self, tab: _Tab, path: str) -> None:
        with self.lock:
            self.k += 1
            tab.phase = ("keyboard", path, self.k)
        self.looked["keyboard"] += 1
        found = self._names(tab, path)
        focusables = self.eval(tab, FOCUSABLES) or []
        reached: set[int] = set()
        ringless: set[int] = set()
        left: set = set()               # where Tab stayed and Shift+Tab moved on: the keyboard can leave it
        budget, presses = len(focusables) + 2, 0
        while focusables and presses < min(budget, MOST_PRESSES):
            presses += 1
            now = self._tab(tab)
            if now is None:
                break
            i = now.get("i")
            if now.get("same"):
                if now.get("inside"):
                    budget += 1         # Tab moves on inside a frame, a player or a date field: one press more
                    continue
                key = (i, now.get("tag"))
                if key in left:
                    break               # back where Tab stays: the keyboard goes no further on this page
                held = self._held(tab, focusables)
                if held == "trapped":
                    found.append({"code": "trapped", "page": path, "control": self._said(focusables, i, now),
                                  "what": "Tab cannot leave this control"})
                    break
                if held == "browser":
                    break               # the browser itself keeps the keyboard there: nothing more to reach
                left.add(key)
                budget += 1
                continue
            if isinstance(i, int) and i >= 0:
                if i in reached:
                    continue
                reached.add(i)
                if not now.get("inside") and not now.get("deep") and now.get("style") == focusables[i].get("style") \
                        and i not in ringless:
                    ringless.add(i)
                    found.append({"code": "no-focus-ring", "page": path, "control": self._said(focusables, i, now),
                                  "what": "nothing shows where the keyboard is when this control is reached"})
        found += self._unreached(tab, path)
        self.saw["keyboard"] += found
        try:
            self.b.call("Runtime.releaseObjectGroup", {"objectGroup": "lantern"}, tab.session)
        except Exception:  # noqa: BLE001
            pass

    def _key(self, tab: _Tab, shift: bool = False) -> None:
        """Tab, or Shift+Tab, as the browser's own key events."""
        for kind in ("rawKeyDown", "keyUp"):
            args = {"type": kind, "key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9}
            if shift:
                args["modifiers"] = 8
            self.b.call("Input.dispatchKeyEvent", args, tab.session)

    def _tab(self, tab: _Tab, shift: bool = False) -> dict | None:
        """Press Tab (or Shift+Tab) and say where the keyboard went (`AFTER_TAB`); None when the page went away."""
        try:
            self._key(tab, shift)
        except Exception:  # noqa: BLE001 - the page went away under the key
            return None
        now = self.eval(tab, AFTER_TAB)
        return now if isinstance(now, dict) else None

    def _held(self, tab: _Tab, focusables: list) -> str:
        """Tab left the keyboard where it was. "left" when Shift+Tab moves it on (it can be left with the keyboard),
        "trapped" when Shift+Tab cannot move it either and the page's own script listens for keys or focus there or
        above it, else "browser": what this browser does by itself (on a page with one control, a browser that brings
        the keyboard back to the first control, or keeps it on the last, keeps it on that one)."""
        back = self._tab(tab, shift=True)
        if back is None:
            return "browser"
        if not back.get("same"):
            return "left"
        if len(focusables) == 1 and self.keyboard_end in ("wraps", "stays"):
            return "browser"
        return "trapped" if self._listens_for_keys(tab) else "browser"

    def _listens_for_keys(self, tab: _Tab) -> bool:
        """Does the page's own script listen for keys or focus where the keyboard is, above it, on the document or on
        the window? The elements are found in Lantern's world and handed to the page's own world by the browser's own
        calls (no script of the page runs for it), where its listeners are read."""
        with self.lock:
            main, world = tab.main, tab.world
        if main is None or world is None:
            return False
        targets: list[str] = []
        try:
            self.b.call("DOM.getDocument", {"depth": 0}, tab.session)
            chain = self.b.call("Runtime.evaluate", {"expression": HOLDERS, "contextId": world, "returnByValue": False,
                                                     "objectGroup": "lantern"}, tab.session)["result"]
            items = self.b.call("Runtime.getProperties", {"objectId": chain["objectId"], "ownProperties": True},
                                tab.session).get("result") or []
            for item in items:
                obj = (item.get("value") or {}).get("objectId")
                if not str(item.get("name", "")).isdigit() or not obj:
                    continue
                node = self.b.call("DOM.requestNode", {"objectId": obj}, tab.session)["nodeId"]
                theirs = self.b.call("DOM.resolveNode", {"nodeId": node, "executionContextId": main,
                                                         "objectGroup": "lantern"}, tab.session)["object"]["objectId"]
                targets.append(theirs)
            for name in ("document", "window"):
                r = self.b.call("Runtime.evaluate", {"expression": name, "contextId": main, "returnByValue": False,
                                                     "objectGroup": "lantern"}, tab.session)
                targets.append(r["result"]["objectId"])
        except Exception:  # noqa: BLE001 - a page that went away, or an element the browser did not hand over
            return False
        for target in targets:
            try:
                listeners = self.b.call("DOMDebugger.getEventListeners", {"objectId": target}, tab.session)
            except Exception:  # noqa: BLE001
                continue
            if any(item.get("type") in KEYISH for item in listeners.get("listeners") or []):
                return True
        return False

    def probe_keyboard(self) -> str:
        """What this browser does when Tab is pressed on the last control of a page (`KEYBOARD_ENDS`), on a page of
        Lantern's own with two buttons and no script; "unknown" when it could not be told."""
        tab = self.fresh()
        try:
            with self.lock:
                self.k += 1
                tab.phase = ("probe", "", self.k)
                loads = tab.loads
            self.b.call("Page.navigate", {"url": PROBE}, tab.session, timeout=self.page_seconds + 15)
            deadline = time.monotonic() + self.page_seconds
            while time.monotonic() < deadline:
                with self.lock:
                    if tab.loads > loads and tab.world is not None:
                        break
                time.sleep(0.02)
            if self.eval(tab, "document.activeElement && document.activeElement.blur(), document.title") != "Lantern":
                return "unknown"
            seen = []
            for _ in range(3):
                self._key(tab)
                seen.append(self.eval(tab, "(() => { const a = document.activeElement; "
                                           "return a && a !== document.body ? String(a.id) : ''; })()"))
        except Exception:  # noqa: BLE001 - the browser did not let the page be opened or the keys be pressed
            return "unknown"
        finally:
            self.drop(tab)
        if seen[:2] != ["a", "b"]:
            return "unknown"
        return {"": "leaves", "a": "wraps", "b": "stays"}.get(seen[2], "unknown")

    @staticmethod
    def _said(focusables: list, i, now: dict) -> str:
        if isinstance(i, int) and 0 <= i < len(focusables):
            f = focusables[i]
            return f"<{f.get('tag')}> {f.get('text') or ''}".strip()[:100]
        return f"<{now.get('tag') or '?'}>"

    def _names(self, tab: _Tab, path: str) -> list[dict]:
        out: list[dict] = []
        try:
            nodes = self.b.call("Accessibility.getFullAXTree", {}, tab.session).get("nodes") or []
        except Exception:  # noqa: BLE001 - a page whose tree the browser did not give
            return out
        for n in nodes[:20000]:
            if n.get("ignored"):
                continue
            role = str((n.get("role") or {}).get("value") or "")
            name = str((n.get("name") or {}).get("value") or "").strip()
            if name or role not in LINKISH + FIELDISH:
                continue
            control = self._node(tab, n.get("backendDOMNodeId"))
            if role in LINKISH:
                out.append({"code": "no-name", "page": path, "control": control,
                            "what": f"a {role} with no name the browser can tell"})
            else:
                out.append({"code": "no-label", "page": path, "control": control,
                            "what": "a form field with no label"})
        return out

    def _node(self, tab: _Tab, backend) -> str:
        try:
            node = self.b.call("DOM.describeNode", {"backendNodeId": backend}, tab.session).get("node") or {}
        except Exception:  # noqa: BLE001
            return "<?>"
        attrs = node.get("attributes") or []
        pairs = dict(zip(attrs[0::2], attrs[1::2]))
        bits = [str(node.get("localName") or node.get("nodeName") or "?").lower()]
        for key in ("id", "name", "type"):
            if pairs.get(key):
                bits.append(f'{key}="{str(pairs[key])[:40]}"')
        return ("<" + " ".join(bits) + ">")[:100]

    def _unreached(self, tab: _Tab, path: str) -> list[dict]:
        """What answers a click, can be seen, and was not reached with Tab. The elements are listed by the browser's
        own calls (no script of the page runs for it), their listeners read in the page's own world, where its script
        put them, and whether they can be seen and whether Tab reached them in Lantern's world, where the walk wrote
        it down."""
        out: list[dict] = []
        with self.lock:
            main, world = tab.main, tab.world
        if main is None or world is None:
            return out
        try:
            root = self.b.call("DOM.getDocument", {"depth": 0}, tab.session)["root"]["nodeId"]
            nodes = self.b.call("DOM.querySelectorAll", {"nodeId": root, "selector": "body *"},
                                tab.session).get("nodeIds") or []
        except Exception:  # noqa: BLE001 - a page whose elements the browser did not list
            return out
        for node in nodes[:MOST_ELEMENTS]:
            try:
                theirs = self.b.call("DOM.resolveNode", {"nodeId": node, "executionContextId": main,
                                                         "objectGroup": "lantern"}, tab.session)["object"]["objectId"]
                listeners = self.b.call("DOMDebugger.getEventListeners", {"objectId": theirs}, tab.session)
            except Exception:  # noqa: BLE001
                continue
            if not any(item.get("type") in CLICKISH for item in listeners.get("listeners") or []):
                continue
            try:
                obj = self.b.call("DOM.resolveNode", {"nodeId": node, "executionContextId": world,
                                                      "objectGroup": "lantern"}, tab.session)["object"]["objectId"]
                shown = self.b.call("Runtime.callFunctionOn", {"objectId": obj, "functionDeclaration": SHOWN,
                                                               "returnByValue": True}, tab.session)
                if (shown.get("result") or {}).get("value") is not True:
                    continue            # hidden: nobody can click it either
                r = self.b.call("Runtime.callFunctionOn", {"objectId": obj, "functionDeclaration": REACHED,
                                                           "returnByValue": True}, tab.session)
                reached = (r.get("result") or {}).get("value")
                if reached is not False:
                    continue
                d = self.b.call("Runtime.callFunctionOn", {"objectId": obj, "functionDeclaration": DESCRIBE,
                                                           "returnByValue": True}, tab.session)
                info = (d.get("result") or {}).get("value") or {}
            except Exception:  # noqa: BLE001
                continue
            control = f"<{info.get('tag') or '?'}" + (f' id="{info["id"][:40]}"' if info.get("id") else "") + "> " \
                + str(info.get("text") or "")
            out.append({"code": "not-reached", "page": path, "control": control.strip()[:100],
                        "what": "it answers a click and cannot be reached with Tab"})
        return out

    # ------------------------------------------------------------------------------------------- visitor
    def visitor(self) -> None:
        for path in self.site.logins:
            tab = self.fresh()
            try:
                got = self.load(tab, path, "visitor")
                status = got["status"]
                if status is None:
                    continue
                self.visitor_judged += 1
                if status in (401, 403) or 300 <= status < 400 or not 200 <= status < 300:
                    continue
                with self.lock:
                    url = tab.url
                password = self.eval(tab, "!!document.querySelector('input[type=password]')")
                if urllib.parse.urlsplit(url).path == path and password is False:
                    self.saw["visitor"].append({"code": "let-in", "page": path, "status": status,
                                                "what": "a visitor who is not signed in was let in"})
            finally:
                self.drop(tab)

    # ------------------------------------------------------------------------------------------- the walk
    def walk(self) -> None:
        self.keyboard_end = self.probe_keyboard()
        for path in self.site.pages:
            self.page(path)
        if self.site.how == "app":
            self.visitor()

    # ------------------------------------------------------------------------------------------- judging
    def judge(self) -> list[dict]:
        with self.lock:
            answers, errors, outside = list(self.answers), list(self.errors), list(self.outside)
        checks: dict[str, dict] = {}

        # the pages where a script from another computer was refused while the page loaded
        refused_on = {o["phase"][1] for o in outside
                      if o["phase"][0] in ("load", "reload") and o["kind"] in SCRIPT_KINDS}

        def put(check: str, outcome: str, why: str | None = None) -> None:
            saw = self.saw[check]
            for row in saw:
                if row["code"] in UNDECIDED.get(check, ()) and row.get("page") in refused_on:
                    row["undecided"] = True
            counted = [row for row in saw if not row.get("undecided")]
            if counted:
                outcome, why = "broken", None
            elif saw:
                outcome, why = "inconclusive", UNDECIDED_WHY
            checks[check] = {"id": check, "outcome": outcome, "codes": sorted({row["code"] for row in counted}),
                             "saw": saw[:200], "why": why}

        put("opens", "held")
        # the page's own script: what it raised or wrote as an error while each page loaded the first time
        first = [e for e in errors if e["phase"][0] == "load"]
        not_loaded = [a for a in answers if a["phase"][0] == "load" and a["kind"] in SCRIPT_KINDS
                      and (a["status"] is None or a["status"] >= 400)]
        for e in first:
            self.saw["script"].append({"code": "raised" if e["how"] == "raised" else "console-error",
                                       "page": e["phase"][1], "what": e["text"]})
        for a in not_loaded:
            self.saw["script"].append({"code": "not-loaded", "page": a["phase"][1], "address": a["path"][:200],
                                       "status": a["status"], "what": "a script the page names is not on the site"})
        self.saw["script"] = _unique(self.saw["script"])
        if not self.scripts and not self.saw["script"]:
            put("script", "nothing-to-check", "the pages have no script")
        else:
            put("script", "held")
        self.saw["leads"] = _unique(self.saw["leads"])
        if self.looked["leads"]:
            put("leads", "held", not_clicked(self.not_clicked) if self.not_clicked else None)
        elif self.not_clicked:
            put("leads", "inconclusive", not_clicked(self.not_clicked))     # it clicked nothing it was to click
        else:
            put("leads", "nothing-to-check", "the pages have no link or button")
        self.saw["forms"] = _unique(self.saw["forms"])
        if self.looked["forms"]:
            put("forms", "held", not_sent(self.not_sent) if self.not_sent else None)
        elif self.not_sent:
            put("forms", "inconclusive", not_sent(self.not_sent))          # it sent none of what it was to send
        else:
            put("forms", "nothing-to-check", "the pages have no form sent to the site")
        if self.site.how != "app" or not self.site.logins:
            put("visitor", "nothing-to-check", "no page asks for a sign-in")
        else:
            put("visitor", "held" if self.visitor_judged else "nothing-to-check",
                None if self.visitor_judged else "no page that asks for a sign-in answered")
        if self.site.how != "app":
            checks["protections"] = {"id": "protections", "outcome": "not-run", "codes": [], "saw": [],
                                     "why": "hosting-unknown"}
        else:
            cookies = 0
            for a in answers:
                if a["status"] is None:
                    continue
                names = {k.lower() for k, _ in a["headers"]}
                if a["kind"] == "Document" and a["status"] < 500:
                    for h in self.site.headers:
                        if h not in names:
                            self.saw["protections"].append({"code": "said-not-sent", "page": a["path"][:200],
                                                            "header": h, "status": a["status"],
                                                            "what": f"the code sets {h} for every response, and this "
                                                                    "page came without it"})
                for k, v in a["headers"]:
                    if k.lower() != "set-cookie":
                        continue
                    name, _, rest = v.partition("=")
                    name = name.strip()
                    if not SIGN_IN_COOKIE.search(name):
                        continue
                    cookies += 1
                    flags = {p.strip().split("=", 1)[0].lower() for p in rest.split(";")[1:]}
                    if "httponly" not in flags:
                        self.saw["protections"].append({"code": "cookie-open", "page": a["path"][:200],
                                                        "cookie": name[:60],
                                                        "what": "a sign-in cookie is set without HttpOnly, so the "
                                                                "page's script can read it"})
            self.saw["protections"] = _unique(self.saw["protections"])
            nothing = not self.site.headers and not cookies
            put("protections", "nothing-to-check" if nothing else "held",
                "the code sets no security header for every response, and no sign-in cookie was set" if nothing else None)
        for o in outside:
            self.saw["outside"].append({"code": "outside-script" if o["kind"] in SCRIPT_KINDS else "outside-file",
                                        "page": o["phase"][1] if len(o["phase"]) > 1 else "",
                                        "address": o["address"], "kind": o["kind"].lower(),
                                        "what": "the page asked another computer for it, and Lantern refused"})
        self.saw["outside"] = _unique(self.saw["outside"])
        put("outside", "held")
        self.saw["keyboard"] = _unique(self.saw["keyboard"])
        put("keyboard", "held" if self.looked["keyboard"] else "nothing-to-check")
        return [checks[c.id] for c in CHECKS]

    def asked_outside(self) -> list[dict]:
        with self.lock:
            outside = list(self.outside)
        seen, out = set(), []
        for o in outside:
            page = o["phase"][1] if len(o["phase"]) > 1 else ""
            key = (o["address"], page)
            if key in seen:
                continue
            seen.add(key)
            out.append({"address": o["address"], "host": o["host"], "kind": o["kind"].lower(), "page": page,
                        "refused": True})
        return out


# ================================================================================================== the report
VIEW_ROWS = 3          # what one check saw, shown in the report (the record keeps up to 200)
VIEW_KEYS = 8          # fields of one such row
VIEW_TEXT = 300        # characters of one value


def view(record, code_sha256: str | None, privacy: str = "full") -> dict | None:
    """What the report shows of the record `lantern browse` left in the results folder (`report.write_report`; the
    card "What the browser saw" on the Advanced readiness page). None when there is no record, or when it does not
    carry this computer's seal or is of other code than `code_sha256`: the release decision says why it does not
    count (`release._browser`), and nothing of it is shown. Otherwise the browser, how many pages were opened, and
    each check with its outcome, its codes, Lantern's own reason and, unless `privacy` is `structure` (the rows hold
    the site's own text: addresses, console lines, the names of controls), the first rows it saw. Only values of the
    shapes Lantern writes are taken, each cut to a bounded length; the viewer escapes every one."""
    from . import release, seal
    if not isinstance(record, dict) or not seal.holds(record):
        return None
    of = record.get("of") if isinstance(record.get("of"), dict) else {}
    if not isinstance(code_sha256, str) or not code_sha256 or of.get("code_sha256") != code_sha256:
        return None

    def text(v, n: int = VIEW_TEXT) -> str | None:
        return v[:n] if isinstance(v, str) else None

    def reason(v) -> str | None:
        return WHY_NOT[v] if isinstance(v, str) and v in WHY_NOT else text(v)

    b = record.get("browser") if isinstance(record.get("browser"), dict) else {}
    named = " ".join(x for x in (text(b.get("name"), 60), text(b.get("version"), 40)) if x)
    if record.get("ran") is not True:
        return {"ran": False, "why": reason(record.get("why_not")), "browser": named or None}
    seconds = record.get("seconds")
    out: dict = {"ran": True, "why": None, "browser": named or None,
                 "pages": len(record["opened"]) if isinstance(record.get("opened"), list) else 0,
                 "seconds": seconds if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) else None,
                 "pictures": len(pictures.listed(record)[1]), "checks": []}
    got = {}
    for c in record.get("checks") if isinstance(record.get("checks"), list) else []:
        if isinstance(c, dict) and isinstance(c.get("id"), str) and c["id"] in BY_ID and c["id"] not in got:
            got[c["id"]] = c
    for check in CHECKS:
        c = got.get(check.id)
        if c is None or c.get("outcome") not in OUTCOMES:
            continue
        codes = [k for k in c.get("codes") or [] if isinstance(k, str) and k in check.codes] \
            if isinstance(c.get("codes"), list) else []
        row = {"id": check.id, "title": check.title, "outcome": c["outcome"], "codes": codes,
               "why": reason(c.get("why")), "blocks": check.id in release.BROWSER_BLOCKS}
        if privacy == "full":
            seen = []
            for s in (c.get("saw") if isinstance(c.get("saw"), list) else [])[:VIEW_ROWS]:
                if isinstance(s, dict):
                    seen.append({k: text(v) if isinstance(v, str) else v for k, v in list(s.items())[:VIEW_KEYS]
                                 if isinstance(k, str) and len(k) <= 40
                                 and (isinstance(v, (str, bool)) or (isinstance(v, int) and not isinstance(v, bool)))})
            row["saw"] = seen
        out["checks"].append(row)
    return out


def _unique(saw: list[dict]) -> list[dict]:
    seen, out = set(), []
    for s in saw:
        key = json.dumps(s, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


# ================================================================================================== the run
def _not_run(why: str, **more) -> dict:
    return {"ran": False, "why_not": why, "why": WHY_NOT[why], **more,
            "checks": [{"id": c.id, "outcome": "not-run", "codes": [], "saw": [], "why": why} for c in CHECKS]}


def _own_sandbox(b) -> tuple[bool, str]:
    """Does the browser keep its own sandbox: on Linux its own page about it must say so, in its own words; on the
    other systems the browser cannot run without it unless it is told to, which Lantern never does."""
    if not sys.platform.startswith("linux"):
        return True, "the browser was not told to switch its sandbox off, which it cannot do by itself here"
    target = b.call("Target.createTarget", {"url": "about:blank"})["targetId"]
    try:
        session = b.call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        b.call("Page.navigate", {"url": "chrome://sandbox"}, session)
        text = ""
        end = time.monotonic() + 10
        while time.monotonic() < end:
            r = b.call("Runtime.evaluate", {"expression": "document.body ? document.body.innerText : ''",
                                            "returnByValue": True}, session)
            text = str((r.get("result") or {}).get("value") or "")
            if "sandboxed" in text:
                break
            time.sleep(0.1)
        ok = "You are adequately sandboxed." in text
        return ok, "the browser's own page about its sandbox: " + ("adequately sandboxed" if ok else "not sandboxed")
    finally:
        try:
            b.call("Target.closeTarget", {"targetId": target})
        except Exception:  # noqa: BLE001
            pass


def run(repo, *, browser: str | None = None, page_seconds: float = PAGE_SECONDS, log=None,
        out: Path | None = None) -> dict:
    """Open the site of the project at `repo` in a browser and give the record (docs/browser.md, "What comes out").
    `browser`: the browser's full path; None looks for one (`find_browser`). `page_seconds`: how long a page has to
    answer and settle. `out`: the results folder the record goes to, which is not part of the code the record says
    it was made on when it lies in the project. Never raises for what the project, its pages or the browser do: a
    run that could not be made says why (`ran` false, `why_not`).

    Every record says which code it is of (`of.code_sha256`: `release.code_digest` over the project's files, taken
    before anything is opened) and carries this computer's seal (`seal.py`), whatever came out: the release decision
    counts a record only for exactly this code and only with that seal (`release._browser`), because the results
    folder usually lies in the project, and a project can bring a record of its own that says every check held."""
    from . import __version__, gitfacts, release, seal
    log = log or (lambda line: None)
    repo = Path(repo).resolve()
    git = gitfacts.info(repo)
    of = {"commit": git.get("commit"), "dirty": git.get("dirty"), "lantern": __version__,
          "code_sha256": release.code_digest(repo, leave_out=out)["sha256"]}
    record = _run(repo, of, browser, page_seconds, log)
    made = seal.sign(record)
    if made is None:
        log("browse: this record carries no seal (LANTERN_HOME cannot be written), so a release decision will not "
            "count it")
    else:
        record["seal"] = made
    return record


def _run(repo: Path, of: dict, browser: str | None, page_seconds: float, log) -> dict:
    """The run itself, for `run`: the record without its seal."""
    from . import _cdp, engine
    found = (os.path.normpath(browser) if _program(browser) else None) if browser else find_browser()
    log(f"browser {found or 'none found'}")
    if found is None:
        return _not_run("no-browser", of=of)
    if not sys.platform.startswith(BUILT_FOR):
        return _not_run("not-built", of=of)
    t0 = time.monotonic()
    site = _site(repo, engine.build_graph(repo))
    if site is None:
        return _not_run("no-site", of=of)
    port = 20000 + secrets.randbelow(40000)
    origin = f"http://localhost:{port}"
    record: dict = {"of": of, "ran": False, "why_not": None, "browser": None,
                    "site": {"how": site.how, "address": origin, "pages": len(site.pages)}}
    door = _Door()
    box = None
    b = None
    walk = None
    try:
        if site.how == "app":
            box = _Box(repo, site.app or {}, port, log)
            why = box.start()
            if why:
                detail = (box.failed or ("", ""))[1]
                log(f"browse: the app was not started ({detail})" if detail else "browse: the app was not started")
                return {**_not_run(why, of=of), "site": record["site"]}
            server = box
        else:
            server = _Pages(site.root, repo)
        holder: dict = {}
        b = _cdp.Browser(found, door.port, events=lambda m, p, s: holder["walk"].event(m, p, s) if "walk" in holder
                         else None, log=log)
        try:
            version = b.start()
        except _cdp.BrowserError as e:
            log(f"browse: the browser could not be used ({e.why})")
            return {**_not_run(e.why if e.why in WHY_NOT else "browser-failed", of=of), "site": record["site"]}
        product = str(version.get("product") or "")
        name, _, number = product.partition("/")
        own, how = _own_sandbox(b)
        record["browser"] = {"name": name or None, "version": number or None, "own_sandbox": own, "how": how}
        if not own:
            return {**_not_run("no-browser-sandbox", of=of), "site": record["site"], "browser": record["browser"]}
        b.call("Browser.setDownloadBehavior", {"behavior": "deny"})
        b.call("Target.setDiscoverTargets", {"discover": True})
        walk = _Walk(b, site, server, page_seconds, origin, log)
        holder["walk"] = walk
        walk.walk()
        record["browser"]["keyboard_end"] = walk.keyboard_end
        record.update(ran=True, opened=walk.pages, checks=walk.judge(), asked_outside=walk.asked_outside())
    except _cdp.BrowserError as e:
        log(f"browse: the browser stopped ({e.why})")
        return {**_not_run("browser-failed", of=of), "site": record["site"], "browser": record["browser"]}
    finally:
        if walk is not None:
            walk.pool.shutdown(wait=False, cancel_futures=True)
        if b is not None:
            b.close()
        if box is not None:
            box.stop()
        door.close()
    with door.lock:
        record["browser_own"] = list(door.seen)
    record["pictures"] = pictures.keep(walk.shots if walk is not None else [])   # on this computer only
    if walk is not None:
        walk.shots = []
    record["seconds"] = round(time.monotonic() - t0, 3)
    if site.notes:
        record["notes"] = site.notes[:10]
    return record
