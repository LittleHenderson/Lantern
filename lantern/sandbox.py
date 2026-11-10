"""Test sandbox for "Watch my tests run" (and the terminal's `trace`).

Lantern reads code and never runs it, with one exception the user asks for: running the project's own tests so the
map can mark the calls that really happen. Those tests run here, never in the project folder as the user:

* **Docker** when the daemon answers (`docker info`) on a Linux computer: a per-language image pinned by digest, the
  project mounted read-only at `/app`, a writable tmpfs at `/tmp`, `--network none`, `--cpus 2 --memory 2g`, a
  non-root user, no capabilities, a 10-minute wall clock. Python tests use the packages already installed in the
  Python that runs Lantern (mounted read-only), so nothing is downloaded. On macOS and Windows those packages are
  not Linux packages, so the restricted subprocess below is used instead.
* **Restricted subprocess** otherwise: a fresh, read-only temp copy of the project; the environment rebuilt from an
  allow-list (PATH, HOME=a temp folder, locale, the runtime's own variables) so no secrets are inherited; resource
  limits on POSIX (CPU, file size, memory for Python) and a Job Object on Windows (memory, kill on close); on Linux a
  Landlock rule set that allows writes only inside the sandbox's temp folder and denies TCP connect/bind; for Python a
  start-up audit hook that refuses writes outside the temp folder and any network socket, on every OS; when Lantern
  runs as root the tests run as `nobody`.

Nothing the tests start outlives them (2026-11-10). When the test command ends, at the wall clock, when the caller
asks (`cancel`, the app's Stop) and when Lantern itself ends, every process it started is ended too: on Linux by the
launcher, which stays as their supervisor and finds them in /proc whatever session or process group they moved to
(`lantern._jail`); on Windows by the Job Object, which the process is put in before it runs (`lantern.winjob`);
elsewhere through the process group. What could not be ended is said in the log, never passed over.

If the sandbox cannot be set up, the tests are not run (`Unavailable`): the Job Object on Windows, Landlock where
the kernel has it, the change to `nobody`, the copy, and for Python the guard above (checked from inside the tests'
Python before the first test is imported). Reading the code needs none of this, so the analysis carries on
(`pipeline.analyze` records why the tests did not run). Before, each of these failed without a word and the tests
ran anyway.

Both backends print `LANTERN-SANDBOX-BLOCKED: <what>` when a test tries to write outside its temp folder or open a
network connection; `blocked` in the result lists them so the app can say why the tests failed.

Python tests run under `lantern.tracehook`; their call pairs are mapped back to the project's own paths and merged
by `trace.merge_trace` exactly as `lantern trace` does. JavaScript, Go, Rust and Java tests run in the same sandbox,
but their calls are not recorded yet: the map upgrades for Python only for now.
Nothing here can create, close or re-rank a finding: the result is call pairs and an exit code.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shlex
import shutil
import signal
import site
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

WALL_CLOCK = 600          # seconds; the directive's 10 minutes
MARK = "LANTERN-SANDBOX-BLOCKED:"
JS_NOTE = "Tests run; your map upgrades for Python only for now."

# Images pinned by digest (multi-arch index digests, Docker Hub). Bump together with a check that they still pull.
IMAGES = {
    "python3.11": "python:3.11-slim-bookworm@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd",
    "python3.12": "python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337",
    "python3.13": "python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f",
    "node": "node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da",
    "go": "golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db",
    "rust": "rust:1-slim-bookworm@sha256:24707e70a4f1e23d9a7b25202ec43126d28a52294b96aad5c670df1fd1f1d400",
    "java": "maven:3-eclipse-temurin-21@sha256:__MAVEN__",
}

# What the copy leaves out: version control, Lantern's own results, caches and virtualenvs (absolute paths inside a
# venv would point back at the original anyway).
SKIP = {".git", ".hg", ".svn", ".lantern", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv",
        "venv", ".tox", ".nox", "target", ".gradle", ".next", ".turbo", ".cache"}


# ---------------------------------------------------------------------------- which command
def _read_json(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _js_command(pkg: Path) -> tuple[str, str] | None:
    d = _read_json(pkg)
    script = (d.get("scripts") or {}).get("test") if isinstance(d.get("scripts"), dict) else None
    deps = {**(d.get("dependencies") or {}), **(d.get("devDependencies") or {})} if isinstance(d.get("devDependencies") or {}, dict) else {}
    root = pkg.parent
    pm = "pnpm" if (root / "pnpm-lock.yaml").exists() else "yarn" if (root / "yarn.lock").exists() else "npm"
    if isinstance(script, str) and script.strip() and "no test specified" not in script:
        return f"{pm} test", f"{pkg.parent.name}/package.json scripts.test" if pkg.parent.name else "package.json scripts.test"
    for tool, cmd in (("vitest", "npx vitest run"), ("jest", "npx jest"), ("mocha", "npx mocha")):
        if tool in deps:
            return cmd, f"{tool} in package.json"
    return None


def detect(repo: Path) -> dict:
    """The command the sheet shows first: read from the project, editable before it runs.
    `language` decides the image and whether calls are recorded (`traced`: Python only for now)."""
    repo = Path(repo)
    py = any((repo / f).exists() for f in ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "requirements.txt"))
    has_py_tests = (any(d.is_dir() for d in (repo / "tests", repo / "test")) and any(repo.glob("test*/**/*.py"))) \
        or any(repo.glob("test_*.py")) or any(repo.glob("*/tests/*.py"))
    if py or has_py_tests:
        return {"command": "python -m pytest -q", "how": "pyproject.toml / tests folder", "language": "python",
                "supported": True, "traced": True,
                "note": "Python tests are recorded function by function: calls they make turn solid on the map."}
    for pkg in [repo / "package.json", *sorted(repo.glob("*/package.json"))]:
        if pkg.exists() and "node_modules" not in pkg.parts:
            js = _js_command(pkg)
            if js:
                cmd, how = js
                if pkg.parent != repo:
                    how += f" (runs in {pkg.parent.name}/)"
                return {"command": cmd, "how": how, "language": "node", "cwd": pkg.parent.relative_to(repo).as_posix(),
                        "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "go.mod").exists():
        return {"command": "go test ./...", "how": "go.mod", "language": "go", "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "Cargo.toml").exists():
        return {"command": "cargo test", "how": "Cargo.toml", "language": "rust", "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "pom.xml").exists():
        return {"command": "mvn -q -o test", "how": "pom.xml", "language": "java", "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "build.gradle").exists() or (repo / "build.gradle.kts").exists():
        cmd = "./gradlew test --offline" if (repo / "gradlew").exists() else "gradle test --offline"
        return {"command": cmd, "how": "build.gradle", "language": "java", "supported": True, "traced": False, "note": JS_NOTE}
    return {"command": "python -m pytest -q", "how": "default", "language": "python", "supported": False, "traced": False,
            "note": "No test setup was found. Add a tests folder (pytest, Jest, Vitest, Mocha, go test, cargo test, "
                    "Maven or Gradle), then try again."}


def check_command(words: list[str]) -> str:
    """The language of an accepted test command, or ValueError. Only test runners: the sheet never becomes 'run
    anything'. The command is an argv list and never goes through a shell."""
    if not words:
        raise ValueError("give the test command")
    head = Path(words[0]).name.lower().removesuffix(".exe").removesuffix(".cmd")
    rest = words[1:]
    if head in ("pytest", "py.test"):
        return "python"
    if head.startswith("python") or head == "py":
        if rest[:2] in (["-m", "pytest"], ["-m", "unittest"]) or (rest and rest[0].endswith(".py") and "test" in rest[0].lower()):
            return "python"
    if head in ("npm", "pnpm", "yarn") and (rest[:1] == ["test"] or rest[:2] == ["run", "test"]):
        return "node"
    if head == "npx" and rest[:1] and rest[0] in ("jest", "vitest", "mocha"):
        return "node"
    if head == "go" and rest[:1] == ["test"]:
        return "go"
    if head == "cargo" and rest[:1] == ["test"]:
        return "rust"
    if head in ("mvn", "mvnw", "gradle", "gradlew") and "test" in rest:
        return "java"
    raise ValueError("only a test command can run here: python -m pytest, pytest, python -m unittest, npm/pnpm/yarn "
                     "test, npx jest|vitest|mocha, go test, cargo test, mvn test or gradle test")


def split(command: str) -> list[str]:
    return shlex.split(command, posix=os.name != "nt") if command else []


# ---------------------------------------------------------------------------- which backend
_DOCKER: dict = {}


def docker_ok() -> bool:
    """The daemon answers, on Linux (cached for a minute). LANTERN_SANDBOX=subprocess turns Docker off."""
    if os.environ.get("LANTERN_SANDBOX", "").lower() == "subprocess" or not sys.platform.startswith("linux"):
        return False
    if _DOCKER.get("t", 0) > time.time() - 60:
        return _DOCKER["ok"]
    ok = False
    if shutil.which("docker"):
        try:
            r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=8)
            ok = r.returncode == 0 and bool(r.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            ok = False
    _DOCKER.update(t=time.time(), ok=ok)
    return ok


def image_for(language: str) -> str | None:
    key = f"python{sys.version_info[0]}.{sys.version_info[1]}" if language == "python" else language
    img = IMAGES.get(key)
    return None if not img or "__" in img else img


def backend_for(language: str) -> str:
    if os.environ.get("LANTERN_SANDBOX", "").lower() == "docker":
        return "docker"
    return "docker" if docker_ok() and image_for(language) else "subprocess"


def describe(repo: Path, language: str) -> dict:
    """What the sheet shows before the user clicks Run: the walls this system's sandbox has. Each line is something
    that is either put in place or, when it cannot be, keeps the tests from running (`Unavailable`), and the last
    line says so. A promise is made only where it is kept: "everything it started is stopped" needs the launcher's
    supervisor (Linux) or the job (Windows)."""
    b = backend_for(language)
    without = "if any of this cannot be set up, your tests are not run"
    if b == "docker":
        return {"name": "docker", "label": "Docker container", "image": image_for(language),
                "details": ["your project is mounted read-only at /app", "network off (--network none)",
                            "2 CPUs, 2 GB memory, 10 minutes", "runs as an unprivileged user; scratch space is wiped after",
                            without]}
    det = ["a fresh read-only copy of your project in a temp folder, deleted after",
           "your environment variables are not passed on (no keys or tokens)",
           "10 minutes, then everything it started is stopped" if _LINUX or sys.platform == "win32" else
           "10 minutes, then the tests are stopped (a program they moved out of their group is not found again)"]
    if sys.platform.startswith("linux") and landlock_abi() >= 1:
        det.insert(1, "writes allowed only in its own temp folder" + (", network connections refused" if landlock_abi() >= 4 else ""))
    if language == "python":
        det.insert(1, "writing outside its temp folder and opening network connections are refused")
    if sys.platform == "win32":
        det.insert(1, "inside a Windows job: 2 GB of memory for each process, and nothing it starts can leave the job")
    det.append(without)
    return {"name": "subprocess", "label": "Restricted process on this computer", "image": None, "details": det}


# ---------------------------------------------------------------------------- Linux Landlock (used by _jail)
def landlock_abi() -> int:
    if not sys.platform.startswith("linux"):
        return 0
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        r = libc.syscall(444, None, 0, 1)   # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        return r if r > 0 else 0
    except (OSError, AttributeError):
        return 0


# ---------------------------------------------------------------------------- the Python audit hook
SITECUSTOMIZE = r'''
# Lantern test sandbox: refuse writes outside the sandbox's temp folder and any network connection.
# Installed as sitecustomize so it is in place before the tests import anything; audit hooks cannot be removed.
import os as _os, sys as _sys, socket as _socket
_W = [_os.path.realpath(p) for p in _os.environ.get("LANTERN_SANDBOX_WRITABLE", "").split(_os.pathsep) if p]
_DEV = {_os.devnull, "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}
_NET = {getattr(_socket, "AF_INET", 2), getattr(_socket, "AF_INET6", 10)}
_WFLAGS = _os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_APPEND | getattr(_os, "O_TRUNC", 0)
for _p in _os.environ.get("LANTERN_SANDBOX_SITE", "").split(_os.pathsep):
    if _p and _p not in _sys.path:   # the host's packages (Docker); their .pth files name host paths, so skip them
        _sys.path.append(_p)
def _ok(path):
    try:
        p = _os.path.realpath(_os.fsdecode(path))
    except (TypeError, ValueError):
        return True
    if p in _DEV or p.upper() == "NUL" or p.startswith("\\\\.\\"):
        return True
    return any(p == w or p.startswith(w + _os.sep) for w in _W)
def _block(what):
    msg = "LANTERN-SANDBOX-BLOCKED: " + what
    try:
        _os.write(2, (msg + "\n").encode("utf-8", "replace"))
    except OSError:
        pass
    raise PermissionError(msg)
_PATHS = {"os.remove": (0,), "os.rmdir": (0,), "os.mkdir": (0,), "os.rename": (0, 1), "os.replace": (0, 1),
          "os.symlink": (1,), "os.link": (1,), "os.truncate": (0,), "os.chmod": (0,), "os.chown": (0,),
          "os.utime": (0,), "shutil.rmtree": (0,), "shutil.copyfile": (1,), "shutil.move": (1,)}
def _hook(ev, args):
    if ev == "open":
        path, mode, flags = (tuple(args) + (None, None, None))[:3]
        if isinstance(path, int) or path is None:
            return
        w = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & _WFLAGS)
        if w and not _ok(path):
            _block("write to " + _os.fsdecode(path))
    elif ev in _PATHS:
        for i in _PATHS[ev]:
            p = args[i] if i < len(args) else None
            if p is not None and not isinstance(p, int) and not _ok(p):
                _block(ev.split(".")[-1] + " " + _os.fsdecode(p))
    elif ev in ("socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg"):
        s = args[0]
        if getattr(s, "family", None) in _NET:
            _block("network " + ev.split(".")[1] + " " + repr(args[1] if len(args) > 1 else "")[:80])
    elif ev == "socket.getaddrinfo":
        host = args[0] if args else None
        if host not in (None, "", "localhost", "127.0.0.1", "::1", b"localhost"):
            _block("network lookup " + repr(host)[:80])
_sys.addaudithook(_hook)
_sys.lantern_sandbox_guard = "on"   # lantern.tracehook looks for this before it runs a test (LANTERN_SANDBOX_GUARD)
'''


# ---------------------------------------------------------------------------- running
class Result(dict):
    pass


def _copy(repo: Path, dst: Path) -> None:
    def ignore(d, names):
        return [n for n in names if n in SKIP]
    shutil.copytree(repo, dst, symlinks=True, ignore=ignore)


_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


def _make_read_only(root: Path) -> None:
    """Take every write bit off the copy (read and execute bits are left as they were)."""
    for dirpath, _dirs, files in os.walk(root, topdown=False):
        for f in files:
            p = os.path.join(dirpath, f)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode & ~_WRITE_BITS)
        os.chmod(dirpath, os.stat(dirpath).st_mode & ~_WRITE_BITS)


def _unlock(path) -> None:
    """Give the owner its rights back on every real folder at and beneath `path`, so that the copy (made read-only)
    and whatever the tests left (a folder with every right taken off) can be deleted. A link is never followed and
    never changed: what it points at is not the sandbox's."""
    todo = [os.fspath(path)]
    while todo:
        d = todo.pop()
        try:
            st = os.lstat(d)
            if not stat.S_ISDIR(st.st_mode):
                continue
            if stat.S_IMODE(st.st_mode) & stat.S_IRWXU != stat.S_IRWXU:
                os.chmod(d, stat.S_IMODE(st.st_mode) | stat.S_IRWXU)
            with os.scandir(d) as entries:
                todo.extend(e.path for e in entries if e.is_dir(follow_symlinks=False))
        except OSError:
            continue


def _rm(path: Path) -> bool:
    """Delete a folder the sandbox made, with all that is in it. True when nothing is left of it.

    Only what is inside `path` is changed. Until 2026-11-10 a link in the copy that pointed at a folder outside had
    that folder's mode changed, and when the folder could not be deleted the mode of the folder it is in was set to
    owner-only: the system's temp folder, for all its users, when Lantern ran as root. Both without a word, and
    with the folder still there."""
    path = Path(path)
    if not os.path.lexists(path):
        return True
    if os.path.islink(path) or not path.is_dir():
        try:
            os.unlink(path)
        except OSError:
            pass
        return not os.path.lexists(path)
    _unlock(path)

    def again(fn, p, exc):   # Windows refuses to delete a read-only file: give it its write bit, try once more
        try:
            if fn in (os.unlink, os.remove, os.rmdir) and not os.path.islink(p):
                os.chmod(p, stat.S_IMODE(os.lstat(p).st_mode) | stat.S_IWRITE | stat.S_IREAD)
                fn(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=again) if sys.version_info < (3, 12) else shutil.rmtree(path, onexc=again)
    return not os.path.lexists(path)


def _env_base(tmp: Path) -> dict:
    """The allow-list. Nothing else from the user's environment reaches the tests."""
    keep = ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT",
            "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "VIRTUAL_ENV", "JAVA_HOME"]
    env = {k: os.environ[k] for k in keep if k in os.environ}
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    env.update({"HOME": str(home), "USERPROFILE": str(home), "TMPDIR": str(tmp), "TEMP": str(tmp), "TMP": str(tmp),
                "APPDATA": str(home), "LOCALAPPDATA": str(home), "XDG_CACHE_HOME": str(tmp / "cache"),
                "CI": "true", "TERM": "dumb", "NO_COLOR": "1", "LANTERN_SANDBOX_WRITABLE": str(tmp),
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPYCACHEPREFIX": str(tmp / "pycache"), "PYTHONUTF8": "1",
                "npm_config_cache": str(tmp / "npm"), "npm_config_update_notifier": "false",
                "GOCACHE": str(tmp / "gocache"), "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOFLAGS": "-mod=mod",
                "CARGO_TARGET_DIR": str(tmp / "target"), "CARGO_NET_OFFLINE": "true"})
    real = Path.home()
    for var, default in (("GOPATH", real / "go"), ("GOMODCACHE", real / "go" / "pkg" / "mod"),
                         ("CARGO_HOME", real / ".cargo"), ("RUSTUP_HOME", real / ".rustup")):
        v = os.environ.get(var) or (str(default) if default.exists() else None)
        if v:
            env[var] = v
    m2 = real / ".m2" / "repository"
    if m2.exists():
        env["MAVEN_OPTS"] = f"-Dmaven.repo.local={m2}"
    return env


def _python_argv(words: list[str]) -> list[str]:
    """`python -m pytest -q` -> the part after the interpreter, with pytest's cache off (it would write next to the
    tests, which the sandbox refuses)."""
    head = Path(words[0]).name.lower()
    rest = words[1:] if head.startswith("python") or head == "py" else ["-m", "pytest", *words[1:]]
    if rest[:2] == ["-m", "pytest"] and "no:cacheprovider" not in rest:
        rest = rest[:2] + ["-p", "no:cacheprovider"] + rest[2:]
    return rest


class Unavailable(RuntimeError):
    """The sandbox could not be set up, so the project's tests were not run. `str()` says why, in words for a
    person; it is never text read from the project or from a run's output."""


_LINUX = sys.platform.startswith("linux")
# POSIX with waitid: a process that has ended can be seen without being collected, and until it is collected its
# number still names its session and process group, so those can be ended without the number meaning another program
_WAITID = os.name == "posix" and all(hasattr(os, n) for n in ("waitid", "P_PID", "WEXITED", "WNOWAIT", "WNOHANG"))
_LIVE: set = set()             # the commands running now
_GOING: set = set()            # the calls of `run()` under way, each until its temp folder has been dealt with
_LIVE_LOCK = threading.Lock()
_KILL_WAIT = 5.0               # seconds a stop goes on ending what is still there before it says what is left
# the launcher's own last line when it could not end something (`lantern._jail._supervise`); only the number is read
_LEFT_BY_LAUNCHER = re.compile(r"sandbox: (\d{1,6}) process\(es\) the command started could not be ended")


def stop_all(wait: float = 30.0) -> int:
    """Ask every command the sandbox is running to end, with everything it started, and wait until that is done
    and each run has tidied up after itself: its last lines logged, its temp folder deleted (the app closing, the
    service shutting down, the program leaving). A run that has not started its command yet (it is still copying
    the project) starts none. Returns how many commands were running.

    Until 2026-11-10 it came back as soon as the processes were ended. The program then left while the run's own
    thread was still at work: the copy of the project stayed in the temp folder, without a word."""
    with _LIVE_LOCK:
        runs, going = list(_LIVE), list(_GOING)
    for g in going:
        g.asked.set()
    for r in runs:
        r.asked.set()
    end = time.monotonic() + wait
    for r in runs:
        r.over.wait(max(0.0, end - time.monotonic()))
    for g in going:
        g.done.wait(max(0.0, end - time.monotonic()))
    return len(runs)


atexit.register(stop_all)


class _Going:
    """One call of `run()`, from before its temp folder is made until that folder has been dealt with. It is what
    the run's commands are handed as their `cancel`: set by the caller's own event, or by `stop_all`."""

    def __init__(self, cancel):
        self.cancel = cancel                  # the caller's event (the person pressed Stop), or None
        self.asked = threading.Event()        # stop_all(): end this run, and start nothing more for it
        self.done = threading.Event()         # nothing of it is left to do

    def is_set(self) -> bool:
        return self.asked.is_set() or (self.cancel is not None and self.cancel.is_set())


class _Run:
    """One command the sandbox is running: its process, the Windows job that holds it, and the one way to end it."""

    def __init__(self, proc, job, ask: float, also):
        self.proc, self.job, self.ask, self.also = proc, job, ask, also
        self.asked = threading.Event()        # stop_all(): end this run
        self.over = threading.Event()         # it has been ended and collected
        self.said: list[str] | None = None
        self.left: list[str] = []             # of `said`: what could not be ended

    def ended(self) -> bool:
        p = self.proc
        if p.returncode is not None:
            return True
        if _WAITID:
            try:
                return os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None
            except ChildProcessError:
                pass
        return p.poll() is not None

    def stop(self) -> list[str]:
        """End the command and everything it started; also after it ended by itself, for what it left running.
        Returns what there is to say about it, in words; `self.left` holds the ones about something that could not
        be ended (a run says "everything it started was ended" only when that list is empty)."""
        if self.said is not None:
            return self.said
        p, said = self.proc, []

        def failed(text: str) -> None:
            said.append(text)
            self.left.append(text)
        running = not self.ended()
        if self.job is not None:              # Windows: every process is in the job, whatever it started
            try:
                self.job.stop()
                end = time.monotonic() + _KILL_WAIT
                while self.job.count() > 0:
                    if time.monotonic() > end:
                        failed(f"{self.job.count()} process(es) are still in the job after Windows was asked to end them")
                        break
                    time.sleep(0.02)
            except OSError as e:
                failed(f"Windows did not end the processes of this run ({e})")
        if os.name == "posix":
            if running and self.ask > 0:
                # ask first: the launcher (lantern._jail) ends everything the command started, also what left its
                # session and process group, and then goes
                try:
                    os.kill(p.pid, signal.SIGTERM)
                    os.kill(p.pid, signal.SIGCONT)     # a launcher that was stopped would not hear it
                except OSError:
                    pass
                end = time.monotonic() + self.ask
                while not self.ended() and time.monotonic() < end:
                    time.sleep(0.02)
                if not self.ended():
                    said.append("the launcher did not answer when asked to stop, so its processes were killed")
            if _LINUX and not self.ended():
                # still there: every process of the run is beneath it, also one that left its session, so they
                # are ended first and the launcher after them
                from . import _jail
                _jail.end_beneath(p.pid)
            end = time.monotonic() + _KILL_WAIT
            while True:                       # whatever is still there, the command itself included
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
                rest = []
                if _LINUX:
                    from . import _jail
                    _jail.end_session(p.pid)
                    rest = _jail.in_session(p.pid)
                if not rest:
                    break
                if time.monotonic() > end:
                    failed(f"{len(rest)} process(es) this run started could not be ended")
                    break
                time.sleep(0.02)
        elif p.poll() is None:
            if self.job is None:
                from .remote import _kill_tree
                _kill_tree(p)
            else:                             # a process that never got into the job (it has not run)
                try:
                    p.kill()
                except OSError:
                    pass
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            failed("the command did not end when it was killed")
        if running and self.also is not None:
            try:
                problem = self.also()
            except (OSError, subprocess.SubprocessError) as e:
                problem = f"the clean-up after stopping it failed ({type(e).__name__})"
            if problem:
                failed(str(problem))
        if self.job is not None:
            self.job.close()
        self.said = said
        return said


def _stream(cmd: list[str], cwd: Path, env: dict, timeout: float, log, job=None, cancel=None, ask: float = 0.0,
            also=None, left: list | None = None) -> tuple[int | None, str, bool]:
    """Run, streaming each output line to `log`, and leave nothing behind: when the command ends, at the wall
    clock (`timeout`), when `cancel` (a threading.Event) is set and when `stop_all` is called, every process it
    started is ended too. Returns (result, output, stopped at the wall clock); the result is None when the command
    was stopped, at the wall clock or because it was asked.

    `job`: called before the process is made; what it returns holds the process (Windows: `winjob.Job`, which the
    process is put in before it runs). `ask`: seconds the command has to end what it started after SIGTERM, for a
    launcher that does so (`_jail`), before everything is killed. `also`: called once the command was stopped
    before its end (Docker: remove the container); it returns None, or the words for what it could not do.
    `left`: a list that is given what could not be ended, each in Lantern's own words (empty: all of it was).
    When `cancel` is set before the command is made, nothing is started: the result is that of a stopped command."""
    if cancel is not None and cancel.is_set():
        return None, "", False
    held = job() if job is not None else None
    if sys.platform == "win32":
        from . import winjob
        kw: dict = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | (winjob.SUSPENDED if held is not None else 0)}
    else:
        kw = {"start_new_session": True}
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", **kw)
    except BaseException:
        if held is not None:
            held.close()
        raise
    run = _Run(proc, held, ask, also)
    with _LIVE_LOCK:
        _LIVE.add(run)
    lines: list[str] = []

    def read():
        for line in proc.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if len(lines) > 4000:
                del lines[:1000]
            log(line)
    reader, why = None, ""
    try:
        if held is not None:
            try:
                held.take(proc.pid)           # in the job before it has run one instruction
                held.release(proc.pid)        # from here it runs
            except OSError as e:
                raise Unavailable("Windows could not put the tests in the job that limits them and ends what they "
                                  f"start ({e}), so they were not started") from e
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        deadline, delay = time.monotonic() + timeout, 0.001
        while not run.ended():
            if run.asked.is_set() or (cancel is not None and cancel.is_set()):
                why = "asked"
                break
            if time.monotonic() >= deadline:
                why = "clock"
                break
            time.sleep(delay)
            delay = min(delay * 2, 0.05)
    finally:
        try:
            said = run.stop()
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(run)
            run.over.set()
            if reader is None:
                proc.stdout.close()
    for line in said:
        log("sandbox: " + line)
    if left is not None:
        left.extend(run.left)
    reader.join(timeout=5)
    if reader.is_alive():
        log("sandbox: something this run started still holds its output open")
    return (None if why else proc.returncode), "\n".join(lines), why == "clock"


def _windows_job():
    """Windows: the Job Object a project's tests run in (2 GB for each process; every process in it ends when the
    job is stopped or closed, and nothing started inside can leave it). None on other systems, where `lantern._jail`
    does that work. `Unavailable` when Windows does not make it: the tests are then not run."""
    if sys.platform != "win32":
        return None
    from . import winjob
    try:
        return winjob.Job()
    except OSError as e:
        raise Unavailable(f"Windows could not make the job that limits the tests and ends what they start ({e}), "
                          "so they were not started") from e


def _stopped(how: str, left: list[str], done: str) -> str:
    """The log's line for a run that was stopped. It says that everything was ended only when that is so: until
    2026-11-10 it said "every process it started was ended" whatever had happened."""
    return f"sandbox: stopped {how}; " + (done if not left else "not everything it started could be ended (the lines above say what)")


def _left_by_launcher(output: str) -> list[str]:
    """What the launcher said it could not end, in Lantern's own words. Its only way to say it is a line of the
    run's output, which a test can print as well: such a test says of itself that it left something."""
    counts = [int(m.group(1)) for m in map(_LEFT_BY_LAUNCHER.fullmatch, output.splitlines()) if m]
    return [f"{counts[-1]} process(es) the tests started could not be ended by their launcher"] if counts else []


def _unavailable(rc, output: str) -> str | None:
    """The launcher, or the tests' own Python before its first test, said the sandbox could not be set up: the
    words for it (always Lantern's own, from `_jail.REASONS`), or None."""
    from . import _jail
    if rc != _jail.UNAVAILABLE:
        return None
    why = None
    for line in output.splitlines():
        i = line.find(_jail.MARK)
        parts = line[i + len(_jail.MARK):].split() if i >= 0 else []
        if parts and parts[0] in _jail.REASONS:
            number = parts[1] if len(parts) > 1 and parts[1].isdigit() else ""
            why = _jail.REASONS[parts[0]] + (f" (error {number})" if number else "")
    return why


def blocked_reasons(output: str) -> list[str]:
    """What the sandbox refused, from its own markers and the kernel's messages (read-only mount, no network)."""
    out, seen = [], set()
    for line in output.splitlines():
        i = line.find(MARK)
        why = None
        if i >= 0:
            why = line[i + len(MARK):].strip()
            if not why or why[0] in "\"'":   # the hook's own source line in a traceback
                continue
        elif "Read-only file system" in line:
            why = "write to a read-only file (the project is mounted read-only)"
        elif "Network is unreachable" in line or "Temporary failure in name resolution" in line:
            why = "network (the sandbox has no network)"
        if why:
            kind = "network" if why.startswith("network") else "write"
            key = (kind, why[:120])
            if key not in seen:
                seen.add(key)
                out.append({"kind": kind, "what": why[:200]})
    return out[:10]


def _map_pairs(data: dict, inner_root: str, repo: Path) -> dict:
    """Recorded filenames point into the copy or the container; point them back at the project."""
    inner = inner_root.rstrip("/\\")
    real = str(repo.resolve())
    for row in data.get("pairs", []):
        for side in ("caller", "callee"):
            f = row[side][0]
            if isinstance(f, str):
                norm = os.path.realpath(f) if not f.startswith("/app") else f
                for pre in {inner, os.path.realpath(inner)}:
                    if norm == pre or norm.startswith(pre + "/") or norm.startswith(pre + os.sep):
                        row[side][0] = real + norm[len(pre):].replace("/", os.sep)
                        break
    return data


def run(repo: Path, words: list[str], log=print, timeout: float = WALL_CLOCK, backend: str | None = None,
        cwd_rel: str = "", cancel=None) -> Result:
    """Run the test command `words` for `repo` in the sandbox. Returns trace data for `trace.merge_trace` (`pairs`)
    plus `backend`, `language`, `traced`, `returncode`, `timed_out`, `cancelled`, `blocked`, `not_ended` (what the
    tests started and Lantern could not end, in its own words; empty when nothing is left), `output_tail`,
    `stderr_tail`. `cancel`: a threading.Event; once set, the tests and everything they started are ended.
    Raises `Unavailable` when the sandbox cannot be set up: the tests were then not run."""
    repo = Path(repo).resolve()
    language = check_command(words)
    backend = backend or backend_for(language)
    me = _Going(cancel)
    with _LIVE_LOCK:
        _GOING.add(me)
    try:
        root = Path(tempfile.mkdtemp(prefix="lantern-sandbox-"))
        try:
            if backend == "docker":
                res = _run_docker(repo, words, language, root, log, timeout, cwd_rel, me)
            else:
                res = _run_subprocess(repo, words, language, root, log, timeout, cwd_rel, me)
        finally:
            if not _rm(root):
                log(f"sandbox: its temp folder could not be deleted and is still there: {root}")
    finally:
        with _LIVE_LOCK:
            _GOING.discard(me)
        me.done.set()            # stop_all() waits for this, so the program does not leave in the middle of the lines above
    res.update(backend=backend, language=language, traced=language == "python")
    res["cancelled"] = res.get("returncode") is None and not res.get("timed_out")
    res["blocked"] = blocked_reasons(res.get("output_tail", "") + "\n" + res.pop("_full", ""))
    res["stderr_tail"] = res.get("output_tail", "")[-2000:]
    return res


def _others_may_read(folder: Path) -> None:
    """The tests run as another user (`nobody`, when Lantern is root): let that user read what Lantern wrote for
    them. Where root's own files are made owner-only (umask 077), Python left the folder of the guard out of its
    path without a word and the tests ran with no guard."""
    os.chmod(folder, stat.S_IRWXU | stat.S_IROTH | stat.S_IXOTH)
    for f in folder.iterdir():
        os.chmod(f, stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)


def _run_subprocess(repo, words, language, root, log, timeout, cwd_rel, cancel=None) -> Result:
    from . import _jail
    app, tmp, hook = root / "app", root / "tmp", root / "hook"
    as_nobody = hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        tmp.mkdir()
        hook.mkdir()
        (hook / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
        log("sandbox: copying the project to a temp folder")
        _copy(repo, app)
        _make_read_only(app)
        env = _env_base(tmp)
        if as_nobody:   # root ignores file modes: run the tests as nobody, who owns only the sandbox folder and its temp
            for dirpath, _dirs, files in os.walk(tmp):
                os.chown(dirpath, 65534, 65534)
                for f in files:
                    os.chown(os.path.join(dirpath, f), 65534, 65534)
            os.chown(root, 65534, 65534)   # mode stays 0700; the copy inside keeps root as owner and no write bits
            _others_may_read(hook)
    except OSError as e:
        first = e.args[0][0] if isinstance(e, shutil.Error) and e.args and e.args[0] else None
        what = f"{first[0]}: {first[2]}" if isinstance(first, (tuple, list)) and len(first) >= 3 else (e.strerror or type(e).__name__)
        raise Unavailable(f"the project could not be copied into the sandbox's temp folder ({str(what)[:200]})") from e
    out_json = tmp / "trace.json"
    pkg_root = str(Path(__file__).resolve().parent.parent)
    if language == "python":
        env["PYTHONPATH"] = os.pathsep.join([str(hook), pkg_root, str(app)])
        env["LANTERN_SANDBOX_GUARD"] = "required"   # lantern.tracehook runs no test without the guard above
        cmd = [sys.executable, "-m", "lantern.tracehook", str(out_json), str(app), "--", *_python_argv(words)]
    else:
        exe = shutil.which(words[0], path=env.get("PATH")) or (str(app / words[0]) if words[0].startswith("./") else words[0])
        cmd = [exe, *words[1:]]
    cwd = app / cwd_rel if cwd_rel else app
    if os.name == "posix":
        policy = {"writable": [str(tmp)], "nobody": as_nobody, "python": language == "python",
                  "net": True, "must": True, "parent": os.getpid()}
        cmd = [sys.executable, "-I", "-m", "lantern._jail", json.dumps(policy), "--", *cmd]
        env_jail = dict(env)
        env_jail["PYTHONPATH"] = env.get("PYTHONPATH", "") if language == "python" else ""
        env = env_jail
        # -I ignores PYTHONPATH for the jail itself; it finds lantern from its own path below
        cmd[2:4] = ["-c", f"import sys; sys.path.insert(0, {pkg_root!r}); from lantern._jail import main; main(sys.argv[1:])"]
    log(f"sandbox: restricted process, running {' '.join(words)}")
    left: list[str] = []
    rc, output, timed_out = _stream(cmd, cwd, env, timeout, log, job=_windows_job, cancel=cancel,
                                    ask=_jail.ASK if _LINUX else 0.0, left=left)
    why = _unavailable(rc, output)
    if why:
        raise Unavailable(why)
    if os.name == "posix":
        left += _left_by_launcher(output)
    if timed_out:
        log(_stopped(f"after {int(timeout)} s (the wall clock)", left, "every process it started was ended"))
    elif rc is None:
        log(_stopped("because it was asked to", left, "every process it started was ended"))
    data = {}
    if out_json.exists():
        try:
            data = json.loads(out_json.read_text(encoding="utf-8") or "{}")
        except ValueError:
            data = {}
    _map_pairs(data, str(app), repo)
    return Result(pairs=data.get("pairs", []), returncode=rc, timed_out=timed_out, output_tail=output[-6000:], _full=output,
                  not_ended=left)


def _site_dirs() -> list[str]:
    seen = []
    for p in sys.path:
        if p and p.rstrip("/").endswith(("site-packages", "dist-packages")) and os.path.isdir(p) and p not in seen:
            seen.append(p)
    try:
        u = site.getusersitepackages()
        if os.path.isdir(u) and u not in seen:
            seen.append(u)
    except AttributeError:
        pass
    return seen


def _run_docker(repo, words, language, root, log, timeout, cwd_rel, cancel=None) -> Result:
    img = image_for(language)
    if not img:
        raise RuntimeError(f"no pinned Docker image for {language}")
    out, hook = root / "out", root / "hook"
    out.mkdir()
    hook.mkdir()
    # the container runs as the user who runs Lantern (or nobody, when that is root), who owns /out
    uid, gid = (os.getuid(), os.getgid()) if os.getuid() != 0 else (65534, 65534)
    if os.getuid() == 0:
        os.chown(out, uid, gid)
    (hook / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
    if os.getuid() == 0:
        _others_may_read(hook)
    name = "lantern-sbx-" + uuid.uuid4().hex[:12]
    pkg = Path(__file__).resolve().parent
    args = ["docker", "run", "--rm", "--name", name, "--network", "none", "--cpus", "2", "--memory", "2g",
            "--pids-limit", "512", "--user", f"{uid}:{gid}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,exec,size=1g,mode=1777",  # nosec B108: the container's own tmpfs
            "-v", f"{repo}:/app:ro", "-v", f"{out}:/out:rw", "-v", f"{hook}:/opt/hook:ro",
            "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp", "-e", "CI=true", "-e", "NO_COLOR=1",
            "-e", "LANTERN_SANDBOX_WRITABLE=/tmp" + os.pathsep + "/out", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "npm_config_cache=/tmp/npm", "-e", "GOCACHE=/tmp/gocache", "-e", "GOFLAGS=-mod=mod",
            "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local", "-e", "CARGO_TARGET_DIR=/tmp/target",
            "-e", "CARGO_NET_OFFLINE=true", "-w", "/app/" + cwd_rel if cwd_rel else "/app"]
    if language == "python":
        sites = _site_dirs()
        for i, s in enumerate(sites):
            args += ["-v", f"{s}:/opt/site/{i}:ro"]
        args += ["-v", f"{pkg}:/opt/lantern/lantern:ro",
                 "-e", "PYTHONPATH=" + ":".join(["/opt/hook", "/opt/lantern", "/app"]), "-e", "LANTERN_SANDBOX_GUARD=required",
                 "-e", "LANTERN_SANDBOX_SITE=" + ":".join(f"/opt/site/{i}" for i in range(len(sites)))]
        cmd = ["python", "-m", "lantern.tracehook", "/out/trace.json", "/app", "--", *_python_argv(words)]
    else:
        env = _env_base(root)
        for var, where in (("GOMODCACHE", "/go/pkg/mod"), ("CARGO_HOME", None)):
            if env.get(var) and Path(env[var]).exists():
                if var == "CARGO_HOME":
                    reg = Path(env[var]) / "registry"
                    if reg.exists():
                        args += ["-v", f"{reg}:/usr/local/cargo/registry:ro"]
                else:
                    args += ["-v", f"{env[var]}:{where}:ro"]
        m2 = Path.home() / ".m2" / "repository"
        if language == "java" and m2.exists():
            args += ["-v", f"{m2}:/m2:ro", "-e", "MAVEN_OPTS=-Dmaven.repo.local=/m2"]
        cmd = list(words)
    log(f"sandbox: Docker ({img.split('@')[0]}, network off, project read-only), running {' '.join(words)}")
    def remove() -> str | None:
        """The docker program was only the container's client: the container goes with this. None when it is gone,
        else the words for it (until 2026-11-10 the answer was not looked at)."""
        try:
            r = subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            return f"its Docker container {name} may still be running: docker rm could not be run ({type(e).__name__})"
        if r.returncode != 0 and "No such container" not in (r.stderr or ""):
            return f"its Docker container {name} may still be running: docker rm ended with {r.returncode}"
        return None
    left: list[str] = []
    rc, output, timed_out = _stream(args + [img, *cmd], root, {k: v for k, v in os.environ.items()}, timeout, log,
                                    cancel=cancel, also=remove, left=left)
    why = _unavailable(rc, output)
    if why:
        raise Unavailable(why)
    if rc == 125 and any(line.startswith("docker: ") for line in output.splitlines()):
        # the docker program's own result and words when Docker itself failed: no container, so no test has run
        raise Unavailable("Docker could not start the container the tests run in (docker run ended with 125; "
                          "what Docker said is in the log)")
    if timed_out:
        log(_stopped(f"after {int(timeout)} s (the wall clock)", left, "the container was removed"))
    elif rc is None:
        log(_stopped("because it was asked to", left, "the container was removed"))
    data = {}
    if (out / "trace.json").exists():
        try:
            data = json.loads((out / "trace.json").read_text(encoding="utf-8") or "{}")
        except ValueError:
            data = {}
    _map_pairs(data, "/app", repo)
    return Result(pairs=data.get("pairs", []), returncode=rc, timed_out=timed_out, output_tail=output[-6000:], _full=output,
                  not_ended=left)
