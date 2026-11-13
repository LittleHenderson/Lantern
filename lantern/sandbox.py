"""Test sandbox for "Watch my tests run" (and the terminal's `trace`), and for `lantern behave`.

Lantern reads code and never runs it, with two exceptions the user asks for: running the project's own tests so the
map can mark the calls that really happen, and starting the project's app to see what it really does
(`lantern.behave`, through `run_inside`: the restricted subprocess only, never Docker). Both run here, never in the
project folder as the user:

* **Docker** when the daemon answers (`docker info`) on a Linux computer: a per-language image pinned by digest, a
  fresh copy of the project mounted at `/app`, a writable tmpfs at `/tmp`, every other file of the container
  read-only, `--network none`, `--cpus 2`, `--memory` (below), a non-root user, no capabilities, a wall clock.
  Python tests use the packages already installed in the Python that runs Lantern (mounted read-only), so
  nothing is downloaded. On macOS and Windows those packages are not Linux packages, so the restricted
  subprocess below is used instead.
* **Restricted subprocess** otherwise: a fresh temp copy of the project; the environment rebuilt from an
  allow-list (PATH, HOME=a temp folder, locale, the runtime's own variables) so no secrets are inherited; resource
  limits on POSIX (CPU, file size, memory: below) and a Job Object on Windows (memory, kill on close); on Linux a
  network of the run's own (below) and a Landlock rule set that allows writes only inside the copy and the
  sandbox's temp folder and, where the run has no network of its own, denies TCP connect/bind; for Python a
  start-up audit hook (`SITECUSTOMIZE`), on every OS, that refuses writes outside the copy and the temp folder
  (a name given beside an open folder is read in that folder; a database file opened with `sqlite3` counts as a
  write unless it cannot be changed), questions about where a name leads, every network socket that is not the
  run's own computer in a network of its own, and a socket file outside those two folders; when Lantern runs as
  root the tests run as `nobody`, who is given the copy. The hook sees what Python does: code inside the process
  that is not Python (a C extension, `ctypes`) is held by the kernel's walls where the system has them and by
  nothing else.

The tests may change their own copy, and nothing else (2026-11-13). The copy is made for one run and thrown away
with it, so what a test writes there reaches nothing: not the project, not the next run. Until then the copy could
not be changed either (every write bit taken off it; under Docker the project itself was mounted read-only), and
a test that does what tests do at home failed in the sandbox: one that writes a file beside the code (a coverage
record, a snapshot, a small database, a build folder), and one that copies a sample folder and writes into the
copy, because a copy made the usual way keeps the marks of what it was copied from. The release decision then read
"Incomplete" ("the sandbox refused something they tried") or, where the refusal came from the file's own marks
and not from the guard, "Blocked: the tests failed". Lantern's own tests were among them. When Lantern is root
the copy is handed to `nobody` (`_hand_over`, no link followed), so a file only its owner may read is read
there as it is at home. An app that one of Lantern's own drivers starts (`run_inside`) still gets a copy it
cannot change: there a write outside the app's data folder is what the check is looking for.

A project may talk to itself (2026-11-13). Tests that start their app's server and call it are how most web
projects are tested, and until then the sandbox refused every listener and every connection, also on this
computer: such tests failed, the release decision said "Incomplete", and Lantern's own tests were among them.
Now the tests get a network of their own, which holds this computer's own address and nothing else:
* Docker: the container's (`--network none` leaves it a loopback address);
* the restricted subprocess on Linux: a network namespace the launcher makes for the run (`lantern._jail`,
  `own_network()` says whether this system can). No other computer can be reached from it, by any language, and
  neither can what the other programs of this computer listen at by address or by socket name: those are in the
  network the run left. (A socket file is a file, not a part of any network: it is the hook's to refuse, above.)
  For Python the hook lets this computer's own addresses through only there (it checks the network's
  number for itself) and still refuses any other address before it is tried, so the log says what was reached for.
Where no such network can be made (macOS, Windows, a Linux system that refuses the rights it takes) nothing on
this computer is let through, as before: a listener there could be reached by the computer's other programs, and
a connection there could reach them. The log and the sheet say so (`describe`).

The time a run gets (2026-11-13) is ten minutes unless the person sets another limit: for one run (`timeout`,
from the sheet's field in the app or `--test-minutes` on the command line), or for an installation
(LANTERN_TEST_MINUTES); `time_limit` is the one place that says how many seconds that is, from 1 to 240 minutes.
Until then it was ten minutes whatever the tests needed, and tests stopped by the clock are "Incomplete", never
passed or failed: a suite that needs eleven minutes (Lantern's own needs more) could not get an answer. The
processor time each process may use follows the limit, on every processor the run may use (`cpu` in the
launcher's policy, `_processors`): tests at work on four processors at once use four seconds of it a second, and
with the limit's seconds alone they met this limit before the clock, which read as a failure.

The memory a run gets (2026-11-13) is 2 GB unless the person sets another limit: for one run (`memory`, from the
sheet's field in the app or `--test-memory` on the command line) or for an installation (LANTERN_TEST_MEMORY_MB);
`memory_limit` is the one place that says how many megabytes that is, from 128 to 1,048,576. What is counted is
memory in use, by the tests and everything they started together: Docker counts it for the container
(`--memory`, with no swap beside it), and on Linux the launcher's supervisor looks at it from outside
(`lantern._jail`). Until then the restricted process gave each Python process 2 GB of address space, which a
program can run out of while it uses little (a file mapped, threads, an allocator's arenas): Lantern's own tests
were refused memory after 302 of them, and the refusal read as "the tests failed". Tests stopped for their
memory did not finish (`over_memory`): the release decision is "Incomplete", never passed or failed. The words
come from the launcher's own line and result (`_over_memory`) or from Docker's answer about the container
(`_docker_oom`); a test that prints the line and ends with that result says of itself that it was stopped, and
gains "Incomplete" where it would have had "Blocked", never a pass. On macOS the limit is put on the address
space as before, and on Windows it is the job's limit for each process: there tests that go over fail in their
own way, and are reported as failed.

What the Python hook does with a project's own ways (2026-11-13; each was found by running Lantern's tests here):
* **A guard the project brings itself.** Python calls audit hooks in the order they were added and the sandbox's
  is the first, so a hook a project adds never saw what the sandbox refuses: a project's tests of its own guard
  failed with the sandbox's words. The hook now keeps the hooks a program adds (`sys.addaudithook` is its own
  function there) and calls them itself, in their order, after it has written its own line down and before it
  refuses. A project's hook may refuse its own way; whatever it lets through is refused as before. Python's own
  rules for adding a hook are kept (a hook already there may keep a newcomer out, and nothing is said).
* **An address written as a number is no question.** `getaddrinfo("192.0.2.1", 80)` asks nobody where a name
  leads, so it is answered; going there is refused as before, and the line then names the connection and not a
  lookup. A name is still refused before anything is asked (`_number` reads strictly: four plain decimal parts or
  what the system takes for IPv6, nothing around it); who a number belongs to (`gethostbyaddr`) is a question.
* **A folder too deep to name.** A name given beside an open folder is placed by that folder's path. Where the
  system does not hand the path back (folders inside each other past the longest path it writes), the folder is
  followed upwards one at a time to one whose path it does hand back (`_far`); only one plain name is let
  through that way.
* **A link is a name.** Removing a link, renaming it and putting it in another name's place change the name and
  nothing of what it names, and the system does not follow it. The hook did, and judged the place the link names:
  a test could not remove a link it had made to anything outside its folders (a virtual environment's link to
  the Python that runs it), nor the folder that held one. Now a name that is removed, renamed or made is judged
  by the folder it is in (`_ok(follow=False)`, the third entry of each row of `_PATHS`); a write, a change of
  rights or dates and a copy go through a link as before, and so does any name that ends in a slash, which the
  system follows. A name beside an open folder is placed by the system's own word for that folder, with nothing
  looked up again (removing a tree 1,100 folders deep took 8.387 seconds under the hook, now 0.129; 0.131 with no
  hook).
* **A second name for a file is the file.** `os.link` gives a file another name, and what is written under the
  new name is written to the file. The hook looked only at where the new name would be; now the file must be in
  the run's own folders too. (Where Landlock stands behind the hook the kernel refused it already.)

What the tests are made of must be readable by the user they run as (2026-11-13). When Lantern is root the tests
run as `nobody`, and a Lantern installed where that user may not enter (a home folder closed to others) started
Python, which found no `lantern`: "the tests failed". The launcher is now told what the run is made of (`_made_of`,
the policy's `readable` and `runs`) and asks for each as that user before anything starts; if one cannot be
read, the tests are not started and the reason is `Unavailable` (`_jail.REASONS["unreadable"]`).

Known and not fixed (found 2026-11-11): on Windows a test that starts an event loop (an async test, a FastAPI test
client) fails in the sandbox. Windows has no call that makes a pair of connected sockets, so Python builds the pair
every event loop wakes itself with from a listener on this computer, and the hook refuses it. The listener is not
let through, because the event loop Windows uses by default makes its connections with a call the hook is never
told about (ConnectEx: Python reports no `socket.connect` event for it), so a loop that could start could connect
with nothing seen. For the same reason `run_inside` starts no app there (`NO_APPS`).

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

Both backends print `LANTERN-SANDBOX-BLOCKED: <what>` when a test tries to write outside its copy and its temp
folder or to reach another computer; `blocked` in the result lists them so the app can say why the tests failed.

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

from . import programs, removal, results

WALL_CLOCK = 600          # seconds: the ten minutes a test run gets unless the person sets another limit
MINUTES = (1, 240)        # what a person may set instead, in whole minutes (`time_limit`)
TIME_VARIABLE = "LANTERN_TEST_MINUTES"    # the limit for a whole installation
MEMORY_MB = 2048          # megabytes of memory in use a test run gets unless the person sets another limit
MEGABYTES = (128, 1 << 20)                # what a person may set instead, in whole megabytes (`memory_limit`)
MEMORY_VARIABLE = "LANTERN_TEST_MEMORY_MB"   # the limit for a whole installation
MARK = "LANTERN-SANDBOX-BLOCKED:"
JS_NOTE = "Tests run; your map upgrades for Python only for now."
INSIDE = ("lantern._behave_inside",)      # Lantern's own drivers that `run_inside` may start in the sandbox
# Where `run_inside` starts nothing, and why (2026-11-11). An app is asked on an event loop, and on Windows the guard
# cannot let one start without losing sight of what it connects to (this module's opening text).
NO_APPS = ("on Windows the sandbox cannot yet see and refuse every connection an app's event loop makes"
           if sys.platform == "win32" else "")

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
def _read_json(p: Path, repo: Path) -> dict:
    """A JSON file of the project (`project_text`: a link that leads out of it, or a pipe, is a file that is not
    there), or {} when it cannot be used."""
    from .python_frontend import project_text
    try:
        d = json.loads(project_text(p, repo))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError, RecursionError):
        return {}


def _recorded(p: Path) -> dict:
    """What the tests' recorder left at `p`, or {}. The tests ran in the folder that holds it and could put anything
    under that name, so only a plain file is read (`results.plain`): not a link (it would be read wherever it leads)
    and not a pipe (reading one nobody writes to never ends, long after the tests were stopped), and only the rows
    that have the recorder's shape are kept (`trace.well_formed`)."""
    from .trace import well_formed
    try:
        return well_formed(json.loads(results.plain(p)[0] or "{}"))
    except (ValueError, RecursionError):
        return {"pairs": []}


def _observed(p: Path) -> dict:
    """What one of Lantern's own drivers (`INSIDE`) left at `p`, or {}. The project's code ran beside it and could
    put anything under that name, so it is read as `_recorded` reads: a plain file only, and of the driver's shape."""
    try:
        data = json.loads(results.plain(p)[0] or "{}")
    except (ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) and isinstance(data.get("probes"), list) and isinstance(data.get("seed"), dict) else {}


def _has(repo: Path, *files: Path) -> bool:
    """Whether one of these is a file of the project (`inside_repo`: not a link that leads out of it, whatever is
    or is not at the link's other end, and not a pipe)."""
    from .python_frontend import inside_repo
    return any(inside_repo(f, repo) for f in files)


def _js_command(pkg: Path, repo: Path) -> tuple[str, str] | None:
    d = _read_json(pkg, repo)
    script = (d.get("scripts") or {}).get("test") if isinstance(d.get("scripts"), dict) else None
    deps = {**(d.get("dependencies") or {}), **(d.get("devDependencies") or {})} if isinstance(d.get("devDependencies") or {}, dict) else {}
    root = pkg.parent
    pm = "pnpm" if _has(repo, root / "pnpm-lock.yaml") else "yarn" if _has(repo, root / "yarn.lock") else "npm"
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
    py = any(_has(repo, repo / f) for f in ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "requirements.txt"))
    has_py_tests = (any(d.is_dir() for d in (repo / "tests", repo / "test")) and _has(repo, *repo.glob("test*/**/*.py"))) \
        or _has(repo, *repo.glob("test_*.py")) or _has(repo, *repo.glob("*/tests/*.py"))
    if py or has_py_tests:
        return {"command": "python -m pytest -q", "how": "pyproject.toml / tests folder", "language": "python",
                "supported": True, "traced": True,
                "note": "Python tests are recorded function by function: calls they make turn solid on the map."}
    for pkg in [repo / "package.json", *sorted(repo.glob("*/package.json"))]:
        if _has(repo, pkg) and "node_modules" not in pkg.parts:
            js = _js_command(pkg, repo)
            if js:
                cmd, how = js
                if pkg.parent != repo:
                    how += f" (runs in {pkg.parent.name}/)"
                return {"command": cmd, "how": how, "language": "node", "cwd": pkg.parent.relative_to(repo).as_posix(),
                        "supported": True, "traced": False, "note": JS_NOTE}
    if _has(repo, repo / "go.mod"):
        return {"command": "go test ./...", "how": "go.mod", "language": "go", "supported": True, "traced": False, "note": JS_NOTE}
    if _has(repo, repo / "Cargo.toml"):
        return {"command": "cargo test", "how": "Cargo.toml", "language": "rust", "supported": True, "traced": False, "note": JS_NOTE}
    if _has(repo, repo / "pom.xml"):
        return {"command": "mvn -q -o test", "how": "pom.xml", "language": "java", "supported": True, "traced": False, "note": JS_NOTE}
    if _has(repo, repo / "build.gradle", repo / "build.gradle.kts"):
        cmd = "./gradlew test --offline" if _has(repo, repo / "gradlew") else "gradle test --offline"
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
    docker = programs.find("docker")
    if docker:
        try:
            r = subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=8, env=programs.env())
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


def _whole(x) -> int | None:
    """`x` as a whole number that is not negative, when it says one in plain figures: a number, or text of digits."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x if x >= 0 else None
    if isinstance(x, float):
        return int(x) if x.is_integer() and 0 <= x < 1e9 else None
    if isinstance(x, str) and x.strip().isascii() and x.strip().isdigit():
        return int(x.strip()) if len(x.strip()) <= 9 else 10 ** 9
    return None


def time_limit(minutes=None) -> int:
    """The seconds a project's tests get (2026-11-13; until then ten minutes whatever anybody wanted, and a suite
    that needs eleven could never get an answer). `minutes` is what the person asked for this run: a whole number
    from 1 to 240, and anything else is said (ValueError), never quietly made into another number, because the
    person would wait for a run that stops earlier than they think. With no word for this run, the installation's
    LANTERN_TEST_MINUTES counts (more than 240 is 240; anything that is no number of minutes is passed over), and
    with neither, ten minutes."""
    low, high = MINUTES
    if minutes is not None:
        n = _whole(minutes)
        if n is None or not low <= n <= high:
            raise ValueError(f"the time limit for the tests is a whole number of minutes from {low} to {high}")
        return n * 60
    n = _whole(os.environ.get(TIME_VARIABLE, ""))
    if n is None or n < low:
        return WALL_CLOCK
    return min(n, high) * 60


def time_asked(minutes=None) -> bool:
    """Whether a limit was set at all, for this run or for the installation: the older way of running tests (in the
    project's folder) keeps its own fifteen minutes when nobody said anything."""
    return minutes is not None or (_whole(os.environ.get(TIME_VARIABLE, "")) or 0) >= MINUTES[0]


def minutes_words(seconds) -> str:
    """A time limit in words: "10 minutes", "1 minute", and for a limit that is no whole number of minutes (a test's
    own, a few seconds) the seconds. Nothing is written for a value that is no sane number."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 < seconds <= MINUTES[1] * 60:
        return ""
    if seconds % 60:
        return f"{int(seconds)} second{'' if int(seconds) == 1 else 's'}"
    n = int(seconds // 60)
    return f"{n} minute{'' if n == 1 else 's'}"


def memory_limit(mb=None) -> int:
    """The megabytes of memory a project's tests may have in use, with everything they started (2026-11-13).
    `mb` is what the person asked for this run: a whole number from 128 to 1,048,576, and anything else is said
    (ValueError), never quietly made into another number. With no word for this run, the installation's
    LANTERN_TEST_MEMORY_MB counts (more than the most is the most; anything that is no such number is passed
    over), and with neither, 2 GB."""
    low, high = MEGABYTES
    if mb is not None:
        n = _whole(mb)
        if n is None or not low <= n <= high:
            raise ValueError(f"the memory limit for the tests is a whole number of megabytes from {low} to {high}")
        return n
    n = _whole(os.environ.get(MEMORY_VARIABLE, ""))
    if n is None or n < low:
        return MEMORY_MB
    return min(n, high)


def memory_words(mb) -> str:
    """A memory limit in words: "2 GB", "256 MB". Nothing is written for a value that is no sane number."""
    if isinstance(mb, bool) or not isinstance(mb, int) or not 0 < mb <= MEGABYTES[1]:
        return ""
    return f"{mb // 1024} GB" if mb % 1024 == 0 else f"{mb} MB"


COPY_WORDS = ("a fresh copy of your project in a temp folder, deleted after: the tests can change the copy and "
              "nothing else")


def describe(repo: Path, language: str, minutes=None, memory=None) -> dict:
    """What the sheet shows before the user clicks Run: the walls this system's sandbox has. Each line is something
    that is either put in place or, when it cannot be, keeps the tests from running (`Unavailable`), and the last
    line says so. A promise is made only where it is kept: "everything it started is stopped" needs the launcher's
    supervisor (Linux) or the job (Windows), and memory in use is counted by Docker and by that supervisor.
    `minutes`, `memory`: the limits this run would have (`time_limit`, `memory_limit`)."""
    b = backend_for(language)
    limit = minutes_words(time_limit(minutes))
    room = memory_words(memory_limit(memory))
    without = "if any of this cannot be set up, your tests are not run"
    if b == "docker":
        return {"name": "docker", "label": "Docker container", "image": image_for(language),
                "details": [COPY_WORDS,
                            "network off (--network none): the tests can listen and call what they started "
                            "inside the container, and reach nothing outside it",
                            f"2 CPUs, {room} memory, {limit}", "runs as an unprivileged user; scratch space is wiped after",
                            without]}
    det = [COPY_WORDS,
           "your environment variables are not passed on (no keys or tokens)",
           f"{limit}, then everything it started is stopped" if _LINUX or sys.platform == "win32" else
           f"{limit}, then the tests are stopped (a program they moved out of their group is not found again)"]
    no_own = own_network()
    if not no_own:
        if landlock_abi() >= 1:
            det.insert(1, "writes allowed only in the copy and its own temp folder")
        if language == "python":
            det.insert(1, "writing outside the copy and its temp folder is refused")
        det.insert(1, "a network of its own: the tests can listen and call what they started on this computer's "
                      "own address; the internet, your network and the addresses your other programs listen at "
                      "are out of reach")
    else:
        if sys.platform.startswith("linux") and landlock_abi() >= 1:
            det.insert(1, "writes allowed only in the copy and its own temp folder" + (", network connections refused" if landlock_abi() >= 4 else ""))
        if language == "python":
            det.insert(1, "writing outside the copy and its temp folder and opening network connections are refused")
        det.insert(2 if language == "python" else 1, NO_OWN_NETWORK.format(why=no_own))
    if sys.platform == "win32":
        det.insert(1, f"inside a Windows job: {room} of memory for each process, and nothing it starts can leave the job")
    if _LINUX:
        det.append(f"{room} of memory for the tests and everything they start, counted together; tests that use "
                   "more are stopped, which is neither a pass nor a failure")
    det.append(without)
    return {"name": "subprocess", "label": "Restricted process on this computer", "image": None, "details": det}


# ---------------------------------------------------------------------------- a network of the run's own
NO_OWN_NETWORK = ("{why}, so nothing on this computer is let through either: tests that start a server and call "
                  "it will fail here")
_OWN_NETWORK: list[str] = []          # the answer of `own_network`, asked once


def own_network() -> str:
    """Can the restricted subprocess give a run a network of its own on this system (this module's opening text)?
    "" when it can, else why not, in words for a person. Asked once: a throwaway process tries what the launcher
    will do (`_jail.try_own_network`), since the answer depends on the kernel and on what this system lets a
    user do, and trying is the only way to know."""
    if _OWN_NETWORK:
        return _OWN_NETWORK[0]
    if not _LINUX:
        why = "a network of their own for the tests is made on Linux only"
    else:
        nobody = hasattr(os, "geteuid") and os.geteuid() == 0
        code = (f"import sys; sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r}); "
                f"from lantern import _jail; sys.exit(min(_jail.try_own_network({nobody!r}), 255))")
        try:
            r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=60, env=programs.env())
            number = r.returncode
        except (OSError, subprocess.SubprocessError):
            number = -1
        why = "" if number == 0 else ("this system does not let the tests have a network of their own"
                                      + (f" (error {number})" if number > 0 else ""))
    _OWN_NETWORK.append(why)
    return why


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
# Lantern test sandbox: refuse writes outside the folders the run may write in (LANTERN_SANDBOX_WRITABLE: its temp
# folder and, for a project's tests, their copy of the project) and any network connection, except, in a network
# of the run's own, to this computer itself.
# Installed as sitecustomize so it is in place before the tests import anything; audit hooks cannot be removed.
import os as _os, sys as _sys, socket as _socket
_W = [_os.path.realpath(p) for p in _os.environ.get("LANTERN_SANDBOX_WRITABLE", "").split(_os.pathsep) if p]
_DEV = {_os.devnull, "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}
_NET = {getattr(_socket, "AF_INET", 2), getattr(_socket, "AF_INET6", 10)}
_UNIX = getattr(_socket, "AF_UNIX", None)
try:
    _SELF = (_socket.gethostname(),)
except OSError:
    _SELF = ()
def _own_network():
    # Is this process in a network of the run's own, which holds this computer's own address and nothing else?
    # The launcher says so after it made one, by the network's number in the kernel (LANTERN_SANDBOX_NET=own:<n>,
    # lantern._jail), and Docker's container is one ("container": --network none). The guard looks for itself:
    # the number must be this process's own network's, and no way out may be switched on in it. Anything else
    # (no word, another number, a system that cannot say) leaves every address refused, as before.
    said = _os.environ.get("LANTERN_SANDBOX_NET", "")
    try:
        if said != "container" and said != "own:%d" % _os.stat("/proc/self/ns/net").st_ino:
            return False
        import fcntl, struct
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            for _, name in _socket.if_nameindex():
                if name != "lo":      # 0x8913: SIOCGIFFLAGS; 0x1: IFF_UP
                    asked = fcntl.ioctl(s, 0x8913, struct.pack("16sH22s", name.encode()[:15], 0, b""))
                    if struct.unpack("16sH22s", asked)[1] & 0x1:
                        return False
        return True
    except Exception:
        return False
_OWN = _own_network()
def _here(addr):
    # An address of this computer itself, as it is written: nothing is looked up to decide it.
    host = addr[0] if isinstance(addr, tuple) and addr else addr
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    h = host.lower()
    if h in ("", "localhost", "::1", "::", "0.0.0.0") or host in _SELF:
        return True
    if h.startswith("::ffff:"):
        h = h[7:]
    p = h.split(".")
    return len(p) == 4 and p[0] == "127" and all(x.isdigit() and int(x) < 256 for x in p)
def _number(host):
    # An address written out as a number: asking where it is asks nothing of any name server, the answer is the
    # number itself. Read strictly, so that what is not surely a number is still a name: four plain decimal parts
    # up to 255 with no zero in front, or what this system reads as an IPv6 address, and nothing around it.
    if isinstance(host, (bytes, bytearray)):
        try:
            host = bytes(host).decode("ascii")
        except ValueError:
            return False
    if not isinstance(host, str) or not host.isascii():
        return False
    p = host.split(".")
    if len(p) == 4 and all(x.isdigit() and len(x) < 4 and int(x) < 256 and (x == "0" or x[0] != "0") for x in p):
        return True
    if ":" in host and all(c in "0123456789abcdefABCDEF:." for c in host):
        try:
            _socket.inet_pton(_socket.AF_INET6, host)
            return True
        except (OSError, ValueError, AttributeError):
            return False
    return False
_WFLAGS = _os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_APPEND | getattr(_os, "O_TRUNC", 0)
for _p in _os.environ.get("LANTERN_SANDBOX_SITE", "").split(_os.pathsep):
    if _p and _p not in _sys.path:   # the host's packages (Docker); their .pth files name host paths, so skip them
        _sys.path.append(_p)
try:
    import fcntl as _fcntl
except ImportError:
    _fcntl = None
def _at(fd):
    # the folder an open folder handle is for; None when this system cannot say
    try:
        return _os.readlink("/proc/self/fd/%d" % fd)
    except OSError:
        pass
    try:
        return _os.fsdecode(_fcntl.fcntl(fd, _fcntl.F_GETPATH, bytes(1024)).split(b"\0", 1)[0])
    except (AttributeError, OSError, ValueError):
        return None
def _full(path, fd=None):
    # A name given beside an open folder (os.unlink(name, dir_fd=fd): how shutil.rmtree and TemporaryDirectory
    # remove a tree) is a file of that folder, not of the current one. None: where that folder is cannot be told.
    p = _os.fsdecode(path)
    if isinstance(fd, int) and fd >= 0 and not _os.path.isabs(p):
        base = _at(fd)
        return None if base is None else _os.path.join(base, p)
    return p
def _plain(n):
    # one name with nothing around it: no folder in front of it, and not "this folder" or "the one above"
    return n not in ("", ".", "..") and "/" not in n and _os.sep not in n and not (_os.altsep and _os.altsep in n)
def _link(n, fd=None):
    # is the thing under this name a link? What cannot be looked at counts as one (it is then followed and judged).
    try:
        st = _os.lstat(n) if fd is None else _os.lstat(n, dir_fd=fd)
        return (st.st_mode & 0o170000) == 0o120000
    except FileNotFoundError:
        return False
    except (OSError, TypeError, ValueError, NotImplementedError):
        return True
def _far(name, fd, follow=True):
    # A name beside an open folder whose own path this system does not hand back: it is longer than a path may be
    # (many folders inside each other). Let through only when it is one plain name (and, where what is done goes
    # through a link, no link there), and the folder, followed upwards one folder at a time, comes to one whose
    # path can be read and that lies in a folder the run may write in. (What lies beneath such a folder lies in it.)
    up = None
    try:
        n = _os.fsdecode(name)
        if not _plain(n) or (follow and _link(n, fd)):
            return False
        cur = fd
        for _ in range(1 << 16):
            above = _os.open("..", _os.O_RDONLY | getattr(_os, "O_DIRECTORY", 0) | getattr(_os, "O_CLOEXEC", 0), dir_fd=cur)
            if up is not None:
                _os.close(up)
            up = cur = above
            base = _at(up)
            if base is not None:
                base = _os.path.realpath(base)
                return any(base == w or base.startswith(w + _os.sep) for w in _W)
        return False
    except (OSError, TypeError, ValueError, NotImplementedError):
        return False
    finally:
        if up is not None:
            try:
                _os.close(up)
            except OSError:
                pass
_PROC = _sys.platform.startswith("linux")     # there the system's word for an open folder's place has no link in it
def _ok(path, fd=None, follow=True):
    # Is what this name stands for in a folder the run may write in? `follow`: what is done goes through a link at
    # the name's end (a write, a change of rights or dates), so the place the link names is judged. Not followed
    # (removing, renaming, making): the name itself is what changes and a link under it is only a name, judged by
    # the folder it is in. Until 2026-11-13 every name was followed, and a test could not remove a link it had made
    # to anything outside its folders (a virtual environment's link to Python). A name that ends in a slash is
    # followed whatever is done: the system then goes through a link to a folder.
    try:
        n = _os.fsdecode(path)
        if isinstance(fd, int) and fd >= 0 and not _os.path.isabs(n):
            base = _at(fd)
            if base is None:
                return _far(n, fd, follow)
            if _plain(n) and not (follow and _link(n, fd)):
                # nothing at the name's end to follow, and the folder is where the system says the open folder is
                p = _os.path.join(base if _PROC else _os.path.realpath(base), n)
            else:
                p = _os.path.realpath(_os.path.join(base, n))
        elif follow:
            p = _os.path.realpath(n)
        else:
            head, tail = _os.path.split(n)
            p = _os.path.join(_os.path.realpath(head or _os.curdir), tail) if _plain(tail) else _os.path.realpath(n)
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
# event -> (where the path is among its arguments, where the open folder it may be named beside is, whether what
# is done goes through a link at the name's end). A second name for a file (os.link) is the file itself, so the
# file must be the run's own too: until 2026-11-13 only the new name was looked at, and where no kernel wall
# stands behind this guard a file outside could be given a name inside and changed under it.
_PATHS = {"os.remove": ((0, 1, 0),), "os.rmdir": ((0, 1, 0),), "os.mkdir": ((0, 2, 0),),
          "os.rename": ((0, 2, 0), (1, 3, 0)), "os.replace": ((0, 2, 0), (1, 3, 0)), "os.symlink": ((1, 2, 0),),
          "os.link": ((0, 2, 1), (1, 3, 0)), "os.truncate": ((0, None, 1),), "os.chmod": ((0, 2, 1),),
          "os.chown": ((0, 3, 1),), "os.utime": ((0, 3, 1),), "shutil.rmtree": ((0, 1, 0),),
          "shutil.copyfile": ((1, None, 1),), "shutil.move": ((1, None, 1),)}
def _judge(ev, args):
    if ev == "open":
        path, mode, flags = (tuple(args) + (None, None, None))[:3]
        if isinstance(path, int) or path is None:
            return
        w = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & _WFLAGS)
        if w and not _ok(path):
            _block("write to " + _os.fsdecode(path))
    elif ev in _PATHS:
        for i, at, follow in _PATHS[ev]:
            p = args[i] if i < len(args) else None
            fd = args[at] if at is not None and at < len(args) else None
            if p is not None and not isinstance(p, int) and not _ok(p, fd, follow):
                _block(ev.split(".")[-1] + " " + (_full(p, fd) or _os.fsdecode(p)))
    elif ev == "sqlite3.connect":
        # SQLite opens and writes its files itself, below Python: a database file outside the folders the run may
        # write in is refused when it could be changed or would be made. One that cannot be written (a file of
        # the copy an app is started on, which is read-only) can still be read.
        db = args[0] if args else None
        if isinstance(db, (str, bytes)) or hasattr(db, "__fspath__"):
            p = _os.fsdecode(db)
            if p.startswith("file:"):
                p, _, q = p[5:].partition("?")
                p = "" if "mode=memory" in q else ("/" + p.lstrip("/") if p.startswith("//") else p)
            if p and p != ":memory:" and not _ok(p) and (not _os.path.exists(p) or _os.access(p, _os.W_OK)):
                _block("write to " + p)
    elif ev in ("socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg"):
        s = args[0]
        fam = getattr(s, "family", None)
        to = args[1] if len(args) > 1 else None
        if fam in _NET:
            # In a network of the run's own: listening anywhere (there is only this computer in it), and calling
            # or sending to this computer's own address. Any other address is refused before it is tried, so
            # the run's log says what the tests reached for.
            if not (_OWN and (ev == "socket.bind" or to is None or _here(to))):
                _block("network " + ev.split(".")[1] + " " + repr("" if to is None else to)[:80])
        elif fam == _UNIX and fam is not None and isinstance(to, (str, bytes, bytearray)) and to:
            # A socket file is how the programs of one computer talk to each other (a desktop's message bus,
            # Docker): one outside the run's own folders is another program's, or would be made where the tests
            # may not write. A socket name that is no file (Linux) is kept apart only in a network of the run's own.
            name = _os.fsdecode(bytes(to)) if not isinstance(to, str) else to
            if name[:1] == "\0":
                if not _OWN:
                    _block("network " + ev.split(".")[1] + " to the socket name " + repr(name[1:])[:80])
            elif not _ok(name):
                _block("network " + ev.split(".")[1] + " to the socket file " + name[:200])
    elif ev in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"):
        # This computer under its own names is no question to the network, and neither is where an address written
        # as a number is. Who a number belongs to (gethostbyaddr) is one.
        host = args[0] if args else None
        if host not in (None, "", "localhost", "127.0.0.1", "::1", b"localhost") and host not in _SELF \
                and not (ev != "socket.gethostbyaddr" and _number(host)):
            _block("network lookup " + repr(host)[:80])
# A guard the project brings itself (an audit hook of its own) has its say first. Python calls hooks in the order
# they were added and this guard is the first, so a hook added later never saw what is refused here: a project's
# tests of its own guard failed in the sandbox with the sandbox's words. So the hooks a program adds are kept here
# and called from this guard's one hook, in their order, between writing this guard's line down and refusing: a
# hook of the project may refuse its own way, and whatever it lets through is refused as it always was. Nothing is
# remembered from one event to the next. A hook added any other way stands behind this guard in Python's own list
# and sees only what the guard let through, as until now.
_THEIRS = []
def _hook(ev, args, judge=_judge, theirs=_THEIRS):
    said = None
    try:
        judge(ev, args)
    except PermissionError as e:
        if not theirs:
            raise
        said = e.args
    for hook in theirs:      # one that arrives in the middle of an event is called for it too, as Python does it
        hook(ev, args)
    if said is not None:
        raise PermissionError(*said)
def _add(hook):
    try:
        _sys.audit("sys.addaudithook")
    except Exception:        # Python's own rule: a hook already there may keep a newcomer out, and nothing is said
        return
    _THEIRS.append(hook)
_add.__name__ = _add.__qualname__ = "addaudithook"
_add.__module__, _add.__doc__ = "sys", _sys.addaudithook.__doc__
_sys.addaudithook(_hook)
_sys.addaudithook = _add
_sys.lantern_sandbox_guard = "on"   # lantern.tracehook looks for this before it runs a test (LANTERN_SANDBOX_GUARD)
'''


# ---------------------------------------------------------------------------- running
class Result(dict):
    pass


def _copy(repo: Path, dst: Path) -> None:
    def ignore(d, names):
        return [n for n in names if n in SKIP]
    shutil.copytree(repo, dst, symlinks=True, ignore=ignore)


def _copy_in(repo: Path, app: Path, log) -> None:
    """The project's copy for one run, or `Unavailable` with the reason when it cannot be made."""
    log("sandbox: copying the project to a temp folder")
    try:
        _copy(repo, app)
    except RecursionError as e:   # the standard library copies by calling itself once per folder level
        raise Unavailable("the project could not be copied into the sandbox's temp folder "
                          "(its folders are nested too deep)") from e
    except OSError as e:
        first = e.args[0][0] if isinstance(e, shutil.Error) and e.args and e.args[0] else None
        what = f"{first[0]}: {first[2]}" if isinstance(first, (tuple, list)) and len(first) >= 3 else (e.strerror or type(e).__name__)
        raise Unavailable(f"the project could not be copied into the sandbox's temp folder ({str(what)[:200]})") from e


def _hand_over(folder: Path, uid: int, gid: int) -> None:
    """Give a folder Lantern made, with all that is in it, to the user the tests run as (Lantern is root, the tests
    are `nobody`). Each thing is handed over as itself: a link the project brought is not followed, to a file or
    to a folder, so nothing outside the folder changes hands."""
    for dirpath, dirs, files in os.walk(folder):     # a link to a folder is listed and not entered
        for name in dirs + files:
            os.chown(os.path.join(dirpath, name), uid, gid, follow_symlinks=False)
    os.chown(folder, uid, gid, follow_symlinks=False)


_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


def _make_read_only(root: Path) -> None:
    """Take every write bit off a copy (read and execute bits are left as they were). For the copy an app is
    started on by one of Lantern's own drivers (`run_inside`); the copy a project's tests get is theirs to change."""
    for dirpath, _dirs, files in os.walk(root, topdown=False):
        for f in files:
            p = os.path.join(dirpath, f)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode & ~_WRITE_BITS)
        os.chmod(dirpath, os.stat(dirpath).st_mode & ~_WRITE_BITS)


def _rm(path: Path) -> bool:
    """Delete a folder the sandbox made, with all that is in it. True when nothing is left of it.

    Only what is inside `path` is changed (`lantern.removal`). Until 2026-11-10 a link in the copy that pointed at a
    folder outside had that folder's mode changed, and when the folder could not be deleted the mode of the folder
    it is in was set to owner-only: the system's temp folder, for all its users, when Lantern ran as root. Both
    without a word, and with the folder still there. A copy nested deeper than about a thousand folders was not
    deleted at all: the standard library's delete stopped with RecursionError (Python 3.11 and 3.12)."""
    return removal.remove(path) is None


def _retry_left(log) -> None:
    """Delete the temp folders an earlier run had to leave (`removal.note`), and say what became of them."""
    try:
        r = removal.retry_noted()
    except Exception:  # noqa: BLE001 - a tidy-up of old folders never keeps the tests from running
        return
    if r["removed"]:
        log(f"sandbox: {r['removed']} temp folder{'s' if r['removed'] != 1 else ''} an earlier run could not delete "
            f"{'are' if r['removed'] != 1 else 'is'} deleted now")
    for p in r["waiting"]:
        log(f"sandbox: a temp folder an earlier run could not delete is still there: {p}")


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


def _windows_job(memory: int = MEMORY_MB):
    """Windows: the Job Object a project's tests run in (`memory` megabytes for each process; every process in it
    ends when the job is stopped or closed, and nothing started inside can leave it). None on other systems, where
    `lantern._jail` does that work. `Unavailable` when Windows does not make it: the tests are then not run."""
    if sys.platform != "win32":
        return None
    from . import winjob
    try:
        return winjob.Job(memory << 20)
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


def _over_memory(rc, output: str) -> bool:
    """The launcher stopped the command because of the memory in use: its own result together with its own line.
    Either alone is the tests' own (a test may print anything and end with any number)."""
    from . import _jail
    if rc != _jail.OVER_MEMORY:
        return False
    for line in output.splitlines():
        parts = line.split()
        if (len(parts) == 4 and parts[0] == _jail.LIMIT_MARK and parts[1] == "memory" and parts[2].isdigit()
                and parts[3].isdigit()):
            return True
    return False


def _docker_oom(docker: str, name: str) -> bool:
    """Whether Docker ended a program of this container because the container was over its memory. Docker's own
    answer about the container, asked after its command ended with an error; anything but a plain yes is a no."""
    try:
        r = subprocess.run([docker, "inspect", "--format", "{{.State.OOMKilled}}", name], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=30, env=programs.env())
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and r.stdout.strip() == "true"


def _over_words(mb: int) -> str:
    had = memory_words(mb)
    return "because the tests used more memory than their limit" + (f" ({had})" if had else "")


# What a program says when the kernel refused it the network: C's and Python's words, Go's (lower case), and
# Node's names for the same errors (`connect ENETUNREACH 192.0.2.1:80`, `listen EACCES: permission denied
# 127.0.0.1`, `getaddrinfo EAI_AGAIN example.com`). Until 2026-11-13 only the first two were known, so a
# JavaScript test the sandbox had stopped was reported as a plain failure of the project's tests.
_NO_NETWORK = re.compile(r"Network is unreachable|network is unreachable|Temporary failure in name resolution"
                         r"|\b(?:connect|listen|bind|send|getaddrinfo) (?:ENETUNREACH|EACCES|EPERM|EAI_AGAIN)\b")


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
            why = "write to a file that cannot be changed (the tests may write in their copy of the project and in /tmp)"
        elif _NO_NETWORK.search(line):
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
        cwd_rel: str = "", cancel=None, memory=None) -> Result:
    """Run the test command `words` for `repo` in the sandbox. Returns trace data for `trace.merge_trace` (`pairs`)
    plus `backend`, `language`, `traced`, `returncode`, `timed_out`, `over_memory` (the tests were stopped because
    they, with what they started, used more memory than `memory_limit`, the megabytes they had), `cancelled`,
    `blocked`, `not_ended` (what the tests started and Lantern could not end, in its own words; empty when nothing
    is left), `own_network` (the tests had a network of their own, where they could listen and call what they
    started), `output_tail`, `stderr_tail`. `memory`: the megabytes for this run (`memory_limit`; ValueError for
    anything that is no such number). `cancel`: a threading.Event; once set, the tests and everything they
    started are ended. Raises `Unavailable` when the sandbox cannot be set up: the tests were then not run."""
    repo = Path(repo).resolve()
    language = check_command(words)
    backend = backend or backend_for(language)
    memory = memory_limit(memory)
    me = _Going(cancel)
    with _LIVE_LOCK:
        _GOING.add(me)
    try:
        _retry_left(log)         # what an earlier run could not delete, tried again before this one makes its own
        root = Path(tempfile.mkdtemp(prefix="lantern-sandbox-"))
        try:
            if backend == "docker":
                res = _run_docker(repo, words, language, root, log, timeout, cwd_rel, me, memory=memory)
            else:
                res = _run_subprocess(repo, words, language, root, log, timeout, cwd_rel, me, memory=memory)
        finally:
            if not _rm(root):
                log(f"sandbox: its temp folder could not be deleted and is still there: {root}")
                removal.note(root)   # written down: the next run deletes it, if it is still the folder made here
    finally:
        with _LIVE_LOCK:
            _GOING.discard(me)
        me.done.set()            # stop_all() waits for this, so the program does not leave in the middle of the lines above
    res.update(backend=backend, language=language, traced=language == "python", memory_limit=memory)
    res.setdefault("own_network", False)
    res.setdefault("over_memory", False)
    res["cancelled"] = res.get("returncode") is None and not res.get("timed_out") and not res.get("over_memory")
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


def run_inside(repo: Path, module: str, scene: dict, log=print, timeout: float = WALL_CLOCK, cancel=None) -> Result:
    """Start one of Lantern's own drivers (`INSIDE`) on a copy of the project in the restricted process: no
    network, writes only in the sandbox's temp folder, never Docker. `scene` goes in as a file and what the driver
    wrote down comes back as `observed` ({} when it left nothing that can be read). The promises are `run`'s:
    `Unavailable` when the sandbox cannot be set up, or starts no app on this system (`NO_APPS`): the project's code
    was then not started. Everything the driver started is ended when it ends, at the time limit and when `cancel`
    is set."""
    if module not in INSIDE:
        raise ValueError("not one of Lantern's own drivers")
    if NO_APPS:
        raise Unavailable(NO_APPS)
    repo = Path(repo).resolve()
    me = _Going(cancel)
    with _LIVE_LOCK:
        _GOING.add(me)
    try:
        _retry_left(log)
        root = Path(tempfile.mkdtemp(prefix="lantern-sandbox-"))
        try:
            res = _run_subprocess(repo, [module], "python", root, log, timeout, "", me, inside=(module, scene),
                                  memory=memory_limit())
        finally:
            if not _rm(root):
                log(f"sandbox: its temp folder could not be deleted and is still there: {root}")
                removal.note(root)
    finally:
        with _LIVE_LOCK:
            _GOING.discard(me)
        me.done.set()
    res.update(backend="subprocess", language="python")
    res.setdefault("over_memory", False)
    res["cancelled"] = res.get("returncode") is None and not res.get("timed_out") and not res.get("over_memory")
    res["blocked"] = blocked_reasons(res.get("output_tail", "") + "\n" + res.pop("_full", ""))
    return res


def _processors() -> int:
    """How many processors a run may use at once."""
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def _made_of(pkg_root: str) -> list[str]:
    """What a Python that runs a project's tests is made of, besides the program itself: Lantern's tracer, Python's
    own library and the folders its installed libraries are in (where the test runner is)."""
    import sysconfig
    places = [str(Path(pkg_root) / "lantern" / "tracehook.py"), os.path.dirname(os.__file__)]
    for name in ("purelib", "platlib"):
        try:
            place = sysconfig.get_path(name)
        except (KeyError, ValueError):
            place = None
        if place and os.path.isdir(place) and place not in places:
            places.append(place)
    return places


def _run_subprocess(repo, words, language, root, log, timeout, cwd_rel, cancel=None, inside=None,
                    memory: int = MEMORY_MB) -> Result:
    from . import _jail
    app, tmp, hook = root / "app", root / "tmp", root / "hook"
    as_nobody = hasattr(os, "geteuid") and os.geteuid() == 0
    # A project's tests may change their copy (2026-11-13): what tests do at home, writing a file beside the code or
    # copying a sample folder and writing into the copy, works here too, and the copy is thrown away with the run.
    # An app started by one of Lantern's own drivers gets a copy it cannot change, as before: there a write
    # outside the app's data folder is what the check is looking for.
    theirs = inside is None
    writable = [tmp, app] if theirs else [tmp]
    try:
        tmp.mkdir()
        hook.mkdir()
        (hook / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
        if inside is not None:      # the scene of one of Lantern's own drivers, written before the folder changes hands
            (tmp / "behave.scene.json").write_text(json.dumps(inside[1]), encoding="utf-8")
        _copy_in(repo, app, log)
        if not theirs:
            _make_read_only(app)
        env = _env_base(tmp)
        env["LANTERN_SANDBOX_WRITABLE"] = os.pathsep.join(str(w) for w in writable)
        if as_nobody:   # root ignores file modes: run the tests as nobody, who owns the sandbox folder, its temp
            _hand_over(tmp, 65534, 65534)       # folder and, for a project's tests, the copy
            if theirs:  # also what only its owner may read (a key file, a folder made under a strict umask)
                _hand_over(app, 65534, 65534)
            os.chown(root, 65534, 65534)   # mode stays 0700; an app's copy keeps root as owner and no write bits
            _others_may_read(hook)
    except OSError as e:
        raise Unavailable("the sandbox's temp folder could not be made ready for the tests "
                          f"({e.strerror or type(e).__name__})") from e
    out_json = tmp / ("behave.observed.json" if inside is not None else "trace.json")
    pkg_root = str(Path(__file__).resolve().parent.parent)
    made_of: list[str] = []         # what the tests' user must be able to read, or the launcher starts nothing
    if language == "python":
        made_of = _made_of(pkg_root)
        env["PYTHONPATH"] = os.pathsep.join([str(hook), pkg_root, str(app)])
        env["LANTERN_SANDBOX_GUARD"] = "required"   # lantern.tracehook runs no test without the guard above
        cmd = [sys.executable, "-m", "lantern.tracehook", str(out_json), str(app), "--", *_python_argv(words)]
        if inside is not None:
            cmd = programs.python(inside[0], str(tmp / "behave.scene.json"), str(out_json), str(app))
    else:
        exe = programs.find(words[0], env.get("PATH")) or (str(app / words[0]) if words[0].startswith("./") else words[0])
        cmd = [exe, *words[1:]]
    cwd = app / cwd_rel if cwd_rel else app
    no_own = own_network()
    if os.name == "posix":
        policy = {"writable": [str(w) for w in writable], "nobody": as_nobody, "python": language == "python",
                  "net": True, "own_net": not no_own, "net_told": inside is None, "must": True,
                  "parent": os.getpid(), "cpu": max(WALL_CLOCK, int(timeout)) * _processors(), "memory": memory << 20,
                  "readable": made_of, "runs": cmd[0] if os.path.isabs(cmd[0]) else ""}
        # One of Lantern's own drivers (`run_inside`) gets the network too, which no other language's code can
        # leave, and is not told: `lantern.behave` reads what an app reached for from what the guard refused,
        # this computer's own address included, so there the guard goes on refusing every address.
        cmd = [sys.executable, "-I", "-m", "lantern._jail", json.dumps(policy), "--", *cmd]
        env_jail = dict(env)
        env_jail["PYTHONPATH"] = env.get("PYTHONPATH", "") if language == "python" else ""
        env = env_jail
        # -I ignores PYTHONPATH for the jail itself; it finds lantern from its own path below
        cmd[2:4] = ["-c", f"import sys; sys.path.insert(0, {pkg_root!r}); from lantern._jail import main; main(sys.argv[1:])"]
    log(f"sandbox: restricted process, running {' '.join(words)}")
    if no_own and inside is None:
        log("sandbox: the tests have no network of their own (" + NO_OWN_NETWORK.format(why=no_own) + ")")
    if inside is not None:
        log("sandbox: the project's app is started by Lantern's own driver, with no network")
    left: list[str] = []
    rc, output, timed_out = _stream(cmd, cwd, env, timeout, log, job=lambda: _windows_job(memory), cancel=cancel,
                                    ask=_jail.ASK if _LINUX else 0.0, left=left)
    why = _unavailable(rc, output)
    if why:
        raise Unavailable(why)
    if os.name == "posix":
        left += _left_by_launcher(output)
    over = os.name == "posix" and _over_memory(rc, output)
    if over:        # stopped by the launcher, which had ended everything before it said so: no result of the tests' own
        rc = None
        log(_stopped(_over_words(memory), left, "every process it started was ended"))
    elif timed_out:
        log(_stopped(f"after {int(timeout)} s (the wall clock)", left, "every process it started was ended"))
    elif rc is None:
        log(_stopped("because it was asked to", left, "every process it started was ended"))
    if inside is not None:
        return Result(observed=_observed(out_json), returncode=rc, timed_out=timed_out, over_memory=over,
                      output_tail=output[-6000:], _full=output, not_ended=left, own_network=False)
    data = _recorded(out_json)
    _map_pairs(data, str(app), repo)
    # `own_network` is what the launcher was told to make: a launcher that could not make it starts nothing
    return Result(pairs=data.get("pairs", []), returncode=rc, timed_out=timed_out, over_memory=over,
                  output_tail=output[-6000:], _full=output, not_ended=left, own_network=not no_own)


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


def _run_docker(repo, words, language, root, log, timeout, cwd_rel, cancel=None, memory: int = MEMORY_MB) -> Result:
    img = image_for(language)
    if not img:
        raise RuntimeError(f"no pinned Docker image for {language}")
    out, hook, app = root / "out", root / "hook", root / "app"
    out.mkdir()
    hook.mkdir()
    # The tests get a copy of the project, theirs to change and thrown away with the run (2026-11-13; until then
    # the project itself was mounted and could not be written, so a test that writes beside its code failed).
    _copy_in(repo, app, log)
    # the container runs as the user who runs Lantern (or nobody, when that is root), who owns /out and the copy
    uid, gid = (os.getuid(), os.getgid()) if os.getuid() != 0 else (65534, 65534)
    if os.getuid() == 0:
        os.chown(out, uid, gid)
        try:
            _hand_over(app, uid, gid)
        except OSError as e:
            raise Unavailable("the project's copy could not be handed to the user the tests run as "
                              f"({e.strerror or type(e).__name__})") from e
    (hook / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
    if os.getuid() == 0:
        _others_may_read(hook)
    name = "lantern-sbx-" + uuid.uuid4().hex[:12]
    pkg = Path(__file__).resolve().parent
    docker = programs.find("docker")     # by its full path, from a folder PATH names in full
    if not docker:
        raise Unavailable("Docker is not installed (no docker program in the folders PATH names)")
    # No `--rm`: the container stays until `remove` below, so that Docker can be asked why a command that ended
    # with an error did (`_docker_oom`). Memory in use only, no swap beside it: the limit means what it says.
    args = [docker, "run", "--name", name, "--network", "none", "--cpus", "2", "--memory", f"{memory}m",
            "--memory-swap", f"{memory}m", "--pids-limit", "512", "--user", f"{uid}:{gid}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,exec,size=1g,mode=1777",  # nosec B108: the container's own tmpfs
            "-v", f"{app}:/app:rw", "-v", f"{out}:/out:rw", "-v", f"{hook}:/opt/hook:ro",
            "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp", "-e", "CI=true", "-e", "NO_COLOR=1",
            "-e", "LANTERN_SANDBOX_WRITABLE=" + os.pathsep.join(["/tmp", "/out", "/app"]), "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "LANTERN_SANDBOX_NET=container",      # --network none: the container's network is its own
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
    log(f"sandbox: Docker ({img.split('@')[0]}, network off, a copy of the project), running {' '.join(words)}")
    def remove() -> str | None:
        """The docker program was only the container's client: the container goes with this. None when it is gone,
        else the words for it (until 2026-11-10 the answer was not looked at)."""
        try:
            r = subprocess.run([docker, "rm", "-f", name], capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=30, env=programs.env())
        except (OSError, subprocess.SubprocessError) as e:
            return f"its Docker container {name} may still be running: docker rm could not be run ({type(e).__name__})"
        if r.returncode != 0 and "No such container" not in (r.stderr or ""):
            return f"its Docker container {name} may still be running: docker rm ended with {r.returncode}"
        return None
    left: list[str] = []
    rc, output, timed_out = _stream(args + [img, *cmd], root, programs.env(), timeout, log,
                                    cancel=cancel, also=remove, left=left)
    why = _unavailable(rc, output)
    if why:
        raise Unavailable(why)
    over = rc not in (None, 0, 125) and _docker_oom(docker, name)
    if rc is not None:      # ended by itself: the container is still there (a stopped run's was removed by `_stream`)
        problem = remove()
        if problem:
            left.append(problem)
            log("sandbox: " + problem)
    if rc == 125 and any(line.startswith("docker: ") for line in output.splitlines()):
        # the docker program's own result and words when Docker itself failed: no container, so no test has run
        raise Unavailable("Docker could not start the container the tests run in (docker run ended with 125; "
                          "what Docker said is in the log)")
    if over:
        rc = None
        log(_stopped(_over_words(memory), left, "the container was removed"))
    elif timed_out:
        log(_stopped(f"after {int(timeout)} s (the wall clock)", left, "the container was removed"))
    elif rc is None:
        log(_stopped("because it was asked to", left, "the container was removed"))
    data = _recorded(out / "trace.json")
    _map_pairs(data, "/app", repo)
    return Result(pairs=data.get("pairs", []), returncode=rc, timed_out=timed_out, over_memory=over,
                  output_tail=output[-6000:], _full=output, not_ended=left, own_network=True)
