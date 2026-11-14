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
That refusal is the hook's, inside Python. Whether a program of the tests that is not Python is kept from the
network there too is another question (`held_below_python`, 2026-11-14): on Linux the kernel's rule for
connections (Landlock, Linux 6.7) or the doorman below answers it; on macOS and Windows nothing of Lantern's does,
and neither does a run inside another sandbox whose doorman makes its connections (there the outer sandbox's walls
decide). Until then the sheet and the log said "nothing on this computer is let through" in all of those places;
now they say which it is (`NOT_HELD`, `NOT_HELD_BESIDE`, `INSIDE_ANOTHER`), and so does the run (`off_network`).

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
(`_docker_oom`: Docker may hear of the kill after the container's end, so a "false" is asked again for
`OOM_WAIT_KILLED` seconds after a kill and `OOM_WAIT` after any other error; a kill Docker never names reads as
failed tests); a test that prints the line and ends with that result says of itself that it was stopped, and
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

The libraries a project names are fetched for the run (2026-11-13, a firm pass or fail, stage 2). Until then
the tests ran on whatever the Python that runs Lantern had installed, and a project whose libraries are not on the
computer failed at its first import: "Blocked: the tests failed", about code nobody had run. Now `run` asks
`lantern.libraries` first: what the project names is read (never run) and fetched in a step of its own, whose one
way out is a doorkeeper that reaches the store and nothing else (`lantern._stores`), ready-built packages only;
the tests then run on exactly those libraries (`libraries` in the result and in `run.json`), with the ones
installed beside Lantern taken off Python's path, and with the network off wherever this run's own walls keep
them from it (`off_network`; where they do not, for tests that are not Python on macOS and Windows, the line
about the libraries says so instead). Libraries that cannot be had are `NoLibraries`
(an `Unavailable`): the tests are not run, because on other libraries they would say nothing about the project.

What a stranger's library can do in the tests (the same day; each wall after a hostile example that got through,
beside a twin that does what honest tests do):
* **It cannot read the person's own files.** On Linux, for Python and JavaScript runs (`READ_WALL_FOR`: the
  languages whose libraries Lantern fetches), the kernel closes the person's own folders to the run's reads
  (`persons_own`, `read_wall`, the launcher's policy `read`): the home folders, the temp folders, the project
  itself (the tests run on a copy) and the other places of `PERSONS_OWN`, with what the run is made of left open
  inside them (its own folder, the Python or Node that runs it: `_tool_folders`). What the tests reached for is
  said (`blocked`, kind `read`), and a run that ends with an error after that is not counted as tests that
  failed. Go, Rust and Java runs, macOS and Windows are as they were.
* **Process pools, locks and queues are the run's own.** Python keeps them as files in the computer's memory
  folder (`/dev/shm`), which is one of those places. A run gets an empty one of its own, gone with the run
  (`_jail._own_memory`, policy `shm`; `own_memory()` says whether this system can), in a namespace where the
  older kinds of shared memory have names of the run's own too. Where none can be made such tests fail, and the
  run says why (`NO_OWN_MEMORY`, `NO_PROCESS_LOCK`).
* **A program that is not Python reaches no other program of the computer.** The hook above is in Python only,
  and the kernel's rules for files say nothing about connecting to a socket file: Node, a compiled test or
  `python -S` could talk to whatever listens at one (the desktop's message bus, a container service, an agent
  that holds keys), and, where the run has no network of its own, send UDP anywhere. Now every connection of
  the tests' programs is made for them by a doorman of Lantern's, which looks first where it leads
  (`lantern._jail`, policy `sockets`; `own_sockets()` says whether this system can, and `own_sockets` in the
  result whether the run had one): a socket file only in the run's own folders, an address only in a network
  of the run's own. What it refuses is said like the hook's refusals. Where no doorman can be made (macOS,
  Windows, Docker's own walls apart, a kernel before 5.6, a run inside a run) the log and the sheet say so
  (`NO_OWN_SOCKETS`, `DOORMAN_ABOVE`). A run inside a run is its own case (`INSIDE_ANOTHER`): the kernel takes
  one such doorman per chain of filters, so the outer run's doorman makes the inner run's connections too, and
  the kernel asks its rules of whoever makes a connection. What the inner run would refuse a program that is
  not Python, a TCP connection or a socket name outside it, is therefore decided by the outer run's walls
  alone: nothing leaves the outer sandbox, and the inner run does not claim walls of its own for it.

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
import errno
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


IMAGE_LIBC = (2, 36)    # the C library of the Python images above (Debian bookworm)


def image_platforms() -> list[str]:
    """The kinds of ready-built Python library that run in the image the tests get, as pip names them, the
    newest first. The libraries are fetched on this computer and run in the container: a package built for this
    computer's newer C library would be fetched without a word and fail at its first import there, and the
    release decision would read "the tests failed"."""
    import platform
    machine = platform.machine() or "x86_64"
    return [f"manylinux_{IMAGE_LIBC[0]}_{minor}_{machine}" for minor in range(IMAGE_LIBC[1], 4, -1)] \
        + [f"manylinux2014_{machine}", f"linux_{machine}"]


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
    `minutes`, `memory`: the limits this run would have (`time_limit`, `memory_limit`). Where the project names
    libraries that would be fetched first, a line says from where and how (`lantern.libraries.described`)."""
    from . import libraries
    b = backend_for(language)
    limit = minutes_words(time_limit(minutes))
    room = memory_words(memory_limit(memory))
    without = "if any of this cannot be set up, your tests are not run"
    fetched = libraries.described(Path(repo), language)
    if b == "docker":
        return {"name": "docker", "label": "Docker container", "image": image_for(language),
                "details": [COPY_WORDS, *([fetched] if fetched else []),
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
        if _LINUX and landlock_abi() >= 1:
            det.insert(1, "writes allowed only in the copy and its own temp folder"
                          + (", network connections refused" if landlock_abi() >= 4 and held_below_python() else ""))
        if language == "python":
            det.insert(1, "writing outside the copy and its temp folder and opening network connections are refused")
        at = 2 if language == "python" else 1
        det[at:at] = _no_network_words(no_own, language)
    if sys.platform == "win32":
        det.insert(1, f"inside a Windows job: {room} of memory for each process, and nothing it starts can leave the job")
    if _LINUX:
        det.append(f"{room} of memory for the tests and everything they start, counted together; tests that use "
                   "more are stopped, which is neither a pass nor a failure")
    if fetched:
        det.insert(1, fetched)
    if _LINUX and language in READ_WALL_FOR and landlock_abi() >= 1:
        det.insert(1, "your home folder, the temp folders, other disks and the project's own folder cannot be read "
                      "by the tests or by anything they start (what runs is the copy)")
    if _LINUX:
        no_memory = own_memory()
        det.append(NO_OWN_MEMORY.format(why=no_memory) if no_memory else
                   "a memory folder of its own for process pools, locks and queues, emptied with the run; what your "
                   "other programs keep in shared memory is out of reach")
        no_doorman = own_sockets()
        det.append(_no_doorman_words(no_doorman) if no_doorman else
                   "every connection of the tests' programs is made for them by Lantern's doorman, which looks "
                   "where it leads first: a socket file outside the tests' own folders (your desktop's message "
                   "bus, a container service, an agent that holds keys) is not reached, by Python or by any "
                   "other program")
    det.append(without)
    return {"name": "subprocess", "label": "Restricted process on this computer", "image": None, "details": det}


# ---------------------------------------------------------------------------- a network of the run's own
NO_OWN_NETWORK = ("{why}, so nothing on this computer is let through either: tests that start a server and call "
                  "it will fail here")
# Where nothing below Python holds a program (`held_below_python`), the two sentences above would be true of
# Python code only. For tests that are not Python, in their place; for Python's tests, beside them.
NOT_HELD = ("{why}. These tests are not Python, and they are not kept from the network by this run: Lantern's guard "
            "is inside Python only, and {how}")
NOT_HELD_BESIDE = ("what is refused here is refused inside Python, by Lantern's guard: a program the tests start "
                   "that is not Python is not kept from the network by this run, because {how}")
_OWN_NETWORK: list[str] = []          # the answer of `own_network`, asked once


def _tries(what: str) -> int:
    """What a throwaway process gets when it does what the launcher will do (`_jail.try_own_network`,
    `_jail.try_own_memory`): 0, the system's error number, or -1 when the process could not be started."""
    nobody = hasattr(os, "geteuid") and os.geteuid() == 0
    code = (f"import sys; sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r}); "
            f"from lantern import _jail; sys.exit(min(_jail.{what}({nobody!r}), 255))")
    try:
        return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60, env=programs.env()).returncode
    except (OSError, subprocess.SubprocessError):
        return -1


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
        number = _tries("try_own_network")
        why = "" if number == 0 else ("this system does not let the tests have a network of their own"
                                      + (f" (error {number})" if number > 0 else ""))
    _OWN_NETWORK.append(why)
    return why


def _own_python_words(windows: bool) -> str:
    """The log's line about the Python of the run's own (`_own_python`). On Windows that Python is a small
    program that starts the computer's Python and tells it where its libraries are, and Windows looks for a
    program named without its folder in the folder of the program that asks before it looks in PATH: so a test
    that starts `python` by the bare name, in an environment of its own making, gets the computer's own Python,
    with the computer's libraries and without Lantern's guard (found on GitHub's Windows machine, 2026-11-14;
    not fixed: a Python of the run's own that is a whole Python is stage 4's)."""
    line = ("they are started by a Python of the run's own, in which the fetched libraries are the only ones: a "
            "Python the tests start themselves ")
    if not windows:
        return line + "finds the same libraries, whatever it is handed"
    return line + ("by its full path, or in the tests' own environment, finds the same libraries. Started by the "
                   "bare name `python` in an environment a test made itself, it is the computer's own Python "
                   "(Windows looks beside the program that asks before it looks in PATH), with the computer's "
                   "libraries and without Lantern's guard")


def held_below_python() -> bool:
    """In the restricted subprocess: is a program of the tests that is not Python (Node, a compiled program, a
    Python started without the guard) held to this run's own rules for connections by something below Python?
    Yes in a network of the run's own (nothing else is in it), behind a doorman of the run's own (it refuses every
    address where the run has no network), and under the kernel's rule for TCP (Landlock since Linux 6.7), unless a
    sandbox around this one makes the connections: the kernel asks that rule of whoever connects, and there that
    is the outer doorman, which goes by the outer sandbox's walls. No on macOS and Windows, where Lantern has no
    such rule to set. The sheet and the log say "refused" only where this says yes (2026-11-14; until then they
    said it everywhere, and inside another sandbox, and for JavaScript tests on Windows, it was not so)."""
    if not _LINUX:
        return False
    if not own_network() or not own_sockets():
        return True
    return landlock_abi() >= 4 and own_sockets() != DOORMAN_ABOVE


def not_held_how() -> str:
    """Why `held_below_python` says no here, for a sentence that ends with it."""
    if not _LINUX:
        return ("the kernel's rules that hold any other program are Linux's (on this system such a program can "
                "also read and write what you can)")
    if own_sockets() == DOORMAN_ABOVE:
        return ("a sandbox around this one makes every connection for what runs inside it and decides each by "
                "its own walls, not by this run's (another program inside that sandbox can be reached, nothing "
                "outside it)")
    return ("this system gives the run no network of its own and no doorman, and its kernel has no rule for "
            "connections that Lantern can set (Linux 6.7 brought one)")


def _no_network_words(why: str, language: str) -> list[str]:
    """What the sheet and the log say about a run with no network of its own: one sentence, and for Python's
    tests a second where nothing below Python holds the programs they start."""
    if held_below_python():
        return [NO_OWN_NETWORK.format(why=why)]
    if language == "python":
        return [NO_OWN_NETWORK.format(why=why), NOT_HELD_BESIDE.format(how=not_held_how())]
    return [NOT_HELD.format(why=why, how=not_held_how())]


def _was_off_network(backend: str, language: str, own: bool) -> bool:
    """Were the tests of a run off the network: in a container and in a network of the run's own, any program;
    elsewhere Python code (the guard), and another program only where something below Python holds it."""
    return bool(backend == "docker" or own or language == "python" or held_below_python())


def tests_off_the_network(language: str) -> bool:
    """Would the tests of a project in `language` run with the network off in this system's sandbox? For the
    sheet; a run says it of itself (`off_network` in its result)."""
    return _was_off_network(backend_for(language), language, not own_network())


# ---------------------------------------------------------------------------- a memory folder of the run's own
NO_OWN_MEMORY = ("{why}, so tests that start a pool of processes, or use a lock or a queue between processes, fail "
                 "here (such a run is not counted as tests that failed)")
_OWN_MEMORY: list[str] = []           # the answer of `own_memory`, asked once


def own_memory() -> str:
    """Can the restricted subprocess give a run a memory folder of its own on this system (this module's opening
    text)? "" when it can, else why not, in words for a person. Asked once, of a throwaway process, like
    `own_network` (`_jail.try_own_memory`). Only Linux keeps what the folder is for as files that every program
    shares; elsewhere there is nothing to make."""
    if _OWN_MEMORY:
        return _OWN_MEMORY[0]
    if not _LINUX:
        why = "a memory folder of their own for the tests is made on Linux only"
    else:
        number = _tries("try_own_memory")
        why = "" if number == 0 else ("this system does not let the tests have a memory folder of their own"
                                      + (f" (error {number})" if number > 0 else ""))
    _OWN_MEMORY.append(why)
    return why


# ---------------------------------------------------------------------------- a doorman of the run's own
NO_OWN_SOCKETS = ("{why}, so a program the tests start that is not Python can still connect to a socket file of "
                  "another program of this computer, which is how programs on one computer talk to each other")
DOORMAN_ABOVE = ("a sandbox around this one already makes every connection for what runs inside it, and judges a "
                 "socket file by that sandbox's own folders")
INSIDE_ANOTHER = (DOORMAN_ABOVE + ": a program the tests start that is not Python reaches what that sandbox lets "
                  "its own programs reach, a socket file in its folders among them, and nothing outside it")
_OWN_SOCKETS: list[str] = []          # the answer of `own_sockets`, asked once


def _no_doorman_words(why: str) -> str:
    """The sentence of a run with no doorman of its own. Inside another sandbox the reach of its programs ends at
    that sandbox; with no doorman at all it ends nowhere on this computer."""
    return INSIDE_ANOTHER if why == DOORMAN_ABOVE else NO_OWN_SOCKETS.format(why=why)


def own_sockets() -> str:
    """Can the restricted subprocess put a run behind a doorman on this system (`_jail._doorman`: every connection
    of the tests' programs is made for them, after a look at where it leads)? "" when it can, else why not, in
    words for a person. Asked once, of a throwaway process, like `own_network` (`_jail.try_own_sockets`): the
    answer depends on the kernel (5.6 or later), on the kind of processor, on what this system lets one program
    know of another, and on whether this process is in a sandbox with a doorman of its own already."""
    if _OWN_SOCKETS:
        return _OWN_SOCKETS[0]
    if not _LINUX:
        why = "the doorman that makes the connections of the tests' programs is made on Linux only"
    else:
        number = _tries("try_own_sockets")
        why = "" if number == 0 else DOORMAN_ABOVE if number == errno.EBUSY else (
            "this system does not let Lantern put a doorman between the tests' programs and the kernel"
            + (f" (error {number})" if number > 0 else ""))
    _OWN_SOCKETS.append(why)
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


# ---------------------------------------------------------------------------- what the tests cannot read
# Folders that are a person's own on a Linux system wherever their home folder is: root's home, the session's
# folder (its sockets and keyrings), disks that were plugged in or attached, the shared temp folders, memory kept
# under a name, mail and print queues, what a site serves. The home folder, the temp folder in use and the
# project itself are added by `persons_own`.
PERSONS_OWN = ("/root", "/run/user", "/run/media",
               "/tmp", "/var/tmp", "/dev/shm",   # nosec B108: named to close them to the tests' reads; nothing is written there
               "/dev/mqueue", "/var/mail", "/var/spool", "/mnt", "/media", "/srv")
# The languages whose runs are closed to those folders: the ones whose libraries Lantern fetches, so that a run
# needs nothing of the home folder but the program that runs it. Go, Rust and Java tests are handed folders of
# the real home (`_env_base`: the module cache, the toolchains, Maven's repository) and are left as they were.
READ_WALL_FOR = ("python", "node")
TOOL_FOLDERS = ("bin", "lib", "lib64", "libexec", "include")    # what a Python or a Node is made of, under its prefix
ENVIRONMENT_SIGNS = ("pyvenv.cfg", "conda-meta")                # a folder that holds one is an environment, all of it


def _within(path: str, folder: str) -> bool:
    """Is `path` the folder `folder` or something in it? Both full paths with no link in them."""
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def _real(place) -> str:
    """The full path of `place` with no link in it, or "" for what cannot be one."""
    try:
        return os.path.realpath(place) if place and place != "~" else ""
    except (OSError, ValueError, TypeError):
        return ""


def persons_own(repo: Path) -> list[str]:
    """The folders of this computer that are the person's own, which a project's tests have no business reading:
    the home folder (the one HOME names, the one the system's list of users names, and, started through sudo, the
    home of whoever started it), the temp folder in use, the project's own folder (the tests run on a copy, and
    the folder holds what is not copied: `.git` with its settings, earlier results), Lantern's own folder where
    one is named, and `PERSONS_OWN`. Each as its real path, once; folders that exist only; never `/`."""
    places = [os.path.expanduser("~")]
    try:
        import pwd
        places.append(pwd.getpwuid(os.getuid()).pw_dir)
        sudo = os.environ.get("SUDO_UID", "")
        if sudo.isdigit():
            places.append(pwd.getpwuid(int(sudo)).pw_dir)
    except (ImportError, KeyError, OSError, OverflowError):
        pass
    places += [tempfile.gettempdir(), str(repo), os.environ.get("LANTERN_HOME", ""), *PERSONS_OWN]
    own: list[str] = []
    for place in places:
        real = _real(place)
        if real and real != os.sep and os.path.isdir(real) and real not in own:
            own.append(real)
    return own


def _tool_folders(prefix: str, closed: list[str]) -> list[str]:
    """What has to stay readable of a Python or a Node installed under `prefix`. Outside every closed folder:
    the prefix as it is. In a closed folder (pyenv, nvm, an environment in the home folder or in the project):
    the whole prefix when it is an environment by what it holds (`ENVIRONMENT_SIGNS`), else only the folders such
    a program is made of (`TOOL_FOLDERS`, as themselves and not through a link). Never a folder that is closed
    or that lies around a closed one: a Python installed straight into the home folder opens `bin` and `lib` of
    it, not the home folder."""
    real = _real(prefix)
    if not real or not os.path.isdir(real):
        return []
    inside = any(_within(real, c) for c in closed)
    around = any(_within(c, real) for c in closed)
    if not inside and not around:
        return [real]
    if not around and any(os.path.lexists(os.path.join(real, sign)) for sign in ENVIRONMENT_SIGNS):
        return [real]
    found = []
    for name in TOOL_FOLDERS:
        folder = os.path.join(real, name)
        if os.path.isdir(folder) and not os.path.islink(folder) and not any(_within(c, folder) for c in closed):
            found.append(folder)
    return found


def read_wall(repo: Path, root: Path, language: str, fetched: bool, program: str = "",
              path: str | None = None) -> dict | None:
    """The launcher's rule for reads (`lantern._jail`, policy `read`) for a run of a project's tests, or None where
    there is none: off Linux, on a kernel without Landlock, and for the languages not in `READ_WALL_FOR`.

    `closed`: `persons_own`. `open`: what the run is made of and may lie in a closed folder: the run's own folder
    `root` (the copy, the temp folder, the fetched libraries), the Python that runs the tests (its prefixes through
    `_tool_folders`, its own library, the program) or the Node (`program`, the tests' command, and `node` as the
    tests' PATH `path` finds it; each as found and as what a link leads to). Where the libraries are not fetched
    (`fetched` false: the project names none, or the run is offline) the tests run on the ones installed beside
    this Python: their folders, the person's own installed ones (`~/.local/lib`, with the programs in
    `~/.local/bin`), every other folder of installed libraries this Python has on its path (`_library_dirs`: a
    run inside a run has the outer run's fetched libraries there) and Lantern's own package, which holds the
    recorder, with the record of its install where that lies beside it (`_install_records`). `list`: the folder
    around that package, whose names Python reads to find it, and no file of which is opened by that.

    Nothing in `open` is a closed folder or lies around one. What is closed and not opened here stays closed: a
    project of the person's that this Python has on its path, a program in the home folder the tests start by
    name. The launcher checks, under the rules, that what the tests are made of can be read, and starts nothing
    otherwise."""
    if not _LINUX or language not in READ_WALL_FOR or landlock_abi() < 1:
        return None
    closed = persons_own(Path(repo))
    opened: list[str] = []
    listed: list[str] = []

    def add(places, to=opened, but=()) -> None:
        for place in places:
            real = _real(place)
            if real and real not in to and os.path.exists(real) and not any(
                    _within(c, real) for c in closed if c not in but):
                to.append(real)
    add([str(root)])
    if language == "python":
        for prefix in dict.fromkeys((sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix)):
            add(_tool_folders(prefix, closed))
        add([os.path.dirname(os.__file__), sys.executable])
        if not fetched:
            import sysconfig
            places = _site_dirs() + _library_dirs()
            for name in ("purelib", "platlib"):
                try:
                    places.append(sysconfig.get_path(name) or "")
                except (KeyError, ValueError):
                    pass
            add(places)
            try:
                add(_tool_folders(site.getuserbase(), closed))
            except (AttributeError, OSError, TypeError):
                pass
            package = Path(__file__).resolve().parent
            add([str(package), *_install_records(package)])
            add([str(package.parent)], listed, but=(_real(repo),))     # the project's names are in its copy anyway
    else:
        for found in (programs.find("node", path), program):
            if not found or not os.path.isabs(found):
                continue
            for place in dict.fromkeys((found, _real(found))):
                folder = os.path.dirname(place)
                if os.path.basename(folder) in ("bin", "sbin"):
                    add(_tool_folders(os.path.dirname(folder), closed))
                add([place])
    return {"closed": closed, "open": opened, "list": listed}


MOST_NAMES = 20_000         # the entries of one folder that are looked at for the record of an installed library


def _records_in(folder: str) -> list[str]:
    """The records of installed libraries that lie in `folder` as folders of their own, the way pip and
    setuptools write them (`<name>-<version>.dist-info`, `<name>.egg-info`). A folder only, and never a link."""
    found = []
    try:
        with os.scandir(folder) as entries:
            for at, entry in enumerate(entries):
                if at >= MOST_NAMES:
                    break
                if entry.name.lower().endswith((".dist-info", ".egg-info")) and entry.is_dir(follow_symlinks=False):
                    found.append(entry.path)
    except OSError:
        pass
    return found


def _library_dirs() -> list[str]:
    """Folders this Python has on its path that hold installed libraries and are not named as Python names its
    own (`_site_dirs` has those): a folder pip installed into (`--target`) that a path file or the environment
    names. It is told by what it holds, the record pip writes for each library it installs (`*.dist-info` with
    its `METADATA`). A project of the person's own that was installed for editing in place holds no such record
    (its own is an `.egg-info`, or lies with the installed libraries) and is not one of these."""
    found = []
    for place in sys.path:
        real = _real(place)
        if not real or real in found or not os.path.isdir(real) or real.rstrip("/").endswith(("site-packages", "dist-packages")):
            continue
        if any(name.lower().endswith(".dist-info") and os.path.isfile(os.path.join(name, "METADATA"))
               for name in _records_in(real)):
            found.append(real)
    return found


def _install_records(package: Path) -> list[str]:
    """The records of an install that lie beside Lantern's package: Lantern installed for editing in place (a
    developer's clone) has `lantern.egg-info` in the folder around its package. Python reads the record of every
    installed library it finds on its path when a test runner looks for its plug-ins, and that folder is on the
    tests' path (the recorder is in the package). Until 2026-11-14 the record was closed with the rest of a home
    folder, and every run in such a place named a read the tests were refused. Every record in that folder is
    opened, Lantern's or not: Python reads each one it sees there, and a record says what is installed (a name,
    a version, the names of files), which the folder's own list of names says too."""
    return _records_in(str(package.parent))


def _closed_to_this_python(wall: dict, repo: Path) -> list[str]:
    """The folders this Python looks for libraries in that the rule for reads leaves closed: a project of the
    person's own that was installed for editing in place. The project under test is not among them where its
    copy stands for it (`_own_code_folders`)."""
    top, found = _real(repo), []
    for place in sys.path:
        real = _real(place)
        if not real or real in found or not os.path.isdir(real) or not any(_within(real, c) for c in wall["closed"]):
            continue
        if any(_within(real, o) for o in wall["open"]) or real in wall["list"]:
            continue
        if top and _within(real, top) and os.path.relpath(real, top) in (".", "src"):
            continue
        found.append(real)
    return found


def _own_code_folders(repo: Path, app: Path) -> list[str]:
    """Where in the copy the project's own code is looked for besides the copy's top folder, by a Python that
    runs on this computer's libraries: `src` (at home such a project is found because it was installed for
    editing in place, which puts the project's own `src` on the path: not the copy, and closed to the tests
    where reads are), and the copy's twin of every other folder of the project this Python has on its path for
    that reason. They go to the end of the tests' path (the guard, LANTERN_SANDBOX_SITE), behind Python's own
    library and the installed ones, as at home."""
    found = [str(app / "src")] if (app / "src").is_dir() else []
    top = _real(repo)
    for place in sys.path if top else []:
        real = _real(place)
        if real and real != top and _within(real, top):
            twin = app / os.path.relpath(real, top)
            if twin.is_dir() and str(twin) not in found:
                found.append(str(twin))
    return found


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
    # Folders of libraries, behind Python's own library as installed libraries are at home: the fetched ones and
    # the project's `src`, or (Docker) the host's packages, whose .pth files name host paths and are not read.
    if _p and _p not in _sys.path:
        _sys.path.append(_p)
def _only_fetched():
    # The tests run on the libraries Lantern fetched for them (lantern.libraries) and on no others. What PYTHONPATH
    # and LANTERN_SANDBOX_SITE name (the guard, the project's copy, the fetched libraries) and Python's own library
    # stay on the path; the
    # libraries installed beside this Python go, with whatever their .pth files put on the path, among the finders
    # or among the loaded modules. Python must still find its own library afterwards: if it does not, everything
    # is put back and the mark below is not set, and lantern's tracer then starts no test.
    real = _os.path.realpath
    mine = [real(p) for name in ("PYTHONPATH", "LANTERN_SANDBOX_SITE")
            for p in _os.environ.get(name, "").split(_os.pathsep) if p]
    own = [real(p) for p in {_sys.base_prefix, _sys.base_exec_prefix} if p]
    def kept(p):
        if not isinstance(p, str) or not p:
            return True
        r = real(p)
        if any(r == m or r.startswith(m + _os.sep) for m in mine):
            return True
        parts = r.replace("\\", "/").split("/")
        if "site-packages" in parts or "dist-packages" in parts or parts[-1].startswith("__editable__"):
            return False
        return any(r == o or r.startswith(o.rstrip(_os.sep) + _os.sep) for o in own)
    def home(obj):
        name = getattr(obj, "__module__", None)
        f = getattr(_sys.modules.get(name) if isinstance(name, str) else None, "__file__", None)
        return _os.path.dirname(f) if isinstance(f, str) else None
    def places(mod):
        f = getattr(mod, "__file__", None)
        if isinstance(f, str):
            return [_os.path.dirname(f)]
        try:
            return [p for p in (getattr(mod, "__path__", None) or []) if isinstance(p, str)]
        except Exception:
            return []
    before = (list(_sys.path), list(_sys.meta_path), list(_sys.path_hooks), dict(_sys.modules))
    try:
        _sys.path[:] = [p for p in _sys.path if kept(p)]
        for group in (_sys.meta_path, _sys.path_hooks):
            group[:] = [f for f in group if home(f) is None or kept(home(f))]
        for name, mod in list(_sys.modules.items()):
            if not all(kept(p) for p in places(mod)):
                del _sys.modules[name]
        _sys.path_importer_cache.clear()
        import importlib.util
        if all(importlib.util.find_spec(m) is not None for m in ("runpy", "json", "unittest", "atexit", "select")):
            return True
    except Exception:
        pass
    _sys.path[:], _sys.meta_path[:], _sys.path_hooks[:] = before[0], before[1], before[2]
    _sys.modules.update(before[3])
    _sys.path_importer_cache.clear()
    return False
if _os.environ.get("LANTERN_SANDBOX_LIBRARIES") == "fetched" and _only_fetched():
    _sys.lantern_sandbox_libraries = "fetched"   # lantern's tracer looks for this before it runs a test
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
# The person's own folders are closed to the run's reads by the kernel, where it can be (lantern.sandbox.read_wall:
# LANTERN_SANDBOX_CLOSED names them, ..._OPENED what stays readable inside them, ..._LISTED the folders whose names
# may be read). The guard refuses nothing there. It says what the tests reached for, once for each place: a run
# that ends with an error after that may be the sandbox's doing, and is then not counted as tests that failed. The
# place is the one the name leads to, as the kernel judges it: a link the project brought, or one the tests made, to
# a folder of the person's own is named by that folder (the folder a name is in is asked for its real place once;
# looking at a name and reading a link are not reads, and the kernel lets them through in a closed folder too).
# Where the kernel has no such rule nothing is closed, and nothing is said.
def _places(name):
    return [p for p in _os.environ.get(name, "").split(_os.pathsep) if _os.path.isabs(p)]
_CLOSED, _OPENED, _LISTED = (_places("LANTERN_SANDBOX_" + n) for n in ("CLOSED", "OPENED", "LISTED"))
# Folders this Python looks for libraries in that are closed now (LANTERN_SANDBOX_SHUT: a project of the person's
# own, installed for editing in place). Python asks every folder on its path for every module it has not found
# yet, so each run named a read of such a folder that no test had asked for. They are taken off the path: nothing
# there can be read anyway, the log names them, and a test that imports what is only there is told "no module".
_SHUT = [_os.path.realpath(p) for p in _places("LANTERN_SANDBOX_SHUT")]
if _SHUT:
    _sys.path[:] = [p for p in _sys.path if not isinstance(p, str) or not p or _os.path.realpath(p) not in _SHUT]
    _sys.path_importer_cache.clear()
# The run's memory folder (lantern._jail._own_memory: where Linux keeps named semaphores and shared memory). When
# the launcher has put an empty one of the run's own in the place of the computer's, it says so with the number
# the system gives that folder, and the folder is then the run's to write in and read, like its temp folder.
try:
    if _os.environ.get("LANTERN_SANDBOX_SHM") == "own:%d" % _os.lstat("/dev/shm").st_dev:
        _W.append("/dev/shm")
        _OPENED.append("/dev/shm")
except OSError:
    pass
_SAID = set()
_REAL = {}
def _in(p, folders):
    return any(p == f or p.startswith(f.rstrip(_os.sep) + _os.sep) for f in folders)
def _leads_to(p):
    head, tail = _os.path.split(p)
    real = _REAL.get(head)
    if real is None:
        if len(_REAL) >= 4096:
            _REAL.clear()
        real = _REAL[head] = _os.path.realpath(head)
    q = _os.path.join(real, tail) if tail else real
    return _os.path.realpath(q) if tail and _link(q) else q
def _reads(path, names=False):
    if len(_SAID) >= 20:
        return
    try:
        p = _os.path.abspath(_os.fsdecode(path))
        q = _leads_to(p)
    except (TypeError, ValueError, OSError):
        return
    if q in _SAID or not _in(q, _CLOSED) or _in(q, _OPENED) or (names and _in(q, _LISTED)):
        return
    _SAID.add(q)
    through = "" if q == p else "reached as " + p[:300] + "; "
    try:
        _os.write(2, ("LANTERN-SANDBOX-BLOCKED: read of " + q[:300] + " (" + through
                      + "your own folders are closed to the tests)\n").encode("utf-8", "replace"))
    except OSError:
        pass
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
        if _CLOSED and not w:
            _reads(path)
    elif ev in ("os.listdir", "os.scandir"):
        p = args[0] if args else None
        if _CLOSED and p is not None and not isinstance(p, int):
            _reads(p, True)
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


MOST_LINKS = 20_000         # links of one repository that are made links again in the tests' copy
LINK_TEXT = 4096            # the longest path a link names


def _n_links(n: int, many: str, one: str) -> str:
    return f"sandbox: {n} {one if n == 1 else many}"


def _links_again(repo: Path, app: Path, log) -> None:
    """The links of a repository, in the copy the tests run on (2026-11-13). A copy of a repository that Lantern
    made itself holds none (`remote.NO_LINKS`): git wrote each link as a small file with the link's own text, so
    that no program reading the copy is led out of it. Tests that go through a link of their own project (a
    fixture that is a link to a program, a folder shared by a link) found that small file, failed, and the
    release decision said "Blocked: the tests failed" for a project whose tests pass at home (two tests of the
    first public JavaScript project run from its link).

    Here each file that the repository's own record calls a link (`gitfacts.links`) is made a link again in the
    tests' copy, which is thrown away with the run, when the link stays in the project: its text is one line of
    a path's length, no full path, and does not go up past the project's top as written; and, once all are
    made, where it leads through the others is still inside the copy (a link to the project's own top makes
    `top/..` the folder above). A link that leads out stays the small file it was, and the log says how many.
    Nothing here opens what a link names, and Lantern's own copy of the repository is not changed. A folder of
    the person's own keeps its links as it always did (`_copy`), with the sandbox's walls around them."""
    if os.name != "posix":
        return
    from . import gitfacts, remote
    try:
        names = gitfacts.links(repo) if remote.is_clone(repo) else None
    except (OSError, RuntimeError):
        names = None
    if not names:
        return
    top = os.path.realpath(app)

    def within(path: str) -> bool:
        return path == top or path.startswith(top + os.sep)

    made: dict[str, tuple[bytes, int]] = {}
    out = odd = 0
    for name in names[:MOST_LINKS]:
        parts = name.split("/")
        if name.startswith("/") or any(part in ("", ".", "..") for part in parts):
            continue
        place = os.path.join(top, *parts)
        try:
            st = os.lstat(place)
        except OSError:
            continue                                # not in the copy (a folder the copy leaves out)
        if stat.S_ISLNK(st.st_mode):
            continue                                # a copy that kept its links: as it is
        try:
            if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= LINK_TEXT \
                    or not within(os.path.realpath(os.path.dirname(place))):
                odd += 1
                continue
            fd = os.open(place, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            try:
                raw = os.read(fd, LINK_TEXT + 1)
            finally:
                os.close(fd)
        except OSError:
            odd += 1
            continue
        if len(raw) != st.st_size or b"\0" in raw or b"\n" in raw or b"\r" in raw:
            odd += 1
            continue
        target = os.fsdecode(raw)
        where = os.path.normpath(os.path.join(os.path.dirname(name), target))
        if target.startswith("/") or where == ".." or where.startswith("../"):
            out += 1
            continue
        beside = f"{place}.lantern-link-{uuid.uuid4().hex[:12]}"
        try:
            os.symlink(target, beside)
            os.replace(beside, place)
        except OSError:
            try:
                os.unlink(beside)
            except OSError:
                pass
            odd += 1
            continue
        made[place] = (raw, stat.S_IMODE(st.st_mode))
    again = True
    while again:                                    # where each one leads, through the others
        again = False
        for place in list(made):
            if within(os.path.realpath(place)):
                continue
            raw, mode = made.pop(place)
            try:
                os.unlink(place)
                fd = os.open(place, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
                try:
                    os.write(fd, raw)
                finally:
                    os.close(fd)
            except OSError:
                pass
            out += 1
            again = True
    if made:
        log(_n_links(len(made), "links of the repository are links again in the tests' copy",
                     "link of the repository is a link again in the tests' copy")
            + " (Lantern's own copy of a repository keeps each as a small file)")
    if out:
        log(_n_links(out, "links of the repository lead out of the project and stay small files in the copy: "
                          "tests that go through them do not find what they name",
                     "link of the repository leads out of the project and stays a small file in the copy: "
                     "tests that go through it do not find what it names"))
    if odd:
        log(_n_links(odd, "files that the repository holds as links are not a link's text in Lantern's copy "
                          "and stay as they are",
                     "file that the repository holds as a link is not a link's text in Lantern's copy and "
                     "stays as it is"))


def _may_enter(path: str, uid: int, gid: int, look=os.stat) -> bool | None:
    """Whether the user `uid`, who is in the group `gid` and no other, may enter the folder at `path`: read from
    the modes of that folder and of every folder above it, as the system reads them (the owner's bits for the
    owner, the group's for the group, everybody's for anybody else). False as soon as one on the way refuses;
    None for a path that is no full path or stops at something that is not there."""
    if not path or not path.startswith("/"):
        return None
    at = "/"
    for part in ["", *[p for p in path.split("/") if p]]:
        at = at.rstrip("/") + "/" + part if part else at
        try:
            st = look(at)
        except OSError:
            return None
        bit = stat.S_IXUSR if st.st_uid == uid else stat.S_IXGRP if st.st_gid == gid else stat.S_IXOTH
        if not stat.S_ISDIR(st.st_mode) or not st.st_mode & bit:
            return False
    return True


def _path_for(path: str, uid: int, gid: int, look=os.stat) -> tuple[str, list[str]]:
    """PATH for tests that run as another user than Lantern (root's Lantern runs them as `nobody`), and the
    folders left out of it: those that user may not enter. Looking for a program in such a folder the system
    answers "permission denied", and a program that is simply nowhere is then reported as one that may not be
    run (2026-11-13: two tests of a public project that expect "not found" failed in the sandbox for it).
    Nothing the tests could have used is taken away."""
    kept, left = [], []
    for folder in path.split(os.pathsep):
        (left if _may_enter(folder, uid, gid, look) is False else kept).append(folder)
    return os.pathsep.join(kept), left


def _copy_in(repo: Path, app: Path, log) -> None:
    """The project's copy for one run, or `Unavailable` with the reason when it cannot be made."""
    log("sandbox: copying the project to a temp folder")
    try:
        _copy(repo, app)
        _links_again(repo, app, log)
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


def _there(path) -> bool:
    """Is something at `path`, as far as this user can tell? A place this user may not look at (a folder above it
    that it may not enter) or a name the system refuses is not there for a run. Python's own `Path.exists` raises
    for both before 3.14, and a run then ended with a Python error: Lantern started as another user with the
    first user's environment, which is how its own tests run in the sandbox as root."""
    try:
        os.stat(path)
    except (OSError, ValueError):
        return False
    return True


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
        v = os.environ.get(var) or (str(default) if _there(default) else None)
        if v:
            env[var] = v
    m2 = real / ".m2" / "repository"
    if _there(m2):
        env["MAVEN_OPTS"] = f"-Dmaven.repo.local={m2}"
    return env


def _python_argv(words: list[str]) -> list[str]:
    """`python -m pytest -q` -> the part after the interpreter; `pytest -q` -> `-m pytest -q`.

    pytest's cache stays on. Until 2026-11-13 it was switched off for every run (`-p no:cacheprovider`: it is
    written beside the tests, which the sandbox refused while the project itself was what the tests saw), and a
    project whose own pytest settings use the cache (`addopts = "--failed-first"`) then had no test run at all:
    pytest does not know the option without its cache, and the release decision read "the tests failed". The
    tests have a copy of their own now, and what the cache writes there goes with it."""
    head = Path(words[0]).name.lower()
    return words[1:] if head.startswith("python") or head == "py" else ["-m", "pytest", *words[1:]]


class Unavailable(RuntimeError):
    """The sandbox could not be set up, so the project's tests were not run. `str()` says why, in words for a
    person; it is never text read from the project or from a run's output."""
    kind = "sandbox"


class NoLibraries(Unavailable):
    """The libraries the project names could not be had for its tests (`lantern.libraries`), so the tests were not
    run: on other libraries than the project's they would say nothing about it. The words are Lantern's own;
    of the project they hold at most the name of a library or of a requirements file, each of a fixed shape."""
    kind = "libraries"


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


# How long Docker is asked whether a container was over its memory, in seconds: after a command that was ended by
# a kill (137, the way the kernel ends a program over its memory), after any other error (a test runner that lost
# a child to the limit reports a failure of its own, some time after the kill), and between two asks.
OOM_WAIT_KILLED = 5.0
OOM_WAIT = 1.0
OOM_ASK_AGAIN = 0.2
# The clock that asking goes by, and the wait between two asks. A test puts its own in their place, so that how often
# Docker is asked is what this code decides and not how fast the machine starts a program.
_oom_clock = time.monotonic
_oom_wait = time.sleep


def _docker_oom(docker: str, name: str, wait: float = 0.0) -> tuple[bool, int]:
    """Whether Docker ended a program of this container because the container was over its memory, and how many
    times Docker was asked. Docker's own answer about the container, asked after its command ended with an error.

    Docker hears of the kill in a message of its own, which may arrive after the container's end: asked once,
    right at the end, it said "false" about tests the kernel had just ended for their memory (CI, 2026-11-13), and
    the run read as failed tests. So a "false" is asked again every `OOM_ASK_AGAIN` seconds until `wait` seconds
    have passed, and a "true" is believed at once. Anything else ends the asking as a no: Docker cannot be asked,
    ends with an error (the container is gone) or says other words."""
    until = _oom_clock() + max(0.0, wait)
    asked = 0
    while True:
        asked += 1
        try:
            r = subprocess.run([docker, "inspect", "--format", "{{.State.OOMKilled}}", name], capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=30, env=programs.env())
        except (OSError, subprocess.SubprocessError):
            return False, asked
        said = r.stdout.strip()
        if r.returncode != 0 or said not in ("true", "false"):
            return False, asked
        left = until - _oom_clock()
        if said == "true" or left <= 0:
            return said == "true", asked
        _oom_wait(min(OOM_ASK_AGAIN, left))


def _over_words(mb: int) -> str:
    had = memory_words(mb)
    return "because the tests used more memory than their limit" + (f" ({had})" if had else "")


# What a program says when the kernel refused it the network: C's and Python's words, Go's (lower case), and
# Node's names for the same errors (`connect ENETUNREACH 192.0.2.1:80`, `listen EACCES: permission denied
# 127.0.0.1`, `getaddrinfo EAI_AGAIN example.com`). Until 2026-11-13 only the first two were known, so a
# JavaScript test the sandbox had stopped was reported as a plain failure of the project's tests.
_NO_NETWORK = re.compile(r"Network is unreachable|network is unreachable|Temporary failure in name resolution"
                         r"|\b(?:connect|listen|bind|send|getaddrinfo) (?:ENETUNREACH|EACCES|EPERM|EAI_AGAIN)\b")
# A run on a Linux that can give it no memory folder of its own (`own_memory`) cannot make a process lock, pool or
# queue: Python makes each from a named semaphore, the system refuses the file below Python, and all the tests'
# output shows is "Permission denied" on the way through `multiprocessing`. That is the sandbox's doing, and is
# said, so such a run is not counted as tests that failed.
_LOCK_REFUSED = re.compile(r"multiprocessing[/\\]synchronize\.py|_multiprocessing\.SemLock")
NO_PROCESS_LOCK = ("write of a process lock, pool or queue (this system gave the tests no memory folder of their own "
                   "to keep one in)")


def blocked_reasons(output: str, no_memory_folder: bool = False) -> list[str]:
    """What the sandbox refused, from its own markers and the kernel's messages (read-only mount, no network).
    `no_memory_folder`: the run was one of the restricted subprocess on a Linux that gave it no memory folder of
    its own, so a process lock that was refused is the sandbox's doing."""
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
            kind = "network" if why.startswith("network") else "read" if why.startswith("read of ") else "write"
            key = (kind, why[:120])
            if key not in seen:
                seen.add(key)
                out.append({"kind": kind, "what": why[:200]})
    if no_memory_folder and "PermissionError: [Errno 13]" in output and _LOCK_REFUSED.search(output):
        out.insert(0, {"kind": "write", "what": NO_PROCESS_LOCK})
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
        cwd_rel: str = "", cancel=None, memory=None, offline: bool | None = None) -> Result:
    """Run the test command `words` for `repo` in the sandbox. Returns trace data for `trace.merge_trace` (`pairs`)
    plus `backend`, `language`, `traced`, `returncode`, `timed_out`, `over_memory` (the tests were stopped because
    they, with what they started, used more memory than `memory_limit`, the megabytes they had), `cancelled`,
    `blocked`, `not_ended` (what the tests started and Lantern could not end, in its own words; empty when nothing
    is left), `own_network` (the tests had a network of their own, where they could listen and call what they
    started), `own_sockets` (every connection of the tests' programs was made for them by Lantern's doorman, so a
    socket file outside their own folders was out of reach for programs that are not Python too; `own_sockets()`
    says why not), `off_network` (this run's own walls kept the tests from the network: Docker, a network of the
    run's own, Python's tests through the guard, or any other program where `held_below_python()`; False for tests
    that are not Python where nothing of Lantern's holds them, and the log then says why), `output_tail`,
    `stderr_tail`. `memory`: the megabytes for this run (`memory_limit`; ValueError for
    anything that is no such number). `cancel`: a threading.Event; once set, the tests and everything they
    started are ended. Raises `Unavailable` when the sandbox cannot be set up: the tests were then not run.

    `libraries` in the result says what the tests ran on (`lantern.libraries`): the libraries the project names
    are fetched first, in a step of their own, and the tests then run on exactly those (`off_network` says whether
    with the network off; `state: "fetched"`, every library with its version and fingerprint); offline (`offline`, else
    LANTERN_OFFLINE) nothing is fetched and the tests run on what this computer has (`"installed"`) or, when a
    library the project names is not there, are not run (`Unavailable`); `"none"` for a project that names none."""
    from . import libraries
    repo = Path(repo).resolve()
    language = check_command(words)
    backend = backend or backend_for(language)
    memory = memory_limit(memory)
    found = libraries.plan(repo, language, words, cwd_rel, offline)   # `Unavailable`: the tests are not started
    me = _Going(cancel)
    with _LIVE_LOCK:
        _GOING.add(me)
    try:
        _retry_left(log)         # what an earlier run could not delete, tried again before this one makes its own
        root = Path(tempfile.mkdtemp(prefix="lantern-sandbox-"))
        try:
            if backend == "docker":
                res = _run_docker(repo, words, language, root, log, timeout, cwd_rel, me, memory=memory, plan=found)
            else:
                res = _run_subprocess(repo, words, language, root, log, timeout, cwd_rel, me, memory=memory,
                                      plan=found)
        finally:
            if not _rm(root):
                log(f"sandbox: its temp folder could not be deleted and is still there: {root}")
                removal.note(root)   # written down: the next run deletes it, if it is still the folder made here
    finally:
        with _LIVE_LOCK:
            _GOING.discard(me)
        me.done.set()            # stop_all() waits for this, so the program does not leave in the middle of the lines above
    res.update(backend=backend, language=language, traced=language == "python", memory_limit=memory,
               libraries=found.record)
    res.setdefault("own_network", False)
    res.setdefault("own_sockets", False)
    res["off_network"] = _was_off_network(backend, language, bool(res["own_network"]))
    res.setdefault("over_memory", False)
    res["cancelled"] = res.get("returncode") is None and not res.get("timed_out") and not res.get("over_memory")
    res["blocked"] = blocked_reasons(res.get("output_tail", "") + "\n" + res.pop("_full", ""),
                                     no_memory_folder=_LINUX and backend == "subprocess" and bool(own_memory()))
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
    res["blocked"] = blocked_reasons(res.get("output_tail", "") + "\n" + res.pop("_full", ""),
                                     no_memory_folder=_LINUX and bool(own_memory()))
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


def _fetched(plan, repo, app, root, cwd_rel, log, cancel, memory):
    """The libraries of this run, fetched before its tests (`lantern.libraries.fetch`): (the folder they are in or
    None when the plan names none to fetch, None or the result of a run that was stopped while they were fetched)."""
    if plan is None or not plan.fetch:
        return None, None
    from . import libraries
    where = libraries.fetch(plan, repo, app, root, cwd_rel, log, cancel, memory)
    if where is not None:
        return where, None
    log(_stopped("because it was asked to", plan.left, "every process the fetch started was ended"))
    return None, Result(pairs=[], returncode=None, timed_out=False, over_memory=False, output_tail="", _full="",
                        not_ended=list(plan.left), own_network=False)


def _tracer(hook: Path) -> Path:
    """Lantern's recorder of calls as one file beside the guard, for tests that run on fetched libraries: the
    folder Lantern itself is installed in may hold this computer's libraries, so it is not put on their path."""
    there = hook / "_lantern_tracer.py"         # the name the tests' command line gives `-m` (`_run_subprocess`)
    shutil.copyfile(Path(__file__).resolve().parent / "tracehook.py", there)
    return there


OWN_PYTHON = "py"       # the folder of a run's own Python, in the run's temp folder


def _own_python(root: Path, libs: Path, app: Path, log) -> tuple[str, Path, Path] | None:
    """A Python of the run's own, for tests that run on fetched libraries: (the program, its folder, the folder
    its installed libraries would be in), or None where it could not be made.

    At home a project's libraries are installed in the Python itself, so a second Python that a test starts finds
    them whatever environment it is handed. Here they were found through the tests' environment alone (PYTHONPATH,
    with the guard taking this computer's libraries off the path): a second Python that was handed another
    environment, or told to pass its environment over (`-I`, `-E`), ran on whatever is installed beside Lantern,
    and the record then named libraries those tests had not run on. So the tests are started by this computer's
    Python under another name: a virtual environment in the run's folder, made by Python's own `venv` with no pip,
    whose one library file (`lantern.pth`) names the folder of the fetched libraries and the project's copy. That
    file names folders; nothing in it is run, and a `.pth` file a fetched library brings is not read at all (the
    libraries' folder is on the path, it is not a folder of installed libraries), so no code of a library runs
    before the guard is in place. The folder is Lantern's and not the tests' to write in.

    The guard still takes this computer's libraries off the path (`_only_fetched`): it is what holds where no
    Python of the run's own can be made, for every Python that is handed the tests' environment."""
    import sysconfig
    import venv
    home = root / OWN_PYTHON
    scripts = "Scripts" if os.name == "nt" else "bin"
    exe = home / scripts / ("python.exe" if os.name == "nt" else "python")
    try:
        venv.EnvBuilder(system_site_packages=False, symlinks=os.name != "nt", with_pip=False).create(home)
        site = Path(sysconfig.get_path("purelib", "venv", {"base": str(home), "platbase": str(home)}))
        if not exe.exists() or not site.is_dir() or home not in site.parents:
            raise OSError(errno.ENOENT, "the environment is not of the shape Python documents")
        for folder in (home, home / scripts, site, *[p for p in site.parents if home in p.parents]):
            os.chmod(folder, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        # Does it start, and is it the environment made above? Asked of the Python itself while the environment
        # still names no folder: Python looks for a start-up file (`sitecustomize`) in every folder on its path,
        # and neither a fetched library nor the project is to be on the path of a Python outside the sandbox.
        said = subprocess.run([str(exe), "-I", "-c", "import os, sys; print(os.path.realpath(sys.prefix))"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
                              cwd=str(home), env=programs.env({k: os.environ[k] for k in (
                                  "PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR") if k in os.environ}))
        if said.returncode != 0 or said.stdout.strip() != os.path.realpath(home):
            raise OSError(errno.ENOEXEC, "the Python made for the run does not start as one")
        src = app / "src"
        named = [str(libs), *([str(src)] if src.is_dir() else []), str(app)]
        if any("\n" in p or "\r" in p or p.lstrip().startswith(("import ", "import\t", "#")) for p in named):
            raise OSError(errno.EINVAL, "a folder name that cannot be written in a path file")
        (site / "lantern.pth").write_text("".join(p + "\n" for p in named), encoding="utf-8")
        for f in (home / "pyvenv.cfg", site / "lantern.pth"):
            os.chmod(f, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    except Exception as e:      # whatever `venv` raises on a Python it cannot copy: the older way holds
        why = e.strerror if isinstance(e, OSError) and e.strerror else type(e).__name__
        log(f"sandbox: a Python of the run's own could not be made ({why}): the tests run on the fetched libraries "
            "through their environment, so a Python they start and hand another environment would not find them")
        _rm(home)
        return None
    _programs_run_by(libs, str(exe))
    return str(exe), home, site


def _programs_run_by(libs: Path, python: str) -> int:
    """The command-line programs the fetched libraries brought (`libs/bin`) name, in their first line, the Python
    that fetched them, as pip writes it: the full path of the Python that runs Lantern. Have them name `python`
    (the run's own) instead, so that such a program runs on the fetched libraries whatever environment the test
    that starts it hands over. Only a plain file whose first line is exactly that line is rewritten, in place and
    never through a link; anything else is left as it is. Returns how many were rewritten. (Windows: a program is
    an .exe that holds the path, and is left.)"""
    was = b"#!" + os.fsencode(sys.executable) + b"\n"
    if os.name != "posix" or any(c in python for c in "\n\r") or " " in python or len(python) > 120:
        return 0
    done = 0
    try:
        names = sorted(os.listdir(libs / "bin"))
    except OSError:
        return 0
    for name in names[:2000]:
        try:
            fd = os.open(libs / "bin" / name, os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 1 << 20:
                continue
            text = os.read(fd, info.st_size + 1)
            if len(text) != info.st_size or not text.startswith(was):
                continue
            new = b"#!" + os.fsencode(python) + b"\n" + text[len(was):]
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, new)
            done += 1
        except OSError:
            continue
        finally:
            os.close(fd)
    return done


def _run_subprocess(repo, words, language, root, log, timeout, cwd_rel, cancel=None, inside=None,
                    memory: int = MEMORY_MB, plan=None) -> Result:
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
        tracer = _tracer(hook) if plan is not None and plan.fetch and language == "python" else None
        if inside is not None:      # the scene of one of Lantern's own drivers, written before the folder changes hands
            (tmp / "behave.scene.json").write_text(json.dumps(inside[1]), encoding="utf-8")
        _copy_in(repo, app, log)
        if not theirs:
            _make_read_only(app)
        env = _env_base(tmp)
        env["LANTERN_SANDBOX_WRITABLE"] = os.pathsep.join(str(w) for w in writable)
        if as_nobody and env.get("PATH"):
            env["PATH"], closed = _path_for(env["PATH"], 65534, 65534)
            if closed:
                log(f"sandbox: {len(closed)} folder{'' if len(closed) == 1 else 's'} of PATH "
                    f"{'is' if len(closed) == 1 else 'are'} closed to the user the tests run as and "
                    f"{'is' if len(closed) == 1 else 'are'} not on the tests' PATH: " + ", ".join(closed[:3])
                    + (f" and {len(closed) - 3} more" if len(closed) > 3 else ""))
        if as_nobody:   # root ignores file modes: run the tests as nobody, who owns the sandbox folder, its temp
            _hand_over(tmp, 65534, 65534)       # folder and, for a project's tests, the copy
            if theirs:  # also what only its owner may read (a key file, a folder made under a strict umask)
                _hand_over(app, 65534, 65534)
            os.chown(root, 65534, 65534)   # mode stays 0700; an app's copy keeps root as owner and no write bits
            _others_may_read(hook)
    except OSError as e:
        raise Unavailable("the sandbox's temp folder could not be made ready for the tests "
                          f"({e.strerror or type(e).__name__})") from e
    libs, stopped = _fetched(plan, repo, app, root, cwd_rel, log, cancel, memory)
    if stopped is not None:
        return stopped
    out_json = tmp / ("behave.observed.json" if inside is not None else "trace.json")
    pkg_root = str(Path(__file__).resolve().parent.parent)
    made_of: list[str] = []         # what the tests' user must be able to read, or the launcher starts nothing
    if language == "python" and libs is not None:
        # On the fetched libraries and no others: the guard takes the libraries installed beside this Python off
        # the path (`_only_fetched`), and the recorder runs from its own file, not from Lantern's folder.
        made_of = [str(tracer), os.path.dirname(os.__file__), str(libs)]
        src = app / "src"
        # The fetched libraries and the project's `src` stand behind Python's own library, where installed
        # libraries stand at home (the guard puts them there). Until 2026-11-13 they stood in front of it: a
        # library that brings a module named like one of Python's own (old back-ports do), or such a file in
        # `src`, was loaded in its place, and tests that pass at home ended with an error.
        env["PYTHONPATH"] = os.pathsep.join([str(hook), str(app)])
        env["LANTERN_SANDBOX_SITE"] = os.pathsep.join([str(libs), *([str(src)] if src.is_dir() else [])])
        env["LANTERN_SANDBOX_GUARD"] = "required"
        env["LANTERN_SANDBOX_LIBRARIES"] = "fetched"
        python, own = sys.executable, _own_python(root, libs, app, log)
        if own is not None:     # this computer's Python under another name, where the only libraries are the fetched
            python = own[0]
            made_of += [str(own[1] / "pyvenv.cfg"), str(own[2] / "lantern.pth")]
            env["VIRTUAL_ENV"] = str(own[1])
        # a program a fetched library brings is found by its name, before one of that name on this computer
        first = [os.path.dirname(python)] if own is not None else []
        first += [str(libs / d) for d in ("bin", "Scripts") if (libs / d).is_dir()]
        env["PATH"] = os.pathsep.join([*first, *([env["PATH"]] if env.get("PATH") else [])])
        # -P, here and wherever the sandbox starts the recorder: `python -m` looks for the module in the current
        # folder first, and that is the project's copy (until 2026-11-13 a project with a file of the recorder's
        # name, or a folder named `lantern`, had that run in its place, and a run with no test in it could end as
        # tests that passed). The recorder puts the current folder on the path itself afterwards.
        cmd = [python, "-P", "-m", "_lantern_tracer", str(out_json), str(app), "--", *_python_argv(words)]
        log("sandbox: the tests run on the fetched libraries and Python's own, with the network off; the "
            "libraries installed on this computer are not on their path")
        if own is not None:
            log("sandbox: " + _own_python_words(sys.platform == "win32"))
    elif language == "python":
        made_of = _made_of(pkg_root)
        env["PYTHONPATH"] = os.pathsep.join([str(hook), pkg_root, str(app)])
        also = _own_code_folders(repo, app)
        if also:                # a project that keeps its code in `src`: found in the copy, behind the libraries
            env["LANTERN_SANDBOX_SITE"] = os.pathsep.join(also)
        env["LANTERN_SANDBOX_GUARD"] = "required"   # lantern.tracehook runs no test without the guard above
        cmd = [sys.executable, "-P", "-m", "lantern.tracehook", str(out_json), str(app), "--", *_python_argv(words)]
        if inside is not None:
            cmd = programs.python(inside[0], str(tmp / "behave.scene.json"), str(out_json), str(app))
    else:
        exe = programs.find(words[0], env.get("PATH")) or (str(app / words[0]) if words[0].startswith("./") else words[0])
        cmd = [exe, *words[1:]]
    cwd = app / cwd_rel if cwd_rel else app
    no_own = own_network()
    no_memory = own_memory() if _LINUX else ""
    no_doorman = own_sockets() if _LINUX else ""
    wall = read_wall(repo, root, language, libs is not None, cmd[0], env.get("PATH")) if os.name == "posix" else None
    if wall is not None and language == "python" and libs is None:
        # The tests' Python by its bare name is this one, also where PATH leads to it through a program in the
        # home folder (pyenv's shim), which the tests can no longer read; and the folder around Lantern's own
        # package has to be one whose names Python can read, or the recorder is not found.
        env["PATH"] = os.pathsep.join([os.path.dirname(sys.executable), *([env["PATH"]] if env.get("PATH") else [])])
        made_of = [*made_of, pkg_root]
    # folders this Python has on its path that are closed now: the guard takes them off the tests' path
    shut = _closed_to_this_python(wall, repo) if wall is not None and language == "python" and libs is None else []
    if wall is not None and language == "python" and not any(os.pathsep in p for group in wall.values() for p in group):
        # for the guard, which says what the tests reached for in a closed folder (it refuses nothing there)
        env.update({"LANTERN_SANDBOX_" + name: os.pathsep.join(wall[key])
                    for name, key in (("CLOSED", "closed"), ("OPENED", "open"), ("LISTED", "list"))})
        if shut and not any(os.pathsep in p for p in shut):
            env["LANTERN_SANDBOX_SHUT"] = os.pathsep.join(shut)
    if os.name == "posix":
        policy = {"writable": [str(w) for w in writable], "nobody": as_nobody, "python": language == "python",
                  "net": True, "own_net": not no_own, "net_told": inside is None, "must": True,
                  "parent": os.getpid(), "cpu": max(WALL_CLOCK, int(timeout)) * _processors(), "memory": memory << 20,
                  "readable": made_of, "runs": cmd[0] if os.path.isabs(cmd[0]) else "",
                  # a memory folder of the run's own, where this system makes one (`own_memory`): what
                  # Python's process locks, pools and queues are kept in, a quarter of the run's memory at most
                  "shm": (memory << 20) // 4 if _LINUX and not no_memory else 0,
                  # a doorman of the run's own, where this system lets Lantern make one (`own_sockets`): every
                  # connection of the tests' programs is made for them, after a look at where it leads
                  "sockets": _LINUX and not no_doorman}
        if wall is not None:
            policy["read"] = wall
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
        first, *more = _no_network_words(no_own, language)
        log("sandbox: the tests have no network of their own (" + first + ")")
        for line in more:
            log("sandbox: " + line)
    if no_memory:
        log("sandbox: the tests have no memory folder of their own (" + NO_OWN_MEMORY.format(why=no_memory) + ")")
    if no_doorman:
        log("sandbox: the tests have no doorman of their own (" + _no_doorman_words(no_doorman) + ")")
    if inside is not None:
        log("sandbox: the project's app is started by Lantern's own driver, with no network")
    if wall is not None:
        log("sandbox: your own folders are closed to " + ("the tests" if inside is None else "the app") + ", for reading "
            "too: your home folder, the temp folders, other disks and the project's own folder (what runs is the "
            "copy). The system's folders and the " + ("Python" if language == "python" else "Node")
            + " that runs them stay open")
        if shut:
            log(f"sandbox: this Python also looks for libraries in {len(shut)} folder(s) of your own that are "
                f"closed now ({shut[0][:200]}{', ...' if len(shut) > 1 else ''}): a library that is only there "
                "is not found by the tests")
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
                      output_tail=output[-6000:], _full=output, not_ended=left, own_network=False,
                      own_sockets=_LINUX and not no_doorman)
    data = _recorded(out_json)
    _map_pairs(data, str(app), repo)
    # `own_network` and `own_sockets` are what the launcher was told to make: a launcher that could not make
    # them starts nothing
    return Result(pairs=data.get("pairs", []), returncode=rc, timed_out=timed_out, over_memory=over,
                  output_tail=output[-6000:], _full=output, not_ended=left, own_network=not no_own,
                  own_sockets=_LINUX and not no_doorman)


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


def _run_docker(repo, words, language, root, log, timeout, cwd_rel, cancel=None, memory: int = MEMORY_MB,
                plan=None) -> Result:
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
    # The libraries the project names are fetched on this computer, in the launcher's sandbox, before the container
    # is made (its network is off); the container then gets them to read and none of this computer's own.
    if plan is not None and plan.fetch and language == "python":
        plan.platforms = image_platforms()      # ready-built for the image's system, which may not be this one
    libs, stopped = _fetched(plan, repo, app, root, cwd_rel, log, cancel, memory)
    if stopped is not None:
        return stopped
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
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "LANTERN_SANDBOX_WRITABLE=" + os.pathsep.join(["/tmp", "/out", "/app"]),  # nosec B108: the container's own tmpfs
            "-e", "LANTERN_SANDBOX_NET=container",      # --network none: the container's network is its own
            "-e", "npm_config_cache=/tmp/npm", "-e", "GOCACHE=/tmp/gocache", "-e", "GOFLAGS=-mod=mod",
            "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local", "-e", "CARGO_TARGET_DIR=/tmp/target",
            "-e", "CARGO_NET_OFFLINE=true", "-w", "/app/" + cwd_rel if cwd_rel else "/app"]
    if language == "python" and libs is not None:
        src = ["/app/src"] if (app / "src").is_dir() else []
        args += ["-v", f"{libs}:/opt/libs:ro", "-v", f"{pkg}:/opt/lantern/lantern:ro",
                 "-e", "PYTHONPATH=" + ":".join(["/opt/hook", "/opt/lantern", "/app"]),
                 "-e", "LANTERN_SANDBOX_SITE=" + ":".join(["/opt/libs", *src]),     # behind Python's own library
                 "-e", "LANTERN_SANDBOX_GUARD=required", "-e", "LANTERN_SANDBOX_LIBRARIES=fetched"]
        cmd = ["python", "-P", "-m", "lantern.tracehook", "/out/trace.json", "/app", "--", *_python_argv(words)]
    elif language == "python":
        sites = _site_dirs()
        for i, s in enumerate(sites):
            args += ["-v", f"{s}:/opt/site/{i}:ro"]
        args += ["-v", f"{pkg}:/opt/lantern/lantern:ro",
                 "-e", "PYTHONPATH=" + ":".join(["/opt/hook", "/opt/lantern", "/app"]), "-e", "LANTERN_SANDBOX_GUARD=required",
                 "-e", "LANTERN_SANDBOX_SITE=" + ":".join(f"/opt/site/{i}" for i in range(len(sites)))]
        cmd = ["python", "-P", "-m", "lantern.tracehook", "/out/trace.json", "/app", "--", *_python_argv(words)]
    else:
        env = _env_base(root)
        for var, where in (("GOMODCACHE", "/go/pkg/mod"), ("CARGO_HOME", None)):
            if env.get(var) and _there(env[var]):
                if var == "CARGO_HOME":
                    reg = Path(env[var]) / "registry"
                    if _there(reg):
                        args += ["-v", f"{reg}:/usr/local/cargo/registry:ro"]
                else:
                    args += ["-v", f"{env[var]}:{where}:ro"]
        m2 = Path.home() / ".m2" / "repository"
        if language == "java" and _there(m2):
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
    over = False
    if rc not in (None, 0, 125):
        over, asked = _docker_oom(docker, name, OOM_WAIT_KILLED if rc == 137 else OOM_WAIT)
        if rc == 137 and not over:
            log(f"sandbox: the tests' program was ended by a kill (137). Docker, asked {asked} times, did not say "
                "that the container was over its memory, so this reads as a failure of the tests")
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
