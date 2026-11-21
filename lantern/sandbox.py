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
come from the launcher's own line and result (`_over_memory`). In a container they are said by the container's
first process, which is Lantern's own and not the tests' (`_first_process`, 2026-11-14): it starts the tests'
command, outlives it, and reads the kernel's own count of the programs of this container that the kernel ended
for the container's memory. Until then Docker alone was asked (`_docker_oom`), and Docker can lose the message
that tells it of such a kill when the program that was ended is the container's first and the container ends
with it: tests the kernel had stopped read as failed tests however long Docker was asked. Docker's answer stays
as the second source, for a container whose first process did not say it (a "false" is asked again for
`OOM_WAIT_KILLED` seconds after a kill and `OOM_WAIT` after any other error; a kill that neither names reads
as failed tests). A test that prints the line and ends with that result says of itself that it was stopped, and
gains "Incomplete" where it would have had "Blocked", never a pass. On Windows (2026-11-20, a firm pass or fail,
stage 4) the run's job counts it: the memory Windows has given the tests and everything they started, together,
which counts memory a program asked for and never wrote (Linux does not count that; a test of each says so).
Windows tells the job when they go over the limit, a message Windows promises to deliver for such a limit, and
`_stream` then ends the run, which is said to be over its memory exactly as on Linux; a wall at twice the limit,
and at least 1 GB above it, keeps a program that asks for very much at once from taking the computer's memory
before that (`winjob.wall`), and a program refused there is said the same way where Windows tells of it, which it
does not promise. Until then the job's limit was for each program alone: programs over it together were not
stopped, a program over it alone was refused memory, and its tests were reported as failed (the same project read
"Blocked" there and "Incomplete" on Linux). On macOS the limit is put on the address space as before.

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

On Windows (a firm pass or fail, stage 4, 2026-11-20). Until then a test that starts an event loop (an async test, a
FastAPI test client) failed in the sandbox there (found 2026-11-11): Windows has no call that makes a pair of
connected sockets, so Python builds the pair every event loop wakes itself with from a listener on this computer,
and the hook refused every listener, because Windows makes no network of the run's own. Now the hook lets a test
listen at this computer's own address at a port the system picks, and call or send only to a port where every
socket is one of the run's own programs, as Windows itself says (its own tables of this computer's sockets, with
the program of each, and the programs of the run's job, `lantern.winjob`); a datagram socket that sends before it
is bound is bound to this computer's own address first. Another program's port, a port a test chose, every address
at once and any other computer stay refused. The event loop Windows uses by default connects with calls Python
tells no hook about (`_overlapped`), and those are judged where the loop calls them. A file's name can lead to
another program or another computer there, and is read as Windows reads it before anything is opened, looked at
or listed: a pipe only of the run's own programs, no share of another computer (by its name, or by a drive letter
Windows gave it), no device but NUL and the console; nothing is handed to another program to open (on every
system) and no other computer's settings are asked for. Another computer's folders are left off the tests' PATH,
and a link of the project to another computer is not copied. What the hook cannot see there is not held: a
program that is not Python, code that calls the system's own library itself, and links the computer already has to
another computer's shares. Apps are started there as on Linux (`run_inside`; until 2026-11-20 none was, `NO_APPS`).

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
# Where `run_inside` starts nothing, and why. An app is asked on an event loop, and until 2026-11-20 the guard could
# not let one start on Windows without losing sight of what it connects to, so no app was started there. Since then
# it judges the calls of either loop there (this module's opening text) and every system Lantern runs on starts
# apps; a system that cannot is named here with the reason.
NO_APPS = ""

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
            det.insert(1, WINDOWS_PYTHON if _windows_rule() else
                       "writing outside the copy and its temp folder and opening network connections are refused")
        at = 2 if language == "python" else 1
        det[at:at] = _no_network_words(no_own, language)
    if sys.platform == "win32":
        det.insert(1, "inside a Windows job, which nothing it starts can leave")
    if _LINUX or sys.platform == "win32":
        det.append(f"{room} of memory for the tests and everything they start, counted together"
                   + (" (what Windows has given them, written to or not)" if sys.platform == "win32" else "")
                   + "; tests that use more are stopped, which is neither a pass nor a failure")
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
# On Windows the guard has a rule of its own where the run has no network of its own (`_windows_net`, a firm pass or
# fail, stage 4, 2026-11-20): until then the two sentences above stood there too, and since that stage they are not
# true there (found on GitHub's Windows machine while the tests of these words were read there).
WINDOWS_NET = ("{why}: on Windows the tests may still start a server at this computer's own address, on a port the "
               "system picks, and call what only their own programs listen at; every other address, on this "
               "computer or outside it, is refused")
WINDOWS_PYTHON = ("writing outside the copy and its temp folder is refused, and so is opening a network connection "
                  "to anything but the tests' own programs")
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


def _windows_rule() -> bool:
    """Does the guard's own rule for Windows decide what the tests' Python may reach here (`_windows_net`): on
    Windows, which makes a run no network of its own. Asked by the words, so that a test can ask them of a pretend
    system."""
    return sys.platform == "win32" and not _LINUX


def _no_network_words(why: str, language: str) -> list[str]:
    """What the sheet and the log say about a run with no network of its own: one sentence, and for Python's
    tests a second where nothing below Python holds the programs they start. On Windows the first says what the
    guard's own rule there lets through (`WINDOWS_NET`)."""
    first = (WINDOWS_NET if _windows_rule() else NO_OWN_NETWORK).format(why=why)
    if held_below_python():
        return [first]
    if language == "python":
        return [first, NOT_HELD_BESIDE.format(how=not_held_how())]
    return [NOT_HELD.format(why=why, how=not_held_how())]


def _was_off_network(backend: str, language: str, own: bool) -> bool:
    """Were the tests of a run off the network: in a container and in a network of the run's own, any program;
    elsewhere Python code (the guard), and another program only where something below Python holds it."""
    return bool(backend == "docker" or own or language == "python" or held_below_python())


def tests_off_the_network(language: str) -> bool:
    """Would the tests of a project in `language` run with the network off in this system's sandbox? For the
    sheet; a run says it of itself (`off_network` in its result)."""
    return _was_off_network(backend_for(language), language, not own_network())


# ---------------------------------------------------------------------------- what a run is kept from, in one line
NOTHING_LEAVES = "Nothing leaves this computer: the tests have no way out to the internet or to your network."
NAMES_LEAVE = ("Your code does not leave this computer: the libraries are fetched by name before the tests start, "
               "and the tests have no way out to the internet or to your network.")
NO_WAY_OUT = {"all": "The tests have no way out to the internet or to your network. ",
              "python": "Python code in the tests has no way out to the internet or to your network. ", "none": ""}
REACH_NETWORK = "reach the internet and your network"
REACH_FILES = "read and change the files {whose} can"


def reach(language: str, fetched: bool = False) -> dict:
    """What a run of a project's tests in `language` would be kept from on this system, for the sheet's last line
    and for the person's word before the run (review stage, 2026-11-15; until then that line was the first
    sentence below on every system and for every kind of test, under a list whose own lines said what is held).
    `network` and `files` are each "all" (every program of the run is held: a container, or the kernel's rules),
    "python" (Python code only, by Lantern's guard: a program the tests start that is not Python is not held)
    or "none". `words` is the line. `ask` is the sentence the person has to agree to before such tests are
    started (`server.reach_asked`), "" where every program is held. It reads the answers `describe` reads
    (`backend_for`, `held_below_python`, `landlock_abi`), so the line cannot promise what the list does not.
    `fetched`: the project's libraries would be fetched first, so their names do leave this computer."""
    python = language == "python"
    if backend_for(language) == "docker":
        network = files = "all"
    else:
        network = "all" if held_below_python() else "python" if python else "none"
        files = "all" if _LINUX and landlock_abi() >= 1 else "python" if python else "none"
    if network == files == "all":
        return {"network": network, "files": files, "words": NAMES_LEAVE if fetched else NOTHING_LEAVES, "ask": ""}
    # as root the tests run as the user nobody: what they can read and change is what every user can
    whose = "every user of this computer" if _LINUX and hasattr(os, "geteuid") and os.geteuid() == 0 else "you"
    can = " and ".join(x for x in (REACH_NETWORK if network != "all" else "",
                                   REACH_FILES.format(whose=whose) if files != "all" else "") if x)
    if python:
        # on Windows a Python the tests start by the bare name can be the computer's own, without the guard
        # (`_own_python_words`)
        more = ", or a Python they start by its bare name," if not _LINUX and sys.platform == "win32" else ""
        ask = (f"On this system a program the tests start that is not Python{more} can {can}: this run does not "
               "keep it from that.")
    else:
        ask = f"On this system these tests, which are not Python, can {can}: this run does not keep them from that."
    return {"network": network, "files": files, "words": NO_WAY_OUT[network] + ask, "ask": ask}


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
_WIN = _sys.platform == "win32"
_STREAM, _DGRAM = getattr(_socket, "SOCK_STREAM", 1), getattr(_socket, "SOCK_DGRAM", 2)
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
# An address is read here the way the system reads it: by what it holds. A pair, a text or bytes of a class of its
# own can answer anything for itself (its entries, its letters, whether it is the same as another value); the
# system goes by the value underneath, and so does the guard, through a plain copy made by the plain type's own
# means. Where the guard hands a value on, the copy is what goes down: what was judged is what is used.
def _held(x):
    for kind in (str, bytes, bytearray, tuple):
        if isinstance(x, kind):
            if type(x) is kind:
                return x
            try:
                return kind.__getitem__(x, slice(None))
            except TypeError:
                return x
    return x
def _pair(a):
    # An address and the host in it as plain values; a bytearray host as bytes, a copy nobody else can change.
    a = _held(a)
    if type(a) is tuple and a:
        host = _held(a[0])
        if type(host) is bytearray:
            host = bytes(host)
        if host is not a[0]:
            a = (host,) + a[1:]
    return a
def _as_handed(a):
    # Whether the host in an address, as it came, is one the system reads as the guard does. A text of a class
    # of its own writes itself out for the system by its own means, and bytes that can be changed may have been
    # changed since. The socket calls hand plain copies down (`_asks_first`), so such a host came another way.
    if isinstance(a, tuple) and tuple.__len__(a):
        h = tuple.__getitem__(a, 0)
        return not ((isinstance(h, str) and type(h) is not str) or isinstance(h, bytearray))
    return True
def _here(addr):
    # An address of this computer itself, as it is written: nothing is looked up to decide it. Its number counts
    # only where it is written the one way every system reads a number (`_number`): a part with a zero in front or
    # a digit of another script may be a name to the system, which then asks for it.
    addr = _pair(addr)
    host = addr[0] if type(addr) is tuple and addr else addr
    if type(host) in (bytes, bytearray):
        host = bytes(host).decode("ascii", "replace")
    if type(host) is not str:
        return False
    h = host.lower() if host.isascii() else host
    if h in ("", "localhost", "::1", "::", "0.0.0.0") or host in _SELF:
        return True
    if h.startswith("::ffff:"):
        h = h[7:]
    p = h.split(".")
    return len(p) == 4 and p[0] == "127" and _number(h)
def _number(host):
    # An address written out as a number: asking where it is asks nothing of any name server, the answer is the
    # number itself. Read strictly, so that what is not surely a number is still a name: four plain decimal parts
    # up to 255 with no zero in front (`_four`), or an IPv6 address written the one way every system reads one
    # (`_six`) that this system reads as one too, and nothing around it.
    host = _held(host)
    if type(host) in (bytes, bytearray):
        try:
            host = bytes(host).decode("ascii")
        except ValueError:
            return False
    if type(host) is not str or not host.isascii():
        return False
    if _four(host):
        return True
    if _six(host):
        try:
            _socket.inet_pton(_socket.AF_INET6, host)
            return True
        except (OSError, ValueError, AttributeError):
            return False
    return False
def _four(h):
    p = h.split(".")
    return len(p) == 4 and all(x.isdigit() and len(x) < 4 and int(x) < 256 and (x == "0" or x[0] != "0") for x in p)
def _six(h):
    # An IPv6 address as every system reads one: eight groups of one to four hex digits with a colon between
    # them, where one "::" may stand for the groups of zeros left out and the last two groups may be written as
    # an IPv4 number, read as strictly as any other. What this system reads as one is not enough: one system reads
    # more as a number than another (Windows takes a zero in front of a part of that IPv4 number, which Linux and
    # macOS take for a name), and what any of them may take for a name is a name here.
    head, gap, tail = h.partition("::")
    groups = (head.split(":") if head else []) + (tail.split(":") if tail else [])
    n = len(groups)
    if groups and "." in groups[-1]:
        if (gap and not tail) or not _four(groups[-1]):
            return False
        groups, n = groups[:-1], n + 1
    if not all(0 < len(g) < 5 and all(c in "0123456789abcdefABCDEF" for c in g) for g in groups):
        return False
    return n < 8 if gap else n == 8
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
    p = _os.fsdecode(_held(_os.fspath(path)))
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
    # followed whatever is done: the system then goes through a link to a folder. The name is read as the system
    # reads it, through a plain copy (a text of a class of its own can answer anything for itself). On Windows a
    # name of another computer, a device or a pipe is never one of the run's folders, and is not looked at (the
    # system would reach for it): only NUL and the console are anybody's to write to.
    try:
        n = _os.fsdecode(_held(_os.fspath(path)))
        if _WIN:
            kind = _winplace(n)[0]
            if kind != "local":
                return kind == "quiet"
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
    if p in _DEV or (_WIN and _winplace(p)[0] == "quiet"):
        return True
    return any(p == w or p.startswith(w + _os.sep) for w in _W)
def _block(what):
    msg = "LANTERN-SANDBOX-BLOCKED: " + what
    try:
        _os.write(2, (msg + "\n").encode("utf-8", "replace"))
    except OSError:
        pass
    raise PermissionError(msg)
_TOLD = set()
def _say(what):
    # the line `_block` writes, for a call that answers "no" where it is refused (whether a file is there), once
    if what in _TOLD or len(_TOLD) >= 64:
        return
    _TOLD.add(what)
    try:
        _os.write(2, ("LANTERN-SANDBOX-BLOCKED: " + what + "\n").encode("utf-8", "replace"))
    except OSError:
        pass
def _shown(text):
    # a name as one line of the run's output
    return text[:1000].replace("\n", "?").replace("\r", "?")
def _plain_path(path):
    # A name as the system is handed it: through its own __fspath__ once, as a plain copy (a text of a class of its
    # own may answer anything for itself, the system reads what it holds), and as text. (None, None): no name.
    try:
        p = _held(_os.fspath(path))
        if type(p) is bytes:
            return p, _os.fsdecode(p)
        if type(p) is str:
            return p, p
    except (TypeError, ValueError, UnicodeError):
        pass
    return None, None
# Windows (a firm pass or fail, stage 4, 2026-11-20). There no wall of the kernel's own stands behind this guard, and
# a file's name can lead to other programs and other computers: a pipe (`\\.\pipe\<name>`) is another program of this
# computer, a share (`\\<computer>\<share>\...`) is a computer on the network, reached when a program only opens,
# looks at or lists a name there, and a device (`\\.\<name>`) is a part of this computer that is no file. A name is
# read here by its text, as Windows reads it, before anything is opened.
_QUIET = {"NUL", "CON", "CONIN$", "CONOUT$"}          # the devices a test may use: nothing, and its own console
_RESERVED = _QUIET | {"PRN", "AUX"} | {k + d for k in ("COM", "LPT") for d in "0123456789\u00b9\u00b2\u00b3"}
def _drive(part):
    return len(part) == 2 and part[1] == ":" and part[0].isascii() and part[0].isalpha()
def _remote_drive(letter):
    # Is this drive letter a share of another computer (`net use Q: \\computer\share`)? Windows keeps that with
    # the drive letter and says it without asking the network (DRIVE_REMOTE).
    if _LIB is None:
        return False
    try:
        return _LIB[5](letter + ":\\") == 4
    except Exception:
        return False
def _winplace(name):
    # ("local", None): a file of this computer's own disks; ("pipe", the pipe's name); ("share", None): a computer
    # on the network, this one too, also by a drive letter Windows gave it; ("device", None); ("quiet", None): NUL
    # or the console, by their names alone.
    n = name.replace("/", "\\")
    if n[:4] in ("\\\\.\\", "\\\\?\\", "\\??\\"):
        rest = n[4:]
        parts = rest.split("\\")
        first = parts[0].lower()
        if any(p in (".", "..") for p in parts):
            return "device", None      # Windows reads these dots from the top of such a name, past a drive
        if first == "pipe" and len(parts) > 1:
            return "pipe", rest[5:]
        if first == "globalroot" and len(parts) > 3 and parts[1].lower() == "device" and parts[2].lower() == "namedpipe":
            return "pipe", "\\".join(parts[3:])
        if first == "unc":
            return "share", None
        if len(parts) == 1 and parts[0].upper() in _QUIET:
            return "quiet", None
        if len(parts) > 1 and _drive(parts[0]):
            return ("share" if _remote_drive(parts[0][0]) else "local"), None
        if len(parts) > 1 and first.startswith("volume{") and first.endswith("}"):
            return "local", None
        return "device", None
    if n[:2] == "\\\\" or (_drive(n[:2]) and _remote_drive(n[0])):
        return "share", None
    last = n.split("\\")[-1]
    if _drive(last[:2]):
        last = last[2:]
    base = last.split(".", 1)[0].split(":", 1)[0].rstrip(" ").upper()
    if base in _RESERVED:
        # a device in any folder, on the Windows of before 11; NUL and the console are harmless there, and on
        # Windows 11 such a name is a file, which is judged as a file
        if n.upper() in _QUIET:
            return "quiet", None
        return ("local" if base in _QUIET else "device"), None
    return "local", None
def _pipe_pid(name):
    # The program that made a pipe, by the name Python gives the pipes it makes (multiprocessing: pyc-<pid>-...,
    # asyncio: python-pipe-<pid>-...); None for any other name.
    low = name.lower()
    for head in ("pyc-", "python-pipe-"):
        if low.startswith(head) and "\\" not in name:
            digits, dash, _ = name[len(head):].partition("-")
            if dash and 0 < len(digits) < 11 and digits.isascii() and digits.isdigit() and digits[0] != "0":
                return int(digits)
    return None
def _windows_place(name, made=False):
    # What the guard says of a name on Windows. (None, False): a file of this computer's own disks, judged further
    # as on any system. (None, True): a pipe of the run's own, NUL and the console, which are no file of a disk and
    # are the run's to use. (the refusal, False): anything else. `made`: a pipe this program makes, which must be
    # named for this program.
    kind, pipe = _winplace(name)
    if kind == "local":
        return None, False
    if kind == "quiet":
        return None, True
    if kind == "pipe":
        pid = _pipe_pid(pipe)
        if pid is not None and (pid == _os.getpid() if made else pid in _run_pids()):
            return None, True
        return "network pipe " + _shown(name), False
    if kind == "share":
        return "network share " + _shown(name), False
    return "device " + _shown(name) + " (the tests may open no device of this computer but NUL and the console)", False
def _not_local(path):
    # the refusal of a name on Windows, or None (anywhere else, and for what is no name)
    name = _plain_path(path)[1] if _WIN and path is not None and not isinstance(path, int) else None
    return None if name is None else _windows_place(name)[0]
# Who holds a port, as Windows itself says (its own tables of this computer's sockets, with the program of each), and
# which programs are the run's: this one and, where the launcher says the run is held in a job of its own
# (LANTERN_SANDBOX_JOB, lantern.winjob: nothing started in it can leave it), every program of that job.
_JOB = _WIN and _os.environ.get("LANTERN_SANDBOX_JOB") == "own"
_LIB = None
if _WIN:
    try:
        import ctypes as _ct
        _sockopt = _ct.WinDLL("ws2_32").getsockopt
        _sockopt.argtypes = (_ct.c_size_t, _ct.c_int, _ct.c_int, _ct.c_void_p, _ct.POINTER(_ct.c_int))
        _sockopt.restype = _ct.c_int
        _drives = _ct.WinDLL("kernel32").GetDriveTypeW
        _drives.argtypes, _drives.restype = (_ct.c_wchar_p,), _ct.c_uint
        _LIB = (_ct, _ct.WinDLL("kernel32", use_last_error=True).QueryInformationJobObject,
                _ct.WinDLL("iphlpapi").GetExtendedTcpTable, _ct.WinDLL("iphlpapi").GetExtendedUdpTable, _sockopt,
                _drives)
    except Exception:
        _LIB = None
# (datagram, family) -> (a row's size, where its port is, where its program is): MIB_TCPROW_OWNER_PID,
# MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID
_ROWS = {(False, 2): (24, 8, 20), (False, 23): (56, 20, 52), (True, 2): (12, 4, 8), (True, 23): (28, 20, 24)}
def _owners(port, dgram):
    # The programs (by number) that hold this computer's sockets at a port: listeners, or datagram sockets, of
    # either family. None where Windows does not say.
    if _LIB is None:
        return None
    ct, call = _LIB[0], _LIB[3] if dgram else _LIB[2]
    found = set()
    for family in (2, 23):
        row, at, who = _ROWS[(dgram, family)]
        size, raw, got = ct.c_ulong(0), None, None
        for _ in range(8):
            buf = (ct.c_char * max(size.value, 8))()
            got = call(buf, ct.byref(size), 0, family, 1 if dgram else 3, 0)   # UDP_TABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER
            if got == 0:
                raw = buf.raw
                break
            if got != 122:                 # ERROR_INSUFFICIENT_BUFFER: the table grew since its size was asked
                break
        if raw is None:
            if family == 23 and got == 50:     # ERROR_NOT_SUPPORTED: this computer has no IPv6
                continue
            return None
        n = int.from_bytes(raw[:4], "little")
        if 4 + n * row > len(raw):
            return None
        for i in range(n):
            o = 4 + i * row
            if int.from_bytes(raw[o + at:o + at + 2], "big") == port:
                found.add(int.from_bytes(raw[o + who:o + who + 4], "little"))
    return found
def _job_pids():
    if _LIB is None:
        return None
    ct, n = _LIB[0], 64
    ptr = ct.sizeof(ct.c_void_p)
    for _ in range(6):
        size = 8 + n * ptr
        buf = (ct.c_char * size)()
        if _LIB[1](None, 3, buf, size, None):        # JobObjectBasicProcessIdList of this program's own job
            raw = buf.raw
            listed = int.from_bytes(raw[4:8], "little")
            if 8 + listed * ptr > len(raw):
                return None
            return {int.from_bytes(raw[8 + i * ptr:8 + (i + 1) * ptr], "little") for i in range(listed)}
        if ct.get_last_error() != 234:              # ERROR_MORE_DATA: more programs than the list could hold
            return None
        n *= 4
    return None
def _run_pids():
    pids = {_os.getpid()}
    if _JOB:
        more = _job_pids()
        if more:
            pids |= more
    return pids
def _runs_port(dgram, port):
    owners = _owners(port, dgram)
    return bool(owners) and owners <= _run_pids()
def _loopback(host):
    # this computer's own address, written as a number
    if type(host) is bytes:
        try:
            host = host.decode("ascii")
        except ValueError:
            return False
    if type(host) is not str or not host.isascii():
        return False
    h = host.lower()
    if h.startswith("::ffff:") and _four(h[7:]):
        h = h[7:]
    if _four(h):
        return h.split(".")[0] == "127"
    if _six(h):
        try:
            return _socket.inet_pton(_socket.AF_INET6, h) == bytes(15) + b"\1"
        except (OSError, ValueError, AttributeError):
            return False
    return False
def _windows_net(word, kind, to):
    # On Windows, where the run has no network of its own: a test listens at this computer's own address only and
    # at port 0, a port the system picks (there a port somebody else holds can be shared, and one a test chose may
    # be one), and calls or sends only to this computer's own address, at a port where every socket is one of the
    # run's own programs, as Windows itself says. Anything else is refused, as on any system without a network of
    # the run's own.
    if type(to) is tuple and len(to) >= 2 and _loopback(to[0]) and type(to[1]) is int and kind in (_STREAM, _DGRAM):
        if word == "bind":
            if to[1] == 0:
                return
        elif 0 < to[1] < 65536 and _runs_port(kind == _DGRAM, to[1]):
            return
    elif to is None and word != "bind":
        return
    _block("network " + word + " " + repr("" if to is None else to)[:80])
def _written_out(sock, to):
    # On Windows the name this computer keeps for itself goes down as its number, so that what the guard judged, a
    # number, is what the system is handed.
    if type(to) is tuple and to and type(to[0]) in (str, bytes):
        host = to[0].decode("ascii", "replace") if type(to[0]) is bytes else to[0]
        if host.isascii() and host.lower() == "localhost":
            try:
                fam = _family(sock)
            except (TypeError, AttributeError):
                return to
            number = {getattr(_socket, "AF_INET", 2): "127.0.0.1", getattr(_socket, "AF_INET6", 23): "::1"}.get(fam)
            if number is not None:
                return (number,) + to[1:]
    return to
def _handle_kind(handle):
    # the kind of socket a handle is (SOCK_STREAM, SOCK_DGRAM, ...), as the system says; None where it does not
    if _LIB is None or type(handle) is not int or not 0 <= handle < 1 << 64:
        return None
    ct = _LIB[0]
    v, n = ct.c_int(0), ct.c_int(4)
    try:
        if _LIB[4](handle, 0xFFFF, 0x1008, ct.byref(v), ct.byref(n)) != 0:     # SOL_SOCKET, SO_TYPE
            return None
    except Exception:
        return None
    return v.value
def _where(path, made=False):
    # A name a call is handed, as the plain name and its text, and whether it is the run's own to use whatever is
    # done with it (a pipe of the run's own, NUL, the console). On Windows a name of another computer, another
    # program's pipe or a device is refused here and named (`_windows_place`), before anything is done with it.
    raw, name = _plain_path(path)
    if name is None or not _WIN:
        return raw, name, False
    why, own = _windows_place(name, made)
    if why is not None:
        _block(why)
    return raw, name, own
def _program_of(line):
    # the program a Windows command line starts, as Windows reads its first word
    c = line.lstrip(" \t")
    if c[:1] == '"':
        return c[1:].split('"', 1)[0]
    return c.split(" ", 1)[0].split("\t", 1)[0]
def _unquote(text):
    # %HH as the byte it stands for, the way SQLite reads a name written as a URI; anything else as it is written
    if "%" not in text:
        return text
    raw, out, i = text.encode("utf-8", "surrogatepass"), bytearray(), 0
    while i < len(raw):
        two = raw[i + 1:i + 3]
        if raw[i] == 37 and len(two) == 2 and all(c in b"0123456789abcdefABCDEF" for c in two):
            out.append(int(two, 16))
            i += 3
        else:
            out.append(raw[i])
            i += 1
    return out.decode("utf-8", "replace")
def _sqlite_files(name):
    # The file a database name stands for. A name written as a URI (file:..., which SQLite reads as one where it is
    # told to) stands for the place in it, read as SQLite reads it: its %HH written out, cut at a NUL, with the
    # computer it names (none, or "localhost", is this one), and none where every `mode` it gives is "memory".
    # Until 2026-11-20 a URI was read by its text: "xmode=memory" read as a database in memory, and a place
    # written with %HH was judged as written.
    if name[:5].lower() != "file:":
        return [] if name in ("", ":memory:") else [name]
    path, _, query = name[5:].split("#", 1)[0].partition("?")
    modes = [_unquote(v) for k, _, v in (q.partition("=") for q in query.split("&")) if _unquote(k) == "mode"]
    if modes and all(m == "memory" for m in modes):
        return []
    host = ""
    if path[:2] == "//":
        host, slash, path = path[2:].partition("/")
        path = slash + path
    place = _unquote(path).split("\0", 1)[0]
    if host and host.lower() != "localhost":
        place = "//" + host + place         # another computer's: refused on Windows, nowhere on any other system
    elif _WIN and place[:1] == "/" and _drive(place[1:3]):
        place = place[1:]
    return [] if place in ("", ":memory:") else [place]
# What a Windows call that opens a file is asked for that changes the file: GENERIC_WRITE, GENERIC_ALL,
# MAXIMUM_ALLOWED, ACCESS_SYSTEM_SECURITY, FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_DELETE_CHILD,
# FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER.
_FILE_WRITES = 0x40000000 | 0x10000000 | 0x02000000 | 0x01000000 | 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 \
    | 0x40000 | 0x80000
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
        p = _os.path.abspath(_os.fsdecode(_held(_os.fspath(path))))
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
        raw, name, own = _where(path)
        if own or name is None:
            return
        w = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & _WFLAGS)
        if w and not _ok(raw):
            _block("write to " + _shown(name))
        if _CLOSED and not w:
            _reads(raw)
    elif ev in ("os.listdir", "os.scandir"):
        p = args[0] if args else None
        if p is not None and not isinstance(p, int):
            raw = _where(p)[0]
            if _CLOSED and raw is not None:
                _reads(raw, True)
    elif ev in _PATHS:
        for i, at, follow in _PATHS[ev]:
            p = args[i] if i < len(args) else None
            fd = args[at] if at is not None and at < len(args) else None
            if p is not None and not isinstance(p, int):
                raw, name, own = _where(p)
                if name is not None and not own and not _ok(raw, fd, follow):
                    _block(ev.split(".")[-1] + " " + _shown(_full(raw, fd) or name))
        if ev == "os.symlink" and args:
            _where(args[0])            # the place the new link names: on Windows never another computer's
    elif ev == "sqlite3.connect":
        # SQLite opens and writes its files itself, below Python: a database file outside the folders the run may
        # write in is refused when it could be changed or would be made. One that cannot be written (a file of
        # the copy an app is started on, which is read-only) can still be read.
        name = _plain_path(args[0] if args else None)[1]
        for p in [] if name is None else _sqlite_files(name):
            if _where(p)[2]:
                continue
            if not _ok(p) and (not _os.path.exists(p) or _os.access(p, _os.W_OK)):
                _block("write to " + _shown(p))
    elif ev in ("socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg"):
        s = args[0]
        try:
            fam = _family(s)       # the socket's own family, whatever a class made from it says of itself
        except (TypeError, AttributeError):
            fam = getattr(s, "family", None)
        came = args[1] if len(args) > 1 else None
        to = _pair(came)
        word = ev.split(".")[1]
        if fam in _NET:
            # In a network of the run's own: listening anywhere (there is only this computer in it), and calling
            # or sending to this computer's own address. Any other address is refused before it is tried, so
            # the run's log says what the tests reached for. So is an address whose host the system may have
            # read as another than the guard reads here (`_as_handed`). On Windows, which makes no network of the
            # run's own: the run's own sockets at this computer's own address (`_windows_net`).
            if not _as_handed(came):
                _block("network " + word + " " + repr("" if to is None else to)[:80])
            if _WIN and not _OWN:
                try:
                    kind = _kind(s)
                except (TypeError, AttributeError):
                    kind = None
                _windows_net(word, kind, to)
            elif not (_OWN and (ev == "socket.bind" or to is None or _here(to))):
                _block("network " + word + " " + repr("" if to is None else to)[:80])
        elif fam == _UNIX and fam is not None and isinstance(to, (str, bytes, bytearray)) and to:
            # A socket file is how the programs of one computer talk to each other (a desktop's message bus,
            # Docker): one outside the run's own folders is another program's, or would be made where the tests
            # may not write. A socket name that is no file (Linux) is kept apart only in a network of the run's own.
            name = _os.fsdecode(bytes(to)) if not isinstance(to, str) else to
            if name[:1] == "\0":
                if not _OWN:
                    _block("network " + word + " to the socket name " + repr(name[1:])[:80])
            elif not _ok(name):
                _block("network " + word + " to the socket file " + name[:200])
        elif _WIN:
            # another kind of socket (Bluetooth, a virtual machine's): there is none of the run's own
            _block("network " + word + " of a socket of the family " + repr(fam)[:20] + " " + repr(to)[:80])
    elif ev in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"):
        # This computer under its own names is no question to the network, and neither is where an address written
        # as a number is. Who a number belongs to (gethostbyaddr) is one, and so is who this computer's own name
        # belongs to, except in a network of the run's own, which nothing leaves (elsewhere `_whose` answers it).
        host = args[0] if args else None
        if type(host) not in (str, bytes, type(None)):
            # A text of a class of its own, or one that can still be changed: the system may be asked for another
            # host than is read here. The lookups hand a plain copy down (`_plainly`), so this one came another way.
            _block("network lookup " + repr(_held(host))[:80])
        if host not in (None, "", "localhost", "127.0.0.1", "::1", b"localhost") \
                and not (host in _SELF and (ev != "socket.gethostbyaddr" or _OWN)) \
                and not (ev != "socket.gethostbyaddr" and _number(host)):
            _block("network lookup " + repr(host)[:80])
    elif ev == "socket.getnameinfo":
        # Python's event does not say whether the number or its owner is asked for; `_who` has read the call and
        # refused the second. A name in the address is no address to ask about, whoever asks.
        to = _pair(args[0]) if args else None
        host = to[0] if type(to) is tuple and to else None
        if type(host) in (str, bytes) and not _here(to) and not _number(host):
            _block("network lookup " + repr(host)[:80])
    elif ev in _HANDED:
        # A file or an address handed to another program of this computer to open (the one it is opened with, a
        # browser for an address), which is none of the run's: on every system, before anything is handed over.
        what = _plain_path(args[0] if args else None)[1]
        _block("network " + _HANDED[ev] + " " + ("" if what is None else repr(what)[:200])
               + " (handed to another program of this computer to open)")
    elif ev == "winreg.ConnectRegistry":
        # the settings of another computer, over the network; this computer's own (no name) are not
        computer = _held(args[0]) if args else None
        if computer is not None and computer != "":
            _block("network registry of " + repr(computer)[:80])
    elif ev == "_winapi.CreateFile":
        # how a program of Windows opens a file, a pipe or a device by its name, below `open`
        name, access, share, made, flags = (tuple(args) + (None,) * 5)[:5]
        raw, plain, own = _where(name)
        if plain is not None and not own:
            writes = not (type(access) is int and not access & _FILE_WRITES and type(made) is int and made == 3
                          and type(flags) is int and not flags & 0x04000000)    # OPEN_EXISTING, DELETE_ON_CLOSE
            if writes and not _ok(raw, None, not (type(flags) is int and flags & 0x00200000)):   # OPEN_REPARSE_POINT
                _block("write to " + _shown(plain))
    elif ev == "_winapi.CreateNamedPipe":
        # a pipe is made only under a name of this program's own: another end of another program's pipe would
        # take its callers
        _where(args[0] if args else None, made=True)
    elif ev == "_winapi.CreateJunction":
        if args:
            _where(args[0])            # the place the junction names
        raw, name, own = _where(args[1] if len(args) > 1 else None)
        if name is not None and not own and not _ok(raw, None, False):
            _block("junction " + _shown(name))
    elif ev == "_winapi.CopyFile2":
        if args:
            _where(args[0])
        raw, name, own = _where(args[1] if len(args) > 1 else None)
        flags = args[2] if len(args) > 2 else 0
        if name is not None and not own and not _ok(raw, None, not (type(flags) is int and flags & 0x800)):
            _block("copyfile " + _shown(name))   # COPY_FILE_COPY_SYMLINK: the link itself is made
    elif ev == "_winapi.CreateProcess":
        # a program started from another computer, or in a folder of another computer
        program, line, folder = (tuple(args) + (None, None, None))[:3]
        for p in (program, folder, _program_of(line) if type(line) is str else None):
            if p:
                _where(p)
    elif ev in _NAMED_FIRST:
        # a library loaded, a folder libraries are looked for in, the current folder, a program started: on
        # Windows never another computer's, a device or a pipe
        p = args[_NAMED_FIRST[ev]] if len(args) > _NAMED_FIRST[ev] else None
        if p is not None and not isinstance(p, int):
            _where(p)
_HANDED = {"os.startfile": "startfile", "os.startfile/2": "startfile", "webbrowser.open": "browser"}
_NAMED_FIRST = {"ctypes.dlopen": 0, "os.add_dll_directory": 0, "os.chdir": 0, "os.exec": 0, "os.spawn": 1,
                "os.posix_spawn": 0}
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
# A name in an address. A socket hands an address to the system in five calls, and where the address holds a host
# name Python has it looked up on the way down and tells its hooks of the call afterwards. So the five calls ask
# here first: for a name that is not this computer's and not a number, Python's own event for a lookup is raised,
# which is refused above like any lookup once the project's own hooks have seen it, and the system is not asked.
# A number, this computer's names and the two words that are no names go down as they did. This holds for
# `socket.socket` and every class made from it (a TLS socket, a test's own), and for an address or a host of a
# class of its own: the address is read by what it holds, and its plain copy is what goes down (`_pair`). A
# program that takes the type beneath `socket.socket`, loads the socket module anew or calls the system's library
# itself is held by the kernel's walls only.
import _socket as _below
_family, _kind, _proto = (getattr(_below.socket, n).__get__ for n in ("family", "type", "proto"))
def _name_first(sock, address):
    # `address` as `_pair` gives it
    if type(address) is not tuple or not address:
        return
    host = address[0]
    if type(host) not in (str, bytes) or _number(host) or _here(address) \
            or host in ("<broadcast>", b"<broadcast>"):
        return
    try:
        family, kind, proto = _family(sock), _kind(sock), _proto(sock)
    except (TypeError, AttributeError):
        return                     # no socket at all: what is wrong with the call is the system's to say
    if family in _NET:
        _sys.audit("socket.getaddrinfo", host, address[1] if len(address) > 1 else None, family, kind, proto)
        _block("network lookup " + repr(host)[:80])
def _bound_first(sock, to):
    # On Windows a datagram socket that sends, or is connected, before it is bound is bound by the system at every
    # address of this computer, where other computers can send to it. One that goes to this computer's own address
    # is bound to that address first, at a port the system picks, judged as any bind is.
    try:
        if _kind(sock) != _DGRAM or _family(sock) not in (2, 23):
            return
        _below.socket.getsockname(sock)
        return                     # bound already
    except (TypeError, AttributeError):
        return
    except OSError:
        pass                       # WSAEINVAL: not bound yet
    if type(to) is tuple and to and _loopback(to[0]):
        try:
            _below.socket.bind(sock, ("::1" if _family(sock) == 23 else "127.0.0.1", 0))
        except OSError:
            pass                   # the call itself then gets the system's own answer
def _asks_first(name, at):
    down = getattr(_socket.socket, name, None)
    if down is None:               # sendmsg: not on every system
        return
    def call(self, *args, **more):
        i = at(args)               # where the address stands among what the call was given
        if i is not None:
            to = _pair(args[i])
            _name_first(self, to)
            if _WIN and not _OWN:
                to = _written_out(self, to)
                if name != "bind":
                    _bound_first(self, to)
            if to is not args[i]:
                args = args[:i] + (to,) + args[i + 1:]
        return down(self, *args, **more)
    call.__name__, call.__qualname__, call.__doc__ = name, "socket." + name, down.__doc__
    setattr(_socket.socket, name, call)
for _n in ("connect", "connect_ex", "bind"):
    _asks_first(_n, lambda a: 0 if a else None)
_asks_first("sendto", lambda a: len(a) - 1 if len(a) > 1 else None)
_asks_first("sendmsg", lambda a: 3 if len(a) > 3 else None)
# Who an address is. `getnameinfo` asks that, as `gethostbyaddr` does, unless it is told to answer with the number
# itself, and Python's event for it does not say which. So the call is read here. An address that is only written
# out (a number, or this computer's own, with NI_NUMERICHOST) goes down: nothing is asked of anybody. Who an address
# belongs to goes down only for this computer's own address in a network of the run's own, which nothing leaves.
# Everything else, a name in the address and a number whose owner is asked for, is refused as the lookup it is.
_NUMERIC = getattr(_socket, "NI_NUMERICHOST", 1)
def _who(down):
    def getnameinfo(sockaddr, flags, /):
        sockaddr = _pair(sockaddr)
        host = sockaddr[0] if type(sockaddr) is tuple and sockaddr else None
        if type(host) in (str, bytes):
            here = _here(sockaddr)
            written = isinstance(flags, int) and int.__and__(flags, _NUMERIC) and (here or _number(host))
            if not written and not (_OWN and here):
                _sys.audit("socket.gethostbyaddr", host)
                _block("network lookup " + repr(host)[:80])
        return down(sockaddr, flags)
    return getnameinfo
# Who this computer is under its own name (`socket.getfqdn` asks: a mail library for a message's id, an HTTP
# server when it starts). In a network of the run's own nothing leaves, and the system is asked. Anywhere else
# the system may ask the network around it, so the guard answers itself, with the name at this computer's own
# address, and the system is not asked at all. Nothing is refused, so no honest test is held up.
def _whose(down):
    def gethostbyaddr(host, /):
        host = _held(host)
        if type(host) is bytearray:
            host = bytes(host)
        if not _OWN and type(host) is str and host in _SELF:
            return (host, [], ["127.0.0.1"])
        return down(host)
    return gethostbyaddr
for _n, _f in (("getnameinfo", _who), ("gethostbyaddr", _whose)):
    _f = _f(getattr(_below, _n))
    _f.__qualname__, _f.__doc__ = _n, getattr(_below, _n).__doc__
    setattr(_socket, _n, _f)
    setattr(_below, _n, _f)
# The lookups themselves. Python has a text host written out for the system by a codec, which asks a class made
# from `str` to do the writing, and tells its hooks of the value as it came. So the host goes down as its plain
# copy: what the hooks are told of is what the system is asked for.
def _plainly(name, word):
    down = getattr(_below, name)
    def lookup(*args, **more):
        if args:
            host = _held(args[0])
            if word is None and type(host) is bytearray:
                host = bytes(host)
            if host is not args[0]:
                args = (host,) + args[1:]
        elif word in more:
            more[word] = _held(more[word])
        return down(*args, **more)
    lookup.__name__, lookup.__qualname__, lookup.__doc__ = name, name, down.__doc__
    setattr(_below, name, lookup)
    if getattr(_socket, name, None) is down:     # `socket.getaddrinfo` is Python's own and calls the one beneath
        setattr(_socket, name, lookup)
_plainly("getaddrinfo", "host")
_plainly("gethostbyname", None)
_plainly("gethostbyname_ex", None)
# Windows: the calls Python tells its hooks nothing of. The event loop Windows uses unless a program asks for
# another connects, sends and opens pipes with calls of its own module (`_overlapped`), and a program that looks at
# a name (whether it is there, what it is, where a link leads, how much room its disk has) or waits for a pipe asks
# the system with no event either; for a name of another computer the system then reaches for it over the network.
# Those calls are wrapped here, by the names programs call them by, and judge as the events above judge. A program
# that loads such a module anew, or calls the system's own library itself, is not held by this guard.
if _WIN:
    try:
        import _overlapped as _ovl
    except ImportError:
        _ovl = None
    try:
        import _winapi as _wa, nt as _nt
    except ImportError:
        _wa = _nt = None
    def _same(call, down, name):
        call.__name__, call.__qualname__ = name, name
        call.__doc__ = getattr(down, "__doc__", None)
        return call
    def _net_of(word, handle, came, want=None):
        # an address one of the loop's calls hands the system, judged as `_judge` judges a socket's
        to = _pair(came)
        kind = _handle_kind(handle)
        if kind is None or (want is not None and kind != want) or not _as_handed(came):
            _block("network " + word + " " + repr("" if to is None else to)[:80])
        _windows_net(word, kind, to)
        if kind == _DGRAM and type(to) is tuple and len(to) in (2, 4):
            # the family the loop's call reads the address in: a pair is IPv4, four parts IPv6
            s = _below.socket(2 if len(to) == 2 else 23, kind, 0, handle)
            try:
                _bound_first(s, to)
            finally:
                s.detach()
        return to
    if _ovl is not None:
        _OV = _ovl.Overlapped
        class _Overlapped:
            # one asynchronous call of the loop's: the two that reach an address are judged, the rest are its own
            __slots__ = ("_ov",)
            def __init__(self, *args, **more):
                self._ov = _OV(*args, **more)
            def __getattr__(self, name):
                if name == "_ov":
                    raise AttributeError(name)
                return getattr(self._ov, name)
            def ConnectEx(self, handle, address, /):
                return self._ov.ConnectEx(handle, _net_of("connect", handle, address, _STREAM))
            def WSASendTo(self, handle, buf, flags, address, /):
                return self._ov.WSASendTo(handle, buf, flags, _net_of("sendto", handle, address, _DGRAM))
        _Overlapped.__name__ = _Overlapped.__qualname__ = "Overlapped"
        _Overlapped.__module__, _Overlapped.__doc__ = "_overlapped", _OV.__doc__
        def _loop_calls(connect, pipe, bind):
            def WSAConnect(handle, address, /):
                return connect(handle, _net_of("connect", handle, address))
            def ConnectPipe(address, /):
                # a client's end of a pipe, opened to read and write: a pipe of the run's own, or a file it may write
                raw, name, own = _where(address)
                if name is not None and not own and not _ok(raw):
                    _block("write to " + _shown(name))
                return pipe(address if raw is None else raw)
            def BindLocal(handle, family, /):
                # The loop binds a socket before it connects it, to every address at a port the system picks: a
                # socket bound so could be made a listener at every address. It is bound to this computer's own
                # address instead, judged as any bind is, which is all a connection to it needs.
                if family not in (2, 23):
                    return bind(handle, family)          # the system's own answer
                kind = _handle_kind(handle)
                if kind is None:
                    _block("network bind of a handle that is no socket of this program")
                s = _below.socket(family, kind, 0, handle)
                try:
                    s.bind(("::1" if family == 23 else "127.0.0.1", 0))
                finally:
                    s.detach()
            return (_same(WSAConnect, connect, "WSAConnect"), _same(ConnectPipe, pipe, "ConnectPipe"),
                    _same(BindLocal, bind, "BindLocal"))
        _ovl.WSAConnect, _ovl.ConnectPipe, _ovl.BindLocal = _loop_calls(_ovl.WSAConnect, _ovl.ConnectPipe, _ovl.BindLocal)
        _ovl.Overlapped = _Overlapped
    if _wa is not None:
        def _waits(down):
            def WaitNamedPipe(name, timeout, /):
                raw = _where(name)[0]
                return down(name if raw is None else raw, timeout)
            return _same(WaitNamedPipe, down, "WaitNamedPipe")
        _wa.WaitNamedPipe = _waits(_wa.WaitNamedPipe)
        if callable(getattr(_wa, "CopyFile2", None)):
            # how `shutil.copy2` copies on Windows: judged here as its event is judged, should a Python not raise it
            def _copies(down):
                def CopyFile2(existing_file_name, new_file_name, flags, progress_routine=None):
                    _judge("_winapi.CopyFile2", (existing_file_name, new_file_name, flags))
                    return down(existing_file_name, new_file_name, flags, progress_routine)
                return _same(CopyFile2, down, "CopyFile2")
            _wa.CopyFile2 = _copies(_wa.CopyFile2)
    def _placed(down, quiet):
        # A call that looks at a name. Another computer's, a device or another program's pipe is refused and named
        # before the system is asked; a call that only answers yes or no answers no, and the name is said once.
        def call(path, *args, **more):
            if path is not None and not isinstance(path, int):
                raw, name = _plain_path(path)
                if name is not None:
                    why = _windows_place(name)[0]
                    if why is not None:
                        if quiet:
                            _say(why)
                            return False
                        _block(why)
                    path = raw
            return down(path, *args, **more)
        return _same(call, down, getattr(down, "__name__", "call"))
    if _nt is not None:
        _WRAPPED = {}
        for _n, _quiet in (("stat", 0), ("lstat", 0), ("readlink", 0), ("_getfinalpathname", 0),
                           ("_getvolumepathname", 0), ("_getdiskusage", 0), ("_findfirstfile", 0), ("access", 1),
                           ("_path_exists", 1), ("_path_isdir", 1), ("_path_isfile", 1), ("_path_islink", 1),
                           ("_path_isjunction", 1), ("_path_lexists", 1), ("_path_isdevdrive", 1)):
            _f = getattr(_nt, _n, None)
            if callable(_f):
                _WRAPPED[id(_f)] = (_f, _placed(_f, _quiet))
        # by every name the system's own modules hold them under (ntpath has some of them as its own functions)
        for _m in (_nt, _os, _os.path):
            for _n, _f in list(vars(_m).items()):
                if id(_f) in _WRAPPED and _WRAPPED[id(_f)][0] is _f:
                    setattr(_m, _n, _WRAPPED[id(_f)][1])
        for _n in ("supports_dir_fd", "supports_fd", "supports_follow_symlinks", "supports_effective_ids"):
            _s = getattr(_os, _n, None)
            if isinstance(_s, set):
                _s.update(w for f, w in list(_WRAPPED.values()) if f in _s)
_sys.addaudithook(_hook)
_sys.addaudithook = _add
_sys.lantern_sandbox_guard = "on"   # lantern.tracehook looks for this before it runs a test (LANTERN_SANDBOX_GUARD)
'''


# ---------------------------------------------------------------------------- running
class Result(dict):
    pass


def _copy(repo: Path, dst: Path) -> list[str]:
    """The project, copied for a run of its tests; its links stay links. On Windows a link that names a place of
    another computer (a share, by its name or by a drive letter Windows gave it) is not copied, and its name is
    handed back: a test that opens it would have Windows reach for that computer over the network, and the guard,
    which reads the name the test gives, would see only a file of the copy (a firm pass or fail, stage 4,
    2026-11-20). A link the tests make themselves is judged when it is made."""
    left: list[str] = []

    def ignore(d, names):
        out = [n for n in names if n in SKIP]
        if sys.platform == "win32":
            for n in names:
                if n not in SKIP and _link_not_here(os.path.join(d, n)):
                    out.append(n)
                    left.append(os.path.relpath(os.path.join(d, n), repo))
        return out
    shutil.copytree(repo, dst, symlinks=True, ignore=ignore)
    return left


def _a_drive(part: str) -> bool:
    return len(part) == 2 and part[1] == ":" and part[0].isascii() and part[0].isalpha()


def _remote_drive(letter: str) -> bool:
    """Is this drive letter a share of another computer (Windows' DRIVE_REMOTE)? Windows says it without asking
    the network. False anywhere else."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return ctypes.WinDLL("kernel32").GetDriveTypeW(ctypes.c_wchar_p(letter + ":\\")) == 4
    except (OSError, AttributeError):
        return False


def _not_here(place: str, remote=None) -> bool:
    """On Windows: is this place anything but a folder or file of this computer's own disks? A share by its name
    (`\\\\computer\\share`, with forward slashes, or `\\\\?\\UNC\\...`), a drive letter Windows gave a share
    (`remote`, a stand-in for Windows' own answer in a test), a pipe or a device. Read from the text, as the guard
    reads a name; nothing is opened."""
    n = place.replace("/", "\\")
    if n[:4] in ("\\\\?\\", "\\\\.\\", "\\??\\"):
        n = n[4:]
        if n[:7].lower() == "volume{":
            return False
        if not _a_drive(n[:2]):
            return True
    elif n[:2] == "\\\\":
        return True
    return _a_drive(n[:2]) and (remote or _remote_drive)(n[0])


def _link_not_here(path: str) -> bool:
    """Is this a link whose text names a place that is not this computer's own (`_not_here`)? Nothing it names is
    opened."""
    try:
        return os.path.islink(path) and _not_here(os.readlink(path))
    except (OSError, ValueError):
        return False


def _path_here(path: str, remote=None, sep: str = os.pathsep) -> tuple[str, list[str]]:
    """PATH for tests on Windows, and the folders left out of it: those of another computer. Windows looks for a
    program named by its bare name in every folder of PATH, and for a share it asks that computer over the
    network, below anything the guard can see."""
    kept, left = [], []
    for folder in path.split(sep):
        (left if folder and _not_here(folder, remote) else kept).append(folder)
    return sep.join(kept), left


MOST_LINKS = 20_000         # links of one repository that are made links again in the tests' copy
LINK_TEXT = 4096            # the longest path a link names
MOST_HOPS = 40              # links followed on the way to one place (Linux's own limit)
MOST_STEPS = 2_000_000      # steps of all the ways read for one copy on Windows, so that no project holds a run up
# a piece of a link's text that Windows reads otherwise than git keeps it: a stream of a file (`a:b`), a character
# Windows allows in no name, a control character, a dot or a space at its end (Windows' own names drop them)
WINDOWS_READS_OTHERWISE = re.compile(r'[<>:"|?*\x00-\x1f]|[. ]$')
SURROGATE = 0x20000000      # the bit of a Windows reparse tag that says the point stands for another place
NO_RIGHT = 1314             # Windows' ERROR_PRIVILEGE_NOT_HELD: this user may make no link


def _n_links(n: int, many: str, one: str) -> str:
    return f"sandbox: {n} {one if n == 1 else many}"


def _pieces(text: str, windows: bool) -> list[str] | None:
    """The pieces of a link's text as this system reads them, or None for a full path (one that does not begin at
    the link's own folder; on Windows also one that names a drive, or begins at the top of one)."""
    if windows:
        if text[:1] in ("/", "\\") or text[1:2] == ":":
            return None
        return re.split(r"[\\/]", text)
    return None if text.startswith("/") else text.split("/")


def _by_text(pieces) -> list[str] | None:
    """A path read by its text alone, each `..` taking away the piece before it: the pieces of the place from the
    project's top, or None when it goes up past the top."""
    at: list[str] = []
    for p in pieces:
        if p in ("", "."):
            continue
        if p != "..":
            at.append(p)
        elif at:
            at.pop()
        else:
            return None
    return at


def _fold(piece: str) -> str:
    """A name as Windows compares names: each letter as its capital, where it has one capital letter."""
    return "".join(u if len(u := c.upper()) == 1 else c for c in piece)


def _key(parts) -> str:
    return "\0".join(_fold(p) for p in parts)


class _Far(Exception):
    """The way of a link could not be followed to its end: a loop, more than MOST_HOPS links on it, or more steps
    for all the ways of one copy than MOST_STEPS."""


def _leads(folder: list[str], pieces: list[str], links: dict[str, list[str]], windows_way: bool,
           steps: list[int]) -> list[str] | None:
    """Where a link in `folder` (its pieces from the project's top) whose text is `pieces` leads, through the
    links that will be in the copy (`links`: the place of each, as `_key` writes it, to the pieces of its text):
    the pieces of the place from the project's top, or None when the way leaves the project; `_Far` when it cannot
    be followed to its end (`steps` counts down). Read two ways. Linux and macOS go into each link on the way
    before the `..` after it (`windows_way` false). Windows puts the folder of a link, the link's text and the rest
    of the way together and reads every `..` of that by its text before it goes on (`windows_way`; found on
    GitHub's Windows machine, 2026-11-20: there `vendor/..` is the project's own top whatever `vendor` names)."""
    first = _by_text([*folder, *pieces]) if windows_way else [*folder, *pieces]
    if first is None:
        return None
    todo, at, keys, hops = list(reversed(first)), [], [], 0        # `todo` is read from its end
    while todo:
        p = todo.pop()
        steps[0] -= 1 + len(at)
        if steps[0] < 0:
            raise _Far
        if p in ("", "."):
            continue
        if p == "..":
            if not at:
                return None
            at.pop()
            keys.pop()
            continue
        key = f"{keys[-1]}\0{_fold(p)}" if keys else _fold(p)
        text = links.get(key)
        if text is None:
            at.append(p)
            keys.append(key)
            continue
        hops += 1
        if hops > MOST_HOPS:
            raise _Far
        if windows_way:
            steps[0] -= len(at) + len(text) + len(todo)
            joined = _by_text([*at, *text, *reversed(todo)])
            if joined is None:
                return None
            todo, at, keys = list(reversed(joined)), [], []
        else:
            todo.extend(reversed(text))
    return at


def _both_ways(found: dict, top: str, steps: list[int]) -> tuple[dict[str, bool], dict[str, str]]:
    """Of the links about to be made on Windows (`found`: each place with its pieces from the project's top and the
    pieces of its text, in the order the repository lists them), those whose way stays inside the project read
    both ways `_leads` reads it, through the links that stay, each with whether the place it leads to is a folder
    (Windows asks which a link is when it is made); and each of the others with the reason, `out` or `far`. As on
    Linux and macOS, where the system's own answer is asked once the links are there, one link at a time: a link
    that leads out goes, and the ones after it are read without it, and all of them again until none goes. Where
    the steps run out, none of them is made."""
    keep = dict(found)
    links = {_key(parts): pieces for parts, pieces in keep.values()}
    left: dict[str, str] = {}
    ends: dict[str, list[str]] = {}
    again = True
    while again:
        again = False
        for place, (parts, pieces) in list(keep.items()):
            try:
                ways = [_leads(parts[:-1], pieces, links, way, steps) for way in (False, True)]
            except _Far:
                if steps[0] < 0:
                    left.update(dict.fromkeys(keep, "far"))
                    return {}, left
                ways = None
            if ways is not None and None not in ways:
                ends[place] = ways[1]
                continue
            del keep[place], links[_key(parts)]
            ends.pop(place, None)
            left[place] = "out" if ways else "far"
            again = True
    return {place: os.path.isdir(os.path.join(top, *end)) for place, end in ends.items()}, left


def _read_small(place: str, st, within) -> bytes | None:
    """The text of the small file at a link's place in Lantern's copy, when it can be a link's text: a plain file of
    one line, no longer than LINK_TEXT, in a folder inside the copy (`within`), read without going through a link
    (where the system has no word for that, Windows, the file is the one `st` looked at just before). None
    otherwise."""
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= LINK_TEXT \
            or not within(os.path.realpath(os.path.dirname(place))):
        return None
    try:
        fd = os.open(place, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_BINARY", 0))
        try:
            again = os.fstat(fd)
            raw = os.read(fd, LINK_TEXT + 1) if stat.S_ISREG(again.st_mode) and again.st_size == st.st_size else b""
        finally:
            os.close(fd)
    except OSError:
        return None
    if len(raw) != st.st_size or b"\0" in raw or b"\n" in raw or b"\r" in raw:
        return None
    return raw


def _write_small(place: str, raw: bytes, mode: int) -> None:
    """The small file a link was, written back at its place (where nothing is now)."""
    fd = os.open(place, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_BINARY", 0), mode)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)


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
    made, where it leads through the others, as the system itself answers, is still inside the copy (a link to
    the project's own top makes `top/..` the folder above). On Windows (a firm pass or fail, stage 4, 2026-11-20;
    until then no link was made there, and tests that pass at home failed in the copy) each is read first the two
    ways `_leads` reads a link, through the links about to be made, and made only where both stay inside: with
    Windows' own separator, and as a link to a folder where it leads to one (`_both_ways`). A link that leads out
    stays the small file it was, and so does one this computer does not let Lantern make; the log says how many.
    Nothing here reads what a link names, and Lantern's own copy of the repository is not changed. A folder of
    the person's own keeps its links as it always did (`_copy`), with the sandbox's walls around them."""
    windows = os.name == "nt"
    if os.name != "posix" and not windows:
        return
    from . import gitfacts, remote
    try:
        names = gitfacts.links(repo) if remote.is_clone(repo) else None
    except (OSError, RuntimeError):
        names = None
    if not names:
        return
    top = os.path.realpath(app)
    folded = os.path.normcase(top)

    def within(path: str) -> bool:
        path = os.path.normcase(path)
        return path == folded or path.startswith(folded + os.sep)

    def stays(place: str) -> bool:
        try:
            return within(os.path.realpath(place))
        except (OSError, ValueError):
            return False

    found: dict[str, tuple[list[str], list[str]]] = {}
    texts: dict[str, tuple[str, bytes, int]] = {}
    said = dict.fromkeys(("out", "far", "other", "refused", "odd"), 0)
    for name in names[:MOST_LINKS]:
        parts = name.split("/")
        if name.startswith("/") or any(part in ("", ".", "..") for part in parts) \
                or windows and any(":" in part or "\\" in part for part in parts):
            continue
        place = os.path.join(top, *parts)
        try:
            st = os.lstat(place)
        except OSError:
            continue                                # not in the copy (a folder the copy leaves out)
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) & SURROGATE:
            continue                                # a copy that kept its links: as it is
        raw = _read_small(place, st, within)
        if raw is None:
            said["odd"] += 1
            continue
        target = os.fsdecode(raw)
        pieces = _pieces(target, windows)
        if pieces is None or _by_text([*parts[:-1], *pieces]) is None:
            said["out"] += 1
            continue
        if windows and any(p not in (".", "..") and WINDOWS_READS_OTHERWISE.search(p) for p in pieces):
            said["other"] += 1
            continue
        found[place] = (parts, pieces)
        texts[place] = (target, raw, stat.S_IMODE(st.st_mode))
    folders: dict[str, bool] = {}
    if windows and found:
        folders, left = _both_ways(found, top, [MOST_STEPS])
        for why in left.values():
            said[why] += 1
        found = {place: found[place] for place in folders}
    made: dict[str, tuple[bytes, int]] = {}
    for place in found:
        target, raw, mode = texts[place]
        beside = f"{place}.lantern-link-{uuid.uuid4().hex[:12]}"
        try:
            os.symlink(target.replace("/", "\\") if windows else target, beside,
                       target_is_directory=folders.get(place, False))
        except OSError as e:
            said["refused" if e.errno == errno.EPERM or getattr(e, "winerror", None) == NO_RIGHT else "odd"] += 1
            continue
        try:
            if windows:                             # Windows puts no link to a folder in a file's place: it goes first
                os.unlink(place)
                try:
                    os.rename(beside, place)
                except OSError:
                    _write_small(place, raw, mode)
                    raise
            else:
                os.replace(beside, place)
        except OSError:
            try:
                os.unlink(beside)
            except OSError:
                pass
            said["odd"] += 1
            continue
        made[place] = (raw, mode)
    again = True
    while again:                                    # where each one leads, through the others, as the system says
        again = False
        for place in list(made):
            if stays(place):
                continue
            raw, mode = made.pop(place)
            os.unlink(place)                        # a link that leads out is never left: the copy fails instead
            _write_small(place, raw, mode)
            said["out"] += 1
            again = True
    if made:
        log(_n_links(len(made), "links of the repository are links again in the tests' copy",
                     "link of the repository is a link again in the tests' copy")
            + " (Lantern's own copy of a repository keeps each as a small file)")
    if said["out"]:
        log(_n_links(said["out"], "links of the repository lead out of the project and stay small files in the "
                                  "copy: tests that go through them do not find what they name",
                     "link of the repository leads out of the project and stays a small file in the copy: "
                     "tests that go through it do not find what it names"))
    if said["far"]:
        log(_n_links(said["far"], "links of the repository lead through too many other links to be followed, and "
                                  "stay small files in the copy: tests that go through them do not find what they name",
                     "link of the repository leads through too many other links to be followed, and stays a small "
                     "file in the copy: tests that go through it do not find what it names"))
    if said["other"]:
        log(_n_links(said["other"], "links of the repository name their place in words Windows reads otherwise "
                                    "than git, and stay small files in the copy: tests that go through them do not "
                                    "find what they name",
                     "link of the repository names its place in words Windows reads otherwise than git, and stays a "
                     "small file in the copy: tests that go through it do not find what it names"))
    if said["refused"]:
        why = " (on Windows that takes Developer Mode or the right to make links)" if windows else ""
        log(_n_links(said["refused"], "links of the repository stay small files in the tests' copy: this computer "
                                      f"did not let Lantern make a link{why}, so tests that go through them do not "
                                      "find what they name",
                     "link of the repository stays a small file in the tests' copy: this computer did not let "
                     f"Lantern make a link{why}, so tests that go through it do not find what it names"))
    if said["odd"]:
        log(_n_links(said["odd"], "files that the repository holds as links are not a link's text in Lantern's copy "
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
        far = _copy(repo, app)
        if far:
            log(_n_links(len(far), "links of the project name", "link of the project names")
                + " a place on another computer and " + ("is" if len(far) == 1 else "are")
                + " not in the tests' copy: " + ", ".join(far[:3]) + (f" and {len(far) - 3} more" if len(far) > 3 else ""))
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
        if getattr(p, "remote", False):       # a process another program runs for this one: it says
            return p.ended()
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
        if getattr(p, "remote", False):
            # The cloud service's steps, started by its switcher (`lantern_cloud.switcher`): the switcher stops the
            # step as above, where the step's user may be signalled, and says what it could not end.
            said, left = p.stop(self.ask)
            self.left.extend(left)
            self.said = said
            return said

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
            also=None, left: list | None = None, start=None) -> tuple[int | None, str, bool]:
    """Run, streaming each output line to `log`, and leave nothing behind: when the command ends, at the wall
    clock (`timeout`), when `cancel` (a threading.Event) is set and when `stop_all` is called, every process it
    started is ended too. Returns (result, output, stopped at the wall clock); the result is None when the command
    was stopped, at the wall clock or because it was asked, and `_jail.OVER_MEMORY` when the job that holds it said
    its programs together went over their memory (Windows: the run is then stopped, as Linux's launcher stops it and
    ends with that result; a job's `refused` says it was so, which a command that ends with that number does not).

    `job`: called before the process is made; what it returns holds the process (Windows: `winjob.Job`, which the
    process is put in before it runs). `ask`: seconds the command has to end what it started after SIGTERM, for a
    launcher that does so (`_jail`), before everything is killed. `also`: called once the command was stopped
    before its end (Docker: remove the container); it returns None, or the words for what it could not do.
    `left`: a list that is given what could not be ended, each in Lantern's own words (empty: all of it was).
    When `cancel` is set before the command is made, nothing is started: the result is that of a stopped command.
    `start`: called in place of making the process here, for a command another program runs for this one (the cloud
    service's switcher, which starts each step as the check's own user: `lantern_cloud.switcher.Remote`); `cmd`,
    `cwd`, `env` and `job` are then the caller's to hand to it, and are not used here."""
    if cancel is not None and cancel.is_set():
        return None, "", False
    held = job() if job is not None and start is None else None
    if sys.platform == "win32":
        from . import winjob
        kw: dict = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | (winjob.SUSPENDED if held is not None else 0)}
    else:
        kw = {"start_new_session": True}
    try:
        if start is not None:
            proc = start()
        else:
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
        watch = getattr(held, "over_memory", None)     # Windows: the job says when its programs went over
        while not run.ended():
            if run.asked.is_set() or (cancel is not None and cancel.is_set()):
                why = "asked"
                break
            if watch is not None and _watched(watch):
                why = "memory"
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
    rc = None if why else proc.returncode
    if why in ("", "memory") and getattr(held, "refused", False) is True:
        # also when Windows said it as the command ended by itself; a run stopped at the wall clock or because it
        # was asked was stopped for that, whatever the job says after
        from . import _jail
        rc = _jail.OVER_MEMORY
    return rc, "\n".join(lines), why == "clock"


def _watched(watch) -> bool:
    """What the job that holds a run says of its memory (`winjob.Job.over_memory`). Lantern cannot say the tests
    passed or failed where Windows does not answer it: the run is then stopped, and is not counted."""
    try:
        return watch()
    except OSError as e:
        raise Unavailable(f"Windows did not say whether the tests stayed within their memory ({e}), so what they "
                          "did is not counted") from e


def _windows_job(memory: int = MEMORY_MB):
    """Windows: the Job Object a project's tests run in (`memory` megabytes for the tests and everything they start,
    counted together, `winjob.Job`; every process in it ends when the job is stopped or closed, and nothing started
    inside can leave it). None on other systems, where `lantern._jail` does that work. `Unavailable` when Windows
    does not make it: the tests are then not run."""
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


# What a container starts with: a small program of Lantern's own, a shell's (every pinned image has one). It starts
# the tests' command and waits for it. When the command ended with an error, it reads the kernel's own count of
# the programs of this container that the kernel ended for the container's memory: `oom_kill` in the container's
# memory.events (cgroup v2) or memory.oom_control (v1), under the place /proc/self/cgroup names where the container
# sees the whole computer's folders, and at the top where it sees only its own. With a count above nought it says
# the launcher's line and ends with the launcher's number, which `_over_memory` reads; with a count of nought, or
# none it can read, it ends as the command did, and Docker is asked as before.
#
# Why (GitHub, 2026-11-14, on main's code): the tracer runs pytest in its own process, so tests over their
# container's memory were the container's first process. The kernel ended it, the container was gone at once, and
# Docker, which hears of such a kill in a message of its own, said "false" for the five seconds it was asked: the
# check read "failed" where "Incomplete" is true. This program is small, so the kernel ends the tests' program and
# not this one; it is still there afterwards, and what it reads is the kernel's count and not a message.
#
# Its own words stand before the command's: the folder of the kernel's counts, the file that names the container's
# own place, the limit in megabytes, the line's first word and the number to end with. Nothing is written into the
# program, and it holds no backslash. Tests that passed have passed, whatever the kernel ended on the way.
_FIRST = """counts=$1 own=$2 limit=$3 mark=$4 code=$5
shift 5
"$@"
rc=$?
[ "$rc" -ne 0 ] || exit 0
whole= memory=
if [ -r "$own" ]; then
  while IFS=: read -r number kinds place || [ -n "$number" ]; do
    case "$number:$kinds" in 0:) whole=$place ;; esac
    case ",$kinds," in *,memory,*) memory=$place ;; esac
  done < "$own"
fi
killed=
for file in "$counts$whole/memory.events" "$counts/memory.events" \
"$counts/memory$memory/memory.oom_control" "$counts/memory/memory.oom_control"; do
  if [ -f "$file" ] && [ -r "$file" ]; then
    while read -r word count || [ -n "$word" ]; do
      if [ "$word" = oom_kill ]; then killed=$count; fi
    done < "$file"
    break
  fi
done
case "$killed" in ''|*[!0-9]*) exit "$rc" ;; esac
[ "$killed" -gt 0 ] 2>/dev/null || exit "$rc"
echo >&2
echo "$mark memory $limit $limit" >&2
exit "$code"
"""


def _first_process(words, memory: int, counts: str = "/sys/fs/cgroup", own: str = "/proc/self/cgroup") -> list[str]:
    """The words a container is started with: Lantern's own first process (`_FIRST`), then the tests' command.
    `counts` and `own` are the kernel's own places in a container; a test gives a folder and a file of its own."""
    from . import _jail
    return ["sh", "-c", _FIRST, "lantern", counts, own, str(int(memory)), _jail.LIMIT_MARK, str(_jail.OVER_MEMORY),
            *words]


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
            kind = "network" if why.startswith("network") else "read" if why.startswith("read of ") \
                else "device" if why.startswith("device ") else "write"
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
        if sys.platform == "win32" and theirs:
            # The tests run in a job of their own (`_windows_job`), which nothing they start can leave: the guard
            # counts every program of that job as the run's own, so a test may call a server another program of
            # its own started (lantern.winjob). An app started by one of Lantern's own drivers is one program, and
            # there only that program's own sockets are its own.
            env["LANTERN_SANDBOX_JOB"] = "own"
        if sys.platform == "win32" and env.get("PATH"):
            env["PATH"], far = _path_here(env["PATH"])
            if far:
                log(f"sandbox: {len(far)} folder{'' if len(far) == 1 else 's'} of PATH "
                    f"{'is' if len(far) == 1 else 'are'} on another computer and "
                    f"{'is' if len(far) == 1 else 'are'} not on the tests' PATH: " + ", ".join(far[:3])
                    + (f" and {len(far) - 3} more" if len(far) > 3 else ""))
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
    jobs: list = []                   # Windows: the job, which says whether its programs went over their memory

    def job():
        jobs.append(_windows_job(memory))
        return jobs[-1]
    rc, output, timed_out = _stream(cmd, cwd, env, timeout, log, job=job, cancel=cancel,
                                    ask=_jail.ASK if _LINUX else 0.0, left=left)
    why = _unavailable(rc, output)
    if why:
        raise Unavailable(why)
    if os.name == "posix":
        left += _left_by_launcher(output)
        over = _over_memory(rc, output)
    else:                             # the job's own word, not a number the tests may end with themselves
        over = rc == _jail.OVER_MEMORY and any(getattr(j, "refused", False) is True for j in jobs)
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
    rc, output, timed_out = _stream(args + [img, *_first_process(cmd, memory)], root, programs.env(), timeout, log,
                                    cancel=cancel, also=remove, left=left)
    why = _unavailable(rc, output)
    if why:
        raise Unavailable(why)
    # The container's first process, which is Lantern's, read the kernel's count and said so: Docker is not asked.
    over = _over_memory(rc, output)
    if over:
        log("sandbox: the kernel ended a program of the tests for the container's memory (the kernel's own count, "
            "read in the container by its first process, which is Lantern's)")
    elif rc not in (None, 0, 125):
        over, asked = _docker_oom(docker, name, OOM_WAIT_KILLED if rc == 137 else OOM_WAIT)
        if rc == 137 and not over:
            log("sandbox: the tests' program was ended by a kill (137). The container's first process did not say "
                f"that the kernel ended a program for the container's memory, and neither did Docker, asked {asked} "
                "times, so this reads as a failure of the tests")
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
