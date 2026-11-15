"""Type-aware call resolution, opt-in (roadmap of 2026-11-14, stage 1): `lantern analyze --typecheck`, LANTERN_TYPECHECK=1.

Where Lantern's own reading leaves a call written in JavaScript/TypeScript or Python unresolved, a type checker that
is installed on this computer is asked where the call goes: the TypeScript compiler (through its API, by the small
program `typecheck_ts.js`) and pyright (its language server, asked for the definition of each callee). What it
answers becomes

* a link into the project (`via: "typecheck"`): `resolved` where the name written at the call names the function
  itself, `inferred` ("likely") where the function is reached through a value's type, as for Lantern's own links
  through a written type; in Python, where that type's method only declares or a class beneath its own writes it
  anew, each function that may run is `possible` and none is called likely (`_Beneath`);
* a built-in or a library call (the function is declared by the language or a library), never where Lantern's own
  reading withheld that label because the function may be the project's (`library-or-repo`);
* nothing: the call stays unresolved, with the reason it had.

A call is one call before and after: the record of the call-site inventory changes its outcome, and the older count
(`Graph.unresolved`) gives up the call it had counted (`Graph.unresolved_at`).

The checkers read the project and run nothing of it:

* they are found outside the analyzed folder (`find`: LANTERN_NODE, LANTERN_TYPESCRIPT, LANTERN_PYRIGHT, else
  PATH); a `node`, a compiler or a pyright that lies inside the project is passed by, and pyright's Python wrapper,
  which may fetch its program, is never started (`node` runs pyright's own JavaScript);
* TypeScript's language server is never used (it loads the plugins a project's tsconfig names); the program is made
  from the files Lantern read and options of Lantern's own, the project's tsconfig is not opened, and no file whose
  real place is outside the project is read (`typecheck_ts.js`);
* pyright is shown a copy that holds the project's Python files and nothing else, beside a settings file Lantern
  wrote: a `pyrightconfig.json` or `pyproject.toml` of the project (which can send it to folders outside the
  project, or to stubs of the project's own for the language's functions) is never in front of it. pyright starts
  whatever program named `python` it finds on its PATH, to ask it where libraries are: its PATH here is an empty
  folder, so no interpreter is started, the project's or anybody's;
* each runs in a folder of Lantern's own with a bare environment, a time limit and a memory limit, started by the
  sandbox's launcher where there is one (POSIX: writes only in that folder, no network), and everything it started
  is ended with it.

What a checker says is taken by shape (`_apply`): a file that is not one Lantern read, a line with no function of
the map, a name that is none is no answer. Nothing here creates, closes or re-ranks a finding.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import signal
import subprocess  # nosec B404 - starts the type checkers this computer has, by full path, never through a shell
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import calls
from .graph import CALLABLE, CALLS, CLASS, IMPLEMENTS, INFERRED, MODULE, POSSIBLE, RESOLVED
from .python_frontend import project_bytes, project_text

ENV = "LANTERN_TYPECHECK"
VIA = "typecheck"
JS_ENDINGS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
SCRIPT = Path(__file__).with_name("typecheck_ts.js")
SECONDS, MOST_SECONDS = 120, 1800       # a checker's time, and the most LANTERN_TYPECHECK_SECONDS may ask for
MOST_FILES = 20_000                     # files handed to a checker
MOST_SITES = 50_000                     # calls asked about, per language
MOST_FILE = 8 << 20                     # a Python file larger than this is not copied
MOST_COPIED = 256 << 20                 # ... and no more than this in all
MOST_ANSWER = 64 << 20
MOST_ROOTS = 40
MEMORY_MB = 4096
ONE_ANSWER = 30                         # seconds pyright has for one call
GRACE = 30                              # seconds past its own time limit before the compiler's program is ended
TS_OLDEST = 5                           # the options Lantern makes the program with are TypeScript 5.0's
NAME = re.compile(r"[\w$@][\w$@./-]{0,160}\Z")
VERSION = re.compile(r"[\w.+-]{1,40}\Z")
DEF = re.compile(r"\s*(?:async\s+)?(def|class)\s+([^\W\d]\w*)")
LAST_NAME = re.compile(r"([^\W\d]\w*)\Z")
IMPLEMENTED = ("FunctionDeclaration", "FunctionExpression", "ArrowFunction", "MethodDeclaration", "GetAccessor",
               "SetAccessor")
COUNTS = ("linked", "likely", "possible", "builtin", "library", "declared", "left")
MOST_REPLACING = 24                     # classes beneath a method's own that write it anew: more are not drawn
DECLARING = ("abstractmethod", "overload")      # decorators under which a method only declares
ON = ("1", "true", "yes", "on")


class Failed(RuntimeError):
    """A checker could not be asked. The words are Lantern's own, never text of a checker or of the project."""


def asked(flag: bool | None = None) -> bool:
    """Was the pass asked for: by the caller, else by LANTERN_TYPECHECK. Never by anything in the project."""
    return bool(flag) if flag is not None else os.environ.get(ENV, "").strip().lower() in ON


def seconds() -> int:
    try:
        n = int(os.environ.get("LANTERN_TYPECHECK_SECONDS", "").strip() or SECONDS)
    except ValueError:
        n = SECONDS
    return max(5, min(n, MOST_SECONDS))


# ---- which checkers this computer has ----

def _real(p) -> Path | None:
    try:
        return Path(p).resolve(strict=True)
    except (OSError, RuntimeError, ValueError, TypeError):
        return None


def _within(p: Path, folder: Path) -> bool:
    return p == folder or folder in p.parents


def _version(package: Path) -> str | None:
    try:
        v = json.loads((package / "package.json").read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError, AttributeError):
        return None
    return v if isinstance(v, str) and VERSION.match(v) else None


def _typescript_places(node: Path | None):
    yield os.environ.get("LANTERN_TYPESCRIPT")
    named = shutil.which("tsc")
    tsc = _real(named) if named else None      # no such command: nothing is looked for beside the current folder
    if tsc is not None:
        yield tsc.parent.parent                                  # <package>/bin/tsc
        yield Path(named).parent / "node_modules" / "typescript"     # npm's `tsc.cmd` on Windows, beside the packages
    if node is not None:
        yield node.parent.parent / "lib" / "node_modules" / "typescript"
        yield node.parent / "node_modules" / "typescript"       # Windows


def _newest(paths) -> list[Path]:
    def number(p: Path):
        return tuple(int(x) for x in re.findall(r"\d+", p.parts[-4])) if len(p.parts) > 4 else ()
    return sorted(paths, key=number, reverse=True)


def _pyright_places(node: Path | None):
    """pyright's own language-server program (JavaScript). The command `pyright-langserver` is that program when
    npm installed it; installed as a Python package it is a wrapper, and the program lies in the package's folder
    or in the folder the wrapper fetched it to."""
    yield os.environ.get("LANTERN_PYRIGHT")
    named = shutil.which("pyright-langserver")
    cmd = _real(named) if named else None
    if cmd is not None:
        yield Path(named).parent / "node_modules" / "pyright" / "langserver.index.js"    # npm's shim on Windows
        if cmd.name.endswith(".js"):
            yield cmd
        else:
            top = cmd.parent.parent
            yield from sorted(top.glob("lib/python*/site-packages/pyright/dist/langserver.index.js"))
            yield top / "Lib" / "site-packages" / "pyright" / "dist" / "langserver.index.js"
    if node is not None:
        yield node.parent.parent / "lib" / "node_modules" / "pyright" / "langserver.index.js"
        yield node.parent / "node_modules" / "pyright" / "langserver.index.js"
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "pyright-python"
    try:
        yield from _newest(cache.glob("*/node_modules/pyright/langserver.index.js"))
    except OSError:
        pass


def find(root: Path) -> dict:
    """The checkers of this computer that lie outside `root`, the analyzed folder: `node`, `typescript` (the
    package's folder), `pyright` (its language server's program), each a full path or None, their versions, and
    under `notes` why a language cannot be asked (None when it can)."""
    root = Path(root).resolve()
    passed: list[str] = []

    def outside(p, what: str) -> Path | None:
        at = _real(p) if p else None
        if at is not None and _within(at, root):
            if what not in passed:
                passed.append(what)
            return None
        return at

    node = outside(os.environ.get("LANTERN_NODE") or shutil.which("node"), "node")
    node = node if node is not None and node.is_file() else None
    ts = ts_version = py = py_version = old = None
    for place in _typescript_places(node):
        at = outside(place, "the TypeScript compiler")
        if at is not None and (at / "lib" / "typescript.js").is_file() and _version(at):
            first = re.match(r"\d+", _version(at))
            if first is None or int(first.group()) < TS_OLDEST:
                old = old or _version(at)
                continue
            ts, ts_version = at, _version(at)
            break
    for place in _pyright_places(node):
        at = outside(place, "pyright")
        if at is not None and at.is_file() and at.name.endswith(".js") and _version(at.parent):
            py, py_version = at, _version(at.parent)
            break

    def why(found, name: str, how: str) -> str | None:
        if node is not None and found is not None:
            return None
        if node is not None and name == "the TypeScript compiler" and old:
            return (f"the TypeScript compiler on this computer is version {old}, and Lantern asks version "
                    f"{TS_OLDEST}.0 or newer")
        missing = "node" if node is None else name
        words = f"{missing} was not found on this computer ({'PATH, or LANTERN_NODE' if node is None else how})"
        return words + ("; one inside the analyzed folder was passed by" if missing in passed else "")

    return {"node": str(node) if node else None,
            "typescript": str(ts) if ts else None, "typescript_version": ts_version,
            "pyright": str(py) if py else None, "pyright_version": py_version, "passed": passed,
            "notes": {"typescript": why(ts, "the TypeScript compiler", "a `tsc` on PATH, or LANTERN_TYPESCRIPT"),
                      "python": why(py, "pyright", "`pyright-langserver` on PATH, or LANTERN_PYRIGHT")}}


# ---- starting a checker ----

def _env(work: Path) -> dict:
    """A bare environment: nothing of the shell's (no NODE_OPTIONS, no proxy, no key), a home and a temp folder of
    the run's own, and a PATH that holds no program, so a checker that looks for one to start finds none."""
    env = {"HOME": str(work), "USERPROFILE": str(work), "TMPDIR": str(work), "TEMP": str(work), "TMP": str(work),
           "PATH": str(work / "empty"), "XDG_CACHE_HOME": str(work / "cache"), "XDG_CONFIG_HOME": str(work / "config"),
           "NO_COLOR": "1"}
    for k in ("SYSTEMROOT", "SystemRoot", "WINDIR"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def _launch(cmd: list[str], work: Path, limit: int) -> list[str]:
    """The command as the sandbox's launcher starts it (POSIX; `lantern/_jail.py`): writes only in `work`, no
    network, memory in use watched, and the launcher ends what the command started. No `must`: the checker only
    reads, so where the kernel has no such rule the launcher says so and the command runs with the rest."""
    if os.name != "posix":
        return cmd
    package = str(Path(__file__).resolve().parent.parent)
    policy = {"writable": [str(work)], "net": True, "own_net": True, "net_told": False, "parent": os.getpid(),
              "cpu": limit * 4}
    if sys.platform.startswith("linux"):    # where the launcher counts memory in use; elsewhere its limit is on the
        policy["memory"] = MEMORY_MB << 20  # address space, which node asks far more of than it uses
    return [sys.executable, "-I", "-c",
            f"import sys; sys.path.insert(0, {package!r}); from lantern._jail import main; main(sys.argv[1:])",
            json.dumps(policy), "--", *cmd]


def _start(cmd: list[str], work: Path, limit: int, err):
    (work / "empty").mkdir(exist_ok=True)
    return subprocess.Popen(_launch(cmd, work, limit), stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # nosec B603 - full paths, no shell
                            stderr=err, cwd=str(work), env=_env(work), start_new_session=os.name == "posix")


def _end(p) -> None:
    """End a checker and what it started. The launcher ends its command's whole tree when it is asked to stop."""
    if p.poll() is None:
        try:
            p.terminate()
            p.wait(5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if os.name == "posix":
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
    elif p.poll() is None:
        try:
            p.kill()
        except OSError:
            pass
    try:
        p.wait(5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    for pipe in (p.stdin, p.stdout):
        try:
            if pipe is not None:
                pipe.close()
        except OSError:
            pass


def _folder() -> Path:
    return Path(tempfile.mkdtemp(prefix="lantern-types-")).resolve()


# ---- TypeScript ----

def _js_files(g) -> list[str]:
    return sorted({n.file for n in g.nodes.values()
                   if n.kind == MODULE and n.id.startswith("js:") and n.file and n.file.endswith(JS_ENDINGS)})


def ask_typescript(tools: dict, root: Path, g, sites: list[dict], limit: int) -> dict:
    """Ask the TypeScript compiler where each call goes -> {"version", "answers": [answer | None], "stopped"}."""
    files = _js_files(g)
    if len(files) > MOST_FILES:
        raise Failed(f"the project has more than {MOST_FILES} JavaScript and TypeScript files")
    ask = {"root": str(root), "typescript": tools["typescript"], "files": files, "seconds": limit,
           "sites": [{"file": s["file"], "line": s["line"], "col": s["col"]} for s in sites],
           "imports": getattr(g, "js_imports", None) or {}}
    work = _folder()
    p = None
    try:
        with open(work / "said.txt", "wb") as err:
            p = _start([tools["node"], f"--max-old-space-size={MEMORY_MB - 512}", str(SCRIPT)], work, limit, err)
            try:
                out, _ = p.communicate(json.dumps(ask).encode("utf-8"), timeout=limit + GRACE)
            except subprocess.TimeoutExpired:
                raise Failed("the TypeScript compiler did not answer in time") from None
        if p.returncode != 0:
            raise Failed(f"the TypeScript compiler ended with an error (result {p.returncode})")
        if len(out) > MOST_ANSWER:
            raise Failed("the TypeScript compiler's answer is larger than Lantern reads")
        try:
            data = json.loads(out.decode("utf-8"))
        except (ValueError, RecursionError):
            raise Failed("the TypeScript compiler's answer could not be read") from None
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != len(sites):
            raise Failed("the TypeScript compiler's answer has another shape than Lantern asked for")
        return {"version": tools["typescript_version"], "answers": [_ts_answer(r) for r in results],
                "stopped": "time" if data.get("stopped") == "time" else None}
    except OSError:
        raise Failed("the TypeScript compiler could not be started") from None
    finally:
        if p is not None:
            _end(p)
        shutil.rmtree(work, ignore_errors=True)


def _ts_answer(r) -> dict | None:
    d = r.get("decl") if isinstance(r, dict) else None
    if not isinstance(d, dict):
        return None
    name, container = d.get("name"), d.get("container")
    name = name if isinstance(name, str) and NAME.match(name) else None
    full = ".".join(x for x in (container if isinstance(container, str) and NAME.match(container) else None, name) if x)
    if d.get("lib") == "builtin":
        return {"where": "builtin", "name": full} if full else None
    if d.get("lib") == "library":
        pkg = d.get("pkg")
        return {"where": "library", "name": f"{pkg}.{full}"} if full and isinstance(pkg, str) and NAME.match(pkg) else None
    what = "class" if d.get("what") == "class" else "function"
    if d.get("lib") or not d.get("body") or (what == "function" and d.get("kind") not in IMPLEMENTED):
        return {"where": "declared"}        # a written type, a signature, a declaration file: no function to link
    return {"where": "project", "file": d.get("file"), "lines": d.get("lines"), "name": name, "what": what,
            "direct": r.get("direct") is True}


# ---- pyright ----

def _py_files(g) -> list[str]:
    return sorted({n.file for n in g.nodes.values()
                   if n.kind == MODULE and n.id.startswith("py:") and n.file and n.file.endswith(".py")})


def _copy(root: Path, src: Path, files: list[str]) -> dict[str, list[bytes]]:
    """The project's Python files, copied for pyright: plain files whose real place is in the project (opened the
    one way Lantern opens a project's file, `project_bytes`), by the names Lantern read them under. Nothing else
    of the project is in the copy. -> {name: its lines}"""
    lines: dict[str, list[bytes]] = {}
    total = 0
    for rel in files:
        parts = rel.split("/")
        if not rel or rel.startswith("/") or any(x in ("", ".", "..") for x in parts):
            continue
        try:
            raw = project_bytes(root.joinpath(*parts), root, MOST_FILE + 1)
        except OSError:
            continue
        if len(raw) > MOST_FILE:
            continue
        total += len(raw)
        if total > MOST_COPIED:
            raise Failed("the project's Python files are larger than Lantern copies for pyright")
        to = src.joinpath(*parts)
        to.parent.mkdir(parents=True, exist_ok=True)
        to.write_bytes(raw)
        lines[rel] = raw.split(b"\n")
    return lines


def _import_roots(names) -> list[str]:
    """The folders imports can start from: the top, `src`, and the folder above each topmost package."""
    packages = {n.rsplit("/", 1)[0] for n in names if n.endswith("/__init__.py")}
    count: dict[str, int] = {}
    for p in packages:
        above = p.rsplit("/", 1)[0] if "/" in p else ""
        if above not in packages:
            count[above] = count.get(above, 0) + 1
    folders = {n.rsplit("/", 1)[0] if "/" in n else "" for n in names}
    if "src" in folders or any(f.startswith("src/") for f in folders):
        count.setdefault("src", 0)
    count.pop("", None)
    return sorted(count, key=lambda r: (-count[r], r))[:MOST_ROOTS]


class _Server:
    """pyright's language server, spoken to over its pipes."""
    NO_ANSWER = object()      # it is there and did not answer in the time it had
    GONE = object()           # it ended, or what it writes can no longer be read: nothing more is asked of it

    def __init__(self, tools: dict, work: Path, ws: Path, limit: int, err):
        self.p = _start([tools["node"], f"--max-old-space-size={MEMORY_MB - 512}", tools["pyright"], "--stdio"],
                        work, limit, err)
        self.n = 0
        self.waiting: dict = {}
        self.lock = threading.Lock()
        self.gone = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()
        # No process is named as the one that started the server (`processId`). The server looks every three
        # seconds whether that process is still there and ends when it cannot see it, and behind the launcher's
        # walls it is not let look at a process outside them: named Lantern, it ended three seconds in. Its pipes
        # end with Lantern, which it ends at too, and the launcher ends what Lantern leaves.
        got = self.ask("initialize", {
            "processId": None, "rootUri": ws.as_uri(),
            "workspaceFolders": [{"uri": ws.as_uri(), "name": "project"}],
            "capabilities": {"workspace": {"configuration": True, "workspaceFolders": True},
                             "textDocument": {"definition": {"linkSupport": False}}}}, min(limit, 120))
        if got is self.NO_ANSWER:
            raise Failed("pyright did not start in time")
        if got is self.GONE:
            raise Failed("pyright could not be started")
        self.tell("initialized", {})

    def _send(self, msg: dict) -> bool:
        body = json.dumps(msg).encode("utf-8")
        try:
            with self.lock:
                self.p.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
                self.p.stdin.flush()
        except (OSError, ValueError):      # its end of the pipe is closed: it is gone
            self.gone.set()
            return False
        return True

    def tell(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def ask(self, method: str, params: dict, timeout: float):
        """What the server answered, NO_ANSWER when it did not in `timeout` seconds, GONE when it is not there to
        answer: nobody waits out an answer's time for a program that has ended."""
        self.n += 1
        done, box = threading.Event(), {}
        self.waiting[self.n] = (done, box)
        if not self._send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) or \
                (self.gone.is_set() and not done.is_set()):
            self.waiting.pop(self.n, None)
            return self.GONE
        if not done.wait(timeout):
            self.waiting.pop(self.n, None)
            return self.NO_ANSWER
        return box["result"] if "result" in box else self.GONE

    def why_gone(self) -> str:
        try:
            self.p.wait(2)
        except subprocess.TimeoutExpired:
            return "pyright's answer could not be read"
        return "pyright ended before it had answered every call"

    def _read(self) -> None:
        try:
            self._read_on()
        finally:                 # nothing more will be read: whoever waits for an answer is told at once
            self.gone.set()
            for done, _box in list(self.waiting.values()):
                done.set()

    def _read_on(self) -> None:
        out = self.p.stdout
        try:
            while True:
                length = 0
                while True:
                    line = out.readline(4096)
                    if not line:
                        return
                    line = line.strip()
                    if not line:
                        break
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                if not 0 < length <= MOST_ANSWER:
                    return
                msg = json.loads(out.read(length).decode("utf-8"))
                if not isinstance(msg, dict):
                    continue
                if "id" in msg and "method" in msg:      # the server asks for settings: it gets none of the project's
                    items = (msg.get("params") or {}).get("items") if msg["method"] == "workspace/configuration" else None
                    answer = [{} for _ in items] if isinstance(items, list) else None
                    self._send({"jsonrpc": "2.0", "id": msg["id"], "result": answer})
                elif "id" in msg:
                    done, box = self.waiting.pop(msg["id"], (None, None))
                    if done is not None:
                        box["result"] = msg.get("result")
                        done.set()
        except (OSError, ValueError, RecursionError):
            return

    def close(self) -> None:
        if self.p.poll() is None and self.ask("shutdown", {}, 5) not in (self.NO_ANSWER, self.GONE):
            self.tell("exit", {})
        _end(self.p)


def _units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _stub_name(home: Path, at: Path, line: int, cache: dict) -> tuple[str, str] | None:
    """A place in the stubs pyright brings -> ("builtin" | "library", the function's dotted name), or None."""
    parts = at.relative_to(home).parts
    if "stdlib" in parts:
        mod = parts[parts.index("stdlib") + 1:]
    elif "stubs" in parts:
        mod = parts[parts.index("stubs") + 2:]
    else:
        return None
    if not mod or not mod[-1].endswith(".pyi"):
        return None
    module = ".".join([*mod[:-1], mod[-1][:-4]]).removesuffix(".__init__")
    if at not in cache:
        try:
            cache[at] = at.read_text(encoding="utf-8", errors="replace").split("\n") if at.stat().st_size <= MOST_FILE else []
        except OSError:
            cache[at] = []
    src = cache[at]
    m = DEF.match(src[line]) if 0 <= line < len(src) else None
    if not m:
        return None
    names, indent = [m.group(2)], len(src[line]) - len(src[line].lstrip())
    for i in range(line - 1, -1, -1):
        text = src[i]
        if not text.strip():
            continue
        depth = len(text) - len(text.lstrip())
        if depth < indent:
            indent = depth
            up = DEF.match(text)
            if up and up.group(1) == "class":
                names.insert(0, up.group(2))
            elif not text.lstrip().startswith(("if ", "else", "elif ", "try", "except", "@", "#")):
                break
        if indent == 0:
            break
    full = ".".join(names)
    if not NAME.match(f"{module}.{full}"):
        return None
    return ("builtin", full) if module == "builtins" else ("library", f"{module}.{full}")


def ask_python(tools: dict, root: Path, g, sites: list[dict], limit: int) -> dict:
    """Ask pyright where each call goes -> {"version", "answers": [answer | None], "stopped"}."""
    files = _py_files(g)
    if len(files) > MOST_FILES:
        raise Failed(f"the project has more than {MOST_FILES} Python files")
    home = Path(tools["pyright"]).parent
    work = _folder()
    ws = work / "ws"
    src = ws / "src"
    srv = None
    deadline = time.monotonic() + limit
    try:
        src.mkdir(parents=True)
        lines = _copy(root, src, files)
        (ws / "pyrightconfig.json").write_text(json.dumps({
            "include": ["src"], "extraPaths": ["src", *(f"src/{r}" for r in _import_roots(lines))],
            "typeCheckingMode": "off", "useLibraryCodeForTypes": False, "autoSearchPaths": False,
            "reportMissingImports": "none", "reportMissingModuleSource": "none"}), encoding="utf-8")
        answers: list = [None] * len(sites)
        stubs: dict = {}
        by_file: dict[str, list[int]] = {}
        for i, s in enumerate(sites):
            if s["file"] in lines:
                by_file.setdefault(s["file"], []).append(i)
        stopped, silent = None, 0
        with open(work / "said.txt", "wb") as err:
            srv = _Server(tools, work, ws, limit, err)
            for rel, wanted in by_file.items():
                if stopped:
                    break
                uri = src.joinpath(*rel.split("/")).as_uri()
                text = b"\n".join(lines[rel]).decode("utf-8", "replace")
                srv.tell("textDocument/didOpen", {"textDocument": {"uri": uri, "languageId": "python", "version": 1,
                                                                   "text": text}})
                for i in wanted:
                    left = deadline - time.monotonic()
                    if left <= 0 or silent >= 3:
                        stopped = "time"
                        break
                    s = sites[i]
                    row = lines[rel][s["line"] - 1] if 0 < s["line"] <= len(lines[rel]) else b""
                    before = row[:max(s["col"] - 1, 0)].decode("utf-8", "replace").rstrip()
                    name = LAST_NAME.search(before)
                    if not name:
                        continue
                    got = srv.ask("textDocument/definition", {
                        "textDocument": {"uri": uri}, "position": {"line": s["line"] - 1, "character": _units(before) - 1}},
                        min(ONE_ANSWER, left))
                    if got is srv.GONE:
                        raise Failed(srv.why_gone())
                    if got is srv.NO_ANSWER:
                        silent += 1
                        continue
                    silent = 0
                    dotted = before[:name.start()].rstrip().endswith(".")
                    answers[i] = _py_answer(got, src, home, lines, stubs, direct=not dotted)
                srv.tell("textDocument/didClose", {"textDocument": {"uri": uri}})
        return {"version": tools["pyright_version"], "answers": answers, "stopped": stopped}
    except OSError:
        raise Failed("pyright could not be started") from None
    finally:
        if srv is not None:
            srv.close()
        shutil.rmtree(work, ignore_errors=True)


def _py_answer(got, src: Path, home: Path, lines: dict, stubs: dict, direct: bool) -> dict | None:
    """What pyright gave for one callee -> an answer, or None where it names no one function."""
    found: dict = {}
    for loc in (got if isinstance(got, list) else [got] if isinstance(got, dict) else []):
        if not isinstance(loc, dict):
            return None
        uri, rng = loc.get("uri") or loc.get("targetUri"), loc.get("range") or loc.get("targetSelectionRange")
        try:
            line, char = rng["start"]["line"], rng["start"]["character"]
            url = urlparse(uri)
            at = Path(unquote(url.path)[1:] if os.name == "nt" else unquote(url.path)).resolve()
        except (TypeError, KeyError, ValueError, AttributeError, OSError, RuntimeError):
            return None
        if url.scheme != "file" or type(line) is not int or type(char) is not int:
            return None
        if _within(at, src):
            rel = at.relative_to(src).as_posix()
            rows = lines.get(rel) or []
            text = rows[line].decode("utf-8", "replace") if 0 <= line < len(rows) else ""
            m = DEF.match(text)
            if not m or _units(text[:m.start(2)]) != char:     # a variable, a parameter, an import: no function
                found[("declared", rel, line)] = {"where": "declared"}
                continue
            found[("project", rel, line)] = {"where": "project", "file": rel, "line": line + 1, "name": m.group(2),
                                             "what": "class" if m.group(1) == "class" else "function", "direct": direct}
        elif _within(at, home):
            named = _stub_name(home, at, line, stubs)
            if named is None:
                return None
            found[named] = {"where": named[0], "name": named[1]}
        else:
            return None
    return next(iter(found.values())) if len(found) == 1 else None


# ---- what the answers change ----

def _less(counts: dict, key: str) -> None:
    if counts.get(key, 0) > 1:
        counts[key] -= 1
    else:
        counts.pop(key, None)


def _settle(g, s: dict, *goes: tuple[str, str]) -> str:
    """The record of the call says where it goes now (`goes`: each target with its confidence), and the older
    count gives the call up: one call, counted once, before and after. -> the call's outcome."""
    outcome, to, _via, conf = calls.classify([(target, confidence, VIA) for target, confidence in goes])
    s.update({"outcome": outcome, "to": to, "via": VIA, "confidence": conf, "reason": None, "why": None})
    was = g.unresolved_at.pop(s["at"], None)
    if was:
        _less(g.unresolved, was[0])
        if was[1]:
            _less(g.unresolved_tests, was[0])
        if outcome == "builtin":
            g.builtin_calls += 1
    return outcome


def _words(st) -> bool:
    return isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str)


def _placeholder(st) -> bool:
    """`...`, or `raise NotImplementedError` (called or not): a line that stands where code is to be written."""
    if isinstance(st, ast.Expr):
        return isinstance(st.value, ast.Constant) and st.value.value is Ellipsis
    if isinstance(st, ast.Raise) and st.exc is not None:
        what = st.exc.func if isinstance(st.exc, ast.Call) else st.exc
        return isinstance(what, ast.Name) and what.id == "NotImplementedError"
    return False


class _Beneath:
    """A type names a class's method. The code that runs is the method of the class the value has, which no type
    says: a method that only declares (`DECLARING`, or a body that is a placeholder) is never that code, and one
    that a class beneath its own writes anew need not be. Measured on five public Python projects (2026-11-15):
    of 60 links through a value's type read by hand, 12 led to a method that only declares and 1 to one that the
    project's default subclass replaces. So such a method is not linked as the likely one: the methods that
    replace it are each `possible`, as for Lantern's own `self.method()` (`via: "override"`), and with it where it
    has code of its own. Python only: the map keeps no class's base for JavaScript."""

    def __init__(self, g, root: Path):
        self.g, self.root, self.files, self.subs = g, root, {}, {}
        for e in g.edges:
            if e.kind == IMPLEMENTS:
                self.subs.setdefault(e.dst, []).append(e.src)

    def method(self, target: str) -> bool:
        cls = self.g.nodes.get(target.rpartition(".")[0])
        return cls is not None and cls.kind == CLASS

    def _functions(self, rel: str) -> dict:
        """{a line a function begins on (its `def`, each of its decorators): the function} for one file, read by
        Python's own parser (nothing of the file is run); empty where the file cannot be read that way."""
        if rel not in self.files:
            found: dict = {}
            try:
                tree = ast.parse(project_text(self.root / rel, self.root, MOST_FILE))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        found[node.lineno] = node
                        for d in node.decorator_list:
                            found.setdefault(d.lineno, node)
            except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
                found = {}
            self.files[rel] = found
        return self.files[rel]

    def only_declares(self, target: str) -> bool:
        """Also true where the method's lines cannot be read: what a method does is then not known, and no link
        is made on a guess."""
        n = self.g.nodes[target]
        fn = self._functions(n.file).get(n.start_line) if n.file else None
        if fn is None or fn.name != target.rpartition(".")[2]:
            return True
        for d in fn.decorator_list:
            if (d.attr if isinstance(d, ast.Attribute) else getattr(d, "id", None)) in DECLARING:
                return True
        body = fn.body[1:] if _words(fn.body[0]) else fn.body
        return bool(body) and all(_placeholder(st) for st in body)

    def may_run(self, target: str) -> list[str]:
        """The functions a call may run that a type says is `target`: the method itself where it has code, then
        the ones that replace it in the classes beneath, by name. Empty where it only declares and nothing of the
        project replaces it, and where more replace it than are drawn (`MOST_REPLACING`)."""
        cls, _, name = target.rpartition(".")
        seen, todo = set(), [cls]
        while todo:
            for sub in self.subs.get(todo.pop(), ()):
                if sub not in seen:
                    seen.add(sub)
                    todo.append(sub)
        over = sorted(m for m in (f"{c}.{name}" for c in seen) if m in self.g.nodes and self.g.nodes[m].kind == CALLABLE)
        if len(over) > MOST_REPLACING:
            return []
        return [m for m in [target, *over] if not self.only_declares(m)]


def _places(g, prefix: str) -> dict:
    index: dict = {}
    for n in g.nodes.values():
        if n.id.startswith(prefix) and n.file and n.kind in (CALLABLE, CLASS) and n.start_line:
            index.setdefault((n.file, n.start_line), []).append(n)
            index.setdefault((n.file, "name", re.split(r"[.:]", n.id)[-1]), []).append(n)
    return index


def _js_node(index: dict, a: dict) -> str | None:
    file, lines, name = a.get("file"), a.get("lines"), a.get("name")
    if not isinstance(file, str) or not isinstance(lines, list):
        return None
    kind = CLASS if a.get("what") == "class" else CALLABLE
    for line in lines[:6]:
        hits = [n for n in index.get((file, line), ()) if n.kind == kind] if type(line) is int else []
        if name is not None:
            hits = [n for n in hits if re.split(r"[.:]", n.id)[-1] == name]
        if len(hits) == 1:
            return hits[0].id
    return None


def _py_node(g, index: dict, a: dict) -> str | None:
    file, line, name = a.get("file"), a.get("line"), a.get("name")
    if not isinstance(file, str) or type(line) is not int or not isinstance(name, str):
        return None
    kind = CLASS if a.get("what") == "class" else CALLABLE
    hits = [n for n in index.get((file, "name", name), ())
            if n.kind == kind and n.start_line <= line <= (n.end_line or n.start_line)]
    if not hits:
        return None
    node = max(hits, key=lambda n: n.start_line)
    if kind == CALLABLE:
        return node.id
    made = g.nodes.get(node.id + ".__init__")       # a class that is called: its own `__init__`, where it writes one
    return made.id if made is not None and made.kind == CALLABLE else None


def _apply(g, root: Path, lang: str, sites: list[dict], answers: list) -> dict:
    index = _places(g, "js:" if lang == "typescript" else "py:")
    beneath = _Beneath(g, root) if lang == "python" else None
    count = dict.fromkeys(COUNTS, 0)
    for s, a in zip(sites, answers):
        count[_use(g, lang, index, s, a, beneath)] += 1
    return count


def _use(g, lang: str, index: dict, s: dict, a, beneath=None) -> str:
    if not isinstance(a, dict) or s["outcome"] != "unresolved" or s["caller"] not in g.nodes:
        return "left"
    where, name = a.get("where"), a.get("name")
    if where == "declared":
        return "declared"
    if where == "project":
        target = _js_node(index, a) if lang == "typescript" else _py_node(g, index, a)
        if target is None:
            return "declared"
        conf = RESOLVED if a.get("direct") is True else INFERRED
        goes = [(target, conf)]
        if conf == INFERRED and beneath is not None and beneath.method(target):     # a type's word for a method
            goes = [(t, INFERRED if t == target else POSSIBLE) for t in beneath.may_run(target)]
            if not goes:
                return "declared"
        for t, c in goes:
            e = g.add_edge(s["caller"], t, kind=CALLS, confidence=c, line=s["line"], via=VIA)
            if e.via in calls.NAME_ONLY_VIA:      # the same link was a guess by method name: now a checker says so too
                e.via = VIA
        outcome = _settle(g, s, *goes)
        return "linked" if outcome == "resolved" else "possible" if outcome == "possible" else "likely"
    if where not in ("builtin", "library") or not isinstance(name, str) or not NAME.match(name) or \
            s["reason"] == "library-or-repo":      # Lantern's own reading withheld a library label here: it stands
        return "left"
    if where == "builtin":
        _settle(g, s, (("builtin:" if lang == "typescript" else "ext:builtins.") + name, INFERRED))
        return "builtin"
    g.external(name)
    if not (lang == "typescript" and name.startswith("react")):     # as the JS/TS reader: React's own hooks are not drawn
        g.add_edge(s["caller"], f"ext:{name}", kind=CALLS, confidence=INFERRED, line=s["line"], via=VIA)
    _settle(g, s, (f"ext:{name}", INFERRED))
    return "library"


def _part(g, root: Path, tools: dict, lang: str, sites: list[dict], ask) -> dict:
    if not sites:
        return {"ran": False, "why": "no call of this language is unresolved", "asked": 0}
    if tools["notes"][lang]:
        return {"ran": False, "why": tools["notes"][lang], "asked": 0, "unresolved": len(sites)}
    began = time.perf_counter()
    try:
        got = ask(tools, root, g, sites[:MOST_SITES], seconds())
        count = _apply(g, root, lang, sites[:MOST_SITES], got["answers"])
    except Failed as e:
        return {"ran": False, "why": str(e), "asked": 0, "unresolved": len(sites)}
    return {"ran": True, "version": got["version"], "asked": min(len(sites), MOST_SITES), **count,
            "not_asked": max(len(sites) - MOST_SITES, 0), "stopped": got.get("stopped"),
            "seconds": round(time.perf_counter() - began, 2)}


def run(g, root: Path) -> dict:
    """Ask the checkers about every call Lantern left unresolved and write what they said onto the map and the
    call-site inventory. Called by `engine.build_graph` before the inventory is closed, only when asked for."""
    root = Path(root).resolve()
    tools = find(root)
    first: dict = {}
    for s in g.sites:
        first.setdefault((s["group"], s["at"]), s)
    open_ = [s for (group, _at), s in first.items()
             if group == "written" and s["outcome"] == "unresolved" and s["caller"] in g.nodes]
    out = {"asked": True,
           "typescript": _part(g, root, tools, "typescript",
                               [s for s in open_ if s["file"].endswith(JS_ENDINGS)], ask_typescript),
           "python": _part(g, root, tools, "python", [s for s in open_ if s["file"].endswith(".py")], ask_python)}
    if tools["passed"]:
        out["passed_by"] = tools["passed"]
    g.meta["typecheck"] = out
    return out


def versions(meta) -> dict:
    """The checkers that ran, with their versions: what a result made with them depends on."""
    return {tool: version for _lang, tool, _words, part, version in _parts(meta) if part.get("ran") is True and version}


def _whole(x) -> int:
    return x if type(x) is int and x > 0 else 0


def _parts(meta):
    """The two checkers' parts of a record, taken by shape: the record may be one read back from a file."""
    meta = meta if isinstance(meta, dict) and meta.get("asked") is True else {}
    for lang, tool, words in (("typescript", "typescript", "the TypeScript compiler"), ("python", "pyright", "pyright")):
        part = meta.get(lang)
        if isinstance(part, dict):
            v = part.get("version")
            yield lang, tool, words, part, (v if isinstance(v, str) and VERSION.match(v) else None)


def rows(meta) -> list[dict]:
    """The checkers a result was made with, for the Evidence Report's list of tools."""
    out = []
    for _lang, tool, _words, part, version in _parts(meta):
        if part.get("ran") is True:
            out.append({"tool": tool, "version": version, "role": "type checker, asked for with --typecheck"})
        elif _whole(part.get("unresolved")):
            out.append({"tool": tool, "version": None, "role": "type checker, asked for with --typecheck",
                        "status": "not asked"})
    return out


def limits(meta) -> list[str]:
    """What a reader of a result made with the pass has to know: lines for the Evidence Report's Limits."""
    out = []
    for lang, _tool, words, part, version in _parts(meta):
        kind = "JavaScript and TypeScript" if lang == "typescript" else "Python"
        if part.get("ran") is True:
            linked, likely, several = (_whole(part.get(k)) for k in ("linked", "likely", "possible"))
            line = (f"Links from a type checker. {words[0].upper() + words[1:]} {version or 'of a version it did not tell'} "
                    f"on this computer was asked where {_whole(part.get('asked'))} {kind} calls go that Lantern's own "
                    f"reading left unresolved (--typecheck): {linked + likely + several} were linked into the project on its word "
                    f"({linked} confirmed, {likely} likely, {several} to each function that may run where the type's "
                    "own method only declares or a class beneath it writes it anew) and "
                    f"{_whole(part.get('builtin')) + _whole(part.get('library'))} "
                    "placed in the language or a library. Such a link is as right as the types written in the code, and "
                    "`lantern verify` repeats it only with --typecheck and the same checker.")
            if part.get("stopped"):
                line += " The checker stopped at its time limit before every call was asked."
            if _whole(part.get("not_asked")):
                line += f" {_whole(part.get('not_asked'))} calls over the most Lantern asks about were not asked."
            out.append(line)
        elif _whole(part.get("unresolved")):
            why = part.get("why")
            out.append(f"Links from a type checker. The type-aware pass was asked for (--typecheck) and {words} was not "
                       f"asked about {_whole(part.get('unresolved'))} unresolved {kind} calls"
                       + (f": {why[:300]}" if isinstance(why, str) and why else "") + ".")
    passed = meta.get("passed_by") if isinstance(meta, dict) and meta.get("asked") is True else None
    names = [x for x in passed if x in ("node", "the TypeScript compiler", "pyright")] if isinstance(passed, list) else []
    if names:
        out.append(f"A copy of {', '.join(names)} inside the analyzed folder was passed by: Lantern does not start a "
                   "program that comes with the project.")
    return out


def line_words(meta) -> str | None:
    """One line for the console: what each checker was asked and what came of it."""
    if not isinstance(meta, dict) or meta.get("asked") is not True:
        return None
    said = []
    for lang, tool in (("typescript", "the TypeScript compiler"), ("python", "pyright")):
        part = meta.get(lang) if isinstance(meta.get(lang), dict) else {}
        if part.get("ran"):
            said.append(f"{tool} {part.get('version')}: {part.get('asked')} unresolved calls asked, "
                        f"{part.get('linked', 0) + part.get('likely', 0) + part.get('possible', 0)} linked into the "
                        f"project ({part.get('linked', 0)} confirmed, {part.get('likely', 0)} likely, "
                        f"{part.get('possible', 0)} to one of several that may run), "
                        f"{part.get('builtin', 0)} built-in, {part.get('library', 0)} library, "
                        f"{part.get('declared', 0) + part.get('left', 0)} still unresolved"
                        + (", stopped at its time limit" if part.get("stopped") else ""))
        elif part.get("unresolved"):
            said.append(f"{tool} not asked: {part.get('why')}")
    return "; ".join(said) or "no unresolved call to ask a type checker about"
