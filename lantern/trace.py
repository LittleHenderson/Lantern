"""Run a program under the trace hook and merge what actually executed into the graph."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from . import results
from .graph import CALLS, OBSERVED, Graph


def counted(tr) -> bool:
    """`run.json`'s record of a test run (`trace`): is anything of that run in the results? Not when the sandbox
    could not be set up and the tests were not run (`ran` false). The results are then those of a check that ran
    no tests, and the Evidence Report, the readiness score and `lantern verify` treat them so. (Tests the person
    stopped part-way leave no record at all: `pipeline.Stopped`.)"""
    return isinstance(tr, dict) and bool(tr) and tr.get("ran") is not False


DEFAULT_TIMEOUT = 900      # seconds: what this way of running a project's tests has always given them


def run_trace(repo: str | Path, command: list[str], timeout: float | None = None) -> dict:
    """Run `command` (a Python invocation) with the hook installed, in the project's own folder and as the person
    (the command line's older way; `lantern.sandbox.run` is the sealed one). Returns raw pair data with
    `returncode`, `stderr_tail` and `time_limit` (the seconds it had: `timeout`, or `DEFAULT_TIMEOUT`).

    A run over its limit is ended and the data says so: `returncode` None and `timed_out` True. Until 2026-11-13
    the limit ended the whole check with a Python error (subprocess.TimeoutExpired) and no result, and only the
    first program was ended: what the tests had started went on running. The command now runs in a process group
    of its own, and at the limit, on Ctrl-C and when Lantern is told to end (SIGTERM, a closed terminal) the whole
    group is ended. A program that moved itself out of that group is not found again; the sealed way finds those
    too. The group is not the terminal's foreground one, so the command is given no keyboard to read from when
    Lantern was started at one (its output was never shown, so nothing could be asked of the person before)."""
    limit = DEFAULT_TIMEOUT if timeout is None else timeout
    repo = str(Path(repo).resolve())
    if command and Path(command[0]).name.startswith("python"):
        command = command[1:]
    if not command:
        raise ValueError("expected a Python command, e.g. `-- -m pytest -q` or `-- app.py`")
    fd, out = tempfile.mkstemp(suffix=".json", prefix="lantern-trace-")
    os.close(fd)
    env = dict(os.environ)
    pkg_root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = os.pathsep.join(p for p in [pkg_root, repo, env.get("PYTHONPATH", "")] if p)
    cmd = [sys.executable, "-m", "lantern.tracehook", out, repo, "--", *command]
    try:
        code, said, timed_out = _run_group(cmd, repo, env, limit)
        try:   # the traced program could put anything under this name: only a plain file is read (`results.plain`)
            data = well_formed(json.loads(results.plain(Path(out))[0] or "{}"))
        except (ValueError, RecursionError):
            data = {}
    finally:
        Path(out).unlink(missing_ok=True)
    data["returncode"] = code
    data["stderr_tail"] = said[-2000:]
    data["time_limit"] = limit
    if timed_out:
        data["timed_out"] = True
    return data


def _run_group(cmd: list[str], cwd: str, env: dict, limit: float) -> tuple[int | None, str, bool]:
    """Start `cmd` in a process group of its own and wait `limit` seconds for it. Returns (its result, or None when
    it was ended at the limit; what it wrote to stderr; whether the limit ended it). Left before the command has
    ended (the limit, Ctrl-C, a signal that ends Lantern, any error), the whole group is ended first; a command
    that ends by itself leaves what it left, as it always did. What the command writes goes to a file of
    Lantern's own and not through a pipe: a program the command started and that outlives it would hold a pipe
    open, and the wait for the pipe's end would be the wait for that program."""
    import signal
    import threading

    from .remote import _kill_tree
    kw: dict = {}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["process_group"] = 0
        try:   # in a group that is not the terminal's foreground one, reading the keyboard would stop the command
            if sys.stdin is not None and sys.stdin.isatty():
                kw["stdin"] = subprocess.DEVNULL
        except (ValueError, OSError):
            pass

    def leave(number, _frame):
        raise SystemExit(128 + number)

    # Told to end while the tests run, Lantern would end at once and leave their group running: for that time the
    # signals that end it are answered by leaving through the `finally` below. Only where nobody else answers them
    # (the default is in place), and only in the main thread, which is where Python lets a handler be set.
    held = {}
    if threading.current_thread() is threading.main_thread():
        for name in ("SIGTERM", "SIGHUP"):
            number = getattr(signal, name, None)
            try:
                if number is not None and signal.getsignal(number) is signal.SIG_DFL:
                    held[number] = signal.signal(number, leave)
            except (ValueError, OSError):
                pass
    proc = None
    try:
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=err, **kw)
            timed_out = False
            try:
                proc.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                timed_out = True
            if timed_out:
                _kill_tree(proc)
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    pass
            err.seek(0, os.SEEK_END)
            err.seek(max(0, err.tell() - 16000))
            said = err.read().decode("utf-8", errors="replace")
            code = None if timed_out else proc.returncode
        return code, said, timed_out
    except BaseException:
        if proc is not None and proc.returncode is None:   # not collected yet, so the group's number is still its own
            _kill_tree(proc)
        raise
    finally:
        for number, before in held.items():
            try:
                signal.signal(number, before)
            except (ValueError, OSError):
                pass


def _entry(e) -> bool:
    """One side of a recorded call as `tracehook` writes it: [file, first line, name, line]."""
    return (isinstance(e, list) and len(e) == 4 and isinstance(e[0], str) and isinstance(e[2], str)
            and (e[3] is None or type(e[3]) is int))


def well_formed(data) -> dict:
    """The record of a traced run with only the rows that have the shape `tracehook` writes. The record is written
    inside the program that was traced, so it can hold anything: until 2026-11-10 a row of another shape ended
    "Watch my tests run" with a Python error."""
    rows = data.get("pairs") if isinstance(data, dict) else None
    kept = [row for row in (rows if isinstance(rows, list) else [])
            if isinstance(row, dict) and _entry(row.get("caller")) and _entry(row.get("callee"))]
    return {"pairs": kept}


def _index(g: Graph):
    """Map (repo-relative file, local qualname) -> node id, plus main-block ranges."""
    by_file_qual: dict[tuple[str, str], str] = {}
    module_of_file: dict[str, str] = {}
    mains: dict[str, tuple[int, int, str]] = {}
    for n in g.nodes.values():
        if not n.file or not n.file.endswith(".py"):
            continue
        if n.kind == "module":
            module_of_file[n.file] = n.id
        elif n.name == "<main>":
            mains[n.file] = (n.start_line, n.end_line, n.id)
    for n in g.nodes.values():
        if n.file and n.file.endswith(".py") and n.kind != "module" and n.name != "<main>":
            mod = g.nodes[module_of_file[n.file]].qualname
            local = n.qualname[len(mod) + 1:]
            by_file_qual[(n.file, local)] = n.id
    return by_file_qual, module_of_file, mains


def _node_for(entry: list, repo: str, idx) -> str | None:
    by_file_qual, module_of_file, mains = idx
    filename, _first, qual, line = entry
    try:
        rel = Path(os.path.relpath(os.path.realpath(filename), repo)).as_posix()
    except ValueError:
        return None
    if qual == "<module>":
        m = mains.get(rel)
        if m and line is not None and m[0] <= line <= m[1]:
            return m[2]
        return module_of_file.get(rel)
    local = qual.replace(".<locals>", "")
    return by_file_qual.get((rel, local))


def merge_trace(g: Graph, data: dict) -> dict:
    """Upgrade matching edges to `observed`; add runtime-only edges. Returns coverage metrics."""
    repo = os.path.realpath(g.repo_root)
    idx = _index(g)
    observed: set[tuple[str, str]] = set()
    unmapped = 0
    for row in data.get("pairs", []):
        a = _node_for(row["caller"], repo, idx)
        b = _node_for(row["callee"], repo, idx)
        if not a or not b:
            unmapped += 1
            continue
        if g.nodes[b].kind in ("module", "class"):
            continue  # module import / class body execution, not a call
        observed.add((a, b))

    static = {(e.src, e.dst): e for e in g.call_edges() if not e.dst.startswith("ext:")}

    # Collapse decorator wrappers: a -> wrapper -> b, where the static graph has a -> b and the
    # wrapper is a function nested inside another function (the usual functools.wraps pattern).
    def is_wrapper(w: str) -> bool:
        n = g.nodes.get(w)
        return bool(n and n.parent and g.nodes.get(n.parent) and g.nodes[n.parent].kind == "callable")

    out_obs: dict[str, set[str]] = {}
    for a, b in observed:
        out_obs.setdefault(a, set()).add(b)
    collapsed: set[tuple[str, str]] = set()
    for a, ws in out_obs.items():
        for w in ws:
            if not is_wrapper(w):
                continue
            for b in out_obs.get(w, ()):
                if (a, b) in static:
                    collapsed.add((a, b))
                    observed_hops = {(a, w), (w, b)}
                    collapsed |= {("hop",) + h for h in observed_hops}
    hops = {(x[1], x[2]) for x in collapsed if x[0] == "hop"}
    observed = (observed - hops) | {x for x in collapsed if x[0] != "hop"}

    found, runtime_only = 0, 0
    for a, b in observed:
        e = static.get((a, b))
        if e is not None:
            found += 1
            e.confidence, e.via = OBSERVED, f"{e.via}+observed"
        else:
            runtime_only += 1
            g.add_edge(a, b, kind=CALLS, confidence=OBSERVED, via="runtime-only")

    # Precision proxy: of static edges whose caller actually ran, how many were observed?
    ran = {a for a, _ in observed}
    # constructing a class with no Python __init__ runs no traceable function: not checkable
    candidates = [k for k in static if k[0] in ran and g.nodes[k[1]].kind != "class"]
    confirmed = sum(1 for k in candidates if k in observed)
    metrics = {
        "observed_edges": len(observed),
        "static_found": found,
        "runtime_only": runtime_only,
        "recall": round(found / len(observed), 3) if observed else None,
        "callers_executed": len(ran),
        "static_edges_from_executed_callers": len(candidates),
        "confirmed_static_edges": confirmed,
        "unmapped_pairs": unmapped,
        "returncode": data.get("returncode"),
        "stderr_tail": (data.get("stderr_tail") or "")[-600:],
    }
    g.meta["trace"] = metrics
    return metrics
