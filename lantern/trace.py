"""Run a program under the trace hook and merge what actually executed into the graph."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .graph import CALLS, OBSERVED, Graph


def run_trace(repo: str | Path, command: list[str], timeout: int = 900) -> dict:
    """Run `command` (a Python invocation) with the hook installed. Returns raw pair data."""
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
    proc = subprocess.run(cmd, cwd=repo, env=env, timeout=timeout, capture_output=True, text=True)
    try:
        data = json.loads(Path(out).read_text() or "{}")
    except json.JSONDecodeError:
        data = {}
    finally:
        Path(out).unlink(missing_ok=True)
    data["returncode"] = proc.returncode
    data["stderr_tail"] = proc.stderr[-2000:]
    return data


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
        rel = os.path.relpath(os.path.realpath(filename), repo)
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
    }
    g.meta["trace"] = metrics
    return metrics
