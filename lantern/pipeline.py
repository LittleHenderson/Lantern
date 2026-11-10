"""The analysis pipeline as plain functions, shared by the command line and the local app (`lantern serve`).

Each step reports progress through `log(line)`; results land in the output folder (default PATH/.lantern).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable

from .graph import Graph

Log = Callable[[str], None]
RANKS = ["critical", "high", "medium", "low"]


def load(out: Path, name: str) -> dict | None:
    p = out / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def out_dir(repo: Path, out: str | Path | None = None) -> Path:
    d = Path(out) if out else repo / ".lantern"
    d.mkdir(parents=True, exist_ok=True)
    return d


def analyze(repo: Path, out: Path, privacy: str = "full", trace_cmd: list[str] | None = None,
            no_scan: bool = False, log: Log = print, offline: bool | None = None, sandbox: bool = False,
            test_cwd: str = "") -> dict:
    """Graph -> (trace) -> scan -> readiness -> report -> evidence. Returns a short summary.
    `sandbox`: run `trace_cmd` (a test command) in `lantern.sandbox` instead of directly (the app always does)."""
    from . import remote
    if remote.is_clone(repo):   # a clone whose checkout could not be completed would report on part of a repository
        remote.check_complete(repo)
    from .engine import build_graph
    from .readiness import assess
    from .report import write_report
    from .security import scan
    from .trace import merge_trace, run_trace

    timings = {}
    t = time.perf_counter()
    g = build_graph(repo)
    timings["graph"] = round(time.perf_counter() - t, 2)
    s = g.stats()
    log(f"graph   {g.meta['files']} files, {s['nodes'].get('callable', 0)} functions, "
        f"{s['internal_call_edges']} internal calls, {s['entry_points']} entry points ({timings['graph']}s)")
    from .calls import line_words
    if line_words(g.meta.get("calls")):
        log(f"calls   {line_words(g.meta.get('calls'))}")
    from .depaudit import offline as offline_env
    offline = offline_env() if offline is None else offline
    run_meta: dict = {"timings": timings, "privacy": privacy, "offline": offline}
    left = remote.skipped(repo) if remote.is_clone(repo) else None
    if left:   # the clone left out files Lantern does not read, to stay under the size cap (remote._checkout)
        run_meta["skipped"] = {k: left.get(k) for k in ("files", "mb", "kept_mb", "cap_mb", "examples")}
    if os.environ.get("LANTERN_CLOUD_RUN") == "1":   # set only by Lantern's cloud worker (cloud/lantern_cloud/worker.py)
        run_meta["place"] = "cloud"
    if trace_cmd:
        t = time.perf_counter()
        extra: dict = {}
        if sandbox:
            from . import sandbox as sbx
            data = sbx.run(repo, trace_cmd, log=log, cwd_rel=test_cwd)
            extra = {k: data.get(k) for k in ("backend", "language", "traced", "timed_out", "blocked")}
            m = merge_trace(g, data) if data.get("traced") else {"returncode": data.get("returncode"), "observed_edges": 0,
                                                                  "recall": None, "runtime_only": 0}
            m["stderr_tail"] = data.get("stderr_tail")
        else:
            m = merge_trace(g, run_trace(repo, trace_cmd))
        timings["trace"] = round(time.perf_counter() - t, 2)
        run_meta["trace"] = {"command": trace_cmd, "returncode": m["returncode"], "observed_edges": m["observed_edges"],
                             "recall": m["recall"], "stderr_tail": (m.get("stderr_tail") or "")[-600:], **extra}
        log(f"trace   {m['observed_edges']} calls seen running, recall {m['recall']}, "
            f"{m['runtime_only']} runtime-only (exit {m['returncode']})")
    sec = None
    if not no_scan:
        t = time.perf_counter()
        sec = scan(g, offline)
        from . import case
        from .evidence import git_info
        earlier = load(out, "security.json")    # the previous run of this folder, before it is replaced
        base = load(out, "baseline.json")
        ids = None
        if earlier and earlier.get("id_version") == sec.get("id_version"):
            ids = {f.get("id") for f in earlier.get("findings", [])}
        if base and base.get("id_version") == sec.get("id_version"):
            ids = (ids or set()) | set(base.get("findings") or {})
        case.stamp(sec, git_info(repo), ids)
        timings["scan"] = round(time.perf_counter() - t, 2)
        c = sec["counts"]
        log(f"scan    {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low "
            f"({timings['scan']}s)")
        # A scanner that did not finish, or did not cover everything, is said on the console and kept in run.json,
        # the readiness file, the Evidence Report and the badge (scanresult.py), never folded into "no findings".
        run_meta["incomplete"] = [{k: t.get(k) for k in ("tool", "state", "status", "why", "role")}
                                  for t in sec.get("incomplete") or []]
        for t in run_meta["incomplete"]:
            log(f"incomplete {t['tool']}: {t['status']}")
        (out / "security.json").write_text(json.dumps(sec, indent=1), encoding="utf-8")
    g.save(out / "graph.json")
    from . import calls
    calls.write(out / "calls.json", g)
    rd = assess(g, sec, run_meta)
    (out / "readiness.json").write_text(json.dumps(rd, indent=1), encoding="utf-8")
    log(f"ready   {rd['score']}/100 (grade {rd['grade']}), {rd['shape']}")
    run_meta["finished_at"] = time.strftime("%Y-%m-%d %H:%M")
    (out / "run.json").write_text(json.dumps(run_meta, indent=1), encoding="utf-8")
    path = write_report(out, g, sec, load(out, "explanations.json"), privacy, timings, rd)
    log(f"report  {path}")
    log(f"proof   {evidence(out, g, sec, rd, run_meta, privacy)}")
    return {"score": rd["score"], "grade": rd["grade"], "shape": rd["shape"],
            "counts": (sec or {}).get("counts"), "incomplete": run_meta.get("incomplete") or [], "report": str(path)}


def evidence(out: Path, g: Graph, sec, rd, run_meta: dict, privacy: str) -> Path:
    from . import evidence as ev
    base = load(out, "baseline.json")
    from .security import ID_VERSION
    if sec is not None and (base is None or base.get("id_version") != ID_VERSION):   # first run, or ids changed
        base = ev.baseline_from(sec, ev.git_info(Path(g.repo_root)).get("commit"), rd)
        (out / "baseline.json").write_text(json.dumps(base, indent=1), encoding="utf-8")
    rec = ev.build(g, sec, rd, load(out, "explanations.json"), run_meta, base, privacy)
    return ev.write(out, rec)["html"]


def rebuild_outputs(out: Path, g: Graph | None = None) -> Path:
    """Re-render report.html and evidence.html from saved results (after explanations change)."""
    from .report import write_report
    g = g or Graph.load(out / "graph.json")
    run_meta = load(out, "run.json") or {}
    sec, rd = load(out, "security.json"), load(out, "readiness.json")
    path = write_report(out, g, sec, load(out, "explanations.json"), run_meta.get("privacy", "full"),
                        run_meta.get("timings"), rd)
    evidence(out, g, sec, rd, run_meta, run_meta.get("privacy", "full"))
    return path


def plan_explain(out: Path, depth: int = 3, limit: int | None = 40, only: list[str] | None = None) -> dict:
    from .explain import estimate, select_nodes
    g = Graph.load(out / "graph.json")
    sec = load(out, "security.json") or {"findings": []}
    nids = select_nodes(g, depth=depth, limit=limit, only=only)
    return {**estimate(g, nids, sec["findings"]), "nodes": nids}


def explain(out: Path, provider, nids: list[str], metaphor: str | None = None,
            progress: Callable | None = None, fresh: bool = False) -> dict:
    """Explain `nids` with `provider`, merge into explanations.json, and re-render the report."""
    from .explain import run
    g = Graph.load(out / "graph.json")
    sec = load(out, "security.json") or {"findings": []}
    prev = load(out, "explanations.json")
    if metaphor is None and prev and (prev.get("metaphor") or {}).get("world"):
        metaphor = prev["metaphor"]["world"]   # keep one metaphor world across runs
    res = run(g, provider, sec["findings"], out / "cache", nids, metaphor=metaphor, progress=progress, fresh=fresh)
    if prev and prev.get("explanations"):
        prev["explanations"].update(res["explanations"])
        res["explanations"] = prev["explanations"]
        if prev.get("metaphor", {}).get("world") == res["metaphor"]["world"] and prev["metaphor"].get("roles"):
            res["metaphor"] = prev["metaphor"]
    (out / "explanations.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    rebuild_outputs(out, g)
    return res
