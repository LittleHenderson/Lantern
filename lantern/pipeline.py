"""The analysis pipeline as plain functions, shared by the command line and the local app (`lantern serve`).

Each step reports progress through `log(line)`; results land in the output folder (default PATH/.lantern).
"""

from __future__ import annotations

import json
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
            no_scan: bool = False, log: Log = print) -> dict:
    """Graph -> (trace) -> scan -> readiness -> report -> evidence. Returns a short summary."""
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
    run_meta: dict = {"timings": timings, "privacy": privacy}
    if trace_cmd:
        t = time.perf_counter()
        m = merge_trace(g, run_trace(repo, trace_cmd))
        timings["trace"] = round(time.perf_counter() - t, 2)
        run_meta["trace"] = {"command": trace_cmd, "returncode": m["returncode"]}
        log(f"trace   {m['observed_edges']} calls seen running, recall {m['recall']}, "
            f"{m['runtime_only']} runtime-only (exit {m['returncode']})")
    sec = None
    if not no_scan:
        t = time.perf_counter()
        sec = scan(g)
        timings["scan"] = round(time.perf_counter() - t, 2)
        c = sec["counts"]
        log(f"scan    {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low "
            f"({timings['scan']}s)")
        (out / "security.json").write_text(json.dumps(sec, indent=1), encoding="utf-8")
    g.save(out / "graph.json")
    rd = assess(g, sec, run_meta)
    (out / "readiness.json").write_text(json.dumps(rd, indent=1), encoding="utf-8")
    log(f"ready   {rd['score']}/100 (grade {rd['grade']}), {rd['shape']}")
    run_meta["finished_at"] = time.strftime("%Y-%m-%d %H:%M")
    (out / "run.json").write_text(json.dumps(run_meta, indent=1), encoding="utf-8")
    path = write_report(out, g, sec, load(out, "explanations.json"), privacy, timings, rd)
    log(f"report  {path}")
    log(f"proof   {evidence(out, g, sec, rd, run_meta, privacy)}")
    return {"score": rd["score"], "grade": rd["grade"], "shape": rd["shape"],
            "counts": (sec or {}).get("counts"), "report": str(path)}


def evidence(out: Path, g: Graph, sec, rd, run_meta: dict, privacy: str) -> Path:
    from . import evidence as ev
    base = load(out, "baseline.json")
    if base is None and sec is not None:
        base = ev.baseline_from(sec, ev.git_info(Path(g.repo_root)).get("commit"))
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
            progress: Callable | None = None) -> dict:
    """Explain `nids` with `provider`, merge into explanations.json, and re-render the report."""
    from .explain import run
    g = Graph.load(out / "graph.json")
    sec = load(out, "security.json") or {"findings": []}
    prev = load(out, "explanations.json")
    if metaphor is None and prev and (prev.get("metaphor") or {}).get("world"):
        metaphor = prev["metaphor"]["world"]   # keep one metaphor world across runs
    res = run(g, provider, sec["findings"], out / "cache", nids, metaphor=metaphor, progress=progress)
    if prev and prev.get("explanations"):
        prev["explanations"].update(res["explanations"])
        res["explanations"] = prev["explanations"]
        if prev.get("metaphor", {}).get("world") == res["metaphor"]["world"] and prev["metaphor"].get("roles"):
            res["metaphor"] = prev["metaphor"]
    (out / "explanations.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    rebuild_outputs(out, g)
    return res
