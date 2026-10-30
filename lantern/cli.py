"""lantern: map, trace, scan, explain, and report on a Python and/or JS/TS repository.

  lantern analyze PATH [--trace -- python -m pytest -q]   build the graph, scan, write report
  lantern trace PATH -- python -m pytest -q               record what actually runs
  lantern explain PATH --model anthropic/<model>          add Three-Lens explanations
  lantern report PATH                                     rebuild report.html from saved results

Results live in PATH/.lantern/ (override with --out).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .graph import Graph


def _out(repo: Path, out: str | None) -> Path:
    d = Path(out) if out else repo / ".lantern"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load(out: Path, name: str) -> dict | None:
    p = out / name
    return json.loads(p.read_text()) if p.exists() else None


def _split_cmd(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def cmd_analyze(a, trace_cmd: list[str]) -> int:
    from .engine import build_graph
    from .report import write_report
    from .security import scan
    from .trace import merge_trace, run_trace

    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    timings = {}
    t = time.perf_counter()
    g = build_graph(repo)
    timings["graph"] = round(time.perf_counter() - t, 2)
    s = g.stats()
    print(f"graph   {g.meta['files']} files ({g.meta['language']}), {s['nodes'].get('callable', 0)} functions, "
          f"{s['internal_call_edges']} internal calls, {s['entry_points']} entry points "
          f"({timings['graph']}s)")
    b = g.meta.get("bridge") or {}
    if b.get("http_calls"):
        print(f"bridge  {b['linked']} of {b['http_calls']} frontend HTTP calls linked to backend routes, "
              f"{b['ambiguous']} ambiguous, {b['unmatched']} going elsewhere")
    if trace_cmd:
        t = time.perf_counter()
        m = merge_trace(g, run_trace(repo, trace_cmd))
        timings["trace"] = round(time.perf_counter() - t, 2)
        print(f"trace   {m['observed_edges']} calls seen running, recall {m['recall']}, "
              f"{m['runtime_only']} runtime-only (exit {m['returncode']})")
    sec = None
    if not a.no_scan:
        t = time.perf_counter()
        sec = scan(g)
        timings["scan"] = round(time.perf_counter() - t, 2)
        c = sec["counts"]
        print(f"scan    {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low "
              f"({timings['scan']}s)")
        (out / "security.json").write_text(json.dumps(sec, indent=1))
    g.save(out / "graph.json")
    (out / "run.json").write_text(json.dumps({"timings": timings, "privacy": a.privacy}, indent=1))
    path = write_report(out, g, sec, _load(out, "explanations.json"), a.privacy, timings)
    print(f"report  {path}")
    return 0


def cmd_trace(a, trace_cmd: list[str]) -> int:
    from .report import write_report
    from .trace import merge_trace, run_trace
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    if not (out / "graph.json").exists():
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    if not trace_cmd:
        print("give the command after --, e.g. lantern trace . -- python -m pytest -q", file=sys.stderr)
        return 2
    g = Graph.load(out / "graph.json")
    m = merge_trace(g, run_trace(repo, trace_cmd))
    print(json.dumps(m, indent=1))
    g.save(out / "graph.json")
    run = _load(out, "run.json") or {}
    write_report(out, g, _load(out, "security.json"), _load(out, "explanations.json"),
                 run.get("privacy", "full"), run.get("timings"))
    return 0


def cmd_explain(a) -> int:
    from .explain import estimate, run, select_nodes
    from .providers import make_provider
    from .report import write_report
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    if not (out / "graph.json").exists():
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    g = Graph.load(out / "graph.json")
    sec = _load(out, "security.json") or {"findings": []}
    nids = select_nodes(g, depth=a.depth, limit=a.max_nodes, only=a.node or None)
    est = estimate(g, nids, sec["findings"])
    print(f"plan    {est['nodes']} functions, about {est['input_tokens']:,} input and "
          f"{est['output_tokens']:,} output tokens. {est['note']}")
    if a.estimate:
        return 0
    provider = make_provider(a.model, base_url=a.base_url)

    def progress(i, n, nid, rec):
        flag = "ok" if rec.get("validated") else ("ERR " + rec["error"][:80] if "error" in rec else "unvalidated")
        print(f"  [{i}/{n}] {g.nodes[nid].qualname}  {flag}", flush=True)

    res = run(g, provider, sec["findings"], out / "cache", nids, metaphor=a.metaphor, progress=progress)
    prev = _load(out, "explanations.json")
    if prev and prev.get("explanations"):
        prev["explanations"].update(res["explanations"])
        res["explanations"] = prev["explanations"]
    (out / "explanations.json").write_text(json.dumps(res, indent=1))
    st = res["stats"]
    print(f"explain {st['validated']} validated ({st['first_try']} first try), {st['failed']} failed, "
          f"{st['cached']} from cache. Tokens: {st['usage']['input_tokens']:,} in, "
          f"{st['usage']['output_tokens']:,} out. Metaphor: {res['metaphor']['world']}")
    run_meta = _load(out, "run.json") or {}
    path = write_report(out, g, sec, res, run_meta.get("privacy", "full"), run_meta.get("timings"))
    print(f"report  {path}")
    return 0


def cmd_report(a) -> int:
    from .report import write_report
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    g = Graph.load(out / "graph.json")
    run_meta = _load(out, "run.json") or {}
    print(write_report(out, g, _load(out, "security.json"), _load(out, "explanations.json"),
                       a.privacy or run_meta.get("privacy", "full"), run_meta.get("timings")))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    argv, trace_cmd = _split_cmd(argv)
    p = argparse.ArgumentParser(prog="lantern", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"lantern {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("path", nargs="?", default=".")
        sp.add_argument("--out", help="results folder (default PATH/.lantern)")

    sp = sub.add_parser("analyze", help="build graph, scan, write report")
    common(sp)
    sp.add_argument("--trace", action="store_true", help="also run the command after -- and record real calls")
    sp.add_argument("--no-scan", action="store_true")
    sp.add_argument("--privacy", choices=["full", "structure"], default="full",
                    help="full embeds function source in the report; structure leaves it out")

    sp = sub.add_parser("trace", help="run a command and mark calls that actually happen")
    common(sp)

    sp = sub.add_parser("explain", help="add Three-Lens explanations")
    common(sp)
    sp.add_argument("--model", help="PROVIDER/MODEL, e.g. anthropic/<model>, openai/<model>, ollama/<model>")
    sp.add_argument("--base-url", help="for openai-compatible endpoints")
    sp.add_argument("--depth", type=int, default=3, help="call depth from entry points (default 3)")
    sp.add_argument("--max-nodes", type=int, default=40, help="cap on functions explained (default 40)")
    sp.add_argument("--node", action="append", help="explain just this qualname (repeatable)")
    sp.add_argument("--metaphor", help='fix the metaphor world, e.g. "a hotel"')
    sp.add_argument("--estimate", action="store_true", help="show the token estimate and stop")

    sp = sub.add_parser("report", help="rebuild report.html")
    common(sp)
    sp.add_argument("--privacy", choices=["full", "structure"])

    a = p.parse_args(argv)
    if a.cmd == "analyze":
        return cmd_analyze(a, trace_cmd if a.trace else [])
    if a.cmd == "trace":
        return cmd_trace(a, trace_cmd)
    if a.cmd == "explain":
        if not a.estimate and not a.model:
            p.error("--model is required (or use --estimate)")
        return cmd_explain(a)
    return cmd_report(a)


if __name__ == "__main__":
    raise SystemExit(main())
