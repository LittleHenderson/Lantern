"""Phase 0 benchmark: graph build time, scan time, and static-vs-runtime accuracy on public repos.

    python bench/run_bench.py WORKDIR [--no-trace] [--only NAME]

Accuracy method: run each repo's own test suite under the trace hook. For every function that
actually executed, compare the static edges Lantern predicted against the calls that really
happened.
  * recall      = observed calls that the static graph also found
  * precision*  = static edges (from executed callers, resolved/inferred only) that were observed
Precision* is a lower bound: tests don't exercise every branch, so a correct edge can go
unobserved. Hand-labelled samples (Phase 0 exit criterion) tighten it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from lantern.engine import build_graph  # Python + TypeScript + API bridge
from lantern.security import scan
from lantern.trace import merge_trace, run_trace

REPOS = [
    # name, git url, ref, install, test command (run from repo root)
    ("click", "https://github.com/pallets/click", "8.1.8", True, ["-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "filterwarnings=ignore", "tests"]),
    ("flask", "https://github.com/pallets/flask", "main", True, ["-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "filterwarnings=ignore", "tests"]),
    ("rich", "https://github.com/Textualize/rich", "v13.9.4", True, ["-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "filterwarnings=ignore", "tests"]),
    ("requests", "https://github.com/psf/requests", "v2.32.3", False, None),
    ("httpie", "https://github.com/httpie/cli", "3.2.4", False, None),
    ("fastapi-template", "https://github.com/fastapi/full-stack-fastapi-template", "master", False, None),
    ("taxonomy", "https://github.com/shadcn-ui/taxonomy", "main", False, None),
]


def sh(cmd, cwd=None, timeout=900):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def ensure_repo(work: Path, name: str, url: str, ref: str) -> Path:
    d = work / name
    if not d.exists():
        r = sh(["git", "clone", "--depth", "1", "--branch", ref, url, str(d)])
        if r.returncode != 0:
            r = sh(["git", "clone", "--depth", "1", url, str(d)])
            if r.returncode != 0:
                raise RuntimeError(r.stderr[-400:])
    return d


def edge_metrics(g, trace_data):
    before = {(e.src, e.dst): e.confidence for e in g.call_edges()}
    m = merge_trace(g, trace_data)
    observed = {(e.src, e.dst) for e in g.call_edges() if e.confidence == "observed"}
    ran = {a for a, _ in observed}
    by_conf, by_via = {}, {}
    for e in g.call_edges():
        k = (e.src, e.dst)
        if e.src not in ran or e.dst.startswith("ext:") or k not in before:
            continue
        if g.nodes[e.dst].kind == "class":   # constructing a class without __init__: unobservable
            continue
        hit = int(k in observed)
        for table, key in ((by_conf, before[k]), (by_via, (e.via or "").split("+")[0])):
            b = table.setdefault(key, [0, 0])
            b[0] += 1
            b[1] += hit
    m["precision_lower_bound"] = {k: round(v[1] / v[0], 3) for k, v in by_conf.items() if v[0]}
    m["static_edges_checked"] = {k: v[0] for k, v in by_conf.items()}
    m["precision_by_method"] = {k: f"{v[1]}/{v[0]}" for k, v in sorted(by_via.items(), key=lambda kv: -kv[1][0])}
    return m


def name_verified(g) -> str | None:
    """For generated API clients (ItemsService.updateItem -> update_item), check each link by name."""
    import re
    links = [e for e in g.call_edges() if (e.via or "").startswith("http-") and not e.dst.startswith("ext:")]
    gen = [e for e in links if ".gen" in (g.nodes[e.src].file or "")]
    if not gen:
        return None
    ok = sum(1 for e in gen if re.sub(r"(?<!^)(?=[A-Z])", "_", g.nodes[e.src].name).lower() == g.nodes[e.dst].name)
    return f"{ok}/{len(gen)}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("work")
    ap.add_argument("--no-trace", action="store_true")
    ap.add_argument("--only")
    a = ap.parse_args()
    work = Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, url, ref, install, test_cmd in REPOS:
        if a.only and name != a.only:
            continue
        print(f"== {name}", flush=True)
        try:
            repo = ensure_repo(work, name, url, ref)
        except Exception as exc:
            print(f"   clone failed: {exc}")
            continue
        t = time.perf_counter()
        g = build_graph(repo)
        t_graph = time.perf_counter() - t
        st = g.stats()
        t = time.perf_counter()
        sec = scan(g)
        t_scan = time.perf_counter() - t
        row = {"name": name, "ref": ref, "files": g.meta["files"], "lines": g.meta["lines"],
               "functions": st["nodes"].get("callable", 0), "entry_points": st["entry_points"],
               "entry_kinds": {}, "internal_edges": st["internal_call_edges"],
               "confidence": st["confidence"], "unresolved": st["unresolved_call_sites"],
               "graph_s": round(t_graph, 2), "scan_s": round(t_scan, 2), "findings": sec["counts"]}
        for n in g.entry_points():
            row["entry_kinds"][n.entry["kind"]] = row["entry_kinds"].get(n.entry["kind"], 0) + 1
        row["languages"] = g.meta.get("languages", {})
        br = g.meta.get("bridge", {})
        if br.get("http_calls"):
            row["bridge"] = {k: v for k, v in br.items() if k != "unmatched_examples"}
            row["bridge"]["links"] = sorted(
                f"{e.detail}  {g.nodes[e.src].qualname} -> {g.nodes[e.dst].qualname}"
                for e in g.call_edges() if (e.via or "").startswith("http-") and not e.dst.startswith("ext:"))
            row["bridge"]["name_verified"] = name_verified(g)
        if test_cmd and not a.no_trace:
            if install:
                sh([sys.executable, "-m", "pip", "install", "-q", "--break-system-packages", "-e", str(repo)])
            t = time.perf_counter()
            data = run_trace(repo, ["python", *test_cmd], timeout=1800)
            row["trace_s"] = round(time.perf_counter() - t, 1)
            row["trace"] = edge_metrics(g, data)
        rows.append(row)
        print(json.dumps(row, indent=1), flush=True)
    (work / "bench_results.json").write_text(json.dumps(rows, indent=1))
    print(f"wrote {work / 'bench_results.json'}")


if __name__ == "__main__":
    main()
