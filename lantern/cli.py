"""lantern: map, explain, audit, and grade a full-stack app (Python + TypeScript/JavaScript).

  lantern serve [PATH ...]                                the local app in your browser (start here)
  lantern analyze PATH [--trace -- python -m pytest -q]   build the graph, scan, write report
  lantern trace PATH -- python -m pytest -q               record what actually runs
  lantern explain PATH --model anthropic/<model>          add Three-Lens explanations
  lantern report PATH                                     rebuild report.html from saved results
  lantern accept PATH FINDING_ID --reason "..."           record an accepted risk (committed in the repo)
  lantern starter PATH [--write NAME]                     show or write generated starter files
  lantern evidence PATH                                   rebuild the commit-pinned Evidence Report
  lantern verify PATH --digest sha256:...                 re-run the analysis and compare with a report
  lantern serve [PATH ...]                                the local app in your browser (start here)

Results live in PATH/.lantern/ (override with --out).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .graph import Graph


def _out(repo: Path, out: str | None) -> Path:
    d = Path(out) if out else repo / ".lantern"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load(out: Path, name: str) -> dict | None:
    p = out / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _split_cmd(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def cmd_analyze(a, trace_cmd: list[str]) -> int:
    from .pipeline import analyze
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    res = analyze(repo, out, a.privacy, trace_cmd, a.no_scan)
    if a.fail_on and res["counts"]:
        levels = RANKS[:RANKS.index(a.fail_on) + 1]
        n = sum(res["counts"].get(k, 0) for k in levels)
        if n:
            print(f"fail    {n} open finding(s) at {a.fail_on} or worse", file=sys.stderr)
            return 1
    return 0


RANKS = ["critical", "high", "medium", "low"]


def cmd_evidence(a) -> int:
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    if not (out / "graph.json").exists():
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    run_meta = _load(out, "run.json") or {}
    if a.reset_baseline and (out / "baseline.json").exists():
        (out / "baseline.json").unlink()
    from .pipeline import evidence
    print(evidence(out, Graph.load(out / "graph.json"), _load(out, "security.json"), _load(out, "readiness.json"),
                   run_meta, run_meta.get("privacy", "full")))
    return 0


def cmd_verify(a) -> int:
    import re
    from . import evidence
    from .engine import build_graph
    from .readiness import assess
    from .security import scan
    want = a.digest
    if a.report:
        m = re.search(r"sha256:[0-9a-f]{64}", Path(a.report).read_text(encoding="utf-8", errors="replace"))
        want = m.group(0) if m else None
    if not want:
        print("give --digest sha256:... or --report evidence.html", file=sys.stderr)
        return 2
    repo = Path(a.path).resolve()
    g = build_graph(repo)
    sec = scan(g)
    rd = assess(g, sec, {})
    gi = evidence.git_info(repo)
    got = evidence.digest(evidence.digest_payload(g, sec, rd, gi.get("commit"), gi.get("dirty", False)))
    print(f"commit  {gi.get('commit')}{' (uncommitted changes present)' if gi.get('dirty') else ''}")
    print(f"report  {want}\nrerun   {got}")
    if got == want:
        print("MATCH: the report's results are what this analyzer finds on this commit.")
        return 0
    print("DIFFERENT: check out the report's commit, install the same scanner versions (see Provenance), "
          "and make sure lantern-accepted.json matches.")
    if a.report and Path(a.report).with_suffix(".json").exists():
        old = json.loads(Path(a.report).with_suffix(".json").read_text(encoding="utf-8")).get("payload", {})
        new = evidence.digest_payload(g, sec, rd, gi.get("commit"), gi.get("dirty", False))
        for k in new:
            if old.get(k) != new[k]:
                print(f"  differs: {k}")
    return 1


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
                 run.get("privacy", "full"), run.get("timings"), _load(out, "readiness.json"))
    return 0


def cmd_explain(a) -> int:
    from .pipeline import explain, plan_explain
    from .providers import make_provider
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    if not (out / "graph.json").exists():
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    plan = plan_explain(out, a.depth, a.max_nodes, a.node or None)
    print(f"plan    {len(plan['nodes'])} functions, about {plan['input_tokens']:,} input and "
          f"{plan['output_tokens']:,} output tokens. {plan['note']}")
    if a.estimate:
        return 0
    provider = make_provider(a.model, base_url=a.base_url)
    g = Graph.load(out / "graph.json")

    def progress(i, n, nid, rec):
        flag = "ok" if rec.get("validated") else ("ERR " + rec["error"][:80] if "error" in rec else "unvalidated")
        print(f"  [{i}/{n}] {g.nodes[nid].qualname}  {flag}", flush=True)

    res = explain(out, provider, plan["nodes"], metaphor=a.metaphor, progress=progress)
    st = res["stats"]
    print(f"explain {st['validated']} validated ({st['first_try']} first try), {st['failed']} failed, "
          f"{st['cached']} from cache. Tokens: {st['usage']['input_tokens']:,} in, "
          f"{st['usage']['output_tokens']:,} out. Metaphor: {res['metaphor']['world']}")
    print(f"report  {out / 'report.html'}")
    return 0


def cmd_report(a) -> int:
    from .report import write_report
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    g = Graph.load(out / "graph.json")
    run_meta = _load(out, "run.json") or {}
    print(write_report(out, g, _load(out, "security.json"), _load(out, "explanations.json"),
                       a.privacy or run_meta.get("privacy", "full"), run_meta.get("timings"),
                       _load(out, "readiness.json")))
    return 0


def cmd_accept(a) -> int:
    import datetime as dt
    import getpass
    from .security import load_accepted, reason_ok, save_accepted
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    accepted = load_accepted(repo)
    if a.remove:
        if accepted.pop(a.finding, None) is None:
            print(f"{a.finding} is not in the accepted list", file=sys.stderr)
            return 2
        print(f"removed {a.finding}; it counts as open again. Wrote {save_accepted(repo, accepted)}")
        return 0
    sec = _load(out, "security.json") or {"findings": []}
    f = next((x for x in sec["findings"] if x["id"] == a.finding), None)
    if f is None:
        print(f"no finding {a.finding} in the last scan; run `lantern analyze` and copy an id from Findings",
              file=sys.stderr)
        return 2
    if not reason_ok(a.reason):
        print("give a real reason (--reason, a sentence of at least 10 letters); it appears in the Evidence Report",
              file=sys.stderr)
        return 2
    accepted[f["id"]] = {"id": f["id"], "rule": f["rule"], "file": f["file"], "line": f["line"],
                         "title": f["title"], "reason": a.reason.strip(), "by": a.by or getpass.getuser(),
                         "date": dt.date.today().isoformat()}
    print(f"accepted {f['id']} ({f['rule']} at {f['file']}:{f['line']}). Wrote {save_accepted(repo, accepted)}")
    print("Re-run `lantern analyze` to update the score. Commit the file so reviewers see the reason.")
    return 0


def cmd_starter(a) -> int:
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    rd = _load(out, "readiness.json")
    if rd is None:
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    files = rd.get("starter", {})
    if not files:
        print("nothing to generate: every starter file already exists")
        return 0
    if not a.write:
        for name, f in files.items():
            print(f"--- {name}{'  (snippet: paste into your code)' if f.get('snippet') else ''}\n# {f['why']}\n"
                  f"{f['content']}")
        print("Write one with: lantern starter PATH --write NAME   (or --write all)")
        return 0
    names = [n for n, f in files.items() if not f.get("snippet")] if a.write == ["all"] else a.write
    for name in names:
        f = files.get(name)
        if f is None or f.get("snippet"):
            print(f"skip {name}: not a writable starter file", file=sys.stderr)
            continue
        dest = (repo / name).resolve()
        if repo not in dest.parents:
            print(f"skip {name}: outside the repository", file=sys.stderr)
            continue
        if dest.exists():
            print(f"skip {name}: already exists, not overwritten")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f["content"], encoding="utf-8")
        print(f"wrote {dest.relative_to(repo)}")
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
    sp.add_argument("--fail-on", choices=RANKS, help="exit 1 if any open finding is at this rank or worse (for CI)")

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

    sp = sub.add_parser("accept", help="accept a finding's risk with a written reason")
    common(sp)
    sp.add_argument("finding", help="finding id (shown in the Findings tab)")
    sp.add_argument("--reason", help="why this risk is acceptable; shown in the Evidence Report")
    sp.add_argument("--by", help="who accepted it (default: your username)")
    sp.add_argument("--remove", action="store_true", help="un-accept: the finding counts as open again")

    sp = sub.add_parser("starter", help="show or write generated starter files (Dockerfile, CI, .env.example, ...)")
    common(sp)
    sp.add_argument("--write", nargs="+", metavar="NAME", help="file name(s) to write, or `all`; never overwrites")

    sp = sub.add_parser("evidence", help="rebuild the Evidence Report from saved results")
    common(sp)
    sp.add_argument("--reset-baseline", action="store_true", help="treat the current findings as the new 'before'")

    sp = sub.add_parser("verify", help="re-run the analysis and compare with an Evidence Report's digest")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--digest", help="sha256:... from the report")
    sp.add_argument("--report", help="evidence.html (or .json) to read the digest from")

    sp = sub.add_parser("serve", help="open the Lantern app in your browser (projects, map, findings, readiness)")
    sp.add_argument("paths", nargs="*", help="project folders to add (analyzed on first open)")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (this computer only)")
    sp.add_argument("--no-open", action="store_true", help="don't open a browser")

    a = p.parse_args(argv)
    if a.cmd == "analyze":
        return cmd_analyze(a, trace_cmd if a.trace else [])
    if a.cmd == "trace":
        return cmd_trace(a, trace_cmd)
    if a.cmd == "explain":
        if not a.estimate and not a.model:
            p.error("--model is required (or use --estimate)")
        return cmd_explain(a)
    if a.cmd == "accept":
        return cmd_accept(a)
    if a.cmd == "starter":
        return cmd_starter(a)
    if a.cmd == "evidence":
        return cmd_evidence(a)
    if a.cmd == "verify":
        return cmd_verify(a)
    if a.cmd == "serve":
        from .server import serve
        return serve(a.paths, host=a.host, port=a.port, open_browser=not a.no_open)
    return cmd_report(a)


if __name__ == "__main__":
    raise SystemExit(main())
