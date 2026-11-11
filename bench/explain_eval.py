"""Explanation eval: run `lantern explain` with a real model on a sample app and record how many explanations pass the
anchor validator, first try and after repair (test checklist 8.4; "Model changes" in the checklist).

    python bench/explain_eval.py PROJECT --live --model PROVIDER/MODEL --destination HOST --max-requests N
                                 [--limit 40] [--out /tmp/explain_eval.json]
                                 [--record docs/explain-runs.md --note "what changed"]

This is part of the live suite (bench/live.py): it starts only when --live, the model, the one host the sample's code
may be sent to and a cap on the number of requests are all given. There is no default model and no falling back to
whatever key the shell holds.

PROJECT is a folder Lantern has analyzed (`lantern analyze PROJECT`; the shop and nextapp fixtures are the standing
samples, the phone-app fixtures the newer ones). The selected functions (entry points + 3 levels, `--limit`) are
explained from scratch (the cache is bypassed, so the number is the model's, not the cache's) and the run's stats
are printed as one row in the shape of docs/explain-runs.md:

    validated / selected, first try, repaired, undetermined, invented findings dropped, tokens in / out

The validator (`explain.validate`) is never loosened to make a model pass. The target is 90% validated on the first
try. `--record` appends the row to the runs file with the date, the model and `--note`, so the history grows without a
hand-written table. Exit code 1 when the first-try rate is under --min-first-try (0.0 by default: a recording run),
so a CI job can fail when a model update drops the rate. tests/test_explain_eval.py runs the harness on a scripted
model offline.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import live  # noqa: E402  (bench/live.py)

from lantern import explain as ex  # noqa: E402
from lantern.graph import Graph  # noqa: E402


def run_eval(provider, project: Path, limit: int | None = 40, depth: int = 3) -> dict:
    out = project / ".lantern"
    g = Graph.load(out / "graph.json", project)
    sec = json.loads((out / "security.json").read_text(encoding="utf-8")) if (out / "security.json").exists() else {"findings": []}
    nids = ex.select_nodes(g, depth=depth, limit=limit)
    res = ex.run(g, provider, sec["findings"], out / "cache", nids, fresh=True)
    st = res["stats"]
    n = len(nids)
    rows = []
    for nid in nids:
        r = res["explanations"].get(nid) or {}
        rows.append({"node": nid, "validated": bool(r.get("validated")), "attempts": r.get("attempts"),
                     "repaired": bool(r.get("repaired")), "undetermined": bool(r.get("undetermined")),
                     "errors": r.get("validation_errors") or ([r["error"]] if r.get("error") else [])})
    return {"model": st.get("model"), "project": project.name, "selected": n, "validated": st["validated"],
            "first_try": st["first_try"], "repaired": st["repaired"], "undetermined": st["undetermined"],
            "invented_dropped": st["invented_findings"], "pairs_dropped": st["pairs_dropped"],
            "scenarios_dropped": st["scenarios_dropped"], "stopped": st.get("stopped"),
            "tokens_in": st["usage"]["input_tokens"], "tokens_out": st["usage"]["output_tokens"],
            "first_try_rate": round(st["first_try"] / n, 3) if n else None,
            "validated_rate": round(st["validated"] / n, 3) if n else None, "rows": rows}


def row(res: dict, note: str = "") -> str:
    """One line in the shape of the lens-v5 table in docs/explain-runs.md."""
    return (f"| {time.strftime('%Y-%m-%d')} | {res['model']} | {res['validated']} / {res['selected']} ({res['project']}) | "
            f"{res['first_try']} | {res['repaired']} | {res['undetermined']} | {res['invented_dropped']} | "
            f"{res['tokens_in']:,} / {res['tokens_out']:,} | {note or 'bench/explain_eval.py run'} |")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("project")
    ap.add_argument("--model")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--out")
    ap.add_argument("--record", help="append the row to this Markdown file (docs/explain-runs.md)")
    ap.add_argument("--note", default="")
    ap.add_argument("--min-first-try", type=float, default=0.0)
    live.add_arguments(ap)
    a = ap.parse_args(argv)
    try:
        provider = live.gate(a, Path(a.project))
    except live.NotApproved as e:
        print(e, file=sys.stderr)
        return 2
    res = run_eval(provider, Path(a.project), limit=a.limit)
    res["requests"], res["max_requests"] = provider.requests, provider.max_requests
    for r in res["rows"]:
        mark = "PASS" if r["validated"] else "FAIL"
        extra = " (repaired)" if r["repaired"] else (" (undetermined)" if r["undetermined"] else "")
        print(f"{mark} {r['node']}{extra}" + ("" if r["validated"] else f"  <- {'; '.join(r['errors'])[:200]}"))
    print("\n" + row(res, a.note))
    print(f"requests to the model: {res['requests']} of at most {res['max_requests']}")
    if res["stopped"]:
        print(f"STOPPED EARLY: {res['stopped']}")
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    if a.record:
        with open(a.record, "a", encoding="utf-8") as fh:
            fh.write(row(res, a.note) + "\n")
    rate = res["first_try_rate"] or 0.0
    refused = live.finish(provider)             # anything but the approved destination was refused, and fails the run
    return 0 if rate >= a.min_first_try and not res["stopped"] and not refused else 1


if __name__ == "__main__":
    sys.exit(main())
