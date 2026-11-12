"""Behaviour benchmark (directive point 5): the plan of `bench/behaviour/plan.py` against Corkboard, the safe app
and each version with one planted problem.

    python bench/behaviour/run_behaviour.py WORKDIR [--jobs 3] [--only ID,ID] [--own-checks] [--results FILE]

Each version is written into WORKDIR/<id> and run by `lantern.behave` inside Lantern's test sandbox: a read-only
copy, no network, its data in a temp folder that is deleted. By default the whole plan is run against every
version, so a planted problem must be caught by the cases written down for it (`plan.EXPECTED`) and no other case
may come out broken; the safe app must hold everywhere. `--own-checks` runs, for a planted version, only the
checks written down for it (what tests/test_behave.py does; a tenth of the time). `--results` writes the table as
Markdown. Result 1 when anything differs from what was written down, or when something outside this computer was
tried (tools/netguard); 3 where the sandbox starts no app (Windows, `sandbox.NO_APPS`).
"""
from __future__ import annotations

import argparse
import importlib.util
import platform
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

from lantern import behave, sandbox  # noqa: E402


def _load(name: str):
    spec = importlib.util.spec_from_file_location("behaviour_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


apps, plans = _load("apps"), _load("plan")
SAFE = "safe"


def run_one(work: Path, name: str, own_checks: bool = False) -> dict:
    """Write one version of the app into `work/<name>`, run the plan against it in the sandbox, and say where
    the outcomes differ from what was written down (`differences`: empty when they do not)."""
    planted = None if name == SAFE else name
    repo = Path(work) / name
    shutil.rmtree(repo, ignore_errors=True)
    apps.build(repo, planted)
    the_plan = plans.plan()
    if own_checks and planted:
        the_plan = plans.only(the_plan, plans.own_checks(planted))
    lines: list[str] = []
    t0 = time.monotonic()
    record = behave.run(repo, log=lines.append, plan=the_plan)
    broken = {f"{o['check']}/{o['case']}": o["codes"] for o in record["outcomes"] if o["outcome"] == "broken"}
    return {"name": name, "summary": record["summary"], "broken": broken, "differences": plans.differences(planted, record),
            "seconds": round(time.monotonic() - t0, 1), "app_starts": record.get("app_starts"), "log": lines[-30:]}


def table(rows: list[dict], own_checks: bool) -> str:
    out = ["| Version | What is planted | Held | Broken | Undecided | Not run | Broken cases | As written down |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        about = "nothing: the safe app" if r["name"] == SAFE else apps.PLANTED[r["name"]][1]
        s = r["summary"]
        cases = "; ".join(f"{case} ({', '.join(codes)})" for case, codes in sorted(r["broken"].items())) or "none"
        out.append(f"| `{r['name']}` | {about} | {s['held']} | {s['broken']} | {s['inconclusive']} | {s['not-run']} | "
                   f"{cases} | {'yes' if not r['differences'] else 'NO: ' + ' / '.join(r['differences'])[:600]} |")
    same = sum(1 for r in rows if not r["differences"])
    out += ["", f"{len(rows)} versions, {same} as written down, {len(rows) - same} differing. "
            + ("Only the checks written down for each planted problem were run." if own_checks else
               "The whole plan was run against every version, so no other case may come out broken.")]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("work", help="a folder for the apps (made if needed)")
    ap.add_argument("--jobs", type=int, default=3, help="versions run side by side")
    ap.add_argument("--only", default="", help=f"comma-separated versions ({SAFE}, or a planted id); default: all")
    ap.add_argument("--own-checks", action="store_true", help="for a planted version, only the checks written down for it")
    ap.add_argument("--results", default="", help="write the table here as Markdown")
    a = ap.parse_args(argv)
    names = [SAFE, *apps.PLANTED]
    only = [n for n in a.only.split(",") if n]
    unknown = [n for n in only if n not in names]
    if unknown:
        print(f"unknown: {', '.join(unknown)}; the versions are: {', '.join(names)}", file=sys.stderr)
        return 2
    if sandbox.NO_APPS:
        print(f"no app is started on this system: {sandbox.NO_APPS}", file=sys.stderr)
        return 3
    guard = netguard.begin()                      # isolated (tools/netguard); this benchmark needs no network at all
    t0 = time.monotonic()
    with ThreadPoolExecutor(max(1, a.jobs)) as pool:
        rows = list(pool.map(lambda name: run_one(Path(a.work), name, a.own_checks), only or names))
    for r in rows:
        print(f"{r['name']:24} {'as written down' if not r['differences'] else 'DIFFERS':16} {r['summary']} "
              f"{r['seconds']} s, {r['app_starts']} app starts")
        for line in r["differences"]:
            print("    " + line)
    took = time.monotonic() - t0
    text = table(rows, a.own_checks)
    print(text.rsplit("\n", 2)[-2])
    if a.results:
        head = (f"# Behaviour benchmark: Corkboard, safe and with each planted problem\n\n"
                f"`python bench/behaviour/run_behaviour.py WORKDIR{' --own-checks' if a.own_checks else ''}`, "
                f"{time.strftime('%Y-%m-%d', time.gmtime())} (UTC), Python {sys.version.split()[0]} on {platform.system()}, "
                f"{a.jobs} side by side, {took:.0f} s in all (one version alone: {min(r['seconds'] for r in rows)} to "
                f"{max(r['seconds'] for r in rows)} s while the others ran). Every app ran in Lantern's test sandbox "
                f"with no network.\n\n")
        Path(a.results).write_text(head + text, encoding="utf-8")
    refused = netguard.end(guard)
    return 1 if any(r["differences"] for r in rows) or refused else 0


if __name__ == "__main__":
    raise SystemExit(main())
