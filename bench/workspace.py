"""Workspace check: a project reads the same inside a workspace as alone, and a split app links again (2026-11-17).

    python bench/workspace.py [--only shop,goapp] [--json FILE]

`lantern workspace` (lantern/workspace.py) copies several projects side by side, each in a folder under its own name,
and checks that folder as one project. Two things have to hold for that to be worth anything, and this measures both
on the sample projects under `tests/fixtures`, offline, with nothing kept between runs (LANTERN_CACHE=off):

  alone and inside   Each sample is read alone, at its own top, and as a member of a workspace beside a small
                     project that answers none of its requests (PARTNER). Its functions (by file and lines), the
                     links between them (with `via` and confidence), its entry points, its call-site records and its
                     findings (rule, file, line, rank) are compared, with every path taken from the member's top.
                     A difference means a reader reads something from the top of the repository, or the workspace
                     changed what the member holds.
  split and joined   A sample that holds a web page and its server in one repository (SPLITS) is split in two, the
                     web folder as a project of its own and the rest as another, and the two are checked as a
                     workspace. The requests linked from page to server are compared with the sample read whole.

What it must show, written down on 2026-11-17 before its first run:

  alone and inside   every sample the same in all five, and no link from a sample to the partner or back;
  split and joined   every request linked in the whole sample from the web folder to the rest is linked across the
                     two projects, by the same rule (`via`) and with the same confidence, and nothing else.

Any difference is either fixed in Lantern after a failing test of its own, or named in
`bench/workspace_results.md` with the reason. Deterministic, no network (tools/netguard), about two minutes. Not
part of CI: `tests/test_workspace.py` runs the cases it found. Run it after changing a reader's idea of where a
project begins.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

SAMPLES = ("aiapp", "androidapp", "cppapp", "csharpapp", "flutterapp", "goapp", "iosapp", "javaapp", "kotlinapp",
           "nextapp", "phpapp", "rnapp", "rubyapp", "rustapp", "shop")
# A small project of another kind, with names no sample has, that answers no request and makes none.
PARTNER = {"README.md": "Notes kept apart from the app.\n",
           "partner_tally/count_words.py": "def count_words(text):\n    return len(text.split())\n\n\n"
                                           "def tally(lines):\n    return sum(count_words(x) for x in lines)\n"}
# The folder of a sample that is its web page, checked as a project of its own; the rest is the other project.
SPLITS = {"aiapp": "web", "cppapp": "web", "goapp": "web", "javaapp": "web", "rubyapp": "web", "rustapp": "web",
          "shop": "web"}
FIVE = ("functions", "links", "entries", "calls", "findings")


def _under(rel: str | None, top: str) -> str | None:
    """A file's path from the member's top; None when it is not the member's."""
    if not rel:
        return None
    if not top:
        return rel
    return rel[len(top) + 1:] if rel.startswith(top + "/") else None


def facts(g, sec, top: str) -> dict:
    """What a project holds, with every path taken from its own top (`top`: its folder in the map, "" when alone)."""
    key = {}
    for nid, n in g.nodes.items():
        rel = _under(n.file, top)
        if rel is not None:
            key[nid] = f"{rel}:{n.start_line}-{n.end_line}:{n.kind}:{n.name}"

    def end(nid):
        return key.get(nid) or (nid if nid.startswith(("ext:", "db:", "builtin:")) else None)

    out = {k: set() for k in FIVE}
    out["functions"] = set(key.values())
    for e in g.edges:
        a, b = key.get(e.src), end(e.dst)
        if a and b:
            out["links"].add(f"{a} -> {b} [{e.kind} {e.via} {e.confidence}]")
    for nid, n in g.nodes.items():
        if nid in key and n.entry:
            detail = str(n.entry.get("detail"))
            if top:      # an entry's words name its file from the top of the map: here, from the member's
                detail = detail.replace(f"({top}/", "(").replace(f" {top}/", " ")
                detail = detail[len(top) + 1:] if detail.startswith(top + "/") else detail
            out["entries"].add(f"{key[nid]} {n.entry.get('kind')} {detail}")
    for s in g.sites:
        rel = _under(s.get("file"), top)
        if rel is not None:
            to = sorted(str(end(t) or "?") for t in s.get("to") or [])
            out["calls"].add(f"{rel}:{s['line']}:{s['col']} {s['group']} {s['outcome']} {s.get('via')} "
                             f"{s.get('reason')} {to}")
    for f in (sec or {}).get("findings", []):
        rel = _under(f.get("file"), top)
        if rel is not None:
            out["findings"].add(f"{f['rule']} {rel}:{f.get('line')} {f['rank']} {f.get('status', 'open')}")
    return out


def _check(folder: Path):
    from lantern.engine import build_graph
    from lantern.security import scan
    g = build_graph(folder)
    return g, scan(g, offline=True)


def _write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def alone_and_inside(name: str, work: Path) -> dict:
    from lantern import workspace
    sample = ROOT / "tests" / "fixtures" / name
    g, sec = _check(sample)
    alone = facts(g, sec, "")
    partner = _write(work / "partner-src" / "partner", PARTNER)
    rec = workspace.make([str(sample), f"partner={partner}"], name=f"w-{name}")
    member = rec["members"][0]["name"]
    g2, sec2 = _check(workspace.folder_of(rec["name"]))
    inside = facts(g2, sec2, member)
    across = g2.meta["workspace"]["across"]
    out = {"member": member, "counts": {k: len(alone[k]) for k in FIVE},
           "only_alone": {k: sorted(alone[k] - inside[k]) for k in FIVE},
           "only_inside": {k: sorted(inside[k] - alone[k]) for k in FIVE},
           "across": {"requests": across["requests"], "code": across["code"]}}
    workspace.remove(rec["name"])
    return out


def _bridged(g, web: str) -> set[str]:
    """The requests the whole sample's map links from a file of its web folder to a route outside it: what was asked,
    the route that answers, and how they were linked."""
    out = set()
    for e in g.edges:
        if not (e.via or "").startswith("http-") or e.src not in g.nodes or e.dst not in g.nodes or outside(e.dst):
            continue
        if (g.nodes[e.src].file or "").startswith(web + "/") and not (g.nodes[e.dst].file or "").startswith(web + "/"):
            route = (g.nodes[e.dst].entry or {}).get("detail")
            out.add(f"{e.detail} => {route} [{e.via} {e.confidence}]")
    return out


def outside(nid: str) -> bool:
    from lantern.graph import outside as out
    return out(nid)


def split_and_joined(name: str, web: str, work: Path) -> dict:
    from lantern import workspace
    from lantern.engine import build_graph
    sample = ROOT / "tests" / "fixtures" / name
    want = _bridged(build_graph(sample), web)
    rest = work / "split" / name / "server"
    shutil.copytree(sample, rest, ignore=lambda d, names: [web] if Path(d) == sample else [])
    page = work / "split" / name / "client"
    shutil.copytree(sample / web, page)
    rec = workspace.make([f"server={rest}", f"client={page}"], name=f"s-{name}")
    g = build_graph(workspace.folder_of(rec["name"]))
    across = g.meta["workspace"]["across"]
    got = {f"{r['call']} => {r['route']} [{r['via']} {r['confidence']}]" for r in across["rows"]
           if r["kind"] == "request" and r["from"] == "client" and r["to"] == "server"}
    workspace.remove(rec["name"])
    return {"whole": len(want), "joined": len(got), "only_whole": sorted(want - got), "only_joined": sorted(got - want),
            "requests_across": across["requests"], "code_across": across["code"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", default="", help="comma-separated sample names (default: every sample)")
    ap.add_argument("--json", default="", help="write the results here as JSON")
    a = ap.parse_args(argv)
    only = [n for n in a.only.split(",") if n]
    unknown = [n for n in only if n not in SAMPLES]
    if unknown:
        print(f"unknown: {', '.join(unknown)}; the samples are: {', '.join(SAMPLES)}", file=sys.stderr)
        return 2
    guard = netguard.begin()                      # isolated (tools/netguard); this benchmark needs no network at all
    os.environ["LANTERN_CACHE"] = "off"           # nothing kept between runs: each reading is done afresh
    work = Path(tempfile.mkdtemp(prefix="lantern-workspace-bench-"))
    os.environ["LANTERN_HOME"] = str(work / "home")
    t0 = time.time()
    report = {"alone_and_inside": {}, "split_and_joined": {}}
    bad = 0
    try:
        for name in only or SAMPLES:
            r = alone_and_inside(name, work)
            report["alone_and_inside"][name] = r
            diff = {k: len(r["only_alone"][k]) + len(r["only_inside"][k]) for k in FIVE}
            crossed = r["across"]["requests"] + r["across"]["code"]
            bad += bool(sum(diff.values()) or crossed)
            print(f"alone/inside  {name:11} " + "  ".join(f"{k} {r['counts'][k]}"
                                                          + (f" (differ {diff[k]})" if diff[k] else "") for k in FIVE)
                  + (f"  across {crossed}" if crossed else ""))
            for k in FIVE:
                for x in r["only_alone"][k][:6]:
                    print(f"    only alone  {k}: {x}")
                for x in r["only_inside"][k][:6]:
                    print(f"    only inside {k}: {x}")
        for name in [n for n in (only or SAMPLES) if n in SPLITS]:
            r = split_and_joined(name, SPLITS[name], work)
            report["split_and_joined"][name] = r
            bad += bool(r["only_whole"] or r["only_joined"])
            print(f"split/joined  {name:11} whole {r['whole']}  joined {r['joined']}  across: {r['requests_across']} "
                  f"requests, {r['code_across']} code")
            for x in r["only_whole"]:
                print(f"    only whole   {x}")
            for x in r["only_joined"]:
                print(f"    only joined  {x}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(f"{len(report['alone_and_inside'])} samples alone and inside, {len(report['split_and_joined'])} split and "
          f"joined, in {time.time() - t0:.0f} s: {bad} with a difference")
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=1), encoding="utf-8")
    refused = netguard.end(guard)
    return 1 if bad or refused else 0


if __name__ == "__main__":
    sys.exit(main())
