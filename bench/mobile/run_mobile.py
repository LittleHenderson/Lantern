"""Findings accuracy on real phone apps: how many findings an engineer agrees with (test checklist 8.2, 10.4).

    python bench/mobile/run_mobile.py WORKDIR [--only NAME] [--budget-s 600] [--queue PATH] [--results PATH]
                                      [--summary PATH] [--min-precision 0.8]

Each app in bench/mobile/apps.json (public Android, iOS, Flutter and React Native apps; an entry may name a local
`path` instead of a `url`) is cloned shallowly and analysed offline. Every finding is then looked up in
bench/mobile/labels.json, where an engineer has written **real**, **false alarm** or **cannot tell** with a reason
(a row per finding id; ids are made from the line's text, so they survive the file moving). The script prints, per
rule and per platform, how many findings were labelled real, how many were false alarms and the precision
(real / (real + false alarm)), writes the Markdown table to --results (bench/mobile/results.md is the last run), and
writes every finding that has no label yet to --queue, which is the list to hand the next engineer (the tester
round's task 4, docs/tester-round.md). It exits 1 when a rule with at least five labels has a precision under
--min-precision: that rule is then the next thing to fix, or to relabel as heuristic.

Nothing here is a unit test (network, minutes); tests/test_mobile_bench.py proves the scoring on the fixtures.
The run is isolated (tools/netguard): a temporary home folder, no keys or saved sign-ins, real model providers off,
and the network refused except for the hosts the apps are cloned from.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)
LABELS = ("real", "false alarm", "cannot tell")


def load_apps(path: Path = HERE / "apps.json") -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_labels(path: Path = HERE / "labels.json") -> dict[str, dict[str, dict]]:
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    for app, rows in data.items():
        for fid, row in rows.items():
            if row.get("label") not in LABELS:
                raise ValueError(f"{app}/{fid}: label must be one of {LABELS}, not {row.get('label')!r}")
            if not str(row.get("reason", "")).strip():
                raise ValueError(f"{app}/{fid}: every label needs a reason")
    return data


def clone(url: str, ref: str | None, dest: Path) -> None:
    cmd = ["git", "clone", "-q", "--depth", "1"] + (["--branch", ref] if ref else []) + [url, str(dest)]
    subprocess.run(cmd, check=True, timeout=900)     # in the isolated run's environment: no sign-in, prompts off


def hosts(apps: list[dict]) -> list[str]:
    """Where the apps are cloned from: everything this benchmark may reach."""
    return sorted({urllib.parse.urlsplit(a["url"]).hostname for a in apps if a.get("url")} - {None})


def commit_of(repo: Path) -> str | None:
    try:
        return subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              encoding="utf-8", timeout=30).stdout.strip() or None
    except (subprocess.SubprocessError, OSError):
        return None


def analyse(app: dict, work: Path, budget_s: int) -> dict:
    """Clone (unless the entry has a local path) and run `lantern analyze --offline`; return the app's findings."""
    name = app["name"]
    repo = ROOT / app["path"] if app.get("path") else work / name
    row: dict = {"name": name, "platform": app["platform"]}
    if not repo.exists():
        try:
            clone(app["url"], app.get("ref"), repo)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            return row | {"status": f"clone failed: {type(exc).__name__}", "findings": []}
    row["commit"] = commit_of(repo)
    out = work / f"{name}.out"
    t = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, "-m", "lantern.cli", "analyze", str(repo), "--out", str(out), "--offline",
                               "--privacy", "structure"], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=budget_s, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        return row | {"status": f"TOO SLOW: stopped after {budget_s} s", "findings": []}
    row["seconds"] = round(time.monotonic() - t, 1)
    sec = out / "security.json"
    if proc.returncode != 0 or not sec.is_file():
        return row | {"status": f"FAILED (exit {proc.returncode}): {proc.stderr.strip().splitlines()[-1:] or ''}", "findings": []}
    data = json.loads(sec.read_text(encoding="utf-8"))
    row["status"] = "ok"
    row["findings"] = [{"id": f["id"], "rule": f.get("rule"), "file": f.get("file"), "line": f.get("line"),
                        "rank": f.get("rank"), "headline": f.get("headline") or f.get("title"),
                        "snippet": (f.get("snippet") or "")[:160], "heuristic": f.get("tool_confidence") == "LOW"}
                       for f in data.get("findings", [])]
    return row


def score(apps: list[dict], labels: dict[str, dict[str, dict]]) -> dict:
    """Join findings with labels: counts per rule, per platform and in total, plus the unlabelled queue."""
    per_rule: dict[str, dict] = defaultdict(lambda: {"real": 0, "false alarm": 0, "cannot tell": 0, "unlabelled": 0, "heuristic": 0})
    per_platform: dict[str, dict] = defaultdict(lambda: {"real": 0, "false alarm": 0, "cannot tell": 0, "unlabelled": 0, "heuristic": 0})
    queue: list[dict] = []
    stale: list[dict] = []
    for app in apps:
        got = labels.get(app["name"], {})
        seen = set()
        for f in app["findings"]:
            seen.add(f["id"])
            lab = got.get(f["id"], {}).get("label", "unlabelled")
            if f.get("heuristic") and lab != "unlabelled":
                # the report already calls it "heuristic": a false alarm here is expected, so it is counted apart
                lab = "heuristic"
            per_rule[f["rule"]][lab] += 1
            per_platform[app["platform"]][lab] += 1
            if lab == "unlabelled":
                queue.append({"app": app["name"], **f})
        for fid, row in got.items():       # a label whose finding no longer appears: the rule changed or the app moved on
            if fid not in seen:
                stale.append({"app": app["name"], "id": fid, **row})

    def prec(c: dict) -> float | None:
        n = c["real"] + c["false alarm"]
        return round(c["real"] / n, 3) if n else None

    rules = {r: {**c, "precision": prec(c)} for r, c in sorted(per_rule.items())}
    plats = {p: {**c, "precision": prec(c)} for p, c in sorted(per_platform.items())}
    total = {k: sum(c[k] for c in per_rule.values()) for k in ("real", "false alarm", "cannot tell", "unlabelled", "heuristic")}
    total["precision"] = prec(total)
    return {"rules": rules, "platforms": plats, "total": total, "queue": queue, "stale": stale}


def table(apps: list[dict], scored: dict) -> str:
    lines = ["| App | Platform | Commit | Findings | Labelled | Real | False alarm | Cannot tell | Status |", "|---|---|---|---:|---:|---:|---:|---:|---|"]
    for a in apps:
        labs = [f for f in a["findings"] if f.get("label")]
        counts = defaultdict(int)
        for f in labs:
            counts[f["label"]] += 1
        lines.append(f"| {a['name']} | {a['platform']} | {a.get('commit') or '–'} | {len(a['findings'])} | {len(labs)} | "
                     f"{counts['real']} | {counts['false alarm']} | {counts['cannot tell']} | {a.get('status', '')} |")
    hdr = ["", "| {} | Real | False alarm | Cannot tell | Labelled heuristic | Not labelled yet | Precision |", "|---|---:|---:|---:|---:|---:|---:|"]

    def line(name, c):
        p = c["precision"]
        return (f"| {name} | {c['real']} | {c['false alarm']} | {c['cannot tell']} | {c['heuristic']} | {c['unlabelled']} | "
                f"{'–' if p is None else format(p, '.0%')} |")
    lines += [h.format("Rule") for h in hdr] + [line(f"`{r}`", c) for r, c in scored["rules"].items()]
    lines.append(line("**all**", scored["total"]))
    lines += [h.format("Platform") for h in hdr] + [line(pl, c) for pl, c in scored["platforms"].items()]
    lines += ["", "Precision = real / (real + false alarm) over the findings an engineer labelled. A finding the report "
              "already marks \"heuristic\" (the check is known to be a guess) is counted in its own column, not against "
              "the rule."]
    return "\n".join(lines)


def attach_labels(apps: list[dict], labels: dict) -> None:
    for a in apps:
        got = labels.get(a["name"], {})
        for f in a["findings"]:
            if f["id"] in got:
                f["label"] = got[f["id"]]["label"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workdir")
    ap.add_argument("--only")
    ap.add_argument("--budget-s", type=int, default=600)
    ap.add_argument("--queue", help="write the findings that have no label yet here (JSON)")
    ap.add_argument("--results", help="write the Markdown tables here (bench/mobile/results.md is the record)")
    ap.add_argument("--summary", help="append the tables to this file too (GitHub step summary)")
    ap.add_argument("--min-precision", type=float, default=0.8)
    ap.add_argument("--min-labels", type=int, default=5)
    a = ap.parse_args(argv)
    work = Path(a.workdir)
    work.mkdir(parents=True, exist_ok=True)
    labels = load_labels()
    apps = [x for x in load_apps() if not a.only or x["name"] == a.only]
    guard = netguard.begin(allow=hosts(apps))
    done = []
    for app in apps:
        print(f"== {app['name']} ({app['platform']})", flush=True)
        row = analyse(app, work, a.budget_s)
        print(f"   {row.get('status')}, {len(row['findings'])} findings, {row.get('seconds', '?')} s", flush=True)
        done.append(row)
    attach_labels(done, labels)
    scored = score(done, labels)
    md = table(done, scored)
    print("\n" + md)
    head = (f"# Mobile findings benchmark\n\nLast run {time.strftime('%Y-%m-%d')}: {scored['total']['real']} real, "
            f"{scored['total']['false alarm']} false alarms, {scored['total']['cannot tell']} undecided, "
            f"{scored['total']['unlabelled']} not labelled yet"
            + (f"; precision {scored['total']['precision']:.0%} over the labelled findings" if scored['total']['precision'] is not None else "")
            + ".\nHow to label: `bench/mobile/README.md`.\n\n")
    if a.results:
        Path(a.results).write_text(head + md + "\n", encoding="utf-8")
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as fh:
            fh.write(head + md + "\n")
    if a.queue:
        Path(a.queue).write_text(json.dumps({"queue": scored["queue"], "stale_labels": scored["stale"]}, indent=1), encoding="utf-8")
        print(f"\n{len(scored['queue'])} findings to label -> {a.queue}" + (f"; {len(scored['stale'])} labels no longer match a finding" if scored["stale"] else ""))
    bad = [r for r, c in scored["rules"].items()
           if c["real"] + c["false alarm"] >= a.min_labels and c["precision"] is not None and c["precision"] < a.min_precision]
    failed = [d["name"] for d in done if d.get("status") != "ok"]
    if bad:
        print(f"\nPRECISION UNDER {a.min_precision:.0%}: {', '.join(bad)}")
    if failed:
        print(f"\nDID NOT FINISH: {', '.join(failed)}")
    refused = netguard.end(guard)                 # anything but the apps' own hosts was refused, and fails the run
    return 1 if bad or failed or refused else 0


if __name__ == "__main__":
    sys.exit(main())
