"""Held-out benchmark: does Lantern find documented problems in apps it was never tuned on, stay quiet on their
safe twins, link the code, and refuse a green release to a vulnerable app?

    python bench/heldout/run_heldout.py WORKDIR [--offline] [--only NAME] [--out results.json] [--label LABEL]
    python bench/heldout/run_heldout.py WORKDIR --score-only     # score results already under WORKDIR/out

The run is isolated (tools/netguard): a temporary home folder, no keys or saved sign-ins, real model providers off, and
the network refused except for where the public apps are fetched from and, without --offline, the dependency audit's
addresses. What else was tried is listed at the end and fails the run. --score-only reaches nothing.

The case list (cases.json), the local apps (apps/*.tmpl) and the rules are frozen; `definition_sha256` in every
result says which definition produced it. Two results compare only when that hash is the same.

What is measured (raw counts, one definition each; see cases.json "rules"):
  * expected problems FOUND (any rank) and FOUND AT MEDIUM OR ABOVE, by class; MISSED by class (an expectation may
    name `rules`, a pattern the finding's rule id must match, where another kind of finding sits on the same lines)
  * safe twins: FALSE ALARMS at medium or above, by class; clean public apps: every medium-or-above finding outside
    tests, labelled through labels.json when a person has read it
  * SECURITY PATHS: expected problems whose finding has a `reachable` entry (a route or page leads to the line)
  * CALL SITES: Graph.call_sites() per app (resolved / inferred / possible / name-only / external / built-in /
    unresolved, one denominator) plus unresolved reasons
  * RELEASE: the decision per app (Blocked / Incomplete / Passed, `readiness.json` "release"); vulnerable apps given
    a green release (Passed); clean apps Blocked (the owner's rule of 2026-11-11: only Blocked counts as refused a
    green release). This benchmark never runs an app's own tests, so every app reads Incomplete at best: those are
    listed apart, each with what is missing, and the count used before the decision existed (anything but Passed)
    stays in the table
  * SCANNERS: each tool's recorded state per app, so a failed scanner is never hidden in a result
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

from lantern.depaudit import AUDIT_HOSTS  # noqa: E402

RANKS = ["critical", "high", "medium", "low"]
MEDIUM_UP = {"critical", "high", "medium"}


def definition_hash() -> str:
    h = hashlib.sha256()
    h.update((HERE / "cases.json").read_bytes())
    for p in sorted(x for x in (HERE / "apps").rglob("*") if x.is_file()):
        h.update(p.relative_to(HERE).as_posix().encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def decode_tmpl(rel: Path) -> Path:
    parts = [p[4:] if p.startswith("dot.") else p for p in rel.parts]
    parts[-1] = parts[-1].removesuffix(".tmpl")
    return Path(*parts)


def materialize(app: dict, dest: Path) -> Path:
    """Copy a local .tmpl app into dest with its real file names."""
    src = HERE / app["path"]
    if dest.exists():
        shutil.rmtree(dest)
    for p in sorted(src.rglob("*.tmpl")):
        target = dest / decode_tmpl(p.relative_to(src))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, target)
    return dest


def fetch(app: dict, dest: Path) -> Path:
    """Shallow-fetch exactly the pinned commit (the clone is untrusted data: nothing in it is run)."""
    if (dest / ".git").exists():
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head == app["commit"]:
            return dest
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", app["source"]],
                ["git", "fetch", "-q", "--depth", "1", "origin", app["commit"]], ["git", "checkout", "-q", "FETCH_HEAD"]):
        r = subprocess.run(cmd, cwd=dest, capture_output=True, text=True, env=env, timeout=600)
        if r.returncode != 0:
            raise RuntimeError(f"{app['name']}: {' '.join(cmd)} failed: {r.stderr[-300:]}")
    return dest


def analyze(src: Path, out: Path, offline: bool, budget: int = 900) -> dict:
    if out.exists():
        shutil.rmtree(out)
    # isolated mode (-I), started through the guard so the analysis has it too: -I alone would leave it out
    cmd = netguard.python_isolated("-m", "lantern.cli", "analyze", str(src), "--out", str(out))
    if offline:
        cmd.append("--offline")
    env = {k: v for k, v in os.environ.items() if not k.endswith("_API_KEY") and k not in ("LANTERN_TOKEN", "LANTERN_MODEL")}
    t = time.perf_counter()
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=budget, env=env, encoding="utf-8")
        rc, tail = r.returncode, (r.stdout + r.stderr)[-1500:]
    except subprocess.TimeoutExpired:
        rc, tail = -1, "timed out"
    return {"returncode": rc, "seconds": round(time.perf_counter() - t, 1), "tail": tail}


def load(out: Path, name: str):
    p = out / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def anchor_line(src: Path, exp: dict) -> int | None:
    p = src / exp["file"]
    if not p.is_file():
        return None
    rx = re.compile(exp["anchor"])
    n = int(exp.get("occurrence", 1))
    for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if rx.search(line):
            n -= 1
            if n == 0:
                return i
    return None


def near(f: dict, exp: dict, line: int) -> bool:
    if f.get("in_tests"):
        return False
    if exp.get("rules") and not re.search(exp["rules"], str(f.get("rule") or "")):   # e.g. an authorization expectation
        return False
    if (f.get("file") or "").replace("\\", "/") != exp["file"]:
        return False
    if exp.get("file_level"):
        return True
    fl = f.get("line")
    return isinstance(fl, int) and abs(fl - line) <= int(exp.get("window", 2))


def best(fs: list[dict]) -> dict | None:
    return min(fs, key=lambda f: RANKS.index(f.get("rank", "low"))) if fs else None


def release_of(rd: dict | None, live: list[dict]) -> dict:
    """The release decision as Lantern states it; before a gate exists, the badge rule (no critical or high)."""
    gate = (rd or {}).get("release")
    if isinstance(gate, dict) and gate.get("decision"):
        crit = [c for c in gate.get("criteria") or [] if isinstance(c, dict) and c.get("required") is not False]
        held = {state: [str(c.get("id")) for c in crit if c.get("state") == state] for state in ("failed", "missing")}
        return {"decision": gate["decision"], "basis": "readiness.json release gate",
                "blocking": held["failed"], "missing": held["missing"],
                "why": {str(c.get("id")): str(c.get("why") or "")[:400] for c in crit
                        if c.get("state") in ("failed", "missing")}}
    bad = [f for f in live if f.get("rank") in ("critical", "high")]
    return {"decision": "Passed" if not bad else "Blocked", "basis": "badge rule: no critical or high outside tests",
            "blocking": ["findings"] if bad else [], "missing": [], "why": {}}


def score_app(app: dict, src: Path, out: Path, labels: dict) -> dict:
    sec, rd, graph = load(out, "security.json"), load(out, "readiness.json"), load(out, "graph.json")
    res: dict = {"name": app["name"], "kind": app["kind"], "stack": app.get("stack"), "complete": bool(sec and rd and graph)}
    if not res["complete"]:
        res["error"] = "results missing"
        return res
    fs = sec.get("findings", [])
    live = [f for f in fs if not f.get("in_tests")]
    res["findings"] = {"all": len(fs), "outside_tests": len(live),
                       "by_rank": {r: sum(1 for f in live if f.get("rank") == r) for r in RANKS}}
    res["scanners"] = [{"tool": t.get("tool"), "status": t.get("status"), "state": t.get("state")} for t in sec.get("tools", [])]
    res["readiness"] = {"score": rd.get("score"), "grade": rd.get("grade"), "shape": rd.get("shape")}
    res["release"] = release_of(rd, live)
    from lantern.graph import Graph
    g = Graph.load(out / "graph.json")
    cs = g.call_sites()
    res["call_sites"] = cs
    res["graph"] = {"files": g.meta.get("files"), "functions": g.stats()["nodes"].get("callable", 0),
                    "internal_edges": g.stats()["internal_call_edges"], "entry_points": g.stats()["entry_points"]}
    prot = {x.get("id"): x.get("status") for x in rd.get("protections") or [] if isinstance(x, dict)}
    rows = []
    for exp in app.get("expect", []):
        row = {"id": exp["id"], "class": exp["class"], "want": exp["want"]}
        want = exp["want"]
        if want in ("finding", "clean", "reachable"):
            line = anchor_line(src, exp)
            row["line"] = line
            if line is None:
                row["status"] = "anchor-missing"
            else:
                hits = [f for f in fs if near(f, exp, line)]
                b = best(hits)
                row["found"] = bool(b)
                row["rank"] = b.get("rank") if b else None
                row["rule"] = b.get("rule") if b else None
                row["reachable"] = bool(b.get("reachable")) if b else False
                if want == "finding":
                    need = exp.get("min_rank")
                    ok_rank = bool(b) and (RANKS.index(b["rank"]) <= RANKS.index(need) if need else b["rank"] in MEDIUM_UP)
                    row["status"] = "found" if ok_rank else ("found-low" if b else "missed")
                elif want == "clean":
                    loud = [f for f in hits if f.get("rank") in MEDIUM_UP]
                    row["status"] = "false-alarm" if loud else "clean"
                    row["rank"] = best(loud)["rank"] if loud else None
                else:   # reachable
                    row["status"] = "covered" if (b and b.get("reachable")) else ("found-no-path" if b else "missed")
        elif want in ("edge", "no-edge"):
            has = any(e.src == exp["src"] and e.dst == exp["dst"] for e in g.call_edges())
            row["status"] = ("found" if has else "missed") if want == "edge" else ("false-link" if has else "clean")
        elif want == "linked":
            nodes = [n for n in g.nodes.values() if n.kind == "callable" and (n.file or "").replace("\\", "/") == exp["file"]
                     and (n.name == exp["name"] or n.name.endswith("." + exp["name"]) or n.id.endswith("::" + exp["name"]))]
            incoming = [e for e in g.call_edges() if any(e.dst == n.id for n in nodes)]
            row["nodes"] = [n.id for n in nodes]
            row["status"] = "found" if incoming else ("node-only" if nodes else "missed")
        elif want == "protection":
            st = prot.get(exp["protection"])
            row["protection_status"] = st
            if "is" in exp:
                row["status"] = "found" if st == exp["is"] else "missed"
            else:
                row["status"] = "found" if (st is not None and st != exp["not"]) else "missed"
        rows.append(row)
    res["expectations"] = rows
    if app["kind"] == "clean":
        lab = labels.get(app["name"], {})
        loud = []
        for f in live:
            if f.get("rank") in MEDIUM_UP:
                key = f"{f.get('rule')}@{f.get('file')}:{f.get('line')}"
                loud.append({"rule": f.get("rule"), "rank": f.get("rank"), "file": f.get("file"), "line": f.get("line"),
                             "label": lab.get(key, {}).get("label", "unlabelled"), "why": lab.get(key, {}).get("why")})
        res["loud_findings"] = loud
    return res


def summarize(apps: list[dict]) -> dict:
    def count(kind, pred):
        return sum(1 for a in apps if a.get("complete") and a["kind"] == kind for r in a["expectations"] if pred(r))
    by_class: dict[str, dict] = {}
    for a in apps:
        for r in a.get("expectations", []):
            if r["want"] == "finding":
                c = by_class.setdefault(r["class"], {"expected": 0, "found": 0, "found_low": 0, "missed": 0})
                c["expected"] += 1
                c["found" if r["status"] == "found" else "found_low" if r["status"] == "found-low" else "missed"] += 1
    fa_class: dict[str, int] = {}
    for a in apps:
        for r in a.get("expectations", []):
            if r["want"] == "clean" and r["status"] == "false-alarm":
                fa_class[r["class"]] = fa_class.get(r["class"], 0) + 1
    paths_total = sum(1 for a in apps for r in a.get("expectations", []) if r["want"] == "finding" and r.get("found"))
    paths_cov = sum(1 for a in apps for r in a.get("expectations", []) if r["want"] == "finding" and r.get("found") and r.get("reachable"))
    cs_total: dict[str, int] = {}
    for a in apps:
        for k, v in (a.get("call_sites") or {}).items():
            if isinstance(v, int):
                cs_total[k] = cs_total.get(k, 0) + v
    vuln = [a for a in apps if a.get("complete") and a["kind"] == "vulnerable"]
    green = [a["name"] for a in vuln if a["release"]["decision"] == "Passed"]
    clean = [a for a in apps if a.get("complete") and a["kind"] == "clean"]
    loud = sum(len(a.get("loud_findings", [])) for a in clean)
    loud_false = sum(1 for a in clean for x in a.get("loud_findings", []) if x["label"] == "false alarm")
    return {
        "expected_problems": sum(c["expected"] for c in by_class.values()),
        "found_medium_or_above": sum(c["found"] for c in by_class.values()),
        "found_only_low": sum(c["found_low"] for c in by_class.values()),
        "missed": sum(c["missed"] for c in by_class.values()),
        "by_class": by_class,
        "safe_twin_anchors": count("clean", lambda r: r["want"] == "clean"),
        "false_alarms_on_safe_twins": sum(fa_class.values()),
        "false_alarms_by_class": fa_class,
        "false_links": count("clean", lambda r: r["status"] == "false-link"),
        "resolution_checks": {"expected": sum(1 for a in apps for r in a.get("expectations", []) if r["want"] in ("edge", "linked")),
                              "found": sum(1 for a in apps for r in a.get("expectations", []) if r["want"] in ("edge", "linked") and r["status"] == "found")},
        "protection_checks": {"expected": sum(1 for a in apps for r in a.get("expectations", []) if r["want"] == "protection"),
                              "found": sum(1 for a in apps for r in a.get("expectations", []) if r["want"] == "protection" and r["status"] == "found")},
        "security_paths": {"found_problems": paths_total, "with_a_mapped_path": paths_cov,
                           "explicit_checks": sum(1 for a in apps for r in a.get("expectations", []) if r["want"] == "reachable"),
                           "explicit_covered": sum(1 for a in apps for r in a.get("expectations", []) if r["want"] == "reachable" and r["status"] == "covered")},
        "call_sites_total": cs_total,
        "vulnerable_apps": len(vuln), "vulnerable_apps_given_green": green,
        "vulnerable_apps_blocked": [a["name"] for a in vuln if a["release"]["decision"] == "Blocked"],
        "vulnerable_apps_incomplete": [a["name"] for a in vuln if a["release"]["decision"] == "Incomplete"],
        # Only Blocked counts as refused a green release (the owner's rule). Incomplete is listed apart with what is
        # missing; `clean_apps_not_passed` is what results before the decision called `clean_apps_blocked`.
        "clean_apps": len(clean),
        "clean_apps_refused": [a["name"] for a in clean if a["release"]["decision"] == "Blocked"],
        "clean_apps_incomplete": [{"name": a["name"], "missing": a["release"].get("missing") or []}
                                  for a in clean if a["release"]["decision"] == "Incomplete"],
        "clean_apps_not_passed": [a["name"] for a in clean if a["release"]["decision"] != "Passed"],
        "loud_findings_on_clean_apps": loud, "of_which_labelled_false_alarm": loud_false,
        "anchor_missing": sum(1 for a in apps for r in a.get("expectations", []) if r.get("status") == "anchor-missing"),
        "incomplete_apps": [a["name"] for a in apps if not a.get("complete")],
    }


def of(name: str, names: list[str] | None, total: int) -> str:
    """One table row: how many of the apps, and which. "not counted" for a result that was written before the count
    existed."""
    if names is None:
        return f"| {name} | not counted in this result |"
    return f"| {name} | {len(names)} / {total} ({', '.join(names) or 'none'}) |"


def held_back(rel: dict) -> str | None:
    """What a decision that is not Passed is held back by, in one line: each criterion with Lantern's own reason."""
    why = rel.get("why") or {}
    parts = []
    for word, key in (("failed", "blocking"), ("missing", "missing")):
        ids = rel.get(key) or []
        if ids:
            parts.append(f"{word}: " + "; ".join(f"{i} ({why[i]})" if why.get(i) else str(i) for i in ids))
    return f"- release {rel['decision']} · " + " · ".join(parts) if parts else None


def markdown(result: dict) -> str:
    s = result["summary"]
    L = [f"# Held-out benchmark · {result['label']}", "",
         f"Engine {result['engine']} · definition {result['definition_sha256'][:12]} · {result['ran_at']} · "
         f"{'offline (no dependency audits)' if result['offline'] else 'online'}", "",
         "| Measure | Count |", "|---|---:|",
         f"| Documented problems expected | {s['expected_problems']} |",
         f"| Found at medium or above | {s['found_medium_or_above']} |",
         f"| Found only as low | {s['found_only_low']} |",
         f"| Missed | {s['missed']} |",
         f"| Safe-twin anchors checked | {s['safe_twin_anchors']} |",
         f"| False alarms on safe twins (medium+) | {s['false_alarms_on_safe_twins']} |",
         f"| False links on safe twins | {s['false_links']} |",
         f"| Resolution checks passed | {s['resolution_checks']['found']} / {s['resolution_checks']['expected']} |",
         f"| Protection checks passed | {s['protection_checks']['found']} / {s['protection_checks']['expected']} |",
         f"| Found problems with a mapped path | {s['security_paths']['with_a_mapped_path']} / {s['security_paths']['found_problems']} |",
         of("Vulnerable apps given a green release (Passed)", s["vulnerable_apps_given_green"], s["vulnerable_apps"]),
         of("Vulnerable apps Blocked", s.get("vulnerable_apps_blocked"), s["vulnerable_apps"]),
         of("Vulnerable apps Incomplete, not Blocked", s.get("vulnerable_apps_incomplete"), s["vulnerable_apps"]),
         of("Clean apps Blocked (refused a green release)", s.get("clean_apps_refused"), s["clean_apps"]),
         of("Clean apps Incomplete (not refused: evidence is missing)",
            [a["name"] for a in s["clean_apps_incomplete"]] if "clean_apps_incomplete" in s else None, s["clean_apps"]),
         # a result written before the release decision has the one count, under its older name
         of("Clean apps not Passed (the count before the release decision)",
            s.get("clean_apps_not_passed", s.get("clean_apps_blocked")), s["clean_apps"]),
         f"| Medium+ findings on clean apps (public and twins) | {s['loud_findings_on_clean_apps']} (labelled false alarm: {s['of_which_labelled_false_alarm']}) |",
         f"| Anchors not found in the pinned code | {s['anchor_missing']} |", "",
         "## By class (documented problems)", "", "| Class | Expected | Found medium+ | Found low | Missed |", "|---|---:|---:|---:|---:|"]
    for c, v in sorted(s["by_class"].items()):
        L.append(f"| {c} | {v['expected']} | {v['found']} | {v['found_low']} | {v['missed']} |")
    L += ["", "## Call sites (one denominator per app)", "",
          "| App | Total | Resolved | Likely | Possible | Name only | External | Built-in | Unresolved |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for a in result["apps"]:
        c = a.get("call_sites") or {}
        if c:
            L.append(f"| {a['name']} | {c.get('total', 0)} | {c.get('resolved_internal', 0)} | {c.get('inferred_internal', 0)} | "
                     f"{c.get('several_possible_targets', 0)} | {c.get('name_only_guess', 0)} | {c.get('known_external', 0)} | "
                     f"{c.get('builtin', 0)} | {c.get('unresolved', 0)} |")
    L += ["", "## Per app", ""]
    for a in result["apps"]:
        if not a.get("complete"):
            L.append(f"### {a['name']} · INCOMPLETE ({a.get('error')})")
            continue
        r = a["readiness"]
        L.append(f"### {a['name']} ({a['kind']}, {a.get('stack')}) · {a['findings']['by_rank']} · score {r['score']} {r['grade']} · "
                 f"release {a['release']['decision']}")
        L.append("")
        if held_back(a["release"]):
            L.append(held_back(a["release"]))
        for e in a["expectations"]:
            extra = f" ({e.get('rule')}, {e.get('rank')}{', path' if e.get('reachable') else ''})" if e.get("found") else ""
            if e["want"] == "protection":
                extra = f" ({e.get('protection_status')})"
            L.append(f"- {e['id']} · {e['class']} · **{e['status']}**{extra}")
        for x in a.get("loud_findings", []):
            L.append(f"- loud: {x['rule']} {x['rank']} {x['file']}:{x['line']} · {x['label']}" + (f" · {x['why']}" if x.get("why") else ""))
        sc = ", ".join(f"{t['tool']}: {t.get('state') or t.get('status')}" for t in a["scanners"])
        L.append(f"- scanners: {sc}")
        L.append("")
    return "\n".join(L)


def hosts(apps: list[dict], offline: bool, score_only: bool) -> list[str]:
    """Everything this run may reach: where its public apps are fetched from and, unless --offline, the dependency
    audit's addresses. Scoring results that are already there reaches nothing."""
    if score_only:
        return []
    fetched = {urllib.parse.urlsplit(app["source"]).hostname for app in apps if "path" not in app}
    return sorted({*fetched, *(() if offline else AUDIT_HOSTS)} - {None})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("workdir")
    ap.add_argument("--offline", action="store_true", help="skip dependency audits (pip-audit, npm audit, OSV)")
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--out", help="write results JSON here (default WORKDIR/heldout_results.json)")
    ap.add_argument("--label", default="run")
    ap.add_argument("--score-only", action="store_true", help="score results already under WORKDIR/out")
    ap.add_argument("--budget", type=int, default=900, help="seconds per app")
    a = ap.parse_args(argv)
    work = Path(a.workdir).resolve()
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "out").mkdir(parents=True, exist_ok=True)
    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))
    chosen = [app for app in cases["apps"] + cases["local"] if not a.only or app["name"] in a.only]
    guard = netguard.begin(allow=hosts(chosen, a.offline, a.score_only))
    labels_p = HERE / "labels.json"
    labels = json.loads(labels_p.read_text(encoding="utf-8")) if labels_p.exists() else {}
    engine = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or "?"
    results = []
    for app in chosen:
        src, out = work / "src" / app["name"], work / "out" / app["name"]
        run_info = None
        if not a.score_only:
            src = materialize(app, src) if "path" in app else fetch(app, src)
            print(f"== {app['name']}", flush=True)
            run_info = analyze(src, out, a.offline, a.budget)
            print(f"   analyze exit {run_info['returncode']} in {run_info['seconds']}s", flush=True)
        r = score_app(app, src, out, labels)
        if run_info:
            r["run"] = run_info
        results.append(r)
    result = {"label": a.label, "engine": engine, "definition_sha256": definition_hash(), "offline": a.offline,
              "ran_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "apps": results, "summary": summarize(results)}
    out_p = Path(a.out) if a.out else work / "heldout_results.json"
    out_p.write_text(json.dumps(result, indent=1), encoding="utf-8")
    out_p.with_suffix(".md").write_text(markdown(result), encoding="utf-8")
    print(markdown(result))
    print(f"\nwrote {out_p} and {out_p.with_suffix('.md')}")
    return netguard.end(guard)                    # anything but the declared hosts was refused, and fails the run


if __name__ == "__main__":
    sys.exit(main())
