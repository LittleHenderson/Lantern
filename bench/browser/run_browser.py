"""Browser benchmark (a firm pass or fail, stage 5, step 5): every version of the sites of one part of
`bench/browser/` opened by `lantern browse`'s eight checks in a real browser, and each compared with what was written
down for it before the benchmark's first run (`bench/browser/README.md`).

    python bench/browser/run_browser.py WORKDIR [--part open|held-back] [--only NAME,NAME] [--jobs 3] [--runs 1]
                                        [--browser FULL PATH] [--results FILE] [--json FILE]

Each version is the family's safe site with its few exact edits (`define.files`), written into
WORKDIR/<part>/<version> and opened by `lantern.browse.run`, as `lantern browse` opens a project: an app in the sealed
box, plain pages served by Lantern's own code, the browser with its own sandbox, a door of Lantern's own as its only
way out. The record of each run is kept in WORKDIR/<part>/records/. `--part` is `open` unless it says otherwise: the
held-back part is run only when it is named, once at the end of stage 5 and again on the code of the release.
`--runs N` opens every version N times and says whether the runs agree. `--results` writes the tables as Markdown and
`--json` everything compared as JSON.

Every run is isolated (`tools/netguard`): a temporary home folder, none of your keys, and no address outside this
computer may be reached at all; what was tried is listed at the end and fails the run. The browser is not Python: on
Linux, `tools/netless.py --watch FILE -- python bench/browser/run_browser.py …` also writes down every address any
program of the run tried.

Result 0 when every version came out as written down and nothing outside this computer was tried; 1 when a version
did not, or something was; 2 when the definitions are at fault or an argument is; 3 when no browser is found or the
checks are not built for this system.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
sys.path.insert(0, str(HERE))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

import define  # noqa: E402  (bench/browser/define.py, the module each part's cases.py takes its names from)
from lantern import browse  # noqa: E402

PARTS = ("open", "held-back")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def part_of(part: str):
    """The families and versions of one part, as its `cases.py` writes them down."""
    if part not in PARTS:
        raise ValueError(f"no part {part!r}; the parts are {', '.join(PARTS)}")
    cases = _load("browser_cases_" + part.replace("-", "_"), HERE / part / "cases.py")
    return cases.FAMILIES, cases.VERSIONS


def definition_sha256(part: str, root: Path = HERE) -> str:
    """One fingerprint of what the part is: `define.py`, the part's `cases.py` and every file of its sites, by name
    and content (`root`: the benchmark's folder). A results file is compared with another only when the two name the
    same fingerprint."""
    h = hashlib.sha256()
    root = Path(root)
    files = [root / "define.py", root / part / "cases.py"]
    files += sorted(p for p in (root / part / "sites").rglob("*") if p.is_file())
    for p in files:
        name = p.relative_to(root).as_posix().encode("utf-8")
        data = p.read_bytes()
        h.update(len(name).to_bytes(4, "big") + name + len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


def _commit() -> str:
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                             encoding="utf-8", timeout=30).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (sha or "unknown") + (" with changes not committed" if dirty else "")


def run_one(work: Path, part: str, name: str, families: dict, versions: dict, browser: str | None,
            runs: int = 1) -> dict:
    """Write one version into `work/<part>/<name>`, open it `runs` times, and compare each run with what was written
    down for it (`define.compare`)."""
    v = versions[name]
    family = families[v.family]
    repo = define.build(HERE / part / "sites", v.family, v, Path(work) / part / name)
    keep = Path(work) / part / "records"
    keep.mkdir(parents=True, exist_ok=True)
    out: list[dict] = []
    t0 = time.monotonic()
    for i in range(runs):
        lines: list[str] = []
        record = browse.run(repo, browser=browser, log=lines.append)
        (keep / f"{name}-{i + 1}.json").write_text(json.dumps(record, indent=1, sort_keys=True), encoding="utf-8")
        compared = define.compare(family, v, record)
        compared["given"] = {c: list(x) for c, x in define.got(record).items()}
        compared["ran"], compared["why_not"] = bool(record.get("ran")), record.get("why_not")
        compared["browser_own"] = len(record.get("browser_own") or [])
        compared["asked_outside"] = len(record.get("asked_outside") or [])
        compared["seconds"] = record.get("seconds")
        compared["browser"] = record.get("browser") or {}
        if not record.get("ran"):
            compared["log"] = lines[-20:]
        out.append(compared)
    same = all(r["given"] == out[0]["given"] for r in out)
    return {"name": name, "family": v.family, "kind": v.kind, "what": v.what, "planted": [list(p) for p in v.planted],
            "beyond": v.beyond, "runs": out, "as_written": all(r["as_written"] for r in out), "same_each_run": same,
            "found": None if v.kind != "planted" else all(r["found"] for r in out),
            "seconds": round(time.monotonic() - t0, 1)}


def tally(rows: list[dict]) -> dict:
    """The counts the README defines, over every run of every version."""
    planted = [r for r in rows if r["kind"] == "planted"]
    clean = [r for r in rows if r["kind"] != "planted"]
    every = [(r["name"], x) for r in rows for x in r["runs"]]
    codes: dict[str, list[int]] = {}
    for r in planted:
        for _, code in r["planted"]:
            codes.setdefault(code, [0, 0])
            codes[code][0] += 1
            codes[code][1] += 1 if r["found"] else 0
    return {
        "versions": len(rows), "as_written": sum(1 for r in rows if r["as_written"]),
        "planted": len(planted), "found": sum(1 for r in planted if r["found"]),
        "clean": len(clean), "clean_as_written": sum(1 for r in clean if r["as_written"]),
        "false_alarms": [[n, *fa] for n, x in every for fa in x["false_alarms"]],
        "missed": [[n, *m] for n, x in every for m in x["missed"]],
        "outcomes": [[n, *o] for n, x in every for o in x["outcomes"]],
        "absent": [[n, *a] for n, x in every for a in x["absent"]],
        "not_run": [[n, x["why_not"]] for n, x in every if not x["ran"]],
        "differ_between_runs": [r["name"] for r in rows if not r["same_each_run"]],
        "browser_own": sum(x["browser_own"] for _, x in every),
        "asked_outside": sum(x["asked_outside"] for _, x in every),
        "codes": {c: {"planted": n, "found": f} for c, (n, f) in sorted(codes.items())},
    }


def _given(r: dict, family) -> str:
    """What the first run gave where it is not the family's safe outcome."""
    first = r["runs"][0]["given"]
    shown = [f"{c} {o}" + (f" ({', '.join(codes)})" if codes else "") for c, (o, codes) in first.items()
             if (o, list(codes)) != (family.safe[c], [])]
    return "; ".join(shown) or "as the safe site"


def table(rows: list[dict], t: dict, families: dict) -> str:
    out = []
    for fam in families.values():
        mine = [r for r in rows if r["family"] == fam.name]
        if not mine:
            continue
        out += [f"### {fam.name}: {fam.what}", "",
                "| Version | Kind | What it is | What the checks gave, where not as on the safe site | As written down |",
                "|---|---|---|---|---|"]
        for r in mine:
            diffs = sorted({d for x in r["runs"] for d in x["differences"]})
            verdict = "yes" if r["as_written"] else "NO: " + " / ".join(diffs)[:900]
            if not r["same_each_run"]:
                verdict += " (the runs did not agree)"
            what = r["what"].replace("|", "\\|")
            out.append(f"| `{r['name']}` | {r['kind']} | {what} | {_given(r, fam)} | {verdict} |")
        out.append("")
    out += ["### Each code", "", "| Code | Planted in | Found in |", "|---|---:|---:|"]
    out += [f"| `{c}` | {n['planted']} | {n['found']} |" for c, n in t["codes"].items()]
    out.append("")
    return "\n".join(out)


def summary(t: dict, runs: int) -> str:
    def listed(rows):
        return "; ".join(" ".join(str(x) for x in row) for row in rows[:12]) + (" …" if len(rows) > 12 else "")
    lines = [f"{t['versions']} versions, {t['as_written']} as written down, {t['versions'] - t['as_written']} not.",
             f"Planted problems found: {t['found']} of {t['planted']}. Safe sites and look-alikes as written down: "
             f"{t['clean_as_written']} of {t['clean']}.",
             f"False alarms (a code given that was not written down): {len(t['false_alarms'])}"
             + (f": {listed(t['false_alarms'])}" if t["false_alarms"] else "") + ".",
             f"Missed (a code written down and not given): {len(t['missed'])}"
             + (f": {listed(t['missed'])}" if t["missed"] else "") + ".",
             f"Another outcome with no code involved: {len(t['outcomes'])}"
             + (f": {listed(t['outcomes'])}" if t["outcomes"] else "") + ".",
             f"A row written down and not seen: {len(t['absent'])}"
             + (f": {listed(t['absent'])}" if t["absent"] else "") + ".",
             f"Runs that could not be made: {len(t['not_run'])}" + (f": {listed(t['not_run'])}" if t["not_run"] else "")
             + "."]
    if runs > 1:
        lines.append(f"Each version opened {runs} times; versions whose runs did not agree: "
                     f"{len(t['differ_between_runs'])}" + (f" ({', '.join(t['differ_between_runs'])})"
                                                           if t["differ_between_runs"] else "") + ".")
    lines.append(f"What the browser itself tried to reach, refused at Lantern's door: {t['browser_own']}. What the "
                 f"sites' pages asked of another computer, refused inside the browser: {t['asked_outside']}.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("work", help="a folder for the versions and their records (made if needed)")
    ap.add_argument("--part", default="open", choices=PARTS, help="which part (default: open)")
    ap.add_argument("--only", default="", help="comma-separated versions; default: every version of the part")
    ap.add_argument("--jobs", type=int, default=3, help="versions opened side by side")
    ap.add_argument("--runs", type=int, default=1, help="how many times each version is opened")
    ap.add_argument("--browser", default=None, help="the browser's full path (default: the one lantern browse finds)")
    ap.add_argument("--results", default="", help="write the tables here as Markdown")
    ap.add_argument("--json", default="", help="write everything compared here as JSON")
    a = ap.parse_args(argv)
    families, versions = part_of(a.part)
    faults = define.faults(families, versions)
    if faults:
        print("the definitions are at fault:\n  " + "\n  ".join(faults), file=sys.stderr)
        return 2
    only = [n for n in a.only.split(",") if n]
    unknown = [n for n in only if n not in versions]
    if unknown or a.runs < 1 or a.jobs < 1:
        print(f"unknown: {', '.join(unknown)}" if unknown else "--runs and --jobs are 1 or more", file=sys.stderr)
        return 2
    if not sys.platform.startswith(browse.BUILT_FOR):
        print(f"the browser checks are not built for this system ({sys.platform})", file=sys.stderr)
        return 3
    browser = a.browser or browse.find_browser()
    if not browser:
        print("no browser found: name one with --browser", file=sys.stderr)
        return 3
    names = only or list(versions)
    sha = definition_sha256(a.part)
    guard = netguard.begin()                      # isolated (tools/netguard); this benchmark needs no network at all
    t0 = time.monotonic()
    with ThreadPoolExecutor(a.jobs) as pool:
        rows = list(pool.map(lambda n: run_one(Path(a.work), a.part, n, families, versions, browser, a.runs), names))
    took = time.monotonic() - t0
    for r in rows:
        print(f"{r['name']:28} {'as written down' if r['as_written'] else 'DIFFERS':16} {r['seconds']} s")
        for line in sorted({d for x in r["runs"] for d in x["differences"]}):
            print("    " + line)
    t = tally(rows)
    said = summary(t, a.runs)
    print(said)
    tried = len(guard.since(0)) if guard is not None else None
    failed = netguard.end(guard)
    seen = next((x["browser"] for r in rows for x in r["runs"] if x["browser"].get("version")), {})
    head = (f"# Browser benchmark: the {a.part} part\n\n"
            f"`python bench/browser/run_browser.py WORKDIR --part {a.part}"
            + (f" --runs {a.runs}" if a.runs > 1 else "") + (f" --only {a.only}" if only else "") + "`, "
            f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime())} (UTC), Lantern {_commit()}, definition "
            f"`{sha[:16]}`, {seen.get('name') or 'browser'} {seen.get('version') or ''}".rstrip()
            + f", Python {sys.version.split()[0]} on {platform.system()}, {a.jobs} side by side, {took:.0f} s in all. "
            + ("The run was isolated by whoever started it. " if tried is None else
               f"What was tried outside this computer and refused by the run's guard: {tried}. ") + "\n\n")
    if a.results:
        Path(a.results).write_text(head + said + "\n\n" + table(rows, t, families), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps({"part": a.part, "definition_sha256": sha, "lantern": _commit(),
                                            "browser": seen, "python": sys.version.split()[0],
                                            "system": platform.system(), "runs": a.runs, "seconds": round(took, 1),
                                            "refused": tried, "tally": t, "versions": rows},
                                           indent=1, sort_keys=True), encoding="utf-8")
    return 1 if t["as_written"] != t["versions"] or failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
