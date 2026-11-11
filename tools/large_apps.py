"""Run Lantern on big public apps and fail when one is too slow, crashes, or uses too much memory (test checklist 3.3).

    python tools/large_apps.py WORKDIR [--only NAME] [--budget-s 900] [--max-mb 4096] [--summary PATH]

Each app is cloned shallowly at a fixed tag, analysed offline at the structure privacy level (no source embedded),
and the wall-clock time, peak memory, size and result counts are written as a Markdown table (to --summary, which the
weekly GitHub Actions job points at its step summary). The run fails when any app takes longer than the budget, is
killed, exits with an error, or writes no report. Nothing here is a unit test: it needs the network and ten minutes,
so it runs on a schedule (.github/workflows/large-apps.yml), not on every push.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

APPS = [
    # name, git url, ref, language the check is mostly about
    ("django", "https://github.com/django/django", "5.1.3", "Python, ~400k lines"),
    ("excalidraw", "https://github.com/excalidraw/excalidraw", "v0.17.6", "TypeScript/React"),
    ("hugo", "https://github.com/gohugoio/hugo", "v0.139.0", "Go"),
    ("ripgrep", "https://github.com/BurntSushi/ripgrep", "14.1.1", "Rust"),
    ("spring-petclinic", "https://github.com/spring-projects/spring-petclinic", "main", "Java/Spring"),
    ("nowinandroid", "https://github.com/android/nowinandroid", "main", "Android, Kotlin, Compose"),
    ("ios-sample-flutter", "https://github.com/flutter/samples", "main", "Flutter/Dart (many apps in one repo)"),
    ("laravel", "https://github.com/laravel/framework", "v11.30.0", "PHP"),
    ("rails-sample", "https://github.com/gothinkster/rails-realworld-example-app", "master", "Ruby on Rails"),
    ("sqlite-cpp-httplib", "https://github.com/yhirose/cpp-httplib", "v0.18.1", "C++"),
]


def clone(url: str, ref: str, dest: Path) -> None:
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", ref, url, str(dest)], check=True,
                   timeout=900)                   # in the isolated run's environment: no sign-in, prompts off


# The analysis runs in a child that reports its own peak memory on its last line of stderr (ru_maxrss is KB on Linux).
CHILD = ("import atexit, resource, runpy, sys\n"
         "atexit.register(lambda: sys.stderr.write('PEAK_KB=%d\\n' % resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))\n"
         "sys.argv = ['lantern'] + sys.argv[1:]\n"
         "runpy.run_module('lantern.cli', run_name='__main__')\n")


def peak_mb(stderr: str) -> float | None:
    m = re.search(r"PEAK_KB=(\d+)", stderr)
    if not m:
        return None
    kb = int(m.group(1))
    return round(kb / (1024 * 1024) if sys.platform == "darwin" else kb / 1024)


def run_one(name: str, url: str, ref: str, work: Path, budget_s: int) -> dict:
    repo = work / name
    row: dict = {"name": name, "ref": ref}
    if not repo.exists():
        t = time.monotonic()
        try:
            clone(url, ref, repo)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            return row | {"status": f"clone failed: {type(exc).__name__}"}
        row["clone_s"] = round(time.monotonic() - t, 1)
    out = work / f"{name}.out"
    t = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, "-c", CHILD, "analyze", str(repo), "--out", str(out), "--offline",
                               "--privacy", "structure"], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=budget_s)
        row["seconds"] = round(time.monotonic() - t, 1)
        row["exit"] = proc.returncode
        row["tail"] = "\n".join(ln for ln in proc.stderr.strip().splitlines()[-4:] if not ln.startswith("PEAK_KB="))
    except subprocess.TimeoutExpired:
        return row | {"seconds": budget_s, "status": f"TOO SLOW: stopped after {budget_s} s"}
    row["peak_mb"] = peak_mb(proc.stderr)
    if proc.returncode != 0 or not (out / "report.html").is_file():
        return row | {"status": f"FAILED (exit {proc.returncode})"}
    g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    meta = g.get("meta", {})
    row.update({"status": "ok", "files": meta.get("files"), "lines": meta.get("lines"), "nodes": len(g.get("nodes", [])),
                "edges": len(g.get("edges", [])), "findings": len(sec.get("findings", [])), "grade": rd.get("grade"),
                "languages": meta.get("language"), "report_kb": (out / "report.html").stat().st_size // 1024})
    return row


def table(rows: list[dict]) -> str:
    head = "| app | ref | languages | files | lines | functions | edges | findings | grade | seconds | peak MB | report KB | status |"
    sep = "|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---|"
    lines = [head, sep]
    for r in rows:
        lines.append("| " + " | ".join(str(r.get(k, "")) for k in ("name", "ref", "languages", "files", "lines", "nodes", "edges",
                                                                  "findings", "grade", "seconds", "peak_mb", "report_kb", "status")) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("work")
    ap.add_argument("--only", help="one app by name")
    ap.add_argument("--budget-s", type=int, default=900, help="seconds each analysis may take (default 15 min)")
    ap.add_argument("--max-mb", type=int, default=4096, help="peak memory each analysis may use")
    ap.add_argument("--summary", help="write the Markdown table here too (CI: $GITHUB_STEP_SUMMARY)")
    a = ap.parse_args(argv)
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    # isolated (tools/netguard): temporary home, no keys, and only the hosts the apps are cloned from can be reached
    guard = netguard.begin(allow=sorted({urllib.parse.urlsplit(url).hostname for _n, url, _r, _w in APPS}))
    rows = []
    for name, url, ref, _what in APPS:
        if a.only and name != a.only:
            continue
        print(f"== {name} ({ref})", flush=True)
        r = run_one(name, url, ref, work, a.budget_s)
        if r.get("status") == "ok" and r.get("peak_mb", 0) > a.max_mb:
            r["status"] = f"TOO MUCH MEMORY: {r['peak_mb']} MB > {a.max_mb}"
        print(f"   {r.get('status')}  {r.get('seconds', '')} s  {r.get('tail', '')}", flush=True)
        rows.append(r)
    md = table(rows)
    print("\n" + md)
    (work / "large-apps.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    if a.summary:
        Path(a.summary).open("a", encoding="utf-8").write("## Large apps\n\n" + md + "\n")
    bad = [r for r in rows if r.get("status") != "ok"]
    for r in bad:
        print(f"FAIL {r['name']}: {r['status']}\n{r.get('tail', '')}", file=sys.stderr)
    refused = netguard.end(guard)
    return 1 if bad or refused else 0


if __name__ == "__main__":
    sys.exit(main())
