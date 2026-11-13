"""Speed and memory of `lantern analyze` on the same small, medium and large projects (directive point 10).

    python bench/speed.py WORKDIR [--only shop,django] [--runs 3] [--engine CHECKOUT] [--json FILE] [--results FILE]
                                  [--browser] [--compare EARLIER.json] [--must-match]

What is measured, each project alone with nothing else running, in a new process every time:

* **first run**: no results folder and nothing Lantern kept from an earlier run (`LANTERN_HOME` is a folder of this
  benchmark's own and is emptied). The operating system's own file cache is warm in every run, first or not.
* **repeat run**: the same command again, with the results and whatever Lantern kept from the first run in place.
* wall-clock seconds, processor seconds of the analysis and every program it started, peak memory of the analysis
  process (its own high-water mark) and of all its processes together (sampled ten times a second; Linux only),
  the size of the report and of the whole results folder, and where the time went (start-up, map, scan, readiness,
  report, evidence), read from the moments the command's own lines arrive.
* **the same results**: a repeat run that used what Lantern kept and a repeat run with that switched off
  (`LANTERN_CACHE=off`) must write the same result files, and so must a first run on kept work and the first run
  that had none. Compared byte for byte: `graph.json`, `calls.json`; the other result files without what a clock
  put into them and nothing else (`still`): how long each tool and each step took (`security.json`,
  `readiness.json`, `run.json`, `report.html`), and the minute or the day the run was made (`run.json`,
  `report.html`, `evidence.json`, `evidence.html`, the badge, and the day `baseline.json` begins with). A
  difference fails the benchmark. The report is compared a second way, by what is in it: its data read back out
  of the page, the map as rows again (`report.html: its data`), which is what is compared with another engine's
  report.
* with `--browser`: how long the report takes to open and to answer three clicks on a slowed phone
  (`tools/report_perf.js`; needs Node with Playwright).

`--engine CHECKOUT` measures another checkout's `lantern` with this file, on the same clones, so a before and an
after are measured the same way; `--compare EARLIER.json` prints the two side by side and says for every project
whether the results are the same as the earlier engine's (`--must-match`: fail when they are not). The projects are
cloned at fixed tags; a run is compared with an earlier one only where both read the same commit.

Not a unit test: it needs the network for the first clone (github.com only, through tools/netguard) and about half
an hour for the whole set.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

sys.path.insert(0, str(ROOT))        # this checkout's `lantern`, for the one reader used here (`read_commit`)

# name, size, git url (None: a folder of this checkout), tag, what it is. Fixed tags, so a later run reads the same code.
PROJECTS = [
    ("shop", "small", None, "tests/fixtures/shop", "Lantern's own sample: React + FastAPI, 12 files"),
    ("ripgrep", "small", "https://github.com/BurntSushi/ripgrep", "14.1.1", "Rust, about 50,000 lines"),
    ("excalidraw", "medium", "https://github.com/excalidraw/excalidraw", "v0.17.6", "TypeScript and React, about 87,000 lines"),
    ("hugo", "medium", "https://github.com/gohugoio/hugo", "v0.139.0", "Go, about 195,000 lines"),
    ("django", "large", "https://github.com/django/django", "5.1.3", "Python, about 481,000 lines"),
    ("laravel", "large", "https://github.com/laravel/framework", "v11.30.0", "PHP, about 416,000 lines"),
]

# The analysis runs in a child that says its own peak memory on its last line of stderr. On Linux that is the
# process's own high-water mark (VmHWM), which starts anew when the program starts: `ru_maxrss` does not, it keeps
# the size of the program that started this one, so a measuring program that has grown gives every child its size.
CHILD = r"""
import atexit, runpy, sys
def _peak():
    kb = 0
    try:
        with open('/proc/self/status', encoding='ascii') as f:
            for line in f:
                if line.startswith('VmHWM:'):
                    kb = int(line.split()[1])
    except OSError:
        pass
    if not kb:
        try:
            import resource
            kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            kb = kb // 1024 if sys.platform == 'darwin' else kb
        except ImportError:
            kb = 0
    sys.stderr.write('PEAK_KB=%d\n' % kb)
atexit.register(_peak)
sys.argv = ['lantern'] + sys.argv[1:]
runpy.run_module('lantern.cli', run_name='__main__')
"""

BYTE_FOR_BYTE = ("graph.json", "calls.json")
# baseline.json begins with the day the first analysis was made (`evidence.baseline_from`), and that day is all a
# clock puts into it. Until 2026-11-12 the file was compared byte for byte: a comparison whose one side ran at
# 23:59 and whose other side ran after midnight said "different" for the two projects in between, and nothing
# but the day differed. Only that day is taken out, where the file starts with it written as a day.
WITHOUT_ITS_DAY = ("baseline.json",)
FIRST_DAY = re.compile(r'\A(\{\s*"date":\s*")[0-9]{4}-[0-9]{2}-[0-9]{2}(")')
# readiness.json repeats the record of a scanner that did not finish or did not cover everything, with how long that
# scanner took (`incomplete[i].duration_ms`); nothing else in it is a clock's. The first measurement of Django showed
# it: 34739 in one run, 32368 in the next, and not one other difference.
WITHOUT_TOOL_TIME = ("readiness.json",)
WITHOUT_CLOCK = ("security.json", "report.html", "evidence.json", "evidence.html", "badge.svg")
# The report is one page: the template of the engine that made it, and the data. Another engine's template may differ
# (so `report.html` itself is compared only among runs of one engine); the data may not. `REPORT_DATA` is the mark of
# what a reader gets back out of the page, with the map as rows again however the page holds it (`report_data`).
REPORT_DATA = "report.html: its data"
DATA_OPEN = '<script type="application/json" id="lantern-data">'
# what another engine must write the same way (the evidence names the engine that made it, so it is left out)
ACROSS_ENGINES = ("graph.json", "calls.json", "security.json", "readiness.json", "baseline.json", "badge.svg", REPORT_DATA)
PHASES = ("start-up", "map", "scan", "readiness", "report", "evidence")
# what a clock put into a result file: how long the run's steps took, and how long each tool took
SHOWN_TIMINGS = re.compile(r'"timings":\s*\{[^{}]*\}')
TOOL_TIME = re.compile(r'"duration_ms":\s*[0-9.]+')
MADE_AT = re.compile(r'"generated_at":\s*"[^"]*"')
SECONDS = re.compile(r"\(([0-9.]+)s\)\s*$")


# ----------------------------------------------------------------------------- the same results
def made_at(out: Path) -> str:
    """The minute the evidence of a run says it was made (`2026-11-12 19:52 UTC`), or nothing."""
    try:
        header = json.loads((out / "evidence.json").read_text(encoding="utf-8")).get("header")
        when = header.get("generated_at") if isinstance(header, dict) else ""
    except (OSError, ValueError, AttributeError):
        return ""
    return when if isinstance(when, str) else ""


def still(text: str, when: str = "") -> str:
    """A result file's text without what a clock put into it: how long the steps and each tool took, the minute the
    run was made as the files write it, and, where `when` is that minute as the evidence says it, the same minute
    and its day as the Evidence page and the badge print them. Nothing else is taken out."""
    text = SHOWN_TIMINGS.sub('"timings":{}', text)
    text = TOOL_TIME.sub('"duration_ms":0', text)
    text = MADE_AT.sub('"generated_at":""', text)
    if len(when) >= 10:
        text = text.replace(when, "").replace(f"· {when[:10]}</span>", "· </span>")
        try:
            y, m, d = (int(x) for x in when[:10].split("-"))
            text = text.replace("· " + time.strftime("%b", (y, m, d, 0, 0, 0, 0, 1, 0)) + f" {d}", "· DAY")
        except ValueError:
            pass
    return text


def report_data(page: str):
    """What a report holds, read back out of the page: its data block, with the map as rows again when the page
    holds it column by column (`lantern/columns.py` of this checkout; a map written as rows is handed back as it
    is, so a report of an engine that does not pack is read the same way). None when the page has no data block;
    ValueError when the data is not JSON or the map is packed in a way this checkout does not write."""
    from lantern import columns
    i = page.find(DATA_OPEN)
    j = page.find("</script>", i)
    if i < 0 or j < 0:
        return None
    data = json.loads(page[i + len(DATA_OPEN):j])
    if isinstance(data, dict) and "graph" in data:
        data["graph"] = columns.unpack_graph(data["graph"])
    return data


def fingerprint(out: Path) -> dict:
    """One SHA-256 for each result file of a run, of what has to be the same in two runs on the same input: the
    files of `BYTE_FOR_BYTE` as they are, `baseline.json` without the day it was made and nothing else taken out
    (`WITHOUT_ITS_DAY`), those of `WITHOUT_TOOL_TIME` without how long a tool took and nothing else taken out, the
    files of `WITHOUT_CLOCK` without what a clock put into them (`still`), `run.json` without its timings and
    clock time, and `REPORT_DATA`: everything the report holds, in the order it holds it, without what a clock put
    into it. A file that is not there has no entry."""
    marks = {}
    for name in BYTE_FOR_BYTE:
        p = out / name
        if p.is_file():
            marks[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    for name in WITHOUT_ITS_DAY:        # a file that does not start with its day has the mark its bytes have
        p = out / name
        if p.is_file():
            text = p.read_bytes().decode("utf-8", errors="surrogateescape")
            marks[name] = hashlib.sha256(FIRST_DAY.sub(r"\1\2", text)
                                         .encode("utf-8", errors="surrogateescape")).hexdigest()
    for name in WITHOUT_TOOL_TIME:      # a file with no tool time in it has the mark its bytes have
        p = out / name
        if p.is_file():
            text = p.read_bytes().decode("utf-8", errors="surrogateescape")
            marks[name] = hashlib.sha256(TOOL_TIME.sub('"duration_ms":0', text)
                                         .encode("utf-8", errors="surrogateescape")).hexdigest()
    p = out / "run.json"
    if p.is_file():
        run = json.loads(p.read_text(encoding="utf-8"))
        for moving in ("timings", "finished_at", "kept"):      # `kept`: how much of the work was reused, not a result
            run.pop(moving, None)
        marks["run.json"] = hashlib.sha256(json.dumps(run, sort_keys=True).encode("utf-8")).hexdigest()
    when = made_at(out)
    for name in WITHOUT_CLOCK:
        p = out / name
        if p.is_file():
            marks[name] = hashlib.sha256(still(p.read_text(encoding="utf-8"), when).encode("utf-8")).hexdigest()
    p = out / "report.html"
    if p.is_file():
        try:
            data = report_data(p.read_text(encoding="utf-8"))
        except ValueError as exc:
            data, marks[REPORT_DATA] = None, f"not read: {exc}"[:200]
        if data is not None:        # the keys in the order written: the same data in another order is not the same
            text = still(json.dumps(data, separators=(",", ":")), when)
            marks[REPORT_DATA] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return marks


def differing(a: dict, b: dict, names=None) -> list[str]:
    """The result files that two runs did not write the same way (or that only one of them wrote)."""
    return sorted(n for n in (names or sorted(set(a) | set(b))) if a.get(n) != b.get(n))


# ----------------------------------------------------------------------------- one run
def phases(lines: list[tuple[float, str]], wall: float) -> dict:
    """Where the time of one run went, from when each of the command's lines arrived (`lines`: seconds since the
    start, the line). The map and the scan say their own seconds at the end of their lines; start-up is what passed
    before the map began (loading Lantern, looking at the folder)."""
    at = {}
    own = {}
    for t, line in lines:
        word = line.split(None, 1)[0] if line.strip() else ""
        if word in ("graph", "scan", "ready", "report", "proof") and word not in at:
            at[word] = t
            m = SECONDS.search(line)
            if m:
                own[word] = float(m.group(1))
    if "graph" not in at or "proof" not in at:
        return {}
    spent = {"map": own.get("graph", 0.0)}
    spent["start-up"] = max(0.0, at["graph"] - spent["map"])
    spent["scan"] = own.get("scan", max(0.0, at.get("scan", at["graph"]) - at["graph"]))
    done = at.get("scan", at["graph"])
    spent["readiness"] = max(0.0, at.get("ready", done) - done)
    spent["report"] = max(0.0, at.get("report", at.get("ready", done)) - at.get("ready", done))
    spent["evidence"] = max(0.0, wall - at.get("report", at["proof"]))
    return {k: round(spent[k], 2) for k in PHASES}


def _tree(pid: int) -> list[int]:
    """The process and everything beneath it (Linux: read from /proc)."""
    kids: dict[int, list[int]] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return [pid]
    for d in names:
        if d.isdigit():
            try:
                with open(f"/proc/{d}/stat", "rb") as f:
                    rest = f.read().rsplit(b")", 1)[1].split()
                kids.setdefault(int(rest[1]), []).append(int(d))
            except (OSError, IndexError, ValueError):
                continue
    found, todo = [], [pid]
    while todo:
        p = todo.pop()
        found.append(p)
        todo += kids.get(p, [])
    return found


def _resident_kb(pid: int) -> int:
    """What a process holds in memory: its share of every page (Pss), so pages two processes share are not counted
    twice; where the kernel does not say that, its resident size."""
    for name, key in (("smaps_rollup", b"Pss:"), ("status", b"VmRSS:")):
        try:
            with open(f"/proc/{pid}/{name}", "rb") as f:
                for line in f:
                    if line.startswith(key):
                        return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            continue
    return 0


class Watch(threading.Thread):
    """Samples the memory of a process and everything it started, ten times a second, and keeps the largest sum."""

    def __init__(self, pid: int):
        super().__init__(daemon=True)
        self.pid, self.peak_kb, self.stop = pid, 0, threading.Event()

    def run(self) -> None:
        if not sys.platform.startswith("linux"):
            return
        while not self.stop.is_set():
            self.peak_kb = max(self.peak_kb, sum(_resident_kb(p) for p in _tree(self.pid)))
            self.stop.wait(0.1)


def _cpu() -> float:
    try:
        import resource
    except ImportError:          # Windows: not measured
        return 0.0
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def run_once(engine: Path, repo: Path, out: Path, home: Path, seconds: int, cache: bool = True) -> dict:
    """One `lantern analyze REPO --out OUT --offline` in a process of its own, measured."""
    env = dict(os.environ, LANTERN_HOME=str(home), PYTHONUNBUFFERED="1")
    env.pop("LANTERN_CACHE", None)
    if not cache:
        env["LANTERN_CACHE"] = "off"
    home.mkdir(parents=True, exist_ok=True)
    err = out.with_name(out.name + ".stderr")
    cpu0, t0 = _cpu(), time.perf_counter()
    lines: list[tuple[float, str]] = []
    with open(err, "w", encoding="utf-8") as errors:
        proc = subprocess.Popen([sys.executable, "-c", CHILD, "analyze", str(repo), "--out", str(out), "--offline"],
                                cwd=str(engine), env=env, stdout=subprocess.PIPE, stderr=errors, text=True,
                                encoding="utf-8", errors="replace")
        watch = Watch(proc.pid)
        watch.start()
        killer = threading.Timer(seconds, proc.kill)
        killer.start()
        try:
            for line in proc.stdout:
                lines.append((time.perf_counter() - t0, line.rstrip("\n")))
            code = proc.wait()
        finally:
            killer.cancel()
            watch.stop.set()
            watch.join(2)
    wall = time.perf_counter() - t0
    said = err.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"PEAK_KB=(\d+)", said)
    row = {"seconds": round(wall, 2), "cpu_seconds": round(_cpu() - cpu0, 2), "exit": code,
           "peak_mb": round(int(m.group(1)) / 1024) if m and int(m.group(1)) else None,
           "peak_all_mb": round(watch.peak_kb / 1024) if watch.peak_kb else None,
           "phases": phases(lines, wall)}
    if code != 0 or not (out / "report.html").is_file():
        row["failed"] = "\n".join(said.strip().splitlines()[-6:])[-1500:] or f"exit {code}"
        return row
    row["report_mb"] = round((out / "report.html").stat().st_size / 1048576, 2)
    row["results_mb"] = round(sum(p.stat().st_size for p in out.rglob("*") if p.is_file()) / 1048576, 2)
    row["same"] = fingerprint(out)
    return row


def on_a_phone(report: Path, seconds: int) -> dict:
    """`tools/report_perf.js` on the report: opening and three clicks on a slowed phone. `{"skipped": why}` when
    Node or Playwright is not there."""
    node = shutil.which("node")
    if not node:
        return {"skipped": "Node is not installed"}
    try:
        p = subprocess.run([node, str(ROOT / "tools" / "report_perf.js"), str(report), "--budget-ms=60000"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=seconds)
    except subprocess.TimeoutExpired:
        return {"skipped": f"the report did not open within {seconds} s"}
    for line in reversed(p.stdout.strip().splitlines()):
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except ValueError:
                break
            return {k: row.get(k) for k in ("firstPaintMs", "findingsMs", "detailMs", "mapMs", "jsHeapMb", "errors")}
    return {"skipped": (p.stderr.strip().splitlines() or ["no answer"])[-1][:200]}


# ----------------------------------------------------------------------------- one project
def fetch(name: str, url: str | None, ref: str, work: Path) -> Path:
    repo = work / name
    if repo.exists():
        return repo
    if url is None:
        shutil.copytree(ROOT / ref, repo, ignore=shutil.ignore_patterns(".lantern", "node_modules", "__pycache__"))
    else:
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", ref, url, str(repo)], check=True,
                       timeout=900)               # in the isolated run's environment: no sign-in, prompts off
    return repo


def read_commit(repo: Path) -> str | None:
    """The commit the clone is at, read by hand (no program is started in a stranger's folder)."""
    try:
        from lantern import gitfacts
        return gitfacts.head_commit(repo, alone=True)
    except Exception:       # noqa: BLE001  (an older engine without the reader: the commit is then not known)
        return None


def _mid(rows: list[dict], key: str):
    values = [r[key] for r in rows if r.get(key) is not None]
    return round(statistics.median(values), 2) if values else None


def measure(name: str, size: str, repo: Path, engine: Path, work: Path, runs: int, seconds: int,
            browser: bool, say=print) -> dict:
    out, home = work / f"{name}.out", work / "_home"
    row: dict = {"name": name, "size": size, "commit": read_commit(repo), "first": [], "repeat": []}

    def wipe(results: bool = True, kept: bool = True) -> None:
        if results:
            shutil.rmtree(out, ignore_errors=True)
        if kept:
            shutil.rmtree(home, ignore_errors=True)

    for i in range(runs):
        wipe()
        first = run_once(engine, repo, out, home, seconds)
        say(f"   first run  {i + 1}: {first['seconds']:7.2f} s  {first.get('peak_mb')} MB")
        row["first"].append(first)
        if first.get("failed"):
            row["failed"] = first["failed"]
            return row
        again = run_once(engine, repo, out, home, seconds)
        say(f"   repeat run {i + 1}: {again['seconds']:7.2f} s  {again.get('peak_mb')} MB")
        row["repeat"].append(again)
        if again.get("failed"):
            row["failed"] = again["failed"]
            return row
    first, again = row["first"][-1], row["repeat"][-1]
    # The same results with and without what Lantern kept. The results folder is in the state a repeat run finds
    # (an earlier `security.json` and the baseline are there), so the only thing that differs is the kept work.
    plain = run_once(engine, repo, out, home, seconds, cache=False)
    row["repeat_without_kept_work"] = {k: plain.get(k) for k in ("seconds", "peak_mb", "exit", "failed")}
    row["repeat_differs"] = differing(again["same"], plain.get("same") or {})
    # ... and a first run (no results folder) that finds kept work, beside the first run that found none.
    wipe(kept=False)
    warm = run_once(engine, repo, out, home, seconds)
    row["first_on_kept_work"] = {k: warm.get(k) for k in ("seconds", "peak_mb", "exit", "failed")}
    row["first_differs"] = differing(first["same"], warm.get("same") or {})
    # every first run and every repeat run among themselves
    row["runs_differ"] = sorted({n for rows in (row["first"], row["repeat"]) for r in rows
                                 for n in differing(rows[0]["same"], r["same"])})
    row["marks"] = {"first": first["same"], "repeat": again["same"]}
    for rows in (row["first"], row["repeat"]):
        for r in rows:
            r.pop("same", None)
    try:
        g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
        sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
        meta = g.get("meta", {})
        row.update(files=meta.get("files"), lines=meta.get("lines"), functions=len(g.get("nodes", [])),
                   links=len(g.get("edges", [])), findings=len(sec.get("findings", [])),
                   languages=meta.get("language"))
    except (OSError, ValueError):
        pass
    for key in ("seconds", "cpu_seconds", "peak_mb", "peak_all_mb", "report_mb", "results_mb"):
        row[f"first_{key}"], row[f"repeat_{key}"] = _mid(row["first"], key), _mid(row["repeat"], key)
    row["first_range"] = [min(r["seconds"] for r in row["first"]), max(r["seconds"] for r in row["first"])]
    row["repeat_range"] = [min(r["seconds"] for r in row["repeat"]), max(r["seconds"] for r in row["repeat"])]
    row["phases"] = {k: _mid([r["phases"] for r in row["first"] if r.get("phases")], k) for k in PHASES}
    row["repeat_phases"] = {k: _mid([r["phases"] for r in row["repeat"] if r.get("phases")], k) for k in PHASES}
    if browser:
        row["phone"] = on_a_phone(out / "report.html", max(120, seconds))
    return row


# ----------------------------------------------------------------------------- the tables
def _same_words(r: dict) -> str:
    if r.get("failed"):
        return "FAILED"
    bad = sorted(set(r.get("repeat_differs") or []) | set(r.get("first_differs") or []) | set(r.get("runs_differ") or []))
    return "the same" if not bad else "DIFFERENT: " + ", ".join(bad)


def table(rows: list[dict]) -> str:
    head = ["project", "size", "files", "lines", "first run s (range)", "repeat run s (range)", "processor s",
            "peak MB", "peak MB, all processes", "report MB", "results MB", "with and without kept work"]
    lines = ["| " + " | ".join(head) + " |", "|---|---|" + "---:|" * 9 + "---|"]
    for r in rows:
        if r.get("failed"):
            lines.append(f"| {r['name']} | {r['size']} | | | FAILED | | | | | | | {r['failed'].splitlines()[-1][:80]} |")
            continue
        lines.append("| " + " | ".join(str(x) for x in (
            r["name"], r["size"], r.get("files", ""), r.get("lines", ""),
            f"{r['first_seconds']} ({r['first_range'][0]} to {r['first_range'][1]})",
            f"{r['repeat_seconds']} ({r['repeat_range'][0]} to {r['repeat_range'][1]})",
            r["first_cpu_seconds"], r["first_peak_mb"], r["first_peak_all_mb"], r["first_report_mb"],
            r["first_results_mb"], _same_words(r))) + " |")
    lines += ["", "Where the time of a first run went (seconds, the middle one of the runs):", "",
              "| project | " + " | ".join(PHASES) + " |", "|---|" + "---:|" * len(PHASES)]
    for r in rows:
        if not r.get("failed"):
            lines.append(f"| {r['name']} | " + " | ".join(str(r["phases"].get(k, "")) for k in PHASES) + " |")
    if any(r.get("phone") for r in rows):
        lines += ["", "The report on a slowed phone (milliseconds; `tools/report_perf.js`):", "",
                  "| project | report MB | opens | findings | one finding | back to the map | memory MB |",
                  "|---|---:|---:|---:|---:|---:|---:|"]
        for r in rows:
            ph = r.get("phone") or {}
            if ph.get("skipped"):
                lines.append(f"| {r['name']} | {r.get('first_report_mb', '')} | not measured: {ph['skipped']} | | | | |")
            elif ph:
                lines.append(f"| {r['name']} | {r.get('first_report_mb', '')} | {ph.get('firstPaintMs')} | "
                             f"{ph.get('findingsMs')} | {ph.get('detailMs')} | {ph.get('mapMs')} | {ph.get('jsHeapMb')} |")
    return "\n".join(lines)


def compare(before: dict, rows: list[dict]) -> tuple[str, list[str]]:
    """This run beside an earlier one, project by project, and the projects whose results are not the same as the
    earlier engine's (only where both read the same commit)."""
    old = {r["name"]: r for r in before.get("projects", [])}
    head = ["project", "first run s before", "after", "repeat run s before", "after", "peak MB before", "after",
            "report MB before", "after", "results"]
    lines = ["| " + " | ".join(head) + " |", "|---|" + "---:|" * 8 + "---|"]
    changed = []
    for r in rows:
        o = old.get(r["name"])
        if not o or o.get("failed") or r.get("failed"):
            continue
        if o.get("commit") != r.get("commit"):
            words = "not compared: another commit"
        else:
            bad = sorted(set(differing(o["marks"]["first"], r["marks"]["first"], ACROSS_ENGINES)) |
                         set(differing(o["marks"]["repeat"], r["marks"]["repeat"], ACROSS_ENGINES)))
            words = "the same as before" if not bad else "DIFFERENT from before: " + ", ".join(bad)
            if bad:
                changed.append(r["name"])
        lines.append("| " + " | ".join(str(x) for x in (
            r["name"], o["first_seconds"], r["first_seconds"], o["repeat_seconds"], r["repeat_seconds"],
            o["first_peak_mb"], r["first_peak_mb"], o["first_report_mb"], r["first_report_mb"], words)) + " |")
    return "\n".join(lines), changed


def engine_commit(engine: Path) -> str | None:
    return read_commit(engine)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("work", help="folder for the clones and the results (kept, so a later run reads the same code)")
    ap.add_argument("--only", default="", help="comma-separated names (default: all)")
    ap.add_argument("--runs", type=int, default=3, help="first runs and repeat runs of each project (default 3)")
    ap.add_argument("--seconds", type=int, default=900, help="wall clock for one analysis")
    ap.add_argument("--engine", default="", help="another checkout whose `lantern` is measured (default: this one)")
    ap.add_argument("--browser", action="store_true", help="also open each report on a slowed phone")
    ap.add_argument("--json", default="", help="write every number here as JSON")
    ap.add_argument("--results", default="", help="write the tables here as Markdown")
    ap.add_argument("--compare", default="", help="the JSON of an earlier run, shown beside this one")
    ap.add_argument("--must-match", action="store_true", help="fail when results differ from the earlier run's")
    a = ap.parse_args(argv)
    names = [n for n in a.only.split(",") if n] or [p[0] for p in PROJECTS]
    unknown = [n for n in names if n not in {p[0] for p in PROJECTS}]
    if unknown or a.runs < 1:
        print(f"unknown: {', '.join(unknown)}; the names are: {', '.join(p[0] for p in PROJECTS)}", file=sys.stderr)
        return 2
    work = Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    engine = Path(a.engine).resolve() if a.engine else ROOT
    # isolated (tools/netguard): temporary home, no keys; only the host the projects are cloned from can be reached,
    # and only when one of them is not in the folder yet
    todo = [p for p in PROJECTS if p[0] in names]
    hosts = sorted({urllib.parse.urlsplit(p[2]).hostname for p in todo if p[2] and not (work / p[0]).exists()})
    guard = netguard.begin(allow=hosts)
    rows = []
    for name, size, url, ref, what in todo:
        print(f"== {name} ({size}: {what})", flush=True)
        try:
            repo = fetch(name, url, ref, work)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            rows.append({"name": name, "size": size, "failed": f"could not be fetched: {type(exc).__name__}"})
            continue
        r = measure(name, size, repo, engine, work, a.runs, a.seconds, a.browser,
                    say=lambda s: print(s, flush=True))
        r["ref"] = ref
        print(f"   {_same_words(r)}", flush=True)
        rows.append(r)
    md = table(rows)
    print("\n" + md)
    changed: list[str] = []
    if a.compare:
        side, changed = compare(json.loads(Path(a.compare).read_text(encoding="utf-8")), rows)
        md += "\n\nBeside the earlier run:\n\n" + side
        print("\n" + side)
    record = {"engine": str(engine), "engine_commit": engine_commit(engine), "runs": a.runs,
              "machine": {"processors": os.cpu_count(), "system": platform.platform(), "python": platform.python_version()},
              "when": time.strftime("%Y-%m-%d %H:%M %Z"), "projects": rows}
    if a.json:
        Path(a.json).write_text(json.dumps(record, indent=1), encoding="utf-8")
    if a.results:
        Path(a.results).write_text(md + "\n", encoding="utf-8")
    bad = [r["name"] for r in rows if r.get("failed") or _same_words(r) != "the same"]
    for n in bad:
        print(f"FAIL {n}: {_same_words(next(r for r in rows if r['name'] == n))}", file=sys.stderr)
    if changed and a.must_match:
        print(f"FAIL results differ from the earlier run's: {', '.join(changed)}", file=sys.stderr)
    refused = netguard.end(guard)
    return 1 if bad or refused or (changed and a.must_match) else 0


if __name__ == "__main__":
    sys.exit(main())
