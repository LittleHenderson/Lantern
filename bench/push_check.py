"""The check before each push, timed and tried with a real `git push` (2026-11-17; roadmap of 2026-11-14, stage 6).

    python bench/push_check.py [--only shop,goapp] [--json FILE]

`lantern hook install` (lantern/hook.py) writes git's pre-push hook: before git sends anything, Lantern compares the
commit being pushed with what the other side has (`lantern diff`'s two checks, offline) and stops the push when the
change brings what blocks a release. This measures it on the sample projects under `tests/fixtures`, each copied
into a repository of its own whose first commit is pushed to a remote on this computer before the hook is written:

  every sample     two harmless changes (a new notes file, then a line more in it), each pushed through the hook:
                   the time of the whole `git push` command; the first check after the hook was written starts with
                   nothing kept (a home folder of its own), the second has what the first kept (`lantern/kept.py`).
  the shop sample  three planted faults, each a new branch pushed through the hook: a route that runs the command it
                   is sent (`shell=True`), a payment key written into a file of the page, a route renamed under the
                   page that still asks for it; and their three twins, which look alike and are none: the route runs
                   a fixed command (a list, no shell), the key's place is kept by filler, the page asks for the new
                   address too.

What it must show, written down on 2026-11-17 before its first run:

  the shop sample  each of the three faults stopped (the push fails and the other side does not get the branch),
                   each twin let through, and every push of it answered in under 3 seconds, the first one included;
  every sample     both harmless pushes let through. Their times are written down, with no claim beyond the shop
                   sample (a larger project takes two longer checks).

Any other outcome is a failure of the check, or is named in `bench/push_check_results.md` with the reason. No
network (tools/netguard); the keys are put together here, at run time, never written into a file of this repository.
Not part of CI: `tests/test_hook.py` runs the cases.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
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
BUDGET = 3.0            # seconds: what a push of the shop sample must be answered in
APP = "shop/app.py"
PAGE = "web/src/api.ts"
RUNS = '\n\n@app.get("/run")\ndef run(cmd: str):\n    return subprocess.check_output(cmd, shell=True)\n'
RUNS_FIXED = '\n\n@app.get("/run")\ndef run():\n    return subprocess.check_output(["uptime"])\n'


def key(filler: bool) -> str:
    """A payment key's line, put together here: filler (the twin) or a key of the shape the patterns look for."""
    tail = "x" * 24 if filler else "Qz7Kp2Lm9Wd4Rt6Yh8Vb3Nc5"
    return 'export const PAYMENTS = "' + "sk_" + "live_" + tail + '"\n'


# (name, what it changes, whether the push must be stopped): each starts from the first commit, as a new branch
CASES = (
    ("runs-what-it-is-sent", {APP: ("add", RUNS)}, True),
    ("runs-a-fixed-command", {APP: ("add", RUNS_FIXED)}, False),
    ("key-in-the-page", {"web/src/payments.ts": ("new", key(filler=False))}, True),
    ("filler-in-the-page", {"web/src/payments.ts": ("new", key(filler=True))}, False),
    ("route-renamed-under-the-page", {APP: ("swap", '@app.post("/backup")', '@app.post("/backups")')}, True),
    ("route-and-page-renamed", {APP: ("swap", '@app.post("/backup")', '@app.post("/backups")'),
                                PAGE: ("swap", 'axios.post("/backup"', 'axios.post("/backups"')}, False),
)


def git(*args, cwd) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "user.name=bench", "-c", "user.email=bench@example.invalid",
                           "-c", "init.defaultBranch=main", "-c", "core.autocrlf=false", "-c", "gc.auto=0", *args],
                          cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def must(p: subprocess.CompletedProcess) -> str:
    if p.returncode != 0:
        raise RuntimeError(f"git: {p.args[-3:]}: {p.stderr.strip()[:400]}")
    return p.stdout.strip()


def push(repo: Path, ref: str) -> dict:
    began = time.perf_counter()
    p = git("push", "origin", ref, cwd=repo)
    took = time.perf_counter() - began
    said = [line for line in p.stderr.splitlines() if line.startswith("lantern ")]
    return {"seconds": round(took, 2), "stopped": p.returncode != 0, "said": said}


def remote_has(remote: Path, branch: str) -> bool:
    return git("rev-parse", "--verify", "--quiet", f"refs/heads/{branch}", cwd=remote).returncode == 0


def sample(name: str, work: Path) -> dict:
    from lantern import hook
    remote = work / name / "remote.git"
    repo = work / name / "repo"
    shutil.copytree(ROOT / "tests" / "fixtures" / name, repo, ignore=shutil.ignore_patterns(".lantern"))
    must(git("init", "-q", "--bare", str(remote), cwd=work))
    must(git("init", "-q", ".", cwd=repo))
    must(git("add", "-A", cwd=repo))
    must(git("commit", "-q", "-m", "first", cwd=repo))
    must(git("remote", "add", "origin", str(remote), cwd=repo))
    must(git("push", "-q", "origin", "main", cwd=repo))
    hook.install(repo)
    out = {"harmless": []}
    for i in (1, 2):
        with open(repo / "PUSH-NOTES.md", "a", encoding="utf-8") as f:
            f.write(f"A note, line {i}.\n")
        must(git("add", "-A", cwd=repo))
        must(git("commit", "-q", "-m", f"notes {i}", cwd=repo))
        got = push(repo, "main")
        got["remote_has"] = not got["stopped"]
        out["harmless"].append(got)
    if name == "shop":
        out["cases"] = {}
        first = must(git("rev-list", "--max-parents=0", "HEAD", cwd=repo))
        for case, edits, stop in CASES:
            must(git("checkout", "-q", "-b", case, first, cwd=repo))
            for rel, how in edits.items():
                p = repo / rel
                if how[0] == "new":
                    p.write_text(how[1], encoding="utf-8")
                elif how[0] == "add":
                    p.write_text(p.read_text(encoding="utf-8") + how[1], encoding="utf-8")
                else:
                    text = p.read_text(encoding="utf-8")
                    assert text.count(how[1]) == 1, (case, rel, how[1])
                    p.write_text(text.replace(how[1], how[2]), encoding="utf-8")
            must(git("add", "-A", cwd=repo))
            must(git("commit", "-q", "-m", case, cwd=repo))
            got = push(repo, case)
            got["remote_has"] = remote_has(remote, case)
            got["must_stop"] = stop
            got["as_written"] = got["stopped"] is stop and got["remote_has"] is (not stop)
            out["cases"][case] = got
    return out


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
    if not shutil.which("git"):
        print("git is not installed: nothing to push", file=sys.stderr)
        return 2
    guard = netguard.begin()                      # isolated (tools/netguard); this benchmark needs no network at all
    work = Path(tempfile.mkdtemp(prefix="lantern-push-bench-"))
    os.environ["LANTERN_HOME"] = str(work / "home")       # nothing kept from earlier runs: the first check starts cold
    os.environ.pop("LANTERN_CACHE", None)
    # the hook git starts runs this Python and this checkout's Lantern by itself (`hook.STARTER` puts the checkout on
    # its path), so nothing here tells it where Lantern is
    report, bad, t0 = {}, 0, time.time()
    try:
        for name in only or SAMPLES:
            r = report[name] = sample(name, work)
            times = [h["seconds"] for h in r["harmless"]]
            let = all(not h["stopped"] for h in r["harmless"])
            bad += not let
            line = f"{name:11} harmless pushes {'let through' if let else 'STOPPED'}: {times[0]:.2f} s first, {times[1]:.2f} s then"
            print(line)
            if not let:
                for h in r["harmless"]:
                    for said in h["said"][:6]:
                        print(f"    {said[:200]}")
            for case, c in (r.get("cases") or {}).items():
                ok = c["as_written"] and c["seconds"] < BUDGET
                bad += not ok
                print(f"    {case:30} {'stopped' if c['stopped'] else 'let through':12} {c['seconds']:.2f} s"
                      + ("" if ok else "   NOT AS WRITTEN"))
            if name == "shop":
                slow = [t for t in times if t >= BUDGET]
                bad += bool(slow)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(f"{len(report)} samples in {time.time() - t0:.0f} s: {bad} not as written down")
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=1), encoding="utf-8")
    refused = netguard.end(guard)
    return 1 if bad or refused else 0


if __name__ == "__main__":
    sys.exit(main())
