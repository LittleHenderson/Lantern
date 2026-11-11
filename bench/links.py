"""Link sweep: a file of a project that is a link out of the project, or a pipe, is not read (2026-11-10).

    python bench/links.py [--only shop,nextapp] [--states pipe,loop] [--jobs 4] [--seconds 30] [--json FILE]
                          [--engine CHECKOUT]

A project comes from anywhere, and a git repository can hold symbolic links to any path of the computer it is cloned
on. Whatever Lantern opens in a project it must open as a file of that project (`python_frontend.project_text`,
`project_bytes`, `inside_repo`): a link that leads out names somebody else's file, and a pipe nobody writes to holds
the reader up for good.

Every file of the sample projects under `tests/fixtures`, and of one more project made of the other files Lantern
looks for by name (EXTRA), is put in six states, one file at a time, and the whole analysis (map, findings,
readiness, report, evidence; Bandit included) runs offline on each:

  gone      the file is taken away
  link      the file is moved out of the project and a link to it is left in its place
  other     the same link, and an empty file where it leads
  nothing   the same link, and nothing where it leads
  pipe      a pipe nobody writes to, under the file's name
  loop      a link to itself, under the file's name (following it never arrives; Python 3.11 and 3.12 raise an
            error of their own for it, so this state is worth a run under each Python)

What counts as a find:

  read through   `link` and `other` give different results: something in the results depends on what the outside
                 file holds. (A link may be named in a result, as a file that was not read; that is the same for
                 both. Comparing with `gone` would count such a line as a read.)
  tells          `other` and `nothing` give different results: the results say whether the outside path exists.
  held up        no result after `--seconds` (the analysis waits on the pipe).
  stopped        a Python error, in any of the six states.
  unstable       the untouched project gives two different results in two runs: nothing can be compared.

Each find is listed with the file and, for the last three, the innermost line of Lantern's own code. The run exits
1 when there is any.

Measured with this file on 2026-11-10 (232 files of 16 projects, 1424 runs): see `bench/links_results.md`.

What it cannot see: a read that changes no result file (the file's content has to matter to the map, the findings,
the readiness score or the Evidence Report), and a tool that is not installed where it runs.

POSIX only (symbolic links and pipes as any user may make them). Deterministic, no network (tools/netguard), about
six minutes with `--jobs 2` when nothing is held up (a run that is held up costs `--seconds`). `--engine CHECKOUT`
sweeps the `lantern` of another checkout with this same file, for a before and after. Not part of CI:
`tests/test_links_out.py` and `tests/test_project_files.py` run the cases this sweep found, and every file of
EXTRA, on every CI run. Run it after adding a reader, or a file that is looked for by its name (and put such a file
into EXTRA when no sample has one).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import shutil
import signal
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

STATES = ("gone", "link", "other", "nothing", "pipe", "loop")
RESULTS = ("graph.json", "security.json", "readiness.json", "calls.json", "evidence.json")
# what differs from one run to the next of the same project: times, and nothing else
DROP = {"timings", "seconds", "elapsed", "generated", "generated_at", "time", "date", "when", "duration", "started",
        "finished", "took", "ms", "analyzed_at", "created", "at", "duration_ms", "digest"}

# The files Lantern looks for by name that no sample project holds, as one small project.
EXTRA = {
    "app.py": "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n\n\n@app.route('/run')\n"
              "def run():\n    return os.popen(request.args['c']).read()\n",
    "requirements.txt": "flask==2.0.0\n",
    "pyproject.toml": "[project]\nname = 'extras'\nversion = '0.1.0'\ndependencies = ['flask==2.0.0']\n"
                      "[project.scripts]\nextras = 'app:run'\n",
    "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    extras2 = app:run\n",
    "package.json": '{"name": "extras", "dependencies": {"express": "4.17.1", "next": "13.0.0"}, '
                    '"scripts": {"test": "jest"}}\n',
    "package-lock.json": '{"name": "extras", "lockfileVersion": 3, "packages": {"node_modules/express": '
                         '{"version": "4.17.1"}}}\n',
    "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./src/*"]}}}\n',
    "src/index.ts": "import { helper } from '@/lib/helper'\nexport function main() { return helper() }\n",
    "src/lib/helper.ts": "export function helper() { return fetch('/api/x') }\n",
    "lantern-narratives.md": "# How it works\n\nThe run page starts a command for the person who is signed in.\n",
    "lantern-accepted.json": '{"accepted": []}\n',
    "README.md": "# Extras\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\nflask run\n",
    "LICENSE": "MIT License\n\nPermission is hereby granted...\n",
    "SECURITY.md": "# Security\n\nReport problems to the maintainers.\n",
    "Dockerfile": 'FROM python:3.12-slim\nUSER app\nHEALTHCHECK CMD true\nCMD ["flask", "run"]\n',
    ".dockerignore": ".git\n.env\n",
    ".gitignore": ".env\nnode_modules\n__pycache__\n",
    ".env.example": "API_URL=http://localhost\n",
    ".github/workflows/ci.yml": "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n",
    ".github/dependabot.yml": "version: 2\nupdates: []\n",
    "docker-compose.yml": "services:\n  web:\n    build: .\n",
    "fly.toml": "app = 'extras'\n",
    "vercel.json": '{"headers": []}\n',
    "netlify.toml": "[build]\ncommand = 'npm run build'\n",
    "firebase.json": '{"hosting": {"public": "public"}}\n',
    "firestore.rules": "service cloud.firestore {\n  match /databases/{db}/documents {\n    match /{doc=**} "
                       "{ allow read, write: if true; }\n  }\n}\n",
    "storage.rules": "service firebase.storage {\n  match /b/{b}/o {\n    match /{all=**} "
                     "{ allow read, write: if true; }\n  }\n}\n",
    "database.rules.json": '{"rules": {".read": true, ".write": true}}\n',
    "notebooks/demo.ipynb": '{"cells": [{"cell_type": "code", "source": ["import openai\\n", '
                            '"openai.chat.completions.create(model=\\"gpt-4\\")\\n"], "outputs": []}], '
                            '"metadata": {}, "nbformat": 4, "nbformat_minor": 5}\n',
    "lantern-packs/mine.json": '{"pack": "mine", "version": "1", "about": "a pack of the project\'s own", "rules": '
                               '[{"id": "LP-MINE-POPEN", "title": "a shell is started", "pattern": "os\\\\.popen", '
                               '"severity": "MEDIUM", "files": ["*.py"]}]}\n',
    "tests/test_app.py": "from app import run\n\n\ndef test_run():\n    assert run\n",
    "pytest.ini": "[pytest]\n",
    "go.mod": "module example.com/extras\n\ngo 1.22\n",
    "main.go": 'package main\n\nimport "net/http"\n\nfunc main() { http.HandleFunc("/x", h); http.ListenAndServe(":8080", nil) }\n'
               "func h(w http.ResponseWriter, r *http.Request) {}\n",
    "Cargo.toml": '[package]\nname = "extras"\nversion = "0.1.0"\n',
    "src/main.rs": "fn main() { helper(); }\nfn helper() {}\n",
    "Gemfile": "source 'https://rubygems.org'\ngem 'rails', '7.0.0'\n",
    "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails (= 7.0.0)\n",
    "composer.json": '{"require": {"laravel/framework": "8.0.0"}}\n',
    "composer.lock": '{"packages": [{"name": "laravel/framework", "version": "v8.0.0"}], "packages-dev": []}\n',
    "pom.xml": "<project><dependencies><dependency><groupId>org.springframework</groupId>"
               "<artifactId>spring-core</artifactId><version>5.0.0</version></dependency></dependencies></project>\n",
    "appsettings.json": '{"ConnectionStrings": {"Default": "Server=x;Database=y"}}\n',
}


class Late(BaseException):
    """One analysis ran longer than the sweep allows. Not an `Exception`: a reader that passes over whatever goes
    wrong with a file (`except Exception`) must not pass over the sweep's own limit. Until 2026-11-10 it did: the
    reader went on, the alarm was spent, and the run then waited on the next pipe for good, or ended in time and was
    counted as not held up."""


_armed = False


def _late(_signum, _frame):
    if _armed:
        raise Late("no result in time")


def limited(seconds: float, fn, again: float = 1.0):
    """Call `fn()` with a limit: (None, None) when it ended in time, ("held", where) when it did not, ("error", what)
    when it raised. The alarm repeats every `again` seconds until `fn` is left, so a limit that was caught on the
    way out (a bare `except:`) is raised once more; after `fn` a late alarm raises nothing."""
    global _armed
    before = signal.signal(signal.SIGALRM, _late)
    try:
        try:
            _armed = True
            signal.setitimer(signal.ITIMER_REAL, seconds, again)
            fn()
        finally:
            _armed = False
        return None, None
    except Late:
        _armed = False
        return "held", _where(sys.exc_info()[2])
    except Exception as e:  # noqa: BLE001 - said as a find
        _armed = False
        return "error", f"{type(e).__name__} at {_where(sys.exc_info()[2])}"
    finally:
        _armed = False
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, before)


def projects(fixtures: Path) -> list[str]:
    return [d.name for d in sorted(fixtures.iterdir()) if d.is_dir() and d.name != "old_results"] + ["extras"]


def make(fixtures: Path, name: str, to: Path) -> None:
    """The project `name` as a folder of its own."""
    if name == "extras":
        for rel, text in EXTRA.items():
            p = to / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
    else:
        shutil.copytree(fixtures / name, to, symlinks=True)


def files_of(fixtures: Path, name: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="lantern-links-") as td:
        make(fixtures, name, Path(td) / name)
        return sorted(p.relative_to(Path(td) / name).as_posix() for p in (Path(td) / name).rglob("*")
                      if p.is_file() and not p.is_symlink())


def put(repo: Path, rel: str, state: str, outside: Path) -> None:
    """Put the file `rel` of the project into one of STATES. `outside` is a folder beside the project."""
    target = repo / rel
    if state == "gone":
        target.unlink()
    elif state == "pipe":
        target.unlink()
        os.mkfifo(target)
    elif state == "loop":
        target.unlink()
        os.symlink(target.name, target)
    else:
        outside.mkdir(exist_ok=True)
        there = outside / "moved"            # one name for the three states, so that a result that names it is the same
        shutil.move(str(target), str(there))
        os.symlink(there, target)
        if state == "other":
            there.write_bytes(b"")
        elif state == "nothing":
            there.unlink()


def _clean(v, tmp: str):
    if isinstance(v, dict):
        return {k: _clean(x, tmp) for k, x in sorted(v.items()) if k not in DROP}
    if isinstance(v, list):
        return [_clean(x, tmp) for x in v]
    return v.replace(tmp, "<TMP>") if isinstance(v, str) else v


def says(out: Path, tmp: str) -> dict:
    """What the analysis said, per result file, without the times and with the temporary folder's name taken out."""
    parts = {}
    for name in RESULTS:
        try:
            data = json.loads((out / name).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            parts[name] = f"unreadable: {type(e).__name__}"
            continue
        parts[name] = hashlib.sha256(json.dumps(_clean(data, tmp), sort_keys=True).encode()).hexdigest()[:16]
    return parts


def _where(tb) -> str:
    """The innermost line of Lantern's own code on the way."""
    last = ""
    for fr in traceback.extract_tb(tb):
        if "/lantern/" in fr.filename.replace("\\", "/") and "site-packages" not in fr.filename:
            last = f"{Path(fr.filename).name}:{fr.lineno} {fr.name}"
    return last


def one(job) -> dict:
    """One analysis of one project with one file in one state."""
    fixtures, name, rel, state, seconds, engine = job
    want = Path(engine).resolve() if engine else ROOT
    if str(want) not in sys.path:
        sys.path.insert(0, str(want))
    from lantern import pipeline, security
    loaded = Path(pipeline.__file__).resolve().parents[1]
    if loaded != want:                                  # never measure one engine and name another
        raise RuntimeError(f"lantern is loaded from {loaded}, not from {want}")
    security.BANDIT_TIMEOUT = max(5, seconds // 2)      # a Bandit that waits on a pipe ends inside the run's own limit
    os.environ["LANTERN_OFFLINE"] = "1"
    td = tempfile.mkdtemp(prefix="lantern-links-")
    res = {"project": name, "file": rel, "state": state, "engine": str(loaded)}
    try:
        repo = Path(td) / "p" / name
        repo.parent.mkdir()
        make(Path(fixtures), name, repo)
        if rel:
            put(repo, rel, state, Path(td) / "outside")
        out = Path(td) / "out"
        out.mkdir()
        kind, what = limited(seconds, lambda: pipeline.analyze(repo, out, log=lambda line: None, offline=True))
        if kind:
            res[kind] = what
        else:
            res["says"] = says(out, td)
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return res


def judge(results: list[dict]) -> dict:
    """{"files", "finds": {kind: [[project, file, state, detail], ...]}} from the results of `one`."""
    by: dict = {}
    for r in results:
        by.setdefault((r["project"], r["file"]), {}).setdefault(r["state"], []).append(r)
    finds: dict[str, list] = {"read through": [], "tells": [], "held up": [], "stopped": [], "unstable": []}
    files = 0
    for (name, rel), states in sorted(by.items()):
        if not rel:
            a, b = states["whole"]
            if "says" not in a or a.get("says") != b.get("says"):
                finds["unstable"].append([name, "", "whole", a.get("error") or a.get("held") or "two runs differ"])
            continue
        files += 1
        for state in STATES:
            r = (states.get(state) or [{}])[0]     # a run of some states only (`--states`) has no word on the others
            if "held" in r:
                finds["held up"].append([name, rel, state, r["held"]])
            elif "error" in r:
                finds["stopped"].append([name, rel, state, r["error"]])
        link, other, nothing = ((states.get(s) or [{}])[0].get("says") for s in ("link", "other", "nothing"))
        if link and other and link != other:
            finds["read through"].append([name, rel, "link", "differs in " + ", ".join(k for k in link if link[k] != other[k])])
        if other and nothing and other != nothing:
            finds["tells"].append([name, rel, "nothing", "differs in " + ", ".join(k for k in other if other[k] != nothing[k])])
    return {"files": files, "finds": finds}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", default="", help="comma-separated project names (default: every sample, and extras)")
    ap.add_argument("--states", default="", help=f"comma-separated states (default: all of {', '.join(STATES)})")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--seconds", type=int, default=30, help="wall clock for one analysis")
    ap.add_argument("--json", default="", help="write the results here as JSON")
    ap.add_argument("--engine", default="", help="another checkout whose `lantern` is swept (default: this one)")
    a = ap.parse_args(argv)
    if os.name != "posix":
        print("this sweep needs a POSIX system (symbolic links and pipes)", file=sys.stderr)
        return 2
    fixtures = ROOT / "tests" / "fixtures"
    names = projects(fixtures)
    only = [n for n in a.only.split(",") if n]
    unknown = [n for n in only if n not in names]
    if unknown:
        print(f"unknown: {', '.join(unknown)}; the projects are: {', '.join(names)}", file=sys.stderr)
        return 2
    states = [s for s in a.states.split(",") if s] or list(STATES)
    if [s for s in states if s not in STATES]:
        print(f"the states are: {', '.join(STATES)}", file=sys.stderr)
        return 2
    guard = netguard.begin()                      # isolated (tools/netguard); this benchmark needs no network at all
    jobs = []
    for name in only or names:
        jobs += [(str(fixtures), name, "", "whole", a.seconds, a.engine)] * 2
        jobs += [(str(fixtures), name, rel, state, a.seconds, a.engine)
                 for rel in files_of(fixtures, name) for state in states]
    t0 = time.time()
    if a.jobs > 1:
        with mp.Pool(a.jobs, maxtasksperchild=20) as pool:
            results = pool.map(one, jobs, chunksize=1)
    else:
        results = [one(j) for j in jobs]
    verdict = judge(results)
    finds = verdict["finds"]
    for kind, rows in finds.items():
        for name, rel, state, detail in rows:
            print(f"{kind:13} {name + '/' + rel:62} {state:8} {detail}")
    print(f"{verdict['files']} files of {len(only or names)} projects, {len(jobs)} runs in {time.time() - t0:.0f} s "
          f"(Python {sys.version.split()[0]}; states: {', '.join(states)}): "
          + ", ".join(f"{len(rows)} {kind}" for kind, rows in finds.items()))
    if a.json:
        Path(a.json).write_text(json.dumps({"engine": sorted({r["engine"] for r in results}), "runs": len(jobs),
                                            "python": sys.version.split()[0], "states": states, **verdict},
                                           indent=1), encoding="utf-8")
    refused = netguard.end(guard)
    return 1 if any(finds.values()) or refused else 0


if __name__ == "__main__":
    mp.set_start_method("spawn" if sys.platform != "linux" else "fork")
    sys.exit(main())
