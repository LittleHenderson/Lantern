"""The analysis pipeline as plain functions, shared by the command line and the local app (`lantern serve`).

Each step reports progress through `log(line)`; results land in the output folder (default PATH/.lantern).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable

from . import results
from .graph import Graph

Log = Callable[[str], None]
RANKS = ["critical", "high", "medium", "low"]


def load(out: Path, name: str) -> dict | None:
    """A result file the command is about, read strictly: one that cannot be read is an error, never "nothing"
    (`results.table`: only a plain file is read, a link or a pipe under the name is `results.Refused`)."""
    return results.table(Path(out) / name)


def earlier(out: Path, name: str, log: Log | None = None, then: str = "") -> dict | None:
    """A file an earlier run left in `out` that this run can do without (`results.earlier`): its table, or None when
    there is none. When one is there and cannot be used, nothing stops: one line in the log says why and what that
    costs (`then`), and the file is left as it is."""
    data, why = results.earlier(out, name)
    if why and log:
        log(f"earlier {name} from an earlier run was not used: {why}. {then}".rstrip())
    return data


def out_dir(repo: Path, out: str | Path | None = None) -> Path:
    """The results folder of `repo` (`out` when the person named one), made when it is not there. `results.Refused`
    when it is a link inside the project or is reached through one (`results.folder`)."""
    return results.folder(repo, out)


# the files every `analyze` writes anew (`security.json` only when the scan runs)
WRITTEN = ("graph.json", "calls.json", "readiness.json", "run.json", "report.html", "evidence.html", "evidence.json",
           "badge.svg")


class Stopped(Exception):
    """The person stopped the project's tests while they ran (`analyze(cancel=)`). The run ends there and no result
    file is written, so the results stay those of the last check that finished: a stop takes nothing away.
    `not_ended`: what the tests started and Lantern could not end, in its own words (empty when nothing is left)."""

    def __init__(self, not_ended=()):
        super().__init__("the tests were stopped before they ended; no result was changed")
        self.not_ended = [str(x) for x in not_ended]


def analyze(repo: Path, out: Path, privacy: str = "full", trace_cmd: list[str] | None = None,
            no_scan: bool = False, log: Log = print, offline: bool | None = None, sandbox: bool = False,
            test_cwd: str = "", cancel=None, test_minutes=None, test_memory=None) -> dict:
    """Graph -> (trace) -> scan -> readiness -> report -> evidence. Returns a short summary.
    `sandbox`: run `trace_cmd` (a test command) in `lantern.sandbox` instead of directly (the app always does).
    `test_minutes`: how long the tests may take, a whole number from 1 to 240 (`sandbox.time_limit`; ValueError
    for anything else, before anything is read). With no word the sandbox gives ten minutes, or what
    LANTERN_TEST_MINUTES says, and the older way (in the project's folder) the fifteen it always gave. Tests
    stopped at the limit are recorded as such (`trace.timed_out`, `trace.time_limit` in `run.json`) and the rest
    of the check goes on: the release decision is then "Incomplete", never passed or failed.
    `test_memory`: the megabytes of memory the tests may have in use in the sandbox, with everything they start,
    from 128 to 1,048,576 (`sandbox.memory_limit`; ValueError for anything else, before anything is read; with no
    word 2 GB, or what LANTERN_TEST_MEMORY_MB says). Tests stopped for their memory are recorded as such
    (`trace.over_memory`, `trace.memory_limit`) and are "Incomplete" too.
    When the sandbox cannot be set up the tests are not run, `run.json` says why (`trace.ran` false,
    `trace.unavailable`), and the rest, which only reads the code, is done all the same. `cancel`: a
    threading.Event; set while the tests run, it ends them and everything they started, and `Stopped` is raised
    before any result file is written. `results.Refused` (a RuntimeError) before anything is analysed when the
    results folder is a link that came with the project, or a folder lies under a result file's name; every file is
    written through `results.write`, and what that met (a link, a pipe) is said in the log at the end."""
    from . import kept, listing, remote
    results.folder(repo, out)   # also for the callers that name `out` themselves (the connector's recheck)
    results.ready(out, WRITTEN if no_scan else ("security.json", *WRITTEN))
    if remote.is_clone(repo):   # a clone whose checkout could not be completed would report on part of a repository
        remote.check_complete(repo)
    from .depaudit import offline as offline_env
    from .security import Early
    offline = offline_env() if offline is None else offline
    # Directive point 10: the project's folder is walked once for the whole run (`listing`), and the scanners that
    # need nothing of the map are started now and run beside the reading of the code (`security.Early`). Not where
    # the project's own tests are run in its folder: they may leave files there that the scanners then read, as
    # they did when every scanner ran after the tests.
    # And how a file reads is kept between runs (`lantern/kept.py`), so a file that has not changed is not read
    # again; the run counts what it took from there and what it worked out anew, and says so.
    in_its_folder = bool(trace_cmd) and not sandbox
    from . import sandbox as sbx
    limit = None                # seconds for the tests; None: the older way's own (`trace.DEFAULT_TIMEOUT`)
    if test_minutes is not None or (trace_cmd and (sandbox or sbx.time_asked())):
        limit = sbx.time_limit(test_minutes)
    room = sbx.memory_limit(test_memory) if test_memory is not None or (trace_cmd and sandbox) else None
    early = None
    with listing.one_run(Path(repo).resolve()), kept.tally():
        try:
            if not no_scan and not in_its_folder:
                early = Early(Path(repo).resolve(), offline).start()
            return _analyze(repo, out, privacy, trace_cmd, no_scan, log, offline, sandbox, test_cwd, cancel, early,
                            limit, room)
        finally:
            if early is not None:
                early.close()   # whatever is still going is ended: a run that stops or fails leaves nothing behind
            kept.tidy()         # at most once a day: what nobody asked for in a month goes, the folder stays bounded


def _analyze(repo: Path, out: Path, privacy: str, trace_cmd, no_scan: bool, log: Log, offline: bool, sandbox: bool,
             test_cwd: str, cancel, early, limit=None, room=None) -> dict:
    from . import listing, remote
    from . import sandbox as sbx
    from . import trace as older
    from .engine import build_graph
    from .readiness import assess
    from .report import write_report
    from .security import scan

    timings = {}
    t = time.perf_counter()
    g = build_graph(repo)
    timings["graph"] = round(time.perf_counter() - t, 2)
    s = g.stats()
    log(f"graph   {g.meta['files']} files, {s['nodes'].get('callable', 0)} functions, "
        f"{s['internal_call_edges']} internal calls, {s['entry_points']} entry points ({timings['graph']}s)")
    from .calls import line_words
    if line_words(g.meta.get("calls")):
        log(f"calls   {line_words(g.meta.get('calls'))}")
    from . import deep
    if deep.line_words(g.meta):   # code nested deeper than a reader follows was left where the reading stopped
        log(f"deep    {deep.line_words(g.meta)}")
    run_meta: dict = {"timings": timings, "privacy": privacy, "offline": offline}
    left = remote.skipped(repo) if remote.is_clone(repo) else None
    if left:   # the clone left out files Lantern does not read, to stay under the size cap (remote._checkout)
        run_meta["skipped"] = {k: left.get(k) for k in ("files", "mb", "kept_mb", "cap_mb", "examples")}
    if os.environ.get("LANTERN_CLOUD_RUN") == "1":   # set only by Lantern's cloud worker (cloud/lantern_cloud/worker.py)
        run_meta["place"] = "cloud"
    if trace_cmd:
        t = time.perf_counter()
        extra: dict = {}
        if sandbox:
            nothing = {"returncode": None, "observed_edges": 0, "recall": None, "runtime_only": 0}
            try:
                data = sbx.run(repo, trace_cmd, log=log, timeout=limit, cwd_rel=test_cwd, cancel=cancel, memory=room)
            except sbx.Unavailable as e:   # no sandbox, no tests; reading the code needs neither
                data = None
                extra = {"ran": False, "unavailable": str(e)}
                m = dict(nothing)
                log(f"trace   the tests were not run: {e}. The rest of the check reads the code and goes on.")
            if data is not None:
                if data.get("cancelled"):   # stopped part-way: what was recorded until then is not a test run
                    log("trace   the tests were stopped before they ended; the results are left as they were")
                    raise Stopped(data.get("not_ended") or [])
                extra = {k: data.get(k) for k in ("backend", "language", "traced", "timed_out", "blocked", "not_ended",
                                                  "own_network")}
                extra["ran"] = True
                extra["time_limit"] = limit
                extra["over_memory"] = bool(data.get("over_memory"))
                extra["memory_limit"] = room
                if data.get("traced"):
                    m = older.merge_trace(g, data)
                else:
                    m = dict(nothing, returncode=data.get("returncode"))
                m["stderr_tail"] = data.get("stderr_tail")
        else:
            data = older.run_trace(repo, trace_cmd, timeout=limit)   # looked up when it is called, as it always was
            m = older.merge_trace(g, data)
            extra = {"time_limit": limit if limit is not None else older.DEFAULT_TIMEOUT}
            if data.get("timed_out"):
                extra["timed_out"] = True
            listing.fresh(repo)     # the tests ran in the project's folder: what is listed from here on is looked up anew
            listing.fresh(Path(repo).resolve())
        timings["trace"] = round(time.perf_counter() - t, 2)
        run_meta["trace"] = {"command": trace_cmd, "returncode": m["returncode"], "observed_edges": m["observed_edges"],
                             "recall": m["recall"], "stderr_tail": (m.get("stderr_tail") or "")[-600:], **extra}
        log(f"trace   {m['observed_edges']} calls seen running, recall {m['recall']}, "
            f"{m['runtime_only']} runtime-only (exit {m['returncode']})")
        if extra.get("timed_out"):   # said in so many words: "exit None" tells nobody what happened
            had = sbx.minutes_words(extra.get("time_limit"))
            log("trace   the tests were stopped at the time limit" + (f" ({had})" if had else "") + ": that is not "
                "a pass and not a failure. They can be given more time (from 1 to 240 minutes).")
        if extra.get("over_memory"):
            had = sbx.memory_words(extra.get("memory_limit"))
            log("trace   the tests were stopped because they used more memory than their limit"
                + (f" ({had})" if had else "") + ": that is not a pass and not a failure. They can be given more "
                "memory (--test-memory, in megabytes).")
    from .evidence import git_info
    git = git_info(repo)        # asked once: the findings' cases and the release decision name the same commit
    sec = None
    if not no_scan:
        t = time.perf_counter()
        sec = scan(g, offline, early)
        from . import case
        # the previous run of this folder, before it is replaced, and the first one
        before = earlier(out, "security.json", log, "This run does not say which findings were there before.")
        base = earlier(out, "baseline.json")    # `evidence` below says so when this one cannot be used
        ids = None
        if before and before.get("id_version") == sec.get("id_version"):
            ids = {f.get("id") for f in before.get("findings") or []}
        if base and base.get("id_version") == sec.get("id_version"):
            ids = (ids or set()) | set(base.get("findings") or {})
        case.stamp(sec, git, ids)
        timings["scan"] = round(time.perf_counter() - t, 2)
        c = sec["counts"]
        log(f"scan    {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low "
            f"({timings['scan']}s)")
        # A scanner that did not finish, or did not cover everything, is said on the console and kept in run.json,
        # the readiness file, the Evidence Report and the badge (scanresult.py), never folded into "no findings".
        run_meta["incomplete"] = [{k: t.get(k) for k in ("tool", "state", "status", "why", "role")}
                                  for t in sec.get("incomplete") or []]
        for t in run_meta["incomplete"]:
            log(f"incomplete {t['tool']}: {t['status']}")
        results.write(out / "security.json", json.dumps(sec, indent=1))
    g.save(out / "graph.json")
    from . import calls
    calls.write(out / "calls.json", g)
    # What `lantern behave` left in the results folder counts for the release decision only when it is of this code
    # and this plan and carries this computer's seal (release.py); a file that cannot be used is said, not guessed at.
    from . import behave, release
    record, unread = results.earlier(out, behave.RESULT_NAME)
    rd = assess(g, sec, run_meta, git=git, behaviour=record, behaviour_unread=unread, out=out)
    results.write(out / "readiness.json", json.dumps(rd, indent=1))
    log(f"ready   {rd['score']}/100 (grade {rd['grade']}), {rd['shape']}")
    log(f"release {release.line(rd['release'])}")
    from . import kept
    work = kept.current()
    if work is not None and work.table():   # what this run did not have to work out again; about the run, like its
        run_meta["kept"] = work.table()     # timings, and in no other result file
        log(f"kept    {work.said()}")
    run_meta["finished_at"] = time.strftime("%Y-%m-%d %H:%M")
    results.write(out / "run.json", json.dumps(run_meta, indent=1))
    words = earlier(out, "explanations.json", log, "The report is written without a model's explanations; "
                    "`lantern explain` writes them again.")
    path = write_report(out, g, sec, words, privacy, timings, rd)
    log(f"report  {path}")
    log(f"proof   {evidence(out, g, sec, rd, run_meta, privacy, log)}")
    for line in results.said(out):
        log(f"note    {line}")
    return {"score": rd["score"], "grade": rd["grade"], "shape": rd["shape"], "release": rd["release"]["decision"], "release_words": rd["release"]["words"],
            "counts": (sec or {}).get("counts"), "incomplete": run_meta.get("incomplete") or [], "report": str(path)}


def evidence(out: Path, g: Graph, sec, rd, run_meta: dict, privacy: str, log: Log | None = None) -> Path:
    """Write the Evidence Report. The baseline (the first analysis) is made here when there is none, or when finding
    ids changed. One that is there and cannot be used (`results.earlier`) is neither compared with nor replaced: it
    may be the only record of the first analysis (a file a merge left with conflict marks), so the report says in its
    Limits that it does not know what was fixed, and `lantern evidence PATH --reset-baseline` starts a new one."""
    from . import evidence as ev
    base, unread = results.earlier(out, "baseline.json")
    from .security import ID_VERSION
    if unread:
        if log:
            log(f"earlier baseline.json was not used: {unread}. The report does not say what was fixed since the "
                "first analysis, and the file is left as it is (`lantern evidence PATH --reset-baseline` starts a "
                "new one).")
    elif sec is not None and (base is None or base.get("id_version") != ID_VERSION):   # first run, or ids changed
        base = ev.baseline_from(sec, ev.git_info(Path(g.repo_root)).get("commit"), rd)
        results.write(out / "baseline.json", json.dumps(base, indent=1))
    rec = ev.build(g, sec, rd, results.earlier(out, "explanations.json")[0], run_meta, base, privacy,
                   baseline_unread=unread)
    return ev.write(out, rec)["html"]


def rebuild_outputs(out: Path, repo: Path, g: Graph | None = None) -> Path:
    """Re-render report.html and evidence.html from saved results (after explanations change). `repo` is the
    project folder the caller was given: the functions' lines are read there, never from a folder the saved map
    names (`Graph.load`)."""
    from .report import write_report
    g = g or Graph.load(out / "graph.json", repo)
    run_meta = load(out, "run.json") or {}
    sec, rd = load(out, "security.json"), load(out, "readiness.json")
    path = write_report(out, g, sec, load(out, "explanations.json"), run_meta.get("privacy", "full"),
                        run_meta.get("timings"), rd)
    evidence(out, g, sec, rd, run_meta, run_meta.get("privacy", "full"))
    return path


def plan_explain(out: Path, repo: Path, depth: int = 3, limit: int | None = 40, only: list[str] | None = None) -> dict:
    from .explain import estimate, select_nodes
    g = Graph.load(out / "graph.json", repo)
    sec = load(out, "security.json") or {"findings": []}
    nids = select_nodes(g, depth=depth, limit=limit, only=only)
    return {**estimate(g, nids, sec["findings"]), "nodes": nids}


def explain(out: Path, repo: Path, provider, nids: list[str], metaphor: str | None = None,
            progress: Callable | None = None, fresh: bool = False) -> dict:
    """Explain `nids` with `provider`, merge into explanations.json, and re-render the report. The code that goes
    to the model is read in `repo`, the project folder the caller was given."""
    from .explain import run
    g = Graph.load(out / "graph.json", repo)
    sec = load(out, "security.json") or {"findings": []}
    prev = load(out, "explanations.json")
    if metaphor is None and prev and (prev.get("metaphor") or {}).get("world"):
        metaphor = prev["metaphor"]["world"]   # keep one metaphor world across runs
    res = run(g, provider, sec["findings"], out / "cache", nids, metaphor=metaphor, progress=progress, fresh=fresh)
    if prev and prev.get("explanations"):
        prev["explanations"].update(res["explanations"])
        res["explanations"] = prev["explanations"]
        if prev.get("metaphor", {}).get("world") == res["metaphor"]["world"] and prev["metaphor"].get("roles"):
            res["metaphor"] = prev["metaphor"]
    results.write(out / "explanations.json", json.dumps(res, indent=1))
    rebuild_outputs(out, repo, g)
    return res
