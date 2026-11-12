"""lantern: map, explain, audit, and grade a full-stack app (Python + TypeScript/JavaScript).

  lantern serve [PATH ...]                                the local app in your browser (start here)
  lantern learn [NAME [DIR]]                              create a starter app to learn Lantern step by step
  lantern analyze PATH [--trace -- python -m pytest -q]   build the graph, scan, write report
  lantern trace PATH -- python -m pytest -q               record what actually runs
  lantern behave PATH                                     start the app in the sandbox and run its lantern-behaviour.json
  lantern explain PATH                                    add Three-Lens explanations (Claude Haiku by default)
  lantern login --github | --google                        get a free allowance (sign in once)
  lantern login --token TOKEN                             use a token you already have
  lantern allowance                                       see how much of it is left
  lantern report PATH                                     rebuild report.html from saved results
  lantern accept PATH FINDING_ID --reason "..."           record an accepted risk (committed in the repo)
  lantern starter PATH [--write NAME]                     show or write generated starter files
  lantern evidence PATH                                   rebuild the commit-pinned Evidence Report
  lantern verify PATH --report evidence.html [-- CMD]     re-run the analysis the same way and compare
  lantern mcp [PATH ...] [--setup]                        serve Lantern to AI assistants (Claude, ChatGPT, Cursor)
  lantern packs PATH                                      list and check the analysis packs a project uses
  lantern export PATH --sarif out.sarif                   findings as SARIF (GitHub code scanning and others)
  lantern usage [--on | --off | --show]                   anonymous usage counts (off by default; --show prints the ping)

Results live in PATH/.lantern/ (override with --out).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .graph import Graph


def _out(repo: Path, out: str | None) -> Path:
    """The results folder, made when it is not there. `results.Refused` when it is a link that came with the
    project, or is reached through one: `main` says so and ends with 2."""
    from . import results
    return results.folder(repo, out)


def _load(out: Path, name: str) -> dict | None:
    from .pipeline import load
    return load(out, name)


def _split_cmd(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def cmd_analyze(a, trace_cmd: list[str]) -> int:
    from .pipeline import analyze
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    try:
        res = analyze(repo, out, a.privacy, trace_cmd, a.no_scan, offline=a.offline or None)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.fail_on and res["counts"]:
        levels = RANKS[:RANKS.index(a.fail_on) + 1]
        n = sum(res["counts"].get(k, 0) for k in levels)
        if n:
            print(f"fail    {n} open finding(s) at {a.fail_on} or worse", file=sys.stderr)
            return 1
    if a.fail_on:
        # A gate cannot pass on findings a scanner never produced: a tool that failed, timed out, was not installed
        # or covered only part of the project fails the run. A skip the user chose (--offline) is listed, not failed.
        broke = [t for t in res.get("incomplete") or [] if t.get("state") != "skipped"]
        if broke:
            for t in broke:
                print(f"fail    incomplete: {t['tool']} {t['status']}", file=sys.stderr)
            print(f"fail    {len(broke)} scanner(s) did not finish or did not cover everything; no clean result "
                  "without them", file=sys.stderr)
            return 1
    if a.require:
        # The release decision of this very run, never one read back from the results folder (a project can bring
        # a readiness.json of its own). `not-blocked` stops on Blocked; `passed` stops on Incomplete too.
        decision = res.get("release")
        if decision != "Passed" and (a.require == "passed" or decision != "Incomplete"):
            words = str(res.get("release_words") or "")
            print(f"fail    the release decision is {decision or 'not made'}"
                  + (f" ({_printable(words)})" if words else ""), file=sys.stderr)
            return 1
    return 0


RANKS = ["critical", "high", "medium", "low"]


def cmd_evidence(a) -> int:
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    if not (out / "graph.json").exists():
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    run_meta = _load(out, "run.json") or {}
    if a.reset_baseline and (out / "baseline.json").exists():
        (out / "baseline.json").unlink()
    from .pipeline import evidence
    print(evidence(out, Graph.load(out / "graph.json", repo), _load(out, "security.json"), _load(out, "readiness.json"),
                   run_meta, run_meta.get("privacy", "full")))
    return 0


def cmd_verify(a, trace_cmd: list[str]) -> int:
    from . import evidence
    want, old = a.digest, None
    if a.report:
        want, old = evidence.read_digest(Path(a.report))
    if not want:
        print("give --digest sha256:... or --report evidence.html", file=sys.stderr)
        return 2
    repo = Path(a.path).resolve()
    r = evidence.verify(repo, want, old, trace_cmd, a.no_scan, a.offline,
                        beside=Path(a.report).resolve().parent if a.report else None)
    if r.get("refused"):
        print(r["refused"] + "\n  lantern verify " + (a.path or ".") + f" --report {a.report} -- "
              + " ".join(r["trace_command"]), file=sys.stderr)
        return 2
    o = r["options"]
    print(f"commit  {r['commit']}{' (uncommitted changes present)' if r['dirty'] else ''}")
    print(f"options scan {'on' if o['scan'] else 'off'}, trace {' '.join(o['trace']) if o['trace'] else 'off'}, "
          f"dependency audit {'on' if o['dependency_audit'] else 'off (offline)'}")
    print(f"report  {r['report']}\nrerun   {r['rerun']}")
    if r["match"]:
        print("MATCH: the report's results are what this analyzer finds on this commit.")
        return 0
    print("DIFFERENT: " + r["note"])
    for k in r.get("differs") or []:
        print(f"  differs: {k}")
    return 1


def cmd_packs(a) -> int:
    from . import packs
    repo = Path(a.path).resolve()
    loaded, problems = packs.load_all(repo, keep_inactive=True)
    for pk in loaded:
        req = pk.get("requires") or {}
        why = "" if pk["active"] else "  not used here: needs " + ", ".join(req.get("files", []) + req.get("text", []))
        why += "" if pk.get("enabled", True) else "  off (turned off in Settings)"
        print(f"{pk['pack']:<20} v{str(pk.get('version', '-')):<6} {len(pk.get('rules', [])):>2} rule(s), "
              f"{len(pk.get('entries', []))} entry pattern(s)  [{pk['source']}]{why}")
    for where, msg in problems:
        print(f"skipped {where}: {msg}", file=sys.stderr)
    if not loaded and not problems:
        print("no packs: built-in packs live in lantern/packs/, a project's in lantern-packs/*.json, "
              "yours in ~/.lantern/packs/")
    return 1 if problems else 0


def cmd_export(a) -> int:
    from .exporters import sarif
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    sec = _load(out, "security.json")
    if sec is None:
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    text = json.dumps(sarif(sec, repo), indent=1)
    if a.sarif == "-":
        print(text)
    else:
        _write_named(repo, Path(a.sarif), text)
        print(f"wrote   {a.sarif}  ({len(sec.get('findings', []))} findings)")
    return 0


def _write_named(repo: Path, dest: Path, text: str) -> None:
    """Write a file the person named on the command line. The name is theirs, so it is written as they wrote it
    (a link of their own is followed, `/dev/stdout` works), with one exception: a link that lies inside the project
    came with the project, and Lantern puts its own file in that link's place (`results.write`)."""
    from . import results
    if results.link_in_project(repo, dest):
        results.write(dest, text, where="the project folder")
    else:
        dest.write_text(text, encoding="utf-8")


def cmd_trace(a, trace_cmd: list[str]) -> int:
    from .report import write_report
    from .trace import merge_trace, run_trace
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    if not (out / "graph.json").exists():
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    if not trace_cmd:
        print("give the command after --, e.g. lantern trace . -- python -m pytest -q", file=sys.stderr)
        return 2
    g = Graph.load(out / "graph.json", repo)
    m = merge_trace(g, run_trace(repo, trace_cmd))
    print(json.dumps(m, indent=1))
    g.save(out / "graph.json")
    run = _load(out, "run.json") or {}
    write_report(out, g, _load(out, "security.json"), _load(out, "explanations.json"),
                 run.get("privacy", "full"), run.get("timings"), _load(out, "readiness.json"))
    return 0


def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def cmd_behave(a) -> int:
    """Run the project's behaviour plan (docs/behaviour.md). 0 only when every case held; 1 when a case is broken,
    undecided or was not run; 2 when there is no plan or it cannot be used; 3 when the app was not started."""
    from . import behave
    repo = Path(a.path).resolve()
    if not repo.is_dir():
        print(f"error: {a.path} is not a folder", file=sys.stderr)
        return 2
    out = _out(repo, a.out)
    try:
        record = behave.run(repo, out=out, log=lambda line: print(line, file=sys.stderr))
    except behave.PlanError as e:
        print(f"error: {behave.PLAN_NAME} cannot be used: {e}", file=sys.stderr)
        return 2
    if not record["ran"]:
        print(f"not run {record['why_not']}")
        return 2 if record.get("no_plan") else 3
    for o in record["outcomes"]:
        if o["outcome"] != "held":
            saw = o.get("saw") or {}
            detail = "; ".join(x for x in (o.get("said") or o.get("why") or "",
                                           f"status {saw['status']}" if saw.get("status") is not None else "",
                                           f"changed {json.dumps(saw['changed'])}" if saw.get("changed") else "",
                                           f"tried {'; '.join(saw['tried'])}" if saw.get("tried") else "",
                                           f"outside its folders {json.dumps(saw['outside'])}" if saw.get("outside") else "")
                               if x)
            # what the app tried is text a request may have chosen: nothing of it reaches the terminal unprintable
            print(_printable(f"{o['outcome']:13} {o['check']} / {o['case']}: {detail}"))
            if o.get("about"):
                print(_printable(f"{'':13} {o['about']}"))
    s = record["summary"]
    print(f"behave        {s['held']} held, {s['broken']} broken, {s['inconclusive']} undecided, {s['not-run']} not run "
          f"({record.get('seconds')} s inside the sandbox)")
    print(f"wrote         {out / behave.RESULT_NAME}")
    return 0 if s["held"] and not (s["broken"] or s["inconclusive"] or s["not-run"]) else 1


def cmd_explain(a) -> int:
    from .pipeline import explain, plan_explain
    from .providers import ensure_consent, make_provider, resolve_default
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    if not (out / "graph.json").exists():
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    plan = plan_explain(out, repo, a.depth, a.max_nodes, a.node or None)
    print(f"plan    {len(plan['nodes'])} functions, about {plan['input_tokens']:,} input and "
          f"{plan['output_tokens']:,} output tokens. {plan['note']}")
    if a.estimate:
        return 0
    try:
        spec, why = resolve_default(a.model)
        provider = make_provider(spec, base_url=a.base_url)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(f"model   {provider.label} ({why})")
    if not ensure_consent(provider, assume_yes=a.yes):
        print("Stopped: nothing was sent.", file=sys.stderr)
        return 3
    g = Graph.load(out / "graph.json", repo)

    def progress(i, n, nid, rec):
        flag = "ok" if rec.get("validated") else ("ERR " + rec["error"][:80] if "error" in rec else "unvalidated")
        print(f"  [{i}/{n}] {g.nodes[nid].qualname}  {flag}", flush=True)

    res = explain(out, repo, provider, plan["nodes"], metaphor=a.metaphor, progress=progress)
    st = res["stats"]
    print(f"explain {st['validated']} validated ({st['first_try']} first try), {st['failed']} failed, "
          f"{st['cached']} from cache. Tokens: {st['usage']['input_tokens']:,} in, "
          f"{st['usage']['output_tokens']:,} out. Metaphor: {res['metaphor']['world']}")
    rem = getattr(provider, "remaining", None)
    if rem and rem.get("requests") is not None:
        print(f"allowance {rem['requests']} free explanations left")
    print(f"report  {out / 'report.html'}")
    if st.get("stopped"):
        print(f"\nStopped early: {st['stopped']}", file=sys.stderr)
    return 0


def cmd_report(a) -> int:
    from .report import write_report
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    g = Graph.load(out / "graph.json", repo)
    run_meta = _load(out, "run.json") or {}
    print(write_report(out, g, _load(out, "security.json"), _load(out, "explanations.json"),
                       a.privacy or run_meta.get("privacy", "full"), run_meta.get("timings"),
                       _load(out, "readiness.json")))
    return 0


def cmd_accept(a) -> int:
    import datetime as dt
    import getpass
    from .security import load_accepted, reason_ok, save_accepted
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    accepted = load_accepted(repo)
    if a.remove:
        if accepted.pop(a.finding, None) is None:
            print(f"{a.finding} is not in the accepted list", file=sys.stderr)
            return 2
        print(f"removed {a.finding}; it counts as open again. Wrote {save_accepted(repo, accepted)}")
        return 0
    sec = _load(out, "security.json") or {"findings": []}
    f = next((x for x in sec["findings"] if x["id"] == a.finding), None)
    if f is None:
        print(f"no finding {a.finding} in the last scan; run `lantern analyze` and copy an id from Findings",
              file=sys.stderr)
        return 2
    if not reason_ok(a.reason):
        print("give a real reason (--reason, a sentence of at least 10 letters); it appears in the Evidence Report",
              file=sys.stderr)
        return 2
    accepted[f["id"]] = {"id": f["id"], "rule": f["rule"], "file": f["file"], "line": f["line"],
                         "title": f["title"], "reason": a.reason.strip(), "by": a.by or getpass.getuser(),
                         "date": dt.date.today().isoformat()}
    print(f"accepted {f['id']} ({f['rule']} at {f['file']}:{f['line']}). Wrote {save_accepted(repo, accepted)}")
    print("Re-run `lantern analyze` to update the score. Commit the file so reviewers see the reason.")
    return 0


def cmd_starter(a) -> int:
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    rd = _load(out, "readiness.json")
    if rd is None:
        print("run `lantern analyze` first", file=sys.stderr)
        return 2
    files = rd.get("starter", {})
    if not files:
        print("nothing to generate: every starter file already exists")
        return 0
    if not a.write:
        for name, f in files.items():
            print(f"--- {name}{'  (snippet: paste into your code)' if f.get('snippet') else ''}\n# {f['why']}\n"
                  f"{f['content']}")
        print("Write one with: lantern starter PATH --write NAME   (or --write all)")
        return 0
    names = [n for n, f in files.items() if not f.get("snippet")] if a.write == ["all"] else a.write
    for name in names:
        f = files.get(name)
        if f is None or f.get("snippet"):
            print(f"skip {name}: not a writable starter file", file=sys.stderr)
            continue
        dest = (repo / name).resolve()
        if repo not in dest.parents:
            print(f"skip {name}: outside the repository", file=sys.stderr)
            continue
        if dest.exists():
            print(f"skip {name}: already exists, not overwritten")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f["content"], encoding="utf-8")
        print(f"wrote {dest.relative_to(repo)}")
    return 0


def cmd_learn(a) -> int:
    from . import learn, pipeline
    here = Path(a.dir or ".").resolve()
    if a.show_fix:
        sid = learn.starter_of(here)
        text = learn.solution_text(sid, Path(a.show_fix).as_posix()) if sid else None
        if text is None:
            print(f"no fixed version of {a.show_fix}" + ("" if sid else " (this folder wasn't made by `lantern learn`)"),
                  file=sys.stderr)
            return 2
        print(text, end="")
        return 0
    if a.check:
        sid = learn.starter_of(here)
        if not sid:
            print("this folder wasn't made by `lantern learn`; run it in a starter app's folder", file=sys.stderr)
            return 2
        pr = learn.progress(sid, here)
        marks = {"done": "[x]", "todo": "[ ]", "unknown": "[?]", "read": "[-]"}
        extra = f" (+{pr['explore']} to explore on your own)" if pr.get("explore") else ""
        print(f"{pr['title']}: {pr['done']} of {pr['total']} checked steps done{extra}")
        for st in pr["steps"]:
            print(f"  {marks[st['status']]} {st['n']}. {st['title']}" + (f"  ({st['why']})" if st["why"] else ""))
        return 0
    if not a.name:
        print("Starter apps: build one, then fix it with Lantern step by step.\n")
        for s in learn.catalog():
            print(f"  {s['id']:<16} {s['title']}  [{s['stack']}, ~{s['minutes']} min]")
            print(f"  {'':<16} teaches: {', '.join(s['teaches'])}\n")
        print("Create one with: lantern learn NAME [FOLDER]   (then `lantern serve FOLDER` and open the Guide tab)")
        return 0
    dest = Path(a.dir or a.name).resolve()
    try:
        files = learn.scaffold(a.name, dest, solved=a.solved)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(f"created {dest} ({len(files)} files)")
    # Analyze right away: this first run is the "before" that the Evidence Report compares your fixes with.
    pipeline.analyze(dest, pipeline.out_dir(dest), offline=a.offline or None)
    print(f"\nNext: lantern serve {dest}   and open the Guide tab (or read {dest / 'TUTORIAL.md'}).")
    print(f"Check your progress any time with: lantern learn --check {dest}")
    return 0


def cmd_login(a) -> int:
    from .providers import ProviderError, save_token, sign_in_claim, sign_in_providers, sign_in_start
    if a.token:
        print(f"saved   {save_token(a.token)}  (the default model now uses the free allowance)")
        return 0
    provider = "github" if a.github else "google" if a.google else None
    if provider is None:
        avail = sign_in_providers()
        print("Get a free allowance (about 300 explanations with Claude Haiku) by signing in once:")
        for p in avail or ["github", "google"]:
            print(f"  lantern login --{p}")
        print("Or save a token you already have:  lantern login --token lt_...")
        return 0
    start = sign_in_start(provider)
    print(f"Sign in with {provider.capitalize()} in your browser:\n  {start['url']}")
    if not a.no_browser:
        import webbrowser
        try:
            webbrowser.open(start["url"])
        except Exception:  # noqa: BLE001: no browser is fine, the link is printed
            pass
    print("waiting for the sign-in to finish (up to 5 minutes)...", flush=True)
    import time as _time
    deadline = _time.time() + 300
    while _time.time() < deadline:
        try:
            tok = sign_in_claim(start["cli"])
        except ProviderError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if tok:
            print(f"saved   {save_token(tok)}  (the default model now uses the free allowance)")
            return 0
        _time.sleep(2)
    print("timed out. Run the command again, or paste the token from the browser page: lantern login --token lt_...",
          file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    """Run one command. A place Lantern will not write to (`results.Refused`: a results folder that is a link which
    came with the project, a folder under a result file's name) ends the command with 2 and the reason in plain
    words; what a write met and replaced (a link, a pipe) and no run's log has said yet goes to stderr."""
    from . import results
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return _main(argv)
    except results.Refused as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        if argv[:1] not in (["mcp"], ["serve"]):
            for line in results.said():
                print(f"note    {line}", file=sys.stderr)


def _main(argv: list[str]) -> int:
    if os.environ.get("LANTERN_SANDBOX_GUARD") == "expected":   # a step of the cloud service: is its guard here?
        from ._jail import say_if_guard_missing
        say_if_guard_missing()
    if argv[:1] == ["mcp"]:   # its own small parser; stdout belongs to the protocol
        from .mcp_server import main as mcp_main
        return mcp_main(argv[1:])
    argv, trace_cmd = _split_cmd(argv)
    p = argparse.ArgumentParser(prog="lantern", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"lantern {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("path", nargs="?", default=".")
        sp.add_argument("--out", help="results folder (default PATH/.lantern)")

    sp = sub.add_parser("analyze", help="build graph, scan, write report")
    common(sp)
    sp.add_argument("--trace", action="store_true", help="also run the command after -- and record real calls")
    sp.add_argument("--no-scan", action="store_true")
    sp.add_argument("--offline", action="store_true",
                    help="skip dependency audits (pip-audit, npm audit), the only steps that use the network")
    sp.add_argument("--privacy", choices=["full", "structure"], default="full",
                    help="full embeds function source in the report; structure leaves it out")
    sp.add_argument("--fail-on", choices=RANKS, help="exit 1 if any open finding is at this rank or worse (for CI)")
    sp.add_argument("--require", choices=["not-blocked", "passed"],
                    help="exit 1 unless this run's release decision is good enough (for CI): not-blocked stops on "
                         "Blocked; passed also stops on Incomplete, so it needs the tests run (--trace) and passing")

    sp = sub.add_parser("trace", help="run a command and mark calls that actually happen")
    common(sp)

    sp = sub.add_parser("behave", help="start the app in the test sandbox and run the project's lantern-behaviour.json")
    common(sp)

    sp = sub.add_parser("explain", help="add Three-Lens explanations")
    common(sp)
    sp.add_argument("--model", help="PROVIDER/MODEL. Default: anthropic/claude-haiku-5-5 with ANTHROPIC_API_KEY, "
                    "else the free allowance after `lantern login`. Others: ollama/<model> (local), "
                    "anthropic/<model>, openai/<model>, gemini/<model>, openrouter/<model>")
    sp.add_argument("--yes", action="store_true", help="agree to send function source to the chosen provider")
    sp.add_argument("--base-url", help="for openai-compatible endpoints")
    sp.add_argument("--depth", type=int, default=3, help="call depth from entry points (default 3)")
    sp.add_argument("--max-nodes", type=int, default=40, help="cap on functions explained (default 40)")
    sp.add_argument("--node", action="append", help="explain just this qualname (repeatable)")
    sp.add_argument("--metaphor", help='fix the metaphor world, e.g. "a hotel"')
    sp.add_argument("--estimate", action="store_true", help="show the token estimate and stop")

    sp = sub.add_parser("login", help="get or save a free-allowance token (Claude Haiku, hosted by Lantern)")
    sp.add_argument("--token", help="a token you already have")
    sp.add_argument("--github", action="store_true", help="sign in with GitHub in your browser")
    sp.add_argument("--google", action="store_true", help="sign in with Google in your browser")
    sp.add_argument("--no-browser", action="store_true", help="print the link instead of opening it")

    sub.add_parser("allowance", help="show what's left of the free allowance")

    sp = sub.add_parser("report", help="rebuild report.html")
    common(sp)
    sp.add_argument("--privacy", choices=["full", "structure"])

    sp = sub.add_parser("accept", help="accept a finding's risk with a written reason")
    common(sp)
    sp.add_argument("finding", help="finding id (shown in the Findings tab)")
    sp.add_argument("--reason", help="why this risk is acceptable; shown in the Evidence Report")
    sp.add_argument("--by", help="who accepted it (default: your username)")
    sp.add_argument("--remove", action="store_true", help="un-accept: the finding counts as open again")

    sp = sub.add_parser("starter", help="show or write generated starter files (Dockerfile, CI, .env.example, ...)")
    common(sp)
    sp.add_argument("--write", nargs="+", metavar="NAME", help="file name(s) to write, or `all`; never overwrites")

    sp = sub.add_parser("evidence", help="rebuild the Evidence Report from saved results")
    common(sp)
    sp.add_argument("--reset-baseline", action="store_true", help="treat the current findings as the new 'before'")

    sp = sub.add_parser("verify", help="re-run the analysis and compare with an Evidence Report's digest")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--digest", help="sha256:... from the report")
    sp.add_argument("--report", help="evidence.html (or .json) to read the digest and run options from")
    sp.add_argument("--no-scan", action="store_true", help="the report was made with --no-scan (read from --report)")
    sp.add_argument("--offline", action="store_true", help="skip the dependency audits (read from --report)")

    sp = sub.add_parser("mcp", help="serve Lantern to an AI assistant over MCP (stdio); --setup prints config")

    sp = sub.add_parser("packs", help="list the analysis packs (rule and framework pattern files) in use and check them")
    common(sp)

    sp = sub.add_parser("export", help="export findings as SARIF for GitHub code scanning and other tools")
    common(sp)
    sp.add_argument("--sarif", metavar="FILE", default="-", help="write here (default: stdout)")

    sp = sub.add_parser("usage", help="anonymous usage counts: off by default; --show prints exactly what would be sent")
    sp.add_argument("--on", action="store_true")
    sp.add_argument("--off", action="store_true")
    sp.add_argument("--show", action="store_true")

    sp = sub.add_parser("learn", help="list starter apps, create one to learn Lantern, or check your progress")
    sp.add_argument("name", nargs="?", help="starter to create (omit to list them)")
    sp.add_argument("dir", nargs="?", help="folder to create it in (default ./NAME); with --check/--show-fix, the app's folder")
    sp.add_argument("--check", action="store_true", help="show which steps are done in this starter app")
    sp.add_argument("--show-fix", metavar="FILE", help="print the fixed version of FILE")
    sp.add_argument("--solved", action="store_true", help="create it with every fix already applied")
    sp.add_argument("--offline", action="store_true", help="skip the dependency audits in the first analysis")

    sp = sub.add_parser("serve", help="open the Lantern app in your browser (projects, map, findings, readiness)")
    sp.add_argument("paths", nargs="*", help="project folders to add (analyzed on first open)")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (this computer only)")
    sp.add_argument("--no-open", action="store_true", help="don't open a browser")
    sp.add_argument("--check", action="store_true",
                    help="start, print the link, load the app once, then stop (exit 0 if it answered)")

    a = p.parse_args(argv)
    # A repository link instead of a folder: clone it (shallow) under ~/.lantern/repos and go on from there.
    from . import remote
    try:
        if remote.looks_like_url(getattr(a, "path", None) or ""):
            a.path = str(remote.clone(a.path, log=lambda m: print(m, file=sys.stderr)))
        if a.cmd == "serve":
            a.paths = [str(remote.clone(x, log=lambda m: print(m, file=sys.stderr))) if remote.looks_like_url(x) else x
                       for x in a.paths]
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    from . import usage
    usage.record({"analyze": "analyze", "trace": "trace", "explain": "explain", "verify": "verify", "export": "export_sarif",
                  "packs": "packs", "learn": "learn", "evidence": "evidence", "accept": "accept", "starter": "starter"}.get(a.cmd, ""))
    if a.cmd != "serve" and usage.enabled():
        import atexit
        from .providers import gateway_url
        atexit.register(usage.send, gateway_url(), 3.0)
    if a.cmd == "analyze":
        return cmd_analyze(a, trace_cmd if a.trace else [])
    if a.cmd == "trace":
        return cmd_trace(a, trace_cmd)
    if a.cmd == "behave":
        return cmd_behave(a)
    if a.cmd == "explain":
        return cmd_explain(a)
    if a.cmd == "login":
        return cmd_login(a)
    if a.cmd == "allowance":
        from .providers import ProviderError, allowance_status
        try:
            st = allowance_status()
        except ProviderError as e:
            print(f"{e}. Run `lantern login --token <token>` first.", file=sys.stderr)
            return 2
        print(f"used    {st['used_requests']} of {st['limit_requests']} explanations "
              f"({st['used_tokens']:,} of {st['limit_tokens']:,} tokens); "
              f"{st['remaining_requests']} left, {st['remaining_today']} today")
        return 0
    if a.cmd == "accept":
        return cmd_accept(a)
    if a.cmd == "starter":
        return cmd_starter(a)
    if a.cmd == "evidence":
        return cmd_evidence(a)
    if a.cmd == "verify":
        return cmd_verify(a, trace_cmd)
    if a.cmd == "usage":
        from . import usage
        if a.on:
            usage.set_enabled(True)
        if a.off:
            usage.set_enabled(False)
        print(usage.describe())
        return 0
    if a.cmd == "packs":
        return cmd_packs(a)
    if a.cmd == "export":
        return cmd_export(a)
    if a.cmd == "learn":
        if (a.check or a.show_fix) and a.name and not a.dir:
            a.dir, a.name = a.name, None   # `lantern learn --check FOLDER`
        return cmd_learn(a)
    if a.cmd == "serve":
        from .server import serve
        return serve(a.paths, host=a.host, port=a.port, open_browser=not a.no_open and not a.check, check=a.check)
    return cmd_report(a)


if __name__ == "__main__":
    raise SystemExit(main())
