"""lantern: map, explain, audit, and grade a full-stack app (Python + TypeScript/JavaScript).

  lantern serve [PATH ...]                                the local app in your browser (start here)
  lantern learn [NAME [DIR]]                              create a starter app to learn Lantern step by step
  lantern analyze PATH [--trace -- python -m pytest -q]   build the graph, scan, write report
  lantern workspace PROJECT PROJECT ... [--name NAME]     several folders or repository links checked as one map
  lantern diff [PATH] [BASE..HEAD]                        what a change does: two versions checked and compared
  lantern hook install [PATH]                             before each push: stop a change that blocks a release
  lantern trace PATH -- python -m pytest -q               record what actually runs
  lantern behave PATH                                     start the app in the sandbox and run its lantern-behaviour.json
  lantern behave PATH --init [--force]                    run nothing: write a first lantern-behaviour.json from the code
  lantern browse PATH                                     open the project's own site in a real browser and say what it saw
  lantern explain PATH                                    add Three-Lens explanations (Claude Haiku by default)
  lantern login --github | --google                        get a free allowance (sign in once)
  lantern login --token TOKEN                             use a token you already have
  lantern allowance                                       see how much of it is left
  lantern report PATH                                     rebuild report.html from saved results
  lantern accept PATH FINDING_ID --reason "..."           record an accepted risk (committed in the repo)
  lantern fix brief PATH FINDING_ID                       what a fix of one finding has to show (the fix contract)
  lantern fix check PATH FINDING_ID [-- TEST COMMAND]     hold a fix to that contract: passed, refused or incomplete
  lantern starter PATH [--write NAME]                     show or write generated starter files
  lantern evidence PATH                                   rebuild the commit-pinned Evidence Report
  lantern verify PATH --report evidence.html [-- CMD]     re-run the analysis the same way and compare
  lantern mcp [PATH ...] [--setup]                        serve Lantern to AI assistants (Claude, ChatGPT, Cursor)
  lantern packs PATH                                      list and check the analysis packs a project uses
  lantern export PATH --sarif out.sarif                   findings as SARIF (GitHub code scanning and others)
  lantern usage [--on | --off | --show]                   anonymous usage counts (off by default; --show prints the ping)
  lantern cache [--clear]                                 what Lantern keeps between runs to be faster; --clear removes it

Results live in PATH/.lantern/ (override with --out).
"""

from __future__ import annotations

import argparse
import contextlib
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


def _minutes(text: str) -> int:
    """`--test-minutes N`: a whole number from 1 to 240, or the parser says so."""
    from . import sandbox
    try:
        return sandbox.time_limit(text) // 60
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _megabytes(text: str) -> int:
    """`--test-memory N`: the megabytes of memory the tests may have in use in the sandbox (`sandbox.memory_limit`)."""
    from . import sandbox
    try:
        return sandbox.memory_limit(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def cmd_analyze(a, trace_cmd: list[str]) -> int:
    from .pipeline import analyze
    repo = Path(a.path).resolve()
    test_cwd = ""
    if a.sandbox:   # the sandbox runs test commands only (as in the app); said before anything is read or written
        from . import sandbox
        try:
            language = sandbox.check_command(trace_cmd)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        found = sandbox.detect(repo)             # started in the folder the app would start them in
        test_cwd = found.get("cwd", "") if found.get("language") == language else ""
    out = _out(repo, a.out)
    try:
        res = analyze(repo, out, a.privacy, trace_cmd, a.no_scan, offline=a.offline or None, sandbox=a.sandbox,
                      test_cwd=test_cwd, test_minutes=a.test_minutes, test_memory=a.test_memory,
                      typecheck=True if a.typecheck else None)
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


def cmd_workspace(a) -> int:
    """`lantern workspace` (lantern/workspace.py): several projects copied side by side and checked as one map, so a
    request one of them makes is linked to the route of another that answers it."""
    from . import workspace
    from .pipeline import analyze

    def say(line):
        print(line, file=sys.stderr)

    try:
        if a.list:
            recs = workspace.listed()
            if not recs:
                print("No workspace yet: `lantern workspace FOLDER FOLDER ...` makes one.")
            for rec in recs:
                print(f"{rec['name']}   made {rec.get('made') or '?'}   {workspace.folder_of(rec['name'])}")
                for m in rec["members"]:
                    at = str(m.get("commit") or "")[:12] or "no commit"
                    print(f"  {_printable(str(m.get('name')))}   {_printable(str(m.get('source')))}   ({at}"
                          f"{', changes not committed' if m.get('dirty') else ''})")
            return 0
        if a.remove:
            workspace.remove(a.remove)
            print(f"removed  the workspace {a.remove}: its copies and its record (the projects themselves are untouched)")
            return 0
        if a.members:
            rec = workspace.make(a.members, name=a.name, log=say)
        elif a.name:
            rec = workspace.again(a.name, log=say)
        else:
            print("error: name two projects or more (folders or repository links), or give --name of a workspace "
                  "made before, --list or --remove NAME", file=sys.stderr)
            return 2
    except workspace.Refused as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    folder = workspace.folder_of(rec["name"])
    print(f"workspace {rec['name']}: " + ", ".join(
        f"{m['name']}" + (f" at {str(m['commit'])[:12]}" if m.get("commit") else " (no commit)")
        for m in rec["members"]) + f"  ({folder})")
    out = _out(folder, a.out)
    try:
        analyze(folder, out, a.privacy, offline=a.offline or None)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"again   lantern workspace --name {rec['name']}   (copies the projects anew and checks them)")
    print(f"serve   lantern serve {folder}")
    return 0


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
    from . import typecheck as types
    # the person's word, by the flag or by LANTERN_TYPECHECK in their own shell; never the report's
    r = evidence.verify(repo, want, old, trace_cmd, a.no_scan, a.offline,
                        beside=Path(a.report).resolve().parent if a.report else None,
                        typecheck=bool(a.typecheck) or types.asked())
    if r.get("refused") and r.get("typecheck"):
        print(r["refused"] + "\n  lantern verify " + (a.path or ".") + f" --report {a.report} --typecheck",
              file=sys.stderr)
        return 2
    if r.get("refused"):
        # the report's words are shown as what the report says, never as a line to run (`evidence.words_shown`)
        print(r["refused"] + "\n  the command the report names, word by word: " + evidence.words_shown(r["trace_command"])
              + "\n  if it is the project's own test command, type it yourself after:  lantern verify "
              + (a.path or ".") + f" --report {a.report} --", file=sys.stderr)
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


def _size(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 100_000 else f"{n / 1e3:.1f} KB"


def cmd_cache(a) -> int:
    """What is kept between runs (`lantern/kept.py`): how much, where, and how to do without it."""
    from . import kept
    where = kept.home()
    if a.clear:
        n, size = kept.size()
        _, stayed = kept.clear()
        print(f"removed {n} kept answers ({_size(size)}) from {where}" if n else f"nothing is kept in {where}")
        if stayed:
            print(f"{stayed} files could not be removed", file=sys.stderr)
        return 1 if stayed else 0
    n, size = kept.size()
    if not n:
        print(f"nothing is kept in {where}")
    else:
        print(f"{n} kept answers ({_size(size)}) in {where}")
        print("  how each file of a project reads and what the outside scanner said about a set of files, by their content;")
        print("  never a finding, a rank or a score: those are worked out in every run")
    print(f"  kept work is {'on' if kept.on() else 'off'}: LANTERN_CACHE=off runs without it, "
          f"LANTERN_CACHE_MB sets how much may be kept (now {kept.cap_bytes() // (1024 * 1024)} MB), "
          "`lantern cache --clear` removes it")
    return 0


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


def _write_named(repo: Path, dest: Path, text: str, newline: str | None = None) -> None:
    """Write a file the person named on the command line. The name is theirs, so it is written as they wrote it
    (a link of their own is followed, `/dev/stdout` works), with one exception: a link that lies inside the project
    came with the project, and Lantern puts its own file in that link's place (`results.write`). `newline` as for
    `open`: None writes this system's line ends, as a report is written; "" writes the text as it is, which a patch
    needs (its lines end as the lines of the files it changes end, and Windows' own line ends on top of those give
    a file no tool applies)."""
    from . import results
    if results.link_in_project(repo, dest):
        results.write(dest, text, newline=newline, where="the project folder")
    else:
        dest.write_text(text, encoding="utf-8", newline=newline)


def cmd_diff(a) -> int:
    """`lantern diff [PATH] [BASE..HEAD]` (lantern/diff.py): two versions of the project checked and compared."""
    from . import diff, gitfacts
    from .pipeline import change
    path, spec = a.path, a.range
    if spec is None and path != "." and not Path(path).is_dir():
        path, spec = ".", path          # `lantern diff main..HEAD`: one word that is no folder is the two versions
    repo = Path(path).resolve()
    quiet = a.format != "line"
    try:
        got = change(repo, spec, out=a.out, offline=a.offline or None, base_results=a.base_results,
                     head_results=a.head_results, base_label=a.base_label, head_label=a.head_label,
                     privacy=a.privacy, log=(lambda line: print(line, file=sys.stderr)) if quiet else print)
    except (gitfacts.NoCommit, diff.NotResults) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.format == "md":
        sys.stdout.write(diff.markdown(got["receipt"], short=a.short))
    elif a.format == "json":
        sys.stdout.write(json.dumps(got["receipt"], indent=1) + "\n")
    else:
        for name in ("html", "md", "json"):
            print(f"wrote   {got['paths'][name]}")
    if a.require:
        return _require_not_blocked(got["receipt"], quiet)
    return 0


MOST_BLOCKERS = 12      # lines a check of a change prints of what blocks; the rest are counted (all are in the receipt)


def _require_not_blocked(receipt: dict, quiet: bool) -> int:
    """`lantern diff --require not-blocked`: 1 when the change itself brings what blocks a release
    (`diff.blockers`), else 0. What blocked the project before the change and still does is the project's, not the
    change's: a project blocked before stays allowed a change that adds nothing that blocks, and the words say so."""
    from . import diff
    rows = diff.blockers(receipt)
    rel = receipt.get("release") or {}
    if rows:
        print(f"fail    this change brings what blocks a release ({len(rows)}):", file=sys.stderr)
        for row in rows[:MOST_BLOCKERS]:
            print(f"fail      - {_printable(row['words'])[:300]}", file=sys.stderr)
        if len(rows) > MOST_BLOCKERS:
            print(f"fail      and {len(rows) - MOST_BLOCKERS} more (all of them are in the receipt)", file=sys.stderr)
        return 1
    after = (rel.get("after") or {}).get("decision")
    words = "pass    this change brings nothing that blocks a release"
    if after == "Blocked":
        words += " (the release decision was Blocked before it, for what was there already, and is still Blocked)"
    print(words, file=sys.stderr if quiet else sys.stdout)
    return 0


def cmd_hook(a) -> int:
    """`lantern hook install|remove|status [PATH]` and `lantern hook run` (lantern/hook.py): an opt-in check of what
    each push sends, before it leaves this computer."""
    from . import hook
    if a.hook_cmd == "run":
        for stream in (sys.stdout, sys.stderr):     # git shows the hook's words as they come: never stop on a sign
            with contextlib.suppress(AttributeError, ValueError):
                stream.reconfigure(errors="replace")
        lines = sys.stdin.read().splitlines() if not sys.stdin.isatty() else []
        return hook.run(Path.cwd(), a.remote, lines)
    repo = Path(a.path).resolve()
    try:
        if a.hook_cmd == "install":
            got = hook.install(repo)
            print(f"wrote   {got['path']}")
            print("Before each push Lantern now checks what the push sends, and stops it when the change brings what "
                  "blocks a release. `git push --no-verify` pushes once without the check; `lantern hook remove` "
                  "takes it away.")
            return 0
        if a.hook_cmd == "remove":
            got = hook.remove(repo)
            print(f"removed {got['path']}" if got["removed"] else
                  f"There is no pre-push hook of Lantern's in this repository ({got['path']}): nothing to remove.")
            return 0
        got = hook.status(repo)
        print(got["words"])
        return 0
    except hook.Refused as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


FIX_NOT_OPEN = ("{id} is not an open finding of this project's last check (ids change when the flagged line changes, "
                "and a finding the project accepted is not open). The Findings page and `lantern analyze` show what "
                "is open.")
FIX_RESULT = {"passed": 0, "refused": 1, "incomplete": 3}


def cmd_fix(a, trace_cmd: list[str]) -> int:
    """`lantern fix brief|check [PATH] FINDING` (lantern/fixcheck.py): what the fix of one finding has to show, and
    whether a fix shows it. Ends with 0 when the fix passed, 1 when it is refused, 3 when nothing is broken and a
    part is not shown (the tests were not run), 2 when nothing could be checked. Nothing here accepts, closes or
    re-ranks a finding, and Lantern applies no change to the project."""
    from . import diff, fixcheck
    from .server import home_dir
    repo = Path(a.path).resolve()
    out = _out(repo, a.out)
    try:
        if a.fix_cmd == "brief":
            from .mcp_server import fix_brief
            got = fix_brief(repo, out, home_dir(), a.finding.strip())
            if got is None:
                print("error: " + FIX_NOT_OPEN.format(id=_printable(a.finding[:80])), file=sys.stderr)
                return 2
            lines, data = got
            if a.format == "json":
                sys.stdout.write(json.dumps(data, indent=1) + "\n")
                return 0
            fid = data["finding"]["id"]
            print(_printable_lines("\n".join(lines)))
            print(f"When the fix is written:  lantern fix check {a.path} {fid} -- <the command that runs your tests>")
            print("Nothing here accepts or closes a finding. A risk that is meant to stay is accepted by a person, "
                  "with `lantern accept` and a written reason.")
            return 0
        from .pipeline import fix_check
        quiet = a.format == "json"
        got = fix_check(repo, a.finding.strip(), out=a.out, candidate=a.candidate, trace_cmd=trace_cmd,
                        suggest=bool(a.suggest), offline=a.offline or None, test_minutes=a.test_minutes,
                        test_memory=a.test_memory, log=lambda line: print(line, file=sys.stderr))
    except (diff.NotResults, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    result, sug = got["result"], got["suggestion"]
    wrote = None
    if sug and sug["text"] is not None:
        dest = Path(a.suggest)
        _write_named(repo, dest, sug["text"], newline="")         # a patch: byte for byte, on every system
        wrote = str(dest)
    if quiet:
        sys.stdout.write(json.dumps({"finding": got["finding"], "verdict": result["verdict"], "contract": result,
                                     "compared_with": got["compared_with"], "candidate": got["candidate"],
                                     "files": got["files"], "tests_ran": got["tests"] is not None,
                                     "suggestion": {"written": wrote, "why": sug["why"]} if sug else None},
                                    indent=1) + "\n")
    else:
        print(f"Compared with {got['compared_with']['words']}.")
        print(_printable_lines(fixcheck.text(result).rstrip()))
        if "tests" in result["not_shown"] and not trace_cmd:
            print(f"To have the tests run on the fixed code, give the command that runs them:  lantern fix check "
                  f"{a.path} {got['finding']} -- <test command>")
        if wrote:
            print(f"wrote   {wrote} (the suggested change; Lantern applied nothing)")
    if sug and sug["text"] is None:
        passed = result["verdict"] == fixcheck.PASSED       # passed, and still not something a patch can carry
        print(f"{'error: ' if passed else 'note    '}no suggested change was written: {_printable(sug['why'] or '')}",
              file=sys.stderr)
        if passed:
            return 2
    return FIX_RESULT.get(result["verdict"], 2)


def _printable_lines(text: str) -> str:
    return "\n".join(_printable(x) for x in text.split("\n"))


def cmd_github(a) -> int:
    """`lantern github setup|summary|save` (lantern/onrepo.py): what Lantern leaves on the repository it checked."""
    from . import onrepo, results
    repo = Path(a.path).resolve()
    try:
        if a.gh == "setup":
            for line in onrepo.setup(repo, ref=a.ref, readme=not a.no_readme, force=a.force):
                print(line)
            print("\nWhat is left, on GitHub:")
            for i, step in enumerate(onrepo.setup_steps(), 1):
                print(f"  {i}. {step}")
            return 0
        out = _out(repo, a.out)
        if a.gh == "summary":
            ev = onrepo.read(out)
            receipt = None
            if a.change and not a.decision_only:
                from . import diff
                try:
                    receipt = diff.read(a.change)
                except diff.NotResults:
                    receipt = {}                    # said in the text; the report itself is still given
            print(onrepo.decision_of(ev) if a.decision_only else
                  onrepo.summary(ev, short=a.short, run_url=a.run_url, report_url=a.report_url, change=receipt),
                  end="\n" if a.decision_only else "")
            return 0
        for p in onrepo.save(repo, out, a.to, run_url=a.run_url, report_url=a.report_url):
            print(f"wrote   {p}")
        return 0
    except (results.Refused, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


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
    from . import sandbox
    g = Graph.load(out / "graph.json", repo)
    data = run_trace(repo, trace_cmd, timeout=sandbox.time_limit(a.test_minutes) if sandbox.time_asked(a.test_minutes) else None)
    if data.get("timed_out"):   # until 2026-11-13 this ended with a Python error and left what the command had started
        had = sandbox.minutes_words(data.get("time_limit"))
        print("the command was stopped at the time limit" + (f" ({had})" if had else "") + ", with the programs it "
              "had started. Nothing was recorded and no result was changed. It can be given more time: "
              "--test-minutes N, from 1 to 240.", file=sys.stderr)
        return 1
    m = merge_trace(g, data)
    print(json.dumps(m, indent=1))
    g.save(out / "graph.json")
    run = _load(out, "run.json") or {}
    write_report(out, g, _load(out, "security.json"), _load(out, "explanations.json"),
                 run.get("privacy", "full"), run.get("timings"), _load(out, "readiness.json"))
    return 0


def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text)


MOST_SAID = 12        # `behave --init` prints this many lines of a kind; the rest are counted (all are in the file)


def _behave_init(repo: Path, a) -> int:
    """Write a first behaviour plan from the code (`lantern behave --init`, lantern/behave_init.py). Nothing of the
    project is run. 0 when a plan was written; 2 when none was, with the reason."""
    from . import behave, behave_init, results

    def say(label: str, text: str) -> None:
        # route paths, file names and settings names are the project's own text
        print(_printable(f"{label:13} {text}"))

    def listed(label: str, rows: list[str], what: str) -> None:
        for row in rows[:MOST_SAID]:
            say(label, row)
        if len(rows) > MOST_SAID:
            say(label, f"and {len(rows) - MOST_SAID} more {what} (all of them are in the file, under \"notes\")")

    try:
        made = behave_init.write(repo, force=a.force)
    except results.Refused as e:
        print(_printable(f"error: {e}"), file=sys.stderr)
        return 2
    plan = made["plan"]
    if plan is None or not made["written"]:
        print(_printable(f"not written   {made['why_not']}")
              + (" (--force writes a new one over it)" if made["exists"] and not a.force else ""))
        return 2
    app = plan["app"]
    say("app", app["asgi"] + (f" (started in {app['cwd']})" if app.get("cwd") else "")
        + (", made by calling that function" if app.get("factory") else ""))
    for name, value in (app.get("env") or {}).items():
        say("setting", f"{name}={value}")
    say("people", ", ".join(plan["people"]) + " (accounts made by the plan's first steps), and \"nobody\" with no login")
    say("plan", f"{len(plan['checks'])} checks, {made['cases']} requests")
    listed("read first", made["notes"], "notes")
    listed("look at", [f"{r['check']}: {r['why']}" for r in made["review"]], "checks to look at")
    listed("left out", [f"{r['route']}: {r['why']}" for r in made["left_out"]], "routes with no check")
    say("wrote", made["written"])
    say("next", f"read {behave.PLAN_NAME}, change what does not fit the app, then: lantern behave {a.path}")
    return 0


def cmd_behave(a) -> int:
    """Run the project's behaviour plan (docs/behaviour.md). 0 only when every case held; 1 when a case is broken,
    undecided or was not run; 2 when there is no plan or it cannot be used; 3 when the app was not started.
    With `--init` nothing is run: a first plan is written from the code (0 written, 2 not written)."""
    from . import behave
    repo = Path(a.path).resolve()
    if not repo.is_dir():
        print(f"error: {a.path} is not a folder", file=sys.stderr)
        return 2
    if a.init:
        return _behave_init(repo, a)
    if a.force:
        print("error: --force goes with --init (it writes a new plan over the one that is there)", file=sys.stderr)
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


def cmd_browse(a) -> int:
    """Open the project's own site in a real browser and say what each check saw (docs/browser.md). The record is
    written as `browser.json` in the results folder whatever came out. 0 only when a check held and every other one
    held or had nothing to check; 1 when a check is broken, undecided or was not run, or none held; 2 when there is
    nothing to open; 3 when the site was not started or no browser could be used."""
    from . import browse, results
    repo = Path(a.path).resolve()
    if not repo.is_dir():
        print(f"error: {a.path} is not a folder", file=sys.stderr)
        return 2
    out = _out(repo, a.out)
    record = browse.run(repo, browser=a.browser, log=lambda line: print(_printable(line), file=sys.stderr))
    results.write(out / browse.RESULT_NAME, json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    if not record["ran"]:
        print(f"not run       {record['why']}")
        print(f"wrote         {out / browse.RESULT_NAME}")
        return 2 if record["why_not"] == "no-site" else 3
    counts = {o: 0 for o in browse.OUTCOMES}
    for c in record["checks"]:
        counts[c["outcome"]] += 1
        if c["outcome"] in ("held", "nothing-to-check"):
            continue
        # what the browser saw is the site's own text (a page's address, a console line): printable only
        saw = "; ".join(_printable(json.dumps(s, ensure_ascii=False)) for s in (c.get("saw") or [])[:3])
        codes = ", ".join(c.get("codes") or [])
        print(_printable(f"{c['outcome']:13} {c['id']}: {codes or c.get('why') or ''}"))
        if saw:
            print(f"{'':13} {saw}")
    print(f"browse        {counts['held']} held, {counts['broken']} broken, {counts['inconclusive']} undecided, "
          f"{counts['nothing-to-check']} with nothing to check, {counts['not-run']} not run "
          f"({record.get('seconds')} s; {len(record.get('opened') or [])} pages opened)")
    print(f"wrote         {out / browse.RESULT_NAME}")
    return 0 if counts["held"] and not (counts["broken"] or counts["inconclusive"] or counts["not-run"]) else 1


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
    from .providers import ProviderError, save_token, sign_in_here, sign_in_page, sign_in_providers
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
    def show(link: str) -> None:
        print(f"Sign in with {provider.capitalize()} in a browser on this computer:\n  {link}")
        print(f"No browser on this computer? Open this one anywhere, press its Copy button, then run "
              f"`lantern login --token lt_...`:\n  {sign_in_page(provider)}")
        if not a.no_browser:
            import webbrowser
            try:
                webbrowser.open(link)
            except Exception:  # noqa: BLE001: no browser is fine, the link is printed
                pass
        print("waiting for the sign-in to finish (up to 5 minutes)...", flush=True)

    try:
        tok = sign_in_here(provider, show)
    except ProviderError as e:
        if e.status == 408:
            print("timed out. Run the command again, or paste the token from the browser page: lantern login --token lt_...",
                  file=sys.stderr)
        else:
            print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"saved   {save_token(tok)}  (the default model now uses the free allowance)")
    return 0



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
    sp.add_argument("--sandbox", action="store_true",
                    help="with --trace: run the tests in Lantern's sandbox, the way the app does (on a copy of the "
                         "project that is thrown away afterwards, kept from the internet and your network where "
                         "this system's sandbox holds them, which the run's first lines say, and with nothing "
                         "they start left running). Only a test command runs there. Without it the command runs "
                         "in the project's folder, as you")
    sp.add_argument("--test-minutes", type=_minutes, metavar="N",
                    help="with --trace: how long the tests may take, from 1 to 240 minutes (default: 10 in the "
                         "sandbox, 15 without it; LANTERN_TEST_MINUTES sets it for every run). Tests stopped at the "
                         "limit are neither passed nor failed")
    sp.add_argument("--test-memory", type=_megabytes, metavar="MB",
                    help="with --trace --sandbox: how much memory the tests and everything they start may have in "
                         "use, in megabytes from 128 to 1048576 (default: 2048; LANTERN_TEST_MEMORY_MB sets it for "
                         "every run). Tests stopped for their memory are neither passed nor failed")
    sp.add_argument("--no-scan", action="store_true")
    sp.add_argument("--typecheck", action="store_true",
                    help="also ask the type checkers installed on this computer (the TypeScript compiler, pyright) "
                         "where the calls go that Lantern's own reading left unresolved. They read the project and "
                         "run nothing of it; a copy of them inside the project is never used. Off unless asked for "
                         "(LANTERN_TYPECHECK=1 asks for it in every run)")
    sp.add_argument("--offline", action="store_true",
                    help="skip dependency audits (pip-audit, npm audit), the only steps that use the network")
    sp.add_argument("--privacy", choices=["full", "structure"], default="full",
                    help="full embeds function source in the report; structure leaves it out")
    sp.add_argument("--fail-on", choices=RANKS, help="exit 1 if any open finding is at this rank or worse (for CI)")
    sp.add_argument("--require", choices=["not-blocked", "passed"],
                    help="exit 1 unless this run's release decision is good enough (for CI): not-blocked stops on "
                         "Blocked; passed also stops on Incomplete, so it needs the tests run (--trace) and passing")

    sp = sub.add_parser("workspace", help="several projects (folders or repository links) checked as one map: a "
                                          "request one makes is linked to the route of another that answers it")
    sp.add_argument("members", nargs="*", metavar="PROJECT",
                    help="a folder or a repository link; NAME=FOLDER or NAME=LINK gives it its name in the map")
    sp.add_argument("--name", help="the workspace's name (default: made from its projects' names); given alone, the "
                                   "projects of that workspace are copied anew from where they came from and checked")
    sp.add_argument("--out", help="results folder (default: the workspace's own folder/.lantern)")
    sp.add_argument("--offline", action="store_true",
                    help="skip dependency audits (pip-audit, npm audit), the only steps that use the network")
    sp.add_argument("--privacy", choices=["full", "structure"], default="full",
                    help="full embeds function source in the report; structure leaves it out")
    sp.add_argument("--list", action="store_true", help="name the workspaces and their projects")
    sp.add_argument("--remove", metavar="NAME",
                    help="remove a workspace: its copies and its record (the projects themselves are not touched)")

    sp = sub.add_parser("trace", help="run a command and mark calls that actually happen")
    common(sp)
    sp.add_argument("--test-minutes", type=_minutes, metavar="N",
                    help="how long the command may take, from 1 to 240 minutes (default 15)")

    sp = sub.add_parser("behave", help="start the app in the test sandbox and run the project's lantern-behaviour.json")
    common(sp)
    sp.add_argument("--init", action="store_true",
                    help="run nothing: write a first lantern-behaviour.json from the code (a FastAPI app), to read, "
                         "change and commit; what Lantern was not sure of and what it left out is listed")
    sp.add_argument("--force", action="store_true",
                    help="with --init: write the new plan over a lantern-behaviour.json that is there")

    sp = sub.add_parser("browse", help="open the project's own site in a real browser and say what it saw "
                                       "(docs/browser.md)")
    common(sp)
    sp.add_argument("--browser", metavar="PATH",
                    help="the full path of the Chrome, Chromium, Edge or Brave to drive (default: LANTERN_BROWSER, "
                         "else where this system installs one)")

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
    sp.add_argument("--typecheck", action="store_true",
                    help="the report was made with --typecheck: ask this computer's type checkers again "
                         "(LANTERN_TYPECHECK=1 says the same). Never read from --report: a report does not start them")

    sp = sub.add_parser("mcp", help="serve Lantern to an AI assistant over MCP (stdio); --setup prints config")

    sp = sub.add_parser("packs", help="list the analysis packs (rule and framework pattern files) in use and check them")
    common(sp)

    sp = sub.add_parser("diff", help="what a change does to the app: two versions of the project checked and compared "
                                     "(doors, login checks, links between page and server, findings, the release decision)")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("range", nargs="?", metavar="BASE..HEAD",
                    help="the two versions: BASE..HEAD, BASE...HEAD (from the commit where the two parted, as a pull "
                         "request shows it), or BASE alone (compared with the files as they are now). With none: the "
                         "last commit compared with the files as they are now")
    sp.add_argument("--out", help="folder for the receipt and the two checks (default PATH/.lantern/change)")
    sp.add_argument("--offline", action="store_true", help="skip the dependency audits in both checks")
    sp.add_argument("--privacy", choices=["full", "structure"], default="full",
                    help="structure: keep the project's source out of the two checks' own reports")
    sp.add_argument("--base-results", metavar="DIR", help="results of a check already made of the code before the change")
    sp.add_argument("--head-results", metavar="DIR", help="results of a check already made of the code after the change")
    sp.add_argument("--base-label", metavar="WORDS", help="what the receipt calls the code before the change (\"main\")")
    sp.add_argument("--head-label", metavar="WORDS", help="what the receipt calls the code after it (\"this pull request\")")
    sp.add_argument("--format", choices=["line", "md", "json"], default="line",
                    help="what to print: where the files were written (default), the text for a pull request, or the data")
    sp.add_argument("--short", action="store_true", help="with --format md: without the list of changed functions")
    sp.add_argument("--require", choices=["not-blocked"],
                    help="exit 1 when the change itself brings what blocks a release (a critical or high finding that "
                         "is new, reached only now, ranked higher or open again, a secret, a request of the page that "
                         "no route answers any more); what blocked the project before the change is not the change's")
    sp = sub.add_parser("hook", help="an opt-in check before each push: what the push sends is compared with what the "
                                     "other side has, and a change that brings what blocks a release is stopped")
    hsub = sp.add_subparsers(dest="hook_cmd", required=True)
    for name, words in (("install", "write the pre-push hook into this repository (never over a hook of yours)"),
                        ("remove", "take Lantern's pre-push hook away (never a hook of yours)"),
                        ("status", "say whether the check before each push is on")):
        hp = hsub.add_parser(name, help=words)
        hp.add_argument("path", nargs="?", default=".")
    hp = hsub.add_parser("run", help="what the hook runs: reads what git says is being pushed on its input")
    hp.add_argument("remote", nargs="?", default=None, help="the remote's name, as git hands it to the hook")
    hp.add_argument("url", nargs="?", default=None, help="the remote's address, as git hands it to the hook")
    sp = sub.add_parser("fix", help="the fix of one finding: what it has to show (brief), and whether a fix shows it "
                                    "(check); a fix that only hides the finding is refused")
    fsub = sp.add_subparsers(dest="fix_cmd", required=True)
    fp = fsub.add_parser("brief", help="where the finding is, how it is reached, and the contract a fix is held to; "
                                       "keeps the check as it is now as the one the fix is compared with")
    common(fp)
    fp.add_argument("finding", help="finding id (shown in the Findings tab), or the beginning of one")
    fp.add_argument("--format", choices=["text", "json"], default="text")
    fp = fsub.add_parser("check", help="check the project again and hold the fix to the contract: 0 passed, 1 refused, "
                                       "3 incomplete. After --, the command that runs the project's tests: it runs "
                                       "in the sandbox, and without it the fix cannot pass")
    common(fp)
    fp.add_argument("finding", help="finding id (shown in the Findings tab), or the beginning of one")
    fp.add_argument("--candidate", metavar="DIR",
                    help="the fix stands in this folder (the project with the fix in it) and not in the project: its "
                         "change is put onto a copy of the project that is thrown away, and checked there. The "
                         "project and its results are left as they are")
    fp.add_argument("--suggest", metavar="FILE",
                    help="with --candidate: write the change to FILE as a patch for a person to apply, only when the "
                         "fix passed. Lantern applies nothing and sends nothing anywhere")
    fp.add_argument("--offline", action="store_true",
                    help="skip the dependency audits, and fetch no libraries for the tests")
    fp.add_argument("--test-minutes", type=_minutes, metavar="N",
                    help="how long the tests may take, from 1 to 240 minutes (default: 10)")
    fp.add_argument("--test-memory", type=_megabytes, metavar="MB",
                    help="how much memory the tests may have in use, in megabytes (default: 2048)")
    fp.add_argument("--format", choices=["text", "json"], default="text",
                    help="what to print: the verdict part by part (default), or the data")

    sp = sub.add_parser("github", help="leave Lantern's report on the GitHub repository it checked: setup, summary, save")
    gsub = sp.add_subparsers(dest="gh", required=True)
    gp = gsub.add_parser("setup", help="write the workflow that checks every push and pull request, the badge and its "
                                       "line in README.md")
    gp.add_argument("path", nargs="?", default=".")
    gp.add_argument("--ref", help="the version of Lantern's GitHub Action to use (default: this Lantern's)")
    gp.add_argument("--no-readme", action="store_true", help="leave README.md as it is")
    gp.add_argument("--force", action="store_true", help="replace a workflow file of that name that is not Lantern's")
    for name, what in (("summary", "print a finished check's result as Markdown (for a comment or a page)"),
                       ("save", "write the report folder that is kept in the repository (.lantern/report)")):
        gp = gsub.add_parser(name, help=what)
        common(gp)
        gp.add_argument("--run-url", help="link to the run that made the report (https://github.com/... only)")
        gp.add_argument("--report-url", help="link to the full report's download (https://github.com/... only)")
        if name == "summary":
            gp.add_argument("--short", action="store_true", help="the shorter form for a pull request's comment")
            gp.add_argument("--change", metavar="FILE", help="the data file of a change receipt (change.json of "
                                                             "`lantern diff`): what a pull request changes is "
                                                             "written right after the decision")
            gp.add_argument("--decision-only", action="store_true", help="print only Passed, Blocked, Incomplete "
                                                                         "or none")
        else:
            gp.add_argument("--to", help=f"the folder inside the project (default {'.lantern/report'})")

    sp = sub.add_parser("export", help="export findings as SARIF for GitHub code scanning and other tools")
    common(sp)
    sp.add_argument("--sarif", metavar="FILE", default="-", help="write here (default: stdout)")

    sp = sub.add_parser("usage", help="anonymous usage counts: off by default; --show prints exactly what would be sent")
    sp.add_argument("--on", action="store_true")
    sp.add_argument("--off", action="store_true")
    sp.add_argument("--show", action="store_true")

    sp = sub.add_parser("cache", help="what Lantern keeps between runs to be faster, on this computer only")
    sp.add_argument("--clear", action="store_true", help="remove everything that is kept")

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
    if a.cmd == "analyze" and not (a.trace and trace_cmd):
        if a.sandbox:
            p.error("--sandbox is where the tests run: give it with --trace and the test command after --, "
                    "e.g. lantern analyze . --trace --sandbox -- python -m pytest -q")
        if a.test_minutes is not None:
            p.error("--test-minutes is the time the tests get: give it with --trace and the test command after --")
    if a.cmd == "analyze" and a.test_memory is not None and not (a.sandbox and a.trace and trace_cmd):
        p.error("--test-memory is the memory the tests get in the sandbox: give it with --trace --sandbox and the "
                "test command after --")
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
    if a.cmd == "workspace":
        return cmd_workspace(a)
    if a.cmd == "trace":
        return cmd_trace(a, trace_cmd)
    if a.cmd == "behave":
        return cmd_behave(a)
    if a.cmd == "browse":
        return cmd_browse(a)
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
    if a.cmd == "diff":
        return cmd_diff(a)
    if a.cmd == "hook":
        return cmd_hook(a)
    if a.cmd == "fix":
        return cmd_fix(a, trace_cmd)
    if a.cmd == "github":
        return cmd_github(a)
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
    if a.cmd == "cache":
        return cmd_cache(a)
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
