"""The release decision (2026-11-09 directive, point 6): Blocked, Incomplete or Passed.

It is worked out from required criteria, never from the average score:

    Blocked      a required criterion failed: a critical or high finding is open outside test code, the project's
                 tests failed, a behaviour check came out broken
    Incomplete   nothing failed, and something required is missing: a scanner did not finish or did not cover
                 everything, libraries were not checked, the tests were not run, the behaviour plan was not run on
                 this code
    Passed       every required criterion that applies to this kind of project has passed

What is required is the project's profile: `findings`, `scanners` and `tests` for every project, `dependencies`
where the project lists libraries, `behaviour` where it brings a behaviour plan (`lantern-behaviour.json`). What the
profile does not ask for is named with the reason (`not_required`), so "Passed" does not read as more than it is.

The record is tied to what was tested (`bind`): the commit and whether files differ from it, a SHA-256 over every
file of the project (path and content), one for each dependency file, the settings of the run, and every tool with
its version and how its run ended. A behaviour record counts only when it is of this plan and this code and carries
this computer's seal (`seal.py`): `behaviour.json` lies in the results folder, which a project can bring along.

Nothing here creates, closes or re-ranks a finding. `readiness.assess` calls `decide` and applies the two rules the
score has: it reads 100 only when the decision is Passed, and a Blocked release cannot score above `BLOCKED_CAP`.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
from pathlib import Path

from . import __version__, scanresult, seal
from .depaudit import TEST_DIR_RE
from .python_frontend import inside_repo, project_sha256, skipped_dir

DECISIONS = ("Blocked", "Incomplete", "Passed")
STATES = ("passed", "failed", "missing", "not-applicable")
BLOCKING_RANKS = ("critical", "high")
BLOCKED_CAP = 59          # the top of grade F: a release-blocking problem is not averaged away by unrelated points
NOT_PASSED_CAP = 99       # 100 is for a passed release with complete evidence
PLAN_NAME = "lantern-behaviour.json"
AUDITS = ("pip-audit", "npm-audit", "maven-audit", "composer-audit", "gem-audit")
SHOWN = 5                 # how many findings, tools or files a sentence names before it says "and N more"

# The files that say which libraries a project uses. Each gets its own SHA-256 in the record.
DEPENDENCY_FILE = re.compile(
    r"(^|/)(requirements[^/]*\.txt|constraints[^/]*\.txt|pyproject\.toml|setup\.(py|cfg)|Pipfile(\.lock)?|poetry\.lock|"
    r"uv\.lock|pdm\.lock|package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|"
    r"go\.(mod|sum)|Cargo\.(toml|lock)|pom\.xml|build\.gradle(\.kts)?|libs\.versions\.toml|composer\.(json|lock)|"
    r"Gemfile(\.lock)?|pubspec\.(yaml|lock)|[^/]+\.csproj|packages\.lock\.json|Podfile(\.lock)?|"
    r"Package\.(swift|resolved)|conanfile\.(txt|py)|vcpkg\.json)$")
# Library lists Lantern reads no advisories for yet: a project that has one cannot have its libraries checked.
NO_AUDIT = (
    (re.compile(r"(^|/)go\.mod$"), "Go (go.mod)"),
    (re.compile(r"(^|/)Cargo\.(toml|lock)$"), "Rust (Cargo)"),
    (re.compile(r"(^|/)pubspec\.(yaml|lock)$"), "Dart and Flutter (pubspec)"),
    (re.compile(r"(^|/)([^/]+\.csproj|packages\.lock\.json)$"), ".NET (NuGet)"),
    (re.compile(r"(^|/)(Podfile(\.lock)?|Package\.(swift|resolved))$"), "Swift (CocoaPods, SwiftPM)"),
    (re.compile(r"(^|/)(conanfile\.(txt|py)|vcpkg\.json)$"), "C and C++ (Conan, vcpkg)"),
)
TITLES = {
    "findings": "No critical or high finding is open",
    "scanners": "Every scanner that applies finished and covered everything",
    "dependencies": "Every library was checked against the advisory databases",
    "tests": "The project's tests were run and passed",
    "behaviour": "The behaviour checks held when the app was started",
}
NO_PLAN = (f"The project has no behaviour plan ({PLAN_NAME}), so no app was started: nothing in this decision says "
           "what the app does when it runs.")
LEFT_OUT = ("the folders no reader of Lantern looks into: version control, installed libraries, build output, Python "
            "environments and Lantern's own results")


# ------------------------------------------------------------------------------------------------ what was tested
def listed(root: Path, leave_out: Path | None = None) -> list[str]:
    """Every file of the project, by its path from the root, sorted: what the readiness checks look at and what the
    record is tied to. Folders every reader leaves out (`python_frontend.skipped_dir`: `.git`, `node_modules`, build
    output, a Python environment, `.lantern`), the results folder of this run when it lies in the project under
    another name (`leave_out`) and anything that is not a plain file of the project (`inside_repo`) are not in it.
    A folder that is a link is not gone into, on any version of Python, so the list is the same wherever it is
    made; a file that is a link to a file of the project is in it under its own name."""
    root = Path(root)
    apart = None
    if leave_out is not None:
        try:
            apart = Path(os.path.realpath(leave_out)).relative_to(os.path.realpath(root)).parts or None
        except (OSError, ValueError):
            apart = None           # the results folder lies outside the project
    out = []
    for folder, names, files in os.walk(root):
        rel = Path(folder).relative_to(root)
        names[:] = [d for d in names if not skipped_dir(folder, d) and (rel / d).parts != apart]
        for name in files:
            p = Path(folder, name)
            if p.is_file() and inside_repo(p, root):
                out.append((rel / name).as_posix())
    out.sort()
    return out


def _sha(root: Path, rel: str) -> str | None:
    try:
        return project_sha256(root / rel, root)
    except OSError:
        return None


def code_digest(root: Path, files: list[str] | None = None, leave_out: Path | None = None) -> dict:
    """`{"files", "sha256", "not_read"}`: one SHA-256 over every file of the project (`listed`), each by its path
    and what it holds, byte for byte. A file that cannot be read is counted in `not_read` and its path alone goes
    in."""
    root = Path(root)
    files = listed(root, leave_out) if files is None else sorted(files)
    h, n, bad = hashlib.sha256(), 0, 0
    for rel in files:
        one = _sha(root, rel)
        if one is None:
            bad += 1
        else:
            n += 1
        h.update(rel.encode("utf-8", "surrogateescape") + b"\0" + (one or "unread").encode("ascii") + b"\n")
    return {"files": n, "sha256": h.hexdigest(), "not_read": bad, "left_out": LEFT_OUT}


def dependency_digests(root: Path, files: list[str]) -> dict:
    """`{"files": {path: sha256}, "count", "sha256"}` for the files that list the project's libraries; `files` holds
    the first 200 by path, `sha256` is over all of them."""
    root = Path(root)
    names = [f for f in sorted(files) if DEPENDENCY_FILE.search(f)]
    h, each = hashlib.sha256(), {}
    for rel in names:
        one = _sha(root, rel) or "unread"
        h.update(rel.encode("utf-8", "surrogateescape") + b"\0" + one.encode("ascii") + b"\n")
        if len(each) < 200:
            each[rel] = one
    return {"files": each, "count": len(names), "sha256": h.hexdigest() if names else None}


def plan_digest(root: Path) -> tuple[str | None, str | None]:
    """(the SHA-256 `lantern behave` gives the project's plan, None), (None, None) when the project has no plan, or
    (None, why) when the plan is there and cannot be used."""
    from . import behave
    try:
        plan = behave.load(Path(root))
    except behave.PlanError as exc:
        return None, str(exc)[:300]
    if plan is None:
        return None, None
    return behave.plan_sha256(plan), None


def bind(root: Path, files: list[str], sec: dict | None, run_meta: dict | None, git: dict | None = None) -> dict:
    """What the decision is about: the exact code, dependency files, settings and tools."""
    from .evidence import run_options, tool_versions
    from .packs import disabled
    root, run_meta, git = Path(root), run_meta or {}, git or {}
    plan, plan_why = plan_digest(root)
    accepted = _sha(root, "lantern-accepted.json") if "lantern-accepted.json" in files else None
    try:
        off = sorted(str(x) for x in disabled())
    except Exception:  # noqa: BLE001 - the person's settings file is odd: the packs then count as on
        off = []
    return {
        "commit": git.get("commit"), "uncommitted_changes": None if not git.get("commit") else bool(git.get("dirty")),
        "code": code_digest(root, files),
        "dependencies": dependency_digests(root, files),
        "settings": {**run_options(sec, run_meta), "place": run_meta.get("place") or "local", "packs_off": off,
                     "accepted_sha256": accepted, "plan_sha256": plan, "plan_unusable": plan_why},
        "tools": [{k: t.get(k) for k in ("tool", "version", "role", "state")} for t in tool_versions(sec)],
        "lantern": __version__, "python": platform.python_version(), "system": platform.system(),
    }


# ------------------------------------------------------------------------------------------------ the criteria
def _crit(cid: str, state: str, why: str, fix: str = "", required: bool = True, **more) -> dict:
    return {"id": cid, "title": TITLES[cid], "required": required, "state": state, "why": why, "fix": fix, **more}


def _more(items: list[str]) -> str:
    return ", ".join(items[:SHOWN]) + (f" and {len(items) - SHOWN} more" if len(items) > SHOWN else "")


def _count(x) -> int:
    """A count out of a record that may have been read back from disk: a whole number above 0, else 0."""
    return x if isinstance(x, int) and not isinstance(x, bool) and x > 0 else 0


def _n(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _findings(sec: dict | None) -> dict:
    if not sec:
        return _crit("findings", "missing", "No security scan was run, so nobody looked.",
                     "Run `lantern analyze` without --no-scan.")
    live = [f for f in sec.get("findings") or [] if not f.get("in_tests") and f.get("rank") in BLOCKING_RANKS]
    open_ = [f for f in live if f.get("status") != "accepted"]
    acc = [f for f in live if f.get("status") == "accepted"]
    said = (f"; {_n(len(acc), 'critical or high finding')} accepted by the project with a written reason"
            if acc else "")
    if open_:
        crit = sum(1 for f in open_ if f["rank"] == "critical")
        ranks = " and ".join(f"{n} {word}" for n, word in ((crit, "critical"), (len(open_) - crit, "high")) if n)
        return _crit("findings", "failed",
                     f"{ranks} finding{'' if len(open_) == 1 else 's'} open outside test code: "
                     + _more([f"{f.get('rule')} at {f.get('file')}:{f.get('line')}" for f in open_]) + said,
                     "Fix each one (the Findings tab says how), or record why the risk is acceptable with "
                     "`lantern accept ID --reason \"...\"`.", ids=[f.get("id") for f in open_][:50])
    return _crit("findings", "passed", "No critical or high finding is open outside test code, from the scanners "
                                       "that ran (they recognise known patterns, not every flaw)" + said + ".")


def _scanners(sec: dict | None) -> dict:
    if not sec:
        return _crit("scanners", "missing", "No scanner was run.", "Run `lantern analyze` without --no-scan.")
    tools = [t for t in sec.get("tools") or [] if isinstance(t, dict) and t.get("tool") not in AUDITS]
    inc = scanresult.incomplete(tools)
    if inc:
        return _crit("scanners", "missing", "Did not finish, or did not cover everything: "
                     + _more([scanresult.words(t) for t in inc]) + ". What they would have found is not in the "
                     "results.", "Install the missing scanner or fix what stopped it, then run the check again.",
                     tools=[str(t.get("tool")) for t in inc][:50])
    ran = [str(t.get("tool")) for t in tools if scanresult.state_of(t) == "ok" and scanresult.applicable(t)]
    return _crit("scanners", "passed", f"{_n(len(ran), 'scanner')} finished: {_more(ran)}.")


def _dependencies(sec: dict | None, files: list[str]) -> dict:
    # The project's own lists: what the audits read (`depaudit._project_files`). A sample app kept among the tests
    # or the examples is not what ships, and no audit reads its lists either.
    lists = [f for f in files if DEPENDENCY_FILE.search(f) and not TEST_DIR_RE.search(f)]
    none_for = sorted({name for rx, name in NO_AUDIT if any(rx.search(f) for f in lists)})
    if not sec:
        return _crit("dependencies", "missing" if lists else "not-applicable", "No library check was run.",
                     "Run `lantern analyze` without --no-scan.", required=bool(lists))
    audits = [t for t in sec.get("tools") or [] if isinstance(t, dict) and t.get("tool") in AUDITS]
    inc = scanresult.incomplete(audits)
    loose = sum(_count(t.get("unpinned")) for t in audits)
    ok = [t for t in audits if scanresult.state_of(t) == "ok" and scanresult.applicable(t)]
    gaps = []
    if inc:
        gaps.append("not checked: " + _more([scanresult.words(t) for t in inc]))
    if loose:
        gaps.append(f"{loose} librar{'y has' if loose == 1 else 'ies have'} no exact version written down, so "
                    f"{'it was' if loose == 1 else 'they were'} not checked")
    unlocked = sum(_count(t.get("unlocked")) for t in audits)
    if unlocked:
        names = [str(x)[:120] for t in audits for x in (t.get("unlocked_examples") or []) if isinstance(x, str)]
        gaps.append(f"{unlocked} librar{'y is' if unlocked == 1 else 'ies are'} named in a file with no lock file "
                    f"beside it, so no version is known and {'it was' if unlocked == 1 else 'they were'} not checked"
                    + (f" ({_more(names)})" if names else ""))
    elsewhere = sum(len(t["other_locks"]) for t in audits if isinstance(t.get("other_locks"), list))
    if elsewhere:
        gaps.append(f"the versions of {elsewhere} folder{'' if elsewhere == 1 else 's'} are in a lock file Lantern "
                    "does not read yet (pnpm, yarn, bun)")
    if none_for:
        gaps.append("Lantern has no library check yet for " + ", ".join(none_for))
    if gaps:
        said = "; ".join(gaps)
        return _crit("dependencies", "missing", said[:1].upper() + said[1:] + ".",
                     "Run the check with the network on, commit a lock file with exact versions, and check the "
                     "libraries Lantern cannot check with that language's own audit tool.")
    if not ok:
        return _crit("dependencies", "not-applicable", "The project lists no libraries in a file Lantern reads.",
                     required=False)
    return _crit("dependencies", "passed", "Every listed library was looked up: "
                 + _more([f"{t.get('tool')} ({t.get('checked')} checked)" if isinstance(t.get("checked"), int)
                          else str(t.get("tool")) for t in ok]) + ". A finding for a library with a known problem "
                 "is ranked like any other.")


def _tests(tests_exist: bool, run_meta: dict) -> dict:
    tr = run_meta.get("trace") if isinstance(run_meta.get("trace"), dict) else None
    how = ("Run them under Lantern: `lantern analyze PATH --trace -- <your test command>`, or “Watch my tests "
           "run” in the app.")
    if not tests_exist:
        return _crit("tests", "missing", "The project has no tests.",
                     "Write tests for the most important flows first (sign-in, payments, changes to data), then "
                     "run them under Lantern.")
    if not tr:
        return _crit("tests", "missing", "The tests were not run in this check. Lantern runs a project's code only "
                                         "when asked, and tests that were not run prove nothing.", how)
    if tr.get("ran") is False:
        return _crit("tests", "missing", "The tests were not run: the sandbox they run in could not be set up on "
                                         "this computer.", how)
    rc = tr.get("returncode")
    if rc == 0:
        return _crit("tests", "passed", "The tests ran in this check and ended with 0 (passed).")
    if rc is None:
        return _crit("tests", "missing", "The test run did not end by itself"
                     + (": it was stopped at the time limit." if tr.get("timed_out") else "."), how)
    if tr.get("blocked"):
        return _crit("tests", "missing", f"The tests ended with {rc} in the sandbox, which refused something they "
                                         "tried (the network, a write outside their folder). That may be the "
                                         "sandbox and not the code, so it is not counted as a failure.",
                     "Make the tests run without the network and without writing outside the project, then run "
                     "them again.")
    return _crit("tests", "failed", f"The tests ran in this check and ended with {rc} (failed).",
                 "Fix the failing tests, then run them again under Lantern.")


def _behaviour(record: dict | None, bound: dict, unread: str | None = None) -> dict:
    s = bound["settings"]
    if s.get("plan_unusable"):
        return _crit("behaviour", "missing", f"The project's behaviour plan cannot be used: {s['plan_unusable']}",
                     f"Fix {PLAN_NAME} (`lantern behave PATH` says what is wrong), then run it.")
    if not s.get("plan_sha256"):
        return _crit("behaviour", "not-applicable", NO_PLAN, required=False)
    run = "Run `lantern behave PATH` on this code, then check again."
    if unread:
        return _crit("behaviour", "missing", f"The record of the last behaviour run could not be used: {unread}.", run)
    if not isinstance(record, dict):
        return _crit("behaviour", "missing", "The project has a behaviour plan and it has not been run: there is "
                                             "no behaviour.json in the results folder.", run)
    if not seal.holds(record):
        return _crit("behaviour", "missing", "The behaviour record in the results folder does not carry this "
                                             "computer's seal: it was made somewhere else, or changed since it "
                                             "was made.", run)
    of = record.get("of") if isinstance(record.get("of"), dict) else {}
    if of.get("plan_sha256") != s["plan_sha256"]:
        return _crit("behaviour", "missing", "The behaviour record is of another plan than the one in the project "
                                             "now.", run)
    if of.get("code_sha256") != bound["code"]["sha256"]:
        return _crit("behaviour", "missing", "The behaviour record was made on other code than this: a file of "
                                             "the project changed since.", run)
    if record.get("ran") is not True:
        return _crit("behaviour", "missing", "The app was not started, or the plan's set-up failed, so no check "
                                             "was made (`lantern behave PATH` says why).", run)
    count = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    num = {k: count.get(k) if isinstance(count.get(k), int) else 0 for k in ("held", "broken", "inconclusive", "not-run")}
    total = sum(num.values())
    if num["broken"]:
        names = [f"{o.get('check')} / {o.get('case')}" for o in record.get("outcomes") or []
                 if isinstance(o, dict) and o.get("outcome") == "broken"]
        return _crit("behaviour", "failed", f"{num['broken']} of {_n(total, 'case')} came out broken when the app "
                                            f"was started: {_more(names)}.",
                     "Fix what each broken case shows (`lantern behave PATH` prints what happened), then run it "
                     "again.")
    if num["inconclusive"] or num["not-run"] or not num["held"]:
        return _crit("behaviour", "missing", f"{num['held']} of {_n(total, 'case')} held; {num['inconclusive']} "
                                             f"could not be decided and {num['not-run']} were not run.", run)
    return _crit("behaviour", "passed", f"All {_n(total, 'case')} of the plan held when the app was started in "
                                        "the sandbox, on this code and this plan.")


# ------------------------------------------------------------------------------------------------ the decision
def decide(*, shape: str, sec: dict | None, tests_exist: bool, run_meta: dict | None, files: list[str],
           bound: dict, behaviour: dict | None = None, behaviour_unread: str | None = None) -> dict:
    """The release decision with every criterion, the profile it was made for and what it is tied to."""
    criteria = [_findings(sec), _scanners(sec), _dependencies(sec, files), _tests(tests_exist, run_meta or {}),
                _behaviour(behaviour, bound, behaviour_unread)]
    required = [c for c in criteria if c["required"]]
    failed = [c for c in required if c["state"] == "failed"]
    missing = [c for c in required if c["state"] == "missing"]
    decision = "Blocked" if failed else "Incomplete" if missing else "Passed"
    if failed:
        words = "Blocked: " + " ".join(c["why"] for c in failed)
    elif missing:
        words = "Incomplete: nothing that was checked blocks a release, and required evidence is missing. " + \
                " ".join(c["why"] for c in missing)
    else:
        words = (f"Passed: every criterion required for this kind of project ({shape}) passed, on exactly the "
                 "code, libraries, settings and tools named below.")
    return {
        "decision": decision, "words": words,
        "profile": {"name": shape, "required": [c["id"] for c in required],
                    "not_required": [{"id": c["id"], "why": c["why"]} for c in criteria if not c["required"]]},
        "criteria": criteria, "blocking": [c["id"] for c in failed], "missing": [c["id"] for c in missing],
        "bound_to": bound,
    }


def score(checklist: int, decision: str) -> int:
    """The score a readiness file shows: the checklist's points, never 100 unless the release passed, and never
    above `BLOCKED_CAP` while something blocks it."""
    if decision == "Blocked":
        return min(checklist, BLOCKED_CAP)
    if decision != "Passed":
        return min(checklist, NOT_PASSED_CAP)
    return checklist


def shown(rd) -> dict | None:
    """The release decision out of a readiness result that was read back from a file, for a card, the connector or
    Ask Lantern: None when the result has none (an older Lantern wrote it) or it is not one of the three words. The
    file lies in the results folder, which may come with the project, so what stands beside the word is taken as
    plain text of a bounded length, and what blocks and what is missing is worked out anew from the criteria."""
    rel = rd.get("release") if isinstance(rd, dict) else None
    if not isinstance(rel, dict) or not isinstance(rel.get("decision"), str) or rel["decision"] not in DECISIONS:
        return None
    text = lambda v, n: v[:n] if isinstance(v, str) else ""     # noqa: E731
    crit = [{"id": text(c.get("id"), 40), "title": text(c.get("title"), 200), "required": c.get("required") is not False,
             "state": c["state"], "why": text(c.get("why"), 1000), "fix": text(c.get("fix"), 600)}
            for c in (rel.get("criteria") if isinstance(rel.get("criteria"), list) else [])
            if isinstance(c, dict) and isinstance(c.get("state"), str) and c["state"] in STATES][:20]
    return {"decision": rel["decision"], "words": text(rel.get("words"), 1500), "criteria": crit,
            "blocking": [c["id"] for c in crit if c["required"] and c["state"] == "failed"],
            "missing": [c["id"] for c in crit if c["required"] and c["state"] == "missing"]}


def said(view: dict | None) -> list[str]:
    """`shown`'s view as lines of text: the decision, then each criterion with its state and its reason."""
    if not view:
        return []
    lines = [f"Release decision: {view['decision']}" + (f" ({view['words']})" if view["words"] else "")]
    for c in view["criteria"]:
        lines.append(f"  - {c['title'] or c['id']}: {c['state']}" + ("" if c["required"] else " (not required for this "
                     "kind of project)") + (f". {c['why']}" if c["why"] else "")
                     + (f" {c['fix']}" if c["fix"] and c["state"] in ("failed", "missing") else ""))
    return lines


def line(rel: dict | None) -> str:
    """One line for a log or a card: the decision and, when it is not Passed, the first reason."""
    if not isinstance(rel, dict) or rel.get("decision") not in DECISIONS:
        return "no release decision"
    first = next((c for c in rel.get("criteria") or [] if isinstance(c, dict)
                  and c.get("id") in (rel.get("blocking") or rel.get("missing") or [])), None)
    return rel["decision"] + (f": {first['why']}" if first else "")
