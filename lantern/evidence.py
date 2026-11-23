"""Evidence Report (spec section 11): a short, commit-pinned, verifiable summary for a skeptical engineer.

The report carries a SHA-256 digest of its deterministic results (graph shape, findings, readiness
checks, tool versions) and the commit hash. `lantern verify` re-runs the analysis on the same commit
and compares digests. The digest proves the results match the code; it is not a signature.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import platform
import re
import subprocess
from pathlib import Path

from . import SCHEMA_VERSION, __version__, deep, gitfacts, programs, release, results, scanresult, typecheck, workspace
from .depaudit import AUDIT_TOOLS
from .graph import Graph, route_words
from .lanes import LANE_WORDS, LANES
from .python_frontend import inside_repo, project_text
from .security import ID_VERSION
from .trace import counted

EVIDENCE_VERSION = 1
NARRATIVES_FILE = "lantern-narratives.md"


# ---------------------------------------------------------------------------- facts

def git_info(repo: Path) -> dict:
    """The commit a folder is at, its branch, whether files differ from the commit, where `origin` is and when the
    commit was made (`gitfacts.info`). Read without obeying the folder's own git settings: until 2026-11-10 this
    asked git inside the folder, and `git status` ran a command planted in its `.git/config`. `note` says why
    there is no commit, or that the files could not be compared (they then count as changed)."""
    return gitfacts.info(repo)


def engine_ref() -> str:
    """The Lantern to install to re-check a report: the commit this copy was built from (written into the cloud image,
    or read from the git checkout Lantern runs from), else the release tag. Installing the newest Lantern instead can
    give a different digest once the analysis changes."""
    from . import _build
    if re.fullmatch(r"[0-9a-f]{40}", _build.COMMIT or ""):
        return _build.COMMIT
    root = Path(__file__).resolve().parent.parent
    git = programs.find("git")
    if git and (root / ".git").exists() and (root / "pyproject.toml").is_file():
        try:
            p = subprocess.run([git, "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=10, env=programs.env())
            if p.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", p.stdout.strip()):
                return p.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    return f"v{__version__}"


def tool_versions(sec: dict | None) -> list[dict]:
    rows = [{"tool": "lantern", "version": __version__, "role": "graph, bridge, web rules, readiness"},
            {"tool": "python", "version": platform.python_version(), "role": "runtime"}]
    try:
        from importlib.metadata import version
        for pkg in ("tree-sitter", "tree-sitter-python", "tree-sitter-typescript", "tree-sitter-javascript"):
            try:
                rows.append({"tool": pkg, "version": version(pkg), "role": "parser"})
            except Exception:  # noqa: BLE001 - optional package metadata
                pass
    except ImportError:
        pass
    for t in (sec or {}).get("tools", []):
        if not isinstance(t, dict):
            continue
        rows.append({"tool": t.get("tool"), "version": t.get("version"), "role": "scanner", "status": t.get("status"),
                     "state": scanresult.state_of(t)})
    return rows


def run_options(sec: dict | None, run_meta: dict | None) -> dict:
    """How the results were made, so `lantern verify` can make them the same way."""
    tr = (run_meta or {}).get("trace")
    # tests that were asked for and not run left nothing in the results: no trace to repeat
    out = {"scan": sec is not None, "trace": tr.get("command") if counted(tr) else None,
           "offline": bool((run_meta or {}).get("offline"))}
    types = (run_meta or {}).get("typecheck")
    if isinstance(types, dict) and types.get("asked"):   # only when asked for: every other run's options stay as they were
        out["typecheck"] = typecheck.versions(types)
    return out


def digest_payload(g: Graph, sec: dict | None, rd: dict | None, commit: str | None, dirty: bool = False,
                   run: dict | None = None) -> dict:
    """The deterministic part of the results. Same code + same tool versions + same run options -> same payload."""
    st = g.stats()
    return {
        "evidence_version": EVIDENCE_VERSION, "schema": SCHEMA_VERSION, "lantern": __version__, "commit": commit,
        "uncommitted_changes": bool(dirty), "run": run or {"scan": sec is not None, "trace": None},
        "graph": {"files": g.meta.get("files"), "lines": g.meta.get("lines"),
                  "nodes": st.get("nodes"), "call_edges": st.get("call_edges"),
                  "entry_points": sorted(f"{(n.entry or {}).get('kind')}:{(n.entry or {}).get('detail')}"
                                         for n in g.entry_points()),
                  "bridge": {k: v for k, v in (g.meta.get("bridge") or {}).items() if isinstance(v, int)}},
        "findings": sorted(f"{f['id']}:{f['rule']}:{f['rank']}:{f.get('status', 'open')}"
                           for f in (sec or {}).get("findings", [])),
        "scanners": sorted(f"{t.get('tool')}:{t.get('version')}:{(t.get('status') or '')[:2]}"
                           for t in (sec or {}).get("tools", [])),
        "readiness": None if not rd else {
            "score": rd["score"], "checks": sorted(f"{c['id']}:{c['status']}" for cat in rd["categories"]
                                                   for c in cat["checks"]),
            "protections": sorted(f"{x['id']}:{x['status']}" for x in rd.get("protections") or []),
            **_release_part(rd.get("release"))},
        # several projects as one map: each one's commit (lantern/workspace.py); nothing for a project of its own
        **workspace.payload(g.meta),
    }


def _release_part(rel) -> dict:
    """The release decision's share of the digest: the decision, each criterion's state and what the decision is
    tied to (the code, the dependency files, the plan, the accepted risks). Nothing for a readiness file an older
    Lantern wrote, so its digest stays what it was."""
    if not isinstance(rel, dict) or rel.get("decision") not in release.DECISIONS:
        return {}
    b = rel.get("bound_to") if isinstance(rel.get("bound_to"), dict) else {}
    part = lambda k: b.get(k) if isinstance(b.get(k), dict) else {}   # noqa: E731
    return {"release": {
        "decision": rel["decision"],
        "criteria": sorted(f"{c.get('id')}:{c.get('state')}" for c in rel.get("criteria") or [] if isinstance(c, dict)),
        "code": part("code").get("sha256"), "dependencies": part("dependencies").get("sha256"),
        "plan": part("settings").get("plan_sha256"), "accepted": part("settings").get("accepted_sha256")}}


def digest(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _call_site_words(c: dict) -> str:
    """One sentence on the denominator: every call site read, and what share each kind is."""
    if not c.get("total"):
        return ""
    pct = lambda n: f"{100 * (n or 0) / c['total']:.1f}%"   # noqa: E731
    return (f" Of {c['total']} call sites read: {pct(c.get('resolved_internal'))} linked to repo code for certain, "
            f"{pct(c.get('inferred_internal'))} likely, {pct(c.get('several_possible_targets'))} to one of several "
            f"targets, {pct(c.get('name_only_guess'))} guessed by method name, {pct(c.get('known_external'))} known "
            f"library calls, {pct(c.get('builtin'))} built-in calls (the language's own functions), "
            f"{pct(c.get('unresolved'))} not traced"
            + (f" ({c['unresolved_in_tests']} of those in test files)" if c.get("unresolved_in_tests") else "") + ".")


AUDIT_LANG = {"pip-audit": "Python", "npm-audit": "npm", "maven-audit": "Gradle/Maven", "composer-audit": "PHP (Composer)",
              "gem-audit": "Ruby (Bundler)", "copied-audit": "copied-in software"}


def _whole(x) -> int:
    """A count out of a record that may have been read back from disk: a whole number above 0, else 0."""
    return x if isinstance(x, int) and not isinstance(x, bool) and x > 0 else 0


def _names(x, most: int = 3) -> list[str]:
    return [str(v)[:120] for v in (x if isinstance(x, list) else []) if isinstance(v, str)][:most]


ROUTES_NOT_READ = {      # `graph.json` `meta.remix.not_read` (the JS/TS reader's words) -> the sentence for the Limits
    "Remix 1 route folders": (
        "This is a Remix 1 app, which keeps its routes in folders. Lantern does not read that layout, so the app's "
        "pages and routes are not on the map, and no finding says who can reach its code."),
    "React Router routes listed in app/routes.ts": (
        "This React Router app lists its routes in app/routes.ts by hand, or names a folder of its own for them. "
        "Lantern does not read that list, so the app's pages and routes are not on the map, and no finding says "
        "who can reach its code."),
}


def routes_not_read(meta: dict) -> list[str]:
    """The Limits lines for an app whose routes the JS/TS reader did not read. The map's own words only pick the
    sentence: a results file is taken by its shape, and nothing of its text is repeated."""
    remix = meta.get("remix") if isinstance(meta, dict) else None
    words = remix.get("not_read") if isinstance(remix, dict) else None
    named = words.split("; ") if isinstance(words, str) else []
    return [sentence for word, sentence in ROUTES_NOT_READ.items() if word in named]


def not_read_lines(sec: dict | None) -> list[str]:
    """The Limits lines for what the project holds that Lantern takes for code or software and no reader opened
    (`security.json` `not_read`, `lantern/unread.py`): code kept under another name, software copied into a vendor
    folder. Counts and the first few names; the record may be one read back from disk."""
    got = (sec or {}).get("not_read")
    got = got if isinstance(got, dict) else {}
    out = []
    kept = got.get("renamed") if isinstance(got.get("renamed"), dict) else None
    n = _whole(kept.get("files")) if kept else 0
    if n:
        endings = kept.get("endings") if isinstance(kept.get("endings"), dict) else {}
        kinds = ", ".join(f"`{str(k)[:20]}`" for k in list(endings)[:6])
        ex = _names(kept.get("examples"))
        line = (f"{n} file{'s hold' if n != 1 else ' holds'} code under another name"
                + (f" ({kinds})" if kinds else "") + (f", {_whole(kept.get('lines'))} lines" if _whole(kept.get("lines")) else "")
                + (f", for example {', '.join(ex)}" if ex else "") + ". Lantern's readers do not open such files: no "
                "map, no path and none of Lantern's own checks (data flow, login checks, call counts) covers them.")
        scanned = min(_whole(kept.get("scanned")), n)
        if scanned == n:
            line += " Bandit read " + ("it" if n == 1 else "all of them") + " for known Python patterns."
        elif scanned:
            line += f" Bandit read {scanned} of them for known Python patterns; no scanner read the other {n - scanned}."
        else:
            line += " No scanner read " + ("it" if n == 1 else "them") + " either."
        out.append(line)
    cp = got.get("copied") if isinstance(got.get("copied"), dict) else None
    copies, loose = (_whole(cp.get("copies")), _whole(cp.get("unnamed"))) if cp else (0, 0)
    cut = bool(cp) and cp.get("cut_short") is True
    if copies or loose or cut:
        parts = []
        if copies:
            named = _names(cp.get("named"))
            tools = (sec or {}).get("tools")
            looked = any(isinstance(x, dict) and x.get("tool") == "copied-audit" and scanresult.state_of(x) in ("ok", "partial")
                         for x in (tools if isinstance(tools, list) else []))
            one = copies == 1
            parts.append(f"{copies} cop{'y says' if one else 'ies say'} what {'it is' if one else 'they are'}"
                         + (f" ({', '.join(named)})" if named else "") + f" and {'was' if one else 'were'} "
                         + ("looked up for known problems" if looked else "not looked up for known problems in this check")
                         + f": the lookup goes by the name and version {'it says it is' if one else 'they say they are'}, "
                         "so whether the files are that version, and what is packed inside, is not checked")
        if loose:
            ex = _names(cp.get("unnamed_examples"))
            parts.append(f"{loose} file{'s' if loose != 1 else ''} of code there carr{'y' if loose != 1 else 'ies'} no name "
                         "and version Lantern can look up" + (f" (for example {', '.join(ex)})" if ex else ""))
        out.append("Software copied into the project (a `vendor` folder). Lantern's readers leave such folders out, so "
                   "no map and no code scanner covers them." + (" " + "; ".join(parts) + "." if parts else "")
                   + (" Part of what lies there was not looked at, not even for names: Lantern looks a few folders "
                      "deep and at a limited number of files." if cut else ""))
    return out


def _reason(t: dict) -> str:
    """The reason in a record, without the "error:"/"skipped:" prefix the status sentence carries."""
    why = str(t.get("why") or "").strip()
    if why:
        return why
    status = str(t.get("status") or "").strip()
    return status.split(":", 1)[1].strip() if ":" in status else status


def incomplete_lines(tools: list[dict]) -> list[str]:
    """One Limits line per scanner that applied to the project and did not finish, did not cover everything, or was
    skipped: what it was for, what happened, and that whatever it would have found is missing."""
    out = []
    for t in scanresult.incomplete(tools):
        name, st = str(t.get("tool") or "?"), scanresult.state_of(t)
        role = f" ({t['role']})" if t.get("role") else ""
        reason = _reason(t)
        if st == "timeout":
            out.append(f"The {name} scan{role} did not finish: it timed out {reason}. Anything it would have found is "
                       "missing from this report.".replace("timed out .", "timed out."))
        elif st == "failed":
            out.append(f"The {name} scan{role} did not finish: {reason}. Anything it would have found is missing from "
                       "this report.")
        elif st == "partial":
            errs = [str(e) for e in (t.get("errors") or []) if isinstance(e, (str, int, float))][:3]
            out.append(f"The {name} scan{role} covered only part of the project: {reason}"
                       + (f" ({'; '.join(errs)})" if errs else "") + ". The findings it did produce are included.")
        elif st == "unavailable":
            out.append(f"The {name} scan{role} did not run: it is not installed ({reason}). Anything it would have "
                       "found is missing from this report.")
        elif name in AUDIT_LANG:
            out.append(f"{AUDIT_LANG[name]} dependencies were not checked for known vulnerabilities ({t.get('status')}).")
        else:
            out.append(f"The {name} scan{role} was skipped: {reason}.")
    return out


def accepted_by(acc) -> str:
    """Who accepted a risk and when, or where: a `# nosec` comment in the code has no name and no date."""
    acc = acc if isinstance(acc, dict) else {}
    if acc.get("how") == "nosec":
        return "in the code, a # nosec comment on the line"
    return f"{acc.get('by') or '?'}, {acc.get('date') or '?'}"


def accepted_words(acc) -> str:
    """One line for an accepted risk (plain text: the caller escapes it)."""
    acc = acc if isinstance(acc, dict) else {}
    if acc.get("how") == "nosec":
        return f"Accepted in the code (a # nosec comment on the line): {acc.get('reason') or ''}"
    return f"Accepted by {acc.get('by') or '?'} on {acc.get('date') or '?'}: {acc.get('reason') or ''}"


NO_LOCK_WORDS = {"npm-audit": ("npm", "package.json"), "composer-audit": ("PHP", "composer.json"),
                 "gem-audit": ("Ruby", "Gemfile")}

# The libraries a project's tests ran on (`run.json` `trace.libraries`, written by `lantern.libraries`), as this
# report shows them. The record may be one read back from the project's own results folder, so it is taken by its
# shape: a state of two, a store that reads like a host, and for each library a name, a version and a fingerprint
# of the forms the stores define. Whatever else an entry holds is left out and counted.
LIBRARY_STATES = ("fetched", "installed")
LIBRARY_STORE = re.compile(r"[A-Za-z0-9.\-\[\]:]{1,100}")
LIBRARY_NAME = re.compile(r"(?:@[A-Za-z0-9._\-]{1,100}/)?[A-Za-z0-9._\-]{1,110}")
LIBRARY_VERSION = re.compile(r"[A-Za-z0-9.+!_\-]{1,100}")
LIBRARY_PRINT = re.compile(r"sha256:[0-9a-f]{64}|sha(?:1|256|384|512)-[A-Za-z0-9+/]{20,100}={0,2}|")
LIBRARY_SOURCE = re.compile(r"sha256:[0-9a-f]{64}")      # the source package a library was built from (`built_from`)
MOST_LIBRARIES = 5000
MOST_ABOVE = 100        # folders above a run's folder: a path is not that deep
LIBRARY_GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,39}")       # a group of libraries, as a tool would write it
MOST_GROUPS = 40


def _optional_left(lib: dict) -> dict | None:
    """The groups of libraries the project names as optional that were not there when the tests ran
    (`libraries.fetch`: they could not be had beside the rest, or were not asked for), or None. By shape: names a
    tool would write and a count for the rest. Why they were left out is a sentence in a file that may have come
    with the project, and is not repeated."""
    opt = lib.get("optional")
    if not isinstance(opt, dict) or opt.get("fetched") is not False:
        return None
    groups = opt.get("groups") if isinstance(opt.get("groups"), list) else []
    named = [g for g in groups[:MOST_GROUPS] if isinstance(g, str) and LIBRARY_GROUP.fullmatch(g)]
    more = opt.get("more") if type(opt.get("more")) is int and 0 <= opt.get("more") <= 100_000 else 0
    return {"groups": named, "more": min(100_000, more + len(groups) - len(named))}


def libraries_clean(lib) -> dict | None:
    """`lib` as the report shows it, or None when it is no record of libraries the tests ran on."""
    if not isinstance(lib, dict) or lib.get("state") not in LIBRARY_STATES or not isinstance(lib.get("packages"), list):
        return None
    packages, left_out = [], lib.get("left_out") if isinstance(lib.get("left_out"), int) and lib.get("left_out") > 0 else 0
    for p in lib["packages"][:MOST_LIBRARIES]:
        name, version, mark = (p.get(k, "") if isinstance(p, dict) else None for k in ("name", "version", "fingerprint"))
        if not (isinstance(name, str) and LIBRARY_NAME.fullmatch(name) and isinstance(version, str)
                and LIBRARY_VERSION.fullmatch(version) and isinstance(mark, str) and LIBRARY_PRINT.fullmatch(mark)):
            left_out += 1
            continue
        row = {"name": name, "version": version, "exact": p.get("exact") is True,
               "checked": p.get("checked") is True, "fingerprint": mark}
        # A library that was built for the run (`libraries._build`): the fingerprint of the source package it was
        # built from, taken by its shape from the run's record (`built`) or from a report read back (`built_from`).
        # The file's name and the tools are text of a file that may have come with the project, and stay there.
        made = p.get("built")
        source = made.get("source_fingerprint") if isinstance(made, dict) else p.get("built_from") if made is None else None
        if isinstance(source, str) and LIBRARY_SOURCE.fullmatch(source):
            row["built_from"] = source
        packages.append(row)
    left_out += max(0, len(lib["packages"]) - MOST_LIBRARIES)
    store, above = lib.get("store"), lib.get("above")
    return {"state": lib["state"], "store": store if isinstance(store, str) and LIBRARY_STORE.fullmatch(store) else "",
            "exact": bool(packages) and not left_out and lib["state"] == "fetched" and all(p["exact"] for p in packages),
            "checked": sum(1 for p in packages if p["checked"]), "left_out": left_out, "packages": packages,
            # folders of packages above the run's own folder, which Node looks in too (JavaScript): a count
            "above": above if type(above) is int and 0 < above <= MOST_ABOVE else 0,
            # groups of optional libraries that were left out of the fetch (Python); the entry is there only then
            **({"optional_left": left} if (left := _optional_left(lib)) else {}),
            # how many of the libraries were built from their source for the run; the entry is there only then
            **({"built": n} if (n := sum(1 for p in packages if "built_from" in p)) else {})}


def libraries_shown(tr) -> dict | None:
    """The libraries of a test run whose results are in the report (`trace.counted`), or None."""
    return libraries_clean(tr.get("libraries")) if counted(tr) else None


def libraries_limits(lib: dict | None) -> list[str]:
    """What the libraries the tests ran on leave unproven: versions nobody fixed, libraries nobody fetched."""
    if not lib:
        return []
    count = len(lib["packages"]) + lib["left_out"]
    loose = count - sum(1 for p in lib["packages"] if p["exact"])
    if lib["state"] == "installed":
        return ["The libraries the tests ran on. The check was offline, so nothing was fetched for the tests: they ran "
                "on the libraries installed on this computer, which may not be the versions the project names."]
    out = []
    if loose:
        out.append(f"The libraries the tests ran on. {loose} of the {count} librar{'y' if count == 1 else 'ies'} fetched "
                   f"for the tests {'is' if loose == 1 else 'are'} at a version the project does not fix: the newest that "
                   "fits was taken, so the same check on another day may run the tests on other versions. A lock file, "
                   "or exact versions (==), fixes this.")
    if lib.get("above"):
        n = lib["above"]
        out.append(f"Packages in reach of the tests that the project does not name. {n} folder{'s' if n != 1 else ''} of "
                   f"packages (node_modules) {'lie' if n != 1 else 'lies'} above the folder the tests ran in, on the "
                   "computer that ran them. Node looks for a package there too, and Lantern cannot take such a folder "
                   "out of its way, so a test may have loaded a package from it. Removing the folder, or running the "
                   "check where the temp folder has none above it, fixes this.")
    if lib.get("optional_left"):
        left = lib["optional_left"]
        shown = [f'"{g}"' for g in left["groups"][:6]]
        more = left["more"] + len(left["groups"]) - len(shown)
        words = (", ".join(shown[:-1]) + (" and " if len(shown) > 1 else "") + shown[-1]) if shown and not more else \
            ", ".join(shown) + (" and " if shown else "") + f"{more} more" if more else "groups the record does not name"
        out.append(f"Libraries the project names as optional. The ones under {words} were not there when the tests "
                   "ran: they could not be fetched beside the libraries the project always needs, or were not asked "
                   "for (the run's log says which, and why). A test of a part that needs one of them fails for that "
                   "alone, and what that part does was not tested.")
    made = [f"{p['name']} {p['version']}" for p in lib["packages"] if "built_from" in p]
    if made:
        shown, one = made[:6], len(made) == 1
        words = (", ".join(shown[:-1]) + (" and " if len(shown) > 1 else "") + shown[-1]) if len(made) == len(shown) \
            else ", ".join(shown) + f" and {len(made) - len(shown)} more"
        out.append(f"Libraries built from their source. {words} {'was' if one else 'were'} not in the store ready-built "
                   f"for the system the tests ran on and {'was' if one else 'were'} built for this run, in the sandbox "
                   f"with the network off, by code the librar{'y brings' if one else 'ies bring'}. The fingerprint "
                   f"shown for {'its' if one else 'each'} source is of the file the store handed out. The package the "
                   "build made was on this computer only for that run, and the tools it was built with were the newest "
                   "that fit, so the same check on another day or another computer may run the tests on a package "
                   "that differs.")
    return out


def limits(g: Graph, sec: dict | None, rd: dict | None, run_meta: dict, privacy: str, exp: dict | None,
           baseline_unread: str | None = None) -> list[str]:
    st = g.stats()
    out = [
        "Business-logic flaws. Scanners and graph checks find known patterns; they can't tell whether your "
        "rules (who may see what, what a price should be) are right.",
        f"Calls Lantern could not trace. {st.get('unresolved_call_sites', 0)} call sites were left unresolved "
        "rather than guessed, mostly calls into libraries or very dynamic code (getattr, plugins, "
        "hooks returning objects)." + _call_site_words(st.get("call_sites") or {}),
    ]
    if st.get("guessed_by_method_name"):
        out.append(f"{st['guessed_by_method_name']} call edges were linked by method name alone because the object's "
                   "type was unknown. They are marked likely or possible, never confirmed, and can point at the "
                   "wrong function.")
    out += deep.words(g.meta)    # code nested deeper than a reader follows: left where the reading stopped, and named
    out += routes_not_read(g.meta)
    tr = run_meta.get("trace")
    if counted(tr):
        out.append(f"Runtime behavior beyond what `{' '.join(tr.get('command', []))}` exercised. Python calls seen "
                   "running are marked observed; everything else is static.")
        out += libraries_limits(libraries_shown(tr))
    elif isinstance(tr, dict) and tr.get("ran") is False:
        why = tr.get("unavailable")
        out.append("Runtime behavior. The project's tests were asked for and were not run, because "
                   + ("the libraries the project names could not be had for them" if tr.get("not_run_for") == "libraries"
                      else "the sandbox they run in could not be set up")
                   + (f" ({why[:300]})" if isinstance(why, str) and why else "")
                   + ". Every edge is from static analysis.")
    else:
        out.append("Runtime behavior. No code was run for this report, so every edge is from static analysis and "
                   "tests were not executed.")
    if "typescript/javascript" in (g.meta.get("languages") or {}):
        out.append("Frontend call edges are static only (no JavaScript runtime tracing yet).")
    out += typecheck.limits(run_meta.get("typecheck"))     # only for a run that asked for the type-aware pass
    if sec is None:
        out.append("Security scanners were not run for this report (--no-scan): no findings does not mean no problems.")
    tools = [t for t in (sec or {}).get("tools", []) if isinstance(t, dict)]
    out += incomplete_lines(tools)
    for t in tools:
        n = t.get("unpinned")           # the record may be one read back from disk: only a count is taken for a count
        n = n if isinstance(n, int) and not isinstance(n, bool) and n > 0 else 0
        tool, were = t.get("tool"), "they were" if n != 1 else "it was"
        if tool == "pip-audit" and n:
            out.append(f"{n} Python requirement{'s name' if n != 1 else ' names'} no exact released version (a range, "
                       f"or a package installed from a link or a folder), so {were} not checked for known "
                       "vulnerabilities. For a range, a lock file fixes this.")
        if tool == "maven-audit" and (t.get("status") == "ok" or (t.get("state") == "partial" and t.get("checked"))):
            out.append("Gradle/Maven libraries were checked as written in the build files; the libraries they pull in "
                       "were not.")
        if tool == "maven-audit" and n:
            out.append(f"{n} Gradle/Maven librar{'ies are' if n != 1 else 'y is'} written without an exact name and "
                       "version (no version, a range, a `+`, or a variable Lantern cannot fill in), so "
                       f"{were} not checked for known vulnerabilities.")
        if tool == "composer-audit" and n:
            out.append(f"{n} PHP librar{'ies' if n != 1 else 'y'} in composer.lock {'are' if n != 1 else 'is'} "
                       f"installed from a branch, not a released version, so {were} not checked for known "
                       "vulnerabilities.")
        u = t.get("unlocked")           # named where no lock file says which version is installed
        u = u if isinstance(u, int) and not isinstance(u, bool) and u > 0 else 0
        if u and tool in NO_LOCK_WORDS:
            kind, file = NO_LOCK_WORDS[tool]
            out.append(f"{u} {kind} librar{'ies are' if u != 1 else 'y is'} named in a {file} with no lock file "
                       f"beside it, so no exact version is known and {'they were' if u != 1 else 'it was'} not "
                       "checked for known vulnerabilities. Committing the lock file fixes this.")
        if isinstance(t.get("other_locks"), list) and t["other_locks"]:
            k = len(t["other_locks"])
            out.append(f"The libraries of {k} folder{'s' if k != 1 else ''} are fixed by a pnpm, yarn or bun lock "
                       "file, which Lantern does not read yet, so they were not checked for known vulnerabilities.")
    if any(f.get("category") == "dependency" for f in (sec or {}).get("findings", [])) or any(
            t.get("tool") in AUDIT_TOOLS and t.get("status") == "ok" for t in (sec or {}).get("tools", [])):
        out.append("Dependency findings come from live vulnerability databases, so a re-check can find new ones "
                   "without any code change.")
    # Counted where the report lists findings (outside test code), so the number matches what the reader can see
    heur = sum(1 for f in (sec or {}).get("findings", []) if f.get("tool_confidence") == "LOW" and not f.get("in_tests"))
    if heur:
        out.append(f"{heur} finding{'s are' if heur != 1 else ' is'} from heuristic checks that can misfire; they are "
                   "labeled as such.")
    if rd:
        out.append("The readiness score uses file and pattern checks. A check passing means the thing exists, not "
                   "that it is configured well.")
    rel = (rd or {}).get("release") if isinstance((rd or {}).get("release"), dict) else None
    if rel:
        out.append("The release decision is about exactly the files, libraries, settings and tools it names, on the "
                   "computer it was made on. A change to any of them needs a new check, and a file in a folder "
                   "Lantern does not read (installed libraries, build output) is not part of it.")
        said = {"behaviour": "What the app does when it runs. ", "browser": "What a browser shows of the project. "}
        for x in (rel.get("profile") or {}).get("not_required") or []:
            if isinstance(x, dict) and x.get("id") in said and isinstance(x.get("why"), str):
                out.append(said[x["id"]] + x["why"][:400])
    if exp and exp.get("explanations"):
        out.append("Plain-language explanations were written by a model. Each phrase is checked to anchor to real "
                   "code, but the wording itself is not proof. The results digest does not cover explanations or "
                   "which model wrote them.")
    if privacy != "full":
        out.append("Source code was left out of this report (structure-only privacy).")
    if baseline_unread:     # `results.earlier`: fixed words, never text from the file
        out.append("What was fixed since the first analysis. The file that records the first analysis "
                   f"(baseline.json in the results folder) could not be used: {str(baseline_unread)[:300]}. It was "
                   "left as it is, and this report compares with nothing. `lantern evidence PATH --reset-baseline` "
                   "starts a new record from today's findings.")
    out += not_read_lines(sec)
    left = run_meta.get("skipped") if isinstance(run_meta.get("skipped"), dict) else None
    if left and isinstance(left.get("files"), int):
        ex = [str(x)[:120] for x in (left.get("examples") or []) if isinstance(x, str)][:3]
        out.append(f"The repository was larger than Lantern's size limit, so {left['files']} file(s) Lantern does not "
                   "read (pictures, video, sound, fonts, archives, compiled programs, model weights, datasets) were "
                   "left out of the copy" + (f", for example {', '.join(ex)}" if ex else "") + ". All code, "
                   "configuration and text files were read.")
    if run_meta.get("place") == "cloud":
        out.append("Made by Lantern's cloud service: the repository was copied into a sandboxed container on Lantern's "
                   "server (no network during the analysis, writes only to its own temp folder), analysed without "
                   "running any of its code, and the copy was deleted afterwards. The sandbox is a restricted process, "
                   "not a separate virtual machine.")
    out += workspace.limits(g.meta)     # several projects as one map: what that does not prove
    return out


# ---------------------------------------------------------------------------- build

def build(g: Graph, sec: dict | None, rd: dict | None, exp: dict | None, run_meta: dict | None,
          baseline: dict | None, privacy: str = "full", baseline_unread: str | None = None) -> dict:
    repo = Path(g.repo_root)
    run_meta = run_meta or {}
    gi = git_info(repo)
    findings = (sec or {}).get("findings", [])
    live = [f for f in findings if not f.get("in_tests")]
    fixed, changed = compare_baseline(findings, baseline)
    narratives = None
    nf = repo / NARRATIVES_FILE
    if inside_repo(nf, repo):   # the project's own file: until 2026-11-10 a link out of the project was shown too
        try:
            narratives = project_text(nf, repo, 20000)
        except OSError:   # it cannot be read: the report is made without it
            narratives = None
    entries = [{"kind": (n.entry or {}).get("kind"), "detail": (n.entry or {}).get("detail"), "name": n.qualname,
                "file": n.file} for n in g.entry_points() if (n.entry or {}).get("kind") != "test"]
    models = []
    if exp and exp.get("stats"):
        s = exp["stats"]
        models.append({"model": s.get("model"), "task": "Three-Lens explanations", "validated": s.get("validated"),
                       "failed": s.get("failed"), "prompt_version": next(
                           (r.get("prompt_version") for r in (exp.get("explanations") or {}).values()), None)})
    payload = digest_payload(g, sec, rd, gi.get("commit"), gi.get("dirty", False), run_options(sec, run_meta))
    ev = {
        "evidence_version": EVIDENCE_VERSION,
        "header": {"repo": gi.get("remote") or repo.name, "name": repo.name, **gi,
                   "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                   "mode": "local", "privacy": privacy, "engine": engine_ref()},
        "scorecard": {
            "readiness": None if not rd else {"score": rd["score"], "grade": rd["grade"], "shape": rd["shape"],
                                              "checklist": rd.get("checklist"),
                                              "categories": [{k: c[k] for k in ("title", "weight", "score", "percent")}
                                                             for c in rd["categories"]]},
            "now": {k: sum(1 for f in live if f["rank"] == k and f.get("status") == "open")
                    for k in ("critical", "high", "medium", "low")},
            "before": (baseline or {}).get("counts"), "baseline_date": (baseline or {}).get("date"),
            "baseline_commit": (baseline or {}).get("commit"),
            "baseline_readiness": (baseline or {}).get("readiness"),
            "new": [_f(f) for f in live if f.get("status") == "open" and baseline and baseline.get("findings")
                    and f["id"] not in baseline["findings"]],
        },
        "architecture": {
            "languages": g.meta.get("languages"), "files": g.meta.get("files"), "lines": g.meta.get("lines"),
            "entries": entries, "bridge": g.meta.get("bridge"),
            "advice": (rd or {}).get("advice", []), "shape": (rd or {}).get("shape"),
            "frameworks": ((rd or {}).get("stack") or {}).get("frameworks", []),
            "edges": g.stats().get("confidence"),
        },
        "security": {
            "open": [_f(f) for f in live if f.get("status") == "open"],
            "accepted": [_f(f) | {"accepted": f.get("accepted")} for f in findings if f.get("status") == "accepted"],
            "fixed": fixed, "changed": changed, "in_tests": sum(1 for f in findings if f.get("in_tests")),
            # each one, so that "N more are in test code" can be read and not only counted (2026-11-19)
            "in_tests_open": [_f(f) for f in findings if f.get("in_tests") and f.get("status") == "open"][:MOST_TEST_ROWS],
            "protections": [{k: x.get(k) for k in ("id", "title", "status", "why", "evidence", "how", "found")}
                            for x in (rd or {}).get("protections") or []],
            # scanners that applied and did not finish or did not cover everything (scanresult.py); the badge says
            # "scan incomplete" while this list is not empty
            "incomplete": [{k: t.get(k) for k in ("tool", "state", "status", "why", "role", "version")}
                           for t in scanresult.incomplete((sec or {}).get("tools")) if isinstance(t, dict)],
        },
        # the release decision with every criterion and what it is tied to (release.py); None for a readiness file an
        # older Lantern wrote
        "release": (rd or {}).get("release") if isinstance((rd or {}).get("release"), dict) else None,
        "understanding": narratives,
        "provenance": {"tools": tool_versions(sec) + typecheck.rows(run_meta.get("typecheck")), "models": models,
                       # the libraries the project's tests ran on, each with its fingerprint (None: no tests, or
                       # tests that ran on no library of anyone's)
                       "libraries": libraries_shown(run_meta.get("trace")),
                       "rules": ["bandit default profile", "lantern-web LW-*/LJ-* rules", "lantern secret patterns",
                                 f"readiness checks v{(rd or {}).get('version', '-')}", f"graph schema {SCHEMA_VERSION}"]
                       + [f"analysis pack {t['tool'].split(':', 1)[1]} v{t.get('version', '-')} ({t.get('status', '')})"
                          for t in (sec or {}).get("tools", []) if str(t.get("tool", "")).startswith("lantern-pack:")]},
        "limits": limits(g, sec, rd, run_meta, privacy, exp, baseline_unread),
        "digest": digest(payload), "payload": payload,
    }
    ws = workspace.shown(g.meta)
    if ws is not None:      # several projects as one map: each one, where it came from and its commit
        ev["provenance"]["workspace"] = ws
    return ev


def read_digest(report: Path) -> tuple[str | None, dict | None]:
    """The digest named in an evidence.html or evidence.json, and the payload when the .json is beside it. Both
    are read only as plain files (`results.plain`): a report that is a link, a pipe or not there is
    `results.Refused`, in words for the person; a .json beside it that is not a plain file is passed over."""
    text, why = results.plain(report)
    if text is None:
        raise results.Refused(f"{report} was not read: {why or 'it is not there'}.")
    m = re.search(r"sha256:[0-9a-f]{64}", text)
    want = m.group(0) if m else None
    old = None
    jp = report if report.suffix == ".json" else report.with_suffix(".json")
    beside = text if jp == report else results.plain(jp)[0]
    if beside is not None:
        try:
            old = json.loads(beside).get("payload") or {}
        except (ValueError, RecursionError, AttributeError):
            old = None
    return want, old


def verify(repo: Path, want: str, old: dict | None, trace_cmd: list[str] | None = None, no_scan: bool = False,
           offline: bool = False, beside: Path | None = None, typecheck: bool = False) -> dict:
    """Re-run the analysis on `repo` the way the report was made and compare digests.

    `typecheck`: the caller's word that this computer's type checkers may be asked again. A report made with the
    type-aware pass is verified only with it (`refused` otherwise, like a trace: a report starts no program), and a
    report made without it is never verified with it.

    Scanning on/off and offline are copied from the report's recorded options; a trace command never is, because a
    trace runs the project's code. The caller types it, and it must match what the report recorded, or the result
    is `refused` with the command to check. `beside`: the results folder the report lies in. It is left out of the
    project's files as it was when the report was made, and the record `lantern behave` left there is handed to the
    release decision (which counts it only with this computer's seal, for this code and this plan); no app is
    started here. Returns match, both digests, the options used, and which payload sections differ (when the
    report's payload is available)."""
    from .engine import build_graph
    from .readiness import assess
    from .security import scan
    from .trace import merge_trace, run_trace
    run = (old or {}).get("run") or {}
    do_scan = run.get("scan", not no_scan) and not no_scan
    want_trace = run.get("trace")
    trace_cmd = trace_cmd or []
    if want_trace and trace_cmd != want_trace:
        return {"match": False, "refused": "This report was made with a trace, which runs the project's code. "
                "Lantern won't run a command taken from a report; check it and pass it yourself.",
                "trace_command": want_trace, "report": want}
    offline = bool(run.get("offline")) or offline
    with_types = isinstance(run.get("typecheck"), dict)
    if with_types and not typecheck:
        return {"match": False, "typecheck": True, "report": want,
                "refused": "This report was made with the type-aware pass (--typecheck), which asks the type checkers "
                           "installed on this computer where calls go. Lantern does not start them because a report "
                           "says so: add --typecheck to check it the same way."}
    from . import kept
    with kept.without():        # a verification does the work again: nothing kept from an earlier run is used
        g = build_graph(repo, typecheck=with_types)
        run_meta: dict = {"offline": offline}
        if g.meta.get("typecheck"):
            run_meta["typecheck"] = g.meta["typecheck"]
        if trace_cmd:
            tm = merge_trace(g, run_trace(repo, trace_cmd))
            run_meta["trace"] = {"command": trace_cmd, "returncode": tm["returncode"]}
        sec = scan(g, offline) if do_scan else None
    gi = git_info(repo)
    record, unread = results.earlier(beside, "behaviour.json") if beside is not None else (None, None)
    seen, seen_unread = results.earlier(beside, "browser.json") if beside is not None else (None, None)
    rd = assess(g, sec, run_meta, git=gi, behaviour=record, behaviour_unread=unread, out=beside, browser=seen,
                browser_unread=seen_unread)
    new = digest_payload(g, sec, rd, gi.get("commit"), gi.get("dirty", False), run_options(sec, run_meta))
    got = digest(new)
    differs = [k for k in new if old is not None and old.get(k) != new[k]] if old is not None else None
    return {"match": got == want, "report": want, "rerun": got, "commit": gi.get("commit"), "dirty": bool(gi.get("dirty")),
            "options": {"scan": do_scan, "trace": trace_cmd or None, "dependency_audit": not offline},
            "differs": differs,
            "note": None if got == want else ("Check out the report's commit, install the same scanner versions (see "
                                              "Provenance), and make sure lantern-accepted.json matches. Dependency "
                                              "findings come from live vulnerability databases, so new advisories "
                                              "alone can make a later run differ.")}


def compare_baseline(findings: list[dict], baseline: dict | None) -> tuple[list[dict], list[dict]]:
    """Baseline findings that are gone. A gone finding counts as fixed only if the same rule doesn't show up as a
    new finding in the same file; otherwise the flagged line was probably edited or moved, so it is listed as
    "changed, still open" and never as fixed. Baselines from before stable ids can't be compared."""
    if not baseline or baseline.get("id_version") != ID_VERSION:
        return [], []
    old = baseline.get("findings") or {}
    cur_ids = {f["id"] for f in findings}
    new_by_place = {(f.get("rule"), f.get("file")) for f in findings if f["id"] not in old and not f.get("in_tests")}
    fixed, changed = [], []
    for k, v in old.items():
        if k in cur_ids:
            continue
        (changed if (v.get("rule"), v.get("file")) in new_by_place else fixed).append(dict(v, id=k))
    return fixed, changed


RANKS = ("critical", "high", "medium", "low")
MOST_TEST_ROWS = 500     # findings in test code listed one by one on the page; the rest are counted
GROUP_AT = 3            # low findings of one rule and one title are folded into one row from this many on


def _grouped(items: list, frow) -> str:
    """The rows of a list of findings, with the low ones of one rule and one title folded into one row that opens to
    show each (a page with 40 `import subprocess` lines reads as one thing to look at, not 40). Nothing is left out:
    every finding is still a row inside its fold, and the counts are the same."""
    groups: dict[tuple, list] = {}
    for f in items:
        if f.get("rank") == "low":
            groups.setdefault((f.get("rule"), f.get("title")), []).append(f)
    out, done = [], set()
    for f in items:
        key = (f.get("rule"), f.get("title"))
        many = groups.get(key) if f.get("rank") == "low" else None
        if not many or len(many) < GROUP_AT:
            out.append(frow(f))
            continue
        if key in done:
            continue
        done.add(key)
        files = len({x.get("file") for x in many})
        out.append(f"<tr><td><span class='sev low'>low</span></td><td><details><summary><b>{E(f['title'])}</b> "
                   f"<span class='tag'>{len(many)} places in {files} file{'s' if files != 1 else ''}</span><br>"
                   f"<span class='muted'>{E(f.get('tool') or '')} {E(f['rule'])}: one kind of finding, folded; open it "
                   "to see each place</span></summary><table>" + "".join(frow(x) for x in many) + "</table></details></td></tr>")
    return "".join(out)


def _f(f: dict) -> dict:
    return {k: f.get(k) for k in ("id", "rank", "rule", "tool", "title", "file", "line", "tool_confidence", "hot_lane", "lanes")} | {
        "path": f.get("ui_path") or (f.get("reachable") or {}).get("path")}


def baseline_from(sec: dict | None, commit: str | None, rd: dict | None = None) -> dict:
    live = [f for f in (sec or {}).get("findings", []) if not f.get("in_tests")]
    return {"date": dt.date.today().isoformat(), "commit": commit, "id_version": ID_VERSION,
            "readiness": None if not rd else {"score": rd.get("score"), "grade": rd.get("grade"),
                                              "categories": {c["title"]: c.get("score") for c in rd.get("categories", [])}},
            "counts": {k: sum(1 for f in live if f["rank"] == k and f.get("status") == "open")
                       for k in ("critical", "high", "medium", "low")},
            "findings": {f["id"]: {"rule": f["rule"], "rank": f["rank"], "title": f["title"], "file": f["file"],
                                   "line": f["line"]} for f in live}}



_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"]


def _w(n: int, cap: bool = False) -> str:
    t = _WORDS[n] if 0 <= n < len(_WORDS) else str(n)
    return t[0].upper() + t[1:] if cap else t


def _memo(ev: dict) -> dict:
    """The sentences at the top of the report (design 4b): what changed since the baseline and what is open."""
    h, sc, se = ev["header"], ev["scorecard"], ev["security"]
    rd = sc.get("readiness") if isinstance(sc.get("readiness"), dict) else None
    base = sc.get("baseline_readiness") if isinstance(sc.get("baseline_readiness"), dict) else {}
    now_open = len(se["open"])
    crit = sum(1 for f in se["open"] if f["rank"] == "critical")
    high = sum(1 for f in se["open"] if f["rank"] == "high")
    name = E(h["name"])
    since = E(sc.get("baseline_date") or "")
    same_day = since == dt.date.today().isoformat()
    title = (f"What changed in {name} since {since}, and what is still open." if since and not same_day
             else f"Where {name} stands today, and what is still open.")
    parts = []
    rel = _release(ev)
    if rel:
        said = release.line(rel)[len(rel["decision"]):].rstrip()
        parts.append(f"Release decision: <b>{E(rel['decision'])}</b>{E(said[:400])}" + ("" if said.endswith(".") else "."))
    if rd:
        if isinstance(base.get("score"), (int, float)) and isinstance(rd["score"], (int, float)) and base["score"] != rd["score"] and not same_day:
            parts.append(f"Readiness moved from <b>{E(base['score'])} to {E(rd['score'])}</b> out of 100 "
                         f"({E(base.get('grade', '?'))} to {E(rd['grade'])}).")
        else:
            parts.append(f"Readiness is <b>{E(rd['score'])} of 100</b> (grade {E(rd['grade'])}).")
    if se["fixed"] or se["accepted"]:
        bits = []
        if se["fixed"]:
            bits.append(f"{_w(len(se['fixed']), True)} finding{'s were' if len(se['fixed']) != 1 else ' was'} fixed")
        if se["accepted"]:
            bits.append(f"{_w(len(se['accepted']), not se['fixed'])} risk{'s were' if len(se['accepted']) != 1 else ' was'} "
                        f"accepted with a written reason")
        parts.append(" and ".join(bits) + ".")
    if now_open:
        tail = []
        if crit:
            tail.append(f"{_w(crit)} of them critical")
        if high:
            tail.append(f"{_w(high)} high")
        parts.append(f"{_w(now_open, True)} finding{'s remain' if now_open != 1 else ' remains'} open"
                     + (", " + ", ".join(tail) if tail else "") + ".")
    else:
        parts.append("No findings are open.")
    inc = [x for x in (se.get("incomplete") or []) if isinstance(x, dict) and x.get("tool")]
    if inc:
        names = ", ".join(E(x["tool"]) for x in inc[:4]) + (f" and {len(inc) - 4} more" if len(inc) > 4 else "")
        parts.append(f"<b>The scan is incomplete:</b> {names} did not finish or did not cover everything, so anything "
                     f"{'it' if len(inc) == 1 else 'they'} would have found is missing from these numbers.")
    parts.append("Facts in this report come from Lantern's parsers and scanners on the commit above; a model wrote none of them.")
    # the "still open" paragraph: the critical ones with where they start
    crits = [f for f in se["open"] if f["rank"] == "critical"]
    if crits:
        where = []
        for f in crits[:3]:
            start = (f.get("path") or [None])[0]
            page = start.split("::")[-1] if start and "::" in start else (start.split(".")[-1] if start else None)
            where.append(f"{E(f['title']).rstrip('.')} (<code>{E(f['file'])}:{E(f.get('line') or '')}</code>"
                         + (f", reached from {E(page)}" if page else "") + ")")
        still = (f"{_w(len(crits), True)} critical finding{'s are' if len(crits) != 1 else ' is'} open: " + "; ".join(where)
                 + ". " + (f"{_w(high, True)} high, {_w(sum(1 for f in se['open'] if f['rank'] == 'medium'))} medium and "
                           f"{_w(sum(1 for f in se['open'] if f['rank'] == 'low'))} low follow below with their paths."
                           if now_open > len(crits) else ""))
    elif now_open:
        still = (f"Nothing critical is open. {_w(now_open, True)} finding{'s' if now_open != 1 else ''} remain"
                 f"{'' if now_open != 1 else 's'} open, listed below with their paths.")
    else:
        still = "Nothing is open. The scanners that ran and what they could not check are listed under Provenance and Limits."
    try:
        delta = (float(rd["score"]) - float(base["score"])) if rd and base.get("score") is not None and not same_day else None
    except (TypeError, ValueError):
        delta = None
    return {"title": title, "lead": " ".join(parts), "still": still, "delta": delta,
            "crit": crit, "high": high, "open": now_open}


# ---------------------------------------------------------------------------- render

def badge_text(ev: dict | None) -> str:
    """What the badge says, and nothing more: the commit, the open critical count, and the date. Never "verified"
    or "secure": no tool can promise that, and an engineer will pick at it. The badge links to the full report,
    whose Limits section says what was not checked."""
    ev = ev or {}
    h, now = ev.get("header") or {}, (ev.get("scorecard") or {}).get("now") or {}
    parts = []
    commit = re.sub(r"[^0-9a-f]", "", str(h.get("commit") or ""))
    if commit:
        parts.append(f"commit {commit[:7]}")
    crit = now.get("critical")
    if isinstance(crit, int) and not isinstance(crit, bool):
        parts.append(f"{crit} critical")
    rel = _release(ev)
    if _incomplete(ev):
        parts.append("scan incomplete")
    elif rel and rel["decision"] != "Passed":   # a release that is not passed says so; one that is says nothing more
        parts.append(rel["decision"].lower())
    when = str(h.get("generated_at") or "")[:10]
    if when:
        try:
            parts.append(dt.date.fromisoformat(when).strftime("%b %d").replace(" 0", " "))
        except ValueError:
            pass
    return " · ".join(parts) or "no analysis yet"


def _incomplete(ev: dict | None) -> bool:
    inc = ((ev or {}).get("security") or {}).get("incomplete") if isinstance((ev or {}).get("security"), dict) else None
    return isinstance(inc, list) and any(isinstance(x, dict) for x in inc)


def _release(ev: dict | None) -> dict | None:
    """The report's release decision when it has one of the three words; None for a report an older Lantern made
    and for a file that holds something else there."""
    rel = (ev or {}).get("release")
    return rel if isinstance(rel, dict) and rel.get("decision") in release.DECISIONS else None


def badge_svg(score: int | None = None, grade: str | None = None, ev: dict | None = None) -> str:
    """`Lantern · commit 1a2b3c · 0 critical · Oct 31`. Color follows the open findings (none critical or high:
    good), not the readiness score, which stays in the tooltip. A scan that did not finish is never green: it says
    "scan incomplete" in grey, because "0 critical" from a scanner that did not run is not a result. Since 2026-11
    the badge is green only for a release that Passed (release.py): a blocked one says "blocked" (the color of the
    findings, or of a high one when tests or a behaviour check block it), an incomplete one "incomplete" in grey.
    A report an older Lantern made has no decision and keeps the older rule."""
    now = ((ev or {}).get("scorecard") or {}).get("now") or {}
    crit = now.get("critical") if isinstance(now.get("critical"), int) else 0
    high = now.get("high") if isinstance(now.get("high"), int) else 0
    rel = _release(ev)
    blocked, short = bool(rel and rel["decision"] == "Blocked"), bool(rel and rel["decision"] == "Incomplete")
    color = ("#B42318" if crit else "#B54708" if high or blocked else "#64748B" if _incomplete(ev) or short
             else "#0D9488" if now else "#64748B")
    right = badge_text(ev)
    title = f"Lantern: {right}" + (f"; readiness {score}/100 {grade}" if score is not None and grade else "") + (
        f"; release decision {rel['decision']}" if rel else "")
    w1, w2 = 58, 12 + round(6.3 * len(right))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w1 + w2}" height="20" role="img" '
            f'aria-label="{html.escape(title, quote=True)}"><title>{html.escape(title)}</title>'
            f'<rect width="{w1}" height="20" rx="3" fill="#0F1B2D"/>'
            f'<rect x="{w1}" width="{w2}" height="20" fill="{color}"/><rect x="{w1}" width="3" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="7" y="14">Lantern</text><text x="{w1 + 6}" y="14">{html.escape(right)}</text></g></svg>')


def badge_record(ev) -> dict:
    """What the badge shows, out of an evidence record read back from a results folder (which a project can bring
    along), each part only in the shape Lantern writes it: the commit's letters, when the report was made, the open
    critical and high counts, the release decision, and whether a scanner that applies did not finish. Until
    2026-11-17 the badge the app and the website serve (`server.result_page`) was drawn from the first three only:
    it was green and said nothing more for a release that was Incomplete, or Blocked by its tests, where the badge
    drawn from the whole record said "incomplete" or "blocked"."""
    ev = ev if isinstance(ev, dict) else {}
    h = ev.get("header") if isinstance(ev.get("header"), dict) else {}
    sc = ev.get("scorecard") if isinstance(ev.get("scorecard"), dict) else {}
    now = sc.get("now") if isinstance(sc.get("now"), dict) else None
    out = {"header": {"commit": re.sub(r"[^0-9a-f]", "", str(h.get("commit") or ""))[:64] or None,
                      "generated_at": h["generated_at"][:80] if isinstance(h.get("generated_at"), str) else None},
           "scorecard": {"now": {k: _whole(now.get(k)) for k in ("critical", "high")} if now else {}}}
    rel = _release(ev)
    if rel:
        out["release"] = {"decision": rel["decision"]}
    if _incomplete(ev):
        out["security"] = {"incomplete": [{}]}
    return out


# --------------------------------------------------------------- the page a shared badge links to (roadmap stage 6)
# A check shared from the website has a page of its own beside its report (`/s/<slug>/check.html`, cloud/): the
# commit, a fingerprint of the code, the release decision, how many of the scanners that apply finished, and one
# line that repeats the check on anybody's computer and ends with MATCH when the results are the same. What the page
# says the check found is read from the part of the record that its fingerprint (`digest`) is made of, and only when
# the fingerprint is that part's own; so the line, which makes the fingerprint again, checks it. Two things come from
# the rest of the record: whether a scanner that was skipped had work to do (its list of scanners that apply and did
# not finish), and the time and the Lantern the line installs (its header, which the website writes itself: another
# Lantern of that repository makes the line end with MATCH only where it makes the same results, which is all MATCH
# says; a commit of a fork, which GitHub also hands out through that repository's address, could say anything, so the
# line is as good as the website that wrote the record). The page says what it is and what it is not: it is served
# while the owner shares it, and it is no promise that the app is safe.
RESULTS_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
CODE_DIGEST = re.compile(r"[0-9a-f]{64}")
CLONE_LINK = re.compile(r"https://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?"
                        r"/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
ENGINE_REF = re.compile(r"[0-9a-f]{40}|v[0-9A-Za-z.+-]{1,40}")
TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,39}(?::[A-Za-z0-9][A-Za-z0-9_.+-]{0,39})?")
TOOL_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z_.+-]{0,39}")
LANTERN_VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]{0,39}")
WHEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?: [0-9]{2}:[0-9]{2} UTC)?")
LANTERN_SOURCE = "https://github.com/LittleHenderson/Lantern"
CHECK_FOLDER = "lantern-check"
CHECK_POLICY = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'none'")
CHECK_SAYS = {
    "Passed": "Every check Lantern requires for this kind of project passed on this commit.",
    "Incomplete": "Nothing Lantern checked failed, and something it requires was not checked on this commit.",
    "Blocked": "Something Lantern requires failed on this commit.",
}
CRITERION_SAYS = {"passed": "passed", "failed": "failed", "missing": "not checked", "not-applicable": "not required"}
SCANNER_LEFT = {"partial": "covered only part of the project", "failed": "did not finish", "timeout": "ran out of time",
                "unavailable": "is not installed", "skipped": "was not run"}
# a scanner's state as the fingerprinted part writes it (`digest_payload`: the first two letters of its status) and
# the states that agree with it; a scanner that covered only part of the project or did not finish always had work
# to do (`scanresult.applicable`), one that was skipped only where the record's own list says so
LEFT_AS = {"pa": ("partial",), "er": ("failed", "timeout")}
NOT_WHOLE = ("This check's record does not hold together: its fingerprint is not the one of its own data. Nothing "
             "on this page can be checked, so no line to check it is given.")
NOT_A_COMMIT = ("This check was of files that no commit holds (an upload, a sample app, or changes that were not "
                "committed), so there is no commit to check out and repeat it on.")


def install_words(engine: str | None) -> str:
    """The command that installs the Lantern a report names (`engine_ref`: that commit or release; else the newest)."""
    return f'pip install "lantern[scan] @ git+{LANTERN_SOURCE}{"@" + engine if engine else ""}"'


def check_facts(ev, link: str | None = None) -> dict:
    """What the page a shared badge links to says, from an evidence record and the link the project was cloned from
    (None for an upload or a sample app). Read only from the part of the record its fingerprint is made of
    (`payload`), and only when the fingerprint is that part's own (`whole`): a scanner it names as having covered only
    part of the project, or as not having finished, is one that did not finish (the record's own list may only say
    which way, `LEFT_AS`); one it names as skipped counts only where that list names it. Every value is taken only in
    the shape Lantern writes it, and the link only as `remote.parse` reads it, put together again from its parts
    and of plain letters (`CLONE_LINK`), so nothing a record or a link holds becomes words of a line to run."""
    ev = ev if isinstance(ev, dict) else {}
    said = ev.get("digest") if isinstance(ev.get("digest"), str) and RESULTS_DIGEST.fullmatch(ev["digest"]) else None
    p = ev.get("payload") if isinstance(ev.get("payload"), dict) else None
    try:
        whole = bool(p is not None and said and digest(p) == said)
    except (TypeError, ValueError, RecursionError):
        whole = False
    p = p if whole else {}
    rd = p.get("readiness") if isinstance(p.get("readiness"), dict) else {}
    rel = rd.get("release") if isinstance(rd.get("release"), dict) else {}
    run = p.get("run") if isinstance(p.get("run"), dict) else {}
    tools: dict[str, tuple[str | None, str]] = {}
    for x in p.get("scanners") if isinstance(p.get("scanners"), list) else []:
        if isinstance(x, str) and x.count(":") >= 2:
            name, version, st = x.rsplit(":", 2)
            if TOOL_NAME.fullmatch(name):
                tools[name] = (version if TOOL_VERSION.fullmatch(version) and version != "None" else None, st)
    finished = sorted(n for n, (_v, st) in tools.items() if st == "ok")
    sec = ev.get("security") if isinstance(ev.get("security"), dict) else {}
    listed: dict[str, object] = {}
    for t in sec.get("incomplete") if isinstance(sec.get("incomplete"), list) else []:
        if isinstance(t, dict) and isinstance(t.get("tool"), str):
            listed[t["tool"]] = t.get("state")
    left: dict[str, str] = {}
    for name, (_v, st) in tools.items():
        state = listed.get(name)
        if st in LEFT_AS:
            left[name] = state if state in LEFT_AS[st] else LEFT_AS[st][0]
        elif st != "ok" and name in listed:
            left[name] = state if state in ("unavailable", "skipped") else "skipped"
    criteria = []
    for x in rel.get("criteria") if isinstance(rel.get("criteria"), list) else []:
        cid, _, state = x.partition(":") if isinstance(x, str) else ("", "", "")
        if cid in release.TITLES and state in CRITERION_SAYS:
            criteria.append((cid, state))
    h = ev.get("header") if isinstance(ev.get("header"), dict) else {}
    clone = name = None
    if isinstance(link, str) and link.strip():
        from . import remote
        try:
            info = remote.parse(link)
        except (ValueError, RuntimeError, TypeError):
            info = None
        if info and CLONE_LINK.fullmatch(info["url"]):
            clone, name = info["url"], f"{info['owner']}/{info['name']}"
    applies = len(finished) + len(left)
    text = lambda v, rx: v if isinstance(v, str) and rx.fullmatch(v) else None   # noqa: E731
    return {
        "whole": whole, "digest": said if whole else None, "commit": commit_named(p.get("commit")),
        "uncommitted": p.get("uncommitted_changes") is True, "code": text(rel.get("code"), CODE_DIGEST),
        "decision": rel.get("decision") if rel.get("decision") in release.DECISIONS else None,
        "criteria": criteria, "finished": finished, "left": sorted(left.items()), "applies": applies,
        "percent": 100 * len(finished) // applies if applies else None,
        "versions": [(n, tools[n][0]) for n in sorted(tools)],
        "when": text(h.get("generated_at"), WHEN), "lantern": text(p.get("lantern"), LANTERN_VERSION),
        "engine": text(h.get("engine"), ENGINE_REF),
        "scan": run.get("scan") is not False, "offline": run.get("offline") is True, "trace": bool(run.get("trace")),
        "typecheck": run.get("typecheck") is not None, "workspace": "workspace" in p,
        "link": clone, "name": name,
    }


def check_line(f: dict) -> tuple[str | None, str]:
    """The one line that repeats a check (`check_facts`) on anybody's computer, and a sentence to say beside it;
    `(None, why)` where no line can repeat it. A check that ran the project's tests or asked this computer's type
    checkers gets none: `lantern verify` with a fingerprint alone does neither, and a line from a page does not start
    the project's code."""
    if not f["whole"]:
        return None, NOT_WHOLE
    if f["workspace"]:
        return None, ("This check read several projects as one map, which is put together on the computer that holds "
                      "them, so it cannot be repeated from a link.")
    if not f["commit"] or f["uncommitted"]:
        return None, NOT_A_COMMIT
    if f["trace"]:
        return None, ("This check ran the project's tests, which runs the project's code. Lantern does not write a "
                      "line that runs a project's code; the evidence page names the command, word by word.")
    if f["typecheck"]:
        return None, ("This check also asked the type checkers of the computer it ran on, which a line from a page "
                      "does not start; the evidence page says how to check such a report.")
    run = (f"lantern verify . --digest {f['digest']}" + (" --offline" if f["offline"] else "")
           + ("" if f["scan"] else " --no-scan"))
    steps = ([f"git clone {f['link']} {CHECK_FOLDER}", f"cd {CHECK_FOLDER}"] if f["link"] else []) + [
        f"git checkout {f['commit']}", install_words(f["engine"]), run]
    return " && ".join(steps), ("" if f["link"] else "Run it in a copy of the project's repository.")


CHECK_STYLE = """.verdict{margin:16px 0 20px;padding:12px 16px;border-radius:12px;background:var(--hover);color:var(--ink);font-size:15px;line-height:1.55}
.verdict b{margin-right:6px} .verdict.good b{color:var(--good-ink)} .verdict.warning b{color:var(--warn-ink)} .verdict.critical b{color:var(--crit-ink)}
pre.line{white-space:pre-wrap;overflow-wrap:anywhere;font:12.5px/1.65 var(--mono);background:var(--soft);color:var(--ink);padding:12px 14px;border-radius:10px;margin:12px 0}
.badge{display:block;margin:0 0 6px;max-width:100%;height:auto} .muted{color:var(--muted)} a{color:var(--accent-ink)}
.topbar a.brand{display:inline-flex;align-items:center;gap:8px;color:var(--ink);text-decoration:none;font-size:15px}
.topbar .mark{width:24px;height:24px;flex:none}"""
# Lantern's mark, as the report and the app draw it
BRAND_MARK = ("<svg class='mark' viewBox='0 0 64 64' aria-hidden='true'><rect width='64' height='64' rx='15' fill='#141416'/>"
              "<path d='M26 13h12M25 51h14' stroke='#F3F3F1' stroke-width='3' stroke-linecap='round'/>"
              "<path d='M22 19h20l-2.5 27h-15z' fill='none' stroke='#F3F3F1' stroke-width='3' stroke-linejoin='round'/>"
              "<path d='M32 25.5c3.2 3.6 4.8 6.3 4.8 8.8a4.8 4.8 0 0 1-9.6 0c0-2.5 1.6-5.2 4.8-8.8z' fill='#FFB547'/></svg>")


def check_html(ev, link: str | None = None) -> str:
    """The page a shared badge links to (`/s/<slug>/check.html` on the website): what the check found, what it is
    tied to and the line that repeats it. No script; every value is escaped and was taken only in the shape Lantern
    writes it (`check_facts`)."""
    f = check_facts(ev, link)
    line, beside = check_line(f)
    title = "Lantern check" + (f" of {f['name']}" if f["name"] else "")
    mark, look = DECISION_LOOK.get(f["decision"] or "", ("–", "none"))
    verdict = (f"<p class='verdict {look}'><b>{mark} {E(f['decision'])}</b> {E(CHECK_SAYS[f['decision']])}</p>"
               if f["decision"] else "<p class='verdict none'><b>– No decision</b> This record names no release "
                                     "decision.</p>")
    if f["applies"]:
        scanners = (f"{len(f['finished'])} of {f['applies']} that apply finished and left out nothing they read "
                    f"({f['percent']}%)" + "".join(f"<br><span class='muted'>{E(n)} {E(SCANNER_LEFT[s])}</span>"
                                                     for n, s in f["left"]))
    else:
        scanners = "No scanner that applies was run." if f["whole"] else "not known"
    code = (f"<code title='{E(f['code'])}'>{E(f['code'][:12])}…</code> <span class='muted'>(SHA-256 of every file of "
            "the project, each by its path and what it holds)</span>") if f["code"] else "not known"
    rows = [("Commit", f"<code>{E(f['commit'])}</code>" if f["commit"] else "none"),
            ("Code fingerprint", code),
            ("Release decision", E(f["decision"] or "none")),
            ("Scanners", scanners),
            ("Checked", (E(f["when"]) if f["when"] else "at a time not known")
             + (f" with Lantern {E(f['lantern'])}" if f["lantern"] else "")),
            ("Results fingerprint", f"<code>{E(f['digest'])}</code>" if f["digest"] else "not known")]
    kv = "".join(f"<div>{E(k)}</div><div>{v}</div>" for k, v in rows)
    crit = "".join(f"<li>{E(release.TITLES[c])}: <b>{E(CRITERION_SAYS[s])}</b></li>" for c, s in f["criteria"])
    versions = ", ".join(f"{E(n)} {E(v)}" if v else f"{E(n)} (version not known)" for n, v in f["versions"])
    if line:
        how = ("<p>Anyone can repeat this check on their own computer. The line "
               + (f"copies the project into a folder called <code>{CHECK_FOLDER}</code>, " if f["link"] else "")
               + "checks out this commit, installs the Lantern that made the check and runs it again. It ends with "
               "MATCH when the results are the same, and with DIFFERENT when they are not.</p>"
               + (f"<p>{E(beside)}</p>" if beside else "") + f"<pre class='line'><code>{E(line)}</code></pre>"
               + "<p class='muted'>The same results need the same scanners at the same versions"
               + (f": {versions}." if versions else ".")
               + (" The check was made offline: no library was looked up, and the line looks none up either."
                  if f["offline"] else " Libraries are looked up in live advisory databases, so an advisory "
                  "published since this check can make that part differ.") + "</p>")
    else:
        how = f"<p>{E(beside)}</p>"
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'><meta name='robots' content='noindex'>"
            f"<meta name='referrer' content='no-referrer'><title>{E(title)}</title>"
            f"<style>{STYLE}{CHECK_STYLE}</style></head><body data-mode='simple'><main>"
            # served only by Lantern (the website's /s/<slug>/, which has / and /guide), and with no script to choose a
            # link: the logo opens the website, which says what Lantern is
            "<div class='topbar'><a class='brand' href='/' title='Lantern: what it is, and how to check an app of your "
            f"own' aria-label='Lantern: what it is, and how to check an app of your own'>{BRAND_MARK}<b>Lantern</b></a>"
            "<span class='sp'></span><a class='btn' id='guidelink' href='/guide' title='How to use Lantern: short "
            "animated demos'>How to use Lantern</a></div>"
            f"<section><img class='badge' src='badge.svg' alt='The badge of this check' height='20'>"
            f"<h1>{E(title)}</h1>{verdict}<div class='kv'>{kv}</div>"
            + (f"<h4>What the decision is made of</h4><ul>{crit}</ul>" if crit else "") + "</section>"
            f"<section><h2>Check it yourself</h2>{how}</section>"
            "<section><h2>What this page does not say</h2><p>It does not say that the app is safe. It says what "
            "Lantern's checks found on this commit and what they could not check: the <a href='evidence.html'>"
            "evidence page</a> lists both, and the <a href='report.html'>report</a> shows every finding.</p>"
            "<p class='muted'>The owner of this check shared this page and can take it back at any time; the link "
            "then says that it is off.</p></section></main></body></html>")


def E(v) -> str:
    """Escape anything for HTML. The renderer also runs on `evidence.json` read back from a repo folder, so no
    field is trusted to be the type or text we wrote."""
    return html.escape("" if v is None else str(v), quote=True)


# A line a reader is told to copy and run holds nothing a report wrote but its commit, and that only as what a
# commit's name can be. A report lies in the project's folder and may be anybody's: until 2026-11-15 the commit went
# into the line as the report wrote it, and the tests' command of a report made with a test run was joined to it
# with spaces (`lantern verify … -- <the report's words>`), on the page, in `lantern verify`'s refusal and in the
# connector's. What a shell does with a line is decided by the line, and escaping for a page changes none of it.
NO_COMMIT_LINE = "Commit your changes and regenerate the report to make it verifiable."
WORDS_SHOWN = 600     # characters of a report's test command that are shown
MOST_WORDS = 40


def commit_named(said) -> str | None:
    """The commit a report names, when it is what a commit's whole name can be (40 or 64 letters of 0-9a-f)."""
    return said if isinstance(said, str) and gitfacts.HEX.fullmatch(said) else None


def words_shown(cmd) -> str:
    """A report's test command as what the report says: a list of its words, each in quotes, with every character
    that is not plain text written by its number (so nothing of it does anything in a terminal or reads as a line
    to run). "" when the report names none. Cut short, and said, past `MOST_WORDS` words or `WORDS_SHOWN` characters."""
    if not isinstance(cmd, list) or not cmd:
        return ""
    text = json.dumps([w if isinstance(w, str) else str(w)[:200] for w in cmd[:MOST_WORDS]])
    if len(cmd) > MOST_WORDS or len(text) > WORDS_SHOWN:
        return text[:WORDS_SHOWN] + " (cut short)"
    return text


def _words_of(ev: dict) -> str:
    run = ev["payload"].get("run") if isinstance(ev.get("payload"), dict) else None
    return words_shown(run.get("trace") if isinstance(run, dict) else None)


def _pct(v) -> float:
    return max(0.0, min(100.0, float(v))) if isinstance(v, (int, float)) else 0.0


def _deploy_svg(shape: str | None) -> str:
    boxes = {
        "full-stack web app": [("Browser", "your frontend (static / edge)"), ("API", "container, 2+ instances"),
                               ("Database", "managed, backups on")],
        "web API": [("Clients", "apps and services"), ("API", "container, 2+ instances"), ("Database", "managed")],
        "frontend web app": [("Browser", "visitors"), ("Edge / CDN", "static hosting"), ("APIs", "third-party services")],
        "command-line tool": [("Source", "tagged release"), ("CI", "build + test on 3 OSes"), ("Registry", "PyPI / npm")],
        "script or worker": [("Scheduler", "cron or queue"), ("Worker", "container, retries"), ("Logs", "kept 30+ days")],
        "library": [("Source", "tagged release"), ("CI", "tests"), ("Registry", "PyPI / npm")],
    }.get(shape or "", [])
    if not boxes:
        return ""
    w, bw, gap = 660, 180, 50
    parts = [f'<svg viewBox="0 0 {w} 90" width="100%" role="img" aria-label="Recommended deployment">',
             '<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
             'orient="auto"><path d="M0 0L10 5L0 10z" fill="currentColor"/></marker></defs>']
    for i, (t, sub) in enumerate(boxes):
        x = 10 + i * (bw + gap)
        parts.append(f'<rect x="{x}" y="15" width="{bw}" height="60" rx="10" fill="none" stroke="currentColor" '
                     f'stroke-opacity=".35"/><text x="{x + bw / 2}" y="41" text-anchor="middle" font-weight="700" '
                     f'font-size="14" fill="currentColor">{E(t)}</text><text x="{x + bw / 2}" y="60" '
                     f'text-anchor="middle" font-size="11" fill="currentColor" fill-opacity=".7">{E(sub)}</text>')
        if i:
            parts.append(f'<line x1="{x - gap + 4}" y1="45" x2="{x - 4}" y2="45" stroke="currentColor" '
                         f'marker-end="url(#a)"/>')
    return "".join(parts) + "</svg>"


def _narratives_html(text: str) -> str:
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        b = block.strip()
        m = re.match(r"^(#{1,4})\s+(.*)", b)
        if m and "\n" not in b:
            out.append(f"<h4>{E(m.group(2))}</h4>")
        else:
            out.append(f"<p>{E(b)}</p>".replace("\n", "<br>"))
    return "".join(out)


DECISION_LOOK = {"Blocked": ("✕", "critical"), "Incomplete": ("◐", "warning"), "Passed": ("✓", "good")}
STATE_LOOK = {"passed": ("✓", "passed", "good"), "failed": ("✕", "failed", "critical"),
              "missing": ("◐", "missing", "warning"), "not-applicable": ("–", "not required", "none")}


def _release_html(ev: dict) -> str:
    """The release decision for the Scorecard section: the word, each criterion with its reason and what to do, the
    profile, and what the decision is tied to. Every value is escaped and taken only in the shape Lantern writes:
    the page is also rebuilt from an `evidence.json` read back from a project's folder."""
    rel = _release(ev)
    if not rel:
        return ""
    text = lambda v, n=600: E(v[:n]) if isinstance(v, str) else ""   # noqa: E731
    table = lambda v: v if isinstance(v, dict) else {}               # noqa: E731
    mark, tone = DECISION_LOOK[rel["decision"]]
    rows = []
    for c in rel.get("criteria") or []:
        if not isinstance(c, dict):
            continue
        m, word, t = STATE_LOOK.get(c.get("state"), ("?", "not known", "none"))
        rows.append(f"<tr><td><span class='st {t}'>{m} {word}</span></td><td><b>{text(c.get('title'), 200)}</b>"
                    f"<div class='muted'>{text(c.get('why'))}</div>"
                    + (f"<div>{text(c.get('fix'))}</div>" if c.get("state") in ("failed", "missing") and c.get("fix") else "")
                    + "</td></tr>")
    prof = table(rel.get("profile"))
    b = table(rel.get("bound_to"))
    code, deps, st = table(b.get("code")), table(b.get("dependencies")), table(b.get("settings"))
    sha = lambda v: f"<code>{E(v)}</code>" if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) else "–"   # noqa: E731
    commit = b.get("commit") if isinstance(b.get("commit"), str) else None
    tied = [("Commit", (f"<code>{E(commit[:12])}</code>" + (" with uncommitted changes" if b.get("uncommitted_changes") else ""))
             if commit else "no git commit"),
            ("Code", f"{E(code.get('files'))} files, SHA-256 {sha(code.get('sha256'))}"
             + (f" · {E(code.get('not_read'))} could not be read" if code.get("not_read") else "")
             + (f"<div class='muted'>Not counted: {text(code.get('left_out'), 300)}.</div>" if code.get("left_out") else "")),
            ("Library lists", (f"{E(deps.get('count'))} file{'s' if deps.get('count') != 1 else ''}, SHA-256 {sha(deps.get('sha256'))}"
                               + "".join(f"<div class='muted'><code>{E(str(k)[:200])}</code> {sha(v)}</div>"
                                         for k, v in list(table(deps.get('files')).items())[:12]))
             if deps.get("count") else "none"),
            ("Settings", " · ".join(x for x in (
                "security scan on" if st.get("scan") else "security scan off",
                ("tests run with <code>" + E(" ".join(str(w) for w in st["trace"])[:200]) + "</code>")
                if isinstance(st.get("trace"), list) and st["trace"] else "tests not run",
                "library check offline" if st.get("offline") else "library check online",
                f"made on {text(st.get('place'), 40) or 'this computer'}",
                ("packs switched off: " + E(", ".join(str(x) for x in st["packs_off"])[:300]))
                if isinstance(st.get("packs_off"), list) and st["packs_off"] else "") if x)
             + (f"<div class='muted'>Accepted risks file: {sha(st.get('accepted_sha256'))}</div>" if st.get("accepted_sha256") else "")
             + (f"<div class='muted'>Behaviour plan: {sha(st.get('plan_sha256'))}</div>" if st.get("plan_sha256") else "")),
            ("Tools", ", ".join(f"{text(t.get('tool'), 60)} {text(t.get('version'), 40) or '?'}"
                                + (f" ({text(t.get('state'), 30)})" if t.get("state") else "")
                                for t in (b.get("tools") or [])[:40] if isinstance(t, dict)) or "–")]
    req = ", ".join(E(str(x)[:40]) for x in prof.get("required") or [] if isinstance(x, str)) or "–"
    not_req = "".join(f"<div class='muted'>Not required: {E(str(x.get('id'))[:40])}. {text(x.get('why'))}</div>"
                      for x in prof.get("not_required") or [] if isinstance(x, dict))
    return (f"<div class='rel {tone}'><b>{mark} Release decision: {E(rel['decision'])}</b>"
            f"<div>{text(rel.get('words'), 1500)}</div></div>"
            f"<table class='crit'>{''.join(rows)}</table>"
            f"<p class='muted'>The decision comes from these criteria, never from the score. Profile: "
            f"{text(prof.get('name'), 80) or '–'}. Required: {req}.</p>{not_req}"
            "<details class='tied'><summary>What this decision is tied to</summary><div class='kv'>"
            + "".join(f"<div>{k}</div><div>{v}</div>" for k, v in tied) + "</div></details>")


# The Evidence page's style sheet: the design tokens of `viewer/app.html` and `viewer/report.html` (one set; change all three
# together). A constant, so that another page Lantern builds without script (`lantern/diff.py`: the change receipt) wears the
# same look and no fourth copy of the tokens is written.
STYLE = """:root{color-scheme:light;--bg:#F5F5F2;--panel:#FFFFFF;--panel-2:#FAFAF8;--ink:#161618;--body:#46464C;--muted:#62626A;--faint:#A3A3A8;--line:rgba(22,22,24,.09);--line-2:rgba(22,22,24,.16);--soft:#EEEEEA;--hover:rgba(22,22,24,.045);
--accent:#0F7B74;--accent-ink:#0B5F5A;--good:#0CA30C;--warning:#FAB219;--serious:#EC835A;--critical:#D03B3B;
--good-soft:rgba(12,163,12,.11);--warning-soft:rgba(250,178,25,.17);--serious-soft:rgba(236,131,90,.16);--critical-soft:rgba(208,59,59,.11);--good-ink:#0A7A0A;--warn-ink:#8A5A00;--crit-ink:#B02A2A;
--font:"DM Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--display:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI Variable Display","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SF Mono","Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace;
--serif:"Lora",Georgia,"Times New Roman",serif}
:root[data-theme=dark]{color-scheme:dark;--bg:#0E0E10;--panel:#161618;--panel-2:#1B1B1E;--ink:#F3F3F1;--body:#BEBEC3;--muted:#9A9AA0;--faint:#5E5E64;--line:rgba(255,255,255,.08);--line-2:rgba(255,255,255,.15);--soft:#0A0A0B;--hover:rgba(255,255,255,.05);
--accent:#4FC3BA;--accent-ink:#7FDBD3;--good-soft:rgba(12,163,12,.20);--warning-soft:rgba(250,178,25,.18);--serious-soft:rgba(236,131,90,.20);--critical-soft:rgba(208,59,59,.22);--good-ink:#5BD15B;--warn-ink:#FAC55A;--crit-ink:#FF8A8A}
@media (prefers-color-scheme: dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#0E0E10;--panel:#161618;--panel-2:#1B1B1E;--ink:#F3F3F1;--body:#BEBEC3;--muted:#9A9AA0;--faint:#5E5E64;--line:rgba(255,255,255,.08);--line-2:rgba(255,255,255,.15);--soft:#0A0A0B;--hover:rgba(255,255,255,.05);
--accent:#4FC3BA;--accent-ink:#7FDBD3;--good-soft:rgba(12,163,12,.20);--warning-soft:rgba(250,178,25,.18);--serious-soft:rgba(236,131,90,.20);--critical-soft:rgba(208,59,59,.22);--good-ink:#5BD15B;--warn-ink:#FAC55A;--crit-ink:#FF8A8A}}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--body);font:14px/1.6 var(--font);-webkit-font-smoothing:antialiased}
main{max-width:880px;margin:0 auto;padding:40px 20px 80px}
section{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:24px 26px;margin:0 0 16px;box-shadow:0 1px 2px rgba(16,16,20,.05)}
section:first-child{position:relative;overflow:hidden}
section:first-child::after{content:"";position:absolute;right:-80px;top:-120px;width:320px;height:260px;background:radial-gradient(closest-side,rgba(255,181,71,.18),transparent);pointer-events:none}
h1{color:var(--ink);font:700 30px/1.15 var(--display);letter-spacing:-.028em;margin:0 0 6px} h2{color:var(--ink);font:650 17px/1.3 var(--display);letter-spacing:-.012em;margin:0 0 14px}
h2 small{color:var(--muted);font:400 13px var(--font);letter-spacing:0} h4{color:var(--ink);font:650 14.5px var(--display);margin:20px 0 8px}
code{font:12.5px var(--mono);background:var(--soft);color:var(--ink);padding:1px 6px;border-radius:6px;overflow-wrap:anywhere}
.muted{color:var(--muted)} .warn{color:var(--warn-ink)}
.incomplete{margin:14px 0 0;padding:10px 14px;border-radius:10px;background:var(--warning-soft);color:var(--ink);font-size:14px;line-height:1.5} .incomplete b{color:var(--warn-ink)}
.rel{margin:0 0 12px;padding:12px 16px;border-radius:12px;background:var(--hover);color:var(--ink);font-size:14px;line-height:1.5} .rel b{font-size:16px}
.rel.critical{background:var(--critical-soft)} .rel.critical b{color:var(--crit-ink)} .rel.warning{background:var(--warning-soft)} .rel.warning b{color:var(--warn-ink)} .rel.good{background:var(--good-soft)} .rel.good b{color:var(--good-ink)}
.crit td{vertical-align:top} .st{display:inline-block;white-space:nowrap;font-size:11.5px;font-weight:600;padding:1px 9px;border-radius:99px;background:var(--hover);color:var(--ink)}
.st.critical{background:var(--critical-soft);color:var(--crit-ink)} .st.warning{background:var(--warning-soft);color:var(--warn-ink)} .st.good{background:var(--good-soft);color:var(--good-ink)}
.tied{margin:10px 0 16px} .tied summary{cursor:pointer;font-weight:600} .tied code{word-break:break-all}
.kv{display:grid;grid-template-columns:160px 1fr;gap:8px 16px} .kv div:nth-child(odd){color:var(--muted)} .kv div:nth-child(even){color:var(--ink)}
.score{display:flex;gap:20px;align-items:center;flex-wrap:wrap} .big{font:700 52px/1 var(--display);letter-spacing:-.035em;color:var(--ink);font-variant-numeric:tabular-nums}
.grade{font:700 20px/1 var(--display);width:46px;height:46px;border-radius:13px;display:grid;place-items:center;background:var(--hover);color:var(--ink)}
.grade.A,.grade.B{background:var(--good-soft)} .grade.C{background:var(--warning-soft)} .grade.D{background:var(--serious-soft)} .grade.F{background:var(--critical-soft)}
table{width:100%;border-collapse:collapse} td{padding:10px 8px;border-top:1px solid var(--line);vertical-align:top} tr:first-child td{border-top:0}
td.num{text-align:right;white-space:nowrap;width:76px;font:12.5px var(--mono);font-variant-numeric:tabular-nums;color:var(--ink)}
.bar{display:block;height:6px;border-radius:99px;background:var(--soft);overflow:hidden;min-width:80px;margin-top:8px} .bar i{display:block;height:100%;border-radius:99px;background:var(--ink)}
.sev{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:600;padding:1px 9px 1px 7px;border-radius:99px;white-space:nowrap;background:var(--hover);color:var(--ink)}
.sev::before{content:"";width:7px;height:7px;border-radius:99px;background:var(--faint)}
.sev.critical{background:var(--critical-soft)} .sev.critical::before{background:var(--critical)} .sev.high{background:var(--serious-soft)} .sev.high::before{background:var(--serious)}
.sev.medium{background:var(--warning-soft)} .sev.medium::before{background:var(--warning)} .sev.low{background:var(--good-soft)} .sev.low::before{background:var(--good)}
.tag{display:inline-block;font-size:11px;font-weight:550;padding:1px 8px;border-radius:99px;border:1px solid var(--line-2);color:var(--body)} .tag.ok{color:var(--good-ink);border-color:var(--good);background:var(--good-soft)}
.path{font:11.5px var(--mono);color:var(--accent-ink)} .glyph{display:inline-flex;gap:3px;vertical-align:middle;margin-right:6px} .glyph i{width:7px;height:7px;border-radius:99px;border:1.2px solid var(--line-2);display:inline-block} .glyph i.lit{background:var(--body);border-color:var(--body)} .glyph i.hot{background:var(--accent);border-color:var(--accent)} .glyph i.hot.critical,.glyph i.hot.high{background:var(--critical);border-color:var(--critical)} .onlane{margin-right:8px} .onlane b{color:var(--ink)} .reason{margin-top:6px;padding:8px 10px;background:var(--panel-2);border:1px solid var(--line);border-radius:9px}
ul{padding-left:20px;margin:8px 0} li{margin:4px 0}
.digest{font:12px var(--mono);overflow-wrap:anywhere;color:var(--ink);background:var(--soft);padding:2px 6px;border-radius:6px}
.diagram{color:var(--ink);margin:12px 0}
button.print{float:right;position:relative;z-index:1;font:inherit;font-size:12.5px;font-weight:600;height:32px;padding:0 14px;border-radius:9px;border:1px solid var(--line-2);background:var(--panel);color:var(--ink);cursor:pointer}
.topbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 18px} .topbar .sp{flex:1}
.seg{display:inline-flex;gap:2px;padding:3px;border-radius:10px;background:var(--hover)} .seg button{font:600 12px var(--font);padding:5px 10px;border-radius:7px;border:0;background:none;color:var(--muted);cursor:pointer} .seg button.on{background:var(--panel);color:var(--ink);box-shadow:0 1px 2px rgba(16,16,20,.08),0 0 0 1px var(--line)}
.topbar .btn{font:600 12.5px var(--font);height:32px;padding:0 12px;border-radius:9px;border:1px solid var(--line-2);background:var(--panel);color:var(--ink);cursor:pointer}
.topbar .dg{font:12px var(--mono);color:var(--muted);padding:0 8px}
.topbar a.btn{display:inline-flex;align-items:center;text-decoration:none} #guidelink[hidden]{display:none}
.eyebrow{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;font:600 11px var(--font);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1.memo{font:600 26px/1.3 var(--display);letter-spacing:-.02em;margin:14px 0 10px;text-wrap:pretty}
p.lead{font-size:15px;line-height:1.65;color:var(--body);margin:0 0 18px} p.lead b{color:var(--ink)}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:0 0 6px} .tiles>div{padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:var(--panel-2)}
.tiles .v{font:700 24px/1.1 var(--display);color:var(--ink);font-variant-numeric:tabular-nums} .tiles .k{font-size:12px;color:var(--muted);margin-top:3px}
.delta{font:600 13px var(--font);vertical-align:middle;padding:1px 7px;border-radius:99px;background:var(--hover);color:var(--muted)} .delta.up{background:var(--good-soft);color:var(--good-ink)} .delta.down{background:var(--critical-soft);color:var(--critical)}
.fx{display:flex;gap:10px;align-items:baseline;padding:8px 0;border-top:1px solid var(--line)} .fx:first-child{border-top:0} .fx b{color:var(--good-ink)} .fx span:nth-child(2){flex:1}
.contents{font-size:12.5px;color:var(--muted);margin-top:6px}
.kind{display:inline-block;font:700 10px var(--mono);letter-spacing:.06em;padding:2px 6px;border-radius:5px;background:var(--hover);color:var(--body)} .kind.fixed{background:var(--good-soft);color:var(--good-ink)} .kind.new{background:var(--warning-soft);color:var(--warn-ink)} .kind.open{background:var(--critical-soft);color:var(--critical)}
td.good{color:var(--good-ink)} td.bad{color:var(--critical)}
body[data-mode=simple] .adv{display:none} body[data-mode=advanced] .simp{display:none}
@media (max-width:700px){.tiles{grid-template-columns:1fr 1fr}}
/* design 4b: the report reads as a printed document. Sheets of paper with square-ish corners, serif headings and lead,
   the four numbers as a ruled row (no boxes), section labels in small capitals. Inside the app (framed) the page is
   transparent so the app's backdrop drifts around the sheets. */
html.framed body{background:transparent}
section{border-radius:6px;padding:44px 64px;box-shadow:0 1px 2px rgba(0,0,0,.08),0 18px 40px -24px rgba(0,0,0,.45)}
section:first-of-type{padding-top:56px} section:first-child::after{display:none}
main{max-width:960px}
.eyebrow{font:500 11.5px var(--mono);letter-spacing:.06em}
h1.memo{font:400 40px/1.18 var(--serif);letter-spacing:-.012em;margin:26px 0 18px;color:var(--ink)}
p.lead{font:16.5px/1.75 var(--serif);margin:0 0 26px}
h2{font:400 24px/1.25 var(--serif);letter-spacing:-.01em;margin:0 0 16px} h2 small{font-family:var(--font)}
.tiles{gap:0;border-top:2px solid var(--ink);border-bottom:1px solid var(--line);padding:6px 0 4px;margin:0 0 22px}
.tiles>div{border:0;background:none;border-radius:0;padding:12px 16px 12px 0}
.tiles .v{font:400 32px/1.15 var(--serif);letter-spacing:-.01em} .tiles .k{font-size:12.5px}
.tiles .fixed .v{color:var(--good-ink)} .tiles .open .v{color:var(--crit-ink)}
.delta{font:500 13px var(--font);background:none;padding:0 0 0 4px} .delta.up,.delta.down{background:none}
.simp h4{font:600 11.5px var(--font);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:22px 0 8px}
.fx{border-top:0;padding:4px 0} .fx span:last-child{font:12px var(--mono)}
.contents{text-align:center;margin-top:34px;font-size:12.5px}
@media (max-width:700px){section{padding:28px 22px} h1.memo{font-size:30px}}
@media print{.topbar{display:none} body{background:#fff} section{break-inside:avoid;border-color:#ccc;box-shadow:none} section:first-child::after{display:none} button.print{display:none}}
@media (max-width:560px){main{padding:20px 12px 60px} section{padding:18px} .kv{grid-template-columns:1fr;gap:2px} .kv div:nth-child(odd){margin-top:8px}}
"""


def render_html(ev: dict, nonce: str | None = None) -> str:
    h, sc, ar, se = ev["header"], ev["scorecard"], ev["architecture"], ev["security"]
    rd = sc["readiness"]
    rel = _release(ev)
    commit = commit_named(h.get("commit"))
    wsp = ev["provenance"].get("workspace") if isinstance(ev["provenance"].get("workspace"), dict) else None
    commit_html = (f"<code>{E(commit[:12])}</code>" + (" <b class='warn'>with uncommitted changes</b>" if h.get("dirty") else "")
                   if commit else "several projects, each at the commit named under Architecture" if wsp
                   else "<b class='warn'>not pinned: no git commit</b>")
    note = h.get("note")    # why there is no commit, or why the files count as changed (`gitfacts`)
    if isinstance(note, str) and note and note != gitfacts.NOT_ONE:
        commit_html += f" <span class='muted'>({E(note[:300])})</span>"

    def cnt(d):
        return " · ".join(f"<span class='sev {k}'>{E(d.get(k, 0))} {k}</span>" for k in ("critical", "high", "medium", "low")) if d else "–"

    cats = "".join(f"<tr><td>{E(c['title'])}</td><td class='num'>{'n/a' if c['score'] is None else E(c['score'])}"
                   f"<span class='muted'>/{E(c['weight'])}</span></td><td><span class='bar'><i style='width:{_pct(c.get('percent'))}%'></i>"
                   f"</span></td></tr>" for c in (rd or {}).get("categories", []))
    entries = "".join(f"<li><span class='tag'>{E(e['kind'])}</span> <code>{E(route_words(e['detail']) or e['name'])}</code> "
                      f"<span class='muted'>{E(e['file'] or '')}</span></li>" for e in ar["entries"][:40])
    if len(ar["entries"]) > 40:
        entries += f"<li class='muted'>and {len(ar['entries']) - 40} more</li>"
    br = ar.get("bridge") or {}
    bridge = (f"<p>{E(br.get('matched', 0))} of {E(br.get('http_calls', 0))} frontend HTTP calls are linked to a backend "
              f"route in this repo; {E(br.get('external', 0))} go to external services.</p>" if br.get("http_calls") else "")
    ws_html = ""
    if wsp:     # several projects as one map (lantern/workspace.py): each one with the commit it was copied at
        members = [m for m in wsp.get("members") or [] if isinstance(m, dict)]
        ws_rows = "".join(
            f"<tr><td><b>{E(m.get('name'))}</b></td><td>{E(m.get('source') or '')} <span class='muted'>"
            f"({'repository link' if m.get('from') == 'link' else 'folder'})</span></td><td>"
            + (f"<code>{E(commit_named(m.get('commit'))[:12])}</code>"
               + (" <b class='warn'>with uncommitted changes</b>" if m.get("dirty") else "")
               if commit_named(m.get("commit")) else "<b class='warn'>no git commit</b>") + "</td></tr>"
            for m in members)
        ws_html = (f"<h4>Projects in this map</h4><p class='muted'>A workspace of {len(members)} projects, copied side "
                   "by side and checked as one map: a request one of them makes is linked to the route of another "
                   "that answers it.</p>"
                   f"<table>{ws_rows}</table><p class='muted'>To check the digest on another computer, check each "
                   "project out at the commit named here, make the workspace there under the same names "
                   f"(<code>lantern workspace NAME=FOLDER … --name {E(wsp.get('name'))}</code>) and run the line in "
                   "section 9.</p>")

    def glyph(f):
        # the stack strip's 4-dot glyph (design 11c): filled = the path goes there, coloured = where the problem lives
        hot = f.get("hot_lane") if f.get("hot_lane") in LANE_WORDS else None
        lit = {l for l in (f.get("lanes") or []) if isinstance(l, str) and l in LANE_WORDS}
        if not hot and not lit:
            return ""
        words = " → ".join(LANE_WORDS[l] for l in LANES if l in lit)
        dots = "".join(f"<i class='{'hot ' + E(f.get('rank') or '') if l == hot else 'lit' if l in lit else ''}'></i>" for l in LANES)
        return (f"<span class='glyph' title='{E(words)}'>{dots}</span>"
                + (f"<span class='onlane'>On the <b>{E(LANE_WORDS[hot])}</b></span>" if hot else ""))

    def frow(f, extra=""):
        path = " → ".join(E(p.split("::")[-1].split(".")[-1]) for p in (f.get("path") or [])[:8])
        heur = " <span class='tag'>heuristic</span>" if f.get("tool_confidence") == "LOW" else ""
        return (f"<tr><td><span class='sev {E(f['rank'])}'>{E(f['rank'])}</span></td><td><b>{E(f['title'])}</b>{heur}<br>"
                f"<span class='muted'>{glyph(f)}{E(f.get('tool') or '')} {E(f['rule'])} · {E(f['file'] or '')}:{E(f.get('line') or '')}"
                f"</span>{'<br><span class=path>' + path + '</span>' if path else ''}{extra}</td></tr>")

    open_rows = _grouped(se["open"], frow) or "<tr><td colspan=2 class='muted'>None.</td></tr>"
    test_open = [x for x in se.get("in_tests_open") or [] if isinstance(x, dict) and x.get("rank") in RANKS]
    test_rows = _grouped(test_open, frow)
    acc_rows = "".join(frow(f, f"<div class='reason'>{E(accepted_words(f['accepted']))}</div>") for f in se["accepted"])
    changed_rows = "".join(f"<tr><td><span class='sev {E(f['rank'])}'>{E(f['rank'])}</span></td><td><b>{E(f['title'])}</b> "
                           f"<span class='tag'>changed · still open</span><br><span class='muted'>{E(f['rule'])} · "
                           f"{E(f['file'] or '')}</span></td></tr>" for f in se.get("changed") or [])
    fixed_rows = "".join(f"<tr><td><span class='sev {E(f['rank'])}'>{E(f['rank'])}</span></td><td><b>{E(f['title'])}</b> "
                         f"<span class='tag ok'>fixed · verified by rescan</span><br><span class='muted'>{E(f['rule'])} · "
                         f"{E(f['file'] or '')}:{E(f.get('line') or '')}</span></td></tr>" for f in se["fixed"])
    prot = [x for x in se.get("protections") or [] if isinstance(x, dict)]
    prot_word = {"add": "add", "check": "check", "in place": "in place"}
    prot_rows = "".join(
        f"<tr><td><span class='tag{' ok' if x.get('status') == 'in place' else ''}'>{prot_word.get(x.get('status'), 'check')}"
        f"</span></td><td><b>{E(x.get('title'))}</b><br><span class='muted'>{E(x.get('why'))}</span>"
        + (f"<br><span class='muted'>Evidence: {E(' · '.join(map(str, x.get('evidence') or [])))}</span>" if x.get("evidence") else "")
        + (f"<br><span class='muted'>Found: {E(' · '.join(map(str, x.get('found') or [])))}</span>"
           if x.get("status") == "in place" and isinstance(x.get("found"), list) and x.get("found") else "")
        + (f"<div class='reason'>{E(x.get('how'))}</div>" if x.get("status") != "in place" else "") + "</td></tr>" for x in prot)
    tools = "".join(f"<tr><td>{E(t['tool'] or '')}</td><td>{E(t.get('version') or '–')}</td><td class='muted'>"
                    f"{E(t.get('role') or '')}"
                    f"{(' · <b class=warn>' + E(t.get('state')) + '</b>') if t.get('state') not in (None, 'ok', 'skipped') else ''}"
                    f"{(' · ' + E(t['status'])) if t.get('status') and t['status'] != 'ok' else ''}"
                    f"</td></tr>" for t in ev["provenance"]["tools"])
    inc = [x for x in se.get("incomplete") or [] if isinstance(x, dict) and x.get("tool")]
    inc_html = ""
    if inc:
        def sentence(x):
            st = scanresult.state_of(x)
            who = E(x["tool"]) + (f" ({E(x['role'])})" if x.get("role") else "")
            reason = E(_reason(x))
            if st in scanresult.BROKEN:
                return f"{who} did not finish: {('timed out ' + reason).strip() if st == 'timeout' else reason}."
            if st == "partial":
                return f"{who} covered only part of the project: {reason}."
            if st == "unavailable":
                return f"{who} did not run: not installed ({reason})."
            return f"{who} was skipped: {reason}."
        inc_html = ("<div class='incomplete'><b>Scan incomplete.</b> " + " ".join(sentence(x) for x in inc)
                    + " Anything those scanners would have found is missing from this report; the numbers above are "
                    "not a clean result.</div>")
    models = "".join(f"<tr><td>{E(m['model'] or '')}</td><td>{E(m['task'])}</td><td class='muted'>{E(m.get('validated'))} "
                     f"validated, {E(m.get('failed'))} rejected · prompt {E(m.get('prompt_version') or '-')}</td></tr>"
                     for m in ev["provenance"]["models"]) or "<tr><td colspan=3 class='muted'>No model was used.</td></tr>"
    libs = libraries_clean(ev["provenance"].get("libraries"))       # the page may be made from a file read back
    libs_html = ""
    if libs and libs["state"] == "fetched" and libs["packages"]:
        count, exact = len(libs["packages"]), sum(1 for p in libs["packages"] if p["exact"])
        rows = "".join(f"<tr><td>{E(p['name'])}</td><td>{E(p['version'])}"
                       f"{'' if p['exact'] else ' <span class=muted>(not fixed by the project)</span>'}</td>"
                       f"<td class='muted'><code>{E(p['fingerprint'])}</code>"
                       f"{' · named by the project' if p['checked'] and 'built_from' not in p else ''}"
                       + (f" · built for this run from its source, <code>{E(p['built_from'])}</code>"
                          f"{' (the fingerprint the project names)' if p['checked'] else ''}" if "built_from" in p else "")
                       + "</td></tr>" for p in libs["packages"])
        libs_html = (f"<h4>Libraries the tests ran on</h4><p class='muted'>Fetched for this run"
                     f"{' from ' + E(libs['store']) if libs['store'] else ''} into a folder that was deleted after, "
                     f"and no others: {count} librar{'y' if count == 1 else 'ies'}, {exact} at a version the project "
                     f"fixes, {libs['checked']} with a fingerprint the project names itself. Each fingerprint is of "
                     "the file that was fetched."
                     + (f" {libs['built']} of them {'was' if libs['built'] == 1 else 'were'} built from "
                        f"{'its' if libs['built'] == 1 else 'their'} source for this run: the first fingerprint there "
                        "is of the package the build made, the second of the source the store handed out."
                        if libs.get("built") else "")
                     + (f" {libs['left_out']} more could not be shown." if libs["left_out"] else "")
                     + f"</p><table>{rows}</table>")
    elif libs and libs["state"] == "installed":
        libs_html = ("<h4>Libraries the tests ran on</h4><p class='muted'>The check was offline: the tests ran on the "
                     "libraries installed on this computer, and nothing was fetched for them.</p>")
    engine = h.get("engine") if isinstance(h.get("engine"), str) and re.fullmatch(r"[0-9a-f]{40}|v[\w.-]+", h["engine"]) else ""
    verify = (f"git checkout {commit[:12]} && {install_words(engine)} && lantern verify . --report evidence.html"
              if commit else NO_COMMIT_LINE)
    if wsp and not commit and isinstance(wsp.get("name"), str) and workspace.NAME.fullmatch(wsp["name"]):
        verify = workspace.VERIFY_LINE.format(name=wsp["name"])
    words = _words_of(ev)
    words_html = ("<p class='muted'>This report was made with a test run, which runs the project's code. Lantern does "
                  "not write that command into the line above. This is the command as the report names it, word by "
                  "word; if it is the project's own test command, type it yourself after the line, behind "
                  f"<code> -- </code>:</p><p><code>{E(words)}</code></p>") if words and commit else ""
    memo = _memo(ev)
    verify_js = json.dumps(verify).replace("<", "\\u003c")   # the verify command inside the page's script
    base_rd = sc.get("baseline_readiness") if isinstance(sc.get("baseline_readiness"), dict) else {}
    base_cats = base_rd.get("categories") if isinstance(base_rd.get("categories"), dict) else {}
    same_day = sc.get("baseline_date") == dt.date.today().isoformat()
    d_html = (f"<span class='delta {'up' if memo['delta'] > 0 else 'down'}'>{'↑' if memo['delta'] > 0 else '↓'} {abs(memo['delta'])}</span>"
              if memo.get("delta") else "")
    tiles = (f"<div class='tiles'>"
             f"<div><div class='v'>{E(rd['score']) if rd else '–'} {d_html}</div><div class='k'>Readiness, grade {E(rd['grade']) if rd else '–'}{' · release ' + E(rel['decision']) if rel else ''}</div></div>"
             f"<div class='{'fixed' if se['fixed'] else ''}'><div class='v'>{len(se['fixed'])}</div><div class='k'>Fixed since baseline</div></div>"
             f"<div class='{'open' if memo['crit'] or memo['high'] else ''}'><div class='v'>{memo['open']}</div><div class='k'>Open · {memo['crit']} critical, {memo['high']} high</div></div>"
             f"<div><div class='v'>{len(se['accepted'])}</div><div class='k'>Accepted with a reason</div></div></div>")
    fixed_list = "".join(f"<div class='fx'><b>✓</b><span>{E(f['title'])} · <code>{E(f['file'] or '')}</code></span>"
                         f"<span class='muted'>{E(f['rank'])} · {E(f['id'][:6])}</span></div>" for f in se["fixed"]) \
        or "<p class='muted'>Nothing yet. Findings fixed after the baseline will be listed here, verified by rescan.</p>"
    # Advanced: scorecard with the baseline column and the findings diff
    def cat_row(c):
        b = base_cats.get(c["title"])
        now = "n/a" if c["score"] is None else f"{E(c['score'])}/{E(c['weight'])}"
        before = "–" if b is None or same_day else f"{E(b)}/{E(c['weight'])}"
        try:
            dl = "" if b is None or c["score"] is None or same_day else (f"+{round(c['score'] - b, 1)}" if c["score"] > b else f"{round(c['score'] - b, 1)}" if c["score"] < b else "0")
        except TypeError:
            dl = ""
        return (f"<tr><td>{E(c['title'])}</td><td class='num'>{before}</td><td class='num'>{now}</td>"
                f"<td class='num {'good' if dl.startswith('+') else 'bad' if dl.startswith('-') else ''}'>{dl}</td>"
                f"<td><span class='bar'><i style='width:{_pct(c.get('percent'))}%'></i></span></td></tr>")
    cats_adv = "".join(cat_row(c) for c in (rd or {}).get("categories", []))
    def drow(kind, f, extra=""):
        return (f"<tr><td><span class='kind {kind.lower()}'>{kind}</span></td><td>{E(f['title'])}"
                f"{(' · <code>' + E(f['file']) + (':' + E(f['line']) if f.get('line') else '') + '</code>') if f.get('file') else ''}{extra}</td>"
                f"<td><span class='sev {E(f['rank'])}'>{E(f['rank'])}</span></td></tr>")
    diff_rows = ("".join(drow("FIXED", f) for f in se["fixed"])
                 + "".join(drow("NEW", f) for f in sc.get("new") or [] if not same_day)
                 + "".join(drow("OPEN", f) for f in se["open"] if f["rank"] in ("critical", "high"))
                 + "".join(drow("ACCEPT", f, f" <span class='muted'>· “{E(f['accepted'].get('reason') or '')}” · {E(accepted_by(f['accepted']))}</span>") for f in se["accepted"]))
    rest_open = [f for f in se["open"] if f["rank"] not in ("critical", "high")]
    diff_more = (f"<p class='muted'>+{len(rest_open)} open ({sum(1 for f in rest_open if f['rank'] == 'medium')} medium, "
                 f"{sum(1 for f in rest_open if f['rank'] == 'low')} low) in section 3.</p>" if rest_open else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidence Report · {E(h['name'])}</title>
<style>
{STYLE}</style></head><body data-mode="simple"><main>
<div class="topbar"><span class="muted" style="font-weight:600;color:var(--ink)">{E(h['name'])} / Evidence Report</span><span class="sp"></span>
<div class="seg" id="mode"><button data-m="simple" class="on">Simple</button><button data-m="advanced">Advanced</button></div>
<span class="dg" title="{E(ev['digest'])}">digest {E(ev['digest'][:14])}…{E(ev['digest'][-4:])}</span>
<button class="btn" id="copyverify">Copy verify command</button><button class="btn" id="savepdf">Save as PDF</button><a class="btn" id="guidelink" href="https://lantern-cloud.fly.dev/guide" rel="noopener" title="How to use Lantern: short animated demos">How to use Lantern</a></div>
<section><div class="eyebrow"><span>Evidence Report · Lantern {E(__version__)}</span><span>{E(h['name'])}{(' · commit ' + E(commit[:7])) if commit else ''} · {E(h['generated_at'][:10])}</span></div>
<h1 class="memo">{memo['title']}</h1>
<p class="lead">{memo['lead']}</p>
{tiles}{inc_html}
<div class="simp"><h4>1 · Fixed since the baseline</h4>{fixed_list}
<h4>2 · Still open</h4><p>{memo['still']}</p>
<div class="contents">Continues: 3 · Scorecard · 4 · Architecture · 5 · Security · 6 · Understanding · 7 · Provenance · 8 · Limits · 9 · Digest</div></div>
<div class="adv"><h4>Readiness scorecard <small class="muted" style="font-weight:400">· 10 categories · weighted · every point has a reason</small></h4>
{f"<table><tr><td class='muted'>Category</td><td class='num muted'>{E(sc['baseline_date'] or 'Baseline')}</td><td class='num muted'>Now</td><td class='num muted'>Δ</td><td></td></tr>{cats_adv}</table>" if rd else '<p class="muted">Readiness was not computed.</p>'}
<h4>Findings · baseline → now <small class="muted" style="font-weight:400">· {len(se['fixed'])} fixed · {memo['open']} open · {len(se['accepted'])} accepted</small></h4>
<table>{diff_rows or "<tr><td colspan=3 class='muted'>No findings.</td></tr>"}</table>{diff_more}</div>
</section>
<section class="adv"><h2>About this report</h2><div class="muted">{E(h['name'])} · made with Lantern {E(__version__)}</div>
<div class="kv" style="margin-top:12px"><div>Repository</div><div>{E(h['repo'] or '')}</div>
<div>Commit</div><div>{commit_html}{(' on ' + E(h['branch'])) if h.get('branch') else ''}</div>
<div>Analyzed</div><div>{E(h['generated_at'])}</div><div>Mode</div><div>local (the code never left this machine{', except to the model provider listed below' if ev['provenance']['models'] else ''})</div>
<div>Privacy level</div><div>{E(h['privacy'])}</div></div></section>

<section><h2>3 · Scorecard</h2>
{_release_html(ev)}
{f'''<div class="score"><span class="big">{E(rd["score"])}<span style="font-size:20px" class="muted">/100</span></span><span class="grade {rd["grade"] if rd.get("grade") in ("A", "B", "C", "D", "F") else ""}">{E(rd["grade"])}</span>
<div class="muted">Deployment readiness for a {E(rd["shape"])}.<br>Most points come from files and patterns found in the code (a test folder, a lock file, a handler), not from running anything: a full mark says the thing is there, not that it works. Only the tests and a behaviour plan, where they ran, are run.<br>Checks that don't apply are skipped, not counted.<br>Low findings don't lower the score; critical, high and medium ones do.{"<br>A required check that was skipped (tests not run, libraries not looked up) earns no points. The score reads 100 only when the release decision is Passed and is held at 59 while it is Blocked" + (f" (the checklist alone gives {E(rd.get('checklist'))})." if isinstance(rd.get("checklist"), (int, float)) and rd.get("checklist") != rd.get("score") else ".") if rel else ""}</div></div>
<table style="margin-top:12px">{cats}</table>''' if rd else '<p class="muted">Readiness was not computed.</p>'}
<div class="kv" style="margin-top:14px"><div>Open findings now</div><div>{cnt(sc['now'])}</div>
<div>At first analysis</div><div>{cnt(sc['before'])}{(' <span class="muted">(' + E(sc['baseline_date'] or '') + ')</span>') if sc.get('before') else ''}</div></div></section>

<section><h2>4 · Architecture</h2>
<p>{E(ar['files'])} files, {E(ar['lines'])} lines{(' · ' + E(', '.join(ar['frameworks']))) if ar['frameworks'] else ''}.
{E(len(ar['entries']))} entry points: the places a user, a request, or a command can start running code.</p>
<ul>{entries}</ul>{bridge}{ws_html}
{f'<h4>Recommended deployment</h4><div class="diagram">{_deploy_svg(ar["shape"])}</div><ul>' + ''.join(f'<li>{E(a)}</li>' for a in ar['advice']) + '</ul>' if ar['advice'] else ''}
</section>

<section><h2>5 · Security <small>· ranked by severity and by whether a user can reach the code</small></h2>
<h4>Open ({len(se['open'])})</h4><table>{open_rows}</table>
{f"<h4>Fixed since first analysis ({len(se['fixed'])})</h4><table>{fixed_rows}</table>" if se['fixed'] else ''}
{f"<h4>Changed but still open ({len(se.get('changed') or [])})</h4><p class='muted'>The flagged line changed, and the same rule now flags new code in the same file, so these are not counted as fixed.</p><table>{changed_rows}</table>" if se.get('changed') else ''}
{f"<h4>Accepted risks ({len(se['accepted'])})</h4><table>{acc_rows}</table>" if se['accepted'] else ''}
{f"<h4>Protections to add ({sum(1 for x in prot if x.get('status') != 'in place')})</h4><p class='muted'>Heuristic: shown only where the code gives a reason; they don't change findings or the score.</p><table>{prot_rows}</table>" if prot else ''}
{(f"<details><summary class='muted'>{E(se['in_tests'])} more finding(s) are in test code only: they do not block a release. Open to see each.</summary><table>{test_rows}</table>" + (f"<p class='muted'>The first {len(test_open)} are listed.</p>" if isinstance(se['in_tests'], int) and se['in_tests'] > len(test_open) else '') + "</details>") if se['in_tests'] and test_rows else (f"<p class='muted'>{E(se['in_tests'])} more finding(s) are in test code only.</p>" if se['in_tests'] else '')}
</section>

<section><h2>6 · Understanding</h2>
{(f"<p class='muted'>These words are the project's own, from <code>{NARRATIVES_FILE}</code>. Lantern shows them as written and did not check them against the code.</p>" + _narratives_html(ev['understanding'])) if ev['understanding'] else f'<p class="muted">No path narratives attached. Write how your key flows work in <code>{NARRATIVES_FILE}</code> at the repository root and regenerate.</p>'}
</section>

<section><h2>7 · Provenance</h2><table>{tools}</table>
<h4>Models</h4><table>{models}</table>
{libs_html}
<h4>Rule sets</h4><ul>{''.join(f'<li>{E(r)}</li>' for r in ev['provenance']['rules'])}</ul>
<p class="muted">Facts (call edges, findings, scores) come from the tools above. Models only explain; they never create or close a finding.</p></section>

<section><h2>8 · Limits <small>· what this report does not prove</small></h2><ul>{''.join(f'<li>{E(x)}</li>' for x in ev['limits'])}</ul></section>

<section><h2>9 · Verify it yourself</h2>
<p>Results digest: <span class="digest">{E(ev['digest'])}</span></p>
<p class="muted">This is a SHA-256 hash of the deterministic results above (graph, findings, readiness checks, tool versions) and the commit. Re-running the open-source analyzer on the same commit with the same tool versions gives the same digest. It shows the results match the code; it is not a signature of who made the report.</p>
<p><code>{E(verify)}</code></p>{words_html}
<p style="margin-top:14px"><b>Badge.</b> <code>badge.svg</code> beside this report reads <span class="digest">Lantern · {E(badge_text(ev))}</span>: the commit, the open critical count, and the date. It never says "verified" or "secure", because no tool can promise that. Link it to this report so a reader lands on the Limits section: <code>[![Lantern](.lantern/badge.svg)](.lantern/evidence.html)</code></p></section>
</main><script{(' nonce="' + E(nonce) + '"') if nonce else ''}>
(function () {{
  var body = document.body, seg = document.getElementById('mode');
  try {{ if (localStorage.getItem('lantern.simple') === '0') body.dataset.mode = 'advanced'; }} catch (e) {{}}
  function draw() {{ var bs = seg.querySelectorAll('button'); for (var i = 0; i < bs.length; i++) bs[i].classList.toggle('on', bs[i].dataset.m === body.dataset.mode); }}
  seg.onclick = function (e) {{ var b = e.target.closest('button'); if (!b) return; body.dataset.mode = b.dataset.m; try {{ localStorage.setItem('lantern.simple', b.dataset.m === 'simple' ? '1' : '0'); }} catch (x) {{}} draw(); }};
  window.setSimple = function (v) {{ body.dataset.mode = v ? 'simple' : 'advanced'; draw(); }};
  draw();
  var cv = document.getElementById('copyverify'), cmd = {verify_js};
  cv.onclick = function () {{ if (navigator.clipboard) navigator.clipboard.writeText(cmd); cv.textContent = 'Copied'; }};
  document.getElementById('savepdf').onclick = function () {{ window.print(); }};   // no inline handler: the page's script policy refuses them
  try {{ if (window.self !== window.top) {{ document.querySelector('.topbar .seg').style.display = 'none'; document.documentElement.classList.add('framed'); }} }} catch (e) {{}}
  // How to use Lantern: the app or website around a framed page has the button; on its own, this site's /guide when
  // Lantern serves the page (/p/, /r/, /s/), else the website's guide (a plain link: nothing is fetched until clicked).
  var gl = document.getElementById('guidelink'), framed = true;
  try {{ framed = window.self !== window.top; }} catch (e) {{}}
  if (framed) gl.hidden = true;
  else if (/^https?:$/.test(location.protocol) && /^\\/(p|r|s)\\//.test(location.pathname)) gl.setAttribute('href', '/guide');
}})();
</script></body></html>"""


def write(out_dir: Path, ev: dict) -> dict[str, Path]:
    paths = {"html": out_dir / "evidence.html", "json": out_dir / "evidence.json"}
    results.write(paths["html"], render_html(ev))
    results.write(paths["json"], json.dumps(ev, indent=1))
    rd = ev["scorecard"]["readiness"]
    if rd:
        paths["badge"] = out_dir / "badge.svg"
        results.write(paths["badge"], badge_svg(rd["score"], rd["grade"], ev))
    return paths
