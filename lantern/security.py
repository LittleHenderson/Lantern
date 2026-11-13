"""Security stage: deterministic scanners find issues; the call graph ranks them by reachability.

Models never create or close findings. They only explain them later (see explain.py).
"""

from __future__ import annotations

import contextvars
import glob
import hashlib
import io
import json
import os
import re
import subprocess
import threading
import time
import tokenize
from collections import deque
from pathlib import Path

from . import context, flowscan, kept, lanes, listing, manifest, programs, quick, results, unread
from .calls import NAME_ONLY_VIA
from .graph import Graph
from .python_frontend import ENV_NAMES, SKIP_DIRS, inside_repo, project_bytes, project_text, skipped_dir
from .strings import sub as strings_sub

UNTRUSTED_ENTRY_KINDS = {"route", "cli", "main", "script"}

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b")),
]
SECRET_EXTS = {".py", ".env", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".txt", ".sh",
               ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html",
               ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".php", ".tf", ".properties", ".xml"}
SECRET_SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock", "uv.lock"}


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).hexdigest()[:12]


# ---------------------------------------------------------------------------- scanners
#
# Every scanner answers with `(findings, record)`, the record made by `scanresult.record` so a run that did not finish
# can never read as a clean result (directive stage 2). The findings a tool did produce are kept even when the rest of
# its run failed; the record's `state`, `why` and `errors` say what is missing.

BANDIT_TIMEOUT = 600
GITLEAKS_TIMEOUT = 300
SECRETS_VERSION = "2"      # the built-in pattern set (SECRET_PATTERNS); bump when a pattern changes


def _rel(repo: Path, name: str) -> str:
    """A path a scanner printed, relative to the repo (a tool prints absolute paths, `./x`, or repo-relative ones)."""
    p = Path(str(name))
    if p.is_absolute():
        try:
            return p.resolve().relative_to(repo.resolve()).as_posix()
        except (ValueError, OSError):
            return p.as_posix()
    s = p.as_posix()
    return s[2:] if s.startswith("./") else s


def _read_text(p: Path, repo: Path) -> str:
    return project_text(p, repo)


BANDIT_READS = (".py", ".pyw")
EXCLUSIONS_FIT = 24_000   # characters: Windows starts no program whose whole command line is longer than 32,767


def _python_named(repo: Path, skipped: list[str]) -> list[tuple[str, str, bool]]:
    """Every file under the project with a name Bandit reads, in one walk (the folders of `skipped`, at the top, are
    the ones Bandit is told to leave out): (its name in the project, its path as Bandit will write it, whether it
    is a file of the project, `inside_repo`)."""
    out = []
    top = os.fspath(repo)
    for dirpath, dirnames, filenames in os.walk(top):
        if dirpath == top:
            dirnames[:] = [d for d in dirnames if d not in skipped]
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.lower().endswith(BANDIT_READS):
                path = os.path.join(dirpath, fn)
                out.append((_under(repo, path), path, inside_repo(Path(path), repo)))
    return out


def _not_the_projects(repo: Path, skipped: list[str], named: list | None = None) -> list[tuple[str, str]]:
    """The Python files under the project that are not files of the project (`inside_repo`: a link that leads out of
    it, a pipe, a link to nothing), each as (its name in the project, its path as Bandit will write it). Bandit finds
    its files itself and opens whatever answers to a `.py` name; Lantern's own reader passed these by already."""
    named = _python_named(repo, skipped) if named is None else named
    return [(name, path) for name, path, own in named if not own]


# What Bandit said about a set of files is kept between runs (`lantern/kept.py`) and used again only when the
# question is the same in every part: the folder (Bandit writes full paths), what it was told to leave out, each
# Python file it may read by name and content, Bandit itself and every plug-in installed for it, and Lantern's own
# code. One file changed, added, removed or renamed: Bandit runs. Only a run that ended as a scan does (0 or 1, with
# a list of results) is kept; `lantern verify` never asks (`kept.without`).
_KEPT_BANDIT = kept.Shelf("bandit", libraries=("bandit",))
BANDIT_GROUPS = ("bandit.plugins", "bandit.blacklists", "bandit.formatters")


def _bandit_question(repo: Path, excl: list[str], named: list[tuple[str, str, bool]]) -> str | None:
    """The key of what Bandit will be asked, or None when nothing may be kept (kept work is off, a file Bandit may
    read cannot be read here, the installed plug-ins cannot be listed)."""
    if not kept.on():
        return None
    try:
        from importlib import metadata
        plugins = sorted((group, ep.name, ep.value, getattr(getattr(ep, "dist", None), "version", "") or "")
                         for group in BANDIT_GROUPS for ep in metadata.entry_points(group=group))
        files = hashlib.sha256()
        for name, path, own in named:
            files.update(name.encode("utf-8", "surrogatepass") + b"\0")
            files.update(hashlib.sha256(project_bytes(Path(path), repo)).digest() if own else b"left out")
    except Exception:   # noqa: BLE001  (whatever went wrong: the scanner is simply run)
        return None
    return _KEPT_BANDIT.key("1", os.fspath(repo), json.dumps(excl), json.dumps(plugins), files.digest())


def _bandit_kept(key: str | None):
    """(what a run of Bandit gave, its version) as it was kept for this very question, or None."""
    from . import scanresult
    was = _KEPT_BANDIT.get(key)
    if (type(was) is dict and was.get("returncode") in (0, 1) and type(was.get("stdout")) is str
            and type(was.get("stderr")) is str and (was.get("version") is None or type(was["version"]) is str)):
        return scanresult.ToolRun(was["returncode"], was["stdout"], was["stderr"]), was["version"]
    return None


HANDED_FIT = 6_000        # characters: the files handed to Bandit by name, beside its exclusions (`EXCLUSIONS_FIT`)


def _handed(repo: Path, rels: list[str]) -> list[tuple[str, str]]:
    """The files Bandit is handed by name, as (name in the project, path as Bandit will write it): as many as fit a
    command line. A name that begins with `-` would be read as a setting and is passed over, and so is one with a
    comma in it (an exclusion is written with commas)."""
    out, room = [], HANDED_FIT
    for rel in rels:
        path = os.path.join(os.fspath(repo), *rel.split("/"))
        if rel.startswith("-") or "," in path or len(path) + 1 > room:
            continue
        room -= len(path) + 1
        out.append((rel, path))
    return out


def _under(repo: Path, name) -> str:
    """Where a path lies under the project, by the text of the two paths (nothing is followed): `pkg/tool.py`."""
    try:
        return Path(os.path.relpath(os.path.abspath(str(name)), os.path.abspath(repo))).as_posix()
    except ValueError:   # Windows: on another drive
        return ""


def _only(paths) -> list[str]:
    """One Bandit exclusion for each path, as many as fit a command line, the ones that are no file at all first (a
    pipe is what Bandit would wait on). Bandit leaves a file out when an exclusion fits its path as a pattern or is
    found anywhere in it, so the plain path of `a.py` would take `a.pyw` and `a.py.old.py` with it: with its last
    letter in brackets it is a pattern for that one file and is found in no other path. A path with a comma in it
    cannot be written (`-x a,b` is two exclusions to Bandit) and is passed over here; `run_bandit` takes nothing
    from a file that is not the project's whether Bandit opened it or not."""
    out, room = [], EXCLUSIONS_FIT
    for path in sorted(paths, key=os.path.isfile):
        if "," in path:
            continue
        esc = glob.escape(path)
        one = esc[:-1] + "[" + esc[-1] + "]"
        room -= len(one) + 1
        if room < 0:
            break
        out.append(one)
    return out


def run_bandit(repo: Path, applicable: bool = True) -> tuple[list[dict], dict]:
    """Bandit over the repo's Python. Exit 0 = ran, nothing found; exit 1 = ran, found something (no --exit-zero, so a
    crash cannot hide behind a zero); anything else is a failure. Files Bandit could not read make the run `partial`
    and are listed. `applicable` is False when the project has no Python, so a missing Bandit is not a gap."""
    import importlib.util
    from . import scanresult
    excl = sorted(d for d in sorted(SKIP_DIRS) + sorted(ENV_NAMES) if (repo / d).exists() and skipped_dir(repo, d))
    named = _python_named(repo, excl)
    left = _not_the_projects(repo, excl, named)
    # Python kept as text (`engine.py.txt`, 2026-11-12): Bandit finds its files by their ending and passes these by,
    # and it reads any file it is handed by name. Until this date no scanner opened them and the record said `ok`.
    also = _handed(repo, unread.python_as_text(repo))
    named = named + [(rel, path, True) for rel, path in also]        # part of the question kept work is asked by
    applicable = applicable or bool(also)
    base: dict = {"role": "Python code patterns", "exclusions": excl + sorted(name for name, _ in left)}
    if importlib.util.find_spec("bandit") is None:
        return [], scanresult.record("bandit", "unavailable", 'pip install "lantern[scan]"', applicable=applicable,
                                     version=None, **base)
    # Two things a project must not choose (until 2026-11-10 it could). Which Python files the scanner loads:
    # `python -m` looks in the current folder first, and Lantern is often started inside the project
    # (`programs.python`). And what the scanner checks: Bandit takes settings from a `.bandit` file anywhere in the
    # folder it scans (checks to skip, files to leave out, a file to write its report to), and with checks switched
    # off that way the record below still said `ok`. Handed a settings file of Lantern's own, with nothing in it,
    # Bandit looks for no other.
    began = time.perf_counter()
    question = _bandit_question(repo, excl, named)
    asked = _bandit_kept(question)
    if asked is not None:       # the same files, the same Bandit, the same question: what it said then
        run, version = asked
        run.duration_ms = int((time.perf_counter() - began) * 1000)
    else:
        try:
            with programs.settings("bandit.ini", "[bandit]\n") as ini:
                # --ignore-nosec: a `# nosec` comment in the project switches a check off for its line, and comes with
                # the project like the code. Bandit lists the line all the same, and Lantern reads the comment itself
                # (`nosec_says`): until 2026-11-11 such a line was listed nowhere.
                cmd = programs.python("bandit", "-r", str(repo), *[path for _, path in also],
                                      "--ini", str(ini), "-f", "json", "-q", "--ignore-nosec")
                if excl or left:
                    cmd += ["-x", ",".join([str(repo / d) for d in excl] + _only(path for _, path in left))]
                run = scanresult.run_tool(cmd, timeout=BANDIT_TIMEOUT)
        except OSError as exc:  # without its own settings file Bandit would look for the project's: it is not started
            return [], scanresult.record("bandit", "failed", "Lantern's settings file for the scanner could not be "
                                         f"written ({exc.strerror or type(exc).__name__})", version=None, **base)
        version = _tool_version(programs.python("bandit", "--version"))
    base |= {"version": version, "exit_code": run.returncode, "duration_ms": run.duration_ms}
    if run.timed_out:
        return [], scanresult.record("bandit", "timeout", f"after {BANDIT_TIMEOUT} s", **base)
    if run.error:
        return [], scanresult.record("bandit", "failed", run.error, **base)
    err = scanresult.tail(run.stderr)
    if run.returncode not in (0, 1):
        return [], scanresult.record("bandit", "failed", f"exit code {run.returncode}: {err or 'no message'}", **base)
    data, why = scanresult.parse_json(run.stdout, dict)
    if data is None:
        return [], scanresult.record("bandit", "failed", why + (f"; stderr: {err}" if err else ""), **base)
    if not isinstance(data.get("results"), list):
        return [], scanresult.record("bandit", "failed", "no results list in the output", **base)
    if asked is None:           # a scan that ended as a scan does: kept for the next time the question is the same
        _KEPT_BANDIT.put(question, {"returncode": run.returncode, "stdout": run.stdout, "stderr": run.stderr,
                                    "version": version})
    out = []
    gone = {name for name, _ in left}

    def ours(name) -> bool:   # whatever the exclusions above did: nothing is taken from a file that is not the project's
        return _under(repo, name) not in gone

    comments: dict[str, dict[int, str]] = {}
    for r in data["results"]:
        if not isinstance(r, dict) or not r.get("test_id") or not r.get("filename") or not ours(r["filename"]):
            continue
        rel = _rel(repo, r["filename"])
        out.append({
            "id": _fid("bandit", r["test_id"], rel, r.get("line_number")),
            "tool": "bandit", "rule": r["test_id"], "title": r.get("issue_text") or r["test_id"],
            "tool_severity": r.get("issue_severity") or "MEDIUM", "tool_confidence": r.get("issue_confidence") or "MEDIUM",
            "file": rel, "line": r.get("line_number"),
            "cwe": (r.get("issue_cwe") or {}).get("id") if isinstance(r.get("issue_cwe"), dict) else None,
            "more_info": r.get("more_info"),
            "snippet": str(r.get("code") or "").strip()[:400], "category": "code",
        })
        said = _nosec_on(repo, rel, r, comments)
        if said:
            out[-1]["nosec"] = said
    metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
    files = sum(1 for k in metrics if k != "_totals" and ours(k))
    errors = [f"{_rel(repo, e.get('filename') or '?')}: {str(e.get('reason') or 'could not be read')[:160]}"
              for e in (data.get("errors") or []) if isinstance(e, dict) and (not e.get("filename") or ours(e["filename"]))]
    base |= {"scope": {"files": files} | ({"under_another_name": len(also)} if also else {}), "findings": len(out)}
    if also:
        base["read_as_text"] = [rel for rel, _ in also]
    if errors:
        return out, scanresult.record("bandit", "partial", f"{len(errors)} file{'s' if len(errors) != 1 else ''} could "
                                      "not be read", errors=errors, **base)
    return out, scanresult.record("bandit", "ok", **base)


# `# nosec`, the form Bandit itself reads: the word, then the checks the comment is about (ids like B602, or their
# names), then whatever else the person wrote. With no check named it is about every check on the line.
NOSEC = re.compile(r"#\s*nosec\b(?P<rest>[^#]*)", re.I)
NOSEC_WORD = re.compile(r"[\s,:]*([A-Za-z_]\w*)")
NOSEC_ID = re.compile(r"B\d{3}$", re.I)
NOSEC_NAME = re.compile(r"[a-z][a-z\d]*(_[a-z\d]+)+$")           # how Bandit names its checks: words joined by _
NOSEC_ONE_WORD = frozenset({"exec", "hashlib", "blacklist"})    # ... and the few names that are one word
NOSEC_REASON = 300


def nosec_says(comment: str, rule: str, name: str | None = None) -> dict | None:
    """What a `# nosec` comment says about one finding of Bandit's. None when it is no such comment, or names other
    checks only (Bandit lists the line then, and the comment is not about this finding). Else `{"reason": text}`,
    with None for the text when nothing that reads as a reason was written (`reason_ok`, the rule `lantern accept`
    has for its reasons). The text is the project's own: bounded, on one line, printable."""
    m = NOSEC.search(comment)
    if not m:
        return None
    rest, pos, named = m.group("rest"), 0, []
    while True:
        t = NOSEC_WORD.match(rest, pos)
        if not t:
            break
        w = t.group(1)
        if not (NOSEC_ID.match(w) or NOSEC_NAME.match(w) or w.lower() in NOSEC_ONE_WORD
                or (name and w.lower() == name.lower())):
            break
        named.append(w.lower())
        pos = t.end()
    if named and rule.lower() not in named and (name or "").lower() not in named:
        return None
    reason = " ".join("".join(c if c.isprintable() else " " for c in rest[pos:]).split()).strip(" :,-\u2013\u2014")
    reason = reason[:NOSEC_REASON].rstrip()
    return {"reason": reason if reason_ok(reason) else None}


def _nosec_on(repo: Path, rel: str, r: dict, cache: dict[str, dict[int, str]]) -> dict | None:
    """The `# nosec` comment on the lines of one of Bandit's results, if it is about that result. Comments are
    taken from Python's own reading of the file, so the words inside a text are none."""
    if rel not in cache:
        found: dict[int, str] = {}
        try:
            text = project_text(repo / rel, repo)
            if "nosec" in text.lower():
                for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                    if tok.type == tokenize.COMMENT and NOSEC.search(tok.string):
                        found[tok.start[0]] = tok.string
        except (OSError, tokenize.TokenError, SyntaxError, ValueError):
            pass        # what was read up to there stands; a file Python cannot read has no findings of Bandit's
        cache[rel] = found
    if not cache[rel]:
        return None
    span = r.get("line_range") if isinstance(r.get("line_range"), list) else []
    lines = sorted({n for n in [r.get("line_number"), *span] if isinstance(n, int)})
    for n in lines:
        if n in cache[rel]:
            said = nosec_says(cache[rel][n], str(r["test_id"]), r.get("test_name") if isinstance(r.get("test_name"), str) else None)
            if said:
                return said
    return None


def run_secrets(repo: Path) -> tuple[list[dict], list[dict]]:
    """Secrets in files: gitleaks when installed, Lantern's built-in patterns otherwise, and also when gitleaks did
    not finish (then both records are kept: gitleaks' failure, and the built-in run marked `fallback_for`), so the
    weaker scan never passes as the stronger one. Returns the findings and one record per tool."""
    from . import scanresult
    records = []
    fallback = None
    gitleaks = programs.find("gitleaks")
    if gitleaks:
        found, rec = _run_gitleaks(repo, gitleaks)
        records.append(rec)
        if rec["state"] == "ok":
            return found, records
        fallback = "gitleaks"
    else:
        records.append(scanresult.record(
            "gitleaks", "unavailable", "built-in patterns ran instead; install gitleaks (github.com/gitleaks/gitleaks) "
            "for its full rule set", applicable=False, role="secrets in files", version=None))
    found, rec = _builtin_secrets(repo)
    if fallback:
        rec["fallback_for"] = fallback
    records.append(rec)
    return found, records


def _run_gitleaks(repo: Path, gitleaks: str) -> tuple[list[dict], dict]:
    """`gitleaks detect --no-git` writing its JSON report to a temp file (never stdout, where a warning could break
    the JSON). `--exit-code 0` makes leaks exit 0, so a non-zero code means gitleaks itself failed; a report file that
    is present and parses is the proof it finished."""
    import os
    import tempfile
    from . import scanresult
    fd, path = tempfile.mkstemp(prefix="lantern-gitleaks-", suffix=".json")
    os.close(fd)
    report = Path(path)
    base: dict = {"role": "secrets in files"}
    try:
        cmd = [gitleaks, "detect", "--no-git", "-s", str(repo), "-f", "json", "-r", str(report), "--exit-code", "0"]
        run = scanresult.run_tool(cmd, timeout=GITLEAKS_TIMEOUT)
        base |= {"version": _tool_version([gitleaks, "version"]), "exit_code": run.returncode,
                 "duration_ms": run.duration_ms}
        if run.timed_out:
            return [], scanresult.record("gitleaks", "timeout", f"after {GITLEAKS_TIMEOUT} s", **base)
        if run.error:
            return [], scanresult.record("gitleaks", "failed", run.error, **base)
        err = scanresult.tail(run.stderr)
        if run.returncode not in (0, 1):
            return [], scanresult.record("gitleaks", "failed", f"exit code {run.returncode}: {err or 'no message'}", **base)
        try:
            text = report.read_text(encoding="utf-8", errors="replace") if report.exists() else ""
        except OSError as exc:
            return [], scanresult.record("gitleaks", "failed", f"report file could not be read ({exc.strerror or exc})", **base)
        if not text.strip():
            if run.returncode == 0:
                return [], scanresult.record("gitleaks", "ok", findings=0, **base)
            return [], scanresult.record("gitleaks", "failed", f"exit code 1 and no report written: {err or 'no message'}", **base)
        rows, why = scanresult.parse_json(text, list)
        if rows is None:
            return [], scanresult.record("gitleaks", "failed", f"report file: {why}", **base)
        out = []
        for r in rows:
            if not isinstance(r, dict) or not r.get("RuleID") or not r.get("File"):
                continue
            rel = _rel(repo, r["File"])
            out.append({
                "id": _fid("gitleaks", r["RuleID"], rel, r.get("StartLine")),
                "tool": "gitleaks", "rule": str(r["RuleID"]), "title": f"Possible secret: {r.get('Description') or r['RuleID']}",
                "tool_severity": "HIGH", "tool_confidence": "MEDIUM",
                "file": rel, "line": r.get("StartLine"),
                "snippet": "[redacted]", "category": "secret",
            })
        return out, scanresult.record("gitleaks", "ok", findings=len(out), **base)
    finally:
        try:
            report.unlink()
        except OSError:
            pass


def _builtin_secrets(repo: Path) -> tuple[list[dict], dict]:
    """Lantern's own secret patterns over the files it reads. A file it cannot read is counted and named, and makes
    the run `partial`."""
    from . import scanresult
    out, errors, files = [], [], 0
    for p, parts in listing.files(repo):    # the project's files, walked once for a whole run
        if p.suffix not in SECRET_EXTS and not p.name.startswith(".env"):
            continue
        if p.name in SECRET_SKIP_FILES or p.name.endswith((".min.js", ".map")):
            continue
        rel = "/".join(parts)
        try:
            text = _read_text(p, repo)
        except OSError as exc:
            errors.append(f"{rel}: {exc.strerror or exc}")
            continue
        files += 1
        whole = quick.Text(text)    # the patterns that can find anything in this file at all; the rest are not tried
        patterns = [row for row in SECRET_PATTERNS if whole.may_match(row[1])]
        if not patterns:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for rule, rx in patterns:
                if rx.search(line):
                    out.append({
                        "id": _fid("secrets", rule, rel, i), "tool": "lantern-secrets", "rule": rule,
                        "title": f"Possible secret ({rule})", "tool_severity": "HIGH",
                        "tool_confidence": "MEDIUM", "file": rel, "line": i,
                        "snippet": "[redacted]", "category": "secret",
                    })
    base = {"role": "secrets in files (built-in patterns)", "version": SECRETS_VERSION, "scope": {"files": files},
            "findings": len(out)}
    if errors:
        return out, scanresult.record("lantern-secrets", "partial", f"{len(errors)} file{'s' if len(errors) != 1 else ''} "
                                      "could not be read", errors=errors, **base)
    return out, scanresult.record("lantern-secrets", "ok", "built-in patterns; install gitleaks for full coverage", **base)


def _tool_version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
                             env=programs.env()).stdout
        m = re.search(r"\d+\.\d+(\.\d+)?", out)
        return m.group(0) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------------------- graph link

REQUEST_DATA = re.compile(r"\b(request|req)\.(args|form|json|body|query|params|values|files|data|cookies|headers|"
                          r"get_json|path_params|query_params|POST|GET|FILES|META)\b|\bsearchParams\b|\bformData\b|"
                          r"\bsys\.argv\b|\binput\(|\bevent\[|\bctx\.(query|params|request)\b|"
                          # Go: net/http, gin, echo, fiber, chi
                          r"\b[rc]\.(PathValue|FormValue|PostFormValue|Body|Header|Cookie|Param|Params|Query|QueryParam|"
                          r"PostForm|BindJSON|ShouldBind\w*|Bind|GetHeader|FormFile|URL\.Query)\b|\bchi\.URLParam\(|"
                          # Java: servlet / Spring
                          r"\.(getParameter|getParameterMap|getHeader|getInputStream|getReader|getCookies|getQueryString|"
                          r"getPathInfo|getRequestURI)\(|"
                          # Android: data another app or a link put into an Intent
                          r"\bget(?:String|Int|Long|Boolean|Bundle|Parcelable|Serializable|CharSequence)(?:Array)?(?:List)?Extra\(|"
                          r"\bgetQueryParameter\(|\bgetIntent\(\)\.(?:getData|getExtras|getDataString)\(|\bintent\.(?:data|extras|dataString)\b"
                          # iOS: what a link carries (ios.py)
                          r"|\.queryItems\b|\bURLComponents\s*\(\s*(?:url|string):|\buserActivity\.webpageURL\b|"
                          r"\burl\.(?:query|path|host|absoluteString|pathComponents|fragment)\b"
                          # Vapor (Swift servers)
                          r"|\breq\.(?:parameters|query|content|headers|body)\b"
                          # Flutter: what a link or a route carries
                          r"|\.(?:queryParameters|pathParameters|queryParametersAll)\b|\bgetInitial(?:Link|Uri|AppLink)\s*\("
                          # React Native / Expo: what a link or a navigation carries
                          r"|\broute\.params\b|\buse(?:Local|Global)SearchParams\s*\(|\bLinking\.parse\s*\("
                          # C#: ASP.NET request data, what a link (`Uri`) or an Android intent carries (MAUI, Xamarin)
                          r"|\bRequest\.(?:Query|Form|Headers|Cookies|RouteValues|Body|QueryString)\b"
                          r"|\b(?:uri|url|link|appLink)\.(?:Query|AbsolutePath|AbsoluteUri|Segments|Fragment|Host|OriginalString)\b"
                          r"|\bHttpUtility\.ParseQueryString\s*\(|\bIntent\.(?:Data|DataString|Extras)\b|\bIntent\.Get\w*Extra\s*\("
                          # PHP: superglobals, Laravel's request, PSR-7 (Slim) requests ($ and -> may be read as . )
                          r"|\b_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\brequest(?:->|\.)(?:input|get|query|post|all|only|"
                          r"file|cookie|header|json|route|string|integer|boolean)\s*\(|\brequest\(\s*['\"]|"
                          r"(?:->|\.)(?:getParsedBody|getQueryParams|getUploadedFiles|getCookieParams)\s*\("
                          r"|\bfile_get_contents\(\s*['\"]php://input")
# Ruby (Rails, Sinatra): `params[:q]`, `params.require(...)`, the raw request, cookies. Only for `.rb` files: a bare
# `params` in JS is usually a router's own value.
RUBY_REQUEST_DATA = re.compile(REQUEST_DATA.pattern + r"|\bparams\b(?:\[[^\]\n]*\])?(?!\s*=[^=])|\brequest\.(?:body|raw_post|headers|"
                               r"query_string|query_parameters|request_parameters|params|env|fullpath|url)\b|"
                               r"\bcookies\s*\[|\bARGV\b|\bgets\b")
# C/C++: program arguments, the environment, what arrives on a socket or stdin, and the request objects of cpp-httplib,
# Crow, Drogon and Pistache.
C_EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp")
C_REQUEST_DATA = re.compile(REQUEST_DATA.pattern + r"|\bargv\s*\[\s*\w*\s*\]|\bgetenv\s*\(|\b(?:recv|recvfrom|fgets|gets)\s*\(|"
                            r"\bgetline\s*\(\s*(?:std::)?cin\b|\bstd::cin\b|\bscanf\s*\(|\breq(?:uest)?(?:\.|->)(?:get_param_value|get_header_value|"
                            r"get_file_value|body|params|path_params|url_params|matches|getParameter|getBody|getJsonObject|"
                            r"getHeader|query|param|resource)\b|\breq->getParameter\b")
# `x = ...`, `const {a, b} = ...`, `x: T = ...`, `x += ...`, `self.x = ...`, `a, b = ...`
ASSIGN = re.compile(r"^\s*(?:(?:const|let|var|val)\s+)?(?P<lhs>[A-Za-z_$][\w$.]*(?:\s*,\s*[A-Za-z_$][\w$.]*)*|"
                    r"\[[^\]=]*\]|\{[^}=]*\})\s*(?::\s*[^=]+?)?\s*(?P<op>[-+*/%&|^]|\*\*|//|\?\?|&&|\|\|)?=(?!=)\s*(?P<rhs>.+)$",
                    re.S)
BINDS = [   # loops and context managers that bind a name to a value
    re.compile(r"^\s*(?:async\s+)?for\s+(?P<lhs>[\w., ]+?)\s+in\s+(?P<rhs>.+?):", re.S),
    re.compile(r"^\s*(?:async\s+)?with\s+(?P<rhs>.+?)\s+as\s+(?P<lhs>\w+)\s*:", re.S),
    re.compile(r"^\s*for\s*\(\s*(?:const|let|var)\s+(?P<lhs>[\w{}\[\], $]+?)\s+(?:of|in)\s+(?P<rhs>[^)]+)\)", re.S),
]
QUOTES = "'\"`"       # what opens a string in the lines the input check reads (found by lantern/strings.py)
_TEMPLATE_REF = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*)|\$([A-Za-z_]\w*)|\\\(\s*([A-Za-z_]\w*)|#\{\s*@?([A-Za-z_]\w*)")


def _blank_string(m: re.Match) -> str:
    """A string literal becomes `''`, keeping the names a template puts into it (`"id = $id"` in Kotlin, `\\(id)` in Swift,
    `${id}` in a JS template literal, `$"…{id}"` in C#) so a value spliced into SQL or a command is still seen as used."""
    refs = [a or b or c or d for a, b, c, d in _TEMPLATE_REF.findall(m.group(0))]
    head = m.string[max(0, m.start() - 2):m.start()]
    if "$" in head:   # C# `$"… {id}"`
        refs += re.findall(r"(?<!\{)\{\s*([A-Za-z_]\w*)", m.group(0))
    return "''" + "".join(f" + {r}" for r in refs)


def _php_line(raw: str) -> str:
    """A PHP line in the shape the input check reads: strings blanked (keeping `$x` and `{$x}` put into double-quoted
    ones), `.` concatenation read as `+`, `->` as `.`, and `$` dropped from variable names."""
    def blank(m: re.Match) -> str:
        if m.group(1) == "'":
            return "''"
        return "''" + "".join(f" + {r}" for r in re.findall(r"\{?\$([A-Za-z_]\w*)", m.group(0)))
    t = strings_sub("'\"", blank, raw)
    t = t.replace(".=", "+=")
    t = re.sub(r"(?<=[\w'\")\]])\s*\.(?!\.)\s*(?=[$\w'\"(])", " + ", t)
    t = t.replace("->", ".").replace("?.", ".")
    return re.sub(r"\$(?=[A-Za-z_])", "", t)


def _rb_line(raw: str) -> str:
    """A Ruby line for the input check: `@x` read as `x` (instance variables carry values between lines of a controller
    action), `%x(...)`/`%Q(...)` read as strings."""
    t = re.sub(r"%[xQqw]?\((.*?)\)", lambda m: '"' + m.group(1).replace('"', "'") + '"', raw)
    return re.sub(r"(?<![\w@])@(?=[A-Za-z_])", "", t)


_C_DECL = re.compile(r"^(\s*)(?:(?:const|static|unsigned|signed|auto|struct|volatile|register)\s+)*[A-Za-z_][\w:]*"
                     r"(?:<[^;=()]*>)?(?:\s+const)?[\s*&]+(?=[A-Za-z_]\w*\s*(?:\[[^\]]*\]\s*)?=)")
_C_FILL = re.compile(r"^(\s*)(?:std::)?(sn?printf|strn?cpy|strn?cat|memcpy|asprintf)\s*\(\s*&?([A-Za-z_]\w*)\s*,(.*)\)\s*;")


def _c_line(raw: str) -> str:
    """A C/C++ line for the input check: a declaration `std::string q = …` read as `q = …`, and a buffer filled by
    `sprintf(buf, …, x)` / `strcpy(buf, x)` read as `buf = … x` (`strcat` as `buf += x`)."""
    t = _C_DECL.sub(r"\1", raw)
    m = _C_FILL.match(t)
    if m:
        op = "+=" if "cat" in m.group(2) else "="
        t = f"{m.group(1)}{m.group(3)} {op} {m.group(4)};"
    return t


def _statements(lines: list[str], first: int, last: int, js: bool) -> list[tuple[int, int, str]]:
    """Lines first..last (1-based, inclusive) grouped into statements: a line with open brackets takes the
    following lines until they balance (at most 12). Comments and string contents are dropped. In JS a line that
    ends by opening a block (`app.post('/x', (req, res) => {`) ends its statement there, so a callback's body is
    read line by line rather than as one giant call."""
    out, buf, start, depth = [], [], 0, 0
    for ln in range(first, min(last, len(lines)) + 1):
        raw = lines[ln - 1]
        code = strings_sub(QUOTES, _blank_string, raw)
        code = re.sub(r"//.*$" if js else r"#.*$", "", code)
        if not buf:
            start = ln
        buf.append(code)
        depth += code.count("(") + code.count("[") + code.count("{") - code.count(")") - code.count("]") - code.count("}")
        if depth <= 0 or len(buf) >= 12 or (js and code.rstrip().endswith("{")):
            out.append((start, ln, " ".join(x.strip() for x in buf)))
            buf, depth = [], 0
    if buf:
        out.append((start, min(last, len(lines)), " ".join(x.strip() for x in buf)))
    return out


def _names(lhs: str) -> list[str]:
    """Names bound by an assignment target: `a`, `a, b`, `[a, b]`, `{a, b: c}`, `self.x`."""
    out = []
    for part in re.split(r"[,\s]+", lhs.strip("[]{} ")):
        part = part.strip().lstrip(".")
        if ":" in part:
            part = part.split(":", 1)[1].strip()   # {key: alias}
        if re.fullmatch(r"[A-Za-z_$][\w$.]*", part):
            out.append(part)
    return out


def _uses(name: str, text: str) -> bool:
    return re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", text) is not None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _input_on_line(g: Graph, f: dict, cache: dict[str, list[str]]) -> dict | False:
    """Does the flagged line use something a caller controls: a parameter, request data, or a local variable
    that was set from either earlier in the same function? Assignments are followed in order inside the function
    only (not across functions, branches, or loops), so it can say yes for a parameter that is in fact always a
    constant, and it says no for input that arrives through another function's return value. A plain `name = ...`
    with nothing tainted on its right clears the name again, but only at the same block level as the line that
    tainted it (or the function body for a parameter): `if not cmd: cmd = "ls"` is a default, not a reset."""
    n = g.nodes.get(f.get("node") or "")
    if not n or not f.get("line") or not n.start_line:
        return False
    if f["file"] not in cache:
        try:
            cache[f["file"]] = project_text(Path(g.repo_root) / f["file"], g.repo_root).splitlines()
        except OSError:
            cache[f["file"]] = []
    src = cache[f["file"]]
    show = (lambda x: x)
    if f["file"].endswith(".php"):
        src = [_php_line(x) for x in src]
        show = (lambda x: re.sub(r"^(request|_[A-Z]+)\b", r"$\1", x).replace(".", "->"))   # back to PHP spelling
    req_re = C_REQUEST_DATA if f["file"].endswith(C_EXTS) else REQUEST_DATA
    if f["file"].endswith(C_EXTS):
        src = [_c_line(x) for x in src]
    if f["file"].endswith(".rb"):
        src = [_rb_line(x) for x in src]
        req_re = RUBY_REQUEST_DATA
    line = f["line"]
    if not 0 < line <= len(src):
        return False
    js = not f["file"].endswith((".py", ".rb"))
    sig = n.signature or ""
    if f["file"].endswith(".go"):
        sig = re.sub(r"^func\s*\([^)]*\)\s*", "func ", sig)      # the receiver is not input
    plist = sig[sig.find("("):] if "(" in sig else ""
    if f["file"].endswith(".rs"):
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        params = []
        for piece in re.split(r",(?![^<(]*[>)])", inner):
            pat = piece.split(":", 1)[0].strip().replace("&", "").replace("mut ", "").strip()
            m = re.fullmatch(r"\w+\((\w+)\)", pat)             # State(state), Path(id), Json(body)
            params.append(m.group(1) if m else pat)
        params = [x for x in params if re.fullmatch(r"[A-Za-z_]\w*", x)]
    elif f["file"].endswith(".php"):
        params = re.findall(r"\$(\w+)", plist)                # `Request $request, $id` → request, id
    elif f["file"].endswith(".dart"):
        # Dart writes `Type name` (and `{required String id}`, `this.id`): the last identifier of each parameter
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", re.sub(r"@\w+(\([^)]*\))?|\brequired\b|[{}\[\]]", " ", inner))
        params = [m.group(1) for piece in inner.split(",")
                  for m in [re.search(r"([A-Za-z_$][\w$]*)\s*(?:=[^,]*)?$", piece.strip())] if m]
    elif f["file"].endswith((".kt", ".swift")):
        # Kotlin and Swift write `name: Type` (after `vararg`/`val`, an argument label, annotations): the name before
        # each top-level colon
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", re.sub(r"@\w+(\([^)]*\))?", "", inner))
        params = [m.group(1) for piece in re.split(r",(?![^(]*\))", inner)
                  for m in [re.search(r"([A-Za-z_]\w*)\s*:", piece)] if m]
    elif f["file"].endswith(C_EXTS):
        # C/C++ write `const std::string& name`, `char **argv`, `int n = 3`: the identifier before any default
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", inner)
        params = [m.group(1) for piece in inner.split(",")
                  for m in [re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:=[^,]*)?$", piece.strip())] if m]
    elif f["file"].endswith((".java", ".cs")):
        # `Type name` order: the last identifier of each parameter (annotations and generics stripped)
        inner = plist[1:plist.rfind(")")] if ")" in plist else plist[1:]
        inner = re.sub(r"<[^<>]*>", "", re.sub(r"@\w+(\([^)]*\))?", "", inner))
        params = [m.group(1) for piece in inner.split(",") for m in [re.search(r"([A-Za-z_$][\w$]*)\s*$", piece.strip())] if m]
    else:
        params = re.findall(r"[(,{]\s*\*{0,2}(?:\.\.\.)?([A-Za-z_$][\w$]*)", plist)
    tainted = {name: f"parameter `{name}`" for name in params if name not in ("self", "cls", "this")}
    stmts = _statements(src, n.start_line, max(n.end_line or n.start_line, line + 3), js)
    flagged = next((st for st in stmts if st[0] <= line <= st[1]), None)
    if flagged is None:
        return False
    head = _indent(src[n.start_line - 1])
    body = next((_indent(src[st[0] - 1]) for st in stmts if _indent(src[st[0] - 1]) > head), head + 1)
    level = {name: body for name in tainted}   # the block level at which each name was tainted
    for start, _end, text in stmts:
        if start >= flagged[0]:
            break
        m = ASSIGN.match(text) or next((b.match(text) for b in BINDS if b.match(text)), None)
        if not m:
            continue
        lhs, rhs = m.group("lhs"), m.group("rhs")
        req = req_re.search(rhs)
        src_name = next((t for t in tainted if _uses(t, rhs)), None)
        if req:
            origin = f"request data `{show(req.group(0))}`"
        elif src_name:
            origin = tainted[src_name]
        else:
            if "op" in m.groupdict() and not m.group("op"):
                for name in _names(lhs):   # a plain reassignment at the same level replaces the tainted value
                    if name in tainted and _indent(src[start - 1]) <= level[name]:
                        del tainted[name], level[name]
            continue
        for name in _names(lhs):
            tainted[name] = f"`{name}`, which line {start} sets from {origin}"
            level[name] = _indent(src[start - 1])
    text = flagged[2]
    m = req_re.search(text)
    if m:
        return {"via": f"request data `{show(m.group(0))}`"}
    for name, origin in tainted.items():
        if _uses(name, text):
            return {"via": origin}
    return False


def _node_at(g: Graph, file: str | None, line: int | None) -> str | None:
    if not file:
        return None
    best, best_span = None, None
    for n in g.nodes_in(file):
        if n.file != file or n.start_line is None:
            continue
        if line is None:
            if n.kind == "module":
                return n.id
            continue
        if n.start_line <= line <= (n.end_line or n.start_line):
            span = (n.end_line or n.start_line) - n.start_line
            if best_span is None or span < best_span:
                best, best_span = n.id, span
    return best


def reachability(g: Graph, include_tests: bool = False, kinds: set[str] | None = None, where=None,
                 worked_out: bool = False, leave=None) -> dict[str, dict]:
    """Multi-source BFS from entry points. Returns node id -> {entry, kind, path}. `where(node)` keeps only the entry
    points it says yes to (`scan` asks for the ones outside test files). `worked_out`: follow only the links Lantern
    worked out to one function, not a guess by method name (`calls.NAME_ONLY_VIA`) and not one of several possible
    targets (`possible`: every class that has the method, every implementation of an interface). `leave(link)`:
    the links it says yes to are not followed."""
    adj: dict[str, list[str]] = {}
    for e in g.call_edges():
        if worked_out and (e.confidence == "possible" or e.via in NAME_ONLY_VIA):
            continue
        if leave is not None and leave(e):
            continue
        adj.setdefault(e.src, []).append(e.dst)
    seen: dict[str, dict] = {}
    q: deque[str] = deque()
    entries = [n for n in g.entry_points() if (include_tests or n.entry["kind"] != "test")
               and (kinds is None or n.entry["kind"] in kinds) and (where is None or where(n))]
    # untrusted-input entries first so their paths win ties
    entries.sort(key=lambda n: 0 if n.entry["kind"] in UNTRUSTED_ENTRY_KINDS else 1)
    for n in entries:
        if n.id not in seen:
            seen[n.id] = {"entry": n.id, "kind": n.entry["kind"], "prev": None}
            q.append(n.id)
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen[nxt] = {"entry": seen[cur]["entry"], "kind": seen[cur]["kind"], "prev": cur}
                q.append(nxt)
    out = {}
    for nid, info in seen.items():
        path, cur = [], nid
        while cur is not None:
            path.append(cur)
            cur = seen[cur]["prev"]
        out[nid] = {"entry": info["entry"], "kind": info["kind"], "path": list(reversed(path))}
    return out


def rank(f: dict) -> str:
    """The rank: the tool's own severity, raised when an entry point from outside reaches the line and request data
    is not ruled out (`_steps`), then capped by what the code around the line shows (context.py: a weak hash used as
    an identifier, SQL that splices only fixed text, a function every caller hands fixed text). A cap is written on
    the finding as `rank_note`, with the rank it would have had as `rank_before_context`, so nothing changes silently.
    That Lantern found no path to a line lowers nothing (directive point 6): it is written in `reachability`."""
    r = _rank(f)
    cap, why = None, None
    ctx = f.get("context") or {}
    h, sql = ctx.get("hash"), ctx.get("sql")
    if h and h["purpose"] == "non-security":
        cap, why = "low", (f"The hash looks like an identifier, seed or checksum ({h['why']}), not protection for a "
                           "password, token or signature. MD5/SHA-1 are fine for that. Lantern read names, not meaning.")
    elif h and h["purpose"] == "unknown":
        cap, why = "medium", ("Lantern could not tell what this hash is for (" + h["why"] + "). It is not ranked "
                              "critical or high without evidence that it protects a password, token or signature.")
    elif sql and sql["fixed_only"] and not f.get("flow"):
        cap, why = "low", ("Only fixed text is put into the SQL string (" + "; ".join(
            f"{s['expr']}: {s['why']}" for s in sql["spliced"]) + ")" + (
            ", and the values are passed to the database driver separately." if sql["driver_params"] else "."))
    elif ctx.get("fixed"):
        fx = ctx["fixed"]
        if fx["calls"]:
            calls = "; ".join(f"`{c['from']}` at {c['file']}:{c['line']}" for c in fx["calls"][:3])
            more = f" and {fx['count'] - 3} more" if fx["count"] > 3 else ""
            how = (f"every call of `{fx['function']}` in the project hands it fixed text ({calls}{more}), and Lantern "
                   "found no other way the function is called. A new caller that hands it request data would change "
                   "this.")
        else:
            how = "the text is written in the code itself, and nothing that comes from outside is put into it."
        cap, why = "low", "Only fixed text reaches this line: " + how
    if cap and RANK_ORDER[r] < RANK_ORDER[cap]:
        f["rank_before_context"] = r
        f["rank_note"] = why
        return cap
    f.pop("rank_before_context", None)
    f.pop("rank_note", None)
    return r


# The tool's own severity as a rank. A rank goes under it only on evidence written on the finding (`rank_note` with
# `rank_before_context`, test code, a rank a rule fixes itself). That Lantern found no path to a line is not evidence:
# until 2026-11 a high with no path was ranked medium and a medium low, "because nothing in the map reaches it".
FLOOR = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
NO_PATH = ("which is not proof that nothing runs it: a scheduler, another program, a framework that calls by name or a "
           "call Lantern could not follow would not show")


def _step(name: str, to: str, why: str) -> dict:
    return {"step": name, "rank": to, "why": why}


def _steps(f: dict) -> list[dict]:
    """How the rank comes about before the code around the line is looked at, one step after the other, each with its
    reason. The tool's severity is where it starts; who reaches the line can only raise it."""
    if f.get("fixed_rank"):
        return [_step("fixed", f["fixed_rank"], f.get("fixed_why") or
                      f"Lantern gives this rule the rank {f['fixed_rank']} whatever reaches it.")]
    if f["category"] == "secret":
        return [_step("fixed", "critical", "A key written in the code is always critical: anyone who can read the "
                                           "code can use it.")]
    if f["category"] == "dependency":   # npm says how bad; pip-audit doesn't, so those stay high
        return [_step("severity", {"moderate": "medium", "low": "low", "info": "low"}.get(str(f.get("dep_severity")),
                                                                                         "high"),
                      "From the advisory's own severity (high when the audit gives none).")]
    own = f.get("tool_severity")
    out = [_step("severity", FLOOR.get(own, "low"), f"{f.get('tool') or 'The tool'} rates the pattern "
                                                   f"{str(own).lower()}.")]
    sev = flowscan.raised_severity(f)     # the tool's own, or graver when request data was followed to the line
    if sev != own:
        out.append(_step("raised", FLOOR.get(sev, "low"), "Lantern followed request data to the line, which makes "
                                                          f"the pattern {str(sev).lower()}."))
    reach = f.get("reachable")
    untrusted = reach and reach["kind"] in UNTRUSTED_ENTRY_KINDS
    if sev == "HIGH" and untrusted and f.get("input") is not False:
        # spec 9.3: high severity and touched by untrusted input (False: the line uses none)
        out.append(_step("raised", "critical", f"{reach['kind']} code reaches it" + (
            ", using request data." if f.get("input") else ", and Lantern could not rule out request data.")))
    elif sev == "MEDIUM" and untrusted:
        out.append(_step("raised", "high", f"{reach['kind']} code reaches it."))
    return out


def _rank(f: dict) -> str:
    return _steps(f)[-1]["rank"]


def rank_basis(f: dict) -> list[dict]:
    """The steps that end at `f["rank"]`: `severity` (the tool's own), `raised` (request data followed to the line; an
    entry point from outside reaches it), `lowered` (evidence from the code around the line, `rank_note`), `fixed` (a
    rank the rule or the kind of finding fixes), `test-code`. Read after `rank` and `in_tests` are set."""
    out = _steps(f)
    if f.get("in_tests") and f.get("category") == "code":
        out.append(_step("test-code", "low", _test_code(f)))
    elif f.get("rank_note"):
        out.append(_step("lowered", f["rank"], f["rank_note"]))
    return out


def reach_state(f: dict) -> dict:
    """What is known about who runs the flagged code, as a fact of its own beside the rank: `reached` (with the kind
    of entry point), `tests-only`, `unknown` (no path found, or the line is in no function of the map: never read as
    "nothing runs it"), `not-code` (a library in a list: there is no line of the project to reach)."""
    r = f.get("reachable")
    if r:
        out = {"state": "reached", "kind": r["kind"], "why": f"{r['kind']} code reaches it on Lantern's map."}
    elif f.get("category") == "dependency":
        out = {"state": "not-code", "why": "A library the project lists. Lantern does not follow calls into libraries, "
                                           "so it cannot say which code of the project uses the affected part."}
    elif f.get("reachable_from_tests_only"):
        out = {"state": "tests-only", "why": "Only the test suite was found to reach this code, " + NO_PATH + "."}
    elif not f.get("node"):
        out = {"state": "unknown", "why": "This line is in no function on Lantern's map (a settings file, a template, "
                                          "a part of the code Lantern does not map), so Lantern cannot say what runs "
                                          "it. That is not proof that nothing does."}
    else:
        out = {"state": "unknown", "why": "Lantern found no path to this code from a page, route, command or script, "
                                          + NO_PATH + "."}
    if f.get("test_file_in_use"):
        out["why"] += " The file is named like a test, but code outside the tests runs it."
    return out


TEST_CODE = "Test code: your users do not run it, so it is ranked low and counted apart."
GUESSED_LINK = (" A call somewhere in the app might lead into this file by its name alone: a method here has the name "
                "of one the app calls on something whose type Lantern cannot tell. That is a guess, and Lantern does "
                "not count a guess as the app running a test file.")
STOOD_IN = (" The app's code did call a function of this file while the tests ran: a test had handed it over (a "
            "stand-in for one of the app's own functions, a callback, a double for one of its objects). That shows "
            "what the tests do, and Lantern does not count it as the app running a test file.")
# A link whose only evidence of where it leads is the recording of the project's own test run: one the code does not
# show at all, or a guess (by method name, one of several overrides) that the run then saw.
SEEN_RUNNING = "runtime-only"
SEEN_TOO = "+observed"
GUESSED_VIA = (*NAME_ONLY_VIA, "override")


def only_the_run_shows(via: str | None) -> bool:
    """Is the tests' own run all that says where this link leads? The code shows no such call (`runtime-only`), or
    Lantern guessed it and the run then saw it (`method-name+observed`). A link read from the code that the run saw
    too (`import+observed`) is the code's."""
    via = via or ""
    return via == SEEN_RUNNING or (via.endswith(SEEN_TOO) and via[: -len(SEEN_TOO)] in GUESSED_VIA)


def _test_code(f: dict) -> str:
    """The words for a finding ranked as test code, with what leads into its file and does not count."""
    return TEST_CODE + (STOOD_IN if f.get("test_file_stood_in") else GUESSED_LINK if f.get("test_file_guessed") else "")


NOSEC_SAYS = {
    "bare": " The line carries a `# nosec` comment, which asks scanners to skip it, and gives no reason. Lantern "
            "lists the finding all the same.",
    "overruled": " The line carries a `# nosec` comment with a reason. Lantern does not take that as settled, "
                 "because it followed request data to this line.",
}


def _request_data(f: dict) -> bool:
    """Did Lantern itself follow request data to the flagged line: across functions (`flow`), or in the line's own
    function (`input` says "request data"; a parameter alone is not that)?"""
    if f.get("flow"):
        return True
    i = f.get("input")
    return isinstance(i, dict) and (bool(i.get("flow")) or "request data" in str(i.get("via") or ""))


def rank_reason(f: dict) -> str:
    """Why `_steps` gave the rank it gave, in words (kept next to `_steps` so the two change together)."""
    if f.get("in_tests") and f.get("category") == "code":
        return _test_code(f)
    if f.get("fixed_rank"):
        return f.get("fixed_why") or f"Lantern gives this rule the rank {f['fixed_rank']} whatever reaches it."
    sev = f.get("tool_severity")
    reach = f.get("reachable")
    untrusted = reach and reach["kind"] in UNTRUSTED_ENTRY_KINDS
    if f.get("category") == "secret":
        return "A key written in the code is always critical: anyone who can read the code can use it."
    if f.get("category") == "dependency":
        return "From the advisory's own severity (high when the audit gives none)."
    base = f"{f.get('tool') or 'The tool'} rates the pattern {str(sev).lower()}"
    if sev and flowscan.raised_severity(f) != sev:
        sev = flowscan.raised_severity(f)
        base += f"; Lantern followed request data to it, which makes it {sev.lower()}"
    if sev == "HIGH" and untrusted and f.get("input") is not False:
        r = base + f", and {reach['kind']} code reaches it" + (", using request data." if f.get("input") else
                                                               "; Lantern could not rule out request data.")
    elif sev == "HIGH" and reach:
        r = base + ", and something in the app reaches it" + (", but no request data reaches the line."
                                                              if f.get("input") is False else ".")
    elif sev == "MEDIUM" and untrusted:
        r = base + f", and {reach['kind']} code reaches it."
    elif sev == "MEDIUM" and reach:
        r = base + f", reached from {reach['kind']} code (not a server route, command or script)."
    elif reach or not f.get("node"):
        r = base + "."
    elif f.get("reachable_from_tests_only"):
        r = base + (". Only the test suite was found to reach it, which is not proof that nothing else runs it, so "
                    "the rank stays at the tool's own severity.")
    else:
        r = base + (". Lantern found no path to it from a page, route or command, which is not proof that nothing "
                    "runs it, so the rank stays at the tool's own severity.")
    if f.get("test_file_in_use"):
        r += " The file is named like a test, but code outside the tests runs it, so it is not counted as test code."
    if (f.get("nosec") or {}).get("state") in NOSEC_SAYS:
        r += NOSEC_SAYS[f["nosec"]["state"]]
    if f.get("rank_note"):
        r += " Then lowered by context: " + f["rank_note"]
    return r


RANK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ACCEPTED_FILE = "lantern-accepted.json"


def load_accepted(repo: Path) -> dict[str, dict]:
    """Accepted risks live in the repo (committed), each with the builder's written reason."""
    p = repo / ACCEPTED_FILE
    try:
        data = manifest.parse_json(project_text(p, repo))
    except OSError:   # not there, or not a file of the project (a link that leads out of it, a pipe): nothing is accepted
        return {}
    # the file comes with the project: only a row with a finding's id and a written reason accepts anything
    return {r["id"]: r for r in manifest.tables(manifest.table(data).get("accepted"))
            if isinstance(r.get("id"), str) and r["id"] and reason_ok(r.get("reason"))}


def reason_ok(reason) -> bool:
    """A real written reason: at least 10 letters/digits across two or more words, not one repeated character.
    Applies to hand-edited `lantern-accepted.json` too, so "x" can't silence --fail-on."""
    if not isinstance(reason, str):
        return False
    words = re.findall(r"[^\W_]{2,}", reason)
    chars = "".join(words)
    return len(words) >= 2 and len(chars) >= 10 and len(set(chars.lower())) >= 5


def save_accepted(repo: Path, accepted: dict[str, dict]) -> Path:
    p = repo / ACCEPTED_FILE
    rows = sorted(accepted.values(), key=lambda r: r["id"])
    results.write(p, json.dumps({"about": "Security findings the builder reviewed and accepted, with reasons. "
                                          "Managed by `lantern accept`.", "accepted": rows}, indent=1) + "\n",
                  where="the project folder")
    return p


ID_VERSION = 2


def stable_ids(repo: Path, findings: list[dict]) -> None:
    """Give each finding an id that survives moving its code: tool, rule, file, and the flagged line's text with
    spaces removed, plus a counter for identical lines in one file. Lines added above a finding don't change it,
    so "fixed" means the flagged code is really gone (or changed). Findings without a line keep the scanner's id."""
    lines: dict[str, list[str]] = {}
    seen: dict[str, int] = {}
    for f in sorted(findings, key=lambda f: (f.get("file") or "", f.get("line") or 0, f.get("rule") or "")):
        if not f.get("file") or not f.get("line"):
            continue
        if f["file"] not in lines:
            try:
                lines[f["file"]] = project_text(repo / f["file"], repo).splitlines()
            except OSError:
                lines[f["file"]] = []
        src = lines[f["file"]]
        text = re.sub(r"\s+", "", src[f["line"] - 1]) if 0 < f["line"] <= len(src) else f"line{f['line']}"
        key = "|".join(map(str, (f.get("tool"), f.get("rule"), f["file"], text)))
        seen[key] = seen.get(key, 0) + 1
        f["id"] = _fid(key, seen[key])


MOST_BESIDE = 8


def beside() -> int:
    """How many scanner programs may run beside the reading of the code: `LANTERN_JOBS` when it is a whole number
    (0: none, each scanner runs in its turn as before 2026-11-12; `MOST_BESIDE` at most), else two where the
    computer has a processor to spare for them and none where it has one."""
    said = os.environ.get("LANTERN_JOBS", "").strip()
    if said.isdigit():
        return min(MOST_BESIDE, int(said))
    return min(2, max(0, (os.cpu_count() or 1) - 1))


class Early:
    """The scanners that read the project's files and nothing of the map, started when a run begins and run beside
    the reading of the code, at most `room` at a time (directive point 10; until 2026-11-12 Bandit was started only
    when the map was finished, and the analysis waited for it: half a minute on a large Python project).

    Started early: Bandit where it is installed, every dependency audit, and the secret scan where gitleaks is
    installed (each is a program of its own, or waits for the network). `scan(g, offline, early)` takes what each
    one gave at the place it ran them before and in the same order, and runs by itself whatever was not started
    early, so the findings and the records are the same as when one runs after the other. `close()` is for the end
    of the run, however it ended: what is still going is ended with everything it started."""

    def __init__(self, repo, offline: bool | None, room: int | None = None):
        self.repo, self.offline = Path(repo), offline
        self.room = beside() if room is None else room
        self._jobs: dict = {}
        self._threads: set[int] = set()
        self._pool = None

    def start(self) -> "Early":
        if self.room < 1 or self._pool is not None:
            return self
        import importlib.util
        from concurrent.futures import ThreadPoolExecutor
        from . import depaudit
        self._pool = ThreadPoolExecutor(max_workers=self.room, thread_name_prefix="lantern-scanner")
        if importlib.util.find_spec("bandit") is not None:      # else `scan` writes the record of its absence
            self._begin("bandit", lambda: run_bandit(self.repo))
        for tool, fn in depaudit.audits():
            self._begin(tool, lambda tool=tool, fn=fn: depaudit.guarded(tool, fn, self.repo, self.offline))
        if programs.find("gitleaks"):
            self._begin("secrets", lambda: run_secrets(self.repo))
        return self

    def _begin(self, name: str, fn) -> None:
        def job():
            self._threads.add(threading.get_ident())
            return fn()
        # in the run's own context: what the scanner takes from kept work is counted with the run's (`kept.tally`)
        self._jobs[name] = self._pool.submit(contextvars.copy_context().run, job)

    def take(self, name: str, fn):
        """What the scanner `name` gave (waited for when it is still going), or what `fn()` gives now when it was
        not started early."""
        job = self._jobs.pop(name, None)
        return fn() if job is None else job.result()

    def close(self) -> None:
        if self._pool is None:
            return
        from . import remote
        left = [job for job in self._jobs.values() if not job.cancel()]   # going, or done and never taken
        if any(not job.done() for job in left):
            remote.end_for(self._threads)
        self._pool.shutdown(wait=True, cancel_futures=True)
        remote.forget(self._threads)
        self._jobs.clear()
        self._pool = None


def _scanned_as_text(tools: list[dict]) -> list[str]:
    """The files kept as text that Bandit was handed and read: none when it did not run to an end."""
    from . import scanresult
    for t in tools:
        if t.get("tool") == "bandit" and scanresult.state_of(t) in ("ok", "partial"):
            failed = [str(e) for e in t.get("errors") or []]
            return [rel for rel in t.get("read_as_text") or [] if not any(e.startswith(rel + ":") for e in failed)]
    return []


def scan(g: Graph, offline: bool | None = None, early: Early | None = None) -> dict:
    """All scanners. `offline` skips the dependency audits, the only steps that use the network
    (None: follow LANTERN_OFFLINE). `early`: the scanners a run started before the map was built (`Early`), used
    only when they were started for this folder and this `offline`."""
    repo = Path(g.repo_root)
    findings, tools = [], []
    from . import depaudit, scanresult
    if early is not None and (early.repo != repo or early.offline != offline):
        early = None

    def took(name: str, fn):
        return fn() if early is None else early.take(name, fn)

    # The steps that read the map and the project's files and nothing another scanner found are worked out first:
    # a scanner program started with the run may still be going, and until 2026-11-12 the run stood still until it
    # had ended (on Django Bandit ends 43 seconds in, the map is done at 26). What each step found is put together
    # below at the place and in the order it always was.
    from .aiapp import scan_ai
    from .packs import load_all, scan_packs, split_enabled
    from .websec import scan_web
    wf, wt = scan_web(g)
    af, ai = scan_ai(g)
    loaded, skipped = load_all(repo, keep_disabled=True)
    loaded, off = split_enabled(loaded)
    pf, pt = scan_packs(repo, loaded) if loaded else ([], [])
    flows_read = flowscan.read(g)
    # Bandit's absence is a gap only when there is Python to read
    f, info = took("bandit", lambda: run_bandit(repo, applicable="python" in (g.meta.get("languages") or {})))
    findings += f
    tools.append(info)
    for tool, fn in depaudit.audits():      # each behind its own wall: one that raises is one `failed` record
        f, info = took(tool, lambda tool=tool, fn=fn: depaudit.guarded(tool, fn, repo, offline))
        findings += f
        tools.append(info)
    f, records = took("secrets", lambda: run_secrets(repo))
    findings += f
    tools += records
    # one problem, one finding: a line LW-SECRET-INLINE lists (what the text signs, the text itself never repeated)
    # is not listed again as Bandit's "possible hardcoded password", ranked low and with the text in its title
    told = {(f["file"], f["line"]) for f in wf if f["rule"] == "LW-SECRET-INLINE"}
    findings = [f for f in findings if not (f["rule"] in ("B105", "B106", "B107") and
                                            (f["file"], f["line"]) in told)]
    findings += wf
    tools += wt
    findings += af
    tools.append({"tool": "lantern-ai", "status": "ok" + ("" if ai["calls"] else " (no model, vector or paid API calls found)"),
                  "version": "0.1"})
    if loaded:
        findings += pf
        tools += pt
    # a pack turned off in Settings is named with its status, so the Evidence Report says it was not used
    tools += [{"tool": f"lantern-pack:{pk['pack']}", "status": "off (turned off in Settings)",
               "version": str(pk.get("version", "-"))} for pk in off]
    tools += [{"tool": where, "status": "skipped: " + why, "version": "-"} for where, why in skipped]
    lines_cache: dict[str, list[str]] = {}
    py_cache: dict = {}

    def lines_for(file: str) -> list[str]:
        if file not in lines_cache:
            try:
                lines_cache[file] = project_text(repo / file, repo).splitlines()
            except OSError:
                lines_cache[file] = []
        return lines_cache[file]
    # Follow the data (flow.py): request data followed across functions to a query, a command, a file, an address, a
    # page. A flow on a line another tool flagged is written on that finding; the others are findings of their own.
    ff, info, flows = flowscan.run(g, findings, lines_for, paid_calls=ai["calls"], ahead=flows_read)
    findings += ff
    tools.append(info)
    stable_ids(repo, findings)
    accepted = load_accepted(repo)
    reach = reachability(g)
    ui_reach = reachability(g, kinds={"page", "main"})
    test_reach = reachability(g, include_tests=True)
    from .js_frontend import TEST_RE as JS_TEST_RE
    from .python_frontend import TEST_FILE_RE
    named_test = lambda file: bool(file and (TEST_FILE_RE.search(file) or JS_TEST_RE.search(file)))
    test_file = lambda nid: nid in g.nodes and named_test(g.nodes[nid].file)        # noqa: E731

    def handed(e) -> bool:
        """A link from outside the test files into one, which only the tests' own run shows."""
        return only_the_run_shows(e.via) and test_file(e.dst) and not test_file(e.src)

    own_reach = in_use = stood_in = guessed = None    # what the entry points outside test files reach; worked out when first asked
    for f in findings:
        pin = f.pop("pin", None)          # a manifest finding names the class it is about (android.py)
        f["node"] = (pin if pin in g.nodes else None) or _node_at(g, f["file"], f["line"])
        r = reach.get(f["node"]) if f["node"] else None
        # Test code is ranked low and counted apart: users do not run the test suite. The file's name alone does not
        # show that. A file named like a test, one function of which a page, route or command outside the test files
        # runs, is the app's own code: the app loads the whole file. (A test file's own small app does not make it
        # so: its entry points are in a test file.) "Runs" means a link Lantern worked out. A guess by method name,
        # or one of several classes that have the method, is no evidence of who runs a file: a test double has the
        # methods of what it stands in for, so every project's fakes would count as the app's own code. Such a
        # file stays test code, and the finding says that a guess leads there (`test_file_guessed`).
        # Nor is what the project's own test run showed (2026-11-13): while the tests run, the app's code calls what
        # a test handed it, a stand-in in the place of one of its functions, a callback, a double for one of its
        # objects, and the recording has those calls, from the app's code into the test file. A link from outside
        # the test files into one that only the run shows (`only_the_run_shows`) is the tests' doing: the file stays
        # test code, as it is with no test run, and the finding says so (`test_file_stood_in`). After "Watch my
        # tests run" on Lantern itself such links made 41 of its test files the app's own code, 3,095 findings, 7 of
        # them high, and the release decision read Blocked for them. A link the code itself shows counts as before,
        # whether the run saw it or not.
        f["in_tests"] = named_test(f["file"])
        f.pop("test_file_in_use", None)
        f.pop("test_file_stood_in", None)
        f.pop("test_file_guessed", None)
        if f["in_tests"]:
            if own_reach is None:
                outside = lambda n: not named_test(n.file)      # noqa: E731
                files = lambda found: {g.nodes[nid].file for nid in found          # noqa: E731
                                       if nid in g.nodes and named_test(g.nodes[nid].file)}
                own_reach = reachability(g, where=outside, worked_out=True, leave=handed)
                in_use = files(own_reach)
                stood_in = files(reachability(g, where=outside, worked_out=True)) - in_use
                guessed = files(reachability(g, where=outside)) - in_use - stood_in
            if f["file"] in in_use:
                r = own_reach.get(f["node"]) or r
                f["in_tests"], f["test_file_in_use"] = False, True
            elif f["file"] in stood_in:
                f["test_file_stood_in"] = True
            elif f["file"] in guessed:
                f["test_file_guessed"] = True
        f["reachable"] = r
        f["reachable_from_tests_only"] = bool(not r and f["node"] in test_reach)
        u = ui_reach.get(f["node"]) if f["node"] else None
        f["ui_path"] = u["path"] if u else None
        # Stack strip: the lane the problem lives on, and every lane its path crosses (lanes.py).
        node = g.nodes.get(f["node"]) if f["node"] else None
        f["hot_lane"] = (node.lane if node else None) or lanes.lane_for_file(f["file"], lanes.phone_roots(g.meta))
        data_hops = ["data"] if node and any((g.nodes.get(e.dst) and g.nodes[e.dst].lane == "data")
                                             for e in g.callees(node.id)) else []
        f["lanes"] = lanes.lanes_for_path(g, (u["path"] if u else None) or (r["path"] if r else None),
                                          f["hot_lane"], data_hops)
        f["input"] = _input_on_line(g, f, lines_cache) if f["category"] == "code" and r and \
            r["kind"] in UNTRUSTED_ENTRY_KINDS else None
        fl = f.get("flow")
        if fl and not f["in_tests"]:
            # followed across functions, from the place the request was read: that says more than the look at the
            # flagged line's own function, which names whatever parameter stands on the line
            f["input"] = {"via": fl["source"]["what"], "flow": True}
            if not r:
                # the map shows no way to this line, and the flow is one: but only from a function that a page, a
                # route or a command reaches. A handler nothing uses read the request in name only.
                start = _node_at(g, fl["source"]["file"], fl["source"]["line"])
                sr = reach.get(start) if start else None
                if sr:
                    path = list(sr["path"])
                    for s in fl["steps"]:
                        nid = _node_at(g, s["file"], s["line"])
                        if nid and nid != path[-1]:
                            path.append(nid)
                    r = f["reachable"] = {"entry": sr["entry"], "kind": sr["kind"], "path": path, "via": "data flow"}
        if f["category"] == "code":
            # what the flagged code is for (context.py); it can lower the rank, never remove the finding
            ctx = {}
            hp = context.hash_purpose(g, f, lines_for, py_cache)
            if hp:
                ctx["hash"] = hp
            sq = context.sql_splice(g, f, py_cache)
            if sq:
                ctx["sql"] = sq
                if sq["fixed_only"] and f["input"] and not fl:
                    # the input check reads the whole statement; for SQL only what is spliced into the text counts
                    f["input"] = False
            # every call of the function hands it fixed text (the data-flow step), or, in Python kept as text, which
            # that step does not read, the flagged call is handed literals only: said on the finding, which stays listed
            fx = flowscan.fixed_evidence(flows, f) or context.fixed_command(g, f, py_cache)
            if fx:
                ctx["fixed"] = fx
                f["input"] = False
            if ctx:
                f["context"] = ctx
        if f.get("rule") == "LW-PUBLIC-SECRET" and not f["in_tests"]:
            # a value visible in the browser is one fact; whether the server trusts it is another (context.py)
            tr = context.public_secret_trust(g, f, lines_for)
            if tr:
                f["trust"] = tr
        f["rank"] = "low" if f["in_tests"] and f["category"] == "code" else rank(f)
        # the facts the rank was worked out from stay their own fields beside it (`tool_severity`, `tool_confidence`,
        # `reachable`, the case's evidence), with what is known about who runs the line and each step to the rank
        f["reachability"] = reach_state(f)
        f["rank_basis"] = rank_basis(f)
        acc = accepted.get(f["id"])
        f["status"] = "accepted" if acc else "open"
        if acc:
            f["accepted"] = {k: acc.get(k) if isinstance(acc.get(k), str) else None for k in ("reason", "by", "date")}
        ns = f.get("nosec")
        if ns:
            # A `# nosec` comment with a written reason is the project's word that it looked at the line: the same
            # as `lantern accept`, and shown the same way. It is not taken where Lantern itself followed request
            # data to the line, and a comment with no reason accepts nothing.
            f["nosec"] = ns = {"state": "bare" if not ns.get("reason") else "overruled" if _request_data(f)
                               else "accepted", "reason": ns.get("reason")}
            if ns["state"] == "accepted" and not acc:
                f["status"] = "accepted"
                f["accepted"] = {"reason": ns["reason"], "by": None, "date": None, "how": "nosec"}
    # Scenarios (scenarios.py): a short story of one person meeting each finding, built from the facts above only.
    from .scenarios import attach as attach_scenarios
    attach_scenarios(findings, g)
    # The case for each finding outside tests (case.py): claim, evidence, conditions, confidence, unknowns, status.
    from .case import attach as attach_cases
    attach_cases(findings, g)
    findings.sort(key=lambda f: (f["in_tests"], RANK_ORDER[f["rank"]], f["file"] or "", f["line"] or 0))
    live =[f for f in findings if not f["in_tests"] and f["status"] == "open"]
    counts = {k: sum(1 for f in live if f["rank"] == k) for k in RANK_ORDER}
    counts["in_tests"] = sum(1 for f in findings if f["in_tests"])
    counts["accepted"] = sum(1 for f in findings if f["status"] == "accepted")
    return {"findings": findings, "tools": tools, "counts": counts, "id_version": ID_VERSION,
            # the scanners that apply to this project and did not finish or did not cover everything (scanresult.py):
            # readiness, the Evidence Report, the badge, the command line and the app all read this list
            "incomplete": scanresult.incomplete(tools),
            # what the project holds that Lantern takes for code or software and no reader opened (`unread.py`): code
            # kept under another name, software copied into a vendor folder. The Evidence Limits and the release
            # decision read it
            "not_read": unread.survey(repo, scanned=_scanned_as_text(tools)),
            "reachable_nodes": len(reach), "total_callables": sum(1 for n in g.nodes.values() if n.kind == "callable"),
            # the routes whose own code turns away whoever is not signed in, as the flow step read it (`flow.Result.
            # logins`; None when it did not run): the card "Login check on routes that change data" counts them as
            # checked, so it tells the story the findings tell (`protections.advise`)
            "logins_shown": sorted(x for x in flows.logins if x in g.nodes) if flows is not None else None,
            "ai": ai, "mobile": g.meta.get("mobile")}
