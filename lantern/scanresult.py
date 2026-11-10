"""One record for every scanner run, so a failure is never reported as a clean result.

Every adapter (Bandit, gitleaks and the built-in secret patterns, pip-audit, npm audit, the OSV audits, Lantern's own
rule sets and analysis packs) describes its run with `record()`:

    state       ok | partial | failed | timeout | unavailable | skipped
    status      the same thing as one sentence, for readers written before `state` existed:
                "ok", "ok (…)", "partial: …", "error: …", "error: timed out …", "skipped: not installed (…)", "skipped: …"
    why         the reason in plain words
    applicable  False when the tool had nothing to do in this project (no Python dependency files; gitleaks absent but
                the built-in patterns ran instead). Only applicable records that are not `ok` make a scan incomplete.
    version, exit_code, scope, exclusions, errors, findings, duration_ms, role, fallback_for   when known

`partial` means the tool finished but did not cover everything (a file it could not read, a package it could not look
up); the findings it did produce are kept, and `errors` lists what was left out. `failed` means the tool ran but its
output could not be trusted (a crash exit code, empty output, broken or wrong-shaped JSON); nothing it would have found
is in the report. `timeout` and `unavailable` (not installed) say so. `skipped` is a deliberate choice (offline) or
nothing to check.

`incomplete(tools)` is the list readiness (`sec-scanners`), the Evidence Report and badge ("scan incomplete"), the
command line (`--fail-on`), `run.json` and the app's project cards all read, so a weaker or missing scan can never
pass as a complete one.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass

STATES = ("ok", "partial", "failed", "timeout", "unavailable", "skipped")
BROKEN = ("failed", "timeout")          # the tool was supposed to run and did not finish
GAPS = ("partial", "unavailable", "skipped")   # it ran, or was skipped, but something it applies to was not covered


@dataclass
class ToolRun:
    """What happened when an outside program was run: the exit code (None when it never ran or was killed), its
    output, whether the time limit killed it, how long it took, and the error when it could not even start."""
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: int = 0
    error: str | None = None


def run_tool(cmd: list[str], *, timeout: float, cwd=None, env: dict | None = None) -> ToolRun:
    """Run a scanner with a time limit. On the limit the whole process tree is killed (`remote.run_bounded`), so a
    helper the tool started cannot keep the run hanging; a program that is not installed is an error, not a crash."""
    from .remote import run_bounded
    t = time.perf_counter()
    try:
        p = run_bounded(list(cmd), cwd=cwd, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ToolRun(None, timed_out=True, duration_ms=_ms(t))
    except OSError as exc:
        return ToolRun(None, error=f"{type(exc).__name__}: {exc}", duration_ms=_ms(t))
    return ToolRun(p.returncode, p.stdout or "", p.stderr or "", duration_ms=_ms(t))


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


def record(tool: str, state: str, why: str = "", *, applicable: bool | None = None, **fields) -> dict:
    """The record of one scanner's run. `applicable` defaults to True except for a `skipped` run (nothing to check);
    pass `applicable=True` for a skip that leaves a gap (offline) and `applicable=False` for a tool another one stood
    in for."""
    if state not in STATES:
        raise ValueError(f"unknown scanner state {state!r}; one of {', '.join(STATES)}")
    if applicable is None:
        applicable = state != "skipped"
    why = " ".join(str(why or "").split())
    if state == "ok":
        status = "ok" + (f" ({why})" if why else "")
    elif state == "partial":
        status = f"partial: {why or 'part of the project was not covered'}"
    elif state == "failed":
        status = f"error: {why or 'the tool did not finish'}"
    elif state == "timeout":
        status = "error: timed out" + (f" {why}" if why else "")
    elif state == "unavailable":
        status = "skipped: not installed" + (f" ({why})" if why else "")
    else:
        status = f"skipped: {why or 'nothing to check'}"
    return {"tool": tool, "state": state, "status": status, "why": why, "applicable": bool(applicable), **fields}


def state_of(info: dict) -> str:
    """The state of a record, including records written before `state` existed (read from their status sentence)."""
    st = info.get("state") if isinstance(info, dict) else None
    if st in STATES:
        return st
    s = " ".join(str((info or {}).get("status") or "").split()).lower()
    if not s or s == "ok" or s.startswith(("ok ", "ok(")):
        return "ok"
    if s.startswith("partial"):
        return "partial"
    if s.startswith("error"):
        return "timeout" if ("timed out" in s or "timeout" in s) else "failed"
    if s.startswith("skipped"):
        return "unavailable" if "not installed" in s else "skipped"
    if s.startswith("off"):      # an analysis pack turned off in Settings
        return "skipped"
    return "failed"


def applicable(info: dict) -> bool:
    """Whether the tool had work to do in this project. Older records say so only through their status sentence: a
    deliberate offline skip and an uninstalled tool leave a gap; nothing to check does not."""
    a = (info or {}).get("applicable")
    if isinstance(a, bool):
        return a
    st = state_of(info)
    if st == "skipped":
        return str((info or {}).get("status") or "").lower().startswith("skipped: offline")
    return True


def incomplete(tools: list[dict] | None) -> list[dict]:
    """The applicable records that are not `ok`: what the report cannot vouch for."""
    return [t for t in (tools or []) if isinstance(t, dict) and state_of(t) != "ok" and applicable(t)]


def broken(tools: list[dict] | None) -> list[dict]:
    """The incomplete records whose tool was supposed to run and did not finish, or ran and left part of the project
    unchecked, or is not installed although the project needs it. A deliberate skip (offline) is not in this list."""
    return [t for t in incomplete(tools) if state_of(t) != "skipped"]


def parse_json(text: str, want: type = dict) -> tuple[object | None, str | None]:
    """A scanner's JSON output, or why it could not be used: empty output, broken JSON, or the wrong shape (a list
    where an object was expected). The caller then checks the keys it needs."""
    if not (text or "").strip():
        return None, "empty output"
    try:
        data = json.loads(text)
    except ValueError as exc:
        return None, f"broken JSON ({str(exc)[:80]})"
    if not isinstance(data, want):
        kind = {dict: "an object", list: "a list"}.get(want, want.__name__)
        return None, f"wrong shape: expected {kind}, got {type(data).__name__}"
    return data, None


def tail(stderr: str, limit: int = 200) -> str:
    """The last non-empty line a tool printed to stderr, for the record's reason."""
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    return lines[-1][:limit] if lines else ""


def words(info: dict) -> str:
    """`tool (status)`, the way readiness, the Evidence Report and the console name an incomplete scanner."""
    return f"{info.get('tool')} ({str(info.get('status') or state_of(info))[:160]})"
