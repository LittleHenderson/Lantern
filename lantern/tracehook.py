"""Runtime call recorder. Runs a Python program and records caller -> callee pairs for code that
lives inside the repo.

Usage (normally invoked by `lantern trace`):
    python -m lantern.tracehook OUT.json REPO_ROOT -- script.py args...
    python -m lantern.tracehook OUT.json REPO_ROOT -- -m pytest -q

Uses PEP 669 `sys.monitoring` on Python 3.12+ (low overhead), and falls back to
`sys.setprofile` on older versions. Only records pairs; never records arguments or values.
"""

from __future__ import annotations

import atexit
import json
import os
import runpy
import sys

_pairs: dict[tuple, int] = {}


def _key(code, line=None):
    return (code.co_filename, code.co_firstlineno, getattr(code, "co_qualname", code.co_name), line)


def _install(repo: str):
    repo = os.path.realpath(repo) + os.sep
    inside: dict[str, bool] = {}

    def is_repo(fn: str) -> bool:
        r = inside.get(fn)
        if r is None:
            if fn.startswith("<") or not os.path.isabs(fn):
                inside[fn] = False
                return False
            real = os.path.realpath(fn)
            r = real.startswith(repo) and f"{os.sep}site-packages{os.sep}" not in real
            inside[fn] = r
        return r

    def record(callee_code, caller_frame):
        if caller_frame is None:
            return
        cc = caller_frame.f_code
        if not (is_repo(callee_code.co_filename) and is_repo(cc.co_filename)):
            return
        caller_line = caller_frame.f_lineno if cc.co_name == "<module>" else None
        k = (_key(cc, caller_line), _key(callee_code))
        _pairs[k] = _pairs.get(k, 0) + 1

    if hasattr(sys, "monitoring"):
        mon = sys.monitoring
        tool = mon.PROFILER_ID
        mon.use_tool_id(tool, "lantern")

        def on_start(code, offset):
            if not is_repo(code.co_filename):
                return mon.DISABLE  # never fire again for library code: keeps overhead low
            record(code, sys._getframe(1).f_back)

        mon.register_callback(tool, mon.events.PY_START, on_start)
        mon.set_events(tool, mon.events.PY_START)
    else:  # pragma: no cover - Python < 3.12
        def prof(frame, event, arg):
            if event == "call":
                record(frame.f_code, frame.f_back)
        sys.setprofile(prof)


def _dump(out: str):
    rows = [{"caller": list(a), "callee": list(b), "count": n} for (a, b), n in _pairs.items()]
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"pairs": rows}, f)


def main(argv: list[str]) -> None:
    if len(argv) < 4 or "--" not in argv:
        print(__doc__)
        raise SystemExit(2)
    out, repo = argv[0], argv[1]
    rest = argv[argv.index("--") + 1:]
    atexit.register(_dump, out)
    sys.path.insert(0, os.path.realpath(repo))
    _install(repo)
    if rest[0] == "-m":
        sys.argv = [rest[1]] + rest[2:]
        runpy.run_module(rest[1], run_name="__main__", alter_sys=True)
    else:
        script = os.path.realpath(rest[0])   # absolute, so recorded filenames map to the repo
        sys.argv = [script] + rest[1:]
        sys.path.insert(0, os.path.dirname(script))
        runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])
