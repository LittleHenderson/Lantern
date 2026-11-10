"""Loaded by every Python process that inherits PYTHONPATH from a guarded test or benchmark run, before the process
imports anything else: it switches the network guard on (`lantern_netguard.py` beside this file) and then hands over
to any other `sitecustomize` further along the path, so nothing that was set up that way is lost."""
import os
import sys

if os.environ.get("LANTERN_NETGUARD_LOG"):
    _here = os.path.dirname(os.path.abspath(__file__))
    try:
        if _here not in sys.path:
            sys.path.insert(0, _here)
        import lantern_netguard
        lantern_netguard.install()
    except Exception as _e:   # noqa: BLE001 - a child that cannot be guarded must say so, loudly, and not run on
        try:
            with open(os.environ["LANTERN_NETGUARD_LOG"], "a", encoding="utf-8") as _f:
                _f.write('{"kind": "guard-failed", "host": %r, "port": null, "pid": %d, "argv": []}\n'
                         % (str(_e)[:100].replace('"', "'"), os.getpid()))
        except OSError:
            pass
        sys.stderr.write("LANTERN-NETGUARD-REFUSED: the network guard could not start in this process: %s\n" % _e)
        sys.stderr.flush()
        os._exit(97)      # not SystemExit: raised from here, Python reports it as a start-up crash with result 1

    def _next_sitecustomize():
        import importlib.util
        for _p in sys.path:
            if not _p or os.path.abspath(_p) == _here:
                continue
            _f = os.path.join(_p, "sitecustomize.py")
            if os.path.isfile(_f):
                _spec = importlib.util.spec_from_file_location("_lantern_next_sitecustomize", _f)
                if _spec and _spec.loader:
                    _spec.loader.exec_module(importlib.util.module_from_spec(_spec))
                return

    try:
        _next_sitecustomize()
    except Exception as _e:   # noqa: BLE001 - as Python does when a sitecustomize fails: one line, and the program runs
        sys.stderr.write("Error in the sitecustomize after the network guard's: %s: %s\n" % (type(_e).__name__, _e))
