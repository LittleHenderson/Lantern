"""Build the full-stack graph: Python, TypeScript/JavaScript, Go, Rust, Java, Kotlin, Swift, Dart, C#, PHP, Ruby, C/C++, then the API bridge between them."""

from __future__ import annotations

import contextlib
import gc
import threading
from pathlib import Path

from . import bridge, calls, cpp_frontend, csharp_frontend, dart_frontend, deep, go_frontend, java_frontend, js_frontend, kotlin_frontend, lanes, packs, php_frontend, python_frontend, ruby_frontend, rust_frontend, swift_frontend
from .graph import MODULE, Graph


HOLD_FULL = 1_000_000       # middle passes of the collector before a full one: none while a map is built
_HELD = threading.Lock()
_held: list = [0, None]     # how many builds are under way, and the collector's thresholds before the first of them


@contextlib.contextmanager
def building():
    """While a map is built, the full passes of Python's cycle collector wait (directive point 10, 2026-11-12).

    Nearly everything made then is kept until the map is done: every function, call and link of the project. A full
    pass looks through all of it again, finds nothing to free, and costs more the more there is: 6 of the 26 seconds
    the map of Django took. The small and the middle passes go on as they were, so what the reading of one file
    leaves behind is freed as before, and the most memory a run uses is what it was (measured: 894 MB against 893).
    When the last build under way ends, however it ends, the thresholds are what they were before the first; a
    collector the program around Lantern switched off is left off."""
    with _HELD:
        if _held[0] == 0:
            _held[1] = gc.get_threshold()
            gc.set_threshold(_held[1][0], _held[1][1], HOLD_FULL)
        _held[0] += 1
    try:
        yield
    finally:
        with _HELD:
            _held[0] -= 1
            if _held[0] == 0:
                gc.set_threshold(*_held[1])
                _held[1] = None


def build_graph(repo: str | Path) -> Graph:
    with building():
        return _build_graph(repo)


def _python(g: Graph, repo) -> dict:
    python_frontend.build_graph(repo, g)
    return {"files": g.meta.get("files", 0), "lines": g.meta.get("lines", 0)}


def _part(g: Graph, repo, reader: str, prefix: str, add) -> dict:
    """One reader's part of the map. A reader leaves a piece of code that is nested deeper than it follows and reads
    on (`lantern/deep.py`). Where it meets such code, or a line of classes or files linked that deep, in a place where
    it has no single piece to leave, it stops: what it had put on the map stays, the stop is written down
    (`deep.stopped`, and from there in the log and the Evidence Report's Limits) and the readers after it run. Until
    2026-11-13 that ended the whole check with "maximum recursion depth exceeded" and no result."""
    try:
        return add(g, repo) or {}
    except RecursionError:
        deep.stopped(g, reader)
        files = [n for n in g.nodes.values() if n.kind == MODULE and n.id.startswith(prefix)]
        return {"files": len(files), "lines": sum(n.end_line or 0 for n in files)} if files else {}


def _build_graph(repo: str | Path) -> Graph:
    g = Graph(str(Path(repo).resolve()))
    py = _part(g, repo, "python", "py:", _python)
    py = {"files": py.get("files", 0), "lines": py.get("lines", 0)}
    js = _part(g, repo, "javascript", "js:", js_frontend.add_js)
    go = _part(g, repo, "go", "go:", go_frontend.add_go)
    rs = _part(g, repo, "rust", "rs:", rust_frontend.add_rust)
    jv = _part(g, repo, "java", "jv:", java_frontend.add_java)
    kt = _part(g, repo, "kotlin", "kt:", kotlin_frontend.add_kotlin)
    sw = _part(g, repo, "swift", "sw:", swift_frontend.add_swift)
    dt = _part(g, repo, "dart", "dt:", dart_frontend.add_dart)
    cs = _part(g, repo, "csharp", "cs:", csharp_frontend.add_csharp)
    ph = _part(g, repo, "php", "php:", php_frontend.add_php)
    rb = _part(g, repo, "ruby", "rb:", ruby_frontend.add_ruby)
    cc = _part(g, repo, "cpp", "cc:", cpp_frontend.add_cpp)
    langs = {}
    if py["files"]:
        langs["python"] = py
    if js.get("files"):
        langs["typescript/javascript"] = js
    if go.get("files"):
        langs["go"] = go
    if rs.get("files"):
        langs["rust"] = rs
    if jv.get("files"):
        langs["java"] = jv
    if kt.get("files"):
        langs["kotlin"] = kt
    if sw.get("files"):
        langs["swift"] = sw
    if dt.get("files"):
        langs["dart"] = dt
    if cs.get("files"):
        langs["c#"] = cs
    if ph.get("files"):
        langs["php"] = ph
    if rb.get("files"):
        langs["ruby"] = rb
    if cc.get("files"):
        langs["c/c++"] = cc
    g.meta.update({
        "languages": langs,
        "files": sum(x.get("files", 0) for x in (py, js, go, rs, jv, kt, sw, dt, cs, ph, rb, cc)),
        "lines": sum(x.get("lines", 0) for x in (py, js, go, rs, jv, kt, sw, dt, cs, ph, rb, cc)),
        "language": " + ".join(langs) or "none",
    })
    # Analysis packs (pattern files) can add entry points for frameworks without built-in support, before the
    # bridge links frontend calls to them.
    on, off = packs.split_enabled(packs.load_all(Path(repo), keep_disabled=True)[0])
    if on:
        packs.apply_entries(g, Path(repo), on)
    if off:   # turned off in Settings: listed, so the map says what it did not use
        g.meta.setdefault("packs", {"added": 0, "ambiguous": 0, "unresolved": 0, "packs": []})["disabled"] = [p["pack"] for p in off]
    from . import android
    android.add_entries(g, repo)   # Android starts apps through manifest components, not main()
    from . import ios
    ios.add_entries(g, repo)       # iPhone screens and links, from the Swift map and the Xcode project
    from . import flutter
    flutter.add_entries(g, repo)   # Flutter screens and links, from the Dart map
    from . import dotnet
    dotnet.add_entries(g, repo)    # .NET MAUI / Xamarin screens and links, from the C# map
    bridge.link(g)
    from . import rn
    rn.add_entries(g, repo)        # React Native / Expo screens and links, from the JS map
    lanes.assign(g)
    calls.finish(g)   # one record per call site (Python and JS/TS), summarised in g.meta["calls"]
    return g
