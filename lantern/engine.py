"""Build the full-stack graph: Python, TypeScript/JavaScript, Go, Rust, Java, Kotlin, Swift, then the API bridge between them."""

from __future__ import annotations

from pathlib import Path

from . import bridge, go_frontend, java_frontend, js_frontend, kotlin_frontend, lanes, packs, python_frontend, rust_frontend, swift_frontend
from .graph import Graph


def build_graph(repo: str | Path) -> Graph:
    g = python_frontend.build_graph(repo)
    py = {"files": g.meta.get("files", 0), "lines": g.meta.get("lines", 0)}
    js = js_frontend.add_js(g, repo)
    go = go_frontend.add_go(g, repo)
    rs = rust_frontend.add_rust(g, repo)
    jv = java_frontend.add_java(g, repo)
    kt = kotlin_frontend.add_kotlin(g, repo)
    sw = swift_frontend.add_swift(g, repo)
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
    g.meta.update({
        "languages": langs,
        "files": sum(x.get("files", 0) for x in (py, js, go, rs, jv, kt, sw)),
        "lines": sum(x.get("lines", 0) for x in (py, js, go, rs, jv, kt, sw)),
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
    bridge.link(g)
    lanes.assign(g)
    return g
