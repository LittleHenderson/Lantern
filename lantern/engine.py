"""Build the full-stack graph: Python, then TypeScript/JavaScript, then the API bridge between them."""

from __future__ import annotations

from pathlib import Path

from . import bridge, go_frontend, js_frontend, packs, python_frontend, rust_frontend
from .graph import Graph


def build_graph(repo: str | Path) -> Graph:
    g = python_frontend.build_graph(repo)
    py = {"files": g.meta.get("files", 0), "lines": g.meta.get("lines", 0)}
    js = js_frontend.add_js(g, repo)
    go = go_frontend.add_go(g, repo)
    rs = rust_frontend.add_rust(g, repo)
    langs = {}
    if py["files"]:
        langs["python"] = py
    if js.get("files"):
        langs["typescript/javascript"] = js
    if go.get("files"):
        langs["go"] = go
    if rs.get("files"):
        langs["rust"] = rs
    g.meta.update({
        "languages": langs,
        "files": py["files"] + js.get("files", 0) + go.get("files", 0) + rs.get("files", 0),
        "lines": py["lines"] + js.get("lines", 0) + go.get("lines", 0) + rs.get("lines", 0),
        "language": " + ".join(langs) or "none",
    })
    # Analysis packs (pattern files) can add entry points for frameworks without built-in support, before the
    # bridge links frontend calls to them.
    loaded, _ = packs.load_all(Path(repo))
    if loaded:
        packs.apply_entries(g, Path(repo), loaded)
    bridge.link(g)
    return g
