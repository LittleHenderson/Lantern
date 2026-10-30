"""Build the full-stack graph: Python, then TypeScript/JavaScript, then the API bridge between them."""

from __future__ import annotations

from pathlib import Path

from . import bridge, js_frontend, python_frontend
from .graph import Graph


def build_graph(repo: str | Path) -> Graph:
    g = python_frontend.build_graph(repo)
    py = {"files": g.meta.get("files", 0), "lines": g.meta.get("lines", 0)}
    js = js_frontend.add_js(g, repo)
    langs = {}
    if py["files"]:
        langs["python"] = py
    if js.get("files"):
        langs["typescript/javascript"] = js
    g.meta.update({
        "languages": langs,
        "files": py["files"] + js.get("files", 0),
        "lines": py["lines"] + js.get("lines", 0),
        "language": " + ".join(langs) or "none",
    })
    bridge.link(g)
    return g
