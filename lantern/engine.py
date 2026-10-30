"""Full-stack build: Python and JS/TS frontends into one graph, then the HTTP bridge between them."""

from __future__ import annotations

from pathlib import Path

from .bridge import link
from .graph import Graph
from .python_frontend import build_graph as build_python
from .ts_frontend import add_to_graph


def build_graph(repo: str | Path) -> Graph:
    repo = Path(repo).resolve()
    g = build_python(repo)
    py = {"files": g.meta.get("files", 0), "lines": g.meta.get("lines", 0)}
    ts = add_to_graph(g, repo)
    bridge = link(g, ts.pop("http_calls"))
    languages = {k: v for k, v in (("python", py), ("typescript", ts)) if v["files"]}
    g.meta.update({
        "language": "+".join(languages) or "none",
        "languages": languages,
        "files": py["files"] + ts["files"],
        "lines": py["lines"] + ts["lines"],
        "bridge": bridge,
    })
    return g
