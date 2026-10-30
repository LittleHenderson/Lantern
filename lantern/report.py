"""Bundle graph, findings and explanations into one self-contained HTML report."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from . import __version__
from .explain import read_source
from .graph import Graph

TEMPLATE = Path(__file__).parent / "viewer" / "report.html"


def collect_sources(g: Graph, max_lines: int = 200) -> dict[str, str]:
    repo = Path(g.repo_root)
    cache: dict[str, list[str]] = {}
    out = {}
    for n in g.nodes.values():
        if n.kind != "callable" or not n.file or n.start_line is None:
            continue
        lines = cache.get(n.file)
        if lines is None:
            try:
                lines = (repo / n.file).read_text(errors="replace").splitlines()
            except OSError:
                lines = []
            cache[n.file] = lines
        chunk = lines[n.start_line - 1:(n.end_line or n.start_line)][:max_lines]
        out[n.id] = "\n".join(chunk)
    return out


def write_report(out_dir: Path, g: Graph, security: dict | None, explanations: dict | None,
                 privacy: str = "full", timings: dict | None = None, readiness: dict | None = None) -> Path:
    bundle = {
        "version": __version__,
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "graph": g.to_dict(),
        "stats": g.stats(),
        "security": security or {"findings": [], "counts": {}, "tools": []},
        "explanations": explanations or {},
        "sources": collect_sources(g) if privacy == "full" else {},
        "privacy": privacy,
        "timings": timings or {},
        "readiness": readiness,
    }
    if privacy != "full":
        for f in bundle["security"]["findings"]:
            f["snippet"] = "[omitted: structure-only privacy level]"
    data = json.dumps(bundle, separators=(",", ":")).replace("</", "<\\/")
    html = TEMPLATE.read_text().replace("/*__LANTERN_DATA__*/null", data)
    path = out_dir / "report.html"
    path.write_text(html)
    return path
