"""Bundle graph, findings and explanations into one self-contained HTML report."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
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
                lines = (repo / n.file).read_text(encoding="utf-8", errors="replace").splitlines()
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
    path = out_dir / "report.html"
    # newline="\n": the content policy hashes the script bytes, so a CRLF rewrite on Windows would block it
    path.write_text(render(bundle), encoding="utf-8", newline="\n")
    return path


DATA_OPEN = '<script type="application/json" id="lantern-data">'


def safe_json(obj) -> str:
    """JSON for inside a <script> element. Escaping every `<` means no text in the data (`</script>`, `<!--`,
    `<script`) can change how the browser tokenizes the element, so the report can't be broken or hijacked by
    a docstring, route path, or model output."""
    return json.dumps(obj, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


CSP_MARK = '<meta charset="utf-8">'
CSP_META = ('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src {hashes}; '
            "style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'\">")


def script_hashes(html: str) -> list[str]:
    """CSP hash sources for the page's inline scripts (the JSON data block never runs and is left out)."""
    out = []
    for m in re.finditer(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", html, re.S):
        if 'type="application/json"' in m.group("attrs"):
            continue
        digest = hashlib.sha256(m.group("body").encode("utf-8")).digest()
        out.append("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    return out


def render(bundle: dict, live: dict | None = None, nonce: str | None = None) -> str:
    """The report page: our template plus the data. `live` (only from `lantern serve`) enables in-page actions;
    `nonce` marks our own scripts for the server's Content-Security-Policy header.

    The page also carries its own Content-Security-Policy in a <meta> tag, listing the SHA-256 of each of our
    scripts. A report opened from disk has no server to send headers, and this makes it hold anyway: someone who
    edits only the data block cannot get script to run (inline handlers, javascript: URLs, and injected scripts
    are all refused), and only a script that hashes to ours runs at all."""
    html = TEMPLATE.read_text(encoding="utf-8").replace("/*__LANTERN_DATA__*/null", safe_json(bundle))
    if live is not None:
        html = html.replace(DATA_OPEN, "<script>window.LANTERN_LIVE = " + safe_json(live) + ";</script>\n" + DATA_OPEN, 1)
    html = html.replace(CSP_MARK, CSP_MARK + "\n" + CSP_META.format(hashes=" ".join(script_hashes(html))), 1)
    if nonce:
        html = html.replace("<script>", f'<script nonce="{nonce}">')
    return html


def read_bundle(path: Path) -> dict:
    """Pull the data back out of a written report.html. The file may have been edited or planted by anyone,
    so only the data comes back (parsed as JSON); the page itself is always rebuilt from our template."""
    text = path.read_text(encoding="utf-8", errors="replace")
    i = text.find(DATA_OPEN)
    j = text.find("</script>", i)
    if i < 0 or j < 0:
        raise ValueError("this report.html was not written by Lantern; analyze again")
    data = json.loads(text[i + len(DATA_OPEN):j])
    if not isinstance(data, dict) or not isinstance(data.get("graph"), dict):
        raise ValueError("this report.html has no Lantern data; analyze again")
    return data
