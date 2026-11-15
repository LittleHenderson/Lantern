"""Which of a project's functions run on the visitor's side: in their browser or on their phone (roadmap stage 1).

The lanes (`lantern/lanes.py`) place a function for the picture, by its file's path. A rule that ranks a finding
higher because "the browser reaches this" needs more than a place in a picture: a reason, in the code, to say that
this function's code is handed to the visitor. `where(g)` names the functions it has such a reason for, each with
the reason as words a finding can repeat:

* the file begins with `"use client"`;
* the file is part of a phone app (React Native, Expo);
* the project has no framework that renders pages on a server (`SERVER_RENDERED`), so what is not in one of its
  server folders is browser code;
* the file is a page of Next.js's `pages/` folder, whose pages run in the browser too, without the functions
  Next.js runs on the server only (`SERVER_ONLY`);
* a function such code calls runs where its caller runs, unless it is the server's own: a route, a file in a server
  folder, a file that begins with `"use server"` (a client file reaches that one over the network).

A function with none of these is not said to run there. In a project that renders on a server, a file with no
directive that nothing on the visitor's side calls is left out: it may be a server component."""
from __future__ import annotations

import re
from pathlib import Path

from . import lanes
from .graph import Graph
from .js_frontend import _nearest_package

SERVER_RENDERED = {"next", "nuxt", "astro", "gatsby", "@sveltejs/kit", "@remix-run/react", "@remix-run/node",
                   "@remix-run/serve", "@remix-run/dev", "@react-router/dev", "@react-router/node",
                   "@builder.io/qwik-city", "@tanstack/start", "@tanstack/react-start", "solid-start", "@solidjs/start"}
PAGES_FOLDER = re.compile(r"(^|/)(src/)?pages/(?!api/)")
SERVER_ONLY = {"getServerSideProps", "getStaticProps", "getStaticPaths"}

BROWSER = "the browser"
PHONE = "the phone"


def _own_name(nid: str) -> str:
    return nid.split("::", 1)[1] if "::" in nid else ""


def _short(nid: str) -> str:
    return _own_name(nid).rsplit(".", 1)[-1] or nid.split(":", 1)[-1].rsplit("/", 1)[-1]


def where(g: Graph) -> dict[str, dict]:
    """node id -> `{"on": "the browser" | "the phone", "why": words}` for each function Lantern can show runs on
    the visitor's side."""
    repo = Path(g.repo_root)
    said = g.meta.get("js_directives") or {}
    phone = lanes.phone_roots(g.meta)
    packages: dict = {}
    out: dict[str, dict] = {}
    for n in g.nodes.values():
        if not n.id.startswith("js:") or not n.file or n.lane == "server":
            continue
        told = said.get(n.file) or ()
        if "use server" in told:
            continue
        if "use client" in told:
            out[n.id] = {"on": BROWSER, "why": f'{n.file} begins with "use client"'}
        elif phone and lanes._in_roots(n.file, phone):
            out[n.id] = {"on": PHONE, "why": f"{n.file} is part of the phone app"}
        elif n.lane in ("browser", "frontend"):
            deps = _nearest_package(repo / n.file, repo, packages)["deps"]
            if not deps & SERVER_RENDERED:
                out[n.id] = {"on": BROWSER, "why": f"{n.file} is part of a web app that runs in the browser"}
            elif "next" in deps and PAGES_FOLDER.search(n.file) and _own_name(n.id).split(".")[0] not in SERVER_ONLY:
                out[n.id] = {"on": BROWSER, "why": f"{n.file} is a page, and a page of the pages folder runs in the "
                                                   "browser too"}
    calls: dict[str, list[str]] = {}
    for e in g.call_edges():
        if not (e.via or "").startswith("http-"):
            calls.setdefault(e.src, []).append(e.dst)
    todo = sorted(out)
    while todo:
        src = todo.pop()
        for dst in calls.get(src, ()):
            n = g.nodes.get(dst)
            if dst in out or n is None or not dst.startswith("js:") or not n.file or n.lane == "server" or \
                    "use server" in (said.get(n.file) or ()) or \
                    (PAGES_FOLDER.search(n.file) and _own_name(dst).split(".")[0] in SERVER_ONLY):
                continue
            out[dst] = {"on": out[src]["on"], "why": f"`{_short(src)}` calls it, and {out[src]['why']}"}
            todo.append(dst)
    return out
