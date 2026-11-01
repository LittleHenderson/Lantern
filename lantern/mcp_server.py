"""Lantern as a connector for AI assistants: a Model Context Protocol (MCP) server over stdio.

One server works in Claude (Desktop and Code), ChatGPT, Cursor and any other MCP client. The assistant
gets Lantern's facts (paths, findings, readiness, explanations) and can ask for a re-check or verify an
Evidence Report. Standard library only; newline-delimited JSON-RPC 2.0 on stdin/stdout.

What the connector can do: read, analyze, re-check, verify.
What it deliberately cannot do: accept a risk, close or dismiss a finding, or change a project's files.
Accepting a risk needs a person's written reason and goes through `lantern accept`; that keeps
"a model never closes a finding" true by construction, not by policy.

Every client that connects identifies itself in the MCP handshake (`clientInfo`). The name and the
time of the last call are kept in LANTERN_HOME/connections.json so Settings can show "Used by
Claude Code, 2 minutes ago" instead of a toggle that cannot tell whether anything is connected.

    lantern mcp                      # serve on stdio (what the assistant's config runs)
    lantern mcp --setup              # print the config snippets for Claude, Cursor, ChatGPT
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path

from . import __version__, pipeline, usage
from .graph import Graph

PROTOCOL_VERSION = "2025-06-18"
MAX_LIST = 60           # findings or paths in one answer; the rest is counted
JSON_SCHEMA_PROJECT = {"type": "string", "description": "Project name as listed by lantern_projects, or a folder path."}

INSTRUCTIONS = (
    "Lantern maps a full-stack app (Python, TypeScript/JavaScript): every call path from a page or route to the "
    "database, security findings ranked by whether a user can reach them, a deployment readiness score, and "
    "three-lens explanations. Its facts come from deterministic analysis, never from a model. Use lantern_paths "
    "before editing a function to see what calls it and whether a user can reach it. Use lantern_findings to get "
    "the exact file, line, click path and fix for a finding. After writing a fix, call lantern_recheck with the "
    "finding id to see whether it is gone. lantern_verify re-runs an Evidence Report's analysis and compares "
    "digests. This connector can read, analyze, re-check and verify. It cannot accept a risk or close a finding: "
    "only the builder can, with a written reason, by running `lantern accept`."
)

CANNOT_CLOSE = ("This connector cannot accept, close or dismiss findings. If a finding is a deliberate, acceptable "
                "risk, the builder runs: lantern accept PATH FINDING_ID --reason \"...\" (the reason is shown in the "
                "Evidence Report).")


# ---------------------------------------------------------------------------- projects

class Projects:
    """Known projects: those listed in the Lantern app (LANTERN_HOME/projects.json), folders given on the command
    line, and the current folder when it has been analyzed."""

    def __init__(self, extra: list[str] | None = None):
        from .server import Store, home_dir
        self.store = Store(home_dir())
        self.extra = [Path(x).resolve() for x in extra or []]

    def all(self) -> list[dict]:
        rows, seen = [], set()
        for p in self.extra + [Path.cwd()] + [Path(p["path"]) for p in self.store.projects()]:
            if str(p) in seen:
                continue
            seen.add(str(p))
            if (p / ".lantern" / "graph.json").exists() or p in self.extra:
                rows.append({"name": p.name or str(p), "path": str(p), "analyzed": (p / ".lantern" / "graph.json").exists()})
        return rows

    def resolve(self, project: str | None) -> Path:
        rows = self.all()
        if not project:
            if len(rows) == 1:
                return Path(rows[0]["path"])
            if (Path.cwd() / ".lantern" / "graph.json").exists():
                return Path.cwd()
            raise ValueError("Say which project: " + (", ".join(r["name"] for r in rows) if rows else
                                                       "none is analyzed yet; give a folder path"))
        project = str(project).strip()
        for r in rows:
            if r["name"].lower() == project.lower() or r["path"] == project:
                return Path(r["path"])
        p = Path(os.path.expanduser(project))
        if p.is_dir():
            return p.resolve()
        hits = [r for r in rows if project.lower() in r["name"].lower()]
        if len(hits) == 1:
            return Path(hits[0]["path"])
        raise ValueError(f"No project called {project!r}. Known: " + (", ".join(r["name"] for r in rows) or "none") +
                         ". A folder path also works.")


def _out(repo: Path) -> Path:
    out = repo / ".lantern"
    if not (out / "graph.json").exists():
        raise ValueError(f"{repo.name} is not analyzed yet. Call lantern_analyze, or run `lantern analyze {repo}`.")
    return out


def _load(out: Path, name: str) -> dict:
    return pipeline.load(out, name) or {}


def _short(nid: str) -> str:
    return nid.split(":", 1)[-1]


def _node_name(g: Graph, nid: str) -> str:
    n = g.nodes.get(nid)
    if n is None:
        return _short(nid)
    if n.entry and n.entry.get("kind") == "page":
        return f"{n.entry.get('detail')} page"
    return n.qualname


def _chain(g: Graph, ids: list[str]) -> str:
    """One path as a readable line: names with the HTTP and click hops between them."""
    parts = []
    for i, nid in enumerate(ids):
        if i:
            e = next((x for x in g.callees(ids[i - 1]) if x.dst == nid), None)
            if e and (e.via or "").startswith("http-"):
                parts.append(f" -HTTP {e.detail or ''}-> ")
            elif e and e.detail:
                parts.append(f" -{e.detail}-> ")
            else:
                parts.append(" -> ")
        parts.append(_node_name(g, nid))
    return "".join(parts)


def find_node(g: Graph, target: str) -> list[str]:
    """Node ids for a target: an id, a qualified name (or its suffix), a bare name, or `file:line`."""
    t = target.strip()
    if t in g.nodes:
        return [t]
    if ":" in t and t.rsplit(":", 1)[1].isdigit():
        file, line = t.rsplit(":", 1)
        from .security import _node_at
        file = file.replace("\\", "/").lstrip("./")
        for cand in {file} | {n.file for n in g.nodes.values() if n.file and n.file.endswith(file)}:
            nid = _node_at(g, cand, int(line))
            if nid:
                return [nid]
        return []
    exact = [n.id for n in g.nodes.values() if n.qualname == t or n.id.endswith("::" + t)]
    if exact:
        return exact
    suffix = [n.id for n in g.nodes.values() if n.kind == "callable" and (n.qualname.endswith("." + t) or n.name == t)]
    if suffix:
        return suffix
    low = t.lower()
    return [n.id for n in g.nodes.values() if n.kind == "callable" and low in n.qualname.lower()][:MAX_LIST]


def _finding_view(f: dict, g: Graph | None, exp: dict | None) -> dict:
    rec = ((exp or {}).get("explanations") or {}).get(f.get("node") or "", {})
    ex = next((x for x in (rec.get("findings") or []) if x.get("id") == f["id"]), None)
    view = {k: f.get(k) for k in ("id", "rank", "rule", "tool", "title", "file", "line", "status", "cwe", "snippet")}
    view["heuristic"] = f.get("tool_confidence") == "LOW"
    view["in_tests"] = bool(f.get("in_tests"))
    view["function"] = _short(f["node"]) if f.get("node") else None
    if g is not None:
        if f.get("ui_path"):
            view["from_the_app"] = _chain(g, f["ui_path"])
        r = f.get("reachable")
        if r and r.get("path") != f.get("ui_path"):
            view["reachable_from"] = {"kind": r.get("kind"), "path": _chain(g, r["path"])}
        if not f.get("ui_path") and not r:
            view["reachable_from"] = None
            view["note"] = "Only reached by tests." if f.get("reachable_from_tests_only") else \
                "Not reachable from any detected entry point."
    if f.get("input"):
        view["uses_outside_input"] = f["input"].get("via")
    if f.get("more_info") and not str(f["more_info"]).startswith("http"):
        view["about"] = f["more_info"]
    if ex:
        view["plain_words"] = ex.get("lens2")
        view["fix"] = ex.get("fix")
    if f.get("status") == "accepted":
        view["accepted"] = f.get("accepted")
    return view


# ---------------------------------------------------------------------------- tools

def tool_projects(P: Projects, args: dict) -> dict:
    rows = []
    for r in P.all():
        out = Path(r["path"]) / ".lantern"
        rd, sec, run = _load(out, "readiness.json"), _load(out, "security.json"), _load(out, "run.json")
        rows.append({**r, "score": rd.get("score"), "grade": rd.get("grade"), "shape": rd.get("shape"),
                     "open_findings": {k: v for k, v in (sec.get("counts") or {}).items()
                                       if k in ("critical", "high", "medium", "low", "accepted")} or None,
                     "analyzed_at": run.get("finished_at")})
    text = "\n".join(f"{r['name']}  {r['path']}" + (f"  readiness {r['score']}/100 ({r['grade']}), findings "
                     f"{r['open_findings']}" if r["analyzed"] else "  (not analyzed yet)") for r in rows) or \
        "No analyzed projects. Call lantern_analyze with a folder path, or run `lantern analyze PATH`."
    return {"text": text, "data": {"projects": rows}}


def tool_findings(P: Projects, args: dict) -> dict:
    repo = P.resolve(args.get("project"))
    out = _out(repo)
    sec, exp = _load(out, "security.json"), _load(out, "explanations.json")
    g = Graph.load(out / "graph.json")
    fs = sec.get("findings") or []
    fid = (args.get("id") or "").strip()
    if fid:
        fs = [f for f in fs if f["id"] == fid or f["id"].startswith(fid)]
        if not fs:
            return {"text": f"No finding {fid} in {repo.name}. It may have been fixed: findings get new ids when "
                            "the flagged line changes. Call lantern_findings without an id to see what is open.",
                    "data": {"findings": []}}
    if args.get("rank"):
        fs = [f for f in fs if f["rank"] == args["rank"]]
    if args.get("file"):
        want = str(args["file"]).replace("\\", "/")
        fs = [f for f in fs if f.get("file") and (f["file"] == want or f["file"].endswith(want))]
    if not args.get("include_accepted"):
        fs = [f for f in fs if f.get("status") != "accepted"]
    if not args.get("include_tests"):
        fs = [f for f in fs if not f.get("in_tests")]
    views = [_finding_view(f, g, exp) for f in fs[:MAX_LIST]]
    lines = [f"{repo.name}: {len(fs)} finding(s)" + (f", showing {MAX_LIST}" if len(fs) > MAX_LIST else "") +
             f". Counts: {sec.get('counts')}"]
    for v in views:
        lines.append(f"- [{v['rank']}] {v['id']} {v['rule']} {v['title']} at {v['file']}:{v['line']}" +
                     (f" in {v['function']}" if v.get("function") else "") + (" (heuristic)" if v["heuristic"] else ""))
        if v.get("from_the_app"):
            lines.append(f"    from the app: {v['from_the_app']}")
        elif v.get("reachable_from"):
            lines.append(f"    reachable from {v['reachable_from']['kind']}: {v['reachable_from']['path']}")
        elif v.get("note"):
            lines.append(f"    {v['note']}")
        if v.get("uses_outside_input"):
            lines.append(f"    uses outside input: {v['uses_outside_input']}")
        if v.get("fix"):
            lines.append(f"    fix: {v['fix']}")
        elif v.get("about"):
            lines.append(f"    {v['about']}")
    lines.append(CANNOT_CLOSE)
    return {"text": "\n".join(lines), "data": {"project": repo.name, "counts": sec.get("counts"), "total": len(fs),
                                               "findings": views, "cannot_close": True}}


def tool_paths(P: Projects, args: dict) -> dict:
    repo = P.resolve(args.get("project"))
    out = _out(repo)
    g = Graph.load(out / "graph.json")
    target = str(args.get("target") or "").strip()
    if not target:
        raise ValueError("give target: a function name, qualified name, node id, or file:line")
    ids = find_node(g, target)
    if not ids:
        raise ValueError(f"nothing in {repo.name} matches {target!r}")
    if len(ids) > 1 and not all(g.nodes[i].qualname == g.nodes[ids[0]].qualname for i in ids):
        names = [g.nodes[i].id for i in ids[:20]]
        return {"text": f"{len(ids)} functions match {target!r}; pick one:\n" + "\n".join(names),
                "data": {"matches": names}}
    from .security import reachability
    reach = reachability(g)
    ui = reachability(g, kinds={"page", "main"})
    sec = _load(out, "security.json")
    rows = []
    for nid in ids[:3]:
        n = g.nodes[nid]
        callers = [{"from": _node_name(g, e.src), "id": e.src, "confidence": e.confidence, "via": e.via,
                    "detail": e.detail, "lines": e.lines[:5]} for e in g.callers(nid)]
        callees = [{"to": _node_name(g, e.dst), "id": e.dst, "confidence": e.confidence, "via": e.via,
                    "detail": e.detail} for e in g.callees(nid)]
        r, u = reach.get(nid), ui.get(nid)
        findings = [f["id"] + " " + f["rule"] for f in (sec.get("findings") or []) if f.get("node") == nid]
        rows.append({"id": nid, "name": n.qualname, "file": n.file, "lines": [n.start_line, n.end_line],
                     "entry": n.entry, "signature": n.signature,
                     "from_the_app": _chain(g, u["path"]) if u else None,
                     "reachable_from": {"kind": r["kind"], "path": _chain(g, r["path"])} if r else None,
                     "callers": callers[:MAX_LIST], "callees": callees[:MAX_LIST], "findings_here": findings})
    lines = []
    for r in rows:
        lines.append(f"{r['name']}  ({r['file']}:{r['lines'][0]}-{r['lines'][1]})" +
                     (f"  entry point: {r['entry']['kind']} {r['entry'].get('detail') or ''}" if r["entry"] else ""))
        lines.append("  from the app: " + r["from_the_app"] if r["from_the_app"] else
                     f"  reachable from {r['reachable_from']['kind']}: {r['reachable_from']['path']}" if r["reachable_from"]
                     else "  not reachable from any detected entry point (a user cannot trigger it, as far as the map shows)")
        lines.append(f"  called by ({len(r['callers'])}): " + (", ".join(
            f"{c['from']} [{c['confidence']}" + (f", {c['detail']}" if c["detail"] else "") + "]" for c in r["callers"][:15]) or "nothing in the repo"))
        lines.append(f"  calls ({len(r['callees'])}): " + (", ".join(
            f"{c['to']} [{c['confidence']}" + (f", {c['detail']}" if c["detail"] else "") + "]" for c in r["callees"][:15]) or "nothing"))
        if r["findings_here"]:
            lines.append("  findings here: " + ", ".join(r["findings_here"]))
    lines.append("Confidence: observed (seen running) > resolved (static, certain) > inferred (likely) > possible. "
                 f"Unresolved calls in this project: {sum(g.unresolved.values())}.")
    return {"text": "\n".join(lines), "data": {"project": repo.name, "functions": rows,
                                               "unresolved_calls": sum(g.unresolved.values())}}


def tool_explain(P: Projects, args: dict) -> dict:
    repo = P.resolve(args.get("project"))
    out = _out(repo)
    g = Graph.load(out / "graph.json")
    ids = find_node(g, str(args.get("target") or ""))
    if not ids:
        raise ValueError(f"nothing in {repo.name} matches {args.get('target')!r}")
    exp = _load(out, "explanations.json")
    recs = exp.get("explanations") or {}
    nid = next((i for i in ids if i in recs), ids[0])
    n = g.nodes[nid]
    rec = recs.get(nid)
    src = None
    if n.file and n.start_line:
        try:
            text = (repo / n.file).read_text(encoding="utf-8", errors="replace").splitlines()
            src = "\n".join(text[n.start_line - 1:(n.end_line or n.start_line)])[:4000]
        except OSError:
            src = None
    if not rec:
        return {"text": f"{n.qualname} ({n.file}:{n.start_line}-{n.end_line}) has no Lantern explanation yet. "
                        f"Run `lantern explain {repo}` (or explain it from the Atlas) to add one.\n\n"
                        + (f"Source:\n{src}" if src else ""),
                "data": {"id": nid, "name": n.qualname, "file": n.file, "lines": [n.start_line, n.end_line],
                         "explanation": None, "source": src}}
    l1, l2, l3 = rec.get("lens1") or {}, rec.get("lens2") or {}, rec.get("lens3") or {}
    pairs = "\n".join(f"  \"{p.get('plain')}\" = {p.get('technical')}" for p in (l3.get("pairs") or []))
    text = (f"{n.qualname}  ({n.file}:{n.start_line}-{n.end_line}), explained by {rec.get('model')}, "
            f"validated: {rec.get('validated')}\n"
            f"Technical: {l1.get('summary')}\n  inputs: {l1.get('inputs')}\n  outputs: {l1.get('outputs')}\n"
            f"  side effects: {l1.get('side_effects')}\n  errors: {l1.get('errors')}\n"
            f"Plain words: {l2.get('text')}\n  example: {l2.get('example')}\n  analogy: {l2.get('analogy')}\n"
            f"Mapped: {l3.get('text')}\n{pairs}")
    return {"text": text, "data": {"id": nid, "name": n.qualname, "file": n.file, "lines": [n.start_line, n.end_line],
                                   "explanation": rec, "source": src}}


def tool_readiness(P: Projects, args: dict) -> dict:
    repo = P.resolve(args.get("project"))
    out = _out(repo)
    rd = _load(out, "readiness.json")
    if not rd:
        raise ValueError("no readiness result; run lantern_analyze")
    cats = [{"title": c["title"], "percent": c["percent"], "weight": c["weight"],
             "failed": [{"title": x["title"], "status": x["status"], "evidence": x.get("evidence"), "fix": x.get("fix")}
                        for x in c["checks"] if x["status"] in ("fail", "partial")]} for c in rd.get("categories", [])]
    nxt = [{"title": c["title"], "category": c.get("category"), "gain": c.get("gain"), "fix": c.get("fix"),
            "evidence": c.get("evidence")} for c in rd.get("next_steps", [])]
    prot = [{k: p.get(k) for k in ("id", "title", "status", "why", "how")} for p in rd.get("protections") or []]
    lines = [f"{repo.name}: readiness {rd['score']}/100, grade {rd['grade']}, shape: {rd.get('shape')}"]
    for c in cats:
        lines.append(f"- {c['title']}: {c['percent'] if c['percent'] is not None else 'n/a'}%" +
                     (" — " + "; ".join(f"{x['title']} ({x['status']})" for x in c["failed"]) if c["failed"] else ""))
    if nxt:
        lines.append("Do first:")
        lines += [f"  {i + 1}. {s['title']} (+{s['gain']}): {s['fix']}" for i, s in enumerate(nxt)]
    if prot:
        lines.append("Protections (heuristic, do not change the score): " +
                     "; ".join(f"{p['title']}: {p['status']}" for p in prot))
    if rd.get("advice"):
        lines.append("Deployment advice: " + " ".join(str(a) for a in rd["advice"][:4]))
    return {"text": "\n".join(lines), "data": {"project": repo.name, "score": rd["score"], "grade": rd["grade"],
                                               "shape": rd.get("shape"), "categories": cats, "next_steps": nxt,
                                               "protections": prot, "advice": rd.get("advice"),
                                               "stack": rd.get("stack")}}


def _snapshot(out: Path) -> dict[str, dict]:
    sec = _load(out, "security.json")
    return {f["id"]: f for f in sec.get("findings") or [] if not f.get("in_tests")}


def _diff(before: dict[str, dict], after: dict[str, dict]) -> dict:
    gone = [before[k] for k in before if k not in after]
    new = [after[k] for k in after if k not in before]
    # a gone finding whose rule reappears in the same file was probably moved, not fixed
    places = {(f["rule"], f.get("file")) for f in new}
    fixed = [f for f in gone if (f["rule"], f.get("file")) not in places]
    changed = [f for f in gone if (f["rule"], f.get("file")) in places]
    brief = lambda f: {k: f.get(k) for k in ("id", "rank", "rule", "title", "file", "line")}  # noqa: E731
    return {"fixed": [brief(f) for f in fixed], "changed_still_open": [brief(f) for f in changed],
            "new": [brief(f) for f in new]}


def tool_analyze(P: Projects, args: dict) -> dict:
    repo = P.resolve(args.get("project"))
    if not repo.is_dir():
        raise ValueError(f"not a folder: {repo}")
    out = repo / ".lantern"
    before = _snapshot(out) if (out / "graph.json").exists() else {}
    log: list[str] = []
    out = pipeline.out_dir(repo)
    privacy = P.store.settings().get("privacy", "full")
    res = pipeline.analyze(repo, out, privacy, log=log.append, offline=args.get("offline"))
    d = _diff(before, _snapshot(out))
    lines = ["\n".join(log)]
    if before:
        lines.append(f"Since the last analysis: {len(d['fixed'])} fixed, {len(d['new'])} new, "
                     f"{len(d['changed_still_open'])} changed but still open.")
    return {"text": "\n".join(lines), "data": {"project": repo.name, **res, "log": log, **d}}


def tool_recheck(P: Projects, args: dict) -> dict:
    repo = P.resolve(args.get("project"))
    out = _out(repo)
    fid = str(args.get("finding") or "").strip()
    if not fid:
        raise ValueError("give finding: the id from lantern_findings")
    before = _snapshot(out)
    target = before.get(fid)
    if target is None:
        raise ValueError(f"{fid} is not an open finding in {repo.name} (ids change when the flagged line changes; "
                         "call lantern_findings to see what is open)")
    log: list[str] = []
    pipeline.analyze(repo, out, P.store.settings().get("privacy", "full"), log=log.append, offline=args.get("offline"))
    after = _snapshot(out)
    d = _diff(before, after)
    still = after.get(fid)
    same_place = [f for f in d["new"] if f["rule"] == target["rule"] and f.get("file") == target.get("file")]
    if still is not None:
        verdict, status = ("still open" if still.get("status") == "open" else still.get("status")), "open"
    elif same_place:
        verdict, status = (f"the flagged line changed but {target['rule']} still fires in {target['file']} "
                           f"(now {', '.join(f['id'] for f in same_place)}); not fixed"), "changed"
    else:
        verdict, status = "gone: no longer reported on this commit", "fixed"
    text = (f"{fid} ({target['rule']} at {target['file']}:{target['line']}): {verdict}.\n"
            f"Whole project since the last analysis: {len(d['fixed'])} fixed, {len(d['new'])} new, "
            f"{len(d['changed_still_open'])} changed but still open. Counts now: {_load(out, 'security.json').get('counts')}")
    return {"text": text, "data": {"project": repo.name, "finding": fid, "status": status, "verdict": verdict,
                                   "was": {k: target.get(k) for k in ("rule", "title", "file", "line", "rank")},
                                   "now": still and _finding_view(still, None, None), **d}}


def tool_verify(P: Projects, args: dict) -> dict:
    from . import evidence
    repo = P.resolve(args.get("project"))
    want, old = (args.get("digest") or "").strip() or None, None
    rp = args.get("report")
    if rp:
        p = Path(os.path.expanduser(str(rp)))
        if not p.is_absolute():
            p = repo / p
        if not p.exists():
            raise ValueError(f"no such report: {rp}")
        want, old = evidence.read_digest(p)
    if not want:
        ev = repo / ".lantern" / "evidence.json"
        if not ev.exists():
            raise ValueError("give digest (sha256:...) or report (path to evidence.html/.json); this project has "
                             "no Evidence Report of its own yet")
        want, old = evidence.read_digest(ev)
    if not want:
        raise ValueError("that report carries no sha256 digest")
    r = evidence.verify(repo, want, old, trace_cmd=None, offline=bool(args.get("offline")))
    if r.get("refused"):
        text = (r["refused"] + " From a terminal: lantern verify " + str(repo) + " --report <report> -- " +
                " ".join(r["trace_command"]))
        return {"text": text, "data": r}
    text = (f"{'MATCH' if r['match'] else 'DIFFERENT'}: report {r['report']}\n rerun  {r['rerun']}\n"
            f" commit {r['commit']}{' (uncommitted changes present)' if r['dirty'] else ''}; options {r['options']}")
    if r["match"]:
        text += "\nThe report's results are what this analyzer finds on this commit."
    else:
        text += "\n" + r["note"] + (("\nSections that differ: " + ", ".join(r["differs"])) if r.get("differs") else "")
    return {"text": text, "data": r}


TOOLS = [
    ("lantern_projects", tool_projects,
     "List the projects Lantern knows (name, folder, readiness score, open findings, when analyzed).",
     {"type": "object", "properties": {}, "additionalProperties": False}),
    ("lantern_findings", tool_findings,
     "Security findings for a project, ranked by severity and by whether a user can reach them. Each carries the "
     "file and line, the click path from the page that triggers it, whether outside input reaches the line, and the "
     "fix when the function was explained. Give `id` for one finding (the id in 'Fix Lantern finding <id>'). "
     "Read-only: this tool cannot accept or close a finding.",
     {"type": "object", "properties": {
         "project": JSON_SCHEMA_PROJECT,
         "id": {"type": "string", "description": "A finding id (or its prefix) to get just that finding."},
         "rank": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
         "file": {"type": "string", "description": "Only findings in this file (path or suffix)."},
         "include_accepted": {"type": "boolean", "description": "Also list risks the builder accepted (default false)."},
         "include_tests": {"type": "boolean", "description": "Also list findings inside test files (default false)."}},
      "additionalProperties": False}),
    ("lantern_paths", tool_paths,
     "What calls a function and what it calls, with Lantern's confidence for each link, and the path a user "
     "takes to reach it (page -> click -> HTTP call -> route -> function). Call this before editing a function. "
     "`target` is a function name, qualified name (pkg.mod.func or Component.method), node id, or file:line.",
     {"type": "object", "properties": {"project": JSON_SCHEMA_PROJECT,
                                       "target": {"type": "string", "description": "Function name, qualified name, node id, or file:line."}},
      "required": ["target"], "additionalProperties": False}),
    ("lantern_explain", tool_explain,
     "The stored three-lens explanation of a function (technical; plain words with an example and analogy; plain "
     "phrases mapped 1:1 to code terms) plus its source. Says so when none exists yet; this tool never calls a model.",
     {"type": "object", "properties": {"project": JSON_SCHEMA_PROJECT,
                                       "target": {"type": "string", "description": "Function name, qualified name, node id, or file:line."}},
      "required": ["target"], "additionalProperties": False}),
    ("lantern_readiness", tool_readiness,
     "Deployment readiness: the 0-100 score and grade, each category with its failed checks and fixes, what to do "
     "first, protections to add, and deployment advice for the app's shape.",
     {"type": "object", "properties": {"project": JSON_SCHEMA_PROJECT}, "additionalProperties": False}),
    ("lantern_analyze", tool_analyze,
     "Analyze (or re-analyze) a project: build the code map, link frontend to backend, run the security scanners, "
     "score readiness, write the report and Evidence Report. Reads the code; never runs it. Reports what was fixed "
     "or new since the last analysis. `project` may be a folder path that Lantern has not seen before.",
     {"type": "object", "properties": {"project": JSON_SCHEMA_PROJECT,
                                       "offline": {"type": "boolean", "description": "Skip the dependency audits (the only network step)."}},
      "additionalProperties": False}),
    ("lantern_recheck", tool_recheck,
     "After a fix: re-analyze and say whether one finding is gone, still open, or moved (the flagged line changed "
     "but the same rule still fires in that file). This is how a fix is verified; a finding is never closed by hand.",
     {"type": "object", "properties": {"project": JSON_SCHEMA_PROJECT,
                                       "finding": {"type": "string", "description": "The finding id from lantern_findings."},
                                       "offline": {"type": "boolean"}},
      "required": ["finding"], "additionalProperties": False}),
    ("lantern_verify", tool_verify,
     "Verify an Evidence Report: re-run the analysis the same way and compare the SHA-256 results digest. Give "
     "`digest` (sha256:...) or `report` (path to evidence.html or evidence.json); with neither, the project's own "
     "latest report is checked. A report made with a runtime trace is refused here, because a trace runs the "
     "project's code; the builder runs that from a terminal.",
     {"type": "object", "properties": {"project": JSON_SCHEMA_PROJECT,
                                       "digest": {"type": "string"}, "report": {"type": "string"},
                                       "offline": {"type": "boolean"}},
      "additionalProperties": False}),
]
TOOL_INDEX = {name: (fn, desc, schema) for name, fn, desc, schema in TOOLS}


def tool_list() -> list[dict]:
    return [{"name": name, "description": desc, "inputSchema": schema,
             "annotations": {"readOnlyHint": name not in ("lantern_analyze", "lantern_recheck", "lantern_verify"),
                             "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}}
            for name, _, desc, schema in TOOLS]


# ---------------------------------------------------------------------------- connections log

def record_connection(store, client: dict | None, tool: str | None = None) -> None:
    """Remember which assistant connected and when it last called a tool (name and time only; never arguments)."""
    name = str((client or {}).get("name") or "unknown client")[:80]
    version = str((client or {}).get("version") or "")[:40]
    try:
        with store.lock:
            rows = store._read("connections.json", {})
            if not isinstance(rows, dict):
                rows = {}
            row = rows.get(name) if isinstance(rows.get(name), dict) else {}
            now = int(time.time())
            row = {"name": name, "version": version or row.get("version", ""), "first_seen": row.get("first_seen", now),
                   "last_used": now, "calls": _num(row.get("calls")) + (1 if tool else 0),
                   "last_tool": tool or row.get("last_tool")}
            rows[name] = row
            store._write("connections.json", rows)
    except OSError:
        pass


def _num(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def connections(store) -> list[dict]:
    rows = store._read("connections.json", {})
    out = []
    for r in (rows.values() if isinstance(rows, dict) else []):
        if isinstance(r, dict) and r.get("name"):
            out.append({"name": str(r["name"])[:80], "version": str(r.get("version") or "")[:40],
                        "last_used": _num(r.get("last_used")), "calls": _num(r.get("calls")),
                        "last_tool": str(r.get("last_tool") or "")[:40]})
    return sorted(out, key=lambda r: -r["last_used"])


# ---------------------------------------------------------------------------- JSON-RPC

class Server:
    def __init__(self, projects: Projects | None = None):
        self.P = projects or Projects()
        self.client: dict | None = None

    def handle(self, msg: dict) -> dict | None:
        """One request or notification in; a response out (None for notifications)."""
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if method is None:
            return None   # a response to something we sent (we never send requests)
        if method == "initialize":
            self.client = params.get("clientInfo") or {}
            record_connection(self.P.store, self.client)
            usage.record("mcp_connect")
            return self._ok(mid, {"protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                                  "capabilities": {"tools": {"listChanged": False}},
                                  "serverInfo": {"name": "lantern", "version": __version__},
                                  "instructions": INSTRUCTIONS})
        if method.startswith("notifications/"):
            return None
        if method == "ping":
            return self._ok(mid, {})
        if method == "tools/list":
            return self._ok(mid, {"tools": tool_list()})
        if method == "tools/call":
            name = params.get("name")
            if name not in TOOL_INDEX:
                return self._err(mid, -32602, f"unknown tool {name!r}; this connector cannot accept or close findings"
                                 if name and ("accept" in name or "close" in name or "dismiss" in name)
                                 else f"unknown tool {name!r}")
            record_connection(self.P.store, self.client, name)
            usage.record("mcp_call")
            args = params.get("arguments") or {}
            try:
                r = TOOL_INDEX[name][0](self.P, args if isinstance(args, dict) else {})
                return self._ok(mid, {"content": [{"type": "text", "text": r["text"]}],
                                      "structuredContent": _jsonable(r["data"]), "isError": False})
            except ValueError as e:
                return self._ok(mid, {"content": [{"type": "text", "text": str(e)}], "isError": True})
            except Exception as e:  # noqa: BLE001: the assistant gets a message, the server stays up
                return self._ok(mid, {"content": [{"type": "text", "text": f"Lantern error: {type(e).__name__}: {e}\n"
                                                                            + traceback.format_exc()[-1500:]}],
                                      "isError": True})
        if method in ("resources/list", "resources/templates/list"):
            return self._ok(mid, {"resources": [], "resourceTemplates": []})
        if method == "prompts/list":
            return self._ok(mid, {"prompts": []})
        return self._err(mid, -32601, f"method not found: {method}")

    @staticmethod
    def _ok(mid, result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _err(mid, code, message):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    def serve_stdio(self, inp=None, outp=None) -> int:
        inp = inp or sys.stdin.buffer
        outp = outp or sys.stdout.buffer
        for raw in inp:
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._write(outp, self._err(None, -32700, "parse error"))
                continue
            msgs = msg if isinstance(msg, list) else [msg]
            for m in msgs:
                if not isinstance(m, dict):
                    self._write(outp, self._err(None, -32600, "invalid request"))
                    continue
                resp = self.handle(m)
                if resp is not None:
                    self._write(outp, resp)
        return 0

    @staticmethod
    def _write(outp, resp: dict) -> None:
        outp.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
        outp.flush()


def _jsonable(x):
    return json.loads(json.dumps(x, default=str))


# ---------------------------------------------------------------------------- setup help

def setup_text() -> str:
    import shutil
    cmd = shutil.which("lantern") or "lantern"
    cfg = json.dumps({"mcpServers": {"lantern": {"command": cmd, "args": ["mcp"]}}}, indent=2)
    return f"""Lantern as a connector. One server, every assistant that speaks MCP.

Claude Code:
  claude mcp add lantern -- {cmd} mcp

Claude Desktop (claude_desktop_config.json), Cursor (.cursor/mcp.json), Windsurf, Codex and others:
{cfg}

ChatGPT (Apps/connectors) and Claude.ai on the web need a server they can reach over HTTPS. Expose this
stdio server with an MCP bridge such as `mcp-proxy` or `supergateway` on a URL you control, then add that
URL as a custom connector. Lantern never opens a port by itself.

What the assistant can do once connected: list projects, read findings (with click paths and fixes), see what
calls a function and whether a user can reach it, read explanations, read readiness, re-analyze, re-check a
finding after a fix, and verify an Evidence Report. It cannot accept or close a finding; that stays with you
(`lantern accept ... --reason`). Settings > Connections in the Lantern app shows which assistants have used it.
"""


def main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="lantern mcp", description="Serve Lantern to an AI assistant over MCP (stdio).")
    p.add_argument("paths", nargs="*", help="project folders to offer (besides those in the Lantern app)")
    p.add_argument("--setup", action="store_true", help="print the config snippets for Claude, Cursor, ChatGPT")
    a = p.parse_args(argv)
    if a.setup:
        print(setup_text())
        return 0
    return Server(Projects(a.paths)).serve_stdio()
